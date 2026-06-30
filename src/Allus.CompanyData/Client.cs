// Client facade.
//
// The one object an integrating company touches. Build it from config (the keys live there and
// nowhere else), then call:
//
//   client.RequestFieldsAsync()              -> cached IReadOnlyList<RequestField>  (slug -> meta)
//   client.ConnectionsAsync(limit, offset)   -> IAsyncEnumerable<Connection> (auto-paged, honors total)
//   client.ConnectionAsync(id)               -> one Connection
//   client.LogsAsync(limit, offset)          -> IReadOnlyList<LogEntry>
//   client.ProcessChangesAsync(handler)      -> the crash-safe pump
//   client.DrainBatchAsync(max)              -> raw unbuffered drain (advanced)
//   client.DeadLetters() / client.RetryDeadLettersAsync(handler)
//   client.VerifyWebhook / ParseWebhook / HandleWebhook   (config-driven, no key args)
//
// How it is wired (the "everything else the SDK hides"):
//   * Auth + transport — an ApiHttp owns the client_credentials token, JSON/XML accept+parse, and
//     the §9 error mapping (incl. 429 backoff).
//   * Decryption — the service private key is loaded ONCE at construction from the configured
//     encrypted PEM + passphrase into an in-memory RSA; a DecryptValue closure over it is handed to
//     every model factory + the pump (config-only key handling — never a method argument).
//   * Slug catalog — RequestFieldsAsync() is fetched once + cached; its slug→type map types every
//     value (address parses to a dictionary, photo becomes a lazy binary handle, etc.).
//   * Binary — a value's BinaryHandle.BytesAsync() GETs the slot file endpoint, unwraps the API's
//     {"encrypted":true,"value":<wrapper>} envelope, and runs the same service-key decrypt.
//   * Changes feed — ProcessChangesAsync delegates to the Pump, injecting a fetch closure
//     (GET /changes?limit=) and a decrypt closure that builds a typed Change.

using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace Allus.CompanyData;

/// <summary>The company-data SDK client facade.</summary>
public sealed class Client : IDisposable
{
    private const string Base = "/api/company-data";
    private const string ConnectionsPath = Base + "/connections";
    private const string ChangesPath = Base + "/changes";
    private const string RequestFieldsPath = Base + "/request-fields";
    private const string LogsPath = Base + "/logs";
    private const string DocumentsPath = Base + "/documents";
    private const string ConnectRequestsPath = Base + "/connect-requests";
    private const string FlowsPath = Base + "/flows";        // POST /api/company-data/flows/{flowId}/runs
    private const string FlowRunsPath = Base + "/flow-runs"; // list / get / answers / generate
    private const string KeysPath = "/api/keys";

    // Default page size for the connections iterator (heavily rate-limited).
    private const int DefaultConnPage = 100;

    // Bounded extra backoff for the connections iterator on a surfaced 429.
    private const int ConnMax429Backoffs = 5;
    private const double ConnDefaultBackoffSeconds = 5.0;
    private const double ConnMaxBackoffSeconds = 120.0;

    private readonly Config _config;
    private readonly ApiHttp _http;
    private readonly IPumpLogger? _log;
    private readonly Func<double, CancellationToken, Task> _sleep;

    private readonly RSA _privateKey;
    private readonly RSA? _accountKey;

    private IReadOnlyList<RequestField>? _requestFields;
    private Dictionary<string, string?> _typeBySlug = new();
    private Pump? _pump;
    private bool _disposed;

    // Recipient RSA public keys (by share_code) — cached for per-person document encryption. A
    // public key is immutable + not a secret (fetched live, never configured).
    private readonly Dictionary<string, RSA> _pubkeyCache = new();

    // The service RSA public key (public half of the loaded private key), derived once.
    private RSA? _servicePublicKey;

    public Client(
        Config config,
        ApiHttp? http = null,
        IPumpLogger? logger = null,
        Func<double, CancellationToken, Task>? sleep = null)
    {
        _config = config;
        _log = logger;
        _sleep = sleep ?? (async (s, ct) => await Task.Delay(TimeSpan.FromSeconds(s), ct).ConfigureAwait(false));
        _http = http ?? new ApiHttp(config);

        // Load the service private key ONCE (config-only key handling). This is the
        // single place the key material is read; a closure over it does every decrypt.
        _privateKey = LoadServiceKey(config);
        // Load the account key ONCE too (null unless configured) — reused per encrypt_payload webhook.
        _accountKey = Webhooks.LoadAccountKey(config);
    }

    // ── constructors (config-only keys) ────────────────────────────────────────────────────────

    /// <summary>Build from a JSON config file (env vars override secrets).</summary>
    public static Client FromConfig(string path) => new(Config.FromFile(path));

    /// <summary>Build entirely from <c>ALLUS_*</c> env vars.</summary>
    public static Client FromEnv() => new(Config.FromEnv());

    // ── decryption wiring (closures over the loaded key — never a method arg) ──────────────────

    private string DecryptValueImpl(object wrapper) => Crypto.Decrypt(wrapper, _privateKey);

    private async Task<object> BinaryFetchImpl(string valueUrl, CancellationToken ct)
    {
        // Fetch the slot file endpoint and unwrap its {"encrypted":true,"value":...} envelope into
        // the inner {"_enc":1,...} wrapper, which the BinaryHandle then decrypts.
        var body = await _http.GetAsync(valueUrl, ct: ct).ConfigureAwait(false);
        if (body.Kind == NodeKind.Object && body.Has("value"))
            return body.Get("value");
        return body; // defensive: some shapes might return the wrapper directly
    }

    private string? TypeForSlugImpl(string slug)
    {
        if (_requestFields is null)
            RequestFieldsAsync().GetAwaiter().GetResult();
        return _typeBySlug.GetValueOrDefault(slug);
    }

    // ── definitions ────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// The cached request-field DEFINITIONS. Fetched once from
    /// <c>GET /api/company-data/request-fields</c> and cached for the life of the client. Returns
    /// YOUR request config — never the person's fields.
    /// </summary>
    public async Task<IReadOnlyList<RequestField>> RequestFieldsAsync(CancellationToken ct = default)
    {
        if (_requestFields is null)
        {
            var body = await _http.GetAsync(RequestFieldsPath, ct: ct).ConfigureAwait(false);
            var fields = RequestField.ListFromApi(body);
            _requestFields = fields;
            _typeBySlug = fields.Where(f => f.Slug is not null)
                .GroupBy(f => f.Slug!)
                .ToDictionary(g => g.Key, g => g.First().Type);
        }
        return _requestFields;
    }

    // ── connections (heavily rate-limited — initial sync / reconciliation) ─────────────────────

    /// <summary>
    /// A lazy async stream paging the list endpoint, yielding one <see cref="Connection"/> at a
    /// time. <paramref name="limit"/> is the page size; <paramref name="offset"/> the starting
    /// offset. The stream auto-pages <c>GET /api/company-data/connections?limit&amp;offset</c>,
    /// honoring the API <c>total</c> (and stopping on a short page), and yields typed connections
    /// (each <c>Values[slug]</c> already decrypted / a lazy binary handle) — bounded memory.
    ///
    /// The connections endpoints are HEAVILY rate-limited: use this for the initial
    /// full sync + occasional reconciliation, never as a poll substitute for the changes feed. On a
    /// surfaced <see cref="RateLimitException"/> the stream backs off per Retry-After and retries
    /// the page a bounded number of times before re-raising.
    /// </summary>
    public async IAsyncEnumerable<Connection> ConnectionsAsync(
        int limit = DefaultConnPage,
        int offset = 0,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        var page = Math.Max(1, limit);
        var cur = Math.Max(0, offset);
        await RequestFieldsAsync(ct).ConfigureAwait(false); // ensure the catalog is loaded for typing

        var yielded = 0;
        long? total = null;
        while (true)
        {
            var body = await GetConnectionsPageAsync(page, cur, ct).ConfigureAwait(false);
            if (total is null)
            {
                var t = body.Get("total").AsString();
                if (long.TryParse(t, out var parsed)) total = parsed;
            }
            var items = ListItems(body);
            if (items.Count == 0) yield break;
            foreach (var obj in items)
            {
                if (obj.Kind != NodeKind.Object) continue;
                yield return Connection.FromApi(
                    obj,
                    TypeForSlugImpl,
                    DecryptValueImpl,
                    (url, c) => BinaryFetchImpl(url, c),
                    identity: obj); // the list row carries identity AND the values map
                yielded++;
            }
            // Stop when we've reached the reported total, or on a short page.
            if (total is { } tot && yielded >= tot) yield break;
            if (items.Count < page) yield break;
            cur += page;
        }
    }

    private async Task<Node> GetConnectionsPageAsync(int page, int offset, CancellationToken ct)
    {
        var attempts = 0;
        while (true)
        {
            try
            {
                return await _http.GetAsync(ConnectionsPath, new Dictionary<string, string>
                {
                    ["limit"] = page.ToString(),
                    ["offset"] = offset.ToString(),
                }, ct).ConfigureAwait(false);
            }
            catch (RateLimitException ex)
            {
                attempts++;
                if (attempts > ConnMax429Backoffs) throw;
                var delay = ConnBackoff(ex.RetryAfter, attempts);
                _log?.Log($"connections rate-limited (offset={offset}); backoff {delay:F1}s (attempt {attempts})");
                if (delay > 0) await _sleep(delay, ct).ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// Fetch a single connection by id → one <see cref="Connection"/>.
    /// <c>GET /api/company-data/connections/{id}</c> returns <c>{connection_id, user_id, values}</c>
    /// and no display_name/connected_at; those identity fields simply stay null.
    /// </summary>
    public async Task<Connection> ConnectionAsync(string id, CancellationToken ct = default)
    {
        await RequestFieldsAsync(ct).ConfigureAwait(false);
        var body = await _http.GetAsync($"{ConnectionsPath}/{id}", ct: ct).ConfigureAwait(false);
        if (body.Kind == NodeKind.Object && body.Has("items") && !body.Has("values"))
        {
            var items = ListItems(body);
            body = items.Count > 0 ? items[0] : Node.Object(new Dictionary<string, Node>());
        }
        return Connection.FromApi(body, TypeForSlugImpl, DecryptValueImpl, (url, c) => BinaryFetchImpl(url, c));
    }

    // ── logs (moderate rate-limit) ──────────────────────────────────────────────────────────────

    /// <summary>
    /// The service's activity log → <c>IReadOnlyList&lt;LogEntry&gt;</c>.
    /// <c>GET /api/company-data/logs?limit&amp;offset</c>. Ops events only — never person field data.
    /// </summary>
    public async Task<IReadOnlyList<LogEntry>> LogsAsync(int limit = 50, int offset = 0, CancellationToken ct = default)
    {
        var body = await _http.GetAsync(LogsPath, new Dictionary<string, string>
        {
            ["limit"] = Math.Max(1, limit).ToString(),
            ["offset"] = Math.Max(0, offset).ToString(),
        }, ct).ConfigureAwait(false);
        return LogEntry.ListFromApi(body);
    }

    // ── changes feed — the crash-safe pump ──────────────────────────────────────────────────────

    /// <summary>The crash-safe changes <see cref="Pump"/> (built lazily).</summary>
    public Pump Pump
    {
        get
        {
            return _pump ??= new Pump(
                _config,
                fetchChanges: FetchChangesAsync,
                decrypt: DecryptChange,
                logger: _log,
                sleep: _sleep);
        }
    }

    private async Task<List<Node>> FetchChangesAsync(int limit, CancellationToken ct)
    {
        var body = await _http.GetAsync(ChangesPath, new Dictionary<string, string>
        {
            ["limit"] = limit.ToString(),
        }, ct).ConfigureAwait(false);
        var items = body.Kind == NodeKind.Object && body.Has("changes")
            ? body.Get("changes").AsList()
            : body.Kind == NodeKind.List ? body.AsList() : new List<Node>();
        return items.Where(o => o.Kind == NodeKind.Object).ToList();
    }

    private Change DecryptChange(Node ev) =>
        Change.FromApi(ev, TypeForSlugImpl, DecryptValueImpl, (url, c) => BinaryFetchImpl(url, c));

    /// <summary>
    /// Drain the changes feed through <paramref name="handler"/> one at a time, crash-safely.
    /// <paramref name="handler"/> must be idempotent (at-least-once; dedup on
    /// <see cref="Change.Id"/>). Runs until the feed is empty then returns (no daemon mode —
    /// schedule re-runs yourself).
    /// </summary>
    public async Task ProcessChangesAsync(
        Func<Change, Task> handler,
        ProcessOptions? options = null,
        CancellationToken ct = default)
    {
        await RequestFieldsAsync(ct).ConfigureAwait(false); // ensure the catalog is loaded for typing
        await Pump.ProcessChangesAsync(handler, options, ct).ConfigureAwait(false);
    }

    /// <summary>Raw, UNBUFFERED drain → <c>List&lt;Change&gt;</c> (advanced — you own durability).</summary>
    public async Task<List<Change>> DrainBatchAsync(int max = DefaultConnPage, CancellationToken ct = default)
    {
        await RequestFieldsAsync(ct).ConfigureAwait(false);
        return await Pump.DrainBatchAsync(max, ct).ConfigureAwait(false);
    }

    /// <summary>The local dead-letter store.</summary>
    public List<Node> DeadLetters() => Pump.DeadLetters();

    /// <summary>Re-drive dead-lettered events through <paramref name="handler"/>.</summary>
    public async Task<int> RetryDeadLettersAsync(
        Func<Change, Task> handler,
        ProcessOptions? options = null,
        CancellationToken ct = default)
    {
        await RequestFieldsAsync(ct).ConfigureAwait(false);
        return await Pump.RetryDeadLettersAsync(handler, options, ct).ConfigureAwait(false);
    }

    // ── webhook receiver helpers (config-driven, no key args) ───────────────────────────────────

    /// <summary>Verify a webhook's <c>X-Allus-Signature</c> HMAC.</summary>
    public bool VerifyWebhook(object rawBody, IReadOnlyDictionary<string, string>? headers)
        => Webhooks.VerifyWebhook(rawBody, headers, _config);

    /// <summary>Parse a webhook body → a typed <see cref="Change"/>.</summary>
    public Change ParseWebhook(object rawBody, IReadOnlyDictionary<string, string>? headers)
    {
        EnsureCatalogForWebhook();
        return Webhooks.ParseWebhook(rawBody, headers, _config,
            TypeForSlugImpl, DecryptValueImpl, (url, c) => BinaryFetchImpl(url, c), _accountKey);
    }

    /// <summary>Verify + parse a webhook in one call → <see cref="Change"/>.</summary>
    public Change HandleWebhook(object rawBody, IReadOnlyDictionary<string, string>? headers)
    {
        EnsureCatalogForWebhook();
        return Webhooks.HandleWebhook(rawBody, headers, _config,
            TypeForSlugImpl, DecryptValueImpl, (url, c) => BinaryFetchImpl(url, c), _accountKey);
    }

    // The webhook parse path types the value via the cached request-fields catalog (one lazy fetch,
    // then cached). TypeForSlugImpl loads it on demand, but loading here keeps the lazy load on the
    // synchronous webhook entry points off the value-typing hot path.
    private void EnsureCatalogForWebhook()
    {
        if (_requestFields is null)
            RequestFieldsAsync().GetAwaiter().GetResult();
    }

    // ── company documents (write) ───────────────────────────────────────────────────────────────

    /// <summary>Fetch + cache the recipient RSA public key by share_code (GET /api/keys/{shareCode}).</summary>
    private async Task<RSA> RecipientPublicKeyAsync(string shareCode, CancellationToken ct = default)
    {
        if (_pubkeyCache.TryGetValue(shareCode, out var cached))
            return cached;
        var body = await _http.GetAsync($"{KeysPath}/{shareCode}", ct: ct).ConfigureAwait(false);
        var spki = body.Kind == NodeKind.Object ? body.Get("public_key").AsString() : null;
        if (string.IsNullOrEmpty(spki))
            throw new ApiException(0, "keys.not_found", $"no public_key for share_code {shareCode}");
        var key = Crypto.LoadPublicKey(spki);
        _pubkeyCache[shareCode] = key;
        return key;
    }

    /// <summary>
    /// Resolve a target's share_code (the recipient public-key handle). Prefers a single-connection
    /// fetch (carries <c>share_code</c>); falls back to a connections scan by <c>user_id</c>. Pass
    /// <c>shareCode</c> to <see cref="CreateDocumentAsync"/> to skip this entirely.
    /// </summary>
    private async Task<string> ResolveShareCodeAsync(
        string? connectionId, string? personUserId, CancellationToken ct)
    {
        if (!string.IsNullOrEmpty(connectionId))
        {
            var body = await _http.GetAsync($"{ConnectionsPath}/{connectionId}", ct: ct).ConfigureAwait(false);
            var sc = body.Kind == NodeKind.Object ? body.Get("share_code").AsString() : null;
            if (!string.IsNullOrEmpty(sc)) return sc!;
        }
        if (!string.IsNullOrEmpty(personUserId))
        {
            await foreach (var conn in ConnectionsAsync(ct: ct).ConfigureAwait(false))
            {
                var raw = conn.Raw as IReadOnlyDictionary<string, object?>;
                var rawUserId = raw is not null && raw.TryGetValue("user_id", out var u) ? u as string : null;
                if (rawUserId == personUserId || conn.PersonId == personUserId)
                {
                    var sc = raw is not null && raw.TryGetValue("share_code", out var s) ? s as string : null;
                    if (!string.IsNullOrEmpty(sc)) return sc!;
                }
            }
        }
        throw new ConfigException(
            "could not resolve a share_code for the target — pass shareCode explicitly");
    }

    /// <summary>
    /// Create a company document for a connection / person (PER-PERSON), or BROADCAST (no target).
    /// <c>payloadKind="json"</c> → <paramref name="jsonValue"/> (object). <c>payloadKind="file"</c> →
    /// <paramref name="fileBytes"/> (+ <paramref name="fileMime"/>). For a broadcast file, the API
    /// validates the <c>original_name</c> extension; pass <paramref name="fileName"/> to set it
    /// explicitly, otherwise it is derived from <paramref name="fileMime"/> when <paramref name="name"/>
    /// has no allowed extension.
    ///
    /// Encryption is decided by the TARGET, not by is_private:
    ///   PER-PERSON (connectionId/personUserId given) → the value is ALWAYS encrypted FOR THE
    ///     RECIPIENT (share_code resolved when not given) before it leaves the process — for EVERY
    ///     per-person doc, private or not. NO key argument.
    ///   BROADCAST (no target) → the value is sent PLAINTEXT. A broadcast MUST be non-private
    ///     (a plaintext value cannot be locked); <c>isPrivate=true</c> therefore requires a target.
    ///
    /// is_private is a DISPLAY-ONLY flag passed through to the API.
    /// </summary>
    public async Task<Document> CreateDocumentAsync(
        string name,
        string payloadKind,
        string kind = "document",
        bool isPrivate = false,
        string? description = null,
        string? connectionId = null,
        string? personUserId = null,
        string? shareCode = null,
        object? jsonValue = null,
        byte[]? fileBytes = null,
        string? fileMime = null,
        string? fileName = null,
        bool requiresSignature = false,
        bool requiresAcceptance = false,
        object? metadata = null,
        string? status = null,
        CancellationToken ct = default)
    {
        if (payloadKind is not ("json" or "file"))
            throw new ConfigException("payloadKind must be 'json' or 'file'");
        if (kind is not ("document" or "agreement" or "subscription"))
            throw new ConfigException("kind must be 'document', 'agreement' or 'subscription'");

        Dictionary<string, object?>? target = null;
        if (!string.IsNullOrEmpty(connectionId))
            target = new Dictionary<string, object?> { ["connection_id"] = connectionId };
        else if (!string.IsNullOrEmpty(personUserId))
            target = new Dictionary<string, object?> { ["person_user_id"] = personUserId };
        // (else: broadcast — target stays null)

        var perPerson = target is not null;
        // A contract (agreement/subscription, or either flag) is ALWAYS per-person → it must target one person.
        var isContract = kind is "agreement" or "subscription" || requiresSignature || requiresAcceptance;
        if (isContract && !perPerson)
            throw new ConfigException("a contract must target one connected person");
        if (isPrivate && !perPerson)
            throw new ConfigException("isPrivate=true requires a per-person target (broadcast is plaintext)");

        RSA? pubkey = null;
        if (perPerson)
        {
            var sc = shareCode ?? await ResolveShareCodeAsync(connectionId, personUserId, ct).ConfigureAwait(false);
            pubkey = await RecipientPublicKeyAsync(sc, ct).ConfigureAwait(false);
        }

        var body = new Dictionary<string, object?>
        {
            ["kind"] = kind,
            ["name"] = name,
            ["payload_kind"] = payloadKind,
            ["is_private"] = isPrivate,
            ["requires_signature"] = requiresSignature,
            ["requires_acceptance"] = requiresAcceptance,
            ["target"] = target,
        };
        if (description is not null) body["description"] = description;
        if (metadata is not null) body["metadata"] = metadata;
        if (status is not null) body["status"] = status;

        if (payloadKind == "json")
        {
            if (jsonValue is null)
                throw new ConfigException("jsonValue is required for payloadKind='json'");
            body["value"] = perPerson
                ? Crypto.EncryptForPublicKey(JsonSerializer.Serialize(jsonValue), pubkey!).ToObjectGraph()
                : jsonValue;
            var created = await _http.PostAsync(DocumentsPath, jsonBody: body, ct: ct).ConfigureAwait(false);
            return Document.FromApi(DocObj(created), DecryptValueImpl);
        }

        // file: create the metadata row first, then upload bytes to /{id}/file.
        if (fileBytes is null)
            throw new ConfigException("fileBytes is required for payloadKind='file'");
        var createdFile = await _http.PostAsync(DocumentsPath, jsonBody: body, ct: ct).ConfigureAwait(false);
        var doc = Document.FromApi(DocObj(createdFile), DecryptValueImpl);
        // The metadata row exists before the bytes are uploaded; if the upload fails, best-effort
        // delete it so a failed CreateDocumentAsync leaves no dangling {"_pending": true} document.
        // Cleanup errors are swallowed and the ORIGINAL upload error is re-thrown.
        try
        {
            if (perPerson)
            {
                // Encrypt the file bytes (EVERY per-person doc): wrap the file envelope string, then send
                // {"value": "<wrapper-as-JSON-string>"} as application/json. The API requires value to be a
                // STRING that JSON-decodes to the {"_enc":1,…} wrapper.
                var envelope = JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["file"] = DataUri(fileBytes, fileMime),
                });
                var wrapper = Crypto.EncryptForPublicKey(envelope, pubkey!);
                await _http.PostAsync($"{DocumentsPath}/{doc.Id}/file",
                    jsonBody: new Dictionary<string, object?> { ["value"] = wrapper.ToJsonString() },
                    ct: ct).ConfigureAwait(false);
            }
            else
            {
                // Broadcast — plaintext file data URI as application/json {"file": …, "original_name": …}.
                await _http.PostAsync($"{DocumentsPath}/{doc.Id}/file",
                    jsonBody: new Dictionary<string, object?>
                    {
                        ["file"] = DataUri(fileBytes, fileMime),
                        ["original_name"] = BroadcastOriginalName(fileName, name, fileMime),
                    },
                    ct: ct).ConfigureAwait(false);
            }
        }
        catch
        {
            try
            {
                await DeleteDocumentAsync(doc.Id!, ct).ConfigureAwait(false);
            }
            catch
            {
                // best-effort cleanup — swallow
            }
            throw;
        }
        return doc;
    }

    /// <summary>List this service's documents (paged; optional person/status filter).</summary>
    public async Task<List<Document>> ListDocumentsAsync(
        string? personUserId = null,
        string? status = null,
        int limit = 100,
        int offset = 0,
        CancellationToken ct = default)
    {
        var query = new Dictionary<string, string>
        {
            ["limit"] = Math.Max(1, limit).ToString(),
            ["offset"] = Math.Max(0, offset).ToString(),
        };
        if (!string.IsNullOrEmpty(personUserId)) query["person_user_id"] = personUserId;
        if (!string.IsNullOrEmpty(status)) query["status"] = status;
        var body = await _http.GetAsync(DocumentsPath, query, ct).ConfigureAwait(false);
        return Document.ListFromApi(body, DecryptValueImpl);
    }

    /// <summary>Fetch one document by id → <see cref="Document"/>.</summary>
    public async Task<Document> DocumentAsync(string documentId, CancellationToken ct = default)
    {
        var body = await _http.GetAsync($"{DocumentsPath}/{documentId}", ct: ct).ConfigureAwait(false);
        return Document.FromApi(DocObj(body), DecryptValueImpl);
    }

    /// <summary>Set a document's lifecycle status (offering|ready_to_sign|active|active_but_ending|ended).</summary>
    public async Task<Document> UpdateDocumentStatusAsync(string documentId, string status, CancellationToken ct = default)
    {
        var body = await _http.PutAsync($"{DocumentsPath}/{documentId}",
            jsonBody: new Dictionary<string, object?> { ["status"] = status }, ct: ct).ConfigureAwait(false);
        return Document.FromApi(DocObj(body), DecryptValueImpl);
    }

    /// <summary>Update a document's metadata / name / description.</summary>
    public async Task<Document> UpdateDocumentMetadataAsync(
        string documentId,
        object? metadata = null,
        string? name = null,
        string? description = null,
        CancellationToken ct = default)
    {
        var payload = new Dictionary<string, object?>();
        if (metadata is not null) payload["metadata"] = metadata;
        if (name is not null) payload["name"] = name;
        if (description is not null) payload["description"] = description;
        if (payload.Count == 0)
            throw new ConfigException("UpdateDocumentMetadataAsync needs metadata, name, or description");
        var body = await _http.PutAsync($"{DocumentsPath}/{documentId}", jsonBody: payload, ct: ct).ConfigureAwait(false);
        return Document.FromApi(DocObj(body), DecryptValueImpl);
    }

    /// <summary>Delete a document (and its on-disk file).</summary>
    public async Task DeleteDocumentAsync(string documentId, CancellationToken ct = default)
    {
        await _http.DeleteAsync($"{DocumentsPath}/{documentId}", ct).ConfigureAwait(false);
    }

    // ── connect requests (service-initiated; idea 2) ────────────────────────────

    /// <summary>
    /// Invite a person (by their share code) to connect to THIS service. Wraps
    /// <c>POST /api/company-data/connect-requests</c> — auto-scoped to the calling client's service.
    /// Fire-and-forget: the person accepts or rejects, and the outcome reaches you only via the
    /// change feed / webhooks (<c>connection_request_accepted</c> / <c>connection_request_rejected</c>).
    /// No crypto, no key handling (the request carries no values). Returns the new request_id.
    /// </summary>
    public async Task<string> SendConnectRequestAsync(string shareCode, CancellationToken ct = default)
    {
        var code = (shareCode ?? "").Trim();
        if (code.Length == 0) throw new ConfigException("shareCode is required");
        var body = await _http.PostAsync(ConnectRequestsPath,
            jsonBody: new Dictionary<string, object?> { ["share_code"] = code }, ct: ct).ConfigureAwait(false);
        var rid = body.Get("request_id").AsString();
        if (string.IsNullOrEmpty(rid))
            throw new ApiException(0, "company_connections.request_failed", "no request_id in response");
        return rid!;
    }

    // ── contract-flow runs (company side — the company is a bound party) ─────────────────────────

    /// <summary>
    /// Start a run for a connection. <paramref name="bindings"/> = {party_key: user_id} covering the
    /// flow's parties (each bound user must be the company or the connected person). Pins the flow's
    /// latest PUBLISHED version. <paramref name="connectionId"/> is the person-side
    /// company_service_connections.id for this service. Returns the created
    /// <see cref="FlowRun"/> (status awaiting_&lt;entry node's party&gt;).
    /// </summary>
    public async Task<FlowRun> TriggerFlowRunAsync(
        string flowId, string connectionId, IReadOnlyDictionary<string, string> bindings,
        CancellationToken ct = default)
    {
        var body = new Dictionary<string, object?>
        {
            ["target"] = new Dictionary<string, object?> { ["connection_id"] = connectionId },
            ["bindings"] = bindings,
        };
        var created = await _http.PostAsync($"{FlowsPath}/{flowId}/runs", jsonBody: body, ct: ct).ConfigureAwait(false);
        return FlowRun.FromApi(created);
    }

    /// <summary>
    /// List this service's runs. An empty/null <paramref name="status"/> defaults to the actionable
    /// "awaiting_company" queue; pass "*" for the unfiltered list, or any status filter.
    /// </summary>
    public async Task<IReadOnlyList<FlowRun>> FlowRunsAsync(string? status = "awaiting_company", CancellationToken ct = default)
    {
        Dictionary<string, string>? query = null;
        if (!string.IsNullOrEmpty(status) && status != "*")
            query = new Dictionary<string, string> { ["status"] = status! };
        var body = await _http.GetAsync(FlowRunsPath, query, ct).ConfigureAwait(false);
        return ListItems(body).Select(FlowRun.FromApi).ToList();
    }

    /// <summary>Fetch one run by id → <see cref="FlowRun"/>.</summary>
    public async Task<FlowRun> FlowRunAsync(string runId, CancellationToken ct = default)
    {
        var body = await _http.GetAsync($"{FlowRunsPath}/{runId}", ct: ct).ConfigureAwait(false);
        return FlowRun.FromApi(body);
    }

    /// <summary>
    /// The service RSA public key = the public half of the loaded service private key. The run payload
    /// does NOT carry the service public key; the company makes its own answer copy by encrypting to
    /// the public half of the same RSA pair it already holds (config-only key handling — no fetch).
    /// </summary>
    private RSA ServicePublicKey()
    {
        if (_servicePublicKey is null)
        {
            var pub = RSA.Create();
            pub.ImportParameters(_privateKey.ExportParameters(false));
            _servicePublicKey = pub;
        }
        return _servicePublicKey;
    }

    /// <summary>
    /// Decrypt the company's service-key answer copies → {slug: plaintext}. Only the rows whose
    /// for_user_id is the company's bound user_id are decryptable with the service private key.
    /// </summary>
    private Dictionary<string, object?> DecryptRunAnswers(FlowRun run)
    {
        var serviceUid = run.ServiceUserId;
        var outMap = new Dictionary<string, object?>();
        foreach (var row in run.Answers)
        {
            if (row.Get("for_user_id").AsString() != serviceUid) continue;
            var slug = row.Get("slug").AsString();
            if (string.IsNullOrEmpty(slug) || !row.Has("value")) continue;
            outMap[slug!] = DecryptValueImpl(row.Get("value"));
        }
        return outMap;
    }

    /// <summary>
    /// Resolve a person party's RSA public key for per-party answer encryption. Prefers a
    /// caller-supplied key, else resolves the person's share_code from the run's connection →
    /// GET /api/keys/{code}.
    ///
    /// Integration gap: the run payload exposes neither person public keys nor per-binding share
    /// codes, so the SDK resolves via the connection. Supply <paramref name="partyPubKeys"/> to skip.
    /// </summary>
    private async Task<RSA> FlowPersonPublicKeyAsync(
        FlowRun run, string uid, IReadOnlyDictionary<string, RSA> partyPubKeys, CancellationToken ct)
    {
        if (partyPubKeys.TryGetValue(uid, out var supplied)) return supplied;
        var sc = await ResolveShareCodeAsync(run.ConnectionId, uid, ct).ConfigureAwait(false);
        return await RecipientPublicKeyAsync(sc, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Fill the company's current node and advance. <paramref name="fill"/> = {slug: plaintext_value}
    /// the caller computed for this node. For EACH answer the SDK encrypts one copy per bound party
    /// (the company via the service public key; each person party via their public key), evaluates the
    /// next node LOCALLY (ordered outgoing edges, first match) over the full decrypted answer map, and
    /// POSTs {answers, next_node?/leaf, next_party?}. Returns the refreshed <see cref="FlowRun"/>. A
    /// document-mode leaf leaves the run "generating" — call <see cref="GenerateFlowDocumentAsync"/>
    /// (or <see cref="ProcessFlowRunAsync"/>, which chains it). <paramref name="partyPubKeys"/> may be
    /// null; supply it to skip the share_code → /api/keys resolution for person parties.
    /// </summary>
    public async Task<FlowRun> SubmitFlowAnswersAsync(
        FlowRun run, IReadOnlyDictionary<string, object?> fill,
        IReadOnlyDictionary<string, RSA>? partyPubKeys = null, CancellationToken ct = default)
    {
        partyPubKeys ??= new Dictionary<string, RSA>();
        var answersSoFar = DecryptRunAnswers(run);
        var full = new Dictionary<string, object?>(answersSoFar);
        foreach (var (k, v) in fill) full[k] = v;
        var svcPub = ServicePublicKey();

        var answersOut = new List<object?>();
        foreach (var (slug, val) in fill)
        {
            var plain = val is string s ? s : JsonSerializer.Serialize(val);
            var values = new List<object?>();
            foreach (var uid in run.Bindings.Values)
            {
                var key = uid == run.ServiceUserId
                    ? svcPub
                    : await FlowPersonPublicKeyAsync(run, uid, partyPubKeys, ct).ConfigureAwait(false);
                values.Add(new Dictionary<string, object?>
                {
                    ["for_user_id"] = uid,
                    ["value"] = Crypto.EncryptForPublicKey(plain, key).ToObjectGraph(),
                });
            }
            answersOut.Add(new Dictionary<string, object?> { ["slug"] = slug, ["values"] = values });
        }

        var (leaf, nextNode) = ComputeNextNode(run.Definition, run.CurrentNode, full);
        var body = new Dictionary<string, object?> { ["answers"] = answersOut };
        if (leaf)
        {
            body["leaf"] = true;
        }
        else
        {
            body["next_node"] = nextNode;
            body["next_party"] = PartyOf(run.Definition, nextNode);
        }
        var res = await _http.PostAsync($"{FlowRunsPath}/{run.Id}/answers", jsonBody: body, ct: ct).ConfigureAwait(false);
        return FlowRun.FromApi(res);
    }

    /// <summary>
    /// Document-mode company leaf: one-time-key value gather → POST /generate. Builds a random 32-byte
    /// AES-256-GCM key, encrypts JSON({slug: plaintext}) of the company's decrypted answers, packs
    /// iv(12)||ciphertext||tag(16), and POSTs {otk: base64(key), values: base64(blob)}. Returns the
    /// API response Node {document_id, status: "awaiting_signature"} (idempotent).
    /// </summary>
    public async Task<Node> GenerateFlowDocumentAsync(FlowRun run, CancellationToken ct = default)
    {
        var answers = DecryptRunAnswers(run);
        var strMap = answers.ToDictionary(
            kv => kv.Key, kv => kv.Value is string s ? s : JsonSerializer.Serialize(kv.Value));
        var payload = System.Text.Encoding.UTF8.GetBytes(JsonSerializer.Serialize(strMap));
        var otk = RandomNumberGenerator.GetBytes(32);
        var iv = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[payload.Length];
        var tag = new byte[16];
        using (var aes = new AesGcm(otk, 16))
            aes.Encrypt(iv, payload, ciphertext, tag);
        var blob = new byte[12 + ciphertext.Length + 16]; // iv(12) || ciphertext || tag(16)
        Buffer.BlockCopy(iv, 0, blob, 0, 12);
        Buffer.BlockCopy(ciphertext, 0, blob, 12, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, blob, 12 + ciphertext.Length, 16);
        var body = new Dictionary<string, object?>
        {
            ["otk"] = Convert.ToBase64String(otk),
            ["values"] = Convert.ToBase64String(blob),
        };
        return await _http.PostAsync($"{FlowRunsPath}/{run.Id}/generate", jsonBody: body, ct: ct).ConfigureAwait(false);
    }

    /// <summary>
    /// High-level company turn: load → (if our turn) fill + advance + generate.
    /// <paramref name="fillNode"/>(node, answers) returns {slug: value}; the SDK encrypts per party,
    /// submits, and — if the submit landed on a document-mode leaf — calls
    /// <see cref="GenerateFlowDocumentAsync"/>. Returns the latest <see cref="FlowRun"/>; when the run
    /// is not awaiting the company it is returned untouched.
    /// </summary>
    public async Task<FlowRun> ProcessFlowRunAsync(
        string runId,
        Func<Node, IReadOnlyDictionary<string, object?>, IReadOnlyDictionary<string, object?>?> fillNode,
        IReadOnlyDictionary<string, RSA>? partyPubKeys = null,
        CancellationToken ct = default)
    {
        var run = await FlowRunAsync(runId, ct).ConfigureAwait(false);
        var companyParty = run.CompanyPartyKey;
        if (companyParty is null || run.Status != $"awaiting_{companyParty}")
            return run; // not our turn (or company not bound)
        var node = NodeByKey(run.Definition, run.CurrentNode);
        if (node is null) return run;
        var answers = DecryptRunAnswers(run);
        var fill = fillNode(node, answers) ?? new Dictionary<string, object?>();
        var merged = new Dictionary<string, object?>(answers);
        foreach (var (k, v) in fill) merged[k] = v;
        var (wasLeaf, _) = ComputeNextNode(run.Definition, run.CurrentNode, merged);
        run = await SubmitFlowAnswersAsync(run, fill, partyPubKeys, ct).ConfigureAwait(false);
        var mode = run.OutputMode ?? run.Definition.Get("output_mode").AsString();
        if (wasLeaf && mode == "document")
        {
            await GenerateFlowDocumentAsync(run, ct).ConfigureAwait(false);
            run = await FlowRunAsync(run.Id!, ct).ConfigureAwait(false);
        }
        return run;
    }

    // ── helpers ──────────────────────────────────────────────────────────────────────────────

    private static RSA LoadServiceKey(Config config)
    {
        string pem;
        try { pem = File.ReadAllText(config.ServicePrivateKey); }
        catch (IOException ex)
        {
            throw new ConfigException(
                $"could not read service_private_key PEM: {config.ServicePrivateKey}: {ex.Message}", ex);
        }
        try { return Crypto.LoadPrivateKey(pem, config.KeyPassphrase); }
        catch (DecryptException ex)
        {
            // A bad passphrase / malformed PEM is a configuration problem (fail fast).
            throw new ConfigException($"could not load service private key: {ex.Message}", ex);
        }
    }

    private static List<Node> ListItems(Node body)
    {
        if (body.Kind == NodeKind.Object)
            return body.Has("items") ? body.Get("items").AsList() : new List<Node>();
        if (body.Kind == NodeKind.List) return body.AsList();
        return new List<Node>();
    }

    /// <summary>
    /// Pull the document object out of a create/get/update response. The API returns the bare
    /// document object; tolerate a <c>{"document": {...}}</c> wrapper too.
    /// </summary>
    private static Node DocObj(Node body)
    {
        if (body.Kind == NodeKind.Object)
        {
            var inner = body.Get("document");
            if (inner.Kind == NodeKind.Object) return inner;
            return body;
        }
        return Node.Object(new Dictionary<string, Node>());
    }

    /// <summary>Look up a node by key in the pinned definition graph.</summary>
    private static Node? NodeByKey(Node definition, string? key)
    {
        if (definition.Get("nodes").Kind != NodeKind.List) return null;
        foreach (var n in definition.Get("nodes").AsList())
            if (n.Kind == NodeKind.Object && n.Get("key").AsString() == key) return n;
        return null;
    }

    /// <summary>
    /// The next node after <paramref name="fromKey"/> — ordered outgoing edges, first match wins.
    /// Leaf is true when there is no outgoing edge or none matched (a dead-end is a leaf).
    /// </summary>
    private static (bool Leaf, string? Next) ComputeNextNode(
        Node definition, string? fromKey, IReadOnlyDictionary<string, object?> answers)
    {
        var edges = (definition.Get("edges").Kind == NodeKind.List ? definition.Get("edges").AsList() : new List<Node>())
            .Where(e => e.Kind == NodeKind.Object && e.Get("from").AsString() == fromKey)
            .OrderBy(e => EdgeSort(e))
            .ToList();
        if (edges.Count == 0) return (true, null);
        foreach (var e in edges)
            if (FlowCondition.Evaluate(e.Get("condition"), answers))
                return (false, e.Get("to").AsString());
        return (true, null);
    }

    private static double EdgeSort(Node edge)
    {
        var s = edge.Get("sort").RawScalar;
        return s switch
        {
            long l => l,
            double d => d,
            int i => i,
            string str when double.TryParse(str, System.Globalization.NumberStyles.Any,
                System.Globalization.CultureInfo.InvariantCulture, out var n) => n,
            _ => 0,
        };
    }

    /// <summary>The party that owns <paramref name="nodeKey"/> in the definition.</summary>
    private static string? PartyOf(Node definition, string? nodeKey)
    {
        var node = NodeByKey(definition, nodeKey);
        return node?.Get("party").AsString();
    }

    /// <summary>Build a <c>data:&lt;mime&gt;;base64,&lt;…&gt;</c> URI for the per-person file envelope.</summary>
    private static string DataUri(byte[] fileBytes, string? mime) =>
        $"data:{mime ?? "application/octet-stream"};base64,{Convert.ToBase64String(fileBytes)}";

    // Allowed broadcast-document MIME → file extension (mirrors the API's allowlist).
    private static readonly Dictionary<string, string> MimeExt = new()
    {
        ["application/pdf"] = "pdf",
        ["application/msword"] = "doc",
        ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"] = "docx",
        ["application/vnd.ms-excel"] = "xls",
        ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"] = "xlsx",
        ["image/png"] = "png",
        ["image/jpeg"] = "jpg",
    };

    private static readonly HashSet<string> AllowedDocExts = new()
    {
        "pdf", "doc", "docx", "xls", "xlsx", "png", "jpg", "jpeg",
    };

    /// <summary>
    /// <c>original_name</c> for a broadcast file upload. The API validates its extension against an
    /// allowlist, but <paramref name="name"/> is a human label that often has no extension. Use an
    /// explicit <paramref name="fileName"/>; else keep <paramref name="name"/> if it already ends in
    /// an allowed extension; else append the extension derived from <paramref name="fileMime"/> (so
    /// <c>"Price list"</c> + <c>application/pdf</c> → <c>"Price list.pdf"</c>).
    /// </summary>
    private static string BroadcastOriginalName(string? fileName, string name, string? fileMime)
    {
        if (!string.IsNullOrEmpty(fileName))
            return fileName;
        var dot = name.LastIndexOf('.');
        var ext = dot >= 0 ? name[(dot + 1)..].ToLowerInvariant() : "";
        if (AllowedDocExts.Contains(ext))
            return name;
        return MimeExt.TryGetValue((fileMime ?? "").ToLowerInvariant(), out var derived)
            ? $"{name}.{derived}"
            : name;
    }

    private static double ConnBackoff(double? retryAfter, int attempt)
    {
        if (retryAfter is >= 0)
            return Math.Min(retryAfter.Value, ConnMaxBackoffSeconds);
        return Math.Min(ConnDefaultBackoffSeconds * Math.Pow(2, attempt - 1), ConnMaxBackoffSeconds);
    }

    /// <summary>Test-only accessor for the service-key decrypt closure.</summary>
    internal string DecryptValueForTest(object wrapper) => DecryptValueImpl(wrapper);

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _privateKey.Dispose();
        _accountKey?.Dispose();
        _servicePublicKey?.Dispose();
        foreach (var key in _pubkeyCache.Values) key.Dispose();
    }
}
