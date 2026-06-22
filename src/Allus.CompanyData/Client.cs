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
    public async Task<RSA> RecipientPublicKeyAsync(string shareCode, CancellationToken ct = default)
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
    /// <paramref name="fileBytes"/> (+ <paramref name="fileMime"/>).
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
        if (perPerson)
        {
            // Encrypt the file bytes (EVERY per-person doc): wrap the file envelope string, then send
            // the wrapper as bytes.
            var envelope = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["file"] = DataUri(fileBytes, fileMime),
            });
            var wrapper = Crypto.EncryptForPublicKey(envelope, pubkey!);
            await _http.PostAsync($"{DocumentsPath}/{doc.Id}/file",
                rawBody: System.Text.Encoding.UTF8.GetBytes(wrapper.ToJsonString()),
                contentType: "application/json", ct: ct).ConfigureAwait(false);
        }
        else
        {
            // Broadcast — raw plaintext bytes.
            await _http.PostAsync($"{DocumentsPath}/{doc.Id}/file",
                rawBody: fileBytes,
                contentType: fileMime ?? "application/octet-stream", ct: ct).ConfigureAwait(false);
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
    public async Task<Document> GetDocumentAsync(string documentId, CancellationToken ct = default)
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

    /// <summary>Build a <c>data:&lt;mime&gt;;base64,&lt;…&gt;</c> URI for the per-person file envelope.</summary>
    private static string DataUri(byte[] fileBytes, string? mime) =>
        $"data:{mime ?? "application/octet-stream"};base64,{Convert.ToBase64String(fileBytes)}";

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
        foreach (var key in _pubkeyCache.Values) key.Dispose();
    }
}
