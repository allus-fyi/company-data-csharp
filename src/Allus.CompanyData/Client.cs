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
//   * Slug catalog — RequestFieldsAsync() is fetched once + cached; its slug→type map names the
//     TYPE of every value.
//   * Field-type registry — FieldTypesAsync() is fetched beside the catalog and held for the life
//     of the client; it is what a type MEANS, so a value's shape follows the type's resolved
//     primitive and storage lane (a composite parses to a dictionary, a photo/document lane becomes
//     a lazy binary handle) rather than a list of type names. A type the held registry does not
//     carry triggers one bounded refetch.
//   * Binary — a value's BinaryHandle.BytesAsync() GETs the slot file endpoint and returns the file
//     bytes. That endpoint has three 200 shapes — an {"encrypted":true,"value":<wrapper>} JSON body
//     the same service-key decrypt unwraps, an {"encrypted":false,"value":"<envelope>"} JSON body
//     carrying that envelope in the clear, or the raw file bytes under the file's own Content-Type —
//     and BinaryFetchImpl classifies which arrived so the caller never has to. PagesAsync() and
//     MetadataAsync() expose the rest of an envelope.
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
    private const string FieldTypesPath = "/api/contact-field-types";
    private const string LogsPath = Base + "/logs";
    private const string DocumentsPath = Base + "/documents";
    private const string ConnectRequestsPath = Base + "/connect-requests";
    private const string BroadcastPath = Base + "/broadcast"; // POST — one plaintext message to every connection
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

    // The slug catalog, fetched once and held for the life of the client. A slug it does not
    // carry — a request slot configured after this client started — triggers ONE refetch; a slug a
    // refetch still does not carry is remembered in _unresolvedSlugs and never asked for again, so
    // a slot this deployment does not have cannot turn every later value into a round trip.
    private IReadOnlyList<RequestField>? _requestFields;
    private Dictionary<string, string?> _typeBySlug = new();
    private readonly HashSet<string> _unresolvedSlugs = new(StringComparer.Ordinal);

    // The field-type registry, fetched beside the catalog and held for the life of the client. A
    // type it does not carry triggers ONE refetch; a type a refetch still does not resolve is
    // remembered in _unresolvedTypes and never asked for again, so a value of a type this
    // deployment does not have cannot turn every later value into a round trip.
    private FieldTypeRegistry? _fieldTypes;
    private readonly HashSet<string> _unresolvedTypes = new(StringComparer.Ordinal);
    // The last registry load's failure, held so a synchronous reader raises it instead of reading
    // an empty registry. Cleared by the first load that succeeds.
    private Exception? _fieldTypesFailure;
    private Pump? _pump;
    private bool _disposed;

    // Recipient RSA public keys (by share_code) — cached for per-person document encryption. A
    // public key is immutable + not a secret (fetched live, never configured).
    private readonly Dictionary<string, RSA> _pubkeyCache = new();
    /// <summary>
    /// <see cref="Dictionary{TKey,TValue}"/> is not thread-safe, and
    /// <see cref="InvalidatePublicKey"/> is documented as something a WEBHOOK consumer calls from its
    /// own thread — concurrently with an encryption that reads or populates this map. Every access
    /// takes this lock. It is never held across the HTTP fetch, or concurrent encryptions would
    /// serialise behind one round-trip.
    /// </summary>
    private readonly object _pubkeyLock = new();
    /// <summary>
    /// A per-key GENERATION counter, bumped by every invalidation.
    /// <para>Locking the dictionary alone is not enough. The fetch path is check (locked) →
    /// release → HTTP → store (locked), so an <c>InvalidatePublicKey</c> landing between the
    /// release and the store is silently undone: the pre-rotation key is written back AFTER the
    /// removal, the <c>key_rotated</c> event has already been consumed, and with no TTL the
    /// process encrypts to the dead key for the rest of its life — the exact symptom this design
    /// exists to prevent.</para>
    /// <para>The fetch snapshots the generation before releasing the lock and stores only if it
    /// is still current; otherwise it discards its result and the next caller refetches.</para>
    /// </summary>
    private readonly Dictionary<string, ulong> _pubkeyGen = new();

    // The service RSA public key (public half of the loaded private key), derived once.
    private RSA? _servicePublicKey;

    // The plain transport plugin calls reach the forwarder over — never the API transport, which
    // attaches the bearer token and rewrites the base URL.
    private readonly HttpClient _pluginHttp = PluginFlowParty.NewTransport();

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

    private TwoFactorClient? _twoFactor;

    /// <summary>2FA-by-allme — the relying-party challenge API (<c>TwoFactor.ChallengeAsync</c> / <c>.ResultAsync</c>).</summary>
    public TwoFactorClient TwoFactor => _twoFactor ??= new TwoFactorClient(_http, _sleep);

    // ── constructors (config-only keys) ────────────────────────────────────────────────────────

    /// <summary>Build from a JSON config file (env vars override secrets).</summary>
    public static Client FromConfig(string path) => new(Config.FromFile(path));

    /// <summary>Build entirely from <c>ALLUS_*</c> env vars.</summary>
    public static Client FromEnv() => new(Config.FromEnv());

    // ── decryption wiring (closures over the loaded key — never a method arg) ──────────────────

    private string DecryptValueImpl(object wrapper) => Crypto.Decrypt(wrapper, _privateKey);

    /// <summary>
    /// Fetch a company-facing binary file endpoint and classify its response.
    /// <para>The endpoint has THREE 200 shapes and which one arrives is not the company's to
    /// predict: a person whose source field is PRIVATE yields <c>application/json</c>
    /// <c>{"encrypted":true,"value":&lt;wrapper&gt;}</c>; a NON-PRIVATE source whose type stores more
    /// than one file or declares metadata entries yields
    /// <c>{"encrypted":false,"value":"&lt;envelope&gt;"}</c>; every other non-private source yields the
    /// file's own Content-Type and the bytes themselves. The bytes shape is told apart on
    /// <c>Content-Type</c> and never by sniffing the body — a PDF or an image that happened to start
    /// with a brace would be indistinguishable from a wrapper — and inside a structured body it is
    /// <c>encrypted</c> that decides.</para>
    /// <para>A 410 <c>company_data.file_expired</c> (the answer's 90-day retention has elapsed)
    /// surfaces as an <see cref="ApiException"/> whose <see cref="ApiException.Details"/> carry
    /// <c>content_sha256</c> and <c>expired_at</c>.</para>
    /// </summary>
    private async Task<BinaryFetchResult> BinaryFetchImpl(string valueUrl, CancellationToken ct)
    {
        var resp = await _http.GetResponseAsync(valueUrl, ct: ct).ConfigureAwait(false);
        var contentType = resp.Header("Content-Type") ?? "";
        var digest = resp.Header("X-Allus-Content-Sha256");

        // Plaintext is claimed ONLY on a Content-Type that positively says so. A missing or empty
        // header falls through to the structured path — the historical shape — because the two failure
        // modes are not symmetrical: mistaking a wrapper for file bytes writes the ciphertext envelope
        // to disk as if it were the document and nothing complains, while mistaking bytes for a wrapper
        // fails loudly at the parse. Guess towards the loud one.
        var isStructured = contentType.Length == 0
            || contentType.Contains("json", StringComparison.OrdinalIgnoreCase)
            || contentType.Contains("xml", StringComparison.OrdinalIgnoreCase);
        if (!isStructured)
            return new BinaryFetchResult(
                Encrypted: false,
                Bytes: resp.BodyBytes,
                ContentType: contentType,
                ContentSha256: digest);

        // Parsed by what the RESPONSE says it is, never by the configured Format: these four routes
        // answer application/json on both structured arms whatever the client speaks.
        var body = _http.ParseResponseByContentType(resp);
        // `encrypted: false` with a string `value` is the PLAINTEXT ENVELOPE arm; every other
        // structured body is the wrapper arm, which is what the bare-wrapper routes (a company's own
        // contract copy, its run slot file) answer with.
        if (body.Kind == NodeKind.Object
            && body.Get("encrypted").RawScalar is bool encryptedFlag
            && !encryptedFlag
            && body.Get("value").RawScalar is string envelopeJson)
        {
            return new BinaryFetchResult(
                Encrypted: false,
                ContentType: contentType.Length == 0 ? null : contentType,
                ContentSha256: digest,
                Envelope: envelopeJson);
        }
        var wrapper = body.Kind == NodeKind.Object && body.Has("value")
            ? body.Get("value")
            : body; // defensive: some shapes might return the wrapper directly
        return new BinaryFetchResult(
            Encrypted: true,
            Wrapper: wrapper,
            ContentType: contentType.Length == 0 ? null : contentType,
            ContentSha256: digest);
    }

    /// <summary>Resolve a request slug to its field type (loads the catalog once).</summary>
    /// <remarks>
    /// The payload is the trigger. The SLUG a value or a change names is what the held catalog may
    /// not carry, and no walk of that catalog can discover it; the slug itself asks for one catalog
    /// refetch, and the type that refetch names goes on to the registry heal. The model factory
    /// that calls this is synchronous, so it blocks on the refetch exactly as it already blocks on
    /// the first catalog load.
    /// </remarks>
    private string? TypeForSlugImpl(string slug)
    {
        if (_requestFields is null)
            RequestFieldsAsync().GetAwaiter().GetResult();
        if (!_typeBySlug.ContainsKey(slug))
            EnsureSlugKnownAsync(slug, CancellationToken.None).GetAwaiter().GetResult();
        return _typeBySlug.GetValueOrDefault(slug);
    }

    /// <summary>One bounded refetch of the catalog when it does not carry a slug in use.</summary>
    /// <remarks>
    /// A request slot configured after this client started is what makes a slug unknown here, and
    /// one refetch of the catalog is what resolves it — together with the type that slot
    /// introduced, which the reload puts through the registry heal. A slug still absent afterwards
    /// belongs to no slot this client can see, so it is remembered and never asked for again.
    /// </remarks>
    private async Task EnsureSlugKnownAsync(string slug, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(slug) || _typeBySlug.ContainsKey(slug) || _unresolvedSlugs.Contains(slug))
            return;
        await LoadRequestFieldsAsync(ct).ConfigureAwait(false);
        if (!_typeBySlug.ContainsKey(slug)) _unresolvedSlugs.Add(slug);
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
            await LoadRequestFieldsAsync(ct).ConfigureAwait(false);
        return _requestFields!;
    }

    /// <summary>One fetch of the catalog, replacing the held one only once it has ARRIVED.</summary>
    private async Task LoadRequestFieldsAsync(CancellationToken ct)
    {
        var body = await _http.GetAsync(RequestFieldsPath, ct: ct).ConfigureAwait(false);
        var fields = RequestField.ListFromApi(body);
        var bySlug = fields.Where(f => f.Slug is not null)
            .GroupBy(f => f.Slug!)
            .ToDictionary(g => g.Key, g => g.First().Type);
        // The catalog is published only once the registry that types it has loaded. Publishing
        // first would let a registry failure leave a cached catalog behind that no later call
        // retries, and every value it types would then be read through a registry that knows
        // nothing.
        await EnsureTypesKnownAsync(bySlug.Values, ct).ConfigureAwait(false);
        _typeBySlug = bySlug;
        _requestFields = fields;
    }

    /// <summary>
    /// The field-type registry — what every TYPE in the catalog means.
    /// </summary>
    /// <remarks>
    /// Fetched from <c>GET /api/contact-field-types</c> beside the request-field catalog and held in
    /// memory for the life of the client. It says which primitive draws a type, which named check
    /// verifies it, which regexes it adds, which sub-fields it carries and on which storage lane its
    /// value lives — so a value's shape and a value's validity both follow the served rows rather
    /// than a list of type names.
    /// </remarks>
    public async Task<FieldTypeRegistry> FieldTypesAsync(CancellationToken ct = default)
    {
        _fieldTypes ??= await LoadFieldTypesAsync(ct).ConfigureAwait(false);
        return _fieldTypes;
    }

    /// <summary>One fetch of the registry rows, with no caching of its own.</summary>
    /// <remarks>
    /// A failure is remembered as a failure: re-thrown to the caller that asked, and recorded so a
    /// synchronous reader raises it too rather than reading an empty registry, whose "accept
    /// anything" answer for an unknown type would be indistinguishable from a real one.
    /// </remarks>
    private async Task<FieldTypeRegistry> LoadFieldTypesAsync(CancellationToken ct)
    {
        try
        {
            // The registry route answers JSON to every caller — it is not one of the company-data
            // routes that honour the configured Format — so its body is parsed as JSON whatever this
            // client speaks elsewhere.
            var resp = await _http.GetResponseAsync(FieldTypesPath, ct: ct).ConfigureAwait(false);
            var registry = new FieldTypeRegistry(_http.ParseResponseAsJson(resp));
            _fieldTypesFailure = null;
            return registry;
        }
        catch (Exception exc)
        {
            _fieldTypesFailure = exc;
            throw;
        }
    }

    /// <summary>
    /// One bounded refetch when the held registry does not carry a type in use.
    /// </summary>
    /// <remarks>
    /// A row added to the registry after this client started is what makes a type unknown here, and
    /// one refetch is what resolves it. A type still absent afterwards is this deployment's answer,
    /// not a stale cache, so it is remembered and never asked for again.
    /// </remarks>
    private async Task EnsureTypesKnownAsync(IEnumerable<string?> types, CancellationToken ct)
    {
        var registry = await FieldTypesAsync(ct).ConfigureAwait(false);
        var missing = types
            .Where(t => !string.IsNullOrEmpty(t) && t != PluginValue.TypeKey && !registry.Knows(t) && !_unresolvedTypes.Contains(t!))
            .Select(t => t!)
            .ToList();
        if (missing.Count == 0) return;
        // The refetch replaces the held registry only once it has ARRIVED. Clearing first would let
        // a failed refetch leave no registry at all, and every type would then read as unknown — a
        // verdict about the deployment standing in for a fetch that did not happen.
        registry = await LoadFieldTypesAsync(ct).ConfigureAwait(false);
        _fieldTypes = registry;
        foreach (var type in missing)
        {
            if (!registry.Knows(type)) _unresolvedTypes.Add(type);
        }
    }

    /// <summary>The registry the synchronous model factories read; the catalog loads it first.</summary>
    /// <remarks>
    /// A load that FAILED raises that failure here rather than answering an empty registry — an
    /// unloaded registry says every type is unknown, and "unknown accepts anything" is a verdict
    /// about the deployment, never a stand-in for a fetch that did not happen. A client that has
    /// never asked for the registry — a receiver calling only the webhook parsers — reads the empty
    /// one, which is the honest answer for a client that fetched nothing.
    /// </remarks>
    private FieldTypeRegistry LoadedFieldTypes()
    {
        if (_fieldTypes is not null) return _fieldTypes;
        if (_fieldTypesFailure is not null) throw _fieldTypesFailure;
        return new FieldTypeRegistry();
    }

    /// <summary>
    /// What every path that TYPES a payload does first: hold the catalog, and hold a registry that
    /// carries every type the catalog names.
    /// </summary>
    /// <remarks>
    /// This is the catalog leg only. The payload leg — a slug or a type the held state does not
    /// carry — runs from <see cref="TypeForSlugImpl"/>, on the value or change that named it.
    /// </remarks>
    private async Task PrepareTypingAsync(CancellationToken ct)
    {
        await RequestFieldsAsync(ct).ConfigureAwait(false);
        await EnsureTypesKnownAsync(_typeBySlug.Values, ct).ConfigureAwait(false);
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
        await PrepareTypingAsync(ct).ConfigureAwait(false); // the catalog and its registry, before typing

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
                    LoadedFieldTypes,
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
        await PrepareTypingAsync(ct).ConfigureAwait(false);
        var body = await _http.GetAsync($"{ConnectionsPath}/{id}", ct: ct).ConfigureAwait(false);
        if (body.Kind == NodeKind.Object && body.Has("items") && !body.Has("values"))
        {
            var items = ListItems(body);
            body = items.Count > 0 ? items[0] : Node.Object(new Dictionary<string, Node>());
        }
        return Connection.FromApi(body, TypeForSlugImpl, LoadedFieldTypes, DecryptValueImpl, (url, c) => BinaryFetchImpl(url, c));
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

    /// <summary>
    /// Drop a person's cached RSA public key, by share code.
    /// </summary>
    /// <remarks>
    /// A public key is immutable, so caching one is safe until the person rotates it. Persons learn
    /// about a rotation from a silent push; a SERVICE gets no pushes at all, so without a signal a
    /// long-lived worker would keep encrypting to the rotated-away key for its whole lifetime.
    /// <para>The changes feed calls this for you. Call it yourself when you consume changes over a
    /// <b>webhook</b> — the verifier is static and has no client instance, so it cannot reach this
    /// cache: on a <c>key_rotated</c> webhook, call
    /// <c>client.InvalidatePublicKey(change.ShareCode)</c>.</para>
    /// <para>The evicted <see cref="RSA"/> is deliberately NOT disposed: an in-flight encryption may
    /// still hold that instance, and disposing under it would throw. It is collected normally.</para>
    /// </remarks>
    public void InvalidatePublicKey(string shareCode)
    {
        lock (_pubkeyLock)
        {
            _pubkeyCache.Remove(shareCode);
            // Any fetch already in flight must not write its stale result back.
            _pubkeyGen[shareCode] = _pubkeyGen.TryGetValue(shareCode, out var g) ? g + 1 : 1;
        }
    }

    private Change DecryptChange(Node ev)
    {
        // The feed is a service's only rotation signal. Deliberately eventual — nothing
        // rejects a document encrypted to a stale key, so a window remains until this is drained.
        // The pull feed names it `event`; a raw webhook body names it `action` (and on
        // document rows `action` carries signed|accepted|cancelled instead) — so match either key.
        if (ev.Kind == NodeKind.Object
            && (ev.Get("event").AsString() == "key_rotated" || ev.Get("action").AsString() == "key_rotated"))
        {
            var shareCode = ev.Get("share_code").AsString() ?? ev.Get("id").Get("share_code").AsString();
            if (!string.IsNullOrEmpty(shareCode)) InvalidatePublicKey(shareCode!);
        }
        return Change.FromApi(ev, TypeForSlugImpl, LoadedFieldTypes, DecryptValueImpl, (url, c) => BinaryFetchImpl(url, c));
    }

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
        await PrepareTypingAsync(ct).ConfigureAwait(false); // the catalog and its registry, before typing
        await Pump.ProcessChangesAsync(handler, options, ct).ConfigureAwait(false);
    }

    /// <summary>Raw, UNBUFFERED drain → <c>List&lt;Change&gt;</c> (advanced — you own durability).</summary>
    public async Task<List<Change>> DrainBatchAsync(int max = DefaultConnPage, CancellationToken ct = default)
    {
        await PrepareTypingAsync(ct).ConfigureAwait(false);
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
        await PrepareTypingAsync(ct).ConfigureAwait(false);
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
            TypeForSlugImpl, LoadedFieldTypes, DecryptValueImpl, (url, c) => BinaryFetchImpl(url, c), _accountKey);
    }

    /// <summary>Verify + parse a webhook in one call → <see cref="Change"/>.</summary>
    public Change HandleWebhook(object rawBody, IReadOnlyDictionary<string, string>? headers)
    {
        EnsureCatalogForWebhook();
        return Webhooks.HandleWebhook(rawBody, headers, _config,
            TypeForSlugImpl, LoadedFieldTypes, DecryptValueImpl, (url, c) => BinaryFetchImpl(url, c), _accountKey);
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
        ulong gen;
        lock (_pubkeyLock)
        {
            if (_pubkeyCache.TryGetValue(shareCode, out var hit)) return hit;
            _pubkeyGen.TryGetValue(shareCode, out gen);
        }
        var body = await _http.GetAsync($"{KeysPath}/{shareCode}", ct: ct).ConfigureAwait(false);
        var spki = body.Kind == NodeKind.Object ? body.Get("public_key").AsString() : null;
        if (string.IsNullOrEmpty(spki))
            throw new ApiException(0, "keys.not_found", $"no public_key for share_code {shareCode}");
        var key = Crypto.LoadPublicKey(spki);
        lock (_pubkeyLock)
        {
            // Store ONLY if no invalidation happened while the request was in flight.
            _pubkeyGen.TryGetValue(shareCode, out var now);
            if (now == gen) _pubkeyCache[shareCode] = key;
        }
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
        string? plainSha256 = null,
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
        else if (!string.IsNullOrEmpty(shareCode))
            // A share_code target is PER-PERSON (encrypted to that recipient), not a
            // broadcast. Without this it fell through to the plaintext all-recipients path.
            target = new Dictionary<string, object?> { ["share_code"] = shareCode };
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
        body["plain_sha256"] = !string.IsNullOrEmpty(plainSha256) ? plainSha256 : Crypto.ComputePlainSha256(fileBytes);
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

    /// <summary>
    /// Download a document's file BYTES. <see cref="DocumentAsync"/> returns metadata only.
    /// This GETs <c>/documents/{id}/file</c> and branches on the document's storage mode (server
    /// contract):
    /// <list type="bullet">
    /// <item>a BROADCAST (non-private) document is stored plaintext and served as RAW bytes → returned
    /// as-is;</item>
    /// <item>a PER-PERSON / private document is encrypted to the RECIPIENT's key and served as
    /// <c>{"encrypted":true,"value":{"_enc":1,…}}</c> — the company CANNOT decrypt that with its
    /// service key, so this fails clearly (<see cref="ApiException"/> <c>documents.recipient_encrypted</c>)
    /// rather than attempting a doomed service-key decrypt. For a generated flow contract's OWN copy
    /// the company uses <see cref="FlowRunDocumentAsync"/> — that copy IS service-key-encrypted.</item>
    /// </list>
    /// </summary>
    public async Task<byte[]> DocumentFileAsync(string documentId, CancellationToken ct = default)
    {
        var raw = await _http.GetRawAsync($"{DocumentsPath}/{documentId}/file", ct: ct).ConfigureAwait(false);
        if (IsRecipientEncryptedResponse(raw))
        {
            throw new ApiException(
                0,
                "documents.recipient_encrypted",
                "This document is encrypted to its recipient and is not readable with the company service key. "
                + "For a generated flow contract, use FlowRunDocumentAsync(runId) to download the company copy.");
        }
        return raw; // broadcast / plaintext bytes
    }

    /// <summary>
    /// True when <paramref name="raw"/> parses as a JSON object with a truthy <c>encrypted</c>
    /// property — the per-person/private document response shape
    /// <c>{"encrypted":true,"value":{"_enc":1,...}}</c>. Any parse failure (the broadcast/plaintext
    /// case, e.g. raw PDF bytes) is treated as "not encrypted" — the bytes ARE the file.
    /// </summary>
    private static bool IsRecipientEncryptedResponse(byte[] raw)
    {
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(raw);
        }
        catch (JsonException)
        {
            return false;
        }
        using (doc)
        {
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return false;
            if (!doc.RootElement.TryGetProperty("encrypted", out var enc)) return false;
            return IsTruthy(enc);
        }
    }

    /// <summary>Loose truthiness for the <c>encrypted</c> flag's JSON value — 0, "0", null and empty
    /// collections are falsy; everything else is truthy.</summary>
    private static bool IsTruthy(JsonElement el) => el.ValueKind switch
    {
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Null => false,
        JsonValueKind.Number => el.TryGetDouble(out var d) && d != 0,
        JsonValueKind.String => el.GetString() is { Length: > 0 } s && s != "0",
        JsonValueKind.Object => el.EnumerateObject().MoveNext(),
        JsonValueKind.Array => el.GetArrayLength() > 0,
        _ => false,
    };

    /// <summary>
    /// Set a document's lifecycle status (offering|ready_to_sign|active|active_but_ending|ended).
    /// <c>waiting</c> is read-only — stamped by a contract-flow run on an unsigned run-participant
    /// copy, never a value to write. Throws with <c>error_key: "documents.run_managed"</c> (409)
    /// when the document is a contract-flow run-participant document and its current status is
    /// <c>waiting</c>, <c>ready_to_sign</c> or <c>offering</c> — that status moves only through
    /// flow generation, the run's own advance, sign/accept, or a run cancel/decline.
    /// </summary>
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

    // ── messaging (company ↔ person) ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Send a 1-on-1 message to the connected person → the new message_id.
    /// <c>POST /api/company-data/connections/{connectionId}/messages</c>. The message is end-to-end
    /// encrypted before it leaves the process: one copy for the PERSON (<c>body</c>) and one for the
    /// SERVICE (<c>sender_body</c>), so the person reads it in their app and this service can re-read
    /// its own outbound text. The platform stores ciphertext only. The route answers 201 with the
    /// created message carrying <c>message_id</c> — the boundary <see cref="MarkMessagesReadAsync"/> takes.
    /// <para><paramref name="personPublicKey"/> is the base64 SPKI carried on the
    /// <c>message_received</c> event — pass it to answer without a second key lookup. Without it the
    /// key is resolved from the connection's <c>share_code</c> (or an explicit
    /// <paramref name="shareCode"/>). Config-only key handling is unchanged: a recipient PUBLIC key
    /// is neither a secret nor a configured key.</para>
    /// <para>Refusals arrive as <see cref="ApiException"/> with the platform error_key:
    /// <c>messages.messaging_not_entitled</c> / <c>messages.messaging_suspended</c> /
    /// <c>messages.not_connected</c> (403), <c>messages.encryption_required</c> (400),
    /// <c>messages.rate_limited</c> (429).</para>
    /// </summary>
    public async Task<string> SendMessageAsync(
        string connectionId,
        string text,
        string? personPublicKey = null,
        string? shareCode = null,
        CancellationToken ct = default)
    {
        var cid = (connectionId ?? "").Trim();
        if (cid.Length == 0) throw new ConfigException("connectionId is required");
        if (string.IsNullOrWhiteSpace(text)) throw new ConfigException("text is required");

        RSA personKey;
        if (!string.IsNullOrEmpty(personPublicKey))
        {
            personKey = Crypto.LoadPublicKey(personPublicKey!);
        }
        else
        {
            var sc = shareCode ?? await ResolveShareCodeAsync(cid, null, ct).ConfigureAwait(false);
            personKey = await RecipientPublicKeyAsync(sc, ct).ConfigureAwait(false);
        }

        // Both copies travel as JSON STRINGS — the message columns are text and the API tells
        // ciphertext from plaintext by looking for the wrapper marker.
        var body = new Dictionary<string, object?>
        {
            ["body"] = Crypto.EncryptForPublicKey(text, personKey).ToJsonString(),
            ["sender_body"] = Crypto.EncryptForPublicKey(text, ServicePublicKey()).ToJsonString(),
        };
        var res = await _http.PostAsync($"{ConnectionsPath}/{cid}/messages", jsonBody: body, ct: ct)
            .ConfigureAwait(false);
        var mid = MessageIdOf(res);
        if (string.IsNullOrEmpty(mid))
            throw new ApiException(0, "messages.send_failed", "no message_id in response");
        return mid!;
    }

    /// <summary>
    /// Send one PLAINTEXT message to every person connected to this service.
    /// <c>POST /api/company-data/broadcast</c>. A broadcast is deliberately not encrypted — one body
    /// cannot be single-key-encrypted to every connection — so it is the one message the platform can
    /// read, exactly as a broadcast document is. It seeds each recipient's ordinary 1-on-1 thread, and
    /// a reply comes back end-to-end encrypted as a <c>message_received</c> event.
    /// <para>Returns the API response. Refusals arrive as <see cref="ApiException"/>:
    /// <c>messages.broadcast_audience_too_large</c> (422, over the connection cap),
    /// <c>messages.broadcast_suspended</c> / <c>messages.messaging_suspended</c> /
    /// <c>messages.messaging_not_entitled</c> (403).</para>
    /// </summary>
    public async Task<Node> BroadcastMessageAsync(string text, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(text)) throw new ConfigException("text is required");
        return await _http.PostAsync(BroadcastPath,
            jsonBody: new Dictionary<string, object?> { ["body"] = text }, ct: ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Acknowledge the inbound messages this service has handled, up to a boundary.
    /// <c>POST /api/company-data/connections/{connectionId}/messages/read</c> with
    /// <c>{up_to_message_id}</c>. Only the person's messages on THIS connection at or before that
    /// message are marked read; one that arrived while the service was working stays unread, so
    /// nothing is swept unhandled. Idempotent — a repeat is a no-op.
    /// <para>Sending a reply does NOT acknowledge anything; a service that never acks lets its unread
    /// grow. The boundary must be a message the PERSON sent on this connection: anything else is
    /// refused with <see cref="ApiException"/> <c>company_data.ack_boundary_invalid</c> (400).</para>
    /// </summary>
    public async Task MarkMessagesReadAsync(
        string connectionId, string upToMessageId, CancellationToken ct = default)
    {
        var cid = (connectionId ?? "").Trim();
        if (cid.Length == 0) throw new ConfigException("connectionId is required");
        var boundary = (upToMessageId ?? "").Trim();
        if (boundary.Length == 0) throw new ConfigException("upToMessageId is required");
        await _http.PostAsync($"{ConnectionsPath}/{cid}/messages/read",
            jsonBody: new Dictionary<string, object?> { ["up_to_message_id"] = boundary },
            ct: ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Pull the new message's id out of a send response — at the top level or nested under
    /// <c>message</c>, and under either <c>message_id</c> or <c>id</c>.
    /// </summary>
    private static string? MessageIdOf(Node body)
    {
        var obj = body;
        if (obj.Kind == NodeKind.Object && obj.Has("message")) obj = obj.Get("message");
        var mid = obj.Get("message_id").AsString() ?? obj.Get("id").AsString();
        return string.IsNullOrEmpty(mid) ? null : mid;
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
    /// A completed run's DECRYPTED answers as <c>{slug: plaintext}</c>. Decrypts the
    /// company's service-key answer copies of an already-fetched run — the public accessor for a
    /// finished run's answers, since the private <c>DecryptRunAnswers</c> it wraps is otherwise
    /// reached only inside <see cref="ProcessFlowRunAsync"/>, which returns an already-completed run
    /// untouched. Fetch the run with <see cref="FlowRunAsync"/> first, then pass it here.
    /// </summary>
    public Dictionary<string, object?> FlowRunAnswers(FlowRun run) => DecryptRunAnswers(run);

    /// <summary>
    /// Download the company's OWN copy of a run's generated flow contract — the PLAINTEXT
    /// file bytes. GETs <c>/flow-runs/{runId}/document/file</c>, which serves the company-party copy
    /// encrypted to the SERVICE key (unlike <see cref="DocumentFileAsync"/>'s recipient-targeted copy),
    /// so the same <see cref="BinaryHandle"/> the slot-file download uses decrypts it → the
    /// <c>{"file":"data:…;base64,…"}</c> envelope → the file bytes. A 404 (<see cref="ApiException"/>)
    /// surfaces when the run has not generated a document yet.
    /// </summary>
    public async Task<byte[]> FlowRunDocumentAsync(string runId, CancellationToken ct = default)
    {
        var handle = new BinaryHandle($"{FlowRunsPath}/{runId}/document/file", BinaryFetchImpl, DecryptValueImpl);
        return await handle.BytesAsync(ct).ConfigureAwait(false);
    }

    /// <summary>
    /// This client's OWN identity from <c>GET /api/company-data/whoami</c>. The COMPANY
    /// party of a <see cref="TriggerFlowRunAsync"/> binding must bind to <c>CompanyUserId</c> (the
    /// person party's user_id comes from the connection), so without this the company-side binding
    /// was unconstructible through the SDK.
    /// </summary>
    public async Task<Identity> IdentityAsync(CancellationToken ct = default)
    {
        var body = await _http.GetAsync($"{Base}/whoami", ct: ct).ConfigureAwait(false);
        return new Identity(body.Get("company_user_id").AsString(), body.Get("service_id").AsString());
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

        // Validate each freshly-typed answer against its field type from the pinned
        // definition, BEFORE encryption. Skip when the type can't be resolved.
        foreach (var (slug, val) in fill)
        {
            var element = FieldElementForSlug(run.Definition, slug);
            var ft = element is null ? null : FieldTypeOfElement(element);
            if (element is not null && !string.IsNullOrEmpty(ft))
            {
                var plainForCheck = val is string vs ? vs : JsonSerializer.Serialize(val);
                // The type is named by the pinned definition — a payload, not the request catalog —
                // so it can be one the held registry has never seen. One bounded refetch resolves
                // it; a type still absent afterwards validates as unknown, which accepts anything.
                await EnsureTypesKnownAsync(new[] { ft }, ct).ConfigureAwait(false);
                var registry = await FieldTypesAsync(ct).ConfigureAwait(false);
                // A choice type whose ROW carries no options takes them from the ELEMENT, which is
                // the only place they exist for select/multiselect. Passing them is what lets the
                // answer be validated at all instead of being measured against an empty domain.
                var options = FieldElementOptions(element);
                if (!registry.IsFieldValueValid(ft!, plainForCheck, options))
                    throw new ValidationException(slug, ft!);
            }
        }

        // A field's min and max are expressions over the live answer map (plugin outputs included);
        // a value outside them is refused before anything is encrypted.
        var live = PluginFlowParty.LiveAnswers(run, answersSoFar, fill);
        foreach (var (slug, val) in fill)
            PluginFlowParty.CheckBounds(run, slug, val, live);

        var sourcePrivate = PluginFlowParty.SourcePrivate(run, fill.Keys, run.ServiceUserId);
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
            var answer = new Dictionary<string, object?> { ["slug"] = slug, ["values"] = values };
            // The value came from a private source: a default reaching one.
            if (sourcePrivate.Contains(slug)) answer["source_private"] = true;
            answersOut.Add(answer);
        }

        var (leaf, nextNode) = ComputeNextNode(run.Definition, run.CurrentNode, full, run.ReferenceDate);
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

    // ── plugins on the company's flow steps ─────────────────────────────────────────────────

    /// <summary>
    /// A pass to the plugins of the plugin elements on the run's current step
    /// (<c>POST /api/company-data/flow-runs/{runId}/plugin-pass</c>). The run must be awaiting the company.
    /// </summary>
    public async Task<PluginPass> PluginPassAsync(string runId, CancellationToken ct = default)
        => PluginPass.FromApi(await _http.PostAsync($"{FlowRunsPath}/{runId}/plugin-pass", jsonBody: null, ct: ct).ConfigureAwait(false));

    private PluginFlowParty PluginParty(string runId) => new(
        _pluginHttp,
        ct => FlowRunAsync(runId, ct),
        ct => PluginPassAsync(runId, ct),
        DecryptRunAnswers,
        run => run.ServiceUserId);

    /// <summary>
    /// Ask the plugin behind the plugin element <paramref name="slug"/> for the options of one
    /// search_select <paramref name="block"/>. <paramref name="query"/> filters them ("" lists
    /// everything); <paramref name="picks"/> holds the ids picked so far by block key and
    /// <paramref name="values"/> the typed block values.
    /// <para><paramref name="draft"/> holds the current step's answers not yet submitted (slug →
    /// plaintext). The plugin's inputs are read from ONE live answer map — the run's stored answers,
    /// overlaid with draft for the current step's slugs, plugin answers expanded, constants computed —
    /// and converted to their declared types. An input that is another party's private value (a slug in
    /// <see cref="FlowRun.PrivateSlugs"/>, a constant reaching one, or a draft whose field's default
    /// reaches one) is never sent: a required one throws <see cref="PluginInputUnavailableException"/>.</para>
    /// <para>The request is sealed to the plugin's public key and posted to the forwarder over a plain
    /// transport that carries no allme credential; the reply is sealed to a key pair made for the call
    /// and opened here.</para>
    /// </summary>
    public Task<PluginOptionsResult> PluginOptionsAsync(
        string runId, string slug, string block, string query,
        IReadOnlyDictionary<string, string>? picks = null, IReadOnlyDictionary<string, object?>? values = null,
        IReadOnlyDictionary<string, object?>? draft = null, CancellationToken ct = default)
        => PluginParty(runId).OptionsAsync(slug, block, query, picks, values, draft, ct);

    /// <summary>
    /// Ask the plugin behind the plugin element <paramref name="slug"/> for the outputs of the picks and
    /// typed values so far, reading inputs as <see cref="PluginOptionsAsync"/> does. Answers
    /// <see cref="PluginOutputs"/>, or <see cref="PluginPicksInvalid"/> when the picks no longer fit;
    /// after changing an input, call it again before submitting.
    /// </summary>
    public Task<PluginOutputsResult> PluginOutputsAsync(
        string runId, string slug,
        IReadOnlyDictionary<string, string>? picks = null, IReadOnlyDictionary<string, object?>? values = null,
        IReadOnlyDictionary<string, object?>? draft = null, CancellationToken ct = default)
        => PluginParty(runId).OutputsAsync(slug, picks, values, draft, ct);

    /// <summary>
    /// Apply <paramref name="slug"/>'s min and max to <paramref name="value"/> over the live answer map
    /// (the stored answers overlaid with <paramref name="draft"/>, plugin answers expanded, constants
    /// computed); throws <see cref="ValidationException"/> naming the broken bound.
    /// <see cref="SubmitFlowAnswersAsync"/> applies the same check to every value it submits.
    /// </summary>
    public void CheckFlowValue(FlowRun run, string slug, object? value, IReadOnlyDictionary<string, object?>? draft = null)
        => PluginFlowParty.CheckBounds(run, slug, value, PluginFlowParty.LiveAnswers(run, DecryptRunAnswers(run), draft));

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
        var (wasLeaf, _) = ComputeNextNode(run.Definition, run.CurrentNode, merged, run.ReferenceDate);
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
    /// The next node after <paramref name="fromKey"/>: ordered outgoing edges, first match wins.
    /// Conditions use the answers — plugin answers expanded — plus computed constants at the run
    /// reference date. No matching outgoing edge means a leaf.
    /// </summary>
    private static (bool Leaf, string? Next) ComputeNextNode(
        Node definition, string? fromKey, IReadOnlyDictionary<string, object?> answers, string? referenceDate)
    {
        var edges = (definition.Get("edges").Kind == NodeKind.List ? definition.Get("edges").AsList() : new List<Node>())
            .Where(e => e.Kind == NodeKind.Object && e.Get("from").AsString() == fromKey)
            .OrderBy(e => EdgeSort(e))
            .ToList();
        if (edges.Count == 0) return (true, null);
        var constants = definition.Get("constants").Kind == NodeKind.List ? definition.Get("constants").AsList() : new List<Node>();
        var materialized = FlowCondition.ComputeConstants(
            constants, FlowCondition.ExpandPluginAnswers(answers, PluginFlowParty.PluginSlugsOf(definition)), referenceDate);
        foreach (var e in edges)
            if (FlowCondition.Evaluate(e.Get("condition"), materialized))
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
    internal static string? PartyOf(Node definition, string? nodeKey)
    {
        var node = NodeByKey(definition, nodeKey);
        return node?.Get("party").AsString();
    }

    /// <summary>
    /// Resolve a fill slug to its field ELEMENT in the pinned flow definition by scanning every
    /// node's elements for a <c>kind:"field"</c> element with the given slug. Returns null when the
    /// slug is not a field element (or elements are absent) — callers then SKIP validation rather
    /// than invent a type.
    /// </summary>
    internal static Node? FieldElementForSlug(Node definition, string slug)
    {
        if (definition.Get("nodes").Kind != NodeKind.List) return null;
        foreach (var n in definition.Get("nodes").AsList())
        {
            if (n.Kind != NodeKind.Object || n.Get("elements").Kind != NodeKind.List) continue;
            foreach (var el in n.Get("elements").AsList())
            {
                if (el.Kind != NodeKind.Object) continue;
                if (el.Get("kind").AsString() == "field" && el.Get("slug").AsString() == slug) return el;
            }
        }
        return null;
    }

    /// <summary>A field element's declared type, null when it names none.</summary>
    internal static string? FieldTypeOfElement(Node element)
    {
        var ft = element.Get("field_type").AsString();
        return string.IsNullOrEmpty(ft) ? element.Get("type").AsString() : ft;
    }

    /// <summary>The option VALUES a flow field element supplies.</summary>
    /// <remarks>
    /// An element's options are <c>{value, label, available_if?}</c> objects; the value is the
    /// domain member. null when the element carries none, which leaves the row's own options — if
    /// it has any — to govern.
    /// </remarks>
    private static IReadOnlyList<string>? FieldElementOptions(Node element)
    {
        if (element.Get("options").Kind != NodeKind.List) return null;
        var values = new List<string>();
        foreach (var option in element.Get("options").AsList())
        {
            if (option.Kind != NodeKind.Object) continue;
            var value = option.Get("value");
            if (!value.IsNull) values.Add(value.AsString() ?? "");
        }
        return values.Count > 0 ? values : null;
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
        _pluginHttp.Dispose();
        lock (_pubkeyLock) { foreach (var key in _pubkeyCache.Values) key.Dispose(); }
    }
}
