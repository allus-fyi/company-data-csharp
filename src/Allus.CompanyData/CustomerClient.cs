// The CUSTOMER-role client (b2b).
//
// CustomerClient is what a connecting company uses to consume and answer another
// company's service over its acct_* credentials: list company↔company connections,
// provide/edit typed consent answers, read (and decrypt) issued documents, run contract
// flows — generating the contract of a run whose last step it answered — drain the account
// change feed, and verify account-level webhooks. It reuses the
// same crash-safe Pump, webhook helpers, and hybrid-crypto core as the service Client.
//
// NO sign/accept methods (spec D6): signing/accepting a contract is a deliberate human
// step-up that stays portal-only; a machine acct_* token is rejected by the API for
// those routes.

using System.Security.Cryptography;
using System.Text.Json;

namespace Allus.CompanyData;

/// <summary>One service the customer is connected to, inside a <see cref="CustomerConnection"/>.</summary>
public sealed record CustomerServiceLink(
    string? ServiceLinkId,
    string? ServiceId,
    string? ServiceName,
    string? ServiceCode,
    IReadOnlyList<object?> Shared,
    IReadOnlyList<object?> Mappings,
    object? PendingConsent,
    Node Raw);

/// <summary>One company↔company connection from the customer's side.</summary>
public sealed record CustomerConnection(
    string? Id,
    string? CompanyUserId,
    string? CompanyName,
    string? CompanyCode,
    string? CustomerType,
    IReadOnlyList<object?> CompanyProfile,
    IReadOnlyList<CustomerServiceLink> Services,
    Node Raw)
{
    internal static CustomerConnection FromApi(Node obj)
    {
        var company = obj.Has("company") ? obj.Get("company") : Node.Object(new Dictionary<string, Node>());
        var services = (obj.Has("services") ? obj.Get("services").AsList() : new List<Node>())
            .Where(s => s.Kind == NodeKind.Object)
            .Select(FromApiServiceLink)
            .ToList();
        return new CustomerConnection(
            Id: Str(obj, "id") ?? Str(obj, "company_connection_id"),
            CompanyUserId: Str(obj, "company_user_id") ?? Str(company, "user_id"),
            CompanyName: Str(obj, "company_name") ?? Str(company, "display_name"),
            CompanyCode: Str(obj, "company_code") ?? Str(company, "share_code"),
            CustomerType: Str(obj, "customer_type"),
            CompanyProfile: (obj.Has("company_profile") ? obj.Get("company_profile").AsList() : new List<Node>())
                .Select(n => n.ToObjectGraph()).ToList(),
            Services: services,
            Raw: obj);
    }

    internal static IReadOnlyList<CustomerConnection> ListFromApi(Node body)
    {
        var items = body.Kind == NodeKind.Object && body.Has("connections")
            ? body.Get("connections").AsList()
            : body.Kind == NodeKind.Object && body.Has("items")
                ? body.Get("items").AsList()
                : body.Kind == NodeKind.List ? body.AsList() : new List<Node>();
        return items.Where(o => o.Kind == NodeKind.Object).Select(FromApi).ToList();
    }

    private static CustomerServiceLink FromApiServiceLink(Node obj) => new(
        ServiceLinkId: Str(obj, "service_link_id") ?? Str(obj, "id"),
        ServiceId: Str(obj, "service_id"),
        ServiceName: Str(obj, "service_name") ?? Str(obj, "name"),
        ServiceCode: Str(obj, "service_code") ?? Str(obj, "share_code"),
        Shared: (obj.Has("shared") ? obj.Get("shared").AsList() : new List<Node>()).Select(n => n.ToObjectGraph()).ToList(),
        Mappings: (obj.Has("mappings") ? obj.Get("mappings").AsList() : new List<Node>()).Select(n => n.ToObjectGraph()).ToList(),
        PendingConsent: obj.Has("pending_consent") ? obj.Get("pending_consent").ToObjectGraph() : null,
        Raw: obj);

    private static string? Str(Node obj, string key)
    {
        if (!obj.Has(key)) return null;
        var s = obj.Get(key).AsString();
        return string.IsNullOrEmpty(s) ? null : s;
    }
}

/// <summary>A typed answer to a consent/edit request row (before encryption).</summary>
public sealed record TypedAnswer(string RequestFieldId, string Value, string Kind = "typed");

/// <summary>A flow party for <see cref="CustomerClient.EncryptFlowAnswer"/>.</summary>
public sealed record FlowParty(string UserId, string? Type = null, bool IsOwner = false);

/// <summary>The b2b customer-side facade. NO sign/accept (spec D6).</summary>
public sealed class CustomerClient
{
    private const string Conn = "/api/company-connections";
    private const string Consents = "/api/company-connections/consents";
    private const string CustomerChanges = "/api/customer/changes";
    private const string Keys = "/api/keys";
    private const string FieldTypesPath = "/api/contact-field-types";

    private readonly Config _config;
    private readonly ApiHttp _http;
    private readonly RSA? _accountKey;
    private readonly Func<double, System.Threading.CancellationToken, Task> _sleep;
    private readonly System.Collections.Generic.Dictionary<string, RSA?> _pubKeyCache = new();
    /// <summary>See Client's _pubkeyLock — same hazard, same remedy.</summary>
    private readonly object _pubKeyLock = new();
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
    private readonly System.Collections.Generic.Dictionary<string, ulong> _pubKeyGen = new();
    /// <summary>
    /// _serviceKeyCache and _requestTypeCache sit on the same concurrent
    /// encryption paths as _pubKeyCache, so an unsynchronised Dictionary corrupts under concurrent
    /// read+write. _requestTypeCache has no invalidator, so it needs no generation counter — but
    /// adding one later MUST bring a generation with it.
    /// <para>_serviceKeyCache is that "later": it now HAS an invalidator
    /// (<see cref="InvalidateServiceKey"/>, driven by the <c>service_key_rotated</c> change), so it
    /// carries _serviceKeyGen under _otherLock, on exactly the same reasoning as _pubKeyGen.</para>
    /// </summary>
    private readonly object _otherLock = new();
    private readonly System.Collections.Generic.Dictionary<string, RSA?> _serviceKeyCache = new();
    private readonly System.Collections.Generic.Dictionary<string, ulong> _serviceKeyGen = new();
    // "companyCode/serviceCode" → {request_field_id: field_type}, for typed-answer validation.
    private readonly System.Collections.Generic.Dictionary<string, System.Collections.Generic.Dictionary<string, string>> _requestTypeCache = new();

    // The field-type registry, fetched beside the request-field lookup and held for the life of the
    // client. A type it does not carry triggers ONE refetch; a type a refetch still does not resolve
    // is remembered in _unresolvedTypes and never asked for again. Both live under _otherLock,
    // beside the caches they are read with.
    private FieldTypeRegistry? _fieldTypes;
    // The last registry load's failure, held so a synchronous reader raises it instead of reading
    // an empty registry. Cleared by the first load that succeeds.
    private Exception? _fieldTypesFailure;
    private readonly HashSet<string> _unresolvedTypes = new(StringComparer.Ordinal);
    private Pump? _pump;
    // The plain transport plugin calls reach the forwarder over — never the API transport, which
    // attaches the bearer token and rewrites the base URL.
    private readonly HttpClient _pluginHttp = PluginFlowParty.NewTransport();

    public CustomerClient(
        Config config,
        ApiHttp? http = null,
        IPumpLogger? logger = null,
        Func<double, System.Threading.CancellationToken, Task>? sleep = null)
    {
        if (string.IsNullOrEmpty(config.CustomerClientId) || string.IsNullOrEmpty(config.CustomerClientSecret))
            throw new ConfigException(
                "CustomerClient requires customer_client_id + customer_client_secret "
                + "(load with Config.FromCustomerFile / FromCustomerEnv)");
        _config = config;
        _sleep = sleep ?? ((s, ct) => Task.Delay(TimeSpan.FromSeconds(Math.Max(0, s)), ct));
        // The transport authenticates as the acct_* client — hand ApiHttp a config
        // whose ClientId/Secret are the customer pair.
        var httpConfig = new Config
        {
            ApiUrl = config.ApiUrl,
            ClientId = config.CustomerClientId,
            ClientSecret = config.CustomerClientSecret,
            CustomerClientId = config.CustomerClientId,
            CustomerClientSecret = config.CustomerClientSecret,
            AccountPrivateKey = config.AccountPrivateKey,
            AccountPassphrase = config.AccountPassphrase,
            Webhooks = config.Webhooks,
            WebhookBearerToken = config.WebhookBearerToken,
            WebhookBasic = config.WebhookBasic,
            WebhookHeader = config.WebhookHeader,
            WebhookAuthNone = config.WebhookAuthNone,
            CacheDir = config.CacheDir,
            Format = config.Format,
        };
        _http = http ?? new ApiHttp(httpConfig);
        // ACCOUNT private key — decrypts received documents/flow copies (loaded once).
        _accountKey = Webhooks.LoadAccountKey(config);
        _ = logger; // reserved (pump uses its own logger sink)
    }

    /// <summary>Build from a customer-role JSON config file.</summary>
    public static CustomerClient FromConfig(string path) => new(Config.FromCustomerFile(path));

    /// <summary>Build entirely from ALLUS_* env vars (customer role).</summary>
    public static CustomerClient FromEnv() => new(Config.FromCustomerEnv());

    // ── connections ────────────────────────────────────────────────────────────

    public async Task<IReadOnlyList<CustomerConnection>> ConnectionsAsync(System.Threading.CancellationToken ct = default)
        => CustomerConnection.ListFromApi(await _http.GetAsync(Conn, null, ct).ConfigureAwait(false));

    public async Task<CustomerConnection> ConnectionAsync(string id, System.Threading.CancellationToken ct = default)
        => CustomerConnection.FromApi(await _http.GetAsync($"{Conn}/{id}", null, ct).ConfigureAwait(false));

    // ── consents (typed answers) ─────────────────────────────────────────────────

    public async Task<object?> ProvideConsentAsync(string consentId, IReadOnlyList<TypedAnswer> answers,
        string companyCode, string serviceCode, System.Threading.CancellationToken ct = default)
    {
        var decisions = await EncryptTypedAsync(answers, companyCode, serviceCode, ct).ConfigureAwait(false);
        var body = await _http.PostAsync($"{Consents}/{consentId}/provide",
            jsonBody: new Dictionary<string, object?> { ["decisions"] = decisions }, ct: ct).ConfigureAwait(false);
        return body.ToObjectGraph();
    }

    public async Task<object?> DeclineConsentAsync(string consentId, System.Threading.CancellationToken ct = default)
        => (await _http.PostAsync($"{Consents}/{consentId}/decline", jsonBody: null, ct: ct).ConfigureAwait(false)).ToObjectGraph();

    public async Task<object?> EditAnswersAsync(string connectionId, string serviceLinkId,
        IReadOnlyList<TypedAnswer> answers, string companyCode, string serviceCode,
        System.Threading.CancellationToken ct = default)
    {
        var decisions = await EncryptTypedAsync(answers, companyCode, serviceCode, ct).ConfigureAwait(false);
        var body = await _http.PutAsync($"{Conn}/{connectionId}/services/{serviceLinkId}/mappings",
            new Dictionary<string, object?> { ["decisions"] = decisions }, ct).ConfigureAwait(false);
        return body.ToObjectGraph();
    }

    // ── documents (account-key decrypt; NO sign/accept — D6) ──────────────────────

    public List<Document> Documents(CustomerConnection connection)
    {
        DecryptValue dv = DecryptAccount;
        var docs = new List<Document>();
        foreach (var svc in connection.Services)
            if (svc.Raw.Has("documents"))
                docs.AddRange(svc.Raw.Get("documents").AsList().Where(d => d.Kind == NodeKind.Object)
                    .Select(d => Document.FromApi(d, dv)));
        if (connection.Raw.Has("documents"))
            docs.AddRange(connection.Raw.Get("documents").AsList().Where(d => d.Kind == NodeKind.Object)
                .Select(d => Document.FromApi(d, dv)));
        return docs;
    }

    public async Task<object?> DocumentFileAsync(string connectionId, string documentId,
        System.Threading.CancellationToken ct = default)
    {
        var body = await _http.GetAsync($"{Conn}/{connectionId}/documents/{documentId}/file", null, ct).ConfigureAwait(false);
        if (body.Kind == NodeKind.Object && body.Has("encrypted") && ModelCoerce.CoerceBool(body.Get("encrypted")) == true && body.Has("value"))
            return JsonSerializer.Deserialize<JsonElement>(DecryptAccount(body.Get("value").ToObjectGraph()!));
        if (body.Kind == NodeKind.Object && body.Has("_enc"))
            return JsonSerializer.Deserialize<JsonElement>(DecryptAccount(body.ToObjectGraph()!));
        return body.ToObjectGraph();
    }

    public async Task<object?> CancelDocumentAsync(string connectionId, string documentId, string? note = null,
        System.Threading.CancellationToken ct = default)
    {
        object? payload = note is null ? null : new Dictionary<string, object?> { ["note"] = note };
        return (await _http.PostAsync($"{Conn}/{connectionId}/documents/{documentId}/cancel", jsonBody: payload, ct: ct).ConfigureAwait(false)).ToObjectGraph();
    }

    // ── contract flows ────────────────────────────────────────────────────────────

    public async Task<IReadOnlyList<FlowRun>> FlowRunsAsync(string connectionId, System.Threading.CancellationToken ct = default)
    {
        var body = await _http.GetAsync($"{Conn}/{connectionId}/flow-runs", null, ct).ConfigureAwait(false);
        var items = body.Kind == NodeKind.Object && body.Has("runs") ? body.Get("runs").AsList()
            : body.Kind == NodeKind.List ? body.AsList() : new List<Node>();
        return items.Where(o => o.Kind == NodeKind.Object).Select(FlowRun.FromApi).ToList();
    }

    public async Task<FlowRun> FlowRunAsync(string connectionId, string runId, System.Threading.CancellationToken ct = default)
        => FlowRun.FromApi(await _http.GetAsync($"{Conn}/{connectionId}/flow-runs/{runId}", null, ct).ConfigureAwait(false));

    /// <summary>
    /// Submit this party's turn (<paramref name="body"/> carries the encrypted per-party answers). It
    /// reads the run first and sets <c>source_private: true</c> on every answer in <c>body.answers</c>
    /// that is private: a field whose default reaches a private source.
    /// </summary>
    public async Task<object?> SubmitFlowAnswersAsync(string connectionId, string runId, object body,
        System.Threading.CancellationToken ct = default)
    {
        object? payload = body;
        if (Node.FromJsonString(JsonSerializer.Serialize(body)).ToObjectGraph() is Dictionary<string, object?> graph
            && graph.TryGetValue("answers", out var answersObj) && answersObj is List<object?> { Count: > 0 } answers)
        {
            var run = await FlowRunAsync(connectionId, runId, ct).ConfigureAwait(false);
            var submitted = answers.OfType<Dictionary<string, object?>>()
                .Select(a => a.TryGetValue("slug", out var s) ? s?.ToString() : null)
                .Where(s => !string.IsNullOrEmpty(s)).Select(s => s!).ToList();
            var sourcePrivate = PluginFlowParty.SourcePrivate(run, submitted, OwnUserId(run));
            foreach (var a in answers.OfType<Dictionary<string, object?>>())
                if (a.TryGetValue("slug", out var s) && s?.ToString() is { } slug && sourcePrivate.Contains(slug))
                    a["source_private"] = true;
            payload = graph;
        }
        return (await _http.PostAsync($"{Conn}/{connectionId}/flow-runs/{runId}/answers", jsonBody: payload, ct: ct).ConfigureAwait(false)).ToObjectGraph();
    }

    public async Task<object?> DeclineFlowRunAsync(string connectionId, string runId, System.Threading.CancellationToken ct = default)
        => (await _http.PostAsync($"{Conn}/{connectionId}/flow-runs/{runId}/decline", jsonBody: null, ct: ct).ConfigureAwait(false)).ToObjectGraph();

    /// <summary>
    /// Generate the contract of a document-mode run whose LEAF this company answered
    /// (<c>POST /api/company-connections/{id}/flow-runs/{runId}/generate</c>). The party that answers a
    /// run's last step generates. Submitting the leaf's answers leaves the run "generating"; pass the
    /// run as re-read then. The whole answer map comes from this company's OWN copy of the answers,
    /// opened with the account key — every party's answers are sealed to every bound party, so that
    /// copy holds the whole run and no service key is involved — and is sealed with the one-time-key
    /// bundle. Returns the API response {document_id, documents, status} (idempotent — a repeat answers
    /// the same document set). Throws <see cref="ConfigException"/> when the run's current step is not
    /// bound to this company — the participant the run lists on <paramref name="connectionId"/>.
    /// </summary>
    public async Task<object?> GenerateFlowDocumentAsync(string connectionId, FlowRun run, System.Threading.CancellationToken ct = default)
    {
        var own = run.Participants.FirstOrDefault(p => p.ConnectionId == connectionId)?.PersonUserId;
        if (string.IsNullOrEmpty(own) || OwnUserId(run) != own)
            throw new ConfigException($"run {run.Id} is not at a step this company answered");
        var body = Crypto.OneTimeKeyBundle(DecryptOwnRunAnswers(run));
        return (await _http.PostAsync($"{Conn}/{connectionId}/flow-runs/{run.Id}/generate", jsonBody: body, ct: ct).ConfigureAwait(false)).ToObjectGraph();
    }

    /// <summary>Encrypt one answer value for one flow party per the P4 key rule.</summary>
    public async Task<Node> EncryptFlowAnswerAsync(string plaintext, FlowParty party,
        string companyCode, string serviceCode, System.Threading.CancellationToken ct = default)
    {
        var pub = party.IsOwner
            ? await ServiceKeyAsync(companyCode, serviceCode, ct).ConfigureAwait(false)
            : await BatchKeyAsync(party.UserId, ct).ConfigureAwait(false);
        if (pub is null) throw new ConfigException($"no public key available for party {party.UserId}");
        return Crypto.EncryptForPublicKey(plaintext, pub);
    }

    // ── plugins on this company's flow steps ──────────────────────────────────────────────

    /// <summary>
    /// A pass to the plugins of the plugin elements on the run's current step
    /// (<c>POST /api/company-connections/{id}/flow-runs/{runId}/plugin-pass</c>). The run must be awaiting
    /// this company's party.
    /// </summary>
    public async Task<PluginPass> PluginPassAsync(string connectionId, string runId, System.Threading.CancellationToken ct = default)
        => PluginPass.FromApi(await _http.PostAsync($"{Conn}/{connectionId}/flow-runs/{runId}/plugin-pass", jsonBody: null, ct: ct).ConfigureAwait(false));

    private PluginFlowParty PluginParty(string connectionId, string runId) => new(
        _pluginHttp,
        ct => FlowRunAsync(connectionId, runId, ct),
        ct => PluginPassAsync(connectionId, runId, ct),
        DecryptOwnRunAnswers,
        OwnUserId);

    /// <summary>
    /// Ask the plugin behind the plugin element <paramref name="slug"/> for the options of one
    /// search_select block — <see cref="Client.PluginOptionsAsync"/> for this company's own party, with
    /// the inputs read from the run's answers this company opens with its account key, overlaid with
    /// <paramref name="draft"/> for the current step's slugs.
    /// </summary>
    public Task<PluginOptionsResult> PluginOptionsAsync(
        string connectionId, string runId, string slug, string block, string query,
        IReadOnlyDictionary<string, string>? picks = null, IReadOnlyDictionary<string, object?>? values = null,
        IReadOnlyDictionary<string, object?>? draft = null, System.Threading.CancellationToken ct = default)
        => PluginParty(connectionId, runId).OptionsAsync(slug, block, query, picks, values, draft, ct);

    /// <summary>
    /// Ask the plugin behind the plugin element <paramref name="slug"/> for the outputs of the picks and
    /// typed values so far — <see cref="Client.PluginOutputsAsync"/> for this company's own party.
    /// Answers <see cref="PluginOutputs"/> or <see cref="PluginPicksInvalid"/>.
    /// </summary>
    public Task<PluginOutputsResult> PluginOutputsAsync(
        string connectionId, string runId, string slug,
        IReadOnlyDictionary<string, string>? picks = null, IReadOnlyDictionary<string, object?>? values = null,
        IReadOnlyDictionary<string, object?>? draft = null, System.Threading.CancellationToken ct = default)
        => PluginParty(connectionId, runId).OutputsAsync(slug, picks, values, draft, ct);

    /// <summary>
    /// Apply <paramref name="slug"/>'s min and max to <paramref name="value"/> over the live answer map
    /// (this company's own copies of the run's answers, overlaid with <paramref name="draft"/>, plugin
    /// answers expanded, constants computed); throws <see cref="ValidationException"/> naming the broken
    /// bound. Call it before <see cref="EncryptFlowAnswerAsync"/> seals the value.
    /// </summary>
    public void CheckFlowValue(FlowRun run, string slug, object? value, IReadOnlyDictionary<string, object?>? draft = null)
        => PluginFlowParty.CheckBounds(run, slug, value, PluginFlowParty.LiveAnswers(run, DecryptOwnRunAnswers(run), draft));

    // The user id bound to the party of the run's current step: the plugin calls and the bound check
    // act on this company's own turn.
    private static string? OwnUserId(FlowRun run)
        => run.Bindings.TryGetValue(Client.PartyOf(run.Definition, run.CurrentNode) ?? "", out var uid) ? uid : null;

    // This company's own copies of the run's answers (for_user_id = the user bound to the current step),
    // opened with the account key. Each bound party's copy holds the whole run, whoever answered each slug.
    private Dictionary<string, object?> DecryptOwnRunAnswers(FlowRun run)
    {
        var own = OwnUserId(run);
        var outMap = new Dictionary<string, object?>();
        if (string.IsNullOrEmpty(own)) return outMap;
        foreach (var row in run.Answers)
        {
            if (row.Get("for_user_id").AsString() != own) continue;
            var slug = row.Get("slug").AsString();
            if (string.IsNullOrEmpty(slug) || !row.Has("value") || row.Get("value").IsNull) continue;
            outMap[slug!] = DecryptAccount(row.Get("value"));
        }
        return outMap;
    }

    // ── change feed (P2 account feed) ─────────────────────────────────────────────

    public Pump Pump => _pump ??= new Pump(_config, FetchChangesAsync, DecryptChange, sleep: _sleep);

    private async Task<List<Node>> FetchChangesAsync(int limit, System.Threading.CancellationToken ct)
    {
        var body = await _http.GetAsync(CustomerChanges, new Dictionary<string, string> { ["limit"] = limit.ToString() }, ct).ConfigureAwait(false);
        var items = body.Kind == NodeKind.Object && body.Has("changes") ? body.Get("changes").AsList()
            : body.Kind == NodeKind.List ? body.AsList() : new List<Node>();
        return items.Where(o => o.Kind == NodeKind.Object).ToList();
    }

    /// <summary>
    /// Drop a person's cached RSA public key, by user id. See
    /// <see cref="Client.InvalidatePublicKey"/>; the changes feed calls this for you, webhook
    /// consumers must call it themselves. The evicted key is not disposed (an in-flight
    /// encryption may still hold it).
    /// </summary>
    public void InvalidatePublicKey(string userId)
    {
        lock (_pubKeyLock)
        {
            _pubKeyCache.Remove(userId);
            // Any fetch already in flight must not write its stale result back.
            _pubKeyGen[userId] = _pubKeyGen.TryGetValue(userId, out var g) ? g + 1 : 1;
        }
    }

    /// <summary>
    /// Drop a SERVICE's cached RSA public key, so the next answer or document encrypted to
    /// it refetches. The mirror of <see cref="InvalidatePublicKey"/> in the service→customer
    /// direction.
    /// <para>The changes feed calls this for you on a <c>service_key_rotated</c> event; webhook
    /// consumers must call it themselves with the body's <c>company_share_code</c> and
    /// <c>service_share_code</c>. As above, the evicted key is deliberately NOT disposed — an
    /// in-flight encryption may still hold that instance, and disposing under it would throw.</para>
    /// </summary>
    public void InvalidateServiceKey(string companyCode, string serviceCode)
    {
        var key = $"{companyCode}/{serviceCode}";
        lock (_otherLock)
        {
            _serviceKeyCache.Remove(key);
            // Any fetch already in flight must not write its stale result back.
            _serviceKeyGen[key] = _serviceKeyGen.TryGetValue(key, out var g) ? g + 1 : 1;
        }
    }

    private Change DecryptChange(Node ev)
    {
        // This cache also stores a negative (null) result, so without invalidation a person
        // who had not generated keys yet would stay unresolvable for the process lifetime too.
        // The pull feed names it `event`; a raw webhook body names it `action` (and on
        // document rows `action` carries signed|accepted|cancelled instead) — so match either key.
        if (ev.Kind == NodeKind.Object
            && (ev.Get("event").AsString() == "key_rotated" || ev.Get("action").AsString() == "key_rotated"))
        {
            var personId = ev.Get("person_user_id").AsString() ?? ev.Get("person_id").AsString();
            if (!string.IsNullOrEmpty(personId)) InvalidatePublicKey(personId!);
        }
        // A service this customer connects to replaced its keypair — drop the cached copy so
        // the next encryption refetches. Same either-key match as above.
        if (ev.Kind == NodeKind.Object
            && (ev.Get("event").AsString() == "service_key_rotated" || ev.Get("action").AsString() == "service_key_rotated"))
        {
            var companyCode = ev.Get("company_share_code").AsString();
            var serviceCode = ev.Get("service_share_code").AsString();
            if (!string.IsNullOrEmpty(companyCode) && !string.IsNullOrEmpty(serviceCode))
            {
                InvalidateServiceKey(companyCode!, serviceCode!);
            }
        }
        return Change.FromApi(ev, _ => null, LoadedFieldTypes, DecryptAccount);
    }

    public Task ProcessChangesAsync(Func<Change, Task> handler, ProcessOptions? options = null, System.Threading.CancellationToken ct = default)
        => Pump.ProcessChangesAsync(handler, options, ct);

    public Task<List<Change>> DrainBatchAsync(int max = 100, System.Threading.CancellationToken ct = default)
        => Pump.DrainBatchAsync(max, ct);

    public IReadOnlyList<Node> DeadLetters() => Pump.DeadLetters();

    public Task<int> RetryDeadLettersAsync(Func<Change, Task> handler, ProcessOptions? options = null, System.Threading.CancellationToken ct = default)
        => Pump.RetryDeadLettersAsync(handler, options, ct);

    // ── account-level webhook receiver helpers (config-driven) ────────────────────

    public bool VerifyWebhook(object rawBody, IReadOnlyDictionary<string, string>? headers)
        => Webhooks.VerifyWebhook(rawBody, headers, _config);

    public Change ParseWebhook(object rawBody, IReadOnlyDictionary<string, string>? headers)
        => Webhooks.ParseWebhook(rawBody, headers, _config, _ => null, LoadedFieldTypes, DecryptAccount, accountKey: _accountKey);

    public Change HandleWebhook(object rawBody, IReadOnlyDictionary<string, string>? headers)
        => Webhooks.HandleWebhook(rawBody, headers, _config, _ => null, LoadedFieldTypes, DecryptAccount, accountKey: _accountKey);

    // ── internals ──────────────────────────────────────────────────────────────────

    private string DecryptAccount(object wrapper)
    {
        if (_accountKey is null) throw new ConfigException("account_private_key is required to decrypt this value");
        return Crypto.Decrypt(wrapper, _accountKey);
    }

    /// <summary>
    /// Resolve {request_field_id: field_type} for a service from the connect-screen lookup, cached
    /// per company/service. Best-effort — a lookup failure yields an empty map so typed-answer
    /// validation is simply skipped.
    /// </summary>
    /// <summary>
    /// The field-type registry — what every TYPE in a request catalog means.
    /// </summary>
    /// <remarks>
    /// Fetched from <c>GET /api/contact-field-types</c> beside the connect-screen lookup this client
    /// resolves a request row's type from, and held in memory for the life of the client. It is what
    /// validates a typed answer before it is encrypted.
    /// </remarks>
    public async Task<FieldTypeRegistry> FieldTypesAsync(System.Threading.CancellationToken ct = default)
    {
        lock (_otherLock)
        {
            if (_fieldTypes is not null) return _fieldTypes;
        }
        var registry = await LoadFieldTypesAsync(ct).ConfigureAwait(false);
        lock (_otherLock) _fieldTypes = registry;
        return registry;
    }

    /// <summary>One fetch of the registry rows, with no caching of its own.</summary>
    /// <remarks>
    /// A failure is remembered as a failure: re-thrown to the caller that asked, and recorded so a
    /// synchronous reader raises it too rather than reading an empty registry, whose "accept
    /// anything" answer for an unknown type would be indistinguishable from a real one.
    /// </remarks>
    private async Task<FieldTypeRegistry> LoadFieldTypesAsync(System.Threading.CancellationToken ct)
    {
        try
        {
            // The registry route answers JSON to every caller — it is not one of the customer
            // routes that honour the configured Format — so its body is parsed as JSON whatever
            // this client speaks elsewhere.
            var resp = await _http.GetResponseAsync(FieldTypesPath, ct: ct).ConfigureAwait(false);
            var registry = new FieldTypeRegistry(_http.ParseResponseAsJson(resp));
            lock (_otherLock) _fieldTypesFailure = null;
            return registry;
        }
        catch (Exception exc)
        {
            lock (_otherLock) _fieldTypesFailure = exc;
            throw;
        }
    }

    /// <summary>One bounded refetch when the held registry does not carry a type in use.</summary>
    /// <remarks>
    /// The refetch replaces the held registry only once it has ARRIVED, so a refetch that fails
    /// leaves the rows already loaded standing rather than none at all.
    /// </remarks>
    private async Task EnsureTypesKnownAsync(IEnumerable<string> types, System.Threading.CancellationToken ct)
    {
        var registry = await FieldTypesAsync(ct).ConfigureAwait(false);
        List<string> missing;
        lock (_otherLock)
        {
            missing = types
                .Where(t => !string.IsNullOrEmpty(t) && !registry.Knows(t) && !_unresolvedTypes.Contains(t))
                .ToList();
        }
        if (missing.Count == 0) return;
        registry = await LoadFieldTypesAsync(ct).ConfigureAwait(false);
        lock (_otherLock)
        {
            _fieldTypes = registry;
            foreach (var type in missing)
            {
                if (!registry.Knows(type)) _unresolvedTypes.Add(type);
            }
        }
    }

    /// <summary>The registry the synchronous webhook parsers read; the request-field lookup loads it.</summary>
    /// <remarks>
    /// A load that FAILED raises that failure rather than answering an empty registry — "unknown
    /// accepts anything" is a verdict about the deployment, never a stand-in for a fetch that did
    /// not happen. A client that never asked for the registry reads the empty one.
    /// </remarks>
    private FieldTypeRegistry LoadedFieldTypes()
    {
        lock (_otherLock)
        {
            if (_fieldTypes is not null) return _fieldTypes;
            if (_fieldTypesFailure is not null) throw _fieldTypesFailure;
            return new FieldTypeRegistry();
        }
    }

    private async Task<Dictionary<string, string>> RequestFieldTypesAsync(string companyCode, string serviceCode, System.Threading.CancellationToken ct)
    {
        var key = $"{companyCode}/{serviceCode}";
        lock (_otherLock)
        {
            if (_requestTypeCache.TryGetValue(key, out var cached)) return cached;
        }
        var map = new Dictionary<string, string>();
        try
        {
            var body = await _http.GetAsync($"{Conn}/lookup/{companyCode}/{serviceCode}", null, ct).ConfigureAwait(false);
            if (body.Kind == NodeKind.Object && body.Get("request_fields").Kind == NodeKind.List)
            {
                foreach (var r in body.Get("request_fields").AsList())
                {
                    if (r.Kind != NodeKind.Object) continue;
                    var id = r.Get("id").AsString();
                    var ft = r.Get("field_type").AsString();
                    if (string.IsNullOrEmpty(ft)) ft = r.Get("type").AsString();
                    if (!string.IsNullOrEmpty(id) && !string.IsNullOrEmpty(ft)) map[id!] = ft!;
                }
            }
        }
        catch (ApiException) { /* best-effort — skip validation when unavailable */ }
        // Cached only once the registry carries the types the lookup named: a cache published ahead
        // of a failed heal is never retried, and every answer it types is then validated against a
        // registry that does not know the type.
        await EnsureTypesKnownAsync(map.Values, ct).ConfigureAwait(false);
        lock (_otherLock) _requestTypeCache[key] = map;
        return map;
    }

    private async Task<List<object>> EncryptTypedAsync(IReadOnlyList<TypedAnswer> answers, string companyCode, string serviceCode, System.Threading.CancellationToken ct)
    {
        var pub = await ServiceKeyAsync(companyCode, serviceCode, ct).ConfigureAwait(false)
            ?? throw new ConfigException($"no service key for {companyCode}/{serviceCode}");
        // Validate each typed answer against its request row's field type, BEFORE encryption.
        // Skip an answer whose type can't be resolved (do not invent one).
        var types = await RequestFieldTypesAsync(companyCode, serviceCode, ct).ConfigureAwait(false);
        foreach (var a in answers)
        {
            var registry = await FieldTypesAsync(ct).ConfigureAwait(false);
            if (types.TryGetValue(a.RequestFieldId, out var ft) && !registry.IsFieldValueValid(ft, a.Value))
                throw new ValidationException(a.RequestFieldId, ft);
        }
        return answers.Select(a => (object)new Dictionary<string, object?>
        {
            ["request_field_id"] = a.RequestFieldId,
            ["kind"] = a.Kind,
            ["value"] = Crypto.EncryptForPublicKey(a.Value, pub).ToObjectGraph(),
        }).ToList();
    }

    private async Task<RSA?> ServiceKeyAsync(string companyCode, string serviceCode, System.Threading.CancellationToken ct)
    {
        var key = $"{companyCode}/{serviceCode}";
        // TryGetValue, not a null check: a null value is a CACHED NEGATIVE and must count as a
        // hit. Lock only around the dictionary accesses, never the HTTP call.
        ulong gen;
        lock (_otherLock)
        {
            if (_serviceKeyCache.TryGetValue(key, out var hit)) return hit;
            _serviceKeyGen.TryGetValue(key, out gen);
        }
        var body = await _http.GetAsync($"{Keys}/{companyCode}/{serviceCode}", null, ct).ConfigureAwait(false);
        var spki = body.Kind == NodeKind.Object && body.Has("public_key") ? body.Get("public_key").AsString() : null;
        var loaded = string.IsNullOrEmpty(spki) ? null : Crypto.LoadPublicKey(spki!);
        // Store ONLY if no invalidation happened while the request was in flight.
        lock (_otherLock)
        {
            _serviceKeyGen.TryGetValue(key, out var now);
            if (now == gen) _serviceKeyCache[key] = loaded;
        }
        return loaded;
    }

    private async Task<RSA?> BatchKeyAsync(string userId, System.Threading.CancellationToken ct)
    {
        // TryGetValue, not a null check: a null value is a CACHED NEGATIVE (person has no key yet)
        // and must still count as a hit. Lock only around the map accesses, never the HTTP call.
        ulong gen;
        lock (_pubKeyLock)
        {
            if (_pubKeyCache.TryGetValue(userId, out var hit)) return hit;
            _pubKeyGen.TryGetValue(userId, out gen);
        }
        var body = await _http.PostAsync($"{Keys}/batch",
            jsonBody: new Dictionary<string, object?> { ["user_ids"] = new[] { userId } }, ct: ct).ConfigureAwait(false);
        string? spki = null;
        if (body.Kind == NodeKind.Object && body.Has("keys"))
        {
            var keys = body.Get("keys");
            if (keys.Kind == NodeKind.Object && keys.Has(userId)) spki = keys.Get(userId).AsString();
        }
        var cached = string.IsNullOrEmpty(spki) ? null : Crypto.LoadPublicKey(spki!);
        lock (_pubKeyLock)
        {
            // Store ONLY if no invalidation happened while the request was in flight.
            _pubKeyGen.TryGetValue(userId, out var now);
            if (now == gen) _pubKeyCache[userId] = cached;
        }
        return cached;
    }
}
