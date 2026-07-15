// The CUSTOMER-role client (b2b, #168).
//
// CustomerClient is what a connecting company uses to consume and answer another
// company's service over its acct_* credentials: list company↔company connections,
// provide/edit typed consent answers, read (and decrypt) issued documents, run contract
// flows, drain the account change feed, and verify account-level webhooks. It reuses the
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

    private readonly Config _config;
    private readonly ApiHttp _http;
    private readonly RSA? _accountKey;
    private readonly Func<double, System.Threading.CancellationToken, Task> _sleep;
    private readonly System.Collections.Generic.Dictionary<string, RSA?> _pubKeyCache = new();
    private readonly System.Collections.Generic.Dictionary<string, RSA?> _serviceKeyCache = new();
    // "companyCode/serviceCode" → {request_field_id: field_type}, for typed-answer validation (#302).
    private readonly System.Collections.Generic.Dictionary<string, System.Collections.Generic.Dictionary<string, string>> _requestTypeCache = new();
    private Pump? _pump;

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

    public async Task<object?> SubmitFlowAnswersAsync(string connectionId, string runId, object body,
        System.Threading.CancellationToken ct = default)
        => (await _http.PostAsync($"{Conn}/{connectionId}/flow-runs/{runId}/answers", jsonBody: body, ct: ct).ConfigureAwait(false)).ToObjectGraph();

    public async Task<object?> DeclineFlowRunAsync(string connectionId, string runId, System.Threading.CancellationToken ct = default)
        => (await _http.PostAsync($"{Conn}/{connectionId}/flow-runs/{runId}/decline", jsonBody: null, ct: ct).ConfigureAwait(false)).ToObjectGraph();

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

    // ── change feed (P2 account feed) ─────────────────────────────────────────────

    public Pump Pump => _pump ??= new Pump(_config, FetchChangesAsync, DecryptChange, sleep: _sleep);

    private async Task<List<Node>> FetchChangesAsync(int limit, System.Threading.CancellationToken ct)
    {
        var body = await _http.GetAsync(CustomerChanges, new Dictionary<string, string> { ["limit"] = limit.ToString() }, ct).ConfigureAwait(false);
        var items = body.Kind == NodeKind.Object && body.Has("changes") ? body.Get("changes").AsList()
            : body.Kind == NodeKind.List ? body.AsList() : new List<Node>();
        return items.Where(o => o.Kind == NodeKind.Object).ToList();
    }

    private Change DecryptChange(Node ev) => Change.FromApi(ev, _ => null, DecryptAccount);

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
        => Webhooks.ParseWebhook(rawBody, headers, _config, _ => null, DecryptAccount, accountKey: _accountKey);

    public Change HandleWebhook(object rawBody, IReadOnlyDictionary<string, string>? headers)
        => Webhooks.HandleWebhook(rawBody, headers, _config, _ => null, DecryptAccount, accountKey: _accountKey);

    // ── internals ──────────────────────────────────────────────────────────────────

    private string DecryptAccount(object wrapper)
    {
        if (_accountKey is null) throw new ConfigException("account_private_key is required to decrypt this value");
        return Crypto.Decrypt(wrapper, _accountKey);
    }

    /// <summary>
    /// Resolve {request_field_id: field_type} for a service from the connect-screen lookup, cached
    /// per company/service. Best-effort — a lookup failure yields an empty map so typed-answer
    /// validation is simply skipped (#302).
    /// </summary>
    private async Task<Dictionary<string, string>> RequestFieldTypesAsync(string companyCode, string serviceCode, System.Threading.CancellationToken ct)
    {
        var key = $"{companyCode}/{serviceCode}";
        if (_requestTypeCache.TryGetValue(key, out var cached)) return cached;
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
        _requestTypeCache[key] = map;
        return map;
    }

    private async Task<List<object>> EncryptTypedAsync(IReadOnlyList<TypedAnswer> answers, string companyCode, string serviceCode, System.Threading.CancellationToken ct)
    {
        var pub = await ServiceKeyAsync(companyCode, serviceCode, ct).ConfigureAwait(false)
            ?? throw new ConfigException($"no service key for {companyCode}/{serviceCode}");
        // #302: validate each typed answer against its request row's field type, BEFORE encryption.
        // Skip an answer whose type can't be resolved (do not invent one).
        var types = await RequestFieldTypesAsync(companyCode, serviceCode, ct).ConfigureAwait(false);
        foreach (var a in answers)
        {
            if (types.TryGetValue(a.RequestFieldId, out var ft) && !FieldValidation.IsValid(ft, a.Value))
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
        if (!_serviceKeyCache.TryGetValue(key, out var cached))
        {
            var body = await _http.GetAsync($"{Keys}/{companyCode}/{serviceCode}", null, ct).ConfigureAwait(false);
            var spki = body.Kind == NodeKind.Object && body.Has("public_key") ? body.Get("public_key").AsString() : null;
            cached = string.IsNullOrEmpty(spki) ? null : Crypto.LoadPublicKey(spki!);
            _serviceKeyCache[key] = cached;
        }
        return cached;
    }

    private async Task<RSA?> BatchKeyAsync(string userId, System.Threading.CancellationToken ct)
    {
        if (!_pubKeyCache.TryGetValue(userId, out var cached))
        {
            var body = await _http.PostAsync($"{Keys}/batch",
                jsonBody: new Dictionary<string, object?> { ["user_ids"] = new[] { userId } }, ct: ct).ConfigureAwait(false);
            string? spki = null;
            if (body.Kind == NodeKind.Object && body.Has("keys"))
            {
                var keys = body.Get("keys");
                if (keys.Kind == NodeKind.Object && keys.Has(userId)) spki = keys.Get(userId).AsString();
            }
            cached = string.IsNullOrEmpty(spki) ? null : Crypto.LoadPublicKey(spki!);
            _pubKeyCache[userId] = cached;
        }
        return cached;
    }
}
