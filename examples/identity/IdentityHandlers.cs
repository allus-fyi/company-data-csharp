using System.Text.Json;
using Allus.CompanyData;
using IdentityModel.Client;
using IdentityModel.OidcClient;
using Microsoft.AspNetCore.Http;

namespace Allus.ExampleTestSuite.Identity;

/// <summary>
/// One run's cross-request state (PKCE verifier / OIDC nonce+redirect / outcome). Serialized to
/// <c>.runtime/runs/{runId}.json</c> by the shared <see cref="Runtime"/>. Free-form <see cref="Result"/>
/// is whatever the scenario produced.
/// </summary>
public sealed class Run : IRun
{
    public string RunId { get; set; } = "";
    public int Scenario { get; set; }
    public string Status { get; set; } = "pending"; // pending | done | failed
    public string? State { get; set; }
    public List<string> Calls { get; set; } = new();

    // Sign-in scenarios (1–4): the PKCE verifier that pairs with the challenge in the authorize URL.
    public string? Verifier { get; set; }

    // OIDC scenarios (5/6): the redirect the OIDC library needs to complete the exchange (state + PKCE
    // verifier ride the fields above; the OIDC library owns nonce handling internally).
    public string? RedirectUri { get; set; }

    // How GET /api/runs advances a still-pending run: detached_signin | detached_enroll | challenge |
    // enroll_redirect (null → completion arrives via /callback).
    public string? Wait { get; set; }
    public bool IsEnroll { get; set; }

    // Scenario 8: the challenge being polled.
    public string? ChallengeId { get; set; }

    public object? Result { get; set; }
    public string? Error { get; set; }
}

/// <summary>
/// The identity family's scenario handlers (contract v3, identity scenarios 1–8). HTTP dispatch → handler
/// → the SDK's intended top-level surface (or the OIDC library for scenarios 5/6). Handlers NEVER perform
/// raw platform HTTP and NEVER block on the SDK's long defaults — detached / challenge waits are
/// short-cycled (timeout=2) inside GET /api/runs.
///
/// Settings flow: the browser POSTs a scenario's setup values to POST /api/scenarios/{id}/config, which
/// writes them to a canonical SDK config FILE (.runtime/config/{id}.json). /start and /enroll then build
/// the SDK from that file via the role-appropriate file constructor (OAuthClient.FromConfig →
/// Config.FromIdwFile; Client.FromConfig → Config.FromFile) and run OFF the config. The request body of
/// /start is ignored; a /start with no saved config → 409 not_configured.
/// </summary>
public sealed class IdentityHandlers
{
    /// <summary>id → "runnable" | "guide". Scenario 7 is the guide card (no /start).</summary>
    private static readonly IReadOnlyDictionary<int, string> Scenarios = new Dictionary<int, string>
    {
        [1] = "runnable", [2] = "runnable", [3] = "runnable", [4] = "runnable",
        [5] = "runnable", [6] = "runnable", [7] = "guide", [8] = "runnable",
    };

    private static readonly HashSet<int> ServiceScenarios = new() { 4, 8 };   // also read live via the data Client
    private static readonly HashSet<int> OAuthUrlScenarios = new() { 1, 2, 3, 4, 8 }; // build a consent URL

    private const string DefaultApiUrl = "https://api.allme.fyi";
    private static readonly string DefaultAuthorizeBase = OAuthClient.DefaultAuthorizeUrl; // https://web.allme.fyi/auth

    /// <summary>
    /// A short-timeout HTTP client for the short-cycled polls. The SDK's poll helpers bound their LOGICAL
    /// loop with timeout=2, but that alone does not bound the underlying HTTP request; a single-worker
    /// server must not be pinned by one blackholed poll, so poll clients get a ~2.5s transport.
    /// </summary>
    private static readonly HttpClient PollHttp = new() { Timeout = TimeSpan.FromSeconds(2.5) };

    private readonly Runtime _rt;

    public IdentityHandlers(Runtime rt) => _rt = rt;

    /// <summary>The identity scenarios for GET /api/meta (numeric ids, scenario 7 is a guide).</summary>
    public IEnumerable<object> ScenarioList() =>
        Scenarios.OrderBy(kv => kv.Key).Select(kv => (object)new { id = kv.Key, kind = kv.Value });

    // ── POST /api/scenarios/{id}/config ──────────────────────────────────────────

    public async Task SaveConfig(HttpContext ctx, int id)
    {
        if (!IsRunnable(id)) { await Web.NotFound(ctx); return; }
        var body = await Web.ReadBody(ctx);

        // Canonical SDK config — the idw role for every OAuth scenario.
        var cfg = new Dictionary<string, object?>
        {
            ["api_url"] = (Web.Str(body, "apiUrl") is { Length: > 0 } a ? a : DefaultApiUrl).TrimEnd('/'),
            ["oauth_client_id"] = Web.Str(body, "oauthClientId") ?? "",
            ["oauth_redirect_uri"] = RedirectUri(ctx),
        };
        if (Web.Str(body, "oauthClientSecret") is { Length: > 0 } secret)
            cfg["oauth_client_secret"] = secret;

        // Scenario 3 (one_time): the OAuth app private key decrypts the claim values (config-only keys).
        if (id == 3)
        {
            if (Web.Str(body, "oauthPrivateKeyPem") is { Length: > 0 } pem)
                cfg["oauth_private_key"] = _rt.MaterializeConfigKey(pem);
            if (Web.Str(body, "oauthKeyPassphrase") is { Length: > 0 } pass)
                cfg["oauth_key_passphrase"] = pass;
        }

        // Scenarios 4/8 also read live values via the service data Client — add the service-role keys.
        if (ServiceScenarios.Contains(id))
        {
            cfg["client_id"] = Web.Str(body, "clientId") ?? "";
            cfg["client_secret"] = Web.Str(body, "clientSecret") ?? "";
            if (Web.Str(body, "servicePrivateKeyPem") is { Length: > 0 } sPem)
                cfg["service_private_key"] = _rt.MaterializeConfigKey(sPem);
            cfg["key_passphrase"] = Web.Str(body, "keyPassphrase") ?? "";
        }

        var configPath = _rt.WriteConfig(id.ToString(), cfg);

        // Demo-only run parameters (NOT SDK Config fields) → meta sidecar.
        var meta = new Dictionary<string, object?>();
        if (OAuthUrlScenarios.Contains(id))
            meta["authorize_base"] = Web.Str(body, "authorizeBase") is { Length: > 0 } ab ? ab : DefaultAuthorizeBase;
        if (id == 3)
            meta["claims"] = Claims(body);
        if (id == 8)
        {
            meta["share_code"] = Web.Str(body, "shareCode") ?? "";
            if (Web.Str(body, "context") is { Length: > 0 } context)
                meta["context"] = context;
        }
        _rt.WriteConfigMeta(id.ToString(), meta);

        await Web.WriteJson(ctx, new { ok = true, configPath });
    }

    // ── POST /api/scenarios/{id}/start ────────────────────────────────────────────

    public async Task Start(HttpContext ctx, int id)
    {
        if (!IsRunnable(id)) { await Web.NotFound(ctx); return; }
        if (!_rt.HasConfig(id.ToString())) { await Web.WriteJson(ctx, new { error = "not_configured" }, 409); return; }

        var runId = _rt.NewRunId();
        var run = new Run { Scenario = id, Status = "pending", State = runId };

        switch (id)
        {
            case 1: // Sign in — redirect
            case 3: // One-time claims
            case 4: // Connect (stay-connected)
            {
                var (verifier, challenge) = Pkce.Generate();
                run.Verifier = verifier;
                var mode = id == 1 ? "signin" : id == 3 ? "one_time" : "connect";
                var claims = id == 3 ? ClaimObjects(id) : null;
                var oauth = OAuthClientFor(id);
                var url = oauth.AuthorizeUrl(mode, claims, runId, "redirect", challenge);
                run.Calls.Add("OAuthClient.AuthorizeUrl");
                _rt.WriteRun(runId, run);
                await Web.WriteJson(ctx, new { runId, action = new { type = "redirect", url } });
                return;
            }

            case 2: // Sign in — detached
            {
                var (verifier, challenge) = Pkce.Generate();
                run.Verifier = verifier;
                run.Wait = "detached_signin";
                var oauth = OAuthClientFor(id);
                var url = oauth.AuthorizeUrl("signin", null, runId, "detached", challenge);
                run.Calls.Add("OAuthClient.AuthorizeUrl");
                _rt.WriteRun(runId, run);
                await Web.WriteJson(ctx, new { runId, action = new { type = "detached", url } });
                return;
            }

            case 5: // OIDC login
            case 6: // OIDC — continue on your phone (#431)
            {
                // The OIDC library owns PKCE + state + nonce (the point of the #314 demonstration). Its
                // generated `state` IS the runId, so /callback finds the run by it (contract: state == runId).
                var oidc = OidcClientFor(id);
                var authState = await oidc.PrepareLoginAsync();
                var oidcRunId = authState.State;
                run.State = oidcRunId;
                run.Verifier = authState.CodeVerifier;
                run.RedirectUri = authState.RedirectUri;
                run.Calls.Add("(oidc) OidcClient.PrepareLoginAsync");
                _rt.WriteRun(oidcRunId, run);
                await Web.WriteJson(ctx, new { runId = oidcRunId, action = new { type = "redirect", url = authState.StartUrl } });
                return;
            }

            case 8: // Standalone service-2FA — the challenge step
            {
                var meta = _rt.ReadConfigMeta(id.ToString());
                var shareCode = Web.Str(meta, "share_code") ?? "";
                var context = Web.Str(meta, "context") is { Length: > 0 } c ? c : null;
                var idempotencyKey = ("demo-" + runId)[..Math.Min(64, ("demo-" + runId).Length)];
                run.Wait = "challenge";
                var client = ServiceClientFor(id);
                var challenge = await client.TwoFactor.ChallengeAsync(shareCode, idempotencyKey, context);
                run.ChallengeId = challenge.ChallengeId;
                run.Calls.Add("Client.TwoFactor");
                run.Calls.Add("TwoFactorClient.ChallengeAsync");
                _rt.WriteRun(runId, run);
                await Web.WriteJson(ctx, new { runId, action = new { type = "challenge", matchingDigits = challenge.MatchingDigits } });
                return;
            }
        }
    }

    // ── POST /api/scenarios/{id}/enroll (scenario 8) ──────────────────────────────

    public async Task Enroll(HttpContext ctx, int id)
    {
        if (id != 8) { await Web.NotFound(ctx); return; }
        if (!_rt.HasConfig(id.ToString())) { await Web.WriteJson(ctx, new { error = "not_configured" }, 409); return; }

        var body = await Web.ReadBody(ctx);
        var responseMode = Web.Str(body, "responseMode") == "detached" ? "detached" : "redirect"; // default redirect
        var runId = _rt.NewRunId();

        var oauth = OAuthClientFor(id);
        var url = oauth.AuthorizeUrl("2fa_enroll", null, runId, responseMode);

        var run = new Run
        {
            Scenario = 8,
            IsEnroll = true,
            Status = "pending",
            State = runId,
            Wait = responseMode == "detached" ? "detached_enroll" : "enroll_redirect",
        };
        run.Calls.Add("OAuthClient.AuthorizeUrl");
        _rt.WriteRun(runId, run);

        object action = responseMode == "detached"
            ? new { type = "detached", url }
            : new { type = "redirect", url };
        await Web.WriteJson(ctx, new { runId, action });
    }

    // ── GET /callback ──────────────────────────────────────────────────────────────

    public async Task Callback(HttpContext ctx)
    {
        var state = ctx.Request.Query["state"].ToString();
        var run = _rt.ReadRun<Run>(state);
        if (run is null) { ctx.Response.Redirect("/?error=unknown_run"); return; }
        var id = run.Scenario;

        try
        {
            if (ctx.Request.Query["enrolled"].ToString() == "true")
            {
                // Redirect-leg enrollment outcome (#436) — nothing to exchange; record it.
                run.Status = "done";
                run.Result = new { enrolled = true };
                run.Calls.Add("callback(enrolled=true)");
            }
            else if (ctx.Request.Query["code"].ToString() is { Length: > 0 } code)
            {
                run = id is 5 or 6 ? await CompleteOidc(run, ctx) : await CompleteSignin(run, code);
            }
            else
            {
                run.Status = "failed";
                run.Error = "callback missing code / enrolled";
            }
        }
        catch (Exception e)
        {
            run.Status = "failed";
            run.Error = e.Message;
        }

        _rt.WriteRun(state, run);
        ctx.Response.Redirect($"/?scenario={id}&run={Uri.EscapeDataString(state)}");
    }

    // ── GET /api/runs/{runId} ────────────────────────────────────────────────────

    public async Task RunStatus(HttpContext ctx, string runId)
    {
        var run = _rt.ReadRun<Run>(runId);
        if (run is null) { await Web.WriteJson(ctx, new { error = "not_found" }, 404); return; }

        // Idempotent: a terminal outcome is returned on every poll until TTL/Clear.
        if (run.Status == "pending")
        {
            run = await Advance(run);
            _rt.WriteRun(runId, run);
        }

        var outObj = new Dictionary<string, object?> { ["status"] = run.Status, ["calls"] = run.Calls };
        if (run.Result is not null) outObj["result"] = run.Result;
        if (run.Error is not null) outObj["error"] = run.Error;
        await Web.WriteJson(ctx, outObj);
    }

    /// <summary>
    /// Short-cycled advance for a pending run awaiting a detached / challenge outcome. ONE SDK wait with
    /// timeout=2 per poll; the SDK's LOGICAL "not completed within Ns" timeout is treated as still-pending;
    /// a real transport failure is a failed run. Clients are rebuilt from the run's scenario config file.
    /// </summary>
    private async Task<Run> Advance(Run run)
    {
        var id = run.Scenario;
        try
        {
            switch (run.Wait)
            {
                case "detached_signin":
                {
                    var oauth = OAuthClientFor(id, shortTimeout: true);
                    var body = await oauth.PollResultAsync(run.State!, 2, 2);
                    run.Calls.Add("OAuthClient.PollResultAsync");
                    if (body.TryGetProperty("code", out var codeEl) && codeEl.GetString() is { Length: > 0 } code)
                        run = await CompleteSignin(run, code);
                    break;
                }
                case "detached_enroll":
                {
                    var oauth = OAuthClientFor(id, shortTimeout: true);
                    var body = await oauth.PollResultAsync(run.State!, 2, 2);
                    run.Calls.Add("OAuthClient.PollResultAsync");
                    if (body.TryGetProperty("enrolled", out var en) && en.ValueKind == JsonValueKind.True)
                    {
                        run.Status = "done";
                        run.Result = new { enrolled = true };
                    }
                    break;
                }
                case "challenge":
                {
                    var client = ServiceClientFor(id, shortTimeout: true);
                    var res = await client.TwoFactor.WaitForResultAsync(run.ChallengeId!, 2, 2);
                    run.Calls.Add("TwoFactorClient.WaitForResultAsync");
                    run.Status = "done";
                    run.Result = new { status = res.Status, completed_at = res.CompletedAt };
                    break;
                }
                // else (redirect / continue-on-phone): completion arrives via /callback — stay pending.
            }
        }
        catch (ApiException e) when (e.Status == 0 && e.Message.Contains("not completed within"))
        {
            // The SDK poll helpers signal a LOGICAL "not completed within Ns" timeout as ApiException(0)
            // with that exact sentinel — still pending (contract §"short-cycled SDK waits").
            return run;
        }
        catch (Exception e)
        {
            // A real network/transport failure (or any other error) is a failed run, not eternal pending.
            run.Status = "failed";
            run.Error = e.Message;
        }
        return run;
    }

    // ── SDK / OIDC completion helpers ──────────────────────────────────────────────

    /// <summary>
    /// Complete a redirect / detached SIGN-IN (scenarios 1–4): exchange + read identity via
    /// CompleteSignInAsync, and for connect (4) read the person's LIVE values via the service data Client.
    /// </summary>
    private async Task<Run> CompleteSignin(Run run, string code)
    {
        var id = run.Scenario;
        var oauth = OAuthClientFor(id);
        var res = await oauth.CompleteSignInAsync(code, run.Verifier);
        run.Calls.Add("OAuthClient.CompleteSignInAsync");

        var result = new Dictionary<string, object?>
        {
            ["user"] = new { sub = res.Sub, share_code = res.ShareCode, display_name = res.DisplayName },
            ["mode"] = res.Mode,
            ["two_factor"] = res.TwoFactor,
            ["values"] = res.Values,
        };

        if (id == 4)
        {
            // Connect: read the person's LIVE values via the service data client, matched by share_code.
            var shareCode = res.ShareCode ?? "";
            var client = ServiceClientFor(id);
            var live = new Dictionary<string, string?>();
            await foreach (var conn in client.ConnectionsAsync())
            {
                if (shareCode.Length > 0 && conn.ShareCode == shareCode)
                {
                    foreach (var (slug, value) in conn.Values)
                        live[slug] = value.ValueObj?.ToString();
                    break;
                }
            }
            run.Calls.Add("Client.ConnectionsAsync");
            result["live_values"] = live;
        }

        run.Status = "done";
        run.Result = result;
        return run;
    }

    /// <summary>Complete an OIDC sign-in (scenarios 5/6) via the OIDC library — id_token verified.</summary>
    private async Task<Run> CompleteOidc(Run run, HttpContext ctx)
    {
        var oidc = OidcClientFor(run.Scenario);
        // Sessionless: rebuild the authorize state the library needs from the run stash.
        var authState = new AuthorizeState
        {
            State = run.State!,
            CodeVerifier = run.Verifier ?? "",
            RedirectUri = run.RedirectUri ?? ConfigRedirectUri(run.Scenario, ctx),
        };
        var data = ctx.Request.QueryString.Value?.TrimStart('?') ?? "";
        var result = await oidc.ProcessResponseAsync(data, authState);
        run.Calls.Add("(oidc) OidcClient.ProcessResponseAsync");
        if (result.IsError)
            throw new InvalidOperationException(result.Error ?? "OIDC response error");

        var claims = result.User?.Claims.ToDictionary(c => c.Type, c => (object?)c.Value)
                     ?? new Dictionary<string, object?>();
        run.Status = "done";
        run.Result = new { claims };
        return run;
    }

    // ── SDK / OIDC client builders — built from the persisted config FILE ──────────

    /// <summary>
    /// Build the OAuth client OFF the scenario's config file via the idw file constructor. FromConfig is
    /// used for the default (deployed) authorize base — the acceptance path; a non-default base (local
    /// stack) still loads Config from the file, only supplying the alternate base the wrapper cannot set.
    /// </summary>
    private OAuthClient OAuthClientFor(int id, bool shortTimeout = false)
    {
        var path = _rt.ConfigPathFor(id.ToString());
        IHttpTransport? transport = shortTimeout ? new HttpTransport(PollHttp) : null;
        var baseUrl = Web.Str(_rt.ReadConfigMeta(id.ToString()), "authorize_base") ?? "";
        if (baseUrl.Length == 0 || baseUrl == OAuthClient.DefaultAuthorizeUrl)
            return OAuthClient.FromConfig(path, transport);
        return new OAuthClient(Config.FromIdwFile(path), transport, authorizeUrl: baseUrl);
    }

    /// <summary>Build the service data client OFF the scenario's config file (service role).</summary>
    private Client ServiceClientFor(int id, bool shortTimeout = false)
    {
        var path = _rt.ConfigPathFor(id.ToString());
        if (!shortTimeout) return Client.FromConfig(path);
        var cfg = Config.FromFile(path);
        return new Client(cfg, new ApiHttp(cfg, new HttpTransport(PollHttp)));
    }

    /// <summary>Build the OIDC client (the #314 compliance surface) from the config file.</summary>
    private OidcClient OidcClientFor(int id)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(_rt.ConfigPathFor(id.ToString())));
        var cfg = doc.RootElement;
        var options = new OidcClientOptions
        {
            Authority = Web.Str(cfg, "api_url"),
            ClientId = Web.Str(cfg, "oauth_client_id"),
            ClientSecret = Web.Str(cfg, "oauth_client_secret"),
            RedirectUri = Web.Str(cfg, "oauth_redirect_uri"),
            Scope = "openid profile email",
            // The token endpoint's only method is client_secret_post.
            TokenClientCredentialStyle = ClientCredentialStyle.PostBody,
            // Plain front-channel authorize (the platform does not implement Pushed Authorization Requests).
            DisablePushedAuthorization = true,
        };
        // Issuer/endpoint override tolerance: discovery is driven off the configured api base, so a local
        // stack whose issuer host differs from the discovery host still works.
        options.Policy.Discovery.RequireHttps = false;
        options.Policy.Discovery.ValidateIssuerName = false;
        options.Policy.Discovery.ValidateEndpoints = false;
        return new OidcClient(options);
    }

    // ── input / config plumbing ────────────────────────────────────────────────────

    /// <summary>The registered redirect URI: http://{host}/callback (host = the serving origin).</summary>
    private static string RedirectUri(HttpContext ctx) => $"http://{ctx.Request.Host.Value}/callback";

    /// <summary>The redirect URI recorded in the scenario's config file (used by the OIDC library).</summary>
    private string ConfigRedirectUri(int id, HttpContext ctx)
    {
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(_rt.ConfigPathFor(id.ToString())));
            return Web.Str(doc.RootElement, "oauth_redirect_uri") ?? RedirectUri(ctx);
        }
        catch (Exception) { return RedirectUri(ctx); }
    }

    private static List<string> Claims(JsonElement body)
    {
        if (body.ValueKind == JsonValueKind.Object && body.TryGetProperty("claims", out var arr) &&
            arr.ValueKind == JsonValueKind.Array && arr.GetArrayLength() > 0)
            return arr.EnumerateArray().Select(e => e.ValueKind == JsonValueKind.String ? e.GetString()! : e.ToString()).ToList();
        return new List<string> { "email", "phone" }; // a small default claim set
    }

    private List<Claim> ClaimObjects(int id)
    {
        var meta = _rt.ReadConfigMeta(id.ToString());
        var types = meta.ValueKind == JsonValueKind.Object && meta.TryGetProperty("claims", out var arr) &&
                    arr.ValueKind == JsonValueKind.Array
            ? arr.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.String).Select(e => e.GetString()!)
            : Enumerable.Empty<string>();
        return types.Select(t => new Claim(t)).ToList();
    }

    private static bool IsRunnable(int id) => Scenarios.TryGetValue(id, out var k) && k == "runnable";
}
