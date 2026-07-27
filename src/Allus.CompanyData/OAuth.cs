// "Sign in with allme" — the RP-side OAuth client (#195).
//
// A third-party site embeds a "Sign in with allme" button, sends the person to the hosted consent
// screen, and — once they approve — receives an authorization code at its redirect URI. This wraps
// the RP half: build the button URL, exchange the code, read the identity, and (for one_time)
// decrypt the shared values. Config-only key handling still holds — the app private key + passphrase
// come from Config (the idw role), never a method argument.

using System.Security.Cryptography;
using System.Text.Json;

namespace Allus.CompanyData;

/// <summary>
/// A claim the relying party asks for — a REQUEST FIELD (#498).
///
/// <para>You describe what you need: a <c>Name</c> (the claim's identity on the wire), a field
/// <c>Type</c>, an advisory <c>Suggest</c>ion, whether it is <c>Required</c>, and whether only a
/// #311-<c>Verified</c> answer will do. You never name one of the person's fields — THEY decide which
/// of theirs answers it.</para>
///
/// <para><c>Name</c> is MANDATORY and must be unique within one request: everything downstream is
/// keyed by it (the stored mapping, the consent outcome, and the <c>Values</c>/<c>Attestations</c>
/// maps <see cref="OAuthClient.CompleteSignInAsync"/> returns). Two claims sharing a name are
/// rejected rather than silently coalesced.</para>
///
/// <para><c>Verified</c> is accepted only where it can be honoured (#498 §3.1b): on the OIDC flow,
/// and only for a type #311 can attest (v1: <c>email</c>). Sending it on a <c>one_time</c> request is
/// refused with <c>invalid_request</c> — that leg carries no source row id, so the server could
/// neither enforce the requirement nor attest it.</para>
/// </summary>
public sealed record Claim(
    string Name,
    string Type,
    string? Suggest = null,
    bool Required = false,
    bool Verified = false,
    string? Label = null);

/// <summary>
/// Proof that a delivered value is the #311-verified one (#498 §3.1a).
///
/// <para>Present only for a <c>Verified</c> claim under ENCRYPTED delivery. The server builds and
/// seals it against your app key — a client-supplied attestation is never accepted — so it attests
/// the server's own record of the row the person chose, which is what makes it evidence.</para>
///
/// <para><c>Verified</c> is computed BY THIS SDK, in constant time, over the plaintext it just
/// decrypted; it is never passed through from the server. <b>A <c>Verified == false</c> entry means
/// MISMATCH and you MUST reject the value.</b> A claim ABSENT from <c>Attestations</c> means "not
/// attested" — never "wrong" — and must be treated as unverified.</para>
///
/// <para><c>VerifiedAt</c> carries the snapshot caveat: it attests the value as verified AT THAT
/// MOMENT, not verified today. A field loses its verification whenever the person re-saves it.</para>
/// </summary>
/// <param name="Verified">Recomputed here, constant-time; false = MISMATCH, reject the value.</param>
/// <param name="Hash">Lowercase hex.</param>
/// <param name="Salt">Lowercase hex.</param>
/// <param name="VerifiedAt">When the field was verified — a snapshot, not verified-today.</param>
public sealed record Attestation(bool Verified, string Hash, string Salt, string VerifiedAt);

/// <summary>
/// The decrypted conclusion of <see cref="OAuthClient.CompleteSignInAsync"/>.
///
/// <para>#498 §5: <c>Sub</c> IS the person's SHARE CODE and is byte-identical to the id_token's
/// <c>sub</c>; <c>ShareCode</c> is retained beside it and now simply equals it. <c>DisplayName</c> is
/// GONE — it is a consented <c>name</c> claim now, or nothing: ask for
/// <c>new Claim("name", "text")</c> and read <c>Values["name"]</c>.</para>
///
/// <para>#498 §3.1a: <c>Attestations</c> is an ADDITIVE sibling map keyed by the SAME claim name as
/// <c>Values</c>, present only for a <c>Verified</c> claim under ENCRYPTED delivery. An integration
/// that never reads it behaves exactly as before.</para>
/// </summary>
public sealed class SignInResult
{
    public string? Sub { get; init; }
    public string? ShareCode { get; init; }
    public string? Mode { get; init; }
    public bool TwoFactor { get; init; }
    public IReadOnlyDictionary<string, string> Values { get; init; } = new Dictionary<string, string>();
    public IReadOnlyDictionary<string, Attestation> Attestations { get; init; } = new Dictionary<string, Attestation>();
}

/// <summary>The RP-side "Sign in with allme" client.</summary>
public sealed class OAuthClient
{
    /// <summary>The hosted consent surface. Native apps claim this https link; web is the fallback.</summary>
    public const string DefaultAuthorizeUrl = "https://web.allme.fyi/auth";

    private static readonly HashSet<string> NonClaimable = new() { "photo", "document", "legal_document" };
    private const int MaxClaims = 15;
    private static readonly HashSet<string> Modes = new() { "signin", "one_time", "connect", "2fa_enroll" };
    private static readonly HashSet<string> ResponseModes = new() { "redirect", "detached" };

    private readonly Config _config;
    private readonly IHttpTransport _transport;
    private readonly string _authorizeBase;
    private readonly Func<int, Task> _sleep;
    private readonly string _apiUrl;

    public OAuthClient(
        Config config,
        IHttpTransport? transport = null,
        string authorizeUrl = DefaultAuthorizeUrl,
        Func<int, Task>? sleep = null)
    {
        if (string.IsNullOrEmpty(config.OAuthClientId) || string.IsNullOrEmpty(config.OAuthRedirectUri))
            throw new ConfigException("OAuthClient requires oauth_client_id + oauth_redirect_uri (idw role)");
        _config = config;
        _transport = transport ?? new HttpTransport();
        _authorizeBase = authorizeUrl;
        _sleep = sleep ?? (ms => Task.Delay(ms));
        _apiUrl = config.ApiUrl.TrimEnd('/');
    }

    /// <summary>Build from an idw-role JSON config file.</summary>
    public static OAuthClient FromConfig(string path, IHttpTransport? transport = null) =>
        new(Config.FromIdwFile(path), transport);

    /// <summary>Build from ALLUS_OAUTH_* env vars.</summary>
    public static OAuthClient FromEnv(IHttpTransport? transport = null) =>
        new(Config.FromIdwEnv(), transport);

    /// <summary>Build the consent-screen URL — the "Sign in with allme" button target.</summary>
    public string AuthorizeUrl(
        string mode,
        IEnumerable<Claim>? claims = null,
        string? state = null,
        string responseMode = "redirect",
        string? codeChallenge = null,
        string? redirectUri = null)
    {
        if (!Modes.Contains(mode))
            throw new ConfigException($"invalid mode '{mode}' (expected signin | one_time | connect | 2fa_enroll)");
        if (!ResponseModes.Contains(responseMode))
            throw new ConfigException($"invalid responseMode '{responseMode}' (expected redirect | detached)");

        var parts = new List<string>
        {
            "client_id=" + Uri.EscapeDataString(_config.OAuthClientId!),
            "redirect_uri=" + Uri.EscapeDataString(redirectUri ?? _config.OAuthRedirectUri!),
            "mode=" + Uri.EscapeDataString(mode),
            "response_mode=" + Uri.EscapeDataString(responseMode),
        };
        if (state is not null) parts.Add("state=" + Uri.EscapeDataString(state));
        if (!string.IsNullOrEmpty(codeChallenge))
        {
            parts.Add("code_challenge=" + Uri.EscapeDataString(codeChallenge));
            parts.Add("code_challenge_method=S256");
        }
        var cleaned = CleanClaims(claims);
        if (cleaned.Count > 0)
            parts.Add("claims=" + Uri.EscapeDataString(JsonSerializer.Serialize(cleaned)));
        return _authorizeBase + "?" + string.Join("&", parts);
    }

    private static List<Dictionary<string, object>> CleanClaims(IEnumerable<Claim>? claims)
    {
        var outList = new List<Dictionary<string, object>>();
        if (claims is null) return outList;
        var seen = new HashSet<string>();
        foreach (var c in claims)
        {
            if (string.IsNullOrEmpty(c.Type) || NonClaimable.Contains(c.Type)) continue;
            // #498 §2: `Name` is the claim's identity and it is mandatory. Refused HERE rather than
            // left to the API, so the integration error surfaces at the call that made it.
            var name = (c.Name ?? string.Empty).Trim();
            if (name.Length == 0)
                throw new ConfigException("every claim must carry a `Name` (#498)");
            if (!seen.Add(name))
                throw new ConfigException($"duplicate claim name '{name}' (#498)");
            var entry = new Dictionary<string, object> { ["name"] = name, ["type"] = c.Type };
            if (!string.IsNullOrEmpty(c.Suggest)) entry["suggest"] = c.Suggest;
            if (c.Required) entry["required"] = true;
            if (c.Verified) entry["verified"] = true;
            if (!string.IsNullOrEmpty(c.Label)) entry["label"] = c.Label;
            outList.Add(entry);
            if (outList.Count >= MaxClaims) break;
        }
        return outList;
    }

    /// <summary>Swap the authorization code for a token (POST /oauth2/token).</summary>
    public async Task<JsonElement> ExchangeCodeAsync(string code, string? codeVerifier = null, CancellationToken ct = default)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = _config.OAuthClientId!,
            ["code"] = code,
            ["redirect_uri"] = _config.OAuthRedirectUri!,
        };
        if (!string.IsNullOrEmpty(codeVerifier)) form["code_verifier"] = codeVerifier!;
        if (!string.IsNullOrEmpty(_config.OAuthClientSecret)) form["client_secret"] = _config.OAuthClientSecret!;
        var res = await _transport.PostFormAsync($"{_apiUrl}/oauth2/token", form, Accept(), ct).ConfigureAwait(false);
        return Parse(res, "token exchange");
    }

    /// <summary>Read the signed-in identity (GET /api/oauth/userinfo) with the RP token.</summary>
    public async Task<JsonElement> UserinfoAsync(string accessToken, CancellationToken ct = default)
    {
        var headers = new Dictionary<string, string> { ["Authorization"] = $"Bearer {accessToken}", ["Accept"] = "application/json" };
        var res = await _transport.GetAsync($"{_apiUrl}/api/oauth/userinfo", null, headers, ct).ConfigureAwait(false);
        return Parse(res, "userinfo");
    }

    /// <summary>Exchange + userinfo in one call, decrypting one_time values via the configured app key.</summary>
    public async Task<SignInResult> CompleteSignInAsync(string code, string? codeVerifier = null, CancellationToken ct = default)
    {
        var token = await ExchangeCodeAsync(code, codeVerifier, ct).ConfigureAwait(false);
        var accessToken = Str(token, "access_token");
        if (string.IsNullOrEmpty(accessToken))
            throw new AuthException("token exchange returned no access_token");
        var info = await UserinfoAsync(accessToken!, ct).ConfigureAwait(false);
        var values = new Dictionary<string, string>();
        var attestations = new Dictionary<string, Attestation>();
        if (info.TryGetProperty("values", out var vals) && vals.ValueKind == JsonValueKind.Object)
        {
            values = DecryptValues(vals);
            if (info.TryGetProperty("values_attestation", out var att) && att.ValueKind == JsonValueKind.Object)
                attestations = DecryptAttestations(att, values);
        }
        return new SignInResult
        {
            Sub = Str(info, "sub"),
            ShareCode = Str(info, "share_code"),
            Mode = Str(info, "mode") ?? Str(token, "mode"),
            TwoFactor = info.TryGetProperty("two_factor", out var tf) && tf.ValueKind == JsonValueKind.True,
            Values = values,
            Attestations = attestations,
        };
    }

    /// <summary>
    /// #498 §3.1a — open the app-key-sealed attestations and attest each value ourselves.
    ///
    /// <para>A SECOND decrypt per verified claim: <c>Values</c> is byte-identical to before, but each
    /// attestation is its own <c>{"_enc":1,...}</c> object. A passthrough accessor handing back an
    /// undecrypted blob would not be an implementation of this.</para>
    ///
    /// <para>An attestation that cannot be opened or parsed is DROPPED, not surfaced as
    /// <c>Verified == false</c> — absence means "not attested" and a mismatch means "reject the
    /// value", and conflating the two would turn a key or transport problem into an accusation that
    /// the data was tampered with.</para>
    /// </summary>
    private Dictionary<string, Attestation> DecryptAttestations(JsonElement raw, Dictionary<string, string> values)
    {
        var outMap = new Dictionary<string, Attestation>();
        var pem = File.ReadAllText(_config.OAuthPrivateKey!);
        using RSA key = Crypto.LoadPrivateKey(pem, _config.OAuthKeyPassphrase!);
        foreach (var prop in raw.EnumerateObject())
        {
            if (!values.TryGetValue(prop.Name, out var plaintext)) continue;
            JsonElement parsed;
            try
            {
                using var doc = JsonDocument.Parse(Crypto.Decrypt(prop.Value, key));
                parsed = doc.RootElement.Clone();
            }
            catch (Exception)
            {
                continue;
            }
            if (parsed.ValueKind != JsonValueKind.Object) continue;
            var hash = Str(parsed, "hash");
            var salt = Str(parsed, "salt");
            if (string.IsNullOrEmpty(hash) || string.IsNullOrEmpty(salt)) continue;
            outMap[prop.Name] = new Attestation(
                // Recomputed here, constant-time, over the plaintext just decrypted — never trusted
                // from the server. false = the delivered value is NOT the verified one; reject it.
                Crypto.HashMatches(salt!, hash!, plaintext),
                hash!,
                salt!,
                Str(parsed, "verified_at") ?? string.Empty);
        }
        return outMap;
    }

    private Dictionary<string, string> DecryptValues(JsonElement values)
    {
        if (string.IsNullOrEmpty(_config.OAuthPrivateKey) || string.IsNullOrEmpty(_config.OAuthKeyPassphrase))
            throw new ConfigException("one_time values present but OAuthPrivateKey / OAuthKeyPassphrase not configured");
        var pem = File.ReadAllText(_config.OAuthPrivateKey!);
        using RSA key = Crypto.LoadPrivateKey(pem, _config.OAuthKeyPassphrase!);
        var outMap = new Dictionary<string, string>();
        foreach (var prop in values.EnumerateObject())
            outMap[prop.Name] = Crypto.Decrypt(prop.Value, key);
        return outMap;
    }

    /// <summary>
    /// Poll /oauth2/result for a detached sign-in or enrollment (single-delivery). A detached sign-in
    /// returns <c>{code, state}</c>; a detached <c>2fa_enroll</c> returns <c>{enrolled: true, state}</c>
    /// (#481). Returns on the first delivered shape (<c>code</c> OR <c>enrolled</c>) and never polls past
    /// it, so a one-shot enrollment result is not consumed and lost.
    /// </summary>
    public async Task<JsonElement> PollResultAsync(string state, int timeoutSeconds = 600, int intervalSeconds = 2, CancellationToken ct = default)
    {
        var form = new Dictionary<string, string> { ["client_id"] = _config.OAuthClientId!, ["state"] = state };
        if (!string.IsNullOrEmpty(_config.OAuthClientSecret)) form["client_secret"] = _config.OAuthClientSecret!;
        var deadline = DateTime.UtcNow.AddSeconds(timeoutSeconds);
        while (true)
        {
            var res = await _transport.PostFormAsync($"{_apiUrl}/oauth2/result", form, Accept(), ct).ConfigureAwait(false);
            if (res.StatusCode == 200)
            {
                var body = ParseObject(res.Body);
                // #481: return on the first delivered terminal shape — a sign-in `code` OR a
                // `2fa_enroll` `enrolled` sentinel ({enrolled: true, state}). Both are one-shot;
                // returning here (rather than looping) keeps an enrollment result from being consumed
                // and lost to a timeout.
                if (body.TryGetProperty("code", out _) || body.TryGetProperty("enrolled", out _)) return body;
            }
            else if (res.StatusCode == 410)
            {
                throw new ApiException(410, "oauth.result_expired", "detached sign-in expired before completion");
            }
            else if (res.StatusCode != 202)
            {
                var (key, msg) = Err(res.Body);
                throw new ApiException(res.StatusCode, key, msg ?? $"result poll rejected (HTTP {res.StatusCode})");
            }
            if (DateTime.UtcNow >= deadline)
                throw new ApiException(0, null, $"detached sign-in not completed within {timeoutSeconds}s");
            await _sleep(intervalSeconds * 1000).ConfigureAwait(false);
        }
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    private static IReadOnlyDictionary<string, string> Accept() =>
        new Dictionary<string, string> { ["Accept"] = "application/json" };

    private JsonElement Parse(HttpResult res, string what)
    {
        if (res.StatusCode >= 200 && res.StatusCode < 300) return ParseObject(res.Body);
        var (key, msg) = Err(res.Body);
        if (res.StatusCode is 401 or 403)
            throw new AuthException($"{what} rejected (HTTP {res.StatusCode})" + (key is null ? "" : $" [{key}]") + (msg is null ? "" : $": {msg}"));
        throw new ApiException(res.StatusCode, key, msg ?? $"{what} rejected (HTTP {res.StatusCode})");
    }

    private static JsonElement ParseObject(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(string.IsNullOrEmpty(body) ? "{}" : body);
            return doc.RootElement.Clone();
        }
        catch (JsonException)
        {
            using var doc = JsonDocument.Parse("{}");
            return doc.RootElement.Clone();
        }
    }

    private static string? Str(JsonElement el, string name) =>
        el.ValueKind == JsonValueKind.Object && el.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String
            ? p.GetString()
            : null;

    private static (string? Key, string? Msg) Err(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(string.IsNullOrEmpty(body) ? "{}" : body);
            var root = doc.RootElement;
            var key = root.TryGetProperty("error_key", out var k) && k.ValueKind == JsonValueKind.String ? k.GetString() : null;
            var msg = root.TryGetProperty("error", out var m) && m.ValueKind == JsonValueKind.String ? m.GetString() : null;
            return (key, msg);
        }
        catch (JsonException)
        {
            return (null, null);
        }
    }
}
