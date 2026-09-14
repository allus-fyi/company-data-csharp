// OAuth token + HTTP layer.
//
// ApiHttp is the thin transport every higher layer goes through. It owns:
//
//  * Auth — client_credentials only. On the first call (or when the cached token is near expiry)
//    it POSTs client_id/client_secret to {api_url}/oauth2/token and caches the bearer token +
//    expiry. Refresh is automatic + transparent; a 401 mid-flight triggers exactly one
//    refresh-and-retry, then surfaces as AuthException.
//  * Region — the configured api_url is the starting point AND the fallback: every response that
//    can name a home base (the token response, a 421 refusal) rebases it, and the token request
//    itself follows the rebase like every other call. See RebaseTo.
//  * Format — sets Accept per Config.Format (application/json | application/xml) and parses the
//    body into a Node accordingly (the XML path is XXE-safe — see Xml.cs).
//  * Errors — maps non-2xx to the error taxonomy: 401 → refresh+retry then AuthException; 421 →
//    rebase+retry once then ApiException; 429 → read Retry-After + bounded backoff then
//    RateLimitException; any other non-2xx → ApiException carrying the body's error_key when
//    present.
//
// Config-only key handling: the client id/secret come from Config — never a method argument.

using System.Text.Json;

namespace Allus.CompanyData;

/// <summary>Authenticated JSON/XML transport for the company-data API.</summary>
public sealed class ApiHttp
{
    // Refresh the token a little before it expires so an in-flight call never races the boundary.
    private const double TokenExpirySkewSeconds = 30.0;

    private const int DefaultMaxRetries429 = 3;
    private const double DefaultBackoffSeconds = 1.0;
    private const double MaxBackoffSeconds = 60.0;

    // The response member (token success body and 421 refusal body alike) naming the home-region base.
    private const string RegionBaseMember = "api_url";
    // The front door's refusal of a data route: rebase to the named base and replay.
    private const string RebaseErrorKey = "region.rebase_required";

    private readonly Config _config;
    private readonly IHttpTransport _transport;
    private readonly Func<double, CancellationToken, Task> _sleep;
    private readonly Func<double> _clock;
    private readonly int _maxRetries429;

    /// <summary>
    /// The base every request goes to, including the token request. Starts at the configured
    /// value; every rebase moves it. Clients do not validate a server-returned base against
    /// anything — they store it and use it.
    /// </summary>
    private string _apiUrl;
    private string? _token;
    private double _tokenExpiry; // monotonic deadline

    public ApiHttp(
        Config config,
        IHttpTransport? transport = null,
        Func<double, CancellationToken, Task>? sleep = null,
        Func<double>? clock = null,
        int maxRetries429 = DefaultMaxRetries429)
    {
        _config = config;
        _transport = transport ?? new HttpTransport();
        _sleep = sleep ?? (async (s, ct) => await Task.Delay(TimeSpan.FromSeconds(s), ct).ConfigureAwait(false));
        _clock = clock ?? (() => Environment.TickCount64 / 1000.0);
        _maxRetries429 = maxRetries429;
        _apiUrl = config.ApiUrl.TrimEnd('/');
    }

    // ── auth ─────────────────────────────────────────────────────────────────────────────────

    private bool TokenValid() => _token is not null && _clock() < _tokenExpiry;

    /// <summary>
    /// POST the client credentials to <c>/oauth2/token</c> and cache the result.
    /// <para>Goes to the CURRENT base, exactly like every other call — once a token response has
    /// named a home base, subsequent token requests go there too, the same as the data calls they
    /// sit beside. The configured value is only the starting point, for the first call of a
    /// process and the fallback when nothing has been stored yet.</para>
    /// </summary>
    private async Task<string> FetchTokenAsync(CancellationToken ct)
    {
        var url = $"{_apiUrl}/oauth2/token";
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = _config.ClientId,
            ["client_secret"] = _config.ClientSecret,
        };

        HttpResult resp;
        try
        {
            resp = await _transport.PostFormAsync(
                url, form, new Dictionary<string, string> { ["Accept"] = "application/json" }, ct)
                .ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw new AuthException($"token request failed: {ex.Message}", ex);
        }

        if (resp.StatusCode < 200 || resp.StatusCode >= 300)
        {
            var (errorKey, message, _) = ExtractError(resp);
            throw new AuthException(
                $"token request rejected (HTTP {resp.StatusCode})"
                + (errorKey is not null ? $" [{errorKey}]" : "")
                + (message is not null ? $": {message}" : ""));
        }

        JsonElement body;
        try
        {
            using var doc = JsonDocument.Parse(resp.Body);
            body = doc.RootElement.Clone();
        }
        catch (JsonException ex)
        {
            throw new AuthException("token response was not valid JSON", ex);
        }

        string? accessToken = null;
        if (body.ValueKind == JsonValueKind.Object && body.TryGetProperty("access_token", out var at)
            && at.ValueKind == JsonValueKind.String)
            accessToken = at.GetString();
        if (string.IsNullOrEmpty(accessToken))
            throw new AuthException("token response missing access_token");

        double expiresIn = 3600.0;
        if (body.ValueKind == JsonValueKind.Object && body.TryGetProperty("expires_in", out var ei))
        {
            if (ei.ValueKind == JsonValueKind.Number) expiresIn = ei.GetDouble();
            else if (ei.ValueKind == JsonValueKind.String && double.TryParse(ei.GetString(), out var p)) expiresIn = p;
        }

        _token = accessToken;
        _tokenExpiry = _clock() + Math.Max(0.0, expiresIn - TokenExpirySkewSeconds);
        // The token is minted at the client's home region and only validates there, so the base
        // the response names is where every company-data call must go from here on.
        string? homeBase = null;
        if (body.ValueKind == JsonValueKind.Object && body.TryGetProperty(RegionBaseMember, out var au)
            && au.ValueKind == JsonValueKind.String)
            homeBase = au.GetString();
        RebaseTo(homeBase);
        return _token!;
    }

    // ── region ─────────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Point subsequent requests — including the next token request — at <paramref name="candidate"/>.
    /// <para>Returns <c>true</c> only when the base actually MOVED. A candidate that is absent, empty,
    /// or equal to the current base is not stored and yields <c>false</c>. Nothing here validates the
    /// candidate against a fetched region list: the SDK stores the base the server names and uses it.</para>
    /// </summary>
    private bool RebaseTo(string? candidate)
    {
        if (candidate is null) return false;
        var b = candidate.Trim().TrimEnd('/');
        if (b.Length == 0 || b == _apiUrl) return false;
        _apiUrl = b;
        return true;
    }

    private async Task<string> BearerAsync(bool forceRefresh, CancellationToken ct)
    {
        if (forceRefresh || !TokenValid())
            return await FetchTokenAsync(ct).ConfigureAwait(false);
        return _token!;
    }

    // ── requests ───────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// GET <paramref name="path"/> (e.g. <c>/api/company-data/connections</c>) → a parsed
    /// <see cref="Node"/>. Adds the bearer token + an Accept header matching <c>Config.Format</c>,
    /// parses JSON or XML, and maps non-2xx to the §9 errors.
    /// </summary>
    public Task<Node> GetAsync(
        string path,
        IReadOnlyDictionary<string, string>? query = null,
        CancellationToken ct = default)
        => RequestAsync("GET", path, query: query, ct: ct);

    /// <summary>
    /// POST <paramref name="path"/> with a JSON body (<paramref name="jsonBody"/>) OR raw bytes
    /// (<paramref name="rawBody"/> + <paramref name="contentType"/>) → a parsed <see cref="Node"/>.
    /// </summary>
    public Task<Node> PostAsync(
        string path,
        object? jsonBody = null,
        byte[]? rawBody = null,
        string? contentType = null,
        CancellationToken ct = default)
        => RequestAsync("POST", path, jsonBody: jsonBody, rawBody: rawBody, contentType: contentType, ct: ct);

    /// <summary>PUT <paramref name="path"/> with a JSON body → a parsed <see cref="Node"/>.</summary>
    public Task<Node> PutAsync(
        string path,
        object? jsonBody = null,
        CancellationToken ct = default)
        => RequestAsync("PUT", path, jsonBody: jsonBody, ct: ct);

    /// <summary>DELETE <paramref name="path"/> → a parsed <see cref="Node"/>.</summary>
    public Task<Node> DeleteAsync(
        string path,
        CancellationToken ct = default)
        => RequestAsync("DELETE", path, ct: ct);

    /// <summary>
    /// GET <paramref name="path"/> returning the RAW 2xx response body BYTES — NO JSON/XML parse.
    /// For downloading file bytes whose body may be non-JSON (a broadcast document's plaintext) —
    /// see <see cref="Client.DocumentFileAsync"/>. Auth/refresh/retry handling is identical to
    /// <see cref="GetAsync"/>.
    /// </summary>
    public async Task<byte[]> GetRawAsync(
        string path,
        IReadOnlyDictionary<string, string>? query = null,
        CancellationToken ct = default)
    {
        var resp = await RequestCoreAsync("GET", path, query: query, ct: ct).ConfigureAwait(false);
        return resp.BodyBytes;
    }

    /// <summary>
    /// GET <paramref name="path"/> returning the whole 2xx <see cref="HttpResult"/> — status, headers
    /// AND raw body, with no parse.
    /// <para>The company-facing binary file endpoints have three 200 shapes (a JSON wrapper for an
    /// encrypted answer, a JSON plaintext envelope, raw file bytes) — the bytes shape told apart by
    /// <c>Content-Type</c> and the two JSON ones by the body's <c>encrypted</c> member — and all
    /// three carry an <c>X-Allus-Content-Sha256</c> digest header. Neither
    /// <see cref="GetAsync"/> (which parses) nor <see cref="GetRawAsync"/> (which drops the headers)
    /// can express that, so this hands the caller the response itself. Auth/refresh/retry and error
    /// mapping are identical.</para>
    /// </summary>
    public Task<HttpResult> GetResponseAsync(
        string path,
        IReadOnlyDictionary<string, string>? query = null,
        CancellationToken ct = default)
        => RequestCoreAsync("GET", path, query: query, ct: ct);

    /// <summary>
    /// Parse a 2xx body the way <see cref="GetAsync"/> would have — for a caller that took the whole
    /// response via <see cref="GetResponseAsync"/> and decided, after looking at the headers, that the
    /// body is structured after all. Keeps the JSON/XML choice in ONE place.
    /// </summary>
    internal Node ParseResponse(HttpResult resp) => ParseBody(resp, _config.Format == "xml");

    /// <summary>
    /// Parse a response body as JSON whatever <c>Format</c> this client speaks, for a route that
    /// answers JSON to every caller rather than honouring the configured format.
    /// </summary>
    internal Node ParseResponseAsJson(HttpResult resp) => ParseBody(resp, false);

    /// <summary>
    /// Parse a response body by what the RESPONSE says it is, for a route whose structured arms are
    /// <c>application/json</c> whatever the client speaks — the binary file routes. A body a client
    /// configured for XML parsed as XML would be unreadable there.
    /// </summary>
    internal Node ParseResponseByContentType(HttpResult resp) =>
        ParseBody(resp, (resp.Header("Content-Type") ?? "").Contains("xml", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// GET/POST/PUT/DELETE → a parsed <see cref="Node"/>. Thin wrapper over
    /// <see cref="RequestCoreAsync"/> that additionally parses the successful body as JSON/XML.
    /// </summary>
    private async Task<Node> RequestAsync(
        string method,
        string path,
        IReadOnlyDictionary<string, string>? query = null,
        object? jsonBody = null,
        byte[]? rawBody = null,
        string? contentType = null,
        CancellationToken ct = default)
    {
        var resp = await RequestCoreAsync(method, path, query, jsonBody, rawBody, contentType, ct).ConfigureAwait(false);
        return ParseBody(resp, _config.Format == "xml");
    }

    /// <summary>
    /// The shared request loop for every verb (GET/raw included). Adds the bearer token + an Accept
    /// header matching <c>Config.Format</c>, carries an optional JSON or raw-bytes body, and maps
    /// non-2xx responses to the SDK errors: 401 → one refresh-and-retry then <see cref="AuthException"/>;
    /// 421 → one rebase-and-retry then <see cref="ApiException"/>; 429 → bounded Retry-After backoff
    /// then <see cref="RateLimitException"/>; other non-2xx → <see cref="ApiException"/> (carrying the
    /// body's <c>error_key</c> when present). Returns the raw successful <see cref="HttpResult"/> —
    /// <see cref="RequestAsync"/> parses it, <see cref="GetRawAsync"/> returns its bytes untouched.
    /// </summary>
    private async Task<HttpResult> RequestCoreAsync(
        string method,
        string path,
        IReadOnlyDictionary<string, string>? query = null,
        object? jsonBody = null,
        byte[]? rawBody = null,
        string? contentType = null,
        CancellationToken ct = default)
    {
        var wantsXml = _config.Format == "xml";
        var accept = wantsXml ? "application/xml" : "application/json";

        // Resolve the request body once: raw bytes win; else a JSON body is serialized.
        byte[]? body = null;
        string? bodyContentType = null;
        if (rawBody is not null)
        {
            body = rawBody;
            bodyContentType = contentType ?? "application/octet-stream";
        }
        else if (jsonBody is not null)
        {
            body = System.Text.Encoding.UTF8.GetBytes(JsonSerializer.Serialize(jsonBody));
            bodyContentType = "application/json";
        }

        var isGet = string.Equals(method, "GET", StringComparison.OrdinalIgnoreCase);

        var retries429 = 0;
        var refreshed401 = false;
        var rebased421 = false;
        while (true)
        {
            // Resolved per attempt, AFTER the bearer call: the first BearerAsync of a process
            // mints the token and rebases from its response, so the base a fresh token was
            // just fetched under is the base this request must go to as well.
            var token = await BearerAsync(forceRefresh: false, ct).ConfigureAwait(false);
            var url = BuildUrl(path);
            var headers = new Dictionary<string, string>
            {
                ["Authorization"] = $"Bearer {token}",
                ["Accept"] = accept,
            };
            HttpResult resp;
            try
            {
                resp = isGet
                    ? await _transport.GetAsync(url, query, headers, ct).ConfigureAwait(false)
                    : await _transport.SendAsync(method, url, body, bodyContentType, headers, ct).ConfigureAwait(false);
            }
            catch (HttpRequestException ex)
            {
                throw new ApiException(0, null, $"request to {path} failed: {ex.Message}");
            }

            var status = resp.StatusCode;

            if (status is >= 200 and < 300)
                return resp;

            if (status == 401)
            {
                if (!refreshed401)
                {
                    refreshed401 = true;
                    await BearerAsync(forceRefresh: true, ct).ConfigureAwait(false);
                    continue;
                }
                var (errorKey, message, _) = ExtractError(resp);
                throw new AuthException(
                    "unauthorized after token refresh"
                    + (errorKey is not null ? $" [{errorKey}]" : "")
                    + (message is not null ? $": {message}" : ""));
            }

            if (status == 421)
            {
                // The front door serves no data route: it names the caller's home base and expects
                // the call there. Rebase once and replay; a second 421 surfaces.
                var (errorKey, message, rebaseDetails) = ExtractError(resp);
                if (!rebased421 && errorKey == RebaseErrorKey)
                {
                    rebaseDetails.TryGetValue(RegionBaseMember, out var candidate);
                    if (RebaseTo(candidate as string))
                    {
                        rebased421 = true;
                        continue;
                    }
                }
                throw new ApiException(status, errorKey, message, rebaseDetails);
            }

            if (status == 429)
            {
                var (errorKey, message, _) = ExtractError(resp);
                // A pending-cap 429 means the caller already holds the maximum concurrent 2FA
                // challenges — a retry can never clear that, so surface it immediately as an
                // ApiException instead of the blind Retry-After backoff every other 429 gets.
                if (errorKey == "twofa.pending_cap")
                    throw new ApiException(status, errorKey, message);
                var retryAfter = ParseRetryAfter(resp);
                if (retries429 < _maxRetries429)
                {
                    retries429++;
                    await _sleep(BackoffDelay(retryAfter, retries429), ct).ConfigureAwait(false);
                    continue;
                }
                throw new RateLimitException(retryAfter, errorKey, message);
            }

            var (ek, msg, details) = ExtractError(resp);
            throw new ApiException(status, ek, msg, details);
        }
    }

    /// <summary>
    /// Resolve <paramref name="path"/> against the CURRENT base. An already-absolute
    /// <paramref name="path"/> (the lazy binary handle's server-supplied <c>value_url</c>) is
    /// reduced to its path+query and rebuilt against the current base too — so a value_url
    /// minted before a rebase, or replayed on a 421 retry after one, still lands at the base
    /// every other request now uses.
    /// </summary>
    private string BuildUrl(string path)
    {
        if (path.StartsWith("http://", StringComparison.Ordinal) || path.StartsWith("https://", StringComparison.Ordinal))
            path = PathAndQuery(path);
        return _apiUrl + (path.StartsWith('/') ? "" : "/") + path;
    }

    /// <summary>
    /// The path + query + fragment portion of an absolute URL, dropping its scheme and host.
    /// </summary>
    private static string PathAndQuery(string absoluteUrl)
    {
        if (!Uri.TryCreate(absoluteUrl, UriKind.Absolute, out var uri))
            return absoluteUrl;
        return uri.PathAndQuery + uri.Fragment;
    }

    private static Node ParseBody(HttpResult resp, bool wantsXml)
    {
        var text = resp.Body;
        if (string.IsNullOrWhiteSpace(text))
            return Node.Object(new Dictionary<string, Node>());
        if (wantsXml)
        {
            try { return Xml.Parse(text); }
            catch (Exception ex) { throw new ApiException(0, null, $"response was not valid XML: {ex.Message}"); }
        }
        try { return Node.FromJsonString(text); }
        catch (JsonException ex)
        {
            throw new ApiException(resp.StatusCode, null, $"response was not valid JSON: {ex.Message}");
        }
    }

    // ── helpers ────────────────────────────────────────────────────────────────────────────────

    private static readonly IReadOnlyDictionary<string, object?> NoDetails =
        new Dictionary<string, object?>();

    /// <summary>
    /// Pull <c>error_key</c> + a message out of a non-2xx body (JSON or XML). Everything BESIDE
    /// the key and the message travels on as <c>Details</c>, so a body that carries actionable data (a
    /// 410 <c>file_expired</c>'s <c>content_sha256</c> + <c>expired_at</c>) is readable without a
    /// bespoke exception type per response.
    /// </summary>
    private static (string? ErrorKey, string? Message, IReadOnlyDictionary<string, object?> Details) ExtractError(HttpResult resp)
    {
        var text = resp.Body;
        if (string.IsNullOrWhiteSpace(text))
            return (null, null, NoDetails);

        Node body;
        var trimmed = text.TrimStart();
        try
        {
            body = trimmed.StartsWith('<') ? Xml.Parse(text) : Node.FromJsonString(text);
        }
        catch
        {
            return (null, text, NoDetails);
        }

        if (body.Kind != NodeKind.Object)
            return (null, null, NoDetails);

        var errorKey = body.Get("error_key").AsString();
        var message = body.Has("error") ? body.Get("error").AsString()
            : body.Has("message") ? body.Get("message").AsString()
            : null;
        var details = body.Without("error_key", "error", "message").ToObjectGraph()
            as IReadOnlyDictionary<string, object?> ?? NoDetails;
        return (errorKey, message, details);
    }

    private static double? ParseRetryAfter(HttpResult resp)
    {
        var raw = resp.Header("Retry-After")?.Trim();
        if (string.IsNullOrEmpty(raw)) return null;
        // The platform sends delta-seconds; an HTTP-date falls back to null (default backoff).
        return double.TryParse(raw, System.Globalization.NumberStyles.Any,
            System.Globalization.CultureInfo.InvariantCulture, out var v) ? v : null;
    }

    private static double BackoffDelay(double? retryAfter, int attempt)
    {
        if (retryAfter is >= 0)
            return Math.Min(retryAfter.Value, MaxBackoffSeconds);
        return Math.Min(DefaultBackoffSeconds * Math.Pow(2, attempt - 1), MaxBackoffSeconds);
    }
}
