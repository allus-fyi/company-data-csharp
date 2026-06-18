// OAuth token + HTTP layer.
//
// ApiHttp is the thin transport every higher layer goes through. It owns:
//
//  * Auth — client_credentials only. On the first call (or when the cached token is near expiry)
//    it POSTs client_id/client_secret to {api_url}/oauth2/token and caches the bearer token +
//    expiry. Refresh is automatic + transparent; a 401 mid-flight triggers exactly one
//    refresh-and-retry, then surfaces as AuthException.
//  * Format — sets Accept per Config.Format (application/json | application/xml) and parses the
//    body into a Node accordingly (the XML path is XXE-safe — see Xml.cs).
//  * Errors — maps non-2xx to the error taxonomy: 401 → refresh+retry then AuthException; 429 → read
//    Retry-After + bounded backoff then RateLimitException; any other non-2xx → ApiException
//    carrying the body's error_key when present.
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

    private readonly Config _config;
    private readonly IHttpTransport _transport;
    private readonly Func<double, CancellationToken, Task> _sleep;
    private readonly Func<double> _clock;
    private readonly int _maxRetries429;

    private readonly string _apiUrl;
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
            var (errorKey, message) = ExtractError(resp);
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
        return _token!;
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
    public async Task<Node> GetAsync(
        string path,
        IReadOnlyDictionary<string, string>? query = null,
        CancellationToken ct = default)
    {
        var url = BuildUrl(path);
        var wantsXml = _config.Format == "xml";
        var accept = wantsXml ? "application/xml" : "application/json";

        var retries429 = 0;
        var refreshed401 = false;
        while (true)
        {
            var token = await BearerAsync(forceRefresh: false, ct).ConfigureAwait(false);
            HttpResult resp;
            try
            {
                resp = await _transport.GetAsync(
                    url, query,
                    new Dictionary<string, string>
                    {
                        ["Authorization"] = $"Bearer {token}",
                        ["Accept"] = accept,
                    }, ct).ConfigureAwait(false);
            }
            catch (HttpRequestException ex)
            {
                throw new ApiException(0, null, $"request to {path} failed: {ex.Message}");
            }

            var status = resp.StatusCode;

            if (status is >= 200 and < 300)
                return ParseBody(resp, wantsXml);

            if (status == 401)
            {
                if (!refreshed401)
                {
                    refreshed401 = true;
                    await BearerAsync(forceRefresh: true, ct).ConfigureAwait(false);
                    continue;
                }
                var (errorKey, message) = ExtractError(resp);
                throw new AuthException(
                    "unauthorized after token refresh"
                    + (errorKey is not null ? $" [{errorKey}]" : "")
                    + (message is not null ? $": {message}" : ""));
            }

            if (status == 429)
            {
                var retryAfter = ParseRetryAfter(resp);
                if (retries429 < _maxRetries429)
                {
                    retries429++;
                    await _sleep(BackoffDelay(retryAfter, retries429), ct).ConfigureAwait(false);
                    continue;
                }
                var (errorKey, message) = ExtractError(resp);
                throw new RateLimitException(retryAfter, errorKey, message);
            }

            var (ek, msg) = ExtractError(resp);
            throw new ApiException(status, ek, msg);
        }
    }

    private string BuildUrl(string path)
    {
        if (path.StartsWith("http://", StringComparison.Ordinal) || path.StartsWith("https://", StringComparison.Ordinal))
            return path;
        return _apiUrl + (path.StartsWith('/') ? "" : "/") + path;
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

    private static (string? ErrorKey, string? Message) ExtractError(HttpResult resp)
    {
        var text = resp.Body;
        if (string.IsNullOrWhiteSpace(text))
            return (null, null);

        Node body;
        var trimmed = text.TrimStart();
        try
        {
            body = trimmed.StartsWith('<') ? Xml.Parse(text) : Node.FromJsonString(text);
        }
        catch
        {
            return (null, text);
        }

        if (body.Kind != NodeKind.Object)
            return (null, null);

        var errorKey = body.Get("error_key").AsString();
        var message = body.Has("error") ? body.Get("error").AsString()
            : body.Has("message") ? body.Get("message").AsString()
            : null;
        return (errorKey, message);
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
