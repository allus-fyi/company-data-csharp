// Low-level HTTP transport seam.
//
// The auth/format/error layer (ApiHttp) goes through an IHttpTransport so it is unit-testable
// without the live API — tests inject a fake transport that records calls + replays scripted
// responses. The default implementation wraps a System.Net.Http.HttpClient.

using System.Net.Http.Headers;

namespace Allus.CompanyData;

/// <summary>A raw HTTP response: status, headers, the body text, and the body's raw bytes.</summary>
public sealed class HttpResult
{
    public int StatusCode { get; init; }
    public string Body { get; init; } = string.Empty;
    /// <summary>
    /// The body's undecoded bytes — what <see cref="ApiHttp.GetRawAsync"/> returns as-is (a broadcast
    /// document's plaintext file bytes may not be valid UTF-8, so <see cref="Body"/> alone would lose
    /// data on a decode/re-encode round trip).
    /// </summary>
    public byte[] BodyBytes { get; init; } = Array.Empty<byte>();
    public IReadOnlyDictionary<string, string> Headers { get; init; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    public string? Header(string name) =>
        Headers.TryGetValue(name, out var v) ? v : null;
}

/// <summary>The seam every higher layer goes through — fakeable for tests.</summary>
public interface IHttpTransport
{
    /// <summary>POST a form-urlencoded body (used only for the token endpoint).</summary>
    Task<HttpResult> PostFormAsync(
        string url,
        IReadOnlyDictionary<string, string> form,
        IReadOnlyDictionary<string, string> headers,
        CancellationToken ct);

    /// <summary>GET with optional query params + headers.</summary>
    Task<HttpResult> GetAsync(
        string url,
        IReadOnlyDictionary<string, string>? query,
        IReadOnlyDictionary<string, string> headers,
        CancellationToken ct);

    /// <summary>
    /// Send a body verb (POST/PUT/DELETE) carrying a raw byte body with an explicit Content-Type
    /// (the JSON path serializes the body to bytes + <c>application/json</c> in the layer above).
    /// A null <paramref name="body"/> sends no body (e.g. DELETE).
    /// </summary>
    Task<HttpResult> SendAsync(
        string method,
        string url,
        byte[]? body,
        string? contentType,
        IReadOnlyDictionary<string, string> headers,
        CancellationToken ct);
}

/// <summary>Default <see cref="IHttpTransport"/> over <see cref="System.Net.Http.HttpClient"/>.</summary>
public sealed class HttpTransport : IHttpTransport
{
    private readonly System.Net.Http.HttpClient _http;

    public HttpTransport(System.Net.Http.HttpClient? http = null)
    {
        _http = http ?? new System.Net.Http.HttpClient();
    }

    public async Task<HttpResult> PostFormAsync(
        string url,
        IReadOnlyDictionary<string, string> form,
        IReadOnlyDictionary<string, string> headers,
        CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = new FormUrlEncodedContent(form),
        };
        ApplyHeaders(req, headers);
        return await SendAsync(req, ct).ConfigureAwait(false);
    }

    public async Task<HttpResult> GetAsync(
        string url,
        IReadOnlyDictionary<string, string>? query,
        IReadOnlyDictionary<string, string> headers,
        CancellationToken ct)
    {
        var full = query is { Count: > 0 } ? url + "?" + BuildQuery(query) : url;
        using var req = new HttpRequestMessage(HttpMethod.Get, full);
        ApplyHeaders(req, headers);
        return await SendAsync(req, ct).ConfigureAwait(false);
    }

    public async Task<HttpResult> SendAsync(
        string method,
        string url,
        byte[]? body,
        string? contentType,
        IReadOnlyDictionary<string, string> headers,
        CancellationToken ct)
    {
        using var req = new HttpRequestMessage(new HttpMethod(method), url);
        if (body is not null)
        {
            var content = new ByteArrayContent(body);
            content.Headers.ContentType =
                new System.Net.Http.Headers.MediaTypeHeaderValue(contentType ?? "application/octet-stream");
            req.Content = content;
        }
        ApplyHeaders(req, headers);
        return await SendAsync(req, ct).ConfigureAwait(false);
    }

    private async Task<HttpResult> SendAsync(HttpRequestMessage req, CancellationToken ct)
    {
        using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
        // Read the bytes ONCE — BodyBytes is the byte-safe original (a broadcast document's plaintext
        // file may not be valid UTF-8); Body is the best-effort text decode every JSON/XML/error-message
        // path already assumes.
        var bytes = await resp.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        var body = bytes.Length == 0 ? string.Empty : System.Text.Encoding.UTF8.GetString(bytes);
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var h in resp.Headers) headers[h.Key] = string.Join(",", h.Value);
        foreach (var h in resp.Content.Headers) headers[h.Key] = string.Join(",", h.Value);
        return new HttpResult
        {
            StatusCode = (int)resp.StatusCode,
            Body = body,
            BodyBytes = bytes,
            Headers = headers,
        };
    }

    private static void ApplyHeaders(HttpRequestMessage req, IReadOnlyDictionary<string, string> headers)
    {
        foreach (var (k, v) in headers)
        {
            if (k.Equals("Accept", StringComparison.OrdinalIgnoreCase))
                req.Headers.Accept.ParseAdd(v);
            else if (k.Equals("Authorization", StringComparison.OrdinalIgnoreCase))
                req.Headers.Authorization = AuthenticationHeaderValue.Parse(v);
            else
                req.Headers.TryAddWithoutValidation(k, v);
        }
    }

    private static string BuildQuery(IReadOnlyDictionary<string, string> query) =>
        string.Join("&", query.Select(kv =>
            $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));
}
