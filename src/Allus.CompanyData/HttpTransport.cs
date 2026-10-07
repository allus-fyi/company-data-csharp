// Low-level HTTP transport seam.
//
// The auth/format/error layer (ApiHttp) goes through an IHttpTransport so it is unit-testable
// without the live API — tests inject a fake transport that records calls + replays scripted
// responses. The default implementation wraps a System.Net.Http.HttpClient.

using System.Diagnostics;
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
    /// <summary>How long one request of the client this transport creates waits for the platform's answer.</summary>
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(45);

    private readonly System.Net.Http.HttpClient _http;

    /// <param name="http">A client passed in keeps its own timeout; the one created here waits 45 seconds.</param>
    public HttpTransport(System.Net.Http.HttpClient? http = null)
    {
        _http = http ?? new System.Net.Http.HttpClient { Timeout = RequestTimeout };
    }

    public async Task<HttpResult> PostFormAsync(
        string url,
        IReadOnlyDictionary<string, string> form,
        IReadOnlyDictionary<string, string> headers,
        CancellationToken ct)
    {
        return await SendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = new FormUrlEncodedContent(form),
            };
            ApplyHeaders(req, headers);
            return req;
        }, ct).ConfigureAwait(false);
    }

    public async Task<HttpResult> GetAsync(
        string url,
        IReadOnlyDictionary<string, string>? query,
        IReadOnlyDictionary<string, string> headers,
        CancellationToken ct)
    {
        var full = query is { Count: > 0 } ? url + "?" + BuildQuery(query) : url;
        return await SendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Get, full);
            ApplyHeaders(req, headers);
            return req;
        }, ct).ConfigureAwait(false);
    }

    public async Task<HttpResult> SendAsync(
        string method,
        string url,
        byte[]? body,
        string? contentType,
        IReadOnlyDictionary<string, string> headers,
        CancellationToken ct)
    {
        return await SendAsync(() =>
        {
            var req = new HttpRequestMessage(new HttpMethod(method), url);
            if (body is not null)
            {
                var content = new ByteArrayContent(body);
                content.Headers.ContentType =
                    new System.Net.Http.Headers.MediaTypeHeaderValue(contentType ?? "application/octet-stream");
                req.Content = content;
            }
            ApplyHeaders(req, headers);
            return req;
        }, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// One exchange, sent once more when it carries a body and its connection was closed before the
    /// response headers arrived; the second outcome, failure included, is the answer. A timeout of the send or of the body read
    /// fails as a dropped connection does there, with <see cref="HttpRequestException"/>; a cancellation
    /// the caller asked for passes unchanged. <paramref name="newRequest"/> is called per attempt, because
    /// a request message is consumed by sending it.
    /// </summary>
    /// <remarks>
    /// A connection closed before the response is the server ending a kept-alive connection on its idle
    /// timeout at the moment a request was written to it: the server never read the request, so sending it
    /// again is the request's first delivery, and the closed connection is never picked again. The handler
    /// reports neither whether the connection had carried an earlier request nor whether part of the status
    /// line or headers had arrived, so a first request on a new connection is sent again too, and so is one
    /// whose response had begun but whose headers were cut off. A request without a body (GET, HEAD, a
    /// bodiless DELETE) is never sent again here: the handler itself retries a failed bodiless request up to
    /// three times, and the SDK adds no send to those. Nothing else is sent again —
    /// not a timeout, a connection that could not be opened, a TLS failure, nor an exchange whose response
    /// headers had arrived: the send completes at the headers, and the body is read afterwards against what
    /// remains of the client's own timeout.
    /// </remarks>
    private async Task<HttpResult> SendAsync(Func<HttpRequestMessage> newRequest, CancellationToken ct)
    {
        for (var attempt = 0; ; attempt++)
        {
            var started = Stopwatch.GetTimestamp();
            using var req = newRequest();
            HttpResponseMessage resp;
            try
            {
                resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            }
            catch (HttpRequestException ex) when (attempt == 0 && req.Content is not null && ClosedBeforeResponse(ex))
            {
                continue;
            }
            catch (OperationCanceledException ex) when (!ct.IsCancellationRequested)
            {
                throw new HttpRequestException("the request timed out", ex);
            }
            using (resp)
            {
                return await ReadAsync(resp, started, ct).ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// Whether a send failed because its connection closed before the response headers arrived: the
    /// response ended before its headers were complete, or the connection was reset or broke under the send.
    /// </summary>
    private static bool ClosedBeforeResponse(HttpRequestException ex) =>
        ex.HttpRequestError == HttpRequestError.ResponseEnded
        || (ex.HttpRequestError == HttpRequestError.Unknown && ex.InnerException is IOException);

    /// <summary>
    /// The response, its body read ONCE within what remains of the client's own timeout — the send
    /// completes at the headers, so the client's timeout no longer covers the body by itself.
    /// </summary>
    private async Task<HttpResult> ReadAsync(HttpResponseMessage resp, long started, CancellationToken ct)
    {
        using var bodyCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        if (_http.Timeout != Timeout.InfiniteTimeSpan)
        {
            var remaining = _http.Timeout - Stopwatch.GetElapsedTime(started);
            bodyCts.CancelAfter(remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero);
        }
        try
        {
            // Read the bytes ONCE — BodyBytes is the byte-safe original (a broadcast document's plaintext
            // file may not be valid UTF-8); Body is the best-effort text decode every JSON/XML/error-message
            // path already assumes.
            var bytes = await resp.Content.ReadAsByteArrayAsync(bodyCts.Token).ConfigureAwait(false);
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
        catch (OperationCanceledException ex) when (!ct.IsCancellationRequested)
        {
            throw new HttpRequestException("the request timed out", ex);
        }
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
