// Fake IHttpTransport doubles mirroring the Python reference's FakeSession: record calls + replay
// scripted responses. No live API is ever touched.

using Allus.CompanyData;

namespace Allus.CompanyData.Tests;

/// <summary>A canned HTTP response builder.</summary>
public static class Resp
{
    public static HttpResult Ok(string body, IDictionary<string, string>? headers = null) =>
        new() { StatusCode = 200, Body = body, Headers = AsDict(headers) };

    public static HttpResult Json(int status, object jsonBody, IDictionary<string, string>? headers = null) =>
        new() { StatusCode = status, Body = System.Text.Json.JsonSerializer.Serialize(jsonBody), Headers = AsDict(headers) };

    public static HttpResult Text(int status, string text, IDictionary<string, string>? headers = null) =>
        new() { StatusCode = status, Body = text, Headers = AsDict(headers) };

    public static HttpResult TokenOk() =>
        Json(200, new { access_token = "tok-123", token_type = "Bearer", expires_in = 3600 });

    private static IReadOnlyDictionary<string, string> AsDict(IDictionary<string, string>? h)
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (h is not null) foreach (var (k, v) in h) d[k] = v;
        return d;
    }
}

/// <summary>Records POST + GET calls and replays queued responses (FIFO) per method.</summary>
public sealed class QueueTransport : IHttpTransport
{
    public Queue<HttpResult> PostResponses { get; } = new();
    public Queue<HttpResult> GetResponses { get; } = new();
    public List<(string Url, IReadOnlyDictionary<string, string> Form)> Posts { get; } = new();
    public List<(string Url, IReadOnlyDictionary<string, string>? Query, IReadOnlyDictionary<string, string> Headers)> Gets { get; } = new();

    public Task<HttpResult> PostFormAsync(string url, IReadOnlyDictionary<string, string> form,
        IReadOnlyDictionary<string, string> headers, CancellationToken ct)
    {
        Posts.Add((url, form));
        return Task.FromResult(PostResponses.Dequeue());
    }

    public Task<HttpResult> GetAsync(string url, IReadOnlyDictionary<string, string>? query,
        IReadOnlyDictionary<string, string> headers, CancellationToken ct)
    {
        Gets.Add((url, query, headers));
        return Task.FromResult(GetResponses.Dequeue());
    }

    public Queue<HttpResult> WriteResponses { get; } = new();
    public List<(string Method, string Url, byte[]? Body, string? ContentType)> Writes { get; } = new();

    public Task<HttpResult> SendAsync(string method, string url, byte[]? body, string? contentType,
        IReadOnlyDictionary<string, string> headers, CancellationToken ct)
    {
        Writes.Add((method, url, body, contentType));
        return Task.FromResult(WriteResponses.Dequeue());
    }
}

/// <summary>
/// Routes GET by URL through a delegate; the token POST always returns the token; write verbs
/// (POST/PUT/DELETE with a body) record + delegate to an optional write router (mirroring the
/// Python reference's <c>FakeSession.request</c> / <c>write_router</c>).
/// </summary>
public sealed class RouterTransport : IHttpTransport
{
    private readonly Func<string, IReadOnlyDictionary<string, string>?, HttpResult> _router;
    private readonly Func<string, string, byte[]?, HttpResult>? _writeRouter;
    public List<(string Url, IReadOnlyDictionary<string, string>? Query)> Gets { get; } = new();
    public List<string> Posts { get; } = new();
    public List<(string Method, string Url, byte[]? Body, string? ContentType)> Writes { get; } = new();

    public RouterTransport(
        Func<string, IReadOnlyDictionary<string, string>?, HttpResult> router,
        Func<string, string, byte[]?, HttpResult>? writeRouter = null)
    {
        _router = router;
        _writeRouter = writeRouter;
    }

    public Task<HttpResult> PostFormAsync(string url, IReadOnlyDictionary<string, string> form,
        IReadOnlyDictionary<string, string> headers, CancellationToken ct)
    {
        Posts.Add(url);
        return Task.FromResult(Resp.TokenOk());
    }

    public Task<HttpResult> GetAsync(string url, IReadOnlyDictionary<string, string>? query,
        IReadOnlyDictionary<string, string> headers, CancellationToken ct)
    {
        Gets.Add((url, query));
        return Task.FromResult(_router(url, query));
    }

    public Task<HttpResult> SendAsync(string method, string url, byte[]? body, string? contentType,
        IReadOnlyDictionary<string, string> headers, CancellationToken ct)
    {
        Writes.Add((method, url, body, contentType));
        if (_writeRouter is null)
            return Task.FromResult(Resp.Json(200, new { }));
        return Task.FromResult(_writeRouter(method, url, body));
    }
}
