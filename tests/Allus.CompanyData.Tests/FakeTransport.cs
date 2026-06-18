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
}

/// <summary>Routes GET by URL through a delegate; POST always returns the token.</summary>
public sealed class RouterTransport : IHttpTransport
{
    private readonly Func<string, IReadOnlyDictionary<string, string>?, HttpResult> _router;
    public List<(string Url, IReadOnlyDictionary<string, string>? Query)> Gets { get; } = new();
    public List<string> Posts { get; } = new();

    public RouterTransport(Func<string, IReadOnlyDictionary<string, string>?, HttpResult> router)
        => _router = router;

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
}
