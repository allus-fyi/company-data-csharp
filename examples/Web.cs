using System.Text.Json;
using Microsoft.AspNetCore.Http;

namespace Allus.ExampleTestSuite;

/// <summary>
/// Shared HTTP plumbing for every family's handlers — JSON/text writers and request-body / header
/// readers. This is scaffolding, not the SDK example: nothing here touches the SDK. Handlers live in the
/// child namespaces (Identity / CompanyData / Flow) and see these helpers as members of the enclosing
/// namespace, so they read as <c>Web.WriteJson(...)</c> / <c>Web.Str(body, "x")</c>.
/// </summary>
public static class Web
{
    public static async Task WriteJson(HttpContext ctx, object data, int status = 200)
    {
        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = "application/json";
        await ctx.Response.WriteAsync(JsonSerializer.Serialize(data));
    }

    /// <summary>
    /// The contract's FAILURE envelope:
    /// <c>{"error": "&lt;token&gt; — &lt;reason&gt;", "message": "&lt;reason&gt;"}</c>.
    /// <para>
    /// The suite's shared frontend client raises <c>body.error</c> VERBATIM and ignores every other key,
    /// so a bare token in <c>error</c> reaches the developer as one uninformative word and the REASON —
    /// which the backend has right there — is dropped. That is the swallowed failure of standards.html
    /// §9: a failure converted into something indistinguishable from any other failure. The token is kept
    /// and the reason appended in the shape this contract already uses for exactly this
    /// (<c>no_origin — …</c>); <c>message</c> keeps the bare reason for a programmatic reader.
    /// </para>
    /// <para>
    /// NOT used for the token-only refusals the suite handles by STATUS rather than body —
    /// <c>409 not_configured</c> (callers switch on the status directly, without needing the body) and
    /// <c>404 not_found</c>.
    /// </para>
    /// </summary>
    public static Task WriteFailure(HttpContext ctx, string reason, string token = "server_error", int status = 500)
    {
        var text = (reason ?? "").Trim();
        return WriteJson(
            ctx,
            new { error = token + " — " + (text.Length == 0 ? "no reason was reported" : text), message = text },
            status);
    }

    /// <summary>
    /// An exception's reason. <c>Message</c> is never null in .NET but CAN be a generic placeholder or
    /// blank for a hand-thrown exception, in which case the type name is the only thing left to report.
    /// </summary>
    public static string ReasonOf(Exception e) =>
        string.IsNullOrWhiteSpace(e.Message) ? e.GetType().FullName ?? "unknown error" : e.Message.Trim();

    /// <summary>
    /// Serve a JSON document that is already encoded, byte for byte — the stored setup snapshot. The
    /// bytes are passed through as they are because parsing and re-serialising them here, or decoding
    /// them to a string and back, would rewrite content this server is not allowed to interpret.
    /// </summary>
    public static async Task WriteRawJson(HttpContext ctx, byte[] blob, int status = 200)
    {
        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = "application/json";
        await ctx.Response.Body.WriteAsync(blob);
    }

    public static async Task WriteText(HttpContext ctx, string body, int status = 200)
    {
        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = "text/plain; charset=utf-8";
        await ctx.Response.WriteAsync(body);
    }

    public static Task WriteOk(HttpContext ctx)
    {
        ctx.Response.ContentType = "application/json";
        return ctx.Response.WriteAsync("{\"ok\":true}");
    }

    public static Task NotFound(HttpContext ctx) => WriteJson(ctx, new { error = "not_found" }, 404);

    /// <summary>Parse the request body as a JSON object; an empty/invalid body is treated as {}.</summary>
    public static async Task<JsonElement> ReadBody(HttpContext ctx)
    {
        using var reader = new StreamReader(ctx.Request.Body);
        var raw = await reader.ReadToEndAsync();
        if (string.IsNullOrWhiteSpace(raw)) return EmptyObject();
        try
        {
            using var doc = JsonDocument.Parse(raw);
            return doc.RootElement.Clone();
        }
        catch (JsonException) { return EmptyObject(); }
    }

    /// <summary>The raw request body verbatim (the webhook receiver verifies the exact bytes as sent).</summary>
    public static async Task<string> ReadRawBody(HttpContext ctx)
    {
        using var reader = new StreamReader(ctx.Request.Body);
        return await reader.ReadToEndAsync();
    }

    /// <summary>The request body as the exact bytes sent — for content that must not be re-encoded.</summary>
    public static async Task<byte[]> ReadRawBodyBytes(HttpContext ctx)
    {
        using var buffer = new MemoryStream();
        await ctx.Request.Body.CopyToAsync(buffer);
        return buffer.ToArray();
    }

    /// <summary>Request headers as a case-insensitive name → value map (for the SDK webhook verify/parse).</summary>
    public static IReadOnlyDictionary<string, string> RequestHeaders(HttpContext ctx)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (k, v) in ctx.Request.Headers)
            map[k] = v.ToString();
        return map;
    }

    public static string? Header(IReadOnlyDictionary<string, string> headers, string name) =>
        headers.TryGetValue(name, out var v) ? v : null;

    public static JsonElement EmptyObject()
    {
        using var doc = JsonDocument.Parse("{}");
        return doc.RootElement.Clone();
    }

    /// <summary>Read a string property from a JSON object, or null when absent / not a string.</summary>
    public static string? Str(JsonElement obj, string name) =>
        obj.ValueKind == JsonValueKind.Object && obj.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String
            ? p.GetString()
            : null;

    /// <summary>Whether a JSON object carries the named property at all (present-but-empty still counts) —
    /// used to tell an explicit "nothing selected" apart from a property nobody sent.</summary>
    public static bool Has(JsonElement obj, string name) =>
        obj.ValueKind == JsonValueKind.Object && obj.TryGetProperty(name, out _);

    /// <summary>Read a string-array property from a JSON object; absent/non-array/non-string elements are
    /// skipped rather than thrown on, so a malformed entry degrades to "not selected" instead of a 500.</summary>
    public static List<string> StrArray(JsonElement obj, string name)
    {
        var list = new List<string>();
        if (obj.ValueKind == JsonValueKind.Object && obj.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in p.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.String)
                    list.Add(item.GetString() ?? "");
            }
        }
        return list;
    }
}
