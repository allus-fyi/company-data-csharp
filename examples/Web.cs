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
}
