using System.Formats.Tar;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using Allus.FlowExample;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.FileProviders;

// One-command launcher for the flow example (contract v2, flow family — see README).
//
//   dotnet run
//
// Steps:
//   1. wipe .runtime/ (fresh state each boot)
//   2. on a missing/changed bundle: fetch the pinned frontend release (frontend.lock), VERIFY sha256,
//      unpack to .frontend/<tag>/  (a present, verified bundle is a cache hit — nothing is re-fetched)
//   3. assert the bundle's contract.json version == the backend's implemented contractVersion
//   4. refuse a busy port with a clear message
//   5. serve http://localhost:${PORT:-8091} — one Kestrel host; a serializing gate keeps it single-worker
//      (contract: no cross-request concurrency to guard).

const int ContractVersion = Server.ContractVersion; // 2
const string ReleaseBase = "https://github.com/allme-sdk/example-test-suite/releases/download";
const string ScenarioId = "flow:run";

var baseDir = FindBaseDir();
Console.Error.WriteLine("flow example (csharp) — starting up");

// 1. fresh runtime state
var rt = new Runtime(baseDir);
rt.WipeAll();

// 2. frontend bundle (pinned release, checksum-verified, TAG-specific cache)
var lockPath = Path.Combine(baseDir, "frontend.lock");
if (!File.Exists(lockPath))
    Fail("frontend.lock missing (need {\"tag\",\"sha256\"}).");
JsonElement lockDoc;
using (var doc = JsonDocument.Parse(File.ReadAllText(lockPath))) lockDoc = doc.RootElement.Clone();
var tag = lockDoc.TryGetProperty("tag", out var tp) ? tp.GetString() ?? "" : "";
var wantSha = (lockDoc.TryGetProperty("sha256", out var sp) ? sp.GetString() ?? "" : "").ToLowerInvariant();
if (tag.Length == 0 || wantSha.Length == 0)
    Fail("frontend.lock malformed (need non-empty \"tag\" and \"sha256\").");

var frontendDir = Path.Combine(baseDir, ".frontend", tag); // per-tag cache dir — a pin bump serves a NEW dir
var markSha = File.Exists(Path.Combine(frontendDir, ".sha"))
    ? File.ReadAllText(Path.Combine(frontendDir, ".sha")).Trim().ToLowerInvariant()
    : "";
var cacheValid = File.Exists(Path.Combine(frontendDir, "index.html"))
    && File.Exists(Path.Combine(frontendDir, "contract.json"))
    && markSha.Length > 0 && markSha == wantSha;
if (cacheValid)
    Console.Error.WriteLine($"frontend {tag} present + checksum-verified (cache hit) — skipping fetch");
else
    await FetchBundle(frontendDir, tag, wantSha);

// 3. contract guard
int? bundleVersion = null;
try
{
    using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(frontendDir, "contract.json")));
    if (doc.RootElement.TryGetProperty("contractVersion", out var cv) && cv.ValueKind == JsonValueKind.Number)
        bundleVersion = cv.GetInt32();
}
catch (Exception e) { Fail($"could not read the bundle's contract.json: {e.Message}"); }
if (bundleVersion != ContractVersion)
    Fail($"contract mismatch: bundle contractVersion={bundleVersion?.ToString() ?? "null"}, backend implements {ContractVersion}.\n"
       + "Bump the frontend.lock pin to a release whose contract.json matches, or update the backend.");

// 4. port
var port = int.TryParse(Environment.GetEnvironmentVariable("PORT"), out var p) ? p : 8091;
try { var l = new TcpListener(IPAddress.Loopback, port); l.Start(); l.Stop(); }
catch (SocketException)
{
    Fail($"port {port} is busy. Set PORT=<n> to use another port "
       + "(one browser origin is shared across SDK examples, so only one runs at a time).");
}

// 5. serve
var sdkVersion = SdkVersion();
var server = new Server(rt, sdkVersion);

var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders(); // keep stdout to our own messages
builder.WebHost.UseUrls($"http://localhost:{port}");
var app = builder.Build();

// Single-worker semantics (contract): serialize every request through one gate, and lazily sweep the
// run TTL on each — so the file store stays lock-free exactly as the contract describes.
var gate = new SemaphoreSlim(1, 1);
app.Use(async (ctx, next) =>
{
    await gate.WaitAsync(ctx.RequestAborted);
    try { rt.Sweep(); await next(); }
    finally { gate.Release(); }
});

var files = new PhysicalFileProvider(frontendDir);
app.UseDefaultFiles(new DefaultFilesOptions { FileProvider = files });
app.UseStaticFiles(new StaticFileOptions { FileProvider = files });

app.MapGet("/api/meta", (HttpContext ctx) => server.Meta(ctx));
app.MapPost("/api/scenarios/{id}/config", (HttpContext ctx, string id) => server.SaveConfig(ctx, id));
app.MapPost("/api/scenarios/{id}/start", (HttpContext ctx, string id) => server.Start(ctx, id));
app.MapPost("/api/scenarios/{id}/clear", async (HttpContext ctx, string id) =>
{
    if (id != ScenarioId)
    {
        ctx.Response.StatusCode = 404;
        ctx.Response.ContentType = "application/json";
        await ctx.Response.WriteAsync("{\"error\":\"not_found\"}");
        return;
    }
    rt.ClearScenario(1); // the single store key
    await WriteOk(ctx);
});
app.MapGet("/api/runs/{runId}", (HttpContext ctx, string runId) => server.RunStatus(ctx, runId));
app.MapPost("/api/clear", async (HttpContext ctx) => { rt.ClearAll(); await WriteOk(ctx); });

// SPA fallback: unknown /api/* → 404 JSON; anything else → index.html (client-side routing).
app.MapFallback(async (HttpContext ctx) =>
{
    if (ctx.Request.Path.StartsWithSegments("/api"))
    {
        ctx.Response.StatusCode = 404;
        ctx.Response.ContentType = "application/json";
        await ctx.Response.WriteAsync("{\"error\":\"not_found\"}");
        return;
    }
    var index = Path.Combine(frontendDir, "index.html");
    if (File.Exists(index))
    {
        ctx.Response.ContentType = "text/html; charset=utf-8";
        await ctx.Response.SendFileAsync(index);
        return;
    }
    ctx.Response.StatusCode = 404;
    await ctx.Response.WriteAsync("bundle not found");
});

Console.Error.WriteLine($"serving http://localhost:{port}  (Ctrl-C to stop)");
app.Run();

// ── helpers ──────────────────────────────────────────────────────────────────

static Task WriteOk(HttpContext ctx)
{
    ctx.Response.ContentType = "application/json";
    return ctx.Response.WriteAsync("{\"ok\":true}");
}

static string FindBaseDir()
{
    var dir = new DirectoryInfo(AppContext.BaseDirectory);
    while (dir is not null)
    {
        if (File.Exists(Path.Combine(dir.FullName, "frontend.lock"))) return dir.FullName;
        dir = dir.Parent;
    }
    return Directory.GetCurrentDirectory();
}

static async Task FetchBundle(string frontendDir, string tag, string wantSha)
{
    var url = $"{ReleaseBase}/{Uri.EscapeDataString(tag)}/dist.tar.gz";
    Console.Error.WriteLine($"fetching frontend {tag} → {url}");
    byte[] bytes;
    try
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
        bytes = await http.GetByteArrayAsync(url);
    }
    catch (Exception e)
    {
        Fail($"could not download the pinned frontend release ({url}): {e.Message}\n"
           + "If the release does not exist yet, seed it manually: build the frontend, then unpack\n"
           + $"dist.tar.gz into {frontendDir} and write its sha256 to {Path.Combine(frontendDir, ".sha")}.");
        return; // unreachable (Fail exits)
    }

    var gotSha = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    if (gotSha != wantSha)
        Fail($"frontend checksum MISMATCH.\n  expected {wantSha}\n  got      {gotSha}\n"
           + "Refusing to serve an unverified bundle. Fix frontend.lock or re-download.");

    if (Directory.Exists(frontendDir)) Directory.Delete(frontendDir, recursive: true);
    Directory.CreateDirectory(frontendDir);
    using (var ms = new MemoryStream(bytes))
    using (var gz = new GZipStream(ms, CompressionMode.Decompress))
        TarFile.ExtractToDirectory(gz, frontendDir, overwriteFiles: true);
    if (!File.Exists(Path.Combine(frontendDir, "index.html")))
        Fail("failed to unpack the frontend bundle (no index.html).");
    File.WriteAllText(Path.Combine(frontendDir, ".sha"), wantSha);
    Console.Error.WriteLine($"frontend {tag} verified + unpacked → {frontendDir}");
}

static string SdkVersion()
{
    var asm = typeof(Allus.CompanyData.Config).Assembly;
    var info = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
               ?? asm.GetName().Version?.ToString() ?? "unknown";
    var plus = info.IndexOf('+');
    return plus >= 0 ? info[..plus] : info;
}

static void Fail(string msg)
{
    Console.Error.WriteLine($"\nERROR: {msg}");
    Environment.Exit(1);
}
