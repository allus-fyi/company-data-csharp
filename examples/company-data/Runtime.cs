using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Allus.CompanyDataExample;

/// <summary>
/// One run's cross-request state. Serialized to <c>.runtime/runs/{runId}.json</c>. The four data
/// scenarios store a terminal <see cref="Result"/>; the accumulating webhook run keeps growing
/// <see cref="Events"/> / <see cref="Unparseable"/> under <c>status:"pending"</c>.
/// </summary>
public sealed class Run
{
    public string RunId { get; set; } = "";
    public string Scenario { get; set; } = "";
    public string Status { get; set; } = "pending"; // pending | done | failed
    public List<string> Calls { get; set; } = new();

    // Data scenarios (read / definitions / changes / documents): the pinned terminal shape.
    public object? Result { get; set; }
    public string? Error { get; set; }

    // Webhook scenario — the accumulating run.
    public string? WebhookId { get; set; }
    public List<object?>? Events { get; set; }   // {source,…,id,raw} projected Change events
    public List<string>? SeenFeedIds { get; set; } // feed-only dedup set for the drainBatch() fallback
    public int Unparseable { get; set; }
}

/// <summary>
/// Cross-request state for the company-data demo backend (contract §"Backend state" / company-data
/// family). Single-worker server → requests serialize; there is NO concurrency to guard, so NO locks,
/// NO tombstones, NO burn-on-read. Everything lives under <see cref="RuntimeDir"/> (git-ignored, wiped
/// at startup):
/// <list type="bullet">
///   <item>config/{sid}.json — the canonical SDK config file a scenario runs OFF (NOT TTL-swept)</item>
///   <item>config/{sid}.meta.json — demo-only run parameters (webhook id, documents share_code)</item>
///   <item>config/keys/&lt;sha1&gt;.pem — the service private-key file(s) a config references by path (0600)</item>
///   <item>runs/{runId}.json — one run's accumulated result + calls (30-min TTL, lazy sweep)</item>
///   <item>webhook-route.json — the SINGLE active webhook run {webhookId, runId}</item>
///   <item>cache/ — the SDK pump's buffer + dead-letter dir (Config.cache_dir), wiped by Clear</item>
/// </list>
/// </summary>
public sealed class Runtime
{
    /// <summary>30-minute run TTL. Config files are exempt (they are configuration, not runs).</summary>
    public static readonly TimeSpan Ttl = TimeSpan.FromMinutes(30);

    public string RuntimeDir { get; }
    public string RunsDir { get; }
    public string ConfigDir { get; }
    public string ConfigKeysDir { get; }
    public string CacheDir { get; }
    public string RoutePath { get; }

    private static readonly JsonSerializerOptions RunJson = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private static readonly JsonSerializerOptions PlainJson = new() { WriteIndented = true };

    public Runtime(string baseDir)
    {
        RuntimeDir = Path.Combine(baseDir, ".runtime");
        RunsDir = Path.Combine(RuntimeDir, "runs");
        ConfigDir = Path.Combine(RuntimeDir, "config");
        ConfigKeysDir = Path.Combine(ConfigDir, "keys");
        // The SDK pump persists its buffer + dead-letters here (Config.cache_dir → this path), so Clear /
        // the startup wipe removes it and the "writes only under .runtime/" property holds.
        CacheDir = Path.Combine(RuntimeDir, "cache");
        RoutePath = Path.Combine(RuntimeDir, "webhook-route.json");
    }

    public void EnsureDirs()
    {
        foreach (var d in new[] { RuntimeDir, RunsDir, ConfigDir, ConfigKeysDir, CacheDir })
            Directory.CreateDirectory(d);
    }

    /// <summary>Startup wipe: remove ALL runtime state, then recreate the empty tree.</summary>
    public void WipeAll()
    {
        if (Directory.Exists(RuntimeDir))
            Directory.Delete(RuntimeDir, recursive: true);
        EnsureDirs();
    }

    // ── lazy TTL sweep (contract: on every request) ────────────────────────────

    /// <summary>
    /// Remove expired run files and orphaned *.tmp files. When the active webhook run expires, its
    /// routing record is dropped too (a stale record never routes to a burned run).
    /// </summary>
    public void Sweep()
    {
        if (Directory.Exists(RunsDir))
        {
            var now = DateTime.UtcNow;
            foreach (var path in Directory.EnumerateFiles(RunsDir))
            {
                if (path.EndsWith(".tmp", StringComparison.Ordinal))
                {
                    TryDelete(path); // orphaned temp from an interrupted write
                    continue;
                }
                if (path.EndsWith(".json", StringComparison.Ordinal) &&
                    now - File.GetLastWriteTimeUtc(path) > Ttl)
                    TryDelete(path);
            }
        }
        // Drop the routing record if its run is gone (expired/swept above).
        var route = ReadRoute();
        if (route is { } r && !File.Exists(Path.Combine(RunsDir, $"{r.RunId}.json")))
            TryDelete(RoutePath);
    }

    // ── config files ───────────────────────────────────────────────────────────

    /// <summary>Filesystem-safe token for a scenario id (e.g. "companydata:read" → "companydata_read").</summary>
    public static string Sid(string scenarioId)
    {
        var sb = new StringBuilder(scenarioId.Length);
        foreach (var ch in scenarioId)
            sb.Append(char.IsAsciiLetterOrDigit(ch) ? ch : '_');
        return sb.ToString().Trim('_');
    }

    public string ConfigPathFor(string id) => Path.Combine(ConfigDir, $"{Sid(id)}.json");
    public string MetaPathFor(string id) => Path.Combine(ConfigDir, $"{Sid(id)}.meta.json");
    public bool HasConfig(string id) => File.Exists(ConfigPathFor(id));

    /// <summary>Write a scenario's canonical SDK config file. Returns the RELATIVE path (for display).</summary>
    public string WriteConfig(string id, IDictionary<string, object?> config)
    {
        EnsureDirs();
        AtomicWrite(ConfigPathFor(id), JsonSerializer.Serialize(config, PlainJson));
        return $".runtime/config/{Sid(id)}.json";
    }

    public void WriteConfigMeta(string id, IDictionary<string, object?> meta)
    {
        EnsureDirs();
        AtomicWrite(MetaPathFor(id), JsonSerializer.Serialize(meta, PlainJson));
    }

    public JsonElement ReadConfigMeta(string id)
    {
        if (!File.Exists(MetaPathFor(id))) return EmptyObject();
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(MetaPathFor(id)));
            return doc.RootElement.Clone();
        }
        catch (JsonException) { return EmptyObject(); }
    }

    /// <summary>
    /// Materialize a browser-sent PEM to config/keys/&lt;sha1&gt;.pem (0600) and return its ABSOLUTE path —
    /// the value recorded in the config file (the SDK reads keys by path). Content-addressed: identical
    /// PEM reuses the same file.
    /// </summary>
    public string MaterializeConfigKey(string pem)
    {
        EnsureDirs();
        var sha1 = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(pem))).ToLowerInvariant();
        var path = Path.Combine(ConfigKeysDir, $"{sha1}.pem");
        if (!File.Exists(path))
            AtomicWrite(path, pem);
        SetOwnerOnly(path);
        return path;
    }

    // ── runs ─────────────────────────────────────────────────────────────────────

    public string NewRunId() => Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

    public void WriteRun(string runId, Run run)
    {
        run.RunId = runId;
        AtomicWrite(Path.Combine(RunsDir, $"{runId}.json"), JsonSerializer.Serialize(run, RunJson));
    }

    /// <summary>Read a run, honouring the TTL. Null for unknown/expired ids (idempotent reads).</summary>
    public Run? ReadRun(string runId)
    {
        if (!IsRunId(runId)) return null;
        var path = Path.Combine(RunsDir, $"{runId}.json");
        if (!File.Exists(path)) return null;
        if (DateTime.UtcNow - File.GetLastWriteTimeUtc(path) > Ttl)
        {
            TryDelete(path);
            return null;
        }
        try { return JsonSerializer.Deserialize<Run>(File.ReadAllText(path), RunJson); }
        catch (JsonException) { return null; }
    }

    // ── webhook routing record (single active webhook run) ────────────────────────

    /// <summary>
    /// Persist the single active webhook route {webhookId, runId}, superseding any prior one. A new
    /// companydata:webhook run calls this on /start; the old run stops receiving (its file stays
    /// readable until TTL/Clear).
    /// </summary>
    public void WriteRoute(string webhookId, string runId)
    {
        EnsureDirs();
        AtomicWrite(RoutePath, JsonSerializer.Serialize(new { webhookId, runId }, PlainJson));
    }

    /// <summary>The active webhook route, or null when none is set.</summary>
    public (string WebhookId, string RunId)? ReadRoute()
    {
        if (!File.Exists(RoutePath)) return null;
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(RoutePath));
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return null;
            var wid = root.TryGetProperty("webhookId", out var w) ? w.GetString() : null;
            var rid = root.TryGetProperty("runId", out var r) ? r.GetString() : null;
            if (string.IsNullOrEmpty(wid) || string.IsNullOrEmpty(rid)) return null;
            return (wid!, rid!);
        }
        catch (JsonException) { return null; }
    }

    public void ClearRoute() => TryDelete(RoutePath);

    // ── clear ─────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Per-scenario clear: delete that scenario's runs + config + meta, drop the route when clearing the
    /// webhook scenario, wipe the shared pump cache, then GC any unreferenced key PEM.
    /// </summary>
    public void ClearScenario(string id)
    {
        foreach (var path in Directory.EnumerateFiles(RunsDir, "*.json"))
        {
            try
            {
                var run = JsonSerializer.Deserialize<Run>(File.ReadAllText(path), RunJson);
                if (run is not null && run.Scenario == id) TryDelete(path);
            }
            catch (JsonException) { /* ignore malformed */ }
        }
        TryDelete(ConfigPathFor(id));
        TryDelete(MetaPathFor(id));
        if (id == "companydata:webhook") ClearRoute();
        RmTree(CacheDir);
        GcConfigKeys();
        EnsureDirs();
    }

    /// <summary>Global clear: wipe all runs, the config tree (configs, metas, keys), the route + cache.</summary>
    public void ClearAll()
    {
        if (Directory.Exists(RunsDir))
            foreach (var path in Directory.EnumerateFiles(RunsDir)) TryDelete(path);
        RmTree(ConfigDir);
        RmTree(CacheDir);
        ClearRoute();
        EnsureDirs();
    }

    /// <summary>Delete any key PEM no surviving config/{sid}.json still references (content-addressed sharing).</summary>
    private void GcConfigKeys()
    {
        var referenced = new HashSet<string>(StringComparer.Ordinal);
        if (Directory.Exists(ConfigDir))
            foreach (var cfgPath in Directory.EnumerateFiles(ConfigDir, "*.json"))
            {
                if (cfgPath.EndsWith(".meta.json", StringComparison.Ordinal)) continue;
                try
                {
                    using var doc = JsonDocument.Parse(File.ReadAllText(cfgPath));
                    if (doc.RootElement.TryGetProperty("service_private_key", out var p) &&
                        p.ValueKind == JsonValueKind.String && !string.IsNullOrEmpty(p.GetString()))
                        referenced.Add(p.GetString()!);
                }
                catch (JsonException) { /* ignore malformed */ }
            }
        if (!Directory.Exists(ConfigKeysDir)) return;
        foreach (var keyPath in Directory.EnumerateFiles(ConfigKeysDir, "*.pem"))
            if (!referenced.Contains(keyPath)) TryDelete(keyPath);
    }

    // ── helpers ─────────────────────────────────────────────────────────────────

    public static bool IsRunId(string s) =>
        s.Length == 32 && s.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static JsonElement EmptyObject()
    {
        using var doc = JsonDocument.Parse("{}");
        return doc.RootElement.Clone();
    }

    /// <summary>Write-temp + atomic rename on the same filesystem (crash hygiene: no partial reads).</summary>
    private static void AtomicWrite(string finalPath, string contents)
    {
        var tmp = $"{finalPath}.{Convert.ToHexString(RandomNumberGenerator.GetBytes(4))}.tmp";
        File.WriteAllText(tmp, contents);
        File.Move(tmp, finalPath, overwrite: true);
    }

    private static void SetOwnerOnly(string path)
    {
        if (OperatingSystem.IsWindows()) return;
        try { File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite); }
        catch (Exception) { /* best-effort on the developer's own machine */ }
    }

    private static void RmTree(string dir)
    {
        try { if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true); }
        catch (IOException) { /* best-effort */ }
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch (IOException) { /* best-effort */ }
    }
}
