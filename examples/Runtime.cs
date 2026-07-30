using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Allus.ExampleTestSuite;

/// <summary>A run persisted to the shared store. Every family's run carries a RunId.</summary>
public interface IRun
{
    string RunId { get; set; }
}

/// <summary>
/// The shared cross-request state store for the whole example test suite (contract §"Backend state").
/// ONE server, ONE <c>.runtime/</c> tree — every family's configs + runs live here, keyed per scenario
/// id. The single-worker server serializes requests, so there is NO concurrency to guard: NO locks, NO
/// tombstones, NO burn-on-read. The tree is git-ignored and wiped at startup:
/// <list type="bullet">
///   <item>config/{sid}.json — a scenario's canonical SDK config file it runs OFF (NOT TTL-swept)</item>
///   <item>config/{sid}.meta.json — demo-only run parameters (authorize_base, claims, webhook id, …)</item>
///   <item>config/keys/&lt;sha1&gt;.pem — private-key file(s) a config references by path (0600)</item>
///   <item>runs/{runId}.json — one run's cross-request state (30-min TTL, lazy sweep)</item>
///   <item>webhook-route.json — the SINGLE active company-data webhook run {webhookId, runId}</item>
///   <item>state.json — the setup snapshot POSTed to /api/state, held verbatim as OPAQUE cold storage:
///   never parsed here, never used to run anything</item>
///   <item>cache/ — the SDK pump's buffer + dead-letter dir (Config.cache_dir), wiped by Clear</item>
/// </list>
/// Runs are stored + read per family via the generic <see cref="WriteRun{T}"/> / <see cref="ReadRun{T}"/>;
/// each run file records its scenario id so sweep/clear/dispatch stay family-agnostic here.
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
    public string StatePath { get; }

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
        // The SDK pump (company-data changes/webhook) persists its buffer + dead-letters here
        // (Config.cache_dir → this path), so Clear / the startup wipe removes it and the
        // "writes only under .runtime/" property holds.
        CacheDir = Path.Combine(RuntimeDir, "cache");
        RoutePath = Path.Combine(RuntimeDir, "webhook-route.json");
        StatePath = Path.Combine(RuntimeDir, "state.json");
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
    /// Remove expired run files and orphaned *.tmp files. When the active webhook run's file is gone, the
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
        var route = ReadRoute();
        if (route is { } r && !File.Exists(Path.Combine(RunsDir, $"{r.RunId}.json")))
            TryDelete(RoutePath);
    }

    // ── config files ───────────────────────────────────────────────────────────

    /// <summary>Filesystem-safe token for a scenario id ("companydata:read" → "companydata_read",
    /// "flow:run" → "flow_run", "1" → "1").</summary>
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
    /// PEM reuses the same file, so two scenarios sharing a service key share the file.
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

    // ── runs (generic — each family stores/reads its own run POCO) ─────────────────

    public string NewRunId() => Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

    public void WriteRun<T>(string runId, T run) where T : IRun
    {
        run.RunId = runId;
        AtomicWrite(Path.Combine(RunsDir, $"{runId}.json"), JsonSerializer.Serialize(run, run!.GetType(), RunJson));
    }

    /// <summary>Read a run as the family's POCO, honouring the TTL. Null for unknown/expired ids.</summary>
    public T? ReadRun<T>(string runId) where T : class
    {
        var path = RunPath(runId);
        if (path is null) return null;
        try { return JsonSerializer.Deserialize<T>(File.ReadAllText(path), RunJson); }
        catch (JsonException) { return null; }
    }

    /// <summary>
    /// The scenario id recorded in a run file (as a string: identity's numeric ids stringify), so the
    /// dispatcher can route GET /api/runs/{id} to the owning family without knowing the run's shape. Null
    /// for an unknown/expired run.
    /// </summary>
    public string? ReadRunScenarioId(string runId)
    {
        var path = RunPath(runId);
        if (path is null) return null;
        try
        {
            var probe = JsonSerializer.Deserialize<ScenarioProbe>(File.ReadAllText(path), RunJson);
            return ScenarioString(probe?.Scenario);
        }
        catch (JsonException) { return null; }
    }

    /// <summary>The run file path if it exists and is within TTL (expired files are swept here), else null.</summary>
    private string? RunPath(string runId)
    {
        if (!IsRunId(runId)) return null;
        var path = Path.Combine(RunsDir, $"{runId}.json");
        if (!File.Exists(path)) return null;
        if (DateTime.UtcNow - File.GetLastWriteTimeUtc(path) > Ttl)
        {
            TryDelete(path);
            return null;
        }
        return path;
    }

    private sealed class ScenarioProbe
    {
        public JsonElement Scenario { get; set; }
    }

    private static string? ScenarioString(JsonElement? e) => e?.ValueKind switch
    {
        JsonValueKind.String => e.Value.GetString(),
        JsonValueKind.Number => e.Value.GetRawText(),
        _ => null,
    };

    // ── webhook routing record (single active company-data webhook run) ────────────

    public void WriteRoute(string webhookId, string runId)
    {
        EnsureDirs();
        AtomicWrite(RoutePath, JsonSerializer.Serialize(new { webhookId, runId }, PlainJson));
    }

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

    // ── the setup snapshot (POST/GET /api/state) ──────────────────────────────────

    /// <summary>
    /// Store the setup snapshot the request carried, VERBATIM. The bytes are OPAQUE here — never parsed,
    /// never inspected, never used to run anything — so nothing in this class constrains what they may
    /// contain, and an empty body is a snapshot like any other. They stay <c>byte[]</c> end to end:
    /// decoding to a string and back would re-encode content this store is not allowed to interpret.
    /// Carries no TTL (it is setup, not a run); removed by a global clear or the startup wipe.
    /// </summary>
    public void WriteState(byte[] blob)
    {
        EnsureDirs();
        AtomicWrite(StatePath, blob);
    }

    /// <summary>
    /// The stored snapshot's bytes, or null when NO snapshot file exists — the file's presence is the
    /// whole of the answer, since judging the content would be the inspection this store does not do. A
    /// file that exists but cannot be read throws, because that is a fault rather than an absence.
    /// </summary>
    public byte[]? ReadState() => File.Exists(StatePath) ? File.ReadAllBytes(StatePath) : null;

    public void ClearState() => TryDelete(StatePath);

    // ── clear ─────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Per-scenario clear: delete that scenario's runs (matched by the recorded scenario id) + config +
    /// meta, then GC unreferenced key PEMs. Company-data extras: clearing the webhook scenario drops the
    /// route, and clearing any company-data scenario wipes the shared pump cache.
    /// </summary>
    public void ClearScenario(string scenarioId)
    {
        foreach (var path in Directory.EnumerateFiles(RunsDir, "*.json"))
        {
            try
            {
                var probe = JsonSerializer.Deserialize<ScenarioProbe>(File.ReadAllText(path), RunJson);
                if (ScenarioString(probe?.Scenario) == scenarioId) TryDelete(path);
            }
            catch (JsonException) { /* ignore malformed */ }
        }
        TryDelete(ConfigPathFor(scenarioId));
        TryDelete(MetaPathFor(scenarioId));
        if (scenarioId == "companydata:webhook") ClearRoute();
        if (scenarioId.StartsWith("companydata:", StringComparison.Ordinal)) RmTree(CacheDir);
        GcConfigKeys();
        EnsureDirs();
    }

    /// <summary>
    /// Global clear: wipe all runs, the config tree (configs, metas, keys), the route + cache, and the
    /// saved setup snapshot. The snapshot goes too because it can hold the same credentials the config
    /// tree does — a clear that left it behind would leave those sitting on disk.
    /// </summary>
    public void ClearAll()
    {
        if (Directory.Exists(RunsDir))
            foreach (var path in Directory.EnumerateFiles(RunsDir)) TryDelete(path);
        RmTree(ConfigDir);
        RmTree(CacheDir);
        ClearRoute();
        ClearState();
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
                    foreach (var field in new[] { "oauth_private_key", "service_private_key" })
                        if (doc.RootElement.TryGetProperty(field, out var p) &&
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

    /// <summary>Accepts both a 32-hex sign-in/data runId and an OIDC library's URL-safe state.</summary>
    public static bool IsRunId(string s) =>
        s.Length is >= 8 and <= 128 && s.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    private static JsonElement EmptyObject()
    {
        using var doc = JsonDocument.Parse("{}");
        return doc.RootElement.Clone();
    }

    /// <summary>Write-temp + atomic rename on the same filesystem (crash hygiene: no partial reads).</summary>
    private static void AtomicWrite(string finalPath, string contents)
    {
        AtomicWrite(finalPath, System.Text.Encoding.UTF8.GetBytes(contents));
    }

    /// <summary>Write-temp + rename for content that must land as the exact bytes given.</summary>
    private static void AtomicWrite(string finalPath, byte[] contents)
    {
        var tmp = $"{finalPath}.{Convert.ToHexString(RandomNumberGenerator.GetBytes(4))}.tmp";
        File.WriteAllBytes(tmp, contents);
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

// ── the "what just happened" trace ──────────────────────────────────────────────

/// <summary>
/// The run trace shared by all three scenario families (standards §1). Several handlers can run twice for
/// one run — /callback carries no already-completed guard, and the flow / company-data poll loops
/// legitimately re-attempt the same call on every poll — so an unconditional append writes the same line
/// again. The trace must read as what the run DID.
///
/// <para><b>RECORD AT ATTEMPT TIME: call this IMMEDIATELY BEFORE the SDK call it names, never after.</b>
/// A run that ends `failed` is still a run the panel reports, and the call the reader most needs to see is
/// the one that threw — a bad client secret, a 429, a decrypt failure. An append placed after the call is
/// skipped by the very exception the reader is trying to understand, so the panel would say only that the
/// client was constructed. This is the same under-reporting the trace exists to prevent, one path further in;
/// the rule is the invariant, not a per-scenario habit. A bulk call records one entry per attempt, so a
/// partial run shows exactly how far it got.</para>
/// </summary>
public static class Trace
{
    /// <summary>
    /// Append a call name preserving first-occurrence order and skipping a repeat. Returns true when the
    /// name was newly added, so the caller can persist on that transition.
    /// </summary>
    public static bool Add(List<string> calls, string name)
    {
        if (calls.Contains(name)) return false;
        calls.Add(name);
        return true;
    }
}
