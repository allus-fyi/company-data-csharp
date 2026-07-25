using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Allus.FlowExample;

/// <summary>
/// One company step the SDK drove, as it appears in the flow log: the field <see cref="Slug"/>, its
/// resolved <see cref="Type"/>, the value <see cref="Submitted"/>, and whether it was
/// <see cref="Accepted"/> (a rejected email carries the validation <see cref="Error"/>).
/// </summary>
public sealed class FlowStep
{
    public string Slug { get; set; } = "";
    public string Type { get; set; } = "";
    public string Submitted { get; set; } = "";
    public bool Accepted { get; set; }
    public string? Error { get; set; }
}

/// <summary>
/// One demo run's cross-request state, serialized to <c>.runtime/runs/{runId}.json</c>. There is NO
/// separate browser-visible platform flow-run id: the platform run lives entirely inside this file
/// (<see cref="FlowRunId"/>), and the demo runId IS the backend run (contract, flow family). The GET
/// /api/runs poll is both the drive loop and the resume; a terminal run (<see cref="Completed"/> or
/// <see cref="Error"/>) is returned unchanged on every subsequent poll.
/// </summary>
public sealed class Run
{
    public string RunId { get; set; } = "";
    public int Scenario { get; set; }               // the internal store key (STORE_ID)
    public string? FlowRunId { get; set; }          // the platform flow-run id, stored INSIDE this run

    /// <summary>The INNER flow status: running | waiting_person | completed (contract's result.status).</summary>
    public string Status { get; set; } = "running";

    public List<FlowStep> Steps { get; set; } = new();
    public List<string> RejectedNodes { get; set; } = new(); // nodes whose email demo has been rejected once
    public List<string> Calls { get; set; } = new();
    public bool Completed { get; set; }

    // Terminal extras (present once the flow completes).
    public List<Dictionary<string, object?>>? Answers { get; set; }
    public Dictionary<string, object?>? Document { get; set; }

    public string? Error { get; set; }
}

/// <summary>
/// Cross-request state for the demo backend (contract §"Backend state", config-file amendment). The
/// single-worker server serializes requests, so there is NO concurrency to guard — NO locks, NO
/// tombstones, NO burn-on-read. Everything lives under <see cref="RuntimeDir"/> (git-ignored, wiped at
/// startup):
/// <list type="bullet">
///   <item>config/{id}.json — the canonical SDK config file the run executes OFF (NOT TTL-swept)</item>
///   <item>config/{id}.meta.json — demo-only run parameters (flow_id, connection_id, fixture)</item>
///   <item>config/keys/&lt;sha1&gt;.pem — the service private-key file a config references by path (0600)</item>
///   <item>runs/{runId}.json — one demo run's flow-run id / steps / outcome (30-min TTL, lazy sweep)</item>
/// </list>
/// The one scenario uses a single store key, so <c>id</c> is a constant here.
/// </summary>
public sealed class Runtime
{
    /// <summary>30-minute run TTL. Config files are exempt (they are configuration, not runs).</summary>
    public static readonly TimeSpan Ttl = TimeSpan.FromMinutes(30);

    public string RuntimeDir { get; }
    public string RunsDir { get; }
    public string ConfigDir { get; }
    public string ConfigKeysDir { get; }

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
    }

    public void EnsureDirs()
    {
        foreach (var d in new[] { RuntimeDir, RunsDir, ConfigDir, ConfigKeysDir })
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

    public void Sweep()
    {
        if (!Directory.Exists(RunsDir)) return;
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

    // ── config files ───────────────────────────────────────────────────────────

    public string ConfigPathFor(int id) => Path.Combine(ConfigDir, $"{id}.json");
    public string MetaPathFor(int id) => Path.Combine(ConfigDir, $"{id}.meta.json");
    public bool HasConfig(int id) => File.Exists(ConfigPathFor(id));

    /// <summary>Write the scenario's canonical SDK config file. Returns the RELATIVE path (for display).</summary>
    public string WriteConfig(int id, IDictionary<string, object?> config)
    {
        EnsureDirs();
        AtomicWrite(ConfigPathFor(id), JsonSerializer.Serialize(config, PlainJson));
        return $".runtime/config/{id}.json";
    }

    public void WriteConfigMeta(int id, IDictionary<string, object?> meta)
    {
        EnsureDirs();
        AtomicWrite(MetaPathFor(id), JsonSerializer.Serialize(meta, PlainJson));
    }

    public JsonElement ReadConfigMeta(int id)
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

    // ── clear ─────────────────────────────────────────────────────────────────────

    /// <summary>Per-scenario clear: delete that store's runs + config + meta, then GC unreferenced keys.</summary>
    public void ClearScenario(int id)
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
        GcConfigKeys();
    }

    /// <summary>Global clear: wipe all run files and the entire config tree (configs, metas, keys).</summary>
    public void ClearAll()
    {
        if (Directory.Exists(RunsDir))
            foreach (var path in Directory.EnumerateFiles(RunsDir)) TryDelete(path);
        if (Directory.Exists(ConfigDir))
            Directory.Delete(ConfigDir, recursive: true);
        EnsureDirs();
    }

    /// <summary>Delete any key PEM no surviving config/{id}.json still references (content-addressed sharing).</summary>
    private void GcConfigKeys()
    {
        var referenced = new HashSet<string>(StringComparer.Ordinal);
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

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch (IOException) { /* best-effort */ }
    }
}
