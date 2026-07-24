using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Allus.IdentityExample;

/// <summary>
/// One run's cross-request state (PKCE verifier / OIDC nonce+redirect / outcome). Serialized to
/// <c>.runtime/runs/{runId}.json</c>. Free-form <see cref="Result"/> is whatever the scenario produced.
/// </summary>
public sealed class Run
{
    public string RunId { get; set; } = "";
    public int Scenario { get; set; }
    public string Status { get; set; } = "pending"; // pending | done | failed
    public string? State { get; set; }
    public List<string> Calls { get; set; } = new();

    // Sign-in scenarios (1–4): the PKCE verifier that pairs with the challenge in the authorize URL.
    public string? Verifier { get; set; }

    // OIDC scenarios (5/6): the redirect the OIDC library needs to complete the exchange (state + PKCE
    // verifier ride the fields above; the OIDC library owns nonce handling internally).
    public string? RedirectUri { get; set; }

    // How GET /api/runs advances a still-pending run: detached_signin | detached_enroll | challenge |
    // enroll_redirect (null → completion arrives via /callback).
    public string? Wait { get; set; }
    public bool IsEnroll { get; set; }

    // Scenario 8: the challenge being polled.
    public string? ChallengeId { get; set; }

    public object? Result { get; set; }
    public string? Error { get; set; }
}

/// <summary>
/// Cross-request state for the demo backend (contract §"Backend state"). Single-worker server → requests
/// serialize; there is NO concurrency to guard, so NO locks, NO tombstones, NO burn-on-read. Everything
/// lives under <see cref="RuntimeDir"/> (git-ignored, wiped at startup):
/// <list type="bullet">
///   <item>config/{id}.json — the canonical SDK config file a scenario runs OFF (NOT TTL-swept)</item>
///   <item>config/{id}.meta.json — demo-only run parameters (authorize_base, claims, share_code, context)</item>
///   <item>config/keys/&lt;sha1&gt;.pem — private-key file(s) a config references by path (0600)</item>
///   <item>runs/{runId}.json — one run's PKCE / nonce / outcome (30-min TTL, lazy sweep)</item>
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

    /// <summary>Write a scenario's canonical SDK config file. Returns the RELATIVE path (for display).</summary>
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

    /// <summary>Per-scenario clear: delete that scenario's runs + config + meta, then GC unreferenced keys.</summary>
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

    /// <summary>Accepts both a 32-hex sign-in runId and an OIDC library's URL-safe state.</summary>
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
