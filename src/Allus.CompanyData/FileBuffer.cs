// Durable plain-file buffer for the crash-safe changes pump.
//
// The changes feed is a server-side drain-on-fetch queue: a fetch returns up to N events and
// deletes those rows in the same transaction — the API keeps no copy. So a drained batch MUST be
// persisted locally BEFORE any delivery, or a consumer crash mid-batch loses events the API
// already deleted. This is that persistence: a zero-dependency, plain-file buffer under cache_dir.
//
// Layout:
//   <cache_dir>/pending/<seq>_<change_id>.json      // one un-acked event, oldest-first
//   <cache_dir>/deadletter/<seq>_<change_id>.json   // events that exhausted retries
//
// * The stored event is the raw hardened API event (its value/value_url is CIPHERTEXT, never the
//   decrypted plaintext) — no PII at rest ("ciphertext at rest").
// * <seq> is a zero-padded, monotonically increasing sequence persisted in <cache_dir>/.seq, so
//   sorting filenames lexicographically yields oldest-first (stable even if event `at` is equal).
// * Writes are crash-safe via AtomicWrite (temp + flush-to-disk + atomic move).
// * Ack(id) deletes the pending file; DeadLetter(id, error, attempts) moves it to deadletter/.
//   Neither re-fetches from the API (it already deleted the row) — the buffer is the only home.

namespace Allus.CompanyData;

/// <summary>A durable, ordered, ciphertext-at-rest event buffer under <c>cache_dir</c>.</summary>
public class FileBuffer
{
    private const string PendingDir = "pending";
    private const string DeadLetterDir = "deadletter";
    private const string SeqFile = ".seq";

    // 16 digits keeps filenames sorting lexicographically up to ~10^16 appends.
    private const int SeqWidth = 16;

    private readonly string _dir;
    private readonly string _pendingDir;
    private readonly string _deadletterDir;
    private readonly string _seqPath;
    private readonly object _lock = new();

    public FileBuffer(string cacheDir)
    {
        _dir = cacheDir;
        _pendingDir = Path.Combine(cacheDir, PendingDir);
        _deadletterDir = Path.Combine(cacheDir, DeadLetterDir);
        _seqPath = Path.Combine(cacheDir, SeqFile);
        Directory.CreateDirectory(_pendingDir);
        Directory.CreateDirectory(_deadletterDir);
    }

    // ── sequence ─────────────────────────────────────────────────────────────────────────────

    private long NextSeq()
    {
        lock (_lock)
        {
            var current = ReadSeq() ?? MaxOnDiskSeq();
            var next = current + 1;
            AtomicWrite.WriteText(_seqPath, next.ToString());
            return next;
        }
    }

    private long? ReadSeq()
    {
        try
        {
            var text = File.ReadAllText(_seqPath).Trim();
            return long.TryParse(text, out var v) ? v : null;
        }
        catch (FileNotFoundException) { return null; }
        catch (DirectoryNotFoundException) { return null; }
    }

    private long MaxOnDiskSeq()
    {
        long best = 0;
        foreach (var d in new[] { _pendingDir, _deadletterDir })
        {
            if (!Directory.Exists(d)) continue;
            foreach (var name in Directory.EnumerateFiles(d).Select(Path.GetFileName))
            {
                var seq = SeqOf(name!);
                if (seq is { } s && s > best) best = s;
            }
        }
        return best;
    }

    // ── append / list / ack ──────────────────────────────────────────────────────────────────

    /// <summary>
    /// Persist a drained batch (oldest-first), each in its own crash-safe file. Each event is
    /// stored verbatim (ciphertext value intact). Returns the pending filenames written. This is
    /// the backup the API no longer holds — it MUST complete before the pump delivers anything.
    /// </summary>
    public List<string> Append(IReadOnlyList<Node> events)
    {
        var written = new List<string>();
        foreach (var ev in events)
        {
            var seq = NextSeq();
            var changeId = ev.Kind == NodeKind.Object ? ev.Get("id").AsString() : null;
            var name = $"{seq.ToString().PadLeft(SeqWidth, '0')}_{SanitizeId(changeId)}.json";
            AtomicWrite.WriteText(Path.Combine(_pendingDir, name), ev.ToJsonString());
            written.Add(name);
        }
        return written;
    }

    /// <summary>All un-acked events, oldest-first (by the sortable filename).</summary>
    public List<Node> Pending() =>
        PendingFiles().Select(n => ReadEvent(_pendingDir, n)).ToList();

    private List<string> PendingFiles() => SortedJsonFiles(_pendingDir);

    private static Node ReadEvent(string directory, string name) =>
        Node.FromJsonString(File.ReadAllText(Path.Combine(directory, name)));

    private string? FindPendingFile(string? changeId)
    {
        var target = SanitizeId(changeId);
        return PendingFiles().FirstOrDefault(name => SplitId(name) == target);
    }

    /// <summary>Delete the pending file for <paramref name="changeId"/> (the per-item ack). Idempotent.</summary>
    public bool Ack(string? changeId)
    {
        var name = FindPendingFile(changeId);
        if (name is null) return false;
        try { File.Delete(Path.Combine(_pendingDir, name)); }
        catch (FileNotFoundException) { return false; }
        return true;
    }

    // ── dead-letter ────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Move a poison event from pending → deadletter with error + attempts. The event keeps its
    /// ciphertext value; the failure context is added under a reserved key so it is never silently
    /// dropped.
    ///
    /// Caveat #4 (at-least-once): the new deadletter copy is written BEFORE the pending copy is
    /// unlinked — a crash between them leaves the event in BOTH dirs → harmless re-delivery on
    /// replay (id-dedup absorbs it). Do NOT "fix" this by deleting-first.
    /// </summary>
    public virtual bool DeadLetter(string? changeId, string error, int attempts)
    {
        var name = FindPendingFile(changeId);
        if (name is null) return false;
        var ev = ReadEvent(_pendingDir, name);
        var record = ev.WithProperty("_deadletter", Node.Object(new Dictionary<string, Node>
        {
            ["error"] = Node.Scalar(error),
            ["attempts"] = Node.Scalar((long)attempts),
        }));
        // Write the deadletter copy first (never lose), then unlink pending.
        AtomicWrite.WriteText(Path.Combine(_deadletterDir, name), record.ToJsonString());
        try { File.Delete(Path.Combine(_pendingDir, name)); }
        catch (FileNotFoundException) { /* already gone */ }
        return true;
    }

    private List<string> DeadLetterFiles() => SortedJsonFiles(_deadletterDir);

    /// <summary>
    /// All dead-lettered events, oldest-first. Each item is the stored (ciphertext) event Node with
    /// a flattened <c>error</c>/<c>attempts</c> lifted out of the reserved <c>_deadletter</c> block.
    /// </summary>
    public List<Node> DeadLetters()
    {
        var outList = new List<Node>();
        foreach (var name in DeadLetterFiles())
        {
            var ev = ReadEvent(_deadletterDir, name);
            var meta = ev.Get("_deadletter");
            var item = ev
                .WithProperty("error", meta.Get("error"))
                .WithProperty("attempts", meta.Get("attempts"));
            outList.Add(item);
        }
        return outList;
    }

    private string? FindDeadLetterFile(string? changeId)
    {
        var target = SanitizeId(changeId);
        return DeadLetterFiles().FirstOrDefault(name => SplitId(name) == target);
    }

    /// <summary>
    /// Rewrite a dead-letter record IN PLACE with a refreshed error + attempts (caveat #2): the
    /// record stays in deadletter/ and is updated atomically (temp + flush + move within the
    /// deadletter dir). It is NEVER routed back through pending/, so a crash anywhere leaves it as
    /// either the old or new dead-letter — it can never resurrect as a live pending event.
    /// Idempotent (false if gone). Preserves the seq prefix so ordering is unchanged. The stored
    /// attempt count is monotonic = max(existing, new) (caveat #3).
    /// </summary>
    public bool UpdateDeadLetter(string? changeId, string error, int attempts)
    {
        var name = FindDeadLetterFile(changeId);
        if (name is null) return false;
        var path = Path.Combine(_deadletterDir, name);
        Node ev;
        try { ev = ReadEvent(_deadletterDir, name); }
        catch (FileNotFoundException) { return false; }

        var prior = ev.Get("_deadletter").Get("attempts").AsString();
        var priorAttempts = long.TryParse(prior, out var pa) ? pa : 0;
        var record = ev
            .Without("_deadletter", "error", "attempts")
            .WithProperty("_deadletter", Node.Object(new Dictionary<string, Node>
            {
                ["error"] = Node.Scalar(error),
                ["attempts"] = Node.Scalar(Math.Max(priorAttempts, attempts)),
            }));
        AtomicWrite.WriteText(path, record.ToJsonString()); // temp+flush+move within deadletter/
        return true;
    }

    /// <summary>Delete a dead-letter record (after a successful re-drive). Idempotent.</summary>
    public bool RemoveDeadLetter(string? changeId)
    {
        var name = FindDeadLetterFile(changeId);
        if (name is null) return false;
        try { File.Delete(Path.Combine(_deadletterDir, name)); }
        catch (FileNotFoundException) { return false; }
        return true;
    }

    // ── helpers ──────────────────────────────────────────────────────────────────────────────

    private static List<string> SortedJsonFiles(string dir)
    {
        if (!Directory.Exists(dir)) return new List<string>();
        var names = Directory.EnumerateFiles(dir)
            .Select(Path.GetFileName)
            .Where(n => n is not null && n.EndsWith(".json", StringComparison.Ordinal)
                        && !n.StartsWith(".tmp_", StringComparison.Ordinal))
            .Select(n => n!)
            .ToList();
        names.Sort(StringComparer.Ordinal); // zero-padded seq prefix → lexicographic == oldest-first
        return names;
    }

    private static string SanitizeId(string? changeId)
    {
        var s = changeId ?? "noid";
        var chars = s.Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '_').ToArray();
        var result = new string(chars);
        return result.Length == 0 ? "noid" : result;
    }

    private static string SplitId(string name)
    {
        var idx = name.IndexOf('_');
        var rest = idx >= 0 ? name[(idx + 1)..] : name;
        return rest.EndsWith(".json", StringComparison.Ordinal) ? rest[..^5] : rest;
    }

    private static long? SeqOf(string name)
    {
        var idx = name.IndexOf('_');
        var head = idx >= 0 ? name[..idx] : name;
        return long.TryParse(head, out var v) ? v : null;
    }
}
