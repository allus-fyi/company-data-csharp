// Crash-safe streaming changes pump.
//
// The changes feed is a server-side drain-on-fetch queue: a fetch returns up to N events (default
// 100, max 500) and deletes those rows in the same transaction — the API keeps no copy. So
// consumption cannot be a plain list: a consumer crash mid-batch would lose events the API already
// deleted, and a huge backlog must not materialize in memory. The pump solves both:
//
//   ProcessChangesAsync(handler) — one Change at a time, until the feed is empty, then RETURNS.
//                                  No follow/daemon mode (you schedule re-runs yourself).
//
// Per cycle:
//   1. Replay first — deliver any un-acked events already in the local buffer (a previous crashed
//      run), oldest-first.
//   2. Drain — when the buffer is empty, fetch ONE batch (≤ batchSize, ≤500) and PERSIST it to the
//      durable buffer (flush-to-disk) BEFORE handing anything out (the backup the API no longer has).
//   3. Deliver one-by-one — for each buffered event oldest-first: decrypt its value (at delivery —
//      never on disk), build the typed Change, call the handler.
//   4. Ack / retry / dead-letter — on success remove the event; on error retry with backoff up to
//      maxRetries, then dead-letter (default) + continue, or halt + rethrow.
//   5. Repeat until a drain returns empty AND the buffer is drained → return.
//
// Durability caveats preserved:
//   (1) decrypt INSIDE the delivery attempt → a DecryptException dead-letters IMMEDIATELY (no
//       retry burn) and never wedges replay;
//   (2) a re-failing dead-letter is updated IN PLACE (never back through pending/);
//   (3) stored attempts are monotonic = max(existing,new);
//   (4) dead_letter writes the new copy BEFORE deleting pending (at-least-once; do not "fix").

namespace Allus.CompanyData;

/// <summary>How a failing handler is resolved.</summary>
public enum OnError { DeadLetter, Halt }

/// <summary>Options for <see cref="Pump.ProcessChangesAsync"/>.</summary>
public sealed class ProcessOptions
{
    /// <summary>Drain batch size, clamped to [1, 500].</summary>
    public int BatchSize { get; init; } = 100;

    /// <summary>Handler retries before dead-lettering (a DecryptException never burns these).</summary>
    public int MaxRetries { get; init; } = 3;

    /// <summary>What to do when retries are exhausted (default <see cref="OnError.DeadLetter"/>).</summary>
    public OnError OnError { get; init; } = OnError.DeadLetter;

    /// <summary>attempt (1-based) → backoff seconds before the next retry.</summary>
    public Func<int, double>? Backoff { get; init; }
}

/// <summary>A minimal pump logger seam (default no-op). Levels are folded to one method.</summary>
public interface IPumpLogger
{
    void Log(string message);
}

/// <summary>The crash-safe changes pump.</summary>
public sealed class Pump
{
    /// <summary>The drain-on-fetch queue caps a fetch at 500.</summary>
    public const int MaxBatch = 500;
    private const int DefaultBatch = 100;
    private const double DefaultBackoffSeconds = 0.5;
    private const double MaxBackoffSeconds = 30.0;

    private readonly Func<int, CancellationToken, Task<List<Node>>> _fetchChanges;
    private readonly Func<Node, Change> _decrypt;
    private readonly IPumpLogger? _log;
    private readonly Func<double, CancellationToken, Task> _sleep;
    private readonly FileBuffer _buffer;

    public Pump(
        Config config,
        Func<int, CancellationToken, Task<List<Node>>> fetchChanges,
        Func<Node, Change> decrypt,
        IPumpLogger? logger = null,
        Func<double, CancellationToken, Task>? sleep = null)
        : this(new FileBuffer(config.CacheDir), fetchChanges, decrypt, logger, sleep)
    {
    }

    // Internal constructor that injects the buffer (used by tests to exercise the crash-window
    // caveat: a FileBuffer subclass whose DeadLetter throws proves the in-place re-drive path never
    // calls DeadLetter on a re-fail).
    internal Pump(
        FileBuffer buffer,
        Func<int, CancellationToken, Task<List<Node>>> fetchChanges,
        Func<Node, Change> decrypt,
        IPumpLogger? logger = null,
        Func<double, CancellationToken, Task>? sleep = null)
    {
        _fetchChanges = fetchChanges;
        _decrypt = decrypt;
        _log = logger;
        _sleep = sleep ?? (async (s, ct) => await Task.Delay(TimeSpan.FromSeconds(s), ct).ConfigureAwait(false));
        // The buffer recovers whatever is already on disk — that recovery IS replay-on-restart.
        _buffer = buffer;
    }

    /// <summary>The durable buffer (exposed for inspection / tests).</summary>
    public FileBuffer Buffer => _buffer;

    private static double DefaultBackoff(int attempt) =>
        Math.Min(DefaultBackoffSeconds * Math.Pow(2, attempt - 1), MaxBackoffSeconds);

    /// <summary>
    /// Stream events through <paramref name="handler"/> until the feed is empty, then return.
    /// <paramref name="handler"/> is called with one typed <see cref="Change"/> at a time and MUST
    /// be idempotent (at-least-once delivery; dedup on <see cref="Change.Id"/>).
    /// </summary>
    public async Task ProcessChangesAsync(
        Func<Change, Task> handler,
        ProcessOptions? options = null,
        CancellationToken ct = default)
    {
        options ??= new ProcessOptions();
        var size = ClampBatch(options.BatchSize);
        var backoff = options.Backoff ?? DefaultBackoff;

        while (true)
        {
            // 1. Replay anything already buffered (a previous crashed run). If empty, drain one batch.
            var pending = _buffer.Pending();
            if (pending.Count > 0)
            {
                _log?.Log($"pump replay: {pending.Count} buffered event(s)");
            }
            else
            {
                var drained = await DrainIntoBufferAsync(size, ct).ConfigureAwait(false);
                if (drained == 0) return; // drain empty AND buffer drained → done
                pending = _buffer.Pending();
            }

            // 3+4. Deliver each buffered event oldest-first; ack/retry/dead-letter.
            foreach (var ev in pending)
                await DeliverOneAsync(ev, handler, options.MaxRetries, options.OnError, backoff, ct)
                    .ConfigureAwait(false);
        }
    }

    private async Task<int> DrainIntoBufferAsync(int size, CancellationToken ct)
    {
        var batch = await _fetchChanges(size, ct).ConfigureAwait(false) ?? new List<Node>();
        _log?.Log($"pump drain: fetched {batch.Count} event(s) (limit={size})");
        if (batch.Count == 0) return 0;
        _buffer.Append(batch); // persist-before-deliver: the durable backup the API no longer has
        return batch.Count;
    }

    private async Task DeliverOneAsync(
        Node ev,
        Func<Change, Task> handler,
        int maxRetries,
        OnError onError,
        Func<int, double> backoff,
        CancellationToken ct)
    {
        var changeId = ev.Get("id").AsString();
        var attempts = 0;

        while (true)
        {
            attempts++;
            Change change;
            try
            {
                // Decrypt only now — never on disk (ciphertext at rest). Inside the try so a
                // poison-ciphertext DecryptException is contained (caveat #1).
                change = _decrypt(ev);
            }
            catch (DecryptException ex)
            {
                // A poison event: re-decrypting won't help, so don't burn retries.
                if (onError == OnError.Halt)
                {
                    _log?.Log($"pump halt: id={changeId} undecryptable ({ex.Message})");
                    throw;
                }
                _buffer.DeadLetter(changeId, $"DecryptException: {ex.Message}", attempts);
                _log?.Log($"pump dead-letter (undecryptable): id={changeId}: {ex.Message}");
                return;
            }

            try
            {
                _log?.Log($"pump deliver: id={changeId} attempt={attempts}");
                await handler(change).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                if (attempts <= maxRetries)
                {
                    var delay = Math.Max(0.0, backoff(attempts));
                    _log?.Log($"pump retry: id={changeId} attempt={attempts} failed ({ex.Message}); backoff {delay:F3}s");
                    if (delay > 0) await _sleep(delay, ct).ConfigureAwait(false);
                    continue;
                }
                if (onError == OnError.Halt)
                {
                    _log?.Log($"pump halt: id={changeId} failed after {attempts} attempt(s)");
                    throw;
                }
                _buffer.DeadLetter(changeId, ex.Message, attempts);
                _log?.Log($"pump dead-letter: id={changeId} after {attempts} attempt(s): {ex.Message}");
                return;
            }

            // Success → per-item ack (remove from the buffer).
            _buffer.Ack(changeId);
            _log?.Log($"pump ack: id={changeId}");
            return;
        }
    }

    /// <summary>
    /// Raw, UNBUFFERED drain → a list of typed Changes (advanced; §6 / §4.1). Fetches one batch
    /// (clamped ≤500) and returns the decrypted Changes directly — it does NOT persist anything, so
    /// YOU own durability. Prefer <see cref="ProcessChangesAsync"/>.
    /// </summary>
    public async Task<List<Change>> DrainBatchAsync(int max = DefaultBatch, CancellationToken ct = default)
    {
        var size = ClampBatch(max);
        var batch = await _fetchChanges(size, ct).ConfigureAwait(false) ?? new List<Node>();
        _log?.Log($"drain_batch: fetched {batch.Count} event(s) (limit={size})");
        return batch.Select(_decrypt).ToList();
    }

    /// <summary>The local dead-letter store (ciphertext + error + attempt count, §6.3).</summary>
    public List<Node> DeadLetters() => _buffer.DeadLetters();

    /// <summary>
    /// Re-drive every dead-lettered event through <paramref name="handler"/>. On
    /// success the record is removed; on repeated failure it is re-dead-lettered IN PLACE (default)
    /// or the error is re-raised (halt). Never re-fetched from the API. Returns the count re-driven.
    /// </summary>
    public async Task<int> RetryDeadLettersAsync(
        Func<Change, Task> handler,
        ProcessOptions? options = null,
        CancellationToken ct = default)
    {
        options ??= new ProcessOptions();
        var backoff = options.Backoff ?? DefaultBackoff;
        var maxRetries = options.MaxRetries;
        var onError = options.OnError;

        var redriven = 0;
        foreach (var record in _buffer.DeadLetters())
        {
            var changeId = record.Get("id").AsString();
            // Strip the reserved failure block before re-decrypting the event.
            var ev = record.Without("_deadletter", "error", "attempts");
            var attempts = 0;
            while (true)
            {
                attempts++;
                Change change;
                try
                {
                    // Decrypt inside the loop so an undecryptable dead-letter is contained here too.
                    change = _decrypt(ev);
                }
                catch (DecryptException ex)
                {
                    if (onError == OnError.Halt)
                    {
                        _log?.Log($"retry_dead_letters halt: id={changeId} undecryptable ({ex.Message})");
                        throw;
                    }
                    _buffer.UpdateDeadLetter(changeId, $"DecryptException: {ex.Message}", attempts);
                    _log?.Log($"retry_dead_letters: id={changeId} still undecryptable ({ex.Message})");
                    break;
                }

                try
                {
                    await handler(change).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    if (attempts <= maxRetries)
                    {
                        var delay = Math.Max(0.0, backoff(attempts));
                        if (delay > 0) await _sleep(delay, ct).ConfigureAwait(false);
                        continue;
                    }
                    if (onError == OnError.Halt)
                    {
                        _log?.Log($"retry_dead_letters halt: id={changeId} failed again");
                        throw;
                    }
                    // Refresh the stored attempt count + error IN PLACE — never re-enters pending/.
                    _buffer.UpdateDeadLetter(changeId, ex.Message, attempts);
                    _log?.Log($"retry_dead_letters: id={changeId} still failing ({ex.Message})");
                    break;
                }

                _buffer.RemoveDeadLetter(changeId);
                _log?.Log($"retry_dead_letters: id={changeId} re-driven OK");
                redriven++;
                break;
            }
        }
        return redriven;
    }

    private static int ClampBatch(int value)
    {
        if (value < 1) return 1;
        return value > MaxBatch ? MaxBatch : value;
    }
}
