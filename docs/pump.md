# The changes pump

The changes feed is a server-side **drain-on-fetch queue**:
`GET /api/company-data/changes?limit=N` returns up to N events (default 100, max
500) **and deletes exactly those rows in the same transaction**. There is no
offset/cursor/page, and the API keeps no copy after a fetch. So a consumer must:

* not lose a drained batch if it crashes mid-batch (the API already deleted it), and
* not materialize a huge backlog in memory.

`client.ProcessChangesAsync(handler)` (delegating to `Allus.CompanyData.Pump`)
does both.

## `ProcessChangesAsync(handler, options)`

```csharp
Task ProcessChangesAsync(
    Func<Change, Task> handler,
    ProcessOptions? options = null,   // BatchSize (≤500, default 100), MaxRetries (3),
                                      // OnError (DeadLetter|Halt), Backoff (attempt → seconds)
    CancellationToken ct = default)
```

Drains the feed through `handler` one `Change` at a time, **until the feed is
empty, then returns**. No follow/daemon mode — schedule re-runs yourself.

## The cycle

1. **Replay first** — deliver any un-acked events already in the local buffer (a previous crashed run), oldest-first.
2. **Drain** — when the buffer is empty, fetch one batch (≤ `BatchSize`, ≤ 500) and **persist it to the durable buffer (flush-to-disk) BEFORE handing anything out**.
3. **Deliver one-by-one** — for each buffered event, oldest-first: decrypt its value *at delivery* (never on disk), build the typed `Change`, `await handler(change)`.
4. **Ack / retry / dead-letter** — on handler success, remove the event from the buffer (ack). On a handler error, retry with `Backoff` up to `MaxRetries`; then:
   * `OnError.DeadLetter` (default) → move it to the dead-letter store, log it, and continue (one poison event never wedges the stream);
   * `OnError.Halt` → re-throw the handler's exception (the event stays un-acked in the buffer for the next run).
   A **`DecryptException`** (corrupt/truncated ciphertext, rotated key) is special: the decrypt runs *inside* the delivery attempt, and an undecryptable event is **dead-lettered immediately** — re-decrypting can't fix it, so it does **not** burn `MaxRetries`. Under `OnError.Halt` it re-throws like a handler error. Either way it never propagates out of `ProcessChangesAsync` and wedges step-1 replay.
5. Repeat until a drain returns empty **and** the buffer is drained → return.

## Crash safety · at-least-once · idempotency

A batch is durably buffered *before* any delivery, and acked per-item only *after*
the handler succeeds. A crash between a handler's success and its ack re-delivers
that event on the next run. Delivery is therefore **at-least-once**:

> **Your handler must be idempotent. Dedup on `Change.Id`** (the stable server
> change-row id, captured before the server delete).

## The durable buffer (on disk)

Under `cache_dir`:

```
<cache_dir>/pending/<seq>_<change_id>.json      # un-acked events, oldest-first
<cache_dir>/deadletter/<seq>_<change_id>.json   # events that exhausted retries
```

* Stored events keep their **ciphertext** `value`/`value_url` — **no plaintext PII is ever written to disk**. Decryption happens only at delivery.
* `<seq>` is a zero-padded, monotonically increasing sequence (persisted in `<cache_dir>/.seq`), so lexicographic filename order == oldest-first (stable even if `at` timestamps are equal/missing).
* Writes are crash-safe: temp file → `FileStream.Flush(flushToDisk: true)` → atomic `File.Move(..., overwrite: true)`. A crash never leaves a half-written file.
* Re-instantiating the buffer on the same `cache_dir` recovers whatever is on disk — that recovery **is** the replay-on-restart.

## Options (`ProcessOptions`)

| Option | Default | Meaning |
|--------|---------|---------|
| `BatchSize` | 100 | Events per drain; clamped to `[1, 500]`. |
| `MaxRetries` | 3 | Handler retries before dead-letter/halt. |
| `OnError` | `OnError.DeadLetter` | `DeadLetter` (continue) or `Halt` (re-throw). |
| `Backoff` | exponential, capped 30s | `Func<int, double>` — attempt (1-based) → seconds between retries. |

> Pass an `IPumpLogger` to the `Client` constructor (not to `ProcessChangesAsync`).
> Every drain, deliver, ack, retry, dead-letter, and replay is logged through it.

## No follow mode — schedule re-runs

```csharp
while (true)
{
    await client.ProcessChangesAsync(Handle);          // returns when the feed empties
    await Task.Delay(TimeSpan.FromSeconds(5));          // the feed is cheap to poll (see rate limits)
}
```

A cron job, a hosted `BackgroundService`, or any scheduler works equally well.

## Dead-letter inspect / re-drive

```csharp
List<Node> DeadLetters()
Task<int>  RetryDeadLettersAsync(Func<Change, Task> handler, ProcessOptions? options = null, ...)
```

* `DeadLetters()` — each `Node` is the stored (ciphertext) event with a flattened `error` and `attempts`, plus its `id` (read via `.Get("id").AsString()` etc.).
* `RetryDeadLettersAsync(handler)` — re-drives every dead-lettered event through `handler`. On success the record is removed. On repeated failure (or a `DecryptException`) the dead-letter record is **updated in place** with the new error + attempt count and stays in `deadletter/` (`OnError.DeadLetter`), or the error re-throws (`OnError.Halt`). The stored attempt count is **monotonic** — clamped to `max(existing, new)` — so a later re-drive with a smaller `MaxRetries` never lowers the recorded total. Returns the count successfully re-driven.

A re-failing dead-letter never re-enters `pending/` — it is rewritten in place
within `deadletter/`, so a crash mid-re-drive can't resurrect it as a live event
on the next run. Dead letters are **never silently dropped** and **never
re-fetched from the API** (it already deleted them) — the local store is their
only home, which is exactly why it's durable.

```csharp
foreach (var dl in client.DeadLetters())
    Console.WriteLine($"{dl.Get("id").AsString()} {dl.Get("error").AsString()} {dl.Get("attempts").AsString()}");

var fixedCount = await client.RetryDeadLettersAsync(Handle);   // after fixing the handler bug
```

## Advanced: `DrainBatchAsync(max)`

```csharp
Task<List<Change>> DrainBatchAsync(int max = 100, CancellationToken ct = default)
```

A raw, **UNBUFFERED** drain: fetches one batch (clamped ≤ 500) and returns the
decrypted `Change`s directly — it does **not** persist anything to the buffer, so
**you own durability** if you use it (a crash loses what the API already deleted).
Prefer `ProcessChangesAsync` for safe consumption.
