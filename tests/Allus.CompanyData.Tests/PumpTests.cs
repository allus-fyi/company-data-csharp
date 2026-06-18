// Crash-safe changes-pump tests. Drives the pump with a fake in-memory changes
// source returning canned CIPHERTEXT events (reusing the shared decryption vector's real
// {_enc:1,...} wrapper as a value) and a decrypt callable running the real crypto core. Nothing
// here touches the live API. Mirrors the Python reference's full §6 coverage incl. the four
// durability caveats.

using System.Security.Cryptography;
using System.Text.Json;
using Allus.CompanyData;
using Xunit;

namespace Allus.CompanyData.Tests;

public sealed class PumpTests : IDisposable
{
    private readonly string _cacheDir;
    private readonly RSA _key;
    private readonly Config _config;

    public PumpTests()
    {
        _cacheDir = Path.Combine(Path.GetTempPath(), "allus-pump-" + Guid.NewGuid().ToString("N"), "allus-cache");
        _key = Vector.PrivateKey();
        _config = new Config
        {
            ApiUrl = "https://api.example.test",
            ClientId = "svc_test",
            ClientSecret = "secret",
            ServicePrivateKey = "unused.pem",
            KeyPassphrase = Vector.Passphrase,
            CacheDir = _cacheDir,
        };
    }

    public void Dispose()
    {
        _key.Dispose();
        var root = Directory.GetParent(_cacheDir)!.FullName;
        if (Directory.Exists(root)) Directory.Delete(root, true);
    }

    // The decrypt callable injected into the pump (mirrors the real Client closure).
    private Func<Node, Change> DecryptChange =>
        ev => Change.FromApi(ev, _ => "text", w => Crypto.Decrypt(w, _key));

    private static List<Node> MakeEvents(int count, int start = 1)
    {
        var events = new List<Node>();
        for (var i = start; i < start + count; i++)
        {
            events.Add(Node.Object(new Dictionary<string, Node>
            {
                ["id"] = Node.Scalar($"chg-{i:D4}"),
                ["event"] = Node.Scalar("field_updated"),
                ["person_user_id"] = Node.Scalar($"person-{i}"),
                ["slug"] = Node.Scalar("work_email"),
                ["value"] = Vector.TextWrapperNode,
                ["live"] = Node.Scalar(true),
                ["at"] = Node.Scalar($"2026-06-17T10:0{i}:00Z"),
            }));
        }
        return events;
    }

    /// <summary>In-memory drain-on-fetch queue: fetch deletes exactly what it returns.</summary>
    private sealed class FakeSource
    {
        private readonly List<Node> _queue;
        public List<int> FetchCalls { get; } = new();
        public FakeSource(IEnumerable<Node> events) => _queue = events.ToList();
        public int Remaining => _queue.Count;

        public Task<List<Node>> Fetch(int limit, CancellationToken ct)
        {
            FetchCalls.Add(limit);
            var batch = _queue.Take(limit).ToList();
            _queue.RemoveRange(0, batch.Count);
            return Task.FromResult(batch);
        }
    }

    private Pump NewPump(FakeSource src) =>
        new(_config, src.Fetch, DecryptChange, sleep: (_, _) => Task.CompletedTask);

    private static Func<Change, Task> H(Action<Change> a) => c => { a(c); return Task.CompletedTask; };

    // ── (a) persist-before-deliver ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task BatchPersistedBeforeAnyHandlerCall()
    {
        var src = new FakeSource(MakeEvents(3));
        int? pendingAtFirstCall = null;
        var pump = NewPump(src);
        await pump.ProcessChangesAsync(H(_ =>
        {
            if (pendingAtFirstCall is null)
                pendingAtFirstCall = new FileBuffer(_config.CacheDir).Pending().Count;
        }));
        Assert.Equal(3, pendingAtFirstCall);
    }

    // ── (b) ack on success ─────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task HandlerSuccessAcksPendingFile()
    {
        var src = new FakeSource(MakeEvents(3));
        var seen = new List<string?>();
        var pump = NewPump(src);
        await pump.ProcessChangesAsync(H(c => seen.Add(c.Id)));
        Assert.Equal(new[] { "chg-0001", "chg-0002", "chg-0003" }, seen);
        var buf = new FileBuffer(_config.CacheDir);
        Assert.Empty(buf.Pending());
        Assert.Empty(buf.DeadLetters());
    }

    [Fact]
    public async Task DeliveredChangeIsDecryptedPlaintext()
    {
        var src = new FakeSource(MakeEvents(1));
        var delivered = new List<Change>();
        var pump = NewPump(src);
        await pump.ProcessChangesAsync(H(c => delivered.Add(c)));
        Assert.Single(delivered);
        Assert.Equal(Vector.TextPlaintext, delivered[0].ValueObj); // not the wrapper
    }

    // ── (c) retry → dead-letter → continue ─────────────────────────────────────────────────────

    [Fact]
    public async Task PoisonEventDeadLetteredOthersProcessed()
    {
        var src = new FakeSource(MakeEvents(3));
        var attempts = 0;
        var deliveredOk = new List<string?>();
        var pump = NewPump(src);
        await pump.ProcessChangesAsync(c =>
        {
            if (c.Id == "chg-0002") { attempts++; throw new InvalidOperationException("poison"); }
            deliveredOk.Add(c.Id);
            return Task.CompletedTask;
        }, new ProcessOptions { MaxRetries = 3 });

        Assert.Equal(4, attempts); // 1 + max_retries
        Assert.Equal(new[] { "chg-0001", "chg-0003" }, deliveredOk);

        var buf = new FileBuffer(_config.CacheDir);
        Assert.Empty(buf.Pending());
        var dl = buf.DeadLetters();
        Assert.Equal(new[] { "chg-0002" }, dl.Select(d => d.Get("id").AsString()));
        Assert.Contains("poison", dl[0].Get("error").AsString());
        Assert.Equal("4", dl[0].Get("attempts").AsString());
    }

    [Fact]
    public async Task OnErrorHaltRaisesAndLeavesPending()
    {
        var src = new FakeSource(MakeEvents(3));
        var pump = NewPump(src);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            pump.ProcessChangesAsync(c =>
            {
                if (c.Id == "chg-0002") throw new InvalidOperationException("halt-me");
                return Task.CompletedTask;
            }, new ProcessOptions { MaxRetries = 1, OnError = OnError.Halt }));

        var buf = new FileBuffer(_config.CacheDir);
        Assert.Equal(new[] { "chg-0002", "chg-0003" }, buf.Pending().Select(e => e.Get("id").AsString()));
    }

    // ── (d) crash test ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task CrashAfterOneThenReplayOnRestart()
    {
        var src = new FakeSource(MakeEvents(3));
        var deliveredRun1 = new List<string?>();
        var pump1 = NewPump(src);
        await Assert.ThrowsAsync<CrashException>(() =>
            pump1.ProcessChangesAsync(c =>
            {
                deliveredRun1.Add(c.Id);
                if (deliveredRun1.Count == 1) return Task.CompletedTask; // #1 acked
                throw new CrashException();                              // crash before #2/#3 ack
            }, new ProcessOptions { MaxRetries = 0, OnError = OnError.Halt }));

        Assert.Equal(new[] { "chg-0001", "chg-0002" }, deliveredRun1);
        var bufMid = new FileBuffer(_config.CacheDir);
        Assert.Equal(new[] { "chg-0002", "chg-0003" }, bufMid.Pending().Select(e => e.Get("id").AsString()));

        // Restart: brand-new pump on the SAME cache_dir, with NO new events. It must REPLAY first.
        var empty = new FakeSource(Enumerable.Empty<Node>());
        var deliveredRun2 = new List<string?>();
        var pump2 = NewPump(empty);
        await pump2.ProcessChangesAsync(H(c => deliveredRun2.Add(c.Id)));

        Assert.Equal(new[] { "chg-0002", "chg-0003" }, deliveredRun2);
        Assert.NotEmpty(empty.FetchCalls);
        Assert.True(empty.FetchCalls[0] >= 1);
        Assert.Empty(new FileBuffer(_config.CacheDir).Pending());
    }

    [Fact]
    public async Task IdempotentChangeIdStableAcrossReplay()
    {
        var src = new FakeSource(MakeEvents(2));
        var run1 = new List<(string? Id, object? Value)>();
        var pump1 = NewPump(src);
        await Assert.ThrowsAsync<CrashException>(() =>
            pump1.ProcessChangesAsync(c => { run1.Add((c.Id, c.ValueObj)); throw new CrashException(); },
                new ProcessOptions { MaxRetries = 0, OnError = OnError.Halt }));

        var run2 = new List<(string? Id, object? Value)>();
        var empty = new FakeSource(Enumerable.Empty<Node>());
        var pump2 = NewPump(empty);
        await pump2.ProcessChangesAsync(H(c => run2.Add((c.Id, c.ValueObj))));

        Assert.Equal("chg-0001", run1[0].Id);
        Assert.Equal("chg-0001", run2[0].Id);
        Assert.Equal(run1[0].Value, run2[0].Value);
    }

    // ── (e) ciphertext at rest ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task BufferFilesStoreCiphertextNotPlaintext()
    {
        var src = new FakeSource(MakeEvents(2));
        var pump = NewPump(src);
        await Assert.ThrowsAsync<StopException>(() =>
            pump.ProcessChangesAsync(_ => throw new StopException(),
                new ProcessOptions { MaxRetries = 0, OnError = OnError.Halt }));

        var pendingDir = Path.Combine(_config.CacheDir, "pending");
        var files = Directory.GetFiles(pendingDir).OrderBy(f => f).ToList();
        Assert.NotEmpty(files);
        foreach (var file in files)
        {
            var rawText = File.ReadAllText(file);
            Assert.DoesNotContain(Vector.TextPlaintext, rawText); // no plaintext at rest
            using var doc = JsonDocument.Parse(rawText);
            Assert.Equal(1, doc.RootElement.GetProperty("value").GetProperty("_enc").GetInt32());
            Assert.Equal(Vector.TextWrapper.GetProperty("k").GetString(),
                doc.RootElement.GetProperty("value").GetProperty("k").GetString());
        }
    }

    // ── (f) returns when drained ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task ProcessChangesReturnsWhenSourceDrained()
    {
        var src = new FakeSource(MakeEvents(5));
        var delivered = new List<string?>();
        var pump = NewPump(src);
        await pump.ProcessChangesAsync(H(c => delivered.Add(c.Id)), new ProcessOptions { BatchSize = 2 });
        Assert.Equal(new[] { "chg-0001", "chg-0002", "chg-0003", "chg-0004", "chg-0005" }, delivered);
        Assert.Equal(0, src.Remaining);
        Assert.Equal(2, src.FetchCalls[^1]); // last fetch returned empty → return
    }

    [Fact]
    public async Task EmptySourceReturnsImmediately()
    {
        var src = new FakeSource(Enumerable.Empty<Node>());
        var delivered = new List<Change>();
        var pump = NewPump(src);
        await pump.ProcessChangesAsync(H(c => delivered.Add(c)));
        Assert.Empty(delivered);
        Assert.Equal(new[] { 100 }, src.FetchCalls); // one drain, default batch_size, got nothing
    }

    [Fact]
    public async Task BatchSizeClampedTo500()
    {
        var src = new FakeSource(MakeEvents(1));
        var pump = NewPump(src);
        await pump.ProcessChangesAsync(H(_ => { }), new ProcessOptions { BatchSize = 9999 });
        Assert.Equal(500, src.FetchCalls.Max());
    }

    // ── drain_batch primitive + dead-letter retry ─────────────────────────────────────────────

    [Fact]
    public async Task DrainBatchIsRawUnbuffered()
    {
        var src = new FakeSource(MakeEvents(3));
        var pump = NewPump(src);
        var batch = await pump.DrainBatchAsync(2);
        Assert.Equal(new[] { "chg-0001", "chg-0002" }, batch.Select(c => c.Id));
        Assert.Empty(new FileBuffer(_config.CacheDir).Pending()); // nothing buffered
        Assert.Equal(new[] { 2 }, src.FetchCalls);
    }

    [Fact]
    public async Task DrainBatchClampedTo500()
    {
        var src = new FakeSource(Enumerable.Empty<Node>());
        var pump = NewPump(src);
        await pump.DrainBatchAsync(10_000);
        Assert.Equal(new[] { 500 }, src.FetchCalls);
    }

    [Fact]
    public async Task RetryDeadLettersRedrives()
    {
        var src = new FakeSource(MakeEvents(2));
        var pump = NewPump(src);
        await pump.ProcessChangesAsync(c =>
        {
            if (c.Id == "chg-0002") throw new InvalidOperationException("boom");
            return Task.CompletedTask;
        }, new ProcessOptions { MaxRetries = 1 });

        Assert.Equal(new[] { "chg-0002" },
            new FileBuffer(_config.CacheDir).DeadLetters().Select(d => d.Get("id").AsString()));

        var redriven = new List<string?>();
        await pump.RetryDeadLettersAsync(H(c => redriven.Add(c.Id)));
        Assert.Equal(new[] { "chg-0002" }, redriven);
        Assert.Empty(new FileBuffer(_config.CacheDir).DeadLetters());
    }

    [Fact]
    public async Task RetryDeadLettersStillFailingStaysDeadletteredNeverPending()
    {
        var src = new FakeSource(MakeEvents(2));
        var pump = NewPump(src);
        await pump.ProcessChangesAsync(c =>
        {
            if (c.Id == "chg-0002") throw new InvalidOperationException("boom");
            return Task.CompletedTask;
        }, new ProcessOptions { MaxRetries = 1 });

        var buf = new FileBuffer(_config.CacheDir);
        var dl0 = buf.DeadLetters();
        Assert.Equal(new[] { "chg-0002" }, dl0.Select(d => d.Get("id").AsString()));
        Assert.Equal("2", dl0[0].Get("attempts").AsString()); // 1 + max_retries

        var pendingDir = Path.Combine(_config.CacheDir, "pending");
        var deadletterDir = Path.Combine(_config.CacheDir, "deadletter");

        var redriven = await pump.RetryDeadLettersAsync(
            c => c.Id == "chg-0002" ? throw new InvalidOperationException("boom") : Task.CompletedTask,
            new ProcessOptions { MaxRetries = 2 });
        Assert.Equal(0, redriven);

        var dl1 = new FileBuffer(_config.CacheDir).DeadLetters();
        Assert.Equal(new[] { "chg-0002" }, dl1.Select(d => d.Get("id").AsString()));
        Assert.Equal("3", dl1[0].Get("attempts").AsString()); // 1 + the 2 re-drive attempts
        Assert.Contains("boom", dl1[0].Get("error").AsString());
        Assert.Empty(new FileBuffer(_config.CacheDir).Pending());
        Assert.Empty(Directory.GetFiles(pendingDir));
        Assert.Single(Directory.GetFiles(deadletterDir), n => n.EndsWith(".json"));

        var ok = new List<string?>();
        var again = await pump.RetryDeadLettersAsync(H(c => ok.Add(c.Id)));
        Assert.Equal(1, again);
        Assert.Equal(new[] { "chg-0002" }, ok);
        Assert.Empty(new FileBuffer(_config.CacheDir).DeadLetters());
        Assert.Empty(new FileBuffer(_config.CacheDir).Pending());
    }

    [Fact]
    public async Task RetryDeadLettersAttemptsMonotonicAcrossRuns()
    {
        var src = new FakeSource(MakeEvents(2));
        var pump = NewPump(src);
        await pump.ProcessChangesAsync(c =>
            c.Id == "chg-0002" ? throw new InvalidOperationException("boom") : Task.CompletedTask,
            new ProcessOptions { MaxRetries = 3 });
        var dl0 = new FileBuffer(_config.CacheDir).DeadLetters();
        Assert.Equal("4", dl0[0].Get("attempts").AsString()); // 1 + 3 retries

        // Re-drive with a SMALLER budget (run-local attempts = 1). The stored count stays clamped at 4.
        Assert.Equal(0, await pump.RetryDeadLettersAsync(
            c => c.Id == "chg-0002" ? throw new InvalidOperationException("boom") : Task.CompletedTask,
            new ProcessOptions { MaxRetries = 0 }));
        var dl1 = new FileBuffer(_config.CacheDir).DeadLetters();
        Assert.Equal("4", dl1[0].Get("attempts").AsString()); // monotonic — NOT 1
    }

    [Fact]
    public async Task RetryDeadLettersCrashWindowNeverResurrectsToPending()
    {
        // The crash window (caveat #2): a crash DURING a still-failing re-drive's rewrite must never
        // leave the event live in pending/. The OLD buggy code did remove_dead_letter → append (→
        // pending/) → dead_letter; a crash between the append and the re-dead-letter would resurrect
        // the dead-letter as a LIVE pending event. We simulate the crash by making the buffer's
        // DeadLetter throw; the FIXED in-place UpdateDeadLetter path never calls DeadLetter on a
        // re-fail, so a fresh pump on the same cache_dir must NOT replay it as pending.
        var src = new FakeSource(MakeEvents(1, start: 2)); // one event: chg-0002
        var pump = NewPump(src);
        await pump.ProcessChangesAsync(_ => throw new InvalidOperationException("boom"),
            new ProcessOptions { MaxRetries = 0 }); // → chg-0002 dead-lettered
        Assert.Equal(new[] { "chg-0002" },
            new FileBuffer(_config.CacheDir).DeadLetters().Select(d => d.Get("id").AsString()));

        // A buffer whose DeadLetter throws (the buggy path's final step). The fixed code never
        // calls DeadLetter on a re-fail (it uses an in-place UpdateDeadLetter), so this is inert for
        // the fix — but lethal for the bug, which is the point.
        var crashingBuffer = new CrashingDeadLetterBuffer(_config.CacheDir);
        var pump2 = new Pump(crashingBuffer, src.Fetch, DecryptChange, sleep: (_, _) => Task.CompletedTask);
        try { await pump2.RetryDeadLettersAsync(_ => throw new InvalidOperationException("boom"),
            new ProcessOptions { MaxRetries = 0 }); }
        catch (CrashException) { /* buggy code would crash here mid-rewrite; fixed code never gets here */ }

        // A brand-new pump on the SAME cache_dir, empty source: REPLAY must find nothing pending.
        var replayed = new List<string?>();
        var pump3 = new Pump(_config, new FakeSource(Enumerable.Empty<Node>()).Fetch, DecryptChange,
            sleep: (_, _) => Task.CompletedTask);
        await pump3.ProcessChangesAsync(H(c => replayed.Add(c.Id)));
        Assert.Empty(replayed); // nothing resurrected into the live stream
        Assert.Empty(new FileBuffer(_config.CacheDir).Pending());
        // Still safely dead-lettered (its only home).
        Assert.Equal(new[] { "chg-0002" },
            new FileBuffer(_config.CacheDir).DeadLetters().Select(d => d.Get("id").AsString()));
    }

    private sealed class CrashingDeadLetterBuffer : FileBuffer
    {
        public CrashingDeadLetterBuffer(string cacheDir) : base(cacheDir) { }
        public override bool DeadLetter(string? changeId, string error, int attempts)
            => throw new CrashException();
    }

    // ── caveat #1: a poison-decrypt event must not wedge the stream ─────────────────────────────

    private static Node MakePoisonEvent(string id) => Node.Object(new Dictionary<string, Node>
    {
        ["id"] = Node.Scalar(id),
        ["event"] = Node.Scalar("field_updated"),
        ["person_user_id"] = Node.Scalar("person-x"),
        ["slug"] = Node.Scalar("work_email"),
        // A structurally-bogus wrapper → DecryptException at delivery (never on disk).
        ["value"] = Node.Object(new Dictionary<string, Node>
        {
            ["_enc"] = Node.Scalar(1L),
            ["k"] = Node.Scalar("@@notbase64@@"),
            ["iv"] = Node.Scalar("AAAA"),
            ["d"] = Node.Scalar("AAAA"),
        }),
        ["live"] = Node.Scalar(true),
        ["at"] = Node.Scalar("2026-06-17T10:09:00Z"),
    });

    [Fact]
    public async Task PoisonDecryptDeadLettersWithoutWedging()
    {
        var decryptCalls = 0;
        Func<Node, Change> decryptChange = ev =>
        {
            var cid = ev.Get("id").AsString();
            if (cid == "chg-0002") { decryptCalls++; throw new DecryptException("corrupt ciphertext for chg-0002"); }
            return Change.FromApi(ev, _ => "text", w => Crypto.Decrypt(w, _key));
        };

        var events = MakeEvents(1, start: 1);
        events.Add(MakePoisonEvent("chg-0002"));
        events.AddRange(MakeEvents(1, start: 3));
        var src = new FakeSource(events);

        var delivered = new List<string?>();
        var pump = new Pump(_config, src.Fetch, decryptChange, sleep: (_, _) => Task.CompletedTask);
        await pump.ProcessChangesAsync(H(c => delivered.Add(c.Id)), new ProcessOptions { MaxRetries = 3 });

        Assert.Equal(new[] { "chg-0001", "chg-0003" }, delivered);
        Assert.Equal(1, decryptCalls); // dead-lettered IMMEDIATELY — no retries

        var buf = new FileBuffer(_config.CacheDir);
        Assert.Empty(buf.Pending());
        var dl = buf.DeadLetters();
        Assert.Equal(new[] { "chg-0002" }, dl.Select(d => d.Get("id").AsString()));
        Assert.Contains("DecryptException", dl[0].Get("error").AsString());
        Assert.Equal("1", dl[0].Get("attempts").AsString());

        Assert.Empty(Directory.GetFiles(Path.Combine(_config.CacheDir, "pending")));
        Assert.Single(Directory.GetFiles(Path.Combine(_config.CacheDir, "deadletter")), n => n.EndsWith(".json"));

        // A fresh pump on the SAME cache_dir, empty source: must NOT re-deliver the poison event.
        var delivered2 = new List<string?>();
        var empty = new FakeSource(Enumerable.Empty<Node>());
        var pump2 = new Pump(_config, empty.Fetch, decryptChange, sleep: (_, _) => Task.CompletedTask);
        await pump2.ProcessChangesAsync(H(c => delivered2.Add(c.Id)));
        Assert.Empty(delivered2);
        Assert.Equal(new[] { "chg-0002" },
            new FileBuffer(_config.CacheDir).DeadLetters().Select(d => d.Get("id").AsString()));
    }

    [Fact]
    public async Task PoisonDecryptWithHaltReraises()
    {
        Func<Node, Change> decryptChange = ev =>
            ev.Get("id").AsString() == "chg-0001"
                ? throw new DecryptException("undecryptable")
                : Change.FromApi(ev, _ => "text", w => Crypto.Decrypt(w, _key));

        var src = new FakeSource(new[] { MakePoisonEvent("chg-0001") });
        var pump = new Pump(_config, src.Fetch, decryptChange, sleep: (_, _) => Task.CompletedTask);
        await Assert.ThrowsAsync<DecryptException>(() =>
            pump.ProcessChangesAsync(H(_ => { }), new ProcessOptions { OnError = OnError.Halt }));
        // The un-acked poison event survives in pending/ (halt left it for inspection).
        Assert.Equal(new[] { "chg-0001" },
            new FileBuffer(_config.CacheDir).Pending().Select(e => e.Get("id").AsString()));
    }

    private sealed class CrashException : Exception { }
    private sealed class StopException : Exception { }
}
