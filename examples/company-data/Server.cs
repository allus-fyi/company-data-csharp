using System.Text;
using System.Text.Json;
using Allus.CompanyData;
using Microsoft.AspNetCore.Http;

namespace Allus.CompanyDataExample;

/// <summary>
/// The company-data demo backend (contract v3, company-data family). One class, one worker: HTTP
/// dispatch → handler → the SDK's intended top-level surface ONLY (no raw platform HTTP, no SDK
/// internals).
///
/// Five scenarios, all namespaced companydata:*, all using the SERVICE-role data <see cref="Client"/>:
///   read        — Client.ConnectionsAsync()   → connection-grouped decrypted values
///   definitions — Client.RequestFieldsAsync()  → your request-field catalog
///   changes     — Client.ProcessChangesAsync() → a crash-safe pump drain (idempotent on Change.Id)
///   webhook     — VerifyWebhook()+ParseWebhook() → a public POST /webhook receiver + a DrainBatchAsync()
///                                                  feed fallback; ONE accumulating run keyed by webhook id
///   documents   — Client.CreateDocumentAsync() ×6 → the six document/contract types
///
/// Settings flow: the browser POSTs a scenario's setup values to POST /api/scenarios/{id}/config, which
/// writes them to a canonical SDK config FILE (.runtime/config/{sid}.json). /start builds the Client from
/// that file (Client.FromConfig → Config.FromFile) and runs OFF it. A /start with no saved config → 409.
/// </summary>
public sealed class Server
{
    public const int ContractVersion = 3;
    public const string Sdk = "csharp";

    private const string Read = "companydata:read";
    private const string Definitions = "companydata:definitions";
    private const string Changes = "companydata:changes";
    private const string Webhook = "companydata:webhook";
    private const string Documents = "companydata:documents";

    /// <summary>id → "runnable". Every company-data scenario runs synchronously (data) or accumulates (webhook).</summary>
    private static readonly IReadOnlyList<string> ScenarioIds = new[]
    {
        Read, Definitions, Changes, Webhook, Documents,
    };

    /// <summary>Scenarios whose SDK Client uses the pump (needs a cache_dir for its buffer/dead-letters).</summary>
    private static readonly HashSet<string> PumpScenarios = new() { Changes, Webhook };

    private const string DefaultApiUrl = "https://api.allme.fyi";

    private readonly Runtime _rt;
    private readonly string _sdkVersion;

    public Server(Runtime rt, string sdkVersion)
    {
        _rt = rt;
        _sdkVersion = sdkVersion;
    }

    // ── GET /api/meta ──────────────────────────────────────────────────────────

    public Task Meta(HttpContext ctx) => WriteJson(ctx, new
    {
        sdk = Sdk,
        sdkVersion = _sdkVersion,
        contractVersion = ContractVersion,
        scenarios = ScenarioIds.Select(id => new { id, kind = "runnable" }),
    });

    // ── POST /api/scenarios/{id}/config ──────────────────────────────────────────

    /// <summary>
    /// Write the browser's setup values to a canonical SDK config FILE. Every company-data scenario uses
    /// the SERVICE-role Client, so the config always carries client_id/secret + the service PEM (by path)
    /// + passphrase. The webhook scenario adds the webhooks:{id:secret} map (the SDK selects the secret by
    /// the X-Allus-Webhook-Id header) and records the webhook id in a meta sidecar (the routing key /start
    /// needs). The documents scenario records the target share code in the sidecar.
    /// </summary>
    public async Task SaveConfig(HttpContext ctx, string id)
    {
        if (!IsScenario(id)) { await NotFound(ctx); return; }
        var body = await ReadBody(ctx);

        var cfg = new Dictionary<string, object?>
        {
            ["api_url"] = (Str(body, "apiUrl") is { Length: > 0 } a ? a : DefaultApiUrl).TrimEnd('/'),
            ["client_id"] = Str(body, "clientId") ?? "",
            ["client_secret"] = Str(body, "clientSecret") ?? "",
            ["key_passphrase"] = Str(body, "keyPassphrase") ?? "",
        };
        if (Str(body, "servicePrivateKeyPem") is { Length: > 0 } pem)
            cfg["service_private_key"] = _rt.MaterializeConfigKey(pem);

        // Pump scenarios persist their buffer/dead-letters under .runtime/cache (Config.cache_dir).
        if (PumpScenarios.Contains(id))
            cfg["cache_dir"] = _rt.CacheDir;

        var meta = new Dictionary<string, object?>();
        if (id == Webhook)
        {
            // The verifier selects the secret by the delivery's X-Allus-Webhook-Id header, so the config's
            // webhooks map must be keyed by the real webhook id.
            var webhookId = Str(body, "webhookId") ?? "";
            var secret = Str(body, "webhookSecret") ?? "";
            if (webhookId.Length > 0 && secret.Length > 0)
                cfg["webhooks"] = new Dictionary<string, string> { [webhookId] = secret };
            if (webhookId.Length > 0)
                meta["webhook_id"] = webhookId; // the routing key /start writes into the route record
        }
        if (id == Documents)
            meta["share_code"] = Str(body, "shareCode") ?? ""; // the per-person/contract target

        var configPath = _rt.WriteConfig(id, cfg);
        _rt.WriteConfigMeta(id, meta);

        await WriteJson(ctx, new { ok = true, configPath });
    }

    // ── POST /api/scenarios/{id}/start ────────────────────────────────────────────

    public async Task Start(HttpContext ctx, string id)
    {
        if (!IsScenario(id)) { await NotFound(ctx); return; }
        if (!_rt.HasConfig(id)) { await WriteJson(ctx, new { error = "not_configured" }, 409); return; }

        switch (id)
        {
            case Read: await DataRun(ctx, id, DoRead); return;
            case Definitions: await DataRun(ctx, id, DoDefinitions); return;
            case Changes: await DataRun(ctx, id, DoChanges); return;
            case Documents: await DataRun(ctx, id, DoDocuments); return;
            case Webhook: await StartWebhook(ctx); return;
        }
    }

    /// <summary>
    /// Run a synchronous data scenario: build the Client from the config file, run the SDK call, and store
    /// the terminal result. The immediate outcome is read once via GET /api/runs (action {type:"data"}).
    /// A start-time failure is a "failed" run — never a 200 without the success envelope.
    /// </summary>
    private async Task DataRun(HttpContext ctx, string id, Func<Client, List<string>, Task<object>> doAsync)
    {
        var runId = _rt.NewRunId();
        var calls = new List<string>();
        var run = new Run { Scenario = id, Calls = calls };
        try
        {
            var client = Client.FromConfig(_rt.ConfigPathFor(id));
            run.Result = await doAsync(client, calls);
            run.Status = "done";
        }
        catch (Exception e)
        {
            run.Status = "failed";
            run.Error = e.Message;
        }
        _rt.WriteRun(runId, run);
        await WriteJson(ctx, new { runId, action = new { type = "data" } });
    }

    /// <summary>
    /// companydata:read — Client.ConnectionsAsync() grouped BY connection (one card per connected person),
    /// so two people who both filled the same slug stay distinguishable.
    /// </summary>
    private async Task<object> DoRead(Client client, List<string> calls)
    {
        var connections = new List<object>();
        await foreach (var conn in client.ConnectionsAsync())
        {
            var values = new List<object>();
            foreach (var (slug, v) in conn.Values)
                values.Add(new
                {
                    slug,
                    value = StringifyValue(v.ValueObj),
                    live = v.Live,
                    at = Iso(v.UpdatedAt),
                });
            connections.Add(new
            {
                connectionId = conn.Id,
                personId = conn.PersonId,
                displayName = conn.DisplayName,
                customerType = conn.CustomerType,
                shareCode = conn.ShareCode,
                values,
            });
        }
        calls.Add("Client.ConnectionsAsync");
        return new { connections };
    }

    /// <summary>
    /// companydata:definitions — Client.RequestFieldsAsync() → your request-field catalog (the folded
    /// mandatory bool + one_time; the raw split flags are debug-only, off the intended surface).
    /// </summary>
    private async Task<object> DoDefinitions(Client client, List<string> calls)
    {
        var fields = new List<object>();
        foreach (var f in await client.RequestFieldsAsync())
            fields.Add(new
            {
                slug = f.Slug,
                label = f.Label,
                type = f.Type,
                mandatory = f.Mandatory,
                one_time = f.OneTime,
            });
        calls.Add("Client.RequestFieldsAsync");
        return new { fields };
    }

    /// <summary>
    /// companydata:changes — Client.ProcessChangesAsync() drains the feed on start through the crash-safe
    /// pump (handler-before-ack, at-least-once), so the append handler is idempotent on the pull-feed
    /// Change.Id. Each event is the rendered-column projection PLUS a raw object with the full public
    /// Change fields.
    /// </summary>
    private async Task<object> DoChanges(Client client, List<string> calls)
    {
        var events = new List<object?>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        await client.ProcessChangesAsync(change =>
        {
            if (change.Id is { } cid)
            {
                if (!seen.Add(cid)) return Task.CompletedTask; // idempotent: dedup replays on Change.Id
            }
            events.Add(ProjectChange(change, null));
            return Task.CompletedTask;
        });
        calls.Add("Client.ProcessChangesAsync");
        return new { events, drained = true };
    }

    /// <summary>
    /// companydata:documents — Client.CreateDocumentAsync() for each of the six document/contract types
    /// (payloads verbatim from apitests/php/documents.php). The per-person / private / contract types
    /// target the connected person by share code (from the setup sidecar).
    /// </summary>
    private async Task<object> DoDocuments(Client client, List<string> calls)
    {
        var shareCode = MetaStr(_rt.ReadConfigMeta(Documents), "share_code") ?? "";

        // (label, perPerson, factory) — the factory builds the exact CreateDocumentAsync call. A perPerson
        // spec has its share_code applied inside DoDocuments so the "target a connected person" rule is
        // visible in one place.
        var specs = new (string Label, bool PerPerson, Func<string?, Task<Document>> Create)[]
        {
            ("Broadcast plaintext JSON (no target)", false, _ => client.CreateDocumentAsync(
                name: "Service notice", payloadKind: "json",
                jsonValue: new Dictionary<string, object?> { ["msg"] = "Scheduled maintenance Sunday" })),

            ("Broadcast PDF file (no target)", false, _ => client.CreateDocumentAsync(
                name: "Price list", payloadKind: "file",
                fileBytes: MinimalPdf("Price list"), fileMime: "application/pdf")),

            ("Per-person NON-private file", true, sc => client.CreateDocumentAsync(
                name: "Your invoice", payloadKind: "file", shareCode: sc,
                fileBytes: MinimalPdf("Your invoice"), fileMime: "application/pdf")),

            ("Per-person PRIVATE file (lock → reveal)", true, sc => client.CreateDocumentAsync(
                name: "Confidential report", payloadKind: "file", isPrivate: true, shareCode: sc,
                fileBytes: MinimalPdf("Confidential report"), fileMime: "application/pdf")),

            ("CONTRACT requiring SIGNATURE", true, sc => client.CreateDocumentAsync(
                name: "Service agreement", kind: "agreement", payloadKind: "file", shareCode: sc,
                requiresSignature: true,
                fileBytes: MinimalPdf("Service agreement"), fileMime: "application/pdf",
                metadata: new Dictionary<string, object?> { ["can_be_cancelled_in_app"] = true })),

            ("CONTRACT requiring ACCEPTANCE", true, sc => client.CreateDocumentAsync(
                name: "Terms update", kind: "agreement", payloadKind: "json", shareCode: sc,
                requiresAcceptance: true,
                jsonValue: new Dictionary<string, object?> { ["version"] = "2.0" },
                metadata: new Dictionary<string, object?>
                {
                    ["plan_name"] = "Pro Plan",
                    ["price"] = "9.99",
                    ["currency"] = "EUR",
                    ["renewal_term"] = "Monthly",
                    ["renewal_date"] = "2026-07-30",
                    ["valid_until"] = "2027-06-30",
                    ["can_be_cancelled_in_app"] = true,
                    ["management_url"] = "https://example.com/manage",
                })),
        };

        var docs = new List<object>();
        for (var i = 0; i < specs.Length; i++)
        {
            var spec = specs[i];
            if (spec.PerPerson && shareCode.Length == 0)
                throw new InvalidOperationException(
                    "this document type targets a connected person — set a target person share code in the setup, then re-run");
            var doc = await spec.Create(spec.PerPerson ? shareCode : null);
            docs.Add(new { index = i + 1, label = spec.Label, document_id = doc.Id, status = doc.Status });
        }
        calls.Add($"Client.CreateDocumentAsync ×{specs.Length}");
        return new { docs };
    }

    // ── companydata:webhook — the accumulating run + public receiver ────────────

    /// <summary>
    /// Start the single accumulating webhook run. Persists the routing record webhookId → runId
    /// (superseding any prior active webhook run) and returns {action:{type:"none"}} — there is NO
    /// long-poll (it would wedge the single worker). Events arrive via POST /webhook and via a per-poll
    /// DrainBatchAsync() feed fallback; the frontend reads the growing list through GET /api/runs.
    /// </summary>
    private async Task StartWebhook(HttpContext ctx)
    {
        var webhookId = MetaStr(_rt.ReadConfigMeta(Webhook), "webhook_id") ?? "";
        if (webhookId.Length == 0) { await WriteJson(ctx, new { error = "not_configured" }, 409); return; }

        var runId = _rt.NewRunId();
        var run = new Run
        {
            Scenario = Webhook,
            Status = "pending", // accumulating — the v1 enum is unchanged
            WebhookId = webhookId,
            Events = new List<object?>(),
            SeenFeedIds = new List<string>(),
            Unparseable = 0,
            Calls = new List<string>
            {
                "(webhook run started — POST /webhook receives; each poll also DrainBatchAsync()s the feed)",
            },
        };
        _rt.WriteRun(runId, run);
        _rt.WriteRoute(webhookId, runId);
        await WriteJson(ctx, new { runId, action = new { type = "none" } });
    }

    /// <summary>
    /// POST /webhook — the PUBLIC inbound delivery. The exact call/status sequence (never the combined
    /// HandleWebhook(), which throws one WebhookException for BOTH a bad HMAC and a parse failure):
    ///   (1) read X-Allus-Webhook-Id; unknown/stale id or no active run → 200 acknowledge-and-discard.
    ///   (2) VerifyWebhook(): false → 401 (a genuine signature failure; misconfiguration should be loud).
    ///   (3) ParseWebhook(): success → append (source:"webhook") + 200; a WebhookException here is a
    ///       VERIFIED-but-unparseable delivery → 200 acknowledge-and-note (increment unparseable) — NOT
    ///       401, since the signature was valid.
    /// All accepted-and-dropped cases return 200 because the platform worker counts EXACTLY 200 as success.
    /// </summary>
    public async Task WebhookReceive(HttpContext ctx)
    {
        var rawBody = await ReadRawBody(ctx);
        var headers = RequestHeaders(ctx);
        var webhookId = Header(headers, "X-Allus-Webhook-Id");

        var route = _rt.ReadRoute();
        if (route is not { } r || webhookId is null || webhookId != r.WebhookId)
        {
            await WriteText(ctx, "discarded: unknown or stale webhook id", 200);
            return;
        }
        var run = _rt.ReadRun(r.RunId);
        if (run is null)
        {
            await WriteText(ctx, "discarded: no active webhook run", 200);
            return;
        }

        var client = Client.FromConfig(_rt.ConfigPathFor(Webhook));
        RecordCall(run, "Client.VerifyWebhook");
        if (!client.VerifyWebhook(rawBody, headers))
        {
            // A genuine signature failure — persist the attempted verify so the calls trace stays truthful.
            _rt.WriteRun(r.RunId, run);
            await WriteText(ctx, "signature verification failed", 401);
            return;
        }
        try
        {
            RecordCall(run, "Client.ParseWebhook");
            var change = client.ParseWebhook(rawBody, headers);
            (run.Events ??= new()).Add(ProjectChange(change, "webhook"));
        }
        catch (WebhookException e)
        {
            // Verified but unparseable/undecryptable — acknowledge (200) and note it in the raw view.
            run.Unparseable += 1;
            (run.Events ??= new()).Add(new Dictionary<string, object?>
            {
                ["source"] = "webhook",
                ["event"] = null,
                ["id"] = null,
                ["note"] = "received, could not parse",
                ["raw"] = new Dictionary<string, object?> { ["error"] = e.Message },
            });
        }
        _rt.WriteRun(r.RunId, run);
        await WriteText(ctx, "ok", 200);
    }

    // ── GET /api/runs/{runId} ────────────────────────────────────────────────────

    public async Task RunStatus(HttpContext ctx, string runId)
    {
        var run = _rt.ReadRun(runId);
        if (run is null) { await WriteJson(ctx, new { error = "not_found" }, 404); return; }

        if (run.Scenario == Webhook)
        {
            // The accumulating webhook run: each poll also does ONE immediate DrainBatchAsync() raw feed
            // fetch (NOT ProcessChangesAsync(), which loops the pump to empty and could stall the single
            // worker) so events generated AFTER start still appear in deployed-no-tunnel mode.
            run = await WebhookFeedFallback(runId, run);
            await WriteJson(ctx, new Dictionary<string, object?>
            {
                ["status"] = run.Status,
                ["calls"] = run.Calls,
                ["result"] = new Dictionary<string, object?>
                {
                    ["webhookId"] = run.WebhookId ?? "",
                    ["events"] = run.Events ?? new List<object?>(),
                    ["unparseable"] = run.Unparseable,
                },
            });
            return;
        }

        var outObj = new Dictionary<string, object?> { ["status"] = run.Status, ["calls"] = run.Calls };
        if (run.Result is not null) outObj["result"] = run.Result;
        if (run.Error is not null) outObj["error"] = run.Error;
        await WriteJson(ctx, outObj);
    }

    /// <summary>
    /// One immediate DrainBatchAsync() fetch per poll for the active webhook run, appending new
    /// source:"feed" events deduped on the pull-feed Change.Id (a feed-only seen-id set in run state).
    /// Only the CURRENT active run pulls (a superseded run stops receiving). A transport/API error is
    /// swallowed so a blackholed feed never fails the accumulating run — the webhook path still works.
    /// </summary>
    private async Task<Run> WebhookFeedFallback(string runId, Run run)
    {
        var route = _rt.ReadRoute();
        if (route is not { } r || r.RunId != runId) return run; // superseded/cleared — this run no longer pulls

        var seen = new HashSet<string>(run.SeenFeedIds ?? new List<string>(), StringComparer.Ordinal);
        try
        {
            var client = Client.FromConfig(_rt.ConfigPathFor(Webhook));
            // Every poll ATTEMPTS the feed pull — record the call now (deduped), so an empty poll still
            // reports the DrainBatchAsync it performed rather than claiming no call.
            var drainNew = RecordCall(run, "Client.DrainBatchAsync");
            var appended = false;
            foreach (var change in await client.DrainBatchAsync())
            {
                if (change.Id is { } cid)
                {
                    if (!seen.Add(cid)) continue;
                    (run.SeenFeedIds ??= new()).Add(cid);
                }
                (run.Events ??= new()).Add(ProjectChange(change, "feed"));
                appended = true;
            }
            if (appended || drainNew) _rt.WriteRun(runId, run);
        }
        catch (Exception)
        {
            // A blackholed/failed feed fetch must not fail the accumulating webhook run.
        }
        return run;
    }

    /// <summary>
    /// Append an SDK-call name to a run's "what just happened" trace, deduped. Returns true when the name
    /// was newly added (so the caller can persist on that transition).
    /// </summary>
    private static bool RecordCall(Run run, string name)
    {
        if (run.Calls.Contains(name)) return false;
        run.Calls.Add(name);
        return true;
    }

    // ── Change projection ──────────────────────────────────────────────────────

    /// <summary>
    /// The rendered-column projection of a Change PLUS a raw object holding the full public Change fields,
    /// so the frontend's JSON.stringify(result) Raw view can show the event-specific extras. Nothing is
    /// dropped from result. <paramref name="source"/> labels a webhook delivery vs a pull-feed row (null
    /// for the changes scenario, where every row is a pull-feed drain).
    /// </summary>
    private object ProjectChange(Change c, string? source)
    {
        var ev = new Dictionary<string, object?>();
        if (source is not null) ev["source"] = source;
        ev["event"] = c.Event;
        ev["personId"] = c.PersonId;
        ev["shareCode"] = c.ShareCode;
        ev["customerType"] = c.CustomerType;
        ev["slug"] = c.Slug;
        ev["value"] = StringifyValue(c.ValueObj);
        ev["live"] = c.Live;
        ev["at"] = Iso(c.At);
        ev["documentId"] = c.DocumentId;
        ev["status"] = c.Status;
        ev["action"] = c.Action;
        ev["id"] = c.Id;
        ev["raw"] = new Dictionary<string, object?>
        {
            ["id"] = c.Id,
            ["event"] = c.Event,
            ["personId"] = c.PersonId,
            ["shareCode"] = c.ShareCode,
            ["customerType"] = c.CustomerType,
            ["slug"] = c.Slug,
            ["value"] = StringifyValue(c.ValueObj),
            ["live"] = c.Live,
            ["documentId"] = c.DocumentId,
            ["status"] = c.Status,
            ["action"] = c.Action,
            ["note"] = c.Note,
            ["method"] = c.Method,
            ["contentSha256"] = c.ContentSha256,
            ["signedAt"] = c.SignedAt,
            ["cancelEffectiveDate"] = c.CancelEffectiveDate,
            ["requestId"] = c.RequestId,
            ["publicKeySha256"] = c.PublicKeySha256,
            ["verified"] = c.Verified,
            ["at"] = Iso(c.At),
        };
        return ev;
    }

    /// <summary>
    /// Render a decrypted value for JSON. A binary value is a lazy <see cref="BinaryHandle"/> — resolve it
    /// to a short descriptor rather than dumping raw bytes; a date/datetime becomes an ISO string; a
    /// structured value (dictionary/list) passes through for the frontend to JSON-stringify.
    /// </summary>
    private static object? StringifyValue(object? v) => v switch
    {
        null or bool or string => v,
        sbyte or byte or short or ushort or int or uint or long or ulong or float or double or decimal => v,
        DateOnly d => d.ToString("yyyy-MM-dd"),
        DateTimeOffset dt => Iso(dt),
        DateTime dt => dt.ToString("yyyy-MM-ddTHH:mm:sszzz"),
        BinaryHandle bh => BinaryDescriptor(bh),
        _ => v, // dictionaries / lists (structured values) — serialized as-is
    };

    private static string BinaryDescriptor(BinaryHandle bh)
    {
        try { return $"[binary {bh.BytesAsync().GetAwaiter().GetResult().Length} bytes]"; }
        catch (Exception) { return "[binary value]"; }
    }

    private static string? Iso(DateTimeOffset? dt) => dt?.ToString("yyyy-MM-ddTHH:mm:sszzz");

    // ── minimal PDF (verbatim shape from apitests/php/documents.php) ─────────────

    /// <summary>A tiny valid one-page PDF carrying <paramref name="label"/> — so the broadcast/per-person/
    /// contract file docs upload real bytes without a fixture file.</summary>
    private static byte[] MinimalPdf(string label)
    {
        var stream = "BT /F1 18 Tf 40 90 Td (" + label.Replace("(", "[").Replace(")", "]") + ") Tj ET";
        var objs = new (int N, string Body)[]
        {
            (1, "<< /Type /Catalog /Pages 2 0 R >>"),
            (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
            (3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 420 160] "
                + "/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"),
            (4, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"),
            (5, "<< /Length " + Encoding.UTF8.GetByteCount(stream) + " >>\nstream\n" + stream + "\nendstream"),
        };
        var sb = new StringBuilder("%PDF-1.4\n");
        var offsets = new Dictionary<int, int>();
        foreach (var (n, body) in objs)
        {
            offsets[n] = Encoding.UTF8.GetByteCount(sb.ToString());
            sb.Append($"{n} 0 obj\n{body}\nendobj\n");
        }
        var xrefPos = Encoding.UTF8.GetByteCount(sb.ToString());
        sb.Append("xref\n0 ").Append(objs.Length + 1).Append("\n0000000000 65535 f \n");
        foreach (var (n, _) in objs)
            sb.Append(offsets[n].ToString("D10")).Append(" 00000 n \n");
        sb.Append("trailer\n<< /Size ").Append(objs.Length + 1)
          .Append(" /Root 1 0 R >>\nstartxref\n").Append(xrefPos).Append("\n%%EOF");
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    // ── input / config plumbing ────────────────────────────────────────────────────

    private static bool IsScenario(string id) => ScenarioIds.Contains(id);

    private static async Task<JsonElement> ReadBody(HttpContext ctx)
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

    private static async Task<string> ReadRawBody(HttpContext ctx)
    {
        using var reader = new StreamReader(ctx.Request.Body);
        return await reader.ReadToEndAsync();
    }

    /// <summary>Request headers as a name → value map (for the SDK webhook verify/parse, which look them up
    /// case-insensitively).</summary>
    private static IReadOnlyDictionary<string, string> RequestHeaders(HttpContext ctx)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (k, v) in ctx.Request.Headers)
            map[k] = v.ToString();
        return map;
    }

    private static string? Header(IReadOnlyDictionary<string, string> headers, string name) =>
        headers.TryGetValue(name, out var v) ? v : null;

    private static JsonElement EmptyObject()
    {
        using var doc = JsonDocument.Parse("{}");
        return doc.RootElement.Clone();
    }

    private static string? Str(JsonElement obj, string name) =>
        obj.ValueKind == JsonValueKind.Object && obj.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String
            ? p.GetString()
            : null;

    private static string? MetaStr(JsonElement meta, string name) => Str(meta, name);

    // ── HTTP plumbing ──────────────────────────────────────────────────────────────

    private static Task NotFound(HttpContext ctx) => WriteJson(ctx, new { error = "not_found" }, 404);

    private static async Task WriteJson(HttpContext ctx, object data, int status = 200)
    {
        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = "application/json";
        await ctx.Response.WriteAsync(JsonSerializer.Serialize(data));
    }

    private static async Task WriteText(HttpContext ctx, string body, int status = 200)
    {
        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = "text/plain; charset=utf-8";
        await ctx.Response.WriteAsync(body);
    }
}
