using System.Text.Json;
using Allus.CompanyData;
using Microsoft.AspNetCore.Http;

namespace Allus.ExampleTestSuite.Flow;

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
/// One demo run's cross-request state, serialized to <c>.runtime/runs/{runId}.json</c> by the shared
/// <see cref="Runtime"/>. There is NO separate browser-visible platform flow-run id: the platform run
/// lives entirely inside this file (<see cref="FlowRunId"/>), and the demo runId IS the backend run
/// (contract, flow family). The GET /api/runs poll is both the drive loop and the resume; a terminal run
/// (<see cref="Completed"/> or <see cref="Error"/>) is returned unchanged on every subsequent poll.
/// </summary>
public sealed class Run : IRun
{
    public string RunId { get; set; } = "";
    public string Scenario { get; set; } = "flow:run"; // the public scenario id (for clear/dispatch)
    public string? FlowRunId { get; set; }             // the platform flow-run id, stored INSIDE this run

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
/// The flow family's ONE scenario handler (contract v3, flow family). HTTP dispatch → handler → the SDK's
/// intended top-level flow surface only (IdentityAsync / TriggerFlowRunAsync / FlowRunAsync /
/// ProcessFlowRunAsync / FlowRunAnswers / FlowRunDocumentAsync). Handlers NEVER perform raw platform HTTP.
///
/// Single scenario "flow:run". There is NO cross-card flow-run-id handoff: the platform flow run lives
/// entirely INSIDE this one demo run's file — the demo runId is the backend run and the platform
/// flowRunId is stored inside it, never exposed as a separate browser input.
///
/// Settings flow: the browser POSTs the scenario's setup values to POST /api/scenarios/{id}/config,
/// which writes them to a canonical SDK config FILE (.runtime/config/flow_run.json; the service PEM →
/// .runtime/config/keys/ by path). /start builds the service <see cref="Client"/> from that file via
/// <see cref="Client.FromConfig"/> (Config.FromFile) and runs OFF the config — exactly as a real
/// integrator wires the SDK. The request body of /start is ignored; a /start with no saved config → 409.
///
/// The GET /api/runs/{runId} poll is the drive loop AND the resume: each poll reads the platform run
/// and, if it is the company's turn, drives exactly ONE company step; otherwise it reports
/// waiting/running and touches nothing (the next poll after the person answers on their phone resumes).
/// </summary>
public sealed class FlowHandlers
{
    /// <summary>The single public scenario id (the flow family). Also the config/run store key.</summary>
    private const string ScenarioId = "flow:run";

    private const string DefaultApiUrl = "https://api.allme.fyi";

    /// <summary>The flow party keys the fixtures pin.</summary>
    private const string PartyCompany = "company";
    private const string PartyCustomer = "customer";

    /// <summary>The canned INVALID value the validation-demo submits once for an email field.</summary>
    private const string InvalidEmail = "not-an-email";

    private readonly Runtime _rt;

    public FlowHandlers(Runtime rt) => _rt = rt;

    private static bool IsKnownScenario(string id) => id == ScenarioId;

    /// <summary>The flow scenario for GET /api/meta.</summary>
    public IEnumerable<object> ScenarioList() =>
        new[] { (object)new { id = ScenarioId, kind = "runnable" } };

    // ── POST /api/scenarios/{id}/config ──────────────────────────────────────────

    /// <summary>
    /// Write the browser's setup values to a canonical SDK config FILE (service role). The service PEM
    /// is written to config/keys/ and referenced by path; the demo-only run parameters (published flow
    /// id, connection id, fixture choice) go to the meta sidecar so the config file stays a pure SDK
    /// config the run executes off.
    /// </summary>
    public async Task SaveConfig(HttpContext ctx, string id)
    {
        if (!IsKnownScenario(id)) { await Web.NotFound(ctx); return; }
        var body = await Web.ReadBody(ctx);

        // Canonical SDK config — the service role (client_credentials + service PEM).
        var cfg = new Dictionary<string, object?>
        {
            ["api_url"] = (Web.Str(body, "apiUrl") is { Length: > 0 } a ? a : DefaultApiUrl).TrimEnd('/'),
            ["client_id"] = Web.Str(body, "clientId") ?? "",
            ["client_secret"] = Web.Str(body, "clientSecret") ?? "",
            ["key_passphrase"] = Web.Str(body, "keyPassphrase") ?? "",
        };
        if (Web.Str(body, "servicePrivateKeyPem") is { Length: > 0 } pem)
            cfg["service_private_key"] = _rt.MaterializeConfigKey(pem);

        var configPath = _rt.WriteConfig(ScenarioId, cfg);

        // Demo-only run parameters (NOT SDK Config fields) → meta sidecar.
        _rt.WriteConfigMeta(ScenarioId, new Dictionary<string, object?>
        {
            ["flow_id"] = Web.Str(body, "flowId") ?? "",
            ["connection_id"] = Web.Str(body, "connectionId") ?? "",
            ["fixture"] = Web.Str(body, "fixture") ?? "",
        });

        await Web.WriteJson(ctx, new { ok = true, configPath });
    }

    // ── POST /api/scenarios/{id}/start ────────────────────────────────────────────

    /// <summary>
    /// Trigger the flow run. Build the service Client from the persisted config file, construct the
    /// bindings via the intended SDK surface (company → IdentityAsync().CompanyUserId; customer →
    /// Connection.PersonId), call TriggerFlowRunAsync, and store the returned platform flowRunId in the
    /// demo run file. Returns {runId, action:{"type":"none"}} — the drive happens on the GET /api/runs poll.
    /// </summary>
    public async Task Start(HttpContext ctx, string id)
    {
        if (!IsKnownScenario(id)) { await Web.NotFound(ctx); return; }
        if (!_rt.HasConfig(ScenarioId))
        {
            // The run is built from the persisted config file, not the request body.
            await Web.WriteJson(ctx, new { error = "not_configured" }, 409);
            return;
        }
        var meta = _rt.ReadConfigMeta(ScenarioId);
        var flowId = Web.Str(meta, "flow_id") ?? "";
        var connectionId = Web.Str(meta, "connection_id") ?? "";
        if (flowId.Length == 0 || connectionId.Length == 0)
        {
            await Web.WriteJson(ctx, new { error = "not_configured", message = "flow id and connection id are required" }, 409);
            return;
        }

        var calls = new List<string>();
        string flowRunId;
        try
        {
            var client = ServiceClient();

            // The COMPANY party binds to this service's own company_user_id (IdentityAsync).
            var identity = await client.IdentityAsync();
            calls.Add("Client.IdentityAsync");
            var companyUserId = identity.CompanyUserId ?? "";
            if (companyUserId.Length == 0)
            {
                await Web.WriteJson(ctx, new { error = "identity_error", message = "IdentityAsync returned no company_user_id" }, 502);
                return;
            }

            // The CUSTOMER party binds to the connected person's public personId (no public user_id).
            var connection = await client.ConnectionAsync(connectionId);
            calls.Add("Client.ConnectionAsync");
            var personId = connection.PersonId;
            if (string.IsNullOrEmpty(personId))
            {
                await Web.WriteJson(ctx, new
                {
                    error = "connection_error",
                    message = $"connection {connectionId} has no personId (not found or not connected)",
                }, 502);
                return;
            }

            var bindings = new Dictionary<string, string>
            {
                [PartyCompany] = companyUserId,
                [PartyCustomer] = personId,
            };
            var flowRun = await client.TriggerFlowRunAsync(flowId, connectionId, bindings);
            calls.Add("Client.TriggerFlowRunAsync");

            flowRunId = flowRun.Id ?? "";
            if (flowRunId.Length == 0)
            {
                await Web.WriteJson(ctx, new { error = "trigger_error", message = "TriggerFlowRunAsync returned no run id" }, 502);
                return;
            }
        }
        catch (Exception e) when (e is ApiException or ConfigException)
        {
            await Web.WriteJson(ctx, new { error = "start_failed", message = e.Message }, 502);
            return;
        }

        var runId = _rt.NewRunId();
        _rt.WriteRun(runId, new Run
        {
            Scenario = ScenarioId,
            FlowRunId = flowRunId,
            Calls = calls,
        });

        await Web.WriteJson(ctx, new { runId, action = new { type = "none" } });
    }

    // ── GET /api/runs/{runId} ──────────────────────────────────────────────────────

    /// <summary>
    /// The idempotent, short-cycled poll that IS the drive loop and the resume. Reads the platform run;
    /// if it is the company's turn drives exactly ONE step; on completion fetches the answers and
    /// (document-mode) downloads the generated contract. A terminal run returns its cached result on
    /// every poll until TTL/Clear.
    /// </summary>
    public async Task RunStatus(HttpContext ctx, string runId)
    {
        var run = _rt.ReadRun<Run>(runId);
        if (run is null) { await Web.WriteJson(ctx, new { error = "not_found" }, 404); return; }

        // Idempotent: once terminal (completed OR errored) the outcome is returned unchanged on every
        // subsequent poll — a failed run must stay failed, not re-drive the platform.
        var terminal = run.Completed || run.Error is not null;
        if (!terminal)
        {
            run = await Advance(run);
            _rt.WriteRun(runId, run);
        }

        await Web.WriteJson(ctx, Result(run));
    }

    /// <summary>One poll's worth of work. Returns the (possibly mutated) run.</summary>
    private async Task<Run> Advance(Run run)
    {
        var flowRunId = run.FlowRunId ?? "";
        if (flowRunId.Length == 0)
        {
            run.Error = "run has no platform flowRunId";
            return run;
        }

        try
        {
            var client = ServiceClient();
            var flowRun = await client.FlowRunAsync(flowRunId);
            AddCall(run, "Client.FlowRunAsync");

            var status = flowRun.Status ?? "";
            var companyParty = flowRun.CompanyPartyKey;
            var companyTurn = companyParty is not null && status == $"awaiting_{companyParty}";

            if (status == "completed")
                return await Complete(run, client, flowRun, flowRunId);
            if (companyTurn)
                return await DriveStep(run, client, flowRun, flowRunId);
            if (status.StartsWith("awaiting_", StringComparison.Ordinal))
            {
                // The person's turn (or the phone signature) — wait; the next poll resumes automatically.
                run.Status = "waiting_person";
                return run;
            }
            // Any transient in-between state (e.g. generating) — keep polling.
            run.Status = "running";
            return run;
        }
        catch (Exception e) when (e is ApiException or ConfigException)
        {
            run.Error = e.Message;
            return run;
        }
    }

    /// <summary>
    /// Drive ONE company step via ProcessFlowRunAsync. The validation demo: for an email field whose
    /// node has not yet been rejected once, fillNode returns the canned INVALID value, which
    /// ProcessFlowRunAsync rejects with a <see cref="ValidationException"/> BEFORE any submit — recorded
    /// as accepted:false without advancing. The next poll (node marked rejected) fills the VALID value →
    /// advances → accepted:true.
    /// </summary>
    private async Task<Run> DriveStep(Run run, Client client, FlowRun flowRun, string flowRunId)
    {
        var nodeKey = flowRun.CurrentNode ?? "";
        var rejectedNodes = run.RejectedNodes;

        var filled = new List<FlowStep>();
        IReadOnlyDictionary<string, object?>? FillNode(Node node, IReadOnlyDictionary<string, object?> answers)
        {
            var nk = node.Get("key").AsString() ?? "";
            var fill = new Dictionary<string, object?>();
            foreach (var el in node.Get("elements").AsList())
            {
                if (el.Get("kind").AsString() != "field") continue;
                var slug = el.Get("slug").AsString();
                if (string.IsNullOrEmpty(slug)) continue;
                var ftype = el.Get("field_type").AsString() ?? "text";
                var rejectDemo = ftype == "email" && !rejectedNodes.Contains(nk);
                var value = rejectDemo ? InvalidEmail : CannedValue(ftype);
                fill[slug] = value;
                filled.Add(new FlowStep { Slug = slug, Type = ftype, Submitted = value });
            }
            return fill;
        }

        try
        {
            await client.ProcessFlowRunAsync(flowRunId, FillNode);
            AddCall(run, "Client.ProcessFlowRunAsync");
            // Advanced: every field filled for this node was accepted.
            foreach (var f in filled)
            {
                f.Accepted = true;
                run.Steps.Add(f);
            }
            run.Status = "running";
            return run;
        }
        catch (ValidationException e)
        {
            // The canned invalid value was rejected BEFORE submit — record it and mark the node so the
            // next poll submits the valid value. The node did NOT advance.
            AddCall(run, "Client.ProcessFlowRunAsync");
            var submitted = InvalidEmail;
            foreach (var f in filled)
                if (f.Slug == e.Slug) { submitted = f.Submitted; break; }
            run.Steps.Add(new FlowStep
            {
                Slug = e.Slug,
                Type = string.IsNullOrEmpty(e.FieldType) ? "email" : e.FieldType,
                Submitted = submitted,
                Accepted = false,
                Error = e.Message,
            });
            if (nodeKey.Length > 0 && !rejectedNodes.Contains(nodeKey))
                rejectedNodes.Add(nodeKey);
            run.Status = "running";
            return run;
        }
    }

    /// <summary>
    /// Terminal: fetch the decrypted answers and, for a document-mode run, download the generated
    /// contract's company copy (FlowRunDocumentAsync — the run-scoped, service-key-decryptable surface).
    /// </summary>
    private async Task<Run> Complete(Run run, Client client, FlowRun flowRun, string flowRunId)
    {
        var answers = client.FlowRunAnswers(flowRun);
        AddCall(run, "Client.FlowRunAnswers");
        run.Answers = answers
            .Select(kv => new Dictionary<string, object?> { ["slug"] = kv.Key, ["value"] = kv.Value })
            .ToList();

        if (flowRun.OutputMode == "document")
        {
            try
            {
                var bytes = await client.FlowRunDocumentAsync(flowRunId);
                AddCall(run, "Client.FlowRunDocumentAsync");
                run.Document = new Dictionary<string, object?>
                {
                    ["status"] = "downloaded", ["downloaded"] = true, ["bytes"] = bytes.Length,
                };
            }
            catch (ApiException e)
            {
                // The run completed but the document is not retrievable yet — report it, don't fail.
                run.Document = new Dictionary<string, object?>
                {
                    ["status"] = "unavailable", ["downloaded"] = false, ["error"] = e.Message,
                };
            }
        }

        run.Status = "completed";
        run.Completed = true;
        return run;
    }

    /// <summary>
    /// The GET /api/runs/{runId} response: the SHARED run envelope (outer
    /// {status:"pending"|"done"|"failed", result?, error?, calls}) with the pinned FLOW shape nested
    /// under `result` ({status:"running"|"waiting_person"|"completed", steps, answers?, document?}). The
    /// shared frontend reads progress ONLY from `run.result` and keeps polling ONLY while the outer
    /// status is "pending", so the inner flow status must NOT sit at the top level — it drives under
    /// "pending" until the platform run completes ("done") or errors ("failed").
    /// </summary>
    private static object Result(Run run)
    {
        var flowStatus = run.Status;
        var outer = run.Error is not null ? "failed" : (flowStatus == "completed" ? "done" : "pending");

        var steps = run.Steps.Select(s =>
        {
            var d = new Dictionary<string, object?>
            {
                ["slug"] = s.Slug, ["type"] = s.Type, ["submitted"] = s.Submitted, ["accepted"] = s.Accepted,
            };
            if (s.Error is not null) d["error"] = s.Error;
            return d;
        }).ToList();

        var result = new Dictionary<string, object?> { ["status"] = flowStatus, ["steps"] = steps };
        if (run.Answers is not null) result["answers"] = run.Answers;
        if (run.Document is not null) result["document"] = run.Document;

        var outMap = new Dictionary<string, object?>
        {
            ["status"] = outer, ["result"] = result, ["calls"] = run.Calls,
        };
        if (run.Error is not null) outMap["error"] = run.Error;
        return outMap;
    }

    // ── SDK client builder — built from the persisted config FILE ──────────────────

    /// <summary>Build the service data client OFF the scenario's config file (service role, Config.FromFile).</summary>
    private Client ServiceClient() => Client.FromConfig(_rt.ConfigPathFor(ScenarioId));

    /// <summary>
    /// A canned VALID plaintext for a field type (demo values over already-supported answerable types).
    /// An unknown / text type accepts anything.
    /// </summary>
    private static string CannedValue(string ftype) => ftype switch
    {
        "email" => "billing@acme.example",
        "number" => "42",
        "boolean" => "true",
        "date" => "2024-01-15",
        "date_of_birth" => "1990-05-01",
        "phone" => "+31201234567",
        "url" => "https://acme.example",
        "address" => JsonSerializer.Serialize(new
        {
            street = "Herengracht 1", city = "Amsterdam", postal_code = "1011AB", country = "NL",
        }),
        _ => "Acme Corporation",
    };

    /// <summary>Append a call name preserving first-occurrence order (a poll may repeat flowRun across polls).</summary>
    private static void AddCall(Run run, string name)
    {
        if (!run.Calls.Contains(name)) run.Calls.Add(name);
    }
}
