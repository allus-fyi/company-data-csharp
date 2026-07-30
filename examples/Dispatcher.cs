using Allus.ExampleTestSuite.CompanyData;
using Allus.ExampleTestSuite.Flow;
using Allus.ExampleTestSuite.Identity;
using Microsoft.AspNetCore.Http;

namespace Allus.ExampleTestSuite;

/// <summary>
/// The single server's request router. It owns the three families' handler objects and dispatches every
/// contract request to the family that owns the scenario id — integer ids (1–8) → identity, "flow:*" →
/// flow, "companydata:*" → company-data. GET /api/runs/{id} is routed by the scenario id recorded in the
/// run file (so a run resolves to its owning family without the browser re-stating it).
///
/// This is scaffolding: it maps ids to handlers and merges the meta list. The SDK calls live entirely in
/// the per-family handler classes.
/// </summary>
public sealed class Dispatcher
{
    public const int ContractVersion = 3; // the single backend implements contract v3
    public const string Sdk = "csharp";

    private enum Family { Identity, Flow, CompanyData }

    private readonly Runtime _rt;
    private readonly string _sdkVersion;
    private readonly IdentityHandlers _identity;
    private readonly FlowHandlers _flow;
    private readonly CompanyDataHandlers _companyData;

    /// <summary>Every known scenario id (guards /clear against unknown ids).</summary>
    private static readonly HashSet<string> KnownScenarios = new(StringComparer.Ordinal)
    {
        "1", "2", "3", "4", "5", "6", "7", "8",
        "flow:run",
        "companydata:read", "companydata:definitions", "companydata:changes",
        "companydata:webhook", "companydata:documents",
    };

    public Dispatcher(Runtime rt, string sdkVersion)
    {
        _rt = rt;
        _sdkVersion = sdkVersion;
        _identity = new IdentityHandlers(rt);
        _flow = new FlowHandlers(rt);
        _companyData = new CompanyDataHandlers(rt);
    }

    // ── GET /api/meta — ALL scenarios of ALL families, contractVersion 3 ─────────

    public Task Meta(HttpContext ctx) => Web.WriteJson(ctx, new
    {
        sdk = Sdk,
        sdkVersion = _sdkVersion,
        contractVersion = ContractVersion,
        scenarios = _identity.ScenarioList()
            .Concat(_flow.ScenarioList())
            .Concat(_companyData.ScenarioList()),
    });

    // ── scenario endpoints — routed by family ────────────────────────────────────

    public Task SaveConfig(HttpContext ctx, string id) => FamilyOf(id) switch
    {
        Family.Identity => _identity.SaveConfig(ctx, int.Parse(id)),
        Family.Flow => _flow.SaveConfig(ctx, id),
        Family.CompanyData => _companyData.SaveConfig(ctx, id),
        _ => Web.NotFound(ctx),
    };

    public Task Start(HttpContext ctx, string id) => FamilyOf(id) switch
    {
        Family.Identity => _identity.Start(ctx, int.Parse(id)),
        Family.Flow => _flow.Start(ctx, id),
        Family.CompanyData => _companyData.Start(ctx, id),
        _ => Web.NotFound(ctx),
    };

    /// <summary>POST /api/scenarios/{id}/enroll — identity scenario 8 only.</summary>
    public Task Enroll(HttpContext ctx, string id) =>
        FamilyOf(id) == Family.Identity ? _identity.Enroll(ctx, int.Parse(id)) : Web.NotFound(ctx);

    /// <summary>POST /api/scenarios/{id}/clear — family-agnostic (the store clears by scenario id).</summary>
    public async Task ClearScenario(HttpContext ctx, string id)
    {
        if (!KnownScenarios.Contains(id)) { await Web.NotFound(ctx); return; }
        _rt.ClearScenario(id);
        await Web.WriteOk(ctx);
    }

    public async Task ClearAll(HttpContext ctx)
    {
        _rt.ClearAll();
        await Web.WriteOk(ctx);
    }

    // ── the setup snapshot (POST/GET /api/state) ─────────────────────────────────

    /// <summary>POST /api/state — the setup snapshot, stored verbatim; its bytes are never inspected.</summary>
    public async Task SaveState(HttpContext ctx)
    {
        _rt.WriteState(await Web.ReadRawBodyBytes(ctx));
        await Web.WriteOk(ctx);
    }

    /// <summary>GET /api/state — handed back exactly as stored; no snapshot file → 404 not_found.</summary>
    public Task RestoreState(HttpContext ctx)
    {
        var blob = _rt.ReadState();
        return blob is null ? Web.NotFound(ctx) : Web.WriteRawJson(ctx, blob);
    }

    // ── GET /api/runs/{runId} — routed by the run's recorded scenario ────────────

    public Task RunStatus(HttpContext ctx, string runId)
    {
        var scenarioId = _rt.ReadRunScenarioId(runId);
        return (scenarioId is null ? (Family?)null : FamilyOf(scenarioId)) switch
        {
            Family.Identity => _identity.RunStatus(ctx, runId),
            Family.Flow => _flow.RunStatus(ctx, runId),
            Family.CompanyData => _companyData.RunStatus(ctx, runId),
            _ => Web.WriteJson(ctx, new { error = "not_found" }, 404),
        };
    }

    // ── public per-family endpoints ──────────────────────────────────────────────

    /// <summary>GET /callback — identity OAuth/OIDC redirect leg.</summary>
    public Task Callback(HttpContext ctx) => _identity.Callback(ctx);

    /// <summary>POST /webhook — company-data public inbound delivery.</summary>
    public Task Webhook(HttpContext ctx) => _companyData.WebhookReceive(ctx);

    // ── id → family ──────────────────────────────────────────────────────────────

    private static Family? FamilyOf(string scenarioId)
    {
        if (int.TryParse(scenarioId, out _)) return Family.Identity;
        if (scenarioId.StartsWith("flow:", StringComparison.Ordinal)) return Family.Flow;
        if (scenarioId.StartsWith("companydata:", StringComparison.Ordinal)) return Family.CompanyData;
        return null;
    }
}
