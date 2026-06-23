// Company-side contract-flow run methods — fully mocked (no live API). Mirrors the Python/TS/Go
// run-method tests: trigger/list/get, decrypt-only-company, per-party fan-out + local routing,
// generate one-time-key shape, and the ProcessFlowRun company-leaf document chain.

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Allus.CompanyData;
using Xunit;

namespace Allus.CompanyData.Tests;

public sealed class FlowRunTests : IDisposable
{
    private const string CompanyUid = "company-1";
    private const string PersonUid = "person-1";

    private readonly string _dir;
    private readonly Config _config;

    public FlowRunTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "allus-flow-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var pem = Path.Combine(_dir, "service-key.pem");
        File.WriteAllText(pem, Vector.EncryptedPem);
        _config = new Config
        {
            ApiUrl = "https://api.allme.fyi",
            ClientId = "svc_abc",
            ClientSecret = "topsecret",
            ServicePrivateKey = pem,
            KeyPassphrase = Vector.Passphrase,
            CacheDir = Path.Combine(_dir, "cache"),
        };
    }

    public void Dispose() => Directory.Delete(_dir, true);

    private Client MakeRwClient(
        Func<string, IReadOnlyDictionary<string, string>?, HttpResult> getRouter,
        Func<string, string, byte[]?, HttpResult> writeRouter)
        => new(_config, http: new ApiHttp(_config, transport: new RouterTransport(getRouter, writeRouter)));

    private static HttpResult NoGet(string url, IReadOnlyDictionary<string, string>? q)
        => throw new Xunit.Sdk.XunitException("unexpected GET " + url);

    private static string VectorPubSpkiB64()
    {
        using var key = Vector.PrivateKey();
        return Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());
    }

    private static JsonElement ParseBody(byte[]? body)
    {
        using var doc = JsonDocument.Parse(Encoding.UTF8.GetString(body!));
        return doc.RootElement.Clone();
    }

    private const string FlowDefJson = """
    {
      "output_mode": "data_only",
      "parties": [{"key":"company"},{"key":"person"}],
      "nodes": [
        {"key":"n1","party":"company"},
        {"key":"n2","party":"person"},
        {"key":"n_end","party":"person"}
      ],
      "edges": [
        {"from":"n1","to":"n_end","sort":0,"condition":{"field":"tier","op":"eq","value":"vip"}},
        {"from":"n1","to":"n2","sort":1,"condition":null}
      ]
    }
    """;

    private static object RunObj(string status = "awaiting_company", string current = "n1",
        object? answers = null, string? defJson = null, string outputMode = "data_only", string? documentId = null)
    {
        using var def = JsonDocument.Parse(defJson ?? FlowDefJson);
        return new
        {
            id = "run-1",
            flow_id = "flow-1",
            flow_version = 3,
            service_id = "svc-1",
            connection_id = "csc-1",
            company_user_id = CompanyUid,
            bindings = new Dictionary<string, string> { ["company"] = CompanyUid, ["person"] = PersonUid },
            status,
            current_node = current,
            document_id = documentId,
            output_mode = outputMode,
            definition = JsonSerializer.Deserialize<object>(def.RootElement.GetRawText()),
            answers = answers ?? new object[0],
            created_at = (string?)null,
            updated_at = (string?)null,
        };
    }

    private static FlowRun RunFromObj(object o)
        => FlowRun.FromApi(Node.FromJsonString(JsonSerializer.Serialize(o)));

    // ── trigger / list / get ──────────────────────────────────────────────────────

    [Fact]
    public async Task TriggerFlowRun()
    {
        JsonElement captured = default;
        string capturedUrl = "";
        var client = MakeRwClient(NoGet, (method, url, body) =>
        {
            capturedUrl = url;
            captured = ParseBody(body);
            return Resp.Json(201, RunObj());
        });
        using (client)
        {
            var run = await client.TriggerFlowRunAsync("flow-1", "csc-1",
                new Dictionary<string, string> { ["company"] = CompanyUid, ["person"] = PersonUid });
            Assert.EndsWith("/company-data/flows/flow-1/runs", capturedUrl);
            Assert.Equal("csc-1", captured.GetProperty("target").GetProperty("connection_id").GetString());
            Assert.Equal("company", run.CompanyPartyKey);
            Assert.Equal(CompanyUid, run.ServiceUserId);
        }
    }

    [Fact]
    public async Task FlowRunsDefaultAwaitingCompany()
    {
        var client = MakeRwClient((url, q) =>
        {
            Assert.EndsWith("/company-data/flow-runs", url);
            Assert.Equal("awaiting_company", q!["status"]);
            return Resp.Json(200, new { total = 1, items = new[] { RunObj() } });
        }, (m, u, b) => Resp.Json(200, new { }));
        using (client)
        {
            var runs = await client.FlowRunsAsync();
            Assert.Single(runs);
            Assert.Equal("awaiting_company", runs[0].Status);
        }
    }

    [Fact]
    public async Task FlowRunById()
    {
        var client = MakeRwClient((url, q) =>
        {
            Assert.EndsWith("/company-data/flow-runs/run-1", url);
            return Resp.Json(200, RunObj());
        }, (m, u, b) => Resp.Json(200, new { }));
        using (client)
        {
            var run = await client.FlowRunAsync("run-1");
            Assert.Equal("n1", run.CurrentNode);
        }
    }

    // ── decrypt prior answers drives local routing (exercises DecryptRunAnswers) ──

    // A flow whose n1→n_end edge is guarded on a PRIOR answer ("tier"=="vip"), so the route is only
    // taken when the company's already-stored "tier" copy decrypts correctly.
    private const string PriorAnswerDefJson = """
    {
      "output_mode": "data_only",
      "parties": [{"key":"company"},{"key":"person"}],
      "nodes": [{"key":"n1","party":"company"},{"key":"n2","party":"person"},{"key":"n_end","party":"person"}],
      "edges": [
        {"from":"n1","to":"n_end","sort":0,"condition":{"field":"tier","op":"eq","value":"vip"}},
        {"from":"n1","to":"n2","sort":1,"condition":null}
      ]
    }
    """;

    [Fact]
    public async Task SubmitRoutesOnPriorDecryptedAnswer()
    {
        using var key = Vector.PrivateKey();
        var tierWrapper = Encryptor.Wrap(key, "vip").ToObjectGraph();
        // Prior company copy of "tier"=vip (only the company copy is decryptable here).
        var answers = new[]
        {
            new { slug = "tier", for_user_id = CompanyUid, value = tierWrapper },
            new { slug = "tier", for_user_id = PersonUid, value = tierWrapper },
        };
        var spki = VectorPubSpkiB64();
        JsonElement captured = default;
        var client = MakeRwClient(KeyGetRouter(spki), (m, url, body) =>
        {
            captured = ParseBody(body);
            return Resp.Json(200, RunObj("awaiting_person", "n_end", defJson: PriorAnswerDefJson));
        });
        using (client)
        {
            var run = RunFromObj(RunObj(answers: answers, defJson: PriorAnswerDefJson));
            // Submitting a NEW field; routing must consider the PRIOR decrypted "tier"=vip → n_end.
            await client.SubmitFlowAnswersAsync(run, new Dictionary<string, object?> { ["note"] = "x" });
            Assert.Equal("n_end", captured.GetProperty("next_node").GetString());
        }
    }

    // ── submit: per-party fan-out + local routing ─────────────────────────────────

    private Func<string, IReadOnlyDictionary<string, string>?, HttpResult> KeyGetRouter(string spki) =>
        (url, q) =>
        {
            if (url.EndsWith("/company-data/connections/csc-1"))
                return Resp.Json(200, new { connection_id = "csc-1", share_code = "ABC123" });
            if (url.EndsWith("/api/keys/ABC123"))
                return Resp.Json(200, new { public_key = spki });
            throw new Xunit.Sdk.XunitException("unexpected GET " + url);
        };

    [Fact]
    public async Task SubmitFanOutAndRoutesFallthrough()
    {
        var spki = VectorPubSpkiB64();
        JsonElement captured = default;
        string capturedUrl = "";
        var client = MakeRwClient(KeyGetRouter(spki), (m, url, body) =>
        {
            capturedUrl = url;
            captured = ParseBody(body);
            return Resp.Json(200, RunObj("awaiting_person", "n2"));
        });
        using (client)
        {
            var run = RunFromObj(RunObj());
            var outRun = await client.SubmitFlowAnswersAsync(run,
                new Dictionary<string, object?> { ["company_name"] = "ACME BV" });
            Assert.EndsWith("/company-data/flow-runs/run-1/answers", capturedUrl);
            var answers = captured.GetProperty("answers");
            Assert.Equal(1, answers.GetArrayLength());
            var values = answers[0].GetProperty("values");
            var forUsers = values.EnumerateArray().Select(v => v.GetProperty("for_user_id").GetString()!).ToHashSet();
            Assert.Equal(new HashSet<string> { CompanyUid, PersonUid }, forUsers);
            foreach (var v in values.EnumerateArray())
                Assert.Equal(1, v.GetProperty("value").GetProperty("_enc").GetInt32());
            // company copy round-trips with the service private key
            using var priv = Vector.PrivateKey();
            var companyCopy = values.EnumerateArray().First(v => v.GetProperty("for_user_id").GetString() == CompanyUid)
                .GetProperty("value");
            Assert.Equal("ACME BV", Crypto.Decrypt(Node.FromJson(companyCopy).ToObjectGraph()!, priv));
            // local routing: no 'tier' → fallthrough to n2
            Assert.Equal("n2", captured.GetProperty("next_node").GetString());
            Assert.Equal("person", captured.GetProperty("next_party").GetString());
            Assert.False(captured.TryGetProperty("leaf", out _));
            Assert.Equal("awaiting_person", outRun.Status);
        }
    }

    [Fact]
    public async Task SubmitRoutesGuardedEdge()
    {
        var spki = VectorPubSpkiB64();
        JsonElement captured = default;
        var client = MakeRwClient(KeyGetRouter(spki), (m, url, body) =>
        {
            captured = ParseBody(body);
            return Resp.Json(200, RunObj("awaiting_person", "n_end"));
        });
        using (client)
        {
            var run = RunFromObj(RunObj());
            await client.SubmitFlowAnswersAsync(run, new Dictionary<string, object?> { ["tier"] = "vip" });
            Assert.Equal("n_end", captured.GetProperty("next_node").GetString());
            Assert.False(captured.TryGetProperty("leaf", out _));
        }
    }

    [Fact]
    public async Task SubmitUsesSuppliedPartyPubKeys()
    {
        using var priv = Vector.PrivateKey();
        var personPub = RSA.Create();
        personPub.ImportParameters(priv.ExportParameters(false));
        JsonElement captured = default;
        var client = MakeRwClient(NoGet, (m, url, body) =>
        {
            captured = ParseBody(body);
            return Resp.Json(200, RunObj("awaiting_person", "n2"));
        });
        using (client)
        {
            var run = RunFromObj(RunObj());
            await client.SubmitFlowAnswersAsync(run, new Dictionary<string, object?> { ["company_name"] = "X" },
                new Dictionary<string, RSA> { [PersonUid] = personPub });
            var values = captured.GetProperty("answers")[0].GetProperty("values");
            Assert.Equal(2, values.GetArrayLength());
        }
    }

    // ── generate (document leaf) ──────────────────────────────────────────────────

    [Fact]
    public async Task GenerateFlowDocumentPostsOtkAndBlob()
    {
        using var key = Vector.PrivateKey();
        var wrapperGraph = Encryptor.Wrap(key, "ACME BV").ToObjectGraph();
        var answers = new[] { new { slug = "company_name", for_user_id = CompanyUid, value = wrapperGraph } };
        JsonElement captured = default;
        string capturedUrl = "";
        var client = MakeRwClient(NoGet, (m, url, body) =>
        {
            capturedUrl = url;
            captured = ParseBody(body);
            return Resp.Json(200, new { document_id = "doc-9", status = "awaiting_signature" });
        });
        using (client)
        {
            var run = RunFromObj(RunObj("generating", "n1", answers, outputMode: "document"));
            var res = await client.GenerateFlowDocumentAsync(run);
            Assert.Equal("doc-9", res.Get("document_id").AsString());
            Assert.EndsWith("/company-data/flow-runs/run-1/generate", capturedUrl);

            var otk = Convert.FromBase64String(captured.GetProperty("otk").GetString()!);
            var blob = Convert.FromBase64String(captured.GetProperty("values").GetString()!);
            Assert.Equal(32, otk.Length);
            Assert.True(blob.Length >= 12 + 16);
            // reproduce the server read: iv(12) || ct || tag(16)
            var iv = blob[..12];
            var tag = blob[^16..];
            var ct = blob[12..^16];
            var plain = new byte[ct.Length];
            using (var aes = new AesGcm(otk, 16))
                aes.Decrypt(iv, ct, tag, plain);
            using var doc = JsonDocument.Parse(Encoding.UTF8.GetString(plain));
            Assert.Equal("ACME BV", doc.RootElement.GetProperty("company_name").GetString());
        }
    }

    // ── ProcessFlowRun: chains submit + generate on a company-leaf document flow ───

    [Fact]
    public async Task ProcessFlowRunCompanyLeafDocument()
    {
        var spki = VectorPubSpkiB64();
        const string single = """
        {"output_mode":"document","parties":[{"key":"company"},{"key":"person"}],
         "nodes":[{"key":"n1","party":"company"}],"edges":[]}
        """;
        var posts = new List<string>();
        var client = MakeRwClient(
            (url, q) =>
            {
                if (url.EndsWith("/company-data/flow-runs/run-1"))
                {
                    var status = posts.Count > 0 ? "awaiting_signature" : "awaiting_company";
                    var docId = posts.Count > 0 ? "doc-9" : null;
                    return Resp.Json(200, RunObj(status, "n1", defJson: single, outputMode: "document", documentId: docId));
                }
                if (url.EndsWith("/company-data/connections/csc-1"))
                    return Resp.Json(200, new { connection_id = "csc-1", share_code = "ABC123" });
                if (url.EndsWith("/api/keys/ABC123"))
                    return Resp.Json(200, new { public_key = spki });
                throw new Xunit.Sdk.XunitException("unexpected GET " + url);
            },
            (m, url, body) =>
            {
                posts.Add(url);
                if (url.EndsWith("/answers"))
                    return Resp.Json(200, RunObj("generating", "n1", defJson: single, outputMode: "document"));
                Assert.EndsWith("/generate", url);
                return Resp.Json(200, new { document_id = "doc-9", status = "awaiting_signature" });
            });
        using (client)
        {
            var run = await client.ProcessFlowRunAsync("run-1",
                (node, answers) => new Dictionary<string, object?> { ["company_name"] = "ACME BV" });
            Assert.Contains(posts, p => p.EndsWith("/answers"));
            Assert.Contains(posts, p => p.EndsWith("/generate"));
            Assert.Equal("awaiting_signature", run.Status);
            Assert.Equal("doc-9", run.DocumentId);
        }
    }

    [Fact]
    public async Task ProcessFlowRunNotOurTurn()
    {
        var calls = 0;
        var client = MakeRwClient(
            (url, q) => Resp.Json(200, RunObj("awaiting_person", "n2")),
            (m, u, b) => Resp.Json(200, new { }));
        using (client)
        {
            var run = await client.ProcessFlowRunAsync("run-1",
                (node, answers) => { calls++; return new Dictionary<string, object?> { ["x"] = "y" }; });
            Assert.Equal("awaiting_person", run.Status);
            Assert.Equal(0, calls);
        }
    }
}
