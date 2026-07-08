// CustomerClient (b2b, #168) — parse + method-shape + key-sourcing tests.
// Reuses the shared decryption vector's key as the customer ACCOUNT key.

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;

namespace Allus.CompanyData.Tests;

public sealed class CustomerClientTests : IDisposable
{
    private readonly string _dir;
    private readonly string _pemPath;
    private readonly Config _config;

    public CustomerClientTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "allus-customer-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_dir);
        _pemPath = Path.Combine(_dir, "account-key.pem");
        File.WriteAllText(_pemPath, Vector.EncryptedPem);
        _config = new Config
        {
            ApiUrl = "https://api.allme.fyi",
            CustomerClientId = "acct_abc",
            CustomerClientSecret = "topsecret",
            AccountPrivateKey = _pemPath,
            AccountPassphrase = Vector.Passphrase,
            CacheDir = Path.Combine(_dir, "cache"),
        };
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private (CustomerClient Client, RouterTransport Transport) Make(
        Func<string, IReadOnlyDictionary<string, string>?, HttpResult> router,
        Func<string, string, byte[]?, HttpResult>? writeRouter = null)
    {
        var transport = new RouterTransport(router, writeRouter);
        return (new CustomerClient(_config, http: new ApiHttp(_config, transport: transport)), transport);
    }

    private static string VectorPubSpki()
    {
        using var key = Vector.PrivateKey();
        return Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());
    }

    [Fact]
    public void CustomerConfigRequiresAcctPair()
    {
        var p = Path.Combine(_dir, "c.json");
        File.WriteAllText(p, "{\"api_url\":\"https://api.allme.fyi\"}");
        Assert.Throws<ConfigException>(() => Config.FromCustomerFile(p));
    }

    [Fact]
    public async Task ConnectionsParsesCompanyAndServices()
    {
        var body = new
        {
            connections = new[]
            {
                new
                {
                    id = "conn-1",
                    customer_type = "company",
                    company = new { user_id = "co-1", display_name = "Acme BV", share_code = "ACME01" },
                    company_profile = new[] { new { slug = "company_email", value = "hi@acme.example" } },
                    services = new[] { new { service_link_id = "sl-1", service_name = "CRM", shared = new[] { new { slug = "x", value = "y" } } } },
                },
            },
        };
        var (client, _) = Make((url, q) => Resp.Json(200, body));
        var conns = await client.ConnectionsAsync();
        Assert.Single(conns);
        Assert.Equal("company", conns[0].CustomerType);
        Assert.Equal("Acme BV", conns[0].CompanyName);
        Assert.Equal("ACME01", conns[0].CompanyCode);
        Assert.Equal("CRM", conns[0].Services[0].ServiceName);
    }

    [Fact]
    public async Task ProvideConsentEncryptsToServiceKey()
    {
        var spki = VectorPubSpki();
        var (client, transport) = Make(
            (url, q) => url.Contains("/api/keys/ACME01/CRM") ? Resp.Json(200, new { public_key = spki }) : Resp.Json(200, new { }),
            (method, url, body) => Resp.Json(200, new { ok = true }));
        await client.ProvideConsentAsync("consent-1",
            new[] { new TypedAnswer("rf-1", "billing@me.example") }, "ACME01", "CRM");
        var write = transport.Writes[^1];
        Assert.EndsWith("/consents/consent-1/provide", write.Url);
        var sent = JsonDocument.Parse(Encoding.UTF8.GetString(write.Body!)).RootElement;
        var decision = sent.GetProperty("decisions")[0];
        Assert.Equal("typed", decision.GetProperty("kind").GetString());
        using var priv = Vector.PrivateKey();
        var plain = Crypto.Decrypt(Node.FromJson(decision.GetProperty("value")), priv);
        Assert.Equal("billing@me.example", plain);
    }

    [Fact]
    public async Task DocumentFileDecryptsWithAccountKey()
    {
        using var priv = Vector.PrivateKey();
        using var pub = RSA.Create();
        pub.ImportSubjectPublicKeyInfo(priv.ExportSubjectPublicKeyInfo(), out _);
        var wrapper = Crypto.EncryptForPublicKey(
            JsonSerializer.Serialize(new { file = "data:application/pdf;base64,AAA", name = "contract.pdf" }), pub);
        var wrapperJson = JsonSerializer.Deserialize<JsonElement>(wrapper.ToJsonString());
        var (client, _) = Make((url, q) => Resp.Json(200, new { encrypted = true, value = wrapperJson }));
        var outEl = (JsonElement)(await client.DocumentFileAsync("conn-1", "doc-1"))!;
        Assert.Equal("contract.pdf", outEl.GetProperty("name").GetString());
    }

    [Fact]
    public async Task DrainBatchUsesCustomerChanges()
    {
        var hit = false;
        var (client, _) = Make((url, q) =>
        {
            if (url.Contains("/api/customer/changes"))
            {
                hit = true;
                return Resp.Json(200, new { changes = new[] { new { id = "ch-1", @event = "share_changed", customer_type = "company" } } });
            }
            return Resp.Json(200, new { });
        });
        var changes = await client.DrainBatchAsync(10);
        Assert.True(hit);
        Assert.Equal("ch-1", changes[0].Id);
        Assert.Equal("company", changes[0].CustomerType);
    }

    [Fact]
    public void NoSignOrAcceptMethods()
    {
        var type = typeof(CustomerClient);
        foreach (var banned in new[] { "Sign", "Accept", "SignDocument", "AcceptDocument", "SignEmailCode", "SignAsync", "AcceptAsync" })
            Assert.Null(type.GetMethod(banned));
    }
}

