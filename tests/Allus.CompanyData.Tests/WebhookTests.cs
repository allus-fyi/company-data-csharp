// Webhook receiver-helper tests. No live API. We build fixture webhook requests the
// way the platform's WebhookDeliveryService does: the body = the slug-keyed Change shape, JSON or
// XML; X-Allus-Signature = lowercase-hex HMAC-SHA256(body, secret); X-Allus-Webhook-Id selects the
// secret; for an encrypt_payload webhook the body is REPLACED by a {"_enc":1,...} envelope
// encrypted to the company ACCOUNT public key with OAEP-SHA1 + AES-256-GCM, and the HMAC is then
// over that envelope. The inner field value is a service-key wrapper (SHA-256), reusing the shared
// vector — so a parsed webhook Change decrypts identically to a feed Change.

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Allus.CompanyData;
using Xunit;

namespace Allus.CompanyData.Tests;

public sealed class WebhookTests : IDisposable
{
    private const string Secret = "wh_secret_abc123";
    private const string WebhookId = "wh-1";

    private readonly string _dir;
    private readonly Config _config;

    public WebhookTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "allus-wh-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var pem = Path.Combine(_dir, "service-key.pem");
        File.WriteAllText(pem, Vector.EncryptedPem);
        _config = new Config
        {
            ApiUrl = "https://api.allme.fyi",
            ClientId = "svc",
            ClientSecret = "s",
            ServicePrivateKey = pem,
            KeyPassphrase = Vector.Passphrase,
            CacheDir = Path.Combine(_dir, "cache"),
            Webhooks = new Dictionary<string, string> { [WebhookId] = Secret },
        };
    }

    public void Dispose() => Directory.Delete(_dir, true);

    private DecryptValue DecryptValue()
    {
        var key = Vector.PrivateKey();
        return w => Crypto.Decrypt(w, key);
    }

    private static TypeForSlug TypeForSlug() =>
        slug => new Dictionary<string, string> { ["work_email"] = "email", ["logo"] = "photo" }.GetValueOrDefault(slug);

    private static string Sign(byte[] body, string secret = Secret) =>
        Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), body)).ToLowerInvariant();

    private static Dictionary<string, string> Headers(byte[] body, string secret = Secret, string webhookId = WebhookId, bool sign = true)
    {
        var h = new Dictionary<string, string> { ["X-Allus-Webhook-Id"] = webhookId, ["X-Allus-Event"] = "field_updated" };
        if (sign) h["X-Allus-Signature"] = Sign(body, secret);
        return h;
    }

    private static byte[] ChangeBody()
    {
        // A plain JSON field_updated change body (slug-keyed Change shape).
        using var doc = JsonDocument.Parse(Vector.TextWrapper.GetRawText());
        var wrapper = doc.RootElement;
        var payload = new Dictionary<string, object?>
        {
            ["id"] = "chg-1",
            ["event"] = "field_updated",
            ["person_user_id"] = "person-1",
            ["slug"] = "work_email",
            ["at"] = "2026-06-17T12:00:00Z",
            ["live"] = true,
            ["value"] = JsonSerializer.Deserialize<Dictionary<string, object?>>(Vector.TextWrapper.GetRawText()),
        };
        return Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload));
    }

    // ── verify ─────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void VerifyTrueWithKnownSecret()
    {
        var body = ChangeBody();
        Assert.True(Webhooks.VerifyWebhook(body, Headers(body), _config));
    }

    [Fact]
    public void VerifyFalseOnTamperedBody()
    {
        var body = ChangeBody();
        var headers = Headers(body); // signature for the ORIGINAL body
        var tampered = body.Concat(new byte[] { (byte)' ' }).ToArray();
        Assert.False(Webhooks.VerifyWebhook(tampered, headers, _config));
    }

    [Fact]
    public void VerifyFalseOnUnknownWebhookId()
    {
        var body = ChangeBody();
        Assert.False(Webhooks.VerifyWebhook(body, Headers(body, webhookId: "wh-UNKNOWN"), _config));
    }

    [Fact]
    public void VerifyFalseOnMissingSignature()
    {
        var body = ChangeBody();
        Assert.False(Webhooks.VerifyWebhook(body, Headers(body, sign: false), _config));
    }

    [Fact]
    public void VerifyAcceptsUppercaseHex()
    {
        var body = ChangeBody();
        var headers = new Dictionary<string, string>
        {
            ["X-Allus-Webhook-Id"] = WebhookId,
            ["X-Allus-Signature"] = Sign(body).ToUpperInvariant(),
        };
        Assert.True(Webhooks.VerifyWebhook(body, headers, _config));
    }

    [Fact]
    public void VerifySingleWebhookShortcut()
    {
        var pem = Path.Combine(_dir, "k2.pem");
        File.WriteAllText(pem, Vector.EncryptedPem);
        var cfg = new Config
        {
            ApiUrl = "https://api.allme.fyi", ClientId = "svc", ClientSecret = "s",
            ServicePrivateKey = pem, KeyPassphrase = Vector.Passphrase,
            CacheDir = Path.Combine(_dir, "c2"),
            Webhooks = new Dictionary<string, string> { [Config.SingleWebhookKey] = Secret },
        };
        var body = ChangeBody();
        // Header carries an id, but config has only the flat secret → falls back to it.
        Assert.True(Webhooks.VerifyWebhook(body, Headers(body), cfg));
    }

    // ── parse (plain JSON) ───────────────────────────────────────────────────────────────────

    [Fact]
    public void ParsePlainJsonBody()
    {
        var body = ChangeBody();
        var change = Webhooks.ParseWebhook(body, Headers(body), _config, TypeForSlug(), DecryptValue());
        Assert.Equal("chg-1", change.Id);
        Assert.Equal("field_updated", change.Event);
        Assert.Equal("person-1", change.PersonId);
        Assert.Equal("work_email", change.Slug);
        Assert.Equal(Vector.TextPlaintext, change.ValueObj);
        Assert.True(change.Live);
    }

    [Fact]
    public void ParseXmlBody()
    {
        var w = Vector.TextWrapper;
        var xml =
            "<response>" +
            "<id>chg-7</id>" +
            "<event>field_updated</event>" +
            "<person_user_id>person-1</person_user_id>" +
            "<slug>work_email</slug>" +
            "<at>2026-06-17T12:00:00Z</at>" +
            "<live>true</live>" +
            "<value>" +
            $"<_enc>1</_enc><k>{w.GetProperty("k").GetString()}</k><iv>{w.GetProperty("iv").GetString()}</iv><d>{w.GetProperty("d").GetString()}</d>" +
            "</value>" +
            "</response>";
        var bytes = Encoding.UTF8.GetBytes(xml);
        var headers = Headers(bytes);

        var change = Webhooks.ParseWebhook(bytes, headers, _config, TypeForSlug(), DecryptValue());
        Assert.Equal("chg-7", change.Id);
        Assert.Equal("field_updated", change.Event);
        Assert.Equal("work_email", change.Slug);
        Assert.Equal(Vector.TextPlaintext, change.ValueObj);
    }

    // ── parse (account-key encrypt_payload envelope) ───────────────────────────────────────────

    [Fact]
    public void ParseAccountKeyEnvelope()
    {
        var (accountPem, accountPub) = Encryptor.MakeAccountKey(_dir, "acctpp");
        var servicePem = Path.Combine(_dir, "service-key2.pem");
        File.WriteAllText(servicePem, Vector.EncryptedPem);
        var config = new Config
        {
            ApiUrl = "https://api.allme.fyi", ClientId = "svc", ClientSecret = "s",
            ServicePrivateKey = servicePem, KeyPassphrase = Vector.Passphrase,
            AccountPrivateKey = accountPem, AccountPassphrase = "acctpp",
            CacheDir = Path.Combine(_dir, "c3"),
            Webhooks = new Dictionary<string, string> { [WebhookId] = Secret },
        };

        var inner = ChangeBody(); // the serialized change (JSON)
        var body = Encryptor.WrapAccountSha1(accountPub, inner); // the envelope IS the sent body
        var headers = Headers(body); // HMAC is over the envelope (the final body)

        Assert.True(Webhooks.VerifyWebhook(body, headers, config));
        var change = Webhooks.ParseWebhook(body, headers, config, TypeForSlug(), DecryptValue());
        Assert.Equal("chg-1", change.Id);
        Assert.Equal("field_updated", change.Event);
        Assert.Equal("work_email", change.Slug);
        // Outer envelope = account-key (SHA-1); inner value = service-key (SHA-256) → vector plaintext.
        Assert.Equal(Vector.TextPlaintext, change.ValueObj);
        accountPub.Dispose();
    }

    [Fact]
    public void ParseAccountEnvelopeWithoutAccountKeyThrows()
    {
        var (_, accountPub) = Encryptor.MakeAccountKey(_dir, "x");
        var body = Encryptor.WrapAccountSha1(accountPub, ChangeBody());
        // _config has no account_private_key.
        Assert.Throws<WebhookException>(() =>
            Webhooks.ParseWebhook(body, Headers(body), _config, TypeForSlug(), DecryptValue()));
        accountPub.Dispose();
    }

    // ── handle = verify + parse ────────────────────────────────────────────────────────────────

    [Fact]
    public void HandleVerifyThenParse()
    {
        var body = ChangeBody();
        var change = Webhooks.HandleWebhook(body, Headers(body), _config, TypeForSlug(), DecryptValue());
        Assert.Equal("chg-1", change.Id);
    }

    [Fact]
    public void HandleBadSignatureThrows()
    {
        var body = ChangeBody();
        var headers = Headers(body);
        headers["X-Allus-Signature"] = "deadbeef"; // wrong
        Assert.Throws<WebhookException>(() =>
            Webhooks.HandleWebhook(body, headers, _config, TypeForSlug(), DecryptValue()));
    }

    // ── Client method delegation ──────────────────────────────────────────────────────────────

    [Fact]
    public void ClientMethodsDelegate()
    {
        var catalogCalls = 0;
        var transport = new RouterTransport((url, q) =>
        {
            Assert.EndsWith("/request-fields", url);
            catalogCalls++;
            return Resp.Json(200, new
            {
                request_fields = new object[]
                {
                    new { slug = "work_email", label = "Work email", type = "email", one_time = false, mandatory_provide = true, mandatory_connected = false },
                },
            });
        });
        using var client = new Client(_config, http: new ApiHttp(_config, transport: transport));
        var body = ChangeBody();
        var headers = Headers(body);

        // verify makes NO HTTP at all.
        Assert.True(client.VerifyWebhook(body, headers));
        Assert.Equal(0, catalogCalls);

        var change = client.HandleWebhook(body, headers);
        Assert.Equal("chg-1", change.Id);
        Assert.Equal(Vector.TextPlaintext, change.ValueObj);
        Assert.Equal(1, catalogCalls); // catalog fetched at most once (cached)
        client.HandleWebhook(body, headers);
        Assert.Equal(1, catalogCalls);
    }

    [Fact]
    public void AccountKeyLoadedOnceAndReused()
    {
        // The Client loads the account key ONCE at construction; encrypt_payload webhooks must not
        // re-read the PEM + re-run PBKDF2. We can't spy on a static load easily, so we assert the
        // observable behavior: three enveloped webhooks all decrypt correctly using the construction
        // -time key, with no per-webhook HTTP beyond the single catalog fetch.
        var (accountPem, accountPub) = Encryptor.MakeAccountKey(_dir, "acctpp");
        var servicePem = Path.Combine(_dir, "service-key3.pem");
        File.WriteAllText(servicePem, Vector.EncryptedPem);
        var cfg = new Config
        {
            ApiUrl = "https://api.allme.fyi", ClientId = "svc", ClientSecret = "s",
            ServicePrivateKey = servicePem, KeyPassphrase = Vector.Passphrase,
            AccountPrivateKey = accountPem, AccountPassphrase = "acctpp",
            CacheDir = Path.Combine(_dir, "c4"),
            Webhooks = new Dictionary<string, string> { [WebhookId] = Secret },
        };

        var catalogCalls = 0;
        var transport = new RouterTransport((url, q) =>
        {
            Assert.EndsWith("/request-fields", url);
            catalogCalls++;
            return Resp.Json(200, new
            {
                request_fields = new object[]
                {
                    new { slug = "work_email", label = "Work email", type = "email", one_time = false, mandatory_provide = true, mandatory_connected = false },
                },
            });
        });
        using var client = new Client(cfg, http: new ApiHttp(cfg, transport: transport));

        var inner = ChangeBody();
        var body = Encryptor.WrapAccountSha1(accountPub, inner);
        var headers = Headers(body);
        for (var i = 0; i < 3; i++)
        {
            var change = client.HandleWebhook(body, headers);
            Assert.Equal("chg-1", change.Id);
            Assert.Equal(Vector.TextPlaintext, change.ValueObj);
        }
        Assert.Equal(1, catalogCalls); // only the catalog fetch — and only once
        accountPub.Dispose();
    }

    [Fact]
    public void ParseWebhookLoadsAccountKeyWhenNotSupplied()
    {
        // Standalone ParseWebhook (no cached key) still works — loads on demand from config.
        var (accountPem, accountPub) = Encryptor.MakeAccountKey(_dir, "acctpp");
        var servicePem = Path.Combine(_dir, "service-key5.pem");
        File.WriteAllText(servicePem, Vector.EncryptedPem);
        var cfg = new Config
        {
            ApiUrl = "https://api.allme.fyi", ClientId = "svc", ClientSecret = "s",
            ServicePrivateKey = servicePem, KeyPassphrase = Vector.Passphrase,
            AccountPrivateKey = accountPem, AccountPassphrase = "acctpp",
            CacheDir = Path.Combine(_dir, "c5"),
            Webhooks = new Dictionary<string, string> { [WebhookId] = Secret },
        };
        var body = Encryptor.WrapAccountSha1(accountPub, ChangeBody());
        var change = Webhooks.ParseWebhook( // no accountKey arg → loaded from config on demand
            body, Headers(body), cfg, TypeForSlug(), DecryptValue());
        Assert.Equal("chg-1", change.Id);
        Assert.Equal(Vector.TextPlaintext, change.ValueObj);
        accountPub.Dispose();
    }
}
