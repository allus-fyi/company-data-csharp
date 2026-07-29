// "Sign in with allme" RP OAuth client tests.

using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using Allus.CompanyData;
using Xunit;

namespace Allus.CompanyData.Tests;

public class OAuthTests
{
    private static Config IdwCfg(string? pem = null, string? pass = null) => new()
    {
        ApiUrl = "https://api.allme.fyi",
        OAuthClientId = "idw_abc123",
        OAuthRedirectUri = "https://shop.example/cb",
        OAuthPrivateKey = pem,
        OAuthKeyPassphrase = pass,
    };

    private static (string Base, Dictionary<string, string> Q) ParseUrl(string url)
    {
        var uri = new System.Uri(url);
        var q = new Dictionary<string, string>();
        foreach (var pair in uri.Query.TrimStart('?').Split('&', System.StringSplitOptions.RemoveEmptyEntries))
        {
            var kv = pair.Split('=', 2);
            q[kv[0]] = System.Uri.UnescapeDataString(kv[1]);
        }
        return ($"{uri.Scheme}://{uri.Host}{uri.AbsolutePath}", q);
    }

    // ── config ─────────────────────────────────────────────────────────────
    [Fact]
    public void IdwConfigRequiresClientAndRedirect()
    {
        var dir = Directory.CreateTempSubdirectory().FullName;
        var p = Path.Combine(dir, "c.json");
        File.WriteAllText(p, "{\"api_url\":\"https://api.allme.fyi\"}");
        Assert.Throws<ConfigException>(() => Config.FromIdwFile(p));
    }

    // ── authorizeUrl ───────────────────────────────────────────────────────
    [Fact]
    public void AuthorizeUrlSigninGolden()
    {
        var c = new OAuthClient(IdwCfg(), new QueueTransport());
        var (bas, q) = ParseUrl(c.AuthorizeUrl("signin", state: "st1"));
        Assert.Equal("https://web.allme.fyi/auth", bas);
        Assert.Equal("idw_abc123", q["client_id"]);
        Assert.Equal("https://shop.example/cb", q["redirect_uri"]);
        Assert.Equal("signin", q["mode"]);
        Assert.Equal("redirect", q["response_mode"]);
        Assert.Equal("st1", q["state"]);
        Assert.False(q.ContainsKey("claims"));
    }

    [Fact]
    public void AuthorizeUrlPkceAndDetached()
    {
        var c = new OAuthClient(IdwCfg(), new QueueTransport());
        var (_, q) = ParseUrl(c.AuthorizeUrl("signin", responseMode: "detached", codeChallenge: "CH"));
        Assert.Equal("detached", q["response_mode"]);
        Assert.Equal("CH", q["code_challenge"]);
        Assert.Equal("S256", q["code_challenge_method"]);
    }

    [Fact]
    public void AuthorizeUrlClaimValidation()
    {
        var c = new OAuthClient(IdwCfg(), new QueueTransport());
        // Every claim carries a mandatory Name — the identity everything downstream is keyed by.
        var claims = new[]
        {
            new Claim("email", "email", "email_personal"),
            new Claim("avatar", "photo"),
            new Claim("phone", "phone", Required: true),
            new Claim("nothing", ""),
        };
        var (_, q) = ParseUrl(c.AuthorizeUrl("one_time", claims));
        using var doc = JsonDocument.Parse(q["claims"]);
        var arr = doc.RootElement;
        Assert.Equal(2, arr.GetArrayLength());
        Assert.Equal("email", arr[0].GetProperty("name").GetString());
        Assert.Equal("email", arr[0].GetProperty("type").GetString());
        Assert.Equal("email_personal", arr[0].GetProperty("suggest").GetString());
        Assert.Equal("phone", arr[1].GetProperty("name").GetString());
        Assert.Equal("phone", arr[1].GetProperty("type").GetString());
        Assert.True(arr[1].GetProperty("required").GetBoolean());
    }

    /// A nameless claim, and two sharing a name, are refused at the call that made them.
    [Fact]
    public void AuthorizeUrlClaimNameRequired()
    {
        var c = new OAuthClient(IdwCfg(), new QueueTransport());
        Assert.Throws<ConfigException>(() => c.AuthorizeUrl("one_time", new[] { new Claim("", "email") }));
        Assert.Throws<ConfigException>(() => c.AuthorizeUrl("one_time", new[]
        {
            new Claim("email", "email"),
            new Claim("email", "text"),
        }));
    }

    /// `verified` travels on the wire, so an RP can demand an attested answer.
    [Fact]
    public void AuthorizeUrlClaimVerified()
    {
        var c = new OAuthClient(IdwCfg(), new QueueTransport());
        var (_, q) = ParseUrl(c.AuthorizeUrl("signin", new[] { new Claim("email", "email", Verified: true) }));
        using var doc = JsonDocument.Parse(q["claims"]);
        Assert.Single(doc.RootElement.EnumerateArray());
        Assert.True(doc.RootElement[0].GetProperty("verified").GetBoolean());
    }

    [Fact]
    public void AuthorizeUrlCaps15()
    {
        var c = new OAuthClient(IdwCfg(), new QueueTransport());
        var claims = new List<Claim>();
        for (var i = 0; i < 30; i++) claims.Add(new Claim($"c{i}", "text"));
        var (_, q) = ParseUrl(c.AuthorizeUrl("one_time", claims));
        using var doc = JsonDocument.Parse(q["claims"]);
        Assert.Equal(15, doc.RootElement.GetArrayLength());
    }

    [Fact]
    public void AuthorizeUrlInvalidModeThrows()
    {
        var c = new OAuthClient(IdwCfg(), new QueueTransport());
        Assert.Throws<ConfigException>(() => c.AuthorizeUrl("bogus"));
    }

    // ── exchange / userinfo / complete ─────────────────────────────────────
    [Fact]
    public async Task ExchangeAndUserinfo()
    {
        var t = new QueueTransport();
        t.PostResponses.Enqueue(Resp.Json(200, new { access_token = "AT", mode = "signin" }));
        t.GetResponses.Enqueue(Resp.Json(200, new { sub = "AB12CD", share_code = "AB12CD", mode = "signin", two_factor = false }));
        var c = new OAuthClient(IdwCfg(), t);
        var tok = await c.ExchangeCodeAsync("CODE", "V");
        Assert.Equal("AT", tok.GetProperty("access_token").GetString());
        Assert.Equal("authorization_code", t.Posts[0].Form["grant_type"]);
        Assert.Equal("V", t.Posts[0].Form["code_verifier"]);
        var info = await c.UserinfoAsync("AT");
        // `sub` IS the share code (byte-identical to the id_token's); display_name is gone.
        Assert.Equal("AB12CD", info.GetProperty("sub").GetString());
        Assert.Equal(info.GetProperty("share_code").GetString(), info.GetProperty("sub").GetString());
        Assert.False(info.TryGetProperty("display_name", out _));
    }

    [Fact]
    public async Task CompleteSignInDecryptsValues()
    {
        var dir = Directory.CreateTempSubdirectory().FullName;
        var pem = Path.Combine(dir, "app.pem");
        File.WriteAllText(pem, Vector.EncryptedPem);
        var t = new QueueTransport();
        t.PostResponses.Enqueue(Resp.Json(200, new { access_token = "AT", mode = "one_time" }));
        t.GetResponses.Enqueue(Resp.Json(200, new
        {
            sub = "AB12CD",
            share_code = "AB12CD",
            mode = "one_time",
            two_factor = true,
            values = new Dictionary<string, object> { ["email_personal"] = Vector.TextWrapper },
        }));
        var c = new OAuthClient(IdwCfg(pem, Vector.Passphrase), t);
        var res = await c.CompleteSignInAsync("CODE", "V");
        Assert.Equal("one_time", res.Mode);
        Assert.True(res.TwoFactor);
        // Sub IS the share code (byte-identical to the id_token's); DisplayName is gone.
        Assert.Equal("AB12CD", res.Sub);
        Assert.Equal(res.Sub, res.ShareCode);
        Assert.Equal(Vector.TextPlaintext, res.Values["email_personal"]);
        // No `values_attestation` on the wire → "not attested", never "wrong".
        Assert.Empty(res.Attestations);
    }

    // ── detached poll ──────────────────────────────────────────────────────
    [Fact]
    public async Task PollResultPendingThenCode()
    {
        var t = new QueueTransport();
        t.PostResponses.Enqueue(Resp.Text(202, ""));
        t.PostResponses.Enqueue(Resp.Text(202, ""));
        t.PostResponses.Enqueue(Resp.Json(200, new { code = "AUTHCODE", state = "DET1" }));
        var c = new OAuthClient(IdwCfg(), t, sleep: _ => Task.CompletedTask);
        var res = await c.PollResultAsync("DET1", timeoutSeconds: 5, intervalSeconds: 0);
        Assert.Equal("AUTHCODE", res.GetProperty("code").GetString());
        Assert.Equal(3, t.Posts.Count);
    }

    [Fact]
    public async Task PollResultExpiredThrows()
    {
        var t = new QueueTransport();
        t.PostResponses.Enqueue(Resp.Json(410, new { error_key = "oauth.result_expired" }));
        var c = new OAuthClient(IdwCfg(), t, sleep: _ => Task.CompletedTask);
        var ex = await Assert.ThrowsAsync<ApiException>(() => c.PollResultAsync("DET1", 5, 0));
        Assert.Equal(410, ex.Status);
    }

    // ── 2fa_enroll mode + detached enrollment poll delivery ─────────────────
    [Fact]
    public void AuthorizeUrlAccepts2faEnrollMode()
    {
        var c = new OAuthClient(IdwCfg(), new QueueTransport());
        var (_, q) = ParseUrl(c.AuthorizeUrl("2fa_enroll", responseMode: "detached", state: "EN1"));
        Assert.Equal("2fa_enroll", q["mode"]);
        Assert.Equal("detached", q["response_mode"]);
    }

    [Fact]
    public async Task PollResultPendingThenEnrolled()
    {
        // A detached 2fa_enroll delivers {enrolled: true, state}, NOT a code. PollResultAsync
        // must return on the `enrolled` sentinel — otherwise it consumes the one-shot result and times out.
        var t = new QueueTransport();
        t.PostResponses.Enqueue(Resp.Text(202, ""));
        t.PostResponses.Enqueue(Resp.Json(200, new { enrolled = true, state = "EN1" }));
        var c = new OAuthClient(IdwCfg(), t, sleep: _ => Task.CompletedTask);
        var res = await c.PollResultAsync("EN1", timeoutSeconds: 5, intervalSeconds: 0);
        Assert.True(res.GetProperty("enrolled").GetBoolean());
        Assert.Equal("EN1", res.GetProperty("state").GetString());
        Assert.Equal(2, t.Posts.Count); // returned on first delivery, never polled past it
    }

    [Fact]
    public async Task PollResultStillReturnsOnCodeAfterEnrollChange()
    {
        // Regression: the enroll addition must not break the sign-in `code` delivery.
        var t = new QueueTransport();
        t.PostResponses.Enqueue(Resp.Json(200, new { code = "AUTHCODE", state = "DET1" }));
        var c = new OAuthClient(IdwCfg(), t, sleep: _ => Task.CompletedTask);
        var res = await c.PollResultAsync("DET1", timeoutSeconds: 5, intervalSeconds: 0);
        Assert.Equal("AUTHCODE", res.GetProperty("code").GetString());
    }
}
