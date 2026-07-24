// #481 additions to the 2FA client: WaitForResultAsync (the base challenge/result client landed via
// #436). All mocked — a QueueTransport replays scripted challenge polls; no live API is touched.

using Allus.CompanyData;
using Xunit;

namespace Allus.CompanyData.Tests;

public class TwoFactorTests
{
    private static Config Cfg() => new()
    {
        ApiUrl = "https://api.allme.fyi",
        ClientId = "svc_abc",
        ClientSecret = "topsecret",
        ServicePrivateKey = "k.pem", // never loaded by ApiHttp
        KeyPassphrase = "pp",
        Format = "json",
    };

    // A TwoFactorClient over a QueueTransport, with an instant (no-delay) sleep.
    private static (TwoFactorClient Tf, QueueTransport T) Make()
    {
        var t = new QueueTransport();
        t.PostResponses.Enqueue(Resp.TokenOk()); // the client_credentials token fetch
        var http = new ApiHttp(Cfg(), transport: t, sleep: (_, _) => Task.CompletedTask);
        return (new TwoFactorClient(http, sleep: (_, _) => Task.CompletedTask), t);
    }

    [Fact]
    public async Task WaitForResultReturnsFirstTerminal()
    {
        var (tf, t) = Make();
        t.GetResponses.Enqueue(Resp.Json(200, new { status = "pending" }));
        t.GetResponses.Enqueue(Resp.Json(200, new { status = "pending" }));
        t.GetResponses.Enqueue(Resp.Json(200, new { status = "approved", completed_at = "2026-07-24T10:00:00Z" }));

        var res = await tf.WaitForResultAsync("chal_1", timeoutSeconds: 600, intervalSeconds: 0);

        Assert.Equal("approved", res.Status);
        Assert.Equal("2026-07-24T10:00:00Z", res.CompletedAt);
        // Stopped at the first terminal read — never re-read a burned challenge.
        Assert.Equal(3, t.Gets.Count);
    }

    [Theory]
    [InlineData("approved")]
    [InlineData("denied")]
    [InlineData("expired")]
    [InlineData("revoked")]
    [InlineData("gone")]
    public async Task WaitForResultEachTerminalStatus(string terminal)
    {
        var (tf, t) = Make();
        t.GetResponses.Enqueue(Resp.Json(200, new { status = "pending" }));
        t.GetResponses.Enqueue(Resp.Json(200, new { status = terminal }));

        var res = await tf.WaitForResultAsync("chal_1", timeoutSeconds: 600, intervalSeconds: 0);
        Assert.Equal(terminal, res.Status);
    }

    [Fact]
    public async Task WaitForResultTimeoutThrowsApiException()
    {
        var (tf, t) = Make();
        // timeoutSeconds = 0 → after the first pending poll the deadline has passed.
        t.GetResponses.Enqueue(Resp.Json(200, new { status = "pending" }));

        var ex = await Assert.ThrowsAsync<ApiException>(
            () => tf.WaitForResultAsync("chal_late", timeoutSeconds: 0, intervalSeconds: 0));
        Assert.Contains("not completed within", ex.Message);
        Assert.Single(t.Gets); // only the one pending poll before giving up
    }
}
