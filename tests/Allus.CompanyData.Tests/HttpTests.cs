// HTTP/auth layer tests. All mocked — no live API. A QueueTransport records
// requests and replays scripted responses so we can exercise: the client_credentials token fetch +
// caching, 401 → one refresh-and-retry → AuthException, 429 → Retry-After backoff → retry /
// RateLimitException, ApiException mapping (carrying the body error_key), and the JSON/XML
// accept + parse paths.

using Allus.CompanyData;
using Xunit;

namespace Allus.CompanyData.Tests;

public class HttpTests
{
    private static Config Cfg(string fmt = "json") => new()
    {
        ApiUrl = "https://api.allme.fyi",
        ClientId = "svc_abc",
        ClientSecret = "topsecret",
        ServicePrivateKey = "k.pem", // never loaded by ApiHttp
        KeyPassphrase = "pp",
        Format = fmt,
    };

    private static ApiHttp MakeClient(QueueTransport t, string fmt = "json", List<double>? sleeps = null,
        Func<double>? clock = null, int maxRetries429 = 3)
    {
        sleeps ??= new List<double>();
        return new ApiHttp(
            Cfg(fmt),
            transport: t,
            sleep: (s, ct) => { sleeps.Add(s); return Task.CompletedTask; },
            clock: clock,
            maxRetries429: maxRetries429);
    }

    // ── token fetch + caching ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task TokenIsFetchedWithClientCredentialsAndAttached()
    {
        var t = new QueueTransport();
        t.PostResponses.Enqueue(Resp.TokenOk());
        t.GetResponses.Enqueue(Resp.Json(200, new { ok = true }));
        var c = MakeClient(t);

        var body = await c.GetAsync("/api/company-data/request-fields");
        Assert.True(body.Get("ok").RawScalar as bool? ?? false);

        Assert.Equal("https://api.allme.fyi/oauth2/token", t.Posts[0].Url);
        Assert.Equal("client_credentials", t.Posts[0].Form["grant_type"]);
        Assert.Equal("svc_abc", t.Posts[0].Form["client_id"]);
        Assert.Equal("topsecret", t.Posts[0].Form["client_secret"]);
        Assert.Equal("Bearer tok-123", t.Gets[0].Headers["Authorization"]);
        Assert.Equal("application/json", t.Gets[0].Headers["Accept"]);
    }

    [Fact]
    public async Task TokenIsCachedAcrossCalls()
    {
        var t = new QueueTransport();
        t.PostResponses.Enqueue(Resp.TokenOk()); // only one token fetch expected
        t.GetResponses.Enqueue(Resp.Json(200, new { n = 1 }));
        t.GetResponses.Enqueue(Resp.Json(200, new { n = 2 }));
        var c = MakeClient(t);

        await c.GetAsync("/api/company-data/changes");
        await c.GetAsync("/api/company-data/changes");
        Assert.Single(t.Posts); // token fetched once and reused
    }

    [Fact]
    public async Task TokenRefetchedWhenExpired()
    {
        var t = new QueueTransport();
        t.PostResponses.Enqueue(Resp.Json(200, new { access_token = "first", expires_in = 0 }));
        t.PostResponses.Enqueue(Resp.Json(200, new { access_token = "second", expires_in = 3600 }));
        t.GetResponses.Enqueue(Resp.Json(200, new { }));
        t.GetResponses.Enqueue(Resp.Json(200, new { }));
        // A clock that advances so the 0-expiry token is stale by the 2nd call.
        var ticks = new Queue<double>(new double[] { 0.0, 0.0, 100.0, 100.0, 100.0, 100.0 });
        var c = new ApiHttp(Cfg(), transport: t, clock: () => ticks.Dequeue());

        await c.GetAsync("/api/company-data/changes"); // fetches "first" (expires_in=0 → already stale)
        await c.GetAsync("/api/company-data/changes"); // must refetch → "second"
        Assert.Equal(2, t.Posts.Count);
        Assert.Equal("Bearer second", t.Gets[1].Headers["Authorization"]);
    }

    [Fact]
    public async Task TokenFetchFailureThrowsAuthException()
    {
        var t = new QueueTransport();
        t.PostResponses.Enqueue(Resp.Json(401, new { error_key = "oauth.bad_client" }));
        var c = MakeClient(t);
        await Assert.ThrowsAsync<AuthException>(() => c.GetAsync("/api/company-data/changes"));
    }

    // ── 401 refresh-and-retry ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Status401TriggersOneRefreshAndRetryThenSucceeds()
    {
        var t = new QueueTransport();
        t.PostResponses.Enqueue(Resp.TokenOk());
        t.PostResponses.Enqueue(Resp.TokenOk()); // initial + one refresh
        t.GetResponses.Enqueue(Resp.Json(401, new { error_key = "auth.expired" }));
        t.GetResponses.Enqueue(Resp.Json(200, new { recovered = true }));
        var c = MakeClient(t);

        var body = await c.GetAsync("/api/company-data/connections");
        Assert.True(body.Get("recovered").RawScalar as bool? ?? false);
        Assert.Equal(2, t.Posts.Count); // token refreshed exactly once
        Assert.Equal(2, t.Gets.Count);  // original + retry
    }

    [Fact]
    public async Task Status401AfterRefreshThrowsAuthException()
    {
        var t = new QueueTransport();
        t.PostResponses.Enqueue(Resp.TokenOk());
        t.PostResponses.Enqueue(Resp.TokenOk());
        t.GetResponses.Enqueue(Resp.Json(401, new { error_key = "auth.expired" }));
        t.GetResponses.Enqueue(Resp.Json(401, new { error_key = "auth.expired" }));
        var c = MakeClient(t);
        await Assert.ThrowsAsync<AuthException>(() => c.GetAsync("/api/company-data/connections"));
        Assert.Equal(2, t.Posts.Count); // only ONE refresh, then gives up
    }

    // ── 429 backoff ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Status429WithRetryAfterBacksOffThenSucceeds()
    {
        var t = new QueueTransport();
        t.PostResponses.Enqueue(Resp.TokenOk());
        t.GetResponses.Enqueue(Resp.Json(429, new { error_key = "rate.limited" },
            new Dictionary<string, string> { ["Retry-After"] = "2" }));
        t.GetResponses.Enqueue(Resp.Json(200, new { done = true }));
        var sleeps = new List<double>();
        var c = MakeClient(t, sleeps: sleeps);

        var body = await c.GetAsync("/api/company-data/changes");
        Assert.True(body.Get("done").RawScalar as bool? ?? false);
        Assert.Equal(new[] { 2.0 }, sleeps); // honored Retry-After
    }

    [Fact]
    public async Task Status429ExhaustsRetriesThenThrowsRateLimitException()
    {
        var t = new QueueTransport();
        t.PostResponses.Enqueue(Resp.TokenOk());
        for (var i = 0; i < 10; i++)
            t.GetResponses.Enqueue(Resp.Json(429, new { error_key = "rate.limited" },
                new Dictionary<string, string> { ["Retry-After"] = "1" }));
        var sleeps = new List<double>();
        var c = MakeClient(t, sleeps: sleeps, maxRetries429: 3);

        var ex = await Assert.ThrowsAsync<RateLimitException>(() => c.GetAsync("/api/company-data/connections"));
        Assert.Equal(1.0, ex.RetryAfter);
        Assert.Equal(429, ex.Status);
        Assert.Equal("rate.limited", ex.ErrorKey);
        Assert.Equal(3, sleeps.Count); // 3 bounded retries
        Assert.Equal(4, t.Gets.Count); // 4 GET attempts total
    }

    [Fact]
    public async Task Status429PendingCapSurfacesImmediatelyWithoutRetry()
    {
        // #481: a twofa.pending_cap 429 can never be cleared by a retry — it must surface at once as
        // ApiException, NOT go through the Retry-After backoff (which every other 429 gets).
        var t = new QueueTransport();
        t.PostResponses.Enqueue(Resp.TokenOk());
        t.GetResponses.Enqueue(Resp.Json(429, new { error_key = "twofa.pending_cap" },
            new Dictionary<string, string> { ["Retry-After"] = "2" }));
        t.GetResponses.Enqueue(Resp.Json(200, new { should = "not be reached" }));
        var sleeps = new List<double>();
        var c = MakeClient(t, sleeps: sleeps);

        var ex = await Assert.ThrowsAsync<ApiException>(() => c.GetAsync("/api/service-2fa/challenges"));
        Assert.Equal(429, ex.Status);
        Assert.Equal("twofa.pending_cap", ex.ErrorKey);
        Assert.IsNotType<RateLimitException>(ex); // immediate ApiException, not the 429 rate-limit path
        Assert.Empty(sleeps);          // no backoff sleep
        Assert.Single(t.Gets);         // no retry — the 200 was never consumed
    }

    [Fact]
    public async Task Status429DefaultBackoffWhenNoRetryAfter()
    {
        var t = new QueueTransport();
        t.PostResponses.Enqueue(Resp.TokenOk());
        t.GetResponses.Enqueue(Resp.Json(429, new { error_key = "rate.limited" })); // no Retry-After
        t.GetResponses.Enqueue(Resp.Json(200, new { ok = 1 }));
        var sleeps = new List<double>();
        var c = MakeClient(t, sleeps: sleeps);
        var body = await c.GetAsync("/api/company-data/changes");
        Assert.Equal(1L, (body.Get("ok").RawScalar as long?));
        Assert.Single(sleeps);
        Assert.True(sleeps[0] > 0); // exponential default kicked in
    }

    // ── ApiException mapping ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task NonSuccessMapsToApiExceptionWithErrorKey()
    {
        var t = new QueueTransport();
        t.PostResponses.Enqueue(Resp.TokenOk());
        t.GetResponses.Enqueue(Resp.Json(403, new
        {
            error = "Not a registered service client",
            error_key = "company_data.no_client",
        }));
        var c = MakeClient(t);
        var ex = await Assert.ThrowsAsync<ApiException>(() => c.GetAsync("/api/company-data/connections"));
        Assert.Equal(403, ex.Status);
        Assert.Equal("company_data.no_client", ex.ErrorKey);
        Assert.IsNotType<RateLimitException>(ex); // RateLimitException subclasses ApiException, but this isn't 429
    }

    [Fact]
    public async Task Status404MapsToApiException()
    {
        var t = new QueueTransport();
        t.PostResponses.Enqueue(Resp.TokenOk());
        t.GetResponses.Enqueue(Resp.Json(404, new { error_key = "company_data.connection_not_found" }));
        var c = MakeClient(t);
        var ex = await Assert.ThrowsAsync<ApiException>(() => c.GetAsync("/api/company-data/connections/zzz"));
        Assert.Equal(404, ex.Status);
        Assert.Equal("company_data.connection_not_found", ex.ErrorKey);
    }

    // ── XML format ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task XmlAcceptHeaderAndParsing()
    {
        var xml =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<response>" +
            "<request_fields>" +
            "<item><slug>work_email</slug><label>Work email</label><type>email</type>" +
            "<one_time>false</one_time><mandatory_provide>true</mandatory_provide>" +
            "<mandatory_connected>false</mandatory_connected></item>" +
            "<item><slug>logo</slug><label>Logo</label><type>photo</type>" +
            "<one_time>false</one_time><mandatory_provide>false</mandatory_provide>" +
            "<mandatory_connected>false</mandatory_connected></item>" +
            "</request_fields>" +
            "</response>";
        var t = new QueueTransport();
        t.PostResponses.Enqueue(Resp.TokenOk());
        t.GetResponses.Enqueue(Resp.Text(200, xml));
        var c = MakeClient(t, fmt: "xml");

        var body = await c.GetAsync("/api/company-data/request-fields");
        Assert.Equal("application/xml", t.Gets[0].Headers["Accept"]);
        Assert.Equal(NodeKind.Object, body.Kind);
        var fields = body.Get("request_fields").AsList();
        Assert.Equal(2, fields.Count);
        Assert.Equal("work_email", fields[0].Get("slug").AsString());
        Assert.Equal("email", fields[0].Get("type").AsString());
        // Booleans come back as the "true"/"false" strings the API wrote.
        Assert.Equal("false", fields[0].Get("one_time").AsString());
        Assert.Equal("true", fields[0].Get("mandatory_provide").AsString());
    }

    [Fact]
    public async Task XmlErrorBodyCarriesErrorKey()
    {
        var xml =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<response><error>nope</error><error_key>company_data.no_client</error_key></response>";
        var t = new QueueTransport();
        t.PostResponses.Enqueue(Resp.TokenOk());
        t.GetResponses.Enqueue(Resp.Text(403, xml));
        var c = MakeClient(t, fmt: "xml");
        var ex = await Assert.ThrowsAsync<ApiException>(() => c.GetAsync("/api/company-data/connections"));
        Assert.Equal("company_data.no_client", ex.ErrorKey);
    }

    [Fact]
    public async Task XmlSingleItemListIsStillAList()
    {
        var xml =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<response><changes><item><id>c1</id><event>connection_created</event>" +
            "<person_user_id>u1</person_user_id></item></changes></response>";
        var t = new QueueTransport();
        t.PostResponses.Enqueue(Resp.TokenOk());
        t.GetResponses.Enqueue(Resp.Text(200, xml));
        var c = MakeClient(t, fmt: "xml");
        var body = await c.GetAsync("/api/company-data/changes");
        Assert.Equal(NodeKind.List, body.Get("changes").Kind);
        Assert.Equal("connection_created", body.Get("changes").AsList()[0].Get("event").AsString());
    }

    // ── XXE safety ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task XmlParsingIsXxeSafe()
    {
        // A DTD with an external/local entity reference. An XXE-vulnerable parser would resolve it;
        // our parser prohibits DTDs entirely → it throws (surfaced as an ApiException), never reads
        // /etc/passwd or expands a billion-laughs bomb.
        var xml =
            "<?xml version=\"1.0\"?>" +
            "<!DOCTYPE response [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>" +
            "<response><error>&xxe;</error></response>";
        var t = new QueueTransport();
        t.PostResponses.Enqueue(Resp.TokenOk());
        t.GetResponses.Enqueue(Resp.Text(200, xml));
        var c = MakeClient(t, fmt: "xml");
        await Assert.ThrowsAsync<ApiException>(() => c.GetAsync("/api/company-data/changes"));
    }
}
