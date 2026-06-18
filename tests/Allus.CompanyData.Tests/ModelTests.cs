// Output-model tests. Drives the model factories with hardened API payloads shaped
// exactly like the live company-data API output (slug-keyed values; NO person source field).
// Ciphertext fields reuse the shared decryption vector's real wrapper, decrypted via an injected
// DecryptValue closure — so this also exercises the model→crypto wiring end-to-end.

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Allus.CompanyData;
using Xunit;

namespace Allus.CompanyData.Tests;

public class ModelTests
{
    private static string Sha256Hex(byte[] data) => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    private static DecryptValue DecryptWith(RSA key) => w => Crypto.Decrypt(w, key);

    private static TypeForSlug TypeResolver()
    {
        var types = new Dictionary<string, string>
        {
            ["work_email"] = "email",
            ["billing_address"] = "address",
            ["dob"] = "date",
            ["logo"] = "photo",
        };
        return slug => types.GetValueOrDefault(slug);
    }

    private static Node Obj(Dictionary<string, Node> map) => Node.Object(map);
    private static Node S(object? v) => Node.Scalar(v);

    // ── RequestField definitions ─────────────────────────────────────────────────────────────

    [Fact]
    public void RequestFieldsParsedAndMandatoryFolded()
    {
        var body = Node.FromJsonString(JsonSerializer.Serialize(new
        {
            request_fields = new object[]
            {
                new { slug = "work_email", label = "Work email", type = "email", one_time = false, mandatory_provide = true, mandatory_connected = false },
                new { slug = "logo", label = "Logo", type = "photo", one_time = true, mandatory_provide = false, mandatory_connected = false },
                new { slug = "ref", label = "Ref", type = "text", one_time = false, mandatory_provide = false, mandatory_connected = true },
            },
        }));
        var fields = RequestField.ListFromApi(body);
        Assert.Equal(new[] { "work_email", "logo", "ref" }, fields.Select(f => f.Slug));
        Assert.True(fields[0].Mandatory);    // mandatory_provide
        Assert.False(fields[1].Mandatory);
        Assert.True(fields[1].OneTime);
        Assert.True(fields[2].Mandatory);    // mandatory_connected folds in
    }

    [Fact]
    public void RequestFieldCoercesXmlBoolStrings()
    {
        var body = Node.FromJsonString(JsonSerializer.Serialize(new
        {
            request_fields = new object[]
            {
                new { slug = "x", label = "X", type = "text", one_time = "false", mandatory_provide = "true", mandatory_connected = "false" },
            },
        }));
        var f = RequestField.ListFromApi(body)[0];
        Assert.False(f.OneTime);
        Assert.True(f.Mandatory);
    }

    // ── Connection detail → typed, slug-keyed values ───────────────────────────────────────────

    [Fact]
    public void ConnectionDetailTypedSlugKeyed()
    {
        using var key = Vector.PrivateKey();
        var addr = Encryptor.Wrap(key, JsonSerializer.Serialize(new { city = "Utrecht", country = "NL" }));
        var dob = Encryptor.Wrap(key, "1990-04-23");

        var detail = Obj(new()
        {
            ["connection_id"] = S("csc-1"),
            ["user_id"] = S("person-1"),
            ["values"] = Obj(new()
            {
                ["work_email"] = Obj(new() { ["value"] = Vector.TextWrapperNode, ["live"] = S(true), ["updatedAt"] = S("2026-06-17T10:00:00Z") }),
                ["billing_address"] = Obj(new() { ["value"] = addr, ["live"] = S(false), ["updatedAt"] = S("2026-06-16T09:00:00Z") }),
                ["dob"] = Obj(new() { ["value"] = dob, ["live"] = S(true), ["updatedAt"] = S("2026-06-15T08:00:00Z") }),
                ["logo"] = Obj(new()
                {
                    ["value_url"] = S("https://api.allme.fyi/api/company-data/connections/csc-1/slots/sf-9/file"),
                    ["live"] = S(true), ["updatedAt"] = S("2026-06-14T07:00:00Z"),
                }),
            }),
        });
        var identity = Obj(new() { ["display_name"] = S("Anna"), ["connected_at"] = S("2026-06-10T00:00:00Z") });

        var conn = Connection.FromApi(detail, TypeResolver(), DecryptWith(key), identity: identity);

        Assert.Equal("csc-1", conn.Id);
        Assert.Equal("person-1", conn.PersonId);
        Assert.Equal("Anna", conn.DisplayName);
        Assert.NotNull(conn.ConnectedAt);

        var email = conn.Values["work_email"];
        Assert.Equal(Vector.TextPlaintext, email.ValueObj);
        Assert.True(email.Live);
        Assert.NotNull(email.UpdatedAt);

        var addrV = conn.Values["billing_address"];
        var addrMap = Assert.IsAssignableFrom<IDictionary<string, object?>>(addrV.ValueObj);
        Assert.Equal("Utrecht", addrMap["city"]);
        Assert.Equal("NL", addrMap["country"]);
        Assert.False(addrV.Live);

        var dobV = conn.Values["dob"];
        Assert.Equal(new DateOnly(1990, 4, 23), dobV.ValueObj);

        var logo = conn.Values["logo"];
        var handle = Assert.IsType<BinaryHandle>(logo.ValueObj);
        Assert.EndsWith("/slots/sf-9/file", handle.ValueUrl);
    }

    [Fact]
    public async Task BinaryHandleLazyFetchAndDecrypt()
    {
        using var key = Vector.PrivateKey();
        string? capturedUrl = null;
        BinaryFetch fetch = (url, ct) => { capturedUrl = url; return Task.FromResult<object>(Vector.BinaryWrapperNode); };

        var detail = Obj(new()
        {
            ["connection_id"] = S("csc-1"),
            ["user_id"] = S("person-1"),
            ["values"] = Obj(new()
            {
                ["logo"] = Obj(new()
                {
                    ["value_url"] = S("https://api.allme.fyi/api/company-data/connections/csc-1/slots/sf-9/file"),
                    ["live"] = S(true),
                }),
            }),
        });
        var conn = Connection.FromApi(detail, _ => "photo", DecryptWith(key), fetch);
        var handle = Assert.IsType<BinaryHandle>(conn.Values["logo"].ValueObj);
        Assert.Null(capturedUrl); // not fetched until .BytesAsync()

        var data = await handle.BytesAsync();
        Assert.EndsWith("/slots/sf-9/file", capturedUrl);
        Assert.Equal(Vector.InnerFullSha256, Sha256Hex(data));

        await handle.BytesAsync(); // cached — no re-fetch
    }

    [Fact]
    public void ConnectionHasNoPersonSourceField()
    {
        using var key = Vector.PrivateKey();
        var detail = Obj(new()
        {
            ["connection_id"] = S("csc-1"),
            ["user_id"] = S("person-1"),
            ["values"] = Obj(new() { ["work_email"] = Obj(new() { ["value"] = Vector.TextWrapperNode, ["live"] = S(true) }) }),
        });
        var conn = Connection.FromApi(detail, _ => "email", DecryptWith(key));
        var serialized = JsonSerializer.Serialize(conn.Raw);
        Assert.DoesNotContain("field_id", serialized);
        Assert.Equal(new[] { "work_email" }, conn.Values.Keys);
    }

    // ── Change events ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public void ChangeFieldUpdatedTypedAndIdPopulated()
    {
        using var key = Vector.PrivateKey();
        var body = Obj(new()
        {
            ["changes"] = Node.List(new List<Node>
            {
                Obj(new()
                {
                    ["id"] = S("chg-42"), ["event"] = S("field_updated"), ["person_user_id"] = S("person-1"),
                    ["slug"] = S("work_email"), ["value"] = Vector.TextWrapperNode, ["live"] = S(true),
                    ["at"] = S("2026-06-17T12:00:00Z"),
                }),
                Obj(new()
                {
                    ["id"] = S("chg-43"), ["event"] = S("connection_created"),
                    ["person_user_id"] = S("person-2"), ["at"] = S("2026-06-17T12:05:00Z"),
                }),
            }),
        });
        var changes = Change.ListFromApi(body, _ => "email", DecryptWith(key));

        var f = changes[0];
        Assert.Equal("chg-42", f.Id);
        Assert.Equal("field_updated", f.Event);
        Assert.Equal("person-1", f.PersonId);
        Assert.Equal("work_email", f.Slug);
        Assert.Equal(Vector.TextPlaintext, f.ValueObj);
        Assert.True(f.Live);
        Assert.NotNull(f.At);

        var c = changes[1];
        Assert.Equal("chg-43", c.Id);
        Assert.Equal("connection_created", c.Event);
        Assert.Null(c.Slug);
        Assert.Null(c.ValueObj);
        Assert.Null(c.Live);
    }

    [Fact]
    public async Task ChangeFieldUpdatedBinaryIsLazyHandle()
    {
        using var key = Vector.PrivateKey();
        var body = Obj(new()
        {
            ["changes"] = Node.List(new List<Node>
            {
                Obj(new()
                {
                    ["id"] = S("chg-50"), ["event"] = S("field_updated"), ["person_user_id"] = S("person-1"),
                    ["slug"] = S("logo"),
                    ["value_url"] = S("https://api.allme.fyi/api/company-data/connections/csc-1/slots/sf-9/file"),
                    ["live"] = S(true), ["at"] = S("2026-06-17T12:00:00Z"),
                }),
            }),
        });
        BinaryFetch fetch = (url, ct) => Task.FromResult<object>(Vector.BinaryWrapperNode);
        var chg = Change.ListFromApi(body, _ => "photo", DecryptWith(key), fetch)[0];
        var handle = Assert.IsType<BinaryHandle>(chg.ValueObj);
        Assert.Equal(Vector.InnerFullSha256, Sha256Hex(await handle.BytesAsync()));
    }

    [Fact]
    public void ChangeConsentEventHasSlugNoValue()
    {
        var body = Obj(new()
        {
            ["changes"] = Node.List(new List<Node>
            {
                Obj(new()
                {
                    ["id"] = S("chg-9"), ["event"] = S("consent_accepted"), ["person_user_id"] = S("p"),
                    ["slug"] = S("work_email"), ["at"] = S("2026-06-17T00:00:00Z"),
                }),
            }),
        });
        var chg = Change.ListFromApi(body, _ => "email", _ => "")[0];
        Assert.Equal("consent_accepted", chg.Event);
        Assert.Equal("work_email", chg.Slug);
        Assert.Null(chg.ValueObj); // consent events carry no value
    }

    // ── LogEntry ────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void LogEntriesParsed()
    {
        var body = Node.FromJsonString(JsonSerializer.Serialize(new
        {
            total = 2,
            items = new object[]
            {
                new { type = "email", message = "stale-queue alert", metadata = new { days = 3 }, at = "2026-06-17T06:00:00Z" },
                new { type = "purge", message = "purged 4 changes", metadata = new { count = 4 }, created_at = "2026-06-17T07:00:00Z" },
            },
        }));
        var logs = LogEntry.ListFromApi(body);
        Assert.Equal(2, logs.Count);
        Assert.Equal("email", logs[0].Type);
        var meta = Assert.IsAssignableFrom<IDictionary<string, object?>>(logs[0].Metadata);
        Assert.Equal(3L, meta["days"]);
        Assert.NotNull(logs[0].At);
        Assert.NotNull(logs[1].At); // 'created_at' fallback for 'at'
    }

    [Fact]
    public void ChangeIncludesShareCode()
    {
        // Every change event carries the person's profile share_code (nullable).
        using var key = Vector.PrivateKey();
        var body = Obj(new()
        {
            ["changes"] = Node.List(new List<Node>
            {
                Obj(new()
                {
                    ["id"] = S("chg-1"), ["event"] = S("connection_created"),
                    ["person_user_id"] = S("person-1"), ["share_code"] = S("ABC123"),
                    ["at"] = S("2026-06-17T12:00:00Z"),
                }),
                Obj(new()
                {
                    ["id"] = S("chg-2"), ["event"] = S("connection_created"),
                    ["person_user_id"] = S("person-2"), ["at"] = S("2026-06-17T12:00:00Z"), // no share_code -> null
                }),
            }),
        });
        var changes = Change.ListFromApi(body, _ => null, DecryptWith(key));
        Assert.Equal("ABC123", changes[0].ShareCode);
        Assert.Null(changes[1].ShareCode);
    }
}
