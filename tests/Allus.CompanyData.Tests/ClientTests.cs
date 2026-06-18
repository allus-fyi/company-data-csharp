// Client-facade tests. Everything is MOCKED — no live API. A RouterTransport
// replays canned hardened API JSON: the token, the request-fields catalog, the connections list, a
// single connection, the logs, the changes feed, and a slot file endpoint. Ciphertext fields reuse
// the shared decryption vector's real wrapper + key (written to a temp PEM the Client loads at
// construction), so this exercises the whole facade → http → crypto → model wiring end-to-end.

using System.Security.Cryptography;
using System.Text.Json;
using Allus.CompanyData;
using Xunit;

namespace Allus.CompanyData.Tests;

public sealed class ClientTests : IDisposable
{
    private readonly string _dir;
    private readonly string _pemPath;
    private readonly Config _config;

    public ClientTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "allus-client-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _pemPath = Path.Combine(_dir, "service-key.pem");
        File.WriteAllText(_pemPath, Vector.EncryptedPem);
        _config = new Config
        {
            ApiUrl = "https://api.allme.fyi",
            ClientId = "svc_abc",
            ClientSecret = "topsecret",
            ServicePrivateKey = _pemPath,
            KeyPassphrase = Vector.Passphrase,
            CacheDir = Path.Combine(_dir, "cache"),
        };
    }

    public void Dispose() => Directory.Delete(_dir, true);

    private static string Sha256Hex(byte[] data) => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    private (Client Client, RouterTransport Transport) Make(Func<string, IReadOnlyDictionary<string, string>?, HttpResult> router)
    {
        var transport = new RouterTransport(router);
        return (new Client(_config, http: new ApiHttp(_config, transport: transport)), transport);
    }

    private static Node EncryptForKey(string plaintext)
    {
        using var key = Vector.PrivateKey();
        return Encryptor.Wrap(key, plaintext);
    }

    private static readonly object RequestFieldsBody = new
    {
        request_fields = new object[]
        {
            new { slug = "work_email", label = "Work email", type = "email", one_time = false, mandatory_provide = true, mandatory_connected = false },
            new { slug = "billing_address", label = "Billing address", type = "address", one_time = false, mandatory_provide = false, mandatory_connected = false },
            new { slug = "logo", label = "Logo", type = "photo", one_time = true, mandatory_provide = false, mandatory_connected = false },
        },
    };

    // ── request_fields() caches ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task RequestFieldsParsedAndCached()
    {
        var calls = 0;
        var (client, _) = Make((url, q) =>
        {
            if (url.EndsWith("/request-fields")) { calls++; return Resp.Json(200, RequestFieldsBody); }
            throw new Xunit.Sdk.XunitException("unexpected GET " + url);
        });
        using (client)
        {
            var fields = await client.RequestFieldsAsync();
            Assert.Equal(new[] { "work_email", "billing_address", "logo" }, fields.Select(f => f.Slug));
            Assert.True(fields[0].Mandatory);

            await client.RequestFieldsAsync(); // cached — does not re-fetch
            Assert.Equal(1, calls);
        }
    }

    // ── connections() lazy stream with decrypted values ───────────────────────────────────────

    [Fact]
    public async Task ConnectionsYieldsTypedDecrypted()
    {
        var addrWrapper = EncryptForKey(JsonSerializer.Serialize(new { city = "Utrecht", country = "NL" }));
        var page1 = new
        {
            total = 1,
            items = new object[]
            {
                new
                {
                    connection_id = "csc-1", user_id = "person-1", display_name = "Anna",
                    connected_at = "2026-06-10T00:00:00Z",
                    values = new Dictionary<string, object>
                    {
                        ["work_email"] = new { value = JsonSerializer.Deserialize<JsonElement>(Vector.TextWrapper.GetRawText()), live = true, updatedAt = "2026-06-17T10:00:00Z" },
                        ["billing_address"] = new { value = JsonSerializer.Deserialize<JsonElement>(addrWrapper.ToJsonString()), live = false },
                        ["logo"] = new { value_url = "https://api.allme.fyi/api/company-data/connections/csc-1/slots/sf-9/file", live = true },
                    },
                    pending_consent = Array.Empty<object>(),
                },
            },
        };

        var (client, transport) = Make((url, q) =>
        {
            if (url.EndsWith("/request-fields")) return Resp.Json(200, RequestFieldsBody);
            if (url.EndsWith("/connections")) return Resp.Json(200, page1);
            throw new Xunit.Sdk.XunitException("unexpected GET " + url);
        });
        using (client)
        {
            var conns = new List<Connection>();
            await foreach (var c in client.ConnectionsAsync(limit: 100)) conns.Add(c);
            Assert.Single(conns);
            var conn = conns[0];
            Assert.Equal("csc-1", conn.Id);
            Assert.Equal("person-1", conn.PersonId);
            Assert.Equal("Anna", conn.DisplayName);

            Assert.Equal(Vector.TextPlaintext, conn.Values["work_email"].ValueObj);
            Assert.True(conn.Values["work_email"].Live);
            var addr = Assert.IsAssignableFrom<IDictionary<string, object?>>(conn.Values["billing_address"].ValueObj);
            Assert.Equal("Utrecht", addr["city"]);
            Assert.IsType<BinaryHandle>(conn.Values["logo"].ValueObj);

            var connGets = transport.Gets.Where(g => g.Url.EndsWith("/connections")).ToList();
            Assert.Single(connGets);
            Assert.DoesNotContain(transport.Gets, g => g.Url.Contains("/file"));
        }
    }

    [Fact]
    public async Task ConnectionsAutoPages()
    {
        object Item(int i) => new { connection_id = $"c{i}", user_id = $"p{i}", display_name = $"N{i}", values = new Dictionary<string, object>() };
        var pages = new[]
        {
            new { total = 3, items = new[] { Item(1), Item(2) } }, // full page (==limit 2)
            new { total = 3, items = new[] { Item(3) } },          // short page → stop
        };
        var i = 0;
        var (client, transport) = Make((url, q) =>
        {
            if (url.EndsWith("/request-fields")) return Resp.Json(200, new { request_fields = Array.Empty<object>() });
            if (url.EndsWith("/connections")) return Resp.Json(200, pages[i++]);
            throw new Xunit.Sdk.XunitException("unexpected GET " + url);
        });
        using (client)
        {
            var ids = new List<string?>();
            await foreach (var c in client.ConnectionsAsync(limit: 2)) ids.Add(c.Id);
            Assert.Equal(new[] { "c1", "c2", "c3" }, ids);
            var offsets = transport.Gets.Where(g => g.Url.EndsWith("/connections"))
                .Select(g => g.Query!["offset"]).ToList();
            Assert.Equal(new[] { "0", "2" }, offsets);
        }
    }

    // ── binary handle fetches the slot endpoint + decrypts ─────────────────────────────────────

    [Fact]
    public async Task BinaryHandleFetchesSlotAndDecrypts()
    {
        var page = new
        {
            total = 1,
            items = new object[]
            {
                new
                {
                    connection_id = "csc-1", user_id = "person-1", display_name = "Anna",
                    values = new Dictionary<string, object>
                    {
                        ["logo"] = new { value_url = "https://api.allme.fyi/api/company-data/connections/csc-1/slots/sf-9/file", live = true },
                    },
                },
            },
        };
        var (client, transport) = Make((url, q) =>
        {
            if (url.EndsWith("/request-fields")) return Resp.Json(200, RequestFieldsBody);
            if (url.EndsWith("/connections")) return Resp.Json(200, page);
            if (url.EndsWith("/slots/sf-9/file"))
                return Resp.Json(200, new { encrypted = true, value = JsonSerializer.Deserialize<JsonElement>(Vector.BinaryWrapper.GetRawText()) });
            throw new Xunit.Sdk.XunitException("unexpected GET " + url);
        });
        using (client)
        {
            var conns = new List<Connection>();
            await foreach (var c in client.ConnectionsAsync()) conns.Add(c);
            var handle = Assert.IsType<BinaryHandle>(conns[0].Values["logo"].ValueObj);
            Assert.DoesNotContain(transport.Gets, g => g.Url.Contains("/file")); // lazy

            var data = await handle.BytesAsync();
            Assert.Contains(transport.Gets, g => g.Url.EndsWith("/slots/sf-9/file"));
            Assert.Equal(Vector.InnerFullSha256, Sha256Hex(data));
        }
    }

    // ── connection(id) ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ConnectionById()
    {
        var detail = new
        {
            connection_id = "csc-7",
            user_id = "person-7",
            values = new Dictionary<string, object>
            {
                ["work_email"] = new { value = JsonSerializer.Deserialize<JsonElement>(Vector.TextWrapper.GetRawText()), live = true },
            },
        };
        var (client, _) = Make((url, q) =>
        {
            if (url.EndsWith("/request-fields")) return Resp.Json(200, RequestFieldsBody);
            if (url.EndsWith("/connections/csc-7")) return Resp.Json(200, detail);
            throw new Xunit.Sdk.XunitException("unexpected GET " + url);
        });
        using (client)
        {
            var conn = await client.ConnectionAsync("csc-7");
            Assert.Equal("csc-7", conn.Id);
            Assert.Equal("person-7", conn.PersonId);
            Assert.Equal(Vector.TextPlaintext, conn.Values["work_email"].ValueObj);
        }
    }

    // ── logs() ─────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task LogsDeserialize()
    {
        var body = new
        {
            total = 2,
            items = new object[]
            {
                new { type = "email", message = "stale-queue alert", metadata = new { days = 3 }, created_at = "2026-06-17T06:00:00Z" },
                new { type = "purge", message = "purged 4", metadata = new { count = 4 }, created_at = "2026-06-17T07:00:00Z" },
            },
        };
        var (client, transport) = Make((url, q) =>
        {
            if (url.EndsWith("/logs")) return Resp.Json(200, body);
            throw new Xunit.Sdk.XunitException("unexpected GET " + url);
        });
        using (client)
        {
            var logs = await client.LogsAsync(limit: 50);
            Assert.Equal(2, logs.Count);
            Assert.Equal("email", logs[0].Type);
            var meta = Assert.IsAssignableFrom<IDictionary<string, object?>>(logs[0].Metadata);
            Assert.Equal(3L, meta["days"]);
            Assert.Equal("50", transport.Gets[0].Query!["limit"]);
        }
    }

    // ── process_changes() drains the feed through the pump one-by-one ──────────────────────────

    [Fact]
    public async Task ProcessChangesDrainsThroughPump()
    {
        var served = false;
        var (client, _) = Make((url, q) =>
        {
            if (url.EndsWith("/request-fields")) return Resp.Json(200, RequestFieldsBody);
            if (url.EndsWith("/changes"))
            {
                if (served) return Resp.Json(200, new { changes = Array.Empty<object>() });
                served = true;
                return Resp.Json(200, new
                {
                    changes = new object[]
                    {
                        new { id = "chg-1", @event = "field_updated", person_user_id = "person-1", slug = "work_email", value = JsonSerializer.Deserialize<JsonElement>(Vector.TextWrapper.GetRawText()), live = true, at = "2026-06-17T12:00:00Z" },
                        new { id = "chg-2", @event = "connection_created", person_user_id = "person-2", at = "2026-06-17T12:05:00Z" },
                    },
                });
            }
            throw new Xunit.Sdk.XunitException("unexpected GET " + url);
        });
        using (client)
        {
            var seen = new List<(string? Id, string? Event, object? Value)>();
            await client.ProcessChangesAsync(c => { seen.Add((c.Id, c.Event, c.ValueObj)); return Task.CompletedTask; });

            Assert.Equal(new[] { "chg-1", "chg-2" }, seen.Select(s => s.Id));
            Assert.Equal("field_updated", seen[0].Event);
            Assert.Equal(Vector.TextPlaintext, seen[0].Value);
            Assert.Equal("connection_created", seen[1].Event);
            Assert.Null(seen[1].Value);
            Assert.Empty(client.Pump.Buffer.Pending());
        }
    }

    // ── construction reads the key once (config-only keys) ────────────────────────

    [Fact]
    public void FromConfigLoadsKey()
    {
        var pem = Path.Combine(_dir, "k.pem");
        File.WriteAllText(pem, Vector.EncryptedPem);
        var cfgPath = Path.Combine(_dir, "config.json");
        File.WriteAllText(cfgPath, JsonSerializer.Serialize(new
        {
            api_url = "https://api.allme.fyi", client_id = "svc_abc", client_secret = "s",
            service_private_key = pem, key_passphrase = Vector.Passphrase,
            cache_dir = Path.Combine(_dir, "cache2"),
        }));
        using var client = Client.FromConfig(cfgPath);
        // The key is loaded into memory and the decrypt closure works on the vector.
        Assert.Equal(Vector.TextPlaintext, client.DecryptValueForTest(Vector.TextWrapperNode));
    }

    [Fact]
    public void FromConfigBadPassphraseIsConfigException()
    {
        var pem = Path.Combine(_dir, "k2.pem");
        File.WriteAllText(pem, Vector.EncryptedPem);
        var cfgPath = Path.Combine(_dir, "config2.json");
        File.WriteAllText(cfgPath, JsonSerializer.Serialize(new
        {
            api_url = "https://api.allme.fyi", client_id = "x", client_secret = "s",
            service_private_key = pem, key_passphrase = "WRONG",
            cache_dir = Path.Combine(_dir, "cache3"),
        }));
        Assert.Throws<ConfigException>(() => Client.FromConfig(cfgPath));
    }
}
