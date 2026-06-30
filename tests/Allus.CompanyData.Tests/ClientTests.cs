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

    // ── company documents (write) ────────────────────────────────────────────────────────────────

    private (Client Client, RouterTransport Transport) MakeRw(
        Func<string, IReadOnlyDictionary<string, string>?, HttpResult> getRouter,
        Func<string, string, byte[]?, HttpResult> writeRouter)
    {
        var transport = new RouterTransport(getRouter, writeRouter);
        return (new Client(_config, http: new ApiHttp(_config, transport: transport)), transport);
    }

    private static string VectorPubSpkiB64()
    {
        using var key = Vector.PrivateKey();
        return Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());
    }

    private static HttpResult NoGet(string url, IReadOnlyDictionary<string, string>? q)
        => throw new Xunit.Sdk.XunitException("unexpected GET " + url);

    private static JsonElement ParseBody(byte[]? body)
    {
        using var doc = JsonDocument.Parse(System.Text.Encoding.UTF8.GetString(body!));
        return doc.RootElement.Clone();
    }

    [Fact]
    public async Task CreateDocumentBroadcastJsonIsPlaintext()
    {
        JsonElement posted = default;
        var (client, _) = MakeRw(NoGet, (method, url, body) =>
        {
            Assert.Equal("POST", method);
            Assert.EndsWith("/documents", url);
            posted = ParseBody(body);
            return Resp.Json(201, new
            {
                id = "d1", kind = "document", name = "Terms", description = (string?)null,
                status = "active", payload_kind = "json", is_private = false,
                value = new { url = "x", v = "1" }, metadata = (object?)null,
                created_at = (string?)null, updated_at = (string?)null,
            });
        });
        using (client)
        {
            var doc = await client.CreateDocumentAsync(name: "Terms", payloadKind: "json",
                jsonValue: new { url = "x", v = "1" }, status: "active");
            Assert.Equal(JsonValueKind.Null, posted.GetProperty("target").ValueKind);
            var val = posted.GetProperty("value");
            Assert.Equal("x", val.GetProperty("url").GetString()); // plaintext, no _enc
            Assert.False(val.TryGetProperty("_enc", out _));
            Assert.False(posted.GetProperty("is_private").GetBoolean());
            Assert.Equal("d1", doc.Id);
            Assert.Equal("active", doc.Status);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CreateDocumentPerPersonEncryptsForBothPrivacy(bool isPrivate)
    {
        var spki = VectorPubSpkiB64();
        var keysFetched = 0;
        JsonElement captured = default;
        var (client, _) = MakeRw(
            (url, q) =>
            {
                Assert.EndsWith("/api/keys/ABC123", url);
                keysFetched++;
                return Resp.Json(200, new { public_key = spki });
            },
            (method, url, body) =>
            {
                captured = ParseBody(body);
                return Resp.Json(201, new
                {
                    id = "d2", kind = "document", name = "PP", description = (string?)null,
                    status = "active", payload_kind = "json", is_private = isPrivate,
                    value = new { }, metadata = (object?)null,
                    created_at = (string?)null, updated_at = (string?)null,
                });
            });
        using (client)
        {
            var doc = await client.CreateDocumentAsync(name: "PP", payloadKind: "json",
                jsonValue: new { plan = "pro" }, connectionId: "conn-1", shareCode: "ABC123",
                isPrivate: isPrivate);
            Assert.Equal(1, keysFetched); // fetched the recipient key
            var val = captured.GetProperty("value");
            Assert.Equal(JsonValueKind.Object, val.ValueKind);
            Assert.Equal(1, val.GetProperty("_enc").GetInt32()); // ENCRYPTED, any is_private
            Assert.True(val.TryGetProperty("k", out _) && val.TryGetProperty("iv", out _) && val.TryGetProperty("d", out _));
            Assert.Equal("conn-1", captured.GetProperty("target").GetProperty("connection_id").GetString());
            Assert.Equal(isPrivate, captured.GetProperty("is_private").GetBoolean());

            // round-trips through the SDK's own decrypt → the original plaintext
            using var priv = Vector.PrivateKey();
            var plaintext = Crypto.Decrypt(Node.FromJson(val), priv);
            using var pdoc = JsonDocument.Parse(plaintext);
            Assert.Equal("pro", pdoc.RootElement.GetProperty("plan").GetString());
            Assert.Equal("d2", doc.Id);
        }
    }

    [Fact]
    public async Task CreateDocumentPrivateBroadcastThrows()
    {
        var (client, _) = MakeRw(NoGet, (m, u, b) => Resp.Json(200, new { }));
        using (client)
        {
            await Assert.ThrowsAsync<ConfigException>(() =>
                client.CreateDocumentAsync(name: "x", payloadKind: "json",
                    jsonValue: new { a = 1 }, isPrivate: true));
        }
    }

    [Fact]
    public async Task CreateDocumentContractWithoutTargetThrows()
    {
        var (client, _) = MakeRw(NoGet, (m, u, b) => Resp.Json(200, new { }));
        using (client)
        {
            await Assert.ThrowsAsync<ConfigException>(() =>
                client.CreateDocumentAsync(name: "Agreement", payloadKind: "json",
                    kind: "agreement", requiresSignature: true, jsonValue: new { a = 1 }));
        }
    }

    [Fact]
    public async Task CreateDocumentInvalidKindThrows()
    {
        var (client, _) = MakeRw(NoGet, (m, u, b) => Resp.Json(200, new { }));
        using (client)
        {
            await Assert.ThrowsAsync<ConfigException>(() =>
                client.CreateDocumentAsync(name: "x", payloadKind: "json",
                    kind: "invalid", jsonValue: new { a = 1 }));
        }
    }

    [Fact]
    public async Task CreateDocumentFileBroadcastUploadsFileDataUri()
    {
        var (client, transport) = MakeRw(NoGet, (method, url, body) =>
        {
            if (url.EndsWith("/documents"))
                return Resp.Json(201, new
                {
                    id = "f1", kind = "document", name = "C", description = (string?)null,
                    status = "active", payload_kind = "file", is_private = false,
                    value = new { _pending = true }, metadata = (object?)null,
                    created_at = (string?)null, updated_at = (string?)null,
                });
            Assert.EndsWith("/documents/f1/file", url);
            return Resp.Json(200, new { id = "f1" });
        });
        using (client)
        {
            var raw = System.Text.Encoding.UTF8.GetBytes("%PDF-1.4 x");
            await client.CreateDocumentAsync(name: "C", payloadKind: "file",
                fileBytes: raw, fileMime: "application/pdf");
            Assert.EndsWith("/documents", transport.Writes[0].Url);
            // first POST has a JSON target=null body
            Assert.Equal(JsonValueKind.Null, ParseBody(transport.Writes[0].Body).GetProperty("target").ValueKind);
            Assert.EndsWith("/documents/f1/file", transport.Writes[1].Url);
            // JSON {"file": "data:application/pdf;base64,…", "original_name": "C.pdf"} (NOT raw bytes).
            // The extensionless human name "C" derives its extension from the MIME (application/pdf).
            var fileBody = ParseBody(transport.Writes[1].Body);
            Assert.Equal("C.pdf", fileBody.GetProperty("original_name").GetString());
            var fileUri = fileBody.GetProperty("file").GetString()!;
            Assert.StartsWith("data:application/pdf;base64,", fileUri);
            Assert.Equal(raw, Convert.FromBase64String(fileUri.Split(',', 2)[1]));
        }
    }

    [Fact]
    public async Task CreateDocumentFileUploadFailureDeletesDanglingDoc()
    {
        // The metadata row is created first; if the /file upload then fails, the just-created
        // (still {"_pending": true}) document must be best-effort DELETEd and the original error rethrown.
        var (client, transport) = MakeRw(NoGet, (method, url, body) =>
        {
            if (method == "POST" && url.EndsWith("/documents"))
                return Resp.Json(201, new
                {
                    id = "f9", kind = "document", name = "C", description = (string?)null,
                    status = "active", payload_kind = "file", is_private = false,
                    value = new { _pending = true }, metadata = (object?)null,
                    created_at = (string?)null, updated_at = (string?)null,
                });
            if (method == "POST" && url.EndsWith("/documents/f9/file"))
                return Resp.Json(500, new { error_key = "documents.upload_failed" }); // upload fails
            if (method == "DELETE" && url.EndsWith("/documents/f9"))
                return Resp.Json(200, new { }); // cleanup succeeds
            throw new Xunit.Sdk.XunitException($"unexpected write {method} {url}");
        });
        using (client)
        {
            // the original upload error surfaces…
            await Assert.ThrowsAsync<ApiException>(() =>
                client.CreateDocumentAsync(name: "C", payloadKind: "file",
                    fileBytes: System.Text.Encoding.UTF8.GetBytes("%PDF-1.4 x"), fileMime: "application/pdf"));
            // …and the dangling metadata row was deleted.
            Assert.Contains(transport.Writes, w => w.Method == "DELETE" && w.Url.EndsWith("/documents/f9"));
        }
    }

    // Run a broadcast file CreateDocument and return the original_name sent on the /file upload.
    private async Task<string?> BroadcastUploadOriginalNameAsync(
        string name, string? fileMime, string? fileName = null)
    {
        var (client, transport) = MakeRw(NoGet, (method, url, body) =>
        {
            if (url.EndsWith("/documents"))
                return Resp.Json(201, new
                {
                    id = "f1", kind = "document", name, description = (string?)null,
                    status = "active", payload_kind = "file", is_private = false,
                    value = new { _pending = true }, metadata = (object?)null,
                    created_at = (string?)null, updated_at = (string?)null,
                });
            return Resp.Json(200, new { id = "f1" });
        });
        using (client)
        {
            await client.CreateDocumentAsync(name: name, payloadKind: "file",
                fileBytes: System.Text.Encoding.UTF8.GetBytes("x"), fileMime: fileMime, fileName: fileName);
            return ParseBody(transport.Writes[1].Body).GetProperty("original_name").GetString();
        }
    }

    [Fact]
    public async Task BroadcastOriginalNameKeepsAllowedExtension()
    {
        // A name that already ends in an allowed extension is left untouched (no "x.pdf.pdf").
        Assert.Equal("Price list.pdf",
            await BroadcastUploadOriginalNameAsync("Price list.pdf", "application/pdf"));
    }

    [Fact]
    public async Task BroadcastOriginalNameDerivesExtensionFromMime()
    {
        // An extensionless human name gets the extension from the MIME type.
        Assert.Equal("Price list.pdf",
            await BroadcastUploadOriginalNameAsync("Price list", "application/pdf"));
        Assert.Equal("Logo.jpg",
            await BroadcastUploadOriginalNameAsync("Logo", "image/jpeg"));
    }

    [Fact]
    public async Task BroadcastOriginalNameExplicitFileNameOverrides()
    {
        // An explicit fileName always wins, even over name's own extension and the MIME.
        Assert.Equal("override.docx",
            await BroadcastUploadOriginalNameAsync("Price list.pdf", "application/pdf", fileName: "override.docx"));
    }

    [Fact]
    public async Task CreateDocumentFilePerPersonUploadsValueWrapperString()
    {
        var spki = VectorPubSpkiB64();
        var (client, transport) = MakeRw(
            (url, q) => Resp.Json(200, new { public_key = spki }),
            (method, url, body) =>
            {
                if (url.EndsWith("/documents"))
                    return Resp.Json(201, new
                    {
                        id = "f2", kind = "document", name = "C", description = (string?)null,
                        status = "active", payload_kind = "file", is_private = true,
                        value = new { _pending = true }, metadata = (object?)null,
                        created_at = (string?)null, updated_at = (string?)null,
                    });
                return Resp.Json(200, new { id = "f2" });
            });
        using (client)
        {
            await client.CreateDocumentAsync(name: "C", payloadKind: "file",
                fileBytes: System.Text.Encoding.UTF8.GetBytes("hello-bytes"),
                fileMime: "application/pdf", personUserId: "u1", shareCode: "ABC123", isPrivate: true);
            var upload = transport.Writes[1].Body;
            Assert.NotNull(upload);
            // body is {"value": "<wrapper-as-JSON-string>"}; value MUST be a string
            var body = ParseBody(upload);
            Assert.Equal(JsonValueKind.String, body.GetProperty("value").ValueKind);
            using var wrapperDoc = JsonDocument.Parse(body.GetProperty("value").GetString()!);
            var wrapper = wrapperDoc.RootElement;
            Assert.Equal(1, wrapper.GetProperty("_enc").GetInt32()); // ciphertext wrapper, not raw file
            // decrypt → the {"file":"data:...base64,..."} envelope holding the original bytes
            using var priv = Vector.PrivateKey();
            var env = Crypto.Decrypt(Node.FromJson(wrapper), priv);
            using var edoc = JsonDocument.Parse(env);
            var fileUri = edoc.RootElement.GetProperty("file").GetString()!;
            Assert.StartsWith("data:application/pdf;base64,", fileUri);
            var payload = Convert.FromBase64String(fileUri.Split(',', 2)[1]);
            Assert.Equal(System.Text.Encoding.UTF8.GetBytes("hello-bytes"), payload);
        }
    }

    [Fact]
    public async Task DocumentVerbsHitRightPath()
    {
        var seen = new List<(string Method, string Url)>();
        var (client, _) = MakeRw(
            (url, q) =>
            {
                if (url.EndsWith("/documents")) return Resp.Json(200, new { total = 0, items = Array.Empty<object>() });
                if (url.Contains("/documents/d9")) return Resp.Json(200, new { id = "d9", payload_kind = "json", is_private = false, value = new { a = 1 } });
                throw new Xunit.Sdk.XunitException("unexpected GET " + url);
            },
            (method, url, body) =>
            {
                seen.Add((method, url));
                return Resp.Json(200, new { id = "d9", payload_kind = "json", is_private = false, value = new { a = 1 }, status = "ended" });
            });
        using (client)
        {
            Assert.Empty(await client.ListDocumentsAsync(status: "active"));
            Assert.Equal("d9", (await client.DocumentAsync("d9")).Id);
            await client.UpdateDocumentStatusAsync("d9", "ended");
            await client.UpdateDocumentMetadataAsync("d9", name: "renamed");
            await client.DeleteDocumentAsync("d9");
            var verbs = seen.Select(s => (s.Method, s.Url.Split("/api/company-data")[^1])).ToList();
            Assert.Contains(("PUT", "/documents/d9"), verbs);
            Assert.Equal(2, verbs.Count(v => v == ("PUT", "/documents/d9")));
            Assert.Contains(("DELETE", "/documents/d9"), verbs);
        }
    }

    // ── connect requests (service-initiated; idea 2) ────────────────────────────

    [Fact]
    public async Task SendConnectRequestPostsShareCodeAndReturnsRequestId()
    {
        JsonElement captured = default;
        var (client, _) = MakeRw(NoGet, (method, url, body) =>
        {
            Assert.Equal("POST", method);
            Assert.EndsWith("/company-data/connect-requests", url);
            captured = ParseBody(body);
            return Resp.Json(201, new { request_id = "req-1" });
        });
        using (client)
        {
            var rid = await client.SendConnectRequestAsync("  ABC123 ");
            Assert.Equal("req-1", rid);
            Assert.Equal("ABC123", captured.GetProperty("share_code").GetString()); // trimmed
        }
    }

    [Fact]
    public async Task SendConnectRequestBlankThrowsConfigException()
    {
        var (client, _) = MakeRw(NoGet, (m, u, b) => Resp.Json(200, new { }));
        using (client)
        {
            await Assert.ThrowsAsync<ConfigException>(() => client.SendConnectRequestAsync("   "));
        }
    }

    [Fact]
    public async Task SendConnectRequestMissingIdThrowsApiException()
    {
        var (client, _) = MakeRw(NoGet, (m, u, b) => Resp.Json(201, new { }));
        using (client)
        {
            await Assert.ThrowsAsync<ApiException>(() => client.SendConnectRequestAsync("ABC123"));
        }
    }
}
