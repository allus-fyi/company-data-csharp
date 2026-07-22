# Webhook receiver helpers

The lower-latency push alternative to polling the changes feed. The platform POSTs
each change event to your configured webhook URL with:

* `X-Allus-Webhook-Id` — which webhook this is (selects the HMAC secret from config).
* `X-Allus-Signature` — `HMAC-SHA256(rawBody, secret)` as lowercase hex.
* the body — the same slug-keyed `Change` shape as the pull feed (JSON or XML). If `encrypt_payload` is on, the body is replaced by a `{"_enc":1,…}` envelope encrypted to the company **account** key (and the HMAC is over that envelope).

**All secrets/keys come from config — these helpers take NO key or secret
arguments.** Always pass the **raw request body bytes** (don't re-serialize a
parsed body; the HMAC is over the exact bytes sent).

## Client methods (the usual form)

```csharp
bool   client.VerifyWebhook(object rawBody, IReadOnlyDictionary<string,string>? headers)
Change client.ParseWebhook(object rawBody, IReadOnlyDictionary<string,string>? headers)
Change client.HandleWebhook(object rawBody, IReadOnlyDictionary<string,string>? headers)  // verify + parse
```

`rawBody` is a `byte[]` (preferred) or a `string`.

| Method | Returns | Errors |
|--------|---------|--------|
| `VerifyWebhook` | `bool` — recomputes `HMAC-SHA256(rawBody, secret)` and constant-time-compares (`CryptographicOperations.FixedTimeEquals`) to `X-Allus-Signature`. `false` on missing signature / unknown id / mismatch. | **Never throws** for a bad signature. |
| `ParseWebhook` | a typed `Change`. Does **not** verify. Handles JSON, XML, and the `encrypt_payload` account-key envelope. | `WebhookException` on a malformed/unparseable body or envelope. |
| `HandleWebhook` | a typed `Change` — verify **then** parse. | `WebhookException` on a bad/unknown signature, or any `ParseWebhook` error. |

## Static functions

The same three are available as `Allus.CompanyData.Webhooks` static methods. They
take the `Config` and the decrypt/type closures explicitly — used by `Client`
internally; you'll normally use the client methods inside an app.

```csharp
Webhooks.VerifyWebhook(rawBody, headers, config) -> bool
Webhooks.ParseWebhook(rawBody, headers, config, typeForSlug, decryptValue, binaryFetch = null, accountKey = null) -> Change
Webhooks.HandleWebhook(rawBody, headers, config, typeForSlug, decryptValue, binaryFetch = null, accountKey = null) -> Change
```

## In a web route

### ASP.NET Core minimal API

```csharp
using Allus.CompanyData;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton(_ => Client.FromConfig("allus.json"));  // one client, app lifetime
var app = builder.Build();

app.MapPost("/allus/webhook", async (HttpRequest req, Client client) =>
{
    using var ms = new MemoryStream();
    await req.Body.CopyToAsync(ms);
    var rawBody = ms.ToArray();                                 // the EXACT bytes (HMAC is over these)
    var headers = req.Headers.ToDictionary(h => h.Key, h => (string)h.Value!);

    Change change;
    try { change = client.HandleWebhook(rawBody, headers); }
    catch (WebhookException) { return Results.Unauthorized(); }  // bad/unknown signature or unparseable

    await ApplyChange(change);   // see "Delivery contract" below before adding dedup
    return Results.Ok();   // 200 — the ONLY status allus counts as delivered
});

app.Run();
```

### MVC / API controller

```csharp
[ApiController]
public class WebhookController(Client client) : ControllerBase
{
    [HttpPost("/allus/webhook")]
    public async Task<IActionResult> Receive()
    {
        using var ms = new MemoryStream();
        await Request.Body.CopyToAsync(ms);
        var rawBody = ms.ToArray();
        var headers = Request.Headers.ToDictionary(h => h.Key, h => (string)h.Value!);
        try
        {
            var change = client.HandleWebhook(rawBody, headers);
            await ApplyChange(change);   // see "Delivery contract" below before adding dedup
            return Ok();
        }
        catch (WebhookException) { return Unauthorized(); }
    }
}
```

Split the steps if you prefer:

```csharp
if (!client.VerifyWebhook(rawBody, headers))
    return Results.Unauthorized();
var change = client.ParseWebhook(rawBody, headers);
```

## Delivery contract — effectively unique, rarely replayed

Each queued event is POSTed **once**, and **only HTTP `200` counts as delivered** — a
`202`, a `204`, a 3xx redirect and every 4xx/5xx are all treated as a failure. On anything
other than `200` (or a timeout or connection error) the event is **not retried in place**:
it and the rest of the webhook's queue move to a durable server-side backlog and the
webhook is marked bad. The backlog is delivered later, either automatically when
the webhook next probes healthy, or when you drain it yourself with
`GET /api/company-data/changes?webhook_id=…` (delete-on-read).

So deliveries are **effectively unique** — with one rare exception. If your endpoint
processed an event but the platform never saw your `200` (your response timed out, or
you crashed after committing but before responding), the event is treated as failed
and replayed on recovery, so you receive it **again**. Nothing caps that at two: a
failed probe leaves its backlog row in place, so every later recovery attempt whose
`200` is likewise lost replays the same event once more. Inside that window the
contract is **at-least-once** — plan for one or more repeats, not for exactly one.

> **Do not use `change.Id` as an idempotency key here.** On the webhook path the id is
> neither reliably stable nor reliably fresh, and a receiver cannot tell which one it is
> holding. A **live** delivery is built with no change row behind it, so its id is minted
> for that single POST — the later replay of the same event is rebuilt from a durable
> backlog row and therefore carries a **different** id. But a replayed delivery carries
> **that row's** id, and the row stays in place until it is delivered successfully, so a
> re-attempted replay arrives with the **same** id — which changes again if the event is
> re-backlogged after a further failure. An id check therefore misses the duplicate you
> are most likely to see and matches only a rarer one; it is not a contract. If you need
> strict idempotency, key on the **content** — event + person + slug/document + payload —
> never on the id.

**Webhooks and the pull feed are alternative integrations — consume one, never both.**
The id-dedup guidance in [pump.md](pump.md) applies to the pump only, where `change.Id`
is the real server change-row id.

## Config-driven secrets

Per-webhook HMAC secrets live in the config `webhooks` map, keyed by webhook id;
the SDK reads `X-Allus-Webhook-Id` and looks up the matching secret. A
single-webhook service can use the flat `"webhook_secret": "…"` shortcut (or
`ALLUS_WEBHOOK_SECRET`). An unknown/unconfigured id ⇒ `VerifyWebhook` returns
`false` (and `HandleWebhook` throws `WebhookException`).

## The `encrypt_payload` account-key envelope

If a webhook has `encrypt_payload` enabled, the whole body is a `{"_enc":1,…}`
envelope encrypted to your company **account** key, and the HMAC is over that
envelope. `ParseWebhook`/`HandleWebhook`:

1. Unwrap the envelope with the configured `account_private_key` + `account_passphrase`.
2. Parse the inner payload (JSON or XML per `format`).
3. Decrypt the inner field `value` (a service-key wrapper) with the service key.

So an `encrypt_payload` `Change` is identical to a plain one. Receiving such a
webhook without an `account_private_key` configured throws `WebhookException`.

The account key is loaded **once** at `Client` construction and reused for every
enveloped webhook (no per-request PEM read / PBKDF2 re-run).

> The envelope uses RSA-OAEP-**SHA1** (`RSAEncryptionPadding.OaepSHA1` — OpenSSL's
> default), distinct from the OAEP-SHA256 used for person field values
> (`RSAEncryptionPadding.OaepSHA256`). The SDK handles this difference internally —
> you only supply the account key in config.

## XML safety

XML bodies are parsed with DTD processing prohibited and no external-entity
resolver (`XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit,
XmlResolver = null }`), so a webhook XML body can never trigger XXE / entity
expansion. The HMAC is always computed over the raw body bytes, never the parsed
tree.
