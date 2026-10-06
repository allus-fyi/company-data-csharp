# Error model

Same taxonomy + names across all six SDKs (adapted to C#'s `*Exception`
convention). All in `Allus.CompanyData`.

| Error | Raised when |
|-------|-------------|
| `ConfigException` | Missing/invalid config, an unreadable key file, or a wrong passphrase — at construction (fail fast). |
| `AuthException` | The `client_credentials` token fetch/refresh failed (bad `client_id`/`secret`, revoked client); or a mid-flight 401 survived the one automatic refresh-and-retry. |
| `ApiException(Status, ErrorKey, Details)` | Any non-2xx from the API. `Details` carries the body's remaining fields (e.g. a 410 `company_data.file_expired`'s `content_sha256` + `expired_at`). |
| `DecryptException` | A ciphertext wrapper is malformed, the key is wrong, or the GCM tag mismatches. |
| `WebhookException` | Signature verification failed, or a webhook envelope couldn't be unwrapped/parsed. |
| `RateLimitException(RetryAfter)` | A 429 from a rate-limited endpoint. Subclass of `ApiException`. |

## `ApiException`

```csharp
public class ApiException : Exception
{
    public int     Status   { get; }   // the HTTP status
    public string? ErrorKey { get; }   // the platform error_key, when the body provided one
    public IReadOnlyDictionary<string, object?> Details { get; }  // the body's remaining fields, verbatim
    // Message carries a human-readable description.
}
```

`ex.Message` reads `"HTTP <status> (<error_key>): <message>"`. A transport failure
(no HTTP response — e.g. a connection error) surfaces as `ApiException` with
`Status == 0`.

`Details` is everything the error body carried besides `error_key`/`error`/`message`
— generic on purpose, so a response with actionable data needs no bespoke exception
type. The live example is a binary slot whose frozen answer has passed its 90-day
retention:

```csharp
catch (ApiException e) when (e.ErrorKey == "company_data.file_expired")
{
    // e.Status == 410
    var digest    = e.Details["content_sha256"];  // sha256 of the bytes that used to be served
    var expiredAt = e.Details["expired_at"];      // when the retention elapsed
}
```

A **421 `region.rebase_required`** never reaches you when the platform is reachable: it is the global front door telling the SDK to send the call to the caller's home region, which the SDK does automatically (README, **How it's wired** → Regions). It surfaces as `ApiException` in exactly three cases: the refusal's base is absent, not a string, or empty (nothing to rebase to); the refusal names the SDK's own current base (a self-referential directive, so rebasing would loop); or a rebase already happened once for this request and a second 421 still comes back. In every other case the SDK rebases and retries transparently.

## One request waits 45 seconds

The SDK's own transport — for `Client`, `CustomerClient` and `OAuthClient` alike —
waits 45 seconds for the platform's answer to one request, and the call then fails
as it does when the connection drops; an `HttpClient` you pass to `HttpTransport`,
or an `IHttpTransport` of your own, keeps its own limit. A request given up may
still have completed on the platform.

## 503 `db.writes_paused` — saving is paused, retry

While the platform cannot complete a save in every region, a call can answer
**503** with `ErrorKey` **`db.writes_paused`** (`"Saving data is not possible
right now"`) and the header `Retry-After: 30`. **Nothing was written**, so the call
is safe to repeat exactly as it was. Reads keep working.

It surfaces as a plain `ApiException` (`Status == 503`, `ErrorKey ==
"db.writes_paused"`); the SDK does not retry it. `ApiException` does not carry the
`Retry-After` header: wait 30 seconds, then repeat the same call.

Where it can come from:

* every company-data and customer call that is not a GET — creating, updating or
  deleting documents, flow-run starts, answers, uploads and generation, consent
  answers, connect requests, messages, 2FA challenges, `/api/keys/batch`;
* the change-feed drains `GET /api/company-data/changes` and
  `GET /api/customer/changes` (`ProcessChangesAsync`, `DrainBatchAsync`): nothing
  was drained, the events stay queued on the server and arrive on a later run, and
  the local buffer is untouched;
* `OAuthClient.PollResultAsync` (`POST /oauth2/result`): the result is not
  consumed; poll again.

The token request (`POST /oauth2/token`) does not answer it: token grants keep
working while saving is paused.

```csharp
catch (ApiException e) when (e.Status == 503 && e.ErrorKey == "db.writes_paused")
{
    await Task.Delay(TimeSpan.FromSeconds(30));
    // repeat the same call
}
```

## 503 `platform.out_of_order` — the platform is out of order, retry

While the region serving a call is being rebuilt, the call answers **503** with
`ErrorKey` **`platform.out_of_order`** (`"allme is temporarily out of order.
Please try again later."`) and the header `Retry-After: 300`. **The request was
not processed**, so the call is safe to repeat exactly as it was. The platform
answers normally again once the region is back in service.

It surfaces as a plain `ApiException` (`Status == 503`, `ErrorKey ==
"platform.out_of_order"`); the SDK does not retry it. `ApiException` does not
carry the `Retry-After` header: wait 300 seconds, then repeat the same call.

Where it can come from:

* every company-data and customer call, reads included — connections, request
  fields, binary fetches, documents, flow runs, consent answers, connect requests,
  messages, 2FA challenges and results, `/api/keys`;
* the change-feed drains `GET /api/company-data/changes` and
  `GET /api/customer/changes` (`ProcessChangesAsync`, `DrainBatchAsync`): nothing
  was drained, the events stay queued on the server and arrive on a later run, and
  the local buffer is untouched;
* every `OAuthClient` call — `ExchangeCodeAsync`, `UserinfoAsync`,
  `PollResultAsync` (the result is not consumed; poll again).

The `client_credentials` token request (`POST /oauth2/token`) the service and
customer clients make does not answer it, so the SDK still holds a token and the
503 arrives on the call itself. Every other grant at `POST /oauth2/token` — the
`OAuthClient` code exchange, a refresh-token grant — answers it.

```csharp
catch (ApiException e) when (e.Status == 503 && e.ErrorKey == "platform.out_of_order")
{
    await Task.Delay(TimeSpan.FromSeconds(300));
    // repeat the same call
}
```

## `RateLimitException`

```csharp
public sealed class RateLimitException : ApiException   // Status is always 429
{
    public double? RetryAfter { get; }   // seconds from the Retry-After header, or null
}
```

The SDK already retries a 429 with backoff before surfacing this:

* the transport (`ApiHttp`) retries a bounded number of times honoring `Retry-After`;
* the `ConnectionsAsync(...)` stream additionally backs off + retries a page a bounded number of times.

For the heavily-limited connections endpoints it surfaces after that backoff so
you don't accidentally hammer them; on the changes feed it auto-backs-off within
reason. If you catch it, wait `ex.RetryAfter` (or a default) before retrying.

## Where each surfaces

| Layer | Common errors |
|-------|---------------|
| `Client.FromConfig` / `FromEnv` (construction) | `ConfigException` |
| Token / any call (auth) | `AuthException` |
| `ConnectionsAsync`, `ConnectionAsync`, `RequestFieldsAsync`, `LogsAsync`, pump drains | `ApiException`, `RateLimitException` |
| Value access / `BinaryHandle.BytesAsync()` / pump delivery | `DecryptException`; `ApiException` on the binary slot file endpoint (incl. 410 `company_data.file_expired`) |
| `VerifyWebhook` / `ParseWebhook` / `HandleWebhook` | `WebhookException` (`VerifyWebhook` returns `false` rather than throwing on a bad signature) |

## Example

```csharp
using Allus.CompanyData;

try
{
    using var client = Client.FromConfig("allus.json");
    await foreach (var conn in client.ConnectionsAsync())
        Process(conn);
}
catch (ConfigException) { /* fix the config / key file */ }
catch (AuthException) { /* bad/revoked credentials */ }
catch (RateLimitException e) { await Task.Delay(TimeSpan.FromSeconds(e.RetryAfter ?? 60)); }
catch (DecryptException) { /* wrong service key or corrupt data */ }
catch (ApiException e) { Log(e.Status, e.ErrorKey, e.Message); }
```
