# Error model

Same taxonomy + names across all six SDKs (adapted to C#'s `*Exception`
convention). All in `Allus.CompanyData`.

| Error | Raised when |
|-------|-------------|
| `ConfigException` | Missing/invalid config, an unreadable key file, or a wrong passphrase — at construction (fail fast). |
| `AuthException` | The `client_credentials` token fetch/refresh failed (bad `client_id`/`secret`, revoked client); or a mid-flight 401 survived the one automatic refresh-and-retry. |
| `ApiException(Status, ErrorKey)` | Any non-2xx from the API. |
| `DecryptException` | A ciphertext wrapper is malformed, the key is wrong, or the GCM tag mismatches. |
| `WebhookException` | Signature verification failed, or a webhook envelope couldn't be unwrapped/parsed. |
| `RateLimitException(RetryAfter)` | A 429 from a rate-limited endpoint. Subclass of `ApiException`. |

## `ApiException`

```csharp
public class ApiException : Exception
{
    public int     Status   { get; }   // the HTTP status
    public string? ErrorKey { get; }   // the platform error_key, when the body provided one
    // Message carries a human-readable description.
}
```

`ex.Message` reads `"HTTP <status> (<error_key>): <message>"`. A transport failure
(no HTTP response — e.g. a connection error) surfaces as `ApiException` with
`Status == 0`.

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
| Value access / `BinaryHandle.BytesAsync()` / pump delivery | `DecryptException` |
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
