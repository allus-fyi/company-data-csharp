# Allus.CompanyData (C# / .NET)

The .NET SDK for the **allus company-data API**. Point it at a JSON config file
and it hands back typed, plaintext, **your-slug-keyed conclusions**: for each
connected person, a map of *your request-field slug → plaintext value* (plus
whether the value is live and when it last changed).

The SDK hides everything else — the OAuth token, the field catalog, the id
plumbing, the hybrid decryption, binary fetching, the changes-queue mechanics,
JSON-vs-XML. The platform is **zero-knowledge**: the API only ever holds
ciphertext, so all decryption happens inside the SDK with your service private
key. **The person's own field choices are never exposed** — you only ever see
the request slots you configured.

> This SDK is one of six language ports (Python · Go · TypeScript · **C#/.NET** ·
> Java · PHP) that share an identical API surface. This manual is the C# view of
> it.

**Contents:** [TL;DR — fetch new updates](#tldr--fetch-new-updates) ·
[Quickstart](#quickstart) · [Every call](#every-call) ·
[The typed value model](#the-typed-value-model) ·
[The changes pump](#the-changes-pump) · [Company documents](#company-documents) ·
[Webhooks](#webhooks) · [Rate limits](#rate-limits) · [Errors](#errors) ·
[How it's wired](#how-its-wired)

Deeper reference pages live in [`docs/`](docs/):
[config](docs/config.md) · [model](docs/model.md) · [pump](docs/pump.md) ·
[webhooks](docs/webhooks.md) · [errors](docs/errors.md).

---

## TL;DR — fetch new updates

```bash
dotnet add package Allus.CompanyData
```

Point a config.json at your service keys:

    {
      "api_url": "https://api.allme.fyi",
      "client_id": "svc_xxx",
      "client_secret": "xxx",
      "service_private_key": "/path/to/service.pem",
      "key_passphrase": "xxx",
      "cache_dir": "./allus-cache"
    }

Drain everything new, handled one update at a time:

```csharp
using Allus.CompanyData;

using var client = Client.FromConfig("config.json");

await client.ProcessChangesAsync(async change =>
{
    // change.Event, change.PersonId, change.Slug, change.ValueObj, change.Live, change.At
    Console.WriteLine($"{change.Event} {change.PersonId} {change.Slug} = {change.ValueObj}");
    await Task.CompletedTask;
});
```

`ProcessChangesAsync` pulls every pending change, decrypts it, and hands them to
your callback **one by one**, acking each only after your code returns. Crash
mid-batch? The next run replays exactly what wasn't acked — nothing is lost, and
the API keeps no backlog of its own. Run it on a schedule (cron / systemd timer);
there is no daemon/follow mode by design. Connections, binary values, and
webhooks are documented below.

---

## Quickstart

Targets **.NET 8.0** (LTS). Namespace `Allus.CompanyData`. No third-party
dependencies — pure `System.Security.Cryptography`.

```bash
dotnet add package Allus.CompanyData
```

```csharp
using Allus.CompanyData;
```

### 1. Write a config file

A single JSON file holds everything. Any field can be overridden by an `ALLUS_*`
env var, so secrets needn't live in the file. **No SDK method ever takes a key,
passphrase, or secret as an argument** — they all come from here.

`allus.json`:

```json
{
  "api_url": "https://api.allme.fyi",
  "client_id": "svc_1a2b3c…",
  "client_secret": "…",
  "service_private_key": "./service-CRM.pem",
  "key_passphrase": "…",

  "account_private_key": "./account.pem",
  "account_passphrase": "…",

  "webhooks": {
    "wh_abc123": "hmac_secret_for_that_webhook"
  },

  "cache_dir": "./allus-cache",
  "format": "json"
}
```

| Field | Required | Meaning |
|-------|----------|---------|
| `api_url` | yes | API base, e.g. `https://api.allme.fyi`. |
| `client_id` / `client_secret` | yes | The registered `client_credentials` credentials for **one** service. |
| `service_private_key` | yes | Path to the OpenSSL-encrypted PKCS#8 PEM you downloaded from the portal. |
| `key_passphrase` | yes | Decrypts that PEM in memory at startup. |
| `account_private_key` / `account_passphrase` | only for `encrypt_payload` webhooks | The company **account** key, used to unwrap an encrypted webhook envelope. |
| `webhooks` / `webhook_secret` | webhook auth — HMAC (default) | Per-webhook HMAC secrets keyed by webhook id (matched via the `X-Allus-Webhook-Id` header). A single-webhook service can use a flat `"webhook_secret": "…"` instead of the map. |
| `webhook_bearer_token` | webhook auth — bearer | Verify `Authorization: Bearer <token>` deliveries. |
| `webhook_basic` | webhook auth — basic | `{"username","password"}` — verify HTTP Basic deliveries. |
| `webhook_header` | webhook auth — header | `{"name","value"}` — verify a custom-header delivery. |
| `webhook_auth_none` | webhook auth — none | `true` — explicit opt-out; `verifyWebhook` always passes (use only behind your own gateway). **Configure at most one** webhook auth method (two+ → `ConfigError`). |
| `cache_dir` | no (default `./allus-cache`) | Durable local buffer for the changes pump. Must be writable + durable. |
| `format` | no (default `json`) | Wire format `json` or `xml`. Invisible in the output. |

Env overrides use the `ALLUS_` prefix of the field name, e.g.
`ALLUS_CLIENT_SECRET`, `ALLUS_KEY_PASSPHRASE`, `ALLUS_ACCOUNT_PASSPHRASE`,
`ALLUS_WEBHOOK_SECRET`. A missing/invalid config (or an unreadable PEM / wrong
passphrase) throws `ConfigException` at construction — fail fast.

### 2. First call — list a connection's values

```csharp
using Allus.CompanyData;

using var client = Client.FromConfig("allus.json");

// Iterate every connected person (lazy, auto-paged).
await foreach (var conn in client.ConnectionsAsync())
{
    Console.WriteLine($"{conn.DisplayName} {conn.PersonId}");
    foreach (var (slug, val) in conn.Values)
        Console.WriteLine($"  {slug} = {val.ValueObj}  (live={val.Live}, updated={val.UpdatedAt})");
    break; // just the first one for the demo
}
```

Or fetch one connection by id:

```csharp
var conn = await client.ConnectionAsync("019xxxxxxxxxxxxxxxxxxxxxxxxx");
var email = (string?)conn.Values["work_email"].ValueObj;   // "alice@acme.com"
```

`Client.FromEnv()` builds the same client entirely from `ALLUS_*` env vars
(no file). `Client` is `IDisposable` — it holds the in-memory RSA key(s), so
`using` it (or calling `Dispose()`) releases them.

---

## Every call

`Client` is the only object you construct. Build it from config, then call its
async methods.

```csharp
Client.FromConfig(string path) -> Client     // from a JSON file (env overrides secrets)
Client.FromEnv()               -> Client      // entirely from ALLUS_* env vars
```

Advanced: the full constructor takes optional `ApiHttp http` (injectable
transport), `IPumpLogger? logger`, and a `sleep` delegate (used by tests).

### `RequestFieldsAsync()`

```csharp
Task<IReadOnlyList<RequestField>> RequestFieldsAsync(CancellationToken ct = default)
```

Your request-field **definitions** — fetched once from
`GET /api/company-data/request-fields` and cached for the life of the client (it
types every value). Returns *your* request config, never the person's fields.

* **Returns:** `IReadOnlyList<RequestField>` — each `RequestField(Slug, Label, Type, OneTime, Mandatory)`. `Mandatory` is true when the field is mandatory-to-provide **or** mandatory-to-stay-connected.
* **Throws:** `AuthException`, `ApiException`, `RateLimitException`.

```csharp
foreach (var f in await client.RequestFieldsAsync())
{
    var flag = f.Mandatory ? "mandatory" : "optional";
    Console.WriteLine($"{f.Slug,-20} {f.Type,-10} {flag}{(f.OneTime ? " (one-time)" : "")}");
}
```

### `ConnectionsAsync(limit, offset)`

```csharp
IAsyncEnumerable<Connection> ConnectionsAsync(int limit = 100, int offset = 0, CancellationToken ct = default)
```

A **lazy async stream** that auto-pages `GET /api/company-data/connections?limit&offset`,
honoring the API `total` (and stopping on a short page), and yields one typed
`Connection` at a time (bounded memory for a large book). Each `conn.Values[slug]`
is already decrypted (or a lazy binary handle).

* **Params:** `limit` — page size (default 100); `offset` — starting offset.
* **Throws:** `AuthException`, `ApiException`, `DecryptException` (per value, when accessed), `RateLimitException` (after the iterator's bounded internal backoff — see [Rate limits](#rate-limits)).

> **Heavily rate-limited.** Use for the initial full sync + occasional
> reconciliation only — never as a poll substitute for the changes feed. The
> stream paces itself within the limit (backs off on `Retry-After`).

```csharp
// Initial full sync, streaming so a 100k-connection book never lands in memory.
await foreach (var conn in client.ConnectionsAsync(limit: 200))
    UpsertLocalRecord(conn);
```

### `ConnectionAsync(id)`

```csharp
Task<Connection> ConnectionAsync(string id, CancellationToken ct = default)
```

Fetch one connection by its connection id (`GET /api/company-data/connections/{id}`).

* **Returns:** one `Connection`. Note: this endpoint returns `{connection_id, user_id, values}` and **no** `display_name`/`connected_at`, so those identity fields are `null` here (the list endpoint carries them).
* **Throws:** `AuthException`, `ApiException` (404 if unknown), `DecryptException`, `RateLimitException`.

```csharp
var conn = await client.ConnectionAsync(connId);
if (conn.Values.TryGetValue("mobile", out var phone))
    Console.WriteLine($"{phone.ValueObj} {(phone.Live ? "live" : "snapshot")}");
```

### `LogsAsync(limit, offset)`

```csharp
Task<IReadOnlyList<LogEntry>> LogsAsync(int limit = 50, int offset = 0, CancellationToken ct = default)
```

The service's activity log (`GET /api/company-data/logs?limit&offset`) — **ops
events only** (email / purge / webhook), never person field data.

* **Returns:** `IReadOnlyList<LogEntry>` — each `LogEntry(Type, Message, Metadata, At)`.
* **Throws:** `AuthException`, `ApiException`, `RateLimitException`.

```csharp
foreach (var entry in await client.LogsAsync(limit: 20))
    Console.WriteLine($"{entry.At} {entry.Type} {entry.Message}");
```

### `ProcessChangesAsync(handler, options)`

```csharp
Task ProcessChangesAsync(Func<Change, Task> handler, ProcessOptions? options = null, CancellationToken ct = default)
```

The crash-safe changes pump: drains the feed through `handler` **one `Change` at
a time**, durably buffering each batch before delivery, with per-item ack and
retry → dead-letter → continue. Runs **until the feed is empty, then returns** —
there is **no follow/daemon mode** (you schedule re-runs yourself). Delivery is
**at-least-once**, so your handler **must be idempotent** (dedup on `Change.Id`).
See [The changes pump](#the-changes-pump) for the full model.

* **Params:** `handler` — your async callback; called with one `Change`. A normal completion is an ack; a thrown exception triggers retry.
* **Options** (`ProcessOptions`): `BatchSize` (clamped to ≤ 500, default 100), `MaxRetries` (default 3), `OnError` (`OnError.DeadLetter` — default — or `OnError.Halt`), `Backoff` (`Func<int, double>`, attempt → seconds).
* **Throws:** `AuthException`, `ApiException`, `RateLimitException` (during a drain); whatever the handler throws if `OnError.Halt` and retries are exhausted.

```csharp
async Task Handle(Change change)
{
    if (AlreadyProcessed(change.Id)) return;          // idempotency — dedup on the stable id
    switch (change.Event)
    {
        case "field_updated":
            await Store(change.PersonId, change.Slug, change.ValueObj);
            break;
        case "connection_deleted" or "field_deleted":
            await Remove(change.PersonId, change.Slug);
            break;
    }
    MarkProcessed(change.Id);
}

await client.ProcessChangesAsync(Handle);             // returns when the feed is empty
```

> Pass a `logger` once to the `Client` constructor (an `IPumpLogger`), not to
> `ProcessChangesAsync`.

### Advanced changes primitives

```csharp
Task<List<Change>> DrainBatchAsync(int max = 100, ...)        // raw, UNBUFFERED — you own durability
List<Node>         DeadLetters()                              // the local dead-letter store
Task<int>          RetryDeadLettersAsync(handler, options, …) // re-drive dead-lettered events; returns count re-driven
```

* `DrainBatchAsync(max)` — fetches one batch (clamped ≤ 500) and returns the decrypted `Change`s directly. It does **not** persist anything, so a crash loses what the API already deleted. Prefer `ProcessChangesAsync` for safe consumption.
* `DeadLetters()` — each `Node` is the stored (ciphertext) event plus a flattened `error` and `attempts`.
* `RetryDeadLettersAsync(handler, options)` — same `MaxRetries` / `OnError` / `Backoff` options as `ProcessChangesAsync`; on success a record is removed, on repeated failure it stays dead-lettered (or re-throws under `OnError.Halt`). Dead letters are never re-fetched from the API — the local store is their only home.

```csharp
foreach (var dl in client.DeadLetters())
    Console.WriteLine($"stuck: {dl.Get("id").AsString()} {dl.Get("error").AsString()} after {dl.Get("attempts").AsString()} attempts");

var n = await client.RetryDeadLettersAsync(Handle);   // after you've fixed the bug
Console.WriteLine($"re-drove {n} dead letters");
```

### Key rotation — `key_rotated` and the public-key cache

Every client caches the RSA public keys it fetches: a person's key is immutable — until they
**rotate** it. A person learns of a rotation from a silent push; your service gets no pushes, so the
`key_rotated` change is your **only** signal. Without it a long-running worker keeps encrypting to
the rotated-away key for its whole lifetime, and the person can never read those values.

**On the pump this is automatic** — the cached key is dropped as the change passes through, before
your handler sees it. **Over a webhook it is not:** the signature verifier is static and has no
client instance, so it cannot reach the cache. Call the invalidator yourself — noting that the two
clients key their caches **differently**: the service client by `share_code`, the customer client by
the person's **user id**. Passing a share code to the customer client removes nothing and leaves you
encrypting to the old key. Both identifiers ride every change, alongside `public_key_sha256` — the
fingerprint of the person's new key.

```csharp
if (change.Event == "key_rotated") {
    client.InvalidatePublicKey(change.ShareCode);    // service Client — keyed by SHARE CODE
    customer.InvalidatePublicKey(change.PersonId);   // CustomerClient — keyed by PERSON USER ID
    // change.PublicKeySha256 = fingerprint of the NEW key, if you want to verify the refetch
}
```

This is **eventual, not fail-closed** — nothing rejects a document encrypted to a stale key, so a
window remains between the rotation and your next drain. Drain often if that window matters.

### `service_key_rotated` — the same thing, the other way round

The customer client also caches the **service's** public key, the one you encrypt your consent
answers and documents *to*, keyed `"companyCode/serviceCode"`. When that company replaces its
service keypair, the `service_key_rotated` change on your account feed is your only signal — you
receive no pushes. Same shape, same guarantees, same automatic handling on the pump:

```csharp
if (change.Event == "service_key_rotated")
{
    // Automatic on the pump. Over a webhook, from the raw event body:
    customer.InvalidateServiceKey(body["company_share_code"], body["service_share_code"]);
    // body["service_public_key_sha256"] = fingerprint of the service's NEW key
}
```

Also **eventual, not fail-closed**. Note the identifiers are **share codes**, not the ids used by
`InvalidatePublicKey` — the two caches are keyed differently and the wrong call removes nothing.

### Webhook helpers (on the client)

The webhook receiver helpers are also exposed as `Client` methods (they delegate
to the static `Webhooks` functions, fully config-driven — no key/secret arguments):

```csharp
bool   client.VerifyWebhook(object rawBody, IReadOnlyDictionary<string,string>? headers)
Change client.ParseWebhook(object rawBody, IReadOnlyDictionary<string,string>? headers)
Change client.HandleWebhook(object rawBody, IReadOnlyDictionary<string,string>? headers)  // verify + parse
```

`rawBody` is the exact request body — a `byte[]` (preferred) or a `string`.

* `VerifyWebhook` — recomputes `HMAC-SHA256(rawBody, secret)` and constant-time-compares it (`CryptographicOperations.FixedTimeEquals`) to `X-Allus-Signature`. Returns `true`/`false`; **never throws** for a bad signature.
* `ParseWebhook` — body → a typed `Change`. Does **not** verify. Handles JSON, XML, and the `encrypt_payload` account-key envelope. Throws `WebhookException` on a malformed/unparseable body.
* `HandleWebhook` — verify **then** parse; throws `WebhookException` on a bad/unknown signature, otherwise returns the `Change`. The typical one-liner inside a route.

See [Webhooks](#webhooks).

---

## The typed value model

You work with these objects and nothing else (all in `Allus.CompanyData`):

```text
RequestField { Slug, Label, Type, OneTime, Mandatory }            // YOUR request config
Connection   { Id, PersonId, DisplayName, ConnectedAt, Values: {<slug>: Value} }
Value        { ValueObj, Live, UpdatedAt }
Change       { Id, Event, PersonId, Slug?, ValueObj?, Live?, At }
LogEntry     { Type, Message, Metadata, At }
```

### Keyed by *your* slug

`conn.Values["work_email"].ValueObj` → `"alice@acme.com"`. The key is the stable,
explicit slug you set per request field in the portal — rename the label freely,
the slug is the contract. **The person's source field is never exposed**: no
source slug, no `field_id`, not even via `.Raw`.

### `Value(ValueObj, Live, UpdatedAt)`

| Member | Meaning |
|--------|---------|
| `ValueObj` | The typed plaintext (see the table below) — `object?`, cast it per the field's type. |
| `Live` | `true` if the person chose "keep connected" (auto-updates); `false` for a one-time snapshot. |
| `UpdatedAt` | `DateTimeOffset?` of when this answer last changed (per-answer, rides on the `Value`). |

### Value types (from the field's `type`)

| Field type | .NET `ValueObj` |
|------------|-----------------|
| `email`, `phone`, `url`, `text` | `string` — `phone` is a single E.164-style string (`+` and digits) |
| `country`, `nationality` | `string` — an ISO 3166-1 alpha-2 code (e.g. `"US"`, `"NL"`); not a display name |
| `address`, `bank`, `creditcard` | `IDictionary<string, object?>` — the decrypted plaintext is a JSON object, parsed for you |
| `date`, `date_of_birth` | `DateOnly` (falls back to the raw `string` if it can't be parsed) |
| `photo`, `document`, `legal_document` | a lazy `BinaryHandle` — see below |
| unanswered / no value | `null` |

`country`/`nationality` values are 2-letter ISO codes, and an `address`'s
`country`/`state` sub-fields are an ISO alpha-2 code / USPS 2-letter state code
respectively. `FieldValidation.IsValid(type, value)` validates these against the
bundled country dataset; `FieldValidation.IsValidCountryCode(code)` /
`FieldValidation.DialCodeFor(code)` check a code or look up its E.164 dial code.

```csharp
var addr = (IDictionary<string, object?>)conn.Values["home_address"].ValueObj!;  // {"street": …, "city": …}
var dob  = (DateOnly)conn.Values["birthday"].ValueObj!;                            // 1990-05-17
```

### Binary fields — the lazy `BinaryHandle`

A photo/document value is a `BinaryHandle`. Nothing is fetched or decrypted until
you call `.BytesAsync()` or `.SaveAsync()`:

```csharp
var handle = (BinaryHandle)conn.Values["passport_scan"].ValueObj!;  // no network yet

byte[] data = await handle.BytesAsync();                  // GET the slot file → decrypt → file bytes
int    n    = await handle.SaveAsync("/tmp/passport.jpg"); // same, atomically written to disk; returns bytes written
Console.WriteLine(handle.ValueUrl);                        // the opaque slot-keyed URL it fetches from
```

`.BytesAsync()` GETs the slot-keyed file endpoint, unwraps the API's
`{"encrypted": true, "value": <wrapper>}` envelope, decrypts with your service
key, parses the inner JSON envelope (`{"full": "data:…"}` for photos,
`{"file": "data:…"}` for documents) and base64-decodes the data URI into the file
bytes. The result is cached on the handle, so repeated calls don't re-fetch.
`.SaveAsync()` writes atomically (temp file → flush-to-disk → atomic move), so a
crash mid-write never leaves a truncated file.

### `Change(Id, Event, PersonId, Slug?, ValueObj?, Live?, At)`

A change-feed / webhook event.

| Member | Meaning |
|--------|---------|
| `Id` | **The stable server change-row id — your dedup key** (captured before the server delete). |
| `Event` | `connection_created`, `connection_deleted`, `field_updated`, `field_deleted`, `consent_accepted`, `consent_declined`. |
| `PersonId` | The person the change is about (may be `null`). |
| `Slug`, `ValueObj`, `Live` | Present only on `field_updated`; `ValueObj` is typed exactly like `Value.ValueObj` (incl. a lazy `BinaryHandle` for binaries). Connection/consent events carry no slot/value. |
| `At` | `DateTimeOffset?` of the change. (There is no separate `UpdatedAt` on a change.) |

### `.Raw`

Every model carries `.Raw` — the underlying *hardened* API object graph
(`Dictionary`/`List`/scalar) — for debugging or an edge case the SDK didn't model.
It still never contains the person's source field.

See [`docs/model.md`](docs/model.md) for the full reference.

---

## The changes pump

The changes feed is a server-side **drain-on-fetch queue**:
`GET /api/company-data/changes?limit=N` returns up to N events (default 100, max
500) **and deletes exactly those rows in the same transaction** — no
offset/cursor, and the API keeps no copy afterward. So consumption can't be a
plain list: a consumer crash mid-batch would lose events the API already deleted,
and a huge backlog must not materialize in memory. `ProcessChangesAsync` solves both.

**Per run, repeating until the feed is empty then returning:**

1. **Replay first.** Deliver any un-acked events already in the local buffer (from a previous crashed run), oldest-first.
2. **Drain.** When the buffer is empty, fetch one batch and **persist it to the durable file buffer (flush-to-disk) BEFORE handing anything out.** This is the backup the API no longer has.
3. **Deliver one-by-one.** For each buffered event, oldest-first: decrypt its value *at delivery* (never on disk), build the typed `Change`, call `handler`.
4. **Ack / retry / dead-letter.** On success, remove the event from the buffer (ack). On a handler error, retry with backoff up to `MaxRetries`; then either move it to the dead-letter store and continue (`OnError.DeadLetter`, default — one poison event never wedges the stream) or stop and re-throw (`OnError.Halt`). A `DecryptException` on a buffered event (corrupt/truncated ciphertext, rotated key) is **dead-lettered immediately** — re-decrypting can't fix it, so it does *not* burn retries (under `OnError.Halt` it re-throws). Either way it never propagates out and wedges replay.
5. Repeat until a drain returns empty **and** the buffer is drained → return.

### The durable buffer

* Plain files under `cache_dir` (zero extra dependencies): `pending/` for un-acked events, `deadletter/` for ones that exhausted retries.
* Stored events keep their **ciphertext** value — **no plaintext PII is ever written to disk**. Decryption happens only at delivery.
* Writes are crash-safe (temp file → flush-to-disk → atomic move). Files are named with a monotonic, zero-padded sequence so they replay oldest-first.

### Crash safety, at-least-once, and idempotency

A batch is durably buffered *before* any delivery, and acked per-item only *after*
the handler succeeds. The ack can't be atomic with your side-effects — a crash
between your handler's success and its ack re-delivers that event on the next run.
That makes delivery **at-least-once**, so:

> **Your handler must be idempotent. Dedup on `Change.Id`.**

`Change.Id` is the stable server change-row id, captured before the server delete,
so it survives crash + replay unchanged.

### No follow mode

`ProcessChangesAsync` returns when the feed empties. **You** schedule re-runs — a
cron job, a `while` loop with a delay, a hosted `BackgroundService`, whatever
fits. The feed is cheap to poll (see [Rate limits](#rate-limits)).

### Worked example

```csharp
using Allus.CompanyData;

using var client = Client.FromConfig("allus.json");

async Task Handle(Change change)
{
    if (Seen(change.Id)) return;          // idempotent — skip anything we've already applied
    switch (change.Event)
    {
        case "field_updated":
            await StoreValue(change.PersonId, change.Slug, change.ValueObj, change.Live);
            break;
        case "field_deleted":
            await ClearValue(change.PersonId, change.Slug);
            break;
        case "connection_deleted":
            await DropPerson(change.PersonId);
            break;
        case "connection_created" or "consent_accepted" or "consent_declined":
            await NoteEvent(change.PersonId, change.Event, change.At);
            break;
    }
    RecordSeen(change.Id);
}

// Schedule your own re-runs; ProcessChangesAsync itself returns when empty.
while (true)
{
    await client.ProcessChangesAsync(Handle, new ProcessOptions { BatchSize = 200, MaxRetries = 5 });
    await Task.Delay(TimeSpan.FromSeconds(5));
}
```

If a handler keeps failing, the event lands in the dead-letter store instead of
blocking the stream; inspect with `client.DeadLetters()` and re-drive with
`client.RetryDeadLettersAsync(Handle)` after fixing the cause. See
[`docs/pump.md`](docs/pump.md).

---

## Company documents

Beyond the inbound request-field values, your service can push **documents** out to
the people it's connected to — a contract to sign, an offer, a generated PDF, a
JSON record. A document targets either **one person** (per-person) or **everyone**
(broadcast), and the SDK handles the encryption for you.

### The one rule that matters

**Every per-person document is automatically end-to-end encrypted to the
recipient's public key. Broadcast documents are sent in plaintext.** Encryption is
decided purely by the *target*, never by you:

| Target | Encryption |
|--------|-----------|
| **per-person** (`connectionId`, `personUserId`, or `shareCode` given) | **always encrypted** to that recipient's key — for *every* per-person doc, regardless of `isPrivate` |
| **broadcast** (no target) | **plaintext** (a plaintext value can't be locked) |

`isPrivate` is **device-display-only** — it controls how the recipient's app shows
the value (a lock-and-tap-to-reveal field vs decrypt-on-load), nothing about the
wire encryption. Because a broadcast value is plaintext and therefore can't be
locked, **`isPrivate=true` requires a per-person target** (passing it on a
broadcast throws `ConfigException`).

No method ever takes a key, passphrase, or secret argument — the recipient's
public key is resolved from the target's `share_code` (fetched + cached for you),
and decryption of anything you read back uses your in-memory service key.

`payloadKind` selects the body shape:

* `"json"` — a structured object you pass as `jsonValue`.
* `"file"` — raw bytes you pass as `fileBytes` (+ a `fileMime`).

### Create a document

```csharp
using Allus.CompanyData;

using var client = Client.FromConfig("allus.json");

// BROADCAST — a plaintext JSON document delivered to every connection.
// (No target → plaintext; isPrivate must stay false here.)
var notice = await client.CreateDocumentAsync(
    name:        "2026 Terms of Service",
    payloadKind: "json",
    kind:        "document",
    jsonValue:   new { version = "2026.1", url = "https://acme.example/tos" });

// PER-PERSON — automatically end-to-end encrypted to the recipient's key.
// Identify the target by connectionId, personUserId, or shareCode (any one).
// isPrivate=true is allowed here (per-person target) and makes the recipient's
// app show it as a lock-to-reveal field — the wire encryption happens regardless.
var contract = await client.CreateDocumentAsync(
    name:         "Service agreement — Alice",
    payloadKind:  "json",
    kind:         "legal_document",
    isPrivate:    true,
    connectionId: "019xxxxxxxxxxxxxxxxxxxxxxxxx",   // or personUserId: "…" / shareCode: "ABC123"
    jsonValue:    new { plan = "pro", signed = false },
    status:       "ready_to_sign");

// PER-PERSON FILE — the bytes are encrypted to the recipient before upload.
byte[] pdf = await File.ReadAllBytesAsync("/tmp/agreement.pdf");
var signed = await client.CreateDocumentAsync(
    name:         "Signed agreement — Alice",
    payloadKind:  "file",
    kind:         "document",
    personUserId: "019yyyyyyyyyyyyyyyyyyyyyyyyy",
    fileBytes:    pdf,
    fileMime:     "application/pdf");

Console.WriteLine($"{contract.Id} {contract.Status} (private={contract.IsPrivate})");
```

`CreateDocumentAsync` returns a `Document(Id, Kind, Name, Description, Status,
PayloadKind, IsPrivate, ValueObj, Metadata, CreatedAt, UpdatedAt)`. For a
`payload_kind="json"` document, call `doc.Json()` to get the plaintext object back
(a per-person doc is decrypted with your service key transparently; a broadcast doc
is already plaintext).

### List, fetch, update, delete

```csharp
// List this service's documents (paged; optional person / status filter).
var docs = await client.ListDocumentsAsync(status: "ready_to_sign", limit: 50);
foreach (var d in docs)
    Console.WriteLine($"{d.Id} {d.Name} [{d.Status}]");

// Fetch one by id.
var doc = await client.DocumentAsync(contract.Id!);

// Advance its lifecycle status.
await client.UpdateDocumentStatusAsync(contract.Id!,
    "active");   // offering | ready_to_sign | active | active_but_ending | ended

// Update metadata / name / description (any subset).
await client.UpdateDocumentMetadataAsync(contract.Id!,
    name: "Service agreement — Alice (v2)",
    metadata: new { revision = 2 });

// Delete the document (and its on-disk file).
await client.DeleteDocumentAsync(contract.Id!);
```

### Reacting to status changes in the pump / webhook

When a recipient acts on a document (e.g. signs it), the platform emits a
**`document_status_changed`** change event. It carries `Change.DocumentId` and
`Change.Status` (no slot/slug/value), so handle it alongside the field events:

```csharp
async Task Handle(Change change)
{
    if (Seen(change.Id)) return;                 // idempotent — dedup on the stable id
    switch (change.Event)
    {
        case "document_status_changed":
            await OnDocumentStatus(change.DocumentId, change.Status);   // e.g. "active"
            break;
        case "field_updated":
            await Store(change.PersonId, change.Slug, change.ValueObj);
            break;
        // … connection_created / connection_deleted / field_deleted / consent_* …
    }
    RecordSeen(change.Id);
}

await client.ProcessChangesAsync(Handle);
```

The same event arrives over [webhooks](#webhooks) with the identical shape — read
`change.DocumentId` / `change.Status` either way.

---

## Webhooks

Webhooks are the lower-latency push alternative to polling the changes feed. The
platform POSTs each change event to your configured webhook URL with:

* `X-Allus-Webhook-Id` — which webhook this is (selects the HMAC secret from config).
* `X-Allus-Signature` — `HMAC-SHA256(rawBody, secret)` as lowercase hex.
* the body — the same slug-keyed `Change` shape as the pull feed (JSON or XML).

All secrets/keys come from config; the helpers take **no key or secret
arguments**. Use the **raw request body bytes** (do not re-serialize a parsed
body — the HMAC is over the exact bytes the platform sent).

### In an ASP.NET Core minimal API

```csharp
using Allus.CompanyData;

var builder = WebApplication.CreateBuilder(args);
// One client for the app lifetime (it holds the in-memory keys + the durable pump buffer).
builder.Services.AddSingleton(_ => Client.FromConfig("allus.json"));
var app = builder.Build();

app.MapPost("/allus/webhook", async (HttpRequest req, Client client) =>
{
    // Read the EXACT bytes — never a re-serialized parsed body (the HMAC is over these bytes).
    using var ms = new MemoryStream();
    await req.Body.CopyToAsync(ms);
    var rawBody = ms.ToArray();
    var headers = req.Headers.ToDictionary(h => h.Key, h => (string)h.Value!);

    Change change;
    try
    {
        change = client.HandleWebhook(rawBody, headers); // verify + parse + decrypt
    }
    catch (WebhookException)
    {
        return Results.Unauthorized();                   // bad / unknown signature, or unparseable envelope
    }

    // Same idempotency rule as the pump: dedup on change.Id.
    if (!Seen(change.Id))
    {
        await ApplyChange(change);
        RecordSeen(change.Id);
    }
    return Results.NoContent();
});

app.Run();
```

`VerifyWebhook` / `ParseWebhook` let you split the steps if you prefer:

```csharp
if (!client.VerifyWebhook(rawBody, headers))
    return Results.Unauthorized();
var change = client.ParseWebhook(rawBody, headers);
```

### Config-driven secrets

Per-webhook HMAC secrets live in the config `webhooks` map, keyed by webhook id;
the SDK reads `X-Allus-Webhook-Id` off the request and looks up the matching
secret. A single-webhook service can use the flat `"webhook_secret": "…"`
shortcut (or `ALLUS_WEBHOOK_SECRET`). An unknown/unconfigured id ⇒ verification
returns `false` (and `HandleWebhook` throws `WebhookException`).

### The `encrypt_payload` account-key envelope

If a webhook has `encrypt_payload` enabled, the body is **replaced** by a
`{"_enc":1,…}` envelope encrypted to your company **account** key (and the HMAC is
over that envelope — the final bytes sent). `ParseWebhook`/`HandleWebhook`
unwrap it transparently using the configured `account_private_key` +
`account_passphrase`, then decrypt the inner field value with the service key — so
an encrypted-payload `Change` is identical to a plain one. If you receive such a
webhook without an `account_private_key` configured, you get a `WebhookException`.

> The account-key envelope uses OAEP-**SHA1** (OpenSSL's default), distinct from
> the OAEP-SHA256 used for person field values — the SDK handles this difference
> internally (`RSAEncryptionPadding.OaepSHA1` vs `OaepSHA256`); you only supply
> the account key in config.

See [`docs/webhooks.md`](docs/webhooks.md).

---

## Rate limits

| Endpoint | Limit | Use it for |
|----------|-------|-----------|
| `changes` (the pump) | **generous** | Poll **as often as you like** — it's a cheap drain-on-fetch queue. |
| `request-fields`, `logs` | moderate | Occasional reads. |
| `connections`, `ConnectionAsync(id)`, binary `/file` | **heavily limited** | Initial full sync + occasional reconciliation **only** — never as a poll substitute. |

A 429 carries `Retry-After`. The SDK backs off and retries automatically:

* The transport (`ApiHttp`) retries a 429 a bounded number of times honoring `Retry-After`, then surfaces `RateLimitException`.
* The `ConnectionsAsync(...)` stream additionally backs off per `Retry-After` on a surfaced `RateLimitException` and retries the page a bounded number of times before re-throwing — so it paces itself within the limit instead of hammering.

If you catch a `RateLimitException`, its `.RetryAfter` is the seconds to wait
(or `null` when the header was absent).

---

## Errors

All in `Allus.CompanyData`. Same taxonomy + names across all six SDKs (adapted to
C#'s `*Exception` convention).

| Error | When |
|-------|------|
| `ConfigException` | Missing/invalid config, unreadable key file, or wrong passphrase — at construction (fail fast). |
| `AuthException` | Token fetch/refresh failed (bad `client_id`/`secret`, revoked client); or a 401 survives the one automatic refresh-and-retry. |
| `ApiException(Status, ErrorKey)` | Any non-2xx from the API; carries the HTTP `Status`, the platform `ErrorKey` (when present), and a message. |
| `DecryptException` | A ciphertext wrapper is malformed, the key is wrong, or the GCM tag mismatches. Surfaces when a value is accessed/decrypted. |
| `WebhookException` | Signature verification failed, or an envelope couldn't be unwrapped/parsed. |
| `RateLimitException(RetryAfter)` | A 429 from a rate-limited endpoint. Subclass of `ApiException` (Status fixed at 429); carries `RetryAfter` (seconds, or `null`). |

```csharp
using Allus.CompanyData;

try
{
    using var client = Client.FromConfig("allus.json");
    await foreach (var conn in client.ConnectionsAsync())
        Process(conn);
}
catch (ConfigException) { /* fix the config / key file */ }
catch (RateLimitException e) { await Task.Delay(TimeSpan.FromSeconds(e.RetryAfter ?? 60)); }
catch (ApiException e) { Log(e.Status, e.ErrorKey, e.Message); }
```

See [`docs/errors.md`](docs/errors.md).

---

## How it's wired

Everything below is what the SDK hides so your code only ever sees conclusions.

**Auth / token.** An `ApiHttp` owns a `client_credentials`-only token. On the
first call (or when the cached token nears expiry) it POSTs
`client_id`/`client_secret` to `{api_url}/oauth2/token` and caches the bearer
token + its expiry; refresh is automatic. A mid-flight 401 triggers exactly one
refresh-and-retry, then `AuthException`. The token is scoped server-side to **one**
service, so every call is implicitly that service's data.

**Slug resolution.** `RequestFieldsAsync()` is fetched once and cached; its
slug→type map types every value (so `address` parses to a dictionary, `photo`
becomes a lazy binary handle, etc.). The connection/changes endpoints return
values keyed by **your** request slug — the person's source field is dropped
server-side and never reaches the SDK.

**Decryption (zero-knowledge).** The service private key is loaded **once** at
construction from the configured encrypted PEM + passphrase
(`RSA.ImportFromEncryptedPem`) into an in-memory `RSA`. A `DecryptValue` closure
over it is handed to every model factory and the pump — the key never appears in
a method signature. Each value is a hybrid wrapper
(`{"_enc":1,"k":rsa_oaep_sha256(aesKey),"iv":…,"d":aes256gcm(…)}`); the SDK
RSA-OAEP-SHA256 unwraps the AES key (`RSAEncryptionPadding.OaepSHA256`, which on
.NET pins MGF1-SHA256), then AES-256-GCM decrypts the payload (`AesGcm`, splitting
the trailing 16-byte tag). **The platform only ever holds ciphertext — it never
sees your plaintext.**

**Binary fetch.** A binary value is a lazy `BinaryHandle` over a slot-keyed
`value_url`. On `.BytesAsync()`/`.SaveAsync()` it GETs that file endpoint, unwraps
the `{"encrypted":true,"value":<wrapper>}` envelope, runs the same service-key
decrypt to a JSON file-envelope, and base64-decodes its data URI to the file
bytes. (Slot-keyed, never source-field-keyed.)

**The drain-on-fetch feed.** `ProcessChangesAsync` delegates to a `Pump` wired to a
fetch closure (`GET /changes?limit=`, returning raw ciphertext events) and a
decrypt closure (builds a typed `Change`). Because the fetch deletes the rows it
returns, the pump persists each batch to the durable file buffer (ciphertext at
rest) before delivery, acks per-item after your handler succeeds, and replays the
buffer on restart — see [The changes pump](#the-changes-pump).

---

## Build & test

```bash
dotnet build                  # clean build of the library + tests
dotnet test                   # all unit tests, incl. the cross-language crypto-parity check
dotnet pack -c Release        # produce the NuGet package
```

The crypto-parity check loads the PBES2-encrypted service PEM with its
passphrase, decrypts the text wrapper to the exact expected plaintext, and
decrypts the binary wrapper to its envelope and then the inner file bytes (both
SHA-256-matched) — proving the wire format is decoded identically to the other
ports, not merely self-consistently.

## Sign in with allme (OAuth, #195)

```csharp
var oauth = OAuthClient.FromConfig("idw-config.json");
var url = oauth.AuthorizeUrl("signin", state: state, codeChallenge: ch);
// ...user approves; your redirect receives ?code=...
var res = await oauth.CompleteSignInAsync(code, verifier); // res.DisplayName, res.Mode, res.Values
```

Modes: `signin` | `one_time` (claim values decrypted for you) | `connect`. `PollResultAsync(state)` drives the detached mode.
