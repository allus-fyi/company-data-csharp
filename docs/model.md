# Output model reference

The conclusions — the only objects you work with, all in `Allus.CompanyData`. Each
is an immutable `record` and carries `.Raw` (the underlying hardened API object
graph; never contains the person's source field).

## `RequestField`

Your request-field **definition** — your config, never the person's fields.
Returned by `client.RequestFieldsAsync()`.

```csharp
public sealed record RequestField(
    string? Slug,      // the stable, company-set key — the contract for value access
    string? Label,     // the human label (rename freely; the slug stays)
    string? Type,      // email|phone|url|text|address|bank|creditcard|date|date_of_birth|photo|document|legal_document
    bool OneTime,      // a one-time snapshot vs a live (auto-updating) answer
    bool Mandatory)    // mandatory-to-provide OR mandatory-to-stay-connected (the API's two flags, folded)
{ public object? Raw { get; init; } }
```

## `Connection`

A connected person — identity + the slug-keyed value map. No source field
anywhere; `Values` is keyed by **your** request slug.

```csharp
public sealed record Connection(
    string? Id,
    string? PersonId,
    string? DisplayName,                          // null on ConnectionAsync(id) (the list endpoint carries it)
    DateTimeOffset? ConnectedAt,                   // likewise null on ConnectionAsync(id)
    IReadOnlyDictionary<string, Value> Values)     // {<your_slug>: Value}
{ public object? Raw { get; init; } }
```

```csharp
conn.Values["work_email"].ValueObj                 // "alice@acme.com"
conn.Values.TryGetValue("mobile", out var mobile)   // false if the person didn't answer that slot
```

## `Value`

One answer for one of your request slots.

```csharp
public sealed record Value(
    object? ValueObj,                  // typed plaintext (see below)
    bool Live,                         // true = "keep connected" (auto-updates); false = one-time snapshot
    DateTimeOffset? UpdatedAt)         // when this answer last changed
{ public object? Raw { get; init; } }
```

### `ValueObj` types (resolved from the field's `type`)

| Field type | .NET `ValueObj` | Notes |
|------------|-----------------|-------|
| `email`, `phone`, `url`, `text` | `string` | The decrypted plaintext. |
| `address`, `bank`, `creditcard` | `IDictionary<string, object?>` | The decrypted plaintext is a JSON object → parsed. A non-JSON structured value throws `DecryptException`. |
| `date`, `date_of_birth` | `DateOnly` | Parsed from ISO `YYYY-MM-DD` (the leading 10 chars); falls back to the raw `string` if unparseable. |
| `photo`, `document`, `legal_document` | `BinaryHandle` | Lazy — nothing fetched/decrypted until `.BytesAsync()`/`.SaveAsync()`. |
| unanswered / no value | `null` | The slot has no answer. |

Cast `ValueObj` to the expected type per the slug's field type:

```csharp
var addr = (IDictionary<string, object?>)conn.Values["home_address"].ValueObj!;
var dob  = (DateOnly)conn.Values["birthday"].ValueObj!;
```

## `BinaryHandle`

A lazy handle for a binary value. No network or decryption happens at construction.

```csharp
public sealed class BinaryHandle
{
    public string? ValueUrl { get; }                                   // the opaque slot-keyed file URL (read-only)
    public Task<byte[]> BytesAsync(CancellationToken ct = default);     // fetch (if needed) → decrypt → decoded primary file bytes
    public Task<int>    SaveAsync(string path, CancellationToken ct);   // write BytesAsync() to path (atomic); returns bytes written
}
```

On first `.BytesAsync()`/`.SaveAsync()`:

1. GET the slot-keyed file endpoint → the API serves `{"encrypted": true, "value": <wrapper>}`.
2. Decrypt the inner `{"_enc":1,…}` wrapper with the service key → a JSON file-envelope string (`{"full": "data:…", "thumb": …}` for photos, `{"file": "data:…", …}` for documents).
3. Base64-decode the primary data URI (`full` for photos, `file` for documents) → the file bytes. Cached on the handle (repeated calls don't re-fetch).

`.SaveAsync()` writes crash-safely: a temp file in the destination directory is
written, flushed to disk (`FileStream.Flush(flushToDisk: true)`), then atomically
`File.Move(temp, dest, overwrite: true)`-d — so a crash mid-write never leaves a
truncated output. An unanswered binary slot yields an empty handle; calling
`.BytesAsync()` on it throws `DecryptException`.

## `Change`

A change-feed / webhook event. Returned by the pump (`ProcessChangesAsync`,
`DrainBatchAsync`) and the webhook helpers.

```csharp
public sealed record Change(
    string? Id,                  // the stable server change-row id — YOUR dedup key
    string? Event,               // see the event table
    string? PersonId,
    string? Slug = null,         // field_updated/field_deleted/consent_* only
    object? ValueObj = null,     // field_updated only; typed exactly like Value.ValueObj
    bool? Live = null,           // field_updated only
    DateTimeOffset? At = null)   // the change time (no separate UpdatedAt on a change)
{ public object? Raw { get; init; } }
```

### Events

| `Event` | Carries |
|---------|---------|
| `connection_created` | identity only (no slot/value) |
| `connection_deleted` | identity only (no slot/value) |
| `field_updated` | `Slug` + decrypted `ValueObj` (+ `Live`); binary → a lazy `BinaryHandle` |
| `field_deleted` | `Slug`, no value |
| `consent_accepted` / `consent_declined` | `Slug` |

`Change.Id` is captured before the server's drain-delete, so it survives a
crash + replay unchanged — dedup on it.

## `LogEntry`

A service activity-log entry — ops events only (email / purge / webhook), never
person field data.

```csharp
public sealed record LogEntry(
    string? Type,
    string? Message,
    object? Metadata,
    DateTimeOffset? At)
{ public object? Raw { get; init; } }
```

## `.Raw` and `Node`

Every model has a `.Raw` property: the underlying (hardened) API object as a plain
graph (`Dictionary<string,object?>` / `List<object?>` / scalar). It never contains
the person's source field — the hardened API doesn't return it. Internally the SDK
materializes both JSON and XML bodies into a wire-format-agnostic `Node` tree (also
the type returned by `client.DeadLetters()`), so the model layer is identical for
either wire format. `Node` exposes `Get(key)`, `AsString()`, `AsList()`,
`AsObject()`, and `ToObjectGraph()`.
