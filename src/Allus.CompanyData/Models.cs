// Output model — the conclusions.
//
// The consumer works with these and nothing else. They are produced by factories that turn a
// hardened API payload Node (slug-keyed `values`; NO person source field) into typed objects,
// decrypting ciphertext via the injected crypto closure.
//
//   RequestField { Slug, Label, Type, OneTime, Mandatory, Verified, VerifiedMaxAgeDays }
//   Connection   { Id, PersonId, DisplayName, ConnectedAt, Values: {<slug>: Value} }
//   Value        { ValueObj, Live, UpdatedAt, Verified, VerifiedAt, VerifiedExpiresAt,
//                  VerifiedMethod, VerifiedProvider, VerificationId }
//   Change       { Id, Event, PersonId, ShareCode?, Slug?, Value?, Live?, At }   // Id = stable dedup key
//   LogEntry     { Type, Message, Metadata, At }
//
// Typed values:
//   * email/phone/url/text                 → string
//   * address/bank/creditcard              → IReadOnlyDictionary<string,object?> (parsed JSON object)
//   * date/date_of_birth                   → DateOnly
//   * photo/document/legal_document and the ID-document subtypes
//     passport/photo_id/drivers_license    → a lazy BinaryHandle
//
// Every model carries Raw — the underlying (hardened) API object graph — for debugging or an edge
// case the SDK didn't model. It still never contains the person's source field. Decryption is
// config-driven: the factory takes a decryptValue closure (over the loaded service private key)
// and, for binaries, a binaryFetch closure — never a key/secret argument.

using System.Globalization;
using System.Text.Json;

namespace Allus.CompanyData;

/// <summary>A decrypt closure: ciphertext wrapper Node → decrypted plaintext string.</summary>
public delegate string DecryptValue(object wrapper);

/// <summary>A type resolver: slug → the request field's type (e.g. "email", "photo"), or null.</summary>
public delegate string? TypeForSlug(string slug);

/// <summary>
/// A binary fetch closure: a slot value_url → the classified response (either the inner
/// {"_enc":1,...} wrapper, or the file bytes themselves when the person's source field is not private).
/// </summary>
public delegate Task<BinaryFetchResult> BinaryFetch(string valueUrl, CancellationToken ct);

internal static class ModelCoerce
{
    public static readonly string[] StructuredTypes = { "address", "bank", "creditcard" };
    // The ID-document subtypes are children of legal_document and share its envelope.
    public static readonly string[] BinaryTypes =
        { "photo", "document", "legal_document", "passport", "photo_id", "drivers_license" };
    public static readonly string[] DateTypes = { "date", "date_of_birth" };

    public static DateTimeOffset? ParseIsoDt(string? value)
    {
        if (string.IsNullOrEmpty(value)) return null;
        return DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture,
            DateTimeStyles.RoundtripKind, out var dt) ? dt : null;
    }

    /// <summary>
    /// Whether a verification expiry stamp has already passed. Absent → false: a verification with
    /// no expiry never lapses. Present but unparseable → true: an expiry that cannot be evaluated
    /// cannot be used to claim the value is still verified today.
    /// </summary>
    public static bool ExpiryPassed(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        var when = ParseIsoDt(value);
        return when is null || when.Value <= DateTimeOffset.UtcNow;
    }

    /// <summary>Coerce a JSON number or an XML numeric string into an int, or null when absent.</summary>
    public static int? CoerceInt(Node node)
    {
        if (node.IsNull) return null;
        return node.RawScalar switch
        {
            long l => (int)l,
            double d => (int)d,
            string s => int.TryParse(s.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture,
                out var parsed) ? parsed : null,
            _ => null,
        };
    }

    public static bool? CoerceBool(Node node)
    {
        if (node.IsNull) return null;
        return node.RawScalar switch
        {
            bool b => b,
            string s => s.Trim().ToLowerInvariant() switch
            {
                "true" or "1" => true,
                "false" or "0" or "" => false,
                _ => (bool?)Convert.ToBoolean(s),
            },
            null => null,
            long l => l != 0,
            double d => d != 0,
            _ => null,
        };
    }

    public static DateOnly? ParseDate(string value)
    {
        var s = value.Trim();
        if (s.Length >= 10) s = s[..10];
        return DateOnly.TryParseExact(s, "yyyy-MM-dd", CultureInfo.InvariantCulture,
            DateTimeStyles.None, out var d) ? d : null;
    }
}

/// <summary>
/// A request-field DEFINITION — YOUR config, never the person's. <see cref="Mandatory"/>
/// folds the API's two flags: true when mandatory to provide OR mandatory to stay connected.
/// </summary>
public sealed record RequestField(
    string? Slug,
    string? Label,
    string? Type,
    bool OneTime,
    bool Mandatory)
{
    /// <summary>The underlying hardened API object (escape hatch).</summary>
    public object? Raw { get; init; }

    /// <summary>Which customer TYPE this row applies to: "person"|"company"|"both" (B2B); null on older API.</summary>
    public string? Audience { get; init; }

    /// <summary>
    /// This row DEMANDS a verified answer: only a value the person verified satisfies it, and an
    /// unverified candidate is refused at the accepting act rather than downgraded.
    /// </summary>
    public bool Verified { get; init; }

    /// <summary>
    /// The oldest verification the demand accepts, in days; null = no age limit. Enforced at the
    /// accepting act only — a standing live link is not re-enforced afterwards, so apply your own
    /// policy from each <see cref="Value.VerifiedAt"/>.
    /// </summary>
    public int? VerifiedMaxAgeDays { get; init; }

    public static RequestField FromApi(Node obj) => new(
        Slug: obj.Get("slug").AsString(),
        Label: obj.Get("label").AsString(),
        Type: obj.Get("type").AsString(),
        OneTime: ModelCoerce.CoerceBool(obj.Get("one_time")) ?? false,
        Mandatory: (ModelCoerce.CoerceBool(obj.Get("mandatory_provide")) ?? false)
                   || (ModelCoerce.CoerceBool(obj.Get("mandatory_connected")) ?? false))
    {
        Raw = obj.ToObjectGraph(),
        Audience = obj.Get("audience").AsString(),
        Verified = ModelCoerce.CoerceBool(obj.Get("verified")) ?? false,
        VerifiedMaxAgeDays = ModelCoerce.CoerceInt(obj.Get("verified_max_age_days")),
    };

    public static List<RequestField> ListFromApi(Node body)
    {
        var items = body.Kind == NodeKind.Object && body.Has("request_fields")
            ? body.Get("request_fields").AsList()
            : body.Kind == NodeKind.List ? body.AsList() : new List<Node>();
        return items.Select(FromApi).ToList();
    }
}

/// <summary>
/// A single answer for one of YOUR request slots. <see cref="ValueObj"/> is the typed
/// plaintext (string / dictionary / DateOnly / lazy BinaryHandle); <see cref="Live"/> = the person
/// chose "keep connected" (auto-updates) vs a one-time snapshot; <see cref="UpdatedAt"/> = when this
/// answer last changed. Both ride on the Value (per-answer), not the definition.
/// </summary>
public sealed record Value(object? ValueObj, bool Live, DateTimeOffset? UpdatedAt)
{
    /// <summary>The underlying hardened API value object (escape hatch).</summary>
    public object? Raw { get; init; }

    /// <summary>True iff the hash recomputes over the plaintext AND the verification has not lapsed.</summary>
    public bool Verified { get; init; }

    /// <summary>
    /// When the person's answering field was verified; null when the value carries no verification.
    /// A stamp, not a promise about today — read it with <see cref="Verified"/>.
    /// </summary>
    public DateTimeOffset? VerifiedAt { get; init; }

    /// <summary>
    /// When that verification lapses (a document-backed verification dies with the document);
    /// null = it does not lapse. Past → <see cref="Verified"/> reads false.
    /// </summary>
    public DateTimeOffset? VerifiedExpiresAt { get; init; }

    /// <summary>
    /// HOW allme bound this value: <c>email_code</c> | <c>sms_code</c> | <c>sumsub_id</c> |
    /// <c>sumsub_address</c>. Null when the value was bound before the proof log existed — the
    /// three proof members arrive together or not at all. Readable whatever
    /// <see cref="Verified"/> says; that boolean stays the only trust decision.
    /// </summary>
    public string? VerifiedMethod { get; init; }

    /// <summary>WHO established the proof: <c>allme</c> | <c>sumsub</c>. Same all-or-none set.</summary>
    public string? VerifiedProvider { get; init; }

    /// <summary>The id to quote back to allme in a dispute. Same all-or-none set.</summary>
    public string? VerificationId { get; init; }

    public static Value FromApi(
        Node obj,
        string? fieldType,
        DecryptValue decryptValue,
        BinaryFetch? binaryFetch)
    {
        var live = ModelCoerce.CoerceBool(obj.Get("live")) ?? false;
        var updatedAt = ModelCoerce.ParseIsoDt(
            obj.Has("updatedAt") ? obj.Get("updatedAt").AsString() : obj.Get("updated_at").AsString());
        var typed = TypedValue(obj, fieldType, decryptValue, binaryFetch);
        return new Value(typed, live, updatedAt)
        {
            Raw = obj.ToObjectGraph(),
            Verified = VerifiedFrom(obj, typed),
            VerifiedAt = ModelCoerce.ParseIsoDt(obj.Get("verified_at").AsString()),
            VerifiedExpiresAt = ModelCoerce.ParseIsoDt(obj.Get("verified_expires_at").AsString()),
            VerifiedMethod = obj.Get("verified_method").AsString(),
            VerifiedProvider = obj.Get("verified_provider").AsString(),
            VerificationId = obj.Get("verification_id").AsString(),
        };
    }

    /// <summary>
    /// Recompute the verified flag from the just-decrypted plaintext (text values only).
    ///
    /// <para>Two conditions, both required: the hash recomputes over the exact plaintext, AND the
    /// verification has not lapsed (<c>verified_expires_at</c> absent or still in the future). A
    /// document-backed verification lapses when the document itself expires, so a stale binding
    /// reads false here without any lookup.</para>
    /// </summary>
    internal static bool VerifiedFrom(Node obj, object? plaintext)
    {
        if (plaintext is not string pt) return false;
        var vhash = obj.Get("verified_hash").AsString();
        var vsalt = obj.Get("verified_salt").AsString();
        if (string.IsNullOrEmpty(vhash) || string.IsNullOrEmpty(vsalt)) return false;
        if (ModelCoerce.ExpiryPassed(obj.Get("verified_expires_at").AsString())) return false;
        return Crypto.HashMatches(vsalt, vhash, pt);
    }

    internal static object? TypedValue(
        Node obj,
        string? fieldType,
        DecryptValue decryptValue,
        BinaryFetch? binaryFetch)
    {
        var ftype = (fieldType ?? "").ToLowerInvariant();

        // Binary → a lazy handle over the slot value_url (no eager fetch/decrypt).
        if (ModelCoerce.BinaryTypes.Contains(ftype) || obj.Has("value_url"))
        {
            var valueUrl = obj.Get("value_url").AsString();
            if (valueUrl is null)
                return new BinaryHandle(valueUrl: null, fetch: null, decrypt: null);
            Func<string, CancellationToken, Task<BinaryFetchResult>>? fetch = binaryFetch is null
                ? null
                : (url, ct) => binaryFetch(url, ct);
            return new BinaryHandle(valueUrl, fetch, w => decryptValue(w));
        }

        // Non-binary → decrypt the ciphertext wrapper to plaintext.
        if (!obj.Has("value") || obj.Get("value").IsNull)
            return null;
        var ciphertext = obj.Get("value");
        var plaintext = decryptValue(ciphertext);

        if (ModelCoerce.StructuredTypes.Contains(ftype))
        {
            try
            {
                using var doc = JsonDocument.Parse(plaintext);
                return Node.FromJson(doc.RootElement).ToObjectGraph();
            }
            catch (JsonException ex)
            {
                throw new DecryptException($"structured value for type '{ftype}' is not valid JSON", ex);
            }
        }

        if (ModelCoerce.DateTypes.Contains(ftype))
        {
            var parsed = ModelCoerce.ParseDate(plaintext);
            return parsed.HasValue ? parsed.Value : plaintext;
        }

        // text/email/phone/url and anything unknown → the plaintext string.
        return plaintext;
    }
}

/// <summary>
/// A connected person — identity + the slug-keyed value map. NO source field anywhere:
/// <see cref="Values"/> is keyed by YOUR request slug.
/// </summary>
public sealed record Connection(
    string? Id,
    string? PersonId,
    string? DisplayName,
    DateTimeOffset? ConnectedAt,
    IReadOnlyDictionary<string, Value> Values)
{
    /// <summary>The underlying hardened API object (escape hatch).</summary>
    public object? Raw { get; init; }

    /// <summary>The connected customer's TYPE: "person"|"company" (B2B); null on older API.</summary>
    public string? CustomerType { get; init; }

    /// <summary>The customer's profile share code (previously only via <see cref="Raw"/>); null when absent.</summary>
    public string? ShareCode { get; init; }

    public static Connection FromApi(
        Node obj,
        TypeForSlug typeForSlug,
        DecryptValue decryptValue,
        BinaryFetch? binaryFetch = null,
        Node? identity = null)
    {
        var id = identity ?? Node.Null;
        var connId = obj.Get("connection_id").AsString()
            ?? obj.Get("id").AsString()
            ?? id.Get("connection_id").AsString();
        var personId = obj.Get("user_id").AsString()
            ?? obj.Get("person_id").AsString()
            ?? obj.Get("person_user_id").AsString()
            ?? id.Get("user_id").AsString();
        var displayName = obj.Get("display_name").AsString() ?? id.Get("display_name").AsString();
        var connectedAt = ModelCoerce.ParseIsoDt(
            obj.Get("connected_at").AsString() ?? id.Get("connected_at").AsString());

        var values = new Dictionary<string, Value>();
        var valuesNode = obj.Get("values");
        if (valuesNode.Kind == NodeKind.Object)
        {
            foreach (var (slug, entry) in valuesNode.AsObject())
            {
                if (entry.Kind != NodeKind.Object) continue;
                values[slug] = Value.FromApi(entry, typeForSlug(slug), decryptValue, binaryFetch);
            }
        }

        return new Connection(connId, personId, displayName, connectedAt, values)
        {
            Raw = obj.ToObjectGraph(),
            CustomerType = obj.Get("customer_type").AsString() ?? id.Get("customer_type").AsString(),
            ShareCode = obj.Get("share_code").AsString() ?? id.Get("share_code").AsString(),
        };
    }
}

/// <summary>
/// A change feed / webhook event. <see cref="Id"/> is the stable server
/// change-row id (the pump dedupes on it after a crash/replay); <see cref="At"/> is the change time
/// (no separate UpdatedAt on a change). <see cref="Slug"/>/<see cref="ValueObj"/>/<see cref="Live"/>
/// are present only on <c>field_updated</c> (connection/consent events carry no slot/value).
/// </summary>
public sealed record Change(
    string? Id,
    string? Event,
    string? PersonId,
    string? ShareCode = null,   // the person's profile share code (every event; may be null)
    string? Slug = null,
    object? ValueObj = null,
    bool? Live = null,
    string? DocumentId = null,  // set on document_status_changed
    string? Status = null,      // set on document_status_changed
    string? Action = null,      // set on document_status_changed for a contract: signed | accepted | cancelled
    string? Note = null,        // set on document_status_changed: the person's optional cancellation note
    string? Method = null,        // set on a signature: biometric | twofa | email | custodian
    string? ContentSha256 = null, // set on a signature: SHA-256 of the signed content
    string? SignedAt = null,      // set on a signature: ISO timestamp the signature was recorded
    string? CancelEffectiveDate = null, // set on a cancelled document_status_changed: ISO date the cancellation takes effect
    string? RequestId = null,   // set on connection_request_accepted | connection_request_rejected
    DateTimeOffset? At = null)
{
    /// <summary>The underlying hardened API object (escape hatch).</summary>
    public object? Raw { get; init; }

    /// <summary>The customer's TYPE: "person"|"company" (B2B); null on older API.</summary>
    public string? CustomerType { get; init; }

    /// <summary>True iff a field_updated value's hash matches AND the verification has not lapsed.</summary>
    public bool Verified { get; init; }

    /// <summary>When the answering field was verified; null when the value carries no verification.</summary>
    public DateTimeOffset? VerifiedAt { get; init; }

    /// <summary>When that verification lapses; null = it does not. Past → <see cref="Verified"/> reads false.</summary>
    public DateTimeOffset? VerifiedExpiresAt { get; init; }

    /// <summary>
    /// HOW allme bound this value: <c>email_code</c> | <c>sms_code</c> | <c>sumsub_id</c> |
    /// <c>sumsub_address</c>. Null when the value was bound before the proof log existed — the
    /// three proof members arrive together or not at all. Readable whatever
    /// <see cref="Verified"/> says; that boolean stays the only trust decision.
    /// </summary>
    public string? VerifiedMethod { get; init; }

    /// <summary>WHO established the proof: <c>allme</c> | <c>sumsub</c>. Same all-or-none set.</summary>
    public string? VerifiedProvider { get; init; }

    /// <summary>The id to quote back to allme in a dispute. Same all-or-none set.</summary>
    public string? VerificationId { get; init; }

    /// <summary>Set on <c>key_rotated</c> — SHA-256 fingerprint of the person's NEW public key.</summary>
    public string? PublicKeySha256 { get; init; }

    /// <summary>Set on <c>message_received</c> — the connection to reply / acknowledge on.</summary>
    public string? ConnectionId { get; init; }

    /// <summary>Set on <c>message_received</c> — the ack boundary (<c>upToMessageId</c>).</summary>
    public string? MessageId { get; init; }

    /// <summary>Set on <c>message_received</c> — base64 SPKI to encrypt the reply to.</summary>
    public string? PersonPublicKey { get; init; }

    /// <summary>Set on <c>message_received</c> — the DECRYPTED message text.</summary>
    public string? MessageBody { get; init; }

    public static Change FromApi(
        Node obj,
        TypeForSlug typeForSlug,
        DecryptValue decryptValue,
        BinaryFetch? binaryFetch = null)
    {
        var slug = obj.Get("slug").AsString();
        var ev = obj.Get("event").AsString();
        bool? live = obj.Has("live") ? ModelCoerce.CoerceBool(obj.Get("live")) : null;

        object? value = null;
        if (ev == "field_updated" && slug is not null && (obj.Has("value") || obj.Has("value_url")))
        {
            // Reuse the Value typing path so feed + connection produce identical typed values
            // (incl. the same lazy BinaryHandle for binaries).
            value = Value.TypedValue(obj, typeForSlug(slug), decryptValue, binaryFetch);
        }

        // message_received carries the connection to answer on, the ack boundary, the person's
        // public key for the reply, and the message ciphertext itself; its created_at stays in Raw.
        var isMessage = ev == "message_received";
        string? messageBody = null;
        if (isMessage && obj.Has("body"))
        {
            // The message ciphertext is carried under `body`, never `value`: on every other
            // event `value` means field ciphertext, which a message body is not. It is
            // encrypted for the SERVICE key, so the ordinary decrypt opens it.
            messageBody = decryptValue(obj.Get("body"));
        }

        return new Change(
            Id: obj.Get("id").AsString(),
            Event: ev,
            PersonId: obj.Get("person_user_id").AsString() ?? obj.Get("person_id").AsString(),
            ShareCode: obj.Get("share_code").AsString(),
            Slug: slug,
            ValueObj: value,
            Live: live,
            DocumentId: obj.Get("document_id").AsString(),
            // 2fa_challenge_completed carries the outcome in Status (approved|denied|revoked); its
            // challenge_id/completed_at stay in Raw. The poll is the record (spec §3).
            Status: (ev == "document_status_changed" || ev == "2fa_challenge_completed") ? obj.Get("status").AsString() : null,
            Action: ev == "document_status_changed" ? obj.Get("action").AsString() : null,
            Note: ev == "document_status_changed" ? obj.Get("note").AsString() : null,
            Method: ev == "document_status_changed" ? obj.Get("method").AsString() : null,
            ContentSha256: ev == "document_status_changed" ? obj.Get("content_sha256").AsString() : null,
            SignedAt: ev == "document_status_changed" ? obj.Get("signed_at").AsString() : null,
            CancelEffectiveDate: ev == "document_status_changed" ? obj.Get("cancel_effective_date").AsString() : null,
            RequestId: ev is "connection_request_accepted" or "connection_request_rejected"
                ? obj.Get("request_id").AsString() : null,
            At: ModelCoerce.ParseIsoDt(obj.Get("at").AsString()))
        {
            Raw = obj.ToObjectGraph(),
            CustomerType = obj.Get("customer_type").AsString(),
            Verified = Value.VerifiedFrom(obj, value),
            VerifiedAt = ModelCoerce.ParseIsoDt(obj.Get("verified_at").AsString()),
            VerifiedExpiresAt = ModelCoerce.ParseIsoDt(obj.Get("verified_expires_at").AsString()),
            VerifiedMethod = obj.Get("verified_method").AsString(),
            VerifiedProvider = obj.Get("verified_provider").AsString(),
            VerificationId = obj.Get("verification_id").AsString(),
            PublicKeySha256 = ev == "key_rotated" ? obj.Get("public_key_sha256").AsString() : null,
            ConnectionId = isMessage ? obj.Get("connection_id").AsString() : null,
            MessageId = isMessage ? obj.Get("message_id").AsString() : null,
            PersonPublicKey = isMessage ? obj.Get("person_public_key").AsString() : null,
            MessageBody = messageBody,
        };
    }

    public static List<Change> ListFromApi(
        Node body,
        TypeForSlug typeForSlug,
        DecryptValue decryptValue,
        BinaryFetch? binaryFetch = null)
    {
        var items = body.Kind == NodeKind.Object && body.Has("changes")
            ? body.Get("changes").AsList()
            : body.Kind == NodeKind.List ? body.AsList() : new List<Node>();
        return items
            .Where(o => o.Kind == NodeKind.Object)
            .Select(o => FromApi(o, typeForSlug, decryptValue, binaryFetch))
            .ToList();
    }
}

/// <summary>
/// A company document the SDK created/queried (company-data side). Value semantics mirror the
/// connection-payload contract — keyed on BROADCAST(plaintext) vs PER-PERSON(always encrypted),
/// NOT on is_private:
/// <code>
///   broadcast file   -> {file, original_name, mime_type, size}   (plaintext)
///   per-person file  -> {"_enc_file": "enc_…json"}   (ciphertext blob, ANY is_private)
///   broadcast json   -> the JSON object   (plaintext)
///   per-person json  -> {"_enc":1,k,iv,d}   (ciphertext wrapper, ANY is_private; decrypt via Json())
/// </code>
/// is_private is device-display-only (lock vs decrypt-on-load), not the value shape.
/// </summary>
public sealed record Document(
    string? Id,
    string? Kind,
    string? Name,
    string? Description,
    string? Status,
    string? PayloadKind,        // "file" | "json"
    bool IsPrivate,
    object? ValueObj,
    object? Metadata,
    DateTimeOffset? CreatedAt,
    DateTimeOffset? UpdatedAt,
    bool RequiresSignature = false,
    bool RequiresAcceptance = false,
    IReadOnlyList<object?>? Signatures = null,  // contract sign/accept audit trail (company-side reads only)
    // Present only on a contract-flow run-participant document: the run's ordered signature
    // summary, one entry per participant owing an act — each
    // {party_key, document_id, position, status, action, acted_at}. Null on any other document.
    IReadOnlyList<object?>? RunSignatures = null)
{
    // The raw value Node (used by Json() to detect an {"_enc":1,…} per-person wrapper) + the
    // decrypt closure (over the loaded service private key). Neither is part of the public record.
    private Node? _valueNode;
    private DecryptValue? _decryptValue;

    /// <summary>The underlying hardened API object (escape hatch).</summary>
    public object? Raw { get; init; }

    /// <summary>
    /// For a json document, return the plaintext object. Decryption is keyed on the value SHAPE
    /// (per-person → encrypted wrapper), NOT on is_private: a per-person json doc (ANY is_private)
    /// is an <c>{"_enc":1,…}</c> wrapper decrypted with the SDK's own private key; a broadcast json
    /// doc is already plaintext and returned as-is.
    /// </summary>
    public object? Json()
    {
        if (PayloadKind != "json")
            throw new DecryptException("Json() is only valid for payload_kind='json' documents");
        var node = _valueNode ?? Node.Null;
        if (node.Kind == NodeKind.Object && node.Has("_enc")
            && (ModelCoerce.CoerceBool(node.Get("_enc")) == true
                || node.Get("_enc").AsString() == "1"))
        {
            if (_decryptValue is null)
                throw new DecryptException("no decrypt wiring for an encrypted (per-person) document");
            var plaintext = _decryptValue(node);
            try
            {
                using var doc = JsonDocument.Parse(plaintext);
                return Node.FromJson(doc.RootElement).ToObjectGraph();
            }
            catch (JsonException ex)
            {
                throw new DecryptException("decrypted document json is not valid JSON", ex);
            }
        }
        return ValueObj;
    }

    public static Document FromApi(Node obj, DecryptValue? decryptValue = null)
    {
        var valueNode = obj.Get("value");
        return new Document(
            Id: obj.Get("id").AsString(),
            Kind: obj.Get("kind").AsString(),
            Name: obj.Get("name").AsString(),
            Description: obj.Get("description").AsString(),
            Status: obj.Get("status").AsString(),
            PayloadKind: obj.Get("payload_kind").AsString(),
            IsPrivate: ModelCoerce.CoerceBool(obj.Get("is_private")) ?? false,
            ValueObj: obj.Has("value") ? valueNode.ToObjectGraph() : null,
            Metadata: obj.Has("metadata") ? obj.Get("metadata").ToObjectGraph() : null,
            CreatedAt: ModelCoerce.ParseIsoDt(obj.Get("created_at").AsString()),
            UpdatedAt: ModelCoerce.ParseIsoDt(obj.Get("updated_at").AsString()),
            RequiresSignature: ModelCoerce.CoerceBool(obj.Get("requires_signature")) ?? false,
            RequiresAcceptance: ModelCoerce.CoerceBool(obj.Get("requires_acceptance")) ?? false,
            Signatures: obj.Has("signatures") && obj.Get("signatures").Kind == NodeKind.List
                ? obj.Get("signatures").AsList().Select(n => n.ToObjectGraph()).ToList()
                : new List<object?>(),
            RunSignatures: obj.Has("run_signatures") && obj.Get("run_signatures").Kind == NodeKind.List
                ? obj.Get("run_signatures").AsList().Select(n => n.ToObjectGraph()).ToList()
                : null)
        {
            _valueNode = obj.Has("value") ? valueNode : Node.Null,
            _decryptValue = decryptValue,
            Raw = obj.ToObjectGraph(),
        };
    }

    public static List<Document> ListFromApi(Node body, DecryptValue? decryptValue = null)
    {
        var items = body.Kind == NodeKind.Object && body.Has("items")
            ? body.Get("items").AsList()
            : body.Kind == NodeKind.List ? body.AsList() : new List<Node>();
        return items.Select(o => FromApi(o, decryptValue)).ToList();
    }
}

/// <summary>
/// The calling client's own service identity, from <c>GET /api/company-data/whoami</c>.
/// <see cref="CompanyUserId"/> is the company user the client is bound to (the value a flow-run
/// binding's company party must use); <see cref="ServiceId"/> is its service.
/// </summary>
public sealed record Identity(string? CompanyUserId, string? ServiceId);

/// <summary>
/// A contract-flow run (company-data side). The company is one of the two bound parties.
/// <see cref="Bindings"/> maps each party key to the bound user_id (the company's own is
/// <see cref="CompanyUserId"/>); <see cref="Answers"/> are the per-party encrypted answer copies
/// (the company reads the rows whose <c>for_user_id == CompanyUserId</c>, decryptable with the
/// service private key); <see cref="Definition"/> is the pinned flow-version graph.
/// </summary>
public sealed record FlowRun(
    string? Id,
    string? FlowId,
    object? FlowVersion,
    string? ServiceId,
    string? ConnectionId,
    string? CompanyUserId,
    IReadOnlyDictionary<string, string> Bindings,
    string? Status,
    string? CurrentNode,
    string? DocumentId,
    string? OutputMode,
    Node Definition,
    IReadOnlyList<Node> Answers,
    DateTimeOffset? CreatedAt,
    DateTimeOffset? UpdatedAt)
{
    /// <summary>The underlying hardened API object (escape hatch).</summary>
    public object? Raw { get; init; }

    /// <summary>Optional YYYY-MM-DD pinned "today" for flow constants; null when absent.</summary>
    public string? ReferenceDate { get; init; }

    /// <summary>
    /// Every party the run binds, the owning company included (flows.html §5a/§9 item 12).
    /// <see cref="ConnectionId"/> above names only the PRIMARY counterparty, so a multi-actor
    /// run's other counterparties are reachable only here.
    /// </summary>
    public IReadOnlyList<FlowRunParticipant> Participants { get; init; } = Array.Empty<FlowRunParticipant>();

    /// <summary>The party key the company is bound to (Bindings[key] == CompanyUserId).</summary>
    public string? CompanyPartyKey
    {
        get
        {
            foreach (var (key, uid) in Bindings)
                if (uid == CompanyUserId) return key;
            return null;
        }
    }

    /// <summary>The company's bound user_id — its answer copies use this for_user_id.</summary>
    public string? ServiceUserId => CompanyUserId;

    public static FlowRun FromApi(Node obj)
    {
        var defNode = obj.Get("definition");
        Node definition;
        if (defNode.Kind == NodeKind.Object)
        {
            definition = defNode;
        }
        else
        {
            definition = Node.Object(new Dictionary<string, Node>
            {
                ["nodes"] = obj.Get("nodes"),
                ["edges"] = obj.Get("edges"),
                ["parties"] = obj.Get("parties"),
                ["output_mode"] = obj.Get("output_mode"),
            });
        }
        var bindings = new Dictionary<string, string>();
        if (obj.Get("bindings").Kind == NodeKind.Object)
            foreach (var (k, v) in obj.Get("bindings").AsObject())
                bindings[k] = v.AsString() ?? "";
        var answers = obj.Get("answers").Kind == NodeKind.List
            ? obj.Get("answers").AsList().Where(a => a.Kind == NodeKind.Object).ToList()
            : new List<Node>();
        var outputMode = obj.Get("output_mode").AsString();
        if (string.IsNullOrEmpty(outputMode))
            outputMode = definition.Get("output_mode").AsString();
        return new FlowRun(
            Id: obj.Get("id").AsString(),
            FlowId: obj.Get("flow_id").AsString(),
            FlowVersion: obj.Has("flow_version") ? obj.Get("flow_version").ToObjectGraph() : null,
            ServiceId: obj.Get("service_id").AsString(),
            ConnectionId: obj.Get("connection_id").AsString(),
            CompanyUserId: obj.Get("company_user_id").AsString(),
            Bindings: bindings,
            Status: obj.Get("status").AsString(),
            CurrentNode: obj.Get("current_node").AsString(),
            DocumentId: obj.Get("document_id").AsString(),
            OutputMode: outputMode,
            Definition: definition,
            Answers: answers,
            CreatedAt: ModelCoerce.ParseIsoDt(obj.Get("created_at").AsString()),
            UpdatedAt: ModelCoerce.ParseIsoDt(obj.Get("updated_at").AsString()))
        {
            Raw = obj.ToObjectGraph(),
            ReferenceDate = obj.Get("reference_date").AsString(),
            Participants = obj.Get("participants").Kind == NodeKind.List
                ? obj.Get("participants").AsList().Where(p => p.Kind == NodeKind.Object).Select(FlowRunParticipant.FromApi).ToList()
                : Array.Empty<FlowRunParticipant>(),
        };
    }
}

/// <summary>
/// One participant's row on a run's <c>participants[]</c> (flows.html §5a/§9 item 12) — the
/// durable participant set, additively carrying its place in the leaf PDF rule's ordered signing
/// plan. One account may hold TWO of these (two owner parties, or one customer bound to two
/// party keys) — never collapse this to a single row by user id.
/// </summary>
public sealed record FlowRunParticipant(
    string? PartyKey,
    string? PersonUserId,
    string? ConnectionId,
    string? DocumentId,
    string? DocumentStatus,
    bool RequiresSignature,
    bool RequiresAcceptance,
    int? Position,   // 1-based place in the signing plan; null for a party the plan does not name
    string? Action,  // "signed" | "accepted" | null — null until this participant's document has acted
    string? ActedAt)
{
    public static FlowRunParticipant FromApi(Node obj) => new(
        PartyKey: obj.Get("party_key").AsString(),
        PersonUserId: obj.Get("person_user_id").AsString(),
        ConnectionId: obj.Get("connection_id").AsString(),
        DocumentId: obj.Get("document_id").AsString(),
        DocumentStatus: obj.Get("document_status").AsString(),
        RequiresSignature: ModelCoerce.CoerceBool(obj.Get("requires_signature")) ?? false,
        RequiresAcceptance: ModelCoerce.CoerceBool(obj.Get("requires_acceptance")) ?? false,
        Position: obj.Get("position").Kind == NodeKind.Scalar && int.TryParse(obj.Get("position").AsString(), out var pos) ? pos : null,
        Action: obj.Get("action").AsString(),
        ActedAt: obj.Get("acted_at").AsString());
}

/// <summary>A service activity-log entry — ops events only, never person data.</summary>
public sealed record LogEntry(
    string? Type,
    string? Message,
    object? Metadata,
    DateTimeOffset? At)
{
    /// <summary>The underlying hardened API object (escape hatch).</summary>
    public object? Raw { get; init; }

    public static LogEntry FromApi(Node obj) => new(
        Type: obj.Get("type").AsString(),
        Message: obj.Get("message").AsString(),
        Metadata: obj.Has("metadata") ? obj.Get("metadata").ToObjectGraph() : null,
        At: ModelCoerce.ParseIsoDt(obj.Get("at").AsString() ?? obj.Get("created_at").AsString()))
    {
        Raw = obj.ToObjectGraph(),
    };

    public static List<LogEntry> ListFromApi(Node body)
    {
        var items = body.Kind == NodeKind.Object && body.Has("items")
            ? body.Get("items").AsList()
            : body.Kind == NodeKind.List ? body.AsList() : new List<Node>();
        return items.Select(FromApi).ToList();
    }
}
