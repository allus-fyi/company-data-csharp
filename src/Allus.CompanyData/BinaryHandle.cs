// Lazy handle for a binary (photo/document) value.
//
// A binary answer is stored server-side as a file, exposed in the hardened API as a slot-keyed
// value_url (never the source field). .BytesAsync() and .SaveAsync() GET that URL and return the
// FILE BYTES; .PagesAsync() and .MetadataAsync() expose the rest of the envelope. The caller never
// has to know which of the three response shapes arrived.
//
// THERE ARE THREE SHAPES, AND WHICH ONE ARRIVES IS NOT THE COMPANY'S CHOICE. The person's own
// privacy setting and the TYPE of the field they answered with decide it, either can change at any
// time, and nothing in the API announces it in advance:
//
//   * private source → application/json {"encrypted":true,"value":<wrapper>}. The wrapper decrypts
//     to a JSON envelope STRING (photo: {"full":"data:...","thumb":...}; single-file document:
//     {"file":"data:...",...}; multi-page document: {"pages":[{"file":"data:...",...}],...}) — NOT
//     raw bytes.
//   * non-private source whose type stores pages or declares entries → application/json
//     {"encrypted":false,"value":"<envelope>"}. The same envelope string, in the clear. There is
//     nothing to decrypt.
//   * every other non-private source → the file's own Content-Type and the body IS the file. A
//     handle built this way needs no service key at all.
//
// Photos resolve to the `full` representation. There is no variant selection.
//
// The fetch + decrypt are supplied by the client as plain callables (config-only key handling —
// the decrypt closure closes over the loaded service private key, so no key is ever passed here).
// The fetch returns a BinaryFetchResult saying which shape arrived (the client classifies it on the
// response's Content-Type; the body is never sniffed). For the shared crypto test vector the
// decrypted envelope is already in hand, so a handle can also be built directly from an envelope
// string (no fetch).
//
// BytesAsync(), PagesAsync() and MetadataAsync() share ONE lazy fetch: whichever is awaited first
// performs it, and every later call answers from the parsed envelope.

using System.Text.Json;

namespace Allus.CompanyData;

/// <summary>Lazy fetch+decrypt handle for a binary value.</summary>
public sealed class BinaryHandle
{
    // Envelope keys that hold the primary binary data URI, in priority order.
    private static readonly string[] DataUriKeys = { "full", "file" };

    // Envelope members that describe the envelope itself rather than the type's own declared
    // entries — everything NOT in this set is metadata.
    private static readonly HashSet<string> EnvelopeMembers = new(StringComparer.Ordinal)
    {
        "pages", "file", "full", "thumb", "original_name", "mime_type", "size",
    };

    private string? _envelopeJson;
    private readonly string? _valueUrl;
    private readonly Func<string, CancellationToken, Task<BinaryFetchResult>>? _fetch;
    private readonly Func<object, string>? _decrypt;

    // Plaintext file bytes, once a plaintext-shaped response has been fetched.
    private byte[]? _plainBytes;
    private string? _contentType;
    private string? _contentSha256;

    /// <summary>Build a handle whose decrypted envelope is already in hand (test vector / inline).</summary>
    public BinaryHandle(string envelopeJson)
    {
        _envelopeJson = envelopeJson;
    }

    /// <summary>
    /// Build a lazy handle: <paramref name="valueUrl"/> is the slot file endpoint;
    /// <paramref name="fetch"/> GETs it and reports which of the three 200 shapes arrived;
    /// <paramref name="decrypt"/> turns an encrypted shape's wrapper into the decrypted envelope
    /// string (closes over the service private key) and is never called for a plaintext one.
    /// A null <paramref name="valueUrl"/> = an empty handle.
    /// </summary>
    public BinaryHandle(
        string? valueUrl,
        Func<string, CancellationToken, Task<BinaryFetchResult>>? fetch,
        Func<object, string>? decrypt)
    {
        _valueUrl = valueUrl;
        _fetch = fetch;
        _decrypt = decrypt;
    }

    /// <summary>The slot-keyed file URL this handle fetches from (opaque to callers).</summary>
    public string? ValueUrl => _valueUrl;

    /// <summary>
    /// The platform's <c>X-Allus-Content-Sha256</c> — the digest of the SERVED ARTIFACT.
    /// <para>Which artifact that is follows the response arm: the raw bytes when the answer arrived
    /// as bytes, and the served <c>value</c> string on either JSON arm — the ciphertext wrapper for a
    /// private source, the plaintext envelope for a non-private one. It is NOT "the sha256 of what
    /// <see cref="BytesAsync"/> returns": on an envelope carrying pages <see cref="BytesAsync"/>
    /// throws, and on an envelope carrying one file it returns the decoded payload rather than the
    /// envelope string.</para>
    /// <para>A consumer can record it and later show that its archived copy has not drifted.
    /// <c>null</c> until something has been fetched, and on a handle built from an envelope that was
    /// never fetched through this class.</para>
    /// <para>It is the platform's word, not a signature: it proves agreement with the platform's
    /// record, not anything to a third party who doubts that record.</para>
    /// </summary>
    public string? ContentSha256 => _contentSha256;

    /// <summary>The response <c>Content-Type</c> the bytes arrived with, once fetched.</summary>
    public string? ContentType => _contentType;

    private async Task<string> ResolveEnvelopeAsync(CancellationToken ct)
    {
        if (_envelopeJson is not null)
            return _envelopeJson;
        await FetchOnceAsync(ct).ConfigureAwait(false);
        if (_envelopeJson is null)
            throw new DecryptException("binary answer arrived as plaintext bytes; use BytesAsync()/SaveAsync()");
        return _envelopeJson;
    }

    /// <summary>
    /// Fetch once and record which shape arrived. Idempotent: the result is cached on the handle so
    /// repeated <see cref="BytesAsync"/>/<see cref="SaveAsync"/> calls do not re-fetch, and so a
    /// plaintext answer's digest survives for <see cref="ContentSha256"/>.
    /// </summary>
    private async Task FetchOnceAsync(CancellationToken ct)
    {
        if (_plainBytes is not null || _envelopeJson is not null)
            return;
        if (_fetch is null || _valueUrl is null)
            throw new DecryptException(
                "BinaryHandle has no envelope and no fetch wiring " +
                "(build it with an envelope string, or value_url + fetch + decrypt)");

        var result = await _fetch(_valueUrl, ct).ConfigureAwait(false);
        _contentType = result.ContentType;
        _contentSha256 = result.ContentSha256;

        if (!result.Encrypted)
        {
            // A plaintext answer needs no service key. Requiring `decrypt` here would make a handle
            // built without one fail on exactly the answers that do not need it. The envelope arm is
            // plaintext too — the same envelope string the wrapper arm decrypts to — so both JSON
            // arms converge here.
            if (result.Envelope is not null)
            {
                _envelopeJson = result.Envelope;
                return;
            }
            _plainBytes = result.Bytes ?? Array.Empty<byte>();
            return;
        }
        if (_decrypt is null)
            throw new DecryptException("binary answer is encrypted but this handle has no decrypt wiring");
        if (result.Wrapper is null)
            throw new DecryptException("binary answer is encrypted but carried no wrapper");
        _envelopeJson = _decrypt(result.Wrapper); // cached so repeated reads don't re-fetch
    }

    /// <summary>The ONE envelope parser both JSON arms go through.</summary>
    private static JsonElement ParseEnvelope(string envelopeJson)
    {
        try
        {
            using var doc = JsonDocument.Parse(envelopeJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                throw new DecryptException("binary envelope must be a JSON object");
            return doc.RootElement.Clone();
        }
        catch (JsonException ex)
        {
            throw new DecryptException("binary envelope is not valid JSON", ex);
        }
    }

    /// <summary><c>data:&lt;mime&gt;;base64,&lt;payload&gt;</c> → the decoded payload.</summary>
    private static byte[] DecodeDataUri(string dataUri)
    {
        const string marker = "base64,";
        var idx = dataUri.IndexOf(marker, StringComparison.Ordinal);
        if (idx == -1)
            throw new DecryptException("binary data URI is not base64-encoded");
        var payload = dataUri[(idx + marker.Length)..];
        try
        {
            return Convert.FromBase64String(payload);
        }
        catch (FormatException ex)
        {
            throw new DecryptException("binary data-URI payload is not valid base64", ex);
        }
    }

    /// <summary>
    /// Turn a decrypted binary envelope STRING into the primary file bytes. Photo envelope → the
    /// <c>full</c> data-URI payload; single-file document envelope → the <c>file</c> data-URI
    /// payload. A MULTI-PAGE envelope has no single primary file, so it throws rather than handing
    /// back the first page as though it were the whole document. Throws
    /// <see cref="DecryptException"/> on a malformed envelope.
    /// </summary>
    public static byte[] ParseEnvelopeBytes(string envelopeJson)
    {
        var envelope = ParseEnvelope(envelopeJson);

        string? dataUri = null;
        foreach (var key in DataUriKeys)
        {
            if (envelope.TryGetProperty(key, out var p) && p.ValueKind == JsonValueKind.String)
            {
                dataUri = p.GetString();
                break;
            }
        }
        if (dataUri is null)
        {
            if (envelope.TryGetProperty("pages", out var pages)
                && pages.ValueKind == JsonValueKind.Array
                && pages.GetArrayLength() > 0)
            {
                throw new DecryptException("multi-page envelope: use pages");
            }
            throw new DecryptException("binary envelope has no 'full'/'file' data-URI payload");
        }

        return DecodeDataUri(dataUri);
    }

    /// <summary>
    /// The parsed envelope, fetching+decrypting on first use. <c>null</c> when the answer is
    /// plaintext BYTES, which carries no envelope at all.
    /// </summary>
    private async Task<JsonElement?> EnvelopeOrNullAsync(CancellationToken ct)
    {
        if (_envelopeJson is null)
        {
            await FetchOnceAsync(ct).ConfigureAwait(false);
            if (_envelopeJson is null)
                return null;
        }
        return ParseEnvelope(_envelopeJson);
    }

    /// <summary>
    /// The envelope's pages, in envelope order — an empty list for a single-file envelope.
    /// <para>Lazy exactly as <see cref="BytesAsync"/> is: the first call of <c>BytesAsync</c>,
    /// <c>PagesAsync</c> or <c>MetadataAsync</c> performs the one fetch and optional decrypt, and
    /// every later call answers from the parsed envelope. A handle built from an envelope string
    /// needs no fetch. A plaintext-BYTES answer carries no envelope, so it has no pages.</para>
    /// </summary>
    public async Task<IReadOnlyList<BinaryPage>> PagesAsync(CancellationToken ct = default)
    {
        var envelope = await EnvelopeOrNullAsync(ct).ConfigureAwait(false);
        if (envelope is null
            || !envelope.Value.TryGetProperty("pages", out var pages)
            || pages.ValueKind != JsonValueKind.Array)
        {
            return Array.Empty<BinaryPage>();
        }

        var out_ = new List<BinaryPage>(pages.GetArrayLength());
        foreach (var page in pages.EnumerateArray())
        {
            if (page.ValueKind != JsonValueKind.Object
                || !page.TryGetProperty("file", out var file)
                || file.ValueKind != JsonValueKind.String)
            {
                throw new DecryptException("binary envelope page has no data-URI payload");
            }
            out_.Add(new BinaryPage(
                StringOrNull(page, "label"),
                StringOrNull(page, "original_name"),
                StringOrNull(page, "mime_type"),
                DecodeDataUri(file.GetString()!)));
        }
        return out_;
    }

    /// <summary>
    /// Every declared entry the envelope carries, as a plain map.
    /// <para>Keys are every envelope member other than the envelope's own (<c>pages</c>,
    /// <c>file</c>, <c>full</c>, <c>thumb</c>, <c>original_name</c>, <c>mime_type</c>,
    /// <c>size</c>); values are the stored string, or <c>null</c> for an entry the person left
    /// unset. <c>name</c> — the holder name an ID provider extracted — is a member like any other
    /// and appears here.</para>
    /// <para><b>The map carries no ordering guarantee.</b> A consumer that needs the type's
    /// declared order reads the envelope string itself.</para>
    /// <para>Empty for a photo, for a plain document that declares no entries, and for a
    /// plaintext-BYTES answer. Lazy exactly as <see cref="PagesAsync"/> is.</para>
    /// </summary>
    public async Task<IReadOnlyDictionary<string, string?>> MetadataAsync(CancellationToken ct = default)
    {
        var envelope = await EnvelopeOrNullAsync(ct).ConfigureAwait(false);
        var out_ = new Dictionary<string, string?>(StringComparer.Ordinal);
        if (envelope is null)
            return out_;
        foreach (var member in envelope.Value.EnumerateObject())
        {
            if (EnvelopeMembers.Contains(member.Name))
                continue;
            out_[member.Name] = member.Value.ValueKind == JsonValueKind.String
                ? member.Value.GetString()
                : null;
        }
        return out_;
    }

    private static string? StringOrNull(JsonElement obj, string key)
        => obj.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    /// <summary>
    /// Fetch (if needed), decrypt, and return the decoded primary file bytes. A plaintext-BYTES
    /// answer short-circuits here — its body already IS the file, so there is no envelope to parse.
    /// A MULTI-PAGE envelope has no single primary file and throws: use <see cref="PagesAsync"/>.
    /// </summary>
    public async Task<byte[]> BytesAsync(CancellationToken ct = default)
    {
        if (_plainBytes is not null)
            return _plainBytes;
        if (_envelopeJson is null)
        {
            await FetchOnceAsync(ct).ConfigureAwait(false);
            if (_plainBytes is not null)
                return _plainBytes;
        }

        var envelope = await ResolveEnvelopeAsync(ct).ConfigureAwait(false);
        return ParseEnvelopeBytes(envelope);
    }

    /// <summary>
    /// Write the decoded file bytes to <paramref name="path"/>; returns the number of bytes
    /// written. Crash-safe (matching the buffer's atomic-write discipline): the bytes
    /// are written to a temp file in the same directory, flushed to disk, and atomically moved into
    /// place — a crash mid-write never leaves a truncated output file.
    /// </summary>
    public async Task<int> SaveAsync(string path, CancellationToken ct = default)
    {
        var data = await BytesAsync(ct).ConfigureAwait(false);
        AtomicWrite.WriteBytes(path, data);
        return data.Length;
    }
}
