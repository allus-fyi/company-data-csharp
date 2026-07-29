// Lazy handle for a binary (photo/document) value.
//
// A binary answer is stored server-side as a file, exposed in the hardened API as a slot-keyed
// value_url (never the source field). .BytesAsync() and .SaveAsync() GET that URL and return the
// FILE BYTES either way — the caller never has to know which of the two response shapes arrived.
//
// #590 — THERE ARE TWO SHAPES, AND WHICH ONE ARRIVES IS THE PERSON'S CHOICE, NOT THE COMPANY'S.
// Whether the person's source field is private decides it, they can change it at any time, and
// nothing in the API announces it in advance:
//
//   * private source → application/json {"encrypted":true,"value":<wrapper>}. The wrapper decrypts
//     to a JSON envelope STRING (photo: {"full":"data:...","thumb":...}; document:
//     {"file":"data:...",...}) — NOT raw bytes — whose primary data-URI payload (`full` for photos,
//     `file` for documents) base64-decodes to the file.
//   * plaintext source → the file's own Content-Type and the body IS the file. There is nothing to
//     decrypt, and a handle built this way needs no service key at all.
//
// Photos resolve to the `full` representation. There is no variant selection: one slot has one byte
// sequence and therefore one digest.
//
// The fetch + decrypt are supplied by the client as plain callables (config-only key handling —
// the decrypt closure closes over the loaded service private key, so no key is ever passed here).
// The fetch returns a BinaryFetchResult saying which shape arrived (the client classifies it on the
// response's Content-Type; the body is never sniffed). For the shared crypto test vector the
// decrypted envelope is already in hand, so a handle can also be built directly from an envelope
// string (no fetch).

using System.Text.Json;

namespace Allus.CompanyData;

/// <summary>Lazy fetch+decrypt handle for a binary value.</summary>
public sealed class BinaryHandle
{
    // Envelope keys that hold the primary binary data URI, in priority order.
    private static readonly string[] DataUriKeys = { "full", "file" };

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
    /// <paramref name="fetch"/> GETs it and reports which of the two 200 shapes arrived (#590);
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
    /// The platform's <c>X-Allus-Content-Sha256</c> for the bytes this handle fetched — the sha256 of
    /// exactly what <see cref="BytesAsync"/> returns, so a consumer can record it and later show that
    /// its archived copy has not drifted. <c>null</c> until something has been fetched, and on a handle
    /// built from an envelope that was never fetched through this class.
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
            // built without one fail on exactly the answers that do not need it.
            _plainBytes = result.Bytes ?? Array.Empty<byte>();
            return;
        }
        if (_decrypt is null)
            throw new DecryptException("binary answer is encrypted but this handle has no decrypt wiring");
        if (result.Wrapper is null)
            throw new DecryptException("binary answer is encrypted but carried no wrapper");
        _envelopeJson = _decrypt(result.Wrapper); // cached so repeated reads don't re-fetch
    }

    /// <summary>
    /// Turn a decrypted binary envelope STRING into the primary file bytes. Photo envelope → the
    /// <c>full</c> data-URI payload; document envelope → the <c>file</c> data-URI payload. Throws
    /// <see cref="DecryptException"/> on a malformed envelope.
    /// </summary>
    public static byte[] ParseEnvelopeBytes(string envelopeJson)
    {
        JsonElement envelope;
        try
        {
            using var doc = JsonDocument.Parse(envelopeJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                throw new DecryptException("binary envelope must be a JSON object");
            envelope = doc.RootElement.Clone();
        }
        catch (JsonException ex)
        {
            throw new DecryptException("binary envelope is not valid JSON", ex);
        }

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
            throw new DecryptException("binary envelope has no 'full'/'file' data-URI payload");

        // data:<mime>;base64,<payload>
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
    /// Fetch (if needed), decrypt, and return the decoded primary file bytes. #590: a plaintext-shaped
    /// answer short-circuits here — its body already IS the file, so there is no envelope to parse.
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
