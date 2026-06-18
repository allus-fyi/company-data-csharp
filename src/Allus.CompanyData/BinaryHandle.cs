// Lazy handle for a binary (photo/document) value.
//
// A binary answer is stored server-side as a file, exposed in the hardened API as a slot-keyed
// value_url (never the source field). On .BytesAsync() / .SaveAsync() the handle GETs that URL,
// receives the {"_enc":1,...} wrapper, runs the same decrypt as text → a JSON envelope STRING
// (photo: {"full":"data:...","thumb":...}; document: {"file":"data:...",...}) — NOT raw bytes —
// then parses the envelope and base64-decodes the primary data-URI payload (`full` for photos,
// `file` for documents) into the file bytes.
//
// The fetch + decrypt are supplied by the client as plain callables (config-only key handling —
// the decrypt closure closes over the loaded service private key, so no key is ever passed here).
// For the shared crypto test vector the decrypted envelope is already in hand, so a handle can
// also be built directly from an envelope string (no fetch).

using System.Text.Json;

namespace Allus.CompanyData;

/// <summary>Lazy fetch+decrypt handle for a binary value.</summary>
public sealed class BinaryHandle
{
    // Envelope keys that hold the primary binary data URI, in priority order.
    private static readonly string[] DataUriKeys = { "full", "file" };

    private string? _envelopeJson;
    private readonly string? _valueUrl;
    private readonly Func<string, CancellationToken, Task<object>>? _fetch;
    private readonly Func<object, string>? _decrypt;

    /// <summary>Build a handle whose decrypted envelope is already in hand (test vector / inline).</summary>
    public BinaryHandle(string envelopeJson)
    {
        _envelopeJson = envelopeJson;
    }

    /// <summary>
    /// Build a lazy handle: <paramref name="valueUrl"/> is the slot file endpoint;
    /// <paramref name="fetch"/> GETs it and returns the inner <c>{"_enc":1,...}</c> wrapper;
    /// <paramref name="decrypt"/> turns that wrapper into the decrypted envelope string (closes
    /// over the service private key). A null <paramref name="valueUrl"/> = an empty handle.
    /// </summary>
    public BinaryHandle(
        string? valueUrl,
        Func<string, CancellationToken, Task<object>>? fetch,
        Func<object, string>? decrypt)
    {
        _valueUrl = valueUrl;
        _fetch = fetch;
        _decrypt = decrypt;
    }

    /// <summary>The slot-keyed file URL this handle fetches from (opaque to callers).</summary>
    public string? ValueUrl => _valueUrl;

    private async Task<string> ResolveEnvelopeAsync(CancellationToken ct)
    {
        if (_envelopeJson is not null)
            return _envelopeJson;
        if (_fetch is null || _decrypt is null || _valueUrl is null)
            throw new DecryptException(
                "BinaryHandle has no envelope and no fetch/decrypt wiring " +
                "(build it with an envelope string, or value_url + fetch + decrypt)");
        var wrapper = await _fetch(_valueUrl, ct).ConfigureAwait(false);
        var envelope = _decrypt(wrapper);
        _envelopeJson = envelope; // cache so repeated reads don't re-fetch
        return envelope;
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
    /// Fetch (if needed), decrypt, and return the decoded primary file bytes.
    /// </summary>
    public async Task<byte[]> BytesAsync(CancellationToken ct = default)
    {
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
