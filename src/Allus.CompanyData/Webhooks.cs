// Webhook receiver helpers.
//
// The lower-latency push alternative to polling the changes feed. The platform delivers each
// change event to the company's configured webhook URL with:
//   * X-Allus-Webhook-Id  — which webhook this is (selects the HMAC secret from config).
//   * X-Allus-Signature   — HMAC-SHA256(rawBody, secret) as lowercase hex.
//   * the body — the same slug-keyed Change shape as the pull feed, JSON or XML. If the webhook has
//     encrypt_payload on, the body is REPLACED by a {"_enc":1,...} envelope encrypted to the
//     company ACCOUNT key (and the HMAC is then over that envelope — the final body sent).
//
// All secrets/keys come from Config. These helpers take NO key or secret arguments.
//
// TWO OAEP code paths:
//   * SHA-256 for the inner per-field service-key values (Crypto.Decrypt) — and all pull-API values;
//   * SHA-1   for the OUTER account-key envelope (OpenSSL's default OAEP padding).
//
// XXE-safe XML parsing throughout (Xml.cs). HMAC is always over the raw bytes, never the parsed tree.

using System.Security.Cryptography;
using System.Text;

namespace Allus.CompanyData;

/// <summary>Config-driven webhook receiver helpers.</summary>
public static class Webhooks
{
    private const string HdrWebhookId = "x-allus-webhook-id";
    private const string HdrSignature = "x-allus-signature";
    private const string EncMarker = "_enc";

    // ── header helpers ─────────────────────────────────────────────────────────────────────────

    private static string? Header(IReadOnlyDictionary<string, string>? headers, string name)
    {
        if (headers is null) return null;
        foreach (var (k, v) in headers)
            if (string.Equals(k, name, StringComparison.OrdinalIgnoreCase))
                return v;
        return null;
    }

    private static byte[] AsBytes(object rawBody) => rawBody switch
    {
        byte[] b => b,
        string s => Encoding.UTF8.GetBytes(s),
        _ => throw new WebhookException("webhook raw_body must be a byte[] or string"),
    };

    // ── verify ───────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Verify a webhook against the SINGLE configured auth method, mirroring the platform's
    /// per-webhook delivery auth (one method per webhook):
    /// <list type="bullet">
    /// <item><c>hmac</c>   — recompute <c>HMAC-SHA256(rawBody, secret)</c> (secret selected by
    /// <c>X-Allus-Webhook-Id</c>) and constant-time-compare to <c>X-Allus-Signature</c>.</item>
    /// <item><c>bearer</c> — <c>Authorization</c> equals <c>Bearer &lt;token&gt;</c>.</item>
    /// <item><c>basic</c>  — <c>Authorization</c> equals <c>Basic &lt;base64(user:pass)&gt;</c>.</item>
    /// <item><c>header</c> — the configured custom header equals the configured value.</item>
    /// <item><c>none</c>   — always <c>true</c> (explicit opt-out).</item>
    /// </list>
    /// All comparisons are constant-time (<see cref="CryptographicOperations.FixedTimeEquals"/>).
    /// Returns <c>false</c> on a missing/mismatched credential, or when no method is configured —
    /// never throws for a bad credential (that is <see cref="HandleWebhook"/>'s job). Which method
    /// is used is decided entirely by config (<see cref="Config.WebhookAuthMethod"/>); config
    /// loading guarantees at most one is set.
    /// </summary>
    public static bool VerifyWebhook(object rawBody, IReadOnlyDictionary<string, string>? headers, Config config)
    {
        var method = config.WebhookAuthMethod();
        if (method is null) return false;
        if (method == "none") return true;

        if (method == "bearer")
        {
            var got = Header(headers, "authorization");
            if (got is null) return false;
            return FixedTimeStringEquals(got, "Bearer " + (config.WebhookBearerToken ?? ""));
        }

        if (method == "basic")
        {
            var got = Header(headers, "authorization");
            if (got is null) return false;
            var creds = $"{config.WebhookBasic!.Username}:{config.WebhookBasic.Password}";
            var token = Convert.ToBase64String(Encoding.UTF8.GetBytes(creds));
            return FixedTimeStringEquals(got, "Basic " + token);
        }

        if (method == "header")
        {
            var got = Header(headers, config.WebhookHeader!.Name);
            if (got is null) return false;
            return FixedTimeStringEquals(got, config.WebhookHeader.Value);
        }

        // method == "hmac"
        var body = AsBytes(rawBody);
        var signature = Header(headers, HdrSignature);
        if (string.IsNullOrEmpty(signature)) return false;

        var webhookId = Header(headers, HdrWebhookId);
        var secret = config.WebhookSecret(webhookId);
        if (string.IsNullOrEmpty(secret)) return false;

        // Convert.ToHexString is uppercase on net8.0; lowercase to match the platform's hex output.
        var expected = Convert.ToHexString(
            HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), body)).ToLowerInvariant();
        // Tolerate an uppercased signature (the platform sends lowercase hex). Constant-time compare.
        var got2 = signature.Trim().ToLowerInvariant();
        if (expected.Length != got2.Length) return false;
        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(expected), Encoding.ASCII.GetBytes(got2));
    }

    // Constant-time string compare (UTF-8 bytes). Different lengths return false; FixedTimeEquals
    // is the timing-safe primitive (mirrors Python's hmac.compare_digest for the alt-auth methods).
    private static bool FixedTimeStringEquals(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));

    // ── parse ────────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Parse a webhook body → a typed <see cref="Change"/>. Does NOT verify the
    /// signature (use <see cref="HandleWebhook"/> for verify+parse). Handles JSON and XML bodies,
    /// and an <c>encrypt_payload</c> account-key envelope: if the (JSON) body is a
    /// <c>{"_enc":1,...}</c> wrapper, it is first unwrapped with the account private key
    /// (OAEP-SHA1) into the inner serialized payload, which is then parsed. The inner field
    /// <c>value</c> (a service-key wrapper) is decrypted by the same model factory the feed uses.
    ///
    /// <paramref name="accountKey"/> is an optional pre-loaded account private key (the Client loads
    /// it ONCE and reuses it). When null, the key is loaded from config on demand.
    /// </summary>
    public static Change ParseWebhook(
        object rawBody,
        IReadOnlyDictionary<string, string>? headers,
        Config config,
        TypeForSlug typeForSlug,
        DecryptValue decryptValue,
        BinaryFetch? binaryFetch = null,
        RSA? accountKey = null)
    {
        var body = AsBytes(rawBody);
        var payload = DecodePayload(body, config, accountKey);
        if (payload.Kind != NodeKind.Object)
            throw new WebhookException("webhook payload is not a JSON/XML object");
        return Change.FromApi(payload, typeForSlug, decryptValue, binaryFetch);
    }

    /// <summary>
    /// Verify + parse a webhook in one call. Throws <see cref="WebhookException"/> on a
    /// bad/unknown signature; otherwise returns the typed <see cref="Change"/>.
    /// </summary>
    public static Change HandleWebhook(
        object rawBody,
        IReadOnlyDictionary<string, string>? headers,
        Config config,
        TypeForSlug typeForSlug,
        DecryptValue decryptValue,
        BinaryFetch? binaryFetch = null,
        RSA? accountKey = null)
    {
        if (!VerifyWebhook(rawBody, headers, config))
            throw new WebhookException("webhook signature verification failed");
        return ParseWebhook(rawBody, headers, config, typeForSlug, decryptValue, binaryFetch, accountKey);
    }

    // ── payload decoding (JSON / XML / encrypt_payload envelope) ──────────────────────────────

    private static Node DecodePayload(byte[] body, Config config, RSA? accountKey)
    {
        var text = Encoding.UTF8.GetString(body).Trim();

        if (text.StartsWith('{'))
        {
            Node obj;
            try { obj = Node.FromJsonString(text); }
            catch (System.Text.Json.JsonException ex)
            { throw new WebhookException($"webhook body is not valid JSON: {ex.Message}", ex); }

            if (obj.Kind == NodeKind.Object
                && obj.Get(EncMarker).AsString() == "1"
                && obj.Has("k") && obj.Has("iv") && obj.Has("d"))
            {
                var inner = UnwrapAccountEnvelope(obj, config, accountKey);
                return DecodeInner(inner);
            }
            return obj;
        }

        if (text.StartsWith('<'))
        {
            try { return Xml.Parse(text); }
            catch (Exception ex) when (ex is not WebhookException)
            { throw new WebhookException($"webhook body is not valid XML: {ex.Message}", ex); }
        }

        throw new WebhookException("webhook body is neither JSON nor XML");
    }

    private static Node DecodeInner(string innerText)
    {
        var stripped = innerText.Trim();
        if (stripped.StartsWith('<'))
        {
            try { return Xml.Parse(stripped); }
            catch (Exception ex) when (ex is not WebhookException)
            { throw new WebhookException($"decrypted webhook payload is not valid XML: {ex.Message}", ex); }
        }
        try { return Node.FromJsonString(stripped); }
        catch (System.Text.Json.JsonException ex)
        { throw new WebhookException($"decrypted webhook payload is not valid JSON: {ex.Message}", ex); }
    }

    // ── account-key (load once + envelope unwrap, OAEP-SHA1) ─────────────────────────────────

    /// <summary>
    /// Load the account private key from config ONCE (or null if not configured). Reused by the
    /// Client so an encrypt_payload webhook never re-reads the PEM + re-runs PBKDF2 per request.
    /// Returns null when no <c>account_private_key</c> is configured. Throws
    /// <see cref="WebhookException"/> on a read / passphrase / PEM problem.
    /// </summary>
    public static RSA? LoadAccountKey(Config config)
    {
        if (string.IsNullOrEmpty(config.AccountPrivateKey)) return null;
        string pem;
        try { pem = File.ReadAllText(config.AccountPrivateKey); }
        catch (IOException ex)
        { throw new WebhookException($"could not read account_private_key PEM: {config.AccountPrivateKey}: {ex.Message}", ex); }
        try { return Crypto.LoadPrivateKey(pem, config.AccountPassphrase ?? ""); }
        catch (DecryptException ex)
        { throw new WebhookException($"could not load account private key: {ex.Message}", ex); }
    }

    private static string UnwrapAccountEnvelope(Node envelope, Config config, RSA? accountKey)
    {
        var key = accountKey ?? LoadAccountKey(config);
        if (key is null)
            throw new WebhookException(
                "received an encrypt_payload webhook but no account_private_key is configured");
        return DecryptOaepSha1(envelope, key);
    }

    private static byte[] B64(Node node, string name)
    {
        var s = node.AsString();
        if (s is null) throw new WebhookException($"envelope field '{name}' must be a base64 string");
        try { return Convert.FromBase64String(s); }
        catch (FormatException ex) { throw new WebhookException($"envelope field '{name}' is not valid base64", ex); }
    }

    /// <summary>
    /// RSA-OAEP(SHA-1, MGF1-SHA1) unwrap + AES-256-GCM decrypt → utf-8 string. Mirrors
    /// <see cref="Crypto.Decrypt"/> but pins SHA-1 for the OAEP/MGF1 hash to match the account-key
    /// envelope (the only place the platform uses SHA-1 OAEP).
    /// </summary>
    private static string DecryptOaepSha1(Node wrapper, RSA privateKey)
    {
        var encKey = B64(wrapper.Get("k"), "k");
        var iv = B64(wrapper.Get("iv"), "iv");
        var ciphertextWithTag = B64(wrapper.Get("d"), "d");

        if (iv.Length != Crypto.GcmIvLen)
            throw new WebhookException($"envelope iv must be {Crypto.GcmIvLen} bytes, got {iv.Length}");
        if (ciphertextWithTag.Length < Crypto.GcmTagLen)
            throw new WebhookException("envelope ciphertext too short to contain a GCM tag");

        byte[] aesKey;
        try
        {
            aesKey = privateKey.Decrypt(encKey, RSAEncryptionPadding.OaepSHA1);
        }
        catch (CryptographicException ex)
        {
            throw new WebhookException($"account-key envelope RSA-OAEP unwrap failed (wrong account key?): {ex.Message}", ex);
        }
        if (aesKey.Length != 32)
            throw new WebhookException($"unwrapped envelope AES key must be 32 bytes, got {aesKey.Length}");

        var ctLen = ciphertextWithTag.Length - Crypto.GcmTagLen;
        var ciphertext = new ReadOnlySpan<byte>(ciphertextWithTag, 0, ctLen);
        var tag = new ReadOnlySpan<byte>(ciphertextWithTag, ctLen, Crypto.GcmTagLen);
        var plaintext = new byte[ctLen];
        try
        {
            using var aes = new AesGcm(aesKey, Crypto.GcmTagLen);
            aes.Decrypt(iv, ciphertext, tag, plaintext);
        }
        catch (CryptographicException ex)
        {
            throw new WebhookException("account-key envelope AES-GCM tag mismatch", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aesKey);
        }

        try { return Encoding.UTF8.GetString(plaintext); }
        catch (DecoderFallbackException ex)
        { throw new WebhookException("decrypted account-key envelope is not valid UTF-8", ex); }
    }
}
