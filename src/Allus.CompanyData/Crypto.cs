// Decryption core — byte-identical across all six SDKs.
//
// Every person value arrives as a ciphertext wrapper, encrypted FOR the service public key; the
// SDK decrypts with the service private key. The algorithm MUST match the platform's Web Crypto
// encryption exactly:
//
//     wrapper = {"_enc":1,
//                "k":  base64(rsa_oaep_sha256(aesKey, servicePublicKey)),
//                "iv": base64(iv12),
//                "d":  base64(aes256gcm_ciphertext_with_tag)}
//
//     decrypt(wrapper, servicePrivateKey):
//       aesKey    = RSA-OAEP(SHA-256, MGF1-SHA256) decrypt wrapper.k    // 32 bytes
//       plaintext = AES-256-GCM decrypt wrapper.d with aesKey, iv=wrapper.iv
//                   // the 16-byte GCM tag is the LAST 16 bytes of d
//       return utf8(plaintext)
//
// .NET specifics:
//   * RSA.Create().ImportFromEncryptedPem(pemChars, passphrase) reads the OpenSSL-encrypted
//     PKCS#8 PEM natively (PBES2 = PBKDF2-HMAC-SHA256 + AES-256-CBC, ~100k iters).
//   * rsa.Decrypt(k, RSAEncryptionPadding.OaepSHA256) — .NET's OaepSHA256 sets MGF1=SHA-256
//     IMPLICITLY (the one platform that does), matching Web Crypto's RSA-OAEP/SHA-256.
//   * AesGcm — we split the trailing 16-byte tag from the ciphertext ourselves and pass
//     (nonce, ciphertext, tag, plaintext).

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Allus.CompanyData;

/// <summary>The decryption core. Stateless static helpers.</summary>
public static class Crypto
{
    /// <summary>GCM tag length in bytes — appended to the AES-GCM ciphertext.</summary>
    public const int GcmTagLen = 16;

    /// <summary>GCM IV length in bytes.</summary>
    public const int GcmIvLen = 12;

    /// <summary>
    /// Load an OpenSSL-encrypted PKCS#8 PEM into an in-memory RSA private key. The PEM is PBES2
    /// (PBKDF2-HMAC-SHA256 + AES-256-CBC); <c>ImportFromEncryptedPem</c> handles the SHA-256 PRF.
    /// The key is never written back to disk in plaintext.
    ///
    /// Config-only key handling: this is the single place a passphrase is used (driven by
    /// <c>Config.KeyPassphrase</c> / <c>Config.AccountPassphrase</c>), never passed in by
    /// application code.
    /// </summary>
    public static RSA LoadPrivateKey(string encryptedPem, string passphrase)
    {
        var rsa = RSA.Create();
        try
        {
            // ImportFromEncryptedPem takes the password as chars; PBES2 is read natively.
            rsa.ImportFromEncryptedPem(encryptedPem.AsSpan(), passphrase.AsSpan());
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or FormatException)
        {
            rsa.Dispose();
            // A wrong passphrase / malformed PEM surfaces here.
            throw new DecryptException($"could not load private key PEM: {ex.Message}", ex);
        }
        return rsa;
    }

    private static byte[] B64Decode(string? value, string fieldName)
    {
        if (value is null)
            throw new DecryptException($"wrapper field '{fieldName}' must be a base64 string");
        try
        {
            return Convert.FromBase64String(value);
        }
        catch (FormatException ex)
        {
            throw new DecryptException($"wrapper field '{fieldName}' is not valid base64", ex);
        }
    }

    /// <summary>
    /// Decrypt a platform <c>{"_enc":1,k,iv,d}</c> wrapper (object or its JSON string) → utf-8
    /// plaintext string.
    ///
    /// For a TEXT value the plaintext is the value itself. For a BINARY value the plaintext is a
    /// JSON envelope STRING (photo: <c>{"full":"data:...","thumb":...}</c>; document:
    /// <c>{"file":"data:...","original_name":...}</c>) — NOT raw bytes. The full binary-handle
    /// parse lives on <see cref="BinaryHandle"/>.
    ///
    /// Throws <see cref="DecryptException"/> on a malformed wrapper, the wrong key, or a GCM tag
    /// mismatch.
    /// </summary>
    public static string Decrypt(object wrapper, RSA privateKey)
    {
        var (k, iv, d) = ExtractWrapperFields(wrapper);

        var encKey = B64Decode(k, "k");
        var ivBytes = B64Decode(iv, "iv");
        var ciphertextWithTag = B64Decode(d, "d");

        if (ivBytes.Length != GcmIvLen)
            throw new DecryptException($"iv must be {GcmIvLen} bytes, got {ivBytes.Length}");
        if (ciphertextWithTag.Length < GcmTagLen)
            throw new DecryptException("ciphertext too short to contain a GCM tag");

        // 1) RSA-OAEP(SHA-256, MGF1-SHA256) unwrap the AES key. .NET's OaepSHA256 pins MGF1-SHA256.
        byte[] aesKey;
        try
        {
            aesKey = privateKey.Decrypt(encKey, RSAEncryptionPadding.OaepSHA256);
        }
        catch (CryptographicException ex)
        {
            throw new DecryptException($"RSA-OAEP unwrap failed (wrong key?): {ex.Message}", ex);
        }

        if (aesKey.Length != 32)
            throw new DecryptException($"unwrapped AES key must be 32 bytes (AES-256), got {aesKey.Length}");

        // 2) AES-256-GCM decrypt. Split the trailing 16-byte tag from the ciphertext (the platform
        //    layout appends the tag) and pass (nonce, ciphertext, tag, plaintext) to AesGcm.
        var ctLen = ciphertextWithTag.Length - GcmTagLen;
        var ciphertext = new ReadOnlySpan<byte>(ciphertextWithTag, 0, ctLen);
        var tag = new ReadOnlySpan<byte>(ciphertextWithTag, ctLen, GcmTagLen);
        var plaintext = new byte[ctLen];
        try
        {
            using var aes = new AesGcm(aesKey, GcmTagLen);
            aes.Decrypt(ivBytes, ciphertext, tag, plaintext);
        }
        catch (CryptographicException ex)
        {
            throw new DecryptException("AES-GCM tag mismatch (wrong key or corrupt data)", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aesKey);
        }

        try
        {
            return Encoding.UTF8.GetString(plaintext);
        }
        catch (DecoderFallbackException ex)
        {
            throw new DecryptException("decrypted plaintext is not valid UTF-8", ex);
        }
    }

    /// <summary>
    /// Load a base64 SPKI/DER public key (the platform's <c>GET /api/keys</c> <c>public_key</c>) →
    /// an RSA public key.
    ///
    /// Config-only key handling does NOT apply to a RECIPIENT public key: it is not a secret and is
    /// fetched live from the API per-recipient (never configured). The SDK still never accepts a
    /// PRIVATE key/passphrase as a method argument.
    /// </summary>
    public static RSA LoadPublicKey(string spkiB64)
    {
        byte[] der;
        try
        {
            der = Convert.FromBase64String(spkiB64);
        }
        catch (FormatException ex)
        {
            throw new DecryptException("recipient public_key is not valid base64", ex);
        }
        var rsa = RSA.Create();
        try
        {
            rsa.ImportSubjectPublicKeyInfo(der, out _);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or FormatException)
        {
            rsa.Dispose();
            throw new DecryptException($"recipient public_key is not a valid SPKI key: {ex.Message}", ex);
        }
        return rsa;
    }

    /// <summary>
    /// Encrypt a UTF-8 string FOR a recipient RSA public key → a <c>{"_enc":1,k,iv,d}</c> wrapper
    /// (as a <see cref="Node"/>). The exact inverse of <see cref="Decrypt"/>:
    /// <code>
    ///   aesKey  = 32 random bytes
    ///   d       = AES-256-GCM(aesKey, iv=12 random bytes).encrypt(utf8(plaintext))  // tag appended
    ///   k       = RSA-OAEP(SHA-256, MGF1-SHA256).encrypt(aesKey, public_key)
    /// </code>
    /// Used for EVERY per-person (targeted) document (json + file), independent of is_private —
    /// broadcast docs stay plaintext. Round-trips through <see cref="Decrypt"/>.
    /// </summary>
    public static Node EncryptForPublicKey(string plaintext, RSA publicKey)
    {
        var aesKey = RandomNumberGenerator.GetBytes(32);
        var iv = RandomNumberGenerator.GetBytes(GcmIvLen); // 12
        try
        {
            var pt = Encoding.UTF8.GetBytes(plaintext);
            var ciphertext = new byte[pt.Length];
            var tag = new byte[GcmTagLen];
            using (var aes = new AesGcm(aesKey, GcmTagLen))
                aes.Encrypt(iv, pt, ciphertext, tag);

            // The platform layout appends the 16-byte GCM tag to the ciphertext.
            var d = new byte[ciphertext.Length + GcmTagLen];
            Buffer.BlockCopy(ciphertext, 0, d, 0, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, d, ciphertext.Length, GcmTagLen);

            // RSA-OAEP(SHA-256, MGF1-SHA256) — .NET's OaepSHA256 pins MGF1-SHA256 (never SHA-1).
            var encKey = publicKey.Encrypt(aesKey, RSAEncryptionPadding.OaepSHA256);

            return Node.Object(new Dictionary<string, Node>
            {
                ["_enc"] = Node.Scalar(1L),
                ["k"] = Node.Scalar(Convert.ToBase64String(encKey)),
                ["iv"] = Node.Scalar(Convert.ToBase64String(iv)),
                ["d"] = Node.Scalar(Convert.ToBase64String(d)),
            });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aesKey);
        }
    }

    /// <summary>
    /// Pull the <c>k</c>/<c>iv</c>/<c>d</c> fields out of a wrapper that may be a
    /// <see cref="JsonElement"/>, an <c>IDictionary</c>, or a JSON string. Throws
    /// <see cref="DecryptException"/> on anything malformed or with a missing field.
    /// </summary>
    public static (string? K, string? Iv, string? D) ExtractWrapperFields(object wrapper)
    {
        switch (wrapper)
        {
            case Node node:
            {
                if (node.Kind == NodeKind.Scalar && node.RawScalar is string scalarJson)
                    return ExtractWrapperFields(scalarJson); // a wrapper serialized as a JSON string
                if (node.Kind != NodeKind.Object)
                    throw new DecryptException("wrapper must be a JSON object");
                string? GetN(string name)
                {
                    if (!node.Has(name))
                        throw new DecryptException($"wrapper missing required field '{name}'");
                    return node.Get(name).AsString();
                }
                return (GetN("k"), GetN("iv"), GetN("d"));
            }
            case string s:
            {
                JsonElement el;
                try
                {
                    using var doc = JsonDocument.Parse(s);
                    el = doc.RootElement.Clone();
                }
                catch (JsonException ex)
                {
                    throw new DecryptException("wrapper string is not valid JSON", ex);
                }
                return ExtractWrapperFields(el);
            }
            case JsonElement el:
            {
                if (el.ValueKind != JsonValueKind.Object)
                    throw new DecryptException("wrapper must be a JSON object");
                string? Get(string name)
                {
                    if (!el.TryGetProperty(name, out var p))
                        throw new DecryptException($"wrapper missing required field '{name}'");
                    return p.ValueKind == JsonValueKind.String ? p.GetString() : p.GetRawText();
                }
                return (Get("k"), Get("iv"), Get("d"));
            }
            case IReadOnlyDictionary<string, object?> dict:
            {
                string? Get(string name)
                {
                    if (!dict.TryGetValue(name, out var v))
                        throw new DecryptException($"wrapper missing required field '{name}'");
                    return v switch
                    {
                        JsonElement je => je.ValueKind == JsonValueKind.String ? je.GetString() : je.GetRawText(),
                        string str => str,
                        null => null,
                        _ => v.ToString(),
                    };
                }
                return (Get("k"), Get("iv"), Get("d"));
            }
            default:
                throw new DecryptException("wrapper must be a JSON object, dictionary, or JSON string");
        }
    }
}
