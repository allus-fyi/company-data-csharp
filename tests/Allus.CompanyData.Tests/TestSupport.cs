// Shared test support: the cross-language decryption vector loader, an in-memory wrapper-encrypt
// helper (the vector key's PUBLIC half, RSA-OAEP-SHA256 + AES-256-GCM), and fake HTTP transports
// mirroring the Python reference's FakeSession.

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Allus.CompanyData;

namespace Allus.CompanyData.Tests;

/// <summary>Loads + exposes the shared <c>sdks/testdata/decryption-vector.json</c> fixture.</summary>
public static class Vector
{
    private static readonly Lazy<JsonElement> _lazy = new(Load);

    public static JsonElement Root => _lazy.Value;

    public static string Path
    {
        get
        {
            // tests run from .../tests/Allus.CompanyData.Tests/bin/Debug/net8.0 — walk up to sdks/.
            var dir = AppContext.BaseDirectory;
            for (var i = 0; i < 8 && dir is not null; i++)
            {
                var candidate = System.IO.Path.Combine(dir, "testdata", "decryption-vector.json");
                if (File.Exists(candidate)) return candidate;
                dir = System.IO.Path.GetDirectoryName(dir);
            }
            // Fall back to the known repo-relative path from the project dir
            // (repo root holds testdata/: .../tests/<proj>/bin/Debug/net8.0 -> 5 levels up).
            return System.IO.Path.GetFullPath(System.IO.Path.Combine(
                AppContext.BaseDirectory, "..", "..", "..", "..", "..", "testdata", "decryption-vector.json"));
        }
    }

    private static JsonElement Load()
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(Path));
        return doc.RootElement.Clone();
    }

    public static string EncryptedPem => Root.GetProperty("encrypted_private_key_pem").GetString()!;
    public static string Passphrase => Root.GetProperty("passphrase").GetString()!;

    public static JsonElement TextWrapper => Root.GetProperty("text").GetProperty("wrapper");
    public static string TextPlaintext => Root.GetProperty("text").GetProperty("plaintext").GetString()!;

    public static JsonElement BinaryWrapper => Root.GetProperty("binary").GetProperty("wrapper");
    public static string DecryptedJsonSha256 => Root.GetProperty("binary").GetProperty("decrypted_json_sha256").GetString()!;
    public static string InnerFullSha256 => Root.GetProperty("binary").GetProperty("inner_full_sha256").GetString()!;

    /// <summary>The vector wrapper as a Node (the shape the model layer passes to the decryptor).</summary>
    public static Node TextWrapperNode => Node.FromJson(TextWrapper);
    public static Node BinaryWrapperNode => Node.FromJson(BinaryWrapper);

    public static RSA PrivateKey() => Crypto.LoadPrivateKey(EncryptedPem, Passphrase);
}

/// <summary>Encrypt arbitrary plaintext into a platform wrapper using the vector key's PUBLIC half.</summary>
public static class Encryptor
{
    /// <summary>RSA-OAEP-SHA256 + AES-256-GCM (tag appended) → a {"_enc":1,k,iv,d} Node.</summary>
    public static Node Wrap(RSA key, string plaintext)
    {
        var aesKey = RandomNumberGenerator.GetBytes(32);
        var iv = RandomNumberGenerator.GetBytes(12);
        var pt = Encoding.UTF8.GetBytes(plaintext);
        var ct = new byte[pt.Length];
        var tag = new byte[16];
        using (var aes = new AesGcm(aesKey, 16))
            aes.Encrypt(iv, pt, ct, tag);
        var d = new byte[ct.Length + 16];
        Buffer.BlockCopy(ct, 0, d, 0, ct.Length);
        Buffer.BlockCopy(tag, 0, d, ct.Length, 16);
        var k = key.Encrypt(aesKey, RSAEncryptionPadding.OaepSHA256);
        return Node.Object(new Dictionary<string, Node>
        {
            ["_enc"] = Node.Scalar(1L),
            ["k"] = Node.Scalar(Convert.ToBase64String(k)),
            ["iv"] = Node.Scalar(Convert.ToBase64String(iv)),
            ["d"] = Node.Scalar(Convert.ToBase64String(d)),
        });
    }

    /// <summary>Wrap to an arbitrary public key with OAEP-SHA1 (the account-key envelope path) → JSON bytes.</summary>
    public static byte[] WrapAccountSha1(RSA accountPub, byte[] plaintext)
    {
        var aesKey = RandomNumberGenerator.GetBytes(32);
        var iv = RandomNumberGenerator.GetBytes(12);
        var ct = new byte[plaintext.Length];
        var tag = new byte[16];
        using (var aes = new AesGcm(aesKey, 16))
            aes.Encrypt(iv, plaintext, ct, tag);
        var d = new byte[ct.Length + 16];
        Buffer.BlockCopy(ct, 0, d, 0, ct.Length);
        Buffer.BlockCopy(tag, 0, d, ct.Length, 16);
        var k = accountPub.Encrypt(aesKey, RSAEncryptionPadding.OaepSHA1);
        var envelope = new Dictionary<string, object>
        {
            ["_enc"] = 1,
            ["k"] = Convert.ToBase64String(k),
            ["iv"] = Convert.ToBase64String(iv),
            ["d"] = Convert.ToBase64String(d),
        };
        return Encoding.UTF8.GetBytes(JsonSerializer.Serialize(envelope));
    }

    /// <summary>Generate an account RSA keypair, write its encrypted PEM, return (path, public key).</summary>
    public static (string Path, RSA Pub) MakeAccountKey(string dir, string passphrase)
    {
        using var key = RSA.Create(2048);
        var pem = key.ExportEncryptedPkcs8PrivateKeyPem(
            passphrase.AsSpan(),
            new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000));
        var path = System.IO.Path.Combine(dir, "account.pem");
        File.WriteAllText(path, pem);
        // Return a separate RSA holding only the public key for encrypting test envelopes.
        var pub = RSA.Create();
        pub.ImportParameters(key.ExportParameters(false));
        return (path, pub);
    }
}
