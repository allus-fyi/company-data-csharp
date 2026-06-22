// Decryption core tests. These prove the C# decryptor reproduces the SHARED test
// vector (sdks/testdata/decryption-vector.json), and — crucially, to avoid circularity — that the
// vector's wrappers are PLATFORM-correct, by decrypting the text wrapper through a fully INDEPENDENT
// toolchain (the OpenSSL CLI for the PBES2 PEM + the RSA-OAEP-SHA256 unwrap, then Node `crypto` for
// the AES-256-GCM step) and getting the same plaintext.

using System.Security.Cryptography;
using System.Text;
using Allus.CompanyData;
using Xunit;

namespace Allus.CompanyData.Tests;

public class CryptoTests
{
    private static string Sha256Hex(byte[] data) => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    // ── Self-consistent decryption (the SDK's own crypto core) ──────────────────────────────────

    [Fact]
    public void LoadPrivateKeyFromPbes2Pem()
    {
        using var key = Crypto.LoadPrivateKey(Vector.EncryptedPem, Vector.Passphrase);
        Assert.Equal(2048, key.KeySize);
    }

    [Fact]
    public void LoadPrivateKeyWrongPassphraseThrows()
    {
        Assert.Throws<DecryptException>(() =>
            Crypto.LoadPrivateKey(Vector.EncryptedPem, "the-wrong-passphrase"));
    }

    [Fact]
    public void DecryptTextWrapperMatchesPlaintext()
    {
        using var key = Vector.PrivateKey();
        var plaintext = Crypto.Decrypt(Vector.TextWrapperNode, key);
        Assert.Equal(Vector.TextPlaintext, plaintext);
    }

    [Fact]
    public void DecryptAcceptsWrapperAsJsonString()
    {
        using var key = Vector.PrivateKey();
        var wrapperStr = Vector.TextWrapper.GetRawText();
        Assert.Equal(Vector.TextPlaintext, Crypto.Decrypt(wrapperStr, key));
    }

    [Fact]
    public async Task DecryptBinaryWrapperToEnvelopeAndInnerBytes()
    {
        using var key = Vector.PrivateKey();
        // Decrypting a binary wrapper yields a JSON envelope STRING.
        var envelopeJson = Crypto.Decrypt(Vector.BinaryWrapperNode, key);
        Assert.Equal(Vector.DecryptedJsonSha256, Sha256Hex(Encoding.UTF8.GetBytes(envelopeJson)));

        // The BinaryHandle parses the envelope → base64-decodes the "full"/"file" data-URI → bytes.
        var inner = BinaryHandle.ParseEnvelopeBytes(envelopeJson);
        Assert.Equal(Vector.InnerFullSha256, Sha256Hex(inner));

        // And via the handle's public .BytesAsync() entry point.
        var handle = new BinaryHandle(envelopeJson);
        Assert.Equal(Vector.InnerFullSha256, Sha256Hex(await handle.BytesAsync()));
    }

    // ── Error paths ────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void DecryptTagMismatchThrows()
    {
        using var key = Vector.PrivateKey();
        var d = Convert.FromBase64String(Vector.TextWrapper.GetProperty("d").GetString()!);
        d[^1] ^= 0xFF; // corrupt the last byte of the GCM tag
        var bad = Node.Object(new Dictionary<string, Node>
        {
            ["k"] = Node.Scalar(Vector.TextWrapper.GetProperty("k").GetString()),
            ["iv"] = Node.Scalar(Vector.TextWrapper.GetProperty("iv").GetString()),
            ["d"] = Node.Scalar(Convert.ToBase64String(d)),
        });
        Assert.Throws<DecryptException>(() => Crypto.Decrypt(bad, key));
    }

    [Fact]
    public void DecryptMissingFieldThrows()
    {
        using var key = Vector.PrivateKey();
        var bad = Node.Object(new Dictionary<string, Node>
        {
            ["k"] = Node.Scalar("AAAA"),
            ["iv"] = Node.Scalar("AAAA"),
        }); // no "d"
        Assert.Throws<DecryptException>(() => Crypto.Decrypt(bad, key));
    }

    [Fact]
    public void DecryptBadBase64Throws()
    {
        using var key = Vector.PrivateKey();
        var bad = Node.Object(new Dictionary<string, Node>
        {
            ["k"] = Node.Scalar("not valid base64 !!!"),
            ["iv"] = Node.Scalar(Vector.TextWrapper.GetProperty("iv").GetString()),
            ["d"] = Node.Scalar(Vector.TextWrapper.GetProperty("d").GetString()),
        });
        Assert.Throws<DecryptException>(() => Crypto.Decrypt(bad, key));
    }

    [Fact]
    public void DecryptWrongIvLengthThrows()
    {
        using var key = Vector.PrivateKey();
        var bad = Node.Object(new Dictionary<string, Node>
        {
            ["k"] = Node.Scalar(Vector.TextWrapper.GetProperty("k").GetString()),
            ["iv"] = Node.Scalar(Convert.ToBase64String(RandomNumberGenerator.GetBytes(16))), // 16, not 12
            ["d"] = Node.Scalar(Vector.TextWrapper.GetProperty("d").GetString()),
        });
        Assert.Throws<DecryptException>(() => Crypto.Decrypt(bad, key));
    }

    [Fact]
    public void ParseEnvelopeWithoutFullOrFileThrows()
    {
        Assert.Throws<DecryptException>(() =>
            BinaryHandle.ParseEnvelopeBytes("{\"thumb\":\"x\"}"));
    }

    // ── BinaryHandle.SaveAsync() is atomic (temp + move) ─────────────────────────────────────────

    [Fact]
    public async Task BinaryHandleSaveWritesBytesAndCount()
    {
        using var key = Vector.PrivateKey();
        var envelopeJson = Crypto.Decrypt(Vector.BinaryWrapperNode, key);
        var handle = new BinaryHandle(envelopeJson);
        var dir = TempDir();
        try
        {
            var outPath = Path.Combine(dir, "out.bin");
            var n = await handle.SaveAsync(outPath);
            var data = await File.ReadAllBytesAsync(outPath);
            Assert.Equal(data.Length, n);
            Assert.Equal(Vector.InnerFullSha256, Sha256Hex(data));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task BinaryHandleSaveIsAtomicNoPartialOnCrash()
    {
        // A crash mid-write must NOT leave a truncated output file (atomic temp + move). We point
        // SaveAsync at a path that is an EXISTING DIRECTORY, so the final File.Move(temp, dest)
        // throws — exercising the cleanup-on-failure path. The pre-existing sibling content must
        // survive, and no .tmp_ partial may leak into the directory.
        using var key = Vector.PrivateKey();
        var envelopeJson = Crypto.Decrypt(Vector.BinaryWrapperNode, key);
        var handle = new BinaryHandle(envelopeJson);

        var dir = TempDir();
        try
        {
            // A sibling file whose content must remain intact.
            var sibling = Path.Combine(dir, "keep.bin");
            var original = System.Text.Encoding.UTF8.GetBytes("ORIGINAL-CONTENT-MUST-SURVIVE");
            await File.WriteAllBytesAsync(sibling, original);

            // The destination is a DIRECTORY → File.Move over it fails after the temp is written.
            var destDir = Path.Combine(dir, "dest-is-a-dir");
            Directory.CreateDirectory(destDir);

            await Assert.ThrowsAnyAsync<Exception>(async () => await handle.SaveAsync(destDir));

            // The sibling is untouched (atomic: the move never clobbered anything else) …
            Assert.Equal(original, await File.ReadAllBytesAsync(sibling));
            // … and no temp/partial file leaked into the directory.
            Assert.DoesNotContain(Directory.GetFiles(dir), f => Path.GetFileName(f).StartsWith(".tmp_"));
        }
        finally { Directory.Delete(dir, true); }
    }

    // ── EncryptForPublicKey round-trips through Decrypt ──────────────────────────────────────────

    [Fact]
    public void EncryptForPublicKeyRoundTripsThroughDecrypt()
    {
        using var priv = RSA.Create(2048);
        var spkiB64 = Convert.ToBase64String(priv.ExportSubjectPublicKeyInfo());
        using var pub = Crypto.LoadPublicKey(spkiB64);
        foreach (var pt in new[] { "hello", "{\"a\":1}", "with-üñîçödé" })
        {
            var wrapper = Crypto.EncryptForPublicKey(pt, pub);
            Assert.True(wrapper.Has("k") && wrapper.Has("iv") && wrapper.Has("d"));
            Assert.Equal(pt, Crypto.Decrypt(wrapper, priv));
        }
    }

    [Fact]
    public void LoadPublicKeyRejectsGarbage()
    {
        Assert.Throws<DecryptException>(() => Crypto.LoadPublicKey("not-base64!!"));
        Assert.Throws<DecryptException>(() =>
            Crypto.LoadPublicKey(Convert.ToBase64String(Encoding.UTF8.GetBytes("not a spki key"))));
    }

    // ── Anti-circularity: independent openssl + node cross-check ────────────────────────────────

    [SkippableFact]
    public void IndependentOpenSslNodeCrosscheck()
    {
        Skip.If(Which("openssl") is null || Which("node") is null,
            "openssl + node required for the independent cross-check");
        Assert.Equal(Vector.TextPlaintext, IndependentDecryptText());
    }

    private static string IndependentDecryptText()
    {
        var w = Vector.TextWrapper;
        var tmp = TempDir("allus-xcheck-");
        try
        {
            var pemPath = Path.Combine(tmp, "key.pem");
            var plainPem = Path.Combine(tmp, "key_plain.pem");
            var kPath = Path.Combine(tmp, "k.bin");
            var aesPath = Path.Combine(tmp, "aeskey.bin");
            var ivPath = Path.Combine(tmp, "iv.bin");
            var dPath = Path.Combine(tmp, "d.bin");

            File.WriteAllText(pemPath, Vector.EncryptedPem);
            File.WriteAllBytes(kPath, Convert.FromBase64String(w.GetProperty("k").GetString()!));
            File.WriteAllBytes(ivPath, Convert.FromBase64String(w.GetProperty("iv").GetString()!));
            File.WriteAllBytes(dPath, Convert.FromBase64String(w.GetProperty("d").GetString()!));

            // 1) OpenSSL: decrypt the PBES2 PKCS#8 PEM with the passphrase.
            RunOrThrow("openssl", new[]
            {
                "pkcs8", "-in", pemPath, "-passin", $"pass:{Vector.Passphrase}", "-out", plainPem,
            });
            // 2) OpenSSL: RSA-OAEP-SHA256 (MGF1-SHA256) unwrap the AES key.
            RunOrThrow("openssl", new[]
            {
                "pkeyutl", "-decrypt", "-inkey", plainPem,
                "-pkeyopt", "rsa_padding_mode:oaep",
                "-pkeyopt", "rsa_oaep_md:sha256",
                "-pkeyopt", "rsa_mgf1_md:sha256",
                "-in", kPath, "-out", aesPath,
            });
            // 3) Node crypto: AES-256-GCM decrypt (independent of System.Security.Cryptography).
            var nodeScript =
                "const fs=require('fs'),crypto=require('crypto');" +
                $"const k=fs.readFileSync({JsStr(aesPath)});" +
                $"const iv=fs.readFileSync({JsStr(ivPath)});" +
                $"const d=fs.readFileSync({JsStr(dPath)});" +
                "const tag=d.subarray(d.length-16),ct=d.subarray(0,d.length-16);" +
                "const dc=crypto.createDecipheriv('aes-256-gcm',k,iv);" +
                "dc.setAuthTag(tag);" +
                "process.stdout.write(Buffer.concat([dc.update(ct),dc.final()]).toString('utf8'));";
            return RunOrThrow("node", new[] { "-e", nodeScript });
        }
        finally { Directory.Delete(tmp, true); }
    }

    // ── process helpers ──────────────────────────────────────────────────────────────────────

    private static string JsStr(string s) => "'" + s.Replace("\\", "\\\\").Replace("'", "\\'") + "'";

    private static string? Which(string exe)
    {
        var pathVar = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in pathVar.Split(Path.PathSeparator))
        {
            if (string.IsNullOrEmpty(dir)) continue;
            var candidate = Path.Combine(dir, exe);
            if (File.Exists(candidate)) return candidate;
        }
        return null;
    }

    private static string RunOrThrow(string exe, string[] args)
    {
        var psi = new System.Diagnostics.ProcessStartInfo(exe)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        // Ensure /opt/homebrew/bin (node/openssl) is reachable.
        var path = psi.Environment.TryGetValue("PATH", out var p) ? p : Environment.GetEnvironmentVariable("PATH");
        psi.Environment["PATH"] = "/opt/homebrew/bin:" + path;
        using var proc = System.Diagnostics.Process.Start(psi)!;
        var stdout = proc.StandardOutput.ReadToEnd();
        var stderr = proc.StandardError.ReadToEnd();
        proc.WaitForExit();
        if (proc.ExitCode != 0)
            throw new Exception($"{exe} failed ({proc.ExitCode}): {stderr}");
        return stdout;
    }

    private static string TempDir(string prefix = "allus-test-")
    {
        var dir = Path.Combine(Path.GetTempPath(), prefix + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }
}
