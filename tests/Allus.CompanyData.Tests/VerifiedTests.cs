using System.Security.Cryptography;
using System.Text;
using Allus.CompanyData;
using Xunit;

public class VerifiedTests
{
    static string H(string salt, string pt) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(salt + pt))).ToLowerInvariant();

    [Fact]
    public void HashMatches_RoundTrip()
    {
        var (salt, pt) = ("0011223344556677", "alice@example.com");
        Assert.True(Crypto.HashMatches(salt, H(salt, pt), pt));
        Assert.False(Crypto.HashMatches(salt, "deadbeef", pt));
        Assert.False(Crypto.HashMatches("", "", pt));
    }

    [Fact]
    public void Value_Verified()
    {
        var (salt, pt) = ("0011223344556677", "alice@example.com");
        var match = Value.FromApi(Node.FromJsonString($"{{\"value\":\"{pt}\",\"live\":true,\"verified_hash\":\"{H(salt, pt)}\",\"verified_salt\":\"{salt}\"}}"), "email", _ => pt, null);
        Assert.True(match.Verified);
        var mismatch = Value.FromApi(Node.FromJsonString($"{{\"value\":\"{pt}\",\"live\":true,\"verified_hash\":\"deadbeef\",\"verified_salt\":\"{salt}\"}}"), "email", _ => pt, null);
        Assert.False(mismatch.Verified);
        var absent = Value.FromApi(Node.FromJsonString($"{{\"value\":\"{pt}\",\"live\":true}}"), "email", _ => pt, null);
        Assert.False(absent.Verified);
    }
}
