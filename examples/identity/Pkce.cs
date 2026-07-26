using System.Security.Cryptography;
using System.Text;

namespace Allus.ExampleTestSuite.Identity;

/// <summary>
/// PKCE (RFC 7636) verifier + S256 challenge. Pure local crypto — no network, no platform HTTP.
/// The SDK takes the code_challenge into <see cref="Allus.CompanyData.OAuthClient.AuthorizeUrl"/> and
/// the code_verifier into <see cref="Allus.CompanyData.OAuthClient.CompleteSignInAsync"/>; the demo
/// generates the pair for the "Sign in with allme" scenarios (1–4). The OIDC scenarios (5/6) let the
/// OIDC library own PKCE instead.
/// </summary>
public static class Pkce
{
    public static (string Verifier, string Challenge) Generate()
    {
        var verifier = B64Url(RandomNumberGenerator.GetBytes(32));
        var challenge = B64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        return (verifier, challenge);
    }

    private static string B64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
