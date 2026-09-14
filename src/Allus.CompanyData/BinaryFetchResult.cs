// One response from a company-facing binary file endpoint, in the shape a BinaryHandle needs.
//
// The route has THREE 200 shapes and the company cannot predict which it will get, because the
// answer depends on the person's own privacy setting and on the TYPE of the field they answered
// with, neither of which the company chooses:
//
//   * encrypted — application/json, {"encrypted":true,"value":<wrapper>}. The wrapper decrypts to the
//     binary ENVELOPE string.
//   * envelope — application/json, {"encrypted":false,"value":"<envelope>"}. The plaintext envelope
//     string itself, for a non-private source whose type stores more than one file or declares
//     metadata entries. Nothing to decrypt.
//   * plaintext bytes — the file's own Content-Type (e.g. image/jpeg, application/pdf) and the body
//     IS the file bytes.
//
// The bytes shape is told apart from the two JSON ones on the response's Content-Type, never guessed
// from the body: a plaintext answer's first byte is whatever the file starts with, and a PDF or a
// JPEG that happened to begin with a brace would be indistinguishable from a wrapper by sniffing.
// Inside a JSON body it is `encrypted` that decides; a JSON body that does not carry
// "encrypted": false with a string "value" is the wrapper arm, which is what the bare-wrapper
// routes (a company's own contract copy, its run slot file) answer with.

namespace Allus.CompanyData;

/// <summary>
/// One binary-file response, classified: which of the three 200 shapes arrived, plus what it carried.
/// </summary>
/// <param name="Encrypted">
/// True for the <c>{"encrypted":true,"value":&lt;wrapper&gt;}</c> shape (the person's source field is
/// private); false for the plaintext envelope shape and for raw file bytes.
/// </param>
/// <param name="Wrapper">The <c>{"_enc":1,…}</c> wrapper — encrypted shape only.</param>
/// <param name="Bytes">The file bytes themselves — plaintext-bytes shape only.</param>
/// <param name="ContentType">The response <c>Content-Type</c>, or null when it said nothing.</param>
/// <param name="ContentSha256">
/// The platform's <c>X-Allus-Content-Sha256</c> — the sha256 of the SERVED ARTIFACT: the raw bytes on
/// the bytes shape, the served <c>value</c> string on either JSON shape — so a consumer can record
/// what it received and later prove its archived copy has not drifted.
/// </param>
/// <param name="Envelope">The plaintext envelope string — envelope shape only.</param>
public sealed record BinaryFetchResult(
    bool Encrypted,
    object? Wrapper = null,
    byte[]? Bytes = null,
    string? ContentType = null,
    string? ContentSha256 = null,
    string? Envelope = null);
