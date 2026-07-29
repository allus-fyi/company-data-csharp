// One response from a company-facing binary file endpoint, in the shape a BinaryHandle needs.
//
// #590 — the route has TWO 200 shapes and the company cannot predict which it will get, because the
// answer depends on whether the person's source field is private, which is theirs to change:
//
//   * encrypted — application/json, {"encrypted":true,"value":<wrapper>}. The wrapper decrypts to the
//     binary ENVELOPE string, from which the file bytes are extracted.
//   * plaintext — the file's own Content-Type (e.g. image/jpeg, application/pdf) and the body IS the
//     file bytes. Nothing to decrypt.
//
// The distinction is made on the response's Content-Type, never guessed from the body: a plaintext
// answer's first byte is whatever the file starts with, and a PDF or a JPEG that happened to begin
// with a brace would be indistinguishable from a wrapper by sniffing.

namespace Allus.CompanyData;

/// <summary>
/// One binary-file response, classified: which of the two 200 shapes arrived, plus what it carried.
/// </summary>
/// <param name="Encrypted">
/// True for the <c>{"encrypted":true,"value":&lt;wrapper&gt;}</c> shape (the person's source field is
/// private); false when the body is the file bytes themselves.
/// </param>
/// <param name="Wrapper">The <c>{"_enc":1,…}</c> wrapper — encrypted shape only.</param>
/// <param name="Bytes">The file bytes themselves — plaintext shape only.</param>
/// <param name="ContentType">The response <c>Content-Type</c>, or null when it said nothing.</param>
/// <param name="ContentSha256">
/// The platform's <c>X-Allus-Content-Sha256</c> — the sha256 of exactly these bytes, present on both
/// shapes — so a consumer can record what it received and later prove its archived copy has not drifted.
/// </param>
public sealed record BinaryFetchResult(
    bool Encrypted,
    object? Wrapper = null,
    byte[]? Bytes = null,
    string? ContentType = null,
    string? ContentSha256 = null);
