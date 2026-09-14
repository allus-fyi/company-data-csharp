namespace Allus.CompanyData;

/// <summary>One page of a multi-page binary answer (an ID document's front, back, …).</summary>
/// <param name="Label">The page's own label (<c>front</c> | <c>back</c> | <c>additional</c>), or null.</param>
/// <param name="Name">The original filename the person uploaded it under, or null.</param>
/// <param name="Mime">The server-derived media type, or null.</param>
/// <param name="Bytes">The decoded page bytes.</param>
public sealed record BinaryPage(
    string? Label,
    string? Name,
    string? Mime,
    byte[] Bytes);
