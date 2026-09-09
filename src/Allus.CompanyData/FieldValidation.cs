using System;
using System.Collections.Generic;

namespace Allus.CompanyData;

/// <summary>
/// Country-data helpers.
/// </summary>
/// <remarks>
/// What a value must satisfy for its field TYPE lives in <see cref="FieldTypeRegistry"/>: a type is
/// a row in the served registry and that class is the one interpreter of those rows. These two
/// helpers are about the bundled country dataset itself, which no registry row carries.
/// </remarks>
public static class FieldValidation
{
    private static readonly HashSet<string> CountrySet = new(CountryData.CountryCodes, StringComparer.Ordinal);

    /// <summary>True if <paramref name="code"/> is an assigned ISO 3166-1 alpha-2 country code.</summary>
    public static bool IsValidCountryCode(string? code) => code is not null && CountrySet.Contains(code);

    /// <summary>The ITU E.164 dial code (digits only, no <c>+</c>) for a country code, or null.</summary>
    public static string? DialCodeFor(string? code) =>
        code is not null && CountryData.DialCodes.TryGetValue(code, out var dial) ? dial : null;
}
