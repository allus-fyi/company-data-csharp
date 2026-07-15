// Field-type value validation — issue #302. Pure + i18n-free. Data-driven: each type maps to a
// "kind"; structured types map each sub-field to its own sub-rule (§2b), reusing the same kinds.
// Validate the PLAINTEXT before encryption, at input surfaces only (never on share/propagate).
// Kept byte-aligned across web / allus / iOS / Android / the 6 SDKs by
// docs/contract-field-validation-vector.json. Reference: frontend/src/fieldValidation.js. Spec:
// docs/superpowers/specs/2026-07-15-field-type-validation-design.html
//
// Contract: FieldValidation.IsValid(type, value) -> bool. Empty value = valid (required is the
// caller's job). Only present, non-empty sub-fields of a structured type are checked.

using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Allus.CompanyData;

/// <summary>Pure field-type value validation (issue #302), pinned by the shared vector.</summary>
public static class FieldValidation
{
    private static readonly Regex EmailRe = new(@"^[^\s@]+@[^\s@]+\.[^\s@]+$");
    private static readonly Regex UrlRe = new(@"^https?://[^\s/$.?#][^\s]*\.[^\s]{2,}$", RegexOptions.IgnoreCase);
    private static readonly Regex SchemeRe = new(@"^https?://", RegexOptions.IgnoreCase);
    private static readonly Regex MimeRe = new(@"^[\w.+-]+/[\w.+-]+$");
    private static readonly Regex PhoneRe = new(@"^\+?\d{4,15}$");
    private static readonly Regex CardRe = new(@"^\d{12,19}$");
    private static readonly Regex DateRe = new(@"^\d{4}-\d{2}-\d{2}$");

    private static readonly Regex PostalRe = new(@"^[A-Za-z0-9][A-Za-z0-9 -]{1,9}$");
    private static readonly Regex ExpiryRe = new(@"^(0[1-9]|1[0-2])/\d{2}(\d{2})?$");
    private static readonly Regex CvcRe = new(@"^\d{3,4}$");
    private static readonly Regex SwiftRe = new(@"^[A-Za-z]{6}[A-Za-z0-9]{2}([A-Za-z0-9]{3})?$");
    private static readonly Regex RoutingRe = new(@"^\d{9}$");
    private static readonly Regex AccountRe = new(@"^[A-Za-z0-9 ]{4,34}$");

    private static readonly Regex PhoneStrip = new(@"[ \-().]");
    private static readonly Regex CardStrip = new(@"[ -]");

    private static readonly string[] Gender = { "Male", "Female", "Non-binary", "Prefer not to say" };

    // #303: country/nationality store an ISO 3166-1 alpha-2 code; address state = USPS 2-letter code.
    // The lists come from the generated country data (do NOT inline them — they would rot).
    private static readonly HashSet<string> CountrySet = new(CountryData.CountryCodes);
    private static readonly HashSet<string> UsStateSet = new(CountryData.UsStateCodes);

    // A structured sub-field rule. Default ({}) = any non-empty string.
    private readonly record struct Sub(bool IsInt = false, Regex? Re = null, string? Kind = null);

    private static readonly Dictionary<string, Dictionary<string, Sub>> Obj = new()
    {
        ["address"] = new()
        {
            ["postal_code"] = new(Re: PostalRe),
            ["country"] = new(Kind: "countryCode"), ["state"] = new(Kind: "usState"),
            ["street"] = new(), ["building_number"] = new(), ["affix"] = new(), ["city"] = new(),
        },
        ["creditcard"] = new()
        {
            ["number"] = new(Kind: "card"),
            ["expiry"] = new(Re: ExpiryRe),
            ["cvc"] = new(Re: CvcRe),
            ["name"] = new(),
        },
        ["bank"] = new()
        {
            ["swift"] = new(Re: SwiftRe),
            ["routing_number"] = new(Re: RoutingRe),
            ["account_number"] = new(Re: AccountRe),
            ["account_holder"] = new(), ["bank_name"] = new(),
        },
        ["document"] = new()
        {
            ["size"] = new(IsInt: true), ["mime_type"] = new(Re: MimeRe),
            ["name"] = new(), ["file"] = new(), ["original_name"] = new(),
        },
        ["legal_document"] = new()
        {
            ["size"] = new(IsInt: true), ["expiry_date"] = new(Kind: "date"), ["mime_type"] = new(Re: MimeRe),
            ["document_number"] = new(), ["file"] = new(), ["original_name"] = new(),
        },
    };

    private readonly record struct Rule(string Kind, Regex? Re = null, string[]? Values = null);

    private static readonly Dictionary<string, Rule> Rules = new()
    {
        ["email"] = new("regex", Re: EmailRe),
        ["phone"] = new("phone"),
        ["url"] = new("url"),
        ["date"] = new("date"),
        ["date_of_birth"] = new("date"),
        ["gender"] = new("enum", Values: Gender),
        ["address"] = new("object"),
        ["creditcard"] = new("object"),
        ["bank"] = new("object"),
        ["document"] = new("object"),
        ["legal_document"] = new("object"),
        ["number"] = new("number"),
        ["boolean"] = new("boolean"),
        ["country"] = new("countryCode"),
        ["nationality"] = new("countryCode"),
        // text + unknown => no rule => accept anything
    };

    private static bool LuhnOk(string digits)
    {
        int sum = 0;
        bool dbl = false;
        for (int i = digits.Length - 1; i >= 0; i--)
        {
            int d = digits[i] - '0';
            if (d < 0 || d > 9) return false;
            if (dbl) { d *= 2; if (d > 9) d -= 9; }
            sum += d;
            dbl = !dbl;
        }
        return sum % 10 == 0;
    }

    private static int DaysInMonth(int y, int m)
    {
        bool leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        if (m == 2 && leap) return 29;
        return new[] { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }[m - 1];
    }

    private static bool ValidDate(string s)
    {
        if (!DateRe.IsMatch(s)) return false;
        int y = int.Parse(s.Substring(0, 4), CultureInfo.InvariantCulture);
        int m = int.Parse(s.Substring(5, 2), CultureInfo.InvariantCulture);
        int d = int.Parse(s.Substring(8, 2), CultureInfo.InvariantCulture);
        if (m < 1 || m > 12) return false;
        if (d < 1 || d > DaysInMonth(y, m)) return false;
        return true;
    }

    // The "content" check shared by top-level rules AND structured sub-rules.
    private static bool ApplyKind(string kind, string value)
    {
        switch (kind)
        {
            case "phone":
                return PhoneRe.IsMatch(PhoneStrip.Replace(value, ""));
            case "url":
                var u = SchemeRe.IsMatch(value) ? value : "https://" + value;
                return UrlRe.IsMatch(u);
            case "date":
                return ValidDate(value);
            case "card":
                var s = CardStrip.Replace(value, "");
                return CardRe.IsMatch(s) && LuhnOk(s);
            case "number":
                var t = value.Trim();
                if (t.Length == 0) return false;
                return double.TryParse(t, NumberStyles.Float, CultureInfo.InvariantCulture, out var f)
                    && !double.IsInfinity(f) && !double.IsNaN(f);
            case "boolean":
                return value == "true" || value == "false";
            case "countryCode":
                return CountrySet.Contains(value);
            case "usState":
                return UsStateSet.Contains(value);
            default:
                return true;
        }
    }

    private static bool ValidObject(string fieldType, string raw)
    {
        JsonElement root;
        try
        {
            using var doc = JsonDocument.Parse(raw);
            root = doc.RootElement.Clone();
        }
        catch (JsonException)
        {
            return false;
        }
        if (root.ValueKind != JsonValueKind.Object) return false;
        var spec = Obj[fieldType];
        foreach (var prop in root.EnumerateObject())
        {
            if (!spec.TryGetValue(prop.Name, out var sub)) return false; // unknown key
            var v = prop.Value;
            if (sub.IsInt)
            {
                if (v.ValueKind != JsonValueKind.Number) return false;
                if (!v.TryGetDouble(out var d) || double.IsInfinity(d) || double.IsNaN(d) || d != Math.Truncate(d))
                    return false;
                continue;
            }
            if (v.ValueKind != JsonValueKind.String) return false;
            var s = v.GetString() ?? "";
            if (s.Length == 0) continue; // empty sub-field ok (partial fill)
            if (sub.Re is not null && !sub.Re.IsMatch(s)) return false;
            if (sub.Kind is not null && !ApplyKind(sub.Kind, s)) return false;
        }
        return true;
    }

    /// <summary>
    /// True when <paramref name="value"/> is an acceptable plaintext for <paramref name="fieldType"/>.
    /// An empty value is valid (emptiness/required is the caller's concern).
    /// </summary>
    public static bool IsValid(string fieldType, string? value)
    {
        var s = value ?? "";
        if (s.Length == 0) return true;
        if (!Rules.TryGetValue(fieldType, out var rule)) return true;
        return rule.Kind switch
        {
            "regex" => rule.Re!.IsMatch(s),
            "enum" => Array.IndexOf(rule.Values!, s) >= 0,
            "object" => ValidObject(fieldType, s),
            _ => ApplyKind(rule.Kind, s),
        };
    }

    /// <summary>Returns null when valid, else the <paramref name="fieldType"/> tag (for i18n mapping).</summary>
    public static string? Error(string fieldType, string? value) =>
        IsValid(fieldType, value) ? null : fieldType;

    /// <summary>True if <paramref name="code"/> is an assigned ISO 3166-1 alpha-2 country code (#303).</summary>
    public static bool IsValidCountryCode(string? code) => code is not null && CountrySet.Contains(code);

    /// <summary>The ITU E.164 dial code (digits only, no <c>+</c>) for a country code, or null (#303).</summary>
    public static string? DialCodeFor(string? code) =>
        code is not null && CountryData.DialCodes.TryGetValue(code, out var dial) ? dial : null;
}
