using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Allus.CompanyData;

/// <summary>
/// The field-type registry — the whole of what a contact-field TYPE means.
/// </summary>
/// <remarks>
/// <para>A type is a ROW, not a literal: the row says what its parent is, which primitive draws it,
/// which named check verifies it, which additive regexes it must match, which sub-fields it carries
/// and on which storage lane its value lives. The rows are served by
/// <c>GET /api/contact-field-types</c>; this class interprets them, so adding a type that reuses
/// existing primitives and checks is a row and nothing else.</para>
///
/// <para>TWO FIXED VOCABULARIES, and only these two are code. <see cref="Inputs"/> is what a
/// platform can DRAW and <see cref="Checks"/> is what it can VERIFY beyond a regex; a new member of
/// a row may only name a member of each, so a new member is code here rather than data.</para>
///
/// <para>INHERITANCE. A child inherits any column it leaves null from its nearest ancestor that
/// sets it — <c>input</c>, <c>lane</c>, <c>check</c>, <c>options</c>, <c>fields</c>.
/// <c>validation</c> is the exception and is ADDITIVE: a value must match the regex of every
/// ancestor that has one, root first, plus the type's own. <see cref="Resolve"/> answers the row
/// with every inherited column filled in and the validations in that order, and every consumer
/// works on that resolved definition rather than on a raw row.</para>
///
/// <para>Pinned case-for-case by <c>testdata/contract-field-validation-vector.json</c>.</para>
/// </remarks>
public sealed class FieldTypeRegistry
{
    /// <summary>The storage lanes a value can live on. <c>inline</c> is the value itself; the other two are files.</summary>
    public static readonly string[] Lanes = { "inline", "photo", "document" };

    /// <summary>The drawing primitives a row may name. A new member is code here, not a row.</summary>
    public static readonly string[] Inputs =
    {
        "line", "date", "list", "multilist", "country", "nationality", "state", "phone",
        "composite", "file", "pages",
    };

    /// <summary>The named checks a row may name — verification beyond a regex. A new member is code here, not a row.</summary>
    public static readonly string[] Checks = { "url", "card", "number", "integer", "decimal", "float" };

    /// <summary>
    /// The lanes each primitive can store on. <c>file</c> is the only primitive with a choice,
    /// which is why a root with that input is the only row whose lane an operator picks.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string[]> InputLanes =
        new Dictionary<string, string[]>
        {
            ["line"] = new[] { "inline" },
            ["date"] = new[] { "inline" },
            ["list"] = new[] { "inline" },
            ["multilist"] = new[] { "inline" },
            ["country"] = new[] { "inline" },
            ["nationality"] = new[] { "inline" },
            ["state"] = new[] { "inline" },
            ["phone"] = new[] { "inline" },
            ["composite"] = new[] { "inline" },
            ["file"] = new[] { "photo", "document" },
            ["pages"] = new[] { "document" },
        };

    /// <summary>The primitives a sub-field entry may name: no composite nesting and no binary.</summary>
    public static readonly string[] EntryInputs =
        { "line", "date", "list", "country", "nationality", "state", "phone" };

    /// <summary>
    /// The members a <c>file</c>/<c>pages</c> envelope carries itself. They belong to the
    /// primitive, so a <c>fields</c> entry may never claim one — the entries are the extra metadata
    /// beside them.
    /// </summary>
    public static readonly string[] EnvelopeMembers =
        { "file", "pages", "original_name", "mime_type", "size", "name", "full", "thumb" };

    /// <summary>The members ONE page of a <c>pages</c> envelope may carry.</summary>
    public static readonly string[] PageMembers =
        { "label", "file", "original_name", "mime_type", "size" };

    /// <summary>
    /// The page slots the multi-page upload draws: a front, an optional back, repeatable extras.
    /// </summary>
    public static readonly string[] PageLabels = { "front", "back", "additional" };

    /// <summary>The longest a stored <c>validation</c> regex may be.</summary>
    public const int MaxValidationLength = 200;

    private static readonly Regex UrlRe =
        new(@"^https?://[^\s/$.?#][^\s]*\.[^\s]{2,}$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex UrlSchemeRe = new(@"^https?://", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex MimeRe = new(@"^[\w.+-]+/[\w.+-]+$", RegexOptions.Compiled);
    private static readonly Regex PhoneRe = new(@"^\+?\d{4,15}$", RegexOptions.Compiled);
    private static readonly Regex PhoneStripRe = new(@"[ \-().]", RegexOptions.Compiled);
    private static readonly Regex CardRe = new(@"^\d{12,19}$", RegexOptions.Compiled);
    private static readonly Regex CardStripRe = new(@"[ -]", RegexOptions.Compiled);
    // Numeric grammars accept ASCII digits only.
    private static readonly Regex IntegerRe = new(@"^-?[0-9]+$", RegexOptions.Compiled);
    // decimal(10,2) is a FIXED shape: up to 8 integer digits + up to 2 decimal digits.
    private static readonly Regex DecimalRe = new(@"^-?[0-9]{1,8}(\.[0-9]{1,2})?$", RegexOptions.Compiled);
    // Float accepts decimal or scientific notation.
    private static readonly Regex FloatRe = new(@"^-?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?$", RegexOptions.Compiled);
    private static readonly Regex DateRe = new(@"^\d{4}-\d{2}-\d{2}$", RegexOptions.Compiled);

    private static readonly int[] DaysInMonthTable = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

    private static readonly HashSet<string> CountrySet = new(CountryData.CountryCodes, StringComparer.Ordinal);
    private static readonly HashSet<string> UsStateSet = new(CountryData.UsStateCodes, StringComparer.Ordinal);

    // Compiled stored regexes, keyed by the raw pattern. A null value records a pattern this engine
    // cannot compile, so it is attempted once rather than per value.
    private static readonly Dictionary<string, Regex?> CompiledRegexes = new(StringComparer.Ordinal);

    /// <summary>One sub-field entry of a <c>composite</c>, <c>file</c> or <c>pages</c> type.</summary>
    public sealed record SubFieldEntry(
        string Key,
        string? Input,
        bool Required,
        string? Check,
        string? Validation,
        IReadOnlyList<string>? Options);

    /// <summary>A row with every inherited column filled in, plus the validations root-first.</summary>
    public sealed record Resolved(
        string Type,
        string? Parent,
        string Label,
        bool IsSystem,
        bool Known,
        string? Input,
        string? Lane,
        string? Check,
        IReadOnlyList<string>? Options,
        IReadOnlyList<SubFieldEntry>? Fields,
        IReadOnlyList<string> Validations);

    private sealed record Row(
        string Type,
        string? Parent,
        string? Label,
        string? Input,
        string? Lane,
        string? Check,
        IReadOnlyList<string>? Options,
        IReadOnlyList<SubFieldEntry>? Fields,
        string? Validation,
        bool IsSystem);

    private readonly List<string> _order = new();
    private readonly Dictionary<string, Row> _byType = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Resolved> _resolved = new(StringComparer.Ordinal);

    /// <summary>
    /// Build a registry from the raw <c>GET /api/contact-field-types</c> array.
    /// </summary>
    /// <remarks>
    /// A registry with no rows knows no type, which is the honest answer for a client that has not
    /// loaded it: every type resolves as unknown and validates as "accept anything".
    /// </remarks>
    public FieldTypeRegistry(Node? rows = null)
    {
        if (rows is null) return;
        foreach (var raw in rows.AsList())
        {
            var type = raw.Get("type").AsString();
            if (string.IsNullOrEmpty(type)) continue;
            if (!_byType.ContainsKey(type!)) _order.Add(type!);
            _byType[type!] = ReadRow(type!, raw);
        }
    }

    private static Row ReadRow(string type, Node raw) => new(
        type,
        raw.Get("parent").AsString(),
        raw.Get("label").AsString(),
        raw.Get("input").AsString(),
        raw.Get("lane").AsString(),
        raw.Get("check").AsString(),
        ReadOptions(raw.Get("options")),
        ReadFields(raw.Get("fields")),
        raw.Get("validation").AsString(),
        ModelCoerce.CoerceBool(raw.Get("is_system")) ?? false);

    private static IReadOnlyList<string>? ReadOptions(Node node)
    {
        if (node.IsNull) return null;
        return node.AsList().Select(o => o.AsString() ?? "").ToList();
    }

    private static IReadOnlyList<SubFieldEntry>? ReadFields(Node node)
    {
        if (node.IsNull) return null;
        return node.AsList().Select(e => new SubFieldEntry(
            e.Get("key").AsString() ?? "",
            e.Get("input").AsString(),
            ModelCoerce.CoerceBool(e.Get("required")) ?? false,
            e.Get("check").AsString(),
            e.Get("validation").AsString(),
            ReadOptions(e.Get("options")))).ToList();
    }

    // ── the tree ─────────────────────────────────────────────────────────────

    /// <summary>Every type the registry carries, in served order.</summary>
    public IReadOnlyList<string> Types() => _order;

    /// <summary>Whether the registry carries this type at all.</summary>
    public bool Knows(string? type) => type is not null && _byType.ContainsKey(type);

    /// <summary>
    /// The resolved definition: every inherited column filled in, validations root-first.
    /// </summary>
    /// <remarks>
    /// A type the registry does not carry resolves to the UNKNOWN definition — every column null,
    /// no validations, <c>Known</c> false. That is a distinct answer from a known type with nothing
    /// set, and callers must read it as "this platform cannot draw or store this", never as a
    /// default.
    /// </remarks>
    public Resolved Resolve(string? type)
    {
        var key = type ?? "";
        if (_resolved.TryGetValue(key, out var cached)) return cached;
        var definition = ResolveIn(key);
        _resolved[key] = definition;
        return definition;
    }

    private Resolved ResolveIn(string type)
    {
        if (!_byType.TryGetValue(type, out var row))
            return new Resolved(type, null, type, false, false, null, null, null, null, null, Array.Empty<string>());

        // Walk to the root collecting the chain, then fill downward: the nearest ancestor that sets
        // an inherited column wins, and the validations come out root-first.
        var chain = new List<Row>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var cursor = type;
        while (cursor is not null && _byType.TryGetValue(cursor, out var current) && seen.Add(cursor))
        {
            chain.Add(current);
            cursor = current.Parent;
        }
        chain.Reverse();

        string? input = null, lane = null, check = null;
        IReadOnlyList<string>? options = null;
        IReadOnlyList<SubFieldEntry>? fields = null;
        var validations = new List<string>();
        foreach (var ancestor in chain)
        {
            if (ancestor.Input is not null) input = ancestor.Input;
            if (ancestor.Lane is not null) lane = ancestor.Lane;
            if (ancestor.Check is not null) check = ancestor.Check;
            if (ancestor.Options is not null) options = ancestor.Options;
            if (ancestor.Fields is not null) fields = ancestor.Fields;
            if (!string.IsNullOrEmpty(ancestor.Validation)) validations.Add(ancestor.Validation!);
        }

        return new Resolved(
            type,
            row.Parent,
            string.IsNullOrEmpty(row.Label) ? type : row.Label!,
            row.IsSystem,
            true,
            input,
            lane,
            check,
            options,
            fields,
            validations);
    }

    /// <summary>
    /// The type and every descendant of it. An unknown type answers itself alone, so a lookup keyed
    /// on a type the registry does not carry still addresses that type rather than nothing.
    /// </summary>
    public IReadOnlyList<string> Descendants(string type)
    {
        var out_ = new List<string> { type };
        var frontier = new HashSet<string>(StringComparer.Ordinal) { type };
        // Bounded by the number of rows: each pass adds only types not already collected.
        for (var guard = _byType.Count; guard > 0 && frontier.Count > 0; guard--)
        {
            var next = new HashSet<string>(StringComparer.Ordinal);
            foreach (var candidate in _order)
            {
                var parent = _byType[candidate].Parent;
                if (parent is not null && frontier.Contains(parent) && !out_.Contains(candidate))
                {
                    out_.Add(candidate);
                    next.Add(candidate);
                }
            }
            frontier = next;
        }
        return out_;
    }

    /// <summary>Whether a request for <paramref name="requested"/> is answered by a field of <paramref name="actual"/>.</summary>
    public bool Accepts(string requested, string actual) =>
        actual == requested || Descendants(requested).Contains(actual);

    // ── storage lane ─────────────────────────────────────────────────────────

    /// <summary>Whether this type's value is a file rather than an inline value.</summary>
    public bool IsBinary(string? type)
    {
        var lane = Resolve(type).Lane;
        return lane is not null && lane != "inline";
    }

    /// <summary>Whether this type uses the document upload/storage lane.</summary>
    public bool IsDocumentLike(string? type) => Resolve(type).Lane == "document";

    /// <summary>Whether this type carries the multi-page ID-document envelope.</summary>
    public bool IsIdDocument(string? type) => Resolve(type).Input == "pages";

    /// <summary>Every type on a lane other than <c>inline</c>.</summary>
    public IReadOnlyList<string> BinaryTypes() => _order.Where(IsBinary).ToList();

    /// <summary>Every type on the <c>document</c> lane.</summary>
    public IReadOnlyList<string> DocumentLikeTypes() => _order.Where(IsDocumentLike).ToList();

    /// <summary>Every type drawn by the multi-page upload.</summary>
    public IReadOnlyList<string> IdDocumentTypes() => _order.Where(IsIdDocument).ToList();

    // ── derived sets ─────────────────────────────────────────────────────────

    /// <summary>
    /// A choice type whose options are supplied elsewhere. It is usable only where something else
    /// carries them — a flow element — so it is offered for no contact field, no request row and no
    /// claim.
    /// </summary>
    public bool IsOptionLessChoice(string type)
    {
        var definition = Resolve(type);
        var isChoice = definition.Input is "list" or "multilist";
        return isChoice && (definition.Options is null || definition.Options.Count == 0);
    }

    /// <summary>
    /// The option domain a choice value is held to: the ROW's own resolved options when it carries
    /// any, else the ones the caller supplies, and NEVER a merge of the two — a row that states its
    /// domain owns it, and a row that states none borrows the caller's whole.
    /// </summary>
    /// <remarks>
    /// null means neither source has a domain: an option-less row asked about with nothing
    /// supplied. A value cannot be measured against that, so <see cref="Validate"/> refuses rather
    /// than testing membership of an empty list, which would refuse every value including a
    /// legitimate one. Public so a caller can RENDER exactly the domain the validator will enforce.
    /// </remarks>
    public IReadOnlyList<string>? OptionsFor(string? type, IReadOnlyList<string>? suppliedOptions = null)
    {
        var rowOptions = Resolve(type).Options;
        if (rowOptions is not null && rowOptions.Count > 0) return rowOptions;
        if (suppliedOptions is not null && suppliedOptions.Count > 0) return suppliedOptions;
        return null;
    }

    /// <summary>The types a contact field, a service request row or an admin field may declare.</summary>
    public IReadOnlyList<string> RequestableTypes() => _order.Where(t => !IsOptionLessChoice(t)).ToList();

    /// <summary>The requestable set plus the option-less choice types a flow element supplies options for.</summary>
    public IReadOnlyList<string> FlowTypes() =>
        RequestableTypes().Concat(_order.Where(IsOptionLessChoice)).ToList();

    /// <summary>
    /// The types an OAuth claim may declare: the requestable set on the <c>inline</c> lane. A file
    /// can never be sealed to a relying party's app key, so no claim can name a binary type.
    /// </summary>
    public IReadOnlyList<string> ClaimableTypes() =>
        RequestableTypes().Where(t => Resolve(t).Lane == "inline").ToList();

    // ── display ──────────────────────────────────────────────────────────────

    /// <summary>
    /// The label to render. A seeded row's <c>label</c> is the <c>fieldtype_*</c> translation key
    /// and a data-added row's is the literal an operator typed; <c>is_system</c> is the
    /// discriminator, and a literal is rendered verbatim rather than looked up.
    /// </summary>
    public string LabelFor(string type) => Resolve(type).Label;

    /// <summary>
    /// The requested types in display order: roots A→Z, each followed by its own children A→Z,
    /// recursively, by the stored label. A requested type the registry does not carry sorts after
    /// the tree, so a picker built from a stale set still shows every entry it was given.
    /// </summary>
    public IReadOnlyList<string> Ordered(IReadOnlyList<string> types)
    {
        var wanted = new HashSet<string>(types, StringComparer.Ordinal);
        var out_ = new List<string>();
        Walk(null, wanted, out_);
        var unknown = types.Where(t => !out_.Contains(t)).ToList();
        unknown.Sort(CompareLabels);
        out_.AddRange(unknown);
        return out_;
    }

    private void Walk(string? parent, HashSet<string> wanted, List<string> into)
    {
        var children = _order.Where(t => _byType[t].Parent == parent).ToList();
        children.Sort((a, b) => CompareLabels(RowLabel(a), RowLabel(b)));
        foreach (var child in children)
        {
            if (wanted.Contains(child)) into.Add(child);
            Walk(child, wanted, into);
        }
    }

    private string RowLabel(string type)
    {
        var label = _byType[type].Label;
        return string.IsNullOrEmpty(label) ? type : label!;
    }

    private static int CompareLabels(string a, string b)
    {
        var byCase = string.CompareOrdinal(a.ToLowerInvariant(), b.ToLowerInvariant());
        return byCase != 0 ? byCase : string.CompareOrdinal(a, b);
    }

    /// <summary>
    /// The nearest ancestor, self included, that is <c>date</c> or <c>number</c>; otherwise the
    /// type itself. The flow BUILDER'S question, and only the builder's.
    /// </summary>
    public string EffectiveType(string type)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        string? cursor = type;
        while (cursor is not null && _byType.TryGetValue(cursor, out var row) && seen.Add(cursor))
        {
            if (cursor is "date" or "number") return cursor;
            cursor = row.Parent;
        }
        return type;
    }

    // ── validation ───────────────────────────────────────────────────────────

    /// <summary>
    /// Validate a plaintext value against a type, in the one fixed order: the
    /// primitive's own rule, then the resolved check, then every regex root-first, then the
    /// sub-field entries. The CHECK's normalised value is what those regexes see; the primitive's is
    /// not.
    /// </summary>
    /// <remarks>
    /// An EMPTY value is valid — required is the caller's job — and a type the registry does not
    /// carry accepts anything, which is the pinned answer for a client older than a type.
    /// </remarks>
    /// <returns>null when valid, else the name of the first failing rule.</returns>
    public string? Validate(string? type, string? value, IReadOnlyList<string>? suppliedOptions = null)
    {
        var text = value ?? "";
        if (text.Length == 0) return null;
        var definition = Resolve(type);
        if (!definition.Known) return null;

        var failure = ApplyPrimitive(definition, text, OptionsFor(type, suppliedOptions));
        if (failure is not null) return failure;

        // A CHECK'S NORMALISATION CARRIES; A PRIMITIVE'S DOES NOT, and the asymmetry is the rule
        // rather than an oversight. A check states the canonical form of the value it verifies — a
        // URL with its scheme, a card number without its separators — so a regex a child adds below
        // it describes that form and is tested against it. A primitive draws a value it does not
        // rewrite, so nothing it does reaches the regex step.
        var matched = text;
        if (!string.IsNullOrEmpty(definition.Check))
        {
            failure = ApplyCheck(definition.Check!, text);
            if (failure is not null) return failure;
            matched = NormaliseForCheck(definition.Check!, text);
        }
        foreach (var regex in definition.Validations)
        {
            if (!MatchesRegex(regex, matched)) return "validation";
        }
        return null;
    }

    /// <summary>True when <paramref name="value"/> is an acceptable plaintext for <paramref name="type"/>.</summary>
    public bool IsFieldValueValid(string? type, string? value, IReadOnlyList<string>? suppliedOptions = null) =>
        Validate(type, value, suppliedOptions) is null;

    /// <summary>Null when valid, else the name of the first failing rule.</summary>
    public string? FieldValueError(string? type, string? value, IReadOnlyList<string>? suppliedOptions = null) =>
        Validate(type, value, suppliedOptions);

    /// <remarks>
    /// <paramref name="options"/> is the domain a choice value is held to, already resolved by
    /// <see cref="OptionsFor"/>; null is "there is no domain", which is refused rather than tested.
    /// </remarks>
    private string? ApplyPrimitive(Resolved definition, string value, IReadOnlyList<string>? options)
    {
        var primitive = definition.Input;
        return primitive switch
        {
            null or "line" => null,
            "date" => IsCalendarDate(value) ? null : "date",
            "list" => options is null ? "options_unavailable" : (options.Contains(value) ? null : "list"),
            "multilist" => options is null
                ? "options_unavailable"
                : (IsOptionArray(value, options) ? null : "multilist"),
            "country" or "nationality" => CountrySet.Contains(value) ? null : primitive,
            "state" => UsStateSet.Contains(value) ? null : "state",
            "phone" => PhoneRe.IsMatch(PhoneStripRe.Replace(value, "")) ? null : "phone",
            "composite" => ValidateObject(value, definition.Fields, Array.Empty<string>()),
            "file" or "pages" => ValidateObject(value, definition.Fields, EnvelopeMembers),
            _ => null,
        };
    }

    /// <summary>
    /// A JSON object value: no unknown key, every required entry present, and each non-empty entry
    /// valid for its own primitive, check and regex.
    /// </summary>
    /// <remarks>
    /// <paramref name="envelopeMembers"/> are the primitive's own members, accepted beside the
    /// entries and validated by <see cref="ValidateEnvelopeMember"/> — the one home for what each
    /// of them looks like.
    /// </remarks>
    private static string? ValidateObject(
        string value, IReadOnlyList<SubFieldEntry>? fields, IReadOnlyList<string> envelopeMembers)
    {
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(value);
        }
        catch (JsonException)
        {
            return "object";
        }
        using (doc)
        {
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return "object";

            var entries = new Dictionary<string, SubFieldEntry>(StringComparer.Ordinal);
            foreach (var entry in fields ?? (IReadOnlyList<SubFieldEntry>)Array.Empty<SubFieldEntry>())
            {
                if (!string.IsNullOrEmpty(entry.Key)) entries[entry.Key] = entry;
            }

            var present = new HashSet<string>(StringComparer.Ordinal);
            foreach (var member in doc.RootElement.EnumerateObject())
            {
                present.Add(member.Name);
                if (entries.TryGetValue(member.Name, out var entry))
                {
                    if (member.Value.ValueKind != JsonValueKind.String) return member.Name;
                    var s = member.Value.GetString() ?? "";
                    if (s.Length > 0 && ValidateEntry(entry, s) is not null) return member.Name;
                    continue;
                }
                if (!envelopeMembers.Contains(member.Name)) return "unknown_key";
                var memberFailure = ValidateEnvelopeMember(member.Name, member.Value);
                if (memberFailure is not null) return memberFailure;
            }

            foreach (var (key, entry) in entries)
            {
                if (!entry.Required) continue;
                if (!present.Contains(key)) return key;
                var got = doc.RootElement.GetProperty(key);
                if (got.ValueKind == JsonValueKind.String && got.GetString() == "") return key;
            }
        }
        return null;
    }

    /// <summary>
    /// ONE member of a <c>file</c>/<c>pages</c> envelope, by its own shape — the single home for
    /// what each member looks like, so a member added to the envelope is one branch here and
    /// nothing else.
    /// </summary>
    /// <remarks>
    /// <c>size</c> is a JSON integer, <c>pages</c> the multi-page list below, <c>mime_type</c> a
    /// MIME string when it carries anything, and every other member a string.
    /// </remarks>
    private static string? ValidateEnvelopeMember(string key, JsonElement raw)
    {
        if (key == "pages") return ValidatePages(raw);
        if (key == "size")
        {
            return raw.ValueKind == JsonValueKind.Number && raw.TryGetInt64(out _) ? null : "size";
        }
        if (raw.ValueKind != JsonValueKind.String) return key;
        var text = raw.GetString() ?? "";
        if (key == "mime_type" && text.Length > 0 && !MimeRe.IsMatch(text)) return "mime_type";
        return null;
    }

    /// <summary>
    /// The <c>pages</c> member of an ID-document envelope: a LIST of page objects, never a scalar.
    /// </summary>
    /// <remarks>
    /// Each page names one uploaded file plus that file's own metadata. <c>file</c> is the
    /// reference and is required; <c>label</c> says which slot the page fills, and the slots are
    /// exactly the ones the multi-page editor draws — a front, an optional back, and repeatable
    /// extras. An empty list is a document whose pages have not been uploaded yet, which is a valid
    /// envelope.
    /// </remarks>
    private static string? ValidatePages(JsonElement raw)
    {
        if (raw.ValueKind != JsonValueKind.Array) return "pages";
        foreach (var page in raw.EnumerateArray())
        {
            if (page.ValueKind != JsonValueKind.Object) return "pages";
            var hasFile = false;
            foreach (var member in page.EnumerateObject())
            {
                if (!PageMembers.Contains(member.Name)) return "pages";
                if (member.Name == "label")
                {
                    if (member.Value.ValueKind != JsonValueKind.String) return "pages";
                    if (!PageLabels.Contains(member.Value.GetString() ?? "")) return "pages";
                    continue;
                }
                if (member.Name == "file")
                {
                    if (member.Value.ValueKind != JsonValueKind.String) return "pages";
                    if ((member.Value.GetString() ?? "").Length == 0) return "pages";
                    hasFile = true;
                    continue;
                }
                if (ValidateEnvelopeMember(member.Name, member.Value) is not null) return "pages";
            }
            if (!hasFile) return "pages";
        }
        return null;
    }

    /// <summary>One sub-field entry: its primitive rule, then its check, then its regex.</summary>
    private static string? ValidateEntry(SubFieldEntry entry, string value)
    {
        var primitive = string.IsNullOrEmpty(entry.Input) ? "line" : entry.Input!;
        var options = entry.Options ?? Array.Empty<string>();
        var failure = primitive switch
        {
            "date" => IsCalendarDate(value) ? null : "date",
            "list" => options.Contains(value) ? null : "list",
            "country" or "nationality" => CountrySet.Contains(value) ? null : primitive,
            "state" => UsStateSet.Contains(value) ? null : "state",
            "phone" => PhoneRe.IsMatch(PhoneStripRe.Replace(value, "")) ? null : "phone",
            _ => null,
        };
        if (failure is not null) return failure;

        // The entry runs the same primitive → check → regex order a top-level value does, and the
        // check's normalisation carries into its regex for the same reason it does there — so a
        // composite's entry can never disagree with a value of the same shape.
        var matched = value;
        if (!string.IsNullOrEmpty(entry.Check))
        {
            if (ApplyCheck(entry.Check!, value) is not null) return entry.Check;
            matched = NormaliseForCheck(entry.Check!, value);
        }
        if (!string.IsNullOrEmpty(entry.Validation) && !MatchesRegex(entry.Validation!, matched))
            return "validation";
        return null;
    }

    /// <summary>
    /// The CANONICAL FORM a named check verifies — and the form a regex below that check is tested
    /// against, since the check is what states it.
    /// </summary>
    public static string NormaliseForCheck(string check, string value) => check switch
    {
        "url" => UrlSchemeRe.IsMatch(value) ? value : "https://" + value,
        "card" => CardStripRe.Replace(value, ""),
        "number" or "integer" or "decimal" or "float" => value.Trim(),
        _ => value,
    };

    /// <summary>One named check, applied to the whole value in its canonical form; null when it passes.</summary>
    public static string? ApplyCheck(string check, string value)
    {
        var normalised = NormaliseForCheck(check, value);
        var ok = check switch
        {
            "url" => UrlRe.IsMatch(normalised),
            "card" => CardRe.IsMatch(normalised) && LuhnOk(normalised),
            "number" => FiniteNumber(normalised),
            "integer" => IntegerRe.IsMatch(normalised),
            "decimal" => DecimalRe.IsMatch(normalised),
            "float" => FloatRe.IsMatch(normalised),
            _ => true,
        };
        return ok ? null : check;
    }

    /// <summary>A stored regex anchored to the WHOLE value, or null when this engine cannot compile it.</summary>
    public static Regex? CompileRegex(string regex)
    {
        lock (CompiledRegexes)
        {
            if (CompiledRegexes.TryGetValue(regex, out var cached)) return cached;
            Regex? compiled;
            try
            {
                compiled = new Regex("^(?:" + regex + ")$");
            }
            catch (ArgumentException)
            {
                compiled = null;
            }
            CompiledRegexes[regex] = compiled;
            return compiled;
        }
    }

    /// <summary>
    /// Whether a value matches a stored regex, which is anchored to the whole value.
    /// </summary>
    /// <remarks>
    /// A pattern that cannot be compiled is refused at write, so reaching this with one means the
    /// stored row predates the rule it is now held to: no verdict can be stated, and refusing the
    /// value would refuse every value of that type.
    /// </remarks>
    public static bool MatchesRegex(string regex, string value)
    {
        var compiled = CompileRegex(regex);
        return compiled is null || compiled.IsMatch(value);
    }

    /// <summary>A real calendar date in <c>YYYY-MM-DD</c>.</summary>
    public static bool IsCalendarDate(string value)
    {
        if (!DateRe.IsMatch(value)) return false;
        var year = int.Parse(value.Substring(0, 4), CultureInfo.InvariantCulture);
        var month = int.Parse(value.Substring(5, 2), CultureInfo.InvariantCulture);
        var day = int.Parse(value.Substring(8, 2), CultureInfo.InvariantCulture);
        if (month < 1 || month > 12) return false;
        return day >= 1 && day <= DaysInMonth(year, month);
    }

    private static int DaysInMonth(int year, int month)
    {
        if (month == 2)
        {
            var leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
            return leap ? 29 : 28;
        }
        return DaysInMonthTable[month - 1];
    }

    private static bool LuhnOk(string digits)
    {
        var total = 0;
        var dbl = false;
        for (var i = digits.Length - 1; i >= 0; i--)
        {
            var d = digits[i] - '0';
            if (d < 0 || d > 9) return false;
            if (dbl)
            {
                d *= 2;
                if (d > 9) d -= 9;
            }
            total += d;
            dbl = !dbl;
        }
        return total % 10 == 0;
    }

    private static bool FiniteNumber(string value)
    {
        if (value.Length == 0) return false;
        return double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var n)
            && !double.IsNaN(n) && !double.IsInfinity(n);
    }

    private static bool IsOptionArray(string value, IReadOnlyList<string> options)
    {
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(value);
        }
        catch (JsonException)
        {
            return false;
        }
        using (doc)
        {
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return false;
            foreach (var element in doc.RootElement.EnumerateArray())
            {
                if (element.ValueKind != JsonValueKind.String) return false;
                if (!options.Contains(element.GetString() ?? "")) return false;
            }
        }
        return true;
    }
}
