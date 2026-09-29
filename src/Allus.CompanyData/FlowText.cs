using System.Text.RegularExpressions;

namespace Allus.CompanyData;

/// <summary>
/// The value tags a contract-flow TEXT element names, read by the platform's text grammar: HTML tags
/// are removed first, <c>\[</c> <c>\]</c> <c>\{</c> <c>\\</c> are escapes, and a <c>{{…}}</c> an
/// escape breaks is not a tag. A tag inside a link address (<c>[a href=X]</c>) is a tag too. A starter
/// compiles the values of the definition's non-owner PARTY tags before it starts a run
/// (<see cref="Client.TriggerFlowRunAsync"/>).
/// </summary>
public static class FlowText
{
    private static readonly Regex HtmlTag = new(@"</?[a-zA-Z][^<>]*>", RegexOptions.CultureInvariant);
    private static readonly Regex TagAt = new(
        @"\G\{\{\s*([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){0,2})\s*\}\}",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private const string Escapable = "[]{\\";

    /// <summary>One non-owner party tag of a definition: the tag, its party key and its field (request slug).</summary>
    public sealed record PartyTag(string Tag, string Party, string Field);

    private static bool AddressCloses(string s, int from)
    {
        for (var i = from; i < s.Length; i++)
        {
            if (s[i] == '\\' && i + 1 < s.Length && Escapable.IndexOf(s[i + 1]) >= 0)
            {
                i++;
                continue;
            }
            if (s[i] == ']') return true;
        }
        return false;
    }

    /// <summary>Every value-tag key a text body names — in its text and its link addresses — lower-cased, first use first.</summary>
    public static IReadOnlyList<string> Tags(string? body)
    {
        var s = HtmlTag.Replace(body ?? "", "");
        var output = new List<string>();
        var inAddress = false;
        var i = 0;
        while (i < s.Length)
        {
            var c = s[i];
            if (c == '\\' && i + 1 < s.Length && Escapable.IndexOf(s[i + 1]) >= 0)
            {
                i += 2;
                continue;
            }
            if (c == '{')
            {
                var m = TagAt.Match(s, i);
                if (m.Success)
                {
                    var k = m.Groups[1].Value.ToLowerInvariant();
                    if (!output.Contains(k)) output.Add(k);
                    i += m.Length;
                    continue;
                }
            }
            if (inAddress && c == ']')
            {
                inAddress = false;
                i++;
                continue;
            }
            if (!inAddress && c == '[' && i + 8 <= s.Length
                && s.Substring(i, 8).ToLowerInvariant() == "[a href=" && AddressCloses(s, i + 8))
            {
                inAddress = true;
                i += 8;
                continue;
            }
            i++;
        }
        return output;
    }

    /// <summary>The definition's NON-OWNER party tags — the tags whose values a starter compiles and seals.</summary>
    public static IReadOnlyList<PartyTag> NonOwnerPartyTags(Node definition)
    {
        var types = new Dictionary<string, string?>();
        if (definition.Get("parties").Kind == NodeKind.List)
        {
            foreach (var p in definition.Get("parties").AsList())
            {
                var key = p.Get("key").AsString();
                if (key is null) continue;
                var t = p.Get("type").AsString();
                types[key.ToLowerInvariant()] = string.IsNullOrEmpty(t) ? null : t;
            }
        }
        var output = new List<PartyTag>();
        if (definition.Get("nodes").Kind != NodeKind.List) return output;
        foreach (var node in definition.Get("nodes").AsList())
        {
            if (node.Get("elements").Kind != NodeKind.List) continue;
            foreach (var el in node.Get("elements").AsList())
            {
                if (el.Get("kind").AsString() != "text") continue;
                var body = new[] { "body", "text", "label" }
                    .Select(k => el.Get(k).AsString())
                    .FirstOrDefault(v => !string.IsNullOrEmpty(v)) ?? "";
                foreach (var tag in Tags(body))
                {
                    var dot = tag.IndexOf('.');
                    if (dot < 0) continue;
                    var party = tag[..dot];
                    if (!types.TryGetValue(party, out var type) || type == "owner") continue;
                    if (output.Any(x => x.Tag == tag)) continue;
                    output.Add(new PartyTag(tag, party, tag[(dot + 1)..]));
                }
            }
        }
        return output;
    }
}
