// XXE-safe XML parsing — the inverse of the platform's XML serialization.
//
// Responses + webhooks may be XML. Each port MUST parse with entity expansion + external-entity
// resolution DISABLED. In .NET that means XmlReader.Create with XmlReaderSettings:
//   DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null
// HMAC is always computed over the raw bytes, never the parsed tree.
//
// The platform's XML serialization:
//   * the document root is <response>;
//   * a PHP list (int keys) renders as repeated <item> children → a list;
//   * an associative array renders as named child tags → a dict (object);
//   * scalars are element text; booleans were written as "true"/"false".
//
// We materialize XML into the same in-memory shape JSON parses to: a Node tree of
// dict/list/scalar, so the model layer is wire-format-agnostic.

using System.Xml;

namespace Allus.CompanyData;

internal static class Xml
{
    /// <summary>
    /// Parse the platform's XML serialization back into a <see cref="Node"/> tree (dict/list/scalar).
    /// XXE-safe: DTDs prohibited, no external resolver. Throws on malformed XML.
    /// </summary>
    public static Node Parse(string text)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit, // no DOCTYPE / entity expansion
            XmlResolver = null,                      // no external-entity resolution
            IgnoreComments = true,
            IgnoreProcessingInstructions = true,
            IgnoreWhitespace = true,
            MaxCharactersFromEntities = 0,
        };

        var doc = new XmlDocument { XmlResolver = null };
        using (var sr = new StringReader(text))
        using (var reader = XmlReader.Create(sr, settings))
        {
            doc.Load(reader);
        }
        if (doc.DocumentElement is null)
            return Node.Null;
        return ElementToNode(doc.DocumentElement);
    }

    private static Node ElementToNode(XmlElement elem)
    {
        var childElements = elem.ChildNodes
            .OfType<XmlElement>()
            .ToList();

        if (childElements.Count == 0)
        {
            // A leaf node: its text (or empty string). Callers coerce types from the known schema;
            // booleans came over as "true"/"false".
            return Node.Scalar(elem.InnerText ?? string.Empty);
        }

        // All children are <item> → a list (PHP int-keyed array).
        if (childElements.All(c => c.LocalName == "item"))
        {
            var list = childElements.Select(ElementToNode).ToList();
            return Node.List(list);
        }

        // Otherwise an object: named tags → keys. Repeated tags collapse to a list.
        var map = new Dictionary<string, Node>();
        foreach (var child in childElements)
        {
            var value = ElementToNode(child);
            var name = child.LocalName;
            if (map.TryGetValue(name, out var existing))
            {
                if (existing.Kind == NodeKind.List)
                    existing.AsList().Add(value);
                else
                    map[name] = Node.List(new List<Node> { existing, value });
            }
            else
            {
                map[name] = value;
            }
        }
        return Node.Object(map);
    }
}
