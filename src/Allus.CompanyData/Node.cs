// A wire-format-agnostic in-memory tree (object / list / scalar / null) so the model layer is
// identical for JSON and XML payloads. JSON (System.Text.Json) and XML both materialize into a
// Node tree, and the models read Node — never JsonElement or XmlElement directly. Scalars are kept
// as their raw string/number/bool; booleans from XML arrive as the "true"/"false" strings the
// platform wrote and are coerced in the model layer.

using System.Text.Json;

namespace Allus.CompanyData;

/// <summary>The kind of a <see cref="Node"/>.</summary>
public enum NodeKind { Null, Scalar, List, Object }

/// <summary>
/// A wire-format-agnostic value: a JSON/XML payload materialized into object/list/scalar/null.
/// The model factories read these so they don't care whether the body was JSON or XML.
/// </summary>
public sealed class Node
{
    public NodeKind Kind { get; }
    private readonly object? _scalar;                // string | bool | double | long | null
    private readonly List<Node>? _list;
    private readonly Dictionary<string, Node>? _object;

    private Node(NodeKind kind, object? scalar = null, List<Node>? list = null, Dictionary<string, Node>? obj = null)
    {
        Kind = kind;
        _scalar = scalar;
        _list = list;
        _object = obj;
    }

    public static readonly Node Null = new(NodeKind.Null);
    public static Node Scalar(object? value) => new(NodeKind.Scalar, scalar: value);
    public static Node List(List<Node> items) => new(NodeKind.List, list: items);
    public static Node Object(Dictionary<string, Node> map) => new(NodeKind.Object, obj: map);

    public bool IsNull => Kind == NodeKind.Null;

    /// <summary>The list items (only valid when <see cref="Kind"/> is <see cref="NodeKind.List"/>).</summary>
    public List<Node> AsList() => _list ?? new List<Node>();

    /// <summary>The object map (only valid when <see cref="Kind"/> is <see cref="NodeKind.Object"/>).</summary>
    public IReadOnlyDictionary<string, Node> AsObject() =>
        _object ?? new Dictionary<string, Node>();

    /// <summary>True when this is an object that contains <paramref name="key"/>.</summary>
    public bool Has(string key) => Kind == NodeKind.Object && _object!.ContainsKey(key);

    /// <summary>Look up an object property; returns a <see cref="NodeKind.Null"/> node if absent.</summary>
    public Node Get(string key) =>
        Kind == NodeKind.Object && _object!.TryGetValue(key, out var n) ? n : Null;

    /// <summary>The scalar as a string (numbers/bools rendered to their string form), or null.</summary>
    public string? AsString()
    {
        if (Kind != NodeKind.Scalar) return null;
        return _scalar switch
        {
            null => null,
            string s => s,
            bool b => b ? "true" : "false",
            double d => d.ToString(System.Globalization.CultureInfo.InvariantCulture),
            long l => l.ToString(System.Globalization.CultureInfo.InvariantCulture),
            _ => _scalar.ToString(),
        };
    }

    /// <summary>The raw scalar object (string/bool/number/null) — used for boolean coercion.</summary>
    public object? RawScalar => _scalar;

    // ── conversions in ───────────────────────────────────────────────────────────────────────

    /// <summary>Materialize a <see cref="JsonElement"/> into a <see cref="Node"/> tree.</summary>
    public static Node FromJson(JsonElement el) => el.ValueKind switch
    {
        JsonValueKind.Object => Object(el.EnumerateObject()
            .ToDictionary(p => p.Name, p => FromJson(p.Value))),
        JsonValueKind.Array => List(el.EnumerateArray().Select(FromJson).ToList()),
        JsonValueKind.String => Scalar(el.GetString()),
        JsonValueKind.Number => el.TryGetInt64(out var l) ? Scalar(l) : Scalar(el.GetDouble()),
        JsonValueKind.True => Scalar(true),
        JsonValueKind.False => Scalar(false),
        JsonValueKind.Null or JsonValueKind.Undefined => Null,
        _ => Null,
    };

    /// <summary>Parse a JSON string into a <see cref="Node"/> tree.</summary>
    public static Node FromJsonString(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return FromJson(doc.RootElement);
    }

    // ── conversions out ────────────────────────────────────────────────────────────────────────

    /// <summary>Serialize this Node back to a JSON string (used to persist buffer events).</summary>
    public string ToJsonString()
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
            WriteJson(writer);
        return System.Text.Encoding.UTF8.GetString(stream.ToArray());
    }

    private void WriteJson(Utf8JsonWriter w)
    {
        switch (Kind)
        {
            case NodeKind.Object:
                w.WriteStartObject();
                foreach (var (k, v) in _object!)
                {
                    w.WritePropertyName(k);
                    v.WriteJson(w);
                }
                w.WriteEndObject();
                break;
            case NodeKind.List:
                w.WriteStartArray();
                foreach (var item in _list!) item.WriteJson(w);
                w.WriteEndArray();
                break;
            case NodeKind.Scalar:
                switch (_scalar)
                {
                    case null: w.WriteNullValue(); break;
                    case string s: w.WriteStringValue(s); break;
                    case bool b: w.WriteBooleanValue(b); break;
                    case long l: w.WriteNumberValue(l); break;
                    case double d: w.WriteNumberValue(d); break;
                    default: w.WriteStringValue(_scalar.ToString()); break;
                }
                break;
            default:
                w.WriteNullValue();
                break;
        }
    }

    /// <summary>A shallow clone of an object Node with one extra property set (used by deadletter).</summary>
    public Node WithProperty(string key, Node value)
    {
        var map = Kind == NodeKind.Object
            ? new Dictionary<string, Node>(_object!)
            : new Dictionary<string, Node>();
        map[key] = value;
        return Object(map);
    }

    /// <summary>A shallow clone of an object Node with the named properties removed.</summary>
    public Node Without(params string[] keys)
    {
        if (Kind != NodeKind.Object) return this;
        var map = new Dictionary<string, Node>(_object!);
        foreach (var k in keys) map.Remove(k);
        return Object(map);
    }

    /// <summary>
    /// Convert this Node back into a plain object graph (Dictionary / List / scalar) — used as the
    /// <c>Raw</c> escape hatch and for re-wrapping a ciphertext value for the decryptor.
    /// </summary>
    public object? ToObjectGraph()
    {
        switch (Kind)
        {
            case NodeKind.Object:
                var map = new Dictionary<string, object?>();
                foreach (var (k, v) in _object!) map[k] = v.ToObjectGraph();
                return map;
            case NodeKind.List:
                return _list!.Select(n => n.ToObjectGraph()).ToList();
            case NodeKind.Scalar:
                return _scalar;
            default:
                return null;
        }
    }
}
