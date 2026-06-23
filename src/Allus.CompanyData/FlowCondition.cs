// Pure port of the platform FlowConditionEvaluator (A-spec §4) — pinned to the shared
// contract-flow-condition-vector.json.
//
// A condition is one of:
//   - a null/non-object Node → always true (the "no condition" short-circuit).
//   - a boolean node {op:"and"|"or"|"not", children:[...]} (not = one child).
//   - a comparison leaf {field, op, value} with op in eq ne lt le gt ge in nin answered empty.
//
// answers is the decrypted {slug: value} map (scalar object values).
//
// Frozen semantics (see the vector):
//   - A blank/missing answer is "unanswered": never matches eq/ne/an ordered comparison
//     (→ false); empty true, answered false; nin true on missing.
//   - eq/ne: booleans by truth, numbers (with numeric-string coercion) by value, else strings
//     exactly. in/nin: membership in the array value.
//   - Ordered (lt/le/gt/ge): BOTH numeric → numeric compare; BOTH non-numeric → string compare
//     (so YYYY-MM-DD dates sort chronologically); MIXED → false.
//   - and over [] → true; or over [] → false.

using System.Globalization;

namespace Allus.CompanyData;

/// <summary>
/// The contract-flow condition evaluator — the single source of routing / show-if /
/// option-availability, byte-identical to the platform PHP reference and the other SDK ports.
/// </summary>
public static class FlowCondition
{
    /// <summary>
    /// Evaluate a condition <see cref="Node"/> against the decrypted answer map.
    /// </summary>
    public static bool Evaluate(Node condition, IReadOnlyDictionary<string, object?> answers)
    {
        if (condition is null || condition.Kind != NodeKind.Object) return true;

        var op = condition.Get("op").AsString();
        if (op is "and" or "or" or "not")
        {
            var kids = condition.Get("children").Kind == NodeKind.List
                ? condition.Get("children").AsList()
                : new List<Node>();
            return op switch
            {
                "and" => kids.All(c => Evaluate(c, answers)),
                "or" => kids.Any(c => Evaluate(c, answers)),
                _ => !Evaluate(kids.Count > 0 ? kids[0] : Node.Null, answers), // not
            };
        }

        var slug = condition.Get("field").AsString() ?? "";
        var targetNode = condition.Get("value");
        var val = answers.TryGetValue(slug, out var v) ? v : null;

        switch (op)
        {
            case "answered": return Answered(val);
            case "empty": return !Answered(val);
            case "in": return InList(targetNode, val);
            case "nin": return !InList(targetNode, val);
        }

        if (!Answered(val)) return false;
        var target = ScalarOf(targetNode);
        switch (op)
        {
            case "eq": return LooseEq(target, val);
            case "ne": return !LooseEq(target, val);
            case "lt" or "gt" or "le" or "ge":
                var a = ToNum(val);
                var b = ToNum(target);
                if (a.HasValue && b.HasValue) return CmpNum(op, a.Value, b.Value);
                // Mixed (one numeric, one not) → false; both non-numeric → string compare.
                if (a.HasValue || b.HasValue) return false;
                return CmpStr(op, Str(val), Str(target));
            default: return false;
        }
    }

    private static bool Answered(object? v)
    {
        if (v is null) return false;
        if (v is string s) return s.Length != 0;
        return true;
    }

    /// <summary>The condition's <c>value</c> scalar (or the list/null Node mapped to a raw object).</summary>
    private static object? ScalarOf(Node node) => node.Kind switch
    {
        NodeKind.Scalar => node.RawScalar,
        NodeKind.Null => null,
        _ => null,
    };

    private static bool InList(Node targetNode, object? val)
    {
        if (targetNode.Kind != NodeKind.List) return false;
        return targetNode.AsList().Any(x => LooseEq(ScalarOf(x), val));
    }

    private static double? ToNum(object? v)
    {
        switch (v)
        {
            case null: return null;
            case bool: return null;
            case double d: return d;
            case float f: return f;
            case long l: return l;
            case int i: return i;
            case string s:
                var t = s.Trim();
                if (t.Length == 0) return null;
                return double.TryParse(t, NumberStyles.Any, CultureInfo.InvariantCulture, out var n) ? n : null;
            default: return null;
        }
    }

    private static bool LooseEq(object? a, object? b)
    {
        if (a is bool || b is bool) return Truthy(a) == Truthy(b);
        var na = ToNum(a);
        var nb = ToNum(b);
        if (na.HasValue && nb.HasValue) return na.Value == nb.Value;
        return Str(a) == Str(b);
    }

    private static bool Truthy(object? v) => v switch
    {
        bool b => b,
        null => false,
        string s => s.Length != 0,
        _ => ToNum(v) is { } n ? n != 0 : true,
    };

    private static string Str(object? v)
    {
        switch (v)
        {
            case null: return "";
            case bool b: return b ? "true" : "false";
            case string s: return s;
            case double d:
                return d == Math.Floor(d) && !double.IsInfinity(d)
                    ? ((long)d).ToString(CultureInfo.InvariantCulture)
                    : d.ToString(CultureInfo.InvariantCulture);
            case float f: return Str((double)f);
            case long l: return l.ToString(CultureInfo.InvariantCulture);
            case int i: return i.ToString(CultureInfo.InvariantCulture);
            default: return v.ToString() ?? "";
        }
    }

    private static bool CmpNum(string op, double a, double b) => op switch
    {
        "lt" => a < b,
        "gt" => a > b,
        "le" => a <= b,
        _ => a >= b, // ge
    };

    private static bool CmpStr(string op, string a, string b) => op switch
    {
        "lt" => string.CompareOrdinal(a, b) < 0,
        "gt" => string.CompareOrdinal(a, b) > 0,
        "le" => string.CompareOrdinal(a, b) <= 0,
        _ => string.CompareOrdinal(a, b) >= 0, // ge
    };
}
