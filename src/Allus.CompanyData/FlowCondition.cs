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
using System.Text.RegularExpressions;

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
            // #102 substring ops (text): contains needs an answer (like in); not_contains is
            // true when unanswered (like nin). Case-sensitive; empty needle counts as contained.
            case "contains": return Answered(val) && Str(val).Contains(Str(ScalarOf(targetNode)));
            case "not_contains": return !(Answered(val) && Str(val).Contains(Str(ScalarOf(targetNode))));
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

    // ── Flow constants (computed variables) — issue #79. Pure; extends the evaluator above. ──
    // ComputeConstants materialises each constant's value into a NEW slug→value map (answers +
    // {key:value}) in topological (dependency) order, so the evaluator's leaf {field:<constKey>}
    // resolves a constant with zero change. null propagates: an unresolved operand yields null; a
    // null constant behaves like an unanswered field. Pinned by contract-flow-constants-vector.json.
    //
    // Constants and expression ASTs travel as the wire-agnostic Node tree (the same type conditions
    // use), so an if-case `when` is just a Node handed to Evaluate(). Numeric results: datediff → long,
    // math → double. Reuses this class's private ToNum / Str and public Evaluate UNCHANGED.

    /// <summary>
    /// Evaluate every constant into a NEW map = answers + {key:value}, in topological (dependency)
    /// order. A ref to an operand not yet in the map resolves to null; null propagates. Cycles
    /// (rejected by the author-side validator) are broken defensively via 3-colour DFS, with
    /// dependency iteration in insertion order so every port breaks the same back-edge.
    /// </summary>
    public static IReadOnlyDictionary<string, object?> ComputeConstants(
        IEnumerable<Node> constants, IReadOnlyDictionary<string, object?> answers, string? referenceDate)
    {
        var outMap = new Dictionary<string, object?>(answers);
        var list = constants?.ToList() ?? new List<Node>();

        var byKey = new Dictionary<string, Node>();
        foreach (var c in list)
        {
            var k = c.Get("key").AsString();
            if (k is not null) byKey[k] = c;
        }
        var constKeys = new HashSet<string>(byKey.Keys);

        var order = new List<string>();
        var state = new Dictionary<string, int>();          // 0 = visiting (grey), 1 = done (black)
        void Visit(string key)
        {
            if (state.ContainsKey(key)) return;             // grey (cycle back-edge) or black → stop
            state[key] = 0;
            var deps = new OrderedKeySet();
            CollectExprConstRefs(byKey[key].Get("expr"), constKeys, deps);
            foreach (var dep in deps.Keys)                  // insertion order — deterministic
                if (byKey.ContainsKey(dep)) Visit(dep);
            state[key] = 1;
            order.Add(key);                                  // post-order → dependencies precede dependents
        }
        foreach (var c in list)
        {
            var k = c.Get("key").AsString();
            if (k is not null) Visit(k);
        }

        foreach (var key in order)
            outMap[key] = EvalExpr(byKey[key].Get("expr"), outMap, referenceDate);   // read prior constants
        return outMap;
    }

    /// <summary>
    /// Only the constant key→value entries (the original answers excluded) — an author-preview
    /// convenience over <see cref="ComputeConstants"/>.
    /// </summary>
    public static IReadOnlyDictionary<string, object?> ResolvedConstants(
        IEnumerable<Node> constants, IReadOnlyDictionary<string, object?> answers, string? referenceDate)
    {
        var list = constants?.ToList() ?? new List<Node>();
        var full = ComputeConstants(list, answers, referenceDate);
        var result = new Dictionary<string, object?>();
        foreach (var c in list)
        {
            var k = c.Get("key").AsString();
            if (k is not null && full.TryGetValue(k, out var v)) result[k] = v;
        }
        return result;
    }

    /// <summary>
    /// Per-call-site wrapper: materialise constants, then evaluate the condition unchanged.
    /// </summary>
    public static bool EvaluateFlowCondition(
        Node condition, IReadOnlyDictionary<string, object?> answers,
        IEnumerable<Node> constants, string? referenceDate)
        => Evaluate(condition, ComputeConstants(constants, answers, referenceDate));

    /// <summary>Evaluate one expression AST node against the map. Any error / unknown path → null.</summary>
    public static object? EvalExpr(Node expr, IReadOnlyDictionary<string, object?> map, string? referenceDate)
    {
        if (expr is null || expr.Kind != NodeKind.Object) return null;
        switch (expr.Get("type").AsString())
        {
            case "lit":
                return LitValue(expr);
            case "ref":
            {
                var key = expr.Get("key").AsString();
                if (key is not null && map.TryGetValue(key, out var v)) return v;   // stored null stays null
                return null;                                                          // operand not in map → null
            }
            case "today":
                return string.IsNullOrEmpty(referenceDate) ? null : referenceDate;    // never the device clock
            case "if":
            {
                foreach (var cs in expr.Get("cases").AsList())
                    if (Evaluate(cs.Get("when"), map))                                // a missing `when` → true
                        return EvalExpr(cs.Get("then"), map, referenceDate);
                return EvalExpr(expr.Get("else"), map, referenceDate);               // else required (total)
            }
            case "concat":
            {
                var sepNode = expr.Get("sep");
                var sep = sepNode.Kind == NodeKind.Scalar && sepNode.RawScalar is string ss ? ss : "";
                var parts = expr.Get("parts").AsList()
                    .Select(p => EvalExpr(p, map, referenceDate))
                    .Select(v => v is null ? "" : Str(v));                           // null part → ""
                return string.Join(sep, parts);                                       // always text
            }
            case "datediff":
            {
                var from = ParseFlowDate(EvalExpr(expr.Get("from"), map, referenceDate));
                var to = ParseFlowDate(EvalExpr(expr.Get("to"), map, referenceDate));
                if (from is null || to is null) return null;                          // non-date operand → null
                var f = from.Value; var t = to.Value;
                return expr.Get("unit").AsString() switch
                {
                    "days" => DiffDays(f, t),
                    "weeks" => DiffDays(f, t) / 7,                                    // long/int → trunc toward zero
                    "months" => DiffMonths(f, t),
                    "years" => DiffYears(f, t),
                    _ => (object?)null,
                };
            }
            case "math":
            {
                var args = expr.Get("args").AsList();
                var nums = new List<double>(args.Count);
                foreach (var a in args)
                {
                    var n = ToNum(EvalExpr(a, map, referenceDate));
                    // any null/non-numeric (incl. bool) arg → null; a non-finite arg (e.g. the
                    // numeric string "1e309" coercing to Infinity) → null (pinned policy).
                    if (!n.HasValue || !double.IsFinite(n.Value)) return null;
                    nums.Add(n.Value);
                }
                switch (expr.Get("op").AsString())
                {
                    case "add": return FinNum(nums.Aggregate(0.0, (x, y) => x + y));   // variadic, identity 0
                    case "mul": return FinNum(nums.Aggregate(1.0, (x, y) => x * y));   // variadic, identity 1
                    case "sub": return nums.Count >= 2 ? FinNum(nums[0] - nums[1]) : null;
                    case "div": return nums.Count >= 2 && nums[1] != 0 ? FinNum(nums[0] / nums[1]) : null;  // /0 → null
                    case "mod": return nums.Count >= 2 && nums[1] != 0 ? FinNum(nums[0] % nums[1]) : null;  // %0 → null (truncated remainder)
                    case "neg": return nums.Count >= 1 ? FinNum(-nums[0]) : null;
                    case "abs": return nums.Count >= 1 ? FinNum(Math.Abs(nums[0])) : null;
                    case "round": return nums.Count >= 1 ? FinNum(Math.Round(nums[0], MidpointRounding.AwayFromZero)) : null;  // half away from zero
                    case "floor": return nums.Count >= 1 ? FinNum(Math.Floor(nums[0])) : null;
                    case "ceil": return nums.Count >= 1 ? FinNum(Math.Ceiling(nums[0])) : null;
                    default: return null;
                }
            }
            default:
                return null;
        }
    }

    /// <summary>The pinned non-finite policy: an overflowed math result (Inf/NaN) → null.</summary>
    private static object? FinNum(double r) => double.IsFinite(r) ? r : (object?)null;

    /// <summary>A lit node's raw scalar value; absent/non-scalar → null (keeps native type).</summary>
    private static object? LitValue(Node expr)
    {
        var v = expr.Get("value");
        return v.Kind == NodeKind.Scalar ? v.RawScalar : null;
    }

    // Parse a value as a UTC-midnight calendar date. Non-strict-ISO-date → null (rejects 2026-02-30
    // via the DateTime constructor). Only a real string operand can be a date; anything else → null.
    private static (int y, int m, int d, DateTime utc)? ParseFlowDate(object? v)
    {
        if (v is not string s) return null;
        var mt = Regex.Match(s.Trim(), @"^(\d{4})-(\d{2})-(\d{2})$");
        if (!mt.Success) return null;
        int y = int.Parse(mt.Groups[1].Value, CultureInfo.InvariantCulture);
        int mo = int.Parse(mt.Groups[2].Value, CultureInfo.InvariantCulture);
        int d = int.Parse(mt.Groups[3].Value, CultureInfo.InvariantCulture);
        if (mo < 1 || mo > 12 || d < 1 || d > 31) return null;
        try
        {
            var utc = new DateTime(y, mo, d, 0, 0, 0, DateTimeKind.Utc);
            if (utc.Year != y || utc.Month != mo || utc.Day != d) return null;
            return (y, mo, d, utc);
        }
        catch (ArgumentOutOfRangeException) { return null; }
    }

    // Whole calendar days (both operands at UTC midnight → the difference is integral). Sign = to - from.
    private static long DiffDays((int y, int m, int d, DateTime utc) from, (int y, int m, int d, DateTime utc) to)
        => (long)Math.Round((to.utc - from.utc).TotalDays);

    // (to.y-from.y)*12 + (to.m-from.m), minus 1 if to.day < from.day. Literal formula; works both signs.
    private static long DiffMonths((int y, int m, int d, DateTime utc) from, (int y, int m, int d, DateTime utc) to)
    {
        long n = (to.y - from.y) * 12L + (to.m - from.m);
        if (to.d < from.d) n -= 1;
        return n;
    }

    // Standard age: to.y-from.y, minus 1 if (to.month, to.day) < (from.month, from.day) lexicographically.
    private static long DiffYears((int y, int m, int d, DateTime utc) from, (int y, int m, int d, DateTime utc) to)
    {
        long n = to.y - from.y;
        if (to.m < from.m || (to.m == from.m && to.d < from.d)) n -= 1;
        return n;
    }

    /// <summary>
    /// Collects keys in first-seen (insertion) order so the DFS dependency iteration is
    /// deterministic — every port breaks the same back-edge on a (validator-rejected) cycle.
    /// </summary>
    private sealed class OrderedKeySet
    {
        private readonly HashSet<string> _seen = new();
        public List<string> Keys { get; } = new();
        public void Add(string k) { if (_seen.Add(k)) Keys.Add(k); }
    }

    // Collect the constant KEYS an expression directly references (topological ordering only).
    private static void CollectExprConstRefs(Node expr, HashSet<string> constKeys, OrderedKeySet acc)
    {
        if (expr.Kind != NodeKind.Object) return;
        switch (expr.Get("type").AsString())
        {
            case "ref":
            {
                var k = expr.Get("key").AsString();
                if (k is not null && constKeys.Contains(k)) acc.Add(k);
                return;
            }
            case "lit":
            case "today":
                return;
            case "if":
                foreach (var cs in expr.Get("cases").AsList())
                {
                    CollectCondConstRefs(cs.Get("when"), constKeys, acc);   // a when-leaf may name a constant
                    CollectExprConstRefs(cs.Get("then"), constKeys, acc);
                }
                CollectExprConstRefs(expr.Get("else"), constKeys, acc);
                return;
            case "concat":
                foreach (var p in expr.Get("parts").AsList()) CollectExprConstRefs(p, constKeys, acc);
                return;
            case "datediff":
                CollectExprConstRefs(expr.Get("from"), constKeys, acc);
                CollectExprConstRefs(expr.Get("to"), constKeys, acc);
                return;
            case "math":
                foreach (var a in expr.Get("args").AsList()) CollectExprConstRefs(a, constKeys, acc);
                return;
        }
    }

    private static void CollectCondConstRefs(Node cond, HashSet<string> constKeys, OrderedKeySet acc)
    {
        if (cond.Kind != NodeKind.Object) return;
        var op = cond.Get("op").AsString();
        if (op is "and" or "or" or "not")
        {
            foreach (var ch in cond.Get("children").AsList()) CollectCondConstRefs(ch, constKeys, acc);
            return;
        }
        var field = cond.Get("field").AsString();
        if (field is not null && constKeys.Contains(field)) acc.Add(field);
    }
}
