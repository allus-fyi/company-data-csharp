// FlowConstants (computed variables) parity — issue #79. Every case in the shared
// contract-flow-constants-vector.json must pass; the same vector pins the PHP reference + the
// python/ts/go/iOS/Android ports. Mirrors FlowConditionTests' directory-walk vector finder.

using System.Text.Json;
using Allus.CompanyData;
using Xunit;

namespace Allus.CompanyData.Tests;

public sealed class FlowConstantsTests
{
    private static string VectorPath()
    {
        var dir = AppContext.BaseDirectory;
        for (var i = 0; i < 8 && dir is not null; i++)
        {
            var candidate = Path.Combine(dir, "testdata", "contract-flow-constants-vector.json");
            if (File.Exists(candidate)) return candidate;
            dir = Path.GetDirectoryName(dir);
        }
        return Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..", "testdata", "contract-flow-constants-vector.json"));
    }

    public static IEnumerable<object[]> Cases()
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(VectorPath()));
        foreach (var c in doc.RootElement.GetProperty("cases").EnumerateArray())
        {
            var name = c.GetProperty("name").GetString()!;
            var constants = c.GetProperty("constants").EnumerateArray().Select(Node.FromJson).ToList();
            var answers = Node.FromJson(c.GetProperty("answers")).ToObjectGraph()
                as IReadOnlyDictionary<string, object?> ?? new Dictionary<string, object?>();
            var referenceDate = c.GetProperty("reference_date").GetString()!;
            var expectJson = c.GetProperty("expect").GetRawText();
            yield return new object[] { name, constants, answers, referenceDate, expectJson };
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void VectorCase(string name, List<Node> constants,
                           IReadOnlyDictionary<string, object?> answers, string referenceDate, string expectJson)
    {
        var result = FlowCondition.ComputeConstants(constants, answers, referenceDate);
        using var expect = JsonDocument.Parse(expectJson);
        foreach (var prop in expect.RootElement.EnumerateObject())
        {
            Assert.True(result.ContainsKey(prop.Name), $"case {name}: missing constant '{prop.Name}'");
            AssertValue(name, prop.Name, result[prop.Name], prop.Value);
        }
    }

    [Fact]
    public void VectorHasAllCases()
    {
        Assert.Equal(51, Cases().Count());
    }

    // ResolvedConstants must return EXACTLY the expect map's keys — constants only, no leaked
    // answer keys — with the same values ComputeConstants produces.
    [Theory]
    [MemberData(nameof(Cases))]
    public void ResolvedConstantsVectorCase(string name, List<Node> constants,
                           IReadOnlyDictionary<string, object?> answers, string referenceDate, string expectJson)
    {
        var result = FlowCondition.ResolvedConstants(constants, answers, referenceDate);
        using var expect = JsonDocument.Parse(expectJson);
        var expectKeys = expect.RootElement.EnumerateObject().Select(p => p.Name).ToHashSet();
        var resultKeys = result.Keys.ToHashSet();
        Assert.True(expectKeys.SetEquals(resultKeys),
            $"case {name}: expected keys [{string.Join(",", expectKeys)}], got [{string.Join(",", resultKeys)}]");
        foreach (var prop in expect.RootElement.EnumerateObject())
        {
            AssertValue(name, prop.Name, result[prop.Name], prop.Value);
        }
    }

    // EvaluateFlowCondition (constants wrapper) run over the 27-case condition vector with empty
    // constants must reproduce plain condition semantics exactly.
    [Theory]
    [MemberData(nameof(FlowConditionTests.Cases), MemberType = typeof(FlowConditionTests))]
    public void EvaluateFlowConditionOverConditionVector(string name, Node condition,
                           IReadOnlyDictionary<string, object?> answers, bool expect)
    {
        var got = FlowCondition.EvaluateFlowCondition(condition, answers, new List<Node>(), null);
        Assert.True(got == expect, $"case {name}");
    }

    // JSON `expect` distinguishes null from absent; numbers are compared numerically so a double
    // math result (5.0) equals a JSON integer (5) and a long datediff (9) equals JSON 9.
    private static void AssertValue(string name, string key, object? actual, JsonElement expected)
    {
        switch (expected.ValueKind)
        {
            case JsonValueKind.Null:
                Assert.True(actual is null, $"case {name}.{key}: expected null, got {Fmt(actual)}");
                break;
            case JsonValueKind.True:
            case JsonValueKind.False:
                Assert.True(actual is bool b && b == expected.GetBoolean(),
                    $"case {name}.{key}: expected {expected.GetBoolean()}, got {Fmt(actual)}");
                break;
            case JsonValueKind.Number:
                var exp = expected.GetDouble();
                var act = AsDouble(actual);
                Assert.True(act.HasValue && act.Value == exp,
                    $"case {name}.{key}: expected {exp}, got {Fmt(actual)}");
                break;
            case JsonValueKind.String:
                Assert.True(actual is string s && s == expected.GetString(),
                    $"case {name}.{key}: expected '{expected.GetString()}', got {Fmt(actual)}");
                break;
            default:
                Assert.Fail($"case {name}.{key}: unsupported expected kind {expected.ValueKind}");
                break;
        }
    }

    private static double? AsDouble(object? v) => v switch
    {
        long l => l,
        int i => i,
        double d => d,
        float f => f,
        _ => null,
    };

    private static string Fmt(object? v) => v is null ? "null" : $"{v} ({v.GetType().Name})";
}
