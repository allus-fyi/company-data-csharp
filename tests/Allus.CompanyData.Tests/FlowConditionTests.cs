// FlowConditionEvaluator parity — every case in the shared vector must pass. The same vector pins
// the PHP reference + the python/ts/go/iOS/Android ports.

using System.Text.Json;
using Allus.CompanyData;
using Xunit;

namespace Allus.CompanyData.Tests;

public sealed class FlowConditionTests
{
    private static string VectorPath()
    {
        var dir = AppContext.BaseDirectory;
        for (var i = 0; i < 8 && dir is not null; i++)
        {
            var candidate = Path.Combine(dir, "testdata", "contract-flow-condition-vector.json");
            if (File.Exists(candidate)) return candidate;
            dir = Path.GetDirectoryName(dir);
        }
        return Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..", "testdata", "contract-flow-condition-vector.json"));
    }

    public static IEnumerable<object[]> Cases()
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(VectorPath()));
        foreach (var c in doc.RootElement.GetProperty("cases").EnumerateArray())
        {
            var name = c.GetProperty("name").GetString()!;
            var condition = Node.FromJson(c.GetProperty("condition"));
            var answersGraph = Node.FromJson(c.GetProperty("answers")).ToObjectGraph()
                as IReadOnlyDictionary<string, object?> ?? new Dictionary<string, object?>();
            var expect = c.GetProperty("expect").GetBoolean();
            yield return new object[] { name, condition, answersGraph, expect };
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void VectorCase(string name, Node condition, IReadOnlyDictionary<string, object?> answers, bool expect)
    {
        Assert.True(FlowCondition.Evaluate(condition, answers) == expect, $"case {name}");
    }

    [Fact]
    public void VectorHasAllCases()
    {
        Assert.Equal(35, Cases().Count());
    }
}
