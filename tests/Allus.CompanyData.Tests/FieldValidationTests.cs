// Field-type registry parity — every case in the shared vector must match. The vector's `registry`
// member is the row set every case is resolved against.

using System.Text.Json;
using Allus.CompanyData;
using Xunit;

namespace Allus.CompanyData.Tests;

public sealed class FieldValidationTests
{
    internal static string VectorPath()
    {
        var dir = AppContext.BaseDirectory;
        for (var i = 0; i < 8 && dir is not null; i++)
        {
            var candidate = Path.Combine(dir, "testdata", "contract-field-validation-vector.json");
            if (File.Exists(candidate)) return candidate;
            dir = Path.GetDirectoryName(dir);
        }
        return Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..", "testdata", "contract-field-validation-vector.json"));
    }

    private static Node Vector() => Node.FromJsonString(File.ReadAllText(VectorPath()));

    /// <summary>The vector's own registry — the rows every case is resolved against.</summary>
    internal static FieldTypeRegistry Registry() => new(Vector().Get("registry"));

    /// <summary>The same rows as a served GET /api/contact-field-types body.</summary>
    internal static string RegistryBody()
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(VectorPath()));
        return doc.RootElement.GetProperty("registry").GetRawText();
    }

    public static IEnumerable<object[]> Cases()
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(VectorPath()));
        foreach (var c in doc.RootElement.GetProperty("cases").EnumerateArray())
        {
            var name = c.GetProperty("name").GetString()!;
            var type = c.GetProperty("type").GetString()!;
            var value = c.GetProperty("value").GetString()!;
            // `options` is the caller's own option list, present only on a choice case.
            IReadOnlyList<string>? options = c.TryGetProperty("options", out var opts)
                ? opts.EnumerateArray().Select(o => o.GetString() ?? "").ToList()
                : null;
            var valid = c.GetProperty("valid").GetBoolean();
            yield return new object[] { name, type, value, options!, valid };
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void VectorCase(string name, string type, string value, IReadOnlyList<string>? options, bool valid)
    {
        Assert.True(Registry().IsFieldValueValid(type, value, options) == valid, $"case {name}");
    }

    [Fact]
    public void VectorHasCases()
    {
        Assert.True(Cases().Count() > 0);
    }

    [Fact]
    public void ResolveCases()
    {
        var registry = Registry();
        using var doc = JsonDocument.Parse(File.ReadAllText(VectorPath()));
        foreach (var c in doc.RootElement.GetProperty("resolve_cases").EnumerateArray())
        {
            var name = c.GetProperty("name").GetString()!;
            var want = c.GetProperty("resolved");
            var got = registry.Resolve(c.GetProperty("type").GetString());
            Assert.Equal(want.GetProperty("type").GetString(), got.Type);
            Assert.Equal(NullableString(want, "parent"), got.Parent);
            Assert.Equal(want.GetProperty("label").GetString(), got.Label);
            Assert.Equal(want.GetProperty("is_system").GetBoolean(), got.IsSystem);
            Assert.Equal(want.GetProperty("known").GetBoolean(), got.Known);
            Assert.Equal(NullableString(want, "input"), got.Input);
            Assert.Equal(NullableString(want, "lane"), got.Lane);
            Assert.Equal(NullableString(want, "check"), got.Check);
            var wantValidations = want.GetProperty("validations").EnumerateArray()
                .Select(v => v.GetString()!).ToList();
            Assert.True(wantValidations.SequenceEqual(got.Validations), name);
        }
    }

    private static string? NullableString(JsonElement obj, string key) =>
        obj.GetProperty(key).ValueKind == JsonValueKind.Null ? null : obj.GetProperty(key).GetString();

    [Fact]
    public void AcceptsCases()
    {
        var registry = Registry();
        using var doc = JsonDocument.Parse(File.ReadAllText(VectorPath()));
        foreach (var c in doc.RootElement.GetProperty("accepts_cases").EnumerateArray())
        {
            var got = registry.Accepts(
                c.GetProperty("requested").GetString()!, c.GetProperty("actual").GetString()!);
            Assert.True(got == c.GetProperty("accepts").GetBoolean(), c.GetProperty("name").GetString());
        }
    }

    [Fact]
    public void OrderedCases()
    {
        var registry = Registry();
        using var doc = JsonDocument.Parse(File.ReadAllText(VectorPath()));
        foreach (var c in doc.RootElement.GetProperty("ordered_cases").EnumerateArray())
        {
            var types = c.GetProperty("types").EnumerateArray().Select(t => t.GetString()!).ToList();
            var want = c.GetProperty("ordered").EnumerateArray().Select(t => t.GetString()!).ToList();
            Assert.True(want.SequenceEqual(registry.Ordered(types)), c.GetProperty("name").GetString());
        }
    }

    [Fact]
    public void EffectiveTypeCases()
    {
        var registry = Registry();
        using var doc = JsonDocument.Parse(File.ReadAllText(VectorPath()));
        foreach (var c in doc.RootElement.GetProperty("effective_type_cases").EnumerateArray())
        {
            Assert.Equal(
                c.GetProperty("effective_type").GetString(),
                registry.EffectiveType(c.GetProperty("type").GetString()!));
        }
    }

    [Fact]
    public void DerivedSets()
    {
        var registry = Registry();
        using var doc = JsonDocument.Parse(File.ReadAllText(VectorPath()));
        var sets = doc.RootElement.GetProperty("derived_sets");
        Assert.True(sets.GetProperty("requestable_types").EnumerateArray().Select(t => t.GetString()!)
            .SequenceEqual(registry.RequestableTypes()));
        Assert.True(sets.GetProperty("flow_types").EnumerateArray().Select(t => t.GetString()!)
            .SequenceEqual(registry.FlowTypes()));
        Assert.True(sets.GetProperty("claimable_types").EnumerateArray().Select(t => t.GetString()!)
            .SequenceEqual(registry.ClaimableTypes()));
    }
}
