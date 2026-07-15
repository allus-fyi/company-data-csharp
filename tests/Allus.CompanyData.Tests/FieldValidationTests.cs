// Field-type validation parity — every case in the shared vector must match. The same vector pins
// the web reference + the allus/iOS/Android/other-SDK ports.

using System.Text.Json;
using Allus.CompanyData;
using Xunit;

namespace Allus.CompanyData.Tests;

public sealed class FieldValidationTests
{
    private static string VectorPath()
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

    public static IEnumerable<object[]> Cases()
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(VectorPath()));
        foreach (var c in doc.RootElement.GetProperty("cases").EnumerateArray())
        {
            var name = c.GetProperty("name").GetString()!;
            var type = c.GetProperty("type").GetString()!;
            var value = c.GetProperty("value").GetString()!;
            var valid = c.GetProperty("valid").GetBoolean();
            yield return new object[] { name, type, value, valid };
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void VectorCase(string name, string type, string value, bool valid)
    {
        Assert.True(FieldValidation.IsValid(type, value) == valid, $"case {name}");
    }

    [Fact]
    public void VectorHasCases()
    {
        Assert.True(Cases().Count() > 0);
    }
}
