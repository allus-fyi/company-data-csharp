// Config loader tests.

using System.Text.Json;
using Allus.CompanyData;
using Xunit;

namespace Allus.CompanyData.Tests;

public class ConfigTests : IDisposable
{
    private readonly string _dir;
    // Track env vars we set so we can clear them after each test (env is process-global).
    private readonly List<string> _setEnv = new();

    public ConfigTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "allus-cfg-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        foreach (var k in _setEnv) Environment.SetEnvironmentVariable(k, null);
        Directory.Delete(_dir, true);
    }

    private void SetEnv(string key, string? value)
    {
        Environment.SetEnvironmentVariable(key, value);
        _setEnv.Add(key);
    }

    private string Write(object data)
    {
        var p = Path.Combine(_dir, "config.json");
        File.WriteAllText(p, JsonSerializer.Serialize(data));
        return p;
    }

    private static Dictionary<string, object?> Full() => new()
    {
        ["api_url"] = "https://api.allme.fyi",
        ["client_id"] = "svc_abc",
        ["client_secret"] = "file-secret",
        ["service_private_key"] = "./service-CRM.pem",
        ["key_passphrase"] = "file-passphrase",
        ["account_private_key"] = "./account.pem",
        ["account_passphrase"] = "acct-pass",
        ["webhooks"] = new Dictionary<string, string> { ["wh_1"] = "secret-one", ["wh_2"] = "secret-two" },
        ["cache_dir"] = "./allus-cache",
        ["format"] = "json",
    };

    [Fact]
    public void FromFileLoadsAllFields()
    {
        var cfg = Config.FromFile(Write(Full()));
        Assert.Equal("https://api.allme.fyi", cfg.ApiUrl);
        Assert.Equal("svc_abc", cfg.ClientId);
        Assert.Equal("file-secret", cfg.ClientSecret);
        Assert.Equal("./service-CRM.pem", cfg.ServicePrivateKey);
        Assert.Equal("file-passphrase", cfg.KeyPassphrase);
        Assert.Equal("./account.pem", cfg.AccountPrivateKey);
        Assert.Equal("acct-pass", cfg.AccountPassphrase);
        Assert.Equal("./allus-cache", cfg.CacheDir);
        Assert.Equal("json", cfg.Format);
        Assert.Equal("secret-one", cfg.WebhookSecret("wh_1"));
        Assert.Equal("secret-two", cfg.WebhookSecret("wh_2"));
    }

    [Fact]
    public void OptionalFieldsDefault()
    {
        var cfg = Config.FromFile(Write(new Dictionary<string, object?>
        {
            ["api_url"] = "https://api.allme.fyi",
            ["client_id"] = "svc_abc",
            ["client_secret"] = "s",
            ["service_private_key"] = "./k.pem",
            ["key_passphrase"] = "p",
        }));
        Assert.Null(cfg.AccountPrivateKey);
        Assert.Null(cfg.AccountPassphrase);
        Assert.Empty(cfg.Webhooks);
        Assert.Equal("./allus-cache", cfg.CacheDir);
        Assert.Equal("json", cfg.Format);
    }

    [Fact]
    public void EnvOverridesFileValues()
    {
        var path = Write(Full());
        SetEnv("ALLUS_CLIENT_SECRET", "env-secret");
        SetEnv("ALLUS_KEY_PASSPHRASE", "env-passphrase");
        SetEnv("ALLUS_API_URL", "https://api-eu.allme.fyi");
        var cfg = Config.FromFile(path);
        Assert.Equal("env-secret", cfg.ClientSecret);
        Assert.Equal("env-passphrase", cfg.KeyPassphrase);
        Assert.Equal("https://api-eu.allme.fyi", cfg.ApiUrl);
        Assert.Equal("svc_abc", cfg.ClientId); // from file (no env)
    }

    [Fact]
    public void FromEnvBuildsWithoutAFile()
    {
        SetEnv("ALLUS_API_URL", "https://api.allme.fyi");
        SetEnv("ALLUS_CLIENT_ID", "svc_env");
        SetEnv("ALLUS_CLIENT_SECRET", "env-secret");
        SetEnv("ALLUS_SERVICE_PRIVATE_KEY", "./k.pem");
        SetEnv("ALLUS_KEY_PASSPHRASE", "env-pass");
        var cfg = Config.FromEnv();
        Assert.Equal("svc_env", cfg.ClientId);
        Assert.Equal("env-secret", cfg.ClientSecret);
    }

    [Fact]
    public void MissingRequiredFieldThrowsConfigException()
    {
        var data = Full();
        data.Remove("client_secret");
        var ex = Assert.Throws<ConfigException>(() => Config.FromFile(Write(data)));
        Assert.Contains("client_secret", ex.Message);
    }

    [Fact]
    public void MissingFileThrowsConfigException()
    {
        Assert.Throws<ConfigException>(() => Config.FromFile(Path.Combine(_dir, "does-not-exist.json")));
    }

    [Fact]
    public void InvalidJsonThrowsConfigException()
    {
        var p = Path.Combine(_dir, "bad.json");
        File.WriteAllText(p, "{ not valid json");
        Assert.Throws<ConfigException>(() => Config.FromFile(p));
    }

    [Fact]
    public void InvalidFormatThrowsConfigException()
    {
        var data = Full();
        data["format"] = "yaml";
        Assert.Throws<ConfigException>(() => Config.FromFile(Write(data)));
    }

    [Fact]
    public void FlatWebhookSecretShortcut()
    {
        var cfg = Config.FromFile(Write(new Dictionary<string, object?>
        {
            ["api_url"] = "https://api.allme.fyi",
            ["client_id"] = "svc_abc",
            ["client_secret"] = "s",
            ["service_private_key"] = "./k.pem",
            ["key_passphrase"] = "p",
            ["webhook_secret"] = "the-only-secret",
        }));
        // No id, or an unknown id, falls back to the single-webhook secret.
        Assert.Equal("the-only-secret", cfg.WebhookSecret());
        Assert.Equal("the-only-secret", cfg.WebhookSecret("anything"));
    }

    [Fact]
    public void NoKeyOrSecretIsEverAMethodArgument()
    {
        // Config-only key handling: the only crypto-adjacent method, WebhookSecret(),
        // takes a webhook *id* — never a secret/key/passphrase.
        var method = typeof(Config).GetMethod(nameof(Config.WebhookSecret))!;
        var paramNames = method.GetParameters().Select(p => p.Name).ToArray();
        Assert.Equal(new[] { "webhookId" }, paramNames);
    }
}
