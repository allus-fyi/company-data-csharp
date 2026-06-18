// Configuration loading.
//
// Config-only key handling is a hard rule: no SDK method ever takes a key, passphrase, or secret
// as an argument. Everything cryptographic — decrypting the service PEM, decrypting field values,
// verifying the webhook HMAC, unwrapping the account-key envelope — is driven entirely by this
// config. A single JSON file holds everything; any field may be overridden by an ALLUS_* env var,
// so secrets needn't live in the file.

using System.Text.Json;

namespace Allus.CompanyData;

/// <summary>HTTP-Basic webhook credentials (<c>"webhook_basic"</c>).</summary>
public sealed record WebhookBasicAuth(string Username, string Password);

/// <summary>A custom-header webhook credential (<c>"webhook_header"</c>).</summary>
public sealed record WebhookHeaderAuth(string Name, string Value);

/// <summary>
/// The whole SDK configuration. Keys live here and nowhere else.
/// </summary>
public sealed class Config
{
    // ── ALLUS_* env-var overrides (scalar fields) ──────────────────────────────────────────────
    private static readonly (string Field, string Env)[] EnvMap =
    {
        (nameof(ApiUrl), "ALLUS_API_URL"),
        (nameof(ClientId), "ALLUS_CLIENT_ID"),
        (nameof(ClientSecret), "ALLUS_CLIENT_SECRET"),
        (nameof(ServicePrivateKey), "ALLUS_SERVICE_PRIVATE_KEY"),
        (nameof(KeyPassphrase), "ALLUS_KEY_PASSPHRASE"),
        (nameof(AccountPrivateKey), "ALLUS_ACCOUNT_PRIVATE_KEY"),
        (nameof(AccountPassphrase), "ALLUS_ACCOUNT_PASSPHRASE"),
        (nameof(CacheDir), "ALLUS_CACHE_DIR"),
        (nameof(Format), "ALLUS_FORMAT"),
    };

    private const string WebhookSecretEnv = "ALLUS_WEBHOOK_SECRET";

    /// <summary>Reserved webhook-map key under which a flat <c>"webhook_secret"</c> is stored.</summary>
    public const string SingleWebhookKey = "__single__";

    private static readonly string[] ValidFormats = { "json", "xml" };

    // ── fields ─────────────────────────────────────────────────────────────────────────────────

    /// <summary>API base URL, e.g. <c>https://api.allme.fyi</c>.</summary>
    public required string ApiUrl { get; init; }

    /// <summary>The registered service client id.</summary>
    public required string ClientId { get; init; }

    /// <summary>The registered service client secret.</summary>
    public required string ClientSecret { get; init; }

    /// <summary>Path to the OpenSSL-encrypted PKCS#8 service private-key PEM.</summary>
    public required string ServicePrivateKey { get; init; }

    /// <summary>Passphrase that decrypts the service PEM in memory.</summary>
    public required string KeyPassphrase { get; init; }

    /// <summary>OPTIONAL — only needed for <c>encrypt_payload</c> webhooks.</summary>
    public string? AccountPrivateKey { get; init; }

    /// <summary>OPTIONAL — passphrase for the account PEM.</summary>
    public string? AccountPassphrase { get; init; }

    /// <summary>
    /// Per-webhook HMAC secrets keyed by webhook id (matched via <c>X-Allus-Webhook-Id</c>). A
    /// single-webhook service can use the flat <c>"webhook_secret"</c> shortcut, stored under
    /// <see cref="SingleWebhookKey"/>.
    /// </summary>
    public IReadOnlyDictionary<string, string> Webhooks { get; init; } =
        new Dictionary<string, string>();

    /// <summary>
    /// OPTIONAL — alternative webhook auth methods, mirroring the platform's per-webhook delivery
    /// auth. Configure AT MOST ONE family among
    /// hmac (<see cref="Webhooks"/>/<c>webhook_secret</c>) | bearer | basic | header | none;
    /// two or more → <see cref="ConfigException"/>. See <see cref="WebhookAuthMethod"/>.
    /// <c>"Authorization: Bearer &lt;token&gt;"</c>.
    /// </summary>
    public string? WebhookBearerToken { get; init; }

    /// <summary>OPTIONAL — <c>{"username","password"}</c> → HTTP-Basic <c>Authorization</c> auth.</summary>
    public WebhookBasicAuth? WebhookBasic { get; init; }

    /// <summary>OPTIONAL — <c>{"name","value"}</c> → a custom-header credential.</summary>
    public WebhookHeaderAuth? WebhookHeader { get; init; }

    /// <summary>OPTIONAL — explicit opt-out: verify is always <c>true</c>.</summary>
    public bool WebhookAuthNone { get; init; }

    /// <summary>Durable local buffer dir for the changes pump.</summary>
    public string CacheDir { get; init; } = "./allus-cache";

    /// <summary>Wire format <c>json</c>|<c>xml</c> (default json) — invisible in the output.</summary>
    public string Format { get; init; } = "json";

    // ── construction (config-only keys) ─────────────────────────────────────────────────────────

    /// <summary>Load from a JSON file; env vars override file values.</summary>
    public static Config FromFile(string path)
    {
        string text;
        try
        {
            text = File.ReadAllText(path);
        }
        catch (FileNotFoundException ex)
        {
            throw new ConfigException($"config file not found: {path}", ex);
        }
        catch (DirectoryNotFoundException ex)
        {
            throw new ConfigException($"config file not found: {path}", ex);
        }
        catch (IOException ex)
        {
            throw new ConfigException($"could not read config file: {path}: {ex.Message}", ex);
        }

        JsonElement root;
        try
        {
            using var doc = JsonDocument.Parse(text);
            root = doc.RootElement.Clone();
        }
        catch (JsonException ex)
        {
            throw new ConfigException($"config file is not valid JSON: {path}: {ex.Message}", ex);
        }

        if (root.ValueKind != JsonValueKind.Object)
            throw new ConfigException($"config file must be a JSON object: {path}");

        return Build(root);
    }

    /// <summary>Build entirely from <c>ALLUS_*</c> env vars.</summary>
    public static Config FromEnv() => Build(null);

    private static Config Build(JsonElement? data)
    {
        // Scalar fields: env var (if set) overrides the file value.
        var values = new Dictionary<string, string>();
        foreach (var (field, env) in EnvMap)
        {
            var envVal = Environment.GetEnvironmentVariable(env);
            if (envVal is not null)
            {
                values[field] = envVal;
            }
            else if (data is { } d && d.TryGetProperty(JsonKey(field), out var prop)
                     && prop.ValueKind is not (JsonValueKind.Null or JsonValueKind.Undefined))
            {
                values[field] = prop.ValueKind == JsonValueKind.String
                    ? prop.GetString()!
                    : prop.GetRawText();
            }
        }

        // Webhook secrets: the "webhooks" map plus the flat "webhook_secret" shortcut.
        var webhooks = new Dictionary<string, string>();
        if (data is { } dd && dd.TryGetProperty("webhooks", out var whProp)
            && whProp.ValueKind is not (JsonValueKind.Null or JsonValueKind.Undefined))
        {
            if (whProp.ValueKind != JsonValueKind.Object)
                throw new ConfigException("\"webhooks\" must be an object mapping webhook id -> secret");
            foreach (var pair in whProp.EnumerateObject())
                webhooks[pair.Name] = pair.Value.ValueKind == JsonValueKind.String
                    ? pair.Value.GetString()!
                    : pair.Value.GetRawText();
        }

        var flatSecret = Environment.GetEnvironmentVariable(WebhookSecretEnv);
        if (flatSecret is null && data is { } d3 && d3.TryGetProperty("webhook_secret", out var fp)
            && fp.ValueKind is not (JsonValueKind.Null or JsonValueKind.Undefined))
        {
            flatSecret = fp.ValueKind == JsonValueKind.String ? fp.GetString() : fp.GetRawText();
        }
        if (flatSecret is not null)
            webhooks[SingleWebhookKey] = flatSecret;

        // Alternative webhook auth methods (file-config only — no env overrides). Validate shapes.
        string? bearer = null;
        if (data is { } d4 && d4.TryGetProperty("webhook_bearer_token", out var bp)
            && bp.ValueKind is not (JsonValueKind.Null or JsonValueKind.Undefined))
        {
            var s = bp.ValueKind == JsonValueKind.String ? bp.GetString() : bp.GetRawText();
            if (!string.IsNullOrEmpty(s)) bearer = s;
        }

        WebhookBasicAuth? basicAuth = null;
        if (data is { } d5 && d5.TryGetProperty("webhook_basic", out var basicProp)
            && basicProp.ValueKind is not (JsonValueKind.Null or JsonValueKind.Undefined))
        {
            var username = ObjString(basicProp, "username");
            var password = ObjString(basicProp, "password");
            if (basicProp.ValueKind != JsonValueKind.Object
                || string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
                throw new ConfigException(
                    "\"webhook_basic\" must be an object with non-empty \"username\" and \"password\"");
            basicAuth = new WebhookBasicAuth(username!, password!);
        }

        WebhookHeaderAuth? headerAuth = null;
        if (data is { } d6 && d6.TryGetProperty("webhook_header", out var hdrProp)
            && hdrProp.ValueKind is not (JsonValueKind.Null or JsonValueKind.Undefined))
        {
            var name = ObjString(hdrProp, "name");
            var value = ObjString(hdrProp, "value");
            if (hdrProp.ValueKind != JsonValueKind.Object
                || string.IsNullOrEmpty(name) || string.IsNullOrEmpty(value))
                throw new ConfigException(
                    "\"webhook_header\" must be an object with non-empty \"name\" and \"value\"");
            headerAuth = new WebhookHeaderAuth(name!, value!);
        }

        var authNone = data is { } d7 && d7.TryGetProperty("webhook_auth_none", out var noneProp)
            && noneProp.ValueKind == JsonValueKind.True;

        // At most one webhook auth FAMILY may be configured (multiple HMAC entries is still one).
        var present = new List<string>();
        if (webhooks.Count > 0) present.Add("hmac");
        if (bearer is not null) present.Add("bearer");
        if (basicAuth is not null) present.Add("basic");
        if (headerAuth is not null) present.Add("header");
        if (authNone) present.Add("none");
        if (present.Count > 1)
            throw new ConfigException(
                "configure at most one webhook auth method (found: " + string.Join(", ", present) + ")");

        // Required fields (fail fast).
        var required = new[]
        {
            nameof(ApiUrl), nameof(ClientId), nameof(ClientSecret),
            nameof(ServicePrivateKey), nameof(KeyPassphrase),
        };
        var missing = required
            .Where(r => !values.TryGetValue(r, out var v) || string.IsNullOrEmpty(v))
            .Select(JsonKey)
            .ToList();
        if (missing.Count > 0)
            throw new ConfigException("missing required config field(s): " + string.Join(", ", missing));

        // Validate the wire format if supplied.
        var format = values.GetValueOrDefault(nameof(Format), "json").ToLowerInvariant();
        if (!ValidFormats.Contains(format))
            throw new ConfigException($"invalid \"format\": '{format}' (expected one of json, xml)");

        return new Config
        {
            ApiUrl = values[nameof(ApiUrl)],
            ClientId = values[nameof(ClientId)],
            ClientSecret = values[nameof(ClientSecret)],
            ServicePrivateKey = values[nameof(ServicePrivateKey)],
            KeyPassphrase = values[nameof(KeyPassphrase)],
            AccountPrivateKey = values.GetValueOrDefault(nameof(AccountPrivateKey)),
            AccountPassphrase = values.GetValueOrDefault(nameof(AccountPassphrase)),
            Webhooks = webhooks,
            WebhookBearerToken = bearer,
            WebhookBasic = basicAuth,
            WebhookHeader = headerAuth,
            WebhookAuthNone = authNone,
            CacheDir = values.GetValueOrDefault(nameof(CacheDir), "./allus-cache"),
            Format = format,
        };
    }

    // Read a string sub-field from a JSON object (any non-string scalar is stringified, matching
    // Python's str() coercion); null/missing/non-object yields null.
    private static string? ObjString(JsonElement obj, string name)
    {
        if (obj.ValueKind != JsonValueKind.Object) return null;
        if (!obj.TryGetProperty(name, out var prop)) return null;
        if (prop.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined) return null;
        return prop.ValueKind == JsonValueKind.String ? prop.GetString() : prop.GetRawText();
    }

    /// <summary>
    /// Resolve the HMAC secret for a webhook id. Falls back to the single-webhook
    /// shortcut secret when there is no id or no id-specific match. The webhook helpers read this —
    /// application code never passes a secret in.
    /// </summary>
    public string? WebhookSecret(string? webhookId = null)
    {
        if (webhookId is not null && Webhooks.TryGetValue(webhookId, out var byId))
            return byId;
        return Webhooks.TryGetValue(SingleWebhookKey, out var flat) ? flat : null;
    }

    /// <summary>
    /// The single configured webhook auth method, or <c>null</c> if none is set. Returns one of
    /// <c>"hmac"</c> | <c>"bearer"</c> | <c>"basic"</c> | <c>"header"</c> | <c>"none"</c>. Config
    /// loading guarantees at most one is configured, so the order here is only a tie-break that
    /// never triggers.
    /// </summary>
    public string? WebhookAuthMethod()
    {
        if (WebhookAuthNone) return "none";
        if (!string.IsNullOrEmpty(WebhookBearerToken)) return "bearer";
        if (WebhookBasic is not null) return "basic";
        if (WebhookHeader is not null) return "header";
        if (Webhooks.Count > 0) return "hmac";
        return null;
    }

    // Map a C# property name to its snake_case JSON/env key (the source-of-truth for messages).
    private static string JsonKey(string field) => field switch
    {
        nameof(ApiUrl) => "api_url",
        nameof(ClientId) => "client_id",
        nameof(ClientSecret) => "client_secret",
        nameof(ServicePrivateKey) => "service_private_key",
        nameof(KeyPassphrase) => "key_passphrase",
        nameof(AccountPrivateKey) => "account_private_key",
        nameof(AccountPassphrase) => "account_passphrase",
        nameof(CacheDir) => "cache_dir",
        nameof(Format) => "format",
        _ => field,
    };
}
