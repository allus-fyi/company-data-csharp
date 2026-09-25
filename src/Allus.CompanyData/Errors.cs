// Error taxonomy — the same names across all six SDKs.
//
// | Error                          | When                                              |
// |--------------------------------|---------------------------------------------------|
// | ConfigException                | Missing/invalid config or key file at construction|
// | AuthException                  | Token fetch/refresh failed (bad creds, revoked).  |
// | ApiException(status,error_key) | Any non-2xx; status + error_key + the body's other fields |
// | DecryptException               | Wrapper malformed, wrong key, or GCM tag mismatch.|
// | WebhookException               | Signature verification failed / envelope unwrap.  |
// | RateLimitException(retryAfter) | A 429 (subclass of ApiException); carries Retry-After.|
// | ValidationException            | A value fails its type's check, or a flow field's min/max. |
// | PluginInputUnavailableException| A required plugin input cannot be sent.           |
//
// Idiomatic C#: every error is an Exception subclass with the "Exception" suffix.

namespace Allus.CompanyData;

/// <summary>
/// Missing or invalid configuration (or key file) at construction (fail fast).
/// </summary>
public class ConfigException : Exception
{
    public ConfigException(string message) : base(message) { }
    public ConfigException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// The <c>client_credentials</c> token fetch or refresh failed. Raised when
/// <c>/oauth2/token</c> rejects the credentials, or a 401 mid-flight survives the one automatic
/// refresh-and-retry.
/// </summary>
public class AuthException : Exception
{
    public AuthException(string message) : base(message) { }
    public AuthException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// Any non-2xx from the API. Carries the HTTP <see cref="Status"/>, the platform
/// <see cref="ErrorKey"/> (when the body provided one), a human-readable message, and the error
/// body's remaining fields as <see cref="Details"/>.
/// </summary>
public class ApiException : Exception
{
    private static readonly IReadOnlyDictionary<string, object?> NoDetails =
        new Dictionary<string, object?>();

    /// <summary>The HTTP status code (0 for a transport-level failure).</summary>
    public int Status { get; }

    /// <summary>The platform <c>error_key</c> from the body, or <c>null</c> if absent.</summary>
    public string? ErrorKey { get; }

    /// <summary>
    /// The error body's remaining fields, verbatim (empty when the body carried none).
    /// <para>A 410 <c>company_data.file_expired</c> is the first response that carries actionable data
    /// BESIDE the key: it returns the expired answer's <c>content_sha256</c> and
    /// <c>expired_at</c>, so a consumer can record that its archived copy is now the only one and
    /// still prove what it holds. Generic rather than a bespoke subclass — every error body's extra
    /// fields become reachable, and no future one needs a new exception type to be readable.</para>
    /// </summary>
    public IReadOnlyDictionary<string, object?> Details { get; }

    public ApiException(
        int status,
        string? errorKey = null,
        string? message = null,
        IReadOnlyDictionary<string, object?>? details = null)
        : base(BuildMessage(status, errorKey, message))
    {
        Status = status;
        ErrorKey = errorKey;
        Details = details ?? NoDetails;
    }

    private static string BuildMessage(int status, string? errorKey, string? message)
    {
        var parts = new List<string> { $"HTTP {status}" };
        if (!string.IsNullOrEmpty(errorKey)) parts.Add($"({errorKey})");
        if (!string.IsNullOrEmpty(message)) parts.Add($": {message}");
        return string.Join(" ", parts);
    }
}

/// <summary>
/// A 429 from a rate-limited endpoint. Subclass of <see cref="ApiException"/> with a
/// fixed status of 429; carries the <see cref="RetryAfter"/> seconds parsed from the
/// <c>Retry-After</c> header (or <c>null</c> when absent).
/// </summary>
public sealed class RateLimitException : ApiException
{
    /// <summary>Parsed <c>Retry-After</c> in seconds, or <c>null</c> when not supplied.</summary>
    public double? RetryAfter { get; }

    public RateLimitException(double? retryAfter = null, string? errorKey = null, string? message = null)
        : base(429, errorKey, message)
    {
        RetryAfter = retryAfter;
    }
}

/// <summary>
/// Wrapper malformed, wrong key, or GCM tag mismatch. Raised by the decryption core.
/// </summary>
public class DecryptException : Exception
{
    public DecryptException(string message) : base(message) { }
    public DecryptException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// Signature verification failed, or a webhook envelope couldn't be unwrapped.
/// </summary>
public class WebhookException : Exception
{
    public WebhookException(string message) : base(message) { }
    public WebhookException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// A freshly-typed value failed its field type's shape/format check before encryption.
/// Names the offending <see cref="Slug"/> and the resolved <see cref="FieldType"/>. Client
/// validation is UX, never a security boundary.
/// </summary>
public class ValidationException : Exception
{
    /// <summary>The slug (flow) or request_field_id (typed answer) of the offending value.</summary>
    public string Slug { get; }

    /// <summary>The resolved field type that the value failed.</summary>
    public string FieldType { get; }

    /// <summary>"min" or "max" when a flow value lies outside its field's bound; null otherwise.</summary>
    public string? Bound { get; }

    /// <summary>The bound the value broke (a number or a YYYY-MM-DD date); null when <see cref="Bound"/> is.</summary>
    public object? BoundValue { get; }

    public ValidationException(string slug, string fieldType)
        : base($"validation error: value for \"{slug}\" is not a valid {fieldType}")
    {
        Slug = slug;
        FieldType = fieldType;
    }

    /// <summary>A flow value outside its field's minimum (<paramref name="bound"/> "min") or maximum ("max").</summary>
    public ValidationException(string slug, string fieldType, string bound, object? boundValue)
        : base(bound == "min"
            ? $"validation error: value for \"{slug}\" is below its minimum {FlowCondition.StringOf(boundValue)}"
            : $"validation error: value for \"{slug}\" is above its maximum {FlowCondition.StringOf(boundValue)}")
    {
        Slug = slug;
        FieldType = fieldType;
        Bound = bound;
        BoundValue = boundValue;
    }
}

/// <summary>
/// A required plugin input cannot be sent. <see cref="Input"/> names the plugin's input key,
/// <see cref="Source"/> the key it is wired to (null when unwired) and <see cref="Reason"/> says why —
/// checked in this order: <see cref="Unwired"/>, <see cref="Unanswered"/>,
/// <see cref="OtherPartyPrivate"/>, <see cref="NotConvertible"/>.
/// </summary>
public class PluginInputUnavailableException : Exception
{
    /// <summary>The company wired no source to the input.</summary>
    public const string Unwired = "unwired";

    /// <summary>The input's source has no value yet.</summary>
    public const string Unanswered = "unanswered";

    /// <summary>The source is another party's private value, which is never sent to a plugin.</summary>
    public const string OtherPartyPrivate = "other_party_private";

    /// <summary>The source's value does not convert to the input's declared type.</summary>
    public const string NotConvertible = "not_convertible";

    /// <summary>The plugin's input key.</summary>
    public string Input { get; }

    /// <summary>The key the input is wired to, or null when it is unwired.</summary>
    public string? Source { get; }

    /// <summary>Why the input is unavailable.</summary>
    public string Reason { get; }

    public PluginInputUnavailableException(string input, string? source, string reason)
        : base($"plugin input \"{input}\" is unavailable: " + reason switch
        {
            Unwired => "no source is wired to it",
            Unanswered => "its source has no value yet",
            OtherPartyPrivate => "its source is another party's private value",
            NotConvertible => "its source's value does not convert to the input's type",
            _ => reason,
        })
    {
        Input = input;
        Source = source;
        Reason = reason;
    }
}
