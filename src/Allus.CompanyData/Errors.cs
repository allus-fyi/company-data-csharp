// Error taxonomy — the same names across all six SDKs.
//
// | Error                          | When                                              |
// |--------------------------------|---------------------------------------------------|
// | ConfigException                | Missing/invalid config or key file at construction|
// | AuthException                  | Token fetch/refresh failed (bad creds, revoked).  |
// | ApiException(status,error_key) | Any non-2xx from the API; carries status+error_key|
// | DecryptException               | Wrapper malformed, wrong key, or GCM tag mismatch.|
// | WebhookException               | Signature verification failed / envelope unwrap.  |
// | RateLimitException(retryAfter) | A 429 (subclass of ApiException); carries Retry-After.|
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
/// <see cref="ErrorKey"/> (when the body provided one), and a human-readable message.
/// </summary>
public class ApiException : Exception
{
    /// <summary>The HTTP status code (0 for a transport-level failure).</summary>
    public int Status { get; }

    /// <summary>The platform <c>error_key</c> from the body, or <c>null</c> if absent.</summary>
    public string? ErrorKey { get; }

    public ApiException(int status, string? errorKey = null, string? message = null)
        : base(BuildMessage(status, errorKey, message))
    {
        Status = status;
        ErrorKey = errorKey;
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
/// A freshly-typed value failed its field type's shape/format check (#302) before encryption.
/// Names the offending <see cref="Slug"/> and the resolved <see cref="FieldType"/>. Client
/// validation is UX, never a security boundary.
/// </summary>
public class ValidationException : Exception
{
    /// <summary>The slug (flow) or request_field_id (typed answer) of the offending value.</summary>
    public string Slug { get; }

    /// <summary>The resolved field type that the value failed.</summary>
    public string FieldType { get; }

    public ValidationException(string slug, string fieldType)
        : base($"validation error: value for \"{slug}\" is not a valid {fieldType}")
    {
        Slug = slug;
        FieldType = fieldType;
    }
}
