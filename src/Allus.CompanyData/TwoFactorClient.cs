using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Allus.CompanyData;

/// <summary>
/// #436 2FA-by-allme — a login-approval challenge returned by <see cref="TwoFactorClient.ChallengeAsync"/>
/// (spec §3). <see cref="MatchingDigits"/> is present only when the service has number matching on — the
/// two digits to DISPLAY on your login page. The person types them back into the allme app; the SERVER
/// adjudicates them (they never leave the app on any payload). Null when number matching is off.
/// </summary>
public sealed record TwoFactorChallenge(
    string ChallengeId,
    string Status,          // always "pending" on creation
    string ExpiresAt,
    string? MatchingDigits)
{
    public static TwoFactorChallenge FromApi(Node obj) => new(
        obj.Get("challenge_id").AsString() ?? "",
        obj.Get("status").AsString() ?? "",
        obj.Get("expires_at").AsString() ?? "",
        obj.Get("matching_digits").AsString());
}

/// <summary>
/// #436 2FA-by-allme — the outcome of <see cref="TwoFactorClient.ResultAsync"/> (spec §3). The poll is the
/// record: the first read of a terminal state delivers it and burns it (a later read is <c>gone</c>).
/// </summary>
public sealed record TwoFactorResult(
    string Status,       // pending | approved | denied | expired | revoked | gone
    string? ExpiresAt,   // set while pending
    string? CompletedAt) // set on a terminal outcome
{
    public static TwoFactorResult FromApi(Node obj) => new(
        obj.Get("status").AsString() ?? "",
        obj.Get("expires_at").AsString(),
        obj.Get("completed_at").AsString());
}

/// <summary>
/// #436 2FA-by-allme — the relying-party challenge API (spec §3), on the SERVICE's data-client credentials
/// (the same auth <see cref="Client"/> uses). Reached via <see cref="Client.TwoFactor"/>.
///
/// A service asks a person (by share code) to approve a login inside the allme app, then polls for the
/// outcome. The poll is the record: the first read of a terminal state delivers it and burns it. A webhook
/// (<c>2fa_challenge_completed</c>) is the best-effort push equivalent; the poll remains authoritative.
/// </summary>
public sealed class TwoFactorClient
{
    private readonly ApiHttp _http;
    // Injectable so WaitForResultAsync is unit-testable without real delays (matches ApiHttp/Client).
    private readonly Func<double, CancellationToken, Task> _sleep;

    internal TwoFactorClient(ApiHttp http, Func<double, CancellationToken, Task>? sleep = null)
    {
        _http = http;
        _sleep = sleep ?? (async (s, ct) => await Task.Delay(TimeSpan.FromSeconds(s), ct).ConfigureAwait(false));
    }

    /// <summary>Initiate a login-approval challenge for the person behind <paramref name="shareCode"/>.</summary>
    /// <param name="shareCode">The person's profile share code.</param>
    /// <param name="idempotencyKey">Required (&lt;=64); a repeat within the TTL returns the SAME challenge and sends no second push.</param>
    /// <param name="context">Plain text shown to the person (&lt;=200 chars), or null for none.</param>
    /// <param name="ct">Cancellation token.</param>
    public async Task<TwoFactorChallenge> ChallengeAsync(
        string shareCode, string idempotencyKey, string? context = null, CancellationToken ct = default)
    {
        var body = await _http.PostAsync(
            "/api/service-2fa/challenges",
            jsonBody: new Dictionary<string, object?>
            {
                ["share_code"] = shareCode,
                ["context"] = context,
                ["idempotency_key"] = idempotencyKey,
            },
            ct: ct).ConfigureAwait(false);
        return TwoFactorChallenge.FromApi(body);
    }

    /// <summary>Poll a challenge. While pending, <c>Status</c> is <c>pending</c>; the first terminal read burns it.</summary>
    public async Task<TwoFactorResult> ResultAsync(string challengeId, CancellationToken ct = default)
    {
        var body = await _http.GetAsync(
            $"/api/service-2fa/challenges/{Uri.EscapeDataString(challengeId)}", null, ct).ConfigureAwait(false);
        return TwoFactorResult.FromApi(body);
    }

    /// <summary>
    /// Poll <see cref="ResultAsync"/> until the status is terminal (no longer <c>pending</c>) and return
    /// that first terminal <see cref="TwoFactorResult"/>.
    ///
    /// Convenience over a manual <see cref="ResultAsync"/> loop (#481; mirrors the detached
    /// <c>PollResultAsync</c> precedent). Because the first terminal read burns the challenge, this returns
    /// as soon as the status leaves <c>pending</c> — it never re-reads a consumed result. Throws
    /// <see cref="ApiException"/> if <paramref name="timeoutSeconds"/> elapse while still pending;
    /// <paramref name="intervalSeconds"/> is the seconds between polls.
    /// </summary>
    public async Task<TwoFactorResult> WaitForResultAsync(
        string challengeId, int timeoutSeconds = 600, int intervalSeconds = 2, CancellationToken ct = default)
    {
        var deadline = DateTime.UtcNow.AddSeconds(timeoutSeconds);
        while (true)
        {
            var res = await ResultAsync(challengeId, ct).ConfigureAwait(false);
            if (res.Status != "pending")
                return res;
            if (DateTime.UtcNow >= deadline)
                throw new ApiException(0, null, $"2FA challenge {challengeId} not completed within {timeoutSeconds}s");
            await _sleep(intervalSeconds, ct).ConfigureAwait(false);
        }
    }
}
