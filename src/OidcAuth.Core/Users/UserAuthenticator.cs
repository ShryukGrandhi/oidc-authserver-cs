using OidcAuth.Core.Mfa;
using OidcAuth.Core.Passwords;

namespace OidcAuth.Core.Users;

public enum AuthOutcome { Success, InvalidCredentials, MfaRequired, InvalidMfa, LockedOut }

public sealed record AuthResult(AuthOutcome Outcome, UserAccount? User = null, TimeSpan RetryAfter = default)
{
    public bool Succeeded => Outcome == AuthOutcome.Success;
}

/// <summary>
/// Password + optional TOTP login. Throttles per username and per client IP independently, so a single
/// IP spraying many usernames and many IPs hammering one username are both slowed down.
/// </summary>
public sealed class UserAuthenticator
{
    private readonly InMemoryUserStore _users;
    private readonly PasswordHasher _hasher;
    private readonly Totp _totp;
    private readonly LoginThrottle _perUser;
    private readonly LoginThrottle _perIp;

    public UserAuthenticator(InMemoryUserStore users, PasswordHasher hasher, Totp totp, LoginThrottle perUser,
        LoginThrottle perIp)
    {
        _users = users;
        _hasher = hasher;
        _totp = totp;
        _perUser = perUser;
        _perIp = perIp;
    }

    public AuthResult Authenticate(string username, string password, string? totpCode, string clientIp)
    {
        string userKey = "u:" + username.ToUpperInvariant();
        string ipKey = "ip:" + clientIp;

        // Refuse before doing any password work: a locked key must not act as a guessing oracle.
        if (_perUser.IsLocked(userKey, out var wait1)) return new AuthResult(AuthOutcome.LockedOut, RetryAfter: wait1);
        if (_perIp.IsLocked(ipKey, out var wait2)) return new AuthResult(AuthOutcome.LockedOut, RetryAfter: wait2);

        var user = _users.FindByUsername(username);
        if (user is null)
        {
            _hasher.VerifyDummy(password);
            Fail(userKey, ipKey);
            return new AuthResult(AuthOutcome.InvalidCredentials);
        }

        var pw = _hasher.Verify(user.PasswordHash, password);
        if (pw == PasswordVerification.Failed)
        {
            Fail(userKey, ipKey);
            return new AuthResult(AuthOutcome.InvalidCredentials);
        }
        if (pw == PasswordVerification.SuccessRehashNeeded) user.PasswordHash = _hasher.Hash(password);

        if (user.TotpSecret is { } secret)
        {
            if (string.IsNullOrEmpty(totpCode)) return new AuthResult(AuthOutcome.MfaRequired, user);
            long last = user.LastTotpCounter;
            long? step = _totp.Verify(secret, totpCode, last);
            if (step is null || !user.TryConsumeTotpCounter(last, step.Value))
            {
                Fail(userKey, ipKey);
                return new AuthResult(AuthOutcome.InvalidMfa);
            }
        }

        _perUser.RecordSuccess(userKey);
        return new AuthResult(AuthOutcome.Success, user);
    }

    private void Fail(string userKey, string ipKey)
    {
        _perUser.RecordFailure(userKey);
        _perIp.RecordFailure(ipKey);
    }
}
