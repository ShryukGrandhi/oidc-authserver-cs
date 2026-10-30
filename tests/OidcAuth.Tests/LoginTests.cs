using OidcAuth.Core.Mfa;
using OidcAuth.Core.Passwords;
using OidcAuth.Core.Users;

namespace OidcAuth.Tests;

public class LoginThrottleTests
{
    [Fact]
    public void Locks_after_free_attempts_with_exponential_backoff()
    {
        var time = new ManualTime();
        var t = new LoginThrottle(time, freeAttempts: 3, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(60), TimeSpan.FromHours(1));
        t.RecordFailure("k");
        t.RecordFailure("k");
        Assert.False(t.IsLocked("k", out _));

        t.RecordFailure("k"); // 3rd: 2s
        Assert.True(t.IsLocked("k", out var wait));
        Assert.Equal(TimeSpan.FromSeconds(2), wait);

        time.Advance(TimeSpan.FromSeconds(2));
        Assert.False(t.IsLocked("k", out _));
        t.RecordFailure("k"); // 4th: 4s
        Assert.True(t.IsLocked("k", out wait));
        Assert.Equal(TimeSpan.FromSeconds(4), wait);

        for (int i = 0; i < 10; i++) t.RecordFailure("k");
        Assert.True(t.IsLocked("k", out wait));
        Assert.Equal(TimeSpan.FromSeconds(60), wait); // capped
    }

    [Fact]
    public void Success_resets_and_old_failures_expire()
    {
        var time = new ManualTime();
        var t = new LoginThrottle(time, 2, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(10), TimeSpan.FromMinutes(5));
        t.RecordFailure("k");
        t.RecordSuccess("k");
        Assert.Equal(0, t.FailureCount("k"));

        t.RecordFailure("k");
        time.Advance(TimeSpan.FromMinutes(6));
        t.RecordFailure("k");
        Assert.Equal(1, t.FailureCount("k"));
        Assert.False(t.IsLocked("k", out _));

        time.Advance(TimeSpan.FromMinutes(6));
        Assert.Equal(1, t.Prune());
    }
}

public class UserAuthenticatorTests
{
    private readonly ManualTime _time = new();
    private readonly InMemoryUserStore _users = new();
    private readonly PasswordHasher _hasher = new(1_000);
    private readonly Totp _totp;
    private readonly UserAuthenticator _auth;
    private readonly byte[] _secret = "12345678901234567890"u8.ToArray();

    public UserAuthenticatorTests()
    {
        _totp = new Totp(_time);
        _auth = new UserAuthenticator(_users, _hasher, _totp,
            new LoginThrottle(_time, 3, TimeSpan.FromSeconds(30), TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(15)),
            new LoginThrottle(_time, 10, TimeSpan.FromSeconds(30), TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(15)));
        _users.Add(new UserAccount { SubjectId = "s-alice", Username = "alice", PasswordHash = _hasher.Hash("pw-alice") });
        _users.Add(new UserAccount { SubjectId = "s-bob", Username = "bob", PasswordHash = _hasher.Hash("pw-bob"), TotpSecret = _secret });
    }

    [Fact]
    public void Password_login_succeeds_and_usernames_are_case_insensitive()
    {
        var r = _auth.Authenticate("ALICE", "pw-alice", null, "1.1.1.1");
        Assert.True(r.Succeeded);
        Assert.Equal("s-alice", r.User!.SubjectId);
    }

    [Fact]
    public void Unknown_user_and_wrong_password_look_identical()
    {
        Assert.Equal(AuthOutcome.InvalidCredentials, _auth.Authenticate("mallory", "x", null, "1.1.1.1").Outcome);
        Assert.Equal(AuthOutcome.InvalidCredentials, _auth.Authenticate("alice", "x", null, "1.1.1.1").Outcome);
    }

    [Fact]
    public void Lockout_blocks_even_the_correct_password()
    {
        for (int i = 0; i < 3; i++) _auth.Authenticate("alice", "wrong", null, "1.1.1.1");
        var r = _auth.Authenticate("alice", "pw-alice", null, "2.2.2.2");
        Assert.Equal(AuthOutcome.LockedOut, r.Outcome);
        Assert.True(r.RetryAfter > TimeSpan.Zero);

        _time.Advance(r.RetryAfter);
        Assert.True(_auth.Authenticate("alice", "pw-alice", null, "2.2.2.2").Succeeded);
    }

    [Fact]
    public void Per_ip_throttle_catches_password_spraying()
    {
        for (int i = 0; i < 10; i++) _auth.Authenticate($"user{i}", "Summer2026!", null, "6.6.6.6");
        Assert.Equal(AuthOutcome.LockedOut, _auth.Authenticate("alice", "pw-alice", null, "6.6.6.6").Outcome);
        Assert.True(_auth.Authenticate("alice", "pw-alice", null, "7.7.7.7").Succeeded);
    }

    [Fact]
    public void Totp_is_required_validated_and_single_use()
    {
        Assert.Equal(AuthOutcome.MfaRequired, _auth.Authenticate("bob", "pw-bob", null, "1.1.1.1").Outcome);
        Assert.Equal(AuthOutcome.InvalidMfa, _auth.Authenticate("bob", "pw-bob", "000000", "1.1.1.1").Outcome);

        string code = _totp.Generate(_secret);
        Assert.True(_auth.Authenticate("bob", "pw-bob", code, "1.1.1.1").Succeeded);
        Assert.Equal(AuthOutcome.InvalidMfa, _auth.Authenticate("bob", "pw-bob", code, "1.1.1.1").Outcome);

        _time.Advance(TimeSpan.FromSeconds(30));
        Assert.True(_auth.Authenticate("bob", "pw-bob", _totp.Generate(_secret), "1.1.1.1").Succeeded);
    }

    [Fact]
    public void Weak_hash_is_upgraded_on_successful_login()
    {
        var u = new UserAccount { SubjectId = "s-c", Username = "carol", PasswordHash = new PasswordHasher(100).Hash("pw") };
        _users.Add(u);
        Assert.True(_auth.Authenticate("carol", "pw", null, "1.1.1.1").Succeeded);
        Assert.StartsWith("pbkdf2-sha256$1000$", u.PasswordHash);
    }
}
