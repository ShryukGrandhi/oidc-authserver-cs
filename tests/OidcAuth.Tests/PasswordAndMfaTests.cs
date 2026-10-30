using OidcAuth.Core.Encoding;
using OidcAuth.Core.Mfa;
using OidcAuth.Core.Passwords;

namespace OidcAuth.Tests;

public class PasswordHasherTests
{
    private readonly PasswordHasher _hasher = new(iterations: 1_000);

    [Fact]
    public void Verifies_correct_password_only()
    {
        string h = _hasher.Hash("hunter2");
        Assert.StartsWith("pbkdf2-sha256$1000$", h);
        Assert.Equal(PasswordVerification.Success, _hasher.Verify(h, "hunter2"));
        Assert.Equal(PasswordVerification.Failed, _hasher.Verify(h, "hunter3"));
        Assert.Equal(PasswordVerification.Failed, _hasher.Verify(h, ""));
    }

    [Fact]
    public void Same_password_gets_different_salts()
    {
        Assert.NotEqual(_hasher.Hash("pw"), _hasher.Hash("pw"));
    }

    [Fact]
    public void Older_work_factor_requests_rehash()
    {
        string weak = new PasswordHasher(iterations: 500).Hash("pw");
        Assert.Equal(PasswordVerification.SuccessRehashNeeded, _hasher.Verify(weak, "pw"));
        string strong = new PasswordHasher(iterations: 2_000).Hash("pw");
        Assert.Equal(PasswordVerification.Success, _hasher.Verify(strong, "pw"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("plaintext")]
    [InlineData("bcrypt$10$abc$def")]
    [InlineData("pbkdf2-sha256$-5$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAA==")]
    [InlineData("pbkdf2-sha256$99999999$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAA==")]
    [InlineData("pbkdf2-sha256$1000$not-base64!$AAAAAAAAAAAAAAAAAAAAAA==")]
    [InlineData("pbkdf2-sha256$1000$AAAAAAAAAAAAAAAAAAAAAA==$AAAA")]
    public void Malformed_hashes_fail_closed(string encoded) =>
        Assert.Equal(PasswordVerification.Failed, _hasher.Verify(encoded, "anything"));
}

public class TotpTests
{
    private static readonly byte[] Sha1Seed = "12345678901234567890"u8.ToArray();
    private static readonly byte[] Sha256Seed = "12345678901234567890123456789012"u8.ToArray();
    private static readonly byte[] Sha512Seed =
        "1234567890123456789012345678901234567890123456789012345678901234"u8.ToArray();

    // RFC 6238 Appendix B, all 18 published vectors.
    [Theory]
    [InlineData(59L, "94287082", "46119246", "90693936")]
    [InlineData(1111111109L, "07081804", "68084774", "25091201")]
    [InlineData(1111111111L, "14050471", "67062674", "99943326")]
    [InlineData(1234567890L, "89005924", "91819424", "93441116")]
    [InlineData(2000000000L, "69279037", "90698825", "38618901")]
    [InlineData(20000000000L, "65353130", "77737706", "47863826")]
    public void Matches_rfc6238_test_vectors(long unixTime, string sha1, string sha256, string sha512)
    {
        long counter = unixTime / 30;
        Assert.Equal(sha1, Totp.Hotp(Sha1Seed, counter, 8, TotpAlgorithm.Sha1));
        Assert.Equal(sha256, Totp.Hotp(Sha256Seed, counter, 8, TotpAlgorithm.Sha256));
        Assert.Equal(sha512, Totp.Hotp(Sha512Seed, counter, 8, TotpAlgorithm.Sha512));
    }

    // RFC 4226 Appendix D HOTP values for counters 0..9.
    [Fact]
    public void Matches_rfc4226_hotp_vectors()
    {
        string[] expected = { "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489" };
        for (int i = 0; i < expected.Length; i++)
            Assert.Equal(expected[i], Totp.Hotp(Sha1Seed, i, 6, TotpAlgorithm.Sha1));
    }

    [Fact]
    public void Accepts_adjacent_steps_and_rejects_outside_window()
    {
        var time = new ManualTime(DateTimeOffset.FromUnixTimeSeconds(1_700_000_010));
        var totp = new Totp(time);
        long now = totp.CurrentCounter;
        Assert.Equal(now - 1, totp.Verify(Sha1Seed, Totp.Hotp(Sha1Seed, now - 1, 6, TotpAlgorithm.Sha1), -1));
        Assert.Equal(now + 1, totp.Verify(Sha1Seed, Totp.Hotp(Sha1Seed, now + 1, 6, TotpAlgorithm.Sha1), -1));
        Assert.Null(totp.Verify(Sha1Seed, Totp.Hotp(Sha1Seed, now - 2, 6, TotpAlgorithm.Sha1), -1));
        Assert.Null(totp.Verify(Sha1Seed, Totp.Hotp(Sha1Seed, now + 2, 6, TotpAlgorithm.Sha1), -1));
    }

    [Fact]
    public void Rejects_replay_of_used_or_older_step()
    {
        var totp = new Totp(new ManualTime());
        string code = totp.Generate(Sha1Seed);
        long? step = totp.Verify(Sha1Seed, code, -1);
        Assert.NotNull(step);
        Assert.Null(totp.Verify(Sha1Seed, code, step!.Value));
        string previous = Totp.Hotp(Sha1Seed, step.Value - 1, 6, TotpAlgorithm.Sha1);
        Assert.Null(totp.Verify(Sha1Seed, previous, step.Value));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("12345")]
    [InlineData("1234567")]
    [InlineData("12a456")]
    [InlineData("１２３４５６")]
    public void Rejects_malformed_codes(string? code) => Assert.Null(new Totp(new ManualTime()).Verify(Sha1Seed, code, -1));

    [Fact]
    public void Provisioning_uri_encodes_secret_in_base32()
    {
        string uri = Totp.ProvisioningUri("Acme Corp", "alice@example.com", Sha1Seed);
        Assert.StartsWith("otpauth://totp/Acme%20Corp:alice%40example.com?secret=", uri);
        Assert.Contains("secret=" + Base32.Encode(Sha1Seed), uri);
    }
}
