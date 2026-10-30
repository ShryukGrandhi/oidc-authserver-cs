using System.Security.Cryptography;
using OidcAuth.Core.Encoding;

namespace OidcAuth.Core.Mfa;

public enum TotpAlgorithm { Sha1, Sha256, Sha512 }

/// <summary>HOTP (RFC 4226) and TOTP (RFC 6238) code generation and verification.</summary>
public sealed class Totp
{
    private static readonly int[] Pow10 = { 1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000 };

    private readonly TimeProvider _time;

    public Totp(TimeProvider time, int stepSeconds = 30, int digits = 6, TotpAlgorithm algorithm = TotpAlgorithm.Sha1,
        int window = 1)
    {
        if (digits is < 6 or > 8) throw new ArgumentOutOfRangeException(nameof(digits));
        if (stepSeconds <= 0) throw new ArgumentOutOfRangeException(nameof(stepSeconds));
        if (window is < 0 or > 10) throw new ArgumentOutOfRangeException(nameof(window));
        _time = time;
        StepSeconds = stepSeconds;
        Digits = digits;
        Algorithm = algorithm;
        Window = window;
    }

    public int StepSeconds { get; }
    public int Digits { get; }
    public TotpAlgorithm Algorithm { get; }
    public int Window { get; }

    public long CounterAt(DateTimeOffset t) => Math.DivRem(t.ToUnixTimeSeconds(), StepSeconds).Quotient;

    public long CurrentCounter => CounterAt(_time.GetUtcNow());

    public string Generate(ReadOnlySpan<byte> secret) => Hotp(secret, CurrentCounter, Digits, Algorithm);

    public static string Hotp(ReadOnlySpan<byte> secret, long counter, int digits, TotpAlgorithm algorithm)
    {
        Span<byte> msg = stackalloc byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(msg, counter);
        Span<byte> mac = stackalloc byte[64];
        int len = algorithm switch
        {
            TotpAlgorithm.Sha1 => HMACSHA1.HashData(secret, msg, mac),
            TotpAlgorithm.Sha256 => HMACSHA256.HashData(secret, msg, mac),
            TotpAlgorithm.Sha512 => HMACSHA512.HashData(secret, msg, mac),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
        };
        // Dynamic truncation, RFC 4226 §5.3.
        int offset = mac[len - 1] & 0x0f;
        int binary = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
        return (binary % Pow10[digits]).ToString(new string('0', digits), System.Globalization.CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Checks <paramref name="code"/> against the current step ± <see cref="Window"/>. Returns the matched
    /// counter, or null. Steps at or below <paramref name="lastUsedCounter"/> are refused so a code (or an
    /// earlier one still inside the window) cannot be replayed. All candidates are compared in constant time.
    /// </summary>
    public long? Verify(ReadOnlySpan<byte> secret, string? code, long lastUsedCounter)
    {
        if (code is null || code.Length != Digits) return null;
        foreach (char c in code) if (c is < '0' or > '9') return null;

        long current = CurrentCounter;
        long? match = null;
        Span<byte> want = stackalloc byte[Digits];
        Span<byte> got = stackalloc byte[Digits];
        System.Text.Encoding.ASCII.GetBytes(code, got);
        for (long c = current - Window; c <= current + Window; c++)
        {
            System.Text.Encoding.ASCII.GetBytes(Hotp(secret, c, Digits, Algorithm), want);
            bool equal = CryptographicOperations.FixedTimeEquals(want, got);
            if (equal && c > lastUsedCounter && match is null) match = c;
        }
        return match;
    }

    public static string ProvisioningUri(string issuer, string account, ReadOnlySpan<byte> secret, int digits = 6,
        int period = 30) =>
        $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(account)}" +
        $"?secret={Base32.Encode(secret)}&issuer={Uri.EscapeDataString(issuer)}&algorithm=SHA1&digits={digits}&period={period}";
}
