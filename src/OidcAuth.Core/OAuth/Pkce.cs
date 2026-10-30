using System.Security.Cryptography;
using OidcAuth.Core.Encoding;

namespace OidcAuth.Core.OAuth;

/// <summary>Proof Key for Code Exchange, RFC 7636. Only the S256 method is accepted.</summary>
public static class Pkce
{
    public const string MethodS256 = "S256";

    public static string CreateVerifier() => Base64Url.Encode(RandomNumberGenerator.GetBytes(32));

    public static string ComputeChallenge(string verifier) =>
        Base64Url.Encode(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(verifier)));

    /// <summary>43–128 characters from the unreserved set [A-Z a-z 0-9 - . _ ~] (RFC 7636 §4.1).</summary>
    public static bool IsValidVerifier(string? v)
    {
        if (v is null || v.Length is < 43 or > 128) return false;
        foreach (char c in v)
            if (c is not (>= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '.' or '_' or '~'))
                return false;
        return true;
    }

    /// <summary>An S256 challenge is always the 43-char base64url encoding of a SHA-256 digest.</summary>
    public static bool IsValidS256Challenge(string? c) =>
        c is { Length: 43 } && Base64Url.TryDecode(c, out var b) && b.Length == 32;

    public static bool Verify(string? verifier, string challenge)
    {
        if (!IsValidVerifier(verifier)) return false;
        Span<byte> computed = stackalloc byte[32];
        SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(verifier!), computed);
        return Base64Url.TryDecode(challenge, out var expected) && CryptographicOperations.FixedTimeEquals(computed, expected);
    }
}
