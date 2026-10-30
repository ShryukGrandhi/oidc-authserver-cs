using System.Security.Cryptography;
using OidcAuth.Core.Encoding;

namespace OidcAuth.Core.OAuth;

/// <summary>
/// Random bearer strings (codes, refresh tokens). Stores only index by SHA-256 of the token, so a dump of
/// server memory or a database does not hand out usable credentials.
/// </summary>
internal static class OpaqueToken
{
    public static string New() => Base64Url.Encode(RandomNumberGenerator.GetBytes(32));

    public static string Hash(string token) =>
        Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(token)));
}
