namespace OidcAuth.Core.Encoding;

/// <summary>Unpadded base64url (RFC 4648 §5), as used by JWS/JWK and PKCE.</summary>
public static class Base64Url
{
    public static string Encode(ReadOnlySpan<byte> data)
    {
        string s = Convert.ToBase64String(data);
        int end = s.Length;
        while (end > 0 && s[end - 1] == '=') end--;
        return string.Create(end, s, static (dst, src) =>
        {
            for (int i = 0; i < dst.Length; i++)
            {
                char c = src[i];
                dst[i] = c == '+' ? '-' : c == '/' ? '_' : c;
            }
        });
    }

    public static byte[] Decode(string s) =>
        TryDecode(s, out var bytes) ? bytes : throw new FormatException("Invalid base64url string.");

    /// <summary>Strict decode: rejects padding, whitespace and characters outside the url-safe alphabet.</summary>
    public static bool TryDecode(ReadOnlySpan<char> s, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (s.Length % 4 == 1) return false;

        int padding = (4 - s.Length % 4) % 4;
        var buf = new char[s.Length + padding];
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9') buf[i] = c;
            else if (c == '-') buf[i] = '+';
            else if (c == '_') buf[i] = '/';
            else return false;
        }
        for (int i = s.Length; i < buf.Length; i++) buf[i] = '=';

        try
        {
            bytes = Convert.FromBase64CharArray(buf, 0, buf.Length);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
