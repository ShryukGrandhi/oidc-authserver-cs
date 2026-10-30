using System.Text;

namespace OidcAuth.Core.Encoding;

/// <summary>RFC 4648 base32, the encoding authenticator apps expect for TOTP secrets.</summary>
public static class Base32
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string Encode(ReadOnlySpan<byte> data, bool pad = false)
    {
        var sb = new StringBuilder((data.Length + 4) / 5 * 8);
        int buffer = 0, bits = 0;
        foreach (byte b in data)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                sb.Append(Alphabet[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }
        if (bits > 0) sb.Append(Alphabet[(buffer << (5 - bits)) & 31]);
        if (pad) while (sb.Length % 8 != 0) sb.Append('=');
        return sb.ToString();
    }

    /// <summary>Case-insensitive decode; ignores '=' padding, spaces and dashes (common in typed secrets).</summary>
    public static byte[] Decode(string s)
    {
        var output = new List<byte>(s.Length * 5 / 8);
        int buffer = 0, bits = 0;
        foreach (char raw in s)
        {
            if (raw is '=' or ' ' or '-') continue;
            char c = char.ToUpperInvariant(raw);
            int v = Alphabet.IndexOf(c);
            if (v < 0) throw new FormatException($"Invalid base32 character '{raw}'.");
            buffer = (buffer << 5) | v;
            bits += 5;
            if (bits >= 8)
            {
                output.Add((byte)(buffer >> (bits - 8)));
                bits -= 8;
            }
        }
        return output.ToArray();
    }
}
