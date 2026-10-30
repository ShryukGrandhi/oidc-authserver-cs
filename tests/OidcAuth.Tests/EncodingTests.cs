using OidcAuth.Core.Encoding;

namespace OidcAuth.Tests;

public class EncodingTests
{
    [Theory]
    [InlineData("", "")]
    [InlineData("f", "MY")]
    [InlineData("fo", "MZXQ")]
    [InlineData("foo", "MZXW6")]
    [InlineData("foob", "MZXW6YQ")]
    [InlineData("fooba", "MZXW6YTB")]
    [InlineData("foobar", "MZXW6YTBOI")]
    public void Base32_matches_rfc4648_vectors(string plain, string unpadded)
    {
        var bytes = System.Text.Encoding.ASCII.GetBytes(plain);
        Assert.Equal(unpadded, Base32.Encode(bytes));
        Assert.Equal(bytes, Base32.Decode(unpadded));
        Assert.Equal(bytes, Base32.Decode(Base32.Encode(bytes, pad: true).ToLowerInvariant()));
    }

    [Fact]
    public void Base32_padded_form_matches_rfc()
    {
        Assert.Equal("MZXW6YTBOI======", Base32.Encode("foobar"u8, pad: true));
        Assert.Throws<FormatException>(() => Base32.Decode("MZ1W"));
    }

    [Fact]
    public void Base64Url_roundtrips_all_lengths_without_padding()
    {
        var rng = new Random(7);
        for (int len = 0; len < 70; len++)
        {
            var data = new byte[len];
            rng.NextBytes(data);
            string s = Base64Url.Encode(data);
            Assert.DoesNotContain('=', s);
            Assert.DoesNotContain('+', s);
            Assert.DoesNotContain('/', s);
            Assert.Equal(data, Base64Url.Decode(s));
        }
    }

    [Theory]
    [InlineData("ab+c")]
    [InlineData("ab/c")]
    [InlineData("abc=")]
    [InlineData("a")]
    [InlineData("ab c")]
    public void Base64Url_rejects_non_url_safe_input(string s) => Assert.False(Base64Url.TryDecode(s, out _));
}
