using System.Text.Json.Nodes;
using OidcAuth.Core.Encoding;
using OidcAuth.Core.Jwt;

namespace OidcAuth.Tests;

public class JwtTests
{
    private sealed class SingleKey(SigningKey key) : IKeyResolver
    {
        public SigningKey? Resolve(string kid) => kid == key.Kid ? key : null;
    }

    private readonly ManualTime _time = new();

    private JwtValidator Validator(SigningKey key, string? typ = null, params string[] algs) => new(new JwtValidationOptions
    {
        Issuer = "https://auth.example",
        Audiences = new[] { "api" },
        AllowedAlgorithms = algs.Length == 0 ? new HashSet<string> { "ES256", "RS256", "HS256" } : algs.ToHashSet(),
        RequiredType = typ,
    }, new SingleKey(key), _time);

    private JsonObject Claims(int expInSeconds = 300)
    {
        long now = _time.GetUtcNow().ToUnixTimeSeconds();
        return new JsonObject
        {
            ["iss"] = "https://auth.example", ["sub"] = "u1", ["aud"] = "api", ["iat"] = now, ["exp"] = now + expInSeconds,
        };
    }

    public static IEnumerable<object[]> Keys() => new[]
    {
        new object[] { "ES256" }, new object[] { "RS256" }, new object[] { "HS256" },
    };

    private static SigningKey Make(string alg) => alg switch
    {
        "ES256" => EcdsaSigningKey.Generate(),
        "RS256" => RsaSigningKey.Generate(),
        _ => HmacSigningKey.Generate(),
    };

    [Theory]
    [MemberData(nameof(Keys))]
    public void Roundtrip_validates_and_returns_claims(string alg)
    {
        using var key = Make(alg);
        string token = JwtEncoder.Encode(Claims(), key);
        var r = Validator(key).Validate(token);
        Assert.True(r.IsValid, r.Error.ToString());
        Assert.Equal("u1", JwtValidator.GetString(r.Claims!, "sub"));
        Assert.Equal(alg, JwtValidator.GetString(r.Header!, "alg"));
    }

    [Theory]
    [MemberData(nameof(Keys))]
    public void Any_payload_tampering_breaks_the_signature(string alg)
    {
        using var key = Make(alg);
        string token = JwtEncoder.Encode(Claims(), key);
        var parts = token.Split('.');
        var claims = JsonNode.Parse(Base64Url.Decode(parts[1]))!.AsObject();
        claims["sub"] = "admin";
        string forged = parts[0] + "." + Base64Url.Encode(System.Text.Encoding.UTF8.GetBytes(claims.ToJsonString())) + "." + parts[2];
        Assert.Equal(JwtError.BadSignature, Validator(key).Validate(forged).Error);
    }

    [Fact]
    public void Flipping_a_signature_bit_fails()
    {
        using var key = EcdsaSigningKey.Generate();
        string token = JwtEncoder.Encode(Claims(), key);
        var parts = token.Split('.');
        var sig = Base64Url.Decode(parts[2]);
        sig[10] ^= 0x01;
        Assert.Equal(JwtError.BadSignature, Validator(key).Validate($"{parts[0]}.{parts[1]}.{Base64Url.Encode(sig)}").Error);
    }

    private static string Unsigned(JsonObject header, JsonObject payload, byte[] sig) =>
        Base64Url.Encode(System.Text.Encoding.UTF8.GetBytes(header.ToJsonString())) + "." +
        Base64Url.Encode(System.Text.Encoding.UTF8.GetBytes(payload.ToJsonString())) + "." + Base64Url.Encode(sig);

    [Theory]
    [InlineData("none")]
    [InlineData("None")]
    [InlineData("NONE")]
    public void Alg_none_is_rejected_in_any_casing(string alg)
    {
        using var key = EcdsaSigningKey.Generate();
        string token = Unsigned(new JsonObject { ["alg"] = alg, ["kid"] = key.Kid }, Claims(), Array.Empty<byte>());
        // An empty signature segment makes the token structurally malformed as well; both must fail.
        Assert.False(Validator(key, null, "ES256", "none").Validate(token).IsValid);
        string withSig = Unsigned(new JsonObject { ["alg"] = alg, ["kid"] = key.Kid }, Claims(), new byte[] { 1 });
        Assert.Equal(JwtError.UnsupportedAlgorithm, Validator(key, null, "ES256", "none").Validate(withSig).Error);
    }

    [Fact]
    public void Rs256_to_Hs256_confusion_is_rejected()
    {
        // Classic attack: sign HS256 using the RSA *public key* bytes as the HMAC secret and hope the verifier
        // feeds its RSA key into HMAC. The key ring binds RS256 to this kid, so the header alg cannot change it.
        using var rsa = RsaSigningKey.Generate();
        var publicKeyBytes = System.Text.Encoding.UTF8.GetBytes(rsa.ToPublicJwk().ToJsonString());
        using var evil = new HmacSigningKey(publicKeyBytes, rsa.Kid);
        string forged = JwtEncoder.Encode(Claims(), evil);
        Assert.Equal(JwtError.AlgorithmKeyMismatch, Validator(rsa, null, "RS256", "HS256").Validate(forged).Error);
    }

    [Fact]
    public void Algorithm_outside_allow_list_is_rejected()
    {
        using var key = HmacSigningKey.Generate();
        Assert.Equal(JwtError.UnsupportedAlgorithm, Validator(key, null, "ES256").Validate(JwtEncoder.Encode(Claims(), key)).Error);
    }

    [Fact]
    public void Unknown_and_missing_kid_are_rejected()
    {
        using var signer = EcdsaSigningKey.Generate();
        using var other = EcdsaSigningKey.Generate();
        Assert.Equal(JwtError.UnknownKey, Validator(other).Validate(JwtEncoder.Encode(Claims(), signer)).Error);

        var noKid = Unsigned(new JsonObject { ["alg"] = "ES256" }, Claims(), new byte[64]);
        Assert.Equal(JwtError.UnknownKey, Validator(signer).Validate(noKid).Error);
    }

    [Fact]
    public void Expiry_respects_clock_skew()
    {
        using var key = EcdsaSigningKey.Generate();
        var v = Validator(key);
        string token = JwtEncoder.Encode(Claims(expInSeconds: 60), key);
        _time.Advance(TimeSpan.FromSeconds(60 + 29));
        Assert.True(v.Validate(token).IsValid);
        _time.Advance(TimeSpan.FromSeconds(1));
        Assert.Equal(JwtError.Expired, v.Validate(token).Error);
    }

    [Fact]
    public void Nbf_and_future_iat_are_enforced()
    {
        using var key = EcdsaSigningKey.Generate();
        var c = Claims();
        c["nbf"] = _time.GetUtcNow().ToUnixTimeSeconds() + 120;
        Assert.Equal(JwtError.NotYetValid, Validator(key).Validate(JwtEncoder.Encode(c, key)).Error);

        c = Claims();
        c["iat"] = _time.GetUtcNow().ToUnixTimeSeconds() + 3600;
        Assert.Equal(JwtError.IssuedInFuture, Validator(key).Validate(JwtEncoder.Encode(c, key)).Error);
    }

    [Fact]
    public void Missing_exp_is_rejected()
    {
        using var key = EcdsaSigningKey.Generate();
        var c = Claims();
        c.Remove("exp");
        Assert.Equal(JwtError.MissingClaim, Validator(key).Validate(JwtEncoder.Encode(c, key)).Error);
    }

    [Fact]
    public void Issuer_and_audience_must_match()
    {
        using var key = EcdsaSigningKey.Generate();
        var c = Claims();
        c["iss"] = "https://evil.example";
        Assert.Equal(JwtError.WrongIssuer, Validator(key).Validate(JwtEncoder.Encode(c, key)).Error);

        c = Claims();
        c["aud"] = "other-api";
        Assert.Equal(JwtError.WrongAudience, Validator(key).Validate(JwtEncoder.Encode(c, key)).Error);

        c = Claims();
        c["aud"] = new JsonArray("other-api", "api");
        Assert.True(Validator(key).Validate(JwtEncoder.Encode(c, key)).IsValid);
    }

    [Fact]
    public void Required_typ_is_enforced()
    {
        using var key = EcdsaSigningKey.Generate();
        Assert.Equal(JwtError.WrongType, Validator(key, "at+jwt").Validate(JwtEncoder.Encode(Claims(), key)).Error);
        Assert.True(Validator(key, "at+jwt").Validate(JwtEncoder.Encode(Claims(), key, "at+jwt")).IsValid);
    }

    [Theory]
    [InlineData("")]
    [InlineData("abc")]
    [InlineData("a.b")]
    [InlineData("a.b.c.d")]
    [InlineData("..")]
    [InlineData("e30.e30.")]
    [InlineData("!!!.e30.AAAA")]
    public void Malformed_tokens_are_rejected(string token)
    {
        using var key = EcdsaSigningKey.Generate();
        Assert.Equal(JwtError.Malformed, Validator(key).Validate(token).Error);
    }

    [Fact]
    public void Duplicate_json_members_and_crit_headers_are_rejected()
    {
        using var key = EcdsaSigningKey.Generate();
        string dupHeader = $"{{\"alg\":\"ES256\",\"kid\":\"{key.Kid}\",\"alg\":\"HS256\"}}";
        string token = Base64Url.Encode(System.Text.Encoding.UTF8.GetBytes(dupHeader)) + ".e30.AAAA";
        Assert.Equal(JwtError.Malformed, Validator(key).Validate(token).Error);

        string crit = Unsigned(new JsonObject { ["alg"] = "ES256", ["kid"] = key.Kid, ["crit"] = new JsonArray("exp") },
            Claims(), new byte[64]);
        Assert.Equal(JwtError.Malformed, Validator(key).Validate(crit).Error);
    }

    [Fact]
    public void Rsa_thumbprint_matches_rfc7638_example()
    {
        const string n =
            "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
            "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5h" +
            "ajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
        Assert.Equal("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", RsaSigningKey.ComputeThumbprint(n, "AQAB"));
        using var key = RsaSigningKey.FromPublic(n, "AQAB");
        Assert.Equal("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", key.Kid);
        Assert.False(key.CanSign);
    }

    [Fact]
    public void Weak_keys_are_refused()
    {
        Assert.Throws<ArgumentException>(() => new HmacSigningKey(new byte[16], "k"));
        Assert.Throws<ArgumentException>(() => new RsaSigningKey(System.Security.Cryptography.RSA.Create(1024), true));
    }
}
