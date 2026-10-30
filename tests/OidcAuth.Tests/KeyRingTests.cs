using System.Text.Json.Nodes;
using OidcAuth.Core.Jwt;

namespace OidcAuth.Tests;

public class KeyRingTests
{
    private readonly ManualTime _time = new();

    private JwtValidator Validator(IKeyResolver keys) => new(new JwtValidationOptions
    {
        Issuer = "iss", Audiences = new[] { "aud" },
    }, keys, _time);

    private string Token(SigningKey key)
    {
        long now = _time.GetUtcNow().ToUnixTimeSeconds();
        return JwtEncoder.Encode(new JsonObject { ["iss"] = "iss", ["aud"] = "aud", ["exp"] = now + 600 }, key);
    }

    [Fact]
    public void Retired_key_verifies_until_grace_period_ends()
    {
        var first = EcdsaSigningKey.Generate();
        var ring = new SigningKeyRing(first, TimeSpan.FromMinutes(15), _time);
        string oldToken = Token(ring.Active);

        ring.Rotate(RsaSigningKey.Generate());
        string newToken = Token(ring.Active);
        Assert.NotEqual(first.Kid, ring.Active.Kid);

        var v = Validator(ring);
        Assert.True(v.Validate(oldToken).IsValid);
        Assert.True(v.Validate(newToken).IsValid);
        Assert.Equal(2, ring.GetJwks()["keys"]!.AsArray().Count);

        _time.Advance(TimeSpan.FromMinutes(15));
        Assert.Equal(JwtError.UnknownKey, v.Validate(oldToken).Error);
        Assert.Single(ring.GetJwks()["keys"]!.AsArray());
        Assert.Equal(1, ring.PruneExpired());
    }

    [Fact]
    public void Jwks_never_contains_private_or_symmetric_material()
    {
        var ring = new SigningKeyRing(EcdsaSigningKey.Generate(), TimeSpan.FromHours(1), _time);
        ring.Rotate(RsaSigningKey.Generate());
        ring.Rotate(HmacSigningKey.Generate());
        string json = ring.GetJwks().ToJsonString();
        Assert.Equal(2, ring.GetJwks()["keys"]!.AsArray().Count);
        foreach (var privateMember in new[] { "\"d\"", "\"p\"", "\"q\"", "\"dp\"", "\"dq\"", "\"qi\"", "\"k\"" })
            Assert.DoesNotContain(privateMember, json);
    }

    [Fact]
    public void Relying_party_can_validate_from_published_jwks()
    {
        var ring = new SigningKeyRing(EcdsaSigningKey.Generate(), TimeSpan.FromHours(1), _time);
        string ecToken = Token(ring.Active);
        ring.Rotate(RsaSigningKey.Generate());
        string rsaToken = Token(ring.Active);

        // Round-trip through JSON text, as a resource server fetching /jwks.json would.
        var jwks = JsonNode.Parse(ring.GetJwks().ToJsonString())!.AsObject();
        using var rp = new JwksKeyResolver(jwks);
        Assert.Equal(2, rp.Count);
        Assert.True(Validator(rp).Validate(ecToken).IsValid);
        Assert.True(Validator(rp).Validate(rsaToken).IsValid);
    }

    [Fact]
    public void Jwks_with_kid_not_matching_thumbprint_is_rejected()
    {
        var ring = new SigningKeyRing(EcdsaSigningKey.Generate(), TimeSpan.FromHours(1), _time);
        var jwks = ring.GetJwks();
        jwks["keys"]![0]!["kid"] = "attacker-chosen";
        Assert.Throws<FormatException>(() => new JwksKeyResolver(jwks));
    }

    [Fact]
    public void Verification_only_key_cannot_become_active()
    {
        var ring = new SigningKeyRing(EcdsaSigningKey.Generate(), TimeSpan.FromHours(1), _time);
        var pub = ring.GetJwks()["keys"]![0]!;
        var verifyOnly = EcdsaSigningKey.FromPublic(pub["x"]!.GetValue<string>(), pub["y"]!.GetValue<string>());
        Assert.Throws<ArgumentException>(() => ring.Rotate(verifyOnly));
    }
}
