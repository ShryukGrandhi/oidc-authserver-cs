using System.Text.Json.Nodes;

namespace OidcAuth.Core.Jwt;

/// <summary>
/// Relying-party side: builds verification keys from a published JWKS document. Each JWK's kid must match
/// its RFC 7638 thumbprint, so a tampered JWKS cannot alias one key under another key's id.
/// </summary>
public sealed class JwksKeyResolver : IKeyResolver, IDisposable
{
    private readonly Dictionary<string, SigningKey> _keys = new(StringComparer.Ordinal);

    public JwksKeyResolver(JsonObject jwks)
    {
        if (jwks["keys"] is not JsonArray arr) throw new FormatException("JWKS has no 'keys' array.");
        foreach (var node in arr)
        {
            if (node is not JsonObject jwk) continue;
            var key = Import(jwk);
            if (key is null) continue;
            if (JwtValidator.GetString(jwk, "kid") is { } kid && kid != key.Kid)
                throw new FormatException($"JWK kid '{kid}' does not match its thumbprint.");
            _keys[key.Kid] = key;
        }
    }

    public int Count => _keys.Count;

    public SigningKey? Resolve(string kid) => _keys.GetValueOrDefault(kid);

    private static SigningKey? Import(JsonObject jwk)
    {
        string? Str(string n) => JwtValidator.GetString(jwk, n);
        if (Str("use") is { } use && use != "sig") return null;
        return Str("kty") switch
        {
            "RSA" when Str("n") is { } n && Str("e") is { } e => RsaSigningKey.FromPublic(n, e),
            "EC" when Str("crv") == "P-256" && Str("x") is { } x && Str("y") is { } y => EcdsaSigningKey.FromPublic(x, y),
            _ => null,
        };
    }

    public void Dispose()
    {
        foreach (var k in _keys.Values) k.Dispose();
        _keys.Clear();
    }
}
