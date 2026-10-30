using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using OidcAuth.Core.Encoding;
using OidcAuth.Core.Jwt;

namespace OidcAuth.Core.OAuth;

public sealed record IssuedAccessToken(string Token, string Jti, DateTimeOffset ExpiresAt);

/// <summary>Mints RFC 9068 JWT access tokens and OpenID Connect ID tokens, and tracks revoked access tokens.</summary>
public sealed class TokenIssuer
{
    public const string AccessTokenType = "at+jwt";

    private readonly AuthServerOptions _options;
    private readonly SigningKeyRing _keys;
    private readonly TimeProvider _time;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _revokedJtis = new(StringComparer.Ordinal);

    public TokenIssuer(AuthServerOptions options, SigningKeyRing keys, TimeProvider time)
    {
        _options = options;
        _keys = keys;
        _time = time;
        AccessTokenValidator = new JwtValidator(new JwtValidationOptions
        {
            Issuer = options.Issuer,
            Audiences = new[] { options.ResourceAudience },
            RequiredType = AccessTokenType,
        }, keys, time);
    }

    public JwtValidator AccessTokenValidator { get; }

    public IssuedAccessToken CreateAccessToken(string subject, string clientId, ScopeSet scopes)
    {
        var now = _time.GetUtcNow();
        var exp = now + _options.AccessTokenLifetime;
        string jti = Base64Url.Encode(RandomNumberGenerator.GetBytes(16));
        var payload = new JsonObject
        {
            ["iss"] = _options.Issuer,
            ["sub"] = subject,
            ["aud"] = _options.ResourceAudience,
            ["client_id"] = clientId,
            ["scope"] = scopes.ToString(),
            ["iat"] = now.ToUnixTimeSeconds(),
            ["exp"] = exp.ToUnixTimeSeconds(),
            ["jti"] = jti,
        };
        return new IssuedAccessToken(JwtEncoder.Encode(payload, _keys.Active, AccessTokenType), jti, exp);
    }

    public string CreateIdToken(string subject, string clientId, string? nonce, DateTimeOffset authTime,
        string accessToken)
    {
        var now = _time.GetUtcNow();
        var payload = new JsonObject
        {
            ["iss"] = _options.Issuer,
            ["sub"] = subject,
            ["aud"] = clientId,
            ["iat"] = now.ToUnixTimeSeconds(),
            ["exp"] = (now + _options.IdTokenLifetime).ToUnixTimeSeconds(),
            ["auth_time"] = authTime.ToUnixTimeSeconds(),
            ["at_hash"] = AtHash(accessToken),
        };
        if (nonce is not null) payload["nonce"] = nonce;
        return JwtEncoder.Encode(payload, _keys.Active);
    }

    /// <summary>OIDC Core §3.1.3.6: base64url of the left half of SHA-256(access_token) for *256 algorithms.</summary>
    public static string AtHash(string accessToken)
    {
        byte[] h = SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(accessToken));
        return Base64Url.Encode(h.AsSpan(0, 16));
    }

    /// <summary>Validates an access token and checks it has not been revoked.</summary>
    public JwtValidationResult ValidateAccessToken(string? token)
    {
        var result = AccessTokenValidator.Validate(token);
        if (result.IsValid && JwtValidator.GetString(result.Claims!, "jti") is { } jti && _revokedJtis.ContainsKey(jti))
            return JwtValidationResult.Fail(JwtError.Revoked);
        return result;
    }

    public void RevokeAccessToken(string jti, DateTimeOffset expiresAt) => _revokedJtis[jti] = expiresAt;

    public bool IsAccessTokenRevoked(string jti) => _revokedJtis.ContainsKey(jti);

    /// <summary>Denylist entries are only needed until the token would have expired anyway.</summary>
    public int PruneRevoked()
    {
        var now = _time.GetUtcNow();
        int removed = 0;
        foreach (var (jti, exp) in _revokedJtis)
            if (exp + TimeSpan.FromMinutes(1) < now && _revokedJtis.TryRemove(jti, out _)) removed++;
        return removed;
    }
}
