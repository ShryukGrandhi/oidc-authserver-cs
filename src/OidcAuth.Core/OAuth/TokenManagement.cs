using System.Text.Json.Nodes;
using OidcAuth.Core.Jwt;

namespace OidcAuth.Core.OAuth;

/// <summary>Token introspection (RFC 7662) and revocation (RFC 7009).</summary>
public sealed class TokenManagement
{
    private readonly RefreshTokenService _refresh;
    private readonly TokenIssuer _issuer;

    public TokenManagement(RefreshTokenService refresh, TokenIssuer issuer)
    {
        _refresh = refresh;
        _issuer = issuer;
    }

    /// <summary>
    /// Only confidential clients may introspect. Anything that is not a currently valid token yields
    /// {"active": false} with no further detail, as the RFC requires.
    /// </summary>
    public OAuthResult<JsonObject> Introspect(OAuthClient caller, string? token, string? hint)
    {
        if (caller.IsPublic) return OAuthError.UnauthorizedClient("Introspection requires a confidential client.");
        var inactive = new JsonObject { ["active"] = false };
        if (string.IsNullOrEmpty(token)) return inactive;

        bool refreshFirst = hint == "refresh_token";
        return (refreshFirst ? IntrospectRefresh(token) ?? IntrospectAccess(token)
                             : IntrospectAccess(token) ?? IntrospectRefresh(token)) ?? inactive;
    }

    private JsonObject? IntrospectAccess(string token)
    {
        var r = _issuer.ValidateAccessToken(token);
        if (!r.IsValid) return null;
        var c = r.Claims!;
        var result = new JsonObject { ["active"] = true, ["token_type"] = "access_token" };
        foreach (var name in new[] { "scope", "client_id", "sub", "aud", "iss", "exp", "iat", "jti" })
            if (c[name] is { } v) result[name] = v.DeepClone();
        return result;
    }

    private JsonObject? IntrospectRefresh(string token)
    {
        if (_refresh.Describe(token) is not { } d) return null;
        return new JsonObject
        {
            ["active"] = true,
            ["token_type"] = "refresh_token",
            ["client_id"] = d.Family.ClientId,
            ["sub"] = d.Family.Subject,
            ["scope"] = d.Family.Scopes.ToString(),
            ["exp"] = d.ExpiresAt.ToUnixTimeSeconds(),
        };
    }

    /// <summary>
    /// Revokes a refresh token (and its whole family) or an access token. Per RFC 7009 §2.2 an unknown or
    /// foreign token is not an error: the response is the same, so the endpoint cannot be used to probe tokens.
    /// </summary>
    public void Revoke(OAuthClient caller, string? token)
    {
        if (string.IsNullOrEmpty(token)) return;

        var family = _refresh.FindFamily(token, includeConsumed: true);
        if (family is not null)
        {
            if (family.ClientId == caller.ClientId) _refresh.RevokeFamily(family.Id);
            return;
        }

        var r = _issuer.AccessTokenValidator.Validate(token);
        if (!r.IsValid) return;
        var c = r.Claims!;
        if (JwtValidator.GetString(c, "client_id") != caller.ClientId) return;
        if (JwtValidator.GetString(c, "jti") is { } jti && JwtValidator.TryGetNumericDate(c, "exp", out long exp))
            _issuer.RevokeAccessToken(jti, DateTimeOffset.FromUnixTimeSeconds(exp));
    }
}
