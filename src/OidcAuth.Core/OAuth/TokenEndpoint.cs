using System.Text.Json.Serialization;

namespace OidcAuth.Core.OAuth;

public sealed record TokenResponse(
    [property: JsonPropertyName("access_token")] string AccessToken,
    [property: JsonPropertyName("token_type")] string TokenType,
    [property: JsonPropertyName("expires_in")] int ExpiresIn,
    [property: JsonPropertyName("scope")] string Scope,
    [property: JsonPropertyName("refresh_token"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    string? RefreshToken = null,
    [property: JsonPropertyName("id_token"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    string? IdToken = null);

/// <summary>Credentials from an HTTP Basic Authorization header, already URL-decoded.</summary>
public sealed record BasicCredentials(string ClientId, string Secret);

/// <summary>
/// Transport-independent token endpoint (RFC 6749 §3.2). The HTTP host only parses the form body and the
/// Authorization header; every protocol decision lives here so it can be unit tested and benchmarked.
/// </summary>
public sealed class TokenEndpoint
{
    private readonly ClientRegistry _clients;
    private readonly AuthorizationCodeStore _codes;
    private readonly RefreshTokenService _refresh;
    private readonly TokenIssuer _issuer;
    private readonly AuthServerOptions _options;

    public TokenEndpoint(ClientRegistry clients, AuthorizationCodeStore codes, RefreshTokenService refresh,
        TokenIssuer issuer, AuthServerOptions options)
    {
        _clients = clients;
        _codes = codes;
        _refresh = refresh;
        _issuer = issuer;
        _options = options;
    }

    public OAuthResult<TokenResponse> Handle(IReadOnlyDictionary<string, string> form, BasicCredentials? basic)
    {
        var auth = AuthenticateClient(form, basic);
        if (!auth.IsOk) return auth.Error!;
        var client = auth.Value!;

        string? grantType = form.GetValueOrDefault("grant_type");
        if (grantType is null) return OAuthError.InvalidRequest("grant_type is required.");
        if (grantType is not (GrantTypes.AuthorizationCode or GrantTypes.RefreshToken or GrantTypes.ClientCredentials))
            return OAuthError.UnsupportedGrantType($"Unsupported grant_type '{grantType}'.");
        if (!client.AllowedGrantTypes.Contains(grantType))
            return OAuthError.UnauthorizedClient($"Client may not use {grantType}.");

        return grantType switch
        {
            GrantTypes.AuthorizationCode => RedeemCode(client, form),
            GrantTypes.RefreshToken => RefreshTokens(client, form),
            _ => ClientCredentials(client, form),
        };
    }

    /// <summary>
    /// Exactly one authentication method per request (RFC 6749 §2.3). Confidential clients must present a
    /// secret; public clients identify with client_id only and are held to PKCE instead.
    /// </summary>
    public OAuthResult<OAuthClient> AuthenticateClient(IReadOnlyDictionary<string, string> form, BasicCredentials? basic)
    {
        string? formId = form.GetValueOrDefault("client_id");
        string? formSecret = form.GetValueOrDefault("client_secret");
        if (basic is not null && formSecret is not null)
            return OAuthError.InvalidRequest("Use one client authentication method, not two.");
        if (basic is not null && formId is not null && formId != basic.ClientId)
            return OAuthError.InvalidRequest("client_id does not match the Authorization header.");

        string? clientId = basic?.ClientId ?? formId;
        string? secret = basic?.Secret ?? formSecret;
        var client = _clients.Find(clientId);
        if (client is null) return OAuthError.InvalidClient("Client authentication failed.");

        if (client.IsPublic)
        {
            if (secret is not null) return OAuthError.InvalidClient("Public clients have no secret.");
            return client;
        }
        return client.VerifySecret(secret) ? client : OAuthError.InvalidClient("Client authentication failed.");
    }

    private OAuthResult<TokenResponse> RedeemCode(OAuthClient client, IReadOnlyDictionary<string, string> form)
    {
        string? code = form.GetValueOrDefault("code");
        string? redirectUri = form.GetValueOrDefault("redirect_uri");
        string? verifier = form.GetValueOrDefault("code_verifier");
        if (code is null || redirectUri is null || verifier is null)
            return OAuthError.InvalidRequest("code, redirect_uri and code_verifier are required.");

        var (status, entry) = _codes.Redeem(code);
        switch (status)
        {
            case CodeRedemptionStatus.NotFound:
                return OAuthError.InvalidGrant("Unknown authorization code.");
            case CodeRedemptionStatus.Expired:
                return OAuthError.InvalidGrant("Authorization code expired.");
            case CodeRedemptionStatus.AlreadyRedeemed:
                RevokeIssuedFrom(entry!);
                return OAuthError.InvalidGrant("Authorization code already used; tokens issued from it were revoked.");
        }

        var grant = entry!.Grant;
        // Binding checks: the code is only good for the client and redirect URI it was issued to,
        // and only with the verifier whose hash was presented at /authorize.
        if (grant.ClientId != client.ClientId) return OAuthError.InvalidGrant("Code was issued to another client.");
        if (grant.RedirectUri != redirectUri) return OAuthError.InvalidGrant("redirect_uri does not match.");
        if (!Pkce.Verify(verifier, grant.CodeChallenge)) return OAuthError.InvalidGrant("PKCE verification failed.");

        var access = _issuer.CreateAccessToken(grant.Subject, client.ClientId, grant.Scopes);
        entry.AccessTokenId = access.Jti;
        entry.AccessTokenExpiry = access.ExpiresAt;

        string? refreshToken = null;
        if (client.AllowedGrantTypes.Contains(GrantTypes.RefreshToken))
        {
            var (token, family) = _refresh.IssueNewFamily(client.ClientId, grant.Subject, grant.Scopes, grant.AuthTime);
            entry.RefreshFamilyId = family.Id;
            refreshToken = token;
        }

        // A replay that raced with us may have flagged the code before we recorded what we issued.
        if (entry.IsCompromised)
        {
            RevokeIssuedFrom(entry);
            return OAuthError.InvalidGrant("Authorization code already used.");
        }

        string? idToken = grant.Scopes.Contains("openid")
            ? _issuer.CreateIdToken(grant.Subject, client.ClientId, grant.Nonce, grant.AuthTime, access.Token)
            : null;
        return Respond(access, grant.Scopes, refreshToken, idToken);
    }

    private OAuthResult<TokenResponse> RefreshTokens(OAuthClient client, IReadOnlyDictionary<string, string> form)
    {
        string? token = form.GetValueOrDefault("refresh_token");
        if (token is null) return OAuthError.InvalidRequest("refresh_token is required.");
        if (!ScopeSet.TryParse(form.GetValueOrDefault("scope"), out var requested))
            return OAuthError.InvalidScope("Malformed scope.");

        var outcome = _refresh.Rotate(token, client.ClientId, requested);
        return outcome.Status switch
        {
            RefreshStatus.Ok => Respond(
                _issuer.CreateAccessToken(outcome.Family!.Subject, client.ClientId, outcome.AccessScopes!),
                outcome.AccessScopes!, outcome.NewToken, null),
            RefreshStatus.ScopeExceeded => OAuthError.InvalidScope("Requested scope exceeds the original grant."),
            RefreshStatus.ReuseDetected => OAuthError.InvalidGrant("Refresh token reuse detected; session revoked."),
            _ => OAuthError.InvalidGrant("Refresh token is invalid, expired or revoked."),
        };
    }

    private OAuthResult<TokenResponse> ClientCredentials(OAuthClient client, IReadOnlyDictionary<string, string> form)
    {
        if (client.IsPublic) return OAuthError.UnauthorizedClient("Public clients cannot use client_credentials.");
        if (!ScopeSet.TryParse(form.GetValueOrDefault("scope"), out var scopes))
            return OAuthError.InvalidScope("Malformed scope.");
        if (scopes.IsEmpty) scopes = client.AllowedScopes;
        if (!scopes.IsSubsetOf(client.AllowedScopes)) return OAuthError.InvalidScope("Scope not allowed for client.");
        if (scopes.Contains("openid")) return OAuthError.InvalidScope("openid requires an end user.");

        return Respond(_issuer.CreateAccessToken(client.ClientId, client.ClientId, scopes), scopes, null, null);
    }

    private void RevokeIssuedFrom(AuthorizationCodeStore.Entry entry)
    {
        if (entry.RefreshFamilyId is { } fam) _refresh.RevokeFamily(fam);
        if (entry.AccessTokenId is { } jti) _issuer.RevokeAccessToken(jti, entry.AccessTokenExpiry);
    }

    private TokenResponse Respond(IssuedAccessToken access, ScopeSet scopes, string? refresh, string? idToken) =>
        new(access.Token, "Bearer", (int)_options.AccessTokenLifetime.TotalSeconds, scopes.ToString(), refresh, idToken);
}
