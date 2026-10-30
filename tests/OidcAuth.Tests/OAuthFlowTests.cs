using OidcAuth.Core.Jwt;
using OidcAuth.Core.OAuth;

namespace OidcAuth.Tests;

public class PkceAndScopeTests
{
    [Fact]
    public void S256_matches_rfc7636_appendix_b()
    {
        const string verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        Assert.Equal("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", Pkce.ComputeChallenge(verifier));
        Assert.True(Pkce.Verify(verifier, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"));
        Assert.False(Pkce.Verify(verifier[..^1] + "l", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("short")]
    [InlineData("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjX")] // 42 chars
    [InlineData("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjX!")] // illegal char
    public void Invalid_verifiers_never_verify(string? verifier) =>
        Assert.False(Pkce.Verify(verifier, Pkce.ComputeChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")));

    [Fact]
    public void Scope_parsing_is_strict_and_order_insensitive()
    {
        Assert.True(ScopeSet.TryParse("b a b", out var s));
        Assert.Equal("a b", s.ToString());
        Assert.Equal(ScopeSet.Of("a", "b"), s);
        Assert.False(ScopeSet.TryParse("a  b", out _));
        Assert.False(ScopeSet.TryParse("a\"b", out _));
        Assert.False(ScopeSet.TryParse("a\\b", out _));
        Assert.True(ScopeSet.Of("a").IsSubsetOf(s));
        Assert.False(ScopeSet.Of("c").IsSubsetOf(s));
    }
}

public class AuthorizationRequestTests
{
    private readonly Harness _h = new();
    private readonly string _challenge = Pkce.ComputeChallenge(Pkce.CreateVerifier());

    private AuthorizationValidation Validate(string? responseType = "code", string? clientId = "spa",
        string? redirect = Harness.SpaRedirect, string? scope = "openid", string? challenge = "default",
        string? method = "S256") =>
        _h.Server.Authorization.Validate(new AuthorizationRequest(responseType, clientId, redirect, scope, "st",
            challenge == "default" ? _challenge : challenge, method, null));

    [Fact]
    public void Unknown_client_or_bad_redirect_is_never_redirected()
    {
        foreach (var v in new[]
                 {
                     Validate(clientId: "nope"),
                     Validate(redirect: null),
                     Validate(redirect: "https://evil.example/callback"),
                     Validate(redirect: Harness.SpaRedirect + "/../../evil"),
                     Validate(redirect: Harness.SpaRedirect + "?x=1"),
                 })
        {
            Assert.False(v.IsValid);
            Assert.Null(v.ErrorRedirectUri);
        }
    }

    [Theory]
    [InlineData("token", "openid", "default", "S256", "unsupported_response_type")]
    [InlineData("code", "openid admin", "default", "S256", "invalid_scope")]
    [InlineData("code", null, "default", "S256", "invalid_scope")]
    [InlineData("code", "openid", null, "S256", "invalid_request")]
    [InlineData("code", "openid", "default", "plain", "invalid_request")]
    [InlineData("code", "openid", "default", null, "invalid_request")]
    [InlineData("code", "openid", "tooShort", "S256", "invalid_request")]
    public void Recoverable_errors_redirect_back_with_state_and_iss(string rt, string? scope, string? challenge,
        string? method, string expectedError)
    {
        var v = Validate(responseType: rt, scope: scope, challenge: challenge, method: method);
        Assert.False(v.IsValid);
        Assert.Equal(expectedError, v.Error!.Code);
        Assert.Equal(expectedError, Harness.QueryParam(v.ErrorRedirectUri!, "error"));
        Assert.Equal("st", Harness.QueryParam(v.ErrorRedirectUri!, "state"));
        Assert.Equal("https://auth.example", Harness.QueryParam(v.ErrorRedirectUri!, "iss"));
    }

    [Fact]
    public void Success_redirect_carries_code_state_and_issuer()
    {
        var (_, _, url) = _h.Authorize();
        Assert.StartsWith(Harness.SpaRedirect + "?code=", url);
        Assert.Equal("xyz", Harness.QueryParam(url, "state"));
        Assert.Equal("https://auth.example", Harness.QueryParam(url, "iss"));
    }

    [Fact]
    public void Client_without_code_grant_is_refused()
    {
        var v = _h.Server.Authorization.Validate(new AuthorizationRequest("code", "svc", null, "reports.read", null,
            _challenge, "S256", null));
        Assert.False(v.IsValid); // svc has no redirect URIs, so it fails before any redirect is possible
    }
}

public class TokenEndpointTests
{
    private readonly Harness _h = new();

    [Fact]
    public void Code_exchange_issues_access_refresh_and_id_tokens()
    {
        var (code, verifier, _) = _h.Authorize(scope: "openid api.read");
        var r = _h.Exchange(code, verifier);
        Assert.True(r.IsOk, r.Error?.Description);
        var t = r.Value!;
        Assert.Equal("Bearer", t.TokenType);
        Assert.Equal(600, t.ExpiresIn);
        Assert.Equal("api.read openid", t.Scope);
        Assert.NotNull(t.RefreshToken);
        Assert.NotNull(t.IdToken);

        var at = _h.Server.Issuer.ValidateAccessToken(t.AccessToken);
        Assert.True(at.IsValid, at.Error.ToString());
        Assert.Equal(_h.Alice.SubjectId, JwtValidator.GetString(at.Claims!, "sub"));
        Assert.Equal("spa", JwtValidator.GetString(at.Claims!, "client_id"));
        Assert.Equal("at+jwt", JwtValidator.GetString(at.Header!, "typ"));

        var idValidator = new JwtValidator(new JwtValidationOptions { Issuer = "https://auth.example", Audiences = new[] { "spa" } },
            _h.Server.Keys, _h.Time);
        var id = idValidator.Validate(t.IdToken);
        Assert.True(id.IsValid, id.Error.ToString());
        Assert.Equal("n-0S6_WzA2Mj", JwtValidator.GetString(id.Claims!, "nonce"));
        Assert.Equal(TokenIssuer.AtHash(t.AccessToken), JwtValidator.GetString(id.Claims!, "at_hash"));
    }

    [Fact]
    public void Id_token_is_only_issued_for_openid_scope()
    {
        var t = _h.LoginSpa(scope: "api.read");
        Assert.Null(t.IdToken);
        Assert.Equal(JwtError.WrongType, new JwtValidator(new JwtValidationOptions
        {
            Issuer = "https://auth.example", Audiences = new[] { "api" }, RequiredType = "JWT",
        }, _h.Server.Keys, _h.Time).Validate(t.AccessToken).Error);
    }

    [Fact]
    public void Wrong_verifier_redirect_or_client_is_invalid_grant()
    {
        var (code, _, _) = _h.Authorize();
        Assert.Equal("invalid_grant", _h.Exchange(code, Pkce.CreateVerifier()).Error!.Code);

        (code, var verifier, _) = _h.Authorize();
        Assert.Equal("invalid_grant", _h.Exchange(code, verifier, redirect: "https://spa.example/other").Error!.Code);

        (code, verifier, _) = _h.Authorize();
        Assert.Equal("invalid_grant", _h.Exchange(code, verifier, clientId: "web", redirect: Harness.SpaRedirect).Error!.Code);
    }

    [Fact]
    public void Failed_attempt_still_burns_the_code()
    {
        // Otherwise an attacker holding a stolen code could brute-force the verifier.
        var (code, verifier, _) = _h.Authorize();
        Assert.False(_h.Exchange(code, Pkce.CreateVerifier()).IsOk);
        Assert.Equal("invalid_grant", _h.Exchange(code, verifier).Error!.Code);
    }

    [Fact]
    public void Expired_code_is_rejected()
    {
        var (code, verifier, _) = _h.Authorize();
        _h.Time.Advance(TimeSpan.FromSeconds(61));
        Assert.Equal("Authorization code expired.", _h.Exchange(code, verifier).Error!.Description);
    }

    [Fact]
    public void Code_replay_revokes_tokens_from_first_redemption()
    {
        var (code, verifier, _) = _h.Authorize();
        var first = _h.Exchange(code, verifier).Value!;
        Assert.True(_h.Server.Issuer.ValidateAccessToken(first.AccessToken).IsValid);

        var replay = _h.Exchange(code, verifier);
        Assert.Equal("invalid_grant", replay.Error!.Code);
        Assert.Equal(JwtError.Revoked, _h.Server.Issuer.ValidateAccessToken(first.AccessToken).Error);
        Assert.Equal("invalid_grant", _h.RefreshAs("spa", first.RefreshToken!).Error!.Code);
    }

    [Fact]
    public void Confidential_client_must_authenticate_exactly_once()
    {
        var (code, verifier, _) = _h.Authorize(clientId: "web");
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code", ["code"] = code, ["redirect_uri"] = Harness.WebRedirect,
            ["code_verifier"] = verifier, ["client_id"] = "web",
        };
        var noSecret = _h.Server.TokenEndpoint.Handle(form, null);
        Assert.Equal("invalid_client", noSecret.Error!.Code);
        Assert.Equal(401, noSecret.Error.Status);

        Assert.Equal("invalid_client", _h.Server.TokenEndpoint.Handle(form, new BasicCredentials("web", "wrong")).Error!.Code);

        form["client_secret"] = _h.WebSecret;
        Assert.Equal("invalid_request", _h.Server.TokenEndpoint.Handle(form, new BasicCredentials("web", _h.WebSecret)).Error!.Code);

        // client_secret_post alone works (the code was not consumed by the failed authentications above).
        Assert.True(_h.Server.TokenEndpoint.Handle(form, null).IsOk);
    }

    [Fact]
    public void Public_client_presenting_a_secret_is_rejected()
    {
        var r = _h.Server.TokenEndpoint.Handle(new Dictionary<string, string> { ["grant_type"] = "refresh_token", ["refresh_token"] = "x" },
            new BasicCredentials("spa", "guess"));
        Assert.Equal("invalid_client", r.Error!.Code);
    }

    [Fact]
    public void Client_credentials_grant_scopes_and_restrictions()
    {
        var basic = new BasicCredentials("svc", _h.SvcSecret);
        var all = _h.Server.TokenEndpoint.Handle(new Dictionary<string, string> { ["grant_type"] = "client_credentials" }, basic);
        Assert.Equal("reports.read reports.write", all.Value!.Scope);
        Assert.Null(all.Value.RefreshToken);
        var claims = _h.Server.Issuer.ValidateAccessToken(all.Value.AccessToken).Claims!;
        Assert.Equal("svc", JwtValidator.GetString(claims, "sub"));

        var narrow = _h.Server.TokenEndpoint.Handle(new Dictionary<string, string>
            { ["grant_type"] = "client_credentials", ["scope"] = "reports.read" }, basic);
        Assert.Equal("reports.read", narrow.Value!.Scope);

        var tooWide = _h.Server.TokenEndpoint.Handle(new Dictionary<string, string>
            { ["grant_type"] = "client_credentials", ["scope"] = "reports.read admin" }, basic);
        Assert.Equal("invalid_scope", tooWide.Error!.Code);

        var spa = _h.Server.TokenEndpoint.Handle(new Dictionary<string, string>
            { ["grant_type"] = "client_credentials", ["client_id"] = "spa" }, null);
        Assert.Equal("unauthorized_client", spa.Error!.Code);
    }

    [Fact]
    public void Unknown_or_missing_grant_type()
    {
        var basic = new BasicCredentials("svc", _h.SvcSecret);
        Assert.Equal("unsupported_grant_type", _h.Server.TokenEndpoint.Handle(new Dictionary<string, string> { ["grant_type"] = "password" }, basic).Error!.Code);
        Assert.Equal("invalid_request", _h.Server.TokenEndpoint.Handle(new Dictionary<string, string>(), basic).Error!.Code);
    }

    [Fact]
    public void Tokens_survive_key_rotation_until_they_expire()
    {
        var t = _h.LoginSpa();
        _h.Server.Keys.Rotate(RsaSigningKey.Generate());
        var t2 = _h.LoginSpa();
        Assert.True(_h.Server.Issuer.ValidateAccessToken(t.AccessToken).IsValid);
        Assert.True(_h.Server.Issuer.ValidateAccessToken(t2.AccessToken).IsValid);
        _h.Time.Advance(TimeSpan.FromMinutes(16));
        _h.Server.Prune();
        Assert.Equal(JwtError.UnknownKey, _h.Server.Issuer.ValidateAccessToken(t.AccessToken).Error);
    }
}
