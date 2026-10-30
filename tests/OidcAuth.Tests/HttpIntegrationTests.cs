using System.Net;
using System.Net.Http.Headers;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Mvc.Testing;
using OidcAuth.Core;
using OidcAuth.Core.Jwt;
using OidcAuth.Core.Mfa;
using OidcAuth.Core.OAuth;

namespace OidcAuth.Tests;

/// <summary>Drives the real ASP.NET Core host in-process over HTTP.</summary>
public class HttpIntegrationTests : IClassFixture<HttpIntegrationTests.Factory>
{
    public sealed class Factory : WebApplicationFactory<Program>
    {
        public string BackendSecret { get; private set; } = "";
        public byte[] BobTotp { get; } = "12345678901234567890"u8.ToArray();

        protected override void ConfigureWebHost(Microsoft.AspNetCore.Hosting.IWebHostBuilder builder)
        {
            builder.UseSetting("Auth:SeedDemoData", "false");
            builder.UseSetting("Auth:Issuer", "http://localhost");
            builder.UseSetting("Auth:PasswordIterations", "1000");
        }

        public AuthServer Auth => Services.GetService(typeof(AuthServer)) as AuthServer ?? throw new InvalidOperationException();

        public void Seed()
        {
            if (Auth.Clients.Find("spa") is not null) return;
            Auth.Clients.Register(OAuthClient.CreatePublic("spa", new[] { "https://spa.example/cb" },
                ScopeSet.Of("openid", "profile", "api.read")));
            (var backend, BackendSecret) = OAuthClient.CreateConfidential("backend", Array.Empty<string>(),
                new HashSet<string> { GrantTypes.ClientCredentials }, ScopeSet.Of("reports.read"));
            Auth.Clients.Register(backend);
            Auth.AddUser("alice", "pw-alice");
            Auth.AddUser("bob", "pw-bob", BobTotp);
            for (int i = 0; i < 5; i++) Auth.AddUser($"locked{i}", "pw");
        }
    }

    private readonly Factory _f;
    private readonly HttpClient _http;

    public HttpIntegrationTests(Factory f)
    {
        _f = f;
        _http = f.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        f.Seed();
    }

    private static FormUrlEncodedContent Form(params (string, string)[] kv) =>
        new(kv.Select(p => new KeyValuePair<string, string>(p.Item1, p.Item2)));

    private async Task<HttpResponseMessage> Authorize(string verifier, string user = "alice", string pw = "pw-alice",
        string? totp = null, string scope = "openid profile api.read")
    {
        var fields = new List<(string, string)>
        {
            ("response_type", "code"), ("client_id", "spa"), ("redirect_uri", "https://spa.example/cb"),
            ("scope", scope), ("state", "s1"), ("nonce", "n1"),
            ("code_challenge", Pkce.ComputeChallenge(verifier)), ("code_challenge_method", "S256"),
            ("username", user), ("password", pw),
        };
        if (totp is not null) fields.Add(("totp", totp));
        return await _http.PostAsync("/authorize", Form(fields.ToArray()));
    }

    private async Task<JsonObject> Login(string user = "alice", string pw = "pw-alice", string? totp = null)
    {
        string verifier = Pkce.CreateVerifier();
        var auth = await Authorize(verifier, user, pw, totp);
        Assert.Equal(HttpStatusCode.Redirect, auth.StatusCode);
        string code = Harness.QueryParam(auth.Headers.Location!.ToString(), "code")!;

        var tok = await _http.PostAsync("/token", Form(("grant_type", "authorization_code"), ("code", code),
            ("redirect_uri", "https://spa.example/cb"), ("code_verifier", verifier), ("client_id", "spa")));
        Assert.Equal(HttpStatusCode.OK, tok.StatusCode);
        Assert.Equal("no-store", tok.Headers.CacheControl!.ToString());
        return JsonNode.Parse(await tok.Content.ReadAsStringAsync())!.AsObject();
    }

    [Fact]
    public async Task Discovery_and_jwks_are_served_and_consistent()
    {
        var disco = JsonNode.Parse(await _http.GetStringAsync("/.well-known/openid-configuration"))!;
        Assert.Equal("http://localhost", disco["issuer"]!.GetValue<string>());
        Assert.Equal("S256", disco["code_challenge_methods_supported"]![0]!.GetValue<string>());

        var jwks = JsonNode.Parse(await _http.GetStringAsync("/jwks.json"))!.AsObject();
        using var rp = new JwksKeyResolver(jwks);
        Assert.NotNull(rp.Resolve(_f.Auth.Keys.Active.Kid));
    }

    [Fact]
    public async Task Full_authorization_code_flow_over_http()
    {
        var tokens = await Login();
        string at = tokens["access_token"]!.GetValue<string>();

        // A resource server validating offline from the JWKS accepts the token.
        var jwks = JsonNode.Parse(await _http.GetStringAsync("/jwks.json"))!.AsObject();
        using var rp = new JwksKeyResolver(jwks);
        var v = new JwtValidator(new JwtValidationOptions { Issuer = "http://localhost", Audiences = new[] { "api" }, RequiredType = "at+jwt" },
            rp, TimeProvider.System).Validate(at);
        Assert.True(v.IsValid, v.Error.ToString());

        var req = new HttpRequestMessage(HttpMethod.Get, "/userinfo");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", at);
        var ui = JsonNode.Parse(await (await _http.SendAsync(req)).Content.ReadAsStringAsync())!;
        Assert.Equal("alice", ui["preferred_username"]!.GetValue<string>());

        var refreshed = await _http.PostAsync("/token", Form(("grant_type", "refresh_token"),
            ("refresh_token", tokens["refresh_token"]!.GetValue<string>()), ("client_id", "spa")));
        Assert.Equal(HttpStatusCode.OK, refreshed.StatusCode);
    }

    [Fact]
    public async Task Revoked_access_token_is_refused_by_userinfo_and_introspection()
    {
        var tokens = await Login();
        string at = tokens["access_token"]!.GetValue<string>();
        Assert.Equal(HttpStatusCode.OK, (await _http.PostAsync("/revoke", Form(("token", at), ("client_id", "spa")))).StatusCode);

        var req = new HttpRequestMessage(HttpMethod.Get, "/userinfo");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", at);
        var res = await _http.SendAsync(req);
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
        Assert.Contains("invalid_token", res.Headers.WwwAuthenticate.ToString());

        var intro = new HttpRequestMessage(HttpMethod.Post, "/introspect") { Content = Form(("token", at)) };
        intro.Headers.Authorization = new AuthenticationHeaderValue("Basic",
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("backend:" + _f.BackendSecret)));
        var body = JsonNode.Parse(await (await _http.SendAsync(intro)).Content.ReadAsStringAsync())!;
        Assert.False(body["active"]!.GetValue<bool>());
    }

    [Fact]
    public async Task Bad_redirect_uri_gets_400_not_a_redirect()
    {
        var res = await _http.PostAsync("/authorize", Form(("response_type", "code"), ("client_id", "spa"),
            ("redirect_uri", "https://evil.example/cb"), ("scope", "openid"), ("code_challenge", Pkce.ComputeChallenge(Pkce.CreateVerifier())),
            ("code_challenge_method", "S256"), ("username", "alice"), ("password", "pw-alice")));
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
        Assert.Null(res.Headers.Location);
    }

    [Fact]
    public async Task Missing_pkce_redirects_back_with_error()
    {
        var res = await _http.PostAsync("/authorize", Form(("response_type", "code"), ("client_id", "spa"),
            ("redirect_uri", "https://spa.example/cb"), ("scope", "openid"), ("state", "abc")));
        Assert.Equal(HttpStatusCode.Redirect, res.StatusCode);
        Assert.Equal("invalid_request", Harness.QueryParam(res.Headers.Location!.ToString(), "error"));
    }

    [Fact]
    public async Task Repeated_parameters_are_rejected()
    {
        var res = await _http.PostAsync("/token", Form(("grant_type", "client_credentials"), ("grant_type", "refresh_token")));
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
    }

    [Fact]
    public async Task Client_credentials_with_basic_auth_and_bad_secret()
    {
        var good = new HttpRequestMessage(HttpMethod.Post, "/token") { Content = Form(("grant_type", "client_credentials")) };
        good.Headers.Authorization = new AuthenticationHeaderValue("Basic",
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("backend:" + _f.BackendSecret)));
        Assert.Equal(HttpStatusCode.OK, (await _http.SendAsync(good)).StatusCode);

        var bad = new HttpRequestMessage(HttpMethod.Post, "/token") { Content = Form(("grant_type", "client_credentials")) };
        bad.Headers.Authorization = new AuthenticationHeaderValue("Basic",
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("backend:nope")));
        var res = await _http.SendAsync(bad);
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
        Assert.Contains("Basic", res.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task Mfa_user_needs_valid_totp()
    {
        string verifier = Pkce.CreateVerifier();
        var noCode = await Authorize(verifier, "bob", "pw-bob");
        Assert.Equal(HttpStatusCode.Unauthorized, noCode.StatusCode);
        Assert.Contains("mfa_required", await noCode.Content.ReadAsStringAsync());

        string code = new Totp(TimeProvider.System).Generate(_f.BobTotp);
        var ok = await Authorize(verifier, "bob", "pw-bob", code);
        Assert.Equal(HttpStatusCode.Redirect, ok.StatusCode);
    }

    [Fact]
    public async Task Brute_force_gets_429_with_retry_after()
    {
        HttpResponseMessage? last = null;
        for (int i = 0; i < 6; i++) last = await Authorize(Pkce.CreateVerifier(), "locked0", "wrong");
        Assert.Equal((HttpStatusCode)429, last!.StatusCode);
        Assert.NotNull(last.Headers.RetryAfter);
    }
}
