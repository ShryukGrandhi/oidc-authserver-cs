using OidcAuth.Core;
using OidcAuth.Core.OAuth;
using OidcAuth.Core.Passwords;

namespace OidcAuth.Tests;

public sealed class ManualTime : TimeProvider
{
    private DateTimeOffset _now;

    public ManualTime(DateTimeOffset? start = null) => _now = start ?? new DateTimeOffset(2026, 1, 15, 12, 0, 0, TimeSpan.Zero);

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan by) => _now += by;

    public void Set(DateTimeOffset at) => _now = at;
}

/// <summary>An AuthServer on a manual clock with three registered clients and one user.</summary>
public sealed class Harness
{
    public const string SpaRedirect = "https://spa.example/callback";
    public const string WebRedirect = "https://web.example/oauth/cb";
    public const string Password = "correct horse battery staple";

    public Harness(ManualTime? time = null)
    {
        Time = time ?? new ManualTime();
        Server = new AuthServer(new AuthServerOptions { Issuer = "https://auth.example" }, Time,
            hasher: new PasswordHasher(iterations: 1_000));

        Server.Clients.Register(OAuthClient.CreatePublic("spa", new[] { SpaRedirect },
            ScopeSet.Of("openid", "profile", "offline_access", "api.read")));

        (var web, WebSecret) = OAuthClient.CreateConfidential("web", new[] { WebRedirect },
            new HashSet<string> { GrantTypes.AuthorizationCode, GrantTypes.RefreshToken },
            ScopeSet.Of("openid", "profile", "api.read", "api.write"));
        Server.Clients.Register(web);

        (var svc, SvcSecret) = OAuthClient.CreateConfidential("svc", Array.Empty<string>(),
            new HashSet<string> { GrantTypes.ClientCredentials }, ScopeSet.Of("reports.read", "reports.write"));
        Server.Clients.Register(svc);

        Alice = Server.AddUser("alice", Password);
    }

    public ManualTime Time { get; }
    public AuthServer Server { get; }
    public string WebSecret { get; }
    public string SvcSecret { get; }
    public Core.Users.UserAccount Alice { get; }

    /// <summary>Runs /authorize for alice and returns the code plus the verifier the client must later present.</summary>
    public (string Code, string Verifier, string RedirectUrl) Authorize(string clientId = "spa", string scope = "openid api.read",
        string? nonce = "n-0S6_WzA2Mj", string? redirect = null)
    {
        string verifier = Pkce.CreateVerifier();
        redirect ??= clientId == "spa" ? SpaRedirect : WebRedirect;
        var v = Server.Authorization.Validate(new AuthorizationRequest("code", clientId, redirect, scope, "xyz",
            Pkce.ComputeChallenge(verifier), "S256", nonce));
        Assert.True(v.IsValid, v.Error?.Description);
        string url = Server.Authorization.IssueCode(v.Request!, Alice.SubjectId, Time.GetUtcNow());
        return (QueryParam(url, "code")!, verifier, url);
    }

    public OAuthResult<TokenResponse> Exchange(string code, string verifier, string clientId = "spa", string? redirect = null)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = redirect ?? (clientId == "spa" ? SpaRedirect : WebRedirect),
            ["code_verifier"] = verifier,
        };
        BasicCredentials? basic = null;
        if (clientId == "web") basic = new BasicCredentials("web", WebSecret);
        else form["client_id"] = clientId;
        return Server.TokenEndpoint.Handle(form, basic);
    }

    public OAuthResult<TokenResponse> RefreshAs(string clientId, string refreshToken, string? scope = null)
    {
        var form = new Dictionary<string, string> { ["grant_type"] = "refresh_token", ["refresh_token"] = refreshToken };
        if (scope is not null) form["scope"] = scope;
        BasicCredentials? basic = null;
        if (clientId == "web") basic = new BasicCredentials("web", WebSecret);
        else form["client_id"] = clientId;
        return Server.TokenEndpoint.Handle(form, basic);
    }

    public TokenResponse LoginSpa(string scope = "openid api.read")
    {
        var (code, verifier, _) = Authorize(scope: scope);
        var r = Exchange(code, verifier);
        Assert.True(r.IsOk, r.Error?.Description);
        return r.Value!;
    }

    public static string? QueryParam(string url, string name)
    {
        var query = new Uri(url).Query.TrimStart('?');
        foreach (var pair in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = pair.IndexOf('=');
            if (Uri.UnescapeDataString(pair[..eq]) == name) return Uri.UnescapeDataString(pair[(eq + 1)..]);
        }
        return null;
    }
}
