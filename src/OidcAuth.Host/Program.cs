using System.Text.Json.Nodes;
using OidcAuth.Core;
using OidcAuth.Core.Jwt;
using OidcAuth.Core.OAuth;
using OidcAuth.Core.Users;
using OidcAuth.Host;

var builder = WebApplication.CreateBuilder(args);
var authConfig = builder.Configuration.GetSection("Auth");

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton(sp => new AuthServer(
    new AuthServerOptions { Issuer = authConfig["Issuer"] ?? "http://localhost:5080" },
    sp.GetRequiredService<TimeProvider>()));
builder.Services.AddHostedService<HousekeepingService>();

var app = builder.Build();
var server = app.Services.GetRequiredService<AuthServer>();
if (authConfig.GetValue<bool>("SeedDemoData")) DemoSeed.Apply(server, app.Logger);

app.MapGet("/.well-known/openid-configuration", (HttpContext ctx) =>
    Results.Json(server.DiscoveryDocument(server.Options.Issuer)));

app.MapGet("/jwks.json", (HttpContext ctx) =>
{
    ctx.Response.Headers.CacheControl = "public, max-age=300";
    return Results.Json(server.Keys.GetJwks());
});

// Headless authorize: the resource owner's credentials are posted alongside the authorization request.
// A browser deployment would render a login/consent page here; the protocol checks are identical.
app.MapPost("/authorize", async (HttpContext ctx) =>
{
    var form = await HttpOAuth.ReadFormAsync(ctx.Request);
    if (form is null) return HttpOAuth.Error(ctx, OAuthError.InvalidRequest("Expected a form body without repeated parameters."));

    var v = server.Authorization.Validate(new AuthorizationRequest(
        form.GetValueOrDefault("response_type"), form.GetValueOrDefault("client_id"),
        form.GetValueOrDefault("redirect_uri"), form.GetValueOrDefault("scope"), form.GetValueOrDefault("state"),
        form.GetValueOrDefault("code_challenge"), form.GetValueOrDefault("code_challenge_method"),
        form.GetValueOrDefault("nonce")));
    if (!v.IsValid)
        return v.ErrorRedirectUri is { } errUrl ? Results.Redirect(errUrl) : HttpOAuth.Error(ctx, v.Error!);

    string ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    var auth = server.Authenticator.Authenticate(form.GetValueOrDefault("username") ?? "",
        form.GetValueOrDefault("password") ?? "", form.GetValueOrDefault("totp"), ip);

    switch (auth.Outcome)
    {
        case AuthOutcome.Success:
            return Results.Redirect(server.Authorization.IssueCode(v.Request!, auth.User!.SubjectId, server.Time.GetUtcNow()));
        case AuthOutcome.LockedOut:
            ctx.Response.Headers.RetryAfter = Math.Ceiling(auth.RetryAfter.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture);
            return Results.Json(new JsonObject { ["error"] = "login_locked" }, statusCode: 429);
        case AuthOutcome.MfaRequired:
            return Results.Json(new JsonObject { ["error"] = "mfa_required" }, statusCode: 401);
        default:
            // Same body for unknown user, wrong password and wrong TOTP: no account enumeration.
            return Results.Json(new JsonObject { ["error"] = "login_failed" }, statusCode: 401);
    }
});

app.MapPost("/token", async (HttpContext ctx) =>
{
    var form = await HttpOAuth.ReadFormAsync(ctx.Request);
    if (form is null) return HttpOAuth.Error(ctx, OAuthError.InvalidRequest("Expected a form body without repeated parameters."));
    var basic = HttpOAuth.ParseBasic(ctx.Request, out bool malformed);
    if (malformed) return HttpOAuth.Error(ctx, OAuthError.InvalidClient("Malformed Authorization header."));

    var result = server.TokenEndpoint.Handle(form, basic);
    if (!result.IsOk) return HttpOAuth.Error(ctx, result.Error!);
    HttpOAuth.NoStore(ctx);
    return Results.Json(result.Value);
});

app.MapPost("/introspect", async (HttpContext ctx) =>
{
    var form = await HttpOAuth.ReadFormAsync(ctx.Request);
    if (form is null) return HttpOAuth.Error(ctx, OAuthError.InvalidRequest("Expected a form body."));
    var basic = HttpOAuth.ParseBasic(ctx.Request, out bool malformed);
    var caller = malformed ? OAuthError.InvalidClient("Malformed Authorization header.")
                           : server.TokenEndpoint.AuthenticateClient(form, basic);
    if (!caller.IsOk) return HttpOAuth.Error(ctx, caller.Error!);

    var r = server.Management.Introspect(caller.Value!, form.GetValueOrDefault("token"), form.GetValueOrDefault("token_type_hint"));
    if (!r.IsOk) return HttpOAuth.Error(ctx, r.Error!);
    HttpOAuth.NoStore(ctx);
    return Results.Json(r.Value);
});

app.MapPost("/revoke", async (HttpContext ctx) =>
{
    var form = await HttpOAuth.ReadFormAsync(ctx.Request);
    if (form is null) return HttpOAuth.Error(ctx, OAuthError.InvalidRequest("Expected a form body."));
    var basic = HttpOAuth.ParseBasic(ctx.Request, out bool malformed);
    var caller = malformed ? OAuthError.InvalidClient("Malformed Authorization header.")
                           : server.TokenEndpoint.AuthenticateClient(form, basic);
    if (!caller.IsOk) return HttpOAuth.Error(ctx, caller.Error!);

    server.Management.Revoke(caller.Value!, form.GetValueOrDefault("token"));
    return Results.Ok();
});

app.MapGet("/userinfo", (HttpContext ctx) =>
{
    string? header = ctx.Request.Headers.Authorization;
    string? token = header is not null && header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? header[7..].Trim() : null;
    var r = server.Issuer.ValidateAccessToken(token);
    if (!r.IsValid)
    {
        ctx.Response.Headers.WWWAuthenticate = token is null
            ? "Bearer"
            : $"Bearer error=\"invalid_token\", error_description=\"{r.Error}\"";
        return Results.StatusCode(401);
    }

    var claims = r.Claims!;
    ScopeSet.TryParse(JwtValidator.GetString(claims, "scope"), out var scopes);
    if (!scopes.Contains("openid"))
    {
        ctx.Response.Headers.WWWAuthenticate = "Bearer error=\"insufficient_scope\", scope=\"openid\"";
        return Results.StatusCode(403);
    }

    string sub = JwtValidator.GetString(claims, "sub")!;
    var body = new JsonObject { ["sub"] = sub };
    if (scopes.Contains("profile") && server.Users.FindBySubject(sub) is { } user)
        body["preferred_username"] = user.Username;
    return Results.Json(body);
});

app.Run();

public partial class Program;
