namespace OidcAuth.Core.OAuth;

public sealed class AuthServerOptions
{
    public required string Issuer { get; init; }

    /// <summary>The "aud" placed in access tokens; resource servers validate against it.</summary>
    public string ResourceAudience { get; init; } = "api";

    public TimeSpan AccessTokenLifetime { get; init; } = TimeSpan.FromMinutes(10);
    public TimeSpan IdTokenLifetime { get; init; } = TimeSpan.FromMinutes(5);
    public TimeSpan AuthorizationCodeLifetime { get; init; } = TimeSpan.FromSeconds(60);
    public TimeSpan RefreshTokenIdleLifetime { get; init; } = TimeSpan.FromDays(1);
    public TimeSpan RefreshTokenAbsoluteLifetime { get; init; } = TimeSpan.FromDays(30);
}
