using System.Text.Json.Nodes;
using OidcAuth.Core.Jwt;
using OidcAuth.Core.Mfa;
using OidcAuth.Core.OAuth;
using OidcAuth.Core.Passwords;
using OidcAuth.Core.Users;

namespace OidcAuth.Core;

/// <summary>Wires the components of the authorization server together. One instance per process.</summary>
public sealed class AuthServer
{
    public AuthServer(AuthServerOptions options, TimeProvider time, SigningKey? initialKey = null,
        PasswordHasher? hasher = null)
    {
        Options = options;
        Time = time;
        // Retired keys stay published for longer than any token they signed can live.
        var keyGrace = (options.AccessTokenLifetime > options.IdTokenLifetime
            ? options.AccessTokenLifetime : options.IdTokenLifetime) + TimeSpan.FromMinutes(5);
        Keys = new SigningKeyRing(initialKey ?? EcdsaSigningKey.Generate(), keyGrace, time);
        Clients = new ClientRegistry();
        Users = new InMemoryUserStore();
        Hasher = hasher ?? new PasswordHasher();
        Totp = new Totp(time);
        Authenticator = new UserAuthenticator(Users, Hasher, Totp,
            perUser: new LoginThrottle(time, 5, TimeSpan.FromSeconds(1), TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(15)),
            perIp: new LoginThrottle(time, 20, TimeSpan.FromSeconds(1), TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(15)));
        Codes = new AuthorizationCodeStore(time);
        Refresh = new RefreshTokenService(time, options.RefreshTokenIdleLifetime, options.RefreshTokenAbsoluteLifetime);
        Issuer = new TokenIssuer(options, Keys, time);
        Authorization = new AuthorizationService(Clients, Codes, options, time);
        TokenEndpoint = new TokenEndpoint(Clients, Codes, Refresh, Issuer, options);
        Management = new TokenManagement(Refresh, Issuer);
    }

    public AuthServerOptions Options { get; }
    public TimeProvider Time { get; }
    public SigningKeyRing Keys { get; }
    public ClientRegistry Clients { get; }
    public InMemoryUserStore Users { get; }
    public PasswordHasher Hasher { get; }
    public Totp Totp { get; }
    public UserAuthenticator Authenticator { get; }
    public AuthorizationCodeStore Codes { get; }
    public RefreshTokenService Refresh { get; }
    public TokenIssuer Issuer { get; }
    public AuthorizationService Authorization { get; }
    public TokenEndpoint TokenEndpoint { get; }
    public TokenManagement Management { get; }

    public UserAccount AddUser(string username, string password, byte[]? totpSecret = null)
    {
        var user = new UserAccount
        {
            SubjectId = Guid.NewGuid().ToString("N"),
            Username = username,
            PasswordHash = Hasher.Hash(password),
            TotpSecret = totpSecret,
        };
        Users.Add(user);
        return user;
    }

    /// <summary>Periodic housekeeping: expired codes, refresh tokens, denylisted JTIs and retired keys.</summary>
    public void Prune()
    {
        Codes.Prune();
        Refresh.Prune();
        Issuer.PruneRevoked();
        Keys.PruneExpired();
    }

    public JsonObject DiscoveryDocument(string baseUrl) => new()
    {
        ["issuer"] = Options.Issuer,
        ["authorization_endpoint"] = baseUrl + "/authorize",
        ["token_endpoint"] = baseUrl + "/token",
        ["userinfo_endpoint"] = baseUrl + "/userinfo",
        ["jwks_uri"] = baseUrl + "/jwks.json",
        ["introspection_endpoint"] = baseUrl + "/introspect",
        ["revocation_endpoint"] = baseUrl + "/revoke",
        ["response_types_supported"] = new JsonArray("code"),
        ["grant_types_supported"] = new JsonArray(GrantTypes.AuthorizationCode, GrantTypes.RefreshToken, GrantTypes.ClientCredentials),
        ["subject_types_supported"] = new JsonArray("public"),
        ["id_token_signing_alg_values_supported"] = new JsonArray("ES256", "RS256"),
        ["code_challenge_methods_supported"] = new JsonArray(Pkce.MethodS256),
        ["token_endpoint_auth_methods_supported"] = new JsonArray("client_secret_basic", "client_secret_post", "none"),
        ["authorization_response_iss_parameter_supported"] = true,
        ["scopes_supported"] = new JsonArray("openid", "profile", "offline_access"),
    };
}
