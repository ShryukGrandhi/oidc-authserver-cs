using System.Security.Cryptography;
using OidcAuth.Core;
using OidcAuth.Core.Encoding;
using OidcAuth.Core.Mfa;
using OidcAuth.Core.OAuth;

namespace OidcAuth.Host;

/// <summary>Registers one public client, one confidential client and two users so the server is usable locally.</summary>
internal static class DemoSeed
{
    public static void Apply(AuthServer server, ILogger log)
    {
        server.Clients.Register(OAuthClient.CreatePublic("demo-spa", new[] { "http://localhost:5173/callback" },
            ScopeSet.Of("openid", "profile", "offline_access")));

        var (backend, secret) = OAuthClient.CreateConfidential("demo-backend", Array.Empty<string>(),
            new HashSet<string> { GrantTypes.ClientCredentials }, ScopeSet.Of("reports.read"));
        server.Clients.Register(backend);

        string password = Base64Url.Encode(RandomNumberGenerator.GetBytes(12));
        server.AddUser("alice", password);
        byte[] totpSecret = RandomNumberGenerator.GetBytes(20);
        server.AddUser("bob", password, totpSecret);

        log.LogWarning("Demo data seeded. demo-backend secret: {Secret}. alice/bob password: {Password}. " +
                       "bob TOTP: {Uri}", secret, password,
            Totp.ProvisioningUri("oidc-authserver", "bob", totpSecret));
    }
}
