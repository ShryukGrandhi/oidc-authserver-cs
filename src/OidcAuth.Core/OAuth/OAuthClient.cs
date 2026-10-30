using System.Collections.Concurrent;
using System.Security.Cryptography;
using OidcAuth.Core.Encoding;

namespace OidcAuth.Core.OAuth;

public static class GrantTypes
{
    public const string AuthorizationCode = "authorization_code";
    public const string RefreshToken = "refresh_token";
    public const string ClientCredentials = "client_credentials";
}

public sealed class OAuthClient
{
    public required string ClientId { get; init; }

    /// <summary>SHA-256 of the client secret; null for public clients (SPAs, native apps).</summary>
    public byte[]? SecretSha256 { get; init; }

    public required IReadOnlyList<string> RedirectUris { get; init; }
    public required IReadOnlySet<string> AllowedGrantTypes { get; init; }
    public required ScopeSet AllowedScopes { get; init; }

    public bool IsPublic => SecretSha256 is null;

    /// <summary>
    /// Client secrets are 256-bit random values, not human passwords, so a fast hash is sufficient:
    /// there is no dictionary to brute-force. Comparison is constant time.
    /// </summary>
    public bool VerifySecret(string? secret)
    {
        if (SecretSha256 is null || secret is null) return false;
        return CryptographicOperations.FixedTimeEquals(
            SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(secret)), SecretSha256);
    }

    public static (OAuthClient Client, string Secret) CreateConfidential(string clientId, IReadOnlyList<string> redirectUris,
        IReadOnlySet<string> grants, ScopeSet scopes)
    {
        string secret = Base64Url.Encode(RandomNumberGenerator.GetBytes(32));
        var client = new OAuthClient
        {
            ClientId = clientId,
            SecretSha256 = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(secret)),
            RedirectUris = redirectUris,
            AllowedGrantTypes = grants,
            AllowedScopes = scopes,
        };
        return (client, secret);
    }

    public static OAuthClient CreatePublic(string clientId, IReadOnlyList<string> redirectUris, ScopeSet scopes) => new()
    {
        ClientId = clientId,
        RedirectUris = redirectUris,
        AllowedGrantTypes = new HashSet<string> { GrantTypes.AuthorizationCode, GrantTypes.RefreshToken },
        AllowedScopes = scopes,
    };
}

public sealed class ClientRegistry
{
    private readonly ConcurrentDictionary<string, OAuthClient> _clients = new(StringComparer.Ordinal);

    public void Register(OAuthClient client)
    {
        if (client.IsPublic && client.AllowedGrantTypes.Contains(GrantTypes.ClientCredentials))
            throw new ArgumentException("Public clients cannot use client_credentials.", nameof(client));
        foreach (var uri in client.RedirectUris)
            if (!Uri.TryCreate(uri, UriKind.Absolute, out var u) || u.Fragment.Length > 0)
                throw new ArgumentException($"Redirect URI '{uri}' must be absolute without a fragment.", nameof(client));
        if (!_clients.TryAdd(client.ClientId, client))
            throw new InvalidOperationException($"Client {client.ClientId} already registered.");
    }

    public OAuthClient? Find(string? clientId) => clientId is null ? null : _clients.GetValueOrDefault(clientId);
}
