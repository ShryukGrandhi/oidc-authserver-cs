namespace OidcAuth.Core.OAuth;

public sealed record AuthorizationRequest(
    string? ResponseType,
    string? ClientId,
    string? RedirectUri,
    string? Scope,
    string? State,
    string? CodeChallenge,
    string? CodeChallengeMethod,
    string? Nonce);

public sealed record ValidatedAuthorization(OAuthClient Client, string RedirectUri, ScopeSet Scopes, string CodeChallenge,
    string? State, string? Nonce);

/// <summary>
/// Outcome of /authorize validation. When the client or redirect URI cannot be trusted the error must be
/// shown to the user directly; redirecting would turn the server into an open redirector (RFC 6749 §4.1.2.1).
/// </summary>
public sealed record AuthorizationValidation(ValidatedAuthorization? Request, OAuthError? Error, string? ErrorRedirectUri)
{
    public bool IsValid => Request is not null;
}

public sealed class AuthorizationService
{
    private readonly ClientRegistry _clients;
    private readonly AuthorizationCodeStore _codes;
    private readonly AuthServerOptions _options;
    private readonly TimeProvider _time;

    public AuthorizationService(ClientRegistry clients, AuthorizationCodeStore codes, AuthServerOptions options,
        TimeProvider time)
    {
        _clients = clients;
        _codes = codes;
        _options = options;
        _time = time;
    }

    public AuthorizationValidation Validate(AuthorizationRequest req)
    {
        var client = _clients.Find(req.ClientId);
        if (client is null)
            return new(null, OAuthError.InvalidRequest("Unknown client_id."), null);

        // Exact string match, no wildcards or prefix matching (OAuth 2.1 / RFC 9700 §4.1.3).
        if (req.RedirectUri is null || !client.RedirectUris.Contains(req.RedirectUri, StringComparer.Ordinal))
            return new(null, OAuthError.InvalidRequest("redirect_uri is missing or not registered."), null);

        AuthorizationValidation Redirect(OAuthError e) => new(null, e, BuildErrorRedirect(req.RedirectUri, e, req.State));

        if (req.ResponseType != "code")
            return Redirect(OAuthError.UnsupportedResponseType("Only response_type=code is supported."));
        if (!client.AllowedGrantTypes.Contains(GrantTypes.AuthorizationCode))
            return Redirect(OAuthError.UnauthorizedClient("Client may not use the authorization code grant."));
        if (!ScopeSet.TryParse(req.Scope, out var scopes) || scopes.IsEmpty)
            return Redirect(OAuthError.InvalidScope("scope is missing or malformed."));
        if (!scopes.IsSubsetOf(client.AllowedScopes))
            return Redirect(OAuthError.InvalidScope("Requested scope exceeds what the client is allowed."));

        // PKCE is mandatory for every client, confidential or not, and only S256 is accepted.
        if (req.CodeChallengeMethod != Pkce.MethodS256)
            return Redirect(OAuthError.InvalidRequest("code_challenge_method must be S256."));
        if (!Pkce.IsValidS256Challenge(req.CodeChallenge))
            return Redirect(OAuthError.InvalidRequest("code_challenge is missing or malformed."));

        return new(new ValidatedAuthorization(client, req.RedirectUri, scopes, req.CodeChallenge!, req.State, req.Nonce),
            null, null);
    }

    /// <summary>Call after the resource owner has authenticated and consented. Returns the redirect URL.</summary>
    public string IssueCode(ValidatedAuthorization req, string subject, DateTimeOffset authTime)
    {
        var now = _time.GetUtcNow();
        string code = _codes.Issue(new AuthorizationGrant(req.Client.ClientId, req.RedirectUri, subject, req.Scopes,
            req.CodeChallenge, req.Nonce, authTime, now + _options.AuthorizationCodeLifetime));
        // "iss" in the response lets clients detect mix-up attacks (RFC 9207).
        return AppendQuery(req.RedirectUri, ("code", code), ("state", req.State), ("iss", _options.Issuer));
    }

    private string BuildErrorRedirect(string redirectUri, OAuthError e, string? state) =>
        AppendQuery(redirectUri, ("error", e.Code), ("error_description", e.Description), ("state", state),
            ("iss", _options.Issuer));

    internal static string AppendQuery(string uri, params (string Key, string? Value)[] pairs)
    {
        var sb = new System.Text.StringBuilder(uri);
        char sep = uri.Contains('?', StringComparison.Ordinal) ? '&' : '?';
        foreach (var (k, v) in pairs)
        {
            if (v is null) continue;
            sb.Append(sep).Append(Uri.EscapeDataString(k)).Append('=').Append(Uri.EscapeDataString(v));
            sep = '&';
        }
        return sb.ToString();
    }
}
