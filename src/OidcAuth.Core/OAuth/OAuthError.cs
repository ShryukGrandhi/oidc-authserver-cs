namespace OidcAuth.Core.OAuth;

/// <summary>An RFC 6749 §5.2 error. <see cref="Status"/> is the HTTP status the endpoint should return.</summary>
public sealed record OAuthError(string Code, string Description, int Status = 400)
{
    public static OAuthError InvalidRequest(string d) => new("invalid_request", d);
    public static OAuthError InvalidClient(string d) => new("invalid_client", d, 401);
    public static OAuthError InvalidGrant(string d) => new("invalid_grant", d);
    public static OAuthError UnauthorizedClient(string d) => new("unauthorized_client", d);
    public static OAuthError UnsupportedGrantType(string d) => new("unsupported_grant_type", d);
    public static OAuthError UnsupportedResponseType(string d) => new("unsupported_response_type", d);
    public static OAuthError InvalidScope(string d) => new("invalid_scope", d);
    public static OAuthError AccessDenied(string d) => new("access_denied", d, 403);
}

public readonly struct OAuthResult<T> where T : class
{
    private OAuthResult(T? value, OAuthError? error)
    {
        Value = value;
        Error = error;
    }

    public T? Value { get; }
    public OAuthError? Error { get; }
    public bool IsOk => Error is null;

    public static implicit operator OAuthResult<T>(T value) => new(value, null);
    public static implicit operator OAuthResult<T>(OAuthError error) => new(null, error);
}
