using System.Text.Json;
using System.Text.Json.Nodes;
using OidcAuth.Core.Encoding;

namespace OidcAuth.Core.Jwt;

public enum JwtError
{
    None,
    Malformed,
    UnsupportedAlgorithm,
    UnknownKey,
    AlgorithmKeyMismatch,
    BadSignature,
    WrongType,
    Expired,
    NotYetValid,
    IssuedInFuture,
    WrongIssuer,
    WrongAudience,
    MissingClaim,
    Revoked,
}

public sealed record JwtValidationResult(JwtError Error, JsonObject? Claims, JsonObject? Header)
{
    public bool IsValid => Error == JwtError.None;
    internal static JwtValidationResult Fail(JwtError e) => new(e, null, null);
}

public interface IKeyResolver
{
    SigningKey? Resolve(string kid);
}

public sealed class JwtValidationOptions
{
    public required string Issuer { get; init; }
    public required IReadOnlyCollection<string> Audiences { get; init; }
    public IReadOnlySet<string> AllowedAlgorithms { get; init; } = new HashSet<string> { "ES256", "RS256" };
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>When set, the header "typ" must match (e.g. "at+jwt" per RFC 9068).</summary>
    public string? RequiredType { get; init; }

    public int MaxTokenLength { get; init; } = 8192;
}

/// <summary>
/// Validates compact JWS tokens. Order matters: structure and algorithm are checked before any key is
/// touched, the signature before the payload is trusted, and only then are time and audience claims read.
/// </summary>
public sealed class JwtValidator
{
    private readonly JwtValidationOptions _options;
    private readonly IKeyResolver _keys;
    private readonly TimeProvider _time;

    public JwtValidator(JwtValidationOptions options, IKeyResolver keys, TimeProvider time)
    {
        _options = options;
        _keys = keys;
        _time = time;
    }

    public JwtValidationResult Validate(string? token)
    {
        if (string.IsNullOrEmpty(token) || token.Length > _options.MaxTokenLength)
            return JwtValidationResult.Fail(JwtError.Malformed);

        int dot1 = token.IndexOf('.');
        int dot2 = dot1 < 0 ? -1 : token.IndexOf('.', dot1 + 1);
        if (dot1 <= 0 || dot2 < 0 || dot2 == dot1 + 1 || dot2 == token.Length - 1 || token.IndexOf('.', dot2 + 1) >= 0)
            return JwtValidationResult.Fail(JwtError.Malformed);

        var header = ParseObject(token.AsSpan(0, dot1));
        if (header is null) return JwtValidationResult.Fail(JwtError.Malformed);

        if (GetString(header, "alg") is not { } alg) return JwtValidationResult.Fail(JwtError.Malformed);
        if (alg.Equals("none", StringComparison.OrdinalIgnoreCase) || !_options.AllowedAlgorithms.Contains(alg))
            return JwtValidationResult.Fail(JwtError.UnsupportedAlgorithm);

        // We implement no JWS extensions, so any "crit" header must be rejected (RFC 7515 §4.1.11).
        if (header.ContainsKey("crit")) return JwtValidationResult.Fail(JwtError.Malformed);

        if (_options.RequiredType is { } requiredTyp)
        {
            string? typ = GetString(header, "typ");
            if (typ is null || !(typ.Equals(requiredTyp, StringComparison.OrdinalIgnoreCase) ||
                                 typ.Equals("application/" + requiredTyp, StringComparison.OrdinalIgnoreCase)))
                return JwtValidationResult.Fail(JwtError.WrongType);
        }

        if (GetString(header, "kid") is not { } kid) return JwtValidationResult.Fail(JwtError.UnknownKey);
        var key = _keys.Resolve(kid);
        if (key is null) return JwtValidationResult.Fail(JwtError.UnknownKey);
        if (!string.Equals(key.Algorithm, alg, StringComparison.Ordinal))
            return JwtValidationResult.Fail(JwtError.AlgorithmKeyMismatch);

        if (!Base64Url.TryDecode(token.AsSpan(dot2 + 1), out var signature))
            return JwtValidationResult.Fail(JwtError.Malformed);

        Span<byte> signingInput = dot2 <= 4096 ? stackalloc byte[dot2] : new byte[dot2];
        System.Text.Encoding.ASCII.GetBytes(token.AsSpan(0, dot2), signingInput);
        if (!key.Verify(signingInput, signature)) return JwtValidationResult.Fail(JwtError.BadSignature);

        var claims = ParseObject(token.AsSpan(dot1 + 1, dot2 - dot1 - 1));
        if (claims is null) return JwtValidationResult.Fail(JwtError.Malformed);

        long now = _time.GetUtcNow().ToUnixTimeSeconds();
        long skew = (long)_options.ClockSkew.TotalSeconds;

        if (!TryGetNumericDate(claims, "exp", out long exp)) return JwtValidationResult.Fail(JwtError.MissingClaim);
        if (now >= exp + skew) return JwtValidationResult.Fail(JwtError.Expired);
        if (TryGetNumericDate(claims, "nbf", out long nbf) && now + skew < nbf)
            return JwtValidationResult.Fail(JwtError.NotYetValid);
        if (TryGetNumericDate(claims, "iat", out long iat) && iat > now + skew)
            return JwtValidationResult.Fail(JwtError.IssuedInFuture);

        if (GetString(claims, "iss") != _options.Issuer) return JwtValidationResult.Fail(JwtError.WrongIssuer);
        if (!AudienceMatches(claims["aud"])) return JwtValidationResult.Fail(JwtError.WrongAudience);

        return new JwtValidationResult(JwtError.None, claims, header);
    }

    private bool AudienceMatches(JsonNode? aud)
    {
        switch (aud)
        {
            case JsonValue v when v.TryGetValue<string>(out var s):
                return _options.Audiences.Contains(s);
            case JsonArray arr:
                foreach (var item in arr)
                    if (item is JsonValue iv && iv.TryGetValue<string>(out var a) && _options.Audiences.Contains(a))
                        return true;
                return false;
            default:
                return false;
        }
    }

    private static JsonObject? ParseObject(ReadOnlySpan<char> segment)
    {
        if (!Base64Url.TryDecode(segment, out var bytes)) return null;
        try
        {
            // Duplicate member names are a known JWT parser-differential vector; reject them outright.
            using var doc = JsonDocument.Parse(bytes);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return null;
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var prop in doc.RootElement.EnumerateObject())
                if (!seen.Add(prop.Name)) return null;
            return JsonObject.Create(doc.RootElement.Clone());
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public static string? GetString(JsonObject obj, string name) =>
        obj[name] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

    public static bool TryGetNumericDate(JsonObject obj, string name, out long value)
    {
        value = 0;
        if (obj[name] is not JsonValue v) return false;
        if (v.TryGetValue<long>(out value)) return true;
        if (v.TryGetValue<double>(out double d) && double.IsFinite(d))
        {
            value = (long)Math.Floor(d);
            return true;
        }
        return false;
    }
}
