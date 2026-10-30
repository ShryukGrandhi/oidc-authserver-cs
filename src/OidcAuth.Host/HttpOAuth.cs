using System.Text;
using System.Text.Json.Nodes;
using OidcAuth.Core.OAuth;

namespace OidcAuth.Host;

/// <summary>HTTP glue: form parsing, client authentication headers and RFC 6749 error responses.</summary>
internal static class HttpOAuth
{
    public static async Task<Dictionary<string, string>?> ReadFormAsync(HttpRequest request)
    {
        if (!request.HasFormContentType) return null;
        var form = await request.ReadFormAsync();
        var dict = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (key, values) in form)
        {
            // RFC 6749 §3.1: parameters must not be included more than once.
            if (values.Count != 1) return null;
            dict[key] = values[0]!;
        }
        return dict;
    }

    /// <summary>Parses "Authorization: Basic". Id and secret are form-urlencoded before base64 (RFC 6749 §2.3.1).</summary>
    public static BasicCredentials? ParseBasic(HttpRequest request, out bool malformed)
    {
        malformed = false;
        string? header = request.Headers.Authorization;
        if (header is null || !header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase)) return null;
        try
        {
            string raw = Encoding.UTF8.GetString(Convert.FromBase64String(header[6..].Trim()));
            int colon = raw.IndexOf(':', StringComparison.Ordinal);
            if (colon < 0)
            {
                malformed = true;
                return null;
            }
            return new BasicCredentials(FormDecode(raw[..colon]), FormDecode(raw[(colon + 1)..]));
        }
        catch (FormatException)
        {
            malformed = true;
            return null;
        }
    }

    private static string FormDecode(string s) => Uri.UnescapeDataString(s.Replace('+', ' '));

    public static IResult Error(HttpContext ctx, OAuthError e)
    {
        NoStore(ctx);
        if (e.Status == 401 && ctx.Request.Headers.Authorization.Count > 0)
            ctx.Response.Headers.WWWAuthenticate = "Basic realm=\"oidc-authserver\"";
        return Results.Json(new JsonObject { ["error"] = e.Code, ["error_description"] = e.Description },
            statusCode: e.Status);
    }

    public static void NoStore(HttpContext ctx)
    {
        ctx.Response.Headers.CacheControl = "no-store";
        ctx.Response.Headers.Pragma = "no-cache";
    }
}
