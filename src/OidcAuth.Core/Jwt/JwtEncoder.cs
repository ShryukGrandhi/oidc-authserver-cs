using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using OidcAuth.Core.Encoding;

namespace OidcAuth.Core.Jwt;

public static class JwtEncoder
{
    // The default encoder HTML-escapes characters such as '+', producing "at+jwt". That is valid JSON but
    // trips naive typ comparisons in other stacks; tokens never land in HTML, so minimal escaping is safe here.
    private static readonly JsonSerializerOptions Compact = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    /// <summary>Produces a compact JWS: base64url(header).base64url(payload).base64url(signature).</summary>
    public static string Encode(JsonObject payload, SigningKey key, string typ = "JWT")
    {
        if (!key.CanSign) throw new InvalidOperationException($"Key {key.Kid} has no private material.");
        var header = new JsonObject { ["alg"] = key.Algorithm, ["typ"] = typ, ["kid"] = key.Kid };
        string signingInput =
            Base64Url.Encode(System.Text.Encoding.UTF8.GetBytes(header.ToJsonString(Compact))) + "." +
            Base64Url.Encode(System.Text.Encoding.UTF8.GetBytes(payload.ToJsonString(Compact)));
        byte[] signature = key.Sign(System.Text.Encoding.ASCII.GetBytes(signingInput));
        return signingInput + "." + Base64Url.Encode(signature);
    }
}
