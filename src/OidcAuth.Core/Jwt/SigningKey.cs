using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using OidcAuth.Core.Encoding;

namespace OidcAuth.Core.Jwt;

/// <summary>
/// A key bound to exactly one JWS algorithm. Binding the algorithm to the key (rather than trusting the
/// token header) is what prevents algorithm-confusion attacks such as RS256-to-HS256 downgrades.
/// </summary>
public abstract class SigningKey : IDisposable
{
    public abstract string Kid { get; }
    public abstract string Algorithm { get; }
    public abstract bool CanSign { get; }
    public abstract byte[] Sign(ReadOnlySpan<byte> data);
    public abstract bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);

    /// <summary>Public JWK for publication in a JWKS document; null for symmetric keys.</summary>
    public abstract JsonObject? ToPublicJwk();

    public virtual void Dispose() => GC.SuppressFinalize(this);

    /// <summary>RFC 7638 thumbprint over the canonical, lexicographically ordered required members.</summary>
    protected static string Thumbprint(string canonicalJson) =>
        Base64Url.Encode(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(canonicalJson)));
}

public sealed class RsaSigningKey : SigningKey
{
    private readonly RSA _rsa;
    private readonly string _n;
    private readonly string _e;

    public RsaSigningKey(RSA rsa, bool hasPrivateKey)
    {
        if (rsa.KeySize < 2048) throw new ArgumentException("RSA keys must be at least 2048 bits.", nameof(rsa));
        _rsa = rsa;
        CanSign = hasPrivateKey;
        var p = rsa.ExportParameters(false);
        _n = Base64Url.Encode(p.Modulus);
        _e = Base64Url.Encode(p.Exponent);
        Kid = ComputeThumbprint(_n, _e);
    }

    public static RsaSigningKey Generate(int bits = 2048) => new(RSA.Create(bits), hasPrivateKey: true);

    public static RsaSigningKey FromPublic(string n, string e)
    {
        var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters { Modulus = Base64Url.Decode(n), Exponent = Base64Url.Decode(e) });
        return new RsaSigningKey(rsa, hasPrivateKey: false);
    }

    public static string ComputeThumbprint(string n, string e) =>
        Thumbprint($"{{\"e\":\"{e}\",\"kty\":\"RSA\",\"n\":\"{n}\"}}");

    public override string Kid { get; }
    public override string Algorithm => "RS256";
    public override bool CanSign { get; }

    public override byte[] Sign(ReadOnlySpan<byte> data) =>
        _rsa.SignData(data.ToArray(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

    public override bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature) =>
        signature.Length == _rsa.KeySize / 8 &&
        _rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

    public override JsonObject ToPublicJwk() => new()
    {
        ["kty"] = "RSA", ["use"] = "sig", ["alg"] = Algorithm, ["kid"] = Kid, ["n"] = _n, ["e"] = _e,
    };

    public override void Dispose()
    {
        _rsa.Dispose();
        base.Dispose();
    }
}

public sealed class EcdsaSigningKey : SigningKey
{
    private readonly ECDsa _ec;
    private readonly string _x;
    private readonly string _y;

    public EcdsaSigningKey(ECDsa ec, bool hasPrivateKey)
    {
        var p = ec.ExportParameters(false);
        if (ec.KeySize != 256 || p.Q.X is not { Length: 32 })
            throw new ArgumentException("Only P-256 keys are supported for ES256.", nameof(ec));
        _ec = ec;
        CanSign = hasPrivateKey;
        _x = Base64Url.Encode(p.Q.X);
        _y = Base64Url.Encode(p.Q.Y);
        Kid = ComputeThumbprint(_x, _y);
    }

    public static EcdsaSigningKey Generate() => new(ECDsa.Create(ECCurve.NamedCurves.nistP256), hasPrivateKey: true);

    public static EcdsaSigningKey FromPublic(string x, string y)
    {
        var ec = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = Base64Url.Decode(x), Y = Base64Url.Decode(y) },
        });
        return new EcdsaSigningKey(ec, hasPrivateKey: false);
    }

    public static string ComputeThumbprint(string x, string y) =>
        Thumbprint($"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}");

    public override string Kid { get; }
    public override string Algorithm => "ES256";
    public override bool CanSign { get; }

    // .NET emits IEEE P1363 (r||s) by default, which is the JWS encoding; DER would be wrong here.
    public override byte[] Sign(ReadOnlySpan<byte> data) => _ec.SignData(data, HashAlgorithmName.SHA256);

    public override bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature) =>
        signature.Length == 64 && _ec.VerifyData(data, signature, HashAlgorithmName.SHA256);

    public override JsonObject ToPublicJwk() => new()
    {
        ["kty"] = "EC", ["use"] = "sig", ["alg"] = Algorithm, ["kid"] = Kid, ["crv"] = "P-256", ["x"] = _x, ["y"] = _y,
    };

    public override void Dispose()
    {
        _ec.Dispose();
        base.Dispose();
    }
}

public sealed class HmacSigningKey : SigningKey
{
    private readonly byte[] _secret;

    public HmacSigningKey(byte[] secret, string kid)
    {
        if (secret.Length < 32) throw new ArgumentException("HS256 secrets must be at least 256 bits.", nameof(secret));
        _secret = secret.ToArray();
        Kid = kid;
    }

    public static HmacSigningKey Generate() =>
        new(RandomNumberGenerator.GetBytes(32), Base64Url.Encode(RandomNumberGenerator.GetBytes(8)));

    public override string Kid { get; }
    public override string Algorithm => "HS256";
    public override bool CanSign => true;

    public override byte[] Sign(ReadOnlySpan<byte> data) => HMACSHA256.HashData(_secret, data);

    public override bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        Span<byte> expected = stackalloc byte[32];
        HMACSHA256.HashData(_secret, data, expected);
        return CryptographicOperations.FixedTimeEquals(expected, signature);
    }

    public override JsonObject? ToPublicJwk() => null;

    public override void Dispose()
    {
        CryptographicOperations.ZeroMemory(_secret);
        base.Dispose();
    }
}
