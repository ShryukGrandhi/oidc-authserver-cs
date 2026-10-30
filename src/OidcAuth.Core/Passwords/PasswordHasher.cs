using System.Globalization;
using System.Security.Cryptography;

namespace OidcAuth.Core.Passwords;

public enum PasswordVerification
{
    Failed,
    Success,

    /// <summary>Correct password, but stored with weaker parameters than current policy.</summary>
    SuccessRehashNeeded,
}

/// <summary>
/// PBKDF2-HMAC-SHA256 password hashing with a self-describing encoding:
/// <c>pbkdf2-sha256$&lt;iterations&gt;$&lt;salt b64&gt;$&lt;hash b64&gt;</c>. Storing the work factor
/// with each hash lets the policy be raised later and old hashes upgraded on the next successful login.
/// </summary>
public sealed class PasswordHasher
{
    public const string Scheme = "pbkdf2-sha256";
    public const int DefaultIterations = 600_000; // OWASP 2023 guidance for PBKDF2-HMAC-SHA256
    private const int SaltSize = 16;
    private const int HashSize = 32;
    private const int MaxIterations = 10_000_000;

    private readonly Lazy<string> _dummyHash;

    public PasswordHasher(int iterations = DefaultIterations)
    {
        if (iterations is < 1 or > MaxIterations) throw new ArgumentOutOfRangeException(nameof(iterations));
        Iterations = iterations;
        _dummyHash = new Lazy<string>(() => Hash(Convert.ToBase64String(RandomNumberGenerator.GetBytes(16))));
    }

    public int Iterations { get; }

    public string Hash(string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, HashSize);
        return string.Create(CultureInfo.InvariantCulture,
            $"{Scheme}${Iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}");
    }

    public PasswordVerification Verify(string encoded, string password)
    {
        if (!TryParse(encoded, out int iterations, out var salt, out var expected)) return PasswordVerification.Failed;
        byte[] actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, expected.Length);
        if (!CryptographicOperations.FixedTimeEquals(actual, expected)) return PasswordVerification.Failed;
        return iterations < Iterations ? PasswordVerification.SuccessRehashNeeded : PasswordVerification.Success;
    }

    /// <summary>
    /// Burns the same CPU as a real verification. Called for unknown usernames so response time does not
    /// reveal which accounts exist.
    /// </summary>
    public void VerifyDummy(string password) => Verify(_dummyHash.Value, password);

    private static bool TryParse(string encoded, out int iterations, out byte[] salt, out byte[] hash)
    {
        iterations = 0;
        salt = hash = Array.Empty<byte>();
        var parts = encoded.Split('$');
        if (parts.Length != 4 || parts[0] != Scheme) return false;
        if (!int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out iterations) ||
            iterations is < 1 or > MaxIterations) return false;
        try
        {
            salt = Convert.FromBase64String(parts[2]);
            hash = Convert.FromBase64String(parts[3]);
        }
        catch (FormatException)
        {
            return false;
        }
        return salt.Length >= 8 && hash.Length is >= 16 and <= 64;
    }
}
