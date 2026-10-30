using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using OidcAuth.Core;
using OidcAuth.Core.Jwt;
using OidcAuth.Core.Mfa;
using OidcAuth.Core.OAuth;
using OidcAuth.Core.Passwords;

// Measures the hot paths of the authorization server in-process (no HTTP), plus two race-safety checks.
// Usage: dotnet run -c Release --project bench/OidcAuth.Bench [-- --quick]
bool quick = args.Contains("--quick");
int scale = quick ? 10 : 1;
CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;

Console.WriteLine($"# oidc-authserver-cs benchmark{(quick ? " (quick)" : "")}");
Console.WriteLine($"runtime: .NET {Environment.Version}, {RuntimeInformation.OSDescription.Trim()}, {RuntimeInformation.ProcessArchitecture}, {Environment.ProcessorCount} logical CPUs");
Console.WriteLine();
Console.WriteLine("| operation | ops | ops/sec | p50 µs | p99 µs |");
Console.WriteLine("|---|---:|---:|---:|---:|");

var time = TimeProvider.System;
long now = time.GetUtcNow().ToUnixTimeSeconds();
var claims = new JsonObject
{
    ["iss"] = "https://auth.example", ["sub"] = "248289761001", ["aud"] = "api", ["client_id"] = "spa",
    ["scope"] = "openid api.read", ["iat"] = now, ["exp"] = now + 600, ["jti"] = "bench",
};

foreach (var key in new SigningKey[] { EcdsaSigningKey.Generate(), RsaSigningKey.Generate(), HmacSigningKey.Generate() })
{
    var validator = new JwtValidator(new JwtValidationOptions
    {
        Issuer = "https://auth.example", Audiences = new[] { "api" },
        AllowedAlgorithms = new HashSet<string> { key.Algorithm },
    }, new Single(key), time);
    string token = JwtEncoder.Encode(claims, key);
    int n = key.Algorithm == "RS256" ? 4_000 : 40_000;
    Measure($"JWT sign {key.Algorithm}", n / scale, () => JwtEncoder.Encode(claims, key));
    Measure($"JWT validate {key.Algorithm}", n / scale, () =>
    {
        if (!validator.Validate(token).IsValid) throw new InvalidOperationException();
    });
}

var hasher = new PasswordHasher();
string stored = hasher.Hash("correct horse battery staple");
Measure($"PBKDF2-SHA256 verify ({hasher.Iterations:N0} iter)", quick ? 3 : 20,
    () => hasher.Verify(stored, "correct horse battery staple"));

var totp = new Totp(time);
byte[] secret = "12345678901234567890"u8.ToArray();
string current = totp.Generate(secret);
Measure("TOTP verify (window ±1)", 100_000 / scale, () => totp.Verify(secret, current, -1));

var server = NewServer();
Measure("code+PKCE flow, 1 thread", 10_000 / scale, () => Flow(server));
Parallel("code+PKCE flow", 40_000 / scale, () => Flow(server));

var refreshServer = NewServer();
Parallel("token requests (1 code + 3 refresh rotations)", 40_000 / scale, () =>
{
    string rt = Flow(refreshServer).RefreshToken!;
    for (int i = 0; i < 3; i++) rt = Refresh(refreshServer, rt).Value!.RefreshToken!;
}, opsPerCall: 4);

Console.WriteLine();
Console.WriteLine("Race-safety checks (8 threads replay the same credential at once):");
Console.WriteLine();
Console.WriteLine("| check | trials | trials where any raced request left a usable token |");
Console.WriteLine("|---|---:|---:|");
RaceCheck("authorization code double-redeem", quick ? 200 : 2_000, s =>
{
    var (code, verifier) = Authorize(s);
    var results = RunConcurrently(8, () => Exchange(s, code, verifier));
    return results.Count(r => r.IsOk && s.Issuer.ValidateAccessToken(r.Value!.AccessToken).IsValid);
});
RaceCheck("refresh token double-rotate", quick ? 200 : 2_000, s =>
{
    string rt = Flow(s).RefreshToken!;
    var results = RunConcurrently(8, () => Refresh(s, rt));
    return results.Count(r => r.IsOk && Refresh(s, r.Value!.RefreshToken!).IsOk);
});
return;

static AuthServer NewServer()
{
    var s = new AuthServer(new AuthServerOptions { Issuer = "https://auth.example" }, TimeProvider.System,
        hasher: new PasswordHasher(1_000));
    s.Clients.Register(OAuthClient.CreatePublic("spa", new[] { "https://spa.example/cb" }, ScopeSet.Of("openid", "api.read")));
    return s;
}

static (string Code, string Verifier) Authorize(AuthServer s)
{
    string verifier = Pkce.CreateVerifier();
    var v = s.Authorization.Validate(new AuthorizationRequest("code", "spa", "https://spa.example/cb", "openid api.read",
        "st", Pkce.ComputeChallenge(verifier), "S256", "nonce"));
    string url = s.Authorization.IssueCode(v.Request!, "user-1", DateTimeOffset.UtcNow);
    int start = url.IndexOf("code=", StringComparison.Ordinal) + 5;
    return (url[start..url.IndexOf('&', start)], verifier);
}

static OAuthResult<TokenResponse> Exchange(AuthServer s, string code, string verifier) =>
    s.TokenEndpoint.Handle(new Dictionary<string, string>
    {
        ["grant_type"] = "authorization_code", ["code"] = code, ["redirect_uri"] = "https://spa.example/cb",
        ["code_verifier"] = verifier, ["client_id"] = "spa",
    }, null);

static OAuthResult<TokenResponse> Refresh(AuthServer s, string rt) =>
    s.TokenEndpoint.Handle(new Dictionary<string, string>
    {
        ["grant_type"] = "refresh_token", ["refresh_token"] = rt, ["client_id"] = "spa",
    }, null);

static TokenResponse Flow(AuthServer s)
{
    var (code, verifier) = Authorize(s);
    var r = Exchange(s, code, verifier);
    return r.Value ?? throw new InvalidOperationException(r.Error!.Description);
}

static T[] RunConcurrently<T>(int n, Func<T> f)
{
    using var barrier = new Barrier(n);
    var results = new T[n];
    var threads = Enumerable.Range(0, n).Select(i => new Thread(() =>
    {
        barrier.SignalAndWait();
        results[i] = f();
    })).ToArray();
    foreach (var t in threads) t.Start();
    foreach (var t in threads) t.Join();
    return results;
}

static void RaceCheck(string name, int trials, Func<AuthServer, int> survivors)
{
    var s = NewServer();
    int bad = 0;
    for (int i = 0; i < trials; i++) if (survivors(s) > 0) bad++;
    Console.WriteLine($"| {name} | {trials:N0} | {bad} |");
}

static void Measure(string name, int n, Action op)
{
    for (int i = 0; i < Math.Min(n, 200); i++) op(); // warm-up
    var lat = new double[n];
    long start = Stopwatch.GetTimestamp();
    for (int i = 0; i < n; i++)
    {
        long t0 = Stopwatch.GetTimestamp();
        op();
        lat[i] = Stopwatch.GetElapsedTime(t0).TotalMicroseconds;
    }
    double secs = Stopwatch.GetElapsedTime(start).TotalSeconds;
    Array.Sort(lat);
    Console.WriteLine($"| {name} | {n:N0} | {n / secs:N0} | {Pct(lat, 0.50):N1} | {Pct(lat, 0.99):N1} |");
}

static void Parallel(string name, int n, Action op, int opsPerCall = 1)
{
    int threads = Environment.ProcessorCount;
    int calls = n / opsPerCall;
    for (int i = 0; i < 200; i++) op();
    long start = Stopwatch.GetTimestamp();
    System.Threading.Tasks.Parallel.For(0, calls, new ParallelOptions { MaxDegreeOfParallelism = threads }, _ => op());
    double secs = Stopwatch.GetElapsedTime(start).TotalSeconds;
    Console.WriteLine($"| {name}, {threads} threads | {calls * opsPerCall:N0} | {calls * opsPerCall / secs:N0} | – | – |");
}

static double Pct(double[] sorted, double p) => sorted[Math.Min(sorted.Length - 1, (int)(p * sorted.Length))];

sealed class Single(SigningKey key) : IKeyResolver
{
    public SigningKey? Resolve(string kid) => kid == key.Kid ? key : null;
}
