using System.Collections.Immutable;
using System.Text.Json.Nodes;

namespace OidcAuth.Core.Jwt;

/// <summary>
/// Holds the active signing key plus recently retired keys. Retired keys keep verifying (and stay in the
/// JWKS) until every token they could have signed has expired, so rotation never breaks live sessions.
/// Reads are lock-free against an immutable snapshot; rotation swaps the snapshot under a lock.
/// </summary>
public sealed class SigningKeyRing : IKeyResolver
{
    private sealed record Snapshot(SigningKey Active, ImmutableArray<(SigningKey Key, DateTimeOffset RetireAt)> Retired);

    private readonly object _writeLock = new();
    private readonly TimeProvider _time;
    private Snapshot _state;

    public SigningKeyRing(SigningKey initial, TimeSpan retiredKeyLifetime, TimeProvider time)
    {
        if (!initial.CanSign) throw new ArgumentException("Active key must be able to sign.", nameof(initial));
        _state = new Snapshot(initial, ImmutableArray<(SigningKey, DateTimeOffset)>.Empty);
        RetiredKeyLifetime = retiredKeyLifetime;
        _time = time;
    }

    public TimeSpan RetiredKeyLifetime { get; }

    public SigningKey Active => Volatile.Read(ref _state).Active;

    public void Rotate(SigningKey next)
    {
        if (!next.CanSign) throw new ArgumentException("Active key must be able to sign.", nameof(next));
        lock (_writeLock)
        {
            var s = _state;
            var retireAt = _time.GetUtcNow() + RetiredKeyLifetime;
            Volatile.Write(ref _state, new Snapshot(next, s.Retired.Add((s.Active, retireAt))));
        }
    }

    /// <summary>Drops retired keys whose grace period has passed. Returns how many were removed.</summary>
    public int PruneExpired()
    {
        lock (_writeLock)
        {
            var s = _state;
            var now = _time.GetUtcNow();
            var keep = s.Retired.Where(r => r.RetireAt > now).ToImmutableArray();
            foreach (var dead in s.Retired.Where(r => r.RetireAt <= now)) dead.Key.Dispose();
            Volatile.Write(ref _state, s with { Retired = keep });
            return s.Retired.Length - keep.Length;
        }
    }

    public SigningKey? Resolve(string kid)
    {
        var s = Volatile.Read(ref _state);
        if (s.Active.Kid == kid) return s.Active;
        var now = _time.GetUtcNow();
        foreach (var (key, retireAt) in s.Retired)
            if (key.Kid == kid && retireAt > now) return key;
        return null;
    }

    public JsonObject GetJwks()
    {
        var s = Volatile.Read(ref _state);
        var now = _time.GetUtcNow();
        var keys = new JsonArray();
        if (s.Active.ToPublicJwk() is { } active) keys.Add(active);
        foreach (var (key, retireAt) in s.Retired)
            if (retireAt > now && key.ToPublicJwk() is { } jwk) keys.Add(jwk);
        return new JsonObject { ["keys"] = keys };
    }
}
