using System.Collections.Concurrent;

namespace OidcAuth.Core.OAuth;

public enum RefreshStatus { Ok, NotFound, WrongClient, Expired, Revoked, ReuseDetected, ScopeExceeded }

public sealed record RefreshOutcome(RefreshStatus Status, string? NewToken = null, RefreshTokenService.Family? Family = null,
    ScopeSet? AccessScopes = null);

/// <summary>
/// Rotating refresh tokens with family-based reuse detection (RFC 9700 §4.14.2). Every refresh consumes the
/// presented token and issues a successor in the same family. If an already-consumed token is presented,
/// someone holds a copy: the whole family is revoked, logging out both the attacker and the legitimate client.
/// </summary>
public sealed class RefreshTokenService
{
    public sealed class Family
    {
        private int _revoked;

        internal Family(string id, string clientId, string subject, ScopeSet scopes, DateTimeOffset authTime,
            DateTimeOffset absoluteExpiry)
        {
            Id = id;
            ClientId = clientId;
            Subject = subject;
            Scopes = scopes;
            AuthTime = authTime;
            AbsoluteExpiry = absoluteExpiry;
        }

        public string Id { get; }
        public string ClientId { get; }
        public string Subject { get; }
        public ScopeSet Scopes { get; }
        public DateTimeOffset AuthTime { get; }
        public DateTimeOffset AbsoluteExpiry { get; }
        public bool IsRevoked => Volatile.Read(ref _revoked) == 1;
        internal void Revoke() => Volatile.Write(ref _revoked, 1);
    }

    private sealed class TokenRecord
    {
        public required Family Family { get; init; }
        public required DateTimeOffset ExpiresAt { get; init; }
        public int Consumed;
    }

    private readonly ConcurrentDictionary<string, TokenRecord> _tokens = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, Family> _families = new(StringComparer.Ordinal);
    private readonly TimeProvider _time;
    private readonly TimeSpan _idle;
    private readonly TimeSpan _absolute;

    public RefreshTokenService(TimeProvider time, TimeSpan idleLifetime, TimeSpan absoluteLifetime)
    {
        _time = time;
        _idle = idleLifetime;
        _absolute = absoluteLifetime;
    }

    public int ActiveTokenCount => _tokens.Count;
    public long ReuseDetections => Interlocked.Read(ref _reuseDetections);
    private long _reuseDetections;

    public (string Token, Family Family) IssueNewFamily(string clientId, string subject, ScopeSet scopes,
        DateTimeOffset authTime)
    {
        var now = _time.GetUtcNow();
        var family = new Family(OpaqueToken.New(), clientId, subject, scopes, authTime, now + _absolute);
        _families[family.Id] = family;
        return (Store(family, now), family);
    }

    /// <summary>Consumes <paramref name="token"/> and returns its successor.</summary>
    /// <param name="requested">Optional down-scoping for the new access token; must be a subset.</param>
    public RefreshOutcome Rotate(string token, string clientId, ScopeSet? requested)
    {
        if (!_tokens.TryGetValue(OpaqueToken.Hash(token), out var rec)) return new(RefreshStatus.NotFound);
        var family = rec.Family;
        if (family.ClientId != clientId) return new(RefreshStatus.WrongClient);
        if (family.IsRevoked) return new(RefreshStatus.Revoked);

        var now = _time.GetUtcNow();
        if (now >= rec.ExpiresAt || now >= family.AbsoluteExpiry) return new(RefreshStatus.Expired);

        var scopes = requested is null || requested.IsEmpty ? family.Scopes : requested;
        if (!scopes.IsSubsetOf(family.Scopes)) return new(RefreshStatus.ScopeExceeded);

        if (Interlocked.Exchange(ref rec.Consumed, 1) != 0)
        {
            Interlocked.Increment(ref _reuseDetections);
            RevokeFamily(family.Id);
            return new(RefreshStatus.ReuseDetected, Family: family);
        }

        string next = Store(family, now);
        // A revocation racing with this rotation must still win: re-check after publishing the successor.
        if (family.IsRevoked) return new(RefreshStatus.Revoked);
        return new(RefreshStatus.Ok, next, family, scopes);
    }

    public Family? FindFamily(string token, bool includeConsumed = false)
    {
        if (!_tokens.TryGetValue(OpaqueToken.Hash(token), out var rec)) return null;
        var now = _time.GetUtcNow();
        if (rec.Family.IsRevoked || now >= rec.ExpiresAt || now >= rec.Family.AbsoluteExpiry) return null;
        if (!includeConsumed && Volatile.Read(ref rec.Consumed) != 0) return null;
        return rec.Family;
    }

    public (DateTimeOffset ExpiresAt, Family Family)? Describe(string token)
    {
        var fam = FindFamily(token);
        if (fam is null || !_tokens.TryGetValue(OpaqueToken.Hash(token), out var rec)) return null;
        return (rec.ExpiresAt < fam.AbsoluteExpiry ? rec.ExpiresAt : fam.AbsoluteExpiry, fam);
    }

    public void RevokeFamily(string familyId)
    {
        if (_families.TryGetValue(familyId, out var f)) f.Revoke();
    }

    public int Prune()
    {
        var now = _time.GetUtcNow();
        int removed = 0;
        foreach (var (hash, rec) in _tokens)
            if ((now >= rec.ExpiresAt || rec.Family.IsRevoked || now >= rec.Family.AbsoluteExpiry) &&
                _tokens.TryRemove(hash, out _)) removed++;
        foreach (var (id, fam) in _families)
            if (now >= fam.AbsoluteExpiry) _families.TryRemove(id, out _);
        return removed;
    }

    private string Store(Family family, DateTimeOffset now)
    {
        string token = OpaqueToken.New();
        var expires = now + _idle;
        if (expires > family.AbsoluteExpiry) expires = family.AbsoluteExpiry;
        _tokens[OpaqueToken.Hash(token)] = new TokenRecord { Family = family, ExpiresAt = expires };
        return token;
    }
}
