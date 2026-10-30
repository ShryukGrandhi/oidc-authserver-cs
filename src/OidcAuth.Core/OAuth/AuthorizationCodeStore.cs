using System.Collections.Concurrent;

namespace OidcAuth.Core.OAuth;

public sealed record AuthorizationGrant(
    string ClientId,
    string RedirectUri,
    string Subject,
    ScopeSet Scopes,
    string CodeChallenge,
    string? Nonce,
    DateTimeOffset AuthTime,
    DateTimeOffset ExpiresAt);

public enum CodeRedemptionStatus { Ok, NotFound, Expired, AlreadyRedeemed }

/// <summary>
/// One-time authorization codes. A redeemed code is kept (as a tombstone) until it expires so that a second
/// redemption is recognised as replay; RFC 6749 §4.1.2 says the server should then revoke the tokens that
/// the first redemption produced.
/// </summary>
public sealed class AuthorizationCodeStore
{
    public sealed class Entry
    {
        private int _redeemed;
        private int _compromised;

        internal Entry(AuthorizationGrant grant) => Grant = grant;

        public AuthorizationGrant Grant { get; }

        /// <summary>Tokens issued on first redemption; set so a later replay can revoke them.</summary>
        public string? RefreshFamilyId { get; internal set; }
        public string? AccessTokenId { get; internal set; }
        public DateTimeOffset AccessTokenExpiry { get; internal set; }

        public bool IsCompromised => Volatile.Read(ref _compromised) == 1;

        internal bool TryRedeem() => Interlocked.Exchange(ref _redeemed, 1) == 0;
        internal void MarkCompromised() => Volatile.Write(ref _compromised, 1);
    }

    private readonly ConcurrentDictionary<string, Entry> _codes = new(StringComparer.Ordinal);
    private readonly TimeProvider _time;
    private int _issuedSincePrune;

    public AuthorizationCodeStore(TimeProvider time) => _time = time;

    public int Count => _codes.Count;

    public string Issue(AuthorizationGrant grant)
    {
        if (Interlocked.Increment(ref _issuedSincePrune) % 1024 == 0) Prune();
        string code = OpaqueToken.New();
        _codes[OpaqueToken.Hash(code)] = new Entry(grant);
        return code;
    }

    public (CodeRedemptionStatus Status, Entry? Entry) Redeem(string code)
    {
        if (!_codes.TryGetValue(OpaqueToken.Hash(code), out var entry)) return (CodeRedemptionStatus.NotFound, null);
        if (!entry.TryRedeem())
        {
            entry.MarkCompromised();
            return (CodeRedemptionStatus.AlreadyRedeemed, entry);
        }
        if (_time.GetUtcNow() >= entry.Grant.ExpiresAt) return (CodeRedemptionStatus.Expired, entry);
        return (CodeRedemptionStatus.Ok, entry);
    }

    public int Prune()
    {
        // Tombstones stay one extra lifetime past expiry: long enough to catch replays of stolen codes.
        var now = _time.GetUtcNow();
        int removed = 0;
        foreach (var (hash, e) in _codes)
        {
            var lifetime = e.Grant.ExpiresAt - e.Grant.AuthTime;
            if (now >= e.Grant.ExpiresAt + lifetime && _codes.TryRemove(hash, out _)) removed++;
        }
        return removed;
    }
}
