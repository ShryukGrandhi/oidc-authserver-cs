using System.Collections.Concurrent;

namespace OidcAuth.Core.Users;

/// <summary>
/// Failure-counting lockout with exponential backoff. After <c>freeAttempts</c> failures inside the
/// failure window, each further failure locks the key for base·2^(n−free), capped at the max.
/// </summary>
public sealed class LoginThrottle
{
    private sealed class Entry
    {
        public int Failures;
        public DateTimeOffset LastFailure;
        public DateTimeOffset LockedUntil;
    }

    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly TimeProvider _time;

    public LoginThrottle(TimeProvider time, int freeAttempts, TimeSpan baseLockout, TimeSpan maxLockout,
        TimeSpan failureWindow)
    {
        _time = time;
        FreeAttempts = freeAttempts;
        BaseLockout = baseLockout;
        MaxLockout = maxLockout;
        FailureWindow = failureWindow;
    }

    public int FreeAttempts { get; }
    public TimeSpan BaseLockout { get; }
    public TimeSpan MaxLockout { get; }
    public TimeSpan FailureWindow { get; }

    public bool IsLocked(string key, out TimeSpan retryAfter)
    {
        retryAfter = TimeSpan.Zero;
        if (!_entries.TryGetValue(key, out var e)) return false;
        lock (e)
        {
            var now = _time.GetUtcNow();
            if (e.LockedUntil <= now) return false;
            retryAfter = e.LockedUntil - now;
            return true;
        }
    }

    public void RecordFailure(string key)
    {
        var e = _entries.GetOrAdd(key, static _ => new Entry());
        lock (e)
        {
            var now = _time.GetUtcNow();
            if (now - e.LastFailure > FailureWindow) e.Failures = 0;
            e.Failures++;
            e.LastFailure = now;
            int over = e.Failures - FreeAttempts;
            if (over >= 0)
            {
                double seconds = BaseLockout.TotalSeconds * Math.Pow(2, Math.Min(over, 30));
                var lockout = TimeSpan.FromSeconds(Math.Min(seconds, MaxLockout.TotalSeconds));
                e.LockedUntil = now + lockout;
            }
        }
    }

    public void RecordSuccess(string key) => _entries.TryRemove(key, out _);

    public int FailureCount(string key) => _entries.TryGetValue(key, out var e) ? e.Failures : 0;

    /// <summary>Forgets keys that are neither locked nor inside the failure window.</summary>
    public int Prune()
    {
        var now = _time.GetUtcNow();
        int removed = 0;
        foreach (var (key, e) in _entries)
        {
            bool stale;
            lock (e) stale = e.LockedUntil <= now && now - e.LastFailure > FailureWindow;
            if (stale && _entries.TryRemove(key, out _)) removed++;
        }
        return removed;
    }
}
