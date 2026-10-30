using System.Collections.Concurrent;

namespace OidcAuth.Core.Users;

public sealed class UserAccount
{
    private long _lastTotpCounter = -1;

    public required string SubjectId { get; init; }
    public required string Username { get; init; }
    public required string PasswordHash { get; set; }
    public byte[]? TotpSecret { get; init; }

    public long LastTotpCounter => Interlocked.Read(ref _lastTotpCounter);

    /// <summary>Atomically advances the last-used TOTP step. Fails if another login consumed it first.</summary>
    internal bool TryConsumeTotpCounter(long expectedLast, long newCounter) =>
        Interlocked.CompareExchange(ref _lastTotpCounter, newCounter, expectedLast) == expectedLast;
}

public sealed class InMemoryUserStore
{
    private readonly ConcurrentDictionary<string, UserAccount> _byName = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, UserAccount> _bySubject = new(StringComparer.Ordinal);

    public void Add(UserAccount user)
    {
        if (!_byName.TryAdd(user.Username, user)) throw new InvalidOperationException($"User {user.Username} exists.");
        _bySubject[user.SubjectId] = user;
    }

    public UserAccount? FindByUsername(string username) => _byName.GetValueOrDefault(username);

    public UserAccount? FindBySubject(string subject) => _bySubject.GetValueOrDefault(subject);
}
