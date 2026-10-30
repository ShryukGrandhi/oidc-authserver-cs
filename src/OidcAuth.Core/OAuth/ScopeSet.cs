namespace OidcAuth.Core.OAuth;

/// <summary>An immutable, ordered set of scope tokens (RFC 6749 §3.3).</summary>
public sealed class ScopeSet : IEquatable<ScopeSet>
{
    private readonly SortedSet<string> _items;

    private ScopeSet(SortedSet<string> items) => _items = items;

    public static ScopeSet Empty { get; } = new(new SortedSet<string>(StringComparer.Ordinal));

    public static ScopeSet Of(params string[] scopes) =>
        TryParse(string.Join(' ', scopes), out var s) ? s : throw new FormatException("Invalid scope token.");

    /// <summary>Parses a space-delimited scope string. Rejects characters outside NQCHAR and empty tokens.</summary>
    public static bool TryParse(string? value, out ScopeSet scopes)
    {
        scopes = Empty;
        if (string.IsNullOrEmpty(value)) return true;
        var set = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var token in value.Split(' '))
        {
            if (token.Length == 0) return false;
            foreach (char c in token)
                if (c is not ('\x21' or >= '\x23' and <= '\x5b' or >= '\x5d' and <= '\x7e')) return false;
            set.Add(token);
        }
        scopes = new ScopeSet(set);
        return true;
    }

    public int Count => _items.Count;
    public bool IsEmpty => _items.Count == 0;
    public bool Contains(string scope) => _items.Contains(scope);
    public bool IsSubsetOf(ScopeSet other) => _items.IsSubsetOf(other._items);
    public IEnumerable<string> Items => _items;

    public bool Equals(ScopeSet? other) => other is not null && _items.SetEquals(other._items);
    public override bool Equals(object? obj) => Equals(obj as ScopeSet);
    public override int GetHashCode() => ToString().GetHashCode(StringComparison.Ordinal);
    public override string ToString() => string.Join(' ', _items);
}
