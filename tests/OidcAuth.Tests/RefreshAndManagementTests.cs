using OidcAuth.Core.OAuth;

namespace OidcAuth.Tests;

public class RefreshTokenTests
{
    private readonly Harness _h = new();

    [Fact]
    public void Each_refresh_rotates_the_token()
    {
        var t = _h.LoginSpa("openid api.read offline_access");
        var r1 = _h.RefreshAs("spa", t.RefreshToken!).Value!;
        Assert.NotEqual(t.RefreshToken, r1.RefreshToken);
        Assert.Null(r1.IdToken);
        var r2 = _h.RefreshAs("spa", r1.RefreshToken!).Value!;
        Assert.NotEqual(r1.RefreshToken, r2.RefreshToken);
        Assert.True(_h.Server.Issuer.ValidateAccessToken(r2.AccessToken).IsValid);
    }

    [Fact]
    public void Reuse_of_a_rotated_token_revokes_the_whole_family()
    {
        var t = _h.LoginSpa();
        var legit = _h.RefreshAs("spa", t.RefreshToken!).Value!; // client rotates normally

        // Attacker replays the stolen, already-consumed token.
        var attack = _h.RefreshAs("spa", t.RefreshToken!);
        Assert.Equal("invalid_grant", attack.Error!.Code);
        Assert.Contains("reuse", attack.Error.Description);

        // The legitimate client's current token is dead too: the session is over for everyone.
        Assert.Equal("invalid_grant", _h.RefreshAs("spa", legit.RefreshToken!).Error!.Code);
        Assert.Equal(1, _h.Server.Refresh.ReuseDetections);
    }

    [Fact]
    public void Refresh_can_downscope_but_never_escalate()
    {
        var t = _h.LoginSpa("openid api.read");
        var down = _h.RefreshAs("spa", t.RefreshToken!, "api.read").Value!;
        Assert.Equal("api.read", down.Scope);

        // The refresh token itself keeps the original grant, so a later refresh can return to it.
        var back = _h.RefreshAs("spa", down.RefreshToken!).Value!;
        Assert.Equal("api.read openid", back.Scope);

        Assert.Equal("invalid_scope", _h.RefreshAs("spa", back.RefreshToken!, "api.read profile").Error!.Code);
    }

    [Fact]
    public void Refresh_token_is_bound_to_its_client()
    {
        var t = _h.LoginSpa();
        Assert.Equal("invalid_grant", _h.RefreshAs("web", t.RefreshToken!).Error!.Code);
        Assert.True(_h.RefreshAs("spa", t.RefreshToken!).IsOk); // the failed attempt did not consume it
    }

    [Fact]
    public void Idle_and_absolute_lifetimes_are_enforced()
    {
        var t = _h.LoginSpa();
        _h.Time.Advance(TimeSpan.FromDays(1));
        Assert.Equal("invalid_grant", _h.RefreshAs("spa", t.RefreshToken!).Error!.Code);

        // Refreshing every 23h keeps the session alive only until the 30-day absolute cap.
        var token = _h.LoginSpa().RefreshToken!;
        int refreshes = 0;
        while (true)
        {
            _h.Time.Advance(TimeSpan.FromHours(23));
            var r = _h.RefreshAs("spa", token);
            if (!r.IsOk) break;
            token = r.Value!.RefreshToken!;
            refreshes++;
        }
        Assert.Equal(31, refreshes); // 31*23h = 713h < 720h; the 32nd at 736h is past the cap
    }
}

public class IntrospectionAndRevocationTests
{
    private readonly Harness _h = new();
    private OAuthClient Web => _h.Server.Clients.Find("web")!;
    private OAuthClient Spa => _h.Server.Clients.Find("spa")!;

    [Fact]
    public void Introspection_reports_active_access_and_refresh_tokens()
    {
        var t = _h.LoginSpa();
        var a = _h.Server.Management.Introspect(Web, t.AccessToken, null).Value!;
        Assert.True(a["active"]!.GetValue<bool>());
        Assert.Equal("access_token", a["token_type"]!.GetValue<string>());
        Assert.Equal("spa", a["client_id"]!.GetValue<string>());

        var r = _h.Server.Management.Introspect(Web, t.RefreshToken, "refresh_token").Value!;
        Assert.True(r["active"]!.GetValue<bool>());
        Assert.Equal("refresh_token", r["token_type"]!.GetValue<string>());
    }

    [Fact]
    public void Introspection_of_garbage_is_just_inactive_and_public_clients_are_refused()
    {
        var x = _h.Server.Management.Introspect(Web, "not-a-token", null).Value!;
        Assert.Single(x);
        Assert.False(x["active"]!.GetValue<bool>());
        Assert.Equal("unauthorized_client", _h.Server.Management.Introspect(Spa, "x", null).Error!.Code);
    }

    [Fact]
    public void Revoking_refresh_token_kills_family_and_access_token_is_denylisted()
    {
        var t = _h.LoginSpa();
        _h.Server.Management.Revoke(Spa, t.RefreshToken);
        Assert.Equal("invalid_grant", _h.RefreshAs("spa", t.RefreshToken!).Error!.Code);
        Assert.False(_h.Server.Management.Introspect(Web, t.RefreshToken, null).Value!["active"]!.GetValue<bool>());

        Assert.True(_h.Server.Issuer.ValidateAccessToken(t.AccessToken).IsValid);
        _h.Server.Management.Revoke(Spa, t.AccessToken);
        Assert.False(_h.Server.Management.Introspect(Web, t.AccessToken, null).Value!["active"]!.GetValue<bool>());
    }

    [Fact]
    public void Clients_cannot_revoke_each_others_tokens()
    {
        var t = _h.LoginSpa();
        _h.Server.Management.Revoke(Web, t.RefreshToken);
        _h.Server.Management.Revoke(Web, t.AccessToken);
        Assert.True(_h.RefreshAs("spa", t.RefreshToken!).IsOk);
        Assert.True(_h.Server.Issuer.ValidateAccessToken(t.AccessToken).IsValid);
    }

    [Fact]
    public void Prune_bounds_memory_after_expiry()
    {
        for (int i = 0; i < 20; i++) _h.LoginSpa();
        var t = _h.LoginSpa();
        _h.Server.Management.Revoke(Spa, t.AccessToken);
        Assert.Equal(21, _h.Server.Refresh.ActiveTokenCount);
        _h.Time.Advance(TimeSpan.FromDays(31));
        _h.Server.Prune();
        Assert.Equal(0, _h.Server.Refresh.ActiveTokenCount);
        Assert.Equal(0, _h.Server.Codes.Count);
        Assert.False(_h.Server.Issuer.IsAccessTokenRevoked("anything"));
    }
}

public class ConcurrencyTests
{
    [Fact]
    public async Task Concurrent_redemptions_of_one_code_yield_at_most_one_token_set()
    {
        var h = new Harness();
        for (int round = 0; round < 200; round++)
        {
            var (code, verifier, _) = h.Authorize();
            var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(() => h.Exchange(code, verifier))));
            int ok = results.Count(r => r.IsOk);
            Assert.True(ok <= 1, $"round {round}: {ok} successful redemptions");
            // Whatever was issued must be revoked, because a replay was observed.
            foreach (var r in results.Where(r => r.IsOk))
                Assert.False(h.Server.Issuer.ValidateAccessToken(r.Value!.AccessToken).IsValid);
        }
    }

    [Fact]
    public async Task Concurrent_refreshes_of_one_token_never_fork_the_session()
    {
        var h = new Harness();
        for (int round = 0; round < 200; round++)
        {
            var t = h.LoginSpa();
            var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(() => h.RefreshAs("spa", t.RefreshToken!))));
            // One request consumes the token; the others are reuse and revoke the family, so no surviving
            // successor may still be usable.
            Assert.True(results.Count(r => r.IsOk) <= 1);
            foreach (var r in results.Where(r => r.IsOk))
                Assert.False(h.RefreshAs("spa", r.Value!.RefreshToken!).IsOk);
        }
    }
}
