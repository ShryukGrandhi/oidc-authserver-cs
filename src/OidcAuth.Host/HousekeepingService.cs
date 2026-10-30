using OidcAuth.Core;

namespace OidcAuth.Host;

/// <summary>Prunes expired codes, tokens and keys once a minute so in-memory state stays bounded.</summary>
internal sealed class HousekeepingService(AuthServer server) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));
        while (await timer.WaitForNextTickAsync(stoppingToken)) server.Prune();
    }
}
