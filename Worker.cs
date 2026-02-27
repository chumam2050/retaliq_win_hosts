using System.Text;
using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace RetaliqHosts
{
    public class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;
        // raw TCP listener removed; HTTP endpoint handles payloads
        private readonly IHostApplicationLifetime _lifetime;
        private readonly IHostsProcessor _hostsProcessor;

        public Worker(ILogger<Worker> logger, IHostApplicationLifetime lifetime, IHostsProcessor hostsProcessor)
        {
            _logger = logger;
            _lifetime = lifetime;
            _hostsProcessor = hostsProcessor;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            // Only run admin check here; HTTP endpoint handles incoming payloads.
            if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
            {
                try
                {
                    var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                    var principal = new System.Security.Principal.WindowsPrincipal(identity);
                    if (!principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator))
                    {
                        _logger.LogError("Administrator privileges are required to modify the hosts file. Stopping application.");
                        _lifetime.StopApplication();
                        return;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to verify administrator privileges. Stopping application.");
                    _lifetime.StopApplication();
                    return;
                }
            }
            else
            {
                _logger.LogError("RetaliqHosts is designed to run on Windows. Stopping application.");
                _lifetime.StopApplication();
                return;
            }

            _logger.LogInformation("Worker running; HTTP endpoint handles payloads. Waiting for stop...");
            try
            {
                await Task.Delay(Timeout.Infinite, stoppingToken);
            }
            catch (OperationCanceledException) { }
        }

        public override Task StopAsync(CancellationToken cancellationToken)
        {
            return base.StopAsync(cancellationToken);
        }

        // HostsProcessor performs hosts file updates; Worker contains only lifecycle/admin checks now.
    }
}
