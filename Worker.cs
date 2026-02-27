using System.Net;
using System.Net.Sockets;
using System.Text;
using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace RetaliqHosts
{
    public class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;
        private TcpListener? _listener;
        private readonly IHostApplicationLifetime _lifetime;

        public Worker(ILogger<Worker> logger, IHostApplicationLifetime lifetime)
        {
            _logger = logger;
            _lifetime = lifetime;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            var port = 8888;
            // Ensure running with administrator privileges on Windows
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
            var portEnv = Environment.GetEnvironmentVariable("RETALIQ_PORT");
            if (!string.IsNullOrEmpty(portEnv) && int.TryParse(portEnv, out var p))
            {
                port = p;
            }

            _listener = new TcpListener(IPAddress.Loopback, port);
            _listener.Start();
            _logger.LogInformation("RetaliqHosts listening on 127.0.0.1:{port}", port);

            try
            {
                while (!stoppingToken.IsCancellationRequested)
                {
                    var acceptTask = _listener.AcceptTcpClientAsync();
                    var completed = await Task.WhenAny(acceptTask, Task.Delay(-1, stoppingToken));
                    if (completed != acceptTask)
                    {
                        // cancellation requested
                        break;
                    }

                    var client = acceptTask.Result;
                    _ = Task.Run(() => HandleClientAsync(client, stoppingToken), stoppingToken);
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Listener encountered an error");
            }
            finally
            {
                _listener.Stop();
            }
        }

        public override Task StopAsync(CancellationToken cancellationToken)
        {
            try
            {
                _listener?.Stop();
            }
            catch { }
            return base.StopAsync(cancellationToken);
        }

        private async Task HandleClientAsync(TcpClient client, CancellationToken stoppingToken)
        {
            using (client)
            {
                var ns = client.GetStream();
                using var sr = new StreamReader(ns, Encoding.UTF8);
                try
                {
                    while (!stoppingToken.IsCancellationRequested && !sr.EndOfStream)
                    {
                        var line = await sr.ReadLineAsync();
                        if (string.IsNullOrWhiteSpace(line))
                            continue;

                        try
                        {
                            await ProcessMessageAsync(line, stoppingToken);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, "Failed to process message");
                        }
                    }
                }
                catch (Exception ex) when (!(ex is OperationCanceledException))
                {
                    _logger.LogError(ex, "Error while handling client");
                }
            }
        }

        private async Task ProcessMessageAsync(string base64Json, CancellationToken ct)
        {
            string json;
            try
            {
                var bytes = Convert.FromBase64String(base64Json);
                json = Encoding.UTF8.GetString(bytes);
            }
            catch (FormatException fx)
            {
                _logger.LogWarning(fx, "Received invalid base64 message");
                return;
            }
            ConfigMessage? msg = null;
            string? blockName = null;
            string? content = null;

            var trimmed = json.TrimStart();
            // If payload is a top-level array of hostnames
            if (trimmed.StartsWith("["))
            {
                try
                {
                    var arr = JsonSerializer.Deserialize<string[]>(json);
                    if (arr == null || arr.Length == 0)
                    {
                        _logger.LogWarning("Received empty hostname array");
                        return;
                    }

                    var hosts = arr.Select(NormalizeHostname).Where(h => !string.IsNullOrEmpty(h)).ToArray();
                    if (hosts.Length == 0)
                    {
                        _logger.LogWarning("No valid hostnames found in array");
                        return;
                    }

                    // Build two lines: IPv4 and IPv6
                    content = $"127.0.0.1 {string.Join(' ', hosts)}\r\n::1 {string.Join(' ', hosts)}";
                    blockName = Environment.GetEnvironmentVariable("RETALIQ_DEFAULT_BLOCK") ?? "inline";
                }
                catch (JsonException jx)
                {
                    _logger.LogWarning(jx, "Invalid JSON array payload");
                    return;
                }
            }
            else
            {
                try
                {
                    msg = JsonSerializer.Deserialize<ConfigMessage>(json, new JsonSerializerOptions
                    {
                        PropertyNameCaseInsensitive = true
                    });
                }
                catch (JsonException jx)
                {
                    _logger.LogWarning(jx, "Invalid JSON payload");
                    return;
                }

                if (msg == null || string.IsNullOrWhiteSpace(msg.BlockName))
                {
                    _logger.LogWarning("Message missing blockName");
                    return;
                }

                blockName = msg.BlockName;

                if (!string.IsNullOrEmpty(msg.Content))
                {
                    content = msg.Content;
                }
                else if (msg.Entries != null && msg.Entries.Length > 0)
                {
                    // Treat entries as hostnames and produce IPv4/IPv6 joined lines
                    var hosts = msg.Entries.Select(NormalizeHostname).Where(h => !string.IsNullOrEmpty(h)).ToArray();
                    if (hosts.Length == 0)
                    {
                        _logger.LogWarning("No valid hostnames found in entries for block {block}", blockName);
                        return;
                    }
                    content = $"127.0.0.1 {string.Join(' ', hosts)}\r\n::1 {string.Join(' ', hosts)}";
                }
                else
                {
                    _logger.LogWarning("Message contains no content for block {block}", msg.BlockName);
                    return;
                }
            }

            try
            {
                await UpdateHostsFileAsync(blockName!, content!);
                _logger.LogInformation("Updated hosts file for block {block}", blockName);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update hosts file for block {block}", blockName);
            }
        }

        private static string NormalizeHostname(string? input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return string.Empty;
            var s = input.Trim();
            // Replace commas and whitespace with dots
            s = Regex.Replace(s, "[,\\s]+", ".");
            // Remove any characters that are not letter, digit, hyphen or dot
            s = Regex.Replace(s, "[^A-Za-z0-9.-]", string.Empty);
            // Collapse multiple dots
            s = Regex.Replace(s, "\\.{2,}", ".");
            // Trim dots from ends
            s = s.Trim('.');
            return s;
        }

        private record ConfigMessage(string BlockName, string? Content, string[]? Entries);

        private async Task UpdateHostsFileAsync(string blockName, string content)
        {
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var hostsPath = Path.Combine(windows, "System32", "drivers", "etc", "hosts");

            if (!File.Exists(hostsPath))
            {
                throw new FileNotFoundException("Hosts file not found", hostsPath);
            }

            var text = await File.ReadAllTextAsync(hostsPath, Encoding.UTF8);

            var startMarker = $"# BEGIN RETALIQHOSTS {blockName}";
            var endMarker = $"# END RETALIQHOSTS {blockName}";

            // Remove existing blocks with same name
            var pattern = $"(?ms)^# BEGIN RETALIQHOSTS {Regex.Escape(blockName)}\r?\n.*?\r?\n# END RETALIQHOSTS {Regex.Escape(blockName)}(?:\r?\n)?";
            text = Regex.Replace(text, pattern, string.Empty);

            // Ensure trailing newline
            if (!text.EndsWith("\n") && !text.EndsWith("\r"))
            {
                text += "\r\n";
            }

            var block = new StringBuilder();
            block.AppendLine(startMarker);
            block.Append(content.TrimEnd());
            block.AppendLine();
            block.AppendLine(endMarker);

            text += block.ToString();

            // Write to temporary file then replace atomically (backup saved)
            var tempPath = Path.GetTempFileName();
            await File.WriteAllTextAsync(tempPath, text, Encoding.UTF8);
            var backupPath = hostsPath + ".retaliq.bak";
            File.Replace(tempPath, hostsPath, backupPath);
        }
    }
}
