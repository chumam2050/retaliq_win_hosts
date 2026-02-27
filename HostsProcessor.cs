using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace RetaliqHosts
{
    public interface IHostsProcessor
    {
        Task ProcessJsonPayloadAsync(string json);
    }

    public class HostsProcessor : IHostsProcessor
    {
        private readonly ILogger<HostsProcessor> _logger;

        public HostsProcessor(ILogger<HostsProcessor> logger)
        {
            _logger = logger;
        }

        public async Task ProcessJsonPayloadAsync(string json)
        {
            if (string.IsNullOrWhiteSpace(json))
            {
                _logger.LogWarning("Empty JSON payload");
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
