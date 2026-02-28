using System.Globalization;

namespace RetaliqHosts
{
    // Very small .env loader: KEY=VALUE pairs, ignores comments and blank lines.
    public static class DotEnv
    {
        public static void Load(string? path = null)
        {
            try
            {
                path ??= Path.Combine(AppContext.BaseDirectory, ".env");
                if (!File.Exists(path)) return;

                foreach (var raw in File.ReadAllLines(path))
                {
                    var line = raw.Trim();
                    if (string.IsNullOrEmpty(line) || line.StartsWith("#"))
                        continue;

                    var idx = line.IndexOf('=');
                    if (idx <= 0) continue;

                    var key = line.Substring(0, idx).Trim();
                    var val = line.Substring(idx + 1).Trim();

                    // remove surrounding quotes if any
                    if ((val.StartsWith("\"") && val.EndsWith("\"")) || (val.StartsWith("'") && val.EndsWith("'")))
                    {
                        val = val.Substring(1, val.Length - 2);
                    }

                    // unescape simple sequences
                    val = val.Replace("\\n", "\n").Replace("\\r", "\r").Replace("\\t", "\t");

                    // set as process-level environment variable
                    Environment.SetEnvironmentVariable(key, val, EnvironmentVariableTarget.Process);
                }
            }
            catch
            {
                // Do not throw on dotenv load errors; fallback to existing environment
            }
        }
    }
}
