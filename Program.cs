using RetaliqHosts;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using System.Net;
using System.Linq;

var host = Host.CreateDefaultBuilder(args)
    .UseWindowsService()
    // Load .env from app base directory into process environment so RETALIQ_* vars can be provided via .env
    .ConfigureHostConfiguration(cfg =>
    {
        // load .env into process env before configuration
        DotEnv.Load();
    })
    .ConfigureServices(services =>
    {
        services.AddHostedService<Worker>();
        services.AddSingleton<IHostsProcessor, HostsProcessor>();
    })
    .ConfigureWebHostDefaults(webBuilder =>
    {
        // expose a simple HTTP endpoint for testing
        webBuilder.UseKestrel();
        // Bind to all interfaces so WSL and other network namespaces can reach the HTTP receiver
        webBuilder.UseUrls("http://0.0.0.0:8888");
        webBuilder.Configure(app =>
        {
            // Read allowlist and API key from environment
            var allowedEnv = Environment.GetEnvironmentVariable("RETALIQ_ALLOWED_IPS");
            var allowedIps = (allowedEnv ?? string.Empty)
                .Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(s => {
                    if (IPAddress.TryParse(s, out var ip)) return ip;
                    return null;
                })
                .Where(x => x != null)
                .Select(x => x!)
                .ToArray();

            // Default to loopback only if none provided
            if (allowedIps.Length == 0)
            {
                allowedIps = new[] { IPAddress.Loopback, IPAddress.IPv6Loopback };
            }

            var apiKey = Environment.GetEnvironmentVariable("RETALIQ_API_KEY");

            app.Use(async (context, next) =>
            {
                var remote = context.Connection.RemoteIpAddress;
                if (remote != null && remote.IsIPv4MappedToIPv6) remote = remote.MapToIPv4();

                var allowed = false;
                if (remote != null)
                {
                    foreach (var ip in allowedIps)
                    {
                        if (ip.Equals(remote)) { allowed = true; break; }
                    }
                }

                if (!allowed)
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    await context.Response.WriteAsync("Forbidden");
                    return;
                }

                if (!string.IsNullOrEmpty(apiKey))
                {
                    if (!context.Request.Headers.TryGetValue("X-Api-Key", out var v) || v != apiKey)
                    {
                        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                        await context.Response.WriteAsync("Unauthorized");
                        return;
                    }
                }

                await next();
            });

            app.UseRouting();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapPost("/hosts", async context =>
                {
                    var processor = context.RequestServices.GetService<IHostsProcessor>();
                    if (processor == null)
                    {
                        context.Response.StatusCode = 500;
                        await context.Response.WriteAsync("Processor not available");
                        return;
                    }
                    using var sr = new System.IO.StreamReader(context.Request.Body, System.Text.Encoding.UTF8);
                    var json = await sr.ReadToEndAsync();
                    await processor.ProcessJsonPayloadAsync(json);
                    context.Response.StatusCode = 200;
                    await context.Response.WriteAsync("OK");
                });
            });
        });
    })
    .Build();

host.Run();
