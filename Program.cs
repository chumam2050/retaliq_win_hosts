using RetaliqHosts;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;

var host = Host.CreateDefaultBuilder(args)
    .UseWindowsService()
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
