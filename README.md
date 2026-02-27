# RetaliqHosts

RetaliqHosts is a .NET Worker Service that listens on localhost for base64-encoded JSON messages describing host entries to add to the Windows `hosts` file. It inserts or replaces named blocks inside the hosts file.

Important: This service must run as Administrator on Windows because it modifies `%SystemRoot%\System32\drivers\etc\hosts`.

## How it works
- The service listens on `127.0.0.1` and port `8888` by default (change `RETALIQ_PORT` env var to override).
- Send a single-line base64-encoded JSON payload to the listener. The service decodes and parses the payload and will insert/update a block in the hosts file.
- Payload forms supported:
  - Top-level JSON array of hostnames: `["a.test","b.test"]` — the service will create two lines:
    - `127.0.0.1 a.test b.test`
    - `::1 a.test b.test`
    The block name will default to `inline` or the value of `RETALIQ_DEFAULT_BLOCK` env var.
  - JSON object: `{"BlockName":"myblock","Entries":["a.test","b.test"]}` or with `Content`.

## Running the service
You must run the service as Administrator on Windows.

To run from source (Developer):
1. Open an elevated (Administrator) PowerShell or Cmd prompt.
2. Build and run:
   - `dotnet build`
   - `dotnet run --project RetaliqHosts.csproj`

To run as a Windows Service:
1. Publish the app: `dotnet publish -c Release -r win-x64 --self-contained false -o publish`.
2. A small helper script is provided at `tools/register-service.ps1` which will register and start the service for you. Run the script from an elevated PowerShell prompt:

```powershell
Set-Location <project-root>
.
\tools\register-service.ps1 -ExePath "$(Resolve-Path publish\RetaliqHosts.exe)"
```

The script will remove an existing service with the same name, register the new service, and start it. By default it creates a service named `RetaliqHosts` running as `LocalSystem`.

### Register with specific account
The registration script accepts `-Username` and `-Password` parameters to run the service under a specific user. If you omit `-Password` the script will prompt you for the password securely.

Example:

```powershell
.
\tools\register-service.ps1 -ExePath "$(Resolve-Path publish\RetaliqHosts.exe)" -Username "DOMAIN\user" -Password "p@ssw0rd"
```

### Unregistering the service
An unregister script is provided at `tools/unregister-service.ps1` to stop and remove the service:

```powershell
.
\tools\unregister-service.ps1 -ServiceName RetaliqHosts
```

## Client
No client is included in the repository. Use any TCP tool to send a single-line base64-encoded JSON payload to `127.0.0.1:8888` (or override with `RETALIQ_PORT`).

Example using PowerShell to send an array payload:

```powershell
$json = '["test1.mydomain.test","test2.mydomain.test","test3.,mydomain.test"]'
$b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
$tcp = New-Object System.Net.Sockets.TcpClient('127.0.0.1', 8888)
$stream = $tcp.GetStream()
$writer = New-Object System.IO.StreamWriter($stream, [Text.Encoding]::UTF8)
$writer.AutoFlush = $true
$writer.WriteLine($b64)
$writer.Dispose()
$tcp.Close()
```

## Security
- Listener binds to `127.0.0.1` by design. Exposing it to external networks is not recommended without proper authentication and TLS.

## Notes
- The service will stop automatically if it does not detect Administrator privileges or if not running on Windows.
- The hosts file is modified atomically and a backup `hosts.retaliq.bak` is created when changes are applied.
