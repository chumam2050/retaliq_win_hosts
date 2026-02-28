# RetaliqHosts

RetaliqHosts is a .NET 8 Worker Service that receives JSON payloads and applies host entries into the Windows `hosts` file. It must run as Administrator on Windows because it updates `%SystemRoot%\System32\drivers\etc\hosts`.

This repository contains an interactive `setup.ps1` that consolidates the service registration, environment management and common helper actions.

Current status
- Service registration and management consolidated into `setup.ps1` (preferred entrypoint for installing/uninstalling, reloading env and rotating API key).
- `.env` is ignored by Git (listed in `.gitignore`) and has been removed from the repository to avoid leaking secrets.
- Environment values (`RETALIQ_API_KEY`, `RETALIQ_ALLOWED_IPS`) are written to the Windows Service registry `Environment` as `REG_MULTI_SZ` so the service inherits them on start.

Quick usage (recommended)
1. Open an elevated (Administrator) PowerShell in the repository root.
2. Run `.\n+   .\setup.ps1` and choose from the interactive menu:
   - `1) Register service` — register and start the service (finds executable under `build/<arch>`).
   - `2) Unregister service` — stop and remove the service and cleanup the registry.
   - `3) Reload service` — reapply `.env` values to the service registry and restart the service.
   - `4) Regenerate API key` — rotate the `RETALIQ_API_KEY` value in `.env` and apply it to the running service.

Developer run
1. Build and run locally (development):
   - `dotnet build`
   - `dotnet run --project RetaliqHosts.csproj`

Publish & install
1. Publish the app for Windows (example):
   ```powershell
   dotnet publish -c Release -r win-x64 --self-contained false -o publish
   ```
2. Use `setup.ps1` -> `Register service` to register the published binary. `setup.ps1` searches for the executable under `build/<arch>` and `publish` outputs when registering.

HTTP receiver and testing
- The service exposes an HTTP endpoint (default `http://0.0.0.0:8888/hosts`).
- Requests are accepted only from IPs listed in `RETALIQ_ALLOWED_IPS`. When `RETALIQ_API_KEY` is set the header `X-Api-Key: <key>` is required.

Example curl (with API key):
```bash
curl -v -X POST "http://host.docker.internal:8888/hosts" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: <your-api-key>" \
  --data-raw '["a.test","b.test"]'
```

Security notes
- Keep `.env` out of source control (it is ignored). If secrets were pushed earlier rotate them and consider history cleanup (BFG or git-filter-repo).
- `setup.ps1` writes environment values under the service registry as `REG_MULTI_SZ` so values are available to the service process at start.

Troubleshooting
- If the service doesn't start, check the Windows Application event log for .NET Runtime errors and run the EXE directly in an elevated console to see startup exceptions.
- To verify the service registry environment run in an elevated PowerShell:
  ```powershell
  (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\RetaliqHosts' -Name Environment).Environment | ForEach-Object { Write-Output "ENV: $_" }
  ```

Contributions
- If you'd like the README expanded with CI publish steps or an automated publish-and-register flow, tell me what you'd prefer and I will add it.
