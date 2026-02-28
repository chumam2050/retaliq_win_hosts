<#
Interactive setup script for RetaliqHosts

Features:
1) checks admin privileges and relaunches elevated if needed
2) detects architecture (x64/x86)
3) unzips build archive for selected arch into `build\<arch>`
4) copies .env.example -> .env if missing (or overwrite with confirmation)
5) generates API key if value is default or empty
6) updates allowed IPs to include localhost, WSL host IP (if available) and docker host IP (if resolvable)
7) calls run-and-register to register the service

Menu choices:
 1) setup service
 2) reload service
 3) unregister service

Run from repository root in an elevated PowerShell session.
#>

function Test-IsAdministrator {
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { return $false }
}

if (-not (Test-IsAdministrator)) {
    Write-Output "This script requires Administrator privileges. Relaunching elevated..."
    $args = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    Start-Process -FilePath powershell -Verb RunAs -ArgumentList $args
    exit
}

function Prompt-SelectArch {
    $is64 = [Environment]::Is64BitOperatingSystem
    $defaultShort = if ($is64) { 'x64' } else { 'x86' }
    $default = if ($is64) { 'win-x64' } else { 'win-x86' }
    Write-Host "Detected OS architecture: $defaultShort (using archive folder name $default)"
    $choice = Read-Host "Select archive to install (win-x64/win-x86) [default: $default]"
    if ([string]::IsNullOrWhiteSpace($choice)) { return $default }
    $choice = $choice.Trim().ToLower()
    if ($choice -in @('win-x64','win-x86')) { return $choice }
    # allow short forms
    if ($choice -in @('x64','x86')) { if ($choice -eq 'x64') { return 'win-x64' } else { return 'win-x86' } }
    Write-Warning "Invalid choice, using default $default"
    return $default
}

function Find-And-Unzip($arch, $buildRoot = '.\build', $force=$false) {
    $zipName1 = Join-Path $buildRoot ("$arch.zip")
    $zipName2 = Join-Path $buildRoot "$arch.zip"
    $zip = $null
    if (Test-Path $zipName1) { $zip = (Resolve-Path $zipName1).Path }
    elseif (Test-Path $zipName2) { $zip = (Resolve-Path $zipName2).Path }
    else {
        # search for any zip containing arch
        $found = Get-ChildItem -Path $buildRoot -Filter "*$arch*.zip" -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) { $zip = $found.FullName }
    }

    if (-not $zip) { Write-Error "No zip archive found for arch $arch under $buildRoot"; return $false }

    # if not found, provide helpful listing
    if (-not $zip) {
        Write-Warning ("Search locations under {0}:" -f $buildRoot)
        Get-ChildItem -Path $buildRoot -Filter '*.zip' -Recurse -File | ForEach-Object { Write-Output "  $($_.FullName)" }
        return $false
    }

    $outDir = Join-Path $buildRoot $arch
    if (Test-Path $outDir) {
        if ($force) { Remove-Item -Recurse -Force $outDir }
        else {
            $c = Read-Host "$outDir already exists. Overwrite? (y/N)"
            if ($c.ToLower() -ne 'y' -and $c.ToLower() -ne 'yes') { Write-Output 'Skipping unzip.'; return $true }
            Remove-Item -Recurse -Force $outDir
        }
    }

    Write-Output "Extracting $zip -> $outDir"
    Expand-Archive -Path $zip -DestinationPath $outDir -Force
    return $true
}

function Ensure-EnvFile {
    $example = Join-Path (Get-Location) '.env.example'
    $env = Join-Path (Get-Location) '.env'
    if (-not (Test-Path $example)) { Write-Warning '.env.example not found'; return }
    if (-not (Test-Path $env)) {
        Copy-Item -Path $example -Destination $env
        Write-Output "Created .env from .env.example"
        return 'created'
    }
    else {
        $c = Read-Host '.env already exists. Overwrite from example? (y/N)'
        if ($c.ToLower() -eq 'y' -or $c.ToLower() -eq 'yes') {
            Copy-Item -Path $example -Destination $env -Force
            Write-Output 'Overwritten .env'
            return 'overwritten'
        }
        else {
            Write-Output 'Kept existing .env'
            return 'kept'
        }
    }
}

function Read-Env($path) {
    $dict = @{}
    if (-not (Test-Path $path)) { return $dict }
    foreach ($line in Get-Content $path) {
        $s = $line.Trim()
        if ($s -eq '' -or $s.StartsWith('#')) { continue }
        $idx = $s.IndexOf('=')
        if ($idx -lt 0) { continue }
        $k = $s.Substring(0,$idx).Trim()
        $v = $s.Substring($idx+1).Trim().Trim('"', "'")
        $dict[$k] = $v
    }
    return $dict
}

function Write-Env($path, $dict) {
    $lines = @()
    foreach ($k in $dict.Keys) { $lines += "$k=$($dict[$k])" }
    Set-Content -Path $path -Value $lines -Encoding UTF8
}

function Generate-ApiKey {
    # generate a 32-char base64url-like string
    $bytes = New-Object byte[] 24
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $b64 = ([Convert]::ToBase64String($bytes).TrimEnd('=')) -replace '\+','-' -replace '/','_'
    return $b64
}

function Get-WSLHostIP {
    if (-not (Get-Command wsl -ErrorAction SilentlyContinue)) { return $null }
    try {
        $out = wsl -e sh -c "grep nameserver /etc/resolv.conf | awk '{print \$2}' | head -n1" 2>$null
        $ip = $out.Trim()
        if ([string]::IsNullOrWhiteSpace($ip)) { return $null }
        return $ip
    }
    catch { return $null }
}

function Resolve-DockerHostIP {
    try {
        $res = Resolve-DnsName host.docker.internal -ErrorAction SilentlyContinue
        if ($res) { return ($res | Select-Object -First 1 -ExpandProperty IPAddress).ToString() }
    }
    catch { }
    # fallback common Docker host IP
    return '172.17.0.1'
}

function Setup-ServiceFlow {
    $arch = Prompt-SelectArch
    if (-not (Find-And-Unzip $arch '.\build' $true)) { Write-Error 'Failed to extract build archive'; return }

    $ensureResult = Ensure-EnvFile
    $envPath = Join-Path (Get-Location) '.env'
    $env = Read-Env $envPath

    if (-not $env.ContainsKey('RETALIQ_API_KEY') -or [string]::IsNullOrWhiteSpace($env['RETALIQ_API_KEY']) -or $env['RETALIQ_API_KEY'] -eq 'replace-with-strong-secret') {
        $new = Generate-ApiKey
        $env['RETALIQ_API_KEY'] = $new
        Write-Output "Generated RETALIQ_API_KEY"
    }

    # build allowed list: prefer existing value in .env if present
    if ($env.ContainsKey('RETALIQ_ALLOWED_IPS') -and -not [string]::IsNullOrWhiteSpace($env['RETALIQ_ALLOWED_IPS'])) {
        Write-Output "Using existing RETALIQ_ALLOWED_IPS from .env: $($env['RETALIQ_ALLOWED_IPS'])"
    }
    else {
        $allowed = @('127.0.0.1')
        $wslip = Get-WSLHostIP
        if ($wslip) { $allowed += $wslip }
        $dockip = Resolve-DockerHostIP
        if ($dockip) { $allowed += $dockip }
        $env['RETALIQ_ALLOWED_IPS'] = ($allowed -join ',')
        Write-Output "Set RETALIQ_ALLOWED_IPS to: $($env['RETALIQ_ALLOWED_IPS'])"
    }

    Write-Env $envPath $env
    Write-Output ".env updated with API key and allowed IPs"

    # call run-and-register wrapper using named parameter splatting to avoid positional parsing issues
    $callParams = @{
        BuildDir = '.\build'
        Arch = $arch
        AllowedIps = $env['RETALIQ_ALLOWED_IPS']
        ApiKey = $env['RETALIQ_API_KEY']
        Force = $true
    }
    Write-Output "Registering service using run-and-register.ps1..."
    if (Test-Path .\run-and-register.ps1) {
        & .\run-and-register.ps1 @callParams
    }
    elseif (Test-Path .\tools\run-and-register.ps1) {
        & .\tools\run-and-register.ps1 @callParams
    }
    else {
        Write-Error 'run-and-register.ps1 not found in repo root or tools folder.'
        return
    }
}

function Reload-Service {
    if (Get-Service -Name RetaliqHosts -ErrorAction SilentlyContinue) {
        # reload .env into service environment then restart
        $envPath = Join-Path (Get-Location) '.env'
        if (Test-Path $envPath) {
            $env = Read-Env $envPath
            $toSet = @{}
            if ($env.ContainsKey('RETALIQ_API_KEY')) { $toSet.RETALIQ_API_KEY = $env['RETALIQ_API_KEY'] }
            if ($env.ContainsKey('RETALIQ_ALLOWED_IPS')) { $toSet.RETALIQ_ALLOWED_IPS = $env['RETALIQ_ALLOWED_IPS'] }
            if ($toSet.Count -gt 0) {
                Update-ServiceEnvironment -ServiceName 'RetaliqHosts' -EnvDict $toSet
            }
        }
        Restart-Service -Name RetaliqHosts -Force
        Write-Output "Service restarted and .env applied to service environment."
    }
    else { Write-Warning "Service RetaliqHosts not found." }
}

function Update-ServiceEnvironment {
    param(
        [string] $ServiceName,
        [hashtable] $EnvDict
    )
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    try {
        $existing = Get-ItemProperty -Path $regPath -Name 'Environment' -ErrorAction SilentlyContinue
        $envs = @()
        if ($existing) { $envs = $existing.Environment }
        # remove keys that we will set
        foreach ($k in $EnvDict.Keys) {
            $envs = $envs | Where-Object { $_ -notlike "$k=*" }
        }
        foreach ($k in $EnvDict.Keys) {
            $envs += "$k=$($EnvDict[$k])"
        }
        Set-ItemProperty -Path $regPath -Name 'Environment' -Value $envs -Force
        Write-Output "Service registry environment updated for $ServiceName"
    }
    catch {
        throw $_
    }
}

function Append-ManualAllowedIp {
    param(
        [string] $ServiceName = 'RetaliqHosts'
    )
    $ip = Read-Host 'Enter IP address to append to allowed list (comma separated allowed)'
    if ([string]::IsNullOrWhiteSpace($ip)) { Write-Warning 'No IP provided'; return }
    $items = $ip.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    $existing = Get-ItemProperty -Path $regPath -Name 'Environment' -ErrorAction SilentlyContinue
    $envs = @()
    if ($existing) { $envs = $existing.Environment }
    $cur = @()
    $envEntry = $envs | Where-Object { $_ -like 'RETALIQ_ALLOWED_IPS=*' }
    if ($envEntry) { $cur = ($envEntry -replace '^RETALIQ_ALLOWED_IPS=','').Split(',') | ForEach-Object { $_.Trim() } }
    foreach ($it in $items) { if ($cur -notcontains $it) { $cur += $it } }
    # update envs
    $envs = $envs | Where-Object { $_ -notlike 'RETALIQ_ALLOWED_IPS=*' }
    $envs += "RETALIQ_ALLOWED_IPS=$($cur -join ',')"
    Set-ItemProperty -Path $regPath -Name 'Environment' -Value $envs -Force
    Write-Output "Appended IP(s) to service allowed list and updated service environment"
    Restart-Service -Name $ServiceName -Force
}

function Unregister-ServiceFlow {
    if (Test-Path .\unregister-service.ps1) { & .\unregister-service.ps1 -ServiceName RetaliqHosts }
    else { Write-Error 'unregister-service.ps1 not found' }
}

# Interactive menu
Write-Output "RetaliqHosts setup - choose an action:"
Write-Output "1) Setup service"
Write-Output "2) Reload service (apply .env to service and restart)"
Write-Output "3) Unregister service"
Write-Output "4) Append manual allowed IP(s) to service (no .env change)"
Write-Output "q) Quit"

$choice = Read-Host "Enter choice [1/2/3/q]"
switch ($choice) {
    '1' { Setup-ServiceFlow }
    '2' { Reload-Service }
    '3' { Unregister-ServiceFlow }
    '4' { Append-ManualAllowedIp }
    'q' { Write-Output 'Exit.' }
    default { Write-Warning 'Unknown choice' }
}
