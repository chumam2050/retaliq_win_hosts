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

function Get-IPHost {
    try {
        # 1. Collect all IPs into an array
        $allIPs = @()
        # Get Host IPs (filtering for active physical/virtual adapters)
        $allIPs += (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notmatch '^127\.' }).IPAddress
        # Get WSL IPs (using 'ip addr' to support BusyBox/Docker-Desktop distros)
        $runningDistros = wsl --list --running --quiet | ForEach-Object { $_.Replace("`0", "").Trim() } | Where-Object { $_ }
        foreach ($distro in $runningDistros) {
            $wslIp = wsl -d $distro ip -o -4 addr show eth0 | ForEach-Object { ($_ -split ' +')[3].Split('/')[0] }
            if ($wslIp) { $allIPs += $wslIp }
        }
        # Get Docker Container IPs
        if (Get-Command docker -ErrorAction SilentlyContinue) {
            $containerIds = docker ps -q
            if ($containerIds) {
                # If containers are running, grab their specific IPs
                $allIPs += docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $containerIds | Where-Object { $_ }
            } else {
                # If no containers are running, append the default Docker Gateway/Bridge IP
                $allIPs += "172.17.0.1"
            }
        }

        # 2. Filter for Unique addresses and Join with Comma
        $uniqueIPs = $allIPs | Select-Object -Unique
        $result = $uniqueIPs -join ","
        return $result
    } catch {
        Write-Warning "Failed to get host IPs: $_"
        return $null
    }
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

    Write-Output "Ensured .env file exists (status: $ensureResult)"

    # If we created or overwrote the env file, generate defaults
    if ($ensureResult -eq 'created' -or $ensureResult -eq 'overwritten') {
        if (-not $env.ContainsKey('RETALIQ_API_KEY') -or [string]::IsNullOrWhiteSpace($env['RETALIQ_API_KEY']) -or $env['RETALIQ_API_KEY'] -eq 'replace-with-strong-secret') {
            $new = Generate-ApiKey
            $env['RETALIQ_API_KEY'] = $new
            Write-Output "Generated RETALIQ_API_KEY"
        }

        # Build allowed list with loopback + discovered addresses
        $allowed = @('127.0.0.1')
        $allIPs = Get-IPHost
        if ($allIPs) { $allowed += $allIPs.Split(',') }
        $env['RETALIQ_ALLOWED_IPS'] = ($allowed -join ',')
        Write-Output "Set RETALIQ_ALLOWED_IPS to: $($env['RETALIQ_ALLOWED_IPS'])"
    }

    # Ensure .env contains at least an API key
    if (-not $env.ContainsKey('RETALIQ_API_KEY') -or [string]::IsNullOrWhiteSpace($env['RETALIQ_API_KEY'])) {
        $env['RETALIQ_API_KEY'] = Generate-ApiKey
        Write-Output 'Generated RETALIQ_API_KEY (missing)'
    }

    Write-Env $envPath $env
    Write-Output ".env updated with API key and allowed IPs"

    # Find the executable under build/<arch>
    $exe = Find-ExeInBuild -BuildRoot (Join-Path (Get-Location) 'build') -Arch $arch -ExeName 'RetaliqHosts.exe'
    if (-not $exe) { Write-Error 'Executable not found; cannot register service'; return }

    # Register service and apply environment
    Register-Service -ExePath $exe -ServiceName 'RetaliqHosts' -DisplayName 'RetaliqHosts Service' -Description 'Service that updates Windows hosts based on received payloads'

    # Apply .env to service registry and restart
    try {
        SetEnvFile -ServiceName 'RetaliqHosts'
        Start-Sleep -Seconds 2
        if (Get-Service -Name 'RetaliqHosts' -ErrorAction SilentlyContinue) {
            Restart-Service -Name 'RetaliqHosts' -Force -ErrorAction Stop
            # Wait for service to reach Running state (up to 15s)
            $attempts = 0
            do {
                Start-Sleep -Seconds 1
                $svc = Get-Service -Name 'RetaliqHosts'
                $attempts++
            } while ($svc.Status -ne 'Running' -and $attempts -lt 15)

            if ($svc.Status -eq 'Running') { Write-Output 'RetaliqHosts is running.' } else { Write-Warning "RetaliqHosts did not reach Running state (status: $($svc.Status))." }
        }
        else { Write-Warning 'Service RetaliqHosts not found to restart.' }
    }
    catch { Write-Warning "Failed to restart/wait for service: $_" }

}

function Find-ExeInBuild {
    param(
        [string] $BuildRoot,
        [string] $Arch,
        [string] $ExeName
    )
    try {
        $root = Resolve-Path -Path $BuildRoot -ErrorAction Stop | Select-Object -First 1 -ExpandProperty Path
    }
    catch { return $null }

    $archNormalized = $Arch.ToLower()
    if ($archNormalized -eq 'auto') { if ([Environment]::Is64BitOperatingSystem) { $archNormalized = 'x64' } else { $archNormalized = 'x86' } }
    $archFolder = if ($archNormalized -eq 'x64') { 'win-x64' } elseif ($archNormalized -eq 'x86') { 'win-x86' } else { $archNormalized }

    $candidate = Join-Path $root $archFolder
    if (-not (Test-Path $candidate)) {
        $alt64 = Join-Path $root 'win-x64'
        $alt86 = Join-Path $root 'win-x86'
        if (Test-Path $alt64) { $candidate = $alt64 }
        elseif (Test-Path $alt86) { $candidate = $alt86 }
        else { return $null }
    }

    $path = Join-Path $candidate $ExeName
    if (Test-Path $path) { return (Resolve-Path $path).Path }
    $found = Get-ChildItem -Path $candidate -Filter $ExeName -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { return $found.FullName }
    return $null
}

function Register-Service {
    param(
        [string] $ExePath = "./publish/RetaliqHosts.exe",
        [string] $ServiceName = "RetaliqHosts",
        [string] $DisplayName = "RetaliqHosts Service",
        [string] $Description = "Service that updates Windows hosts based on received payloads",
        [string] $Username = '',
        [string] $Password = ''
    )

    try {
        $ExePathResolved = (Resolve-Path -Path $ExePath -ErrorAction Stop).Path
    }
    catch {
        Write-Error "Executable not found at $ExePath. Publish the project first to create the binary."
        exit 1
    }

    # Stop and remove existing service if present
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Write-Output "Stopping existing service..."
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Write-Output "Removing existing service..."
        sc.exe delete $ServiceName | Out-Null
        Start-Sleep -Seconds 1
    }

    # If a username is provided, ensure we have a password (prompt if not supplied)
    $obj = 'LocalSystem'
    $pwdPlain = ''
    if (-not [string]::IsNullOrWhiteSpace($Username)) {
        $obj = $Username
        if ([string]::IsNullOrWhiteSpace($Password)) {
            # Prompt for secure password
            $secure = Read-Host -AsSecureString -Prompt "Enter service account password for $Username"
            try {
                $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
                $pwdPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
            }
            catch {
                Write-Error "Failed to convert secure password to plain text."
                exit 1
            }
        }
        else {
            $pwdPlain = $Password
        }
    }

    Write-Output "Creating service $ServiceName pointing to $ExePath"

    # Build sc.exe create command
    $createArgs = @()
    $createArgs += "create `"$ServiceName`""
    $createArgs += "binPath= `"$ExePath`""
    $createArgs += "DisplayName= `"$DisplayName`""
    $createArgs += "start= auto"
    $createArgs += "obj= `"$obj`""
    if (-not [string]::IsNullOrEmpty($pwdPlain)) {
        $createArgs += "password= `"$pwdPlain`""
    }

    $cmd = "sc.exe " + ($createArgs -join ' ')
    Invoke-Expression $cmd

    if ($LASTEXITCODE -eq 0) {
        # Set description if provided
        if (-not [string]::IsNullOrWhiteSpace($Description)) {
            sc.exe description $ServiceName `"$Description`" | Out-Null
        }

        Write-Output "Service created. Sending start request..."
        # Use sc.exe start to avoid PowerShell Start-Service blocking if the service does not reach Running state
        sc.exe start $ServiceName | Out-Null
        Write-Output "Start request sent. The service may take a moment to reach Running state."
    } else {
        Write-Error "Failed to create service"
    }
}

function Reload-Service {
    if (Get-Service -Name RetaliqHosts -ErrorAction SilentlyContinue) {
        # reload .env into service environment then restart
        SetEnvFile -ServiceName RetaliqHosts
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
    $envs = @()
    $cur = @()
    $envEntry = $envs | Where-Object { $_ -like 'RETALIQ_ALLOWED_IPS=*' }
    if ($envEntry) { $cur = ($envEntry -replace '^RETALIQ_ALLOWED_IPS=','').Split(',') | ForEach-Object { $_.Trim() } }
    foreach ($it in $items) { if ($cur -notcontains $it) { $cur += $it } }
    # update envs
    $envs = $envs | Where-Object { $_ -notlike 'RETALIQ_ALLOWED_IPS=*' }
    $envs += "RETALIQ_ALLOWED_IPS=$($cur -join ',')"
    SetEnvFile -ServiceName $ServiceName
    Write-Output "Appended IP(s) to service allowed list and updated service environment"
    Restart-Service -Name RetaliqHosts -Force
}

function Unregister-ServiceFlow {
    param(
        [string] $ServiceName = 'RetaliqHosts'
    )

    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Write-Output "Stopping service $ServiceName..."
        try { Stop-Service -Name $ServiceName -Force -ErrorAction Stop } catch { Write-Warning "Failed to stop service: $_" }

        Write-Output "Removing service $ServiceName..."
        try {
            sc.exe delete $ServiceName | Out-Null
            Start-Sleep -Seconds 1
        }
        catch { Write-Warning "Failed to delete service: $_" }

        # cleanup Environment registry value if present
        try {
            $rk = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Services\$ServiceName", $true)
            if ($rk -ne $null) {
                if ($rk.GetValueNames() -contains 'Environment') {
                    $rk.DeleteValue('Environment', $false)
                }
                $rk.Close()
            }
        }
        catch { Write-Warning "Failed to clean service registry: $_" }

        Write-Output "$ServiceName unregistered."
    }
    else {
        Write-Warning "Service $ServiceName not found."
    }
}

function Regenerate-ApiKeyFlow {
    $envPath = Join-Path (Get-Location) '.env'
    if (-not (Test-Path $envPath)) {
        Write-Warning '.env not found. Run setup to create one first.'
        return
    }

    $env = Read-Env $envPath
    $old = $null
    if ($env.ContainsKey('RETALIQ_API_KEY')) { $old = $env['RETALIQ_API_KEY'] }

    $new = Generate-ApiKey
    $env['RETALIQ_API_KEY'] = $new
    Write-Env $envPath $env
    Write-Output "Generated new RETALIQ_API_KEY: $new"

    SetEnvFile -ServiceName 'RetaliqHosts'

    Restart-Service -Name RetaliqHosts -Force
}

function SetEnvFile {
    param(
        [string] $ServiceName = 'RetaliqHosts'
    )
    try {
        $envPath = Join-Path (Get-Location) '.env'
        $envs = Read-Env $envPath
        $AllowedIps = $envs['RETALIQ_ALLOWED_IPS'] 
        $ApiKey = $envs['RETALIQ_API_KEY'] 
        if ($envs.Count -gt 0) {
            # Ensure we write a REG_MULTI_SZ value
            try {
               $rk = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Services\RetaliqHosts', $true)
               $new = [string[]]@(
                  "RETALIQ_ALLOWED_IPS=$AllowedIps",
                  "RETALIQ_API_KEY=$ApiKey"
               )
               $rk.SetValue('Environment', $new, [Microsoft.Win32.RegistryValueKind]::MultiString)
               $rk.Close()
            }
            catch {
                Write-Warning "Failed to write registry Environment as MultiString, falling back: $_"
                Set-ItemProperty -Path $regPath -Name 'Environment' -Value $envs -Force
            }
        }
    }
    catch {
        Write-Warning "Failed to set service environment variables: $_"
    }
}

# Interactive menu
Write-Output "RetaliqHosts setup - choose an action:"
Write-Output "1) Register service"
Write-Output "2) Unregister service"
Write-Output "3) Reload service (apply .env to service and restart)"
Write-Output "4) Regenerate API key and apply to service"
Write-Output "q) Quit"

$choice = Read-Host "Enter choice [1/2/3/4/q]"
switch ($choice) {
    '1' { Setup-ServiceFlow }
    '2' { Unregister-ServiceFlow }
    '3' { Reload-Service }
    '4' { Regenerate-ApiKeyFlow }
    'q' { Write-Output 'Exit.' }
    default { Write-Warning 'Unknown choice' }
}
