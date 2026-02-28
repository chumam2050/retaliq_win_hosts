param(
    [string] $BuildDir = ".\build",
    [string] $ExeName = "RetaliqHosts.exe",
    [string] $Arch = 'auto',
    [string] $ServiceName = "RetaliqHosts",
    [string] $DisplayName = "RetaliqHosts Service",
    [string] $Description = "Service that updates Windows hosts based on received payloads",
    [string] $Username = '',
    [string] $Password = '',
    [string] $AllowedIps = '',
    [string] $ApiKey = '',
    [switch] $Force
)

# Support callers that pass an argument array incorrectly bound: fallback parse $args into named params
if ($args.Count -gt 0) {
    for ($i = 0; $i -lt $args.Count; $i++) {
        $a = $args[$i]
        if ($a -like '-*') {
            $name = $a.TrimStart('-')
            # next value may be a flag or a value
            $next = $null
            if ($i + 1 -lt $args.Count) { $next = $args[$i+1] }
            switch ($name.ToLower()) {
                'builddir' { if ($next -and $next -notlike '-*') { $BuildDir = $next; $i++ } }
                'exename' { if ($next -and $next -notlike '-*') { $ExeName = $next; $i++ } }
                'arch' { if ($next -and $next -notlike '-*') { $Arch = $next; $i++ } }
                'servicename' { if ($next -and $next -notlike '-*') { $ServiceName = $next; $i++ } }
                'displayname' { if ($next -and $next -notlike '-*') { $DisplayName = $next; $i++ } }
                'description' { if ($next -and $next -notlike '-*') { $Description = $next; $i++ } }
                'username' { if ($next -and $next -notlike '-*') { $Username = $next; $i++ } }
                'password' { if ($next -and $next -notlike '-*') { $Password = $next; $i++ } }
                'allowedips' { if ($next -and $next -notlike '-*') { $AllowedIps = $next; $i++ } }
                'apikey' { if ($next -and $next -notlike '-*') { $ApiKey = $next; $i++ } }
                'force' { $Force = $true }
                default { }
            }
        }
    }
}

function Test-IsAdministrator {
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

if (-not (Test-IsAdministrator)) {
    Write-Output "Not running as Administrator. Relaunching elevated..."
    $argParts = @()
    if ($BuildDir) { $argParts += "-BuildDir `"$BuildDir`"" }
    if ($ExeName) { $argParts += "-ExeName `"$ExeName`"" }
    if ($ServiceName) { $argParts += "-ServiceName `"$ServiceName`"" }
    if ($DisplayName) { $argParts += "-DisplayName `"$DisplayName`"" }
    if ($Description) { $argParts += "-Description `"$Description`"" }
    if ($Username) { $argParts += "-Username `"$Username`"" }
    if ($Password) { $argParts += "-Password `"$Password`"" }
    if ($AllowedIps) { $argParts += "-AllowedIps `"$AllowedIps`"" }
    if ($ApiKey) { $argParts += "-ApiKey `"$ApiKey`"" }
    if ($Force) { $argParts += "-Force" }
    $argsString = $argParts -join ' '
    $scriptPath = $PSCommandPath
    $psi = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" $argsString"
    Start-Process -FilePath powershell -Verb RunAs -ArgumentList $psi
    exit
}

# Delegate to register script (support scripts moved to repo root)
try {
    # Resolve build dir and locate executable
    $fullBuildDir = Resolve-Path -Path $BuildDir -ErrorAction Stop | Select-Object -First 1 -ExpandProperty Path
}
catch {
    Write-Error "Build directory '$BuildDir' not found."
    exit 1
}

# Determine desired architecture folder
$archNormalized = $Arch.ToLower()
if ($archNormalized -eq 'auto') { if ([Environment]::Is64BitOperatingSystem) { $archNormalized = 'x64' } else { $archNormalized = 'x86' } }
$archFolder = if ($archNormalized -eq 'x64') { 'win-x64' } elseif ($archNormalized -eq 'x86') { 'win-x86' } else { $archNormalized }

$candidatePath = Join-Path $fullBuildDir $archFolder
if (-not (Test-Path $candidatePath)) {
    $alt64 = Join-Path $fullBuildDir 'win-x64'
    $alt86 = Join-Path $fullBuildDir 'win-x86'
    if (Test-Path $alt64) { $candidatePath = $alt64; Write-Warning "Requested arch '$Arch' not found; falling back to win-x64" }
    elseif (Test-Path $alt86) { $candidatePath = $alt86; Write-Warning "Requested arch '$Arch' not found; falling back to win-x86" }
    else { Write-Error "No architecture-specific build folders found under '$fullBuildDir'."; exit 1 }
}

$exePath = Join-Path $candidatePath $ExeName
if (-not (Test-Path $exePath)) {
    Write-Warning "Executable not found at expected path '$exePath'. Searching recursively under '$candidatePath'..."
    $found = Get-ChildItem -Path $candidatePath -Filter $ExeName -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { $exePath = $found.FullName; Write-Output "Found executable at '$exePath'." }
    else {
        Write-Error "Executable '$ExeName' not found under '$candidatePath'. Please publish the project into the build folder before running this script."
        exit 1
    }
}

# Delegate to register script (support scripts moved to repo root or tools)
$candidateScripts = @('.\register-service.ps1', '.\tools\register-service.ps1')
$scriptToRun = $candidateScripts | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($scriptToRun) {
    Write-Output "Invoking registration script: $scriptToRun with exe path $exePath"
    # Build parameters for the register script
    $p = @{
        ExePath = $exePath
        ServiceName = $ServiceName
        DisplayName = $DisplayName
        Description = $Description
    }
    if ($Username) { $p.Username = $Username }
    if ($Password) { $p.Password = $Password }

    & $scriptToRun @p

    # If AllowedIps or ApiKey provided, also set them on the service registry Environment
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
        $existing = Get-ItemProperty -Path $regPath -Name 'Environment' -ErrorAction SilentlyContinue
        $envs = @()
        if ($existing) { $envs = $existing.Environment }
        if ($AllowedIps) {
            $envs = $envs | Where-Object { $_ -notlike 'RETALIQ_ALLOWED_IPS=*' }
            $envs += "RETALIQ_ALLOWED_IPS=$AllowedIps"
        }
        if ($ApiKey) {
            $envs = $envs | Where-Object { $_ -notlike 'RETALIQ_API_KEY=*' }
            $envs += "RETALIQ_API_KEY=$ApiKey"
        }
        if ($envs.Count -gt 0) { Set-ItemProperty -Path $regPath -Name 'Environment' -Value $envs -Force }
    }
    catch {
        Write-Warning "Failed to set service environment variables: $_"
    }
}
else {
    Write-Error "register-service.ps1 not found in repository root or tools folder."
    exit 1
}
