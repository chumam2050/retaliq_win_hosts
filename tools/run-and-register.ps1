param(
    [string] $BuildDir = ".\build",
    [string] $ExeName = "RetaliqHosts.exe",
    [string] $Arch = 'auto', # values: auto, x64, x86
    [string] $ServiceName = "RetaliqHosts",
    [string] $DisplayName = "RetaliqHosts Service",
    [string] $Description = "Service that updates Windows hosts based on received payloads",
    [string] $Username = '',
    [string] $Password = '',
    [string] $AllowedIps = '',
    [string] $ApiKey = '',
    [switch] $Force
)

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

    # Rebuild argument list to pass to elevated PowerShell
    $argParts = @()
    if ($BuildDir) { $argParts += "-BuildDir `"$BuildDir`"" }
    if ($ExeName) { $argParts += "-ExeName `"$ExeName`"" }
    if ($ServiceName) { $argParts += "-ServiceName `"$ServiceName`"" }
    if ($DisplayName) { $argParts += "-DisplayName `"$DisplayName`"" }
    if ($Description) { $argParts += "-Description `"$Description`"" }
    if ($Username) { $argParts += "-Username `"$Username`"" }
    if ($Password) { $argParts += "-Password `"$Password`"" }
    if ($Force) { $argParts += "-Force" }

    $argsString = $argParts -join ' '

    $scriptPath = $PSCommandPath
    $psi = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" $argsString"
    Start-Process -FilePath powershell -Verb RunAs -ArgumentList $psi
    exit
}


# Now running elevated
try {
    $fullBuildDir = Resolve-Path -Path $BuildDir -ErrorAction Stop | Select-Object -First 1 -ExpandProperty Path
}
catch {
    Write-Error "Build directory '$BuildDir' not found. Please build the project into that folder or pass -BuildDir pointing to the folder containing your build subfolders."
    exit 1
}

# Determine desired architecture
$archNormalized = $Arch.ToLower()
if ($archNormalized -eq 'auto') {
    if ([Environment]::Is64BitOperatingSystem) { $archNormalized = 'x64' } else { $archNormalized = 'x86' }
}

$archFolder = if ($archNormalized -eq 'x64') { 'win-x64' } elseif ($archNormalized -eq 'x86') { 'win-x86' } else { $archNormalized }

$candidatePath = Join-Path $fullBuildDir $archFolder
if (-not (Test-Path $candidatePath)) {
    # try fallback to whichever exists
    $alt64 = Join-Path $fullBuildDir 'win-x64'
    $alt86 = Join-Path $fullBuildDir 'win-x86'
    if (Test-Path $alt64) { $candidatePath = $alt64; Write-Warning "Requested arch '$Arch' not found; falling back to win-x64" }
    elseif (Test-Path $alt86) { $candidatePath = $alt86; Write-Warning "Requested arch '$Arch' not found; falling back to win-x86" }
    else {
        Write-Error "No architecture-specific build folders found under '$fullBuildDir'. Expected 'win-x64' or 'win-x86'."
        Write-Output "Contents:`n$(Get-ChildItem -Path $fullBuildDir | ForEach-Object { $_.Name })"
        exit 1
    }
}

$exePath = Join-Path $candidatePath $ExeName
if (-not (Test-Path $exePath)) {
    Write-Warning "Executable not found at expected path '$exePath'. Searching recursively under '$candidatePath'..."
    $found = Get-ChildItem -Path $candidatePath -Filter $ExeName -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) {
        $exePath = $found.FullName
        Write-Output "Found executable at '$exePath'."
    }
    else {
        Write-Warning "Not found under arch folder. Searching entire build directory '$fullBuildDir'..."
        $foundAll = Get-ChildItem -Path $fullBuildDir -Filter $ExeName -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($foundAll) {
            $exePath = $foundAll.FullName
            Write-Output "Found executable at '$exePath'."
        }
        else {
            Write-Error "Executable '$ExeName' not found under '$fullBuildDir'. Please publish the project into the build folder before running this script."
            Write-Output "Contents (top-level):`n$(Get-ChildItem -Path $fullBuildDir | ForEach-Object { $_.Name })"
            exit 1
        }
    }
}

$registerScript = Join-Path (Split-Path -Parent $PSCommandPath) "register-service.ps1"
if (-not (Test-Path $registerScript)) {
    Write-Error "Register script not found at '$registerScript'."
    exit 1
}

Write-Output "Registering service using executable: $exePath"

# Build invocation for register-service.ps1 using direct parameter passing to avoid quoting issues
    Write-Output "Executing register script with resolved parameters..."

    $resolvedExe = (Resolve-Path $exePath).Path

    $params = @{
        ExePath = $resolvedExe
        ServiceName = $ServiceName
        DisplayName = $DisplayName
        Description = $Description
    }

    if ($Username -and $Password) { $params.Username = $Username; $params.Password = $Password }
    elseif ($Username) { $params.Username = $Username }

    & $registerScript @params -ErrorAction Stop | Out-Default

    # Add Windows Firewall rule to allow HTTP on 8888 so WSL/Docker can reach the service
    if ($IsWindows) {
        try {
            $ruleName = 'RetaliqHosts HTTP'
            $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
            if (-not $existing) {
                Write-Output "Creating Windows Firewall rule: $ruleName (port 8888)"
                New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -LocalPort 8888 -Protocol TCP -Action Allow -Profile Private,Public -ErrorAction Stop | Out-Null
            }
            else {
                Write-Output "Firewall rule '$ruleName' already exists"
            }
        }
        catch {
            Write-Warning "Failed to add firewall rule: $_"
        }
    }

    # Set environment variables for service (RETALIQ_ALLOWED_IPS and RETALIQ_API_KEY)
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
        $existing = Get-ItemProperty -Path $regPath -Name "Environment" -ErrorAction SilentlyContinue
        $envs = @()
        if ($existing) { $envs = $existing.Environment }

        if ($AllowedIps) {
            Write-Output "Preparing RETALIQ_ALLOWED_IPS for service $ServiceName"
            $envs = $envs | Where-Object { -not ($_ -like 'RETALIQ_ALLOWED_IPS=*') }
            $envs += "RETALIQ_ALLOWED_IPS=$AllowedIps"
        }
        if ($ApiKey) {
            Write-Output "Preparing RETALIQ_API_KEY for service $ServiceName"
            $envs = $envs | Where-Object { -not ($_ -like 'RETALIQ_API_KEY=*') }
            $envs += "RETALIQ_API_KEY=$ApiKey"
        }

        if ($envs.Count -gt 0) {
            Set-ItemProperty -Path $regPath -Name "Environment" -Value $envs -Force
            Write-Output "Service environment variables updated. Restart the service to apply them."
        }
    }
    catch {
        Write-Warning "Failed to set service environment variables: $_"
    }

    Write-Output "Done."
