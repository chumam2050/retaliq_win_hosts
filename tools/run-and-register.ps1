param(
    [string] $BuildDir = ".\build",
    [string] $ExeName = "RetaliqHosts.exe",
    [string] $Arch = 'auto', # values: auto, x64, x86
    [string] $ServiceName = "RetaliqHosts",
    [string] $DisplayName = "RetaliqHosts Service",
    [string] $Description = "Service that updates Windows hosts based on received payloads",
    [string] $Username = '',
    [string] $Password = '',
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
    Write-Error "Executable not found at '$exePath'. Please publish the project into the build subfolder before running this script."
    exit 1
}

$registerScript = Join-Path (Split-Path -Parent $PSCommandPath) "register-service.ps1"
if (-not (Test-Path $registerScript)) {
    Write-Error "Register script not found at '$registerScript'."
    exit 1
}

Write-Output "Registering service using executable: $exePath"

# Build invocation for register-service.ps1
$invokeArgs = @()
$invokeArgs += "-ExePath `"$(Resolve-Path $exePath)`""
$invokeArgs += "-ServiceName `"$ServiceName`""
$invokeArgs += "-DisplayName `"$DisplayName`""
$invokeArgs += "-Description `"$Description`""
if ($Username) { $invokeArgs += "-Username `"$Username`"" }
if ($Password) { $invokeArgs += "-Password `"$Password`"" }
if ($Force) { $invokeArgs += "-Force" }

$cmd = "$registerScript " + ($invokeArgs -join ' ')

Write-Output "Executing: $cmd"
& $registerScript @($invokeArgs) | Out-Default

Write-Output "Done." 
