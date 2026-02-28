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

# Delegate to tools script in tools folder
if (Test-Path .\tools\run-and-register.ps1) {
    .\tools\run-and-register.ps1 @PSBoundParameters
} else {
    Write-Error "tools\run-and-register.ps1 not found. Ensure scripts were moved to tools folder."
    exit 1
}
