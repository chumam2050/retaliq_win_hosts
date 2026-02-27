<#
    build-all.ps1

    Publish the RetaliqHosts project for win-x64 and win-x86 and place outputs
    directly under <repo-root>\build\win-x64 and build\win-x86.

    Usage (from repo root):
      .\build-all.ps1
      .\build-all.ps1 -ProjectPath .\RetaliqHosts.csproj -OutputRoot .\build -SelfContained $true -Force
#>

param(
    [string] $ProjectPath = ".\RetaliqHosts.csproj",
    [string] $OutputRoot = ".\build",
    [string[]] $RIDs = @("win-x64","win-x86"),
    [string] $Configuration = "Release",
    [bool] $SelfContained = $true,
    [switch] $Force
)

function Resolve-ProjectPath($p) {
    try { return (Resolve-Path -Path $p -ErrorAction Stop).Path }
    catch {
        $scriptDir = Split-Path -Parent $PSCommandPath
        $candidate = Join-Path $scriptDir $p
        try { return (Resolve-Path -Path $candidate -ErrorAction Stop).Path } catch { }
        Write-Error "Project path '$p' not found."; exit 1
    }
}

$proj = Resolve-ProjectPath $ProjectPath

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    Write-Error "dotnet CLI not found in PATH. Install .NET SDK or add it to PATH."; exit 2
}

$rootOut = Resolve-Path -Path $OutputRoot -ErrorAction SilentlyContinue
if (-not $rootOut) { New-Item -ItemType Directory -Path $OutputRoot | Out-Null }
$rootOut = (Resolve-Path -Path $OutputRoot).Path

Write-Output "Project: $proj"
Write-Output "Output root: $rootOut"
Write-Output "Configuration: $Configuration"
Write-Output "Self-contained: $SelfContained"

foreach ($rid in $RIDs) {
    $outDir = Join-Path $rootOut $rid
    if (Test-Path $outDir) {
        if ($Force) {
            Write-Output "Removing existing output: $outDir"
            Remove-Item -Recurse -Force -Path $outDir
        }
        else {
            Write-Output "Output exists for $rid at $outDir. Use -Force to overwrite. Skipping."
            continue
        }
    }

    Write-Output "Publishing for runtime identifier: $rid"
    $sc = if ($SelfContained) { 'true' } else { 'false' }
    dotnet publish $proj -c $Configuration -r $rid --self-contained $sc -o $outDir
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        Write-Error "dotnet publish failed for $rid (exit $exitCode)."
        exit $exitCode
    }

    Write-Output "Published $rid -> $outDir"

    # Create a zip archive of the published output
    try {
        $zipPath = Join-Path $rootOut ("$rid.zip")
        if (Test-Path $zipPath) {
            if ($Force) { Remove-Item -Path $zipPath -Force }
            else { Write-Output "Zip already exists at $zipPath (use -Force to overwrite). Skipping zip."; continue }
        }

        Write-Output "Creating zip archive: $zipPath"
        Compress-Archive -Path (Join-Path $outDir '*') -DestinationPath $zipPath -Force
        Write-Output "Created archive: $zipPath"
    }
    catch {
        Write-Warning ("Failed to create zip for {0}: {1}" -f $outDir, $_)
    }
}

Write-Output "All done."
