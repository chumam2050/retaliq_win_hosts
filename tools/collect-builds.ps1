<#
    Collect published build outputs under a complex nested build folder and place
    each runtime publish into a clean folder under the build root.

    Example:
      .\tools\collect-builds.ps1 -BuildRoot .\build -ExeName RetaliqHosts.exe -Force

    This will search for all occurrences of the executable and copy the containing
    publish folder to e.g. build\win-x64 and build\win-x86.
#>
param(
    [string] $BuildRoot = ".\build",
    [string] $ExeName = "RetaliqHosts.exe",
    [switch] $Force
)

try {
    $root = (Resolve-Path -Path $BuildRoot -ErrorAction Stop).Path
}
catch {
    Write-Error "Build root '$BuildRoot' not found."
    exit 1
}

Write-Output "Searching for '$ExeName' under: $root"

$found = Get-ChildItem -Path $root -Filter $ExeName -Recurse -File -ErrorAction SilentlyContinue
if (-not $found) {
    Write-Warning "No '$ExeName' files found under $root"
    exit 0
}

foreach ($f in $found) {
    $exeDir = $f.Directory.FullName
    # Determine architecture label from path
    $arch = if ($exeDir -match 'win-x64') { 'win-x64' } elseif ($exeDir -match 'win-x86') { 'win-x86' } else {
        # fallback: use directory name of parent
        Split-Path -Leaf $exeDir
    }

    $dest = Join-Path $root $arch
    if (Test-Path $dest) {
        if ($Force) {
            Write-Output "Removing existing destination: $dest"
            Remove-Item -Recurse -Force -Path $dest
        }
        else {
            Write-Output "Destination already exists: $dest (use -Force to overwrite). Skipping copy from $exeDir"
            continue
        }
    }

    Write-Output "Copying publish contents from '$exeDir' -> '$dest'"
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    # Copy all files from exe directory (and subfolders) to destination
    Copy-Item -Path (Join-Path $exeDir '*') -Destination $dest -Recurse -Force

    Write-Output "Copied $($f.FullName) to $dest"
}

Write-Output "Collect complete."
