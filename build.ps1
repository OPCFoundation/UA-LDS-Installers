<#
.SYNOPSIS
    UA Local Discovery Server - Build Script

.DESCRIPTION
    Orchestrates the full LDS build pipeline that the old Jenkins job did:
      1. Bump version, generate buildversion.h
      2. Per arch: build OpenSSL 3.5.6 from upstream source (if not already built)
      3. Per arch: build UA-LDS (opcualds.exe + dnssd.dll) via CMake
      4. Per arch: build mDNSResponder.exe via CMake          [TODO until port]
      5. Per arch: build ldsca.dll (MSI custom actions)       [TODO until port]
      6. Per arch: stage binaries + sign
      7. Per arch: WiX merge module + installer + sign
      8. Bundle redistributable ZIP

    Steps 4-5 currently fail loudly with "TODO: not yet ported" markers; the
    WiX phase is skipped automatically when staging is incomplete. That lets
    you smoke-test the OpenSSL + UA-LDS portion today and incrementally light
    up the rest of the pipeline.

.PARAMETER Platform
    Target platform: x86, x64, or both (default: both)

.PARAMETER Clean
    Remove CMake build directories before rebuilding (does NOT rebuild OpenSSL).

.PARAMETER CleanOpenSSL
    Force re-fetch + re-build of OpenSSL for each requested arch.

.PARAMETER Spectre
    Add /Qspectre. Requires Spectre-mitigated libs installed via VS Installer.

.PARAMETER SkipWix
    Build binaries only; do not run wix.

.NOTES
    Prereqs (one-time setup):
      - VS 2022 or newer with C++ desktop workload, MSVC v143 toolset
      - CMake 3.20+
      - WiX v4+: dotnet tool install --global wix
      - Strawberry Perl (for OpenSSL Configure)
      - AzureSignTool (only if code signing): dotnet tool install --global AzureSignTool

    Code signing credentials in env:
      $env:SigningVaultURL, $env:SigningClientId, $env:SigningClientSecret,
      $env:SigningTenantId, $env:SigningCertName, $env:SigningURL
    If $env:SigningClientSecret is empty/unset, signing is skipped.
#>

[CmdletBinding()]
param(
    [ValidateSet('x86', 'x64', 'both')]
    [string]$Platform = 'both',

    [switch]$Clean,
    [switch]$CleanOpenSSL,
    [switch]$Spectre,
    [switch]$SkipWix,

    [string]$BuildRoot,
    [string]$OutDir,
    [string]$WixCmd
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RepoRoot    = Split-Path -Parent $ScriptDir
$UaLdsDir    = Join-Path $RepoRoot 'UA-LDS'
$MdnsDir     = Join-Path $RepoRoot 'UA-LDS-mDNSResponder'
$CaDir       = Join-Path $ScriptDir 'CustomActions'
$WixDir      = Join-Path $ScriptDir 'WiX'
$CmakeDir    = Join-Path $ScriptDir 'cmake'
$OldDir      = Join-Path $RepoRoot 'UA-LDS-Installers-Old'

if (-not $BuildRoot) { $BuildRoot = if ($env:BUILD_ROOT) { $env:BUILD_ROOT } else { Join-Path $ScriptDir 'build' } }
if (-not $OutDir)    { $OutDir    = if ($env:OUT_DIR)    { $env:OUT_DIR }    else { Join-Path $ScriptDir 'out' } }
if (-not $WixCmd)    { $WixCmd    = if ($env:WIX_CMD)    { $env:WIX_CMD }    else { 'wix' } }

$HardeningCmake = Join-Path $CmakeDir 'Hardening.cmake'

# ---------------------------------------------------------------------------
# Tool checks
# ---------------------------------------------------------------------------
function Assert-Tool {
    param([string]$Name, [string]$Hint)
    try {
        $null = Get-Command $Name -ErrorAction Stop
    } catch {
        throw "Required tool '$Name' not found on PATH. $Hint"
    }
}

Assert-Tool 'cmake' 'Install via Visual Studio Installer or cmake.org.'
Assert-Tool 'perl'  'Install Strawberry Perl (https://strawberryperl.com) - required by OpenSSL Configure.'
Assert-Tool 'git'   'Required to clone OpenSSL.'
if (-not $SkipWix) {
    Assert-Tool $WixCmd 'Install with: dotnet tool install --global wix'

    # Install the WiX extensions we use, matching the wix tool's version.
    # `wix extension add` is idempotent and silent when already present.
    $wixVer = (& $WixCmd --version) -replace '\+.*',''
    foreach ($ext in 'WixToolset.Util.wixext','WixToolset.Firewall.wixext','WixToolset.UI.wixext') {
        & $WixCmd extension add "$ext/$wixVer" 2>$null | Out-Null
    }
}

# ---------------------------------------------------------------------------
# Locate vcvarsall.bat (needed to set the right env for OpenSSL's nmake build)
# ---------------------------------------------------------------------------
function Find-VcVarsAll {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) {
        throw "vswhere.exe not found. Visual Studio Installer required."
    }
    $vsRoot = (& $vswhere -latest -products * -requires Microsoft.VisualStudio.Workload.NativeDesktop -property installationPath) | Select-Object -First 1
    if (-not $vsRoot) { throw "No Visual Studio install with the C++ desktop workload was found." }
    $vcvars = Join-Path $vsRoot 'VC\Auxiliary\Build\vcvarsall.bat'
    if (-not (Test-Path $vcvars)) { throw "vcvarsall.bat not found at $vcvars" }
    return $vcvars
}
$VcVarsAll = Find-VcVarsAll

# ---------------------------------------------------------------------------
# Code signing detection
# ---------------------------------------------------------------------------
$SigningEnabled = -not [string]::IsNullOrWhiteSpace($env:SigningClientSecret)
if ($SigningEnabled) {
    try { & AzureSignTool --version 2>$null | Out-Null; if ($LASTEXITCODE -ne 0) { throw } }
    catch { throw "Signing requested but AzureSignTool not found. Install with: dotnet tool install --global AzureSignTool" }
    Write-Host 'Code signing: ENABLED'
} else {
    Write-Host 'Code signing: DISABLED (SigningClientSecret not set)'
}

function Sign-Files {
    param([string[]]$Files)
    if (-not $SigningEnabled) { return }
    $existing = @($Files | Where-Object { Test-Path $_ })
    if ($existing.Count -eq 0) { return }
    Write-Host "  Signing $($existing.Count) file(s)..."
    & AzureSignTool sign `
        -kvu $env:SigningVaultURL `
        -kvi $env:SigningClientId `
        -kvs $env:SigningClientSecret `
        -kvt $env:SigningTenantId `
        -kvc $env:SigningCertName `
        -tr  $env:SigningURL `
        -td  sha256 `
        @existing | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Code signing failed.' }
}

# ---------------------------------------------------------------------------
# Version: parse version.txt, bump build.txt, regenerate UA-LDS buildversion.h
# and patch config.h's UALDS_CONF_VERSION_PATCH/BUILD lines.
# ---------------------------------------------------------------------------
$VersionFile = Join-Path $ScriptDir 'version.txt'
$BuildFile   = Join-Path $ScriptDir 'build.txt'
if (-not (Test-Path $VersionFile)) { throw "Missing $VersionFile" }
if (-not (Test-Path $BuildFile))   { throw "Missing $BuildFile" }

$Major = $null; $Minor = $null; $Revision = $null
foreach ($line in (Get-Content $VersionFile)) {
    if ($line -match '^\s*MAJOR\s*=\s*(\d+)')    { $Major    = [int]$Matches[1] }
    if ($line -match '^\s*MINOR\s*=\s*(\d+)')    { $Minor    = [int]$Matches[1] }
    if ($line -match '^\s*REVISION\s*=\s*(\d+)') { $Revision = [int]$Matches[1] }
}
if ($null -eq $Major -or $null -eq $Minor -or $null -eq $Revision) {
    throw "Could not parse MAJOR/MINOR/REVISION from $VersionFile"
}
$Build = [int]((Get-Content $BuildFile -Raw).Trim()) + 1
Set-Content -Path $BuildFile -Value $Build -NoNewline

$Version       = "$Major.$Minor.$Revision.$Build"
$ShortVersion  = "$Major.$Minor.$Revision"
$CopyrightYear = (Get-Date).Year

# Regenerate UA-LDS\buildversion.h (replaces the old Perl XXX/YYY substitution)
$BuildVerH = Join-Path $UaLdsDir 'buildversion.h'
$buildVerLines = @(
    '/* Auto-generated by UA-LDS-Installers\build.ps1. Do not edit. */',
    '#ifndef __BUILDVERSION_H__',
    '#define __BUILDVERSION_H__',
    "#define BUILD_NUMBER $Build",
    '#endif'
)
Set-Content -Path $BuildVerH -Value $buildVerLines -Encoding ASCII

# Patch config.h's VERSION_PATCH and VERSION_BUILD lines (regex-replace works
# whether the file still has XXX/YYY placeholders or numeric leftovers).
$ConfigH = Join-Path $UaLdsDir 'config.h'
if (-not (Test-Path $ConfigH)) { throw "Missing $ConfigH" }
$cfg = Get-Content $ConfigH -Raw
$cfg = $cfg -replace 'define\s+UALDS_CONF_VERSION_MAJOR\s+\S+', "define UALDS_CONF_VERSION_MAJOR $Major"
$cfg = $cfg -replace 'define\s+UALDS_CONF_VERSION_MINOR\s+\S+', "define UALDS_CONF_VERSION_MINOR $Minor"
$cfg = $cfg -replace 'define\s+UALDS_CONF_VERSION_PATCH\s+\S+', "define UALDS_CONF_VERSION_PATCH $Revision"
$cfg = $cfg -replace 'define\s+UALDS_CONF_VERSION_BUILD\s+\S+', "define UALDS_CONF_VERSION_BUILD $Build"
Set-Content -Path $ConfigH -Value $cfg -Encoding ASCII -NoNewline

Write-Host ''
Write-Host "Building UA-LDS version $Version"
Write-Host ''

# ---------------------------------------------------------------------------
# Phase 2: OpenSSL - fetch upstream source + build for each requested arch
# Outputs into UA-LDS\stack\openssl-$arch\.  Static libs (no-shared).
# ---------------------------------------------------------------------------
function Build-OpenSSL {
    param([string]$Arch)

    $sslPrefix = Join-Path $UaLdsDir "stack\openssl-$Arch"
    $sslSource = Join-Path $UaLdsDir 'stack\openssl-src'
    $sslMarker = Join-Path $sslPrefix 'lib\libcrypto.lib'

    if ($CleanOpenSSL -and (Test-Path $sslPrefix)) {
        Write-Host "  Cleaning $sslPrefix"
        Remove-Item $sslPrefix -Recurse -Force
    }
    if (Test-Path $sslMarker) {
        Write-Host "OpenSSL ($Arch): already built at $sslPrefix - skipping"
        return
    }

    # Clone upstream OpenSSL at the pinned tag if not present
    if (-not (Test-Path (Join-Path $sslSource 'Configure'))) {
        Write-Host "OpenSSL: cloning upstream source (tag openssl-3.5.6)..."
        & git clone --branch openssl-3.5.6 --depth 1 https://github.com/openssl/openssl.git $sslSource | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "git clone of OpenSSL failed." }
    }

    $vcArg  = if ($Arch -eq 'x86') { 'x86' } else { 'x64' }
    $target = if ($Arch -eq 'x86') { 'VC-WIN32' } else { 'VC-WIN64A' }

    # nmake needs a vcvars'd env.  Use -vcvars_ver=14.4 to select the v143
    # (MSVC 14.4x) toolset even when a newer VS is installed.
    # Build the .cmd content as an array using format-operator interpolation
    # so the literal " characters in the output are unambiguous.
    $opensslLines = @(
        '@echo off',
        ('call "{0}" {1} -vcvars_ver=14.4 || exit /b 10' -f $VcVarsAll, $vcArg),
        ('cd /d "{0}" || exit /b 11' -f $sslSource),
        'nmake clean 1>nul 2>nul',
        ('perl Configure {0} no-shared no-asm no-ec no-autoload-config --prefix="{1}" --openssldir="{1}\ssl" || exit /b 12' -f $target, $sslPrefix),
        'nmake || exit /b 13',
        'nmake install_sw || exit /b 14',
        'exit /b 0'
    )
    $tmp = [System.IO.Path]::ChangeExtension([System.IO.Path]::GetTempFileName(), '.cmd')
    Set-Content -Path $tmp -Value $opensslLines -Encoding ASCII
    Write-Host "Building OpenSSL 3.5.6 ($Arch) - this takes 10-20 min the first time..."
    & cmd.exe /c $tmp | Out-Host
    $code = $LASTEXITCODE
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    if ($code -ne 0) { throw "OpenSSL build failed for $Arch (exit $code)." }

    # OpenSSL 3.x installs libs under lib (no libeay32/ssleay32 aliases needed
    # since UA-LDS's stack/CMakeLists uses FindOpenSSL which finds libcrypto.lib + libssl.lib).
    if (-not (Test-Path $sslMarker)) {
        throw "OpenSSL install did not produce $sslMarker."
    }
    Write-Host "OpenSSL ($Arch): built into $sslPrefix"
}

# ---------------------------------------------------------------------------
# Phase 3: UA-LDS (opcualds.exe, dnssd.dll, uastack.lib) via CMake
# ---------------------------------------------------------------------------
function Build-UALDS {
    param([string]$Arch)

    # UA-LDS's stack/Stack/CMakeLists hard-codes OPENSSL_ROOT_DIR to
    # ${_PROJECT_ROOT}/openssl.  We don't modify that file; instead, copy the
    # per-arch build into UA-LDS\stack\openssl right before configuring.
    $opensslPerArch = Join-Path $UaLdsDir "stack\openssl-$Arch"
    $opensslShared  = Join-Path $UaLdsDir 'stack\openssl'
    if (Test-Path $opensslShared) { Remove-Item $opensslShared -Recurse -Force }
    Copy-Item $opensslPerArch $opensslShared -Recurse -Force

    $BuildDir = Join-Path $BuildRoot "UA-LDS\$Arch"
    if ($Clean -and (Test-Path $BuildDir)) { Remove-Item $BuildDir -Recurse -Force }
    New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null

    $cmakeArch = if ($Arch -eq 'x86') { 'Win32' } else { 'x64' }
    Write-Host "Configuring UA-LDS ($Arch)..."

    # Apply per-arch extra hardening flags on top of cmake/Hardening.cmake:
    #   x86 → /SAFESEH
    #   x64 → /HIGHENTROPYVA
    # Plus optional /Qspectre.
    $extraC   = ''
    $extraExe = if ($Arch -eq 'x86') { '/SAFESEH' } else { '/HIGHENTROPYVA' }
    $extraDll = if ($Arch -eq 'x86') { '/SAFESEH' } else { '/HIGHENTROPYVA' }
    if ($Spectre) { $extraC += ' /Qspectre' }

    $args = @(
        '-S', $UaLdsDir, '-B', $BuildDir,
        '-A', $cmakeArch, '-T', 'v143',
        '-C', $HardeningCmake,
        "-DCMAKE_C_FLAGS=/GS /sdl /guard:cf /wd4996$extraC",
        "-DCMAKE_EXE_LINKER_FLAGS=/NXCOMPAT /DYNAMICBASE /GUARD:CF /SUBSYSTEM:CONSOLE,6.01 $extraExe",
        "-DCMAKE_SHARED_LINKER_FLAGS=/NXCOMPAT /DYNAMICBASE /GUARD:CF $extraDll"
    )
    & cmake @args | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "UA-LDS CMake configure failed for $Arch." }

    Write-Host "Building UA-LDS ($Arch)..."
    & cmake --build $BuildDir --config Release | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "UA-LDS build failed for $Arch." }

    # Output: <BuildDir>\bin\Release\opcualds.exe, dnssd.dll
    # (CMAKE_RUNTIME_OUTPUT_DIRECTORY in UA-LDS/CMakeLists is bin/)
    $binOut = Join-Path $BuildDir 'bin\Release'
    if (-not (Test-Path (Join-Path $binOut 'opcualds.exe'))) {
        throw "Expected opcualds.exe not produced at $binOut"
    }
    return $binOut
}

# ---------------------------------------------------------------------------
# Phase 4: mDNSResponder.exe - TODO: not yet ported to CMake
# ---------------------------------------------------------------------------
function Build-MDNSResponder {
    param([string]$Arch)
    $cml = Join-Path $MdnsDir 'CMakeLists.txt'
    if (-not (Test-Path $cml)) {
        Write-Host "  mDNSResponder ($Arch): SKIPPED - UA-LDS-mDNSResponder/CMakeLists.txt not yet present (Phase 2 of plan)." -ForegroundColor Yellow
        return $null
    }
    $BuildDir = Join-Path $BuildRoot "mDNSResponder\$Arch"
    if ($Clean -and (Test-Path $BuildDir)) { Remove-Item $BuildDir -Recurse -Force }
    New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
    $cmakeArch = if ($Arch -eq 'x86') { 'Win32' } else { 'x64' }
    $extraExe  = if ($Arch -eq 'x86') { '/SAFESEH' } else { '/HIGHENTROPYVA' }
    & cmake -S $MdnsDir -B $BuildDir -A $cmakeArch -T v143 -C $HardeningCmake `
        "-DCMAKE_EXE_LINKER_FLAGS=/NXCOMPAT /DYNAMICBASE /GUARD:CF /SUBSYSTEM:CONSOLE,6.01 $extraExe" | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "mDNSResponder CMake configure failed for $Arch." }
    & cmake --build $BuildDir --config Release | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "mDNSResponder build failed for $Arch." }
    return (Join-Path $BuildDir 'bin\Release')
}

# ---------------------------------------------------------------------------
# Phase 5: ldsca.dll (MSI custom actions) - TODO: not yet ported
# ---------------------------------------------------------------------------
function Build-CustomActions {
    param([string]$Arch)
    $cml = Join-Path $CaDir 'CMakeLists.txt'
    if (-not (Test-Path $cml)) {
        Write-Host "  CustomActions ($Arch): SKIPPED - UA-LDS-Installers/CustomActions/CMakeLists.txt not yet present (Phase 3 of plan)." -ForegroundColor Yellow
        return $null
    }
    $BuildDir = Join-Path $BuildRoot "CustomActions\$Arch"
    if ($Clean -and (Test-Path $BuildDir)) { Remove-Item $BuildDir -Recurse -Force }
    New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
    $cmakeArch = if ($Arch -eq 'x86') { 'Win32' } else { 'x64' }
    $extraDll  = if ($Arch -eq 'x86') { '/SAFESEH' } else { '/HIGHENTROPYVA' }
    & cmake -S $CaDir -B $BuildDir -A $cmakeArch -T v143 -C $HardeningCmake `
        "-DCMAKE_SHARED_LINKER_FLAGS=/NXCOMPAT /DYNAMICBASE /GUARD:CF $extraDll" | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "CustomActions CMake configure failed for $Arch." }
    & cmake --build $BuildDir --config Release | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "CustomActions build failed for $Arch." }
    return (Join-Path $BuildDir 'bin\Release')
}

# ---------------------------------------------------------------------------
# Phase 6: Stage binaries into out\$Arch\bin\
# ---------------------------------------------------------------------------
function Stage-Arch {
    param([string]$Arch, [string]$UaLdsBin, [string]$MdnsBin, [string]$CaBin)

    $StageBin = Join-Path $OutDir "$Arch\bin"
    if (Test-Path $StageBin) { Remove-Item $StageBin -Recurse -Force }
    New-Item -ItemType Directory -Path $StageBin -Force | Out-Null

    # From UA-LDS CMake build:
    Copy-Item (Join-Path $UaLdsBin 'opcualds.exe') $StageBin
    Copy-Item (Join-Path $UaLdsBin 'dnssd.dll')    $StageBin

    # ualds.ini (the default config the installer ships)
    Copy-Item (Join-Path $UaLdsDir 'etc\ualds.ini') $StageBin

    $staged = @{
        'opcualds.exe'      = $true
        'dnssd.dll'         = $true
        'ualds.ini'         = $true
        'mDNSResponder.exe' = $false
        'ldsca.dll'         = $false
    }

    if ($MdnsBin) {
        Copy-Item (Join-Path $MdnsBin 'mDNSResponder.exe') $StageBin
        $staged['mDNSResponder.exe'] = $true
    }
    if ($CaBin) {
        Copy-Item (Join-Path $CaBin 'ldsca.dll') $StageBin
        $staged['ldsca.dll'] = $true
    }

    # Sign whatever we did stage that's a PE binary
    if ($SigningEnabled) {
        $toSign = @($staged.GetEnumerator() | Where-Object { $_.Value -and ($_.Key -like '*.exe' -or $_.Key -like '*.dll') } | ForEach-Object { Join-Path $StageBin $_.Key })
        Sign-Files $toSign
    }

    Write-Host "Staged $Arch binaries in $StageBin"
    return $staged
}

# ---------------------------------------------------------------------------
# Phase 7: WiX (skipped if any required binary missing)
# ---------------------------------------------------------------------------
function Build-Wix {
    param([string]$Arch, [hashtable]$Staged)

    foreach ($k in @('opcualds.exe','dnssd.dll','ualds.ini','mDNSResponder.exe','ldsca.dll')) {
        if (-not $Staged[$k]) {
            Write-Host "WiX ($Arch): SKIPPED - staging incomplete (missing $k)." -ForegroundColor Yellow
            return
        }
    }

    $StageBin = Join-Path $OutDir "$Arch\bin"
    $WixOut   = Join-Path $OutDir 'wix'
    New-Item -ItemType Directory -Path $WixOut -Force | Out-Null

    # Stable per-arch GUIDs (used by WiX merge module Id).  Generated once,
    # don't change between versions.
    if ($Arch -eq 'x86') {
        $ModuleGuid = '8D3F1E54-3C2A-4A6B-9F1E-5E7F2C8A4001'
    } else {
        $ModuleGuid = '8D3F1E54-3C2A-4A6B-9F1E-5E7F2C8A4002'
    }
    # Preserved UpgradeCode from the InstallShield project (1.02.334 → 1.04.413).
    # DO NOT regenerate - field installs depend on this GUID for upgrade.
    $UpgradeCode = 'B264EE1D-BEDE-4E35-91D9-AEC6EB0E7DF7'

    $MsmName = "opc-ua-lds-mergemodule-$ShortVersion-$Arch.msm"
    $MsiName = "opc-ua-lds-$ShortVersion-$Arch.msi"
    $MsmPath = Join-Path $WixOut $MsmName
    $MsiPath = Join-Path $WixOut $MsiName

    Write-Host "WiX ($Arch): building merge module..."
    & $WixCmd build (Join-Path $WixDir 'MergeModule.wxs') `
        -arch $Arch `
        -ext WixToolset.Util.wixext `
        -ext WixToolset.Firewall.wixext `
        -d "BinDir=$StageBin" `
        -d "ModuleGuid=$ModuleGuid" `
        -d "Platform=$Arch" `
        -d "Version=$Version" `
        -bindpath $WixDir `
        -o $MsmPath | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "wix merge module build failed for $Arch." }
    Sign-Files @($MsmPath)

    Write-Host "WiX ($Arch): building installer..."
    & $WixCmd build (Join-Path $WixDir 'Installer.wxs') `
        -arch $Arch `
        -ext WixToolset.UI.wixext `
        -d "MsmFile=$MsmPath" `
        -d "UpgradeCode=$UpgradeCode" `
        -d "Version=$Version" `
        -d "Platform=$Arch" `
        -d "HelpDir=$(Join-Path $OutDir 'help')" `
        -d "CertGenDir=$(Join-Path $OutDir 'certgenerator')" `
        -bindpath $WixDir `
        -o $MsiPath | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "wix installer build failed for $Arch." }
    Sign-Files @($MsiPath)

    Write-Host "WiX ($Arch): $MsiName"
}

# ---------------------------------------------------------------------------
# Phase 8: Stage shared (help, certgenerator) - same files for both arches
# ---------------------------------------------------------------------------
function Stage-Shared {
    $HelpStage = Join-Path $OutDir 'help'
    if (Test-Path $HelpStage) { Remove-Item $HelpStage -Recurse -Force }
    New-Item -ItemType Directory -Path $HelpStage -Force | Out-Null
    $oldHelp = Join-Path $OldDir 'LDSBinaries\doc'
    if (Test-Path $oldHelp) {
        Copy-Item (Join-Path $oldHelp '*') $HelpStage -Recurse -Force
        Write-Host "Help: staged from $oldHelp"
    } else {
        Write-Host "Help: source not found at $oldHelp - feature payload will be empty." -ForegroundColor Yellow
    }

    $CertStage = Join-Path $OutDir 'certgenerator'
    if (Test-Path $CertStage) { Remove-Item $CertStage -Recurse -Force }
    New-Item -ItemType Directory -Path $CertStage -Force | Out-Null
    $oldCert = Join-Path $OldDir 'LDSBinaries\dummys\Opc.Ua.CertificateGenerator.exe'
    if (Test-Path $oldCert) {
        Copy-Item $oldCert $CertStage
        Write-Host "CertGenerator: staged from $oldCert (3rd-party signed binary - re-signing skipped)"
    } else {
        Write-Host "CertGenerator: source not found at $oldCert - feature payload will be empty." -ForegroundColor Yellow
    }
}

# ===========================================================================
# Main
# ===========================================================================
try {
    New-Item -ItemType Directory -Path $BuildRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $OutDir    -Force | Out-Null

    $platforms = if ($Platform -eq 'both') { @('x86','x64') } else { @($Platform) }

    foreach ($arch in $platforms) {
        Write-Host ''
        Write-Host '============================================================'
        Write-Host "  $arch"
        Write-Host '============================================================'

        Build-OpenSSL $arch
        $uaLdsBin = Build-UALDS $arch
        $mdnsBin  = Build-MDNSResponder $arch
        $caBin    = Build-CustomActions $arch
        $staged   = Stage-Arch $arch $uaLdsBin $mdnsBin $caBin

        if (-not $SkipWix) {
            Stage-Shared       # idempotent, OK to call inside loop
            Build-Wix $arch $staged
        }
    }

    # -----------------------------------------------------------------------
    # Redistributable ZIP
    # -----------------------------------------------------------------------
    if (-not $SkipWix) {
        $DistDir = Join-Path $ScriptDir 'dist'
        New-Item -ItemType Directory -Path $DistDir -Force | Out-Null
        $WixOut = Join-Path $OutDir 'wix'
        $msi = @(Get-ChildItem $WixOut -Filter '*.msi' -ErrorAction SilentlyContinue)
        if ($msi.Count -gt 0) {
            $ZipName = "OPC-UA-Local-Discovery-Server-$ShortVersion.zip"
            $ZipPath = Join-Path $DistDir $ZipName
            if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }
            $items = @($msi.FullName)
            $items += @(Get-ChildItem $WixOut -Filter '*.msm' | Select-Object -ExpandProperty FullName)
            $changelog = Join-Path $UaLdsDir 'Changelog.txt'
            if (Test-Path $changelog) { $items += $changelog }
            Compress-Archive -Path $items -DestinationPath $ZipPath -CompressionLevel Optimal
            Write-Host ''
            Write-Host "Redistributable: $ZipPath"
        }
    }

    Write-Host ''
    Write-Host '============================================================'
    Write-Host '  BUILD COMPLETE'
    Write-Host '============================================================'
    Write-Host "  Version: $Version"
    Write-Host "  Output:  $OutDir"
}
catch {
    Write-Host ''
    Write-Host "BUILD FAILED: $_" -ForegroundColor Red
    exit 1
}
