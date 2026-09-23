#requires -Version 7.0
# <summary>
# Self-check for this fork's local (license-free bypass) patch set.
# Run from the repository root:  pwsh -File tools/check_local_patches.ps1
# Exits non-zero if any bypass invariant is missing, so it can be wired into CI.
# </summary>
param(
    [string]$RepoRoot = ''
)

if (-not $RepoRoot) {
    if ($PSCommandPath) {
        $RepoRoot = (Resolve-Path (Join-Path (Split-Path $PSCommandPath) '..')).Path
    } else {
        $RepoRoot = (Get-Location).Path
    }
}

$script:failures = 0
$script:checks = 0

function Read-RepoFile {
    param([string]$File)
    $path = Join-Path $RepoRoot $File
    if (-not (Test-Path -LiteralPath $path)) {
        Write-Host "FAIL [$File] file not found"
        $script:failures++
        $script:checks++
        return $null
    }
    Get-Content -LiteralPath $path -Raw -ErrorAction Stop
}

function Test-Pattern {
    param([string]$File, [string]$Pattern, [string]$Name)
    $script:checks++
    $text = Read-RepoFile $File
    if ($null -eq $text) { return }
    if ($text -match $Pattern) {
        Write-Host "OK   [$Name]"
    } else {
        Write-Host "FAIL [$Name] pattern not found in $File"
        $script:failures++
    }
}

function Test-NoPattern {
    param([string]$File, [string]$Pattern, [string]$Name)
    $script:checks++
    $text = Read-RepoFile $File
    if ($null -eq $text) { return }
    if ($text -notmatch $Pattern) {
        Write-Host "OK   [$Name]"
    } else {
        Write-Host "FAIL [$Name] forbidden pattern present in $File"
        $script:failures++
    }
}

$Verify = 'Sandboxie/core/drv/verify.c'
$Util   = 'Sandboxie/core/drv/util.c'
$Updater = 'SandboxiePlus/SandMan/OnlineUpdater.cpp'
$SandMan = 'SandboxiePlus/SandMan/SandMan.cpp'

# 1-4 verify.c: the 4 license stubs must return their (upstream) status,
# not the hardcoded STATUS_SUCCESS that masks real failures.
Test-Pattern $Verify 'BCryptCloseAlgorithmProvider\(signAlgHandle, 0\);\r?\n\r?\n\s+return status;' 'verify.c KphVerifySignature returns status'
Test-Pattern $Verify 'return status;\r?\n\}\r?\n\r?\nNTSTATUS KphVerifyBuffer\(' 'verify.c KphVerifyFile returns status'
Test-Pattern $Verify 'MyFreeHash\(&hashObj\);\r?\n\r?\n\s+return status;' 'verify.c KphVerifyBuffer returns status'
Test-Pattern $Verify 'return status;\r?\n\}\r?\n\r?\nNTSTATUS KphVerifyCurrentProcess\(\)' 'verify.c KphReadSignature returns status'

# 5-6 util.c: keep the real code-integrity and caller-signature probes.
Test-NoPattern $Util '_FX BOOLEAN MyIsTestSigning\(void\)\r?\n\{\r?\n#ifdef LICENSE_FREE\r?\n\s+return TRUE;' 'util.c no unconditional test-signing bypass'
Test-NoPattern $Util '_FX BOOLEAN MyIsCallerSigned\(void\)\r?\n\{[^}]*#ifdef LICENSE_FREE[^}]*return TRUE;' 'util.c no unconditional caller-signature bypass'

# 7-8 driver.c / api.c: service-port authorization must remain enforced.
Test-Pattern 'Sandboxie/core/drv/driver.c' 'BOOLEAN Driver_OsTestSigning = FALSE;' 'driver.c test-signing default false'
Test-Pattern 'Sandboxie/core/drv/api.c' 'if \(NT_SUCCESS\(status\) && !MyIsCallerSigned\(\)\)\s*status = STATUS_INVALID_SIGNATURE;' 'api.c Api_SetServicePort enforces signature'

# 9-11: no remaining consumer may consult the driver cert to gate features.
# net.c is checked for any CertInfo reference at all.
Test-NoPattern 'Sandboxie/core/svc/UserServer.cpp' 'CertInfo\.opt_enc' 'UserServer.cpp EFS opt_enc gate removed'
Test-NoPattern 'Sandboxie/core/dll/dns_filter.c' 'CertInfo\.opt_net' 'dns_filter.c opt_net gate removed'
Test-NoPattern 'Sandboxie/core/dll/net.c' 'CertInfo' 'net.c cert gate removed'

# 12-15: the #ifdef guards above are dead code unless the defines are set,
# so verify the build system still declares them.
Test-Pattern 'Sandboxie/core/drv/SboxDrv.vcxproj' '<PreprocessorDefinitions>[^<]*LICENSE_FREE[^<]*</PreprocessorDefinitions>' 'SboxDrv.vcxproj LICENSE_FREE defined'
Test-Pattern 'SandboxiePlus/SandMan/SandMan.vcxproj' '<PreprocessorDefinitions>[^<]*LICENSE_FREE[^<]*NO_INSTALLER_UPDATE[^<]*</PreprocessorDefinitions>' 'SandMan.vcxproj LICENSE_FREE + NO_INSTALLER_UPDATE defined'
Test-Pattern 'SandboxiePlus/SandMan/SandMan.qc.pro' 'DEFINES\s*\+=.*LICENSE_FREE.*NO_INSTALLER_UPDATE' 'SandMan.qc.pro LICENSE_FREE + NO_INSTALLER_UPDATE defined'
Test-Pattern 'SandboxiePlus/SandMan/SandMan-Qt6.qc.pro' 'DEFINES\s*\+=.*LICENSE_FREE.*NO_INSTALLER_UPDATE' 'SandMan-Qt6.qc.pro LICENSE_FREE + NO_INSTALLER_UPDATE defined'

# 15-18: NO_INSTALLER_UPDATE must guard every network/update entry point.
Test-Pattern $Updater 'SB_PROGRESS COnlineUpdater::GetUpdates\([^}]*#ifdef NO_INSTALLER_UPDATE' 'OnlineUpdater GetUpdates disabled'
Test-Pattern $Updater 'SB_PROGRESS COnlineUpdater::GetSupportCert\([^}]*#ifdef NO_INSTALLER_UPDATE' 'OnlineUpdater GetSupportCert disabled'
Test-Pattern $Updater 'bool COnlineUpdater::DownloadUpdate\([^}]*#ifdef NO_INSTALLER_UPDATE' 'OnlineUpdater DownloadUpdate disabled'
Test-Pattern $Updater 'bool COnlineUpdater::RunInstaller\([^}]*#ifdef NO_INSTALLER_UPDATE' 'OnlineUpdater RunInstaller disabled'
Test-Pattern $Updater 'void COnlineUpdater::Process\(\)\s*\{\s*#ifdef NO_INSTALLER_UPDATE' 'OnlineUpdater Process scheduling disabled'

# 19: GUI must not overwrite the certificate state returned by the driver.
Test-NoPattern $SandMan 'g_CertInfo\.active\s*=\s*true;\s*g_CertInfo\.expired\s*=\s*false;' 'SandMan no certificate state forgery'

# 20-22: extension — remaining OnlineUpdater entry points must stay guarded.
Test-Pattern $Updater 'void COnlineUpdater::CheckForUpdates\([^}]*#ifdef NO_INSTALLER_UPDATE' 'OnlineUpdater CheckForUpdates disabled'
Test-Pattern $Updater 'bool COnlineUpdater::ApplyUpdate\([^}]*#ifdef NO_INSTALLER_UPDATE' 'OnlineUpdater ApplyUpdate disabled'
Test-Pattern $Updater 'bool COnlineUpdater::DownloadInstaller\([^}]*#ifdef NO_INSTALLER_UPDATE' 'OnlineUpdater DownloadInstaller disabled'
Test-Pattern $Updater 'void COnlineUpdater::UpdateTemplates\(\)\s*\{\s*#ifdef NO_INSTALLER_UPDATE' 'OnlineUpdater UpdateTemplates disabled'
Test-Pattern $Updater 'bool COnlineUpdater::IsLockRequired\([^}]*#ifdef NO_INSTALLER_UPDATE' 'OnlineUpdater IsLockRequired disabled'
Test-Pattern $Updater 'SB_RESULT\(int\) COnlineUpdater::RunUpdater\([^}]*#ifdef NO_INSTALLER_UPDATE' 'OnlineUpdater RunUpdater disabled'

# 23a: the root mechanism — driver must keep its hardcoded eternal certificate
# (KphValidateCertificate must not fall back to parsing Certificate.dat).
Test-Pattern $Verify 'Verify_CertInfo\.type\s*=\s*eCertEternal' 'verify.c KphValidateCertificate hardcodes eternal cert'
Test-Pattern $Verify 'NTSTATUS KphVerifyCurrentProcess\(\)\s*\{\s*return STATUS_SUCCESS;' 'verify.c KphVerifyCurrentProcess stubbed'

# 26-27: SandMan must not reach the updater from the menu or the sbie:// scheme.
Test-Pattern $SandMan 'void CSandMan::CheckForUpdates\(bool bManual\)\s*\{?\s*\r?\n\{?\s*#ifdef NO_INSTALLER_UPDATE' 'SandMan CheckForUpdates disabled'
Test-Pattern $SandMan 'if \(scheme == "sbie"\) \{\s*#ifdef NO_INSTALLER_UPDATE' 'SandMan sbie:// scheme disabled'

# 28: certificate refresh must be a no-op.
Test-Pattern 'SandboxiePlus/SandMan/Windows/SettingsWindow.cpp' 'bool CSettingsWindow::CertRefreshRequired\(\)\s*\{\s*#ifdef NO_INSTALLER_UPDATE' 'SettingsWindow CertRefreshRequired disabled'

# 29: no dead references to the removed COnlineUpdater::UpdateCert.
Test-NoPattern 'SandboxiePlus/SandMan/Windows/SupportDialog.cpp' 'm_pUpdater->UpdateCert' 'SupportDialog no UpdateCert references'

# 30-32: Classic UI must not contact the update/certificate servers.
$ClassicUpdater = 'Sandboxie/apps/control/Updater.cpp'
$ClassicFrame   = 'Sandboxie/apps/control/MyFrame.cpp'
$ClassicAbout   = 'Sandboxie/apps/control/AboutDialog.cpp'
Test-Pattern $ClassicUpdater 'bool CUpdater::CheckUpdates\([^{]*\{[^}]*online update checks disabled[^}]*return false;' 'Classic Updater CheckUpdates disabled'
Test-Pattern $ClassicUpdater '//CreateThread\(NULL, 0, UpdaterServiceThread' 'Classic Updater thread spawn commented'
Test-NoPattern $ClassicFrame '(?m)^\s*CUpdater::GetInstance\(\)\.CheckUpdates\(this, false\);' 'Classic MyFrame no active auto update check'
Test-Pattern $ClassicFrame '//\s*CUpdater::GetInstance\(\)\.CheckUpdates\(this, false\);' 'Classic MyFrame update block commented'
Test-Pattern $ClassicAbout 'static BOOL GetCertificateFromServer\([^{]*\{[^}]*certificate retrieval disabled[^}]*return FALSE;' 'Classic AboutDialog cert download disabled'
Test-NoPattern $ClassicAbout '(?m)^\s*DownloadCertificateData\(L"sandboxie-plus\.com"' 'Classic AboutDialog no active cert HTTP call'

# 33-36: UpdUtil must not run or ship at install time.
$Iss  = 'Installer/Sandboxie-Plus.iss'
$Nsi  = 'Sandboxie/install/SandboxieVS.nsi'
$Copy = 'Installer/copy_build.cmd'
Test-Pattern $Iss ';\s*Filename: "\{app\}\\UpdUtil\.exe"' 'Plus installer UpdUtil run commented'
Test-Pattern $Iss ';\s*Name: "RefreshBuild"' 'Plus installer RefreshBuild task commented'
Test-Pattern $Nsi ';\s*Call CheckUpdates' 'Classic installer update check commented'
Test-Pattern $Nsi ';\s*File /oname=UpdUtil\.exe' 'Classic installer UpdUtil packaging commented'
Test-Pattern $Copy 'rem\s+copy /y.*UpdUtil\.exe' 'copy_build no longer stages UpdUtil'

Write-Host ""
if ($script:failures -gt 0) {
    Write-Host "BYPASS SELF-CHECK FAILED: $script:failures of $script:checks checks failed."
    exit 1
}
Write-Host "BYPASS SELF-CHECK PASSED: all $script:checks checks passed."
