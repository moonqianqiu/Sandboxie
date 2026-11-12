#!/usr/bin/env bash
# Self-check for this fork's local (license-free bypass) patch set.
# Bash rewrite of tools/check_local_patches.ps1 -- no PowerShell 7 dependency.
# Run from the repository root:  bash tools/check_local_patches.sh [repo-root]
# Exits non-zero if any bypass invariant is missing; wired into CI (shell: bash).
set -uo pipefail

RepoRoot=''
if [ $# -gt 0 ]; then RepoRoot=$1; fi
if [ -z "$RepoRoot" ]; then
    RepoRoot=$(cd "$(dirname "$0")/.." && pwd)
fi

checks=0
failures=0

test_pattern() {
    local file=$1 pattern=$2 name=$3
    local path="$RepoRoot/$file"
    checks=$((checks + 1))
    if [ ! -f "$path" ]; then
        printf 'FAIL [%s] file not found: %s\n' "$name" "$file"
        failures=$((failures + 1))
        return
    fi
    if grep -Pzq -- "$pattern" "$path"; then
        printf 'OK   [%s]\n' "$name"
    else
        printf 'FAIL [%s] pattern not found in %s\n' "$name" "$file"
        failures=$((failures + 1))
    fi
}

test_no_pattern() {
    local file=$1 pattern=$2 name=$3
    local path="$RepoRoot/$file"
    checks=$((checks + 1))
    if [ ! -f "$path" ]; then
        printf 'FAIL [%s] file not found: %s\n' "$name" "$file"
        failures=$((failures + 1))
        return
    fi
    if grep -Pzq -- "$pattern" "$path"; then
        printf 'FAIL [%s] forbidden pattern present in %s\n' "$name" "$file"
        failures=$((failures + 1))
    else
        printf 'OK   [%s]\n' "$name"
    fi
}

Verify='Sandboxie/core/drv/verify.c'
Util='Sandboxie/core/drv/util.c'
Updater='SandboxiePlus/SandMan/OnlineUpdater.cpp'
SandMan='SandboxiePlus/SandMan/SandMan.cpp'
Iss='Installer/Sandboxie-Plus.iss'
Nsi='Sandboxie/install/SandboxieVS.nsi'
Copy='Installer/copy_build.cmd'
ClassicUpdater='Sandboxie/apps/control/Updater.cpp'
ClassicFrame='Sandboxie/apps/control/MyFrame.cpp'
ClassicAbout='Sandboxie/apps/control/AboutDialog.cpp'

# 1-5: the four signature primitives keep their real BCrypt implementation.
test_pattern "$Verify" 'BCryptVerifySignature\(keyHandle' 'verify.c KphVerifySignature performs real signature check'
test_pattern "$Verify" 'BCryptCloseAlgorithmProvider\(signAlgHandle, 0\);\r?\n\r?\n\s+return status;' 'verify.c KphVerifySignature returns status'
test_pattern "$Verify" 'return status;\r?\n\}\r?\n\r?\nNTSTATUS KphVerifyFile\(' 'verify.c KphVerifyFile returns status'
test_pattern "$Verify" 'MyFreeHash\(&hashObj\);\r?\n\r?\n\s+return status;' 'verify.c KphVerifyBuffer returns status'
test_pattern "$Verify" 'return status;\r?\n\}\r?\n\r?\nNTSTATUS KphVerifyCurrentProcess\(\)' 'verify.c KphReadSignature returns status'
# 6: root mechanism must not read any certificate file at all.
test_no_pattern "$Verify" 'Certificate\.dat' 'verify.c does not read Certificate.dat'
# 7-8: keep the real code-integrity and caller-signature probes.
test_no_pattern "$Util" '_FX BOOLEAN MyIsTestSigning\(void\)\r?\n\{\r?\n#ifdef LICENSE_FREE\r?\n\s+return TRUE;' 'util.c no unconditional test-signing bypass'
test_no_pattern "$Util" '_FX BOOLEAN MyIsCallerSigned\(void\)\r?\n\{[^}]*#ifdef LICENSE_FREE[^}]*return TRUE;' 'util.c no unconditional caller-signature bypass'
# 9-10: service-port authorization must remain enforced.
test_pattern 'Sandboxie/core/drv/driver.c' 'BOOLEAN Driver_OsTestSigning = FALSE;' 'driver.c test-signing default false'
test_pattern 'Sandboxie/core/drv/api.c' 'if \(NT_SUCCESS\(status\) && !MyIsCallerSigned\(\)\)\s*status = STATUS_INVALID_SIGNATURE;' 'api.c Api_SetServicePort enforces signature'
# 11-13: no remaining consumer may consult the driver cert to gate features.
test_no_pattern 'Sandboxie/core/svc/UserServer.cpp' 'CertInfo\.opt_enc' 'UserServer.cpp EFS opt_enc gate removed'
test_no_pattern 'Sandboxie/core/dll/dns_filter.c' 'CertInfo\.opt_net' 'dns_filter.c opt_net gate removed'
test_no_pattern 'Sandboxie/core/dll/net.c' 'CertInfo' 'net.c cert gate removed'
# 14-17: the #ifdef guards are dead code unless the build system declares them.
test_pattern 'Sandboxie/core/drv/SboxDrv.vcxproj' '<PreprocessorDefinitions>[^<]*LICENSE_FREE[^<]*</PreprocessorDefinitions>' 'SboxDrv.vcxproj LICENSE_FREE defined'
test_pattern 'SandboxiePlus/SandMan/SandMan.vcxproj' '<PreprocessorDefinitions>[^<]*LICENSE_FREE[^<]*NO_INSTALLER_UPDATE[^<]*</PreprocessorDefinitions>' 'SandMan.vcxproj LICENSE_FREE + NO_INSTALLER_UPDATE defined'
test_pattern 'SandboxiePlus/SandMan/SandMan.qc.pro' 'DEFINES\s*\+=.*LICENSE_FREE.*NO_INSTALLER_UPDATE' 'SandMan.qc.pro LICENSE_FREE + NO_INSTALLER_UPDATE defined'
test_pattern 'SandboxiePlus/SandMan/SandMan-Qt6.qc.pro' 'DEFINES\s*\+=.*LICENSE_FREE.*NO_INSTALLER_UPDATE' 'SandMan-Qt6.qc.pro LICENSE_FREE + NO_INSTALLER_UPDATE defined'
# 18-22: NO_INSTALLER_UPDATE must guard every network/update entry point.
test_pattern "$Updater" 'SB_PROGRESS COnlineUpdater::GetUpdates\([^}]*#ifdef NO_INSTALLER_UPDATE' 'OnlineUpdater GetUpdates disabled'
test_pattern "$Updater" 'SB_PROGRESS COnlineUpdater::GetSupportCert\([^}]*#ifdef NO_INSTALLER_UPDATE' 'OnlineUpdater GetSupportCert disabled'
test_pattern "$Updater" 'bool COnlineUpdater::DownloadUpdate\([^}]*#ifdef NO_INSTALLER_UPDATE' 'OnlineUpdater DownloadUpdate disabled'
test_pattern "$Updater" 'bool COnlineUpdater::RunInstaller\([^}]*#ifdef NO_INSTALLER_UPDATE' 'OnlineUpdater RunInstaller disabled'
test_pattern "$Updater" 'void COnlineUpdater::Process\(\)\s*\{\s*#ifdef NO_INSTALLER_UPDATE' 'OnlineUpdater Process scheduling disabled'
# 23: GUI must not overwrite the certificate state returned by the driver.
test_no_pattern "$SandMan" 'g_CertInfo\.active\s*=\s*true;\s*g_CertInfo\.expired\s*=\s*false;' 'SandMan no certificate state forgery'
# 24-29: remaining OnlineUpdater entry points must stay guarded.
test_pattern "$Updater" 'void COnlineUpdater::CheckForUpdates\([^}]*#ifdef NO_INSTALLER_UPDATE' 'OnlineUpdater CheckForUpdates disabled'
test_pattern "$Updater" 'bool COnlineUpdater::ApplyUpdate\([^}]*#ifdef NO_INSTALLER_UPDATE' 'OnlineUpdater ApplyUpdate disabled'
test_pattern "$Updater" 'bool COnlineUpdater::DownloadInstaller\([^}]*#ifdef NO_INSTALLER_UPDATE' 'OnlineUpdater DownloadInstaller disabled'
test_pattern "$Updater" 'void COnlineUpdater::UpdateTemplates\(\)\s*\{\s*#ifdef NO_INSTALLER_UPDATE' 'OnlineUpdater UpdateTemplates disabled'
test_pattern "$Updater" 'bool COnlineUpdater::IsLockRequired\([^}]*#ifdef NO_INSTALLER_UPDATE' 'OnlineUpdater IsLockRequired disabled'
test_pattern "$Updater" 'SB_RESULT\(int\) COnlineUpdater::RunUpdater\([^}]*#ifdef NO_INSTALLER_UPDATE' 'OnlineUpdater RunUpdater disabled'
# 30-31: driver keeps its hardcoded eternal certificate.
test_pattern "$Verify" 'Verify_CertInfo\.type\s*=\s*eCertEternal' 'verify.c KphValidateCertificate hardcodes eternal cert'
test_pattern "$Verify" 'NTSTATUS KphVerifyCurrentProcess\(\)\s*\{\s*return STATUS_SUCCESS;' 'verify.c KphVerifyCurrentProcess stubbed'
# 32-34: SandMan / SettingsWindow must not reach the updater or refresh certs.
test_pattern "$SandMan" 'void CSandMan::CheckForUpdates\(bool bManual\)\s*\{?\s*\r?\n\{?\s*#ifdef NO_INSTALLER_UPDATE' 'SandMan CheckForUpdates disabled'
test_pattern "$SandMan" 'if \(scheme == "sbie"\) \{\s*#ifdef NO_INSTALLER_UPDATE' 'SandMan sbie:// scheme disabled'
test_pattern 'SandboxiePlus/SandMan/Windows/SettingsWindow.cpp' 'bool CSettingsWindow::CertRefreshRequired\(\)\s*\{\s*#ifdef NO_INSTALLER_UPDATE' 'SettingsWindow CertRefreshRequired disabled'
# 35: no dead references to the removed COnlineUpdater::UpdateCert.
test_no_pattern 'SandboxiePlus/SandMan/Windows/SupportDialog.cpp' 'm_pUpdater->UpdateCert' 'SupportDialog no UpdateCert references'
# 36-41: Classic UI must not contact the update/certificate servers.
test_pattern "$ClassicUpdater" 'bool CUpdater::CheckUpdates\([^{]*\{[^}]*online update checks disabled[^}]*return false;' 'Classic Updater CheckUpdates disabled'
test_pattern "$ClassicUpdater" '//CreateThread\(NULL, 0, UpdaterServiceThread' 'Classic Updater thread spawn commented'
test_no_pattern "$ClassicFrame" '(?m)^\s*CUpdater::GetInstance\(\)\.CheckUpdates\(this, false\);' 'Classic MyFrame no active auto update check'
test_pattern "$ClassicFrame" '//\s*CUpdater::GetInstance\(\)\.CheckUpdates\(this, false\);' 'Classic MyFrame update block commented'
test_pattern "$ClassicAbout" 'static BOOL GetCertificateFromServer\([^{]*\{[^}]*certificate retrieval disabled[^}]*return FALSE;' 'Classic AboutDialog cert download disabled'
test_no_pattern "$ClassicAbout" '(?m)^\s*DownloadCertificateData\(L"sandboxie-plus\.com"' 'Classic AboutDialog no active cert HTTP call'
# 42-46: UpdUtil must not run or ship at install time.
test_pattern "$Iss" ';\s*Filename: "\{app\}\\UpdUtil\.exe"' 'Plus installer UpdUtil run commented'
test_pattern "$Iss" ';\s*Name: "RefreshBuild"' 'Plus installer RefreshBuild task commented'
test_pattern "$Nsi" ';\s*Call CheckUpdates' 'Classic installer update check commented'
test_pattern "$Nsi" ';\s*File /oname=UpdUtil\.exe' 'Classic installer UpdUtil packaging commented'
test_pattern "$Copy" 'rem\s+copy /y.*UpdUtil\.exe' 'copy_build no longer stages UpdUtil'

# 47: once the upstream merge lands, the MCP module must not consult the
# driver certificate state at all (enforced by check 47 below).
Mcp='SandboxiePlus/SandMan/Mcp/McpTools.cpp'
if [ ! -f "$RepoRoot/$Mcp" ]; then
    printf 'SKIP [MCP certificate gate removed] (upstream MCP files not merged yet)\n'
else
    test_no_pattern "$Mcp" 'g_CertInfo' 'MCP certificate gate removed'
fi

printf '\n'
if [ "$failures" -gt 0 ]; then
    printf 'BYPASS SELF-CHECK FAILED: %s of %s checks failed.\n' "$failures" "$checks"
    exit 1
fi
printf 'BYPASS SELF-CHECK PASSED: all %s checks passed.\n' "$checks"
