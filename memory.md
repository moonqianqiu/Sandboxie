# Fork 说明：moonqianqiu/Sandboxie

> 仓库内文档，随版本控制同步；给后续维护者和 AI 助手看。
> 本 fork 的改动都是企业内部需求，**不是 bug，不要还原**。
> 权威清单以 tools/check_local_patches.sh（47 项静态自检）为准；本文只讲「为什么」和「改了哪几块」。

## 1. 这个 fork 是什么

- 上游：sandboxie-plus/Sandboxie（remote upstream）；本仓库 origin = moonqianqiu/Sandboxie，master 跟踪 origin/master。
- 目的：企业内部使用需要**去掉支持者证书认证**和**联网自动更新**，让内部构建无需证书即可全功能运行，安装与运行期不联网。
- 边界：只绕过「证书 / 更新」这一层。沙箱隔离、令牌限制、访问控制保持上游语义；verify.c 的四个签名原语仍是真实 BCrypt 校验，api.c 仍强制 MyIsCallerSigned()，util.c / driver.c 保留真实 test-signing 检查。
- 合并基线：已合并 upstream/master @ 92f0e17c（1.19.1，2026-11-11），merge commit c38194fc；之后本地改造 04d9797c。哈希会过时，以 git log 为准。

## 2. 改了哪几块（按组件，不逐行）

- 驱动 / 内核：Sandboxie/core/drv/verify.c 硬编码 Verify_CertInfo.type = eCertEternal、KphVerifyCurrentProcess() 返回 STATUS_SUCCESS、不再读 Certificate.dat；SboxDrv.vcxproj 定义 LICENSE_FREE。
- 服务端门控：UserServer.cpp（opt_enc）、dns_filter.c（opt_net）、net.c 不再用 CertInfo 门控功能。
- Plus UI：SandMan.vcxproj / SandMan.qc.pro / SandMan-Qt6.qc.pro 定义 LICENSE_FREE + NO_INSTALLER_UPDATE；OnlineUpdater.cpp 各入口由 #ifdef NO_INSTALLER_UPDATE 守卫；SandMan.cpp 的 CheckForUpdates() 与 sbie://、SettingsWindow.cpp 的 CertRefreshRequired()、SupportDialog.cpp 的 UpdateCert 均禁用。不伪造 g_CertInfo.active。
- Classic UI：Updater.cpp / MyFrame.cpp / AboutDialog.cpp 禁用在线更新与证书下载。
- 打包 / CI：Sandboxie-Plus.iss、SandboxieVS.nsi、copy_build.cmd 注释掉 UpdUtil；main.yml 注释 push/pull_request 触发与 Build_ARM64_Qt6 job，新增 Verify local bypass patches 步骤。
- MCP（1.19.1 新增）：Mcp/McpTools.cpp 的 CallVersion() 不再输出 Data["certificate"] 和 if (!g_CertInfo.active) 证书描述，文件内 g_CertInfo 引用为 0；保留 SettingsWindow.h 的 include（本机不能构建验证，避免引入间接头文件依赖风险）。

## 3. 自检（最重要）

- tools/check_local_patches.sh：47 项静态检查，覆盖上面所有不变量；CI 的 Verify local bypass patches 步骤用 shell: bash 调用它。
- **合并上游、或改动上述任何文件之后都要跑** bash tools/check_local_patches.sh，退出码 0 才算通过。
- 原 check_local_patches.ps1 已删除（本机没有 pwsh 7）。
- 本机没有编译环境：**只做静态检查，不本地构建**；CI 的 push 触发已注释，靠 workflow_dispatch。

## 4. 合并上游的流程与坑

1. git fetch upstream，确认 merge-base；git merge --no-ff upstream/master。
2. 冲突几乎总在 .gitignore 末尾：本地加 .zcode/.vscode，上游加 docs pack 3 行 —— 两段全保留，统一 LF。
3. 自动合并但必须人工复核的 4 个文件：main.yml、SandMan.cpp、SandMan.vcxproj、Windows/SettingsWindow.cpp —— 确认宏定义、#ifdef 守卫、自检步骤没被上游覆盖，且上游新增代码没有重新调用 CheckForUpdates / UpdateCert / SetCertificate / InitCertSlot。
4. 跑自检 + git diff --check；提交信息用英文；一个 PR 一个逻辑变更。
5. push 需要凭据：本机 credential.helper 未配置，用 git -c credential.helper=wincred push origin master（凭据在 Windows 凭据管理器）。

## 5. 红线

- 不要把上述证书 / 更新相关改动「修回去」，不要删自检脚本或 CI 自检步骤。
- 不放松默认隔离、访问检查、令牌限制；不要把证书绕过扩大成签名绕过。
- 合并时不要接受上游重新引入的证书 / 更新调用。

## 6. 已知风险（每次升级重新审视）

- 1.19.1 引入的 MCP / HttpServer 会在 SandMan 内开本地 HTTP 监听；Sandboxie/core/drv/ipc.c 有内核改动 —— 已接受，但升级时要重看。
- Installer/build_docs_pack.cmd --force 会联网拉文档。
- lupdate 会让 24 个 .ts 翻译文件产生巨大 diff，按上游版本接受即可，不必逐行审。
- 本文件已纳入版本控制；合并上游时保留本地版本（上游没有同名文件），并顺手更新第 1 节的合并基线。
