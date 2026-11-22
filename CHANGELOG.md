# 更新日志

## [2026-11-21] 工具箱新增系统常用操作子菜单

- **install_menu.sh v1.1.0**: 主菜单新增 `3. 系统常用操作`
  - 更新系统软件包(自动识别 apt/dnf/yum/apk)
  - 更新 VLESS+Reality(Xray 官方脚本升级,保留配置)
  - 更新 BBR 脚本 / 更新工具箱自身(重新拉取最新版)
  - 查看系统资源(内存/磁盘/负载)、清理无用依赖与缓存
- 伪装站点修改支持推荐列表(10 个最优站点选择)

## [2026-11-21] reality_install.sh: 默认端口改为 8443

- 默认端口 **443 → 8443**,避开 Nginx 等服务的 443 占用(端口冲突时自动探测 8443-8449/8888/2053/2096)
- README 同步更新端口示例(--port=9443 示例)

## [2026-11-21] 新增 VLESS + Reality 一键安装

- **新增 `reality_install.sh`**：VLESS + TCP + XTLS-Vision + REALITY 一键部署
  - 基于 XTLS/Xray-core 官方安装脚本，自动安装 Xray、生成 UUID/密钥/shortId
  - 免域名、免证书，伪装真实网站（默认 www.microsoft.com，支持 --dest/--sni 自定义）
  - 端口占用检测、配置合法性校验（xray run -test）、自动启动并设开机自启
  - 输出标准客户端分享链接（v2rayN/NekoBox/Sing-box 等直接导入）
  - 支持 --port / --dest / --sni / --uuid / --short-id / --status / --remove
- **README 更新**：新增 Reality 一键命令与参数说明，中英文同步

## [2026-11-21] 项目重构：合并 ubuntu-bbr-optimizer

- **合并 BBR 优化工具**：将原 ubuntu-bbr-optimizer 项目的 `bbr_install.sh`(v2.0.0) 与 `uninstall.sh` 并入本仓库 `bbr/` 目录
- **修复 install.sh 中文编码损坏**：上一 commit 用错误编码转换损坏 200+ 处中文，本次从原始版本恢复完整中文内容
- **重写 README**：统一两个项目的文档，提供 V2Ray + BBR 两条一键安装命令
- **验证**：install.sh 已包含上游 wulabing 脚本全部最新修复（debian12 兼容、域名解析检测、IPv6-only 支持等）

## [2026-04-21] BBR 优化脚本 v2.0.0（原 ubuntu-bbr-optimizer）

### Changed
- **Cross-distro:** 重构为特性门控调优（内核 3.10+）和 sysctl.d/limits.d 基础配置
- **Idempotency & rollback:** 写入受管配置文件，支持干净还原/卸载
- **Security:** 移除不安全的下载指引，XanMod 仓库 URL 切换到 HTTPS
### Added
- **Smart selection:** 自动拥塞控制选择（`bbr → cubic → reno`）
- **Adaptive tuning:** 可选 RTT 探测和 `autotune` 循环
- **Observability:** 基本状态监控和 logrotate 集成

## [1.1.9.0-fixed] - 2025-11-02

### 🔴 最新修复（第二次更新）

#### 修复16-18: jemalloc编译内存不足问题
**问题：** 编译jemalloc时出现内存不足错误，进程被OOM killer杀死
**修复：**
- 智能计算编译线程数（基于可用内存）
- 添加内存检查和自动降级机制
- 支持跳过jemalloc继续安装
- Nginx配置根据jemalloc状态动态调整

### 🔴 最新修复（第一次更新）

#### 修复15: netcat包名兼容性问题
**问题：** 在Debian/Ubuntu某些版本中，`netcat`包不存在，导致安装SSL证书依赖失败
**错误信息：** `E: Package 'netcat' has no installation candidate`
**修复：**
- 统一使用`netcat-openbsd`包（所有Debian/Ubuntu版本都支持）
- 添加备选方案：`netcat-traditional`
- 改进错误处理，确保至少`socat`安装成功

### ✅ 已修复的问题（共18个）

#### 严重Bug（3个）
1. ✅ 修复域名解析IP显示变量错误（第460行）
2. ✅ 修复base64编码跨平台兼容性问题
3. ✅ 修复证书更新脚本路径错误

#### 安全问题（2个）
4. ✅ 改进防火墙处理（不直接关闭）
5. ✅ 改进SELinux处理（询问用户，默认permissive）

#### 功能问题（6个）
6. ✅ 添加输入验证（域名、端口、UUID）
7. ✅ 添加网络下载重试机制
8. ✅ 改进域名检查的错误处理
9. ✅ 改进端口占用处理
10. ✅ 确保日志目录存在
11. ✅ **修复netcat包名兼容性问题**（新增）

#### 代码质量（4个）
12. ✅ 改进base64编码函数
13. ✅ 统一使用改进的下载函数
14. ✅ 改进错误处理
15. ✅ 添加更详细的提示信息

#### 编译问题（3个）
16. ✅ **智能计算编译线程数（避免内存不足）**（新增）
17. ✅ **改进jemalloc编译流程（添加降级机制）**（新增）
18. ✅ **动态调整Nginx配置（支持jemalloc可选）**（新增）

---

## [1.1.9.0] - 原始版本

这是从GitHub下载的原始脚本版本，包含14个已知问题。
