# V2Ray & BBR 网络优化工具箱

[English](#english) | [中文](#chinese)

<a name="chinese"></a>
## 中文说明

一个集成了 **V2Ray 一键安装(修复版)** 与 **BBR 网络加速优化** 的 Linux 网络工具箱。

---

## 📦 一键安装

### 1. V2Ray 一键安装（含 TLS + WS 伪装，修复 18 个问题）

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/shakebbq-dot/v2rayfix/main/install.sh)"
```

> 基于 wulabing/V2Ray_ws-tls_bash_onekey 修复版：自动输入验证、网络下载重试、
> jemalloc 内存自适应编译、netcat 兼容、IPv6-only 支持等。

### 2. VLESS + Reality 一键安装（抗封锁最强，免域名免证书）

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/shakebbq-dot/v2rayfix/main/reality_install.sh)"
```

> 基于 XTLS/Xray-core 官方脚本：VLESS + TCP + XTLS-Vision + REALITY 协议，
> 无需域名和证书，伪装真实网站(默认 www.microsoft.com)，主动探测无特征，
> 是当前抗封锁抗识别能力最强的方案。自动生成 UUID/密钥/shortId，输出客户端分享链接。

**常用参数：**

```bash
# 指定端口（443 被占时用，如 NAT/家宽）
bash -c "$(curl -fsSL .../reality_install.sh)" --port=8443

# 指定伪装站点（需支持 TLS1.3+h2）与 SNI
bash -c "$(curl -fsSL .../reality_install.sh)" --dest=www.apple.com --sni=www.apple.com

# 查看状态 / 卸载
sudo ./reality_install.sh --status
sudo ./reality_install.sh --remove
```

### 3. BBR 加速与优化（多发行版，内核 3.10+）

```bash
curl -fsSL https://raw.githubusercontent.com/shakebbq-dot/v2rayfix/main/bbr/bbr_install.sh -o bbr_install.sh \
  && chmod +x bbr_install.sh && sudo ./bbr_install.sh
```

**常用命令（静默模式）：**

```bash
# 智能启用（自动选择最佳算法 bbr → cubic → reno）
sudo ./bbr_install.sh enable --cc=auto --qdisc=auto

# 指定启用 BBR + fq 队列
sudo ./bbr_install.sh enable --cc=bbr --qdisc=fq

# 应用系统优化（含 RTT 自适应 buffer）
sudo ./bbr_install.sh optimize

# 安装 XanMod 高性能内核（Ubuntu/Debian，自动按 CPU 微架构选包）
sudo ./bbr_install.sh --install-xanmod

# 查看当前状态
sudo ./bbr_install.sh monitor

# 还原/卸载优化
sudo ./bbr_install.sh restore   # 或 ./uninstall.sh
```

---

## 📂 项目结构

```
v2rayfix/
├── install.sh                # V2Ray 一键安装（WS+TLS，修复版）
├── reality_install.sh        # VLESS+Vision+Reality 一键安装（抗封锁最强）
├── bbr/
│   ├── bbr_install.sh        # BBR 优化主脚本 v2.0.0（推荐使用）
│   ├── uninstall.sh          # BBR 卸载脚本
│   ├── tcp.sh                # 旧版 BBR 脚本（BBR/魔改/BBRplus/Lotserver）
│   ├── tcp_optimized.sh      # 旧版 TCP 优化脚本 v3.0.0
│   ├── tcp_optimized_fixed.sh# 旧版 TCP 优化（修复版）
│   └── ...                   # 其他参考脚本
├── README.md                 # 本文件
├── CHANGELOG.md              # 更新日志
├── 问题分析报告.md           # V2Ray 脚本问题分析
├── 修复说明.md               # V2Ray 修复详情
├── 快速修复指南.md           # 快速修复指引
└── jemalloc编译问题修复指南.md
```

---

## 🔧 V2Ray 修复版主要改进

### 严重 Bug（必须修复）
1. ✅ 修复域名解析 IP 显示变量错误
2. ✅ 修复 base64 编码跨平台兼容性问题
3. ✅ 修复证书更新脚本路径错误

### 安全问题（高优先级）
4. ✅ 改进防火墙处理（不直接关闭）
5. ✅ 改进 SELinux 处理（询问用户，默认 permissive）

### 功能改进（中优先级）
6. ✅ 添加输入验证（域名、端口、UUID）
7. ✅ 添加网络下载重试机制
8. ✅ 改进域名检查的错误处理
9. ✅ 改进端口占用处理
10. ✅ 确保日志目录存在
11. ✅ 修复 netcat 包名兼容性问题

### 编译问题
12. ✅ 智能计算编译线程数（避免内存不足）
13. ✅ 改进 jemalloc 编译流程（添加降级机制）
14. ✅ 动态调整 Nginx 配置（支持 jemalloc 可选）

---

## 🚀 BBR 优化版功能

- **多发行版支持**：Ubuntu/Debian/CentOS/RHEL/Fedora/Arch/openSUSE（特性按内核能力降级）
- **智能算法选择**：自动选 BBR → CUBIC → Reno
- **系统优化**：写入 `/etc/sysctl.d/99-bbr-optimizer.conf`（幂等、可回滚）
- **资源限制**：写入 `/etc/security/limits.d/99-bbr-optimizer.conf`
- **RTT 自适应**：可选 ping 探测，按延迟自动调整 rmem/wmem
- **XanMod 内核**：自动检测 CPU 微架构（AVX512/AVX2/POPCNT）选 x64v1-v4 包
- **完整回滚**：`restore`/`uninstall` 一键还原

---

## ⚠️ 重要提示

1. 仅用于 Linux 系统（Debian/Ubuntu/CentOS 等）
2. 需要 root 权限运行
3. 建议先在测试环境验证，运行前备份重要数据

## 🔗 相关链接

- 原始 V2Ray 脚本：https://github.com/wulabing/V2Ray_ws-tls_bash_onekey
- V2Ray 官方文档：https://www.v2ray.com

---

<a name="english"></a>
## English

A Linux network toolbox with three one-click scripts: a **fixed V2Ray WS+TLS installer** (18 issues fixed), a **VLESS+Vision+REALITY installer** (no domain/cert needed, best against censorship), and a **cross-distro BBR optimizer**.

### One-click installs

```bash
# V2Ray (WS+TLS, fixed)
bash -c "$(curl -fsSL https://raw.githubusercontent.com/shakebbq-dot/v2rayfix/main/install.sh)"

# VLESS + XTLS-Vision + REALITY (recommended, no domain needed)
bash -c "$(curl -fsSL https://raw.githubusercontent.com/shakebbq-dot/v2rayfix/main/reality_install.sh)"

# BBR optimization
curl -fsSL https://raw.githubusercontent.com/shakebbq-dot/v2rayfix/main/bbr/bbr_install.sh -o bbr_install.sh \
  && chmod +x bbr_install.sh && sudo ./bbr_install.sh
```
