#!/usr/bin/env bash
#============================================================================
#  v2rayfix 工具箱统一管理菜单
#  整合: VLESS+Reality 代理 | BBR 网络加速
#  用法: ./install_menu.sh           进入主菜单
#============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;36m'
PLAIN='\033[0m'

if [[ ! -t 1 ]]; then
    RED=''; GREEN=''; YELLOW=''; BLUE=''; PLAIN=''
fi

info()  { echo -e "${GREEN}[信息]${PLAIN} $*"; }
warn()  { echo -e "${YELLOW}[警告]${PLAIN} $*"; }
err()   { echo -e "${RED}[错误]${PLAIN} $*"; }

VERSION="1.1.0"
GITHUB_RAW="https://raw.githubusercontent.com/shakebbq-dot/v2rayfix/main"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REALITY_SCRIPT="$SCRIPT_DIR/reality_install.sh"
BBR_SCRIPT="$SCRIPT_DIR/bbr/bbr_install.sh"
BBR_SCRIPT_FLAT="$SCRIPT_DIR/bbr_install.sh"

require_root() {
    [[ ${EUID:-$(id -u)} -eq 0 ]] || die "本脚本必须以 root 身份运行"
}

# 下载仓库脚本到临时位置(支持在任意目录一键使用)
# 注意: 总是强制重新下载, 避免 /tmp 缓存旧版脚本导致功能缺失
fetch_script() {
    local name="$1"  # reality_install.sh | bbr/bbr_install.sh
    local dest="$2"
    rm -f "$dest"
    info "下载 $name ..."
    curl -fsSL "$GITHUB_RAW/$name" -o "$dest" 2>/dev/null || { rm -f "$dest"; return 1; }
    chmod +x "$dest"
    echo "$dest"
}

get_reality_script() {
    local dest
    if [[ -f "$REALITY_SCRIPT" ]]; then
        dest="$REALITY_SCRIPT"
    else
        dest="/tmp/v2rayfix_reality_install.sh"
        fetch_script "reality_install.sh" "$dest" >/dev/null || die "Reality 脚本下载失败"
    fi
    echo "$dest"
}

get_bbr_script() {
    local dest
    if [[ -f "$BBR_SCRIPT" ]]; then
        dest="$BBR_SCRIPT"
    elif [[ -f "$BBR_SCRIPT_FLAT" ]]; then
        dest="$BBR_SCRIPT_FLAT"
    else
        dest="/tmp/v2rayfix_bbr_install.sh"
        fetch_script "bbr/bbr_install.sh" "$dest" >/dev/null || die "BBR 脚本下载失败"
    fi
    echo "$dest"
}

xray_status_line() {
    if [[ ! -x /usr/local/bin/xray ]]; then
        echo -e "  VLESS+Reality: ${YELLOW}未安装${PLAIN}"
    elif systemctl is-active --quiet xray 2>/dev/null; then
        echo -e "  VLESS+Reality: ${GREEN}运行中${PLAIN}"
    else
        echo -e "  VLESS+Reality: ${RED}未运行${PLAIN}"
    fi
}

bbr_status_line() {
    local cc=""
    cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)"
    if [[ -n "$cc" ]]; then
        echo -e "  BBR 加速:     ${GREEN}已启用 ($cc)${PLAIN}"
    else
        echo -e "  BBR 加速:     ${YELLOW}未检测/未知${PLAIN}"
    fi
}

main_menu() {
    while true; do
        clear
        echo -e "${BLUE}================================================${PLAIN}"
        echo -e "${BLUE}   v2rayfix 工具箱 v${VERSION}   ${PLAIN}"
        echo -e "${BLUE}================================================${PLAIN}"
        xray_status_line
        bbr_status_line
        echo -e "${BLUE}------------------------------------------------${PLAIN}"
        echo "  1. VLESS+Reality 代理 (安装/管理)"
        echo "  2. BBR 网络加速 (启用/优化/内核)"
        echo "  3. 系统常用操作 (更新/升级/清理)"
        echo "  0. 退出"
        echo -e "${BLUE}================================================${PLAIN}"
        read -rp "请输入选项 [0-3]: " choice
        case "$choice" in
            1) reality_submenu ;;
            2) bbr_submenu ;;
            3) sys_submenu ;;
            0) break ;;
            *) warn "无效选项" ;;
        esac
        echo
        read -rp "按回车键返回主菜单..." _
    done
}

reality_submenu() {
    local r
    r="$(get_reality_script)"
    while true; do
        clear
        echo -e "${BLUE}================================================${PLAIN}"
        echo -e "${BLUE}   VLESS+Reality 代理 ${PLAIN}"
        echo -e "${BLUE}================================================${PLAIN}"
        xray_status_line
        echo -e "${BLUE}------------------------------------------------${PLAIN}"
        echo "  1. 安装 VLESS+Reality 代理"
        echo "  2. 管理菜单 (改端口/SNI/UUID/密钥/卸载)"
        echo "  0. 返回主菜单"
        echo -e "${BLUE}================================================${PLAIN}"
        read -rp "请输入选项 [0-2]: " c
        case "$c" in
            1) bash "$r" --install ;;
            2) bash "$r" --menu ;;
            0) return ;;
            *) warn "无效选项" ;;
        esac
        echo
        read -rp "按回车键返回..." _
    done
}

bbr_submenu() {
    local bb
    bb="$(get_bbr_script)"
    info "进入 BBR 菜单: $bb"
    bash "$bb"
}

# ---- 系统常用操作 ----
detect_pkg_mgr() {
    if command -v apt-get >/dev/null 2>&1; then
        echo "apt"
    elif command -v dnf >/dev/null 2>&1; then
        echo "dnf"
    elif command -v yum >/dev/null 2>&1; then
        echo "yum"
    elif command -v apk >/dev/null 2>&1; then
        echo "apk"
    else
        echo ""
    fi
}

sys_update() {
    local pm
    pm="$(detect_pkg_mgr)"
    if [[ -z "$pm" ]]; then
        die "无法识别的包管理器,请手动执行系统更新"
    fi
    warn "将更新系统软件包(可能耗时较长)..."
    case "$pm" in
        apt)
            apt-get update -y
            apt-get upgrade -y
            ;;
        dnf)
            dnf upgrade -y
            ;;
        yum)
            yum update -y
            ;;
        apk)
            apk update && apk upgrade
            ;;
    esac
    info "系统软件更新完成"
}

sys_autoremove() {
    local pm
    pm="$(detect_pkg_mgr)"
    warn "清理无用的依赖包与缓存..."
    case "$pm" in
        apt)
            apt-get autoremove -y 2>/dev/null || true
            apt-get autoclean -y 2>/dev/null || true
            ;;
        dnf|yum)
            "$pm" autoremove -y 2>/dev/null || true
            "$pm" clean all 2>/dev/null || true
            ;;
        apk)
            apk cache clean 2>/dev/null || true
            ;;
    esac
    info "清理完成"
}

sys_resources() {
    echo -e "${BLUE}================ 系统资源 ================${PLAIN}"
    echo "  系统: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"
    echo "  内核: $(uname -r)"
    echo "  运行: $(uptime -p 2>/dev/null || uptime)"
    echo "  CPU:  $(nproc) 核, 负载 $(cat /proc/loadavg | cut -d' ' -f1-3)"
    if command -v free >/dev/null 2>&1; then
        free -h | awk 'NR==1 || /Mem:/ {print "  内存: " $0}'
    fi
    if command -v df >/dev/null 2>&1; then
        df -h / | awk 'NR==1 || NR==2 {print "  磁盘: " $0}'
    fi
    echo -e "${BLUE}===========================================${PLAIN}"
}

update_reality() {
    require_root
    if [[ ! -x /usr/local/bin/xray ]]; then
        warn "Xray 未安装,先安装: 主菜单 → 1 → 1"
        return
    fi
    local cur
    cur="$(/usr/local/bin/xray version 2>/dev/null | head -n1)"
    info "当前: $cur"
    info "正在通过官方脚本更新 Xray(保留现有配置)..."
    if bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install; then
        systemctl restart xray 2>/dev/null || true
        info "Xray 更新完成"
        /usr/local/bin/xray version | head -n1
    else
        die "Xray 更新失败"
    fi
}

update_bbr_script() {
    # 强制重新下载 BBR 脚本(覆盖缓存)
    local dest
    if [[ -f "$BBR_SCRIPT" ]]; then
        info "BBR 脚本已随工具箱更新(本地路径: $BBR_SCRIPT)"
        return
    fi
    dest="/tmp/v2rayfix_bbr_install.sh"
    rm -f "$dest"
    if fetch_script "bbr/bbr_install.sh" "$dest" >/dev/null; then
        info "BBR 脚本已更新: $dest"
        info "通过 主菜单 → 2 进入新版 BBR 菜单"
    else
        die "BBR 脚本更新失败"
    fi
}

update_toolbox() {
    warn "重新下载工具箱主菜单到 /tmp/v2rayfix_menu.sh 并进入..."
    local dest="/tmp/v2rayfix_menu.sh"
    rm -f "$dest"
    if fetch_script "install_menu.sh" "$dest" >/dev/null; then
        info "工具箱已更新,切换到新版本..."
        exec bash "$dest"
    else
        die "工具箱更新失败"
    fi
}

sys_submenu() {
    while true; do
        clear
        echo -e "${BLUE}================================================${PLAIN}"
        echo -e "${BLUE}   系统常用操作 ${PLAIN}"
        echo -e "${BLUE}================================================${PLAIN}"
        echo "  1. 更新系统软件包 (apt/dnf/yum)"
        echo "  2. 更新 VLESS+Reality (Xray 升级)"
        echo "  3. 更新 BBR 脚本 (重新拉取最新版)"
        echo "  4. 更新工具箱自身"
        echo "  5. 查看系统资源 (内存/磁盘/负载)"
        echo "  6. 清理无用依赖与缓存"
        echo "  0. 返回主菜单"
        echo -e "${BLUE}================================================${PLAIN}"
        read -rp "请输入选项 [0-6]: " c
        case "$c" in
            1) sys_update ;;
            2) update_reality ;;
            3) update_bbr_script ;;
            4) update_toolbox ;;
            5) sys_resources ;;
            6) sys_autoremove ;;
            0) return ;;
            *) warn "无效选项" ;;
        esac
        echo
        read -rp "按回车键返回..." _
    done
}

main() {
    case "${1:-}" in
        -h|--help)
            echo "用法: $0"
            echo "  v2rayfix 工具箱统一菜单:"
            echo "    1 = VLESS+Reality 代理 (安装/管理)"
            echo "    2 = BBR 网络加速 (启用/优化/内核)"
            echo "    3 = 系统常用操作 (更新/升级/清理)"
            exit 0
            ;;
    esac
    main_menu
}

main "$@"
