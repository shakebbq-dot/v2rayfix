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

VERSION="1.0.0"
GITHUB_RAW="https://raw.githubusercontent.com/shakebbq-dot/v2rayfix/main"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REALITY_SCRIPT="$SCRIPT_DIR/reality_install.sh"
BBR_SCRIPT="$SCRIPT_DIR/bbr/bbr_install.sh"
BBR_SCRIPT_FLAT="$SCRIPT_DIR/bbr_install.sh"

require_root() {
    [[ ${EUID:-$(id -u)} -eq 0 ]] || die "本脚本必须以 root 身份运行"
}

# 下载仓库脚本到临时位置(支持在任意目录一键使用)
fetch_script() {
    local name="$1"  # reality_install.sh | bbr/bbr_install.sh
    local dest="$2"
    if [[ -f "$dest" ]]; then
        echo "$dest"
        return 0
    fi
    info "下载 $name ..."
    curl -fsSL "$GITHUB_RAW/$name" -o "$dest" 2>/dev/null || return 1
    chmod +x "$dest"
    echo "$dest"
}

get_reality_script() {
    if [[ -f "$REALITY_SCRIPT" ]]; then
        echo "$REALITY_SCRIPT"
    else
        fetch_script "reality_install.sh" "/tmp/v2rayfix_reality_install.sh" || die "Reality 脚本下载失败"
    fi
}

get_bbr_script() {
    if [[ -f "$BBR_SCRIPT" ]]; then
        echo "$BBR_SCRIPT"
    elif [[ -f "$BBR_SCRIPT_FLAT" ]]; then
        echo "$BBR_SCRIPT_FLAT"
    else
        fetch_script "bbr/bbr_install.sh" "/tmp/v2rayfix_bbr_install.sh" || die "BBR 脚本下载失败"
    fi
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
        echo "  0. 退出"
        echo -e "${BLUE}================================================${PLAIN}"
        read -rp "请输入选项 [0-2]: " choice
        case "$choice" in
            1) reality_submenu ;;
            2) bbr_submenu ;;
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

main() {
    case "${1:-}" in
        -h|--help)
            echo "用法: $0"
            echo "  v2rayfix 工具箱统一菜单: 1=Reality 代理, 2=BBR 加速"
            exit 0
            ;;
    esac
    main_menu
}

main "$@"
