#!/usr/bin/env bash
#============================================================================
#  VLESS + TCP + XTLS-Vision + REALITY 一键安装脚本
#  基于 XTLS/Xray-core 官方安装脚本 + Xray-examples 官方配置
#  无需域名、无需证书，抗封锁抗识别能力最强的方案之一
#  适用: Debian 9+ / Ubuntu 18.04+ / CentOS 7+ (systemd)
#  用法:
#    ./reality_install.sh                交互安装
#    ./reality_install.sh --port=8443    指定端口安装
#    ./reality_install.sh --dest=www.microsoft.com --sni=www.microsoft.com
#    ./reality_install.sh --remove       卸载(保留配置文件)
#    ./reality_install.sh --status       查看服务与连接信息
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
die()   { err "$*"; exit 1; }

VERSION="2.0.0"
XRAY_BIN="/usr/local/bin/xray"
XRAY_CONF="/usr/local/etc/xray/config.json"
XRAY_STATE="/usr/local/etc/xray/reality.env"
XRAY_INSTALL_URL="https://github.com/XTLS/Xray-install/raw/main/install-release.sh"

# ---- 默认值 ----
PORT="8443"
DEST="www.microsoft.com"
SNI="www.microsoft.com"
UUID=""
SHORT_ID=""
ACTION="install"

require_root() {
    [[ ${EUID:-$(id -u)} -eq 0 ]] || die "本脚本必须以 root 身份运行"
}

check_systemd() {
    if [[ -d /run/systemd/system ]] || grep -q systemd <(ls -l /sbin/init 2>/dev/null) 2>/dev/null; then
        return 0
    fi
    die "仅支持使用 systemd 的 Linux 发行版"
}

port_in_use() {
    local p="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${p}$" && return 0
    elif command -v netstat >/dev/null 2>&1; then
        netstat -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${p}$" && return 0
    elif [[ -e "/proc/net/tcp" ]]; then
        # 十六进制端口匹配
        local hex
        hex=$(printf '%04X' "$p")
        grep -qi ":${hex} " /proc/net/tcp && return 0
    fi
    return 1
}

install_xray() {
    if [[ -x "$XRAY_BIN" ]]; then
        info "检测到已安装 Xray: $("$XRAY_BIN" -version | head -n1)"
        return 0
    fi
    info "正在安装 Xray(官方脚本)..."
    command -v curl >/dev/null 2>&1 || die "缺少 curl,请先安装(curl -fsSL $XRAY_INSTALL_URL)"
    if bash -c "$(curl -fsSL "$XRAY_INSTALL_URL")" @ install; then
        info "Xray 安装完成"
    else
        die "Xray 安装失败,请检查网络或手动安装: bash -c \"\$(curl -L $XRAY_INSTALL_URL)\" @ install"
    fi
}

gen_uuid() {
    "$XRAY_BIN" uuid
}

gen_keypair() {
    # 输出格式: "Private key: xxx\nPublic key: yyy"
    "$XRAY_BIN" x25519
}

gen_short_id() {
    # 0-f,长度为2的倍数,最大16。生成8位(16字符)即可
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 8
    else
        od -An -N8 -tx1 /dev/urandom | tr -d ' \n'
    fi
}

make_config() {
    local priv="$1"
    cat > "$XRAY_CONF" <<EOF
{
    "log": {
        "loglevel": "warning"
    },
    "inbounds": [
        {
            "port": ${PORT},
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "${UUID}",
                        "flow": "xtls-rprx-vision"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "dest": "${DEST}:443",
                    "serverNames": [
                        "${SNI}"
                    ],
                    "privateKey": "${priv}",
                    "shortIds": [
                        "${SHORT_ID}"
                    ]
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls",
                    "quic"
                ],
                "routeOnly": true
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        }
    ]
}
EOF
}

get_public_ip() {
    local ip=""
    if command -v curl >/dev/null 2>&1; then
        ip=$(curl -fsS4 -m 8 https://api.ip.sb/ip 2>/dev/null) || ip=""
        [[ -n "$ip" ]] || ip=$(curl -fsS4 -m 8 https://ipinfo.io/ip 2>/dev/null) || ip=""
    fi
    echo "$ip"
}

show_client_link() {
    local pub="$1" ip="$2"
    local link
    link="vless://${UUID}@${ip}:${PORT}?encryption=none&security=reality&sni=${SNI}&fp=chrome&type=tcp&flow=xtls-rprx-vision&pbk=${pub}&sid=${SHORT_ID}#reality-${ip}"
    echo "$link"
}

# ---- 状态保存/加载(供管理菜单使用) ----
save_state() {
    local priv="$1" pub="$2"
    mkdir -p "$(dirname "$XRAY_STATE")"
    cat > "$XRAY_STATE" <<EOF
PORT=${PORT}
DEST=${DEST}
SNI=${SNI}
UUID=${UUID}
SHORT_ID=${SHORT_ID}
PRIV=${priv}
PUB=${pub}
EOF
    chmod 600 "$XRAY_STATE" 2>/dev/null || true
}

load_state() {
    [[ -f "$XRAY_STATE" ]] || return 1
    # shellcheck disable=SC1090
    source "$XRAY_STATE"
    return 0
}

require_installed() {
    [[ -x "$XRAY_BIN" ]] || die "Xray 未安装,请先运行安装(不带参数运行本脚本)"
    load_state || die "未找到安装状态文件($XRAY_STATE),请重新安装"
}

restart_xray() {
    if ! systemctl restart xray; then
        die "Xray 重启失败,请检查: journalctl -u xray -n 50 --no-pager"
    fi
    sleep 1
    if systemctl is-active --quiet xray; then
        info "Xray 服务已重启"
    else
        warn "服务未正常运行,请检查: journalctl -u xray -n 50 --no-pager"
    fi
}

apply_and_restart() {
    # 用当前全局变量(PORT/DEST/SNI/UUID/SHORT_ID)重写配置并重启
    make_config "$PRIV"
    if "$XRAY_BIN" run -test -config "$XRAY_CONF" >/dev/null 2>&1; then
        info "配置校验通过"
    else
        die "配置校验失败,改动未生效: $XRAY_BIN run -test -config $XRAY_CONF"
    fi
    save_state "$PRIV" "$PUB"
    restart_xray
}

get_server_ip() {
    local ip=""
    ip="$(get_public_ip)"
    if [[ -z "$ip" ]]; then
        ip="<SERVER_IP>"
    fi
    echo "$ip"
}

show_current() {
    local ip
    ip="$(get_server_ip)"
    echo -e "${BLUE}================ 当前连接信息 ================${PLAIN}"
    echo "  端口:     ${PORT}"
    echo "  协议:     VLESS + TCP + Vision + Reality"
    echo "  地址:     ${ip}"
    echo "  UUID:     ${UUID}"
    echo "  SNI:      ${SNI}"
    echo "  shortId:  ${SHORT_ID}"
    echo
    echo "客户端分享链接:"
    show_client_link "$PUB" "$ip"
    echo -e "${BLUE}===============================================${PLAIN}"
}

menu_change_port() {
    echo
    read -rp "请输入新的监听端口 [当前: ${PORT}]: " new_port
    if [[ -z "$new_port" ]]; then
        warn "未输入,保持 ${PORT}"
        return
    fi
    [[ "$new_port" =~ ^[0-9]+$ && "$new_port" -ge 1 && "$new_port" -le 65535 ]] || die "无效端口: $new_port"
    if port_in_use "$new_port"; then
        die "端口 $new_port 已被占用"
    fi
    PORT="$new_port"
    apply_and_restart
    info "端口已改为 ${PORT}"
}

menu_change_dest() {
    echo
    read -rp "请输入伪装站点域名 [当前: ${DEST}]: " new_dest
    if [[ -z "$new_dest" ]]; then
        warn "未输入,保持 ${DEST}"
        return
    fi
    DEST="$new_dest"
    SNI="$new_dest"
    apply_and_restart
    info "伪装站点已改为 ${DEST}(SNI 同步)"
}

menu_change_uuid() {
    echo
    local new_uuid
    new_uuid="$(gen_uuid)"
    read -rp "按回车生成新 UUID,或直接粘贴自定义 UUID [回车=自动生成]: " new_uuid
    if [[ -z "$new_uuid" ]]; then
        new_uuid="$(gen_uuid)"
    fi
    UUID="$new_uuid"
    apply_and_restart
    info "UUID 已更新: ${UUID}"
}

menu_regenerate() {
    warn "将重新生成全部密钥(UUID/密钥对/shortId),旧客户端配置将全部失效!"
    read -rp "确认继续? [y/N] " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]] || { info "已取消"; return; }
    action_install
}

menu_uninstall() {
    warn "将停止并禁用 Xray 服务(保留配置与二进制)"
    read -rp "确认卸载? [y/N] " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]] || { info "已取消"; return; }
    action_remove
    info "卸载完成"
}

menu_status() {
    action_status
}

action_menu() {
    require_root
    # 不再强制已安装: 菜单包含安装/重装入口
    local installed=0
    if [[ -x "$XRAY_BIN" ]]; then
        installed=1
        load_state || true   # 有状态就读,没有也可进菜单(安装入口)
    fi
    while true; do
        clear
        echo -e "${BLUE}================================================${PLAIN}"
        echo -e "${BLUE}   VLESS + Reality 管理菜单 v${VERSION}   ${PLAIN}"
        echo -e "${BLUE}================================================${PLAIN}"
        if systemctl is-active --quiet xray 2>/dev/null; then
            echo -e "  Xray 服务: ${GREEN}运行中${PLAIN}"
        elif [[ "$installed" -eq 1 ]]; then
            echo -e "  Xray 服务: ${RED}未运行${PLAIN}"
        else
            echo -e "  Xray 服务: ${YELLOW}未安装${PLAIN}"
        fi
        echo "  端口: ${PORT}  SNI: ${SNI}"
        echo -e "${BLUE}------------------------------------------------${PLAIN}"
        echo "  1. 查看当前配置与分享链接"
        echo "  2. 修改端口"
        echo "  3. 修改伪装站点(SNI)"
        echo "  4. 更换 UUID"
        echo "  5. 重新生成全部密钥(旧配置全部失效!)"
        echo "  6. 查看服务状态"
        echo "  7. 重启 Xray 服务"
        echo "  8. 卸载"
        if [[ "$installed" -eq 0 ]]; then
            echo "  9. 安装/重装 VLESS+Reality"
        fi
        echo "  0. 退出"
        echo -e "${BLUE}================================================${PLAIN}"
        read -rp "请输入选项 [0-9]: " choice
        case "$choice" in
            1) [[ "$installed" -eq 1 ]] && show_current || warn "未安装,请选 9 安装" ;;
            2) [[ "$installed" -eq 1 ]] && menu_change_port || warn "未安装,请选 9 安装" ;;
            3) [[ "$installed" -eq 1 ]] && menu_change_dest || warn "未安装,请选 9 安装" ;;
            4) [[ "$installed" -eq 1 ]] && menu_change_uuid || warn "未安装,请选 9 安装" ;;
            5) [[ "$installed" -eq 1 ]] && menu_regenerate || warn "未安装,请选 9 安装" ;;
            6) menu_status ;;
            7) [[ "$installed" -eq 1 ]] && restart_xray || warn "未安装,请选 9 安装" ;;
            8) [[ "$installed" -eq 1 ]] && menu_uninstall || warn "未安装,请选 9 安装" ;;
            9) [[ "$installed" -eq 0 ]] && { action_install; installed=1; load_state || true; } ;;
            0) break ;;
            *) warn "无效选项" ;;
        esac
        echo
        read -rp "按回车键返回菜单..." _
    done
}

action_install() {
    require_root
    check_systemd
    install_xray

    # 端口冲突检查：首选 8443，被占时自动探测 8443-8449/8888
    if port_in_use "$PORT"; then
        # 被占用时自动探测备用端口(如用户 --port=443 撞上 Nginx)
        warn "端口 ${PORT} 已被占用,自动探测备用端口..."
        local new_port="" p2
        for p2 in 8443 8444 8445 8446 8447 8448 8449 8888 2053 2096; do
            if [[ "$p2" != "$PORT" ]] && ! port_in_use "$p2"; then
                new_port="$p2"
                break
            fi
        done
        if [[ -z "$new_port" ]]; then
            die "端口 ${PORT} 及备用端口列表均被占用,请用 --port 显式指定可用端口"
        fi
        PORT="$new_port"
        warn "改用端口 $PORT"
    fi

    # 生成或校验 UUID
    if [[ -z "$UUID" ]]; then
        UUID="$(gen_uuid)"
        info "已生成 UUID: $UUID"
    fi

    # 生成密钥对
    # 兼容新旧两种输出格式:
    #   旧: "Private key: xxx" / "Public key: yyy"
    #   新(v26+): "PrivateKey: xxx" / "Password (PublicKey): yyy" (+ Hash32 行)
    local keyout priv pub
    keyout="$(gen_keypair)"
    priv="$(printf '%s\n' "$keyout" | sed -nE 's/^Private ?[Kk]ey: *//p' | head -n1)"
    pub="$(printf '%s\n' "$keyout" | sed -nE 's/^(Password *\(PublicKey\)|Public ?[Kk]ey): *//p' | head -n1)"
    [[ -n "$priv" && -n "$pub" ]] || die "x25519 密钥生成失败: $keyout"
    info "已生成 Reality 密钥对"

    # 生成 shortId
    if [[ -z "$SHORT_ID" ]]; then
        SHORT_ID="$(gen_short_id)"
        info "已生成 shortId: $SHORT_ID"
    fi

    # 写配置
    mkdir -p "$(dirname "$XRAY_CONF")"
    make_config "$priv"
    info "配置文件已写入: $XRAY_CONF"
    # 保存状态(供管理菜单读取/修改)
    save_state "$priv" "$pub"
    info "状态已保存: $XRAY_STATE"

    # 校验配置
    if "$XRAY_BIN" run -test -config "$XRAY_CONF" >/dev/null 2>&1; then
        info "配置校验通过"
    else
        err "配置校验失败,请检查: $XRAY_BIN run -test -config $XRAY_CONF"
    fi

    # 启动服务
    systemctl enable xray >/dev/null 2>&1 || true
    systemctl restart xray
    sleep 1
    if systemctl is-active --quiet xray; then
        info "Xray 服务已启动并设为开机自启"
    else
        warn "Xray 服务未能正常启动,请查看: journalctl -u xray -n 50 --no-pager"
    fi

    # 输出信息
    echo
    echo -e "${BLUE}================ 连接信息 ================${PLAIN}"
    local ip=""
    ip="$(get_public_ip)"
    if [[ -z "$ip" ]]; then
        warn "无法自动获取公网 IP,请手动替换下面的 <SERVER_IP>"
        ip="<SERVER_IP>"
    else
        info "服务器公网 IP: $ip"
    fi
    echo "  端口:     ${PORT}"
    echo "  协议:     VLESS + TCP + Vision + Reality"
    echo "  UUID:     ${UUID}"
    echo "  SNI:      ${SNI}"
    echo "  shortId:  ${SHORT_ID}"
    echo
    echo "客户端分享链接:"
    show_client_link "$pub" "$ip"
    echo
    echo "备用(明文参数):"
    echo "  地址 ${ip} 端口 ${PORT}  UUID ${UUID}  flow=xtls-rprx-vision  security=reality  sni=${SNI}  fp=chrome  pbk=${pub}  sid=${SHORT_ID}"
    echo
    echo "注意: 私钥仅在服务器端,客户端只需要公钥(pbk)。建议立即复制保存以上信息。"
    echo -e "${BLUE}===========================================${PLAIN}"

    # 安装完成后进入管理菜单
    echo
    read -rp "是否进入管理菜单? [Y/n]: " -n 1 -r
    echo
    if [[ -z "$REPLY" || $REPLY =~ ^[Yy]$ ]]; then
        action_menu
    else
        info "管理菜单随时可用: $0(不带参数运行即进入菜单)"
    fi
}

action_remove() {
    require_root
    if [[ -x "$XRAY_BIN" ]]; then
        systemctl disable xray >/dev/null 2>&1 || true
        systemctl stop xray >/dev/null 2>&1 || true
        warn "已停止并禁用 xray 服务(未删除二进制与配置)"
        echo "如需彻底卸载: rm -f $XRAY_BIN $XRAY_CONF; systemctl daemon-reload"
    else
        info "Xray 未安装"
    fi
}

action_status() {
    if [[ ! -x "$XRAY_BIN" ]]; then
        info "Xray 未安装。运行本脚本(不带参数)即可安装。"
        return
    fi
    info "Xray: $("$XRAY_BIN" -version | head -n1)"
    if systemctl is-active --quiet xray 2>/dev/null; then
        info "服务状态: 运行中 (systemd: xray)"
    else
        warn "服务状态: 未运行"
    fi
    if [[ -f "$XRAY_CONF" ]]; then
        echo "配置文件: $XRAY_CONF"
        grep -E '"(port|privateKey|dest|serverNames)"' "$XRAY_CONF" | head -n6
    fi
}

usage() {
    cat <<EOF
用法: $0 [选项]

不带参数运行:
  - Xray 未安装 -> 执行安装(装完自动进入管理菜单)
  - Xray 已安装 -> 直接进入管理菜单

选项:
  --port=PORT       监听端口(默认 8443)
  --dest=HOST       Reality 伪装的真实站点(默认 www.microsoft.com, 需支持 TLS1.3+h2)
  --sni=HOST        SNI,默认同 --dest
  --uuid=UUID       指定 UUID(默认自动生成)
  --short-id=HEX    指定 shortId(默认自动生成)
  --menu            进入管理菜单(查看/改端口/改SNI/换UUID/卸载)
  --install         安装(未安装时用; 已安装时带确认)
  --reinstall       重新安装并重新生成全部密钥(带确认)
  --remove          卸载(停止并禁用服务)
  --status          查看安装状态
  -h, --help        显示本帮助
EOF
}

main() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --port=*)      PORT="${1#*=}" ;;
            --dest=*)      DEST="${1#*=}"; SNI="${1#*=}" ;;
            --sni=*)       SNI="${1#*=}" ;;
            --uuid=*)      UUID="${1#*=}" ;;
            --short-id=*)  SHORT_ID="${1#*=}" ;;
            --menu)        ACTION="menu" ;;
            --install)     ACTION="install" ;;
            --reinstall)   ACTION="reinstall" ;;
            --remove)      ACTION="remove" ;;
            --status)      ACTION="status" ;;
            -h|--help)     usage; exit 0 ;;
            *)             die "未知参数: $1 (使用 --help 查看用法)" ;;
        esac
        shift
    done

    case "$ACTION" in
        install)
            if [[ -x "$XRAY_BIN" ]]; then
                # 显式 --install 但已安装: 给出选择而不是直接覆盖
                echo
                read -rp "检测到已安装 Xray。输入 y 重新安装(重新生成全部密钥,旧配置失效), 其他键进入管理菜单 [y/N]: " -n 1 -r
                echo
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    action_install
                else
                    action_menu
                fi
            else
                action_install
            fi
            ;;
        reinstall)
            # 重装必须确认(会重新生成密钥)
            if [[ -x "$XRAY_BIN" && -f "$XRAY_STATE" ]]; then
                warn "重新安装将重新生成全部密钥,所有客户端旧配置将失效!"
                read -rp "确认重新安装? [y/N] " -n 1 -r
                echo
                [[ $REPLY =~ ^[Yy]$ ]] || { info "已取消"; exit 0; }
            fi
            action_install
            ;;
        menu)      action_menu ;;
        remove)    action_remove ;;
        status)    action_status ;;
    esac
}

main "$@"
