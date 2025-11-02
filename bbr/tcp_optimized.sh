#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#=================================================
# System Required: Ubuntu 18+, Debian 10+, CentOS 8+
# Description: Modern TCP BBR Optimization Script
# Version: 2.0.0
# Author: Network Optimization Tool
# GitHub: https://github.com/shakebbq-dot/v2rayfix/raw/main/bbr
# Features: Latest Kernel BBR, System Tuning, Security
#=================================================

sh_ver="2.0.0"
Green_font_prefix="\033[32m"
Red_font_prefix="\033[31m" 
Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[信息]${Font_color_suffix}"
Error="${Red_font_prefix}[错误]${Font_color_suffix}"
Tip="${Green_font_prefix}[注意]${Font_color_suffix}"

# 检查系统信息
check_sys(){
	if [[ -f /etc/redhat-release ]]; then
		release="centos"
	elif grep -Eqi "debian" /etc/issue; then
		release="debian"
	elif grep -Eqi "ubuntu" /etc/issue; then
		release="ubuntu"
	else
		echo -e "${Error} 不支持此操作系统！" && exit 1
	fi
	
	bit=$(uname -m)
	if [[ ${bit} == "x86_64" ]]; then
		bit="x64"
	elif [[ ${bit} == "i386" || ${bit} == "i686" ]]; then
		bit="x86"
	else
		echo -e "${Error} 不支持此架构：${bit}！" && exit 1
	fi
}

# 安装最新稳定版内核（支持BBR）
install_latest_kernel(){
	echo -e "${Info} 正在安装最新稳定版内核..."
	
	if [[ "${release}" == "ubuntu" || "${release}" == "debian" ]]; then
		# Ubuntu/Debian: 使用官方仓库的最新稳定内核
		apt-get update
		apt-get install -y --install-recommends linux-generic-hwe-20.04
		
	elif [[ "${release}" == "centos" ]]; then
		# CentOS: 使用ELRepo仓库
		rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
		yum install -y https://www.elrepo.org/elrepo-release-8.el8.elrepo.noarch.rpm
		yum --enablerepo=elrepo-kernel install -y kernel-ml
	fi
	
	echo -e "${Info} 内核安装完成，需要重启生效"
	read -p "是否立即重启？[Y/n]" choice
	case "$choice" in 
		y|Y|'' ) reboot ;;
		* ) echo "请手动重启后继续" ;;
	esac
}

# 启用BBR
enable_bbr(){
	echo -e "${Info} 正在启用BBR..."
	
	# 移除旧配置
	sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
	
	# 添加新配置（使用最新的cake队列算法）
	echo "net.core.default_qdisc=cake" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
	
	# 应用配置
	sysctl -p
	
	echo -e "${Info} BBR已启用！"
}

# 系统优化配置
optimize_system(){
	echo -e "${Info} 正在优化系统配置..."
	
	# 备份原始配置
	cp /etc/sysctl.conf /etc/sysctl.conf.backup
	
	# 优化TCP参数
	cat > /tmp/sysctl_optimize.conf << EOF
# TCP BBR Configuration
net.core.default_qdisc = cake
net.ipv4.tcp_congestion_control = bbr

# Network Performance Optimization
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535

# TCP Buffer Optimization
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_mem = 65536 131072 262144

# TCP Connection Optimization
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# IPv4 Settings
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_slow_start_after_idle = 0

# File Descriptors
fs.file-max = 2097152
fs.nr_open = 2097152
EOF
	
	# 应用优化配置
	cat /tmp/sysctl_optimize.conf >> /etc/sysctl.conf
	sysctl -p
	
	# 优化文件描述符限制
	echo "* soft nofile 1048576" >> /etc/security/limits.conf
	echo "* hard nofile 1048576" >> /etc/security/limits.conf
	echo "root soft nofile 1048576" >> /etc/security/limits.conf
	echo "root hard nofile 1048576" >> /etc/security/limits.conf
	
	echo -e "${Info} 系统优化完成！"
}

# 检查BBR状态
check_bbr_status(){
	echo -e "${Info} 检查当前BBR状态..."
	
	# 检查当前拥塞控制算法
	current_cc=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
	current_qdisc=$(sysctl net.core.default_qdisc | awk '{print $3}')
	
	echo "当前拥塞控制: ${current_cc}"
	echo "当前队列算法: ${current_qdisc}"
	
	if [[ "${current_cc}" == "bbr" ]]; then
		echo -e "${Info} BBR已启用！"
	else
		echo -e "${Error} BBR未启用"
	fi
}

# 安全清理函数
safe_cleanup(){
	rm -f /tmp/sysctl_optimize.conf
	rm -f /tmp/kernel_install.log
}

# 主菜单
main_menu(){
	clear
	echo -e "=== TCP网络优化脚本 v${sh_ver} ==="
	echo "1. 安装最新稳定版内核"
	echo "2. 启用BBR加速"
	echo "3. 系统性能优化"
	echo "4. 检查BBR状态"
	echo "5. 退出"
	echo ""
	
	read -p "请选择操作 [1-5]: " choice
	case $choice in
		1) install_latest_kernel ;;
		2) enable_bbr ;;
		3) optimize_system ;;
		4) check_bbr_status ;;
		5) exit 0 ;;
		*) echo "无效选择" ;;
	esac
	
	# 返回主菜单
	echo ""
	read -p "按回车键返回主菜单..."
	# 移除递归调用main_menu，避免栈溢出和闪屏
}

# 脚本入口
trap safe_cleanup EXIT
check_sys
echo -e "${Info} 检测到系统: ${release} ${bit}"

# 使用循环代替递归，避免栈溢出
while true; do
    main_menu
done