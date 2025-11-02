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
Info="${Green_font_prefix}[Info]${Font_color_suffix}"
Error="${Red_font_prefix}[Error]${Font_color_suffix}"
Tip="${Green_font_prefix}[Note]${Font_color_suffix}"

# Check system information
check_sys(){
	if [[ -f /etc/redhat-release ]]; then
		release="centos"
	elif grep -Eqi "debian" /etc/issue; then
		release="debian"
	elif grep -Eqi "ubuntu" /etc/issue; then
		release="ubuntu"
	else
		echo -e "${Error} Unsupported OS!" && exit 1
	fi
	
	bit=$(uname -m)
	if [[ ${bit} == "x86_64" ]]; then
		bit="x64"
	elif [[ ${bit} == "i386" || ${bit} == "i686" ]]; then
		bit="x86"
	else
		echo -e "${Error} Unsupported architecture: ${bit}!" && exit 1
	fi
}

# Install latest stable kernel (with BBR support)
install_latest_kernel(){
	echo -e "${Info} Installing latest stable kernel..."
	
	if [[ "${release}" == "ubuntu" || "${release}" == "debian" ]]; then
		# Ubuntu/Debian: Use official repository
		apt-get update
		apt-get install -y --install-recommends linux-generic-hwe-20.04
		
	elif [[ "${release}" == "centos" ]]; then
		# CentOS: Use ELRepo repository
		rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
		rpm -Uvh https://www.elrepo.org/elrepo-release-8.el8.elrepo.noarch.rpm
		yum --enablerepo=elrepo-kernel install -y kernel-ml
	fi
	
	echo -e "${Info} Kernel installed, reboot required"
	read -p "Reboot now? [Y/n]" choice
	case "$choice" in 
		y|Y|'' ) reboot ;;
		* ) echo "Please reboot manually" ;;
	esac
}

# Enable BBR
enable_bbr(){
	echo -e "${Info} Enabling BBR..."
	
	# Remove old configurations
	sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
	
	# Add new configurations (using latest cake algorithm)
	echo "net.core.default_qdisc=cake" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
	
	# Apply configurations
	sysctl -p
	
	echo -e "${Info} BBR enabled!"
}

# System optimization
optimize_system(){
	echo -e "${Info} Optimizing system configuration..."
	
	# Backup original config
	cp /etc/sysctl.conf /etc/sysctl.conf.backup
	
	# Optimize TCP parameters
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
	
	# Apply optimization config
	cat /tmp/sysctl_optimize.conf >> /etc/sysctl.conf
	sysctl -p
	
	# Optimize file descriptor limits
	echo "* soft nofile 1048576" >> /etc/security/limits.conf
	echo "* hard nofile 1048576" >> /etc/security/limits.conf
	echo "root soft nofile 1048576" >> /etc/security/limits.conf
	echo "root hard nofile 1048576" >> /etc/security/limits.conf
	
	echo -e "${Info} System optimization completed!"
}

# Check BBR status
check_bbr_status(){
	echo -e "${Info} Checking BBR status..."
	
	# Check current congestion control algorithm
	current_cc=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
	current_qdisc=$(sysctl net.core.default_qdisc 2>/dev/null | awk '{print $3}')
	
	echo "Current congestion control: ${current_cc:-Not set}"
	echo "Current queue algorithm: ${current_qdisc:-Not set}"
	
	if [[ "${current_cc}" == "bbr" ]]; then
		echo -e "${Info} BBR is enabled!"
	else
		echo -e "${Error} BBR is not enabled"
	fi
}

# Safe cleanup function
safe_cleanup(){
	rm -f /tmp/sysctl_optimize.conf
	rm -f /tmp/kernel_install.log
}

# Main menu
main_menu(){
	clear
	echo -e "=== TCP Network Optimization Script v${sh_ver} ==="
	echo "1. Install latest stable kernel"
	echo "2. Enable BBR acceleration"
	echo "3. System performance optimization"
	echo "4. Check BBR status"
	echo "5. Exit"
	echo ""
	
	read -p "Please choose [1-5]: " choice
	case $choice in
		1) install_latest_kernel ;;
		2) enable_bbr ;;
		3) optimize_system ;;
		4) check_bbr_status ;;
		5) exit 0 ;;
		*) echo "Invalid choice" ;;
	esac
	
	# Return to main menu
	echo ""
	read -p "Press Enter to return to main menu..."
	main_menu
}

# Script entry point
trap safe_cleanup EXIT
check_sys
echo -e "${Info} Detected system: ${release} ${bit}"
main_menu