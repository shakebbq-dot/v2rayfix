#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#=================================================
# System Required: Ubuntu 18+, Debian 10+, CentOS 8+
# Description: Advanced TCP BBR Optimization Script
# Version: 3.0.0
# Author: Network Optimization Tool
# GitHub: https://github.com/shakebbq-dot/v2rayfix/raw/main/bbr
# Features: BBR/BBRPlus/MagicBBR, Kernel Update, System Tuning
#=================================================

sh_ver="3.0.0"
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



# Install BBRPlus (Enhanced BBR)
install_bbrplus(){
    echo -e "${Info} Installing BBRPlus..."
    
    # Check if system supports BBRPlus
    if [[ "${release}" != "ubuntu" && "${release}" != "debian" ]]; then
        echo -e "${Error} BBRPlus only supports Ubuntu/Debian systems"
        return 1
    fi
    
    # Install required packages
    apt-get update
    apt-get install -y build-essential libncurses5-dev libssl-dev bc
    
    # Download and compile BBRPlus kernel
    echo -e "${Info} Downloading BBRPlus kernel source..."
    cd /tmp
    wget -O bbrplus.tar.gz https://github.com/cx9208/bbrplus/archive/refs/heads/master.tar.gz
    tar -xzf bbrplus.tar.gz
    cd bbrplus-master
    
    # Compile and install
    echo -e "${Info} Compiling BBRPlus kernel..."
    make -j$(nproc)
    make modules_install
    make install
    
    # Update grub
    update-grub
    
    echo -e "${Info} BBRPlus installed! Reboot required."
    read -p "Reboot now? [Y/n]" choice
    case "$choice" in 
        y|Y|'' ) reboot ;;
        * ) echo "Please reboot manually" ;;
    esac
}

# Install Magic BBR (Modified BBR)
install_magic_bbr(){
    echo -e "${Info} Installing Magic BBR..."
    
    # Magic BBR uses different congestion control parameters
    echo -e "${Info} Configuring Magic BBR parameters..."
    
    # Remove old configurations
    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
    
    # Magic BBR specific configuration
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    
    # Magic BBR optimized parameters
    cat >> /etc/sysctl.conf << EOF
# Magic BBR Optimization
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_ecn = 2
net.ipv4.tcp_frto = 2
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
EOF
    
    # Apply configurations
    sysctl -p
    
    echo -e "${Info} Magic BBR installed and configured!"
}

# Update BBR configuration
update_bbr_config(){
    echo -e "${Info} Updating BBR configuration..."
    
    # Backup current config
    cp /etc/sysctl.conf /etc/sysctl.conf.backup.$(date +%Y%m%d%H%M%S)
    
    # Remove old BBR configurations
    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
    sed -i '/# Magic BBR Optimization/d' /etc/sysctl.conf
    sed -i '/# TCP BBR Configuration/d' /etc/sysctl.conf
    
    # Add latest optimized configuration
    cat >> /etc/sysctl.conf << EOF
# Latest BBR Optimization (Updated: $(date))
net.core.default_qdisc = cake
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.somaxconn = 65535
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_mem = 65536 131072 262144
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
EOF
    
    # Apply configurations
    sysctl -p
    
    echo -e "${Info} BBR configuration updated successfully!"
}

# Script entry point
trap safe_cleanup EXIT
check_sys
echo -e "${Info} Detected system: ${release} ${bit}"

# Main execution loop
while true; do
	clear
	echo -e "=== TCP网络优化脚本 v${sh_ver} ==="
	echo "1. 安装最新稳定内核"
	echo "2. 启用BBR加速"
	echo "3. 系统性能优化"
	echo "4. 检查BBR状态"
	echo "5. 安装BBRPlus (增强版BBR)"
	echo "6. 安装魔改BBR (修改版BBR)"
	echo "7. 更新BBR配置"
	echo "8. 退出"
	echo ""
	
	read -p "请选择 [1-8]: " choice
	case $choice in
		1) install_latest_kernel ;;
		2) enable_bbr ;;
		3) optimize_system ;;
		4) check_bbr_status ;;
		5) install_bbrplus ;;
		6) install_magic_bbr ;;
		7) update_bbr_config ;;
		8) exit 0 ;;
		*) echo -e "${Error} 无效选择，请重新输入" ; sleep 2 ; continue ;;
	esac
	
	# Return to main menu
	echo ""
	read -p "按回车键返回主菜单..."
done