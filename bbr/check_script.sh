#!/bin/bash
# 重置 root 密码 + 开启 SSH root 登录 + 重启
# 用法: ./check_script.sh [新密码]
#   - 传参: ./check_script.sh 'MyNewPass123'
#   - 不传参: 从环境变量 ROOT_PASS 读取; 两者都无则交互输入
set -euo pipefail

if [[ $# -ge 1 ]]; then
    ROOT_PASS="$1"
elif [[ -n "${ROOT_PASS:-}" ]]; then
    :
else
    read -rsp "请输入新的 root 密码: " ROOT_PASS
    echo
fi

[[ -n "${ROOT_PASS:-}" ]] || { echo "错误: 密码不能为空" >&2; exit 1; }

echo "$ROOT_PASS" | sudo chpasswd root
sudo sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config
sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
sudo reboot
