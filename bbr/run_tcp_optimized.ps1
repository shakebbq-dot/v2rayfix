# PowerShell脚本 - 在Linux服务器上运行TCP优化脚本
# 使用方法：在Windows上准备，然后复制到Linux服务器执行
# GitHub: https://github.com/shakebbq-dot/v2rayfix

Write-Host "=== TCP网络优化脚本运行指南 ===" -ForegroundColor Green
Write-Host ""

# 方法1：直接上传到Linux服务器运行
Write-Host "方法1：直接上传到Linux服务器" -ForegroundColor Yellow
Write-Host "1. 将 tcp_optimized.sh 上传到Linux服务器的 /tmp/ 目录"
Write-Host "2. 在Linux服务器上执行以下命令：" -ForegroundColor Cyan
Write-Host "   chmod +x /tmp/tcp_optimized.sh"
Write-Host "   cd /tmp"
Write-Host "   ./tcp_optimized.sh"
Write-Host ""

# 方法2：使用SCP上传
Write-Host "方法2：使用SCP上传（需要OpenSSH）" -ForegroundColor Yellow
Write-Host "在PowerShell中执行：" -ForegroundColor Cyan
Write-Host "   scp tcp_optimized.sh root@你的服务器IP:/tmp/"
Write-Host "   ssh root@你的服务器IP 'chmod +x /tmp/tcp_optimized.sh && cd /tmp && ./tcp_optimized.sh'"
Write-Host ""

# 方法3：一键运行脚本
Write-Host "方法3：一键运行（需要提前配置SSH密钥）" -ForegroundColor Yellow
$serverIP = Read-Host "请输入Linux服务器IP地址"
$username = Read-Host "请输入用户名（默认root）"
if ([string]::IsNullOrEmpty($username)) { $username = "root" }

Write-Host "正在准备运行..." -ForegroundColor Green

# 检查文件是否存在
if (-not (Test-Path "tcp_optimized.sh")) {
    Write-Host "错误：tcp_optimized.sh 文件不存在！" -ForegroundColor Red
    exit 1
}

# 创建临时运行脚本
$tempScript = @'
#!/bin/bash
# 自动运行TCP优化脚本

echo "正在上传并运行TCP优化脚本..."

# 检查是否已经存在
if [ -f "/tmp/tcp_optimized.sh" ]; then
    rm -f /tmp/tcp_optimized.sh
fi

# 等待标准输入（文件内容）
cat > /tmp/tcp_optimized.sh

# 设置执行权限
chmod +x /tmp/tcp_optimized.sh

# 运行脚本
echo "开始执行TCP优化..."
cd /tmp
./tcp_optimized.sh
'@

Set-Content -Path "temp_run.sh" -Value $tempScript

Write-Host "运行命令：" -ForegroundColor Cyan
Write-Host "cat tcp_optimized.sh | ssh ${username}@${serverIP} 'bash -s'"

$confirm = Read-Host "是否立即运行？(y/n)"
if ($confirm -eq "y" -or $confirm -eq "Y") {
    try {
        Get-Content "tcp_optimized.sh" | ssh ${username}@${serverIP} 'bash -s'
        Write-Host "脚本执行完成！" -ForegroundColor Green
    } catch {
        Write-Host "执行失败：$_" -ForegroundColor Red
    }
} else {
    Write-Host "已准备好命令，您可以手动执行。" -ForegroundColor Yellow
}

# 清理临时文件
if (Test-Path "temp_run.sh") { Remove-Item "temp_run.sh" }

Write-Host ""
Write-Host "=== 运行说明 ===" -ForegroundColor Green
Write-Host "1. 确保Linux服务器可以正常访问"
Write-Host "2. 确保有root权限或sudo权限"
Write-Host "3. 建议在服务器空闲时运行"
Write-Host "4. 运行完成后可能需要重启服务器" -ForegroundColor Yellow