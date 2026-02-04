# ===============================================================================
# Enhanced WireGuard Tunnel Manager for Windows 11 - ULTIMATE VERSION
# Version: 2.5 ULTIMATE
# Features: Multi-tunnel, Auto-reconnect, Network diagnostics, Toast notifications,
#           Speed test, Connection history, Data tracking, Advanced settings
# ===============================================================================

#Requires -Version 5.1

# ===============================================================================
# CONFIGURATION
# ===============================================================================

$Script:Config = @{
    LogPath = "$env:TEMP\WireGuard-Manager.log"
    ConfigPath = "$env:USERPROFILE\AppData\Local\WireGuard\Configurations"
    BackupPath = "$env:USERPROFILE\Documents\WireGuard-Backups"
    AutoReconnect = $true
    HealthCheckInterval = 30
    NotificationsEnabled = $true
    KillSwitchEnabled = $false
    AutoReconnectAttempts = 3
    ConnectionHistoryPath = "$env:TEMP\WireGuard-History.json"
}

$Script:StartTime = Get-Date
$Script:SelectedTunnel = $null
$Script:AllTunnels = @()

# ===============================================================================
# ADMIN CHECK
# ===============================================================================

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Requesting administrator privileges..." -ForegroundColor Yellow
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# ===============================================================================
# LOGGING FUNCTIONS
# ===============================================================================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    try {
        Add-Content -Path $Script:Config.LogPath -Value $logMessage -ErrorAction SilentlyContinue
    } catch {
        # Silently fail if logging not available
    }
}

# ===============================================================================
# NOTIFICATION FUNCTIONS
# ===============================================================================

function Show-Notification {
    param(
        [string]$Title,
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Type = 'Info'
    )

    if (-not $Script:Config.NotificationsEnabled) { return }

    try {
        $icon = switch ($Type) {
            'Success' { '(OK)' }
            'Error' { '(X)' }
            'Warning' { '(!)' }
            default { '(i)' }
        }

        # Windows 11 Toast Notification
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
        $notification = New-Object System.Windows.Forms.NotifyIcon
        $notification.Icon = [System.Drawing.SystemIcons]::Information
        $notification.BalloonTipIcon = $Type
        $notification.BalloonTipText = $Message
        $notification.BalloonTipTitle = "$icon $Title"
        $notification.Visible = $true
        $notification.ShowBalloonTip(3000)
    } catch {
        # Fallback - silently ignore
    }
}

# ===============================================================================
# TUNNEL DISCOVERY
# ===============================================================================

function Get-AllTunnels {
    Write-Log "Discovering WireGuard tunnels..."

    $tunnels = @()
    $services = Get-Service -Name "WireGuardTunnel`$*" -ErrorAction SilentlyContinue

    foreach ($service in $services) {
        $tunnelName = $service.Name -replace 'WireGuardTunnel\$', ''
        $tunnels += @{
            Name = $tunnelName
            ServiceName = $service.Name
            Status = $service.Status
            DisplayName = $service.DisplayName
        }
    }

    Write-Log "Found $($tunnels.Count) tunnel(s)"
    return $tunnels
}

function Select-Tunnel {
    $Script:AllTunnels = Get-AllTunnels

    if ($Script:AllTunnels.Count -eq 0) {
        Write-Host "`n[!] No WireGuard tunnels found!" -ForegroundColor Yellow
        Write-Host "Please install WireGuard and add at least one tunnel configuration." -ForegroundColor Gray
        Write-Host "`nPress any key to exit..." -ForegroundColor Gray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        exit
    }

    if ($Script:AllTunnels.Count -eq 1) {
        $Script:SelectedTunnel = $Script:AllTunnels[0].Name
        return
    }

    Clear-Host
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "         SELECT WIREGUARD TUNNEL                                " -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""

    for ($i = 0; $i -lt $Script:AllTunnels.Count; $i++) {
        $tunnel = $Script:AllTunnels[$i]
        $statusIcon = if ($tunnel.Status -eq 'Running') { '[ON]' } else { '[OFF]' }
        $statusColor = if ($tunnel.Status -eq 'Running') { 'Green' } else { 'Red' }

        Write-Host "  $($i + 1). " -NoNewline -ForegroundColor White
        Write-Host "$statusIcon " -NoNewline -ForegroundColor $statusColor
        Write-Host "$($tunnel.Name)" -ForegroundColor White
    }

    Write-Host ""
    $selection = Read-Host "Select tunnel (1-$($Script:AllTunnels.Count))"

    if ([int]$selection -ge 1 -and [int]$selection -le $Script:AllTunnels.Count) {
        $Script:SelectedTunnel = $Script:AllTunnels[[int]$selection - 1].Name
        Write-Log "Selected tunnel: $Script:SelectedTunnel"
    } else {
        $Script:SelectedTunnel = $Script:AllTunnels[0].Name
        Start-Sleep -Seconds 1
    }
}

# ===============================================================================
# TUNNEL STATUS & INFO
# ===============================================================================

function Get-TunnelStatus {
    param([string]$tunnelName)

    $serviceName = "WireGuardTunnel`$$tunnelName"
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

    if ($service) {
        return $service.Status
    } else {
        return "Not Installed"
    }
}

function Get-TunnelUptime {
    param([string]$tunnelName)

    try {
        $serviceName = "WireGuardTunnel`$$tunnelName"
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

        if ($service -and $service.Status -eq 'Running') {
            $process = Get-Process | Where-Object { $_.Name -like "*wireguard*" } | Select-Object -First 1
            if ($process) {
                $uptime = (Get-Date) - $process.StartTime
                return "{0:hh\:mm\:ss}" -f $uptime
            }
        }
    } catch {
        return "N/A"
    }

    return "00:00:00"
}

function Get-TunnelIP {
    param([string]$tunnelName)

    try {
        $adapter = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like "*WireGuard*" -and $_.Status -eq "Up" } | Select-Object -First 1
        if ($adapter) {
            $ip = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
            if ($ip) {
                return $ip.IPAddress
            }
        }
    } catch {
        return "N/A"
    }

    return "N/A"
}

function Get-PublicIP {
    try {
        $ip = (Invoke-RestMethod -Uri "https://api.ipify.org?format=json" -TimeoutSec 5).ip
        return $ip
    } catch {
        return "N/A"
    }
}

function Test-Connectivity {
    param([string]$Target = "1.1.1.1")

    try {
        $ping = Test-Connection -ComputerName $Target -Count 1 -Quiet -ErrorAction SilentlyContinue
        return $ping
    } catch {
        return $false
    }
}

function Get-Latency {
    param([string]$Target = "1.1.1.1")

    try {
        $ping = Test-Connection -ComputerName $Target -Count 1 -ErrorAction SilentlyContinue
        if ($ping) {
            return "$($ping.ResponseTime) ms"
        }
    } catch {
        return "N/A"
    }

    return "N/A"
}

function Get-DataTransferStats {
    param([string]$tunnelName)

    try {
        $adapter = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like "*WireGuard*" -and $_.Status -eq "Up" } | Select-Object -First 1
        if ($adapter) {
            $stats = Get-NetAdapterStatistics -Name $adapter.Name -ErrorAction SilentlyContinue
            if ($stats) {
                return @{
                    Sent = [math]::Round($stats.SentBytes / 1MB, 2)
                    Received = [math]::Round($stats.ReceivedBytes / 1MB, 2)
                }
            }
        }
    } catch {
        # Return zero stats on error
    }

    return @{ Sent = 0; Received = 0 }
}

function Test-ConnectionSpeed {
    Write-Host "`n  [~] Testing connection speed..." -ForegroundColor Yellow

    try {
        $testUrl = "https://speed.cloudflare.com/__down?bytes=5000000"
        $startTime = Get-Date

        $webClient = New-Object System.Net.WebClient
        $data = $webClient.DownloadData($testUrl)

        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalSeconds
        $speedMbps = [math]::Round(($data.Length * 8 / $duration) / 1MB, 2)

        return "$speedMbps Mbps"
    } catch {
        return "Test failed"
    }
}

function Save-ConnectionHistory {
    param(
        [string]$TunnelName,
        [string]$Action,
        [string]$Status
    )

    $entry = @{
        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Tunnel = $TunnelName
        Action = $Action
        Status = $Status
    }

    try {
        $history = @()
        if (Test-Path $Script:Config.ConnectionHistoryPath) {
            $history = Get-Content $Script:Config.ConnectionHistoryPath | ConvertFrom-Json
        }

        $history += $entry

        if ($history.Count -gt 100) {
            $history = $history | Select-Object -Last 100
        }

        $history | ConvertTo-Json | Set-Content $Script:Config.ConnectionHistoryPath
    } catch {
        Write-Log "Failed to save connection history: $_" -Level ERROR
    }
}

function Get-ConnectionHistory {
    try {
        if (Test-Path $Script:Config.ConnectionHistoryPath) {
            return Get-Content $Script:Config.ConnectionHistoryPath | ConvertFrom-Json
        }
    } catch {
        # Return empty array on error
    }

    return @()
}

# ===============================================================================
# ENHANCED UI DISPLAY
# ===============================================================================

function Show-EnhancedMenu {
    Clear-Host

    $status = Get-TunnelStatus -tunnelName $Script:SelectedTunnel
    $isConnected = $status -eq "Running"

    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "     WIREGUARD TUNNEL MANAGER - ULTIMATE v2.5                                  " -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "  ACTIVE TUNNEL" -ForegroundColor DarkGray
    Write-Host "  -----------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  Name: " -NoNewline -ForegroundColor Gray
    Write-Host $Script:SelectedTunnel -ForegroundColor White

    Write-Host "  Status: " -NoNewline -ForegroundColor Gray
    if ($isConnected) {
        Write-Host "[CONNECTED]" -ForegroundColor Green
    } else {
        Write-Host "[DISCONNECTED]" -ForegroundColor Red
    }

    if ($isConnected) {
        Write-Host "  Uptime: " -NoNewline -ForegroundColor Gray
        Write-Host (Get-TunnelUptime -tunnelName $Script:SelectedTunnel) -ForegroundColor Cyan

        Write-Host "  Tunnel IP: " -NoNewline -ForegroundColor Gray
        Write-Host (Get-TunnelIP -tunnelName $Script:SelectedTunnel) -ForegroundColor Cyan

        Write-Host "  Public IP: " -NoNewline -ForegroundColor Gray
        Write-Host (Get-PublicIP) -ForegroundColor Yellow

        Write-Host "  Latency: " -NoNewline -ForegroundColor Gray
        Write-Host (Get-Latency) -ForegroundColor Cyan

        $stats = Get-DataTransferStats -tunnelName $Script:SelectedTunnel
        Write-Host "  Data Sent: " -NoNewline -ForegroundColor Gray
        Write-Host "$($stats.Sent) MB" -ForegroundColor Green
        Write-Host "  Data Received: " -NoNewline -ForegroundColor Gray
        Write-Host "$($stats.Received) MB" -ForegroundColor Green

        $connectivity = Test-Connectivity
        Write-Host "  Connectivity: " -NoNewline -ForegroundColor Gray
        if ($connectivity) {
            Write-Host "[OK]" -ForegroundColor Green
        } else {
            Write-Host "[FAILED]" -ForegroundColor Red
        }
    }

    Write-Host ""
    Write-Host "  AVAILABLE TUNNELS ($($Script:AllTunnels.Count))" -ForegroundColor DarkGray
    Write-Host "  -----------------------------------------------" -ForegroundColor DarkGray

    foreach ($tunnel in $Script:AllTunnels) {
        $icon = if ($tunnel.Status -eq 'Running') { '[ON]' } else { '[OFF]' }
        $color = if ($tunnel.Status -eq 'Running') { 'Green' } else { 'DarkGray' }
        $isCurrent = $tunnel.Name -eq $Script:SelectedTunnel

        Write-Host "  $icon " -NoNewline -ForegroundColor $color
        if ($isCurrent) {
            Write-Host "$($tunnel.Name) [ACTIVE]" -ForegroundColor White
        } else {
            Write-Host $tunnel.Name -ForegroundColor Gray
        }
    }

    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "  ACTIONS                                                                      " -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "  [1] Start Tunnel        [2] Stop Tunnel" -ForegroundColor White
    Write-Host "  [3] Restart Tunnel      [4] Switch Tunnel" -ForegroundColor White
    Write-Host "  [5] Network Diagnostics [6] View Configuration" -ForegroundColor White
    Write-Host "  [7] Auto-Start Settings [8] Backup Configs" -ForegroundColor White
    Write-Host "  [9] Advanced Settings   [I] Import/Manage Tunnels" -ForegroundColor Cyan
    Write-Host "  [Q] Quick Toggle        [S] Speed Test" -ForegroundColor White
    Write-Host "  [H] Connection History  [L] View Logs" -ForegroundColor White
    Write-Host "  [R] Refresh             [0] Exit" -ForegroundColor Gray

    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
}

# ===============================================================================
# TUNNEL OPERATIONS
# ===============================================================================

function Start-Tunnel {
    param([string]$tunnelName)

    Write-Host "`n[~] Starting tunnel '$tunnelName'..." -ForegroundColor Yellow
    $serviceName = "WireGuardTunnel`$$tunnelName"

    try {
        Start-Service -Name $serviceName -ErrorAction Stop
        Write-Host "[+] Tunnel started successfully!" -ForegroundColor Green
        Write-Log "Tunnel '$tunnelName' started" -Level SUCCESS
        Save-ConnectionHistory -TunnelName $tunnelName -Action "Start" -Status "Success"
        Show-Notification -Title "WireGuard Connected" -Message "Tunnel '$tunnelName' is now active" -Type Success
    } catch {
        Write-Host "[!] Error starting tunnel: $_" -ForegroundColor Red
        Write-Log "Failed to start tunnel '$tunnelName': $_" -Level ERROR
        Save-ConnectionHistory -TunnelName $tunnelName -Action "Start" -Status "Failed"
        Show-Notification -Title "Connection Failed" -Message "Could not start tunnel '$tunnelName'" -Type Error
    }

    Start-Sleep -Seconds 2
}

function Stop-Tunnel {
    param([string]$tunnelName)

    Write-Host "`n[~] Stopping tunnel '$tunnelName'..." -ForegroundColor Yellow
    $serviceName = "WireGuardTunnel`$$tunnelName"

    try {
        Stop-Service -Name $serviceName -ErrorAction Stop
        Write-Host "[+] Tunnel stopped successfully!" -ForegroundColor Green
        Write-Log "Tunnel '$tunnelName' stopped" -Level SUCCESS
        Save-ConnectionHistory -TunnelName $tunnelName -Action "Stop" -Status "Success"
        Show-Notification -Title "WireGuard Disconnected" -Message "Tunnel '$tunnelName' has been stopped" -Type Info
    } catch {
        Write-Host "[!] Error stopping tunnel: $_" -ForegroundColor Red
        Write-Log "Failed to stop tunnel '$tunnelName': $_" -Level ERROR
        Save-ConnectionHistory -TunnelName $tunnelName -Action "Stop" -Status "Failed"
    }

    Start-Sleep -Seconds 2
}

function Restart-Tunnel {
    param([string]$tunnelName)

    Write-Host "`n[~] Restarting tunnel '$tunnelName'..." -ForegroundColor Yellow
    $serviceName = "WireGuardTunnel`$$tunnelName"

    try {
        Restart-Service -Name $serviceName -ErrorAction Stop
        Write-Host "[+] Tunnel restarted successfully!" -ForegroundColor Green
        Write-Log "Tunnel '$tunnelName' restarted" -Level SUCCESS
        Save-ConnectionHistory -TunnelName $tunnelName -Action "Restart" -Status "Success"
        Show-Notification -Title "WireGuard Restarted" -Message "Tunnel '$tunnelName' has been restarted" -Type Success
    } catch {
        Write-Host "[!] Error restarting tunnel: $_" -ForegroundColor Red
        Write-Log "Failed to restart tunnel '$tunnelName': $_" -Level ERROR
        Save-ConnectionHistory -TunnelName $tunnelName -Action "Restart" -Status "Failed"
    }

    Start-Sleep -Seconds 2
}

function Invoke-QuickToggle {
    $status = Get-TunnelStatus -tunnelName $Script:SelectedTunnel

    if ($status -eq "Running") {
        Stop-Tunnel -tunnelName $Script:SelectedTunnel
    } elseif ($status -eq "Stopped") {
        Start-Tunnel -tunnelName $Script:SelectedTunnel
    } else {
        Write-Host "`n  [!] Cannot toggle - tunnel status: $status" -ForegroundColor Red
        Start-Sleep -Seconds 2
    }
}

# ===============================================================================
# HISTORY & LOGS
# ===============================================================================

function Show-ConnectionHistory {
    Clear-Host
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "           CONNECTION HISTORY                                   " -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""

    $history = Get-ConnectionHistory

    if ($history.Count -eq 0) {
        Write-Host "  No connection history available." -ForegroundColor Gray
    } else {
        Write-Host "  Last 20 connections:" -ForegroundColor Gray
        Write-Host "  -----------------------------------------------" -ForegroundColor DarkGray
        Write-Host ""

        $recent = $history | Select-Object -Last 20
        foreach ($entry in $recent) {
            $statusColor = if ($entry.Status -eq "Success") { "Green" } else { "Red" }
            $actionColor = switch ($entry.Action) {
                "Start" { "Green" }
                "Stop" { "Red" }
                "Restart" { "Yellow" }
                default { "Gray" }
            }

            Write-Host "  $($entry.Timestamp) " -NoNewline -ForegroundColor DarkGray
            Write-Host "[$($entry.Action)]" -NoNewline -ForegroundColor $actionColor
            Write-Host " $($entry.Tunnel) - " -NoNewline -ForegroundColor White
            Write-Host $entry.Status -ForegroundColor $statusColor
        }
    }

    Write-Host ""
    Write-Host "Press any key to return..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Show-Logs {
    Clear-Host
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "           APPLICATION LOGS                                     " -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""

    if (Test-Path $Script:Config.LogPath) {
        Write-Host "  Log file: " -NoNewline -ForegroundColor Gray
        Write-Host $Script:Config.LogPath -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Last 30 entries:" -ForegroundColor Gray
        Write-Host "  -----------------------------------------------" -ForegroundColor DarkGray
        Write-Host ""

        $logs = Get-Content $Script:Config.LogPath -Tail 30
        foreach ($log in $logs) {
            $color = "Gray"
            if ($log -match "ERROR") { $color = "Red" }
            elseif ($log -match "WARN") { $color = "Yellow" }
            elseif ($log -match "SUCCESS") { $color = "Green" }
            elseif ($log -match "INFO") { $color = "Cyan" }

            Write-Host "  $log" -ForegroundColor $color
        }
    } else {
        Write-Host "  [!] Log file not found!" -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "Press any key to return..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ===============================================================================
# ADVANCED SETTINGS
# ===============================================================================

function Show-AdvancedSettings {
    Clear-Host
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "           ADVANCED SETTINGS                                    " -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "  Current Settings:" -ForegroundColor Gray
    Write-Host "  -----------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "  1. Notifications: " -NoNewline -ForegroundColor Gray
    $notifColor = if ($Script:Config.NotificationsEnabled) { "Green" } else { "Red" }
    Write-Host $(if ($Script:Config.NotificationsEnabled) { "ENABLED" } else { "DISABLED" }) -ForegroundColor $notifColor

    Write-Host "  2. Auto-Reconnect: " -NoNewline -ForegroundColor Gray
    $autoColor = if ($Script:Config.AutoReconnect) { "Green" } else { "Red" }
    Write-Host $(if ($Script:Config.AutoReconnect) { "ENABLED" } else { "DISABLED" }) -ForegroundColor $autoColor

    Write-Host "  3. Health Check Interval: " -NoNewline -ForegroundColor Gray
    Write-Host "$($Script:Config.HealthCheckInterval) seconds" -ForegroundColor Cyan

    Write-Host ""
    Write-Host "  -----------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [1] Toggle Notifications" -ForegroundColor White
    Write-Host "  [2] Toggle Auto-Reconnect" -ForegroundColor White
    Write-Host "  [3] Export Diagnostic Report" -ForegroundColor Cyan
    Write-Host "  [4] Clear Connection History" -ForegroundColor Red
    Write-Host "  [5] Clear Logs" -ForegroundColor Red
    Write-Host "  [0] Back to main menu" -ForegroundColor Gray
    Write-Host ""

    $choice = Read-Host "Select option"

    switch ($choice) {
        "1" {
            $Script:Config.NotificationsEnabled = -not $Script:Config.NotificationsEnabled
            $status = if ($Script:Config.NotificationsEnabled) { "ENABLED" } else { "DISABLED" }
            Write-Host "`n  [+] Notifications $status" -ForegroundColor Green
            Write-Log "Notifications $status" -Level INFO
            Start-Sleep -Seconds 2
            Show-AdvancedSettings
        }
        "2" {
            $Script:Config.AutoReconnect = -not $Script:Config.AutoReconnect
            $status = if ($Script:Config.AutoReconnect) { "ENABLED" } else { "DISABLED" }
            Write-Host "`n  [+] Auto-Reconnect $status" -ForegroundColor Green
            Write-Log "Auto-Reconnect $status" -Level INFO
            Start-Sleep -Seconds 2
            Show-AdvancedSettings
        }
        "3" {
            Export-DiagnosticReport
            Show-AdvancedSettings
        }
        "4" {
            Write-Host "`n  [!] Clear connection history? (Y/N): " -NoNewline -ForegroundColor Yellow
            $confirm = Read-Host
            if ($confirm -eq "Y") {
                Remove-Item $Script:Config.ConnectionHistoryPath -ErrorAction SilentlyContinue
                Write-Host "  [+] Connection history cleared" -ForegroundColor Green
                Write-Log "Connection history cleared" -Level INFO
            }
            Start-Sleep -Seconds 2
            Show-AdvancedSettings
        }
        "5" {
            Write-Host "`n  [!] Clear logs? (Y/N): " -NoNewline -ForegroundColor Yellow
            $confirm = Read-Host
            if ($confirm -eq "Y") {
                Remove-Item $Script:Config.LogPath -ErrorAction SilentlyContinue
                Write-Host "  [+] Logs cleared" -ForegroundColor Green
            }
            Start-Sleep -Seconds 2
            Show-AdvancedSettings
        }
    }
}

function Export-DiagnosticReport {
    Write-Host "`n  [~] Generating diagnostic report..." -ForegroundColor Yellow

    try {
        $reportPath = "$env:USERPROFILE\Desktop\WireGuard-Diagnostics-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

        $report = "================================================================`n"
        $report += "  WIREGUARD DIAGNOSTIC REPORT`n"
        $report += "================================================================`n"
        $report += "`nGenerated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n`n"
        $report += "[SYSTEM INFORMATION]`n"
        $report += "----------------------------------------------------------------`n"
        $report += "OS: $(([System.Environment]::OSVersion).VersionString)`n"
        $report += "PowerShell: $($PSVersionTable.PSVersion)`n"
        $report += "Hostname: $env:COMPUTERNAME`n"
        $report += "User: $env:USERNAME`n`n"

        $report += "[TUNNEL STATUS]`n"
        $report += "----------------------------------------------------------------`n"
        $report += "Active Tunnel: $($Script:SelectedTunnel)`n"
        $report += "Status: $(Get-TunnelStatus -tunnelName $Script:SelectedTunnel)`n"
        $report += "Tunnel IP: $(Get-TunnelIP -tunnelName $Script:SelectedTunnel)`n"
        $report += "Public IP: $(Get-PublicIP)`n"
        $report += "Uptime: $(Get-TunnelUptime -tunnelName $Script:SelectedTunnel)`n`n"

        $report += "[ALL TUNNELS]`n"
        $report += "----------------------------------------------------------------`n"
        foreach ($tunnel in $Script:AllTunnels) {
            $report += "- $($tunnel.Name): $($tunnel.Status)`n"
        }

        $report += "`n[NETWORK DIAGNOSTICS]`n"
        $report += "----------------------------------------------------------------`n"
        $report += "Connectivity Test: $(if (Test-Connectivity) { 'PASS' } else { 'FAIL' })`n"
        $report += "Latency (1.1.1.1): $(Get-Latency)`n"
        $report += "Latency (8.8.8.8): $(Get-Latency -Target '8.8.8.8')`n`n"

        $report += "[CONFIGURATION]`n"
        $report += "----------------------------------------------------------------`n"
        $report += "Notifications: $(if ($Script:Config.NotificationsEnabled) { 'Enabled' } else { 'Disabled' })`n"
        $report += "Auto-Reconnect: $(if ($Script:Config.AutoReconnect) { 'Enabled' } else { 'Disabled' })`n"

        if (Test-Path $Script:Config.LogPath) {
            $report += "`n[RECENT LOGS (Last 20)]`n"
            $report += "----------------------------------------------------------------`n"
            $recentLogs = Get-Content $Script:Config.LogPath -Tail 20
            foreach ($log in $recentLogs) {
                $report += "$log`n"
            }
        }

        $report += "`n================================================================`n"

        $report | Set-Content -Path $reportPath

        Write-Host "  [+] Diagnostic report saved to:" -ForegroundColor Green
        Write-Host "    $reportPath" -ForegroundColor Cyan
        Write-Log "Diagnostic report exported to: $reportPath" -Level INFO
    } catch {
        Write-Host "  [!] Failed to generate report: $_" -ForegroundColor Red
        Write-Log "Failed to generate diagnostic report: $_" -Level ERROR
    }

    Write-Host ""
    Write-Host "Press any key to continue..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ===============================================================================
# NETWORK DIAGNOSTICS
# ===============================================================================

function Show-NetworkDiagnostics {
    Clear-Host
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "           NETWORK DIAGNOSTICS                                  " -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "[~] Running diagnostics..." -ForegroundColor Yellow
    Write-Host ""

    Write-Host "  Public IP Address:" -ForegroundColor Gray
    $publicIP = Get-PublicIP
    Write-Host "  -> $publicIP" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "  Tunnel IP Address:" -ForegroundColor Gray
    $tunnelIP = Get-TunnelIP -tunnelName $Script:SelectedTunnel
    Write-Host "  -> $tunnelIP" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "  DNS Resolution Test:" -ForegroundColor Gray
    try {
        $dns = Resolve-DnsName google.com -ErrorAction Stop | Select-Object -First 1
        Write-Host "  -> [OK] ($($dns.IPAddress))" -ForegroundColor Green
    } catch {
        Write-Host "  -> [FAILED]" -ForegroundColor Red
    }
    Write-Host ""

    Write-Host "  Latency Tests:" -ForegroundColor Gray
    $targets = @(
        @{Name="Cloudflare DNS"; IP="1.1.1.1"},
        @{Name="Google DNS"; IP="8.8.8.8"},
        @{Name="Google.com"; IP="google.com"}
    )

    foreach ($target in $targets) {
        Write-Host "  -> $($target.Name): " -NoNewline -ForegroundColor DarkGray
        $latency = Get-Latency -Target $target.IP
        if ($latency -ne "N/A") {
            Write-Host $latency -ForegroundColor Green
        } else {
            Write-Host "Timeout" -ForegroundColor Red
        }
    }
    Write-Host ""

    $status = Get-TunnelStatus -tunnelName $Script:SelectedTunnel
    if ($status -eq "Running") {
        Write-Host "  Data Transfer:" -ForegroundColor Gray
        $stats = Get-DataTransferStats -tunnelName $Script:SelectedTunnel
        Write-Host "  -> Sent: $($stats.Sent) MB" -ForegroundColor Green
        Write-Host "  -> Received: $($stats.Received) MB" -ForegroundColor Green
        Write-Host ""
    }

    Write-Host "  Active Network Adapters:" -ForegroundColor Gray
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    foreach ($adapter in $adapters) {
        $isWG = $adapter.InterfaceDescription -like "*WireGuard*"
        $icon = if ($isWG) { "[VPN]" } else { "[LAN]" }
        Write-Host "  -> $icon $($adapter.Name) - " -NoNewline -ForegroundColor DarkGray
        Write-Host $adapter.InterfaceDescription -ForegroundColor $(if ($isWG) { 'Green' } else { 'Gray' })
    }

    Write-Host ""
    Write-Host "Press any key to return..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ===============================================================================
# CONFIGURATION VIEWER
# ===============================================================================

function Show-Configuration {
    Clear-Host
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "           TUNNEL CONFIGURATION                                 " -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""

    $configFile = "$($Script:Config.ConfigPath)\$($Script:SelectedTunnel).conf"

    if (Test-Path $configFile) {
        Write-Host "  Configuration for: " -NoNewline -ForegroundColor Gray
        Write-Host $Script:SelectedTunnel -ForegroundColor White
        Write-Host "  Location: " -NoNewline -ForegroundColor Gray
        Write-Host $configFile -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  -----------------------------------------------" -ForegroundColor DarkGray
        Write-Host ""

        $content = Get-Content $configFile
        foreach ($line in $content) {
            if ($line -match "^\[.*\]$") {
                Write-Host "  $line" -ForegroundColor Yellow
            } elseif ($line -match "^[^=]+=") {
                $parts = $line -split "=", 2
                Write-Host "  $($parts[0].Trim()) = " -NoNewline -ForegroundColor Gray

                if ($parts[0].Trim() -match "PrivateKey|PresharedKey") {
                    Write-Host "***HIDDEN***" -ForegroundColor DarkGray
                } else {
                    Write-Host $parts[1].Trim() -ForegroundColor Cyan
                }
            } else {
                Write-Host "  $line" -ForegroundColor DarkGray
            }
        }
    } else {
        Write-Host "  [!] Configuration file not found!" -ForegroundColor Red
        Write-Host "  Expected location: $configFile" -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "Press any key to return..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ===============================================================================
# AUTO-START CONFIGURATION
# ===============================================================================

function Show-AutoStartSettings {
    Clear-Host
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "           AUTO-START SETTINGS                                  " -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""

    $serviceName = "WireGuardTunnel`$$($Script:SelectedTunnel)"
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

    if ($service) {
        $startType = $service.StartType

        Write-Host "  Current tunnel: " -NoNewline -ForegroundColor Gray
        Write-Host $Script:SelectedTunnel -ForegroundColor White
        Write-Host ""
        Write-Host "  Current startup type: " -NoNewline -ForegroundColor Gray

        $color = switch ($startType) {
            'Automatic' { 'Green' }
            'Manual' { 'Yellow' }
            'Disabled' { 'Red' }
            default { 'Gray' }
        }
        Write-Host $startType -ForegroundColor $color
        Write-Host ""
        Write-Host "  -----------------------------------------------" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  [1] Enable Auto-Start (Start with Windows)" -ForegroundColor Green
        Write-Host "  [2] Disable Auto-Start (Manual start only)" -ForegroundColor Yellow
        Write-Host "  [0] Back to main menu" -ForegroundColor Gray
        Write-Host ""

        $choice = Read-Host "Select option"

        switch ($choice) {
            "1" {
                try {
                    Set-Service -Name $serviceName -StartupType Automatic -ErrorAction Stop
                    Write-Host "`n  [+] Auto-start enabled successfully!" -ForegroundColor Green
                    Write-Log "Auto-start enabled for '$($Script:SelectedTunnel)'" -Level SUCCESS
                    Start-Sleep -Seconds 2
                } catch {
                    Write-Host "`n  [!] Failed to enable auto-start: $_" -ForegroundColor Red
                    Write-Log "Failed to enable auto-start: $_" -Level ERROR
                    Start-Sleep -Seconds 3
                }
            }
            "2" {
                try {
                    Set-Service -Name $serviceName -StartupType Manual -ErrorAction Stop
                    Write-Host "`n  [+] Auto-start disabled successfully!" -ForegroundColor Green
                    Write-Log "Auto-start disabled for '$($Script:SelectedTunnel)'" -Level SUCCESS
                    Start-Sleep -Seconds 2
                } catch {
                    Write-Host "`n  [!] Failed to disable auto-start: $_" -ForegroundColor Red
                    Write-Log "Failed to disable auto-start: $_" -Level ERROR
                    Start-Sleep -Seconds 3
                }
            }
        }
    } else {
        Write-Host "  [!] Service not found!" -ForegroundColor Red
        Start-Sleep -Seconds 2
    }
}

# ===============================================================================
# IMPORT & TUNNEL MANAGEMENT
# ===============================================================================

function Import-TunnelConfiguration {
    Clear-Host
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "           IMPORT TUNNEL CONFIGURATION                          " -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "  Import Methods:" -ForegroundColor Gray
    Write-Host "  -----------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [1] Browse for .conf file" -ForegroundColor White
    Write-Host "  [2] Import from folder (bulk import)" -ForegroundColor White
    Write-Host "  [3] Create new configuration manually" -ForegroundColor White
    Write-Host "  [0] Back to main menu" -ForegroundColor Gray
    Write-Host ""

    $choice = Read-Host "Select import method"

    switch ($choice) {
        "1" {
            Write-Host ""
            Write-Host "  [~] Enter full path to .conf file:" -ForegroundColor Yellow
            Write-Host "      Example: C:\Downloads\myclient.conf" -ForegroundColor DarkGray
            Write-Host ""
            $sourcePath = Read-Host "  Path"

            if (Test-Path $sourcePath) {
                try {
                    $fileName = [System.IO.Path]::GetFileName($sourcePath)
                    $destPath = Join-Path $Script:Config.ConfigPath $fileName

                    if (-not (Test-Path $Script:Config.ConfigPath)) {
                        New-Item -ItemType Directory -Path $Script:Config.ConfigPath -Force | Out-Null
                    }

                    Copy-Item -Path $sourcePath -Destination $destPath -Force
                    Write-Host ""
                    Write-Host "  [+] Configuration imported successfully!" -ForegroundColor Green
                    Write-Host "  [+] Location: $destPath" -ForegroundColor Cyan
                    Write-Host ""
                    Write-Host "  [i] To activate this tunnel, use WireGuard GUI or run:" -ForegroundColor Yellow
                    Write-Host "      wireguard.exe /installtunnelservice `"$destPath`"" -ForegroundColor DarkGray
                    Write-Log "Configuration imported: $fileName" -Level SUCCESS
                } catch {
                    Write-Host ""
                    Write-Host "  [!] Import failed: $_" -ForegroundColor Red
                    Write-Log "Failed to import configuration: $_" -Level ERROR
                }
            } else {
                Write-Host ""
                Write-Host "  [!] File not found: $sourcePath" -ForegroundColor Red
            }

            Write-Host ""
            Write-Host "Press any key to continue..." -ForegroundColor DarkGray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Import-TunnelConfiguration
        }
        "2" {
            Write-Host ""
            Write-Host "  [~] Enter folder path containing .conf files:" -ForegroundColor Yellow
            Write-Host "      Example: C:\Downloads\WireGuard-Configs" -ForegroundColor DarkGray
            Write-Host ""
            $folderPath = Read-Host "  Path"

            if (Test-Path $folderPath) {
                try {
                    $configs = Get-ChildItem -Path $folderPath -Filter "*.conf"

                    if ($configs.Count -eq 0) {
                        Write-Host ""
                        Write-Host "  [!] No .conf files found in folder" -ForegroundColor Red
                    } else {
                        Write-Host ""
                        Write-Host "  [~] Found $($configs.Count) configuration file(s)" -ForegroundColor Yellow
                        Write-Host ""

                        if (-not (Test-Path $Script:Config.ConfigPath)) {
                            New-Item -ItemType Directory -Path $Script:Config.ConfigPath -Force | Out-Null
                        }

                        $imported = 0
                        foreach ($config in $configs) {
                            try {
                                $destPath = Join-Path $Script:Config.ConfigPath $config.Name
                                Copy-Item -Path $config.FullName -Destination $destPath -Force
                                Write-Host "  [+] Imported: $($config.Name)" -ForegroundColor Green
                                $imported++
                            } catch {
                                Write-Host "  [!] Failed: $($config.Name) - $_" -ForegroundColor Red
                            }
                        }

                        Write-Host ""
                        Write-Host "  [+] Successfully imported $imported of $($configs.Count) configurations" -ForegroundColor Green
                        Write-Log "Bulk imported $imported configurations" -Level SUCCESS
                    }
                } catch {
                    Write-Host ""
                    Write-Host "  [!] Import failed: $_" -ForegroundColor Red
                    Write-Log "Bulk import failed: $_" -Level ERROR
                }
            } else {
                Write-Host ""
                Write-Host "  [!] Folder not found: $folderPath" -ForegroundColor Red
            }

            Write-Host ""
            Write-Host "Press any key to continue..." -ForegroundColor DarkGray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Import-TunnelConfiguration
        }
        "3" {
            Write-Host ""
            Write-Host "  [~] Creating new WireGuard configuration..." -ForegroundColor Yellow
            Write-Host ""

            $tunnelName = Read-Host "  Tunnel name (e.g., MyVPN)"

            if ($tunnelName) {
                Write-Host ""
                Write-Host "  [~] Enter configuration details (paste entire config):" -ForegroundColor Yellow
                Write-Host "      Press Enter twice when done" -ForegroundColor DarkGray
                Write-Host ""

                $configLines = @()
                do {
                    $line = Read-Host
                    if ($line) {
                        $configLines += $line
                    }
                } while ($line)

                if ($configLines.Count -gt 0) {
                    try {
                        $configPath = Join-Path $Script:Config.ConfigPath "$tunnelName.conf"

                        if (-not (Test-Path $Script:Config.ConfigPath)) {
                            New-Item -ItemType Directory -Path $Script:Config.ConfigPath -Force | Out-Null
                        }

                        $configLines | Out-File -FilePath $configPath -Encoding UTF8

                        Write-Host ""
                        Write-Host "  [+] Configuration created successfully!" -ForegroundColor Green
                        Write-Host "  [+] Location: $configPath" -ForegroundColor Cyan
                        Write-Log "Configuration created: $tunnelName.conf" -Level SUCCESS
                    } catch {
                        Write-Host ""
                        Write-Host "  [!] Failed to create configuration: $_" -ForegroundColor Red
                        Write-Log "Failed to create configuration: $_" -Level ERROR
                    }
                } else {
                    Write-Host ""
                    Write-Host "  [!] No configuration data provided" -ForegroundColor Red
                }
            }

            Write-Host ""
            Write-Host "Press any key to continue..." -ForegroundColor DarkGray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Import-TunnelConfiguration
        }
    }
}

function Show-TunnelManagement {
    Clear-Host
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "           TUNNEL MANAGEMENT                                    " -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""

    # Show installed services
    Write-Host "  [INSTALLED SERVICES]" -ForegroundColor Green
    Write-Host "  -----------------------------------------------" -ForegroundColor DarkGray

    $services = Get-Service -Name "WireGuardTunnel`$*" -ErrorAction SilentlyContinue
    if ($services.Count -eq 0) {
        Write-Host "  No tunnel services installed" -ForegroundColor Gray
    } else {
        foreach ($service in $services) {
            $tunnelName = $service.Name -replace 'WireGuardTunnel\$', ''
            $statusIcon = if ($service.Status -eq 'Running') { '[ON]' } else { '[OFF]' }
            $statusColor = if ($service.Status -eq 'Running') { 'Green' } else { 'Red' }
            Write-Host "  $statusIcon " -NoNewline -ForegroundColor $statusColor
            Write-Host "$tunnelName" -NoNewline -ForegroundColor White
            Write-Host " ($($service.Status))" -ForegroundColor Gray
        }
    }

    Write-Host ""
    Write-Host "  [CONFIGURATION FILES]" -ForegroundColor Yellow
    Write-Host "  -----------------------------------------------" -ForegroundColor DarkGray

    # Show configuration files
    if (Test-Path $Script:Config.ConfigPath) {
        $configs = Get-ChildItem -Path $Script:Config.ConfigPath -Filter "*.conf"
        if ($configs.Count -eq 0) {
            Write-Host "  No configuration files found" -ForegroundColor Gray
        } else {
            foreach ($config in $configs) {
                $tunnelName = $config.BaseName
                $hasService = $services | Where-Object { $_.Name -eq "WireGuardTunnel`$$tunnelName" }
                $icon = if ($hasService) { '[SVC]' } else { '[CFG]' }
                $color = if ($hasService) { 'Green' } else { 'Yellow' }
                Write-Host "  $icon " -NoNewline -ForegroundColor $color
                Write-Host "$tunnelName" -NoNewline -ForegroundColor White
                Write-Host " - $([math]::Round($config.Length/1KB, 2)) KB" -ForegroundColor DarkGray
            }
        }
    } else {
        Write-Host "  Configuration folder not found" -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "  -----------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [1] Import new tunnel" -ForegroundColor Cyan
    Write-Host "  [2] Delete tunnel configuration" -ForegroundColor Red
    Write-Host "  [3] Install tunnel service (activate config)" -ForegroundColor Green
    Write-Host "  [4] Uninstall tunnel service" -ForegroundColor Red
    Write-Host "  [5] Show configuration details" -ForegroundColor White
    Write-Host "  [0] Back to main menu" -ForegroundColor Gray
    Write-Host ""

    $choice = Read-Host "Select option"

    switch ($choice) {
        "1" {
            Import-TunnelConfiguration
            Show-TunnelManagement
        }
        "2" {
            Write-Host ""
            Write-Host "  [!] Enter tunnel name to delete:" -ForegroundColor Yellow
            $tunnelName = Read-Host "  Name"

            if ($tunnelName) {
                $configPath = Join-Path $Script:Config.ConfigPath "$tunnelName.conf"
                if (Test-Path $configPath) {
                    Write-Host ""
                    Write-Host "  [!] Delete $tunnelName.conf? (Y/N):" -NoNewline -ForegroundColor Red
                    $confirm = Read-Host
                    if ($confirm -eq "Y") {
                        try {
                            Remove-Item $configPath -Force
                            Write-Host "  [+] Configuration deleted" -ForegroundColor Green
                            Write-Log "Configuration deleted: $tunnelName.conf" -Level INFO
                        } catch {
                            Write-Host "  [!] Failed to delete: $_" -ForegroundColor Red
                        }
                    }
                } else {
                    Write-Host "  [!] Configuration not found: $tunnelName.conf" -ForegroundColor Red
                }
            }

            Start-Sleep -Seconds 2
            Show-TunnelManagement
        }
        "3" {
            Write-Host ""
            Write-Host "  [i] Use WireGuard GUI to install tunnel service," -ForegroundColor Yellow
            Write-Host "      or run in elevated CMD:" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "      wireguard.exe /installtunnelservice `"path\to\config.conf`"" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "Press any key to continue..." -ForegroundColor DarkGray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Show-TunnelManagement
        }
        "4" {
            Write-Host ""
            Write-Host "  [!] Enter tunnel name to uninstall service:" -ForegroundColor Yellow
            $tunnelName = Read-Host "  Name"

            if ($tunnelName) {
                $serviceName = "WireGuardTunnel`$$tunnelName"
                $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

                if ($service) {
                    Write-Host ""
                    Write-Host "  [!] Uninstall service for $tunnelName? (Y/N):" -NoNewline -ForegroundColor Red
                    $confirm = Read-Host
                    if ($confirm -eq "Y") {
                        Write-Host ""
                        Write-Host "  [i] Use WireGuard GUI or run in elevated CMD:" -ForegroundColor Yellow
                        Write-Host "      wireguard.exe /uninstalltunnelservice `"$tunnelName`"" -ForegroundColor Cyan
                    }
                } else {
                    Write-Host "  [!] Service not found: $serviceName" -ForegroundColor Red
                }
            }

            Write-Host ""
            Write-Host "Press any key to continue..." -ForegroundColor DarkGray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Show-TunnelManagement
        }
        "5" {
            Write-Host ""
            Write-Host "  [~] Enter tunnel name:" -ForegroundColor Yellow
            $tunnelName = Read-Host "  Name"

            if ($tunnelName) {
                $configPath = Join-Path $Script:Config.ConfigPath "$tunnelName.conf"
                if (Test-Path $configPath) {
                    Write-Host ""
                    Write-Host "  Configuration: $tunnelName.conf" -ForegroundColor Cyan
                    Write-Host "  -----------------------------------------------" -ForegroundColor DarkGray
                    Write-Host ""
                    $content = Get-Content $configPath
                    foreach ($line in $content) {
                        if ($line -match "PrivateKey|PresharedKey") {
                            $parts = $line -split "=", 2
                            Write-Host "  $($parts[0])= ***HIDDEN***" -ForegroundColor DarkGray
                        } else {
                            Write-Host "  $line" -ForegroundColor Gray
                        }
                    }
                } else {
                    Write-Host "  [!] Configuration not found" -ForegroundColor Red
                }
            }

            Write-Host ""
            Write-Host "Press any key to continue..." -ForegroundColor DarkGray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Show-TunnelManagement
        }
    }
}

# ===============================================================================
# BACKUP FUNCTIONALITY
# ===============================================================================

function Backup-Configurations {
    Clear-Host
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "           BACKUP CONFIGURATIONS                                " -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "[~] Creating backup..." -ForegroundColor Yellow

    try {
        if (-not (Test-Path $Script:Config.BackupPath)) {
            New-Item -ItemType Directory -Path $Script:Config.BackupPath -Force | Out-Null
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupFolder = Join-Path $Script:Config.BackupPath "WireGuard_Backup_$timestamp"
        New-Item -ItemType Directory -Path $backupFolder -Force | Out-Null

        if (Test-Path $Script:Config.ConfigPath) {
            $configs = Get-ChildItem -Path $Script:Config.ConfigPath -Filter "*.conf"

            Write-Host ""
            Write-Host "  Backing up configurations:" -ForegroundColor Gray

            foreach ($config in $configs) {
                Copy-Item -Path $config.FullName -Destination $backupFolder -Force
                Write-Host "  [+] $($config.Name)" -ForegroundColor Green
            }

            Write-Host ""
            Write-Host "  [+] Backup completed successfully!" -ForegroundColor Green
            Write-Host "  Location: $backupFolder" -ForegroundColor Cyan
            Write-Log "Configurations backed up to: $backupFolder" -Level SUCCESS

        } else {
            Write-Host "  [!] Configuration folder not found!" -ForegroundColor Red
        }

    } catch {
        Write-Host "  [!] Backup failed: $_" -ForegroundColor Red
        Write-Log "Backup failed: $_" -Level ERROR
    }

    Write-Host ""
    Write-Host "Press any key to return..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ===============================================================================
# MAIN APPLICATION LOOP
# ===============================================================================

Write-Log "WireGuard Manager started" -Level INFO

Select-Tunnel

do {
    Show-EnhancedMenu

    Write-Host "  Select option: " -NoNewline -ForegroundColor Gray
    $choice = Read-Host

    switch ($choice.ToUpper()) {
        "1" {
            Start-Tunnel -tunnelName $Script:SelectedTunnel
        }
        "2" {
            Stop-Tunnel -tunnelName $Script:SelectedTunnel
        }
        "3" {
            Restart-Tunnel -tunnelName $Script:SelectedTunnel
        }
        "4" {
            Select-Tunnel
        }
        "5" {
            Show-NetworkDiagnostics
        }
        "6" {
            Show-Configuration
        }
        "7" {
            Show-AutoStartSettings
        }
        "8" {
            Backup-Configurations
        }
        "9" {
            Show-AdvancedSettings
        }
        "I" {
            Show-TunnelManagement
        }
        "Q" {
            Invoke-QuickToggle
        }
        "S" {
            Write-Host "`n  Testing connection speed..." -ForegroundColor Yellow
            $speed = Test-ConnectionSpeed
            Write-Host "  Download Speed: $speed" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "Press any key to continue..." -ForegroundColor DarkGray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "H" {
            Show-ConnectionHistory
        }
        "L" {
            Show-Logs
        }
        "R" {
            # Refresh
        }
        "0" {
            Write-Host "`n  Goodbye!" -ForegroundColor Cyan
            Write-Log "WireGuard Manager exited" -Level INFO
            Start-Sleep -Seconds 1
            exit
        }
        default {
            Write-Host "`n  [!] Invalid choice. Please select a valid option." -ForegroundColor Red
            Start-Sleep -Seconds 2
        }
    }
} while ($choice -ne "0")
