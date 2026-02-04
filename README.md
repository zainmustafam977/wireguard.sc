# WireGuard Tunnel Manager (Ultimate) - Windows

Enhanced WireGuard Tunnel Manager for Windows 11 — a user-friendly PowerShell script (wg.ps1) to manage WireGuard tunnels with multi-tunnel support, auto-reconnect, diagnostics, notifications, speed tests, connection history, backups, and advanced settings.

## Repository description

Wireguard Script for managing the wireguard application on widnows, Practically for the standard user with the elevating permission assess.

(Recommended short description for GitHub repository metadata)

"WireGuard Tunnel Manager for Windows — PowerShell script to manage WireGuard tunnels with auto-reconnect, diagnostics, notifications, backups, and advanced controls."

## Features

- Multi-tunnel discovery and selection
- Start / Stop / Restart and Quick Toggle actions
- Auto-reconnect support and configurable health checks
- Connection history and persistent logging
- Network diagnostics (public IP, tunnel IP, DNS, latency)
- Data transfer statistics per tunnel
- Speed test (download)
- Toast-style notifications (Windows Forms fallback)
- Backup and import/export of .conf files
- Auto-start (service) configuration helpers
- Diagnostic report export
- Safe viewing of configuration files (sensitive keys hidden)

## Requirements

- Windows 10/11 (script optimized for Windows 11)
- PowerShell 5.1 or later
- WireGuard for Windows installed (wireguard.exe)
- Elevated permissions (run as Administrator)

## Installation

1. Clone the repository:

   git clone https://github.com/zainmustafam977/wireguard.sc.git

2. Open an elevated PowerShell prompt (Run as Administrator).

3. Execute the script:

   powershell -NoProfile -ExecutionPolicy Bypass -File .\wg.ps1

Notes:
- The script requests elevation if run without admin rights.
- Tunnel services are named like `WireGuardTunnel$<TunnelName>` by WireGuard.
- To install/uninstall a tunnel service manually, use `wireguard.exe /installtunnelservice "C:\path\to\config.conf"` and `/uninstalltunnelservice "<TunnelName>".

## Usage

- Run the script and follow the interactive menu.
- Select a tunnel to view status, uptime, IPs, and perform actions.
- Use the Tunnel Management menu to import, create or delete configuration files.
- View logs and export a diagnostic report to help troubleshooting.

## Configuration

The script exposes a configuration object near the top of `wg.ps1`:

- LogPath: Path to the application log file
- ConfigPath: Folder where WireGuard `.conf` files are stored
- BackupPath: Where configuration backups are saved
- AutoReconnect: Enable/disable automatic reconnect attempts
- HealthCheckInterval: Seconds between health checks
- NotificationsEnabled: Enable/disable toast notifications
- KillSwitchEnabled: Placeholder for kill-switch behavior (disabled by default)
- AutoReconnectAttempts: Number of reconnect attempts
- ConnectionHistoryPath: Path to store connection history JSON

Edit these values directly in the script or extend the script to load a user configuration file.

## Security & Privacy

- The script hides `PrivateKey` and `PresharedKey` fields when displaying configuration files.
- Always keep your `.conf` files and private keys secure.
- Consider filesystem permissions for the `ConfigPath` and backup locations.

## Troubleshooting

- If no tunnels are discovered, ensure your `.conf` files exist in `%USERPROFILE%\AppData\Local\WireGuard\Configurations` or update `ConfigPath`.
- If the script fails to start a service, verify WireGuard is installed and you have administrative privileges.
- For connectivity issues, run the Network Diagnostics and export a Diagnostic Report (`Export-DiagnosticReport`).

## Contribution

Contributions, issues and feature requests are welcome.

Please open an issue or submit a pull request with a clear description and minimal reproducible steps.

Coding style and tests:
- Keep PowerShell functions small and single-purpose.
- Add unit-like tests where possible using Pester for PowerShell.

## Suggested repository metadata (for owner to set on GitHub)

- Topics / Keywords: wireguard, vpn, vpn-manager, powershell, windows, wireguard-windows, vpn-tool, network-tools, diagnostics, automation
- Default branch: main
- License: MIT
- Primary language: PowerShell
- Homepage: https://github.com/zainmustafam977/wireguard.sc
- Maintainer: zainmustafam977

## Example README badges (optional)

- Build / CI: (add your CI badge if you set up workflow)
- License: MIT

## License

This repository is provided under the MIT License. See LICENSE file for details.

## Author / Maintainer

- zainmustafam977 — Primary maintainer
