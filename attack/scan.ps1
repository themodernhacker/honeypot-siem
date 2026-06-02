# Port scan / service probe against the local Cowrie honeypot.
# Uses nmap if available (richer, gives the T1046 / service-version evidence),
# otherwise falls back to PowerShell's Test-NetConnection.

param(
    [string]$TargetHost = "127.0.0.1",
    [int]$Port = 2222
)

$nmap = Get-Command nmap -ErrorAction SilentlyContinue
if ($nmap) {
    Write-Host "[*] nmap found - running service/version scan" -ForegroundColor Cyan
    & nmap -sV -p $Port $TargetHost
} else {
    Write-Host "[*] nmap not found - using Test-NetConnection" -ForegroundColor Yellow
    Write-Host "    (install nmap from https://nmap.org/download.html for -sV banner grabbing)"
    Test-NetConnection -ComputerName $TargetHost -Port $Port
}
