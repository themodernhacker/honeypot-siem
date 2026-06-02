# apply-custom-rules.ps1
# =======================
# Injects the lab's custom Cowrie decoders + detection rules into the running
# Wazuh manager, then restarts it so they load. Run this ONCE after the stack
# is up and healthy. The files land in the manager's named volume (/var/ossec/etc),
# so they persist across `docker compose restart` and `up -d` — you only need to
# re-run this after `docker compose down -v` (which wipes volumes).
#
# Why a script instead of a bind mount? Bind-mounting files into /var/ossec/etc
# stops Wazuh from initialising its default config on first boot. Copying them in
# afterwards avoids that entirely.
#
# Usage (from repo root, after `docker compose up -d` in wazuh-docker/single-node):
#   pwsh wazuh\apply-custom-rules.ps1

param(
    [string]$Manager = "single-node-wazuh.manager-1"
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot   # repo root (parent of wazuh/)

Write-Host "[*] Copying custom rules + decoder into $Manager ..." -ForegroundColor Cyan
docker cp "$repo\rules\local_rules.xml"   "${Manager}:/var/ossec/etc/rules/local_rules.xml"
docker cp "$repo\rules\local_decoder.xml" "${Manager}:/var/ossec/etc/decoders/local_decoder.xml"

Write-Host "[*] Fixing ownership..." -ForegroundColor Cyan
docker exec $Manager chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/decoders/local_decoder.xml

Write-Host "[*] Verifying rules parse cleanly (wazuh-logtest sanity)..." -ForegroundColor Cyan
docker exec $Manager /var/ossec/bin/wazuh-control restart

Write-Host "[+] Done. Custom Cowrie rules loaded. Generate some honeypot traffic and" -ForegroundColor Green
Write-Host "    check Wazuh -> Threat Hunting, filter  rule.groups: cowrie" -ForegroundColor Green
