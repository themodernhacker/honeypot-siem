# Write-up: SSH Brute Force → Account Compromise

> Template write-up. Replace the _[screenshot]_ placeholders and the example IP
> with your real captured data after running Phase 4. Aim for ~1 page.

## Summary

An attacker (here, my own `brute_force.py` against the lab) repeatedly attempts
to log into the SSH honeypot, fails many times, then succeeds with a guessed
credential — the classic credential-access → initial-access chain.

## The telemetry

Cowrie logged the attempt as JSON. Representative failed-login event:

```json
{"eventid":"cowrie.login.failed","username":"root","password":"123456",
 "src_ip":"172.18.0.1","message":"login attempt [root/123456] failed", ...}
```

_[screenshot: cowrie.json failures]_

## The detection

Wazuh's frequency rule correlates the burst:

```xml
<rule id="100104" level="10" frequency="8" timeframe="120">
  <if_matched_sid>100102</if_matched_sid>
  <same_source_ip />
  <description>Cowrie: SSH brute-force — 8+ failed logins from $(src_ip) in 120s.</description>
  <mitre><id>T1110</id></mitre>
</rule>
```

When a login then succeeds from the same IP, rule **100105** escalates it to a
level-12 "valid-account compromise" alert (T1078 + T1110).

_[screenshot: Wazuh alert 100104 + 100105 with MITRE tags]_

## MITRE ATT&CK

- **T1110 — Brute Force** (Credential Access)
- **T1078 — Valid Accounts** (Initial Access)

## What a real analyst would do next

1. Confirm whether the source IP is internal or external; check threat intel.
2. Determine if the targeted account exists on real assets and whether the
   guessed password is in use anywhere → force a reset.
3. Hunt for the same source IP across other logs (lateral movement, VPN, web).
4. Recommend controls: rate-limiting / fail2ban, key-only SSH, MFA, and a
   detection for "success immediately after N failures" (exactly rule 100105).
