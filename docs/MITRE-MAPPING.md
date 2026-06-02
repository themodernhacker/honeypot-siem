# MITRE ATT&CK Mapping

Every detection rule in [`rules/local_rules.xml`](../rules/local_rules.xml) is
tagged with the MITRE ATT&CK technique it represents. This table is the
"detection-engineering portfolio" view of the lab.

| Rule ID | Detection                                   | ATT&CK Technique | Tactic                | Level |
|--------:|---------------------------------------------|------------------|-----------------------|:-----:|
| 100101  | New connection to SSH honeypot              | T1021.004 — Remote Services: SSH | Lateral Movement | 3 |
| 100102  | Failed SSH login                            | T1110 — Brute Force | Credential Access  | 5 |
| 100103  | Successful SSH login                         | T1078 — Valid Accounts | Initial Access  | 6 |
| 100104  | 8+ failed logins from one IP in 120s        | T1110 — Brute Force | Credential Access  | 10 |
| 100105  | Successful login *after* brute force         | T1078 + T1110 | Initial Access / Cred. Access | 12 |
| 100106  | Command executed in honeypot session         | T1059.004 — Unix Shell | Execution      | 5 |
| 100107  | Recon command (`uname`,`id`,`whoami`,…)      | T1082 + T1033 | Discovery             | 8 |
| 100108  | Payload download command (`wget`/`curl`/…)   | T1105 — Ingress Tool Transfer | Command & Control | 10 |
| 100109  | File actually downloaded into honeypot       | T1105 — Ingress Tool Transfer | Command & Control | 10 |
| 100110  | 12+ rapid connections in 60s (automation)    | T1046 — Network Service Discovery | Discovery   | 7 |
| 100111  | Tunnel/proxy attempt through honeypot        | T1090 — Proxy | Command & Control     | 9 |

## Attack-chain story

A realistic Cowrie session walks the ATT&CK kill chain end-to-end:

1. **T1046 / T1021.004** — attacker scans and connects to SSH (100110, 100101).
2. **T1110** — they brute-force credentials; the frequency rule fires (100104).
3. **T1078** — a guessed credential succeeds; success-after-brute-force fires (100105).
4. **T1059.004** — they drop into a shell and run commands (100106).
5. **T1082 / T1033** — recon to understand the host (100107).
6. **T1105** — they pull down a second-stage payload (100108 / 100109).

> Note on T1046: Cowrie only exposes port 2222, so the strongest network-scan
> evidence lives in the attacker-side `nmap` output and the rapid-connection
> rule (100110), not in a multi-port signature. This is called out honestly in
> the write-ups rather than overstated.
