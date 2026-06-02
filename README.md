# Honeypot SIEM — Purple-Team Detection Lab

A self-contained purple-team lab that runs an **SSH honeypot (Cowrie)**, ships
its events into a **SIEM (Wazuh)**, and detects simulated attacks with custom
detection rules **mapped to MITRE ATT&CK**. Built end-to-end in Docker on a
single machine — attack it, detect it, document it.

> **Stack:** Wazuh 4.9 (SIEM) · Cowrie (SSH honeypot) · Docker Compose · Python
> (paramiko) attacker · MITRE ATT&CK

![Architecture](docs/architecture.png) <!-- add a draw.io export here -->

---

## What this demonstrates

- **Detection engineering** — 11 custom Wazuh rules with frequency-based
  correlation (brute force, post-brute-force compromise), in version control:
  [`rules/local_rules.xml`](rules/local_rules.xml)
- **MITRE ATT&CK mapping** — every alert tagged to a technique:
  [`docs/MITRE-MAPPING.md`](docs/MITRE-MAPPING.md)
- **Log pipeline design** — Cowrie JSON → Wazuh manager via a shared volume,
  no host agent, fully reproducible from this repo
- **Purple-team workflow** — scripted, controlled attacks and the analysis of
  the resulting alerts: [`attack/`](attack/)

---

## Architecture

```
┌────────────┐   SSH :2222    ┌─────────────┐   cowrie.json   ┌──────────────────┐
│  Attacker  │ ─────────────► │   Cowrie    │ ──────────────► │  Wazuh Manager   │
│ (scripts/  │  brute-force,  │  honeypot   │  (shared vol)   │  decoders+rules  │
│  nmap/ssh) │  recon, wget   │  (Docker)   │                 │  MITRE tagging   │
└────────────┘                └─────────────┘                 └────────┬─────────┘
                                                                        │
                                                              ┌─────────▼─────────┐
                                                              │ Wazuh Indexer +   │
                                                              │ Dashboard (:443)  │
                                                              └───────────────────┘
```

## Quick start

Full instructions: [`docs/SETUP.md`](docs/SETUP.md). In short (Windows + Docker
Desktop, from the repo root):

```powershell
git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.0
cd wazuh-docker\single-node
docker compose -f generate-indexer-certs.yml run --rm generator
copy ..\..\wazuh\docker-compose.override.yml .\docker-compose.override.yml
# add the <localfile> block from wazuh/manager-localfile-snippet.xml to
#   config\wazuh_cluster\wazuh_manager.conf
docker compose up -d
pwsh ..\..\wazuh\apply-custom-rules.ps1   # inject custom rules once stack is healthy
# open https://localhost  (change the default admin password!)
```

Then run the attacks:

```powershell
cd ..\..\attack
pip install paramiko
.\scan.ps1
python brute_force.py
python run_session.py
```

---

## Detections & MITRE coverage

| Detection | ATT&CK | Rule |
|-----------|--------|:----:|
| SSH brute force (8+ fails/120s, one source) | T1110 | 100104 |
| Successful login after brute force | T1078 + T1110 | 100105 |
| Remote payload download (`wget`/`curl`) | T1105 | 100108/109 |
| Recon commands (`uname`,`id`,…) | T1082 + T1033 | 100107 |
| Rapid connections / automation | T1046 | 100110 |
| Tunnel/proxy via honeypot | T1090 | 100111 |

Full table: [`docs/MITRE-MAPPING.md`](docs/MITRE-MAPPING.md).

---

## Screenshots

| | |
|---|---|
| Wazuh dashboard | ![](screenshots/01-wazuh-dashboard.png) |
| Cowrie JSON capture | ![](screenshots/02-cowrie-json.png) |
| MITRE-tagged alerts | ![](screenshots/03-alerts.png) |

---

## Write-ups

Attack-by-attack analysis (log → rule that caught it → MITRE technique → what an
analyst does next) lives in [`docs/`](docs):

- [Brute force into an account takeover](docs/writeup-brute-force.md)
- [Looking around after getting in](docs/writeup-recon.md)
- [Pulling down a second stage](docs/writeup-payload-download.md)

---

## What I learned

Real engineering problems I hit and solved while building this (not theory):

- **Wazuh correlation uses specific field names.** `<same_source_ip/>` only works
  on Wazuh's built-in `srcip` field. Cowrie's JSON decodes the address as the
  dynamic field `src_ip`, so my brute-force correlation silently never fired
  until I switched to `<same_field>src_ip</same_field>`. Lesson: verify which
  field your correlation actually keys on.
- **Bind-mounting into a Docker named volume can break app init.** Mounting rule
  files into `/var/ossec/etc` made Wazuh think the volume was already populated
  and skip copying its default config, so the manager wouldn't start. Fixed by
  injecting rules *after* first boot via `docker cp` (see `apply-custom-rules.ps1`).
- **Honeypot detection has blind spots.** Cowrie only exposes port 2222, so a
  port-scan (T1046) leaves weak evidence on the honeypot itself — the strong
  signal is on the attacker/network side. I represented this honestly rather
  than overstating coverage.
- **Config encoding matters.** Cowrie reads `userdb.txt` as ASCII and crashed on
  a single non-ASCII dash in a comment, which broke all authentication. Small
  byte, big outage — exactly the kind of thing real detection pipelines hit.
- Mapping each detection to MITRE ATT&CK turns a pile of alerts into a readable
  attack story (recon → brute force → compromise → discovery → tool transfer).

---

## Repo layout

```
rules/      custom Wazuh decoders + detection rules (the core artifact)
cowrie/     honeypot config (cowrie.cfg, userdb.txt) + logs (gitignored)
wazuh/      compose override + manager config snippet
attack/     controlled attack scripts (brute force, session, scan)
docs/       setup guide, MITRE mapping, attack write-ups
screenshots/ evidence for the README
```

---

_Lab for educational/defensive security use against my own infrastructure only._
