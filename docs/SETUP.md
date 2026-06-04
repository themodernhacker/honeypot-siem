# Setup Guide — Honeypot SIEM Lab (Windows + Docker Desktop)

This guide is adapted for **Windows 11 + Docker Desktop**. Everything runs in
Docker — Wazuh (SIEM), Cowrie (SSH honeypot), and the log pipeline between them.
No Wazuh agent is installed on the host; the manager reads Cowrie's JSON log
through a shared volume, which keeps the whole lab reproducible from this repo.

> Run all commands from the repo root (the folder you cloned this repo into).
> Use **PowerShell**. Where a command differs from the original plan it's noted.

---

## Phase 0 — Prep

1. **Start Docker Desktop** and wait until it says *Engine running*.
2. Give Docker enough memory: **Settings → Resources → Memory ≥ 6 GB** (Wazuh's
   indexer is heavy). 8 GB is comfortable.
3. Verify:
   ```powershell
   docker --version
   docker compose version
   docker info --format '{{.ServerVersion}}'
   ```
   On Docker Desktop the `vm.max_map_count` kernel setting is already high
   enough inside the Docker VM, so the Linux `sysctl` step from the plan is
   **not needed**.

**Done when:** `docker info` returns a server version without errors.

---

## Phase 1 — Stand up Wazuh

```powershell
git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.0
cd wazuh-docker\single-node

# Generate the TLS certs the stack needs (one-time)
docker compose -f generate-indexer-certs.yml run --rm generator
```

Now wire in the honeypot **before** the first boot:

```powershell
# From wazuh-docker\single-node :
copy ..\..\wazuh\docker-compose.override.yml .\docker-compose.override.yml
```

Add the Cowrie log source to the manager config. Open
`config\wazuh_cluster\wazuh_manager.conf` and paste the `<localfile>` block from
[`wazuh/manager-localfile-snippet.xml`](../wazuh/manager-localfile-snippet.xml)
inside `<ossec_config>`.

Bring it all up:

```powershell
docker compose up -d
docker compose ps
```

> **Why custom rules are NOT bind-mounted.** `/var/ossec/etc` is a named volume
> that Wazuh only populates with its default config when the volume looks empty.
> Bind-mounting individual rule files into it makes Docker pre-create those
> directories, Wazuh then skips its default-config copy, and the manager fails
> to start (missing `etc/shared/ar.conf`). So we inject the rules *after* the
> stack is healthy instead — see below.

Wait until the manager is initialised (analysisd running), then load the custom
Cowrie rules. They land in the named volume and persist across restarts:

```powershell
# From the repo root:
pwsh wazuh\apply-custom-rules.ps1
```

- Wait ~2–3 min, then open **https://localhost** (port 443).
- Default creds are in the compose file (`admin` / `SecretPassword`) — **change
  them** before you make the repo public.
- 📸 **Screenshot** the empty dashboard → `screenshots/01-wazuh-dashboard.png`

**Done when:** You can log into the Wazuh dashboard and `docker compose ps`
shows `wazuh.manager`, `wazuh.indexer`, `wazuh.dashboard`, and `cowrie` healthy.

---

## Phase 2 — Verify Cowrie

Cowrie came up with the stack (it's in the override). Confirm it's logging:

```powershell
# From the repo root, in a new PowerShell window:
ssh -p 2222 root@localhost      # try a few fake passwords, e.g. 123456, admin, root
```

Check the JSON log appeared:

```powershell
Get-Content .\cowrie\log\cowrie.json -Tail 20
```

- 📸 **Screenshot** a captured login attempt → `screenshots/02-cowrie-json.png`

**Done when:** `cowrie.json` contains `cowrie.login.failed` events for your test.

---

## Phase 3 — Confirm the pipeline (Cowrie → Wazuh)

Our `local_rules.xml` and the manager `<localfile>` are already loaded. Validate
the rules parsed without error and that alerts flow:

```powershell
# Check the manager loaded our rules cleanly
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
# (paste a line from cowrie.json, Ctrl+C to exit)
```

Generate a few more logins, then in the dashboard go to **Threat Hunting /
Discover** and filter `rule.groups: cowrie`.

- 📸 **Screenshot** Cowrie alerts in Wazuh → `screenshots/03-alerts.png`

**Done when:** Cowrie events show up as Wazuh alerts tagged with `cowrie`.

> Troubleshooting: if no alerts, check `docker logs single-node-wazuh.manager-1`,
> confirm the localfile path, and that `cowrie/log/cowrie.json` is non-empty.
> Container names may differ — use `docker compose ps` to get exact names.

---

## Phase 4 — Generate attacks

See [`attack/README.md`](../attack/README.md). Run the controlled brute-force,
scan, and command-execution scripts against `localhost:2222`. This is **your**
honeypot on **your** machine — standard purple-team practice.

**Done when:** Wazuh shows alerts from the scan, brute-force (rule 100104), and
command activity (rules 100106–100108).

---

## Phase 5 — Detection engineering + MITRE

The rules already map to MITRE (see [`MITRE-MAPPING.md`](MITRE-MAPPING.md)).
Instead of building panels by hand, import the ready-made dashboard:

```powershell
curl -k -u admin:SecretPassword -H "osd-xsrf: true" `
  -X POST "https://localhost/api/saved_objects/_import?overwrite=true" `
  --form file=@wazuh\dashboard\cowrie-dashboard.ndjson
```

That loads the **"Honeypot SIEM - Cowrie overview"** dashboard with panels for
top source IPs, top usernames/passwords, commands run, alerts over time, and a
MITRE technique breakdown. See [`wazuh/dashboard/README.md`](../wazuh/dashboard/README.md)
for the UI import path and how to rebuild it. Screenshot each panel into
`screenshots/05-*.png`.

**Done when:** Each alert is tagged with a technique and the dashboard is built.

---

## Phase 6 — Document & ship

Fill in [`../README.md`](../README.md), add the architecture diagram, write the
attack write-ups in `docs/`, then make the GitHub repo public and pin it.

---

## Teardown

```powershell
cd wazuh-docker\single-node
docker compose down            # keep data
docker compose down -v         # wipe volumes (fresh start)
```
