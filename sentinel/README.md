# Microsoft Sentinel + KQL

This folder mirrors the Wazuh detections in Microsoft Sentinel using KQL. The
idea is to take the same Cowrie honeypot data, send a sample into a free Sentinel
workspace, and write the same detections in the query language UK SOC teams
actually use day to day.

The KQL queries in [`kql/`](kql/) are one-to-one with the Wazuh rules:

| Query | Detects | MITRE | Wazuh rule |
|-------|---------|-------|:----------:|
| [01-brute-force.kql](kql/01-brute-force.kql) | 8+ failed logins from one IP | T1110 | 100104 |
| [02-success-after-bruteforce.kql](kql/02-success-after-bruteforce.kql) | login that works right after a failure burst | T1078 + T1110 | 100105 |
| [03-recon-commands.kql](kql/03-recon-commands.kql) | `uname` / `id` / `cat /etc/passwd` etc. | T1082 + T1033 | 100107 |
| [04-payload-download.kql](kql/04-payload-download.kql) | `wget` / `curl` of a remote file | T1105 | 100108 |
| [05-rapid-connections-scan.kql](kql/05-rapid-connections-scan.kql) | burst of connections from one IP | T1046 | 100110 |

## Free setup

Everything here fits in free tiers:

1. **Azure free account** at azure.microsoft.com/free (free credit, and Log
   Analytics has a free daily ingestion allowance).
2. Optional: a **Microsoft 365 Developer tenant** if you want a full E5 sandbox,
   but it is not required just to run a Log Analytics workspace.
3. In the Azure portal, create a **Log Analytics workspace** (any name, cheapest
   region). Onboarding Microsoft Sentinel onto that workspace is a single click
   under the Sentinel blade.

## Getting the data in

The Cowrie logs are plain JSON, so the quickest path is the Azure Monitor HTTP
Data Collector API:

1. In the workspace, open **Settings > Agents** and copy the **Workspace ID** and
   a **Primary key**.
2. Set them as environment variables (so they never end up in the repo):
   ```powershell
   setx WORKSPACE_ID  "<your-workspace-id>"
   setx WORKSPACE_KEY "<your-primary-key>"
   ```
   Reopen the terminal so the variables load.
3. Send a sample of the honeypot log:
   ```powershell
   python ingest_cowrie.py ..\cowrie\log\cowrie.json --limit 500
   ```
4. Wait a few minutes, then in Sentinel open **Logs** and run `Cowrie_CL` to see
   the rows. Now paste any query from `kql/` and run it.

The custom table is called `Cowrie_CL`, and the HTTP Data Collector API suffixes
fields by type, so `eventid` becomes `eventid_s`, `src_ip` becomes `src_ip_s`,
and so on. The queries already use those names.

> Heads up: Microsoft is moving ingestion to the newer Logs Ingestion API, which
> uses Data Collection Rules and lets you keep your own column names. The HTTP
> Data Collector API still works and is the simplest option for a lab like this.
> If you use the newer API, drop the `_s` suffixes from the column names.

## Turning a query into an alert

In Sentinel, open **Analytics > Create > Scheduled query rule**, paste a query,
set how often it runs and the threshold, and map it to the MITRE technique from
the table above. That gives you a real Sentinel analytics rule, which is exactly
what the "Microsoft Sentinel, KQL" line on a CV is pointing at.

## What is manual

Creating the Azure account, the workspace, onboarding Sentinel, running the
ingestion, and screenshotting the KQL hits all happen in your own tenant. The
code and queries here are everything that can be prepared up front.
