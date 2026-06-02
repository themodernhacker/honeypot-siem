# Cowrie dashboard

`cowrie-dashboard.ndjson` is a saved-objects bundle for Wazuh (OpenSearch
Dashboards). Importing it gives you a ready-made dashboard called
**"Honeypot SIEM - Cowrie overview"** with seven panels:

- Alerts over time
- Top source IPs
- Alerts by MITRE technique
- Top usernames tried
- Top passwords tried
- Commands run
- Top detection rules

Every panel is scoped to `rule.groups: cowrie`.

## Import (UI)

1. Open the Wazuh dashboard at https://localhost
2. Menu, then Dashboards Management, then Saved Objects
3. Click Import, choose `cowrie-dashboard.ndjson`, allow overwrite
4. Open the dashboard from the Dashboards app. If you see no data, widen the
   time picker (top right) to cover when you ran the attacks.

## Import (API)

```powershell
curl -k -u admin:SecretPassword -H "osd-xsrf: true" `
  -X POST "https://localhost/api/saved_objects/_import?overwrite=true" `
  --form file=@cowrie-dashboard.ndjson
```

## Rebuilding

The bundle is generated, not hand-written. If you add fields or panels, edit
`build_saved_objects.py` and run it again:

```powershell
python build_saved_objects.py
```

It assumes the alerts index pattern id is `wazuh-alerts-*`, which is the default
in a single-node Wazuh install.
