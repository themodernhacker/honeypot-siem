#!/usr/bin/env python3
r"""
Push a sample of Cowrie honeypot logs into a Microsoft Sentinel (Log Analytics)
workspace, so the KQL detections in kql/ have data to run against.

This uses the Azure Monitor HTTP Data Collector API, which is the simplest way
to get a custom log into a free-tier workspace. It creates (or appends to) a
custom table named  Cowrie_CL  and type-suffixes the fields (eventid_s, src_ip_s).

Credentials are read from environment variables and are NEVER hard-coded:
    WORKSPACE_ID   - the Log Analytics workspace ID (a GUID)
    WORKSPACE_KEY  - the workspace primary or secondary key

Usage:
    setx WORKSPACE_ID  "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"   (then reopen shell)
    setx WORKSPACE_KEY "your-primary-key"
    python ingest_cowrie.py ..\cowrie\log\cowrie.json --limit 500

Note: Microsoft is moving to the newer Logs Ingestion API (DCR based). The HTTP
Data Collector API still works and is fine for a lab; see README.md.
"""
import argparse
import base64
import datetime
import hashlib
import hmac
import json
import os
import ssl
import sys
import urllib.request

LOG_TYPE = "Cowrie"
API_VERSION = "2016-04-01"

# Some Python builds (e.g. msys2/mingw) ship without a usable CA bundle, which
# makes HTTPS verification fail. Prefer certifi's bundle when it is installed.
try:
    import certifi
    _SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())
except Exception:
    _SSL_CONTEXT = ssl.create_default_context()


def build_signature(workspace_id, key, date, content_length):
    x_headers = f"x-ms-date:{date}"
    string_to_hash = f"POST\n{content_length}\napplication/json\n{x_headers}\n/api/logs"
    decoded_key = base64.b64decode(key)
    digest = hmac.new(decoded_key, string_to_hash.encode("utf-8"), hashlib.sha256).digest()
    encoded = base64.b64encode(digest).decode("utf-8")
    return f"SharedKey {workspace_id}:{encoded}"


def post(workspace_id, key, body_bytes):
    date = datetime.datetime.now(datetime.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    signature = build_signature(workspace_id, key, date, len(body_bytes))
    url = f"https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version={API_VERSION}"
    req = urllib.request.Request(url, data=body_bytes, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", signature)
    req.add_header("Log-Type", LOG_TYPE)
    req.add_header("x-ms-date", date)
    req.add_header("time-generated-field", "timestamp")
    with urllib.request.urlopen(req, timeout=30, context=_SSL_CONTEXT) as resp:
        return resp.status


def main():
    ap = argparse.ArgumentParser(description="Send Cowrie JSON logs to a Sentinel workspace.")
    ap.add_argument("logfile", help="path to cowrie.json")
    ap.add_argument("--limit", type=int, default=500, help="max recent events to send")
    args = ap.parse_args()

    workspace_id = os.environ.get("WORKSPACE_ID")
    workspace_key = os.environ.get("WORKSPACE_KEY")
    if not workspace_id or not workspace_key:
        sys.exit("Set WORKSPACE_ID and WORKSPACE_KEY environment variables first.")

    records = []
    with open(args.logfile, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    records = records[-args.limit:]
    if not records:
        sys.exit("No JSON records found to send.")

    body = json.dumps(records).encode("utf-8")
    status = post(workspace_id, workspace_key, body)
    if status == 200:
        print(f"Sent {len(records)} events to table Cowrie_CL. "
              "It can take a few minutes to appear in the workspace.")
    else:
        sys.exit(f"Ingestion failed with HTTP {status}")


if __name__ == "__main__":
    main()
