# Detection-as-code tests

A tiny test suite for the detection rules themselves. It replays known Cowrie
events through the running Wazuh manager's `wazuh-logtest` and asserts that each
one fires the rule it is supposed to. Same idea as unit tests, but for
detections: after editing a regex or a threshold in
[`rules/local_rules.xml`](../rules/local_rules.xml), run this and find out
straight away whether you kept the detection working, instead of finding out live
during an incident.

Most portfolio projects stop at "the rule fired once in a screenshot." This turns
that into something you can re-run on every change.

## What it checks

[`test_detections.py`](test_detections.py) covers both kinds of rule:

- **Single-event pattern rules** (deterministic): new connection (100101), failed
  login (100102), successful login (100103), command executed (100106), recon
  command (100107), payload download (100108).
- **Stateful correlation rules**: it feeds a whole burst in one `wazuh-logtest`
  session so the frequency counters accumulate, then asserts the brute-force rule
  (100104), success-after-brute-force (100105), and rapid-connection (100110)
  fire.

The synthetic events use a TEST-NET-3 source address (`203.0.113.7`, RFC 5737) so
it is obvious at a glance that they are crafted fixtures, not captured traffic.

## Prerequisites

1. The lab stack is up: `docker compose up -d` in `wazuh-docker/single-node`.
2. The custom rules are loaded: `pwsh wazuh/apply-custom-rules.ps1`.
3. The manager container is running (default name `single-node-wazuh.manager-1`).

The runner does a preflight check for all three and prints exactly what to fix if
something is missing.

## Run it

```bash
python tests/test_detections.py
```

If your manager container has a different name:

```bash
python tests/test_detections.py --manager <container-name>
```

Expected output when the stack is healthy and the rules are loaded:

```
Detection tests against manager 'single-node-wazuh.manager-1'

  [PASS]  rule 100101  <-  new SSH connection
  [PASS]  rule 100102  <-  failed login
  ...
  10 passed, 0 failed, 10 total
```

Exit codes: `0` all passed, `1` an assertion failed (a detection regressed), `2`
could not reach the manager (stack not up, wrong container name, or rules not
loaded). The `2` case is deliberately separate from `1` so "the lab is not
running" never looks like "a detection broke."

## Notes

- Pure standard-library Python, no packages to install. It shells out to the
  `docker` CLI, so it runs the same on Windows PowerShell, macOS, and Linux.
- `wazuh-logtest` runs the real decode-and-rule pipeline, so a pass here means the
  rule genuinely fires in the manager, not just that a regex matches in isolation.
