# Linux Syslog Analysis — SOC Fundamentals Project

**Author:** Hosni Nheri
**Skills demonstrated:** Linux log analysis, `grep`/`awk` command-line investigation, SSH brute-force detection, data-quality troubleshooting in security logs

## Objective

Analyze `/var/log/syslog` and `/var/log/auth.log` on a Linux system to detect suspicious authentication activity — the same first step a SOC analyst takes when investigating a potential intrusion.

## Setup

Sample logs (`auth.log`, `syslog`) simulating a small web server (`web01`) with mixed legitimate and malicious SSH traffic.

## 1. Filtering log entries

```bash
grep 'sshd' syslog                    # isolate all SSH-related events
grep 'Jun 12' syslog | grep 'sshd'    # narrow to a specific day
```

## 2. Reviewing authentication events

```bash
less auth.log
```

Two distinct patterns emerged:
- Legitimate logins from internal IPs (`192.168.1.0/24`) for known users (`hnheri`, `jdupont`, `mlemoine`)
- Repeated **failed logins for `root` and `admin`** from an external IP (`203.0.113.77`) — a classic brute-force signature
- **"Invalid user" attempts** (`oracle`, `test`) from a second external IP (`198.51.100.23`) — indicates account/username enumeration

## 3. Summarizing with `awk`

**Naive approach** (fixed column count):
```bash
awk '/sshd/ && /Failed password/ {print $11}' auth.log | sort | uniq -c | sort -nr
```
Output:
```
8 203.0.113.77
2 test
2 oracle
```

**⚠️ Finding — a real parsing gotcha:** When `sshd` logs an *invalid user* attempt, the message format shifts (`Failed password for invalid user oracle from ...` vs. `Failed password for root from ...`), inserting two extra words and shifting every fixed-position field. A naive `awk '{print $11}'` silently grabs the wrong column instead of the IP for those lines — it doesn't error, it just returns wrong data. This is a common trap in log parsing and a good reason SOC teams prefer structured logging (JSON, CEF) or field-aware tools like Splunk's SPL over raw positional `awk`.

**Corrected extraction:**
```bash
awk '/sshd/ && /Failed password/ {
  if ($0 ~ /invalid user/) print $13; else print $11
}' auth.log | sort | uniq -c | sort -nr
```
Output:
```
8 203.0.113.77
4 198.51.100.23
```

## 4. Successful logins per user

```bash
awk '/sshd/ && /Accepted password/ {print $9}' auth.log | sort | uniq -c | sort -nr
```
```
3 hnheri
1 mlemoine
1 jdupont
```
All successful logins trace back to internal, expected IPs — no anomaly here.

## Conclusion — Analyst Summary

| Indicator | Value | Verdict |
|---|---|---|
| Brute-force source | `203.0.113.77` | 8 failed attempts on `root`/`admin` → **block/alert** |
| Enumeration source | `198.51.100.23` | 4 failed attempts on non-existent users (`oracle`, `test`) → **block/alert** |
| Legitimate access | `192.168.1.0/24` | 5 successful logins, all internal, all known users → **no action** |

**Recommended next steps** (what a SOC analyst would do next):
1. Add both external IPs to a blocklist / firewall rule
2. Check whether `root` SSH login is disabled (`PermitRootLogin no` in `sshd_config`) — the brute-force target suggests it might not be
3. Set up a Splunk/SIEM alert rule for >5 failed SSH logins from the same IP within 5 minutes

## Tools used
`grep`, `awk`, `sort`, `uniq` — no external tools required, demonstrating that meaningful log analysis is possible with native Linux utilities before reaching for a SIEM.

---

## 5. Hands-on lab — Real brute force on Kali (attack → logs → detection)

> ⚠️ **Ethical note:** this attack was performed exclusively against a lab machine I own and control (localhost, isolated VirtualBox VM, NAT-only network). Never run `hydra` or similar tools against systems you don't own or don't have explicit written authorization to test — doing so against third-party systems is illegal.

To validate the methodology from the sections above on a real system, I used **Kali Linux as an attacker platform with Hydra**, targeting its own local SSH service, and analyzed the resulting logs the same way a SOC analyst would investigate a real intrusion.

### Lab setup

```bash
# Target: local SSH server on Kali
sudo service ssh start

# Weak password on the 'kali' account (deliberately weak for the lab)
sudo passwd kali        # chose: kali

# Small custom wordlist instead of rockyou.txt (14M passwords = too slow for a demo)
cat > ~/soc-lab/passwords.txt << 'EOF'
123456
password
admin
letmein
kali
EOF
```

> **Note on root:** the default `#PermitRootLogin prohibit-password` means root can't log in with a password — hydra would fail even with the right password. I attacked the `kali` account instead (Option: enable `PermitRootLogin yes` + `sudo passwd root` to simulate a more exposed target).

### The attack (hydra)

```bash
hydra -l kali -P ~/soc-lab/passwords.txt -t 4 ssh://127.0.0.1
```

Result — dictionary attack succeeded in ~5 seconds:

```
[22][ssh] host: 127.0.0.1   login: kali   password: kali
1 of 1 target successfully completed, 1 valid password found
```

### ⚠️ Gotcha #1 — `/var/log/auth.log` doesn't exist on modern Kali

Recent Kali releases (systemd) no longer ship rsyslog by default: authentication events go to the **systemd journal**, not a text file.

```bash
grep 'sshd' /var/log/auth.log
# grep: /var/log/auth.log: No such file or directory
```

**Gotcha #2 — `_COMM=sshd` returns nothing.** OpenSSH 9.8+ split the daemon: authentication events are now emitted by **`sshd-session`**, so the classic filter misses them:

```bash
journalctl _COMM=sshd --no-pager          # only "Server listening..." lines
journalctl _COMM=sshd-session --no-pager  # the actual auth events
```

### Observed events

```
Sep 28 11:37:57 Hosni sshd-session[65085]: Failed password for kali from 127.0.0.1 port 37106 ssh2
Sep 28 11:37:57 Hosni sshd-session[65084]: Failed password for kali from 127.0.0.1 port 37092 ssh2
Sep 28 11:37:57 Hosni sshd-session[65085]: Accepted password for kali from 127.0.0.1 port 37106 ssh2
Sep 28 11:37:57 Hosni sshd-session[65087]: Failed password for kali from 127.0.0.1 port 37130 ssh2
Sep 28 11:37:57 Hosni sshd-session[65086]: Failed password for kali from 127.0.0.1 port 37120 ssh2
```

### Detection analysis (awk over journalctl)

Same parsing logic as section 3, piped from the journal:

```bash
journalctl _COMM=sshd-session --no-pager \
  | grep 'Failed password' \
  | awk '{ if ($0 ~ /invalid user/) print $13; else print $11 }' \
  | sort | uniq -c | sort -nr
```
```
4 127.0.0.1
```

```bash
journalctl _COMM=sshd-session --no-pager | grep 'Accepted password' | awk '{print $9}'
```
```
kali
```

### Incident summary

| Indicator | Value | Verdict |
|---|---|---|
| Source | `127.0.0.1` (lab) | 4 failed attempts **within the same second** |
| Target account | `kali` | Dictionary attack (hydra signature: parallel ports, sub-second timing) |
| **Compromise** | ✅ password `kali` found and accepted | Weak password present in attacker wordlist |

The 1-second timeframe across multiple source ports is itself an IOC — no human types that fast; it's an automated tool.

### Lessons learned (extending section "Recommended next steps")

1. **Strong passwords defeat dictionary attacks** — a password absent from common wordlists makes hydra impractical.
2. **`PermitRootLogin no` works** — it neutralized root as a brute-force target before the attack even started.
3. **Rate-limiting helps**: reduce hydra's parallelism (`-t 4`) — sshd with `MaxAuthTries`/`fail2ban` would have banned the source IP.
4. **Know your logging pipeline**: on systemd systems the SOC must query `journalctl` (`_COMM=sshd-session` on OpenSSH ≥ 9.8), not assume `/var/log/auth.log` exists.
5. Detection rule that would have fired here: `>3 Failed password from same IP within 60s → alert`.

### Tools used (lab)
`hydra`, `journalctl`, `awk`, `sort`, `uniq` — attack simulation and detection on the same box, no external target involved.

---
**Hosni Nheri** — Telecommunications Engineering Student, ENET'Com Sfax
Certified: Splunk Certified Cybersecurity Defense Analyst (Splunk, 09/2026) · Cybersecurity Defense Analyst Career Path (Cisco Networking Academy, 09/2026) · CCNA: Switching, Routing and Wireless Essentials (Cisco Networking Academy, 05/2026) · Ethical Hacker (Cisco Networking Academy, 12/2025)
[LinkedIn](https://linkedin.com/in/hosni-nheri) · [GitHub](https://github.com/HosniNheri1)
