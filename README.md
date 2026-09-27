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
*This project is based on the "Log Analysis Projects for Beginners" curriculum by [0xrajneesh](https://github.com/0xrajneesh/Log-Analysis-Projects-for-Beginners).*
