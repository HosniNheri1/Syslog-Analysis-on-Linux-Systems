# Linux Syslog Analysis — SOC Fundamentals Project

**Author:** Hosni Nheri
**Skills demonstrated:** Linux log analysis, `grep`/`awk` command-line investigation, SSH brute-force detection, data-quality troubleshooting in security logs, Splunk Enterprise (SPL, alerting), SOAR automation with Shuffle (multi-source enrichment, conditional logic, notification), Docker/Swarm troubleshooting, disk/partition management

[View the portfolio][https://github.com/HosniNheri1/SSH Brute-Force Detection & SOAR Response.html
](https://hosninheri1.github.io/SSH Brute-Force Detection & SOAR Response.html)
/)

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

## 6. From detection to automated response — Splunk Enterprise + Shuffle SOAR

> Building on sections 1–5 (grep/awk analysis, then real hydra attack + journalctl detection), this section moves the same detection logic into a SIEM (Splunk Enterprise) and wires it to a SOAR platform (Shuffle, cloud instance) for automated enrichment.

### 6.1 Architecture

```
Kali VM: hydra SSH brute force
        │
        ▼
auth.log ingested into Splunk Enterprise
        │
        ▼
Splunk saved search (SPL) ──► Alert (threshold-based)
        │
        ▼  webhook
Shuffle workflow (shuffler.io, cloud)
        │
        ▼
Http node → AbuseIPDB v2 /check → IP reputation (abuseConfidenceScore)
```

### 6.2 Detection logic in Splunk (SPL)

Ingested `auth.log`. Reproducing the same brute-force detection built with `awk` in section 3, now in SPL:

```spl
index=main sourcetype=linux_secure "Failed password"
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| where count > 5
```

Tested against the lab's `auth.log`: 8 failed-password events, correctly grouped under `src_ip`, satisfying the `count > 5` threshold.

### 6.3 Alert configuration

- Name: `SSH Brute Force Detection`
- Type: Scheduled (cron)
- Trigger condition: `Number of Results > 0`
- Trigger action: **Webhook** → Shuffle workflow URL (`https://shuffler.io/api/v1/hooks/webhook_...`)
- Payload includes `search_name`, `src_ip`, and `count` from the search results, confirmed via Splunk's own alert fields (`$exec.result.src_ip`, `$exec.result.count` in Shuffle)

### 6.4 Shuffle SOAR workflow

1. **Webhook trigger** receives the Splunk alert payload — confirmed working via Splunk's **Run** action and the triggered-alert payload showing up in Shuffle's execution log
2. **Http node** → calls AbuseIPDB's v2 API directly:
   ```
   GET https://api.abuseipdb.com/api/v2/check?ipAddress=$exec.result.src_ip
   Headers: Key: <api_key>, Accept: application/json
   ```
3. Response returns `abuseConfidenceScore`, `countryCode`, `isp`, `totalReports`, etc. for the reported IP

**Note on infrastructure:** the workflow runs on Shuffle's cloud offering (shuffler.io) rather than a self-hosted instance. A self-hosted Shuffle stack (Docker Swarm + Orborus worker) was attempted first; it required `docker swarm init` and a dedicated `shuffle_swarm_executions` network to dispatch worker containers, and was abandoned in favor of the managed cloud service to keep focus on the detection/enrichment logic rather than container orchestration.

### 6.5 End-to-end test

Validation chain, confirmed working:

- Splunk: search returns 8 results for `203.0.113.77` (`count > 5` satisfied); alert fires via manual **Run** and via scheduled cron
- Shuffle: execution shows `"status": "FINISHED"`, `"location": "Cloud"`, webhook payload correctly parsed (`src_ip`, `count`)
- AbuseIPDB call: `"status": 200`, `"success": true`

**Test note on private vs. public IPs:** a first test used a private/internal IP (`192.168.56.101`), which AbuseIPDB cannot score (`abuseConfidenceScore: 0`, `isPublic: false`) — expected behavior, not a bug. To validate a non-zero score, synthetic log lines using a known public IP were injected via `logger`:
```bash
for i in {1..10}; do
  sudo logger -p auth.warning -t sshd "Failed password for invalid user attacker from 118.25.6.39 port $((40000+i)) ssh2"
done
```
This produced a real `abuseConfidenceScore` from AbuseIPDB, confirming the enrichment logic works correctly against a genuinely reported IP.

### 6.6 Troubleshooting log — real gotchas hit along the way

In the same spirit as the `journalctl`/`sshd-session` gotchas in section 5, here's what actually broke during setup, consistent with this project's theme of documenting real parsing/ops traps rather than hiding them:

- **Disk space**: Splunk refused to start after running out of disk on the lab VM. Root cause: the swap partition sat between the root partition and free disk space, blocking `growpart` from extending root. Fixed by deleting the swap partition (`fdisk`), extending the root partition (`growpart` + `resize2fs`), and recreating swap as a file (`fallocate`/`mkswap`/`swapon`) instead of a partition.
- **Self-hosted Shuffle / Orborus**: worker containers failed to dispatch with `network shuffle_swarm_executions not found`, then `Swarm init issue: ... advertise address ... not recognized` — caused by the lab VM having two active network interfaces (NAT `eth0` + host-only `eth1`), which broke Orborus's automatic address detection. Resolved by running `docker swarm init --advertise-addr <eth0 IP>` explicitly. Ultimately moved to Shuffle's cloud offering to avoid further infra debugging and focus on the SOC workflow itself.
- **AbuseIPDB endpoint**: the app's default action pointed at a deprecated/incorrect endpoint (`www.abuseipdb.com/check/.../json`, API v1-style), returning `401`/timeout errors. Fixed by using a generic **Http** node pointed directly at the documented v2 endpoint (`https://api.abuseipdb.com/api/v2/check`) with the API key passed as a `Key:` header.
- **API key hygiene**: the AbuseIPDB key was pasted in plaintext during troubleshooting screenshots and was regenerated afterward as a precaution — a reminder that lab screenshots meant for documentation should have secrets redacted before sharing, not after.

### 6.7 Multi-source enrichment and conditional response

Building on the working AbuseIPDB enrichment (6.4), the workflow was extended with a second enrichment source and a conditional, human-reviewable response branch:

```
[Http 1 — AbuseIPDB] ──► [Email 1]            (analyst notification)
      │
      └─► [virustotal]
            │
            └──► [firewall-sim]               (dry-run firewall action)
```

**VirusTotal enrichment** — a second Http node queries VirusTotal's IP report:
```
GET https://www.virustotal.com/api/v3/ip_addresses/$exec.result.src_ip
Headers: x-apikey: <api_key>
```
Returns `attributes.last_analysis_stats.malicious` (number of security vendors flagging the IP), `attributes.country`, `attributes.as_owner`, `attributes.tags`.

**Conditional branch** — a condition on the edge between `Http 1` (AbuseIPDB) and the downstream nodes:
```
$http_1.body.data.abuseConfidenceScore > 50
```
Only IPs above this threshold proceed to notification and the firewall simulation, keeping low-confidence results out of the analyst's inbox.

**Analyst notification (Email)** — sends a formatted summary (IP, attempt count, AbuseIPDB score, VirusTotal detections) for human review, rather than relying on a single automated signal.

**Firewall simulation (dry-run)** — rather than executing a real `iptables` block, a `firewall-sim` Http POST node sends a structured dry-run report to a Discord webhook, keeping remediation observable and reversible instead of live and irreversible:
```
🔒 ACTION FIREWALL (DRY-RUN)
IP : 185.220.101.1
Tentatives : 20
AbuseIPDB : 100/100
Pays : DE
AS Owner : Stiftung Erneuerbare Freiheit
Statut : SIMULE - aucun blocage reel
```

**Validation test** — synthetic log lines for a known malicious public IP were injected to produce a realistic, non-zero score:
```bash
for i in {1..10}; do
  sudo logger -p auth.warning -t sshd "Failed password for invalid user attacker from 185.220.101.1 port $((46000+i)) ssh2"
done
```
Result: AbuseIPDB returned a 100/100 confidence score, VirusTotal confirmed multiple malicious detections, the conditional branch fired, and the Discord dry-run message was delivered with the enriched data — confirming the full pipeline end to end.

**Gotcha — JSON body built from dynamic fields:** the first version of the `firewall-sim` POST body raised `SyntaxError - invalid syntax. Perhaps you forgot a comma?` on Discord's side. Cause: a dynamically-injected field (a list-type value from VirusTotal, such as `tags`) broke the surrounding JSON string when inserted as plain text rather than a properly-encoded value. Fixed by simplifying the message body to scalar fields only and reintroducing list-type fields separately once the base message validated successfully — a reminder that string-templating JSON by hand is fragile whenever a variable's type isn't guaranteed to be a plain string or number.

### 6.8 Final pipeline

```
Kali VM (hydra / logger synthetic events)
        │
        ▼
Splunk Enterprise — SPL detection, threshold alert
        │  webhook
        ▼
Shuffle (cloud) ──► AbuseIPDB (reputation score)
        │
        ├─► Email notification (always, for visibility)
        │
        └─ if score > 50 ─► VirusTotal (cross-check)
                                  │
                                  └─► Discord dry-run firewall report
```

### 6.9 Design notes — why human-in-the-loop and dry-run matter

Auto-blocking on every alert is risky in a real environment: internal IPs misclassified as external, shared NAT gateways, or a misconfigured app retrying logins can all trigger false positives. This pipeline deliberately stops short of an irreversible action — the firewall node is a **dry-run** that reports what *would* happen, and a human analyst receives the enrichment data via email before any real remediation is considered. This reflects how a SOC actually tunes SOAR playbooks: automation handles detection and enrichment reliably; a human makes the final call on anything destructive.

### 6.10 Possible future extensions

- Replace the dry-run Discord report with a real, gated remediation step (e.g., a firewall API call) behind explicit manual approval in Shuffle
- Add a third enrichment source (GreyNoise, Shodan) for further cross-validation
- Track blocked/flagged IPs in a small datastore to detect repeat offenders across alert cycles

### Tools used (this section)
Splunk Enterprise (SPL, alerting), Shuffle (cloud SOAR workflow: webhook, Http nodes, conditions, Email), AbuseIPDB API v2, VirusTotal API v3, Discord webhook, `logger` (synthetic log injection for testing).

---
**Hosni Nheri** — Telecommunications Engineering Student, ENET'Com Sfax
Certified: Splunk Certified Cybersecurity Defense Analyst (Splunk, 09/2026) · Cybersecurity Defense Analyst Career Path (Cisco Networking Academy, 09/2026) · CCNA: Switching, Routing and Wireless Essentials (Cisco Networking Academy, 05/2026) · Ethical Hacker (Cisco Networking Academy, 12/2025)
[LinkedIn](https://linkedin.com/in/hosni-nheri) · [GitHub](https://github.com/HosniNheri1)
