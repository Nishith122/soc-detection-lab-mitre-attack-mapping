# SOC Detection Lab — Home Security Operations Centre

> Built a 3-VM security lab simulating real enterprise SOC workflows.  
> Deployed Splunk SIEM, ingested Windows 11 telemetry via Sysmon, simulated attacks from Kali Linux, and built detection rules mapped to MITRE ATT&CK.

---

## Lab Architecture

```
┌─────────────────┐         attacks          ┌─────────────────┐
│   Kali Linux    │ ──────────────────────── │   Windows 11    │
│   (Attacker)    │                          │  (Victim Host)  │
│  10.10.1.59     │                          │  10.10.1.11     │
└─────────────────┘                          │  + Sysmon v15   │
                                             │  + UF Forwarder │
                                             └────────┬────────┘
                                                      │ logs (port 9997)
                                             ┌────────▼────────┐
                                             │  Ubuntu Server  │
                                             │  Splunk 10.2.2  │
                                             │  (SIEM)         │
                                             │  10.10.1.9      │
                                             └─────────────────┘
```

| Component | Tool | Purpose |
|---|---|---|
| Attacker | Kali Linux | Nmap, Hydra, RDP brute force |
| Victim | Windows 11 + Sysmon v15.20 | Target host, deep telemetry |
| SIEM | Ubuntu + Splunk Enterprise 10.2.2 | Log aggregation, detection, alerting |
| Forwarder | Splunk Universal Forwarder | Ships Windows + Sysmon logs to Splunk |

---

## Projects

### Project 1 — Home SOC Lab: Threat Detection with Splunk

**What I built:**
- Deployed Splunk SIEM on Ubuntu, configured receiving on port 9997
- Installed Sysmon v15.20 with custom config enabling process, network and file telemetry
- Configured Splunk Universal Forwarder to ship Windows Security, System, and Sysmon logs
- Ran 4 attack simulations from Kali Linux and detected each one in Splunk

**Attacks simulated and detected:**

| Attack | Tool | Detection | Splunk EventID |
|---|---|---|---|
| Port scan | Nmap -sT | Network connections spike | Sysmon EC=3 |
| Brute force | Hydra | 5+ failures in 5 min | EventID 4625 |
| RDP breach | xfreerdp | Successful RDP logon | EventID 4624 Logon_Type=10 |
| Persistence | net user | New admin account created | EventID 4720 |

**Key SPL queries written:**

```spl
# Brute force detection
index=windows_logs EventCode=4625 earliest=-5m
| stats count as FailedAttempts by Account_Name, Source_Network_Address
| where FailedAttempts >= 5
| sort -FailedAttempts

# RDP breach after brute force
index=windows_logs (EventCode=4625 OR EventCode=4624) earliest=-1h
| eval Status=if(EventCode=4624,"SUCCESS","FAILED")
| timechart span=1m count by Status

# New account creation (persistence)
index=windows_logs EventCode=4720
| table _time, SAM_Account_Name, Account_Name, ComputerName
```

**Screenshots:**

![SOC Dashboard](screenshots/01-splunk-dashboard.png)
![Brute Force Timechart](screenshots/02-brute-force-timechart.png)
![Alert Triggered](screenshots/03-alert-triggered.png)
![RDP Breach Detection](screenshots/04-rdp-breach.png)

---

### Project 2 — Ransomware Behavior Detection Lab

**What I built:**
- Simulated a full ransomware kill chain using PowerShell on Windows 11
- Detected each stage behaviorally using Sysmon + Splunk — no signatures
- Built 3 detection alerts including a kill chain correlation query with dynamic RiskScore
- Mapped all detections to MITRE ATT&CK

**Ransomware kill chain simulated:**

| Stage | Action | MITRE Technique |
|---|---|---|
| Recon | File discovery with Get-ChildItem -Recurse | T1083 |
| Defense evasion | Disable Windows Defender | T1562.001 |
| Backup destruction | vssadmin delete shadows /all | T1490 |
| Encryption | 30 files renamed to .locked in 45 seconds | T1486 |
| Ransom note | README_LOCKED.txt dropped in target dirs | T1491 |

**Key SPL detection queries:**

```spl
# Shadow copy deletion — #1 ransomware indicator
index=sysmon_logs EventCode=1
| search CommandLine="*vssadmin*delete*" OR CommandLine="*shadowcopy*delete*"
| table _time, Image, CommandLine, User

# Mass file encryption detection
index=sysmon_logs EventCode=11 earliest=-1m
| search TargetFilename="*.locked"
| stats count as FilesEncrypted by host
| where FilesEncrypted > 10

# Full kill chain correlation with RiskScore
index=sysmon_logs earliest=-10m
(
    (EventCode=1 CommandLine="*vssadmin*delete*")
    OR (EventCode=11 TargetFilename="*.locked")
    OR (EventCode=1 CommandLine="*Get-ChildItem*Recurse*")
)
| stats
    count(eval(EventCode=1 AND match(CommandLine,"vssadmin"))) as ShadowDelete,
    count(eval(EventCode=11)) as FilesRenamed,
    count(eval(EventCode=1 AND match(CommandLine,"Get-ChildItem"))) as FileDiscovery
    by host
| where ShadowDelete > 0 OR FilesRenamed > 10
| eval RiskScore=ShadowDelete*50 + FilesRenamed*2 + FileDiscovery*5
| sort -RiskScore
```

**Detection alerts built:**

| Alert | Trigger | Severity |
|---|---|---|
| CRITICAL - Shadow Copy Deletion | Real-time, any result | Critical |
| HIGH - Mass File Rename | Every 1 min, >20 renames | High |
| CRITICAL - Ransomware Kill Chain | Every 1 min, RiskScore >0 | Critical |

**Screenshots:**

![Encrypted Files Detected](screenshots/05-locked-files-detected.png)
![Encryption Wave Timechart](screenshots/06-encryption-timechart.png)
![Shadow Copy Alert](screenshots/07-shadow-copy-alert.png)
![Kill Chain Correlation](screenshots/08-kill-chain-correlation.png)

---

### Project 3 — MITRE ATT&CK Detection Coverage Map

**What I built:**
- Mapped all detection rules from both labs to MITRE ATT&CK Enterprise framework
- Identified coverage across 6 tactics with 9 techniques
- Performed gap analysis identifying 4 high-priority undetected areas
- Documented remediation roadmap prioritised by risk

**Coverage map:**

![MITRE ATT&CK Coverage Map](screenshots/09-mitre-coverage-map.png)

**Detection coverage:**

| Technique ID | Technique Name | Tactic | Detection |
|---|---|---|---|
| T1595 | Active Scanning | Reconnaissance | Sysmon EC=3 network spike from Kali |
| T1110.001 | Password Guessing | Credential Access | EventID 4625 threshold alert |
| T1021.001 | Remote Desktop Protocol | Lateral Movement | EventID 4624 Logon_Type=10 |
| T1136.001 | Local Account Creation | Persistence | EventID 4720 |
| T1083 | File & Directory Discovery | Discovery | Sysmon EC=1 Get-ChildItem -Recurse |
| T1490 | Inhibit System Recovery | Impact | Sysmon EC=1 vssadmin delete |
| T1486 | Data Encrypted for Impact | Impact | Sysmon EC=11 mass .locked creation |
| T1562.001 | Disable Windows Defender | Defense Evasion | Sysmon EC=1 Set-MpPreference |
| T1491 | Defacement | Impact | Sysmon EC=11 README_LOCKED.txt |

**Detection gaps identified:**

| Tactic | Gap | Remediation | Priority |
|---|---|---|---|
| Initial Access | No phishing detection | Add email gateway + web proxy logs | High |
| Command & Control | No C2 monitoring | Alert on Sysmon EC=22 DNS anomalies | High |
| Exfiltration | No data theft detection | Monitor large outbound transfers | Medium |
| Execution | Partial — missing macro execution | Alert on Office apps spawning cmd.exe | Medium |

---

## Skills Demonstrated

```
SIEM:           Splunk Enterprise 10.2.2 — indexing, SPL queries, dashboards, alerts
Endpoint:       Sysmon v15.20 — process, network, file telemetry
Log Analysis:   Windows Event IDs 4624, 4625, 4720, 4740 + Sysmon EventCodes 1, 3, 11
Attack Tools:   Nmap, Hydra, xfreerdp, PowerShell simulation scripts
Frameworks:     MITRE ATT&CK Enterprise — 9 techniques across 6 tactics
Detection:      Behavioral detection, threshold alerting, kill chain correlation
Documentation:  Incident reports, gap analysis, detection mapping
```

---

## Certifications

- Splunk Core Certified User
- Google Cybersecurity Certificate
- TryHackMe SOC Level 1 — [tryhackme.com/p/rnishith721]
- Cisco Introduction to Cybersecurity

---

## Incident Reports

- [INC-LAB-001 — Brute Force + RDP Breach + Persistence](incident-reports/INC-LAB-001.md)
- [INC-LAB-002 — Ransomware Kill Chain Detection](incident-reports/INC-LAB-002.md)

---

## Repository Structure

```
soc-detection-lab/
├── README.md
├── screenshots/
│   ├── 01-splunk-dashboard.png
│   ├── 02-brute-force-timechart.png
│   ├── 03-alert-triggered.png
│   ├── 04-rdp-breach.png
│   ├── 05-locked-files-detected.png
│   ├── 06-encryption-timechart.png
│   ├── 07-shadow-copy-alert.png
│   ├── 08-kill-chain-correlation.png
│   └── 09-mitre-coverage-map.png
├── splunk-queries/
│   ├── home-lab-detections.spl
│   └── ransomware-detections.spl
├── configs/
│   ├── inputs.conf
│   └── sysmon-lab-config.xml
├── simulation-scripts/
│   └── ransomware-simulation.ps1
├── incident-reports/
│   ├── INC-LAB-001.md
│   └── INC-LAB-002.md
└── mitre-coverage/
    ├── coverage-map.png
    ├── technique-mapping-table.md
    └── gaps-analysis.md
```

---

*Built as part of a self-directed SOC Analyst preparation program targeting L1 SOC roles.*  
*All simulations conducted in an isolated lab environment. No real systems were harmed.*
