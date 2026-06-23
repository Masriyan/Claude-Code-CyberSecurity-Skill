---
name: Blue Team Defense & Hardening
description: System hardening, detection engineering, security baseline monitoring, patch management, defense-in-depth architecture, and security posture improvement
version: 3.0.0
author: Masriyan
tags: [cybersecurity, blue-team, defense, hardening, detection, baseline, siem, endpoint, cis]
---

# Blue Team Defense & Hardening

## Purpose

Enable Claude to assist defenders with comprehensive security hardening, detection rule engineering, security baseline establishment, patch management, and security architecture review. Claude directly analyzes provided configurations, scripts, and system state — then produces specific hardening commands, detection rules, and improvement plans.

---

## Activation Triggers

This skill activates when the user asks about:
- Hardening Linux (Ubuntu, RHEL, CentOS, Debian) servers
- Hardening Windows Server or Windows workstations (CIS Benchmarks)
- Creating detection rules (Sigma, Splunk, KQL, YARA, Snort/Suricata)
- Security baseline definition and monitoring
- Patch management strategy and prioritization
- Security architecture review (defense-in-depth, zero trust)
- Implementing Sysmon, auditd, or Windows audit policy
- Hardening SSH, nginx, Apache, or database configurations
- Network security controls and microsegmentation
- Endpoint protection (EDR, HIPS) configuration guidance
- Security posture improvement after a red team or pentest

---

## Prerequisites

```bash
pip install pyyaml jinja2 requests
```

**Tools used in this skill:**
- `Sysmon` — Windows endpoint telemetry (SwiftOnSecurity config recommended)
- `auditd` — Linux audit daemon
- `Lynis` — Linux security auditing tool
- `OpenSCAP / oscap` — CIS/STIG compliance scanning
- `fail2ban` — SSH and service brute-force protection
- `CIS-CAT` — CIS Benchmark compliance tool

---

## Core Capabilities

### 1. Linux System Hardening

**When the user asks to harden a Linux server:**

Claude produces specific commands ready to run.

#### SSH Hardening
```bash
# /etc/ssh/sshd_config — Secure SSH configuration
cat >> /etc/ssh/sshd_config << 'EOF'
# Security hardening
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers [specific_users]     # Explicit user allowlist
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PrintMotd no
Banner /etc/ssh/banner
Subsystem sftp /usr/lib/openssh/sftp-server -l INFO
EOF

# Restart SSH (check config first)
sshd -t && systemctl restart sshd
```

#### Kernel Hardening (sysctl)
```bash
# /etc/sysctl.d/99-security.conf
cat > /etc/sysctl.d/99-security.conf << 'EOF'
# Disable IP forwarding (unless this is a router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Disable source routing (prevents IP spoofing attacks)
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Enable SYN cookies (SYN flood protection)
net.ipv4.tcp_syncookies = 1

# Ignore ICMP broadcasts
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable ICMP redirects (prevents routing manipulation)
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# Log suspicious packets
net.ipv4.conf.all.log_martians = 1

# Disable IPv6 if not needed
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# Address space layout randomization
kernel.randomize_va_space = 2

# Restrict core dumps (prevents memory leaks)
fs.suid_dumpable = 0

# Restrict kernel log access to root
kernel.dmesg_restrict = 1

# Disable magic SysRq key
kernel.sysrq = 0

# Hide kernel pointers
kernel.kptr_restrict = 2

# Restrict ptrace to own processes
kernel.yama.ptrace_scope = 1
EOF

sysctl --system
```

#### Firewall Configuration (iptables/nftables)
```bash
# UFW (Uncomplicated Firewall) — Ubuntu/Debian
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh                    # or: ufw allow from [admin_ip] to any port 22
ufw allow from [monitoring_ip] to any port 9100  # Prometheus node exporter (internal only)
ufw enable
ufw status verbose

# iptables — manual approach for fine-grained control
iptables -F                              # Flush existing rules
iptables -P INPUT DROP                   # Default deny
iptables -P FORWARD DROP                 # Default deny forwarding
iptables -P OUTPUT ACCEPT                # Allow all outbound (or restrict too)

# Allow established/related connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow SSH from specific subnet only
iptables -A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -m conntrack --ctstate NEW -j ACCEPT

# Rate-limit SSH to prevent brute force
iptables -A INPUT -p tcp --dport 22 -m recent --set --name SSH
iptables -A INPUT -p tcp --dport 22 -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP

# Allow HTTPS
iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT

# Log and drop everything else
iptables -A INPUT -j LOG --log-prefix "iptables-DROP: " --log-level 7
iptables -A INPUT -j DROP

# Save rules
iptables-save > /etc/iptables/rules.v4
```

#### File System Security
```bash
# Find SUID/SGID binaries (audit these)
find / -perm /4000 -type f 2>/dev/null | sort   # SUID
find / -perm /2000 -type f 2>/dev/null | sort   # SGID

# Remove unnecessary SUID bits
chmod u-s /usr/bin/at    # Example: remove SUID from 'at' if not needed

# World-writable files (should be minimal)
find / -perm -002 -type f 2>/dev/null | grep -v proc

# Secure /tmp and /var/tmp
# In /etc/fstab, add: nodev,nosuid,noexec for /tmp
# tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0

# Immutable critical files (prevent modification even as root)
chattr +i /etc/passwd
chattr +i /etc/shadow
chattr +i /etc/sudoers

# File integrity monitoring
apt-get install aide
aideinit
aide --check  # Run periodically, alert on changes
```

#### Audit Logging (auditd)
```bash
# Install auditd
apt-get install auditd

# /etc/audit/rules.d/hardening.rules
cat > /etc/audit/rules.d/hardening.rules << 'EOF'
# Monitor system calls
-a always,exit -F arch=b64 -S execve -k exec_tracking
-a always,exit -F arch=b32 -S execve -k exec_tracking

# Monitor authentication
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k sudoers

# Monitor privileged commands
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k sudo_use
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k su_use

# Monitor network configuration changes
-a always,exit -F arch=b64 -S sethostname -k network_changes
-w /etc/hosts -p wa -k network_changes

# Monitor cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Successful file deletion (detect cleanup by attackers)
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -k delete

# Make the configuration immutable (requires reboot to change)
-e 2
EOF

service auditd restart

# Query audit logs
ausearch -k sudo_use -i        # Find all sudo usage
ausearch -k identity -i        # Find all user/group changes
```

#### Linux Hardening Checklist
```
Authentication:
[ ] Root login disabled (local and SSH)
[ ] Password authentication disabled for SSH (key-only)
[ ] Strong password policy enforced (PAM pwquality)
[ ] sudo configured with minimal privilege (specific commands, no NOPASSWD)
[ ] Inactive accounts locked or removed (>90 days)

Services:
[ ] Unnecessary services disabled (systemctl list-units --state=active)
[ ] No listening services on 0.0.0.0 that shouldn't be public
[ ] Web server runs as non-root user
[ ] Database not accessible from internet

Kernel & OS:
[ ] Security patches current (apt upgrade / yum update)
[ ] ASLR enabled (randomize_va_space=2)
[ ] ptrace restrictions (yama.ptrace_scope=1)
[ ] Core dumps disabled or restricted
[ ] AppArmor/SELinux in enforcing mode

Monitoring:
[ ] auditd installed and running
[ ] Log forwarding to SIEM configured
[ ] File integrity monitoring active
[ ] fail2ban installed for SSH protection
```

### 2. Windows System Hardening

**When the user asks to harden a Windows system:**

**PowerShell — Immediate Hardening Commands:**
```powershell
# Disable LLMNR (used in LLMNR poisoning attacks)
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" `
  -Name "EnableMulticast" -Value 0 -Type DWord

# Disable NBT-NS (NetBIOS Name Service — used in Responder attacks)
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled}
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2)  # 2 = Disable NetBIOS over TCP/IP
}

# Enable PowerShell Script Block Logging
$psLogPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $psLogPath -Force
Set-ItemProperty -Path $psLogPath -Name "EnableScriptBlockLogging" -Value 1

# Disable SMBv1 (EternalBlue vulnerability)
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# Enable Windows Defender real-time protection
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -CloudBlockLevel High
Set-MpPreference -CloudExtendedTimeout 50
Update-MpSignature

# Enable Windows Firewall on all profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Enable Credential Guard (requires Windows 10/2016+)
# Set via Group Policy: Computer Configuration → Administrative Templates → 
# System → Device Guard → Turn On Virtualization Based Security
```

**Sysmon Deployment for Endpoint Visibility:**
```powershell
# Download Sysmon and SwiftOnSecurity config
Invoke-WebRequest -Uri "https://live.sysinternals.com/Sysmon64.exe" -OutFile C:\Windows\Sysmon64.exe

# Deploy with SwiftOnSecurity config (most commonly recommended)
# Download config: https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml
Sysmon64.exe -accepteula -i sysmonconfig-export.xml

# Verify Sysmon is running
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
```

**Windows Audit Policy:**
```powershell
# Enable comprehensive Windows audit policy
# (Or configure via Group Policy → Computer Config → Windows Settings → Security Settings → Advanced Audit Policy)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Account Lockout" /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"Policy Change" /success:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable

# Enable command line logging in Event ID 4688
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
  /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

**Windows Hardening Checklist (CIS Level 1):**
```
Account Security:
[ ] Guest account disabled
[ ] Local Administrator account disabled or renamed
[ ] LAPS deployed (Local Administrator Password Solution)
[ ] No accounts with "Password never expires"
[ ] Account lockout: 5 attempts, 30-min lockout
[ ] Admin accounts not used for daily tasks

Network Security:
[ ] SMBv1 disabled
[ ] LLMNR disabled via GPO
[ ] NBT-NS disabled on all NICs
[ ] RDP restricted to VPN/jump host access only
[ ] WinRM access restricted to admin systems
[ ] PowerShell remoting disabled where not needed

Logging & Monitoring:
[ ] Windows Defender enabled and updated
[ ] EDR agent deployed and communicating
[ ] Sysmon deployed with current config
[ ] Event log size: Security 1GB+, System 512MB+, Application 256MB+
[ ] Log forwarding to SIEM configured

System Configuration:
[ ] BitLocker enabled on all endpoints
[ ] AppLocker or WDAC configured for application control
[ ] UAC: Prompt for credentials for all apps
[ ] Windows Update: Automatic, critical updates immediate
[ ] Unnecessary features removed (Telnet, SMB1, PowerShell 2.0)
[ ] WDAC Code Integrity policies for servers
```

### 3. Detection Engineering

**When the user asks to create detection rules:**

Claude produces complete, ready-to-deploy detection rules.

**Detection Rule Development Workflow:**

```
Step 1: Define what you're detecting
  - What specific behavior? (not "malware" but "PowerShell download cradle")
  - Which ATT&CK technique? (T1059.001 — PowerShell)
  - What data sources? (PowerShell logs, process creation, network)

Step 2: Collect sample telemetry
  - Capture true positive examples (from lab, red team, threat intel)
  - Collect false positive examples (legitimate activity)

Step 3: Identify unique indicators
  - What distinguishes malicious from legitimate?
  - Avoid indicators that change between variants (file names, IPs)
  - Prefer behavioral indicators (parent-child process, network pattern)

Step 4: Write and tune the rule
  - Start with high-confidence, low-noise detection
  - Test against both TP and FP datasets
  - Add exceptions for known-legitimate patterns

Step 5: Deploy and monitor
  - Track alert volume: sudden increase = new FP
  - Review untuned rules monthly
```

**Detection Rule Templates:**

```yaml
# Sigma Rule: Suspicious Process Spawned from Office Application
title: Office Application Spawning Script Interpreter
id: d2b45b6c-7b4e-4c2f-a8b9-1234567890ab
status: stable
description: Detects Office applications spawning script interpreters — common in macro-based initial access
references:
  - https://attack.mitre.org/techniques/T1566/001/
tags:
  - attack.initial_access
  - attack.t1566.001
  - attack.execution
  - attack.t1059
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith:
      - '\WINWORD.EXE'
      - '\EXCEL.EXE'
      - '\POWERPNT.EXE'
      - '\MSACCESS.EXE'
      - '\MSPUB.EXE'
      - '\outlook.exe'
  selection_child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\regsvr32.exe'
      - '\rundll32.exe'
  condition: selection_parent and selection_child
falsepositives:
  - Some legitimate macros may spawn cmd.exe for administrative purposes (rare)
level: high
```

**Suricata Network Detection Rule:**
```suricata
# Detect C2 traffic via HTTP with suspicious pattern
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"MALWARE Generic HTTP C2 Beacon - Suspicious Pattern";
    flow:established,to_server;
    http.method; content:"POST";
    http.request_body; content:!"";
    http.user_agent; content:"Mozilla/4.0 (compatible; MSIE 6.0;";
    http.uri; pcre:"/\/[a-z]{8}(\/[a-z]{4})?$/";  # Random 8-char path
    threshold:type both, track by_src, count 3, seconds 300;
    classtype:trojan-activity;
    sid:9100001;
    rev:1;
)
```

**YARA Rule for Host-Based Detection:**
```yara
rule Suspicious_PowerShell_Download_Cradle {
    meta:
        author = "Blue Team"
        description = "Detects PowerShell download cradle in scripts or command lines"
        date = "2025-05-28"
    
    strings:
        $cradle1 = "(New-Object Net.WebClient).DownloadString" ascii wide nocase
        $cradle2 = "IEX(New-Object" ascii wide nocase
        $cradle3 = "Invoke-Expression (Invoke-WebRequest" ascii wide nocase
        $cradle4 = "[System.Net.WebClient]" ascii wide nocase
        $cradle5 = "iex (iwr" ascii wide nocase
        
        $encoded = "-EncodedCommand " ascii wide nocase
        $bypass  = "-ExecutionPolicy Bypass" ascii wide nocase
        $nop     = "-WindowStyle Hidden" ascii wide nocase
    
    condition:
        any of ($cradle*) or (2 of ($encoded, $bypass, $nop))
}
```

### 4. Security Baseline Monitoring

**When the user asks to define or monitor security baselines:**

**Baseline Definition Framework:**

```markdown
## Security Baseline — [System Type] — [Environment]

### Normal Behavior Profiles

**Authentication Baseline:**
- Admin accounts: Only log in during business hours (08:00–18:00 local)
- Service accounts: Never have interactive logon (Event 4624 Type 2)
- Failed logins: <5 per user per day (>5 = investigate)
- New login locations: Alert on first-time country/city

**Process Baseline:**
- Web server: Never spawns cmd.exe or powershell.exe
- Database: No outbound network connections except DB clients
- System processes: Parent process matches expected (e.g., services.exe → svchost.exe)

**Network Baseline:**
- Workstations: No direct SMB to other workstations (server-to-server OK)
- DNS: <100 queries per minute per host; 50+ unique domains per hour = investigate
- Egress: Only expected protocols (HTTPS, DNS, SMTP for mail servers)

**File System Baseline:**
- System directories: No new executables in \Windows\System32\ between patches
- User directories: Alert on new .exe, .dll, .ps1 in %APPDATA%
- Logs: Never deleted (alert on Event ID 1102)
```

**Automated Baseline Checks:**
```bash
# Linux: Track listening services
netstat -tulnap > /tmp/services_current.txt
diff /tmp/services_baseline.txt /tmp/services_current.txt

# Compare against known-good process list
ps auxf > /tmp/processes_current.txt
diff /tmp/processes_baseline.txt /tmp/processes_current.txt

# Find recently modified system files
find /bin /sbin /usr/bin /usr/sbin /lib -newer /tmp/baseline_timestamp -type f 2>/dev/null

# Windows: Compare running services
Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object Name,DisplayName | Sort-Object Name
```

```bash
python scripts/hardening_checker.py --os ubuntu --output report.json
python scripts/hardening_checker.py --os windows --cis-level 1 --output report.json
```

### 5. Patch Management Strategy

**When the user asks about patch management:**

**Patch Prioritization Matrix:**
| CVSS | Exploitability | In CISA KEV? | Priority | SLA |
|------|---------------|-------------|---------|-----|
| 9.0–10.0 | Remote, no auth | Yes | P1 — Emergency | 24 hours |
| 9.0–10.0 | Remote, no auth | No | P1 — Critical | 48 hours |
| 7.0–8.9 | Remote | Any | P2 — High | 7 days |
| 4.0–6.9 | Local | Any | P3 — Medium | 30 days |
| 0.1–3.9 | Any | No | P4 — Low | 90 days |
| 0.0 | N/A | N/A | P5 — Info | Next cycle |

**Patch Rollout Process:**
```
1. RECEIVE patch (vendor advisory, CVE, CISA alert)
2. ASSESS severity and exploitability (CVSS + CISA KEV check)
3. TEST in non-production environment (Dev → QA → Staging)
4. PLAN rollout window (off-peak, with rollback procedure)
5. DEPLOY to production (phased: 10% → 50% → 100%)
6. VERIFY patch applied and service running
7. MONITOR for regressions (24-48 hours)
8. DOCUMENT in change management system
```

**Track patch debt:**
```bash
# Ubuntu/Debian
apt list --upgradable 2>/dev/null | wc -l   # Total upgradable
apt list --upgradable 2>/dev/null | grep -i security  # Security-only

# RHEL/CentOS
yum check-update --security

# Windows
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10
# Or: Get pending updates
(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0 and Type='Software'").Updates | Select-Object Title
```

### 6. Security Architecture Review

**When the user asks to review security architecture:**

**Defense-in-Depth Framework:**
```
Layer 1 — Perimeter Defense
  ├── External firewall / WAF
  ├── IDS/IPS (Suricata/Snort)
  ├── DDoS protection
  └── DNS filtering

Layer 2 — Network Segmentation
  ├── VLANs: Servers / Users / IoT / Guests / Management
  ├── East-west traffic controls
  ├── Micro-segmentation for critical systems
  └── Network access control (802.1X)

Layer 3 — Endpoint Defense
  ├── EDR (CrowdStrike, SentinelOne, Defender for Endpoint)
  ├── AV / NGAV
  ├── Host firewall
  └── Application control (AppLocker / WDAC)

Layer 4 — Identity & Access Management
  ├── MFA for all users
  ├── Privileged Access Management (PAM)
  ├── JIT / JEA (Just-in-Time, Just-Enough-Admin)
  └── Zero Trust Network Access (ZTNA)

Layer 5 — Data Protection
  ├── Encryption at rest (BitLocker, dm-crypt)
  ├── Encryption in transit (TLS 1.2/1.3)
  ├── Data Loss Prevention (DLP)
  └── Backup with integrity verification

Layer 6 — Detection & Response
  ├── SIEM (log aggregation + correlation)
  ├── SOAR (automated response)
  ├── Threat intelligence feeds
  └── Vulnerability management
```

**Zero Trust Assessment Checklist:**
```
Identity Verification:
[ ] All access requires strong authentication (MFA)
[ ] Identity verified continuously, not just at login
[ ] Privileged accounts isolated (PAW — Privileged Access Workstations)
[ ] Service-to-service authentication (not just user-to-service)

Network Micro-Segmentation:
[ ] No implicit trust between network segments
[ ] East-west inspection enabled
[ ] Access granted per-application, not per-network
[ ] Least-privilege network access enforced

Device Trust:
[ ] Device health verified before access granted
[ ] MDM/EMM for endpoint management
[ ] Certificate-based authentication where possible
[ ] Unmanaged/BYOD devices isolated

Application Security:
[ ] Applications authenticated, not just networks
[ ] API gateway for service-to-service calls
[ ] RBAC enforced at application layer
[ ] Secrets management (Vault, not environment variables)
```

---

## Post-Engagement Hardening

**When the user wants to harden based on red team findings:**

```markdown
## Post-Red-Team Hardening Priority List

Given findings from [Engagement Date] assessment:

### P1 — Immediate (48 hours)
- [ ] Disable LLMNR and NBT-NS (used for initial credential capture)
  → `Set-ItemProperty HKLM:\... EnableMulticast 0`
- [ ] Enable MFA for all admin accounts (used for lateral movement)
- [ ] Patch [CVE-2024-XXXX] on all internet-facing servers

### P2 — This Week  
- [ ] Deploy Sysmon with SwiftOnSecurity config (detection gap)
- [ ] Enable PowerShell Script Block Logging (GPO)
- [ ] Block PsExec from non-admin hosts via AppLocker

### P3 — This Month
- [ ] Implement LAPS (Local Admin Password Solution)
- [ ] Deploy network segmentation (workstation-to-workstation blocking)
- [ ] Enable credential guard on domain-joined workstations

### P4 — Next Quarter
- [ ] Implement Privileged Access Workstations (PAW) for IT admins
- [ ] Deploy deception technology (honeypots/honeytokens)
- [ ] Red team readiness exercise (purple team)
```

---

## Script Reference

### `hardening_checker.py`
```bash
python scripts/hardening_checker.py --os ubuntu --output report.json
python scripts/hardening_checker.py --os ubuntu --cis-level 1 --fix-mode
python scripts/hardening_checker.py --os windows --cis-level 1 --output report.json
```

---

## Skill Integration

| Condition | Adjacent Skill |
|-----------|---------------|
| Red team findings → create remediation plan | ← Skill 14 (Red Team Operations) |
| Detection rules → deploy to SIEM | → Skill 12 (Log Analysis) |
| New detection rules → add to CSOC | → Skill 11 (CSOC Automation) |
| Vulnerability scanner findings → patch plan | ← Skill 02 (Vulnerability Scanner) |
| Threat hunt gaps → improve detection coverage | ← Skill 06 (Threat Hunting) |

---

## References

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [MITRE D3FEND Framework](https://d3fend.mitre.org/)
- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Microsoft Security Baselines](https://www.microsoft.com/en-us/download/details.aspx?id=55319)
- [NSA Cybersecurity Guidance](https://www.nsa.gov/cybersecurity/guidance/)
- [SANS Critical Security Controls](https://www.sans.org/critical-security-controls/)
- [Lynis Hardening Tool](https://cisofy.com/lynis/)
- [The Linux Hardening Guide](https://madaidans-insecurities.github.io/guides/linux-hardening.html)


---

## v3.0 Enhancements (2026 Update)

**Detection-as-code and modern baselines:**

- **Current OS baselines** — Windows 11 / Server 2025 and recent Linux CIS benchmarks; enforce LAPS (Windows LAPS), Credential Guard, and Attack Surface Reduction (ASR) rules.
- **Telemetry that matters** — deploy a maintained Sysmon config (SwiftOnSecurity/Olaf base), enable PowerShell script-block + module logging, command-line auditing, and ship to the SIEM; on Linux use auditd + eBPF (Falco/Tetragon).
- **Detection-as-code** — manage Sigma detections in git with tests and CI conversion to the target SIEM; track ATT&CK coverage as a measurable metric (DeTT&CT-style).
- **Identity hardening** — phishing-resistant MFA (FIDO2/passkeys), conditional access, and tiered admin (PAW) to counter token theft and AD escalation.
- **Zero Trust maturity** — assess against CISA's Zero Trust Maturity Model pillars (identity, device, network, app, data) and report a maturity score per pillar.
- **Cloud & container hardening** — extend baselines to cloud workloads and Kubernetes (ties to Skill 10); validate with the included checker and CSPM.

**Precision rule:** every recommendation pairs the hardening change with the detection that proves it (or catches its bypass).
