# SOC Home Lab: Active Directory Password Spray Detection

A home-built Security Operations Center lab for detecting authentication attacks against Active Directory, using Splunk Enterprise for log collection, correlation, and alerting.

This project simulates a real attack scenario end to end. Build the infrastructure, generate telemetry, launch an attack, then detect and alert on it. Basically the same workflow a SOC analyst runs in a live environment.

> ⚠️ All IP addresses, hostnames, and other identifying values in the screenshots below have been blurred. This lab runs entirely on isolated, non-production VMs.

---

## Architecture

![Lab architecture diagram](00-architecture-diagram.svg)

| Role | System |
|---|---|
| Attacker | Kali Linux |
| Domain Controller | Windows Server 2022 (Active Directory) |
| Domain-joined endpoint | Windows 10 |
| SIEM | Ubuntu Server running Splunk Enterprise |

All four machines run as VirtualBox VMs on an isolated internal network.

![Lab infrastructure, VirtualBox VM inventory](01-lab-infrastructure.png)

---

## 1. Building the Domain

Stood up a Windows Server 2022 domain controller: installed the AD DS role, then ran the Active Directory Domain Services Configuration Wizard to promote the server and stand up a new forest with the root domain `lab.local`.

![Server Manager dashboard before role install](02a-server-manager-dashboard.png)
![ADDS deployment configuration, add a new forest](02b-adds-deployment-config.png)
![Specifying the root domain name](02c-domain-name.png)
![Domain controller options, functional level, DNS, Global Catalog](02d-domain-controller-options.png)
![AD DS configuration wizard installing](02e-adds-install-progress.png)

Created an Organizational Unit and the domain user accounts used later as spray targets.

![Creating a new Organizational Unit](02f-new-ou.png)
![Active Directory Users and Computers with OU and accounts](02g-active-directory-final.png)

---

## 2. Standing Up the SIEM

Installed Splunk Enterprise on Ubuntu Server as the central log collection and analysis platform.

![Splunk Enterprise installation](03-splunk-install.png)

Deployed the Splunk Universal Forwarder to the domain controller and Windows 10 endpoint to ship Windows Event Logs into Splunk, and created a dedicated `endpoint` index to receive them.

![Universal Forwarder / data input configuration](04-universal-forwarder.png)

Installed Sysmon on the endpoints for richer process, network, and logon telemetry beyond native Windows Event Logs, and configured it to forward into Splunk as well.

![Sysmon installation and configuration](05-sysmon-config.png)

---

## 3. Simulating the Attack

From the Kali VM, ran a password spray attack against the domain controller using **NetExec** (the actively maintained successor to CrackMapExec). It tests a small set of common passwords across multiple domain accounts to avoid account lockout thresholds while still triggering detection-worthy failed logon activity.

![Password spray attack with NetExec](06-password-spray-attack.png)

This generated a mix of:
- **Event ID 4625**, failed logon attempts across the sprayed accounts
- **Event ID 4624**, the successful logon(s) that a real spray would eventually land

![Failed authentication events in Splunk](07-failed-auth-events.png)

---

## 4. Detection Engineering

Wrote an SPL detection query to identify password spray behavior: a single source authenticating against many distinct accounts, with a high failure count, within a short time window. That's the fingerprint that separates a spray (one source, many users) from a brute force (one source, one user, many passwords).

```spl
index=endpoint EventCode=4625
| bucket _time span=5m
| stats count as failed_attempts, dc(Account_Name) as unique_users, values(Account_Name) as targeted_users by Source_Network_Address, _time
| where unique_users >= 5
```

![SPL detection query and search results](08-spl-detection-query.png)

Then confirmed the successful hit: searched EventCode=4624 (successful logon) for the same source and time window to find the one account whose password matched the spray list. That's the moment the attack would have actually gotten in.

Turned the detection search into a **scheduled Splunk alert** so it runs continuously and fires when spray-like behavior is detected, instead of relying on manual hunting.

![Scheduled alert configuration](09-scheduled-alert.png)

---

## 5. SOC Monitoring Dashboard

Built a Splunk dashboard to give an at-a-glance view of authentication activity: failed vs. successful logons over time, top targeted accounts, and top source hosts. This is for ongoing monitoring rather than one-off investigation.

![SOC monitoring dashboard](10-soc-dashboard.png)
![SOC monitoring dashboard](10-soc-dashboardd.png)
![SOC monitoring dashboard](10-soc-dashboarddd.png)

---

## Findings

- A single source IP failed authentication against 7 distinct domain accounts within a 5-minute window. That's well outside normal user behavior and a clear spray signature (one source, many users), not a brute force (one source, one user).
- The attack paced attempts across the user list per password rather than hammering one account, avoiding per-account lockout thresholds. This is exactly why spray attacks are worth detecting specifically rather than relying on lockout policy alone.
- One account's password matched the sprayed list, producing a successful EventCode 4624 logon in the same window as the failures. This shows the full path from initial attempts to compromise.

## Remediation Recommendations

- Enforce a strong password policy and check accounts against known-breached password lists.
- Enable MFA for all domain accounts, especially privileged ones.
- Monitor and alert on the failed-logon-across-many-accounts pattern shown above, rather than relying solely on per-account lockout.
- Consider Azure AD Smart Lockout or a similar adaptive lockout policy that accounts for spray patterns specifically.

---

## What This Demonstrates

- Building and hardening a small Active Directory environment from scratch
- Deploying a SIEM (Splunk Enterprise) and onboarding Windows/Sysmon log sources
- Simulating a realistic credential attack (password spray) with NetExec
- Writing SPL detections mapped to a real attack technique (MITRE ATT&CK T1110.003, Password Spraying)
- Turning a detection into an actionable, scheduled alert
- Building a monitoring dashboard for ongoing visibility

## Tools Used

`VirtualBox` · `Windows Server 2022 (Active Directory)` · `Windows 10` · `Ubuntu Server` · `Splunk Enterprise` · `Splunk Universal Forwarder` · `Sysmon` · `Kali Linux` · `NetExec`

## Next Steps

- [ ] Add more detection rules (Kerberoasting, lateral movement, persistence)
- [ ] Automate VM provisioning
- [ ] Layer in Sysmon-based process/network detections alongside the auth-log detections above
