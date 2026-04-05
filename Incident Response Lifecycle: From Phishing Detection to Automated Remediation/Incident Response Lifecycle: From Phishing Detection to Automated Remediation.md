# 🛡️Incident Response Lifecycle: From Phishing Detection to Automated Remediation

## 📋 Project Objective:
The primary goal of this project is to architect and validate a **unified Security Operations Center (SOC) ecosystem** capable of handling complex, multi-stage cyber attacks. 

By integrating **Velociraptor (DFIR)**, **TheHive (Case Management)**, and **Cortex (SOAR)**, this simulation demonstrates:
* **Advanced Host Forensics**: Utilizing EDR artifacts to reconstruct attacker timelines and identify stealthy persistence mechanisms.
* **Incident Orchestration**: Implementing a structured IR lifecycle (NIST/SANS) to reduce **Mean Time to Respond (MTTR)** through automated observable enrichment.
* **Framework Alignment**: Mapping adversary TTPs to the **MITRE ATT&CK** and **Cyber Kill Chain** frameworks to identify defensive gaps and improve detection logic.
* **Response Automation**: Bridging the gap between manual forensic analysis and automated SOAR workflows to ensure high-fidelity alerting and rapid containment.

# Lab Setup & Architecture
| Asset | OS | IP Address | Role |
|-------|-----|-------------|------|
| WS2019-Victim | Windows Server 2019 | 10.0.0.10 | Compromised host (target) |
| Velociraptor | Ubuntu (Nginx proxy) | 10.0.0.22 | Digital Forensics & Incident Response (DFIR) |
| TheHive-SOC | Ubuntu | 10.0.0.30 port 9000 | Case Management & Incident Reporting |
| Cortex SOAR | Docker container | 10.0.0.30 port 9001 | Automated Observable Enrichment |
| Snort IDS | Ubuntu | 10.0.1.254 | Network Intrusion Detection System |


# Incident Case Study: "Operation Salary Snatch" 

## 📝 Executive Summary
**Date:** 2024-05-20  
**Target Host:** `WS2019-Victim` (10.0.0.10)  
**Attack Vector:** Spear-Phishing (T1566.001)

| Attribute | Details |
|-----------|---------|
| **Severity** | 🔴 **High** (Credential Theft & Exfiltration) |
| **Status** | ✅ **Remediated & Closed** |
| **Threat Actor** | Unidentified (Phishing-driven Malware) |
| **Primary Goal** | Financial Data Exfiltration & Domain Credential Harvesting |

**Summary of Activity:** A targeted spear-phishing attack led to the execution of a malicious binary (`Salary_Update.exe`), resulting in an active C2 reverse shell. The adversary successfully bypassed security policies, established persistence via a hidden scheduled task, and utilized **Mimikatz** for credential harvesting. Defensive evasion was achieved by wiping critical Windows Event Logs. The incident was contained and remediated within the defined SLA.

---

## ⛓️ Attack Timeline & Chain (TL;DR)

1.  **Initial Access (Delivery)** Phishing email from spoofed domain `deemo.lab` delivered to `admin@demo.lab`. Contains malicious dropper disguised as a document.
2.  **Execution (Exploitation)** User execution of `Salary_Update.exe`. The process spawns a hidden **PowerShell** wrapper (`salary_wrapper.ps1`) to download secondary payloads: `nc.exe` and `2.dll` (Mimikatz).
3.  **Persistence (Installation)** Creation of a hidden Scheduled Task `\SystemHealthMonitor` triggering `update.ps1`. This ensures re-infection and C2 callback upon system reboot.
4.  **C2 & Exfiltration (Actions on Objectives)** Adversary establishes a **Reverse Shell** to `104.208.16.95` on port `443`. Manual discovery leads to the exfiltration of a financial report.
5.  **Defense Evasion** Execution of `wevtutil` commands to purge **Security**, **System**, and **PowerShell/Operational** logs, effectively removing the host-based forensic trail.

---

## 🔍 Intelligence & Indicators of Compromise (IoCs)

### Network Indicators
* **C2 Server IP:** `104.208.16.95` (Port: 443)
* **Sender Domain:** `deemo.lab` (Suspicious domain mimicry)

### Host Indicators
| Artifact Name | Type | SHA256 Hash |
|---------------|------|-------------|
| `Salary_Update.exe` | Dropper / PE | `5cbf2f4b4a57bcac660c79772401077764f60e85a5123a7e311859a211abb9c1` |
| `update.ps1` | PowerShell Script | (Identify Hash via Velociraptor) |
| `2.dll` | Mimikatz / Library | `6349c0af16bbd22b44bcbbe25c19d82d` |

---

# 🕵️ Forensic Investigation (Deep Dive)

We have received a suspicious email from one of the company's users. Let's analyze it.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen1.png?raw=true)

First, we will download the email and extract all the attachments to the “extracted” folder.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle%3A%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen2.png)

Open the email and analyze it.
We see that the sender is “support@deemo.lab” and the recipient is “admin@demo.lab”.Note, that the sender domain name is suspi The subject of the email is “Salary Update”. Since the valid users are in the “demo.lab” domain, it is clear that “support@deemo.lab” is not the actual support service in the domain. We see that the attachment is “Salary_Update.exe”.Suspicious. Because the document that should show the salary update should have the .docx extension

Let's collect the hashes of this suspicious file:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle%3A%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen3.png)

-MD5: 236420e9795b30db8bf9e7db4b74610e 

-SHA1: 7fcff16ee32d0685de0b766d0342d1001dc81657 

-SHA256: 5cbf2f4b4a57bcac660c79772401077764f60e85a5123a7e311859a211abb9c1

Let's check if this attachment is malicious. Paste the SHA256 hash of our file into VirusTotal:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle%3A%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen4.png)

### Collecting IoC:
 - `1) Sender's email: “support@deemo.lab”`
 - `2) Sender's domain: “deemo.lab”`
 - `3) File hashes:
-MD5: 236420e9795b30db8bf9e7db4b74610e 
-SHA1: 7fcff16ee32d0685de0b766d0342d1001dc81657 
-SHA256:5cbf2f4b4a57bcac660c79772401077764f60e85a5123a7e311859a211abb9c1`
 - `4) Attachment name: “Salary_Update.exe”.`

Now we need to analyse.This is necessary in order to build a Cyber Kill Chain. The email is a phishing email. VirusTotal has detected that this file(attachment) is malicious. One of the signs that indicate that the file is malicious is the analysis of the file hash on VirusTotal.

# Detection & Deep Forensic Analysis (Velociraptor Artifacts)
Сonnect to the WS2019 host. We run the malicious powershell script “update.ps1” on it - this PowerShell script simulates an attack that would occur if we opened a malicious attachment in an email. Now switch to Velociraptor, select our host, and create a new artifact.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle%3A%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen5.png)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle%3A%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen6.png)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle%3A%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen7.png)

Select an artifact and click **Launch**.

In our case, we need to analyze the following artifacts to fully analyze the infected host

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle%3A%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen8.png)


### Analyze **Windows.System.Pslist**:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle%3A%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen9.png)

We see that a powershell process is running associated with the attachment file “Salary_Update.exe”. The file is running from the “Downloads” folder, which also indicates suspicious activity. We can also see that a script is running from the Temp folder (temporary folder) to execute the malicious file Salary_Update.exe.
PID:7076. PPID:6868.

**Executed command**:
`
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoExit -WindowStyle Hidden -File C:\Windows\Temp\salary_wrapper.ps1 -ExePath C:\Users\administrator\Downloads\Salary_Update.exe
`

**Path to file**: `C:\Users\administrator\Downloads\Salary_Update.exe`

**Path to powershell script**: ` C:\Windows\Temp\salary_wrapper.ps1`

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen10.PNG?raw=true)
 Here the malicious **update.ps1** script was launched.
 
 ### Analyze **Generic.Forensic.LocalHashes.Glob**:
 
![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen11.PNG?raw=true)
 
 Almost all the files that were uploaded can be considered IoC

**File Location:**`C:\Users\Administrator\Downloads\Salary_Update.exe`
**File hash:**`236420e9795b30db8bf9e7db4b74610e `

### Analyze **Windows.Network.Netstat**:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen12.PNG?raw=true)

First, sort by Timestamp. We see suspicious connections to IP addresses that are not part of the 10.0.0.0/24 subnet. We will note important PID in the screenshot, which will be useful for further analysis. Here the attacker established connections with C2 servers. **PIDs:2744,7076,6468.**

### Analyse **Windows.System.TaskSheduler:**

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen13.PNG?raw=true)

We see a suspicious process running in `\SystemHealthMonitor`, because in arguments of this process, we see a powershell command, which executes a powershell script `update.ps1`.

Signature `-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass` indicates that attacker was hiding the update.ps1 script launch windows and bypassed security policies.

### Analyse **HashRunKeys:**

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen14.PNG?raw=true)

The attacker has gained permanent access to the host. Even if you terminate the current malicious process, the `update.ps1` file will execute again after a reboot and user login, potentially restoring the reverse connection (Reverse Shell) to the attacker's server. The **Run** section is used to automatically load programs. The entry is created in the specific user's branch (whose SID is visible in the screenshot), which means that the script will run every time this user logs in.

### Analyse **Windows.Detection.BinaryHunter**

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen15.PNG?raw=true)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen16.PNG?raw=true)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen17.PNG?raw=true)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen18.PNG?raw=true)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen19.PNG?raw=true)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen20.PNG?raw=true)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen21.PNG?raw=true)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen22.PNG?raw=true)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen23.PNG?raw=true)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen24.PNG?raw=true)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen25.PNG?raw=true)

Let's write down the paths to the suspicious files, the sizes of the files themselves, and the hashes. This will be useful for further analysis of the files in VirusTotal and AbuseIPDB. And of course, we will add these hashes to the incident card in TheHive.

**Paths to suspicious files:**

`C:\Users\Administrator\AppData\Local\Temp\T1106.exe`

`C:\Users\Administrator\AppData\Local\Temp\T1140_calc_decoded.exe`

`C:\Users\Administrator\Downloads\Financial_Report_Q1_2025.exe`

`C:\Users\Administrator\Downloads\Salary_Update.exe`

`C:\Users\Administrator\Downloads\nc.exe`

`C:\Users\Administrator\Downloads\nmap-7.95-setup.exe`

`C:\Users\Administrator\Downloads\sublime_text_build_4200_x64_setup.exe`

`C:\Users\Administrator\Downloads\Sysmon\Sysmon.exe`

`C:\Users\Administrator\Downloads\Sysmon\Sysmon64.exe`

`C:\Users\Administrator\Downloads\Sysmon\Sysmon64a.exe`

`C:\Users\Administrator\Downloads\T1036\2.dll`
	
**Sizes and hashes of suspicious files:**

`T1106.exe`:size-4608, hash:`af48a76432e7aaf77f234c4009b1c6d9`

`T1140_calc_decoded.exe`: size 27648, hash:`dead69d07bc33b762abd466fb6f53e11`

`Financial_Report_Q1_2025.exe`: size 95904, hash: `c164c1292b187895a44d6ded60391f75`

`Salary_Update.exe`: size 670, hash:`236420e9795b30db8bf9e7db4b74610e`

`nc.exe`: size 38616, hash:`5dcf26e3fbce71902b0cd7c72c60545b`

`nmap-7.95-setup.exe`: size 33969480, hash:`bd457e3fb19a7f127a23369e70ee84fc`

`sublime_text_build_4200_x64_setup.exe`: size: 16200128, hash: `ef560fd427fcd7a81fe00084b99af5c1`

`Sysmon.exe`: size: 8480560, hash: `7bb6c3a0f6c177784f5c64db992f5412`

`Sysmon64.exe`: size: 456324, hash: `7663c565bf28115506cb7ebd1da389e0`

`Sysmon64a.exe`: size: 4993440, hash: `b2f954c42948c64edaee9ded4909de5b`

`2.dll` - it's a Mimicatz file (which can also be considered a suspicious process, as .dll files are system files and should not be located in the Downloads folder). size:10240, hash: `6349c0af16bbd22b44bcbbe25c19d82d`

### Analyse Windows.EventLogs.Cleared

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen26.PNG?raw=true)

We see an event with EventID=1102, i.e. cleaning the Security log. Then there are 4 events with EventID=104, i.e. cleaning the System log.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen27.PNG?raw=true)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen28.PNG?raw=true)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen29.PNG?raw=true)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen30.PNG?raw=true)

The account that performed the cleanup: *DEMO\administrator*
The names of the cleaned logs: `Security`, `System`, `Application`, `Windows PowerShell`, `Microsoft-Windows-PowerShell/Operational`.
The attacker cleared Windows Event Logs to hide the activity of an intrusion. Windows Event Logs are a record of a computer's alerts and notifications.

# Incident Registration & Case Management (TheHive Integration)

*Remark:* Please ignore the timestamp, as there are some issues with TheHive. Of course, this should not happen during a real incident investigation at SOC, as the timeline of the attack plays a crucial role. However, we will create a timeline of the attack later.

**Note**: all file hashes and suspicious ip-addresses we must to add in *Observables* in TheHive.

We must create an incident card, tasks, and observables based on the artifacts we found in Velociraptor.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen31.PNG?raw=true)

Let's create the following incident card in TheHive. Ignore the date on the card. In the actual incident, enter the date (timestamp) that represents the earliest action related to the alert. Set the criticality level to High because the Financial Report document from the host running the malicious file has been compromised.
About tags:
-**Lateral Movement** - `TA0008` in Mittre Att&ck.Attacker explored the system and found a valuable file with information, which he later exfiltrated.

-**Exfiltration** - `TA0010` in Mittre Att&ck. As i mentioned before, attacker was hiding his activity in a system.

## Tasks

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen32.PNG?raw=true)

The first step is to isolate the host from the network.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen33.PNG?raw=true)

In artifact Windows.System.TaskSheduler in Velociraptor we saw \SystemHealthMonitor with this powershell script: 
```
-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File "C:\Windows\Temp\update.ps1"
```

In the next task we need to analyse the malicious powershell script, that included in `Salary_Update.exe` attachment to a suspicious email.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen34.PNG?raw=true)

Then create a task to analyse malicious attachment `Salary_Update.exe`. In the description, provide the file path and file hash.


![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen35.PNG?raw=true)

Now let's analyze the suspicious IP address that our host 10.0.0.10 was connected to (again, we go back to Velociraptor EDR and look at Windows.Network.Netstat ). In it, we see the host connected to an IP address that is not part of our domain. Let's create the following task:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen36.PNG?raw=true)

In the further course of the analysis, as I mentioned, a malware-initiated autorun which was found in HashRunKeys. It needs to be disabled because the malware file will automatically load, causing damage to the infrastructure. To prevent this, create the next task:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen37.PNG?raw=true)

Next, we will analyze the files found in Windows.Detection.BinaryHunter to find out which malicious files were also executed along with the original malware. These file hashes should also be added to the *Observables* for analysis! :

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen38.PNG?raw=true)

As a conclusion, you can add infrastructure analysis and search for other compromised hosts, assess the scale of infrastructure infection, reset the passwords of all domain user accounts, block IoC in all security systems, and remove persistence mechanisms with a save in the SOC:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen39.PNG?raw=true)

**Note** that in the time when screenshot was taken, I didn't add all observables and TTPs

## Observables

Now that we have set up the tasks to investigate, we can add observables to analyze the behavior of malicious files, scripts, and IP addresses.

*Remark:* I forgot to enable the “IsIoC” icon. In a real incident, if it's really necessary, you should enable it. This will help analysts focus on the details of incident.

These are the observables which I added in an incident card:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen40.PNG?raw=true)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen41.PNG?raw=true)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen42.PNG?raw=true)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen43.PNG?raw=true)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen44.PNG?raw=true)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen45.PNG?raw=true)

Please note that any Sysmon files which are located in the Downloads folder are almost always suspicious. The only exception is when we installed the file ourselves from the official Microsoft website, but in our case, we didn't download the file ourselves, and instead downloaded a malicious file. In this situation, it is essential to scan the Sysmon files in the Downloads directory.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen46.PNG?raw=true)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen47.PNG?raw=true)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen48.PNG?raw=true)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen49.PNG?raw=true)

## TTPs in Mittre Att&ck

Now, based on the tasks we set for the incident, we will determine (of course, using the timeline) the tactics and techniques that are relevant to the incident. In SOC, this approach is crucial because it transforms disparate events (alerts) into a structured model of the attacker's behavior. Mapping to MITRE ATT&CK helps identify missed attacker actions, assess the actual damage, and, most importantly, understand which correlation rules or log sources have failed.

At the very beginning, a malicious attachment was opened from a phishing email( because sender's domain: “deemo.lab”, while our domain is "demo.lab").This allowed the attacker  to gain access to a victim's host.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen50.PNG?raw=true)

In this case, the T1566 technique in Mittre Att&ck is suitable. The sub-technique will be T1566.001, because there was a malicious attachment in the email. Add this technique to a incident card in TheHive:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen51.PNG?raw=true)

Next, the host was initially infected, or rather, the user launched the malicious file `Salary_Update.exe`

Since this is a malicious file that was launched by the user, let's explore the tactics in the Execution -> User Execution -> Malicious File section.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen52.PNG?raw=true)

Add this tactic to an incident card:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen53.PNG?raw=true)

We also note the parent process, namely the execution of the salary_wrapper.ps1 and update.ps1 PowerShell scripts to download additional software and exfiltrate data. Then in Mittre Att&ck, this will be a tactic related to executing a powershell script

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen54.PNG?raw=true)

Let's add this tactic to the incident card in TheHive:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen55.PNG?raw=true)

And the tactic, which connects with data exfiltration ( in our case this is a Financial report):

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen56.PNG?raw=true)

We know that the attacker has remotely connected to the control server aka C2 server in order to compromise the report itself (this can be found in the Windows.Network.Netstat artifacts in Velociraptor EDR)

Make sure to add this technique to the incident card:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen57.PNG?raw=true)

Remember about this artefact in Velociraptor EDR:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen58.PNG?raw=true)

As I mentioned, powershell script update.ps1 added an entry to the registry's startup list to ensure automatic launch when the user logs in. This is associated with persistence in a system. Let's find tactic which associated with that in Mittre Att&ck:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen59.PNG?raw=true)

Let's add that in an incident card:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen60.PNG?raw=true)

Then remember that in **Windows.EventLogs.Cleared** in Velociraptor EDR was found deleting logs after actions in the system. The following tactics in Mittre Att&ck are associated with this action:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen61.PNG?raw=true)

Let's add this technique to the incident card:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen62.PNG?raw=true)

Don't forget that the attacker bypassed the security policy

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen63.PNG?raw=true)

Therefore, the following tactic  in Mittre Att&ck is the best in this case:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen64.PNG?raw=true)

Add this tactic to the incident card:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen65.PNG?raw=true)

# Intelligence Enrichment & Automated Triage (Cortex SOAR)

**Note:** *"It should be noted that in my SOC environment, there are no dedicated Responders integrated with the NGFW or other technical security controls (such as EDR, email gateway, or web proxy). Therefore, while it is a best practice to automatically feed suspicious indicators (e.g., a malicious IP address) from the Analyzers to the NGFW block list, this capability is currently not available in my setup."*

First, you need to create a cortex server that our TheHive will integrate with. From the administrator account, go to Platform management and add a server:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen66.PNG?raw=true)

Next, we login to Cortex as an administrator, go to the same organization where we've deployed our server, and create an account for integration with TheHive. Make sure to create an API key for that account, which i mentioned, to connect our analyzers to TheHive. Then, we log in to this account to add analyzers and responders.
Next, we need to add the analyzers themselves. To do this, we create accounts in AbuseIPDB and VirusTotal and save the API keys. Next, go to our organization in the “Organizations” tab, select “Analyzers”, and choose the analyzers you need. Then, insert the API key from the account of the analyzer you selected:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen67.PNG?raw=true)

Well, insert the API key from the analyser which we have chosen. In my case, it will be AbuseIPDB and VirusTotal.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen68.PNG?raw=true)


![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen69.PNG?raw=true)

After adding it, go to the incident card in **Observables** and run:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen70.PNG?raw=true)

We can see that this ip address is malicious. This is shown to us by the analysis of the ip address itself from AbuseIPDB. Just in case, let's check the ip of the compromised host. This is because it is possible for a virus to lower the reputation of the ip address itself: sending spam, participating in DDOS attacks, and so on.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen71.PNG?raw=true)

Talking about hash analysis. I can recommend choosing this type of analyzer from VirusTotal, because it will be convenient to visually see the reputation of the file:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen72.PNG?raw=true)

Run all the analyzers that we have configured. Here is the result of analyzing hashes and IP addresses:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen73.PNG?raw=true)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Incident%20Response%20Lifecycle:%20From%20Phishing%20Detection%20to%20Automated%20Remediation/Screenshots/screen74.PNG?raw=true)

# Incident Remediation, Framework Mapping & Strategic Recommendations

## Cyber Kill Chain Analysis
To better understand the attacker's progression, the incident has been mapped against the Lockheed Martin Cyber Kill Chain. This model highlights the critical stages where the attack could have been disrupted.

| Phase | Action Observed | Detection/Prevention Gap |
| :--- | :--- | :--- |
| **1. Reconnaissance** | Domain spoofing (`deemo.lab`) to impersonate internal support. | Lack of look-alike domain monitoring. |
| **2. Weaponization** | Creation of `Salary_Update.exe` (malicious dropper) and `update.ps1`. | Attachment not detonated in a sandbox. |
| **3. Delivery** | Spear-phishing email sent to `admin@demo.lab`. | Weak SPF/DMARC or Email Gateway policy. |
| **4. Exploitation** | User execution of `.exe` from the Downloads folder. | ASR rules not enforced on workstations. |
| **5. Installation** | Persistence via Registry Run Keys and Scheduled Tasks. | Late detection of `powershell.exe` abuse. |
| **6. Command & Control** | Reverse shell established to `104.208.16.95:443`. | Missing outbound traffic filtering/TLS inspection. |
| **7. Actions on Obj.** | Exfiltration of `Financial_Report_Q1_2025.exe` & log clearing. | Absence of DLP and real-time SIEM alerts for log deletion. |

---

## Post-Incident Recovery & Remediation
Following the identification and enrichment of IoCs, the following containment and eradication steps were executed:

1.  **Host Isolation**: The victim host `10.0.0.10` was logically isolated via VLAN/Micro-segmentation.
2.  **Persistence Removal**: 
    * **Scheduled Tasks**: Deleted via PowerShell: `Unregister-ScheduledTask -TaskName "SystemHealthMonitor" -Confirm:$false`.
    * **Registry Keys**: Removed `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` entry.
3.  **Threat Eradication**: 
    * Terminated active PIDs: `2744`, `7076`, `6468`.
    * Sanitized `\Downloads` and `\Temp` directories.
4.  **Credential Hardening**: Mandatory password reset for `DEMO\administrator` due to Mimikatz detection (`2.dll`).

---

## MITRE ATT&CK Matrix Mapping
Mapping adversary behavior to identify specific visibility gaps.

| Tactic | Technique ID | Technique Name | Observation / Evidence |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1566.001 | Phishing: Malicious Attachment | Email from `support@deemo.lab` with `Salary_Update.exe`. |
| **Execution** | T1204.002 | User Execution: Malicious File | Manual execution from the Downloads folder. |
| **Execution** | T1059.001 | PowerShell | Usage of `.ps1` for payload delivery and C2. |
| **Persistence** | T1547.001 | Registry Run Keys / Startup Folder | Persistence via `HKCU\...\Run` key. |
| **Persistence** | T1053.005 | Scheduled Task | Malicious task `\SystemHealthMonitor` created. |
| **Defense Evasion** | T1070.001 | Indicator Removal: Clear Logs | **EventID 1102** and **104** (Security/System logs). |
| **Defense Evasion** | T1562.001 | Impair Defenses | Use of `-ExecutionPolicy Bypass` and `-WindowStyle Hidden`. |
| **Credential Access**| T1003.001 | OS Credential Dumping | Detection of Mimikatz components (`2.dll`). |
| **Command & Control**| T1071.001 | Application Layer Protocol | Reverse shell to `104.208.16.95` over port 443. |
| **Exfiltration** | T1041 | Exfiltration Over C2 Channel | Transfer of `Financial_Report_Q1_2025.exe`. |

---

## SOC Recommendations

### Short-Term (Immediate Hardening)
* **ASR Rules**: Implement Microsoft Defender ASR rule: "Block executable content from email client and webmail".
* **PowerShell Hardening**: Enforce **Constrained Language Mode** to limit malicious script capabilities.
* **Log Centralization**: Forward all Event Logs to a central SIEM to ensure audit trails survive local log clearing.

### Long-Term (Strategic Improvements)
* **Email Security**: Deploy DMARC/SPF/DKIM and look-alike domain protection.
* **Detection Tuning**: Create high-priority alerts for **EventID 1102** (Log Cleared) and **EventID 4698** (Scheduled Task Created).
* **Zero Trust**: Restrict workstation-to-internet traffic to essential ports only via a proxy/NGFW.

## Conclusion
The simulation demonstrated a complete incident lifecycle. By integrating **Velociraptor**, **TheHive**, and **Cortex SOAR**, the investigation transitioned from a simple alert to a full forensic reconstruction. Automation in Cortex reduced MTTR, while MITRE/Kill Chain mapping provided the necessary intelligence to improve organizational defense posture.
