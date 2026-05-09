# 🛡️ Windows Persistence Analysis & Incident Response Lab 

## Project Overview
This lab demonstrates a practical end-to-end security workflow: emulating adversary persistence techniques using the **Atomic Red Team** framework, identifying traces in a Windows environment, and performing manual incident response (IR).

The lab focuses on identifying unauthorized system changes and correlating host-based artifacts with network activity.

---

## 🛠 Technical Stack
* **Framework:** [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) (Mapped to MITRE ATT&CK)
* **Environment:** Windows Server, PowerShell
* **Analysis Tools:** Windows Event Viewer, Registry Editor, Netstat, Tasklist
* **MITRE ATT&CK Techniques Studied:** 
    * **T1547.001:** Registry Run Keys / Startup Folder
    * **T1543.003:** Create or Modify System Process (Windows Service)

---

## 🚀 Execution Phase (Attack Emulation)

To simulate a realistic threat, I used the `Invoke-AtomicRedTeam` module to establish persistence.

1. **Environment Setup:**
  
   ```powershell
   Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
   ```
2. **Emulate an attack via Powershell script:**
   ```powershell
   Invoke-AtomicTest T1547.001-1
	 ```
  
   ![Importing the module and executing the T1547.001 atomic test](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Windows%20Persistence%20%26%20Incident%20Response%20Hands-on%20Lab/Pictures/picture_1.PNG)
---
## 🔍 Detection & Analysis Phase
  
1. **Registry Forensics** 

	```
		Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
	```
  
  ![Detection of the "Atomic Red Team" persistence artifact in the Registry](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Windows%20Persistence%20%26%20Incident%20Response%20Hands-on%20Lab/Pictures/picture_2.PNG)
  
Adversaries often use `"Run"` keys to maintain access after a reboot. I performed a manual check of the registry hives to identify suspicious entries.
2. **Event Log Analysis**

Monitoring for new service installations is a critical detection strategy. By filtering the System log for **Event ID 7045**, I discovered an unauthorized service.
* **Service Name:** `hacker`
* **Service File Name:** `c:\tools\script.bat`

![Identifying the malicious service installation in Event Viewer.](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Windows%20Persistence%20%26%20Incident%20Response%20Hands-on%20Lab/Pictures/picture_3.PNG))

3. **Script & Network Analysis**

I analyzed the identified batch file to understand its intent.The script was designed to use **Netcat(nc.exe)** for outbound communication:
		
`start /b nc.exe google.com 80`
  
![Analysis of the malicious script content.](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Windows%20Persistence%20%26%20Incident%20Response%20Hands-on%20Lab/Pictures/picture_4.PNG)

Using `netstat -b` , I confirmed an established connection to a remote host initiated by the rogue process.

![Correlating the malicious process with active network connections.](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Windows%20Persistence%20%26%20Incident%20Response%20Hands-on%20Lab/Pictures/picture_5.PNG)

![List of processes on a host.](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Windows%20Persistence%20%26%20Incident%20Response%20Hands-on%20Lab/Pictures/picture_6.PNG)

----
## 🛡️ Remediation & Response (IR)
Once the threat was validated, I executed a remediation plan to contain the incident and restore the system to a known good state.

1. **Containment:** Terminated the malicious process:

`taskkill /PID <PID> /F`

2. **Eradication:** Removed the persistence mechanisms (Registry key and Windows Service):

`sc delete hacker`

3. **Recovery:** Deleted the malicious artifacts (`nc.exe`, `script.bat`) from the filesystem:

![Successful termination of the process and deletion of the service.](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Windows%20Persistence%20%26%20Incident%20Response%20Hands-on%20Lab/Pictures/picture_7.PNG)

----
## 📈 Key Takeaways
* Developed hands-on experience mapping system artifacts to the MITRE ATT&CK framework.
* Mastered the use of native Windows tools for initial triage and threat hunting.
* Refined the incident response lifecycle: from detection to full remediation.
