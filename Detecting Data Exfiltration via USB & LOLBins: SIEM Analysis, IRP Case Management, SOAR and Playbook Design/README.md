# 🛡️ Detecting Data Exfiltration via USB & LOLBins: SIEM Analysis, IRP Case Management, and SOAR Playbook Design

## 📌 Project Overview

This laboratory simulates a real-world security incident investigation within the **Demo Lab** corporate network. The project covers the entire **Incident Response Lifecycle**, from initial detection in ELK SIEM to automated enrichment via Cortex SOAR and formal case management in TheHive.

The scenario involves a **compromised Domain Admin account**, the use of **LOLBins (Living off the Land Binaries)** for evasion, and data exfiltration via a physical USB device.

## 🛠️ Technical stack

* **SIEM:** ELK Stack (Elasticsearch, Kibana)
* **IRP:** TheHive (Case Management)
* **SOAR:** Cortex (Automation & Observables Analysis)
* **External Intelligence:** VirusTotal API, AbuseIPDB API
* **Frameworks:** MITRE ATT&CK, NIST Incident Response Lifecycle

# 🕵️ Phase 1: Detection & Log Analysis (ELK SIEM)
Let's move to ELK and load the logs.
First, let's write a KQL query to detect this activity outside of business hours:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_1.PNG)

We can see that the incident was confirmed. Indeed, such an event occurred. Let's move on to this event in the log:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_2.PNG)

We see a very important thing: a very important confidential file was read, and it was read from an unknown IP address that we previously noticed. We see that the file.share_name is “Confidential” and the Event ID is 4663. This means that an important document was compromised from the compromised host 10.0.0.10 (this host has access to confidential data in the “Confidential” shared folder).

Let's take a look at all the activities that occurred from a suspicious IP address:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_3.PNG)

We can see that the attacker used the shared folder and viewed confidential documents. We can also see that the Finance shared folder has the following access settings: **“Everyone:FullControl”**. This is a very **critical vulnerability!** Anyone can access this folder, and anyone can manage the files (including deleting and modifying them). This vulnerability can be exploited by an attacker to encrypt files, install malware, and more.

 Now, let's explore different actions that can be performed on files. We can write the following KQL query and see the results:
 
![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_4.PNG)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_5.PNG)

The attacker gained access to the following files: Confidential.docx, Budget.xlsx, Report.docx, and Presentation.pptx.

I will mark this log:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_6.PNG)

Event ID 4648 is generated when a process attempts an account logon by explicitly specifying that account’s credentials. This most commonly occurs in batch-type configurations such as scheduled tasks, or when using the “RUNAS” command. 

Since there is a suspicion that the host with ip:10.0.0.6 is compromised, let's look at the events related to this ip address and the server with ip:10.0.0.10:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_7.PNG)

We can see that the files Budget.xlsx and Report.docx. were accessed from ip:10.0.0.6, which may also indicate suspicious activity.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_8.PNG)

We note that the rundll32.exe file has been modified, and the attacker has used the LOLBIN file located on our host. Additionally, it is important to note that the path to C:\Windows\System32\drivers\usbhub.sys, disk.sys, and USBSTOR.sys has been specified. This indicates that the attacker has connected a USB drive to the file server.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_9.PNG)

Let's take a look at the logs and see that the attacker has connected a flash drive. We know that when we connect a USB drive to a device, a new drive appears on the computer with a non-standard letter in the lexicographic order, such as "E".

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_10.PNG)

Let's pay attention to this log. As we can see, by selecting event.action:”FileCopy” beforehand, we can see that sensitive documents were copied from the file server and sent to the E:\Stolen\ folder, which also confirms the hypothesis about the external storage device.
Let's also note a very important detail:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_11.PNG)

The command which listed here indicates the launch of suspicious processes such as rundll32.exe, usbinst.dll, and InstallUSBDevice. Please note that usbinst.dll performs low-level work to establish communication between the computer and the USB device for encryption/signature purposes.

However, it is important to note that the account was logged out at 17:00, indicating that the active phase of the attack had ended.

# 📋 Phase 2: Incident Response & Case Management (TheHive IRP)

To structure all the artifacts we found and build a chain of events, find tactics and techniques from MITRE ATT&CK, and help SOC analysts analyze this incident, we will use IRP TheHive:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_12.PNG)

Let's create an incident card. In our case, the administrator account from the “Demo.lab” domain was compromised. Make sure to specify that sensitive data was accessed and access rights were changed.

Now let's move on to the **Tasks** themselves. At the very beginning, it is necessary to block the IP address from which the administrator account was compromised, otherwise the attack may escalate and worsen the situation. Make sure to include this in the **Tasks**:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_13.PNG)

Next, you need to disable the administrator account, as we know that it has been compromised, and the administrator always has elevated privileges, allowing an attacker to perform critical actions with this account. Add this to Tasks:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_14.PNG)

Next, you need to check the active sessions of the administrator account, because an attacker could compromise another host in the company and use it to compromise the administrator account. Add it to Tasks.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_15.PNG)

Next, we need to analyze the data from APPSERVER to see if the attacker could have left traces there. We also need to determine what data was compromised from the host. Add this to Tasks.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_16.PNG)

Recall that the attacker changed permissions on a folder containing sensitive data, making it public. This means they changed permissions on the shared folder in Active Directory within the domain. Therefore, we need to analyze Active Directory and eliminate access to the shared folder containing sensitive data. Add this to Tasks:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_17.PNG)

Next, you need to check whether the attacker has been moving around the network. It's especially important to understand that the attacker has compromised the administrator account, and you need to check whether they've accessed other accounts in the domain. Add this to Tasks:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_18.PNG)

Thus, we got 6 Tasks:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_19.PNG)

Now let's add **Observables**

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_20.png)

Of course, we need to analyze the attacker's IP address to see if it's associated with various APT groups. We also need to check the IP addresses of the administrator and one of the users. We'll also analyze the files compromised by the attacker through the administrator account, as well as the Finance folder.

Next, we'll add tactics and techniques from **Mitre Att&ck:**

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_21.png)

Let's look at each of the techniques:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_22.png)

Tactic **T1133** was not chosen without reason. Due to the fact that the ELK logs did not reveal how the compromise occurred, there is a suspicion that the compromise occurred through remote services (for example, VPN, Citrix, and others).

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_23.png)

The **T1020** technique would be very suitable here, because the attacker was extracting sensitive documents.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_24.png)

The **T1048** technique is suitable here, as data exfiltration occurred via a file server. The specific network protocol is unknown, but it was most likely either `SMB` or `FTP`.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_25.PNG)

**T1562.001** or **T1685** would be a good choice here, as the attacker was changing permissions on a folder containing sensitive data in `Active Directory`.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_26.PNG)

Technique **T1078.002** is a good fit since the administrator account was compromised.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_27.PNG)

The **T1005** technique would be suitable here, since the attacker was extracting data onto a flash drive.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_28.PNG)

The **T1039** technique would also work here, since we know that the files were downloaded from a file server.

# ⚡ Phase 3: Security Stack Integration & Automated Enrichment (Cortex, TheHive, VirusTotal & AbuseIPDB)

Now we need to analyze the artifacts we found during the incident investigation. Since we don't have access to the files, but we have IP addresses, we'll analyze them.

At first, we need to create an administrator account and then create an organisation:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_29.PNG)

Now we need to add an organization, let's call it the “practicum” organization.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_30.PNG)

Next, we go to our previously created organization and click `Add user`.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_31.PNG)

Add the user "SOC-admin" and grant them the following privileges: `read`, `analyze`, and `orgadmin`. After this, we'll see the active user in our organization:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_32.PNG)

Click “Create API key”, and then click “Reveal” to copy our key and then use it for integration with IRP (I advise you to save this key somewhere, because later we will have to insert it into IRP).

Now let's go to `TheHive` interface under the administrator account and go to platform management.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_33.PNG)

Then click on the “+” sign next to “Servers”, a window should appear on the right.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_34.PNG)

It should look like this. You also need to remove the certificate check, but if you have one, it's better to add it; it will improve security. I won't be adding one for this lab. Then click "Add server," and now we've configured the integration of the two systems using an API key!

Now we need to add the analyzers themselves. To do this, in Cortex SOAR, go to the SOC-admin account and navigate to the analyzers section:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_35.PNG)

As part of the lab, we'll simply add integration with AbuseIPDB and VirusTotal to check IP addresses, since we don't have actual files downloaded by the attacker.

Now, to implement VirusTotal and AbuseIPDB, you need to create accounts on the VirusTotal and AbuseIPDB websites and save the API keys for each.

In Cortex SOAR, go to "Organizations," select "Analyzers," then select "VirusTotal_GetReport_3_1," as it's designed for analyzing the reputations of file hashes, IP addresses, etc.
We add the server name, URL, and our saved API key.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_36.PNG)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_37.PNG)

Configure as shown in the screenshot, and also remove "TLP check" and "PAP check." Be sure to enter the API key we created in VirusTotal.
Do the same for AbuseIPDB. I chose AbuseIPDB_2_0:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_38.PNG)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Detecting%20Data%20Exfiltration%20via%20USB%20%26%20LOLBins%3A%20SIEM%20Analysis%2C%20IRP%20Case%20Management%2C%20SOAR%20and%20Playbook%20Design/Pictures/picture_39.PNG)

Click on Analyzers, select AbuseIPDB and VirusTotal and get the result.

# 📖 Phase 4: Incident Response Playbook (SOP)

## Stage 1: Initial Assessment and Verification (0-10 minutes)

### *Step 1:*  Confirmation of the incident
		1. Check alert details in SIEM
 	   2. Determine if the alert is related to scheduled work or known activity
		3. Evaluate the alarm as false if the number of events is below the set threshold
    	4. If in doubt, escalate the incident to the second line of support (L2) for further analysis. Do not close the incident until the legitimacy of the actions is fully confirmed.
      
### *Step 2:*  Context check
		1. If the login time is non-standard, check the user's work schedule
 	   2. If the location is unusual, check:Employee business trips and VPN usage
     
## Stage 2: Risk analysis and assessment (10-30 minutes)

### *Step 1:* Timeline analysis
		1. Collect a timeline of account activity over the last 24 hours
    	2. Determine what actions were performed after logging in
### *Step 2:* Evaluating file storage activity
		1. Check for changes in file resource settings
    	2. Check which files have been opened, modified, or deleted
### *Step 3:* Determining the risk category
		 Classify the incident by risk level (low/medium/high):
		- Low: Single login during off-hours from a known region
		- Medium: Multiple logins or access to non-standard files
		- High: Access from an unknown region with configuration changes
## Stage 3: Containment and Response (30-60 minutes)
### *Step 1:* Additional verification
		1. Contact the user via a secure channel (phone or corporate messenger). Sharing passwords, tokens, or account details via email is prohibited.
    	2. If the user confirms the action, close the incident as a false positive.
### *Step 2:* Responding to a confirmed incident
		1. If the actions are not confirmed by the user or there is no response, block the account
    	2. Check other active user sessions
        3. Force quit sessions
## Stage 4: Investigation (1-4 hours)
### *Step 1:* Deep activity analysis
		1. Isolate the system from the network. Before any state changes (shutdown/reboot), collect artifacts: a RAM dump and a disk copy for subsequent analysis.
    	2. Check associated IP addresses
### *Step 2:* Impact Analysis
		1. Determine what data was read, modified, or copied
    	2. Assess the criticality of the affected data
### *Step 3:*  Checking for indicators of compromise
		1. Check for new or changed accounts
    	2. Check for changes in group policies
        3. Scan your system for malware
## Stage 5: Recovery (4-24 hours)
### *Step 1:* Resetting credentials
		1. Reset the password of the affected account
    	2. Make sure the temporary account lock has been lifted
### *Step 2:* Checking for changes
		1. Check and roll back unauthorized changes to file permissions
    	2. Restore file server configuration
### *Step 3:* Final scan
		1. Perform a full system scan
    	2. Check logs for any residual suspicious activity
## Stage 6: Learning and improving (post-incident)
### *Step 1:* Incident Analysis
		1. Conduct a mandatory root cause analysis. Determine how the breach occurred: through phishing, a software vulnerability, or password theft.
    	2. Conduct a retrospective analysis of the incident
### *Step 2:* Improving control
		1. Update the whitelist of allowed countries
    	2. Set up multi-factor authentication for privileged accounts
### *Step 3:* Updated playbook and rules
		1. Update thresholds in correlation rules
    	2. Improve response procedures
      
      
# 🎯 Phase 5: Adversary Tactic Mapping (MITRE ATT&CK Framework)
To standardize the investigation and align with industry best practices, I mapped the attacker's behavior to the **MITRE ATT&CK Matrix**. This process allows for a better understanding of the adversary's lifecycle and helps in developing more robust detection rules.

| Tactic | Technique ID | Technique Name | Evidence / Observation |
| :--- | :--- | :--- | :--- |
| **Initial Access** | **T1078.002** | Valid Accounts: Domain Accounts | Compromise of the `Demo.lab\administrator` account. |
| **Persistence** | **T1133** | External Remote Services | Suspected entry via remote services (VPN/Citrix) due to anomalous login source. |
| **Defense Evasion** | **T1562.001** | Impair Defenses: Disable or Modify Tools | Unauthorized modification of file permissions in Active Directory ("Everyone: FullControl"). |
| **Defense Evasion** | **T1218.011** | System Binary Proxy Execution: Rundll32 | Use of `rundll32.exe` (LOLBin) to load `usbinst.dll` for malicious activity. |
| **Discovery** | **T1039** | Data from Network Shared Drive | Discovery and access of sensitive documents on the centralized file server. |
| **Collection** | **T1005** | Data from Local System | Exfiltration of sensitive data to a physical USB device (Volume `E:\`). |
| **Exfiltration** | **T1020** | Automated Exfiltration | Bulk copying of `Confidential.docx`, `Budget.xlsx`, and other documents to `E:\Stolen\`. |

### 🧠 Strategic Impact
Mapping these techniques identified critical gaps in the current security posture:
1. **Privileged Access Management (PAM):** Lack of MFA for domain administrators.
2. **Endpoint Control:** Unrestricted use of USB storage devices on sensitive servers.
3. **Data Loss Prevention (DLP):** Absence of alerts for bulk file copying from "Confidential" shares.

# 📈 Executive Summary

*   **Incident:** Compromise of a Domain Admin account followed by data exfiltration via USB.
*   **Root Cause:** Overly permissive share permissions (Everyone: FullControl) and lack of Multi-Factor Authentication (MFA).
*   **Recovery:** Successfully identified the full list of compromised documents, revoked unauthorized access, and implemented a 6-stage response playbook.
*   **Business Impact:** Prevented further data loss and identified critical infrastructure gaps.
