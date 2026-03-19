# :shield: Hybrid Attack Simulation & Log Correlation Study

## Scenario
There are signals of suspicious activity in the company. They say that someone is conducting attacks inside the network, trying to gain unauthorized access and intercept credentials through Kerberoasting. As a security specialist, you need to conduct "training" attacks in order to be able to track them in the logs, just as a real attacker would do.


## Virtual Machines
* **10.0.0.21** — Ubuntu 22.04: Installed Wireshark and auxiliary utilities for attacks and scanning: Nmap, Hydra, Impacket. ***Attacker's host***
* **10.0.1.254** — Ubuntu 22.04: With Snort and iptables installed. ***Victim's host***
* **10.0.0.10** — Windows Server 2019: AD domain controller, DNS. ***Victim's host***

## Setting up logging
First, you need to configure logging on the victim's computer to see all the hacker's attacks.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Hybrid%20Attack%20Simulation%20%26%20Log%20Correlation%20Study/Pictures%20for%20Hybrid%20Attack%20Simulation%20%26%20Log%20Correlation%20Study.md/screen_1.PNG)


Click on “Default Domain Controllers Policy” right mouse button, then click ”edit”.Then click on “Computer Configuration” and then follow the path shown in the screenshot:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Hybrid%20Attack%20Simulation%20%26%20Log%20Correlation%20Study/Pictures%20for%20Hybrid%20Attack%20Simulation%20%26%20Log%20Correlation%20Study.md/screen_2.PNG)

Here we need to configure audit policies.Then configure like that:


### Turn on Account Logon:

**Audit Kerberos Authentication Service** → `Success`, `Failure`.

**Audit Kerberos Service Ticket Operations** → `Success`, `Failure`.
### Turn on Logon/Logoff:
**Audit Logon** → `Success`, `Failure`.
### Turn on Account Management:
**Audit User Account Management** → `Success`, `Failure`.

**Audit Computer Account Management** → `Success`, `Failure`.
### Turn on Detailed Tracking:
**Audit Process Creation** → `Success`.

After that click on powershell and write this:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Hybrid%20Attack%20Simulation%20%26%20Log%20Correlation%20Study/Pictures%20for%20Hybrid%20Attack%20Simulation%20%26%20Log%20Correlation%20Study.md/screen_3.PNG)

If everything is alright, we will see that.

## PART 1 “Brute Force attack for Windows credentials”
Let’s move to host 10.0.0.21 ( hacker) and then use Hydra to brure force password.
Here you can see that we use wordlist: passwords.txt which located in a Desktop. So after brute you can see login and password.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Hybrid%20Attack%20Simulation%20%26%20Log%20Correlation%20Study/Pictures%20for%20Hybrid%20Attack%20Simulation%20%26%20Log%20Correlation%20Study.md/screen_4.PNG)

Let’s check windows logs in event viewer and then understand how did this happen. We need to check Event ID 4624, because this Event ID is responsible for successful authentication (mark: attack we started at 10:34:44, so we need to check successful logs starting from this time):

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Hybrid%20Attack%20Simulation%20%26%20Log%20Correlation%20Study/Pictures%20for%20Hybrid%20Attack%20Simulation%20%26%20Log%20Correlation%20Study.md/upd.PNG)

Here we can see that at 10:34:45 we found a password. Because at this time we successfully authenticated to a system.
Let’s check Event ID 4625, this Event ID is responsible for failed authentication.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Hybrid%20Attack%20Simulation%20%26%20Log%20Correlation%20Study/Pictures%20for%20Hybrid%20Attack%20Simulation%20%26%20Log%20Correlation%20Study.md/screen_6.PNG)

Here we can see that starting at 10:34:44 we see many failed authentication attempts. It means that hacker was trying to guess passwords to log into the system (brute force attack).

## PART 2 “Kerberoasting”
Let’s move to an attacker’s machine and then write this to a terminal

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Hybrid%20Attack%20Simulation%20%26%20Log%20Correlation%20Study/Pictures%20for%20Hybrid%20Attack%20Simulation%20%26%20Log%20Correlation%20Study.md/kerberoasting.PNG)

This command means that we will attack kerberoasting, using login and a password, to recieve service credentials. At first, we made a LDAP query to find all users with SPN, and then requested a **TGS ticket**, specifying the found user `"kerberoast_test1"`, `“kerberoast_test2”` and other.After that we see password hashes(i’ve hidden them for safety).We can also decrypt them via ***“John The Ripper”*** and wordlist.Script, which i printed in a console, is a python script, like ***“Impacket”***
Then let’s analyse in a windows what’s happened. For that we need to check in event viewer kerberos logs.

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Hybrid%20Attack%20Simulation%20%26%20Log%20Correlation%20Study/Pictures%20for%20Hybrid%20Attack%20Simulation%20%26%20Log%20Correlation%20Study.md/kerberos_log.PNG)

Here we can see that was a request for kerberos service ticket from `kerberoast_test2`, and other account names (i mean `kerberoast_test3`, `kerberoast_test4` and `kerberoast_test5`).

## PART 3 "Scanning"

Before scanning we need to configure a VM with snort server. How to install and configure snort you can read here ->[Guide](https://www.zenarmor.com/docs/linux-tutorials/how-to-install-and-configure-snort-on-ubuntu-linux) After installing you need to add nmap detecting rule to a snort.rules file. Then launch snort. Let’s attack and analyze!
At first, let’s scan an victim snort server:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Hybrid%20Attack%20Simulation%20%26%20Log%20Correlation%20Study/Pictures%20for%20Hybrid%20Attack%20Simulation%20%26%20Log%20Correlation%20Study.md/screen_7_nmap.PNG)

I didn’t show all ports but we need to understand  that in a real situation here can be open ports and in that case attacker can attack to these ports.
So now we need to analyze logs. Let’s move to syslog:

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Hybrid%20Attack%20Simulation%20%26%20Log%20Correlation%20Study/Pictures%20for%20Hybrid%20Attack%20Simulation%20%26%20Log%20Correlation%20Study.md/screen_8_syslog.PNG)

In my case i used `grep -a “PORTSCAN DETECTED”` according to rule detection. The configuration was like that:

```
sudo iptables -N PORTSCAN
sudo iptables -A INPUT -p tcp --syn -j PORTSCAN
sudo iptables -A PORTSCAN -m recent --name portscan --set
sudo iptables -A PORTSCAN -m recent --name portscan --update --seconds 3 --hitcount 10 -j LOG --log-prefix "PORTSCAN DETECTED: " --log-level 4
sudo iptables -A PORTSCAN -m recent --name portscan --update --seconds 3 --hitcount 10 -j DROP
```

![](https://github.com/cbrkrtek/SOC-analyst-hands-on-labs/blob/main/Hybrid%20Attack%20Simulation%20%26%20Log%20Correlation%20Study/Pictures%20for%20Hybrid%20Attack%20Simulation%20%26%20Log%20Correlation%20Study.md/screen_9_snort_logs.PNG)

## PART 4 "Main conclusions"
I appreciate the implementation of this scenario, because it provides a hands-on experience that I can apply in my future position as a cybersecurity analyst. Thanks for reading!!! :smile:
