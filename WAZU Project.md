# WAZU Project

## SOC Monitoring and Threat Detection using Wazuh SIEM

## **Introduction**

### **Background**

In today’s digital age, organizations increasingly rely on technology to store, process, and transmit critical information. With this dependence comes an increased risk of cyber threats, ranging from data breaches and malware infections to insider threats and advanced persistent threats (APTs). As a result, Security Information and Event Management (SIEM) tools have become essential for monitoring, detecting, and responding to these threats in real-time.

Wazuh is a powerful open-source security platform that offers unified SIEM and XDR (Extended Detection and Response) capabilities. It integrates log data collection, intrusion detection, vulnerability detection, file integrity monitoring, and much more, making it a popular solution among cybersecurity professionals and organizations seeking to build cost-effective, scalable security infrastructure.
### **Motivation**

As a cybersecurity enthusiast and aspiring professional, I wanted to gain practical, hands-on experience with a modern SIEM solution. While theoretical knowledge provides a foundation, understanding how to deploy, configure, and analyze security data from real systems is critical for a successful career in cybersecurity. This project is motivated by the need to bridge that gap between theory and real-world application, and to build a showcase-worthy project that demonstrates practical skills to potential employers.

Additionally, Wazuh provides a great learning opportunity due to its extensive documentation, strong community support, and the ability to simulate real attacks in a controlled lab environment.

### **Purpose**

The primary purpose of this project is to set up and configure a complete Wazuh-based SIEM environment, simulate a series of cyber-attacks from a Kali Linux machine on a Ubuntu endpoint, and analyze how Wazuh detects and reports these attacks. Through this project, I aim to:

- Understand the architecture and components of the Wazuh platform.
- Learn how to collect and analyze security event logs from Ubuntu systems.
- Simulate common attack vectors to generate meaningful security events.
- Demonstrate detection, alerting, and analysis capabilities of Wazuh.
- Build a foundational skill set for a career in Security Operations Center (SOC) or threat hunting roles.

This project not only enhances my understanding of SIEM systems but also serves as a valuable portfolio piece that illustrates my commitment to cybersecurity and continuous learning.

## **Wazuh Architecture**

Wazuh is a modular, scalable, and open-source **Security Information and Event Management (SIEM)** platform that provides threat detection, compliance monitoring, and incident response. Its architecture is based on three main components:

**Wazuh Agent**

- Installed on endpoints (e.g., Windows, Linux, macOS).
- Collects security data from the local system, such as:
    - System logs (Syslog/Event logs)
    - File integrity monitoring (FIM)
    - Active processes
    - Rootkit detection
- Sends the collected data to the **Wazuh Manager**.

Example: Installed on your Ubuntu machine to collect logs and forward them for analysis.

**Wazuh Manager**

- The **central brain** of the Wazuh platform.
- Responsibilities:
    - Receives and processes data from agents
    - Correlates events with detection rules
    - Triggers alerts for suspicious activity
    - Manages agent registration and configuration
- Stores alerts and forwards them to Elasticsearch for indexing.

> Example: The Wazuh VM (OVA) runs the manager that receives data from your Windows agent.
> 

**Elasticsearch**

- Stores structured and indexed data (alerts, logs, events).
- Enables fast search and filtering of security events.
- Acts as the data source for the Wazuh dashboard.

**Wazuh Dashboard (Web Interface)**

- A **Kibana-based GUI** used to visualize alerts and interact with Wazuh data.
- Allows:
    - Viewing of agent status
    - Alert investigation
    - Filtering and dashboarding
    - Rule tuning and monitoring

**Flow Summary**

1. **Agent** collects data from host
2. Sends data to **Manager**
3. Manager evaluates data with rules → generates alerts
4. Alerts stored in **Elasticsearch**
5. Data visualized in **Dashboard**

### **Environment Setup**

This project was conducted in a virtualized lab environment hosted on a **Windows 11 (64-bit)** machine. The setup includes a Wazuh all-in-one server running in VirtualBox, a Kali Linux VM for simulating attacks, and the host machine itself (Windows 11) acting as the monitored endpoint, with the Wazuh agent installed directly on it.
**Host System**

- **Operating System:** Windows 11 (64-bit)
- **Virtualization Tool:** Oracle VirtualBox (v7.x)
- **Purpose:** Hosts both the Wazuh Server and Kali Linux virtual machines, and also serves as the endpoint (target) for monitoring and attack simulation.

---

 **Wazuh All-in-One Server (OVA)**

- **Base Image:** Wazuh OVA downloaded from https://wazuh.com/downloads
- **Purpose:** Runs the complete Wazuh stack:
    - Wazuh Manager
    - Elasticsearch
    - Wazuh Dashboard
- **VM Configuration:**
    - RAM: 6 GB
    - CPU: 2 Cores
    - Network Adapter: **Bridged Adapter** (for communication with host and Kali)
- **Access:**
    - Web Interface: `https://<Wazuh_VM_IP>`
    - CLI Login: `wazuh / wazuh`
    - Dashboard Login: `admin / admin`

---

**Monitored Endpoint (Main Host Machine)**

- **Operating System:** Windows 11 (Host OS)
- **Purpose:** Acts as the monitored endpoint for Wazuh
- **Installed Components:**
    - Wazuh Agent (configured to connect to the Wazuh Manager)
    - Sysmon (for detailed event logging)
- **Agent Configuration:**
    - Wazuh Manager IP set in `ossec.conf`
- **Monitored Data Sources:**
    - Windows Event Logs
    - Sysmon logs
    - Optional file integrity monitoring

---

### **Attack Simulation Machine**

- **Operating System:** Kali Linux (VirtualBox VM)
- **Purpose:** Simulates attacks against the Windows 11 host to generate alerts
- **Installed Tools:**
    - Nmap (port scanning)
    - Hydra (brute-force)
    - Metasploit Framework (exploit execution)
    - Netcat (reverse shell)
    - Wireshark (network traffic analysis)

---

### **Networking Configuration**

All systems are connected to the same virtual LAN using **Bridged Networking** to ensure full communication:

- **Wazuh Server (OVA)**, **Kali Linux VM**, and **Windows 11 Host** are all on the same local subnet.
- The **Wazuh Agent** on the Windows 11 host sends logs to the **Wazuh Manager**.
- The **Kali VM** targets the IP of the Windows 11 host during simulated attacks.

  ### Installation

Download the ova file.
<img width="1902" height="965" alt="image" src="https://github.com/user-attachments/assets/699600fc-6b35-4809-829c-8d21b922cd22" />
Edit the network settings after adding ova to virtualbox
<img width="1568" height="930" alt="image" src="https://github.com/user-attachments/assets/98800b70-8b24-4d59-ba24-55b70227bc8b" />
After installation start the wazuh, wazuh will give you the username and password to access the wazuh.
<img width="830" height="622" alt="image" src="https://github.com/user-attachments/assets/3171e8d5-534a-46fc-b62f-84fd37355c47" />
<img width="854" height="621" alt="image" src="https://github.com/user-attachments/assets/cc57a730-c0c2-428e-9fa7-41e08db08da0" />
use ip a to get the machine ip to access the wazuh webpage
<img width="833" height="567" alt="image" src="https://github.com/user-attachments/assets/4611f3a0-9fd8-4870-8e07-61290aecb30e" />
`sudo cat /etc/wazuh-indexer/opensearch-security/internal_users.yml`
 Run this command to open the credentials file
<img width="810" height="616" alt="image" src="https://github.com/user-attachments/assets/79256874-adf3-436c-9ad2-67bacd1a810b" />
to access the wazuh dashboard, use the full url like [https://192.168.29.218](https://192.168.29.218/), aslo check the port wazuh dashboard is running, using command `sudo nano /etc/wazuh-dashboard/opensearch_dashboards.yml`
<img width="776" height="591" alt="image" src="https://github.com/user-attachments/assets/67348862-01df-48e3-8856-16c9a4329d46" />
Connect to the Wazuh machine's SSH service from the Kali machine to access its terminal interactively.

Enable and start the SSH service on the Wazuh machine:

`sudo systemctl enable --now sshd`

Check the status of the SSH service:

`sudo systemctl status sshd`

Ensure that the service is **active (running)**.

1. **From your Kali/Ubuntu machine, connect to the Wazuh machine using SSH:**

`ssh wazuh-user@192.168.29.218`

Replace `wazuh-user` with the actual username of the Wazuh machine.
<img width="788" height="592" alt="image" src="https://github.com/user-attachments/assets/b50b4743-a619-4e21-8c4e-e2a9fb3e451d" />
<img width="1591" height="627" alt="image" src="https://github.com/user-attachments/assets/e39ab7b6-a621-4290-b2b1-eea45e839b41" />
use user name and password as “admin”
<img width="1618" height="920" alt="image" src="https://github.com/user-attachments/assets/6fb4e64e-69a3-4929-9c9d-e87210cbaf98" />
<img width="1814" height="1006" alt="image" src="https://github.com/user-attachments/assets/5de6fa56-d5a0-4862-866a-13b541b4f57a" />
Next step is to add end points. click on “Agents by status” 
<img width="1901" height="565" alt="image" src="https://github.com/user-attachments/assets/e84b73d0-9d44-416a-b794-0453f3ab0312" />
select windows to set the end point as windows. and set the server address  wazu ip.
<img width="1907" height="912" alt="image" src="https://github.com/user-attachments/assets/da669e89-de9a-4c8a-b8b2-c6560ccb179c" />
<img width="1855" height="733" alt="image" src="https://github.com/user-attachments/assets/2fd5c034-fba2-4e41-a5b5-f711893ea345" />
give an agent name which must be unique, and run the following command in the power shell to install the agent, and start the agent using the command below. `NET START WazuhSvc` 

 `Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Wazuh*" }`
<img width="1482" height="754" alt="image" src="https://github.com/user-attachments/assets/c80053f1-cc64-4ae0-93fc-6f4aed965827" />
if command line installation dosent work , do the graphical installation. 

 `Get-Service | Where-Object { $_.Name -like "*Wazuh*" }`
 <img width="1103" height="255" alt="image" src="https://github.com/user-attachments/assets/90848888-14a8-4a56-9cb0-0557f77d8ccf" />
Open wazuh to check the agent is connected
<img width="1351" height="657" alt="image" src="https://github.com/user-attachments/assets/4dde5efb-afb7-4a34-9d20-e7ed3585a3a6" />
we have the agent connected to the wazuh server.

## Wazuh Overview
<img width="1897" height="958" alt="image" src="https://github.com/user-attachments/assets/c2f4c397-7925-4607-8fac-2ab04171905f" />
The same way you can install agent on ubuntu.

The **Overview page in Wazuh** (inside the Wazuh Dashboard/Kibana interface) provides a **high-level summary** of your security posture by showing **key metrics, alerts, and activity** across all connected agents. 
This page gives you a **centralized view of your security environment**, helping you quickly assess the health and activity of your system.

Wazuh Dashboard → Overview
### **Agents Summary**

- Shows total number of agents.
- Displays **online**, **disconnected**, and **never connected** agent counts.
- Useful for quickly seeing if any endpoints are not reporting.

### **Alert Volume**

- **Critical Severity (Level 15+):**
    
    Indicates very serious threat (e.g., root access attempts, successful attacks).
    
- **High Severity (Level 12–14):**
    
    Potential threats that need immediate review (e.g., brute-force attempts, privilege escalation).
    
- **Medium Severity (Level 7–11):**
    
    Less urgent but still relevant (e.g., scan activity, suspicious behavior).
    
- **Low Severity (Level 0–6):**
    
    Informational logs or minor anomalies.
    

### **Endpoint Security**

- **Configuration Assessment:** Checks compliance with hardening benchmarks (like CIS).
- **Malware Detection:** Looks for Indicators of Compromise (IOCs) based on known threats.
- **File Integrity Monitoring (FIM):** Alerts on unauthorized file changes.

### **Threat Intelligence**

- **Threat Hunting:** Manually inspect suspicious activities in logs and alerts.
- **MITRE ATT&CK:** Visualize alerts mapped to MITRE techniques for advanced understanding.
- **Vulnerability Detection:** Identifies vulnerable applications/services using integrated feeds.
Navigation Panel 
<img width="394" height="805" alt="image" src="https://github.com/user-attachments/assets/40d20ea5-89ff-425f-aee3-7298e046def8" />
### **Explore Section**

This area is used for **searching, visualizing, and managing data** collected from your endpoints.

- **Discover:**
    
    Explore raw logs and events. Great for deep diving into individual log entries.
    
- **Dashboards:**
    
    Access and manage pre-built or custom dashboards (like the Overview, FIM, Malware dashboards, etc.).
    
- **Visualize:**
    
    Create and manage visual elements like graphs, bar charts, and tables that can be added to dashboards.
    
- **Reporting:**
    
    Generate and download reports based on dashboards or visualizations.
    
- **Alerting:**
    
    Set up alerts to notify you when certain conditions (like critical severity) are met.
    
- **Maps:**
    
    View event data geolocated on a world map (requires GeoIP data).
    
- **Notifications:**
    
    Configure and manage how you’re notified about alerts (e.g., email, Slack, etc.).
    

---

### **Endpoint Security Section**

Focused on monitoring and protecting endpoints (your systems or devices).

- **Configuration Assessment:**
    
    Scans systems for compliance with security standards (like CIS Benchmarks).
    
- **Malware Detection:**
    
    Shows alerts triggered by known malware behavior or Indicators of Compromise (IOCs).
    
- **File Integrity Monitoring (FIM):**
    
    Alerts you when files or directories are changed, useful for detecting tampering or unauthorized changes.
### **Threat Intelligence Section**

Tools to help you **analyze, investigate, and understand** threats more deeply.

- **Threat Hunting:**
    
    Allows manual investigation into suspicious behavior or anomalies across your network.
    
- **Vulnerability Detection:**
    
    Identifies systems that are running software with known vulnerabilities.
    
- **MITRE ATT&CK:**
    
    Visual mapping of detected alerts to MITRE ATT&CK tactics and techniques. Helps understand the type and phase of attack.
## Custom Rules in wazuh

Creating rules in Wazuh depends on the type of event you want to detect and the tool generating the logs. Below are the different use cases and where to define the corresponding rules:

- **Wazuh Agent Rules** (for endpoint activity):
    
    Use this when detecting events like command executions, log file access, or general system activity on the endpoint.
    
    ➤ Rule path: `/var/ossec/etc/rules/local_rules.xml` on the agent.
    
- **Auditd Rules** (for Linux system-level monitoring):
    
    Ideal for capturing Linux events such as file access, command usage, and user activity using the audit subsystem.
    
    ➤ Rule path: `/etc/audit/rules.d/custom.rules`.
    
- **Suricata Rules** (for network intrusion detection):
    
    Use this to detect network-based threats like Nmap scans, brute-force attacks, and suspicious packets.
    
    ➤ Rule path: `/etc/suricata/rules/custom.rules`.
    
- **Wazuh Manager Rules** (for central log correlation):
    
    Best for creating logic to analyze, correlate, or normalize logs collected from multiple agents.
    
    ➤ Rule path: `/var/ossec/etc/rules/local_rules.xml` on the manager.
    
- **Wazuh Decoders** (for custom log parsing):
    
    When logs are in non-standard formats (e.g., from Sysmon or Suricata), create custom decoders to extract fields for rule matching.
    
    ➤ Decoder path: `/var/ossec/etc/decoders/local_decoder.xml`.
Each of these components plays a specific role in building a comprehensive threat detection strategy using Wazuh.
### Attack Detection in Wazuh

Wazuh has a built-in ruleset that analyzes logs and detects malicious activity.

Wazuh rules cover:

- Malware detection (EICAR, LOLBins)
- Brute force attacks
- Port scans
- Privilege escalation
- File integrity changes
- Suspicious PowerShell or CMD usage
- MITRE ATT&CK mapping
### ATTACK and  DETECTION ON UBUNTU (Agent)
Install wazuh agent in ubuntu
<img width="1903" height="882" alt="image" src="https://github.com/user-attachments/assets/e5bd44d2-b8ff-40db-93b7-118176eff1c6" />
<img width="1886" height="963" alt="image" src="https://github.com/user-attachments/assets/8f0faf57-cdfb-4a78-be2e-4fa8cc6423d1" />
Perform a bruteforce attack on ssh service
<img width="1269" height="216" alt="image" src="https://github.com/user-attachments/assets/2857069b-b5b6-4311-89ca-68d81c335064" />
Check the wazuh events to get the attack detected event
<img width="1893" height="957" alt="image" src="https://github.com/user-attachments/assets/2b951876-ae44-40c6-af5d-6ff21e2263f3" />
from 192.168.29.98 :  This is your attacking machine (Kali Linux)
port 49972 :  This is the source port used by your Kali machine
ssh2 : Indicates the SSH protocol version used
in document details panel we can see more details on this
<img width="1412" height="887" alt="image" src="https://github.com/user-attachments/assets/f75ae634-7a87-4e3a-9866-b2a2c53bfc8a" />
#### Network Detection
### Suricata

To get the network detection we neet to install suricata

Because **Suricata detects attacks happening on the network interface** of the system it is installed on. If you want to detect:

- 🔍 Nmap scans
- 🔥 Port scans
- 🐍 Exploit attempts
- 🌐 Suspicious HTTP/DNS/SSH traffic
    
    ...you need Suricata installed on the system that receives this traffic — **the agent** (e.g., your target machine or victim).
    

Install Suricata-Update Tool

`sudo apt install -y suricata-update`
<img width="737" height="107" alt="image" src="https://github.com/user-attachments/assets/1fe71745-80ff-42d9-a302-495456f119c2" />
Fetch the Latest Rules

`/var/lib/suricata/rules/suricata.rules`

Restart Suricata

`sudo systemctl restart suricata`

Confirm Rules are Loaded

`sudo suricata -T -c /etc/suricata/suricata.yaml -v`
<img width="1350" height="214" alt="image" src="https://github.com/user-attachments/assets/e5c8a76b-3fda-4937-8e95-41fb426ecd7e" />
After restart, Suricata will log alerts to: `/var/log/suricata/eve.json`

### **Ensure the Agent is Reading**

**`eve.json`**

On your **Wazuh agent (Ubuntu)**, check this file:

`sudo nano /var/ossec/etc/ossec.conf`
Make sure you have this block inside `<ossec_config>`:
`<localfile>
<log_format>json</log_format>
<location>/var/log/suricata/eve.json</location>
</localfile>`

Restart the Agent

`sudo systemctl restart wazuh-agent`
### Creating Custom Rule

**Suricata Rule** (for network detection like Nmap scan)

Create the custom rule file in the folder `/var/lib/suricata/rules`
<img width="812" height="206" alt="image" src="https://github.com/user-attachments/assets/81499687-a3a7-417a-ac92-6489c63f66f7" />
create some custom rules
<img width="1208" height="558" alt="image" src="https://github.com/user-attachments/assets/12f265a9-8776-4029-8b6c-152a9724353f" />
as per rules Nmap tcp scan, sql injection,xss attacks,directory enumeration etc will get detected

also specify the rule file name in the suricata.yaml file in `/etc/suricata/`
<img width="1212" height="718" alt="image" src="https://github.com/user-attachments/assets/f47829df-211e-42ed-88fa-33ef712c7cdd" />
`sudo suricata -c suricata.yaml -i enp0s3`
This command starts Suricata manually in live packet capture mode, using a specified network interface and configuration file.
<img width="1285" height="819" alt="image" src="https://github.com/user-attachments/assets/668611a7-a8a5-4bec-8063-d32264b88bfb" />
now lets perform the attacks one by one using the kali linux machine,

To get the detected attacks , Filter by the agent and the log location.
<img width="1913" height="260" alt="image" src="https://github.com/user-attachments/assets/e1cfc024-7b2b-439b-ac49-021a6b445d40" />
SQL injection
<img width="1111" height="212" alt="image" src="https://github.com/user-attachments/assets/de10799c-83cf-4bcd-93dc-d57564dbd7b9" />
`sqlmap -u "http://192.168.29.252?id=1" --batch --level=5 --risk=3 `
<img width="1900" height="964" alt="image" src="https://github.com/user-attachments/assets/2f838c7e-a040-4df8-84e9-617aead71d70" />
Directory enumeration
<img width="938" height="422" alt="image" src="https://github.com/user-attachments/assets/5e43a424-33c3-4622-a490-0925c0c369fe" />
`gobuster dir -u http://192.168.29.252/ -w /usr/share/wordlists/dirb/common.txt `
<img width="1912" height="899" alt="image" src="https://github.com/user-attachments/assets/cde572eb-8515-494f-af68-478e322e79cb" />
Ping flood attack
<img width="946" height="512" alt="image" src="https://github.com/user-attachments/assets/a1e14882-8473-4c2d-8fd6-cb593ac986b0" />
`ping -s 65500 192.168.29.252 `
<img width="1898" height="898" alt="image" src="https://github.com/user-attachments/assets/a6539b6f-1841-4979-af23-7201b5026046" />
Nmap Scan
<img width="1124" height="228" alt="image" src="https://github.com/user-attachments/assets/008bece2-8fef-4ab4-ab9f-9d376a38703e" />
<img width="1911" height="953" alt="image" src="https://github.com/user-attachments/assets/41e08f3e-70a4-4c48-90f4-8e3303ddc163" />
This is how set custom rules and perform attacks







  
