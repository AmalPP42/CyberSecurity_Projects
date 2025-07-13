## SOC Monitoring and Threat Detection using Wazuh SIEM

## **Introduction**

### **Background**

In today’s digital age, organizations increasingly rely on technology to store, process, and transmit critical information. With this dependence comes an increased risk of cyber threats, ranging from data breaches and malware infections to insider threats and advanced persistent threats (APTs). As a result, Security Information and Event Management (SIEM) tools have become essential for monitoring, detecting, and responding to these threats in real-time.

Wazuh is a powerful open-source security platform that offers unified SIEM and XDR (Extended Detection and Response) capabilities. It integrates log data collection, intrusion detection, vulnerability detection, file integrity monitoring, and much more, making it a popular solution among cybersecurity professionals and organizations seeking to build cost-effective, scalable security infrastructure.

### **Motivation**

As a cybersecurity enthusiast and aspiring professional, I wanted to gain practical, hands-on experience with a modern SIEM solution. While theoretical knowledge provides a foundation, understanding how to deploy, configure, and analyze security data from real systems is critical for a successful career in cybersecurity. This project is motivated by the need to bridge that gap between theory and real-world application, and to build a showcase-worthy project that demonstrates practical skills to potential employers.

Additionally, Wazuh provides a great learning opportunity due to its extensive documentation, strong community support, and the ability to simulate real attacks in a controlled lab environment.

### **Purpose**

The primary purpose of this project is to set up and configure a complete Wazuh-based SIEM environment, simulate a series of cyber-attacks from a Kali Linux machine on a Windows endpoint, and analyze how Wazuh detects and reports these attacks. Through this project, I aim to:

- Understand the architecture and components of the Wazuh platform.
- Learn how to collect and analyze security event logs from Windows systems.
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

Example: Installed on your Windows machine to collect logs and forward them for analysis.

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
<img width="1902" height="965" alt="image" src="https://github.com/user-attachments/assets/b8b0ed7a-8d96-49e8-ad1c-7246f77132b3" />
Edit the network settings after adding ova to virtualbox
<img width="1568" height="930" alt="image" src="https://github.com/user-attachments/assets/87a0c5eb-dbc4-48dd-a7b4-867674574176" />
After installation start the wazuh, wazuh will give you the username and password to access the wazuh.
<img width="830" height="622" alt="image" src="https://github.com/user-attachments/assets/bb7025ae-5ec2-4556-96fd-6a87cdbd648a" />
<img width="854" height="621" alt="image" src="https://github.com/user-attachments/assets/54ebc47f-b15c-41f2-ae7f-06770a9794b2" />
use `ip a` to get the machine ip to access the wazuh webpage
<img width="833" height="567" alt="image" src="https://github.com/user-attachments/assets/189f2583-4c53-44dd-ae5c-4f844a3616d5" />
`sudo cat /etc/wazuh-indexer/opensearch-security/internal_users.yml`
 Run this command to open the credentials file
<img width="810" height="616" alt="image" src="https://github.com/user-attachments/assets/1dcb653b-b950-4933-bee0-73ab03874502" />
<img width="1618" height="920" alt="image" src="https://github.com/user-attachments/assets/00e79da8-f342-4a90-8da0-f21f6745af54" />
<img width="1814" height="1006" alt="image" src="https://github.com/user-attachments/assets/8dc1ef10-acff-47fa-a2a7-7f5f5d41dd4e" />
Next step is to add end points. click on “Agents by status” 
<img width="1901" height="565" alt="image" src="https://github.com/user-attachments/assets/ddd7d2ee-7dcf-4691-90e9-c596d449b017" />
select windows to set the end point as windows. and set the server address  wazu ip.
<img width="1907" height="912" alt="image" src="https://github.com/user-attachments/assets/35dc8388-47cd-48c4-a656-8c9768e4274b" />
<img width="1855" height="733" alt="image" src="https://github.com/user-attachments/assets/76ee6771-b241-4b4b-aa92-97fdec1747e5" />
give an agent name which must be unique, and run the following command in the power shell to install the agent, and start the agent using the command below. `NET START WazuhSvc` 
 `Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Wazuh*" }`















