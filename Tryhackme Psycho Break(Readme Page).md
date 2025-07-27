# TryHackMe - Psycho Break 🧠💥

## 🧾 Room Overview
**Psycho Break** is a TryHackMe CTF-style vulnerable machine where the objective is to perform enumeration, gain user access, and escalate privileges to root. This box teaches valuable lessons about insecure scripts, weak service configurations, and abuse of cron jobs.

---

## 🎯 Objective
- Enumerate the target system
- Gain initial foothold as user `kidman`
- Escalate privileges to root
- Capture both user and root flags

---

## 🛠️ Tools Used
- [`nmap`](https://nmap.org/) – port scanning and service detection
- [`gobuster`](https://github.com/OJ/gobuster) – directory brute-forcing
- [`hydra`](https://github.com/vanhauser-thc/thc-hydra) – brute force login credentials
- [`python`](https://www.python.org/) – reverse shell payload
- `netcat` – catch reverse shell
- `crontab` – analyze scheduled tasks

---

## 🧵 Summary of the Box

1. **Enumeration** revealed open ports and a web server with hidden directories.
2. Using **gobuster**, a login page was found. Default or guessed credentials allowed access.
3. A suspicious file `/var/.the_eye_of_ruvik.py` was found owned by root but **writable by the user**.
4. The script was automatically executed via a **cron job running as root** every 2 minutes.
5. Injected a **Python reverse shell payload** into the script, which successfully spawned a **root shell**.
6. Collected both user and root flags.

---

## 📚 Key Learning Points

- 🛠️ **Writable files owned by root** that are executed regularly can be abused for **privilege escalation**.
- ⚙️ **Cron jobs** can become a critical weakness when they run insecure or user-editable scripts.
- 🐚 Using a **reverse shell in Python** can be an effective technique to maintain access.
- 🔒 Always validate permissions of scripts run as privileged users.

---

## 📌 Flags Captured
- ✅ `user.txt`
- ✅ `root.txt`

---

## 📦 Additional Notes
For details on enumeration, payloads, and privilege escalation, see:
- `initial-access.md`
- `privilege-escalation.md`

---

> 🧠 *"No one shall hide from Ruvik..."* — This box shows exactly why **script security and proper permission management** are critical in any Linux system.

