# 📌 Bug Bounty Report – SoundCloud (via Bugcrowd)
**Prepared by:**  
Amal P P  
📧 amalpp42@gmail.com  
📞 +91 8281506341  
## Tools & Environment

**Operating System:** Kali Linux  

**Tools Utilized:**  
- **Nessus** – Vulnerability scanning and assessment  
- **Subfinder** – Subdomain enumeration  
- **Httpx** – Probing live hosts and HTTP response validation  
- **Waybackurls** – Extracting archived URLs from the Wayback Machine  
- **GF (Gf-Patterns: SQLi, XSS)** – Filtering potential vulnerable parameters  
- **SQLMap** – Automated SQL Injection testing  
- **DalFox** – Advanced XSS scanning and validation  
- **FFuF (Fuzz Faster U Fool)** – Web fuzzing and content discovery  
- **Arjun** – Parameter discovery and fuzzing  
- **cURL (manual testing)** – Crafting and sending custom HTTP requests  
- **OWASP ZAP** – Web application penetration testing and interception proxy  
- **Nuclei** – Template-based vulnerability scanning and detection  

---

## Objective
The objective of this report is to document a security vulnerability identified on **SoundCloud.com** during authorized bug bounty testing under the **Bugcrowd program**. The report aims to:  

- Provide a detailed explanation of the discovered issue.  
- Demonstrate its potential security impact on SoundCloud users and the platform.  
- Recommend remediation measures to help prevent exploitation and strengthen SoundCloud’s overall security posture.  

---

## Introduction
This report highlights a security vulnerability discovered during authorized bug bounty testing on the target application **SoundCloud.com** under the **Bugcrowd program**.  

The goal of this report is to:  
- Provide a clear explanation of the issue.  
- Outline its potential impact.  
- Document reproducible steps so that the development team can effectively validate and address the vulnerability.  

# Bug Bounty Report – SoundCloud (via Bugcrowd)

This report documents a security vulnerability identified in **SoundCloud** during authorized testing under the **Bugcrowd bug bounty program**.  

The purpose of this report is to:  
- Provide a clear explanation of the issue.  
- Outline its potential security impact.  
- Document reproducible steps, ensuring that the SoundCloud security team can verify and address the finding effectively.  

**SoundCloud** is the world’s largest open audio platform. With over **200 million tracks** from **20 million creators** heard in **190 countries**, what’s next in music is first on SoundCloud.  
<img width="1879" height="968" alt="image" src="https://github.com/user-attachments/assets/306ad645-d9a9-4cc8-a405-6f36ca32edbd" />
<img width="960" height="948" alt="image" src="https://github.com/user-attachments/assets/36b7e49d-1b28-428c-b6d8-86f66c1ab941" />
<img width="1305" height="960" alt="image" src="https://github.com/user-attachments/assets/f5e9d4b4-3f75-44e7-92fa-3bf19ad30a81" />

## Scope

### In-Scope
In-scope refers to the specific **assets, applications, endpoints, or functionalities** that the security team has explicitly authorized for testing under the bug bounty program.  

These targets are within the program’s boundaries and are eligible for:  
- Vulnerability discovery  
- Reporting  
- Potential reward  

---

### Out-of-Scope
Out-of-scope refers to any **assets, systems, or functionalities** that are **not authorized** for testing.  

Attempting to exploit or scan these areas could result in:  
- Violation of bug bounty rules  
- Legal consequences  
- Disqualification from the program  

⚠️ Vulnerabilities reported on out-of-scope targets are generally **not eligible for rewards**.  

## Reconnaissance & Enumeration

### Nessus Scan
**Nessus** is a widely used vulnerability assessment tool that scans systems and applications to identify potential security weaknesses.  

It categorizes findings into five severity levels:  
- 🔴 Critical  
- 🟠 High  
- 🟡 Medium  
- 🔵 Low  
- ⚪ Informational  

**Scan Results:**  
During the scan of **SoundCloud.com**, Nessus identified a total of **21 vulnerabilities**.  
All of the findings were classified under the **Informational** category, meaning:  
- No immediate exploitable issues of higher severity were detected.  
- The results highlight low-risk or informational insights rather than critical threats.  
 
<img width="1911" height="807" alt="image" src="https://github.com/user-attachments/assets/ad27684b-3e7d-4ff4-8259-1be497210537" />
<img width="1820" height="882" alt="image" src="https://github.com/user-attachments/assets/07f594aa-0fcb-4c19-b2e2-92610b5e9687" />

### Nmap Scan – Port 80 Analysis

During the reconnaissance phase, an **Nmap scan** was performed against the target domain **soundcloud.com**.  

**Findings:**  
- **Port 80 (HTTP)** was found to be **open**, indicating that the application accepts connections over unencrypted HTTP.  
- This can potentially expose traffic to risks such as man-in-the-middle (MITM) attacks if not properly secured.  

To further analyze the security posture, the presence of **HSTS (HTTP Strict Transport Security)** was verified.  

<img width="859" height="226" alt="image" src="https://github.com/user-attachments/assets/6c1885b6-02dc-486e-a97a-cfefd77f0290" />
### What is HSTS?

**HTTP Strict Transport Security (HSTS)** is a web security policy mechanism that enforces browsers to interact with a website **only via HTTPS**.  

It helps prevent:  
- 🔻 Protocol downgrade attacks  
- 🍪 Cookie hijacking  
- 🚫 Insecure HTTP connections  

---

### Verification Command
To check if **HSTS** is enabled on **soundcloud.com**, the following command was used:

```bash
curl -I https://soundcloud.com | grep -i strict-transport-security
```
<img width="750" height="127" alt="image" src="https://github.com/user-attachments/assets/41fe86e8-9972-478b-acfc-005cee9de123" />

### HSTS Response on SoundCloud
Upon checking the response headers of **soundcloud.com**, the **Strict-Transport-Security (HSTS)** header was found to be enabled with the following configuration:


#### Header Breakdown:
- **max-age=63072000** → The browser will remember for **2 years** (≈ 63,072,000 seconds) that SoundCloud must only be accessed via HTTPS.  
- **includeSubDomains** → The HTTPS-only rule applies to **all subdomains** (e.g., `api.soundcloud.com`, `blog.soundcloud.com`), ensuring complete coverage.  
- **preload** → SoundCloud is included in the **HSTS Preload List**, which is built directly into major browsers such as Chrome, Firefox, and Safari.  
  - This means even first-time visitors typing `http://soundcloud.com` are automatically redirected to **HTTPS before any request leaves their browser**.  

### Security Implications
Enabling **HSTS** provides the following security benefits:  
- ✅ Prevents **SSL stripping attacks**  
- ✅ Protects users from **protocol downgrade attempts**  
- ✅ Mitigates **session hijacking risks** over insecure HTTP  
- ✅ Enhances overall **trust and security posture** for both the main domain and its subdomains  

---

### Subdomain Enumeration – Subfinder
As part of reconnaissance, **Subfinder** was used to identify subdomains associated with **soundcloud.com**.  

**About Subfinder:**  
- A fast and reliable subdomain discovery tool  
- Aggregates results from passive sources such as:  
  - Search engines  
  - Certificate transparency logs  
  - DNS records  
  - APIs  

**Command Used:**
```bash
subfinder -d soundcloud.com -all -o subs.txt
 ```
<img width="933" height="344" alt="image" src="https://github.com/user-attachments/assets/34d22f0d-8bde-490f-a180-fe0e68a7427a" />

### Live Host Discovery – Httpx

After enumerating subdomains with **Subfinder**, the next step was to validate which subdomains were actively responding.  
For this, **Httpx** was used.  

**About Httpx:**  
- A fast and flexible HTTP probing tool  
- Checks the **availability of hosts**  
- Gathers **HTTP response details**  

**Command Used:**
```bash
cat subs.txt | httpx-toolkit > alive.txt
```
<img width="923" height="358" alt="image" src="https://github.com/user-attachments/assets/0eaceb29-a874-45fe-b1bf-fc35040c490f" />

### Historical URL Discovery – Waybackurls

After identifying active subdomains with **Httpx**, the next step was to gather **historical URLs** associated with these domains.  
For this, **Waybackurls** was used.  

**About Waybackurls:**  
- Extracts URLs from the **Wayback Machine (Internet Archive)** and other sources  
- Provides visibility into **archived endpoints** that may no longer be directly linked but could still be accessible  

**Command Used:**
```bash
cat alive.txt | waybackurls > urls.txt
```
<img width="920" height="62" alt="image" src="https://github.com/user-attachments/assets/9b4dadcb-6403-462a-a6f5-060492c235bf" />

### Filtering Potential Injection Points – GF Patterns

After collecting a large set of URLs using **Waybackurls**, the next task was to filter them for potentially vulnerable endpoints.  
For this, the tool **GF (Gf-Patterns)** was used.  

**About GF:**  
- Applies predefined **regex patterns** to quickly identify URLs  
- Detects parameters commonly associated with web vulnerabilities such as:  
  - **SQL Injection (SQLi)**  
  - **Cross-Site Scripting (XSS)**  

**Commands Used:**
```bash
cat urls.txt | gf sqli > sqli.txt
cat urls.txt | gf xss > xss.txt
```

<img width="814" height="147" alt="image" src="https://github.com/user-attachments/assets/0f86e06e-70a1-415e-8944-8b0c75b46ae3" />

### Purpose of GF Filtering
- 🎯 Narrow down a large dataset of URLs into focused subsets for **SQLi** and **XSS** testing  
- ⚡ Increase efficiency by eliminating irrelevant endpoints  
- 🛠️ Build a structured workflow for subsequent tools like:  
  - **SQLMap** (for SQL Injection)  
  - **DalFox** (for XSS)  

---

### SQL Injection Testing – SQLMap
After filtering potential SQL injection points using **GF (sqli pattern)**, the shortlisted URLs stored in `sqli.txt` were tested using **SQLMap**.  

**About SQLMap:**  
- Automated tool for detecting and exploiting **SQL injection vulnerabilities**  
- Capable of identifying a wide range of SQLi techniques  
- Supports multiple database management systems  

**Command Used:**
```bash
sqlmap -m sqli.txt --batch --random-agent --level=2 --risk=2
```
<img width="1384" height="597" alt="image" src="https://github.com/user-attachments/assets/835b5d09-c577-4d62-8289-296057ebc510" />

### Purpose of SQLMap Testing
- ✅ Validate whether the URLs flagged by **GF** are actually vulnerable to **SQL injection**  
- ⚡ Automate payload injection and detection of database-related flaws  
- 📑 Collect detailed evidence for potential exploitation scenarios  

---

### Findings (SQLMap)
SQLMap successfully scanned the endpoints listed in **sqli.txt**.  

**Result:**  
- *(Insert result here, e.g., No SQL injection vulnerabilities were confirmed OR SQLMap detected potential injection points in specific parameters)*  

---

### Cross-Site Scripting (XSS) Testing – DalFox
After filtering potential XSS endpoints using **GF (xss pattern)**, the shortlisted URLs stored in **xss.txt** were tested using **DalFox**.  

**About DalFox:**  
- Stands for **“DalFox is a parameter miner & XSS scanner”**  
- Advanced tool for detecting and validating:  
  - Reflected XSS  
  - Stored XSS  
  - DOM-based XSS  
- Automates:  
  - Payload injection  
  - Parameter mining  
  - Verification of results  


<img width="1559" height="808" alt="image" src="https://github.com/user-attachments/assets/54877452-febd-4c4a-87eb-39a6e42979dd" />
### Purpose of DalFox Testing
- ✅ Confirm whether the URLs flagged by **GF** are actually vulnerable to **XSS attacks**  
- ⚡ Automate payload injection to detect **reflected, stored, or DOM-based XSS**  
- 📑 Document successful findings for further **manual validation**  

---

### Findings (DalFox)
DalFox scanned all URLs from **xss.txt**.  

**Result:**  
- *(Insert result here, e.g., No confirmed XSS vulnerabilities were detected OR DalFox identified potential XSS in specific parameters)*  

---

### Parameter Discovery & Fuzzing
After identifying live URLs, the next step was to discover **endpoints with parameters** and **fuzz for hidden directories or files**.  

**Purpose:**  
- Expands the attack surface  
- Helps locate potential entry points not directly visible to users  

**Command Used:**
```bash
sudo cat urls.txt | grep "?" > param-urls.txt
```
<img width="1194" height="246" alt="image" src="https://github.com/user-attachments/assets/d0d5e71c-1d60-4254-9bb8-b02dcd84f1b5" />
**Command Used:**
```bash
cat param-urls.txt | gf xss > xss-urls.txt
```
<img width="1250" height="279" alt="image" src="https://github.com/user-attachments/assets/42f22596-e751-4310-a5c8-244b06c4f797" />

### Directory and File Fuzzing (FFuF)

**Fuzzing** is a security testing technique used to discover:  
- 🔒 Hidden resources  
- ⚙️ Misconfigurations  
- 🐞 Vulnerabilities  

This is done by automatically injecting large volumes of test inputs into an application.  

In **web application security**, fuzzing is commonly applied to:  
- **Directories & Files** → Discover hidden paths (e.g., `/admin`, `/config`, `/backup.zip`)  
- **Parameters** → Identify input fields that may be vulnerable to injection attacks (e.g., XSS, SQLi, LFI)  
- **Headers & Values** → Test for weaknesses in HTTP headers, cookies, and tokens  

**Primary Goal:**  
Uncover unexpected or unprotected functionality that may not be visible to regular users.  
**Command Used:**
```bash
ffuf -u http://soundcloud.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 50 -mc 200,403 -o results.json
``` 
<img width="1248" height="810" alt="image" src="https://github.com/user-attachments/assets/d097533f-fe06-4e04-8b48-ebaec1152286" />
The objective was to **identify accessible and restricted resources** across **SoundCloud’s subdomains** by performing:  
- 🌐 **Virtual Host (vhost) fuzzing**  
- 📂 **Directory fuzzing**  

This approach helps uncover hidden or restricted endpoints that may not be directly exposed to users. 

<img width="1089" height="519" alt="image" src="https://github.com/user-attachments/assets/2cab2159-89ba-4025-bbc7-2874b83dbaac" />

**Command Used:**
```bash
ffuf -u https://HOST.soundcloud.com/DIR \
     -w alive.txt:HOST \
     -w /usr/share/seclists/Discovery/Web-Content/common.txt:DIR \
     -t 50 -mc 200,403 -o results.json
```
The scan tested multiple combinations of **subdomains** and **directories**.  

Responses were filtered to identify:  
- ✅ **200 (OK)** → Valid, accessible endpoints  
- 🔒 **403 (Forbidden)** → Restricted resources that may require bypass testing  

The results were saved in **results.json** and later parsed into separate files:  
- 📂 **200-urls.txt** → Accessible endpoints  
- 📂 **403-urls.txt** → Restricted endpoints for detailed review  

Extract only the **403 endpoints** into a clean list with this command:

```bash
jq -r '.results[] | select(.status == 403) | .url' results.json > 403-urls.txt
```
### Parameter Discovery (Arjun)

**Arjun** is a parameter discovery tool.  

Many hidden or undocumented parameters exist in web apps (e.g., `?id=`, `?redirect=`, `?next=`, `?lang=`).  

Attackers can abuse these parameters for:  
- 💉 SQL Injection (SQLi)  
- ⚡ Cross-Site Scripting (XSS)  
- 🌐 Server-Side Request Forgery (SSRF)  
- 💻 Remote Code Execution (RCE)  
- 🔀 Open Redirects  

**How it works:**  
Arjun brute-forces **GET** and **POST** parameters by sending requests with wordlist-based parameters and analyzing responses.  
<img width="950" height="347" alt="image" src="https://github.com/user-attachments/assets/3386a336-fb06-4019-807f-072adbb90b0b" />

### OWASP ZAP Automation Testing

**OWASP ZAP (Zed Attack Proxy)** is an open-source web application security scanner.  

It can:  
- 🔍 Intercept traffic (similar to Burp Suite)  
- 🛡️ Scan for vulnerabilities such as **XSS, SQLi, CSRF, SSRF, etc.**  
- ⚙️ Automate reconnaissance, scanning, and reporting via scripts  

**Automation Benefits:**  
- Easily integrates into **CI/CD pipelines** (e.g., Jenkins, GitHub Actions, GitLab)  
- Can be scheduled with **cron jobs** for regular, automated scans  

<img width="1681" height="920" alt="image" src="https://github.com/user-attachments/assets/01842e40-a4f4-4c36-bc59-890394b27677" />

### Scanning with Nuclei

**Nuclei** is a fast, template-based vulnerability scanner.  

It uses **YAML-based templates** to perform security checks such as:  
- 🌐 DNS misconfigurations  
- 🛡️ Web vulnerabilities (XSS, SQLi, RCE, etc.)  
- 📂 Exposure of sensitive files (e.g., `.git`, `.env`)  
- 🐞 CVEs and misconfigurations  

**Why it’s widely used in bug bounty hunting, pentesting, and security audits:**  
- 🚀 It’s fast (written in Go)  
- 👥 Templates are community-driven and regularly updated  
- 🔄 Automates repetitive vulnerability checks  
<img width="1875" height="846" alt="image" src="https://github.com/user-attachments/assets/799c262f-3bde-40c7-9b6d-68a5ce2c9ccb" />
<img width="1280" height="732" alt="image" src="https://github.com/user-attachments/assets/2ef657da-744a-49fc-998a-2d0f5d71a64d" />
[credentials-disclosure] [http] [unknown] [<https://store.soundcloud.com>](https://store.soundcloud.com/)  
`"accessToken":"71c46bdb90a148191c2cbf2099bffd12"`

---

### Details
- **[credentials-disclosure]** → The Nuclei template that got triggered  
  - It looks for **exposed secrets/credentials** in HTTP responses (API keys, tokens, etc.)  

- **[http]** → The protocol scanned was an **HTTP/HTTPS request**  

- **[unknown]** → Severity is not explicitly set in the template *(could be Medium/High)*  

- **Target** → `https://store.soundcloud.com`  

- **Evidence Found** →  
  ```json
  "accessToken":"71c46bdb90a148191c2cbf2099bffd12"
```      
### Is This a Real Vulnerability?

Yes, **potentially**. Access tokens are **sensitive**.  

If valid, they could allow:  
- 🔑 Authentication bypass  
- 📡 API data access  
- 👤 Account takeover (depending on scope)  

---

### Token Validation Command
```bash
curl -s https://store.soundcloud.com | grep accessToken
```
<img width="1905" height="104" alt="image" src="https://github.com/user-attachments/assets/59961f8f-d2ba-42a5-b4bc-132cfa2c101f" />
# Storefront API Token Exposure Analysis

This is a **Storefront API token** (used for reading data like products, collections, etc.).  
It’s **not** the Admin API token (those are private and high-privilege).  

Storefront tokens are usually exposed in client-side code by design.  
Storefront access tokens are public by nature and are **not considered sensitive** in most cases.  

They only allow **read access** to public store data (e.g., products, categories, search).  
They **cannot** modify inventory, process orders, or access private customer data.  

## What You Can Do with a Storefront API Token

If you tried using this token with the Shopify Storefront API, you could:

- Fetch product listings  
- Run searches  
- Query public store info  

You **cannot** access restricted or admin-level data.  

> This is not a vulnerability, but a normal Shopify behavior.  
> In bug bounty testing, this would be considered **informational only**, unless you can prove excessive data exposure (e.g., hidden/unpublished products being accessible).

---

## Conclusion

The Nuclei scanning project successfully demonstrated the use of **automated, template-based vulnerability detection** against a real-world target.  
By leveraging community-driven YAML templates, the tool efficiently identified potential issues such as:

- Credential disclosures  
- Misconfigurations  
- Exposed API tokens  

During the engagement, a **credential disclosure alert** was triggered on `store.soundcloud.com`, where an `accessToken` was exposed in the HTTP response. Upon further validation, it was confirmed that:

- This was a Shopify **Storefront API token**, which is public by design.  
- Storefront tokens allow **read-only access** to public data such as product listings and collections.  

---

## Key Takeaways

- **Nuclei** is highly effective in quickly uncovering exposures and misconfigurations.  
- **Validation of results is essential**, as not all findings are exploitable vulnerabilities.  
- **Context matters**: what looks like a sensitive credential may be part of the platform’s normal design.  
- **Responsible reporting** ensures that bug bounty submissions remain credible by distinguishing between real vulnerabilities and expected behaviors.  

---

## Final Note

This project highlights the importance of combining **automated scanning** with **manual validation** and **contextual analysis**.  
Nuclei’s speed and breadth make it a valuable tool in bug bounty hunting and security assessments, but **human judgment** remains critical in separating true positives from informational findings.












