# Phishing-Email-Analysis
 <br>

 ## ⚠️  Disclaimer

* **Educational & Research Purpose Only:** This analysis report and associated artifacts are compiled strictly for educational, threat research, and defensive security purposes. 
* **Defanged Indicators:** All malicious URLs, IP addresses, and domain names within this documentation have been intentionally defanged to prevent accidental execution or navigation. Do not attempt to re-enable or visit these domains outside of a dedicated, isolated sandbox environment.
* **No Malicious Code Redistribution:** This repository contains static forensic documentation and metadata extracted from the message source. It does not host executable malware, active exploit payloads, or weaponized scripts.

## 🌐 Sample Source & Acknowledgments

* **Sample Origin:** The analyzed `.eml` sample was sourced from the open-source threat repository **PhishPot** by **rf-peixoto/phishing_pot.git** (https://github.com/rf-peixoto/phishing_pot)
* **Analysis Scope:** All forensics conducted in this report are based strictly on static source code analysis of the raw email file (`.eml`). No active infrastructure was dynamically interacted with or exploited during this investigation.

---
Before performing phishing triage, I reviewed core email authentication protocols—SPF, DKIM, and DMARC—to establish the technical baseline required for verifying domain legitimacy and header integrity


---

# Sender Policy Framework (SPF)

* is an email authentication protocol defined in RFC 7208 that allows domain owners to publish a list of authorized IP addresses and mail servers in their public DNS records.

## Security Function

Prevents unauthorized IP addresses from sending emails on behalf of a specific domain, mitigating direct domain spoofing and unauthenticated mail delivery.

###  1. Publishing Process (Sender Side)

* **Step 1:** The domain owner identifies all mail servers and third-party services authorized to send email for their domain.
* **Step 2:** The domain owner creates an SPF record specifying those authorized IP addresses, CIDR blocks, or mechanisms (`include:`).
* **Step 3:** The domain owner publishes this record as a TXT record in their public DNS zone (e.g., `v=spf1 ip4:192.0.2.1 include:_spf.google.com ~all`).

###  2. Verification Process (Receiver Side)

* **Step 1:** The recipient's mail server receives the incoming email from a sending server IP address.
* **Step 2:** It extracts the envelope sender domain (`MAIL FROM` / Return-Path) from the SMTP session.
* **Step 3:** It queries public DNS for the SPF TXT record of that exact envelope domain.
* **Step 4:** It fetches the authorized IP list and compares the actual sending server IP address against it.
* **Step 5:** It evaluates the result and assigns an SPF status:
* **Pass:** The sending IP is explicitly authorized in the SPF record.
* **Fail / SoftFail (`-all` / `~all`):** The sending IP is not authorized (the email is flagged as suspicious, routed to Spam, or rejected).

---


## DKIM (DomainKeys Identified Mail)
* is an email authentication protocol that uses public-key cryptography to prove an email's sender identity and guarantee its content was not tampered with in transit.

## Security Function

###  1. Signing Process (Sender Side)

* **Step 1:** The sender's mail server takes the email headers and body.
* **Step 2:** It hashes them into a single fingerprint using the **SHA-256** algorithm.
* **Step 3:** It encrypts that hash using its secret **Private Key**.
* **Step 4:** That encrypted hash is attached to the email header as the **digital signature (`b=`)**.

---

###  2. Verification Process (Receiver Side)

* **Step 1:** The recipient's mail server receives the email and extracts the `DKIM-Signature` header.
* **Step 2:** It fetches the sender’s **Public Key** from their public DNS records (`selector._domainkey.domain.com`).
* **Step 3:** It decrypts the digital signature (`b=`) using that Public Key to reveal the original hash.
* **Step 4:** It independently hashes the received email headers and body to create a new fingerprint.
* **Step 5:** It compares both hashes:
* **Match:** `dkim=pass` (The email is authentic and was not altered).
* **Mismatch:** `dkim=fail` (The email was tampered with or sent by an unauthorized server).


---


## Domain-based Message Authentication, Reporting, and Conformance (DMARC)

* is an email authentication protocol defined in RFC 7489 that builds on SPF and DKIM to allow domain owners to enforce policy actions for failing emails and receive aggregate reporting on domain usage.

## Security Function

Prevents direct domain spoofing and phishing by enforcing **Identifier Alignment** between SPF/DKIM authentication and the visible `From:` header, instructing receiving servers how to handle unauthenticated messages (`none`, `quarantine`, or `reject`).

### 1. Publishing & Policy Setup (Sender Side)

* **Step 1:** The domain owner ensures SPF and/or DKIM protocols are properly configured for their sending infrastructure.
* **Step 2:** The domain owner determines their desired policy enforcement level (`p=none`, `p=quarantine`, or `p=reject`) and specifies aggregate report destinations (`rua=`).
* **Step 3:** The domain owner publishes a TXT record at the `_dmarc` subdomain in public DNS (e.g., `v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com`).

###  2. Verification & Policy Enforcement Process (Receiver Side)

* **Step 1:** The recipient's mail server receives an incoming email and performs standard SPF and DKIM checks.
* **Step 2:** It extracts the domain visible to the end-user in the email client's `From:` header.
* **Step 3:** It evaluates **Identifier Alignment**:
* **SPF Alignment:** Checks if the SPF-authenticated domain (`MAIL FROM`) matches the visible `From:` domain.
* **DKIM Alignment:** Checks if the DKIM signing domain (`d=`) matches the visible `From:` domain.


* **Step 4:** It queries public DNS for the DMARC record published at `_dmarc.[From-Domain]`.
* **Step 5:** It determines the final DMARC status and executes the domain owner's policy:
* **Pass:** At least one protocol (SPF or DKIM) passes **AND** aligns with the visible `From:` domain. The email is delivered normally.
* **Fail:** Neither protocol passes with alignment. The receiving server enforces the published policy (`p=none` delivers with reporting, `p=quarantine` sends to Spam, `p=reject` blocks delivery).


---


### **Phishing Triage Workflow**

1. **Static Header Inspection:** Check headers for authentication anomalies and sender spoofing.
   Inspect raw headers for **SPF/DKIM/DMARC** validation results, verify alignment between the `Header From`, `Return-Path`, and `Reply-To` addresses, and identify the originating mail relay IP.

2. **Body & Payload Inspection (HTML Source Analysis):** Safely analyze the message body and embedded content.
   Examine the raw `.eml` HTML source code to identify zero-attachment triggers (such as hidden 1x1 tracking pixels/web beacons) and verify underlying hyperlinked URLs against their displayed anchor text.

3. **Artifact Extraction & Defanging:** Safely document indicators without risk of execution.
   Extract all network artifacts (IPs, domain names, tracking endpoints, and landing page URLs) and convert them into defanged formats (e.g., `hxxps[:]//` and `domain[.]com`) to prevent accidental clicks during documentation.

4. **Reputation & Infrastructure Lookups:** Evaluate threat intelligence across external aggregators.
   Query extracted IOCs against threat intelligence tools (VirusTotal, URLScan.io, and WHOIS) to assess vendor detections, analyze rendered landing pages, evaluate domain registration age, and check host IP reputation.

5. **Containment & Remediation:** Mitigate risk across the environment based on confirmed indicators.
   If confirmed malicious: block the malicious IPs and domains at the firewall/web proxy, purge matching messages tenant-wide via the Secure Email Gateway (SEG), and investigate endpoint or identity logs if any user interacted with the payload.
---


## 1. Incident Overview
* **Source:** PhishingPot ((https://github.com/rf-peixoto/phishing_pot))
* **Final Verdict:** Phishing / Credential Harvesting <!-- Options: Benign, Spam, Phishing, Malicious Payload -->
* **Risk Level:** High <!-- Options: Low, Medium, High, Critical -->

### Summary
A suspicious email sample simulating an account security alert was extracted from PhishPot for threat analysis. Initial header and protocol triage revealed unverified authentication (`spf=none`, `dkim=none`, `dmarc=permerror`). Because automated email gateway controls could not verify the sender, investigation pivoted to payload triage. Analysis of the email body revealed a typo-squatted URL designed for credential harvesting.

---

## 2. Email Header & Authentication Triage

### Key Header Metadata
* **Header From (Visible From):** `Microsoft account team <no-reply@access-accsecurity[.]com>`
* **Return-Path (MAIL FROM / Envelope Sender):** `thcultarfdes[.]co[.]uk`
* **Reply-To:** `sotrecognizd@gmail[.]com` <!-- Notice the mismatch with both From and Return-Path! -->
* **To:** `phishing@pot`
* **Subject:** `Microsoft account unusual signin activity`
* **Message-ID:** `<032672b4-77ca-42f8-a036-9711e91bd1f3@DB8EUR06FT032[.]eop-eur06[.]prod[.]protection[.]outlook[.]com>` 
* **Originating IP:** `89[.]144[.]44.2`


### Protocol Authentication Checks
* **SPF Status:** `spf=none` — No SPF record published or evaluated for the sending domain.
* **DKIM Status:** `dkim=none` — Email contains no cryptographic DKIM signature.
* **DMARC Status:** `dmarc=permerror` — DNS TXT record for DMARC is malformed or invalid; gateway action defaulted to `action=none`.


 **Triage Decision:** Because SPF, DKIM, and DMARC are unverified, automated authentication cannot confirm sender identity. Moving directly to Phase 2: Payload and Content Analysis.

---

## 3. Email Body & Social Engineering Analysis

* **Psychological Tactics:** Urgency / Fear of Account Loss (e.g., "Account suspended within 24 hours").
* **Brand Impersonation:** Mimicking official corporate security alert banners.

---

## 4. My Findings

After completing header authentication triage, I analyzed the raw .eml body code for embedded URLs and hidden HTML tags. No file attachments were present in this sample. The body inspection revealed the following components:

### 1. Embedded Tracking Pixel (Web Beacon)
* **Code Snippet:** `<img alt="" src="hxxp[:]//thebandalisty[.]com/track/o43062rdzGz18708448Gdrw1821750fYo33632dSjh176" width="1px" height="1px" style="visibility:hidden">`

* **Purpose:** User Tracking & Target Telemetry (Silently confirms active inbox, logs victim IP address, and captures open timestamp via automated HTTP GET request).
* **Threat Intelligence:**
  * **VirusTotal:** `11` vendor detections (3 flagged as Malicious, 7 flagged as Phishing and 1 flagged as Suspicious).
---

## 5. MITRE ATT&CK Mapping

* **Primary Technique:** Phishing for Information: Spearphishing Link (`T1598.003`)
* **Tactic:** Reconnaissance
* **Context:** Adversaries embed links and 1x1 tracking pixels ("web beacons") in HTML emails to solicit credentials and trigger remote requests that log recipient telemetry.

| Sub-Technique / Secondary ID | Technique Name | Context |
| :--- | :--- | :--- |
| `T1598.003` | Phishing for Information: Spearphishing Link | Credential harvesting via fake login portal |


## 6. Key Indicators of Compromise (IOCs)

| Type | Indicator (Defanged) | Context / Function |
| :--- | :--- | :--- |
| **Originating IP** | `89[.]144[.]44[.]2` | Mail Relay & Hosting Server IP |
| **Header From Domain** | `access-accsecurity[.]com` | Impersonated Look-Alike Brand Domain |
| **Return-Path Domain** | `thcultarfdes[.]co[.]uk` | Unauthorized Transmission Domain |
| **Tracking URL** | `hxxp[:]//thebandalisty[.]com/track/o43062rdzGz18708448Gdrw1821750fYo33632dSjh176` | Embedded Web Beacon (Telemetry Trigger) |
| **Phishing Landing URL** | `hxxps[:]//access-accsecurity[.]com/login[.]php` | Credential Harvesting Page |

## 7. Recommended SOC Mitigations

1. **Perimeter Controls:** Block domain `access-accsecurity[.]com` and IP `192[.]0[.]2[.]45` on perimeter firewalls, secure email gateways (SEG), and DNS resolvers.
2. **Mailbox Cleanup:** Purge all emails originating from sender `bounce@untrusted-domain[.]com` across all tenant mailboxes.
3. **Identity & Access Management:** Reset credentials and revoke active session tokens for any users who clicked or submitted information to the phishing portal.
