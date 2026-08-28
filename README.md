# Phishing-Email-Analysis
Phishing email triage reports using real public samples, analyzing headers, URLs, attachments, and threat indicators with safe analysis tools.

---

### **Phishing Triage Workflow**

1. **Static Header Inspection:** Fastest check for domain spoofing.

Inspect raw headers for **SPF/DKIM/DMARC** pass/fail results, matching `Return-Path`, and originating server IP.


2. **Extract & Defang Indicators (IOCs):** Safely copy artifacts without accidental clicks.

Extract URLs and file hashes without opening them directly. Convert strings into defanged formats (e.g., `example[.]com` or `hxxps://`).


3. **Automated Reputation & Sandbox Analysis:** Scalable analysis method for high ticket volume.

Pass extracted file hashes and URLs into threat intelligence aggregators (VirusTotal, URLScan.io) or run automated cloud detonation in a sandbox.


4. **Containment & Eradication:** Protect the enterprise network.

If confirmed malicious: purge the email from recipient inboxes via email gateway/SIEM, block the malicious domain/IP at the firewall/proxy, and isolate any endpoint that executed the payload.


---

Prior to the phishing analysis, I evaluated foundational email security protocols and authentication standards to establish infrastructural context

**Sender Policy Framework (SPF)**
- is an email authentication mechanism defined in RFC 7208 that allows domain owners to publish a list of authorized IP addresses and mail servers in their public DNS records.

**Security Function**
SPF prevents unauthorized IP addresses from sending emails on behalf of a specific domain, mitigating direct domain spoofing.

1. The Actual Flow
Sender sends the email: The attacker's server sends an email claiming to be admin@company.com.

Gmail receives the email: Gmail's incoming server receives the message and looks at the sender's IP address.

Gmail queries Public DNS: Gmail reaches out to public DNS and asks: "Hey, what is company.com's SPF record?"

DNS responds: DNS sends back company.com's authorized IP list.

Gmail compares and decides:

Gmail checks if the sender's IP matches the list.

If it fails, Gmail's security filters use that FAIL status (along with DKIM and DMARC results) to push the email directly into the Spam folder or reject/block it entirely before it hits the inbox.





First look ive found this source code of the html suspicious:

<img alt="" src="http://thebandalisty.com/track/o43062rdzGz18708448Gdrw1821750fYo33632dSjh176" width="1px" height="1px" style="visibility:hidden">

it is purposely small and hidden to the body of the email, i did run the url to the virustotal and result is that 3 security vendors flagged this as malicious while 7 of security flagged this as Phishing and one vendor flagged as Suspicious

so far this is progress of my investigation to this malicious email
