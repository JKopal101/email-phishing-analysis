# Analysing a Phishing Email

## Project Overview

### Goal
To identify potential malicious qualities in emails. Email phishing is the most common cyber-social engineering attack in cybersecurity, requiring vigilance. Attackers craft emails to look as real as possible to deceive victims, often for financial gain. The sample analyzed in this case pretends to be from an official bank, Chase Bank.  

## Approach & Tools

### Spotting Red Flags in Email

- **Unfamiliar sender or email address**:  
  - From an `@proton.me` email, which doesn't seem legitimate for a bank. Different domain names can indicate spoofing.
  - The "Reply-To" email differs from the sender.

- **Urgent or alarming language**:  
  - Email states that the recipient's bank account has been locked.

- **Suspicious attachments or links**:  
  - Unexpected links requesting sensitive information (e.g., "Reactivate Your Account" button).

- **Generic greetings**:  
  - Uses broad salutations like "Dear Customer" instead of addressing the recipient by name.

- **Spelling and grammar mistakes**:  
  - Poor grammar and vague messaging.

- **Request for personal or financial information**:  
  - Asks for passwords, credit card numbers, or bank details.

- **Mismatch between display name and email address**:  
  - Display name shows "Chase Online Service" while the email address is from `kellyellen425@proton.me`.

- **Inconsistent or suspicious URLs**:  
  - Hovering over links reveals `dsgo.to`, which is not a Chase Bank domain.

- **Unexpected request for payment**:  
  - No direct request for payment found.

- **Too good to be true offers**:  
  - No unrealistic offers.

- **Unfamiliar or odd attachments**:  
  - No attachments found in this email.

- **Lack of company branding**:  
  - Uses the Chase Bank logo, but inconsistently.

### Unusual Sender’s Email Domain
- The email comes from an untrusted domain (`@proton.me`) rather than the official company domain.
- The "From" address appears to be `alerts@chase.com`, but the "Reply-To" address is `kellyellin426@proton.me`.
- No legitimate email signature from Chase Bank.

### Tools Used:
- Python Email IOC Extractor
- Whois command
- [DomainTools.com](https://www.domaintools.com/) - Whois Lookup
- [URLscan.io](https://urlscan.io/)
- Sublime Text (Header Analysis)
- CyberChef (Decoding the URL)
- VirusTotal

## Implementation & Findings

### "From" Address
- Appears as `alerts@chase.com`, but the actual sender is a ProtonMail address.

### "Reply-To" Address
- Differs from the "From" address, a common tactic to redirect replies to scammers.

### "Received" Fields
- Tracing the email path reveals an unrelated provider.
- IP address analysis using MXToolbox or IPVoid indicates possible phishing association.

### External Links and Attachments
- Hovering over links shows mismatched URLs.
- VirusTotal and PhishTank scans can confirm malicious intent.
- No attachments were found in this email.

### DKIM, SPF, and DMARC Authentication
- **DKIM**: Signature timeout, indicating potential spoofing.
- **SPF**: The email passes SPF authentication since ProtonMail is a legitimate email service, but it redirects replies to an unofficial address.
- **DMARC**: Failed due to misalignment between the sender’s domain and the email signature.

### Message-ID Analysis
- Unique but does not raise immediate concerns.

### Subject Encoding and Language
- No encoding issues, but the subject is vague and socially engineered.

## Sample Phishing Email Headers

```plaintext
Date: Wed, 01 May 2024 20:04:05 +0000
Subject: Your Bank Account has been blocked due to unusual activities
To: Bob Sanders <bob.sanders@corhalitech.com>
From: alerts@chase.com
Reply-To: kellyellin426@proton.me
Return-Path: kellyellin426@proton.me
Sender IP: 185.70.40.140 (registered to ProtonMail)
Resolve Host: mail-40140.protonmail.ch
Message ID: <i7g9MMh5NtErtaOzQZEp3D-i-u3FWwdo0wY5mhD8Q1vIvv1yeLj-jMWPAn-HP3FugKsucesWSubO0Vns8GRFYG0aH4MyU2paqP6yUnRcgaU=@protonmail.com>
Subject: "Your Bank Account has been blocked due to unusual activity"
```

### URL Analysis
- Main URL link (when hovering over "Reactivate Your Account"):
  ```plaintext
  hxxps[://]dsgo[.]to/CQECQECnpqY3NDSGtODt9ft2qtxzcXGUveTV5fRYmtYAZsQCnpqY3NDSGtODt9ft2qtxzcXGUveTV5fRYmtYAZsQCQECnpqY3NDSGtODt9ft2qtxzcXGUveTV5fRYmtYAZsQ
  ```
- URLScan and VirusTotal did not flag the URL, but it does not lead to Chase Bank.

## Verdict
- The sender is unaffiliated with Chase Bank, making this a clear impersonation attempt.
- The "From" and "Reply-To" addresses differ.
- The domain failed DMARC authentication.
- The email includes suspicious links leading to an unrelated domain.

## Solutions & Recommendations
- **Blocking actions**:
  - Block the sender's email address on the email gateway.
  - Block the suspicious URL in Endpoint Detection and Response (EDR) and Web Proxy.
- **Incident response**:
  - Investigate whether other users received similar emails.
  - Check email logs for further phishing attempts.
- **User Awareness**:
  - Educate employees on phishing indicators.
  - Encourage verification of suspicious emails with IT/security teams.

## Conclusion & References
- **Phishing Likelihood**: High.
- The mismatched sender email, failed DMARC check, and suspicious link indicate a phishing attempt.
- References:
  - [MXToolbox](https://mxtoolbox.com/)
  - [VirusTotal](https://www.virustotal.com/)
  - [PhishTank](https://www.phishtank.com/)
  - [URLScan.io](https://urlscan.io/)
