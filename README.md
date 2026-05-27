# Threat-Intelligence-Project-Report-NETFLIX
An OSINT-based Cyber Threat Intelligence (CTI) assessment evaluating the external digital footprint, brand impersonation vectors, and infrastructure exposure of Netflix Inc. Features a structured analysis mapped to the MITRE ATT&amp;CK framework with actionable enterprise mitigations.
# Cyber Threat Intelligence Report

## 📄 [Download Full Project PDF](./Threat%20Intelligence%20capstone%20project%20on%20Netflix.pdf)

---

**Project Title:** OSINT-Based Threat Intelligence Assessment[cite: 1] 
**Target Organization:** Netflix Inc.[cite: 1] 
**Industry Sector:** Technology/Media & Entertainment[cite: 1] 
**Analyst:** Remi Adeparusi[cite: 1] 
**Date:** January 22nd, 2026[cite: 1] 

---

## Confidentiality Notice
This report contains defensive Cyber threat intelligence derived exclusively from publicly available open-source information (OSINT)[cite: 1]. It is prepared strictly for educational and analytical purposes and does not include exploitation, intrusion, or unauthorized access activities[cite: 1].

---

## 1. Executive Summary
This report presents an Open-Source Intelligence (OSINT) threat intelligence assessment of Netflix, Inc[cite: 1]. It focuses on phishing, brand impersonation, and credential harvesting threats[cite: 1]. By using only passive and ethical intelligence collection techniques, the analysis shows how threat actors take advantage of publicly available information and trusted cloud services to mislead Netflix customers[cite: 1]. 

The active phishing pages, exposed subdomains, and legitimate cloud infrastructure (AWS) that attackers use to get around security filters[cite: 1]. Even though Netflix has strong email authentication and security controls, attackers continue to adapt through social engineering, which remains a constant high business risk due to attackers using trusted cloud infrastructure for phishing makes it more likely that attackers will successfully collect credentials[cite: 1]. This could lead to financial loss from account takeovers, damage to reputation from brand abuse, and a decrease in customer trust[cite: 1]. 

**Primary Recommendation:** Use improved domain monitoring and automated take-down services for look-alike domains[cite: 1].

---

## 2. Organization Profile & Footprint

### 2.1 Organization Profile/Overview
Netflix, Inc. is a global streaming service that offers subscription video on demand in over 190 countries[cite: 1]. Some of its core services include film/television production, streaming media, and mobile gaming[cite: 1]. Its wide online presence, which includes login portals, billing systems, customer support platforms, and mobile apps, makes the brand a common target for phishing and fraud-related cybercrime[cite: 1].

### 2.2 Netflix Digital Footprint
Netflix has a high digital footprint globally as it provides a platform where customers can carry out their online services[cite: 1]. The digital footprint raises the visibility and trust that the firm enjoys; despite that, it presents an enablement target and a platform where driven reconnaissance and brand impersonation can take place[cite: 1]. Its huge digital footprint is characterized by wide subdomains such as:
* **netflix.com** (Main site for customer logins, managing accounts, handling billing, and password resets)[cite: 1].
* **help.netflix.com**[cite: 1].
* **aboutnetflix.com**[cite: 1].
* **Social Media handles:** Instagram (@netflix), waernetflix[cite: 1].

---

## 3. Scope and Objectives

### 3.1 Intelligence Objectives
The main objective of this assessment is to understand how the information made public can be utilized in conducting phishing activities, brand impersonation, credential harvesting, and other fraudulent activities against Netflix and its customers[cite: 1]. Through the application of ethical and passive OSINT approaches, the assessment aims at identifying the risks from the public digital footprint of Netflix and conducting ways through which these risks can create a potential impact on its customers and its daily business operations[cite: 1].

**This project aims to:**
* Determine phishing and impersonation campaigns targeting Netflix by examining indexed pages of Netflix logins, account recovery mechanisms, and popular Netflix-themed content often used in social engineering attacks[cite: 1].
* Find exposed or observable assets including domains, subdomains, email formats, and past web page content that can be used as leverage by the attacker when creating a campaign of phishing or simply gathering information[cite: 1].
* Measure the degree of brand abuse for fraud involving look-alike domains, replicated web pages, and third-party infrastructures with the intent to trick Netflix subscribers into giving their credentials and payment details[cite: 1].
* Obtain attacker intents and methods by combining results from the correlation of OSINT with the MITRE ATT&CK reference and identifying the ways the attacker can advance from reconnaissance to credential theft and takeover[cite: 1].
* Explain and translate technical observations into a business-relevant risk regarding what it means to their reputation, customer trust, and possible loss as opposed to exploitability of the system[cite: 1].

### 3.2 Scope & Limitations
The Netflix OSINT project is based solely on open-source intelligence with no active scanning, penetration testing, or exploitation of systems whatsoever[cite: 1]. Only information gathered from public sources is considered for this project while ensuring that all activities were done within ethical and legal bounds to make this project information-based only[cite: 1].

---

## 4. Methodology & Tools Used

### 4.1 OSINT Methodology
* **Planning Phase:** Started with explaining intelligence requirements such as identification of Phishing, brand Impersonation, and fraud risks to Netflix[cite: 1]. The assessment only took into account publicly available information related to the external digital footprint of Netflix; no scanning or exploitation was performed[cite: 1].
* **Collection Phase:** Publicly available and accessible data was collected through ethical OSINT practices like the use of search engines, domain enumeration, online reputation information, and web archiving[cite: 1]. Emphasis is placed on domains, subdomains, email patterns, login pages, account-related pages, and phishing indicators often exploited by attackers[cite: 1].
* **Processing Phase:** We utilized the data that was previously collected, reviewed, filtered, and validated in order to reduce the occurrence of false positives while removing any extra information that was not required[cite: 1]. Indicators were also enriched using "Reputation Services" in order to verify their legitimacy while checking their abuse history in an accurate manner[cite: 1].
* **Analysis Phase:** Validated information was analyzed to understand attacker intent, technique, or potential scope[cite: 1]. Observations were also correlated with the MITRE ATT&CK framework to understand the potential capabilities that attackers could utilize while moving from reconnaissance stages, credential theft, and fraud leveraging the brand name Netflix[cite: 1].
* **Dissemination Phase:** The results were disseminated and documented in a structured threat intelligence report designed for a SOC and CTI audience[cite: 1]. Findings were translated into business-relevant risks supported by evidence, with actionable mitigation recommendations provided to reduce exposure[cite: 1].

### 4.2 Tools Utilized
* **Google Dorks:** Used to find publicly indexed content related to Netflix login portals, password reset mechanisms, security documents, etc[cite: 1]. This was used to imitate the behavior of attackers looking for high-value userspace content that often ends up being cloned to perform phishing attacks[cite: 1].
* **theHarvester:** Used to make a passive enumeration of email patterns and subdomain names associated with Netflix from publicly available information[cite: 1]. This illustrates how attackers gather legitimate-appearing forms of emails and web content that could be used to impersonate and social engineer[cite: 1].
* **Shodan:** Used at a high level to verify the presence of publicly identifiable services associated with Netflix[cite: 1]. No host selection, port, or vulnerability identification was made[cite: 1]. The tool allows for the comprehension of the outside view of the system on the part of the attacker[cite: 1].
* **Wayback Machine:** Used to investigate different historical designs of Netflix's online web pages such as their login page and support page designs in terms of how they might have been utilized by malicious actors to phish unsuspecting visitors to these websites[cite: 1].
* **MXToolbox:** Used to assess the email authentication posture of Netflix, including SPF, DKIM, and DMARC[cite: 1]. Results show that it has great protections in place to prevent direct domain spoofing[cite: 1]. 
* **VirusTotal:** Used to evaluate the reputation of Netflix-themed URLs and phishing indicators; the tool helps confirm if the suspicious link has been previously flagged by security vendors or the community[cite: 1].
* **URLScan.io:** Used to safely observe the behavior of suspected phishing URLs without direct interaction[cite: 1]. This gives context on page structure, redirection behavior, and the loading of external resources[cite: 1].
* **AbuseIPDB:** Used to evaluate the historical reputation of IP addresses used to host phishing infrastructure[cite: 1]. This also enables the identification of frequently misused cloud-based services by criminals[cite: 1].
* **WHOIS:** Used in validating and ensuring domain ownership, registration details, and age[cite: 1]. This is done to identify genuine Netflix properties from recently registered Similarly named domains usually used in phishing[cite: 1].
* **Have I Been Pwned:** Used for checking if the publicly disclosed email addresses related to Netflix were present in any data breaches[cite: 1]. This step assists with the verification of indicators as well as the minimization of false-positive occurrences[cite: 1].

---

## 5. OSINT Collection Summary
This assessment went through a collection of several openly sourced data points through ethical OSINT techniques in order to assess phishing campaigns, brand impersonation, credential harvesting, and fraud risks against Netflix[cite: 1]. The focus of this collection phase was on identifying information that could be used by threat actors in reconnaissance and social engineering activities[cite: 1].

### Data Types Collected:
* **Domains and look-alike domains** similar to Netflix branding, including publicly observable login, billing, and support-related URLs[cite: 1]. These were studied in order to understand how attackers could build domains that look very similar for phishing and impersonation campaigns[cite: 1].
* **Information regarding Email addresses** and email pattern identification concerning Netflix and publicly available Internet services[cite: 1]. This information illustrates ways an attacker can develop legitimate mail address formats to send phishing emails[cite: 1].
* **IP addresses and related providers** of web hosting services used to conduct suspicious phishing activities[cite: 1]. These indicators were referenced at a high level to focus on the use of third-party or cloud-hosted services usually misused by attackers[cite: 1].
* **URLs related to phishing, brand impersonation, fraudulent and credentialing activity attacks**, like URLs found in phishing messages themed on Netflix and other phishing pages disguised as Netflix[cite: 1].
* **Historical web content** like old login and account-related content that demonstrates how attackers reuse old legitimate designs to add credibility to phishing campaigns[cite: 1].
* **Email authentication information**, as well as reputation metadata, including SPF, DKIM, DMARC, and public reputation[cite: 1]. This helps assess the organization's immunity towards domain spoofing and the attacker using alternative delivery methods[cite: 1].

---

## 6. Key Findings & Exposure

### 6.1 Phishing and Brand Impersonation
This part highlights the observation of threat actors using the trusted brand name of Netflix in an attempt to swindle its end-users for their own financial benefit[cite: 1]. Financial gain and payment fraud are the most noticeable themes in the emails[cite: 1]. Attackers often launch a spear-phishing attack where they encourage the user to click on malicious links to verify their account or change payment details[cite: 1]. All campaigns employ electronically mediated social engineering tactics to induce a sense of legitimacy[cite: 1].

* **Look-alike domains and infrastructure identified:** The adversaries were found to utilize the email delivery system of the popular online cloud service, Amazon Web Services (AWS), which is considered to be a safe delivery platform[cite: 1]. By doing so, the adversaries can avoid detection by other threat intelligence tools that will flag the mail as being "clean" due to the source reputation[cite: 1]. The attackers, during the reconnaissance stage, have been observed to use third-party domains in order to carry out their attack lifecycle[cite: 1]. A particular IP address, `54.240.4.22`, was found and processed through the tool AbuseIPDB as a part of the infrastructure for the attacks[cite: 1].
* **Fake login pages and cloned content:** Using the Google Dork `inurl:netflix login` reveals active phishing pages that look like the official network login portal[cite: 1]. Threat actors were successful at cloning the Netflix logo to deceive customers of its authenticity[cite: 1]. The fake pages were designed to capture inputs, allowing attackers to harvest users' credentials when entered[cite: 1].

### 6.2 Infrastructure Exposure
This section reviews the technical assets, cloud techniques, and patterns that reveal Netflix's digital presence and exposure to potential exploitation[cite: 1].

* Researching the publicly visible services based on the results of `shodan.io` searches (`org:"netflix"`) and `theHarvester` results revealed an exposure of some subdomains[cite: 1]. Shodan reported some open ports associated with the Netflix organization, with some detailed reporting on port configuration and their organizational service maps[cite: 1]. Wayback Machine history revealed how Netflix web design has evolved, helping threat actors build clones for phishing[cite: 1].
* In regard to the cloud or hosting patterns abused by attackers, adversaries do not simply carry out attacks against Netflix; instead, they utilize trusted cloud ecosystems to remain under the cover of their ill practices[cite: 1].
* The analysis of phishing samples collected via MXToolbox showed that the cyberattackers are taking advantage of the Amazon Web Services (AWS) infrastructure, revealing the abuse of trusted infrastructure[cite: 1]. Because AWS is a trusted cloud email delivery infrastructure, threat intelligence tools or services like VirusTotal have labeled the emails as "clean," which impacted the initial results[cite: 1].
* Cybercriminals were discovered to be acquiring, renting, or leasing third-party domains to host and support their activities, mimicking Netflix's hosting infrastructure, logos, etc[cite: 1]. Cybercriminals employ different solutions, including physical or virtual infrastructure hosting via relaying information to and from compromised systems through legitimate public web services[cite: 1].

### 6.3 Data Leakage Indicators
Publicly accessible documents related to Netflix, including policy and security materials, were found using passive search methods[cite: 1]. This matters because even if documents don't include sensitive information, they can give attackers access to legitimate branding, logos, and formatting[cite: 1]. They can as well expose official language used in customer communications and insight into account recovery or security processes[cite: 1]. These can be reused to create convincing phishing emails and cloned web pages, increasing the chance of user interaction[cite: 1].

Under the breached or leaked email addresses (no credentials), publicly discovered Netflix-related email addresses were found and checked against known breach databases[cite: 1]. No exposed credentials were observed[cite: 1]. This matters because, though no credentials were discovered, exposing valid email addresses or patterns allows attackers to create realistic sender or recipient addresses, target spear-phishing campaigns more effectively, and boost trust by mimicking legitimate Netflix communication formats[cite: 1]. This information makes it easier for attackers during reconnaissance and raises their chances of successful phishing[cite: 1]. The email `hcho@netflix.com` was identified via theHarvester and was revealed to have appeared in historical data breaches using `haveibeenpwned.com`[cite: 1].

---

## 7. Threat Analysis & Risk Assessment

### 7.1 Likely Attack Paths
From the threat actor's perspective, the collected OSINT gives enough information to support phishing and brand impersonation campaigns without needing to compromise systems directly[cite: 1].
1. **Reconnaissance:** Attackers collect publicly available Netflix login pages, email formats, and past web designs[cite: 1].
2. **Resource Development:** They create look-alike domains and cloned login pages using Netflix branding and language[cite: 1].
3. **Delivery:** Phishing emails are sent from third-party or cloud-hosted systems to avoid detection and appear more legitimate[cite: 1].
4. **Credential Harvesting:** Victims are redirected to fake login or billing pages where their credentials or payment details are captured[cite: 1].
5. **Exploitation and Impact:** Compromised accounts are used for subscription fraud, resale, or further social engineering[cite: 1].

### Common Attacker Techniques:
* Brand impersonation with look-alike domains[cite: 1].
* Social engineering through urgent messaging[cite: 1].
* Credential harvesting using cloned login pages[cite: 1].
* Use of trusted cloud services to lower the chances of detection[cite: 1].

### Alignment With Known Threat Behaviors (MITRE ATT&CK)
The observed activity matches established adversary techniques:
* **Reconnaissance - Phishing for Information (T1598):** Collecting user and organization information to aid targeting[cite: 1].
* **Resource Development - Acquire Infrastructure (T1583):** Registering domains and using third-party hosting services[cite: 1].
* **Initial Access - Phishing (T1566):** Delivering malicious links through impersonation emails[cite: 1].
* **Credential Access - Input Capture (T1056):** Harvesting credentials using fake web forms[cite: 1].
* **Command and Control - Web Services (T1102):** Sending captured data through legitimate external services[cite: 1].

### 7.2 Business Risk Impact

| Risk Category | Impact Level | Description |
| :--- | :--- | :--- |
| **Brand Reputation**[cite: 1] | **High**[cite: 1] | Brand impersonation and phishing directly influence public perception because customers link fraudulent communications to Netflix[cite: 1]. Ongoing phishing campaigns weaken confidence in official communications[cite: 1]. Negative experiences are often shared publicly, increasing reputation harm[cite: 1]. |
| **Customer Trust**[cite: 1] | **High**[cite: 1] | Trust is crucial for subscription-based services[cite: 1]. Successful phishing lowers confidence in account security[cite: 1]. Users may hesitate to engage with legitimate Netflix emails[cite: 1]. Loss of trust can lead to account cancellations or decreased engagement[cite: 1]. Even unsuccessful phishing attempts harm customer trust over time[cite: 1]. |
| **Financial Fraud**[cite: 1] | **Medium-High**[cite: 1] | Phishing and account takeover campaigns targeting Netflix customers can lead to subscription fraud, unauthorized account access, customer support costs, refunds, fraud prevention, and higher spending on monitoring and take-down efforts[cite: 1]. While Netflix's core infrastructure remains secure, the size of the user base increases the financial impact of even low-cost phishing operations[cite: 1]. |
| **Operational/Regulatory**[cite: 1] | **Low-Medium**[cite: 1] | There was no evidence of internal data breaches or regulatory violations[cite: 1]. However, misuse of customer data through phishing may lead to regulatory scrutiny[cite: 1]. Areas with strict consumer protection laws may demand notification or investigation[cite: 1]. Regulatory exposure is limited but could grow if phishing activity increases or causes widespread consumer harm[cite: 1]. |

---

## 8. Mitigation & Recommendations

* **Brand Monitoring and Takedown Processes:** There should be continuous brand monitoring to find look-alike domains, fake websites, and impersonation campaigns that target Netflix[cite: 1]. This should be done by closely monitoring newly registered domains that look like Netflix branding, setting up quick takedown processes with registrars and hosting providers, and working with threat intelligence vendors to detect brand abuse[cite: 1]. Finding issues early shortens the lifespan of phishing campaigns and limits customer exposure[cite: 1].
* **Email Security Improvements (SPF, DKIM, DMARC):** Maintain and enforce strong email authentication policies to prevent domain spoofing and impersonation[cite: 1]. Continue enforcing DMARC with a strict policy[cite: 1]. Regularly review SPF and DKIM settings for third-party services[cite: 1]. DMARC reports for spoofing attempts and trends in abuse should be monitored[cite: 1]. This action will force attackers into relying on less trusted infrastructure, which increases detection and reduces the effectiveness of their campaigns[cite: 1].
* **User Awareness and Phishing Education:** Strengthen customer awareness programs that focus on identifying phishing and fraudulent communications[cite: 1]. This can be achieved by publishing clear guidance on official Netflix communication practices, regularly reminding users to verify URLs before entering their credentials, and providing simple ways for users to report suspected phishing attempts[cite: 1]. An informed user base greatly reduces the success rate of social engineering attacks[cite: 1].
* **Continuous OSINT and Threat Monitoring:** Integrate continuous OSINT monitoring into the threat process to identify emerging threats early[cite: 1]. This should be done by monitoring phishing feeds, breach notifications, and abuse databases[cite: 1]. Track trends in attacker infrastructure and their delivery methods[cite: 1]. Periodically reassess exposure using passive OSINT techniques[cite: 1]. Proactive monitoring will allow for early warnings, trend analysis, and quicker responses to changing threats[cite: 1].

---

## 9. Conclusion
This OSINT-based threat intelligence assessment looked at Netflix's external digital presence, focusing on phishing, brand impersonation, credential harvesting, fraud-driven social engineering attacks, and misuse of trusted infrastructure[cite: 1]. The findings show that despite Netflix having strong internal security measures and effective email authentication, its global brand visibility attracts threats driven by social engineering that target customers instead of core systems[cite: 1]. 

Publicly accessible branding elements, login workflows, and communication patterns give attackers enough information to carry out convincing phishing campaigns[cite: 1]. This poses risks of financial loss, reputation harm, and loss of customer trust[cite: 1]. The assessment highlights the need for ongoing OSINT-driven monitoring to catch emerging threats early, support quick responses, and guide risk-based decision-making[cite: 1]. Proactive threat intelligence, along with solid brand protection and user awareness, is crucial for minimizing the impact of external threats and ensuring long-term organizational strength[cite: 1].

---

## 10. Ethical Considerations & Disclaimer
All the data used in this assessment was obtained from publicly available sources of open-source intelligence (OSINT) information[cite: 1]. No active scanning or exploitation of the Netflix infrastructure was performed[cite: 1]. The examination was done solely for academic purposes to assess the exposure to external threats[cite: 1]. No confidential data was used or maintained[cite: 1].

---

## References
* **AbuseIPDB:** Abuseipdb: IP address reputation and abuse reporting. `https://www.abuseipdb.com`[cite: 1]
* **Google:** Google search. `https://www.google.com`[cite: 1]
* **Internet Archive:** Wayback machine. `http://web.archive.org`[cite: 1]
* **MXToolbox:** MXToolbox: DNS, blacklist, and email diagnostics. `https://mxtoolbox.com`[cite: 1]
* **Shodan:** Shodan search engine. `https://www.shodan.io`[cite: 1]
* **VirusTotal:** VirusTotal: Analyzing suspicious files and URLs. `https://www.virustotal.com`[cite: 1]
* **theHarvester:** theHarvester OSINT tool. `https://github.com/laramies/theHarvester`[cite: 1]
* **MITRE:** MITRE ATT&CK: Adversary tactics and techniques knowledge base. `https://attack.mitre.org`[cite: 1]
