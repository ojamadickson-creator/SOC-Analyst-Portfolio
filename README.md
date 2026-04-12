# SOC-Analyst-Portfolio(TryHackMe)
Hands-on SOC Analyst projects including Splunk SIEM detection rules, Wireshark incident response investigations, and phishing email analysis.
 Table of Contents

Executive Summary 

Project Overview

Environment & Tools

Asset Prioritization

Alert Triage Summary

False Positives
True Positives

Investigation Methodology — The Five Ws

Post-Compromise Analysis

MITRE ATT&CK Mapping

Incident Report

Threat Intelligence Enrichment

Alert Fine-Tuning Recommendations

Remediation & Incident Response

Simulation Results & KPIs

Lessons Learned

Skills Demonstrate

 

 
 Executive Summary
 
This project documents a real-world simulation of a cyberattack against a company, processed and investigated by a Security Operations Center (SOC) analyst(Ojama Dickson). Think of the SOC as your organization's security watchtower — analysts monitor thousands of alerts every day and must quickly determine which ones represent genuine threats and which are harmless background noise.
What happened in this simulation:
The attacker sent a carefully crafted email to the company's CEO, Michael Scott. The email was disguised as an overdue invoice, threatening legal action unless an attachment was opened immediately. This tactic called phishing, is one of the most common ways attackers break into organizations. Once the CEO opened the attachment, the attacker gained access to his computer and began quietly exploring the network, looking for financial records and sensitive data.
What the SOC analyst did:
Out of 36 alerts received, I correctly identified every genuine threat (100% True Positive rate) while also correctly dismissing the majority of false alarms (79% False Positive rate). This balance is critical — missing a real threat can be catastrophic, but raising too many false alarms causes "alert fatigue," making analysts less effective over time.
Why this matters to your business:
A single compromised executive account can expose sensitive financial data, damage your company's reputation, and result in significant regulatory fines. This simulation demonstrates the skills, tools, and methodologies a SOC analyst brings to protect your organization before, during, and after an attack.



 Project Overview
 ![Table](https://github.com/user-attachments/assets/26045064-dc77-4624-abf6-f2c69a90615f)



 Environment & Tools
 Platform used  is TryHackMe SOC Simulator

 Tools
 ![Tools](https://github.com/user-attachments/assets/2789ef46-699d-424e-95ac-bf6995f63ef3)
 


 Asset Prioritization
Before triaging alerts, a SOC analyst must understand the organization's asset landscape. High-value targets receive immediate attention because a compromise of their accounts carries disproportionate risk to the business.



Alert Triage Summary

False Positives
One of the most important skills in SOC work is knowing what not to escalate. Out of the 32 alerts processed during this simulation, a significant portion turned out to be false positives — legitimate activity that simply looked suspicious at first glance. Correctly dismissing these kept the investigation focused on the real threat.

Spam Emails
The first wave of false positives came in the form of phishing-style emails. While they looked suspicious on the surface, closer inspection told a different story.
The first email claimed the recipient had a wealthy relative who left them a secret inheritance — a classic scam format. It was sent to a generic support mailbox with no specific individual named, carried no attachment, and contained no malicious link. This was generic mass spam, not a targeted attack.
The second and third waves followed a similar pattern. Emails with flashy subject lines like "Unlock the ultimate strategy to skyrocket your Hard Empire" and "Travel through time" were sent to multiple employees. While the CEO was among the recipients, the content was identical for everyone — a strong sign that the attacker had no specific intelligence about who they were targeting. Real spear-phishing personalises the message to the individual. These emails did neither, and with no attachments or links present, there was no active threat to chase.

 System Processes 
Several process-related alerts fired during the simulation, each one requiring a quick but careful investigation to rule out malicious intent.
Windows Update Process — One alert flagged a well-known Windows system process responsible for managing software updates and protecting core system files. A quick check confirmed it was running from its expected location, with standard command-line arguments, and no additional software was being installed alongside it. The department it ran on had no other suspicious activity at the time.
Verdict: Legitimate. Dismissed.
Task Scheduling Process — Another alert flagged a process responsible for hosting Windows scheduled tasks. This is a process attackers can abuse for persistence or C2 activity, so it was checked carefully. The host it appeared on belongs to a department that routinely uses scheduled tasks for business workflows, and it was confirmed the process was clean. No unusual network connections or child processes were observed.
Verdict: Legitimate task scheduling. Dismissed.
Hardware Communication Process — A third process alert involved one of the most fundamental processes in Windows — the service host responsible for hardware and software communication. Multiple instances of this process are completely normal on any Windows machine. The activity occurred during standard office hours and was consistent with a physical device being connected at the workstation.
Verdict: Expected system behaviour. Dismissed.
Scheduled Task via Command Line — The final process alert involved a command-line task activation that initially looked worth investigating, especially given the active incident unfolding elsewhere on the network. However, the account running it did not have elevated privileges, the task itself matched routine departmental activity, and there was no connection to the ongoing compromise. The suspicious context of the simulation made this feel more threatening than it was.
Verdict: Routine scheduling activity. Dismissed — though flagged as worth monitoring given the broader incident.

 True Positives
 Every alert in this section was confirmed as a genuine threat and escalated with full documentation. Together, they tell the story of a single coordinated attack from the first deceptive email all the way through to active data theft. Reading them in sequence reveals how quickly a phishing email can spiral into a full network compromise when left unchecked.
 
<img width="2724" height="1128" alt="CEO email with attachment" src="https://github.com/user-attachments/assets/78380906-5e3c-4354-8aad-559ffc6e27c6" />

 The Entry Point — A Fake Invoice Email
Everything started with a single email landing in the CEO's inbox. On the surface, it looked like a routine billing notification. The sender claimed the CEO's account was 30 days overdue and threatened legal action unless payment was processed immediately. Attached was a ZIP file named "Important Invoice February."
Several things made this stand out immediately. The sender's domain had a negative reputation score — a red flag that showed up the moment it was checked against threat intelligence. Inside the ZIP was what appeared to be a PDF, but a closer look at the file extension revealed something was off. It was actually a disguised executable program designed to run when opened, not a document designed to be read.
The urgency in the language, the financial pressure, the threat of legal consequences — all classic social engineering tactics designed to make someone act before they think. 

 Signs of Remote Access — RDPclip.exe
Within minutes of the phishing email being delivered, an unusual process appeared on the CEO's workstation — RDPclip.exe. This is a legitimate Windows process that manages clipboard sharing during Remote Desktop sessions. On its own, it raises no alarm. In context, it was deeply concerning.
No remote desktop session had been authorised. No IT activity was scheduled. The process appeared within 16 minutes of a confirmed malicious email and simultaneously on a Sales workstation on the other side of the network. That simultaneous appearance on two machines pointed strongly to a remote connection being established, likely through a reverse shell triggered by the attachment being opened.

 Post-Exploitation Tools Deployed — PowerView and PowerUp via PowerShell
Shortly after, PowerShell was detected launching from an unusual location — the CEO's Downloads folder rather than any standard system directory. This alone is a red flag. Legitimate system processes do not run from a user's personal Downloads folder.
What was being executed made the situation significantly worse. Two well-known post-exploitation scripts had been dropped to that same folder:

PowerView.ps1 — a tool used by attackers to map out an Active Directory environment, identify users, groups, and machines, and understand the network they've landed in
PowerUp.ps1 — a tool used to identify local privilege escalation opportunities, helping an attacker gain higher-level access than their initial foothold provides

The presence of these tools confirmed this was not an accidental infection. Someone was actively operating inside the CEO's machine with intent. This was escalated and mapped to MITRE ATT&CK technique T1059.001 — PowerShell execution.

Network Reconnaissance — Six Rapid NSLOOKUP Queries
With a foothold established, the attacker began exploring. NSLOOKUP — a legitimate command-line tool used to query DNS records was executed six times in rapid succession from the CEO's workstation.
A CEO running one NSLOOKUP query might be unusual. Six in quick succession is not something any executive does manually. This was clearly automated, scripted behaviour as the attacker methodically mapping the internal network, identifying hostnames, servers, and infrastructure to understand what else they could reach.
The pattern was consistent with an attacker figuring out where the valuable assets are before moving toward them. All six executions were escalated together as confirmed network reconnaissance activity.


Privilege Escalation — Net.exe from an Elevated Command Prompt
Next came Net.exe — a Windows utility that, in the right hands, is used for routine administrative tasks like managing user accounts and network shares. In this context, it was anything but routine.
Net.exe was being run from an elevated command prompt, giving it administrator-level permissions. More tellingly, it was executing from the Downloads folder — not from its expected home in the Windows system directory. This non-standard execution path is a classic indicator of an attacker who has dropped a tool and is running it outside normal system controls.
The likely purpose: enumerating user accounts and group memberships to identify high-privilege accounts worth targeting next. This was escalated as a confirmed privilege escalation attempt.

Data Theft in Progress — Robocopy
The investigation reached its most serious point when Robocopy was detected running via PowerShell on the CEO's machine. Robocopy is a powerful Windows file-copying utility — legitimate in the hands of an IT administrator, deeply alarming when a PowerShell script is using it to mirror files across a network.
The target was financial records stored on another host on the same network. The attacker had mapped the network, escalated their privileges, and was now in the process of copying sensitive financial data — staging it for exfiltration.
To cover their tracks, the attacker also attempted to delete the contents of the Downloads folder using PowerShell — trying to remove the tools they had used and make forensic analysis harder. The deletion attempt itself became another piece of evidence.
This was escalated as active data exfiltration in progress

Investigation Methodology — The Five Ws
For every True Positive, the following structured approach was applied to ensure a complete and defensible investigation.

![True-Positive-Deep-Dive](https://github.com/user-attachments/assets/ad364d74-653e-40cb-bbac-5924baa47ea1)


Indicators of Compromise (IOCs)

Sender Domain:    [FLAGGED — Negative community score on reputation check]
Attachment Name:  important invoice february.zip
Payload:          Executable file with disguised PDF extension
Social Engineering: Urgency + Financial Threat + Legal Threat


Post-Compromise Activity
![Post-Compromise](https://github.com/user-attachments/assets/eb3c29b1-25da-4d38-b62a-ba0992fa267a)

MITRE ATT&CK Mapping
![MITRE](https://github.com/user-attachments/assets/f0bb2560-b24b-4445-b090-2250c7a77807)

Incident Report
INCIDENT ID: INC-2024-001 Classification: CRITICAL Status: Contained — Pending Full Forensic Review Analyst: Dickson Ojama

A targeted spear-phishing email was delivered to CEO Michael Scott at approximately 15:00. The email impersonated a billing entity and contained a malicious executable disguised as an invoice PDF inside a ZIP archive. Upon execution, the attacker established remote access to the CEO's workstation (Host 3459), deployed post-exploitation tools (PowerView and PowerUp), performed extensive network reconnaissance using repeated NSLOOKUP queries, attempted privilege escalation via Net.exe, and used Robocopy to stage files for exfiltration. 

Indicators of Compromise (IOCs)

![IOCs](https://github.com/user-attachments/assets/9067194d-0a16-4802-825d-9c4b3ed2f741)


Impact Assessment

![Impact](https://github.com/user-attachments/assets/589df850-870c-43da-bc82-69eb6205832d)





















