// =========================================================
// SEED GRAPH EXPANSION -- BATCH 6: SOCIAL ENGINEERING & PHYSICAL
// =========================================================
// Sources:
//   - MITRE ATT&CK (attack.mitre.org), Enterprise Matrix:
//       T1566 Phishing (Initial Access tactic, parent technique)
//         T1566.001 Spearphishing Attachment
//         T1566.002 Spearphishing Link
//         T1566.004 Spearphishing Voice (added to cover vishing
//         scenarios, e.g. help-desk social engineering)
//       T1598 Phishing for Information (Reconnaissance tactic --
//         distinct from T1566: this covers deceptive communication
//         used to gather information rather than gain direct access,
//         the closest formal ATT&CK mapping for pretexting)
//       T1091 Replication Through Removable Media
//       T1200 Hardware Additions
//       M1017 User Training -- MITRE's own listed mitigation for
//         the Phishing technique family, mapped here to Security
//         Awareness Training.
//   - FBI Internet Crime Complaint Center (IC3) for Business Email
//     Compromise as a tracked, named crime category and its
//     standard mitigation (out-of-band verification of payment
//     requests).
//   - NIST SP 800-50 (Building an Information Technology Security
//     Awareness and Training Program) and CISA physical security
//     guidance for the non-technical defences below.
//   - CWE-451 (cwe.mitre.org) for the one weakness in this domain
//     with a genuine software root cause (deceptive UI).
//
// Honest scope note: Business Email Compromise and Tailgating /
// Piggybacking are well-documented, industry-standard named attack
// patterns (tracked by the FBI IC3 and CISA physical-security
// guidance respectively) but are not themselves individual MITRE
// ATT&CK technique IDs -- described accurately below without
// inventing a false technique mapping for either. Most attacks in
// this batch don't get an EXPLOITS->CWE edge, since social
// engineering targets human decision-making rather than a specific
// software weakness -- the same honest-scope approach Batch 3
// (Malware & Endpoint) took for persistence/evasion techniques.
//
// ADDITIVE to all previous seed/batch files. Run as ONE continuous
// statement, MATCH block first (same pattern as Batches 2-5).
// =========================================================

// ---------- MATCH EXISTING NODES ----------

MATCH (root:Concept {name: "Cybersecurity"})
MATCH (userData:Asset {name: "User Data"})
MATCH (sessionCookie:Asset {name: "Session Cookie"})
MATCH (mfa:Defence {name: "Multi-Factor Authentication"})
MATCH (sessionHijack:Attack {name: "Session Hijacking"})
MATCH (trojan:Attack {name: "Trojan"})
MATCH (ransomware:Attack {name: "Ransomware"})
MATCH (cloudAcctCompromise:Attack {name: "Cloud Account Compromise"})

// ---------- NEW CONCEPT ----------

MERGE (socEng:Concept {name: "Social Engineering & Physical Security"})
  SET socEng.description = "Attacks that target human decision-making and physical access controls rather than a technical flaw in software -- exploiting trust, urgency, and authority to get a person to hand over credentials, run malicious code, or grant physical entry."
MERGE (root)-[:LEARN_NEXT]->(socEng)

// ---------- NEW ASSETS ----------

MERGE (endpointDevice:Asset {name: "Endpoint Device"})
  SET endpointDevice.description = "A user-operated workstation, laptop, or other device -- the landing point for malware delivered through a malicious attachment or a dropped USB drive, before it can spread any further."
MERGE (physicalPremises:Asset {name: "Physical Premises"})
  SET physicalPremises.description = "An organization's physical office, data center, or other controlled-access facility -- the target of attacks that bypass digital controls entirely by gaining unauthorized physical entry."

// ---------- NEW ATTACKS ----------

MERGE (phishing:Attack {name: "Phishing"})
  SET phishing.description = "Sending fraudulent communications, typically email, that appear to come from a trusted source, in order to steal credentials or deliver malware. The parent technique in MITRE ATT&CK's Initial Access tactic (T1566), covering the whole family of spearphishing sub-techniques."
MERGE (spearAttach:Attack {name: "Spearphishing Attachment"})
  SET spearAttach.description = "A targeted phishing email containing a malicious file attachment, relying on the recipient opening it to execute malicious code on their device (MITRE ATT&CK T1566.001)."
MERGE (spearLink:Attack {name: "Spearphishing Link"})
  SET spearLink.description = "A targeted phishing email containing a malicious link, typically leading to a fake login page designed to harvest the victim's credentials or session cookie (MITRE ATT&CK T1566.002)."
MERGE (bec:Attack {name: "Business Email Compromise"})
  SET bec.description = "Impersonating an executive, vendor, or trusted colleague via a spoofed or compromised email account to trick an employee into making a fraudulent wire transfer or sensitive-data disclosure. Tracked by the FBI's Internet Crime Complaint Center (IC3) as one of the costliest categories of reported cybercrime."
MERGE (vishing:Attack {name: "Vishing (Voice Phishing)"})
  SET vishing.description = "Phishing conducted over a phone call or voice channel rather than email, often impersonating IT support or a help desk to pressure a victim into revealing credentials or approving a fraudulent access request (MITRE ATT&CK T1566.004, Spearphishing Voice)."
MERGE (pretexting:Attack {name: "Pretexting"})
  SET pretexting.description = "Fabricating a plausible false scenario (a pretext) to manipulate a target into divulging information or performing an action they otherwise wouldn't -- the closest formal ATT&CK mapping is T1598 (Phishing for Information), which covers deceptive communication used specifically to gather information rather than gain direct system access."
MERGE (baiting:Attack {name: "Baiting (Malicious USB Drop)"})
  SET baiting.description = "Leaving a malware-infected USB drive somewhere a target is likely to find and plug it in out of curiosity, relying on human curiosity rather than any network-facing vulnerability (related to MITRE ATT&CK T1091, Replication Through Removable Media, and T1200, Hardware Additions)."
MERGE (tailgating:Attack {name: "Tailgating / Piggybacking"})
  SET tailgating.description = "Following an authorized person through a secured door or checkpoint without presenting one's own credentials, exploiting social courtesy (holding the door) rather than any flaw in the access-control system itself."

// ---------- NEW VULNERABILITY ----------

MERGE (cwe451:Vulnerability {name: "CWE-451"})
  SET cwe451.description = "User Interface (UI) Misrepresentation of Critical Information -- the official CWE title. The user interface does not accurately represent the security-critical context of what a user is about to do, such as showing a URL or sender that appears legitimate but is not."

MERGE (spearLink)-[:EXPLOITS]->(cwe451)

// ---------- NEW DEFENCES ----------

MERGE (secAwareness:Defence {name: "Security Awareness Training"})
  SET secAwareness.description = "Regularly training employees to recognize phishing, vishing, and pretexting attempts and to follow verification procedures before acting on unusual requests -- MITRE ATT&CK's own listed mitigation (M1017, User Training) for the Phishing technique family, and the core recommendation of NIST SP 800-50."
MERGE (emailFilter:Defence {name: "Email Filtering / Anti-Phishing Gateway"})
  SET emailFilter.description = "Automated scanning of inbound email for known malicious attachments, links, and sender-spoofing indicators, blocking or quarantining suspicious messages before they reach a user's inbox."
MERGE (dmarc:Defence {name: "DMARC / DKIM / SPF Email Authentication"})
  SET dmarc.description = "A set of email-authentication standards that let a domain owner cryptographically assert which mail servers are allowed to send on its behalf, letting receiving servers reject or flag messages that spoof that domain's identity -- a direct mitigation for both phishing and Business Email Compromise."
MERGE (physicalAccessControl:Defence {name: "Physical Access Control"})
  SET physicalAccessControl.description = "Badge readers, mantraps, and staffed entry points that require every individual to independently authenticate before entering a facility, closing the social gap tailgating depends on."
MERGE (mediaRestriction:Defence {name: "Removable Media Restriction"})
  SET mediaRestriction.description = "Disabling or tightly controlling USB and other removable-media ports on endpoint devices via policy, so an unknown drive plugged in by a curious employee cannot execute automatically or at all."
MERGE (verificationCallback:Defence {name: "Out-of-Band Verification Procedures"})
  SET verificationCallback.description = "Requiring any unusual or high-value request (a wire transfer, a password reset, a credential disclosure) to be independently confirmed through a separate, previously-known communication channel before acting on it -- the FBI IC3's standard recommended defence against Business Email Compromise and vishing."

MERGE (secAwareness)-[:MITIGATES]->(phishing)
MERGE (secAwareness)-[:MITIGATES]->(vishing)
MERGE (secAwareness)-[:MITIGATES]->(pretexting)
MERGE (secAwareness)-[:MITIGATES]->(tailgating)
MERGE (secAwareness)-[:MITIGATES]->(baiting)
MERGE (emailFilter)-[:MITIGATES]->(phishing)
MERGE (emailFilter)-[:MITIGATES]->(spearAttach)
MERGE (emailFilter)-[:MITIGATES]->(spearLink)
MERGE (emailFilter)-[:MITIGATES]->(bec)
MERGE (dmarc)-[:MITIGATES]->(bec)
MERGE (dmarc)-[:MITIGATES]->(phishing)
MERGE (physicalAccessControl)-[:MITIGATES]->(tailgating)
MERGE (mediaRestriction)-[:MITIGATES]->(baiting)
MERGE (verificationCallback)-[:MITIGATES]->(vishing)
MERGE (verificationCallback)-[:MITIGATES]->(pretexting)
MERGE (verificationCallback)-[:MITIGATES]->(bec)
MERGE (mfa)-[:MITIGATES]->(phishing)
MERGE (mfa)-[:MITIGATES]->(spearLink)

// ---------- NEW TOOLS ----------

MERGE (gophish:Tool {name: "Gophish"})
  SET gophish.description = "An open-source phishing simulation framework used by security teams to run controlled phishing campaigns against their own organization, measuring click rates and reinforcing awareness training."
MERGE (setTool:Tool {name: "Social-Engineer Toolkit (SET)"})
  SET setTool.description = "An open-source penetration testing framework specifically designed to simulate social engineering attacks, including phishing, credential harvesting pages, and pretext-based scenarios, for authorized red-team testing."
MERGE (kingPhisher:Tool {name: "King Phisher"})
  SET kingPhisher.description = "An open-source phishing campaign toolkit used for authorized penetration testing, supporting campaign tracking, credential-harvesting pages, and detailed reporting on simulated attachment-based phishing."

MERGE (gophish)-[:TOOL_USED_FOR]->(phishing)
MERGE (gophish)-[:TOOL_USED_FOR]->(spearLink)
MERGE (setTool)-[:TOOL_USED_FOR]->(phishing)
MERGE (setTool)-[:TOOL_USED_FOR]->(pretexting)
MERGE (kingPhisher)-[:TOOL_USED_FOR]->(spearAttach)

// ---------- TARGETS (impact) ----------

MERGE (phishing)-[:TARGETS]->(userData)
MERGE (spearAttach)-[:TARGETS]->(endpointDevice)
MERGE (spearLink)-[:TARGETS]->(sessionCookie)
MERGE (bec)-[:TARGETS]->(userData)
MERGE (vishing)-[:TARGETS]->(userData)
MERGE (pretexting)-[:TARGETS]->(userData)
MERGE (baiting)-[:TARGETS]->(endpointDevice)
MERGE (tailgating)-[:TARGETS]->(physicalPremises)

// ---------- CROSS-LINKS (RELATED_TO) ----------

MERGE (spearAttach)-[:RELATED_TO]->(trojan)
MERGE (spearLink)-[:RELATED_TO]->(sessionHijack)
MERGE (bec)-[:RELATED_TO]->(cloudAcctCompromise)
MERGE (baiting)-[:RELATED_TO]->(ransomware)
MERGE (tailgating)-[:RELATED_TO]->(baiting)
MERGE (pretexting)-[:RELATED_TO]->(vishing)

// ---------- GUIDED MODE TREE PLACEMENT ----------

MERGE (socEng)-[:LEARN_NEXT]->(phishing)
MERGE (socEng)-[:LEARN_NEXT]->(spearAttach)
MERGE (socEng)-[:LEARN_NEXT]->(spearLink)
MERGE (socEng)-[:LEARN_NEXT]->(bec)
MERGE (socEng)-[:LEARN_NEXT]->(vishing)
MERGE (socEng)-[:LEARN_NEXT]->(pretexting)
MERGE (socEng)-[:LEARN_NEXT]->(baiting)
MERGE (socEng)-[:LEARN_NEXT]->(tailgating);
