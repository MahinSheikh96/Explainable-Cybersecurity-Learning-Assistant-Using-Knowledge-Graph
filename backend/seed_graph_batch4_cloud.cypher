// =========================================================
// SEED GRAPH EXPANSION -- BATCH 4: CLOUD & IDENTITY
// =========================================================
// Sources:
//   - MITRE ATT&CK (attack.mitre.org), Cloud Matrix:
//       T1530 Data from Cloud Storage Object
//       T1078.004 Valid Accounts: Cloud Accounts
//       T1552.005 Unsecured Credentials: Cloud Instance Metadata API
//       T1580 Cloud Infrastructure Discovery
//       T1136 Create Account (cloud persistence)
//       T1578 Modify Cloud Compute Infrastructure
//   - CWE (cwe.mitre.org): CWE-732 (Incorrect Permission Assignment
//     for Critical Resource), CWE-269 (Improper Privilege Management)
//
// Honest scope note: this is a smaller batch (20 nodes vs 26-35 in
// previous batches) -- Cloud/Identity has fewer independently
// verifiable CWE/technique mappings than Web or Network security.
// Kept smaller and fully grounded rather than padded.
//
// ADDITIVE. Run as ONE continuous statement, MATCH block first.
// =========================================================

// ---------- MATCH EXISTING NODES ----------

MATCH (root:Concept {name: "Cybersecurity"})
MATCH (userData:Asset {name: "User Data"})
MATCH (database:Asset {name: "Database"})
MATCH (mfa:Defence {name: "Multi-Factor Authentication"})
MATCH (leastPrivAccess:Defence {name: "Least Privilege Access Control"})
MATCH (bac:Attack {name: "Broken Access Control"})
MATCH (ssrf:Attack {name: "Server-Side Request Forgery"})
MATCH (credStuff:Attack {name: "Credential Stuffing"})

// ---------- NEW CONCEPT ----------

MERGE (cloudIdentity:Concept {name: "Cloud & Identity Security"})
  SET cloudIdentity.description = "Securing resources hosted on third-party cloud platforms (AWS, Azure, GCP) and the identity/access-management systems that control who and what can reach them -- a domain where misconfiguration, not traditional software bugs, is the dominant root cause of real incidents."
MERGE (root)-[:LEARN_NEXT]->(cloudIdentity)

// ---------- NEW ASSET ----------

MERGE (cloudInfra:Asset {name: "Cloud Infrastructure"})
  SET cloudInfra.description = "The compute instances, storage buckets, and configuration resources an organization runs on a cloud provider -- distinct from the application code itself, and directly reachable via the provider's own management APIs if credentials are compromised."

// ---------- NEW ATTACKS ----------

MERGE (cloudStorageExposure:Attack {name: "Cloud Storage Data Exposure"})
  SET cloudStorageExposure.description = "Directly accessing data from cloud object storage (e.g. AWS S3, Azure Blob Storage) that has been left publicly accessible or granted overly broad permissions, allowing anyone to read or download its contents without needing to compromise the application at all (MITRE ATT&CK T1530)."
MERGE (cloudAcctCompromise:Attack {name: "Cloud Account Compromise"})
  SET cloudAcctCompromise.description = "Gaining access to cloud services (AWS, Azure, GCP, Office 365) using stolen or guessed valid account credentials, rather than exploiting a technical flaw -- the single most common initial access vector in real cloud incidents (MITRE ATT&CK T1078.004)."
MERGE (metadataApiTheft:Attack {name: "Cloud Metadata API Credential Theft"})
  SET metadataApiTheft.description = "Querying a cloud instance's metadata service (an internal-only API every cloud VM can reach, describing itself and often holding temporary credentials) to steal those credentials -- most commonly reached in practice via an SSRF vulnerability in a hosted application (MITRE ATT&CK T1552.005)."
MERGE (cloudInfraDiscovery:Attack {name: "Cloud Infrastructure Discovery"})
  SET cloudInfraDiscovery.description = "Enumerating a compromised cloud account's resources -- instances, storage buckets, IAM roles, network configuration -- to map out what's available and plan further attack steps (MITRE ATT&CK T1580)."
MERGE (maliciousCloudAcct:Attack {name: "Malicious Cloud Account Creation"})
  SET maliciousCloudAcct.description = "Creating a new IAM user or service account within a compromised cloud environment to maintain persistent access, so that access survives even if the originally-compromised credential is later revoked (MITRE ATT&CK T1136)."
MERGE (modifyCloudInfra:Attack {name: "Modify Cloud Compute Infrastructure"})
  SET modifyCloudInfra.description = "Creating, deleting, or reconfiguring cloud compute resources (e.g. spinning up new instances for cryptomining, or taking a snapshot of a storage volume to exfiltrate it) using compromised account permissions (MITRE ATT&CK T1578)."
MERGE (iamPrivEsc:Attack {name: "IAM Privilege Escalation"})
  SET iamPrivEsc.description = "Exploiting overly permissive or misconfigured Identity and Access Management policies to gain higher privileges than originally granted, often by chaining together several individually-limited permissions into a combination the policy author didn't anticipate."

// ---------- NEW VULNERABILITIES (CWE) ----------

MERGE (cwe732:Vulnerability {name: "CWE-732"})
  SET cwe732.description = "Incorrect Permission Assignment for Critical Resource -- the official CWE title. The product specifies permissions for a security-critical resource in a way that allows access from unintended actors, the root cause behind most real-world public cloud storage exposure incidents."
MERGE (cwe269:Vulnerability {name: "CWE-269"})
  SET cwe269.description = "Improper Privilege Management -- the official CWE title. The product does not properly assign, modify, track, or check privileges for an actor, creating a path for that actor to gain unintended access or capabilities."

MERGE (cloudStorageExposure)-[:EXPLOITS]->(cwe732)
MERGE (iamPrivEsc)-[:EXPLOITS]->(cwe269)

// ---------- NEW DEFENCES ----------

MERGE (zeroTrust:Defence {name: "Zero Trust Architecture"})
  SET zeroTrust.description = "A security model that assumes no user, device, or network location is inherently trustworthy, requiring every request to be authenticated and authorized on its own merits regardless of where it originates from."
MERGE (jitAccess:Defence {name: "Just-In-Time Access"})
  SET jitAccess.description = "Granting elevated permissions only for the specific, limited time window they're actually needed, rather than leaving privileged access permanently active and available to be abused if the account is compromised."
MERGE (cspm:Defence {name: "Cloud Security Posture Management"})
  SET cspm.description = "Tooling that continuously scans a cloud environment's actual configuration against security best practices, flagging issues like publicly exposed storage buckets or overly permissive IAM policies before they're exploited."
MERGE (imdsv2:Defence {name: "Instance Metadata Service Hardening"})
  SET imdsv2.description = "Requiring session-oriented, token-based authentication to query a cloud instance's metadata service (such as AWS's IMDSv2), rather than allowing simple unauthenticated requests -- directly closing the path SSRF-to-credential-theft attacks depend on."
MERGE (bucketAudit:Defence {name: "Cloud Storage Access Auditing"})
  SET bucketAudit.description = "Regularly reviewing and testing cloud storage bucket policies against the principle of least privilege, catching accidental public-exposure misconfigurations before an attacker finds them."
MERGE (egressFilter:Defence {name: "Egress Filtering"})
  SET egressFilter.description = "Restricting and monitoring outbound network connections from a system, limiting what an application server can reach even if compromised -- including blocking unintended access to internal-only endpoints like the cloud metadata service."

MERGE (cspm)-[:MITIGATES]->(cloudStorageExposure)
MERGE (cspm)-[:MITIGATES]->(cloudInfraDiscovery)
MERGE (mfa)-[:MITIGATES]->(cloudAcctCompromise)
MERGE (zeroTrust)-[:MITIGATES]->(cloudAcctCompromise)
MERGE (jitAccess)-[:MITIGATES]->(iamPrivEsc)
MERGE (leastPrivAccess)-[:MITIGATES]->(iamPrivEsc)
MERGE (imdsv2)-[:MITIGATES]->(metadataApiTheft)
MERGE (bucketAudit)-[:MITIGATES]->(cloudStorageExposure)
MERGE (egressFilter)-[:MITIGATES]->(metadataApiTheft)

// ---------- NEW TOOLS ----------

MERGE (scoutsuite:Tool {name: "ScoutSuite"})
  SET scoutsuite.description = "An open-source, multi-cloud security auditing tool that assesses the configuration of AWS, Azure, and GCP environments against security best practices."
MERGE (prowler:Tool {name: "Prowler"})
  SET prowler.description = "An open-source security assessment tool for AWS (and other cloud providers) that checks configurations against security best practices and compliance frameworks."
MERGE (pacu:Tool {name: "Pacu"})
  SET pacu.description = "An open-source AWS exploitation framework used in offensive security testing to simulate what an attacker could do with a given set of compromised AWS credentials."

MERGE (scoutsuite)-[:TOOL_USED_FOR]->(cloudStorageExposure)
MERGE (scoutsuite)-[:TOOL_USED_FOR]->(cloudInfraDiscovery)
MERGE (prowler)-[:TOOL_USED_FOR]->(cloudStorageExposure)
MERGE (prowler)-[:TOOL_USED_FOR]->(iamPrivEsc)
MERGE (pacu)-[:TOOL_USED_FOR]->(cloudAcctCompromise)
MERGE (pacu)-[:TOOL_USED_FOR]->(modifyCloudInfra)

// ---------- TARGETS (impact) ----------

MERGE (cloudStorageExposure)-[:TARGETS]->(userData)
MERGE (cloudStorageExposure)-[:TARGETS]->(database)
MERGE (cloudAcctCompromise)-[:TARGETS]->(userData)
MERGE (modifyCloudInfra)-[:TARGETS]->(cloudInfra)
MERGE (cloudInfraDiscovery)-[:TARGETS]->(cloudInfra)
MERGE (maliciousCloudAcct)-[:TARGETS]->(cloudInfra)

// ---------- CROSS-LINKS (RELATED_TO) ----------

MERGE (metadataApiTheft)-[:RELATED_TO]->(ssrf)
MERGE (cloudAcctCompromise)-[:RELATED_TO]->(credStuff)
MERGE (iamPrivEsc)-[:RELATED_TO]->(bac)
MERGE (cloudStorageExposure)-[:RELATED_TO]->(bac)

// ---------- GUIDED MODE TREE PLACEMENT ----------

MERGE (cloudIdentity)-[:LEARN_NEXT]->(cloudStorageExposure)
MERGE (cloudIdentity)-[:LEARN_NEXT]->(cloudAcctCompromise)
MERGE (cloudIdentity)-[:LEARN_NEXT]->(metadataApiTheft)
MERGE (cloudIdentity)-[:LEARN_NEXT]->(cloudInfraDiscovery)
MERGE (cloudIdentity)-[:LEARN_NEXT]->(maliciousCloudAcct)
MERGE (cloudIdentity)-[:LEARN_NEXT]->(modifyCloudInfra)
MERGE (cloudIdentity)-[:LEARN_NEXT]->(iamPrivEsc);
