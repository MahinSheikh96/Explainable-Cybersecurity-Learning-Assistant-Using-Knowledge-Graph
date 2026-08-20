// =========================================================
// SEED GRAPH EXPANSION -- BATCH 1: WEB APPLICATION SECURITY
// =========================================================
// Sources:
//   - OWASP Top 10:2025 (owasp.org/Top10/2025/) -- finalized Jan 2026.
//     Category names, CWE mappings, and descriptions below are
//     paraphrased from the official pages for each category cited
//     inline. A03 (Software Supply Chain Failures) and A10
//     (Mishandling of Exceptional Conditions) are NEW in 2025 with
//     no 2021 predecessor, so their content was fetched fresh rather
//     than drawn from general knowledge.
//   - CWE (cwe.mitre.org) for individual weakness definitions.
//
// This is ADDITIVE to seed_graph.cypher -- run this AFTER the
// original seed script, never instead of it. MERGE is idempotent,
// so re-running this file is always safe.
//
// As established in Phase 2: this must run as ONE continuous
// statement. Do not add semicolons between MERGE blocks -- Cypher
// variable scope breaks across semicolon-separated statements.
// =========================================================

// ---------- MATCH EXISTING NODES FROM seed_graph.cypher ----------
// Required because this is a SEPARATE query execution -- variable
// bindings from the original seed script do NOT carry over. Using
// MATCH (not MERGE) here is deliberate: if seed_graph.cypher hasn't
// been run yet, this will fail loudly and clearly, rather than
// silently creating duplicate/incorrect nodes.

MATCH (webApp:Technology {name: "Web Application"})
MATCH (database:Asset {name: "Database"})
MATCH (userData:Asset {name: "User Data"})
MATCH (sessionCookie:Asset {name: "Session Cookie"})
MATCH (sqli:Attack {name: "SQL Injection"})
MATCH (csrf:Attack {name: "Cross-Site Request Forgery"})
MATCH (injection:Concept {name: "Injection Attacks"})
MATCH (webSec:Concept {name: "Web Security"})
MATCH (authn:Concept {name: "Authentication & Session Management"})
MATCH (clientSide:Concept {name: "Client-Side Attacks"})
MATCH (secByDesign:Concept {name: "Secure Coding Practices"})
MATCH (inputVal:Defence {name: "Input Validation"})

// ---------- NEW ATTACKS ----------

MERGE (bac:Attack {name: "Broken Access Control"})
  SET bac.description = "Exploiting an application's failure to enforce restrictions on what authenticated users are allowed to do, such as viewing or modifying another user's data by changing an identifier in a URL or request."
MERGE (ssrf:Attack {name: "Server-Side Request Forgery"})
  SET ssrf.description = "Tricking a server into making unauthorized HTTP requests on the attacker's behalf, often used to reach internal-only services or cloud metadata endpoints that aren't meant to be internet-accessible."
MERGE (deser:Attack {name: "Insecure Deserialization"})
  SET deser.description = "Supplying malicious serialized data to an application that deserializes it without validation, potentially leading to remote code execution or object injection."
MERGE (cmdInj:Attack {name: "Command Injection"})
  SET cmdInj.description = "Injecting operating-system commands into an application that passes unsanitized input to a system shell, allowing arbitrary command execution on the host."
MERGE (xxe:Attack {name: "XML External Entity Injection"})
  SET xxe.description = "Exploiting XML parsers configured to process external entity references, allowing an attacker to read local files, perform SSRF, or cause denial of service."
MERGE (pathTrav:Attack {name: "Path Traversal"})
  SET pathTrav.description = "Manipulating file-path input (e.g. using '../' sequences) to access files and directories stored outside the intended folder."
MERGE (credStuff:Attack {name: "Credential Stuffing"})
  SET credStuff.description = "Automated attempts to log in using large lists of username/password pairs leaked from other breaches, exploiting the fact that many users reuse passwords across sites."
MERGE (sessionHijack:Attack {name: "Session Hijacking"})
  SET sessionHijack.description = "Stealing or fixing a valid session identifier to impersonate an authenticated user without needing their credentials."
MERGE (clickjacking:Attack {name: "Clickjacking"})
  SET clickjacking.description = "Tricking a user into clicking something different from what they perceive, typically by overlaying a transparent malicious frame over a legitimate page."
MERGE (openRedirect:Attack {name: "Open Redirect"})
  SET openRedirect.description = "Abusing an application's unchecked redirect functionality to send victims to an attacker-controlled site, often used to make phishing links appear trustworthy."
MERGE (supplyChain:Attack {name: "Software Supply Chain Attack"})
  SET supplyChain.description = "Compromising an application indirectly by tampering with a trusted third-party dependency, build tool, or update mechanism it relies on, rather than attacking the application directly."

// ---------- NEW VULNERABILITIES (CWE) ----------

MERGE (cwe862:Vulnerability {name: "CWE-862"})
  SET cwe862.description = "Missing Authorization -- the software does not perform an authorization check when a user attempts to access a resource or perform an action."
MERGE (cwe918:Vulnerability {name: "CWE-918"})
  SET cwe918.description = "Server-Side Request Forgery -- the web server receives a URL from an upstream component and retrieves it without sufficiently ensuring the request is being sent to the intended destination."
MERGE (cwe502:Vulnerability {name: "CWE-502"})
  SET cwe502.description = "Deserialization of Untrusted Data -- the application deserializes data from an untrusted source without verifying it is valid, allowing an attacker to control application logic or execute code."
MERGE (cwe78:Vulnerability {name: "CWE-78"})
  SET cwe78.description = "OS Command Injection -- the software builds an OS command using externally influenced input without neutralizing special elements that could modify the intended command."
MERGE (cwe611:Vulnerability {name: "CWE-611"})
  SET cwe611.description = "Improper Restriction of XML External Entity Reference -- the XML parser processes a document containing external entity references without properly restricting resolution of those entities."
MERGE (cwe22:Vulnerability {name: "CWE-22"})
  SET cwe22.description = "Path Traversal -- the software uses external input to construct a pathname without properly neutralizing special elements that could resolve to a location outside a restricted directory."
MERGE (cwe307:Vulnerability {name: "CWE-307"})
  SET cwe307.description = "Improper Restriction of Excessive Authentication Attempts -- the application does not implement sufficient measures to prevent repeated, automated login attempts."
MERGE (cwe384:Vulnerability {name: "CWE-384"})
  SET cwe384.description = "Session Fixation -- the application authenticates a user without first invalidating an existing session, allowing an attacker who fixed the session ID beforehand to hijack it."
MERGE (cwe1021:Vulnerability {name: "CWE-1021"})
  SET cwe1021.description = "Improper Restriction of Rendered UI Layers or Frames -- the application does not prevent itself from being loaded inside a hidden or disguised frame on another site."
MERGE (cwe601:Vulnerability {name: "CWE-601"})
  SET cwe601.description = "URL Redirection to Untrusted Site -- the application accepts a user-controlled input that specifies a redirect destination without validating that it points to a trusted location."
MERGE (cwe1395:Vulnerability {name: "CWE-1395"})
  SET cwe1395.description = "Dependency on Vulnerable Third-Party Component -- the product depends on a third-party component that contains one or more known vulnerabilities."

MERGE (bac)-[:EXPLOITS]->(cwe862)
MERGE (ssrf)-[:EXPLOITS]->(cwe918)
MERGE (deser)-[:EXPLOITS]->(cwe502)
MERGE (cmdInj)-[:EXPLOITS]->(cwe78)
MERGE (xxe)-[:EXPLOITS]->(cwe611)
MERGE (pathTrav)-[:EXPLOITS]->(cwe22)
MERGE (credStuff)-[:EXPLOITS]->(cwe307)
MERGE (sessionHijack)-[:EXPLOITS]->(cwe384)
MERGE (clickjacking)-[:EXPLOITS]->(cwe1021)
MERGE (openRedirect)-[:EXPLOITS]->(cwe601)
MERGE (supplyChain)-[:EXPLOITS]->(cwe1395)

// ---------- NEW DEFENCES ----------

MERGE (rbac:Defence {name: "Role-Based Access Control"})
  SET rbac.description = "Restricting system access based on a user's assigned role, enforcing that every request is checked against what that role is permitted to do -- the core mitigation for broken access control."
MERGE (sbom:Defence {name: "Software Bill of Materials"})
  SET sbom.description = "Maintaining a complete, continuously updated inventory of every direct and transitive dependency a project relies on, enabling fast identification of affected systems when a component is found vulnerable."
MERGE (safeDeser:Defence {name: "Safe Deserialization Practices"})
  SET safeDeser.description = "Avoiding native deserialization of untrusted data entirely where possible, or restricting deserialization to an explicit allow-list of expected types."
MERGE (cmdAllowlist:Defence {name: "Command Input Allow-listing"})
  SET cmdAllowlist.description = "Avoiding direct invocation of system shells with user input; where unavoidable, strictly validating input against an allow-list rather than trying to blocklist dangerous characters."
MERGE (xmlHardening:Defence {name: "XML Parser Hardening"})
  SET xmlHardening.description = "Disabling external entity resolution and DTD processing in XML parsers by default, removing the mechanism XXE attacks depend on."
MERGE (pathCanon:Defence {name: "Path Canonicalization"})
  SET pathCanon.description = "Resolving file paths to their canonical form and verifying the result stays within an allowed base directory before granting file access."
MERGE (mfa:Defence {name: "Multi-Factor Authentication"})
  SET mfa.description = "Requiring a second independent proof of identity beyond a password, substantially reducing the impact of credential stuffing and other password-only attacks."
MERGE (sessionRegen:Defence {name: "Session Regeneration on Login"})
  SET sessionRegen.description = "Issuing a brand-new session identifier at the moment a user authenticates, invalidating any session ID that may have been fixed by an attacker beforehand."
MERGE (frameProtect:Defence {name: "Frame Protection Headers"})
  SET frameProtect.description = "Using headers such as Content-Security-Policy's frame-ancestors directive to control which sites, if any, are allowed to embed a page in a frame, preventing clickjacking."
MERGE (redirectAllowlist:Defence {name: "Redirect Destination Allow-listing"})
  SET redirectAllowlist.description = "Validating any user-supplied redirect target against a fixed allow-list of permitted destinations rather than redirecting to arbitrary user input."

MERGE (rbac)-[:MITIGATES]->(bac)
MERGE (redirectAllowlist)-[:MITIGATES]->(ssrf)
MERGE (safeDeser)-[:MITIGATES]->(deser)
MERGE (cmdAllowlist)-[:MITIGATES]->(cmdInj)
MERGE (inputVal)-[:MITIGATES]->(cmdInj)
MERGE (xmlHardening)-[:MITIGATES]->(xxe)
MERGE (pathCanon)-[:MITIGATES]->(pathTrav)
MERGE (mfa)-[:MITIGATES]->(credStuff)
MERGE (sessionRegen)-[:MITIGATES]->(sessionHijack)
MERGE (frameProtect)-[:MITIGATES]->(clickjacking)
MERGE (redirectAllowlist)-[:MITIGATES]->(openRedirect)
MERGE (sbom)-[:MITIGATES]->(supplyChain)

// ---------- NEW TOOLS ----------

MERGE (depCheck:Tool {name: "OWASP Dependency-Check"})
  SET depCheck.description = "A software composition analysis tool that identifies project dependencies and checks whether any have publicly disclosed vulnerabilities."
MERGE (nuclei:Tool {name: "Nuclei"})
  SET nuclei.description = "An open-source vulnerability scanner that uses community-contributed templates to test web applications and infrastructure against known vulnerability patterns."
MERGE (nikto:Tool {name: "Nikto"})
  SET nikto.description = "An open-source web server scanner that tests for dangerous files, outdated software versions, and other common misconfigurations."

MERGE (depCheck)-[:TOOL_USED_FOR]->(supplyChain)
MERGE (nuclei)-[:TOOL_USED_FOR]->(ssrf)
MERGE (nuclei)-[:TOOL_USED_FOR]->(pathTrav)
MERGE (nikto)-[:TOOL_USED_FOR]->(bac)

// ---------- TARGETS (impact) ----------

MERGE (ssrf)-[:TARGETS]->(database)
MERGE (deser)-[:TARGETS]->(webApp)
MERGE (cmdInj)-[:TARGETS]->(webApp)
MERGE (bac)-[:TARGETS]->(userData)
MERGE (credStuff)-[:TARGETS]->(userData)
MERGE (sessionHijack)-[:TARGETS]->(sessionCookie)
MERGE (supplyChain)-[:TARGETS]->(webApp)

// ---------- CROSS-LINKS (RELATED_TO, for Free-Flow discovery) ----------

MERGE (bac)-[:RELATED_TO]->(sqli)
MERGE (xxe)-[:RELATED_TO]->(ssrf)
MERGE (pathTrav)-[:RELATED_TO]->(cmdInj)
MERGE (sessionHijack)-[:RELATED_TO]->(csrf)
MERGE (clickjacking)-[:RELATED_TO]->(csrf)
MERGE (supplyChain)-[:RELATED_TO]->(sqli)
MERGE (credStuff)-[:RELATED_TO]->(sessionHijack)

// ---------- GUIDED MODE TREE PLACEMENT ----------

MERGE (injection)-[:LEARN_NEXT]->(cmdInj)
MERGE (injection)-[:LEARN_NEXT]->(xxe)
MERGE (webSec)-[:LEARN_NEXT]->(bac)
MERGE (webSec)-[:LEARN_NEXT]->(ssrf)
MERGE (webSec)-[:LEARN_NEXT]->(deser)
MERGE (webSec)-[:LEARN_NEXT]->(pathTrav)
MERGE (authn)-[:LEARN_NEXT]->(credStuff)
MERGE (authn)-[:LEARN_NEXT]->(sessionHijack)
MERGE (clientSide)-[:LEARN_NEXT]->(clickjacking)
MERGE (clientSide)-[:LEARN_NEXT]->(openRedirect)
MERGE (secByDesign)-[:LEARN_NEXT]->(supplyChain);
