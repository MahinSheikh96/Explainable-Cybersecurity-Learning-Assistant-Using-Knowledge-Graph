// =========================================================
// SEED GRAPH: Explainable Cybersecurity Learning Assistant
// Corrected version: ONE single Cypher statement.
// No semicolons until the very end, so every variable
// (root, webSec, sqli, xss, etc.) stays in scope for the
// whole script and relationship MERGEs reference the real
// nodes instead of creating blank duplicates.
// =========================================================

// ---------- CONCEPTS (Guided Mode hierarchy) ----------
MERGE (root:Concept {name: "Cybersecurity"})
  SET root.description = "The root topic covering all security domains in this graph."
MERGE (webSec:Concept {name: "Web Security"})
  SET webSec.description = "Security concerns specific to web applications and browsers."
MERGE (injection:Concept {name: "Injection Attacks"})
  SET injection.description = "A class of attacks where untrusted input is interpreted as code or commands."
MERGE (clientSide:Concept {name: "Client-Side Attacks"})
  SET clientSide.description = "Attacks that execute in the context of a victim's browser."

MERGE (root)-[:LEARN_NEXT]->(webSec)
MERGE (webSec)-[:LEARN_NEXT]->(injection)
MERGE (webSec)-[:LEARN_NEXT]->(clientSide)
MERGE (webSec)-[:PREREQUISITE]->(injection)
MERGE (webSec)-[:PREREQUISITE]->(clientSide)

// ---------- ATTACKS ----------
MERGE (sqli:Attack {name: "SQL Injection"})
  SET sqli.description = "Injecting malicious SQL statements into input fields to manipulate database queries."
MERGE (xss:Attack {name: "Cross-Site Scripting"})
  SET xss.description = "Injecting malicious scripts into web pages viewed by other users."

MERGE (injection)-[:LEARN_NEXT]->(sqli)
MERGE (clientSide)-[:LEARN_NEXT]->(xss)

// ---------- VULNERABILITIES (CWE) ----------
MERGE (cwe89:Vulnerability {name: "CWE-89"})
  SET cwe89.description = "Improper Neutralization of Special Elements used in an SQL Command."
MERGE (cwe79:Vulnerability {name: "CWE-79"})
  SET cwe79.description = "Improper Neutralization of Input During Web Page Generation."

MERGE (sqli)-[:EXPLOITS]->(cwe89)
MERGE (xss)-[:EXPLOITS]->(cwe79)

// ---------- TECHNOLOGIES ----------
MERGE (webApp:Technology {name: "Web Application"})
  SET webApp.description = "A server-side application accessed via HTTP."
MERGE (sqlDb:Technology {name: "SQL Database"})
  SET sqlDb.description = "A relational database queried using SQL."
MERGE (browserDom:Technology {name: "Browser DOM"})
  SET browserDom.description = "The Document Object Model rendered and scripted in a user's browser."

MERGE (cwe89)-[:RELATED_TO]->(sqlDb)
MERGE (cwe79)-[:RELATED_TO]->(browserDom)
MERGE (sqli)-[:RELATED_TO]->(webApp)
MERGE (xss)-[:RELATED_TO]->(webApp)

// ---------- ASSETS (impact targets) ----------
MERGE (userData:Asset {name: "User Data"})
  SET userData.description = "Personally identifiable or sensitive information stored by the application."
MERGE (sessionCookie:Asset {name: "Session Cookie"})
  SET sessionCookie.description = "A token used to maintain an authenticated user session."
MERGE (database:Asset {name: "Database"})
  SET database.description = "The underlying data store for the application."

MERGE (sqli)-[:TARGETS]->(userData)
MERGE (sqli)-[:TARGETS]->(database)
MERGE (xss)-[:TARGETS]->(sessionCookie)
MERGE (xss)-[:TARGETS]->(userData)

// ---------- DEFENCES ----------
MERGE (preparedStmt:Defence {name: "Prepared Statements"})
  SET preparedStmt.description = "Parameterized queries that separate SQL code from user-supplied data."
MERGE (inputVal:Defence {name: "Input Validation"})
  SET inputVal.description = "Checking that input conforms to expected format before processing."
MERGE (outputEnc:Defence {name: "Output Encoding"})
  SET outputEnc.description = "Encoding output so browsers render it as data, not executable script."
MERGE (csp:Defence {name: "Content Security Policy"})
  SET csp.description = "An HTTP header that restricts which scripts a browser is allowed to execute."
MERGE (leastPriv:Defence {name: "Least Privilege DB Accounts"})
  SET leastPriv.description = "Limiting database account permissions to only what the application needs."

MERGE (preparedStmt)-[:MITIGATES]->(sqli)
MERGE (inputVal)-[:MITIGATES]->(sqli)
MERGE (inputVal)-[:MITIGATES]->(xss)
MERGE (outputEnc)-[:MITIGATES]->(xss)
MERGE (csp)-[:MITIGATES]->(xss)
MERGE (leastPriv)-[:MITIGATES]->(sqli)

// ---------- TOOLS ----------
MERGE (sqlmap:Tool {name: "sqlmap"})
  SET sqlmap.description = "An open-source penetration testing tool that automates SQL injection detection."
MERGE (burp:Tool {name: "Burp Suite"})
  SET burp.description = "A web application security testing platform, widely used for XSS discovery."
MERGE (owaspZap:Tool {name: "OWASP ZAP"})
  SET owaspZap.description = "A free, open-source web application security scanner."

MERGE (sqlmap)-[:TOOL_USED_FOR]->(sqli)
MERGE (burp)-[:TOOL_USED_FOR]->(xss)
MERGE (burp)-[:TOOL_USED_FOR]->(sqli)
MERGE (owaspZap)-[:TOOL_USED_FOR]->(sqli)
MERGE (owaspZap)-[:TOOL_USED_FOR]->(xss)

// ---------- CROSS-LINKS (Free-Flow related-concept discovery) ----------
MERGE (sqli)-[:RELATED_TO]->(xss)
MERGE (cwe89)-[:RELATED_TO]->(cwe79)
MERGE (preparedStmt)-[:RELATED_TO]->(inputVal)
MERGE (outputEnc)-[:RELATED_TO]->(csp)
MERGE (sqlmap)-[:RELATED_TO]->(burp)
MERGE (burp)-[:RELATED_TO]->(owaspZap)

// ---------- ADDITIONAL CONCEPT NODES ----------
MERGE (authn:Concept {name: "Authentication & Session Management"})
  SET authn.description = "Concepts around verifying identity and maintaining secure sessions."
MERGE (secByDesign:Concept {name: "Secure Coding Practices"})
  SET secByDesign.description = "General principles for writing code resistant to common vulnerabilities."

MERGE (root)-[:LEARN_NEXT]->(authn)
MERGE (webSec)-[:LEARN_NEXT]->(secByDesign)
MERGE (secByDesign)-[:RELATED_TO]->(preparedStmt)
MERGE (secByDesign)-[:RELATED_TO]->(inputVal)
MERGE (authn)-[:RELATED_TO]->(sessionCookie)
MERGE (authn)-[:PREREQUISITE]->(webSec)

// ---------- EXTRA ATTACK-ADJACENT NODE ----------
MERGE (csrf:Attack {name: "Cross-Site Request Forgery"})
  SET csrf.description = "Tricking an authenticated user's browser into submitting an unwanted request."

MERGE (clientSide)-[:LEARN_NEXT]->(csrf)
MERGE (csrf)-[:RELATED_TO]->(xss)
MERGE (csrf)-[:TARGETS]->(sessionCookie)
MERGE (csp)-[:MITIGATES]->(csrf)

MERGE (csrfTokenDef:Defence {name: "Anti-CSRF Tokens"})
  SET csrfTokenDef.description = "Unique tokens embedded in forms to verify request origin."
MERGE (csrfTokenDef)-[:MITIGATES]->(csrf)
MERGE (csrfTokenDef)-[:RELATED_TO]->(csp);
