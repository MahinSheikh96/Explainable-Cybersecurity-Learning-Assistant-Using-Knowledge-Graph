// =========================================================
// ENRICHMENT: Original 26 nodes -- more accurate, detailed
// descriptions grounded in real sources
// =========================================================
// Sources:
//   - CWE-89, CWE-79 exact titles/definitions: cwe.mitre.org
//   - SQL Injection / XSS taxonomy (reflected/stored/DOM-based):
//     standard, well-established security literature
//   - OWASP Cheat Sheet Series for defence mechanisms
//   - Tool descriptions: each project's own official description
//     (sqlmap.org, PortSwigger/Burp Suite, OWASP ZAP project page)
//
// This UPDATES existing nodes only (via MATCH + SET) -- it does not
// add or remove any nodes or relationships. Safe to run any time
// after seed_graph.cypher. Run as ONE continuous statement.
//
// IMPORTANT (learned the hard way): unlike a chain of MERGE...SET
// blocks (which flows fluidly without anything between them -- see
// seed_graph.cypher and seed_graph_batch1_webapp.cypher), a plain
// MATCH...SET followed by another MATCH requires an explicit WITH *
// between them. MERGE has combined read+write semantics that let it
// chain freely; bare MATCH does not. Neo4j will throw
// "WITH is required between SET and MATCH" without it.
// =========================================================

// ---------- ATTACKS ----------

MATCH (sqli:Attack {name: "SQL Injection"})
SET sqli.description = "Injecting malicious SQL syntax into an application's database queries via untrusted input, exploiting insufficient neutralization of special characters. Can allow an attacker to read, modify, or delete data, bypass authentication, or in severe cases execute commands on the underlying host."
WITH *

MATCH (xss:Attack {name: "Cross-Site Scripting"})
SET xss.description = "Injecting malicious scripts into content served to other users, due to a failure to neutralize user-controllable input before it's rendered in a web page. Occurs in three main forms: Reflected (input echoed back immediately in the response), Stored (input persisted and served to later visitors), and DOM-based (a client-side script itself writes untrusted data into the page)."
WITH *

MATCH (csrf:Attack {name: "Cross-Site Request Forgery"})
SET csrf.description = "Tricking an authenticated user's browser into submitting a state-changing request to a site they're logged into, without their knowledge, by exploiting the browser's automatic inclusion of session cookies on cross-site requests."
WITH *

// ---------- VULNERABILITIES (CWE) ----------

MATCH (cwe89:Vulnerability {name: "CWE-89"})
SET cwe89.description = "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') -- the official CWE title. The product constructs a SQL command using externally-influenced input without sufficiently neutralizing special elements that could modify the command's intended structure or logic."
WITH *

MATCH (cwe79:Vulnerability {name: "CWE-79"})
SET cwe79.description = "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') -- the official CWE title. The product does not neutralize, or incorrectly neutralizes, user-controllable input before placing it in output served as a web page to other users."
WITH *

// ---------- DEFENCES ----------

MATCH (preparedStmt:Defence {name: "Prepared Statements"})
SET preparedStmt.description = "Parameterized queries that send SQL code and user-supplied data to the database as separate channels, so input can never be reinterpreted as part of the query structure -- the primary, most reliable defence against SQL injection recommended by the OWASP SQL Injection Prevention Cheat Sheet."
WITH *

MATCH (inputVal:Defence {name: "Input Validation"})
SET inputVal.description = "Checking that input conforms to an expected format, type, length, and range before it is processed, ideally using an allow-list (defining what IS permitted) rather than a block-list (trying to enumerate what is forbidden), since block-lists are easy to bypass with unanticipated encodings."
WITH *

MATCH (outputEnc:Defence {name: "Output Encoding"})
SET outputEnc.description = "Encoding output according to the specific context it's placed in (HTML body, HTML attribute, JavaScript, URL, or CSS each require different encoding rules) so that browsers render untrusted data as inert text rather than executable script -- the primary defence against XSS per OWASP's XSS Prevention Cheat Sheet."
WITH *

MATCH (csp:Defence {name: "Content Security Policy"})
SET csp.description = "An HTTP response header that lets a site declare which sources of scripts, styles, and other resources the browser is allowed to load and execute, acting as a defence-in-depth layer that can block injected scripts even if an XSS flaw exists in the page."
WITH *

MATCH (leastPriv:Defence {name: "Least Privilege DB Accounts"})
SET leastPriv.description = "Configuring the database account an application connects with to hold only the minimum permissions it actually needs (e.g. no DROP TABLE or file-system access), so that a successful SQL injection is contained rather than granting full database or server compromise."
WITH *

MATCH (csrfTokenDef:Defence {name: "Anti-CSRF Tokens"})
SET csrfTokenDef.description = "A unique, unpredictable token generated per session (or per request) and embedded in forms/requests, which the server verifies before processing any state-changing action -- since an attacker forging a cross-site request has no way to know or include the correct token value."
WITH *

// ---------- TOOLS ----------

MATCH (sqlmap:Tool {name: "sqlmap"})
SET sqlmap.description = "An open-source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws, and can take over database servers by supporting a wide range of database management systems and injection techniques."
WITH *

MATCH (burp:Tool {name: "Burp Suite"})
SET burp.description = "An integrated platform for web application security testing, developed by PortSwigger, combining an intercepting proxy, automated and manual vulnerability scanners, and a suite of tools for manipulating HTTP requests -- one of the most widely used tools in professional web application penetration testing."
WITH *

MATCH (owaspZap:Tool {name: "OWASP ZAP"})
SET owaspZap.description = "A free, open-source web application security scanner maintained as an OWASP flagship project, offering both automated scanning and manual testing tools, widely used by developers and dedicated penetration testers alike."
WITH *

// ---------- TECHNOLOGY / ASSET (lighter touch -- structural nodes) ----------

MATCH (webApp:Technology {name: "Web Application"})
SET webApp.description = "Software that runs on a server and is accessed by users through a web browser over HTTP/HTTPS, rather than being installed locally -- the primary target surface for most of the attacks in this graph."
WITH *

MATCH (sqlDb:Technology {name: "SQL Database"})
SET sqlDb.description = "A relational database that stores and retrieves data using Structured Query Language (SQL), the target of SQL injection attacks when an application fails to safely construct queries against it."
WITH *

MATCH (browserDom:Technology {name: "Browser DOM"})
SET browserDom.description = "The Document Object Model -- the browser's in-memory, structured representation of a web page, which JavaScript can read and modify. XSS attacks succeed by getting malicious script executed within this environment, in the security context of the vulnerable site."
WITH *

MATCH (userData:Asset {name: "User Data"})
SET userData.description = "Personally identifiable or otherwise sensitive information belonging to an application's users (e.g. names, emails, payment details), whose confidentiality and integrity are commonly the ultimate target of attacks like SQL injection and XSS."
WITH *

MATCH (sessionCookie:Asset {name: "Session Cookie"})
SET sessionCookie.description = "A token stored in the browser that identifies an authenticated user's session to the server on subsequent requests. If stolen (e.g. via XSS) or forged (e.g. via session fixation), it allows an attacker to impersonate that user without needing their password."
WITH *

MATCH (database:Asset {name: "Database"})
SET database.description = "The backend data store underlying an application. A successful SQL injection can grant an attacker direct read/write access to everything in it, well beyond whatever the application's own interface was designed to expose.";
