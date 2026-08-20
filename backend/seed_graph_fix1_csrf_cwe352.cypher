// =========================================================
// FIX 1: Add missing CWE-352 mapping for Cross-Site Request Forgery
// =========================================================
// Gap found during a source-accuracy review: every other Attack node
// in this graph that has a direct software-weakness root cause has
// an EXPLOITS edge to its CWE (SQLi -> CWE-89, XSS -> CWE-79, etc.),
// but Cross-Site Request Forgery -- present since the original
// seed_graph.cypher -- never got one.
//
// Source: CWE (cwe.mitre.org). CWE-352 is not a minor omission --
// verified against the live 2024 and 2025 CWE Top 25 Most Dangerous
// Software Weaknesses lists at cwe.mitre.org/top25/, it ranks #3-4,
// ahead of SQL Injection in both years.
//
// ADDITIVE to all previous seed/batch files. Run as ONE continuous
// statement, MATCH block first (same pattern as Batches 2-6).
// =========================================================

MATCH (csrf:Attack {name: "Cross-Site Request Forgery"})

MERGE (cwe352:Vulnerability {name: "CWE-352"})
  SET cwe352.description = "Cross-Site Request Forgery (CSRF) -- the official CWE title. The web application does not, or cannot, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request, allowing an attacker to trick an authenticated user's browser into issuing state-changing requests on their behalf."

MERGE (csrf)-[:EXPLOITS]->(cwe352);
