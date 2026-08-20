// =========================================================
// SEED GRAPH EXPANSION -- BATCH 5: CRYPTOGRAPHY
// =========================================================
// Sources:
//   - CWE (cwe.mitre.org). Correction (verified against the live
//     2024/2025 CWE Top 25 lists at cwe.mitre.org/top25/): CWE-295,
//     CWE-327, and CWE-330 below are real, correctly-described CWE
//     entries, but none of them actually appear on the CWE Top 25
//     Most Dangerous Software Weaknesses list for 2024 or 2025 --
//     an earlier version of this comment incorrectly claimed they
//     did. They're included here because they're the standard,
//     well-documented weakness categories behind real cryptographic
//     failures, not because of a Top 25 ranking.
//   - MITRE ATT&CK (attack.mitre.org), Enterprise Matrix:
//       T1110 Brute Force (parent technique)
//         T1110.002 Password Cracking (offline)
//         T1110.003 Password Spraying
//       T1600 Weaken Encryption (Defense Evasion)
//         T1600.001 Reduce Key Space
//       T1552 Unsecured Credentials (parent technique)
//         T1552.001 Credentials In Files
//   - NIST SP 800-63B (Digital Identity Guidelines) for password
//     hashing / rate-limiting mitigation guidance.
//   - OWASP Cryptographic Storage Cheat Sheet and OWASP
//     Transport Layer Security Cheat Sheet for defence
//     descriptions.
//
// Honest scope note: Rainbow Table Attack, Padding Oracle Attack,
// Certificate Spoofing, and Predictable Random Value Exploitation
// are well-established named attack patterns in cryptographic
// security literature and OWASP guidance, but (unlike the T1110
// and T1600 entries above) do not have their own dedicated MITRE
// ATT&CK technique IDs -- they're described accurately below
// without inventing a false technique mapping for them.
//
// ADDITIVE to all previous seed/batch files. Run as ONE continuous
// statement, MATCH block first (same pattern as Batches 2-4).
// =========================================================

// ---------- MATCH EXISTING NODES ----------

MATCH (root:Concept {name: "Cybersecurity"})
MATCH (userData:Asset {name: "User Data"})
MATCH (sessionCookie:Asset {name: "Session Cookie"})
MATCH (networkTraffic:Asset {name: "Network Traffic"})
MATCH (networkSniffing:Attack {name: "Network Sniffing"})
MATCH (credStuff:Attack {name: "Credential Stuffing"})
MATCH (sessionHijack:Attack {name: "Session Hijacking"})
MATCH (aitm:Attack {name: "Adversary-in-the-Middle"})
MATCH (supplyChain:Attack {name: "Software Supply Chain Attack"})
MATCH (cloudAcctCompromise:Attack {name: "Cloud Account Compromise"})
MATCH (cwe307:Vulnerability {name: "CWE-307"})

// ---------- NEW CONCEPT ----------

MERGE (crypto:Concept {name: "Cryptography"})
  SET crypto.description = "The study of how cryptographic algorithms, keys, randomness, and certificates are used (and misused) to protect data confidentiality, integrity, and authenticity -- distinct from network or application security in that most failures here stem from weak primitives or poor key handling rather than missing input checks."
MERGE (root)-[:LEARN_NEXT]->(crypto)

// ---------- NEW ASSET ----------

MERGE (cryptoKeyMaterial:Asset {name: "Cryptographic Key Material"})
  SET cryptoKeyMaterial.description = "Secret keys, private keys, and other cryptographic material an application depends on to encrypt data or prove its identity -- if exposed, every guarantee built on top of that key (confidentiality, authenticity) is lost, regardless of how strong the underlying algorithm is."

// ---------- NEW ATTACKS ----------

MERGE (pwCracking:Attack {name: "Password Cracking (Offline Brute Force)"})
  SET pwCracking.description = "Systematically guessing passwords against a stolen hash dump, entirely offline and without triggering any login-attempt limits on the target system, until a hash matches (MITRE ATT&CK T1110.002)."
MERGE (pwSpraying:Attack {name: "Password Spraying"})
  SET pwSpraying.description = "Attempting one or a few commonly-used passwords against many different accounts, rather than many passwords against one account, specifically to stay under per-account lockout thresholds that would otherwise block a conventional brute-force attempt (MITRE ATT&CK T1110.003)."
MERGE (rainbowTable:Attack {name: "Rainbow Table Attack"})
  SET rainbowTable.description = "Reversing a stolen password hash back to its plaintext value using a precomputed lookup table of hash-to-password mappings, avoiding the need to compute each guess's hash live -- effective specifically against unsalted or weakly-hashed password stores."
MERGE (paddingOracle:Attack {name: "Padding Oracle Attack"})
  SET paddingOracle.description = "Exploiting a system that reveals (directly or via timing) whether decrypted ciphertext had valid padding, allowing an attacker to decrypt or forge ciphertext byte-by-byte without ever knowing the encryption key."
MERGE (tlsDowngrade:Attack {name: "TLS Downgrade Attack"})
  SET tlsDowngrade.description = "Forcing a connection to negotiate an older, weaker encryption protocol or cipher suite than both endpoints actually support, so the traffic can then be broken by attacking the weaker algorithm (MITRE ATT&CK T1600, Weaken Encryption)."
MERGE (certSpoofing:Attack {name: "Certificate Spoofing"})
  SET certSpoofing.description = "Presenting a fraudulent or improperly-validated TLS certificate to a victim, exploiting an application's failure to properly verify a certificate chain, so the victim unknowingly establishes an encrypted connection directly with the attacker instead of the intended server."
MERGE (keyExtraction:Attack {name: "Cryptographic Key Extraction"})
  SET keyExtraction.description = "Recovering a hard-coded secret or private key from an application's source code, compiled binary, configuration file, or public repository, after which every protection that key was meant to provide is void (MITRE ATT&CK T1552.001, Credentials In Files)."
MERGE (predictableRandom:Attack {name: "Predictable Random Value Exploitation"})
  SET predictableRandom.description = "Predicting a supposedly-random value -- a session token, password-reset token, or cryptographic nonce -- because it was generated using a non-cryptographic random number generator with a guessable seed or limited entropy source."

// ---------- NEW VULNERABILITIES (CWE) ----------

MERGE (cwe327:Vulnerability {name: "CWE-327"})
  SET cwe327.description = "Use of a Broken or Risky Cryptographic Algorithm -- the official CWE title. The product uses a deprecated, custom, or otherwise weak cryptographic algorithm, undermining any protection it was meant to provide."
MERGE (cwe321:Vulnerability {name: "CWE-321"})
  SET cwe321.description = "Use of Hard-coded Cryptographic Key -- the official CWE title. The product uses a hard-coded cryptographic key as part of its authentication or encryption process, meaning every deployed copy of the software shares an identical, un-rotatable key."
MERGE (cwe330:Vulnerability {name: "CWE-330"})
  SET cwe330.description = "Use of Insufficiently Random Values -- the official CWE title. The product uses insufficiently random numbers or values in a security context that depends on them being unpredictable, such as session tokens or nonces."
MERGE (cwe295:Vulnerability {name: "CWE-295"})
  SET cwe295.description = "Improper Certificate Validation -- the official CWE title. The product does not validate, or incorrectly validates, a certificate, which can allow an attacker to spoof a trusted entity by interfering in the communication path."
MERGE (cwe916:Vulnerability {name: "CWE-916"})
  SET cwe916.description = "Use of Password Hash With Insufficient Computational Effort -- the official CWE title. The product generates a password hash using an algorithm with low computational cost, allowing an attacker who obtains the hash to brute-force or table-lookup the original password far faster than a properly-slow algorithm would allow."
MERGE (cwe311:Vulnerability {name: "CWE-311"})
  SET cwe311.description = "Missing Encryption of Sensitive Data -- the official CWE title. The product does not encrypt sensitive data before storing or transmitting it, leaving it readable to anyone able to intercept the transmission or access the storage medium directly."

MERGE (pwCracking)-[:EXPLOITS]->(cwe916)
MERGE (rainbowTable)-[:EXPLOITS]->(cwe916)
MERGE (paddingOracle)-[:EXPLOITS]->(cwe327)
MERGE (tlsDowngrade)-[:EXPLOITS]->(cwe327)
MERGE (certSpoofing)-[:EXPLOITS]->(cwe295)
MERGE (pwSpraying)-[:EXPLOITS]->(cwe307)
MERGE (keyExtraction)-[:EXPLOITS]->(cwe321)
MERGE (predictableRandom)-[:EXPLOITS]->(cwe330)
MERGE (networkSniffing)-[:EXPLOITS]->(cwe311)

// ---------- NEW DEFENCES ----------

MERGE (strongHash:Defence {name: "Strong Password Hashing (bcrypt/Argon2/scrypt)"})
  SET strongHash.description = "Hashing passwords with a deliberately slow, memory-hard algorithm designed for this purpose, per NIST SP 800-63B guidance, so that even a stolen hash dump takes an infeasible amount of compute time to crack at scale."
MERGE (lockout:Defence {name: "Account Lockout & Rate Limiting"})
  SET lockout.description = "Restricting how many authentication attempts an account (or source IP) can make in a given window, closing off both online brute-force and password-spraying attacks without requiring the user to do anything differently."
MERGE (csprng:Defence {name: "Cryptographically Secure Random Number Generation"})
  SET csprng.description = "Generating security-sensitive values (session tokens, password-reset codes, nonces) using a CSPRNG rather than a general-purpose pseudo-random generator, so outputs cannot be predicted even by an attacker who knows the generator's algorithm."
MERGE (keyMgmt:Defence {name: "Secure Key Management (KMS/HSM)"})
  SET keyMgmt.description = "Storing and rotating cryptographic keys in a dedicated key-management service or hardware security module rather than embedding them in source code or config files, so keys can be rotated, audited, and revoked without a code change."
MERGE (tls13:Defence {name: "TLS 1.3 Enforcement"})
  SET tls13.description = "Configuring servers to negotiate only modern TLS versions and disable legacy protocols and cipher suites, per the OWASP Transport Layer Security Cheat Sheet, removing the weaker options a downgrade attack would otherwise force a connection back to."
MERGE (certPinning:Defence {name: "Certificate Pinning"})
  SET certPinning.description = "Hard-coding or storing the expected certificate (or public key) a client should see from a given server, so the client rejects the connection outright if presented with any other certificate, even one that would otherwise pass normal chain validation."
MERGE (aead:Defence {name: "Authenticated Encryption (AEAD)"})
  SET aead.description = "Using an authenticated encryption mode (such as AES-GCM) that verifies ciphertext integrity as part of decryption, so tampered or invalid ciphertext is rejected outright rather than decrypted and revealing padding-validity information to an attacker."
MERGE (encryptionTransit:Defence {name: "Encryption at Rest and in Transit"})
  SET encryptionTransit.description = "Encrypting sensitive data both while stored and while being transmitted, so that intercepting network traffic or gaining access to a storage medium yields ciphertext rather than directly readable data."

MERGE (strongHash)-[:MITIGATES]->(pwCracking)
MERGE (strongHash)-[:MITIGATES]->(rainbowTable)
MERGE (lockout)-[:MITIGATES]->(pwSpraying)
MERGE (csprng)-[:MITIGATES]->(predictableRandom)
MERGE (keyMgmt)-[:MITIGATES]->(keyExtraction)
MERGE (tls13)-[:MITIGATES]->(tlsDowngrade)
MERGE (certPinning)-[:MITIGATES]->(certSpoofing)
MERGE (aead)-[:MITIGATES]->(paddingOracle)
MERGE (encryptionTransit)-[:MITIGATES]->(networkSniffing)

// ---------- NEW TOOLS ----------

MERGE (hashcat:Tool {name: "Hashcat"})
  SET hashcat.description = "A widely-used, GPU-accelerated password recovery tool supporting a large range of hash algorithms, commonly used in both offline password cracking and rainbow-table-style attacks."
MERGE (johnTheRipper:Tool {name: "John the Ripper"})
  SET johnTheRipper.description = "A free, open-source password-cracking tool originally built for detecting weak Unix passwords, now supporting hundreds of hash and cipher types across offline cracking workflows."
MERGE (hydra:Tool {name: "Hydra"})
  SET hydra.description = "A parallelized network login-cracking tool supporting numerous protocols, commonly used to perform online brute-force and password-spraying attacks against live authentication services."
MERGE (testssl:Tool {name: "testssl.sh"})
  SET testssl.description = "A free command-line tool that checks a server's TLS/SSL configuration for supported protocols, cipher suites, and known vulnerabilities, commonly used to identify downgrade-attack exposure."

MERGE (hashcat)-[:TOOL_USED_FOR]->(pwCracking)
MERGE (hashcat)-[:TOOL_USED_FOR]->(rainbowTable)
MERGE (johnTheRipper)-[:TOOL_USED_FOR]->(pwCracking)
MERGE (hydra)-[:TOOL_USED_FOR]->(pwSpraying)
MERGE (testssl)-[:TOOL_USED_FOR]->(tlsDowngrade)

// ---------- TARGETS (impact) ----------

MERGE (pwCracking)-[:TARGETS]->(userData)
MERGE (pwSpraying)-[:TARGETS]->(userData)
MERGE (rainbowTable)-[:TARGETS]->(userData)
MERGE (certSpoofing)-[:TARGETS]->(networkTraffic)
MERGE (tlsDowngrade)-[:TARGETS]->(networkTraffic)
MERGE (keyExtraction)-[:TARGETS]->(cryptoKeyMaterial)
MERGE (predictableRandom)-[:TARGETS]->(sessionCookie)

// ---------- CROSS-LINKS (RELATED_TO) ----------

MERGE (pwCracking)-[:RELATED_TO]->(rainbowTable)
MERGE (pwSpraying)-[:RELATED_TO]->(credStuff)
MERGE (certSpoofing)-[:RELATED_TO]->(aitm)
MERGE (tlsDowngrade)-[:RELATED_TO]->(aitm)
MERGE (keyExtraction)-[:RELATED_TO]->(cloudAcctCompromise)
MERGE (keyExtraction)-[:RELATED_TO]->(supplyChain)
MERGE (predictableRandom)-[:RELATED_TO]->(sessionHijack)

// ---------- GUIDED MODE TREE PLACEMENT ----------

MERGE (crypto)-[:LEARN_NEXT]->(pwCracking)
MERGE (crypto)-[:LEARN_NEXT]->(pwSpraying)
MERGE (crypto)-[:LEARN_NEXT]->(rainbowTable)
MERGE (crypto)-[:LEARN_NEXT]->(paddingOracle)
MERGE (crypto)-[:LEARN_NEXT]->(tlsDowngrade)
MERGE (crypto)-[:LEARN_NEXT]->(certSpoofing)
MERGE (crypto)-[:LEARN_NEXT]->(keyExtraction)
MERGE (crypto)-[:LEARN_NEXT]->(predictableRandom);
