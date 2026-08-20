// =========================================================
// SEED GRAPH EXPANSION -- BATCH 2: NETWORK SECURITY
// =========================================================
// Sources:
//   - MITRE ATT&CK (attack.mitre.org), Enterprise Matrix:
//       T1557 Adversary-in-the-Middle (parent technique)
//         T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay
//         T1557.002 ARP Cache Poisoning
//         T1557.003 DHCP Spoofing
//         T1557.004 Evil Twin
//       T1040 Network Sniffing
//       T1046 Network Service Discovery
//       T1498 Network Denial of Service
//     Note: MITRE deliberately uses "Adversary-in-the-Middle" rather
//     than "Man-in-the-Middle" as the more precise, inclusive term --
//     preserved here rather than using the older common name.
//   - CWE (cwe.mitre.org): CWE-300 (Channel Accessible by
//     Non-Endpoint), CWE-400 (Uncontrolled Resource Consumption)
//   - Specific mitigations (Dynamic ARP Inspection, DNSSEC) are
//     drawn directly from MITRE's own listed mitigations for T1557.
//
// ADDITIVE to seed_graph.cypher and seed_graph_batch1_webapp.cypher.
// Run as ONE continuous statement (MERGE chains fine without WITH;
// see seed_graph_batch1_webapp.cypher's header for why this differs
// from the MATCH+SET enrichment script, which does need WITH *).
// =========================================================

// ---------- MATCH EXISTING NODES ----------

MATCH (root:Concept {name: "Cybersecurity"})
MATCH (webApp:Technology {name: "Web Application"})
MATCH (userData:Asset {name: "User Data"})
MATCH (sessionCookie:Asset {name: "Session Cookie"})
MATCH (sessionHijack:Attack {name: "Session Hijacking"})
MATCH (credStuff:Attack {name: "Credential Stuffing"})

// ---------- NEW CONCEPT (tree placement) ----------

MERGE (networkSec:Concept {name: "Network Security"})
  SET networkSec.description = "The practice of protecting the confidentiality, integrity, and availability of data as it moves across and between networks, distinct from securing an individual application or host."
MERGE (root)-[:LEARN_NEXT]->(networkSec)

// ---------- NEW ASSET ----------

MERGE (networkTraffic:Asset {name: "Network Traffic"})
  SET networkTraffic.description = "Data actively flowing between systems on a network, as opposed to data at rest -- the direct target of interception-based attacks like sniffing and adversary-in-the-middle positioning."

// ---------- NEW ATTACKS ----------

MERGE (aitm:Attack {name: "Adversary-in-the-Middle"})
  SET aitm.description = "Positioning oneself between two communicating devices to intercept, read, or modify their traffic, by abusing networking protocols (ARP, DNS, DHCP, etc.) that determine how traffic is routed. MITRE ATT&CK (T1557) uses this term in preference to the older 'Man-in-the-Middle', as more precise and inclusive of the range of techniques involved."
MERGE (arpPoison:Attack {name: "ARP Cache Poisoning"})
  SET arpPoison.description = "Sending forged ARP replies to associate the attacker's MAC address with another device's IP address (commonly the default gateway), causing victims to route their traffic through the attacker. Exploits the fact that ARP is stateless and requires no authentication (MITRE ATT&CK T1557.002)."
MERGE (dnsSpoof:Attack {name: "DNS Spoofing"})
  SET dnsSpoof.description = "Providing false DNS responses to redirect a victim's traffic to an attacker-controlled server instead of the legitimate destination, by exploiting insufficient authentication of name-resolution responses (related to MITRE ATT&CK T1557.001)."
MERGE (dhcpSpoof:Attack {name: "DHCP Spoofing"})
  SET dhcpSpoof.description = "Running a rogue DHCP server on a network to hand out malicious configuration (such as a false default gateway or DNS server) to new devices, positioning the attacker to intercept their traffic (MITRE ATT&CK T1557.003)."
MERGE (evilTwin:Attack {name: "Evil Twin"})
  SET evilTwin.description = "Setting up a rogue Wi-Fi access point that mimics a legitimate one, tricking devices into connecting to it so the attacker can intercept and manipulate their traffic (MITRE ATT&CK T1557.004)."
MERGE (networkSniffing:Attack {name: "Network Sniffing"})
  SET networkSniffing.description = "Passively monitoring network traffic using a device's network interface to capture information in transit, including credentials sent over unencrypted protocols (MITRE ATT&CK T1040)."
MERGE (portScan:Attack {name: "Network Service Discovery"})
  SET portScan.description = "Probing a target's ports and services -- commonly called port scanning -- to identify what is running and potentially exploitable, without completing a full connection to each service (MITRE ATT&CK T1046)."
MERGE (netDos:Attack {name: "Network Denial of Service"})
  SET netDos.description = "Degrading or blocking the availability of a targeted resource by exhausting the network bandwidth or connection-handling capacity it depends on (MITRE ATT&CK T1498)."
MERGE (synFlood:Attack {name: "SYN Flood Attack"})
  SET synFlood.description = "A denial-of-service technique that sends a high volume of TCP connection requests (SYN packets) without completing the handshake, exhausting the target server's capacity to track half-open connections."
MERGE (dnsAmp:Attack {name: "DNS Amplification Attack"})
  SET dnsAmp.description = "A reflection-based denial-of-service technique that sends small, spoofed-source DNS queries to open DNS resolvers, which then send much larger responses to the spoofed victim address -- multiplying the attacker's bandwidth many times over."

// ---------- NEW VULNERABILITIES (CWE) ----------

MERGE (cwe300:Vulnerability {name: "CWE-300"})
  SET cwe300.description = "Channel Accessible by Non-Endpoint ('Man-in-the-Middle') -- the official CWE title. The product does not adequately verify the identity of actors at both ends of a communication channel, or does not adequately ensure the channel's integrity, allowing it to be accessed or influenced by a non-endpoint actor."
MERGE (cwe400:Vulnerability {name: "CWE-400"})
  SET cwe400.description = "Uncontrolled Resource Consumption -- the software does not properly restrict the amount of resources (network bandwidth, connections, memory, etc.) that can be allocated in response to a request, allowing it to be exhausted and rendering the system unavailable."

MERGE (aitm)-[:EXPLOITS]->(cwe300)
MERGE (arpPoison)-[:EXPLOITS]->(cwe300)
MERGE (dnsSpoof)-[:EXPLOITS]->(cwe300)
MERGE (dhcpSpoof)-[:EXPLOITS]->(cwe300)
MERGE (evilTwin)-[:EXPLOITS]->(cwe300)
MERGE (netDos)-[:EXPLOITS]->(cwe400)
MERGE (synFlood)-[:EXPLOITS]->(cwe400)
MERGE (dnsAmp)-[:EXPLOITS]->(cwe400)

// ---------- NEW DEFENCES ----------

MERGE (firewall:Defence {name: "Firewall"})
  SET firewall.description = "A network security control that filters incoming and outgoing traffic based on defined rules, blocking unauthorized access attempts and unwanted connections."
MERGE (ids:Defence {name: "Intrusion Detection System"})
  SET ids.description = "A system that monitors network or host activity for signs of malicious behaviour or policy violations and generates alerts, without itself blocking the traffic."
MERGE (ips:Defence {name: "Intrusion Prevention System"})
  SET ips.description = "A system that monitors network traffic for malicious activity like an IDS, but actively blocks or drops the offending traffic in real time rather than only alerting."
MERGE (vpn:Defence {name: "Virtual Private Network"})
  SET vpn.description = "An encrypted tunnel between a device and a remote network, protecting traffic in transit from interception or tampering even on an untrusted local network."
MERGE (dai:Defence {name: "Dynamic ARP Inspection"})
  SET dai.description = "A switch-level security feature that validates ARP packets against a trusted binding table before forwarding them, dropping packets that don't match a known legitimate IP-to-MAC mapping -- MITRE's own listed mitigation for ARP cache poisoning."
MERGE (dnssec:Defence {name: "DNSSEC"})
  SET dnssec.description = "DNS Security Extensions -- a set of extensions that let DNS responses be cryptographically signed and validated, allowing resolvers to detect forged or tampered responses used in DNS spoofing."
MERGE (networkSeg:Defence {name: "Network Segmentation"})
  SET networkSeg.description = "Dividing a network into smaller, isolated segments so that a compromise or interception in one segment doesn't automatically expose traffic or systems in another."
MERGE (synCookies:Defence {name: "SYN Cookies"})
  SET synCookies.description = "A technique where the server encodes connection state into the initial SYN-ACK response itself instead of storing it in memory, avoiding the resource exhaustion a SYN flood is designed to cause."
MERGE (wpa3:Defence {name: "WPA3 Encryption"})
  SET wpa3.description = "The current Wi-Fi security standard, providing stronger encryption and protection against offline password-guessing than its predecessors, making it harder for a rogue access point to convincingly impersonate a legitimate network."
MERGE (dnsRRL:Defence {name: "DNS Response Rate Limiting"})
  SET dnsRRL.description = "Configuring DNS resolvers to limit how many responses they'll send to a single source in a given time window, directly countering the reflection/amplification technique DNS amplification attacks depend on."

MERGE (dai)-[:MITIGATES]->(arpPoison)
MERGE (dnssec)-[:MITIGATES]->(dnsSpoof)
MERGE (vpn)-[:MITIGATES]->(aitm)
MERGE (vpn)-[:MITIGATES]->(networkSniffing)
MERGE (firewall)-[:MITIGATES]->(netDos)
MERGE (firewall)-[:MITIGATES]->(portScan)
MERGE (ids)-[:MITIGATES]->(portScan)
MERGE (ids)-[:MITIGATES]->(netDos)
MERGE (ips)-[:MITIGATES]->(netDos)
MERGE (networkSeg)-[:MITIGATES]->(aitm)
MERGE (synCookies)-[:MITIGATES]->(synFlood)
MERGE (wpa3)-[:MITIGATES]->(evilTwin)
MERGE (dnsRRL)-[:MITIGATES]->(dnsAmp)

// ---------- NEW TOOLS ----------

MERGE (wireshark:Tool {name: "Wireshark"})
  SET wireshark.description = "A widely used open-source network protocol analyzer that captures and inspects traffic in detail, standard for both diagnosing network issues and analyzing sniffing/AiTM attack traffic."
MERGE (nmap:Tool {name: "Nmap"})
  SET nmap.description = "A free, open-source tool for network discovery and security auditing, used to identify live hosts, open ports, and running services -- the standard tool for network service discovery/port scanning."
MERGE (aircrackng:Tool {name: "Aircrack-ng"})
  SET aircrackng.description = "A suite of tools for assessing Wi-Fi network security, covering packet capture, network monitoring, and testing the strength of wireless encryption."
MERGE (ettercap:Tool {name: "Ettercap"})
  SET ettercap.description = "An open-source tool for adversary-in-the-middle attacks on a LAN, supporting live traffic interception and ARP poisoning -- cited directly by MITRE as an example tool used to perform T1557.002."

MERGE (wireshark)-[:TOOL_USED_FOR]->(networkSniffing)
MERGE (nmap)-[:TOOL_USED_FOR]->(portScan)
MERGE (aircrackng)-[:TOOL_USED_FOR]->(evilTwin)
MERGE (ettercap)-[:TOOL_USED_FOR]->(arpPoison)
MERGE (ettercap)-[:TOOL_USED_FOR]->(aitm)

// ---------- TARGETS (impact) ----------

MERGE (aitm)-[:TARGETS]->(networkTraffic)
MERGE (aitm)-[:TARGETS]->(sessionCookie)
MERGE (networkSniffing)-[:TARGETS]->(networkTraffic)
MERGE (networkSniffing)-[:TARGETS]->(userData)
MERGE (netDos)-[:TARGETS]->(webApp)
MERGE (synFlood)-[:TARGETS]->(webApp)
MERGE (dnsAmp)-[:TARGETS]->(webApp)

// ---------- CROSS-LINKS (RELATED_TO) ----------

MERGE (arpPoison)-[:RELATED_TO]->(aitm)
MERGE (dnsSpoof)-[:RELATED_TO]->(aitm)
MERGE (dhcpSpoof)-[:RELATED_TO]->(aitm)
MERGE (evilTwin)-[:RELATED_TO]->(aitm)
MERGE (aitm)-[:RELATED_TO]->(sessionHijack)
MERGE (networkSniffing)-[:RELATED_TO]->(credStuff)
MERGE (synFlood)-[:RELATED_TO]->(netDos)
MERGE (dnsAmp)-[:RELATED_TO]->(netDos)

// ---------- GUIDED MODE TREE PLACEMENT ----------

MERGE (networkSec)-[:LEARN_NEXT]->(aitm)
MERGE (networkSec)-[:LEARN_NEXT]->(portScan)
MERGE (networkSec)-[:LEARN_NEXT]->(netDos)
MERGE (networkSec)-[:LEARN_NEXT]->(networkSniffing)
MERGE (aitm)-[:LEARN_NEXT]->(arpPoison)
MERGE (aitm)-[:LEARN_NEXT]->(dnsSpoof)
MERGE (aitm)-[:LEARN_NEXT]->(dhcpSpoof)
MERGE (aitm)-[:LEARN_NEXT]->(evilTwin)
MERGE (netDos)-[:LEARN_NEXT]->(synFlood)
MERGE (netDos)-[:LEARN_NEXT]->(dnsAmp);
