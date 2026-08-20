"""
explanation_engine.py
----------------------
Converts a graph path (list of nodes + list of relationship types) into
plain-English text using fixed string templates. This is the core of the
system's "explainability": every sentence produced can be traced directly
back to a specific relationship (edge) in the knowledge graph. There is no
AI or language model involved anywhere in this module — only Python string
formatting driven by a lookup dictionary.

Input format (matches what /path and /question already return):
    nodes = [{"name": "SQL Injection", "labels": ["Attack"]}, ...]
    relationships = ["EXPLOITS", "RELATED_TO", ...]

There is always exactly one fewer relationship than nodes, since each
relationship connects two consecutive nodes in the path.
"""

# ---------------------------------------------------------------
# Relationship -> phrase template.
# {A} and {B} are placeholders for the node names on either side.
# Keep these grammatically self-contained sentences (subject + verb
# + object) so they can be joined together or used standalone.
# ---------------------------------------------------------------
RELATIONSHIP_TEMPLATES = {
    "EXPLOITS": "{A} exploits {B}",
    "MITIGATES": "{A} mitigates {B}",
    "TOOL_USED_FOR": "{A} is used to test for {B}",
    "TARGETS": "{A} ultimately targets {B}",
    "RELATED_TO": "{A} is related to {B}",
    "LEARN_NEXT": "after {A}, the recommended next topic is {B}",
    "PREREQUISITE": "{A} should be understood before {B}",
}

# Fallback phrase for any relationship type not in the dictionary above,
# so the engine never crashes on an unrecognised edge -- it just
# degrades gracefully to a generic (but still readable) sentence.
DEFAULT_TEMPLATE = "{A} is connected to {B} via {REL}"


def _node_name(node: dict) -> str:
    """Safely extract a node's display name."""
    return node.get("name", "Unknown")


def _phrase_for_hop(node_a: dict, node_b: dict, relationship: str) -> str:
    """
    Builds a single hop's sentence fragment, e.g.
    "SQL Injection exploits CWE-89"
    """
    template = RELATIONSHIP_TEMPLATES.get(relationship)
    a_name = _node_name(node_a)
    b_name = _node_name(node_b)

    if template is None:
        return DEFAULT_TEMPLATE.format(A=a_name, B=b_name, REL=relationship)

    return template.format(A=a_name, B=b_name)


def generate_explanation(nodes: list, relationships: list, detail_level: str = "concise") -> str:
    """
    Converts a path into a natural-language explanation.

    Parameters
    ----------
    nodes : list of dicts, each with at least a "name" key
            (optionally "description" for detailed mode)
    relationships : list of relationship-type strings, one shorter than nodes
    detail_level : "concise" or "detailed"

    Returns
    -------
    A single string containing the full explanation.
    """
    if len(nodes) < 2 or len(relationships) != len(nodes) - 1:
        # Path too short to explain, or malformed input from the caller.
        # Returning a plain fallback keeps the API from erroring out
        # on an edge case like a single-node "path".
        if len(nodes) == 1:
            return f"{_node_name(nodes[0])} has no further path to explain."
        return "Unable to generate an explanation: the provided path is malformed."

    if detail_level not in ("concise", "detailed"):
        detail_level = "concise"

    sentences = []

    for i, relationship in enumerate(relationships):
        node_a = nodes[i]
        node_b = nodes[i + 1]
        hop_sentence = _phrase_for_hop(node_a, node_b, relationship)

        if detail_level == "detailed":
            # Weave in the destination node's description, if present,
            # so the reader gets context on *why* this hop matters,
            # not just that it exists. Phrased as its own clause rather
            # than forced after "which", since stored descriptions are
            # noun phrases (e.g. "Improper Neutralization of...") that
            # don't always read naturally as a relative clause.
            description = node_b.get("description")
            if description:
                b_name = _node_name(node_b)
                hop_sentence += f" ({b_name} refers to {_describe_clause(description)})"

        sentences.append(hop_sentence)

    # Join hops into a flowing paragraph. Capitalize the first sentence,
    # separate subsequent ones with "; " for concise mode, or ". " with
    # capitalization for detailed mode so it reads like real prose.
    if detail_level == "concise":
        full_text = "; ".join(sentences)
        full_text = full_text[0].upper() + full_text[1:] + "."
    else:
        full_text = ". ".join(s[0].upper() + s[1:] for s in sentences) + "."

    return full_text


def _describe_clause(description: str) -> str:
    """
    Converts a stored description (which is normally a standalone sentence,
    e.g. "Improper Neutralization of Special Elements used in an SQL Command.")
    into a subordinate clause that reads naturally after "which".
    We lowercase the first letter and strip the trailing period so it
    slots grammatically into the middle of a sentence.
    """
    clause = description.strip()
    if clause.endswith("."):
        clause = clause[:-1]
    if clause:
        clause = clause[0].lower() + clause[1:]
    return clause


def generate_summary_line(nodes: list, relationships: list) -> str:
    """
    A short one-line summary showing the raw path, useful for debugging
    or for a small "trace" caption under the main explanation in the UI
    (keeps the explainability promise visible: users can always see the
    literal edges behind the plain-English text).
    e.g. "SQL Injection -> EXPLOITS -> CWE-89 -> RELATED_TO -> SQL Database"
    """
    if not nodes:
        return ""

    parts = [_node_name(nodes[0])]
    for i, relationship in enumerate(relationships):
        parts.append(f"-> {relationship} ->")
        parts.append(_node_name(nodes[i + 1]))

    return " ".join(parts)