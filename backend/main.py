"""
main.py
-------
FastAPI backend for the Explainable Cybersecurity Learning Assistant.

Endpoints:
  GET  /node/{name}            -> node details + direct neighbours
  GET  /path?start=X&end=Y     -> shortest path between two nodes
  GET  /related?node=X         -> RELATED_TO neighbours
  GET  /defenses?attack=X      -> defences that MITIGATE the attack
  GET  /tools?attack=X         -> tools with TOOL_USED_FOR the attack
  GET  /children?node=X        -> LEARN_NEXT children (Guided Mode tree)
  GET  /search?q=X             -> case-insensitive name search (Free-Flow)
  GET  /questions               -> list of premade questions (for dropdown)
  POST /question                -> answer a premade question with a graph
                                   path + generated explanation

Run with:
  uvicorn main:app --reload
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from neo4j.exceptions import ServiceUnavailable

from db import get_driver, verify_connectivity, close_driver
from questions import get_question, list_questions
from explanation_engine import generate_explanation, generate_summary_line


@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- Startup ---
    try:
        verify_connectivity()
        print("✅ Connected to Neo4j successfully.")
    except ServiceUnavailable as e:
        print("❌ Could not connect to Neo4j. Is the DBMS running in Neo4j Desktop?")
        raise e

    # Idempotent -- safe to run on every startup. Every endpoint looks
    # nodes up by name, so this keeps lookups fast as the graph grows
    # toward 100-150 nodes. Neo4j indexes are scoped per label, so we
    # create one for each label used in this ontology.
    node_labels = [
        "Attack",
        "Vulnerability",
        "Defence",
        "Tool",
        "Concept",
        "Technology",
        "Asset",
    ]
    with get_driver().session() as session:
        for label in node_labels:
            session.run(
                f"CREATE INDEX {label.lower()}_name_index IF NOT EXISTS "
                f"FOR (n:{label}) ON (n.name)"
            )
        print("✅ Ensured name indexes on all node labels.")

    yield  # --- App runs here ---

    # --- Shutdown ---
    close_driver()


app = FastAPI(title="Cybersecurity Knowledge Graph API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =================================================================
# GET /node/{name}
# =================================================================
@app.get("/node/{name}")
def get_node(name: str):
    query = """
    MATCH (n {name: $name})
    OPTIONAL MATCH (n)-[r]-(neighbour)
    RETURN
        n.name AS name,
        labels(n) AS labels,
        n.description AS description,
        collect(DISTINCT {
            name: neighbour.name,
            labels: labels(neighbour),
            relationship: type(r)
        }) AS neighbours
    """
    with get_driver().session() as session:
        result = session.run(query, name=name)
        record = result.single()

    if record is None or record["name"] is None:
        raise HTTPException(status_code=404, detail=f"Node '{name}' not found.")

    neighbours = [n for n in record["neighbours"] if n["name"] is not None]

    return {
        "name": record["name"],
        "labels": record["labels"],
        "description": record["description"],
        "neighbours": neighbours,
    }


# =================================================================
# GET /path?start=X&end=Y
# =================================================================
@app.get("/path")
def get_shortest_path(start: str, end: str):
    query = """
    MATCH (a {name: $start}), (b {name: $end}),
          p = shortestPath((a)-[*..6]-(b))
    RETURN
        [node IN nodes(p) | {
            name: node.name,
            labels: labels(node),
            description: node.description
        }] AS pathNodes,
        [rel IN relationships(p) | type(rel)] AS pathRelationships
    """
    with get_driver().session() as session:
        result = session.run(query, start=start, end=end)
        record = result.single()

    if record is None:
        raise HTTPException(
            status_code=404,
            detail=f"No path found between '{start}' and '{end}'. "
                   f"Check both node names exist and are connected.",
        )

    return {
        "start": start,
        "end": end,
        "nodes": record["pathNodes"],
        "relationships": record["pathRelationships"],
    }


# =================================================================
# GET /related?node=X
# =================================================================
@app.get("/related")
def get_related(node: str):
    query = """
    MATCH (n {name: $node})-[:RELATED_TO]-(related)
    RETURN DISTINCT related.name AS name, labels(related) AS labels,
           related.description AS description
    """
    with get_driver().session() as session:
        result = session.run(query, node=node)
        records = [dict(r) for r in result]

    if not records:
        with get_driver().session() as session:
            exists = session.run(
                "MATCH (n {name: $node}) RETURN n.name AS name", node=node
            ).single()
        if exists is None:
            raise HTTPException(status_code=404, detail=f"Node '{node}' not found.")

    return {"node": node, "related": records}


# =================================================================
# GET /defenses?attack=X
# =================================================================
@app.get("/defenses")
def get_defenses(attack: str):
    query = """
    MATCH (d:Defence)-[:MITIGATES]->(a:Attack {name: $attack})
    RETURN d.name AS name, d.description AS description
    """
    with get_driver().session() as session:
        result = session.run(query, attack=attack)
        records = [dict(r) for r in result]

    if not records:
        with get_driver().session() as session:
            exists = session.run(
                "MATCH (a:Attack {name: $attack}) RETURN a.name AS name", attack=attack
            ).single()
        if exists is None:
            raise HTTPException(status_code=404, detail=f"Attack '{attack}' not found.")

    return {"attack": attack, "defenses": records}


# =================================================================
# GET /tools?attack=X
# =================================================================
@app.get("/tools")
def get_tools(attack: str):
    query = """
    MATCH (t:Tool)-[:TOOL_USED_FOR]->(a:Attack {name: $attack})
    RETURN t.name AS name, t.description AS description
    """
    with get_driver().session() as session:
        result = session.run(query, attack=attack)
        records = [dict(r) for r in result]

    if not records:
        with get_driver().session() as session:
            exists = session.run(
                "MATCH (a:Attack {name: $attack}) RETURN a.name AS name", attack=attack
            ).single()
        if exists is None:
            raise HTTPException(status_code=404, detail=f"Attack '{attack}' not found.")

    return {"attack": attack, "tools": records}


# =================================================================
# GET /children?node=X
# =================================================================
@app.get("/children")
def get_children(node: str):
    """
    Returns nodes reachable via an outgoing LEARN_NEXT relationship.
    Used by Guided Mode's tree navigation.
    """
    query = """
    MATCH (n {name: $node})-[:LEARN_NEXT]->(child)
    RETURN child.name AS name, labels(child) AS labels, child.description AS description
    ORDER BY child.name
    """
    with get_driver().session() as session:
        result = session.run(query, node=node)
        records = [dict(r) for r in result]

    if not records:
        with get_driver().session() as session:
            exists = session.run(
                "MATCH (n {name: $node}) RETURN n.name AS name", node=node
            ).single()
        if exists is None:
            raise HTTPException(status_code=404, detail=f"Node '{node}' not found.")

    return {"node": node, "children": records}


# =================================================================
# GET /search?q=X
# =================================================================
@app.get("/search")
def search_nodes(q: str):
    """
    Case-insensitive substring search across all node names, used by
    Free-Flow Mode's search bar. Solves the exact-case-match limitation
    of the other endpoints -- a Free-Flow user shouldn't need to know
    the precise capitalization of a concept to find it.

    Returns at most 10 matches, ordered alphabetically. An empty or
    very short query returns no results rather than the whole graph,
    to avoid overwhelming the autocomplete dropdown.
    """
    if not q or len(q.strip()) < 2:
        return {"query": q, "results": []}

    query = """
    MATCH (n)
    WHERE toLower(n.name) CONTAINS toLower($q)
    RETURN n.name AS name, labels(n) AS labels
    ORDER BY n.name
    LIMIT 10
    """
    with get_driver().session() as session:
        result = session.run(query, q=q.strip())
        records = [dict(r) for r in result]

    return {"query": q, "results": records}


# =================================================================
# GET /questions  (helper endpoint for the frontend dropdown)
# =================================================================
@app.get("/questions")
def get_questions():
    return {"questions": list_questions()}


# =================================================================
# POST /question
# =================================================================
class QuestionRequest(BaseModel):
    question_id: str
    detail_level: str = "concise"


@app.post("/question")
def answer_question(payload: QuestionRequest):
    question = get_question(payload.question_id)
    if question is None:
        raise HTTPException(
            status_code=404,
            detail=f"Question id '{payload.question_id}' not found.",
        )

    path_data = get_shortest_path(question["start"], question["end"])

    explanation = generate_explanation(
        nodes=path_data["nodes"],
        relationships=path_data["relationships"],
        detail_level=payload.detail_level,
    )
    trace = generate_summary_line(
        nodes=path_data["nodes"],
        relationships=path_data["relationships"],
    )

    return {
        "question": question["text"],
        "path": path_data,
        "explanation": explanation,
        "trace": trace,
    }