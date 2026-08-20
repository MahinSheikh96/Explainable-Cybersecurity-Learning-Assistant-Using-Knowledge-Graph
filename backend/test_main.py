"""
test_main.py
------------
Automated backend test suite, built on pytest + FastAPI's TestClient
(which itself is built on httpx, per the original spec's requirement).

IMPORTANT: these are INTEGRATION tests, not unit tests with mocks.
They run against your actual, live Neo4j instance (same one the app
uses), seeded with seed_graph.cypher. This is deliberate: the whole
point of this project is that every answer is grounded in real graph
data, so testing against a mock would only prove the code compiles,
not that the reasoning is correct. Before running these, make sure:
  1. Neo4j Desktop's DBMS is running
  2. seed_graph.cypher has been loaded (26 nodes / ~48 relationships)
  3. backend/.env has the correct credentials

Run with:
  pytest test_main.py -v
"""

import pytest
from fastapi.testclient import TestClient

from main import app


@pytest.fixture(scope="module")
def client():
    # Using TestClient as a context manager triggers the app's
    # startup/shutdown events (Neo4j connectivity check + index
    # creation), same as a real run.
    with TestClient(app) as c:
        yield c


# =================================================================
# GET /node/{name}
# =================================================================
class TestGetNode:
    def test_existing_node_returns_full_details(self, client):
        response = client.get("/node/SQL Injection")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "SQL Injection"
        assert "Attack" in data["labels"]
        assert data["description"]
        assert len(data["neighbours"]) > 0

    def test_neighbours_have_relationship_type(self, client):
        response = client.get("/node/SQL Injection")
        data = response.json()
        # Every neighbour must carry the relationship that connects it,
        # since that's what the frontend uses to group/color edges.
        for neighbour in data["neighbours"]:
            assert neighbour["relationship"]
            assert neighbour["name"]

    def test_nonexistent_node_returns_404(self, client):
        response = client.get("/node/This Node Does Not Exist")
        assert response.status_code == 404

    def test_case_sensitive_exact_match_required(self, client):
        # /node/{name} is intentionally exact-match (only /search is
        # case-insensitive) -- confirms that design choice still holds.
        response = client.get("/node/sql injection")
        assert response.status_code == 404


# =================================================================
# GET /path
# =================================================================
class TestGetPath:
    def test_path_between_connected_nodes(self, client):
        response = client.get(
            "/path", params={"start": "SQL Injection", "end": "User Data"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["nodes"][0]["name"] == "SQL Injection"
        assert data["nodes"][-1]["name"] == "User Data"
        # One fewer relationship than nodes, since each relationship
        # connects two consecutive nodes.
        assert len(data["relationships"]) == len(data["nodes"]) - 1

    def test_path_with_nonexistent_node_returns_404(self, client):
        response = client.get(
            "/path", params={"start": "SQL Injection", "end": "Not A Real Node"}
        )
        assert response.status_code == 404

    def test_path_nodes_include_descriptions(self, client):
        # /path must include descriptions -- the explanation engine's
        # detailed mode depends on this.
        response = client.get(
            "/path", params={"start": "SQL Injection", "end": "CWE-89"}
        )
        data = response.json()
        assert all(n.get("description") for n in data["nodes"])


# =================================================================
# GET /defenses
# =================================================================
class TestGetDefenses:
    def test_sql_injection_defenses(self, client):
        response = client.get("/defenses", params={"attack": "SQL Injection"})
        assert response.status_code == 200
        data = response.json()
        names = [d["name"] for d in data["defenses"]]
        assert "Prepared Statements" in names

    def test_nonexistent_attack_returns_404(self, client):
        response = client.get("/defenses", params={"attack": "Not A Real Attack"})
        assert response.status_code == 404


# =================================================================
# GET /tools
# =================================================================
class TestGetTools:
    def test_sql_injection_tools(self, client):
        response = client.get("/tools", params={"attack": "SQL Injection"})
        assert response.status_code == 200
        data = response.json()
        names = [t["name"] for t in data["tools"]]
        assert "sqlmap" in names

    def test_nonexistent_attack_returns_404(self, client):
        response = client.get("/tools", params={"attack": "Not A Real Attack"})
        assert response.status_code == 404


# =================================================================
# GET /related
# =================================================================
class TestGetRelated:
    def test_sql_injection_related_concepts(self, client):
        response = client.get("/related", params={"node": "SQL Injection"})
        assert response.status_code == 200
        data = response.json()
        names = [r["name"] for r in data["related"]]
        assert "Cross-Site Scripting" in names

    def test_nonexistent_node_returns_404(self, client):
        response = client.get("/related", params={"node": "Not A Real Node"})
        assert response.status_code == 404


# =================================================================
# GET /children
# =================================================================
class TestGetChildren:
    def test_root_children(self, client):
        response = client.get("/children", params={"node": "Cybersecurity"})
        assert response.status_code == 200
        data = response.json()
        names = [c["name"] for c in data["children"]]
        assert "Web Security" in names

    def test_leaf_node_has_no_children(self, client):
        # An Attack node has no outgoing LEARN_NEXT, so this should be
        # an empty list, NOT a 404 (the node exists, it just has no
        # LEARN_NEXT children -- different from not existing at all).
        response = client.get("/children", params={"node": "SQL Injection"})
        assert response.status_code == 200
        assert response.json()["children"] == []

    def test_nonexistent_node_returns_404(self, client):
        response = client.get("/children", params={"node": "Not A Real Node"})
        assert response.status_code == 404


# =================================================================
# GET /search
# =================================================================
class TestSearch:
    def test_case_insensitive_search(self, client):
        response = client.get("/search", params={"q": "sql"})
        assert response.status_code == 200
        names = [r["name"] for r in response.json()["results"]]
        assert "SQL Injection" in names

    def test_uppercase_query_still_matches(self, client):
        response = client.get("/search", params={"q": "SQL"})
        names = [r["name"] for r in response.json()["results"]]
        assert "SQL Injection" in names

    def test_too_short_query_returns_empty_not_error(self, client):
        response = client.get("/search", params={"q": "s"})
        assert response.status_code == 200
        assert response.json()["results"] == []

    def test_no_match_returns_empty_list(self, client):
        response = client.get("/search", params={"q": "zzzznonexistent"})
        assert response.status_code == 200
        assert response.json()["results"] == []


# =================================================================
# GET /questions
# =================================================================
class TestQuestionsList:
    def test_returns_all_premade_questions(self, client):
        response = client.get("/questions")
        assert response.status_code == 200
        questions = response.json()["questions"]
        assert len(questions) == 5
        assert all("id" in q and "text" in q for q in questions)


# =================================================================
# POST /question
# =================================================================
class TestAnswerQuestion:
    def test_valid_question_id_concise(self, client):
        response = client.post(
            "/question", json={"question_id": "q1", "detail_level": "concise"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["explanation"]
        assert data["trace"]
        assert data["path"]["nodes"]

    def test_valid_question_id_detailed_is_longer(self, client):
        concise = client.post(
            "/question", json={"question_id": "q1", "detail_level": "concise"}
        ).json()
        detailed = client.post(
            "/question", json={"question_id": "q1", "detail_level": "detailed"}
        ).json()
        # Detailed mode appends descriptions, so it should never be
        # shorter than concise mode for the same question.
        assert len(detailed["explanation"]) >= len(concise["explanation"])

    def test_invalid_question_id_returns_404(self, client):
        response = client.post("/question", json={"question_id": "not_a_real_id"})
        assert response.status_code == 404

    def test_missing_question_id_returns_422(self, client):
        # Pydantic validation error -- question_id is a required field.
        response = client.post("/question", json={})
        assert response.status_code == 422

    def test_invalid_detail_level_falls_back_gracefully(self, client):
        # explanation_engine.generate_explanation defaults unrecognised
        # detail_level values to "concise" rather than erroring.
        response = client.post(
            "/question", json={"question_id": "q1", "detail_level": "not_a_real_mode"}
        )
        assert response.status_code == 200