"""
db.py
-----
Creates a single, reusable Neo4j driver instance for the whole app.
FastAPI will call get_driver() once at startup and reuse the same
connection pool for every request, instead of opening a new connection
per API call (which would be slow and wasteful).
"""

import os
from dotenv import load_dotenv
from neo4j import GraphDatabase

# Load variables from backend/.env into the process environment
load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USER = os.getenv("NEO4J_USER")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")

if not all([NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD]):
    raise RuntimeError(
        "Missing Neo4j connection details. Check that backend/.env exists "
        "and contains NEO4J_URI, NEO4J_USER, and NEO4J_PASSWORD."
    )

# The driver manages a connection pool internally — safe to reuse
# across requests, and should be created only once per process.
driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))


def get_driver():
    """Returns the shared driver instance for use in endpoint functions."""
    return driver


def verify_connectivity():
    """
    Call this once at startup to fail fast with a clear error
    if Neo4j isn't reachable, rather than failing confusingly
    on the first real request.
    """
    driver.verify_connectivity()


def close_driver():
    """Call this on app shutdown to cleanly release connections."""
    driver.close()