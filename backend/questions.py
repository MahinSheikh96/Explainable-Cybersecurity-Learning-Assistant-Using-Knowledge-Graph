"""
questions.py
------------
Maps a small, fixed set of "premade questions" (shown as a dropdown in the
frontend) to a start node and end node in the graph. The /question endpoint
finds the shortest path between them and turns it into a plain-English
explanation via the explanation engine (built in Phase 4).

To add a new question later: add a new entry here with a unique id.
No other code changes are needed — the frontend dropdown (Phase 6) will
read this same list via a small helper endpoint.
"""

PREDEFINED_QUESTIONS = {
    "q1": {
        "text": "How does SQL Injection lead to loss of user data?",
        "start": "SQL Injection",
        "end": "User Data",
    },
    "q2": {
        "text": "How does Cross-Site Scripting compromise a session cookie?",
        "start": "Cross-Site Scripting",
        "end": "Session Cookie",
    },
    "q3": {
        "text": "What defends against SQL Injection?",
        "start": "SQL Injection",
        "end": "Prepared Statements",
    },
    "q4": {
        "text": "How is CSRF related to Cross-Site Scripting?",
        "start": "Cross-Site Request Forgery",
        "end": "Cross-Site Scripting",
    },
    "q5": {
        "text": "What tool is used to test for SQL Injection?",
        "start": "SQL Injection",
        "end": "sqlmap",
    },
}


def get_question(question_id: str):
    """Returns the question dict for a given id, or None if not found."""
    return PREDEFINED_QUESTIONS.get(question_id)


def list_questions():
    """Returns all questions in a frontend-friendly list format."""
    return [
        {"id": qid, "text": q["text"]}
        for qid, q in PREDEFINED_QUESTIONS.items()
    ]