import { useState, useEffect, useCallback } from "react";
import { fetchQuestions, askQuestion } from "../api";

/**
 * QuestionPanel
 * -------------
 * Available in both Guided and Free-Flow Mode. Fetches the premade
 * question list on mount, and on selection calls POST /question, then
 * hands the returned path up to the parent (App) via onAnswer so it
 * can be revealed/highlighted on whichever graph is currently active.
 */
export default function QuestionPanel({ onAnswer, onClear }) {
  const [questions, setQuestions] = useState([]);
  const [selectedId, setSelectedId] = useState("");
  const [detailLevel, setDetailLevel] = useState("concise");
  const [answer, setAnswer] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchQuestions()
      .then((data) => setQuestions(data.questions || []))
      .catch(() => setQuestions([]));
  }, []);

  const runQuestion = useCallback(
    async (questionId, level) => {
      if (!questionId) return;
      setLoading(true);
      try {
        const data = await askQuestion(questionId, level);
        setAnswer(data);
        onAnswer?.(data.path);
      } catch {
        setAnswer(null);
      } finally {
        setLoading(false);
      }
    },
    [onAnswer]
  );

  const handleSelectChange = (e) => {
    const id = e.target.value;
    setSelectedId(id);
    if (id) {
      runQuestion(id, detailLevel);
    } else {
      setAnswer(null);
      onClear?.();
    }
  };

  const handleToggleDetail = (level) => {
    setDetailLevel(level);
    if (selectedId) runQuestion(selectedId, level);
  };

  const handleDismiss = () => {
    setSelectedId("");
    setAnswer(null);
    onClear?.();
  };

  return (
    <div className="question-panel">
      <select
        className="question-panel__select"
        value={selectedId}
        onChange={handleSelectChange}
      >
        <option value="">Ask a premade question…</option>
        {questions.map((q) => (
          <option key={q.id} value={q.id}>
            {q.text}
          </option>
        ))}
      </select>

      {(answer || loading) && (
        <div className="question-panel__answer">
          {loading && <p className="question-panel__loading">Thinking…</p>}

          {!loading && answer && (
            <>
              <div className="question-panel__toggle">
                <button
                  className={detailLevel === "concise" ? "is-active" : ""}
                  onClick={() => handleToggleDetail("concise")}
                >
                  Concise
                </button>
                <button
                  className={detailLevel === "detailed" ? "is-active" : ""}
                  onClick={() => handleToggleDetail("detailed")}
                >
                  Detailed
                </button>
                <button className="question-panel__dismiss" onClick={handleDismiss}>
                  ✕
                </button>
              </div>
              <p className="question-panel__explanation">{answer.explanation}</p>
              <p className="question-panel__trace">{answer.trace}</p>
            </>
          )}
        </div>
      )}
    </div>
  );
}
