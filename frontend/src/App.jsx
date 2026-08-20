import { useState, useCallback, useRef, useEffect } from "react";
import KnowledgeUniverse from "./components/KnowledgeUniverse";
import SearchBar from "./components/SearchBar";
import QuestionPanel from "./components/QuestionPanel";
import PathFinder from "./components/PathFinder";
import { fetchDefenses, fetchTools } from "./api";
import { primaryLabel, colorVarFor } from "./nodeColors";

/**
 * App
 * ---
 * Guided Mode and Free-Flow Mode share the same KnowledgeUniverse graph
 * engine. Switching modes resets the canvas -- enforced by giving the
 * graph a `key={mode}`, which forces React to fully unmount and remount
 * it (a fresh Cytoscape instance) rather than trying to reconcile state
 * between two different interaction models.
 *
 * QuestionPanel lives in the header and works in both modes: it calls
 * graphRef.current.revealPath(...) to reveal/highlight the answer's
 * path on whichever graph is currently active.
 *
 * SearchBar only renders in Free-Flow Mode, calling
 * graphRef.current.revealBareNode(...) to drop a searched concept onto
 * the canvas without navigating away from Guided Mode's fixed root.
 */
export default function App() {
  const [mode, setMode] = useState("guided"); // "guided" | "freeflow"
  const [theme, setTheme] = useState(() => localStorage.getItem("kg-theme") || "dark");
  const [nodeDetails, setNodeDetails] = useState(null);
  const graphRef = useRef(null);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("kg-theme", theme);
    // Cytoscape doesn't watch CSS changes -- explicitly tell the graph
    // to re-read variable values now that the theme attribute changed.
    graphRef.current?.refreshTheme();
  }, [theme]);

  const handleSelect = useCallback((data) => {
    setNodeDetails(data);
  }, []);

  const handleModeChange = (newMode) => {
    if (newMode === mode) return;
    setMode(newMode);
    setNodeDetails(null);
  };

  const handleSearchSelect = useCallback((name, labels) => {
    graphRef.current?.revealBareNode(name, labels);
  }, []);

  const handleQuestionAnswer = useCallback((pathData) => {
    graphRef.current?.revealPath(pathData);
  }, []);

  const handleQuestionClear = useCallback(() => {
    graphRef.current?.clearHighlight();
  }, []);

  const handlePathFound = useCallback((pathData) => {
    graphRef.current?.revealPath(pathData);
  }, []);

  const handlePathClear = useCallback(() => {
    graphRef.current?.clearHighlight();
  }, []);

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="app-header__brand">
          <span className="app-header__glyph">◈</span>
          <div>
            <h1 className="app-header__title">Cybersecurity Knowledge Graph</h1>
            <p className="app-header__subtitle">Explainable learning assistant</p>
          </div>
        </div>

        <div className="app-header__controls">
          <button
            className="theme-toggle"
            onClick={() => setTheme((t) => (t === "dark" ? "light" : "dark"))}
            title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
          >
            {theme === "dark" ? "☀" : "☾"}
          </button>

          <div className="mode-toggle">
            <button
              className={mode === "guided" ? "is-active" : ""}
              onClick={() => handleModeChange("guided")}
            >
              Guided Mode
            </button>
            <button
              className={mode === "freeflow" ? "is-active" : ""}
              onClick={() => handleModeChange("freeflow")}
            >
              Free-Flow Mode
            </button>
          </div>

          {mode === "freeflow" && <SearchBar onSelectNode={handleSearchSelect} />}

          <PathFinder onPathFound={handlePathFound} onClear={handlePathClear} />

          <QuestionPanel onAnswer={handleQuestionAnswer} onClear={handleQuestionClear} />
        </div>
      </header>

      <div className="app-body">
        <main className="app-main">
          <KnowledgeUniverse
            key={mode}
            ref={graphRef}
            onSelect={handleSelect}
            startEmpty={mode === "freeflow"}
          />
          <DetailPanel nodeDetails={nodeDetails} />
        </main>
      </div>
    </div>
  );
}

function DetailPanel({ nodeDetails }) {
  const [recommendations, setRecommendations] = useState(null);
  const [recLoading, setRecLoading] = useState(false);

  const isAttack = (nodeDetails?.labels || []).includes("Attack");

  useEffect(() => {
    if (!nodeDetails || !isAttack) {
      setRecommendations(null);
      return;
    }
    let cancelled = false;
    setRecLoading(true);
    Promise.all([fetchDefenses(nodeDetails.name), fetchTools(nodeDetails.name)])
      .then(([defensesData, toolsData]) => {
        if (cancelled) return;
        setRecommendations({
          defenses: defensesData.defenses || [],
          tools: toolsData.tools || [],
        });
      })
      .catch(() => {
        if (!cancelled) setRecommendations(null);
      })
      .finally(() => {
        if (!cancelled) setRecLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [nodeDetails, isAttack]);

  if (!nodeDetails) {
    return (
      <div className="detail-panel detail-panel--empty">
        <p>Click a node in the graph above to see its details here.</p>
      </div>
    );
  }

  const label = primaryLabel(nodeDetails.labels);
  const colorVar = colorVarFor(nodeDetails.labels);

  const grouped = {};
  (nodeDetails.neighbours || []).forEach((n) => {
    if (!grouped[n.relationship]) grouped[n.relationship] = [];
    grouped[n.relationship].push(n);
  });

  return (
    <div className="detail-panel">
      <div className="detail-panel__heading">
        <span className="label-badge" style={{ background: `var(${colorVar})` }}>
          {label}
        </span>
        <h2>{nodeDetails.name}</h2>
      </div>

      {nodeDetails.description && (
        <p className="detail-panel__description">{nodeDetails.description}</p>
      )}

      {isAttack && (recLoading || recommendations) && (
        <RecommendationsPanel loading={recLoading} recommendations={recommendations} />
      )}

      {Object.keys(grouped).length > 0 && (
        <div className="detail-panel__relations">
          {Object.entries(grouped).map(([relType, items]) => (
            <div className="relation-group" key={relType}>
              <div className="relation-group__type">{relType}</div>
              <ul className="relation-group__list">
                {items.map((item, i) => (
                  <li key={`${item.name}-${i}`}>{item.name}</li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/**
 * RecommendationsPanel
 * ---------------------
 * Dedicated, purpose-built panel for Attack nodes -- pulled from the
 * actual /defenses and /tools endpoints rather than just reading them
 * out of the generic neighbours list, and given visual prominence
 * (bordered cards, colored accents matching the Defence/Tool node
 * colors) so recommendations are the first thing you notice on an
 * attack's detail view, not something buried in a relationship list.
 */
function RecommendationsPanel({ loading, recommendations }) {
  if (loading) {
    return (
      <div className="recommendations">
        <p className="recommendations__loading">Loading recommendations…</p>
      </div>
    );
  }

  if (!recommendations) return null;
  const { defenses, tools } = recommendations;
  if (defenses.length === 0 && tools.length === 0) return null;

  return (
    <div className="recommendations">
      {defenses.length > 0 && (
        <div className="recommendation-card recommendation-card--defence">
          <div className="recommendation-card__title">🛡 Recommended Defenses</div>
          <ul className="recommendation-card__list">
            {defenses.map((d) => (
              <li key={d.name}>
                <span className="recommendation-card__name">{d.name}</span>
                {d.description && (
                  <span className="recommendation-card__desc">{d.description}</span>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      {tools.length > 0 && (
        <div className="recommendation-card recommendation-card--tool">
          <div className="recommendation-card__title">🔧 Tools Used For Testing</div>
          <ul className="recommendation-card__list">
            {tools.map((t) => (
              <li key={t.name}>
                <span className="recommendation-card__name">{t.name}</span>
                {t.description && (
                  <span className="recommendation-card__desc">{t.description}</span>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
