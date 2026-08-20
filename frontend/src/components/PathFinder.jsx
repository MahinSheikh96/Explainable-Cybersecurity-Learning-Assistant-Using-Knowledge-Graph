import { useState } from "react";
import SearchBar from "./SearchBar";
import { fetchPath } from "../api";

/**
 * PathFinder
 * ----------
 * Available in both modes. Lets the user search for a start node and
 * an end node independently (reusing SearchBar purely for its
 * autocomplete, not for revealing anything itself), then calls
 * GET /path and hands the result up to the parent to reveal/highlight
 * on whichever graph is active -- via the same revealPath imperative
 * method the QuestionPanel already uses.
 *
 * This is what makes "visualize attack paths" a general capability
 * rather than something only the 5 premade questions can do.
 */
export default function PathFinder({ onPathFound, onClear }) {
  const [open, setOpen] = useState(false);
  const [start, setStart] = useState(null);
  const [end, setEnd] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleFind = async () => {
    if (!start || !end) return;
    setLoading(true);
    setError(null);
    try {
      const data = await fetchPath(start.name, end.name);
      onPathFound?.(data);
    } catch (err) {
      setError(
        err?.response?.status === 404
          ? "No connection found between those two nodes."
          : "Couldn't find a path -- try again."
      );
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setStart(null);
    setEnd(null);
    setError(null);
    onClear?.();
  };

  return (
    <div className="path-finder">
      <button
        className={`path-finder__toggle ${open ? "is-active" : ""}`}
        onClick={() => setOpen((o) => !o)}
      >
        Find a path…
      </button>

      {open && (
        <div className="path-finder__panel">
          <label className="path-finder__label">From</label>
          <SearchBar onSelectNode={(name, labels) => setStart({ name, labels })} />
          {start && <div className="path-finder__chosen">✓ {start.name}</div>}

          <label className="path-finder__label">To</label>
          <SearchBar onSelectNode={(name, labels) => setEnd({ name, labels })} />
          {end && <div className="path-finder__chosen">✓ {end.name}</div>}

          <div className="path-finder__actions">
            <button
              className="path-finder__find"
              disabled={!start || !end || loading}
              onClick={handleFind}
            >
              {loading ? "Finding…" : "Find Path"}
            </button>
            <button className="path-finder__reset" onClick={handleReset}>
              Reset
            </button>
          </div>

          {error && <p className="path-finder__error">{error}</p>}
        </div>
      )}
    </div>
  );
}
