import { useState, useEffect, useRef, useCallback } from "react";
import { searchNodes } from "../api";
import { primaryLabel, colorVarFor } from "../nodeColors";

/**
 * SearchBar
 * ---------
 * Free-Flow Mode only. Debounced live search against /search
 * (case-insensitive substring match), showing up to 10 suggestions.
 * Selecting one calls onSelectNode(name, labels), which the parent
 * wires to graphRef.current.revealBareNode.
 */
export default function SearchBar({ onSelectNode }) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState([]);
  const [open, setOpen] = useState(false);
  const debounceRef = useRef(null);

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);

    if (query.trim().length < 2) {
      setResults([]);
      setOpen(false);
      return;
    }

    debounceRef.current = setTimeout(async () => {
      try {
        const data = await searchNodes(query.trim());
        setResults(data.results || []);
        setOpen(true);
      } catch {
        setResults([]);
      }
    }, 250);

    return () => clearTimeout(debounceRef.current);
  }, [query]);

  const handleSelect = useCallback(
    (result) => {
      onSelectNode(result.name, result.labels);
      setQuery("");
      setResults([]);
      setOpen(false);
    },
    [onSelectNode]
  );

  return (
    <div className="search-bar">
      <input
        type="text"
        className="search-bar__input"
        placeholder="Search any concept (e.g. sqlmap, CWE-79)…"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        onFocus={() => results.length > 0 && setOpen(true)}
        onBlur={() => setTimeout(() => setOpen(false), 150)}
      />
      {open && results.length > 0 && (
        <ul className="search-bar__suggestions">
          {results.map((r) => (
            <li
              key={r.name}
              className="search-bar__suggestion"
              onMouseDown={() => handleSelect(r)}
            >
              <span
                className="search-bar__dot"
                style={{ background: `var(${colorVarFor(r.labels)})` }}
              />
              <span>{r.name}</span>
              <span className="search-bar__label">{primaryLabel(r.labels)}</span>
            </li>
          ))}
        </ul>
      )}
      {open && results.length === 0 && query.trim().length >= 2 && (
        <ul className="search-bar__suggestions">
          <li className="search-bar__suggestion search-bar__suggestion--empty">
            No matches for "{query.trim()}"
          </li>
        </ul>
      )}
    </div>
  );
}
