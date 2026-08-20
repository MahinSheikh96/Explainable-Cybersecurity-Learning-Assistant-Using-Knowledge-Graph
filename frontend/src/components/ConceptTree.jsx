import { useState } from "react";
import { fetchChildren } from "../api";
import { colorVarFor } from "../nodecolors";

/**
 * TreeNode
 * --------
 * A single row in the tree. Manages its own expand/collapse state and
 * lazily fetches its children from /children only the first time it's
 * expanded (cached afterwards in local state) — keeps the tree snappy
 * without a big upfront fetch of the whole hierarchy.
 */
function TreeNode({ name, description, labels, depth, onSelect, selectedName }) {
  const [expanded, setExpanded] = useState(false);
  const [children, setChildren] = useState(null); // null = not yet fetched
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const hasFetchedChildren = children !== null;
  const isSelected = selectedName === name;

  async function handleToggleExpand(e) {
    e.stopPropagation();
    if (!hasFetchedChildren) {
      setLoading(true);
      setError(null);
      try {
        const data = await fetchChildren(name);
        setChildren(data.children);
      } catch (err) {
        setError("Couldn't load children.");
        setChildren([]);
      } finally {
        setLoading(false);
      }
    }
    setExpanded((prev) => !prev);
  }

  function handleSelect() {
    onSelect(name);
  }

  const colorVar = colorVarFor(labels);
  const isLeafGuess = hasFetchedChildren && children.length === 0;

  return (
    <div className="tree-node" style={{ "--depth": depth }}>
      <div
        className={`tree-row${isSelected ? " tree-row--selected" : ""}`}
        onClick={handleSelect}
      >
        <button
          className={`tree-caret${expanded ? " tree-caret--open" : ""}`}
          onClick={handleToggleExpand}
          aria-label={expanded ? `Collapse ${name}` : `Expand ${name}`}
          aria-expanded={expanded}
        >
          {loading ? "…" : isLeafGuess ? "·" : "▸"}
        </button>
        <span className="tree-dot" style={{ background: `var(${colorVar})` }} />
        <span className="tree-label">{name}</span>
      </div>

      {expanded && (
        <div className="tree-children">
          {error && <div className="tree-error">{error}</div>}
          {hasFetchedChildren &&
            children.map((child) => (
              <TreeNode
                key={child.name}
                name={child.name}
                description={child.description}
                labels={child.labels}
                depth={depth + 1}
                onSelect={onSelect}
                selectedName={selectedName}
              />
            ))}
        </div>
      )}
    </div>
  );
}

/**
 * ConceptTree
 * -----------
 * Root of Guided Mode's navigation. Always starts from the fixed
 * "Cybersecurity" root node and expands downward via LEARN_NEXT edges
 * (fetched through /children, never the generic /node neighbour list,
 * so the tree only ever shows learning-path structure).
 */
export default function ConceptTree({ onSelect, selectedName }) {
  return (
    <div className="concept-tree">
      <div className="concept-tree__heading">Guided Mode</div>
      <TreeNode
        name="Cybersecurity"
        depth={0}
        onSelect={onSelect}
        selectedName={selectedName}
      />
    </div>
  );
}
