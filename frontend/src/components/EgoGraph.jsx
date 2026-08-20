import { useEffect, useRef } from "react";
import cytoscape from "cytoscape";
import { resolvedColorFor, primaryLabel } from "../nodecolors";

/**
 * EgoGraph
 * --------
 * Renders the selected concept at the CENTER of a small radial graph,
 * with its direct neighbours (from /node/{name}, all relationship
 * types) arranged around it via Cytoscape's "concentric" layout. This
 * is the "small universe" view: clicking a neighbour re-centers the
 * graph on it, giving a lightweight exploratory feel even within the
 * structured Guided Mode.
 *
 * Props:
 *   centerNode: { name, labels, description, neighbours: [...] } | null
 *   onNodeClick: (name: string) => void  -- called when any node (including
 *                a neighbour) is clicked, so the parent can re-center or
 *                update the detail panel.
 */
export default function EgoGraph({ centerNode, onNodeClick }) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);

  useEffect(() => {
    if (!containerRef.current) return;

    // Tear down any previous instance before building a new one --
    // Cytoscape doesn't like being re-initialised on the same DOM node
    // without cleanup, and we rebuild elements fully on every selection
    // change rather than diffing (graphs here are small: ~5-8 nodes).
    if (cyRef.current) {
      cyRef.current.destroy();
      cyRef.current = null;
    }

    if (!centerNode) return;

    const elements = buildElements(centerNode);

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: buildStylesheet(),
      layout: {
        name: "concentric",
        concentric: (node) => (node.data("isCenter") ? 2 : 1),
        levelWidth: () => 1,
        minNodeSpacing: 60,
        animate: false,
      },
      userZoomingEnabled: true,
      userPanningEnabled: true,
      boxSelectionEnabled: false,
    });

    cy.on("tap", "node", (evt) => {
      const nodeName = evt.target.data("label");
      if (onNodeClick) onNodeClick(nodeName);
    });

    cyRef.current = cy;

    return () => {
      cy.destroy();
      cyRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [centerNode]);

  if (!centerNode) {
    return (
      <div className="ego-graph ego-graph--empty">
        <p>Select a concept from the tree to explore its connections.</p>
      </div>
    );
  }

  return <div className="ego-graph" ref={containerRef} />;
}

function buildElements(centerNode) {
  const nodes = [
    {
      data: {
        id: centerNode.name,
        label: centerNode.name,
        color: resolvedColorFor(centerNode.labels),
        isCenter: true,
      },
    },
  ];
  const edges = [];

  (centerNode.neighbours || []).forEach((n, i) => {
    const nodeId = `${n.name}__${i}`; // unique even if same name appears via two relationship types
    nodes.push({
      data: {
        id: nodeId,
        label: n.name,
        color: resolvedColorFor(n.labels),
        isCenter: false,
      },
    });
    edges.push({
      data: {
        id: `edge-${nodeId}`,
        source: centerNode.name,
        target: nodeId,
        relType: n.relationship,
      },
    });
  });

  return [...nodes, ...edges];
}

function buildStylesheet() {
  return [
    {
      selector: "node",
      style: {
        "background-color": "data(color)",
        label: "data(label)",
        color: "#e7edf3",
        "font-family": "IBM Plex Mono, monospace",
        "font-size": 11,
        "text-valign": "bottom",
        "text-margin-y": 6,
        "text-wrap": "wrap",
        "text-max-width": "90px",
        width: 28,
        height: 28,
        "border-width": 2,
        "border-color": "#0a0e13",
      },
    },
    {
      selector: "node[?isCenter]",
      style: {
        width: 46,
        height: 46,
        "font-size": 13,
        "font-weight": 600,
        "border-width": 3,
        "border-color": "#4dd6c4",
      },
    },
    {
      selector: "edge",
      style: {
        width: 1.5,
        "line-color": "#232d38",
        "target-arrow-color": "#232d38",
        "target-arrow-shape": "triangle",
        "curve-style": "bezier",
        label: "data(relType)",
        "font-size": 8,
        "font-family": "IBM Plex Mono, monospace",
        color: "#5a6672",
        "text-rotation": "autorotate",
        "text-margin-y": -6,
      },
    },
  ];
}
