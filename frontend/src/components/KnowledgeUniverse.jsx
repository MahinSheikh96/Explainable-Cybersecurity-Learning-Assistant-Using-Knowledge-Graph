import {
  useEffect,
  useRef,
  useState,
  useCallback,
  forwardRef,
  useImperativeHandle,
} from "react";
import cytoscape from "cytoscape";
import { fetchNode } from "../api";
import {
  resolvedColorFor,
  resolvedRelColor,
  resolveCssVar,
  lighten,
  darken,
} from "../nodeColors";

const ROOT_NAME = "Cybersecurity";
const ORBIT_RADIUS = 220;

/**
 * KnowledgeUniverse
 * -----------------
 * Shared graph engine for BOTH Guided Mode and Free-Flow Mode. Starts
 * with "Cybersecurity" at the center; clicking any node expands its
 * connections in an arc anchored to that node (see computeArcPositions),
 * never repositioning anything already on screen.
 *
 * Exposes an imperative API (via ref) used by parent components:
 *   - revealBareNode(name, labels): drops an unconnected node onto the
 *     canvas near the root, without fetching its neighbours yet. Used
 *     by Free-Flow's search bar -- the user then clicks it normally to
 *     expand, same as any other node.
 *   - revealPath(pathData): ensures every node/edge in a path (from the
 *     /question endpoint) exists on the canvas, adding whatever's
 *     missing, then highlights the whole path and focuses the camera
 *     on it. Used by the premade-question dropdown, in both modes.
 *   - clearHighlight(): removes any active path highlight.
 */
const KnowledgeUniverse = forwardRef(function KnowledgeUniverse(
  { onSelect, startEmpty = false },
  ref
) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);
  const expandedRef = useRef(new Set());
  // Caches fetchNode() results by name so re-clicking an already-seen
  // node (to refresh the detail panel) doesn't hit the network again --
  // the biggest single contributor to expansion feeling slow.
  const nodeCacheRef = useRef(new Map());
  // Tracks which node "discovered" (first revealed) each other node,
  // so double-click can collapse exactly the subtree that a given
  // node's expansion introduced.
  const parentOfRef = useRef(new Map());
  const childrenOfRef = useRef(new Map());
  const [loadingNode, setLoadingNode] = useState(null);
  const [error, setError] = useState(null);

  const fitView = useCallback((eles) => {
    const cy = cyRef.current;
    if (!cy || cy.destroyed()) return;
    cy.animate(
      { fit: { eles: eles || cy.elements(), padding: 70 } },
      { duration: 220, easing: "ease-out" }
    );
  }, []);

  const expandNode = useCallback(
    async (name) => {
      setError(null);

      // Cache hit: skip the network round-trip entirely. This is what
      // makes re-clicking an already-expanded node feel instant instead
      // of re-fetching data it already has.
      const cached = nodeCacheRef.current.get(name);
      if (cached) {
        onSelect?.(cached);
        return;
      }

      setLoadingNode(name);
      try {
        const t0 = performance.now();
        const data = await fetchNode(name);
        const ms = Math.round(performance.now() - t0);
        // eslint-disable-next-line no-console
        console.log(`[KnowledgeUniverse] fetchNode("${name}") took ${ms}ms`);
        nodeCacheRef.current.set(name, data);
        onSelect?.(data);

        const cy = cyRef.current;
        if (!cy || cy.destroyed()) return;

        if (!expandedRef.current.has(name)) {
          const parentEle = cy.getElementById(name);
          const parentPos = parentEle.position();
          const rootPos =
            cy.getElementById(ROOT_NAME).length > 0
              ? cy.getElementById(ROOT_NAME).position()
              : parentPos;

          const newNodeNames = [];
          (data.neighbours || []).forEach((n) => {
            if (n.name && cy.getElementById(n.name).length === 0) {
              newNodeNames.push(n);
            }
          });

          const positions = computeArcPositions(
            parentPos,
            rootPos,
            newNodeNames.length,
            name === ROOT_NAME || parentPos === rootPos
          );

          const newElements = [];
          newNodeNames.forEach((n) => {
            newElements.push({
              group: "nodes",
              data: { id: n.name, label: n.name, labels: n.labels },
              // Spawn AT the parent's position, invisible -- animated
              // outward below. This reads as the new node budding out
              // of the node you clicked, rather than popping in at a
              // final position while the camera separately pans to it.
              position: { x: parentPos.x, y: parentPos.y },
              classes: "growing-in",
            });
            parentOfRef.current.set(n.name, name);
            if (!childrenOfRef.current.has(name)) {
              childrenOfRef.current.set(name, new Set());
            }
            childrenOfRef.current.get(name).add(n.name);
          });

          (data.neighbours || []).forEach((n) => {
            if (!n.name) return;
            const edgeId = `${name}__${n.relationship}__${n.name}`;
            const reverseEdgeId = `${n.name}__${n.relationship}__${name}`;
            if (
              cy.getElementById(edgeId).length === 0 &&
              cy.getElementById(reverseEdgeId).length === 0
            ) {
              newElements.push({
                group: "edges",
                data: {
                  id: edgeId,
                  source: name,
                  target: n.name,
                  relationship: n.relationship,
                },
                classes: "growing-in",
              });
            }
          });

          if (newElements.length > 0) {
            const added = cy.add(newElements);

            // Animate each new node from the parent's position out to
            // its computed arc slot, fading in as it travels. Edges
            // just fade in (their endpoints move with the nodes
            // automatically, so they don't need a position animation).
            newNodeNames.forEach((n, i) => {
              const ele = cy.getElementById(n.name);
              ele.animate(
                { position: positions[i], style: { opacity: 1 } },
                {
                  duration: 420,
                  easing: "ease-out-cubic",
                  complete: () => ele.removeClass("growing-in"),
                }
              );
            });
            added
              .filter((ele) => ele.isEdge())
              .animate(
                { style: { opacity: 1 } },
                {
                  duration: 420,
                  easing: "ease-out-cubic",
                  complete: () =>
                    added.filter((ele) => ele.isEdge()).removeClass("growing-in"),
                }
              );
          }
          expandedRef.current.add(name);
          fitView();
        }
      } catch (err) {
        setError(`Couldn't load "${name}".`);
      } finally {
        setLoadingNode(null);
      }
    },
    [onSelect, fitView]
  );

  const collapseNode = useCallback((name) => {
    const cy = cyRef.current;
    if (!cy || cy.destroyed()) return;
    if (!childrenOfRef.current.has(name)) return; // nothing was ever expanded from here

    // Gather every descendant this node's expansion (directly or
    // transitively) introduced, so collapsing a branch removes the
    // whole subtree, not just the immediate children.
    const toRemove = new Set();
    const stack = [name];
    while (stack.length > 0) {
      const current = stack.pop();
      const kids = childrenOfRef.current.get(current);
      if (!kids) continue;
      kids.forEach((kid) => {
        if (!toRemove.has(kid)) {
          toRemove.add(kid);
          stack.push(kid);
        }
      });
    }

    if (toRemove.size === 0) return;

    toRemove.forEach((n) => {
      cy.getElementById(n).remove(); // also removes any incident edges
      nodeCacheRef.current.delete(n);
      expandedRef.current.delete(n);
      parentOfRef.current.delete(n);
      childrenOfRef.current.delete(n);
    });

    childrenOfRef.current.delete(name);
    expandedRef.current.delete(name); // clicking `name` again re-expands fresh
    nodeCacheRef.current.delete(name); // <-- this was missing: without it,
    // the next click on `name` hit the cache-hit shortcut in expandNode
    // and returned immediately, before ever reaching the re-expand logic.
    fitView();
  }, [fitView]);

  // --- Imperative API for parent components (search bar, question panel) ---
  useImperativeHandle(
    ref,
    () => ({
      revealBareNode(name, labels) {
        const cy = cyRef.current;
        if (!cy || cy.destroyed()) return;

        if (cy.getElementById(name).length > 0) {
          fitView(cy.getElementById(name));
          return;
        }

        const rootExists = cy.getElementById(ROOT_NAME).length > 0;
        const anchorPos = rootExists
          ? cy.getElementById(ROOT_NAME).position()
          : { x: 0, y: 0 };
        const angle = Math.random() * Math.PI * 2;
        const pos = {
          x: anchorPos.x + ORBIT_RADIUS * Math.cos(angle),
          y: anchorPos.y + ORBIT_RADIUS * Math.sin(angle),
        };

        cy.add({
          group: "nodes",
          data: { id: name, label: name, labels: labels || ["Concept"] },
          position: pos,
        });
        fitView();
      },

      async revealPath(pathData) {
        const cy = cyRef.current;
        if (!cy || cy.destroyed() || !pathData) return;

        const { nodes = [], relationships = [] } = pathData;

        nodes.forEach((nodeInfo, i) => {
          if (cy.getElementById(nodeInfo.name).length > 0) return;

          let anchorPos;
          if (i > 0 && cy.getElementById(nodes[i - 1].name).length > 0) {
            anchorPos = cy.getElementById(nodes[i - 1].name).position();
          } else if (cy.getElementById(ROOT_NAME).length > 0) {
            anchorPos = cy.getElementById(ROOT_NAME).position();
          } else {
            anchorPos = { x: 0, y: 0 };
          }
          const angle = Math.random() * Math.PI * 2;
          const pos = {
            x: anchorPos.x + ORBIT_RADIUS * Math.cos(angle),
            y: anchorPos.y + ORBIT_RADIUS * Math.sin(angle),
          };

          cy.add({
            group: "nodes",
            data: {
              id: nodeInfo.name,
              label: nodeInfo.name,
              labels: nodeInfo.labels,
            },
            position: pos,
          });
        });

        const highlightEdgeIds = [];
        relationships.forEach((rel, i) => {
          const a = nodes[i]?.name;
          const b = nodes[i + 1]?.name;
          if (!a || !b) return;
          const id1 = `${a}__${rel}__${b}`;
          const id2 = `${b}__${rel}__${a}`;
          if (cy.getElementById(id1).length > 0) {
            highlightEdgeIds.push(id1);
          } else if (cy.getElementById(id2).length > 0) {
            highlightEdgeIds.push(id2);
          } else {
            cy.add({
              group: "edges",
              data: { id: id1, source: a, target: b, relationship: rel },
            });
            highlightEdgeIds.push(id1);
          }
        });

        cy.elements().removeClass("highlighted");
        const nodeIds = nodes.map((n) => n.name);
        const highlighted = cy.nodes().filter((n) => nodeIds.includes(n.id()));
        highlighted.addClass("highlighted");
        highlightEdgeIds.forEach((id) => {
          const ele = cy.getElementById(id);
          if (ele.length > 0) ele.addClass("highlighted");
        });

        fitView(highlighted);
      },

      clearHighlight() {
        const cy = cyRef.current;
        if (!cy || cy.destroyed()) return;
        cy.elements().removeClass("highlighted");
      },

      refreshTheme() {
        // Cytoscape reads CSS variables into plain color strings once,
        // at style-function call time -- it doesn't watch for CSS
        // changes itself. When the light/dark toggle flips the
        // data-theme attribute, we re-apply the whole stylesheet so
        // every style function re-reads the now-current variable
        // values (background colors, text colors, etc).
        const cy = cyRef.current;
        if (!cy || cy.destroyed()) return;
        cy.style(cytoscapeStylesheet()).update();
      },
    }),
    [fitView]
  );

  useEffect(() => {
    const cy = cytoscape({
      container: containerRef.current,
      elements: startEmpty
        ? []
        : [
            {
              group: "nodes",
              data: { id: ROOT_NAME, label: ROOT_NAME, labels: ["Concept"] },
              position: { x: 0, y: 0 },
            },
          ],
      style: cytoscapeStylesheet(),
      wheelSensitivity: 0.25,
    });

    cyRef.current = cy;

    cy.on("tap", "node", (evt) => {
      const name = evt.target.id();
      expandNode(name);
    });

    // Double-click/double-tap collapses whatever this node's expansion
    // introduced -- the inverse gesture to single-click-to-expand.
    cy.on("dbltap", "node", (evt) => {
      const name = evt.target.id();
      collapseNode(name);
    });

    if (!startEmpty) {
      expandNode(ROOT_NAME);
    }

    return () => {
      cy.destroy();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="universe-graph">
      <div ref={containerRef} className="universe-graph__canvas" />
      {loadingNode && (
        <div className="universe-graph__status">Loading {loadingNode}…</div>
      )}
      {error && (
        <div className="universe-graph__status universe-graph__status--error">
          {error}
        </div>
      )}
      <div className="universe-graph__hint">
        {startEmpty
          ? "Search for a concept above to add it • double-click to collapse"
          : "Click a node to expand • double-click to collapse"}
      </div>
    </div>
  );
});

export default KnowledgeUniverse;

function computeArcPositions(parentPos, rootPos, count, isRoot) {
  if (count === 0) return [];

  const positions = [];

  if (isRoot) {
    for (let i = 0; i < count; i++) {
      const angle = (i / count) * Math.PI * 2;
      positions.push({
        x: parentPos.x + ORBIT_RADIUS * Math.cos(angle),
        y: parentPos.y + ORBIT_RADIUS * Math.sin(angle),
      });
    }
    return positions;
  }

  const dx = parentPos.x - rootPos.x;
  const dy = parentPos.y - rootPos.y;
  const dist = Math.sqrt(dx * dx + dy * dy);
  const outwardAngle = dist < 1 ? Math.random() * Math.PI * 2 : Math.atan2(dy, dx);

  const spread = Math.min(Math.PI * 0.9, 0.35 + count * 0.28);
  const startAngle = outwardAngle - spread / 2;

  for (let i = 0; i < count; i++) {
    const t = count === 1 ? 0.5 : i / (count - 1);
    const angle = startAngle + t * spread;
    positions.push({
      x: parentPos.x + ORBIT_RADIUS * Math.cos(angle),
      y: parentPos.y + ORBIT_RADIUS * Math.sin(angle),
    });
  }
  return positions;
}

function cytoscapeStylesheet() {
  const textColor = resolveCssVar("--text-primary", "#e7edf3");
  const chipBg = resolveCssVar("--bg-panel-raised", "#1a212b");
  const chipBorder = resolveCssVar("--border-subtle", "#232c37");
  const rootRingColor = resolveCssVar("--text-primary", "#e7edf3");

  return [
    {
      // Nodes are rendered as a small colored dot; the label lives
      // BELOW the node as its own background "chip" rather than being
      // squeezed inside the circle. This fixes two problems at once:
      // long names (e.g. "Authentication & Session Management") no
      // longer get clipped by a fixed-size circle, and the chip's own
      // background/border gives the text reliable contrast regardless
      // of the node's accent color or the active light/dark theme.
      selector: "node",
      style: {
        "background-fill": "radial-gradient",
        "background-gradient-stop-colors": (ele) => {
          const base = resolvedColorFor(ele.data("labels"));
          return `${lighten(base, 0.75)} ${lighten(base, 0.15)} ${base} ${darken(
            base,
            0.45
          )}`;
        },
        "background-gradient-stop-positions": "0% 25% 55% 100%",

        width: (ele) => (ele.data("id") === ROOT_NAME ? 48 : 32),
        height: (ele) => (ele.data("id") === ROOT_NAME ? 48 : 32),
        "border-width": (ele) => (ele.data("id") === ROOT_NAME ? 4 : 2),
        "border-opacity": (ele) => (ele.data("id") === ROOT_NAME ? 1 : 0.75),
        "border-color": (ele) =>
          ele.data("id") === ROOT_NAME
            ? rootRingColor
            // A darker (not lighter) rim reads as the shaded edge of a
            // glossy sphere -- real glass/glass-like objects darken at
            // the silhouette edge, with brightness concentrated toward
            // the center highlight instead.
            : darken(resolvedColorFor(ele.data("labels")), 0.35),

        label: "data(label)",
        color: textColor,
        "font-family": "IBM Plex Mono, monospace",
        "font-size": (ele) => (ele.data("id") === ROOT_NAME ? 13 : 11),
        "font-weight": 600,
        "text-valign": "bottom",
        "text-halign": "center",
        "text-margin-y": 8,
        "text-wrap": "wrap",
        "text-max-width": 110,
        "text-background-color": chipBg,
        "text-background-opacity": 0.95,
        "text-background-shape": "roundrectangle",
        "text-background-padding": 5,
        "text-border-width": 1,
        "text-border-color": chipBorder,
        "text-border-opacity": 1,
      },
    },
    {
      selector: "node.highlighted",
      style: {
        "border-width": 4,
        "border-color": "#f5c518",
        "text-border-color": "#f5c518",
        "text-border-width": 2,
        "z-index": 999,
      },
    },
    {
      // Applied to nodes/edges at the moment they're created, instead
      // of an inline `style` bypass -- Cytoscape recommends classes
      // over creation-time style bypasses for exactly this kind of
      // "starts hidden, then animates in" case.
      selector: ".growing-in",
      style: { opacity: 0 },
    },
    {
      selector: "edge",
      style: {
        width: 1.5,
        "line-color": (ele) => resolvedRelColor(ele.data("relationship")),
        "curve-style": "bezier",
        label: "data(relationship)",
        "font-family": "IBM Plex Mono, monospace",
        "font-size": 8,
        color: resolveCssVar("--text-dim", "#8a97a5"),
        "text-rotation": "autorotate",
        "text-background-color": resolveCssVar("--bg-app", "#0d1117"),
        "text-background-opacity": 0.85,
        "text-background-padding": 2,
      },
    },
    {
      selector: "edge.highlighted",
      style: {
        width: 3.5,
        "line-color": "#f5c518",
        "z-index": 998,
      },
    },
  ];
}
