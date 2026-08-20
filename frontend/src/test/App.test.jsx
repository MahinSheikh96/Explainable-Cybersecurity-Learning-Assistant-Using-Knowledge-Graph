import { describe, it, expect, vi } from "vitest";
import { act } from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import App from "../App";

/**
 * App.test.jsx
 * ------------
 * A "smoke test", not a full end-to-end test: it confirms the app
 * mounts without crashing and that the core interactive elements
 * (mode toggle, search bar, path finder, question panel, theme
 * toggle) render and respond to basic interaction.
 *
 * Two things are deliberately mocked out rather than tested for real:
 *
 * 1. Cytoscape itself -- it renders to an HTML <canvas>, which jsdom
 *    (the fake browser this test runs in) doesn't support well enough
 *    to meaningfully test. We replace it with a minimal fake that
 *    satisfies the methods KnowledgeUniverse calls, so the component
 *    can mount without throwing, without actually testing Cytoscape's
 *    own rendering (that's Cytoscape's job to test, not ours).
 *
 * 2. The API layer (api.js) -- this is a smoke test, not an
 *    integration test, so it doesn't hit a real backend. Every
 *    exported function resolves instantly with a plausible shape.
 *    (Phase 8's backend suite, test_main.py, is what actually tests
 *    real endpoint behavior against real Neo4j data.)
 *
 * Every render() is wrapped in `await act(async () => {...})` so that
 * the promises KnowledgeUniverse/QuestionPanel kick off on mount
 * (fetchNode, fetchQuestions) resolve and settle before assertions
 * run -- without this, React logs "not wrapped in act" warnings even
 * though the tests still pass.
 */

vi.mock("cytoscape", () => {
  const makeFakeElement = () => ({
    length: 0,
    position: () => ({ x: 0, y: 0 }),
    animate: vi.fn(),
    removeClass: vi.fn(),
    addClass: vi.fn(),
    isEdge: () => false,
    remove: vi.fn(),
  });

  const fakeCy = {
    on: vi.fn(),
    getElementById: vi.fn(() => makeFakeElement()),
    add: vi.fn(() => ({
      filter: () => ({ animate: vi.fn(), removeClass: vi.fn() }),
    })),
    elements: vi.fn(() => ({ removeClass: vi.fn() })),
    nodes: vi.fn(() => ({ filter: () => ({ addClass: vi.fn(), length: 0 }) })),
    layout: vi.fn(() => ({ run: vi.fn() })),
    animate: vi.fn(),
    style: vi.fn(() => ({ update: vi.fn() })),
    destroy: vi.fn(),
    destroyed: () => false,
  };

  return { default: vi.fn(() => fakeCy) };
});

vi.mock("../api", () => ({
  fetchNode: vi.fn(() =>
    Promise.resolve({
      name: "Cybersecurity",
      labels: ["Concept"],
      description: "The root topic.",
      neighbours: [],
    })
  ),
  fetchChildren: vi.fn(() => Promise.resolve({ children: [] })),
  fetchDefenses: vi.fn(() => Promise.resolve({ defenses: [] })),
  fetchTools: vi.fn(() => Promise.resolve({ tools: [] })),
  fetchRelated: vi.fn(() => Promise.resolve({ related: [] })),
  fetchPath: vi.fn(() => Promise.resolve({ nodes: [], relationships: [] })),
  fetchQuestions: vi.fn(() =>
    Promise.resolve({ questions: [{ id: "q1", text: "Sample question?" }] })
  ),
  askQuestion: vi.fn(() =>
    Promise.resolve({
      explanation: "Sample explanation.",
      trace: "A -> RELATES -> B",
      path: { nodes: [], relationships: [] },
    })
  ),
  searchNodes: vi.fn(() => Promise.resolve({ results: [] })),
}));

/** Renders <App /> and flushes any pending microtasks from mount-time fetches. */
async function renderApp() {
  await act(async () => {
    render(<App />);
  });
}

describe("App smoke test", () => {
  it("renders the header title", async () => {
    await renderApp();
    expect(screen.getByText("Cybersecurity Knowledge Graph")).toBeInTheDocument();
  });

  it("renders both mode toggle buttons", async () => {
    await renderApp();
    expect(screen.getByRole("button", { name: "Guided Mode" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Free-Flow Mode" })).toBeInTheDocument();
  });

  it("shows the search bar only after switching to Free-Flow Mode", async () => {
    await renderApp();
    expect(screen.queryByPlaceholderText(/Search any concept/i)).not.toBeInTheDocument();

    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Free-Flow Mode" }));
    });

    expect(screen.getByPlaceholderText(/Search any concept/i)).toBeInTheDocument();
  });

  it("opens the Path Finder panel and shows From/To fields", async () => {
    await renderApp();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /Find a path/i }));
    });

    expect(screen.getByText("From")).toBeInTheDocument();
    expect(screen.getByText("To")).toBeInTheDocument();
  });

  it("loads premade questions into the dropdown", async () => {
    await renderApp();
    await waitFor(() => {
      expect(screen.getByText("Sample question?")).toBeInTheDocument();
    });
  });

  it("toggles the theme attribute on the document root", async () => {
    await renderApp();
    const before = document.documentElement.getAttribute("data-theme");

    const themeButton = screen.getByTitle(/Switch to (light|dark) mode/i);
    await act(async () => {
      fireEvent.click(themeButton);
    });

    const after = document.documentElement.getAttribute("data-theme");
    expect(after).not.toBe(before);
  });

  it("auto-selects the root node on initial load", async () => {
    // Guided Mode calls expandNode(ROOT_NAME) on mount, which also
    // fires onSelect -- so the detail panel shows Cybersecurity's
    // details immediately, rather than the "click a node" placeholder.
    await renderApp();
    expect(screen.getByText("Cybersecurity")).toBeInTheDocument();
    expect(screen.getByText("The root topic.")).toBeInTheDocument();
  });
});
