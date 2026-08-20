export const LABEL_COLOR_VAR = {
  Attack: "--c-attack",
  Vulnerability: "--c-vulnerability",
  Defence: "--c-defence",
  Tool: "--c-tool",
  Concept: "--c-concept",
  Technology: "--c-technology",
  Asset: "--c-asset",
};

export function primaryLabel(labels) {
  if (!labels || labels.length === 0) return "Concept";
  return labels[0];
}

export function colorVarFor(labels) {
  const label = primaryLabel(labels);
  return LABEL_COLOR_VAR[label] || "--text-dim";
}

export function resolvedColorFor(labels) {
  const varName = colorVarFor(labels);
  if (typeof window === "undefined") return "#8a97a5";
  const styles = getComputedStyle(document.documentElement);
  const value = styles.getPropertyValue(varName).trim();
  return value || "#8a97a5";
}

/** Generic CSS-variable resolver, for anything not covered by the
 *  label/relationship-specific helpers above (e.g. text and border
 *  colors that need to follow the active light/dark theme). */
export function resolveCssVar(varName, fallback = "#8a97a5") {
  if (typeof window === "undefined") return fallback;
  const styles = getComputedStyle(document.documentElement);
  const value = styles.getPropertyValue(varName).trim();
  return value || fallback;
}

/**
 * Small hex color-mixing helpers, used to build the radial-gradient
 * "glass" effect on nodes: a lightened highlight near the center,
 * fading to the true accent color, darkened slightly at the rim.
 */
function hexToRgb(hex) {
  const clean = hex.replace("#", "");
  const full = clean.length === 3 ? clean.split("").map((c) => c + c).join("") : clean;
  const int = parseInt(full, 16);
  return { r: (int >> 16) & 255, g: (int >> 8) & 255, b: int & 255 };
}

function rgbToHex(r, g, b) {
  const clamp = (v) => Math.max(0, Math.min(255, Math.round(v)));
  return (
    "#" +
    [clamp(r), clamp(g), clamp(b)]
      .map((v) => v.toString(16).padStart(2, "0"))
      .join("")
  );
}

/** Mixes a hex color toward white by `amount` (0-1). */
export function lighten(hex, amount) {
  const { r, g, b } = hexToRgb(hex);
  return rgbToHex(
    r + (255 - r) * amount,
    g + (255 - g) * amount,
    b + (255 - b) * amount
  );
}

/** Mixes a hex color toward black by `amount` (0-1). */
export function darken(hex, amount) {
  const { r, g, b } = hexToRgb(hex);
  return rgbToHex(r * (1 - amount), g * (1 - amount), b * (1 - amount));
}

export const REL_COLOR_VAR = {
  EXPLOITS: "--c-attack",
  TARGETS: "--c-attack",
  MITIGATES: "--c-defence",
  TOOL_USED_FOR: "--c-tool",
  RELATED_TO: "--text-faint",
  LEARN_NEXT: "--c-concept",
  PREREQUISITE: "--c-concept",
};

export function resolvedRelColor(relationship) {
  const varName = REL_COLOR_VAR[relationship] || "--text-faint";
  if (typeof window === "undefined") return "#5a6672";
  const styles = getComputedStyle(document.documentElement);
  const value = styles.getPropertyValue(varName).trim();
  return value || "#5a6672";
}