/**
 * Appearance + layout presets. The theme system writes these into CSS
 * custom properties on <html data-theme>, so any panel reading from
 * var(--accent) etc. picks the change up instantly.
 */

export const ACCENTS = [
  { id: "cyan", label: "Cyan",   hex: "#22d3ee", rgb: "34 211 238",  glow: "rgba(34,211,238,0.55)"  },
  { id: "neon", label: "Neon",   hex: "#39ff7e", rgb: "57 255 126",  glow: "rgba(57,255,126,0.55)"  },
  { id: "amber",label: "Amber",  hex: "#fb923c", rgb: "251 146 60",  glow: "rgba(251,146,60,0.55)"  },
  { id: "blood",label: "Blood",  hex: "#ef4444", rgb: "239 68 68",   glow: "rgba(239,68,68,0.55)"   },
  { id: "violet",label:"Violet", hex: "#a855f7", rgb: "168 85 247",  glow: "rgba(168,85,247,0.55)"  },
  { id: "gold", label: "Gold",   hex: "#facc15", rgb: "250 204 21",  glow: "rgba(250,204,21,0.55)"  },
];

export const FONTS = [
  { id: "jetbrains", label: "JetBrains Mono", stack: '"JetBrains Mono", "Menlo", monospace' },
  { id: "fira",      label: "Fira Code",      stack: '"Fira Code", "Menlo", monospace' },
  { id: "ibm",       label: "IBM Plex Mono",  stack: '"IBM Plex Mono", "Menlo", monospace' },
  { id: "ubuntu",    label: "Ubuntu Mono",    stack: '"Ubuntu Mono", "Menlo", monospace' },
  { id: "system",    label: "System Mono",    stack: 'ui-monospace, "Menlo", monospace' },
];

export const DENSITIES = [
  { id: "compact",     label: "Compact",     scale: 0.92, padding: "0.5rem" },
  { id: "normal",      label: "Normal",      scale: 1.00, padding: "0.75rem" },
  { id: "comfortable", label: "Comfortable", scale: 1.08, padding: "1rem" },
];

export const MOTION = [
  { id: "full",    label: "Full"    },
  { id: "reduced", label: "Reduced" },
  { id: "off",     label: "Off"     },
];

export const BG_TEXTURES = [
  { id: "grid",      label: "Grid"      },
  { id: "scanlines", label: "Scanlines" },
  { id: "noise",     label: "Noise"     },
  { id: "none",      label: "None"      },
];

export const APPEARANCE = {
  id: "appearance",
  label: "Appearance",
  blurb: "Theme · font · motion · effects",
  defaults: {
    accent: "cyan",
    font: "jetbrains",
    density: "normal",
    motion: "full",
    background: "grid",
    crt: true,
    scanlines: true,
    glow: true,
    glowStrength: 60,
    radius: 0,
    showFooter: true,
    showHud: true,
    statusChipFlash: true,
  },
  presets: [
    { name: "Default",   patch: { accent: "cyan",   font: "jetbrains", density: "normal",  motion: "full",    background: "grid",      crt: true,  scanlines: true,  glow: true,  glowStrength: 60 } },
    { name: "Brutalist", patch: { accent: "neon",   font: "ibm",       density: "compact", motion: "reduced", background: "none",      crt: false, scanlines: false, glow: false, glowStrength: 0  } },
    { name: "VHS",       patch: { accent: "violet", font: "ubuntu",    density: "normal",  motion: "full",    background: "scanlines", crt: true,  scanlines: true,  glow: true,  glowStrength: 90 } },
    { name: "Halon",     patch: { accent: "blood",  font: "fira",      density: "comfortable", motion: "full", background: "noise",   crt: true,  scanlines: false, glow: true,  glowStrength: 75 } },
    { name: "Daylight",  patch: { accent: "amber",  font: "jetbrains", density: "comfortable", motion: "reduced", background: "none", crt: false, scanlines: false, glow: false, glowStrength: 20 } },
  ],
};

export const LAYOUT = {
  id: "layout",
  label: "Layout",
  blurb: "Panel order · visibility · sizing",
  defaults: {
    panels: ["mission", "stream", "remediation", "graph"],
    visible: { mission: true, stream: true, remediation: true, graph: true },
    streamCols: 7,           // 1..12
    remediationCols: 5,      // 1..12
    graphFull: true,         // false → side-by-side with table
    streamHeight: 460,
    graphHeight: 360,
    showHeader: true,
    showFooter: true,
    bootSplash: true,
  },
  presets: [
    { name: "Default",       patch: { panels: ["mission","stream","remediation","graph"], visible: { mission:true, stream:true, remediation:true, graph:true }, streamCols: 7, remediationCols: 5, graphFull: true } },
    { name: "Stream-Heavy",  patch: { streamCols: 9, remediationCols: 3, graphFull: true, streamHeight: 560 } },
    { name: "Graph-Focus",   patch: { panels: ["mission","graph","stream","remediation"], graphFull: true, graphHeight: 520 } },
    { name: "Patch Triage",  patch: { streamCols: 4, remediationCols: 8, graphFull: true } },
    { name: "Minimal",       patch: { visible: { mission: false, stream: true, remediation: true, graph: false }, showFooter: false } },
  ],
};

const RADIUS_MAP = { sharp: "0px", soft: "2px", round: "6px" };

/**
 * Side-effect: writes the chosen palette into :root CSS vars. Idempotent.
 */
export function applyAppearance(a) {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  const accent = ACCENTS.find((x) => x.id === a.accent) ?? ACCENTS[0];
  const font   = FONTS.find((x) => x.id === a.font) ?? FONTS[0];
  const density = DENSITIES.find((x) => x.id === a.density) ?? DENSITIES[1];

  root.style.setProperty("--accent", accent.hex);
  root.style.setProperty("--accent-rgb", accent.rgb);
  root.style.setProperty("--accent-glow", accent.glow);
  root.style.setProperty("--font-mono", font.stack);
  root.style.setProperty("--density-scale", String(density.scale));
  root.style.setProperty("--density-pad", density.padding);
  root.style.setProperty(
    "--glow-strength",
    String((a.glow ? a.glowStrength : 0) / 100)
  );
  root.style.setProperty(
    "--radius",
    typeof a.radius === "number" ? `${a.radius}px` : RADIUS_MAP[a.radius] ?? "0px"
  );

  root.dataset.motion = a.motion;
  root.dataset.background = a.background;
  root.dataset.crt = a.crt ? "on" : "off";
  root.dataset.scanlines = a.scanlines ? "on" : "off";
  root.dataset.statusflash = a.statusChipFlash ? "on" : "off";
  root.dataset.accent = a.accent;
}
