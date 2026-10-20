import type { ITheme } from "@xterm/xterm";

/** Terminal colors: what the vault keeps for an imported theme, and what a built-in one defines. */
export interface ThemeColors {
  name: string;
  background: string;
  foreground: string;
  cursor: string;
  /** The character under a block cursor. */
  cursorAccent: string;
  selectionBackground: string;
  /** null: a selection keeps the text's colors. */
  selectionForeground?: string | null;
  /** black, red, green, yellow, blue, magenta, cyan, white, then the same eight bright. */
  ansi: string[];
}

export interface BuiltinTheme extends ThemeColors {
  /** What hosts and settings store to name it: `builtin:<slug>`. Never changes once released. */
  id: string;
  /** "Brand dark", "High contrast", … */
  style: string;
  /** When to use it. */
  mood: string;
  /** xterm.js `minimumContrastRatio`: colors too close to the background are adjusted to it. */
  minimumContrast: number;
}

/**
 * The seven schemes from the MorphGate Brand design system (`terminal-schemes.json`). Every ANSI
 * color except black reaches the scheme's minimum contrast against its background. The 256-color
 * cube and grey ramp keep their xterm values; 24-bit color passes through.
 */
export const BUILTIN_THEMES: BuiltinTheme[] = [
  {
    id: "builtin:console",
    name: "Console",
    style: "Brand dark",
    mood: "The default. Petrol-black canvas, mint prompt, amber block cursor.",
    background: "#0a1113",
    foreground: "#dce6e3",
    cursor: "#ffb547",
    cursorAccent: "#0a1113",
    selectionBackground: "#12362f",
    minimumContrast: 4.5,
    ansi: ["#0a1113", "#ff6b6b", "#3ddbb6", "#ffb547", "#6cb6ff", "#d59cff", "#4fd1e8", "#dce6e3", "#5e7072", "#ff9494", "#7bebd0", "#ffcc80", "#9dcfff", "#e6c2ff", "#8ae4f2", "#ffffff"],
  },
  {
    id: "builtin:greenbar",
    name: "Greenbar",
    style: "Brand light",
    mood: "Printer-paper canvas for bright rooms and screen shares. Every color darkened to read on paper.",
    background: "#f2f5f1",
    foreground: "#0c1a1c",
    cursor: "#a86400",
    cursorAccent: "#f2f5f1",
    selectionBackground: "#d2f1e6",
    minimumContrast: 4.5,
    ansi: ["#0c1a1c", "#b42b28", "#0a7564", "#8a5600", "#1f5fad", "#8a3fb8", "#0b6e80", "#4a5c5c", "#66787a", "#9e2622", "#086452", "#754900", "#1a5094", "#76339e", "#095d6c", "#2b3a3b"],
  },
  {
    id: "builtin:phosphor",
    name: "Phosphor P1",
    style: "Retro monochrome",
    mood: "Green phosphor CRT. One hue; the 16 colors become 8 steps of brightness.",
    background: "#030a06",
    foreground: "#5df29e",
    cursor: "#5df29e",
    cursorAccent: "#030a06",
    selectionBackground: "#0e3320",
    minimumContrast: 4.5,
    ansi: ["#030a06", "#2e9e60", "#5df29e", "#9cf7c4", "#2a9258", "#47d184", "#7bf4b2", "#c2fadb", "#237a49", "#3db873", "#86f5b8", "#c4fbdc", "#2e9e60", "#5df29e", "#a6f8cb", "#e6fdf0"],
  },
  {
    id: "builtin:sodium",
    name: "Sodium P3",
    style: "Retro monochrome",
    mood: "Amber phosphor, the color of the cursor in the mark, for long night sessions.",
    background: "#0c0803",
    foreground: "#ffb547",
    cursor: "#ffb547",
    cursorAccent: "#0c0803",
    selectionBackground: "#3a2c12",
    minimumContrast: 4.5,
    ansi: ["#0c0803", "#b87a22", "#ffb547", "#ffd08a", "#a86f1e", "#e09a38", "#ffc36b", "#ffe3b8", "#8a5a18", "#d18c2c", "#ffc266", "#ffdda6", "#b87a22", "#ffb547", "#ffd699", "#fff3e0"],
  },
  {
    id: "builtin:bastion",
    name: "Bastion",
    style: "High contrast",
    mood: "Pure black and white with saturated colors, every one 7:1 or more. For low vision, glare and projectors.",
    background: "#000000",
    foreground: "#ffffff",
    cursor: "#ffd166",
    cursorAccent: "#000000",
    selectionBackground: "#1f4d44",
    minimumContrast: 7,
    ansi: ["#000000", "#ff8a8a", "#5cf2c8", "#ffd166", "#8cc4ff", "#e7a8ff", "#66e6ff", "#ffffff", "#a3b2b0", "#ffb0b0", "#9af7dd", "#ffe4a3", "#b8dbff", "#f1ccff", "#a3f0ff", "#ffffff"],
  },
  {
    id: "builtin:dusk",
    name: "Dusk",
    style: "Low glare",
    mood: "Lifted slate canvas and softened colors for eight-hour sessions. Lower contrast by design, still 4.5:1.",
    background: "#172024",
    foreground: "#c3cdca",
    cursor: "#e0b06e",
    cursorAccent: "#172024",
    selectionBackground: "#24423c",
    minimumContrast: 4.5,
    ansi: ["#172024", "#e39a98", "#7fcdb5", "#e0b87e", "#93b5dd", "#c2a9de", "#8cc8d2", "#c3cdca", "#7f9193", "#ecadab", "#98d9c5", "#eac897", "#a9c5e6", "#d0bce7", "#a4d5dd", "#e2e8e6"],
  },
  {
    id: "builtin:production",
    name: "Production",
    style: "Per-host warning",
    mood: "Console with a red-tinted canvas. Assign it to production hosts so the window itself says where you are.",
    background: "#1a0b0e",
    foreground: "#ecdadb",
    cursor: "#ff6b6b",
    cursorAccent: "#1a0b0e",
    selectionBackground: "#4a1f25",
    minimumContrast: 4.5,
    ansi: ["#1a0b0e", "#ff7a7a", "#3ddbb6", "#ffb547", "#7dbeff", "#dda6ff", "#5cd6ea", "#ecdadb", "#7a6366", "#ffa0a0", "#7bebd0", "#ffcc80", "#a6d4ff", "#ebc7ff", "#8fe6f3", "#ffffff"],
  },
];

/** The scheme that marks a host as production: its tabs also get a PROD label. */
export const PRODUCTION_THEME = "builtin:production";
/** What "follow the app theme" picks. */
export const APP_THEME_SCHEMES = { dark: "builtin:console", light: "builtin:greenbar" } as const;

export const DEFAULT_THEME = BUILTIN_THEMES[0].id;
/** The terminal's default face (bundled); then common coding fonts, then the system's. */
export const DEFAULT_FONT = '"Atkinson Hyperlegible Mono", "JetBrains Mono", "Fira Code", ui-monospace, monospace';

/** A theme by the id a host or the settings store, falling back to the default. */
export function findTheme(id: string | null | undefined, vaultThemes: (ThemeColors & { id: string })[]): ThemeColors {
  return (
    BUILTIN_THEMES.find((t) => t.id === id) ??
    vaultThemes.find((t) => t.id === id) ??
    BUILTIN_THEMES.find((t) => t.id === DEFAULT_THEME)!
  );
}

const ANSI_KEYS = [
  "black",
  "red",
  "green",
  "yellow",
  "blue",
  "magenta",
  "cyan",
  "white",
  "brightBlack",
  "brightRed",
  "brightGreen",
  "brightYellow",
  "brightBlue",
  "brightMagenta",
  "brightCyan",
  "brightWhite",
] as const;

/** The theme as xterm.js takes it. */
export function xtermTheme(t: ThemeColors): ITheme {
  const theme: ITheme = {
    background: t.background,
    foreground: t.foreground,
    cursor: t.cursor,
    cursorAccent: t.cursorAccent,
    selectionBackground: t.selectionBackground,
  };
  if (t.selectionForeground) theme.selectionForeground = t.selectionForeground;
  ANSI_KEYS.forEach((k, i) => (theme[k] = t.ansi[i]));
  return theme;
}
