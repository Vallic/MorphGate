// Split panes: several sessions side by side in one tab. A tab's layout is a tree: a pane (a
// session's tab key), or panes in a row (side by side) or a column (one below the other), each
// taking its share of the space. Every terminal stays mounted where it is; the layout only
// places it (in percent of the workspace), so splitting or closing a pane never drops a session.

export type Layout = { pane: number } | { dir: "row" | "column"; parts: Layout[]; sizes: number[] };

export interface Split {
  layout: Layout;
  /** Keystrokes typed in one pane go to every pane. */
  broadcast: boolean;
  /** The pane last used: the tab reopens on it. */
  focus: number;
}

/** In percent of the workspace. */
export interface Rect {
  left: number;
  top: number;
  width: number;
  height: number;
}

/** A pane can't be made smaller than this share of its row or column. */
const MIN = 0.1;

export const panes = (l: Layout): number[] => ("pane" in l ? [l.pane] : l.parts.flatMap(panes));

export const holds = (l: Layout, key: number) => panes(l).includes(key);

/** `at` split in `dir` with a new pane `key` after it (beside it in a row, below it in a column). */
export function addPane(l: Layout, at: number, key: number, dir: "row" | "column"): Layout {
  if ("pane" in l) {
    return l.pane === at ? { dir, parts: [l, { pane: key }], sizes: [0.5, 0.5] } : l;
  }
  const i = l.parts.findIndex((p) => "pane" in p && p.pane === at);
  // Splitting along the row or column it's in: a sibling, with half of `at`'s share.
  if (i >= 0 && l.dir === dir) {
    const half = l.sizes[i] / 2;
    return {
      dir,
      parts: [...l.parts.slice(0, i + 1), { pane: key }, ...l.parts.slice(i + 1)],
      sizes: [...l.sizes.slice(0, i), half, half, ...l.sizes.slice(i + 1)],
    };
  }
  return { ...l, parts: l.parts.map((p) => addPane(p, at, key, dir)) };
}

/** The layout without pane `key`: its share goes to its neighbours, a lone part takes its
 * parent's place. `null` when nothing is left. */
export function removePane(l: Layout, key: number): Layout | null {
  if ("pane" in l) return l.pane === key ? null : l;
  const kept: Layout[] = [];
  const sizes: number[] = [];
  l.parts.forEach((p, i) => {
    const next = removePane(p, key);
    if (next) {
      kept.push(next);
      sizes.push(l.sizes[i]);
    }
  });
  if (kept.length === 0) return null;
  if (kept.length === 1) return kept[0];
  const total = sizes.reduce((a, b) => a + b, 0);
  return { dir: l.dir, parts: kept, sizes: sizes.map((s) => s / total) };
}

/** Where each pane goes. */
export function rects(l: Layout, box: Rect = { left: 0, top: 0, width: 100, height: 100 }, out = new Map<number, Rect>()) {
  if ("pane" in l) {
    out.set(l.pane, box);
    return out;
  }
  let offset = 0;
  l.parts.forEach((p, i) => {
    const share = l.sizes[i];
    const part =
      l.dir === "row"
        ? { left: box.left + box.width * offset, top: box.top, width: box.width * share, height: box.height }
        : { left: box.left, top: box.top + box.height * offset, width: box.width, height: box.height * share };
    rects(p, part, out);
    offset += share;
  });
  return out;
}

/** A border between two parts that can be dragged: `path` leads to the split (indexes into
 * `parts`), `index` is the part before it. `box` is the split's own area. */
export interface Divider {
  path: number[];
  index: number;
  dir: "row" | "column";
  /** Its position along the split, in percent of the workspace. */
  at: number;
  box: Rect;
}

export function dividers(l: Layout, box: Rect = { left: 0, top: 0, width: 100, height: 100 }, path: number[] = [], out: Divider[] = []): Divider[] {
  if ("pane" in l) return out;
  let offset = 0;
  l.parts.forEach((p, i) => {
    const share = l.sizes[i];
    const part =
      l.dir === "row"
        ? { left: box.left + box.width * offset, top: box.top, width: box.width * share, height: box.height }
        : { left: box.left, top: box.top + box.height * offset, width: box.width, height: box.height * share };
    dividers(p, part, [...path, i], out);
    offset += share;
    if (i < l.parts.length - 1) {
      out.push({ path, index: i, dir: l.dir, at: l.dir === "row" ? box.left + box.width * offset : box.top + box.height * offset, box });
    }
  });
  return out;
}

/** Moves divider `d` to `at` (percent of the workspace along its direction), keeping both parts
 * at least MIN of their split. */
export function moveDivider(l: Layout, d: Divider, at: number): Layout {
  if ("pane" in l) return l;
  if (d.path.length > 0) {
    const [head, ...rest] = d.path;
    return { ...l, parts: l.parts.map((p, i) => (i === head ? moveDivider(p, { ...d, path: rest }, at) : p)) };
  }
  const start = d.dir === "row" ? d.box.left : d.box.top;
  const length = d.dir === "row" ? d.box.width : d.box.height;
  const before = l.sizes.slice(0, d.index).reduce((a, b) => a + b, 0);
  const pair = l.sizes[d.index] + l.sizes[d.index + 1];
  const wanted = (at - start) / length - before;
  const first = Math.min(Math.max(wanted, MIN), pair - MIN);
  const sizes = [...l.sizes];
  sizes[d.index] = first;
  sizes[d.index + 1] = pair - first;
  return { ...l, sizes };
}
