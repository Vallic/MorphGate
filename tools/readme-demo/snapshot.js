// Runs in the app's page (demo.mjs passes it over WebDriver): what the window shows, as shapes to
// draw: boxes (backgrounds, borders, inset underlines), text where the layout put it, and the
// page's own SVG icons. `mask` swaps text (the test machine's user and address for demo ones).
// The terminal's text isn't taken: the recording replays there (its geometry is returned).
// eslint-disable-next-line no-unused-vars
function snapshot(mask) {
  const boxes = [];
  const texts = [];
  const icons = [];
  let terminal = null;
  const view = { x: 0, y: 0, w: innerWidth, h: innerHeight };
  const clear = (c) => !c || c === "transparent" || /rgba\([^)]*,\s*0\)$/.test(c);
  const swap = (t) => mask.reduce((s, [from, to]) => s.split(from).join(to), t);
  const meet = (a, b) => {
    const x = Math.max(a.x, b.x);
    const y = Math.max(a.y, b.y);
    return { x, y, w: Math.max(0, Math.min(a.x + a.w, b.x + b.w) - x), h: Math.max(0, Math.min(a.y + a.h, b.y + b.h) - y) };
  };
  const rectOf = (r) => ({ x: r.left, y: r.top, w: r.width, h: r.height });
  const font = (cs) => ({
    family: cs.fontFamily,
    size: parseFloat(cs.fontSize),
    weight: cs.fontWeight,
    style: cs.fontStyle,
    spacing: cs.letterSpacing === "normal" ? 0 : parseFloat(cs.letterSpacing),
    color: cs.color,
    opacity: 1,
  });
  const cased = (t, cs) => (cs.textTransform === "uppercase" ? t.toUpperCase() : cs.textTransform === "lowercase" ? t.toLowerCase() : t);

  /** A line of text at `r`, clipped to `clip`; cut with an ellipsis where the element does.
   * `color` overrides the element's (a placeholder's). */
  function text(str, r, cs, clip, ellipsis, color) {
    if (!str.trim() || r.width === 0) return;
    let t = cased(swap(str), cs);
    let w = r.width;
    const right = clip.x + clip.w;
    if (ellipsis && r.right > right + 1) {
      const per = r.width / t.length;
      const fit = Math.max(0, Math.floor((right - r.left) / per) - 1);
      t = `${t.slice(0, fit).trimEnd()}…`;
      w = per * t.length;
    }
    const f = font(cs);
    texts.push({ text: t, x: r.left, y: r.top, w, h: r.height, clip, ...f, color: color ?? f.color });
  }

  /** The page's SVG with each shape's computed paint written on it (the app styles its marks by
   * class), `currentColor` resolved. */
  function paint(svg) {
    const copy = svg.cloneNode(true);
    const from = [svg, ...svg.querySelectorAll("*")];
    const to = [copy, ...copy.querySelectorAll("*")];
    from.forEach((el, i) => {
      const cs = getComputedStyle(el);
      for (const p of ["fill", "stroke", "stroke-width", "stroke-linecap", "stroke-linejoin", "fill-opacity", "stroke-opacity"]) {
        const v = cs.getPropertyValue(p);
        if (v) to[i].setAttribute(p, v);
      }
      to[i].removeAttribute("class");
      to[i].removeAttribute("style");
    });
    return copy.outerHTML;
  }

  function walk(el, clip, opacity) {
    const cs = getComputedStyle(el);
    if (cs.display === "none" || cs.visibility === "hidden") return;
    const op = opacity * parseFloat(cs.opacity);
    if (op === 0) return;
    const r = el.getBoundingClientRect();
    const box = rectOf(r);
    const inner = /(hidden|auto|scroll|clip)/.test(`${cs.overflowX} ${cs.overflowY}`) ? meet(clip, box) : clip;

    if (el.classList?.contains("xterm-screen")) {
      const rows = el.querySelector(".xterm-rows");
      const rcs = getComputedStyle(rows ?? el);
      terminal = { ...box, family: rcs.fontFamily, size: parseFloat(rcs.fontSize) };
      return;
    }
    if (el instanceof SVGSVGElement) {
      // Turned by CSS (a chevron pointing down), on it or the span around it: about its middle.
      const turns = [el, el.parentElement].map((e) => getComputedStyle(e).transform).filter((t) => t && t !== "none");
      if (box.w && box.h) icons.push({ svg: paint(el), ...box, color: cs.color, clip, opacity: op, turns });
      return;
    }
    if (box.w > 0 && box.h > 0) {
      const radius = parseFloat(cs.borderTopLeftRadius) || 0;
      if (!clear(cs.backgroundColor)) boxes.push({ ...box, fill: cs.backgroundColor, radius, clip, opacity: op });
      const sides = ["Top", "Right", "Bottom", "Left"].map((s) => ({
        s,
        w: cs[`border${s}Style`] === "none" ? 0 : parseFloat(cs[`border${s}Width`]),
        c: cs[`border${s}Color`],
      }));
      const all = sides.every((x) => x.w === sides[0].w && x.c === sides[0].c);
      if (all && sides[0].w > 0 && !clear(sides[0].c)) {
        boxes.push({ ...box, stroke: sides[0].c, strokeWidth: sides[0].w, radius, clip, opacity: op });
      } else {
        for (const { s, w, c } of sides) {
          if (!w || clear(c)) continue;
          const at = { Top: [0, 0, box.w, w], Bottom: [0, box.h - w, box.w, w], Left: [0, 0, w, box.h], Right: [box.w - w, 0, w, box.h] }[s];
          boxes.push({ x: box.x + at[0], y: box.y + at[1], w: at[2], h: at[3], fill: c, radius: 0, clip, opacity: op });
        }
      }
      // An inset shadow without blur: a bar along one side (the active tab's underline).
      for (const m of cs.boxShadow.matchAll(/(rgba?\([^)]*\))\s+(-?[\d.]+)px\s+(-?[\d.]+)px\s+0px(?:\s+0px)?\s+inset/g)) {
        const [, c, dx, dy] = m;
        const x = +dx;
        const y = +dy;
        if (y < 0) boxes.push({ x: box.x, y: box.y + box.h + y, w: box.w, h: -y, fill: c, radius: 0, clip, opacity: op });
        if (y > 0) boxes.push({ x: box.x, y: box.y, w: box.w, h: y, fill: c, radius: 0, clip, opacity: op });
        if (x > 0) boxes.push({ x: box.x, y: box.y, w: x, h: box.h, fill: c, radius: 0, clip, opacity: op });
        if (x < 0) boxes.push({ x: box.x + box.w + x, y: box.y, w: -x, h: box.h, fill: c, radius: 0, clip, opacity: op });
      }
    }
    // A field's value, or its placeholder.
    if (el instanceof HTMLInputElement && el.type !== "checkbox" && el.type !== "radio") {
      const value = el.value || el.placeholder;
      if (value) {
        const pad = parseFloat(cs.paddingLeft) + parseFloat(cs.borderLeftWidth);
        const color = el.value ? cs.color : getComputedStyle(el, "::placeholder").color || cs.color;
        // Its width as the page's font has it.
        const ctx = (snapshot.canvas ??= document.createElement("canvas")).getContext("2d");
        ctx.font = `${cs.fontStyle} ${cs.fontWeight} ${cs.fontSize} ${cs.fontFamily}`;
        const width = ctx.measureText(value).width;
        text(value, { left: box.x + pad, top: box.y, width, height: box.h, right: box.x + pad + width }, cs, meet(inner, box), false, color);
      }
      return;
    }
    const ellipsis = cs.textOverflow === "ellipsis";
    for (const n of el.childNodes) {
      if (n.nodeType === Node.TEXT_NODE) {
        if (!n.textContent.trim()) continue;
        const range = document.createRange();
        range.selectNodeContents(n);
        const lines = [...range.getClientRects()];
        if (lines.length <= 1) {
          if (lines[0]) text(n.textContent.replace(/\s+/g, " ").trim(), lines[0], cs, inner, ellipsis);
          continue;
        }
        // Wrapped: a word at a time, gathered into its lines.
        const words = [...n.textContent.matchAll(/\S+/g)].map((w) => {
          range.setStart(n, w.index);
          range.setEnd(n, w.index + w[0].length);
          return { t: w[0], r: range.getBoundingClientRect() };
        });
        const rows = [];
        for (const w of words) {
          const row = rows.find((x) => Math.abs(x.top - w.r.top) < 2);
          if (row) {
            row.t += ` ${w.t}`;
            row.right = w.r.right;
          } else rows.push({ t: w.t, top: w.r.top, left: w.r.left, right: w.r.right, height: w.r.height });
        }
        for (const row of rows) text(row.t, { left: row.left, top: row.top, width: row.right - row.left, height: row.height, right: row.right }, cs, inner, ellipsis);
      } else if (n.nodeType === Node.ELEMENT_NODE) {
        walk(n, inner, op);
      }
    }
  }
  walk(document.body, view, 1);
  const bg = getComputedStyle(document.body).backgroundColor;
  return { width: innerWidth, height: innerHeight, background: bg, boxes, texts, icons, terminal };
}
