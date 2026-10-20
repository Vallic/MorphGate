import { onPhone } from "./mobile/useMobile";

/** The desktop layout on a touch screen (iPad): a field focused by itself (autoFocus) brings up
 * the on-screen keyboard, which covers half the screen and moves the layout from under the next
 * tap (it takes two taps to hit anything). There, a field takes focus only from a tap on it (or
 * its label, or the terminal it belongs to) or from a key. The phone layout doesn't autofocus. */
export function focusOnlyByTouch() {
  if (onPhone || !matchMedia("(hover: none) and (pointer: coarse)").matches) return;
  let tapped: Element | null = null;
  let keyAt = 0;
  window.addEventListener("pointerdown", (e) => (tapped = e.target instanceof Element ? e.target : null), true);
  window.addEventListener("keydown", () => (keyAt = performance.now()), true);
  document.addEventListener(
    "focusin",
    (e) => {
      const field = e.target;
      if (!(field instanceof HTMLElement) || !field.matches("input, textarea, [contenteditable='true']")) return;
      const scope = tapped?.closest("label, .xterm") ?? tapped;
      const byTap = scope?.contains(field) ?? false;
      if (!byTap && performance.now() - keyAt > 1000) field.blur();
    },
    true,
  );
}
