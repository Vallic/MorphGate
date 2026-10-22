/** Puts `text` on the clipboard: through the Clipboard API, else the older copy command (WebKit
 * refuses the first where it doesn't count the click as the person's, or without a permission).
 * False when neither worked, so the button can say so instead of nothing happening. */
export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // The older way, below.
  }
  const area = document.createElement("textarea");
  area.value = text;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.appendChild(area);
  area.select();
  try {
    return document.execCommand("copy");
  } catch {
    return false;
  } finally {
    area.remove();
  }
}
