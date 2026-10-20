import { useEffect, useState } from "react";

/** Android and iOS builds (the webview's user agent says which), apart from iPads: iPadOS's web
 * view says it's a Mac, and iPads get the desktop layout. */
export const onPhone = /Android|iPhone|iPad|iPod/i.test(navigator.userAgent);

/** Android and iOS builds, iPads included (a Mac has no touch points). What these can't do: run
 * programs, update themselves. And what they don't do: sell. Plans are bought on the website,
 * and the app doesn't point there: store builds don't link to buying outside the store (App
 * Store 3.1.3, Google Play's payments policy). */
export const mobileOs = onPhone || iPadAsMac();

/** iPhones and iPads. The iOS app names no other mobile platform (App Store 2.3.10). */
export const onIos = /iPhone|iPad|iPod/.test(navigator.userAgent) || iPadAsMac();

function iPadAsMac(): boolean {
  return /Macintosh/.test(navigator.userAgent) && navigator.maxTouchPoints > 1;
}

const NARROW = "(max-width: 640px)";

/** Whether the window is as narrow as a phone. */
export function useNarrow(): boolean {
  const [narrow, setNarrow] = useState(() => matchMedia(NARROW).matches);
  useEffect(() => {
    const m = matchMedia(NARROW);
    const changed = () => setNarrow(m.matches);
    m.addEventListener("change", changed);
    return () => m.removeEventListener("change", changed);
  }, []);
  return narrow;
}

/** The phone layout: on Android and iOS, and in a desktop window narrower than a phone's. */
export function useMobile(): boolean {
  return useNarrow() || onPhone;
}

/** "14 min", "2 h", "3 d": how long a session has been open. */
export function since(ms: number): string {
  const min = Math.max(0, Math.floor((Date.now() - ms) / 60_000));
  if (min < 60) return `${min} min`;
  if (min < 48 * 60) return `${Math.floor(min / 60)} h`;
  return `${Math.floor(min / (24 * 60))} d`;
}
