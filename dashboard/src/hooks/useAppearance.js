import { useEffect } from "react";
import { applyAppearance } from "../lib/appearancePresets.js";

/**
 * Reflects the appearance config onto :root CSS vars whenever it changes.
 * Mounted once at the app shell — no per-render cost beyond style writes.
 */
export function useAppearanceSync(appearance) {
  useEffect(() => {
    if (appearance) applyAppearance(appearance);
  }, [appearance]);
}
