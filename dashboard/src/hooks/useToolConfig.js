import { useCallback, useEffect, useMemo, useState } from "react";
import { TOOLS } from "../lib/toolDefaults.js";

const STORAGE_KEY = "gordian.toolConfig.v1";

const initialState = () =>
  Object.fromEntries(TOOLS.map((t) => [t.id, { ...t.defaults }]));

const load = () => {
  if (typeof window === "undefined") return initialState();
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return initialState();
    const parsed = JSON.parse(raw);
    // Merge against defaults so newly-added fields get sane values without
    // wiping the operator's saved preferences.
    return Object.fromEntries(
      TOOLS.map((t) => [t.id, { ...t.defaults, ...(parsed[t.id] ?? {}) }])
    );
  } catch {
    return initialState();
  }
};

/**
 * Persisted, per-tool configuration store. Returns a flat API:
 *   state[toolId]                — current values
 *   set(toolId, key, value)      — patch one field
 *   patch(toolId, partial)       — patch many fields at once (presets)
 *   reset(toolId?)               — defaults for one tool, or all if omitted
 */
export function useToolConfig() {
  const [state, setState] = useState(load);

  useEffect(() => {
    if (typeof window === "undefined") return;
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    } catch {
      /* quota — ignore */
    }
  }, [state]);

  const set = useCallback((toolId, key, value) => {
    setState((prev) => ({
      ...prev,
      [toolId]: { ...prev[toolId], [key]: value },
    }));
  }, []);

  const patch = useCallback((toolId, partial) => {
    setState((prev) => ({
      ...prev,
      [toolId]: { ...prev[toolId], ...partial },
    }));
  }, []);

  const reset = useCallback((toolId) => {
    if (!toolId) {
      setState(initialState());
      return;
    }
    const def = TOOLS.find((t) => t.id === toolId)?.defaults;
    if (def) setState((prev) => ({ ...prev, [toolId]: { ...def } }));
  }, []);

  const enabledTools = useMemo(
    () =>
      TOOLS.filter((t) => t.id !== "global" && t.id !== "engine").filter(
        (t) => state[t.id]?.enabled
      ),
    [state]
  );

  return { state, set, patch, reset, enabledTools };
}
