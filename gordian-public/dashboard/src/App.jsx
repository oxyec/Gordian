import { useEffect, useState } from "react";
import BootScreen from "./components/BootScreen.jsx";
import Dashboard from "./components/Dashboard.jsx";

const BOOT_FLAG = "gordian.boot.skipped";
const TOOL_KEY  = "gordian.toolConfig.v1";

/**
 * App shell — gates the dashboard behind a one-time boot splash per session.
 * Skip-state is held in sessionStorage so a hot-reload during dev doesn't
 * force you through the splash again. The splash can also be permanently
 * disabled via Config → Layout → bootSplash.
 */
export default function App() {
  const [booted, setBooted] = useState(() => {
    if (typeof window === "undefined") return true;
    if (window.sessionStorage.getItem(BOOT_FLAG) === "1") return true;
    try {
      const raw = window.localStorage.getItem(TOOL_KEY);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (parsed?.layout?.bootSplash === false) return true;
      }
    } catch {
      /* ignore */
    }
    return false;
  });

  useEffect(() => {
    if (booted && typeof window !== "undefined") {
      window.sessionStorage.setItem(BOOT_FLAG, "1");
    }
  }, [booted]);

  if (!booted) return <BootScreen onEnter={() => setBooted(true)} />;
  return <><div role="status" style={{padding: "12px", background: "#422006", color: "#fef3c7", textAlign: "center"}}>
    DEMO PREVIEW — synthetic data. Engage, Abort and Patch only simulate UI state; use the authenticated API or Go TUI for real scans.
  </div><Dashboard /></>;
}
