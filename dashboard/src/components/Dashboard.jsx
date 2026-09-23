import { useMemo, useState } from "react";
import { Crosshair, Settings2 } from "lucide-react";
import Header from "./Header.jsx";
import MissionControl from "./MissionControl.jsx";
import LiveEventStream from "./LiveEventStream.jsx";
import RemediationTable from "./RemediationTable.jsx";
import AttackGraph from "./AttackGraph.jsx";
import ToolConfig from "./ToolConfig.jsx";
import { useEventStream } from "../hooks/useWebSocket.js";
import { useToolConfig } from "../hooks/useToolConfig.js";
import { useAppearanceSync } from "../hooks/useAppearance.js";
import { exportOffensiveConfig } from "../lib/toolDefaults.js";
import { MOCK_GRAPH, MOCK_REMEDIATIONS } from "../lib/mockData.js";

const DEFAULT_WS_PATH = "/api/v1/live";

const toWebSocketBase = (value) => {
  const raw = String(value ?? "").trim();
  if (!raw) return null;

  if (raw.startsWith("ws://") || raw.startsWith("wss://")) {
    return raw.replace(/\/+$/, "");
  }
  if (raw.startsWith("http://") || raw.startsWith("https://")) {
    return raw.replace(/^http/i, "ws").replace(/\/+$/, "");
  }
  return null;
};

const withPath = (base, path) => {
  const cleanBase = base.replace(/\/+$/, "");
  if (cleanBase.endsWith(path)) return cleanBase;
  return `${cleanBase}${path}`;
};

const resolveWsUrl = () => {
  const explicitWs = toWebSocketBase(import.meta.env.VITE_WS_URL);
  if (explicitWs) {
    return withPath(explicitWs, import.meta.env.VITE_WS_PATH || DEFAULT_WS_PATH);
  }

  const apiBase = toWebSocketBase(import.meta.env.VITE_API_BASE_URL);
  if (apiBase) {
    return withPath(apiBase, import.meta.env.VITE_WS_PATH || DEFAULT_WS_PATH);
  }

  if (typeof window !== "undefined") {
    const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
    return `${scheme}//${window.location.host}${DEFAULT_WS_PATH}`;
  }

  return `ws://127.0.0.1:8000${DEFAULT_WS_PATH}`;
};

const WS_URL = resolveWsUrl();

const VIEWS = [
  { id: "ops",    label: "Operations", icon: Crosshair  },
  { id: "config", label: "Config",     icon: Settings2  },
];

// Tailwind needs class names visible at build time — these literals are kept
// in scope so the JIT compiler emits them. lg:col-span-{1..12} all referenced.
// eslint-disable-next-line no-unused-vars
const _SAFE_COLS =
  "lg:col-span-1 lg:col-span-2 lg:col-span-3 lg:col-span-4 lg:col-span-5 lg:col-span-6 lg:col-span-7 lg:col-span-8 lg:col-span-9 lg:col-span-10 lg:col-span-11 lg:col-span-12";

const COL_CLASS = {
  1:  "lg:col-span-1",
  2:  "lg:col-span-2",
  3:  "lg:col-span-3",
  4:  "lg:col-span-4",
  5:  "lg:col-span-5",
  6:  "lg:col-span-6",
  7:  "lg:col-span-7",
  8:  "lg:col-span-8",
  9:  "lg:col-span-9",
  10: "lg:col-span-10",
  11: "lg:col-span-11",
  12: "lg:col-span-12",
};

/**
 * Top-level shell:
 *  · Boot splash already cleared by App.jsx.
 *  · Header (toggleable via layout.showHeader / appearance.showHud).
 *  · View switcher: Operations grid vs. Config tabs.
 *  · Footer (toggleable via layout.showFooter / appearance.showFooter).
 *
 * Layout state is held by useToolConfig and reflects directly into the grid
 * (panel order, visibility, column widths, heights). Appearance state is
 * applied to :root by useAppearanceSync.
 */
export default function Dashboard() {
  const { events, status, clear } = useEventStream(null, { maxBuffer: 400, autoMock: true });
  const [view, setView] = useState("ops");
  const [engagement, setEngagement] = useState(null);

  const { state, set, patch, reset } = useToolConfig();
  useAppearanceSync(state.appearance);

  const layout = state.layout;
  const appearance = state.appearance;
  const showHeader = layout.showHeader && appearance.showHud;
  const showFooter = layout.showFooter && appearance.showFooter;

  const handleEngage = (cfg) => setEngagement(cfg);
  const handleAbort = () => setEngagement(null);
  const handlePatch = (row) => {
    console.info("[gordian] patch request", row.cve);
  };

  // Demo controls update local configuration only.
  const handleApply = () => {};

  const visiblePanels = useMemo(
    () => layout.panels.filter((k) => layout.visible?.[k]),
    [layout.panels, layout.visible]
  );

  const renderPanel = (key) => {
    switch (key) {
      case "mission":
        return (
          <div key="mission" className="lg:col-span-12">
            <MissionControl
              engaged={Boolean(engagement)}
              onEngage={handleEngage}
              onAbort={handleAbort}
            />
          </div>
        );
      case "stream":
        return (
          <div
            key="stream"
            className={COL_CLASS[layout.streamCols] ?? COL_CLASS[7]}
            style={{ minHeight: `${layout.streamHeight}px` }}
          >
            <LiveEventStream events={events} status={status} onClear={clear} />
          </div>
        );
      case "remediation":
        return (
          <div
            key="remediation"
            className={COL_CLASS[layout.remediationCols] ?? COL_CLASS[5]}
            style={{ minHeight: `${layout.streamHeight}px` }}
          >
            <RemediationTable rows={MOCK_REMEDIATIONS} onPatch={handlePatch} />
          </div>
        );
      case "graph":
        return (
          <div
            key="graph"
            className={layout.graphFull ? COL_CLASS[12] : COL_CLASS[6]}
            style={{ minHeight: `${layout.graphHeight}px` }}
          >
            <AttackGraph graph={MOCK_GRAPH} />
          </div>
        );
      default:
        return null;
    }
  };

  return (
    <div className="flex min-h-screen flex-col bg-slate-950">
      {showHeader && <Header status={status} operatorIp="192.0.2.42" />}

      {/* View switcher */}
      <div className="flex items-center justify-between border-b border-slate-800 bg-slate-950/95 px-4 py-2">
        <nav className="flex items-stretch gap-0 border border-slate-800">
          {VIEWS.map((v) => {
            const Icon = v.icon;
            const isActive = view === v.id;
            return (
              <button
                key={v.id}
                type="button"
                onClick={() => setView(v.id)}
                className={`flex items-center gap-2 border-r border-slate-800 px-4 py-1.5 text-[11px] uppercase tracking-[0.25em] transition-colors last:border-r-0 ${
                  isActive
                    ? "bg-cyan-400 text-slate-950 shadow-neon"
                    : "bg-slate-950 text-slate-400 hover:bg-cyan-400/10 hover:text-cyan-300"
                }`}
              >
                <Icon className="h-3.5 w-3.5" />
                {v.label}
              </button>
            );
          })}
        </nav>
        <div className="hidden items-center gap-2 text-[10px] uppercase tracking-[0.3em] text-slate-500 sm:flex">
          <span>view //</span>
          <span className="text-cyan-300">{view}</span>
          <span>· panels {visiblePanels.length}/{layout.panels.length}</span>
        </div>
      </div>

      {view === "ops" ? (
        <main className="grid flex-1 grid-cols-1 gap-3 p-3 lg:grid-cols-12">
          {visiblePanels.map(renderPanel)}
          {visiblePanels.length === 0 && (
            <div className="col-span-12 flex h-64 items-center justify-center border border-dashed border-slate-800 bg-slate-950/40 text-[11px] uppercase tracking-[0.3em] text-slate-600">
              all panels hidden — re-enable in config // layout
            </div>
          )}
        </main>
      ) : (
        <main className="flex-1 p-3">
          <div className="h-full min-h-[calc(100vh-180px)]">
            <ToolConfig
              state={state}
              set={set}
              patch={patch}
              reset={reset}
              onSubmit={handleApply}
            />
          </div>
        </main>
      )}

      {showFooter && (
        <footer className="border-t border-slate-800 bg-slate-950/95 px-4 py-2 text-[10px] uppercase tracking-[0.25em] text-slate-600">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span>
              <span className="text-cyan-400">gordian</span> · tactical console ·
              mit license
            </span>
            <span>
              engagement: {engagement ? `${engagement.target} (${engagement.mode})` : "standby"}
            </span>
          </div>
        </footer>
      )}
    </div>
  );
}
