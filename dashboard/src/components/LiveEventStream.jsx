import { useEffect, useMemo, useRef, useState } from "react";
import { Terminal, Pause, Play, Trash2, Filter } from "lucide-react";

const TOOL_STYLES = {
  nmap: { color: "text-cyan-300", border: "border-cyan-400/40", tag: "NMAP" },
  nuclei: { color: "text-red-400", border: "border-red-500/50", tag: "NUCLEI" },
  ffuf: { color: "text-orange-300", border: "border-orange-400/40", tag: "FFUF" },
  engine: { color: "text-emerald-400", border: "border-emerald-400/40", tag: "ENGINE" },
  raw: { color: "text-slate-400", border: "border-slate-700", tag: "RAW" },
};

const LEVEL_STYLES = {
  info: "text-slate-400",
  warn: "text-orange-300",
  high: "text-orange-400",
  critical: "text-red-400 font-semibold",
};

const FILTERS = ["all", "nmap", "nuclei", "ffuf", "engine"];

const styleFor = (tool) => TOOL_STYLES[tool] ?? TOOL_STYLES.raw;

const formatTs = (ts) => {
  if (!ts) return "--:--:--";
  try {
    const d = new Date(ts);
    return d.toISOString().slice(11, 19);
  } catch {
    return "--:--:--";
  }
};

/**
 * Hacker-style auto-scrolling console for the live WS stream.
 * Pause stops auto-scroll *and* freezes the buffer view; clear flushes.
 */
export default function LiveEventStream({ events, status, onClear }) {
  const [filter, setFilter] = useState("all");
  const [paused, setPaused] = useState(false);
  const bodyRef = useRef(null);

  const filtered = useMemo(
    () => (filter === "all" ? events : events.filter((e) => e.tool === filter)),
    [events, filter]
  );

  useEffect(() => {
    if (paused || !bodyRef.current) return;
    bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
  }, [filtered, paused]);

  return (
    <section className="panel flex h-full flex-col">
      <div className="panel-header">
        <div className="panel-title">
          <Terminal className="h-3.5 w-3.5" />
          live.event.stream
          <span className="ml-2 text-slate-600">/api/v1/live</span>
        </div>
        <div className="flex items-center gap-2">
          <span
            className={`chip ${
              status === "open"
                ? "chip-live"
                : status === "mock"
                ? "chip-warn"
                : "chip-crit"
            }`}
          >
            <span className="live-dot" />
            {status === "open"
              ? "STREAM"
              : status === "mock"
              ? "MOCK"
              : status === "connecting"
              ? "SYNC"
              : "DOWN"}
          </span>
          <span className="chip">{events.length} evt</span>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2 border-b border-slate-800 bg-slate-950/40 px-3 py-2">
        <Filter className="h-3 w-3 text-slate-500" />
        {FILTERS.map((f) => (
          <button
            key={f}
            type="button"
            onClick={() => setFilter(f)}
            className={`px-2 py-0.5 text-[10px] uppercase tracking-widest border transition-colors ${
              filter === f
                ? "border-accent bg-accent-faint text-accent"
                : "border-slate-800 text-slate-500 hover:border-accent-soft hover:text-accent"
            }`}
          >
            {f}
          </button>
        ))}
        <div className="ml-auto flex items-center gap-2">
          <button
            type="button"
            onClick={() => setPaused((p) => !p)}
            className="btn-ghost"
          >
            {paused ? (
              <>
                <Play className="h-3 w-3" /> Resume
              </>
            ) : (
              <>
                <Pause className="h-3 w-3" /> Pause
              </>
            )}
          </button>
          <button type="button" onClick={onClear} className="btn-ghost">
            <Trash2 className="h-3 w-3" /> Clear
          </button>
        </div>
      </div>

      <div
        ref={bodyRef}
        className="relative flex-1 overflow-y-auto bg-slate-950 px-3 py-2 text-[12px] leading-relaxed"
      >
        <div className="pointer-events-none absolute inset-0 grid-bg opacity-50" />
        <div className="relative space-y-0.5">
          {filtered.length === 0 && (
            <div className="text-slate-700">// awaiting telemetry...</div>
          )}
          {filtered.map((e) => {
            const s = styleFor(e.tool);
            return (
              <div key={e.id} className="flex items-start gap-2 animate-boot">
                <span className="w-[68px] shrink-0 text-slate-700 tabular-nums">
                  {formatTs(e.ts)}
                </span>
                <span
                  className={`shrink-0 border px-1.5 text-[10px] uppercase tracking-wider ${s.border} ${s.color}`}
                >
                  {s.tag}
                </span>
                <span
                  className={`break-words ${LEVEL_STYLES[e.level] ?? "text-slate-300"}`}
                >
                  {e.msg}
                </span>
              </div>
            );
          })}
          {!paused && (
            <div className="text-accent">
              <span className="animate-pulse">_</span>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
