import { useMemo, useState } from "react";
import { ShieldCheck, ArrowDown, ArrowUp, Zap } from "lucide-react";

const STATUS_STYLE = {
  READY: "border-cyan-400/40 text-cyan-300",
  QUEUED: "border-slate-700 text-slate-400",
  PATCHING: "border-orange-400/50 text-orange-300 animate-pulse",
  DEFERRED: "border-red-500/50 text-red-400",
  DONE: "border-emerald-400/40 text-emerald-400",
};

const severityFor = (cvss) => {
  if (cvss >= 9) return { label: "CRIT", cls: "text-red-400" };
  if (cvss >= 7) return { label: "HIGH", cls: "text-orange-300" };
  if (cvss >= 4) return { label: "MED", cls: "text-yellow-300" };
  return { label: "LOW", cls: "text-emerald-400" };
};

const RiskBar = ({ value }) => {
  const pct = Math.min(100, Math.max(0, value));
  const tone =
    pct >= 30
      ? "bg-red-500"
      : pct >= 15
      ? "bg-orange-400"
      : "bg-cyan-400";
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-24 border border-slate-800 bg-slate-900">
        <div
          className={`h-full ${tone}`}
          style={{ width: `${pct}%`, transition: "width 240ms ease-out" }}
        />
      </div>
      <span className="w-12 text-right tabular-nums text-slate-200">
        {pct.toFixed(1)}%
      </span>
    </div>
  );
};

/**
 * Sortable remediation table — defaults to "highest risk-reduction first" so
 * the operator's eye lands on the patch that buys the most kill-chain breakage.
 */
export default function RemediationTable({ rows = [], onPatch }) {
  const [sortKey, setSortKey] = useState("riskReduction");
  const [sortDir, setSortDir] = useState("desc");

  const sorted = useMemo(() => {
    const dir = sortDir === "asc" ? 1 : -1;
    return [...rows].sort((a, b) => {
      const av = a[sortKey];
      const bv = b[sortKey];
      if (typeof av === "number") return (av - bv) * dir;
      return String(av).localeCompare(String(bv)) * dir;
    });
  }, [rows, sortKey, sortDir]);

  const toggleSort = (key) => {
    if (key === sortKey) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("desc");
    }
  };

  const SortIcon = ({ k }) =>
    sortKey !== k ? null : sortDir === "asc" ? (
      <ArrowUp className="ml-1 inline h-3 w-3" />
    ) : (
      <ArrowDown className="ml-1 inline h-3 w-3" />
    );

  return (
    <section className="panel flex h-full flex-col">
      <div className="panel-header">
        <div className="panel-title">
          <ShieldCheck className="h-3.5 w-3.5" />
          remediation.priority
        </div>
        <span className="chip chip-warn">
          {rows.length} candidate{rows.length === 1 ? "" : "s"}
        </span>
      </div>

      <div className="grid grid-cols-[1.4fr_1.2fr_2fr_0.7fr_0.9fr_0.7fr] items-center border-b border-slate-800 bg-slate-900/50 px-3 py-2 text-[10px] uppercase tracking-[0.2em] text-slate-500">
        <button
          onClick={() => toggleSort("cve")}
          className="text-left hover:text-accent"
        >
          CVE <SortIcon k="cve" />
        </button>
        <button
          onClick={() => toggleSort("host")}
          className="text-left hover:text-accent"
        >
          Host <SortIcon k="host" />
        </button>
        <button
          onClick={() => toggleSort("riskReduction")}
          className="text-left hover:text-accent"
        >
          Risk Reduction <SortIcon k="riskReduction" />
        </button>
        <button
          onClick={() => toggleSort("cvss")}
          className="text-left hover:text-accent"
        >
          CVSS <SortIcon k="cvss" />
        </button>
        <button
          onClick={() => toggleSort("status")}
          className="text-left hover:text-accent"
        >
          Status <SortIcon k="status" />
        </button>
        <span className="text-right">Action</span>
      </div>

      <div className="flex-1 overflow-y-auto">
        {sorted.length === 0 && (
          <div className="px-3 py-6 text-center text-xs text-slate-600">
            // no patch candidates yet — engage a target to populate
          </div>
        )}
        {sorted.map((r, idx) => {
          const sev = severityFor(r.cvss);
          const statusCls = STATUS_STYLE[r.status] ?? STATUS_STYLE.QUEUED;
          return (
            <div
              key={r.cve}
              className="grid grid-cols-[1.4fr_1.2fr_2fr_0.7fr_0.9fr_0.7fr] items-center border-b border-slate-900 px-3 py-2.5 text-xs hover:bg-accent-mute"
            >
              <div className="flex items-center gap-2">
                <span className="text-slate-700 tabular-nums">
                  {String(idx + 1).padStart(2, "0")}
                </span>
                <span className="font-semibold text-accent">{r.cve}</span>
                {r.weaponized && (
                  <span title="Weaponized exploit available">
                    <Zap className="h-3 w-3 text-red-400" />
                  </span>
                )}
              </div>
              <div className="truncate text-slate-300">{r.host}</div>
              <RiskBar value={r.riskReduction} />
              <div className={`tabular-nums ${sev.cls}`}>
                {r.cvss.toFixed(1)}{" "}
                <span className="text-slate-600">{sev.label}</span>
              </div>
              <div>
                <span className={`chip ${statusCls}`}>{r.status}</span>
              </div>
              <div className="text-right">
                <button
                  type="button"
                  onClick={() => onPatch?.(r)}
                  className="btn-ghost"
                >
                  Patch
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}
