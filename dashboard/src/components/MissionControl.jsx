import { useState } from "react";
import { Crosshair, Power, Ghost, Scale, Flame, Square } from "lucide-react";

const MODES = [
  {
    id: "stealth",
    label: "Stealth",
    icon: Ghost,
    blurb: "Passive recon · low signal · slow ttl",
    accent: "border-accent-soft text-accent hover:bg-accent-faint",
    active: "bg-accent border-accent shadow-accent",
  },
  {
    id: "balanced",
    label: "Balanced",
    icon: Scale,
    blurb: "Mixed scans · default cadence",
    accent: "border-orange-400/40 text-orange-300 hover:bg-orange-400/10",
    active: "bg-orange-400 text-slate-950 border-orange-300 shadow-warn",
  },
  {
    id: "aggressive",
    label: "Aggressive",
    icon: Flame,
    blurb: "Full surface · loud · fast",
    accent: "border-red-500/40 text-red-300 hover:bg-red-500/10",
    active: "bg-red-500 text-slate-950 border-red-400 shadow-kill",
  },
];

/**
 * Mission Control — the operator's launch console. Owns target + mode locally;
 * promotes the engagement up via onEngage so the parent can wire it to the API.
 */
export default function MissionControl({ engaged = false, onEngage, onAbort }) {
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState("balanced");

  const submit = (e) => {
    e.preventDefault();
    const trimmed = target.trim();
    if (!trimmed) return;
    onEngage?.({ target: trimmed, mode });
  };

  return (
    <section className="panel">
      <div className="panel-header">
        <div className="panel-title">
          <Crosshair className="h-3.5 w-3.5" />
          mission.control
        </div>
        <span className={`chip ${engaged ? "chip-crit" : "chip-live"}`}>
          <span className="live-dot" />
          {engaged ? "ENGAGED" : "STANDBY"}
        </span>
      </div>

      <form onSubmit={submit} className="space-y-4 p-4">
        <div className="space-y-1.5">
          <label className="text-[10px] uppercase tracking-[0.25em] text-slate-500">
            target.acquire
          </label>
          <div className="flex items-stretch gap-0">
            <span className="flex items-center border border-r-0 border-slate-800 bg-slate-900/60 px-3 text-accent">
              ▸
            </span>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="hostname / cidr / url   (e.g. 10.0.0.0/24)"
              className="input"
              spellCheck={false}
              autoComplete="off"
            />
          </div>
        </div>

        <div className="space-y-1.5">
          <label className="text-[10px] uppercase tracking-[0.25em] text-slate-500">
            engagement.mode
          </label>
          <div className="grid grid-cols-3 gap-2">
            {MODES.map(({ id, label, icon: Icon, blurb, accent, active }) => {
              const isActive = mode === id;
              return (
                <button
                  key={id}
                  type="button"
                  onClick={() => setMode(id)}
                  className={`group flex flex-col items-start gap-1 border px-3 py-2 text-left transition-all ${
                    isActive ? active : `border-slate-800 text-slate-400 ${accent}`
                  }`}
                >
                  <span className="flex items-center gap-2 text-[11px] uppercase tracking-[0.2em]">
                    <Icon className="h-3.5 w-3.5" />
                    {label}
                  </span>
                  <span
                    className={`text-[10px] leading-snug ${
                      isActive ? "text-slate-900" : "text-slate-500"
                    }`}
                  >
                    {blurb}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        <div className="flex items-center justify-between border-t border-slate-800 pt-4">
          <div className="text-[10px] uppercase tracking-[0.2em] text-slate-600">
            mode //{" "}
            <span className="text-accent">{mode}</span>
            <span className="mx-2 text-slate-700">|</span>
            target //{" "}
            <span className="text-accent">
              {target ? target : "—"}
            </span>
          </div>
          <div className="flex gap-2">
            {engaged && (
              <button
                type="button"
                onClick={onAbort}
                className="btn-danger"
              >
                <Square className="h-3.5 w-3.5" />
                Abort
              </button>
            )}
            <button
              type="submit"
              disabled={engaged || !target.trim()}
              className="btn-primary"
            >
              <Power className="h-3.5 w-3.5" />
              {engaged ? "Live" : "Engage"}
            </button>
          </div>
        </div>
      </form>
    </section>
  );
}
