import { Swords, Activity, Wifi, WifiOff, Radio } from "lucide-react";
import { useClock } from "../hooks/useClock.js";

const STATUS_LABEL = {
  open: { text: "SYSTEM: ACTIVE", chip: "chip-live", icon: Wifi },
  connecting: { text: "SYSTEM: SYNC", chip: "chip-warn", icon: Radio },
  closed: { text: "SYSTEM: OFFLINE", chip: "chip-crit", icon: WifiOff },
  mock: { text: "SYSTEM: SIMULATED", chip: "chip-warn", icon: Activity },
};

/**
 * Top status bar — brand mark, live system state, UTC clock, operator IP.
 * Reads its own clock so it stays decoupled from the rest of the dashboard.
 */
export default function Header({ status = "open", operatorIp = "192.0.2.42" }) {
  const { label } = useClock();
  const meta = STATUS_LABEL[status] ?? STATUS_LABEL.open;
  const Icon = meta.icon;

  return (
    <header className="relative border-b border-slate-800 bg-slate-950/95">
      <div className="scanlines" />
      <div className="relative z-10 flex flex-wrap items-center justify-between gap-3 px-4 py-3">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center border border-accent-soft bg-accent-faint text-accent shadow-accent">
            <Swords className="h-4 w-4" />
          </div>
          <div className="leading-tight">
            <div className="text-base font-bold tracking-[0.35em] text-accent">
              GORDIAN
            </div>
            <div className="text-[10px] uppercase tracking-[0.4em] text-slate-500">
              v1.0 · tactical kill-chain console
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <span className={`chip ${meta.chip}`}>
            <span className="live-dot" />
            <Icon className="h-3 w-3" />
            {meta.text}
          </span>
          <span className="chip">
            <span className="text-slate-600">OP //</span>
            <span className="text-accent">{operatorIp}</span>
          </span>
          <span className="chip">
            <span className="text-slate-600">UTC //</span>
            <span className="text-slate-200 tabular-nums">{label}</span>
          </span>
        </div>
      </div>
    </header>
  );
}
