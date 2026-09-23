import { useEffect, useRef, useState } from "react";
import { MoreVertical } from "lucide-react";

/**
 * Per-panel gear dropdown. Renders nothing visible until clicked.
 * Items: [{ icon?: Component, label, onClick, danger?: boolean, divider?: boolean }]
 */
export default function PanelMenu({ items = [], align = "right" }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    if (!open) return;
    const handler = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    const esc = (e) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", handler);
    document.addEventListener("keydown", esc);
    return () => {
      document.removeEventListener("mousedown", handler);
      document.removeEventListener("keydown", esc);
    };
  }, [open]);

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen((s) => !s)}
        className={`flex h-6 w-6 items-center justify-center border transition-colors ${
          open
            ? "border-cyan-400 text-cyan-300 shadow-neon"
            : "border-slate-800 text-slate-500 hover:border-cyan-400/50 hover:text-cyan-300"
        }`}
        aria-haspopup="menu"
        aria-expanded={open}
        title="Panel options"
      >
        <MoreVertical className="h-3 w-3" />
      </button>
      {open && (
        <div
          role="menu"
          className={`absolute z-30 mt-1 min-w-[180px] border border-slate-800 bg-slate-950/95 py-1 shadow-neon ${
            align === "right" ? "right-0" : "left-0"
          }`}
        >
          {items.map((it, idx) => {
            if (it.divider) {
              return (
                <div
                  key={`div-${idx}`}
                  className="my-1 border-t border-slate-800/70"
                />
              );
            }
            const Icon = it.icon;
            return (
              <button
                key={it.label}
                type="button"
                role="menuitem"
                onClick={() => {
                  it.onClick?.();
                  setOpen(false);
                }}
                className={`flex w-full items-center gap-2 px-3 py-1.5 text-left text-[11px] uppercase tracking-[0.18em] transition-colors ${
                  it.danger
                    ? "text-red-400 hover:bg-red-500/10"
                    : "text-slate-300 hover:bg-cyan-400/10 hover:text-cyan-200"
                }`}
              >
                {Icon && <Icon className="h-3 w-3" />}
                {it.label}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
