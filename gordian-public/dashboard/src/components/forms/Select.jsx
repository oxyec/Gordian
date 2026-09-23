import { ChevronDown } from "lucide-react";

/**
 * Segmented select — when there are ≤ 5 options we render pill buttons;
 * otherwise we fall through to a native <select> with a custom chevron.
 * Keeps the cyberdeck look without losing keyboard accessibility.
 */
export default function Select({ id, value, onChange, options, pillCap = 5 }) {
  if (options.length <= pillCap) {
    return (
      <div
        id={id}
        role="radiogroup"
        className="flex flex-wrap gap-0 border border-slate-800 bg-slate-950"
      >
        {options.map((o, idx) => {
          const isActive = o.value === value;
          return (
            <button
              key={o.value}
              type="button"
              role="radio"
              aria-checked={isActive}
              onClick={() => onChange(o.value)}
              className={`flex-1 border-r border-slate-800 px-3 py-2 text-[11px] uppercase tracking-[0.18em] transition-colors last:border-r-0 ${
                isActive
                  ? "bg-cyan-400 text-slate-950"
                  : "text-slate-400 hover:bg-cyan-400/10 hover:text-cyan-300"
              } ${idx === 0 ? "" : ""}`}
            >
              {o.label}
            </button>
          );
        })}
      </div>
    );
  }

  return (
    <div className="relative">
      <select
        id={id}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="input appearance-none pr-9"
      >
        {options.map((o) => (
          <option key={o.value} value={o.value} className="bg-slate-950">
            {o.label}
          </option>
        ))}
      </select>
      <ChevronDown className="pointer-events-none absolute right-2 top-1/2 h-4 w-4 -translate-y-1/2 text-cyan-400" />
    </div>
  );
}
