import { Minus, Plus } from "lucide-react";

/**
 * Number input with +/- buttons. step defaults to 1 but tools like rate-limit
 * pass step=10. Empty string is preserved so the user can clear and retype.
 */
export default function NumberInput({
  id,
  value,
  onChange,
  min,
  max,
  step = 1,
  suffix,
  placeholder,
}) {
  const clamp = (n) => {
    if (Number.isNaN(n)) return value;
    if (typeof min === "number" && n < min) return min;
    if (typeof max === "number" && n > max) return max;
    return n;
  };

  const bump = (delta) => {
    const cur = typeof value === "number" ? value : Number(value) || 0;
    onChange(clamp(cur + delta));
  };

  return (
    <div className="flex items-stretch border border-slate-800 bg-slate-950 focus-within:border-cyan-400">
      <button
        type="button"
        onClick={() => bump(-step)}
        className="border-r border-slate-800 px-2 text-cyan-400 hover:bg-cyan-400/10"
        aria-label="decrement"
      >
        <Minus className="h-3.5 w-3.5" />
      </button>
      <input
        id={id}
        type="number"
        value={value === "" || value === null || value === undefined ? "" : value}
        onChange={(e) => {
          const v = e.target.value;
          if (v === "") return onChange("");
          onChange(clamp(Number(v)));
        }}
        min={min}
        max={max}
        step={step}
        placeholder={placeholder}
        className="w-full bg-transparent px-2 py-1.5 text-sm text-slate-200 tabular-nums placeholder:text-slate-600 focus:outline-none [appearance:textfield] [&::-webkit-inner-spin-button]:appearance-none [&::-webkit-outer-spin-button]:appearance-none"
      />
      {suffix && (
        <span className="flex items-center border-l border-slate-800 px-2 text-[10px] uppercase tracking-widest text-slate-500">
          {suffix}
        </span>
      )}
      <button
        type="button"
        onClick={() => bump(step)}
        className="border-l border-slate-800 px-2 text-cyan-400 hover:bg-cyan-400/10"
        aria-label="increment"
      >
        <Plus className="h-3.5 w-3.5" />
      </button>
    </div>
  );
}
