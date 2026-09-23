/**
 * Square hard-edged on/off switch. No rounded corners, no smoke. Click on
 * either label or the rail flips it.
 */
export default function Toggle({ id, checked, onChange, onLabel = "ON", offLabel = "OFF" }) {
  return (
    <button
      id={id}
      type="button"
      role="switch"
      aria-checked={checked}
      onClick={() => onChange(!checked)}
      className={`flex h-8 w-20 select-none items-center border text-[10px] uppercase tracking-[0.25em] transition-colors ${
        checked
          ? "border-cyan-400 bg-cyan-400/15 text-cyan-300 shadow-neon"
          : "border-slate-800 bg-slate-950 text-slate-500 hover:border-cyan-400/40"
      }`}
    >
      <span
        className={`flex h-full w-1/2 items-center justify-center transition-colors ${
          checked ? "bg-cyan-400 text-slate-950" : ""
        }`}
      >
        {onLabel}
      </span>
      <span
        className={`flex h-full w-1/2 items-center justify-center transition-colors ${
          checked ? "" : "bg-slate-800 text-slate-300"
        }`}
      >
        {offLabel}
      </span>
    </button>
  );
}
