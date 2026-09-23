/**
 * Label + hint wrapper used by every form control. Keeps the visual rhythm
 * (uppercase mono label, slate hint, divider) consistent across config tabs.
 */
export default function Field({ label, hint, htmlFor, badge, children, span = 1 }) {
  return (
    <div className={`flex flex-col gap-1.5 ${span === 2 ? "sm:col-span-2" : ""}`}>
      <div className="flex items-center justify-between">
        <label
          htmlFor={htmlFor}
          className="flex items-center gap-2 text-[10px] uppercase tracking-[0.22em] text-slate-500"
        >
          {label}
          {badge && (
            <span className="border border-slate-800 bg-slate-900/70 px-1.5 py-px text-[9px] tracking-widest text-cyan-300">
              {badge}
            </span>
          )}
        </label>
      </div>
      {children}
      {hint && (
        <div className="text-[10px] leading-snug text-slate-600">{hint}</div>
      )}
    </div>
  );
}
