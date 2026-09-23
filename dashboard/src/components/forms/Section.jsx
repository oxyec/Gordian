/**
 * Subheader inside a tool-config tab. Used to group related fields
 * (e.g. "Discovery", "Timing", "Output") so a long form stays scannable.
 */
export default function Section({ title, hint, children }) {
  return (
    <fieldset className="border border-slate-800 bg-slate-950/50">
      <legend className="ml-3 border border-slate-800 bg-slate-900 px-2 py-0.5 text-[10px] uppercase tracking-[0.25em] text-cyan-400">
        {title}
      </legend>
      {hint && (
        <div className="border-b border-slate-800/60 bg-slate-900/30 px-4 py-1.5 text-[10px] uppercase tracking-widest text-slate-600">
          {hint}
        </div>
      )}
      <div className="grid grid-cols-1 gap-4 p-4 sm:grid-cols-2">
        {children}
      </div>
    </fieldset>
  );
}
