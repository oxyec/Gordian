/**
 * Native range slider styled to match the cyberdeck. We render a 0..max scale
 * underneath plus the live value badge so the operator never wonders where 47
 * sits on a 0..1000 scale.
 */
export default function Slider({
  id,
  value,
  onChange,
  min = 0,
  max = 100,
  step = 1,
  suffix,
  marks = [],
}) {
  const pct = ((value - min) / (max - min)) * 100;
  return (
    <div className="space-y-1">
      <div className="flex items-center gap-3">
        <input
          id={id}
          type="range"
          min={min}
          max={max}
          step={step}
          value={value}
          onChange={(e) => onChange(Number(e.target.value))}
          className="h-2 w-full cursor-pointer appearance-none border border-slate-800 bg-slate-900 [&::-webkit-slider-thumb]:h-3 [&::-webkit-slider-thumb]:w-3 [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:bg-cyan-400 [&::-webkit-slider-thumb]:shadow-neon [&::-moz-range-thumb]:h-3 [&::-moz-range-thumb]:w-3 [&::-moz-range-thumb]:border-0 [&::-moz-range-thumb]:bg-cyan-400"
          style={{
            background: `linear-gradient(to right, rgba(34,211,238,0.4) ${pct}%, #0f172a ${pct}%)`,
          }}
        />
        <span className="min-w-[4.5rem] border border-slate-800 bg-slate-950 px-2 py-1 text-center text-[11px] tabular-nums text-cyan-300">
          {value}
          {suffix && <span className="ml-1 text-slate-500">{suffix}</span>}
        </span>
      </div>
      {marks.length > 0 && (
        <div className="flex justify-between px-0.5 text-[9px] uppercase tracking-widest text-slate-600">
          {marks.map((m) => (
            <span key={m}>{m}</span>
          ))}
        </div>
      )}
    </div>
  );
}
