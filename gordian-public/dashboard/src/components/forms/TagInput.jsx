import { useState } from "react";
import { X } from "lucide-react";

/**
 * Chip-based string-array editor. Used for ffuf extensions, nuclei tags,
 * crown-jewel hosts, etc. Comma + Enter both commit a value.
 */
export default function TagInput({
  id,
  value = [],
  onChange,
  placeholder,
  normalize = (v) => v.trim(),
  validate = (v) => v.length > 0,
  suggestions = [],
}) {
  const [draft, setDraft] = useState("");

  const commit = (raw) => {
    const v = normalize(raw);
    if (!validate(v)) return;
    if (value.includes(v)) return;
    onChange([...value, v]);
    setDraft("");
  };

  const remove = (idx) => {
    const next = value.slice();
    next.splice(idx, 1);
    onChange(next);
  };

  const handleKey = (e) => {
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault();
      commit(draft);
    } else if (e.key === "Backspace" && !draft && value.length) {
      remove(value.length - 1);
    }
  };

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-1 border border-slate-800 bg-slate-950 px-2 py-1.5 focus-within:border-cyan-400">
        {value.map((tag, idx) => (
          <span
            key={`${tag}-${idx}`}
            className="flex items-center gap-1 border border-cyan-400/40 bg-cyan-400/10 px-1.5 py-0.5 text-[11px] text-cyan-200"
          >
            {tag}
            <button
              type="button"
              onClick={() => remove(idx)}
              className="text-cyan-300 hover:text-red-400"
              aria-label={`remove ${tag}`}
            >
              <X className="h-3 w-3" />
            </button>
          </span>
        ))}
        <input
          id={id}
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={handleKey}
          onBlur={() => draft && commit(draft)}
          placeholder={value.length === 0 ? placeholder : ""}
          spellCheck={false}
          autoComplete="off"
          className="min-w-[8ch] flex-1 bg-transparent px-1 py-0.5 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none"
        />
      </div>
      {suggestions.length > 0 && (
        <div className="flex flex-wrap gap-1">
          <span className="text-[10px] uppercase tracking-widest text-slate-600">
            quick:
          </span>
          {suggestions.map((s) => {
            const active = value.includes(s);
            return (
              <button
                key={s}
                type="button"
                onClick={() =>
                  active
                    ? onChange(value.filter((v) => v !== s))
                    : commit(s)
                }
                className={`border px-1.5 py-0.5 text-[10px] uppercase tracking-widest transition-colors ${
                  active
                    ? "border-cyan-400 bg-cyan-400/15 text-cyan-300"
                    : "border-slate-800 text-slate-500 hover:border-cyan-400/40 hover:text-cyan-300"
                }`}
              >
                {s}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
