/**
 * Plain text input — same chrome as the rest of the form primitives so the
 * tool config tabs stay visually uniform.
 */
export default function TextInput({
  id,
  value,
  onChange,
  placeholder,
  prefix,
  mono = true,
}) {
  return (
    <div className="flex items-stretch border border-slate-800 bg-slate-950 focus-within:border-cyan-400">
      {prefix && (
        <span className="flex items-center border-r border-slate-800 px-3 text-cyan-400">
          {prefix}
        </span>
      )}
      <input
        id={id}
        type="text"
        value={value ?? ""}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        spellCheck={false}
        autoComplete="off"
        className={`w-full bg-transparent px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none ${
          mono ? "font-mono" : ""
        }`}
      />
    </div>
  );
}
