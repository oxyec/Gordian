import { Power } from "lucide-react";
import Field from "../forms/Field.jsx";
import Section from "../forms/Section.jsx";
import Toggle from "../forms/Toggle.jsx";
import TextInput from "../forms/TextInput.jsx";
import { RECON_TOOL_KEYS } from "../../lib/toolDefaults.js";

/**
 * Per-recon-tool toggle + binary + extra-args + full command override.
 * Each tool gets its own dropdown card so settings never overlap.
 */
export default function ReconConfig({ cfg, set }) {
  const enabledCount = RECON_TOOL_KEYS.reduce(
    (n, { key }) => n + (cfg?.[key]?.enabled ? 1 : 0),
    0
  );

  const updateTool = (key, prop, value) =>
    set(key, { ...(cfg[key] || {}), [prop]: value });

  return (
    <div className="space-y-4">
      <Section
        title="Recon helpers"
        hint={`${enabledCount} / ${RECON_TOOL_KEYS.length} active. Each tool runs through OffensiveConfig.tool_binaries / tool_extra_args / tool_command_overrides.`}
      >
        {RECON_TOOL_KEYS.map(({ key, label, blurb }) => {
          const t = cfg[key] || { enabled: false, binary: key, extraArgs: "", commandOverride: "" };
          return (
            <div
              key={key}
              className={`relative col-span-1 sm:col-span-2 border ${
                t.enabled
                  ? "border-cyan-400/40 bg-cyan-400/5"
                  : "border-slate-800 bg-slate-950/50"
              } p-3 transition-colors corner-mark`}
            >
              <div className="mb-3 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Power
                    className={`h-3.5 w-3.5 ${
                      t.enabled ? "text-cyan-300" : "text-slate-600"
                    }`}
                  />
                  <span className="text-[12px] uppercase tracking-[0.22em] text-slate-200">
                    {label}
                  </span>
                  <span className="text-[10px] text-slate-600">{blurb}</span>
                </div>
                <Toggle
                  checked={t.enabled}
                  onChange={(v) => updateTool(key, "enabled", v)}
                />
              </div>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <Field label="Binary" badge={`tool_binaries.${key}`}>
                  <TextInput
                    value={t.binary}
                    onChange={(v) => updateTool(key, "binary", v)}
                    placeholder={key}
                    prefix="$"
                  />
                </Field>
                <Field label="Extra args" badge={`tool_extra_args.${key}`}>
                  <TextInput
                    value={t.extraArgs}
                    onChange={(v) => updateTool(key, "extraArgs", v)}
                    placeholder="-silent -t 50"
                  />
                </Field>
                <Field
                  label="Full command override"
                  badge={`tool_command_overrides.${key}`}
                  hint="Use {target}, {url}, {host}, {domain}, {wordlist} placeholders."
                  span={2}
                >
                  <TextInput
                    value={t.commandOverride}
                    onChange={(v) => updateTool(key, "commandOverride", v)}
                    placeholder={`${key} -d {domain} -o /tmp/${key}.json`}
                  />
                </Field>
              </div>
            </div>
          );
        })}
      </Section>
    </div>
  );
}
