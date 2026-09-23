import { ArrowUp, ArrowDown, GripVertical, Eye, EyeOff } from "lucide-react";
import Field from "../forms/Field.jsx";
import Section from "../forms/Section.jsx";
import Toggle from "../forms/Toggle.jsx";
import Slider from "../forms/Slider.jsx";
import NumberInput from "../forms/NumberInput.jsx";

const PANEL_LABELS = {
  mission: { label: "Mission Control", blurb: "Engagement launcher + abort" },
  stream:  { label: "Live Event Stream", blurb: "Color-coded operator log" },
  remediation: { label: "Remediation Table", blurb: "Sortable CVE → patch list" },
  graph:   { label: "Attack Graph", blurb: "SVG kill-chain visualizer" },
};

/**
 * Layout config — panel order / visibility / column widths / section heights.
 * Pure UI state; consumed by Dashboard to drive its 12-col grid.
 */
export default function LayoutConfig({ cfg, set }) {
  const move = (idx, dir) => {
    const next = [...cfg.panels];
    const swap = idx + dir;
    if (swap < 0 || swap >= next.length) return;
    [next[idx], next[swap]] = [next[swap], next[idx]];
    set("panels", next);
  };

  const toggleVisible = (key) =>
    set("visible", { ...cfg.visible, [key]: !cfg.visible[key] });

  return (
    <div className="space-y-4">
      <Section title="Panel order" hint="Top → bottom render order. Hidden panels stay in the list so order is preserved if you re-enable them.">
        <Field label="Layout stack" span={2}>
          <ul className="flex flex-col border border-slate-800 bg-slate-950/60">
            {cfg.panels.map((key, idx) => {
              const meta = PANEL_LABELS[key] ?? { label: key, blurb: "" };
              const visible = Boolean(cfg.visible?.[key]);
              return (
                <li
                  key={key}
                  className={`flex items-center justify-between gap-2 border-b border-slate-800/70 px-3 py-2 last:border-b-0 ${
                    visible ? "" : "opacity-60"
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <GripVertical className="h-3.5 w-3.5 text-slate-700" />
                    <span className="w-6 text-[11px] tabular-nums text-cyan-400">
                      {String(idx + 1).padStart(2, "0")}
                    </span>
                    <div>
                      <div className="text-[12px] uppercase tracking-[0.22em] text-slate-200">
                        {meta.label}
                      </div>
                      <div className="text-[10px] text-slate-600">{meta.blurb}</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-1">
                    <button
                      type="button"
                      onClick={() => toggleVisible(key)}
                      className={`flex h-7 w-7 items-center justify-center border ${
                        visible
                          ? "border-cyan-400/40 text-cyan-300"
                          : "border-slate-800 text-slate-600"
                      } hover:border-cyan-400 hover:text-cyan-200`}
                      title={visible ? "Hide panel" : "Show panel"}
                    >
                      {visible ? <Eye className="h-3 w-3" /> : <EyeOff className="h-3 w-3" />}
                    </button>
                    <button
                      type="button"
                      onClick={() => move(idx, -1)}
                      disabled={idx === 0}
                      className="flex h-7 w-7 items-center justify-center border border-slate-800 text-slate-400 hover:border-cyan-400 hover:text-cyan-300 disabled:opacity-30"
                      title="Move up"
                    >
                      <ArrowUp className="h-3 w-3" />
                    </button>
                    <button
                      type="button"
                      onClick={() => move(idx, 1)}
                      disabled={idx === cfg.panels.length - 1}
                      className="flex h-7 w-7 items-center justify-center border border-slate-800 text-slate-400 hover:border-cyan-400 hover:text-cyan-300 disabled:opacity-30"
                      title="Move down"
                    >
                      <ArrowDown className="h-3 w-3" />
                    </button>
                  </div>
                </li>
              );
            })}
          </ul>
        </Field>
      </Section>

      <Section title="Grid widths" hint="12-column system. Stream + remediation share a row.">
        <Field label="Stream width" hint={`Remediation auto-fills ${12 - cfg.streamCols} cols.`}>
          <Slider
            value={cfg.streamCols}
            onChange={(v) => {
              set("streamCols", v);
              set("remediationCols", 12 - v);
            }}
            min={3}
            max={9}
            step={1}
            suffix="col"
            marks={["3", "6", "9"]}
          />
        </Field>
        <Field label="Remediation width">
          <Slider
            value={cfg.remediationCols}
            onChange={(v) => {
              set("remediationCols", v);
              set("streamCols", 12 - v);
            }}
            min={3}
            max={9}
            step={1}
            suffix="col"
            marks={["3", "6", "9"]}
          />
        </Field>
        <Field label="Graph full-width" hint="OFF puts the graph beside the table on wide screens.">
          <Toggle
            checked={cfg.graphFull}
            onChange={(v) => set("graphFull", v)}
          />
        </Field>
      </Section>

      <Section title="Heights">
        <Field label="Stream / table min height">
          <NumberInput
            value={cfg.streamHeight}
            onChange={(v) => set("streamHeight", v || 240)}
            min={240}
            max={900}
            step={20}
            suffix="px"
          />
        </Field>
        <Field label="Graph min height">
          <NumberInput
            value={cfg.graphHeight}
            onChange={(v) => set("graphHeight", v || 240)}
            min={240}
            max={900}
            step={20}
            suffix="px"
          />
        </Field>
      </Section>

      <Section title="Chrome">
        <Field label="Render header bar">
          <Toggle checked={cfg.showHeader} onChange={(v) => set("showHeader", v)} />
        </Field>
        <Field label="Render footer bar">
          <Toggle checked={cfg.showFooter} onChange={(v) => set("showFooter", v)} />
        </Field>
        <Field label="Show boot splash on first paint" hint="The ASCII GORDIAN intro.">
          <Toggle checked={cfg.bootSplash} onChange={(v) => set("bootSplash", v)} />
        </Field>
      </Section>
    </div>
  );
}
