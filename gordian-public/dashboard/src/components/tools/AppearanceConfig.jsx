import { Palette, Type, Sparkles, Eye } from "lucide-react";
import Field from "../forms/Field.jsx";
import Section from "../forms/Section.jsx";
import Toggle from "../forms/Toggle.jsx";
import Select from "../forms/Select.jsx";
import Slider from "../forms/Slider.jsx";
import NumberInput from "../forms/NumberInput.jsx";
import {
  ACCENTS,
  FONTS,
  DENSITIES,
  MOTION,
  BG_TEXTURES,
} from "../../lib/appearancePresets.js";

const fontOptions = FONTS.map((f) => ({ value: f.id, label: f.label }));
const densityOptions = DENSITIES.map((d) => ({ value: d.id, label: d.label }));
const motionOptions = MOTION.map((m) => ({ value: m.id, label: m.label }));
const bgOptions = BG_TEXTURES.map((b) => ({ value: b.id, label: b.label }));

/**
 * Appearance config — colour, type, motion, ambience.
 * Writes only to CSS vars / dataset attrs (handled by useAppearanceSync).
 */
export default function AppearanceConfig({ cfg, set }) {
  const accent = ACCENTS.find((a) => a.id === cfg.accent) ?? ACCENTS[0];

  return (
    <div className="space-y-4">
      <Section title="Theme" hint="Maps to :root --accent / --accent-rgb / --accent-glow">
        <Field label="Accent palette" hint="Click a swatch to recolour the entire deck." span={2}>
          <div className="grid grid-cols-3 gap-2 sm:grid-cols-6">
            {ACCENTS.map((a) => {
              const active = cfg.accent === a.id;
              return (
                <button
                  key={a.id}
                  type="button"
                  onClick={() => set("accent", a.id)}
                  className={`group relative flex flex-col items-stretch border transition-colors ${
                    active
                      ? "border-cyan-300 shadow-neon"
                      : "border-slate-800 hover:border-slate-600"
                  }`}
                  title={a.label}
                >
                  <span
                    className="block h-8 w-full"
                    style={{ background: a.hex, boxShadow: active ? `0 0 18px ${a.glow}` : undefined }}
                  />
                  <span
                    className={`px-1 py-1 text-center text-[10px] uppercase tracking-[0.22em] ${
                      active ? "bg-slate-900 text-cyan-300" : "bg-slate-950 text-slate-500"
                    }`}
                  >
                    {a.label}
                  </span>
                </button>
              );
            })}
          </div>
        </Field>
        <Field label="Active hex" hint="Mirror of the chosen swatch.">
          <div className="flex h-9 items-center gap-2 border border-slate-800 bg-slate-950 px-3">
            <span
              className="h-3.5 w-3.5 border border-slate-700"
              style={{ background: accent.hex }}
            />
            <span className="text-[12px] tabular-nums text-cyan-200">{accent.hex}</span>
          </div>
        </Field>
        <Field label="Border radius" hint="0 = sharp cyberdeck, 6 = softened.">
          <Slider
            value={cfg.radius ?? 0}
            onChange={(v) => set("radius", v)}
            min={0}
            max={12}
            step={1}
            suffix="px"
            marks={["0", "4", "8", "12"]}
          />
        </Field>
      </Section>

      <Section title="Typography" hint="Maps to :root --font-mono">
        <Field label="Mono font">
          <Select
            value={cfg.font}
            onChange={(v) => set("font", v)}
            options={fontOptions}
            pillCap={5}
          />
        </Field>
        <Field label="Density" hint="Scales padding + font-size across all panels.">
          <Select
            value={cfg.density}
            onChange={(v) => set("density", v)}
            options={densityOptions}
            pillCap={3}
          />
        </Field>
      </Section>

      <Section title="Motion" hint="Maps to html[data-motion]">
        <Field label="Animation level" hint="Reduced disables loops; Off kills transitions too.">
          <Select
            value={cfg.motion}
            onChange={(v) => set("motion", v)}
            options={motionOptions}
            pillCap={3}
          />
        </Field>
        <Field label="Status chip flash" hint="Pulse the SYSTEM:ACTIVE indicator.">
          <Toggle
            checked={cfg.statusChipFlash}
            onChange={(v) => set("statusChipFlash", v)}
          />
        </Field>
      </Section>

      <Section title="Ambience" hint="Maps to html[data-background] + html[data-crt|scanlines]">
        <Field label="Background texture">
          <Select
            value={cfg.background}
            onChange={(v) => set("background", v)}
            options={bgOptions}
            pillCap={4}
          />
        </Field>
        <Field label="CRT vignette" hint="Subtle screen-edge darkening + warp.">
          <Toggle checked={cfg.crt} onChange={(v) => set("crt", v)} />
        </Field>
        <Field label="Scanlines" hint="Horizontal phosphor lines overlay.">
          <Toggle checked={cfg.scanlines} onChange={(v) => set("scanlines", v)} />
        </Field>
        <Field label="Neon glow" hint="Halo around accent borders, buttons, dots.">
          <Toggle checked={cfg.glow} onChange={(v) => set("glow", v)} />
        </Field>
        {cfg.glow && (
          <Field label="Glow strength" span={2}>
            <Slider
              value={cfg.glowStrength}
              onChange={(v) => set("glowStrength", v)}
              min={0}
              max={100}
              step={5}
              suffix="%"
              marks={["0", "30", "60", "100"]}
            />
          </Field>
        )}
      </Section>

      <Section title="Chrome" hint="Persistent UI furniture toggles">
        <Field label="Show HUD header" hint="Logo · clock · IP bar across the top.">
          <Toggle checked={cfg.showHud} onChange={(v) => set("showHud", v)} />
        </Field>
        <Field label="Show status footer" hint="License + engagement strip at the bottom.">
          <Toggle checked={cfg.showFooter} onChange={(v) => set("showFooter", v)} />
        </Field>
      </Section>

      <Section title="Live preview">
        <Field label="Token sample" span={2}>
          <div className="space-y-2 border border-slate-800 bg-slate-950/80 p-3 corner-mark">
            <div className="flex items-center gap-3">
              <span
                className="inline-block h-2.5 w-2.5"
                style={{ background: accent.hex, boxShadow: cfg.glow ? `0 0 12px ${accent.glow}` : "none" }}
              />
              <span className="text-[11px] uppercase tracking-[0.3em]" style={{ color: accent.hex }}>
                gordian // {cfg.accent}
              </span>
            </div>
            <pre
              className="whitespace-pre overflow-x-auto text-[11px]"
              style={{
                fontFamily: FONTS.find((f) => f.id === cfg.font)?.stack ?? "monospace",
                color: accent.hex,
              }}
            >
{`> ./gordian --target acme.tld
[+] dijkstra path computed in 0.42s
[!] 3 critical CVEs on db-internal-04`}
            </pre>
          </div>
        </Field>
      </Section>
    </div>
  );
}
