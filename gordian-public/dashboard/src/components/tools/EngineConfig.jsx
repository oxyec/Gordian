import Field from "../forms/Field.jsx";
import Section from "../forms/Section.jsx";
import Toggle from "../forms/Toggle.jsx";
import Select from "../forms/Select.jsx";
import NumberInput from "../forms/NumberInput.jsx";
import TagInput from "../forms/TagInput.jsx";
import Slider from "../forms/Slider.jsx";

const ALGOS = [
  { value: "dijkstra", label: "Dijkstra" },
  { value: "astar", label: "A*" },
  { value: "bellman", label: "Bellman-Ford" },
];

export default function EngineConfig({ cfg, set }) {
  const totalWeight = (
    Number(cfg.cvssWeight || 0) +
    Number(cfg.epssWeight || 0) +
    Number(cfg.weaponizedBonus || 0) +
    Number(cfg.kevBonus || 0)
  ).toFixed(2);

  return (
    <div className="space-y-4">
      <Section title="Pathfinding">
        <Field label="Algorithm" hint="Dijkstra is the engine default and what the visualizer expects.">
          <Select
            value={cfg.algorithm}
            onChange={(v) => set("algorithm", v)}
            options={ALGOS}
          />
        </Field>
        <Field label="Max hops" hint="Truncate paths longer than this. 0 = no limit.">
          <NumberInput
            value={cfg.maxHops}
            onChange={(v) => set("maxHops", v || 0)}
            min={0}
            max={32}
          />
        </Field>
        <Field label="Path budget" hint="Stop after N kill-chains. Higher = more thorough, slower.">
          <NumberInput
            value={cfg.pathBudget}
            onChange={(v) => set("pathBudget", v || 1)}
            min={1}
            max={500}
            step={1}
          />
        </Field>
        <Field label="Recompute interval" hint="How often the engine re-runs Dijkstra after new findings.">
          <NumberInput
            value={cfg.recomputeMs}
            onChange={(v) => set("recomputeMs", v || 500)}
            min={500}
            max={60000}
            step={500}
            suffix="ms"
          />
        </Field>
      </Section>

      <Section title="Edge cost weights" hint={`Σ = ${totalWeight} (no need to sum to 1 — weights are relative)`}>
        <Field label="CVSS weight" badge="cvss">
          <Slider
            value={cfg.cvssWeight}
            onChange={(v) => set("cvssWeight", Number(v.toFixed(2)))}
            min={0}
            max={1}
            step={0.05}
          />
        </Field>
        <Field label="EPSS weight" badge="epss">
          <Slider
            value={cfg.epssWeight}
            onChange={(v) => set("epssWeight", Number(v.toFixed(2)))}
            min={0}
            max={1}
            step={0.05}
          />
        </Field>
        <Field label="Weaponized bonus" badge="exploit">
          <Slider
            value={cfg.weaponizedBonus}
            onChange={(v) => set("weaponizedBonus", Number(v.toFixed(2)))}
            min={0}
            max={1}
            step={0.05}
          />
        </Field>
        <Field label="KEV bonus" badge="kev">
          <Slider
            value={cfg.kevBonus}
            onChange={(v) => set("kevBonus", Number(v.toFixed(2)))}
            min={0}
            max={1}
            step={0.05}
          />
        </Field>
      </Section>

      <Section title="Targets & visibility">
        <Field
          label="Crown jewels"
          hint="Hosts the engine treats as terminal goals when scoring kill-chains."
          span={2}
        >
          <TagInput
            value={cfg.crownJewels}
            onChange={(v) => set("crownJewels", v)}
            placeholder="db-internal-04"
          />
        </Field>
        <Field
          label="Treat patched edges as blocked"
          hint="When ON, simulating a patch removes the edge instead of just down-weighting it."
        >
          <Toggle
            checked={cfg.treatPatchedAsBlocked}
            onChange={(v) => set("treatPatchedAsBlocked", v)}
          />
        </Field>
        <Field
          label="Show all paths in graph"
          hint="OFF = only the cheapest path per crown jewel is highlighted."
        >
          <Toggle
            checked={cfg.showAllPaths}
            onChange={(v) => set("showAllPaths", v)}
          />
        </Field>
      </Section>
    </div>
  );
}
