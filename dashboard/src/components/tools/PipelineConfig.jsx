import Field from "../forms/Field.jsx";
import Section from "../forms/Section.jsx";
import Toggle from "../forms/Toggle.jsx";
import NumberInput from "../forms/NumberInput.jsx";
import TextInput from "../forms/TextInput.jsx";

export default function PipelineConfig({ cfg, set }) {
  return (
    <div className="space-y-4">
      <Section title="Inputs" hint="Files the ETL reads at the top of the run.">
        <Field label="Network topology JSON" badge="--network" span={2}>
          <TextInput
            value={cfg.network}
            onChange={(v) => set("network", v)}
            placeholder="data/sample_network.json"
          />
        </Field>
        <Field label="CVE feed JSON" badge="--cves" span={2}>
          <TextInput
            value={cfg.cves}
            onChange={(v) => set("cves", v)}
            placeholder="data/cve_feed.json"
          />
        </Field>
      </Section>

      <Section title="Outputs">
        <Field label="Reports directory" badge="--out" span={2}>
          <TextInput
            value={cfg.out}
            onChange={(v) => set("out", v)}
            placeholder="reports"
          />
        </Field>
        <Field label="Top patches" badge="--top-patches" hint="How many remediation rows to surface.">
          <NumberInput
            value={cfg.topPatches}
            onChange={(v) => set("topPatches", v || 1)}
            min={1}
            max={50}
            suffix="rows"
          />
        </Field>
        <Field label="Skip remediation analysis" badge="--no-remediation" hint="Faster on huge graphs.">
          <Toggle
            checked={cfg.skipRemediation}
            onChange={(v) => set("skipRemediation", v)}
          />
        </Field>
      </Section>

      <Section title="Run behaviour">
        <Field label="Fail on findings" badge="--fail-on-findings" hint="Exit code 2 — useful as a CI gate.">
          <Toggle
            checked={cfg.failOnFindings}
            onChange={(v) => set("failOnFindings", v)}
          />
        </Field>
        <Field label="Quiet mode" badge="--quiet">
          <Toggle
            checked={cfg.quiet}
            onChange={(v) => set("quiet", v)}
          />
        </Field>
        <Field label="Verbose log" badge="-v">
          <Toggle
            checked={cfg.verbose}
            onChange={(v) => set("verbose", v)}
          />
        </Field>
        <Field label="Stream live events" badge="--live-log" hint="Required by the dashboard.">
          <Toggle
            checked={cfg.liveLog}
            onChange={(v) => set("liveLog", v)}
          />
        </Field>
      </Section>
    </div>
  );
}
