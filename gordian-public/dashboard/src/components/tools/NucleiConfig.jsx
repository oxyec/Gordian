import Field from "../forms/Field.jsx";
import Section from "../forms/Section.jsx";
import Toggle from "../forms/Toggle.jsx";
import NumberInput from "../forms/NumberInput.jsx";
import TextInput from "../forms/TextInput.jsx";
import TagInput from "../forms/TagInput.jsx";

const SEVERITY_SUGGESTIONS = ["info", "low", "medium", "high", "critical"];
const TAG_SUGGESTIONS = ["cve", "exposure", "misconfig", "tech", "default-login", "intrusive", "kev", "rce", "sqli", "xss"];
const EXCLUDE_SUGGESTIONS = ["dos", "intrusive", "fuzz", "miscellaneous"];

export default function NucleiConfig({ cfg, set }) {
  return (
    <div className="space-y-4">
      <Section title="Engine">
        <Field label="Enabled">
          <Toggle
            checked={cfg.enabled}
            onChange={(v) => set("enabled", v)}
          />
        </Field>
        <Field label="Binary path">
          <TextInput
            value={cfg.binary}
            onChange={(v) => set("binary", v)}
            placeholder="nuclei"
            prefix="$"
          />
        </Field>
        <Field
          label="Templates path"
          hint="Maps to nuclei_templates. Empty = use system default ~/nuclei-templates."
          span={2}
        >
          <TextInput
            value={cfg.templatesPath}
            onChange={(v) => set("templatesPath", v)}
            placeholder="/opt/nuclei-templates/http/cves"
          />
        </Field>
      </Section>

      <Section title="Selection">
        <Field
          label="Severity (-s)"
          hint="Comma list. Order doesn't matter; lowercase normalised."
          span={2}
        >
          <TagInput
            value={cfg.severity}
            onChange={(v) => set("severity", v)}
            placeholder="high,critical"
            normalize={(v) => v.trim().toLowerCase()}
            validate={(v) => SEVERITY_SUGGESTIONS.includes(v)}
            suggestions={SEVERITY_SUGGESTIONS}
          />
        </Field>
        <Field label="Include tags (-tags)" span={2}>
          <TagInput
            value={cfg.tags}
            onChange={(v) => set("tags", v)}
            placeholder="cve,exposure"
            normalize={(v) => v.trim().toLowerCase()}
            suggestions={TAG_SUGGESTIONS}
          />
        </Field>
        <Field label="Exclude tags (-etags)" span={2}>
          <TagInput
            value={cfg.excludeTags}
            onChange={(v) => set("excludeTags", v)}
            placeholder="dos,intrusive"
            normalize={(v) => v.trim().toLowerCase()}
            suggestions={EXCLUDE_SUGGESTIONS}
          />
        </Field>
        <Field label="KEV-only" hint="Restrict to CISA KEV-listed CVEs only.">
          <Toggle
            checked={cfg.onlyKev}
            onChange={(v) => set("onlyKev", v)}
          />
        </Field>
        <Field label="Follow redirects (-fr)">
          <Toggle
            checked={cfg.followRedirects}
            onChange={(v) => set("followRedirects", v)}
          />
        </Field>
        <Field label="Include req/resp in output (-irr)">
          <Toggle
            checked={cfg.includeRR}
            onChange={(v) => set("includeRR", v)}
          />
        </Field>
      </Section>

      <Section title="Throughput" hint="Maps to max_nuclei_rate in OffensiveConfig">
        <Field label="Rate limit (-rl)">
          <NumberInput
            value={cfg.rateLimit}
            onChange={(v) => set("rateLimit", v || 1)}
            min={1}
            max={10000}
            step={10}
            suffix="req/s"
          />
        </Field>
        <Field label="Bulk size (-bs)">
          <NumberInput
            value={cfg.bulkSize}
            onChange={(v) => set("bulkSize", v || 1)}
            min={1}
            max={500}
            suffix="hosts"
          />
        </Field>
        <Field label="Concurrency (-c)" hint="Templates running in parallel per host.">
          <NumberInput
            value={cfg.concurrency}
            onChange={(v) => set("concurrency", v || 1)}
            min={1}
            max={500}
            suffix="tpl"
          />
        </Field>
        <Field label="Timeout (-timeout)">
          <NumberInput
            value={cfg.timeout}
            onChange={(v) => set("timeout", v || 1)}
            min={1}
            max={120}
            suffix="s"
          />
        </Field>
        <Field label="Retries (-retries)">
          <NumberInput
            value={cfg.retries}
            onChange={(v) => set("retries", v || 0)}
            min={0}
            max={10}
          />
        </Field>
        <Field label="Extra args" badge="tool_extra_args.nuclei">
          <TextInput
            value={cfg.extraArgs}
            onChange={(v) => set("extraArgs", v)}
            placeholder="-stats -silent"
          />
        </Field>
        <Field
          label="Full command override"
          badge="tool_command_overrides.nuclei"
          hint="Placeholders: {target}, {url}, {host}."
          span={2}
        >
          <TextInput
            value={cfg.commandOverride}
            onChange={(v) => set("commandOverride", v)}
            placeholder="nuclei -u {url} -t /opt/templates -severity high,critical"
          />
        </Field>
      </Section>
    </div>
  );
}
