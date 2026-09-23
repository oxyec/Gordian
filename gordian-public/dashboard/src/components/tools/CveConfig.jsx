import Field from "../forms/Field.jsx";
import Section from "../forms/Section.jsx";
import Toggle from "../forms/Toggle.jsx";
import Select from "../forms/Select.jsx";
import NumberInput from "../forms/NumberInput.jsx";
import TextInput from "../forms/TextInput.jsx";
import TagInput from "../forms/TagInput.jsx";

const PROFILES = [
  { value: "local",        label: "Local file" },
  { value: "cisa_kev",     label: "CISA KEV" },
  { value: "nvd_recent",   label: "NVD Recent" },
  { value: "ghsa_recent",  label: "GHSA Recent" },
  { value: "osv_enriched", label: "OSV Enriched" },
  { value: "multi",        label: "Multi-source" },
];
const SYNC_POLICY  = [
  { value: "always",   label: "Always" },
  { value: "if-stale", label: "If stale" },
  { value: "never",    label: "Never" },
];
const SYNC_SCHEDULE = [
  { value: "off",    label: "Off" },
  { value: "daily",  label: "Daily" },
  { value: "weekly", label: "Weekly" },
];
const SOURCE_SUGGESTIONS = ["cisa_kev", "nvd_recent", "ghsa_recent", "osv_enriched"];

export default function CveConfig({ cfg, set }) {
  return (
    <div className="space-y-4">
      <Section title="Source" hint="Maps to --cve-profile / --cve-cache-dir / --cve-auto-download">
        <Field label="Profile">
          <Select value={cfg.profile} onChange={(v) => set("profile", v)} options={PROFILES} pillCap={4} />
        </Field>
        <Field label="Auto-download">
          <Toggle checked={cfg.autoDownload} onChange={(v) => set("autoDownload", v)} />
        </Field>
        <Field label="Cache directory" span={2}>
          <TextInput value={cfg.cacheDir} onChange={(v) => set("cacheDir", v)} placeholder="data/cve_cache" />
        </Field>
        <Field label="Max items" badge="--cve-max-items" hint="Cap entries kept from synced profiles.">
          <NumberInput value={cfg.maxItems} onChange={(v) => set("maxItems", v || 1)} min={1} max={100000} step={100} />
        </Field>
        <Field label="OSV lookup limit" badge="--cve-osv-lookup-limit">
          <NumberInput value={cfg.osvLookupLimit} onChange={(v) => set("osvLookupLimit", v || 1)} min={1} max={5000} step={10} />
        </Field>
      </Section>

      <Section title="Sync cadence">
        <Field label="Sync policy" badge="--cve-sync-policy">
          <Select value={cfg.syncPolicy} onChange={(v) => set("syncPolicy", v)} options={SYNC_POLICY} />
        </Field>
        <Field label="Schedule" badge="--cve-sync-schedule">
          <Select value={cfg.syncSchedule} onChange={(v) => set("syncSchedule", v)} options={SYNC_SCHEDULE} />
        </Field>
        <Field label="Stale threshold" badge="--cve-stale-hours" hint="Refresh when cache older than this.">
          <NumberInput value={cfg.staleHours} onChange={(v) => set("staleHours", v || 1)} min={0.5} max={720} step={0.5} suffix="h" />
        </Field>
      </Section>

      <Section title="Multi-source merge" hint="Used when profile = Multi-source">
        <Field label="Source priority" hint="Highest first." span={2}>
          <TagInput
            value={cfg.sourcePriority}
            onChange={(v) => set("sourcePriority", v)}
            placeholder="cisa_kev,nvd_recent,..."
            normalize={(v) => v.trim().toLowerCase()}
            suggestions={SOURCE_SUGGESTIONS}
          />
        </Field>
        <Field label="Disable sources" hint="Excluded from the merge." span={2}>
          <TagInput
            value={cfg.disableSources}
            onChange={(v) => set("disableSources", v)}
            placeholder="osv_enriched"
            normalize={(v) => v.trim().toLowerCase()}
            suggestions={SOURCE_SUGGESTIONS}
          />
        </Field>
      </Section>

      <Section title="Asset-aware filtering" hint="Pre-rank CVEs by inferred asset/service relevance">
        <Field label="Enable" badge="--asset-aware-cves">
          <Toggle checked={cfg.assetAware} onChange={(v) => set("assetAware", v)} />
        </Field>
        <Field label="Minimum relevance score" badge="--asset-cve-min-score">
          <NumberInput value={cfg.assetMinScore} onChange={(v) => set("assetMinScore", v || 0)} min={0} max={100} />
        </Field>
        <Field label="Keep top fallback" badge="--asset-cve-keep-top">
          <NumberInput value={cfg.assetKeepTop} onChange={(v) => set("assetKeepTop", v || 1)} min={1} max={5000} step={10} />
        </Field>
      </Section>
    </div>
  );
}
