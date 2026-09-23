import Field from "../forms/Field.jsx";
import Section from "../forms/Section.jsx";
import Toggle from "../forms/Toggle.jsx";
import Select from "../forms/Select.jsx";
import NumberInput from "../forms/NumberInput.jsx";
import TextInput from "../forms/TextInput.jsx";
import TagInput from "../forms/TagInput.jsx";

const MODES = [
  { value: "auto",     label: "Auto" },
  { value: "manual",   label: "Manual" },
  { value: "dry-run",  label: "Dry-Run" },
  { value: "disabled", label: "Disabled" },
];
const SPEEDS = [
  { value: "stealth",    label: "Stealth" },
  { value: "balanced",   label: "Balanced" },
  { value: "aggressive", label: "Aggressive" },
];
const INTENSITIES = [
  { value: "low",    label: "Low" },
  { value: "medium", label: "Medium" },
  { value: "high",   label: "High" },
];

export default function GlobalConfig({ cfg, set }) {
  return (
    <div className="space-y-4">
      <Section title="Engagement posture" hint="Maps to OffensiveConfig.{enabled,mode,speed,intensity}">
        <Field label="Hub enabled" hint="OFF skips the entire offensive pipeline.">
          <Toggle checked={cfg.enabled} onChange={(v) => set("enabled", v)} />
        </Field>
        <Field label="Mode" badge="--offensive-mode">
          <Select value={cfg.mode} onChange={(v) => set("mode", v)} options={MODES} pillCap={4} />
        </Field>
        <Field label="Speed" badge="--offensive-speed">
          <Select value={cfg.speed} onChange={(v) => set("speed", v)} options={SPEEDS} />
        </Field>
        <Field label="Intensity" badge="--offensive-intensity">
          <Select value={cfg.intensity} onChange={(v) => set("intensity", v)} options={INTENSITIES} />
        </Field>
        <Field label="Target override" badge="--offensive-target" hint="Hostname / IP / CIDR / URL." span={2}>
          <TextInput
            value={cfg.target}
            onChange={(v) => set("target", v)}
            placeholder="example.com or 10.0.0.0/24"
          />
        </Field>
        <Field label="Dry-run only" badge="--offensive-dry-run" hint="Build commands, stream intent, never execute.">
          <Toggle checked={cfg.offensiveDryRun} onChange={(v) => set("offensiveDryRun", v)} />
        </Field>
        <Field label="Full control" badge="--full-control" hint="Disallow simulated execution. Requires real target.">
          <Toggle checked={cfg.fullControl} onChange={(v) => set("fullControl", v)} />
        </Field>
        <Field label="Auto-arm tools" badge="--auto-arm-tools" hint="Auto-install missing core tools (Linux/WSL).">
          <Toggle checked={cfg.autoArmTools} onChange={(v) => set("autoArmTools", v)} />
        </Field>
        <Field label="Directory injection" badge="--offensive-no-dir-inject" hint="Feed ffuf paths back as graph findings.">
          <Toggle checked={cfg.directoryInjection} onChange={(v) => set("directoryInjection", v)} />
        </Field>
      </Section>

      <Section title="Concurrency & timeouts">
        <Field label="Max concurrency">
          <NumberInput value={cfg.maxConcurrency} onChange={(v) => set("maxConcurrency", v || 1)} min={1} max={64} />
        </Field>
        <Field label="Per-command timeout">
          <NumberInput value={cfg.timeoutSeconds} onChange={(v) => set("timeoutSeconds", v || 10)} min={10} max={3600} step={10} suffix="s" />
        </Field>
        <Field label="Max run wallclock" badge="--max-run-seconds" hint="0 = no cap.">
          <NumberInput value={cfg.maxRunSeconds} onChange={(v) => set("maxRunSeconds", v || 0)} min={0} max={86400} step={60} suffix="s" />
        </Field>
        <Field label="Max followup targets" badge="--max-followup-targets">
          <NumberInput value={cfg.maxFollowupTargets} onChange={(v) => set("maxFollowupTargets", v || 1)} min={1} max={10000} />
        </Field>
      </Section>

      <Section title="Budgets" hint="Hard ceilings — engagement aborts when any limit is hit. 0 = no cap.">
        <Field label="Max total targets" badge="--max-total-targets">
          <NumberInput value={cfg.maxTotalTargets} onChange={(v) => set("maxTotalTargets", v || 0)} min={0} max={100000} step={10} />
        </Field>
        <Field label="Max total commands" badge="--max-total-commands">
          <NumberInput value={cfg.maxTotalCommands} onChange={(v) => set("maxTotalCommands", v || 0)} min={0} max={100000} step={10} />
        </Field>
        <Field label="Max findings" badge="--max-findings">
          <NumberInput value={cfg.maxFindings} onChange={(v) => set("maxFindings", v || 0)} min={0} max={100000} step={10} />
        </Field>
      </Section>

      <Section title="Scope & safety">
        <Field label="Require scope match" badge="--require-scope-match">
          <Toggle checked={cfg.requireScopeMatch} onChange={(v) => set("requireScopeMatch", v)} />
        </Field>
        <Field label="BugBounty mode" badge="--bugbounty-mode" hint="X-Bug-Bounty header, slower defaults, scope enforced.">
          <Toggle checked={cfg.bugbountyMode} onChange={(v) => set("bugbountyMode", v)} />
        </Field>
        <Field label="Scope policy file" badge="--scope-file" span={2}>
          <TextInput value={cfg.scopePolicyFile} onChange={(v) => set("scopePolicyFile", v)} placeholder="data/scope.json" />
        </Field>
        <Field label="Allowed time windows" badge="--allowed-time-window" hint="UTC, format HH:MM-HH:MM. Multiple chips allowed." span={2}>
          <TagInput
            value={cfg.allowedTimeWindows}
            onChange={(v) => set("allowedTimeWindows", v)}
            placeholder="22:00-06:00"
            validate={(v) => /^\d{2}:\d{2}-\d{2}:\d{2}$/.test(v)}
          />
        </Field>
      </Section>

      <Section title="Wordlists & hints">
        <Field label="Auto-download wordlists" badge="--wordlist-auto-download">
          <Toggle checked={cfg.wordlistAutoDownload} onChange={(v) => set("wordlistAutoDownload", v)} />
        </Field>
        <Field label="Wordlist store dir" badge="--wordlist-store-dir">
          <TextInput value={cfg.wordlistStoreDir} onChange={(v) => set("wordlistStoreDir", v)} placeholder="data/wordlists" />
        </Field>
        <Field label="Tech hints" badge="--target-tech" hint="Pre-seed orchestrator with detected tech." span={2}>
          <TagInput
            value={cfg.techHints}
            onChange={(v) => set("techHints", v)}
            placeholder="wordpress,nginx"
            normalize={(v) => v.trim().toLowerCase()}
            suggestions={["nginx", "apache", "wordpress", "drupal", "joomla", "laravel", "django", "rails", "spring", "api"]}
          />
        </Field>
        <Field label="Request headers" badge="--request-header" hint="Applied to ffuf/nuclei/katana/httpx. Format: 'Key: Value'." span={2}>
          <TagInput
            value={cfg.requestHeaders}
            onChange={(v) => set("requestHeaders", v)}
            placeholder="X-Bug-Bounty: gordian"
            validate={(v) => /^[A-Za-z][\w-]*:\s?.+/.test(v)}
          />
        </Field>
      </Section>

      <Section title="Source files">
        <Field label="Offensive config JSON" badge="--offensive-config" span={2}>
          <TextInput value={cfg.offensiveConfig} onChange={(v) => set("offensiveConfig", v)} placeholder="data/offensive_config.json" />
        </Field>
      </Section>
    </div>
  );
}
