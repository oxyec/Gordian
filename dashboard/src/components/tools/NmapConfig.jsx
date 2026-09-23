import Field from "../forms/Field.jsx";
import Section from "../forms/Section.jsx";
import Toggle from "../forms/Toggle.jsx";
import Select from "../forms/Select.jsx";
import NumberInput from "../forms/NumberInput.jsx";
import TextInput from "../forms/TextInput.jsx";
import TagInput from "../forms/TagInput.jsx";

const SCAN_TYPES = [
  { value: "-sS", label: "SYN (-sS)" },
  { value: "-sT", label: "Connect (-sT)" },
  { value: "-sU", label: "UDP (-sU)" },
  { value: "-sV", label: "Service (-sV)" },
  { value: "-sn", label: "Ping (-sn)" },
];

const TIMING = [
  { value: "-T0", label: "T0" },
  { value: "-T1", label: "T1" },
  { value: "-T2", label: "T2" },
  { value: "-T3", label: "T3" },
  { value: "-T4", label: "T4" },
  { value: "-T5", label: "T5" },
];

const PORT_SPEC = [
  { value: "top100", label: "Top 100" },
  { value: "top1000", label: "Top 1000" },
  { value: "all", label: "All 65535" },
  { value: "custom", label: "Custom" },
];

const SCRIPT_SUGGESTIONS = ["default", "vuln", "auth", "discovery", "intrusive", "safe", "exploit"];

export default function NmapConfig({ cfg, set }) {
  return (
    <div className="space-y-4">
      <Section title="Scan profile">
        <Field label="Enabled" hint="Disable to skip nmap entirely for this engagement.">
          <Toggle
            checked={cfg.enabled}
            onChange={(v) => set("enabled", v)}
          />
        </Field>
        <Field label="Binary path" hint="Use a custom build (e.g. /opt/nmap/bin/nmap).">
          <TextInput
            value={cfg.binary}
            onChange={(v) => set("binary", v)}
            placeholder="nmap"
            prefix="$"
          />
        </Field>
        <Field label="Scan type" hint="SYN is fastest but needs root.">
          <Select
            value={cfg.scanType}
            onChange={(v) => set("scanType", v)}
            options={SCAN_TYPES}
            pillCap={6}
          />
        </Field>
        <Field label="Timing" hint="T4 is the sweet spot. T0/T1 = paranoid, T5 = insane.">
          <Select
            value={cfg.timing}
            onChange={(v) => set("timing", v)}
            options={TIMING}
            pillCap={6}
          />
        </Field>
      </Section>

      <Section title="Discovery">
        <Field label="Port scope">
          <Select
            value={cfg.portSpec}
            onChange={(v) => set("portSpec", v)}
            options={PORT_SPEC}
          />
        </Field>
        <Field
          label="Custom ports"
          hint="Used only when port scope is set to Custom. Comma list or ranges (22,80,443,8000-9000)."
        >
          <TextInput
            value={cfg.customPorts}
            onChange={(v) => set("customPorts", v)}
            placeholder="22,80,443,8000-9000"
          />
        </Field>
        <Field label="Service detection (-sV)">
          <Toggle
            checked={cfg.serviceDetection}
            onChange={(v) => set("serviceDetection", v)}
          />
        </Field>
        <Field label="OS detection (-O)" hint="Requires raw sockets. Adds noise.">
          <Toggle
            checked={cfg.osDetection}
            onChange={(v) => set("osDetection", v)}
          />
        </Field>
        <Field label="Aggressive (-A)" hint="-O + -sV + scripts + traceroute. Loud.">
          <Toggle
            checked={cfg.aggressive}
            onChange={(v) => set("aggressive", v)}
          />
        </Field>
        <Field label="Skip ping (-Pn)" hint="Treat all hosts as up. Use behind firewalls.">
          <Toggle
            checked={cfg.skipPing}
            onChange={(v) => set("skipPing", v)}
          />
        </Field>
      </Section>

      <Section title="Scripts">
        <Field
          label="NSE scripts"
          hint="Comma-separated --script values. Suggestions are bundled categories."
          span={2}
        >
          <TagInput
            value={cfg.scripts}
            onChange={(v) => set("scripts", v)}
            placeholder="default,vuln,..."
            suggestions={SCRIPT_SUGGESTIONS}
          />
        </Field>
      </Section>

      <Section title="Throttle & escape hatch" hint="Maps to max_nmap_rate in OffensiveConfig">
        <Field label="Max packet rate" hint="0 = no cap. Honoured by --max-rate.">
          <NumberInput
            value={cfg.maxRate}
            onChange={(v) => set("maxRate", v || 0)}
            min={0}
            max={100000}
            step={10}
            suffix="pkt/s"
          />
        </Field>
        <Field label="Min parallelism">
          <NumberInput
            value={cfg.parallelism}
            onChange={(v) => set("parallelism", v || 0)}
            min={1}
            max={512}
            step={1}
            suffix="hosts"
          />
        </Field>
        <Field label="Extra args" badge="tool_extra_args.nmap" hint="Appended verbatim. Use carefully." span={2}>
          <TextInput
            value={cfg.extraArgs}
            onChange={(v) => set("extraArgs", v)}
            placeholder="--reason --open"
          />
        </Field>
        <Field
          label="Full command override"
          badge="tool_command_overrides.nmap"
          hint="Replaces the entire command. Placeholders: {target}, {url}, {host}."
          span={2}
        >
          <TextInput
            value={cfg.commandOverride}
            onChange={(v) => set("commandOverride", v)}
            placeholder="nmap -sV -T4 --top-ports 1000 {target} -oX -"
          />
        </Field>
      </Section>
    </div>
  );
}
