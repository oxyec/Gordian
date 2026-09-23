import Field from "../forms/Field.jsx";
import Section from "../forms/Section.jsx";
import Toggle from "../forms/Toggle.jsx";
import Select from "../forms/Select.jsx";
import NumberInput from "../forms/NumberInput.jsx";
import TextInput from "../forms/TextInput.jsx";
import TagInput from "../forms/TagInput.jsx";
import Slider from "../forms/Slider.jsx";

const PROFILES = [
  { value: "default", label: "Default" },
  { value: "common", label: "Common" },
  { value: "raft", label: "RAFT" },
  { value: "big", label: "Big" },
  { value: "custom", label: "Custom" },
];

const METHODS = [
  { value: "GET", label: "GET" },
  { value: "POST", label: "POST" },
  { value: "PUT", label: "PUT" },
  { value: "DELETE", label: "DELETE" },
  { value: "HEAD", label: "HEAD" },
];

const EXT_SUGGESTIONS = ["php", "asp", "aspx", "jsp", "txt", "bak", "db", "env", "old", "zip", "tar.gz", "json", "xml"];
const CODE_SUGGESTIONS = ["200", "201", "204", "301", "302", "307", "401", "403", "405", "500"];

export default function FfufConfig({ cfg, set }) {
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
            placeholder="ffuf"
            prefix="$"
          />
        </Field>
        <Field label="HTTP method">
          <Select
            value={cfg.method}
            onChange={(v) => set("method", v)}
            options={METHODS}
            pillCap={5}
          />
        </Field>
        <Field label="Auto calibrate (-ac)" hint="Auto-detect bogus 'found' responses.">
          <Toggle
            checked={cfg.autoCalibrate}
            onChange={(v) => set("autoCalibrate", v)}
          />
        </Field>
      </Section>

      <Section title="Wordlist" hint="Maps to ffuf_wordlist + ffuf_wordlist_profile">
        <Field label="Profile">
          <Select
            value={cfg.wordlistProfile}
            onChange={(v) => set("wordlistProfile", v)}
            options={PROFILES}
          />
        </Field>
        <Field label="Path" hint="Used when profile = Custom, or to override the bundled list.">
          <TextInput
            value={cfg.wordlist}
            onChange={(v) => set("wordlist", v)}
            placeholder="/usr/share/seclists/Discovery/Web-Content/common.txt"
          />
        </Field>
        <Field label="Extensions" hint="Maps to ffuf_extensions. Empty list = no -e flag." span={2}>
          <TagInput
            value={cfg.extensions}
            onChange={(v) => set("extensions", v)}
            placeholder="php,bak,db,env"
            normalize={(v) => v.replace(/^\.+/, "").trim().toLowerCase()}
            suggestions={EXT_SUGGESTIONS}
          />
        </Field>
      </Section>

      <Section title="Performance">
        <Field label="Threads (-t)" hint="Maps to max_ffuf_threads.">
          <Slider
            value={cfg.threads}
            onChange={(v) => set("threads", v)}
            min={1}
            max={200}
            step={1}
            suffix="thr"
            marks={["1", "50", "100", "200"]}
          />
        </Field>
        <Field label="Per-request delay (-p)">
          <NumberInput
            value={cfg.delayMs}
            onChange={(v) => set("delayMs", v || 0)}
            min={0}
            max={5000}
            step={50}
            suffix="ms"
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
        <Field label="Recursion (-recursion)">
          <Toggle
            checked={cfg.recursion}
            onChange={(v) => set("recursion", v)}
          />
        </Field>
        {cfg.recursion && (
          <Field label="Recursion depth">
            <NumberInput
              value={cfg.recursionDepth}
              onChange={(v) => set("recursionDepth", v || 1)}
              min={1}
              max={10}
              suffix="lvl"
            />
          </Field>
        )}
      </Section>

      <Section title="Match / filter">
        <Field label="Match status (-mc)">
          <TagInput
            value={cfg.matchCodes}
            onChange={(v) => set("matchCodes", v)}
            placeholder="200,301"
            normalize={(v) => v.trim()}
            validate={(v) => /^[0-9]{3}$/.test(v)}
            suggestions={CODE_SUGGESTIONS}
          />
        </Field>
        <Field label="Filter status (-fc)">
          <TagInput
            value={cfg.filterCodes}
            onChange={(v) => set("filterCodes", v)}
            placeholder="404,500"
            normalize={(v) => v.trim()}
            validate={(v) => /^[0-9]{3}$/.test(v)}
            suggestions={CODE_SUGGESTIONS}
          />
        </Field>
        <Field label="Filter size (-fs)" hint="Drop responses with this exact body length.">
          <TextInput
            value={cfg.filterSize}
            onChange={(v) => set("filterSize", v)}
            placeholder="0,3104"
          />
        </Field>
        <Field label="Filter words (-fw)">
          <TextInput
            value={cfg.filterWords}
            onChange={(v) => set("filterWords", v)}
            placeholder="42"
          />
        </Field>
      </Section>

      <Section title="Headers & escape" hint="Maps to request_headers in OffensiveConfig">
        <Field label="HTTP headers" hint="One per chip. Format: 'Name: value'." span={2}>
          <TagInput
            value={cfg.headers}
            onChange={(v) => set("headers", v)}
            placeholder='X-Bug-Bounty: gordian-test'
            validate={(v) => /^[A-Za-z][\w-]*:\s?.+/.test(v)}
          />
        </Field>
        <Field label="Extra args" badge="tool_extra_args.ffuf" span={2}>
          <TextInput
            value={cfg.extraArgs}
            onChange={(v) => set("extraArgs", v)}
            placeholder="-noninteractive -of json"
          />
        </Field>
        <Field
          label="Full command override"
          badge="tool_command_overrides.ffuf"
          hint="Placeholders: {target}, {url}, {fuzz_url}, {wordlist}."
          span={2}
        >
          <TextInput
            value={cfg.commandOverride}
            onChange={(v) => set("commandOverride", v)}
            placeholder="ffuf -u {fuzz_url} -w {wordlist} -t 40"
          />
        </Field>
      </Section>
    </div>
  );
}
