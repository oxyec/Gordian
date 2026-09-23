import Field from "../forms/Field.jsx";
import Section from "../forms/Section.jsx";
import Toggle from "../forms/Toggle.jsx";
import NumberInput from "../forms/NumberInput.jsx";
import TextInput from "../forms/TextInput.jsx";

export default function ServerConfig({ cfg, set }) {
  return (
    <div className="space-y-4">
      <Section title="Dashboard server" hint="Maps to --dashboard-* CLI flags">
        <Field label="Enable WS server" badge="--dashboard-enable">
          <Toggle checked={cfg.enabled} onChange={(v) => set("enabled", v)} />
        </Field>
        <Field label="Bind host" badge="--dashboard-host" hint="Use 0.0.0.0 to expose to LAN. Treat as untrusted.">
          <TextInput value={cfg.host} onChange={(v) => set("host", v)} placeholder="127.0.0.1" />
        </Field>
        <Field label="Port" badge="--dashboard-port">
          <NumberInput value={cfg.port} onChange={(v) => set("port", v || 1)} min={1} max={65535} />
        </Field>
        <Field label="Retain events" badge="--dashboard-retain-events" hint="WS bootstrap + /events buffer length.">
          <NumberInput value={cfg.retainEvents} onChange={(v) => set("retainEvents", v || 1)} min={10} max={100000} step={100} />
        </Field>
      </Section>

      <Section title="Terminal companion">
        <Field label="Launch terminal app" badge="--terminal-app" hint="Interactive Rich-based menu mode.">
          <Toggle checked={cfg.terminalApp} onChange={(v) => set("terminalApp", v)} />
        </Field>
        <Field label="Skip Rich intro" badge="--no-intro">
          <Toggle checked={cfg.noIntro} onChange={(v) => set("noIntro", v)} />
        </Field>
        <Field label="Intro line speed" badge="--intro-speed" hint="Seconds per line for the boot animation.">
          <NumberInput
            value={cfg.introSpeed}
            onChange={(v) => set("introSpeed", v || 0.001)}
            min={0.001}
            max={2}
            step={0.005}
            suffix="s"
          />
        </Field>
      </Section>
    </div>
  );
}
