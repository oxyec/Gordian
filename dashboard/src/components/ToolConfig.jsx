import { useMemo, useState } from "react";
import {
  Settings2,
  RotateCcw,
  Save,
  Copy,
  CheckCheck,
  Activity,
  Radar,
  FileSearch,
  ShieldAlert,
  GitBranch,
  Workflow,
  Database,
  ServerCog,
  Crosshair,
  Sparkles,
  LayoutDashboard,
} from "lucide-react";
import { TOOLS, GROUPS, exportOffensiveConfig } from "../lib/toolDefaults.js";
import GlobalConfig from "./tools/GlobalConfig.jsx";
import NmapConfig from "./tools/NmapConfig.jsx";
import FfufConfig from "./tools/FfufConfig.jsx";
import NucleiConfig from "./tools/NucleiConfig.jsx";
import EngineConfig from "./tools/EngineConfig.jsx";
import PipelineConfig from "./tools/PipelineConfig.jsx";
import CveConfig from "./tools/CveConfig.jsx";
import ServerConfig from "./tools/ServerConfig.jsx";
import ReconConfig from "./tools/ReconConfig.jsx";
import LayoutConfig from "./tools/LayoutConfig.jsx";
import AppearanceConfig from "./tools/AppearanceConfig.jsx";

const TAB_META = {
  pipeline:   { icon: Workflow,        accent: "text-cyan-300"    },
  cve:        { icon: Database,        accent: "text-emerald-300" },
  engine:     { icon: GitBranch,       accent: "text-emerald-400" },
  server:     { icon: ServerCog,       accent: "text-cyan-300"    },
  global:     { icon: Settings2,       accent: "text-cyan-300"    },
  nmap:       { icon: Radar,           accent: "text-cyan-300"    },
  ffuf:       { icon: FileSearch,      accent: "text-orange-300"  },
  nuclei:     { icon: ShieldAlert,     accent: "text-red-400"     },
  recon:      { icon: Crosshair,       accent: "text-violet-300"  },
  layout:     { icon: LayoutDashboard, accent: "text-cyan-300"    },
  appearance: { icon: Sparkles,        accent: "text-amber-300"   },
};

const PANELS = {
  pipeline: PipelineConfig,
  cve: CveConfig,
  engine: EngineConfig,
  server: ServerConfig,
  global: GlobalConfig,
  nmap: NmapConfig,
  ffuf: FfufConfig,
  nuclei: NucleiConfig,
  recon: ReconConfig,
  layout: LayoutConfig,
  appearance: AppearanceConfig,
};

// Tools whose top-level state has no `enabled` flag — never render an OFF chip.
const ALWAYS_ON = new Set(["pipeline", "cve", "engine", "global", "layout", "appearance", "recon"]);

/**
 * Tabbed configuration center. 11 tools split across 3 groups (Core /
 * Offensive / Interface). Each tab is its own isolated form powered by the
 * shared useToolConfig store. Footer streams the live CLI preview.
 */
export default function ToolConfig({ state, set, patch, reset, onSubmit }) {
  const [active, setActive] = useState("pipeline");
  const [copied, setCopied] = useState(false);

  const tool = useMemo(() => TOOLS.find((t) => t.id === active), [active]);
  const Panel = PANELS[active];
  const cfg = state[active];
  const cli = useMemo(() => tool?.toCli?.(cfg) ?? [], [tool, cfg]);
  const cliString = cli.join(" ");

  const grouped = useMemo(
    () =>
      GROUPS.map((g) => ({
        ...g,
        items: TOOLS.filter((t) => t.group === g.id),
      })),
    []
  );

  const copyCli = async () => {
    if (!cliString) return;
    try {
      await navigator.clipboard?.writeText(cliString);
      setCopied(true);
      setTimeout(() => setCopied(false), 1400);
    } catch {
      /* clipboard blocked — silent */
    }
  };

  const handlePreset = (presetPatch) => patch(active, presetPatch);

  const handleSubmit = () => {
    const payload = exportOffensiveConfig(state);
    onSubmit?.(payload);
  };

  return (
    <section className="panel flex h-full flex-col">
      <div className="panel-header">
        <div className="panel-title">
          <Settings2 className="h-3.5 w-3.5" />
          tool.config
          <span className="ml-2 text-slate-600">
            // {TOOLS.length} surfaces · persisted locally
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => reset(active)}
            className="btn-ghost"
            title={`Reset ${tool?.label ?? active} to defaults`}
          >
            <RotateCcw className="h-3 w-3" />
            Reset Tab
          </button>
          <button
            type="button"
            onClick={() => reset()}
            className="btn-danger"
            title="Reset every tool to defaults"
          >
            <RotateCcw className="h-3 w-3" />
            Reset All
          </button>
          <button
            type="button"
            onClick={handleSubmit}
            className="btn-primary"
            title="Send the merged config to /api/config"
          >
            <Save className="h-3 w-3" />
            Apply
          </button>
        </div>
      </div>

      <div className="grid flex-1 grid-cols-1 lg:grid-cols-[220px_1fr]">
        {/* Tab rail — grouped */}
        <nav className="flex flex-row gap-0 overflow-x-auto border-b border-slate-800 bg-slate-950/60 lg:flex-col lg:border-b-0 lg:border-r">
          {grouped.map((group) => (
            <div key={group.id} className="contents lg:block">
              <div className="hidden lg:flex items-center gap-2 border-b border-slate-800/60 bg-slate-900/40 px-3 py-1.5 text-[9px] uppercase tracking-[0.3em] text-slate-500">
                <span className="h-px flex-1 bg-slate-800" />
                <span>{group.label}</span>
                <span className="h-px w-3 bg-slate-800" />
              </div>
              {group.items.map((t) => {
                const meta = TAB_META[t.id] ?? { icon: Settings2, accent: "" };
                const Icon = meta.icon;
                const isActive = active === t.id;
                const enabled = ALWAYS_ON.has(t.id)
                  ? true
                  : Boolean(state[t.id]?.enabled);
                return (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() => setActive(t.id)}
                    className={`group relative flex w-full items-center gap-3 border-b border-slate-800/70 px-3 py-2.5 text-left transition-colors ${
                      isActive
                        ? "bg-cyan-400/10 text-cyan-300"
                        : "text-slate-400 hover:bg-slate-900/60 hover:text-cyan-300"
                    }`}
                  >
                    {isActive && (
                      <span className="absolute inset-y-0 left-0 w-0.5 bg-cyan-400 shadow-neon" />
                    )}
                    <Icon className={`h-4 w-4 ${isActive ? meta.accent : ""}`} />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 text-[12px] uppercase tracking-[0.2em]">
                        {t.label}
                        {!enabled && (
                          <span className="border border-slate-700 px-1 text-[8px] tracking-widest text-slate-600">
                            OFF
                          </span>
                        )}
                      </div>
                      <div className="truncate text-[10px] text-slate-600">
                        {t.blurb}
                      </div>
                    </div>
                    {isActive && (
                      <Activity className="h-3 w-3 text-cyan-400 animate-pulse" />
                    )}
                  </button>
                );
              })}
            </div>
          ))}
        </nav>

        {/* Panel body */}
        <div className="flex min-h-0 flex-col">
          {/* Preset bar */}
          {tool?.presets?.length > 0 && (
            <div className="flex flex-wrap items-center gap-2 border-b border-slate-800 bg-slate-900/40 px-4 py-2">
              <span className="text-[10px] uppercase tracking-[0.25em] text-slate-500">
                presets //
              </span>
              {tool.presets.map((p) => (
                <button
                  key={p.name}
                  type="button"
                  onClick={() => handlePreset(p.patch)}
                  className="border border-slate-800 px-2 py-0.5 text-[10px] uppercase tracking-widest text-slate-400 transition-colors hover:border-cyan-400 hover:text-cyan-300"
                >
                  {p.name}
                </button>
              ))}
            </div>
          )}

          {/* Form */}
          <div className="flex-1 overflow-y-auto p-4">
            {Panel && (
              <Panel
                cfg={cfg}
                set={(key, value) => set(active, key, value)}
              />
            )}
          </div>

          {/* CLI preview footer (hidden for pure-UI tools) */}
          {active !== "layout" && active !== "appearance" && (
            <div className="border-t border-slate-800 bg-slate-950/80 p-3">
              <div className="mb-2 flex items-center justify-between text-[10px] uppercase tracking-[0.25em] text-slate-500">
                <span>
                  cli.preview //{" "}
                  <span className="text-cyan-400">{tool?.id}</span>
                </span>
                <button
                  type="button"
                  onClick={copyCli}
                  disabled={!cliString}
                  className="btn-ghost"
                >
                  {copied ? (
                    <>
                      <CheckCheck className="h-3 w-3 text-emerald-400" />
                      Copied
                    </>
                  ) : (
                    <>
                      <Copy className="h-3 w-3" />
                      Copy
                    </>
                  )}
                </button>
              </div>
              <pre className="overflow-x-auto whitespace-pre-wrap break-all border border-slate-800 bg-slate-950 p-2 text-[11px] leading-relaxed text-emerald-300">
                {cliString || "// disabled — flip Enabled to render command"}
              </pre>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
