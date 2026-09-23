/**
 * Single source of truth for every tunable in the dashboard.
 *
 * Field names mirror the Gordian CLI (main.py argparse) and OffensiveConfig
 * (src/offensive/config.py) so the JSON we POST to /api/config is drop-in
 * compatible with the backend.
 *
 * Each tool exports:
 *   id            stable identifier + storage key
 *   label, blurb  shown in the tab nav
 *   group         "core" | "offensive" | "ui" — used for grouping the rail
 *   defaults      starting values
 *   presets       quick-fire profiles ({name, patch})
 *   toCli(cfg)    array → joined into the live shell preview
 */

import { APPEARANCE, LAYOUT } from "./appearancePresets.js";

/* ------------------------------------------------------------------ Pipeline */
export const PIPELINE = {
  id: "pipeline",
  label: "Pipeline",
  blurb: "Network input · CVE feed · output",
  group: "core",
  defaults: {
    network: "data/sample_network.json",
    cves: "data/cve_feed.json",
    out: "reports",
    topPatches: 5,
    skipRemediation: false,
    failOnFindings: false,
    quiet: false,
    verbose: false,
    liveLog: true,
  },
  presets: [
    { name: "Default", patch: { topPatches: 5, skipRemediation: false, quiet: false, verbose: false } },
    { name: "CI Gate", patch: { failOnFindings: true, quiet: true, skipRemediation: false, topPatches: 10 } },
    { name: "Verbose", patch: { verbose: true, quiet: false, liveLog: true } },
    { name: "Fast",    patch: { skipRemediation: true, quiet: true, topPatches: 3 } },
  ],
  toCli(c) {
    const out = ["python", "main.py"];
    if (c.network) out.push("--network", c.network);
    if (c.cves) out.push("--cves", c.cves);
    if (c.out) out.push("--out", c.out);
    if (c.topPatches) out.push("--top-patches", String(c.topPatches));
    if (c.skipRemediation) out.push("--no-remediation");
    if (c.failOnFindings) out.push("--fail-on-findings");
    if (c.quiet) out.push("--quiet");
    if (c.verbose) out.push("-v");
    if (c.liveLog) out.push("--live-log");
    return out;
  },
};

/* ------------------------------------------------------------------ CVE feed */
export const CVE = {
  id: "cve",
  label: "CVE Feed",
  blurb: "Source · sync cadence · asset-aware filter",
  group: "core",
  defaults: {
    profile: "local",
    cacheDir: "data/cve_cache",
    autoDownload: true,
    maxItems: 2000,
    syncPolicy: "if-stale",
    syncSchedule: "off",
    staleHours: 24,
    osvLookupLimit: 80,
    sourcePriority: ["cisa_kev", "nvd_recent", "ghsa_recent", "osv_enriched"],
    disableSources: [],
    assetAware: false,
    assetMinScore: 2,
    assetKeepTop: 120,
  },
  presets: [
    { name: "Local",    patch: { profile: "local", autoDownload: false, syncPolicy: "never" } },
    { name: "Daily",    patch: { profile: "nvd_recent", syncSchedule: "daily", syncPolicy: "if-stale", staleHours: 24 } },
    { name: "Multi",    patch: { profile: "multi", syncPolicy: "if-stale", maxItems: 3000, osvLookupLimit: 120 } },
    { name: "KEV-Only", patch: { profile: "cisa_kev", assetAware: false, syncSchedule: "daily" } },
  ],
  toCli(c) {
    const out = [];
    if (c.profile) out.push("--cve-profile", c.profile);
    if (c.cacheDir) out.push("--cve-cache-dir", c.cacheDir);
    out.push(c.autoDownload ? "--cve-auto-download" : "--no-cve-auto-download");
    if (c.maxItems) out.push("--cve-max-items", String(c.maxItems));
    if (c.syncPolicy) out.push("--cve-sync-policy", c.syncPolicy);
    if (c.syncSchedule) out.push("--cve-sync-schedule", c.syncSchedule);
    if (c.staleHours) out.push("--cve-stale-hours", String(c.staleHours));
    if (c.osvLookupLimit) out.push("--cve-osv-lookup-limit", String(c.osvLookupLimit));
    if (c.sourcePriority?.length) out.push("--cve-source-priority", c.sourcePriority.join(","));
    if (c.disableSources?.length) out.push("--cve-disable-sources", c.disableSources.join(","));
    if (c.assetAware) {
      out.push("--asset-aware-cves");
      out.push("--asset-cve-min-score", String(c.assetMinScore));
      out.push("--asset-cve-keep-top", String(c.assetKeepTop));
    }
    return out;
  },
};

/* ------------------------------------------------------ Dashboard / Server */
export const SERVER = {
  id: "server",
  label: "Server",
  blurb: "Dashboard host · port · WS retention",
  group: "core",
  defaults: {
    enabled: true,
    host: "127.0.0.1",
    port: 8765,
    retainEvents: 2000,
    terminalApp: false,
    noIntro: false,
    introSpeed: 0.065,
  },
  presets: [
    { name: "Default", patch: { enabled: true, host: "127.0.0.1", port: 8765, retainEvents: 2000 } },
    { name: "LAN",     patch: { enabled: true, host: "0.0.0.0",   port: 8765, retainEvents: 5000 } },
    { name: "Headless",patch: { enabled: false, terminalApp: false, noIntro: true } },
  ],
  toCli(c) {
    const out = [];
    if (c.enabled) out.push("--dashboard-enable");
    if (c.host) out.push("--dashboard-host", c.host);
    if (c.port) out.push("--dashboard-port", String(c.port));
    if (c.retainEvents) out.push("--dashboard-retain-events", String(c.retainEvents));
    if (c.terminalApp) out.push("--terminal-app");
    if (c.noIntro) out.push("--no-intro");
    else if (c.introSpeed) out.push("--intro-speed", String(c.introSpeed));
    return out;
  },
};

/* ------------------------------------------------------ Offensive Hub global */
export const GLOBAL = {
  id: "global",
  label: "Hub",
  blurb: "Offensive hub · scope · safety · budgets",
  group: "offensive",
  defaults: {
    enabled: true,
    target: "",
    mode: "auto",                 // auto | manual | dry-run | disabled
    speed: "balanced",            // stealth | balanced | aggressive
    intensity: "medium",          // low | medium | high
    fullControl: false,
    offensiveDryRun: false,
    autoArmTools: true,
    maxConcurrency: 3,
    timeoutSeconds: 900,
    maxTotalTargets: 0,
    maxTotalCommands: 0,
    maxFindings: 0,
    maxRunSeconds: 0,
    maxFollowupTargets: 40,
    bugbountyMode: false,
    requireScopeMatch: false,
    directoryInjection: true,
    wordlistAutoDownload: true,
    wordlistStoreDir: "data/wordlists",
    scopePolicyFile: "",
    techHints: [],
    requestHeaders: [],
    allowedTimeWindows: [],
    offensiveConfig: "data/offensive_config.json",
  },
  presets: [
    { name: "Stealth",     patch: { mode: "auto",   speed: "stealth",    intensity: "low",    maxConcurrency: 2, requireScopeMatch: true, bugbountyMode: false, offensiveDryRun: false } },
    { name: "Balanced",    patch: { mode: "auto",   speed: "balanced",   intensity: "medium", maxConcurrency: 3 } },
    { name: "Aggressive",  patch: { mode: "auto",   speed: "aggressive", intensity: "high",   maxConcurrency: 8, requireScopeMatch: false } },
    { name: "Dry-Run",     patch: { mode: "dry-run", offensiveDryRun: true } },
    { name: "BugBounty",   patch: { mode: "auto", speed: "balanced", intensity: "medium", bugbountyMode: true, requireScopeMatch: true, maxConcurrency: 4 } },
    { name: "Disabled",    patch: { enabled: false, mode: "disabled" } },
  ],
  toCli(c) {
    const out = [];
    if (c.offensiveConfig) out.push("--offensive-config", c.offensiveConfig);
    if (c.mode) out.push("--offensive-mode", c.mode);
    if (c.target) out.push("--offensive-target", c.target);
    if (c.speed) out.push("--offensive-speed", c.speed);
    if (c.intensity) out.push("--offensive-intensity", c.intensity);
    if (c.bugbountyMode) out.push("--bugbounty-mode");
    if (c.requireScopeMatch) out.push("--require-scope-match");
    if (c.scopePolicyFile) out.push("--scope-file", c.scopePolicyFile);
    if (c.fullControl) out.push("--full-control");
    if (c.offensiveDryRun) out.push("--offensive-dry-run");
    if (!c.directoryInjection) out.push("--offensive-no-dir-inject");
    if (c.autoArmTools) out.push("--auto-arm-tools");
    if (c.wordlistStoreDir) out.push("--wordlist-store-dir", c.wordlistStoreDir);
    out.push(c.wordlistAutoDownload ? "--wordlist-auto-download" : "--no-wordlist-auto-download");
    if (c.maxTotalTargets > 0) out.push("--max-total-targets", String(c.maxTotalTargets));
    if (c.maxTotalCommands > 0) out.push("--max-total-commands", String(c.maxTotalCommands));
    if (c.maxFindings > 0) out.push("--max-findings", String(c.maxFindings));
    if (c.maxRunSeconds > 0) out.push("--max-run-seconds", String(c.maxRunSeconds));
    if (c.maxFollowupTargets > 0) out.push("--max-followup-targets", String(c.maxFollowupTargets));
    if (c.techHints?.length) out.push("--target-tech", c.techHints.join(","));
    (c.requestHeaders || []).forEach((h) => out.push("--request-header", `"${h}"`));
    (c.allowedTimeWindows || []).forEach((w) => out.push("--allowed-time-window", w));
    return out;
  },
};

/* --------------------------------------------------------------------- Nmap */
export const NMAP = {
  id: "nmap",
  label: "Nmap",
  blurb: "Network sweep + service fingerprinting",
  group: "offensive",
  binary: "nmap",
  defaults: {
    enabled: true,
    binary: "nmap",
    scanType: "-sS",
    timing: "-T4",
    portSpec: "top1000",
    customPorts: "",
    serviceDetection: true,
    osDetection: false,
    aggressive: false,
    skipPing: false,
    scripts: ["default"],
    maxRate: 0,
    parallelism: 32,
    extraArgs: "",
    commandOverride: "",
  },
  presets: [
    { name: "Quick",      patch: { scanType: "-sS", timing: "-T4", portSpec: "top100",  scripts: [],                  osDetection: false, aggressive: false } },
    { name: "Service",    patch: { scanType: "-sV", timing: "-T4", portSpec: "top1000", scripts: ["default"],         osDetection: false, aggressive: false } },
    { name: "Aggressive", patch: { scanType: "-sV", timing: "-T4", portSpec: "all",     scripts: ["default","vuln"],  osDetection: true,  aggressive: true  } },
    { name: "Stealth",    patch: { scanType: "-sS", timing: "-T2", portSpec: "top100",  scripts: [],                  osDetection: false, aggressive: false, skipPing: true, maxRate: 50 } },
  ],
  toCli(c) {
    if (!c.enabled) return [];
    if (c.commandOverride) return [c.commandOverride];
    const out = [c.binary || "nmap", c.scanType, c.timing];
    if (c.serviceDetection && c.scanType !== "-sV") out.push("-sV");
    if (c.osDetection) out.push("-O");
    if (c.aggressive) out.push("-A");
    if (c.skipPing) out.push("-Pn");
    if (c.scripts?.length) out.push(`--script=${c.scripts.join(",")}`);
    if (c.portSpec === "top100") out.push("--top-ports", "100");
    else if (c.portSpec === "top1000") out.push("--top-ports", "1000");
    else if (c.portSpec === "all") out.push("-p-");
    else if (c.portSpec === "custom" && c.customPorts) out.push("-p", c.customPorts);
    if (c.maxRate > 0) out.push("--max-rate", String(c.maxRate));
    if (c.parallelism > 0) out.push("--min-parallelism", String(c.parallelism));
    if (c.extraArgs) out.push(c.extraArgs);
    out.push("<TARGET>");
    return out;
  },
};

/* --------------------------------------------------------------------- FFUF */
export const FFUF = {
  id: "ffuf",
  label: "FFUF",
  blurb: "Content + parameter fuzzing",
  group: "offensive",
  binary: "ffuf",
  defaults: {
    enabled: true,
    binary: "ffuf",
    wordlist: "/usr/share/seclists/Discovery/Web-Content/common.txt",
    wordlistProfile: "default",
    extensions: ["php", "txt", "bak", "db", "env"],
    threads: 40,
    delayMs: 0,
    timeout: 10,
    matchCodes: ["200", "204", "301", "302", "307", "401", "403"],
    filterCodes: [],
    filterSize: "",
    filterWords: "",
    recursion: false,
    recursionDepth: 2,
    method: "GET",
    headers: ["User-Agent: gordian/1.0"],
    autoCalibrate: true,
    extraArgs: "",
    commandOverride: "",
  },
  presets: [
    { name: "Quick",   patch: { threads: 20, extensions: ["php","txt"], recursion: false, delayMs: 0 } },
    { name: "Deep",    patch: { threads: 60, extensions: ["php","txt","bak","db","env","old","zip"], recursion: true, recursionDepth: 3 } },
    { name: "Stealth", patch: { threads: 5,  delayMs: 250, recursion: false, autoCalibrate: true } },
  ],
  toCli(c) {
    if (!c.enabled) return [];
    if (c.commandOverride) return [c.commandOverride];
    const out = [c.binary || "ffuf", "-w", c.wordlist, "-u", "<TARGET>/FUZZ"];
    if (c.extensions?.length) out.push("-e", "." + c.extensions.join(",."));
    if (c.threads) out.push("-t", String(c.threads));
    if (c.delayMs > 0) out.push("-p", `${(c.delayMs / 1000).toFixed(2)}`);
    if (c.timeout) out.push("-timeout", String(c.timeout));
    if (c.matchCodes?.length) out.push("-mc", c.matchCodes.join(","));
    if (c.filterCodes?.length) out.push("-fc", c.filterCodes.join(","));
    if (c.filterSize) out.push("-fs", String(c.filterSize));
    if (c.filterWords) out.push("-fw", String(c.filterWords));
    if (c.recursion) out.push("-recursion", "-recursion-depth", String(c.recursionDepth));
    if (c.method && c.method !== "GET") out.push("-X", c.method);
    if (c.autoCalibrate) out.push("-ac");
    (c.headers || []).forEach((h) => out.push("-H", `"${h}"`));
    if (c.extraArgs) out.push(c.extraArgs);
    return out;
  },
};

/* --------------------------------------------------------------------- Nuclei */
export const NUCLEI = {
  id: "nuclei",
  label: "Nuclei",
  blurb: "Template-driven vulnerability matching",
  group: "offensive",
  binary: "nuclei",
  defaults: {
    enabled: true,
    binary: "nuclei",
    templatesPath: "",
    severity: ["high", "critical"],
    tags: ["cve", "exposure"],
    excludeTags: ["dos", "intrusive"],
    rateLimit: 150,
    bulkSize: 25,
    concurrency: 25,
    timeout: 5,
    retries: 1,
    followRedirects: true,
    includeRR: false,
    onlyKev: false,
    extraArgs: "",
    commandOverride: "",
  },
  presets: [
    { name: "Critical", patch: { severity: ["critical"], tags: ["cve"], onlyKev: true, rateLimit: 100 } },
    { name: "Default",  patch: { severity: ["high","critical"], tags: ["cve","exposure"], rateLimit: 150 } },
    { name: "Wide",     patch: { severity: ["info","low","medium","high","critical"], tags: ["cve","exposure","misconfig","tech"], rateLimit: 250 } },
  ],
  toCli(c) {
    if (!c.enabled) return [];
    if (c.commandOverride) return [c.commandOverride];
    const out = [c.binary || "nuclei", "-u", "<TARGET>"];
    if (c.templatesPath) out.push("-t", c.templatesPath);
    if (c.severity?.length) out.push("-s", c.severity.join(","));
    if (c.tags?.length) out.push("-tags", c.tags.join(","));
    if (c.excludeTags?.length) out.push("-etags", c.excludeTags.join(","));
    if (c.rateLimit) out.push("-rl", String(c.rateLimit));
    if (c.bulkSize) out.push("-bs", String(c.bulkSize));
    if (c.concurrency) out.push("-c", String(c.concurrency));
    if (c.timeout) out.push("-timeout", String(c.timeout));
    if (c.retries) out.push("-retries", String(c.retries));
    if (c.followRedirects) out.push("-fr");
    if (c.includeRR) out.push("-irr");
    if (c.onlyKev) out.push("-itags", "kev");
    if (c.extraArgs) out.push(c.extraArgs);
    return out;
  },
};

/* --------------------------------------------------------- Recon helper tools */
const RECON_TOOL_KEYS = [
  { key: "subfinder",    label: "Subfinder",    blurb: "Passive subdomain enum" },
  { key: "amass",        label: "Amass",        blurb: "Multi-source enum" },
  { key: "bbot",         label: "BBOT",         blurb: "Recon swiss-army" },
  { key: "katana",       label: "Katana",       blurb: "Crawl + endpoint discovery" },
  { key: "httpx",        label: "httpx",        blurb: "HTTP probe + tech detect" },
  { key: "secretfinder", label: "SecretFinder", blurb: "JS secret regex" },
  { key: "linkfinder",   label: "LinkFinder",   blurb: "JS endpoint extraction" },
  { key: "gitleaks",     label: "Gitleaks",     blurb: "Repo secret scan" },
  { key: "aquatone",     label: "Aquatone",     blurb: "Visual recon" },
  { key: "gowitness",    label: "Gowitness",    blurb: "Headless screenshots" },
];

const reconDefaults = Object.fromEntries(
  RECON_TOOL_KEYS.map(({ key }) => [
    key,
    { enabled: false, binary: key, extraArgs: "", commandOverride: "" },
  ])
);

export const RECON = {
  id: "recon",
  label: "Recon",
  blurb: "Subfinder · Amass · BBOT · Katana · httpx · …",
  group: "offensive",
  meta: RECON_TOOL_KEYS,
  defaults: reconDefaults,
  presets: [
    { name: "Off",     patch: Object.fromEntries(RECON_TOOL_KEYS.map(({ key }) => [key, { enabled: false, binary: key, extraArgs: "", commandOverride: "" }])) },
    { name: "Passive", patch: { subfinder: { enabled: true,  binary: "subfinder", extraArgs: "", commandOverride: "" },
                                amass:     { enabled: true,  binary: "amass",     extraArgs: "", commandOverride: "" },
                                httpx:     { enabled: true,  binary: "httpx",     extraArgs: "", commandOverride: "" } } },
    { name: "Full",    patch: Object.fromEntries(RECON_TOOL_KEYS.map(({ key }) => [key, { enabled: true, binary: key, extraArgs: "", commandOverride: "" }])) },
  ],
  toCli(cfg) {
    return RECON_TOOL_KEYS.flatMap(({ key }) => {
      const t = cfg[key];
      if (!t?.enabled) return [];
      if (t.commandOverride) return [`# ${key}: ${t.commandOverride}`];
      const args = t.extraArgs ? ` ${t.extraArgs}` : "";
      return [`# ${key}: ${t.binary}${args}`.trim()];
    });
  },
};

/* --------------------------------------------------------- Gordian Engine core */
export const ENGINE = {
  id: "engine",
  label: "Engine",
  blurb: "Gordian core · Dijkstra path scoring",
  group: "core",
  defaults: {
    algorithm: "dijkstra",
    cvssWeight: 0.5,
    epssWeight: 0.3,
    weaponizedBonus: 0.2,
    kevBonus: 0.15,
    maxHops: 6,
    recomputeMs: 5000,
    crownJewels: ["db-internal-04", "auth-svc-01"],
    treatPatchedAsBlocked: true,
    showAllPaths: false,
    pathBudget: 12,
  },
  presets: [
    { name: "Default",    patch: { algorithm: "dijkstra", cvssWeight: 0.5, epssWeight: 0.3, weaponizedBonus: 0.2 } },
    { name: "EPSS-Heavy", patch: { cvssWeight: 0.2, epssWeight: 0.6, weaponizedBonus: 0.2 } },
    { name: "KEV-Only",   patch: { kevBonus: 0.5, weaponizedBonus: 0.4, cvssWeight: 0.1 } },
  ],
  toCli(c) {
    return [
      "gordian",
      "--algo", c.algorithm,
      "--w-cvss", String(c.cvssWeight),
      "--w-epss", String(c.epssWeight),
      "--w-weap", String(c.weaponizedBonus),
      "--w-kev",  String(c.kevBonus),
      "--max-hops", String(c.maxHops),
      "--paths",   String(c.pathBudget),
      ...(c.crownJewels || []).flatMap((j) => ["--crown", j]),
      ...(c.treatPatchedAsBlocked ? ["--block-patched"] : []),
      ...(c.showAllPaths ? ["--all-paths"] : []),
    ];
  },
};

/* ----------------------------------------------------- Group + tool registry */
export const GROUPS = [
  { id: "core",      label: "Core" },
  { id: "offensive", label: "Offensive" },
  { id: "ui",        label: "Interface" },
];

// LAYOUT + APPEARANCE come pre-grouped from appearancePresets
LAYOUT.group = "ui";
APPEARANCE.group = "ui";

export const TOOLS = [
  PIPELINE,
  CVE,
  ENGINE,
  SERVER,
  GLOBAL,
  NMAP,
  FFUF,
  NUCLEI,
  RECON,
  LAYOUT,
  APPEARANCE,
];

/**
 * Map the merged config onto the OffensiveConfig JSON shape used by
 * src/offensive/config.py. Extra fields (pipeline/cve/server/recon/ui) ride
 * along under namespaced keys so the backend can consume them too.
 */
export function exportOffensiveConfig(state) {
  const g     = state.global   ?? GLOBAL.defaults;
  const nmap  = state.nmap     ?? NMAP.defaults;
  const ffuf  = state.ffuf     ?? FFUF.defaults;
  const nuc   = state.nuclei   ?? NUCLEI.defaults;
  const recon = state.recon    ?? RECON.defaults;

  const enabledTools = [
    nmap.enabled && "nmap",
    ffuf.enabled && "ffuf",
    nuc.enabled  && "nuclei",
    ...RECON_TOOL_KEYS.map(({ key }) => recon?.[key]?.enabled && key),
  ].filter(Boolean);

  const toolBinaries = {
    nmap: nmap.binary,
    ffuf: ffuf.binary,
    nuclei: nuc.binary,
    ...Object.fromEntries(
      RECON_TOOL_KEYS.map(({ key }) => [key, recon?.[key]?.binary || key])
    ),
  };

  const toArgs = (s) => (s ? s.split(/\s+/).filter(Boolean) : null);
  const toolExtraArgs = Object.fromEntries(
    [
      ["nmap",  toArgs(nmap.extraArgs)],
      ["ffuf",  toArgs(ffuf.extraArgs)],
      ["nuclei",toArgs(nuc.extraArgs)],
      ...RECON_TOOL_KEYS.map(({ key }) => [key, toArgs(recon?.[key]?.extraArgs)]),
    ].filter(([, v]) => v && v.length)
  );

  const toolCommandOverrides = Object.fromEntries(
    [
      ["nmap", nmap.commandOverride],
      ["ffuf", ffuf.commandOverride],
      ["nuclei", nuc.commandOverride],
      ...RECON_TOOL_KEYS.map(({ key }) => [key, recon?.[key]?.commandOverride]),
    ]
      .filter(([, v]) => v && v.trim())
      .map(([k, v]) => [k, [v]])
  );

  return {
    enabled: g.enabled,
    mode: g.mode,
    target: g.target || undefined,
    speed: g.speed,
    intensity: g.intensity,
    full_control: g.fullControl,
    max_concurrency: g.maxConcurrency,
    timeout_seconds: g.timeoutSeconds,
    directory_injection: g.directoryInjection,
    bugbounty_mode: g.bugbountyMode,
    require_scope_match: g.requireScopeMatch,
    wordlist_auto_download: g.wordlistAutoDownload,
    wordlist_store_dir: g.wordlistStoreDir,
    scope_policy_file: g.scopePolicyFile || undefined,
    tech_hints: g.techHints,
    request_headers: g.requestHeaders,
    allowed_time_windows: g.allowedTimeWindows,
    max_total_targets: g.maxTotalTargets || undefined,
    max_total_commands: g.maxTotalCommands || undefined,
    max_findings: g.maxFindings || undefined,
    max_run_seconds: g.maxRunSeconds || undefined,
    max_followup_targets: g.maxFollowupTargets,
    tools: enabledTools,
    tool_binaries: toolBinaries,
    tool_extra_args: toolExtraArgs,
    tool_command_overrides: toolCommandOverrides,
    ffuf_wordlist: ffuf.wordlist,
    ffuf_wordlist_profile: ffuf.wordlistProfile,
    ffuf_extensions: ffuf.extensions,
    max_ffuf_threads: ffuf.threads,
    max_nuclei_rate: nuc.rateLimit,
    max_nmap_rate: nmap.maxRate || undefined,
    nuclei_templates: nuc.templatesPath || undefined,

    // namespaced extras for the pipeline/CVE/server/UI surfaces
    _pipeline: state.pipeline,
    _cve: state.cve,
    _server: state.server,
    _engine: state.engine,
    _layout: state.layout,
    _appearance: state.appearance,
  };
}

export { RECON_TOOL_KEYS };
