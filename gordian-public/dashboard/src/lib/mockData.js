// Mock data — used during dev when the FastAPI WebSocket isn't running.
// The shapes mirror the JSON contract emitted by /api/v1/live.

export const MOCK_EVENT_SOURCES = [
  { tool: "nmap", level: "info", msg: "TCP/443 open on dmz-edge-01" },
  { tool: "nmap", level: "info", msg: "Service detect: nginx 1.18.0 (Ubuntu)" },
  { tool: "nuclei", level: "high", msg: "CVE-2023-44487 (HTTP/2 Rapid Reset) MATCHED" },
  { tool: "nuclei", level: "critical", msg: "CVE-2024-3094 backdoor signature on db-internal-04" },
  { tool: "ffuf", level: "warn", msg: "Found /admin (302) on app-prod-02" },
  { tool: "engine", level: "info", msg: "Dijkstra recompute → 12 paths, best cost 3.4" },
  { tool: "engine", level: "info", msg: "Patching CVE-2023-44487 cuts 7/12 kill-chains" },
  { tool: "engine", level: "warn", msg: "Crown-jewel reachable via 2 hops from internet" },
  { tool: "ffuf", level: "info", msg: "Wordlist exhausted on auth-svc-01 (no findings)" },
  { tool: "nmap", level: "info", msg: "OS guess: Linux 5.x kernel on db-internal-04" },
];

export const MOCK_REMEDIATIONS = [
  {
    cve: "CVE-2024-3094",
    host: "db-internal-04",
    riskReduction: 42.7,
    cvss: 10.0,
    epss: 0.97,
    weaponized: true,
    status: "READY",
  },
  {
    cve: "CVE-2023-44487",
    host: "dmz-edge-01",
    riskReduction: 31.2,
    cvss: 7.5,
    epss: 0.94,
    weaponized: true,
    status: "QUEUED",
  },
  {
    cve: "CVE-2023-22515",
    host: "app-prod-02",
    riskReduction: 18.4,
    cvss: 9.8,
    epss: 0.81,
    weaponized: true,
    status: "PATCHING",
  },
  {
    cve: "CVE-2024-21413",
    host: "mail-relay-01",
    riskReduction: 11.9,
    cvss: 9.8,
    epss: 0.42,
    weaponized: false,
    status: "READY",
  },
  {
    cve: "CVE-2022-26134",
    host: "wiki-internal",
    riskReduction: 6.1,
    cvss: 9.8,
    epss: 0.88,
    weaponized: true,
    status: "DEFERRED",
  },
];

export const MOCK_GRAPH = {
  nodes: [
    { id: "internet", label: "INTERNET", x: 60, y: 140, kind: "external" },
    { id: "dmz-edge-01", label: "dmz-edge-01", x: 220, y: 80, kind: "edge" },
    { id: "app-prod-02", label: "app-prod-02", x: 400, y: 60, kind: "app" },
    { id: "auth-svc-01", label: "auth-svc-01", x: 400, y: 200, kind: "app" },
    { id: "db-internal-04", label: "db-internal-04", x: 600, y: 130, kind: "crown" },
    { id: "mail-relay-01", label: "mail-relay-01", x: 220, y: 220, kind: "edge" },
  ],
  edges: [
    { from: "internet", to: "dmz-edge-01", cost: 1.0, cve: "CVE-2023-44487" },
    { from: "internet", to: "mail-relay-01", cost: 2.4, cve: "CVE-2024-21413" },
    { from: "dmz-edge-01", to: "app-prod-02", cost: 0.8, cve: "CVE-2023-22515" },
    { from: "app-prod-02", to: "auth-svc-01", cost: 1.1, cve: null },
    { from: "auth-svc-01", to: "db-internal-04", cost: 0.6, cve: "CVE-2024-3094" },
    { from: "app-prod-02", to: "db-internal-04", cost: 1.4, cve: "CVE-2024-3094" },
  ],
  killChain: ["internet", "dmz-edge-01", "app-prod-02", "db-internal-04"],
};

let mockTimer = null;

/**
 * Streams mock events into a callback at a steady cadence.
 * Returns a stop() function. Used as a fallback when the WS endpoint is down.
 */
export function startMockStream(onEvent, intervalMs = 1400) {
  let i = 0;
  stopMockStream();
  mockTimer = setInterval(() => {
    const tpl = MOCK_EVENT_SOURCES[i % MOCK_EVENT_SOURCES.length];
    onEvent({
      ...tpl,
      ts: new Date().toISOString(),
      id: `mock-${Date.now()}-${i}`,
    });
    i += 1;
  }, intervalMs);
  return stopMockStream;
}

export function stopMockStream() {
  if (mockTimer) {
    clearInterval(mockTimer);
    mockTimer = null;
  }
}
