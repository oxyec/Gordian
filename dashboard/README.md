# ⚔️ Gordian // Tactical Console

> Cyberdeck UI for the Gordian attack-path engine.
> React + Vite + Tailwind. This is a **demo preview** using synthetic telemetry.
> Engage, Abort and Patch simulate local UI state. Real scans use the authenticated API or Go TUI.

```text
         /\
        /  \
       |    |
       |    |
     __|____|__        ____               _ _
    [==========]      / ___| ___  _ __ __| (_) __ _ _ __
        |  |         | |  _ / _ \| '__/ _` | |/ _` | '_ \
     o--|--|--o      | |_| | (_) | | | (_| | | (_| | | | |
    / \ |  | / \      \____|\___/|_|  \__,_|_|\__,_|_| |_|
   o---o|--|o---o
  / \ / |  | \ / \
 o---o  |  |  o---o
  \ / \ |  | / \ /
   o---o|--|o---o
    \ / |  | \ /
     o--|--|--o
        |  |
        \  /
         \/
```

---

## Stack

| Layer       | Choice                         |
|-------------|--------------------------------|
| Build       | Vite 6.4.3                     |
| Framework   | React 18                       |
| Styling     | Tailwind CSS 3 (JIT)           |
| Icons       | lucide-react                   |
| Transport   | Native `WebSocket` + JSON      |
| Backend dev | FastAPI on `127.0.0.1:8000`    |

No state libs, no UI kits, no router. Pure components, plain hooks.

---

## Quickstart

```bash
cd dashboard
npm install
npm run dev          # http://127.0.0.1:5173
```

The preview deliberately uses a synthetic event stream and does not connect to the API.
The event shapes below are an integration reference, not a claim of live scan control.
Future browser integration must exchange an authenticated HTTP request for a single-use
WebSocket ticket; never put the long-lived API key in URLs or browser storage.

```bash
npm run build        # production bundle → dashboard/dist
npm run preview      # serve the prod bundle on :4173
```

---

## Layout

```
┌──────────────────────────────────────────────────────────┐
│ Header     ⚔ GORDIAN v1.0   ●ACTIVE   OP // 192.0.2.42   │
├──────────────────────────────────────────────────────────┤
│ Mission Control  [target ____]  [stealth|balanced|aggr] │
├───────────────────────────────┬──────────────────────────┤
│ Live Event Stream             │ Remediation Priority     │
│   nmap / nuclei / ffuf        │   sortable, risk-bar     │
│   color-coded, auto-scroll    │   weaponized flag        │
├───────────────────────────────┴──────────────────────────┤
│ Attack Graph (SVG)  internet → dmz → app → 💎crown      │
└──────────────────────────────────────────────────────────┘
```

Single 12-col grid (`grid grid-cols-12`); collapses to one column under `lg`.

---

## File map

```
dashboard/
├── index.html              # entry, font preload, CRT theme color
├── vite.config.js          # /api proxy (HTTP + WS) → FastAPI
├── tailwind.config.js      # neon palette + boot/scan/blip keyframes
├── postcss.config.js
├── public/favicon.svg
└── src/
    ├── main.jsx            # ReactDOM root
    ├── App.jsx             # boot-splash gate → Dashboard
    ├── index.css           # Tailwind base + .panel/.btn/.chip primitives
    ├── components/
    │   ├── BootScreen.jsx       # ASCII art + boot log + ENGAGE
    │   ├── Header.jsx           # brand · status chip · UTC clock
    │   ├── Dashboard.jsx        # grid layout, wires hook → panels
    │   ├── MissionControl.jsx   # target input + mode selector + Engage
    │   ├── LiveEventStream.jsx  # filterable, pausable, color-coded log
    │   ├── RemediationTable.jsx # sortable CVE patch list with risk bar
    │   └── AttackGraph.jsx      # SVG kill-chain map (mock data)
    ├── hooks/
    │   ├── useWebSocket.js  # reconnect + mock-fallback stream hook
    │   └── useClock.js      # 1-Hz UTC ticker
    └── lib/
        └── mockData.js      # MOCK_EVENT_SOURCES, MOCK_REMEDIATIONS, MOCK_GRAPH
```

---

## Backend contract

The hook expects a JSON message per WS frame:

```json
{
  "ts": "2026-04-17T12:34:56.789Z",
  "tool": "nmap | nuclei | ffuf | engine | raw",
  "level": "info | warn | high | critical",
  "msg": "free-form text"
}
```

Anything extra is preserved on the event object and ignored by the renderer.

For the planned REST surface:

| Method | Path                | Purpose                              |
|--------|---------------------|--------------------------------------|
| WS     | `/api/v1/live`      | Live tool + engine event stream      |
| POST   | `/api/engage`       | `{target, mode}` → start engagement  |
| POST   | `/api/abort`        | Stop the running engagement          |
| GET    | `/api/remediations` | Ranked CVE patch candidates          |
| GET    | `/api/graph`        | Nodes + edges + current kill-chain   |

The mock data in `src/lib/mockData.js` mirrors these shapes so the UI can be
developed and reviewed before any backend work lands.

---

## Design language

| Token     | Value                  | Used for                          |
|-----------|------------------------|-----------------------------------|
| bg        | `slate-950` `#020617`  | Page + panel background           |
| panel     | `slate-900/70`         | Header strips                     |
| border    | `slate-800` `#1e293b`  | Every divider — sharp, no radius  |
| cyan      | `#22d3ee`              | Live / safe / brand               |
| orange    | `#fb923c`              | Warn · simulated mode             |
| red       | `#ef4444`              | Critical · kill-chain             |
| emerald   | `#34d399`              | Boot OK · stream pulse            |
| font      | JetBrains Mono         | Everything                        |

**Geometry rule:** no `rounded-*`. Every box is a rectangle. Glow is added via
`box-shadow` (`shadow-neon`, `shadow-warn`, `shadow-kill`) — never via blur on
the element itself.

**Motion rule:** subtle, never decorative.
- `pulseDot` for live indicators (1.4s)
- `boot` for log lines appearing
- `scanline` overlay on the boot CRT
- `dash` on the kill-chain edges
- `blip` on crown-jewel nodes

---

## Extending

Add a new panel:

1. Drop a component in `src/components/`.
2. Wrap its root in `<section className="panel">` so it picks up the chrome.
3. Use `panel-header` + `panel-title` for the strip.
4. Slot it into the grid in `Dashboard.jsx` with the right `lg:col-span-*`.

Add a new tool color in the live stream: extend `TOOL_STYLES` in
[`LiveEventStream.jsx`](src/components/LiveEventStream.jsx).

Wire a real backend action: replace the placeholder in `Dashboard.jsx`
(`handleEngage`, `handleAbort`, `handlePatch`) with `fetch("/api/...")` calls.
The Vite proxy already routes them to FastAPI in dev.

---

## License

MIT — same as the parent Gordian project.
