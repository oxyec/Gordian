import { useEffect, useState } from "react";

const ASCII_LOGO = `         /\\
        /  \\
       |    |
       |    |
     __|____|__        ____               _ _
    [==========]      / ___| ___  _ __ __| (_) __ _ _ __
        |  |         | |  _ / _ \\| '__/ _\` | |/ _\` | '_ \\
     o--|--|--o      | |_| | (_) | | | (_| | | (_| | | | |
    / \\ |  | / \\      \\____|\\___/|_|  \\__,_|_|\\__,_|_| |_|
   o---o|--|o---o
  / \\ / |  | \\ / \\
 o---o  |  |  o---o
  \\ / \\ |  | / \\ /
   o---o|--|o---o
    \\ / |  | \\ /
     o--|--|--o
        |  |
        \\  /
         \\/`;

const BOOT_LINES = [
  "[ OK ] cold-start sequence",
  "[ OK ] mounting graph kernel ........ Dijkstra v1.0",
  "[ OK ] loading CVE feed ............. NVD + EPSS + KEV",
  "[ OK ] orchestrator handshake ....... fastapi://127.0.0.1:8000",
  "[ OK ] streaming bus open ........... /api/v1/live",
  "[ OK ] tactical UI online ........... cyberdeck v1",
];

/**
 * Cold-boot splash. Animates BOOT_LINES line-by-line, then waits for the
 * user to commit before yielding to the dashboard. Pressing any key skips.
 */
export default function BootScreen({ onEnter }) {
  const [shown, setShown] = useState(0);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    if (shown >= BOOT_LINES.length) {
      const t = setTimeout(() => setReady(true), 250);
      return () => clearTimeout(t);
    }
    const t = setTimeout(() => setShown((s) => s + 1), 220);
    return () => clearTimeout(t);
  }, [shown]);

  useEffect(() => {
    const handler = (e) => {
      if (!ready) return;
      if (e.key === "Enter" || e.key === " ") onEnter();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [ready, onEnter]);

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-slate-950 grid-bg">
      <div className="scanlines" />
      <div className="relative z-10 mx-4 w-full max-w-3xl border border-slate-800 bg-slate-950/90 p-6 shadow-neon crt">
        <div className="mb-4 flex items-center justify-between border-b border-slate-800 pb-2 text-[11px] uppercase tracking-[0.25em] text-slate-500">
          <span className="text-cyan-400">// gordian.boot</span>
          <span className="flex items-center gap-2">
            <span className="live-dot" /> kernel online
          </span>
        </div>

        <pre className="select-none whitespace-pre text-[11px] leading-tight text-cyan-400/90 sm:text-xs">
          {ASCII_LOGO}
        </pre>

        <div className="mt-5 space-y-1 text-[12px] leading-relaxed text-slate-300">
          {BOOT_LINES.slice(0, shown).map((line, i) => (
            <div key={i} className="animate-boot">
              <span className="text-emerald-400">{line.slice(0, 6)}</span>
              <span>{line.slice(6)}</span>
            </div>
          ))}
          {shown < BOOT_LINES.length && (
            <div className="text-cyan-400 animate-pulse">_</div>
          )}
        </div>

        <div className="mt-6 flex items-center justify-between border-t border-slate-800 pt-4 text-[11px] uppercase tracking-[0.2em]">
          <div className="text-slate-500">
            {">"} a reasoning layer for vulnerability management
          </div>
          <button
            type="button"
            onClick={onEnter}
            disabled={!ready}
            className="btn-primary"
          >
            {ready ? "Engage Console ▶" : "Loading..."}
          </button>
        </div>
      </div>
    </div>
  );
}
