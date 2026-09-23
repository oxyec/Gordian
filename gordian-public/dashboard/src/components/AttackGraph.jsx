import { useMemo } from "react";
import { GitBranch, Crown, Globe, Server, Shield } from "lucide-react";

const NODE_STYLE = {
  external: { fill: "#0f172a", stroke: "#fb923c", text: "#fb923c", icon: Globe, label: "EXT" },
  edge: { fill: "#0f172a", stroke: "#22d3ee", text: "#22d3ee", icon: Shield, label: "EDGE" },
  app: { fill: "#0f172a", stroke: "#94a3b8", text: "#cbd5e1", icon: Server, label: "APP" },
  crown: { fill: "#1f0a10", stroke: "#ef4444", text: "#ef4444", icon: Crown, label: "CROWN" },
};

/**
 * Static SVG kill-chain map. The Dijkstra path from the engine is highlighted
 * red with an animated dash so the operator's eye tracks it instantly.
 *
 * NOTE: positions are pre-computed in mockData; a future iteration will pull
 * a real layout (force-directed) from the backend graph endpoint.
 */
export default function AttackGraph({ graph }) {
  const { nodes, edges, killChain } = graph;
  const nodeMap = useMemo(
    () => Object.fromEntries(nodes.map((n) => [n.id, n])),
    [nodes]
  );
  const killSet = useMemo(() => {
    const set = new Set();
    for (let i = 0; i < killChain.length - 1; i += 1) {
      set.add(`${killChain[i]}→${killChain[i + 1]}`);
    }
    return set;
  }, [killChain]);

  const isKill = (e) => killSet.has(`${e.from}→${e.to}`);

  return (
    <section className="panel flex h-full flex-col">
      <div className="panel-header">
        <div className="panel-title">
          <GitBranch className="h-3.5 w-3.5" />
          attack.graph
          <span className="ml-2 text-slate-600">dijkstra · cheapest paths</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="chip">
            <span className="h-1.5 w-1.5 bg-accent" /> safe
          </span>
          <span className="chip chip-crit">
            <span className="h-1.5 w-1.5 bg-red-500" /> kill-chain
          </span>
        </div>
      </div>

      <div className="relative flex-1 overflow-hidden bg-slate-950">
        <div className="pointer-events-none absolute inset-0 grid-bg opacity-60" />
        <svg viewBox="0 0 700 280" className="relative h-full w-full">
          <defs>
            <marker
              id="arrow"
              viewBox="0 0 10 10"
              refX="9"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M0,0 L10,5 L0,10 z" fill="#475569" />
            </marker>
            <marker
              id="arrow-kill"
              viewBox="0 0 10 10"
              refX="9"
              refY="5"
              markerWidth="7"
              markerHeight="7"
              orient="auto-start-reverse"
            >
              <path d="M0,0 L10,5 L0,10 z" fill="#ef4444" />
            </marker>
            <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="2.4" result="b" />
              <feMerge>
                <feMergeNode in="b" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {edges.map((e) => {
            const a = nodeMap[e.from];
            const b = nodeMap[e.to];
            if (!a || !b) return null;
            const kill = isKill(e);
            const stroke = kill ? "#ef4444" : "#334155";
            const dash = kill ? "6 4" : "2 4";
            const midX = (a.x + b.x) / 2;
            const midY = (a.y + b.y) / 2;
            return (
              <g key={`${e.from}-${e.to}`}>
                <line
                  x1={a.x}
                  y1={a.y}
                  x2={b.x}
                  y2={b.y}
                  stroke={stroke}
                  strokeWidth={kill ? 1.6 : 1}
                  strokeDasharray={dash}
                  markerEnd={kill ? "url(#arrow-kill)" : "url(#arrow)"}
                  filter={kill ? "url(#glow)" : undefined}
                  className={kill ? "animate-dash" : undefined}
                  style={kill ? { strokeDashoffset: 0 } : undefined}
                />
                <text
                  x={midX}
                  y={midY - 6}
                  textAnchor="middle"
                  className="fill-slate-500"
                  style={{ fontSize: 9, letterSpacing: 1 }}
                >
                  {e.cve ? `${e.cve} · ${e.cost.toFixed(1)}` : `cost ${e.cost.toFixed(1)}`}
                </text>
              </g>
            );
          })}

          {nodes.map((n) => {
            const s = NODE_STYLE[n.kind];
            const onKill = killChain.includes(n.id);
            return (
              <g key={n.id} transform={`translate(${n.x},${n.y})`}>
                {onKill && (
                  <circle
                    r={22}
                    fill="none"
                    stroke={s.stroke}
                    strokeOpacity={0.5}
                    className="animate-blip"
                  />
                )}
                <rect
                  x={-46}
                  y={-16}
                  width={92}
                  height={32}
                  fill={s.fill}
                  stroke={s.stroke}
                  strokeWidth={1.2}
                />
                <text
                  x={-38}
                  y={-2}
                  fill={s.text}
                  style={{ fontSize: 8, letterSpacing: 1.5 }}
                >
                  {s.label}
                </text>
                <text
                  x={-38}
                  y={11}
                  fill="#cbd5e1"
                  style={{ fontSize: 10 }}
                >
                  {n.label}
                </text>
              </g>
            );
          })}
        </svg>

        {/* HUD overlay */}
        <div className="pointer-events-none absolute bottom-2 left-2 border border-slate-800 bg-slate-950/80 px-2 py-1 text-[10px] uppercase tracking-widest text-slate-500">
          <span className="text-accent">path:</span>{" "}
          {killChain.join(" → ")}
        </div>
      </div>
    </section>
  );
}
