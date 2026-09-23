/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      fontFamily: {
        mono: [
          "JetBrains Mono",
          "Fira Code",
          "IBM Plex Mono",
          "Menlo",
          "ui-monospace",
          "monospace",
        ],
      },
      boxShadow: {
        neon: "0 0 0 1px rgba(34,211,238,0.45), 0 0 24px -6px rgba(34,211,238,0.55)",
        kill: "0 0 0 1px rgba(239,68,68,0.5), 0 0 24px -6px rgba(239,68,68,0.6)",
        warn: "0 0 0 1px rgba(251,146,60,0.45), 0 0 24px -6px rgba(251,146,60,0.55)",
      },
      keyframes: {
        flicker: {
          "0%,100%": { opacity: "1" },
          "45%": { opacity: "0.85" },
          "50%": { opacity: "0.55" },
          "55%": { opacity: "0.95" },
        },
        scanline: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100%)" },
        },
        pulseDot: {
          "0%,100%": { opacity: "1", boxShadow: "0 0 8px currentColor" },
          "50%": { opacity: "0.35", boxShadow: "0 0 0px currentColor" },
        },
        boot: {
          "0%": { opacity: "0", transform: "translateY(4px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        dash: {
          "0%": { strokeDashoffset: "100" },
          "100%": { strokeDashoffset: "0" },
        },
        blip: {
          "0%,100%": { transform: "scale(1)", opacity: "1" },
          "50%": { transform: "scale(1.6)", opacity: "0.4" },
        },
      },
      animation: {
        flicker: "flicker 4s linear infinite",
        scanline: "scanline 8s linear infinite",
        "pulse-dot": "pulseDot 1.4s ease-in-out infinite",
        boot: "boot 220ms ease-out both",
        dash: "dash 3s linear infinite",
        blip: "blip 1.8s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};
