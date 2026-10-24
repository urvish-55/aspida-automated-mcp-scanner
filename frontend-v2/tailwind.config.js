/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ["class", '[data-theme="dark"]'],
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "hsl(var(--bg) / <alpha-value>)",
        panel: "hsl(var(--panel) / <alpha-value>)",
        raised: "hsl(var(--raised) / <alpha-value>)",
        line: "hsl(var(--line) / <alpha-value>)",
        fg: "hsl(var(--fg) / <alpha-value>)",
        dim: "hsl(var(--dim) / <alpha-value>)",
        brand: "hsl(var(--brand) / <alpha-value>)",
        sev: {
          critical: "hsl(var(--sev-critical) / <alpha-value>)",
          high: "hsl(var(--sev-high) / <alpha-value>)",
          medium: "hsl(var(--sev-medium) / <alpha-value>)",
          low: "hsl(var(--sev-low) / <alpha-value>)",
          info: "hsl(var(--sev-info) / <alpha-value>)",
        },
        ok: "hsl(var(--ok) / <alpha-value>)",
        warn: "hsl(var(--warn) / <alpha-value>)",
      },
      fontFamily: {
        sans: ['"Inter"', '"Segoe UI"', "system-ui", "-apple-system", "sans-serif"],
        mono: ['"JetBrains Mono"', '"Cascadia Code"', "ui-monospace", "Consolas", "monospace"],
      },
      boxShadow: { glow: "0 0 0 1px hsl(var(--brand) / 0.35), 0 0 24px -6px hsl(var(--brand) / 0.35)" },
      keyframes: {
        shimmer: { "100%": { transform: "translateX(100%)" } },
        pulseDot: { "0%,100%": { opacity: "1" }, "50%": { opacity: "0.35" } },
      },
      animation: { shimmer: "shimmer 1.6s infinite", pulseDot: "pulseDot 1.4s ease-in-out infinite" },
    },
  },
  plugins: [],
};
