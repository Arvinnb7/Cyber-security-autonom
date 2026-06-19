import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        ink: {
          950: "#070b14",
          900: "#0b1220",
          850: "#0f1828",
          800: "#131f33",
          700: "#1c2b45",
          600: "#27395a",
        },
        accent: { DEFAULT: "#38bdf8", soft: "#7dd3fc" },
        risk: {
          critical: "#f43f5e",
          high: "#fb923c",
          medium: "#facc15",
          low: "#34d399",
        },
      },
      fontFamily: {
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      boxShadow: {
        glow: "0 0 0 1px rgba(56,189,248,0.15), 0 8px 30px rgba(2,6,23,0.6)",
      },
    },
  },
  plugins: [],
};
export default config;
