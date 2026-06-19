"use client";

import { RadialBar, RadialBarChart, PolarAngleAxis, ResponsiveContainer } from "recharts";
import { riskBand, riskColor } from "@/lib/api";

export default function RiskGauge({ score }: { score: number }) {
  const color = riskColor(score);
  const data = [{ name: "risk", value: score, fill: color }];
  return (
    <div className="relative h-52 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <RadialBarChart
          innerRadius="78%"
          outerRadius="100%"
          data={data}
          startAngle={220}
          endAngle={-40}
          barSize={18}
        >
          <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
          <RadialBar background={{ fill: "#1c2b45" }} dataKey="value" cornerRadius={12} />
        </RadialBarChart>
      </ResponsiveContainer>
      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
        <div className="text-5xl font-bold tracking-tight" style={{ color }}>
          {Math.round(score)}
        </div>
        <div className="text-xs uppercase tracking-widest text-slate-400">{riskBand(score)} risk</div>
      </div>
    </div>
  );
}
