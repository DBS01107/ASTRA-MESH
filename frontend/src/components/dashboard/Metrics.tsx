"use client";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'; //

export default function Metrics({ title, color, history = [] }: { title: string, color: string, history?: {time: string, threat: number}[] }) {
  // Gracefully provide a flatline array if no scan has populated the history yet
  const chartData = history.length > 0 ? history : [
    { time: '00:00', threat: 0 },
    { time: '00:01', threat: 0 }
  ];

  return (
    <div className="h-full w-full flex flex-col">
      <h3 className="text-[10px] font-bold tracking-widest text-muted mb-2 uppercase">{title}</h3>
      <div className="flex-1 min-h-[100px]">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={chartData}>
            <defs>
              <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={color} stopOpacity={0.3}/>
                <stop offset="95%" stopColor={color} stopOpacity={0}/>
              </linearGradient>
            </defs>
            <XAxis dataKey="time" stroke="#475569" fontSize={8} tickMargin={5} minTickGap={10} axisLine={false} tickLine={false} />
            <YAxis stroke="#475569" fontSize={8} tickMargin={5} axisLine={false} tickLine={false} />
            <Tooltip 
              contentStyle={{ backgroundColor: '#05060b', border: '1px solid rgba(34,211,238,0.2)', fontSize: '10px' }}
            />
            <Area type="monotone" dataKey="threat" stroke={color} fillOpacity={1} fill="url(#colorRisk)" strokeWidth={2} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}