"use client";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'; //

const data = [
  { time: '02:00', threat: 40 },
  { time: '02:05', threat: 32 },
  { time: '02:10', threat: 65 },
  { time: '02:15', threat: 88 },
  { time: '02:20', threat: 74 },
];

export default function Metrics({ title, color }: { title: string, color: string }) {
  return (
    <div className="h-full w-full flex flex-col">
      <h3 className="text-[10px] font-bold tracking-widest text-muted mb-2 uppercase">{title}</h3>
      <div className="flex-1 min-h-[100px]">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data}>
            <defs>
              <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={color} stopOpacity={0.3}/>
                <stop offset="95%" stopColor={color} stopOpacity={0}/>
              </linearGradient>
            </defs>
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