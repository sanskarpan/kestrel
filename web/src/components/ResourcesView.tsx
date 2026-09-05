import { useState, useMemo, useEffect } from "react";
import { useContainers, useCgroup, usePressure } from "@/api/queries";
import { useAppStore } from "@/store/appStore";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, AreaChart, Area, BarChart, Bar, CartesianGrid, Legend } from "recharts";

function fmtBytes(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1024*1024) return `${(n/1024).toFixed(1)} KiB`;
  if (n < 1024*1024*1024) return `${(n/1024/1024).toFixed(1)} MiB`;
  return `${(n/1024/1024/1024).toFixed(2)} GiB`;
}
type PsiPoint = { t: string; cpuSome: number; memSome: number; ioSome: number; cpuFull: number | null; memFull: number | null };

export function ResourcesView() {
  const { data: containers } = useContainers();
  const selectedId = useAppStore((s) => s.selectedId);
  const setSelectedId = useAppStore((s) => s.setSelectedId);
  const [localSel, setLocalSel] = useState<string | null>(null);
  const activeId = localSel ?? selectedId ?? containers?.[0]?.id ?? null;
  const cgroupQ = useCgroup(activeId);
  const pressureQ = usePressure(activeId);
  const [psiHistory, setPsiHistory] = useState<PsiPoint[]>([]);
  const [prevActiveId, setPrevActiveId] = useState(activeId);
  // Render-phase reset (React's sanctioned derived-state pattern): clear
  // PSI history when the selected container changes, without an effect.
  if (prevActiveId !== activeId) {
    setPrevActiveId(activeId);
    setPsiHistory([]);
  }

  // Accumulating a rolling window from the 1 Hz PSI poll stream is
  // external synchronization, not derivable during render.
  useEffect(() => {
    if (!pressureQ.data) return;
    const now = new Date().toLocaleTimeString();
    // oxlint-disable-next-line react/set-state-in-effect — see above
    setPsiHistory((prev) => [...prev.slice(-29), {
      t: now,
      cpuSome: pressureQ.data!.cpu.some.avg10,
      memSome: pressureQ.data!.memory.some.avg10,
      ioSome: pressureQ.data!.io.some.avg10,
      cpuFull: pressureQ.data!.cpu.full?.avg10 ?? null,
      memFull: pressureQ.data!.memory.full?.avg10 ?? null,
    }]);
  }, [pressureQ.data]);

  const throttlePct = useMemo(() => {
    if (!cgroupQ.data) return 0;
    const { nr_periods, nr_throttled } = cgroupQ.data.cpu_stat;
    return nr_periods ? (nr_throttled / nr_periods) * 100 : 0;
  }, [cgroupQ.data]);

  const memLimit = useMemo(() => {
    if (!cgroupQ.data) return null;
    const v = cgroupQ.data.memory_max.trim();
    if (v === "max" || v === "") return null;
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
  }, [cgroupQ.data]);

  const memPct = useMemo(() => {
    if (!cgroupQ.data || memLimit === null || memLimit === 0) return null;
    return (cgroupQ.data.memory_current / memLimit) * 100;
  }, [cgroupQ.data, memLimit]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">Resources & Pressure</h1>
          <p className="text-sm text-muted-foreground">cgroup + PSI (1 Hz sampler) — cpu.max, memory peak, throttle, Recharts.</p>
        </div>
        <Select value={activeId ?? ""} onValueChange={(v)=>{setLocalSel(v); setSelectedId(v);}}>
          <SelectTrigger className="w-[220px]"><SelectValue placeholder="Select container" /></SelectTrigger>
          <SelectContent>{containers?.map((c)=><SelectItem key={c.id} value={c.id}>{c.id.slice(0,12)} — {c.status}</SelectItem>)}</SelectContent>
        </Select>
      </div>

      {!activeId ? <Card><CardContent className="py-8 text-sm text-muted-foreground">Select a container.</CardContent></Card>
      : cgroupQ.isLoading ? <Card><CardContent className="py-8 text-sm text-muted-foreground">Loading cgroup…</CardContent></Card>
      : cgroupQ.error ? <Card><CardContent className="py-6 text-sm text-destructive">{String(cgroupQ.error)}</CardContent></Card>
      : cgroupQ.data && (
        <>
          <div className="grid gap-4 md:grid-cols-3">
            <Card>
              <CardHeader className="pb-2"><CardTitle className="text-sm">CPU throttling</CardTitle><CardDescription>cpu.stat nr_throttled / nr_periods</CardDescription></CardHeader>
              <CardContent className="space-y-2">
                <div className="flex items-baseline justify-between"><span className="text-2xl font-mono">{throttlePct.toFixed(1)}%</span><Badge variant={throttlePct>10?"destructive":"secondary"}>{cgroupQ.data.cpu_stat.nr_throttled}/{cgroupQ.data.cpu_stat.nr_periods}</Badge></div>
                <Progress value={Math.min(throttlePct,100)} />
                <div className="text-xs text-muted-foreground">usage {cgroupQ.data.cpu_stat.usage_usec} µs · throttled {cgroupQ.data.cpu_stat.throttled_usec} µs</div>
                <div className="text-xs font-mono">cpu.max {cgroupQ.data.cpu_max}</div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2"><CardTitle className="text-sm">Memory</CardTitle><CardDescription>memory.current vs max</CardDescription></CardHeader>
              <CardContent className="space-y-2">
                <div className="text-2xl font-mono">{fmtBytes(cgroupQ.data.memory_current)}</div>
                {memPct !== null ? <><Progress value={Math.min(memPct,100)} /><div className="text-xs text-muted-foreground">{memPct.toFixed(1)}% of {fmtBytes(memLimit!)} </div></> : <div className="text-xs text-muted-foreground">limit: {cgroupQ.data.memory_max} (unbounded)</div>}
                <div className="text-xs font-mono">pids {cgroupQ.data.pids_current} / {cgroupQ.data.pids_max}</div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2"><CardTitle className="text-sm">I/O</CardTitle><CardDescription>per-device rbytes/wbytes</CardDescription></CardHeader>
              <CardContent>
                {cgroupQ.data.io_stat.length===0 ? <div className="text-sm text-muted-foreground">No I/O stats</div>
                : (
                  <div className="h-[110px]">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={cgroupQ.data.io_stat.slice(0,4).map((d)=>({ name:`${d.major}:${d.minor}`, r: d.rbytes, w: d.wbytes }))}>
                        <CartesianGrid strokeDasharray="3 3" opacity={0.2} />
                        <XAxis dataKey="name" fontSize={10} />
                        <YAxis fontSize={10} tickFormatter={(v)=>fmtBytes(v as number)} />
                        <Tooltip formatter={(v)=>fmtBytes(v as number)} />
                        <Legend />
                        <Bar dataKey="r" name="read" fill="#06b6d4" />
                        <Bar dataKey="w" name="write" fill="#f59e0b" />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader><CardTitle className="text-sm">PSI — some avg10 (1 Hz poll)</CardTitle><CardDescription>cpu / memory / io stall pressure; full vs some.</CardDescription></CardHeader>
            <CardContent className="h-[220px]">
              {psiHistory.length < 2 ? <div className="text-sm text-muted-foreground py-8 text-center">Collecting PSI samples… ({psiHistory.length})</div>
              : (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={psiHistory}>
                    <CartesianGrid strokeDasharray="3 3" opacity={0.2} />
                    <XAxis dataKey="t" fontSize={10} />
                    <YAxis fontSize={10} domain={[0, 100]} tickFormatter={(v)=>`${v}%`} />
                    <Tooltip />
                    <Legend />
                    <Line type="monotone" dataKey="cpuSome" name="cpu some" stroke="#22c55e" dot={false} strokeWidth={2} />
                    <Line type="monotone" dataKey="memSome" name="mem some" stroke="#ef4444" dot={false} strokeWidth={2} />
                    <Line type="monotone" dataKey="ioSome" name="io some" stroke="#06b6d4" dot={false} strokeWidth={2} />
                  </LineChart>
                </ResponsiveContainer>
              )}
            </CardContent>
          </Card>

          {pressureQ.data && (
            <Card>
              <CardHeader><CardTitle className="text-sm">Current PSI detail</CardTitle></CardHeader>
              <CardContent className="grid gap-3 md:grid-cols-3 text-xs font-mono">
                {(["cpu","memory","io"] as const).map((k)=>(
                  <div key={k} className="rounded border p-2">
                    <div className="font-semibold">{k}</div>
                    <div>some avg10 {pressureQ.data![k].some.avg10.toFixed(2)}% avg60 {pressureQ.data![k].some.avg60.toFixed(2)} total {pressureQ.data![k].some.total_us}µs</div>
                    <div>full {pressureQ.data![k].full ? `${pressureQ.data![k].full!.avg10.toFixed(2)}%` : "— (kernel N/A)"}</div>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          <div className="h-[160px]">
            <Card className="h-full flex flex-col">
              <CardHeader className="pb-2"><CardTitle className="text-sm">Memory over time (current window)</CardTitle></CardHeader>
              <CardContent className="flex-1">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={psiHistory.map((p)=>({ t:p.t, mem: cgroupQ.data.memory_current }))}>
                    <CartesianGrid strokeDasharray="3 3" opacity={0.2} />
                    <XAxis dataKey="t" fontSize={10} />
                    <YAxis fontSize={10} tickFormatter={(v)=>fmtBytes(v as number)} />
                    <Tooltip formatter={(v)=>fmtBytes(v as number)} />
                    <Area type="monotone" dataKey="mem" stroke="#8b5cf6" fill="#8b5cf6" fillOpacity={0.3} />
                  </AreaChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>
        </>
      )}
    </div>
  );
}
