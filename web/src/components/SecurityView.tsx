import { useState, useEffect, useRef } from "react";
import { useContainers, useCaps, useSeccomp } from "@/api/queries";
import { useAppStore } from "@/store/appStore";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

const CAP_SETS: (keyof import("@/api/types").CapabilitiesResponse)[] = ["bounding","effective","inheritable","permitted","ambient"];

export function SecurityView() {
  const { data: containers } = useContainers();
  const selectedId = useAppStore((s)=>s.selectedId);
  const setSelectedId = useAppStore((s)=>s.setSelectedId);
  const [localSel, setLocalSel] = useState<string|null>(null);
  const activeId = localSel ?? selectedId ?? containers?.[0]?.id ?? null;
  const capsQ = useCaps(activeId);
  const seccompQ = useSeccomp(activeId);
  const violationFeed = useAppStore((s)=>s.violationFeed);

  // Also watch SSE for live seccomp.violation events pushed via global App events
  const events = useAppStore((s)=>s.events);
  const [liveViolations, setLiveViolations] = useState<{syscall:string, ts:string}[]>([]);
  // Dedupe key: the events array is re-scanned on every SSE arrival, so
  // already-processed events must be skipped to avoid duplicate feed entries.
  const seenViolations = useRef<Set<string>>(new Set());
  // oxlint-disable-next-line react/set-state-in-effect — syncing the external SSE event stream into local + global violation feeds; not derivable during render
  useEffect(()=>{
    for (const ev of events) {
      if (ev.type === "seccomp.violation" || ev.type === "seccomp_violation" || ev.type === "SeccompViolation") {
        const key = `${ev.timestamp}:${ev.type}:${JSON.stringify(ev.data)}`;
        if (seenViolations.current.has(key)) continue;
        seenViolations.current.add(key);
        const data = ev.data as { syscall?: string; id?: string, syscall_name?: string } | string;
        const syscall = typeof data === "string" ? data : (data.syscall ?? data.syscall_name ?? JSON.stringify(data));
        setLiveViolations((prev)=>[{syscall, ts: ev.timestamp}, ...prev].slice(0,20));
        // also push to global violation feed if matches activeId
        const eid = typeof data === "object" && data && "id" in data ? (data as {id:string}).id : null;
        if (!eid || eid===activeId) {
          useAppStore.getState().pushViolation({ id: eid ?? activeId ?? "unknown", syscall, ts: ev.timestamp });
        }
      }
    }
  }, [events, activeId]);

  const allCaps = capsQ.data ? Array.from(new Set([...capsQ.data.bounding, ...capsQ.data.effective, ...capsQ.data.permitted, ...capsQ.data.inheritable, ...capsQ.data.ambient])).sort() : [];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div><h1 className="text-xl font-semibold">Security</h1><p className="text-sm text-muted-foreground">Capability matrix (5 sets) + seccomp profile + live violation feed.</p></div>
        <Select value={activeId ?? ""} onValueChange={(v)=>{setLocalSel(v); setSelectedId(v);}}>
          <SelectTrigger className="w-[220px]"><SelectValue placeholder="Select container" /></SelectTrigger>
          <SelectContent>{containers?.map((c)=><SelectItem key={c.id} value={c.id}>{c.id.slice(0,12)} — {c.status}</SelectItem>)}</SelectContent>
        </Select>
      </div>

      {!activeId ? <Card><CardContent className="py-8 text-sm text-muted-foreground">Select a container.</CardContent></Card>
      : (
        <>
          <Card>
            <CardHeader><CardTitle className="text-sm">Capability matrix</CardTitle><CardDescription>5 sets from config.json process.capabilities — check = present.</CardDescription></CardHeader>
            <CardContent>
              {capsQ.isLoading ? <div className="text-sm text-muted-foreground">Loading caps…</div>
              : capsQ.error ? <div className="text-sm text-destructive">{String(capsQ.error)}</div>
              : allCaps.length===0 ? <div className="text-sm text-muted-foreground">No capabilities configured (empty or no config.json caps section).</div>
              : (
                <div className="overflow-auto">
                  <table className="w-full text-xs">
                    <thead><tr className="border-b text-muted-foreground"><th className="text-left py-1">Capability</th>{CAP_SETS.map((s)=><th key={s} className="text-center px-2">{s}</th>)}</tr></thead>
                    <tbody>
                      {allCaps.map((cap)=>(
                        <tr key={cap} className="border-b last:border-0">
                          <td className="py-1 font-mono">{cap}</td>
                          {CAP_SETS.map((set)=>(
                            <td key={set} className="text-center">{((capsQ.data as unknown as Record<string,string[]>)[set])?.includes(cap) ? "✓" : "—"}</td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle className="text-sm">Seccomp</CardTitle><CardDescription>profile from config.json + violations ring buffer (last 200).</CardDescription></CardHeader>
            <CardContent className="space-y-3">
              {seccompQ.isLoading ? <div className="text-sm text-muted-foreground">Loading seccomp…</div>
              : seccompQ.error ? <div className="text-sm text-destructive">{String(seccompQ.error)}</div>
              : (
                <>
                  {seccompQ.data?.profile ? (
                    <div className="rounded border p-3 text-xs space-y-2">
                      <div><span className="font-semibold">defaultAction</span> <Badge variant="outline">{seccompQ.data.profile.default_action}</Badge></div>
                      {seccompQ.data.profile.architectures.length>0 && <div>arches: {seccompQ.data.profile.architectures.join(", ")}</div>}
                      <div className="space-y-1">
                        {seccompQ.data.profile.syscalls.map((sc, i)=>(
                          <div key={i} className="flex flex-wrap gap-1 items-center"><Badge variant="secondary">{sc.action}</Badge>{sc.names.map((n)=><Badge key={n} variant="outline" className="font-mono text-[10px]">{n}</Badge>)}</div>
                        ))}
                      </div>
                    </div>
                  ) : <div className="text-sm text-muted-foreground">No seccomp profile (container created without seccomp_notify_syscalls).</div>}
                  <div>
                    <div className="text-xs font-semibold mb-1">Violations ({seccompQ.data?.violations.length ?? 0} retained)</div>
                    {seccompQ.data?.violations && seccompQ.data.violations.length>0 ? (
                      <div className="max-h-32 overflow-auto rounded border bg-muted/30 p-2 font-mono text-xs">
                        {seccompQ.data.violations.map((v, i)=><div key={i}>{v}</div>)}
                      </div>
                    ) : <div className="text-xs text-muted-foreground">No violations observed via attach session.</div>}
                  </div>
                  {liveViolations.length>0 && (
                    <div>
                      <div className="text-xs font-semibold mb-1">Live SSE feed (this session) <Badge variant="destructive">{liveViolations.length}</Badge></div>
                      <div className="max-h-32 overflow-auto rounded border bg-amber-50 dark:bg-amber-950 p-2 font-mono text-xs">
                        {liveViolations.map((v,i)=><div key={i}>[{v.ts}] {v.syscall}</div>)}
                      </div>
                    </div>
                  )}
                  {violationFeed.length>0 && (
                    <div>
                      <div className="text-xs font-semibold">Global violation feed (zustand)</div>
                      <div className="max-h-24 overflow-auto text-[11px] font-mono">{violationFeed.slice(0,5).map((v,i)=><div key={i}>{v.id.slice(0,8)} {v.syscall} @ {v.ts}</div>)}</div>
                    </div>
                  )}
                  <p className="text-[11px] text-muted-foreground">Note: violations only accumulate while a client holds an attach WS session (see SeccompLog doc). Open Terminal attach to observe.</p>
                </>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
