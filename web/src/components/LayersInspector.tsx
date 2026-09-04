import { useMemo, useState } from "react";
import { useContainers, useLayers, useCopyups } from "@/api/queries";
import { useAppStore } from "@/store/appStore";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";

function fmtBytes(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1024*1024) return `${(n/1024).toFixed(1)} KiB`;
  if (n < 1024*1024*1024) return `${(n/1024/1024).toFixed(1)} MiB`;
  return `${(n/1024/1024/1024).toFixed(2)} GiB`;
}

export function LayersInspector() {
  const { data: containers } = useContainers();
  const selectedId = useAppStore((s) => s.selectedId);
  const setSelectedId = useAppStore((s) => s.setSelectedId);
  const [localSel, setLocalSel] = useState<string | null>(null);
  const activeId = localSel ?? selectedId ?? containers?.[0]?.id ?? null;
  const layersQ = useLayers(activeId);
  const copyupsQ = useCopyups(activeId);

  const totalLayerBytes = useMemo(() => layersQ.data?.layers.reduce((a,b)=>a+b.size_bytes,0) ?? 0, [layersQ.data]);
  const totalCopyupBytes = useMemo(() => copyupsQ.data?.copy_ups.reduce((a,b)=>a+b.size_bytes,0) ?? 0, [copyupsQ.data]);
  const amplification = totalLayerBytes ? (totalCopyupBytes / totalLayerBytes) : 0;
  const maxLayer = useMemo(() => Math.max(...(layersQ.data?.layers.map(l=>l.size_bytes) ?? [1])), [layersQ.data]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">Layer & Copy-Up Inspector</h1>
          <p className="text-sm text-muted-foreground">Overlay stack + copy-up heatmap + amplification ratio.</p>
        </div>
        <Select value={activeId ?? ""} onValueChange={(v)=>{setLocalSel(v); setSelectedId(v);}}>
          <SelectTrigger className="w-[220px]"><SelectValue placeholder="Select container" /></SelectTrigger>
          <SelectContent>{containers?.map((c)=><SelectItem key={c.id} value={c.id}>{c.id.slice(0,12)} — {c.status}</SelectItem>)}</SelectContent>
        </Select>
      </div>

      {!activeId ? <Card><CardContent className="py-8 text-sm text-muted-foreground">Select a container to inspect layers.</CardContent></Card>
      : layersQ.isLoading ? <Card><CardContent className="py-8 text-sm text-muted-foreground">Loading layers…</CardContent></Card>
      : layersQ.error ? <Card><CardContent className="py-6 text-sm text-destructive">{String(layersQ.error)}</CardContent></Card>
      : !layersQ.data || layersQ.data.layers.length===0 ? <Card><CardHeader><CardTitle>No layers</CardTitle><CardDescription>Container may be from bundle_rootfs (no image layers) or layers.json missing.</CardDescription></CardHeader></Card>
      : (
        <>
          <div className="grid gap-4 md:grid-cols-3">
            <Card><CardHeader className="pb-2"><CardTitle className="text-sm">Total layer bytes</CardTitle></CardHeader><CardContent className="text-lg font-mono">{fmtBytes(totalLayerBytes)}</CardContent></Card>
            <Card><CardHeader className="pb-2"><CardTitle className="text-sm">Copy-up bytes</CardTitle></CardHeader><CardContent className="text-lg font-mono">{fmtBytes(totalCopyupBytes)} <span className="text-xs text-muted-foreground">({copyupsQ.data?.copy_ups.length ?? 0} files)</span></CardContent></Card>
            <Card><CardHeader className="pb-2"><CardTitle className="text-sm">Amplification</CardTitle><CardDescription>copy-up / layer total</CardDescription></CardHeader><CardContent className="text-lg font-mono">{(amplification*100).toFixed(2)}% {amplification>0.2 && <Badge variant="destructive" className="ml-2">high churn</Badge>}</CardContent></Card>
          </div>

          <Card>
            <CardHeader><CardTitle className="text-sm">Overlay stack (lower → upper)</CardTitle><CardDescription>Each chain-id sized bar; origin is diff_dir on host.</CardDescription></CardHeader>
            <CardContent className="space-y-3">
              {layersQ.data.layers.map((l, idx)=>(
                <div key={l.chain_id} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono">[{idx}] {l.chain_id.slice(0,16)}…</span>
                    <span className="text-muted-foreground">{fmtBytes(l.size_bytes)}</span>
                  </div>
                  <Progress value={maxLayer ? (l.size_bytes / maxLayer)*100 : 0} />
                  <div className="text-[11px] text-muted-foreground truncate">{l.origin}</div>
                </div>
              ))}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0">
              <div><CardTitle className="text-sm">Copy-ups</CardTitle><CardDescription>scan_copy_ups() — upper files that shadow a lower layer. Heat by size.</CardDescription></div>
              <Badge variant="outline">{copyupsQ.data?.copy_ups.length ?? 0}</Badge>
            </CardHeader>
            <CardContent>
              {copyupsQ.isLoading ? <div className="text-sm text-muted-foreground">Scanning…</div>
                : copyupsQ.error ? <div className="text-sm text-destructive">{String(copyupsQ.error)}</div>
                : !copyupsQ.data || copyupsQ.data.copy_ups.length===0 ? <div className="text-sm text-muted-foreground">No copy-ups detected — upper is clean.</div>
                : (
                  <div className="max-h-[340px] overflow-auto">
                    <table className="w-full text-xs">
                      <thead className="sticky top-0 bg-card"><tr className="border-b text-muted-foreground"><th className="text-left py-1">Path</th><th className="text-right">Size</th><th className="text-left pl-2">From layer</th><th className="text-left pl-2">Kind</th></tr></thead>
                      <tbody>
                        {[...copyupsQ.data.copy_ups].sort((a,b)=>b.size_bytes-a.size_bytes).map((c)=>(
                          <tr key={c.path} className="border-b last:border-0">
                            <td className="py-1 font-mono truncate max-w-[280px]" title={c.path}>{c.path}</td>
                            <td className="text-right font-mono">{fmtBytes(c.size_bytes)}</td>
                            <td className="pl-2 font-mono text-[11px]">{c.from_layer.slice(0,12)}</td>
                            <td className="pl-2"><Badge variant={c.kind==="Modified"?"destructive":"secondary"} className="text-[10px]">{c.kind}</Badge></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
