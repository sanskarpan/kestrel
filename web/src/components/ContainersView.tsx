import { useContainers } from "@/api/queries";
import { useAppStore } from "@/store/appStore";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

function statusVariant(s: string) {
  switch (s) {
    case "Running": return "default" as const;
    case "Created": return "secondary" as const;
    case "Paused": return "outline" as const;
    case "Stopped": return "destructive" as const;
    default: return "secondary" as const;
  }
}

export function ContainersView() {
  const { data, isLoading, error, refetch, isFetching } = useContainers();
  const selectedId = useAppStore((s) => s.selectedId);
  const setSelectedId = useAppStore((s) => s.setSelectedId);

  if (error) {
    return (
      <Card>
        <CardHeader><CardTitle>Containers — error</CardTitle><CardDescription>{String(error)}</CardDescription></CardHeader>
        <CardContent><Button variant="outline" size="sm" onClick={() => refetch()}>Retry</Button></CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Containers</h1>
        <div className="flex items-center gap-2">
          <Badge variant="outline">{data?.length ?? 0} total</Badge>
          <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>{isFetching ? "Refreshing…" : "Refresh"}</Button>
        </div>
      </div>

      {isLoading ? (
        <Card><CardContent className="py-8 text-sm text-muted-foreground">Loading containers…</CardContent></Card>
      ) : !data || data.length === 0 ? (
        <Card>
          <CardHeader><CardTitle>No containers</CardTitle><CardDescription>Try: kestrel run --rm alpine echo hello</CardDescription></CardHeader>
        </Card>
      ) : (
        <div className="grid gap-3">
          {data.map((c) => (
            <Card key={c.id} className={selectedId === c.id ? "ring-2 ring-primary" : ""}>
              <CardHeader className="pb-2">
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <CardTitle className="font-mono text-sm truncate">{c.id.slice(0, 12)} · {c.id.slice(0, 8)}</CardTitle>
                    <CardDescription className="font-mono text-xs truncate">{c.bundle}</CardDescription>
                  </div>
                  <Badge variant={statusVariant(c.status)}>{c.status}</Badge>
                </div>
              </CardHeader>
              <CardContent className="flex flex-wrap items-center gap-2 text-xs">
                <span className="text-muted-foreground">pid {c.pid ?? "—"}</span>
                <span className="text-muted-foreground">tty {c.tty ? "yes" : "no"}</span>
                <span className="text-muted-foreground">net {c.network_mode ?? "none"}</span>
                {c.network?.ip && <Badge variant="outline">{c.network.ip}</Badge>}
                <div className="ml-auto flex gap-1">
                  <Button size="xs" variant={selectedId === c.id ? "default" : "outline"} onClick={() => setSelectedId(c.id)}>Select</Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
      {selectedId && <p className="text-xs text-muted-foreground">Selected <code>{selectedId.slice(0,12)}</code> — other views use this selection. Change via dropdown in each view too.</p>}
    </div>
  );
}
