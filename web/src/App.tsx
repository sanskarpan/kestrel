import { useEffect, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/api/client";
import { createEventSource } from "@/sse/client";
import {
  Boxes,
  Network,
  Layers,
  Activity,
  Shield,
  Terminal,
  Orbit,
  CircleDot,
  AlertTriangle,
} from "lucide-react";

type View = "containers" | "namespaces" | "layers" | "resources" | "network" | "security" | "terminal";

const VIEWS: { id: View; label: string; icon: React.ElementType; desc: string }[] = [
  { id: "containers", label: "Containers", icon: Boxes, desc: "List, lifecycle, logs" },
  { id: "namespaces", label: "Namespaces", icon: Orbit, desc: "D3 force graph — 8 ns types" },
  { id: "layers", label: "Layers & Copy-Up", icon: Layers, desc: "Overlay stack + amplification" },
  { id: "resources", label: "Resources & PSI", icon: Activity, desc: "cgroup + PSI charts" },
  { id: "network", label: "Network", icon: Network, desc: "veth / bridge / NAT topology" },
  { id: "security", label: "Security", icon: Shield, desc: "Caps + seccomp violations" },
  { id: "terminal", label: "Terminal", icon: Terminal, desc: "xterm.js attach/exec" },
];

function ConnectionDot({ connected }: { connected: boolean | null }) {
  const color = connected === null ? "bg-yellow-500" : connected ? "bg-green-500" : "bg-red-500";
  const label = connected === null ? "checking…" : connected ? "connected" : "daemon offline";
  return (
    <span className="inline-flex items-center gap-2 text-xs text-muted-foreground">
      <span className={`h-2 w-2 rounded-full ${color} animate-pulse`} />
      {label}
    </span>
  );
}

export default function App() {
  const [view, setView] = useState<View>("containers");
  const [connected, setConnected] = useState<boolean | null>(null);
  const [containers, setContainers] = useState<unknown[] | null>(null);
  const [events, setEvents] = useState<string[]>([]);

  // Poll containers + SSE health
  useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      try {
        const list = await api.listContainers();
        if (!cancelled) {
          setContainers(list as unknown[]);
          setConnected(true);
        }
      } catch {
        if (!cancelled) setConnected(false);
      }
    };
    poll();
    const id = setInterval(poll, 3000);
    const close = createEventSource(
      api.eventsUrl(),
      (ev) => setEvents((prev) => [`${ev.type}`, ...prev].slice(0, 30)),
      (ok) => setConnected(ok),
    );
    return () => {
      cancelled = true;
      clearInterval(id);
      close();
    };
  }, []);

  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* Header */}
      <header className="sticky top-0 z-10 border-b bg-background/80 backdrop-blur">
        <div className="mx-auto flex max-w-[1400px] items-center justify-between px-4 py-3">
          <div className="flex items-center gap-3">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary text-primary-foreground font-bold">
              K
            </div>
            <div>
              <div className="font-semibold leading-none">kestrel</div>
              <div className="text-xs text-muted-foreground">Container Runtime — Rust + Linux 5.11+</div>
            </div>
            <Badge variant="outline" className="ml-2 hidden sm:inline-flex">
              {connected ? `${containers?.length ?? 0} containers` : "—"}
            </Badge>
          </div>
          <div className="flex items-center gap-3">
            <ConnectionDot connected={connected} />
            <Separator orientation="vertical" className="h-6" />
            <Button variant="outline" size="sm" onClick={() => window.location.reload()}>
              Reconnect
            </Button>
          </div>
        </div>
      </header>

      <div className="mx-auto flex max-w-[1400px]">
        {/* Sidebar */}
        <aside className="hidden w-64 shrink-0 border-r p-3 md:block">
          <nav className="space-y-1">
            {VIEWS.map((v) => {
              const Icon = v.icon;
              const active = view === v.id;
              return (
                <button
                  key={v.id}
                  onClick={() => setView(v.id)}
                  className={`flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors ${
                    active ? "bg-primary text-primary-foreground" : "hover:bg-muted"
                  }`}
                >
                  <Icon className="h-4 w-4" />
                  <span className="font-medium">{v.label}</span>
                </button>
              );
            })}
          </nav>
          <Separator className="my-4" />
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <CircleDot className="h-4 w-4" /> Daemon
              </CardTitle>
              <CardDescription className="text-xs">
                {connected === false
                  ? "kestreld not reachable at localhost:7777. Start it in the Lima VM: sudo ./target/debug/kestreld"
                  : "Proxied via Vite → localhost:7777 (/v1, /events)"}
              </CardDescription>
            </CardHeader>
            <CardContent className="text-xs text-muted-foreground">
              <div>API: /v1/containers</div>
              <div>SSE: /events</div>
              <div>Socket: /run/kestrel.sock</div>
            </CardContent>
          </Card>
          {connected === false && (
            <div className="mt-3 flex gap-2 rounded-lg border border-amber-200 bg-amber-50 p-3 text-xs text-amber-900 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-100">
              <AlertTriangle className="h-4 w-4 shrink-0" />
              <span>Host is macOS — runtime needs Linux VM. Use `make vm-ssh`.</span>
            </div>
          )}
          <div className="mt-4 space-y-1">
            <div className="text-xs font-medium">Recent events</div>
            <div className="max-h-40 overflow-auto rounded border bg-muted/30 p-2 font-mono text-[11px]">
              {events.length === 0 ? (
                <span className="text-muted-foreground">no events yet</span>
              ) : (
                events.map((e, i) => <div key={i}>{e}</div>)
              )}
            </div>
          </div>
        </aside>

        {/* Main */}
        <main className="flex-1 p-4 md:p-6">
          {/* Mobile tabs */}
          <div className="mb-4 md:hidden">
            <Tabs value={view} onValueChange={(v) => setView(v as View)}>
              <TabsList className="flex w-full flex-wrap">
                {VIEWS.map((v) => (
                  <TabsTrigger key={v.id} value={v.id} className="text-xs">
                    {v.label}
                  </TabsTrigger>
                ))}
              </TabsList>
            </Tabs>
          </div>

          {view === "containers" && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h1 className="text-xl font-semibold">Containers</h1>
                <Badge variant={connected ? "default" : "destructive"}>{connected ? "live" : "offline"}</Badge>
              </div>
              <Card>
                <CardHeader>
                  <CardTitle>Coming from kestreld</CardTitle>
                  <CardDescription>
                    TanStack Table: id, image, state, CPU%, mem, PIDs, ports. Data from GET /v1/containers + SSE.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {containers === null ? (
                    <div className="text-sm text-muted-foreground">
                      {connected === false
                        ? "Daemon offline — run in Lima VM: limactl shell kestrel → sudo ./target/debug/kestreld"
                        : "Loading…"}
                    </div>
                  ) : containers.length === 0 ? (
                    <div className="text-sm text-muted-foreground">No containers. Try: kestrel run --rm alpine echo hello</div>
                  ) : (
                    <pre className="max-h-96 overflow-auto rounded bg-muted p-3 text-xs">
                      {JSON.stringify(containers, null, 2)}
                    </pre>
                  )}
                </CardContent>
              </Card>
            </div>
          )}

          {view === "namespaces" && (
            <Placeholder
              title="Namespace Explorer"
              subtitle="D3 force graph — processes ↔ 8 namespaces. Shared netns converges to one node (pod semantics)."
              spec="SPEC §4, PROMPT Phase 2"
              endpoint="GET /containers/:id/namespaces + GET /system/namespaces"
            />
          )}
          {view === "layers" && (
            <Placeholder
              title="Layer & Copy-Up Inspector"
              subtitle="Overlay stack (lowerdir…upper) + copy-up heatmap + amplification ratio."
              spec="SPEC §6, CHECKLIST Phase 4"
              endpoint="GET /containers/:id/layers, /copyups — scan_copy_ups()"
            />
          )}
          {view === "resources" && (
            <Placeholder
              title="Resource & Pressure"
              subtitle="CPU vs cpu.max, memory high/max/peak, OOM markers, PSI some/full (Recharts)."
              spec="SPEC §5.3, PROMPT Phase 3"
              endpoint="GET /containers/:id/cgroup, /pressure — 1 Hz sampler"
            />
          )}
          {view === "network" && (
            <Placeholder
              title="Network Topology"
              subtitle="D3: bridges, veth pairs (IFLA_LINK), netns, NAT rules."
              spec="SPEC §11"
              endpoint="GET /containers/:id/network + GET /system/topology"
            />
          )}
          {view === "security" && (
            <Placeholder
              title="Security"
              subtitle="Capability matrix (5 sets) + seccomp profile + live violation feed."
              spec="SPEC §8"
              endpoint="GET /containers/:id/caps, /seccomp + seccomp.violation SSE"
            />
          )}
          {view === "terminal" && (
            <Placeholder
              title="Terminal"
              subtitle="xterm.js over WS /containers/:id/attach + POST /containers/:id/resize."
              spec="SPEC §13"
              endpoint="WS /containers/:id/attach, POST /resize"
            />
          )}

          <Separator className="my-6" />
          <div className="text-xs text-muted-foreground">
            Build: <code>cargo build --workspace</code> inside Lima VM (Linux 5.11+, cgroup2, overlay). Web dev:{" "}
            <code>npm --prefix web run dev</code> → http://localhost:5173. Lima mount fixed to{" "}
            <code>~/Developer/kestrel → ~/kestrel</code>.
          </div>
        </main>
      </div>
    </div>
  );
}

function Placeholder({ title, subtitle, spec, endpoint }: { title: string; subtitle: string; spec: string; endpoint: string }) {
  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">{title}</h1>
      <p className="text-sm text-muted-foreground">{subtitle}</p>
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Spec</CardTitle>
            <CardDescription>{spec}</CardDescription>
          </CardHeader>
          <CardContent className="font-mono text-xs">{endpoint}</CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Status</CardTitle>
            <CardDescription>Placeholder — wire to kestreld after VM is up.</CardDescription>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            UI contract matches SPEC §13. Backend already implements these endpoints; frontend only needs D3/Recharts wiring.
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
