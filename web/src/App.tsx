import { useEffect, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/api/client";
import { createEventSource } from "@/sse/client";
import { useAppStore } from "@/store/appStore";
import { ContainersView } from "@/components/ContainersView";
import { NamespaceExplorer } from "@/components/NamespaceExplorer";
import { LayersInspector } from "@/components/LayersInspector";
import { ResourcesView } from "@/components/ResourcesView";
import { NetworkTopology } from "@/components/NetworkTopology";
import { SecurityView } from "@/components/SecurityView";
import { TerminalView } from "@/components/TerminalView";
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
  const pushEvent = useAppStore((s) => s.pushEvent);
  const events = useAppStore((s) => s.events);

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
      (ev) => pushEvent(ev),
      (ok) => setConnected(ok),
    );
    return () => {
      cancelled = true;
      clearInterval(id);
      close();
    };
  }, [pushEvent]);

  return (
    <div className="min-h-screen bg-background text-foreground">
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
                events.slice(0,30).map((e, i) => <div key={i}>{e.type}</div>)
              )}
            </div>
          </div>
        </aside>

        <main className="flex-1 p-4 md:p-6">
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

          {view === "containers" && <ContainersView />}
          {view === "namespaces" && <NamespaceExplorer />}
          {view === "layers" && <LayersInspector />}
          {view === "resources" && <ResourcesView />}
          {view === "network" && <NetworkTopology />}
          {view === "security" && <SecurityView />}
          {view === "terminal" && <TerminalView />}

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
