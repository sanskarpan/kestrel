import { useEffect, useRef, useState, useMemo } from "react";
import * as d3 from "d3";
import { useContainers, useNamespaces, useSystemNamespaces } from "@/api/queries";
import { useAppStore } from "@/store/appStore";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

type GraphNode = {
  id: string;
  kind: "container" | "ns";
  label: string;
  nsType?: string;
  inode?: number;
  shared?: boolean;
};
type GraphLink = { source: string; target: string };

const NS_COLORS: Record<string, string> = {
  mnt: "#ef4444", uts: "#f59e0b", ipc: "#eab308", pid: "#22c55e",
  net: "#06b6d4", user: "#8b5cf6", cgroup: "#ec4899", time: "#6b7280",
};

export function NamespaceExplorer() {
  const { data: containers } = useContainers();
  const selectedId = useAppStore((s) => s.selectedId);
  const setSelectedId = useAppStore((s) => s.setSelectedId);
  const [localSel, setLocalSel] = useState<string | null>(null);
  const activeId = localSel ?? selectedId ?? containers?.[0]?.id ?? null;
  const { data: nsData, isLoading, error } = useNamespaces(activeId);
  const { data: sysNs } = useSystemNamespaces(true);
  const svgRef = useRef<SVGSVGElement>(null);

  const { nodes, links } = useMemo(() => {
    if (!nsData || !activeId) return { nodes: [] as GraphNode[], links: [] as GraphLink[] };
    const n: GraphNode[] = [];
    const l: GraphLink[] = [];
    const containerNodeId = `container:${activeId}`;
    n.push({ id: containerNodeId, kind: "container", label: activeId.slice(0, 8) });
    for (const ns of nsData.namespaces) {
      const nodeId = `ns:${ns.ns_type}:${ns.inode}`;
      n.push({ id: nodeId, kind: "ns", label: `${ns.ns_type}:${String(ns.inode).slice(-4)}`, nsType: ns.ns_type, inode: ns.inode, shared: ns.shared_with.length > 0 });
      l.push({ source: containerNodeId, target: nodeId });
    }
    // If system view shows sharing, annotate: same inode appears elsewhere - already via shared_with
    return { nodes: n, links: l };
  }, [nsData, activeId]);

  useEffect(() => {
    if (!svgRef.current || nodes.length === 0) return;
    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();
    const width = svgRef.current.clientWidth || 600;
    const height = 380;
    svg.attr("viewBox", `0 0 ${width} ${height}`);

    const simNodes = nodes.map((n) => ({ ...n })) as (GraphNode & d3.SimulationNodeDatum)[];
    const simLinks = links.map((l) => ({ ...l })) as d3.SimulationLinkDatum<GraphNode & d3.SimulationNodeDatum>[];

    const simulation = d3.forceSimulation(simNodes)
      .force("link", d3.forceLink(simLinks).id((d: unknown) => (d as GraphNode).id).distance(90))
      .force("charge", d3.forceManyBody().strength(-250))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius(38));

    const link = svg.append("g").selectAll("line")
      .data(simLinks).enter().append("line")
      .attr("stroke", "#94a3b8").attr("stroke-opacity", 0.6).attr("stroke-width", 1.2);

    const node = svg.append("g").selectAll("g")
      .data(simNodes).enter().append("g")
      .call(d3.drag<SVGGElement, GraphNode & d3.SimulationNodeDatum>()
        .on("start", (event, d) => { if (!event.active) simulation.alphaTarget(0.3).restart(); (d as unknown as { fx: number | null; fy: number | null }).fx = d.x ?? null; (d as unknown as { fx: number | null; fy: number | null }).fy = d.y ?? null; })
        .on("drag", (event, d) => { (d as unknown as { fx: number; fy: number }).fx = event.x; (d as unknown as { fx: number; fy: number }).fy = event.y; })
        .on("end", (event, d) => { if (!event.active) simulation.alphaTarget(0); (d as unknown as { fx: null; fy: null }).fx = null; (d as unknown as { fx: null; fy: null }).fy = null; }));

    node.append("circle")
      .attr("r", (d) => d.kind === "container" ? 22 : 18)
      .attr("fill", (d) => d.kind === "container" ? "#0f172a" : (d.nsType ? NS_COLORS[d.nsType] ?? "#64748b" : "#64748b"))
      .attr("stroke", (d) => d.shared ? "#facc15" : "#fff")
      .attr("stroke-width", (d) => d.shared ? 3 : 1.5);

    node.append("text")
      .text((d) => d.label)
      .attr("text-anchor", "middle")
      .attr("dy", 4)
      .attr("font-size", "9px")
      .attr("fill", "#fff")
      .attr("pointer-events", "none")
      .attr("font-weight", 600);

    // tooltip via title
    node.append("title").text((d) => d.kind === "container" ? `container ${activeId}` : `${d.nsType} inode ${d.inode}${d.shared ? " (shared)" : ""}`);

    simulation.on("tick", () => {
      link.attr("x1", (d) => (d.source as unknown as { x: number }).x)
        .attr("y1", (d) => (d.source as unknown as { y: number }).y)
        .attr("x2", (d) => (d.target as unknown as { x: number }).x)
        .attr("y2", (d) => (d.target as unknown as { y: number }).y);
      node.attr("transform", (d) => `translate(${d.x},${d.y})`);
    });

    return () => { simulation.stop(); };
  }, [nodes, links, activeId]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">Namespace Explorer</h1>
          <p className="text-sm text-muted-foreground">D3 force graph — 8 ns types. Shared netns converges to one node.</p>
        </div>
        <Select value={activeId ?? ""} onValueChange={(v) => { setLocalSel(v); setSelectedId(v); }}>
          <SelectTrigger className="w-[200px]"><SelectValue placeholder="Select container" /></SelectTrigger>
          <SelectContent>{containers?.map((c) => <SelectItem key={c.id} value={c.id}>{c.id.slice(0,12)} — {c.status}</SelectItem>)}</SelectContent>
        </Select>
      </div>

      {isLoading ? <Card><CardContent className="py-8 text-sm text-muted-foreground">Loading namespaces…</CardContent></Card>
        : error ? <Card><CardContent className="py-6 text-sm text-destructive">{String(error)}</CardContent></Card>
        : !nsData || nsData.namespaces.length === 0 ? <Card><CardHeader><CardTitle>No namespaces pinned</CardTitle><CardDescription>Mount ns may be absent on Lima VM (EINVAL). Check /system/namespaces for host-wide view.</CardDescription></CardHeader></Card>
        : (
          <>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Force Graph</CardTitle>
                <CardDescription>Drag nodes. Yellow ring = shared inode (shared_with non-empty). Colors per ns type.</CardDescription>
              </CardHeader>
              <CardContent>
                <svg ref={svgRef} className="w-full h-[380px] rounded border bg-card" />
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {Object.entries(NS_COLORS).map(([k, col]) => (
                    <span key={k} className="inline-flex items-center gap-1 text-xs"><span className="h-3 w-3 rounded-full" style={{ background: col }} />{k}</span>
                  ))}
                  <Badge variant="outline" className="ml-2">container = dark</Badge>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader><CardTitle className="text-sm">Inodes</CardTitle></CardHeader>
              <CardContent>
                <div className="overflow-auto">
                  <table className="w-full text-xs">
                    <thead><tr className="text-muted-foreground border-b"><th className="py-1 text-left">Type</th><th className="text-left">Inode</th><th className="text-left">Shared with</th></tr></thead>
                    <tbody>{nsData.namespaces.map((n) => (
                      <tr key={n.ns_type} className="border-b last:border-0"><td className="py-1.5 font-medium">{n.ns_type}</td><td className="font-mono">{n.inode}</td><td>{n.shared_with.length ? n.shared_with.map((s) => <Badge key={s} variant="secondary" className="mr-1 text-[10px]">{s.slice(0,8)}</Badge>) : <span className="text-muted-foreground">—</span>}</td></tr>
                    ))}</tbody>
                  </table>
                </div>
              </CardContent>
            </Card>

            {sysNs && (
              <Card>
                <CardHeader><CardTitle className="text-sm">Host-wide /system/namespaces sample</CardTitle><CardDescription>{Object.keys(sysNs.processes).length} pids visible</CardDescription></CardHeader>
                <CardContent className="max-h-40 overflow-auto font-mono text-[11px] bg-muted/30 rounded p-2">
                  {Object.entries(sysNs.processes).slice(0,5).map(([pid, nsMap]) => (
                    <div key={pid}>{pid}: {Object.entries(nsMap).map(([k,v]) => `${k}=${v}`).join(" ")}</div>
                  ))}
                </CardContent>
              </Card>
            )}
          </>
        )}
    </div>
  );
}
