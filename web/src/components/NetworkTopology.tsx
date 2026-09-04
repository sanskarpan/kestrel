import { useEffect, useRef, useMemo } from "react";
import * as d3 from "d3";
import { useTopology, useContainers } from "@/api/queries";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

type Node = { id: string; kind: "bridge" | "container"; label: string; subnet?: string };
type Link = { source: string; target: string };

export function NetworkTopology() {
  const topoQ = useTopology();
  const { data: containers } = useContainers();
  const svgRef = useRef<SVGSVGElement>(null);

  const { nodes, links } = useMemo(() => {
    if (!topoQ.data) return { nodes: [] as Node[], links: [] as Link[] };
    const nodes: Node[] = [];
    const links: Link[] = [];
    for (const br of topoQ.data.bridges) {
      const brId = `bridge:${br.name}`;
      nodes.push({ id: brId, kind: "bridge", label: br.name, subnet: br.subnet });
      for (const c of br.containers) {
        const cId = `container:${c.id}`;
        nodes.push({ id: cId, kind: "container", label: `${c.id.slice(0,8)} ${c.ip}` });
        links.push({ source: brId, target: cId });
      }
    }
    return { nodes, links };
  }, [topoQ.data]);

  useEffect(() => {
    if (!svgRef.current || nodes.length===0) return;
    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();
    const width = svgRef.current.clientWidth || 600;
    const height = 360;
    svg.attr("viewBox", `0 0 ${width} ${height}`);

    const simNodes = nodes.map((n)=>({ ...n })) as (Node & d3.SimulationNodeDatum)[];
    const simLinks = links.map((l)=>({ ...l })) as d3.SimulationLinkDatum<Node & d3.SimulationNodeDatum>[];

    const sim = d3.forceSimulation(simNodes)
      .force("link", d3.forceLink(simLinks).id((d: unknown)=>(d as Node).id).distance(110))
      .force("charge", d3.forceManyBody().strength(-300))
      .force("center", d3.forceCenter(width/2, height/2))
      .force("collide", d3.forceCollide().radius(50));

    const link = svg.append("g").selectAll("line")
      .data(simLinks).enter().append("line")
      .attr("stroke", "#94a3b8").attr("stroke-width", 1.5).attr("stroke-dasharray", "6 3");

    const node = svg.append("g").selectAll("g")
      .data(simNodes).enter().append("g")
      .call(d3.drag<SVGGElement, Node & d3.SimulationNodeDatum>()
        .on("start", (e,d)=>{ if(!e.active) sim.alphaTarget(0.3).restart(); (d as unknown as {fx:number|null}).fx = d.x ?? null; (d as unknown as {fy:number|null}).fy = d.y ?? null; })
        .on("drag", (e,d)=>{ (d as unknown as {fx:number}).fx=e.x; (d as unknown as {fy:number}).fy=e.y; })
        .on("end", (e,d)=>{ if(!e.active) sim.alphaTarget(0); (d as unknown as {fx:null}).fx=null; (d as unknown as {fy:null}).fy=null; }));

    node.append("rect")
      .attr("width", (d)=> d.kind==="bridge" ? 120 : 140)
      .attr("height", (d)=> d.kind==="bridge" ? 40 : 28)
      .attr("x", (d)=> d.kind==="bridge" ? -60 : -70)
      .attr("y", (d)=> d.kind==="bridge" ? -20 : -14)
      .attr("rx", 8)
      .attr("fill", (d)=> d.kind==="bridge" ? "#0ea5e9" : "#1e293b")
      .attr("stroke", "#fff").attr("stroke-width", 1.2);

    node.append("text")
      .text((d)=> d.label)
      .attr("text-anchor","middle").attr("dy", 4).attr("font-size","10px").attr("fill","#fff").attr("font-weight",600)
      .attr("pointer-events","none");

    node.append("title").text((d)=> d.kind==="bridge" ? `bridge ${d.label} subnet ${d.subnet}` : d.label);

    sim.on("tick", ()=>{
      link.attr("x1", (d)=>(d.source as unknown as {x:number}).x)
        .attr("y1", (d)=>(d.source as unknown as {y:number}).y)
        .attr("x2", (d)=>(d.target as unknown as {x:number}).x)
        .attr("y2", (d)=>(d.target as unknown as {y:number}).y);
      node.attr("transform", (d)=>`translate(${d.x},${d.y})`);
    });
    return ()=>{ sim.stop(); };
  }, [nodes, links]);

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Network Topology</h1>
      <p className="text-sm text-muted-foreground">Bridges, veth pairs (IFLA_LINK), netns, NAT rules — via GET /system/topology + per-container /network.</p>

      {topoQ.isLoading ? <Card><CardContent className="py-8 text-sm text-muted-foreground">Loading topology…</CardContent></Card>
      : topoQ.error ? <Card><CardContent className="py-6 text-sm text-destructive">{String(topoQ.error)}</CardContent></Card>
      : !topoQ.data || topoQ.data.bridges.length===0 ? (
        <Card><CardHeader><CardTitle>No bridge containers</CardTitle><CardDescription>No containers with network_mode=bridge. Create one: kestrel run --network bridge nginx</CardDescription></CardHeader>
          <CardContent className="text-xs text-muted-foreground">Total containers: {containers?.length ?? 0}. Topology aggregates only bridge-mode attachments.</CardContent></Card>
      ) : (
        <>
          <Card>
            <CardHeader className="pb-2"><CardTitle className="text-sm">D3 Topology</CardTitle><CardDescription>{topoQ.data.bridges.length} bridge(s) — dashed lines are veth pairs to containers.</CardDescription></CardHeader>
            <CardContent>
              <svg ref={svgRef} className="w-full h-[360px] rounded border bg-card" />
            </CardContent>
          </Card>
          <div className="grid gap-3 md:grid-cols-2">
            {topoQ.data.bridges.map((br)=>(
              <Card key={br.name}>
                <CardHeader className="pb-2"><CardTitle className="text-sm flex items-center gap-2">{br.name} <Badge variant="outline">{br.subnet}</Badge></CardTitle></CardHeader>
                <CardContent className="text-xs space-y-1">
                  {br.containers.map((c)=><div key={c.id} className="flex justify-between font-mono"><span>{c.id.slice(0,12)}</span><span>{c.ip}</span></div>)}
                </CardContent>
              </Card>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
