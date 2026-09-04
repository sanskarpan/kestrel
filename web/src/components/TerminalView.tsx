import { useEffect, useRef, useState } from "react";
import { useContainers } from "@/api/queries";
import { useAppStore } from "@/store/appStore";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";

export function TerminalView() {
  const { data: containers } = useContainers();
  const selectedId = useAppStore((s)=>s.selectedId);
  const setSelectedId = useAppStore((s)=>s.setSelectedId);
  const [localSel, setLocalSel] = useState<string|null>(null);
  const activeId = localSel ?? selectedId ?? containers?.[0]?.id ?? null;
  const [status, setStatus] = useState<"idle"|"connecting"|"connected"|"error"|"closed">("idle");
  const [errorMsg, setErrorMsg] = useState<string>("");
  const containerRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const fitRef = useRef<FitAddon | null>(null);

  const connect = () => {
    if (!activeId) return;
    disconnect();
    setStatus("connecting");
    setErrorMsg("");
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const url = `${protocol}//${window.location.host}/containers/${activeId}/attach`;
    const ws = new WebSocket(url);
    ws.binaryType = "arraybuffer";
    wsRef.current = ws;

    const term = new Terminal({ cursorBlink: true, fontSize: 13, theme: { background: "#0f172a" } });
    const fit = new FitAddon();
    term.loadAddon(fit);
    termRef.current = term;
    fitRef.current = fit;
    if (containerRef.current) {
      term.open(containerRef.current);
      setTimeout(()=>fit.fit(), 50);
    }
    term.writeln(`\x1b[33mConnecting to ${activeId.slice(0,12)}…\x1b[0m`);

    term.onData((data)=>{
      if (ws.readyState===WebSocket.OPEN) ws.send(new TextEncoder().encode(data));
      // xterm fallback: also send as binary if ws expects binary
      // ws binary for attach: raw bytes. Send as binary.
      try {
        if (ws.readyState===WebSocket.OPEN) ws.send(new Uint8Array(new TextEncoder().encode(data)));
      } catch { /* ignore */ }
    });

    ws.onopen = () => { setStatus("connected"); term.writeln(`\x1b[32mAttached. Type to send input (tty only).\x1b[0m`); };
    ws.onmessage = (ev) => {
      if (typeof ev.data === "string") {
        if (ev.data === "kestrel.attach.ready") {
          term.writeln(`\x1b[90m[attach ready]\x1b[0m`);
        } else {
          term.write(ev.data);
        }
      } else if (ev.data instanceof ArrayBuffer) {
        term.write(new Uint8Array(ev.data));
      }
    };
    ws.onerror = () => { setStatus("error"); setErrorMsg("WebSocket error — check daemon reachable and container tty"); };
    ws.onclose = (e) => { setStatus("closed"); term.writeln(`\r\n\x1b[31m[closed ${e.code} ${e.reason}]\x1b[0m`); };
  };

  const disconnect = () => {
    if (wsRef.current) { try { wsRef.current.close(); } catch { /* ignore */ } wsRef.current=null; }
    if (termRef.current) { try { termRef.current.dispose(); } catch { /* ignore */ } termRef.current=null; }
    fitRef.current=null;
    if (containerRef.current) containerRef.current.innerHTML="";
    setStatus("idle");
  };

  useEffect(()=>()=>{ disconnect(); }, []);

  // handle resize sends POST /containers/:id/resize
  const sendResize = async () => {
    if (!activeId || !termRef.current) return;
    const cols = termRef.current.cols;
    const rows = termRef.current.rows;
    try {
      await fetch(`/containers/${activeId}/resize`, { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({ cols, rows }) });
    } catch (e) { setErrorMsg(String(e)); }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div><h1 className="text-xl font-semibold">Terminal</h1><p className="text-sm text-muted-foreground">xterm.js over WS /containers/:id/attach + POST /resize.</p></div>
        <div className="flex items-center gap-2">
          <Select value={activeId ?? ""} onValueChange={(v)=>{setLocalSel(v); setSelectedId(v);}}>
            <SelectTrigger className="w-[200px]"><SelectValue placeholder="Select container" /></SelectTrigger>
            <SelectContent>{containers?.map((c)=><SelectItem key={c.id} value={c.id}>{c.id.slice(0,12)} — {c.status}{c.tty?" tty":""}</SelectItem>)}</SelectContent>
          </Select>
          <Button size="sm" onClick={connect} disabled={!activeId || status==="connected" || status==="connecting"}>Attach</Button>
          <Button size="sm" variant="outline" onClick={disconnect} disabled={status==="idle"}>Disconnect</Button>
          <Button size="sm" variant="outline" onClick={sendResize} disabled={status!=="connected"}>Resize</Button>
        </div>
      </div>

      <Card>
        <CardHeader className="pb-2 flex flex-row items-center justify-between space-y-0">
          <div><CardTitle className="text-sm">xterm</CardTitle><CardDescription>Binary WS bridge to attach.sock; Text = ready signal.</CardDescription></div>
          <Badge variant={status==="connected"?"default": status==="error"?"destructive":"secondary"}>{status}</Badge>
        </CardHeader>
        <CardContent>
          {errorMsg && <div className="mb-2 text-xs text-destructive">{errorMsg}</div>}
          <div ref={containerRef} className="h-[420px] rounded bg-[#0f172a] p-2 overflow-hidden" />
          <p className="mt-2 text-xs text-muted-foreground">Non-tty containers reject input with 1008 policy violation and close. Use resize only on tty containers.</p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle className="text-sm">Also: Exec (WS /exec)</CardTitle><CardDescription>One-off exec over GET /containers/:id/exec — send init JSON then stream.</CardDescription></CardHeader>
        <CardContent className="text-xs font-mono">
          ws = new WebSocket(`ws://localhost:7777/containers/{`+"id"+`}/exec`); ws.onopen=() =&gt; ws.send(JSON.stringify({"{"}cmd:["sh"], tty:false{"}"}))
        </CardContent>
      </Card>
    </div>
  );
}
