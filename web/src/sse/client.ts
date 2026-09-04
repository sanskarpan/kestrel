// web/src/sse/client.ts — EventSource with reconnect backoff, feeds zustand store
export type KestrelEvent = {
  type: string;
  data: unknown;
  timestamp: string;
};

export function createEventSource(
  url: string,
  onEvent: (ev: KestrelEvent) => void,
  onStatus: (connected: boolean) => void,
): () => void {
  let es: EventSource | null = null;
  let backoff = 500;
  let closed = false;

  const connect = () => {
    if (closed) return;
    es = new EventSource(url);
    es.onopen = () => {
      backoff = 500;
      onStatus(true);
    };
    es.onerror = () => {
      onStatus(false);
      es?.close();
      if (!closed) setTimeout(connect, backoff);
      backoff = Math.min(backoff * 2, 10000);
    };
    es.onmessage = (e) => {
      try {
        const parsed = JSON.parse(e.data) as KestrelEvent;
        onEvent(parsed);
      } catch {
        onEvent({ type: "message", data: e.data, timestamp: new Date().toISOString() });
      }
    };
  };

  connect();
  return () => {
    closed = true;
    es?.close();
  };
}
