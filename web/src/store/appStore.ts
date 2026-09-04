// web/src/store/appStore.ts — zustand store for dashboard
import { create } from "zustand";

export type KestrelEvent = {
  type: string;
  data: unknown;
  timestamp: string;
};

interface AppState {
  selectedId: string | null;
  setSelectedId: (id: string | null) => void;
  events: KestrelEvent[];
  pushEvent: (ev: KestrelEvent) => void;
  clearEvents: () => void;
  violationFeed: { id: string; syscall: string; ts: string }[];
  pushViolation: (v: { id: string; syscall: string; ts: string }) => void;
}

export const useAppStore = create<AppState>((set) => ({
  selectedId: null,
  setSelectedId: (id) => set({ selectedId: id }),
  events: [],
  pushEvent: (ev) => set((s) => ({ events: [ev, ...s.events].slice(0, 100) })),
  clearEvents: () => set({ events: [] }),
  violationFeed: [],
  pushViolation: (v) => set((s) => ({ violationFeed: [v, ...s.violationFeed].slice(0, 50) })),
}));
