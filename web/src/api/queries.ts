// web/src/api/queries.ts — TanStack Query hooks for kestreld
import { useQuery } from "@tanstack/react-query";
import { api } from "./client";
import type {
  ContainerView,
  NamespacesResponse,
  CgroupResponse,
  PressureResponse,
  MountsResponse,
  CapabilitiesResponse,
  LayersResponse,
  CopyUpsResponse,
  SeccompResponse,
  SystemNamespacesResponse,
  TopologyResponse,
  NetworkInfo,
} from "./types";

export function useContainers() {
  return useQuery({
    queryKey: ["containers"],
    queryFn: () => api.listContainers() as Promise<ContainerView[]>,
    refetchInterval: 3000,
  });
}

export function useContainer(id: string | null) {
  return useQuery({
    queryKey: ["container", id],
    queryFn: () => api.getContainer(id!) as Promise<ContainerView>,
    enabled: !!id,
  });
}

export function useNamespaces(id: string | null) {
  return useQuery({
    queryKey: ["namespaces", id],
    queryFn: () => api.getNamespaces(id!) as Promise<NamespacesResponse>,
    enabled: !!id,
  });
}

export function useSystemNamespaces(enabled = true) {
  return useQuery({
    queryKey: ["system-namespaces"],
    queryFn: () => api.getSystemNamespaces() as Promise<SystemNamespacesResponse>,
    enabled,
  });
}

export function useCgroup(id: string | null) {
  return useQuery({
    queryKey: ["cgroup", id],
    queryFn: () => api.getCgroup(id!) as Promise<CgroupResponse>,
    enabled: !!id,
    refetchInterval: 2000,
  });
}

export function usePressure(id: string | null) {
  return useQuery({
    queryKey: ["pressure", id],
    queryFn: () => api.getPressure(id!) as Promise<PressureResponse>,
    enabled: !!id,
    refetchInterval: 1000,
  });
}

export function useLayers(id: string | null) {
  return useQuery({
    queryKey: ["layers", id],
    queryFn: () => api.getLayers(id!) as Promise<LayersResponse>,
    enabled: !!id,
  });
}

export function useCopyups(id: string | null) {
  return useQuery({
    queryKey: ["copyups", id],
    queryFn: () => api.getCopyups(id!) as Promise<CopyUpsResponse>,
    enabled: !!id,
    refetchInterval: 5000,
  });
}

export function useMounts(id: string | null) {
  return useQuery({
    queryKey: ["mounts", id],
    queryFn: () => api.getMounts(id!) as Promise<MountsResponse>,
    enabled: !!id,
  });
}

export function useCaps(id: string | null) {
  return useQuery({
    queryKey: ["caps", id],
    queryFn: () => api.getCaps(id!) as Promise<CapabilitiesResponse>,
    enabled: !!id,
  });
}

export function useSeccomp(id: string | null) {
  return useQuery({
    queryKey: ["seccomp", id],
    // poll every 3s — violations arrive via event bus but snapshot is polled
    queryFn: () => api.getSeccomp(id!) as Promise<SeccompResponse>,
    enabled: !!id,
    refetchInterval: 3000,
  });
}

export function useContainerNetwork(id: string | null) {
  return useQuery({
    queryKey: ["container-network", id],
    queryFn: () => api.getNetwork(id!) as Promise<NetworkInfo | null>,
    enabled: !!id,
  });
}

export function useTopology() {
  return useQuery({
    queryKey: ["topology"],
    queryFn: () => api.getSystemTopology() as Promise<TopologyResponse>,
    refetchInterval: 5000,
  });
}
