// web/src/api/types.ts — typed mirrors of kestreld JSON responses
export type ContainerStatus = "Created" | "Running" | "Paused" | "Stopped" | string;

export interface ContainerView {
  id: string;
  status: ContainerStatus;
  pid: number | null;
  bundle: string;
  exit_code: number | null;
  tty: boolean;
  network_mode: string | null;
  namespaces: unknown | null;
  cgroup: unknown | null;
  network: NetworkInfo | null;
}

export interface NetworkInfo {
  mode: string;
  bridge_name: string | null;
  ip: string | null;
  gateway: string | null;
  published_ports: [number, number][];
}

export interface NamespaceEntry {
  ns_type: string;
  inode: number;
  shared_with: string[];
}
export interface NamespacesResponse {
  namespaces: NamespaceEntry[];
}

export interface SystemNamespacesResponse {
  processes: Record<string, Record<string, number>>;
}

export interface CpuStatOut {
  usage_usec: number;
  nr_periods: number;
  nr_throttled: number;
  throttled_usec: number;
}
export interface IoDeviceStatOut {
  major: number;
  minor: number;
  rbytes: number;
  wbytes: number;
  rios: number;
  wios: number;
  dbytes: number;
  dios: number;
}
export interface CgroupResponse {
  cpu_stat: CpuStatOut;
  memory_current: number;
  pids_current: number;
  io_stat: IoDeviceStatOut[];
  cpu_max: string;
  memory_max: string;
  pids_max: string;
}

export interface PsiLineOut {
  avg10: number;
  avg60: number;
  avg300: number;
  total_us: number;
}
export interface PsiOut {
  some: PsiLineOut;
  full: PsiLineOut | null;
}
export interface PressureResponse {
  cpu: PsiOut;
  memory: PsiOut;
  io: PsiOut;
}

export interface MountEntry {
  mount_id: number;
  parent_id: number;
  major: number;
  minor: number;
  root: string;
  mount_point: string;
  mount_options: string;
  propagation: string;
  fs_type: string;
  mount_source: string;
  super_options: string;
}
export interface MountsResponse {
  mounts: MountEntry[];
}

export interface CapabilitiesResponse {
  bounding: string[];
  effective: string[];
  inheritable: string[];
  permitted: string[];
  ambient: string[];
}

export interface LayerEntry {
  chain_id: string;
  origin: string;
  size_bytes: number;
}
export interface LayersResponse {
  layers: LayerEntry[];
}

export interface CopyUpEntry {
  path: string;
  size_bytes: number;
  from_layer: string;
  kind: string;
}
export interface CopyUpsResponse {
  copy_ups: CopyUpEntry[];
}

export interface SeccompSyscallRuleOut {
  names: string[];
  action: string;
}
export interface SeccompProfileOut {
  default_action: string;
  architectures: string[];
  syscalls: SeccompSyscallRuleOut[];
}
export interface SeccompResponse {
  profile: SeccompProfileOut | null;
  violations: string[];
}

export interface TopologyContainer {
  id: string;
  ip: string;
}
export interface TopologyBridge {
  name: string;
  subnet: string;
  containers: TopologyContainer[];
}
export interface TopologyResponse {
  bridges: TopologyBridge[];
}

export interface ContainerNetworkResponse extends NetworkInfo {}
