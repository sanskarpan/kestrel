//! OCI Runtime & Image Spec types, re-exported from `oci-spec`, plus
//! kestrel-specific extensions (validation, default-spec generation,
//! image-config translation, user resolution, forward-compatible parsing).

pub mod default_spec;
pub mod image;
pub mod raw;
pub mod state;
pub mod user;
pub mod validate;

pub mod runtime {
    pub use oci_spec::runtime::{
        Arch,
        Capabilities,
        Capability,
        Hooks,
        Linux,
        LinuxBlockIo,
        LinuxBlockIoBuilder,
        LinuxBuilder,
        LinuxCapabilities,
        LinuxCapabilitiesBuilder,
        LinuxCpu,
        LinuxCpuBuilder,
        LinuxDevice,
        LinuxHugepageLimit,
        LinuxHugepageLimitBuilder,
        LinuxIdMapping,
        LinuxIdMappingBuilder,
        LinuxMemory,
        LinuxMemoryBuilder,
        LinuxNamespace,
        LinuxNamespaceType,
        LinuxPids,
        LinuxPidsBuilder,
        LinuxResources,
        LinuxResourcesBuilder,
        LinuxSeccomp,
        LinuxSeccompAction,
        LinuxSeccompArg,
        LinuxSeccompArgBuilder,
        LinuxSeccompBuilder,
        LinuxSeccompFilterFlag,
        LinuxSeccompOperator,
        LinuxSyscall,
        LinuxSyscallBuilder,
        Mount,
        MountBuilder,
        PosixRlimit,
        // LinuxRlimit is an alias for upstream's PosixRlimit, to match this project's own CHECKLIST.md naming.
        PosixRlimit as LinuxRlimit,
        PosixRlimitBuilder,
        PosixRlimitType,
        Process,
        ProcessBuilder,
        Root,
        RootBuilder,
        Spec,
        SpecBuilder,
        User,
        UserBuilder,
    };
}

pub mod image_spec {
    pub use oci_spec::image::{
        Config, ConfigBuilder, Descriptor, ImageConfiguration, ImageConfigurationBuilder,
        ImageIndex, ImageManifest, RootFs, RootFsBuilder,
    };
}
