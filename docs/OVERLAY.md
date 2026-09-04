# docs/OVERLAY.md — OverlayFS in Kestrel

Layer model, snapshotter layout, whiteouts, opaque dirs, copy-up, and the symlink farm.

## Layer Model

Images are content-addressed. Every blob (manifest, config, tar) is stored by `sha256:<digest>` under `content/blobs/sha256/`. Extraction computes two hashes:

* **digest** — SHA-256 of the *compressed* blob (manifest reference, fetch verification).
* **diffID** — SHA-256 of the *uncompressed* tar (listed in image config `rootfs.diff_ids`).

**chainID** identifies a stack:

```
chainID(0) = diffID(0)
chainID(n) = SHA256( chainID(n-1) + " " + diffID(n) )
```

Two images sharing a base share chainIDs → layers deduped on disk.

```
content/blobs/sha256/<digest>          ← compressed tar, manifest, config
layers/<chainID>/
  diff/                                ← extracted lowerdir
  link                                 ← short name for symlink farm
  parent                               ← parent chainID
l/<6-char>  ->  ../layers/<chain>/diff ← symlink farm
snapshots/<id>/
  upper/                               ← writable layer
  work/                                ← overlay workdir (MUST be empty at mount)
  merged/                              ← mountpoint
```

```
     ┌─────────────────────────────────────────────────┐
     │              merged (mountpoint)                │  ← what container sees
     ├─────────────────────────────────────────────────┤
     │  upper/          │  l/ABCD12 → …  l/EF34GH → … │  ← upper + lowerdir stack
     │  (writable)      │  (symlink farm, bottom→top) │
     ├──────────────────┴──────────────────────────────┤
     │  lower layers (read-only diffs, shared)         │
     │  chain n ──► chain n-1 ──► … ──► chain 0 (base)│
     └─────────────────────────────────────────────────┘

  Mount option (rightmost = bottom, so layers reversed):
    lowerdir=l/EF34GH:l/ABCD12:… , upperdir=…/upper , workdir=…/work
```

## The Mount

```rust
pub fn mount_overlay(&self, snap: &Snapshot) -> Result<()> {
    let lowers: Vec<String> = snap.lower_links.iter().rev().map(|l| format!("l/{l}")).collect();
    let mut opts = format!("lowerdir={},upperdir={},workdir={}", lowers.join(":"), snap.upper.display(), snap.work.display());
    if self.rootless { opts.push_str(",userxattr"); }          // 5.11+, unprivileged xattrs
    if self.metacopy { opts.push_str(",metacopy=on"); }        // chmod → metadata-only copy-up
    if self.redirect_dir { opts.push_str(",redirect_dir=on"); }
    mount(Some("overlay"), &snap.merged, Some("overlay"), MsFlags::empty(), Some(opts.as_str()))?;
    Ok(())
}
```

* `userxattr` (5.11+): use `user.overlay.*` instead of `trusted.overlay.*` when rootless.
* `metacopy=on`: `chmod`/`chown` copies metadata only; data deferred to first write.
* `index=on`, `volatile` optional.

Unmount via `MNT_DETACH` with busy-retry.

## Why the Symlink Farm Exists

Mount option strings are capped at one page (4096 bytes). An image with 40 layers × 64-hex chainIDs blows past it. Docker's `overlay2` solution:

```
l/DPFA3D  ->  ../layers/sha256:9f8a…/diff
```

and `chdir(data_dir)` before mounting so options use relative `l/<short>` paths. Not an optimization — deep images fail to mount without it.

```
  Without farm:  lowerdir=/var/lib/kestrel/layers/sha256:abc…/diff:/var/lib/kestrel/layers/sha256:def…/diff:…  →  >4096 bytes → EINVAL
  With farm:     lowerdir=l/DPFA3D:l/XK92PQ:…  +  chdir(/var/lib/kestrel)  →  fits in one page
```

## Whiteouts & Opaque Dirs

OCI layers encode deletions as `.wh.*` files in the tar. Extraction translates:

| Concept | Tar entry | On-disk (upperdir) |
|---------|-----------|---------------------|
| Deleted file | `.wh.<name>` | char device `0:0` (`mknod S_IFCHR`) |
| Deleted+recreated dir (opaque) | `.wh..wh..opq` | xattr `trusted.overlay.opaque="y"` (or `user.overlay.opaque`) |
| Renamed dir from lower | — | xattr `trusted.overlay.redirect=<path>` |

```rust
for entry in Archive::new(tar).entries()? {
    let name = path.file_name().unwrap_or("");
    if name == ".wh..wh..opq" {
        xattr::set(&dir, &format!("{ns}.opaque"), b"y")?; continue;
    }
    if let Some(target) = name.strip_prefix(".wh.") {
        let wh = dest.join(parent).join(target);
        let _ = fs::remove_file(&wh);
        mknod(&wh, SFlag::S_IFCHR, Mode::empty(), makedev(0,0))?; continue;
    }
    entry.unpack_in(dest)?;
}
```

* Hardlinks handled within a single layer.
* Path traversal guarded: reject `..`, absolute, symlink-escape entries.
* `work` must be empty at mount time.
* Driver fallback: `overlay2` → `fuse-overlayfs` → `vfs` (full copy, slow but correct).

## Copy-Up & Tracing

Writing one byte to a 2 GiB lower file copies the full 2 GiB — the biggest surprise disk/latency cost. Kestrel makes it visible:

```rust
pub struct CopyUpEvent {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub from_layer: String,   // origin chainID
    pub detected_at: SystemTime,
    pub kind: CopyUpKind,     // Data | MetadataOnly | Whiteout | Opaque
}
pub fn scan_copy_ups(snap: &Snapshot, ns: &str) -> Result<Vec<CopyUpEvent>>
```

Walk `upperdir`, correlate against lowers; `metacopy` xattr distinguishes `MetadataOnly` from `Data`. The UI shows a heatmap (top files by bytes, amplification ratio = logical writes vs physical bytes) and shared-layer indicators.

## pivot_root (The Modern Idiom)

`chroot` is escapable (`fchdir` + `chdir("..")` with a leaked fd or `CAP_SYS_CHROOT`); `pivot_root` swaps the mount serving as `/`:

```rust
mount(None::<&str>, "/", None::<&str>, MS_REC|MS_PRIVATE, None::<&str>)?; // detach propagation or pivot fails
mount(Some(new_root), new_root, None::<&str>, MS_BIND|MS_REC, None::<&str>)?; // make mount point
chdir(new_root)?;
pivot_root(".", ".")?;                                           // old root stacked over "."
mount(None::<&str>, ".", None::<&str>, MS_REC|MS_SLAVE, None::<&str>)?; // don't propagate umount
umount2(".", MNT_DETACH)?; chdir("/")?;
```

Fallback is `MS_MOVE` + `chroot` where `pivot_root` unavailable.

## Standard Mounts (Before pivot_root, Into merged)

| Target | Type | Options |
|--------|------|---------|
| `/proc` | `proc` | `nosuid,noexec,nodev` |
| `/sys` | `sysfs` | `nosuid,noexec,nodev,ro` |
| `/sys/fs/cgroup` | `cgroup2` | `nosuid,noexec,nodev,relatime,ro` (rw if cgroupns) |
| `/dev` | `tmpfs` | `nosuid,strictatime,mode=755,size=65536k` |
| `/dev/pts` | `devpts` | `newinstance,ptmxmode=0666,mode=0620,gid=5` |
| `/dev/shm` | `tmpfs` | `mode=1777,size=65536k` |
| `/dev/mqueue` | `mqueue` | `nosuid,noexec,nodev` |

Device nodes (`null/zero/full/random/urandom/tty`) via `mknod` when privileged, else **bind-mounted from host** when rootless.

Masked (`/proc/acpi`, `/proc/kcore`, `/sys/firmware`, …) → `/dev/null` bind or empty ro `tmpfs`. Read-only (`/proc/bus`, `/proc/sys`, …) → **bind then remount** (single `MS_BIND|MS_RDONLY` silently ignores `RDONLY` — classic bug; `make_readonly` does the two-call sequence).

## Further Reading

* `crates/kestrel-rootfs/src/{snapshot,overlay,mounts,pivot}.rs`
* `docs/superpowers/specs/2026-08-03-phase4-rootfs-design.md`
* SPEC §6–§7, CHECKLIST Phase 4
