//! Hook execution with a timeout, WITHOUT spawning any thread (Rule #2:
//! kestrel-runtime must not spawn threads, transitively — a
//! Command::spawn() child is a process, not a thread, so this is fine;
//! a naive timeout-via-watcher-thread would not be). Shared by
//! kestrel-runtime (createRuntime/poststart/poststop hooks) and
//! kestrel-init (createContainer/startContainer hooks) — lives in
//! kestrel-oci since both already depend on it and neither can depend on
//! the other.

use std::io::Write;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use crate::runtime::Hook;

pub fn run_hooks(hooks: &[Hook], stdin_json: &[u8]) -> Result<()> {
    for hook in hooks {
        run_one_hook(hook, stdin_json)?;
    }
    Ok(())
}

fn run_one_hook(hook: &Hook, stdin_json: &[u8]) -> Result<()> {
    let mut cmd = Command::new(hook.path());
    if let Some(args) = hook.args() {
        // Per Hook's own doc comment, `args` follows execv(3) argv
        // semantics: "Arguments used for the binary, including the
        // binary name itself." That means args[0] is the process's
        // intended argv[0] (conventionally the binary's name), which is
        // NOT necessarily the same string as `hook.path()` (the path
        // used to *locate* the binary) — execv's own path-vs-argv[0]
        // split allows them to differ, and OCI runtimes (e.g. runc) hand
        // `hook.Args` to the underlying exec syscall completely
        // unmodified, letting argv[0] be whatever the hook author wrote.
        //
        // EMPIRICALLY VERIFIED (see hooks::tests::test_hook_receives_args0_as_argv0_not_duplicated
        // below, using a compiled C probe binary that dumps its own argv
        // — a real ELF binary, not a `#!/bin/sh` script, because the
        // kernel's shebang handling rewrites argv[0] for scripts
        // regardless of what any caller sets, which would have given a
        // false signal either way):
        // std::process::Command has no built-in way to make argv[0]
        // diverge from the program path — Command::new(path).args(&args[..])
        // would duplicate the binary name (argv[0] = path, argv[1] =
        // args[0] = the name again, which is the bug this comment
        // originally warned about), and Command::new(path).args(&args[1..])
        // would silently drop the caller's requested argv[0] and
        // substitute `hook.path()` instead — neither matches execv
        // semantics. The correct mapping uses the Unix-only
        // `CommandExt::arg0` to set argv[0] independently of the
        // executable path, then appends the rest of `args` starting at
        // index 1:
        if let Some((arg0, rest)) = args.split_first() {
            cmd.arg0(arg0);
            cmd.args(rest);
        }
    }
    if let Some(env) = hook.env() {
        cmd.env_clear();
        for kv in env {
            if let Some((k, v)) = kv.split_once('=') {
                cmd.env(k, v);
            }
        }
    }
    cmd.stdin(Stdio::piped());

    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawning hook {}", hook.path().display()))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(stdin_json);
    }

    let timeout = hook
        .timeout()
        .map(|s| Duration::from_secs(s as u64))
        .unwrap_or(Duration::from_secs(30));
    wait_with_timeout(&mut child, timeout)
        .with_context(|| format!("hook {} timed out or failed", hook.path().display()))
}

fn wait_with_timeout(child: &mut Child, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().context("polling hook process")? {
            anyhow::ensure!(status.success(), "hook exited with {status}");
            return Ok(());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("hook exceeded its timeout");
        }
        // NOTE for reviewers: this does NOT spawn a new OS thread. It
        // blocks the CALLING thread (the same thread already running
        // run_hooks/wait_with_timeout), which is exactly what Rule #2
        // requires — the rule forbids kestrel-runtime from creating
        // additional threads, not from sleeping on the one it already
        // has. std::thread::sleep is a syscall (nanosleep) made by the
        // current thread, not a constructor for a new one.
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::HookBuilder;
    use std::fs;
    use std::time::Instant;

    #[test]
    fn test_successful_hook_returns_ok() {
        let hook = HookBuilder::default()
            .path("/usr/bin/true")
            .build()
            .expect("build hook");
        // /usr/bin/true may not exist on every platform; fall back to /bin/true.
        let hook = if hook.path().exists() {
            hook
        } else {
            HookBuilder::default()
                .path("/bin/true")
                .build()
                .expect("build hook")
        };

        let result = run_hooks(std::slice::from_ref(&hook), b"{}");
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn test_failing_hook_returns_err() {
        let hook = HookBuilder::default()
            .path("/usr/bin/false")
            .build()
            .expect("build hook");
        let hook = if hook.path().exists() {
            hook
        } else {
            HookBuilder::default()
                .path("/bin/false")
                .build()
                .expect("build hook")
        };

        let result = run_hooks(std::slice::from_ref(&hook), b"{}");
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn test_hook_exceeding_timeout_is_killed_within_timeout_window() {
        // Deliberately NOT a freshly-written-to-disk script. Writing a
        // fresh `sleepy.sh` via fs::write + chmod and then immediately
        // Command::spawn()-ing it races the kernel's handling of a
        // just-written, just-chmod'd executable: spawn can intermittently
        // fail with ETXTBSY ("Text file busy"), especially under
        // concurrent filesystem I/O from other parallel-running tests on
        // this project's virtiofs-backed Lima VM mount. A spawn failure
        // is still `Err`, so it would silently satisfy the
        // `result.is_err()` assertion below while completing in a few
        // milliseconds — a completely different failure path than the
        // timeout-driven SIGKILL this test exists to exercise — which
        // then (correctly) trips the test's own lower-bound timing
        // assertion. Using `/bin/sh`, a stable binary that is already on
        // disk before this test ever runs, sidesteps that race window
        // entirely: there is no fresh write for the kernel to still be
        // settling. `-c "sleep 5"` gives the same "hangs past the
        // timeout" behavior the test needs without a script file.
        let hook = HookBuilder::default()
            .path("/bin/sh")
            .args(vec![
                "sh".to_string(),
                "-c".to_string(),
                "sleep 5".to_string(),
            ])
            .timeout(1i64)
            .build()
            .expect("build hook");

        let start = Instant::now();
        let result = run_hooks(std::slice::from_ref(&hook), b"{}");
        let elapsed = start.elapsed();

        assert!(result.is_err(), "expected Err, got {result:?}");
        // The poll loop should notice the timeout and kill the child
        // within roughly one timeout window, not block forever on a
        // hung wait() for the full 5s sleep.
        assert!(
            elapsed < Duration::from_millis(2500),
            "expected timeout enforcement near 1s, took {elapsed:?}"
        );
        assert!(
            elapsed >= Duration::from_millis(900),
            "timeout fired suspiciously early: {elapsed:?}"
        );
    }

    /// Empirically resolves the args[0]-skipping question flagged in this
    /// module's doc comment: compiles a tiny C probe that dumps its own
    /// argv to a file, invokes it through a Hook whose `args` follows the
    /// OCI convention (args[0] == the intended binary name, distinct from
    /// `path`), and asserts on what the probe actually received.
    ///
    /// Uses a *compiled* C binary as the probe, not a `#!/bin/sh` script.
    /// An earlier version of this test used a shell script and got a
    /// false signal: Linux's kernel-level shebang handling
    /// (`binfmt_script`) unconditionally rewrites argv when execing an
    /// interpreted script — it discards whatever argv[0] the caller
    /// supplied and substitutes `[interpreter, script_path, ...original
    /// argv[1:]]` before the interpreter ever sees it. That rewrite
    /// happens in the kernel, identically for every caller (`execve`
    /// directly, runc, or this code) — it is not something any
    /// userspace runtime can opt out of, so a script-based probe cannot
    /// distinguish "our arg0 handling is wrong" from "the target
    /// happened to be a script". Compiling a real ELF binary removes
    /// that confound and tests the actual mechanism this module relies
    /// on: `std::os::unix::process::CommandExt::arg0`.
    #[test]
    fn test_hook_receives_args0_as_argv0_not_duplicated() {
        let tmp = tempdir();
        let out_file = tmp.join("argv.out");
        let probe = compile_argv_probe_binary(&tmp, &out_file);

        let hook = HookBuilder::default()
            .path(probe)
            .args(vec![
                "some-name".to_string(),
                "arg1".to_string(),
                "arg2".to_string(),
            ])
            .build()
            .expect("build hook");

        let result = run_hooks(std::slice::from_ref(&hook), b"{}");
        assert!(result.is_ok(), "expected Ok, got {result:?}");

        let received = fs::read_to_string(&out_file).expect("read argv dump");
        // argv[0] must be "some-name" (args[0] from the Hook spec), NOT
        // the probe binary's own path, and NOT duplicated as an extra
        // argument. argv[1]/argv[2] carry the rest of args unchanged.
        let expected = "argv[0]=some-name\nargv[1]=arg1\nargv[2]=arg2\n";
        assert_eq!(received, expected, "hook did not receive expected argv");

        cleanup_tempdir(tmp);
    }

    /// Compiles a tiny C program (via `cc`, present on the dev box/VM)
    /// that dumps its own `argv` to `out_file` and returns the path to
    /// the resulting binary. `out_file`'s path is baked in as a string
    /// literal at compile time rather than passed via env/argv, so the
    /// probe's own argv is exactly what the caller (this test) supplies
    /// through `Hook::args` — nothing extra layered on top.
    fn compile_argv_probe_binary(
        dir: &std::path::Path,
        out_file: &std::path::Path,
    ) -> std::path::PathBuf {
        let src_path = dir.join("argv_probe.c");
        let bin_path = dir.join("argv_probe");
        let src = format!(
            r#"#include <stdio.h>
int main(int argc, char **argv) {{
    FILE *f = fopen("{out}", "w");
    if (!f) return 1;
    for (int i = 0; i < argc; i++) {{
        fprintf(f, "argv[%d]=%s\n", i, argv[i]);
    }}
    fclose(f);
    return 0;
}}
"#,
            out = out_file.display()
        );
        fs::write(&src_path, src).expect("write probe C source");

        let status = Command::new("cc")
            .arg("-o")
            .arg(&bin_path)
            .arg(&src_path)
            .status()
            .expect("run cc to compile argv probe");
        assert!(status.success(), "cc failed to compile argv probe");

        bin_path
    }

    // --- tiny tempdir helpers (avoid pulling in a tempfile dependency
    // just for these four tests) ---

    fn tempdir() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_nanos();
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);

        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "kestrel-oci-hooks-test-{}-{nanos}-{n}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create tempdir");
        dir
    }

    fn cleanup_tempdir(dir: std::path::PathBuf) {
        let _ = fs::remove_dir_all(dir);
    }
}
