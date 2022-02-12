//! The implementation of the omegaUp sandbox.
//!
//! This has three layers:
//!
//! * Parent process: this is the process in which [`Command::spawn()`] is invoked. Linux namespace
//!   restrictions make it such that this process must perform some initialization on behalf of the
//!   namespaced process (namely: setting the u/gid mapping for the unprivileged user namespace in
//!   the container, and setting up the sandboxed process' cgroups).
//!
//!   This process will spawn the sandboxed init process and then wait for it to send the result of
//!   the execution and exit.
//! * Sandboxed init: Linux processes with pid 1 are treated differently by the kernel. One of
//!   these differences is that by default they block most async signals (except `SIGKILL`). Since
//!   the resource limits depend on the `SIGXCPU` and `SIGXFSZ` signals being delivered, there
//!   needs to be a process to act as pid 1 that will create the process to be sandboxed. This
//!   process sets _most_ of the sandboxing on itself: setting up the mount namespace, net
//!   namespace, dropping capabilities and other process-level privileges, and sending the parent
//!   process the pid of the jailed process so that the parent can set up the cgroup for the jailed
//!   process.
//!
//!   After forking the jailed process, it will receive the seccomp-bpf notification file and will
//!   wait until either a forbidden syscall is attempted to be invoked by the jailed process (which
//!   causes the sandboxed init process to kill the jailed process), for the jailed process to exit
//!   (normally or through a signal that terminates the process), or for the wall time limit to
//!   elapse, whichever happens first. Once that is done, it will send the parent process the
//!   result of the execution and exit, terminating the container and any stray processes that may
//!   be lingering.
//! * Jailed process: This is the untrusted code that will be run inside the sandbox. This process
//!   finishes sandboxing itself (setting process limits, signal handlers, and the seccomp-bpf
//!   syscall filter) and finally calls
//!   [`execve(2)`](https://man7.org/linux/man-pages/man2/execve.2.html) to start executing the
//!   untrusted code.

mod cgroups;
pub(crate) mod child;
pub(crate) mod child_init;
mod options;
pub(crate) mod parent;

use std::fmt::Debug;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use flexbuffers::FlexbufferSerializer;
use nix::errno::Errno;
use nix::sched::CloneFlags;
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::waitpid;
use nix::unistd::{fork, ForkResult, Pid};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::args;
use crate::jail::cgroups::CGroup;
use crate::sys::{clone3, CloneArgs};

pub use crate::sys::WaitStatus;
/// An alias of WaitidStatus.
pub use crate::sys::WaitidStatus as JailResult;

#[derive(Serialize, Deserialize, Debug)]
struct ParentSetupDoneEvent {}

#[derive(Serialize, Deserialize, Debug)]
struct SendSeccompFDEvent {}

#[derive(Serialize, Deserialize, Debug)]
struct SetupCgroupRequest {}

#[derive(Serialize, Deserialize, Debug)]
struct SetupCgroupResponse {}

fn write_message<T: Serialize>(writer: &mut UnixStream, message: T) -> Result<()> {
    let mut s = FlexbufferSerializer::new();
    message.serialize(&mut s).context("serialize")?;
    writer
        .write_all(&s.view().len().to_be_bytes())
        .context("write size")?;
    writer.write_all(s.view()).context("write message")?;
    Ok(())
}

fn read_message<T: DeserializeOwned>(reader: &mut UnixStream) -> Result<T> {
    let mut header = [0u8; 8];
    reader.read_exact(&mut header).context("read size")?;
    let n = usize::from_be_bytes(header.try_into().context("parse size")?);
    let mut buf = vec![0u8; n];
    reader.read_exact(&mut buf).context("read message")?;
    Ok(T::deserialize(
        flexbuffers::Reader::get_root(buf.as_slice()).context("get flexbuffers root")?,
    )
    .context("deserialize message")?)
}

/// A builder for [`Jail`].
pub struct Command {
    args: args::Args,
}

impl Command {
    /// Constructs a new `Command` for spawning a [`Jail`].
    pub fn new(args: args::Args) -> Command {
        Command { args: args }
    }

    /// Executes the [`Jail`] as a child, sandboxed process, returning a handle to it.
    pub fn spawn(self) -> Result<Jail> {
        let jail_options = options::JailOptions::new(self.args).context("create jail options")?;
        Jail::new(jail_options)
    }
}

/// Representation of a running or exited sandboxed process.
///
/// The sandboxed process will make use of [Linux
/// capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html) so that they are all
/// relatively isolated from each other and the rest of the system. The attack surface area is
/// further reduced by the use of Linux's
/// [`seccomp(2)`](https://man7.org/linux/man-pages/man2/seccomp.2.html) system call, which
/// restricts what system calls can be performed by the sandboxed process. Limits for other
/// resources (CPU time, wall time, address space, memory, filesystem usage) are also put in place
/// for the sandboxed process for even more protection.
///
/// Sandboxed processes are created by the [`Command`] struct, which configures the spawning
/// process through a builder-style interface.
///
/// There is no implementation of [`Drop`](std::ops::Drop) for sandboxed processes, so if you do
/// not ensure that the `Jail` has exited then it will continue to run, even after the `Jail`
/// handle to the child process has gone out of scope.
///
/// Calling [`wait`](Jail::wait()) will make the parent process wait until the child has actually
/// exited before continuing.
#[must_use]
pub struct Jail {
    child: Pid,
    child_start: Instant,
    meta: Option<PathBuf>,
    parent_sock: UnixStream,
    cgroups: Vec<CGroup>,
}

impl Jail {
    fn new(jail_options: options::JailOptions) -> Result<Jail> {
        let (mut parent_sock, parent_jail_sock) =
            UnixStream::pair().context("create socket pair")?;

        // We need to create a child that will become init (pid 1) in the container. This process
        // cannot be the jailed process because pid 1 processed have special rules regarding signal
        // disposision. These rules effectively ignore most signals (except the obvious ones like
        // SIGKILL), so it would complicate getting signals like SIGXCPU delivered.
        let child_start = Instant::now();
        let child = if jail_options.disable_sandboxing {
            // clone3 is blocked by Docker's seccomp filter.
            match unsafe { fork() }.context("fork")? {
                ForkResult::Parent { child, .. } => child,
                ForkResult::Child => Pid::from_raw(0),
            }
        } else {
            clone3(&mut CloneArgs {
                flags: CloneFlags::CLONE_NEWUSER
                    | CloneFlags::CLONE_NEWPID
                    | CloneFlags::CLONE_NEWIPC
                    | CloneFlags::CLONE_NEWUTS
                    | CloneFlags::CLONE_NEWCGROUP,
                exit_signal: libc::SIGCHLD,
            })
            .context("clone")?
        };
        if child == Pid::from_raw(0) {
            std::mem::drop(parent_sock);
            match child_init::run(parent_jail_sock, jail_options) {
                Ok(()) => unsafe { libc::exit(0) },
                Err(err) => {
                    log::error!("child execution failed: {:#}", err);
                    unsafe { libc::exit(1) }
                }
            }
        }

        std::mem::drop(parent_jail_sock);
        let cgroups = match parent::setup_child(&mut parent_sock, child, &jail_options) {
            Ok(cgroups) => cgroups,
            Err(err) => {
                log::error!("setup child failed: {:#}", err);

                // Forcibly kill the child, but still return so that the caller can still call
                // wait().
                kill(child, Signal::SIGKILL).context("kill child")?;
                return Ok(Jail {
                    child: child,
                    child_start: child_start,
                    meta: jail_options.meta,
                    parent_sock: parent_sock,
                    cgroups: vec![],
                });
            }
        };

        Ok(Jail {
            child: child,
            child_start: child_start,
            meta: jail_options.meta,
            parent_sock: parent_sock,
            cgroups: cgroups,
        })
    }

    /// Waits for the sandboxed process to exit completely, returning information about resource
    /// usage and exit status of the process.
    ///
    /// This function consumes the `Jail`, so it can only be used once.
    pub fn wait(mut self) -> Result<JailResult> {
        // Even if we don't get a result back, proceed so that we can wait on the child. This
        // prevents the sandbox from becoming a zombie.
        let status = match read_message::<JailResult>(&mut self.parent_sock) {
            Err(err) => {
                log::error!("read waitid status message: {:#}", err);
                let _ = kill(self.child, Signal::SIGKILL);
                JailResult {
                    status: WaitStatus::Signaled(self.child, Signal::SIGKILL),
                    user_time: Duration::ZERO,
                    system_time: Duration::ZERO,
                    wall_time: Instant::now().duration_since(self.child_start),
                    max_rss: 0,
                }
            }
            Ok(status) => status,
        };

        loop {
            match waitpid(self.child, None) {
                Err(Errno::EINTR) => {
                    continue;
                }
                Err(err) => {
                    log::error!("waitpid({}, 0): {:#}", self.child, err);
                }
                Ok(_) => {
                    break;
                }
            }
        }

        // This is here just to make the dead code detector to avoid complaining about the cgroups.
        // This way the directories will be deleted here once the child has exited.
        std::mem::drop(self.cgroups);

        if let Some(meta) = &self.meta {
            if let Err(err) = Jail::wait_write_meta_file(&meta, &status) {
                log::error!("write meta file: {:#}", err);
            }
        }

        Ok(status)
    }

    fn wait_write_meta_file<P>(meta: P, status: &JailResult) -> Result<()>
    where
        P: Debug + AsRef<Path>,
    {
        let mut meta_file = File::create(&meta).with_context(|| anyhow!("create {:?}", &meta))?;

        meta_file
            .write_fmt(format_args!("time:{}\n", status.user_time.as_micros()))
            .with_context(|| anyhow!("write {:?}", meta))?;
        meta_file
            .write_fmt(format_args!(
                "time-sys:{}\n",
                status.system_time.as_micros()
            ))
            .with_context(|| anyhow!("write {:?}", meta))?;
        meta_file
            .write_fmt(format_args!("time-wall:{}\n", status.wall_time.as_micros()))
            .with_context(|| anyhow!("write {:?}", meta))?;
        meta_file
            .write_fmt(format_args!("mem:{}\n", status.max_rss))
            .with_context(|| anyhow!("write {:?}", meta))?;
        match status.status {
            WaitStatus::Exited(_, status) => meta_file
                .write_fmt(format_args!("status:{}\n", status))
                .with_context(|| anyhow!("write {:?}", meta))?,
            WaitStatus::Signaled(_, signal) => meta_file
                .write_fmt(format_args!("signal:{}\n", signal.as_str()))
                .with_context(|| anyhow!("write {:?}", meta))?,
            WaitStatus::Syscalled(_, syscall) => meta_file
                .write_fmt(format_args!(
                    "signal:SIGSYS\nsyscall:{}\n",
                    syscalls::Sysno::new(syscall.try_into()?)
                        .map_or_else(|| format!("#{}", syscall), |s| String::from(s.name()))
                ))
                .with_context(|| anyhow!("write {:?}", meta))?,
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::fs::{create_dir, read_to_string, write, File};
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::Duration;

    use anyhow::{anyhow, Context, Result};
    use nix::mount::MsFlags;
    use nix::sys::signal::Signal;
    use nix::unistd::Pid;
    use once_cell::sync::Lazy;
    use tempdir::TempDir;

    use crate::jail::options::{JailOptions, MountArgs, Stdio};
    use crate::jail::{Jail, JailResult, WaitStatus};

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    struct TestCase {
        widget: &'static str,
        stdin: &'static str,
        stdout: Option<&'static str>,
        stderr: Option<&'static str>,
        status: WaitStatus,
    }

    impl Default for TestCase {
        fn default() -> TestCase {
            TestCase {
                widget: "",
                stdin: "",
                stdout: None,
                stderr: None,
                status: WaitStatus::Exited(Pid::from_raw(2), 0),
            }
        }
    }

    static TEST_HELPER_PATH: Lazy<PathBuf> = Lazy::new(|| {
        assert!(Command::new("cargo")
            .args(["build", "--quiet", "--bin=omegajail-test-helper"])
            .status()
            .context("run cargo build --quiet --bin=omegajail-test-helper")
            .unwrap()
            .success());

        PathBuf::from("./target/debug/omegajail-test-helper")
            .canonicalize()
            .unwrap()
    });

    fn run_test_case(test_case: TestCase) -> Result<JailResult> {
        let tmp_dir = TempDir::new(&test_case.widget)
            .with_context(|| anyhow!("TempDir::new({})", &test_case.widget))?;

        let stdin_path = tmp_dir.path().join("stdin");
        write(&stdin_path, test_case.stdin.as_bytes())
            .with_context(|| anyhow!("write({:?}, {})", &stdin_path, &test_case.stdin))?;
        let stdout_path = tmp_dir.path().join("stdout");
        File::create(&stdout_path).with_context(|| anyhow!("File::create({:?})", &stdout_path))?;
        let stderr_path = tmp_dir.path().join("stderr");
        File::create(&stderr_path).with_context(|| anyhow!("File::create({:?})", &stderr_path))?;

        let rootfs_path = tmp_dir.path().join("rootfs");
        create_dir(&rootfs_path).with_context(|| anyhow!("create_dir({:?})", &rootfs_path))?;

        let options = JailOptions {
            disable_sandboxing: false,
            homedir: PathBuf::from("/home"),
            rootfs: rootfs_path.clone(),
            cgroup_path: None,
            mounts: vec![
                MountArgs {
                    source: Some(PathBuf::from("/")),
                    target: rootfs_path.clone(),
                    fstype: None,
                    flags: MsFlags::MS_BIND | MsFlags::MS_RDONLY | MsFlags::MS_REC,
                    data: None,
                },
                MountArgs {
                    source: None,
                    target: rootfs_path.join("proc"),
                    fstype: Some(String::from("proc")),
                    flags: MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
                    data: None,
                },
                MountArgs {
                    source: None,
                    target: rootfs_path.join("mnt"),
                    fstype: Some(String::from("tmpfs")),
                    flags: MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
                    data: Some(String::from("size=4096,mode=555")),
                },
                MountArgs {
                    source: Some(PathBuf::from(tmp_dir.path())),
                    target: rootfs_path.join("mnt/stdio"),
                    fstype: None,
                    flags: MsFlags::MS_BIND | MsFlags::MS_RDONLY | MsFlags::MS_REC,
                    data: None,
                },
            ],
            args: vec![
                CString::new((*TEST_HELPER_PATH).to_str().ok_or_else(|| anyhow!("path is not unicode"))?)?,
                CString::new(format!("--widget={}", test_case.widget))?,
            ],
            env: vec![],
            // allows everything _except_ `mount(2)`.
            seccomp_bpf_filter_contents: base64::decode("IAAAAAQAAAAVAAEAPgAAwAYAAAAAAAAAIAAAAAAAAAAVAAIBpQAAAAYAAAAAAP9/BgAAAAAA/38GAAAAAADAfw==")?,
            seccomp_profile_name: String::from("test"),
            meta: None,

            stdin: Stdio::Mounted(stdin_path.clone()),
            stdout: Stdio::Mounted(stdout_path.clone()),
            stderr: Stdio::Mounted(stderr_path.clone()),

            time_limit: Some(Duration::from_secs(1)),
            wall_time_limit: Duration::from_secs(2),
            output_limit: Some(16 * 1024),
            memory_limit: Some(32 * 1024 * 1024),
            use_cgroups_for_memory_limit: false,
            vm_memory_size_in_bytes: 0u64,
        };

        let jail = Jail::new(options)?;

        let result = jail.wait()?;
        assert_eq!(test_case.status, result.status);

        if let Some(expected_stdout) = test_case.stdout {
            let stdout = read_to_string(&stdout_path)?;
            assert_eq!(expected_stdout, &stdout);
        }
        if let Some(expected_stderr) = test_case.stderr {
            let stderr = read_to_string(&stderr_path)?;
            assert_eq!(expected_stderr, &stderr);
        }

        Ok(result)
    }

    #[test]
    fn test_stdio() -> Result<()> {
        init();
        run_test_case(TestCase {
            widget: "stdio",
            stdin: "stdin\n",
            stdout: Some("stdout\n"),
            stderr: Some("stderr\n"),
            ..TestCase::default()
        })?;

        Ok(())
    }

    #[test]
    fn test_file_descriptors() -> Result<()> {
        init();
        run_test_case(TestCase {
            widget: "file-descriptors",
            stdin: "",
            // File descriptor 3 is the fd of the `/proc/self/fd` directory.
            stdout: Some("/proc/self/fd/0\n/proc/self/fd/1\n/proc/self/fd/2\n/proc/self/fd/3\n"),
            stderr: Some(""),
            ..TestCase::default()
        })?;

        Ok(())
    }

    #[test]
    fn test_abort() -> Result<()> {
        init();
        run_test_case(TestCase {
            widget: "abort",
            stdin: "",
            stdout: Some(""),
            status: WaitStatus::Signaled(Pid::from_raw(2), Signal::SIGABRT),
            ..TestCase::default()
        })?;

        Ok(())
    }

    #[test]
    fn test_oom() -> Result<()> {
        init();
        let result = run_test_case(TestCase {
            widget: "oom",
            stdin: "",
            status: WaitStatus::Exited(Pid::from_raw(2), 1),
            ..TestCase::default()
        })?;

        assert!(result.max_rss >= 16 * 1024 * 1024);

        Ok(())
    }

    #[test]
    fn test_syscall() -> Result<()> {
        init();
        run_test_case(TestCase {
            widget: "syscall",
            stdin: "",
            status: WaitStatus::Syscalled(Pid::from_raw(2), libc::SYS_mount.try_into()?),
            ..TestCase::default()
        })?;

        Ok(())
    }

    #[test]
    fn test_sigxfsz() -> Result<()> {
        init();
        run_test_case(TestCase {
            widget: "sigxfsz",
            stdin: "",
            status: WaitStatus::Signaled(Pid::from_raw(2), Signal::SIGXFSZ),
            ..TestCase::default()
        })?;

        Ok(())
    }

    #[test]
    fn test_sigxcpu() -> Result<()> {
        init();
        let result = run_test_case(TestCase {
            widget: "sigxcpu",
            stdin: "",
            stdout: Some(""),
            status: WaitStatus::Signaled(Pid::from_raw(2), Signal::SIGXCPU),
            ..TestCase::default()
        })?;

        // This is proactively killed by the CPU time limit.
        assert!(result.wall_time >= Duration::from_secs(1));
        assert!(result.wall_time <= Duration::from_secs(2));

        Ok(())
    }

    #[test]
    fn test_sleep() -> Result<()> {
        init();
        let result = run_test_case(TestCase {
            widget: "sleep",
            stdin: "",
            stdout: Some(""),
            status: WaitStatus::Signaled(Pid::from_raw(2), Signal::SIGXCPU),
            ..TestCase::default()
        })?;

        // This does not use any CPU (it's only sleeping), so it's killed by the wall-time limit.
        assert!(result.wall_time >= Duration::from_secs(2));

        Ok(())
    }
}
