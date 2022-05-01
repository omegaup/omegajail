use std::fs::{read_to_string, File};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use anyhow::{bail, Context, Error, Result};
use nix::errno::Errno;
use nix::ioctl_readwrite;
use nix::sched::CloneFlags;
use nix::sys::signal::Signal;
use nix::sys::wait::WaitPidFlag;
use nix::unistd::Pid;
use passfd::FdPassingExt;
use serde::{Deserialize, Serialize};

/// Error checker for libc functions.
///
/// Returns an [`std::io::Error`] with the stringified error if the result of the function call is
/// negative, and the result of the function as-is otherwise.
fn check_err(num: libc::c_long) -> Result<libc::c_long> {
    if num < 0 {
        return Err(Error::new(Errno::from_i32(num.try_into()?)));
    }
    Ok(num)
}

/// Arguments to clone3.
pub(crate) struct CloneArgs {
    /// Flags bit mask
    pub(crate) flags: CloneFlags,
    /// Signal to deliver to parent on child termination
    pub(crate) exit_signal: i32,
}

/// Creates a new process or thread. Returns in both parent and child process.
pub(crate) fn clone3(args: &CloneArgs) -> Result<Pid> {
    /// The low-level interface to the clone arguments.
    #[repr(C)]
    struct LinuxCloneArgs {
        /// Flags bit mask
        flags: u64,
        /// Where to store PID file descriptor (int *)
        pidfd: u64,
        /// Where to store child TID, in child's memory (pid_t *)
        child_tid: u64,
        /// Where to store child TID, in parent's memory (pid_t *)
        parent_tid: u64,
        /// Signal to deliver to parent on child termination
        exit_signal: u64,
        /// Pointer to lowest byte of stack
        stack: u64,
        /// Size of stack
        stack_size: u64,
        /// Location of new TLS
        tls: u64,
        /// Pointer to a pid_t array (since Linux 5.5)
        set_tid: u64,
        /// Number of elements in set_tid (since Linux 5.5)
        set_tid_size: u64,
        /// File descriptor for target cgroup of child (since Linux 5.7)
        cgroup: u64,
    }

    let mut linux_clone_args = LinuxCloneArgs {
        flags: args.flags.bits().try_into()?,
        pidfd: 0,
        child_tid: 0,
        parent_tid: 0,
        exit_signal: u64::try_from(args.exit_signal)?,
        stack: 0,
        stack_size: 0,
        tls: 0,
        set_tid: 0,
        set_tid_size: 0,
        cgroup: 0,
    };

    let clone_result = check_err(unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &mut linux_clone_args as *mut _ as *mut libc::c_void,
            std::mem::size_of::<LinuxCloneArgs>(),
        )
    })
    .context("clone3")?;

    Ok(Pid::from_raw(clone_result.try_into()?))
}

pub(crate) struct Capabilities {
    pub(crate) effective: u64,
    pub(crate) permitted: u64,
    pub(crate) inheritable: u64,
    pub(crate) bounding: u64,
    pub(crate) ambient: u64,
}

pub(crate) fn capset(caps: Capabilities) -> Result<()> {
    #[repr(C)]
    struct CapUserHeader {
        version: u32,
        pid: i32,
    }

    #[repr(C)]
    #[derive(Debug)]
    struct CapUserData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    let mut header = CapUserHeader {
        version: 0x20080522u32,
        pid: 0,
    };
    let mut data = vec![
        CapUserData {
            effective: (caps.effective & 0xffffffff).try_into()?,
            permitted: (caps.permitted & 0xffffffff).try_into()?,
            inheritable: (caps.inheritable & 0xffffffff).try_into()?,
        },
        CapUserData {
            effective: ((caps.effective >> 32) & 0xffffffff).try_into()?,
            permitted: ((caps.permitted >> 32) & 0xffffffff).try_into()?,
            inheritable: ((caps.inheritable >> 32) & 0xffffffff).try_into()?,
        },
    ];

    const PR_CAPBSET_DROP: i32 = 24;
    const PR_CAP_AMBIENT: i32 = 47;
    const PR_CAP_AMBIENT_CLEAR_ALL: u64 = 4;

    let last_cap: u64 = read_to_string("/proc/sys/kernel/cap_last_cap")
        .context("read(/proc/sys/kernel/cap_last_cap)")?
        .trim()
        .parse()?;

    if caps.ambient == 0 {
        check_err(unsafe {
            libc::syscall(
                libc::SYS_prctl,
                PR_CAP_AMBIENT,
                PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            )
        })
        .context("prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)")?;
    }

    for i in 0..(last_cap + 1) {
        if (caps.bounding & (1 << i)) != 0 {
            continue;
        }
        check_err(unsafe { libc::syscall(libc::SYS_prctl, PR_CAPBSET_DROP, i, 0, 0, 0) })
            .with_context(|| format!("prctl(PR_CAPBSET_DROP, {}, 0, 0, 0)", i))?;
    }

    check_err(unsafe {
        libc::syscall(
            libc::SYS_capset,
            &mut header as *mut _ as *mut libc::c_void,
            data.as_mut_ptr(),
        )
    })
    .context("capset")?;

    Ok(())
}

pub(crate) fn set_all_securebits() -> Result<()> {
    const PR_SET_SECUREBITS: i32 = 28;

    const SECBIT_NOROOT: u64 = 1 << 0;
    const SECBIT_NOROOT_LOCKED: u64 = 1 << 1;
    const SECBIT_NO_SETUID_FIXUP: u64 = 2 << 0;
    const SECBIT_NO_SETUID_FIXUP_LOCKED: u64 = 3 << 1;
    const SECBIT_KEEP_CAPS: u64 = 4 << 0;
    const SECBIT_KEEP_CAPS_LOCKED: u64 = 5 << 1;
    const SECBIT_NO_CAP_AMBIENT_RAISE: u64 = 6 << 0;
    const SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED: u64 = 7 << 1;

    check_err(unsafe {
        libc::syscall(
            libc::SYS_prctl,
            PR_SET_SECUREBITS,
            SECBIT_NO_CAP_AMBIENT_RAISE
                | SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED
                | SECBIT_KEEP_CAPS
                | SECBIT_KEEP_CAPS_LOCKED
                | SECBIT_NO_SETUID_FIXUP
                | SECBIT_NO_SETUID_FIXUP_LOCKED
                | SECBIT_NOROOT
                | SECBIT_NOROOT_LOCKED,
        )
    })
    .context("prctl(PR_SET_SECUREBITS)")?;

    Ok(())
}

pub(crate) fn set_no_new_privs() -> Result<()> {
    const PR_SET_NO_NEW_PRIVS: i32 = 38;

    check_err(unsafe { libc::syscall(libc::SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) })
        .context("prctl(PR_SET_NO_NEW_PRIVS)")?;

    Ok(())
}

pub(crate) fn seccomp_set_mode_filter(filter: &[u8]) -> Result<()> {
    const SECCOMP_SET_MODE_FILTER: i32 = 1;

    const SECCOMP_FILTER_FLAG_TSYNC: u64 = 1 << 0;
    const SECCOMP_FILTER_FLAG_TSYNC_ESRCH: u64 = 1 << 4;

    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *const libc::c_void,
    }

    let fprog = SockFprog {
        len: (filter.len() / 8).try_into()?,
        filter: filter.as_ptr() as *const _,
    };

    check_err(unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_TSYNC
                | SECCOMP_FILTER_FLAG_TSYNC_ESRCH,
            &fprog as *const _ as *const libc::c_void,
        )
    }).context("seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC|SECCOMP_FILTER_FLAG_TSYNC_ESRCH)")?;

    Ok(())
}

pub(crate) fn seccomp_set_mode_filter_with_listener(filter: &[u8]) -> Result<File> {
    const SECCOMP_SET_MODE_FILTER: i32 = 1;

    const SECCOMP_FILTER_FLAG_TSYNC: u64 = 1 << 0;
    const SECCOMP_FILTER_FLAG_NEW_LISTENER: u64 = 1 << 3;
    const SECCOMP_FILTER_FLAG_TSYNC_ESRCH: u64 = 1 << 4;

    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *const libc::c_void,
    }

    let fprog = SockFprog {
        len: (filter.len() / 8).try_into()?,
        filter: filter.as_ptr() as *const _,
    };

    let fd: RawFd = check_err(unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_TSYNC
                | SECCOMP_FILTER_FLAG_NEW_LISTENER
                | SECCOMP_FILTER_FLAG_TSYNC_ESRCH,
            &fprog as *const _ as *const libc::c_void,
        )
    }).context("seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC|SECCOMP_FILTER_FLAG_NEW_LISTENER|SECCOMP_FILTER_FLAG_TSYNC_ESRCH)")?.try_into()?;

    Ok(unsafe { File::from_raw_fd(fd) })
}

pub(crate) fn seccomp_get_notification_size() -> Result<usize> {
    const SECCOMP_GET_NOTIF_SIZES: i32 = 3;

    #[repr(C)]
    struct SeccompNotifSizes {
        seccomp_notif: u16,
        seccomp_notif_resp: u16,
        seccomp_data: u16,
    }

    let mut sizes = SeccompNotifSizes {
        seccomp_notif: 0,
        seccomp_notif_resp: 0,
        seccomp_data: 0,
    };

    check_err(unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_GET_NOTIF_SIZES,
            0,
            &mut sizes as *mut _ as *mut libc::c_void,
        )
    })
    .context("seccomp(SECCOMP_GET_NOTIF_SIZES)")?;

    Ok(usize::from(sizes.seccomp_notif))
}

#[doc(hidden)]
#[repr(C)]
#[derive(Clone)]
pub struct SeccompData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

#[doc(hidden)]
#[repr(C)]
#[derive(Clone)]
pub struct SeccompNotif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}

const SECCOMP_IOC_MAGIC: u8 = b'!'; // Defined in linux/uapi/linux/seccomp.h

ioctl_readwrite!(
    #[doc(hidden)]
    seccomp_notif_recv,
    SECCOMP_IOC_MAGIC,
    0,
    SeccompNotif
);

pub(crate) fn seccomp_read_notification(fd: RawFd, buf: &mut [u8]) -> Result<SeccompNotif> {
    loop {
        match unsafe { seccomp_notif_recv(fd, buf as *mut _ as *mut SeccompNotif) } {
            Err(Errno::EINTR) => {}
            Err(err) => {
                log::error!("failed: {:#}", err);
                break;
            }
            Ok(_) => {
                break;
            }
        }
    }
    Ok(unsafe { &*(buf as *mut _ as *mut SeccompNotif) }.clone())
}

pub(crate) fn pidfd_open(pid: Pid, flags: i32) -> Result<File> {
    let fd = check_err(unsafe { libc::syscall(libc::SYS_pidfd_open, pid, flags) })?;

    Ok(unsafe { File::from_raw_fd(fd.try_into()?) })
}

pub(crate) fn close_range(first: RawFd, last: Option<RawFd>, flags: u32) -> Result<()> {
    check_err(unsafe { libc::syscall(libc::SYS_close_range, first, last.unwrap_or(-1), flags) })?;

    Ok(())
}

pub(crate) enum WaitidWhich {
    Pid(Pid),
}

mod pid_serde {
    use nix::unistd::Pid;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct Repr(i32);

    pub(crate) fn serialize<S>(pid: &Pid, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let r = Repr(pid.as_raw());
        r.serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Pid, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Repr::deserialize(deserializer) {
            Ok(repr) => Ok(Pid::from_raw(repr.0)),
            Err(err) => Err(err),
        }
    }
}

mod signal_serde {
    use nix::sys::signal::Signal;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct Repr(i32);

    pub(crate) fn serialize<S>(signal: &Signal, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let r = Repr(signal.clone() as i32);
        r.serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Signal, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Repr::deserialize(deserializer) {
            Ok(repr) => match repr.0.try_into() {
                Ok(val) => Ok(val),
                Err(err) => Err(D::Error::custom(format!(
                    "value out of range: {}: {:#}",
                    repr.0, err
                ))),
            },
            Err(err) => Err(err),
        }
    }
}

/// Possible return values from the [`wait(2)`](https://man7.org/linux/man-pages/man2/wait.2.html)
/// family of syscalls, plus any associated information.
///
/// This is a subset of [`nix::sys::wait::WaitStatus`] that is also serializable.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum WaitStatus {
    /// The process exited with the exit code.
    Exited(#[serde(with = "pid_serde")] Pid, i32),
    /// The process exited because it called a forbidden syscall.
    Syscalled(#[serde(with = "pid_serde")] Pid, i32),
    /// The process exited because it received a signal.
    Signaled(
        #[serde(with = "pid_serde")] Pid,
        #[serde(with = "signal_serde")] Signal,
    ),
}

/// Describes the result of a process after it has terminated.
///
/// This also contains information about the resource usage of the process: user time, system time,
/// wall time, and max RSS.
#[derive(Serialize, Deserialize, Debug)]
pub struct WaitidStatus {
    /// The exit status of the process.
    pub status: WaitStatus,
    /// The amount of CPU time spent running userspace code.
    pub user_time: Duration,
    /// The amount of CPU time spent running kernel code on behalf of the process.
    pub system_time: Duration,
    /// The amount of wall time during which the process was running.
    pub wall_time: Duration,
    /// The maximum Resident Set Size (memory) consumed by the process.
    pub max_rss: u64,
}

pub(crate) fn waitid(which: WaitidWhich, options: WaitPidFlag) -> Result<WaitidStatus> {
    #[repr(C)]
    #[derive(Debug)]
    struct KernelSiginfo {
        si_signo: i32,
        si_errno: i32,
        si_code: i32,
        __pad: i32,

        // The contents of `sifields._sigchld`
        si_pid: i32,
        si_uid: u32,
        si_status: i32,
        si_utime: libc::clock_t,
        si_stime: libc::clock_t,
    }

    #[repr(C)]
    #[derive(Debug)]
    struct Rusage {
        /// user time used
        ru_utime: libc::timeval,
        /// system time used
        ru_stime: libc::timeval,
        /// maximum resident set size
        ru_maxrss: i64,
        /// integral shared memory size
        ru_ixrss: i64,
        /// integral unshared data size
        ru_idrss: i64,
        /// integral unshared stack size
        ru_isrss: i64,
        /// page reclaims
        ru_minflt: i64,
        /// page faults
        ru_majflt: i64,
        /// swaps
        ru_nswap: i64,
        /// block input operations
        ru_inblock: i64,
        /// block output operations
        ru_oublock: i64,
        /// messages sent
        ru_msgsnd: i64,
        /// messages received
        ru_msgrcv: i64,
        /// signals received
        ru_nsignals: i64,
        /// voluntary context switches
        ru_nvcsw: i64,
        /// involuntary context switches
        ru_nivcsw: i64,
    }
    static_assertions::assert_eq_size!(Rusage, [u8; 144]);

    const SI_MAX_SIZE: usize = 128;
    let mut kernel_siginfo_buf = vec![0u8; SI_MAX_SIZE];
    let (idtype, id) = match which {
        WaitidWhich::Pid(pid) => (1, pid.as_raw()),
    };
    let mut rusage = Rusage {
        ru_utime: libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
        ru_stime: libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
        ru_maxrss: 0,
        ru_ixrss: 0,
        ru_idrss: 0,
        ru_isrss: 0,
        ru_minflt: 0,
        ru_majflt: 0,
        ru_nswap: 0,
        ru_inblock: 0,
        ru_oublock: 0,
        ru_msgsnd: 0,
        ru_msgrcv: 0,
        ru_nsignals: 0,
        ru_nvcsw: 0,
        ru_nivcsw: 0,
    };
    check_err(unsafe {
        libc::syscall(
            libc::SYS_waitid,
            idtype,
            id,
            kernel_siginfo_buf.as_mut_ptr(),
            options.bits(),
            &mut rusage as *mut _,
        )
    })
    .context("waitid")?;
    let kernel_siginfo = unsafe { &*(kernel_siginfo_buf.as_ptr() as *const KernelSiginfo) };
    log::info!("{:?}", &kernel_siginfo);
    let exit_pid = Pid::from_raw(kernel_siginfo.si_pid);
    const CLD_EXITED: i32 = 1;
    const CLD_KILLED: i32 = 2;
    const CLD_DUMPED: i32 = 3;
    Ok(WaitidStatus {
        status: match kernel_siginfo.si_code {
            CLD_EXITED => WaitStatus::Exited(exit_pid, kernel_siginfo.si_status),
            CLD_KILLED => WaitStatus::Signaled(exit_pid, kernel_siginfo.si_status.try_into()?),
            CLD_DUMPED => WaitStatus::Signaled(exit_pid, kernel_siginfo.si_status.try_into()?),
            _ => {
                bail!("unexpected si_code: {:?}", kernel_siginfo);
            }
        },
        system_time: Duration::from_secs(rusage.ru_stime.tv_sec.try_into()?)
            + Duration::from_micros(rusage.ru_stime.tv_usec.try_into()?),
        user_time: Duration::from_secs(rusage.ru_utime.tv_sec.try_into()?)
            + Duration::from_micros(rusage.ru_utime.tv_usec.try_into()?),
        wall_time: Duration::ZERO,
        max_rss: (rusage.ru_maxrss * 1024).try_into()?,
    })
}

pub(crate) trait RecvFile {
    /// A wrapper around [`passfd::FdPassingExt::recv_fd`] to return a [`File`] instead of a [`RawFd`].
    fn recv_file(&self) -> std::io::Result<File>;
}

impl RecvFile for UnixStream {
    fn recv_file(&self) -> std::io::Result<File> {
        let fd = self.recv_fd()?;
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

pub(crate) trait SendFile {
    fn send_file(&self, file: File) -> std::io::Result<()>;
}

impl SendFile for UnixStream {
    /// A wrapper around [`passfd::FdPassingExt::send_fd`] that takes a [`File`] instead of a [`RawFd`].
    fn send_file(&self, file: File) -> std::io::Result<()> {
        self.send_fd(file.as_raw_fd())?;
        Ok(())
    }
}
