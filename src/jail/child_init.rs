use std::fs::{create_dir_all, metadata, File};
use std::ops::Add;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{sched_getaffinity, sched_setaffinity, unshare, CloneFlags, CpuSet};
use nix::sys::epoll::{
    epoll_create1, epoll_ctl, epoll_wait, EpollCreateFlags, EpollEvent, EpollFlags, EpollOp,
};
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::WaitPidFlag;
use nix::unistd::{
    chdir, chroot, close, dup2, fchdir, fork, getgid, getuid, pipe2, pivot_root, sethostname,
    setresgid, setresuid, ForkResult, Pid,
};

use crate::jail::options::{JailOptions, Stdio};
use crate::jail::{
    read_message, write_message, ParentSetupDoneEvent, SendSeccompFDEvent, SetupCgroupRequest,
    SetupCgroupResponse,
};
use crate::sys::{
    capset, close_range, pidfd_open, seccomp_get_notification_size, seccomp_read_notification,
    set_all_securebits, set_no_new_privs, waitid, Capabilities, RecvFile, SendFile, WaitStatus,
    WaitidStatus, WaitidWhich,
};

// Used to pass None to nix::mount::mount
const NONE: Option<&'static [u8]> = None;

pub(crate) fn run(mut parent_jail_sock: UnixStream, opts: JailOptions) -> Result<()> {
    set_cpu_affinity().context("set cpu affinity")?;

    read_message::<ParentSetupDoneEvent>(&mut parent_jail_sock)
        .context("wait for parent setup done")?;

    // Once we reach this point, the parent has helped us set the ugid map and have all
    // privileges.
    let uid = getuid();
    setresuid(uid, uid, uid).context("setresuid")?;
    let gid = getgid();
    setresgid(gid, gid, gid).context("setresgid")?;

    if !opts.disable_sandboxing {
        setup_net_namespace().context("setup net namespace")?;
        setup_mount_namespace(&opts).context("setup mount namespace")?;
        drop_privileges().context("drop privileges")?;
    } else {
        setup_unsandboxed_filesystem(&opts).context("setup filesystem")?;
    }
    set_no_new_privs().context("set_no_new_privs")?;

    let parent_jail_sock_fd = parent_jail_sock.as_raw_fd();
    let first_range_fd = unsafe {
        (
            RawFd::from_raw_fd(3),
            RawFd::from_raw_fd(parent_jail_sock_fd - 1),
        )
    };
    let second_range_fd = unsafe { RawFd::from_raw_fd(parent_jail_sock_fd + 1) };
    if !opts.disable_sandboxing {
        if first_range_fd.0 < first_range_fd.1 {
            close_range(first_range_fd.0, Some(first_range_fd.1), 0).with_context(|| {
                anyhow!("close_range({}, {})", first_range_fd.0, first_range_fd.1)
            })?;
        }
        close_range(second_range_fd, None, 0)
            .with_context(|| anyhow!("close_range({}, ~0U)", second_range_fd))?;
    }

    let (jail_sock, child_sock) = UnixStream::pair().context("create socket pair")?;
    let (read_pipe, write_pipe) = {
        let (rfd, wfd) = pipe2(OFlag::O_CLOEXEC).context("create pipe")?;
        unsafe { (File::from_raw_fd(rfd), File::from_raw_fd(wfd)) }
    };

    // Now the only thing left is to set up the seccomp-bpf filter and execve the child.
    match unsafe { fork() }.context("fork")? {
        ForkResult::Parent { child, .. } => {
            std::mem::drop(child_sock);
            std::mem::drop(read_pipe);
            let _ = close(libc::STDIN_FILENO);
            let _ = close(libc::STDOUT_FILENO);

            {
                write_message(&mut parent_jail_sock, SetupCgroupRequest {})
                    .context("write setup cgroup request")?;
                let child_pidfd =
                    pidfd_open(child, 0).with_context(|| anyhow!("pidfd_open({})", child))?;
                parent_jail_sock
                    .send_file(child_pidfd)
                    .context("send child pidfd")?;
                read_message::<SetupCgroupResponse>(&mut parent_jail_sock)
                    .context("read setup cgroup response")?;
            }
            let child_start = Instant::now();
            let deadline = child_start.add(opts.wall_time_limit);
            std::mem::drop(write_pipe);

            let status = wait_child(
                child,
                jail_sock,
                child_start,
                deadline,
                opts.vm_memory_size_in_bytes,
            );
            write_message(&mut parent_jail_sock, status).context("write status")?;
        }
        ForkResult::Child => {
            std::mem::drop(parent_jail_sock);
            std::mem::drop(jail_sock);
            std::mem::drop(write_pipe);

            if let Err(err) = crate::jail::child::run(child_sock, read_pipe, &opts) {
                log::error!("run child failed: {:#}", err);
                unsafe { libc::exit(1) }
            }
            unsafe { libc::exit(0) };
        }
    }

    Ok(())
}

fn set_cpu_affinity() -> Result<()> {
    // Set the processor affinity mask to a single core. If this process already
    // has an affinity mask set with more than one core set, limit it to the
    // first one in the set.
    // This is effectively a no-op on the runner machines since they are
    // single-core, but this helps avoid some amount of noise on multi-core
    // machines.
    let cpu_set = sched_getaffinity(Pid::this()).context("sched_getaffinity")?;
    let mut new_cpu_set = CpuSet::new();
    for i in 0..CpuSet::count() {
        if !cpu_set
            .is_set(i)
            .with_context(|| anyhow!("cpu_set.is_set({})", i))?
        {
            continue;
        }
        new_cpu_set
            .set(i)
            .with_context(|| anyhow!("cpu_set.set({})", i))?;
        break;
    }
    if cpu_set != new_cpu_set {
        sched_setaffinity(Pid::this(), &new_cpu_set).context("sched_setaffinity")?;
    }

    Ok(())
}

fn setup_net_namespace() -> Result<()> {
    unshare(CloneFlags::CLONE_NEWNET).context("unshare(CLONE_NEWNET)")?;
    sethostname("omegajail").context("sethostname(omegajail)")?;

    Ok(())
}

fn setup_mount_namespace(opts: &JailOptions) -> Result<()> {
    unshare(CloneFlags::CLONE_NEWNS).context("unshare(CLONE_NEWNS)")?;
    mount(NONE, "/", NONE, MsFlags::MS_REC | MsFlags::MS_PRIVATE, NONE)
        .context("mount / as private")?;
    for mount_args in &opts.mounts {
        if !mount_args.target.exists() {
            if !mount_args.flags.contains(MsFlags::MS_BIND) {
                create_dir_all(&mount_args.target)
                    .with_context(|| format!("create bind target {:?}", &mount_args.target))?;
            } else {
                let source_path = mount_args
                    .source
                    .as_ref()
                    .ok_or_else(|| anyhow!("source for mount {:?} not provided", &mount_args))?;
                if metadata(source_path)?.is_dir() {
                    create_dir_all(&mount_args.target)
                        .with_context(|| format!("create bind target {:?}", &mount_args.target))?;
                } else {
                    if let Some(target_parent) = mount_args.target.parent() {
                        create_dir_all(&target_parent)
                            .with_context(|| format!("create bind target {:?}", &target_parent))?;
                    }
                    File::create(&mount_args.target)
                        .with_context(|| format!("create bind target {:?}", &mount_args.target))?;
                }
            }
        }
        mount(
            mount_args.source.as_ref(),
            &mount_args.target,
            mount_args.fstype.as_deref(),
            mount_args.flags,
            mount_args.data.as_deref(),
        )
        .with_context(|| format!("mount({:?})", &mount_args))?;
    }

    // Now we can pivot_root.
    let oldroot = File::options()
        .read(true)
        .custom_flags(OFlag::O_DIRECTORY.bits())
        .open("/")
        .context("open old root")?;
    let newroot = File::options()
        .read(true)
        .custom_flags(OFlag::O_DIRECTORY.bits())
        .open(&opts.rootfs)
        .context("open new root")?;
    mount(
        Some(&opts.rootfs),
        &opts.rootfs,
        NONE,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        NONE,
    )
    .with_context(|| format!("remount rootfs {:?}", &opts.rootfs))?;
    chdir(&opts.rootfs).with_context(|| format!("chdir rootfs {:?}", &opts.rootfs))?;
    pivot_root(".", ".").context("pivot_root(\".\", \".\")")?;
    fchdir(oldroot.as_raw_fd()).context("fchdir old rootfs")?;
    mount(NONE, ".", NONE, MsFlags::MS_PRIVATE | MsFlags::MS_REC, NONE)
        .context("remount old rootfs as private")?;
    umount2(".", MntFlags::MNT_DETACH).context("unmount old rootfs")?;
    fchdir(newroot.as_raw_fd()).context("fchdir new rootfs")?;
    chroot("/").context("chroot(\"/\")")?;
    chdir("/").context("chdir(\"/\")")?;
    mount(
        NONE,
        "/",
        NONE,
        MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_RDONLY,
        NONE,
    )
    .context("remount / as read-only")?;
    mount(
        NONE,
        "/tmp",
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        Some("size=67108864,mode=1777"),
    )
    .context("mount /tmp")?;
    chdir("/home").context("chdir(\"/home\")")?;

    // Redirect stdio.
    match opts.stdin {
        Stdio::Mounted(_) | Stdio::DevNull(_) => {
            let f = File::open("/mnt/stdio/stdin").context("open /mnt/stdio/stdin")?;
            dup2(f.as_raw_fd(), libc::STDIN_FILENO).context("dup2 stdin")?;
        }
        Stdio::FileDescriptor(libc::STDIN_FILENO) => {}
        Stdio::FileDescriptor(fd) => {
            dup2(fd, libc::STDIN_FILENO).context("dup2 stdin")?;
            close(fd).context("close stdin")?;
        }
    }
    match opts.stdout {
        Stdio::Mounted(_) | Stdio::DevNull(_) => {
            let f = File::options()
                .write(true)
                .open("/mnt/stdio/stdout")
                .context("open /mnt/stdio/stdout")?;
            dup2(f.as_raw_fd(), libc::STDOUT_FILENO).context("dup2 stdout")?;
        }
        Stdio::FileDescriptor(libc::STDOUT_FILENO) => {}
        Stdio::FileDescriptor(fd) => {
            dup2(fd, libc::STDOUT_FILENO).context("dup2 stdout")?;
            close(fd).context("close stdout")?;
        }
    }
    match opts.stderr {
        Stdio::Mounted(_) | Stdio::DevNull(_) => {
            let f = File::options()
                .append(true)
                .open("/mnt/stdio/stderr")
                .context("open /mnt/stdio/stderr")?;
            dup2(f.as_raw_fd(), libc::STDERR_FILENO).context("dup2 stderr")?;
        }
        Stdio::FileDescriptor(libc::STDERR_FILENO) => {}
        Stdio::FileDescriptor(fd) => {
            dup2(fd, libc::STDERR_FILENO).context("dup2 stderr")?;
            close(fd).context("close stderr")?;
        }
    }
    umount2("/mnt/stdio", MntFlags::MNT_DETACH).context("unmount /mnt/stdio")?;

    Ok(())
}

fn setup_unsandboxed_filesystem(opts: &JailOptions) -> Result<()> {
    chdir(&opts.homedir).with_context(|| anyhow!("chdir({:?})", opts.homedir))?;

    // Redirect stdio.
    match &opts.stdin {
        Stdio::Mounted(path) => {
            let f = File::open(&path).with_context(|| anyhow!("open {:?}", &path))?;
            dup2(f.as_raw_fd(), libc::STDIN_FILENO).context("dup2 stdin")?;
        }
        Stdio::DevNull(_) => {
            let f = File::open("/dev/null").with_context(|| anyhow!("open(\"/dev/null\")"))?;
            dup2(f.as_raw_fd(), libc::STDIN_FILENO).context("dup2 stdin")?;
        }
        Stdio::FileDescriptor(libc::STDIN_FILENO) => {}
        Stdio::FileDescriptor(fd) => {
            dup2(*fd, libc::STDIN_FILENO).context("dup2 stdin")?;
            close(*fd).context("close stdin")?;
        }
    }
    match &opts.stdout {
        Stdio::Mounted(path) => {
            let f = File::options()
                .write(true)
                .open(&path)
                .with_context(|| anyhow!("open {:?}", &path))?;
            dup2(f.as_raw_fd(), libc::STDOUT_FILENO).context("dup2 stdout")?;
        }
        Stdio::DevNull(_) => {
            let f = File::options()
                .write(true)
                .open("/dev/null")
                .with_context(|| anyhow!("open(\"/dev/null\")"))?;
            dup2(f.as_raw_fd(), libc::STDIN_FILENO).context("dup2 stdout")?;
        }
        Stdio::FileDescriptor(libc::STDOUT_FILENO) => {}
        Stdio::FileDescriptor(fd) => {
            dup2(*fd, libc::STDOUT_FILENO).context("dup2 stdout")?;
            close(*fd).context("close stdout")?;
        }
    }
    match &opts.stderr {
        Stdio::Mounted(path) => {
            let f = File::options()
                .append(true)
                .open(&path)
                .with_context(|| anyhow!("open {:?}", &path))?;
            dup2(f.as_raw_fd(), libc::STDERR_FILENO).context("dup2 stderr")?;
        }
        Stdio::DevNull(_) => {
            let f = File::options()
                .append(true)
                .open("/dev/null")
                .with_context(|| anyhow!("open(\"/dev/null\")"))?;
            dup2(f.as_raw_fd(), libc::STDIN_FILENO).context("dup2 stderr")?;
        }
        Stdio::FileDescriptor(libc::STDERR_FILENO) => {}
        Stdio::FileDescriptor(fd) => {
            dup2(*fd, libc::STDERR_FILENO).context("dup2 stderr")?;
            close(*fd).context("close stderr")?;
        }
    }

    Ok(())
}

fn drop_privileges() -> Result<()> {
    set_all_securebits().context("set_all_securebits")?;
    capset(Capabilities {
        effective: 0,
        permitted: 0,
        inheritable: 0,
        ambient: 0,
        bounding: 0,
    })
    .context("capset")?;

    Ok(())
}

fn wait_child(
    child: Pid,
    mut jail_sock: UnixStream,
    child_start: Instant,
    deadline: Instant,
    vm_memory_size_in_bytes: u64,
) -> WaitidStatus {
    let seccomp_fd = match wait_receive_seccomp_fd(&mut jail_sock) {
        Err(err) => {
            log::error!("receive seccomp fd: {:#}", err);
            let _ = kill(child, Signal::SIGKILL);
            None
        }
        Ok(seccomp_fd) => Some(seccomp_fd),
    };
    let override_status = match wait_read_seccomp_notification(child, deadline, seccomp_fd) {
        Err(err) => {
            log::error!("read seccomp notification: {:#}", err);
            let _ = kill(child, Signal::SIGKILL);
            None
        }
        Ok(result) => result,
    };

    let mut status = match waitid(
        WaitidWhich::Pid(child),
        WaitPidFlag::WEXITED | WaitPidFlag::WSTOPPED,
    ) {
        Err(err) => {
            log::error!("waitid(Pid({}), WEXITED|WSTOPPED): {:#}", child, err);
            let _ = kill(child, Signal::SIGKILL);
            WaitidStatus {
                status: WaitStatus::Signaled(child, Signal::SIGKILL),
                user_time: Duration::ZERO,
                system_time: Duration::ZERO,
                wall_time: Instant::now().duration_since(child_start),
                max_rss: 0,
            }
        }
        Ok(status) => status,
    };
    status.wall_time = Instant::now().duration_since(child_start);
    status.max_rss = status.max_rss.saturating_sub(vm_memory_size_in_bytes);
    if let Some(s) = override_status {
        status.status = s;
    }

    status
}

fn wait_receive_seccomp_fd(jail_sock: &mut UnixStream) -> Result<File> {
    read_message::<SendSeccompFDEvent>(jail_sock).context("wait for seccomp fd message")?;
    Ok(jail_sock.recv_file().context("receive seccomp fd")?)
}

fn wait_read_seccomp_notification(
    child: Pid,
    deadline: Instant,
    seccomp_file: Option<File>,
) -> Result<Option<WaitStatus>> {
    let epoll_file = unsafe {
        File::from_raw_fd(epoll_create1(EpollCreateFlags::EPOLL_CLOEXEC).context("epoll_create1")?)
    };
    let child_pidfd = pidfd_open(child, 0).with_context(|| anyhow!("pidfd_open({})", child))?;

    let seccomp_fd = seccomp_file.as_ref().map_or(-1, |f| f.as_raw_fd());
    if seccomp_fd != -1 {
        epoll_ctl(
            epoll_file.as_raw_fd(),
            EpollOp::EpollCtlAdd,
            seccomp_fd,
            Some(&mut EpollEvent::new(
                EpollFlags::EPOLLIN,
                seccomp_fd.try_into()?,
            )),
        )
        .context("epoll_ctl(EPOLL_CTL_ADD, seccomp_fd")?;
    }
    epoll_ctl(
        epoll_file.as_raw_fd(),
        EpollOp::EpollCtlAdd,
        child_pidfd.as_raw_fd(),
        Some(&mut EpollEvent::new(
            EpollFlags::EPOLLIN,
            child_pidfd.as_raw_fd().try_into()?,
        )),
    )
    .context("epoll_ctl(EPOLL_CTL_ADD, child_pidfd")?;

    let mut notification_contents =
        vec![0u8; seccomp_get_notification_size().context("seccomp_get_notification_size")?];

    let mut events = vec![EpollEvent::empty(); 2];
    loop {
        let timeout = deadline.saturating_duration_since(Instant::now());
        if timeout == Duration::ZERO {
            kill(child, Signal::SIGKILL).context("kill child")?;
            return Ok(Some(WaitStatus::Signaled(child, Signal::SIGXCPU)));
        }
        let nfds = match epoll_wait(
            epoll_file.as_raw_fd(),
            &mut events,
            timeout.as_millis().try_into()?,
        ) {
            Err(Errno::EINTR) => {
                continue;
            }
            Err(err) => {
                bail!("epoll_wait: {:#}", err);
            }
            Ok(nfds) => nfds,
        };
        for i in 0..nfds {
            if events[i].data() == child_pidfd.as_raw_fd().try_into()? {
                return Ok(None);
            } else {
                let notification =
                    seccomp_read_notification(seccomp_fd, &mut notification_contents)
                        .context("seccomp_read_notification")?;
                kill(child, Signal::SIGKILL).context("kill child")?;
                return Ok(Some(WaitStatus::Syscalled(child, notification.data.nr)));
            }
        }
    }
}
