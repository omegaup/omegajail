use std::fs::File;
use std::io::{ErrorKind, Read};
use std::os::unix::net::UnixStream;

use anyhow::{anyhow, bail, Context, Result};
use nix::sys::resource::{setrlimit, Resource};
use nix::sys::signal::{sigprocmask, SigSet, SigmaskHow};
use nix::unistd::execve;

use crate::jail::options::JailOptions;
use crate::jail::{write_message, SendSeccompFDEvent};
use crate::sys::{seccomp_set_mode_filter_with_listener, SendFile};

pub(crate) fn run(
    mut child_sock: UnixStream,
    mut read_pipe: File,
    opts: &JailOptions,
) -> Result<()> {
    setup_process_limits(&opts).context("setup net namespace")?;
    setup_signal_handlers().context("setup signal handlers")?;

    setup_seccomp_bpf(&mut child_sock, &opts).context("setup_seccomp_bpf")?;
    std::mem::drop(child_sock);

    // Wait for the read pipe to finish
    loop {
        let mut buf = vec![0u8];
        match read_pipe.read(&mut buf) {
            Err(err) => {
                if err.kind() == ErrorKind::Interrupted {
                    continue;
                }
                bail!("epoll_wait: {:#}", err);
            }
            Ok(_) => {
                break;
            }
        };
    }
    std::mem::drop(read_pipe);

    execve(opts.args[0].as_ref(), opts.args.as_ref(), opts.env.as_ref())
        .with_context(|| format!("execve({:?}, {:?})", &opts.args, &opts.env))?;
    Ok(())
}

fn setup_process_limits(opts: &JailOptions) -> Result<()> {
    setrlimit(Resource::RLIMIT_STACK, None, None)
        .context("setrlimit(RLIMIT_STACK, RLIM_INFINITY, RLIM_INFINITY)")?;
    setrlimit(Resource::RLIMIT_CORE, Some(0), Some(0)).context("setrlimit(RLIMIT_CORE, 0, 0)")?;
    if let Some(time_limit) = opts.time_limit {
        let soft_limit = time_limit.as_secs()
            + match time_limit.subsec_millis() {
                0 => 0,
                _ => 1,
            };
        setrlimit(Resource::RLIMIT_CPU, Some(soft_limit), Some(soft_limit + 1)).with_context(
            || anyhow!("setrlimit(RLIMIT_CPU, {}, {})", soft_limit, soft_limit + 1),
        )?;
    }
    if let Some(output_limit) = opts.output_limit {
        setrlimit(Resource::RLIMIT_FSIZE, opts.output_limit, opts.output_limit).with_context(
            || {
                anyhow!(
                    "setrlimit(RLIMIT_FSIZE, {}, {})",
                    output_limit,
                    output_limit
                )
            },
        )?;
    }
    if !opts.use_cgroups_for_memory_limit {
        if let Some(memory_limit) = opts.memory_limit {
            setrlimit(Resource::RLIMIT_AS, opts.memory_limit, opts.memory_limit).with_context(
                || anyhow!("setrlimit(RLIMIT_AS, {}, {})", memory_limit, memory_limit),
            )?;
        }
    }
    Ok(())
}

fn setup_signal_handlers() -> Result<()> {
    sigprocmask(SigmaskHow::SIG_SETMASK, Some(&SigSet::empty()), None)
        .context("sigprocmask(SIG_SETMASK, [], nullptr)")?;
    sigprocmask(SigmaskHow::SIG_UNBLOCK, Some(&SigSet::all()), None)
        .context("sigprocmask(SIG_UNBLOCK, ~[], nullptr)")?;
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigemptyset(&mut mask) };
    let action = libc::sigaction {
        sa_sigaction: libc::SIG_DFL,
        sa_mask: mask,
        sa_flags: 0,
        sa_restorer: None,
    };
    let mut new_action = unsafe { std::mem::zeroed() };
    for signum in 1..33 {
        unsafe {
            libc::sigaction(signum, &action, &mut new_action);
        }
    }

    Ok(())
}

fn setup_seccomp_bpf(child_sock: &mut UnixStream, opts: &JailOptions) -> Result<()> {
    let fd = seccomp_set_mode_filter_with_listener(&opts.seccomp_bpf_filter_contents)
        .context("seccomp_set_mode_filter_with_listener")?;
    let write_message_result = write_message(child_sock, SendSeccompFDEvent {});
    let send_result = child_sock.send_file(fd);
    write_message_result.context("write parent setup done event")?;
    send_result.context("send seccomp fd")?;

    Ok(())
}
