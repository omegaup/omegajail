//! A helper binary to test the various edge cases of the sandbox.
use std::fs::read_dir;
use std::io::{stderr, stdin, stdout, Read, Write};
use std::process::abort;
use std::thread::sleep;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::{ArgEnum, Parser};
use nix::mount::{mount, MsFlags};

// Used to pass None to nix::mount::mount
const NONE: Option<&'static [u8]> = None;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ArgEnum)]
enum Widget {
    /// Basic stdio test.
    Stdio,
    /// Ensure that only file descriptors 1-3 are accessible.
    FileDescriptors,
    /// Terminate the process abnormally.
    Abort,
    /// Try to use a lot of memory.
    OOM,
    /// Use a forbidden syscall (`mount(2)`).
    Syscall,
    /// Try to write a lot to stdout.
    Sigxfsz,
    /// Do useless computation to exceed CPU quota.
    Sigxcpu,
    /// Take a break, sleep a bit.
    Sleep,
}

#[derive(Parser)]
struct Args {
    /// Run a specific widget that will be executed inside the sandbox.
    #[clap(long, arg_enum)]
    widget: Widget,
}

fn main() -> Result<()> {
    let args = Args::parse();

    match args.widget {
        Widget::Stdio => {
            let mut stdin_buf = String::new();
            stdin().read_to_string(&mut stdin_buf)?;
            assert_eq!("stdin\n", &stdin_buf);
            stdout().write_all(b"stdout\n")?;
            stderr().write_all(b"stderr\n")?;
        }
        Widget::FileDescriptors => {
            let mut fds = read_dir("/proc/self/fd")?
                .map(|res| res.map(|e| e.path()))
                .collect::<Result<Vec<_>, std::io::Error>>()?;
            fds.sort();
            for fd in fds {
                println!("{}", fd.as_path().display());
            }
        }
        Widget::Abort => {
            abort();
        }
        Widget::OOM => {
            let mut buf = Vec::<u8>::new();
            for i in 0..128 {
                buf.try_reserve(4 * 1024 * 1024)
                    .with_context(|| anyhow!("allocation failed at round {}", i))?;
                for i in 0..4 * 1024 * 1024 {
                    buf.push((i & 0xff) as u8);
                }
            }
            let total = buf.iter().fold(0u64, |acc, x| acc + (*x as u64));
            assert_eq!(total, 68451041280u64);
        }
        Widget::Syscall => {
            mount(
                NONE,
                "/var/empty",
                Some("tmpfs"),
                MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
                Some("size=4096,mode=555"),
            )
            .context("mount a new tmpfs in /var/empty")?;
        }
        Widget::Sigxfsz => {
            let buf = vec![97u8; 40960];
            loop {
                stdout().write_all(&buf)?;
            }
        }
        Widget::Sigxcpu => {
            let mut i: u64 = 0;
            let mut j: u64 = 0;
            loop {
                if let Some(x) = j.checked_add(i + 1) {
                    i += 1;
                    j = x;
                } else {
                    break;
                }
            }
            // Not expected to be reached before the process is killed.
            println!("{} {}", i, j);
        }
        Widget::Sleep => {
            sleep(Duration::from_secs(60));
            // Not expected to be reached before the process is killed.
            println!("yawn");
        }
    }

    Ok(())
}
