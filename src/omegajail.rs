use std::fs::File;
use std::os::unix::io::AsRawFd;

use anyhow::{bail, Context, Result};
use clap::Parser;
use nix::unistd::dup2;

#[doc(hidden)]
fn main() -> Result<()> {
    let args = omegajail::Args::parse();

    // Redirect all logging to the stderr file.
    if let Some(stderr) = &args.stderr {
        // Rust does not allow the combination of create, truncate, and append. Create+truncate the
        // file first, and then open for appending.
        File::options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&stderr)
            .with_context(|| format!("create stderr {}", &stderr))?;
        let f = File::options()
            .append(true)
            .open(&stderr)
            .with_context(|| format!("open stderr for appending {}", &stderr))?;
        dup2(f.as_raw_fd(), libc::STDERR_FILENO)?;
    }
    env_logger::Builder::new()
        .filter(None, log::LevelFilter::Info)
        .init();

    let result = omegajail::Command::new(args).spawn()?.wait()?;
    match result.status {
        omegajail::sys::WaitStatus::Exited(_, 0) => {}
        _ => {
            bail!("jail did not exit cleanly: {:?}", result);
        }
    };

    Ok(())
}
