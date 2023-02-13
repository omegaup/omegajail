use std::fs::{read_to_string, File};
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use nix::unistd::{getgid, getuid, Pid};

use crate::jail::cgroups::CGroup;
use crate::jail::options::JailOptions;
use crate::jail::{
    read_message, write_message, ParentSetupDoneEvent, SetupCgroupRequest, SetupCgroupResponse,
};
use crate::sys::RecvFile;

pub(crate) fn setup_child(
    parent_sock: &mut UnixStream,
    child: Pid,
    jail_options: &JailOptions,
) -> Result<Vec<CGroup>> {
    if !jail_options.disable_sandboxing {
        setup_ugid_mapping(child).context("setup child ugid mapping")?;
    }
    write_message(parent_sock, ParentSetupDoneEvent {}).context("write parent setup done event")?;

    read_message::<SetupCgroupRequest>(parent_sock).context("wait for setup cgroup request")?;
    let cgroups = if !jail_options.disable_sandboxing {
        let pidfd = parent_sock.recv_file().context("receive seccomp pidfd")?;
        match &jail_options.cgroup_path {
            Some(cgroup_path_root) => {
                let pid = get_pid_from_pidfd(&pidfd).context("get jailed pid")?;
                let cgroup_path = cgroup_path_root.join(&jail_options.seccomp_profile_name);
                let cgroup = CGroup::new(
                    if CGroup::is_cgroup_v2() { "" } else { "memory" },
                    &cgroup_path,
                )
                .with_context(|| anyhow!("create cgroup {:?}", &cgroup_path))?;
                cgroup
                    .add_pid(pid)
                    .with_context(|| anyhow!("add {} to cgroup", pid))?;
                if jail_options.use_cgroups_for_memory_limit {
                    if let Some(memory_limit) = jail_options.memory_limit {
                        cgroup.set_memory_limit(memory_limit).with_context(|| {
                            anyhow!("set pid {}'s memory limit to {}", pid, memory_limit)
                        })?;
                    }
                }
                vec![cgroup]
            }
            None => {
                vec![]
            }
        }
    } else {
        vec![]
    };

    write_message(parent_sock, SetupCgroupResponse {}).context("write setup cgroup response")?;

    Ok(cgroups)
}

fn get_pid_from_pidfd(pidfd: &File) -> Result<Pid> {
    let fdinfo = read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()))
        .context("contents of the pidfd")?;
    for line in fdinfo.lines() {
        let tokens: Vec<&str> = line.split(':').collect();
        if tokens.len() != 2 {
            continue;
        }
        if tokens[0] != "Pid" {
            continue;
        }
        return Ok(Pid::from_raw(tokens[1].trim().parse()?));
    }

    bail!("Pid label not found: {}", fdinfo);
}

fn setup_ugid_mapping(child: Pid) -> Result<()> {
    // Write the necessary files for the user namespace to work.
    let proc_dir = PathBuf::from(format!("/proc/{}", child));
    {
        let uid = getuid();
        let uid_map_path = proc_dir.join("uid_map");
        File::options()
            .write(true)
            .open(&uid_map_path)
            .with_context(|| format!("open {:?}", &uid_map_path))?
            .write_all(format!("{} {} 1", uid, uid).as_bytes())
            .with_context(|| format!("write {:?}", &uid_map_path))?;
    }
    {
        let setgroups_path = proc_dir.join("setgroups");
        File::options()
            .write(true)
            .open(&setgroups_path)
            .with_context(|| format!("open {:?}", &setgroups_path))?
            .write_all("deny".as_bytes())
            .with_context(|| format!("write {:?}", &setgroups_path))?;
    }
    {
        let gid = getgid();
        let gid_map_path = proc_dir.join("gid_map");
        File::options()
            .write(true)
            .open(&gid_map_path)
            .with_context(|| format!("open {:?}", &gid_map_path))?
            .write_all(format!("{} {} 1", gid, gid).as_bytes())
            .with_context(|| format!("write {:?}", &gid_map_path))?;
    }

    Ok(())
}
