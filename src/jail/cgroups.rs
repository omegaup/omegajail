use std::fmt::Debug;
use std::fs::{create_dir, remove_dir, write};
use std::io::ErrorKind;
use std::ops::Drop;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use rand::{thread_rng, Rng};

use nix::unistd::Pid;

pub(crate) struct CGroup {
    path: PathBuf,
    v2: bool,
}

impl CGroup {
    pub(crate) fn new<'a, P1, P2>(subsystem: P1, cgroup_path: P2) -> Result<CGroup>
    where
        P1: 'a + Debug + AsRef<Path>,
        P2: 'a + Debug + AsRef<Path>,
    {
        let root = PathBuf::from("/sys/fs/cgroup").join(&subsystem).join(
            if cgroup_path.as_ref().is_absolute() {
                cgroup_path
                    .as_ref()
                    .strip_prefix("/")
                    .with_context(|| anyhow!("relativize {:?}", &cgroup_path))?
            } else {
                cgroup_path.as_ref()
            },
        );
        let v2 = subsystem.as_ref() == Path::new("");
        if !root.exists() {
            create_dir(&root).with_context(|| anyhow!("create_dir({:?})", &root))?;
            if v2 {
                let subtree_control = root.join("cgroup.subtree_control");
                write(&subtree_control, b"+memory\n")
                    .with_context(|| anyhow!("write +memory to {:?}", &subtree_control))?;
            }
        }
        let mut rng = thread_rng();
        for _ in 0..16 {
            let dir = root.join(format!("omegajail_{:016x}", rng.gen::<u64>()));
            if let Err(err) = create_dir(&dir) {
                if err.kind() == ErrorKind::AlreadyExists {
                    continue;
                }
                bail!("create_dir({:?}): {:#}", &dir, err);
            }
            return Ok(CGroup { path: dir, v2: v2 });
        }

        bail!("could not create a cgroup in {:?} after 16 rounds", root);
    }

    pub(crate) fn add_pid(&self, pid: Pid) -> Result<()> {
        let procs_path = self.path.join("cgroup.procs");
        write(&procs_path, format!("{}", pid))
            .with_context(|| anyhow!("write {} to {:?}", pid, &procs_path))
    }

    pub(crate) fn set_memory_limit(&self, limit: u64) -> Result<()> {
        let memory_max_path = self.path.join(if self.v2 {
            "memory.max"
        } else {
            "memory.limit_in_bytes"
        });
        write(&memory_max_path, format!("{}", limit))
            .with_context(|| anyhow!("write {} to {:?}", limit, &memory_max_path))
    }

    pub(crate) fn is_cgroup_v2() -> bool {
        return Path::new("/sys/fs/cgroup/cgroup.controllers").exists();
    }
}

impl Drop for CGroup {
    fn drop(&mut self) {
        if let Err(err) = remove_dir(&self.path) {
            log::error!("remove_dir({:?}): {:#}", &self.path, err);
        }
    }
}
