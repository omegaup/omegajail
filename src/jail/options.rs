use std::ffi::CString;
use std::fs::{canonicalize, File};
use std::io::Read;
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use itertools::Itertools;
use nix::mount::MsFlags;

use crate::args;

const DEFAULT_EXTRA_MEMORY_SIZE_IN_BYTES: u64 = 16 * 1024 * 1024;
const RUBY_EXTRA_MEMORY_SIZE_IN_BYTES: u64 = 56 * 1024 * 1024;
const GO_EXTRA_MEMORY_SIZE_IN_BYTES: u64 = 512 * 1024 * 1024;
const JULIA_EXTRA_MEMORY_SIZE_IN_BYTES: u64 = 512 * 1024 * 1024;

// These are obtained by running an "empty" and measuring
// its memory consumption, as reported by omegajail.
const JAVA_VM_MEMORY_SIZE_IN_BYTES: u64 = 47 * 1024 * 1024;
const CLR_VM_MEMORY_SIZE_IN_BYTES: u64 = 20 * 1024 * 1024;
const RUBY_VM_MEMORY_SIZE_IN_BYTES: u64 = 12 * 1024 * 1024;

// This is the result of executing the following Java code:
//
// public class Main {
//   public static void main(String[] args) {
//     System.out.println(
//         16 * 1024 * 1024 +
//         Runtime.getRuntime().totalMemory() -
//         Runtime.getRuntime().freeMemory()
//     );
//   }
// }
const JAVA_MIN_HEAP_SIZE_IN_BYTES: u64 = 18 * 1024 * 1024;

pub(crate) enum Stdio {
    Mounted(PathBuf),
    DevNull(PathBuf),
    FileDescriptor(RawFd),
}

#[derive(Debug, Clone)]
pub(crate) struct MountArgs {
    pub source: Option<PathBuf>,
    pub target: PathBuf,
    pub fstype: Option<String>,
    pub flags: MsFlags,
    pub data: Option<String>,
}

pub(crate) struct JailOptions {
    pub disable_sandboxing: bool,
    pub homedir: PathBuf,
    pub rootfs: PathBuf,
    pub cgroup_path: Option<PathBuf>,
    pub mounts: Vec<MountArgs>,
    pub args: Vec<CString>,
    pub env: Vec<CString>,
    pub seccomp_bpf_filter_notify_contents: Vec<u8>,
    pub seccomp_bpf_filter_sigsys_contents: Vec<u8>,
    pub seccomp_profile_name: String,
    pub meta: Option<PathBuf>,

    pub stdin: Stdio,
    pub stdout: Stdio,
    pub stderr: Stdio,

    pub time_limit: Option<Duration>,
    pub wall_time_limit: Duration,
    pub output_limit: Option<u64>,
    pub memory_limit: Option<u64>,
    pub use_cgroups_for_memory_limit: bool,
    pub vm_memory_size_in_bytes: u64,
    pub allow_sigsys_fallback: bool,
}

impl JailOptions {
    pub(crate) fn new(args: args::Args) -> Result<JailOptions> {
        let root = PathBuf::from(
            canonicalize(&args.root).with_context(|| format!("canonicalize({})", &args.root))?,
        );
        let mut mounts = Vec::<MountArgs>::new();
        let rootfs = if args.compile.is_some() {
            root.join("root-compilers")
        } else {
            root.join("root")
        };
        mounts.push(MountArgs {
            source: Some(PathBuf::from(
                canonicalize(&args.homedir)
                    .with_context(|| format!("canonicalize({})", &args.homedir))?,
            )),
            target: rootfs.join("home"),
            fstype: None,
            flags: if args.homedir_writable {
                MsFlags::MS_BIND
            } else {
                MsFlags::MS_BIND | MsFlags::MS_RDONLY
            },
            data: None,
        });
        mounts.push(MountArgs {
            source: None,
            target: rootfs.join("proc"),
            fstype: Some(String::from("proc")),
            flags: MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
            data: None,
        });
        mounts.push(MountArgs {
            source: None,
            target: rootfs.join("mnt/stdio"),
            fstype: Some(String::from("tmpfs")),
            flags: MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
            data: Some(String::from("size=4096,mode=555")),
        });
        // Create the stdout / stderr files if needed.
        let stdin = if let Some(stdin) = &args.stdin {
            File::open(stdin).with_context(|| format!("open stdin {}", &stdin))?;
            let source = PathBuf::from(
                canonicalize(&stdin).with_context(|| format!("canonicalize({})", &stdin))?,
            );
            mounts.push(MountArgs {
                source: Some(source.clone()),
                target: rootfs.join("mnt/stdio/stdin"),
                fstype: None,
                flags: MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                data: None,
            });

            Stdio::Mounted(source)
        } else if unsafe { libc::isatty(libc::STDIN_FILENO) == 0 } {
            let source = rootfs.join("dev/null");
            mounts.push(MountArgs {
                source: Some(source.clone()),
                target: rootfs.join("mnt/stdio/stdin"),
                fstype: None,
                flags: MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                data: None,
            });

            Stdio::DevNull(source)
        } else {
            Stdio::FileDescriptor(libc::STDIN_FILENO)
        };
        let stdout = if let Some(stdout) = &args.stdout {
            File::create(stdout).with_context(|| format!("create stdout {}", &stdout))?;
            let source = PathBuf::from(
                canonicalize(&stdout).with_context(|| format!("canonicalize({})", &stdout))?,
            );
            mounts.push(MountArgs {
                source: Some(source.clone()),
                target: rootfs.join("mnt/stdio/stdout"),
                fstype: None,
                flags: MsFlags::MS_BIND,
                data: None,
            });

            Stdio::Mounted(source)
        } else if unsafe { libc::isatty(libc::STDOUT_FILENO) == 0 } {
            let source = rootfs.join("dev/null");
            mounts.push(MountArgs {
                source: Some(source.clone()),
                target: rootfs.join("mnt/stdio/stdout"),
                fstype: None,
                flags: MsFlags::MS_BIND,
                data: None,
            });

            Stdio::DevNull(source)
        } else {
            Stdio::FileDescriptor(libc::STDOUT_FILENO)
        };
        let stderr = if let Some(stderr) = &args.stderr {
            File::options()
                .append(true)
                .create(true)
                .open(stderr)
                .with_context(|| format!("create stderr {}", &stderr))?;
            let source = PathBuf::from(
                canonicalize(&stderr).with_context(|| format!("canonicalize({})", &stderr))?,
            );
            mounts.push(MountArgs {
                source: Some(source.clone()),
                target: rootfs.join("mnt/stdio/stderr"),
                fstype: None,
                flags: MsFlags::MS_BIND,
                data: None,
            });

            Stdio::Mounted(source)
        } else if unsafe { libc::isatty(libc::STDERR_FILENO) == 0 } {
            let source = rootfs.join("dev/null");
            mounts.push(MountArgs {
                source: Some(source.clone()),
                target: rootfs.join("mnt/stdio/stderr"),
                fstype: None,
                flags: MsFlags::MS_BIND,
                data: None,
            });

            Stdio::DevNull(source)
        } else {
            Stdio::FileDescriptor(libc::STDERR_FILENO)
        };

        let mut execve_args = Vec::<String>::new();
        let mut env: Vec<&str> = vec!["HOME=/home", "LANG=en_US.UTF-8", "PATH=/usr/bin"];
        let mut seccomp_profile_name = String::new();
        let mut extra_memory_size_in_bytes = DEFAULT_EXTRA_MEMORY_SIZE_IN_BYTES;
        let mut vm_memory_size_in_bytes = 0u64;
        let mut use_cgroups_for_memory_limit: bool = false;

        if let Some(lang) = args.compile {
            let compile_sources = &args
                .compile_source
                .ok_or(anyhow!("--compile-source missing"))?;
            match lang {
                args::Language::C | args::Language::C11GCC => {
                    seccomp_profile_name = String::from("gcc");
                    execve_args.extend([
                        String::from("/usr/bin/gcc-10"),
                        String::from("-o"),
                        String::from(args.compile_target),
                        String::from("-std=c11"),
                        String::from("-O2"),
                    ]);
                    execve_args.extend(compile_sources.iter().map(|s| s.clone()));
                    execve_args.push(String::from("-lm"));
                }
                args::Language::C11Clang => {
                    seccomp_profile_name = String::from("clang");
                    execve_args.extend([
                        String::from("/usr/bin/clang-10"),
                        String::from("-o"),
                        String::from(args.compile_target),
                        String::from("-std=c11"),
                        String::from("-O3"),
                        String::from("-march=native"),
                    ]);
                    execve_args.extend(compile_sources.iter().map(|s| s.clone()));
                    execve_args.push(String::from("-lm"));
                }
                args::Language::Cpp03GCC => {
                    seccomp_profile_name = String::from("gcc");
                    execve_args.extend([
                        String::from("/usr/bin/g++-10"),
                        String::from("-o"),
                        String::from(args.compile_target),
                        String::from("-std=c++03"),
                        String::from("-O2"),
                    ]);
                    execve_args.extend(compile_sources.iter().map(|s| s.clone()));
                    execve_args.push(String::from("-lm"));
                }
                args::Language::Cpp03Clang => {
                    seccomp_profile_name = String::from("clang");
                    execve_args.extend([
                        String::from("/usr/bin/clang++-10"),
                        String::from("-o"),
                        String::from(args.compile_target),
                        String::from("-std=c++03"),
                        String::from("-O2"),
                    ]);
                    execve_args.extend(compile_sources.iter().map(|s| s.clone()));
                    execve_args.push(String::from("-lm"));
                }
                args::Language::Cpp | args::Language::Cpp11 | args::Language::Cpp11GCC => {
                    seccomp_profile_name = String::from("gcc");
                    execve_args.extend([
                        String::from("/usr/bin/g++-10"),
                        String::from("-o"),
                        String::from(args.compile_target),
                        String::from("-std=c++11"),
                        String::from("-O2"),
                    ]);
                    execve_args.extend(compile_sources.iter().map(|s| s.clone()));
                    execve_args.push(String::from("-lm"));
                }
                args::Language::Cpp11Clang => {
                    seccomp_profile_name = String::from("clang");
                    execve_args.extend([
                        String::from("/usr/bin/clang++-10"),
                        String::from("-o"),
                        String::from(args.compile_target),
                        String::from("-std=c++11"),
                        String::from("-O2"),
                    ]);
                    execve_args.extend(compile_sources.iter().map(|s| s.clone()));
                    execve_args.push(String::from("-lm"));
                }
                args::Language::Cpp17GCC => {
                    seccomp_profile_name = String::from("gcc");
                    execve_args.extend([
                        String::from("/usr/bin/g++-10"),
                        String::from("-o"),
                        String::from(args.compile_target),
                        String::from("-std=c++17"),
                        String::from("-O2"),
                    ]);
                    execve_args.extend(compile_sources.iter().map(|s| s.clone()));
                    execve_args.push(String::from("-lm"));
                }
                args::Language::Cpp17Clang => {
                    seccomp_profile_name = String::from("clang");
                    execve_args.extend([
                        String::from("/usr/bin/clang++-10"),
                        String::from("-o"),
                        String::from(args.compile_target),
                        String::from("-std=c++17"),
                        String::from("-O2"),
                    ]);
                    execve_args.extend(compile_sources.iter().map(|s| s.clone()));
                    execve_args.push(String::from("-lm"));
                }
                args::Language::Cpp20GCC => {
                    seccomp_profile_name = String::from("gcc");
                    execve_args.extend([
                        String::from("/usr/bin/g++-10"),
                        String::from("-o"),
                        String::from(args.compile_target),
                        String::from("-std=c++20"),
                        String::from("-O2"),
                    ]);
                    execve_args.extend(compile_sources.iter().map(|s| s.clone()));
                    execve_args.push(String::from("-lm"));
                }
                args::Language::Cpp20Clang => {
                    seccomp_profile_name = String::from("clang");
                    execve_args.extend([
                        String::from("/usr/bin/clang++-10"),
                        String::from("-o"),
                        String::from(args.compile_target),
                        String::from("-std=c++20"),
                        String::from("-O2"),
                    ]);
                    execve_args.extend(compile_sources.iter().map(|s| s.clone()));
                    execve_args.push(String::from("-lm"));
                }
                args::Language::Pascal => {
                    seccomp_profile_name = String::from("fpc");
                    execve_args.extend([
                        String::from("/usr/bin/fpc"),
                        String::from("-Tlinux"),
                        String::from("-O2"),
                        String::from("-Mobjfpc"),
                        String::from("-Sc"),
                        String::from("-Sh"),
                        format!("-o{}", args.compile_target),
                    ]);
                    execve_args.extend(compile_sources.iter().map(|s| s.clone()));
                }
                args::Language::Lua => {
                    seccomp_profile_name = String::from("lua");
                    execve_args.extend([
                        String::from("/usr/bin/luac5.3"),
                        String::from("-o"),
                        String::from(args.compile_target),
                    ]);
                    execve_args.extend(compile_sources.iter().map(|s| s.clone()));
                }
                args::Language::Haskell => {
                    seccomp_profile_name = String::from("ghc");
                    mounts.push(MountArgs {
                        source: Some(root.join("root-hs")),
                        target: rootfs.join("usr/lib/ghc"),
                        fstype: None,
                        flags: MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                        data: None,
                    });
                    execve_args.extend([
                        String::from("/usr/lib/ghc/bin/ghc"),
                        String::from("-B/usr/lib/ghc"),
                        String::from("-O2"),
                        String::from("-o"),
                        String::from(args.compile_target),
                    ]);
                    execve_args.extend(compile_sources.iter().map(|s| s.clone()));
                }
                args::Language::Java | args::Language::Kotlin => {
                    seccomp_profile_name = String::from("javac");
                    mounts.push(MountArgs {
                        source: Some(root.join("root-java")),
                        target: rootfs.join("usr/lib/jvm"),
                        fstype: None,
                        flags: MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                        data: None,
                    });
                    mounts.push(MountArgs {
                        source: Some(root.join("bin")),
                        target: rootfs.join("var/lib/omegajail/bin"),
                        fstype: None,
                        flags: MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                        data: None,
                    });
                    execve_args.extend([
                        String::from("/var/lib/omegajail/bin/java-compile"),
                        String::from(match lang {
                            args::Language::Java => "--language=java",
                            args::Language::Kotlin => "--language=kotlin",
                            _ => panic!("unreachable"),
                        }),
                        args.compile_target.clone(),
                    ]);
                    execve_args.extend(compile_sources.iter().map(|s| s.clone()));
                }
                args::Language::Python2 => {
                    seccomp_profile_name = String::from("pyc");
                    mounts.push(MountArgs {
                        source: Some(root.join("root-python2")),
                        target: rootfs.join("usr/lib/python2.7"),
                        fstype: None,
                        flags: MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                        data: None,
                    });
                    execve_args.extend([
                        String::from("/usr/bin/python2.7"),
                        String::from("-m"),
                        String::from("py_compile"),
                    ]);
                    execve_args.extend(compile_sources.iter().map(|s| s.clone()));
                }
                args::Language::Python | args::Language::Python3 => {
                    seccomp_profile_name = String::from("pyc");
                    mounts.push(MountArgs {
                        source: Some(root.join("root-python3")),
                        target: rootfs.join("opt/python3"),
                        fstype: None,
                        flags: MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                        data: None,
                    });
                    execve_args.extend([
                        String::from("/usr/bin/python3.9"),
                        String::from("-m"),
                        String::from("py_compile"),
                    ]);
                    execve_args.extend(compile_sources.iter().map(|s| s.clone()));
                }
                args::Language::Ruby => {
                    seccomp_profile_name = String::from("ruby");
                    mounts.push(MountArgs {
                        source: Some(root.join("root-ruby")),
                        target: rootfs.join("usr/lib/ruby"),
                        fstype: None,
                        flags: MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                        data: None,
                    });
                    execve_args.extend([String::from("/usr/bin/ruby"), String::from("-wc")]);
                    execve_args.extend(compile_sources.iter().map(|s| s.clone()));
                }
                args::Language::Rust => {
                    seccomp_profile_name = String::from("rustc");
                    mounts.push(MountArgs {
                        source: Some(root.join("root-rust")),
                        target: rootfs.join("opt/rust"),
                        fstype: None,
                        flags: MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                        data: None,
                    });
                    execve_args.extend([
                        String::from("/opt/rust/cargo/bin/rustc"),
                        String::from("-O"),
                        String::from("-o"),
                        args.compile_target.clone(),
                    ]);
                    execve_args.extend(compile_sources.iter().map(|s| s.clone()));
                }
                args::Language::Go => {
                    seccomp_profile_name = String::from("go-build");
                    mounts.push(MountArgs {
                        source: Some(root.join("root-go")),
                        target: rootfs.join("opt/go"),
                        fstype: None,
                        flags: MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                        data: None,
                    });
                    execve_args.extend([
                        String::from("/opt/go/bin/go"),
                        String::from("build"),
                        String::from("-o"),
                        args.compile_target.clone(),
                    ]);
                    execve_args.extend(compile_sources.iter().map(|s| s.clone()));
                }
                args::Language::JavaScript => {
                    seccomp_profile_name = String::from("js");
                    mounts.push(MountArgs {
                        source: Some(root.join("root-js")),
                        target: rootfs.join("opt/nodejs"),
                        fstype: None,
                        flags: MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                        data: None,
                    });
                    execve_args.extend([
                        String::from("/opt/nodejs/bin/node"),
                        String::from("--check"),
                    ]);
                    execve_args.extend(compile_sources.iter().map(|s| s.clone()));
                }
                args::Language::KarelJava | args::Language::KarelPascal => {
                    seccomp_profile_name = String::from("js");
                    mounts.push(MountArgs {
                        source: Some(root.join("root-js")),
                        target: rootfs.join("opt/nodejs"),
                        fstype: None,
                        flags: MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                        data: None,
                    });
                    execve_args.extend([
                        String::from("/opt/nodejs/bin/node"),
                        String::from("/opt/nodejs/karel.js"),
                        String::from("compile"),
                        String::from(match lang {
                            args::Language::KarelJava => "java",
                            args::Language::KarelPascal => "pascal",
                            _ => panic!("unreachable"),
                        }),
                        String::from("-o"),
                        format!("{}.kx", &args.compile_target),
                    ]);
                    execve_args.extend(compile_sources.iter().map(|s| s.clone()));
                }
                args::Language::CSharp => {
                    seccomp_profile_name = String::from("csc");
                    mounts.push(MountArgs {
                        source: Some(root.join("root-dotnet")),
                        target: rootfs.join("usr/share/dotnet"),
                        fstype: None,
                        flags: MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                        data: None,
                    });
                    execve_args.extend([
                        String::from("/usr/share/dotnet/dotnet"),
                        String::from("/usr/share/dotnet/sdk/6.0.101/Roslyn/bincore/csc.dll"),
                        String::from("-noconfig"),
                        String::from("@/usr/share/dotnet/Release.rsp"),
                        format!(
                            "-out:{}.dll",
                            PathBuf::from(
                                compile_sources
                                    .first()
                                    .ok_or(anyhow!("empty --compile-source"))?
                            )
                            .parent()
                            .context("invalid --compile-source")?
                            .join(args.compile_target.clone())
                            .to_str()
                            .ok_or(anyhow!("could not convert path to string"))?,
                        ),
                        String::from("-target:exe"),
                    ]);
                    execve_args.extend(compile_sources.iter().map(|s| s.clone()));
                }
            }
        } else if let Some(lang) = args.run {
            match lang {
                args::Language::C
                | args::Language::Cpp
                | args::Language::C11GCC
                | args::Language::C11Clang
                | args::Language::Cpp03GCC
                | args::Language::Cpp03Clang
                | args::Language::Cpp11
                | args::Language::Cpp11GCC
                | args::Language::Cpp11Clang
                | args::Language::Cpp17GCC
                | args::Language::Cpp17Clang
                | args::Language::Cpp20GCC
                | args::Language::Cpp20Clang => {
                    seccomp_profile_name = String::from("cpp");
                    execve_args.extend([format!("./{}", args.run_target)]);
                }
                args::Language::Pascal => {
                    seccomp_profile_name = String::from("pas");
                    execve_args.extend([format!("./{}", args.run_target)]);
                }
                args::Language::Lua => {
                    seccomp_profile_name = String::from("lua");
                    execve_args.extend([
                        String::from("/usr/bin/lua5.3"),
                        format!("./{}", args.run_target),
                    ]);
                }
                args::Language::Haskell => {
                    seccomp_profile_name = String::from("hs");
                    mounts.push(MountArgs {
                        source: Some(root.join("root-hs")),
                        target: rootfs.join("usr/lib/ghc"),
                        fstype: None,
                        flags: MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                        data: None,
                    });
                    execve_args.extend([format!("./{}", args.run_target)]);
                }
                args::Language::Java | args::Language::Kotlin => {
                    vm_memory_size_in_bytes = JAVA_VM_MEMORY_SIZE_IN_BYTES;
                    extra_memory_size_in_bytes = u64::MAX;
                    seccomp_profile_name = String::from("java");
                    mounts.push(MountArgs {
                        source: Some(root.join("root-java")),
                        target: rootfs.join("usr/lib/jvm"),
                        fstype: None,
                        flags: MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                        data: None,
                    });
                    execve_args.extend([
                        String::from("/usr/bin/java"),
                        String::from("-Xshare:on"),
                        String::from("-XX:+UnlockExperimentalVMOptions"),
                        String::from("-XX:+UseSerialGC"),
                    ]);
                    if let Some(memory_limit) = &args.memory_limit {
                        execve_args.extend([format!(
                            "-Xmx{}",
                            memory_limit + JAVA_MIN_HEAP_SIZE_IN_BYTES
                        )]);
                    }
                    if lang == args::Language::Kotlin {
                        execve_args.extend([
                            format!("-XX:AOTLibrary=/usr/lib/jvm/java.base.so,/usr/lib/jvm/kotlin-stdlib.jar.so,./{}.so",
                       args.run_target),
                            String::from("-cp"),
                            String::from("/usr/lib/jvm/kotlinc/lib/kotlin-stdlib.jar:."),
                            format!("{}Kt", &args.run_target),
                        ]);
                    } else {
                        execve_args.extend([
                            format!(
                                "-XX:AOTLibrary=/usr/lib/jvm/java.base.so,./{}.so",
                                args.run_target,
                            ),
                            args.run_target.clone(),
                        ]);
                    }
                }
                args::Language::Python2 => {
                    seccomp_profile_name = String::from("py");
                    mounts.push(MountArgs {
                        source: Some(root.join("root-python2")),
                        target: rootfs.join("usr/lib/python2.7"),
                        fstype: None,
                        flags: MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                        data: None,
                    });
                    execve_args.extend([
                        String::from("/usr/bin/python2.7"),
                        String::from(format!("{}.py", args.run_target)),
                    ]);
                }
                args::Language::Python | args::Language::Python3 => {
                    seccomp_profile_name = String::from("py");
                    mounts.push(MountArgs {
                        source: Some(root.join("root-python3")),
                        target: rootfs.join("opt/python3"),
                        fstype: None,
                        flags: MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                        data: None,
                    });
                    execve_args.extend([
                        String::from("/usr/bin/python3.9"),
                        format!("{}.py", args.run_target),
                    ]);
                }
                args::Language::Ruby => {
                    extra_memory_size_in_bytes = RUBY_EXTRA_MEMORY_SIZE_IN_BYTES;
                    vm_memory_size_in_bytes = RUBY_VM_MEMORY_SIZE_IN_BYTES;
                    seccomp_profile_name = String::from("ruby");
                    mounts.push(MountArgs {
                        source: Some(root.join("root-ruby")),
                        target: rootfs.join("usr/lib/ruby"),
                        fstype: None,
                        flags: MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                        data: None,
                    });
                    execve_args.extend([
                        String::from("/usr/bin/ruby"),
                        format!("{}.rb", args.run_target),
                    ]);
                }
                args::Language::Rust => {
                    seccomp_profile_name = String::from("rs");
                    execve_args.extend([format!("./{}", args.run_target)]);
                }
                args::Language::Go => {
                    extra_memory_size_in_bytes = GO_EXTRA_MEMORY_SIZE_IN_BYTES;
                    seccomp_profile_name = String::from("go");
                    execve_args.extend([format!("./{}", args.run_target)]);
                }
                args::Language::Julia => {
                    extra_memory_size_in_bytes = JULIA_EXTRA_MEMORY_SIZE_IN_BYTES;
                    seccomp_profile_name = String::from("jl");
                    mounts.push(MountArgs {
                        source: Some(root.join("root-julia")),
                        target: rootfs.join("opt/julia"),
                        fstype: None,
                        flags: MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                        data: None,
                    });
                    execve_args.extend([
                        String::from("/usr/bin/julia"),
                        format!("{}.jl", args.run_target),
                    ]);
                }
                args::Language::JavaScript => {
                    seccomp_profile_name = String::from("js");
                    mounts.push(MountArgs {
                        source: Some(root.join("root-js")),
                        target: rootfs.join("opt/nodejs"),
                        fstype: None,
                        flags: MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                        data: None,
                    });
                    execve_args.extend([
                        String::from("/opt/nodejs/bin/node"),
                        String::from("--jitless"),
                        format!("{}.js", &args.run_target),
                    ]);
                }
                args::Language::KarelPascal | args::Language::KarelJava => {
                    seccomp_profile_name = String::from("karel");
                    mounts.push(MountArgs {
                        source: Some(root.join("root-js")),
                        target: rootfs.join("opt/nodejs"),
                        fstype: None,
                        flags: MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                        data: None,
                    });
                    execve_args.extend([
                        String::from("/opt/nodejs/karel.wasm"),
                        String::from(format!("{}.kx", &args.run_target)),
                    ]);
                }
                args::Language::CSharp => {
                    extra_memory_size_in_bytes = CLR_VM_MEMORY_SIZE_IN_BYTES;
                    use_cgroups_for_memory_limit = true;
                    vm_memory_size_in_bytes = CLR_VM_MEMORY_SIZE_IN_BYTES;
                    seccomp_profile_name = String::from("cs");
                    mounts.push(MountArgs {
                        source: Some(root.join("root-dotnet")),
                        target: rootfs.join("usr/share/dotnet"),
                        fstype: None,
                        flags: MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                        data: None,
                    });
                    execve_args.extend([
                        String::from("/usr/share/dotnet/dotnet"),
                        format!("{}.dll", &args.run_target),
                    ]);
                    env.push("DOTNET_CLI_TELEMETRY_OPTOUT=1");
                }
            }
        }

        for bind in args.bind {
            let parts: Vec<&str> = bind.split(":").collect();

            if parts.len() != 2 {
                bail!("invalid bind description: {:?}", bind);
            }

            mounts.push(MountArgs {
                source: Some(parts[0].into()),
                target: rootfs.join(parts[1][1..].to_string()),
                fstype: None,
                flags: MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                data: None,
            });
        }

        execve_args.extend(args.extra_args);

        let mut seccomp_bpf_filter_notify_contents = vec![];
        let mut bpf_filter_path = root.join(format!("policies/{}.bpf", seccomp_profile_name));
        File::open(&bpf_filter_path)
            .with_context(|| format!("open {:?}", &bpf_filter_path))?
            .read_to_end(&mut seccomp_bpf_filter_notify_contents)
            .with_context(|| format!("read {:?}", &bpf_filter_path))?;

        let mut seccomp_bpf_filter_sigsys_contents = vec![];
        bpf_filter_path = root.join(format!("policies/sigsys/{}.bpf", seccomp_profile_name));
        File::open(&bpf_filter_path)
            .with_context(|| format!("open {:?}", &bpf_filter_path))?
            .read_to_end(&mut seccomp_bpf_filter_sigsys_contents)
            .with_context(|| format!("read {:?}", &bpf_filter_path))?;

        let (time_limit, wall_time_limit) = match args.time_limit {
            Some(time_limit) => (
                Some(Duration::from_millis(time_limit)),
                Duration::from_millis(time_limit + args.extra_wall_time_limit),
            ),
            None => (None, Duration::from_millis(args.extra_wall_time_limit)),
        };

        Ok(JailOptions {
            disable_sandboxing: args.disable_sandboxing,
            homedir: PathBuf::from(args.homedir),
            rootfs: rootfs,
            cgroup_path: Some(PathBuf::from(args.cgroup_path)),
            mounts: mounts,
            args: execve_args
                .iter()
                .map(|s| CString::new(s.clone()))
                .try_collect()?,
            env: env.iter().map(|s| CString::new(*s)).try_collect()?,
            seccomp_bpf_filter_notify_contents: seccomp_bpf_filter_notify_contents,
            seccomp_bpf_filter_sigsys_contents: seccomp_bpf_filter_sigsys_contents,
            seccomp_profile_name: seccomp_profile_name,
            meta: args.meta.map(|s| PathBuf::from(s)),

            stdin: stdin,
            stdout: stdout,
            stderr: stderr,

            time_limit: time_limit,
            wall_time_limit: wall_time_limit,
            output_limit: args.output_limit,
            vm_memory_size_in_bytes: vm_memory_size_in_bytes,
            use_cgroups_for_memory_limit: use_cgroups_for_memory_limit,
            memory_limit: match args
                .memory_limit
                .map(|m| m.saturating_add(extra_memory_size_in_bytes))
            {
                Some(u64::MAX) => None,
                Some(m) => Some(m),
                None => None,
            },
            allow_sigsys_fallback: args.allow_sigsys_fallback,
        })
    }
}
