//! The arguments for the jail.

use clap::{ArgEnum, ArgGroup, Parser};

/// The languages supported by the jail.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ArgEnum)]
pub enum Language {
    C,
    #[clap(name = "c11-gcc")]
    C11GCC,
    C11Clang,
    Cpp,
    Cpp03GCC,
    Cpp03Clang,
    Cpp11,
    Cpp11GCC,
    Cpp11Clang,
    Cpp17GCC,
    Cpp17Clang,
    Cpp20GCC,
    Cpp20Clang,
    #[clap(name = "pas")]
    Pascal,
    Lua,
    #[clap(name = "hs")]
    Haskell,
    #[clap(name = "java")]
    Java,
    #[clap(name = "kt")]
    Kotlin,
    #[clap(name = "py")]
    Python,
    #[clap(name = "py2")]
    Python2,
    #[clap(name = "py3")]
    Python3,
    #[clap(name = "rb")]
    Ruby,
    #[clap(name = "cs")]
    CSharp,
    #[clap(name = "rs")]
    Rust,
    Go,
    #[clap(name = "js")]
    JavaScript,
    #[clap(name = "kj")]
    KarelJava,
    #[clap(name = "kp")]
    KarelPascal,
}

/// [`clap`](::clap) arguments for the sandboxing.
#[derive(Parser, Clone, Debug)]
#[clap(author, version, about, long_about = None, trailing_var_arg(true))]
#[clap(group(ArgGroup::new("run_mode").required(true).args(&["compile", "run"])))]
pub struct Args {
    /// Root of the omegajail runtime
    #[clap(long, default_value = ".")]
    pub root: String,

    /// Run omegajail in compilation mode for the specified language
    #[clap(
        long,
        arg_enum,
        value_name = "LANGUAGE",
        requires = "compile-source",
        requires = "compile-target"
    )]
    pub compile: Option<Language>,

    /// Add the file to the compilation
    #[clap(long, value_name = "PATH")]
    pub compile_source: Option<Vec<String>>,

    /// Target of the compilation
    #[clap(long, value_name = "PATH", default_value = "Main")]
    pub compile_target: String,

    /// Run omegajail in run mode for the specified language
    #[clap(long, arg_enum, value_name = "LANGUAGE", requires = "run-target")]
    pub run: Option<Language>,

    /// Set the target name to execute
    #[clap(long, value_name = "PATH", default_value = "Main")]
    pub run_target: String,

    /// Specifies |path| to be mounted as /home and chdir'ed to.
    #[clap(long, value_name = "PATH")]
    pub homedir: String,

    /// Specifies that /home will be mounted read-write
    #[clap(long)]
    pub homedir_writable: bool,

    /// Redirects stdin
    #[clap(long, short = '0', value_name = "PATH")]
    pub stdin: Option<String>,

    /// Redirects stdout
    #[clap(long, short = '1', value_name = "PATH")]
    pub stdout: Option<String>,

    /// Redirects stderr
    #[clap(long, short = '2', value_name = "PATH")]
    pub stderr: Option<String>,

    /// Writes a .meta file
    #[clap(long, short = 'M', value_name = "PATH")]
    pub meta: Option<String>,

    /// Sets the time limit
    #[clap(long, short = 't', value_name = "MSEC")]
    pub time_limit: Option<u64>,

    /// Sets the time limit
    #[clap(long, short = 'w', value_name = "MSEC", default_value = "1000")]
    pub extra_wall_time_limit: u64,

    /// Sets the output limit
    #[clap(long, short = 'O', value_name = "BYTES")]
    pub output_limit: Option<u64>,

    /// Sets the memory limit
    #[clap(long, short = 'm', value_name = "BYTES")]
    pub memory_limit: Option<u64>,

    /// The cgroup hierarchy in which processes will be placed
    #[clap(
        long,
        default_value = "/system.slice/omegaup-runner.service/omegajail",
        value_name = "PATH"
    )]
    pub cgroup_path: String,

    /// Completely disable containerization. This is very insecure and should only be used when
    /// omegajail is already being run in a container
    #[clap(long)]
    pub disable_sandboxing: bool,

    /// Additional bind-mounts
    #[clap(long, value_name = "SOURCE:TARGET")]
    pub bind: Vec<String>,

    /// Allows downgrading to the SIGSYS-based seccomp filter that doesn't provide correct SYSACLL
    /// information always
    #[clap(long)]
    pub allow_sigsys_fallback: bool,

    /// Any additional arguments to the executable
    pub extra_args: Vec<String>,
}
