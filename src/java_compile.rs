use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use clap::{ArgEnum, Parser};

#[allow(dead_code)]
fn trim_extension<S1: AsRef<str>, S2: AsRef<str>>(filename: S1, extension: S2) -> String {
    filename
        .as_ref()
        .strip_suffix(extension.as_ref())
        .unwrap_or(filename.as_ref())
        .into()
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ArgEnum)]
enum Language {
    Java,
    Kotlin,
}

#[derive(Parser, Clone, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// The language in which to compile
    #[clap(long, arg_enum, value_name = "LANGUAGE", default_value = "java")]
    language: Language,

    /// The name of the entrypoint class
    target: String,

    /// The sources to be compiled
    #[clap(required = true)]
    sources: Vec<String>,
}

#[doc(hidden)]
fn main() -> Result<()> {
    let args = Args::parse();
    println!("target = {:?} sources = {:?}", args.target, args.sources);

    let mut compiler_args = match args.language {
        Language::Java => vec![
            "/usr/bin/javac".into(),
            "-J-Xmx896M".into(),
            "-J-Xms32M".into(),
        ],
        Language::Kotlin => vec![
            "/usr/lib/jvm/kotlinc/bin/kotlinc".into(),
            "-Xmx896M".into(),
            "-Xms32M".into(),
        ],
    };
    if args.language == Language::Kotlin {
    }
    compiler_args.extend_from_slice(&["-d".into(), ".".into()]);

    if args.language == Language::Kotlin {
        compiler_args.push("-include-runtime".into());
        compiler_args.push("-jvm-target".into());
        compiler_args.push("17".into());
    }

    compiler_args.extend_from_slice(&args.sources);

    let status = Command::new(&compiler_args[0])
        .args(compiler_args[1..].iter())
        .status()
        .with_context(|| anyhow!("execve({:?})", &compiler_args))?;
    if !status.success() {
        bail!("execve({:?}) failed: {:?}", &compiler_args, status);
    }

    Ok(())
}
