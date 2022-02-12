use std::env;
use std::ffi::CString;
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use clap::{ArgEnum, Parser};
use nix::unistd::execve;

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

    let mut jaotc_args: Vec<String> = vec![
        "/usr/bin/jaotc".into(),
        "-J-Xmx512M".into(),
        "-J-XX:+UseSerialGC".into(),
        "-J-Xshare:on".into(),
        "--output".into(),
        format!("{}.so", args.target),
    ];
    let mut compiler_args = match args.language {
        Language::Java => vec![
            "/usr/bin/javac".into(),
            "-J-Xmx896M".into(),
            "-J-Xms32M".into(),
        ],
        Language::Kotlin => vec![
            "/usr/bin/java".into(),
            "-Xmx896M".into(),
            "-Xms32M".into(),
            "-Xshare:on".into(),
            "-XX:+UseSerialGC".into(),
            "-XX:+UnlockExperimentalVMOptions".into(),
            "-XX:AOTLibrary=/usr/lib/jvm/java.base.so".into(),
            "-cp".into(),
            "/usr/lib/jvm/kotlinc/lib/kotlin-preloader.jar".into(),
            "org.jetbrains.kotlin.preloading.Preloader".into(),
            "-cp".into(),
            "/usr/lib/jvm/kotlinc/lib/kotlin-compiler.jar".into(),
            "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler".into(),
        ],
    };
    if args.language == Language::Kotlin {
        jaotc_args.extend_from_slice(&[
            "-J-XX:+UnlockExperimentalVMOptions".into(),
            "-J-XX:AOTLibrary=/usr/lib/jvm/java.base.so,/usr/lib/jvm/kotlin-stdlib.jar.so".into(),
        ]);
    }
    compiler_args.extend_from_slice(&["-d".into(), ".".into()]);
    compiler_args.extend_from_slice(&args.sources);
    jaotc_args.extend(args.sources.iter().map(|source| match args.language {
        Language::Java => format!("{}.class", trim_extension(source, ".java"),),
        Language::Kotlin => format!("{}Kt.class", trim_extension(source, ".kt"),),
    }));

    let status = Command::new(&compiler_args[0])
        .args(compiler_args[1..].iter())
        .status()
        .with_context(|| anyhow!("execve({:?})", &compiler_args))?;
    if !status.success() {
        bail!("execve({:?}) failed: {:?}", &compiler_args, status);
    }

    let environ: Vec<CString> = env::vars()
        .map(|(key, value)| CString::new(format!("{}={}", key, value)).unwrap())
        .collect();
    execve(
        CString::new(jaotc_args[0].as_str()).unwrap().as_ref(),
        jaotc_args
            .iter()
            .map(|s| CString::new(s.as_str()).unwrap())
            .collect::<Vec<CString>>()
            .as_ref(),
        environ.as_ref(),
    )
    .with_context(|| format!("execve({:?}, {:?})", &jaotc_args, &environ))?;
    Ok(())
}
