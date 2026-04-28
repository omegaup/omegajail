#!/bin/bash
# Script to fix warnings in the code

# Fix src/jail/options.rs
sed -i 's/DevNull(PathBuf)/DevNull(())/g' src/jail/options.rs
sed -i 's/Stdio::DevNull(source)/Stdio::DevNull(())/g' src/jail/options.rs
sed -i 's/let mut env: Vec<&str>/let env: Vec<&str>/g' src/jail/options.rs

# Fix src/java_compile.rs
sed -i '1s/use std::env;//' src/java_compile.rs
sed -i '2s/use std::ffi::CString;//' src/java_compile.rs
sed -i '7s/use nix::unistd::execve;//' src/java_compile.rs

echo "Corrections applied. Running cargo check to verify..."
cargo check
