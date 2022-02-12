#![doc = include_str!("../README.md")]
#![doc(issue_tracker_base_url = "https://github.com/omegaup/omegajail/issues/")]

mod args;
pub mod jail;
#[doc(hidden)]
pub mod sys;

pub use args::Args;
pub use jail::Command;
