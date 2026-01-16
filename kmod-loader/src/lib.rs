#![no_std]
#![allow(unsafe_op_in_unsafe_fn)]
pub mod arch;
mod loader;
mod module;
mod param;

use axerrno::{LinuxError, LinuxResult};
pub use loader::{KernelModuleHelper, ModuleLoader, ModuleOwner, SectionMemOps, SectionPerm};
extern crate alloc;

type Result<T> = LinuxResult<T>;
type ModuleErr = LinuxError;
