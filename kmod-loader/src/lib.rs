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

// type Result<T> = core::result::Result<T, ModuleErr>;

// #[derive(Debug)]
// pub enum ModuleErr {
//     InvalidElf,
//     InvalidOperation,
//     UnsupportedArch,
//     RelocationFailed(String),
//     MemoryAllocationFailed,
//     UnsupportedFeature,
//     UndefinedSymbol,
//     EINVAL,
//     ENOSPC,
// }
// impl core::fmt::Display for ModuleErr {
//     fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
//         match self {
//             ModuleErr::InvalidElf => write!(f, "Invalid ELF file"),
//             ModuleErr::InvalidOperation => write!(f, "Invalid operation"),
//             ModuleErr::UnsupportedArch => write!(f, "Unsupported architecture"),
//             ModuleErr::RelocationFailed(msg) => write!(f, "Relocation failed: {}", msg),
//             ModuleErr::MemoryAllocationFailed => write!(f, "Memory allocation failed"),
//             ModuleErr::UnsupportedFeature => write!(f, "Unsupported feature encountered"),
//             ModuleErr::UndefinedSymbol => write!(f, "Undefined symbol encountered"),
//             ModuleErr::EINVAL => write!(f, "Invalid argument"),
//             ModuleErr::ENOSPC => write!(f, "No space left on device"),
//         }
//     }
// }

// impl core::error::Error for ModuleErr {}
