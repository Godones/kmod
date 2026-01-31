#![no_std]
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(clippy::missing_safety_doc)]
extern crate alloc;

use axerrno::{LinuxError, LinuxResult};

type Result<T> = LinuxResult<T>;
type ModuleErr = LinuxError;

pub mod kstrtox;
pub mod mm;
pub mod param;
pub mod string;
pub mod string_helper;
