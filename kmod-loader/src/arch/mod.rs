mod aarch64;
mod loongarch64;
mod riscv64;
mod x86_64;

#[cfg(target_arch = "aarch64")]
pub use aarch64::Aarch64RelocationType as RelocationType;
#[cfg(target_arch = "loongarch64")]
pub use loongarch64::Loongarch64RelocationType as RelocationType;
#[cfg(target_arch = "riscv64")]
pub use riscv64::Riscv64RelocationType as RelocationType;
#[cfg(target_arch = "x86_64")]
pub use x86_64::X86_64RelocationType as RelocationType;
