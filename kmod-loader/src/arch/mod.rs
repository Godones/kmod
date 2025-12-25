mod aarch64;
mod loongarch64;
mod riscv64;
mod x86_64;

pub use aarch64::{Aarch64ArchRelocate, Aarch64RelocationType};
pub use loongarch64::{Loongarch64ArchRelocate, Loongarch64RelocationType};
pub use riscv64::{Riscv64ArchRelocate, Riscv64RelocationType};
pub use x86_64::{X86_64ArchRelocate, X86_64RelocationType};

/// Extracts the relocation type from the r_info field of an Elf64_Rela
const fn get_rela_type(r_info: u64) -> u32 {
    (r_info & 0xffffffff) as u32
}

/// Extracts the symbol index from the r_info field of an Elf64_Rela
const fn get_rela_sym_idx(r_info: u64) -> usize {
    (r_info >> 32) as usize
}

#[derive(Debug, Clone, Copy)]
struct Ptr(u64);
impl Ptr {
    fn as_ptr<T>(&self) -> *mut T {
        self.0 as *mut T
    }

    /// Writes a value of type T to the pointer location
    pub fn write<T>(&self, value: T) {
        unsafe {
            let ptr = self.as_ptr::<T>();
            ptr.write(value);
        }
    }

    pub fn read<T>(&self) -> T {
        unsafe {
            let ptr = self.as_ptr::<T>();
            ptr.read()
        }
    }

    pub fn add(&self, offset: usize) -> Ptr {
        Ptr(self.0 + offset as u64)
    }

    pub fn as_slice<T>(&self, len: usize) -> &[T] {
        unsafe {
            let ptr = self.as_ptr::<T>();
            core::slice::from_raw_parts(ptr, len)
        }
    }
}

#[macro_export]
macro_rules! BIT {
    ($nr:expr) => {
        (1u32 << $nr)
    };
}

#[macro_export]
macro_rules! BIT_U64 {
    ($nr:expr) => {
        (1u64 << $nr)
    };
}
