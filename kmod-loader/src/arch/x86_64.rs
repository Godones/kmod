use alloc::format;
use goblin::elf::SectionHeader;
use int_enum::IntEnum;

use crate::arch::{Ptr, get_rela_sym_idx, get_rela_type};
use crate::loader::{KernelModuleHelper, ModuleLoadInfo, ModuleOwner};
use crate::{ModuleErr, Result};

#[repr(u32)]
#[derive(Debug, Clone, Copy, IntEnum)]
#[allow(non_camel_case_types)]
/// See <https://elixir.bootlin.com/linux/v6.6/source/arch/x86/include/asm/elf.h#L47>
pub enum X86_64RelocationType {
    /// No reloc
    R_X86_64_NONE = 0,
    /// Direct 64 bit
    R_X86_64_64 = 1,
    /// PC relative 32 bit signed
    R_X86_64_PC32 = 2,
    /// 32 bit GOT entry
    R_X86_64_GOT32 = 3,
    /// 32 bit PLT address
    R_X86_64_PLT32 = 4,
    /// Copy symbol at runtime
    R_X86_64_COPY = 5,
    /// Create GOT entry
    R_X86_64_GLOB_DAT = 6,
    /// Create PLT entry
    R_X86_64_JUMP_SLOT = 7,
    /// Adjust by program base
    R_X86_64_RELATIVE = 8,
    /// 32 bit signed pc relative offset to GOT
    R_X86_64_GOTPCREL = 9,
    /// Direct 32 bit zero extended
    R_X86_64_32 = 10,
    /// Direct 32 bit sign extended
    R_X86_64_32S = 11,
    /// Direct 16 bit zero extended
    R_X86_64_16 = 12,
    /// 16 bit sign extended pc relative
    R_X86_64_PC16 = 13,
    /// Direct 8 bit sign extended
    R_X86_64_8 = 14,
    /// 8 bit sign extended pc relative
    R_X86_64_PC8 = 15,
    /// Place relative 64-bit signed
    R_X86_64_PC64 = 24,
}

type X64RelTy = X86_64RelocationType;

impl X86_64RelocationType {
    fn apply_relocation(&self, location: u64, mut target_addr: u64) -> Result<()> {
        let size;
        let location = Ptr(location);
        let overflow = || {
            log::error!(
                "overflow in relocation type {:?}, target address {:#x}",
                self,
                target_addr
            );
            log::error!("module likely not compiled with -mcmodel=kernel");
            ModuleErr::RelocationFailed(format!(
                "Overflow in relocation type {:?}, target address {:#x}",
                self, target_addr
            ))
        };
        match self {
            X64RelTy::R_X86_64_NONE => return Ok(()),
            X64RelTy::R_X86_64_64 => {
                size = 8;
            }
            X64RelTy::R_X86_64_32 => {
                if target_addr != target_addr as u32 as u64 {
                    return Err(overflow());
                }
                size = 4;
            }
            X64RelTy::R_X86_64_32S => {
                if target_addr as i64 != target_addr as i32 as i64 {
                    return Err(overflow());
                }
                size = 4;
            }
            X64RelTy::R_X86_64_PC32 | X64RelTy::R_X86_64_PLT32 => {
                target_addr = target_addr.wrapping_sub(location.0);
                size = 4;
            }
            X64RelTy::R_X86_64_PC64 => {
                target_addr = target_addr.wrapping_sub(location.0);
                size = 8;
            }
            _ => {
                return Err(ModuleErr::RelocationFailed(format!(
                    "Unsupported relocation type: {:?}",
                    self
                )));
            }
        }
        // if (memcmp(loc, &zero, size))
        if location.as_slice::<u8>(size).iter().any(|&b| b != 0) {
            log::error!(
                "x86/modules: Invalid relocation target, existing value is nonzero for type {:?}, loc: {:#x}, value: {:#x}",
                self,
                location.0,
                target_addr
            );
            return Err(ModuleErr::RelocationFailed(format!(
                "Invalid relocation target, existing value is nonzero for type {:?}",
                self
            )));
        } else {
            // Write the relocated value
            match size {
                4 => location.write::<u32>(target_addr as u32),
                8 => location.write::<u64>(target_addr as u64),
                _ => unreachable!(),
            }
        }
        Ok(())
    }
}

pub struct X86_64ArchRelocate;

#[allow(unused_assignments)]
impl X86_64ArchRelocate {
    /// See https://elixir.bootlin.com/linux/v6.6/source/arch/x86/kernel/module.c#L252
    pub fn apply_relocate_add<H: KernelModuleHelper>(
        rela_list: &[goblin::elf64::reloc::Rela],
        rel_section: &SectionHeader,
        sechdrs: &[SectionHeader],
        load_info: &ModuleLoadInfo,
        module: &ModuleOwner<H>,
    ) -> Result<()> {
        for rela in rela_list {
            let rel_type = get_rela_type(rela.r_info);
            let sym_idx = get_rela_sym_idx(rela.r_info);

            // This is where to make the change
            let location = sechdrs[rel_section.sh_info as usize].sh_addr + rela.r_offset;
            let sym = load_info.syms[sym_idx];

            let reloc_type = X86_64RelocationType::try_from(rel_type).map_err(|_| {
                ModuleErr::RelocationFailed(format!("Invalid relocation type: {}", rel_type))
            })?;

            let target_addr = sym.st_value.wrapping_add(rela.r_addend as u64);

            log::info!(
                "[{}]: Applying relocation {:?} at location {:#x} with target addr {:#x}",
                module.name(),
                reloc_type,
                location,
                target_addr
            );

            let res = reloc_type.apply_relocation(location, target_addr);
            match res {
                Err(e) => {
                    let sym_name = &load_info.symbol_names[sym_idx];
                    log::error!("[{}]: '{}' {:?}", module.name(), sym_name, e);
                    return Err(e);
                }
                Ok(_) => { /* Successfully applied relocation */ }
            }
        }
        Ok(())
    }
}
