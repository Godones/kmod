use crate::{ModuleErr, Result};

use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};
use bitflags::bitflags;
use core::fmt::Display;
use goblin::elf::{Elf, SectionHeader};
use kmod::ModuleInfo;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SectionPerm: u8 {
        const READ = 0b001;
        const WRITE = 0b010;
        const EXECUTE = 0b100;
    }
}

impl Display for SectionPerm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut perms = String::new();
        if self.contains(SectionPerm::READ) {
            perms.push('R');
        }
        if self.contains(SectionPerm::WRITE) {
            perms.push('W');
        }
        if self.contains(SectionPerm::EXECUTE) {
            perms.push('X');
        }
        write!(f, "{}", perms)
    }
}

impl SectionPerm {
    /// Create ModuleSectionPermissions from ELF section flags
    pub fn from_elf_flags(sh_flags: u64) -> Self {
        let mut perms = SectionPerm::empty();
        if (sh_flags & goblin::elf::section_header::SHF_ALLOC as u64) != 0 {
            perms |= SectionPerm::READ;
        }
        if (sh_flags & goblin::elf::section_header::SHF_WRITE as u64) != 0 {
            perms |= SectionPerm::WRITE;
        }
        if (sh_flags & goblin::elf::section_header::SHF_EXECINSTR as u64) != 0 {
            perms |= SectionPerm::EXECUTE;
        }
        perms
    }
}

/// Trait to get raw pointer from a reference
pub trait SectionMemOps {
    fn as_ptr(&self) -> *const u8;
    fn as_mut_ptr(&mut self) -> *mut u8;
    /// Change the permissions of the memory region
    fn change_perms(&mut self, perms: SectionPerm) -> bool;
}

/// Trait for kernel module helper functions
pub trait KernelModuleHelper {
    /// Allocate virtual memory for module section
    fn vmalloc(size: usize) -> Box<dyn SectionMemOps>;
    /// Resolve symbol name to address
    fn resolve_symbol(name: &str) -> Option<usize>;
    /// Flush CPU cache for the given memory region
    fn flsuh_cache(_addr: usize, _size: usize) {
        // Default implementation does nothing
    }
}

pub struct ModuleLoader<'a, H: KernelModuleHelper> {
    elf: Elf<'a>,
    elf_data: &'a [u8],
    module_name: Option<&'a str>,
    __helper: core::marker::PhantomData<H>,
}

struct SectionPages {
    name: String,
    addr: Box<dyn SectionMemOps>,
    size: usize,
    perms: SectionPerm,
}

pub struct ModuleOwner<H: KernelModuleHelper> {
    module_info: ModuleInfo,
    pages: Vec<SectionPages>,
    _helper: core::marker::PhantomData<H>,
}

impl<H: KernelModuleHelper> ModuleOwner<H> {
    /// Get the name of the module
    pub fn name(&self) -> &str {
        self.module_info.name()
    }

    /// Call the module's init function
    pub fn call_init(&mut self) -> Result<i32> {
        if let Some(init_fn) = self.module_info.init_fn.take() {
            let result = init_fn();
            Ok(result)
        } else {
            log::warn!("The init function can only be called once.");
            Err(ModuleErr::InvalidOperation)
        }
    }

    /// Call the module's exit function
    pub fn call_exit(&mut self) {
        if let Some(exit_fn) = self.module_info.exit_fn.take() {
            exit_fn();
        } else {
            log::warn!("The exit function can only be called once.");
        }
    }
}

const fn align_up(addr: usize, align: usize) -> usize {
    (addr + align - 1) & !(align - 1)
}

// const fn align_down(addr: usize, align: usize) -> usize {
//     addr & !(align - 1)
// }

pub struct ModuleLoadInfo {
    pub(crate) syms: Vec<goblin::elf::sym::Sym>,
    pub(crate) symbol_names: Vec<String>,
}

impl<'a, H: KernelModuleHelper> ModuleLoader<'a, H> {
    /// create a new ELF loader
    pub fn new(elf_data: &'a [u8]) -> Result<Self> {
        let elf = Elf::parse(elf_data).map_err(|_| ModuleErr::InvalidElf)?;
        if !elf.is_64 {
            return Err(ModuleErr::UnsupportedArch);
        }
        let module_name = elf.shdr_strtab.get_at(elf.header.e_shstrndx as usize);
        Ok(ModuleLoader {
            elf,
            elf_data,
            module_name,
            __helper: core::marker::PhantomData,
        })
    }

    /// Load the module into kernel space
    pub fn load_module(mut self) -> Result<ModuleOwner<H>> {
        let mut owner = self.pre_read_modinfo()?;
        self.layout_and_allocate(&mut owner)?;
        let load_info = self.simplify_symbols()?;
        self.apply_relocations(load_info, &owner)?;

        self.post_read_modinfo(&mut owner)?;

        self.set_section_perms(&mut owner)?;

        log::error!(
            "Module({}) loaded successfully, info: {:?}",
            owner.name(),
            owner.module_info
        );
        Ok(owner)
    }

    fn find_modinfo_section(&self) -> Result<&SectionHeader> {
        for shdr in &self.elf.section_headers {
            let sec_name = self
                .elf
                .shdr_strtab
                .get_at(shdr.sh_name)
                .ok_or(ModuleErr::InvalidElf)?;

            if sec_name == ".modinfo" {
                return Ok(shdr);
            }
        }
        Err(ModuleErr::InvalidElf)
    }

    fn pre_read_modinfo(&self) -> Result<ModuleOwner<H>> {
        let modinfo_shdr = self.find_modinfo_section()?;
        let file_offset = modinfo_shdr.sh_offset as usize;
        let size = modinfo_shdr.sh_size as usize;

        if size != core::mem::size_of::<ModuleInfo>() {
            return Err(ModuleErr::InvalidElf);
        }

        let modinfo_data = &self.elf_data[file_offset..file_offset + size];
        let module_info: ModuleInfo =
            unsafe { core::ptr::read(modinfo_data.as_ptr() as *const ModuleInfo) };

        Ok(ModuleOwner {
            module_info,
            pages: Vec::new(),
            _helper: core::marker::PhantomData,
        })
    }

    fn post_read_modinfo(&mut self, owner: &mut ModuleOwner<H>) -> Result<()> {
        let modinfo_shdr = self.find_modinfo_section()?;
        let size = modinfo_shdr.sh_size as usize;

        if size != core::mem::size_of::<ModuleInfo>() {
            return Err(ModuleErr::InvalidElf);
        }
        // the data address is the allocated virtual address and it has been relocated
        let modinfo_data = modinfo_shdr.sh_addr as *mut u8;
        let module_info = unsafe { core::ptr::read(modinfo_data as *const ModuleInfo) };
        owner.module_info = module_info;
        Ok(())
    }

    fn set_section_perms(&self, owner: &mut ModuleOwner<H>) -> Result<()> {
        for page in &mut owner.pages {
            if !page.addr.change_perms(page.perms) {
                log::error!(
                    "Failed to change permissions of section '{}' to {}",
                    page.name,
                    page.perms
                );
                return Err(ModuleErr::InvalidOperation);
            }
            H::flsuh_cache(page.addr.as_ptr() as usize, page.size);
        }
        Ok(())
    }

    /// Layout sections and allocate memory
    /// See <https://elixir.bootlin.com/linux/v6.6/source/kernel/module/main.c#L2363>
    fn layout_and_allocate(&mut self, owner: &mut ModuleOwner<H>) -> Result<()> {
        for shdr in &mut self.elf.section_headers {
            let sec_name = self
                .elf
                .shdr_strtab
                .get_at(shdr.sh_name)
                .unwrap_or("<unknown>");

            // Skip non-allocatable sections
            if (shdr.sh_flags & goblin::elf::section_header::SHF_ALLOC as u64) == 0 {
                continue;
            }

            assert!(
                shdr.sh_addr % 4096 == 0,
                "Section '{}' address not page-aligned",
                sec_name
            );
            let file_offset = shdr.sh_offset as usize;
            let size = shdr.sh_size as usize;

            let perms = SectionPerm::from_elf_flags(shdr.sh_flags);

            if size == 0 {
                log::error!("Skipping zero-size section '{}'", sec_name);
                continue;
            }

            let aligned_size = align_up(size, 4096);

            // Allocate memory for the section
            let mut addr = H::vmalloc(aligned_size);
            if addr.as_ptr().is_null() {
                return Err(ModuleErr::MemoryAllocationFailed);
            }

            let raw_addr = addr.as_ptr() as u64;

            // Copy section data from ELF to allocated memory
            let section_data = &self.elf_data[file_offset..file_offset + size];
            unsafe {
                core::ptr::copy_nonoverlapping(section_data.as_ptr(), addr.as_mut_ptr(), size);
            }

            // Store the allocated page info
            owner.pages.push(SectionPages {
                name: sec_name.to_string(),
                addr,
                size: aligned_size,
                perms,
            });

            // update section address
            // Note: In a real loader, we would update the section header's sh_addr field
            // to reflect the new virtual address.
            shdr.sh_addr = raw_addr;
        }

        for page in &owner.pages {
            log::error!(
                "Allocated section '{:>16}' at {:p} [{}] ({:8<#x})",
                page.name,
                page.addr.as_ptr(),
                page.perms,
                page.size
            );
        }

        Ok(())
    }

    /// Change all symbols so that st_value encodes the pointer directly.
    ///
    /// See <https://elixir.bootlin.com/linux/v6.6/source/kernel/module/main.c#L1367>
    fn simplify_symbols(&self) -> Result<ModuleLoadInfo> {
        let mut loadinfo = ModuleLoadInfo {
            syms: Vec::new(),
            symbol_names: Vec::new(),
        };

        for sym in self.elf.syms.iter() {
            let sym_name = self.elf.strtab.get_at(sym.st_name).unwrap_or("<unknown>");

            let sym_name = format!("{:#}", rustc_demangle::demangle(sym_name));
            let sym_value = sym.st_value;
            let sym_size = sym.st_size;

            // For debugging purposes, print symbol info
            log::debug!(
                "Symbol: ('{}') [{}] Value: 0x{:016x} Size: {}",
                sym_name,
                sym_section_to_str(sym.st_shndx as _),
                sym_value,
                sym_size
            );

            loadinfo.syms.push(sym);
            loadinfo.symbol_names.push(sym_name.clone());

            match sym.st_shndx as _ {
                goblin::elf::section_header::SHN_UNDEF => {
                    // Undefined symbol
                    let sym_address = H::resolve_symbol(&sym_name);
                    // Ok if resolved.
                    if let Some(addr) = sym_address {
                        log::error!(
                            "  -> Resolved undefined symbol '{}' ({}) to address 0x{:016x}",
                            sym_name,
                            sym_bind_to_str(sym.st_bind()),
                            addr
                        );
                        // we would update the symbol table entry's st_value
                        // to reflect the resolved address.
                        loadinfo.syms.last_mut().unwrap().st_value = addr as u64;
                    } else {
                        // Ok if weak or ignored.
                        if sym.st_bind() == goblin::elf::sym::STB_WEAK {
                            log::warn!(
                                "  -> Unresolved weak symbol '{}' ({})",
                                sym_name,
                                sym_bind_to_str(sym.st_bind())
                            );
                        } else {
                            log::warn!(
                                "  -> Unresolved symbol '{}' ({})",
                                sym_name,
                                sym_bind_to_str(sym.st_bind())
                            );
                        }
                    }
                }
                goblin::elf::section_header::SHN_ABS => {
                    // Don't need to do anything
                    log::debug!("Absolute symbol: {} 0x{:x}", sym_name, sym_value);
                }
                goblin::elf::section_header::SHN_COMMON => {
                    // Ignore common symbols
                    // We compiled with -fno-common. These are not supposed to happen.
                    log::debug!("Common symbol: {}", sym_name);
                    log::warn!(
                        "{}: please compile with -fno-common",
                        self.module_name.unwrap_or("<unknown>")
                    );
                    return Err(ModuleErr::UnsupportedFeature);
                }
                ty => {
                    /* Divert to percpu allocation if a percpu var. */
                    // if (sym[i].st_shndx == info->index.pcpu)
                    //     secbase = (unsigned long)mod_percpu(mod);
                    // else
                    //     secbase = info->sechdrs[sym[i].st_shndx].sh_addr;
                    // sym[i].st_value += secbase;

                    // TODO: Handle special sections like percpu
                    // Normal symbol defined in a section
                    loadinfo.syms.last_mut().unwrap().st_value +=
                        self.elf.section_headers[ty as usize].sh_addr;
                    log::trace!(
                        "  -> Defined symbol '{}' in section {} at address 0x{:016x}",
                        sym_name,
                        ty,
                        loadinfo.syms.last().unwrap().st_value
                    );
                }
            }
        }

        Ok(loadinfo)
    }

    /// See <https://elixir.bootlin.com/linux/v6.6/source/kernel/module/main.c#L1438>
    fn apply_relocations(&self, load_info: ModuleLoadInfo, owner: &ModuleOwner<H>) -> Result<()> {
        for (_, shdr) in self.elf.section_headers.iter().enumerate() {
            let infosec = shdr.sh_info;

            let sec_name = self
                .elf
                .shdr_strtab
                .get_at(shdr.sh_name)
                .ok_or(ModuleErr::InvalidElf)?;

            // Not a valid relocation section?
            if infosec >= self.elf.section_headers.len() as u32 {
                continue;
            }
            // Don't bother with non-allocated sections
            if self.elf.section_headers[infosec as usize].sh_flags
                & goblin::elf::section_header::SHF_ALLOC as u64
                == 0
            {
                continue;
            }

            // Skip non-relocation sections
            if shdr.sh_type != goblin::elf::section_header::SHT_RELA {
                continue;
            }

            let to_section = &self.elf.section_headers[infosec as usize];
            let to_sec_name = self
                .elf
                .shdr_strtab
                .get_at(to_section.sh_name)
                .ok_or(ModuleErr::InvalidElf)?;

            let rela_entries = shdr.sh_size as usize / shdr.sh_entsize as usize;
            log::error!(
                "Applying relocations for section '{}' to '{}', {} entries",
                sec_name,
                to_sec_name,
                rela_entries
            );

            let offset = shdr.sh_offset as usize;
            // Size of Elf64_Rela
            debug_assert!(shdr.sh_entsize == 24);

            let data_buf = &self.elf_data[offset..offset + shdr.sh_size as usize];
            let rela_list = unsafe {
                goblin::elf64::reloc::from_raw_rela(data_buf.as_ptr() as _, shdr.sh_size as usize)
            };

            match self.elf.header.e_machine {
                goblin::elf::header::EM_RISCV => {
                    crate::arch::Riscv64ArchRelocate::apply_relocate_add(
                        &rela_list,
                        shdr,
                        &self.elf.section_headers,
                        &load_info,
                        owner,
                    )?;
                }
                goblin::elf::header::EM_LOONGARCH => {
                    crate::arch::Loongarch64ArchRelocate::apply_relocate_add(
                        &rela_list,
                        shdr,
                        &self.elf.section_headers,
                        &load_info,
                        owner,
                    )?;
                }
                goblin::elf::header::EM_AARCH64 => {
                    crate::arch::Aarch64ArchRelocate::apply_relocate_add(
                        &rela_list,
                        shdr,
                        &self.elf.section_headers,
                        &load_info,
                        owner,
                    )?;
                }
                goblin::elf::header::EM_X86_64 => {
                    crate::arch::X86_64ArchRelocate::apply_relocate_add(
                        &rela_list,
                        shdr,
                        &self.elf.section_headers,
                        &load_info,
                        owner,
                    )?;
                }
                _ => {
                    panic!(
                        "Relocations for architecture '{}' not supported",
                        self.get_machine_type()
                    );
                }
            }
        }
        Ok(())
    }

    fn get_machine_type(&self) -> &'static str {
        match self.elf.header.e_machine {
            goblin::elf::header::EM_X86_64 => "x86-64",
            goblin::elf::header::EM_AARCH64 => "AArch64",
            goblin::elf::header::EM_RISCV => "RISC-V",
            goblin::elf::header::EM_LOONGARCH => "LoongArch",
            _ => "unknown",
        }
    }
}

const fn sym_bind_to_str(bind: u8) -> &'static str {
    match bind {
        goblin::elf::sym::STB_LOCAL => "LOCAL",
        goblin::elf::sym::STB_GLOBAL => "GLOBAL",
        goblin::elf::sym::STB_WEAK => "WEAK",
        _ => "UNKNOWN",
    }
}

const fn sym_section_to_str(shndx: u32) -> &'static str {
    match shndx {
        goblin::elf::section_header::SHN_UNDEF => "UNDEF(0)",
        goblin::elf::section_header::SHN_LORESERVE => "LORESERVE(0xff00)",
        // goblin::elf::section_header::SHN_LOPROC => "LOPROC(0xff00)",
        goblin::elf::section_header::SHN_HIPROC => "HIPROC(0xff1f)",
        goblin::elf::section_header::SHN_ABS => "ABS(0xfff1)",
        goblin::elf::section_header::SHN_COMMON => "COMMON(0xfff2)",
        goblin::elf::section_header::SHN_HIRESERVE => "HIRESERVE(0xffff)",
        _ => "OTHER",
    }
}

// #define SHN_LIVEPATCH	0xff20
