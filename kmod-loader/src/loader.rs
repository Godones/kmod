use crate::{ModuleErr, Result, module::ModuleInfo};

use alloc::{
    boxed::Box,
    ffi::CString,
    format,
    string::{String, ToString},
    vec::Vec,
};
use bitflags::bitflags;
use core::{ffi::CStr, fmt::Display};
use goblin::elf::{Elf, SectionHeader};
use kmod::Module;

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
pub trait SectionMemOps: Send + Sync {
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
    name: Option<String>,
    module: Module,
    _helper: core::marker::PhantomData<H>,
}

impl<H: KernelModuleHelper> ModuleOwner<H> {
    /// Get the name of the module
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub(crate) fn set_name(&mut self, name: &str) {
        self.name = Some(name.to_string());
    }

    /// Call the module's init function
    pub fn call_init(&mut self) -> Result<i32> {
        if let Some(init_fn) = self.module.take_init_fn() {
            let result = unsafe { init_fn() };
            Ok(result)
        } else {
            log::warn!("The init function can only be called once.");
            Err(ModuleErr::EINVAL)
        }
    }

    /// Call the module's exit function
    pub fn call_exit(&mut self) {
        if let Some(exit_fn) = self.module.take_exit_fn() {
            log::warn!("Calling module exit function...");
            unsafe {
                exit_fn();
            }
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

const SKIP_SECTIONS: &[&str] = &[".note", ".modinfo", "__version"];

pub(crate) struct ModuleLoadInfo {
    pub(crate) syms: Vec<(goblin::elf::sym::Sym, String)>,
}

impl<'a, H: KernelModuleHelper> ModuleLoader<'a, H> {
    /// create a new ELF loader
    pub fn new(elf_data: &'a [u8]) -> Result<Self> {
        let elf = Elf::parse(elf_data).map_err(|_| ModuleErr::ENOEXEC)?;
        if !elf.is_64 {
            return Err(ModuleErr::ENOEXEC);
        }
        Ok(ModuleLoader {
            elf,
            elf_data,
            __helper: core::marker::PhantomData,
        })
    }

    /// Check module signature
    ///
    /// See <https://elixir.bootlin.com/linux/v6.6/source/kernel/module/signing.c#L70>
    fn module_sig_check(&self) -> bool {
        // TODO: implement module signature check
        true
    }

    /// Check userspace passed ELF module against our expectations, and cache
    /// useful variables for further processing as we go.
    ///
    /// See <https://elixir.bootlin.com/linux/v6.6/source/kernel/module/main.c#L1669>
    fn elf_validity_cache_copy(&self) -> Result<ModuleOwner<H>> {
        if self.elf.header.e_type != goblin::elf::header::ET_REL {
            log::error!(
                "Invalid ELF type: {}, expected ET_REL",
                self.elf.header.e_type
            );
            return Err(ModuleErr::ENOEXEC);
        }

        elf_check_arch(&self.elf)?;

        // Verify if the section name table index is valid.
        if self.elf.header.e_shstrndx == goblin::elf::section_header::SHN_UNDEF as _
            || self.elf.header.e_shstrndx as usize >= self.elf.section_headers.len()
        {
            log::error!(
                "Invalid ELF section name index: {} || e_shstrndx ({}) >= e_shnum ({})",
                self.elf.header.e_shstrndx,
                self.elf.header.e_shstrndx,
                self.elf.section_headers.len()
            );
            return Err(ModuleErr::ENOEXEC);
        }

        // The section name table must be NUL-terminated, as required
        // by the spec. This makes strcmp and pr_* calls that access
        // strings in the section safe.
        if self.elf.shdr_strtab.len() == 0 {
            log::error!("ELF section name string table is empty");
            return Err(ModuleErr::ENOEXEC);
        }

        // The code assumes that section 0 has a length of zero and
        // an addr of zero, so check for it.
        if self.elf.section_headers[0].sh_type != goblin::elf::section_header::SHT_NULL
            || self.elf.section_headers[0].sh_size != 0
            || self.elf.section_headers[0].sh_addr != 0
        {
            log::error!(
                "ELF Spec violation: section 0 type({})!=SH_NULL or non-zero len or addr",
                self.elf.section_headers[0].sh_type
            );
            return Err(ModuleErr::ENOEXEC);
        }

        let mut num_sym_secs = 0;
        let mut num_mod_secs = 0;
        let mut num_info_secs = 0;
        let mut info_idx = 0;
        let mut mod_idx = 0;
        for (idx, shdr) in self.elf.section_headers.iter().enumerate() {
            let ty = shdr.sh_type;
            match ty {
                goblin::elf::section_header::SHT_NULL | goblin::elf::section_header::SHT_NOBITS => {
                    continue;
                }
                goblin::elf::section_header::SHT_SYMTAB => {
                    if shdr.sh_link == goblin::elf::section_header::SHN_UNDEF
                        || shdr.sh_link as usize >= self.elf.section_headers.len()
                    {
                        log::error!(
                            "Invalid ELF sh_link!=SHN_UNDEF({}) or (sh_link({}) >= hdr->e_shnum({})",
                            shdr.sh_link,
                            shdr.sh_link,
                            self.elf.section_headers.len()
                        );
                        return Err(ModuleErr::ENOEXEC);
                    }
                    num_sym_secs += 1;
                }
                _ => {
                    let shdr_name = self
                        .elf
                        .shdr_strtab
                        .get_at(shdr.sh_name)
                        .ok_or(ModuleErr::ENOEXEC)?;
                    if shdr_name == ".gnu.linkonce.this_module" {
                        num_mod_secs += 1;
                        mod_idx = idx;
                    } else if shdr_name == ".modinfo" {
                        num_info_secs += 1;
                        info_idx = idx;
                    }

                    if shdr.sh_flags == goblin::elf::section_header::SHF_ALLOC as _ {
                        // Check that section names are valid
                        let _name = self
                            .elf
                            .shdr_strtab
                            .get_at(shdr.sh_name)
                            .ok_or(ModuleErr::ENOEXEC)?;
                    }
                }
            }
        }

        let mut owner = None;
        if num_info_secs > 1 {
            log::error!("Only one .modinfo section must exist.");
            return Err(ModuleErr::ENOEXEC);
        } else if num_info_secs == 1 {
            owner = Some(self.pre_read_modinfo(info_idx)?);
            if let Some(ref o) = owner {
                log::error!("Module({:?}) info: {:?}", o.name(), o.module_info);
            }
        }
        let mut owner = owner.ok_or(ModuleErr::ENOEXEC)?;
        let module_name = owner.name().unwrap_or("<unknown>");

        if num_sym_secs != 1 {
            log::error!("{}: module has no symbols (stripped?)", module_name);
            return Err(ModuleErr::ENOEXEC);
        }
        /*
         * The ".gnu.linkonce.this_module" ELF section is special. It is
         * what modpost uses to refer to __this_module and let's use rely
         * on THIS_MODULE to point to &__this_module properly. The kernel's
         * modpost declares it on each modules's *.mod.c file. If the struct
         * module of the kernel changes a full kernel rebuild is required.
         *
         * We have a few expectaions for this special section, the following
         * code validates all this for us:
         *
         *   o Only one section must exist
         *   o We expect the kernel to always have to allocate it: SHF_ALLOC
         *   o The section size must match the kernel's run time's struct module
         *     size
         */
        if num_mod_secs != 1 {
            log::error!(
                "module {}: Only one .gnu.linkonce.this_module section must exist.",
                module_name
            );
            return Err(ModuleErr::ENOEXEC);
        }

        let this_module_shdr = &self.elf.section_headers[mod_idx];
        if this_module_shdr.sh_type == goblin::elf::section_header::SHT_NOBITS {
            log::error!(
                "module {}: .gnu.linkonce.this_module section must have a size set",
                module_name
            );
            return Err(ModuleErr::ENOEXEC);
        }

        if this_module_shdr.sh_flags & goblin::elf::section_header::SHF_ALLOC as u64 == 0 {
            log::error!(
                "module {}: .gnu.linkonce.this_module section size must match the kernel's built struct module size at run time",
                module_name
            );
            return Err(ModuleErr::ENOEXEC);
        }
        // If we didn't load the .modinfo 'name' field earlier, fall back to
        // on-disk struct mod 'name' field.
        if owner.name().is_none() {
            self.pre_read_this_module(mod_idx, &mut owner)?;
        }
        Ok(owner)
    }

    /// Load the module into kernel space
    pub fn load_module(mut self, args: CString) -> Result<ModuleOwner<H>> {
        if !self.module_sig_check() {
            log::error!("Module signature check failed");
            return Err(ModuleErr::ENOEXEC);
        }
        // let arch = offset_of!(kmod::kbindings::module, arch);
        // log::error!("Offset of module.arch: {}", arch);
        let mut owner = self.elf_validity_cache_copy()?;

        self.layout_and_allocate(&mut owner)?;
        let load_info: ModuleLoadInfo = self.simplify_symbols(&owner)?;
        self.apply_relocations(load_info, &owner)?;

        self.post_read_this_module(&mut owner)?;

        self.find_module_sections(&mut owner)?;

        self.complete_formation(&mut owner)?;

        self.parse_args(&mut owner, args)?;

        log::error!("Module({:?}) loaded successfully!", owner.name());
        Ok(owner)
    }

    /// Args looks like "foo=bar,bar2 baz=fuz wiz". Parse them and set module parameters.
    fn parse_args(&self, owner: &mut ModuleOwner<H>, args: CString) -> Result<()> {
        let name = owner.name().unwrap_or("unknown").to_string();
        let kparams = owner.module.params_mut();
        let after_dashes = crate::param::parse_args(&name, args, kparams, i16::MIN, i16::MAX)?;
        if !after_dashes.is_empty() {
            log::warn!(
                "[{}]: parameters '{}' after '--' ignored",
                name,
                after_dashes.to_str().unwrap_or("<invalid UTF-8>")
            );
        }
        Ok(())
    }

    /// Find section by name
    fn find_section(&self, name: &str) -> Result<&SectionHeader> {
        for shdr in &self.elf.section_headers {
            let sec_name = self
                .elf
                .shdr_strtab
                .get_at(shdr.sh_name)
                .ok_or(ModuleErr::ENOEXEC)?;

            if sec_name == name {
                return Ok(shdr);
            }
        }
        log::error!("Section '{}' not found", name);
        Err(ModuleErr::ENOEXEC)
    }

    fn pre_read_modinfo(&self, info_idx: usize) -> Result<ModuleOwner<H>> {
        let modinfo_shdr = &self.elf.section_headers[info_idx];
        let file_offset = modinfo_shdr.sh_offset as usize;
        let size = modinfo_shdr.sh_size as usize;

        let mut modinfo_data = &self.elf_data[file_offset..file_offset + size];
        let mut module_info = ModuleInfo::new();

        log::info!("Reading .modinfo section (size: {:#x})", size);

        // read the modinfo data
        // format is key=value\0key=value\0...
        loop {
            if modinfo_data.is_empty() {
                break;
            }
            let cstr = CStr::from_bytes_until_nul(modinfo_data)
                .map_err(|_| ModuleErr::EINVAL)
                .unwrap();
            let str_slice = cstr.to_str().map_err(|_| ModuleErr::EINVAL)?;
            modinfo_data = &modinfo_data[cstr.to_bytes_with_nul().len()..];

            let mut split = str_slice.splitn(2, '=');
            let key = split.next().ok_or(ModuleErr::EINVAL)?.to_string();
            let value = split.next().ok_or(ModuleErr::EINVAL)?.to_string();
            module_info.add_kv(key, value);
        }

        let name = module_info.get("name").map(|s| s.to_string());

        Ok(ModuleOwner {
            name,
            module_info,
            pages: Vec::new(),
            module: Module::default(),
            _helper: core::marker::PhantomData,
        })
    }

    /// Read the __this_module structure to get module name. If the name of owner
    /// is not set, set it here.
    fn pre_read_this_module(&self, idx: usize, owner: &mut ModuleOwner<H>) -> Result<()> {
        let this_module_shdr = &self.elf.section_headers[idx];
        let size = this_module_shdr.sh_size as usize;
        if size != core::mem::size_of::<Module>() {
            log::error!(
                "Invalid .gnu.linkonce.this_module section size: {}, expected: {}",
                size,
                core::mem::size_of::<Module>()
            );
            return Err(ModuleErr::ENOEXEC);
        }
        let modinfo_data = this_module_shdr.sh_addr as *mut u8;
        let module = unsafe { core::ptr::read(modinfo_data as *const Module) };
        let name = module.name();
        owner.set_name(name);
        Ok(())
    }

    /// After relocating, read the __this_module structure to get init and exit function pointers
    fn post_read_this_module(&mut self, owner: &mut ModuleOwner<H>) -> Result<()> {
        let this_module_shdr = self.find_section(".gnu.linkonce.this_module")?;
        // the data address is the allocated virtual address and it has been relocated
        let modinfo_data = this_module_shdr.sh_addr as *mut u8;
        let module = unsafe { core::ptr::read(modinfo_data as *const Module) };

        let init_fn = module.init_fn();
        let exit_fn = module.exit_fn();

        log::error!(
            "Module init_fn: {:?}, exit_fn: {:?}",
            init_fn.map(|f| f as *const ()),
            exit_fn.map(|f| f as *const ())
        );

        owner.module = module;
        Ok(())
    }

    /// Get number of objects and starting address of a section.
    fn section_objs(&self, name: &str, object_size: usize) -> Result<(usize, *const u8)> {
        let section = self
            .find_section(name)
            .unwrap_or(&self.elf.section_headers[0]); // Section 0 has sh_addr 0 and sh_size 0.
        let num = section.sh_size as usize / object_size;
        let addr = section.sh_addr as *const u8;
        Ok((num, addr))
    }

    fn find_module_sections(&self, owner: &mut ModuleOwner<H>) -> Result<()> {
        let (num_kparams, kparam_addr) =
            self.section_objs("__param", size_of::<kmod::kernel_param>())?;
        let raw_module = owner.module.raw_mod();
        raw_module.kp = kparam_addr as *mut kmod::kernel_param;
        raw_module.num_kp = num_kparams as _;

        // TODO: implement finding other sections:
        // __ksymtab
        // __kcrctab
        // __ksymtab_gpl
        // __kcrctab_gpl
        Ok(())
    }

    /// Finally it's fully formed, ready to start executing.
    fn complete_formation(&self, owner: &mut ModuleOwner<H>) -> Result<()> {
        for page in &mut owner.pages {
            if !page.addr.change_perms(page.perms) {
                log::error!(
                    "Failed to change permissions of section '{}' to {}",
                    page.name,
                    page.perms
                );
                return Err(ModuleErr::EINVAL);
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
                log::debug!("Skipping non-allocatable section '{}'", sec_name);
                continue;
            }

            // Skip sections in the skip list
            if SKIP_SECTIONS.iter().any(|&s| sec_name.starts_with(s)) {
                log::warn!("Skipping section '{}' in skip list", sec_name);
                continue;
            }

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
                return Err(ModuleErr::ENOSPC);
            }

            let raw_addr = addr.as_ptr() as u64;

            // Copy section data from ELF to allocated memory
            // For SHT_NOBITS sections (like .bss), memory is already zeroed by vmalloc
            if shdr.sh_type != goblin::elf::section_header::SHT_NOBITS {
                let section_data = &self.elf_data[file_offset..file_offset + size];
                unsafe {
                    core::ptr::copy_nonoverlapping(section_data.as_ptr(), addr.as_mut_ptr(), size);
                }
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
                "Allocated section '{:>26}' at {:p} [{}] ({:8<#x})",
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
    fn simplify_symbols(&self, owner: &ModuleOwner<H>) -> Result<ModuleLoadInfo> {
        let mut loadinfo = ModuleLoadInfo { syms: Vec::new() };

        // Skip the first symbol (index 0), which is always the undefined symbol
        for (idx, sym) in self.elf.syms.iter().enumerate() {
            if idx == 0 {
                loadinfo.syms.push((sym, "".to_string()));
                // Symbol 0 is always SHN_UNDEF and should be skipped
                continue;
            }

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

            // Create a mutable copy for potential updates
            let mut updated_sym = sym;

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
                        // Update the symbol table entry's st_value to the resolved address
                        updated_sym.st_value = addr as u64;
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
                            return Err(ModuleErr::ENOENT);
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
                    log::warn!("{:?}: please compile with -fno-common", owner.name());
                    return Err(ModuleErr::ENOEXEC);
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
                    // Add section base address to symbol's offset within the section
                    let secbase = self.elf.section_headers[ty as usize].sh_addr;
                    updated_sym.st_value = sym.st_value.wrapping_add(secbase);
                    log::trace!(
                        "  -> Defined symbol '{}' in section {} at address 0x{:016x} (base: 0x{:016x} + offset: 0x{:016x})",
                        sym_name,
                        ty,
                        updated_sym.st_value,
                        secbase,
                        sym.st_value
                    );
                }
            }

            // Push the updated symbol to the list
            loadinfo.syms.push((updated_sym, sym_name));
        }

        Ok(loadinfo)
    }

    /// See <https://elixir.bootlin.com/linux/v6.6/source/kernel/module/main.c#L1438>
    fn apply_relocations(&self, load_info: ModuleLoadInfo, owner: &ModuleOwner<H>) -> Result<()> {
        for shdr in self.elf.section_headers.iter() {
            let infosec = shdr.sh_info;

            let sec_name = self
                .elf
                .shdr_strtab
                .get_at(shdr.sh_name)
                .ok_or(ModuleErr::ENOEXEC)?;

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
                .ok_or(ModuleErr::ENOEXEC)?;

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
                        rela_list,
                        shdr,
                        &self.elf.section_headers,
                        &load_info,
                        owner,
                    )?;
                }
                goblin::elf::header::EM_LOONGARCH => {
                    crate::arch::Loongarch64ArchRelocate::apply_relocate_add(
                        rela_list,
                        shdr,
                        &self.elf.section_headers,
                        &load_info,
                        owner,
                    )?;
                }
                goblin::elf::header::EM_AARCH64 => {
                    crate::arch::Aarch64ArchRelocate::apply_relocate_add(
                        rela_list,
                        shdr,
                        &self.elf.section_headers,
                        &load_info,
                        owner,
                    )?;
                }
                goblin::elf::header::EM_X86_64 => {
                    crate::arch::X86_64ArchRelocate::apply_relocate_add(
                        rela_list,
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

/// Check if the ELF file is for a supported architecture
fn elf_check_arch(elf: &goblin::elf::Elf) -> Result<()> {
    if elf.header.e_machine != goblin::elf::header::EM_AARCH64
        && elf.header.e_machine != goblin::elf::header::EM_X86_64
        && elf.header.e_machine != goblin::elf::header::EM_RISCV
        && elf.header.e_machine != goblin::elf::header::EM_LOONGARCH
    {
        log::error!(
            "Invalid ELF machine: {}, expected AARCH64({}), X86_64({}), RISC-V({}), LOONGARCH({})",
            elf.header.e_machine,
            goblin::elf::header::EM_AARCH64,
            goblin::elf::header::EM_X86_64,
            goblin::elf::header::EM_RISCV,
            goblin::elf::header::EM_LOONGARCH
        );
        return Err(ModuleErr::ENOEXEC);
    }
    Ok(())
}
