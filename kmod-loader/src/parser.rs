use goblin::elf::Elf;

use crate::arch::RelocationType;

pub struct ElfParser<'a> {
    elf: Elf<'a>,
    elf_data: &'a [u8],
}

impl<'a> ElfParser<'a> {
    pub fn new(elf_data: &'a [u8]) -> Result<Self, &'static str> {
        let elf = Elf::parse(elf_data).map_err(|_| "Failed to parse ELF data")?;
        if !elf.is_64 {
            return Err("Only 64-bit ELF files are supported");
        }
        Ok(ElfParser { elf, elf_data })
    }

    pub fn print_elf_header(&self) {
        println!("=== ELF header ===");
        println!("ELF Type: {}", self.get_elf_type());
        println!("Machine: {}", self.get_machine_type());
        println!("Version: {}", self.elf.header.e_version);
        println!("Entry point: 0x{:x}", self.elf.header.e_entry);
    }

    pub fn print_sections(&self) {
        println!("=== Sections ===");
        println!(
            "{:<4} {:<25} {:<12} {:<16} {:<16} {:<12} {:<12} {:<12}",
            "Index", "Name", "Type", "Flags", "Address", "Offset", "Size", "Align"
        );
        println!("{}", "-".repeat(110));

        for (idx, section) in self.elf.section_headers.iter().enumerate() {
            let name = self
                .elf
                .shdr_strtab
                .get_at(section.sh_name)
                .unwrap_or("<unknown>");
            let type_str = self.get_section_type(section.sh_type);
            let flags_str = self.get_section_flags(section.sh_flags);

            println!(
                "{:<4} {:<25} {:<12} {:<16} 0x{:<14x} 0x{:<14x} 0x{:<10x} {:<12}",
                idx,
                name,
                type_str,
                flags_str,
                section.sh_addr,
                section.sh_offset,
                section.sh_size,
                section.sh_addralign
            );
        }
        println!();
    }

    pub fn print_relocations(&self) {
        println!("=== Relocations ===");

        let mut has_relocs = false;

        for (_idx, section) in self.elf.section_headers.iter().enumerate() {
            if section.sh_type == goblin::elf::section_header::SHT_REL {
                panic!("REL relocations are not supported in this parser");
            }
            if section.sh_type == goblin::elf::section_header::SHT_RELA {
                has_relocs = true;
                let section_name = self
                    .elf
                    .shdr_strtab
                    .get_at(section.sh_name)
                    .unwrap_or("<unknown>");
                println!("\nSection: {} (Type: RELA)", section_name);
                println!(
                    "{:<16} {:<35} {:<30} {:<16}",
                    "Offset", "Type", "Symbol", "Addend"
                );
                println!("{}", "-".repeat(100));
                self.parse_and_print_rela_relocs(section);
            }
        }

        if !has_relocs {
            println!("No relocation sections found\n");
        } else {
            println!();
        }
    }

    fn parse_and_print_rela_relocs(&self, section: &goblin::elf::section_header::SectionHeader) {
        let offset = section.sh_offset as usize;

        // Size of Elf64_Rela
        debug_assert!(section.sh_entsize == 24);
        let data = self.elf_data;

        let data_buf = &data[offset..offset + section.sh_size as usize];

        let rela_list = unsafe {
            goblin::elf64::reloc::from_raw_rela(data_buf.as_ptr() as _, section.sh_size as usize)
        };

        for rela in rela_list {
            let rel_offset = rela.r_offset;
            let r_info = rela.r_info;
            let addend = rela.r_addend;

            let rel_type = (r_info & 0xffffffff) as u32;
            let sym_idx = (r_info >> 32) as usize;

            let rel_type = RelocationType::try_from(rel_type)
                .map(|ty| format!("{ty:?}"))
                .unwrap_or_else(|_| format!("Unknown({})", rel_type));

            let sym_name = self.get_symbol_name(sym_idx).unwrap_or("unknow");

            println!(
                "0x{:<14x} {:<35} {:<30} 0x{:x}",
                rel_offset, rel_type, sym_name, addend
            );
        }
    }

    fn get_elf_type(&self) -> &'static str {
        match self.elf.header.e_type {
            goblin::elf::header::ET_NONE => "None (ET_NONE)",
            goblin::elf::header::ET_REL => "Relocatable (ET_REL)",
            goblin::elf::header::ET_EXEC => "Executable (ET_EXEC)",
            goblin::elf::header::ET_DYN => "Shared Object (ET_DYN)",
            goblin::elf::header::ET_CORE => "Core (ET_CORE)",
            _ => "Unknown",
        }
    }

    fn get_section_flags(&self, sh_flags: u64) -> String {
        let mut flags = String::new();
        if sh_flags & goblin::elf::section_header::SHF_WRITE as u64 != 0 {
            flags.push('W');
        }
        if sh_flags & goblin::elf::section_header::SHF_ALLOC as u64 != 0 {
            flags.push('A');
        }
        if sh_flags & goblin::elf::section_header::SHF_EXECINSTR as u64 != 0 {
            flags.push('X');
        }
        flags
    }

    fn get_machine_type(&self) -> &'static str {
        match self.elf.header.e_machine {
            goblin::elf::header::EM_386 => "Intel 80386",
            goblin::elf::header::EM_X86_64 => "x86-64",
            goblin::elf::header::EM_ARM => "ARM",
            goblin::elf::header::EM_AARCH64 => "AArch64",
            goblin::elf::header::EM_PPC => "PowerPC",
            _ => "unknown",
        }
    }

    fn get_section_type(&self, sh_type: u32) -> &'static str {
        match sh_type {
            goblin::elf::section_header::SHT_NULL => "NULL",
            goblin::elf::section_header::SHT_PROGBITS => "PROGBITS",
            goblin::elf::section_header::SHT_SYMTAB => "SYMTAB",
            goblin::elf::section_header::SHT_STRTAB => "STRTAB",
            goblin::elf::section_header::SHT_RELA => "RELA",
            goblin::elf::section_header::SHT_HASH => "HASH",
            goblin::elf::section_header::SHT_DYNAMIC => "DYNAMIC",
            goblin::elf::section_header::SHT_NOTE => "NOTE",
            goblin::elf::section_header::SHT_NOBITS => "NOBITS",
            goblin::elf::section_header::SHT_REL => "REL",
            goblin::elf::section_header::SHT_SHLIB => "SHLIB",
            goblin::elf::section_header::SHT_DYNSYM => "DYNSYM",
            _ => "Other",
        }
    }

    fn get_symbol_name(&self, sym_idx: usize) -> Result<&'a str, ()> {
        if sym_idx < self.elf.syms.len() {
            if let Some(sym) = self.elf.syms.get(sym_idx) {
                return Ok(self.elf.strtab.get_at(sym.st_name).unwrap_or("<unknown>"));
            }
        }
        Err(())
    }
}
