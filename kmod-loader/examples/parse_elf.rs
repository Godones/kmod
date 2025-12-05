use kmod_loader::ElfParser;
use std::env;
use std::path::Path;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <ELF file path>", args[0]);
        std::process::exit(1);
    }

    let file_path = Path::new(&args[1]);

    let data = std::fs::read(file_path).expect("Failed to read file");
    let data_box = data.into_boxed_slice();

    match ElfParser::new(&data_box) {
        Ok(parser) => {
            parser.print_elf_header();
            parser.print_sections();
            parser.print_relocations();
        }
        Err(e) => {
            eprintln!("Error: Failed to parse ELF file: {}", e);
            std::process::exit(1);
        }
    }
}
