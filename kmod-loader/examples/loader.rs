use kmod_loader::{KernelModuleHelper, ModuleLoader, SectionMemOps, SectionPerm};
use std::env;
use std::ffi::CString;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .format_timestamp(None)
        .init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <ELF file path>", args[0]);
        std::process::exit(1);
    }

    let file_path = Path::new(&args[1]);

    let abs_file_path = if file_path.is_absolute() {
        file_path.to_path_buf()
    } else {
        env::current_dir()?.join(file_path)
    };

    println!("ELF file: {}", abs_file_path.display());

    let data = std::fs::read(file_path).expect("Failed to read file");
    let data_box = data.into_boxed_slice();

    let loader = ModuleLoader::<FakeHelper>::new(&data_box).unwrap();
    let args = CString::new("").unwrap();
    let owner = loader.load_module(args).unwrap();
    drop(owner);
    Ok(())
}

struct FakeHelper;

impl KernelModuleHelper for FakeHelper {
    fn vmalloc(size: usize) -> Box<dyn SectionMemOps> {
        assert!(size % 4096 == 0);
        let mmap = memmap2::MmapOptions::new()
            .len(size)
            .populate()
            .map_anon()
            .expect("Failed to allocate memory");
        Box::new(MmapAsPtr(mmap))
    }

    fn resolve_symbol(_name: &str) -> Option<usize> {
        // println!("Resolving symbol: {}", name);
        Some(0)
    }
}

struct MmapAsPtr(memmap2::MmapMut);

impl SectionMemOps for MmapAsPtr {
    fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr() as *mut u8
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }

    fn change_perms(&mut self, _perms: SectionPerm) -> bool {
        true
    }
}
