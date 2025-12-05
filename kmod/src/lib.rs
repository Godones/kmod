#![no_std]
#![feature(linkage)]

use core::ptr;

// 模块元数据结构 - 与C兼容
#[repr(C)]
pub struct ModuleInfo {
    pub magic: u32,                              // 魔数 "MODU"
    pub name: [u8; 64],                          // 模块名称
    pub version: [u8; 32],                       // 版本号
    pub init_fn: Option<extern "C" fn() -> i32>, // 初始化函数
    pub exit_fn: Option<extern "C" fn()>,        // 清理函数
    pub size: usize,                             // 模块大小
}

pub const MODULE_MAGIC: u32 = 0x4D4F4455; // "MODU"

// 模块注册表
pub static mut MODULE_REGISTRY: [*const ModuleInfo; 256] = [ptr::null(); 256];
pub static mut MODULE_COUNT: usize = 0;

// 简化的模块加载器
pub struct ModuleLoader;

impl ModuleLoader {
    /// 加载模块到内核
    pub unsafe fn load_module(
        module_data: &[u8],
        module_size: usize,
    ) -> Result<&'static ModuleInfo, &'static str> {
        // 1. 验证模块基本格式
        if module_size < core::mem::size_of::<ModuleInfo>() {
            return Err("Module too small");
        }

        // 2. 验证魔数
        let magic_ptr = module_data.as_ptr() as *const u32;
        if ptr::read_volatile(magic_ptr) != MODULE_MAGIC {
            return Err("Invalid module magic");
        }

        // 3. 将模块数据转换为ModuleInfo引用
        let module_info = &*(module_data.as_ptr() as *const ModuleInfo);

        // 4. 注册模块
        Self::register_module(module_info)?;

        Ok(module_info)
    }

    unsafe fn register_module(module: &'static ModuleInfo) -> Result<(), &'static str> {
        if MODULE_COUNT >= MODULE_REGISTRY.len() {
            return Err("Module registry full");
        }

        MODULE_REGISTRY[MODULE_COUNT] = module;
        MODULE_COUNT += 1;

        Ok(())
    }

    /// 初始化所有已加载模块
    pub unsafe fn initialize_modules() -> Result<(), &'static str> {
        for i in 0..MODULE_COUNT {
            let module = &*MODULE_REGISTRY[i];
            if let Some(init_fn) = module.init_fn {
                let result = init_fn();
                if result != 0 {
                    return Err("Module initialization failed");
                }
            }
        }
        Ok(())
    }
}

// 模块信息宏
#[macro_export]
macro_rules! declare_module {
    ($name:expr, $version:expr, $init:expr, $exit:expr) => {
        #[used]
        #[link_section = ".modinfo"]
        pub static MODULE_INFO: $crate::ModuleInfo = $crate::ModuleInfo {
            magic: $crate::MODULE_MAGIC,
            name: $crate::str_to_array64($name),
            version: $crate::str_to_array32($version),
            init_fn: Some($init),
            exit_fn: Some($exit),
            size: core::mem::size_of::<$crate::ModuleInfo>(),
        };
    };
}

pub const fn str_to_array64(s: &str) -> [u8; 64] {
    let mut array = [0u8; 64];
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() && i < 63 {
        array[i] = bytes[i];
        i += 1;
    }
    array
}

pub const fn str_to_array32(s: &str) -> [u8; 32] {
    let mut array = [0u8; 32];
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() && i < 31 {
        array[i] = bytes[i];
        i += 1;
    }
    array
}

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
