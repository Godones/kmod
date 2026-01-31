# kmod-loader

Rust内核模块动态加载库，支持ELF格式的内核模块加载和执行。

## 功能

- **ELF解析** - 使用goblin库解析ELF格式的模块文件
- **动态加载** - 分配内存、加载段、处理重定位
- **符号解析** - 解决内核符号和模块内部符号引用
- **权限管理** - 为不同段设置读、写、执行权限
- **多架构支持** - 支持x86_64、riscv64、aarch64等架构

## 核心组件

- **ModuleLoader** - 负责解析和加载ELF模块
- **ModuleOwner** - 封装已加载的模块，管理其生命周期
- **KernelModuleHelper** - 用户实现的辅助函数接口（符号解析、内存分配等）
- **SectionMemOps** - 内存段操作接口

## 使用示例

```rust
use kmod_loader::{ModuleLoader, KernelModuleHelper, ModuleOwner};

struct MyHelper;

impl KernelModuleHelper for MyHelper {
    fn vmalloc(size: usize) -> Box<dyn SectionMemOps> {
        // 分配内存
    }
    
    fn resolve_symbol(name: &str) -> Option<usize> {
        // 解析符号地址
    }
}

// 加载模块
let mut loader = ModuleLoader::<MyHelper>::new(elf_data)?;
let mut module = loader.load_module(args)?;

// 调用初始化函数
module.call_init()?;

// 调用退出函数
module.call_exit();
```





