# RKM - Rust Kernel Modules
<!-- [![Crates.io](https://img.shields.io/crates/v/kmod.svg)](https://crates.io/crates/kmod)
[![Docs.rs](https://docs.rs/kmod/badge.svg)](https://docs.rs/kmod) -->
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)


一组工具和库，用于支持在Rust实现的内核中使用Rust编写原生可加载模块(LKM-rust)，同时支持加载Linux的可加载内核模块(LKM)。
 
## 📦 项目组成

本项目包含以下组件：
- **`kapi`**: 提供了Linux内核中常见的字符串和内存操作函数的Rust实现，以便于加载LKM时提供符号
- **`kbindings`**: Linux内核C绑定，提供内核API的Rust FFI接口
- **`kmacro`**: 过程宏库，简化Rust内核模块的开发（提供`#[init_fn]`、`#[exit_fn]`、`module!`等宏）
- **`kmod`**: 核心库，导出其它组件中内核模块开发的抽象和工具
- **`kmod-loader`**: 内核空间加载器，用于动态加载和管理Rust编写的内核模块/LKM
（支持符号解析、重定位等）
- **`modules/hello`**: 示例"Hello World"内核模块，展示使用Rust写内核模块基本用法

## 🚀 快速开始

### 前置要求

- Rust工具链（nightly版本）
- Linux内核头文件
- 交叉编译工具链（如需要目标架构编译）

### 构建示例模块

```bash
# 构建hello模块（默认架构）
make hello

# 为特定架构构建
make TARGET=riscv64gc-unknown-none-elf hello
make TARGET=aarch64-unknown-none hello
make TARGET=x86_64-unknown-none hello
```

### 编写自己的模块

```rust
#![no_std]

use kmod::{exit_fn, init_fn, module};

#[init_fn]
pub fn my_module_init() -> i32 {
    // 模块初始化代码
    0 // 返回0表示成功
}

#[exit_fn]
fn my_module_exit() {
    // 模块清理代码
}

module!(
    name: "my_module",
    license: "GPL",
    description: "My kernel module description",
    version: "0.1.0",
);
```

## 🏗️ 架构支持

支持以下目标架构：

- ✅ x86_64 (`x86_64-unknown-none`)
- ✅ RISC-V 64 (`riscv64gc-unknown-none-elf`)
- ✅ ARM64/AArch64 (`aarch64-unknown-none`, `aarch64-unknown-none-softfloat`)
- ✅ LoongArch64 (`loongarch64-unknown-none`, `loongarch64-unknown-none-softfloat`)

## 📚 主要特性

### kmacro - 宏支持

- `#[init_fn]` - 标记模块初始化函数
- `#[exit_fn]` - 标记模块退出函数
- `module!` - 定义模块元数据（名称、许可证、描述、版本等）
- `#[capi_fn]` - 导出C API兼容函数
- `#[cdata]` - 定义内核模块数据结构

### kmod-loader - 动态加载器

- ELF解析和加载
- 符号解析和重定位
- 支持模块参数传递
- 多架构支持（x86_64、riscv64、aarch64、loongarch64）

## 🔧 构建系统


### 1. Makefile方式

```bash
# 构建所有模块
make all

# 构建特定模块
make MODULE=hello

# 清理构建产物
make clean

# 为特定架构构建
make TARGET=riscv64gc-unknown-none-elf MODULE=hello
```
构建流程：
```
Cargo构建 → 提取.rlib → 链接成可重定位ELF (.ko) → 验证
```

## 📖 文档

- [KMod.md](docs/KMod.md) - 详细的内核模块技术文档（符号表、参数系统等）
- [MAKEFILE_GUIDE.md](MAKEFILE_GUIDE.md) - Makefile构建系统使用指南
- [kmod-loader/README.md](kmod-loader/README.md) - 加载器使用说明

## 🛠️ 开发指南

### 添加新模块

1. 在`modules/`目录下创建新目录
2. 添加`Cargo.toml`和`src/lib.rs`
3. 在根`Cargo.toml`的workspace中添加模块
4. 使用`make MODULE=your_module`构建

### 模块参数示例

```rust
use kmod::{module_param, ModuleParam};

static MY_PARAM: ModuleParam<i32> = ModuleParam::new(42);

module_param!(MY_PARAM, "int", 0o644, "My parameter description");
```

## 🎯 待办事项

- [ ] 完善文档和示例
- [ ] 改进错误处理机制
- [ ] 添加单元测试
- [ ] 支持内核版本兼容性检查
- [ ] 支持模块签名和验证

## 📄 许可证

MIT License

## 🤝 贡献

欢迎提交Issue和Pull Request！


