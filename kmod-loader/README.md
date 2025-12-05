# kmod-loader - 内核模块加载器

这是一个用Rust实现的Linux内核可加载模块(LKM)加载器，基于`goblin` ELF解析库。

## 当前功能

本阶段实现了ELF文件解析功能：

### 1. **ELF文件头解析** (`print_elf_header`)
   - ELF文件类型（可重定位、可执行、共享对象等）
   - 机器架构信息（x86-64、ARM等）

### 4. **重定位信息解析** (`print_relocations`)
   - 解析REL和RELA类型的重定位项
   - 显示重定位偏移、类型、符号和加数
   - 支持x86-64和ARM架构的重定位类型
   - 自动识别重定位类型名称（如R_X86_64_PC32、R_X86_64_PLT32等）

## 使用方法

### 构建库
```bash
cargo build --package kmod-loader
```

### 编译示例程序
```bash
cargo build --example parse_elf
```

### 运行示例
```bash
# 解析内核模块或ELF文件
cargo run --example parse_elf -- ./target/hello.ko

# 或使用编译好的二进制
./target/debug/examples/parse_elf ./target/hello.ko
```

## 示例输出

程序会输出：

```
=== ELF 文件头 ===
ELF类型: 可重定位 (ET_REL)
机器架构: x86-64
版本: 1
...

=== 重定位信息 ===
段: .rela.text (类型: RELA)
偏移               类型                                  符号                             加数
...
```

## 依赖

- **goblin**: 用于ELF文件解析的高效Rust库

## 库接口

### 主要结构体

`ElfParser` 提供以下方法：

```rust
// 创建解析器实例
pub fn new(path: &Path) -> io::Result<Self>

// 打印各种信息
pub fn print_elf_header(&self)        // 输出ELF文件头
pub fn print_relocations(&self)       // 输出重定位信息
```


