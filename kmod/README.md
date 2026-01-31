# kmod

Rust内核模块开发库，提供内核模块和参数的Rust抽象。该crate主要导出其它内核模块相关crate所需的核心结构。

## 功能

- **Module** - 内核模块结构体，包装Linux内核的`module`结构
  - 管理初始化和退出函数
  - 访问模块名称和参数
  - 无需手动编写C绑定

- **KernelParam** - 内核模块参数结构体，包装Linux内核的`kernel_param`结构
  - 访问参数名称和值
  - 管理参数操作和标志
  - 类型安全的参数处理

## 使用示例

```rust
use kmod::{Module, init_fn, exit_fn, module_init};

module_init! {
    name: "my_module",
    version: "0.1.0",
    license: "MIT",
}

#[init_fn]
fn init() -> i32 {
    0
}

#[exit_fn]
fn cleanup() {
}
```
