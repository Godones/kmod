# kmacro

Rust过程宏库，为内核模块开发提供便捷的属性宏。

## 功能

- **`#[init_fn]`** - 标记模块初始化函数，自动生成 `init_module()` 入口并放入 `.text.init` 段
- **`#[exit_fn]`** - 标记模块退出函数，自动生成 `cleanup_module()` 入口并放入 `.text.exit` 段
- **`#[capi_fn]`** - 标记C API函数，应用 `no_mangle` 和 `.c.text` 段
- **`#[cdata`** - 标记C静态数据，应用 `no_mangle`、`used` 和 `.c.data` 段
- **`#[module_init]`** - 声明模块元数据（名称、版本、许可证、描述）

## 使用示例

```rust
use kmacro::{init_fn, exit_fn, module_init};

module_init! {
    name: "my_module",
    version: "0.1.0",
    license: "MIT",
    description: "My kernel module",
}

#[init_fn]
fn init() -> i32 {
    println!("Module loaded");
    0
}

#[exit_fn]
fn cleanup() {
    println!("Module unloaded");
}
```
