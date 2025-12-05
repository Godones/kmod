// modules/hello/src/lib.rs
#![no_std]
#![no_main]

use kmod::declare_module;

// 模块初始化函数
#[unsafe(no_mangle)]
pub extern "C" fn hello_init() -> i32 {
    // 这里可以调用内核的日志功能
    // 简化实现，直接返回成功
    0
}

// 模块清理函数
#[unsafe(no_mangle)]
pub extern "C" fn hello_exit() {
    // 清理代码
}

// 声明模块信息
declare_module!(
    "hello",    // 名称
    "1.0.0",    // 版本
    hello_init, // 初始化函数
    hello_exit  // 清理函数
);

// 强制导出符号
#[used]
#[unsafe(no_mangle)]
pub static __module_start: u8 = 0;

#[used]
#[unsafe(no_mangle)]
pub static __module_end: u8 = 0;
