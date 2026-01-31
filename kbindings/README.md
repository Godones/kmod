# kbindings

该crate提供了Linux内核头文件绑定，以便于正确加载和处理LKM（Linux Kernel Modules）。

## 注意事项

- 该crate通常是架构+内核版本+内核配置特定的。
- 目前该crate仅包含riscv64架构的绑定(v6.17)。