# Makefile - 内核模块构建系统示例

该脚本展示了如何使用Makefile来编译和链接Rust编写的内核可加载模块(RKM)。在你的内核中，你可以根据需要修改和扩展此Makefile以适应你的项目需求。

## 概述

用于编译和链接内核可加载模块(RKM-Rust kernel modules)。和LKM(Linux kernel
modules)的编译和链接方式有所区别。 

## 构建流程

```
编译模块 (cargo build)
    ↓
提取静态库中的对象文件 (直接复用.rlib即可)
    ↓
链接成可重定位ELF (ld -r)
    ↓
验证 .ko 文件
    ↓
清理临时文件
```

## 使用方法

### 基本命令

```bash
# 编译所有模块
make

# 编译特定模块
make hello

# 列出可用的模块
make list-modules

# 显示帮助
make help

# 显示配置
make show-config

# 清理构建产物
make clean

# 完整重建
make rebuild
```

### 高级用法

```bash
# 为不同架构构建
make TARGET=riscv64gc-unknown-none-elf

# 使用自定义模块路径
make MODULE_PATHS=custom_modules

# 指定自定义链接脚本
make LINKER_SCRIPT=custom.ld

# 组合参数
make hello TARGET=riscv64gc-unknown-none-elf LINKER_SCRIPT=custom.ld
```

## 变量说明

| 变量            | 默认值                         | 说明                 |
| --------------- | ------------------------------ | -------------------- |
| `TARGET`        | `x86_64-unknown-none`          | Rust编译目标三元组   |
| `MODULE_PATHS`  | `modules`                      | 模块源代码所在目录   |
| `LINKER_SCRIPT` | `linker.ld`                    | 链接脚本路径         |
| `LD_COMMAND`    | `ld` 或 `riscv64-linux-gnu-ld` | 链接器命令(自动选择) |
| `BUILD_DIR`     | `target`                       | 构建输出目录         |

## 目标(Targets)说明

### 主要目标

- **all** - 编译所有模块(默认)
- **modules** - 编译所有可用模块
- **<module_name>** - 编译指定模块

### 信息目标

- **list-modules** - 列出可用的模块
- **show-config** - 显示当前配置
- **help** - 显示帮助信息

### 清理目标

- **clean** - 删除所有构建产物
- **rebuild** - 完整重建(clean + all)

### 内部目标(不直接调用)

- **process-module-library** - 处理模块库(提取对象文件)
- **create-kernel-module** - 创建.ko文件(链接对象文件)
- **verify-kernel-module** - 验证.ko文件


## 文件结构

生成的.ko文件位置：
```
target/
└── <module_name>/
    └── <module_name>.ko
```

## 常见问题

### Q: 如何只构建特定模块而不构建所有模块？
A: 使用 `make <module_name>`，例如 `make hello`

### Q: 如何修改输出目录？
A: 修改Makefile中的 `BUILD_DIR` 变量，或在命令行中指定：`make BUILD_DIR=custom_output`

### Q: 如何使用自定义的链接脚本？
A: 使用 `LINKER_SCRIPT` 变量：`make LINKER_SCRIPT=my_linker.ld`


## 与ELF解析器集成

生成的.ko文件可以使用kmod-loader中的ELF解析器验证：

```bash
# 解析并显示.ko文件的详细信息
cargo run --example parse_elf -- target/hello/hello.ko
```

## 注意事项
1. **cargo必须安装** - Makefile依赖cargo编译模块
2. **linker.ld文件** - 链接脚本必须存在于项目根目录

