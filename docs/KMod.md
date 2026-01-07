# 参考信息

```c
typedef struct {
    Elf64_Word      st_name;
    unsigned char   st_info;
    unsigned char   st_other;
    Elf64_Half      st_shndx;
    Elf64_Addr      st_value;
    Elf64_Xword     st_size;
} Elf64_Sym;
```

- `st_name` - 符号名称在字符串表中的偏移
- `st_info` - 符号类型和绑定信息
  - bind（高4位）：决定链接时的处理方式
    - 0 - STB_LOCAL：局部符号，仅在定义它的文件中可见
    - 1 - STB_GLOBAL：全局符号，在所有文件中可见
    - 2 - STB_WEAK：弱符号，类似于全局符号，但可以被其他符号覆盖
  - type（低4位）：符号类型
    - STT_NOTYPE 未分类
    - STT_OBJECT 数据对象（变量）
    - STT_FUNC 函数
    - STT_SECTION 段符号
    - STT_FILE 文件符号
- `st_other` - 符号的其他信息(通常为0)
  - 低 2 位表示可见性
    - STV_DEFAULT：默认可见性
    - STV_HIDDEN：隐藏符号
    - STV_PROTECTED：受保护符号
  - 内核不会加载 STV_HIDDEN 的符号（它们不导出）
- `st_shndx` - 符号所在的节区索引
  - 特殊值：
    - SHN_UNDEF (0)：未定义符号
    - SHN_ABS (0xfff1)：绝对符号
    - SHN_COMMON (0xfff2)：公共符号,common 块（全局变量未初始化）
- `st_value` - 符号的值（地址）
  - 如果符号在某 section 中（定义符号），则为该符号在 section 中的偏移
  - 如果符号未定义，则为0
  - 如果是绝对符号（SHN_ABS），则为绝对地址
- `st_size` - 符号的大小（以字节为单位）用于调试、统计等目的


## 内核模块参数

内核模块参数允许在加载模块时传递参数，以配置模块的行为。参数可以通过`module_param`宏定义，并指定类型和权限。例如：

```c
#include <linux/module.h>
static int my_param = 0;
module_param(my_param, int, 0644);
```

这段代码定义了一个名为`my_param`的整数参数，默认值为0，并且权限设置为0644（允许读写）。加载模块时，可以通过命令行参数传递参数值，例如：

```sh
insmod my_module.ko my_param=42
```

在内核中，模块参数通过`struct kernel_param`结构体进行管理，该结构体包含参数的名称、类型、权限以及指向参数值的指针。内核模块加载器会解析传递的参数，并将其值设置到相应的变量中。
```rust
#[repr(C)]
#[derive(Copy, Clone)]
pub struct kernel_param {
    pub name: *const core::ffi::c_char,
    pub mod_: *mut module,
    pub ops: *const kernel_param_ops,
    pub perm: u16_,
    pub level: s8,
    pub flags: u8_,
    pub __bindgen_anon_1: kernel_param__bindgen_ty_1,
}
```
我们需要关注ops字段，它指向一个`kernel_param_ops`结构体，该结构体定义了操作函数，用于处理参数的设置和获取。内核为不同类型的参数提供了不同的操作函数，例如整数、字符串等。通过这些操作函数，内核模块可以正确地解析和处理传递的参数值。然而，这些ops并不是直接可见的，在`kernel/params.c`中，这些ops通过宏进行定义和注册，例如：

```c
#define STANDARD_PARAM_DEF(name, type, format, strtolfn)      		\
	int param_set_##name(const char *val, const struct kernel_param *kp) \
	{								\
		return strtolfn(val, 0, (type *)kp->arg);		\
	}								\
	int param_get_##name(char *buffer, const struct kernel_param *kp) \
	{								\
		return scnprintf(buffer, PAGE_SIZE, format "\n",	\
				*((type *)kp->arg));			\
	}								\
	const struct kernel_param_ops param_ops_##name = {			\
		.set = param_set_##name,				\
		.get = param_get_##name,				\
	};								\
	EXPORT_SYMBOL(param_set_##name);				\
	EXPORT_SYMBOL(param_get_##name);				\
	EXPORT_SYMBOL(param_ops_##name)


STANDARD_PARAM_DEF(byte,	unsigned char,		"%hhu",		kstrtou8);
STANDARD_PARAM_DEF(short,	short,			"%hi",		kstrtos16);
STANDARD_PARAM_DEF(ushort,	unsigned short,		"%hu",		kstrtou16);
STANDARD_PARAM_DEF(int,		int,			"%i",		kstrtoint);
STANDARD_PARAM_DEF(uint,	unsigned int,		"%u",		kstrtouint);
STANDARD_PARAM_DEF(long,	long,			"%li",		kstrtol);
STANDARD_PARAM_DEF(ulong,	unsigned long,		"%lu",		kstrtoul);
STANDARD_PARAM_DEF(ullong,	unsigned long long,	"%llu",		kstrtoull);
STANDARD_PARAM_DEF(hexint,	unsigned int,		"%#08x", 	kstrtouint);
```
在Rust实现中，如果要支持内核模块参数的功能，需要在kmod库中添加对这些ops的支持，以便正确处理不同类型的参数。



## LKM 兼容性
尽管LKM（Loadable Kernel Module）使得内核功能变得灵活和可扩展，但是LKM并不是二进制兼容的，甚至在API上也不保证兼容性，这导致不同内核版本之间LKM需要重新编译。为了实现加载LKM的目标，需要确定以下几点：
- 内核版本：不同的内核版本可能有不同的内核API和数据结构定义
- 架构：不同的CPU架构（如x86_64, arm64, riscv64等）可能具有架构相关的定义
- 内核配置选择：内核配置选项（如启用或禁用某些功能）可能影响内核数据结构和API

在确定了这三点后，就可以明确LKM的编译环境，进而在kmod库中添加相关的数据结构定义，从而实现LKM的正确加载和运行。


## 特殊问题
- 在la64架构上，如果没有设置code-model,可能会产生特殊的重定位项。比如其默认使用的medium code-model,会导致生成R_LARCH_CALL36重定位类型,这在内核模块加载时是不被支持的。因此，需要在编译时指定`-C code-model=large`来避免这种情况的发生。
- --gc-sections 链接选项可以移除未使用的节，从而减少模块大小与重定位数量
- linux的lkm 会产生`.__mcount_locs`节, 该节用于支持内核的函数调用跟踪功能。如果模块不使用该功能, 可以通过`ccflags-remove-y := -pg`来避免生成该节。
- linux的lkm 会产生`.__patchable_function_entries`节, 这个功能与`.__mcount_locs`类似, 可以通过`ccflags-remove-y := -fpatchable-function-entry=%`来避免生成该节。
- linux的lkm 会产生`.return_sites`节, 记录了“每个函数里 return 指令的位置”，用于运行时动态打补丁，实现函数返回路径的跟踪与修改。
  
### x86_64架构下的内核模块重定位问题:

根据 [内核文档](https://www.kernel.org/doc/html/v5.8/x86/x86_64/mm.html) 中的描述：x86_64 架构下，内核模块所在的虚拟地址空间范围是 `0xffffffffa0000000` 到 `ffffffffff000000`。 这个地址区间的设置是与其重定位项相关的，对于`R_X86_64_32S`类型的重定位项，内核需要对计算出来的地址进行截断并进行符号扩展，以确保地址的正确性。如果高位不为1，加载器会返回错误。[What do R_X86_64_32S and R_X86_64_64 relocation mean?](https://stackoverflow.com/questions/6093547/what-do-r-x86-64-32s-and-r-x86-64-64-relocation-mean) 该文档有一些示例说明。

目前，Starry的基座Arceos的内核地址空间起始地址位于`0xffff_8000_0020_0000`，其布局与Linux具有较大的差别。Linux内核在编译内核模块时会选用`code-model=kernel`，这与其地址空间布局密切相关。因此无法当前无法直接使用该code-model来编译内核模块。为了解决这个问题，目前的做法是使用`code-model=large`来编译内核模块，这样可以避免生成一些跟地址空间布局相关的重定位项，从而避免上述问题的发生。


### Linux数据结构

可以通过以下命令确定内核某些头文件中的数据结构定义（源码目录下）：
```sh
gcc -E \
  -Iinclude \
  -Iinclude/generated \
  -Iarch/$(ARCH)/include \
  -Iarch/$(ARCH)/include/generated \
  -include include/linux/kconfig.h \
  -include include/generated/autoconf.h \
  target.h > target.i
```

在发行版的内核头文件中，可以使用类似如下的命令来预处理内核模块相关的数据结构定义，例如`module.h`:
```sh
COMMON=/usr/src/linux-headers-6.17.13+deb14-common
ARCH=/usr/src/linux-headers-6.17.13+deb14-riscv64
KDIR=/lib/modules/6.17.13+deb14-riscv64/build

gcc -E \
    -I$COMMON/include \
    -I$COMMON/include/generated \
    -I$COMMON/arch/riscv/include \
    -I$ARCH/arch/riscv/include \
    -I$ARCH/arch/riscv/include/generated \
    -I$ARCH/include \
    -include $COMMON/include/linux/kconfig.h \
    -include $KDIR/include/generated/autoconf.h \
    $COMMON/include/linux/module.h > module.i
```

##  参考链接
- riscv64架构对plt/got的处理: https://elixir.bootlin.com/linux/v6.6/source/arch/riscv/kernel/module-sections.c#L90
- https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html
- https://crab2313.github.io/post/kernel-module/
- https://bbs.kanxue.com/thread-271555-1.htm