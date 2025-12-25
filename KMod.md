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


## 特殊问题
- 在la64架构上，如果没有设置code-model,可能会产生特殊的重定位项。比如其默认使用的medium code-model,会导致生成R_LARCH_CALL36重定位类型,这在内核模块加载时是不被支持的。因此，需要在编译时指定`-C code-model=large`来避免这种情况的发生。
- --gc-sections 链接选项可以移除未使用的节，从而减少模块大小与重定位数量
  
  
### x86_64架构下的内核模块重定位问题:

根据 [内核文档](https://www.kernel.org/doc/html/v5.8/x86/x86_64/mm.html) 中的描述：x86_64 架构下，内核模块所在的虚拟地址空间范围是 `0xffffffffa0000000` 到 `ffffffffff000000`。 这个地址区间的设置是与其重定位项相关的，对于`R_X86_64_32S`类型的重定位项，内核需要对计算出来的地址进行截断并进行符号扩展，以确保地址的正确性。如果高位不为1，加载器会返回错误。[What do R_X86_64_32S and R_X86_64_64 relocation mean?](https://stackoverflow.com/questions/6093547/what-do-r-x86-64-32s-and-r-x86-64-64-relocation-mean) 该文档有一些示例说明。

目前，Starry的基座Arceos的内核地址空间起始地址位于`0xffff_8000_0020_0000`，其布局与Linux具有较大的差别。Linux内核在编译内核模块时会选用`code-model=kernel`，这与其地址空间布局密切相关。因此无法当前无法直接使用该code-model来编译内核模块。为了解决这个问题，目前的做法是使用`code-model=large`来编译内核模块，这样可以避免生成一些跟地址空间布局相关的重定位项，从而避免上述问题的发生。


##  参考链接
- riscv64架构对plt/got的处理: https://elixir.bootlin.com/linux/v6.6/source/arch/riscv/kernel/module-sections.c#L90
- https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html
- https://crab2313.github.io/post/kernel-module/
- https://bbs.kanxue.com/thread-271555-1.htm