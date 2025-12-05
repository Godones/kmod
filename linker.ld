SECTIONS
{
    /* 模块加载地址 - 在实际加载时会被重定位 */
    . = 0x00000000;
    
    /* 模块头信息 */
    .modheader : ALIGN(0x8) {
        /* 魔数: "MODU" */
        LONG(0x4D4F4455);
        /* 模块格式版本 */
        SHORT(1);
        /* 标志位 */
        SHORT(0);
        /* 模块总大小（在链接后填充） */
        LONG(SIZEOF(.modheader) + SIZEOF(.text) + SIZEOF(.rodata) + 
            SIZEOF(.data) + SIZEOF(.bss));
        /* 模块名称偏移 */
        LONG(module_name - .);
        /* 模块版本偏移 */
        LONG(module_version - .);
    }
    
    .text : ALIGN(0x1000) {
        *(.text .text.*)
        *(.text.init)
        *(.text.exit)
    }

    .rodata : ALIGN(0x1000) {
        *(.rodata .rodata.*)
        /* 模块信息段 */
        . = ALIGN(8);
        module_name = .;
        *(.modinfo)
        module_version = .;
    }
    
    .data : ALIGN(0x1000) {
        *(.data .data.*)
    }
    
    .bss : ALIGN(0x1000) {
        *(.bss .bss.*)
        *(COMMON)
    }
      
    /* 丢弃不需要的节区 */
    /DISCARD/ : {
        *(.comment)
        *(.note.GNU-stack)
        *(.gnu.version)
        *(.eh_frame)
        *(.eh_frame_hdr)
    }
}

/* 定义入口符号（可选） */
/* PROVIDE(_start = hello_init); */