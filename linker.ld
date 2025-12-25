SECTIONS
{
    . = 0x0;

    .modinfo : {
        /* 魔数: "MODU"
        LONG(0x4D4F4455);
        /* 模块格式版本 */
        /* SHORT(1); */
        /* 标志位 */
        /* SHORT(0); */
        /* 模块总大小（在链接后填充） */
        /* LONG(SIZEOF(.modheader) + SIZEOF(.text) + SIZEOF(.rodata) +  */
            /* SIZEOF(.data) + SIZEOF(.bss)); */
        /* 模块名称偏移 */
        /* LONG(module_name - .); */
        /* 模块版本偏移 */
        /* LONG(module_version - .); */
        *(.modinfo)
    }

    .text : {
        *(.text .text.*)
        *(.ltext .ltext.*)
        KEEP(*(.text.init))
        KEEP(*(.text.exit))
    }

    .rodata : {
        *(.rodata .rodata.*)
        *(.lrodata .lrodata.*)
        . = ALIGN(8);
    }

    .data : {
        *(.data .data.*)
    }

    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    }

    /DISCARD/ : {
        *(.comment)
        *(.note.GNU-stack)
        *(.gnu.version)
        *(.eh_frame)
        *(.eh_frame_hdr)
    }
}