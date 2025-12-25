use crate::{BIT, ModuleErr, Result};
use alloc::format;

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy)]
pub enum Aarch64RelocOp {
    RELOC_OP_NONE,
    RELOC_OP_ABS,
    RELOC_OP_PREL,
    RELOC_OP_PAGE,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aarch64InsnMovwImmType {
    AARCH64_INSN_IMM_MOVNZ,
    AARCH64_INSN_IMM_MOVKZ,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aarch64InsnImmType {
    AARCH64_INSN_IMM_ADR,
    AARCH64_INSN_IMM_26,
    AARCH64_INSN_IMM_19,
    AARCH64_INSN_IMM_16,
    AARCH64_INSN_IMM_14,
    AARCH64_INSN_IMM_12,
    AARCH64_INSN_IMM_9,
    AARCH64_INSN_IMM_7,
    AARCH64_INSN_IMM_6,
    AARCH64_INSN_IMM_S,
    AARCH64_INSN_IMM_R,
    AARCH64_INSN_IMM_N,
    AARCH64_INSN_IMM_MAX,
}

// See <https://elixir.bootlin.com/linux/v6.6/source/arch/arm64/include/asm/brk-imm.h#L26>
const FAULT_BRK_IMM: u32 = 0x100;
const AARCH64_BREAK_MON: u32 = 0xd4200000;
// See <https://elixir.bootlin.com/linux/v6.6/source/arch/arm64/include/asm/insn-def.h#L21>
const AARCH64_BREAK_FAULT: u32 = AARCH64_BREAK_MON | (FAULT_BRK_IMM << 5);

const ADR_IMM_HILOSPLIT: u32 = 2;
const ADR_IMM_SIZE: u64 = 2 * 1024 * 1024;
const ADR_IMM_LOMASK: u32 = (1 << ADR_IMM_HILOSPLIT) - 1;
const ADR_IMM_HIMASK: u32 = ((ADR_IMM_SIZE >> ADR_IMM_HILOSPLIT) - 1) as u32;
const ADR_IMM_LOSHIFT: u32 = 29;
const ADR_IMM_HISHIFT: u32 = 5;

/// See https://elixir.bootlin.com/linux/v6.6/source/arch/arm64/lib/insn.c#L112
#[allow(unused_assignments)]
pub fn aarch64_insn_encode_immediate(
    imm_type: Aarch64InsnImmType,
    mut insn: u32,
    mut imm: u64,
) -> u32 {
    if insn == AARCH64_BREAK_FAULT {
        return insn;
    }
    let mut immlo = 0u32;
    let mut immhi = 0u32;
    let mut mask = 0u32;
    let mut shift = 0i32;
    match imm_type {
        Aarch64InsnImmType::AARCH64_INSN_IMM_ADR => {
            shift = 0;
            immlo = (imm as u32 & ADR_IMM_LOMASK) << ADR_IMM_LOSHIFT;
            imm >>= ADR_IMM_HILOSPLIT;
            immhi = (imm as u32 & ADR_IMM_HIMASK) << ADR_IMM_HISHIFT;
            imm = immlo as u64 | immhi as u64;
            mask = (ADR_IMM_LOMASK << ADR_IMM_LOSHIFT) | (ADR_IMM_HIMASK << ADR_IMM_HISHIFT);
        }

        _ => {
            if let Ok((s, m)) = aarch64_get_imm_shift_mask(imm_type) {
                shift = s;
                mask = m;
            } else {
                log::error!("unknown immediate encoding: {:?}", imm_type);
                return AARCH64_BREAK_FAULT;
            }
        }
    }

    // Update the immediate field.
    insn &= !(mask << shift);
    insn |= (imm as u32 & mask) << shift;
    insn
}

fn aarch64_get_imm_shift_mask(imm_type: Aarch64InsnImmType) -> Result<(i32, u32)> {
    match imm_type {
        Aarch64InsnImmType::AARCH64_INSN_IMM_26 => Ok((0, BIT!(26) - 1)),
        Aarch64InsnImmType::AARCH64_INSN_IMM_19 => Ok((5, BIT!(19) - 1)),
        Aarch64InsnImmType::AARCH64_INSN_IMM_16 => Ok((5, BIT!(16) - 1)),
        Aarch64InsnImmType::AARCH64_INSN_IMM_14 => Ok((5, BIT!(14) - 1)),
        Aarch64InsnImmType::AARCH64_INSN_IMM_12 => Ok((10, BIT!(12) - 1)),
        Aarch64InsnImmType::AARCH64_INSN_IMM_9 => Ok((12, BIT!(9) - 1)),
        Aarch64InsnImmType::AARCH64_INSN_IMM_7 => Ok((15, BIT!(7) - 1)),
        Aarch64InsnImmType::AARCH64_INSN_IMM_6 | Aarch64InsnImmType::AARCH64_INSN_IMM_S => {
            Ok((10, BIT!(6) - 1))
        }
        Aarch64InsnImmType::AARCH64_INSN_IMM_R => Ok((16, BIT!(6) - 1)),
        Aarch64InsnImmType::AARCH64_INSN_IMM_N => Ok((22, 1)),
        _ => Err(ModuleErr::RelocationFailed(format!(
            "unknown immediate encoding: {:?}",
            imm_type
        ))),
    }
}
