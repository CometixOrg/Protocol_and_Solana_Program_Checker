//! Common interface for built-in and user supplied programs
use {
    crate::{
        ebpf,
        elf::ElfError,
        vm::{Config, ContextObject, EbpfVm},
    },
    std::collections::{btree_map::Entry, BTreeMap},
};

/// Defines a set of _version of an executable
#[derive(Debug, PartialEq, PartialOrd, Eq, Clone, Copy)]
pub enum Version {
    /// The legacy format
    V0,
    /// SIMD-0166
    V1,
    /// SIMD-0174, SIMD-0173
    V2,
    /// SIMD-0178, SIMD-0179, SIMD-0189
    V3,
    /// Used for future versions
    Reserved,
}

impl Version {
    /// Enable SIMD-0166: dynamic stack frames
    pub fn dynamic_stack_frames(self) -> bool {
        self >= Version::V1
    }

    /// Enable SIMD-0174: arithmetics improvements
    pub fn enable_pqr(self) -> bool {
        self >= Version::V2
    }
    /// ... SIMD-0174
    pub fn explicit_sign_extension_of_results(self) -> bool {
        self >= Version::V2
    }
    /// ... SIMD-0174
    pub fn swap_sub_reg_imm_operands(self) -> bool {
        self >= Version::V2
    }
    /// ... SIMD-0174
    pub fn disable_neg(self) -> bool {
        self >= Version::V2
    }

    /// Enable SIMD-0173: instruction encoding improvements
    pub fn callx_uses_src_reg(self) -> bool {
        self >= Version::V2
    }
    /// ... SIMD-0173
    pub fn disable_lddw(self) -> bool {
        self >= Version::V2
    }
    /// ... SIMD-0173
    pub fn disable_le(self) -> bool {
        self >= Version::V2
    }
    /// ... SIMD-0173
    pub fn move_memory_instruction_classes(self) -> bool {
        self >= Version::V2
    }

    /// Enable SIMD-0178:  Static Syscalls
    /// Enable SIMD-0179:  stricter verification constraints
    pub fn static_syscalls(self) -> bool {
        self >= Version::V3
    }
    /// Enable SIMD-0189:  stricter ELF headers
    pub fn enable_stricter_elf_headers(self) -> bool {
        self >= Version::V3
    }
    /// ... SIMD-0189
    pub fn enable_lower_bytecode_vaddr(self) -> bool {
        self >= Version::V3
    }

    /// Ensure that rodata sections don't exceed their maximum allowed size and
    /// overlap with the stack
    pub fn reject_rodata_stack_overlap(self) -> bool {
        self != Version::V0
    }

    /// Allow sh_addr != sh_offset in elf sections.
    pub fn enable_elf_vaddr(self) -> bool {
        self != Version::V0
    }

    /// Calculate the target program counter for a CALL_IMM instruction depending on
    /// the  version.
    pub fn calculate_call_imm_target_pc(self, pc: usize, imm: i64) -> u32 {
        if self.static_syscalls() {
            (pc as i64).saturating_add(imm).saturating_add(1) as u32
        } else {
            imm as u32
        }
    }
}
