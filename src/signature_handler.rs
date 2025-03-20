#![allow(clippy::arithmetic_side_effects)]

use self::InstructionType::{
    AluBinary, AluUnary, CallImm, CallReg, Endian, JumpConditional, JumpUnconditional, LoadDwImm,
    LoadReg, NoOperand, StoreImm, StoreReg, Syscall,
};
use crate::{
    asm_parser::{
        parse,
        Operand::{Integer, Label, Memory, Register},
        Statement,
    },
    ebpf::{self, Insn},
    elf::Executable,
    program::{BuiltinProgram, FunctionRegistry, SBPFVersion},
    vm::ContextObject,
};
use std::collections::HashMap;

#[cfg(not(feature = "shuttle-test"))]
use std::sync::Arc;

#[cfg(feature = "shuttle-test")]
use shuttle::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq)]
enum InstructionType {
    AluBinary,
    AluUnary,
    LoadDwImm,
    LoadReg,
    StoreImm,
    StoreReg,
    JumpUnconditional,
    JumpConditional,
    Syscall,
    CallImm,
    CallReg,
    Endian(i64),
    NoOperand,
}

fn make_instruction_map(sbpf_version: SBPFVersion) -> HashMap<String, (InstructionType, u8)> {
    let mut result = HashMap::new();

    let alu_binary_ops = [
        ("add", ebpf::BPF_ADD),
        ("sub", ebpf::BPF_SUB),
        ("mul", ebpf::BPF_MUL),
        ("div", ebpf::BPF_DIV),
        ("or", ebpf::BPF_OR),
        ("and", ebpf::BPF_AND),
        ("lsh", ebpf::BPF_LSH),
        ("rsh", ebpf::BPF_RSH),
        ("mod", ebpf::BPF_MOD),
        ("xor", ebpf::BPF_XOR),
        ("mov", ebpf::BPF_MOV),
        ("arsh", ebpf::BPF_ARSH),
        ("hor", ebpf::BPF_HOR),
    ];

    let mem_classes = [
        (
            "ldx",
            LoadReg,
            ebpf::BPF_MEM | ebpf::BPF_LDX,
            ebpf::BPF_ALU32_LOAD | ebpf::BPF_X,
        ),
        (
            "st",
            StoreImm,
            ebpf::BPF_MEM | ebpf::BPF_ST,
            ebpf::BPF_ALU64_STORE | ebpf::BPF_K,
        ),
        (
            "stx",
            StoreReg,
            ebpf::BPF_MEM | ebpf::BPF_STX,
            ebpf::BPF_ALU64_STORE | ebpf::BPF_X,
        ),
    ];
    let mem_sizes = [
        ("b", ebpf::BPF_B, ebpf::BPF_1B),
        ("h", ebpf::BPF_H, ebpf::BPF_2B),
        ("w", ebpf::BPF_W, ebpf::BPF_4B),
        ("dw", ebpf::BPF_DW, ebpf::BPF_8B),
    ];

    let jump_conditions = [
        ("jeq", ebpf::BPF_JEQ),
        ("jgt", ebpf::BPF_JGT),
        ("jge", ebpf::BPF_JGE),
        ("jlt", ebpf::BPF_JLT),
        ("jle", ebpf::BPF_JLE),
        ("jset", ebpf::BPF_JSET),
        ("jne", ebpf::BPF_JNE),
        ("jsgt", ebpf::BPF_JSGT),
        ("jsge", ebpf::BPF_JSGE),
        ("jslt", ebpf::BPF_JSLT),
        ("jsle", ebpf::BPF_JSLE),
    ];

    {
        let mut entry = |name: &str, inst_type: InstructionType, opc: u8| {
            result.insert(name.to_string(), (inst_type, opc))
        };

        if sbpf_version == SBPFVersion::V0 {
            entry("exit", NoOperand, ebpf::EXIT);
            entry("return", NoOperand, ebpf::EXIT);
        } else {
            entry("exit", NoOperand, ebpf::RETURN);
            entry("return", NoOperand, ebpf::RETURN);
        }

        // Miscellaneous.
        entry("ja", JumpUnconditional, ebpf::JA);
        entry(
            "syscall",
            Syscall,
            if sbpf_version == SBPFVersion::V0 {
                ebpf::CALL_IMM
            } else {
                ebpf::SYSCALL
            },
        );
        entry("call", CallImm, ebpf::CALL_IMM);
        entry("callx", CallReg, ebpf::CALL_REG);
        entry("lddw", LoadDwImm, ebpf::LD_DW_IMM);

        // AluUnary.
        entry("neg", AluUnary, ebpf::NEG64);
        entry("neg32", AluUnary, ebpf::NEG32);
        entry("neg64", AluUnary, ebpf::NEG64);

        // AluBinary.
        for &(name, opc) in &alu_binary_ops {
            entry(name, AluBinary, ebpf::BPF_ALU64_STORE | opc);
            entry(&format!("{name}32"), AluBinary, ebpf::BPF_ALU32_LOAD | opc);
            entry(&format!("{name}64"), AluBinary, ebpf::BPF_ALU64_STORE | opc);
        }

        // Product Quotient Remainder.
        entry(
            "lmul",
            AluBinary,
            ebpf::BPF_PQR | ebpf::BPF_B | ebpf::BPF_LMUL,
        );
        entry(
            "lmul64",
            AluBinary,
            ebpf::BPF_PQR | ebpf::BPF_B | ebpf::BPF_LMUL,
        );
        entry("lmul32", AluBinary, ebpf::BPF_PQR | ebpf::BPF_LMUL);
        entry(
            "uhmul",
            AluBinary,
            ebpf::BPF_PQR | ebpf::BPF_B | ebpf::BPF_UHMUL,
        );
        entry(
            "uhmul64",
            AluBinary,
            ebpf::BPF_PQR | ebpf::BPF_B | ebpf::BPF_UHMUL,
        );
        entry(
            "shmul",
            AluBinary,
            ebpf::BPF_PQR | ebpf::BPF_B | ebpf::BPF_SHMUL,
        );
        entry(
            "shmul64",
            AluBinary,
            ebpf::BPF_PQR | ebpf::BPF_B | ebpf::BPF_SHMUL,
        );
        entry(
            "udiv",
            AluBinary,
            ebpf::BPF_PQR | ebpf::BPF_B | ebpf::BPF_UDIV,
        );
        entry(
            "udiv64",
            AluBinary,
            ebpf::BPF_PQR | ebpf::BPF_B | ebpf::BPF_UDIV,
        );
        entry("udiv32", AluBinary, ebpf::BPF_PQR | ebpf::BPF_UDIV);
        entry(
            "urem",
            AluBinary,
            ebpf::BPF_PQR | ebpf::BPF_B | ebpf::BPF_UREM,
        );
        entry(
            "urem64",
            AluBinary,
            ebpf::BPF_PQR | ebpf::BPF_B | ebpf::BPF_UREM,
        );
        entry("urem32", AluBinary, ebpf::BPF_PQR | ebpf::BPF_UREM);
        entry(
            "sdiv",
            AluBinary,
            ebpf::BPF_PQR | ebpf::BPF_B | ebpf::BPF_SDIV,
        );
        entry(
            "sdiv64",
            AluBinary,
            ebpf::BPF_PQR | ebpf::BPF_B | ebpf::BPF_SDIV,
        );
        entry("sdiv32", AluBinary, ebpf::BPF_PQR | ebpf::BPF_SDIV);
        entry(
            "srem",
            AluBinary,
            ebpf::BPF_PQR | ebpf::BPF_B | ebpf::BPF_SREM,
        );
        entry(
            "srem64",
            AluBinary,
            ebpf::BPF_PQR | ebpf::BPF_B | ebpf::BPF_SREM,
        );
        entry("srem32", AluBinary, ebpf::BPF_PQR | ebpf::BPF_SREM);

        // Memory
        if sbpf_version.move_memory_instruction_classes() {
            for &(prefix, class, _, opcode) in &mem_classes {
                for &(suffix, _, size) in &mem_sizes {
                    entry(&format!("{prefix}{suffix}"), class, opcode | size);
                }
            }
        } else {
            for &(prefix, class, opcode, _) in &mem_classes {
                for &(suffix, size, _) in &mem_sizes {
                    entry(&format!("{prefix}{suffix}"), class, opcode | size);
                }
            }
        }

        // JumpConditional.
        for &(name, condition) in &jump_conditions {
            entry(name, JumpConditional, ebpf::BPF_JMP | condition);
        }

        // Endian.
        for &size in &[16, 32, 64] {
            entry(&format!("be{size}"), Endian(size), ebpf::BE);
            entry(&format!("le{size}"), Endian(size), ebpf::LE);
        }
    }

    result
}

fn insn(opc: u8, dst: i64, src: i64, off: i64, imm: i64) -> Result<Insn, String> {
    if !(0..16).contains(&dst) {
        return Err(format!("Invalid destination register {dst}"));
    }
    if !(0..16).contains(&src) {
        return Err(format!("Invalid source register {src}"));
    }
    if off < i16::MIN as i64 || off > i16::MAX as i64 {
        return Err(format!("Invalid offset {off}"));
    }
    if imm < i32::MIN as i64 || imm > i32::MAX as i64 {
        return Err(format!("Invalid immediate {imm}"));
    }
    Ok(Insn {
        ptr: 0,
        opc,
        dst: dst as u8,
        src: src as u8,
        off: off as i16,
        imm,
    })
}

fn resolve_label(
    insn_ptr: usize,
    labels: &HashMap<&str, usize>,
    label: &str,
) -> Result<i64, String> {
    labels
        .get(label)
        .map(|target_pc| *target_pc as i64 - insn_ptr as i64 - 1)
        .ok_or_else(|| format!("Label not found {label}"))
}
