#[macro_use]
extern crate json;

extern crate elf;
use std::path::PathBuf;

extern crate cometix_sol;
use cometix_sol::{
    elf::Executable,
    program::{BuiltinProgram, FunctionRegistry, Version},
    static_analysis::Analysis,
    vm::TestContextObject,
};
use std::sync::Arc;
fn to_json(program: &[u8]) -> String {
    let executable = Executable::<TestContextObject>::from_text_bytes(
        program,
        Arc::new(BuiltinProgram::new_mock()),
        Version::V3,
        FunctionRegistry::default(),
    )
    .unwrap();
    let analysis = Analysis::from_executable(&executable).unwrap();

    let mut json_insns = vec![];
    for (pc, insn) in analysis.instructions.iter().enumerate() {
        json_insns.push(object!(
            "opc"  => format!("{:#x}", insn.opc), // => insn.opc,
            "dst"  => format!("{:#x}", insn.dst), // => insn.dst,
            "src"  => format!("{:#x}", insn.src), // => insn.src,
            "off"  => format!("{:#x}", insn.off), // => insn.off,
            "imm"  => format!("{:#x}", insn.imm as i32), // => insn.imm,
            "desc" => analysis.disassemble_instruction(
                insn,
                pc
            ),
        ));
    }
    json::stringify_pretty(
        object!(
        "size"  => json_insns.len(),
        "insns" => json_insns
        ),
        4,
    )
}

// Load a program from an object file, and prints it to standard output as a JSON string.
fn main() {
    // Let's reuse this file from `load_elf` example.
    let filename = "examples/load_elf__block_a_port.o";

    let path = PathBuf::from(filename);
    let file = match elf::File::open_path(path) {
        Ok(f) => f,
        Err(e) => panic!("Error: {:?}", e),
    };

    let text_scn = match file.get_section(".classifier") {
        Some(s) => s,
        None => panic!("Failed to look up .classifier section"),
    };

    let prog = &text_scn.data;

    println!("{}", to_json(prog));
}
