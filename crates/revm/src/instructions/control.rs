use crate::{gas, interpreter::Interpreter, Host, Return, Spec, SpecId::*, U256, opcode};

pub fn jump(interpreter: &mut Interpreter, _host: &mut dyn Host) {
    gas!(interpreter, gas::MID);
    pop!(interpreter, dest);
    let dest = as_usize_or_fail!(interpreter, dest, Return::InvalidJump);
    if is_valid_jump(interpreter, _host, dest) {
        interpreter.instruction_pointer =
            unsafe { interpreter.contract.bytecode.as_ptr().add(dest) };
    } else {
        interpreter.instruction_result = Return::InvalidJump;
    }
}

pub fn jumpi(interpreter: &mut Interpreter, _host: &mut dyn Host) {
    gas!(interpreter, gas::HIGH);
    pop!(interpreter, dest, value);
    if value != U256::ZERO {
        let dest = as_usize_or_fail!(interpreter, dest, Return::InvalidJump);
        if is_valid_jump(interpreter, _host, dest) {
            // TODO: safety comment?
            interpreter.instruction_pointer =
                unsafe { interpreter.contract.bytecode.as_ptr().add(dest) };
        } else {
            interpreter.instruction_result = Return::InvalidJump;
        }
    }
}

fn is_valid_jump(interpreter: &mut Interpreter, _host: &mut dyn Host, dest: usize) -> bool {
    if dest >= interpreter.contract.bytecode.len() {
        println!("dest == {} >= interpreter.contract.bytecode.len() == {}", dest, interpreter.contract.bytecode.len());
        return false;
    }

    // invariant: we have checked every jumpdest prior to pointer.
    let mut pointer = std::cmp::max(
        interpreter.instruction_pointer, interpreter.jumptable.index_pointer);
    let dest_pointer = unsafe { interpreter.contract.bytecode.as_ptr().add(dest) };

    if dest_pointer < pointer {
        return interpreter.jumptable.jumps[dest];
    }

    let jumps = &mut interpreter.jumptable.jumps;

    while pointer <= dest_pointer {
        let opcode = unsafe { *pointer };

        if opcode == opcode::JUMPDEST {
            let index = unsafe {
                pointer.offset_from(interpreter.contract.bytecode.as_ptr()) as usize
            };
            jumps[index] = true;
        }

        let count = match opcode {
            opcode::PUSH1..=opcode::PUSH32 => ((opcode - opcode::PUSH1) + 2) as usize,
            _ => 1,
        };

        pointer = unsafe { pointer.add(count) };
    }

    interpreter.jumptable.index_pointer = pointer;

    return jumps[dest];
}

pub fn jumpdest(interpreter: &mut Interpreter, _host: &mut dyn Host) {
    gas!(interpreter, gas::JUMPDEST);
    let pc = interpreter.program_counter();
    interpreter.jumptable.jumps[pc - 1] = true;
}

pub fn pc(interpreter: &mut Interpreter, _host: &mut dyn Host) {
    gas!(interpreter, gas::BASE);
    push!(interpreter, U256::from(interpreter.program_counter() - 1));
}

pub fn ret(interpreter: &mut Interpreter, _host: &mut dyn Host) {
    // zero gas cost gas!(interp,gas::ZERO);
    pop!(interpreter, start, len);
    let len = as_usize_or_fail!(interpreter, len, Return::OutOfGas);
    if len == 0 {
        interpreter.return_range = usize::MAX..usize::MAX;
    } else {
        let offset = as_usize_or_fail!(interpreter, start, Return::OutOfGas);
        memory_resize!(interpreter, offset, len);
        interpreter.return_range = offset..(offset + len);
    }
    interpreter.instruction_result = Return::Return;
}

pub fn revert<SPEC: Spec>(interpreter: &mut Interpreter, _host: &mut dyn Host) {
    // zero gas cost gas!(interp,gas::ZERO);
    // EIP-140: REVERT instruction
    check!(interpreter, SPEC::enabled(BYZANTIUM));
    pop!(interpreter, start, len);
    let len = as_usize_or_fail!(interpreter, len, Return::OutOfGas);
    if len == 0 {
        interpreter.return_range = usize::MAX..usize::MAX;
    } else {
        let offset = as_usize_or_fail!(interpreter, start, Return::OutOfGas);
        memory_resize!(interpreter, offset, len);
        interpreter.return_range = offset..(offset + len);
    }
    interpreter.instruction_result = Return::Revert;
}
