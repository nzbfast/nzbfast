use super::{Error, Result};

const MEMORY_SIZE: usize = 0x40000;
const MEMORY_MASK: u32 = 0x3ffff;
const GLOBAL_BASE: usize = 0x3c000;
const SYSTEM_GLOBAL_SIZE: usize = 64;
const MAX_USER_GLOBAL: usize = 0x2000 - SYSTEM_GLOBAL_SIZE;
const MAX_STATIC_DATA: usize = MEMORY_SIZE - GLOBAL_BASE;
const MAX_INSTRUCTIONS: usize = 25_000_000;
const FLAG_C: u32 = 1;
const FLAG_Z: u32 = 2;
const FLAG_S: u32 = 0x8000_0000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    pub static_data: Vec<u8>,
    pub instructions: Vec<Instruction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    pub opcode: Opcode,
    pub byte_mode: bool,
    pub operands: Vec<Operand>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    Mov = 0,
    Cmp = 1,
    Add = 2,
    Sub = 3,
    Jz = 4,
    Jnz = 5,
    Inc = 6,
    Dec = 7,
    Jmp = 8,
    Xor = 9,
    And = 10,
    Or = 11,
    Test = 12,
    Js = 13,
    Jns = 14,
    Jb = 15,
    Jbe = 16,
    Ja = 17,
    Jae = 18,
    Push = 19,
    Pop = 20,
    Call = 21,
    Ret = 22,
    Not = 23,
    Shl = 24,
    Shr = 25,
    Sar = 26,
    Neg = 27,
    Pusha = 28,
    Popa = 29,
    Pushf = 30,
    Popf = 31,
    Movzx = 32,
    Movsx = 33,
    Xchg = 34,
    Mul = 35,
    Div = 36,
    Adc = 37,
    Sbb = 38,
    Print = 39,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operand {
    Register(u8),
    Immediate(u32),
    RegisterIndirect(u8),
    Indexed { register: u8, base: u32 },
    Absolute(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation<'a> {
    pub input: &'a [u8],
    pub regs: [u32; 7],
    pub global_data: &'a [u8],
    pub file_offset: u64,
    pub exec_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionResult {
    pub output: Vec<u8>,
    pub globals: Vec<u8>,
    pub regs: [u32; 8],
}

impl Program {
    pub fn parse(blob: &[u8]) -> Result<Self> {
        if blob.is_empty() {
            return Err(Error::InvalidData("RARVM program blob is empty"));
        }
        if blob.iter().fold(0u8, |acc, &byte| acc ^ byte) != 0 {
            return Err(Error::InvalidData("RARVM program checksum mismatch"));
        }

        let mut bits = BitReader::new(&blob[1..]);
        let mut static_data = Vec::new();
        if bits.read_bit()? != 0 {
            let size = bits
                .read_vm_number()?
                .checked_add(1)
                .ok_or(Error::InvalidData("RARVM static data size overflows"))?
                as usize;
            if size > MAX_STATIC_DATA {
                return Err(Error::InvalidData("RARVM static data is too large"));
            }
            for _ in 0..size {
                static_data.push(bits.read_bits(8)? as u8);
            }
        }

        let mut instructions = Vec::new();
        while bits.remaining_bits() >= 8 {
            match parse_instruction(&mut bits, instructions.len()) {
                Ok(instruction) => instructions.push(instruction),
                Err(Error::NeedMoreInput) => break,
                Err(error) => return Err(error),
            }
        }

        if instructions
            .last()
            .is_none_or(|instruction| !instruction.opcode.is_unconditional_control_transfer())
        {
            instructions.push(Instruction {
                opcode: Opcode::Ret,
                byte_mode: false,
                operands: Vec::new(),
            });
        }

        Ok(Self {
            static_data,
            instructions,
        })
    }

    pub fn execute(&self, invocation: Invocation<'_>) -> Result<ExecutionResult> {
        let mut vm = Vm::new(self, invocation)?;
        vm.run(self)
    }
}

impl Opcode {
    fn from_u8(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Mov),
            1 => Ok(Self::Cmp),
            2 => Ok(Self::Add),
            3 => Ok(Self::Sub),
            4 => Ok(Self::Jz),
            5 => Ok(Self::Jnz),
            6 => Ok(Self::Inc),
            7 => Ok(Self::Dec),
            8 => Ok(Self::Jmp),
            9 => Ok(Self::Xor),
            10 => Ok(Self::And),
            11 => Ok(Self::Or),
            12 => Ok(Self::Test),
            13 => Ok(Self::Js),
            14 => Ok(Self::Jns),
            15 => Ok(Self::Jb),
            16 => Ok(Self::Jbe),
            17 => Ok(Self::Ja),
            18 => Ok(Self::Jae),
            19 => Ok(Self::Push),
            20 => Ok(Self::Pop),
            21 => Ok(Self::Call),
            22 => Ok(Self::Ret),
            23 => Ok(Self::Not),
            24 => Ok(Self::Shl),
            25 => Ok(Self::Shr),
            26 => Ok(Self::Sar),
            27 => Ok(Self::Neg),
            28 => Ok(Self::Pusha),
            29 => Ok(Self::Popa),
            30 => Ok(Self::Pushf),
            31 => Ok(Self::Popf),
            32 => Ok(Self::Movzx),
            33 => Ok(Self::Movsx),
            34 => Ok(Self::Xchg),
            35 => Ok(Self::Mul),
            36 => Ok(Self::Div),
            37 => Ok(Self::Adc),
            38 => Ok(Self::Sbb),
            39 => Ok(Self::Print),
            _ => Err(Error::InvalidData("RARVM opcode is invalid")),
        }
    }

    fn operand_count(self) -> usize {
        match self {
            Self::Ret | Self::Pusha | Self::Popa | Self::Pushf | Self::Popf | Self::Print => 0,
            Self::Jz
            | Self::Jnz
            | Self::Inc
            | Self::Dec
            | Self::Jmp
            | Self::Js
            | Self::Jns
            | Self::Jb
            | Self::Jbe
            | Self::Ja
            | Self::Jae
            | Self::Push
            | Self::Pop
            | Self::Call
            | Self::Not
            | Self::Neg => 1,
            Self::Mov
            | Self::Cmp
            | Self::Add
            | Self::Sub
            | Self::Xor
            | Self::And
            | Self::Or
            | Self::Test
            | Self::Shl
            | Self::Shr
            | Self::Sar
            | Self::Movzx
            | Self::Movsx
            | Self::Xchg
            | Self::Mul
            | Self::Div
            | Self::Adc
            | Self::Sbb => 2,
        }
    }

    fn supports_byte_mode(self) -> bool {
        matches!(
            self,
            Self::Mov
                | Self::Cmp
                | Self::Add
                | Self::Sub
                | Self::Inc
                | Self::Dec
                | Self::Xor
                | Self::And
                | Self::Or
                | Self::Test
                | Self::Not
                | Self::Shl
                | Self::Shr
                | Self::Sar
                | Self::Neg
                | Self::Xchg
                | Self::Mul
                | Self::Div
                | Self::Adc
                | Self::Sbb
        )
    }

    fn is_jump_or_call(self) -> bool {
        matches!(
            self,
            Self::Jz
                | Self::Jnz
                | Self::Jmp
                | Self::Js
                | Self::Jns
                | Self::Jb
                | Self::Jbe
                | Self::Ja
                | Self::Jae
                | Self::Call
        )
    }

    fn is_unconditional_control_transfer(self) -> bool {
        matches!(self, Self::Jmp | Self::Ret)
    }
}

fn parse_instruction(bits: &mut BitReader<'_>, instruction_index: usize) -> Result<Instruction> {
    let opcode = if bits.read_bit()? == 0 {
        Opcode::from_u8(bits.read_bits(3)? as u8)?
    } else {
        Opcode::from_u8(bits.read_bits(5)? as u8 + 8)?
    };
    let byte_mode = opcode.supports_byte_mode() && bits.read_bit()? != 0;
    let mut operands = Vec::with_capacity(opcode.operand_count());
    for operand_index in 0..opcode.operand_count() {
        let mut operand = parse_operand(bits, byte_mode)?;
        if operand_index == 0 && opcode.is_jump_or_call() {
            if let Operand::Immediate(value) = operand {
                operand = Operand::Immediate(remap_jump_target(value, instruction_index));
            }
        }
        operands.push(operand);
    }
    Ok(Instruction {
        opcode,
        byte_mode,
        operands,
    })
}

fn parse_operand(bits: &mut BitReader<'_>, byte_mode: bool) -> Result<Operand> {
    if bits.read_bit()? != 0 {
        return Ok(Operand::Register(bits.read_bits(3)? as u8));
    }
    if bits.read_bit()? == 0 {
        return if byte_mode {
            Ok(Operand::Immediate(bits.read_bits(8)?))
        } else {
            Ok(Operand::Immediate(bits.read_vm_number()?))
        };
    }
    if bits.read_bit()? == 0 {
        return Ok(Operand::RegisterIndirect(bits.read_bits(3)? as u8));
    }
    if bits.read_bit()? == 0 {
        Ok(Operand::Indexed {
            register: bits.read_bits(3)? as u8,
            base: bits.read_vm_number()?,
        })
    } else {
        Ok(Operand::Absolute(bits.read_vm_number()?))
    }
}

fn remap_jump_target(value: u32, instruction_index: usize) -> u32 {
    if value >= 256 {
        return value - 256;
    }

    let mut distance = value as i64;
    if distance >= 136 {
        distance -= 264;
    } else if distance >= 16 {
        distance -= 8;
    } else if distance >= 8 {
        distance -= 16;
    }
    (instruction_index as i64).wrapping_add(distance) as u32
}

struct Vm {
    memory: Vec<u8>,
    regs: [u32; 8],
    flags: u32,
}

impl Vm {
    fn new(program: &Program, invocation: Invocation<'_>) -> Result<Self> {
        if invocation.input.len() > GLOBAL_BASE {
            return Err(Error::InvalidData("RARVM filter input is too large"));
        }

        let mut memory = vec![0u8; MEMORY_SIZE];
        memory[..invocation.input.len()].copy_from_slice(invocation.input);
        let global_len = invocation.global_data.len().min(0x2000);
        memory[GLOBAL_BASE..GLOBAL_BASE + global_len]
            .copy_from_slice(&invocation.global_data[..global_len]);
        // Static data follows the fixed system globals even when the caller
        // passes fewer than SYSTEM_GLOBAL_SIZE bytes (a program's first run
        // has none): placed at GLOBAL_BASE it would be overwritten by the
        // length and file-offset globals below, and a program that indexes
        // its table as `[R3 + 64 + i]` (the RAR 3 IA-64 filter) reads zeros.
        let static_start = GLOBAL_BASE + global_len.max(SYSTEM_GLOBAL_SIZE);
        let static_len = program
            .static_data
            .len()
            .min(MEMORY_SIZE.saturating_sub(static_start));
        memory[static_start..static_start + static_len]
            .copy_from_slice(&program.static_data[..static_len]);

        write_u32(
            &mut memory,
            GLOBAL_BASE + 0x1c,
            invocation.input.len() as u32,
        );
        write_u32(&mut memory, GLOBAL_BASE + 0x20, 0);
        write_u32(
            &mut memory,
            GLOBAL_BASE + 0x24,
            invocation.file_offset as u32,
        );
        write_u32(
            &mut memory,
            GLOBAL_BASE + 0x28,
            (invocation.file_offset >> 32) as u32,
        );
        write_u32(&mut memory, GLOBAL_BASE + 0x2c, invocation.exec_count);

        let mut regs = [0u32; 8];
        regs[..7].copy_from_slice(&invocation.regs);
        regs[3] = GLOBAL_BASE as u32;
        regs[4] = invocation.input.len() as u32;
        regs[5] = invocation.exec_count;
        regs[6] = invocation.file_offset as u32;
        regs[7] = MEMORY_SIZE as u32;

        Ok(Self {
            memory,
            regs,
            flags: 0,
        })
    }

    fn run(&mut self, program: &Program) -> Result<ExecutionResult> {
        let mut ip = 0usize;
        let mut terminated = false;
        for _ in 0..MAX_INSTRUCTIONS {
            let Some(instruction) = program.instructions.get(ip) else {
                terminated = true;
                break;
            };
            ip += 1;
            if let Some(next_ip) = self.execute_instruction(instruction, ip)? {
                if next_ip >= program.instructions.len() {
                    terminated = true;
                    break;
                }
                ip = next_ip;
            }
            // A top-level RET is reported by `execute_instruction` as a jump
            // past the end, checked BEFORE it pops. Testing the stack pointer
            // here, after the instruction, also ended the program on every
            // subroutine RET that emptied the stack - so a program that CALLs
            // (the RAR 3 IA-64 filter) stopped at its first return.
        }
        if !terminated {
            return Err(Error::InvalidData("RARVM instruction limit exceeded"));
        }

        let mut output_pos = self.read_u32(GLOBAL_BASE + 0x20) as usize & MEMORY_MASK as usize;
        let mut output_size = self.read_u32(GLOBAL_BASE + 0x1c) as usize & MEMORY_MASK as usize;
        if output_pos
            .checked_add(output_size)
            .is_none_or(|end| end > MEMORY_SIZE)
        {
            output_pos = 0;
            output_size = 0;
        }
        let output = self.memory[output_pos..output_pos + output_size].to_vec();

        let user_global = (self.read_u32(GLOBAL_BASE + 0x30) as usize).min(MAX_USER_GLOBAL);
        let globals =
            self.memory[GLOBAL_BASE..GLOBAL_BASE + SYSTEM_GLOBAL_SIZE + user_global].to_vec();
        Ok(ExecutionResult {
            output,
            globals,
            regs: self.regs,
        })
    }

    fn execute_instruction(
        &mut self,
        instruction: &Instruction,
        ip: usize,
    ) -> Result<Option<usize>> {
        let byte_mode = instruction.byte_mode;
        let op = |index| {
            instruction
                .operands
                .get(index)
                .ok_or(Error::InvalidData("RARVM instruction operand is missing"))
        };
        match instruction.opcode {
            Opcode::Mov => {
                let value = self.read_operand(op(1)?, byte_mode);
                self.write_operand(op(0)?, value, byte_mode)?;
            }
            Opcode::Cmp => {
                let a = self.read_operand(op(0)?, byte_mode);
                let b = self.read_operand(op(1)?, byte_mode);
                self.set_sub_flags(a, b, 0, byte_mode);
            }
            Opcode::Add => {
                let a = self.read_operand(op(0)?, byte_mode);
                let b = self.read_operand(op(1)?, byte_mode);
                let result = self.mask_width(a.wrapping_add(b), byte_mode);
                self.write_operand(op(0)?, result, byte_mode)?;
                self.set_add_flags(a, b, 0, result, byte_mode);
            }
            Opcode::Sub => {
                let a = self.read_operand(op(0)?, byte_mode);
                let b = self.read_operand(op(1)?, byte_mode);
                let result = self.mask_width(a.wrapping_sub(b), byte_mode);
                self.write_operand(op(0)?, result, byte_mode)?;
                self.set_sub_flags(a, b, 0, byte_mode);
            }
            Opcode::Jz => return Ok(self.conditional_jump(op(0)?, self.flags & FLAG_Z != 0)),
            Opcode::Jnz => return Ok(self.conditional_jump(op(0)?, self.flags & FLAG_Z == 0)),
            Opcode::Inc => {
                let value = self.read_operand(op(0)?, byte_mode).wrapping_add(1);
                let result = self.mask_width(value, byte_mode);
                self.write_operand(op(0)?, result, byte_mode)?;
                self.set_zs(result, byte_mode);
            }
            Opcode::Dec => {
                let value = self.read_operand(op(0)?, byte_mode).wrapping_sub(1);
                let result = self.mask_width(value, byte_mode);
                self.write_operand(op(0)?, result, byte_mode)?;
                self.set_zs(result, byte_mode);
            }
            Opcode::Jmp => return Ok(Some(self.read_operand(op(0)?, false) as usize)),
            Opcode::Xor | Opcode::And | Opcode::Or | Opcode::Test => {
                let a = self.read_operand(op(0)?, byte_mode);
                let b = self.read_operand(op(1)?, byte_mode);
                let result = match instruction.opcode {
                    Opcode::Xor => a ^ b,
                    Opcode::And | Opcode::Test => a & b,
                    Opcode::Or => a | b,
                    _ => unreachable!(),
                };
                let result = self.mask_width(result, byte_mode);
                if instruction.opcode != Opcode::Test {
                    self.write_operand(op(0)?, result, byte_mode)?;
                }
                self.set_zs(result, byte_mode);
            }
            Opcode::Js => return Ok(self.conditional_jump(op(0)?, self.flags & FLAG_S != 0)),
            Opcode::Jns => return Ok(self.conditional_jump(op(0)?, self.flags & FLAG_S == 0)),
            Opcode::Jb => return Ok(self.conditional_jump(op(0)?, self.flags & FLAG_C != 0)),
            Opcode::Jbe => {
                return Ok(self.conditional_jump(op(0)?, self.flags & (FLAG_C | FLAG_Z) != 0));
            }
            Opcode::Ja => {
                return Ok(self.conditional_jump(op(0)?, self.flags & (FLAG_C | FLAG_Z) == 0));
            }
            Opcode::Jae => return Ok(self.conditional_jump(op(0)?, self.flags & FLAG_C == 0)),
            Opcode::Push => self.push(self.read_operand(op(0)?, false)),
            Opcode::Pop => {
                let value = self.pop();
                self.write_operand(op(0)?, value, false)?;
            }
            Opcode::Call => {
                self.push(ip as u32);
                return Ok(Some(self.read_operand(op(0)?, false) as usize));
            }
            Opcode::Ret => {
                if self.regs[7] >= MEMORY_SIZE as u32 {
                    return Ok(Some(usize::MAX));
                }
                return Ok(Some(self.pop() as usize));
            }
            Opcode::Not => {
                let result = self.mask_width(!self.read_operand(op(0)?, byte_mode), byte_mode);
                self.write_operand(op(0)?, result, byte_mode)?;
            }
            Opcode::Shl | Opcode::Shr | Opcode::Sar => {
                self.shift(
                    instruction.opcode,
                    op(0)?,
                    self.read_operand(op(1)?, byte_mode),
                    byte_mode,
                )?;
            }
            Opcode::Neg => {
                let value = self.read_operand(op(0)?, byte_mode);
                let result = self.mask_width(0u32.wrapping_sub(value), byte_mode);
                self.write_operand(op(0)?, result, byte_mode)?;
                if result == 0 {
                    self.flags = FLAG_Z;
                } else {
                    self.flags = FLAG_C | (result & self.sign_bit(byte_mode));
                }
            }
            Opcode::Pusha => {
                let regs = self.regs;
                for value in regs {
                    self.push(value);
                }
            }
            Opcode::Popa => {
                let mut stack = self.regs[7];
                for index in (0..8).rev() {
                    self.regs[index] = self.read_mem(stack, false);
                    stack = stack.wrapping_add(4);
                }
            }
            Opcode::Pushf => self.push(self.flags),
            Opcode::Popf => self.flags = self.pop(),
            Opcode::Movzx => {
                let value = self.read_operand(op(1)?, true) & 0xff;
                self.write_operand(op(0)?, value, false)?;
            }
            Opcode::Movsx => {
                let value = self.read_operand(op(1)?, true) as u8 as i8 as i32 as u32;
                self.write_operand(op(0)?, value, false)?;
            }
            Opcode::Xchg => {
                let a = self.read_operand(op(0)?, byte_mode);
                let b = self.read_operand(op(1)?, byte_mode);
                self.write_operand(op(0)?, b, byte_mode)?;
                self.write_operand(op(1)?, a, byte_mode)?;
            }
            Opcode::Mul => {
                let result = self
                    .read_operand(op(0)?, byte_mode)
                    .wrapping_mul(self.read_operand(op(1)?, byte_mode));
                self.write_operand(op(0)?, self.mask_width(result, byte_mode), byte_mode)?;
            }
            Opcode::Div => {
                let divisor = self.read_operand(op(1)?, byte_mode);
                if let Some(result) = self.read_operand(op(0)?, byte_mode).checked_div(divisor) {
                    self.write_operand(op(0)?, result, byte_mode)?;
                }
            }
            Opcode::Adc | Opcode::Sbb => {
                let a = self.read_operand(op(0)?, byte_mode);
                let b = self.read_operand(op(1)?, byte_mode);
                let carry = u32::from(self.flags & FLAG_C != 0);
                let result = if instruction.opcode == Opcode::Adc {
                    self.mask_width(a.wrapping_add(b).wrapping_add(carry), byte_mode)
                } else {
                    self.mask_width(a.wrapping_sub(b).wrapping_sub(carry), byte_mode)
                };
                self.write_operand(op(0)?, result, byte_mode)?;
                if instruction.opcode == Opcode::Adc {
                    self.set_add_flags(a, b, carry, result, byte_mode);
                } else {
                    self.set_sub_flags(a, b, carry, byte_mode);
                }
            }
            Opcode::Print => {}
        }
        Ok(None)
    }

    fn conditional_jump(&self, operand: &Operand, condition: bool) -> Option<usize> {
        condition.then_some(self.read_operand(operand, false) as usize)
    }

    fn read_operand(&self, operand: &Operand, byte_mode: bool) -> u32 {
        match *operand {
            Operand::Register(index) => {
                let value = self.regs[index as usize];
                if byte_mode {
                    value & 0xff
                } else {
                    value
                }
            }
            Operand::Immediate(value) => self.mask_width(value, byte_mode),
            Operand::RegisterIndirect(index) => self.read_mem(self.regs[index as usize], byte_mode),
            Operand::Indexed { register, base } => {
                self.read_mem(base.wrapping_add(self.regs[register as usize]), byte_mode)
            }
            Operand::Absolute(address) => self.read_mem(address, byte_mode),
        }
    }

    fn write_operand(&mut self, operand: &Operand, value: u32, byte_mode: bool) -> Result<()> {
        match *operand {
            Operand::Register(index) => {
                let slot = &mut self.regs[index as usize];
                if byte_mode {
                    *slot = (*slot & 0xffff_ff00) | (value & 0xff);
                } else {
                    *slot = value;
                }
            }
            Operand::RegisterIndirect(index) => {
                self.write_mem(self.regs[index as usize], value, byte_mode)
            }
            Operand::Indexed { register, base } => {
                self.write_mem(
                    base.wrapping_add(self.regs[register as usize]),
                    value,
                    byte_mode,
                );
            }
            Operand::Absolute(address) => self.write_mem(address, value, byte_mode),
            Operand::Immediate(_) => {
                return Err(Error::InvalidData("RARVM write to immediate operand"))
            }
        }
        Ok(())
    }

    fn read_mem(&self, address: u32, byte_mode: bool) -> u32 {
        let address = address & MEMORY_MASK;
        if byte_mode {
            u32::from(self.memory[address as usize])
        } else {
            self.read_u32(address as usize)
        }
    }

    fn write_mem(&mut self, address: u32, value: u32, byte_mode: bool) {
        let address = address & MEMORY_MASK;
        if byte_mode {
            self.memory[address as usize] = value as u8;
        } else {
            write_u32(&mut self.memory, address as usize, value);
        }
    }

    fn read_u32(&self, address: usize) -> u32 {
        let address = address as u32;
        u32::from_le_bytes([
            self.memory[(address & MEMORY_MASK) as usize],
            self.memory[(address.wrapping_add(1) & MEMORY_MASK) as usize],
            self.memory[(address.wrapping_add(2) & MEMORY_MASK) as usize],
            self.memory[(address.wrapping_add(3) & MEMORY_MASK) as usize],
        ])
    }

    fn push(&mut self, value: u32) {
        self.regs[7] = self.regs[7].wrapping_sub(4);
        self.write_mem(self.regs[7], value, false);
    }

    fn pop(&mut self) -> u32 {
        let value = self.read_mem(self.regs[7], false);
        self.regs[7] = self.regs[7].wrapping_add(4);
        value
    }

    fn shift(&mut self, opcode: Opcode, dst: &Operand, count: u32, byte_mode: bool) -> Result<()> {
        if count == 0 {
            return Ok(());
        }
        let width = if byte_mode { 8 } else { 32 };
        let count = count.min(width);
        let value = self.read_operand(dst, byte_mode);
        let result = match opcode {
            Opcode::Shl => {
                if count == width {
                    0
                } else {
                    value.wrapping_shl(count)
                }
            }
            Opcode::Shr => {
                if count == width {
                    0
                } else {
                    value.wrapping_shr(count)
                }
            }
            Opcode::Sar => {
                if byte_mode {
                    if count >= 8 {
                        if value & 0x80 != 0 {
                            0xff
                        } else {
                            0
                        }
                    } else {
                        ((value as u8 as i8) >> count) as u8 as u32
                    }
                } else if count >= 32 {
                    if value & 0x8000_0000 != 0 {
                        u32::MAX
                    } else {
                        0
                    }
                } else {
                    ((value as i32) >> count) as u32
                }
            }
            _ => unreachable!(),
        };
        let carry = match opcode {
            Opcode::Shl => value & (1 << (width - count)) != 0,
            Opcode::Shr | Opcode::Sar => value & (1 << (count - 1)) != 0,
            _ => unreachable!(),
        };
        let result = self.mask_width(result, byte_mode);
        self.write_operand(dst, result, byte_mode)?;
        self.set_zsc(result, carry, byte_mode);
        Ok(())
    }

    fn set_add_flags(&mut self, a: u32, b: u32, carry: u32, result: u32, byte_mode: bool) {
        let mask = self.value_mask(byte_mode) as u64;
        let sum = (a as u64 & mask) + (b as u64 & mask) + u64::from(carry);
        self.set_zsc(result, sum > mask, byte_mode);
    }

    fn set_sub_flags(&mut self, a: u32, b: u32, borrow: u32, byte_mode: bool) {
        let mask = self.value_mask(byte_mode) as u64;
        let a = a as u64 & mask;
        let subtrahend = (b as u64 & mask) + u64::from(borrow);
        let result = self.mask_width((a as u32).wrapping_sub(subtrahend as u32), byte_mode);
        self.set_zsc(result, a < subtrahend, byte_mode);
    }

    fn set_zs(&mut self, result: u32, byte_mode: bool) {
        self.flags = if result == 0 {
            FLAG_Z
        } else {
            result & self.sign_bit(byte_mode)
        };
    }

    fn set_zsc(&mut self, result: u32, carry: bool, byte_mode: bool) {
        self.set_zs(result, byte_mode);
        if carry {
            self.flags |= FLAG_C;
        }
    }

    fn mask_width(&self, value: u32, byte_mode: bool) -> u32 {
        value & self.value_mask(byte_mode)
    }

    fn value_mask(&self, byte_mode: bool) -> u32 {
        if byte_mode {
            0xff
        } else {
            u32::MAX
        }
    }

    fn sign_bit(&self, byte_mode: bool) -> u32 {
        if byte_mode {
            0x80
        } else {
            FLAG_S
        }
    }
}

fn write_u32(memory: &mut [u8], address: usize, value: u32) {
    let address = address as u32;
    for (offset, byte) in value.to_le_bytes().into_iter().enumerate() {
        memory[(address.wrapping_add(offset as u32) & MEMORY_MASK) as usize] = byte;
    }
}

#[derive(Debug, Clone)]
struct BitReader<'a> {
    input: &'a [u8],
    bit_pos: usize,
}

impl<'a> BitReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, bit_pos: 0 }
    }

    fn remaining_bits(&self) -> usize {
        self.input.len() * 8 - self.bit_pos
    }

    fn read_bit(&mut self) -> Result<u32> {
        self.read_bits(1)
    }

    fn read_bits(&mut self, count: usize) -> Result<u32> {
        if count > 32 {
            return Err(Error::InvalidData("RARVM bit read is too wide"));
        }
        if self.remaining_bits() < count {
            return Err(Error::NeedMoreInput);
        }
        let mut value = 0;
        for _ in 0..count {
            let byte = self.input[self.bit_pos / 8];
            let bit = (byte >> (7 - (self.bit_pos % 8))) & 1;
            value = (value << 1) | u32::from(bit);
            self.bit_pos += 1;
        }
        Ok(value)
    }

    fn read_vm_number(&mut self) -> Result<u32> {
        match self.read_bits(2)? {
            0 => self.read_bits(4),
            1 => {
                let high = self.read_bits(8)?;
                if high >= 16 {
                    Ok(high)
                } else {
                    Ok(0xffff_ff00 | (high << 4) | self.read_bits(4)?)
                }
            }
            2 => self.read_bits(16),
            3 => self.read_bits(32),
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_xor_checksum() {
        assert_eq!(
            Program::parse(&[0x12, 0x34]),
            Err(Error::InvalidData("RARVM program checksum mismatch"))
        );
    }

    #[test]
    fn parses_static_data_and_appends_implicit_ret() {
        let mut bits = BitWriter::new();
        bits.write_bits(1, 1);
        write_vm_number(&mut bits, 2);
        bits.write_bits(0xaa, 8);
        bits.write_bits(0xbb, 8);
        bits.write_bits(0xcc, 8);
        let program = Program::parse(&with_xor(bits.finish())).unwrap();

        assert_eq!(program.static_data, [0xaa, 0xbb, 0xcc]);
        assert_eq!(
            program.instructions,
            [Instruction {
                opcode: Opcode::Ret,
                byte_mode: false,
                operands: Vec::new(),
            }]
        );
    }

    #[test]
    fn parses_register_immediate_and_memory_operands() {
        let mut bits = BitWriter::new();
        bits.write_bits(0, 1);
        write_opcode(&mut bits, Opcode::Mov);
        bits.write_bits(0, 1);
        write_reg(&mut bits, 2);
        write_number_immediate(&mut bits, 0x1234);
        write_opcode(&mut bits, Opcode::Add);
        bits.write_bits(1, 1);
        write_reg_indirect(&mut bits, 3);
        write_byte_immediate(&mut bits, 0x7f);
        write_opcode(&mut bits, Opcode::Sub);
        bits.write_bits(0, 1);
        write_indexed(&mut bits, 1, 0x44);
        write_absolute(&mut bits, 0x3c000);
        write_opcode(&mut bits, Opcode::Ret);

        let program = Program::parse(&with_xor(bits.finish())).unwrap();
        assert!(program.static_data.is_empty());
        assert_eq!(program.instructions.len(), 4);
        assert_eq!(program.instructions[0].opcode, Opcode::Mov);
        assert!(!program.instructions[0].byte_mode);
        assert_eq!(
            program.instructions[0].operands,
            [Operand::Register(2), Operand::Immediate(0x1234)]
        );
        assert_eq!(program.instructions[1].opcode, Opcode::Add);
        assert!(program.instructions[1].byte_mode);
        assert_eq!(
            program.instructions[1].operands,
            [Operand::RegisterIndirect(3), Operand::Immediate(0x7f)]
        );
        assert_eq!(
            program.instructions[2].operands,
            [
                Operand::Indexed {
                    register: 1,
                    base: 0x44,
                },
                Operand::Absolute(0x3c000),
            ]
        );
        assert_eq!(program.instructions[3].opcode, Opcode::Ret);
    }

    #[test]
    fn remaps_jump_immediates_to_instruction_indices() {
        let mut bits = BitWriter::new();
        bits.write_bits(0, 1);
        write_opcode(&mut bits, Opcode::Print);
        write_opcode(&mut bits, Opcode::Jmp);
        write_number_immediate(&mut bits, 15);

        let program = Program::parse(&with_xor(bits.finish())).unwrap();
        assert_eq!(program.instructions.len(), 2);
        assert_eq!(
            program.instructions[1],
            Instruction {
                opcode: Opcode::Jmp,
                byte_mode: false,
                operands: vec![Operand::Immediate(0)],
            }
        );
    }

    #[test]
    fn executes_arithmetic_and_memory_writes() {
        let program = Program {
            static_data: Vec::new(),
            instructions: vec![
                Instruction {
                    opcode: Opcode::Mov,
                    byte_mode: false,
                    operands: vec![Operand::Register(0), Operand::Immediate(7)],
                },
                Instruction {
                    opcode: Opcode::Add,
                    byte_mode: false,
                    operands: vec![Operand::Register(0), Operand::Immediate(5)],
                },
                Instruction {
                    opcode: Opcode::Mov,
                    byte_mode: true,
                    operands: vec![Operand::Absolute(0), Operand::Register(0)],
                },
                Instruction {
                    opcode: Opcode::Ret,
                    byte_mode: false,
                    operands: Vec::new(),
                },
            ],
        };

        let result = program
            .execute(Invocation {
                input: &[0],
                regs: [0; 7],
                global_data: &[],
                file_offset: 0,
                exec_count: 0,
            })
            .unwrap();

        assert_eq!(result.output, [12]);
        assert_eq!(result.regs[0], 12);
    }

    #[test]
    fn executes_conditional_jump_and_stack_call() {
        let program = Program {
            static_data: Vec::new(),
            instructions: vec![
                Instruction {
                    opcode: Opcode::Mov,
                    byte_mode: false,
                    operands: vec![Operand::Register(0), Operand::Immediate(1)],
                },
                Instruction {
                    opcode: Opcode::Cmp,
                    byte_mode: false,
                    operands: vec![Operand::Register(0), Operand::Immediate(1)],
                },
                Instruction {
                    opcode: Opcode::Jz,
                    byte_mode: false,
                    operands: vec![Operand::Immediate(4)],
                },
                Instruction {
                    opcode: Opcode::Mov,
                    byte_mode: false,
                    operands: vec![Operand::Register(0), Operand::Immediate(99)],
                },
                Instruction {
                    opcode: Opcode::Call,
                    byte_mode: false,
                    operands: vec![Operand::Immediate(6)],
                },
                Instruction {
                    opcode: Opcode::Ret,
                    byte_mode: false,
                    operands: Vec::new(),
                },
                Instruction {
                    opcode: Opcode::Add,
                    byte_mode: false,
                    operands: vec![Operand::Register(0), Operand::Immediate(41)],
                },
                Instruction {
                    opcode: Opcode::Ret,
                    byte_mode: false,
                    operands: Vec::new(),
                },
            ],
        };

        let result = program
            .execute(Invocation {
                input: &[0],
                regs: [0; 7],
                global_data: &[],
                file_offset: 0,
                exec_count: 0,
            })
            .unwrap();

        assert_eq!(result.regs[0], 42);
    }

    #[test]
    fn executes_unconditional_jumps_and_mutating_unary_ops() {
        let result = execute_instructions(vec![
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Register(0), Operand::Immediate(1)],
            ),
            instr(Opcode::Inc, false, vec![Operand::Register(0)]),
            instr(Opcode::Dec, false, vec![Operand::Register(0)]),
            instr(Opcode::Not, false, vec![Operand::Register(0)]),
            instr(Opcode::Neg, false, vec![Operand::Register(0)]),
            instr(Opcode::Jmp, false, vec![Operand::Immediate(7)]),
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Register(0), Operand::Immediate(99)],
            ),
            instr(Opcode::Ret, false, Vec::new()),
        ]);

        assert_eq!(result.regs[0], 2);
    }

    #[test]
    fn executes_logic_ops_and_test_without_writing_destination() {
        let result = execute_instructions(vec![
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Register(0), Operand::Immediate(0b1010)],
            ),
            instr(
                Opcode::Xor,
                false,
                vec![Operand::Register(0), Operand::Immediate(0b1100)],
            ),
            instr(
                Opcode::And,
                false,
                vec![Operand::Register(0), Operand::Immediate(0b0110)],
            ),
            instr(
                Opcode::Or,
                false,
                vec![Operand::Register(0), Operand::Immediate(0b0001)],
            ),
            instr(
                Opcode::Test,
                false,
                vec![Operand::Register(0), Operand::Immediate(0b0100)],
            ),
            instr(Opcode::Jnz, false, vec![Operand::Immediate(7)]),
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Register(0), Operand::Immediate(99)],
            ),
            instr(Opcode::Ret, false, Vec::new()),
        ]);

        assert_eq!(result.regs[0], 0b0111);
    }

    #[test]
    fn executes_unsigned_conditional_jumps() {
        let result = execute_instructions(vec![
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Register(0), Operand::Immediate(0)],
            ),
            instr(
                Opcode::Cmp,
                false,
                vec![Operand::Immediate(1), Operand::Immediate(2)],
            ),
            instr(Opcode::Jb, false, vec![Operand::Immediate(5)]),
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Register(0), Operand::Immediate(99)],
            ),
            instr(Opcode::Ret, false, Vec::new()),
            instr(Opcode::Jbe, false, vec![Operand::Immediate(7)]),
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Register(0), Operand::Immediate(98)],
            ),
            instr(
                Opcode::Cmp,
                false,
                vec![Operand::Immediate(3), Operand::Immediate(2)],
            ),
            instr(Opcode::Ja, false, vec![Operand::Immediate(10)]),
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Register(0), Operand::Immediate(97)],
            ),
            instr(
                Opcode::Cmp,
                false,
                vec![Operand::Immediate(3), Operand::Immediate(2)],
            ),
            instr(Opcode::Jae, false, vec![Operand::Immediate(13)]),
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Register(0), Operand::Immediate(96)],
            ),
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Register(0), Operand::Immediate(42)],
            ),
            instr(Opcode::Ret, false, Vec::new()),
        ]);

        assert_eq!(result.regs[0], 42);
    }

    #[test]
    fn executes_signed_conditional_jumps() {
        let result = execute_instructions(vec![
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Register(0), Operand::Immediate(0)],
            ),
            instr(
                Opcode::Sub,
                false,
                vec![Operand::Register(0), Operand::Immediate(1)],
            ),
            instr(Opcode::Js, false, vec![Operand::Immediate(5)]),
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Register(1), Operand::Immediate(99)],
            ),
            instr(Opcode::Ret, false, Vec::new()),
            instr(
                Opcode::Add,
                false,
                vec![Operand::Register(0), Operand::Immediate(1)],
            ),
            instr(Opcode::Jns, false, vec![Operand::Immediate(8)]),
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Register(1), Operand::Immediate(98)],
            ),
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Register(1), Operand::Immediate(42)],
            ),
            instr(Opcode::Ret, false, Vec::new()),
        ]);

        assert_eq!(result.regs[0], 0);
        assert_eq!(result.regs[1], 42);
    }

    #[test]
    fn executes_stack_register_and_flag_round_trips() {
        let result = execute_instructions(vec![
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Register(0), Operand::Immediate(10)],
            ),
            instr(Opcode::Push, false, vec![Operand::Register(0)]),
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Register(0), Operand::Immediate(0)],
            ),
            instr(Opcode::Pop, false, vec![Operand::Register(1)]),
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Register(0), Operand::Immediate(10)],
            ),
            instr(Opcode::Pusha, false, Vec::new()),
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Register(0), Operand::Immediate(99)],
            ),
            instr(Opcode::Popa, false, Vec::new()),
            instr(
                Opcode::Cmp,
                false,
                vec![Operand::Immediate(1), Operand::Immediate(2)],
            ),
            instr(Opcode::Pushf, false, Vec::new()),
            instr(
                Opcode::Cmp,
                false,
                vec![Operand::Immediate(2), Operand::Immediate(2)],
            ),
            instr(Opcode::Popf, false, Vec::new()),
            instr(Opcode::Jb, false, vec![Operand::Immediate(14)]),
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Register(1), Operand::Immediate(99)],
            ),
            instr(Opcode::Ret, false, Vec::new()),
        ]);

        assert_eq!(result.regs[0], 10);
        assert_eq!(result.regs[1], 10);
    }

    #[test]
    fn executes_shifts_with_byte_and_word_modes() {
        let result = execute_instructions(vec![
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Register(0), Operand::Immediate(0x81)],
            ),
            instr(
                Opcode::Shl,
                false,
                vec![Operand::Register(0), Operand::Immediate(1)],
            ),
            instr(
                Opcode::Shr,
                false,
                vec![Operand::Register(0), Operand::Immediate(2)],
            ),
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Register(1), Operand::Immediate(0x80)],
            ),
            instr(
                Opcode::Sar,
                true,
                vec![Operand::Register(1), Operand::Immediate(1)],
            ),
            instr(Opcode::Ret, false, Vec::new()),
        ]);

        assert_eq!(result.regs[0], 0x40);
        assert_eq!(result.regs[1], 0xc0);
    }

    #[test]
    fn byte_mode_sar_accepts_shift_count_equal_to_width() {
        let result = execute_instructions(vec![
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Register(0), Operand::Immediate(0x80)],
            ),
            instr(
                Opcode::Sar,
                true,
                vec![Operand::Register(0), Operand::Immediate(8)],
            ),
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Register(1), Operand::Immediate(0x7f)],
            ),
            instr(
                Opcode::Sar,
                true,
                vec![Operand::Register(1), Operand::Immediate(8)],
            ),
            instr(Opcode::Ret, false, Vec::new()),
        ]);

        assert_eq!(result.regs[0], 0xff);
        assert_eq!(result.regs[1], 0);
    }

    #[test]
    fn full_width_shl_and_shr_clear_destination() {
        let result = execute_instructions(vec![
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Register(0), Operand::Immediate(0x1234_5678)],
            ),
            instr(
                Opcode::Shl,
                false,
                vec![Operand::Register(0), Operand::Immediate(32)],
            ),
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Register(1), Operand::Immediate(0x8765_4321)],
            ),
            instr(
                Opcode::Shr,
                false,
                vec![Operand::Register(1), Operand::Immediate(32)],
            ),
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Register(2), Operand::Immediate(0xff)],
            ),
            instr(
                Opcode::Shl,
                true,
                vec![Operand::Register(2), Operand::Immediate(8)],
            ),
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Register(3), Operand::Immediate(0xff)],
            ),
            instr(
                Opcode::Shr,
                true,
                vec![Operand::Register(3), Operand::Immediate(8)],
            ),
            instr(Opcode::Ret, false, Vec::new()),
        ]);

        assert_eq!(result.regs[0], 0);
        assert_eq!(result.regs[1], 0);
        assert_eq!(result.regs[2] & 0xff, 0);
        assert_eq!(result.regs[3] & 0xff, 0);
    }

    #[test]
    fn sbb_sets_borrow_flag_when_subtrahend_plus_carry_wraps_byte_width() {
        let result = execute_instructions(vec![
            instr(
                Opcode::Cmp,
                true,
                vec![Operand::Immediate(0), Operand::Immediate(1)],
            ),
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Register(0), Operand::Immediate(0)],
            ),
            instr(
                Opcode::Sbb,
                true,
                vec![Operand::Register(0), Operand::Immediate(0xff)],
            ),
            instr(Opcode::Jb, false, vec![Operand::Immediate(6)]),
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Register(1), Operand::Immediate(0xdead)],
            ),
            instr(Opcode::Ret, false, Vec::new()),
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Register(1), Operand::Immediate(0xbeef)],
            ),
            instr(Opcode::Ret, false, Vec::new()),
        ]);

        assert_eq!(result.regs[0] & 0xff, 0);
        assert_eq!(result.regs[1], 0xbeef);
    }

    #[test]
    fn zero_count_shifts_are_noops() {
        let result = execute_instructions(vec![
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Register(0), Operand::Immediate(0x1234_5678)],
            ),
            instr(
                Opcode::Shl,
                false,
                vec![Operand::Register(0), Operand::Immediate(0)],
            ),
            instr(
                Opcode::Shr,
                false,
                vec![Operand::Register(0), Operand::Immediate(0)],
            ),
            instr(
                Opcode::Sar,
                false,
                vec![Operand::Register(0), Operand::Immediate(0)],
            ),
            instr(Opcode::Ret, false, Vec::new()),
        ]);

        assert_eq!(result.regs[0], 0x1234_5678);
    }

    #[test]
    fn output_range_accepts_exclusive_memory_end() {
        let program = Program {
            static_data: Vec::new(),
            instructions: vec![
                instr(
                    Opcode::Mov,
                    false,
                    vec![
                        Operand::Absolute((GLOBAL_BASE + 0x20) as u32),
                        Operand::Immediate((MEMORY_SIZE - 1) as u32),
                    ],
                ),
                instr(
                    Opcode::Mov,
                    false,
                    vec![
                        Operand::Absolute((GLOBAL_BASE + 0x1c) as u32),
                        Operand::Immediate(1),
                    ],
                ),
                instr(
                    Opcode::Mov,
                    true,
                    vec![
                        Operand::Absolute((MEMORY_SIZE - 1) as u32),
                        Operand::Immediate(0x5a),
                    ],
                ),
                instr(Opcode::Ret, false, Vec::new()),
            ],
        };

        let result = program
            .execute(Invocation {
                input: &[0],
                regs: [0; 7],
                global_data: &[],
                file_offset: 0,
                exec_count: 0,
            })
            .unwrap();

        assert_eq!(result.output, [0x5a]);
    }

    #[test]
    fn executes_extension_exchange_multiply_divide_and_carry_arithmetic() {
        let result = execute_instructions(vec![
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Absolute(0), Operand::Immediate(0x80)],
            ),
            instr(
                Opcode::Movzx,
                false,
                vec![Operand::Register(0), Operand::Absolute(0)],
            ),
            instr(
                Opcode::Movsx,
                false,
                vec![Operand::Register(1), Operand::Absolute(0)],
            ),
            instr(
                Opcode::Xchg,
                false,
                vec![Operand::Register(0), Operand::Register(1)],
            ),
            instr(
                Opcode::Mul,
                false,
                vec![Operand::Register(1), Operand::Immediate(3)],
            ),
            instr(
                Opcode::Div,
                false,
                vec![Operand::Register(1), Operand::Immediate(2)],
            ),
            instr(
                Opcode::Cmp,
                false,
                vec![Operand::Immediate(1), Operand::Immediate(2)],
            ),
            instr(
                Opcode::Adc,
                false,
                vec![Operand::Register(1), Operand::Immediate(1)],
            ),
            instr(
                Opcode::Cmp,
                false,
                vec![Operand::Immediate(1), Operand::Immediate(2)],
            ),
            instr(
                Opcode::Sbb,
                false,
                vec![Operand::Register(1), Operand::Immediate(2)],
            ),
            instr(Opcode::Print, false, Vec::new()),
            instr(Opcode::Ret, false, Vec::new()),
        ]);

        assert_eq!(result.regs[0], 0xffff_ff80);
        assert_eq!(result.regs[1], 0xbf);
    }

    #[test]
    fn preserves_requested_user_globals() {
        let program = Program {
            static_data: b"static".to_vec(),
            instructions: vec![
                Instruction {
                    opcode: Opcode::Mov,
                    byte_mode: false,
                    operands: vec![Operand::Absolute(0x3c030), Operand::Immediate(4)],
                },
                Instruction {
                    opcode: Opcode::Ret,
                    byte_mode: false,
                    operands: Vec::new(),
                },
            ],
        };

        let result = program
            .execute(Invocation {
                input: &[1, 2, 3],
                regs: [0; 7],
                global_data: &[0; 64],
                file_offset: 0x1_0000_0002,
                exec_count: 9,
            })
            .unwrap();

        assert_eq!(result.output, [1, 2, 3]);
        assert_eq!(result.globals.len(), 68);
        assert_eq!(&result.globals[64..], b"stat");
    }

    /// A program's first run passes no globals. Its static data must still
    /// start at `GLOBAL_BASE + SYSTEM_GLOBAL_SIZE`, where the standard IA-64
    /// program reads its table; placed at `GLOBAL_BASE`, the length and
    /// file-offset globals overwrote it and that program ran as the identity.
    #[test]
    fn static_data_follows_system_globals_when_no_globals_are_passed() {
        let program = Program {
            static_data: (1..=0x40).collect(),
            instructions: vec![
                instr(
                    Opcode::Mov,
                    false,
                    vec![Operand::Register(0), Operand::Absolute(0x3c040)],
                ),
                instr(
                    Opcode::Mov,
                    false,
                    vec![Operand::Register(1), Operand::Absolute(0x3c07c)],
                ),
                instr(Opcode::Ret, false, Vec::new()),
            ],
        };

        let result = program
            .execute(Invocation {
                input: &[0; 0x30],
                regs: [0; 7],
                global_data: &[],
                file_offset: 0x1234,
                exec_count: 0,
            })
            .unwrap();

        assert_eq!(result.regs[0], u32::from_le_bytes([1, 2, 3, 4]));
        assert_eq!(result.regs[1], u32::from_le_bytes([0x3d, 0x3e, 0x3f, 0x40]));
        assert_eq!(result.output, [0; 0x30]);
    }

    #[test]
    fn ia64_standard_program_rewrites_a_branch_slot() {
        // Template 0x16 with major opcode 5 in the first slot; the 20-bit
        // immediate becomes absolute by subtracting (file_offset >> 4).
        let program = Program::parse(crate::codec::rar29::RAR3_ITANIUM_FILTER_BYTECODE).unwrap();
        let mut input = vec![0u8; 22];
        input[0] = 0x16;
        input[5] = 0x14;
        let result = program
            .execute(Invocation {
                input: &input,
                regs: [0; 7],
                global_data: &[],
                file_offset: 0x10,
                exec_count: 0,
            })
            .unwrap();

        assert_ne!(result.output, input);
    }

    #[test]
    fn parse_rejects_huge_static_data_size_without_preallocating() {
        let err = Program::parse(&[0xff, 0xff, 0xff, 0xff, 0, 0]).unwrap_err();
        assert_eq!(err, Error::InvalidData("RARVM static data is too large"));
    }

    #[test]
    fn parse_rejects_static_data_larger_than_vm_memory() {
        let mut bits = BitWriter::new();
        bits.write_bits(1, 1);
        write_vm_number(&mut bits, MAX_STATIC_DATA as u32);

        let err = Program::parse(&with_xor(bits.finish())).unwrap_err();
        assert_eq!(err, Error::InvalidData("RARVM static data is too large"));
    }

    fn instr(opcode: Opcode, byte_mode: bool, operands: Vec<Operand>) -> Instruction {
        Instruction {
            opcode,
            byte_mode,
            operands,
        }
    }

    fn execute_instructions(instructions: Vec<Instruction>) -> ExecutionResult {
        Program {
            static_data: Vec::new(),
            instructions,
        }
        .execute(Invocation {
            input: &[0],
            regs: [0; 7],
            global_data: &[],
            file_offset: 0,
            exec_count: 0,
        })
        .unwrap()
    }

    struct BitWriter {
        output: Vec<u8>,
        bit_pos: usize,
    }

    impl BitWriter {
        fn new() -> Self {
            Self {
                output: Vec::new(),
                bit_pos: 0,
            }
        }

        fn write_bits(&mut self, value: u32, count: usize) {
            for i in (0..count).rev() {
                if self.bit_pos.is_multiple_of(8) {
                    self.output.push(0);
                }
                if (value >> i) & 1 != 0 {
                    let idx = self.output.len() - 1;
                    self.output[idx] |= 1 << (7 - (self.bit_pos % 8));
                }
                self.bit_pos += 1;
            }
        }

        fn finish(self) -> Vec<u8> {
            self.output
        }
    }

    fn with_xor(mut payload: Vec<u8>) -> Vec<u8> {
        let checksum = payload.iter().fold(0u8, |acc, &byte| acc ^ byte);
        payload.insert(0, checksum);
        payload
    }

    fn write_opcode(bits: &mut BitWriter, opcode: Opcode) {
        let value = opcode as u8;
        if value <= 7 {
            bits.write_bits(0, 1);
            bits.write_bits(u32::from(value), 3);
        } else {
            bits.write_bits(1, 1);
            bits.write_bits(u32::from(value - 8), 5);
        }
    }

    fn write_reg(bits: &mut BitWriter, reg: u8) {
        bits.write_bits(1, 1);
        bits.write_bits(u32::from(reg), 3);
    }

    fn write_number_immediate(bits: &mut BitWriter, value: u32) {
        bits.write_bits(0, 2);
        write_vm_number(bits, value);
    }

    fn write_byte_immediate(bits: &mut BitWriter, value: u8) {
        bits.write_bits(0, 2);
        bits.write_bits(u32::from(value), 8);
    }

    fn write_reg_indirect(bits: &mut BitWriter, reg: u8) {
        bits.write_bits(0b010, 3);
        bits.write_bits(u32::from(reg), 3);
    }

    fn write_indexed(bits: &mut BitWriter, reg: u8, base: u32) {
        bits.write_bits(0b0110, 4);
        bits.write_bits(u32::from(reg), 3);
        write_vm_number(bits, base);
    }

    fn write_absolute(bits: &mut BitWriter, address: u32) {
        bits.write_bits(0b0111, 4);
        write_vm_number(bits, address);
    }

    fn write_vm_number(bits: &mut BitWriter, value: u32) {
        if value <= 15 {
            bits.write_bits(0, 2);
            bits.write_bits(value, 4);
        } else if value <= 255 {
            bits.write_bits(1, 2);
            bits.write_bits(value, 8);
        } else if value <= 0xffff {
            bits.write_bits(2, 2);
            bits.write_bits(value, 16);
        } else {
            bits.write_bits(3, 2);
            bits.write_bits(value, 32);
        }
    }
}
