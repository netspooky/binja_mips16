from binaryninja.architecture import Architecture, RegisterInfo, ArchitectureHook
from binaryninja.log import log_info
from binaryninja.function import InstructionInfo, InstructionTextToken, InstructionTextTokenType
from binaryninja.enums import Endianness, BranchType
import struct
from mips16_disasembler import *

class MIPSEL16E(Architecture):
  name = "MIPSEL16"
  endianness = Endianness.LittleEndian
  address_size = 4 # Addrs are 32-bit
  instr_alignment = 2 # 2 byte alignment
  max_instr_length = 4 # EXTEND and JAL opcodes are 4 bytes in length
  # MD00076-2B-MIPS1632-AFP-02.63.pdf Table 3.1
  regs = {"s0": RegisterInfo("s0", 4),
          "s1": RegisterInfo("s1", 4),
          "v0": RegisterInfo("v0", 4),
          "v1": RegisterInfo("v1", 4),
          "a0": RegisterInfo("a0", 4),
          "a1": RegisterInfo("a1", 4),
          "a2": RegisterInfo("a2", 4),
          "a3": RegisterInfo("a3", 4),
          "t8": RegisterInfo("t8", 4), # MIPS16e Condition Code register; implicitly referenced by the BTEQZ, BTNEZ, CMP, CMPI, SLT, SLTU, SLTI, and SLTIU instructions
          "sp": RegisterInfo("sp", 4),
          "ra": RegisterInfo("ra", 4),
          "hi": RegisterInfo("hi", 4), # Contains high-order word of multiply or divide result.
          "lo": RegisterInfo("lo", 4), #Contains low-order word of multiply or divide result.
          "pc": RegisterInfo("pc", 4)
	  }
  reg_lookup = ["s0", "s1", "v0", "v1", "a0", "a1", "a2", "a3", "t8", "sp", "ra", "hi", "lo", "pc"]
  stack_pointer = "sp"


  def sign_extend(self, value, from_nbits=None):
    if from_nbits is None:
      from_nbits = value.nbits
    sign_bit_mask = 1 << (from_nbits-1)
    low_bits_mask = sign_bit_mask - 1
    return (value & low_bits_mask) - (value & sign_bit_mask)

  def disassemble(self, data):
    '''
    * Apply mask to bytes
    * If extended then length +=2
    '''
    insn = {"insn": "",
            "args": "",
            "length": 2
    }
    extend_val = 0
    if (len(data) < 2):
      # Invalid length
      return insn
    #print(f"[Disassemble] {data}, len: {len(data)}")
    unpacked_insn = struct.unpack("<H", data[0:2])[0]
    print(f"[Disassemble] data: {hex(unpacked_insn)}")
    if unpacked_insn == 0x1a00:
      # cheap JAL patch for now
      # TODO fix this properly
      insn['insn'] = "jal"
      insn['length'] += 2
      return insn
    for mips16_insn in mips16_opcodes:
      # index 3 == Mask, index 2 == Match
      if (mips16_insn[3] & unpacked_insn) == mips16_insn[2]:
        insn['insn'] = mips16_insn[0]
        if insn['insn'] == 'extend':
          '''
          Extended OPCODE
          * 4 byte length in total
          * 0-11 bits used to combine with the next instruction
          * an abomination of an opcode lol
          '''
          # Disassemble the next two bytes.
          next_op_code = self.disassemble(data[2::])
          insn['insn'] = next_op_code['insn']
          insn['length'] += 2
          extend_val = unpacked_insn & 0x7FF
        else:
          break
        break
    # Get Operands (todo)
    #print(f"[Disassemble] insn: {insn}")
    return insn

  '''
  Binja Callbacks below
  '''
  def get_instruction_info(self, data, addr):
    result = InstructionInfo()
    insn = self.disassemble(data)
    #print(f"[get_instruction_info] addr: 0x{addr:08X}, insn: {insn}")
    result.length = insn['length']
    return result

  def get_instruction_text(self, data, addr):
    result = []
    #print(f"[get_instruction_text] addr: 0x{addr:08X}")
    insn = self.disassemble(data)
    result.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, insn['insn']))
    return result, insn['length']
  
  def get_instruction_low_level_il(self, data, addr, il):
    #print(f"[get_instruction_low_level_il] addr: 0x{addr:08X}")
    return True


MIPSEL16E().register()