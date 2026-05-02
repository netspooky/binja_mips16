import struct
from mips16_disasembler import *

### XXX - Uncomment to use headless for testing 
import rpyc
c = rpyc.connect("127.0.0.1", 18812) 
bn = c.root.binaryninja 
bv = c.root.bv
Architecture = bn.architecture.Architecture
ArchitectureHook = bn.architecture.ArchitectureHook
RegisterInfo = bn.architecture.RegisterInfo
log_info = bn.log.log_info
InstructionInfo = bn.function.InstructionInfo
InstructionTextToken = bn.function.InstructionTextToken
InstructionTextTokenType = bn.function.InstructionTextTokenType
Endianness = bn.enums.Endianness
BranchType = bn.enums.BranchType

### XXX - Uncomment if using as a plugin
#from binaryninja.architecture import Architecture, RegisterInfo, ArchitectureHook
#from binaryninja.log import log_info
#from binaryninja.function import InstructionInfo, InstructionTextToken, InstructionTextTokenType
#from binaryninja.enums import Endianness, BranchType

# XXX - this has to be uncommented in order to make it a real plugin, uncommented for test
#class MIPSEL16E(Architecture):
class MIPSEL16E():
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
    #print(f"[Disassemble] data: {hex(unpacked_insn)}")
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
        #print(f"{hex(unpacked_insn)}")

        # Decode Instructions
        if insn['insn'] == 'b': insn['args'] = m16e_b(unpacked_insn)
        if insn['insn'] == 'beqz': insn['args'] = m16e_beqz(unpacked_insn)
        if insn['insn'] == 'bteqz': insn['args'] = m16e_bteqz(unpacked_insn)
        if insn['insn'] == 'btnez': insn['args'] = m16e_btnez(unpacked_insn)
        if insn['insn'] == 'cmpi': insn['args'] = m16e_cmpi(unpacked_insn)
        if insn['insn'] == 'li': insn['args'] = m16e_li(unpacked_insn)
        if insn['insn'] == 'lw': insn['args'] = m16e_lw(unpacked_insn)
        if insn['insn'] == 'move': insn['args'] = m16e_move(unpacked_insn)
        if insn['insn'] == 'sb': insn['args'] = m16e_sb(unpacked_insn)
        if insn['insn'] == 'slti': insn['args'] = m16e_slti(unpacked_insn)
        if insn['insn'] == 'sw': insn['args'] = m16e_sw(unpacked_insn)

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
    if insn['insn'] == 'restore':
      result.add_branch(BranchType.FunctionReturn)
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

### XXX - Uncomment for plugin mode
#MIPSEL16E().register()

if __name__ == "__main__":
    A159 = "\x1b[38;5;159m" # Cyan
    A219 = "\x1b[38;5;219m" # Pink
    A226 = "\x1b[38;5;226m" # Yellow
    AEnd = "\x1b[0m"

    start_addr = 0x4023b0
    amount2read = 100
    print(f"[+] Reading {amount2read} bytes from 0x{start_addr:02x}...")

    _data = bv.read(start_addr,amount2read)#24)
    _data_len = len(_data)
    print(f"[+] Read {_data_len} bytes!")

    xm16 = MIPSEL16E()

    _idx = 0
    while _idx < _data_len:
      try:
        _dis_out = xm16.disassemble(_data[_idx:])
        _dis_len  = _dis_out['length']
        _insn = _dis_out['insn']
        _args = _dis_out['args']
        _idata = _data[_idx:_idx+_dis_len]
        _spacing = '    ' if _dis_len == 2 else ''

        out = ""
        out += f"{A219}len: {_dis_len}{AEnd} | "
        # todo swap endianness
        out += f"{A226}{_idata.hex()}{_spacing}{AEnd} | "
        out += f"{A159}{_insn}{AEnd} {_args}"
        print(out)
        _idx = _idx + _dis_out['length']
      except Exception as e:
        print(f"Error!! {e}")

