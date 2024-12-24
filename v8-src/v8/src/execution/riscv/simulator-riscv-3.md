Response: The user wants a summary of the functionality of the provided C++ code snippet. The code is part of a larger file (`simulator-riscv.cc`) which is responsible for simulating the execution of RISC-V instructions within the V8 JavaScript engine.

The provided snippet contains implementations of various RISC-V instructions. I need to identify the different instruction types being handled (R-type, I-type, S-type, B-type, U-type, J-type, and compressed instructions) and then within each type, list the specific instructions that are implemented.

Since the user explicitly asked about the relationship with JavaScript, I need to consider how these simulated RISC-V instructions might be used in the context of running JavaScript within V8. The simulator would be used when the underlying hardware architecture is not the target architecture, allowing V8 to still execute JavaScript code by interpreting the target architecture's instructions. Therefore, the implemented instructions are those that are necessary to execute the generated machine code for the RISC-V architecture. I can illustrate this with a simple JavaScript example that might involve some of these instructions at the machine code level.

The prompt also mentions that this is part 4 of 5. This likely means the surrounding parts handle other aspects of the simulator. This context is helpful but I should focus on summarizing the functionality *within this provided snippet*.
这是 `v8/src/execution/riscv/simulator-riscv.cc` 文件的第 4 部分代码，它主要负责 **RISC-V 指令的解码和执行**。

具体来说，这部分代码包含了 `Simulator` 类中的多个方法，用于处理不同类型的 RISC-V 指令：

1. **`DecodeRType()`**: 解码和执行 R-type（寄存器-寄存器操作）指令。
2. **`DecodeIType()`**: 解码和执行 I-type（立即数操作）指令。
3. **`DecodeSType()`**: 解码和执行 S-type（存储）指令。
4. **`DecodeBType()`**: 解码和执行 B-type（分支）指令。
5. **`DecodeUType()`**: 解码和执行 U-type（大立即数）指令。
6. **`DecodeJType()`**: 解码和执行 J-type（跳转）指令。
7. **`DecodeCRType()`**: 解码和执行 C-type（压缩 R 类型）指令。
8. **`DecodeCAType()`**: 解码和执行 CA-type（压缩算术类型）指令。
9. **`DecodeCIType()`**: 解码和执行 CI-type（压缩立即数类型）指令。
10. **`DecodeCIWType()`**: 解码和执行 CIW-type（压缩立即数字宽类型）指令。
11. **`DecodeCSSType()`**: 解码和执行 CSS-type（压缩存储栈指针类型）指令。
12. **`DecodeCLType()`**: 解码和执行 CL-type（压缩加载类型）指令。
13. **`DecodeCSType()`**: 解码和执行 CS-type（压缩存储类型）指令。
14. **`DecodeCJType()`**: 解码和执行 CJ-type（压缩跳转类型）指令。
15. **`DecodeCBType()`**: 解码和执行 CB-type（压缩分支类型）指令。
16. **`DecodeRvvIVV()`**, **`DecodeRvvIVI()`**, **`DecodeRvvIVX()`**, **`DecodeRvvMVV()`**, **`DecodeRvvMVX()`**, **`DecodeRvvFVV()`**:  解码和执行 RVV (RISC-V Vector Extension) 的各种指令类型，包括向量-向量、向量-立即数、向量-标量操作，以及浮点向量操作。

**与 JavaScript 的关系：**

V8 是一个 JavaScript 引擎。当 V8 需要在 RISC-V 架构的处理器上执行 JavaScript 代码时，它会将 JavaScript 代码编译成 RISC-V 的机器码。 然而，在某些情况下（例如，开发、测试或者目标硬件并非真正的 RISC-V 处理器时），V8 会使用模拟器来执行这些 RISC-V 机器码。

`simulator-riscv.cc` 文件中的代码就是 V8 中 RISC-V 指令集的软件模拟器的一部分。它模拟了 RISC-V CPU 的行为，包括寄存器、内存以及各种指令的执行逻辑。

**JavaScript 示例：**

以下是一个非常简单的 JavaScript 例子，展示了其在底层可能涉及到的 RISC-V 指令类型（请注意，实际的编译和执行过程会复杂得多，这里只是为了说明概念）：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
console.log(result);
```

当 V8 编译这段 JavaScript 代码并在 RISC-V 架构上运行时，底层的机器码可能会包含类似以下的 RISC-V 指令（这只是一个简化的例子，实际指令会更复杂，并且可能包含 V8 特有的 built-in 函数调用）：

* **`addi` (I-type):**  将立即数加到寄存器。例如，将参数 5 和 10 加载到寄存器中。
* **`add` (R-type):** 将两个寄存器的值相加。例如，执行 `a + b` 的加法运算。
* **`mv` (R-type, 实际上可能用 `addi rd, rs1, 0` 实现):** 将一个寄存器的值移动到另一个寄存器。例如，将计算结果存储到特定的寄存器。
* **`jal` (J-type):** 跳转并链接，用于函数调用。例如，调用 `console.log` 函数。
* **`beq` 或 `bne` (B-type):** 分支指令，用于控制程序流程，例如在条件语句中。
* **`lw` 或 `sw` (I-type/S-type):** 加载和存储指令，用于访问内存中的数据。例如，访问变量 `result` 的内存地址。

在 V8 的 RISC-V 模拟器中，当遇到这些 RISC-V 指令时，`simulator-riscv.cc` 中的相应 `Decode...Type()` 函数会被调用，模拟这些指令的行为，例如更新寄存器的值、修改内存内容或改变程序计数器（PC）的值，从而实现 JavaScript 代码的执行。

总而言之，这部分代码是 V8 引擎在非 RISC-V 硬件上运行 RISC-V 代码的关键组成部分，它通过软件模拟实现了 RISC-V 指令集的行为，使得 V8 能够执行编译成 RISC-V 机器码的 JavaScript 代码。

Prompt: 
```
这是目录为v8/src/execution/riscv/simulator-riscv.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共5部分，请归纳一下它的功能

"""
& ~sreg_t(1);
      set_pc(next_pc);
      if (v8_flags.trace_sim) {
        Builtin builtin = LookUp((Address)get_pc());
        if (builtin != Builtin::kNoBuiltinId) {
          auto code = builtins_.code(builtin);
          if ((rs1_reg() != ra || imm12() != 0)) {
            if ((Address)get_pc() == code->instruction_start()) {
              sreg_t arg0 = get_register(a0);
              sreg_t arg1 = get_register(a1);
              sreg_t arg2 = get_register(a2);
              sreg_t arg3 = get_register(a3);
              sreg_t arg4 = get_register(a4);
              sreg_t arg5 = get_register(a5);
              sreg_t arg6 = get_register(a6);
              sreg_t arg7 = get_register(a7);
              sreg_t* stack_pointer =
                  reinterpret_cast<sreg_t*>(get_register(sp));
              sreg_t arg8 = stack_pointer[0];
              sreg_t arg9 = stack_pointer[1];
              PrintF(
                  "Call to Builtin at %s "
                  "a0 %08" REGIx_FORMAT " ,a1 %08" REGIx_FORMAT
                  " ,a2 %08" REGIx_FORMAT " ,a3 %08" REGIx_FORMAT
                  " ,a4 %08" REGIx_FORMAT " ,a5 %08" REGIx_FORMAT
                  " ,a6 %08" REGIx_FORMAT " ,a7 %08" REGIx_FORMAT
                  " ,0(sp) %08" REGIx_FORMAT " ,8(sp) %08" REGIx_FORMAT
                  " ,sp %08" REGIx_FORMAT ",fp %08" REGIx_FORMAT " \n",
                  builtins_.name(builtin), arg0, arg1, arg2, arg3, arg4, arg5,
                  arg6, arg7, arg8, arg9, get_register(sp), get_register(fp));
            }
          } else if (rd_reg() == zero_reg) {
            PrintF("Return to Builtin at %s \n", builtins_.name(builtin));
          }
        }
      }
      break;
    }
    case RO_LB: {
      sreg_t addr = rs1() + imm12();
      if (!ProbeMemory(addr, sizeof(int8_t))) return;
      int8_t val = ReadMem<int8_t>(addr, instr_.instr());
      set_rd(sext_xlen(val), false);
      TraceMemRd(addr, val, get_register(rd_reg()));
      break;
    }
    case RO_LH: {
      sreg_t addr = rs1() + imm12();
      if (!ProbeMemory(addr, sizeof(int16_t))) return;
      int16_t val = ReadMem<int16_t>(addr, instr_.instr());
      set_rd(sext_xlen(val), false);
      TraceMemRd(addr, val, get_register(rd_reg()));
      break;
    }
    case RO_LW: {
      sreg_t addr = rs1() + imm12();
      if (!ProbeMemory(addr, sizeof(int32_t))) return;
      int32_t val = ReadMem<int32_t>(addr, instr_.instr());
      set_rd(sext_xlen(val), false);
      TraceMemRd(addr, val, get_register(rd_reg()));
      break;
    }
    case RO_LBU: {
      sreg_t addr = rs1() + imm12();
      if (!ProbeMemory(addr, sizeof(int8_t))) return;
      uint8_t val = ReadMem<uint8_t>(addr, instr_.instr());
      set_rd(zext_xlen(val), false);
      TraceMemRd(addr, val, get_register(rd_reg()));
      break;
    }
    case RO_LHU: {
      sreg_t addr = rs1() + imm12();
      if (!ProbeMemory(addr, sizeof(int16_t))) return;
      uint16_t val = ReadMem<uint16_t>(addr, instr_.instr());
      set_rd(zext_xlen(val), false);
      TraceMemRd(addr, val, get_register(rd_reg()));
      break;
    }
#ifdef V8_TARGET_ARCH_RISCV64
    case RO_LWU: {
      int64_t addr = rs1() + imm12();
      if (!ProbeMemory(addr, sizeof(int32_t))) return;
      uint32_t val = ReadMem<uint32_t>(addr, instr_.instr());
      set_rd(zext_xlen(val), false);
      TraceMemRd(addr, val, get_register(rd_reg()));
      break;
    }
    case RO_LD: {
      int64_t addr = rs1() + imm12();
      if (!ProbeMemory(addr, sizeof(int64_t))) return;
      int64_t val = ReadMem<int64_t>(addr, instr_.instr());
      set_rd(sext_xlen(val), false);
      TraceMemRd(addr, val, get_register(rd_reg()));
      break;
    }
#endif /*V8_TARGET_ARCH_RISCV64*/
    case RO_ADDI: {
      set_rd(sext_xlen(rs1() + imm12()));
      break;
    }
    case RO_SLTI: {
      set_rd(sreg_t(rs1()) < sreg_t(imm12()));
      break;
    }
    case RO_SLTIU: {
      set_rd(reg_t(rs1()) < reg_t(imm12()));
      break;
    }
    case RO_XORI: {
      set_rd(imm12() ^ rs1());
      break;
    }
    case RO_ORI: {
      set_rd(imm12() | rs1());
      break;
    }
    case RO_ANDI: {
      set_rd(imm12() & rs1());
      break;
    }
    case OP_SHL: {
      switch (instr_.Funct6FieldRaw() | OP_SHL) {
        case RO_SLLI:
          require(shamt6() < xlen);
          set_rd(sext_xlen(rs1() << shamt6()));
          break;
        case RO_BCLRI: {
          require(shamt6() < xlen);
          sreg_t index = shamt6() & (xlen - 1);
          set_rd(rs1() & ~(1l << index));
          break;
        }
        case RO_BINVI: {
          require(shamt6() < xlen);
          sreg_t index = shamt6() & (xlen - 1);
          set_rd(rs1() ^ (1l << index));
          break;
        }
        case RO_BSETI: {
          require(shamt6() < xlen);
          sreg_t index = shamt6() & (xlen - 1);
          set_rd(rs1() | (1l << index));
          break;
        }
        case OP_COUNT:
          switch (instr_.Shamt()) {
            case 0: {  // clz
              sreg_t x = rs1();
              int highest_setbit = -1;
              for (auto i = xlen - 1; i >= 0; i--) {
                if ((x & (1l << i))) {
                  highest_setbit = i;
                  break;
                }
              }
              set_rd(xlen - 1 - highest_setbit);
              break;
            }
            case 1: {  // ctz
              sreg_t x = rs1();
              int lowest_setbit = xlen;
              for (auto i = 0; i < xlen; i++) {
                if ((x & (1l << i))) {
                  lowest_setbit = i;
                  break;
                }
              }
              set_rd(lowest_setbit);
              break;
            }
            case 2: {  // cpop
              int i = 0;
              sreg_t n = rs1();
              while (n) {
                n &= (n - 1);
                i++;
              }
              set_rd(i);
              break;
            }
            case 4:
              set_rd(int8_t(rs1()));
              break;
            case 5:
              set_rd(int16_t(rs1()));
              break;
            default:
              UNSUPPORTED_RISCV();
          }
          break;
        default:
          UNSUPPORTED_RISCV();
      }
      break;
    }
    case OP_SHR: {  //  RO_SRAI
      switch (instr_.Funct6FieldRaw() | OP_SHR) {
        case RO_SRLI:
          require(shamt6() < xlen);
          set_rd(sext_xlen(zext_xlen(rs1()) >> shamt6()));
          break;
        case RO_SRAI:
          require(shamt6() < xlen);
          set_rd(sext_xlen(sext_xlen(rs1()) >> shamt6()));
          break;
        case RO_BEXTI: {
          require(shamt6() < xlen);
          sreg_t index = shamt6() & (xlen - 1);
          set_rd((rs1() >> index) & 1);
          break;
        }
        case RO_ORCB&(kFunct6Mask | OP_SHR): {
          reg_t rs1_val = rs1();
          reg_t result = 0;
          reg_t mask = 0xFF;
          reg_t step = 8;
          for (reg_t i = 0; i < xlen; i += step) {
            if ((rs1_val & mask) != 0) {
              result |= mask;
            }
            mask <<= step;
          }
          set_rd(result);
          break;
        }
        case RO_RORI: {
#ifdef V8_TARGET_ARCH_RISCV64
          int16_t shamt = shamt6();
#else
          int16_t shamt = shamt5();
#endif
          set_rd((reg_t(rs1()) >> shamt) | (reg_t(rs1()) << (xlen - shamt)));
          break;
        }
        case RO_REV8: {
          if (imm12() == RO_REV8_IMM12) {
            reg_t input = rs1();
            reg_t output = 0;
            reg_t j = xlen - 1;
            for (int i = 0; i < xlen; i += 8) {
              output |= ((input >> (j - 7)) & 0xff) << i;
              j -= 8;
            }
            set_rd(output);
            break;
          }
          UNSUPPORTED_RISCV();
        }
        default:
          UNSUPPORTED_RISCV();
      }
      break;
    }
#ifdef V8_TARGET_ARCH_RISCV64
    case RO_ADDIW: {
      set_rd(sext32(rs1() + imm12()));
      break;
    }
    case OP_SHLW:
      switch (instr_.Funct7FieldRaw() | OP_SHLW) {
        case RO_SLLIW:
          set_rd(sext32(rs1() << shamt5()));
          break;
        case RO_SLLIUW:
          set_rd(zext32(rs1()) << shamt6());
          break;
        case OP_COUNTW: {
          switch (instr_.Shamt()) {
            case 0: {  // clzw
              sreg_t x = rs1();
              int highest_setbit = -1;
              for (auto i = 31; i >= 0; i--) {
                if ((x & (1l << i))) {
                  highest_setbit = i;
                  break;
                }
              }
              set_rd(31 - highest_setbit);
              break;
            }
            case 1: {  // ctzw
              sreg_t x = rs1();
              int lowest_setbit = 32;
              for (auto i = 0; i < 32; i++) {
                if ((x & (1l << i))) {
                  lowest_setbit = i;
                  break;
                }
              }
              set_rd(lowest_setbit);
              break;
            }
            case 2: {  // cpopw
              int i = 0;
              int32_t n = static_cast<int32_t>(rs1());
              while (n) {
                n &= (n - 1);
                i++;
              }
              set_rd(i);
              break;
            }
            default:
              UNSUPPORTED_RISCV();
          }
          break;
        }
        default:
          UNSUPPORTED_RISCV();
      }
      break;
    case OP_SHRW: {  //  RO_SRAI
      switch (instr_.Funct7FieldRaw() | OP_SHRW) {
        case RO_SRLIW:
          set_rd(sext32(uint32_t(rs1()) >> shamt5()));
          break;
        case RO_SRAIW:
          set_rd(sext32(int32_t(rs1()) >> shamt5()));
          break;
        case RO_RORIW: {
          reg_t extz_rs1 = zext32(rs1());
          int16_t shamt = shamt5();
          set_rd(sext32((extz_rs1 >> shamt) | (extz_rs1 << (32 - shamt))));
          break;
        }
        default:
          UNSUPPORTED_RISCV();
      }
      break;
    }
#endif /*V8_TARGET_ARCH_RISCV64*/
    case RO_FENCE: {
      // DO nothing in sumulator
      break;
    }
    case RO_ECALL: {                   // RO_EBREAK
      if (instr_.Imm12Value() == 0) {  // ECALL
        SoftwareInterrupt();
      } else if (instr_.Imm12Value() == 1) {  // EBREAK
        SoftwareInterrupt();
      } else {
        UNSUPPORTED();
      }
      break;
    }
      // TODO(riscv): use Zifencei Standard Extension macro block
    case RO_FENCE_I: {
      // spike: flush icache.
      break;
    }
      // TODO(riscv): use Zicsr Standard Extension macro block
    case RO_CSRRW: {
      if (rd_reg() != zero_reg) {
        set_rd(zext_xlen(read_csr_value(csr_reg())));
      }
      write_csr_value(csr_reg(), rs1());
      break;
    }
    case RO_CSRRS: {
      set_rd(zext_xlen(read_csr_value(csr_reg())));
      if (rs1_reg() != zero_reg) {
        set_csr_bits(csr_reg(), rs1());
      }
      break;
    }
    case RO_CSRRC: {
      set_rd(zext_xlen(read_csr_value(csr_reg())));
      if (rs1_reg() != zero_reg) {
        clear_csr_bits(csr_reg(), rs1());
      }
      break;
    }
    case RO_CSRRWI: {
      if (rd_reg() != zero_reg) {
        set_rd(zext_xlen(read_csr_value(csr_reg())));
      }
      write_csr_value(csr_reg(), imm5CSR());
      break;
    }
    case RO_CSRRSI: {
      set_rd(zext_xlen(read_csr_value(csr_reg())));
      if (imm5CSR() != 0) {
        set_csr_bits(csr_reg(), imm5CSR());
      }
      break;
    }
    case RO_CSRRCI: {
      set_rd(zext_xlen(read_csr_value(csr_reg())));
      if (imm5CSR() != 0) {
        clear_csr_bits(csr_reg(), imm5CSR());
      }
      break;
    }
    // TODO(riscv): use F Extension macro block
    case RO_FLW: {
      sreg_t addr = rs1() + imm12();
      if (!ProbeMemory(addr, sizeof(float))) return;
      uint32_t val = ReadMem<uint32_t>(addr, instr_.instr());
      set_frd(Float32::FromBits(val), false);
      TraceMemRdFloat(addr, Float32::FromBits(val),
                      get_fpu_register(frd_reg()));
      break;
    }
    // TODO(riscv): use D Extension macro block
    case RO_FLD: {
      sreg_t addr = rs1() + imm12();
      if (!ProbeMemory(addr, sizeof(double))) return;
      uint64_t val = ReadMem<uint64_t>(addr, instr_.instr());
      set_drd(Float64::FromBits(val), false);
      TraceMemRdDouble(addr, Float64::FromBits(val),
                       get_fpu_register(frd_reg()));
      break;
    }
    default: {
#ifdef CAN_USE_RVV_INSTRUCTIONS
      if (!DecodeRvvVL()) {
        UNSUPPORTED();
      }
      break;
#else
      UNSUPPORTED();
#endif
    }
  }
}

void Simulator::DecodeRVSType() {
  switch (instr_.InstructionBits() & kSTypeMask) {
    case RO_SB:
      if (!ProbeMemory(rs1() + s_imm12(), sizeof(int8_t))) return;
      WriteMem<uint8_t>(rs1() + s_imm12(), (uint8_t)rs2(), instr_.instr());
      break;
    case RO_SH:
      if (!ProbeMemory(rs1() + s_imm12(), sizeof(int16_t))) return;
      WriteMem<uint16_t>(rs1() + s_imm12(), (uint16_t)rs2(), instr_.instr());
      break;
    case RO_SW:
      if (!ProbeMemory(rs1() + s_imm12(), sizeof(int32_t))) return;
      WriteMem<uint32_t>(rs1() + s_imm12(), (uint32_t)rs2(), instr_.instr());
      break;
#ifdef V8_TARGET_ARCH_RISCV64
    case RO_SD:
      if (!ProbeMemory(rs1() + s_imm12(), sizeof(int64_t))) return;
      WriteMem<uint64_t>(rs1() + s_imm12(), (uint64_t)rs2(), instr_.instr());
      break;
#endif /*V8_TARGET_ARCH_RISCV64*/
    // TODO(riscv): use F Extension macro block
    case RO_FSW: {
      if (!ProbeMemory(rs1() + s_imm12(), sizeof(float))) return;
      WriteMem<Float32>(rs1() + s_imm12(),
                        get_fpu_register_Float32(rs2_reg(), false),
                        instr_.instr());
      break;
    }
    // TODO(riscv): use D Extension macro block
    case RO_FSD: {
      if (!ProbeMemory(rs1() + s_imm12(), sizeof(double))) return;
      WriteMem<Float64>(rs1() + s_imm12(), get_fpu_register_Float64(rs2_reg()),
                        instr_.instr());
      break;
    }
    default:
#ifdef CAN_USE_RVV_INSTRUCTIONS
      if (!DecodeRvvVS()) {
        UNSUPPORTED();
      }
      break;
#else
      UNSUPPORTED();
#endif
  }
}

void Simulator::DecodeRVBType() {
  switch (instr_.InstructionBits() & kBTypeMask) {
    case RO_BEQ:
      if (rs1() == rs2()) {
        int64_t next_pc = get_pc() + boffset();
        set_pc(next_pc);
      }
      break;
    case RO_BNE:
      if (rs1() != rs2()) {
        int64_t next_pc = get_pc() + boffset();
        set_pc(next_pc);
      }
      break;
    case RO_BLT:
      if (rs1() < rs2()) {
        int64_t next_pc = get_pc() + boffset();
        set_pc(next_pc);
      }
      break;
    case RO_BGE:
      if (rs1() >= rs2()) {
        int64_t next_pc = get_pc() + boffset();
        set_pc(next_pc);
      }
      break;
    case RO_BLTU:
      if ((reg_t)rs1() < (reg_t)rs2()) {
        int64_t next_pc = get_pc() + boffset();
        set_pc(next_pc);
      }
      break;
    case RO_BGEU:
      if ((reg_t)rs1() >= (reg_t)rs2()) {
        int64_t next_pc = get_pc() + boffset();
        set_pc(next_pc);
      }
      break;
    default:
      UNSUPPORTED();
  }
}
void Simulator::DecodeRVUType() {
  // U Type doesn't have additoinal mask
  switch (instr_.BaseOpcodeFieldRaw()) {
    case LUI:
      set_rd(u_imm20());
      break;
    case AUIPC:
      set_rd(sext_xlen(u_imm20() + get_pc()));
      break;
    default:
      UNSUPPORTED();
  }
}
void Simulator::DecodeRVJType() {
  // J Type doesn't have additional mask
  switch (instr_.BaseOpcodeValue()) {
    case JAL: {
      set_rd(get_pc() + kInstrSize);
      int64_t next_pc = get_pc() + imm20J();
      set_pc(next_pc);
      break;
    }
    default:
      UNSUPPORTED();
  }
}
void Simulator::DecodeCRType() {
  switch (instr_.RvcFunct4Value()) {
    case 0b1000:
      if (instr_.RvcRs1Value() != 0 && instr_.RvcRs2Value() == 0) {  // c.jr
        set_pc(rvc_rs1());
      } else if (instr_.RvcRdValue() != 0 &&
                 instr_.RvcRs2Value() != 0) {  // c.mv
        set_rvc_rd(sext_xlen(rvc_rs2()));
      } else {
        UNSUPPORTED_RISCV();
      }
      break;
    case 0b1001:
      if (instr_.RvcRs1Value() == 0 && instr_.RvcRs2Value() == 0) {  // c.ebreak
        DieOrDebug();
      } else if (instr_.RvcRdValue() != 0 &&
                 instr_.RvcRs2Value() == 0) {  // c.jalr
        set_register(ra, get_pc() + kShortInstrSize);
        set_pc(rvc_rs1());
      } else if (instr_.RvcRdValue() != 0 &&
                 instr_.RvcRs2Value() != 0) {  // c.add
        set_rvc_rd(sext_xlen(rvc_rs1() + rvc_rs2()));
      } else {
        UNSUPPORTED();
      }
      break;
    default:
      UNSUPPORTED();
  }
}

void Simulator::DecodeCAType() {
  switch (instr_.InstructionBits() & kCATypeMask) {
    case RO_C_SUB:
      set_rvc_rs1s(sext_xlen(rvc_rs1s() - rvc_rs2s()));
      break;
    case RO_C_XOR:
      set_rvc_rs1s(rvc_rs1s() ^ rvc_rs2s());
      break;
    case RO_C_OR:
      set_rvc_rs1s(rvc_rs1s() | rvc_rs2s());
      break;
    case RO_C_AND:
      set_rvc_rs1s(rvc_rs1s() & rvc_rs2s());
      break;
#if V8_TARGET_ARCH_RISCV64
    case RO_C_SUBW:
      set_rvc_rs1s(sext32(rvc_rs1s() - rvc_rs2s()));
      break;
    case RO_C_ADDW:
      set_rvc_rs1s(sext32(rvc_rs1s() + rvc_rs2s()));
      break;
#endif
    default:
      UNSUPPORTED();
  }
}

void Simulator::DecodeCIType() {
  switch (instr_.RvcOpcode()) {
    case RO_C_NOP_ADDI:
      if (instr_.RvcRdValue() == 0)  // c.nop
        break;
      else  // c.addi
        set_rvc_rd(sext_xlen(rvc_rs1() + rvc_imm6()));
      break;
#if V8_TARGET_ARCH_RISCV64
    case RO_C_ADDIW:
      set_rvc_rd(sext32(rvc_rs1() + rvc_imm6()));
      break;
#endif
    case RO_C_LI:
      set_rvc_rd(sext_xlen(rvc_imm6()));
      break;
    case RO_C_LUI_ADD:
      if (instr_.RvcRdValue() == 2) {
        // c.addi16sp
        int64_t value = get_register(sp) + rvc_imm6_addi16sp();
        set_register(sp, value);
      } else if (instr_.RvcRdValue() != 0 && instr_.RvcRdValue() != 2) {
        // c.lui
        set_rvc_rd(rvc_u_imm6());
      } else {
        UNSUPPORTED();
      }
      break;
    case RO_C_SLLI:
      set_rvc_rd(sext_xlen(rvc_rs1() << rvc_shamt6()));
      break;
    case RO_C_FLDSP: {
      sreg_t addr = get_register(sp) + rvc_imm6_ldsp();
      uint64_t val = ReadMem<uint64_t>(addr, instr_.instr());
      set_rvc_drd(Float64::FromBits(val), false);
      TraceMemRdDouble(addr, Float64::FromBits(val),
                       get_fpu_register(rvc_frd_reg()));
      break;
    }
#if V8_TARGET_ARCH_RISCV64
    case RO_C_LWSP: {
      sreg_t addr = get_register(sp) + rvc_imm6_lwsp();
      int64_t val = ReadMem<int32_t>(addr, instr_.instr());
      set_rvc_rd(sext_xlen(val), false);
      TraceMemRd(addr, val, get_register(rvc_rd_reg()));
      break;
    }
    case RO_C_LDSP: {
      sreg_t addr = get_register(sp) + rvc_imm6_ldsp();
      int64_t val = ReadMem<int64_t>(addr, instr_.instr());
      set_rvc_rd(sext_xlen(val), false);
      TraceMemRd(addr, val, get_register(rvc_rd_reg()));
      break;
    }
#elif V8_TARGET_ARCH_RISCV32
    case RO_C_FLWSP: {
      sreg_t addr = get_register(sp) + rvc_imm6_ldsp();
      uint32_t val = ReadMem<uint32_t>(addr, instr_.instr());
      set_rvc_frd(Float32::FromBits(val), false);
      TraceMemRdFloat(addr, Float32::FromBits(val),
                      get_fpu_register(rvc_frd_reg()));
      break;
    }
    case RO_C_LWSP: {
      sreg_t addr = get_register(sp) + rvc_imm6_lwsp();
      int32_t val = ReadMem<int32_t>(addr, instr_.instr());
      set_rvc_rd(sext_xlen(val), false);
      TraceMemRd(addr, val, get_register(rvc_rd_reg()));
      break;
    }
#endif
    default:
      UNSUPPORTED();
  }
}

void Simulator::DecodeCIWType() {
  switch (instr_.RvcOpcode()) {
    case RO_C_ADDI4SPN: {
      set_rvc_rs2s(get_register(sp) + rvc_imm8_addi4spn());
      break;
      default:
        UNSUPPORTED();
    }
  }
}

void Simulator::DecodeCSSType() {
  switch (instr_.RvcOpcode()) {
    case RO_C_FSDSP: {
      sreg_t addr = get_register(sp) + rvc_imm6_sdsp();
      WriteMem<Float64>(addr, get_fpu_register_Float64(rvc_rs2_reg()),
                        instr_.instr());
      break;
    }
#if V8_TARGET_ARCH_RISCV32
    case RO_C_FSWSP: {
      sreg_t addr = get_register(sp) + rvc_imm6_sdsp();
      WriteMem<Float32>(addr, get_fpu_register_Float32(rvc_rs2_reg(), false),
                        instr_.instr());
      break;
    }
#endif
    case RO_C_SWSP: {
      sreg_t addr = get_register(sp) + rvc_imm6_swsp();
      WriteMem<int32_t>(addr, (int32_t)rvc_rs2(), instr_.instr());
      break;
    }
#if V8_TARGET_ARCH_RISCV64
    case RO_C_SDSP: {
      sreg_t addr = get_register(sp) + rvc_imm6_sdsp();
      WriteMem<int64_t>(addr, (int64_t)rvc_rs2(), instr_.instr());
      break;
    }
#endif
    default:
      UNSUPPORTED();
  }
}

void Simulator::DecodeCLType() {
  switch (instr_.RvcOpcode()) {
    case RO_C_LW: {
      sreg_t addr = rvc_rs1s() + rvc_imm5_w();
      int64_t val = ReadMem<int32_t>(addr, instr_.instr());
      set_rvc_rs2s(sext_xlen(val), false);
      TraceMemRd(addr, val, get_register(rvc_rs2s_reg()));
      break;
    }
    case RO_C_FLD: {
      sreg_t addr = rvc_rs1s() + rvc_imm5_d();
      uint64_t val = ReadMem<uint64_t>(addr, instr_.instr());
      set_rvc_drs2s(Float64::FromBits(val), false);
      break;
    }
#if V8_TARGET_ARCH_RISCV64
    case RO_C_LD: {
      sreg_t addr = rvc_rs1s() + rvc_imm5_d();
      int64_t val = ReadMem<int64_t>(addr, instr_.instr());
      set_rvc_rs2s(sext_xlen(val), false);
      TraceMemRd(addr, val, get_register(rvc_rs2s_reg()));
      break;
    }
#elif V8_TARGET_ARCH_RISCV32
    case RO_C_FLW: {
      sreg_t addr = rvc_rs1s() + rvc_imm5_d();
      uint32_t val = ReadMem<uint32_t>(addr, instr_.instr());
      set_rvc_frs2s(Float32::FromBits(val), false);
      break;
    }
#endif
    default:
      UNSUPPORTED();
  }
}

void Simulator::DecodeCSType() {
  switch (instr_.RvcOpcode()) {
    case RO_C_SW: {
      sreg_t addr = rvc_rs1s() + rvc_imm5_w();
      WriteMem<int32_t>(addr, (int32_t)rvc_rs2s(), instr_.instr());
      break;
    }
#if V8_TARGET_ARCH_RISCV64
    case RO_C_SD: {
      sreg_t addr = rvc_rs1s() + rvc_imm5_d();
      WriteMem<int64_t>(addr, (int64_t)rvc_rs2s(), instr_.instr());
      break;
    }
#endif
    case RO_C_FSD: {
      sreg_t addr = rvc_rs1s() + rvc_imm5_d();
      WriteMem<double>(addr, static_cast<double>(rvc_drs2s()), instr_.instr());
      break;
    }
    default:
      UNSUPPORTED();
  }
}

void Simulator::DecodeCJType() {
  switch (instr_.RvcOpcode()) {
    case RO_C_J: {
      set_pc(get_pc() + instr_.RvcImm11CJValue());
      break;
    }
    default:
      UNSUPPORTED();
  }
}

void Simulator::DecodeCBType() {
  switch (instr_.RvcOpcode()) {
    case RO_C_BNEZ:
      if (rvc_rs1() != 0) {
        sreg_t next_pc = get_pc() + rvc_imm8_b();
        set_pc(next_pc);
      }
      break;
    case RO_C_BEQZ:
      if (rvc_rs1() == 0) {
        sreg_t next_pc = get_pc() + rvc_imm8_b();
        set_pc(next_pc);
      }
      break;
    case RO_C_MISC_ALU:
      if (instr_.RvcFunct2BValue() == 0b00) {  // c.srli
        set_rvc_rs1s(sext_xlen(sext_xlen(rvc_rs1s()) >> rvc_shamt6()));
      } else if (instr_.RvcFunct2BValue() == 0b01) {  // c.srai
        require(rvc_shamt6() < xlen);
        set_rvc_rs1s(sext_xlen(sext_xlen(rvc_rs1s()) >> rvc_shamt6()));
      } else if (instr_.RvcFunct2BValue() == 0b10) {  // c.andi
        set_rvc_rs1s(rvc_imm6() & rvc_rs1s());
      } else {
        UNSUPPORTED();
      }
      break;
    default:
      UNSUPPORTED();
  }
}

/**
 * RISCV-ISA-SIM
 *
 * @link      https://github.com/riscv/riscv-isa-sim/
 * @copyright Copyright (c)  The Regents of the University of California
 * @license   hhttps://github.com/riscv/riscv-isa-sim/blob/master/LICENSE
 */
// ref:  https://locklessinc.com/articles/sat_arithmetic/
template <typename T, typename UT>
static inline T sat_add(T x, T y, bool& sat) {
  UT ux = x;
  UT uy = y;
  UT res = ux + uy;
  sat = false;
  int sh = sizeof(T) * 8 - 1;

  /* Calculate overflowed result. (Don't change the sign bit of ux) */
  ux = (ux >> sh) + (((UT)0x1 << sh) - 1);

  /* Force compiler to use cmovns instruction */
  if ((T)((ux ^ uy) | ~(uy ^ res)) >= 0) {
    res = ux;
    sat = true;
  }

  return res;
}

template <typename T, typename UT>
static inline T sat_sub(T x, T y, bool& sat) {
  UT ux = x;
  UT uy = y;
  UT res = ux - uy;
  sat = false;
  int sh = sizeof(T) * 8 - 1;

  /* Calculate overflowed result. (Don't change the sign bit of ux) */
  ux = (ux >> sh) + (((UT)0x1 << sh) - 1);

  /* Force compiler to use cmovns instruction */
  if ((T)((ux ^ uy) & (ux ^ res)) < 0) {
    res = ux;
    sat = true;
  }

  return res;
}

template <typename T>
T sat_addu(T x, T y, bool& sat) {
  T res = x + y;
  sat = false;

  sat = res < x;
  res |= -(res < x);

  return res;
}

template <typename T>
T sat_subu(T x, T y, bool& sat) {
  T res = x - y;
  sat = false;

  sat = !(res <= x);
  res &= -(res <= x);

  return res;
}

#ifdef CAN_USE_RVV_INSTRUCTIONS
void Simulator::DecodeRvvIVV() {
  DCHECK_EQ(instr_.InstructionBits() & (kBaseOpcodeMask | kFunct3Mask), OP_IVV);
  switch (instr_.InstructionBits() & kVTypeMask) {
    case RO_V_VADD_VV: {
      RVV_VI_VV_LOOP({ vd = vs1 + vs2; });
      break;
    }
    case RO_V_VSADD_VV: {
      RVV_VI_GENERAL_LOOP_BASE
      bool sat = false;
      switch (rvv_vsew()) {
        case E8: {
          VV_PARAMS(8);
          vd = sat_add<int8_t, uint8_t>(vs2, vs1, sat);
          break;
        }
        case E16: {
          VV_PARAMS(16);
          vd = sat_add<int16_t, uint16_t>(vs2, vs1, sat);
          break;
        }
        case E32: {
          VV_PARAMS(32);
          vd = sat_add<int32_t, uint32_t>(vs2, vs1, sat);
          break;
        }
        default: {
          VV_PARAMS(64);
          vd = sat_add<int64_t, uint64_t>(vs2, vs1, sat);
          break;
        }
      }
      set_rvv_vxsat(sat);
      RVV_VI_LOOP_END
      break;
    }
    case RO_V_VSADDU_VV:
      RVV_VI_VV_ULOOP({
        vd = vs2 + vs1;
        vd |= -(vd < vs2);
      })
      break;
    case RO_V_VSUB_VV: {
      RVV_VI_VV_LOOP({ vd = vs2 - vs1; })
      break;
    }
    case RO_V_VSSUB_VV: {
      RVV_VI_GENERAL_LOOP_BASE
      bool sat = false;
      switch (rvv_vsew()) {
        case E8: {
          VV_PARAMS(8);
          vd = sat_sub<int8_t, uint8_t>(vs2, vs1, sat);
          break;
        }
        case E16: {
          VV_PARAMS(16);
          vd = sat_sub<int16_t, uint16_t>(vs2, vs1, sat);
          break;
        }
        case E32: {
          VV_PARAMS(32);
          vd = sat_sub<int32_t, uint32_t>(vs2, vs1, sat);
          break;
        }
        default: {
          VV_PARAMS(64);
          vd = sat_sub<int64_t, uint64_t>(vs2, vs1, sat);
          break;
        }
      }
      set_rvv_vxsat(sat);
      RVV_VI_LOOP_END
      break;
    }
    case RO_V_VSSUBU_VV: {
      RVV_VI_GENERAL_LOOP_BASE
      bool sat = false;
      switch (rvv_vsew()) {
        case E8: {
          VV_UPARAMS(8);
          vd = sat_subu<uint8_t>(vs2, vs1, sat);
          break;
        }
        case E16: {
          VV_UPARAMS(16);
          vd = sat_subu<uint16_t>(vs2, vs1, sat);
          break;
        }
        case E32: {
          VV_UPARAMS(32);
          vd = sat_subu<uint32_t>(vs2, vs1, sat);
          break;
        }
        default: {
          VV_UPARAMS(64);
          vd = sat_subu<uint64_t>(vs2, vs1, sat);
          break;
        }
      }
      set_rvv_vxsat(sat);
      RVV_VI_LOOP_END
      break;
    }
    case RO_V_VAND_VV: {
      RVV_VI_VV_LOOP({ vd = vs1 & vs2; })
      break;
    }
    case RO_V_VOR_VV: {
      RVV_VI_VV_LOOP({ vd = vs1 | vs2; })
      break;
    }
    case RO_V_VXOR_VV: {
      RVV_VI_VV_LOOP({ vd = vs1 ^ vs2; })
      break;
    }
    case RO_V_VMAXU_VV: {
      RVV_VI_VV_ULOOP({
        if (vs1 <= vs2) {
          vd = vs2;
        } else {
          vd = vs1;
        }
      })
      break;
    }
    case RO_V_VMAX_VV: {
      RVV_VI_VV_LOOP({
        if (vs1 <= vs2) {
          vd = vs2;
        } else {
          vd = vs1;
        }
      })
      break;
    }
    case RO_V_VMINU_VV: {
      RVV_VI_VV_ULOOP({
        if (vs1 <= vs2) {
          vd = vs1;
        } else {
          vd = vs2;
        }
      })
      break;
    }
    case RO_V_VMIN_VV: {
      RVV_VI_VV_LOOP({
        if (vs1 <= vs2) {
          vd = vs1;
        } else {
          vd = vs2;
        }
      })
      break;
    }
    case RO_V_VMV_VV: {
      if (instr_.RvvVM()) {
        RVV_VI_VVXI_MERGE_LOOP({
          vd = vs1;
          USE(simm5);
          USE(vs2);
          USE(rs1);
        });
      } else {
        RVV_VI_VVXI_MERGE_LOOP({
          bool use_first = (Rvvelt<uint64_t>(0, (i / 64)) >> (i % 64)) & 0x1;
          vd = use_first ? vs1 : vs2;
          USE(simm5);
          USE(rs1);
        });
      }
      break;
    }
    case RO_V_VMSEQ_VV: {
      RVV_VI_VV_LOOP_CMP({ res = vs1 == vs2; })
      break;
    }
    case RO_V_VMSNE_VV: {
      RVV_VI_VV_LOOP_CMP({ res = vs1 != vs2; })
      break;
    }
    case RO_V_VMSLTU_VV: {
      RVV_VI_VV_ULOOP_CMP({ res = vs2 < vs1; })
      break;
    }
    case RO_V_VMSLT_VV: {
      RVV_VI_VV_LOOP_CMP({ res = vs2 < vs1; })
      break;
    }
    case RO_V_VMSLE_VV: {
      RVV_VI_VV_LOOP_CMP({ res = vs2 <= vs1; })
      break;
    }
    case RO_V_VMSLEU_VV: {
      RVV_VI_VV_ULOOP_CMP({ res = vs2 <= vs1; })
      break;
    }
    case RO_V_VADC_VV:
      if (instr_.RvvVM()) {
        RVV_VI_VV_LOOP_WITH_CARRY({
          auto& v0 = Rvvelt<uint64_t>(0, midx);
          vd = vs1 + vs2 + (v0 >> mpos) & 0x1;
        })
      } else {
        UNREACHABLE();
      }
      break;
    case RO_V_VSLL_VV: {
      RVV_VI_VV_LOOP({ vd = vs2 << (vs1 & (rvv_sew() - 1)); })
      break;
    }
    case RO_V_VSRL_VV:
      RVV_VI_VV_ULOOP({ vd = vs2 >> (vs1 & (rvv_sew() - 1)); })
      break;
    case RO_V_VSRA_VV:
      RVV_VI_VV_LOOP({ vd = vs2 >> (vs1 & (rvv_sew() - 1)); })
      break;
    case RO_V_VSMUL_VV: {
      RVV_VI_GENERAL_LOOP_BASE
      RVV_VI_LOOP_MASK_SKIP()
      if (rvv_vsew() == E8) {
        VV_PARAMS(8);
        int16_t result = (int16_t)vs1 * (int16_t)vs2;
        uint8_t round = get_round(static_cast<int>(rvv_vxrm()), result, 7);
        result = (result >> 7) + round;
        vd = signed_saturation<int16_t, int8_t>(result, 8);
      } else if (rvv_vsew() == E16) {
        VV_PARAMS(16);
        int32_t result = (int32_t)vs1 * (int32_t)vs2;
        uint8_t round = get_round(static_cast<int>(rvv_vxrm()), result, 15);
        result = (result >> 15) + round;
        vd = signed_saturation<int32_t, int16_t>(result, 16);
      } else if (rvv_vsew() == E32) {
        VV_PARAMS(32);
        int64_t result = (int64_t)vs1 * (int64_t)vs2;
        uint8_t round = get_round(static_cast<int>(rvv_vxrm()), result, 31);
        result = (result >> 31) + round;
        vd = signed_saturation<int64_t, int32_t>(result, 32);
      } else if (rvv_vsew() == E64) {
        VV_PARAMS(64);
        __int128_t result = (__int128_t)vs1 * (__int128_t)vs2;
        uint8_t round = get_round(static_cast<int>(rvv_vxrm()), result, 63);
        result = (result >> 63) + round;
        vd = signed_saturation<__int128_t, int64_t>(result, 64);
      } else {
        UNREACHABLE();
      }
      RVV_VI_LOOP_END
      rvv_trace_vd();
      break;
    }
    case RO_V_VRGATHER_VV: {
      RVV_VI_GENERAL_LOOP_BASE
      CHECK_NE(rvv_vs1_reg(), rvv_vd_reg());
      CHECK_NE(rvv_vs2_reg(), rvv_vd_reg());
      switch (rvv_vsew()) {
        case E8: {
          auto vs1 = Rvvelt<uint8_t>(rvv_vs1_reg(), i);
          // if (i > 255) continue;
          Rvvelt<uint8_t>(rvv_vd_reg(), i, true) =
              vs1 >= rvv_vlmax() ? 0 : Rvvelt<uint8_t>(rvv_vs2_reg(), vs1);
          break;
        }
        case E16: {
          auto vs1 = Rvvelt<uint16_t>(rvv_vs1_reg(), i);
          Rvvelt<uint16_t>(rvv_vd_reg(), i, true) =
              vs1 >= rvv_vlmax() ? 0 : Rvvelt<uint16_t>(rvv_vs2_reg(), vs1);
          break;
        }
        case E32: {
          auto vs1 = Rvvelt<uint32_t>(rvv_vs1_reg(), i);
          Rvvelt<uint32_t>(rvv_vd_reg(), i, true) =
              vs1 >= rvv_vlmax() ? 0 : Rvvelt<uint32_t>(rvv_vs2_reg(), vs1);
          break;
        }
        default: {
          auto vs1 = Rvvelt<uint64_t>(rvv_vs1_reg(), i);
          Rvvelt<uint64_t>(rvv_vd_reg(), i, true) =
              vs1 >= rvv_vlmax() ? 0 : Rvvelt<uint64_t>(rvv_vs2_reg(), vs1);
          break;
        }
      }
      RVV_VI_LOOP_END;
      rvv_trace_vd();
      break;
    }
    default:
      // v8::base::EmbeddedVector<char, 256> buffer;
      // SNPrintF(trace_buf_, " ");
      // disasm::NameConverter converter;
      // disasm::Disassembler dasm(converter);
      // // Use a reasonably large buffer.
      // dasm.InstructionDecode(buffer, reinterpret_cast<uint8_t*>(&instr_));

      // PrintF("EXECUTING  0x%08" PRIxPTR "   %-44s\n",
      //        reinterpret_cast<intptr_t>(&instr_), buffer.begin());
      UNIMPLEMENTED_RISCV();
      break;
  }
  set_rvv_vstart(0);
}

void Simulator::DecodeRvvIVI() {
  DCHECK_EQ(instr_.InstructionBits() & (kBaseOpcodeMask | kFunct3Mask), OP_IVI);
  switch (instr_.InstructionBits() & kVTypeMask) {
    case RO_V_VADD_VI: {
      RVV_VI_VI_LOOP({ vd = simm5 + vs2; })
      break;
    }
    case RO_V_VSADD_VI: {
      RVV_VI_GENERAL_LOOP_BASE
      bool sat = false;
      switch (rvv_vsew()) {
        case E8: {
          VI_PARAMS(8);
          vd = sat_add<int8_t, uint8_t>(vs2, simm5, sat);
          break;
        }
        case E16: {
          VI_PARAMS(16);
          vd = sat_add<int16_t, uint16_t>(vs2, simm5, sat);
          break;
        }
        case E32: {
          VI_PARAMS(32);
          vd = sat_add<int32_t, uint32_t>(vs2, simm5, sat);
          break;
        }
        default: {
          VI_PARAMS(64);
          vd = sat_add<int64_t, uint64_t>(vs2, simm5, sat);
          break;
        }
      }
      set_rvv_vxsat(sat);
      RVV_VI_LOOP_END
      break;
    }
    case RO_V_VSADDU_VI: {
      RVV_VI_VI_ULOOP({
        vd = vs2 + uimm5;
        vd |= -(vd < vs2);
      })
      break;
    }
    case RO_V_VRSUB_VI: {
      RVV_VI_VI_LOOP({ vd = simm5 - vs2; })
      break;
    }
    case RO_V_VAND_VI: {
      RVV_VI_VI_LOOP({ vd = simm5 & vs2; })
      break;
    }
    case RO_V_VOR_VI: {
      RVV_VI_VI_LOOP({ vd = simm5 | vs2; })
      break;
    }
    case RO_V_VXOR_VI: {
      RVV_VI_VI_LOOP({ vd = simm5 ^ vs2; })
      break;
    }
    case RO_V_VMV_VI:
      if (instr_.RvvVM()) {
        RVV_VI_VVXI_MERGE_LOOP({
          vd = simm5;
          USE(vs1);
          USE(vs2);
          USE(rs1);
        });
      } else {
        RVV_VI_VVXI_MERGE_LOOP({
          bool use_first = (Rvvelt<uint64_t>(0, (i / 64)) >> (i % 64)) & 0x1;
          vd = use_first ? simm5 : vs2;
          USE(vs1);
          USE(rs1);
        });
      }
      break;
    case RO_V_VMSEQ_VI:
      RVV_VI_VI_LOOP_CMP({ res = simm5 == vs2; })
      break;
    case RO_V_VMSNE_VI:
      RVV_VI_VI_LOOP_CMP({ res = simm5 != vs2; })
      break;
    case RO_V_VMSLEU_VI:
      RVV_VI_VI_ULOOP_CMP({ res = vs2 <= uimm5; })
      break;
    case RO_V_VMSLE_VI:
      RVV_VI_VI_LOOP_CMP({ res = vs2 <= simm5; })
      break;
    case RO_V_VMSGT_VI:
      RVV_VI_VI_LOOP_CMP({ res = vs2 > simm5; })
      break;
    case RO_V_VSLIDEDOWN_VI: {
      RVV_VI_CHECK_SLIDE(false);
      const uint8_t sh = instr_.RvvUimm5();
      RVV_VI_GENERAL_LOOP_BASE

      reg_t offset = 0;
      bool is_valid = (i + sh) < rvv_vlmax();

      if (is_valid) {
        offset = sh;
      }

      switch (rvv_vsew()) {
        case E8: {
          VI_XI_SLIDEDOWN_PARAMS(8, offset);
          vd = is_valid ? vs2 : 0;
        } break;
        case E16: {
          VI_XI_SLIDEDOWN_PARAMS(16, offset);
          vd = is_valid ? vs2 : 0;
        } break;
        case E32: {
          VI_XI_SLIDEDOWN_PARAMS(32, offset);
          vd = is_valid ? vs2 : 0;
        } break;
        default: {
          VI_XI_SLIDEDOWN_PARAMS(64, offset);
          vd = is_valid ? vs2 : 0;
        } break;
      }
      RVV_VI_LOOP_END
      rvv_trace_vd();
    } break;
    case RO_V_VSLIDEUP_VI: {
      RVV_VI_CHECK_SLIDE(true);

      const uint8_t offset = instr_.RvvUimm5();
      RVV_VI_GENERAL_LOOP_BASE
      if (rvv_vstart() < offset && i < offset) continue;

      switch (rvv_vsew()) {
        case E8: {
          VI_XI_SLIDEUP_PARAMS(8, offset);
          vd = vs2;
        } break;
        case E16: {
          VI_XI_SLIDEUP_PARAMS(16, offset);
          vd = vs2;
        } break;
        case E32: {
          VI_XI_SLIDEUP_PARAMS(32, offset);
          vd = vs2;
        } break;
        default: {
          VI_XI_SLIDEUP_PARAMS(64, offset);
          vd = vs2;
        } break;
      }
      RVV_VI_LOOP_END
      rvv_trace_vd();
    } break;
    case RO_V_VSRL_VI:
      RVV_VI_VI_ULOOP({ vd = vs2 >> (uimm5 & (rvv_sew() - 1)); })
      break;
    case RO_V_VSRA_VI:
      RVV_VI_VI_LOOP({ vd = vs2 >> (simm5 & (rvv_sew() - 1) & 0x1f); })
      break;
    case RO_V_VSLL_VI:
      RVV_VI_VI_ULOOP({ vd = vs2 << (uimm5 & (rvv_sew() - 1)); })
      break;
    case RO_V_VADC_VI:
      if (instr_.RvvVM()) {
        RVV_VI_XI_LOOP_WITH_CARRY({
          auto& v0 = Rvvelt<uint64_t>(0, midx);
          vd = simm5 + vs2 + (v0 >> mpos) & 0x1;
          USE(rs1);
        })
      } else {
        UNREACHABLE();
      }
      break;
    case RO_V_VNCLIP_WI:
      RVV_VN_CLIP_VI_LOOP()
      break;
    case RO_V_VNCLIPU_WI:
      RVV_VN_CLIPU_VI_LOOP()
      break;
    default:
      UNIMPLEMENTED_RISCV();
      break;
  }
}

void Simulator::DecodeRvvIVX() {
  DCHECK_EQ(instr_.InstructionBits() & (kBaseOpcodeMask | kFunct3Mask), OP_IVX);
  switch (instr_.InstructionBits() & kVTypeMask) {
    case RO_V_VADD_VX: {
      RVV_VI_VX_LOOP({ vd = rs1 + vs2; })
      break;
    }
    case RO_V_VSADD_VX: {
      RVV_VI_GENERAL_LOOP_BASE
      bool sat = false;
      switch (rvv_vsew()) {
        case E8: {
          VX_PARAMS(8);
          vd = sat_add<int8_t, uint8_t>(vs2, rs1, sat);
          break;
        }
        case E16: {
          VX_PARAMS(16);
          vd = sat_add<int16_t, uint16_t>(vs2, rs1, sat);
          break;
        }
        case E32: {
          VX_PARAMS(32);
          vd = sat_add<int32_t, uint32_t>(vs2, rs1, sat);
          break;
        }
        default: {
          VX_PARAMS(64);
          vd = sat_add<int64_t, uint64_t>(vs2, rs1, sat);
          break;
        }
      }
      set_rvv_vxsat(sat);
      RVV_VI_LOOP_END
      break;
    }
    case RO_V_VSADDU_VX: {
      RVV_VI_VX_ULOOP({
        vd = vs2 + rs1;
        vd |= -(vd < vs2);
      })
      break;
    }
    case RO_V_VSUB_VX: {
      RVV_VI_VX_LOOP({ vd = vs2 - rs1; })
      break;
    }
    case RO_V_VSSUB_VX: {
      RVV_VI_GENERAL_LOOP_BASE
      bool sat = false;
      switch (rvv_vsew()) {
        case E8: {
          VX_PARAMS(8);
          vd = sat_sub<int8_t, uint8_t>(vs2, rs1, sat);
          break;
        }
        case E16: {
          VX_PARAMS(16);
          vd = sat_sub<int16_t, uint16_t>(vs2, rs1, sat);
          break;
        }
        case E32: {
          VX_PARAMS(32);
          vd = sat_sub<int32_t, uint32_t>(vs2, rs1, sat);
          break;
        }
        default: {
          VX_PARAMS(64);
          vd = sat_sub<int64_t, uint64_t>(vs2, rs1, sat);
          break;
        }
      }
      set_rvv_vxsat(sat);
      RVV_VI_LOOP_END
      break;
    }
    case RO_V_VRSUB_VX: {
      RVV_VI_VX_LOOP({ vd = rs1 - vs2; })
      break;
    }
    case RO_V_VAND_VX: {
      RVV_VI_VX_LOOP({ vd = rs1 & vs2; })
      break;
    }
    case RO_V_VOR_VX: {
      RVV_VI_VX_LOOP({ vd = rs1 | vs2; })
      break;
    }
    case RO_V_VXOR_VX: {
      RVV_VI_VX_LOOP({ vd = rs1 ^ vs2; })
      break;
    }
    case RO_V_VMAX_VX: {
      RVV_VI_VX_LOOP({
        if (rs1 <= vs2) {
          vd = vs2;
        } else {
          vd = rs1;
        }
      })
      break;
    }
    case RO_V_VMAXU_VX: {
      RVV_VI_VX_ULOOP({
        if (rs1 <= vs2) {
          vd = vs2;
        } else {
          vd = rs1;
        }
      })
      break;
    }
    case RO_V_VMINU_VX: {
      RVV_VI_VX_ULOOP({
        if (rs1 <= vs2) {
          vd = rs1;
        } else {
          vd = vs2;
        }
      })
      break;
    }
    case RO_V_VMIN_VX: {
      RVV_VI_VX_LOOP({
        if (rs1 <= vs2) {
          vd = rs1;
        } else {
          vd = vs2;
        }
      })
      break;
    }
    case RO_V_VMV_VX:
      if (instr_.RvvVM()) {
        RVV_VI_VVXI_MERGE_LOOP({
          vd = rs1;
          USE(vs1);
          USE(vs2);
          USE(simm5);
        });
      } else {
        RVV_VI_VVXI_MERGE_LOOP({
          bool use_first = (Rvvelt<uint64_t>(0, (i / 64)) >> (i % 64)) & 0x1;
          vd = use_first ? rs1 : vs2;
          USE(vs1);
          USE(simm5);
        });
      }
      break;
    case RO_V_VMSEQ_VX:
      RVV_VI_VX_LOOP_CMP({ res = vs2 == rs1; })
      break;
    case RO_V_VMSNE_VX:
      RVV_VI_VX_LOOP_CMP({ res = vs2 != rs1; })
      break;
    case RO_V_VMSLT_VX:
      RVV_VI_VX_LOOP_CMP({ res = vs2 < rs1; })
      break;
    case RO_V_VMSLTU_VX:
      RVV_VI_VX_ULOOP_CMP({ res = vs2 < rs1; })
      break;
    case RO_V_VMSLE_VX:
      RVV_VI_VX_LOOP_CMP({ res = vs2 <= rs1; })
      break;
    case RO_V_VMSLEU_VX:
      RVV_VI_VX_ULOOP_CMP({ res = vs2 <= rs1; })
      break;
    case RO_V_VMSGT_VX:
      RVV_VI_VX_LOOP_CMP({ res = vs2 > rs1; })
      break;
    case RO_V_VMSGTU_VX:
      RVV_VI_VX_ULOOP_CMP({ res = vs2 > rs1; })
      break;
    case RO_V_VSLIDEDOWN_VX: {
      RVV_VI_CHECK_SLIDE(false);

      const sreg_t sh = get_register(rs1_reg());
      RVV_VI_GENERAL_LOOP_BASE

      reg_t offset = 0;
      bool is_valid = (i + sh) < rvv_vlmax();

      if (is_valid) {
        offset = sh;
      }

      switch (rvv_vsew()) {
        case E8: {
          VI_XI_SLIDEDOWN_PARAMS(8, offset);
          vd = is_valid ? vs2 : 0;
        } break;
        case E16: {
          VI_XI_SLIDEDOWN_PARAMS(16, offset);
          vd = is_valid ? vs2 : 0;
        } break;
        case E32: {
          VI_XI_SLIDEDOWN_PARAMS(32, offset);
          vd = is_valid ? vs2 : 0;
        } break;
        default: {
          VI_XI_SLIDEDOWN_PARAMS(64, offset);
          vd = is_valid ? vs2 : 0;
        } break;
      }
      RVV_VI_LOOP_END
      rvv_trace_vd();
    } break;
    case RO_V_VSLIDEUP_VX: {
      RVV_VI_CHECK_SLIDE(true);

      const reg_t offset = get_register(rs1_reg());
      RVV_VI_GENERAL_LOOP_BASE
      if (rvv_vstart() < offset && i < offset) continue;

      switch (rvv_vsew()) {
        case E8: {
          VI_XI_SLIDEUP_PARAMS(8, offset);
          vd = vs2;
        } break;
        case E16: {
          VI_XI_SLIDEUP_PARAMS(16, offset);
          vd = vs2;
        } break;
        case E32: {
          VI_XI_SLIDEUP_PARAMS(32, offset);
          vd = vs2;
        } break;
        default: {
          VI_XI_SLIDEUP_PARAMS(64, offset);
          vd = vs2;
        } break;
      }
      RVV_VI_LOOP_END
      rvv_trace_vd();
    } break;
    case RO_V_VADC_VX:
      if (instr_.RvvVM()) {
        RVV_VI_XI_LOOP_WITH_CARRY({
          auto& v0 = Rvvelt<uint64_t>(0, midx);
          vd = rs1 + vs2 + (v0 >> mpos) & 0x1;
          USE(simm5);
        })
      } else {
        UNREACHABLE();
      }
      break;
    case RO_V_VSLL_VX: {
      RVV_VI_VX_LOOP({ vd = vs2 << (rs1 & (rvv_sew() - 1)); })
      break;
    }
    case RO_V_VSRL_VX: {
      RVV_VI_VX_ULOOP({ vd = (vs2 >> (rs1 & (rvv_sew() - 1))); })
      break;
    }
    case RO_V_VSRA_VX: {
      RVV_VI_VX_LOOP({ vd = ((vs2) >> (rs1 & (rvv_sew() - 1))); })
      break;
    }
    default:
      UNIMPLEMENTED_RISCV();
      break;
  }
}

void Simulator::DecodeRvvMVV() {
  DCHECK_EQ(instr_.InstructionBits() & (kBaseOpcodeMask | kFunct3Mask), OP_MVV);
  switch (instr_.InstructionBits() & kVTypeMask) {
    case RO_V_VMUNARY0: {
      if (instr_.Vs1Value() == VID_V) {
        CHECK(rvv_vsew() >= E8 && rvv_vsew() <= E64);
        uint8_t rd_num = rvv_vd_reg();
        require_align(rd_num, rvv_vflmul());
        require_vm;
        for (uint8_t i = rvv_vstart(); i < rvv_vl(); ++i) {
          RVV_VI_LOOP_MASK_SKIP();
          switch (rvv_vsew()) {
            case E8:
              Rvvelt<uint8_t>(rd_num, i, true) = i;
              break;
            case E16:
              Rvvelt<uint16_t>(rd_num, i, true) = i;
              break;
            case E32:
              Rvvelt<uint32_t>(rd_num, i, true) = i;
              break;
            default:
              Rvvelt<uint64_t>(rd_num, i, true) = i;
              break;
          }
        }
        set_rvv_vstart(0);
      } else {
        UNIMPLEMENTED_RISCV();
      }
      break;
    }
    case RO_V_VMUL_VV: {
      RVV_VI_VV_LOOP({ vd = vs2 * vs1; })
      break;
    }
    case RO_V_VWMUL_VV: {
      RVV_VI_CHECK_DSS(true);
      RVV_VI_VV_LOOP_WIDEN({
        VI_WIDE_OP_AND_ASSIGN(vs2, vs1, 0, *, +, int);
        USE(vd);
      })
      break;
    }
    case RO_V_VWMULU_VV: {
      RVV_VI_CHECK_DSS(true);
      RVV_VI_VV_LOOP_WIDEN({
        VI_WIDE_OP_AND_ASSIGN(vs2, vs1, 0, *, +, uint);
        USE(vd);
      })
      break;
    }
    case RO_V_VMULHU_VV: {
      RVV_VI_VV_LOOP({ vd = ((__uint128_t)vs2 * vs1) >> rvv_sew(); })
      break;
    }
    case RO_V_VMULH_VV: {
      RVV_VI_VV_LOOP({ vd = ((__int128_t)vs2 * vs1) >> rvv_sew(); })
      break;
    }
    case RO_V_VDIV_VV: {
      RVV_VI_VV_LOOP({ vd = vs2 / vs1; })
      break;
    }
    case RO_V_VDIVU_VV: {
      RVV_VI_VV_LOOP({ vd = vs2 / vs1; })
      break;
    }
    case RO_V_VWXUNARY0: {
      if (rvv_vs1_reg() == 0) {
        // vmv.x.s
        switch (rvv_vsew()) {
          case E8:
            set_rd(Rvvelt<type_sew_t<8>::type>(rvv_vs2_reg(), 0));
            break;
          case E16:
            set_rd(Rvvelt<type_sew_t<16>::type>(rvv_vs2_reg(), 0));
            break;
          case E32:
            set_rd(Rvvelt<type_sew_t<32>::type>(rvv_vs2_reg(), 0));
            break;
          case E64:
            set_rd(Rvvelt<type_sew_t<64>::type>(rvv_vs2_reg(), 0));
            break;
          default:
            UNREACHABLE();
        }
        set_rvv_vstart(0);
        rvv_trace_vd();
      } else if (rvv_vs1_reg() == 0b10000) {
        // vpopc
        reg_t cnt = 0;
        RVV_VI_GENERAL_LOOP_BASE
        RVV_VI_LOOP_MASK_SKIP()
        const uint8_t idx = i / 64;
        const uint8_t pos = i % 64;
        bool mask = (Rvvelt<uint64_t>(rvv_vs2_reg(), idx) >> pos) & 0x1;
        if (mask) cnt++;
        RVV_VI_LOOP_END
        set_register(rd_reg(), cnt);
        rvv_trace_vd();
      } else if (rvv_vs1_reg() == 0b10001) {
        // vfirst
        sreg_t index = -1;
        RVV_VI_GENERAL_LOOP_BASE
        RVV_VI_LOOP_MASK_SKIP()
        const uint8_t idx = i / 64;
        const uint8_t pos = i % 64;
        bool mask = (Rvvelt<uint64_t>(rvv_vs2_reg(), idx) >> pos) & 0x1;
        if (mask) {
          index = i;
          break;
        }
        RVV_VI_LOOP_END
        set_register(rd_reg(), index);
        rvv_trace_vd();
      } else {
        v8::base::EmbeddedVector<char, 256> buffer;
        disasm::NameConverter converter;
        disasm::Disassembler dasm(converter);
        dasm.InstructionDecode(buffer, reinterpret_cast<uint8_t*>(&instr_));
        PrintF("EXECUTING  0x%08" PRIxPTR "   %-44s\n",
               reinterpret_cast<intptr_t>(&instr_), buffer.begin());
        UNIMPLEMENTED_RISCV();
      }
    } break;
    case RO_V_VREDMAXU:
      RVV_VI_VV_ULOOP_REDUCTION(
          { vd_0_res = (vd_0_res >= vs2) ? vd_0_res : vs2; })
      break;
    case RO_V_VREDMAX:
      RVV_VI_VV_LOOP_REDUCTION(
          { vd_0_res = (vd_0_res >= vs2) ? vd_0_res : vs2; })
      break;
    case RO_V_VREDMINU:
      RVV_VI_VV_ULOOP_REDUCTION(
          { vd_0_res = (vd_0_res <= vs2) ? vd_0_res : vs2; })
      break;
    case RO_V_VREDMIN:
      RVV_VI_VV_LOOP_REDUCTION(
          { vd_0_res = (vd_0_res <= vs2) ? vd_0_res : vs2; })
      break;
    case RO_V_VXUNARY0:
      if (rvv_vs1_reg() == 0b00010) {
        RVV_VI_VIE_8_LOOP(false);
      } else if (rvv_vs1_reg() == 0b00011) {
        RVV_VI_VIE_8_LOOP(true);
      } else if (rvv_vs1_reg() == 0b00100) {
        RVV_VI_VIE_4_LOOP(false);
      } else if (rvv_vs1_reg() == 0b00101) {
        RVV_VI_VIE_4_LOOP(true);
      } else if (rvv_vs1_reg() == 0b00110) {
        RVV_VI_VIE_2_LOOP(false);
      } else if (rvv_vs1_reg() == 0b00111) {
        RVV_VI_VIE_2_LOOP(true);
      } else {
        UNSUPPORTED_RISCV();
      }
      break;
    case RO_V_VWADDU_VV:
      RVV_VI_CHECK_DSS(true);
      RVV_VI_VV_LOOP_WIDEN({
        VI_WIDE_OP_AND_ASSIGN(vs2, vs1, 0, +, +, uint);
        USE(vd);
      })
      break;
    case RO_V_VWADD_VV:
      RVV_VI_CHECK_DSS(true);
      RVV_VI_VV_LOOP_WIDEN({
        VI_WIDE_OP_AND_ASSIGN(vs2, vs1, 0, +, +, int);
        USE(vd);
      })
      break;
    case RO_V_VCOMPRESS_VV: {
      CHECK_EQ(rvv_vstart(), 0);
      require_align(rvv_vd_reg(), rvv_vflmul());
      require_align(rvv_vs2_reg(), rvv_vflmul());
      require(rvv_vd_reg() != rvv_vs2_reg());
      require_noover(rvv_vd_reg(), rvv_vflmul(), rvv_vs1_reg(), 1);

      reg_t pos = 0;

      RVV_VI_GENERAL_LOOP_BASE
      const uint64_t midx = i / 64;
      const uint64_t mpos = i % 64;

      bool do_mask = (Rvvelt<uint64_t>(rvv_vs1_reg(), midx) >> mpos) & 0x1;
      if (do_mask) {
        switch (rvv_vsew()) {
          case E8:
            Rvvelt<uint8_t>(rvv_vd_reg(), pos, true) =
                Rvvelt<uint8_t>(rvv_vs2_reg(), i);
            break;
          case E16:
            Rvvelt<uint16_t>(rvv_vd_reg(), pos, true) =
                Rvvelt<uint16_t>(rvv_vs2_reg(), i);
            break;
          case E32:
            Rvvelt<uint32_t>(rvv_vd_reg(), pos, true) =
                Rvvelt<uint32_t>(rvv_vs2_reg(), i);
            break;
          default:
            Rvvelt<uint64_t>(rvv_vd_reg(), pos, true) =
                Rvvelt<uint64_t>(rvv_vs2_reg(), i);
            break;
        }

        ++pos;
      }
      RVV_VI_LOOP_END;
      rvv_trace_vd();
    } break;
    default:
      v8::base::EmbeddedVector<char, 256> buffer;
      disasm::NameConverter converter;
      disasm::Disassembler dasm(converter);
      dasm.InstructionDecode(buffer, reinterpret_cast<uint8_t*>(&instr_));
      PrintF("EXECUTING  0x%08" PRIxPTR "   %-44s\n",
             reinterpret_cast<intptr_t>(&instr_), buffer.begin());
      UNIMPLEMENTED_RISCV();
      break;
  }
}

void Simulator::DecodeRvvMVX() {
  DCHECK_EQ(instr_.InstructionBits() & (kBaseOpcodeMask | kFunct3Mask), OP_MVX);
  switch (instr_.InstructionBits() & kVTypeMask) {
    case RO_V_VRXUNARY0:
      // vmv.s.x
      if (instr_.Vs2Value() == 0x0) {
        if (rvv_vl() > 0 && rvv_vstart() < rvv_vl()) {
          switch (rvv_vsew()) {
            case E8:
              Rvvelt<uint8_t>(rvv_vd_reg(), 0, true) =
                  (uint8_t)get_register(rs1_reg());
              break;
            case E16:
              Rvvelt<uint16_t>(rvv_vd_reg(), 0, true) =
                  (uint16_t)get_register(rs1_reg());
              break;
            case E32:
              Rvvelt<uint32_t>(rvv_vd_reg(), 0, true) =
                  (uint32_t)get_register(rs1_reg());
              break;
            case E64:
              Rvvelt<uint64_t>(rvv_vd_reg(), 0, true) =
                  (uint64_t)get_register(rs1_reg());
              break;
            default:
              UNREACHABLE();
          }
        }
        set_rvv_vstart(0);
        rvv_trace_vd();
      } else {
        UNSUPPORTED_RISCV();
      }
      break;
    case RO_V_VDIV_VX: {
      RVV_VI_VX_LOOP({ vd = vs2 / rs1; })
      break;
    }
    case RO_V_VDIVU_VX: {
      RVV_VI_VX_ULOOP({ vd = vs2 / rs1; })
      break;
    }
    case RO_V_VMUL_VX: {
      RVV_VI_VX_LOOP({ vd = vs2 * rs1; })
      break;
    }
    case RO_V_VWADDUW_VX: {
      RVV_VI_CHECK_DDS(false);
      RVV_VI_VX_LOOP_WIDEN({
        VI_WIDE_WVX_OP(rs1, +, uint);
        USE(vd);
        USE(vs2);
      })
      break;
    }
    case RO_V_VSLIDE1DOWN_VX: {
      RVV_VI_CHECK_SLIDE(false);
      RVV_VI_GENERAL_LOOP_BASE
      switch (rvv_vsew()) {
        case E8: {
          VX_SLIDE1DOWN_PARAMS(8, 1);
        } break;
        case E16: {
          VX_SLIDE1DOWN_PARAMS(16, 1);
        } break;
        case E32: {
          VX_SLIDE1DOWN_PARAMS(32, 1);
        } break;
        default: {
          VX_SLIDE1DOWN_PARAMS(64, 1);
        } break;
      }
      RVV_VI_LOOP_END
      rvv_trace_vd();
    } break;
    case RO_V_VSLIDE1UP_VX: {
      RVV_VI_CHECK_SLIDE(true);
      RVV_VI_GENERAL_LOOP_BASE
      if (i < rvv_vstart()) continue;
      switch (rvv_vsew()) {
        case E8: {
          VX_SLIDE1UP_PARAMS(8, 1);
        } break;
        case E16: {
          VX_SLIDE1UP_PARAMS(16, 1);
        } break;
        case E32: {
          VX_SLIDE1UP_PARAMS(32, 1);
        } break;
        default: {
          VX_SLIDE1UP_PARAMS(64, 1);
        } break;
      }
      RVV_VI_LOOP_END
      rvv_trace_vd();
    } break;
    default:
      v8::base::EmbeddedVector<char, 256> buffer;
      disasm::NameConverter converter;
      disasm::Disassembler dasm(converter);
      dasm.InstructionDecode(buffer, reinterpret_cast<uint8_t*>(&instr_));
      PrintF("EXECUTING  0x%08" PRIxPTR "   %-44s\n",
             reinterpret_cast<intptr_t>(&instr_), buffer.begin());
      UNIMPLEMENTED_RISCV();
      break;
  }
}

void Simulator::DecodeRvvFVV() {
  DCHECK_EQ(instr_.InstructionBits() & (kBaseOpcodeMask | kFunct3Mask), OP_FVV);
  switch (instr_.InstructionBits() & kVTypeMask) {
    case RO_V_VFDIV_VV: {
      RVV_VI_VFP_VV_LOOP(
          { UNIMPLEMENTED(); },
          {
            // TODO(riscv): use rm value (round mode)
            auto fn = [this](float vs1, float vs2) {
              if (is_invalid_fdiv(vs1, vs2)) {
                this->set_fflags(kInvalidOperation);
                return std::numeric_limits<float>::quiet_NaN();
              } else if (vs1 == 0.0f) {
                this->set_fflags(kDivideByZero);
                return (std::signbit(vs1) == std::signbit(vs2)
                            ? std::numeric_limits<float>::infinity()
                            : -std::numeric_limits<float>::infinity());
              } else {
                return vs2 / vs1;
              }
            };
            auto alu_out = fn(vs1, vs2);
            // if any input or result is NaN, the result is quiet_NaN
            if (std::isnan(alu_out) || std::isnan(vs1) || std::isnan(vs2)) {
              // signaling_nan sets kInvalidOperation bit
              if (isSnan(alu_out) || isSnan(vs1) || isSnan(vs2))
                set_fflags(kInvalidOperation);
              alu_out = std::numeric_limits<float>::quiet_NaN();
            }
            vd = alu_out;
          },
          {
            // TODO(riscv): use rm value (round mode)
            auto fn = [this](double vs1, double vs2) {
              if (is_invalid_fdiv(vs1, vs2)) {
                this->set_fflags(kInvalidOperation);
                return std::numeric_limits<double>::quiet_NaN();
              } else if (vs1 == 0.0f) {
                this->set_fflags(kDivideByZero);
                return (std::signbit(vs1) == std::signbit(vs2)
                            ? std::numeric_limits<double>::infinity()
                            : -std::numeric_limits<double>::infinity());
              } else {
                return vs2 / vs1;
              }
            };
            auto alu_out = fn(vs1, vs2);
            // if any input or result is NaN, the result is quiet_NaN
            if (std::isnan(alu_out) || std::isnan(vs1) || std::isnan(vs2)) {
              // signaling_nan sets kInvalidOperation bit
              if (isSnan(alu_out) || isSnan(vs1) || isSnan(vs2))
                set_fflags(kInvalidOperation);
              alu_out = std::numeric_limits<double>::quiet_NaN();
            }
            vd = alu_out;
          })
      break;
    }
    case RO_V_VFMUL_VV: {
      RVV_VI_VFP_VV_LOOP(
          { UNIMPLEMENTED(); },
          {
            // TODO(riscv): use rm value (round mode)
            auto fn = [this](double drs1, double drs2) {
              if (is_invalid_fmul(drs1, drs2)) {
                this->set_fflags(kInvalidOperation);
                return std::numeric_limits<double>::quiet_NaN();
              } else {
                return drs1 * drs2;
              }
            };
            auto alu_out = fn(vs1, vs2);
            // if any input or result is NaN, the result is quiet_NaN
            if (std::isnan(alu_out) || std::isnan(vs1) || std::isnan(vs2)) {
              // signaling_nan sets kInvalidOperation bit
              if (isSnan(alu_out) || isSnan(vs1) || isSnan(vs2))
                set_fflags(kInvalidOperation);
              alu_out = std::numeric_limits<float>::quiet_NaN();
            }
            vd = alu_out;
          },
          {
            // TODO(riscv): use rm value (round mode)
            auto fn = [this](double drs1, double drs2) {
              if (is_invalid_fmul(drs1, drs2)) {
                this->set_fflags(kInvalidOperation);
                return std::numeric_limits<double>::quiet_NaN();
              } else {
                return drs1 * drs2;
              }
            };
            auto alu_out = fn(vs1, vs2);
            // if any input or result is NaN, the result is quiet_NaN
            if (std::isnan(alu_out) || std::isnan(vs1) || std::isnan(vs2)) {
              // signaling_nan sets kInvalidOperation bit
              if (isSnan(alu_out) || isSnan(vs1) || isSnan(vs2))
                set_fflags(kInvalidOperation);
              alu_out = std::numeric_limits<double>::quiet_NaN();
            }
            vd = alu_out;
          })
      break;
    }
    case RO_V_VFUNARY0:
      switch (instr_.Vs1Value()) {
        case VFCVT_X_F_V:
          RVV_VI_VFP_VF_LOOP(
              { UNIMPLEMENTED(); },
              {
                Rvvelt<int32_t>(rvv_vd_reg(), i) =
                    RoundF2IHelper<int32_t>(vs2, read_csr_value(csr_frm));
                USE(vd);
                USE(fs1);
              },
              {
                Rvvelt<int64_t>(rvv_vd_reg(), i) =
                    RoundF2IHelper<int64_t>(vs2, read_csr_value(csr_frm));
                USE(vd);
                USE(fs1);
              })
          break;
        case VFCVT_XU_F_V:
          RVV_VI_VFP_VF_LOOP(
              { UNIMPLEMENTED(); },
              {
                Rvvelt<uint32_t>(rvv_vd_reg(), i) =
                    RoundF2IHelper<uint32_t>(vs2, read_csr_value(csr_frm));
                USE(vd);
                USE(fs1);
              },
              {
                Rvvelt<uint64_t>(rvv_vd_reg(), i) =
                    RoundF2IHelper<uint64_t>(vs2, read_csr_value(csr_frm));
                USE(vd);
                USE(fs1);
              })
          break;
        case VFCVT_F_XU_V:
          RVV_VI_VFP_VF_LOOP({ UNIMPLEMENTED(); },
                             {
                               auto vs2_i = Rvvelt<uint32_t>(rvv_vs2_reg(), i);
                               vd = static_cast<float>(vs2_i);
                               USE(vs2);
                               USE(fs1);
                             },
                             {
                               auto vs2_i = Rvvelt<uint64_t>(rvv_vs2_reg(), i);
                               vd = static_cast<double>(vs2_i);
                               USE(vs2);
                               USE(fs1);
                             })
          break;
        case VFCVT_F_X_V:
          RVV_VI_VFP_VF_LOOP({ UNIMPLEMENTED(); },
                             {
                               auto vs2_i = Rvvelt<int32_t>(rvv_vs2_reg(), i);
                               vd = static_cast<float>(vs2_i);
                               USE(vs2);
                               USE(fs1);
                             },
                             {
                               auto vs2_i = Rvvelt<int64_t>(rvv_vs2_reg(), i);
                               vd = static_cast<double>(vs2_i);
                               USE(vs2);
                               USE(fs1);
                             })
          break;
        case VFNCVT_F_F_W:
          RVV_VI_VFP_CVT_SCALE(
              { UNREACHABLE(); }, { UNREACHABLE(); },
              {
                auto vs2 = Rvvelt<double>(rvv_vs2_reg(), i);
                Rvvelt<float>(rvv_vd_reg(), i, true) =
                    CanonicalizeDoubleToFloatOperation(
                        [](double drs) { return static_cast<float>(drs); },
                        vs2);
              },
              { ; }, { ; }, { ; }, false, (rvv_vsew() >= E16))
          break;
        case VFNCVT_X_F_W:
          RVV_VI_VFP_CVT_SCALE(
              { UNREACHABLE(); }, { UNREACHABLE(); },
              {
                auto vs2 = Rvvelt<double>(rvv_vs2_reg(), i);
                int32_t& vd = Rvvelt<int32_t>(rvv_vd_reg(), i, true);
                vd = RoundF2IHelper<int32_t>(vs2, read_csr_value(csr_frm));
              },
              { ; }, { ; }, { ; }, false, (rvv_vsew() <= E32))
          break;
        case VFNCVT_XU_F_W:
          RVV_VI_VFP_CVT_SCALE(
              { UNREACHABLE(); }, { UNREACHABLE(); },
              {
                auto vs2 = Rvvelt<double>(rvv_vs2_reg(), i);
                uint32_t& vd = Rvvelt<uint32_t>(rvv_vd_reg(), i, true);
                vd = RoundF2IHelper<uint32_t>(vs2, read_csr_value(csr_frm));
              },
              { ; }, { ; }, { ; }, false, (rvv_vsew() <= E32))
          break;
        case VFWCVT_F_X_V:
          RVV_VI_VFP_CVT_SCALE({ UNREACHABLE(); },
                               {
                                 auto vs2 = Rvvelt<int16_t>(rvv_vs2_reg(), i);
                                 Rvvelt<float32_t>(rvv_vd_reg(), i, true) =
                                     static_cast<float>(vs2);
                               },
                               {
                                 auto vs2 = Rvvelt<int32_t>(rvv_vs2_reg(), i);
                                 Rvvelt<double>(rvv_vd_reg(), i, true) =
                                     static_cast<double>(vs2);
                               },
                               { ; }, { ; }, { ; }, true, (rvv_vsew() >= E8))
          break;
        case VFWCVT_F_XU_V:
          RVV_VI_VFP_CVT_SCALE({ UNREACHABLE(); },
                               {
                                 auto vs2 = Rvvelt<uint16_t>(rvv_vs2_reg(), i);
                                 Rvvelt<float32_t>(rvv_vd_reg(), i, true) =
                                     static_cast<float>(vs2);
                               },
                               {
                                 auto vs2 = Rvvelt<uint32_t>(rvv_vs2_reg(), i);
                                 Rvvelt<double>(rvv_vd_reg(), i, true) =
                                     static_cast<double>(vs2);
                               },
                               { ; }, { ; }, { ; }, true, (rvv_vsew() >= E8))
          break;
        case VFWCVT_XU_F_V:
          RVV_VI_VFP_CVT_SCALE({ UNREACHABLE(); }, { UNREACHABLE(); },
                               {
                                 auto vs2 = Rvvelt<float32_t>(rvv_vs2_reg(), i);
                                 Rvvelt<uint64_t>(rvv_vd_reg(), i, true) =
                                     static_cast<uint64_t>(vs2);
                               },
                               { ; }, { ; }, { ; }, true, (rvv_vsew() >= E16))
          break;
        case VFWCVT_X_F_V:
          RVV_VI_VFP_CVT_SCALE({ UNREACHABLE(); }, { UNREACHABLE(); },
                               {
                                 auto vs2 = Rvvelt<float32_t>(rvv_vs2_reg(), i);
                                 Rvvelt<int64_t>(rvv_vd_reg(), i, true) =
                                     static_cast<int64_t>(vs2);
                               },
                               { ; }, { ; }, { ; }, true, (rvv_vsew() >= E16))
          break;
        case VFWCVT_F_F_V:
          RVV_VI_VFP_CVT_SCALE({ UNREACHABLE(); }, { UNREACHABLE(); },
                               {
                                 auto vs2 = Rvvelt<float32_t>(rvv_vs2_reg(), i);
                                 Rvvelt<double>(rvv_vd_reg(), i, true) =
                                     static_cast<double>(vs2);
                               },
                               { ; }, { ; }, { ; }, true, (rvv_vsew() >= E16))
          break;
        default:
          UNSUPPORTED_RISCV();
      }
      break;
    case RO_V_VFUNARY1:
      switch (instr_.Vs1Value()) {
        case VFCLASS_V:
          RVV_VI_VFP_VF_LOOP(
              { UNIMPLEMENTED(); },
              {
                int32_t& vd_i = Rvvelt<int32_t>(rvv_vd_reg(), i, true);
                vd_i = int32_t(FclassHelper(vs2));
                USE(fs1);
                USE(vd);
              },
              {
                int64_t& vd_i = Rvvelt<int64_t>(rvv_vd_reg(), i, true);
                vd_i = FclassHelper(vs2);
                USE(fs1);
                
"""


```