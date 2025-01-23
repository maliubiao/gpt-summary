Response: The user wants a summary of the provided C++ code. This is the third part of a five-part series, so the summary should focus on the functionality within this specific chunk of code.

The code seems to be part of a MIPS64 simulator. It defines methods for decoding and executing various MIPS64 instructions. The code handles different instruction types, including:

*   **COP1 instructions:** Floating-point operations.
*   **SPECIAL instructions:** Integer arithmetic, logical operations, shifts, jumps, and conditional moves.
*   **SPECIAL2 and SPECIAL3 instructions:** More integer and bit manipulation instructions.
*   **MSA instructions:** Media Streaming Application (MSA) instructions for SIMD operations.

The functionality involves fetching operands from registers, performing the operation, and writing the result back to registers or memory. It also handles potential exceptions like integer overflow.

Considering it's part 3, the functionality likely builds upon what was in parts 1 and 2 and will be further extended in parts 4 and 5.

Regarding the relationship with JavaScript, the simulator is likely used in the V8 JavaScript engine to execute JavaScript code on MIPS64 architectures. I can provide JavaScript examples that would translate to the MIPS64 instructions handled in this code.
这是v8/src/execution/mips64/simulator-mips64.cc文件的第三部分，主要负责MIPS64架构模拟器的**指令解码和执行**，特别是针对以下类型的指令：

*   **COP1类指令:**  用于执行浮点运算，例如加载和存储浮点数到FPU寄存器，以及执行浮点数的加法、减法、乘法等。
*   **SPECIAL类指令:**  用于执行各种整数运算，包括算术运算（加减乘除）、逻辑运算（与或非异或）、移位操作、跳转指令（包括带链接的跳转）、以及条件移动指令。
*   **SPECIAL2和SPECIAL3类指令:**  包含一些更特定的整数和位操作指令，例如计算前导零、位段提取和插入、字节和半字操作等。
*   **MSA (Media Streaming Application) 指令:** 用于执行SIMD (单指令多数据) 操作，涉及到向量化的算术、逻辑、移位、比较以及加载和存储操作。

**与JavaScript的关系:**

V8 JavaScript引擎使用这种模拟器来在不支持MIPS64硬件的平台上运行JavaScript代码，或者用于测试和调试MIPS64架构上的JavaScript代码。当V8需要执行一段JavaScript代码时，它会将其编译成MIPS64机器码（或者其内部表示），然后模拟器会逐条解释和执行这些机器码。

以下是一些JavaScript代码示例，以及它们可能在模拟器中对应的MIPS64指令类型（在第三部分代码中出现的指令）：

**1. 浮点数操作:**

```javascript
let a = 1.5;
let b = 2.5;
let sum = a + b;
```

这在模拟器中可能涉及到 `LDC1` (加载双精度浮点数到FPU寄存器) 和 `ADD.D` (双精度浮点数加法) 指令。

**2. 整数算术和逻辑操作:**

```javascript
let x = 10;
let y = 5;
let product = x * y;
let andResult = x & y;
```

这可能涉及到 `LD` (加载整数到通用寄存器), `DMULT` (64位整数乘法 - 结果可能存放在HI和LO寄存器中), `AND` (按位与) 指令。

**3. 位移操作:**

```javascript
let num = 8; // 二进制 1000
let shifted = num << 2; // 左移两位，二进制 100000
```

这可能涉及到 `DSLL` (64位逻辑左移) 指令。

**4. 条件判断和跳转:**

```javascript
let count = 0;
if (count < 10) {
  count++;
}
```

这可能涉及到 `BEQZ` (如果等于零则跳转), `BNEZ` (如果不等于零则跳转), `DADD` (64位整数加法) 指令。

**5. MSA (SIMD) 操作 (如果JavaScript引擎使用了MSA扩展):**

虽然JavaScript本身没有直接的MSA语法，但底层的实现可能会利用SIMD指令来加速某些操作，例如数组元素的并行处理。

```javascript
let arr1 = [1, 2, 3, 4];
let arr2 = [5, 6, 7, 8];
// 假设底层使用了SIMD指令进行并行加法
let resultArr = arr1.map((v, i) => v + arr2[i]);
```

这在模拟器中可能涉及到 `ADDU_W.QB` (MSA字节向量加法) 或类似的MSA指令。

**总结来说，这部分代码是MIPS64模拟器的核心执行单元，负责将MIPS64指令翻译成模拟器可以理解和执行的操作。它对于V8引擎在MIPS64架构上的运行至关重要。**

### 提示词
```
这是目录为v8/src/execution/mips64/simulator-mips64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```
er);
      uint32_t reg = static_cast<uint32_t>(rt());
      if (kArchVariant == kMips64r6) {
        FCSR_ = reg | kFCSRNaN2008FlagMask;
      } else {
        DCHECK_EQ(kArchVariant, kMips64r2);
        FCSR_ = reg & ~kFCSRNaN2008FlagMask;
      }
      TraceRegWr(FCSR_);
      break;
    }
    case MTC1:
      // Hardware writes upper 32-bits to zero on mtc1.
      set_fpu_register_hi_word(fs_reg(), 0);
      set_fpu_register_word(fs_reg(), static_cast<int32_t>(rt()));
      TraceRegWr(get_fpu_register(fs_reg()), FLOAT_DOUBLE);
      break;
    case DMTC1:
      SetFPUResult2(fs_reg(), rt());
      break;
    case MTHC1:
      set_fpu_register_hi_word(fs_reg(), static_cast<int32_t>(rt()));
      TraceRegWr(get_fpu_register(fs_reg()), DOUBLE);
      break;
    case S:
      DecodeTypeRegisterSRsType();
      break;
    case D:
      DecodeTypeRegisterDRsType();
      break;
    case W:
      DecodeTypeRegisterWRsType();
      break;
    case L:
      DecodeTypeRegisterLRsType();
      break;
    default:
      UNREACHABLE();
  }
}

void Simulator::DecodeTypeRegisterCOP1X() {
  switch (instr_.FunctionFieldRaw()) {
    case MADD_S: {
      DCHECK_EQ(kArchVariant, kMips64r2);
      float fr, ft, fs;
      fr = get_fpu_register_float(fr_reg());
      fs = get_fpu_register_float(fs_reg());
      ft = get_fpu_register_float(ft_reg());
      SetFPUFloatResult(fd_reg(), fs * ft + fr);
      break;
    }
    case MSUB_S: {
      DCHECK_EQ(kArchVariant, kMips64r2);
      float fr, ft, fs;
      fr = get_fpu_register_float(fr_reg());
      fs = get_fpu_register_float(fs_reg());
      ft = get_fpu_register_float(ft_reg());
      SetFPUFloatResult(fd_reg(), fs * ft - fr);
      break;
    }
    case MADD_D: {
      DCHECK_EQ(kArchVariant, kMips64r2);
      double fr, ft, fs;
      fr = get_fpu_register_double(fr_reg());
      fs = get_fpu_register_double(fs_reg());
      ft = get_fpu_register_double(ft_reg());
      SetFPUDoubleResult(fd_reg(), fs * ft + fr);
      break;
    }
    case MSUB_D: {
      DCHECK_EQ(kArchVariant, kMips64r2);
      double fr, ft, fs;
      fr = get_fpu_register_double(fr_reg());
      fs = get_fpu_register_double(fs_reg());
      ft = get_fpu_register_double(ft_reg());
      SetFPUDoubleResult(fd_reg(), fs * ft - fr);
      break;
    }
    default:
      UNREACHABLE();
  }
}

void Simulator::DecodeTypeRegisterSPECIAL() {
  int64_t i64hilo;
  uint64_t u64hilo;
  int64_t alu_out;
  bool do_interrupt = false;

  switch (instr_.FunctionFieldRaw()) {
    case SELEQZ_S:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetResult(rd_reg(), rt() == 0 ? rs() : 0);
      break;
    case SELNEZ_S:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetResult(rd_reg(), rt() != 0 ? rs() : 0);
      break;
    case JR: {
      int64_t next_pc = rs();
      int64_t current_pc = get_pc();
      Instruction* branch_delay_instr =
          reinterpret_cast<Instruction*>(current_pc + kInstrSize);
      BranchDelayInstructionDecode(branch_delay_instr);
      set_pc(next_pc);
      pc_modified_ = true;
      break;
    }
    case JALR: {
      int64_t next_pc = rs();
      int64_t current_pc = get_pc();
      int32_t return_addr_reg = rd_reg();
      Instruction* branch_delay_instr =
          reinterpret_cast<Instruction*>(current_pc + kInstrSize);
      BranchDelayInstructionDecode(branch_delay_instr);
      set_register(return_addr_reg, current_pc + 2 * kInstrSize);
      set_pc(next_pc);
      pc_modified_ = true;
      break;
    }
    case SLL:
      SetResult(rd_reg(), static_cast<int32_t>(rt()) << sa());
      break;
    case DSLL:
      SetResult(rd_reg(), rt() << sa());
      break;
    case DSLL32:
      SetResult(rd_reg(), rt() << sa() << 32);
      break;
    case SRL:
      if (rs_reg() == 0) {
        // Regular logical right shift of a word by a fixed number of
        // bits instruction. RS field is always equal to 0.
        // Sign-extend the 32-bit result.
        alu_out = static_cast<int32_t>(static_cast<uint32_t>(rt_u()) >> sa());
      } else if (rs_reg() == 1) {
        // Logical right-rotate of a word by a fixed number of bits. This
        // is special case of SRL instruction, added in MIPS32 Release 2.
        // RS field is equal to 00001.
        alu_out = static_cast<int32_t>(
            base::bits::RotateRight32(static_cast<const uint32_t>(rt_u()),
                                      static_cast<const uint32_t>(sa())));
      } else {
        UNREACHABLE();
      }
      SetResult(rd_reg(), alu_out);
      break;
    case DSRL:
      if (rs_reg() == 0) {
        // Regular logical right shift of a word by a fixed number of
        // bits instruction. RS field is always equal to 0.
        // Sign-extend the 64-bit result.
        alu_out = static_cast<int64_t>(rt_u() >> sa());
      } else if (rs_reg() == 1) {
        // Logical right-rotate of a word by a fixed number of bits. This
        // is special case of SRL instruction, added in MIPS32 Release 2.
        // RS field is equal to 00001.
        alu_out = static_cast<int64_t>(base::bits::RotateRight64(rt_u(), sa()));
      } else {
        UNREACHABLE();
      }
      SetResult(rd_reg(), alu_out);
      break;
    case DSRL32:
      if (rs_reg() == 0) {
        // Regular logical right shift of a word by a fixed number of
        // bits instruction. RS field is always equal to 0.
        // Sign-extend the 64-bit result.
        alu_out = static_cast<int64_t>(rt_u() >> sa() >> 32);
      } else if (rs_reg() == 1) {
        // Logical right-rotate of a word by a fixed number of bits. This
        // is special case of SRL instruction, added in MIPS32 Release 2.
        // RS field is equal to 00001.
        alu_out =
            static_cast<int64_t>(base::bits::RotateRight64(rt_u(), sa() + 32));
      } else {
        UNREACHABLE();
      }
      SetResult(rd_reg(), alu_out);
      break;
    case SRA:
      SetResult(rd_reg(), (int32_t)rt() >> sa());
      break;
    case DSRA:
      SetResult(rd_reg(), rt() >> sa());
      break;
    case DSRA32:
      SetResult(rd_reg(), rt() >> sa() >> 32);
      break;
    case SLLV:
      SetResult(rd_reg(), (int32_t)rt() << rs());
      break;
    case DSLLV:
      SetResult(rd_reg(), rt() << rs());
      break;
    case SRLV:
      if (sa() == 0) {
        // Regular logical right-shift of a word by a variable number of
        // bits instruction. SA field is always equal to 0.
        alu_out = static_cast<int32_t>((uint32_t)rt_u() >> rs());
      } else {
        // Logical right-rotate of a word by a variable number of bits.
        // This is special case od SRLV instruction, added in MIPS32
        // Release 2. SA field is equal to 00001.
        alu_out = static_cast<int32_t>(
            base::bits::RotateRight32(static_cast<const uint32_t>(rt_u()),
                                      static_cast<const uint32_t>(rs_u())));
      }
      SetResult(rd_reg(), alu_out);
      break;
    case DSRLV:
      if (sa() == 0) {
        // Regular logical right-shift of a word by a variable number of
        // bits instruction. SA field is always equal to 0.
        alu_out = static_cast<int64_t>(rt_u() >> rs());
      } else {
        // Logical right-rotate of a word by a variable number of bits.
        // This is special case od SRLV instruction, added in MIPS32
        // Release 2. SA field is equal to 00001.
        alu_out =
            static_cast<int64_t>(base::bits::RotateRight64(rt_u(), rs_u()));
      }
      SetResult(rd_reg(), alu_out);
      break;
    case SRAV:
      SetResult(rd_reg(), (int32_t)rt() >> rs());
      break;
    case DSRAV:
      SetResult(rd_reg(), rt() >> rs());
      break;
    case LSA: {
      DCHECK_EQ(kArchVariant, kMips64r6);
      int8_t sa = lsa_sa() + 1;
      int32_t _rt = static_cast<int32_t>(rt());
      int32_t _rs = static_cast<int32_t>(rs());
      int32_t res = _rs << sa;
      res += _rt;
      SetResult(rd_reg(), static_cast<int64_t>(res));
      break;
    }
    case DLSA:
      DCHECK_EQ(kArchVariant, kMips64r6);
      SetResult(rd_reg(), (rs() << (lsa_sa() + 1)) + rt());
      break;
    case MFHI:  // MFHI == CLZ on R6.
      if (kArchVariant != kMips64r6) {
        DCHECK_EQ(sa(), 0);
        alu_out = get_register(HI);
      } else {
        // MIPS spec: If no bits were set in GPR rs(), the result written to
        // GPR rd() is 32.
        DCHECK_EQ(sa(), 1);
        alu_out = base::bits::CountLeadingZeros32(static_cast<int32_t>(rs_u()));
      }
      SetResult(rd_reg(), alu_out);
      break;
    case MFLO:  // MFLO == DCLZ on R6.
      if (kArchVariant != kMips64r6) {
        DCHECK_EQ(sa(), 0);
        alu_out = get_register(LO);
      } else {
        // MIPS spec: If no bits were set in GPR rs(), the result written to
        // GPR rd() is 64.
        DCHECK_EQ(sa(), 1);
        alu_out = base::bits::CountLeadingZeros64(static_cast<int64_t>(rs_u()));
      }
      SetResult(rd_reg(), alu_out);
      break;
    // Instructions using HI and LO registers.
    case MULT: {  // MULT == D_MUL_MUH.
      int32_t rs_lo = static_cast<int32_t>(rs());
      int32_t rt_lo = static_cast<int32_t>(rt());
      i64hilo = static_cast<int64_t>(rs_lo) * static_cast<int64_t>(rt_lo);
      if (kArchVariant != kMips64r6) {
        set_register(LO, static_cast<int32_t>(i64hilo & 0xFFFFFFFF));
        set_register(HI, static_cast<int32_t>(i64hilo >> 32));
      } else {
        switch (sa()) {
          case MUL_OP:
            SetResult(rd_reg(), static_cast<int32_t>(i64hilo & 0xFFFFFFFF));
            break;
          case MUH_OP:
            SetResult(rd_reg(), static_cast<int32_t>(i64hilo >> 32));
            break;
          default:
            UNIMPLEMENTED_MIPS();
            break;
        }
      }
      break;
    }
    case MULTU:
      u64hilo = static_cast<uint64_t>(rs_u() & 0xFFFFFFFF) *
                static_cast<uint64_t>(rt_u() & 0xFFFFFFFF);
      if (kArchVariant != kMips64r6) {
        set_register(LO, static_cast<int32_t>(u64hilo & 0xFFFFFFFF));
        set_register(HI, static_cast<int32_t>(u64hilo >> 32));
      } else {
        switch (sa()) {
          case MUL_OP:
            SetResult(rd_reg(), static_cast<int32_t>(u64hilo & 0xFFFFFFFF));
            break;
          case MUH_OP:
            SetResult(rd_reg(), static_cast<int32_t>(u64hilo >> 32));
            break;
          default:
            UNIMPLEMENTED_MIPS();
            break;
        }
      }
      break;
    case DMULT:  // DMULT == D_MUL_MUH.
      if (kArchVariant != kMips64r6) {
        set_register(LO, rs() * rt());
        set_register(HI, base::bits::SignedMulHigh64(rs(), rt()));
      } else {
        switch (sa()) {
          case MUL_OP:
            SetResult(rd_reg(), rs() * rt());
            break;
          case MUH_OP:
            SetResult(rd_reg(), base::bits::SignedMulHigh64(rs(), rt()));
            break;
          default:
            UNIMPLEMENTED_MIPS();
            break;
        }
      }
      break;
    case DMULTU:
      if (kArchVariant != kMips64r6) {
        set_register(LO, rs_u() * rt_u());
        set_register(HI, base::bits::UnsignedMulHigh64(rs_u(), rt_u()));
      } else {
        UNIMPLEMENTED_MIPS();
      }
      break;
    case DIV:
    case DDIV: {
      const int64_t int_min_value =
          instr_.FunctionFieldRaw() == DIV ? INT_MIN : LONG_MIN;
      switch (kArchVariant) {
        case kMips64r2:
          // Divide by zero and overflow was not checked in the
          // configuration step - div and divu do not raise exceptions. On
          // division by 0 the result will be UNPREDICTABLE. On overflow
          // (INT_MIN/-1), return INT_MIN which is what the hardware does.
          if (rs() == int_min_value && rt() == -1) {
            set_register(LO, int_min_value);
            set_register(HI, 0);
          } else if (rt() != 0) {
            set_register(LO, rs() / rt());
            set_register(HI, rs() % rt());
          }
          break;
        case kMips64r6:
          switch (sa()) {
            case DIV_OP:
              if (rs() == int_min_value && rt() == -1) {
                SetResult(rd_reg(), int_min_value);
              } else if (rt() != 0) {
                SetResult(rd_reg(), rs() / rt());
              }
              break;
            case MOD_OP:
              if (rs() == int_min_value && rt() == -1) {
                SetResult(rd_reg(), 0);
              } else if (rt() != 0) {
                SetResult(rd_reg(), rs() % rt());
              }
              break;
            default:
              UNIMPLEMENTED_MIPS();
              break;
          }
          break;
        default:
          break;
      }
      break;
    }
    case DIVU:
      switch (kArchVariant) {
        case kMips64r6: {
          uint32_t rt_u_32 = static_cast<uint32_t>(rt_u());
          uint32_t rs_u_32 = static_cast<uint32_t>(rs_u());
          switch (sa()) {
            case DIV_OP:
              if (rt_u_32 != 0) {
                SetResult(rd_reg(), static_cast<int32_t>(rs_u_32 / rt_u_32));
              }
              break;
            case MOD_OP:
              if (rt_u() != 0) {
                SetResult(rd_reg(), static_cast<int32_t>(rs_u_32 % rt_u_32));
              }
              break;
            default:
              UNIMPLEMENTED_MIPS();
              break;
          }
        } break;
        default: {
          if (rt_u() != 0) {
            uint32_t rt_u_32 = static_cast<uint32_t>(rt_u());
            uint32_t rs_u_32 = static_cast<uint32_t>(rs_u());
            set_register(LO, static_cast<int32_t>(rs_u_32 / rt_u_32));
            set_register(HI, static_cast<int32_t>(rs_u_32 % rt_u_32));
          }
        }
      }
      break;
    case DDIVU:
      switch (kArchVariant) {
        case kMips64r6: {
          switch (instr_.SaValue()) {
            case DIV_OP:
              if (rt_u() != 0) {
                SetResult(rd_reg(), rs_u() / rt_u());
              }
              break;
            case MOD_OP:
              if (rt_u() != 0) {
                SetResult(rd_reg(), rs_u() % rt_u());
              }
              break;
            default:
              UNIMPLEMENTED_MIPS();
              break;
          }
        } break;
        default: {
          if (rt_u() != 0) {
            set_register(LO, rs_u() / rt_u());
            set_register(HI, rs_u() % rt_u());
          }
        }
      }
      break;
    case ADD:
    case DADD:
      if (HaveSameSign(rs(), rt())) {
        if (rs() > 0) {
          if (rs() > (Registers::kMaxValue - rt())) {
            SignalException(kIntegerOverflow);
          }
        } else if (rs() < 0) {
          if (rs() < (Registers::kMinValue - rt())) {
            SignalException(kIntegerUnderflow);
          }
        }
      }
      SetResult(rd_reg(), rs() + rt());
      break;
    case ADDU: {
      int32_t alu32_out = static_cast<int32_t>(rs() + rt());
      // Sign-extend result of 32bit operation into 64bit register.
      SetResult(rd_reg(), static_cast<int64_t>(alu32_out));
      break;
    }
    case DADDU:
      SetResult(rd_reg(), rs() + rt());
      break;
    case SUB:
    case DSUB:
      if (!HaveSameSign(rs(), rt())) {
        if (rs() > 0) {
          if (rs() > (Registers::kMaxValue + rt())) {
            SignalException(kIntegerOverflow);
          }
        } else if (rs() < 0) {
          if (rs() < (Registers::kMinValue + rt())) {
            SignalException(kIntegerUnderflow);
          }
        }
      }
      SetResult(rd_reg(), rs() - rt());
      break;
    case SUBU: {
      int32_t alu32_out = static_cast<int32_t>(rs() - rt());
      // Sign-extend result of 32bit operation into 64bit register.
      SetResult(rd_reg(), static_cast<int64_t>(alu32_out));
      break;
    }
    case DSUBU:
      SetResult(rd_reg(), rs() - rt());
      break;
    case AND:
      SetResult(rd_reg(), rs() & rt());
      break;
    case OR:
      SetResult(rd_reg(), rs() | rt());
      break;
    case XOR:
      SetResult(rd_reg(), rs() ^ rt());
      break;
    case NOR:
      SetResult(rd_reg(), ~(rs() | rt()));
      break;
    case SLT:
      SetResult(rd_reg(), rs() < rt() ? 1 : 0);
      break;
    case SLTU:
      SetResult(rd_reg(), rs_u() < rt_u() ? 1 : 0);
      break;
    // Break and trap instructions.
    case BREAK:
      do_interrupt = true;
      break;
    case TGE:
      do_interrupt = rs() >= rt();
      break;
    case TGEU:
      do_interrupt = rs_u() >= rt_u();
      break;
    case TLT:
      do_interrupt = rs() < rt();
      break;
    case TLTU:
      do_interrupt = rs_u() < rt_u();
      break;
    case TEQ:
      do_interrupt = rs() == rt();
      break;
    case TNE:
      do_interrupt = rs() != rt();
      break;
    case SYNC:
      // TODO(palfia): Ignore sync instruction for now.
      break;
    // Conditional moves.
    case MOVN:
      if (rt()) {
        SetResult(rd_reg(), rs());
      }
      break;
    case MOVCI: {
      uint32_t cc = instr_.FBccValue();
      uint32_t fcsr_cc = get_fcsr_condition_bit(cc);
      if (instr_.Bit(16)) {  // Read Tf bit.
        if (test_fcsr_bit(fcsr_cc)) SetResult(rd_reg(), rs());
      } else {
        if (!test_fcsr_bit(fcsr_cc)) SetResult(rd_reg(), rs());
      }
      break;
    }
    case MOVZ:
      if (!rt()) {
        SetResult(rd_reg(), rs());
      }
      break;
    default:
      UNREACHABLE();
  }
  if (do_interrupt) {
    SoftwareInterrupt();
  }
}

void Simulator::DecodeTypeRegisterSPECIAL2() {
  int64_t alu_out;
  switch (instr_.FunctionFieldRaw()) {
    case MUL:
      alu_out = static_cast<int32_t>(rs_u()) * static_cast<int32_t>(rt_u());
      SetResult(rd_reg(), alu_out);
      // HI and LO are UNPREDICTABLE after the operation.
      set_register(LO, Unpredictable);
      set_register(HI, Unpredictable);
      break;
    case CLZ:
      // MIPS32 spec: If no bits were set in GPR rs(), the result written to
      // GPR rd is 32.
      alu_out = base::bits::CountLeadingZeros32(static_cast<uint32_t>(rs_u()));
      SetResult(rd_reg(), alu_out);
      break;
    case DCLZ:
      // MIPS64 spec: If no bits were set in GPR rs(), the result written to
      // GPR rd is 64.
      alu_out = base::bits::CountLeadingZeros64(static_cast<uint64_t>(rs_u()));
      SetResult(rd_reg(), alu_out);
      break;
    default:
      alu_out = 0x12345678;
      UNREACHABLE();
  }
}

void Simulator::DecodeTypeRegisterSPECIAL3() {
  int64_t alu_out;
  switch (instr_.FunctionFieldRaw()) {
    case EXT: {  // Mips32r2 instruction.
      // Interpret rd field as 5-bit msbd of extract.
      uint16_t msbd = rd_reg();
      // Interpret sa field as 5-bit lsb of extract.
      uint16_t lsb = sa();
      uint16_t size = msbd + 1;
      uint64_t mask = (1ULL << size) - 1;
      alu_out = static_cast<int32_t>((rs_u() & (mask << lsb)) >> lsb);
      SetResult(rt_reg(), alu_out);
      break;
    }
    case DEXT: {  // Mips64r2 instruction.
      // Interpret rd field as 5-bit msbd of extract.
      uint16_t msbd = rd_reg();
      // Interpret sa field as 5-bit lsb of extract.
      uint16_t lsb = sa();
      uint16_t size = msbd + 1;
      uint64_t mask = (size == 64) ? UINT64_MAX : (1ULL << size) - 1;
      alu_out = static_cast<int64_t>((rs_u() & (mask << lsb)) >> lsb);
      SetResult(rt_reg(), alu_out);
      break;
    }
    case DEXTM: {
      // Interpret rd field as 5-bit msbdminus32 of extract.
      uint16_t msbdminus32 = rd_reg();
      // Interpret sa field as 5-bit lsb of extract.
      uint16_t lsb = sa();
      uint16_t size = msbdminus32 + 1 + 32;
      uint64_t mask = (size == 64) ? UINT64_MAX : (1ULL << size) - 1;
      alu_out = static_cast<int64_t>((rs_u() & (mask << lsb)) >> lsb);
      SetResult(rt_reg(), alu_out);
      break;
    }
    case DEXTU: {
      // Interpret rd field as 5-bit msbd of extract.
      uint16_t msbd = rd_reg();
      // Interpret sa field as 5-bit lsbminus32 of extract and add 32 to get
      // lsb.
      uint16_t lsb = sa() + 32;
      uint16_t size = msbd + 1;
      uint64_t mask = (size == 64) ? UINT64_MAX : (1ULL << size) - 1;
      alu_out = static_cast<int64_t>((rs_u() & (mask << lsb)) >> lsb);
      SetResult(rt_reg(), alu_out);
      break;
    }
    case INS: {  // Mips32r2 instruction.
      // Interpret rd field as 5-bit msb of insert.
      uint16_t msb = rd_reg();
      // Interpret sa field as 5-bit lsb of insert.
      uint16_t lsb = sa();
      uint16_t size = msb - lsb + 1;
      uint64_t mask = (1ULL << size) - 1;
      alu_out = static_cast<int32_t>((rt_u() & ~(mask << lsb)) |
                                     ((rs_u() & mask) << lsb));
      SetResult(rt_reg(), alu_out);
      break;
    }
    case DINS: {  // Mips64r2 instruction.
      // Interpret rd field as 5-bit msb of insert.
      uint16_t msb = rd_reg();
      // Interpret sa field as 5-bit lsb of insert.
      uint16_t lsb = sa();
      uint16_t size = msb - lsb + 1;
      uint64_t mask = (1ULL << size) - 1;
      alu_out = (rt_u() & ~(mask << lsb)) | ((rs_u() & mask) << lsb);
      SetResult(rt_reg(), alu_out);
      break;
    }
    case DINSM: {  // Mips64r2 instruction.
      // Interpret rd field as 5-bit msbminus32 of insert.
      uint16_t msbminus32 = rd_reg();
      // Interpret sa field as 5-bit lsb of insert.
      uint16_t lsb = sa();
      uint16_t size = msbminus32 + 32 - lsb + 1;
      uint64_t mask;
      if (size < 64)
        mask = (1ULL << size) - 1;
      else
        mask = std::numeric_limits<uint64_t>::max();
      alu_out = (rt_u() & ~(mask << lsb)) | ((rs_u() & mask) << lsb);
      SetResult(rt_reg(), alu_out);
      break;
    }
    case DINSU: {  // Mips64r2 instruction.
      // Interpret rd field as 5-bit msbminus32 of insert.
      uint16_t msbminus32 = rd_reg();
      // Interpret rd field as 5-bit lsbminus32 of insert.
      uint16_t lsbminus32 = sa();
      uint16_t lsb = lsbminus32 + 32;
      uint16_t size = msbminus32 + 32 - lsb + 1;
      uint64_t mask = (1ULL << size) - 1;
      alu_out = (rt_u() & ~(mask << lsb)) | ((rs_u() & mask) << lsb);
      SetResult(rt_reg(), alu_out);
      break;
    }
    case BSHFL: {
      int32_t sa = instr_.SaFieldRaw() >> kSaShift;
      switch (sa) {
        case BITSWAP: {
          uint32_t input = static_cast<uint32_t>(rt());
          uint32_t output = 0;
          uint8_t i_byte, o_byte;

          // Reverse the bit in byte for each individual byte
          for (int i = 0; i < 4; i++) {
            output = output >> 8;
            i_byte = input & 0xFF;

            // Fast way to reverse bits in byte
            // Devised by Sean Anderson, July 13, 2001
            o_byte = static_cast<uint8_t>(((i_byte * 0x0802LU & 0x22110LU) |
                                           (i_byte * 0x8020LU & 0x88440LU)) *
                                              0x10101LU >>
                                          16);

            output = output | (static_cast<uint32_t>(o_byte << 24));
            input = input >> 8;
          }

          alu_out = static_cast<int64_t>(static_cast<int32_t>(output));
          break;
        }
        case SEB: {
          uint8_t input = static_cast<uint8_t>(rt());
          uint32_t output = input;
          uint32_t mask = 0x00000080;

          // Extending sign
          if (mask & input) {
            output |= 0xFFFFFF00;
          }

          alu_out = static_cast<int32_t>(output);
          break;
        }
        case SEH: {
          uint16_t input = static_cast<uint16_t>(rt());
          uint32_t output = input;
          uint32_t mask = 0x00008000;

          // Extending sign
          if (mask & input) {
            output |= 0xFFFF0000;
          }

          alu_out = static_cast<int32_t>(output);
          break;
        }
        case WSBH: {
          uint32_t input = static_cast<uint32_t>(rt());
          uint64_t output = 0;

          uint32_t mask = 0xFF000000;
          for (int i = 0; i < 4; i++) {
            uint32_t tmp = mask & input;
            if (i % 2 == 0) {
              tmp = tmp >> 8;
            } else {
              tmp = tmp << 8;
            }
            output = output | tmp;
            mask = mask >> 8;
          }
          mask = 0x80000000;

          // Extending sign
          if (mask & output) {
            output |= 0xFFFFFFFF00000000;
          }

          alu_out = static_cast<int64_t>(output);
          break;
        }
        default: {
          const uint8_t bp2 = instr_.Bp2Value();
          sa >>= kBp2Bits;
          switch (sa) {
            case ALIGN: {
              if (bp2 == 0) {
                alu_out = static_cast<int32_t>(rt());
              } else {
                uint64_t rt_hi = rt() << (8 * bp2);
                uint64_t rs_lo = rs() >> (8 * (4 - bp2));
                alu_out = static_cast<int32_t>(rt_hi | rs_lo);
              }
              break;
            }
            default:
              alu_out = 0x12345678;
              UNREACHABLE();
          }
          break;
        }
      }
      SetResult(rd_reg(), alu_out);
      break;
    }
    case DBSHFL: {
      int32_t sa = instr_.SaFieldRaw() >> kSaShift;
      switch (sa) {
        case DBITSWAP: {
          switch (sa) {
            case DBITSWAP_SA: {  // Mips64r6
              uint64_t input = static_cast<uint64_t>(rt());
              uint64_t output = 0;
              uint8_t i_byte, o_byte;

              // Reverse the bit in byte for each individual byte
              for (int i = 0; i < 8; i++) {
                output = output >> 8;
                i_byte = input & 0xFF;

                // Fast way to reverse bits in byte
                // Devised by Sean Anderson, July 13, 2001
                o_byte =
                    static_cast<uint8_t>(((i_byte * 0x0802LU & 0x22110LU) |
                                          (i_byte * 0x8020LU & 0x88440LU)) *
                                             0x10101LU >>
                                         16);

                output = output | ((static_cast<uint64_t>(o_byte) << 56));
                input = input >> 8;
              }

              alu_out = static_cast<int64_t>(output);
              break;
            }
          }
          break;
        }
        case DSBH: {
          uint64_t input = static_cast<uint64_t>(rt());
          uint64_t output = 0;

          uint64_t mask = 0xFF00000000000000;
          for (int i = 0; i < 8; i++) {
            uint64_t tmp = mask & input;
            if (i % 2 == 0)
              tmp = tmp >> 8;
            else
              tmp = tmp << 8;

            output = output | tmp;
            mask = mask >> 8;
          }

          alu_out = static_cast<int64_t>(output);
          break;
        }
        case DSHD: {
          uint64_t input = static_cast<uint64_t>(rt());
          uint64_t output = 0;

          uint64_t mask = 0xFFFF000000000000;
          for (int i = 0; i < 4; i++) {
            uint64_t tmp = mask & input;
            if (i == 0)
              tmp = tmp >> 48;
            else if (i == 1)
              tmp = tmp >> 16;
            else if (i == 2)
              tmp = tmp << 16;
            else
              tmp = tmp << 48;
            output = output | tmp;
            mask = mask >> 16;
          }

          alu_out = static_cast<int64_t>(output);
          break;
        }
        default: {
          const uint8_t bp3 = instr_.Bp3Value();
          sa >>= kBp3Bits;
          switch (sa) {
            case DALIGN: {
              if (bp3 == 0) {
                alu_out = static_cast<int64_t>(rt());
              } else {
                uint64_t rt_hi = rt() << (8 * bp3);
                uint64_t rs_lo = rs() >> (8 * (8 - bp3));
                alu_out = static_cast<int64_t>(rt_hi | rs_lo);
              }
              break;
            }
            default:
              alu_out = 0x12345678;
              UNREACHABLE();
          }
          break;
        }
      }
      SetResult(rd_reg(), alu_out);
      break;
    }
    default:
      UNREACHABLE();
  }
}

int Simulator::DecodeMsaDataFormat() {
  int df = -1;
  if (instr_.IsMSABranchInstr()) {
    switch (instr_.RsFieldRaw()) {
      case BZ_V:
      case BNZ_V:
        df = MSA_VECT;
        break;
      case BZ_B:
      case BNZ_B:
        df = MSA_BYTE;
        break;
      case BZ_H:
      case BNZ_H:
        df = MSA_HALF;
        break;
      case BZ_W:
      case BNZ_W:
        df = MSA_WORD;
        break;
      case BZ_D:
      case BNZ_D:
        df = MSA_DWORD;
        break;
      default:
        UNREACHABLE();
    }
  } else {
    int DF[] = {MSA_BYTE, MSA_HALF, MSA_WORD, MSA_DWORD};
    switch (instr_.MSAMinorOpcodeField()) {
      case kMsaMinorI5:
      case kMsaMinorI10:
      case kMsaMinor3R:
        df = DF[instr_.Bits(22, 21)];
        break;
      case kMsaMinorMI10:
        df = DF[instr_.Bits(1, 0)];
        break;
      case kMsaMinorBIT:
        df = DF[instr_.MsaBitDf()];
        break;
      case kMsaMinorELM:
        df = DF[instr_.MsaElmDf()];
        break;
      case kMsaMinor3RF: {
        uint32_t opcode = instr_.InstructionBits() & kMsa3RFMask;
        switch (opcode) {
          case FEXDO:
          case FTQ:
          case MUL_Q:
          case MADD_Q:
          case MSUB_Q:
          case MULR_Q:
          case MADDR_Q:
          case MSUBR_Q:
            df = DF[1 + instr_.Bit(21)];
            break;
          default:
            df = DF[2 + instr_.Bit(21)];
            break;
        }
      } break;
      case kMsaMinor2R:
        df = DF[instr_.Bits(17, 16)];
        break;
      case kMsaMinor2RF:
        df = DF[2 + instr_.Bit(16)];
        break;
      default:
        UNREACHABLE();
    }
  }
  return df;
}

void Simulator::DecodeTypeMsaI8() {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(CpuFeatures::IsSupported(MIPS_SIMD));
  uint32_t opcode = instr_.InstructionBits() & kMsaI8Mask;
  int8_t i8 = instr_.MsaImm8Value();
  msa_reg_t ws, wd;

  switch (opcode) {
    case ANDI_B:
      get_msa_register(instr_.WsValue(), ws.b);
      for (int i = 0; i < kMSALanesByte; i++) {
        wd.b[i] = ws.b[i] & i8;
      }
      set_msa_register(instr_.WdValue(), wd.b);
      TraceMSARegWr(wd.b);
      break;
    case ORI_B:
      get_msa_register(instr_.WsValue(), ws.b);
      for (int i = 0; i < kMSALanesByte; i++) {
        wd.b[i] = ws.b[i] | i8;
      }
      set_msa_register(instr_.WdValue(), wd.b);
      TraceMSARegWr(wd.b);
      break;
    case NORI_B:
      get_msa_register(instr_.WsValue(), ws.b);
      for (int i = 0; i < kMSALanesByte; i++) {
        wd.b[i] = ~(ws.b[i] | i8);
      }
      set_msa_register(instr_.WdValue(), wd.b);
      TraceMSARegWr(wd.b);
      break;
    case XORI_B:
      get_msa_register(instr_.WsValue(), ws.b);
      for (int i = 0; i < kMSALanesByte; i++) {
        wd.b[i] = ws.b[i] ^ i8;
      }
      set_msa_register(instr_.WdValue(), wd.b);
      TraceMSARegWr(wd.b);
      break;
    case BMNZI_B:
      get_msa_register(instr_.WsValue(), ws.b);
      get_msa_register(instr_.WdValue(), wd.b);
      for (int i = 0; i < kMSALanesByte; i++) {
        wd.b[i] = (ws.b[i] & i8) | (wd.b[i] & ~i8);
      }
      set_msa_register(instr_.WdValue(), wd.b);
      TraceMSARegWr(wd.b);
      break;
    case BMZI_B:
      get_msa_register(instr_.WsValue(), ws.b);
      get_msa_register(instr_.WdValue(), wd.b);
      for (int i = 0; i < kMSALanesByte; i++) {
        wd.b[i] = (ws.b[i] & ~i8) | (wd.b[i] & i8);
      }
      set_msa_register(instr_.WdValue(), wd.b);
      TraceMSARegWr(wd.b);
      break;
    case BSELI_B:
      get_msa_register(instr_.WsValue(), ws.b);
      get_msa_register(instr_.WdValue(), wd.b);
      for (int i = 0; i < kMSALanesByte; i++) {
        wd.b[i] = (ws.b[i] & ~wd.b[i]) | (wd.b[i] & i8);
      }
      set_msa_register(instr_.WdValue(), wd.b);
      TraceMSARegWr(wd.b);
      break;
    case SHF_B:
      get_msa_register(instr_.WsValue(), ws.b);
      for (int i = 0; i < kMSALanesByte; i++) {
        int j = i % 4;
        int k = (i8 >> (2 * j)) & 0x3;
        wd.b[i] = ws.b[i - j + k];
      }
      set_msa_register(instr_.WdValue(), wd.b);
      TraceMSARegWr(wd.b);
      break;
    case SHF_H:
      get_msa_register(instr_.WsValue(), ws.h);
      for (int i = 0; i < kMSALanesHalf; i++) {
        int j = i % 4;
        int k = (i8 >> (2 * j)) & 0x3;
        wd.h[i] = ws.h[i - j + k];
      }
      set_msa_register(instr_.WdValue(), wd.h);
      TraceMSARegWr(wd.h);
      break;
    case SHF_W:
      get_msa_register(instr_.WsValue(), ws.w);
      for (int i = 0; i < kMSALanesWord; i++) {
        int j = (i8 >> (2 * i)) & 0x3;
        wd.w[i] = ws.w[j];
      }
      set_msa_register(instr_.WdValue(), wd.w);
      TraceMSARegWr(wd.w);
      break;
    default:
      UNREACHABLE();
  }
}

template <typename T>
T Simulator::MsaI5InstrHelper(uint32_t opcode, T ws, int32_t i5) {
  T res;
  uint32_t ui5 = i5 & 0x1Fu;
  uint64_t ws_u64 = static_cast<uint64_t>(ws);
  uint64_t ui5_u64 = static_cast<uint64_t>(ui5);

  switch (opcode) {
    case ADDVI:
      res = static_cast<T>(ws + ui5);
      break;
    case SUBVI:
      res = static_cast<T>(ws - ui5);
      break;
    case MAXI_S:
      res = static_cast<T>(std::max(ws, static_cast<T>(i5)));
      break;
    case MINI_S:
      res = static_cast<T>(std::min(ws, static_cast<T>(i5)));
      break;
    case MAXI_U:
      res = static_cast<T>(std::max(ws_u64, ui5_u64));
      break;
    case MINI_U:
      res = static_cast<T>(std::min(ws_u64, ui5_u64));
      break;
    case CEQI:
      res = static_cast<T>(!Compare(ws, static_cast<T>(i5)) ? -1ull : 0ull);
      break;
    case CLTI_S:
      res = static_cast<T>((Compare(ws, static_cast<T>(i5)) == -1) ? -1ull
                                                                   : 0ull);
      break;
    case CLTI_U:
      res = static_cast<T>((Compare(ws_u64, ui5_u64) == -1) ? -1ull : 0ull);
      break;
    case CLEI_S:
      res =
          static_cast<T>((Compare(ws, static_cast<T>(i5)) != 1) ? -1ull : 0ull);
      break;
    case CLEI_U:
      res = static_cast<T>((Compare(ws_u64, ui5_u64) != 1) ? -1ull : 0ull);
      break;
    default:
      UNREACHABLE();
  }
  return res;
}

void Simulator::DecodeTypeMsaI5() {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(CpuFeatures::IsSupported(MIPS_SIMD));
  uint32_t opcode = instr_.InstructionBits() & kMsaI5Mask;
  msa_reg_t ws, wd;

  // sign extend 5bit value to int32_t
  int32_t i5 = static_cast<int32_t>(instr_.MsaImm5Value() << 27) >> 27;

#define MSA_I5_DF(elem, num_of_lanes)                      \
  get_msa_register(instr_.WsValue(), ws.elem);             \
  for (int i = 0; i < num_of_lanes; i++) {                 \
    wd.elem[i] = MsaI5InstrHelper(opcode, ws.elem[i], i5); \
  }                                                        \
  set_msa_register(instr_.WdValue(), wd.elem);             \
  TraceMSARegWr(wd.elem)

  switch (DecodeMsaDataFormat()) {
    case MSA_BYTE:
      MSA_I5_DF(b, kMSALanesByte);
      break;
    case MSA_HALF:
      MSA_I5_DF(h, kMSALanesHalf);
      break;
    case MSA_WORD:
      MSA_I5_DF(w, kMSALanesWord);
      break;
    case MSA_DWORD:
      MSA_I5_DF(d, kMSALanesDword);
      break;
    default:
      UNREACHABLE();
  }
#undef MSA_I5_DF
}

void Simulator::DecodeTypeMsaI10() {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(CpuFeatures::IsSupported(MIPS_SIMD));
  uint32_t opcode = instr_.InstructionBits() & kMsaI5Mask;
  int64_t s10 = (static_cast<int64_t>(instr_.MsaImm10Value()) << 54) >> 54;
  msa_reg_t wd;

#define MSA_I10_DF(elem, num_of_lanes, T)      \
  for (int i = 0; i < num_of_lanes; ++i) {     \
    wd.elem[i] = static_cast<T>(s10);          \
  }                                            \
  set_msa_register(instr_.WdValue(), wd.elem); \
  TraceMSARegWr(wd.elem)

  if (opcode == LDI) {
    switch (DecodeMsaDataFormat()) {
      case MSA_BYTE:
        MSA_I10_DF(b, kMSALanesByte, int8_t);
        break;
      case MSA_HALF:
        MSA_I10_DF(h, kMSALanesHalf, int16_t);
        break;
      case MSA_WORD:
        MSA_I10_DF(w, kMSALanesWord, int32_t);
        break;
      case MSA_DWORD:
        MSA_I10_DF(d, kMSALanesDword, int64_t);
        break;
      default:
        UNREACHABLE();
    }
  } else {
    UNREACHABLE();
  }
#undef MSA_I10_DF
}

void Simulator::DecodeTypeMsaELM() {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(CpuFeatures::IsSupported(MIPS_SIMD));
  uint32_t opcode = instr_.InstructionBits() & kMsaLongerELMMask;
  int32_t n = instr_.MsaElmNValue();
  int64_t alu_out;
  switch (opcode) {
    case CTCMSA:
      DCHECK_EQ(sa(), kMSACSRRegister);
      MSACSR_ = base::bit_cast<uint32_t>(
          static_cast<int32_t>(registers_[rd_reg()] & kMaxUInt32));
      TraceRegWr(static_cast<int32_t>(MSACSR_));
      break;
    case CFCMSA:
      DCHECK_EQ(rd_reg(), kMSACSRRegister);
      SetResult(sa(), static_cast<int64_t>(base::bit_cast<int32_t>(MSACSR_)));
      break;
    case MOVE_V: {
      msa_reg_t ws;
      get_msa_register(ws_reg(), &ws);
      set_msa_register(wd_reg(), &ws);
      TraceMSARegWr(&ws);
    } break;
    default:
      opcode &= kMsaELMMask;
      switch (opcode) {
        case COPY_S:
        case COPY_U: {
          msa_reg_t ws;
          switch (DecodeMsaDataFormat()) {
            case MSA_BYTE:
              DCHECK_LT(n, kMSALanesByte);
              get_msa_register(instr_.WsValue(), ws.b);
              alu_out = static_cast<int32_t>(ws.b[n]);
              SetResult(wd_reg(),
                        (opcode == COPY_U) ? alu_out & 0xFFu : alu_out);
              break;
            case MSA_HALF:
              DCHECK_LT(n, kMSALanesHalf);
              get_msa_register(instr_.WsValue(), ws.h);
              alu_out = static_cast<int32_t>(ws.h[n]);
              SetResult(wd_reg(),
                        (opcode == COPY_U) ? alu_out & 0xFFFFu : alu_out);
              break;
            case MSA_WORD:
              DCHECK_LT(n, kMSALanesWord);
              get_msa_register(instr_.WsValue(), ws.w);
              alu_out = static_cast<int32_t>(ws.w[n]);
              SetResult(wd_reg(),
                        (opcode == COPY_U) ? alu_out & 0xFFFFFFFFu : alu_out);
              break;
            case MSA_DWORD:
              DCHECK_LT(n, kMSALanesDword);
              get_msa_register(instr_.WsValue(), ws.d);
              alu_out = static_cast<int64_t>(ws.d[n]);
              SetResult(wd_reg(), alu_out);
              break;
            default:
              UNREACHABLE();
          }
        } break;
        case INSERT: {
          msa_reg_t wd;
          switch (DecodeMsaDataFormat()) {
            case MSA_BYTE: {
              DCHECK_LT(n, kMSALanesByte);
              int64_t rs = get_register(instr_.WsValue());
              get_msa_register(instr_.WdValue(), wd.b);
              wd.b[n] = rs & 0xFFu;
              set_msa_register(instr_.WdValue(), wd.b);
              TraceMSARegWr(wd.b);
              break;
            }
            case MSA_HALF: {
              DCHECK_LT(n, kMSALanesHalf);
              int64_t rs = get_register(instr_.WsValue());
              get_msa_register(instr_.WdValue(), wd.h);
              wd.h[n] = rs & 0xFFFFu;
              set_msa_register(instr_.WdValue(), wd.h);
              TraceMSARegWr(wd.h);
              break;
            }
            case MSA_WORD: {
              DCHECK_LT(n, kMSALanesWord);
              int64_t rs = get_register(instr_.WsValue());
              get_msa_register(instr_.WdValue(), wd.w);
              wd.w[n] = rs & 0xFFFFFFFFu;
              set_msa_register(instr_.WdValue(), wd.w);
              TraceMSARegWr(wd.w);
              break;
            }
            case MSA_DWORD: {
              DCHECK_LT(n, kMSALanesDword);
              int64_t rs = get_register(instr_.WsValue());
              get_msa_register(instr_.WdValue(), wd.d);
              wd.d[n] = rs;
              set_msa_register(instr_.WdValue(), wd.d);
              TraceMSARegWr(wd.d);
              break;
            }
            default:
              UNREACHABLE();
          }
        } break;
        case SLDI: {
          uint8_t v[32];
          msa_reg_t ws;
          msa_reg_t wd;
          get_msa_register(ws_reg(), &ws);
          get_msa_register(wd_reg(), &wd);
#define SLDI_DF(s, k)                \
  for (unsigned i = 0; i < s; i++) { \
    v[i] = ws.b[s * k + i];          \
    v[i + s] = wd.b[s * k + i];      \
  }                                  \
  for (unsigned i = 0; i < s; i++) { \
    wd.b[s * k + i] = v[i + n];      \
  }
          switch (DecodeMsaDataFormat()) {
            case MSA_BYTE:
              DCHECK(n < kMSALanesByte);
              SLDI_DF(kMSARegSize / sizeof(int8_t) / kBitsPerByte, 0)
              break;
            case MSA_HALF:
              DCHECK(n < kMSALanesHalf);
              for (int k = 0; k < 2; ++k) {
                SLDI_DF(kMSARegSize / sizeof(int16_t) / kBitsPerByte, k)
              }
              break;
            case MSA_WORD:
              DCHECK(n < kMSALanesWord);
              for (int k = 0; k < 4; ++k) {
                SLDI_DF(kMSARegSize / sizeof(int32_t) / kBitsPerByte, k)
              }
              break;
            case MSA_DWORD:
              DCHECK(n < kMSALanesDword);
              for (int k = 0; k < 8; ++k) {
                SLDI_DF(kMSARegSize / sizeof(int64_t) / kBitsPerByte, k)
              }
              break;
            default:
              UNREACHABLE();
          }
          set_msa_register(wd_reg(), &wd);
          TraceMSARegWr(&wd);
        } break;
#undef SLDI_DF
        case SPLATI:
        case INSVE:
          UNIMPLEMENTED();
        default:
          UNREACHABLE();
      }
      break;
  }
}

template <typename T>
T Simulator::MsaBitInstrHelper(uint32_t opcode, T wd, T ws, int32_t m) {
  using uT = typename std::make_unsigned<T>::type;
  T res;
  switch (opcode) {
    case SLLI:
      res = static_cast<T>(ws << m);
      break;
    case SRAI:
      res = static_cast<T>(ArithmeticShiftRight(ws, m));
      break;
    case SRLI:
      res = static_cast<T>(static_cast<uT>(ws) >> m);
      break;
    case BCLRI:
      res = static_cast<T>(static_cast<T>(~(1ull << m)) & ws);
      break;
    case BSETI:
      res = static_cast<T>(static_cast<T>(1ull << m) | ws);
      break;
    case BNEGI:
      res = static_cast<T>(static_cast<T>(1ull << m) ^ ws);
      break;
    case BINSLI: {
      int elem_size = 8 * sizeof(T);
      int bits = m + 1;
      if (bits == elem_size) {
        res = static_cast<T>(ws);
      } else {
        uint64_t mask = ((1ull << bits) - 1) << (elem_size - bits);
        res = static_cast<T>((static_cast<T>(mask) & ws) |
                             (static_cast<T>(~mask) & wd));
      }
    } break;
    case BINSRI: {
      int elem_size = 8 * sizeof(T);
      int bits = m + 1;
      if (bits == elem_size) {
        res = static_cast<T>(ws);
      } else {
        uint64_t mask = (1ull << bits) - 1;
        res = static_cast<T>((static_cast<T>(mask) & ws) |
                             (static_cast<T>(~mask) & wd));
      }
    } break;
    case SAT_S: {
#define M_MAX_INT(x) static_cast<int64_t>((1LL << ((x)-1)) - 1)
#define M_MIN_INT(x) static_cast<int64_t>(-(1LL << ((x)-1)))
      int shift = 64 - 8 * sizeof(T);
      int64_t ws_i64 = (static_cast<int64_t>(ws) << shift) >> shift;
      res = static_cast<T>(ws_i64 < M_MIN_INT(m + 1)
                               ? M_MIN_INT(m + 1)
                               : ws_i64 > M_MAX_INT(m + 1) ? M_MAX_INT(m + 1)
                                                           : ws_i64);
#undef M_MAX_INT
#undef M_MIN_INT
    } break;
    case SAT_U: {
#define M_MAX_UINT(x) static_cast<uint64_t>(-1ULL >> (64 - (x)))
      uint64_t mask = static_cast<uint64_t>(-1ULL >> (64 - 8 * sizeof(T)));
      uint64_t ws_u64 = static_cast<uint64_t>(ws) & mask;
      res = static_cast<T>(ws_u64 < M_MAX_UINT(m + 1) ? ws_u64
                                                      : M_MAX_UINT(m + 1));
#undef M_MAX_UINT
    } break;
    case SRARI:
      if (!m) {
        res = static_cast<T>(ws);
      } else {
        res = static_cast<T>(ArithmeticShiftRight(ws, m)) +
              static_cast<T>((ws >> (m - 1)) & 0x1);
      }
      break;
    case SRLRI:
      if (!m) {
        res = static_cast<T>(ws);
      } else {
        res = static_cast<T>(static_cast<uT>(ws) >> m) +
              static_cast<T>((ws >> (m - 1)) & 0x1);
      }
      break;
    default:
      UNREACHABLE();
  }
  return res;
}

void Simulator::DecodeTypeMsaBIT() {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(CpuFeatures::IsSupported(MIPS_SIMD));
  uint32_t opcode = instr_.InstructionBits() & kMsaBITMask;
  int32_t m = instr_.MsaBitMValue();
  msa_reg_t wd, ws;

#define MSA_BIT_DF(elem, num_of_lanes)                                 \
  get_msa_register(instr_.WsValue(), ws.elem);                         \
  if (opcode == BINSLI || opcode == BINSRI) {                          \
    get_msa_register(instr_.WdValue(), wd.elem);                       \
  }                                                                    \
  for (int i = 0; i < num_of_lanes; i++) {                             \
    wd.elem[i] = MsaBitInstrHelper(opcode, wd.elem[i], ws.elem[i], m); \
  }                                                                    \
  set_msa_register(instr_.WdValue(), wd.elem);                         \
  TraceMSARegWr(wd.elem)

  switch (DecodeMsaDataFormat()) {
    case MSA_BYTE:
      DCHECK(m < kMSARegSize / kMSALanesByte);
      MSA_BIT_DF(b, kMSALanesByte);
      break;
    case MSA_HALF:
      DCHECK(m < kMSARegSize / kMSALanesHalf);
      MSA_BIT_DF(h, kMSALanesHalf);
      break;
    case MSA_WORD:
      DCHECK(m < kMSARegSize / kMSALanesWord);
      MSA_BIT_DF(w, kMSALanesWord);
      break;
    case MSA_DWORD:
      DCHECK(m < kMSARegSize / kMSALanesDword);
      MSA_BIT_DF(d, kMSALanesDword);
      break;
    default:
      UNREACHABLE();
  }
#undef MSA_BIT_DF
}

void Simulator::DecodeTypeMsaMI10() {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(CpuFeatures::IsSupported(MIPS_SIMD));
  uint32_t opcode = instr_.InstructionBits() & kMsaMI10Mask;
  int64_t s10 = (static_cast<int64_t>(instr_.MsaImmMI10Value()) << 54) >> 54;
  int64_t rs = get_register(instr_.WsValue());
  int64_t addr;
  msa_reg_t wd;

#define MSA_MI10_LOAD(elem, num_of_lanes, T)       \
  for (int i = 0; i < num_of_lanes; ++i) {         \
    addr = rs + (s10 + i) * sizeof(T);             \
    wd.elem[i] = ReadMem<T>(addr, instr_.instr()); \
  }                                                \
  set_msa_register(instr_.WdValue(), wd.elem);

#define MSA_MI10_STORE(elem, num_of_lanes, T)      \
  get_msa_register(instr_.WdValue(), wd.elem);     \
  for (int i = 0; i < num_of_lanes; ++i) {         \
    addr = rs + (s10 + i) * sizeof(T);             \
    WriteMem<T>(addr, wd.elem[i], instr_.instr()); \
  }

  if (opcode == MSA_LD) {
    switch (DecodeMsaDataFormat()) {
      case MSA_BYTE:
        MSA_MI10_LOAD(b, kMSALanesByte, int8_t);
        break;
      case MSA_HALF:
        MSA_MI10_LOAD(h, kMSALanesHalf, int16_t);
        break;
      case MSA_WORD:
        MSA_MI10_LOAD(w, kMSALanesWord, int32_t);
        break;
      case MSA_DWORD:
        MSA_MI10_LOAD(d, kMSALanesDword, int64_t);
        break;
      default:
        UNREACHABLE();
    }
  } else if (opcode == MSA_ST) {
    switch (DecodeMsaDataFormat()) {
      case MSA_BYTE:
        MSA_MI10_STORE(b, kMSALanesByte, int8_t);
        break;
      case MSA_HALF:
        MSA_MI10_STORE(h, kMSALanesHalf, int16_t);
        break;
      case MSA_WORD:
        MSA_MI10_STORE(w, kMSALanesWord, int32_t);
        break;
      case MSA_DWORD:
        MSA_MI10_STORE(d, kMSALanesDword, int64_t);
        break;
      default:
        UNREACHABLE();
    }
  } else {
    UNREACHABLE();
  }

#undef MSA_MI10_LOAD
#undef MSA_MI10_STORE
}

template <typename T>
T Simulator::Msa3RInstrHelper(uint32_t opcode, T wd, T ws, T wt) {
  using uT = typename std::make_unsigned<T>::type;
  T res;
  int wt_modulo = wt % (sizeof(T) * 8);
  switch (opcode) {
    case SLL_MSA:
      res = static_cast<T>(ws << wt_modulo);
      break;
    case SRA_MSA:
      res = static_cast<T>(ArithmeticShiftRight(ws, wt_modulo));
      break;
    case SRL_MSA:
      res = static_cast<T>(static_cast<uT>(ws) >> wt_modulo);
      break;
    case BCLR:
      res = static_cast<T>(static_cast<T>(~(1ull << wt_modulo)) & ws);
      break;
    case BSET:
      res = static_cast<T>(static_cast<T>(1ull << wt_modulo) | ws);
      break;
    case BNEG:
      res = static_cast<T>(static_cast<T>(1ull << wt_modulo) ^ ws);
      break;
    case BINSL: {
      int elem_size = 8 * sizeof(T);
      int bits = wt_modulo + 1;
      if (bits == elem_size) {
        res = static_cast<T>(ws);
      } else {
        uint64_t mask = ((1ull << bits) - 1) << (elem_size - bits);
        res = static_cast<T>((static_cast<T>(mask) & ws) |
                             (static_cast<T>(~mask) & wd));
      }
    } break;
    case BINSR: {
      int elem_size = 8 * sizeof(T);
      int bits = wt_modulo + 1;
      if (bits == elem_size) {
        res = static_cast<T>(ws);
      } else {
        uint64_t mask = (1ull << bits) - 1;
        res = static_cast<T>((static_cast<T>(mask) & ws) |
                             (static_cast<T>(~mask) & wd));
      }
    } break;
    case ADDV:
      res = ws + wt;
      break;
    case SUBV:
      res = ws - wt;
      break;
    case MAX_S:
      res = std::max(ws, wt);
      break;
    case MAX_U:
      res = static_cast<T>(std::max(static_cast<uT>(ws), static_cast<uT>(wt)));
      break;
    case MIN_S:
      res = std::min(ws, wt);
      break;
    case MIN_U:
      res = static_cast<T>(std::min(static_cast<uT>(ws), static_cast<uT>(wt)));
      break;
    case MAX_A:
      // We use negative abs in order to avoid problems
      // with corner case for MIN_INT
      res = Nabs(ws) < Nabs(wt) ? ws : wt;
      break;
    case MIN_A:
      // We use negative abs in order to avoid problems
      // with corner case for MIN_INT
      res = Nabs(ws) > Nabs(wt) ? ws : wt;
      break;
    case CEQ:
      res = static_cast<T>(!Compare(ws, wt) ? -1ull : 0ull);
      break;
    case CLT_S:
      res = static_cast<T>((Compare(ws, wt) == -1) ? -1ull : 0ull);
      break;
    case CLT_U:
      res = static_cast<T>(
          (Compare(static_cast<uT>(ws), static_cast<uT>(wt)) == -1) ? -1ull
                                                                    : 0ull);
      break;
    case CLE_S:
      res = static_cast<T>((Compare(ws, wt) != 1) ? -1ull : 0ull);
      break;
    case CLE_U:
      res = static_cast<T>(
          (Compare(static_cast<uT>(ws), static_cast<uT>(wt)) != 1) ? -1ull
                                                                   : 0ull);
      break;
    case ADD_A:
      res = static_cast<T>(Abs(ws) + Abs(wt));
      break;
    case ADDS_A: {
      T ws_nabs = Nabs(ws);
      T wt_nabs = Nabs(wt);
      if (ws_nabs < -std::numeric_limits<T>::max() - wt_nabs) {
        res = std::numeric_limits<T>::max();
      } else {
        res = -(ws_nabs + wt_nabs);
      }
    } break;
    case ADDS_S:
      res = SaturateAdd(ws, wt);
      break;
    case ADDS_U: {
      uT ws_u = static_cast<uT>(ws);
      uT wt_u = static_cast<uT>(wt);
      res = static_cast<T>(SaturateAdd(ws_u, wt_u));
    } break;
    case AVE_S:
      res = static_cast<T>((wt & ws) + ((wt ^ ws) >> 1));
      break;
    case AVE_U: {
      uT ws_u = static_cast<uT>(ws);
      uT wt_u = static_cast<uT>(wt);
      res = static_cast<T>((wt_u & ws_u) + ((wt_u ^ ws_u) >> 1));
    } break;
    case AVER_S:
      res = static_cast<T>((wt | ws) - ((wt ^ ws) >> 1));
      break;
    case AVER_U: {
      uT ws_u = static_cast<uT>(ws);
      uT wt_u = static_cast<uT>(wt);
      res = static_cast<T>((wt_u | ws_u) - ((wt_u ^ ws_u) >> 1));
    } break;
    case SUBS_S:
      res = SaturateSub(ws, wt);
      break;
    case SUBS_U: {
      uT ws_u = static_cast<uT>(ws);
      uT wt_u = static_cast<uT>(wt);
      res = static_cast<T>(SaturateSub(ws_u, wt_u));
    } break;
    case SUBSUS_U: {
      uT wsu = static_cast<uT>(ws);
      if (wt > 0) {
        uT wtu = static_cast<uT>(wt);
        if (wtu > wsu) {
          res = 0;
        } else {
          res = static_cast<T>(wsu - wtu);
        }
      } else {
        if (wsu > std::numeric_limits<uT>::max() + wt) {
          res = static_cast<T>(std::numeric_limits<uT>::max());
        } else {
          res = static_cast<T>(wsu - wt);
        }
      }
    } break;
    case SUBSUU_S: {
      uT wsu = static_cast<uT>(ws);
      uT wtu = static_cast<uT>(wt);
      uT wdu;
      if (wsu > wtu) {
        wdu = wsu - wtu;
        if (wdu > std::numeric_limits<T>::max()) {
          res = std::numeric_limits<T>::max();
        } else {
          res = static_cast<T>(wdu);
        }
      } else {
        wdu = wtu - wsu;
        CHECK(-std::numeric_limits<T>::max() ==
              std::numeric_limits<T>::min() + 1);
        if (wdu <= std::numeric_limits<T>::max()) {
          res = -static_cast<T>(wdu);
        } else {
          res = std::numeric_limits<T>::min();
        }
      }
    } break;
    case ASUB_S:
      res = static_cast<T>(Abs(ws - wt));
      break;
    case ASUB_U: {
      uT wsu = static_cast<uT>(ws);
      uT wtu = static_cast<uT>(wt);
      res = static_cast<T>(wsu > wtu ? wsu - wtu : wtu - wsu);
    } break;
    case MULV:
      res = ws * wt;
      break;
    case MADDV:
      res = wd + ws * wt;
      break;
    case MSUBV:
      res = wd - ws * wt;
      break;
    case DIV_S_MSA:
      res = wt != 0 ? ws / wt : static_cast<T>(Unpredictable);
      break;
    case DIV_U:
      res = wt != 0 ? static_cast<T>(static_cast<uT>(ws) / static_cast<uT>(wt))
                    : static_cast<T>(Unpredictable);
      break;
    case MOD_S:
      res = wt != 0 ? ws % wt : static_cast<T>(Unpredictable);
      break;
    case MOD_U:
      res = wt != 0 ? static_cast<T>(static_cast<uT>(ws) % static_cast<uT>(wt))
                    : static_cast<T>(Unpredictable);
      break;
    case DOTP_S:
    case DOTP_U:
    case DPADD_S:
    case DPADD_U:
    case DPSUB_S:
    case DPSUB_U:
    case SLD:
    case SPLAT:
      UNIMPLEMENTED();
      break;
    case SRAR: {
      int bit = wt_modulo == 0 ? 0 : (ws >> (wt_modulo - 1)) & 1;
      res = static_cast<T>(ArithmeticShiftRight(ws, wt_modulo) + bit);
    } break;
    case SRLR: {
      uT wsu = static_cast<uT>(ws);
      int bit = wt_modulo == 0 ? 0 : (wsu >> (wt_modulo - 1)) & 1;
      res = static_cast<T>((wsu >> wt_modulo) + bit);
    } break;
    default:
      UNREACHABLE();
  }
  return res;
}
template <typename T_int, typename T_reg>
void Msa3RInstrHelper_shuffle(const uint32_t opcode, T_reg ws, T_reg wt,
                              T_reg wd, const int i, const int num_of_lanes) {
  T_int *ws_p, *wt_p, *wd_p;
  ws_p = reinterpret_cast<T_int*>(ws);
  wt_p = reinterpret_cast<T_int*>(wt);
  wd_p = reinterpret_cast<T_int*>(wd);
  switch (opcode) {
    case PCKEV:
      wd_p[i] = wt_p[2 * i];
      wd_p[i + num_of_lanes / 2] = ws_p[2 * i];
      break;
    case PCKOD:
      wd_p[i] = wt_p[2 * i + 1];
      wd_p[i + num_of_lanes / 2] = ws_p[2 * i + 1];
      break;
    case ILVL:
      wd_p[2 * i] = wt_p[i + num_of_lanes / 2];
      wd_p[2 * i + 1] = ws_p[i + num_of_lanes / 2];
      break;
    case ILVR:
      wd_p[2 * i] = wt_p[i];
      wd_p[2 * i + 1] = ws_p[i];
      break;
    case ILVEV:
      wd_p[2 * i] = wt_p[2 * i];
      wd_p[2 * i + 1] = ws_p[2 * i];
      break;
    case ILVOD:
      wd_p[2 * i] = wt_p[2 * i + 1];
      wd_p[2 * i + 1] = ws_p[2 * i + 1];
      break;
    case VSHF: {
      const int mask_not_valid = 0xC0;
      const int mask_6_bits = 0x3F;
      if ((wd_p[i] & mask_not_valid)) {
        wd_p[i] = 0;
      } else {
        int k = (wd_p[i] & mask_6_bits) % (num_of_lanes * 2);
        wd_p[i] = k >= num_of_lanes ? ws_p[k - num_of_lanes] : wt_p[k];
      }
    } break;
    default:
      UNREACHABLE();
  }
}

template <typename T_int, typename T_smaller_int, typename T_reg>
void Msa3RInstrHelper_horizontal(const uint32_t opcode, T_reg ws, T_reg wt,
                                 T_reg wd, const int i,
                                 const int num_of_lanes) {
  using T_uint = typename std::make_unsigned<T_int>::type;
  using T_smaller_uint = typename std::make_unsigned<T_smaller_int>::type;
  T_int* wd_p;
  T_smaller_int *ws_p, *wt_p;
  ws_p = reinterpret_cast<T_smaller_int*>(ws);
  wt_p = reinterpret_cast<T_smaller_int*>(wt);
  wd_p = reinterpret_cast<T_int*>(wd);
  T_uint* wd_pu;
  T_smaller_uint *ws_pu, *wt_pu;
  ws_pu = reinterpret_cast<T_smaller_uint*>(ws);
  wt_pu = reinterpret_cast<T_smaller_uint*>(wt);
  wd_pu = reinterpret_cast<T_uint*>(wd);
  switch (opcode) {
    case HADD_S:
      wd_p[i] =
          static_cast<T_int>(ws_p[2 * i + 1]) + static_cast<T_int>(wt_p[2 * i]);
      break;
    case HADD_U:
      wd_pu[i] = static_cast<T_uint>(ws_pu[2 * i + 1]) +
                 static_cast<T_uint>(wt_pu[2 * i]);
      break;
    case HSUB_S:
      wd_p[i] =
          static_cast<T_int>(ws_p[2 * i + 1]) - static_cast<T_int>(wt_p[2 * i]);
      break;
    case HSUB_U:
      wd_pu[i] = static_cast<T_uint>(ws_pu[2 * i + 1]) -
                 static_cast<T_uint>(wt_pu[2 * i]);
      break;
    default:
      UNREACHABLE();
  }
}

void Simulator::DecodeTypeMsa3R() {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK(CpuFeatures::IsSupported(MIPS_SIMD));
  uint32_t opcode = instr_.InstructionBits() & kMsa3RMask;
  msa_reg_t ws, wd, wt;
  get_msa_register(ws_reg(), &ws);
  get_msa_register(wt_reg(), &wt);
  get_msa_register(wd_reg(), &wd);
  switch (opcode) {
    case HADD_S:
    case HADD_U:
    case HSUB_S:
    case HSUB_U:
#define HORIZONTAL_ARITHMETIC_DF(num_of_lanes, int_type, lesser_int_type) \
  for (int i = 0; i < num_of_lanes; ++i) {                                \
    Msa3RInstrHelper_horizontal<int_type, lesser_int_type>(               \
        opcode, &ws, &wt, &wd, i, num_of_lanes);                          \
  }
      switch (DecodeMsaDataFormat()) {
        case MSA_HALF:
          HORIZONTAL_ARITHMETIC_DF(kMSALanesHalf, int16_t, int8_t);
          break;
        case MSA_WORD:
          HORIZONTAL_ARITHMETIC_DF(kMSALanesWord, int32_t, int16_t);
          break;
        case MSA_DWORD:
          HORIZONTAL_ARITHMETIC_DF(kMSALanesDword, int64_t, int32_t);
          break;
        default:
          UNREACHABLE();
      }
      break;
#undef HORIZONTAL_ARITHMETIC_DF
    case VSHF:
#define VSHF_DF(num_of_lanes, int_type)                          \
  for (int i = 0; i < num_of_lanes; ++i) {                       \
    Msa3RInstrHelper_shuffle<int_type>(opcode, &ws, &wt, &wd, i, \
                                       num_of_lanes);            \
  }
      switch (DecodeMsaDataFormat()) {
        case MSA_BYTE:
          VSHF_DF(kMSALanesByte, int8_t);
          break;
        case MSA_HALF:
          VSHF_DF(kMSALanesHalf, int16_t);
          break;
        case MSA_WORD:
          VSHF_DF(kMSALanesWord, int32_t);
          break;
        case MSA_DWORD:
          VSHF_DF(kMSALanesDword, int64_t);
          break;
        default:
          UNREACHABLE();
      }
#undef VSHF_DF
      break;
    case PCKEV:
    case PCKOD:
    case ILVL:
    case ILVR:
    case ILVEV:
    case ILVOD:
#define INTERLEAVE_PACK_DF(num_of_lanes, int_type)               \
  for (int i = 0; i < num_of_lanes / 2; ++i) {                   \
    Msa3RInstrHelper_shuffle<int_type>(opcode, &ws, &wt, &wd, i, \
                                       num_of_lanes);            \
  }
      switch (DecodeMsaDataFormat()) {
        case MSA_BYTE:
          INTERLEAVE_PACK_DF(kMSALanesByte, int8_t);
          break;
        case MSA_HALF:
          INTERLEAVE_PACK_DF(kMSALanesHalf, int16_t);
          break;
        case MSA_WORD:
          INTERLEAVE_PACK_DF(kMSALanesWord, int32_t);
          break;
        case MSA_DWORD:
          INTERLEAVE_PACK_DF(kMSALanesDword, int64_t);
          break;
        default:
          UNREACHABLE();
      }
      break;
#undef INTERLEAVE_PACK_DF
    default:
#define MSA_3R_DF(elem, num_of_lanes)                                          \
  for (int i = 0; i < num_of_lanes; i++) {                                     \
    wd.elem[i] = Msa3RInstrHelper(opcode, wd.elem[i], ws.elem[i], wt.elem[i]); \
  }

      switch (DecodeMsaDataFormat()) {
        case MSA_BYTE:
          MSA_3R_DF(b, kMSALanesByte);
          break;
        case MSA_HALF:
          MSA_3R_DF(h, kMSALanesHalf);
          break;
        case MSA_WORD:
          MSA_3R_DF(w, kMSALanesWord);
          break;
        case MSA_DWORD:
          MSA_3R_DF(d, kMSALanesDword);
          break;
        default:
          UNREACHABLE();
      }
#undef MSA_3R_DF
      break;
  }
  set_msa_register(wd_reg(), &wd);
  TraceMSARegWr(&wd);
}

template <typename T_int, typename T_fp, typename T_reg>
void Msa3RFInstrHelper(uint32_t opcode, T_reg ws, T_reg wt, T_reg* wd) {
  const T_int all_ones = static_cast<T_int>(-1);
  const T_fp s_element = *reinterpret_cast<T_fp*>(&ws);
  const T_fp t_element = *reinterpret_cast<T_fp*>(&wt);
  switch (opcode) {
    case FCUN: {
      if (std::isnan(s_element) || std::isnan(t_element)) {
        *wd = all_ones;
      } else {
        *wd = 0;
      }
    } break;
    case FCEQ: {
      if (s_element != t_element || std::isnan(s_element) ||
          std::isnan(t_element)) {
        *wd = 0;
      } else {
        *wd = all_ones;
      }
    } break;
    case FCUEQ: {
      if (s_element == t_element || std::isnan(s_element) ||
          std::isnan(t_element)) {
        *wd = all_ones;
      } else {
        *wd = 0;
      }
    } break;
    case FCLT: {
      if (s_element >= t_element || std::isnan(s_element) ||
          std::isnan(t_element)) {
        *wd = 0;
      } else {
        *wd = all_ones;
      }
    } break;
    case FCULT: {
      if (s_element < t_element || std::isnan(s_element) ||
          std::isnan(t_element)) {
        *wd = all_ones;
      } else {
        *wd = 0;
      }
    } break;
    case FCLE: {
      if (s_element > t_element || std::isnan(s_element) ||
          std::isnan(t_element)) {
        *wd = 0;
      } else {
        *wd = all_ones;
      }
    } break;
    case FCULE: {
      if (s_element <= t_element || std::isnan(s_element) ||
          std::isnan(t_element)) {
        *wd = all_ones;
      } else {
        *wd = 0;
      }
    } break;
    case FCOR: {
      if (std::isnan(s_element) || std::isnan(t_element)) {
        *wd = 0;
      } else {
        *wd = all_ones;
      }
    } break;
    case FCUNE: {
      if (s_element != t_element || std::isnan(s_element) ||
          std::isnan(t_element)) {
        *wd = all_ones;
      } else {
        *wd = 0;
      }
    } break;
    case FCNE: {
      if (s_element == t_element || std::isnan(s_element) ||
          std::isnan(t_element)) {
        *wd = 0;
      } else {
        *wd = all_ones;
      }
    } break;
    case FADD:
      *wd = base::bit_cast<T_int>(s_element + t_element);
      break;
    case FSUB:
      *wd = base::bit_cast<T_int>(s_element - t_element);
      break;
    case FMUL:
      *wd = base::bit_cast<T_int>(s_element * t_element);
      break;
    case FDIV: {
      if (t_element == 0) {
        *wd = base::bit_cast<T_int>(std::numeric_limits<T_fp>::quiet_NaN());
      } else {
        *wd = base::bit_cast<T_int>(s_element / t_element);
      }
    } break;
    case FMADD:
      *wd = base::bit_cast<T_int>(
          std::fma(s_element, t_element, *reinterpret_cast<T_fp*>(wd)));
      break;
    case FMSUB:
      *wd = base::bit_cast<T_int>(
          std::fma(-s_element, t_element, *reinterpret_cast<T_fp*>(wd)));
      break;
    case FEXP2:
      *wd = base::bit_cast<T_int>(std::ldexp(s_element, static_cast<int>(wt)));
      break;
    case FMIN:
      *wd = base::bit_cast<T_int>(std::min(s_element, t_element));
      break;
    case FMAX:
      *wd = base::bit_cast<T_int>(std::max(s_element, t_element));
      break;
    case FMIN_A: {
      *wd = base::bit_cast<T_int>(
          std::fabs(s_element) < std::fabs(t_element) ? s_element : t_element);
    } break;
    case FMAX_A: {
      *wd = base::bit_cast<T_int>(
          std::fabs(s_element) > std::fabs(t_element) ? s_element : t_element);
    } break;
    case FSOR:
    case FSUNE:
    case FSNE:
    case FSAF:
    case FSUN:
    case FSEQ:
    case FSUEQ:
    case FSLT:
    case FSULT:
    case FSLE:
    case FSULE:
      UNIMPLEMENTED();
      break;
    default:
      UNREACHABLE();
  }
}

template <typename T_int, typename T_int_dbl, typename T_reg>
void Msa3RFInstrHelper2(uint32_t opcode, T_reg ws, T_reg wt, T_reg* wd) {
  //  using T_uint = typename std::make_unsigned<T_int>::type;
  using T_uint_dbl = typename std::make_unsigned<T_int_dbl>::type;
  const T_int max_int = std::numeric_limits<T_int>::max();
  const T_int min_int = std::numeric_limits<T_int>::min();
  const int shift = kBitsPerByte * sizeof(T_int) - 1;
  const T_int_dbl reg_s = ws;
  const T_int_dbl reg_t = wt;
  T_int_dbl product, result;
  product = reg_s * reg_t;
  switch (opcode) {
    case MUL_Q: {
      const T_int_dbl min_fix_dbl =
          base::bit_cast<T_uint_dbl>(std::numeric_limits<T_int_dbl
```