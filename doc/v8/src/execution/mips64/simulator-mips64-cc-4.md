Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/execution/mips64/simulator-mips64.cc`. The request has several parts:

1. **List the functionality:**  Identify the main tasks the code performs.
2. **Torque source check:** Determine if the file could be a Torque file based on its extension (it isn't).
3. **JavaScript relation:** If the code relates to JavaScript functionality, provide a JavaScript example.
4. **Code logic inference:**  Present a scenario with inputs and expected outputs for a specific code section.
5. **Common programming errors:**  Point out potential user errors related to the code.
6. **Summary:**  Provide a concise overview of the code's purpose.

Let's break down the code snippet:

* It's part of a simulator for the MIPS64 architecture within the V8 JavaScript engine.
* The code contains methods like `DecodeTypeRegisterCOP1`, `DecodeTypeRegisterCOP1X`, `DecodeTypeRegisterSPECIAL`, `DecodeTypeRegisterSPECIAL2`, `DecodeTypeRegisterSPECIAL3`, `DecodeTypeMsaI8`, and `DecodeMsaDataFormat`.
* These methods seem to be responsible for decoding and simulating the execution of various MIPS64 instructions.
* There are different instruction types handled, including floating-point (COP1), general-purpose arithmetic and logical operations (SPECIAL), and MSA (MIPS SIMD Architecture) instructions.
* The code manipulates simulated registers (general-purpose, floating-point, MSA) and flags.
* It handles branching, arithmetic operations, bit manipulation, and potentially exceptions.

**Plan:**

1. State the primary function of the code: simulating MIPS64 instructions.
2. Address the Torque question: confirm it's not Torque based on the `.cc` extension.
3. Explain the connection to JavaScript: this code simulates the underlying architecture that executes JavaScript. Give a simple JS example that would translate to some of these MIPS instructions.
4. Choose a representative code block (e.g., a simple arithmetic operation within `DecodeTypeRegisterSPECIAL`) and provide an example with input register values and the expected output register value.
5. Identify common programming errors that could relate to MIPS assembly or the simulated environment (e.g., integer overflow, division by zero).
6. Summarize the code's role as a MIPS64 instruction simulator within V8.
```
这是目录为v8/src/execution/mips64/simulator-mips64.cc的一个v8源代码， 请列举一下它的功能,
如果v8/src/execution/mips64/simulator-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共9部分，请归纳一下它的功能
```

**功能归纳:**

这部分 `v8/src/execution/mips64/simulator-mips64.cc` 代码主要负责 **模拟 MIPS64 架构的指令执行过程**。具体来说，它实现了以下功能：

1. **解码 MIPS64 指令:**  代码中的 `DecodeTypeRegisterCOP1`, `DecodeTypeRegisterCOP1X`, `DecodeTypeRegisterSPECIAL`, `DecodeTypeRegisterSPECIAL2`, `DecodeTypeRegisterSPECIAL3`, `DecodeTypeMsaI8`, `DecodeMsaDataFormat` 等方法负责识别和解析不同的 MIPS64 指令格式和操作码。

2. **模拟指令操作:** 针对解码后的指令，代码模拟了这些指令在 MIPS64 架构上的具体行为，包括：
   - **算术和逻辑运算:**  例如加法、减法、乘法、除法、位运算（AND, OR, XOR, NOT）、移位等。
   - **浮点运算:**  处理浮点数的加法、减法、乘法、乘加、乘减等操作，以及与浮点控制状态寄存器 (FCSR) 相关的操作。
   - **跳转和分支:**  模拟无条件跳转 (JR, JALR) 和条件分支指令 (通过修改程序计数器 PC)。
   - **寄存器操作:**  模拟数据的读取和写入到通用寄存器、浮点寄存器以及 HI 和 LO 特殊寄存器。
   - **内存访问 (未在本段代码中直接体现，但在完整的模拟器中是必需的):**  尽管本段代码没有直接的内存访问指令，但它为后续的加载和存储指令的模拟奠定了基础。
   - **MIPS SIMD Architecture (MSA) 指令:**  模拟 MSA 扩展指令集的操作，包括向量化的算术、逻辑和数据处理。
   - **异常和中断处理:** 模拟某些指令可能触发的异常，例如整数溢出、除零错误等。

3. **维护模拟器状态:** 代码维护了模拟的 CPU 状态，包括通用寄存器 (`registers_`), 浮点寄存器 (`fpu_registers_`), 程序计数器 (`pc_`), HI 和 LO 寄存器，以及浮点控制状态寄存器 (`FCSR_`)。

4. **指令追踪:** 代码中存在 `TraceRegWr` 和 `TraceMSARegWr` 等函数调用，表明模拟器可能具有跟踪指令执行和寄存器变化的功能，这对于调试和理解代码执行过程很有用。

**关于是否为 Torque 源代码:**

`v8/src/execution/mips64/simulator-mips64.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件。 如果以 `.tq` 结尾，那才是 V8 Torque 源代码。

**与 JavaScript 的关系:**

`v8/src/execution/mips64/simulator-mips64.cc` 是 V8 JavaScript 引擎的一部分，它在以下方面与 JavaScript 功能相关：

- **JavaScript 执行的底层支撑:**  V8 引擎会将 JavaScript 代码编译成机器码（在 MIPS64 架构上运行时会编译成 MIPS64 指令）。这个模拟器允许开发者和 V8 团队在没有实际 MIPS64 硬件的情况下测试和调试生成的机器码。
- **理解 JavaScript 行为:** 了解这个模拟器的工作原理可以帮助理解 JavaScript 代码在底层是如何被执行的，例如，一个简单的 JavaScript 加法操作可能会对应到模拟器中 `DecodeTypeRegisterSPECIAL` 部分处理的 `ADD` 或 `DADD` 指令。

**JavaScript 示例:**

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
console.log(result); // 输出 15
```

当 V8 引擎执行这段 JavaScript 代码时，`a + b` 这个加法操作最终会被翻译成底层的 MIPS64 加法指令。 `v8/src/execution/mips64/simulator-mips64.cc` 中的代码就负责模拟这些 MIPS64 加法指令的执行。

**代码逻辑推理示例:**

选择 `DecodeTypeRegisterSPECIAL` 中的 `ADD` 指令部分进行推理：

```c++
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
```

**假设输入:**

- 当前执行的指令是 `ADD`
- 寄存器 `rs` 的值为 `5`
- 寄存器 `rt` 的值为 `10`
- 寄存器 `rd` 将存储结果

**输出:**

- `HaveSameSign(rs(), rt())` 返回 `true` (5 和 10 都是正数)。
- `rs() > 0` 为 `true`。
- `rs() > (Registers::kMaxValue - rt())` 为 `false` (假设 `Registers::kMaxValue` 是一个很大的正数，例如 `2^31 - 1`)。
- 不会触发异常。
- `SetResult(rd_reg(), rs() + rt())` 将把 `5 + 10 = 15` 写入到寄存器 `rd`。

**假设输入 (会触发溢出):**

- 当前执行的指令是 `ADD`
- 寄存器 `rs` 的值为 `2147483647` (接近 `int32` 的最大值)
- 寄存器 `rt` 的值为 `1`
- 寄存器 `rd` 将存储结果

**输出:**

- `HaveSameSign(rs(), rt())` 返回 `true`。
- `rs() > 0` 为 `true`。
- `rs() > (Registers::kMaxValue - rt())` 为 `true` (如果 `Registers::kMaxValue` 等于 `2147483647`)。
- `SignalException(kIntegerOverflow)` 将被调用，模拟整数溢出异常。
- `SetResult` 不会被执行，或者执行后结果可能不正确（取决于具体的模拟器实现）。

**用户常见的编程错误举例:**

与这段代码模拟的指令相关的常见编程错误包括：

1. **整数溢出:**  例如，在 C++ 或 JavaScript 中进行超出数据类型范围的整数运算。模拟器的 `ADD` 和 `DADD` 指令部分就模拟了这种错误的处理。

   ```javascript
   let maxInt = 2147483647;
   let result = maxInt + 1; // 在某些情况下可能会溢出，导致不期望的结果
   ```

2. **除零错误:** MIPS 架构的除法指令在除数为零时会产生未定义的行为或异常。 模拟器的 `DIV` 和 `DDIV` 指令部分处理了这种情况。

   ```javascript
   function divide(a, b) {
     return a / b;
   }

   let result = divide(10, 0); // 这将导致错误或异常
   ```

3. **位运算错误:**  对二进制数据进行错误的位操作，例如移位操作超出范围。 模拟器中的移位指令 (`SLL`, `SRL`, `SRA` 等) 的模拟有助于发现这类错误。

   ```javascript
   let num = 5; // 二进制 0101
   let shifted = num << 35; // 位移量过大，可能导致不期望的结果
   ```

**总结第5部分的功能:**

这部分代码是 MIPS64 架构模拟器的核心组成部分，它专注于 **解码和模拟各种 MIPS64 指令的执行**，包括浮点运算、通用算术和逻辑运算、跳转分支指令以及 MSA 扩展指令。它维护了模拟的 CPU 状态，并能检测某些类型的错误，为 V8 引擎在 MIPS64 平台上的正确运行提供了基础。

Prompt: 
```
这是目录为v8/src/execution/mips64/simulator-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/mips64/simulator-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共9部分，请归纳一下它的功能

"""
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
      set_msa_register(instr_.WdValue(
"""


```