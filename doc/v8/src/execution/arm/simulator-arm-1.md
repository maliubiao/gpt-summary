Response: The user wants a summary of the C++ code provided, which is part 2 of 4 of a file simulating ARM instructions for the V8 JavaScript engine.

**Breakdown of the code:**

1. **`Simulator::ExecuteInstruction` (continuation):** This section handles the execution of various ARM instructions based on their opcode and type.
    *   **SVC (Software Interrupt):**  Handles calls to external C++ functions and breakpoints.
    *   **NaN Canonicalization:** Provides functions to standardize NaN representations for floats and doubles according to ARM standards.
    *   **Stop Helpers:** Functions to manage "stops" (breakpoints or specific points of interest) in the simulation.
    *   **Instruction Decoding:**  A series of `DecodeTypeX` functions that handle different ARM instruction formats. This part focuses on:
        *   Type 0 and 1 (Data Processing):  Includes arithmetic, logical, and move instructions, along with some special cases like multiply, extra loads/stores, and system register access (MSR/MRS).
        *   Type 2 (Load/Store with Immediate Offset): Handles basic memory access with immediate offsets.
        *   Type 3 (Load/Store with Register Offset): Deals with memory access where the offset is determined by a register, including extensions like signed/unsigned byte/half-word loads/stores.

2. **`Simulator::DecodeType3` (continuation):** This section continues handling instructions of type 3, which are more complex and include:
    *   Bitfield operations (extract, clear, insert).
    *   Multiply instructions with accumulate and high-part results.
    *   Division instructions.
    *   Byte reversal.
    *   Signed/unsigned extension operations.

3. **`Simulator::DecodeType4` (Load/Store Multiple):** Handles instructions that load or store multiple registers at once.

4. **`Simulator::DecodeType5` (Branch):**  Executes branch instructions, potentially with linking (saving the return address).

5. **`Simulator::DecodeType6` (Coprocessor Instructions):** Calls a separate function to handle coprocessor instructions.

6. **`Simulator::DecodeType7` (Software Interrupt/Coprocessor Instructions):** Handles software interrupts (SVC) and calls separate functions for specific coprocessors, notably VFP (Vector Floating Point) and CP15 (System Control Coprocessor).

7. **`Simulator::DecodeTypeVFP` (Vector Floating Point):**  Implements a subset of ARM's VFP instructions for floating-point operations.

8. **Helper Functions for VFP:**  Includes functions for:
    *   Moving data between core registers and VFP registers.
    *   Comparing floating-point numbers.
    *   Converting between single and double precision.
    *   Converting floating-point to integer with proper rounding and saturation.

**Relationship to JavaScript:**

This code is part of the V8 JavaScript engine, specifically the simulator used when the target architecture is ARM but the development environment might be different. The simulator allows V8 to execute JavaScript code on an ARM architecture without needing actual ARM hardware.

**Illustrative JavaScript Example:**

Since this section heavily deals with floating-point operations and integer conversions with specific rounding modes, a JavaScript example demonstrating these concepts would be relevant.

```javascript
// Example demonstrating floating-point behavior and potential integer conversions

let floatValue = 123.456;
let doubleValue = 987.654321;

// In JavaScript, the Number type is double-precision float
console.log("JavaScript float:", floatValue);
console.log("JavaScript double:", doubleValue);

// Integer conversion (JavaScript uses standard rounding)
let intFromFloat = parseInt(floatValue); // Standard rounding towards zero
console.log("Integer from float (parseInt):", intFromFloat);

// Simulate VFP-like conversion (rounding towards negative infinity for example)
function simulateVFPRoundDownToInt(doubleVal) {
  return Math.floor(doubleVal);
}
console.log("Simulated VFP round down:", simulateVFPRoundDownToInt(doubleValue));

// Demonstrating NaN handling
let nanValue = NaN;
console.log("NaN value:", nanValue);
console.log("Is NaN:", isNaN(nanValue));
```

This JavaScript example shows basic floating-point values and how JavaScript handles integer conversion. The simulated `simulateVFPRoundDownToInt` function hints at the more specific rounding modes the simulator needs to handle, which are crucial for accurate emulation of ARM's floating-point behavior when running JavaScript code. The NaN example relates to the `canonicalizeNaN` functions in the C++ code.
这个C++源代码文件是V8 JavaScript引擎中ARM架构模拟器的第二部分，主要负责**解码和执行各种ARM指令**。它是`Simulator::ExecuteInstruction`函数和其中调用的各种指令解码及处理函数的延续。

具体功能可以归纳如下：

1. **继续处理`Simulator::ExecuteInstruction`函数中的指令执行逻辑：**
    *   **处理软件中断 (SVC)：**  这是ARM中调用操作系统服务的指令。在模拟器中，它被用来调用外部的C++函数，用于执行一些特定的操作（例如系统调用、调用runtime函数等）。代码中可以看到对`UnsafeGenericFunctionCall`的调用，这正是模拟器执行外部C++函数的方式。
    *   **处理断点指令 (Breakpoint)：** 当遇到断点指令时，会调用调试器进行调试。
    *   **处理停止指令 (Stop)：**  模拟器可以设置一些“停止点”，当执行到这些点时，模拟器会暂停执行并输出信息，用于调试和分析。代码中实现了启用、禁用和计数停止点的机制。

2. **实现浮点数 NaN 的规范化：** 提供了将浮点数 NaN 值规范化为特定模式的函数，这符合ARM架构的规范。这确保了在模拟器中 NaN 的表示与真实ARM硬件的行为一致。

3. **提供停止点辅助功能：**  包含用于管理和控制模拟器停止点的函数，例如判断是否是受监控的停止点、是否启用、启用/禁用停止点、增加停止计数器以及打印停止点信息。

4. **实现各种ARM指令的解码和执行逻辑（`DecodeType01`，`DecodeType2`，`DecodeType3`）：**
    *   **`DecodeType01`：**  处理ARM指令类型0和1，涵盖了大量的数据处理指令，包括：
        *   算术运算 (ADD, SUB, RSB, ADC, SBC, RSC)。
        *   逻辑运算 (AND, EOR, ORR, BIC, MVN)。
        *   比较运算 (TST, TEQ, CMP, CMN)。
        *   移位操作。
        *   乘法指令 (MUL, MLA, MLS, UMULL, UMLAL, SMULL, SMLAL)。
        *   扩展的加载/存储指令 (LDRH, STRH, LDRSB, LDRSH, STRD, LDRD)。
        *   独占访问指令 (LDREX, STREX)。
        *   杂项指令 (MSR, MRS, BX, BLX, CLZ, BKPT)。
    *   **`DecodeType2`：** 处理类型2的加载和存储指令，这些指令使用立即数偏移量。
    *   **`DecodeType3`：** 处理类型3的加载和存储指令，这些指令使用寄存器偏移量，并且包含一些更复杂的指令，例如：
        *   位域操作 (UBFX, SBFX, BFC, BFI)。
        *   乘法指令 (SMMUL, SMMLA)。
        *   除法指令 (SDIV, UDIV)。
        *   字节反转指令 (REV)。
        *   符号和零扩展指令 (SXTAB, SXTB, SXTAH, SXTH, UXTAB, UXTB, UXTAH, UXTH)。
        *   打包指令 (PKHBT, PKHTB)。
        *   饱和指令 (USAT)。
        *   位反转指令 (RBIT)。

5. **实现类型4和类型5指令的解码和执行逻辑（`DecodeType4`，`DecodeType5`）：**
    *   **`DecodeType4`：** 处理批量加载和存储指令 (LDM, STM)，可以一次性加载或存储多个寄存器。
    *   **`DecodeType5`：** 处理分支指令 (B, BL)，用于控制程序的流程，`BL` 指令还会将返回地址保存到 `lr` 寄存器。

6. **实现类型6和类型7指令的解码和执行逻辑（`DecodeType6`，`DecodeType7`）：**
    *   **`DecodeType6`：**  处理协处理器指令，这部分代码调用了 `DecodeType6CoprocessorIns` 函数，具体实现可能在其他文件中。
    *   **`DecodeType7`：** 处理软件中断指令 (再次提到 SVC) 和协处理器指令，特别是针对 VFP (Vector Floating Point) 和 CP15 (System Control Coprocessor) 的指令。

7. **实现VFP协处理器的指令解码和执行逻辑（`DecodeTypeVFP`）：**  模拟了ARM VFP协处理器的一部分指令，用于处理浮点数运算，包括：
    *   数据传输指令 (VMOV)。
    *   类型转换指令 (VCVT)。
    *   绝对值指令 (VABS)。
    *   取反指令 (VNEG)。
    *   加法指令 (VADD)。
    *   减法指令 (VSUB)。
    *   乘法指令 (VMUL)。
    *   除法指令 (VDIV)。
    *   比较指令 (VCMP)。
    *   平方根指令 (VSQRT)。
    *   系统寄存器访问指令 (VMSR, VMRS)。
    *   重复元素指令 (VDUP)。

8. **提供VFP相关的辅助函数：**  例如，用于在核心寄存器和VFP寄存器之间移动数据、比较浮点数、在单精度和双精度之间转换、以及浮点数到整数的转换，并处理饱和和舍入模式。

**与 JavaScript 的功能关系：**

这个文件是 V8 引擎的一部分，V8 负责执行 JavaScript 代码。当 V8 需要在 ARM 架构上运行，但运行环境本身不是真实的 ARM 硬件时，就会使用这个模拟器。这个模拟器会解释执行 JavaScript 代码编译成的 ARM 机器码。

*   **浮点数运算：** JavaScript 中的 `Number` 类型本质上是双精度浮点数。`DecodeTypeVFP` 中模拟的浮点数运算指令（例如加减乘除、类型转换、比较等）直接对应了 JavaScript 中对数字进行操作时的底层实现。
*   **整数运算和位操作：** JavaScript 也支持整数运算和位操作。`DecodeType01` 和 `DecodeType3` 中模拟的算术、逻辑和位操作指令对应了 JavaScript 中 `+`, `-`, `*`, `/`, `&`, `|`, `^`, `<<`, `>>`, `>>>` 等运算符的底层实现。
*   **内存访问：**  JavaScript 引擎需要管理内存来存储对象和变量。`DecodeType2`, `DecodeType3`, `DecodeType4` 中模拟的加载和存储指令对应了 JavaScript 引擎在内存中读写数据的操作。
*   **函数调用和控制流：** JavaScript 中的函数调用和控制流（例如 `if`, `else`, 循环）最终会转化为机器码中的分支指令。`DecodeType5` 中模拟的分支指令对应了这些控制流的底层实现。
*   **NaN 处理：** JavaScript 中存在 `NaN` (Not a Number) 值。`canonicalizeNaN` 函数和 `DecodeTypeVFP` 中对 NaN 的处理确保了模拟器对 NaN 的行为与真实的 ARM 硬件一致，从而保证了 JavaScript 代码在模拟器中的执行结果的正确性。

**JavaScript 示例：**

```javascript
// 浮点数运算，对应 DecodeTypeVFP 中的指令
let a = 1.5;
let b = 2.5;
let sum = a + b; // 模拟 VADD 等指令

// 整数运算和位操作，对应 DecodeType01 和 DecodeType3 中的指令
let x = 10;
let y = 5;
let andResult = x & y; // 模拟 AND 指令
let shiftedX = x << 2; // 模拟移位指令

// 函数调用，对应 DecodeType5 中的指令
function myFunction() {
  return 42;
}
let result = myFunction(); // 模拟 BL 指令

// NaN 的处理，对应 canonicalizeNaN 和 DecodeTypeVFP 中的处理
let nanValue = 0 / 0;
console.log(isNaN(nanValue)); // 模拟对 NaN 的判断

// 类型转换，对应 DecodeTypeVFP 中的 VCVT 指令
let floatNum = 3.14;
let intNum = parseInt(floatNum); // JavaScript 的 parseInt 内部可能会涉及到浮点数到整数的转换
```

总结来说，这个 C++ 文件是 V8 引擎中至关重要的组成部分，它通过模拟 ARM 指令的执行，使得 JavaScript 代码能够在非 ARM 架构上进行开发、测试和运行。文件中实现的各种指令解码和执行逻辑，以及对浮点数和控制流的处理，都直接关联到 JavaScript 语言的底层实现。

### 提示词
```
这是目录为v8/src/execution/arm/simulator-arm.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```
2, arg13, arg14,
              arg15, arg16, arg17, arg18, arg19);
          if (!stack_aligned) {
            PrintF(" with unaligned stack %08x\n", get_register(sp));
          }
          PrintF("\n");
        }
        CHECK(stack_aligned);
        int64_t result = UnsafeGenericFunctionCall(
            external, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
            arg9, arg10, arg11, arg12, arg13, arg14, arg15, arg16, arg17, arg18,
            arg19);
#ifdef DEBUG
        TrashCallerSaveRegisters();
#endif
        int32_t lo_res = static_cast<int32_t>(result);
        int32_t hi_res = static_cast<int32_t>(result >> 32);
        if (InstructionTracingEnabled()) {
          PrintF("Returned %08x\n", lo_res);
        }
        set_register(r0, lo_res);
        set_register(r1, hi_res);
      }
      set_register(lr, saved_lr);
      set_pc(get_register(lr));
      break;
    }
    case kBreakpoint:
      ArmDebugger(this).Debug();
      break;
    // stop uses all codes greater than 1 << 23.
    default:
      if (svc >= (1 << 23)) {
        uint32_t code = svc & kStopCodeMask;
        if (isWatchedStop(code)) {
          IncreaseStopCounter(code);
        }
        // Stop if it is enabled, otherwise go on jumping over the stop
        // and the message address.
        if (isEnabledStop(code)) {
          if (code != kMaxStopCode) {
            PrintF("Simulator hit stop %u. ", code);
          } else {
            PrintF("Simulator hit stop. ");
          }
          DebugAtNextPC();
        }
      } else {
        // This is not a valid svc code.
        UNREACHABLE();
      }
  }
}

float Simulator::canonicalizeNaN(float value) {
  // Default NaN value, see "NaN handling" in "IEEE 754 standard implementation
  // choices" of the ARM Reference Manual.
  constexpr uint32_t kDefaultNaN = 0x7FC00000u;
  if (FPSCR_default_NaN_mode_ && std::isnan(value)) {
    value = base::bit_cast<float>(kDefaultNaN);
  }
  return value;
}

Float32 Simulator::canonicalizeNaN(Float32 value) {
  // Default NaN value, see "NaN handling" in "IEEE 754 standard implementation
  // choices" of the ARM Reference Manual.
  constexpr Float32 kDefaultNaN = Float32::FromBits(0x7FC00000u);
  return FPSCR_default_NaN_mode_ && value.is_nan() ? kDefaultNaN : value;
}

double Simulator::canonicalizeNaN(double value) {
  // Default NaN value, see "NaN handling" in "IEEE 754 standard implementation
  // choices" of the ARM Reference Manual.
  constexpr uint64_t kDefaultNaN = uint64_t{0x7FF8000000000000};
  if (FPSCR_default_NaN_mode_ && std::isnan(value)) {
    value = base::bit_cast<double>(kDefaultNaN);
  }
  return value;
}

Float64 Simulator::canonicalizeNaN(Float64 value) {
  // Default NaN value, see "NaN handling" in "IEEE 754 standard implementation
  // choices" of the ARM Reference Manual.
  constexpr Float64 kDefaultNaN =
      Float64::FromBits(uint64_t{0x7FF8000000000000});
  return FPSCR_default_NaN_mode_ && value.is_nan() ? kDefaultNaN : value;
}

// Stop helper functions.
bool Simulator::isWatchedStop(uint32_t code) {
  DCHECK_LE(code, kMaxStopCode);
  return code < kNumOfWatchedStops;
}

bool Simulator::isEnabledStop(uint32_t code) {
  DCHECK_LE(code, kMaxStopCode);
  // Unwatched stops are always enabled.
  return !isWatchedStop(code) ||
         !(watched_stops_[code].count & kStopDisabledBit);
}

void Simulator::EnableStop(uint32_t code) {
  DCHECK(isWatchedStop(code));
  if (!isEnabledStop(code)) {
    watched_stops_[code].count &= ~kStopDisabledBit;
  }
}

void Simulator::DisableStop(uint32_t code) {
  DCHECK(isWatchedStop(code));
  if (isEnabledStop(code)) {
    watched_stops_[code].count |= kStopDisabledBit;
  }
}

void Simulator::IncreaseStopCounter(uint32_t code) {
  DCHECK_LE(code, kMaxStopCode);
  DCHECK(isWatchedStop(code));
  if ((watched_stops_[code].count & ~(1 << 31)) == 0x7FFFFFFF) {
    PrintF(
        "Stop counter for code %i has overflowed.\n"
        "Enabling this code and reseting the counter to 0.\n",
        code);
    watched_stops_[code].count = 0;
    EnableStop(code);
  } else {
    watched_stops_[code].count++;
  }
}

// Print a stop status.
void Simulator::PrintStopInfo(uint32_t code) {
  DCHECK_LE(code, kMaxStopCode);
  if (!isWatchedStop(code)) {
    PrintF("Stop not watched.");
  } else {
    const char* state = isEnabledStop(code) ? "Enabled" : "Disabled";
    int32_t count = watched_stops_[code].count & ~kStopDisabledBit;
    // Don't print the state of unused breakpoints.
    if (count != 0) {
      if (watched_stops_[code].desc) {
        PrintF("stop %i - 0x%x: \t%s, \tcounter = %i, \t%s\n", code, code,
               state, count, watched_stops_[code].desc);
      } else {
        PrintF("stop %i - 0x%x: \t%s, \tcounter = %i\n", code, code, state,
               count);
      }
    }
  }
}

// Handle execution based on instruction types.

// Instruction types 0 and 1 are both rolled into one function because they
// only differ in the handling of the shifter_operand.
void Simulator::DecodeType01(Instruction* instr) {
  int type = instr->TypeValue();
  if ((type == 0) && instr->IsSpecialType0()) {
    // multiply instruction or extra loads and stores
    if (instr->Bits(7, 4) == 9) {
      if (instr->Bit(24) == 0) {
        // Raw field decoding here. Multiply instructions have their Rd in
        // funny places.
        int rn = instr->RnValue();
        int rm = instr->RmValue();
        int rs = instr->RsValue();
        int32_t rs_val = get_register(rs);
        int32_t rm_val = get_register(rm);
        if (instr->Bit(23) == 0) {
          if (instr->Bit(21) == 0) {
            // The MUL instruction description (A 4.1.33) refers to Rd as being
            // the destination for the operation, but it confusingly uses the
            // Rn field to encode it.
            // Format(instr, "mul'cond's 'rn, 'rm, 'rs");
            int rd = rn;  // Remap the rn field to the Rd register.
            int32_t alu_out = base::MulWithWraparound(rm_val, rs_val);
            set_register(rd, alu_out);
            if (instr->HasS()) {
              SetNZFlags(alu_out);
            }
          } else {
            int rd = instr->RdValue();
            int32_t acc_value = get_register(rd);
            if (instr->Bit(22) == 0) {
              // The MLA instruction description (A 4.1.28) refers to the order
              // of registers as "Rd, Rm, Rs, Rn". But confusingly it uses the
              // Rn field to encode the Rd register and the Rd field to encode
              // the Rn register.
              // Format(instr, "mla'cond's 'rn, 'rm, 'rs, 'rd");
              int32_t mul_out = base::MulWithWraparound(rm_val, rs_val);
              int32_t result = base::AddWithWraparound(acc_value, mul_out);
              set_register(rn, result);
            } else {
              // Format(instr, "mls'cond's 'rn, 'rm, 'rs, 'rd");
              int32_t mul_out = base::MulWithWraparound(rm_val, rs_val);
              int32_t result = base::SubWithWraparound(acc_value, mul_out);
              set_register(rn, result);
            }
          }
        } else {
          // The signed/long multiply instructions use the terms RdHi and RdLo
          // when referring to the target registers. They are mapped to the Rn
          // and Rd fields as follows:
          // RdLo == Rd
          // RdHi == Rn (This is confusingly stored in variable rd here
          //             because the mul instruction from above uses the
          //             Rn field to encode the Rd register. Good luck figuring
          //             this out without reading the ARM instruction manual
          //             at a very detailed level.)
          // Format(instr, "'um'al'cond's 'rd, 'rn, 'rs, 'rm");
          int rd_hi = rn;  // Remap the rn field to the RdHi register.
          int rd_lo = instr->RdValue();
          int32_t hi_res = 0;
          int32_t lo_res = 0;
          if (instr->Bit(22) == 1) {
            int64_t left_op = static_cast<int32_t>(rm_val);
            int64_t right_op = static_cast<int32_t>(rs_val);
            uint64_t result = left_op * right_op;
            hi_res = static_cast<int32_t>(result >> 32);
            lo_res = static_cast<int32_t>(result & 0xFFFFFFFF);
          } else {
            // unsigned multiply
            uint64_t left_op = static_cast<uint32_t>(rm_val);
            uint64_t right_op = static_cast<uint32_t>(rs_val);
            uint64_t result = left_op * right_op;
            hi_res = static_cast<int32_t>(result >> 32);
            lo_res = static_cast<int32_t>(result & 0xFFFFFFFF);
          }
          set_register(rd_lo, lo_res);
          set_register(rd_hi, hi_res);
          if (instr->HasS()) {
            UNIMPLEMENTED();
          }
        }
      } else {
        if (instr->Bits(24, 23) == 3) {
          if (instr->Bit(20) == 1) {
            // ldrex
            int rt = instr->RtValue();
            int rn = instr->RnValue();
            int32_t addr = get_register(rn);
            switch (instr->Bits(22, 21)) {
              case 0: {
                // Format(instr, "ldrex'cond 'rt, ['rn]");
                int value = ReadExW(addr);
                set_register(rt, value);
                break;
              }
              case 1: {
                // Format(instr, "ldrexd'cond 'rt, ['rn]");
                int* rn_data = ReadExDW(addr);
                set_dw_register(rt, rn_data);
                break;
              }
              case 2: {
                // Format(instr, "ldrexb'cond 'rt, ['rn]");
                uint8_t value = ReadExBU(addr);
                set_register(rt, value);
                break;
              }
              case 3: {
                // Format(instr, "ldrexh'cond 'rt, ['rn]");
                uint16_t value = ReadExHU(addr);
                set_register(rt, value);
                break;
              }
              default:
                UNREACHABLE();
            }
          } else {
            // The instruction is documented as strex rd, rt, [rn], but the
            // "rt" register is using the rm bits.
            int rd = instr->RdValue();
            int rt = instr->RmValue();
            int rn = instr->RnValue();
            DCHECK_NE(rd, rn);
            DCHECK_NE(rd, rt);
            int32_t addr = get_register(rn);
            switch (instr->Bits(22, 21)) {
              case 0: {
                // Format(instr, "strex'cond 'rd, 'rm, ['rn]");
                int value = get_register(rt);
                int status = WriteExW(addr, value);
                set_register(rd, status);
                break;
              }
              case 1: {
                // Format(instr, "strexd'cond 'rd, 'rm, ['rn]");
                DCHECK_EQ(rt % 2, 0);
                int32_t value1 = get_register(rt);
                int32_t value2 = get_register(rt + 1);
                int status = WriteExDW(addr, value1, value2);
                set_register(rd, status);
                break;
              }
              case 2: {
                // Format(instr, "strexb'cond 'rd, 'rm, ['rn]");
                uint8_t value = get_register(rt);
                int status = WriteExB(addr, value);
                set_register(rd, status);
                break;
              }
              case 3: {
                // Format(instr, "strexh'cond 'rd, 'rm, ['rn]");
                uint16_t value = get_register(rt);
                int status = WriteExH(addr, value);
                set_register(rd, status);
                break;
              }
              default:
                UNREACHABLE();
            }
          }
        } else {
          UNIMPLEMENTED();  // Not used by V8.
        }
      }
    } else {
      // extra load/store instructions
      int rd = instr->RdValue();
      int rn = instr->RnValue();
      int32_t rn_val = get_register(rn);
      int32_t addr = 0;
      if (instr->Bit(22) == 0) {
        int rm = instr->RmValue();
        int32_t rm_val = get_register(rm);
        switch (instr->PUField()) {
          case da_x: {
            // Format(instr, "'memop'cond'sign'h 'rd, ['rn], -'rm");
            DCHECK(!instr->HasW());
            addr = rn_val;
            rn_val = base::SubWithWraparound(rn_val, rm_val);
            set_register(rn, rn_val);
            break;
          }
          case ia_x: {
            // Format(instr, "'memop'cond'sign'h 'rd, ['rn], +'rm");
            DCHECK(!instr->HasW());
            addr = rn_val;
            rn_val = base::AddWithWraparound(rn_val, rm_val);
            set_register(rn, rn_val);
            break;
          }
          case db_x: {
            // Format(instr, "'memop'cond'sign'h 'rd, ['rn, -'rm]'w");
            rn_val = base::SubWithWraparound(rn_val, rm_val);
            addr = rn_val;
            if (instr->HasW()) {
              set_register(rn, rn_val);
            }
            break;
          }
          case ib_x: {
            // Format(instr, "'memop'cond'sign'h 'rd, ['rn, +'rm]'w");
            rn_val = base::AddWithWraparound(rn_val, rm_val);
            addr = rn_val;
            if (instr->HasW()) {
              set_register(rn, rn_val);
            }
            break;
          }
          default: {
            // The PU field is a 2-bit field.
            UNREACHABLE();
          }
        }
      } else {
        int32_t imm_val = (instr->ImmedHValue() << 4) | instr->ImmedLValue();
        switch (instr->PUField()) {
          case da_x: {
            // Format(instr, "'memop'cond'sign'h 'rd, ['rn], #-'off8");
            DCHECK(!instr->HasW());
            addr = rn_val;
            rn_val = base::SubWithWraparound(rn_val, imm_val);
            set_register(rn, rn_val);
            break;
          }
          case ia_x: {
            // Format(instr, "'memop'cond'sign'h 'rd, ['rn], #+'off8");
            DCHECK(!instr->HasW());
            addr = rn_val;
            rn_val = base::AddWithWraparound(rn_val, imm_val);
            set_register(rn, rn_val);
            break;
          }
          case db_x: {
            // Format(instr, "'memop'cond'sign'h 'rd, ['rn, #-'off8]'w");
            rn_val = base::SubWithWraparound(rn_val, imm_val);
            addr = rn_val;
            if (instr->HasW()) {
              set_register(rn, rn_val);
            }
            break;
          }
          case ib_x: {
            // Format(instr, "'memop'cond'sign'h 'rd, ['rn, #+'off8]'w");
            rn_val = base::AddWithWraparound(rn_val, imm_val);
            addr = rn_val;
            if (instr->HasW()) {
              set_register(rn, rn_val);
            }
            break;
          }
          default: {
            // The PU field is a 2-bit field.
            UNREACHABLE();
          }
        }
      }
      if (((instr->Bits(7, 4) & 0xD) == 0xD) && (instr->Bit(20) == 0)) {
        DCHECK_EQ(rd % 2, 0);
        if (instr->HasH()) {
          // The strd instruction.
          int32_t value1 = get_register(rd);
          int32_t value2 = get_register(rd + 1);
          WriteDW(addr, value1, value2);
        } else {
          // The ldrd instruction.
          int* rn_data = ReadDW(addr);
          set_dw_register(rd, rn_data);
        }
      } else if (instr->HasH()) {
        if (instr->HasSign()) {
          if (instr->HasL()) {
            int16_t val = ReadH(addr);
            set_register(rd, val);
          } else {
            int16_t val = get_register(rd);
            WriteH(addr, val);
          }
        } else {
          if (instr->HasL()) {
            uint16_t val = ReadHU(addr);
            set_register(rd, val);
          } else {
            uint16_t val = get_register(rd);
            WriteH(addr, val);
          }
        }
      } else {
        // signed byte loads
        DCHECK(instr->HasSign());
        DCHECK(instr->HasL());
        int8_t val = ReadB(addr);
        set_register(rd, val);
      }
      return;
    }
  } else if ((type == 0) && instr->IsMiscType0()) {
    if ((instr->Bits(27, 23) == 2) && (instr->Bits(21, 20) == 2) &&
        (instr->Bits(15, 4) == 0xF00)) {
      // MSR
      int rm = instr->RmValue();
      DCHECK_NE(pc, rm);  // UNPREDICTABLE
      SRegisterFieldMask sreg_and_mask =
          instr->BitField(22, 22) | instr->BitField(19, 16);
      SetSpecialRegister(sreg_and_mask, get_register(rm));
    } else if ((instr->Bits(27, 23) == 2) && (instr->Bits(21, 20) == 0) &&
               (instr->Bits(11, 0) == 0)) {
      // MRS
      int rd = instr->RdValue();
      DCHECK_NE(pc, rd);  // UNPREDICTABLE
      SRegister sreg = static_cast<SRegister>(instr->BitField(22, 22));
      set_register(rd, GetFromSpecialRegister(sreg));
    } else if (instr->Bits(22, 21) == 1) {
      int rm = instr->RmValue();
      switch (instr->BitField(7, 4)) {
        case BX:
          set_pc(get_register(rm));
          break;
        case BLX: {
          uint32_t old_pc = get_pc();
          set_pc(get_register(rm));
          set_register(lr, old_pc + kInstrSize);
          break;
        }
        case BKPT:
          PrintF("Simulator hit BKPT. ");
          DebugAtNextPC();
          break;
        default:
          UNIMPLEMENTED();
      }
    } else if (instr->Bits(22, 21) == 3) {
      int rm = instr->RmValue();
      int rd = instr->RdValue();
      switch (instr->BitField(7, 4)) {
        case CLZ: {
          uint32_t bits = get_register(rm);
          int leading_zeros = 0;
          if (bits == 0) {
            leading_zeros = 32;
          } else {
            while ((bits & 0x80000000u) == 0) {
              bits <<= 1;
              leading_zeros++;
            }
          }
          set_register(rd, leading_zeros);
          break;
        }
        default:
          UNIMPLEMENTED();
      }
    } else {
      PrintF("%08x\n", instr->InstructionBits());
      UNIMPLEMENTED();
    }
  } else if ((type == 1) && instr->IsNopLikeType1()) {
    if (instr->BitField(7, 0) == 0) {
      // NOP.
    } else if (instr->BitField(7, 0) == 20) {
      // CSDB.
    } else {
      PrintF("%08x\n", instr->InstructionBits());
      UNIMPLEMENTED();
    }
  } else {
    int rd = instr->RdValue();
    int rn = instr->RnValue();
    int32_t rn_val = get_register(rn);
    int32_t shifter_operand = 0;
    bool shifter_carry_out = false;
    if (type == 0) {
      shifter_operand = GetShiftRm(instr, &shifter_carry_out);
    } else {
      DCHECK_EQ(instr->TypeValue(), 1);
      shifter_operand = GetImm(instr, &shifter_carry_out);
    }
    int32_t alu_out;

    switch (instr->OpcodeField()) {
      case AND: {
        // Format(instr, "and'cond's 'rd, 'rn, 'shift_rm");
        // Format(instr, "and'cond's 'rd, 'rn, 'imm");
        alu_out = rn_val & shifter_operand;
        set_register(rd, alu_out);
        if (instr->HasS()) {
          SetNZFlags(alu_out);
          SetCFlag(shifter_carry_out);
        }
        break;
      }

      case EOR: {
        // Format(instr, "eor'cond's 'rd, 'rn, 'shift_rm");
        // Format(instr, "eor'cond's 'rd, 'rn, 'imm");
        alu_out = rn_val ^ shifter_operand;
        set_register(rd, alu_out);
        if (instr->HasS()) {
          SetNZFlags(alu_out);
          SetCFlag(shifter_carry_out);
        }
        break;
      }

      case SUB: {
        // Format(instr, "sub'cond's 'rd, 'rn, 'shift_rm");
        // Format(instr, "sub'cond's 'rd, 'rn, 'imm");
        alu_out = base::SubWithWraparound(rn_val, shifter_operand);
        set_register(rd, alu_out);
        if (instr->HasS()) {
          SetNZFlags(alu_out);
          SetCFlag(!BorrowFrom(rn_val, shifter_operand));
          SetVFlag(OverflowFrom(alu_out, rn_val, shifter_operand, false));
        }
        break;
      }

      case RSB: {
        // Format(instr, "rsb'cond's 'rd, 'rn, 'shift_rm");
        // Format(instr, "rsb'cond's 'rd, 'rn, 'imm");
        alu_out = base::SubWithWraparound(shifter_operand, rn_val);
        set_register(rd, alu_out);
        if (instr->HasS()) {
          SetNZFlags(alu_out);
          SetCFlag(!BorrowFrom(shifter_operand, rn_val));
          SetVFlag(OverflowFrom(alu_out, shifter_operand, rn_val, false));
        }
        break;
      }

      case ADD: {
        // Format(instr, "add'cond's 'rd, 'rn, 'shift_rm");
        // Format(instr, "add'cond's 'rd, 'rn, 'imm");
        alu_out = base::AddWithWraparound(rn_val, shifter_operand);
        set_register(rd, alu_out);
        if (instr->HasS()) {
          SetNZFlags(alu_out);
          SetCFlag(CarryFrom(rn_val, shifter_operand));
          SetVFlag(OverflowFrom(alu_out, rn_val, shifter_operand, true));
        }
        break;
      }

      case ADC: {
        // Format(instr, "adc'cond's 'rd, 'rn, 'shift_rm");
        // Format(instr, "adc'cond's 'rd, 'rn, 'imm");
        alu_out = base::AddWithWraparound(
            base::AddWithWraparound(rn_val, shifter_operand), GetCarry());
        set_register(rd, alu_out);
        if (instr->HasS()) {
          SetNZFlags(alu_out);
          SetCFlag(CarryFrom(rn_val, shifter_operand, GetCarry()));
          SetVFlag(OverflowFrom(alu_out, rn_val, shifter_operand, true));
        }
        break;
      }

      case SBC: {
        //        Format(instr, "sbc'cond's 'rd, 'rn, 'shift_rm");
        //        Format(instr, "sbc'cond's 'rd, 'rn, 'imm");
        alu_out = base::SubWithWraparound(
            base::SubWithWraparound(rn_val, shifter_operand),
            (GetCarry() ? 0 : 1));
        set_register(rd, alu_out);
        if (instr->HasS()) {
          SetNZFlags(alu_out);
          SetCFlag(!BorrowFrom(rn_val, shifter_operand, GetCarry()));
          SetVFlag(OverflowFrom(alu_out, rn_val, shifter_operand, false));
        }
        break;
      }

      case RSC: {
        Format(instr, "rsc'cond's 'rd, 'rn, 'shift_rm");
        Format(instr, "rsc'cond's 'rd, 'rn, 'imm");
        break;
      }

      case TST: {
        if (instr->HasS()) {
          // Format(instr, "tst'cond 'rn, 'shift_rm");
          // Format(instr, "tst'cond 'rn, 'imm");
          alu_out = rn_val & shifter_operand;
          SetNZFlags(alu_out);
          SetCFlag(shifter_carry_out);
        } else {
          // Format(instr, "movw'cond 'rd, 'imm").
          alu_out = instr->ImmedMovwMovtValue();
          set_register(rd, alu_out);
        }
        break;
      }

      case TEQ: {
        if (instr->HasS()) {
          // Format(instr, "teq'cond 'rn, 'shift_rm");
          // Format(instr, "teq'cond 'rn, 'imm");
          alu_out = rn_val ^ shifter_operand;
          SetNZFlags(alu_out);
          SetCFlag(shifter_carry_out);
        } else {
          // Other instructions matching this pattern are handled in the
          // miscellaneous instructions part above.
          UNREACHABLE();
        }
        break;
      }

      case CMP: {
        if (instr->HasS()) {
          // Format(instr, "cmp'cond 'rn, 'shift_rm");
          // Format(instr, "cmp'cond 'rn, 'imm");
          alu_out = base::SubWithWraparound(rn_val, shifter_operand);
          SetNZFlags(alu_out);
          SetCFlag(!BorrowFrom(rn_val, shifter_operand));
          SetVFlag(OverflowFrom(alu_out, rn_val, shifter_operand, false));
        } else {
          // Format(instr, "movt'cond 'rd, 'imm").
          alu_out =
              (get_register(rd) & 0xFFFF) | (instr->ImmedMovwMovtValue() << 16);
          set_register(rd, alu_out);
        }
        break;
      }

      case CMN: {
        if (instr->HasS()) {
          // Format(instr, "cmn'cond 'rn, 'shift_rm");
          // Format(instr, "cmn'cond 'rn, 'imm");
          alu_out = base::AddWithWraparound(rn_val, shifter_operand);
          SetNZFlags(alu_out);
          SetCFlag(CarryFrom(rn_val, shifter_operand));
          SetVFlag(OverflowFrom(alu_out, rn_val, shifter_operand, true));
        } else {
          // Other instructions matching this pattern are handled in the
          // miscellaneous instructions part above.
          UNREACHABLE();
        }
        break;
      }

      case ORR: {
        // Format(instr, "orr'cond's 'rd, 'rn, 'shift_rm");
        // Format(instr, "orr'cond's 'rd, 'rn, 'imm");
        alu_out = rn_val | shifter_operand;
        set_register(rd, alu_out);
        if (instr->HasS()) {
          SetNZFlags(alu_out);
          SetCFlag(shifter_carry_out);
        }
        break;
      }

      case MOV: {
        // Format(instr, "mov'cond's 'rd, 'shift_rm");
        // Format(instr, "mov'cond's 'rd, 'imm");
        alu_out = shifter_operand;
        set_register(rd, alu_out);
        if (instr->HasS()) {
          SetNZFlags(alu_out);
          SetCFlag(shifter_carry_out);
        }
        break;
      }

      case BIC: {
        // Format(instr, "bic'cond's 'rd, 'rn, 'shift_rm");
        // Format(instr, "bic'cond's 'rd, 'rn, 'imm");
        alu_out = rn_val & ~shifter_operand;
        set_register(rd, alu_out);
        if (instr->HasS()) {
          SetNZFlags(alu_out);
          SetCFlag(shifter_carry_out);
        }
        break;
      }

      case MVN: {
        // Format(instr, "mvn'cond's 'rd, 'shift_rm");
        // Format(instr, "mvn'cond's 'rd, 'imm");
        alu_out = ~shifter_operand;
        set_register(rd, alu_out);
        if (instr->HasS()) {
          SetNZFlags(alu_out);
          SetCFlag(shifter_carry_out);
        }
        break;
      }

      default: {
        UNREACHABLE();
      }
    }
  }
}

void Simulator::DecodeType2(Instruction* instr) {
  int rd = instr->RdValue();
  int rn = instr->RnValue();
  int32_t rn_val = get_register(rn);
  int32_t im_val = instr->Offset12Value();
  int32_t addr = 0;
  switch (instr->PUField()) {
    case da_x: {
      // Format(instr, "'memop'cond'b 'rd, ['rn], #-'off12");
      DCHECK(!instr->HasW());
      addr = rn_val;
      rn_val -= im_val;
      set_register(rn, rn_val);
      break;
    }
    case ia_x: {
      // Format(instr, "'memop'cond'b 'rd, ['rn], #+'off12");
      DCHECK(!instr->HasW());
      addr = rn_val;
      rn_val += im_val;
      set_register(rn, rn_val);
      break;
    }
    case db_x: {
      // Format(instr, "'memop'cond'b 'rd, ['rn, #-'off12]'w");
      rn_val -= im_val;
      addr = rn_val;
      if (instr->HasW()) {
        set_register(rn, rn_val);
      }
      break;
    }
    case ib_x: {
      // Format(instr, "'memop'cond'b 'rd, ['rn, #+'off12]'w");
      rn_val += im_val;
      addr = rn_val;
      if (instr->HasW()) {
        set_register(rn, rn_val);
      }
      break;
    }
    default: {
      UNREACHABLE();
    }
  }
  if (instr->HasB()) {
    if (instr->HasL()) {
      uint8_t val = ReadBU(addr);
      set_register(rd, val);
    } else {
      uint8_t val = get_register(rd);
      WriteB(addr, val);
    }
  } else {
    if (instr->HasL()) {
      set_register(rd, ReadW(addr));
    } else {
      WriteW(addr, get_register(rd));
    }
  }
}

void Simulator::DecodeType3(Instruction* instr) {
  int rd = instr->RdValue();
  int rn = instr->RnValue();
  int32_t rn_val = get_register(rn);
  bool shifter_carry_out = false;
  int32_t shifter_operand = GetShiftRm(instr, &shifter_carry_out);
  int32_t addr = 0;
  switch (instr->PUField()) {
    case da_x: {
      DCHECK(!instr->HasW());
      Format(instr, "'memop'cond'b 'rd, ['rn], -'shift_rm");
      UNIMPLEMENTED();
    }
    case ia_x: {
      if (instr->Bit(4) == 0) {
        // Memop.
      } else {
        if (instr->Bit(5) == 0) {
          switch (instr->Bits(22, 21)) {
            case 0:
              if (instr->Bit(20) == 0) {
                if (instr->Bit(6) == 0) {
                  // Pkhbt.
                  uint32_t rn_val = get_register(rn);
                  uint32_t rm_val = get_register(instr->RmValue());
                  int32_t shift = instr->Bits(11, 7);
                  rm_val <<= shift;
                  set_register(rd, (rn_val & 0xFFFF) | (rm_val & 0xFFFF0000U));
                } else {
                  // Pkhtb.
                  uint32_t rn_val = get_register(rn);
                  int32_t rm_val = get_register(instr->RmValue());
                  int32_t shift = instr->Bits(11, 7);
                  if (shift == 0) {
                    shift = 32;
                  }
                  rm_val >>= shift;
                  set_register(rd, (rn_val & 0xFFFF0000U) | (rm_val & 0xFFFF));
                }
              } else {
                UNIMPLEMENTED();
              }
              break;
            case 1:
              UNIMPLEMENTED();
            case 2:
              UNIMPLEMENTED();
            case 3: {
              // Usat.
              int32_t sat_pos = instr->Bits(20, 16);
              int32_t sat_val = (1 << sat_pos) - 1;
              int32_t shift = instr->Bits(11, 7);
              int32_t shift_type = instr->Bit(6);
              int32_t rm_val = get_register(instr->RmValue());
              if (shift_type == 0) {  // LSL
                rm_val <<= shift;
              } else {  // ASR
                rm_val >>= shift;
              }
              // If saturation occurs, the Q flag should be set in the CPSR.
              // There is no Q flag yet, and no instruction (MRS) to read the
              // CPSR directly.
              if (rm_val > sat_val) {
                rm_val = sat_val;
              } else if (rm_val < 0) {
                rm_val = 0;
              }
              set_register(rd, rm_val);
              break;
            }
          }
        } else {
          switch (instr->Bits(22, 21)) {
            case 0:
              UNIMPLEMENTED();
            case 1:
              if (instr->Bits(9, 6) == 1) {
                if (instr->Bit(20) == 0) {
                  if (instr->Bits(19, 16) == 0xF) {
                    // Sxtb.
                    int32_t rm_val = get_register(instr->RmValue());
                    int32_t rotate = instr->Bits(11, 10);
                    switch (rotate) {
                      case 0:
                        break;
                      case 1:
                        rm_val = (rm_val >> 8) | (rm_val << 24);
                        break;
                      case 2:
                        rm_val = (rm_val >> 16) | (rm_val << 16);
                        break;
                      case 3:
                        rm_val = (rm_val >> 24) | (rm_val << 8);
                        break;
                    }
                    set_register(rd, static_cast<int8_t>(rm_val));
                  } else {
                    // Sxtab.
                    int32_t rn_val = get_register(rn);
                    int32_t rm_val = get_register(instr->RmValue());
                    int32_t rotate = instr->Bits(11, 10);
                    switch (rotate) {
                      case 0:
                        break;
                      case 1:
                        rm_val = (rm_val >> 8) | (rm_val << 24);
                        break;
                      case 2:
                        rm_val = (rm_val >> 16) | (rm_val << 16);
                        break;
                      case 3:
                        rm_val = (rm_val >> 24) | (rm_val << 8);
                        break;
                    }
                    set_register(rd, rn_val + static_cast<int8_t>(rm_val));
                  }
                } else {
                  if (instr->Bits(19, 16) == 0xF) {
                    // Sxth.
                    int32_t rm_val = get_register(instr->RmValue());
                    int32_t rotate = instr->Bits(11, 10);
                    switch (rotate) {
                      case 0:
                        break;
                      case 1:
                        rm_val = (rm_val >> 8) | (rm_val << 24);
                        break;
                      case 2:
                        rm_val = (rm_val >> 16) | (rm_val << 16);
                        break;
                      case 3:
                        rm_val = (rm_val >> 24) | (rm_val << 8);
                        break;
                    }
                    set_register(rd, static_cast<int16_t>(rm_val));
                  } else {
                    // Sxtah.
                    int32_t rn_val = get_register(rn);
                    int32_t rm_val = get_register(instr->RmValue());
                    int32_t rotate = instr->Bits(11, 10);
                    switch (rotate) {
                      case 0:
                        break;
                      case 1:
                        rm_val = (rm_val >> 8) | (rm_val << 24);
                        break;
                      case 2:
                        rm_val = (rm_val >> 16) | (rm_val << 16);
                        break;
                      case 3:
                        rm_val = (rm_val >> 24) | (rm_val << 8);
                        break;
                    }
                    set_register(rd, rn_val + static_cast<int16_t>(rm_val));
                  }
                }
              } else if (instr->Bits(27, 16) == 0x6BF &&
                         instr->Bits(11, 4) == 0xF3) {
                // Rev.
                uint32_t rm_val = get_register(instr->RmValue());
                set_register(rd, ByteReverse(rm_val));
              } else {
                UNREACHABLE();
              }
              break;
            case 2:
              if ((instr->Bit(20) == 0) && (instr->Bits(9, 6) == 1)) {
                if (instr->Bits(19, 16) == 0xF) {
                  // Uxtb16.
                  uint32_t rm_val = get_register(instr->RmValue());
                  int32_t rotate = instr->Bits(11, 10);
                  switch (rotate) {
                    case 0:
                      break;
                    case 1:
                      rm_val = (rm_val >> 8) | (rm_val << 24);
                      break;
                    case 2:
                      rm_val = (rm_val >> 16) | (rm_val << 16);
                      break;
                    case 3:
                      rm_val = (rm_val >> 24) | (rm_val << 8);
                      break;
                  }
                  set_register(rd, (rm_val & 0xFF) | (rm_val & 0xFF0000));
                } else {
                  UNIMPLEMENTED();
                }
              } else {
                UNIMPLEMENTED();
              }
              break;
            case 3:
              if ((instr->Bits(9, 6) == 1)) {
                if (instr->Bit(20) == 0) {
                  if (instr->Bits(19, 16) == 0xF) {
                    // Uxtb.
                    uint32_t rm_val = get_register(instr->RmValue());
                    int32_t rotate = instr->Bits(11, 10);
                    switch (rotate) {
                      case 0:
                        break;
                      case 1:
                        rm_val = (rm_val >> 8) | (rm_val << 24);
                        break;
                      case 2:
                        rm_val = (rm_val >> 16) | (rm_val << 16);
                        break;
                      case 3:
                        rm_val = (rm_val >> 24) | (rm_val << 8);
                        break;
                    }
                    set_register(rd, (rm_val & 0xFF));
                  } else {
                    // Uxtab.
                    uint32_t rn_val = get_register(rn);
                    uint32_t rm_val = get_register(instr->RmValue());
                    int32_t rotate = instr->Bits(11, 10);
                    switch (rotate) {
                      case 0:
                        break;
                      case 1:
                        rm_val = (rm_val >> 8) | (rm_val << 24);
                        break;
                      case 2:
                        rm_val = (rm_val >> 16) | (rm_val << 16);
                        break;
                      case 3:
                        rm_val = (rm_val >> 24) | (rm_val << 8);
                        break;
                    }
                    set_register(rd, rn_val + (rm_val & 0xFF));
                  }
                } else {
                  if (instr->Bits(19, 16) == 0xF) {
                    // Uxth.
                    uint32_t rm_val = get_register(instr->RmValue());
                    int32_t rotate = instr->Bits(11, 10);
                    switch (rotate) {
                      case 0:
                        break;
                      case 1:
                        rm_val = (rm_val >> 8) | (rm_val << 24);
                        break;
                      case 2:
                        rm_val = (rm_val >> 16) | (rm_val << 16);
                        break;
                      case 3:
                        rm_val = (rm_val >> 24) | (rm_val << 8);
                        break;
                    }
                    set_register(rd, (rm_val & 0xFFFF));
                  } else {
                    // Uxtah.
                    uint32_t rn_val = get_register(rn);
                    uint32_t rm_val = get_register(instr->RmValue());
                    int32_t rotate = instr->Bits(11, 10);
                    switch (rotate) {
                      case 0:
                        break;
                      case 1:
                        rm_val = (rm_val >> 8) | (rm_val << 24);
                        break;
                      case 2:
                        rm_val = (rm_val >> 16) | (rm_val << 16);
                        break;
                      case 3:
                        rm_val = (rm_val >> 24) | (rm_val << 8);
                        break;
                    }
                    set_register(rd, rn_val + (rm_val & 0xFFFF));
                  }
                }
              } else {
                // PU == 0b01, BW == 0b11, Bits(9, 6) != 0b0001
                if ((instr->Bits(20, 16) == 0x1F) &&
                    (instr->Bits(11, 4) == 0xF3)) {
                  // Rbit.
                  uint32_t rm_val = get_register(instr->RmValue());
                  set_register(rd, base::bits::ReverseBits(rm_val));
                } else {
                  UNIMPLEMENTED();
                }
              }
              break;
          }
        }
        return;
      }
      break;
    }
    case db_x: {
      if (instr->Bits(22, 20) == 0x5) {
        if (instr->Bits(7, 4) == 0x1) {
          int rm = instr->RmValue();
          int32_t rm_val = get_register(rm);
          int rs = instr->RsValue();
          int32_t rs_val = get_register(rs);
          if (instr->Bits(15, 12) == 0xF) {
            // SMMUL (in V8 notation matching ARM ISA format)
            // Format(instr, "smmul'cond 'rn, 'rm, 'rs");
            rn_val = base::bits::SignedMulHigh32(rm_val, rs_val);
          } else {
            // SMMLA (in V8 notation matching ARM ISA format)
            // Format(instr, "smmla'cond 'rn, 'rm, 'rs, 'rd");
            int rd = instr->RdValue();
            int32_t rd_val = get_register(rd);
            rn_val = base::bits::SignedMulHighAndAdd32(rm_val, rs_val, rd_val);
          }
          set_register(rn, rn_val);
          return;
        }
      }
      if (instr->Bits(5, 4) == 0x1) {
        if ((instr->Bit(22) == 0x0) && (instr->Bit(20) == 0x1)) {
          // (s/u)div (in V8 notation matching ARM ISA format) rn = rm/rs
          // Format(instr, "'(s/u)div'cond'b 'rn, 'rm, 'rs);
          int rm = instr->RmValue();
          int32_t rm_val = get_register(rm);
          int rs = instr->RsValue();
          int32_t rs_val = get_register(rs);
          int32_t ret_val = 0;
          // udiv
          if (instr->Bit(21) == 0x1) {
            ret_val = base::bit_cast<int32_t>(
                base::bits::UnsignedDiv32(base::bit_cast<uint32_t>(rm_val),
                                          base::bit_cast<uint32_t>(rs_val)));
          } else {
            ret_val = base::bits::SignedDiv32(rm_val, rs_val);
          }
          set_register(rn, ret_val);
          return;
        }
      }
      // Format(instr, "'memop'cond'b 'rd, ['rn, -'shift_rm]'w");
      addr = rn_val - shifter_operand;
      if (instr->HasW()) {
        set_register(rn, addr);
      }
      break;
    }
    case ib_x: {
      if (instr->HasW() && (instr->Bits(6, 4) == 0x5)) {
        uint32_t widthminus1 = static_cast<uint32_t>(instr->Bits(20, 16));
        uint32_t lsbit = static_cast<uint32_t>(instr->Bits(11, 7));
        uint32_t msbit = widthminus1 + lsbit;
        if (msbit <= 31) {
          if (instr->Bit(22)) {
            // ubfx - unsigned bitfield extract.
            uint32_t rm_val =
                static_cast<uint32_t>(get_register(instr->RmValue()));
            uint32_t extr_val = rm_val << (31 - msbit);
            extr_val = extr_val >> (31 - widthminus1);
            set_register(instr->RdValue(), extr_val);
          } else {
            // sbfx - signed bitfield extract.
            int32_t rm_val = get_register(instr->RmValue());
            int32_t extr_val = static_cast<uint32_t>(rm_val) << (31 - msbit);
            extr_val = extr_val >> (31 - widthminus1);
            set_register(instr->RdValue(), extr_val);
          }
        } else {
          UNREACHABLE();
        }
        return;
      } else if (!instr->HasW() && (instr->Bits(6, 4) == 0x1)) {
        uint32_t lsbit = static_cast<uint32_t>(instr->Bits(11, 7));
        uint32_t msbit = static_cast<uint32_t>(instr->Bits(20, 16));
        if (msbit >= lsbit) {
          // bfc or bfi - bitfield clear/insert.
          uint32_t rd_val =
              static_cast<uint32_t>(get_register(instr->RdValue()));
          uint32_t bitcount = msbit - lsbit + 1;
          uint32_t mask = 0xFFFFFFFFu >> (32 - bitcount);
          rd_val &= ~(mask << lsbit);
          if (instr->RmValue() != 15) {
            // bfi - bitfield insert.
            uint32_t rm_val =
                static_cast<uint32_t>(get_register(instr->RmValue()));
            rm_val &= mask;
            rd_val |= rm_val << lsbit;
          }
          set_register(instr->RdValue(), rd_val);
        } else {
          UNREACHABLE();
        }
        return;
      } else {
        // Format(instr, "'memop'cond'b 'rd, ['rn, +'shift_rm]'w");
        addr = base::AddWithWraparound(rn_val, shifter_operand);
        if (instr->HasW()) {
          set_register(rn, addr);
        }
      }
      break;
    }
    default: {
      UNREACHABLE();
    }
  }
  if (instr->HasB()) {
    if (instr->HasL()) {
      uint8_t byte = ReadB(addr);
      set_register(rd, byte);
    } else {
      uint8_t byte = get_register(rd);
      WriteB(addr, byte);
    }
  } else {
    if (instr->HasL()) {
      set_register(rd, ReadW(addr));
    } else {
      WriteW(addr, get_register(rd));
    }
  }
}

void Simulator::DecodeType4(Instruction* instr) {
  DCHECK_EQ(instr->Bit(22), 0);  // only allowed to be set in privileged mode
  if (instr->HasL()) {
    // Format(instr, "ldm'cond'pu 'rn'w, 'rlist");
    HandleRList(instr, true);
  } else {
    // Format(instr, "stm'cond'pu 'rn'w, 'rlist");
    HandleRList(instr, false);
  }
}

void Simulator::DecodeType5(Instruction* instr) {
  // Format(instr, "b'l'cond 'target");
  int off =
      static_cast<int>(static_cast<uint32_t>(instr->SImmed24Value()) << 2);
  intptr_t pc_address = get_pc();
  if (instr->HasLink()) {
    set_register(lr, pc_address + kInstrSize);
  }
  int pc_reg = get_register(pc);
  set_pc(pc_reg + off);
}

void Simulator::DecodeType6(Instruction* instr) {
  DecodeType6CoprocessorIns(instr);
}

void Simulator::DecodeType7(Instruction* instr) {
  if (instr->Bit(24) == 1) {
    SoftwareInterrupt(instr);
  } else {
    switch (instr->CoprocessorValue()) {
      case 10:  // Fall through.
      case 11:
        DecodeTypeVFP(instr);
        break;
      case 15:
        DecodeTypeCP15(instr);
        break;
      default:
        UNIMPLEMENTED();
    }
  }
}

// void Simulator::DecodeTypeVFP(Instruction* instr)
// The Following ARMv7 VFPv instructions are currently supported.
// vmov :Sn = Rt
// vmov :Rt = Sn
// vcvt: Dd = Sm
// vcvt: Sd = Dm
// vcvt.f64.s32 Dd, Dd, #<fbits>
// Dd = vabs(Dm)
// Sd = vabs(Sm)
// Dd = vneg(Dm)
// Sd = vneg(Sm)
// Dd = vadd(Dn, Dm)
// Sd = vadd(Sn, Sm)
// Dd = vsub(Dn, Dm)
// Sd = vsub(Sn, Sm)
// Dd = vmul(Dn, Dm)
// Sd = vmul(Sn, Sm)
// Dd = vdiv(Dn, Dm)
// Sd = vdiv(Sn, Sm)
// vcmp(Dd, Dm)
// vcmp(Sd, Sm)
// Dd = vsqrt(Dm)
// Sd = vsqrt(Sm)
// vmrs
// vdup.size Qd, Rt.
void Simulator::DecodeTypeVFP(Instruction* instr) {
  DCHECK((instr->TypeValue() == 7) && (instr->Bit(24) == 0x0));
  DCHECK_EQ(instr->Bits(11, 9), 0x5);
  // Obtain single precision register codes.
  int m = instr->VFPMRegValue(kSinglePrecision);
  int d = instr->VFPDRegValue(kSinglePrecision);
  int n = instr->VFPNRegValue(kSinglePrecision);
  // Obtain double precision register codes.
  int vm = instr->VFPMRegValue(kDoublePrecision);
  int vd = instr->VFPDRegValue(kDoublePrecision);
  int vn = instr->VFPNRegValue(kDoublePrecision);

  if (instr->Bit(4) == 0) {
    if (instr->Opc1Value() == 0x7) {
      // Other data processing instructions
      if ((instr->Opc2Value() == 0x0) && (instr->Opc3Value() == 0x1)) {
        // vmov register to register.
        if (instr->SzValue() == 0x1) {
          uint32_t data[2];
          get_d_register(vm, data);
          set_d_register(vd, data);
        } else {
          set_s_register(d, get_s_register(m));
        }
      } else if ((instr->Opc2Value() == 0x0) && (instr->Opc3Value() == 0x3)) {
        // vabs
        if (instr->SzValue() == 0x1) {
          Float64 dm = get_double_from_d_register(vm);
          constexpr uint64_t kSignBit64 = uint64_t{1} << 63;
          Float64 dd = Float64::FromBits(dm.get_bits() & ~kSignBit64);
          dd = canonicalizeNaN(dd);
          set_d_register_from_double(vd, dd);
        } else {
          Float32 sm = get_float_from_s_register(m);
          constexpr uint32_t kSignBit32 = uint32_t{1} << 31;
          Float32 sd = Float32::FromBits(sm.get_bits() & ~kSignBit32);
          sd = canonicalizeNaN(sd);
          set_s_register_from_float(d, sd);
        }
      } else if ((instr->Opc2Value() == 0x1) && (instr->Opc3Value() == 0x1)) {
        // vneg
        if (instr->SzValue() == 0x1) {
          Float64 dm = get_double_from_d_register(vm);
          constexpr uint64_t kSignBit64 = uint64_t{1} << 63;
          Float64 dd = Float64::FromBits(dm.get_bits() ^ kSignBit64);
          dd = canonicalizeNaN(dd);
          set_d_register_from_double(vd, dd);
        } else {
          Float32 sm = get_float_from_s_register(m);
          constexpr uint32_t kSignBit32 = uint32_t{1} << 31;
          Float32 sd = Float32::FromBits(sm.get_bits() ^ kSignBit32);
          sd = canonicalizeNaN(sd);
          set_s_register_from_float(d, sd);
        }
      } else if ((instr->Opc2Value() == 0x7) && (instr->Opc3Value() == 0x3)) {
        DecodeVCVTBetweenDoubleAndSingle(instr);
      } else if ((instr->Opc2Value() == 0x8) && (instr->Opc3Value() & 0x1)) {
        DecodeVCVTBetweenFloatingPointAndInteger(instr);
      } else if ((instr->Opc2Value() == 0xA) && (instr->Opc3Value() == 0x3) &&
                 (instr->Bit(8) == 1)) {
        // vcvt.f64.s32 Dd, Dd, #<fbits>
        int fraction_bits = 32 - ((instr->Bits(3, 0) << 1) | instr->Bit(5));
        int fixed_value = get_sinteger_from_s_register(vd * 2);
        double divide = 1 << fraction_bits;
        set_d_register_from_double(vd, fixed_value / divide);
      } else if (((instr->Opc2Value() >> 1) == 0x6) &&
                 (instr->Opc3Value() & 0x1)) {
        DecodeVCVTBetweenFloatingPointAndInteger(instr);
      } else if (((instr->Opc2Value() == 0x4) || (instr->Opc2Value() == 0x5)) &&
                 (instr->Opc3Value() & 0x1)) {
        DecodeVCMP(instr);
      } else if (((instr->Opc2Value() == 0x1)) && (instr->Opc3Value() == 0x3)) {
        // vsqrt
        if (instr->SzValue() == 0x1) {
          double dm_value = get_double_from_d_register(vm).get_scalar();
          double dd_value = std::sqrt(dm_value);
          dd_value = canonicalizeNaN(dd_value);
          set_d_register_from_double(vd, dd_value);
        } else {
          float sm_value = get_float_from_s_register(m).get_scalar();
          float sd_value = std::sqrt(sm_value);
          sd_value = canonicalizeNaN(sd_value);
          set_s_register_from_float(d, sd_value);
        }
      } else if (instr->Opc3Value() == 0x0) {
        // vmov immediate.
        if (instr->SzValue() == 0x1) {
          set_d_register_from_double(vd, instr->DoubleImmedVmov());
        } else {
          // Cast double to float.
          float value = instr->DoubleImmedVmov().get_scalar();
          set_s_register_from_float(d, value);
        }
      } else if (((instr->Opc2Value() == 0x6)) && (instr->Opc3Value() == 0x3)) {
        // vrintz - truncate
        if (instr->SzValue() == 0x1) {
          double dm_value = get_double_from_d_register(vm).get_scalar();
          double dd_value = trunc(dm_value);
          dd_value = canonicalizeNaN(dd_value);
          set_d_register_from_double(vd, dd_value);
        } else {
          float sm_value = get_float_from_s_register(m).get_scalar();
          float sd_value = truncf(sm_value);
          sd_value = canonicalizeNaN(sd_value);
          set_s_register_from_float(d, sd_value);
        }
      } else {
        UNREACHABLE();  // Not used by V8.
      }
    } else if (instr->Opc1Value() == 0x3) {
      if (instr->Opc3Value() & 0x1) {
        // vsub
        if (instr->SzValue() == 0x1) {
          double dn_value = get_double_from_d_register(vn).get_scalar();
          double dm_value = get_double_from_d_register(vm).get_scalar();
          double dd_value = dn_value - dm_value;
          dd_value = canonicalizeNaN(dd_value);
          set_d_register_from_double(vd, dd_value);
        } else {
          float sn_value = get_float_from_s_register(n).get_scalar();
          float sm_value = get_float_from_s_register(m).get_scalar();
          float sd_value = sn_value - sm_value;
          sd_value = canonicalizeNaN(sd_value);
          set_s_register_from_float(d, sd_value);
        }
      } else {
        // vadd
        if (instr->SzValue() == 0x1) {
          double dn_value = get_double_from_d_register(vn).get_scalar();
          double dm_value = get_double_from_d_register(vm).get_scalar();
          double dd_value = dn_value + dm_value;
          dd_value = canonicalizeNaN(dd_value);
          set_d_register_from_double(vd, dd_value);
        } else {
          float sn_value = get_float_from_s_register(n).get_scalar();
          float sm_value = get_float_from_s_register(m).get_scalar();
          float sd_value = sn_value + sm_value;
          sd_value = canonicalizeNaN(sd_value);
          set_s_register_from_float(d, sd_value);
        }
      }
    } else if ((instr->Opc1Value() == 0x2) && !(instr->Opc3Value() & 0x1)) {
      // vmul
      if (instr->SzValue() == 0x1) {
        double dn_value = get_double_from_d_register(vn).get_scalar();
        double dm_value = get_double_from_d_register(vm).get_scalar();
        double dd_value = dn_value * dm_value;
        dd_value = canonicalizeNaN(dd_value);
        set_d_register_from_double(vd, dd_value);
      } else {
        float sn_value = get_float_from_s_register(n).get_scalar();
        float sm_value = get_float_from_s_register(m).get_scalar();
        float sd_value = sn_value * sm_value;
        sd_value = canonicalizeNaN(sd_value);
        set_s_register_from_float(d, sd_value);
      }
    } else if ((instr->Opc1Value() == 0x0)) {
      // vmla, vmls
      const bool is_vmls = (instr->Opc3Value() & 0x1);
      if (instr->SzValue() == 0x1) {
        const double dd_val = get_double_from_d_register(vd).get_scalar();
        const double dn_val = get_double_from_d_register(vn).get_scalar();
        const double dm_val = get_double_from_d_register(vm).get_scalar();

        // Note: we do the mul and add/sub in separate steps to avoid getting a
        // result with too high precision.
        const double res = dn_val * dm_val;
        set_d_register_from_double(vd, res);
        if (is_vmls) {
          set_d_register_from_double(vd, canonicalizeNaN(dd_val - res));
        } else {
          set_d_register_from_double(vd, canonicalizeNaN(dd_val + res));
        }
      } else {
        const float sd_val = get_float_from_s_register(d).get_scalar();
        const float sn_val = get_float_from_s_register(n).get_scalar();
        const float sm_val = get_float_from_s_register(m).get_scalar();

        // Note: we do the mul and add/sub in separate steps to avoid getting a
        // result with too high precision.
        const float res = sn_val * sm_val;
        set_s_register_from_float(d, res);
        if (is_vmls) {
          set_s_register_from_float(d, canonicalizeNaN(sd_val - res));
        } else {
          set_s_register_from_float(d, canonicalizeNaN(sd_val + res));
        }
      }
    } else if ((instr->Opc1Value() == 0x4) && !(instr->Opc3Value() & 0x1)) {
      // vdiv
      if (instr->SzValue() == 0x1) {
        double dn_value = get_double_from_d_register(vn).get_scalar();
        double dm_value = get_double_from_d_register(vm).get_scalar();
        double dd_value = base::Divide(dn_value, dm_value);
        div_zero_vfp_flag_ = (dm_value == 0);
        dd_value = canonicalizeNaN(dd_value);
        set_d_register_from_double(vd, dd_value);
      } else {
        float sn_value = get_float_from_s_register(n).get_scalar();
        float sm_value = get_float_from_s_register(m).get_scalar();
        float sd_value = base::Divide(sn_value, sm_value);
        div_zero_vfp_flag_ = (sm_value == 0);
        sd_value = canonicalizeNaN(sd_value);
        set_s_register_from_float(d, sd_value);
      }
    } else {
      UNIMPLEMENTED();  // Not used by V8.
    }
  } else {
    if ((instr->VCValue() == 0x0) && (instr->VAValue() == 0x0)) {
      DecodeVMOVBetweenCoreAndSinglePrecisionRegisters(instr);
    } else if ((instr->VLValue() == 0x0) && (instr->VCValue() == 0x1)) {
      if (instr->Bit(23) == 0) {
        // vmov (ARM core register to scalar)
        int vd = instr->VFPNRegValue(kDoublePrecision);
        int rt = instr->RtValue();
        int opc1_opc2 = (instr->Bits(22, 21) << 2) | instr->Bits(6, 5);
        if ((opc1_opc2 & 0xB) == 0) {
          // NeonS32/NeonU32
          uint32_t data[2];
          get_d_register(vd, data);
          data[instr->Bit(21)] = get_register(rt);
          set_d_register(vd, data);
        } else {
          uint64_t data;
          get_d_register(vd, &data);
          uint64_t rt_value = get_register(rt);
          if ((opc1_opc2 & 0x8) != 0) {
            // NeonS8 / NeonU8
            int i = opc1_opc2 & 0x7;
            int shift = i * kBitsPerByte;
            const uint64_t mask = 0xFF;
            data &= ~(mask << shift);
            data |= (rt_value & mask) << shift;
            set_d_register(vd, &data);
          } else if ((opc1_opc2 & 0x1) != 0) {
            // NeonS16 / NeonU16
            int i = (opc1_opc2 >> 1) & 0x3;
            int shift = i * kBitsPerByte * kShortSize;
            const uint64_t mask = 0xFFFF;
            data &= ~(mask << shift);
            data |= (rt_value & mask) << shift;
            set_d_register(vd, &data);
          } else {
            UNREACHABLE();  // Not used by V8.
          }
        }
      } else {
        // vdup.size Qd, Rt.
        NeonSize size = Neon32;
        if (instr->Bit(5) != 0)
          size = Neon16;
        else if (instr->Bit(22) != 0)
          size = Neon8;
        int vd = instr->VFPNRegValue(kSimd128Precision);
        int rt = instr->RtValue();
        uint32_t rt_value = get_register(rt);
        uint32_t q_data[4];
        switch (size) {
          case Neon8: {
            rt_value &= 0xFF;
            uint8_t* dst = reinterpret_cast<uint8_t*>(q_data);
            for (int i = 0; i < 16; i++) {
              dst[i] = rt_value;
            }
            break;
          }
          case Neon16: {
            // Perform pairwise op.
            rt_value &= 0xFFFFu;
            uint32_t rt_rt = (rt_value << 16) | (rt_value & 0xFFFFu);
            for (int i = 0; i < 4; i++) {
              q_data[i] = rt_rt;
            }
            break;
          }
          case Neon32: {
            for (int i = 0; i < 4; i++) {
              q_data[i] = rt_value;
            }
            break;
          }
          default:
            UNREACHABLE();
        }
        set_neon_register(vd, q_data);
      }
    } else if ((instr->VLValue() == 0x1) && (instr->VCValue() == 0x1)) {
      // vmov (scalar to ARM core register)
      int vn = instr->VFPNRegValue(kDoublePrecision);
      int rt = instr->RtValue();
      int opc1_opc2 = (instr->Bits(22, 21) << 2) | instr->Bits(6, 5);
      uint64_t data;
      get_d_register(vn, &data);
      if ((opc1_opc2 & 0xB) == 0) {
        // NeonS32 / NeonU32
        DCHECK_EQ(0, instr->Bit(23));
        int32_t int_data[2];
        memcpy(int_data, &data, sizeof(int_data));
        set_register(rt, int_data[instr->Bit(21)]);
      } else {
        uint64_t data;
        get_d_register(vn, &data);
        bool u = instr->Bit(23) != 0;
        if ((opc1_opc2 & 0x8) != 0) {
          // NeonS8 / NeonU8
          int i = opc1_opc2 & 0x7;
          int shift = i * kBitsPerByte;
          uint32_t scalar = (data >> shift) & 0xFFu;
          if (!u && (scalar & 0x80) != 0) scalar |= 0xFFFFFF00;
          set_register(rt, scalar);
        } else if ((opc1_opc2 & 0x1) != 0) {
          // NeonS16 / NeonU16
          int i = (opc1_opc2 >> 1) & 0x3;
          int shift = i * kBitsPerByte * kShortSize;
          uint32_t scalar = (data >> shift) & 0xFFFFu;
          if (!u && (scalar & 0x8000) != 0) scalar |= 0xFFFF0000;
          set_register(rt, scalar);
        } else {
          UNREACHABLE();  // Not used by V8.
        }
      }
    } else if ((instr->VLValue() == 0x1) && (instr->VCValue() == 0x0) &&
               (instr->VAValue() == 0x7) && (instr->Bits(19, 16) == 0x1)) {
      // vmrs
      uint32_t rt = instr->RtValue();
      if (rt == 0xF) {
        Copy_FPSCR_to_APSR();
      } else {
        // Emulate FPSCR from the Simulator flags.
        uint32_t fpscr = (n_flag_FPSCR_ << 31) | (z_flag_FPSCR_ << 30) |
                         (c_flag_FPSCR_ << 29) | (v_flag_FPSCR_ << 28) |
                         (FPSCR_default_NaN_mode_ << 25) |
                         (inexact_vfp_flag_ << 4) | (underflow_vfp_flag_ << 3) |
                         (overflow_vfp_flag_ << 2) | (div_zero_vfp_flag_ << 1) |
                         (inv_op_vfp_flag_ << 0) | (FPSCR_rounding_mode_);
        set_register(rt, fpscr);
      }
    } else if ((instr->VLValue() == 0x0) && (instr->VCValue() == 0x0) &&
               (instr->VAValue() == 0x7) && (instr->Bits(19, 16) == 0x1)) {
      // vmsr
      uint32_t rt = instr->RtValue();
      if (rt == pc) {
        UNREACHABLE();
      } else {
        uint32_t rt_value = get_register(rt);
        n_flag_FPSCR_ = (rt_value >> 31) & 1;
        z_flag_FPSCR_ = (rt_value >> 30) & 1;
        c_flag_FPSCR_ = (rt_value >> 29) & 1;
        v_flag_FPSCR_ = (rt_value >> 28) & 1;
        FPSCR_default_NaN_mode_ = (rt_value >> 25) & 1;
        inexact_vfp_flag_ = (rt_value >> 4) & 1;
        underflow_vfp_flag_ = (rt_value >> 3) & 1;
        overflow_vfp_flag_ = (rt_value >> 2) & 1;
        div_zero_vfp_flag_ = (rt_value >> 1) & 1;
        inv_op_vfp_flag_ = (rt_value >> 0) & 1;
        FPSCR_rounding_mode_ =
            static_cast<VFPRoundingMode>((rt_value)&kVFPRoundingModeMask);
      }
    } else {
      UNIMPLEMENTED();  // Not used by V8.
    }
  }
}

void Simulator::DecodeTypeCP15(Instruction* instr) {
  DCHECK((instr->TypeValue() == 7) && (instr->Bit(24) == 0x0));
  DCHECK_EQ(instr->CoprocessorValue(), 15);

  if (instr->Bit(4) == 1) {
    // mcr
    int crn = instr->Bits(19, 16);
    int crm = instr->Bits(3, 0);
    int opc1 = instr->Bits(23, 21);
    int opc2 = instr->Bits(7, 5);
    if ((opc1 == 0) && (crn == 7)) {
      // ARMv6 memory barrier operations.
      // Details available in ARM DDI 0406C.b, B3-1750.
      if (((crm == 10) && (opc2 == 5)) ||  // CP15DMB
          ((crm == 10) && (opc2 == 4)) ||  // CP15DSB
          ((crm == 5) && (opc2 == 4))) {   // CP15ISB
        // These are ignored by the simulator for now.
      } else {
        UNIMPLEMENTED();
      }
    }
  } else {
    UNIMPLEMENTED();
  }
}

void Simulator::DecodeVMOVBetweenCoreAndSinglePrecisionRegisters(
    Instruction* instr) {
  DCHECK((instr->Bit(4) == 1) && (instr->VCValue() == 0x0) &&
         (instr->VAValue() == 0x0));

  int t = instr->RtValue();
  int n = instr->VFPNRegValue(kSinglePrecision);
  bool to_arm_register = (instr->VLValue() == 0x1);

  if (to_arm_register) {
    int32_t int_value = get_sinteger_from_s_register(n);
    set_register(t, int_value);
  } else {
    int32_t rs_val = get_register(t);
    set_s_register_from_sinteger(n, rs_val);
  }
}

void Simulator::DecodeVCMP(Instruction* instr) {
  DCHECK((instr->Bit(4) == 0) && (instr->Opc1Value() == 0x7));
  DCHECK(((instr->Opc2Value() == 0x4) || (instr->Opc2Value() == 0x5)) &&
         (instr->Opc3Value() & 0x1));
  // Comparison.

  VFPRegPrecision precision = kSinglePrecision;
  if (instr->SzValue() == 0x1) {
    precision = kDoublePrecision;
  }

  int d = instr->VFPDRegValue(precision);
  int m = 0;
  if (instr->Opc2Value() == 0x4) {
    m = instr->VFPMRegValue(precision);
  }

  if (precision == kDoublePrecision) {
    double dd_value = get_double_from_d_register(d).get_scalar();
    double dm_value = 0.0;
    if (instr->Opc2Value() == 0x4) {
      dm_value = get_double_from_d_register(m).get_scalar();
    }

    // Raise exceptions for quiet NaNs if necessary.
    if (instr->Bit(7) == 1) {
      if (std::isnan(dd_value)) {
        inv_op_vfp_flag_ = true;
      }
    }

    Compute_FPSCR_Flags(dd_value, dm_value);
  } else {
    float sd_value = get_float_from_s_register(d).get_scalar();
    float sm_value = 0.0;
    if (instr->Opc2Value() == 0x4) {
      sm_value = get_float_from_s_register(m).get_scalar();
    }

    // Raise exceptions for quiet NaNs if necessary.
    if (instr->Bit(7) == 1) {
      if (std::isnan(sd_value)) {
        inv_op_vfp_flag_ = true;
      }
    }

    Compute_FPSCR_Flags(sd_value, sm_value);
  }
}

void Simulator::DecodeVCVTBetweenDoubleAndSingle(Instruction* instr) {
  DCHECK((instr->Bit(4) == 0) && (instr->Opc1Value() == 0x7));
  DCHECK((instr->Opc2Value() == 0x7) && (instr->Opc3Value() == 0x3));

  VFPRegPrecision dst_precision = kDoublePrecision;
  VFPRegPrecision src_precision = kSinglePrecision;
  if (instr->SzValue() == 1) {
    dst_precision = kSinglePrecision;
    src_precision = kDoublePrecision;
  }

  int dst = instr->VFPDRegValue(dst_precision);
  int src = instr->VFPMRegValue(src_precision);

  if (dst_precision == kSinglePrecision) {
    double val = get_double_from_d_register(src).get_scalar();
    set_s_register_from_float(dst, static_cast<float>(val));
  } else {
    float val = get_float_from_s_register(src).get_scalar();
    set_d_register_from_double(dst, static_cast<double>(val));
  }
}

bool get_inv_op_vfp_flag(VFPRoundingMode mode, double val, bool unsigned_) {
  DCHECK((mode == RN) || (mode == RM) || (mode == RZ));
  double max_uint = static_cast<double>(0xFFFFFFFFu);
  double max_int = static_cast<double>(kMaxInt);
  double min_int = static_cast<double>(kMinInt);

  // Check for NaN.
  if (val != val) {
    return true;
  }

  // Check for overflow. This code works because 32bit integers can be
  // exactly represented by ieee-754 64bit floating-point values.
  switch (mode) {
    case RN:
      return unsigned_ ? (val >= (max_uint + 0.5)) || (val < -0.5)
                       : (val >= (max_int + 0.5)) || (val < (min_int - 0.5));

    case RM:
      return unsigned_ ? (val >= (max_uint + 1.0)) || (val < 0)
                       : (val >= (max_int + 1.0)) || (val < min_int);

    case RZ:
      return unsigned_ ? (val >= (max_uint + 1.0)) || (val <= -1)
                       : (val >= (max_int + 1.0)) || (val <= (min_int - 1.0));
    default:
      UNREACHABLE();
  }
}

// We call this function only if we had a vfp invalid exception.
// It returns the correct saturated value.
int VFPConversionSaturate(double val, bool unsigned_res) {
  if (val != val) {
    return 0;
  } else {
    if (unsigned_res) {
      return (val < 0) ? 0 : 0xFFFFFFFFu;
    } else {
      return (val < 0) ? kMinInt : kMaxInt;
    }
  }
}

int32_t Simulator::ConvertDoubleToInt(double val, bool unsigned_integer,
                                      VFPRoundingMode mode) {
  int32_t result;
  if (unsigned_integer) {
    // The FastD2UI helper does not have the rounding behavior we want here
    // (it doesn't guarantee any particular rounding, and it doesn't check
    // for or handle overflow), so do the conversion by hand.
    using limits = std::numeric_limits<uint32_t>;
    if (val > limits::max()) {
      result = limits::max();
    } else if (!(val >= 0)) {  // Negation to catch NaNs.
      result = 0;
    } else {
      result = static_cast<uint32_t>(val);
    }
  } else {
    result = FastD2IChecked(val);
  }

  inv_op_vfp_flag_ = get_inv_op_vfp_flag(mode, val, unsigned_integer);

  double abs_diff = unsigned_integer
                        ? std::fabs(val - static_cast<uint32_t>(result))
                        : std::fabs(val - result);

  inexact_vfp_flag_ = (abs_diff != 0);

  if (inv_op_vfp_flag_) {
    result = VFPConv
```