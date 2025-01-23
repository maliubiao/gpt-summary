Response:
The user wants a summary of the functionalities of the provided C++ code snippet from `v8/src/execution/arm/simulator-arm.cc`.

Here's a breakdown of the code's functionality:

1. **Generic Function Call Handling:**  The code handles calls to external C/C++ functions from the simulated ARM environment.
2. **Breakpoint Handling:** It implements a breakpoint mechanism for debugging.
3. **Stop Code Handling:**  It introduces the concept of "stop codes" for controlled simulation pauses and debugging.
4. **NaN Canonicalization:**  It provides functions to canonicalize NaN (Not a Number) values according to ARM standards.
5. **Stop Management:**  Functions to enable, disable, and count stop occurrences.
6. **Instruction Decoding and Execution (Partial):**  The code contains logic for decoding and executing various ARM instructions. This section is broken down by instruction type.
    - **Type 0 and 1 (Data Processing):**  Handles arithmetic, logical, and move instructions. Includes special handling for multiply and extended load/store instructions.
    - **Type 2 (Load/Store Immediate):** Handles loading and storing words and bytes with immediate offsets.
    - **Type 3 (Load/Store with Register Offset):**  Handles loading and storing with register offsets and includes more complex instruction decoding like `PKHBT`, `PKHTB`, `USAT`, `SXTB`, `SXAB`, `SXTH`, `SXAH`.

Considering this is "Part 3 of 7", the code likely focuses on a subset of the ARM instruction set.

**Plan:**

1. **List functionalities directly derived from the code.**
2. **Check for .tq extension:**  The filename ends in `.cc`, so it's C++, not Torque.
3. **Relate to JavaScript functionality:**  Connect the simulated ARM instructions to potential JavaScript operations they might represent at a lower level.
4. **Provide examples for code logic and assumptions.**
5. **Illustrate common programming errors.**
6. **Summarize the overall functionality of this part.**
这是 `v8/src/execution/arm/simulator-arm.cc` 源代码的第三部分，主要功能是模拟 ARM 架构的 CPU 指令执行。以下是其功能的详细列举：

**主要功能:**

1. **外部函数调用模拟 (Generic Function Call Handling):**
   - 允许模拟器调用外部 C/C++ 函数。
   - 负责设置函数调用的参数 (最多 20 个参数)。
   - 检查堆栈是否对齐 (stack alignment)。
   - 调用 `UnsafeGenericFunctionCall` 执行外部函数。
   - 获取外部函数的返回值，并将其设置回模拟器的寄存器 `r0` 和 `r1` (分别对应低 32 位和高 32 位)。
   - 恢复调用者的 `lr` 寄存器。
   - 将模拟器的程序计数器 `pc` 设置为返回地址。

2. **断点支持 (Breakpoint Handling):**
   - 当遇到 `kBreakpoint` 指令时，会调用 `ArmDebugger(this).Debug()`，允许进行交互式调试。

3. **停止码机制 (Stop Code Handling):**
   - 引入了 "停止码" (stop code) 的概念，允许在模拟执行过程中人为地设置停止点。
   - `kStopCodeMask` 用于提取停止码。
   - `isWatchedStop` 判断是否是被监控的停止码。
   - `IncreaseStopCounter` 增加停止码的计数器。
   - `isEnabledStop` 判断停止码是否被启用。
   - 如果停止码被启用 (`isEnabledStop(code)` 为真)，模拟器会打印停止信息并调用 `DebugAtNextPC()`，进入调试状态。
   - 未知的 `svc` 代码会导致 `UNREACHABLE()` 错误。

4. **NaN 值规范化 (NaN Canonicalization):**
   - 提供了一系列 `canonicalizeNaN` 函数，用于将浮点数 (float, double) 和 V8 内部浮点数类型 (Float32, Float64) 的 NaN 值规范化为 ARM 标准的默认 NaN 值。
   - 这取决于 `FPSCR_default_NaN_mode_` 的设置。

5. **停止码管理 (Stop Management):**
   - `isWatchedStop`: 检查给定的代码是否是“被监视”的停止点。
   - `isEnabledStop`: 检查给定的停止点是否已启用。
   - `EnableStop`: 启用一个被监视的停止点。
   - `DisableStop`: 禁用一个被监视的停止点。
   - `IncreaseStopCounter`: 增加特定停止点的计数器，并处理计数器溢出的情况。
   - `PrintStopInfo`: 打印特定停止点的状态信息，包括是否启用、计数器值和描述。

6. **指令解码和执行 (Instruction Decoding and Execution - 部分):**
   - 实现了部分 ARM 指令的解码和执行逻辑。
   - **`DecodeType01(Instruction* instr)`**: 处理类型 0 和类型 1 的指令，主要涉及数据处理指令，包括算术运算、逻辑运算、移位操作、乘法运算以及一些扩展的加载/存储指令。
     -  特别处理了 `MUL` (乘法), `MLA` (乘加), `MLS` (乘减), `UMULL`/`SMULL` (长乘法) 指令。
     -  支持独占加载 (`LDREX`) 和独占存储 (`STREX`) 指令。
     -  处理带有寄存器或立即数偏移的加载/存储半字 (`STRH`, `LDRH`) 和双字 (`STRD`, `LDRD`) 指令。
     -  支持 `MSR` (将寄存器值写入特殊寄存器) 和 `MRS` (从特殊寄存器读取值到寄存器) 指令。
     -  支持分支交换指令 `BX` 和带链接的分支交换指令 `BLX`。
     -  支持断点指令 `BKPT`。
     -  支持前导零计数指令 `CLZ`。
     -  实现了多种数据处理操作，如 `AND`, `EOR`, `SUB`, `RSB`, `ADD`, `ADC`, `SBC`, `TST`, `TEQ`, `CMP`, `CMN`, `ORR`, `MOV`, `BIC`, `MVN` 等。
   - **`DecodeType2(Instruction* instr)`**: 处理类型 2 的指令，主要涉及带有立即数偏移的加载和存储指令 (`LDR`, `STR`, `LDRB`, `STRB`)。
   - **`DecodeType3(Instruction* instr)`**: 处理类型 3 的指令，主要涉及带有寄存器偏移的加载和存储指令，以及一些其他的数据处理指令，例如 `PKHBT`, `PKHTB`, `USAT`, `SXTB`, `SXAB`, `SXTH`, `SXAH` 等。

**关于文件扩展名和 Torque:**

根据您提供的描述，`v8/src/execution/arm/simulator-arm.cc` 的确是以 `.cc` 结尾，这意味着它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件（Torque 源代码文件通常以 `.tq` 结尾）。

**与 JavaScript 功能的关系 (示例):**

模拟器执行的 ARM 指令最终是为了支持 JavaScript 的执行。以下是一些 JavaScript 功能与其可能对应的模拟器行为示例：

* **JavaScript 的数值运算 (+, -, *, /, %, &, |, ^, 等):**  模拟器中的 `ADD`, `SUB`, `MUL`, `AND`, `ORR`, `EOR` 等指令会直接对应 JavaScript 中的这些运算符。
   ```javascript
   let a = 10;
   let b = 5;
   let sum = a + b; // 模拟器会执行 ADD 指令
   let product = a * b; // 模拟器会执行 MUL 指令
   ```

* **JavaScript 的比较运算 (==, !=, >, <, >=, <=):** 模拟器中的 `CMP` 指令用于比较，并设置标志位，后续的分支指令会根据这些标志位决定程序的执行路径。
   ```javascript
   let x = 7;
   let y = 12;
   if (x < y) { // 模拟器会执行 CMP 指令，然后根据比较结果决定是否执行 if 块
       console.log("x is less than y");
   }
   ```

* **JavaScript 的变量赋值:** 模拟器中的 `MOV` 或存储指令 (`STR`) 用于将值写入内存或寄存器，对应 JavaScript 中变量的赋值操作。
   ```javascript
   let message = "Hello"; // 模拟器可能使用 MOV 指令将字符串的地址存储到寄存器中
   ```

* **JavaScript 的函数调用:** 模拟器中的外部函数调用机制 (`UnsafeGenericFunctionCall`) 用于调用 V8 引擎内部的 C++ 函数，这些函数实现了 JavaScript 的内置方法或运行时功能。
   ```javascript
   console.log("Hello"); // 模拟器会调用 V8 引擎中实现 console.log 功能的 C++ 函数
   ```

* **JavaScript 的内存操作 (例如，TypedArrays):** 模拟器中的加载 (`LDR`) 和存储 (`STR`) 指令用于访问内存，这与 JavaScript 中对 `ArrayBuffer` 或 `TypedArray` 的操作相关。
   ```javascript
   const buffer = new ArrayBuffer(8);
   const view = new Int32Array(buffer);
   view[0] = 42; // 模拟器会执行 STR 指令将 42 存储到内存中
   let value = view[0]; // 模拟器会执行 LDR 指令从内存中读取值
   ```

**代码逻辑推理 (假设输入与输出):**

假设模拟器执行到以下代码，且寄存器 `r0` 的值为 `0x1`, `r1` 的值为 `0x2`:

```c++
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
```

**假设输入:**

* `instr` 代表一个 `ADD` 指令，例如 `add r2, r0, r1` (将 `r0` 和 `r1` 的值相加，结果存入 `r2`)。
* `rn_val` (来自 `r0`) = `0x1`
* `shifter_operand` (来自 `r1`) = `0x2`
* `rd` (目标寄存器 `r2`)

**预期输出:**

* `alu_out` = `0x1 + 0x2 = 0x3`
* 寄存器 `r2` 的值将被设置为 `0x3`。
* 如果指令带有 `S` 后缀 (例如 `adds`)，则会根据结果 `0x3` 设置 N (负数) 和 Z (零) 标志位（N=0, Z=0）。C (进位) 和 V (溢出) 标志位也会根据加法运算的结果设置。

**用户常见的编程错误 (举例):**

1. **堆栈未对齐 (Stack misalignment) 在调用外部函数时:**
   - **错误示例 (C++ 中导致问题的场景):**  在手动汇编代码或进行底层操作时，错误地修改了堆栈指针，导致其不是 8 字节对齐。
   - **模拟器行为:**  模拟器会检测到堆栈未对齐，并可能打印警告信息，如代码中的 `PrintF(" with unaligned stack %08x\n", get_register(sp));`。这在实际硬件上可能会导致性能下降或错误。

2. **使用了错误的停止码:**
   - **错误示例:** 用户在调试时，错误地使用了未定义的或错误的停止码。
   - **模拟器行为:** 如果停止码 `>= (1 << 23)`，但不是一个已知的监控停止码，则不会触发预期的调试行为。如果 `svc` 代码小于 `(1 << 23)`，则会触发 `UNREACHABLE()`，表明这是一个无效的 `svc` 代码。

3. **误解独占加载/存储指令的使用:**
   - **错误示例:**  在多线程或并发场景中，不正确地使用 `LDREX` 和 `STREX` 指令来实现原子操作，例如在没有检查 `STREX` 的返回值就认为操作成功。
   - **模拟器行为:** 虽然模拟器本身不直接模拟多线程，但在模拟相关指令的行为时，可以帮助理解这些指令的语义。如果 `STREX` 操作失败（例如，由于其他模拟的核修改了内存），它会返回一个非零值，表示操作失败。

4. **忽视标志位的影响:**
   - **错误示例:**  在编写汇编代码时，没有正确理解数据处理指令是否会影响标志位，导致后续依赖这些标志位的条件分支行为不符合预期。
   - **模拟器行为:** 模拟器会准确地设置和使用标志位，帮助开发者理解指令的副作用。

**归纳功能 (本部分):**

总而言之，`v8/src/execution/arm/simulator-arm.cc` 的这一部分主要负责 **模拟 ARM 架构 CPU 的核心执行流程**，具体包括：

- **处理外部函数调用:** 允许模拟器与外部环境交互。
- **提供基本的调试支持:** 通过断点和停止码机制，方便调试模拟执行过程。
- **规范化 NaN 值:** 确保浮点运算的正确性。
- **管理停止码:**  为更精细的调试和测试提供支持。
- **解码和执行部分 ARM 指令:**  涵盖了数据处理、加载/存储等核心指令类型，是模拟器执行 JavaScript 代码的基础。

这部分代码是 V8 引擎在 ARM 架构上运行 JavaScript 代码的核心组成部分，它通过软件模拟硬件的行为，使得 V8 能够在非 ARM 硬件上进行测试和开发。

### 提示词
```
这是目录为v8/src/execution/arm/simulator-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/arm/simulator-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
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
```