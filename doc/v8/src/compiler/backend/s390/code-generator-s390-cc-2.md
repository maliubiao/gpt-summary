Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/compiler/backend/s390/code-generator-s390.cc`. They are asking for a summary of its functions, specifically as part 3 of a 5-part series.

Here's a breakdown of how to address the request:

1. **Identify the core purpose:** The filename `code-generator-s390.cc` suggests this code is responsible for generating machine code for the s390 architecture within the V8 compiler.

2. **Analyze the structure:** The code consists of a large `switch` statement within a loop (implied by the iteration over `instr`). Each `case` handles a specific `kArch...` or `kS390_...` instruction. This means the code is mapping high-level, architecture-neutral instructions to s390 assembly instructions.

3. **Categorize the functionalities:**  The `case` labels reveal different categories of operations:
    * **Memory access:** `kArchLoad`, `kArchStore`, `kArchStackSlot`, `kS390_Peek`, `kS390_Push`, `kS390_StoreToStackSlot`.
    * **Arithmetic and logical operations:** `kS390_Abs`, `kS390_And`, `kS390_Or`, `kS390_Xor`, `kS390_ShiftLeft`, `kS390_ShiftRight`, `kS390_RotRight`, `kS390_Add`, `kS390_Sub`, `kS390_Mul`, `kS390_Div`, `kS390_Mod`, `kS390_Neg`.
    * **Floating-point operations:** `kS390_AddFloat`, `kS390_SubFloat`, `kS390_MulFloat`, `kS390_DivFloat`, `kS390_AbsFloat`, `kS390_SqrtFloat`, `kS390_FloorFloat`, `kS390_CeilFloat`, `kS390_TruncateFloat`, along with many `kIeee754Float64...` cases.
    * **Bit manipulation:** `kS390_Cntlz`, `kS390_Popcnt`.
    * **Comparisons:** `kS390_Cmp`, `kS390_Tst`.
    * **Conversions:**  Various `kS390_...ToInt`, `kS390_...ToFloat` conversions.
    * **Bitcasting:** `kS390_Bitcast...`.
    * **SIMD operations:**  Implied by `kS390_LoadReverseSimd128RR` and `MachineRepresentation::kSimd128`.
    * **Write barriers:** `kArchStoreWithWriteBarrier`.
    * **Stack checks:** `kArchStackCheckOffset`.

4. **Relate to JavaScript (if applicable):** Many of these operations have direct counterparts in JavaScript. Arithmetic, logical, comparison, and type conversion operations are fundamental. Floating-point operations are crucial for numerical computations.

5. **Illustrate with JavaScript examples:** Choose a few common operations and show their JavaScript equivalents. For example, `kS390_Add32` maps to `+`, `kS390_MulDouble` to `*`, type conversions like `Number(value)`.

6. **Consider potential programming errors:**  Think about common mistakes related to the listed operations, such as integer overflow, floating-point precision issues, incorrect type conversions.

7. **Formulate assumptions for input/output (if applicable):** For specific instructions like arithmetic operations, provide example input registers and their expected output.

8. **Address the `.tq` check:** Explain that `.tq` files indicate Torque source code, and this file is `.cc`, meaning it's regular C++.

9. **Synthesize the summary (part 3):** Combine the identified functionalities and their relationship to compilation into a concise summary, keeping in mind this is part 3 of 5. Focus on the code generation aspect.

**Self-Correction/Refinement:**

* Initially, I might focus too much on individual instruction details. The request is for a functional summary, so grouping related functionalities is more effective.
*  The "part 3 of 5" hint suggests the earlier parts likely covered higher-level compilation stages. Therefore, emphasize this code's role in the *backend* of the compiler.
* Ensure the JavaScript examples are clear and directly related to the C++ operations.
* The assumption/input-output part is most relevant for binary operations. For memory access or control flow, it might be less directly applicable. Focus on instructions where the input and output are clearly defined.
看起来你提供的代码是 `v8/src/compiler/backend/s390/code-generator-s390.cc` 文件的一部分，这个文件是 V8 引擎中负责将中间代码（通常是 Hydrogen 或 Lithium）转换成 s390 架构的机器码的关键组件。

**功能归纳 (第 3 部分):**

基于你提供的代码片段，可以归纳出 `v8/src/compiler/backend/s390/code-generator-s390.cc` 的以下功能：

1. **实现 S390 架构特定的指令生成:** 这段代码的核心功能是根据输入的中间指令 (`Instruction* instr`)，生成对应的 S390 汇编指令。`switch` 语句根据不同的 `opcode()` 值，分发到不同的代码生成逻辑，每个 `case` 分支都负责处理特定的操作，例如加载、存储、算术运算、逻辑运算、浮点运算、类型转换等等。

2. **处理内存访问指令:** 代码中包含了处理内存加载 (`kArchLoad`) 和存储 (`kArchStore`, `kArchStoreWithWriteBarrier`) 的逻辑，包括直接寻址和基于寄存器偏移的寻址。它还处理了栈帧操作 (`kArchStackSlot`, `kS390_Peek`, `kS390_Push`, `kS390_StoreToStackSlot`)。

3. **实现算术和逻辑运算:**  代码片段涵盖了大量的 S390 架构的算术和逻辑运算指令，包括加法 (`kS390_Add32`, `kS390_Add64`, `kS390_AddFloat`, `kS390_AddDouble`)、减法 (`kS390_Sub32`, `kS390_Sub64`, `kS390_SubFloat`, `kS390_SubDouble`)、乘法 (`kS390_Mul32`, `kS390_Mul64`, `kS390_MulFloat`, `kS390_MulDouble`)、除法 (`kS390_Div32`, `kS390_Div64`, `kS390_DivFloat`, `kS390_DivDouble`)、取模 (`kS390_Mod32`, `kS390_Mod64`)、绝对值 (`kS390_Abs32`, `kS390_Abs64`, `kS390_AbsFloat`, `kS390_AbsDouble`)、位运算（与 `kS390_And32`, `kS390_And64`，或 `kS390_Or32`, `kS390_Or64`，异或 `kS390_Xor32`, `kS390_Xor64`，移位 `kS390_ShiftLeft`, `kS390_ShiftRight`，循环移位 `kS390_RotRight`）。

4. **处理浮点运算:**  代码包含了对单精度和双精度浮点数的各种运算，包括基本的算术运算、平方根 (`kS390_SqrtFloat`, `kS390_SqrtDouble`)、 floor (`kS390_FloorFloat`, `kS390_FloorDouble`)、ceil (`kS390_CeilFloat`, `kS390_CeilDouble`)、truncate (`kS390_TruncateFloat`, `kS390_TruncateDouble`) 以及 IEEE 754 标准的数学函数 (例如 `kIeee754Float64Acos`, `kIeee754Float64Sin` 等)。

5. **实现类型转换:**  代码负责生成将不同数据类型之间进行转换的指令，例如整数到浮点数 (`kS390_Int64ToFloat32`, `kS390_Int64ToDouble`)、浮点数到整数 (`kS390_DoubleToInt32`, `kS390_DoubleToUint32`)，以及不同大小整数之间的转换 (`kS390_SignExtendWord8ToInt32`, `kS390_Uint32ToUint64`)。

6. **处理位操作:**  包含了计算前导零个数 (`kS390_Cntlz32`, `kS390_Cntlz64`) 和人口计数（popcount，计算二进制表示中 1 的个数）(`kS390_Popcnt32`, `kS390_Popcnt64`) 的指令。

7. **实现比较操作:**  提供了生成比较指令的逻辑，用于整数 (`kS390_Cmp32`, `kS390_Cmp64`) 和浮点数 (`kS390_CmpFloat`, `kS390_CmpDouble`) 的比较。也包含了测试指令 (`kS390_Tst32`, `kS390_Tst64`)。

8. **处理位类型转换和数据操作:**  包含了将浮点数和整数之间进行位模式转换的操作 (`kS390_BitcastFloat32ToInt32`, `kS390_BitcastDoubleToInt64`)，以及从 32 位字构建双精度浮点数 (`kS390_DoubleFromWord32Pair`) 和提取双精度浮点数的低/高 32 位字 (`kS390_DoubleExtractLowWord32`, `kS390_DoubleExtractHighWord32`)。

9. **实现加载和存储特定大小的数据:**  提供了加载不同大小整数的指令 (`kS390_LoadWordS8`, `kS390_LoadWordU16` 等) 以及字节序反转的加载指令 (`kS390_LoadReverse16`, `kS390_LoadReverse32`, `kS390_LoadReverse64`)。

**关于文件类型和 JavaScript 关系:**

* **文件类型:** `v8/src/compiler/backend/s390/code-generator-s390.cc` 以 `.cc` 结尾，这表明它是一个 **C++ 源代码文件**。如果以 `.tq` 结尾，那它才是一个 V8 Torque 源代码文件。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。

* **与 JavaScript 的关系:**  `v8/src/compiler/backend/s390/code-generator-s390.cc`  直接影响 JavaScript 代码的执行性能。当 V8 编译 JavaScript 代码时，这个文件中的代码会生成实际在 S390 架构的 CPU 上运行的机器码。例如，JavaScript 中的算术运算符（`+`, `-`, `*`, `/`），位运算符（`&`, `|`, `^`, `<<`, `>>`），以及 Math 对象中的各种数学函数（`Math.sqrt()`, `Math.floor()`, `Math.sin()` 等）的执行，最终都会依赖于这里生成的 S390 汇编指令。

**JavaScript 示例:**

以下是一些 JavaScript 代码示例，它们的功能会涉及到 `v8/src/compiler/backend/s390/code-generator-s390.cc` 中生成的 S390 汇编指令：

```javascript
// 算术运算 (对应 kS390_Add32, kS390_MulDouble 等)
let a = 10;
let b = 5;
let sum = a + b;
let product = a * 3.14;

// 位运算 (对应 kS390_And32, kS390_ShiftLeft32 等)
let x = 0b1010;
let y = 0b1100;
let andResult = x & y;
let shifted = x << 2;

// 浮点数运算 (对应 kS390_AddFloat, kIeee754Float64Sin 等)
let angle = Math.PI / 2;
let sineValue = Math.sin(angle);
let squareRoot = Math.sqrt(25);

// 类型转换 (对应 kS390_DoubleToInt32 等)
let floatNum = 12.34;
let intNum = parseInt(floatNum);

// 比较运算 (对应 kS390_Cmp32, kS390_CmpDouble 等)
let p = 20;
let q = 25;
if (p < q) {
  console.log("p is less than q");
}
```

当 V8 编译并执行这些 JavaScript 代码时，`code-generator-s390.cc` 中的代码会生成相应的 S390 机器码来实现这些操作。

**代码逻辑推理示例 (假设输入与输出):**

假设有一个中间指令 `instr`，其 `opcode()` 为 `kS390_Add64`，输入寄存器 `i.InputRegister(0)` 包含值 `0x10`，`i.InputRegister(1)` 包含值 `0x20`，输出寄存器为 `i.OutputRegister(0)`。

**假设输入:**
* `instr->opcode()`: `kS390_Add64`
* `i.InputRegister(0)`: 寄存器 R5，值为 `0x10`
* `i.InputRegister(1)`: 寄存器 R6，值为 `0x20`
* `i.OutputRegister(0)`: 寄存器 R7

**代码逻辑 (摘自代码片段):**
```c++
case kS390_Add64:
  if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
    ASSEMBLE_BIN_OP(RRRInstr(agrk), RM64Instr(ag), RRIInstr(AddS64));
  } else {
    ASSEMBLE_BIN_OP(RRInstr(agr), RM64Instr(ag), RIInstr(agfi));
  }
  break;
```
这段代码会根据 CPU 是否支持 `DISTINCT_OPS` 特性，生成不同的加法指令。假设不支持，则会生成 `agr` 指令。

**预期输出 (生成的 S390 汇编指令):**
```assembly
agr r7, r5, r6  // 将 r5 和 r6 的值相加，结果存储到 r7
```

**用户常见的编程错误示例:**

如果生成的代码涉及到类型转换，用户可能会遇到以下编程错误：

```javascript
// 错误示例 1: 浮点数转整数精度丢失
let largeFloat = 9007199254740992.0; // 大于 2^53 的浮点数
let intValue = parseInt(largeFloat); // intValue 的值可能不等于 largeFloat

// 错误示例 2: 未注意整数溢出
let maxInt = 2147483647;
let overflow = maxInt + 1; // overflow 的值可能会回绕到最小值

// 错误示例 3: 浮点数比较的精度问题
let num1 = 0.1 + 0.2;
let num2 = 0.3;
if (num1 !== num2) { // 浮点数运算可能导致精度误差
  console.log("num1 is not equal to num2"); // 这段代码可能会执行
}
```

`code-generator-s390.cc` 生成的代码会忠实地执行这些操作，但不会主动防止这些编程错误。这些错误需要在 JavaScript 代码层面进行预防和处理。

总而言之，`v8/src/compiler/backend/s390/code-generator-s390.cc` 是 V8 引擎将 JavaScript 代码转换为可在 S390 架构上执行的机器码的关键部分，它负责实现各种语言结构和操作符的底层指令生成。

### 提示词
```
这是目录为v8/src/compiler/backend/s390/code-generator-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/s390/code-generator-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
lhs_register, sp, Operand(offset));
      }

      constexpr size_t kValueIndex = 0;
      DCHECK(instr->InputAt(kValueIndex)->IsRegister());
      __ CmpU64(lhs_register, i.InputRegister(kValueIndex));
      break;
    }
    case kArchStackCheckOffset:
      __ LoadSmiLiteral(i.OutputRegister(),
                        Smi::FromInt(GetStackCheckOffset()));
      break;
    case kArchTruncateDoubleToI:
      __ TruncateDoubleToI(isolate(), zone(), i.OutputRegister(),
                           i.InputDoubleRegister(0), DetermineStubCallMode());
      break;
    case kArchStoreWithWriteBarrier: {
      RecordWriteMode mode = RecordWriteModeField::decode(instr->opcode());
      AddressingMode addressing_mode =
          AddressingModeField::decode(instr->opcode());
      Register object = i.InputRegister(0);
      size_t index = 0;
      MemOperand operand = i.MemoryOperand(&addressing_mode, &index);
      Register value = i.InputRegister(index);
      Register scratch0 = i.TempRegister(0);
      Register scratch1 = i.TempRegister(1);

      if (v8_flags.debug_code) {
        // Checking that |value| is not a cleared weakref: our write barrier
        // does not support that for now.
        __ CmpS64(value, Operand(kClearedWeakHeapObjectLower32));
        __ Check(ne, AbortReason::kOperandIsCleared);
      }

      OutOfLineRecordWrite* ool = zone()->New<OutOfLineRecordWrite>(
          this, object, operand, value, scratch0, scratch1, mode,
          DetermineStubCallMode(), &unwinding_info_writer_);
      __ StoreTaggedField(value, operand);

      if (mode > RecordWriteMode::kValueIsPointer) {
        __ JumpIfSmi(value, ool->exit());
      }
      __ CheckPageFlag(object, scratch0,
                       MemoryChunk::kPointersFromHereAreInterestingMask, ne,
                       ool->entry());
      __ bind(ool->exit());
      break;
    }
    case kArchStoreIndirectWithWriteBarrier:
      UNREACHABLE();
    case kArchStackSlot: {
      FrameOffset offset =
          frame_access_state()->GetFrameOffset(i.InputInt32(0));
      __ AddS64(i.OutputRegister(), offset.from_stack_pointer() ? sp : fp,
                Operand(offset.offset()));
      break;
    }
    case kS390_Peek: {
      int reverse_slot = i.InputInt32(0);
      int offset =
          FrameSlotToFPOffset(frame()->GetTotalFrameSlotCount() - reverse_slot);
      if (instr->OutputAt(0)->IsFPRegister()) {
        LocationOperand* op = LocationOperand::cast(instr->OutputAt(0));
        if (op->representation() == MachineRepresentation::kFloat64) {
          __ LoadF64(i.OutputDoubleRegister(), MemOperand(fp, offset));
        } else if (op->representation() == MachineRepresentation::kFloat32) {
          __ LoadF32(i.OutputFloatRegister(), MemOperand(fp, offset));
        } else {
          DCHECK_EQ(MachineRepresentation::kSimd128, op->representation());
          __ LoadV128(i.OutputSimd128Register(), MemOperand(fp, offset),
                      kScratchReg);
        }
      } else {
        __ LoadU64(i.OutputRegister(), MemOperand(fp, offset));
      }
      break;
    }
    case kS390_Abs32:
      // TODO(john.yan): zero-ext
      __ lpr(i.OutputRegister(0), i.InputRegister(0));
      break;
    case kS390_Abs64:
      __ lpgr(i.OutputRegister(0), i.InputRegister(0));
      break;
    case kS390_And32:
      // zero-ext
      if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
        ASSEMBLE_BIN32_OP(RRRInstr(nrk), RM32Instr(And), RIInstr(nilf));
      } else {
        ASSEMBLE_BIN32_OP(RRInstr(nr), RM32Instr(And), RIInstr(nilf));
      }
      break;
    case kS390_And64:
      if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
        ASSEMBLE_BIN_OP(RRRInstr(ngrk), RM64Instr(ng), nullInstr);
      } else {
        ASSEMBLE_BIN_OP(RRInstr(ngr), RM64Instr(ng), nullInstr);
      }
      break;
    case kS390_Or32:
      // zero-ext
      if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
        ASSEMBLE_BIN32_OP(RRRInstr(ork), RM32Instr(Or), RIInstr(oilf));
      } else {
        ASSEMBLE_BIN32_OP(RRInstr(or_z), RM32Instr(Or), RIInstr(oilf));
      }
      break;
    case kS390_Or64:
      if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
        ASSEMBLE_BIN_OP(RRRInstr(ogrk), RM64Instr(og), nullInstr);
      } else {
        ASSEMBLE_BIN_OP(RRInstr(ogr), RM64Instr(og), nullInstr);
      }
      break;
    case kS390_Xor32:
      // zero-ext
      if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
        ASSEMBLE_BIN32_OP(RRRInstr(xrk), RM32Instr(Xor), RIInstr(xilf));
      } else {
        ASSEMBLE_BIN32_OP(RRInstr(xr), RM32Instr(Xor), RIInstr(xilf));
      }
      break;
    case kS390_Xor64:
      if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
        ASSEMBLE_BIN_OP(RRRInstr(xgrk), RM64Instr(xg), nullInstr);
      } else {
        ASSEMBLE_BIN_OP(RRInstr(xgr), RM64Instr(xg), nullInstr);
      }
      break;
    case kS390_ShiftLeft32:
      // zero-ext
      if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
        ASSEMBLE_BIN32_OP(RRRInstr(ShiftLeftU32), nullInstr,
                          RRIInstr(ShiftLeftU32));
      } else {
        ASSEMBLE_BIN32_OP(RRInstr(sll), nullInstr, RIInstr(sll));
      }
      break;
    case kS390_ShiftLeft64:
      ASSEMBLE_BIN_OP(RRRInstr(sllg), nullInstr, RRIInstr(sllg));
      break;
    case kS390_ShiftRight32:
      // zero-ext
      if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
        ASSEMBLE_BIN32_OP(RRRInstr(srlk), nullInstr, RRIInstr(srlk));
      } else {
        ASSEMBLE_BIN32_OP(RRInstr(srl), nullInstr, RIInstr(srl));
      }
      break;
    case kS390_ShiftRight64:
      ASSEMBLE_BIN_OP(RRRInstr(srlg), nullInstr, RRIInstr(srlg));
      break;
    case kS390_ShiftRightArith32:
      // zero-ext
      if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
        ASSEMBLE_BIN32_OP(RRRInstr(srak), nullInstr, RRIInstr(srak));
      } else {
        ASSEMBLE_BIN32_OP(RRInstr(sra), nullInstr, RIInstr(sra));
      }
      break;
    case kS390_ShiftRightArith64:
      ASSEMBLE_BIN_OP(RRRInstr(srag), nullInstr, RRIInstr(srag));
      break;
    case kS390_RotRight32: {
      // zero-ext
      if (HasRegisterInput(instr, 1)) {
        __ lcgr(kScratchReg, i.InputRegister(1));
        __ rll(i.OutputRegister(), i.InputRegister(0), kScratchReg);
      } else {
        __ rll(i.OutputRegister(), i.InputRegister(0),
               Operand(32 - i.InputInt32(1)));
      }
      CHECK_AND_ZERO_EXT_OUTPUT(2);
      break;
    }
    case kS390_RotRight64:
      if (HasRegisterInput(instr, 1)) {
        __ lcgr(kScratchReg, i.InputRegister(1));
        __ rllg(i.OutputRegister(), i.InputRegister(0), kScratchReg);
      } else {
        DCHECK(HasImmediateInput(instr, 1));
        __ rllg(i.OutputRegister(), i.InputRegister(0),
                Operand(64 - i.InputInt32(1)));
      }
      break;
    // TODO(john.yan): clean up kS390_RotLeftAnd...
    case kS390_RotLeftAndClear64:
      if (CpuFeatures::IsSupported(GENERAL_INSTR_EXT)) {
        int shiftAmount = i.InputInt32(1);
        int endBit = 63 - shiftAmount;
        int startBit = 63 - i.InputInt32(2);
        __ RotateInsertSelectBits(i.OutputRegister(), i.InputRegister(0),
                                  Operand(startBit), Operand(endBit),
                                  Operand(shiftAmount), true);
      } else {
        int shiftAmount = i.InputInt32(1);
        int clearBit = 63 - i.InputInt32(2);
        __ rllg(i.OutputRegister(), i.InputRegister(0), Operand(shiftAmount));
        __ sllg(i.OutputRegister(), i.OutputRegister(), Operand(clearBit));
        __ srlg(i.OutputRegister(), i.OutputRegister(),
                Operand(clearBit + shiftAmount));
        __ sllg(i.OutputRegister(), i.OutputRegister(), Operand(shiftAmount));
      }
      break;
    case kS390_RotLeftAndClearLeft64:
      if (CpuFeatures::IsSupported(GENERAL_INSTR_EXT)) {
        int shiftAmount = i.InputInt32(1);
        int endBit = 63;
        int startBit = 63 - i.InputInt32(2);
        __ RotateInsertSelectBits(i.OutputRegister(), i.InputRegister(0),
                                  Operand(startBit), Operand(endBit),
                                  Operand(shiftAmount), true);
      } else {
        int shiftAmount = i.InputInt32(1);
        int clearBit = 63 - i.InputInt32(2);
        __ rllg(i.OutputRegister(), i.InputRegister(0), Operand(shiftAmount));
        __ sllg(i.OutputRegister(), i.OutputRegister(), Operand(clearBit));
        __ srlg(i.OutputRegister(), i.OutputRegister(), Operand(clearBit));
      }
      break;
    case kS390_RotLeftAndClearRight64:
      if (CpuFeatures::IsSupported(GENERAL_INSTR_EXT)) {
        int shiftAmount = i.InputInt32(1);
        int endBit = 63 - i.InputInt32(2);
        int startBit = 0;
        __ RotateInsertSelectBits(i.OutputRegister(), i.InputRegister(0),
                                  Operand(startBit), Operand(endBit),
                                  Operand(shiftAmount), true);
      } else {
        int shiftAmount = i.InputInt32(1);
        int clearBit = i.InputInt32(2);
        __ rllg(i.OutputRegister(), i.InputRegister(0), Operand(shiftAmount));
        __ srlg(i.OutputRegister(), i.OutputRegister(), Operand(clearBit));
        __ sllg(i.OutputRegister(), i.OutputRegister(), Operand(clearBit));
      }
      break;
    case kS390_Add32: {
      // zero-ext
      if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
        ASSEMBLE_BIN32_OP(RRRInstr(ark), RM32Instr(AddS32), RRIInstr(AddS32));
      } else {
        ASSEMBLE_BIN32_OP(RRInstr(ar), RM32Instr(AddS32), RIInstr(AddS32));
      }
      break;
    }
    case kS390_Add64:
      if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
        ASSEMBLE_BIN_OP(RRRInstr(agrk), RM64Instr(ag), RRIInstr(AddS64));
      } else {
        ASSEMBLE_BIN_OP(RRInstr(agr), RM64Instr(ag), RIInstr(agfi));
      }
      break;
    case kS390_AddFloat:
      ASSEMBLE_BIN_OP(DDInstr(aebr), DMTInstr(AddFloat32), nullInstr);
      break;
    case kS390_AddDouble:
      ASSEMBLE_BIN_OP(DDInstr(adbr), DMTInstr(AddFloat64), nullInstr);
      break;
    case kS390_Sub32:
      // zero-ext
      if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
        ASSEMBLE_BIN32_OP(RRRInstr(srk), RM32Instr(SubS32), RRIInstr(SubS32));
      } else {
        ASSEMBLE_BIN32_OP(RRInstr(sr), RM32Instr(SubS32), RIInstr(SubS32));
      }
      break;
    case kS390_Sub64:
      if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
        ASSEMBLE_BIN_OP(RRRInstr(sgrk), RM64Instr(sg), RRIInstr(SubS64));
      } else {
        ASSEMBLE_BIN_OP(RRInstr(sgr), RM64Instr(sg), RIInstr(SubS64));
      }
      break;
    case kS390_SubFloat:
      ASSEMBLE_BIN_OP(DDInstr(sebr), DMTInstr(SubFloat32), nullInstr);
      break;
    case kS390_SubDouble:
      ASSEMBLE_BIN_OP(DDInstr(sdbr), DMTInstr(SubFloat64), nullInstr);
      break;
    case kS390_Mul32:
      // zero-ext
      if (CpuFeatures::IsSupported(MISC_INSTR_EXT2)) {
        ASSEMBLE_BIN32_OP(RRRInstr(msrkc), RM32Instr(msc), RIInstr(MulS32));
      } else {
        ASSEMBLE_BIN32_OP(RRInstr(MulS32), RM32Instr(MulS32), RIInstr(MulS32));
      }
      break;
    case kS390_Mul32WithOverflow:
      // zero-ext
      ASSEMBLE_BIN32_OP(RRRInstr(Mul32WithOverflowIfCCUnequal),
                        RRM32Instr(Mul32WithOverflowIfCCUnequal),
                        RRIInstr(Mul32WithOverflowIfCCUnequal));
      break;
    case kS390_Mul64:
      ASSEMBLE_BIN_OP(RRInstr(MulS64), RM64Instr(MulS64), RIInstr(MulS64));
      break;
    case kS390_Mul64WithOverflow: {
      Register dst = i.OutputRegister(), src1 = i.InputRegister(0),
               src2 = i.InputRegister(1);
      CHECK(!AreAliased(dst, src1, src2));
      if (CpuFeatures::IsSupported(MISC_INSTR_EXT2)) {
        __ msgrkc(dst, src1, src2);
      } else {
        // Mul high.
        __ MulHighS64(r1, src1, src2);
        // Mul low.
        __ mov(dst, src1);
        __ MulS64(dst, src2);
        // Test whether {high} is a sign-extension of {result}.
        __ ShiftRightS64(r0, dst, Operand(63));
        __ CmpU64(r1, r0);
      }
      break;
    }
    case kS390_MulHigh32:
      // zero-ext
      ASSEMBLE_BIN_OP(RRRInstr(MulHighS32), RRM32Instr(MulHighS32),
                      RRIInstr(MulHighS32));
      break;
    case kS390_MulHighU32:
      // zero-ext
      ASSEMBLE_BIN_OP(RRRInstr(MulHighU32), RRM32Instr(MulHighU32),
                      RRIInstr(MulHighU32));
      break;
    case kS390_MulHighU64:
      ASSEMBLE_BIN_OP(RRRInstr(MulHighU64), nullInstr, nullInstr);
      break;
    case kS390_MulHighS64:
      ASSEMBLE_BIN_OP(RRRInstr(MulHighS64), nullInstr, nullInstr);
      break;
    case kS390_MulFloat:
      ASSEMBLE_BIN_OP(DDInstr(meebr), DMTInstr(MulFloat32), nullInstr);
      break;
    case kS390_MulDouble:
      ASSEMBLE_BIN_OP(DDInstr(mdbr), DMTInstr(MulFloat64), nullInstr);
      break;
    case kS390_Div64:
      ASSEMBLE_BIN_OP(RRRInstr(DivS64), RRM64Instr(DivS64), nullInstr);
      break;
    case kS390_Div32: {
      // zero-ext
      ASSEMBLE_BIN_OP(RRRInstr(DivS32), RRM32Instr(DivS32), nullInstr);
      break;
    }
    case kS390_DivU64:
      ASSEMBLE_BIN_OP(RRRInstr(DivU64), RRM64Instr(DivU64), nullInstr);
      break;
    case kS390_DivU32: {
      // zero-ext
      ASSEMBLE_BIN_OP(RRRInstr(DivU32), RRM32Instr(DivU32), nullInstr);
      break;
    }
    case kS390_DivFloat:
      ASSEMBLE_BIN_OP(DDInstr(debr), DMTInstr(DivFloat32), nullInstr);
      break;
    case kS390_DivDouble:
      ASSEMBLE_BIN_OP(DDInstr(ddbr), DMTInstr(DivFloat64), nullInstr);
      break;
    case kS390_Mod32:
      // zero-ext
      ASSEMBLE_BIN_OP(RRRInstr(ModS32), RRM32Instr(ModS32), nullInstr);
      break;
    case kS390_ModU32:
      // zero-ext
      ASSEMBLE_BIN_OP(RRRInstr(ModU32), RRM32Instr(ModU32), nullInstr);
      break;
    case kS390_Mod64:
      ASSEMBLE_BIN_OP(RRRInstr(ModS64), RRM64Instr(ModS64), nullInstr);
      break;
    case kS390_ModU64:
      ASSEMBLE_BIN_OP(RRRInstr(ModU64), RRM64Instr(ModU64), nullInstr);
      break;
    case kS390_AbsFloat:
      __ lpebr(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kS390_SqrtFloat:
      ASSEMBLE_UNARY_OP(D_DInstr(sqebr), nullInstr, nullInstr);
      break;
    case kS390_SqrtDouble:
      ASSEMBLE_UNARY_OP(D_DInstr(sqdbr), nullInstr, nullInstr);
      break;
    case kS390_FloorFloat:
      __ FloorF32(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kS390_CeilFloat:
      __ CeilF32(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kS390_TruncateFloat:
      __ TruncF32(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    //  Double operations
    case kS390_ModDouble:
      ASSEMBLE_FLOAT_MODULO();
      break;
    case kIeee754Float64Acos:
      ASSEMBLE_IEEE754_UNOP(acos);
      break;
    case kIeee754Float64Acosh:
      ASSEMBLE_IEEE754_UNOP(acosh);
      break;
    case kIeee754Float64Asin:
      ASSEMBLE_IEEE754_UNOP(asin);
      break;
    case kIeee754Float64Asinh:
      ASSEMBLE_IEEE754_UNOP(asinh);
      break;
    case kIeee754Float64Atanh:
      ASSEMBLE_IEEE754_UNOP(atanh);
      break;
    case kIeee754Float64Atan:
      ASSEMBLE_IEEE754_UNOP(atan);
      break;
    case kIeee754Float64Atan2:
      ASSEMBLE_IEEE754_BINOP(atan2);
      break;
    case kIeee754Float64Tan:
      ASSEMBLE_IEEE754_UNOP(tan);
      break;
    case kIeee754Float64Tanh:
      ASSEMBLE_IEEE754_UNOP(tanh);
      break;
    case kIeee754Float64Cbrt:
      ASSEMBLE_IEEE754_UNOP(cbrt);
      break;
    case kIeee754Float64Sin:
      ASSEMBLE_IEEE754_UNOP(sin);
      break;
    case kIeee754Float64Sinh:
      ASSEMBLE_IEEE754_UNOP(sinh);
      break;
    case kIeee754Float64Cos:
      ASSEMBLE_IEEE754_UNOP(cos);
      break;
    case kIeee754Float64Cosh:
      ASSEMBLE_IEEE754_UNOP(cosh);
      break;
    case kIeee754Float64Exp:
      ASSEMBLE_IEEE754_UNOP(exp);
      break;
    case kIeee754Float64Expm1:
      ASSEMBLE_IEEE754_UNOP(expm1);
      break;
    case kIeee754Float64Log:
      ASSEMBLE_IEEE754_UNOP(log);
      break;
    case kIeee754Float64Log1p:
      ASSEMBLE_IEEE754_UNOP(log1p);
      break;
    case kIeee754Float64Log2:
      ASSEMBLE_IEEE754_UNOP(log2);
      break;
    case kIeee754Float64Log10:
      ASSEMBLE_IEEE754_UNOP(log10);
      break;
    case kIeee754Float64Pow:
      ASSEMBLE_IEEE754_BINOP(pow);
      break;
    case kS390_Neg32:
      __ lcr(i.OutputRegister(), i.InputRegister(0));
      CHECK_AND_ZERO_EXT_OUTPUT(1);
      break;
    case kS390_Neg64:
      __ lcgr(i.OutputRegister(), i.InputRegister(0));
      break;
    case kS390_MaxFloat:
      __ FloatMax(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                  i.InputDoubleRegister(1));
      break;
    case kS390_MaxDouble:
      __ DoubleMax(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                   i.InputDoubleRegister(1));
      break;
    case kS390_MinFloat:
      __ FloatMin(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                  i.InputDoubleRegister(1));
      break;
    case kS390_FloatNearestInt:
      __ NearestIntF32(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kS390_MinDouble:
      __ DoubleMin(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                   i.InputDoubleRegister(1));
      break;
    case kS390_AbsDouble:
      __ lpdbr(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kS390_FloorDouble:
      __ FloorF64(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kS390_CeilDouble:
      __ CeilF64(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kS390_TruncateDouble:
      __ TruncF64(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kS390_RoundDouble:
      __ fidbra(ROUND_TO_NEAREST_AWAY_FROM_0, i.OutputDoubleRegister(),
                i.InputDoubleRegister(0));
      break;
    case kS390_DoubleNearestInt:
      __ NearestIntF64(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kS390_NegFloat:
      ASSEMBLE_UNARY_OP(D_DInstr(lcebr), nullInstr, nullInstr);
      break;
    case kS390_NegDouble:
      ASSEMBLE_UNARY_OP(D_DInstr(lcdbr), nullInstr, nullInstr);
      break;
    case kS390_Cntlz32: {
      __ CountLeadingZerosU32(i.OutputRegister(), i.InputRegister(0), r0);
      break;
    }
    case kS390_Cntlz64: {
      __ CountLeadingZerosU64(i.OutputRegister(), i.InputRegister(0), r0);
      break;
    }
    case kS390_Popcnt32:
      __ Popcnt32(i.OutputRegister(), i.InputRegister(0));
      break;
    case kS390_Popcnt64:
      __ Popcnt64(i.OutputRegister(), i.InputRegister(0));
      break;
    case kS390_Cmp32:
      ASSEMBLE_COMPARE32(CmpS32, CmpU32);
      break;
    case kS390_Cmp64:
      ASSEMBLE_COMPARE(CmpS64, CmpU64);
      break;
    case kS390_CmpFloat:
      ASSEMBLE_FLOAT_COMPARE(cebr, ceb, ley);
      // __ cebr(i.InputDoubleRegister(0), i.InputDoubleRegister(1));
      break;
    case kS390_CmpDouble:
      ASSEMBLE_FLOAT_COMPARE(cdbr, cdb, ldy);
      // __ cdbr(i.InputDoubleRegister(0), i.InputDoubleRegister(1));
      break;
    case kS390_Tst32:
      if (HasRegisterInput(instr, 1)) {
        __ And(r0, i.InputRegister(0), i.InputRegister(1));
      } else {
        // detect tmlh/tmhl/tmhh case
        Operand opnd = i.InputImmediate(1);
        if (is_uint16(opnd.immediate())) {
          __ tmll(i.InputRegister(0), opnd);
        } else {
          __ lr(r0, i.InputRegister(0));
          __ nilf(r0, opnd);
        }
      }
      break;
    case kS390_Tst64:
      if (HasRegisterInput(instr, 1)) {
        __ AndP(r0, i.InputRegister(0), i.InputRegister(1));
      } else {
        Operand opnd = i.InputImmediate(1);
        if (is_uint16(opnd.immediate())) {
          __ tmll(i.InputRegister(0), opnd);
        } else {
          __ AndP(r0, i.InputRegister(0), opnd);
        }
      }
      break;
    case kS390_Float64SilenceNaN: {
      DoubleRegister value = i.InputDoubleRegister(0);
      DoubleRegister result = i.OutputDoubleRegister();
      __ CanonicalizeNaN(result, value);
      break;
    }
    case kS390_Push: {
      int stack_decrement = i.InputInt32(0);
      int slots = stack_decrement / kSystemPointerSize;
      LocationOperand* op = LocationOperand::cast(instr->InputAt(1));
      MachineRepresentation rep = op->representation();
      int pushed_slots = ElementSizeInPointers(rep);
      // Slot-sized arguments are never padded but there may be a gap if
      // the slot allocator reclaimed other padding slots. Adjust the stack
      // here to skip any gap.
      __ AllocateStackSpace((slots - pushed_slots) * kSystemPointerSize);
      switch (rep) {
        case MachineRepresentation::kFloat32:
          __ lay(sp, MemOperand(sp, -kSystemPointerSize));
          __ StoreF32(i.InputDoubleRegister(1), MemOperand(sp));
          break;
        case MachineRepresentation::kFloat64:
          __ lay(sp, MemOperand(sp, -kDoubleSize));
          __ StoreF64(i.InputDoubleRegister(1), MemOperand(sp));
          break;
        case MachineRepresentation::kSimd128:
          __ lay(sp, MemOperand(sp, -kSimd128Size));
          __ StoreV128(i.InputDoubleRegister(1), MemOperand(sp), kScratchReg);
          break;
        default:
          __ Push(i.InputRegister(1));
          break;
      }
      frame_access_state()->IncreaseSPDelta(slots);
      break;
    }
    case kS390_PushFrame: {
      int num_slots = i.InputInt32(1);
      __ lay(sp, MemOperand(sp, -num_slots * kSystemPointerSize));
      if (instr->InputAt(0)->IsFPRegister()) {
        LocationOperand* op = LocationOperand::cast(instr->InputAt(0));
        if (op->representation() == MachineRepresentation::kFloat64) {
          __ StoreF64(i.InputDoubleRegister(0), MemOperand(sp));
        } else {
          DCHECK_EQ(MachineRepresentation::kFloat32, op->representation());
          __ StoreF32(i.InputDoubleRegister(0), MemOperand(sp));
        }
      } else {
        __ StoreU64(i.InputRegister(0), MemOperand(sp));
      }
      break;
    }
    case kS390_StoreToStackSlot: {
      int slot = i.InputInt32(1);
      if (instr->InputAt(0)->IsFPRegister()) {
        LocationOperand* op = LocationOperand::cast(instr->InputAt(0));
        if (op->representation() == MachineRepresentation::kFloat64) {
          __ StoreF64(i.InputDoubleRegister(0),
                      MemOperand(sp, slot * kSystemPointerSize));
        } else if (op->representation() == MachineRepresentation::kFloat32) {
          __ StoreF32(i.InputDoubleRegister(0),
                      MemOperand(sp, slot * kSystemPointerSize));
        } else {
          DCHECK_EQ(MachineRepresentation::kSimd128, op->representation());
          __ StoreV128(i.InputDoubleRegister(0),
                       MemOperand(sp, slot * kSystemPointerSize), kScratchReg);
        }
      } else {
        __ StoreU64(i.InputRegister(0),
                    MemOperand(sp, slot * kSystemPointerSize));
      }
      break;
    }
    case kS390_SignExtendWord8ToInt32:
      __ lbr(i.OutputRegister(), i.InputRegister(0));
      CHECK_AND_ZERO_EXT_OUTPUT(1);
      break;
    case kS390_SignExtendWord16ToInt32:
      __ lhr(i.OutputRegister(), i.InputRegister(0));
      CHECK_AND_ZERO_EXT_OUTPUT(1);
      break;
    case kS390_SignExtendWord8ToInt64:
      __ lgbr(i.OutputRegister(), i.InputRegister(0));
      break;
    case kS390_SignExtendWord16ToInt64:
      __ lghr(i.OutputRegister(), i.InputRegister(0));
      break;
    case kS390_SignExtendWord32ToInt64:
      __ lgfr(i.OutputRegister(), i.InputRegister(0));
      break;
    case kS390_Uint32ToUint64:
      // Zero extend
      __ llgfr(i.OutputRegister(), i.InputRegister(0));
      break;
    case kS390_Int64ToInt32:
      // sign extend
      __ lgfr(i.OutputRegister(), i.InputRegister(0));
      break;
    // Convert Fixed to Floating Point
    case kS390_Int64ToFloat32:
      __ ConvertInt64ToFloat(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    case kS390_Int64ToDouble:
      __ ConvertInt64ToDouble(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    case kS390_Uint64ToFloat32:
      __ ConvertUnsignedInt64ToFloat(i.OutputDoubleRegister(),
                                     i.InputRegister(0));
      break;
    case kS390_Uint64ToDouble:
      __ ConvertUnsignedInt64ToDouble(i.OutputDoubleRegister(),
                                      i.InputRegister(0));
      break;
    case kS390_Int32ToFloat32:
      __ ConvertIntToFloat(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    case kS390_Int32ToDouble:
      __ ConvertIntToDouble(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    case kS390_Uint32ToFloat32:
      __ ConvertUnsignedIntToFloat(i.OutputDoubleRegister(),
                                   i.InputRegister(0));
      break;
    case kS390_Uint32ToDouble:
      __ ConvertUnsignedIntToDouble(i.OutputDoubleRegister(),
                                    i.InputRegister(0));
      break;
    case kS390_DoubleToInt32: {
      Label done;
      if (i.OutputCount() > 1) {
        __ mov(i.OutputRegister(1), Operand(1));
      }
      __ ConvertDoubleToInt32(i.OutputRegister(0), i.InputDoubleRegister(0),
                              kRoundToNearest);
      __ b(Condition(0xE), &done, Label::kNear);  // normal case
      if (i.OutputCount() > 1) {
        __ mov(i.OutputRegister(1), Operand::Zero());
      } else {
        __ mov(i.OutputRegister(0), Operand::Zero());
      }
      __ bind(&done);
      break;
    }
    case kS390_DoubleToUint32: {
      Label done;
      if (i.OutputCount() > 1) {
        __ mov(i.OutputRegister(1), Operand(1));
      }
      __ ConvertDoubleToUnsignedInt32(i.OutputRegister(0),
                                      i.InputDoubleRegister(0));
      __ b(Condition(0xE), &done, Label::kNear);  // normal case
      if (i.OutputCount() > 1) {
        __ mov(i.OutputRegister(1), Operand::Zero());
      } else {
        __ mov(i.OutputRegister(0), Operand::Zero());
      }
      __ bind(&done);
      break;
    }
    case kS390_DoubleToInt64: {
      Label done;
      if (i.OutputCount() > 1) {
        __ mov(i.OutputRegister(1), Operand(1));
      }
      __ ConvertDoubleToInt64(i.OutputRegister(0), i.InputDoubleRegister(0));
      __ b(Condition(0xE), &done, Label::kNear);  // normal case
      if (i.OutputCount() > 1) {
        __ mov(i.OutputRegister(1), Operand::Zero());
      } else {
        __ mov(i.OutputRegister(0), Operand::Zero());
      }
      __ bind(&done);
      break;
    }
    case kS390_DoubleToUint64: {
      Label done;
      if (i.OutputCount() > 1) {
        __ mov(i.OutputRegister(1), Operand(1));
      }
      __ ConvertDoubleToUnsignedInt64(i.OutputRegister(0),
                                      i.InputDoubleRegister(0));
      __ b(Condition(0xE), &done, Label::kNear);  // normal case
      if (i.OutputCount() > 1) {
        __ mov(i.OutputRegister(1), Operand::Zero());
      } else {
        __ mov(i.OutputRegister(0), Operand::Zero());
      }
      __ bind(&done);
      break;
    }
    case kS390_Float32ToInt32: {
      Label done;
      __ ConvertFloat32ToInt32(i.OutputRegister(0), i.InputDoubleRegister(0),
                               kRoundToZero);
      bool set_overflow_to_min_i32 = MiscField::decode(instr->opcode());
      if (set_overflow_to_min_i32) {
        // Avoid INT32_MAX as an overflow indicator and use INT32_MIN instead,
        // because INT32_MIN allows easier out-of-bounds detection.
        __ b(Condition(0xE), &done, Label::kNear);  // normal case
        __ llilh(i.OutputRegister(0), Operand(0x8000));
      }
      __ bind(&done);
      break;
    }
    case kS390_Float32ToUint32: {
      Label done;
      __ ConvertFloat32ToUnsignedInt32(i.OutputRegister(0),
                                       i.InputDoubleRegister(0));
      bool set_overflow_to_min_u32 = MiscField::decode(instr->opcode());
      if (set_overflow_to_min_u32) {
        // Avoid UINT32_MAX as an overflow indicator and use 0 instead,
        // because 0 allows easier out-of-bounds detection.
        __ b(Condition(0xE), &done, Label::kNear);  // normal case
        __ mov(i.OutputRegister(0), Operand::Zero());
      }
      __ bind(&done);
      break;
    }
    case kS390_Float32ToUint64: {
      Label done;
      if (i.OutputCount() > 1) {
        __ mov(i.OutputRegister(1), Operand(1));
      }
      __ ConvertFloat32ToUnsignedInt64(i.OutputRegister(0),
                                       i.InputDoubleRegister(0));
      __ b(Condition(0xE), &done, Label::kNear);  // normal case
      if (i.OutputCount() > 1) {
        __ mov(i.OutputRegister(1), Operand::Zero());
      } else {
        __ mov(i.OutputRegister(0), Operand::Zero());
      }
      __ bind(&done);
      break;
    }
    case kS390_Float32ToInt64: {
      Label done;
      if (i.OutputCount() > 1) {
        __ mov(i.OutputRegister(1), Operand(1));
      }
      __ ConvertFloat32ToInt64(i.OutputRegister(0), i.InputDoubleRegister(0));
      __ b(Condition(0xE), &done, Label::kNear);  // normal case
      if (i.OutputCount() > 1) {
        __ mov(i.OutputRegister(1), Operand::Zero());
      } else {
        __ mov(i.OutputRegister(0), Operand::Zero());
      }
      __ bind(&done);
      break;
    }
    case kS390_DoubleToFloat32:
      ASSEMBLE_UNARY_OP(D_DInstr(ledbr), nullInstr, nullInstr);
      break;
    case kS390_Float32ToDouble:
      ASSEMBLE_UNARY_OP(D_DInstr(ldebr), D_MInstr(LoadF32AsF64), nullInstr);
      break;
    case kS390_DoubleExtractLowWord32:
      __ lgdr(i.OutputRegister(), i.InputDoubleRegister(0));
      __ llgfr(i.OutputRegister(), i.OutputRegister());
      break;
    case kS390_DoubleExtractHighWord32:
      __ lgdr(i.OutputRegister(), i.InputDoubleRegister(0));
      __ srlg(i.OutputRegister(), i.OutputRegister(), Operand(32));
      break;
    case kS390_DoubleFromWord32Pair:
      __ LoadU32(kScratchReg, i.InputRegister(1));
      __ ShiftLeftU64(i.TempRegister(0), i.InputRegister(0), Operand(32));
      __ OrP(i.TempRegister(0), i.TempRegister(0), kScratchReg);
      __ MovInt64ToDouble(i.OutputDoubleRegister(), i.TempRegister(0));
      break;
    case kS390_DoubleInsertLowWord32:
      __ lgdr(kScratchReg, i.InputDoubleRegister(0));
      __ lr(kScratchReg, i.InputRegister(1));
      __ ldgr(i.OutputDoubleRegister(), kScratchReg);
      break;
    case kS390_DoubleInsertHighWord32:
      __ sllg(kScratchReg, i.InputRegister(1), Operand(32));
      __ lgdr(r0, i.InputDoubleRegister(0));
      __ lr(kScratchReg, r0);
      __ ldgr(i.OutputDoubleRegister(), kScratchReg);
      break;
    case kS390_DoubleConstruct:
      __ sllg(kScratchReg, i.InputRegister(0), Operand(32));
      __ lr(kScratchReg, i.InputRegister(1));

      // Bitwise convert from GPR to FPR
      __ ldgr(i.OutputDoubleRegister(), kScratchReg);
      break;
    case kS390_LoadWordS8:
      ASSEMBLE_LOAD_INTEGER(LoadS8);
      break;
    case kS390_BitcastFloat32ToInt32:
      ASSEMBLE_UNARY_OP(R_DInstr(MovFloatToInt), R_MInstr(LoadU32), nullInstr);
      break;
    case kS390_BitcastInt32ToFloat32:
      __ MovIntToFloat(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    case kS390_BitcastDoubleToInt64:
      __ MovDoubleToInt64(i.OutputRegister(), i.InputDoubleRegister(0));
      break;
    case kS390_BitcastInt64ToDouble:
      __ MovInt64ToDouble(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    case kS390_LoadWordU8:
      ASSEMBLE_LOAD_INTEGER(LoadU8);
      break;
    case kS390_LoadWordU16:
      ASSEMBLE_LOAD_INTEGER(LoadU16);
      break;
    case kS390_LoadWordS16:
      ASSEMBLE_LOAD_INTEGER(LoadS16);
      break;
    case kS390_LoadWordU32:
      ASSEMBLE_LOAD_INTEGER(LoadU32);
      break;
    case kS390_LoadWordS32:
      ASSEMBLE_LOAD_INTEGER(LoadS32);
      break;
    case kS390_LoadReverse16:
      ASSEMBLE_LOAD_INTEGER(lrvh);
      break;
    case kS390_LoadReverse32:
      ASSEMBLE_LOAD_INTEGER(lrv);
      break;
    case kS390_LoadReverse64:
      ASSEMBLE_LOAD_INTEGER(lrvg);
      break;
    case kS390_LoadReverse16RR:
      __ lrvr(i.OutputRegister(), i.InputRegister(0));
      __ rll(i.OutputRegister(), i.OutputRegister(), Operand(16));
      break;
    case kS390_LoadReverse32RR:
      __ lrvr(i.OutputRegister(), i.InputRegister(0));
      break;
    case kS390_LoadReverse64RR:
      __ lrvgr(i.OutputRegister(), i.InputRegister(0));
      break;
    case kS390_LoadReverseSimd128RR:
      __ vlgv(r0, i.InputSimd128Register(0), MemOperand(r0, 0), Condition(3));
      __ vlgv(r1, i.InputSimd128Register(0), MemOperand(r0, 1), Condition(3));
      __ lrvgr(r0, r0);
      __ lrvgr
```