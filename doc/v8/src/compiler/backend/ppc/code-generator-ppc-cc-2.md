Response:
My thinking process to arrive at the summary of the provided code snippet goes like this:

1. **Identify the Core Functionality:** The code is a `switch` statement handling different `case` values starting with `kIeee754Float64Log10` and ending mid-sentence within a `kPPC_##name` block. The `case` values strongly suggest these are instructions or operations within a specific architecture (PPC - PowerPC). The surrounding context (given in the prompt as part of `code-generator-ppc.cc`) confirms this. The code is generating machine code for PPC.

2. **Analyze Individual Cases:** I'd go through each `case` block and decipher what it does. I look for patterns and helper macros/functions.

    * **`ASSEMBLE_IEEE754_UNOP/BINOP`:** These clearly deal with IEEE 754 floating-point operations (log10, pow).
    * **`kPPC_Neg`:**  A simple negation operation. The `__ neg()` function hints at assembly code generation.
    * **`kPPC_MaxDouble/MinDouble`:** Finding the maximum/minimum of two doubles. The `__ MaxF64()` and `__ MinF64()` functions again point to assembly generation.
    * **`ASSEMBLE_FLOAT_UNOP_RC`:**  Another pattern for floating-point unary operations (abs, sqrt, floor, ceil, truncate, round, negate). The `RC` likely relates to setting condition codes in the processor status register.
    * **`kPPC_Cntlz32/Cntlz64`:** Counting leading zeros (32-bit and 64-bit).
    * **`kPPC_Popcnt32/Popcnt64`:** Counting set bits (population count).
    * **`ASSEMBLE_COMPARE/ASSEMBLE_FLOAT_COMPARE`:** Comparing integers and floating-point numbers.
    * **`kPPC_Tst32/Tst64`:**  Bitwise AND for testing bits.
    * **`kPPC_Float64SilenceNaN`:** Handling NaN (Not-a-Number) values.
    * **`kPPC_Push/PushFrame/StoreToStackSlot`:** Stack manipulation operations.
    * **`kPPC_ExtendSignWord...`:** Sign extension operations.
    * **`kPPC_Uint32ToUint64/Int64ToInt32`:** Integer type conversions.
    * **`kPPC_Int64ToFloat32/Double`, `kPPC_Uint64ToFloat32/Double`, `kPPC_Int32ToFloat32/Double`, `kPPC_Uint32ToFloat32/Double`:**  Integer-to-floating-point conversions.
    * **`kPPC_Float32ToInt32/Uint32`, `kPPC_DoubleToInt32/Uint32/Int64/Uint64`:** Floating-point-to-integer conversions, including checks for overflow.
    * **`kPPC_DoubleToFloat32/Float32ToDouble`:** Floating-point type conversions.
    * **`kPPC_DoubleExtractLow/HighWord32`, `kPPC_DoubleFromWord32Pair`, `kPPC_DoubleInsertLow/HighWord32`, `kPPC_DoubleConstruct`:** Operations to manipulate the individual 32-bit parts of a 64-bit double.
    * **`kPPC_BitcastFloat32ToInt32/Int32ToFloat32/DoubleToInt64/Int64ToDouble`:** Reinterpreting the bit pattern of a value as another type.
    * **`ASSEMBLE_LOAD_INTEGER/FLOAT`, `ASSEMBLE_STORE_INTEGER/FLOAT`:** Loading and storing data from/to memory.
    * **`kPPC_LoadSimd128/StoreSimd128`:** Loading and storing SIMD (Single Instruction, Multiple Data) registers.
    * **`kPPC_LoadReverseSimd128RR`:** Reversing the byte order within a SIMD register.
    * **`kAtomicExchange...`, `kAtomicCompareExchange...`, `kPPC_Atomic...`:** Atomic operations for thread safety.
    * **`kPPC_ByteRev32/64`, `kPPC_LoadByteRev32/64`, `kPPC_StoreByteRev32/64`:** Byte reversal operations.
    * **`SIMD_BINOP_LIST`, `SIMD_UNOP_LIST`, etc.:**  Large blocks of SIMD instructions. The macros like `EMIT_SIMD_BINOP` suggest a systematic way of handling these.

3. **Identify Common Themes:**  As I go through the cases, I notice recurring themes:

    * **Arithmetic Operations:** Basic math like addition, subtraction, multiplication, division, negation.
    * **Floating-Point Operations:**  Operations defined by the IEEE 754 standard (log, pow, sqrt, etc.).
    * **Bitwise Operations:** AND, OR, XOR, shifts, counting bits.
    * **Comparisons:** Integer and floating-point comparisons.
    * **Type Conversions:** Converting between integers and floating-point numbers of different sizes.
    * **Memory Access:** Loading and storing data.
    * **Stack Manipulation:** Pushing and popping values.
    * **Atomic Operations:** Ensuring thread safety.
    * **SIMD Operations:**  Vectorized operations for improved performance on parallelizable tasks.

4. **Infer Overall Function:** Based on the individual operations and the themes, I can conclude that this code is responsible for *generating machine code instructions* for the PowerPC architecture. It takes higher-level instructions (likely from V8's intermediate representation) and translates them into the specific PowerPC assembly instructions needed to perform those operations.

5. **Address Specific Questions:**

    * **`.tq` Extension:** The prompt states that if the file ended with `.tq`, it would be a Torque source file. Since it ends with `.cc`, it's a C++ source file.
    * **Relationship to JavaScript:**  Many of the operations directly correspond to JavaScript functionalities. For instance, `kIeee754Float64Log10` implements `Math.log10()`, `kPPC_MaxDouble` implements `Math.max()`, and type conversions are crucial for how JavaScript handles numbers.
    * **JavaScript Examples:**  I would pick a few representative operations and show their JavaScript equivalents.
    * **Code Logic Inference:** I'd choose a simple case (like `kPPC_Neg`) and show how a given input register value would result in a specific output register value after the operation.
    * **Common Programming Errors:** I'd think about common mistakes related to the types of operations handled, like integer overflow during conversions or incorrect usage of bitwise operators.

6. **Structure the Summary:**  Finally, I'd organize my findings into a clear and concise summary, addressing each point in the prompt. I would start with the main function, then elaborate on specific aspects like the relationship with JavaScript, provide examples, and address potential programming errors. Since this is "Part 3," I'd focus on summarizing *just* the functionality within the provided snippet.

This systematic approach allows me to understand the purpose of the code, connect it to broader concepts (like JavaScript execution and CPU architecture), and answer the specific questions asked in the prompt.
这是目录为`v8/src/compiler/backend/ppc/code-generator-ppc.cc`的V8源代码的第三部分，主要功能是**为PowerPC (PPC) 架构生成特定类型的机器码指令**。

**功能归纳:**

这部分代码是 `CodeGenerator` 类中处理特定中间表示 (IR) 指令的一部分，负责将这些指令转换为实际的PowerPC汇编代码。  它涵盖了以下主要功能：

1. **数学运算:**  包括浮点数的对数运算 (log10)、幂运算 (pow)，以及整数的取负运算。
2. **浮点数比较与最值:**  实现浮点数的最大值和最小值运算。
3. **浮点数绝对值、开方、取整:**  提供了浮点数的绝对值、平方根以及各种取整操作 (floor, ceil, truncate, round)。
4. **浮点数取负:**  对浮点数进行取负操作。
5. **位操作:**  实现计算前导零 (cntlz) 和人口计数 (popcnt) 的操作，支持32位和64位整数。
6. **比较操作:**  支持32位和64位整数以及双精度浮点数的比较操作。
7. **位测试:**  通过与操作和符号扩展来测试指定位。
8. **NaN处理:**  提供将浮点数静音化的操作。
9. **栈操作:**  实现了将数据压入栈 (`Push`) 和为栈帧分配空间 (`PushFrame`) 的操作，并提供了将数据存储到栈槽 (`StoreToStackSlot`) 的功能。
10. **符号扩展:**  提供了将8位、16位和32位有符号数扩展到64位的功能。
11. **类型转换:**  支持各种整数类型之间的转换 (如 `uint32` 到 `uint64`)，以及整数与浮点数之间的转换 (包括有符号和无符号的32位/64位整数与单/双精度浮点数之间的转换)。 此外，还包括浮点数到整数的转换，并考虑了溢出情况的处理。
12. **浮点数精度转换:**  支持双精度浮点数到单精度浮点数的转换，以及单精度到双精度的转换。
13. **双精度浮点数分解与构造:**  提供了提取双精度浮点数的低位和高位32位部分，以及从两个32位数构造双精度浮点数的功能。
14. **位运算转换:**  提供了浮点数和整数之间的位模式转换 (bitcast)。
15. **内存加载:**  实现了加载各种大小 (8位、16位、32位、64位) 的整数 (有符号和无符号) 以及单精度和双精度浮点数的操作。  也包括加载SIMD (Single Instruction, Multiple Data) 寄存器的操作。
16. **内存存储:**  实现了存储各种大小的整数和浮点数到内存的操作，并支持存储SIMD寄存器。
17. **原子操作:**  提供了多种原子操作，如原子交换 (exchange) 和原子比较交换 (compare exchange)，以及原子加、减、与、或、异或等二元运算，支持不同大小的整数类型。
18. **字节序反转:**  实现了32位和64位整数的字节序反转操作，以及加载和存储字节反转后的数据。
19. **SIMD支持:**  提供了大量的SIMD指令支持，包括各种算术运算、比较运算、位运算、移位操作、类型转换、逻辑运算、加载/存储等，涵盖了 `F64x2`, `F32x4`, `I64x2`, `I32x4`, `I16x8`, `I8x16`, `S128` 等多种SIMD类型。

**如果 `v8/src/compiler/backend/ppc/code-generator-ppc.cc` 以 `.tq` 结尾:**

正如您所说，如果文件以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言，用于生成高效的 C++ 代码。当前的 `.cc` 扩展名表明它是直接的 C++ 代码。

**与 JavaScript 功能的关系及举例:**

这段代码中实现的许多功能都直接对应于 JavaScript 的内置对象和操作符。

* **`Math.log10()` (kIeee754Float64Log10):**
  ```javascript
  let x = 100;
  let result = Math.log10(x); // result 将是 2
  ```
* **`Math.pow()` (kIeee754Float64Pow):**
  ```javascript
  let base = 2;
  let exponent = 3;
  let result = Math.pow(base, exponent); // result 将是 8
  ```
* **一元负号运算符 (`-`) (kPPC_NegDouble):**
  ```javascript
  let num = 5.5;
  let negativeNum = -num; // negativeNum 将是 -5.5
  ```
* **`Math.max()` (kPPC_MaxDouble):**
  ```javascript
  let a = 10;
  let b = 20;
  let maxVal = Math.max(a, b); // maxVal 将是 20
  ```
* **类型转换 (例如 kPPC_Int32ToDouble):**
  ```javascript
  let integer = 42;
  let doubleVal = integer; // JavaScript 会自动进行类型转换
  console.log(typeof doubleVal); // 输出 "number"
  ```
* **位运算符 (例如，虽然此处没有直接的 JavaScript 位运算符对应，但 `kPPC_Cntlz32` 和 `kPPC_Popcnt32` 可以用于实现一些高级的位操作):**
  ```javascript
  // JavaScript 的位运算符，但底层可能用到类似的指令
  let num = 8; // 二进制 1000
  let leadingZeros = Math.clz32(num); // 计算前导零，尽管 JavaScript 没有直接提供完全相同的指令
  ```
* **SIMD 操作 (例如 kPPC_F64x2Add):**  虽然 JavaScript 中直接使用 SIMD 的语法可能不同（例如使用 `Float64x2` 类型），但底层的 V8 实现会利用这些 SIMD 指令来加速向量运算。

**代码逻辑推理 (假设输入与输出):**

以 `case kPPC_Neg:` 为例：

**假设输入:**
* `i.OutputRegister()` 指向寄存器 `r5`
* `i.InputRegister(0)` 指向寄存器 `r3`
* 寄存器 `r3` 的值为 `10`

**输出:**
执行 `__ neg(r5, r3, LeaveOE, i.OutputRCBit());` 后，寄存器 `r5` 的值将是 `-10`。 `LeaveOE` 和 `i.OutputRCBit()` 控制是否影响溢出标志位和条件码寄存器，这里假设不影响。

以 `case kPPC_MaxDouble:` 为例：

**假设输入:**
* `i.OutputDoubleRegister()` 指向浮点寄存器 `f1`
* `i.InputDoubleRegister(0)` 指向浮点寄存器 `f2`，值为 `3.14`
* `i.InputDoubleRegister(1)` 指向浮点寄存器 `f3`，值为 `2.71`
* `kScratchDoubleReg` 是一个临时浮点寄存器

**输出:**
执行 `__ MaxF64(f1, f2, f3, kScratchDoubleReg);` 后，浮点寄存器 `f1` 的值将是 `3.14` (因为 3.14 > 2.71)。

**涉及用户常见的编程错误及举例:**

* **类型转换错误:**  在 JavaScript 中，类型转换有时是隐式的，但如果不注意，可能会导致意外的结果。例如，将一个超出整数范围的浮点数转换为整数可能导致截断或得到意外的值。
  ```javascript
  let largeFloat = 999999999999999999999.9;
  let integerValue = parseInt(largeFloat); // 可能得到不期望的结果，因为超出了整数范围
  ```
* **位运算理解错误:**  位运算符操作的是数字的二进制表示，初学者容易混淆其作用。例如，左右移位操作可能导致符号位的变化，与预期不符。
  ```javascript
  let num = -1; // 二进制表示是所有位都为 1
  let shifted = num >> 1; // 右移一位，符号位不变，结果仍然是 -1
  ```
* **浮点数精度问题:** 浮点数在计算机中以近似值存储，进行比较时可能会出现意想不到的结果。
  ```javascript
  let a = 0.1 + 0.2;
  let b = 0.3;
  console.log(a === b); // 输出 false，因为浮点数精度问题，a 并不完全等于 0.3
  ```
* **原子操作使用不当 (虽然 JavaScript 开发者通常不直接接触这些底层操作，但在多线程/Worker 环境下可能会遇到相关概念):**  在多线程环境下，如果不正确地使用原子操作来保护共享资源，可能导致数据竞争和程序错误。

总而言之，这部分 `code-generator-ppc.cc` 代码是 V8 引擎将 JavaScript 代码转换为高效的 PowerPC 机器码的关键组成部分，它实现了各种基本的和高级的运算，使得 JavaScript 能够在 PowerPC 架构上高效运行。

### 提示词
```
这是目录为v8/src/compiler/backend/ppc/code-generator-ppc.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/ppc/code-generator-ppc.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
case kIeee754Float64Log10:
      ASSEMBLE_IEEE754_UNOP(log10);
      break;
    case kIeee754Float64Pow:
      ASSEMBLE_IEEE754_BINOP(pow);
      break;
    case kPPC_Neg:
      __ neg(i.OutputRegister(), i.InputRegister(0), LeaveOE, i.OutputRCBit());
      break;
    case kPPC_MaxDouble:
      __ MaxF64(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                i.InputDoubleRegister(1), kScratchDoubleReg);
      break;
    case kPPC_MinDouble:
      __ MinF64(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                i.InputDoubleRegister(1), kScratchDoubleReg);
      break;
    case kPPC_AbsDouble:
      ASSEMBLE_FLOAT_UNOP_RC(fabs, 0);
      break;
    case kPPC_SqrtDouble:
      ASSEMBLE_FLOAT_UNOP_RC(fsqrt, MiscField::decode(instr->opcode()));
      break;
    case kPPC_FloorDouble:
      ASSEMBLE_FLOAT_UNOP_RC(frim, MiscField::decode(instr->opcode()));
      break;
    case kPPC_CeilDouble:
      ASSEMBLE_FLOAT_UNOP_RC(frip, MiscField::decode(instr->opcode()));
      break;
    case kPPC_TruncateDouble:
      ASSEMBLE_FLOAT_UNOP_RC(friz, MiscField::decode(instr->opcode()));
      break;
    case kPPC_RoundDouble:
      ASSEMBLE_FLOAT_UNOP_RC(frin, MiscField::decode(instr->opcode()));
      break;
    case kPPC_NegDouble:
      ASSEMBLE_FLOAT_UNOP_RC(fneg, 0);
      break;
    case kPPC_Cntlz32:
      __ cntlzw(i.OutputRegister(), i.InputRegister(0));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_Cntlz64:
      __ cntlzd(i.OutputRegister(), i.InputRegister(0));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_Popcnt32:
      __ Popcnt32(i.OutputRegister(), i.InputRegister(0));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_Popcnt64:
      __ Popcnt64(i.OutputRegister(), i.InputRegister(0));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_Cmp32:
      ASSEMBLE_COMPARE(cmpw, cmplw);
      break;
    case kPPC_Cmp64:
      ASSEMBLE_COMPARE(cmp, cmpl);
      break;
    case kPPC_CmpDouble:
      ASSEMBLE_FLOAT_COMPARE(fcmpu);
      break;
    case kPPC_Tst32:
      if (HasRegisterInput(instr, 1)) {
        __ and_(r0, i.InputRegister(0), i.InputRegister(1), i.OutputRCBit());
      } else {
        __ andi(r0, i.InputRegister(0), i.InputImmediate(1));
      }
      __ extsw(r0, r0, i.OutputRCBit());
      DCHECK_EQ(SetRC, i.OutputRCBit());
      break;
    case kPPC_Tst64:
      if (HasRegisterInput(instr, 1)) {
        __ and_(r0, i.InputRegister(0), i.InputRegister(1), i.OutputRCBit());
      } else {
        __ andi(r0, i.InputRegister(0), i.InputImmediate(1));
      }
      DCHECK_EQ(SetRC, i.OutputRCBit());
      break;
    case kPPC_Float64SilenceNaN: {
      DoubleRegister value = i.InputDoubleRegister(0);
      DoubleRegister result = i.OutputDoubleRegister();
      __ CanonicalizeNaN(result, value);
      break;
    }
    case kPPC_Push: {
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
          __ StoreF32WithUpdate(i.InputDoubleRegister(1),
                                MemOperand(sp, -kSystemPointerSize), r0);
          break;
        case MachineRepresentation::kFloat64:
          __ StoreF64WithUpdate(i.InputDoubleRegister(1),
                                MemOperand(sp, -kDoubleSize), r0);
          break;
        case MachineRepresentation::kSimd128:
          __ addi(sp, sp, Operand(-kSimd128Size));
          __ StoreSimd128(i.InputSimd128Register(1), MemOperand(r0, sp),
                          kScratchReg);
          break;
        default:
          __ StoreU64WithUpdate(i.InputRegister(1),
                                MemOperand(sp, -kSystemPointerSize), r0);
          break;
      }
      frame_access_state()->IncreaseSPDelta(slots);
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    }
    case kPPC_PushFrame: {
      int num_slots = i.InputInt32(1);
      if (instr->InputAt(0)->IsFPRegister()) {
        LocationOperand* op = LocationOperand::cast(instr->InputAt(0));
        if (op->representation() == MachineRepresentation::kFloat64) {
          __ StoreF64WithUpdate(i.InputDoubleRegister(0),
                                MemOperand(sp, -num_slots * kSystemPointerSize),
                                r0);
        } else {
          DCHECK_EQ(MachineRepresentation::kFloat32, op->representation());
          __ StoreF32WithUpdate(i.InputDoubleRegister(0),
                                MemOperand(sp, -num_slots * kSystemPointerSize),
                                r0);
        }
      } else {
        __ StoreU64WithUpdate(i.InputRegister(0),
                              MemOperand(sp, -num_slots * kSystemPointerSize),
                              r0);
      }
      break;
    }
    case kPPC_StoreToStackSlot: {
      int slot = i.InputInt32(1);
      if (instr->InputAt(0)->IsFPRegister()) {
        LocationOperand* op = LocationOperand::cast(instr->InputAt(0));
        if (op->representation() == MachineRepresentation::kFloat64) {
          __ StoreF64(i.InputDoubleRegister(0),
                      MemOperand(sp, slot * kSystemPointerSize), r0);
        } else if (op->representation() == MachineRepresentation::kFloat32) {
          __ StoreF32(i.InputDoubleRegister(0),
                      MemOperand(sp, slot * kSystemPointerSize), r0);
        } else {
          DCHECK_EQ(MachineRepresentation::kSimd128, op->representation());
          __ StoreSimd128(i.InputSimd128Register(0),
                          MemOperand(sp, slot * kSystemPointerSize),
                          kScratchReg);
        }
      } else {
        __ StoreU64(i.InputRegister(0),
                    MemOperand(sp, slot * kSystemPointerSize), r0);
      }
      break;
    }
    case kPPC_ExtendSignWord8:
      __ extsb(i.OutputRegister(), i.InputRegister(0));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_ExtendSignWord16:
      __ extsh(i.OutputRegister(), i.InputRegister(0));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_ExtendSignWord32:
      __ extsw(i.OutputRegister(), i.InputRegister(0));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_Uint32ToUint64:
      // Zero extend
      __ clrldi(i.OutputRegister(), i.InputRegister(0), Operand(32));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_Int64ToInt32:
      __ extsw(i.OutputRegister(), i.InputRegister(0));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_Int64ToFloat32:
      __ ConvertInt64ToFloat(i.InputRegister(0), i.OutputDoubleRegister());
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_Int64ToDouble:
      __ ConvertInt64ToDouble(i.InputRegister(0), i.OutputDoubleRegister());
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_Uint64ToFloat32:
      __ ConvertUnsignedInt64ToFloat(i.InputRegister(0),
                                     i.OutputDoubleRegister());
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_Uint64ToDouble:
      __ ConvertUnsignedInt64ToDouble(i.InputRegister(0),
                                      i.OutputDoubleRegister());
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_Int32ToFloat32:
      __ ConvertIntToFloat(i.InputRegister(0), i.OutputDoubleRegister());
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_Int32ToDouble:
      __ ConvertIntToDouble(i.InputRegister(0), i.OutputDoubleRegister());
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_Uint32ToFloat32:
      __ ConvertUnsignedIntToFloat(i.InputRegister(0),
                                   i.OutputDoubleRegister());
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_Uint32ToDouble:
      __ ConvertUnsignedIntToDouble(i.InputRegister(0),
                                    i.OutputDoubleRegister());
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_Float32ToInt32: {
      bool set_overflow_to_min_i32 = MiscField::decode(instr->opcode());
      if (set_overflow_to_min_i32) {
        __ mtfsb0(VXCVI);  // clear FPSCR:VXCVI bit
      }
      __ fctiwz(kScratchDoubleReg, i.InputDoubleRegister(0));
      __ MovDoubleLowToInt(i.OutputRegister(), kScratchDoubleReg);
      if (set_overflow_to_min_i32) {
        // Avoid INT32_MAX as an overflow indicator and use INT32_MIN instead,
        // because INT32_MIN allows easier out-of-bounds detection.
        CRegister cr = cr7;
        int crbit = v8::internal::Assembler::encode_crbit(
            cr, static_cast<CRBit>(VXCVI % CRWIDTH));
        __ mcrfs(cr, VXCVI);  // extract FPSCR field containing VXCVI into cr7
        __ li(kScratchReg, Operand(1));
        __ ShiftLeftU64(kScratchReg, kScratchReg,
                        Operand(31));  // generate INT32_MIN.
        __ isel(i.OutputRegister(0), kScratchReg, i.OutputRegister(0), crbit);
      }
      break;
    }
    case kPPC_Float32ToUint32: {
      bool set_overflow_to_min_u32 = MiscField::decode(instr->opcode());
      if (set_overflow_to_min_u32) {
        __ mtfsb0(VXCVI);  // clear FPSCR:VXCVI bit
      }
      __ fctiwuz(kScratchDoubleReg, i.InputDoubleRegister(0));
      __ MovDoubleLowToInt(i.OutputRegister(), kScratchDoubleReg);
      if (set_overflow_to_min_u32) {
        // Avoid UINT32_MAX as an overflow indicator and use 0 instead,
        // because 0 allows easier out-of-bounds detection.
        CRegister cr = cr7;
        int crbit = v8::internal::Assembler::encode_crbit(
            cr, static_cast<CRBit>(VXCVI % CRWIDTH));
        __ mcrfs(cr, VXCVI);  // extract FPSCR field containing VXCVI into cr7
        __ li(kScratchReg, Operand::Zero());
        __ isel(i.OutputRegister(0), kScratchReg, i.OutputRegister(0), crbit);
      }
      break;
    }
#define DOUBLE_TO_INT32(op)                                                \
  bool check_conversion = i.OutputCount() > 1;                             \
  CRegister cr = cr7;                                                      \
  FPSCRBit fps_bit = VXCVI;                                                \
  int cr_bit = v8::internal::Assembler::encode_crbit(                      \
      cr, static_cast<CRBit>(fps_bit % CRWIDTH));                          \
  __ mtfsb0(fps_bit); /* clear FPSCR:VXCVI bit */                          \
  __ op(kScratchDoubleReg, i.InputDoubleRegister(0));                      \
  __ MovDoubleLowToInt(i.OutputRegister(0), kScratchDoubleReg);            \
  __ mcrfs(cr, VXCVI); /* extract FPSCR field containing VXCVI into cr7 */ \
  if (check_conversion) {                                                  \
    __ li(i.OutputRegister(1), Operand(1));                                \
    __ isel(i.OutputRegister(1), r0, i.OutputRegister(1), cr_bit);         \
  } else {                                                                 \
    __ isel(i.OutputRegister(0), r0, i.OutputRegister(0), cr_bit);         \
  }
    case kPPC_DoubleToInt32: {
      DOUBLE_TO_INT32(fctiwz)
      break;
    }
    case kPPC_DoubleToUint32: {
      DOUBLE_TO_INT32(fctiwuz)
      break;
    }
#undef DOUBLE_TO_INT32
    case kPPC_DoubleToInt64: {
      bool check_conversion = i.OutputCount() > 1;
      __ mtfsb0(VXCVI);  // clear FPSCR:VXCVI bit
      __ ConvertDoubleToInt64(i.InputDoubleRegister(0),
                              i.OutputRegister(0), kScratchDoubleReg);
      CRegister cr = cr7;
      int crbit = v8::internal::Assembler::encode_crbit(
          cr, static_cast<CRBit>(VXCVI % CRWIDTH));
      __ mcrfs(cr, VXCVI);  // extract FPSCR field containing VXCVI into cr7
      // Handle conversion failures (such as overflow).
      if (check_conversion) {
        __ li(i.OutputRegister(1), Operand(1));
        __ isel(i.OutputRegister(1), r0, i.OutputRegister(1), crbit);
      } else {
        __ isel(i.OutputRegister(0), r0, i.OutputRegister(0), crbit);
      }
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    }
    case kPPC_DoubleToUint64: {
      bool check_conversion = (i.OutputCount() > 1);
      if (check_conversion) {
        __ mtfsb0(VXCVI);  // clear FPSCR:VXCVI bit
      }
      __ ConvertDoubleToUnsignedInt64(i.InputDoubleRegister(0),
                                      i.OutputRegister(0), kScratchDoubleReg);
      if (check_conversion) {
        // Set 2nd output to zero if conversion fails.
        CRegister cr = cr7;
        int crbit = v8::internal::Assembler::encode_crbit(
            cr, static_cast<CRBit>(VXCVI % CRWIDTH));
        __ mcrfs(cr, VXCVI);  // extract FPSCR field containing VXCVI into cr7
        __ li(i.OutputRegister(1), Operand(1));
        __ isel(i.OutputRegister(1), r0, i.OutputRegister(1), crbit);
      }
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    }
    case kPPC_DoubleToFloat32:
      ASSEMBLE_FLOAT_UNOP_RC(frsp, 0);
      break;
    case kPPC_Float32ToDouble:
      // Nothing to do.
      __ Move(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_DoubleExtractLowWord32:
      __ MovDoubleLowToInt(i.OutputRegister(), i.InputDoubleRegister(0));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_DoubleExtractHighWord32:
      __ MovDoubleHighToInt(i.OutputRegister(), i.InputDoubleRegister(0));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_DoubleFromWord32Pair:
      __ clrldi(kScratchReg, i.InputRegister(1), Operand(32));
      __ ShiftLeftU64(i.TempRegister(0), i.InputRegister(0), Operand(32));
      __ OrU64(i.TempRegister(0), i.TempRegister(0), kScratchReg);
      __ MovInt64ToDouble(i.OutputDoubleRegister(), i.TempRegister(0));
      break;
    case kPPC_DoubleInsertLowWord32:
      __ InsertDoubleLow(i.OutputDoubleRegister(), i.InputRegister(1), r0);
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_DoubleInsertHighWord32:
      __ InsertDoubleHigh(i.OutputDoubleRegister(), i.InputRegister(1), r0);
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_DoubleConstruct:
      __ MovInt64ComponentsToDouble(i.OutputDoubleRegister(),
                                    i.InputRegister(0), i.InputRegister(1), r0);
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_BitcastFloat32ToInt32:
      __ MovFloatToInt(i.OutputRegister(), i.InputDoubleRegister(0),
                       kScratchDoubleReg);
      break;
    case kPPC_BitcastInt32ToFloat32:
      __ MovIntToFloat(i.OutputDoubleRegister(), i.InputRegister(0), ip);
      break;
    case kPPC_BitcastDoubleToInt64:
      __ MovDoubleToInt64(i.OutputRegister(), i.InputDoubleRegister(0));
      break;
    case kPPC_BitcastInt64ToDouble:
      __ MovInt64ToDouble(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    case kPPC_LoadWordU8:
      ASSEMBLE_LOAD_INTEGER(lbz, plbz, lbzx, false);
      break;
    case kPPC_LoadWordS8:
      ASSEMBLE_LOAD_INTEGER(lbz, plbz, lbzx, false);
      __ extsb(i.OutputRegister(), i.OutputRegister());
      break;
    case kPPC_LoadWordU16:
      ASSEMBLE_LOAD_INTEGER(lhz, plhz, lhzx, false);
      break;
    case kPPC_LoadWordS16:
      ASSEMBLE_LOAD_INTEGER(lha, plha, lhax, false);
      break;
    case kPPC_LoadWordU32:
      ASSEMBLE_LOAD_INTEGER(lwz, plwz, lwzx, false);
      break;
    case kPPC_LoadWordS32:
      ASSEMBLE_LOAD_INTEGER(lwa, plwa, lwax, true);
      break;
    case kPPC_LoadWord64:
      ASSEMBLE_LOAD_INTEGER(ld, pld, ldx, true);
      break;
    case kPPC_LoadFloat32:
      ASSEMBLE_LOAD_FLOAT(lfs, plfs, lfsx);
      break;
    case kPPC_LoadDouble:
      ASSEMBLE_LOAD_FLOAT(lfd, plfd, lfdx);
      break;
    case kPPC_LoadSimd128: {
      Simd128Register result = i.OutputSimd128Register();
      AddressingMode mode = kMode_None;
      MemOperand operand = i.MemoryOperand(&mode);
      bool is_atomic = i.InputInt32(2);
      DCHECK_EQ(mode, kMode_MRR);
      __ LoadSimd128(result, operand, kScratchReg);
      if (is_atomic) __ lwsync();
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    }
    case kPPC_LoadReverseSimd128RR: {
      __ xxbrq(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kPPC_StoreWord8:
      ASSEMBLE_STORE_INTEGER(stb, pstb, stbx, false);
      break;
    case kPPC_StoreWord16:
      ASSEMBLE_STORE_INTEGER(sth, psth, sthx, false);
      break;
    case kPPC_StoreWord32:
      ASSEMBLE_STORE_INTEGER(stw, pstw, stwx, false);
      break;
    case kPPC_StoreWord64:
      ASSEMBLE_STORE_INTEGER(std, pstd, stdx, true);
      break;
    case kPPC_StoreFloat32:
      ASSEMBLE_STORE_FLOAT(stfs, pstfs, stfsx);
      break;
    case kPPC_StoreDouble:
      ASSEMBLE_STORE_FLOAT(stfd, pstfd, stfdx);
      break;
    case kPPC_StoreSimd128: {
      size_t index = 0;
      AddressingMode mode = kMode_None;
      MemOperand operand = i.MemoryOperand(&mode, &index);
      Simd128Register value = i.InputSimd128Register(index);
      bool is_atomic = i.InputInt32(3);
      if (is_atomic) __ lwsync();
      DCHECK_EQ(mode, kMode_MRR);
      __ StoreSimd128(value, operand, kScratchReg);
      if (is_atomic) __ sync();
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    }
    case kAtomicLoadInt8:
    case kAtomicLoadInt16:
      UNREACHABLE();
    case kAtomicExchangeInt8:
      __ AtomicExchange<int8_t>(
          MemOperand(i.InputRegister(0), i.InputRegister(1)),
          i.InputRegister(2), i.OutputRegister());
      break;
    case kPPC_AtomicExchangeUint8:
      __ AtomicExchange<uint8_t>(
          MemOperand(i.InputRegister(0), i.InputRegister(1)),
          i.InputRegister(2), i.OutputRegister());
      break;
    case kAtomicExchangeInt16: {
      ASSEMBLE_ATOMIC_EXCHANGE(int16_t, ByteReverseU16);
      __ extsh(i.OutputRegister(), i.OutputRegister());
      break;
    }
    case kPPC_AtomicExchangeUint16: {
      ASSEMBLE_ATOMIC_EXCHANGE(uint16_t, ByteReverseU16);
      break;
    }
    case kPPC_AtomicExchangeWord32: {
      ASSEMBLE_ATOMIC_EXCHANGE(uint32_t, ByteReverseU32);
      break;
    }
    case kPPC_AtomicExchangeWord64: {
      ASSEMBLE_ATOMIC_EXCHANGE(uint64_t, ByteReverseU64);
      break;
    }
    case kAtomicCompareExchangeInt8:
      __ AtomicCompareExchange<int8_t>(
          MemOperand(i.InputRegister(0), i.InputRegister(1)),
          i.InputRegister(2), i.InputRegister(3), i.OutputRegister(),
          kScratchReg);
      break;
    case kPPC_AtomicCompareExchangeUint8:
      __ AtomicCompareExchange<uint8_t>(
          MemOperand(i.InputRegister(0), i.InputRegister(1)),
          i.InputRegister(2), i.InputRegister(3), i.OutputRegister(),
          kScratchReg);
      break;
    case kAtomicCompareExchangeInt16: {
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE(int16_t, ByteReverseU16);
      __ extsh(i.OutputRegister(), i.OutputRegister());
      break;
    }
    case kPPC_AtomicCompareExchangeUint16: {
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE(uint16_t, ByteReverseU16);
      break;
    }
    case kPPC_AtomicCompareExchangeWord32: {
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE(uint32_t, ByteReverseU32);
      break;
    }
    case kPPC_AtomicCompareExchangeWord64: {
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE(uint64_t, ByteReverseU64);
    } break;

#define ATOMIC_BINOP_CASE(op, inst)                            \
  case kPPC_Atomic##op##Int8:                                  \
    ASSEMBLE_ATOMIC_BINOP_BYTE(inst, int8_t);                  \
    __ extsb(i.OutputRegister(), i.OutputRegister());          \
    break;                                                     \
  case kPPC_Atomic##op##Uint8:                                 \
    ASSEMBLE_ATOMIC_BINOP_BYTE(inst, uint8_t);                 \
    break;                                                     \
  case kPPC_Atomic##op##Int16:                                 \
    ASSEMBLE_ATOMIC_BINOP(inst, int16_t, ByteReverseU16, r0);  \
    __ extsh(i.OutputRegister(), i.OutputRegister());          \
    break;                                                     \
  case kPPC_Atomic##op##Uint16:                                \
    ASSEMBLE_ATOMIC_BINOP(inst, uint16_t, ByteReverseU16, r0); \
    break;                                                     \
  case kPPC_Atomic##op##Int32:                                 \
    ASSEMBLE_ATOMIC_BINOP(inst, int32_t, ByteReverseU32, r0);  \
    __ extsw(i.OutputRegister(), i.OutputRegister());          \
    break;                                                     \
  case kPPC_Atomic##op##Uint32:                                \
    ASSEMBLE_ATOMIC_BINOP(inst, uint32_t, ByteReverseU32, r0); \
    break;                                                     \
  case kPPC_Atomic##op##Int64:                                 \
  case kPPC_Atomic##op##Uint64:                                \
    ASSEMBLE_ATOMIC_BINOP(inst, uint64_t, ByteReverseU64, r0); \
    break;
      ATOMIC_BINOP_CASE(Add, add)
      ATOMIC_BINOP_CASE(Sub, sub)
      ATOMIC_BINOP_CASE(And, and_)
      ATOMIC_BINOP_CASE(Or, orx)
      ATOMIC_BINOP_CASE(Xor, xor_)
#undef ATOMIC_BINOP_CASE

    case kPPC_ByteRev32: {
      Register input = i.InputRegister(0);
      Register output = i.OutputRegister();
      Register temp1 = r0;
      if (CpuFeatures::IsSupported(PPC_10_PLUS)) {
        __ brw(output, input);
        __ extsw(output, output);
        break;
      }
      __ rotlwi(temp1, input, 8);
      __ rlwimi(temp1, input, 24, 0, 7);
      __ rlwimi(temp1, input, 24, 16, 23);
      __ extsw(output, temp1);
      break;
    }
    case kPPC_LoadByteRev32: {
      ASSEMBLE_LOAD_INTEGER_RR(lwbrx);
      break;
    }
    case kPPC_StoreByteRev32: {
      ASSEMBLE_STORE_INTEGER_RR(stwbrx);
      break;
    }
    case kPPC_ByteRev64: {
      Register input = i.InputRegister(0);
      Register output = i.OutputRegister();
      Register temp1 = r0;
      Register temp2 = kScratchReg;
      Register temp3 = i.TempRegister(0);
      if (CpuFeatures::IsSupported(PPC_10_PLUS)) {
        __ brd(output, input);
        break;
      }
      __ rldicl(temp1, input, 32, 32);
      __ rotlwi(temp2, input, 8);
      __ rlwimi(temp2, input, 24, 0, 7);
      __ rotlwi(temp3, temp1, 8);
      __ rlwimi(temp2, input, 24, 16, 23);
      __ rlwimi(temp3, temp1, 24, 0, 7);
      __ rlwimi(temp3, temp1, 24, 16, 23);
      __ rldicr(temp2, temp2, 32, 31);
      __ orx(output, temp2, temp3);
      break;
    }
    case kPPC_LoadByteRev64: {
      ASSEMBLE_LOAD_INTEGER_RR(ldbrx);
      break;
    }
    case kPPC_StoreByteRev64: {
      ASSEMBLE_STORE_INTEGER_RR(stdbrx);
      break;
    }
// Simd Support.
#define SIMD_BINOP_LIST(V) \
  V(F64x2Add)              \
  V(F64x2Sub)              \
  V(F64x2Mul)              \
  V(F64x2Div)              \
  V(F64x2Eq)               \
  V(F64x2Lt)               \
  V(F64x2Le)               \
  V(F32x4Add)              \
  V(F32x4Sub)              \
  V(F32x4Mul)              \
  V(F32x4Div)              \
  V(F32x4Min)              \
  V(F32x4Max)              \
  V(F32x4Eq)               \
  V(F32x4Lt)               \
  V(F32x4Le)               \
  V(I64x2Add)              \
  V(I64x2Sub)              \
  V(I64x2Eq)               \
  V(I64x2GtS)              \
  V(I32x4Add)              \
  V(I32x4Sub)              \
  V(I32x4Mul)              \
  V(I32x4MinS)             \
  V(I32x4MinU)             \
  V(I32x4MaxS)             \
  V(I32x4MaxU)             \
  V(I32x4Eq)               \
  V(I32x4GtS)              \
  V(I32x4GtU)              \
  V(I32x4DotI16x8S)        \
  V(I16x8Add)              \
  V(I16x8Sub)              \
  V(I16x8Mul)              \
  V(I16x8MinS)             \
  V(I16x8MinU)             \
  V(I16x8MaxS)             \
  V(I16x8MaxU)             \
  V(I16x8Eq)               \
  V(I16x8GtS)              \
  V(I16x8GtU)              \
  V(I16x8AddSatS)          \
  V(I16x8SubSatS)          \
  V(I16x8AddSatU)          \
  V(I16x8SubSatU)          \
  V(I16x8SConvertI32x4)    \
  V(I16x8UConvertI32x4)    \
  V(I16x8RoundingAverageU) \
  V(I16x8Q15MulRSatS)      \
  V(I8x16Add)              \
  V(I8x16Sub)              \
  V(I8x16MinS)             \
  V(I8x16MinU)             \
  V(I8x16MaxS)             \
  V(I8x16MaxU)             \
  V(I8x16Eq)               \
  V(I8x16GtS)              \
  V(I8x16GtU)              \
  V(I8x16AddSatS)          \
  V(I8x16SubSatS)          \
  V(I8x16AddSatU)          \
  V(I8x16SubSatU)          \
  V(I8x16SConvertI16x8)    \
  V(I8x16UConvertI16x8)    \
  V(I8x16RoundingAverageU) \
  V(S128And)               \
  V(S128Or)                \
  V(S128Xor)               \
  V(S128AndNot)

#define EMIT_SIMD_BINOP(name)                                     \
  case kPPC_##name: {                                             \
    __ name(i.OutputSimd128Register(), i.InputSimd128Register(0), \
            i.InputSimd128Register(1));                           \
    break;                                                        \
  }
      SIMD_BINOP_LIST(EMIT_SIMD_BINOP)
#undef EMIT_SIMD_BINOP
#undef SIMD_BINOP_LIST

#define SIMD_BINOP_WITH_SCRATCH_LIST(V) \
  V(F64x2Ne)                            \
  V(F64x2Pmin)                          \
  V(F64x2Pmax)                          \
  V(F32x4Ne)                            \
  V(F32x4Pmin)                          \
  V(F32x4Pmax)                          \
  V(I64x2Ne)                            \
  V(I64x2GeS)                           \
  V(I64x2ExtMulLowI32x4S)               \
  V(I64x2ExtMulHighI32x4S)              \
  V(I64x2ExtMulLowI32x4U)               \
  V(I64x2ExtMulHighI32x4U)              \
  V(I32x4Ne)                            \
  V(I32x4GeS)                           \
  V(I32x4GeU)                           \
  V(I32x4ExtMulLowI16x8S)               \
  V(I32x4ExtMulHighI16x8S)              \
  V(I32x4ExtMulLowI16x8U)               \
  V(I32x4ExtMulHighI16x8U)              \
  V(I16x8Ne)                            \
  V(I16x8GeS)                           \
  V(I16x8GeU)                           \
  V(I16x8ExtMulLowI8x16S)               \
  V(I16x8ExtMulHighI8x16S)              \
  V(I16x8ExtMulLowI8x16U)               \
  V(I16x8ExtMulHighI8x16U)              \
  V(I16x8DotI8x16S)                     \
  V(I8x16Ne)                            \
  V(I8x16GeS)                           \
  V(I8x16GeU)                           \
  V(I8x16Swizzle)

#define EMIT_SIMD_BINOP_WITH_SCRATCH(name)                        \
  case kPPC_##name: {                                             \
    __ name(i.OutputSimd128Register(), i.InputSimd128Register(0), \
            i.InputSimd128Register(1), kScratchSimd128Reg);       \
    break;                                                        \
  }
      SIMD_BINOP_WITH_SCRATCH_LIST(EMIT_SIMD_BINOP_WITH_SCRATCH)
#undef EMIT_SIMD_BINOP_WITH_SCRATCH
#undef SIMD_BINOP_WITH_SCRATCH_LIST

#define SIMD_SHIFT_LIST(V) \
  V(I64x2Shl)              \
  V(I64x2ShrS)             \
  V(I64x2ShrU)             \
  V(I32x4Shl)              \
  V(I32x4ShrS)             \
  V(I32x4ShrU)             \
  V(I16x8Shl)              \
  V(I16x8ShrS)             \
  V(I16x8ShrU)             \
  V(I8x16Shl)              \
  V(I8x16ShrS)             \
  V(I8x16ShrU)

#define EMIT_SIMD_SHIFT(name)                                     \
  case kPPC_##name: {                                             \
    __ name(i.OutputSimd128Register(), i.InputSimd128Register(0), \
            i.InputRegister(1), kScratchSimd128Reg);              \
    break;                                                        \
  }
      SIMD_SHIFT_LIST(EMIT_SIMD_SHIFT)
#undef EMIT_SIMD_SHIFT
#undef SIMD_SHIFT_LIST

#define SIMD_UNOP_LIST(V)   \
  V(F64x2Abs)               \
  V(F64x2Neg)               \
  V(F64x2Sqrt)              \
  V(F64x2Ceil)              \
  V(F64x2Floor)             \
  V(F64x2Trunc)             \
  V(F64x2PromoteLowF32x4)   \
  V(F32x4Abs)               \
  V(F32x4Neg)               \
  V(F32x4SConvertI32x4)     \
  V(F32x4UConvertI32x4)     \
  V(I64x2Neg)               \
  V(I32x4Neg)               \
  V(F32x4Sqrt)              \
  V(F32x4Ceil)              \
  V(F32x4Floor)             \
  V(F32x4Trunc)             \
  V(F64x2ConvertLowI32x4S)  \
  V(I64x2SConvertI32x4Low)  \
  V(I64x2SConvertI32x4High) \
  V(I32x4SConvertI16x8Low)  \
  V(I32x4SConvertI16x8High) \
  V(I32x4UConvertF32x4)     \
  V(I16x8SConvertI8x16Low)  \
  V(I16x8SConvertI8x16High) \
  V(I8x16Popcnt)            \
  V(S128Not)

#define EMIT_SIMD_UNOP(name)                                       \
  case kPPC_##name: {                                              \
    __ name(i.OutputSimd128Register(), i.InputSimd128Register(0)); \
    break;                                                         \
  }
      SIMD_UNOP_LIST(EMIT_SIMD_UNOP)
#undef EMIT_SIMD_UNOP
#undef SIMD_UNOP_LIST

#define SIMD_UNOP_WITH_SCRATCH_LIST(V) \
  V(F32x4DemoteF64x2Zero)              \
  V(I64x2Abs)                          \
  V(I32x4Abs)                          \
  V(I32x4SConvertF32x4)                \
  V(I32x4TruncSatF64x2SZero)           \
  V(I32x4TruncSatF64x2UZero)           \
  V(I16x8Abs)                          \
  V(I16x8Neg)                          \
  V(I8x16Abs)                          \
  V(I8x16Neg)

#define EMIT_SIMD_UNOP_WITH_SCRATCH(name)                         \
  case kPPC_##name: {                                             \
    __ name(i.OutputSimd128Register(), i.InputSimd128Register(0), \
            kScratchSimd128Reg);                                  \
    break;                                                        \
  }
      SIMD_UNOP_WITH_SCRATCH_LIST(EMIT_SIMD_UNOP_WITH_SCRATCH)
#undef EMIT_SIMD_UNOP_WITH_SCRATCH
#undef SIMD_UNOP_WITH_SCRATCH_LIST

#define SIMD_ALL_TRUE_LIST(V) \
  V(I64x2AllTrue)             \
  V(I32x4AllTrue)             \
  V(I16x8AllTrue)             \
  V(I8x16AllTrue)
#define EMIT_SIMD_ALL_TRUE(name)                                   \
  case kPPC_##name: {                                              \
    __ name(i.OutputRegister(), i.InputSimd128Register(0), r0, ip, \
            kScratchSimd128Reg);                                   \
    break;                                                         \
  }
      SIMD_ALL_TRUE_LIST(EMIT_SIMD_ALL_TRUE)
#undef EMIT_SIMD_ALL_TRUE
#undef SIMD_ALL_TRUE_LIST

#define SIMD_QFM_LIST(V) \
  V(F64x2Qfma)           \
  V(F64x2Qfms)           \
  V(F32x4Qfma)           \
  V(F32x4Qfms)
#define EMIT_SIMD_QFM(name)                                       \
  case kPPC_##name: {                                             \
    __ name(i.OutputSimd128Register(), i.InputSimd128Register(0), \
            i.InputSimd128Register(1), i.InputSimd128Register(2), \
            kScratchSimd128Reg);                                  \
    break;                                                        \
  }
      SIMD_QFM_LIST(EMIT_SIMD_QFM)
#undef EMIT_SIMD_QFM
#undef SIMD_QFM_LIST

#define SIMD_EXT_ADD_PAIRWISE_LIST(V) \
  V(I32x4ExtAddPairwiseI16x8S)        \
  V(I32x4ExtAddPairwiseI16x8U)        \
  V(I16x8ExtAddPairwiseI8x16S)        \
  V(I16x8ExtAddPairwiseI8x16U)
#define EMIT_SIMD_EXT_ADD_PAIRWISE(name)                          \
  case kPPC_##name: {                                             \
    __ name(i.OutputSimd128Register(), i.InputSimd128Register(0), \
            kScratchSimd128Reg, kScratchSimd128Reg2);             \
    break;                                                        \
  }
      SIMD_EXT_ADD_PAIRWISE_LIST(EMIT_SIMD_EXT_ADD_PAIRWISE)
#undef EMIT_SIMD_EXT_ADD_PAIRWISE
#undef SIMD_EXT_ADD_PAIRWISE_LIST

#define SIMD_LOAD_LANE_LIST(V)    \
  V(S128Load64Lane, LoadLane64LE) \
  V(S128Load32Lane, LoadLane32LE) \
  V(S128Load16Lane, LoadLane16LE) \
  V(S128Load8Lane, LoadLane8LE)

#define EMIT_SIMD_LOAD_LANE(name, op)                                      \
  case kPPC_##name: {                                                      \
    Simd128Register dst = i.OutputSimd128Register();                       \
    DCHECK_EQ(dst, i.InputSimd128Register(0));                             \
    AddressingMode mode = kMode_None;                                      \
    size_t index = 1;
```