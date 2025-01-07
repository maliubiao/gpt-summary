Response:
My thought process for analyzing the provided C++ code snippet goes like this:

1. **Identify the Core Function:** The code is within a `switch` statement based on `instr->opcode()`. This immediately tells me that the primary function of this code block is to handle different instruction opcodes. The surrounding context (not fully provided, but hinted at by the file name `code-generator-arm.cc`) suggests this is part of a code generation process for the ARM architecture.

2. **Group by Functionality:** I start grouping the `case` statements based on the prefix of the opcode (e.g., `kArmFloat`, `kArmPush`, `kArmF64x2`, `kArmI32x4`, etc.). This helps in understanding the high-level categories of operations being performed. For example, all `kArmFloat` cases deal with floating-point operations.

3. **Analyze Individual Cases:** For each group, I examine individual `case` statements. I pay attention to:
    * **Opcode Name:** This gives a strong indication of the operation (e.g., `kArmFloat64Min` suggests finding the minimum of two 64-bit floats).
    * **Input and Output Types:**  The code uses `InputFloatRegister`, `OutputDoubleRegister`, `InputInt32`, `OutputSimd128Register`, etc. These tell me the data types involved.
    * **Assembler Instructions:** The `__ Move`, `__ FloatMin`, `__ vpush`, `__ ldr`, etc., lines are calls to the ARM assembler. These are the low-level instructions being generated.
    * **Helper Functions/Classes:**  Things like `OutOfLineFloat32Min`, `UseScratchRegisterScope`, `FrameSlotToFPOffset`, `ElementSizeInPointers`, `CpuFeatureScope` suggest additional logic or abstractions.
    * **DCHECK Statements:** These are assertions, used for internal validation. They can provide clues about expected conditions.

4. **Look for Patterns and Common Themes:** Within the groups, I look for repeating patterns. For example, many of the SIMD instructions follow a similar structure for extracting/replacing lanes, performing arithmetic operations, and comparisons. The `ASSEMBLE_F64X2_ARITHMETIC_BINOP` macro is a clear example of code reuse.

5. **Infer Functionality from Assembler Instructions:**  Even without deep ARM assembly knowledge, I can often infer the purpose of a sequence of instructions. For instance, a `vpush` followed by incrementing the `frame_access_state` likely means pushing data onto the stack and updating the stack pointer. `ldr` and `str` usually indicate loading from and storing to memory.

6. **Consider Potential JavaScript Equivalents:**  If an operation seems related to standard JavaScript behavior (like `Math.min`, floating-point arithmetic, array operations via SIMD), I think about how it might be expressed in JavaScript. This helps bridge the gap between the low-level code and the higher-level language.

7. **Identify Potential Programming Errors:** Based on the operations, I consider common errors that programmers might make. For example, incorrect stack management when using `push` and `poke`, or issues with NaN handling in floating-point comparisons.

8. **Structure the Summary:** I organize my findings into logical categories:
    * **Core Function:** A high-level description of the code's purpose.
    * **Specific Functionalities:** Listing the different groups of operations.
    * **JavaScript Relation (if applicable):**  Providing JavaScript examples.
    * **Code Logic Reasoning:**  Illustrating the input/output of specific operations.
    * **Common Programming Errors:**  Giving examples of mistakes related to the code.

**Applying this to the provided snippet:**

* **Initial Scan:** I see a `switch` statement handling various `kArm...` cases. Many cases involve floating-point (`FloatMin`, `SilenceNaN`), stack manipulation (`Push`, `Poke`, `Peek`), and SIMD operations (`F64x2`, `I32x4`, `I64x2`, `F32x4`).
* **Float Operations:**  `kArmFloat32Min` and `kArmFloat64Min` clearly implement the `Math.min` function for single and double-precision floats. The "out-of-line" logic suggests special handling for cases where the inputs are different. `kArmFloat64SilenceNaN` handles NaN canonicalization.
* **Stack Operations:** `kArmPush` pushes data onto the stack. The size is calculated. `kArmPoke` writes to a specific slot on the stack. `kArmPeek` reads from the stack.
* **SIMD Operations:**  The numerous `kArmF64x2`, `kArmI32x4`, etc., cases point to a significant focus on SIMD (Single Instruction, Multiple Data) operations, dealing with 128-bit vectors of various data types (floats, integers). I notice patterns in arithmetic operations (`Add`, `Sub`, `Mul`, `Div`), comparisons (`Eq`, `Ne`, `Lt`, `Le`), lane manipulation (`Splat`, `ExtractLane`, `ReplaceLane`), and conversions.
* **JavaScript Connection:** The float min/max operations directly relate to `Math.min` and `Math.max`. SIMD operations have equivalents in JavaScript's Typed Arrays and the WebAssembly SIMD proposal.
* **Potential Errors:** Stack operations are prone to errors if the `stack_decrement` is calculated incorrectly, leading to incorrect memory access. Floating-point comparisons can be tricky with NaNs. SIMD operations require careful understanding of lane ordering and data types.

By following these steps, I can systematically analyze the code snippet and arrive at a comprehensive understanding of its functionality, its relationship to JavaScript, and potential pitfalls. The grouping and pattern recognition are particularly helpful in dealing with a large number of similar cases.
这是v8源代码文件 `v8/src/compiler/backend/arm/code-generator-arm.cc` 的第三部分，它负责为 ARM 架构生成机器码。 让我们来归纳一下这部分代码的功能：

**核心功能归纳：**

这部分代码主要负责处理以下类型的 ARM 指令生成：

1. **浮点数最小值操作 (`kArmFloat32Min`, `kArmFloat64Min`)**:  实现了单精度和双精度浮点数的最小值计算。它会检查输入是否相同，如果相同则直接移动，否则会调用一个 out-of-line 的辅助函数来处理 NaN 的情况。

2. **浮点数 NaN 规范化 (`kArmFloat64SilenceNaN`)**: 将双精度浮点数的 NaN 值转换为规范的 NaN 表示形式。

3. **栈操作 (`kArmPush`, `kArmPoke`, `kArmPeek`)**:
   - `kArmPush`: 将数据压入栈中，并根据数据类型（浮点、双精度浮点、SIMD 或普通寄存器）选择相应的压栈指令。同时会更新栈指针。
   - `kArmPoke`: 将寄存器的值写入栈中的特定偏移位置。
   - `kArmPeek`: 从栈中的特定偏移位置读取数据到寄存器，支持浮点、双精度浮点和 SIMD 类型。

4. **内存屏障 (`kArmDmbIsh`, `kArmDsbIsb`)**:  插入内存屏障指令，用于确保内存操作的顺序性。

5. **SIMD (NEON) 操作 (大量 `kArm...` 开头的指令)**:  这部分是此代码块的重点，包含了大量的 SIMD 指令实现，用于并行处理数据。  这些指令涵盖了：
   - **乘法 (`kArmVmullLow`, `kArmVmullHigh`)**:  执行向量乘法，并将结果的高位或低位部分存储到输出向量。
   - **加法规约 (`kArmVpadal`)**:  将向量相邻的元素相加，并将结果累加到目标向量。
   - **成对加法 (`kArmVpaddl`)**:  将向量相邻的元素成对相加。
   - **SIMD 浮点操作 (`kArmF64x2...`, `kArmF32x4...`)**:  包括：
     - 创建 (`kArmF64x2Splat`)
     - 提取 (`kArmF64x2ExtractLane`, `kArmF32x4ExtractLane`)
     - 替换 (`kArmF64x2ReplaceLane`, `kArmF32x4ReplaceLane`)
     - 绝对值 (`kArmF64x2Abs`, `kArmF32x4Abs`)
     - 取反 (`kArmF64x2Neg`, `kArmF32x4Neg`)
     - 平方根 (`kArmF64x2Sqrt`, `kArmF32x4Sqrt`)
     - 加法 (`kArmF64x2Add`, `kArmF32x4Add`)
     - 减法 (`kArmF64x2Sub`, `kArmF32x4Sub`)
     - 乘法 (`kArmF64x2Mul`, `kArmF32x4Mul`)
     - 除法 (`kArmF64x2Div`, `kArmF32x4Div`)
     - 最小值 (`kArmF64x2Min`, `kArmF32x4Min`, `kArmF64x2Pmin`, `kArmF32x4Pmin`)
     - 最大值 (`kArmF64x2Max`, `kArmF32x4Max`, `kArmF64x2Pmax`, `kArmF32x4Pmax`)
     - 比较 (`kArmF64x2Eq`, `kArmF64x2Ne`, `kArmF64x2Lt`, `kArmF64x2Le`, `kArmF32x4Eq`, `kArmF32x4Ne`, `kArmF32x4Lt`, `kArmF32x4Le`)
     - 融合乘加 (`kArmF64x2Qfma`, `kArmF32x4Qfma`)
     - 融合乘减 (`kArmF64x2Qfms`, `kArmF32x4Qfms`)
     - 取整 (`kArmF64x2Ceil`, `kArmF64x2Floor`, `kArmF64x2Trunc`, `kArmF64x2NearestInt`)
     - 类型转换 (`kArmF64x2ConvertLowI32x4S`, `kArmF64x2ConvertLowI32x4U`, `kArmF32x4SConvertI32x4`, `kArmF32x4UConvertI32x4`, `kArmF32x4DemoteF64x2Zero`)
   - **SIMD 整数操作 (`kArmI64x2...`, `kArmI32x4...`, `kArmI16x8...`)**: 包括：
     - 创建 (`kArmI64x2SplatI32Pair`, `kArmI32x4Splat`, `kArmI16x8Splat`)
     - 替换 (`kArmI64x2ReplaceLaneI32Pair`, `kArmI32x4ReplaceLane`, `kArmI16x8ReplaceLane`)
     - 加法 (`kArmI64x2Add`, `kArmI32x4Add`)
     - 减法 (`kArmI64x2Sub`, `kArmI32x4Sub`)
     - 乘法 (`kArmI64x2Mul`, `kArmI32x4Mul`)
     - 绝对值 (`kArmI64x2Abs`, `kArmI32x4Abs`)
     - 取反 (`kArmI64x2Neg`, `kArmI32x4Neg`)
     - 左移 (`kArmI64x2Shl`, `kArmI32x4Shl`)
     - 右移 (有符号和无符号) (`kArmI64x2ShrS`, `kArmI64x2ShrU`, `kArmI32x4ShrS`, `kArmI32x4ShrU`)
     - 位掩码 (`kArmI64x2BitMask`, `kArmI32x4BitMask`)
     - 类型转换 (`kArmI64x2SConvertI32x4Low`, `kArmI64x2SConvertI32x4High`, `kArmI64x2UConvertI32x4Low`, `kArmI64x2UConvertI32x4High`, `kArmI32x4SConvertF32x4`, `kArmI32x4SConvertI16x8Low`, `kArmI32x4SConvertI16x8High`, `kArmI32x4UConvertF32x4`, `kArmI32x4UConvertI16x8Low`, `kArmI32x4UConvertI16x8High`, `kArmI32x4TruncSatF64x2SZero`, `kArmI32x4TruncSatF64x2UZero`)
     - 比较 (`kArmI64x2Eq`, `kArmI64x2Ne`, `kArmI64x2GtS`, `kArmI64x2GeS`, `kArmI32x4Eq`, `kArmI32x4Ne`, `kArmI32x4GtS`, `kArmI32x4GeS`, `kArmI32x4MinS`, `kArmI32x4MaxS`, `kArmI32x4MinU`, `kArmI32x4MaxU`, `kArmI32x4GtU`, `kArmI32x4GeU`)
     - 点积 (`kArmI32x4DotI16x8S`, `kArmI16x8DotI8x16S`, `kArmI32x4DotI8x16AddS`)
     - 提取 (`kArmI32x4ExtractLane`, `kArmI16x8ExtractLaneU`, `kArmI16x8ExtractLaneS`)

**关于 .tq 后缀和 JavaScript 关系：**

*   `v8/src/compiler/backend/arm/code-generator-arm.cc` **不是**以 `.tq` 结尾，因此它不是 v8 Torque 源代码。Torque 是一种用于定义 V8 内部 Built-in 函数的 DSL。

*   虽然这个 C++ 文件本身不是 JavaScript 代码，但它生成的机器码 **直接对应于 JavaScript 的功能**。 例如：
    *   `kArmFloat32Min` 和 `kArmFloat64Min` 实现了 JavaScript 中的 `Math.min()` 函数。
    *   大量的 SIMD 指令支持了 JavaScript 中的 `TypedArrays` 和 WebAssembly 的 SIMD 功能，允许 JavaScript 代码进行高性能的并行数据处理。

**JavaScript 示例 (与浮点数最小值操作相关):**

```javascript
// JavaScript 中的 Math.min() 函数
let a = 5.2;
let b = 3.8;
let min_val = Math.min(a, b); // min_val 将会是 3.8

// 对应的，v8/src/compiler/backend/arm/code-generator-arm.cc 中的 kArmFloat64Min
// 或 kArmFloat32Min 会生成相应的 ARM 指令来完成这个计算。
```

**代码逻辑推理示例 (以 `kArmFloat64Min` 为例):**

**假设输入:**

*   `i.InputDoubleRegister(0)` (左操作数) 包含双精度浮点数 `7.5`.
*   `i.InputDoubleRegister(1)` (右操作数) 包含双精度浮点数 `2.1`.

**输出:**

*   `i.OutputDoubleRegister()` (结果寄存器) 将包含双精度浮点数 `2.1`.

**代码逻辑:**

1. 代码首先检查左操作数和右操作数是否相同 (`left == right`)。在这个例子中，它们不相同。
2. 创建一个 `OutOfLineFloat64Min` 对象来处理可能出现的 NaN 情况。
3. 执行 ARM 的浮点数最小值指令 `__ FloatMin(result, left, right, ool->entry())`，将 `left` 和 `right` 中的较小值存入 `result` 寄存器。如果涉及到 NaN，则跳转到 `ool->entry()` 标签指向的代码。
4. 执行 `__ bind(ool->exit())`，将控制流绑定回正常流程。

**用户常见的编程错误示例 (与栈操作相关):**

```c++
// 错误示例：栈溢出
case kArmPush: {
  int stack_decrement = i.InputInt32(0);
  // 错误地分配了过小的栈空间，假设 slots 比实际需要的少
  int slots = 1;
  __ AllocateStackSpace(slots * kSystemPointerSize);
  // ... 实际推送了比 slots 更多的数据
  __ push(i.InputRegister(1));
  frame_access_state()->IncreaseSPDelta(stack_decrement / kSystemPointerSize);
  DCHECK_EQ(LeaveCC, i.OutputSBit());
  break;
}
```

**错误说明:** 用户可能错误地计算了需要压入栈的数据量，导致 `AllocateStackSpace` 分配的空间不足。后续的 `push` 操作会覆盖栈上的其他数据，导致程序崩溃或产生未定义的行为。

**总结：**

这部分 `v8/src/compiler/backend/arm/code-generator-arm.cc` 代码是 V8 编译器后端中非常重要的一部分，它负责将中间表示的指令转换为实际的 ARM 机器码。  它涵盖了浮点数运算、栈操作以及大量的 SIMD 指令，这些指令直接支撑了 JavaScript 中相应的语言特性和性能优化。 这部分代码的正确性和效率对于 V8 引擎的整体性能至关重要。

Prompt: 
```
这是目录为v8/src/compiler/backend/arm/code-generator-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/arm/code-generator-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能

"""
putFloatRegister();
      SwVfpRegister left = i.InputFloatRegister(0);
      SwVfpRegister right = i.InputFloatRegister(1);
      if (left == right) {
        __ Move(result, left);
      } else {
        auto ool = zone()->New<OutOfLineFloat32Min>(this, result, left, right);
        __ FloatMin(result, left, right, ool->entry());
        __ bind(ool->exit());
      }
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmFloat64Min: {
      DwVfpRegister result = i.OutputDoubleRegister();
      DwVfpRegister left = i.InputDoubleRegister(0);
      DwVfpRegister right = i.InputDoubleRegister(1);
      if (left == right) {
        __ Move(result, left);
      } else {
        auto ool = zone()->New<OutOfLineFloat64Min>(this, result, left, right);
        __ FloatMin(result, left, right, ool->entry());
        __ bind(ool->exit());
      }
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmFloat64SilenceNaN: {
      DwVfpRegister value = i.InputDoubleRegister(0);
      DwVfpRegister result = i.OutputDoubleRegister();
      __ VFPCanonicalizeNaN(result, value);
      break;
    }
    case kArmPush: {
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
          __ vpush(i.InputFloatRegister(1));
          break;
        case MachineRepresentation::kFloat64:
          __ vpush(i.InputDoubleRegister(1));
          break;
        case MachineRepresentation::kSimd128:
          __ vpush(i.InputSimd128Register(1));
          break;
        default:
          __ push(i.InputRegister(1));
          break;
      }
      frame_access_state()->IncreaseSPDelta(slots);
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmPoke: {
      int const slot = MiscField::decode(instr->opcode());
      __ str(i.InputRegister(0), MemOperand(sp, slot * kSystemPointerSize));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmPeek: {
      int reverse_slot = i.InputInt32(0);
      int offset =
          FrameSlotToFPOffset(frame()->GetTotalFrameSlotCount() - reverse_slot);
      if (instr->OutputAt(0)->IsFPRegister()) {
        LocationOperand* op = LocationOperand::cast(instr->OutputAt(0));
        if (op->representation() == MachineRepresentation::kFloat64) {
          __ vldr(i.OutputDoubleRegister(), MemOperand(fp, offset));
        } else if (op->representation() == MachineRepresentation::kFloat32) {
          __ vldr(i.OutputFloatRegister(), MemOperand(fp, offset));
        } else {
          DCHECK_EQ(MachineRepresentation::kSimd128, op->representation());
          UseScratchRegisterScope temps(masm());
          Register scratch = temps.Acquire();
          __ add(scratch, fp, Operand(offset));
          __ vld1(Neon8, NeonListOperand(i.OutputSimd128Register()),
                  NeonMemOperand(scratch));
        }
      } else {
        __ ldr(i.OutputRegister(), MemOperand(fp, offset));
      }
      break;
    }
    case kArmDmbIsh: {
      __ dmb(ISH);
      break;
    }
    case kArmDsbIsb: {
      __ dsb(SY);
      __ isb(SY);
      break;
    }
    case kArmVmullLow: {
      auto dt = static_cast<NeonDataType>(MiscField::decode(instr->opcode()));
      __ vmull(dt, i.OutputSimd128Register(), i.InputSimd128Register(0).low(),
               i.InputSimd128Register(1).low());
      break;
    }
    case kArmVmullHigh: {
      auto dt = static_cast<NeonDataType>(MiscField::decode(instr->opcode()));
      __ vmull(dt, i.OutputSimd128Register(), i.InputSimd128Register(0).high(),
               i.InputSimd128Register(1).high());
      break;
    }
    case kArmVpadal: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      auto dt = static_cast<NeonDataType>(MiscField::decode(instr->opcode()));
      __ vpadal(dt, i.OutputSimd128Register(), i.InputSimd128Register(1));
      break;
    }
    case kArmVpaddl: {
      auto dt = static_cast<NeonDataType>(MiscField::decode(instr->opcode()));
      __ vpaddl(dt, i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmF64x2Splat: {
      Simd128Register dst = i.OutputSimd128Register();
      DoubleRegister src = i.InputDoubleRegister(0);
      __ Move(dst.low(), src);
      __ Move(dst.high(), src);
      break;
    }
    case kArmF64x2ExtractLane: {
      __ ExtractLane(i.OutputDoubleRegister(), i.InputSimd128Register(0),
                     i.InputInt8(1));
      break;
    }
    case kArmF64x2ReplaceLane: {
      __ ReplaceLane(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputDoubleRegister(2), i.InputInt8(1));
      break;
    }
    case kArmF64x2Abs: {
      __ vabs(i.OutputSimd128Register().low(), i.InputSimd128Register(0).low());
      __ vabs(i.OutputSimd128Register().high(),
              i.InputSimd128Register(0).high());
      break;
    }
    case kArmF64x2Neg: {
      __ vneg(i.OutputSimd128Register().low(), i.InputSimd128Register(0).low());
      __ vneg(i.OutputSimd128Register().high(),
              i.InputSimd128Register(0).high());
      break;
    }
    case kArmF64x2Sqrt: {
      __ vsqrt(i.OutputSimd128Register().low(),
               i.InputSimd128Register(0).low());
      __ vsqrt(i.OutputSimd128Register().high(),
               i.InputSimd128Register(0).high());
      break;
    }
    case kArmF64x2Add: {
      ASSEMBLE_F64X2_ARITHMETIC_BINOP(vadd);
      break;
    }
    case kArmF64x2Sub: {
      ASSEMBLE_F64X2_ARITHMETIC_BINOP(vsub);
      break;
    }
    case kArmF64x2Mul: {
      ASSEMBLE_F64X2_ARITHMETIC_BINOP(vmul);
      break;
    }
    case kArmF64x2Div: {
      ASSEMBLE_F64X2_ARITHMETIC_BINOP(vdiv);
      break;
    }
    case kArmF64x2Min: {
      Simd128Register result = i.OutputSimd128Register();
      Simd128Register left = i.InputSimd128Register(0);
      Simd128Register right = i.InputSimd128Register(1);
      if (left == right) {
        __ Move(result, left);
      } else {
        auto ool_low = zone()->New<OutOfLineFloat64Min>(
            this, result.low(), left.low(), right.low());
        auto ool_high = zone()->New<OutOfLineFloat64Min>(
            this, result.high(), left.high(), right.high());
        __ FloatMin(result.low(), left.low(), right.low(), ool_low->entry());
        __ bind(ool_low->exit());
        __ FloatMin(result.high(), left.high(), right.high(),
                    ool_high->entry());
        __ bind(ool_high->exit());
      }
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmF64x2Max: {
      Simd128Register result = i.OutputSimd128Register();
      Simd128Register left = i.InputSimd128Register(0);
      Simd128Register right = i.InputSimd128Register(1);
      if (left == right) {
        __ Move(result, left);
      } else {
        auto ool_low = zone()->New<OutOfLineFloat64Max>(
            this, result.low(), left.low(), right.low());
        auto ool_high = zone()->New<OutOfLineFloat64Max>(
            this, result.high(), left.high(), right.high());
        __ FloatMax(result.low(), left.low(), right.low(), ool_low->entry());
        __ bind(ool_low->exit());
        __ FloatMax(result.high(), left.high(), right.high(),
                    ool_high->entry());
        __ bind(ool_high->exit());
      }
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
#undef ASSEMBLE_F64X2_ARITHMETIC_BINOP
    case kArmF64x2Eq: {
      UseScratchRegisterScope temps(masm());
      Register scratch = temps.Acquire();
      __ mov(scratch, Operand(0));
      __ VFPCompareAndSetFlags(i.InputSimd128Register(0).low(),
                               i.InputSimd128Register(1).low());
      __ mov(scratch, Operand(-1), LeaveCC, eq);
      __ vmov(i.OutputSimd128Register().low(), scratch, scratch);

      __ mov(scratch, Operand(0));
      __ VFPCompareAndSetFlags(i.InputSimd128Register(0).high(),
                               i.InputSimd128Register(1).high());
      __ mov(scratch, Operand(-1), LeaveCC, eq);
      __ vmov(i.OutputSimd128Register().high(), scratch, scratch);
      break;
    }
    case kArmF64x2Ne: {
      UseScratchRegisterScope temps(masm());
      Register scratch = temps.Acquire();
      __ mov(scratch, Operand(0));
      __ VFPCompareAndSetFlags(i.InputSimd128Register(0).low(),
                               i.InputSimd128Register(1).low());
      __ mov(scratch, Operand(-1), LeaveCC, ne);
      __ vmov(i.OutputSimd128Register().low(), scratch, scratch);

      __ mov(scratch, Operand(0));
      __ VFPCompareAndSetFlags(i.InputSimd128Register(0).high(),
                               i.InputSimd128Register(1).high());
      __ mov(scratch, Operand(-1), LeaveCC, ne);
      __ vmov(i.OutputSimd128Register().high(), scratch, scratch);
      break;
    }
    case kArmF64x2Lt: {
      UseScratchRegisterScope temps(masm());
      Register scratch = temps.Acquire();
      __ VFPCompareAndSetFlags(i.InputSimd128Register(0).low(),
                               i.InputSimd128Register(1).low());
      __ mov(scratch, Operand(0), LeaveCC, cs);
      __ mov(scratch, Operand(-1), LeaveCC, mi);
      __ vmov(i.OutputSimd128Register().low(), scratch, scratch);

      __ VFPCompareAndSetFlags(i.InputSimd128Register(0).high(),
                               i.InputSimd128Register(1).high());
      __ mov(scratch, Operand(0), LeaveCC, cs);
      __ mov(scratch, Operand(-1), LeaveCC, mi);
      __ vmov(i.OutputSimd128Register().high(), scratch, scratch);
      break;
    }
    case kArmF64x2Le: {
      UseScratchRegisterScope temps(masm());
      Register scratch = temps.Acquire();
      __ VFPCompareAndSetFlags(i.InputSimd128Register(0).low(),
                               i.InputSimd128Register(1).low());
      __ mov(scratch, Operand(0), LeaveCC, hi);
      __ mov(scratch, Operand(-1), LeaveCC, ls);
      __ vmov(i.OutputSimd128Register().low(), scratch, scratch);

      __ VFPCompareAndSetFlags(i.InputSimd128Register(0).high(),
                               i.InputSimd128Register(1).high());
      __ mov(scratch, Operand(0), LeaveCC, hi);
      __ mov(scratch, Operand(-1), LeaveCC, ls);
      __ vmov(i.OutputSimd128Register().high(), scratch, scratch);
      break;
    }
    case kArmF64x2Pmin: {
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register lhs = i.InputSimd128Register(0);
      Simd128Register rhs = i.InputSimd128Register(1);
      DCHECK_EQ(dst, lhs);

      // Move rhs only when rhs is strictly lesser (mi).
      __ VFPCompareAndSetFlags(rhs.low(), lhs.low());
      __ vmov(dst.low(), rhs.low(), mi);
      __ VFPCompareAndSetFlags(rhs.high(), lhs.high());
      __ vmov(dst.high(), rhs.high(), mi);
      break;
    }
    case kArmF64x2Pmax: {
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register lhs = i.InputSimd128Register(0);
      Simd128Register rhs = i.InputSimd128Register(1);
      DCHECK_EQ(dst, lhs);

      // Move rhs only when rhs is strictly greater (gt).
      __ VFPCompareAndSetFlags(rhs.low(), lhs.low());
      __ vmov(dst.low(), rhs.low(), gt);
      __ VFPCompareAndSetFlags(rhs.high(), lhs.high());
      __ vmov(dst.high(), rhs.high(), gt);
      break;
    }
    case kArmF64x2Qfma: {
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register src0 = i.InputSimd128Register(0);
      Simd128Register src1 = i.InputSimd128Register(1);
      Simd128Register src2 = i.InputSimd128Register(2);
      __ vmul(dst.low(), src0.low(), src1.low());
      __ vmul(dst.high(), src0.high(), src1.high());
      __ vadd(dst.low(), src2.low(), dst.low());
      __ vadd(dst.high(), src2.high(), dst.high());
      break;
    }
    case kArmF64x2Qfms: {
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register src0 = i.InputSimd128Register(0);
      Simd128Register src1 = i.InputSimd128Register(1);
      Simd128Register src2 = i.InputSimd128Register(2);
      __ vmul(dst.low(), src0.low(), src1.low());
      __ vmul(dst.high(), src0.high(), src1.high());
      __ vsub(dst.low(), src2.low(), dst.low());
      __ vsub(dst.high(), src2.high(), dst.high());
      break;
    }
    case kArmF64x2Ceil: {
      CpuFeatureScope scope(masm(), ARMv8);
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register src = i.InputSimd128Register(0);
      __ vrintp(dst.low(), src.low());
      __ vrintp(dst.high(), src.high());
      break;
    }
    case kArmF64x2Floor: {
      CpuFeatureScope scope(masm(), ARMv8);
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register src = i.InputSimd128Register(0);
      __ vrintm(dst.low(), src.low());
      __ vrintm(dst.high(), src.high());
      break;
    }
    case kArmF64x2Trunc: {
      CpuFeatureScope scope(masm(), ARMv8);
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register src = i.InputSimd128Register(0);
      __ vrintz(dst.low(), src.low());
      __ vrintz(dst.high(), src.high());
      break;
    }
    case kArmF64x2NearestInt: {
      CpuFeatureScope scope(masm(), ARMv8);
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register src = i.InputSimd128Register(0);
      __ vrintn(dst.low(), src.low());
      __ vrintn(dst.high(), src.high());
      break;
    }
    case kArmF64x2ConvertLowI32x4S: {
      __ F64x2ConvertLowI32x4S(i.OutputSimd128Register(),
                               i.InputSimd128Register(0));
      break;
    }
    case kArmF64x2ConvertLowI32x4U: {
      __ F64x2ConvertLowI32x4U(i.OutputSimd128Register(),
                               i.InputSimd128Register(0));
      break;
    }
    case kArmF64x2PromoteLowF32x4: {
      __ F64x2PromoteLowF32x4(i.OutputSimd128Register(),
                              i.InputSimd128Register(0));
      break;
    }
    case kArmI64x2SplatI32Pair: {
      Simd128Register dst = i.OutputSimd128Register();
      __ vdup(Neon32, dst, i.InputRegister(0));
      __ ReplaceLane(dst, dst, i.InputRegister(1), NeonS32, 1);
      __ ReplaceLane(dst, dst, i.InputRegister(1), NeonS32, 3);
      break;
    }
    case kArmI64x2ReplaceLaneI32Pair: {
      Simd128Register dst = i.OutputSimd128Register();
      int8_t lane = i.InputInt8(1);
      __ ReplaceLane(dst, dst, i.InputRegister(2), NeonS32, lane * 2);
      __ ReplaceLane(dst, dst, i.InputRegister(3), NeonS32, lane * 2 + 1);
      break;
    }
    case kArmI64x2Add: {
      __ vadd(Neon64, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI64x2Sub: {
      __ vsub(Neon64, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI64x2Mul: {
      UseScratchRegisterScope temps(masm());
      QwNeonRegister dst = i.OutputSimd128Register();
      QwNeonRegister left = i.InputSimd128Register(0);
      QwNeonRegister right = i.InputSimd128Register(1);
      QwNeonRegister tmp1 = i.TempSimd128Register(0);
      QwNeonRegister tmp2 = temps.AcquireQ();

      // This algorithm uses vector operations to perform 64-bit integer
      // multiplication by splitting it into a high and low 32-bit integers.
      // The tricky part is getting the low and high integers in the correct
      // place inside a NEON register, so that we can use as little vmull and
      // vmlal as possible.

      // Move left and right into temporaries, they will be modified by vtrn.
      __ vmov(tmp1, left);
      __ vmov(tmp2, right);

      // This diagram shows how the 64-bit integers fit into NEON registers.
      //
      //             [q.high()| q.low()]
      // left/tmp1:  [ a3, a2 | a1, a0 ]
      // right/tmp2: [ b3, b2 | b1, b0 ]
      //
      // We want to multiply the low 32 bits of left with high 32 bits of right,
      // for each lane, i.e. a2 * b3, a0 * b1. However, vmull takes two input d
      // registers, and multiply the corresponding low/high 32 bits, to get a
      // 64-bit integer: a1 * b1, a0 * b0. In order to make it work we transpose
      // the vectors, so that we get the low 32 bits of each 64-bit integer into
      // the same lane, similarly for high 32 bits.
      __ vtrn(Neon32, tmp1.low(), tmp1.high());
      // tmp1: [ a3, a1 | a2, a0 ]
      __ vtrn(Neon32, tmp2.low(), tmp2.high());
      // tmp2: [ b3, b1 | b2, b0 ]

      __ vmull(NeonU32, dst, tmp1.low(), tmp2.high());
      // dst: [ a2*b3 | a0*b1 ]
      __ vmlal(NeonU32, dst, tmp1.high(), tmp2.low());
      // dst: [ a2*b3 + a3*b2 | a0*b1 + a1*b0 ]
      __ vshl(NeonU64, dst, dst, 32);
      // dst: [ (a2*b3 + a3*b2) << 32 | (a0*b1 + a1*b0) << 32 ]

      __ vmlal(NeonU32, dst, tmp1.low(), tmp2.low());
      // dst: [ (a2*b3 + a3*b2)<<32 + (a2*b2) | (a0*b1 + a1*b0)<<32 + (a0*b0) ]
      break;
    }
    case kArmI64x2Abs: {
      __ I64x2Abs(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmI64x2Neg: {
      Simd128Register dst = i.OutputSimd128Register();
      __ vmov(dst, uint64_t{0});
      __ vsub(Neon64, dst, dst, i.InputSimd128Register(0));
      break;
    }
    case kArmI64x2Shl: {
      ASSEMBLE_SIMD_SHIFT_LEFT(vshl, 6, Neon32, NeonS64);
      break;
    }
    case kArmI64x2ShrS: {
      // Only the least significant byte of each lane is used, so we can use
      // Neon32 as the size.
      ASSEMBLE_SIMD_SHIFT_RIGHT(vshr, 6, Neon32, NeonS64);
      break;
    }
    case kArmI64x2ShrU: {
      // Only the least significant byte of each lane is used, so we can use
      // Neon32 as the size.
      ASSEMBLE_SIMD_SHIFT_RIGHT(vshr, 6, Neon32, NeonU64);
      break;
    }
    case kArmI64x2BitMask: {
      __ I64x2BitMask(i.OutputRegister(), i.InputSimd128Register(0));
      break;
    }
    case kArmI64x2SConvertI32x4Low: {
      __ vmovl(NeonS32, i.OutputSimd128Register(),
               i.InputSimd128Register(0).low());
      break;
    }
    case kArmI64x2SConvertI32x4High: {
      __ vmovl(NeonS32, i.OutputSimd128Register(),
               i.InputSimd128Register(0).high());
      break;
    }
    case kArmI64x2UConvertI32x4Low: {
      __ vmovl(NeonU32, i.OutputSimd128Register(),
               i.InputSimd128Register(0).low());
      break;
    }
    case kArmI64x2UConvertI32x4High: {
      __ vmovl(NeonU32, i.OutputSimd128Register(),
               i.InputSimd128Register(0).high());
      break;
    }
    case kArmF32x4Splat: {
      int src_code = i.InputFloatRegister(0).code();
      __ vdup(Neon32, i.OutputSimd128Register(),
              DwVfpRegister::from_code(src_code / 2), src_code % 2);
      break;
    }
    case kArmF32x4ExtractLane: {
      __ ExtractLane(i.OutputFloatRegister(), i.InputSimd128Register(0),
                     i.InputInt8(1));
      break;
    }
    case kArmF32x4ReplaceLane: {
      __ ReplaceLane(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputFloatRegister(2), i.InputInt8(1));
      break;
    }
    case kArmF32x4SConvertI32x4: {
      __ vcvt_f32_s32(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmF32x4UConvertI32x4: {
      __ vcvt_f32_u32(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmF32x4Abs: {
      __ vabs(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmF32x4Neg: {
      __ vneg(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmF32x4Sqrt: {
      QwNeonRegister dst = i.OutputSimd128Register();
      QwNeonRegister src1 = i.InputSimd128Register(0);
      DCHECK_EQ(dst, q0);
      DCHECK_EQ(src1, q0);
#define S_FROM_Q(reg, lane) SwVfpRegister::from_code(reg.code() * 4 + lane)
      __ vsqrt(S_FROM_Q(dst, 0), S_FROM_Q(src1, 0));
      __ vsqrt(S_FROM_Q(dst, 1), S_FROM_Q(src1, 1));
      __ vsqrt(S_FROM_Q(dst, 2), S_FROM_Q(src1, 2));
      __ vsqrt(S_FROM_Q(dst, 3), S_FROM_Q(src1, 3));
#undef S_FROM_Q
      break;
    }
    case kArmF32x4Add: {
      __ vadd(i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmF32x4Sub: {
      __ vsub(i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmF32x4Mul: {
      __ vmul(i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmF32x4Div: {
      QwNeonRegister dst = i.OutputSimd128Register();
      QwNeonRegister src1 = i.InputSimd128Register(0);
      QwNeonRegister src2 = i.InputSimd128Register(1);
      DCHECK_EQ(dst, q0);
      DCHECK_EQ(src1, q0);
      DCHECK_EQ(src2, q1);
#define S_FROM_Q(reg, lane) SwVfpRegister::from_code(reg.code() * 4 + lane)
      __ vdiv(S_FROM_Q(dst, 0), S_FROM_Q(src1, 0), S_FROM_Q(src2, 0));
      __ vdiv(S_FROM_Q(dst, 1), S_FROM_Q(src1, 1), S_FROM_Q(src2, 1));
      __ vdiv(S_FROM_Q(dst, 2), S_FROM_Q(src1, 2), S_FROM_Q(src2, 2));
      __ vdiv(S_FROM_Q(dst, 3), S_FROM_Q(src1, 3), S_FROM_Q(src2, 3));
#undef S_FROM_Q
      break;
    }
    case kArmF32x4Min: {
      __ vmin(i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmF32x4Max: {
      __ vmax(i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmF32x4Eq: {
      __ vceq(i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmF32x4Ne: {
      Simd128Register dst = i.OutputSimd128Register();
      __ vceq(dst, i.InputSimd128Register(0), i.InputSimd128Register(1));
      __ vmvn(dst, dst);
      break;
    }
    case kArmF32x4Lt: {
      __ vcgt(i.OutputSimd128Register(), i.InputSimd128Register(1),
              i.InputSimd128Register(0));
      break;
    }
    case kArmF32x4Le: {
      __ vcge(i.OutputSimd128Register(), i.InputSimd128Register(1),
              i.InputSimd128Register(0));
      break;
    }
    case kArmF32x4Pmin: {
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register lhs = i.InputSimd128Register(0);
      Simd128Register rhs = i.InputSimd128Register(1);
      DCHECK_NE(dst, lhs);
      DCHECK_NE(dst, rhs);

      // f32x4.pmin(lhs, rhs)
      // = v128.bitselect(rhs, lhs, f32x4.lt(rhs, lhs))
      // = v128.bitselect(rhs, lhs, f32x4.gt(lhs, rhs))
      __ vcgt(dst, lhs, rhs);
      __ vbsl(dst, rhs, lhs);
      break;
    }
    case kArmF32x4Pmax: {
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register lhs = i.InputSimd128Register(0);
      Simd128Register rhs = i.InputSimd128Register(1);
      DCHECK_NE(dst, lhs);
      DCHECK_NE(dst, rhs);

      // f32x4.pmax(lhs, rhs)
      // = v128.bitselect(rhs, lhs, f32x4.gt(rhs, lhs))
      __ vcgt(dst, rhs, lhs);
      __ vbsl(dst, rhs, lhs);
      break;
    }
    case kArmF32x4Qfma: {
      Simd128Register dst = i.OutputSimd128Register();
      __ vmul(dst, i.InputSimd128Register(0), i.InputSimd128Register(1));
      __ vadd(dst, i.InputSimd128Register(2), dst);
      break;
    }
    case kArmF32x4Qfms: {
      Simd128Register dst = i.OutputSimd128Register();
      __ vmul(dst, i.InputSimd128Register(0), i.InputSimd128Register(1));
      __ vsub(dst, i.InputSimd128Register(2), dst);
      break;
    }
    case kArmF32x4DemoteF64x2Zero: {
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register src = i.InputSimd128Register(0);
      __ vcvt_f32_f64(SwVfpRegister::from_code(dst.code() * 4), src.low());
      __ vcvt_f32_f64(SwVfpRegister::from_code(dst.code() * 4 + 1), src.high());
      __ vmov(dst.high(), 0);
      break;
    }
    case kArmI32x4Splat: {
      __ vdup(Neon32, i.OutputSimd128Register(), i.InputRegister(0));
      break;
    }
    case kArmI32x4ExtractLane: {
      __ ExtractLane(i.OutputRegister(), i.InputSimd128Register(0), NeonS32,
                     i.InputInt8(1));
      break;
    }
    case kArmI32x4ReplaceLane: {
      __ ReplaceLane(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputRegister(2), NeonS32, i.InputInt8(1));
      break;
    }
    case kArmI32x4SConvertF32x4: {
      __ vcvt_s32_f32(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmI32x4SConvertI16x8Low: {
      __ vmovl(NeonS16, i.OutputSimd128Register(),
               i.InputSimd128Register(0).low());
      break;
    }
    case kArmI32x4SConvertI16x8High: {
      __ vmovl(NeonS16, i.OutputSimd128Register(),
               i.InputSimd128Register(0).high());
      break;
    }
    case kArmI32x4Neg: {
      __ vneg(Neon32, i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmI32x4Shl: {
      ASSEMBLE_SIMD_SHIFT_LEFT(vshl, 5, Neon32, NeonS32);
      break;
    }
    case kArmI32x4ShrS: {
      ASSEMBLE_SIMD_SHIFT_RIGHT(vshr, 5, Neon32, NeonS32);
      break;
    }
    case kArmI32x4Add: {
      __ vadd(Neon32, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI32x4Sub: {
      __ vsub(Neon32, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI32x4Mul: {
      __ vmul(Neon32, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI32x4MinS: {
      __ vmin(NeonS32, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI32x4MaxS: {
      __ vmax(NeonS32, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI64x2Eq: {
      __ I64x2Eq(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputSimd128Register(1));
      break;
    }
    case kArmI64x2Ne: {
      __ I64x2Ne(i.OutputSimd128Register(), i.InputSimd128Register(0),
                 i.InputSimd128Register(1));
      break;
    }
    case kArmI64x2GtS: {
      __ I64x2GtS(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kArmI64x2GeS: {
      __ I64x2GeS(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kArmI32x4Eq: {
      __ vceq(Neon32, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI32x4Ne: {
      Simd128Register dst = i.OutputSimd128Register();
      __ vceq(Neon32, dst, i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      __ vmvn(dst, dst);
      break;
    }
    case kArmI32x4GtS: {
      __ vcgt(NeonS32, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI32x4GeS: {
      __ vcge(NeonS32, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI32x4UConvertF32x4: {
      __ vcvt_u32_f32(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmI32x4UConvertI16x8Low: {
      __ vmovl(NeonU16, i.OutputSimd128Register(),
               i.InputSimd128Register(0).low());
      break;
    }
    case kArmI32x4UConvertI16x8High: {
      __ vmovl(NeonU16, i.OutputSimd128Register(),
               i.InputSimd128Register(0).high());
      break;
    }
    case kArmI32x4ShrU: {
      ASSEMBLE_SIMD_SHIFT_RIGHT(vshr, 5, Neon32, NeonU32);
      break;
    }
    case kArmI32x4MinU: {
      __ vmin(NeonU32, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI32x4MaxU: {
      __ vmax(NeonU32, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI32x4GtU: {
      __ vcgt(NeonU32, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI32x4GeU: {
      __ vcge(NeonU32, i.OutputSimd128Register(), i.InputSimd128Register(0),
              i.InputSimd128Register(1));
      break;
    }
    case kArmI32x4Abs: {
      __ vabs(Neon32, i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmI32x4BitMask: {
      Register dst = i.OutputRegister();
      UseScratchRegisterScope temps(masm());
      Simd128Register src = i.InputSimd128Register(0);
      Simd128Register tmp = temps.AcquireQ();
      Simd128Register mask = i.TempSimd128Register(0);

      __ vshr(NeonS32, tmp, src, 31);
      // Set i-th bit of each lane i. When AND with tmp, the lanes that
      // are signed will have i-th bit set, unsigned will be 0.
      __ vmov(mask.low(), base::Double(uint64_t{0x0000'0002'0000'0001}));
      __ vmov(mask.high(), base::Double(uint64_t{0x0000'0008'0000'0004}));
      __ vand(tmp, mask, tmp);
      __ vpadd(Neon32, tmp.low(), tmp.low(), tmp.high());
      __ vpadd(Neon32, tmp.low(), tmp.low(), kDoubleRegZero);
      __ VmovLow(dst, tmp.low());
      break;
    }
    case kArmI32x4DotI16x8S: {
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register lhs = i.InputSimd128Register(0);
      Simd128Register rhs = i.InputSimd128Register(1);
      UseScratchRegisterScope temps(masm());
      Simd128Register scratch = temps.AcquireQ();
      __ vmull(NeonS16, scratch, lhs.low(), rhs.low());
      __ vpadd(Neon32, dst.low(), scratch.low(), scratch.high());
      __ vmull(NeonS16, scratch, lhs.high(), rhs.high());
      __ vpadd(Neon32, dst.high(), scratch.low(), scratch.high());
      break;
    }
    case kArmI16x8DotI8x16S: {
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register lhs = i.InputSimd128Register(0);
      Simd128Register rhs = i.InputSimd128Register(1);
      UseScratchRegisterScope temps(masm());
      Simd128Register scratch = temps.AcquireQ();
      __ vmull(NeonS8, scratch, lhs.low(), rhs.low());
      __ vpadd(Neon16, dst.low(), scratch.low(), scratch.high());
      __ vmull(NeonS8, scratch, lhs.high(), rhs.high());
      __ vpadd(Neon16, dst.high(), scratch.low(), scratch.high());
      break;
    }
    case kArmI32x4DotI8x16AddS: {
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register lhs = i.InputSimd128Register(0);
      Simd128Register rhs = i.InputSimd128Register(1);
      Simd128Register tmp1 = i.TempSimd128Register(0);
      DCHECK_EQ(dst, i.InputSimd128Register(2));
      UseScratchRegisterScope temps(masm());
      Simd128Register scratch = temps.AcquireQ();
      __ vmull(NeonS8, scratch, lhs.low(), rhs.low());
      __ vpadd(Neon16, tmp1.low(), scratch.low(), scratch.high());
      __ vmull(NeonS8, scratch, lhs.high(), rhs.high());
      __ vpadd(Neon16, tmp1.high(), scratch.low(), scratch.high());
      __ vpadal(NeonS16, dst, tmp1);
      break;
    }
    case kArmI32x4TruncSatF64x2SZero: {
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register src = i.InputSimd128Register(0);
      __ vcvt_s32_f64(SwVfpRegister::from_code(dst.code() * 4), src.low());
      __ vcvt_s32_f64(SwVfpRegister::from_code(dst.code() * 4 + 1), src.high());
      __ vmov(dst.high(), 0);
      break;
    }
    case kArmI32x4TruncSatF64x2UZero: {
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register src = i.InputSimd128Register(0);
      __ vcvt_u32_f64(SwVfpRegister::from_code(dst.code() * 4), src.low());
      __ vcvt_u32_f64(SwVfpRegister::from_code(dst.code() * 4 + 1), src.high());
      __ vmov(dst.high(), 0);
      break;
    }
    case kArmI16x8Splat: {
      __ vdup(Neon16, i.OutputSimd128Register(), i.InputRegister(0));
      break;
    }
    case kArmI16x8ExtractLaneU: {
      __ ExtractLane(i.OutputRegister(), i.InputSimd128Register(0), NeonU16,
                     i.InputInt8(1));
      break;
    }
    case kArmI16x8ExtractLaneS: {
      __ ExtractLane(i.OutputRegister(), i.InputSimd128Register(0), NeonS16,
                     i.InputInt8(1));
      break;
    }
    case kArmI16x8ReplaceLane: {
      __ ReplaceLane(i.OutputSimd128
"""


```