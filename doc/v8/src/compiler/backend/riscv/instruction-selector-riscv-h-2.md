Response:
The user is asking for a summary of the functionality of the provided C++ header file.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Purpose:** The file name `instruction-selector-riscv.h` and the namespace `v8::internal::compiler::riscv` strongly suggest this file is responsible for instruction selection for the RISC-V architecture within the V8 JavaScript engine's compiler. Instruction selection is the process of mapping high-level intermediate representation (IR) operations to specific machine instructions.

2. **Scan for Key Class:**  The code defines a class template `InstructionSelectorT`. This is the central element, and most of the functionality is encapsulated within its methods. The `<typename Adapter>` indicates it's designed to work with different compiler phases or contexts.

3. **Analyze `Visit...` Methods:** The numerous methods starting with `Visit` are crucial. These methods correspond to different types of operations in the compiler's IR (e.g., `VisitF32x4Min`, `VisitI32x4SConvertI16x8Low`, `VisitWord32Clz`). Each `Visit` method takes a `node_t` as input, which likely represents a node in the IR graph. These methods are the core of the instruction selection process, handling specific operations.

4. **Examine the Operations:** The names of the `Visit` methods provide insights into the operations being handled:
    * **SIMD Operations:**  Methods like `VisitF32x4Min`, `VisitI32x4DotI16x8S`, and `VisitI8x16Shuffle` clearly deal with SIMD (Single Instruction, Multiple Data) instructions, common for vector processing and performance optimization.
    * **Data Type Conversions:**  Methods like `VisitI32x4SConvertI16x8Low` and `VisitSignExtendWord8ToInt32` handle conversions between different data types.
    * **Bitwise Operations:** `VisitWord32Clz` and `VisitWord32Ctz` handle bit manipulation instructions.
    * **Floating-Point Operations:** `VisitF64x2Eq`, `VisitF32x4Pmin` deal with floating-point comparisons and min/max operations.
    * **Special Instructions:** `VisitSetStackPointer` indicates handling of architecture-specific operations.

5. **Look for Supporting Classes/Types:** The `RiscvOperandGeneratorT` class is used extensively within the `Visit` methods. This class likely handles the generation of operands (registers, immediates) for the RISC-V instructions. The `InstructionOperand` type represents these operands.

6. **Identify Emitted Instructions:** The `this->Emit(...)` calls within the `Visit` methods are the actual point where RISC-V instructions are generated. The first argument to `Emit` (e.g., `kRiscvVmv`, `kRiscvVfminVv`) represents the opcode of the RISC-V instruction.

7. **Infer Functionality:** Based on the above observations, the primary function of the file is to define how different high-level operations are translated into concrete RISC-V machine instructions. This involves:
    * Identifying the type of operation.
    * Generating the necessary operands.
    * Emitting the appropriate RISC-V instruction.

8. **Check for `.tq` Extension:** The prompt mentions checking for a `.tq` extension, indicating Torque code. The provided code doesn't have this extension, so it's standard C++.

9. **Relate to JavaScript:**  The operations handled (SIMD, data conversions, etc.) are directly related to JavaScript features, especially when dealing with typed arrays, WebAssembly, and performance-critical code.

10. **Consider Code Logic and Examples:** The `Visit` methods contain specific logic for handling each operation, often involving sequences of RISC-V instructions. For example, the `VisitF32x4Min` method uses multiple instructions to handle potential NaN values correctly. Thinking about potential JavaScript code that would trigger these operations helps illustrate the connection.

11. **Think About Common Errors:**  Instruction selection needs to be correct. A common error would be incorrect mapping of IR operations to instructions, leading to wrong results or crashes. Another error could be incorrect operand generation.

12. **Synthesize the Summary:** Combine the findings into a concise summary covering the main purpose, key functionalities, and connection to JavaScript. Address the specific points raised in the prompt (Torque, JavaScript examples, etc.). Since this is part 3, reiterate the overall function based on the detailed analysis.
这是v8源代码文件 `v8/src/compiler/backend/riscv/instruction-selector-riscv.h` 的第三部分，延续了前两部分的内容，主要功能是 **为 RISC-V 架构选择合适的机器指令**，将 V8 编译器生成的中间表示（IR）节点转换为具体的 RISC-V 汇编指令。

**归纳一下它的功能：**

结合前两部分，这个头文件定义了 `InstructionSelectorT` 模板类，专门用于 RISC-V 架构的指令选择。其核心功能是实现各种 `Visit` 方法，每个方法对应一种特定的 IR 节点类型，并负责生成相应的 RISC-V 指令序列。

**具体来说，这部分代码的功能集中在处理 SIMD (Single Instruction, Multiple Data) 相关的操作，特别是：**

* **浮点 SIMD 比较操作:**  例如 `VisitF64x2Eq`, `VisitF64x2Ne`, `VisitF32x4Lt`, `VisitF32x4Le` 等，用于比较 SIMD 向量中的浮点数元素，并生成相应的 RISC-V 向量比较指令 (`kRiscvVmfeqVv`, `kRiscvVmfneVv`, `kRiscvVmfltVv`, `kRiscvVmfleVv`)。
* **SIMD 数据类型转换操作:** 例如 `VisitI32x4SConvertI16x8Low`, `VisitI16x8SConvertI8x16High` 等，用于在不同大小和类型的 SIMD 向量之间进行转换，并生成 RISC-V 的向量扩展、截断等指令 (`kRiscvVsextVf2`, `kRiscvVzextVf2`, `kRiscvVnclip`, `kRiscvVnclipu`)。
* **SIMD 平均值计算:** 例如 `VisitI8x16RoundingAverageU`, `VisitI16x8RoundingAverageU`，实现了 SIMD 向量的平均值计算，并使用了 RISC-V 的向量加法、移位和截断指令。
* **SIMD 点积运算:** 例如 `VisitI32x4DotI16x8S`, `VisitI16x8DotI8x16I7x16S`, `VisitI32x4DotI8x16I7x16AddS`，实现了 SIMD 向量的点积运算，并使用了 RISC-V 的向量乘法、压缩和加法指令。
* **SIMD 洗牌 (Shuffle) 和 Swizzle 操作:** `VisitI8x16Shuffle` 和 `VisitI8x16Swizzle` 用于重新排列 SIMD 向量中的元素，并生成相应的 RISC-V 指令 (`kRiscvI8x16Shuffle`, `kRiscvVrgather`)。
* **SIMD 位掩码操作:** 例如 `VisitI64x2BitMask`, `VisitI32x4BitMask` 等，用于生成 SIMD 向量的位掩码，并使用 RISC-V 的向量比较和移动指令 (`kRiscvVmslt`, `kRiscvVmvXs`)。
* **SIMD 扩展乘法操作:** 例如 `VisitI64x2ExtMulLowI32x4S`, `VisitI32x4ExtMulHighI16x8U` 等，用于计算 SIMD 向量的扩展乘法，结果宽度是输入宽度的两倍，并生成 RISC-V 的向量乘法和滑动指令 (`kRiscvVwmul`, `kRiscvVwmulu`, `kRiscvVslidedown`).
* **SIMD 成对的最小值/最大值操作:** `VisitF32x4Pmin`, `VisitF32x4Pmax`, `VisitF64x2Pmin`, `VisitF64x2Pmax`，用于计算 SIMD 向量中相邻元素的最小值或最大值。

**如果 `v8/src/compiler/backend/riscv/instruction-selector-riscv.h` 以 `.tq` 结尾，那它是个 v8 torque 源代码。**

但从你提供的代码片段来看，这个文件是标准的 C++ 头文件 (`.h`)，而不是 Torque (`.tq`) 文件。 Torque 是一种 V8 特有的领域特定语言，用于生成高效的 C++ 代码。

**如果它与 javascript 的功能有关系，请用 javascript 举例说明。**

这些 SIMD 操作直接对应 JavaScript 中 `SIMD` API 的功能，例如 `Float32x4`, `Int32x4` 等类型提供的操作：

```javascript
const a = Float32x4(1.0, 2.0, 3.0, 4.0);
const b = Float32x4(5.0, 6.0, 7.0, 8.0);

// 对应 VisitF32x4Min
const min_result = Math.min(a, b); //  注意：这只是概念上的对应，实际 JS API 可能略有不同

// 对应 VisitI32x4DotI16x8S (需要将 Float32x4 视为 i32x4，实际使用时会有类型转换)
// 假设我们有 Int16x8 类型 (JS 中可能没有直接对应，这里仅为说明)
// const c = Int16x8(1, 2, 3, 4, 5, 6, 7, 8);
// const d = Int16x8(9, 10, 11, 12, 13, 14, 15, 16);
// const dot_product = SIMD.i32x4.dot(c, d);

// 对应 VisitI8x16Shuffle
const e = Int8x16(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
const shuffle_indices = [0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15];
const shuffled = SIMD.shuffle(e, shuffle_indices);
```

**如果有代码逻辑推理，请给出假设输入与输出。**

以 `VisitF32x4Min` 方法为例：

**假设输入:**

* `node` 代表一个 `F32x4Min` 的 IR 节点。
* `this->input_at(node, 0)` 返回一个代表 `Float32x4(1.0, NaN, -3.0, -4.0)` 的操作数。
* `this->input_at(node, 1)` 返回一个代表 `Float32x4(5.0, 2.0, NaN, -8.0)` 的操作数。

**代码逻辑推理:**

该方法会生成一系列 RISC-V 指令，其目标是计算两个 `Float32x4` 向量的逐元素最小值，并正确处理 NaN 值。  它使用了临时寄存器 `temp1`, `mask_reg`, `temp2`, `NaN`, `result`。

* `kRiscvVmfeqVv` 指令用于比较向量元素是否相等，这里被用来检测 NaN 值（因为 NaN 不等于自身）。
* `kRiscvVandVv` 指令用于执行向量按位与操作，生成一个掩码，用于标记两个输入向量中对应位置都是 NaN 的元素。
* `kRiscvVmv` 指令用于将立即数加载到向量寄存器中，这里用于创建一个包含 NaN 值的向量。
* `kRiscvVfminVv` 指令执行向量的浮点最小值操作，并使用掩码来处理 NaN 值（如果掩码指示某个位置是 NaN，则结果将是 NaN）。

**输出 (预期的 RISC-V 指令序列，简化表示):**

```assembly
vmfeq.vv v0, input0, input0  // 检测 input0 中的 NaN
vmfeq.vv v1, input1, input1  // 检测 input1 中的 NaN
vand.vv v0, v1, v0           // 生成掩码，标记两个输入都是 NaN 的位置
vsetvli zero, zero, e32, m1, ta, ma  // 设置向量长度和配置
vfmv.s.i v2, 0x7fc00000          // 将 NaN 的 IEEE 754 表示加载到标量寄存器
vfmv.v.s v3, fcsr, v2          // 将标量 NaN 广播到向量寄存器 v3 (假设 v3 是 kSimd128ScratchReg)
vfmin.vv v4, input1, input0, v0.t // 计算最小值，并使用掩码处理 NaN
vmv.v.v output, v4              // 将结果移动到输出寄存器
```

**实际输出会是 `Emit` 函数生成的更具体的指令表示。**

**如果涉及用户常见的编程错误，请举例说明。**

在使用 SIMD API 时，常见的编程错误包括：

* **数据类型不匹配:**  例如，尝试将 `Int32x4` 与 `Float32x4` 直接进行算术运算，而没有进行显式转换。这会导致类型错误。
* **误解 SIMD 操作的语义:** 例如，错误地认为 `Math.min(a, b)` 会对两个 `Float32x4` 向量进行逐元素最小值运算。实际上，JavaScript 的 `Math.min` 只能比较标量值。需要使用 `SIMD.Float32x4.min(a, b)`。
* **忽略 NaN 值的处理:** 浮点 SIMD 操作中，NaN 值的处理需要特别注意。例如，直接使用加法或乘法可能会导致结果中出现意外的 NaN 值。`VisitF32x4Min` 方法中对 NaN 的处理就是一个例子。
* **洗牌 (Shuffle) 索引错误:** 在使用 `SIMD.shuffle` 时，如果提供的索引超出范围 (0-15)，会导致错误或未定义的行为.

**总结一下它的功能：**

这个代码片段是 V8 编译器中 RISC-V 后端指令选择器的一部分，专注于将 SIMD 相关的 IR 节点转换为高效的 RISC-V 向量指令。它涵盖了浮点和整数 SIMD 的比较、类型转换、算术运算（包括点积和平均值）、洗牌以及位掩码等操作，是实现 JavaScript SIMD API 在 RISC-V 架构上高性能执行的关键组成部分。

Prompt: 
```
这是目录为v8/src/compiler/backend/riscv/instruction-selector-riscv.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/riscv/instruction-selector-riscv.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
cratchReg);
    this->Emit(kRiscvVmv, NaN, g.UseImmediate(0x7FC00000), g.UseImmediate(E32),
               g.UseImmediate(m1));
    this->Emit(kRiscvVfminVv, result, g.UseRegister(this->input_at(node, 1)),
               g.UseRegister(this->input_at(node, 0)), g.UseImmediate(E32),
               g.UseImmediate(m1), g.UseImmediate(MaskType::Mask));
    this->Emit(kRiscvVmv, g.DefineAsRegister(node), result, g.UseImmediate(E32),
               g.UseImmediate(m1));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Max(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp1 = g.TempFpRegister(v0);
    InstructionOperand mask_reg = g.TempFpRegister(v0);
    InstructionOperand temp2 = g.TempFpRegister(kSimd128ScratchReg);

    this->Emit(kRiscvVmfeqVv, temp1, g.UseRegister(this->input_at(node, 0)),
               g.UseRegister(this->input_at(node, 0)), g.UseImmediate(E32),
               g.UseImmediate(m1));
    this->Emit(kRiscvVmfeqVv, temp2, g.UseRegister(this->input_at(node, 1)),
               g.UseRegister(this->input_at(node, 1)), g.UseImmediate(E32),
               g.UseImmediate(m1));
    this->Emit(kRiscvVandVv, mask_reg, temp2, temp1, g.UseImmediate(E32),
               g.UseImmediate(m1));

    InstructionOperand NaN = g.TempFpRegister(kSimd128ScratchReg);
    InstructionOperand result = g.TempFpRegister(kSimd128ScratchReg);
    this->Emit(kRiscvVmv, NaN, g.UseImmediate(0x7FC00000), g.UseImmediate(E32),
               g.UseImmediate(m1));
    this->Emit(kRiscvVfmaxVv, result, g.UseRegister(this->input_at(node, 1)),
               g.UseRegister(this->input_at(node, 0)), g.UseImmediate(E32),
               g.UseImmediate(m1), g.UseImmediate(MaskType::Mask));
    this->Emit(kRiscvVmv, g.DefineAsRegister(node), result, g.UseImmediate(E32),
               g.UseImmediate(m1));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4RelaxedMin(node_t node) {
    VisitF32x4Min(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2RelaxedMin(node_t node) {
    VisitF64x2Min(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2RelaxedMax(node_t node) {
    VisitF64x2Max(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4RelaxedMax(node_t node) {
    VisitF32x4Max(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Eq(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp1 = g.TempFpRegister(v0);
    this->Emit(kRiscvVmfeqVv, temp1, g.UseRegister(this->input_at(node, 1)),
               g.UseRegister(this->input_at(node, 0)), g.UseImmediate(E64),
               g.UseImmediate(m1));
    InstructionOperand temp2 = g.TempFpRegister(kSimd128ScratchReg);
    this->Emit(kRiscvVmv, temp2, g.UseImmediate(0), g.UseImmediate(E64),
               g.UseImmediate(m1));
    this->Emit(kRiscvVmergeVx, g.DefineAsRegister(node), g.UseImmediate(-1),
               temp2, g.UseImmediate(E64), g.UseImmediate(m1));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Ne(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp1 = g.TempFpRegister(v0);
    this->Emit(kRiscvVmfneVv, temp1, g.UseRegister(this->input_at(node, 1)),
               g.UseRegister(this->input_at(node, 0)), g.UseImmediate(E64),
               g.UseImmediate(m1));
    InstructionOperand temp2 = g.TempFpRegister(kSimd128ScratchReg);
    this->Emit(kRiscvVmv, temp2, g.UseImmediate(0), g.UseImmediate(E64),
               g.UseImmediate(m1));
    this->Emit(kRiscvVmergeVx, g.DefineAsRegister(node), g.UseImmediate(-1),
               temp2, g.UseImmediate(E64), g.UseImmediate(m1));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Lt(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp1 = g.TempFpRegister(v0);
    this->Emit(kRiscvVmfltVv, temp1, g.UseRegister(this->input_at(node, 0)),
               g.UseRegister(this->input_at(node, 1)), g.UseImmediate(E64),
               g.UseImmediate(m1));
    InstructionOperand temp2 = g.TempFpRegister(kSimd128ScratchReg);
    this->Emit(kRiscvVmv, temp2, g.UseImmediate(0), g.UseImmediate(E64),
               g.UseImmediate(m1));
    this->Emit(kRiscvVmergeVx, g.DefineAsRegister(node), g.UseImmediate(-1),
               temp2, g.UseImmediate(E64), g.UseImmediate(m1));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Le(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp1 = g.TempFpRegister(v0);
    this->Emit(kRiscvVmfleVv, temp1, g.UseRegister(this->input_at(node, 0)),
               g.UseRegister(this->input_at(node, 1)), g.UseImmediate(E64),
               g.UseImmediate(m1));
    InstructionOperand temp2 = g.TempFpRegister(kSimd128ScratchReg);
    this->Emit(kRiscvVmv, temp2, g.UseImmediate(0), g.UseImmediate(E64),
               g.UseImmediate(m1));
    this->Emit(kRiscvVmergeVx, g.DefineAsRegister(node), g.UseImmediate(-1),
               temp2, g.UseImmediate(E64), g.UseImmediate(m1));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Eq(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp1 = g.TempFpRegister(v0);
    this->Emit(kRiscvVmfeqVv, temp1, g.UseRegister(this->input_at(node, 1)),
               g.UseRegister(this->input_at(node, 0)), g.UseImmediate(E32),
               g.UseImmediate(m1));
    InstructionOperand temp2 = g.TempFpRegister(kSimd128ScratchReg);
    this->Emit(kRiscvVmv, temp2, g.UseImmediate(0), g.UseImmediate(E32),
               g.UseImmediate(m1));
    this->Emit(kRiscvVmergeVx, g.DefineAsRegister(node), g.UseImmediate(-1),
               temp2, g.UseImmediate(E32), g.UseImmediate(m1));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Ne(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp1 = g.TempFpRegister(v0);
    this->Emit(kRiscvVmfneVv, temp1, g.UseRegister(this->input_at(node, 1)),
               g.UseRegister(this->input_at(node, 0)), g.UseImmediate(E32),
               g.UseImmediate(m1));
    InstructionOperand temp2 = g.TempFpRegister(kSimd128ScratchReg);
    this->Emit(kRiscvVmv, temp2, g.UseImmediate(0), g.UseImmediate(E32),
               g.UseImmediate(m1));
    this->Emit(kRiscvVmergeVx, g.DefineAsRegister(node), g.UseImmediate(-1),
               temp2, g.UseImmediate(E32), g.UseImmediate(m1));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Lt(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp1 = g.TempFpRegister(v0);
    this->Emit(kRiscvVmfltVv, temp1, g.UseRegister(this->input_at(node, 0)),
               g.UseRegister(this->input_at(node, 1)), g.UseImmediate(E32),
               g.UseImmediate(m1));
    InstructionOperand temp2 = g.TempFpRegister(kSimd128ScratchReg);
    this->Emit(kRiscvVmv, temp2, g.UseImmediate(0), g.UseImmediate(E32),
               g.UseImmediate(m1));
    this->Emit(kRiscvVmergeVx, g.DefineAsRegister(node), g.UseImmediate(-1),
               temp2, g.UseImmediate(E32), g.UseImmediate(m1));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Le(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp1 = g.TempFpRegister(v0);
    this->Emit(kRiscvVmfleVv, temp1, g.UseRegister(this->input_at(node, 0)),
               g.UseRegister(this->input_at(node, 1)), g.UseImmediate(E32),
               g.UseImmediate(m1));
    InstructionOperand temp2 = g.TempFpRegister(kSimd128ScratchReg);
    this->Emit(kRiscvVmv, temp2, g.UseImmediate(0), g.UseImmediate(E32),
               g.UseImmediate(m1));
    this->Emit(kRiscvVmergeVx, g.DefineAsRegister(node), g.UseImmediate(-1),
               temp2, g.UseImmediate(E32), g.UseImmediate(m1));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4SConvertI16x8Low(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp = g.TempFpRegister(kSimd128ScratchReg);
    this->Emit(kRiscvVmv, temp, g.UseRegister(this->input_at(node, 0)),
               g.UseImmediate(E32), g.UseImmediate(m1));
    this->Emit(kRiscvVsextVf2, g.DefineAsRegister(node), temp,
               g.UseImmediate(E32), g.UseImmediate(m1));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4UConvertI16x8Low(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp = g.TempFpRegister(kSimd128ScratchReg);
    this->Emit(kRiscvVmv, temp, g.UseRegister(this->input_at(node, 0)),
               g.UseImmediate(E32), g.UseImmediate(m1));
    this->Emit(kRiscvVzextVf2, g.DefineAsRegister(node), temp,
               g.UseImmediate(E32), g.UseImmediate(m1));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8SConvertI8x16High(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp1 = g.TempFpRegister(v0);
    Emit(kRiscvVslidedown, temp1, g.UseRegister(this->input_at(node, 0)),
         g.UseImmediate(8), g.UseImmediate(E8), g.UseImmediate(m1));
    Emit(kRiscvVsextVf2, g.DefineAsRegister(node), temp1, g.UseImmediate(E16),
         g.UseImmediate(m1));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8SConvertI32x4(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp = g.TempFpRegister(v26);
    InstructionOperand temp2 = g.TempFpRegister(v27);
    this->Emit(kRiscvVmv, temp, g.UseRegister(this->input_at(node, 0)),
               g.UseImmediate(E32), g.UseImmediate(m1));
    this->Emit(kRiscvVmv, temp2, g.UseRegister(this->input_at(node, 1)),
               g.UseImmediate(E32), g.UseImmediate(m1));
    this->Emit(kRiscvVnclip, g.DefineAsRegister(node), temp, g.UseImmediate(0),
               g.UseImmediate(E16), g.UseImmediate(m1),
               g.UseImmediate(FPURoundingMode::RNE));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8UConvertI32x4(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp = g.TempFpRegister(v26);
    InstructionOperand temp2 = g.TempFpRegister(v27);
    InstructionOperand temp3 = g.TempFpRegister(v26);
    this->Emit(kRiscvVmv, temp, g.UseRegister(this->input_at(node, 0)),
               g.UseImmediate(E32), g.UseImmediate(m1));
    this->Emit(kRiscvVmv, temp2, g.UseRegister(this->input_at(node, 1)),
               g.UseImmediate(E32), g.UseImmediate(m1));
    this->Emit(kRiscvVmax, temp3, temp, g.UseImmediate(0), g.UseImmediate(E32),
               g.UseImmediate(m2));
    this->Emit(kRiscvVnclipu, g.DefineAsRegister(node), temp3,
               g.UseImmediate(0), g.UseImmediate(E16), g.UseImmediate(m1),
               g.UseImmediate(FPURoundingMode::RNE));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16RoundingAverageU(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp = g.TempFpRegister(kSimd128ScratchReg);
    this->Emit(kRiscvVwadduVv, temp, g.UseRegister(this->input_at(node, 0)),
               g.UseRegister(this->input_at(node, 1)), g.UseImmediate(E8),
               g.UseImmediate(m1));
    InstructionOperand temp2 = g.TempFpRegister(kSimd128ScratchReg3);
    this->Emit(kRiscvVwadduWx, temp2, temp, g.UseImmediate(1),
               g.UseImmediate(E8), g.UseImmediate(m1));
    InstructionOperand temp3 = g.TempFpRegister(kSimd128ScratchReg3);
    this->Emit(kRiscvVdivu, temp3, temp2, g.UseImmediate(2),
               g.UseImmediate(E16), g.UseImmediate(m2));
    this->Emit(kRiscvVnclipu, g.DefineAsRegister(node), temp3,
               g.UseImmediate(0), g.UseImmediate(E8), g.UseImmediate(m1),
               g.UseImmediate(FPURoundingMode::RNE));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16SConvertI16x8(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp = g.TempFpRegister(v26);
    InstructionOperand temp2 = g.TempFpRegister(v27);
    this->Emit(kRiscvVmv, temp, g.UseRegister(this->input_at(node, 0)),
               g.UseImmediate(E16), g.UseImmediate(m1));
    this->Emit(kRiscvVmv, temp2, g.UseRegister(this->input_at(node, 1)),
               g.UseImmediate(E16), g.UseImmediate(m1));
    this->Emit(kRiscvVnclip, g.DefineAsRegister(node), temp, g.UseImmediate(0),
               g.UseImmediate(E8), g.UseImmediate(m1),
               g.UseImmediate(FPURoundingMode::RNE));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16UConvertI16x8(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp = g.TempFpRegister(v26);
    InstructionOperand temp2 = g.TempFpRegister(v27);
    InstructionOperand temp3 = g.TempFpRegister(v26);
    this->Emit(kRiscvVmv, temp, g.UseRegister(this->input_at(node, 0)),
               g.UseImmediate(E16), g.UseImmediate(m1));
    this->Emit(kRiscvVmv, temp2, g.UseRegister(this->input_at(node, 1)),
               g.UseImmediate(E16), g.UseImmediate(m1));
    this->Emit(kRiscvVmax, temp3, temp, g.UseImmediate(0), g.UseImmediate(E16),
               g.UseImmediate(m2));
    this->Emit(kRiscvVnclipu, g.DefineAsRegister(node), temp3,
               g.UseImmediate(0), g.UseImmediate(E8), g.UseImmediate(m1),
               g.UseImmediate(FPURoundingMode::RNE));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8RoundingAverageU(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp = g.TempFpRegister(v16);
    InstructionOperand temp2 = g.TempFpRegister(v16);
    InstructionOperand temp3 = g.TempFpRegister(v16);
    this->Emit(kRiscvVwadduVv, temp, g.UseRegister(this->input_at(node, 0)),
               g.UseRegister(this->input_at(node, 1)), g.UseImmediate(E16),
               g.UseImmediate(m1));
    this->Emit(kRiscvVwadduWx, temp2, temp, g.UseImmediate(1),
               g.UseImmediate(E16), g.UseImmediate(m1));
    this->Emit(kRiscvVdivu, temp3, temp2, g.UseImmediate(2),
               g.UseImmediate(E32), g.UseImmediate(m2));
    this->Emit(kRiscvVnclipu, g.DefineAsRegister(node), temp3,
               g.UseImmediate(0), g.UseImmediate(E16), g.UseImmediate(m1),
               g.UseImmediate(FPURoundingMode::RNE));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4DotI16x8S(node_t node) {
    constexpr int32_t FIRST_INDEX = 0b01010101;
    constexpr int32_t SECOND_INDEX = 0b10101010;
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp = g.TempFpRegister(v16);
    InstructionOperand temp1 = g.TempFpRegister(v14);
    InstructionOperand temp2 = g.TempFpRegister(v30);
    InstructionOperand dst = g.DefineAsRegister(node);
    this->Emit(kRiscvVwmul, temp, g.UseRegister(this->input_at(node, 0)),
               g.UseRegister(this->input_at(node, 1)), g.UseImmediate(E16),
               g.UseImmediate(m1));
    this->Emit(kRiscvVcompress, temp2, temp, g.UseImmediate(FIRST_INDEX),
               g.UseImmediate(E32), g.UseImmediate(m2));
    this->Emit(kRiscvVcompress, temp1, temp, g.UseImmediate(SECOND_INDEX),
               g.UseImmediate(E32), g.UseImmediate(m2));
    this->Emit(kRiscvVaddVv, dst, temp1, temp2, g.UseImmediate(E32),
               g.UseImmediate(m1));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8DotI8x16I7x16S(node_t node) {
    constexpr int32_t FIRST_INDEX = 0b0101010101010101;
    constexpr int32_t SECOND_INDEX = 0b1010101010101010;
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp = g.TempFpRegister(v16);
    InstructionOperand temp1 = g.TempFpRegister(v14);
    InstructionOperand temp2 = g.TempFpRegister(v30);
    InstructionOperand dst = g.DefineAsRegister(node);
    this->Emit(kRiscvVwmul, temp, g.UseRegister(this->input_at(node, 0)),
               g.UseRegister(this->input_at(node, 1)), g.UseImmediate(E8),
               g.UseImmediate(m1));
    this->Emit(kRiscvVcompress, temp2, temp, g.UseImmediate(FIRST_INDEX),
               g.UseImmediate(E16), g.UseImmediate(m2));
    this->Emit(kRiscvVcompress, temp1, temp, g.UseImmediate(SECOND_INDEX),
               g.UseImmediate(E16), g.UseImmediate(m2));
    this->Emit(kRiscvVaddVv, dst, temp1, temp2, g.UseImmediate(E16),
               g.UseImmediate(m1));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4DotI8x16I7x16AddS(node_t node) {
    constexpr int32_t FIRST_INDEX = 0b0001000100010001;
    constexpr int32_t SECOND_INDEX = 0b0010001000100010;
    constexpr int32_t THIRD_INDEX = 0b0100010001000100;
    constexpr int32_t FOURTH_INDEX = 0b1000100010001000;
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand intermediate = g.TempFpRegister(v12);
    this->Emit(kRiscvVwmul, intermediate,
               g.UseRegister(this->input_at(node, 0)),
               g.UseRegister(this->input_at(node, 1)), g.UseImmediate(E8),
               g.UseImmediate(m1));

    InstructionOperand compressedPart1 = g.TempFpRegister(v14);
    InstructionOperand compressedPart2 = g.TempFpRegister(v16);
    this->Emit(kRiscvVcompress, compressedPart2, intermediate,
               g.UseImmediate(FIRST_INDEX), g.UseImmediate(E16),
               g.UseImmediate(m2));
    this->Emit(kRiscvVcompress, compressedPart1, intermediate,
               g.UseImmediate(SECOND_INDEX), g.UseImmediate(E16),
               g.UseImmediate(m2));

    InstructionOperand compressedPart3 = g.TempFpRegister(v20);
    InstructionOperand compressedPart4 = g.TempFpRegister(v26);
    this->Emit(kRiscvVcompress, compressedPart3, intermediate,
               g.UseImmediate(THIRD_INDEX), g.UseImmediate(E16),
               g.UseImmediate(m2));
    this->Emit(kRiscvVcompress, compressedPart4, intermediate,
               g.UseImmediate(FOURTH_INDEX), g.UseImmediate(E16),
               g.UseImmediate(m2));

    InstructionOperand temp2 = g.TempFpRegister(v18);
    InstructionOperand temp = g.TempFpRegister(kSimd128ScratchReg);
    this->Emit(kRiscvVwaddVv, temp2, compressedPart1, compressedPart2,
               g.UseImmediate(E16), g.UseImmediate(m1));
    this->Emit(kRiscvVwaddVv, temp, compressedPart3, compressedPart4,
               g.UseImmediate(E16), g.UseImmediate(m1));

    InstructionOperand mul_result = g.TempFpRegister(v16);
    InstructionOperand dst = g.DefineAsRegister(node);
    this->Emit(kRiscvVaddVv, mul_result, temp2, temp, g.UseImmediate(E32),
               g.UseImmediate(m1));
    this->Emit(kRiscvVaddVv, dst, mul_result,
               g.UseRegister(this->input_at(node, 2)), g.UseImmediate(E32),
               g.UseImmediate(m1));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Shuffle(node_t node) {
    uint8_t shuffle[kSimd128Size];
    bool is_swizzle;
    // TODO(riscv): Properly use view here once Turboshaft support is
    // implemented.
    auto view = this->simd_shuffle_view(node);
    CanonicalizeShuffle(view, shuffle, &is_swizzle);
    node_t input0 = view.input(0);
    node_t input1 = view.input(1);
    RiscvOperandGeneratorT<Adapter> g(this);
    // uint8_t shuffle32x4[4];
    // ArchOpcode opcode;
    // if (TryMatchArchShuffle(shuffle, arch_shuffles, arraysize(arch_shuffles),
    //                         is_swizzle, &opcode)) {
    //   VisitRRR(this, opcode, node);
    //   return;
    // }
    // uint8_t offset;
    // if (wasm::SimdShuffle::TryMatchConcat(shuffle, &offset)) {
    //   Emit(kRiscvS8x16Concat, g.DefineSameAsFirst(node),
    //   g.UseRegister(input1),
    //        g.UseRegister(input0), g.UseImmediate(offset));
    //   return;
    // }
    // if (wasm::SimdShuffle::TryMatch32x4Shuffle(shuffle, shuffle32x4)) {
    //   Emit(kRiscvS32x4Shuffle, g.DefineAsRegister(node),
    //   g.UseRegister(input0),
    //        g.UseRegister(input1),
    //        g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle32x4)));
    //   return;
    // }
    Emit(kRiscvI8x16Shuffle, g.DefineAsRegister(node), g.UseRegister(input0),
         g.UseRegister(input1),
         g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle)),
         g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle + 4)),
         g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle + 8)),
         g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle + 12)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Swizzle(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand temps[] = {g.TempSimd128Register()};
    // We don't want input 0 or input 1 to be the same as output, since we will
    // modify output before do the calculation.
    Emit(kRiscvVrgather, g.DefineAsRegister(node),
         g.UseUniqueRegister(this->input_at(node, 0)),
         g.UseUniqueRegister(this->input_at(node, 1)), g.UseImmediate(E8),
         g.UseImmediate(m1), arraysize(temps), temps);
}

#define VISIT_BIMASK(TYPE, VSEW, LMUL)                                      \
  template <typename Adapter>                                               \
  void InstructionSelectorT<Adapter>::Visit##TYPE##BitMask(node_t node) {   \
    RiscvOperandGeneratorT<Adapter> g(this);                                \
    InstructionOperand temp = g.TempFpRegister(v16);                        \
    this->Emit(kRiscvVmslt, temp, g.UseRegister(this->input_at(node, 0)),   \
               g.UseImmediate(0), g.UseImmediate(VSEW), g.UseImmediate(m1), \
               g.UseImmediate(true));                                       \
    this->Emit(kRiscvVmvXs, g.DefineAsRegister(node), temp,                 \
               g.UseImmediate(E32), g.UseImmediate(m1));                    \
  }

SIMD_INT_TYPE_LIST(VISIT_BIMASK)
#undef VISIT_BIMASK

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4SConvertI16x8High(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp = g.TempFpRegister(kSimd128ScratchReg);
    this->Emit(kRiscvVslidedown, temp, g.UseRegister(this->input_at(node, 0)),
               g.UseImmediate(4), g.UseImmediate(E16), g.UseImmediate(m1));
    this->Emit(kRiscvVsextVf2, g.DefineAsRegister(node), temp,
               g.UseImmediate(E32), g.UseImmediate(m1));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4UConvertI16x8High(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp = g.TempFpRegister(kSimd128ScratchReg);
    this->Emit(kRiscvVslidedown, temp, g.UseRegister(this->input_at(node, 0)),
               g.UseImmediate(4), g.UseImmediate(E16), g.UseImmediate(m1));
    this->Emit(kRiscvVzextVf2, g.DefineAsRegister(node), temp,
               g.UseImmediate(E32), g.UseImmediate(m1));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8SConvertI8x16Low(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp = g.TempFpRegister(kSimd128ScratchReg);
    this->Emit(kRiscvVmv, temp, g.UseRegister(this->input_at(node, 0)),
               g.UseImmediate(E16), g.UseImmediate(m1));
    this->Emit(kRiscvVsextVf2, g.DefineAsRegister(node), temp,
               g.UseImmediate(E16), g.UseImmediate(m1));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8UConvertI8x16High(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp = g.TempFpRegister(kSimd128ScratchReg);
    Emit(kRiscvVslidedown, temp, g.UseRegister(this->input_at(node, 0)),
         g.UseImmediate(8), g.UseImmediate(E8), g.UseImmediate(m1));
    Emit(kRiscvVzextVf2, g.DefineAsRegister(node), temp, g.UseImmediate(E16),
         g.UseImmediate(m1));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8UConvertI8x16Low(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp = g.TempFpRegister(kSimd128ScratchReg);
    Emit(kRiscvVmv, temp, g.UseRegister(this->input_at(node, 0)),
         g.UseImmediate(E16), g.UseImmediate(m1));
    Emit(kRiscvVzextVf2, g.DefineAsRegister(node), temp, g.UseImmediate(E16),
         g.UseImmediate(m1));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord8ToInt32(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    Emit(kRiscvSignExtendByte, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord16ToInt32(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    Emit(kRiscvSignExtendShort, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Clz(node_t node) {
  VisitRR(this, kRiscvClz32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Ctz(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    Emit(kRiscvCtz32, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
}

#define VISIT_EXT_MUL(OPCODE1, OPCODE2, TYPE)                                  \
  template <typename Adapter>                                                  \
  void InstructionSelectorT<Adapter>::Visit##OPCODE1##ExtMulLow##OPCODE2##S(   \
      node_t node) {                                                           \
      RiscvOperandGeneratorT<Adapter> g(this);                                 \
      Emit(kRiscvVwmul, g.DefineAsRegister(node),                              \
           g.UseUniqueRegister(this->input_at(node, 0)),                       \
           g.UseUniqueRegister(this->input_at(node, 1)),                       \
           g.UseImmediate(E##TYPE), g.UseImmediate(mf2));                      \
  }                                                                            \
  template <typename Adapter>                                                  \
  void InstructionSelectorT<Adapter>::Visit##OPCODE1##ExtMulHigh##OPCODE2##S(  \
      node_t node) {                                                           \
      RiscvOperandGeneratorT<Adapter> g(this);                                 \
      InstructionOperand t1 = g.TempFpRegister(v16);                           \
      Emit(kRiscvVslidedown, t1, g.UseUniqueRegister(this->input_at(node, 0)), \
           g.UseImmediate(kRvvVLEN / TYPE / 2), g.UseImmediate(E##TYPE),       \
           g.UseImmediate(m1));                                                \
      InstructionOperand t2 = g.TempFpRegister(v17);                           \
      Emit(kRiscvVslidedown, t2, g.UseUniqueRegister(this->input_at(node, 1)), \
           g.UseImmediate(kRvvVLEN / TYPE / 2), g.UseImmediate(E##TYPE),       \
           g.UseImmediate(m1));                                                \
      Emit(kRiscvVwmul, g.DefineAsRegister(node), t1, t2,                      \
           g.UseImmediate(E##TYPE), g.UseImmediate(mf2));                      \
  }                                                                            \
  template <typename Adapter>                                                  \
  void InstructionSelectorT<Adapter>::Visit##OPCODE1##ExtMulLow##OPCODE2##U(   \
      node_t node) {                                                           \
      RiscvOperandGeneratorT<Adapter> g(this);                                 \
      Emit(kRiscvVwmulu, g.DefineAsRegister(node),                             \
           g.UseUniqueRegister(this->input_at(node, 0)),                       \
           g.UseUniqueRegister(this->input_at(node, 1)),                       \
           g.UseImmediate(E##TYPE), g.UseImmediate(mf2));                      \
  }                                                                            \
  template <typename Adapter>                                                  \
  void InstructionSelectorT<Adapter>::Visit##OPCODE1##ExtMulHigh##OPCODE2##U(  \
      node_t node) {                                                           \
      RiscvOperandGeneratorT<Adapter> g(this);                                 \
      InstructionOperand t1 = g.TempFpRegister(v16);                           \
      Emit(kRiscvVslidedown, t1, g.UseUniqueRegister(this->input_at(node, 0)), \
           g.UseImmediate(kRvvVLEN / TYPE / 2), g.UseImmediate(E##TYPE),       \
           g.UseImmediate(m1));                                                \
      InstructionOperand t2 = g.TempFpRegister(v17);                           \
      Emit(kRiscvVslidedown, t2, g.UseUniqueRegister(this->input_at(node, 1)), \
           g.UseImmediate(kRvvVLEN / TYPE / 2), g.UseImmediate(E##TYPE),       \
           g.UseImmediate(m1));                                                \
      Emit(kRiscvVwmulu, g.DefineAsRegister(node), t1, t2,                     \
           g.UseImmediate(E##TYPE), g.UseImmediate(mf2));                      \
  }

VISIT_EXT_MUL(I64x2, I32x4, 32)
VISIT_EXT_MUL(I32x4, I16x8, 16)
VISIT_EXT_MUL(I16x8, I8x16, 8)
#undef VISIT_EXT_MUL

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Pmin(node_t node) {
    VisitUniqueRRR(this, kRiscvF32x4Pmin, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Pmax(node_t node) {
    VisitUniqueRRR(this, kRiscvF32x4Pmax, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Pmin(node_t node) {
    VisitUniqueRRR(this, kRiscvF64x2Pmin, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Pmax(node_t node) {
    VisitUniqueRRR(this, kRiscvF64x2Pmax, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToFloat16RawBits(
    node_t node) {
  UNIMPLEMENTED();
}

// static
MachineOperatorBuilder::AlignmentRequirements
InstructionSelector::AlignmentRequirements() {
#ifdef RISCV_HAS_NO_UNALIGNED
  return MachineOperatorBuilder::AlignmentRequirements::
      NoUnalignedAccessSupport();
#else
  return MachineOperatorBuilder::AlignmentRequirements::
      FullUnalignedAccessSupport();
#endif
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::AddOutputToSelectContinuation(
    OperandGenerator* g, int first_input_index, node_t node) {
  UNREACHABLE();
}

#if V8_ENABLE_WEBASSEMBLY
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSetStackPointer(node_t node) {
  OperandGenerator g(this);
  auto input = g.UseRegister(this->input_at(node, 0));
  Emit(kArchSetStackPointer, 0, nullptr, 1, &input);
}
#endif

#undef SIMD_BINOP_LIST
#undef SIMD_SHIFT_OP_LIST
#undef SIMD_UNOP_LIST
#undef SIMD_UNOP_LIST2
#undef SIMD_TYPE_LIST
#undef SIMD_INT_TYPE_LIST
#undef TRACE

}  // namespace compiler
}  // namespace internal
}  // namespace v8

#endif  // V8_COMPILER_BACKEND_RISCV_INSTRUCTION_SELECTOR_RISCV_H_

"""


```