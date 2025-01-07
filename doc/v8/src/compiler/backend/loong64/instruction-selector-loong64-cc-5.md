Response:
Let's break down the thought process for analyzing this V8 code snippet.

1. **Identify the Core Purpose:** The filename `instruction-selector-loong64.cc` strongly suggests this code is responsible for selecting machine instructions for the LoongArch 64-bit architecture within the V8 compiler's backend. The "instruction selector" part is key.

2. **Recognize the V8 Context:** Knowing it's V8 code, recall the compilation pipeline. The instruction selector comes *after* the high-level intermediate representation (like the "Node" mentioned). Its job is to translate these high-level operations into low-level, architecture-specific instructions.

3. **Scan for Key Patterns:**  Look for recurring elements and structures. The `#define` macros are very prominent. Notice patterns like `SIMD_..._LIST` and `SIMD_VISIT_...`. This immediately signals that the code heavily deals with SIMD (Single Instruction, Multiple Data) operations. The `V(...)` pattern within these macros suggests a mapping between high-level SIMD operations and specific LoongArch instructions (like `kLoong64F64x2Add`).

4. **Focus on the Data Structures (Macros):**
    * `SIMD_TYPE_LIST`:  Lists the supported SIMD types (F64x2, F32x4, etc.).
    * `SIMD_UNOP_LIST`: Lists unary SIMD operations (e.g., negation, absolute value).
    * `SIMD_SHIFT_OP_LIST`:  Lists SIMD shift operations.
    * `SIMD_BINOP_LIST`: Lists binary SIMD operations (addition, subtraction, comparison, etc.).

5. **Examine the `Visit...` Functions:** These functions are the core of the instruction selection process. The naming convention `VisitS128Const`, `VisitF64x2Add`, etc., strongly implies that there's a `Visit` function for each supported high-level operation.

6. **Analyze the `VisitS128Const` Example:** This function provides a concrete example of how the instruction selection works.
    * It takes a `Node*` as input (the high-level representation).
    * It extracts data from the node (the constant value).
    * It checks for specific cases (all zeros, all ones) for optimization.
    * It emits specific LoongArch instructions (`kLoong64S128Zero`, `kLoong64S128AllOnes`, `kLoong64S128Const`).
    * The `Loong64OperandGeneratorT` is responsible for creating the operands for these instructions.

7. **Infer the General Process:** From the patterns and the `VisitS128Const` example, deduce the general flow:  The instruction selector examines a high-level operation (represented by a `Node`), determines the appropriate LoongArch instruction(s) to implement it, and generates the corresponding machine code operands.

8. **Address the Specific Questions:** Now go back to the prompt's questions and answer them based on the analysis:
    * **Functionality:**  Translate high-level operations to LoongArch instructions, focusing on SIMD.
    * **.tq extension:**  The code explicitly checks for `.tq` and correctly identifies it as a Torque source if present. This requires recognizing the relationship between `.cc` and `.tq` files in V8.
    * **JavaScript relationship:**  SIMD operations in JavaScript are directly related to the functionality here. Provide a JavaScript SIMD example and show how it maps conceptually to the code.
    * **Code logic inference:**  The `VisitS128Const` function is the best example for this. Describe the input (a constant SIMD value), the logic (checking for all zeros/ones), and the output (LoongArch instructions).
    * **Common programming errors:**  Relate potential JavaScript errors (type mismatches, incorrect lane access) to the underlying SIMD operations being handled.
    * **Part 6 Summary:**  Synthesize the findings from the previous sections into a concise summary. Emphasize the instruction selection role, the LoongArch target, and the handling of SIMD.

9. **Consider Edge Cases and Details:**  Notice the `UNIMPLEMENTED()` calls. This indicates that some SIMD operations or FP16 support might not be fully implemented yet. The presence of different `Adapter` types (`TurbofanAdapter`, `TurboshaftAdapter`) suggests the code supports different compilation pipelines within V8.

10. **Refine and Organize:**  Structure the answer logically, starting with the core purpose and then addressing each specific point. Use clear and concise language. Provide code examples where necessary to illustrate the connection to JavaScript.

Self-Correction/Refinement during the process:

* **Initial thought:**  "This is just about translating instructions."
* **Correction:** Realize the strong emphasis on *SIMD* operations. This becomes a central theme of the description.
* **Initial thought:**  "The macros are just boilerplate."
* **Correction:** Recognize that the macros *define* the mapping between high-level operations and low-level instructions – a crucial part of the functionality.
* **Initial thought:** "Just describe the `Visit` functions."
* **Correction:** Use the `VisitS128Const` function as a concrete, illustrative example to make the explanation clearer.
* **Initial thought:** "JavaScript examples are optional."
* **Correction:**  Realize that providing JavaScript examples significantly strengthens the explanation of the code's purpose and its relationship to the user-facing language.
好的，我们来归纳一下 `v8/src/compiler/backend/loong64/instruction-selector-loong64.cc` 这个文件的功能。

**功能归纳:**

`v8/src/compiler/backend/loong64/instruction-selector-loong64.cc` 文件是 V8 JavaScript 引擎中专门为 **LoongArch 64 位架构** 实现的**指令选择器**。它的核心功能是将**平台无关的中间代码 (Intermediate Representation, IR)** 转换为 **LoongArch 64 位架构特定的机器指令**。

更具体地说，这个文件的主要职责包括：

1. **遍历中间表示 (IR):**  它会接收由编译器前端生成的 IR 图，并逐个访问其中的节点（代表操作）。

2. **模式匹配和指令选择:** 对于每个 IR 节点，它会根据节点的操作类型以及操作数，查找并选择最合适的 LoongArch 64 位机器指令来实现该操作。这涉及到将高级抽象操作映射到具体的硬件指令。

3. **生成机器指令:**  选择合适的指令后，它会生成相应的 `Instruction` 对象，这些对象包含了要执行的机器指令以及其操作数等信息。

4. **处理 SIMD 指令:**  从代码中可以看出，这个文件大量处理 SIMD (Single Instruction, Multiple Data) 操作，例如 `F64x2Add`、`I32x4Mul` 等。它负责将 JavaScript 或 WebAssembly 中的 SIMD 操作转换为 LoongArch 架构的 SIMD 指令。

5. **处理常量:**  例如 `VisitS128Const` 函数，它负责处理 128 位常量，并尝试优化，例如对于全零或全一的常量，会使用特定的指令。

6. **处理内存访问、算术运算、逻辑运算、位运算等各种操作:**  虽然给出的代码片段主要集中在 SIMD 操作上，但完整的文件会处理各种不同的 IR 节点类型。

7. **支持不同的编译管道:** 代码中出现了 `TurbofanAdapter` 和 `TurboshaftAdapter`，这意味着这个指令选择器可以用于 V8 中不同的编译管道 (Turbofan 和 Turboshaft)。

**关于是否为 Torque 源代码:**

根据您提供的规则，`v8/src/compiler/backend/loong64/instruction-selector-loong64.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 Torque 源代码。如果它以 `.tq` 结尾，那才会被认为是 Torque 源代码。

**与 JavaScript 功能的关系及举例:**

`instruction-selector-loong64.cc` 的功能直接关系到 JavaScript 中与性能相关的部分，特别是涉及到 SIMD 操作的场景。

**JavaScript 示例:**

```javascript
// 假设我们有以下使用了 SIMD 的 JavaScript 代码
const a = Float64x2(1.0, 2.0);
const b = Float64x2(3.0, 4.0);
const sum = a.add(b); // SIMD 加法

console.log(sum.x); // 输出 4.0
console.log(sum.y); // 输出 6.0
```

**说明:**

当 V8 编译这段 JavaScript 代码时，`a.add(b)` 这个 SIMD 加法操作会被表示成一个 IR 节点。`instruction-selector-loong64.cc` 中的 `VisitF64x2Add` 函数（或者与之相关的代码）将会负责将这个 IR 节点转换为 LoongArch64 架构上执行双精度浮点数 SIMD 加法的指令，例如 `kLoong64F64x2Add`。

**代码逻辑推理 (以 `VisitS128Const` 为例):**

**假设输入:** 一个表示 128 位常量 `[1, 1, 1, 1]` 的 IR 节点。

**代码逻辑:**

1. `VisitS128Const` 函数被调用。
2. 从 IR 节点中提取 128 位常量的值，存储在 `val` 数组中，此时 `val` 为 `[1, 1, 1, 1]`。
3. 检查 `all_zeros` 和 `all_ones`。 由于 `val` 不是全零也不是全一，这两个条件都不满足。
4. 执行 `Emit(kLoong64S128Const, dst, g.UseImmediate(val[0]), g.UseImmediate(val[1]), g.UseImmediate(val[2]), g.UseImmediate(val[3]));`
5. 生成一个 LoongArch64 的 `kLoong64S128Const` 指令，并将常量值 `1, 1, 1, 1` 作为立即数操作数。 `dst` 是目标寄存器。

**输出:**  生成一个 LoongArch64 的机器指令，该指令会将 128 位常量 `[1, 1, 1, 1]` 加载到目标寄存器 `dst` 中。

**涉及用户常见的编程错误及举例:**

虽然指令选择器本身不直接处理用户的编程错误，但它所处理的 SIMD 操作容易引发一些常见的编程错误。

**JavaScript 示例 (常见的 SIMD 编程错误):**

```javascript
const a = Float32x4(1.0, 2.0, 3.0, 4.0);
const b = Float64x2(5.0, 6.0);

// 错误：尝试将 Float32x4 和 Float64x2 相加，类型不匹配
// const sum = a.add(b); // 这会导致 JavaScript 运行时错误 (TypeError)

// 错误：尝试访问超出范围的 lane
const c = Float32x4(1.0, 2.0, 3.0, 4.0);
// console.log(c.getLane(4)); // 这会导致 JavaScript 运行时错误 (RangeError)
```

**说明:**

* **类型不匹配:**  SIMD 操作通常要求操作数的类型一致。如果用户尝试对不同类型的 SIMD 值进行运算，会导致错误。指令选择器会针对这些不同类型的 SIMD 操作生成相应的指令，但前提是 JavaScript 层面允许这些操作（某些跨类型的转换或运算是允许的）。
* **访问超出范围的 lane:** SIMD 向量有固定数量的 lane（通道）。尝试访问不存在的 lane 会导致错误。指令选择器生成的指令会操作这些 lane，错误的索引会导致不可预测的结果或程序崩溃。

**总结:**

`v8/src/compiler/backend/loong64/instruction-selector-loong64.cc` 是 V8 引擎中至关重要的一个组件，它负责将高级的 JavaScript (特别是 SIMD 部分) 或 WebAssembly 代码翻译成底层的、可以在 LoongArch64 架构上执行的机器指令，是连接高级语言和硬件的关键桥梁。

Prompt: 
```
这是目录为v8/src/compiler/backend/loong64/instruction-selector-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/loong64/instruction-selector-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共6部分，请归纳一下它的功能

"""
SatF64x2SZero, kLoong64I32x4TruncSatF64x2SZero)         \
  V(I32x4TruncSatF64x2UZero, kLoong64I32x4TruncSatF64x2UZero)         \
  V(I32x4RelaxedTruncF32x4S, kLoong64I32x4RelaxedTruncF32x4S)         \
  V(I32x4RelaxedTruncF32x4U, kLoong64I32x4RelaxedTruncF32x4U)         \
  V(I32x4RelaxedTruncF64x2SZero, kLoong64I32x4RelaxedTruncF64x2SZero) \
  V(I32x4RelaxedTruncF64x2UZero, kLoong64I32x4RelaxedTruncF64x2UZero) \
  V(I16x8Neg, kLoong64I16x8Neg)                                       \
  V(I16x8SConvertI8x16Low, kLoong64I16x8SConvertI8x16Low)             \
  V(I16x8SConvertI8x16High, kLoong64I16x8SConvertI8x16High)           \
  V(I16x8UConvertI8x16Low, kLoong64I16x8UConvertI8x16Low)             \
  V(I16x8UConvertI8x16High, kLoong64I16x8UConvertI8x16High)           \
  V(I16x8Abs, kLoong64I16x8Abs)                                       \
  V(I16x8BitMask, kLoong64I16x8BitMask)                               \
  V(I8x16Neg, kLoong64I8x16Neg)                                       \
  V(I8x16Abs, kLoong64I8x16Abs)                                       \
  V(I8x16Popcnt, kLoong64I8x16Popcnt)                                 \
  V(I8x16BitMask, kLoong64I8x16BitMask)                               \
  V(S128Not, kLoong64S128Not)                                         \
  V(I64x2AllTrue, kLoong64I64x2AllTrue)                               \
  V(I32x4AllTrue, kLoong64I32x4AllTrue)                               \
  V(I16x8AllTrue, kLoong64I16x8AllTrue)                               \
  V(I8x16AllTrue, kLoong64I8x16AllTrue)                               \
  V(V128AnyTrue, kLoong64V128AnyTrue)

#define SIMD_SHIFT_OP_LIST(V) \
  V(I64x2Shl)                 \
  V(I64x2ShrS)                \
  V(I64x2ShrU)                \
  V(I32x4Shl)                 \
  V(I32x4ShrS)                \
  V(I32x4ShrU)                \
  V(I16x8Shl)                 \
  V(I16x8ShrS)                \
  V(I16x8ShrU)                \
  V(I8x16Shl)                 \
  V(I8x16ShrS)                \
  V(I8x16ShrU)

#define SIMD_BINOP_LIST(V)                                \
  V(F64x2Add, kLoong64F64x2Add)                           \
  V(F64x2Sub, kLoong64F64x2Sub)                           \
  V(F64x2Mul, kLoong64F64x2Mul)                           \
  V(F64x2Div, kLoong64F64x2Div)                           \
  V(F64x2Min, kLoong64F64x2Min)                           \
  V(F64x2Max, kLoong64F64x2Max)                           \
  V(F64x2Eq, kLoong64F64x2Eq)                             \
  V(F64x2Ne, kLoong64F64x2Ne)                             \
  V(F64x2Lt, kLoong64F64x2Lt)                             \
  V(F64x2Le, kLoong64F64x2Le)                             \
  V(F64x2RelaxedMin, kLoong64F64x2RelaxedMin)             \
  V(F64x2RelaxedMax, kLoong64F64x2RelaxedMax)             \
  V(I64x2Eq, kLoong64I64x2Eq)                             \
  V(I64x2Ne, kLoong64I64x2Ne)                             \
  V(I64x2Add, kLoong64I64x2Add)                           \
  V(I64x2Sub, kLoong64I64x2Sub)                           \
  V(I64x2Mul, kLoong64I64x2Mul)                           \
  V(I64x2GtS, kLoong64I64x2GtS)                           \
  V(I64x2GeS, kLoong64I64x2GeS)                           \
  V(F32x4Add, kLoong64F32x4Add)                           \
  V(F32x4Sub, kLoong64F32x4Sub)                           \
  V(F32x4Mul, kLoong64F32x4Mul)                           \
  V(F32x4Div, kLoong64F32x4Div)                           \
  V(F32x4Max, kLoong64F32x4Max)                           \
  V(F32x4Min, kLoong64F32x4Min)                           \
  V(F32x4Eq, kLoong64F32x4Eq)                             \
  V(F32x4Ne, kLoong64F32x4Ne)                             \
  V(F32x4Lt, kLoong64F32x4Lt)                             \
  V(F32x4Le, kLoong64F32x4Le)                             \
  V(F32x4RelaxedMin, kLoong64F32x4RelaxedMin)             \
  V(F32x4RelaxedMax, kLoong64F32x4RelaxedMax)             \
  V(I32x4Add, kLoong64I32x4Add)                           \
  V(I32x4Sub, kLoong64I32x4Sub)                           \
  V(I32x4Mul, kLoong64I32x4Mul)                           \
  V(I32x4MaxS, kLoong64I32x4MaxS)                         \
  V(I32x4MinS, kLoong64I32x4MinS)                         \
  V(I32x4MaxU, kLoong64I32x4MaxU)                         \
  V(I32x4MinU, kLoong64I32x4MinU)                         \
  V(I32x4Eq, kLoong64I32x4Eq)                             \
  V(I32x4Ne, kLoong64I32x4Ne)                             \
  V(I32x4GtS, kLoong64I32x4GtS)                           \
  V(I32x4GeS, kLoong64I32x4GeS)                           \
  V(I32x4GtU, kLoong64I32x4GtU)                           \
  V(I32x4GeU, kLoong64I32x4GeU)                           \
  V(I32x4DotI16x8S, kLoong64I32x4DotI16x8S)               \
  V(I16x8Add, kLoong64I16x8Add)                           \
  V(I16x8AddSatS, kLoong64I16x8AddSatS)                   \
  V(I16x8AddSatU, kLoong64I16x8AddSatU)                   \
  V(I16x8Sub, kLoong64I16x8Sub)                           \
  V(I16x8SubSatS, kLoong64I16x8SubSatS)                   \
  V(I16x8SubSatU, kLoong64I16x8SubSatU)                   \
  V(I16x8Mul, kLoong64I16x8Mul)                           \
  V(I16x8MaxS, kLoong64I16x8MaxS)                         \
  V(I16x8MinS, kLoong64I16x8MinS)                         \
  V(I16x8MaxU, kLoong64I16x8MaxU)                         \
  V(I16x8MinU, kLoong64I16x8MinU)                         \
  V(I16x8Eq, kLoong64I16x8Eq)                             \
  V(I16x8Ne, kLoong64I16x8Ne)                             \
  V(I16x8GtS, kLoong64I16x8GtS)                           \
  V(I16x8GeS, kLoong64I16x8GeS)                           \
  V(I16x8GtU, kLoong64I16x8GtU)                           \
  V(I16x8GeU, kLoong64I16x8GeU)                           \
  V(I16x8RoundingAverageU, kLoong64I16x8RoundingAverageU) \
  V(I16x8SConvertI32x4, kLoong64I16x8SConvertI32x4)       \
  V(I16x8UConvertI32x4, kLoong64I16x8UConvertI32x4)       \
  V(I16x8Q15MulRSatS, kLoong64I16x8Q15MulRSatS)           \
  V(I16x8RelaxedQ15MulRS, kLoong64I16x8RelaxedQ15MulRS)   \
  V(I8x16Add, kLoong64I8x16Add)                           \
  V(I8x16AddSatS, kLoong64I8x16AddSatS)                   \
  V(I8x16AddSatU, kLoong64I8x16AddSatU)                   \
  V(I8x16Sub, kLoong64I8x16Sub)                           \
  V(I8x16SubSatS, kLoong64I8x16SubSatS)                   \
  V(I8x16SubSatU, kLoong64I8x16SubSatU)                   \
  V(I8x16MaxS, kLoong64I8x16MaxS)                         \
  V(I8x16MinS, kLoong64I8x16MinS)                         \
  V(I8x16MaxU, kLoong64I8x16MaxU)                         \
  V(I8x16MinU, kLoong64I8x16MinU)                         \
  V(I8x16Eq, kLoong64I8x16Eq)                             \
  V(I8x16Ne, kLoong64I8x16Ne)                             \
  V(I8x16GtS, kLoong64I8x16GtS)                           \
  V(I8x16GeS, kLoong64I8x16GeS)                           \
  V(I8x16GtU, kLoong64I8x16GtU)                           \
  V(I8x16GeU, kLoong64I8x16GeU)                           \
  V(I8x16RoundingAverageU, kLoong64I8x16RoundingAverageU) \
  V(I8x16SConvertI16x8, kLoong64I8x16SConvertI16x8)       \
  V(I8x16UConvertI16x8, kLoong64I8x16UConvertI16x8)       \
  V(S128And, kLoong64S128And)                             \
  V(S128Or, kLoong64S128Or)                               \
  V(S128Xor, kLoong64S128Xor)                             \
  V(S128AndNot, kLoong64S128AndNot)

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitS128Const(node_t node) {
  UNIMPLEMENTED();
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitS128Const(Node* node) {
  Loong64OperandGeneratorT<TurbofanAdapter> g(this);
  static const int kUint32Immediates = kSimd128Size / sizeof(uint32_t);
  uint32_t val[kUint32Immediates];
  memcpy(val, S128ImmediateParameterOf(node->op()).data(), kSimd128Size);
  // If all bytes are zeros or ones, avoid emitting code for generic constants
  bool all_zeros = !(val[0] || val[1] || val[2] || val[3]);
  bool all_ones = val[0] == UINT32_MAX && val[1] == UINT32_MAX &&
                  val[2] == UINT32_MAX && val[3] == UINT32_MAX;
  InstructionOperand dst = g.DefineAsRegister(node);
  if (all_zeros) {
    Emit(kLoong64S128Zero, dst);
  } else if (all_ones) {
    Emit(kLoong64S128AllOnes, dst);
  } else {
    Emit(kLoong64S128Const, dst, g.UseImmediate(val[0]), g.UseImmediate(val[1]),
         g.UseImmediate(val[2]), g.UseImmediate(val[3]));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Zero(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    Loong64OperandGeneratorT<TurbofanAdapter> g(this);
    Emit(kLoong64S128Zero, g.DefineAsRegister(node));
  }
}

#define SIMD_VISIT_SPLAT(Type)                                          \
  template <typename Adapter>                                           \
  void InstructionSelectorT<Adapter>::Visit##Type##Splat(node_t node) { \
    VisitRR(this, kLoong64##Type##Splat, node);                         \
  }
SIMD_TYPE_LIST(SIMD_VISIT_SPLAT)
#undef SIMD_VISIT_SPLAT

#define SIMD_VISIT_EXTRACT_LANE(Type, Sign)                           \
  template <typename Adapter>                                         \
  void InstructionSelectorT<Adapter>::Visit##Type##ExtractLane##Sign( \
      node_t node) {                                                  \
    VisitRRI(this, kLoong64##Type##ExtractLane##Sign, node);          \
  }
SIMD_VISIT_EXTRACT_LANE(F64x2, )
SIMD_VISIT_EXTRACT_LANE(F32x4, )
SIMD_VISIT_EXTRACT_LANE(I64x2, )
SIMD_VISIT_EXTRACT_LANE(I32x4, )
SIMD_VISIT_EXTRACT_LANE(I16x8, U)
SIMD_VISIT_EXTRACT_LANE(I16x8, S)
SIMD_VISIT_EXTRACT_LANE(I8x16, U)
SIMD_VISIT_EXTRACT_LANE(I8x16, S)
#undef SIMD_VISIT_EXTRACT_LANE

#define SIMD_VISIT_REPLACE_LANE(Type)                                         \
  template <typename Adapter>                                                 \
  void InstructionSelectorT<Adapter>::Visit##Type##ReplaceLane(node_t node) { \
    VisitRRIR(this, kLoong64##Type##ReplaceLane, node);                       \
  }
SIMD_TYPE_LIST(SIMD_VISIT_REPLACE_LANE)
#undef SIMD_VISIT_REPLACE_LANE

#define SIMD_VISIT_UNOP(Name, instruction)                       \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitRR(this, instruction, node);                            \
  }
SIMD_UNOP_LIST(SIMD_VISIT_UNOP)
#undef SIMD_VISIT_UNOP

#define SIMD_VISIT_SHIFT_OP(Name)                                \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitSimdShift(this, kLoong64##Name, node);                  \
  }
SIMD_SHIFT_OP_LIST(SIMD_VISIT_SHIFT_OP)
#undef SIMD_VISIT_SHIFT_OP

#define SIMD_VISIT_BINOP(Name, instruction)                      \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    VisitRRR(this, instruction, node);                           \
  }
SIMD_BINOP_LIST(SIMD_VISIT_BINOP)
#undef SIMD_VISIT_BINOP

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Select(node_t node) {
  VisitRRRR(this, kLoong64S128Select, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16RelaxedLaneSelect(node_t node) {
  VisitS128Select(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8RelaxedLaneSelect(node_t node) {
  VisitS128Select(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4RelaxedLaneSelect(node_t node) {
  VisitS128Select(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2RelaxedLaneSelect(node_t node) {
  VisitS128Select(node);
}

#define SIMD_UNIMP_OP_LIST(V) \
  V(F64x2Qfma)                \
  V(F64x2Qfms)                \
  V(F32x4Qfma)                \
  V(F32x4Qfms)                \
  V(I16x8DotI8x16I7x16S)      \
  V(I32x4DotI8x16I7x16AddS)

#define SIMD_VISIT_UNIMP_OP(Name)                                \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    UNIMPLEMENTED();                                             \
  }
SIMD_UNIMP_OP_LIST(SIMD_VISIT_UNIMP_OP)

#undef SIMD_VISIT_UNIMP_OP
#undef SIMD_UNIMP_OP_LIST

#define UNIMPLEMENTED_SIMD_FP16_OP_LIST(V) \
  V(F16x8Splat)                            \
  V(F16x8ExtractLane)                      \
  V(F16x8ReplaceLane)                      \
  V(F16x8Abs)                              \
  V(F16x8Neg)                              \
  V(F16x8Sqrt)                             \
  V(F16x8Floor)                            \
  V(F16x8Ceil)                             \
  V(F16x8Trunc)                            \
  V(F16x8NearestInt)                       \
  V(F16x8Add)                              \
  V(F16x8Sub)                              \
  V(F16x8Mul)                              \
  V(F16x8Div)                              \
  V(F16x8Min)                              \
  V(F16x8Max)                              \
  V(F16x8Pmin)                             \
  V(F16x8Pmax)                             \
  V(F16x8Eq)                               \
  V(F16x8Ne)                               \
  V(F16x8Lt)                               \
  V(F16x8Le)                               \
  V(F16x8SConvertI16x8)                    \
  V(F16x8UConvertI16x8)                    \
  V(I16x8SConvertF16x8)                    \
  V(I16x8UConvertF16x8)                    \
  V(F32x4PromoteLowF16x8)                  \
  V(F16x8DemoteF32x4Zero)                  \
  V(F16x8DemoteF64x2Zero)                  \
  V(F16x8Qfma)                             \
  V(F16x8Qfms)

#define SIMD_VISIT_UNIMPL_FP16_OP(Name)                          \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    UNIMPLEMENTED();                                             \
  }

UNIMPLEMENTED_SIMD_FP16_OP_LIST(SIMD_VISIT_UNIMPL_FP16_OP)
#undef SIMD_VISIT_UNIMPL_FP16_OP
#undef UNIMPLEMENTED_SIMD_FP16_OP_LIST

#if V8_ENABLE_WEBASSEMBLY
namespace {

struct ShuffleEntry {
  uint8_t shuffle[kSimd128Size];
  ArchOpcode opcode;
};

static const ShuffleEntry arch_shuffles[] = {
    {{0, 1, 2, 3, 16, 17, 18, 19, 4, 5, 6, 7, 20, 21, 22, 23},
     kLoong64S32x4InterleaveRight},
    {{8, 9, 10, 11, 24, 25, 26, 27, 12, 13, 14, 15, 28, 29, 30, 31},
     kLoong64S32x4InterleaveLeft},
    {{0, 1, 2, 3, 8, 9, 10, 11, 16, 17, 18, 19, 24, 25, 26, 27},
     kLoong64S32x4PackEven},
    {{4, 5, 6, 7, 12, 13, 14, 15, 20, 21, 22, 23, 28, 29, 30, 31},
     kLoong64S32x4PackOdd},
    {{0, 1, 2, 3, 16, 17, 18, 19, 8, 9, 10, 11, 24, 25, 26, 27},
     kLoong64S32x4InterleaveEven},
    {{4, 5, 6, 7, 20, 21, 22, 23, 12, 13, 14, 15, 28, 29, 30, 31},
     kLoong64S32x4InterleaveOdd},

    {{0, 1, 16, 17, 2, 3, 18, 19, 4, 5, 20, 21, 6, 7, 22, 23},
     kLoong64S16x8InterleaveRight},
    {{8, 9, 24, 25, 10, 11, 26, 27, 12, 13, 28, 29, 14, 15, 30, 31},
     kLoong64S16x8InterleaveLeft},
    {{0, 1, 4, 5, 8, 9, 12, 13, 16, 17, 20, 21, 24, 25, 28, 29},
     kLoong64S16x8PackEven},
    {{2, 3, 6, 7, 10, 11, 14, 15, 18, 19, 22, 23, 26, 27, 30, 31},
     kLoong64S16x8PackOdd},
    {{0, 1, 16, 17, 4, 5, 20, 21, 8, 9, 24, 25, 12, 13, 28, 29},
     kLoong64S16x8InterleaveEven},
    {{2, 3, 18, 19, 6, 7, 22, 23, 10, 11, 26, 27, 14, 15, 30, 31},
     kLoong64S16x8InterleaveOdd},
    {{6, 7, 4, 5, 2, 3, 0, 1, 14, 15, 12, 13, 10, 11, 8, 9},
     kLoong64S16x4Reverse},
    {{2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13},
     kLoong64S16x2Reverse},

    {{0, 16, 1, 17, 2, 18, 3, 19, 4, 20, 5, 21, 6, 22, 7, 23},
     kLoong64S8x16InterleaveRight},
    {{8, 24, 9, 25, 10, 26, 11, 27, 12, 28, 13, 29, 14, 30, 15, 31},
     kLoong64S8x16InterleaveLeft},
    {{0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30},
     kLoong64S8x16PackEven},
    {{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31},
     kLoong64S8x16PackOdd},
    {{0, 16, 2, 18, 4, 20, 6, 22, 8, 24, 10, 26, 12, 28, 14, 30},
     kLoong64S8x16InterleaveEven},
    {{1, 17, 3, 19, 5, 21, 7, 23, 9, 25, 11, 27, 13, 29, 15, 31},
     kLoong64S8x16InterleaveOdd},
    {{7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8},
     kLoong64S8x8Reverse},
    {{3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12},
     kLoong64S8x4Reverse},
    {{1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14},
     kLoong64S8x2Reverse}};

bool TryMatchArchShuffle(const uint8_t* shuffle, const ShuffleEntry* table,
                         size_t num_entries, bool is_swizzle,
                         ArchOpcode* opcode) {
  uint8_t mask = is_swizzle ? kSimd128Size - 1 : 2 * kSimd128Size - 1;
  for (size_t i = 0; i < num_entries; ++i) {
    const ShuffleEntry& entry = table[i];
    int j = 0;
    for (; j < kSimd128Size; ++j) {
      if ((entry.shuffle[j] & mask) != (shuffle[j] & mask)) {
        break;
      }
    }
    if (j == kSimd128Size) {
      *opcode = entry.opcode;
      return true;
    }
  }
  return false;
}

}  // namespace

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitI8x16Shuffle(node_t node) {
  UNIMPLEMENTED();
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitI8x16Shuffle(Node* node) {
  uint8_t shuffle[kSimd128Size];
  bool is_swizzle;
  // TODO(LOONG_dev): Properly use view here once Turboshaft support is
  // implemented.
  auto view = this->simd_shuffle_view(node);
  CanonicalizeShuffle(view, shuffle, &is_swizzle);
  uint8_t shuffle32x4[4];
  ArchOpcode opcode;
  if (TryMatchArchShuffle(shuffle, arch_shuffles, arraysize(arch_shuffles),
                          is_swizzle, &opcode)) {
    VisitRRR(this, opcode, node);
    return;
  }
  Node* input0 = node->InputAt(0);
  Node* input1 = node->InputAt(1);
  uint8_t offset;
  Loong64OperandGeneratorT<TurbofanAdapter> g(this);
  if (wasm::SimdShuffle::TryMatchConcat(shuffle, &offset)) {
    Emit(kLoong64S8x16Concat, g.DefineSameAsFirst(node), g.UseRegister(input1),
         g.UseRegister(input0), g.UseImmediate(offset));
    return;
  }
  if (wasm::SimdShuffle::TryMatch32x4Shuffle(shuffle, shuffle32x4)) {
    Emit(kLoong64S32x4Shuffle, g.DefineAsRegister(node), g.UseRegister(input0),
         g.UseRegister(input1),
         g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle32x4)));
    return;
  }
  Emit(kLoong64I8x16Shuffle, g.DefineAsRegister(node), g.UseRegister(input0),
       g.UseRegister(input1),
       g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle)),
       g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle + 4)),
       g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle + 8)),
       g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle + 12)));
}
#else
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Shuffle(node_t node) {
  UNREACHABLE();
}
#endif  // V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Swizzle(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    Loong64OperandGeneratorT<TurbofanAdapter> g(this);
    InstructionOperand temps[] = {g.TempSimd128Register()};
    // We don't want input 0 or input 1 to be the same as output, since we will
    // modify output before do the calculation.
    Emit(kLoong64I8x16Swizzle, g.DefineAsRegister(node),
         g.UseUniqueRegister(node->InputAt(0)),
         g.UseUniqueRegister(node->InputAt(1)), arraysize(temps), temps);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSetStackPointer(node_t node) {
  OperandGenerator g(this);
  auto input = g.UseRegister(this->input_at(node, 0));
  Emit(kArchSetStackPointer, 0, nullptr, 1, &input);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord8ToInt32(node_t node) {
  VisitRR(this, kLoong64Ext_w_b, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord16ToInt32(node_t node) {
  VisitRR(this, kLoong64Ext_w_h, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord8ToInt64(node_t node) {
  VisitRR(this, kLoong64Ext_w_b, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord16ToInt64(node_t node) {
  VisitRR(this, kLoong64Ext_w_h, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord32ToInt64(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    Loong64OperandGeneratorT<Adapter> g(this);
    Emit(kLoong64Sll_w, g.DefineAsRegister(node),
         g.UseRegister(node->InputAt(0)), g.TempImmediate(0));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Pmin(node_t node) {
  VisitUniqueRRR(this, kLoong64F32x4Pmin, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Pmax(node_t node) {
  VisitUniqueRRR(this, kLoong64F32x4Pmax, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Pmin(node_t node) {
  VisitUniqueRRR(this, kLoong64F64x2Pmin, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Pmax(node_t node) {
  VisitUniqueRRR(this, kLoong64F64x2Pmax, node);
}

#define VISIT_EXT_MUL(OPCODE1, OPCODE2)                                    \
  template <typename Adapter>                                              \
  void InstructionSelectorT<Adapter>::Visit##OPCODE1##ExtMulLow##OPCODE2(  \
      node_t node) {}                                                      \
  template <typename Adapter>                                              \
  void InstructionSelectorT<Adapter>::Visit##OPCODE1##ExtMulHigh##OPCODE2( \
      node_t node) {}

VISIT_EXT_MUL(I64x2, I32x4S)
VISIT_EXT_MUL(I64x2, I32x4U)
VISIT_EXT_MUL(I32x4, I16x8S)
VISIT_EXT_MUL(I32x4, I16x8U)
VISIT_EXT_MUL(I16x8, I8x16S)
VISIT_EXT_MUL(I16x8, I8x16U)
#undef VISIT_EXT_MUL

#define VISIT_EXTADD_PAIRWISE(OPCODE)                              \
  template <typename Adapter>                                      \
  void InstructionSelectorT<Adapter>::Visit##OPCODE(node_t node) { \
    if constexpr (Adapter::IsTurboshaft) {                         \
      UNIMPLEMENTED();                                             \
    } else {                                                       \
      Loong64OperandGeneratorT<Adapter> g(this);                   \
      Emit(kLoong64ExtAddPairwise, g.DefineAsRegister(node),       \
           g.UseRegister(node->InputAt(0)));                       \
    }                                                              \
  }
VISIT_EXTADD_PAIRWISE(I16x8ExtAddPairwiseI8x16S)
VISIT_EXTADD_PAIRWISE(I16x8ExtAddPairwiseI8x16U)
VISIT_EXTADD_PAIRWISE(I32x4ExtAddPairwiseI16x8S)
VISIT_EXTADD_PAIRWISE(I32x4ExtAddPairwiseI16x8U)
#undef VISIT_EXTADD_PAIRWISE

template <typename Adapter>
void InstructionSelectorT<Adapter>::AddOutputToSelectContinuation(
    OperandGenerator* g, int first_input_index, node_t node) {
  UNREACHABLE();
}

// static
MachineOperatorBuilder::Flags
InstructionSelector::SupportedMachineOperatorFlags() {
  MachineOperatorBuilder::Flags flags = MachineOperatorBuilder::kNoFlags;
  return flags | MachineOperatorBuilder::kWord32ShiftIsSafe |
         MachineOperatorBuilder::kInt32DivIsSafe |
         MachineOperatorBuilder::kUint32DivIsSafe |
         MachineOperatorBuilder::kFloat64RoundDown |
         MachineOperatorBuilder::kFloat32RoundDown |
         MachineOperatorBuilder::kFloat64RoundUp |
         MachineOperatorBuilder::kFloat32RoundUp |
         MachineOperatorBuilder::kFloat64RoundTruncate |
         MachineOperatorBuilder::kFloat32RoundTruncate |
         MachineOperatorBuilder::kFloat64RoundTiesEven |
         MachineOperatorBuilder::kFloat32RoundTiesEven;
}

// static
MachineOperatorBuilder::AlignmentRequirements
InstructionSelector::AlignmentRequirements() {
  return MachineOperatorBuilder::AlignmentRequirements::
      FullUnalignedAccessSupport();
}

template class EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    InstructionSelectorT<TurbofanAdapter>;
template class EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    InstructionSelectorT<TurboshaftAdapter>;

#undef SIMD_BINOP_LIST
#undef SIMD_SHIFT_OP_LIST
#undef SIMD_UNOP_LIST
#undef SIMD_TYPE_LIST
#undef TRACE

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""


```