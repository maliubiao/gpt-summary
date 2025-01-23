Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

1. **Initial Understanding:** The filename `instruction-selector-mips64.cc` strongly suggests this code is responsible for selecting machine instructions for the MIPS64 architecture within the V8 JavaScript engine's compiler. The presence of templates like `InstructionSelectorT<TurbofanAdapter>` and `InstructionSelectorT<TurboshaftAdapter>` indicates it supports different compilation pipelines within V8 (Turbofan and Turboshaft).

2. **High-Level Functionality Identification:** The core function is instruction selection. This involves taking higher-level intermediate representation (IR) nodes and translating them into specific MIPS64 machine instructions. This is a crucial step in the compilation process.

3. **Structure and Key Components:**
    * **Templates:**  The code uses templates extensively (`InstructionSelectorT`). This allows the same logic to be used with different "adapters" (like `TurbofanAdapter` and `TurboshaftAdapter`), which likely represent different phases or styles of compilation.
    * **`Visit...` Methods:** The numerous `Visit...` methods (e.g., `VisitS128Const`, `VisitI8x16Shuffle`) are the workhorses. Each `Visit` method corresponds to a specific IR node type (e.g., `S128Const` for a 128-bit constant).
    * **Macros:**  Macros like `SIMD_TYPE_LIST`, `SIMD_VISIT_SPLAT`, etc., are used for code generation and to reduce redundancy, especially when dealing with similar operations across different data types (SIMD).
    * **`Emit` Function:** The `Emit` function is likely responsible for actually generating the machine instruction and adding it to the instruction stream. It takes an opcode and operands.
    * **Operand Generation:**  The `Mips64OperandGeneratorT` class is responsible for creating operands for the instructions, converting IR node values into registers, immediates, etc.
    * **SIMD Operations:** A significant portion of the code deals with SIMD (Single Instruction, Multiple Data) operations, indicated by types like `I8x16`, `F32x4`, and functions like `VisitI8x16Shuffle`.
    * **Helper Functions:** Functions like `TryMatchArchShuffle` and `CanonicalizeShuffle` suggest optimizations or specific handling for certain patterns of operations.
    * **Unimplemented/Unreachable:** The use of `UNIMPLEMENTED()` and `UNREACHABLE()` signifies areas of the code that are either not yet implemented or should not be reached under normal circumstances.

4. **Detailed Analysis of Key Sections:**
    * **SIMD Constants (`VisitS128Const`):**  This shows how 128-bit constant values are handled, with special cases for all zeros and all ones.
    * **SIMD Splat (`Visit...Splat`):**  These methods likely duplicate a single scalar value across all lanes of a SIMD vector.
    * **SIMD Extract/Replace Lane (`Visit...ExtractLane`, `Visit...ReplaceLane`):**  These methods access or modify individual elements within a SIMD vector.
    * **SIMD Binary/Unary/Shift Operations (`SIMD_BINOP_LIST`, `SIMD_UNOP_LIST`, `SIMD_SHIFT_OP_LIST`):** These define the handling of common SIMD arithmetic and logical operations.
    * **SIMD Shuffle (`VisitI8x16Shuffle`):**  This is a complex operation that rearranges elements within or between SIMD vectors. The code attempts to match common shuffle patterns for optimization.
    * **Sign Extension (`VisitSignExtend...`):** These methods convert smaller integer types to larger ones while preserving the sign.
    * **Packed Min/Max (`VisitF32x4Pmin`, `VisitF32x4Pmax`):**  These perform element-wise minimum or maximum operations on SIMD vectors.
    * **Extended Multiply (`VISIT_EXT_MUL`):** These operations perform multiplication and extract either the lower or upper part of the result, often used for widening multiplication.
    * **Pairwise Add (`VISIT_EXTADD_PAIRWISE`):**  These add adjacent elements within a SIMD vector.

5. **Answering Specific Questions:**
    * **Functionality Summary:** Based on the analysis, the primary function is to translate IR nodes into MIPS64 instructions, with a strong focus on SIMD operations.
    * **Torque Source:** The absence of a `.tq` suffix indicates it's not a Torque file.
    * **JavaScript Relevance:** The SIMD operations directly relate to JavaScript's SIMD.js API (now deprecated but its concepts are still relevant in WebAssembly). The example demonstrates creating and operating on SIMD values in JavaScript.
    * **Code Logic/Assumptions:** The `VisitS128Const` method makes the assumption that checking for all zeros or all ones is a worthwhile optimization. Inputs are IR nodes, outputs are MIPS64 instructions.
    * **Common Programming Errors:**  Incorrect shuffle patterns or out-of-bounds lane access are potential errors when using SIMD.
    * **Overall Function:**  Reiterating the core purpose of instruction selection within the V8 compilation pipeline.

6. **Refinement and Organization:** The final step is to organize the findings into a clear and structured answer, covering all aspects requested in the prompt. Using bullet points, code examples, and clear explanations enhances readability. Specifically addressing each part of the prompt ("list functionality," "Torque source," etc.) is important.
这是对 V8 引擎中 MIPS64 架构的指令选择器部分代码的分析。指令选择器的主要任务是将中间表示 (IR) 的节点转换为目标架构 (MIPS64) 的机器指令。

**核心功能:**

1. **指令选择:**  `instruction-selector-mips64.cc` 负责将 V8 编译器生成的与 MIPS64 架构相关的中间代码（节点）转换为实际的 MIPS64 汇编指令。这是编译器后端的核心步骤，因为它弥合了高级代码表示和底层硬件指令之间的差距。

2. **SIMD 指令支持:** 该文件包含了大量处理 SIMD (Single Instruction, Multiple Data) 操作的代码。SIMD 允许同时对多个数据元素执行相同的操作，这对于提升性能至关重要，尤其是在处理多媒体和数值计算时。代码中定义了各种 SIMD 操作的指令选择逻辑，例如：
   - 加法、减法、乘法、除法 (`VisitF64x2Add`, `VisitI32x4Sub` 等)
   - 比较运算 (`VisitF16x8Eq`, `VisitI32x4GtS` 等)
   - 位运算 (`VisitS128And`, `VisitS128Or` 等)
   - 车道操作 (Lane Operations)： 提取、替换、混洗 SIMD 向量中的元素 (`VisitF64x2ExtractLane`, `VisitI32x4ReplaceLane`, `VisitI8x16Shuffle`)
   - 类型转换 (`VisitI8x16SConvertI16x8`, `VisitF16x8SConvertI16x8`)
   - 规约操作 (Reduction Operations，例如 `Pmin`, `Pmax`)

3. **常量加载:** `VisitS128Const` 方法处理 128 位常量值的加载，并针对全零和全一的情况进行了优化。

4. **符号扩展:**  提供了将较小位宽的整数扩展到较大位宽的指令选择 (`VisitSignExtendWord8ToInt32`, `VisitSignExtendWord16ToInt64` 等)。

5. **堆栈指针操作:** 提供了设置堆栈指针的指令选择 (`VisitSetStackPointer`).

6. **支持不同的编译适配器:** 使用模板 `InstructionSelectorT`，支持 `TurbofanAdapter` 和 `TurboshaftAdapter` 两种不同的编译器后端适配器。这表明 V8 内部可能存在多种编译流水线。

7. **未实现的功能:** 代码中存在 `UNIMPLEMENTED()` 的调用，表明某些 SIMD 操作或特性在 MIPS64 架构上尚未完全实现。

**关于源代码类型:**

- 代码以 `.cc` 结尾，因此是 **C++ 源代码**，而不是 Torque 源代码。 Torque 源代码文件通常以 `.tq` 结尾。

**与 JavaScript 功能的关系 (SIMD.js):**

这段代码直接关系到 JavaScript 中的 **SIMD (Single Instruction, Multiple Data)** 功能。虽然 SIMD.js API 已经被弃用，但其概念和底层的指令实现仍然存在于 WebAssembly 中，并且 V8 内部仍然需要处理这些操作。

**JavaScript 示例 (说明 SIMD 功能):**

```javascript
// 假设我们有 SIMD 类型 (虽然 SIMD.js 已弃用，这里仅为概念说明)
// 并且 V8 内部将其映射到 MIPS64 的 SIMD 指令

// 创建两个 4x32 位整数的 SIMD 向量
const a = SIMD.int32x4(1, 2, 3, 4);
const b = SIMD.int32x4(5, 6, 7, 8);

// 执行 SIMD 加法 (对应于 MIPS64 的 SIMD 加法指令)
const sum = SIMD.int32x4.add(a, b);
// sum 的结果将是 SIMD.int32x4(6, 8, 10, 12)

// 提取 SIMD 向量中的一个元素 (对应于 MIPS64 的提取 Lane 指令)
const firstElement = SIMD.int32x4.extractLane(sum, 0); // firstElement 的值为 6

// 创建一个 SIMD 常量 (对应于 MIPS64 的常量加载指令)
const zero = SIMD.int32x4(0, 0, 0, 0);

// 执行 SIMD 混洗操作 (对应于 MIPS64 的混洗指令)
// 假设存在 shuffle 操作
// const shuffled = SIMD.int32x4.shuffle(a, [3, 2, 1, 0]);
// shuffled 的结果将是 SIMD.int32x4(4, 3, 2, 1)
```

**代码逻辑推理 (以 `VisitS128Const` 为例):**

**假设输入:** 一个表示 128 位常量的 IR 节点 `node`。这个节点携带了常量的实际 16 字节数据。

**输出:**  MIPS64 的汇编指令，用于将该常量加载到寄存器中。

**逻辑:**

1. 从 `node` 中获取 128 位常量的值，将其存储在 `val` 数组中 (每 32 位为一个元素)。
2. 检查常量是否为全零或全一。
3. 如果是全零，则发射 `kMips64S128Zero` 指令。
4. 如果是全一，则发射 `kMips64S128AllOnes` 指令。
5. 否则，发射通用的 `kMips64S128Const` 指令，并将 `val` 数组中的四个 32 位值作为立即数操作数传递给该指令。

**用户常见的编程错误 (与 SIMD 相关):**

1. **类型不匹配:**  在 SIMD 操作中，确保操作数的元素类型和位宽一致。例如，尝试将 `int32x4` 向量与 `float32x4` 向量相加会导致错误。

   ```javascript
   // 错误示例 (假设存在这种 SIMD 类型)
   const intVec = SIMD.int32x4(1, 2, 3, 4);
   const floatVec = SIMD.float32x4(1.0, 2.0, 3.0, 4.0);
   // 尝试进行类型不匹配的操作
   // const result = SIMD.int32x4.add(intVec, floatVec); // 这通常是不允许的
   ```

2. **车道 (Lane) 索引越界:**  在提取或替换 SIMD 向量元素时，使用超出有效范围的索引会导致错误。对于 4x32 位的向量，有效的车道索引是 0, 1, 2, 3。

   ```javascript
   // 错误示例
   const vec = SIMD.int32x4(1, 2, 3, 4);
   // 尝试访问超出范围的索引
   // const element = SIMD.int32x4.extractLane(vec, 4); // 错误，索引 4 超出范围
   ```

3. **混洗 (Shuffle) 操作参数错误:**  `VisitI8x16Shuffle` 处理的混洗操作需要提供正确的混洗模式，指定如何重新排列向量中的字节。错误的混洗模式可能导致意想不到的结果或运行时错误。

   ```javascript
   // 错误示例 (假设 shuffle 函数接受一个索引数组)
   const vec1 = SIMD.int8x16( /* ... */ );
   const vec2 = SIMD.int8x16( /* ... */ );
   // 混洗索引数组的长度应该与向量的长度相同
   // const shuffled = SIMD.int8x16.shuffle(vec1, vec2, [0, 1, 2]); // 错误，索引数组长度不足
   ```

4. **未考虑 SIMD 操作的特性:**  某些 SIMD 指令可能具有特定的行为，例如饱和运算（结果被限制在一定范围内）。不理解这些特性可能会导致逻辑错误。

**第 6 部分功能归纳:**

作为第六部分，这段代码主要集中在 **MIPS64 架构下 SIMD 指令的选择和实现**。它涵盖了多种 SIMD 数据类型和操作，包括算术运算、逻辑运算、比较运算、车道操作、类型转换以及常量加载等。这部分代码是 V8 引擎支持高性能 SIMD 操作的关键组成部分，尤其对于那些编译到 WebAssembly 的 SIMD 代码来说至关重要。它定义了如何将通用的 SIMD 中间表示转换为特定的 MIPS64 机器指令，从而利用 MIPS64 硬件提供的 SIMD 能力来提升 JavaScript 和 WebAssembly 代码的执行效率。

### 提示词
```
这是目录为v8/src/compiler/backend/mips64/instruction-selector-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/mips64/instruction-selector-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
I8x16SConvertI16x8, kMips64I8x16SConvertI16x8)       \
  V(I8x16UConvertI16x8, kMips64I8x16UConvertI16x8)       \
  V(S128And, kMips64S128And)                             \
  V(S128Or, kMips64S128Or)                               \
  V(S128Xor, kMips64S128Xor)                             \
  V(S128AndNot, kMips64S128AndNot)

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitS128Const(node_t node) {
  UNIMPLEMENTED();
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitS128Const(Node* node) {
  Mips64OperandGeneratorT<TurbofanAdapter> g(this);
  static const int kUint32Immediates = kSimd128Size / sizeof(uint32_t);
  uint32_t val[kUint32Immediates];
  memcpy(val, S128ImmediateParameterOf(node->op()).data(), kSimd128Size);
  // If all bytes are zeros or ones, avoid emitting code for generic constants
  bool all_zeros = !(val[0] || val[1] || val[2] || val[3]);
  bool all_ones = val[0] == UINT32_MAX && val[1] == UINT32_MAX &&
                  val[2] == UINT32_MAX && val[3] == UINT32_MAX;
  InstructionOperand dst = g.DefineAsRegister(node);
  if (all_zeros) {
    Emit(kMips64S128Zero, dst);
  } else if (all_ones) {
    Emit(kMips64S128AllOnes, dst);
  } else {
    Emit(kMips64S128Const, dst, g.UseImmediate(val[0]), g.UseImmediate(val[1]),
         g.UseImmediate(val[2]), g.UseImmediate(val[3]));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Zero(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    Mips64OperandGeneratorT<Adapter> g(this);
    Emit(kMips64S128Zero, g.DefineAsRegister(node));
  }
}
#define SIMD_VISIT_SPLAT(Type)                                          \
  template <typename Adapter>                                           \
  void InstructionSelectorT<Adapter>::Visit##Type##Splat(node_t node) { \
    VisitRR(this, kMips64##Type##Splat, node);                          \
  }
SIMD_TYPE_LIST(SIMD_VISIT_SPLAT)
#undef SIMD_VISIT_SPLAT

#define SIMD_VISIT_EXTRACT_LANE(Type, Sign)                           \
  template <typename Adapter>                                         \
  void InstructionSelectorT<Adapter>::Visit##Type##ExtractLane##Sign( \
      node_t node) {                                                  \
    VisitRRI(this, kMips64##Type##ExtractLane##Sign, node);           \
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
    VisitRRIR(this, kMips64##Type##ReplaceLane, node);                        \
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
    VisitSimdShift(this, kMips64##Name, node);                   \
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

#define SIMD_RELAXED_OP_LIST(V)  \
  V(F64x2RelaxedMin)             \
  V(F64x2RelaxedMax)             \
  V(F32x4RelaxedMin)             \
  V(F32x4RelaxedMax)             \
  V(I32x4RelaxedTruncF32x4S)     \
  V(I32x4RelaxedTruncF32x4U)     \
  V(I32x4RelaxedTruncF64x2SZero) \
  V(I32x4RelaxedTruncF64x2UZero) \
  V(I16x8RelaxedQ15MulRS)        \
  V(I8x16RelaxedLaneSelect)      \
  V(I16x8RelaxedLaneSelect)      \
  V(I32x4RelaxedLaneSelect)      \
  V(I64x2RelaxedLaneSelect)

#define SIMD_VISIT_RELAXED_OP(Name)                              \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    UNREACHABLE();                                               \
  }
SIMD_RELAXED_OP_LIST(SIMD_VISIT_RELAXED_OP)
#undef SIMD_VISIT_SHIFT_OP

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Select(node_t node) {
  VisitRRRR(this, kMips64S128Select, node);
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
     kMips64S32x4InterleaveRight},
    {{8, 9, 10, 11, 24, 25, 26, 27, 12, 13, 14, 15, 28, 29, 30, 31},
     kMips64S32x4InterleaveLeft},
    {{0, 1, 2, 3, 8, 9, 10, 11, 16, 17, 18, 19, 24, 25, 26, 27},
     kMips64S32x4PackEven},
    {{4, 5, 6, 7, 12, 13, 14, 15, 20, 21, 22, 23, 28, 29, 30, 31},
     kMips64S32x4PackOdd},
    {{0, 1, 2, 3, 16, 17, 18, 19, 8, 9, 10, 11, 24, 25, 26, 27},
     kMips64S32x4InterleaveEven},
    {{4, 5, 6, 7, 20, 21, 22, 23, 12, 13, 14, 15, 28, 29, 30, 31},
     kMips64S32x4InterleaveOdd},

    {{0, 1, 16, 17, 2, 3, 18, 19, 4, 5, 20, 21, 6, 7, 22, 23},
     kMips64S16x8InterleaveRight},
    {{8, 9, 24, 25, 10, 11, 26, 27, 12, 13, 28, 29, 14, 15, 30, 31},
     kMips64S16x8InterleaveLeft},
    {{0, 1, 4, 5, 8, 9, 12, 13, 16, 17, 20, 21, 24, 25, 28, 29},
     kMips64S16x8PackEven},
    {{2, 3, 6, 7, 10, 11, 14, 15, 18, 19, 22, 23, 26, 27, 30, 31},
     kMips64S16x8PackOdd},
    {{0, 1, 16, 17, 4, 5, 20, 21, 8, 9, 24, 25, 12, 13, 28, 29},
     kMips64S16x8InterleaveEven},
    {{2, 3, 18, 19, 6, 7, 22, 23, 10, 11, 26, 27, 14, 15, 30, 31},
     kMips64S16x8InterleaveOdd},
    {{6, 7, 4, 5, 2, 3, 0, 1, 14, 15, 12, 13, 10, 11, 8, 9},
     kMips64S16x4Reverse},
    {{2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13},
     kMips64S16x2Reverse},

    {{0, 16, 1, 17, 2, 18, 3, 19, 4, 20, 5, 21, 6, 22, 7, 23},
     kMips64S8x16InterleaveRight},
    {{8, 24, 9, 25, 10, 26, 11, 27, 12, 28, 13, 29, 14, 30, 15, 31},
     kMips64S8x16InterleaveLeft},
    {{0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30},
     kMips64S8x16PackEven},
    {{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31},
     kMips64S8x16PackOdd},
    {{0, 16, 2, 18, 4, 20, 6, 22, 8, 24, 10, 26, 12, 28, 14, 30},
     kMips64S8x16InterleaveEven},
    {{1, 17, 3, 19, 5, 21, 7, 23, 9, 25, 11, 27, 13, 29, 15, 31},
     kMips64S8x16InterleaveOdd},
    {{7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8},
     kMips64S8x8Reverse},
    {{3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12},
     kMips64S8x4Reverse},
    {{1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14},
     kMips64S8x2Reverse}};

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
  // TODO(MIPS_dev): Properly use view here once Turboshaft support is
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
  Mips64OperandGeneratorT<TurbofanAdapter> g(this);
  if (wasm::SimdShuffle::TryMatchConcat(shuffle, &offset)) {
    Emit(kMips64S8x16Concat, g.DefineSameAsFirst(node), g.UseRegister(input1),
         g.UseRegister(input0), g.UseImmediate(offset));
    return;
  }
  if (wasm::SimdShuffle::TryMatch32x4Shuffle(shuffle, shuffle32x4)) {
    Emit(kMips64S32x4Shuffle, g.DefineAsRegister(node), g.UseRegister(input0),
         g.UseRegister(input1),
         g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle32x4)));
    return;
  }
  Emit(kMips64I8x16Shuffle, g.DefineAsRegister(node), g.UseRegister(input0),
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
    Mips64OperandGeneratorT<Adapter> g(this);
    InstructionOperand temps[] = {g.TempSimd128Register()};
    // We don't want input 0 or input 1 to be the same as output, since we will
    // modify output before do the calculation.
    Emit(kMips64I8x16Swizzle, g.DefineAsRegister(node),
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
  VisitRR(this, kMips64Seb, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord16ToInt32(node_t node) {
  VisitRR(this, kMips64Seh, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord8ToInt64(node_t node) {
  VisitRR(this, kMips64Seb, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord16ToInt64(node_t node) {
  VisitRR(this, kMips64Seh, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord32ToInt64(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    Mips64OperandGeneratorT<Adapter> g(this);
    Emit(kMips64Shl, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)),
         g.TempImmediate(0));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Pmin(node_t node) {
  VisitUniqueRRR(this, kMips64F32x4Pmin, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Pmax(node_t node) {
  VisitUniqueRRR(this, kMips64F32x4Pmax, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Pmin(node_t node) {
  VisitUniqueRRR(this, kMips64F64x2Pmin, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Pmax(node_t node) {
  VisitUniqueRRR(this, kMips64F64x2Pmax, node);
}

#define VISIT_EXT_MUL(OPCODE1, OPCODE2, TYPE)                              \
  template <typename Adapter>                                              \
  void InstructionSelectorT<Adapter>::Visit##OPCODE1##ExtMulLow##OPCODE2(  \
      node_t node) {                                                       \
    if constexpr (Adapter::IsTurboshaft) {                                 \
      UNIMPLEMENTED();                                                     \
    } else {                                                               \
      Mips64OperandGeneratorT<Adapter> g(this);                            \
      Emit(kMips64ExtMulLow | MiscField::encode(TYPE),                     \
           g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)),      \
           g.UseRegister(node->InputAt(1)));                               \
    }                                                                      \
  }                                                                        \
  template <typename Adapter>                                              \
  void InstructionSelectorT<Adapter>::Visit##OPCODE1##ExtMulHigh##OPCODE2( \
      node_t node) {                                                       \
    if constexpr (Adapter::IsTurboshaft) {                                 \
      UNIMPLEMENTED();                                                     \
    } else {                                                               \
      Mips64OperandGeneratorT<Adapter> g(this);                            \
      Emit(kMips64ExtMulHigh | MiscField::encode(TYPE),                    \
           g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)),      \
           g.UseRegister(node->InputAt(1)));                               \
    }                                                                      \
  }

VISIT_EXT_MUL(I64x2, I32x4S, MSAS32)
VISIT_EXT_MUL(I64x2, I32x4U, MSAU32)
VISIT_EXT_MUL(I32x4, I16x8S, MSAS16)
VISIT_EXT_MUL(I32x4, I16x8U, MSAU16)
VISIT_EXT_MUL(I16x8, I8x16S, MSAS8)
VISIT_EXT_MUL(I16x8, I8x16U, MSAU8)
#undef VISIT_EXT_MUL

#define VISIT_EXTADD_PAIRWISE(OPCODE, TYPE)                            \
  template <typename Adapter>                                          \
  void InstructionSelectorT<Adapter>::Visit##OPCODE(node_t node) {     \
    if constexpr (Adapter::IsTurboshaft) {                             \
      UNIMPLEMENTED();                                                 \
    } else {                                                           \
      Mips64OperandGeneratorT<Adapter> g(this);                        \
      Emit(kMips64ExtAddPairwise | MiscField::encode(TYPE),            \
           g.DefineAsRegister(node), g.UseRegister(node->InputAt(0))); \
    }                                                                  \
  }
VISIT_EXTADD_PAIRWISE(I16x8ExtAddPairwiseI8x16S, MSAS8)
VISIT_EXTADD_PAIRWISE(I16x8ExtAddPairwiseI8x16U, MSAU8)
VISIT_EXTADD_PAIRWISE(I32x4ExtAddPairwiseI16x8S, MSAS16)
VISIT_EXTADD_PAIRWISE(I32x4ExtAddPairwiseI16x8U, MSAU16)
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
  return flags | MachineOperatorBuilder::kWord32Ctz |
         MachineOperatorBuilder::kWord64Ctz |
         MachineOperatorBuilder::kWord32Popcnt |
         MachineOperatorBuilder::kWord64Popcnt |
         MachineOperatorBuilder::kWord32ShiftIsSafe |
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
  if (kArchVariant == kMips64r6) {
    return MachineOperatorBuilder::AlignmentRequirements::
        FullUnalignedAccessSupport();
  } else {
    DCHECK_EQ(kMips64r2, kArchVariant);
    return MachineOperatorBuilder::AlignmentRequirements::
        NoUnalignedAccessSupport();
  }
}

template class EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    InstructionSelectorT<TurbofanAdapter>;
template class EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    InstructionSelectorT<TurboshaftAdapter>;

#undef SIMD_BINOP_LIST
#undef SIMD_SHIFT_OP_LIST
#undef SIMD_RELAXED_OP_LIST
#undef SIMD_UNOP_LIST
#undef SIMD_TYPE_LIST
#undef TRACE

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```