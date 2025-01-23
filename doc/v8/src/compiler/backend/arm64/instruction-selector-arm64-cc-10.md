Response:
Let's break down the thought process for analyzing this C++ code snippet.

1. **Understand the Context:** The filename `instruction-selector-arm64.cc` and the namespace `v8::internal::compiler::backend::arm64` immediately tell us this code is part of V8, the JavaScript engine, specifically responsible for selecting ARM64 instructions during the compilation backend phase. The suffix `-arm64` is a strong indicator of architecture-specific logic.

2. **Identify the Core Class:**  The presence of `InstructionSelectorT<Adapter>` and its methods like `Visit...` strongly suggests this is a template class implementing a visitor pattern. The `<Adapter>` likely allows the class to be used in different compilation pipelines (e.g., Turbofan, Turboshaft).

3. **Analyze the `Visit` Methods:**  The numerous `Visit...` methods are the key to understanding the functionality. Each one seems to correspond to a specific operation or node type within V8's intermediate representation (IR). The names themselves are often indicative of the operation they handle (e.g., `VisitI16x8RelaxedLaneSelect`, `VisitF64x2Qfma`, `VisitI8x16Shuffle`).

4. **Focus on Recurring Patterns:** Notice the `VISIT_SIMD_QFMOP` macro. This signals a pattern for handling SIMD (Single Instruction, Multiple Data) floating-point fused multiply-add/subtract operations. This immediately tells us SIMD instruction selection is a significant part of this file's responsibility.

5. **Examine the `Shuffle` Logic:** The `ShuffleEntry` struct and the `arch_shuffles` array clearly deal with SIMD shuffle operations (rearranging elements within vectors). The `TryMatchArchShuffle` function suggests an attempt to directly map common shuffle patterns to specific ARM64 instructions for optimization. The `ArrangeShuffleTable` function reveals details about how input registers are managed for shuffle operations.

6. **Look for Architecture-Specific Instructions:**  Pay attention to identifiers prefixed with `kArm64` (e.g., `kArm64S32x4ZipLeft`, `kArm64Sxtb32`). These are directly related to ARM64 assembly instructions, confirming the file's role in low-level code generation.

7. **Consider the WebAssembly Integration:** The `#if V8_ENABLE_WEBASSEMBLY` blocks indicate that some functionality is specific to WebAssembly. The `Visit...` methods within these blocks likely handle WebAssembly-specific SIMD and conversion operations.

8. **Infer General Functionality:** Based on the observed patterns, we can start to list the functionalities:
    * Selecting ARM64 instructions for various operations.
    * Handling SIMD operations (arithmetic, shuffles, conversions).
    * Optimizing common SIMD patterns.
    * Supporting WebAssembly SIMD instructions.
    * Managing register allocation (implicitly through `OperandGenerator`).
    * Potentially handling stack pointer manipulation.
    * Supporting sign extension operations.

9. **Address the Specific Questions:** Now, go back to the prompt's specific questions:
    * **Functionality Listing:** Summarize the inferred functionalities.
    * **Torque:** Check if the filename ends in `.tq`. In this case, it doesn't.
    * **JavaScript Relationship:**  Since this is the *instruction selector*, it's deeply connected to how JavaScript's high-level operations are translated into low-level machine code. Think about SIMD operations in JavaScript and how they might be implemented. Provide a concrete JavaScript example that would trigger the kind of SIMD operations handled in the code.
    * **Code Logic Reasoning:** The shuffle logic provides a good example. Describe the input (shuffle mask), the process of matching against known patterns, and the output (specific ARM64 instruction). Provide a concrete example.
    * **Common Programming Errors:** Consider errors related to incorrect shuffle masks or type mismatches in SIMD operations.
    * **Part of a Whole:**  Recognize that this file is one part of a larger compilation pipeline and plays a crucial role in the backend.

10. **Refine and Organize:**  Structure the answer logically, starting with a high-level overview and then delving into specifics. Use clear language and provide concrete examples where possible. Ensure all parts of the prompt are addressed.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This just selects instructions."
* **Correction:** "It's more than just basic selection. It handles complex SIMD operations and optimizations."
* **Initial thought:** "The adapter is just a detail."
* **Correction:** "The adapter is important because it signifies the flexibility of the instruction selector to be used in different contexts."
* **Initial thought:** "JavaScript examples are hard to come up with."
* **Correction:** "Focus on the *concept* the code implements. If it's about SIMD shuffles, think about how JavaScript's TypedArrays or WebAssembly's SIMD features would use them."

By following these steps and continuously refining the understanding, one can effectively analyze and explain the functionality of this complex C++ code snippet.
好的，我们来分析一下 `v8/src/compiler/backend/arm64/instruction-selector-arm64.cc` 这个文件的功能。

**文件功能概览**

`v8/src/compiler/backend/arm64/instruction-selector-arm64.cc` 是 V8 JavaScript 引擎中，针对 ARM64 架构的**指令选择器 (Instruction Selector)** 的实现。 它的主要职责是将 V8 中间表示 (Intermediate Representation, IR) 中的节点 (nodes) 转换成具体的 ARM64 汇编指令。

**详细功能分解**

1. **访问 IR 节点并生成指令:**  文件中定义了多个 `Visit...` 方法，每个方法对应处理一种或多种 IR 节点。当编译器遍历 IR 图时，会调用相应的 `Visit` 方法。这些方法内部会根据节点的类型和操作，选择合适的 ARM64 指令，并生成指令对象。

2. **SIMD 指令支持 (重点):** 代码中大量涉及 SIMD (Single Instruction, Multiple Data) 相关的操作，例如：
    * `VisitI16x8RelaxedLaneSelect`, `VisitI32x4RelaxedLaneSelect`, `VisitI64x2RelaxedLaneSelect`: 处理 SIMD 通道选择操作。
    * `VISIT_SIMD_QFMOP` 宏和相关的 `VisitF64x2Qfma` 等方法：处理 SIMD 浮点数的融合乘加/减 (Fused Multiply-Add/Subtract) 操作。
    * `VisitI8x16Shuffle`: 处理 SIMD 数据的混洗 (shuffle) 操作。

3. **SIMD Shuffle 优化:**  代码中定义了 `ShuffleEntry` 结构体和 `arch_shuffles` 数组，用于匹配常见的 SIMD shuffle 模式到特定的 ARM64 指令，以实现优化。例如，`kArm64S32x4ZipLeft`, `kArm64S32x4UnzipRight` 等都是 ARM64 提供的优化指令。

4. **处理 WebAssembly SIMD 指令:**  通过 `#if V8_ENABLE_WEBASSEMBLY` 宏，可以看到针对 WebAssembly SIMD 指令的支持，例如：
    * `VisitF16x8Pmin`, `VisitF32x4Pmax` 等：处理 SIMD 的最小值/最大值操作。
    * `VisitI64x2SConvertI32x4Low` 等：处理 SIMD 数据类型的转换操作（例如，将多个 32 位整数转换为 64 位整数）。
    * `VisitI8x16Popcnt`: 处理 SIMD 向量中每个字节的 popcount (计算二进制表示中 1 的个数)。

5. **处理通用指令:** 除了 SIMD 指令，还处理一些通用的指令，例如：
    * `VisitSetStackPointer`: 设置栈指针。
    * `VisitSignExtendWord8ToInt32` 等：处理有符号扩展操作。

6. **辅助函数和数据结构:**  代码中包含了一些辅助函数，例如 `TryMatchArchShuffle`, `ArrangeShuffleTable`，以及用于存储 shuffle 模式的 `ShuffleEntry` 结构体。

**关于文件后缀 `.tq`**

根据您的描述，如果 `v8/src/compiler/backend/arm64/instruction-selector-arm64.cc` 以 `.tq` 结尾，那么它会是 V8 Torque 源代码。 然而，当前的文件后缀是 `.cc`，表明它是标准的 C++ 源代码。 Torque 是一种用于生成 V8 代码的领域特定语言，通常用于实现内置函数或一些性能关键的代码。

**与 JavaScript 的关系及示例**

`instruction-selector-arm64.cc` 的功能是将 V8 的 IR 转换为机器码，因此它直接影响 JavaScript 代码的执行效率。  当 JavaScript 代码中涉及到可以映射到 ARM64 特有指令的操作时，这个文件就起到了关键作用，尤其是 SIMD 相关的操作。

**JavaScript 示例 (SIMD)**

```javascript
// 使用 TypedArray 和 SIMD 操作
const a = new Float32Array([1.0, 2.0, 3.0, 4.0]);
const b = new Float32Array([5.0, 6.0, 7.0, 8.0]);

const va = SIMD.float32x4(a[0], a[1], a[2], a[3]);
const vb = SIMD.float32x4(b[0], b[1], b[2], b[3]);

const vc = SIMD.float32x4.add(va, vb); // SIMD 加法

console.log(vc); // 输出类似: Float32x4 { x: 6, y: 8, z: 10, w: 12 }
```

在这个例子中，`SIMD.float32x4.add` 操作在底层就可能通过 `instruction-selector-arm64.cc` 中的相关 `Visit` 方法，最终被翻译成 ARM64 的 SIMD 加法指令 (例如，VEADD.4S)。

**代码逻辑推理示例 (SIMD Shuffle)**

**假设输入:**

* **IR 节点类型:**  `kSimdShuffle` (表示 SIMD shuffle 操作)
* **输入向量 1 的值:**  `[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]` (可以想象成一个 16 字节的向量)
* **输入向量 2 的值:**  `[17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32]`
* **Shuffle Mask:** `[0, 1, 16, 17, 2, 3, 18, 19, 4, 5, 20, 21, 6, 7, 22, 23]` (表示从输入向量中选择哪些字节组成新的向量)

**输出:**

根据 `arch_shuffles` 中的定义，这个 shuffle mask 对应于 `kArm64S8x16ZipLeft` 指令。因此，指令选择器会生成一个 `kArm64S8x16ZipLeft` 的指令，操作数会指向输入向量 1 和输入向量 2 所在的寄存器。

**用户常见的编程错误 (与 SIMD 相关)**

1. **类型不匹配:**  在 JavaScript 中使用 SIMD 时，如果操作数的类型不匹配，会导致错误。例如，尝试将 `Float32x4` 向量与 `Int32x4` 向量相加。

   ```javascript
   const floatVec = SIMD.float32x4(1, 2, 3, 4);
   const intVec = SIMD.int32x4(5, 6, 7, 8);

   // 错误：不能直接将不同类型的 SIMD 向量相加
   // const result = SIMD.float32x4.add(floatVec, intVec);
   ```

2. **Shuffle Mask 错误:**  在 WebAssembly 中进行 SIMD shuffle 操作时，如果提供的 shuffle mask 超出范围 (例如，索引大于等于向量长度)，会导致未定义的行为或错误。

3. **性能陷阱:**  不恰当的使用 SIMD 操作可能不会带来预期的性能提升，反而可能因为数据重排或其他开销导致性能下降。例如，在数据量很小的情况下使用 SIMD 可能不如标量操作高效。

**归纳总结 (第 11 部分)**

作为第 11 部分，也是最后一部分，`v8/src/compiler/backend/arm64/instruction-selector-arm64.cc` 的功能可以被归纳为：

* **最终代码生成阶段的关键组件:** 它负责将编译器生成的与架构无关的中间表示，转化为特定于 ARM64 架构的可执行机器码指令。
* **针对 ARM64 进行优化:**  它利用 ARM64 架构提供的特性，例如 SIMD 指令，来提升 JavaScript 代码的执行效率。
* **连接高级语言和底层硬件:**  它是连接 JavaScript 抽象概念和 ARM64 硬件指令的桥梁。
* **保证代码正确性和性能:**  通过精确地选择和生成指令，它确保了生成的代码既能正确执行 JavaScript 逻辑，又能尽可能地高效运行。

总而言之，`v8/src/compiler/backend/arm64/instruction-selector-arm64.cc` 是 V8 引擎中至关重要的一个文件，它体现了编译器后端针对特定硬件架构进行优化的核心工作。

### 提示词
```
这是目录为v8/src/compiler/backend/arm64/instruction-selector-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/arm64/instruction-selector-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第11部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
id InstructionSelectorT<Adapter>::VisitI16x8RelaxedLaneSelect(node_t node) {
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

#define VISIT_SIMD_QFMOP(op)                                   \
  template <typename Adapter>                                  \
  void InstructionSelectorT<Adapter>::Visit##op(node_t node) { \
    Arm64OperandGeneratorT<Adapter> g(this);                   \
    Emit(kArm64##op, g.DefineSameAsInput(node, 2),             \
         g.UseRegister(this->input_at(node, 0)),               \
         g.UseRegister(this->input_at(node, 1)),               \
         g.UseRegister(this->input_at(node, 2)));              \
  }
VISIT_SIMD_QFMOP(F64x2Qfma)
VISIT_SIMD_QFMOP(F64x2Qfms)
VISIT_SIMD_QFMOP(F32x4Qfma)
VISIT_SIMD_QFMOP(F32x4Qfms)
VISIT_SIMD_QFMOP(F16x8Qfma)
VISIT_SIMD_QFMOP(F16x8Qfms)
#undef VISIT_SIMD_QFMOP

namespace {

struct ShuffleEntry {
  uint8_t shuffle[kSimd128Size];
  ArchOpcode opcode;
};

static const ShuffleEntry arch_shuffles[] = {
    {{0, 1, 2, 3, 16, 17, 18, 19, 4, 5, 6, 7, 20, 21, 22, 23},
     kArm64S32x4ZipLeft},
    {{8, 9, 10, 11, 24, 25, 26, 27, 12, 13, 14, 15, 28, 29, 30, 31},
     kArm64S32x4ZipRight},
    {{0, 1, 2, 3, 8, 9, 10, 11, 16, 17, 18, 19, 24, 25, 26, 27},
     kArm64S32x4UnzipLeft},
    {{4, 5, 6, 7, 12, 13, 14, 15, 20, 21, 22, 23, 28, 29, 30, 31},
     kArm64S32x4UnzipRight},
    {{0, 1, 2, 3, 16, 17, 18, 19, 8, 9, 10, 11, 24, 25, 26, 27},
     kArm64S32x4TransposeLeft},
    {{4, 5, 6, 7, 20, 21, 22, 23, 12, 13, 14, 15, 21, 22, 23, 24},
     kArm64S32x4TransposeRight},
    {{4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11},
     kArm64S32x2Reverse},

    {{0, 1, 16, 17, 2, 3, 18, 19, 4, 5, 20, 21, 6, 7, 22, 23},
     kArm64S16x8ZipLeft},
    {{8, 9, 24, 25, 10, 11, 26, 27, 12, 13, 28, 29, 14, 15, 30, 31},
     kArm64S16x8ZipRight},
    {{0, 1, 4, 5, 8, 9, 12, 13, 16, 17, 20, 21, 24, 25, 28, 29},
     kArm64S16x8UnzipLeft},
    {{2, 3, 6, 7, 10, 11, 14, 15, 18, 19, 22, 23, 26, 27, 30, 31},
     kArm64S16x8UnzipRight},
    {{0, 1, 16, 17, 4, 5, 20, 21, 8, 9, 24, 25, 12, 13, 28, 29},
     kArm64S16x8TransposeLeft},
    {{2, 3, 18, 19, 6, 7, 22, 23, 10, 11, 26, 27, 14, 15, 30, 31},
     kArm64S16x8TransposeRight},
    {{6, 7, 4, 5, 2, 3, 0, 1, 14, 15, 12, 13, 10, 11, 8, 9},
     kArm64S16x4Reverse},
    {{2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13},
     kArm64S16x2Reverse},

    {{0, 16, 1, 17, 2, 18, 3, 19, 4, 20, 5, 21, 6, 22, 7, 23},
     kArm64S8x16ZipLeft},
    {{8, 24, 9, 25, 10, 26, 11, 27, 12, 28, 13, 29, 14, 30, 15, 31},
     kArm64S8x16ZipRight},
    {{0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30},
     kArm64S8x16UnzipLeft},
    {{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31},
     kArm64S8x16UnzipRight},
    {{0, 16, 2, 18, 4, 20, 6, 22, 8, 24, 10, 26, 12, 28, 14, 30},
     kArm64S8x16TransposeLeft},
    {{1, 17, 3, 19, 5, 21, 7, 23, 9, 25, 11, 27, 13, 29, 15, 31},
     kArm64S8x16TransposeRight},
    {{7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8}, kArm64S8x8Reverse},
    {{3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12}, kArm64S8x4Reverse},
    {{1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14},
     kArm64S8x2Reverse}};

bool TryMatchArchShuffle(const uint8_t* shuffle, const ShuffleEntry* table,
                         size_t num_entries, bool is_swizzle,
                         ArchOpcode* opcode) {
  uint8_t mask = is_swizzle ? kSimd128Size - 1 : 2 * kSimd128Size - 1;
  for (size_t i = 0; i < num_entries; i++) {
    const ShuffleEntry& entry = table[i];
    int j = 0;
    for (; j < kSimd128Size; j++) {
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

template <typename Adapter>
void ArrangeShuffleTable(Arm64OperandGeneratorT<Adapter>* g,
                         typename Adapter::node_t input0,
                         typename Adapter::node_t input1,
                         InstructionOperand* src0, InstructionOperand* src1) {
  if (input0 == input1) {
    // Unary, any q-register can be the table.
    *src0 = *src1 = g->UseRegister(input0);
  } else {
    // Binary, table registers must be consecutive.
    *src0 = g->UseFixed(input0, fp_fixed1);
    *src1 = g->UseFixed(input1, fp_fixed2);
  }
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Shuffle(node_t node) {
  uint8_t shuffle[kSimd128Size];
  bool is_swizzle;
  auto view = this->simd_shuffle_view(node);
  CanonicalizeShuffle(view, shuffle, &is_swizzle);
  node_t input0 = view.input(0);
  node_t input1 = view.input(1);
  uint8_t shuffle32x4[4];
  Arm64OperandGeneratorT<Adapter> g(this);
  ArchOpcode opcode;
  if (TryMatchArchShuffle(shuffle, arch_shuffles, arraysize(arch_shuffles),
                          is_swizzle, &opcode)) {
    Emit(opcode, g.DefineAsRegister(node), g.UseRegister(input0),
         g.UseRegister(input1));
    return;
  }
  uint8_t offset;
  if (wasm::SimdShuffle::TryMatchConcat(shuffle, &offset)) {
    Emit(kArm64S8x16Concat, g.DefineAsRegister(node), g.UseRegister(input0),
         g.UseRegister(input1), g.UseImmediate(offset));
    return;
  }
  int index = 0;
  uint8_t from = 0;
  uint8_t to = 0;
  if (wasm::SimdShuffle::TryMatch32x4Shuffle(shuffle, shuffle32x4)) {
    if (wasm::SimdShuffle::TryMatchSplat<4>(shuffle, &index)) {
      DCHECK_GT(4, index);
      Emit(kArm64S128Dup, g.DefineAsRegister(node), g.UseRegister(input0),
           g.UseImmediate(4), g.UseImmediate(index % 4));
    } else if (wasm::SimdShuffle::TryMatch32x4Reverse(shuffle32x4)) {
      Emit(kArm64S32x4Reverse, g.DefineAsRegister(node), g.UseRegister(input0));
    } else if (wasm::SimdShuffle::TryMatch32x4OneLaneSwizzle(shuffle32x4, &from,
                                                             &to)) {
      Emit(kArm64S32x4OneLaneSwizzle, g.DefineAsRegister(node),
           g.UseRegister(input0), g.TempImmediate(from), g.TempImmediate(to));
    } else if (wasm::SimdShuffle::TryMatchIdentity(shuffle)) {
      // Bypass normal shuffle code generation in this case.
      // EmitIdentity
      MarkAsUsed(input0);
      MarkAsDefined(node);
      SetRename(node, input0);
    } else {
      Emit(kArm64S32x4Shuffle, g.DefineAsRegister(node), g.UseRegister(input0),
           g.UseRegister(input1),
           g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle32x4)));
    }
    return;
  }
  if (wasm::SimdShuffle::TryMatchSplat<8>(shuffle, &index)) {
    DCHECK_GT(8, index);
    Emit(kArm64S128Dup, g.DefineAsRegister(node), g.UseRegister(input0),
         g.UseImmediate(8), g.UseImmediate(index % 8));
    return;
  }
  if (wasm::SimdShuffle::TryMatchSplat<16>(shuffle, &index)) {
    DCHECK_GT(16, index);
    Emit(kArm64S128Dup, g.DefineAsRegister(node), g.UseRegister(input0),
         g.UseImmediate(16), g.UseImmediate(index % 16));
    return;
  }
  // Code generator uses vtbl, arrange sources to form a valid lookup table.
  InstructionOperand src0, src1;
  ArrangeShuffleTable(&g, input0, input1, &src0, &src1);
  Emit(kArm64I8x16Shuffle, g.DefineAsRegister(node), src0, src1,
       g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle)),
       g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle + 4)),
       g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle + 8)),
       g.UseImmediate(wasm::SimdShuffle::Pack4Lanes(shuffle + 12)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSetStackPointer(node_t node) {
  OperandGenerator g(this);
  auto input = g.UseRegister(this->input_at(node, 0));
  Emit(kArchSetStackPointer, 0, nullptr, 1, &input);
}

#endif  // V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord8ToInt32(node_t node) {
  VisitRR(this, kArm64Sxtb32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord16ToInt32(node_t node) {
  VisitRR(this, kArm64Sxth32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord8ToInt64(node_t node) {
  VisitRR(this, kArm64Sxtb, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord16ToInt64(node_t node) {
  VisitRR(this, kArm64Sxth, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSignExtendWord32ToInt64(node_t node) {
  VisitRR(this, kArm64Sxtw, node);
}

#if V8_ENABLE_WEBASSEMBLY
namespace {
template <typename Adapter>
void VisitPminOrPmax(InstructionSelectorT<Adapter>* selector, ArchOpcode opcode,
                     typename Adapter::node_t node) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  // Need all unique registers because we first compare the two inputs, then
  // we need the inputs to remain unchanged for the bitselect later.
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseUniqueRegister(selector->input_at(node, 0)),
                 g.UseUniqueRegister(selector->input_at(node, 1)));
}
}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF16x8Pmin(node_t node) {
  VisitPminOrPmax(this, kArm64F16x8Pmin, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF16x8Pmax(node_t node) {
  VisitPminOrPmax(this, kArm64F16x8Pmax, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Pmin(node_t node) {
  VisitPminOrPmax(this, kArm64F32x4Pmin, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Pmax(node_t node) {
  VisitPminOrPmax(this, kArm64F32x4Pmax, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Pmin(node_t node) {
  VisitPminOrPmax(this, kArm64F64x2Pmin, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Pmax(node_t node) {
  VisitPminOrPmax(this, kArm64F64x2Pmax, node);
}

namespace {
template <typename Adapter>
void VisitSignExtendLong(InstructionSelectorT<Adapter>* selector,
                         ArchOpcode opcode, typename Adapter::node_t node,
                         int lane_size) {
  InstructionCode code = opcode;
  code |= LaneSizeField::encode(lane_size);
  VisitRR(selector, code, node);
}
}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2SConvertI32x4Low(node_t node) {
  VisitSignExtendLong(this, kArm64Sxtl, node, 64);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2SConvertI32x4High(node_t node) {
  VisitSignExtendLong(this, kArm64Sxtl2, node, 64);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2UConvertI32x4Low(node_t node) {
  VisitSignExtendLong(this, kArm64Uxtl, node, 64);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2UConvertI32x4High(node_t node) {
  VisitSignExtendLong(this, kArm64Uxtl2, node, 64);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4SConvertI16x8Low(node_t node) {
  VisitSignExtendLong(this, kArm64Sxtl, node, 32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4SConvertI16x8High(node_t node) {
  VisitSignExtendLong(this, kArm64Sxtl2, node, 32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4UConvertI16x8Low(node_t node) {
  VisitSignExtendLong(this, kArm64Uxtl, node, 32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4UConvertI16x8High(node_t node) {
  VisitSignExtendLong(this, kArm64Uxtl2, node, 32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8SConvertI8x16Low(node_t node) {
  VisitSignExtendLong(this, kArm64Sxtl, node, 16);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8SConvertI8x16High(node_t node) {
  VisitSignExtendLong(this, kArm64Sxtl2, node, 16);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8UConvertI8x16Low(node_t node) {
  VisitSignExtendLong(this, kArm64Uxtl, node, 16);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8UConvertI8x16High(node_t node) {
  VisitSignExtendLong(this, kArm64Uxtl2, node, 16);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Popcnt(node_t node) {
  InstructionCode code = kArm64Cnt;
  code |= LaneSizeField::encode(8);
  VisitRR(this, code, node);
}
#endif  // V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void InstructionSelectorT<Adapter>::AddOutputToSelectContinuation(
    OperandGenerator* g, int first_input_index, node_t node) {
  continuation_outputs_.push_back(g->DefineAsRegister(node));
}

// static
MachineOperatorBuilder::Flags
InstructionSelector::SupportedMachineOperatorFlags() {
  auto flags = MachineOperatorBuilder::kFloat32RoundDown |
               MachineOperatorBuilder::kFloat64RoundDown |
               MachineOperatorBuilder::kFloat32RoundUp |
               MachineOperatorBuilder::kFloat64RoundUp |
               MachineOperatorBuilder::kFloat32RoundTruncate |
               MachineOperatorBuilder::kFloat64RoundTruncate |
               MachineOperatorBuilder::kFloat64RoundTiesAway |
               MachineOperatorBuilder::kFloat32RoundTiesEven |
               MachineOperatorBuilder::kFloat64RoundTiesEven |
               MachineOperatorBuilder::kWord32Popcnt |
               MachineOperatorBuilder::kWord64Popcnt |
               MachineOperatorBuilder::kWord32ShiftIsSafe |
               MachineOperatorBuilder::kInt32DivIsSafe |
               MachineOperatorBuilder::kUint32DivIsSafe |
               MachineOperatorBuilder::kWord32ReverseBits |
               MachineOperatorBuilder::kWord64ReverseBits |
               MachineOperatorBuilder::kSatConversionIsSafe |
               MachineOperatorBuilder::kFloat32Select |
               MachineOperatorBuilder::kFloat64Select |
               MachineOperatorBuilder::kWord32Select |
               MachineOperatorBuilder::kWord64Select |
               MachineOperatorBuilder::kLoadStorePairs;
  if (CpuFeatures::IsSupported(FP16)) {
    flags |= MachineOperatorBuilder::kFloat16 |
             MachineOperatorBuilder::kTruncateFloat64ToFloat16RawBits;
  }
  return flags;
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

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```