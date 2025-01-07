Response:
The user wants me to analyze a C++ code snippet from V8's `instruction-selector-ia32.cc` file. Specifically, they want to know the functionality of this code, considering aspects like its potential nature as a Torque file, its relation to JavaScript, illustrative examples, logical reasoning, common programming errors, and a summary of its purpose.

Here's a breakdown of my thought process:

1. **Identify the Core Function:** The code consists of template specializations of `InstructionSelectorT` for different node types. These node types (`VisitF64x2Min`, `VisitI64x2SplatI32Pair`, `VisitI8x16Shuffle`, etc.) suggest that this code is involved in selecting specific IA-32 instructions for operations represented in an intermediate representation (IR) of a program. The presence of `Emit` calls confirms this, as `Emit` is likely a function to output the selected instruction.

2. **Determine if it's a Torque file:** The prompt explicitly asks if the `.cc` extension could mean it's a Torque file. This is incorrect. Torque files use the `.tq` extension. I need to state this clearly.

3. **Assess JavaScript Relevance:** The code is part of V8, the JavaScript engine. Therefore, it's directly related to how JavaScript code is compiled and executed on IA-32 architectures. The operations handled in the code (SIMD operations like `F64x2Min`, `I64x2SplatI32Pair`, shuffles, etc.) are often used to optimize JavaScript, particularly in areas like WebAssembly or when using typed arrays. I should provide a JavaScript example demonstrating a scenario where such optimizations might be relevant.

4. **Illustrate with Examples and Logical Reasoning:** For each function, I need to:
    * **Identify the operation:**  What kind of computation is being performed (e.g., finding the minimum of two double-precision vectors, creating a 128-bit constant)?
    * **Describe the IA-32 instructions:**  What specific IA-32 instructions are being emitted based on CPU features (AVX or SSE)?
    * **Simulate input and output (if applicable):** For functions dealing with data manipulation (like `VisitI8x16Shuffle`), provide an example of input data and the expected output after the shuffle operation. This helps illustrate the logic.

5. **Consider Common Programming Errors:** While this specific code deals with instruction selection, a common error related to the *use* of these optimized operations in JavaScript (especially WebAssembly) is providing incorrect input types or sizes, leading to runtime errors or unexpected behavior. I should provide such an example.

6. **Address the "Part X of Y" Instruction:** The prompt indicates this is part 5 of 6. This suggests a larger context of instruction selection. I should summarize the code's function within this broader context, highlighting that it's responsible for handling specific SIMD and other operations for the IA-32 architecture.

7. **Structure the Response:** I will organize my answer by addressing each of the user's requests systematically. This will make the explanation clear and easy to follow.

**(Self-Correction/Refinement):**  Initially, I might focus too much on the low-level details of each instruction. However, the user's request is more about the *overall functionality* within the V8 context. Therefore, while mentioning specific instructions is important, I should also emphasize the higher-level purpose of instruction selection and how it contributes to JavaScript performance. I also need to be careful to distinguish between the Turbofan and Turboshaft adapters where the code explicitly handles them differently. For the shuffle operation, it's crucial to explain the different cases and the rationale behind choosing specific IA-32 instructions. Finally, for the "common errors" section, I should ensure the example is relevant to the *effects* of the optimized code, even if the error isn't directly within the C++ snippet itself.
这是目录为 `v8/src/compiler/backend/ia32/instruction-selector-ia32.cc` 的一个 V8 源代码片段。它属于 V8 引擎的**后端编译器**部分，负责将中间表示 (IR) 的代码转换为特定目标架构（在本例中为 IA-32）的机器指令。

**以下是它的功能列表：**

1. **指令选择 (Instruction Selection):** 这是其核心功能。代码中的 `InstructionSelectorT` 类以及其 `Visit...` 方法定义了如何将各种高级操作（在编译器 IR 中表示为节点）转换为对应的 IA-32 机器指令序列。

2. **SIMD 指令支持 (SIMD Instruction Support):**  该代码片段主要关注 SIMD (Single Instruction, Multiple Data) 向量操作，特别是 128 位 SIMD 指令（通常对应于 SSE 和 AVX 指令集）。它处理了各种 SIMD 操作，例如：
    * **创建 SIMD 常量 (`VisitS128Const`)**:  将一个 128 位常量加载到 SIMD 寄存器中。
    * **浮点 SIMD 操作 (`VisitF64x2Min`, `VisitF64x2Max`, `VisitF32x4Splat` 等)**:  执行双精度和单精度浮点向量的最小值、最大值、复制等操作。
    * **整数 SIMD 操作 (`VisitI64x2Neg`, `VisitI64x2ShrS`, `VisitI32x4SConvertF32x4` 等)**:  执行有符号和无符号整数向量的取反、右移、类型转换等操作。
    * **SIMD 逻辑操作 (`VisitS128Zero`, `VisitS128Select`, `VisitS128AndNot`)**:  执行 SIMD 向量的置零、选择、按位与非等逻辑操作。
    * **SIMD 元素提取和替换 (`VisitF64x2ExtractLane`, `VisitI32x4ReplaceLane`)**:  从 SIMD 向量中提取特定元素或替换特定元素。
    * **SIMD 移位操作 (`VisitI8x16Shl`, `VisitI8x16ShrS`, `VisitI8x16ShrU`)**:  执行 SIMD 向量的左移和右移操作。
    * **SIMD 混洗操作 (`VisitI8x16Shuffle`, `VisitI8x16Swizzle`)**:  重新排列 SIMD 向量中的元素。
    * **SIMD 类型转换 (`VisitF32x4UConvertI32x4`, `VisitI32x4UConvertF32x4`)**:  在不同 SIMD 数据类型之间进行转换。
    * **SIMD 聚合操作 (`VisitV128AnyTrue`, `VisitI16x8BitMask`)**:  检查 SIMD 向量中是否有任何元素为真，或生成位掩码。

3. **架构特性感知 (Architecture Feature Awareness):** 代码中使用了 `IsSupported(AVX)` 来检查处理器是否支持 AVX 指令集。这允许代码为支持 AVX 的处理器生成更优化的指令，否则使用 SSE 指令。

4. **Turbofan 和 Turboshaft 支持 (Turbofan and Turboshaft Support):** 代码使用了模板 `InstructionSelectorT<Adapter>`，其中 `Adapter` 可以是 `TurbofanAdapter` 或 `TurboshaftAdapter`。这表明该代码同时支持 V8 的两个编译器管道：
    * **Turbofan:** V8 的主要优化编译器。
    * **Turboshaft:** V8 的下一代编译器。
    针对不同的编译器管道，某些操作的处理方式可能不同（例如，`VisitI64x2SplatI32Pair` 和 `VisitI64x2ReplaceLaneI32Pair` 在 Turboshaft 中被降低到其他操作）。

5. **零和全一优化:** 在处理 SIMD 常量时 (`VisitS128Const`)，代码会检查常量是否全零或全一。如果是，则会使用特定的 `kIA32S128Zero` 或 `kIA32S128AllOnes` 指令，避免生成通用的常量加载代码。

**关于 `.tq` 结尾：**

`v8/src/compiler/backend/ia32/instruction-selector-ia32.cc` 以 `.cc` 结尾，表示它是一个标准的 C++ 源文件。如果文件名以 `.tq` 结尾，那才表示它是一个 **V8 Torque 源代码**。Torque 是一种用于定义 V8 内部 API 和运行时函数的领域特定语言。

**与 JavaScript 功能的关系及示例：**

这段代码直接影响 JavaScript 代码在 IA-32 架构上的执行效率。当 JavaScript 代码执行某些操作时，V8 的编译器会将其转换为一系列 IR 节点。`instruction-selector-ia32.cc` 的作用就是将这些节点转换为高效的 IA-32 机器码。

例如，JavaScript 的 `Math.min` 和 `Math.max` 函数在某些场景下可以被编译器优化为 SIMD 指令。同样，WebAssembly 的 SIMD 指令会直接映射到这里的代码进行处理。

**JavaScript 示例：**

```javascript
// 使用 Math.min 处理数组中的最小值 (可能被优化为 SIMD)
const arr1 = [1.5, 2.7, 0.8, 3.1];
const arr2 = [2.0, 1.9, 1.2, 2.5];
const result = [
  Math.min(arr1[0], arr2[0]),
  Math.min(arr1[1], arr2[1]),
  Math.min(arr1[2], arr2[2]),
  Math.min(arr1[3], arr2[3]),
];
console.log(result); // 输出: [1.5, 1.9, 0.8, 2.5]

// 使用 WebAssembly SIMD 指令
// (需要 WebAssembly 环境)
// 假设有一个 WebAssembly 模块导出了一个名为 f64x2_min 的函数
// 该函数接受两个 f64x2 类型的参数并返回它们的最小值
// const instance = ... // 加载 WebAssembly 模块
// const a = new Float64Array([1.0, 2.0]);
// const b = new Float64Array([3.0, 0.5]);
// const result_wasm = instance.exports.f64x2_min(a, b);
// console.log(result_wasm); // 输出类似: [1.0, 0.5]
```

在这些例子中，当 V8 编译器遇到这些操作时，`VisitF64x2Min` 等方法会被调用，并根据目标架构和可用特性选择合适的 IA-32 `minpd` (SSE) 或 `vminpd` (AVX) 指令。

**代码逻辑推理示例：**

**假设输入:**  一个表示 `F64x2Min` 操作的 IR 节点，其输入是两个指向双精度浮点数数组的寄存器。

**输出:**  如果支持 AVX，则会 `Emit(kIA32F64x2Min, dst, operand0, operand1)`，生成一个使用 AVX 指令 `vminpd` 的机器指令，将两个输入寄存器中的双精度浮点向量进行按元素最小值比较，并将结果存储到目标寄存器 `dst` 中。如果不支持 AVX，则会 `Emit(kIA32F64x2Min, g.DefineSameAsFirst(node), operand0, operand1)`，可能使用 SSE 指令 `minpd`，并且将结果存储回第一个操作数所在的寄存器，以节省一次移动操作。

**用户常见的编程错误示例：**

涉及到 SIMD 操作时，用户常见的编程错误包括：

* **数据类型不匹配:**  例如，尝试将整数 SIMD 操作应用于浮点数数组，或者混合使用不同大小的 SIMD 向量。
* **内存对齐问题:**  某些 SIMD 指令要求操作数在内存中是特定大小对齐的（例如，16 字节对齐）。如果数据未对齐，可能会导致性能下降甚至程序崩溃。
* **越界访问:**  在进行 SIMD 操作时，确保操作不会超出数组的边界。
* **错误的混洗模式:**  在 `VisitI8x16Shuffle` 等操作中，提供错误的混洗模式会导致得到非预期的结果。

**示例 (JavaScript/WebAssembly):**

```javascript
// 错误地尝试将整数 SIMD 操作应用于浮点数数组 (WebAssembly)
// (假设 i32x4.add 是一个接受 i32x4 类型的函数)
// const floatArray = new Float32Array([1.0, 2.0, 3.0, 4.0]);
// const intArrayView = new Int32Array(floatArray.buffer);
// instance.exports.i32x4_add(intArrayView, intArrayView); // 可能会导致类型错误或非预期结果

// 内存对齐问题 (在 JavaScript 中不容易直接触发，但在底层 C++ 或 WebAssembly 中需要注意)
// 如果在 C++ 中手动分配内存并传递给 WebAssembly 进行 SIMD 操作，
// 必须确保内存是 16 字节对齐的。

// 错误的混洗模式 (WebAssembly)
// const a = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
// const shuffleMask = new Uint8Array([15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]);
// const resultShuffle = instance.exports.i8x16_shuffle(a, shuffleMask); // 如果 shuffleMask 超出范围或模式错误，结果可能不正确
```

**第 5 部分，共 6 部分的功能归纳:**

作为指令选择过程的第五部分，这段代码主要负责 **将 IR 中表示的 SIMD (向量) 操作转换为 IA-32 架构特定的机器指令**。它涵盖了浮点、整数、逻辑、混洗等多种 SIMD 操作，并且能够根据处理器是否支持 AVX 指令集来选择不同的指令。此外，它还处理了一些非 SIMD 但与指令选择相关的操作（例如，设置堆栈指针）。这段代码是 V8 编译器后端优化的关键组成部分，直接影响 JavaScript 和 WebAssembly 代码在 IA-32 处理器上的执行效率。它体现了 V8 对现代处理器 SIMD 特性的利用，以提升性能。

Prompt: 
```
这是目录为v8/src/compiler/backend/ia32/instruction-selector-ia32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/ia32/instruction-selector-ia32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能

"""
 IA32OperandGeneratorT<Adapter> g(this);
  static const int kUint32Immediates = kSimd128Size / sizeof(uint32_t);
  uint32_t val[kUint32Immediates];
  if constexpr (Adapter::IsTurboshaft) {
    const turboshaft::Simd128ConstantOp& constant =
        this->Get(node).template Cast<turboshaft::Simd128ConstantOp>();
    memcpy(val, constant.value, kSimd128Size);
  } else {
    memcpy(val, S128ImmediateParameterOf(node->op()).data(), kSimd128Size);
  }
  // If all bytes are zeros or ones, avoid emitting code for generic constants
  bool all_zeros = !(val[0] || val[1] || val[2] || val[3]);
  bool all_ones = val[0] == UINT32_MAX && val[1] == UINT32_MAX &&
                  val[2] == UINT32_MAX && val[3] == UINT32_MAX;
  InstructionOperand dst = g.DefineAsRegister(node);
  if (all_zeros) {
    Emit(kIA32S128Zero, dst);
  } else if (all_ones) {
    Emit(kIA32S128AllOnes, dst);
  } else {
    InstructionOperand inputs[kUint32Immediates];
    for (int i = 0; i < kUint32Immediates; ++i) {
      inputs[i] = g.UseImmediate(val[i]);
    }
    InstructionOperand temp(g.TempRegister());
    Emit(kIA32S128Const, 1, &dst, kUint32Immediates, inputs, 1, &temp);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Min(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand operand0 = g.UseRegister(this->input_at(node, 0));
  InstructionOperand operand1 = g.UseRegister(this->input_at(node, 1));

  if (IsSupported(AVX)) {
    Emit(kIA32F64x2Min, g.DefineAsRegister(node), operand0, operand1);
  } else {
    Emit(kIA32F64x2Min, g.DefineSameAsFirst(node), operand0, operand1);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Max(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand operand0 = g.UseRegister(this->input_at(node, 0));
  InstructionOperand operand1 = g.UseRegister(this->input_at(node, 1));
  if (IsSupported(AVX)) {
    Emit(kIA32F64x2Max, g.DefineAsRegister(node), operand0, operand1);
  } else {
    Emit(kIA32F64x2Max, g.DefineSameAsFirst(node), operand0, operand1);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2Splat(node_t node) {
  VisitRRSimd(this, node, kIA32F64x2Splat);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF64x2ExtractLane(node_t node) {
  VisitRRISimd(this, node, kIA32F64x2ExtractLane, kIA32F64x2ExtractLane);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitI64x2SplatI32Pair(
    node_t node) {
  // In turboshaft it gets lowered to an I32x4Splat.
  UNREACHABLE();
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitI64x2SplatI32Pair(Node* node) {
  IA32OperandGeneratorT<TurbofanAdapter> g(this);
  Int32Matcher match_left(node->InputAt(0));
  Int32Matcher match_right(node->InputAt(1));
  if (match_left.Is(0) && match_right.Is(0)) {
    Emit(kIA32S128Zero, g.DefineAsRegister(node));
  } else {
    InstructionOperand operand0 = g.UseRegister(node->InputAt(0));
    InstructionOperand operand1 = g.Use(node->InputAt(1));
    Emit(kIA32I64x2SplatI32Pair, g.DefineAsRegister(node), operand0, operand1);
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitI64x2ReplaceLaneI32Pair(
    node_t node) {
  // In turboshaft it gets lowered to an I32x4ReplaceLane.
  UNREACHABLE();
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitI64x2ReplaceLaneI32Pair(
    Node* node) {
  IA32OperandGeneratorT<TurbofanAdapter> g(this);
  InstructionOperand operand = g.UseRegister(node->InputAt(0));
  InstructionOperand lane = g.UseImmediate(OpParameter<int32_t>(node->op()));
  InstructionOperand low = g.Use(node->InputAt(1));
  InstructionOperand high = g.Use(node->InputAt(2));
  Emit(kIA32I64x2ReplaceLaneI32Pair, g.DefineSameAsFirst(node), operand, lane,
       low, high);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2Neg(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  // If AVX unsupported, make sure dst != src to avoid a move.
  InstructionOperand operand0 =
      IsSupported(AVX) ? g.UseRegister(this->input_at(node, 0))
                       : g.UseUniqueRegister(this->input_at(node, 0));
  Emit(kIA32I64x2Neg, g.DefineAsRegister(node), operand0);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2ShrS(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand dst =
      IsSupported(AVX) ? g.DefineAsRegister(node) : g.DefineSameAsFirst(node);

  if (g.CanBeImmediate(this->input_at(node, 1))) {
    Emit(kIA32I64x2ShrS, dst, g.UseRegister(this->input_at(node, 0)),
         g.UseImmediate(this->input_at(node, 1)));
  } else {
    InstructionOperand temps[] = {g.TempSimd128Register(), g.TempRegister()};
    Emit(kIA32I64x2ShrS, dst, g.UseUniqueRegister(this->input_at(node, 0)),
         g.UseRegister(this->input_at(node, 1)), arraysize(temps), temps);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI64x2Mul(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempSimd128Register(),
                                g.TempSimd128Register()};
  Emit(kIA32I64x2Mul, g.DefineAsRegister(node),
       g.UseUniqueRegister(this->input_at(node, 0)),
       g.UseUniqueRegister(this->input_at(node, 1)), arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4Splat(node_t node) {
  VisitRRSimd(this, node, kIA32F32x4Splat);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4ExtractLane(node_t node) {
  VisitRRISimd(this, node, kIA32F32x4ExtractLane);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF32x4UConvertI32x4(node_t node) {
  VisitRRSimd(this, node, kIA32F32x4UConvertI32x4);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4SConvertF32x4(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempRegister()};
  InstructionOperand dst =
      IsSupported(AVX) ? g.DefineAsRegister(node) : g.DefineSameAsFirst(node);
  Emit(kIA32I32x4SConvertF32x4, dst, g.UseRegister(this->input_at(node, 0)),
       arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4UConvertF32x4(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempSimd128Register(),
                                g.TempSimd128Register()};
  InstructionCode opcode =
      IsSupported(AVX) ? kAVXI32x4UConvertF32x4 : kSSEI32x4UConvertF32x4;
  Emit(opcode, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 0)), arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Zero(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  Emit(kIA32S128Zero, g.DefineAsRegister(node));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128Select(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand dst =
      IsSupported(AVX) ? g.DefineAsRegister(node) : g.DefineSameAsFirst(node);
  Emit(kIA32S128Select, dst, g.UseRegister(this->input_at(node, 0)),
       g.UseRegister(this->input_at(node, 1)),
       g.UseRegister(this->input_at(node, 2)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitS128AndNot(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  // andnps a b does ~a & b, but we want a & !b, so flip the input.
  InstructionOperand dst =
      IsSupported(AVX) ? g.DefineAsRegister(node) : g.DefineSameAsFirst(node);
  Emit(kIA32S128AndNot, dst, g.UseRegister(this->input_at(node, 1)),
       g.UseRegister(this->input_at(node, 0)));
}

#define VISIT_SIMD_SPLAT(Type)                                          \
  template <typename Adapter>                                           \
  void InstructionSelectorT<Adapter>::Visit##Type##Splat(node_t node) { \
    bool set_zero;                                                      \
    if constexpr (Adapter::IsTurboshaft) {                              \
      set_zero = this->MatchIntegralZero(this->input_at(node, 0));      \
    } else {                                                            \
      set_zero = Int32Matcher(node->InputAt(0)).Is(0);                  \
    }                                                                   \
    if (set_zero) {                                                     \
      IA32OperandGeneratorT<Adapter> g(this);                           \
      Emit(kIA32S128Zero, g.DefineAsRegister(node));                    \
    } else {                                                            \
      VisitRO(this, node, kIA32##Type##Splat);                          \
    }                                                                   \
  }
SIMD_INT_TYPES(VISIT_SIMD_SPLAT)
#undef SIMD_INT_TYPES
#undef VISIT_SIMD_SPLAT

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF16x8Splat(node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16ExtractLaneU(node_t node) {
  VisitRRISimd(this, node, kIA32Pextrb);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16ExtractLaneS(node_t node) {
  VisitRRISimd(this, node, kIA32I8x16ExtractLaneS);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8ExtractLaneU(node_t node) {
  VisitRRISimd(this, node, kIA32Pextrw);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8ExtractLaneS(node_t node) {
  VisitRRISimd(this, node, kIA32I16x8ExtractLaneS);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI32x4ExtractLane(node_t node) {
  VisitRRISimd(this, node, kIA32I32x4ExtractLane);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF16x8ExtractLane(node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitF16x8ReplaceLane(node_t node) {
  UNIMPLEMENTED();
}

#define SIMD_REPLACE_LANE_TYPE_OP(V) \
  V(I32x4, kIA32Pinsrd)              \
  V(I16x8, kIA32Pinsrw)              \
  V(I8x16, kIA32Pinsrb)              \
  V(F32x4, kIA32Insertps)            \
  V(F64x2, kIA32F64x2ReplaceLane)

#define VISIT_SIMD_REPLACE_LANE(TYPE, OPCODE)                                 \
  template <typename Adapter>                                                 \
  void InstructionSelectorT<Adapter>::Visit##TYPE##ReplaceLane(node_t node) { \
    IA32OperandGeneratorT<Adapter> g(this);                                   \
    int lane;                                                                 \
    if constexpr (Adapter::IsTurboshaft) {                                    \
      const turboshaft::Simd128ReplaceLaneOp& op =                            \
          this->Get(node).template Cast<turboshaft::Simd128ReplaceLaneOp>();  \
      lane = op.lane;                                                         \
    } else {                                                                  \
      lane = OpParameter<int32_t>(node->op());                                \
    }                                                                         \
    InstructionOperand operand0 = g.UseRegister(this->input_at(node, 0));     \
    InstructionOperand operand1 = g.UseImmediate(lane);                       \
    auto input1 = this->input_at(node, 1);                                    \
    InstructionOperand operand2;                                              \
    if constexpr (OPCODE == kIA32F64x2ReplaceLane) {                          \
      operand2 = g.UseRegister(input1);                                       \
    } else {                                                                  \
      operand2 = g.Use(input1);                                               \
    }                                                                         \
    /* When no-AVX, define dst == src to save a move. */                      \
    InstructionOperand dst = IsSupported(AVX) ? g.DefineAsRegister(node)      \
                                              : g.DefineSameAsFirst(node);    \
    Emit(OPCODE, dst, operand0, operand1, operand2);                          \
  }
SIMD_REPLACE_LANE_TYPE_OP(VISIT_SIMD_REPLACE_LANE)
#undef VISIT_SIMD_REPLACE_LANE
#undef SIMD_REPLACE_LANE_TYPE_OP

#define VISIT_SIMD_SHIFT_UNIFIED_SSE_AVX(Opcode)                   \
  template <typename Adapter>                                      \
  void InstructionSelectorT<Adapter>::Visit##Opcode(node_t node) { \
    VisitRROSimdShift(this, node, kIA32##Opcode);                  \
  }
SIMD_SHIFT_OPCODES_UNIFED_SSE_AVX(VISIT_SIMD_SHIFT_UNIFIED_SSE_AVX)
#undef VISIT_SIMD_SHIFT_UNIFIED_SSE_AVX
#undef SIMD_SHIFT_OPCODES_UNIFED_SSE_AVX

// TODO(v8:9198): SSE requires operand0 to be a register as we don't have memory
// alignment yet. For AVX, memory operands are fine, but can have performance
// issues if not aligned to 16/32 bytes (based on load size), see SDM Vol 1,
// chapter 14.9
#define VISIT_SIMD_UNOP(Opcode)                                    \
  template <typename Adapter>                                      \
  void InstructionSelectorT<Adapter>::Visit##Opcode(node_t node) { \
    IA32OperandGeneratorT<Adapter> g(this);                        \
    Emit(kIA32##Opcode, g.DefineAsRegister(node),                  \
         g.UseRegister(this->input_at(node, 0)));                  \
  }
SIMD_UNOP_LIST(VISIT_SIMD_UNOP)
#undef VISIT_SIMD_UNOP
#undef SIMD_UNOP_LIST

#define UNIMPLEMENTED_SIMD_UNOP_LIST(V) \
  V(F16x8Abs)                           \
  V(F16x8Neg)                           \
  V(F16x8Sqrt)                          \
  V(F16x8Floor)                         \
  V(F16x8Ceil)                          \
  V(F16x8Trunc)                         \
  V(F16x8NearestInt)

#define SIMD_VISIT_UNIMPL_UNOP(Name)                             \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    UNIMPLEMENTED();                                             \
  }

UNIMPLEMENTED_SIMD_UNOP_LIST(SIMD_VISIT_UNIMPL_UNOP)
#undef SIMD_VISIT_UNIMPL_UNOP
#undef UNIMPLEMENTED_SIMD_UNOP_LIST

#define UNIMPLEMENTED_SIMD_CVTOP_LIST(V) \
  V(F16x8SConvertI16x8)                  \
  V(F16x8UConvertI16x8)                  \
  V(I16x8SConvertF16x8)                  \
  V(I16x8UConvertF16x8)                  \
  V(F32x4PromoteLowF16x8)                \
  V(F16x8DemoteF32x4Zero)                \
  V(F16x8DemoteF64x2Zero)

#define SIMD_VISIT_UNIMPL_CVTOP(Name)                            \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    UNIMPLEMENTED();                                             \
  }

UNIMPLEMENTED_SIMD_CVTOP_LIST(SIMD_VISIT_UNIMPL_CVTOP)
#undef SIMD_VISIT_UNIMPL_CVTOP
#undef UNIMPLEMENTED_SIMD_CVTOP_LIST

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitV128AnyTrue(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempRegister()};
  Emit(kIA32S128AnyTrue, g.DefineAsRegister(node),
       g.UseRegister(this->input_at(node, 0)), arraysize(temps), temps);
}

#define VISIT_SIMD_ALLTRUE(Opcode)                                            \
  template <typename Adapter>                                                 \
  void InstructionSelectorT<Adapter>::Visit##Opcode(node_t node) {            \
    IA32OperandGeneratorT<Adapter> g(this);                                   \
    InstructionOperand temps[] = {g.TempRegister(), g.TempSimd128Register()}; \
    Emit(kIA32##Opcode, g.DefineAsRegister(node),                             \
         g.UseUniqueRegister(this->input_at(node, 0)), arraysize(temps),      \
         temps);                                                              \
  }
SIMD_ALLTRUE_LIST(VISIT_SIMD_ALLTRUE)
#undef VISIT_SIMD_ALLTRUE
#undef SIMD_ALLTRUE_LIST

#define VISIT_SIMD_BINOP(Opcode)                                   \
  template <typename Adapter>                                      \
  void InstructionSelectorT<Adapter>::Visit##Opcode(node_t node) { \
    VisitRROSimd(this, node, kAVX##Opcode, kSSE##Opcode);          \
  }
SIMD_BINOP_LIST(VISIT_SIMD_BINOP)
#undef VISIT_SIMD_BINOP
#undef SIMD_BINOP_LIST

#define UNIMPLEMENTED_SIMD_BINOP_LIST(V) \
  V(F16x8Add)                            \
  V(F16x8Sub)                            \
  V(F16x8Mul)                            \
  V(F16x8Div)                            \
  V(F16x8Min)                            \
  V(F16x8Max)                            \
  V(F16x8Pmin)                           \
  V(F16x8Pmax)                           \
  V(F16x8Eq)                             \
  V(F16x8Ne)                             \
  V(F16x8Lt)                             \
  V(F16x8Le)

#define SIMD_VISIT_UNIMPL_BINOP(Name)                            \
  template <typename Adapter>                                    \
  void InstructionSelectorT<Adapter>::Visit##Name(node_t node) { \
    UNIMPLEMENTED();                                             \
  }

UNIMPLEMENTED_SIMD_BINOP_LIST(SIMD_VISIT_UNIMPL_BINOP)
#undef SIMD_VISIT_UNIMPL_BINOP
#undef UNIMPLEMENTED_SIMD_BINOP_LIST

#define VISIT_SIMD_BINOP_UNIFIED_SSE_AVX(Opcode)                   \
  template <typename Adapter>                                      \
  void InstructionSelectorT<Adapter>::Visit##Opcode(node_t node) { \
    VisitRROSimd(this, node, kIA32##Opcode, kIA32##Opcode);        \
  }
SIMD_BINOP_UNIFIED_SSE_AVX_LIST(VISIT_SIMD_BINOP_UNIFIED_SSE_AVX)
#undef VISIT_SIMD_BINOP_UNIFIED_SSE_AVX
#undef SIMD_BINOP_UNIFIED_SSE_AVX_LIST

#define VISIT_SIMD_BINOP_RRR(OPCODE)                               \
  template <typename Adapter>                                      \
  void InstructionSelectorT<Adapter>::Visit##OPCODE(node_t node) { \
    VisitRRRSimd(this, node, kIA32##OPCODE);                       \
  }
SIMD_BINOP_RRR(VISIT_SIMD_BINOP_RRR)
#undef VISIT_SIMD_BINOP_RRR
#undef SIMD_BINOP_RRR

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI16x8BitMask(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempSimd128Register()};
  Emit(kIA32I16x8BitMask, g.DefineAsRegister(node),
       g.UseUniqueRegister(this->input_at(node, 0)), arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Shl(node_t node) {
  VisitI8x16Shift(this, node, kIA32I8x16Shl);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16ShrS(node_t node) {
  VisitI8x16Shift(this, node, kIA32I8x16ShrS);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16ShrU(node_t node) {
  VisitI8x16Shift(this, node, kIA32I8x16ShrU);
}
#endif  // V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32AbsWithOverflow(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64AbsWithOverflow(node_t node) {
  UNREACHABLE();
}

#if V8_ENABLE_WEBASSEMBLY
namespace {

// Returns true if shuffle can be decomposed into two 16x4 half shuffles
// followed by a 16x8 blend.
// E.g. [3 2 1 0 15 14 13 12].
bool TryMatch16x8HalfShuffle(uint8_t* shuffle16x8, uint8_t* blend_mask) {
  *blend_mask = 0;
  for (int i = 0; i < 8; i++) {
    if ((shuffle16x8[i] & 0x4) != (i & 0x4)) return false;
    *blend_mask |= (shuffle16x8[i] > 7 ? 1 : 0) << i;
  }
  return true;
}

struct ShuffleEntry {
  uint8_t shuffle[kSimd128Size];
  ArchOpcode opcode;
  ArchOpcode avx_opcode;
  bool src0_needs_reg;
  bool src1_needs_reg;
};

// Shuffles that map to architecture-specific instruction sequences. These are
// matched very early, so we shouldn't include shuffles that match better in
// later tests, like 32x4 and 16x8 shuffles. In general, these patterns should
// map to either a single instruction, or be finer grained, such as zip/unzip or
// transpose patterns.
static const ShuffleEntry arch_shuffles[] = {
    {{0, 1, 2, 3, 4, 5, 6, 7, 16, 17, 18, 19, 20, 21, 22, 23},
     kIA32S64x2UnpackLow,
     kIA32S64x2UnpackLow,
     true,
     false},
    {{8, 9, 10, 11, 12, 13, 14, 15, 24, 25, 26, 27, 28, 29, 30, 31},
     kIA32S64x2UnpackHigh,
     kIA32S64x2UnpackHigh,
     true,
     false},
    {{0, 1, 2, 3, 16, 17, 18, 19, 4, 5, 6, 7, 20, 21, 22, 23},
     kIA32S32x4UnpackLow,
     kIA32S32x4UnpackLow,
     true,
     false},
    {{8, 9, 10, 11, 24, 25, 26, 27, 12, 13, 14, 15, 28, 29, 30, 31},
     kIA32S32x4UnpackHigh,
     kIA32S32x4UnpackHigh,
     true,
     false},
    {{0, 1, 16, 17, 2, 3, 18, 19, 4, 5, 20, 21, 6, 7, 22, 23},
     kIA32S16x8UnpackLow,
     kIA32S16x8UnpackLow,
     true,
     false},
    {{8, 9, 24, 25, 10, 11, 26, 27, 12, 13, 28, 29, 14, 15, 30, 31},
     kIA32S16x8UnpackHigh,
     kIA32S16x8UnpackHigh,
     true,
     false},
    {{0, 16, 1, 17, 2, 18, 3, 19, 4, 20, 5, 21, 6, 22, 7, 23},
     kIA32S8x16UnpackLow,
     kIA32S8x16UnpackLow,
     true,
     false},
    {{8, 24, 9, 25, 10, 26, 11, 27, 12, 28, 13, 29, 14, 30, 15, 31},
     kIA32S8x16UnpackHigh,
     kIA32S8x16UnpackHigh,
     true,
     false},

    {{0, 1, 4, 5, 8, 9, 12, 13, 16, 17, 20, 21, 24, 25, 28, 29},
     kSSES16x8UnzipLow,
     kAVXS16x8UnzipLow,
     true,
     false},
    {{2, 3, 6, 7, 10, 11, 14, 15, 18, 19, 22, 23, 26, 27, 30, 31},
     kSSES16x8UnzipHigh,
     kAVXS16x8UnzipHigh,
     true,
     true},
    {{0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30},
     kSSES8x16UnzipLow,
     kAVXS8x16UnzipLow,
     true,
     true},
    {{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31},
     kSSES8x16UnzipHigh,
     kAVXS8x16UnzipHigh,
     true,
     true},

    {{0, 16, 2, 18, 4, 20, 6, 22, 8, 24, 10, 26, 12, 28, 14, 30},
     kSSES8x16TransposeLow,
     kAVXS8x16TransposeLow,
     true,
     true},
    {{1, 17, 3, 19, 5, 21, 7, 23, 9, 25, 11, 27, 13, 29, 15, 31},
     kSSES8x16TransposeHigh,
     kAVXS8x16TransposeHigh,
     true,
     true},
    {{7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8},
     kSSES8x8Reverse,
     kAVXS8x8Reverse,
     true,
     true},
    {{3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12},
     kSSES8x4Reverse,
     kAVXS8x4Reverse,
     true,
     true},
    {{1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14},
     kSSES8x2Reverse,
     kAVXS8x2Reverse,
     true,
     true}};

bool TryMatchArchShuffle(const uint8_t* shuffle, const ShuffleEntry* table,
                         size_t num_entries, bool is_swizzle,
                         const ShuffleEntry** arch_shuffle) {
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
      *arch_shuffle = &entry;
      return true;
    }
  }
  return false;
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Shuffle(node_t node) {
  uint8_t shuffle[kSimd128Size];
  bool is_swizzle;
  auto view = this->simd_shuffle_view(node);
  CanonicalizeShuffle(view, shuffle, &is_swizzle);

  int imm_count = 0;
  static const int kMaxImms = 6;
  uint32_t imms[kMaxImms];
  int temp_count = 0;
  static const int kMaxTemps = 2;
  InstructionOperand temps[kMaxTemps];

  IA32OperandGeneratorT<Adapter> g(this);
  bool use_avx = CpuFeatures::IsSupported(AVX);
  // AVX and swizzles don't generally need DefineSameAsFirst to avoid a move.
  bool no_same_as_first = use_avx || is_swizzle;
  // We generally need UseRegister for input0, Use for input1.
  // TODO(v8:9198): We don't have 16-byte alignment for SIMD operands yet, but
  // we retain this logic (continue setting these in the various shuffle match
  // clauses), but ignore it when selecting registers or slots.
  bool src0_needs_reg = true;
  bool src1_needs_reg = false;
  ArchOpcode opcode = kIA32I8x16Shuffle;  // general shuffle is the default

  uint8_t offset;
  uint8_t shuffle32x4[4];
  uint8_t shuffle16x8[8];
  int index;
  const ShuffleEntry* arch_shuffle;
  if (wasm::SimdShuffle::TryMatchConcat(shuffle, &offset)) {
    if (wasm::SimdShuffle::TryMatch32x4Rotate(shuffle, shuffle32x4,
                                              is_swizzle)) {
      uint8_t shuffle_mask = wasm::SimdShuffle::PackShuffle4(shuffle32x4);
      opcode = kIA32S32x4Rotate;
      imms[imm_count++] = shuffle_mask;
    } else {
      // Swap inputs from the normal order for (v)palignr.
      SwapShuffleInputs(view);
      is_swizzle = false;  // It's simpler to just handle the general case.
      no_same_as_first = use_avx;  // SSE requires same-as-first.
      opcode = kIA32S8x16Alignr;
      // palignr takes a single imm8 offset.
      imms[imm_count++] = offset;
    }
  } else if (TryMatchArchShuffle(shuffle, arch_shuffles,
                                 arraysize(arch_shuffles), is_swizzle,
                                 &arch_shuffle)) {
    opcode = use_avx ? arch_shuffle->avx_opcode : arch_shuffle->opcode;
    src0_needs_reg = !use_avx || arch_shuffle->src0_needs_reg;
    // SSE can't take advantage of both operands in registers and needs
    // same-as-first.
    src1_needs_reg = use_avx && arch_shuffle->src1_needs_reg;
    no_same_as_first = use_avx;
  } else if (wasm::SimdShuffle::TryMatch32x4Shuffle(shuffle, shuffle32x4)) {
    uint8_t shuffle_mask = wasm::SimdShuffle::PackShuffle4(shuffle32x4);
    if (is_swizzle) {
      if (wasm::SimdShuffle::TryMatchIdentity(shuffle)) {
        // Bypass normal shuffle code generation in this case.
        node_t input = view.input(0);
        // EmitIdentity
        MarkAsUsed(input);
        MarkAsDefined(node);
        SetRename(node, input);
        return;
      } else {
        // pshufd takes a single imm8 shuffle mask.
        opcode = kIA32S32x4Swizzle;
        no_same_as_first = true;
        // TODO(v8:9198): This doesn't strictly require a register, forcing the
        // swizzles to always use registers until generation of incorrect memory
        // operands can be fixed.
        src0_needs_reg = true;
        imms[imm_count++] = shuffle_mask;
      }
    } else {
      // 2 operand shuffle
      // A blend is more efficient than a general 32x4 shuffle; try it first.
      if (wasm::SimdShuffle::TryMatchBlend(shuffle)) {
        opcode = kIA32S16x8Blend;
        uint8_t blend_mask = wasm::SimdShuffle::PackBlend4(shuffle32x4);
        imms[imm_count++] = blend_mask;
      } else {
        opcode = kIA32S32x4Shuffle;
        no_same_as_first = true;
        // TODO(v8:9198): src0 and src1 is used by pshufd in codegen, which
        // requires memory to be 16-byte aligned, since we cannot guarantee that
        // yet, force using a register here.
        src0_needs_reg = true;
        src1_needs_reg = true;
        imms[imm_count++] = shuffle_mask;
        int8_t blend_mask = wasm::SimdShuffle::PackBlend4(shuffle32x4);
        imms[imm_count++] = blend_mask;
      }
    }
  } else if (wasm::SimdShuffle::TryMatch16x8Shuffle(shuffle, shuffle16x8)) {
    uint8_t blend_mask;
    if (wasm::SimdShuffle::TryMatchBlend(shuffle)) {
      opcode = kIA32S16x8Blend;
      blend_mask = wasm::SimdShuffle::PackBlend8(shuffle16x8);
      imms[imm_count++] = blend_mask;
    } else if (wasm::SimdShuffle::TryMatchSplat<8>(shuffle, &index)) {
      opcode = kIA32S16x8Dup;
      src0_needs_reg = false;
      imms[imm_count++] = index;
    } else if (TryMatch16x8HalfShuffle(shuffle16x8, &blend_mask)) {
      opcode = is_swizzle ? kIA32S16x8HalfShuffle1 : kIA32S16x8HalfShuffle2;
      // Half-shuffles don't need DefineSameAsFirst or UseRegister(src0).
      no_same_as_first = true;
      src0_needs_reg = false;
      uint8_t mask_lo = wasm::SimdShuffle::PackShuffle4(shuffle16x8);
      uint8_t mask_hi = wasm::SimdShuffle::PackShuffle4(shuffle16x8 + 4);
      imms[imm_count++] = mask_lo;
      imms[imm_count++] = mask_hi;
      if (!is_swizzle) imms[imm_count++] = blend_mask;
    }
  } else if (wasm::SimdShuffle::TryMatchSplat<16>(shuffle, &index)) {
    opcode = kIA32S8x16Dup;
    no_same_as_first = use_avx;
    src0_needs_reg = true;
    imms[imm_count++] = index;
  }
  if (opcode == kIA32I8x16Shuffle) {
    // Use same-as-first for general swizzle, but not shuffle.
    no_same_as_first = !is_swizzle;
    src0_needs_reg = !no_same_as_first;
    imms[imm_count++] = wasm::SimdShuffle::Pack4Lanes(shuffle);
    imms[imm_count++] = wasm::SimdShuffle::Pack4Lanes(shuffle + 4);
    imms[imm_count++] = wasm::SimdShuffle::Pack4Lanes(shuffle + 8);
    imms[imm_count++] = wasm::SimdShuffle::Pack4Lanes(shuffle + 12);
    temps[temp_count++] = g.TempRegister();
  }

  // Use DefineAsRegister(node) and Use(src0) if we can without forcing an extra
  // move instruction in the CodeGenerator.
  node_t input0 = view.input(0);
  InstructionOperand dst =
      no_same_as_first ? g.DefineAsRegister(node) : g.DefineSameAsFirst(node);
  // TODO(v8:9198): Use src0_needs_reg when we have memory alignment for SIMD.
  InstructionOperand src0 = g.UseRegister(input0);
  USE(src0_needs_reg);

  int input_count = 0;
  InstructionOperand inputs[2 + kMaxImms + kMaxTemps];
  inputs[input_count++] = src0;
  if (!is_swizzle) {
    node_t input1 = view.input(1);
    // TODO(v8:9198): Use src1_needs_reg when we have memory alignment for SIMD.
    inputs[input_count++] = g.UseRegister(input1);
    USE(src1_needs_reg);
  }
  for (int i = 0; i < imm_count; ++i) {
    inputs[input_count++] = g.UseImmediate(imms[i]);
  }
  Emit(opcode, 1, &dst, input_count, inputs, temp_count, temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitI8x16Swizzle(node_t node) {
  InstructionCode op = kIA32I8x16Swizzle;

  node_t left = this->input_at(node, 0);
  node_t right = this->input_at(node, 1);
  if constexpr (Adapter::IsTurboshaft) {
    const turboshaft::Simd128BinopOp& binop =
        this->Get(node).template Cast<turboshaft::Simd128BinopOp>();
    DCHECK(binop.kind ==
           turboshaft::any_of(
               turboshaft::Simd128BinopOp::Kind::kI8x16Swizzle,
               turboshaft::Simd128BinopOp::Kind::kI8x16RelaxedSwizzle));
    bool relaxed =
        binop.kind == turboshaft::Simd128BinopOp::Kind::kI8x16RelaxedSwizzle;
    if (relaxed) {
      op |= MiscField::encode(true);
    } else {
      // If the indices vector is a const, check if they are in range, or if the
      // top bit is set, then we can avoid the paddusb in the codegen and simply
      // emit a pshufb.
      const turboshaft::Operation& right_op = this->Get(right);
      if (auto c = right_op.TryCast<turboshaft::Simd128ConstantOp>()) {
        std::array<uint8_t, kSimd128Size> imms;
        std::memcpy(&imms, c->value, kSimd128Size);
        op |= MiscField::encode(wasm::SimdSwizzle::AllInRangeOrTopBitSet(imms));
      }
    }
  } else {
    // Turbofan.
    bool relaxed = OpParameter<bool>(node->op());
    if (relaxed) {
      op |= MiscField::encode(true);
    } else {
      auto m = V128ConstMatcher(node->InputAt(1));
      if (m.HasResolvedValue()) {
        // If the indices vector is a const, check if they are in range, or if
        // the top bit is set, then we can avoid the paddusb in the codegen and
        // simply emit a pshufb.
        auto imms = m.ResolvedValue().immediate();
        op |= MiscField::encode(wasm::SimdSwizzle::AllInRangeOrTopBitSet(imms));
      }
    }
  }

  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand temps[] = {g.TempRegister()};
  Emit(op,
       IsSupported(AVX) ? g.DefineAsRegister(node) : g.DefineSameAsFirst(node),
       g.UseRegister(left), g.UseRegister(right), arraysize(temps), temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSetStackPointer(node_t node) {
  OperandGenerator g(this);
  auto input = g.UseAny(this->input_at(node, 0));
  Emit(kArchSetStackPointer, 0, nullptr, 1, &input);
}

namespace {

template <typename Adapter>
void VisitMinOrMax(InstructionSelectorT<Adapter>* selector,
                   typename Adapter::node_t node, ArchOpcode opcode,
                   bool flip_inputs) {
  // Due to the way minps/minpd work, we want the dst to be same as the second
  // input: b = pmin(a, b) directly maps to minps b a.
  IA32OperandGeneratorT<Adapter> g(selector);
  InstructionOperand dst = selector->IsSupported(AVX)
                               ? g.DefineAsRegister(node)
                               : g.DefineSameAsFirst(node);
  if (flip_inputs) {
    
"""


```