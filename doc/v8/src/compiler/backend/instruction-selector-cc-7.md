Response:
Let's break down the thought process for analyzing the provided C++ code snippet and generating the comprehensive answer.

**1. Initial Understanding & Goal:**

The primary goal is to understand the functionality of the given V8 source code file (`instruction-selector.cc`) and explain it clearly. The prompt also includes several specific constraints and requests (Torque, JavaScript relation, logic, errors, and a summary). The "Part 8 of 8" suggests this is the final piece, so a summarizing function is crucial.

**2. High-Level Analysis - Identifying Key Components:**

Scanning the code, several patterns and keywords stand out:

* **`InstructionSelector`:** This is the central class, suggesting it's responsible for selecting instructions.
* **`Visit...` methods:**  These methods, like `VisitI8x16ExtractLaneS`, `VisitF64x2ReplaceLane`, etc., strongly indicate a pattern of handling different operation types. The names suggest they deal with SIMD (Single Instruction, Multiple Data) operations.
* **`Opcode::k...`:** These enums represent different kinds of operations that the instruction selector needs to handle.
* **`MarkAs...` methods:**  These functions (`MarkAsWord32`, `MarkAsSimd128`, etc.) seem to be involved in classifying or tagging nodes based on their data type.
* **SIMD-related keywords:** `Simd128`, `Simd256`, `ExtractLane`, `ReplaceLane`, `Ternary`, `Splat`, etc., clearly point to SIMD instruction selection.
* **`FrameStateDescriptor`:** This suggests handling the state of the execution stack.
* **`ZeroExtendsWord32ToWord64`:**  This function hints at optimizations or specific handling for 32-bit to 64-bit conversions.
* **Template Usage:** The presence of `template <typename Adapter>` suggests the code is designed to be adaptable for different architectures or compilation pipelines (likely Turbofan and Turboshaft, as mentioned later).

**3. Deduction of Primary Functionality:**

Based on the identified components, the core function of `instruction-selector.cc` is to take a high-level representation of operations (likely from the compiler's intermediate representation) and translate them into specific machine instructions for the target architecture. This is a crucial step in the compilation process.

**4. Addressing Specific Constraints and Requests:**

* **`.tq` suffix:** The code is clearly C++, not Torque. This is a direct check.
* **JavaScript Relation:** Since this is part of V8, which executes JavaScript, there *must* be a connection. The SIMD operations are a strong candidate for relating to JavaScript's SIMD API. The example needs to demonstrate how these SIMD operations manifest in JavaScript.
* **Code Logic/Reasoning:** The `ZeroExtendsWord32ToWord64` function provides a good opportunity to illustrate logical reasoning. We can create a scenario where this optimization would apply. The need for "hypothetical input and output" directs this aspect.
* **Common Programming Errors:** The SIMD API in JavaScript can be tricky, so a common error related to lane indexing or type mismatches is a good example.
* **Summary (Part 8 of 8):**  The summary should reiterate the core function and emphasize its role in the overall compilation pipeline.

**5. Structuring the Answer:**

A logical structure for the answer is essential for clarity:

1. **Core Functionality:** Start with a clear statement of the file's purpose.
2. **Key Functionalities (Detailed):** Break down the core function into more specific aspects, like SIMD instruction selection, handling different data types, and frame state management.
3. **Torque Check:** Directly address the `.tq` question.
4. **JavaScript Relation (with Example):** Provide a concrete JavaScript example to link the C++ code to user-level behavior.
5. **Code Logic/Reasoning (with Example):**  Explain the `ZeroExtendsWord32ToWord64` logic with a hypothetical input and output.
6. **Common Programming Errors (with Example):** Illustrate a typical error a JavaScript developer might encounter when using the related features.
7. **Summary:**  Provide a concise overview of the file's role as the final piece of the provided code.

**6. Generating Examples and Explanations:**

* **JavaScript Example:** Focus on a simple SIMD operation that directly maps to the C++ code (e.g., extracting a lane).
* **Logic Example:**  Choose a scenario where a 32-bit value is being used in a 64-bit context, allowing for the zero-extension optimization.
* **Error Example:** Pick a common mistake with SIMD, such as accessing an invalid lane index.

**7. Refining and Reviewing:**

After drafting the initial answer, review it for clarity, accuracy, and completeness. Ensure all the constraints from the prompt have been addressed. Use clear and concise language, avoiding overly technical jargon where possible. For instance, initially, I might have just said "lowering," but "translating high-level operations into low-level machine code" is more descriptive for a broader audience. Similarly, explicitly stating the connection to Turbofan and Turboshaft, mentioned in the code, enhances the answer.

This iterative process of understanding, analyzing, deducing, structuring, and refining helps in generating a comprehensive and accurate answer to the prompt. The key is to break down the complex code into understandable components and then connect those components to the user's perspective (in this case, a JavaScript developer).
好的，让我们来分析一下 `v8/src/compiler/backend/instruction-selector.cc` 这个文件的功能。

**功能归纳:**

`v8/src/compiler/backend/instruction-selector.cc` 的主要功能是**将编译器生成的中间表示（IR，Intermediate Representation）指令选择并转换为目标架构的机器指令**。它是 V8 编译器后端的重要组成部分，负责将与平台无关的 IR 节点映射到特定的 CPU 指令，以便在目标硬件上执行。

**具体功能分解:**

1. **遍历中间表示 (IR) 图:**  代码中可以看到 `Visit` 开头的函数，例如 `VisitI8x16ExtractLaneS(node)`。这表明 `InstructionSelector` 会遍历编译器生成的 IR 图中的节点。

2. **识别操作类型:**  通过 `node->opcode()` 获取当前节点的操作码，然后根据操作码的类型（例如 `Opcode::kSimd128ReplaceLane`）进行不同的处理。

3. **选择机器指令:** 针对不同的 IR 操作和目标架构，选择最合适的机器指令来实现该操作。例如，`VisitI8x16ExtractLaneS` 函数会选择用于从 128 位 SIMD 寄存器中提取 8 位有符号整数的指令。

4. **处理 SIMD 指令:**  代码中大量涉及到 `Simd128` 和 `Simd256` 相关的操作码，例如 `Simd128ReplaceLaneOp`, `Simd128ExtractLaneOp`, `Simd128TernaryOp` 等。这表明该文件负责处理 SIMD (Single Instruction, Multiple Data) 向量指令的选择。

5. **处理不同数据类型:**  可以看到代码针对不同的数据类型（例如 `I8x16`, `I16x8`, `I32x4`, `F32x4`, `F64x2`）有不同的处理逻辑，确保选择的机器指令能够正确操作这些数据类型。

6. **处理内存访问:**  `Opcode::kSimd128LaneMemory` 以及 `VisitLoadLane` 和 `VisitStoreLane` 函数表明该文件也负责处理 SIMD 寄存器与内存之间的数据加载和存储操作。

7. **处理控制流:**  虽然这段代码片段主要关注运算操作，但 `InstructionSelector` 在完整的文件中也会处理控制流相关的指令选择，例如分支、跳转等。

8. **处理函数调用和栈操作:** `VisitLoadStackPointer` 和 `VisitSetStackPointer` 表明它也处理与函数调用和栈管理相关的操作。

9. **平台适配:**  通过模板 `template <typename Adapter>` 可以看出，`InstructionSelector` 被设计为可适配不同的后端架构，例如 Turbofan 和 Turboshaft。

10. **零扩展优化:** `ZeroExtendsWord32ToWord64` 函数表明 `InstructionSelector` 还会进行一些优化，例如在 64 位架构上将 32 位值零扩展到 64 位，以提高效率。

**关于是否是 Torque 源代码:**

根据您提供的代码，`v8/src/compiler/backend/instruction-selector.cc` **不是**以 `.tq` 结尾，因此它是一个 **C++ 源代码文件**，而不是 V8 Torque 源代码。Torque 文件通常用于定义 V8 的内置函数和类型。

**与 JavaScript 的关系 (以 SIMD 为例):**

`instruction-selector.cc` 中处理的 SIMD 指令与 JavaScript 中的 SIMD API 直接相关。JavaScript 提供了 `SIMD` 对象，允许开发者在 JavaScript 中使用 SIMD 指令进行并行计算。

**JavaScript 示例:**

```javascript
// 创建一个 int32x4 类型的 SIMD 向量
const a = SIMD.int32x4(1, 2, 3, 4);

// 提取索引为 2 的 lane 的值
const laneValue = SIMD.extractLane(a, 2); // laneValue 将会是 3

console.log(laneValue);

// 创建另一个 int32x4 类型的 SIMD 向量
const b = SIMD.int32x4(5, 6, 7, 8);

// 替换向量 a 中索引为 1 的 lane 的值为 10
const replacedA = SIMD.replaceLane(a, 1, 10); // replacedA 将会是 int32x4(1, 10, 3, 4)

console.log(replacedA);

// 执行加法操作
const sum = SIMD.int32x4.add(a, b); // sum 将会是 int32x4(6, 8, 10, 12)

console.log(sum);
```

当 V8 执行这段 JavaScript 代码时，编译器会生成相应的 IR 节点。`instruction-selector.cc` 中的代码则负责将这些 IR 节点转换为目标架构的 SIMD 机器指令，例如 SSE、AVX 等。例如，`SIMD.extractLane(a, 2)` 可能会对应到 `Opcode::kSimd128ExtractLane`，然后由 `VisitI32x4ExtractLane` 函数选择合适的机器指令。

**代码逻辑推理 (以 `ZeroExtendsWord32ToWord64` 为例):**

**假设输入:**

一个 IR 节点 `node`，代表一个 32 位整数运算的结果。在 64 位架构上，这个结果将被用作一个 64 位值的操作数。

**代码逻辑:**

`ZeroExtendsWord32ToWord64(node)` 函数的目的是判断 `node` 代表的值是否可以保证其高 32 位为零。如果是，那么在生成机器指令时，就不需要显式地进行零扩展操作，因为某些 32 位运算在 64 位寄存器中会自动将高 32 位清零。

**输出:**

如果 `ZeroExtendsWord32ToWord64(node)` 返回 `true`，则表示可以安全地假设 `node` 的高 32 位为零。如果返回 `false`，则需要进行显式的零扩展操作，以确保 64 位运算的正确性。

**例如:** 假设 `node` 是一个 32 位整数加法运算的结果。在某些 64 位架构上，32 位加法的结果会自动存储在 64 位寄存器的低 32 位，高 32 位被清零。在这种情况下，`ZeroExtendsWord32ToWord64(node)` 可能会返回 `true`。

**用户常见的编程错误 (以 SIMD 为例):**

使用 SIMD 时，一个常见的编程错误是**访问越界的 lane 索引**。

**JavaScript 示例 (错误):**

```javascript
const vec = SIMD.float32x4(1.0, 2.0, 3.0, 4.0);

// 尝试访问索引为 4 的 lane，但有效索引是 0, 1, 2, 3
const value = SIMD.extractLane(vec, 4); // 这将导致错误
```

在 V8 的实现中，当执行到 `SIMD.extractLane(vec, 4)` 时，`instruction-selector.cc` 中对应的指令选择逻辑会尝试生成访问 SIMD 寄存器的指令。如果索引超出范围，这通常会导致程序崩溃或产生未定义的行为。虽然 JavaScript 引擎会进行一些边界检查，但在性能关键的代码路径中，这种错误可能会逃脱检查并导致问题。

**总结 (第 8 部分，共 8 部分):**

作为编译过程的最后阶段，`v8/src/compiler/backend/instruction-selector.cc` 扮演着至关重要的角色。它接收编译器前端和优化的结果（IR），并将其精确地转换为目标机器可以理解和执行的指令。该文件尤其关注 SIMD 指令的处理，这直接支持了 JavaScript 中高性能的并行计算能力。通过选择正确的指令并进行必要的优化，`instruction-selector.cc` 直接影响着 V8 引擎生成的代码的执行效率和性能。它确保了 JavaScript 代码能够高效地运行在各种不同的硬件架构之上。

### 提示词
```
这是目录为v8/src/compiler/backend/instruction-selector.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/instruction-selector.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第8部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
x4ReplaceLane(node);
        case Simd128ReplaceLaneOp::Kind::kF64x2:
          return VisitF64x2ReplaceLane(node);
      }
    }
    case Opcode::kSimd128ExtractLane: {
      const Simd128ExtractLaneOp& extract = op.Cast<Simd128ExtractLaneOp>();
      switch (extract.kind) {
        case Simd128ExtractLaneOp::Kind::kI8x16S:
          MarkAsWord32(node);
          return VisitI8x16ExtractLaneS(node);
        case Simd128ExtractLaneOp::Kind::kI8x16U:
          MarkAsWord32(node);
          return VisitI8x16ExtractLaneU(node);
        case Simd128ExtractLaneOp::Kind::kI16x8S:
          MarkAsWord32(node);
          return VisitI16x8ExtractLaneS(node);
        case Simd128ExtractLaneOp::Kind::kI16x8U:
          MarkAsWord32(node);
          return VisitI16x8ExtractLaneU(node);
        case Simd128ExtractLaneOp::Kind::kI32x4:
          MarkAsWord32(node);
          return VisitI32x4ExtractLane(node);
        case Simd128ExtractLaneOp::Kind::kI64x2:
          MarkAsWord64(node);
          return VisitI64x2ExtractLane(node);
        case Simd128ExtractLaneOp::Kind::kF16x8:
          MarkAsFloat32(node);
          return VisitF16x8ExtractLane(node);
        case Simd128ExtractLaneOp::Kind::kF32x4:
          MarkAsFloat32(node);
          return VisitF32x4ExtractLane(node);
        case Simd128ExtractLaneOp::Kind::kF64x2:
          MarkAsFloat64(node);
          return VisitF64x2ExtractLane(node);
      }
    }
    case Opcode::kSimd128LoadTransform:
      MarkAsSimd128(node);
      return VisitLoadTransform(node);
    case Opcode::kSimd128LaneMemory: {
      const Simd128LaneMemoryOp& memory = op.Cast<Simd128LaneMemoryOp>();
      MarkAsSimd128(node);
      if (memory.mode == Simd128LaneMemoryOp::Mode::kLoad) {
        return VisitLoadLane(node);
      } else {
        DCHECK_EQ(memory.mode, Simd128LaneMemoryOp::Mode::kStore);
        return VisitStoreLane(node);
      }
    }
    case Opcode::kSimd128Ternary: {
      const Simd128TernaryOp& ternary = op.Cast<Simd128TernaryOp>();
      MarkAsSimd128(node);
      switch (ternary.kind) {
#define VISIT_SIMD_TERNARY(kind)        \
  case Simd128TernaryOp::Kind::k##kind: \
    return Visit##kind(node);
        FOREACH_SIMD_128_TERNARY_OPCODE(VISIT_SIMD_TERNARY)
#undef VISIT_SIMD_TERNARY
      }
    }

    // SIMD256
#if V8_ENABLE_WASM_SIMD256_REVEC
    case Opcode::kSimd256Constant: {
      const Simd256ConstantOp& constant = op.Cast<Simd256ConstantOp>();
      MarkAsSimd256(node);
      if (constant.IsZero()) return VisitS256Zero(node);
      return VisitS256Const(node);
    }
    case Opcode::kSimd256Extract128Lane: {
      MarkAsSimd128(node);
      return VisitExtractF128(node);
    }
    case Opcode::kSimd256LoadTransform: {
      MarkAsSimd256(node);
      return VisitSimd256LoadTransform(node);
    }
    case Opcode::kSimd256Unary: {
      const Simd256UnaryOp& unary = op.Cast<Simd256UnaryOp>();
      MarkAsSimd256(node);
      switch (unary.kind) {
#define VISIT_SIMD_256_UNARY(kind)    \
  case Simd256UnaryOp::Kind::k##kind: \
    return Visit##kind(node);
        FOREACH_SIMD_256_UNARY_OPCODE(VISIT_SIMD_256_UNARY)
#undef VISIT_SIMD_256_UNARY
      }
    }
    case Opcode::kSimd256Binop: {
      const Simd256BinopOp& binop = op.Cast<Simd256BinopOp>();
      MarkAsSimd256(node);
      switch (binop.kind) {
#define VISIT_SIMD_BINOP(kind)        \
  case Simd256BinopOp::Kind::k##kind: \
    return Visit##kind(node);
        FOREACH_SIMD_256_BINARY_OPCODE(VISIT_SIMD_BINOP)
#undef VISIT_SIMD_BINOP
      }
    }
    case Opcode::kSimd256Shift: {
      const Simd256ShiftOp& shift = op.Cast<Simd256ShiftOp>();
      MarkAsSimd256(node);
      switch (shift.kind) {
#define VISIT_SIMD_SHIFT(kind)        \
  case Simd256ShiftOp::Kind::k##kind: \
    return Visit##kind(node);
        FOREACH_SIMD_256_SHIFT_OPCODE(VISIT_SIMD_SHIFT)
#undef VISIT_SIMD_SHIFT
      }
    }
    case Opcode::kSimd256Ternary: {
      const Simd256TernaryOp& ternary = op.Cast<Simd256TernaryOp>();
      MarkAsSimd256(node);
      switch (ternary.kind) {
#define VISIT_SIMD_256_TERNARY(kind)    \
  case Simd256TernaryOp::Kind::k##kind: \
    return Visit##kind(node);
        FOREACH_SIMD_256_TERNARY_OPCODE(VISIT_SIMD_256_TERNARY)
#undef VISIT_SIMD_256_UNARY
      }
    }
    case Opcode::kSimd256Splat: {
      const Simd256SplatOp& splat = op.Cast<Simd256SplatOp>();
      MarkAsSimd256(node);
      switch (splat.kind) {
#define VISIT_SIMD_SPLAT(kind)        \
  case Simd256SplatOp::Kind::k##kind: \
    return Visit##kind##Splat(node);
        FOREACH_SIMD_256_SPLAT_OPCODE(VISIT_SIMD_SPLAT)
#undef VISIT_SIMD_SPLAT
      }
    }
#ifdef V8_TARGET_ARCH_X64
    case Opcode::kSimd256Shufd: {
      MarkAsSimd256(node);
      return VisitSimd256Shufd(node);
    }
    case Opcode::kSimd256Shufps: {
      MarkAsSimd256(node);
      return VisitSimd256Shufps(node);
    }
    case Opcode::kSimd256Unpack: {
      MarkAsSimd256(node);
      return VisitSimd256Unpack(node);
    }
    case Opcode::kSimdPack128To256: {
      MarkAsSimd256(node);
      return VisitSimdPack128To256(node);
    }
#endif  // V8_TARGET_ARCH_X64
#endif  // V8_ENABLE_WASM_SIMD256_REVEC

    case Opcode::kLoadStackPointer:
      return VisitLoadStackPointer(node);

    case Opcode::kSetStackPointer:
      return VisitSetStackPointer(node);

#endif  // V8_ENABLE_WEBASSEMBLY

#define UNREACHABLE_CASE(op) case Opcode::k##op:
      TURBOSHAFT_JS_OPERATION_LIST(UNREACHABLE_CASE)
      TURBOSHAFT_SIMPLIFIED_OPERATION_LIST(UNREACHABLE_CASE)
      TURBOSHAFT_WASM_OPERATION_LIST(UNREACHABLE_CASE)
      TURBOSHAFT_OTHER_OPERATION_LIST(UNREACHABLE_CASE)
      UNREACHABLE_CASE(PendingLoopPhi)
      UNREACHABLE_CASE(Tuple)
      UNREACHABLE_CASE(Dead)
      UNREACHABLE();
#undef UNREACHABLE_CASE
  }
}

template <typename Adapter>
bool InstructionSelectorT<Adapter>::CanProduceSignalingNaN(Node* node) {
  // TODO(jarin) Improve the heuristic here.
  if (node->opcode() == IrOpcode::kFloat64Add ||
      node->opcode() == IrOpcode::kFloat64Sub ||
      node->opcode() == IrOpcode::kFloat64Mul) {
    return false;
  }
  return true;
}

#if V8_TARGET_ARCH_64_BIT
template <typename Adapter>
bool InstructionSelectorT<Adapter>::ZeroExtendsWord32ToWord64(
    node_t node, int recursion_depth) {
  // To compute whether a Node sets its upper 32 bits to zero, there are three
  // cases.
  // 1. Phi node, with a computed result already available in phi_states_:
  //    Read the value from phi_states_.
  // 2. Phi node, with no result available in phi_states_ yet:
  //    Recursively check its inputs, and store the result in phi_states_.
  // 3. Anything else:
  //    Call the architecture-specific ZeroExtendsWord32ToWord64NoPhis.

  // Limit recursion depth to avoid the possibility of stack overflow on very
  // large functions.
  const int kMaxRecursionDepth = 100;

  if (this->IsPhi(node)) {
    if (recursion_depth == 0) {
      if (phi_states_.empty()) {
        // This vector is lazily allocated because the majority of compilations
        // never use it.
        phi_states_ = ZoneVector<Upper32BitsState>(
            node_count_, Upper32BitsState::kNotYetChecked, zone());
      }
    }

    Upper32BitsState current = phi_states_[this->id(node)];
    if (current != Upper32BitsState::kNotYetChecked) {
      return current == Upper32BitsState::kZero;
    }

    // If further recursion is prevented, we can't make any assumptions about
    // the output of this phi node.
    if (recursion_depth >= kMaxRecursionDepth) {
      return false;
    }

    // Optimistically mark the current node as zero-extended so that we skip it
    // if we recursively visit it again due to a cycle. If this optimistic guess
    // is wrong, it will be corrected in MarkNodeAsNotZeroExtended.
    phi_states_[this->id(node)] = Upper32BitsState::kZero;

    int input_count = this->value_input_count(node);
    for (int i = 0; i < input_count; ++i) {
      node_t input = this->input_at(node, i);
      if (!ZeroExtendsWord32ToWord64(input, recursion_depth + 1)) {
        MarkNodeAsNotZeroExtended(node);
        return false;
      }
    }

    return true;
  }
  return ZeroExtendsWord32ToWord64NoPhis(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::MarkNodeAsNotZeroExtended(node_t node) {
  if (phi_states_[this->id(node)] == Upper32BitsState::kMayBeNonZero) return;
  phi_states_[this->id(node)] = Upper32BitsState::kMayBeNonZero;
  ZoneVector<node_t> worklist(zone_);
  worklist.push_back(node);
  while (!worklist.empty()) {
    node = worklist.back();
    worklist.pop_back();
    // We may have previously marked some uses of this node as zero-extended,
    // but that optimistic guess was proven incorrect.
    if constexpr (Adapter::IsTurboshaft) {
      for (turboshaft::OpIndex use : turboshaft_uses(node)) {
        if (phi_states_[this->id(use)] == Upper32BitsState::kZero) {
          phi_states_[this->id(use)] = Upper32BitsState::kMayBeNonZero;
          worklist.push_back(use);
        }
      }
    } else {
      for (Edge edge : node->use_edges()) {
        Node* use = edge.from();
        if (phi_states_[this->id(use)] == Upper32BitsState::kZero) {
          phi_states_[this->id(use)] = Upper32BitsState::kMayBeNonZero;
          worklist.push_back(use);
        }
      }
    }
  }
}
#endif  // V8_TARGET_ARCH_64_BIT

namespace {

FrameStateDescriptor* GetFrameStateDescriptorInternal(
    Zone* zone, turboshaft::Graph* graph,
    const turboshaft::FrameStateOp& state) {
  const FrameStateInfo& state_info = state.data->frame_state_info;
  uint16_t parameters = state_info.parameter_count();
  uint16_t max_arguments = state_info.max_arguments();
  int locals = state_info.local_count();
  int stack = state_info.stack_count();

  FrameStateDescriptor* outer_state = nullptr;
  if (state.inlined) {
    outer_state = GetFrameStateDescriptorInternal(
        zone, graph,
        graph->Get(state.parent_frame_state())
            .template Cast<turboshaft::FrameStateOp>());
  }

#if V8_ENABLE_WEBASSEMBLY
  if (state_info.type() == FrameStateType::kJSToWasmBuiltinContinuation) {
    auto function_info = static_cast<const JSToWasmFrameStateFunctionInfo*>(
        state_info.function_info());
    return zone->New<JSToWasmFrameStateDescriptor>(
        zone, state_info.type(), state_info.bailout_id(),
        state_info.state_combine(), parameters, locals, stack,
        state_info.shared_info(), outer_state, function_info->signature());
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  return zone->New<FrameStateDescriptor>(
      zone, state_info.type(), state_info.bailout_id(),
      state_info.state_combine(), parameters, max_arguments, locals, stack,
      state_info.shared_info(), state_info.bytecode_array(), outer_state,
      state_info.function_info()->wasm_liftoff_frame_size(),
      state_info.function_info()->wasm_function_index());
}

FrameStateDescriptor* GetFrameStateDescriptorInternal(Zone* zone,
                                                      FrameState state) {
  DCHECK_EQ(IrOpcode::kFrameState, state->opcode());
  DCHECK_EQ(FrameState::kFrameStateInputCount, state->InputCount());
  const FrameStateInfo& state_info = FrameStateInfoOf(state->op());
  uint16_t parameters = state_info.parameter_count();
  uint16_t max_arguments = state_info.max_arguments();
  int locals = state_info.local_count();
  int stack = state_info.stack_count();

  FrameStateDescriptor* outer_state = nullptr;
  if (state.outer_frame_state()->opcode() == IrOpcode::kFrameState) {
    outer_state = GetFrameStateDescriptorInternal(
        zone, FrameState{state.outer_frame_state()});
  }

#if V8_ENABLE_WEBASSEMBLY
  if (state_info.type() == FrameStateType::kJSToWasmBuiltinContinuation) {
    auto function_info = static_cast<const JSToWasmFrameStateFunctionInfo*>(
        state_info.function_info());
    return zone->New<JSToWasmFrameStateDescriptor>(
        zone, state_info.type(), state_info.bailout_id(),
        state_info.state_combine(), parameters, locals, stack,
        state_info.shared_info(), outer_state, function_info->signature());
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  return zone->New<FrameStateDescriptor>(
      zone, state_info.type(), state_info.bailout_id(),
      state_info.state_combine(), parameters, max_arguments, locals, stack,
      state_info.shared_info(), state_info.bytecode_array(), outer_state,
      state_info.function_info()->wasm_liftoff_frame_size(),
      state_info.function_info()->wasm_function_index());
}

}  // namespace

template <>
FrameStateDescriptor*
InstructionSelectorT<TurboshaftAdapter>::GetFrameStateDescriptor(node_t node) {
  const turboshaft::FrameStateOp& state =
      this->turboshaft_graph()
          ->Get(node)
          .template Cast<turboshaft::FrameStateOp>();
  auto* desc = GetFrameStateDescriptorInternal(instruction_zone(),
                                               this->turboshaft_graph(), state);
  *max_unoptimized_frame_height_ =
      std::max(*max_unoptimized_frame_height_,
               desc->total_conservative_frame_size_in_bytes() +
                   (desc->max_arguments() * kSystemPointerSize));
  return desc;
}

template <>
FrameStateDescriptor*
InstructionSelectorT<TurbofanAdapter>::GetFrameStateDescriptor(node_t node) {
  FrameState state{node};
  auto* desc = GetFrameStateDescriptorInternal(instruction_zone(), state);
  *max_unoptimized_frame_height_ =
      std::max(*max_unoptimized_frame_height_,
               desc->total_conservative_frame_size_in_bytes() +
                   (desc->max_arguments() * kSystemPointerSize));
  return desc;
}

#if V8_ENABLE_WEBASSEMBLY
// static
template <typename Adapter>
void InstructionSelectorT<Adapter>::SwapShuffleInputs(
    typename Adapter::SimdShuffleView& view) {
  view.SwapInputs();
}
#endif  // V8_ENABLE_WEBASSEMBLY

template class InstructionSelectorT<TurbofanAdapter>;
template class InstructionSelectorT<TurboshaftAdapter>;

// static
InstructionSelector InstructionSelector::ForTurbofan(
    Zone* zone, size_t node_count, Linkage* linkage,
    InstructionSequence* sequence, Schedule* schedule,
    SourcePositionTable* source_positions, Frame* frame,
    EnableSwitchJumpTable enable_switch_jump_table, TickCounter* tick_counter,
    JSHeapBroker* broker, size_t* max_unoptimized_frame_height,
    size_t* max_pushed_argument_count, SourcePositionMode source_position_mode,
    Features features, EnableScheduling enable_scheduling,
    EnableRootsRelativeAddressing enable_roots_relative_addressing,
    EnableTraceTurboJson trace_turbo) {
  return InstructionSelector(
      new InstructionSelectorT<TurbofanAdapter>(
          zone, node_count, linkage, sequence, schedule, source_positions,
          frame, enable_switch_jump_table, tick_counter, broker,
          max_unoptimized_frame_height, max_pushed_argument_count,
          source_position_mode, features, enable_scheduling,
          enable_roots_relative_addressing, trace_turbo),
      nullptr);
}

InstructionSelector InstructionSelector::ForTurboshaft(
    Zone* zone, size_t node_count, Linkage* linkage,
    InstructionSequence* sequence, turboshaft::Graph* graph, Frame* frame,
    EnableSwitchJumpTable enable_switch_jump_table, TickCounter* tick_counter,
    JSHeapBroker* broker, size_t* max_unoptimized_frame_height,
    size_t* max_pushed_argument_count, SourcePositionMode source_position_mode,
    Features features, EnableScheduling enable_scheduling,
    EnableRootsRelativeAddressing enable_roots_relative_addressing,
    EnableTraceTurboJson trace_turbo) {
  return InstructionSelector(
      nullptr,
      new InstructionSelectorT<TurboshaftAdapter>(
          zone, node_count, linkage, sequence, graph,
          &graph->source_positions(), frame, enable_switch_jump_table,
          tick_counter, broker, max_unoptimized_frame_height,
          max_pushed_argument_count, source_position_mode, features,
          enable_scheduling, enable_roots_relative_addressing, trace_turbo));
}

InstructionSelector::InstructionSelector(
    InstructionSelectorT<TurbofanAdapter>* turbofan_impl,
    InstructionSelectorT<TurboshaftAdapter>* turboshaft_impl)
    : turbofan_impl_(turbofan_impl), turboshaft_impl_(turboshaft_impl) {
  DCHECK_NE(!turbofan_impl_, !turboshaft_impl_);
}

InstructionSelector::~InstructionSelector() {
  DCHECK_NE(!turbofan_impl_, !turboshaft_impl_);
  delete turbofan_impl_;
  delete turboshaft_impl_;
}

#define DISPATCH_TO_IMPL(...)                    \
  DCHECK_NE(!turbofan_impl_, !turboshaft_impl_); \
  if (turbofan_impl_) {                          \
    return turbofan_impl_->__VA_ARGS__;          \
  } else {                                       \
    return turboshaft_impl_->__VA_ARGS__;        \
  }

std::optional<BailoutReason> InstructionSelector::SelectInstructions() {
  DISPATCH_TO_IMPL(SelectInstructions())
}

bool InstructionSelector::IsSupported(CpuFeature feature) const {
  DISPATCH_TO_IMPL(IsSupported(feature))
}

const ZoneVector<std::pair<int, int>>& InstructionSelector::instr_origins()
    const {
  DISPATCH_TO_IMPL(instr_origins())
}

const std::map<NodeId, int> InstructionSelector::GetVirtualRegistersForTesting()
    const {
  DISPATCH_TO_IMPL(GetVirtualRegistersForTesting());
}

#undef DISPATCH_TO_IMPL
#undef VISIT_UNSUPPORTED_OP

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```