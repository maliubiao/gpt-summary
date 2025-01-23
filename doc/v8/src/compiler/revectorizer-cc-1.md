Response:
The user wants me to analyze a C++ source code file (`v8/src/compiler/revectorizer.cc`) from the V8 JavaScript engine and explain its functionality. I need to address several specific points:

1. **Core Functionality:** Describe what this code does.
2. **Torque Source:** Check if the filename ends with `.tq`. If so, mention that it's a V8 Torque source file.
3. **JavaScript Relation:** If the code relates to JavaScript functionality, provide a JavaScript example.
4. **Code Logic Inference:**  If there's logical reasoning in the code, give a hypothetical input and output.
5. **Common Programming Errors:** If the code touches upon common user programming errors, provide an example.
6. **Summary:** Provide a concise summary of the code's purpose, given that this is the second part of a two-part explanation.

**Analysis of the Code Snippet:**

The code snippet provided seems to be focused on the "revectorization" process within the V8 compiler. It deals with optimizing SIMD (Single Instruction, Multiple Data) operations. Here's a breakdown of the key parts:

* **`Revectorizer` Class:** This class is responsible for the revectorization logic.
* **`VectorizeTree` Function:** This is the core function. It takes a `PackNode` (likely representing a group of related SIMD operations) and attempts to combine them into wider SIMD operations (e.g., combining two 128-bit SIMD operations into a single 256-bit operation).
* **SIMD Opcode Handling:** The `switch (op)` statement handles various SIMD opcodes (`kPhi`, `kLoopExitValue`, `kI8x16Shuffle`, `kS128Zero`, `kS128Const`, `kProtectedLoad`, `kLoad`, `kProtectedStore`, `kStore`, `kLoadTransform`, `kExtractF128`). It defines how each 128-bit SIMD operation can be "revectorized" into a 256-bit equivalent.
* **Memory Operations:** The code handles loads and stores (`kLoad`, `kStore`, `kProtectedLoad`, `kProtectedStore`) and transforms them to wider SIMD versions.
* **Shuffle Operations:** The code has specific logic for handling `kI8x16Shuffle`, potentially combining two 128-bit shuffles into a single 256-bit shuffle.
* **`TryRevectorize` Function:** This function orchestrates the revectorization process for a given function. It collects potential candidates for revectorization (`CollectSeeds`), groups them (`group_of_stores_`), and then attempts to reduce and vectorize them (`ReduceStoreChains`, `ReduceStoreChain`).
* **`CollectSeeds`:**  This method seems to identify pairs of 128-bit SIMD store operations that are candidates for being combined into 256-bit stores.
* **`ReduceStoreChains` and `ReduceStoreChain`:** These functions analyze groups of store operations to determine if they can be safely and effectively combined into wider SIMD operations.
* **CPU Feature Detection:** `DetectCPUFeatures` checks if the CPU supports AVX2, which is required for 256-bit SIMD operations.

**Plan for the Response:**

1. **Functionality:** Explain that the code optimizes SIMD operations by combining smaller ones into larger ones (revectorization), focusing on 128-bit to 256-bit SIMD.
2. **Torque:** State that the file does not end in `.tq` and is therefore not a Torque source file.
3. **JavaScript Relation:** Provide a JavaScript example demonstrating how developers use SIMD operations, which this C++ code aims to optimize under the hood.
4. **Code Logic Inference:** Focus on the `VectorizeTree` function and a specific case like `kI8x16Shuffle` to illustrate how two 128-bit shuffle operations are combined into a 256-bit one. Provide a simplified hypothetical input (two 128-bit shuffle nodes) and the expected output (a single 256-bit shuffle node).
5. **Common Programming Errors:**  Discuss how incorrect memory alignment or accessing memory outside of allocated bounds can be problematic with SIMD, even though the C++ code is handling the internal optimization.
6. **Summary:** Summarize the role of this code as part of the V8 compiler's optimization pipeline, specifically for SIMD operations, building on the understanding from the (hypothetical) first part.
这是v8源代码文件 `v8/src/compiler/revectorizer.cc` 的第二部分，延续了第一部分的功能描述。根据提供的代码，我们可以归纳出以下功能：

**核心功能：SIMD (Single Instruction, Multiple Data) 指令的优化（Revectorization）**

该文件的核心目标是识别并优化代码中的 SIMD 指令，特别是将两个相邻的 128 位 SIMD 操作合并为一个 256 位 SIMD 操作，以提升性能。这被称为 "revectorization"。

**具体功能点:**

* **`VectorizeTree(PackNode* pnode)`:**  这是执行 revectorization 的核心函数。它接收一个 `PackNode`，该节点表示一组可以合并的 128 位 SIMD 操作。函数会根据操作类型 (`IrOpcode`) 创建相应的 256 位 SIMD 操作节点。
* **支持多种 SIMD 操作类型:** 代码中 `switch (op)` 语句涵盖了多种 128 位 SIMD 操作，例如：
    * **Phi 和 LoopExitValue:**  处理控制流相关的 SIMD 值。
    * **算术和逻辑运算:**  通过 `SIMPLE_SIMD_OP` 宏定义，支持各种 SIMD 算术和逻辑运算的 revectorization。
    * **移位操作:** 通过 `SIMD_SHIFT_OP` 宏定义，支持 SIMD 移位操作的 revectorization，并确保移位量是相同的标量。
    * **符号扩展转换:** 通过 `SIMD_SIGN_EXTENSION_CONVERT_OP` 宏定义，支持 SIMD 符号扩展转换操作。
    * **Splat 操作:** 通过 `SIMD_SPLAT_OP` 宏定义，支持从标量值创建 SIMD 向量的操作。
    * **Shuffle 操作 (`kI8x16Shuffle`):**  特别处理了 128 位 shuffle 操作合并为 256 位 shuffle 操作的情况，包括 swizzle 操作。如果 shuffle 操作是 splat，则会尝试转换为 `LoadSplat` 操作。
    * **常量和零值:**  支持 128 位 SIMD 常量和零值的 revectorization。
    * **加载和存储操作 (`kProtectedLoad`, `kLoad`, `kProtectedStore`, `kStore`):** 将 128 位 SIMD 加载和存储操作转换为 256 位操作。
    * **加载转换操作 (`kLoadTransform`):**  将各种 128 位 SIMD 加载转换操作转换为相应的 256 位版本。
    * **提取操作 (`kExtractF128`):** 用于在 revectorization 后提取 128 位 SIMD 值。
* **`DetectCPUFeatures()`:** 检测 CPU 是否支持 AVX2 指令集，这是使用 256 位 SIMD 指令的前提。
* **`TryRevectorize(const char* function)`:**  尝试对给定的函数进行 revectorization。它会收集潜在的 revectorization 候选者 (`CollectSeeds`) 并尝试合并它们 (`ReduceStoreChains`, `ReduceStoreChain`).
* **`UpdateSources()`:**  在 revectorization 后，更新相关节点的依赖关系，移除不再使用的源节点。
* **`CollectSeeds()`:**  收集可以进行 revectorization 的存储操作对。它会查找地址相邻且在控制流上支配位置相同的 128 位 SIMD 存储操作。
* **`ReduceStoreChains(ZoneMap<Node*, StoreNodeSet>* store_chains)` 和 `ReduceStoreChain(const ZoneVector<Node*>& Stores)`:**  分析收集到的存储操作链，判断是否可以安全且有效地合并为 256 位存储操作。
* **`PrintStores(ZoneMap<Node*, StoreNodeSet>* store_chains)`:**  用于调试，打印可以进行 revectorization 的存储操作信息。

**关于问题中的其他点：**

* **是否为 Torque 源代码:**  根据文件名 `revectorizer.cc`，它不是以 `.tq` 结尾，因此不是 V8 Torque 源代码。它是标准的 C++ 源代码。
* **与 JavaScript 的关系:**  这个 C++ 代码直接影响 JavaScript 的性能。当 JavaScript 代码中使用 SIMD 类型（例如 `Float32x4`, `Int32x4` 等）进行计算时，V8 的编译器会尝试将这些操作映射到高效的底层机器指令。`revectorizer.cc` 的工作就是进一步优化这些 SIMD 操作。

**JavaScript 示例:**

```javascript
function multiplyVectors(a, b) {
  const result = Float32x4(a.x * b.x, a.y * b.y, a.z * b.z, a.w * b.w);
  return result;
}

const vec1 = Float32x4(1, 2, 3, 4);
const vec2 = Float32x4(5, 6, 7, 8);
const product = multiplyVectors(vec1, vec2);
// 在 V8 内部，revectorizer 可能会将针对 vec1 和 vec2 的操作合并为更宽的 SIMD 指令
```

在这个例子中，`Float32x4` 是 JavaScript 中 SIMD 的类型。V8 的 `revectorizer.cc` 代码会在编译 `multiplyVectors` 函数时，尝试将针对 `vec1` 和 `vec2` 的 SIMD 操作（例如乘法）合并为更高效的 256 位 SIMD 指令（如果硬件支持）。

**代码逻辑推理 (以 `kI8x16Shuffle` 为例):**

**假设输入:**

* 两个相邻的 128 位 SIMD shuffle 操作节点 `node0` 和 `node1`，它们的操作数都是 128 位 SIMD 向量。
* `node0` 和 `node1` 在控制流上是相邻的，并且满足 revectorization 的条件。

**输出:**

* 创建一个新的 256 位 SIMD shuffle 操作节点 `new_node`。
* `new_node` 的操作数是合并后的 256 位向量（由 `node0` 和 `node1` 的输入组成）。
* `new_node` 的 shuffle 掩码是将 `node0` 和 `node1` 的 16 字节掩码合并成一个 32 字节的掩码。例如，如果 `node0` 的掩码是 `[0, 1, ..., 15]`，`node1` 的掩码是 `[0, 1, ..., 15]`，那么 `new_node` 的掩码可能是 `[0, 1, ..., 15, 16, 17, ..., 31]`。
* 原来的 `node0` 和 `node1` 的使用处会被替换为从 `new_node` 提取 128 位部分的指令（如果需要）。

**涉及用户常见的编程错误:**

虽然 `revectorizer.cc` 是编译器内部的优化，但它与用户使用 SIMD 时的常见错误有关，例如：

* **内存对齐问题:** SIMD 指令通常要求操作数在内存中是对齐的（例如，16 字节对齐）。如果用户在 JavaScript 中使用的 ArrayBuffer 或 TypedArray 没有正确对齐，那么底层的 SIMD 操作可能会导致性能下降甚至错误。虽然 revectorizer 尝试优化，但前提是底层的内存访问是有效的。
* **不必要的独立 SIMD 操作:** 用户可能编写了可以合并为更宽 SIMD 操作的独立 SIMD 代码，但并没有意识到。`revectorizer` 的作用就是尝试在编译时自动进行这种合并。

**示例 (内存对齐问题):**

```javascript
const buffer = new ArrayBuffer(20); // 长度不是 16 的倍数
const view = new Float32Array(buffer);
const vec1 = Float32x4(1, 2, 3, 4);
const vec2 = Float32x4(view[0], view[1], view[2], view[3]); // 可能未正确对齐
const result = Float32x4.add(vec1, vec2);
```

在这个例子中，如果 `view` 的起始地址没有 16 字节对齐，那么尝试将其加载到 `vec2` 中可能会导致性能问题。虽然 `revectorizer` 无法直接解决这种用户代码中的内存对齐问题，但它依赖于后续的机器码生成阶段能够处理这些情况（可能会回退到非 SIMD 操作或使用特殊的非对齐加载指令）。

**总结 (结合第一部分):**

综合来看，`v8/src/compiler/revectorizer.cc` 是 V8 编译器中负责 SIMD 指令优化的重要组成部分。它通过分析程序中的 128 位 SIMD 操作，尝试将相邻且符合条件的指令合并为更宽的 256 位 SIMD 指令，从而提高 JavaScript 代码的执行效率，特别是在处理大量数值计算时。 第一部分可能负责了 revectorization 的前期准备工作，例如识别潜在的 revectorization 机会，而第二部分则专注于实际的指令合并和图节点的修改。该模块依赖于硬件对 AVX2 指令集的支持，并在编译时进行静态分析和优化。

### 提示词
```
这是目录为v8/src/compiler/revectorizer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/revectorizer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
\n", __func__);

  Node* node0 = pnode->Nodes()[0];
  Node* node1 = pnode->Nodes()[1];
  if (pnode->RevectorizedNode()) {
    TRACE("Diamond merged for #%d:%s\n", node0->id(), node0->op()->mnemonic());
    return pnode->RevectorizedNode();
  }

  int input_count = node0->InputCount();
  TRACE("Vectorize #%d:%s, input count: %d\n", node0->id(),
        node0->op()->mnemonic(), input_count);

  IrOpcode::Value op = node0->opcode();
  const Operator* new_op = nullptr;
  Node* source = nullptr;
  Node* dead = mcgraph()->Dead();
  base::SmallVector<Node*, 2> inputs(input_count);
  for (int i = 0; i < input_count; i++) inputs[i] = dead;

  switch (op) {
    case IrOpcode::kPhi: {
      DCHECK_EQ(PhiRepresentationOf(node0->op()),
                MachineRepresentation::kSimd128);
      new_op = mcgraph_->common()->Phi(MachineRepresentation::kSimd256,
                                       input_count - 1);
      inputs[input_count - 1] = NodeProperties::GetControlInput(node0);
      break;
    }
    case IrOpcode::kLoopExitValue: {
      DCHECK_EQ(LoopExitValueRepresentationOf(node0->op()),
                MachineRepresentation::kSimd128);
      new_op =
          mcgraph_->common()->LoopExitValue(MachineRepresentation::kSimd256);
      inputs[input_count - 1] = NodeProperties::GetControlInput(node0);
      break;
    }
#define SIMPLE_CASE(from, to)           \
  case IrOpcode::k##from:               \
    new_op = mcgraph_->machine()->to(); \
    break;
      SIMPLE_SIMD_OP(SIMPLE_CASE)
#undef SIMPLE_CASE
#undef SIMPLE_SIMD_OP

#define SHIFT_CASE(from, to)                   \
  case IrOpcode::k##from: {                    \
    DCHECK(ShiftBySameScalar(pnode->Nodes())); \
    new_op = mcgraph_->machine()->to();        \
    inputs[1] = node0->InputAt(1);             \
    break;                                     \
  }
      SIMD_SHIFT_OP(SHIFT_CASE)
#undef SHIFT_CASE
#undef SIMD_SHIFT_OP

#define SIGN_EXTENSION_CONVERT_CASE(from, not_used, to)          \
  case IrOpcode::k##from: {                                      \
    DCHECK_EQ(node0->InputAt(0), pnode->Nodes()[1]->InputAt(0)); \
    new_op = mcgraph_->machine()->to();                          \
    inputs[0] = node0->InputAt(0);                               \
    break;                                                       \
  }
      SIMD_SIGN_EXTENSION_CONVERT_OP(SIGN_EXTENSION_CONVERT_CASE)
#undef SIGN_EXTENSION_CONVERT_CASE
#undef SIMD_SIGN_EXTENSION_CONVERT_OP

#define SPLAT_CASE(from, to)            \
  case IrOpcode::k##from:               \
    new_op = mcgraph_->machine()->to(); \
    inputs[0] = node0->InputAt(0);      \
    break;
      SIMD_SPLAT_OP(SPLAT_CASE)
#undef SPLAT_CASE
#undef SIMD_SPLAT_OP
    case IrOpcode::kI8x16Shuffle: {
      // clang-format off
      if (IsSplat(pnode->Nodes())) {
        const uint8_t* shuffle = S128ImmediateParameterOf(node0->op()).data();
        int index, offset;

        // Match Splat and Revectorize to LoadSplat as AVX-256 does not support
        // shuffling across 128-bit lane.
        if (wasm::SimdShuffle::TryMatchSplat<4>(shuffle, &index)) {
          new_op = mcgraph_->machine()->LoadTransform(
              MemoryAccessKind::kProtectedByTrapHandler,
              LoadTransformation::kS256Load32Splat);
          offset = index * 4;
        } else if (wasm::SimdShuffle::TryMatchSplat<2>(shuffle, &index)) {
          new_op = mcgraph_->machine()->LoadTransform(
              MemoryAccessKind::kProtectedByTrapHandler,
              LoadTransformation::kS256Load64Splat);
          offset = index * 8;
        } else {
          UNREACHABLE();
        }

        source = node0->InputAt(offset >> 4);
        DCHECK_EQ(source->opcode(), IrOpcode::kProtectedLoad);
        inputs.resize_no_init(4);
        // Update LoadSplat offset.
        if (index) {
          SourcePositionTable::Scope scope(source_positions_, source);
          inputs[0] = graph()->NewNode(mcgraph_->machine()->Int64Add(),
                                       source->InputAt(0),
                                       mcgraph_->Int64Constant(offset));
        } else {
          inputs[0] = source->InputAt(0);
        }
        // Keep source index, effect and control inputs.
        inputs[1] = source->InputAt(1);
        inputs[2] = source->InputAt(2);
        inputs[3] = source->InputAt(3);
        input_count = 4;
      } else {
        const uint8_t* shuffle0 = S128ImmediateParameterOf(node0->op()).data();
        const uint8_t* shuffle1 = S128ImmediateParameterOf(node1->op()).data();
        uint8_t new_shuffle[32];

        if (node0->InputAt(0) == node0->InputAt(1) &&
            node1->InputAt(0) == node1->InputAt(1)) {
          // Shuffle is Swizzle
          for (int i = 0; i < 16; ++i) {
            new_shuffle[i] = shuffle0[i] % 16;
            new_shuffle[i + 16] = 16 + shuffle1[i] % 16;
          }
        } else {
          for (int i = 0; i < 16; ++i) {
            if (shuffle0[i] < 16) {
              new_shuffle[i] = shuffle0[i];
            } else {
              new_shuffle[i] = 16 + shuffle0[i];
            }

            if (shuffle1[i] < 16) {
              new_shuffle[i + 16] = 16 + shuffle1[i];
            } else {
              new_shuffle[i + 16] = 32 + shuffle1[i];
            }
          }
        }
        new_op = mcgraph_->machine()->I8x32Shuffle(new_shuffle);
      }
      break;
      // clang-format on
    }
    case IrOpcode::kS128Zero: {
      new_op = mcgraph_->machine()->S256Zero();
      break;
    }
    case IrOpcode::kS128Const: {
      uint8_t value[32];
      const uint8_t* value0 = S128ImmediateParameterOf(node0->op()).data();
      const uint8_t* value1 = S128ImmediateParameterOf(node1->op()).data();
      for (int i = 0; i < kSimd128Size; ++i) {
        value[i] = value0[i];
        value[i + 16] = value1[i];
      }
      new_op = mcgraph_->machine()->S256Const(value);
      break;
    }
    case IrOpcode::kProtectedLoad: {
      DCHECK_EQ(LoadRepresentationOf(node0->op()).representation(),
                MachineRepresentation::kSimd128);
      new_op = mcgraph_->machine()->ProtectedLoad(MachineType::Simd256());
      SetMemoryOpInputs(inputs, pnode, 2);
      break;
    }
    case IrOpcode::kLoad: {
      DCHECK_EQ(LoadRepresentationOf(node0->op()).representation(),
                MachineRepresentation::kSimd128);
      new_op = mcgraph_->machine()->Load(MachineType::Simd256());
      SetMemoryOpInputs(inputs, pnode, 2);
      break;
    }
    case IrOpcode::kProtectedStore: {
      DCHECK_EQ(StoreRepresentationOf(node0->op()).representation(),
                MachineRepresentation::kSimd128);
      new_op =
          mcgraph_->machine()->ProtectedStore(MachineRepresentation::kSimd256);
      SetMemoryOpInputs(inputs, pnode, 3);
      break;
    }
    case IrOpcode::kStore: {
      DCHECK_EQ(StoreRepresentationOf(node0->op()).representation(),
                MachineRepresentation::kSimd128);
      WriteBarrierKind write_barrier_kind =
          StoreRepresentationOf(node0->op()).write_barrier_kind();
      new_op = mcgraph_->machine()->Store(StoreRepresentation(
          MachineRepresentation::kSimd256, write_barrier_kind));
      SetMemoryOpInputs(inputs, pnode, 3);
      break;
    }
    case IrOpcode::kLoadTransform: {
      LoadTransformParameters params = LoadTransformParametersOf(node0->op());
      LoadTransformation new_transformation;

      // clang-format off
      switch (params.transformation) {
        case LoadTransformation::kS128Load8Splat:
          new_transformation = LoadTransformation::kS256Load8Splat;
          break;
        case LoadTransformation::kS128Load16Splat:
          new_transformation = LoadTransformation::kS256Load16Splat;
          break;
        case LoadTransformation::kS128Load32Splat:
          new_transformation = LoadTransformation::kS256Load32Splat;
          break;
        case LoadTransformation::kS128Load64Splat:
          new_transformation = LoadTransformation::kS256Load64Splat;
          break;
        case LoadTransformation::kS128Load8x8S:
          new_transformation = LoadTransformation::kS256Load8x16S;
          break;
        case LoadTransformation::kS128Load8x8U:
          new_transformation = LoadTransformation::kS256Load8x16U;
          break;
        case LoadTransformation::kS128Load16x4S:
          new_transformation = LoadTransformation::kS256Load16x8S;
          break;
        case LoadTransformation::kS128Load16x4U:
          new_transformation = LoadTransformation::kS256Load16x8U;
          break;
        case LoadTransformation::kS128Load32x2S:
          new_transformation = LoadTransformation::kS256Load32x4S;
          break;
        case LoadTransformation::kS128Load32x2U:
          new_transformation = LoadTransformation::kS256Load32x4U;
          break;
        default:
          UNREACHABLE();
      }
      // clang-format on

      new_op =
          mcgraph_->machine()->LoadTransform(params.kind, new_transformation);
      SetMemoryOpInputs(inputs, pnode, 2);
      break;
    }
    case IrOpcode::kExtractF128: {
      pnode->SetRevectorizedNode(node0->InputAt(0));
      // The extract uses other than its parent don't need to change.
      break;
    }
    default:
      UNREACHABLE();
  }

  DCHECK(pnode->RevectorizedNode() || new_op);
  if (new_op != nullptr) {
    SourcePositionTable::Scope scope(source_positions_, node0);
    Node* new_node =
        graph()->NewNode(new_op, input_count, inputs.begin(), true);
    pnode->SetRevectorizedNode(new_node);
    for (int i = 0; i < input_count; i++) {
      if (inputs[i] == dead) {
        new_node->ReplaceInput(i, VectorizeTree(pnode->GetOperand(i)));
      }
    }
    // Extract Uses
    const ZoneVector<Node*>& nodes = pnode->Nodes();
    for (size_t i = 0; i < nodes.size(); i++) {
      if (i > 0 && nodes[i] == nodes[i - 1]) continue;
      Node* input_128 = nullptr;
      for (auto edge : nodes[i]->use_edges()) {
        Node* useNode = edge.from();
        if (!GetPackNode(useNode)) {
          if (NodeProperties::IsValueEdge(edge)) {
            // Extract use
            TRACE("Replace Value Edge from %d:%s, to %d:%s\n", useNode->id(),
                  useNode->op()->mnemonic(), edge.to()->id(),
                  edge.to()->op()->mnemonic());

            if (!input_128) {
              TRACE("Create ExtractF128(%lu) node from #%d\n", i,
                    new_node->id());
              input_128 = graph()->NewNode(
                  mcgraph()->machine()->ExtractF128(static_cast<int32_t>(i)),
                  new_node);
            }
            edge.UpdateTo(input_128);
          } else if (NodeProperties::IsEffectEdge(edge)) {
            TRACE("Replace Effect Edge from %d:%s, to %d:%s\n", useNode->id(),
                  useNode->op()->mnemonic(), edge.to()->id(),
                  edge.to()->op()->mnemonic());

            edge.UpdateTo(new_node);
          }
        }
      }
      if (nodes[i]->uses().empty()) nodes[i]->Kill();
    }

    // Update effect use of NewNode from the dependent source.
    if (op == IrOpcode::kI8x16Shuffle && IsSplat(nodes)) {
      DCHECK(source);
      NodeProperties::ReplaceEffectInput(source, new_node, 0);
      TRACE("Replace Effect Edge from %d:%s, to %d:%s\n", source->id(),
            source->op()->mnemonic(), new_node->id(),
            new_node->op()->mnemonic());
      // Remove unused value use, so that we can safely elimite the node later.
      NodeProperties::ReplaceValueInput(node0, dead, 0);
      NodeProperties::ReplaceValueInput(node0, dead, 1);
      TRACE("Remove Value Input of %d:%s\n", node0->id(),
            node0->op()->mnemonic());

      // We will try cleanup source nodes later
      sources_.insert(source);
    }
  }

  return pnode->RevectorizedNode();
}

void Revectorizer::DetectCPUFeatures() {
  base::CPU cpu;
  if (v8_flags.enable_avx && v8_flags.enable_avx2 && cpu.has_avx2()) {
    support_simd256_ = true;
  }
}

bool Revectorizer::TryRevectorize(const char* function) {
  source_positions_->AddDecorator();

  bool success = false;
  if (support_simd256_ && graph_->GetSimdStoreNodes().size()) {
    TRACE("TryRevectorize %s\n", function);
    CollectSeeds();
    for (auto entry : group_of_stores_) {
      ZoneMap<Node*, StoreNodeSet>* store_chains = entry.second;
      if (store_chains != nullptr) {
        PrintStores(store_chains);
        if (ReduceStoreChains(store_chains)) {
          TRACE("Successful revectorize %s\n", function);
          success = true;
        }
      }
    }
    TRACE("Finish revectorize %s\n", function);
  }
  source_positions_->RemoveDecorator();
  return success;
}

void Revectorizer::UpdateSources() {
  for (auto* src : sources_) {
    std::vector<Node*> effect_uses;
    bool hasExternalValueUse = false;
    for (auto edge : src->use_edges()) {
      Node* use = edge.from();
      if (!GetPackNode(use)) {
        if (NodeProperties::IsValueEdge(edge)) {
          TRACE("Source node has external value dependence %d:%s\n",
                edge.from()->id(), edge.from()->op()->mnemonic());
          hasExternalValueUse = true;
          break;
        } else if (NodeProperties::IsEffectEdge(edge)) {
          effect_uses.push_back(use);
        }
      }
    }

    if (!hasExternalValueUse) {
      // Remove unused source and linearize effect chain.
      Node* effect = NodeProperties::GetEffectInput(src);
      for (auto use : effect_uses) {
        TRACE("Replace Effect Edge for source node from %d:%s, to %d:%s\n",
              use->id(), use->op()->mnemonic(), effect->id(),
              effect->op()->mnemonic());
        NodeProperties::ReplaceEffectInput(use, effect, 0);
      }
    }
  }

  sources_.clear();
}

void Revectorizer::CollectSeeds() {
  for (auto it = graph_->GetSimdStoreNodes().begin();
       it != graph_->GetSimdStoreNodes().end(); ++it) {
    Node* node = *it;
    Node* dominator = slp_tree_->GetEarlySchedulePosition(node);

    if ((GetMemoryOffsetValue(node) % kSimd128Size) != 0) {
      continue;
    }
    Node* address = GetNodeAddress(node);
    ZoneMap<Node*, StoreNodeSet>* store_nodes;
    auto first_level_iter = group_of_stores_.find(dominator);
    if (first_level_iter == group_of_stores_.end()) {
      store_nodes = zone_->New<ZoneMap<Node*, StoreNodeSet>>(zone_);
      group_of_stores_[dominator] = store_nodes;
    } else {
      store_nodes = first_level_iter->second;
    }
    auto second_level_iter = store_nodes->find(address);
    if (second_level_iter == store_nodes->end()) {
      second_level_iter =
          store_nodes->insert({address, StoreNodeSet(zone())}).first;
    }
    second_level_iter->second.insert(node);
  }
}

bool Revectorizer::ReduceStoreChains(
    ZoneMap<Node*, StoreNodeSet>* store_chains) {
  TRACE("Enter %s\n", __func__);
  bool changed = false;
  for (auto chain_iter = store_chains->cbegin();
       chain_iter != store_chains->cend(); ++chain_iter) {
    if (chain_iter->second.size() >= 2 && chain_iter->second.size() % 2 == 0) {
      ZoneVector<Node*> store_chain(chain_iter->second.begin(),
                                    chain_iter->second.end(), zone_);
      for (auto it = store_chain.begin(); it < store_chain.end(); it = it + 2) {
        ZoneVector<Node*> stores_unit(it, it + 2, zone_);
        if ((NodeProperties::GetEffectInput(stores_unit[0]) == stores_unit[1] ||
             NodeProperties::GetEffectInput(stores_unit[1]) ==
                 stores_unit[0]) &&
            ReduceStoreChain(stores_unit)) {
          changed = true;
        }
      }
    }
  }

  return changed;
}

bool Revectorizer::ReduceStoreChain(const ZoneVector<Node*>& Stores) {
  TRACE("Enter %s, root@ (#%d,#%d)\n", __func__, Stores[0]->id(),
        Stores[1]->id());
  if (!IsContinuousAccess(Stores)) {
    return false;
  }

  PackNode* root = slp_tree_->BuildTree(Stores);
  if (!root) {
    TRACE("Build tree failed!\n");
    return false;
  }

  slp_tree_->Print("After build tree");

  if (DecideVectorize()) {
    VectorizeTree(root);
    UpdateSources();
    slp_tree_->Print("After vectorize tree");

    if (node_observer_for_test_) {
      slp_tree_->ForEach([&](const PackNode* pnode) {
        Node* node = pnode->RevectorizedNode();
        if (node) {
          node_observer_for_test_->OnNodeCreated(node);
        }
      });
    }
  }

  TRACE("\n");
  return true;
}

void Revectorizer::PrintStores(ZoneMap<Node*, StoreNodeSet>* store_chains) {
  if (!v8_flags.trace_wasm_revectorize) {
    return;
  }
  TRACE("Enter %s\n", __func__);
  for (auto it = store_chains->cbegin(); it != store_chains->cend(); ++it) {
    if (it->second.size() > 0) {
      TRACE("address = #%d:%s \n", it->first->id(),
            it->first->op()->mnemonic());

      for (auto node : it->second) {
        TRACE("#%d:%s, ", node->id(), node->op()->mnemonic());
      }

      TRACE("\n");
    }
  }
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```