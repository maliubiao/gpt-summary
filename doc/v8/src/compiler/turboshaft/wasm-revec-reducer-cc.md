Response:
My thinking process to arrive at the summary of `wasm-revec-reducer.cc` goes like this:

1. **Understand the File Path:** The path `v8/src/compiler/turboshaft/wasm-revec-reducer.cc` immediately tells me this code is part of the V8 JavaScript engine, specifically the Turboshaft compiler (a newer compiler pipeline), and is related to WebAssembly (`wasm`) and a "revec-reducer". "Revec" likely refers to "revectorization," a compiler optimization technique.

2. **Initial Code Scan - Keywords and Structure:**  I quickly scan the code for prominent keywords and structural elements:
    * `#include`:  Headers like `<optional>`, logging, `opmasks.h`, and `simd-shuffle.h` hint at the code's purpose. The presence of `simd-shuffle.h` strongly suggests SIMD (Single Instruction, Multiple Data) optimizations.
    * `#define TRACE(...)`:  This indicates debugging/logging functionality specifically for this component.
    * `namespace v8::internal::compiler::turboshaft`:  Confirms the location within the V8 codebase.
    * Function definitions:  I look at the function names: `IsSameOpAndKind`, `GetSimdOpcodeName`, the `StoreLoadInfo` template, `LoadStrideEqualTo`, `IsSplat`, the `SLPTree` class and its methods (`GetPackNode`, `GetIntersectPackNodes`, `Print`, `HasInputDependencies`, `NewPackNode`, etc.), and various matching functions (`Try256ShuffleMatchLoad8x8U`, `TryGetExtendIntToF32x4Info`, `TryMatchExtendIntToF32x4`). These names provide strong clues about the code's functionality.

3. **Identify Core Concepts:** Based on the keywords and function names, I start to identify the core concepts:
    * **SIMD:**  The repeated mention of "Simd128" and "shuffle" clearly points to SIMD vectorization.
    * **Load/Store Optimization:** The `StoreLoadInfo` class and `LoadStrideEqualTo` suggest optimizations related to memory access patterns.
    * **Pattern Matching:**  Functions like `Try256ShuffleMatchLoad8x8U` and `TryGetExtendIntToF32x4Info` indicate the code is looking for specific patterns in the IR (Intermediate Representation) of the WebAssembly code.
    * **Node Groups and Packing:** The `NodeGroup` concept and the `SLPTree` class with `PackNode` and related types are central. This implies the code groups similar operations together for optimization.
    * **SLP Tree:** The `SLPTree` class suggests the use of a "Superword Level Parallelism" (SLP) tree, a data structure used in vectorization to find independent operations that can be executed in parallel on SIMD units.

4. **Infer the Purpose of `WasmRevecReducer`:** Combining the above, I can infer that `wasm-revec-reducer.cc` is responsible for **identifying opportunities to vectorize WebAssembly code by grouping similar operations together** (primarily SIMD operations) and potentially rearranging memory accesses for more efficient SIMD execution.

5. **Focus on the `SLPTree` Class:** The `SLPTree` class seems to be the core component. I analyze its methods:
    * `GetPackNode`, `GetIntersectPackNodes`:  Accessing the packing information.
    * `NewPackNode`, `NewForcePackNode`, `NewBundlePackNode`, `NewIntersectPackNode`, `NewShufflePackNode`:  Creating different types of packed nodes, indicating various vectorization strategies.
    * `BuildTree`, `BuildTreeRec`:  Constructing the SLP tree recursively.
    * `CanBePacked`:  Determining if a group of operations is suitable for packing.
    * The "TryMatch" functions: These are for specific SIMD instruction patterns.

6. **Understand the `PackNode` Hierarchy:**  The different types of `PackNode` (e.g., `ForcePackNode`, `BundlePackNode`, `ShufflePackNode`) suggest different ways to represent the grouped operations for optimization.

7. **Consider Potential Use Cases and Limitations:**
    * **Common Programming Errors:** While not explicitly detailed in *this* part of the code, the optimization target (SIMD) and memory access patterns hint at potential errors like unaligned memory access or inefficient use of vector instructions.
    * **Assumptions and Inputs/Outputs:** The code assumes it's working on the Turboshaft IR. The input would be a portion of the IR, and the output would be a modified IR with packed operations.

8. **Synthesize the Summary:**  Based on the analysis, I formulate a concise summary that covers the key functionalities:
    * Its role in Turboshaft and WebAssembly.
    * Its core task of vectorization using an SLP tree.
    * The concept of `PackNode` and its variations.
    * The importance of pattern matching for specific SIMD idioms.
    * The handling of memory operations (loads/stores).
    * The constraints like side effects and basic blocks.

9. **Address the Specific Instructions:** Finally, I go back to the prompt's specific questions:
    * **Functionality Listing:**  I enumerate the key functionalities identified in the analysis.
    * **`.tq` Extension:** I correctly state that `.tq` indicates Torque (a V8 language).
    * **JavaScript Relation:** I provide a conceptual JavaScript example showing a potential scenario that this code optimizes. Since the code deals with low-level SIMD operations, the JavaScript example is more about *what* the WASM might be doing.
    * **Logic Reasoning:** I give a simplified example of input and output related to packing two addition operations.
    * **Common Errors:** I provide examples of potential programming errors in the *WASM* code that this optimization might target.
    * **Overall Functionality:** I provide a high-level summary as requested.

This iterative process of scanning, identifying concepts, inferring purpose, focusing on key components, and then synthesizing the information allows me to create a comprehensive summary of the given C++ source code, even without a deep understanding of every single line.
这是 v8/src/compiler/turboshaft/wasm-revec-reducer.cc 源代码的第一部分，其主要功能是 **WebAssembly 代码的向量化优化（revectorization）**。更具体地说，它旨在识别可以组合成 SIMD（单指令多数据）操作的标量操作序列，从而提高 WebAssembly 代码的执行效率。

以下是根据代码内容归纳的功能点：

**核心功能：**

1. **识别可打包的节点对 (Node Groups)：**  代码定义了 `NodeGroup` 来表示一对可以被组合成 SIMD 操作的节点。它通过 `CanBePacked` 函数来判断两个操作是否可以打包在一起，考虑了操作码、操作类型、副作用和是否在同一个基本块等因素。

2. **构建 SLP (Superword Level Parallelism) 树：**  代码使用 `SLPTree` 类来构建一个树形结构，用于表示可以并行执行的 SIMD 操作。`BuildTree` 和 `BuildTreeRec` 函数负责递归地构建这个树。

3. **表示打包节点 (Pack Nodes)：** 代码定义了 `PackNode` 类及其子类（如 `ForcePackNode`, `BundlePackNode`, `ShufflePackNode`），用于表示一组被打包在一起的节点。不同的 `PackNode` 子类可能对应不同的向量化策略。

4. **处理 Load 和 Store 操作的向量化：**  `StoreLoadInfo` 结构体用于分析 `StoreOp` 和 `LoadOp`，计算它们之间的相对偏移，以便识别可以合并的连续内存访问。`LoadStrideEqualTo` 函数用于判断一组 Load 操作是否具有相同的步幅。

5. **处理 SIMD 特定的操作：**
   - 代码包含了对 SIMD 洗牌 (Shuffle) 操作的特殊处理，例如 `Try256ShuffleMatchLoad8x8U` 和 `X64TryMatch256Shuffle`，尝试将标量的洗牌操作组合成更高效的 256 位 SIMD 洗牌指令。
   - `TryGetExtendIntToF32x4Info` 和 `TryMatchExtendIntToF32x4` 尝试识别将多个小的整数值扩展并转换为浮点数的模式，以便进行向量化。

6. **支持强制打包 (Force Packing) 和交叉打包 (Intersect Packing)：**  `ForcePackNode` 用于强制将某些节点对打包在一起，即使它们可能不完全匹配。`IntersectPackNode` 用于处理多个打包节点共享同一个节点的情况。

7. **副作用分析：**  `IsSideEffectFree` 函数用于判断两个操作之间是否存在副作用，这是判断是否可以安全地重新排序或合并操作的关键。

**关于代码格式和命名：**

- 代码使用了清晰的命名约定，例如 `IsSameOpAndKind`，`GetSimdOpcodeName` 等。
- 使用了宏 `TRACE` 进行调试输出，方便跟踪向量化过程。

**与 JavaScript 的关系：**

这段代码直接在 V8 引擎的编译器中工作，它的目标是优化 WebAssembly 代码。虽然它不是直接用 JavaScript 编写的，但它直接影响着在 JavaScript 环境中运行的 WebAssembly 模块的性能。

**假设输入与输出（代码逻辑推理）：**

假设有以下 WebAssembly 操作序列（对应 Turboshaft 的 IR 节点）：

```
node1: i32.add local.get 0, const 1
node2: i32.add local.get 1, const 1
```

如果 `CanBePacked(node1, node2)` 返回 `true` (假设局部变量 0 和 1 可以被视为 SIMD 通道)，那么 `BuildTreeRec` 可能会输出一个 `PackNode`，它包含 `node1` 和 `node2`，并且可能将这两个加法操作表示为一个 SIMD 加法操作。

**用户常见的编程错误（WASM 层面）：**

虽然这段代码本身不直接处理用户的编程错误，但它尝试优化由 WebAssembly 编译器生成的代码。用户在编写 WebAssembly 代码时可能犯的错误，导致这段代码可以进行优化的情况包括：

1. **手写标量 SIMD 操作：** 用户可能没有使用 WebAssembly 的 SIMD 指令，而是使用标量操作来模拟 SIMD 行为。例如，对数组的每个元素进行相同的操作，这段代码可以识别这种模式并将其转换为真正的 SIMD 指令。

   **JavaScript 示例（概念性）：**

   ```javascript
   // 假设 WebAssembly 模块执行类似的操作
   function scalarAdd(arr1, arr2, result) {
     for (let i = 0; i < arr1.length; i++) {
       result[i] = arr1[i] + arr2[i];
     }
   }
   ```

   `wasm-revec-reducer.cc` 的目标就是将 WebAssembly 中类似 `scalarAdd` 的标量操作转换为 SIMD 操作，如果可能的话。

2. **连续但独立的内存访问：** 用户可能连续加载或存储相邻的内存位置，但使用了独立的 Load/Store 指令。这段代码尝试识别这种模式并将它们合并为 SIMD Load/Store 操作。

**总结（第 1 部分的功能）：**

总而言之，`v8/src/compiler/turboshaft/wasm-revec-reducer.cc` 的第一部分主要定义了用于 **识别和表示 WebAssembly 代码中可以进行 SIMD 向量化优化的结构和算法**。它专注于构建 SLP 树，处理 Load/Store 操作，以及识别特定的 SIMD 操作模式，为后续的向量化代码生成做准备。它旨在将标量的操作序列转换为更高效的 SIMD 指令，从而提升 WebAssembly 代码的性能。

### 提示词
```
这是目录为v8/src/compiler/turboshaft/wasm-revec-reducer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/wasm-revec-reducer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/turboshaft/wasm-revec-reducer.h"

#include <optional>

#include "src/base/logging.h"
#include "src/compiler/turboshaft/opmasks.h"
#include "src/wasm/simd-shuffle.h"

#define TRACE(...)                                  \
  do {                                              \
    if (v8_flags.trace_wasm_revectorize) {          \
      PrintF("Revec: %s %d: ", __func__, __LINE__); \
      PrintF(__VA_ARGS__);                          \
    }                                               \
  } while (false)

namespace v8::internal::compiler::turboshaft {

// Returns true if op in node_group have same kind.
bool IsSameOpAndKind(const Operation& op0, const Operation& op1) {
#define CASE(operation)                                \
  case Opcode::k##operation: {                         \
    using Op = operation##Op;                          \
    return op0.Cast<Op>().kind == op1.Cast<Op>().kind; \
  }
  if (op0.opcode != op1.opcode) {
    return false;
  }
  switch (op0.opcode) {
    CASE(Simd128Unary)
    CASE(Simd128Binop)
    CASE(Simd128Shift)
    CASE(Simd128Ternary)
    CASE(Simd128Splat)
    default:
      return true;
  }
#undef CASE
}

std::string GetSimdOpcodeName(Operation const& op) {
  std::ostringstream oss;
  if (op.Is<Simd128BinopOp>() || op.Is<Simd128UnaryOp>() ||
      op.Is<Simd128ShiftOp>() || op.Is<Simd128TestOp>() ||
      op.Is<Simd128TernaryOp>()) {
    op.PrintOptions(oss);
  } else {
    oss << OpcodeName(op.opcode);
  }
  return oss.str();
}

//  This class is the wrapper for StoreOp/LoadOp, which is helpful to calcualte
//  the relative offset between two StoreOp/LoadOp.
template <typename Op,
          typename = std::enable_if_t<
              std::is_same_v<Op, StoreOp> || std::is_same_v<Op, LoadOp> ||
              std::is_same_v<Op, Simd128LoadTransformOp>>>
class StoreLoadInfo {
 public:
  StoreLoadInfo(const Graph* graph, const Op* op)
      : op_(op), offset_(op->offset) {
    base_ = &graph->Get(op->base());
    if constexpr (std::is_same_v<Op, Simd128LoadTransformOp>) {
      DCHECK_EQ(offset_, 0);
      const WordBinopOp* add_op = base_->TryCast<WordBinopOp>();
      if (!add_op || add_op->kind != WordBinopOp::Kind::kAdd ||
          add_op->rep != WordRepresentation::Word64()) {
        SetInvalid();
        return;
      }
      base_ = &graph->Get(add_op->left());
      const ConstantOp* const_op =
          graph->Get(add_op->right()).TryCast<ConstantOp>();
      if (!const_op) {
        SetInvalid();
        return;
      }
      // const_op->word64() won't be greater than uint32::max under 32-bits wasm
      // memory.
      DCHECK_EQ(const_op->word64(), const_op->word32());
      offset_ = const_op->word32();
    }
    const ChangeOp* change = nullptr;
    if constexpr (std::is_same_v<Op, Simd128LoadTransformOp>) {
      change = graph->Get(op->index()).template TryCast<ChangeOp>();
    } else {
      if (!op->index().has_value()) return;
      change = graph->Get(op->index().value()).template TryCast<ChangeOp>();
    }
    if (change == nullptr) {
      SetInvalid();
      return;
    }
    DCHECK_EQ(change->kind, ChangeOp::Kind::kZeroExtend);
    const Operation* change_input = &graph->Get(change->input());
    if (const ConstantOp* const_op = change_input->TryCast<ConstantOp>()) {
      DCHECK_EQ(const_op->kind, ConstantOp::Kind::kWord32);
      int new_offset;
      if (base::bits::SignedAddOverflow32(static_cast<int>(const_op->word32()),
                                          offset_, &new_offset)) {
        // offset is overflow
        SetInvalid();
        return;
      }
      offset_ = new_offset;
      return;
    }
    index_ = change_input;
  }

  std::optional<int> operator-(const StoreLoadInfo<Op>& rhs) const {
    DCHECK(IsValid() && rhs.IsValid());
    bool calculatable = base_ == rhs.base_ && index_ == rhs.index_;

    if constexpr (std::is_same_v<Op, Simd128LoadTransformOp>) {
      calculatable &= (op_->load_kind == rhs.op_->load_kind &&
                       op_->transform_kind == rhs.op_->transform_kind);
    } else {
      calculatable &= (op_->kind == rhs.op_->kind);
    }

    if constexpr (std::is_same_v<Op, StoreOp>) {
      // TODO(v8:12716) If one store has a full write barrier and the other has
      // no write barrier, consider combine them with a full write barrier.
      calculatable &= (op_->write_barrier == rhs.op_->write_barrier);
    }

    if (calculatable) {
      return offset_ - rhs.offset_;
    }
    return {};
  }

  bool IsValid() const { return op_ != nullptr; }

  const Operation* index() const { return index_; }
  int offset() const { return offset_; }
  const Op* op() const { return op_; }

 private:
  void SetInvalid() { op_ = nullptr; }

  const Op* op_;
  const Operation* base_ = nullptr;
  const Operation* index_ = nullptr;
  int offset_;
};

struct StoreInfoCompare {
  bool operator()(const StoreLoadInfo<StoreOp>& lhs,
                  const StoreLoadInfo<StoreOp>& rhs) const {
    if (lhs.index() != rhs.index()) {
      return lhs.index() < rhs.index();
    }
    return lhs.offset() < rhs.offset();
  }
};

using StoreInfoSet = ZoneSet<StoreLoadInfo<StoreOp>, StoreInfoCompare>;

// Return whether the stride of node_group equal to a specific value
template <class Op, class Info>
bool LoadStrideEqualTo(const Graph& graph, const NodeGroup& node_group,
                       int stride) {
  base::SmallVector<Info, 2> load_infos;
  for (OpIndex op_idx : node_group) {
    const Operation& op = graph.Get(op_idx);
    const Op& load_op = op.Cast<Op>();
    Info info(&graph, &load_op);
    if (!info.IsValid()) {
      return false;
    }
    load_infos.push_back(info);
  }
  return load_infos[1] - load_infos[0] == stride;
}

// Returns true if all of the nodes in node_group are identical.
// Splat opcode in WASM SIMD is used to create vector with identical lanes.
template <typename T>
bool IsSplat(const T& node_group) {
  DCHECK_EQ(node_group.size(), 2);
  return node_group[1] == node_group[0];
}

void PackNode::Print(Graph* graph) const {
  Operation& op = graph->Get(nodes_[0]);
  TRACE("%s(#%d, #%d)\n", GetSimdOpcodeName(op).c_str(), nodes_[0].id(),
        nodes_[1].id());
}

PackNode* SLPTree::GetPackNode(OpIndex node) {
  auto itr = node_to_packnode_.find(node);
  if (itr != node_to_packnode_.end()) {
    return itr->second;
  }
  return analyzer_->GetPackNode(node);
}

ZoneVector<PackNode*>* SLPTree::GetIntersectPackNodes(OpIndex node) {
  auto I = node_to_intersect_packnodes_.find(node);
  if (I != node_to_intersect_packnodes_.end()) {
    return &(I->second);
  }
  return nullptr;
}

template <typename FunctionType>
void ForEach(FunctionType callback,
             const ZoneUnorderedMap<OpIndex, PackNode*>& node_map) {
  absl::flat_hash_set<PackNode const*> visited;

  for (auto& entry : node_map) {
    PackNode const* pnode = entry.second;
    if (!pnode || visited.find(pnode) != visited.end()) {
      continue;
    }
    visited.insert(pnode);

    callback(pnode);
  }
}

template <typename FunctionType>
void ForEach(FunctionType callback,
             const ZoneUnorderedMap<OpIndex, ZoneVector<PackNode*>>& node_map) {
  absl::flat_hash_set<PackNode const*> visited;

  for (auto entry : node_map) {
    for (auto pnode : entry.second) {
      if (visited.find(pnode) != visited.end()) {
        continue;
      }
      visited.insert(pnode);
      callback(pnode);
    }
  }
}

void SLPTree::Print(const char* info) {
  TRACE("%s, %zu Packed node:\n", info, node_to_packnode_.size());
  if (!v8_flags.trace_wasm_revectorize) {
    return;
  }

  ForEach([this](PackNode const* pnode) { pnode->Print(&graph_); },
          node_to_packnode_);
  ForEach([this](PackNode const* pnode) { pnode->Print(&graph_); },
          node_to_intersect_packnodes_);
}

bool SLPTree::HasInputDependencies(const NodeGroup& node_group) {
  DCHECK_EQ(node_group.size(), 2);
  if (node_group[0] == node_group[1]) return false;
  OpIndex start, end;
  if (node_group[0] < node_group[1]) {
    start = node_group[0];
    end = node_group[1];
  } else {
    start = node_group[1];
    end = node_group[0];
  }
  // Do BFS from the end node and see if there is a path to the start node.
  ZoneQueue<OpIndex> to_visit(phase_zone_);
  to_visit.push(end);
  while (!to_visit.empty()) {
    OpIndex to_visit_node = to_visit.front();
    Operation& op = graph_.Get(to_visit_node);
    to_visit.pop();
    for (OpIndex input : op.inputs()) {
      if (input == start) {
        return true;
      } else if (input > start) {
        // We should ensure that there is no back edge.
        DCHECK_LT(input, to_visit_node);
        to_visit.push(input);
      }
    }
  }
  return false;
}

PackNode* SLPTree::NewPackNode(const NodeGroup& node_group) {
  TRACE("PackNode %s(#%d, #%d)\n",
        GetSimdOpcodeName(graph_.Get(node_group[0])).c_str(),
        node_group[0].id(), node_group[1].id());
  PackNode* pnode = phase_zone_->New<PackNode>(phase_zone_, node_group);
  for (OpIndex node : node_group) {
    node_to_packnode_[node] = pnode;
  }
  return pnode;
}

PackNode* SLPTree::NewForcePackNode(const NodeGroup& node_group,
                                    ForcePackNode::ForcePackType type,
                                    const Graph& graph) {
  // Currently we only support force packing two nodes.
  DCHECK_EQ(node_group.size(), 2);
  // We should guarantee that the one node in the NodeGroup does not rely on the
  // result of the other. Because it is costly to force pack such candidates.
  // For example, we have four nodes {A, B, C, D} which are connected by input
  // edges: A <-- B <-- C <-- D. If {B} and {D} are already packed into a
  // PackNode and we want to force pack {A} and {C}, we need to duplicate {B}
  // and the result will be {A, B, C}, {B, D}. This increase the cost of
  // ForcePack so currently we do not support it.
  if (HasInputDependencies(node_group)) {
    TRACE("ForcePackNode %s(#%d, #%d) failed due to input dependencies.\n",
          GetSimdOpcodeName(graph_.Get(node_group[0])).c_str(),
          node_group[0].id(), node_group[1].id());
    return nullptr;
  }

  TRACE("ForcePackNode %s(#%d, #%d)\n",
        GetSimdOpcodeName(graph_.Get(node_group[0])).c_str(),
        node_group[0].id(), node_group[1].id());
  ForcePackNode* pnode =
      phase_zone_->New<ForcePackNode>(phase_zone_, node_group, type);
  for (OpIndex node : node_group) {
    node_to_packnode_[node] = pnode;
  }

  return pnode;
}

BundlePackNode* SLPTree::NewBundlePackNode(const NodeGroup& node_group,
                                           OpIndex base, int8_t offset,
                                           uint8_t lane_size,
                                           bool is_sign_extract,
                                           bool is_sign_convert) {
  Operation& op = graph_.Get(node_group[0]);
  TRACE("PackNode %s(#%d:, #%d)\n", GetSimdOpcodeName(op).c_str(),
        node_group[0].id(), node_group[1].id());
  BundlePackNode* pnode = phase_zone_->New<BundlePackNode>(
      phase_zone_, node_group, base, offset, lane_size, is_sign_extract,
      is_sign_convert);
  for (OpIndex node : node_group) {
    node_to_packnode_[node] = pnode;
  }
  return pnode;
}

PackNode* SLPTree::NewIntersectPackNode(const NodeGroup& node_group) {
  // Similar as ForcePackNode, dependent inputs are not supported.
  if (HasInputDependencies(node_group)) {
    TRACE("IntersectPackNode %s(#%d, #%d) failed due to input dependencies.\n",
          GetSimdOpcodeName(graph_.Get(node_group[0])).c_str(),
          node_group[0].id(), node_group[1].id());
    return nullptr;
  }

  TRACE("IntersectPackNode %s(#%d, #%d)\n",
        GetSimdOpcodeName(graph_.Get(node_group[0])).c_str(),
        node_group[0].id(), node_group[1].id());
  PackNode* intersect_pnode = phase_zone_->New<PackNode>(
      phase_zone_, node_group, PackNode::kIntersectPackNode);

  for (int i = 0; i < static_cast<int>(node_group.size()); i++) {
    OpIndex op_idx = node_group[i];
    if (i > 0 && op_idx == node_group[0]) continue;
    auto it = node_to_intersect_packnodes_.find(op_idx);
    if (it == node_to_intersect_packnodes_.end()) {
      bool result;
      std::tie(it, result) = node_to_intersect_packnodes_.emplace(
          op_idx, ZoneVector<PackNode*>(phase_zone_));
      DCHECK(result);
    }
    it->second.push_back(intersect_pnode);
  }

  return intersect_pnode;
}

PackNode* SLPTree::NewCommutativePackNodeAndRecurs(const NodeGroup& node_group,
                                                   unsigned depth) {
  PackNode* pnode = NewPackNode(node_group);

  const Simd128BinopOp& op0 = graph_.Get(node_group[0]).Cast<Simd128BinopOp>();
  const Simd128BinopOp& op1 = graph_.Get(node_group[1]).Cast<Simd128BinopOp>();

  bool same_kind =
      (op0.left() == op1.left()) ||
      IsSameOpAndKind(graph_.Get(op0.left()), graph_.Get(op1.left()));
  bool need_swap = Simd128BinopOp::IsCommutative(op0.kind) && !same_kind;
  if (need_swap) {
    TRACE("Change the order of binop operands\n");
  }
  for (int i = 0; i < 2; ++i) {
    // Swap the left and right input if necessary
    unsigned node1_input_index = need_swap ? 1 - i : i;
    NodeGroup operands(graph_.Get(node_group[0]).input(i),
                       graph_.Get(node_group[1]).input(node1_input_index));

    PackNode* child = BuildTreeRec(operands, depth + 1);
    if (child) {
      pnode->SetOperand(i, child);
    } else {
      return nullptr;
    }
  }
  return pnode;
}

PackNode* SLPTree::NewPackNodeAndRecurs(const NodeGroup& node_group,
                                        int start_index, int count,
                                        unsigned depth) {
  PackNode* pnode = NewPackNode(node_group);
  for (int i = 0; i < count; ++i) {
    // Prepare the operand vector.
    int input_index = i + start_index;
    NodeGroup operands(graph_.Get(node_group[0]).input(input_index),
                       graph_.Get(node_group[1]).input(input_index));

    PackNode* child = BuildTreeRec(operands, depth + 1);
    if (child) {
      pnode->SetOperand(i, child);
    } else {
      return nullptr;
    }
  }
  return pnode;
}

ShufflePackNode* SLPTree::NewShufflePackNode(
    const NodeGroup& node_group, ShufflePackNode::SpecificInfo::Kind kind) {
  Operation& op = graph_.Get(node_group[0]);
  TRACE("PackNode %s(#%d:, #%d)\n", GetSimdOpcodeName(op).c_str(),
        node_group[0].id(), node_group[1].id());
  ShufflePackNode* pnode =
      phase_zone_->New<ShufflePackNode>(phase_zone_, node_group, kind);
  for (OpIndex node : node_group) {
    node_to_packnode_[node] = pnode;
  }
  return pnode;
}

ShufflePackNode* SLPTree::Try256ShuffleMatchLoad8x8U(
    const NodeGroup& node_group, const uint8_t* shuffle0,
    const uint8_t* shuffle1) {
  uint8_t shuffle_copy0[kSimd128Size];
  uint8_t shuffle_copy1[kSimd128Size];

  V<Simd128> op_idx0 = node_group[0];
  V<Simd128> op_idx1 = node_group[1];
  const Simd128ShuffleOp& op0 = graph_.Get(op_idx0).Cast<Simd128ShuffleOp>();
  const Simd128ShuffleOp& op1 = graph_.Get(op_idx1).Cast<Simd128ShuffleOp>();

  if (op0.left() == op0.right() || op1.left() == op1.right()) {
    // Here shuffle couldn't be swizzle
    return nullptr;
  }

  CopyChars(shuffle_copy0, shuffle0, kSimd128Size);
  CopyChars(shuffle_copy1, shuffle1, kSimd128Size);

  bool need_swap, is_swizzle;

#define CANONICALIZE_SHUFFLE(n)                                                \
  wasm::SimdShuffle::CanonicalizeShuffle(false, shuffle_copy##n, &need_swap,   \
                                         &is_swizzle);                         \
  if (is_swizzle) {                                                            \
    /* Here shuffle couldn't be swizzle*/                                      \
    return nullptr;                                                            \
  }                                                                            \
  V<Simd128> shuffle##n##_left_idx = need_swap ? op##n.right() : op##n.left(); \
  V<Simd128> shuffle##n##_right_idx = need_swap ? op##n.left() : op##n.right();

  CANONICALIZE_SHUFFLE(0);
  CANONICALIZE_SHUFFLE(1);

#undef CANONICALIZE_SHUFFLE
  if (shuffle0_left_idx != shuffle1_left_idx) {
    // Not the same left
    return nullptr;
  }

  const Simd128LoadTransformOp* load_transform =
      graph_.Get(shuffle0_left_idx).TryCast<Simd128LoadTransformOp>();

  if (!load_transform) {
    // shuffle left is not Simd128LoadTransformOp
    return nullptr;
  }

  Simd128ConstantOp* shuffle0_const =
      graph_.Get(shuffle0_right_idx).TryCast<Simd128ConstantOp>();
  Simd128ConstantOp* shuffle1_const =
      graph_.Get(shuffle1_right_idx).TryCast<Simd128ConstantOp>();

  if (!shuffle0_const || !shuffle1_const || !shuffle0_const->IsZero() ||
      !shuffle1_const->IsZero()) {
    // Shuffle right is not zero
    return nullptr;
  }

  if (load_transform->transform_kind ==
      Simd128LoadTransformOp::TransformKind::k64Zero) {
    /*
      should look like this:
      shuffle0 = 0,x,x,x,  1,x,x,x  2,x,x,x  3,x,x,x
      shuffle1 = 4,x,x,x,  5,x,x,x  6,x,x,x  7,x,x,x
      x >= 16
    */

    for (int i = 0; i < kSimd128Size / 4; ++i) {
      if (shuffle_copy0[i * 4] != i || shuffle_copy1[i * 4] != i + 4) {
        // not match
        return nullptr;
      }

      if (shuffle_copy0[i * 4 + 1] < kSimd128Size ||
          shuffle_copy0[i * 4 + 2] < kSimd128Size ||
          shuffle_copy0[i * 4 + 3] < kSimd128Size ||
          shuffle_copy1[i * 4 + 1] < kSimd128Size ||
          shuffle_copy1[i * 4 + 2] < kSimd128Size ||
          shuffle_copy1[i * 4 + 3] < kSimd128Size) {
        // not match
        return nullptr;
      }
    }
    TRACE("match load extend 8x8->32x8\n");
    return NewShufflePackNode(
        node_group, ShufflePackNode::SpecificInfo::Kind::kS256Load8x8U);
  }
  return nullptr;
}

#ifdef V8_TARGET_ARCH_X64
ShufflePackNode* SLPTree::X64TryMatch256Shuffle(const NodeGroup& node_group,
                                                const uint8_t* shuffle0,
                                                const uint8_t* shuffle1) {
  DCHECK_EQ(node_group.size(), 2);
  OpIndex op_idx0 = node_group[0];
  OpIndex op_idx1 = node_group[1];
  const Simd128ShuffleOp& op0 = graph_.Get(op_idx0).Cast<Simd128ShuffleOp>();
  const Simd128ShuffleOp& op1 = graph_.Get(op_idx1).Cast<Simd128ShuffleOp>();

  uint8_t shuffle8x32[32];

  if (op0.left() == op0.right() && op1.left() == op1.right()) {
    // shuffles are swizzles
    for (int i = 0; i < 16; ++i) {
      shuffle8x32[i] = shuffle0[i] % 16;
      shuffle8x32[i + 16] = 16 + shuffle1[i] % 16;
    }

    if (uint8_t shuffle32x8[8];
        wasm::SimdShuffle::TryMatch32x8Shuffle(shuffle8x32, shuffle32x8)) {
      uint8_t control;
      if (wasm::SimdShuffle::TryMatchVpshufd(shuffle32x8, &control)) {
        ShufflePackNode* pnode = NewShufflePackNode(
            node_group, ShufflePackNode::SpecificInfo::Kind::kShufd);
        pnode->info().set_shufd_control(control);
        return pnode;
      }
    }
  } else if (op0.left() != op0.right() && op1.left() != op1.right()) {
    // shuffles are not swizzles
    for (int i = 0; i < 16; ++i) {
      if (shuffle0[i] < 16) {
        shuffle8x32[i] = shuffle0[i];
      } else {
        shuffle8x32[i] = 16 + shuffle0[i];
      }

      if (shuffle1[i] < 16) {
        shuffle8x32[i + 16] = 16 + shuffle1[i];
      } else {
        shuffle8x32[i + 16] = 32 + shuffle1[i];
      }
    }

    if (const wasm::ShuffleEntry<kSimd256Size>* arch_shuffle;
        wasm::SimdShuffle::TryMatchArchShuffle(shuffle8x32, false,
                                               &arch_shuffle)) {
      ShufflePackNode::SpecificInfo::Kind kind;
      switch (arch_shuffle->opcode) {
        case kX64S32x8UnpackHigh:
          kind = ShufflePackNode::SpecificInfo::Kind::kS32x8UnpackHigh;
          break;
        case kX64S32x8UnpackLow:
          kind = ShufflePackNode::SpecificInfo::Kind::kS32x8UnpackLow;
          break;
        default:
          UNREACHABLE();
      }
      ShufflePackNode* pnode = NewShufflePackNode(node_group, kind);
      return pnode;
    } else if (uint8_t shuffle32x8[8]; wasm::SimdShuffle::TryMatch32x8Shuffle(
                   shuffle8x32, shuffle32x8)) {
      uint8_t control;
      if (wasm::SimdShuffle::TryMatchShufps256(shuffle32x8, &control)) {
        ShufflePackNode* pnode = NewShufflePackNode(
            node_group, ShufflePackNode::SpecificInfo::Kind::kShufps);
        pnode->info().set_shufps_control(control);
        return pnode;
      }
    }
  }

  return nullptr;
}
#endif  // V8_TARGET_ARCH_X64

// Try to match i8x16/i16x8 to f32x4 conversion pattern.
// The following wasm snippet is an example for load i8x16,
// extend to i32x4 and convert to f32x4
//  (f32x4.replace_lane 3
//     (f32x4.replace_lane 2
//       (f32x4.replace_lane 1
//         (f32x4.splat
//           (f32.convert_i32_u
//             (i8x16.extract_lane_u 0
//               (local.tee 7
//                 (v128.load align=1
//                   (local.get 0))))))
//         (f32.convert_i32_u
//           (i8x16.extract_lane_u 1
//             (local.get 7))))
//       (f32.convert_i32_u
//         (i8x16.extract_lane_u 2
//           (local.get 7))))
//     (f32.convert_i32_u
//       (i8x16.extract_lane_u 3
//         (local.get 7))))
std::optional<SLPTree::ExtendIntToF32x4Info>
SLPTree::TryGetExtendIntToF32x4Info(OpIndex index) {
  OpIndex current = index;
  LaneExtendInfo lane_extend_info[4];

  // Get information for lane 1 to lane 3
  for (int lane_index = 3; lane_index > 0; lane_index--) {
    const Simd128ReplaceLaneOp* replace_lane =
        graph_.Get(current)
            .TryCast<turboshaft::Opmask::kSimd128ReplaceLaneF32x4>();
    if (!replace_lane) {
      TRACE("Mismatch in replace lane\n");
      return {};
    }
    const ChangeOp* change =
        graph_.Get(replace_lane->new_lane()).TryCast<ChangeOp>();
    if (!change) {
      TRACE("Mismatch in type convert\n");
      return {};
    }
    const Simd128ExtractLaneOp* extract_lane =
        graph_.Get(change->input()).TryCast<Simd128ExtractLaneOp>();
    if (!extract_lane) {
      TRACE("Mismatch in extract lane\n");
      return {};
    }
    lane_extend_info[lane_index].replace_lane_index = replace_lane->lane;
    lane_extend_info[lane_index].change_kind = change->kind;
    lane_extend_info[lane_index].extract_from = extract_lane->input();
    lane_extend_info[lane_index].extract_kind = extract_lane->kind;
    lane_extend_info[lane_index].extract_lane_index = extract_lane->lane;

    current = replace_lane->into();
  }

  // Get information for lane 0(splat)
  const Simd128SplatOp* splat = graph_.Get(current).TryCast<Simd128SplatOp>();
  if (!splat) {
    TRACE("Mismatch in splat\n");
    return {};
  }
  const ChangeOp* change = graph_.Get(splat->input()).TryCast<ChangeOp>();
  if (!change) {
    TRACE("Mismatch in splat type convert\n");
    return {};
  }
  const Simd128ExtractLaneOp* extract_lane =
      graph_.Get(change->input()).TryCast<Simd128ExtractLaneOp>();
  if (!extract_lane) {
    TRACE("Mismatch in splat extract lane\n");
    return {};
  }
  lane_extend_info[0].replace_lane_index = 0;
  lane_extend_info[0].change_kind = change->kind;
  lane_extend_info[0].extract_from = extract_lane->input();
  lane_extend_info[0].extract_kind = extract_lane->kind;
  lane_extend_info[0].extract_lane_index = extract_lane->lane;

  // Pattern matching for f32x4.convert_i32x4(i32x4.extract_lane)
  for (int i = 0; i < 4; i++) {
    if (lane_extend_info[i].replace_lane_index != i) {
      return {};
    }
    if (lane_extend_info[i].change_kind != lane_extend_info[0].change_kind ||
        (lane_extend_info[i].change_kind != ChangeOp::Kind::kSignedToFloat &&
         lane_extend_info[i].change_kind != ChangeOp::Kind::kUnsignedToFloat)) {
      return {};
    }
    if (lane_extend_info[i].extract_from != lane_extend_info[0].extract_from) {
      return {};
    }
    if (lane_extend_info[i].extract_kind != lane_extend_info[0].extract_kind ||
        (lane_extend_info[i].extract_kind !=
             Simd128ExtractLaneOp::Kind::kI8x16S &&
         lane_extend_info[i].extract_kind !=
             Simd128ExtractLaneOp::Kind::kI8x16U &&
         lane_extend_info[i].extract_kind !=
             Simd128ExtractLaneOp::Kind::kI16x8S &&
         lane_extend_info[i].extract_kind !=
             Simd128ExtractLaneOp::Kind::kI16x8U)) {
      return {};
    }
    if (lane_extend_info[i].extract_lane_index !=
        lane_extend_info[0].extract_lane_index + i) {
      return {};
    }
  }

  ExtendIntToF32x4Info info;
  info.extend_from = lane_extend_info[0].extract_from;
  info.start_lane = lane_extend_info[0].extract_lane_index;
  if (lane_extend_info[0].extract_kind == Simd128ExtractLaneOp::Kind::kI8x16S ||
      lane_extend_info[0].extract_kind == Simd128ExtractLaneOp::Kind::kI8x16U) {
    info.lane_size = 1;
  } else {
    info.lane_size = 2;
  }
  info.is_sign_extract =
      lane_extend_info[0].extract_kind == Simd128ExtractLaneOp::Kind::kI8x16S ||
      lane_extend_info[0].extract_kind == Simd128ExtractLaneOp::Kind::kI16x8S;
  info.is_sign_convert =
      lane_extend_info[0].change_kind == ChangeOp::Kind::kSignedToFloat;

  return info;
}

bool SLPTree::TryMatchExtendIntToF32x4(const NodeGroup& node_group,
                                       ExtendIntToF32x4Info* info) {
  OpIndex node0 = node_group[0];
  OpIndex node1 = node_group[1];
  std::optional<ExtendIntToF32x4Info> info0 = TryGetExtendIntToF32x4Info(node0);
  std::optional<ExtendIntToF32x4Info> info1 = TryGetExtendIntToF32x4Info(node1);
  if (!info0.has_value() || !info1.has_value()) {
    return false;
  }

  if (info0.value().extend_from != info1.value().extend_from ||
      info0.value().is_sign_extract != info1.value().is_sign_extract ||
      info0.value().lane_size != info1.value().lane_size ||
      info0.value().is_sign_convert != info1.value().is_sign_convert) {
    return false;
  }

  uint32_t min_lane_index =
      std::min(info0.value().start_lane, info1.value().start_lane);
  if (std::abs(info0.value().start_lane - info1.value().start_lane) != 4) {
    return false;
  }
  if (info0.value().lane_size == 1) {
    if (min_lane_index != 0 && min_lane_index != 8) {
      return false;
    }
  } else {
    DCHECK_EQ(info0.value().lane_size, 2);
    if (min_lane_index != 0) {
      return false;
    }
  }

  *info = info0.value();
  info->start_lane = min_lane_index;
  return true;
}

void SLPTree::DeleteTree() {
  node_to_packnode_.clear();
  node_to_intersect_packnodes_.clear();
}

bool CannotSwapProtectedLoads(OpEffects first, OpEffects second) {
  EffectDimensions produces = first.produces;
  // The control flow effects produces by Loads are due to trap handler. We can
  // ignore this kind of effect when swapping two Loads that both have trap
  // handler.
  produces.control_flow = false;
  return produces.bits() & (second.consumes.bits());
}

bool IsProtectedLoad(Operation& op) {
  if (op.opcode == Opcode::kLoad) {
    return op.Cast<LoadOp>().kind.with_trap_handler;
  } else if (op.opcode == Opcode::kSimd128LoadTransform) {
    return op.Cast<Simd128LoadTransformOp>().load_kind.with_trap_handler;
  }
  return false;
}

bool SLPTree::IsSideEffectFree(OpIndex first, OpIndex second) {
  DCHECK_LE(first.offset(), second.offset());
  if (first == second) return true;
  OpEffects effects = graph().Get(second).Effects();
  OpIndex prev_node = graph().PreviousIndex(second);
  while (prev_node != first) {
    OpEffects prev_effects = graph().Get(prev_node).Effects();
    if ((IsProtectedLoad(graph().Get(second)) &&
         IsProtectedLoad(graph().Get(prev_node)))
            ? CannotSwapProtectedLoads(prev_effects, effects)
            : CannotSwapOperations(prev_effects, effects)) {
      TRACE("break side effect %d, %d\n", prev_node.id(), second.id());
      return false;
    }
    prev_node = graph().PreviousIndex(prev_node);
  }
  return true;
}

bool IsSignExtensionOp(Operation& op) {
  if (const Simd128UnaryOp* unop = op.TryCast<Simd128UnaryOp>()) {
    return unop->kind >= Simd128UnaryOp::Kind::kFirstSignExtensionOp &&
           unop->kind <= Simd128UnaryOp::Kind::kLastSignExtensionOp;
  } else if (const Simd128BinopOp* binop = op.TryCast<Simd128BinopOp>()) {
    return binop->kind >= Simd128BinopOp::Kind::kFirstSignExtensionOp &&
           binop->kind <= Simd128BinopOp::Kind::kLastSignExtensionOp;
  }
  return false;
}

bool SLPTree::CanBePacked(const NodeGroup& node_group) {
  OpIndex node0 = node_group[0];
  OpIndex node1 = node_group[1];
  Operation& op0 = graph_.Get(node0);
  Operation& op1 = graph_.Get(node1);

  if (op0.opcode != op1.opcode) {
    TRACE("Different opcode\n");
    return false;
  }

  if (graph().BlockIndexOf(node0) != graph().BlockIndexOf(node1)) {
    TRACE("Can't pack operations of different basic block\n");
    return false;
  }

  auto is_sign_ext = IsSignExtensionOp(op0) && IsSignExtensionOp(op1);

  if (!is_sign_ext && !IsSameOpAndKind(op0, op1)) {
    TRACE("(%s, %s) have different op\n", GetSimdOpcodeName(op0).c_str(),
          GetSimdOpcodeName(op1).c_str());
    return false;
  }

  if (node0.offset() <= node1.offset() ? !IsSideEffectFree(node0, node1)
                                       : !IsSideEffectFree(node1, node0)) {
    TRACE("Break side effect\n");
    return false;
  }
  return true;
}

bool SLPTree::IsEqual(const OpIndex node0, const OpIndex node1) {
  if (node0 == node1) return true;
  if (const ConstantOp* const0 = graph_.Get(node0).TryCast<ConstantOp>()) {
    if (const ConstantOp* const1 = graph_.Get(node1).TryCast<ConstantOp>()) {
      return *const0 == *const1;
    }
  }
  return false;
}

PackNode* SLPTree::BuildTree(const NodeGroup& roots) {
  root_ = BuildTreeRec(roots, 0);
  return root_;
}

bool IsLoadExtend(const Simd128LoadTransformOp& op) {
  switch (op.transform_kind) {
    case Simd128LoadTransformOp::TransformKind::k8x8S:
    case Simd128LoadTransformOp::TransformKind::k8x8U:
    case Simd128LoadTransformOp::TransformKind::k16x4S:
    case Simd128LoadTransformOp::TransformKind::k16x4U:
    case Simd128LoadTransformOp::TransformKind::k32x2S:
    case Simd128LoadTransformOp::TransformKind::k32x2U:
      return true;
    default:
      return false;
  }
}

bool IsLoadSplat(const Simd128LoadTransformOp& op) {
  switch (op.transform_kind) {
    case Simd128LoadTransformOp::TransformKind::k8Splat:
    case Simd128LoadTransformOp::TransformKind::k16Splat:
    case Simd128LoadTransformOp::TransformKind::k32Splat:
    case Simd128LoadTransformOp::TransformKind::k64Splat:
      return true;
    default:
      return false;
  }
}

PackNode* SLPTree::BuildTreeRec(const NodeGroup& node_group,
                                unsigned recursion_depth) {
  DCHECK_EQ(node_group.size(), 2);

  OpIndex node0 = node_group[0];
  OpIndex node1 = node_group[1];
  Operation& op0 = graph_.Get(node0);
  Operation& op1 = graph_.Get(node1);

  if (recursion_depth == RecursionMaxDepth) {
    TRACE("Failed due to max recursion depth!\n");
    return nullptr;
  }

  if (!CanBePacked(node_group)) {
    return nullptr;
  }

  // Check if this is a duplicate of another entry.
  bool is_intersected = false;
  // For revisited node_group, we only need to match from node0.
  if (PackNode* pnode = GetPackNode(node0)) {
    const Operation& op = graph_.Get(node0);
    if (pnode->IsSame(node_group)) {
      TRACE("Perfect diamond merge at #%d,%s\n", node0.id(),
            GetSimdOpcodeName(op).c_str());
      return pnode;
    }

    // TODO(yolanda): Support other intersect PackNode e.g. overlapped loads.
    if (!pnode->IsForcePackNode() || recursion_depth < 1) {
      TRACE("Unsupported partial overlap at #%d,%s!\n", node0.id(),
            GetSimdOpcodeName(op).c_str());
      return nullptr;
    }

    // Match intersect packnodes from current tree.
    if (auto intersect_packnodes = GetIntersectPackNodes(node0)) {
      for (auto intersect_pnode : *intersect_packnodes) {
        if (intersect_pnode->IsSame(node_group)) {
          TRACE("Perfect diamond merge at intersect pack node #%d,%s, #%d\n",
                node0.id(), GetSimdOpcodeName(op).c_str(), node1.id());
          return intersect_pnode;
        }
      }
    }

    // Match intersect packnodes from analyzer
    if (auto intersect_packnodes = analyzer_->GetIntersectPackNodes(node0)) {
      for (auto intersect_pnode : *intersect_packnodes) {
        if (intersect_pnode->IsSame(node_group)) {
          TRACE("Perfect diamond merge at intersec
```