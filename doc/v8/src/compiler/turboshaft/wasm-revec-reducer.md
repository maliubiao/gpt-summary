Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript example.

1. **Understand the Goal:** The core request is to understand the functionality of `wasm-revec-reducer.cc` and illustrate its relationship with JavaScript using an example. The file name strongly suggests it's about "revectorization" in the context of WebAssembly.

2. **Initial Skim and Keyword Identification:**  A quick read reveals key terms: `compiler`, `turboshaft`, `wasm`, `revectorize`, `SIMD`, `PackNode`, `SLPTree`, `StoreOp`, `LoadOp`, `shuffle`. These immediately point to compiler optimizations targeting SIMD (Single Instruction, Multiple Data) operations in WebAssembly.

3. **Core Functionality Hypothesis:** Based on the keywords, the primary goal is likely to identify opportunities to combine multiple scalar WebAssembly operations into a single, wider SIMD operation. This improves performance by processing more data in parallel.

4. **Detailed Examination of Key Classes and Functions:**

   * **`IsSameOpAndKind`:** This function checks if two operations have the same opcode and a specific "kind" (relevant for parameterized SIMD operations). This is fundamental for determining if two operations are candidates for combining.

   * **`GetSimdOpcodeName`:**  A utility for printing SIMD opcode names, useful for debugging/tracing.

   * **`StoreLoadInfo`:** This is crucial. It encapsulates information about memory access operations (loads and stores), including the base address, offset, and index. The logic for handling `Simd128LoadTransformOp` (which might involve an address calculation) is important. The `-` operator overload calculates the relative offset between two memory operations, which is a key factor in determining if they can be vectorized.

   * **`LoadStrideEqualTo`:** Checks if a group of load operations have a consistent stride in memory access. This is a classic pattern for vectorization.

   * **`IsSplat`:** Detects if a group of nodes represents the same value, which can be optimized into a "splat" SIMD operation (replicating a single value across the vector).

   * **`PackNode`, `SLPTree`:** These are the central data structures for representing and managing the potential vectorization opportunities. `PackNode` represents a group of operations that *can* be combined, and `SLPTree` (Superword Level Parallelism Tree) seems to be the algorithm or framework for finding these groups. The methods within `SLPTree` (like `NewPackNode`, `BuildTreeRec`, `CanBePacked`) are the core of the vectorization process. The handling of "intersecting" pack nodes is interesting – it suggests handling cases where potential vectorization opportunities overlap.

   * **`TryMatchExtendIntToF32x4`:** This function specifically looks for a common pattern where integer values are extracted from a SIMD vector, converted to floats, and then combined into a float SIMD vector. This is a good example of pattern-based optimization.

   * **`CanBePacked`:**  This function determines if two operations are actually safe to combine, considering opcode, side effects, and basic block placement.

   * **`BuildTreeRec`:** The recursive function that drives the `SLPTree` construction, exploring potential combinations of operations.

   * **`WasmRevecAnalyzer`:** The main class that orchestrates the process. It identifies "seeds" (potential starting points for vectorization), builds `SLPTree`s, and decides whether to perform the vectorization based on a cost/benefit analysis.

5. **Identifying the Connection to JavaScript:** The key connection is *WebAssembly*. JavaScript engines like V8 compile WebAssembly code. This C++ code is part of V8's Turboshaft compiler, which optimizes WebAssembly. Therefore, the optimizations performed by this code directly impact the performance of WebAssembly code running in a JavaScript environment.

6. **Crafting the JavaScript Example:**  The goal of the example is to demonstrate the kind of WebAssembly code that this C++ code aims to optimize. It should involve:
   * **SIMD operations:** Specifically `i32x4`.
   * **Loads from memory:**  Demonstrating the potential for combining multiple loads.
   * **Arithmetic operations:** Showing how element-wise operations can be vectorized.
   * **Sequential access pattern:**  Making the relative offsets between loads clear.

7. **Refining the Explanation:**  After understanding the code and creating the example, the explanation should clearly articulate:
   * The purpose of the code (SIMD vectorization).
   * The key techniques used (identifying patterns, calculating strides, building the SLP tree).
   * The benefits of this optimization (improved performance).
   * The direct link to JavaScript (optimizing WebAssembly executed by JavaScript engines).

8. **Self-Correction/Refinement:**  During the process, I might have initially focused too much on individual functions. Realizing the importance of the overall workflow and the role of `SLPTree` and `WasmRevecAnalyzer` is crucial. Also, ensuring the JavaScript example is simple and directly illustrates the core concept is important. Initially, I might have considered more complex SIMD operations, but simpler loads and additions are easier to understand in the context of the explanation. Making sure the JavaScript example aligns with the C++ code's focus (like the `StoreLoadInfo` and stride calculations) is key.
这个C++源代码文件 `wasm-revec-reducer.cc` 的功能是 **在 V8 引擎的 Turboshaft 编译器中，针对 WebAssembly 代码进行 SIMD (Single Instruction, Multiple Data) 的重构优化 (Revectorization)**。

更具体地说，它的目标是：

1. **识别可以被合并成更宽 SIMD 操作的多个 WebAssembly 操作。** 例如，多个独立的 `i32.load` 操作如果访问连续的内存地址，就可以被合并成一个 `i32x4.load` 操作。
2. **构建一个 SLP (Superword Level Parallelism) 树来表示这些可以合并的操作。** SLP 是一种用于自动向量化的技术。
3. **决定是否值得进行重构优化。** 这涉及到成本效益分析，例如，合并操作的收益是否大于引入新的 SIMD 操作的开销。

**与 JavaScript 的关系：**

这个 C++ 文件是 V8 引擎的一部分，V8 引擎是执行 JavaScript 代码的核心组件。当 JavaScript 代码中包含 WebAssembly 模块时，V8 会编译和执行这些 WebAssembly 代码。`wasm-revec-reducer.cc` 的工作直接影响到 WebAssembly 代码在 V8 中的执行效率。通过将多个标量操作转换为更高效的 SIMD 操作，它可以显著提升 WebAssembly 代码的性能。

**JavaScript 举例说明：**

虽然 `wasm-revec-reducer.cc` 是 C++ 代码，但它优化的是 WebAssembly 代码。我们可以用一个简单的 JavaScript 例子来展示一个可能被 `wasm-revec-reducer.cc` 优化的 WebAssembly 代码场景：

```javascript
// WebAssembly 文本格式 (.wat)

(module
  (memory (export "memory") 1)
  (func (export "add_four") (param $ptr i32) (result i32 i32 i32 i32)
    local.get $ptr
    i32.load ;; 加载地址 ptr 的 i32 值
    local.get $ptr
    i32.const 4
    i32.add
    i32.load ;; 加载地址 ptr + 4 的 i32 值
    local.get $ptr
    i32.const 8
    i32.add
    i32.load ;; 加载地址 ptr + 8 的 i32 值
    local.get $ptr
    i32.const 12
    i32.add
    i32.load ;; 加载地址 ptr + 12 的 i32 值
    i32.add
    i32.add
    i32.add
  )
)
```

在这个 WebAssembly 代码片段中，`add_four` 函数从内存中连续加载四个 32 位整数，并将它们相加。  `wasm-revec-reducer.cc` 的目标就是识别这种连续加载的模式，并将其转换为更高效的 SIMD 加载和加法操作，例如：

1. **识别连续加载：** `i32.load` 指令加载了地址 `ptr`, `ptr + 4`, `ptr + 8`, `ptr + 12` 的值。这些地址是连续的。
2. **合并为 SIMD 加载：** `wasm-revec-reducer.cc` 可以将这四个 `i32.load` 操作合并为一个 `i32x4.load` 操作，一次性加载四个 32 位整数到一个 128 位 SIMD 寄存器中。
3. **合并为 SIMD 加法：** 如果后续还有对这四个加载的值进行元素级操作（例如，与另一个 `i32x4` 向量相加），`wasm-revec-reducer.cc` 也可以将这些标量加法操作合并为 SIMD 加法操作。

**在 JavaScript 中使用这个 WebAssembly 模块：**

```javascript
async function runWasm() {
  const response = await fetch('your_wasm_module.wasm'); // 假设你有一个编译好的 wasm 文件
  const bytes = await response.arrayBuffer();
  const instance = await WebAssembly.instantiate(bytes, {});
  const memory = new Int32Array(instance.instance.exports.memory.buffer);
  const ptr = 0; // 假设从内存地址 0 开始加载
  memory[0] = 10;
  memory[1] = 20;
  memory[2] = 30;
  memory[3] = 40;

  const result = instance.instance.exports.add_four(ptr);
  console.log(result); // 输出 100 (10 + 20 + 30 + 40)
}

runWasm();
```

当这段 JavaScript 代码执行时，V8 引擎会加载并编译 WebAssembly 模块。`wasm-revec-reducer.cc` 在编译阶段发挥作用，尝试优化 `add_four` 函数中的内存访问和加法操作，使其利用 CPU 的 SIMD 指令，从而提高执行效率。

**总结:**

`wasm-revec-reducer.cc` 是 V8 引擎中负责 WebAssembly 代码 SIMD 重构优化的关键组件。它通过识别可以并行执行的标量操作，并将其转换为更高效的 SIMD 指令，从而提升 WebAssembly 代码在 JavaScript 环境中的性能。 上述 JavaScript 例子展示了一个 WebAssembly 代码场景，其中的连续内存加载操作可能会被 `wasm-revec-reducer.cc` 优化。

### 提示词
```
这是目录为v8/src/compiler/turboshaft/wasm-revec-reducer.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
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
          TRACE("Perfect diamond merge at intersect pack node #%d,%s, #%d\n",
                node0.id(), GetSimdOpcodeName(op).c_str(), node1.id());
          return intersect_pnode;
        }
      }
    }

    is_intersected = true;
    TRACE("Partial overlap at #%d,%s!\n", node0.id(),
          GetSimdOpcodeName(op).c_str());
  }

  // Catch overlapped PackNode on the other nodes.
  if (!is_intersected) {
    for (int i = 1; i < static_cast<int>(node_group.size()); i++) {
      const OpIndex op_idx = node_group[i];
      const Operation& op = graph_.Get(op_idx);
      if (auto pnode = GetPackNode(op_idx)) {
        if (!pnode->IsForcePackNode()) {
          TRACE("Unsupported partial overlap at #%d,%s!\n", op_idx.id(),
                GetSimdOpcodeName(op).c_str());
          return nullptr;
        }
      } else if (!GetIntersectPackNodes(op_idx) &&
                 !analyzer_->GetIntersectPackNodes(op_idx)) {
        continue;
      }

      is_intersected = true;
      TRACE("Partial overlap at #%d,%s!\n", op_idx.id(),
            GetSimdOpcodeName(op).c_str());
      break;
    }
  }

  if (is_intersected) {
    TRACE("Create IntersectPackNode due to partial overlap!\n");
    PackNode* pnode = NewIntersectPackNode(node_group);
    return pnode;
  }

  int value_in_count = op0.input_count;

  switch (op0.opcode) {
    case Opcode::kSimd128Constant: {
      PackNode* p = NewPackNode(node_group);
      return p;
    }

    case Opcode::kSimd128LoadTransform: {
      const Simd128LoadTransformOp& transform_op0 =
          op0.Cast<Simd128LoadTransformOp>();
      const Simd128LoadTransformOp& transform_op1 =
          op1.Cast<Simd128LoadTransformOp>();
      StoreLoadInfo<Simd128LoadTransformOp> info0(&graph_, &transform_op0);
      StoreLoadInfo<Simd128LoadTransformOp> info1(&graph_, &transform_op1);
      auto stride = info1 - info0;
      if (IsLoadSplat(transform_op0)) {
        TRACE("Simd128LoadTransform: LoadSplat\n");
        if (IsSplat(node_group) ||
            (stride.has_value() && stride.value() == 0)) {
          return NewPackNode(node_group);
        }
        return NewForcePackNode(node_group, ForcePackNode::kGeneral, graph_);
      } else if (IsLoadExtend(transform_op0)) {
        TRACE("Simd128LoadTransform: LoadExtend\n");
        if (stride.has_value()) {
          const int value = stride.value();
          if (value == kSimd128Size / 2) {
            return NewPackNode(node_group);
          } else if (value == 0) {
            return NewForcePackNode(node_group, ForcePackNode::kSplat, graph_);
          }
        }
        return NewForcePackNode(node_group, ForcePackNode::kGeneral, graph_);
      } else {
        TRACE("Load Transfrom k64Zero/k32Zero!\n");
        DCHECK(transform_op0.transform_kind ==
                   Simd128LoadTransformOp::TransformKind::k32Zero ||
               transform_op0.transform_kind ==
                   Simd128LoadTransformOp::TransformKind::k64Zero);
        if (stride.has_value() && stride.value() == 0) {
          return NewForcePackNode(node_group, ForcePackNode::kSplat, graph_);
        }
        return NewForcePackNode(node_group, ForcePackNode::kGeneral, graph_);
      }
    }

    case Opcode::kLoad: {
      TRACE("Load leaf node\n");
      const LoadOp& load0 = op0.Cast<LoadOp>();
      const LoadOp& load1 = op1.Cast<LoadOp>();
      if (load0.loaded_rep != MemoryRepresentation::Simd128() ||
          load1.loaded_rep != MemoryRepresentation::Simd128()) {
        TRACE("Failed due to non-simd load representation!\n");
        return nullptr;
      }
      StoreLoadInfo<LoadOp> info0(&graph_, &load0);
      StoreLoadInfo<LoadOp> info1(&graph_, &load1);
      auto stride = info1 - info0;
      if (stride.has_value()) {
        if (const int value = stride.value(); value == kSimd128Size) {
          // TODO(jiepan) Sort load
          return NewPackNode(node_group);
        } else if (value == 0) {
          return NewForcePackNode(node_group, ForcePackNode::kSplat, graph_);
        }
      }
      return NewForcePackNode(node_group, ForcePackNode::kGeneral, graph_);
    }
    case Opcode::kStore: {
      TRACE("Added a vector of stores.\n");
      // input: base, value, [index]
      PackNode* pnode = NewPackNodeAndRecurs(node_group, 1, 1, recursion_depth);
      return pnode;
    }
    case Opcode::kPhi: {
      TRACE("Added a vector of phi nodes.\n");
      const PhiOp& phi = graph().Get(node0).Cast<PhiOp>();
      if (phi.rep != RegisterRepresentation::Simd128() ||
          op0.input_count != op1.input_count) {
        TRACE("Failed due to invalid phi\n");
        return nullptr;
      }
      PackNode* pnode =
          NewPackNodeAndRecurs(node_group, 0, value_in_count, recursion_depth);
      return pnode;
    }
    case Opcode::kSimd128Unary: {
#define UNARY_CASE(op_128, not_used) case Simd128UnaryOp::Kind::k##op_128:
#define UNARY_SIGN_EXTENSION_CASE(op_low, not_used1, op_high)                 \
  case Simd128UnaryOp::Kind::k##op_low: {                                     \
    if (const Simd128UnaryOp* unop1 =                                         \
            op1.TryCast<Opmask::kSimd128##op_high>();                         \
        unop1 && op0.Cast<Simd128UnaryOp>().input() == unop1->input()) {      \
      return NewPackNode(node_group);                                         \
    }                                                                         \
    [[fallthrough]];                                                          \
  }                                                                           \
  case Simd128UnaryOp::Kind::k##op_high: {                                    \
    if (op1.Cast<Simd128UnaryOp>().kind == op0.Cast<Simd128UnaryOp>().kind) { \
      auto force_pack_type =                                                  \
          node0 == node1 ? ForcePackNode::kSplat : ForcePackNode::kGeneral;   \
      return NewForcePackNode(node_group, force_pack_type, graph_);           \
    } else {                                                                  \
      return nullptr;                                                         \
    }                                                                         \
  }
      switch (op0.Cast<Simd128UnaryOp>().kind) {
        SIMD256_UNARY_SIGN_EXTENSION_OP(UNARY_SIGN_EXTENSION_CASE)
        SIMD256_UNARY_SIMPLE_OP(UNARY_CASE) {
          TRACE("Added a vector of Unary\n");
          PackNode* pnode = NewPackNodeAndRecurs(node_group, 0, value_in_count,
                                                 recursion_depth);
          return pnode;
        }
        default: {
          TRACE("Unsupported Simd128Unary: %s\n",
                GetSimdOpcodeName(op0).c_str());
          return nullptr;
        }
      }
#undef UNARY_CASE
#undef UNARY_SIGN_EXTENSION_CASE
    }
    case Opcode::kSimd128Binop: {
#define BINOP_CASE(op_128, not_used) case Simd128BinopOp::Kind::k##op_128:
#define BINOP_SIGN_EXTENSION_CASE(op_low, not_used1, op_high)                 \
  case Simd128BinopOp::Kind::k##op_low: {                                     \
    if (const Simd128BinopOp* binop1 =                                        \
            op1.TryCast<Opmask::kSimd128##op_high>();                         \
        binop1 && op0.Cast<Simd128BinopOp>().left() == binop1->left() &&      \
        op0.Cast<Simd128BinopOp>().right() == binop1->right()) {              \
      return NewPackNode(node_group);                                         \
    }                                                                         \
    [[fallthrough]];                                                          \
  }                                                                           \
  case Simd128BinopOp::Kind::k##op_high: {                                    \
    if (op1.Cast<Simd128BinopOp>().kind == op0.Cast<Simd128BinopOp>().kind) { \
      auto force_pack_type =                                                  \
          node0 == node1 ? ForcePackNode::kSplat : ForcePackNode::kGeneral;   \
      return NewForcePackNode(node_group, force_pack_type, graph_);           \
    } else {                                                                  \
      return nullptr;                                                         \
    }                                                                         \
  }
      switch (op0.Cast<Simd128BinopOp>().kind) {
        SIMD256_BINOP_SIGN_EXTENSION_OP(BINOP_SIGN_EXTENSION_CASE)
        SIMD256_BINOP_SIMPLE_OP(BINOP_CASE) {
          TRACE("Added a vector of Binop\n");
          PackNode* pnode =
              NewCommutativePackNodeAndRecurs(node_group, recursion_depth);
          return pnode;
        }
        default: {
          TRACE("Unsupported Simd128Binop: %s\n",
                GetSimdOpcodeName(op0).c_str());
          return nullptr;
        }
      }
#undef BINOP_CASE
#undef BINOP_SIGN_EXTENSION_CASE
    }
    case Opcode::kSimd128Shift: {
      Simd128ShiftOp& shift_op0 = op0.Cast<Simd128ShiftOp>();
      Simd128ShiftOp& shift_op1 = op1.Cast<Simd128ShiftOp>();
      if (IsEqual(shift_op0.shift(), shift_op1.shift())) {
        switch (op0.Cast<Simd128ShiftOp>().kind) {
#define SHIFT_CASE(op_128, not_used) case Simd128ShiftOp::Kind::k##op_128:
          SIMD256_SHIFT_OP(SHIFT_CASE) {
            TRACE("Added a vector of Shift op.\n");
            // We've already checked that the "shift by" input of both shifts is
            // the same, and we'll only pack the 1st input of the shifts
            // together anyways (since on both Simd128 and Simd256, the "shift
            // by" input of shifts is a Word32). Thus we only need to check the
            // 1st input of the shift when recursing.
            constexpr int kShiftValueInCount = 1;
            PackNode* pnode = NewPackNodeAndRecurs(
                node_group, 0, kShiftValueInCount, recursion_depth);
            return pnode;
          }
#undef SHIFT_CASE
          default: {
            TRACE("Unsupported Simd128ShiftOp: %s\n",
                  GetSimdOpcodeName(op0).c_str());
            return nullptr;
          }
        }
      }
      TRACE("Failed due to SimdShiftOp kind or shift scalar is different!\n");
      return nullptr;
    }
    case Opcode::kSimd128Ternary: {
#define TERNARY_CASE(op_128, not_used) case Simd128TernaryOp::Kind::k##op_128:
      switch (op0.Cast<Simd128TernaryOp>().kind) {
        SIMD256_TERNARY_OP(TERNARY_CASE) {
          TRACE("Added a vector of Ternary\n");
          PackNode* pnode = NewPackNodeAndRecurs(node_group, 0, value_in_count,
                                                 recursion_depth);
          return pnode;
        }
#undef TERNARY_CASE
        default: {
          TRACE("Unsupported Simd128Ternary: %s\n",
                GetSimdOpcodeName(op0).c_str());
          return nullptr;
        }
      }
    }

    case Opcode::kSimd128Splat: {
      if (op0.input(0) != op1.input(0)) {
        TRACE("Failed due to different splat input!\n");
        return nullptr;
      }
      PackNode* pnode = NewPackNode(node_group);
      return pnode;
    }

    case Opcode::kSimd128Shuffle: {
      // We pack shuffles only if it can match specific patterns. We should
      // avoid packing general shuffles because it will cause regression.
      const auto& shuffle0 = op0.Cast<Simd128ShuffleOp>().shuffle;
      const auto& shuffle1 = op1.Cast<Simd128ShuffleOp>().shuffle;

      if (CompareCharsEqual(shuffle0, shuffle1, kSimd128Size)) {
        if (IsSplat(node_group)) {
          // Check if the shuffle can be replaced by a loadsplat.
          // Take load32splat as an example:
          // 1. Param0  # be used as load base
          // 2. Param1  # be used as load index
          // 3. Param2  # be used as store base
          // 4. Param3  # be used as store index
          // 5. Load128(base, index, offset=0)
          // 6. AnyOp
          // 7. Shuffle32x4 (1,2, [2,2,2,2])
          // 8. Store128(3,4,7, offset=0)
          // 9. Store128(3,4,7, offset=16)
          //
          // We can replace the load128 and shuffle with a loadsplat32:
          // 1. Param0  # be used as load base
          // 2. Param1  # be used as load index
          // 3. Param2  # be used as store base
          // 4. Param3  # be used as store index
          // 5. Load32Splat256(base, index, offset=4)
          // 6. Store256(3,4,7,offset=0)
          int index;
          if (wasm::SimdShuffle::TryMatchSplat<4>(shuffle0, &index) &&
              graph_.Get(op0.input(index >> 2)).opcode == Opcode::kLoad) {
            ShufflePackNode* pnode = NewShufflePackNode(
                node_group,
                ShufflePackNode::SpecificInfo::Kind::kS256Load32Transform);
            pnode->info().set_splat_index(index);
            return pnode;
          } else if (wasm::SimdShuffle::TryMatchSplat<2>(shuffle0, &index) &&
                     graph_.Get(op0.input(index >> 1)).opcode ==
                         Opcode::kLoad) {
            ShufflePackNode* pnode = NewShufflePackNode(
                node_group,
                ShufflePackNode::SpecificInfo::Kind::kS256Load64Transform);
            pnode->info().set_splat_index(index);
            return pnode;
          }
        } else {
#ifdef V8_TARGET_ARCH_X64
          if (ShufflePackNode* pnode =
                  X64TryMatch256Shuffle(node_group, shuffle0, shuffle1)) {
            // Manually invoke recur build tree for shuffle node
            for (int i = 0; i < value_in_count; ++i) {
              NodeGroup operands(graph_.Get(node_group[0]).input(i),
                                 graph_.Get(node_group[1]).input(i));

              PackNode* child = BuildTreeRec(operands, recursion_depth + 1);
              if (child) {
                pnode->SetOperand(i, child);
              } else {
                return nullptr;
              }
            }
            return pnode;
          }
#endif  // V8_TARGET_ARCH_X64
          return nullptr;
        }

        TRACE("Unsupported Simd128Shuffle\n");
        return nullptr;

      } else {
        return Try256ShuffleMatchLoad8x8U(node_group, shuffle0, shuffle1);
      }
    }

    case Opcode::kSimd128ReplaceLane: {
      ExtendIntToF32x4Info info;
      if (TryMatchExtendIntToF32x4(node_group, &info)) {
        TRACE("Match extend i8x4/i16x4 to f32x4\n");
        PackNode* p = NewBundlePackNode(
            node_group, info.extend_from, info.start_lane, info.lane_size,
            info.is_sign_extract, info.is_sign_convert);
        return p;
      }
      if (recursion_depth < 1) {
        TRACE("Do not force pack at root #%d:%s\n", node0.id(),
              GetSimdOpcodeName(op0).c_str());
        return nullptr;
      }
      return NewForcePackNode(
          node_group,
          node0 == node1 ? ForcePackNode::kSplat : ForcePackNode::kGeneral,
          graph_);
    }

    default:
      TRACE("Default branch #%d:%s\n", node0.id(),
            GetSimdOpcodeName(op0).c_str());
      break;
  }
  return nullptr;
}

bool WasmRevecAnalyzer::MergeSLPTrees() {
  // We ensured the SLP trees are mergable when BuildTreeRec.
  for (auto entry : slp_tree_->GetIntersectNodeMapping()) {
    auto it = revectorizable_intersect_node_.find(entry.first);
    if (it == revectorizable_intersect_node_.end()) {
      bool result;
      std::tie(it, result) = revectorizable_intersect_node_.emplace(
          entry.first, ZoneVector<PackNode*>(phase_zone_));
      DCHECK(result);
    }
    ZoneVector<PackNode*>& intersect_pnodes = it->second;
    intersect_pnodes.insert(intersect_pnodes.end(), entry.second.begin(),
                            entry.second.end());
    SLOW_DCHECK(std::unique(intersect_pnodes.begin(), intersect_pnodes.end()) ==
                intersect_pnodes.end());
  }

  revectorizable_node_.merge(slp_tree_->GetNodeMapping());
  return true;
}

bool WasmRevecAnalyzer::IsSupportedReduceSeed(const Operation& op) {
  if (!op.Is<Simd128BinopOp>()) {
    return false;
  }
  switch (op.Cast<Simd128BinopOp>().kind) {
#define CASE(op_128) case Simd128BinopOp::Kind::k##op_128:
    REDUCE_SEED_KIND(CASE) { return true; }
    default:
      return false;
  }
#undef CASE
}

void WasmRevecAnalyzer::ProcessBlock(const Block& block) {
  StoreInfoSet simd128_stores(phase_zone_);
  for (const Operation& op : base::Reversed(graph_.operations(block))) {
    if (const StoreOp* store_op = op.TryCast<StoreOp>()) {
      if (store_op->stored_rep == MemoryRepresentation::Simd128()) {
        StoreLoadInfo<StoreOp> info(&graph_, store_op);
        if (info.IsValid()) {
          simd128_stores.insert(info);
        }
      }
    }
    // Try to find reduce op which can be used as revec seeds.
    if (IsSupportedReduceSeed(op)) {
      const Simd128BinopOp& binop = op.Cast<Simd128BinopOp>();
      V<Simd128> left_index = binop.left();
      V<Simd128> right_index = binop.right();
      const Operation& left_op = graph_.Get(left_index);
      const Operation& right_op = graph_.Get(right_index);

      if (left_index != right_index && left_op.opcode == right_op.opcode &&
          IsSameOpAndKind(left_op, right_op)) {
        reduce_seeds_.push_back({left_index, right_index});
      }
    }
  }

  if (simd128_stores.size() >= 2) {
    for (auto it = std::next(simd128_stores.cbegin()),
              end = simd128_stores.cend();
         it != end;) {
      const StoreLoadInfo<StoreOp>& info0 = *std::prev(it);
      const StoreLoadInfo<StoreOp>& info1 = *it;
      auto diff = info1 - info0;

      if (diff.has_value()) {
        const int value = diff.value();
        DCHECK_GE(value, 0);
        if (value == kSimd128Size) {
          store_seeds_.push_back(
              {graph_.Index(*info0.op()), graph_.Index(*info1.op())});
          if (std::distance(it, end) < 2) {
            break;
          }
          std::advance(it, 2);
          continue;
        }
      }
      it++;
    }
  }
}

void WasmRevecAnalyzer::Run() {
  for (Block& block : base::Reversed(graph_.blocks())) {
    ProcessBlock(block);
  }

  if (store_seeds_.empty() && reduce_seeds_.empty()) {
    TRACE("Empty seed\n");
    return;
  }

  if (v8_flags.trace_wasm_revectorize) {
    PrintF("store seeds:\n");
    for (auto pair : store_seeds_) {
      PrintF("{\n");
      PrintF("#%u ", pair.first.id());
      graph_.Get(pair.first).Print();
      PrintF("#%u ", pair.second.id());
      graph_.Get(pair.second).Print();
      PrintF("}\n");
    }

    PrintF("reduce seeds:\n");
    for (auto pair : reduce_seeds_) {
      PrintF("{ ");
      PrintF("#%u, ", pair.first.id());
      PrintF("#%u ", pair.second.id());
      PrintF("}\n");
    }
  }
  slp_tree_ = phase_zone_->New<SLPTree>(graph_, this, phase_zone_);

  ZoneVector<std::pair<OpIndex, OpIndex>> all_seeds(
      store_seeds_.begin(), store_seeds_.end(), phase_zone_);
  all_seeds.insert(all_seeds.end(), reduce_seeds_.begin(), reduce_seeds_.end());

  for (auto pair : all_seeds) {
    NodeGroup roots(pair.first, pair.second);

    slp_tree_->DeleteTree();
    PackNode* root = slp_tree_->BuildTree(roots);
    if (!root) {
      TRACE("Build tree failed!\n");
      continue;
    }

    slp_tree_->Print("After build tree");
    if (!MergeSLPTrees()) {
      TRACE("Failed to merge revectorizable nodes!\n");
    }
  }

  // Early exist when no revectorizable node found.
  if (revectorizable_node_.empty()) return;

  // Build SIMD usemap
  use_map_ = phase_zone_->New<SimdUseMap>(graph_, phase_zone_);
  if (!DecideVectorize()) {
    revectorizable_node_.clear();
  } else {
    should_reduce_ = true;
    Print("Decide to vectorize");
  }
}

bool WasmRevecAnalyzer::DecideVectorize() {
  TRACE("Enter %s\n", __func__);
  int save = 0, cost = 0;
  ForEach(
      [&](PackNode const* pnode) {
        const NodeGroup& nodes = pnode->nodes();
        // An additional store is emitted in case of OOB trap at the higher
        // 128-bit address. Thus no save if the store at lower address is
        // executed first. Return directly as we dont need to check external use
        // for stores.
        if (graph_.Get(nodes[0]).opcode == Opcode::kStore) {
          if (nodes[0] > nodes[1]) save++;
          return;
        }

        if (pnode->IsForcePackNode()) {
          cost++;
          return;
        }

        // Splat nodes will not cause a saving as it simply extends itself.
        if (!IsSplat(nodes)) {
          save++;
        }

#ifdef V8_TARGET_ARCH_X64
        // On x64 platform, we dont emit extract for lane 0 as the source ymm
        // register is alias to the corresponding xmm register in lower 128-bit.
        for (int i = 1; i < static_cast<int>(nodes.size()); i++) {
          if (nodes[i] == nodes[0]) continue;
#else
        for (int i = 0; i < static_cast<int>(nodes.size()); i++) {
          if (i > 0 && nodes[i] == nodes[0]) continue;
#endif  // V8_TARGET_ARCH_X64

          for (auto use : use_map_->uses(nodes[i])) {
            if (!GetPackNode(use) || GetPackNode(use)->IsForcePackNode()) {
              TRACE("External use edge: (%d:%s) -> (%d:%s)\n", use.id(),
                    OpcodeName(graph_.Get(use).opcode), nodes[i].id(),
                    OpcodeName(graph_.Get(nodes[i]).opcode));
              ++cost;

              // We only need one Extract node and all other uses can share.
              break;
            }
          }
        }
      },
      revectorizable_node_);

  ForEach(
      [&](PackNode const* pnode) {
        // We always generate SimdPack128To256Op for IntersectPackNode.
        cost++;
        return;
      },
      revectorizable_intersect_node_);

  TRACE("Save: %d, cost: %d\n", save, cost);
  return save > cost;
}

void WasmRevecAnalyzer::Print(const char* info) {
  if (!v8_flags.trace_wasm_revectorize) {
    return;
  }

  TRACE("%s, %zu revectorizable nodes:\n", info, revectorizable_node_.size());
  ForEach([this](PackNode const* pnode) { pnode->Print(&graph_); },
          revectorizable_node_);
  TRACE("%s, %zu revectorizable intersect nodes:\n", info,
        revectorizable_intersect_node_.size());
  ForEach([this](PackNode const* pnode) { pnode->Print(&graph_); },
          revectorizable_intersect_node_);
}

}  // namespace v8::internal::compiler::turboshaft
```