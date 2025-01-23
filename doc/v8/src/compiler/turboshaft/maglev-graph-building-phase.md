Response: The user wants a summary of the provided C++ code file, which is part of the V8 JavaScript engine. I need to understand the purpose of `maglev-graph-building-phase.cc` within the Turboshaft compiler pipeline and explain its relation to JavaScript functionality. Since this is the first part of a larger file, I should focus on the concepts and components introduced in this section.

**Key observations from the code:**

* **Includes:** The file includes various headers from V8, specifically related to compilation, Turboshaft, and Maglev. This suggests it's involved in translating or converting between these two intermediate representations.
* **Namespaces:** It operates within the `v8::internal::compiler::turboshaft` namespace.
* **Class `MaglevGraphBuildingPhase`:** Although not fully visible in this part, the file name strongly suggests this class or related functionality is central.
* **Reducers:** The use of `BlockOriginTrackingReducer` as a template parameter for `TSAssembler` indicates a mechanism for tracking the origin of Turboshaft blocks back to their Maglev counterparts.
* **Class `GeneratorAnalyzer`:** This class seems to handle the complexities of translating Maglev graphs for JavaScript generators into Turboshaft, addressing issues like bypassed loop headers.
* **Macros:** Several macros like `GET_FRAME_STATE_MAYBE_ABORT`, `BAILOUT_IF_TOO_MANY_ARGUMENTS_FOR_CALL`, `GENERATE_AND_MAP_BUILTIN_CALL`, and `RETURN_IF_UNREACHABLE` suggest common patterns for error handling, call generation, and optimization during the graph building process.
* **Class `GraphBuildingNodeProcessor`:** This class appears to be the core component responsible for iterating through Maglev nodes and generating the corresponding Turboshaft graph. It manages mappings between Maglev and Turboshaft blocks and nodes.
* **Node Processing:** The `Process` methods for various Maglev node types (e.g., `Constant`, `RootConstant`, `Phi`, `Call`) indicate how different Maglev IR constructs are translated into Turboshaft operations.
* **Frame States:** Handling of `FrameState` suggests this phase is crucial for deoptimization and debugging.
* **Builtins and Calls:** The code handles calls to JavaScript functions and built-in functions, indicating its role in translating function invocation semantics.

**Plan:**

1. **State the core function:**  The primary goal is to build a Turboshaft graph from a Maglev graph.
2. **Explain the context:** This is a phase within the V8 compilation pipeline, specifically bridging Maglev and Turboshaft.
3. **Highlight key classes:** Briefly describe the roles of `GeneratorAnalyzer` and `GraphBuildingNodeProcessor`.
4. **Mention the tracking mechanism:** Explain the purpose of `BlockOriginTrackingReducer`.
5. **Illustrate with a JavaScript example:** Show a simple JavaScript generator function and how its execution flow might involve the concepts addressed in the code (like resuming and potentially bypassing loop headers).
这个C++源代码文件 `maglev-graph-building-phase.cc` 的主要功能是将 **Maglev 中间表示（IR）** 的图结构转换成 **Turboshaft 中间表示** 的图结构。这是 V8 JavaScript 引擎编译优化管道中的一个关键步骤，它负责将 Maglev 的图表示形式转化为更适合后续优化和代码生成的 Turboshaft 图。

具体来说，从这个文件的第一部分可以看出，它涵盖了以下几个关键方面：

1. **基础架构和依赖:**  它包含了必要的头文件，定义了命名空间，并引入了 Turboshaft 框架中的核心组件，如 `Graph`, `Block`, `Operation`, `Assembler` 等。

2. **值表示转换:**  定义了 Maglev 的 `ValueRepresentation` 到 Turboshaft 的 `MachineType` 的映射关系，以及处理不同元素类型大小的函数。这说明了在两种 IR 之间进行数据类型转换的重要性。

3. **块来源追踪 (`BlockOriginTrackingReducer`):**  这个 reducer 的作用是跟踪 Turboshaft 中构建的每个代码块在原始 Maglev 图中的对应块。这对于后续的一些优化（如 Phi 节点的输入重排序）至关重要，因为 Maglev 和 Turboshaft 的块顺序可能不同。

4. **生成器分析 (`GeneratorAnalyzer`):**  这个类专门处理 JavaScript 生成器函数的编译。由于生成器的 `yield` 关键字会导致执行流程的中断和恢复，Maglev 图中可能存在绕过循环头部的边。Turboshaft 要求循环头部必须支配循环内的所有块，因此 `GeneratorAnalyzer` 的作用是识别这些绕过的情况，并为后续的图构建提供必要的信息，以便正确地处理生成器的控制流。

5. **图构建的核心 (`GraphBuildingNodeProcessor`):**  虽然具体的节点处理逻辑只展现了一部分，但 `GraphBuildingNodeProcessor` 是负责遍历 Maglev 图中的节点，并将其转换为相应的 Turboshaft 操作的核心类。它维护了 Maglev 和 Turboshaft 节点和块之间的映射关系，并处理了变量和寄存器的管理。

**与 JavaScript 功能的关系以及示例：**

这个文件直接关系到 JavaScript 中 **生成器（Generators）** 的功能。

**JavaScript 示例：**

```javascript
function* myGenerator() {
  console.log("开始");
  let i = 0;
  while (i < 3) {
    if (i % 2 === 0) {
      yield i;
    }
    i++;
  }
  console.log("结束");
}

const generator = myGenerator();
console.log(generator.next()); // 输出: 开始, { value: 0, done: false }
console.log(generator.next()); // 输出: { value: undefined, done: false }
console.log(generator.next()); // 输出: { value: 2, done: false }
console.log(generator.next()); // 输出: 结束, { value: undefined, done: true }
```

**说明：**

在这个例子中，`yield` 关键字会暂停函数的执行，并将 `i` 的值返回。当调用 `generator.next()` 时，函数会从上次暂停的地方恢复执行。

**`GeneratorAnalyzer` 在编译这个生成器函数时会发挥作用，它需要处理以下情况：**

* **Maglev 图中的绕过循环头部的边：**  在上面的例子中，当 `i` 是奇数时，`yield` 不会被执行，执行流程会直接跳到 `i++`。在 Maglev 图中，这可能会表现为从 `if` 语句的分支直接跳转到循环的后一部分，绕过了循环头部。
* **Turboshaft 的要求：** Turboshaft 需要循环头部支配循环内的所有块。
* **`GeneratorAnalyzer` 的作用：**  `GeneratorAnalyzer` 会识别这种绕过，并告知 `GraphBuildingNodeProcessor` 在构建 Turboshaft 图时需要采取特殊措施，例如插入额外的跳转或条件分支，以确保 Turboshaft 图的结构符合要求。

总而言之，这个文件的第一部分主要介绍了将 Maglev 图转换为 Turboshaft 图的基础框架和处理生成器函数的特殊逻辑，这是 V8 优化 JavaScript 代码的关键步骤。

### 提示词
```
这是目录为v8/src/compiler/turboshaft/maglev-graph-building-phase.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/turboshaft/maglev-graph-building-phase.h"

#include <limits>
#include <memory>
#include <optional>
#include <type_traits>

#include "src/base/logging.h"
#include "src/base/small-vector.h"
#include "src/base/vector.h"
#include "src/codegen/bailout-reason.h"
#include "src/codegen/optimized-compilation-info.h"
#include "src/common/globals.h"
#include "src/compiler/access-builder.h"
#include "src/compiler/bytecode-analysis.h"
#include "src/compiler/bytecode-liveness-map.h"
#include "src/compiler/frame-states.h"
#include "src/compiler/globals.h"
#include "src/compiler/js-heap-broker.h"
#include "src/compiler/turboshaft/assembler.h"
#include "src/compiler/turboshaft/graph.h"
#include "src/compiler/turboshaft/index.h"
#include "src/compiler/turboshaft/machine-optimization-reducer.h"
#include "src/compiler/turboshaft/maglev-early-lowering-reducer-inl.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/phase.h"
#include "src/compiler/turboshaft/representations.h"
#include "src/compiler/turboshaft/required-optimization-reducer.h"
#include "src/compiler/turboshaft/sidetable.h"
#include "src/compiler/turboshaft/utils.h"
#include "src/compiler/turboshaft/value-numbering-reducer.h"
#include "src/compiler/turboshaft/variable-reducer.h"
#include "src/compiler/write-barrier-kind.h"
#include "src/deoptimizer/deoptimize-reason.h"
#include "src/handles/global-handles-inl.h"
#include "src/handles/handles.h"
#include "src/interpreter/bytecode-register.h"
#include "src/maglev/maglev-basic-block.h"
#include "src/maglev/maglev-compilation-info.h"
#include "src/maglev/maglev-compilation-unit.h"
#include "src/maglev/maglev-graph-builder.h"
#include "src/maglev/maglev-graph-labeller.h"
#include "src/maglev/maglev-graph-processor.h"
#include "src/maglev/maglev-graph-verifier.h"
#include "src/maglev/maglev-ir-inl.h"
#include "src/maglev/maglev-ir.h"
#include "src/maglev/maglev-phi-representation-selector.h"
#include "src/maglev/maglev-post-hoc-optimizations-processors.h"
#include "src/objects/elements-kind.h"
#include "src/objects/heap-object.h"
#include "src/objects/js-array-buffer.h"
#include "src/objects/objects.h"
#include "src/objects/property-cell.h"
#include "src/zone/zone-containers.h"

namespace v8::internal::compiler::turboshaft {

#include "src/compiler/turboshaft/define-assembler-macros.inc"

namespace {

MachineType MachineTypeFor(maglev::ValueRepresentation repr) {
  switch (repr) {
    case maglev::ValueRepresentation::kTagged:
      return MachineType::AnyTagged();
    case maglev::ValueRepresentation::kInt32:
      return MachineType::Int32();
    case maglev::ValueRepresentation::kUint32:
      return MachineType::Uint32();
    case maglev::ValueRepresentation::kIntPtr:
      return MachineType::IntPtr();
    case maglev::ValueRepresentation::kFloat64:
      return MachineType::Float64();
    case maglev::ValueRepresentation::kHoleyFloat64:
      return MachineType::HoleyFloat64();
  }
}

int ElementsKindSize(ElementsKind element_kind) {
  switch (element_kind) {
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) \
  case TYPE##_ELEMENTS:                           \
    DCHECK_LE(sizeof(ctype), 8);                  \
    return sizeof(ctype);
    TYPED_ARRAYS(TYPED_ARRAY_CASE)
    default:
      UNREACHABLE();
#undef TYPED_ARRAY_CASE
  }
}

}  // namespace

// This reducer tracks the Maglev origin of the Turboshaft blocks that we build
// during the translation. This is then used when reordering Phi inputs.
template <class Next>
class BlockOriginTrackingReducer : public Next {
 public:
  TURBOSHAFT_REDUCER_BOILERPLATE(BlockOriginTracking)
  void SetMaglevInputBlock(const maglev::BasicBlock* block) {
    maglev_input_block_ = block;
  }
  const maglev::BasicBlock* maglev_input_block() const {
    return maglev_input_block_;
  }
  void Bind(Block* block) {
    Next::Bind(block);
    // The 1st block we bind doesn't exist in Maglev and is meant to hold
    // Constants (which in Maglev are not in any block), and thus
    // {maglev_input_block_} should still be nullptr. In all other cases,
    // {maglev_input_block_} should not be nullptr.
    DCHECK_EQ(maglev_input_block_ == nullptr,
              block == &__ output_graph().StartBlock());
    turboshaft_block_origins_[block->index()] = maglev_input_block_;
  }

  const maglev::BasicBlock* GetMaglevOrigin(const Block* block) {
    DCHECK_NOT_NULL(turboshaft_block_origins_[block->index()]);
    return turboshaft_block_origins_[block->index()];
  }

 private:
  const maglev::BasicBlock* maglev_input_block_ = nullptr;
  GrowingBlockSidetable<const maglev::BasicBlock*> turboshaft_block_origins_{
      __ phase_zone()};
};

class GeneratorAnalyzer {
  // A document explaning how generators are handled by the translation can be
  // found here:
  //
  //     https://docs.google.com/document/d/1-iFoVuvpIEjA9dtSsOjmKL5vAzzvf0cKI6f4zaObiV8/edit?usp=sharing
  //
  //
  // Because of generator resumes, Maglev graphs can have edges that bypass loop
  // headers. This actually happens everytime a loop contains a `yield`.
  // In Turboshaft, however, the loop header must always dominate every block in
  // the loop, and thus does not allow such edges that bypass the loop header.
  // For instance,
  //
  //     function* foo() {
  //       for (let i = 0; i < 10; i++) {
  //         if (i % 2 == 0) {
  //           yield i;
  //         }
  //       }
  //     }
  //
  // The corresponding Maglev graph will look something like (this is a little
  // bit simplified since details don't matter much for this high level
  // explanation; the drawing in FindLoopHeaderBypasses below gives a more
  // precise view of what the Maglev graph looks like):
  //
  //                       + 1 ------+
  //                       | Switch  |
  //                       +---------+
  //                        /      \
  //                      /          \      |----------------------|
  //                    /              \    |                      |
  //                  /                 v   v                      |
  //                /              + 2 --------+                   |
  //              /                | Loop      |                   |
  //             |                 +-----------+                   |
  //             |                      |                          |
  //             |                      |                          |
  //             v                      v                          |
  //        + 4 ------+             + 3 --------------+            |
  //        | Resume  |             | Branch(i%2==0)  |            |
  //        +---------+             +-----------------+            |
  //            |                     /        \                   |
  //            |                    /          \                  |
  //            |                   /            \                 |
  //            |             + 5 -------+        |                |
  //            |             | yield i  |        |                |
  //            |             +----------+        |                |
  //            |                                 |                |
  //            |----------------------------|    |                |
  //                                         |    |                |
  //                                         v    v                |
  //                                    + 6 ----------+            |
  //                                    | i++         |            |
  //                                    | backedge    |            |
  //                                    +-------------+            |
  //                                           |                   |
  //                                           |-------------------|
  //
  // In this graph, the edge from block 4 to block 6 bypasses the loop header.
  //
  //
  // Note that it's even possible that the graph contains no forward path from
  // the loop header to the backedge. This happens for instance when the loop
  // body always unconditionally yields. In such cases, the backedge is always
  // reached through the main resume switch. For instance:
  //
  //     function* foo() {
  //       for (let i = 0; i < 10; i++) {
  //         yield i;
  //       }
  //     }
  //
  // Will produce the following graph:
  //
  //                       + 1 ------+
  //                       | Switch  |
  //                       +---------+
  //                        /      \
  //                      /          \      |-------------|
  //                    /              \    |             |
  //                  /                 v   v             |
  //                /              + 2 --------+          |
  //              /                | Loop      |          |
  //             |                 +-----------+          |
  //             |                      |                 |
  //             |                      |                 |
  //             v                      v                 |
  //        + 4 ------+             + 3 -------+          |
  //        | Resume  |             | yield i  |          |
  //        +---------+             +----------+          |
  //             |                                        |
  //             |                                        |
  //             |----------------------------------------|
  //
  //
  // GeneratorAnalyzer finds the loop in the Maglev graph, and finds the
  // generator resume edges that bypass loops headers. The GraphBuilder then
  // uses this information to re-route such edges to loop headers and insert
  // secondary switches. For instance, the graph right above will be transformed
  // to something like this:
  //
  //                       + 1 ------+
  //                       | Switch  |
  //                       +---------+
  //                          |  |
  //                          |  |
  //                          v  v
  //                     + 2 --------+
  //                     | p1 = phi  |
  //                     +-----------+
  //                          |
  //                          |    |-----------------------|
  //                          |    |                       |
  //                          v    v                       |
  //                     + 3 -----------------+            |
  //                     | Loop               |            |
  //                     | p2 = phi(p1,...)   |            |
  //                     +--------------------+            |
  //                           |                           |
  //                           |                           |
  //                           v                           |
  //                     + 4 -----------+                  |
  //                     | Switch(p2)   |                  |
  //                     +--------------+                  |
  //                       /       \                       |
  //                     /           \                     |
  //                   /               \                   |
  //                 v                   v                 |
  //           + 5 --------+        + 6 --------+          |
  //           | Resume    |        | yield i   |          |
  //           +-----------+        +-----------+          |
  //                 |                                     |
  //                 |                                     |
  //                 |-------------------------------------|

 public:
  explicit GeneratorAnalyzer(Zone* phase_zone,
                             maglev::MaglevGraphLabeller* labeller)
      : labeller_(labeller),
        block_to_header_(phase_zone),
        visit_queue_(phase_zone) {
    USE(labeller_);
  }

  void Analyze(maglev::Graph* graph) {
    for (auto it = graph->rbegin(); it != graph->rend(); ++it) {
      if ((*it)->is_loop()) {
        FindLoopBody(it);
      }
    }

    FindLoopHeaderBypasses(graph);
  }

  bool JumpBypassesHeader(const maglev::BasicBlock* target) {
    return block_to_innermost_bypassed_header_.contains(target);
  }

  const maglev::BasicBlock* GetInnermostBypassedHeader(
      const maglev::BasicBlock* target) {
    DCHECK(JumpBypassesHeader(target));
    return block_to_innermost_bypassed_header_[target];
  }

  bool HeaderIsBypassed(const maglev::BasicBlock* header) {
    DCHECK(header->is_loop());
    return bypassed_headers_.contains(header);
  }

  const maglev::BasicBlock* GetLoopHeader(const maglev::BasicBlock* node) {
    if (block_to_header_.contains(node)) {
      return block_to_header_[node];
    }
    return nullptr;
  }

  bool has_header_bypasses() const { return !bypassed_headers_.empty(); }

 private:
  // We consider that every block in between the loop header and the backedge
  // belongs to the loop. This is a little bit more conservative than necessary
  // and might include blocks that in fact cannot reach the backedge, but it
  // makes dealing with exception blocks easier (because they have no explicit
  // predecessors in Maglev).
  void FindLoopBody(maglev::BlockConstReverseIterator it) {
    const maglev::BasicBlock* header = *it;
    DCHECK(header->is_loop());

    --it;  // Skipping the header, since we consider its loop header to be the
           // header of their outer loop (if any).

    const maglev::BasicBlock* backedge_block = header->backedge_predecessor();
    if (backedge_block == header) {
      // This is a 1-block loop. Since headers are part of the outer loop, we
      // have nothing to mark.
      return;
    }

    block_to_header_[backedge_block] = header;

    for (; *it != backedge_block; --it) {
      const maglev::BasicBlock* curr = *it;
      if (block_to_header_.contains(curr)) {
        // {curr} is part of an inner loop.
        continue;
      }
      block_to_header_[curr] = header;
    }
  }

  void FindLoopHeaderBypasses(maglev::Graph* graph) {
    // As mentioned earlier, Maglev graphs for resumable generator functions
    // always start with a main dispatch switch in the 3rd block:
    //
    //
    //                       + 1 -----------------+
    //                       | InitialValues...   |
    //                       | Jump               |
    //                       +--------------------+
    //                                  |
    //                                  |
    //                                  v
    //                       + 2 --------------------+
    //                       | BranchIfRootConstant  |
    //                       +-----------------------+
    //                          /                  \
    //                         /                     \
    //                        /                        \
    //                       /                           \
    //                      v                              v
    //              + 3 ----------+                  + 4 --------------+
    //              | Load state  |                  | Initial setup   |
    //              | Switch      |                  | return          |
    //              +-------------+                  +-----------------+
    //                /    |    \
    //               /     |     \
    //              v      v      v
    //          Resuming in various places
    //
    //
    //
    // In order to find loop header bypasses, we are looking for cases where
    // the destination of the dispatch switch (= the successors of block 3) are
    // inside a loop.

    constexpr int kGeneratorSwitchBLockIndex = 2;
    maglev::BasicBlock* generator_switch_block =
        graph->blocks()[kGeneratorSwitchBLockIndex];
    DCHECK(generator_switch_block->control_node()->Is<maglev::Switch>());

    for (maglev::BasicBlock* target : generator_switch_block->successors()) {
      const maglev::BasicBlock* innermost_header = GetLoopHeader(target);

      if (innermost_header) {
        // This case bypasses a loop header.
        RecordHeadersForBypass(target, innermost_header);
      }
    }
  }

  void RecordHeadersForBypass(maglev::BasicBlock* initial_target,
                              const maglev::BasicBlock* innermost_header) {
    block_to_innermost_bypassed_header_[initial_target] = innermost_header;
    bypassed_headers_.insert(innermost_header);

    for (const maglev::BasicBlock* outer_header =
             GetLoopHeader(innermost_header);
         outer_header; outer_header = GetLoopHeader(outer_header)) {
      bypassed_headers_.insert(outer_header);
    }
  }

  maglev::MaglevGraphLabeller* labeller_;

  // Map from blocks inside loops to the header of said loops.
  ZoneAbslFlatHashMap<const maglev::BasicBlock*, const maglev::BasicBlock*>
      block_to_header_;

  // Map from jump target to the innermost header they bypass.
  std::unordered_map<const maglev::BasicBlock*, const maglev::BasicBlock*>
      block_to_innermost_bypassed_header_;
  // Set of headers that are bypassed because of generator resumes.
  std::unordered_set<const maglev::BasicBlock*> bypassed_headers_;

  // {visit_queue_} is used in FindLoopBody to store nodes that still need to be
  // visited. It is an instance variable in order to reuse its memory more
  // efficiently.
  ZoneVector<const maglev::BasicBlock*> visit_queue_;
};

#define GET_FRAME_STATE_MAYBE_ABORT(name, deopt_info)                       \
  V<FrameState> name;                                                       \
  {                                                                         \
    OptionalV<FrameState> _maybe_frame_state = BuildFrameState(deopt_info); \
    if (!_maybe_frame_state.has_value()) {                                  \
      DCHECK(bailout_->has_value());                                        \
      return maglev::ProcessResult::kAbort;                                 \
    }                                                                       \
    name = _maybe_frame_state.value();                                      \
  }

constexpr bool TooManyArgumentsForCall(size_t arguments_count) {
  constexpr int kCalleeCount = 1;
  constexpr int kFrameStateCount = 1;
  return (arguments_count + kCalleeCount + kFrameStateCount) >
         std::numeric_limits<decltype(Operation::input_count)>::max();
}

#define BAILOUT_IF_TOO_MANY_ARGUMENTS_FOR_CALL(count) \
  {                                                   \
    if (TooManyArgumentsForCall(count)) {             \
      *bailout_ = BailoutReason::kTooManyArguments;   \
      return maglev::ProcessResult::kAbort;           \
    }                                                 \
  }

#define GENERATE_AND_MAP_BUILTIN_CALL(node, builtin, frame_state, arguments, \
                                      ...)                                   \
  BAILOUT_IF_TOO_MANY_ARGUMENTS_FOR_CALL(arguments.size());                  \
  SetMap(node, GenerateBuiltinCall(node, builtin, frame_state, arguments,    \
                                   ##__VA_ARGS__));

// Turboshaft's MachineOptimizationReducer will sometimes detect that the
// condition for a DeoptimizeIf is always true, and replace it with an
// unconditional Deoptimize. When this happens, the assembler doesn't emit
// anything until the next reachable block is bound, which can lead to some
// Variable or OpIndex being Invalid, which can break some assumptions. To avoid
// this, the RETURN_IF_UNREACHABLE macro can be used to early-return.
#define RETURN_IF_UNREACHABLE()                 \
  if (__ generating_unreachable_operations()) { \
    return maglev::ProcessResult::kContinue;    \
  }

// TODO(dmercadier): LazyDeoptOnThrow is currently not very cleanly dealt with.
// In Maglev, it is a property of the ExceptionHandlerInfo, which is use by all
// throwing nodes and is created in a single place
// (MaglevGraphBuilder::AttachExceptionHandlerInfo). However, during the
// translation, we create different kind of calls from different places (Call,
// CallBuiltin_XXX, CallRuntime_XXX), and non-call nodes can also
// LazyDeoptOnThrow (such as GenericBinop) and we always have to manually
// remember to pass ShouldLazyDeoptOnThrow, which is easy to forget, which can
// then easily lead to bugs. A few ideas come to mind:
//
//  - Make ShouldLazyDeoptOnThrow non-optional on all throwing nodes. This is a
//    bit verbose, but at least we won't forget it.
//
//  - Make ThrowingScope automatically annotate all throwing nodes that are
//    emitted while the scope is active. The Assembler would be doing most of
//    the work: it would have a "LazyDeoptOnThrowScope" or something similar,
//    and any throwing node emitted during this scope would have the
//    LazyDeoptOnThrow property added as needed. All throwing nodes have a
//    {lazy_deopt_on_throw} field defined by THROWING_OP_BOILERPLATE (except
//    calls, but we could add it), so it shouldn't be very hard for the
//    Assembler to deal with this in a unified way.
//    The downside of this approach is that the interaction between this and
//    {current_catch_block} (in particular with nested scopes) might introduce
//    even more complexity and magic in the assembler.

class GraphBuildingNodeProcessor {
 public:
  using AssemblerT =
      TSAssembler<BlockOriginTrackingReducer, MaglevEarlyLoweringReducer,
                  MachineOptimizationReducer, VariableReducer,
                  RequiredOptimizationReducer, ValueNumberingReducer>;

  GraphBuildingNodeProcessor(
      PipelineData* data, Graph& graph, Zone* temp_zone,
      maglev::MaglevCompilationUnit* maglev_compilation_unit,
      std::optional<BailoutReason>* bailout)
      : data_(data),
        temp_zone_(temp_zone),
        assembler_(data, graph, graph, temp_zone),
        maglev_compilation_unit_(maglev_compilation_unit),
        node_mapping_(temp_zone),
        block_mapping_(temp_zone),
        regs_to_vars_(temp_zone),
        loop_single_edge_predecessors_(temp_zone),
        maglev_representations_(temp_zone),
        generator_analyzer_(temp_zone,
                            maglev_compilation_unit_->graph_labeller()),
        bailout_(bailout) {}

  void PreProcessGraph(maglev::Graph* graph) {
    for (maglev::BasicBlock* block : *graph) {
      block_mapping_[block] =
          block->is_loop() ? __ NewLoopHeader() : __ NewBlock();
    }
    // Constants are not in a block in Maglev but are in Turboshaft. We bind a
    // block now, so that Constants can then be emitted.
    __ Bind(__ NewBlock());

    if (maglev_compilation_unit_->bytecode()
            .incoming_new_target_or_generator_register()
            .is_valid()) {
      // The Maglev graph might contain a RegisterInput for
      // kJavaScriptCallNewTargetRegister later in the graph, which in
      // Turboshaft is represented as a Parameter. We create this Parameter
      // here, because the Instruction Selector tends to be unhappy when
      // Parameters are defined late in the graph.
      int new_target_index = Linkage::GetJSCallNewTargetParamIndex(
          maglev_compilation_unit_->parameter_count());
      new_target_param_ = __ Parameter(
          new_target_index, RegisterRepresentation::Tagged(), "%new.target");
    }

    if (graph->has_resumable_generator()) {
      generator_analyzer_.Analyze(graph);

      dummy_object_input_ = __ SmiConstant(0);
      dummy_word32_input_ = __ Word32Constant(0);
      dummy_float64_input_ = __ Float64Constant(0);

      header_switch_input_ = __ NewVariable(RegisterRepresentation::Word32());
      loop_default_generator_value_ = __ Word32Constant(kDefaultSwitchVarValue);
      generator_context_ =
          __ NewLoopInvariantVariable(RegisterRepresentation::Tagged());
      __ SetVariable(generator_context_, __ NoContextConstant());
    }

    // Maglev nodes often don't have the NativeContext as input, but instead
    // rely on the MaglevAssembler to provide it during code generation, unlike
    // Turboshaft nodes, which need the NativeContext as an explicit input if
    // they use it. We thus emit a single NativeContext constant here, which we
    // reuse later to construct Turboshaft nodes.
    native_context_ =
        __ HeapConstant(broker_->target_native_context().object());
  }

  void PostProcessGraph(maglev::Graph* graph) {
    // It can happen that some Maglev loops don't actually loop (the backedge
    // isn't actually reachable). We can't know this when emitting the header in
    // Turboshaft, which means that we still emit the header, but then we never
    // come around to calling FixLoopPhis on it. So, once we've generated the
    // whole Turboshaft graph, we go over all loop headers, and if some turn out
    // to not be headers, we turn them into regular merge blocks (and patch
    // their PendingLoopPhis).
    for (Block& block : __ output_graph().blocks()) {
      if (block.IsLoop() && block.PredecessorCount() == 1) {
        __ output_graph().TurnLoopIntoMerge(&block);
      }
    }
  }

  // The Maglev graph for resumable generator functions always has the main
  // dispatch Switch in its 3rd block.
  bool IsMaglevMainGeneratorSwitchBlock(
      const maglev::BasicBlock* maglev_block) {
    if (!generator_analyzer_.has_header_bypasses()) return false;
    constexpr int kMainSwitchBlockId = 3;
    bool is_main_switch_block =
        maglev_compilation_unit_->graph_labeller()->BlockId(maglev_block) ==
        kMainSwitchBlockId;
    DCHECK_IMPLIES(is_main_switch_block,
                   maglev_block->control_node()->Is<maglev::Switch>());
    return is_main_switch_block;
  }

  maglev::BlockProcessResult PreProcessBasicBlock(
      maglev::BasicBlock* maglev_block) {
    // Note that it's important to call SetMaglevInputBlock before calling Bind,
    // so that BlockOriginTrackingReducer::Bind records the correct predecessor
    // for the current block.
    __ SetMaglevInputBlock(maglev_block);

    is_visiting_generator_main_switch_ =
        IsMaglevMainGeneratorSwitchBlock(maglev_block);

    Block* turboshaft_block = Map(maglev_block);

    if (__ current_block() != nullptr) {
      // The first block for Constants doesn't end with a Jump, so we add one
      // now.
      __ Goto(turboshaft_block);
    }

#ifdef DEBUG
    loop_phis_first_input_.clear();
    loop_phis_first_input_index_ = -1;
    catch_block_begin_ = V<Object>::Invalid();
#endif

    if (maglev_block->is_loop() &&
        (loop_single_edge_predecessors_.contains(maglev_block) ||
         pre_loop_generator_blocks_.contains(maglev_block))) {
      EmitLoopSinglePredecessorBlock(maglev_block);
    }

    if (maglev_block->is_exception_handler_block()) {
      StartExceptionBlock(maglev_block);
      return maglev::BlockProcessResult::kContinue;
    }

    // SetMaglevInputBlock should have been called before calling Bind, and the
    // current `maglev_input_block` should thus already be `maglev_block`.
    DCHECK_EQ(__ maglev_input_block(), maglev_block);
    if (!__ Bind(turboshaft_block)) {
      // The current block is not reachable.
      return maglev::BlockProcessResult::kContinue;
    }

    if (maglev_block->is_loop()) {
      // The "permutation" stuff that comes afterwards in this function doesn't
      // apply to loops, since loops always have 2 predecessors in Turboshaft,
      // and in both Turboshaft and Maglev, the backedge is always the last
      // predecessors, so we never need to reorder phi inputs.
      return maglev::BlockProcessResult::kContinue;
    } else if (maglev_block->is_exception_handler_block()) {
      // We need to emit the CatchBlockBegin at the begining of this block. Note
      // that if this block has multiple predecessors (because multiple throwing
      // operations are caught by the same catch handler), then edge splitting
      // will have already created CatchBlockBegin operations in the
      // predecessors, and calling `__ CatchBlockBegin` now will actually only
      // emit a Phi of the CatchBlockBegin of the predecessors (which is exactly
      // what we want). See the comment above CatchBlockBegin in
      // TurboshaftAssemblerOpInterface.
      catch_block_begin_ = __ CatchBlockBegin();
    }

    // Because of edge splitting in Maglev (which happens on Bind rather than on
    // Goto), predecessors in the Maglev graph are not always ordered by their
    // position in the graph (ie, block 4 could be the second predecessor and
    // block 5 the first one). However, since we're processing the graph "in
    // order" (because that's how the maglev GraphProcessor works), predecessors
    // in the Turboshaft graph will be ordered by their position in the graph.
    // Additionally, optimizations during the translation (like constant folding
    // by MachineOptimizationReducer) could change control flow and remove
    // predecessors (by changing a Branch into a Goto for instance).
    // We thus compute in {predecessor_permutation_} a map from Maglev
    // predecessor index to Turboshaft predecessor index, and we'll use this
    // later when emitting Phis to reorder their inputs.
    predecessor_permutation_.clear();
    if (maglev_block->has_phi() &&
        // We ignore this for exception phis since they have no inputs in Maglev
        // anyways, and in Turboshaft we rely on {regs_to_vars_} to populate
        // their inputs (and also, Maglev exception blocks have no
        // predecessors).
        !maglev_block->is_exception_handler_block()) {
      ComputePredecessorPermutations(maglev_block, turboshaft_block, false,
                                     false);
    }
    return maglev::BlockProcessResult::kContinue;
  }

  void ComputePredecessorPermutations(maglev::BasicBlock* maglev_block,
                                      Block* turboshaft_block,
                                      bool skip_backedge,
                                      bool ignore_last_predecessor) {
    // This function is only called for loops that need a "single block
    // predecessor" (from EmitLoopSinglePredecessorBlock). The backedge should
    // always be skipped in thus cases. Additionally, this means that when
    // even when {maglev_block} is a loop, {turboshaft_block} shouldn't and
    // should instead be the new single forward predecessor of the loop.
    DCHECK_EQ(skip_backedge, maglev_block->is_loop());
    DCHECK(!turboshaft_block->IsLoop());

    DCHECK(maglev_block->has_phi());
    DCHECK(turboshaft_block->IsBound());
    DCHECK_EQ(__ current_block(), turboshaft_block);

    // Collecting the Maglev predecessors.
    base::SmallVector<const maglev::BasicBlock*, 16> maglev_predecessors;
    maglev_predecessors.resize_no_init(maglev_block->predecessor_count());
    for (int i = 0; i < maglev_block->predecessor_count() - skip_backedge;
         ++i) {
      maglev_predecessors[i] = maglev_block->predecessor_at(i);
    }

    predecessor_permutation_.clear();
    predecessor_permutation_.resize_and_init(maglev_block->predecessor_count(),
                                             Block::kInvalidPredecessorIndex);
    int index = turboshaft_block->PredecessorCount() - 1;
    // Iterating predecessors from the end (because it's simpler and more
    // efficient in Turboshaft).
    for (const Block* pred : turboshaft_block->PredecessorsIterable()) {
      if (ignore_last_predecessor &&
          index == turboshaft_block->PredecessorCount() - 1) {
        // When generator resumes bypass loop headers, we add an additional
        // predecessor to the header's predecessor (called {pred_for_generator}
        // in EmitLoopSinglePredecessorBlock). This block doesn't have Maglev
        // origin, we thus have to skip it here. To compensate,
        // MakePhiMaybePermuteInputs will take an additional input for these
        // cases.
        index--;
        continue;
      }
      // Finding out to which Maglev predecessor {pred} corresponds.
      const maglev::BasicBlock* orig = __ GetMaglevOrigin(pred);
      auto orig_index = *base::index_of(maglev_predecessors, orig);

      predecessor_permutation_[orig_index] = index;
      index--;
    }
    DCHECK_EQ(index, -1);
  }

  // Exceptions Phis are a bit special in Maglev: they have no predecessors, and
  // get populated on Throw based on values in the FrameState, which can be raw
  // Int32/Float64. However, they are always Tagged, which means that retagging
  // happens when they are populated. This can lead to exception Phis having a
  // mix of tagged and untagged predecessors (the latter would be automatically
  // retagged). When this happens, we need to manually retag all of the
  // predecessors of the exception Phis. To do so:
  //
  //   - If {block} has a single predecessor, it means that it won't have
  //     exception "phis" per se, but just values that have to retag.
  //
  //   - If {block} has multiple predecessors, then we need to do the retagging
  //     in the predecessors. It's a bit annoying because we've already bound
  //     and finalized all of the predecessors by now. So, we create new
  //     predecessor blocks in which we insert the taggings, patch the old
  //     predecessors to point to the new ones, and update the predecessors of
  //     {block}.
  void StartExceptionBlock(maglev::BasicBlock* maglev_catch_handler) {
    Block* turboshaft_catch_handler = Map(maglev_catch_handler);
    if (turboshaft_catch_handler->PredecessorCount() == 0) {
      // Some Assembler optimizations made this catch handler not be actually
      // reachable.
      return;
    }
    if (turboshaft_catch_handler->PredecessorCount() == 1) {
      StartSinglePredecessorExceptionBlock(maglev_catch_handler,
                                           turboshaft_catch_handler);
    } else {
      StartMultiPredecessorExceptionBlock(maglev_catch_handler,
                                          turboshaft_catch_handler);
    }
  }
  void StartSinglePredecessorExceptionBlock(
      maglev::BasicBlock* maglev_catch_handler,
      Block* turboshaft_catch_handler) {
    if (!__ Bind(turboshaft_catch_handler)) return;
    catch_block_begin_ = __ CatchBlockBegin();
    if (!maglev_catch_handler->has_phi()) return;
    InsertTaggingForPhis(maglev_catch_handler);
  }
  // InsertTaggingForPhis makes sure that all of the inputs of the exception
  // phis of {maglev_catch_handler} are tagged. If some aren't tagged, it
  // inserts a tagging node in the current block and updates the corresponding
  // Variable.
  void InsertTaggingForPhis(maglev::BasicBlock* maglev_catch_handler) {
    DCHECK(maglev_catch_handler->has_phi());

    IterCatchHandlerPhis(maglev_catch_handler, [&](interpreter::Register owner,
                                                   Variable var) {
      DCHECK_NE(owner, interpreter::Register::virtual_accumulator());
      V<Any> ts_idx = __ GetVariable(var);
      DCHECK(maglev_representations_.contains(ts_idx));
      switch (maglev_representations_[ts_idx]) {
        case maglev::ValueRepresentation::kTagged:
          // Already tagged, nothing to do.
          break;
        case maglev::ValueRepresentation::kInt32:
          __ SetVariable(var, __ ConvertInt32ToNumber(V<Word32>::Cast(ts_idx)));
          break;
        case maglev::ValueRepresentation::kUint32:
          __ SetVariable(var,
                         __ ConvertUint32ToNumber(V<Word32>::Cast(ts_idx)));
          break;
        case maglev::ValueRepresentation::kFloat64:
          __ SetVariable(
              var,
              Float64ToTagged(
                  V<Float64>::Cast(ts_idx),
                  maglev::Float64ToTagged::ConversionMode::kCanonicalizeSmi));
          break;
        case maglev::ValueRepresentation::kHoleyFloat64:
          __ SetVariable(
              var, HoleyFloat64ToTagged(V<Float64>::Cast(ts_idx),
                                        maglev::HoleyFloat64ToTagged::
                                            ConversionMode::kCanonicalizeSmi));
          break;
        case maglev::ValueRepresentation::kIntPtr:
          UNREACHABLE();
      }
    });
  }
  void StartMultiPredecessorExceptionBlock(
      maglev::BasicBlock* maglev_catch_handler,
      Block* turboshaft_catch_handler) {
    if (!maglev_catch_handler->has_phi()) {
      // The very simple case: the catch handler didn't have any Phis, we don't
      // have to do anything complex.
      if (!__ Bind(turboshaft_catch_handler)) return;
      catch_block_begin_ = __ CatchBlockBegin();
      return;
    }

    // Inserting the tagging in all of the predecessors.
    auto predecessors = turboshaft_catch_handler->Predecessors();
    turboshaft_catch_handler->ResetAllPredecessors();
    base::SmallVector<V<Object>, 16> catch_block_begins;
    for (Block* predecessor : predecessors) {
      // Recording the CatchBlockBegin of this predecessor.
      V<Object> catch_begin = predecessor->begin();
      DCHECK(Asm().Get(catch_begin).template Is<CatchBlockBeginOp>());
      catch_block_begins.push_back(catch_begin);

      TagExceptionPhiInputsForBlock(predecessor, maglev_catch_handler,
                                    turboshaft_catch_handler);
    }

    // Finally binding the catch handler.
    __ Bind(turboshaft_catch_handler);

    // We now need to insert a Phi for the CatchBlockBegins of the
    // predecessors (usually, we would just call `__ CatchBlockbegin`, which
    // takes care of creating a Phi node if necessary, but this won't work here,
    // because this mechanisms expects the CatchBlockBegin to be the 1st
    // instruction of the predecessors, and it isn't the case since the
    // predecessors are now the blocks with the tagging).
    catch_block_begin_ = __ Phi(base::VectorOf(catch_block_begins));
  }
  void TagExceptionPhiInputsForBlock(Block* old_block,
                                     maglev::BasicBlock* maglev_catch_handler,
                                     Block* turboshaft_catch_handler) {
    DCHECK(maglev_catch_handler->has_phi());

    // We start by patching in-place the predecessors final Goto of {old_block}
    // to jump to a new block (in which we'll insert the tagging).
    Block* new_block = __ NewBlock();
    const GotoOp& old_goto =
        old_block->LastOperation(__ output_graph()).Cast<GotoOp>();
    DCHECK_EQ(old_goto.destination, turboshaft_catch_handler);
    __ output_graph().Replace<GotoOp>(__ output_graph().Index(old_goto),
                                      new_block, /* is_backedge */ false);
    __ AddPredecessor(old_block, new_block, false);

    // Now, we bind the new block and insert the taggings
    __ BindReachable(new_block);
    InsertTaggingForPhis(maglev_catch_handler);

    // Finally, we just go from this block to the catch handler.
    __ Goto(turboshaft_catch_handler);
  }

  void EmitLoopSinglePredecessorBlock(maglev::BasicBlock* maglev_loop_header) {
    DCHECK(maglev_loop_header->is_loop());

    bool has_special_generator_handling = false;
    V<Word32> switch_var_first_input;
    if (pre_loop_generator_blocks_.contains(maglev_loop_header)) {
      // This loop header used to be bypassed by generator resume edges. It will
      // now act as a secondary switch for the generator resumes.
      std::vector<GeneratorSplitEdge>& generator_preds =
          pre_loop_generator_blocks_[maglev_loop_header];
      // {generator_preds} contains all of the edges that were bypassing this
      // loop header. Rather than adding that many predecessors to the loop
      // header, will create a single predecessor, {pred_for_generator}, to
      // which all of the edges of {generator_preds} will go.
      Block* pred_for_generator = __ NewBlock();

      for (GeneratorSplitEdge pred : generator_preds) {
        __ Bind(pred.pre_loop_dst);
        __ SetVariable(header_switch_input_,
                       __ Word32Constant(pred.switch_value));
        __ Goto(pred_for_generator);
      }

      __ Bind(pred_for_generator);
      switch_var_first_input = __ GetVariable(header_switch_input_);
      DCHECK(switch_var_first_input.valid());

      BuildJump(maglev_loop_header);

      has_special_generator_handling = true;
      on_generator_switch_loop_ = true;
    }

    DCHECK(loop_single_edge_predecessors_.contains(maglev_loop_header));
    Block* loop_pred = loop_single_edge_predecessors_[maglev_loop_header];
    __ Bind(loop_pred);

    if (maglev_loop_header->has_phi()) {
      ComputePredecessorPermutations(maglev_loop_header, loop_pred, true,
                                     has_special_generator_handling);

      // Now we need to emit Phis (one per loop phi in {block}, which should
      // contain the same input except for the backedge).
      loop_phis_first_input_.clear();
      loop_phis_first_input_index_ = 0;
      for (maglev::Phi* phi : *maglev_loop_header->phis()) {
        constexpr int kSkipBackedge = 1;
        int input_count = phi->input_count() - kSkipBackedge;

        if (has_special_generator_handling) {
          // Adding an input to the Phis to account for the additional
          // generator-related predecessor.
          V<Any> additional_input;
          switch (phi->value_representation()) {
            case maglev::ValueRepresentation::kTagged:
              additional_input = dummy_object_input_;
              break;
            case maglev::ValueRepresentation::kInt32:
            case maglev::ValueRepresentation::kUint32:
              additional_input = dummy_word32_input_;
              break;
            case maglev::ValueRepresentation::kFloat64:
            case maglev::ValueRepresentation::kHoleyFloat64:
              additional_input = dummy_float64_input_;
              break;
            case maglev::ValueRepresentation::kIntPtr:
              // Maglev doesn't have IntPtr Phis.
              UNREACHABLE();
          }
          loop_phis_first_input_.push_back(
              MakePhiMaybePermuteInputs(phi, input_count, additional_input));
        } else {
          loop_phis_first_input_.push_back(
              MakePhiMaybePermuteInputs(phi, input_count));
        }
      }
    }

    if (has_special_generator_handling) {
      // We now emit the Phi that will be used in the loop's main switch.
      base::SmallVector<OpIndex, 16> inputs;
      constexpr int kSkipGeneratorPredecessor = 1;

      // We insert a default input for all of the non-generator predecessor.
      int input_count_without_generator =
          loop_pred->PredecessorCount() - kSkipGeneratorPredecessor;
      DCHECK(loop_default_generator_value_.valid());
      inputs.insert(inputs.begin(), input_count_without_generator,
                    loop_default_generator_value_);

      // And we insert the "true" input for the generator predecessor (which is
      // {pred_for_generator} above).
      DCHECK(switch_var_first_input.valid());
      inputs.push_back(switch_var_first_input);

      __ SetVariable(
          header_switch_input_,
          __ Phi(base::VectorOf(inputs), RegisterRepresentation::Word32()));
    }

    // Actually jumping to the loop.
    __ Goto(Map(maglev_loop_header));
  }

  void PostPhiProcessing() {
    // Loop headers that are bypassed because of generators need to be turned
    // into secondary generator switches (so as to not be bypassed anymore).
    // Concretely, we split the loop headers in half by inserting a Switch right
    // after the loop phis have been emitted. Here is a visual representation of
    // what's happening:
    //
    // Before:
    //
    //              |         ----------------------------
    //              |         |                          |
    //              |         |                          |
    //              v         v                          |
    //      +------------------------+                   |
    //      | phi_1(...)             |                   |
    //      | ...                    |                   |
    //      | phi_k(...)             |                   |
    //      | <some op 1>            |                   |
    //      | ...                    |                   |
    //      | <some op n>            |                   |
    //      | Branch                 |                   |
    //      +------------------------+                   |
    //                 |                                 |
    //                 |                                 |
    //                 v                                 |
    //
    //
    // After:
    //
    //
    //              |         -----------------------------------
    //              |         |                                 |
    //              |         |                                 |
    //              v         v                                 |
    //      +------------------------+                          |
    //      | phi_1(...)             |                          |
    //      | ...                    |                          |
    //      | phi_k(...)             |                          |
    //      | Switch                 |                          |
    //      +------------------------+                          |
    //        /   |     |      \                                |
    //       /    |     |       \                               |
    //      /     |     |        \                              |
    //     v      v     v         v                             |
    //                        +------------------+              |
    //                        | <some op 1>      |              |
    //                        | ...              |              |
    //                        | <some op n>      |              |
    //                        | Branch           |              |
    //                        +------------------+              |
    //                                 |                        |
    //                                 |                        |
    //                                 v                        |
    //
    //
    // Since `PostPhiProcessing` is called right after all phis have been
    // emitted, now is thus the time to split the loop header.

    if (on_generator_switch_loop_) {
      const maglev::BasicBlock* maglev_loop_header = __ maglev_input_block();
      DCHECK(maglev_loop_header->is_loop());
      std::vector<GeneratorSplitEdge>& generator_preds =
          pre_loop_generator_blocks_[maglev_loop_header];

      compiler::turboshaft::SwitchOp::Case* cases =
          __ output_graph().graph_zone()
              -> AllocateArray<compiler::turboshaft::SwitchOp::Case>(
                               generator_preds.size());

      for (int i = 0; static_cast<unsigned int>(i) < generator_preds.size();
           i++) {
        GeneratorSplitEdge pred = generator_preds[i];
        cases[i] = {pred.switch_value, pred.inside_loop_target,
                    BranchHint::kNone};
      }
      Block* default_block = __ NewBlock();
      __ Switch(__ GetVariable(header_switch_input_),
                base::VectorOf(cases, generator_preds.size()), default_block);

      // We now bind {default_block}. It will contain the rest of the loop
      // header. The MaglevGraphProcessor will continue to visit the header's
      // body as if nothing happened.
      __ Bind(default_block);
    }
    on_generator_switch_loop_ = false;
  }

  maglev::ProcessResult Process(maglev::Constant* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, __ HeapConstant(node->object().object()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::RootConstant* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, __ HeapConstant(MakeRef(broker_, node->DoReify(local_isolate_))
                                     .AsHeapObject()
                                     .object()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::Int32Constant* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, __ Word32Constant(node->value()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::Uint32Constant* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, __ Word32SignHintUnsigned(__ Word32Constant(node->value())));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::Float64Constant* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, __ Float64Constant(node->value()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::SmiConstant* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, __ SmiConstant(node->value()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::TaggedIndexConstant* node,
                                const maglev::ProcessingState& state) {
    // TODO(dmercadier): should this really be a SmiConstant, or rather a
    // Word32Constant?
    SetMap(node, __ SmiConstant(node->value().ptr()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::TrustedConstant* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, __ TrustedHeapConstant(node->object().object()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::InitialValue* node,
                                const maglev::ProcessingState& state) {
    // TODO(dmercadier): InitialValues are much simpler in Maglev because they
    // are mapped directly to interpreter registers, whereas Turbofan changes
    // the indices, making everything more complex. We should try to have the
    // same InitialValues in Turboshaft as in Maglev, in order to simplify
    // things.
#ifdef DEBUG
    // We cannot use strdup or something that simple for {debug_name}, because
    // it has to be zone allocated rather than heap-allocated, since it won't be
    // freed and this would thus cause a leak.
    std::string reg_string_name = node->source().ToString();
    base::Vector<char> debug_name_arr =
        graph_zone()->NewVector<char>(reg_string_name.length() + /* \n */ 1);
    snprintf(debug_name_arr.data(), debug_name_arr.length(), "%s",
             reg_string_name.c_str());
    char* debug_name = debug_name_arr.data();
#else
    char* debug_name = nullptr;
#endif
    interpreter::Register source = node->source();
    V<Object> value;
    if (source.is_function_closure()) {
      // The function closure is a Parameter rather than an OsrValue even when
      // OSR-compiling.
      value = __ Parameter(Linkage::kJSCallClosureParamIndex,
                           RegisterRepresentation::Tagged(), debug_name);
    } else if (maglev_compilation_unit_->is_osr()) {
      int index;
      if (source.is_current_context()) {
        index = Linkage::kOsrContextSpillSlotIndex;
      } else if (source == interpreter::Register::virtual_accumulator()) {
        index = Linkage::kOsrAccumulatorRegisterIndex;
      } else if (source.is_parameter()) {
        index = source.ToParameterIndex();
      } else {
        // For registers, recreate the index computed by FillWithOsrValues in
        // BytecodeGraphBuilder.
        index = source.index() + InterpreterFrameConstants::kExtraSlotCount +
                maglev_compilation_unit_->parameter_count();
      }
      value = __ OsrValue(index);
    } else {
      int index = source.ToParameterIndex();
      if (source.is_current_context()) {
        index = Linkage::GetJSCallContextParamIndex(
            maglev_compilation_unit_->parameter_count());
      } else {
        index = source.ToParameterIndex();
      }
      value = __ Parameter(index, RegisterRepresentation::Tagged(), debug_name);
    }
    SetMap(node, value);
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::RegisterInput* node,
                                const maglev::ProcessingState& state) {
    DCHECK(maglev_compilation_unit_->bytecode()
               .incoming_new_target_or_generator_register()
               .is_valid());
    DCHECK_EQ(node->input(), kJavaScriptCallNewTargetRegister);
    DCHECK(new_target_param_.valid());
    SetMap(node, new_target_param_);
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::FunctionEntryStackCheck* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());
    __ JSFunctionEntryStackCheck(native_context(), frame_state);
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::Phi* node,
                                const maglev::ProcessingState& state) {
    int input_count = node->input_count();
    RegisterRepresentation rep =
        RegisterRepresentationFor(node->value_representation());
    if (node->is_exception_phi()) {
      if (node->owner() == interpreter::Register::virtual_accumulator()) {
        DCHECK(catch_block_begin_.valid());
        SetMap(node, catch_block_begin_);
      } else {
        Variable var = regs_to_vars_[node->owner().index()];
        SetMap(node, __ GetVariable(var));
        // {var} won't be used anymore once we've created the mapping from
        // {node} to its value. We thus reset it, in order to avoid Phis being
        // created for {var} at later merge points.
        __ SetVariable(var, V<Object>::Invalid());
      }
      return maglev::ProcessResult::kContinue;
    }
    if (__ current_block()->IsLoop()) {
      DCHECK(state.block()->is_loop());
      OpIndex first_phi_input;
      if (state.block()->predecessor_count() > 2 ||
          generator_analyzer_.HeaderIsBypassed(state.block())) {
        // This loop has multiple forward edges in Maglev, so we should have
        // created an intermediate block in Turboshaft, which will be the only
        // predecessor of the Turboshaft loop, and from which we'll find the
        // first input for this loop phi.
        DCHECK_EQ(loop_phis_first_input_.size(),
                  static_cast<size_t>(state.block()->phis()->LengthForTest()));
        DCHECK_GE(loop_phis_first_input_index_, 0);
        DCHECK_LT(loop_phis_first_input_index_, loop_phis_first_input_.size());
        DCHECK(loop_single_edge_predecessors_.contains(state.block()));
        DCHECK_EQ(loop_single_edge_predecessors_[state.block()],
                  __ current_block()->LastPredecessor());
        first_phi_input = loop_phis_first_input_[loop_phis_first_input_index_];
        loop_phis_first_input_index_++;
      } else {
        DCHECK_EQ(input_count, 2);
        DCHECK_EQ(state.block()->predecessor_count(), 2);
        DCHECK(loop_phis_first_input_.empty());
        first_phi_input = Map(node->input(0));
      }
      SetMap(node, __ PendingLoopPhi(first_phi_input, rep));
    } else {
      SetMap(node, MakePhiMaybePermuteInputs(node, input_count));
    }
    return maglev::ProcessResult::kContinue;
  }

  V<Any> MakePhiMaybePermuteInputs(
      maglev::ValueNode* maglev_node, int maglev_input_count,
      OptionalV<Any> additional_input = OptionalV<Any>::Nullopt()) {
    DCHECK(!predecessor_permutation_.empty());

    base::SmallVector<OpIndex, 16> inputs;
    // Note that it's important to use `current_block()->PredecessorCount()` as
    // the size of {inputs}, because some Maglev predecessors could have been
    // dropped by Turboshaft during the translation (and thus, `input_count`
    // might be too much).
    inputs.resize_and_init(__ current_block()->PredecessorCount());
    for (int i = 0; i < maglev_input_count; ++i) {
      if (predecessor_permutation_[i] != Block::kInvalidPredecessorIndex) {
        inputs[predecessor_permutation_[i]] =
            MapPhiInput(maglev_node->input(i), predecessor_permutation_[i]);
      }
    }

    if (additional_input.has_value()) {
      // When a loop header was bypassed by a generator resume, we insert an
      // additional predecessor to the loop, and thus need an additional input
      // for the Phis.
      inputs[inputs.size() - 1] = additional_input.value();
    }

    return __ Phi(
        base::VectorOf(inputs),
        RegisterRepresentationFor(maglev_node->value_representation()));
  }

  maglev::ProcessResult Process(maglev::Call* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());
    V<Object> function = Map(node->function());
    V<Context> context = Map(node->context());

    Builtin builtin;
    switch (node->target_type()) {
      case maglev::Call::TargetType::kAny:
        switch (node->receiver_mode()) {
          case ConvertReceiverMode::kNullOrUndefined:
            builtin = Builtin::kCall_ReceiverIsNullOrUndefined;
            break;
          case ConvertReceiverMode::kNotNullOrUndefined:
            builtin = Builtin::kCall_ReceiverIsNotNullOrUndefined;
            break;
          case ConvertReceiverMode::kAny:
            builtin = Builtin::kCall_ReceiverIsAny;
            break;
        }
        break;
      case maglev::Call::TargetType::kJSFunction:
        switch (node->receiver_mode()) {
          case ConvertReceiverMode::kNullOrUndefined:
            builtin = Builtin::kCallFunction_ReceiverIsNullOrUndefined;
            break;
          case ConvertReceiverMode::kNotNullOrUndefined:
            builtin = Builtin::kCallFunction_ReceiverIsNotNullOrUndefined;
            break;
          case ConvertReceiverMode::kAny:
            builtin = Builtin::kCallFunction_ReceiverIsAny;
            break;
        }
        break;
    }

    base::SmallVector<OpIndex, 16> arguments;
    arguments.push_back(function);
    arguments.push_back(__ Word32Constant(node->num_args()));
    for (auto arg : node->args()) {
      arguments.push_back(Map(arg));
    }
    arguments.push_back(context);

    GENERATE_AND_MAP_BUILTIN_CALL(node, builtin, frame_state,
                                  base::VectorOf(arguments), node->num_args());

    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CallKnownJSFunction* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());
    V<Object> callee = Map(node->closure());
    int actual_parameter_count = JSParameterCount(node->num_args());

    if (node->shared_function_info().HasBuiltinId()) {
      // Note that there is no need for a ThrowingScope here:
      // GenerateBuiltinCall takes care of creating one.
      base::SmallVector<OpIndex, 16> arguments;
      arguments.push_back(callee);
      arguments.push_back(Map(node->new_target()));
      arguments.push_back(__ Word32Constant(actual_parameter_count));
#ifdef V8_ENABLE_LEAPTIERING
      arguments.push_back(__ Word32Constant(kPlaceholderDispatchHandle));
#endif
      arguments.push_back(Map(node->receiver()));
      for (int i = 0; i < node->num_args(); i++) {
        arguments.push_back(Map(node->arg(i)));
      }
      // Setting missing arguments to Undefined.
      for (int i = actual_parameter_count; i < node->expected_parameter_count();
           i++) {
        arguments.push_back(__ HeapConstant(local_factory_->undefined_value()));
      }
      arguments.push_back(Map(node->context()));
      GENERATE_AND_MAP_BUILTIN_CALL(
          node, node->shared_function_info().builtin_id(), frame_state,
          base::VectorOf(arguments),
          std::max<int>(actual_parameter_count,
                        node->expected_parameter_count()));
    } else {
      ThrowingScope throwing_scope(this, node);
      base::SmallVector<OpIndex, 16> arguments;
      arguments.push_back(Map(node->receiver()));
      for (int i = 0; i < node->num_args(); i++) {
        arguments.push_back(Map(node->arg(i)));
      }
      // Setting missing arguments to Undefined.
      for (int i = actual_parameter_count; i < node->expected_parameter_count();
           i++) {
        arguments.push_back(__ HeapConstant(local_factory_->undefined_value()));
      }
      arguments.push_back(Map(node->new_target()));
      arguments.push_back(__ Word32Constant(actual_parameter_count));
#ifdef V8_ENABLE_LEAPTIERING
      arguments.push_back(__ Word32Constant(kPlaceholderDispatchHandle));
#endif

      // Load the context from {callee}.
      OpIndex context =
          __ LoadField(callee, AccessBuilder::ForJSFunctionContext());
      arguments.push_back(context);

      const CallDescriptor* descriptor = Linkage::GetJSCallDescriptor(
          graph_zone(), false,
          std::max<int>(actual_parameter_count,
                        node->expected_parameter_count()),
          CallDescriptor::kNeedsFrameState | CallDescriptor::kCanUseRoots);

      LazyDeoptOnThrow lazy_deopt_on_throw = ShouldLazyDeoptOnThrow(node);

      BAILOUT_IF_TOO_MANY_ARGUMENTS_FOR_CALL(arguments.size());
      SetMap(node, __ Call(V<CallTarget>::Cast(callee), frame_state,
                           base::VectorOf(arguments),
                           TSCallDescriptor::Create(descriptor, CanThrow::kYes,
                                                    lazy_deopt_on_throw,
                                                    graph_zone())));
    }

    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CallKnownApiFunction* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());

    if (node->inline_builtin()) {
      DCHECK(v8_flags.maglev_inline_api_calls);
      // TODO(dmercadier, 40912714, 42203760): The flag maglev_inline_api_calls
      // is currently experimental, and it's not clear at this point if it will
      // even become non-experimental, so we currently don't support it in the
      // Maglev->Turboshaft translation. Note that a quick-fix would be to treat
      // kNoProfilingInlined like kNoProfiling, although this would be slower
      // than desired.
      UNIMPLEMENTED();
    }

    OpIndex api_holder;
    if (node->api_holder().has_value()) {
      api_holder = __ HeapConstant(node->api_holder().value().object());
    } else {
      api_holder = Map(node->receiver());
    }

    V<Object> target =
        __ HeapConstant(node->function_template_info().AsHeapObject().object());

    ApiFunction function(node->function_template_info().callback(broker_));
    ExternalReference function_ref = ExternalReference::Create(
        &function, ExternalReference::DIRECT_API_CALL);

    base::SmallVector<OpIndex, 16> arguments;
    arguments.push_back(__ ExternalConstant(function_ref));
    arguments.push_back(__ Word32Constant(node->num_args()));
    arguments.push_back(target);
    arguments.push_back(api_holder);
    arguments.push_back(Map(node->receiver()));
    for (maglev::Input arg : node->args()) {
      arguments.push_back(Map(arg));
    }
    arguments.push_back(Map(node->context()));

    Builtin builtin;
    switch (node->mode()) {
      case maglev::CallKnownApiFunction::Mode::kNoProfiling:
        builtin = Builtin::kCallApiCallbackOptimizedNoProfiling;
        break;
      case maglev::CallKnownApiFunction::Mode::kNoProfilingInlined:
        // Handled earlier when checking `node->inline_builtin()`.
        UNREACHABLE();
      case maglev::CallKnownApiFunction::Mode::kGeneric:
        builtin = Builtin::kCallApiCallbackOptimized;
        break;
    }

    int stack_arg_count = node->num_args() + /* implicit receiver */ 1;
    GENERATE_AND_MAP_BUILTIN_CALL(node, builtin, frame_state,
                                  base::VectorOf(arguments), stack_arg_count);

    return maglev::ProcessResult::kContinue;
  }
  V<Any> GenerateBuiltinCall(
      maglev::NodeBase* node, Builtin builtin,
      OptionalV<FrameState> frame_state, base::Vector<const OpIndex> arguments,
      std::optional<int> stack_arg_count = std::nullopt) {
    ThrowingScope throwing_scope(this, node);
    DCHECK(!TooManyArgumentsForCall(arguments.size()));

    Callable callable = Builtins::CallableFor(isolate_, builtin);
    const CallInterfaceDescriptor& descriptor = callable.descriptor();
    CallDescriptor* call_descriptor = Linkage::GetStubCallDescriptor(
        graph_zone(), descriptor,
        stack_arg_count.has_value() ? stack_arg_count.value()
                                    : descriptor.GetStackParameterCount(),
        frame_state.valid() ? CallDescriptor::kNeedsFrameState
                            : CallDescriptor::kNoFlags);
    V<Code> stub_code = __ HeapConstant(callable.code());

    LazyDeoptOnThrow lazy_deopt_on_throw = ShouldLazyDeoptOnThrow(node);

    return __ Call(stub_code, frame_state, base::VectorOf(arguments),
                   TSCallDescriptor::Create(call_descriptor, CanThrow::kYes,
                                            lazy_deopt_on_throw, graph_zone()));
  }
  maglev::ProcessResult Process(maglev::CallBuiltin* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deop
```