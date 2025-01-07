Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Identify the Core Purpose:** The file name `loop-unrolling-reducer.h` immediately suggests its main function: reducing loops by unrolling them. The comments at the top reinforce this. The terms "fully unrolls," "partially unrolls," and "remove loops" are key indicators.

2. **Understand the Context (V8, Turboshaft):** The directory `v8/src/compiler/turboshaft/` tells us this is part of the V8 JavaScript engine's Turboshaft compiler pipeline. This means the code deals with optimizing JavaScript code during compilation.

3. **Analyze the Key Classes:**
    * **`IterationCount`:** This class clearly represents the number of times a loop iterates. The `Kind` enum (`kExact`, `kApprox`, `kUnknown`) is important. It tells us about the certainty of the iteration count. Methods like `IsExact`, `IsSmallerThan` provide ways to query this information.
    * **`StaticCanonicalForLoopMatcher`:** The name and comments reveal its purpose: identifying simple, "canonical" `for` loops where the iteration count can be determined statically. The `GetIterCountIfStaticCanonicalForLoop` method is the core function. The nested `CmpOp` and `BinOp` enums define the supported comparison and binary operations within these loops.
    * **`LoopUnrollingAnalyzer`:** This class is responsible for analyzing the graph of operations and deciding *which* loops to unroll and *how*. It uses the `StaticCanonicalForLoopMatcher` to determine iteration counts. The methods like `ShouldFullyUnrollLoop`, `ShouldPartiallyUnrollLoop`, and `ShouldRemoveLoop` are the decision-making functions.
    * **`LoopStackCheckElisionReducer`:**  This reducer focuses on removing redundant stack checks within loops, especially after unrolling.
    * **`LoopUnrollingReducer`:** This is the main reducer class. It implements the actual loop unrolling logic, using the information provided by the `LoopUnrollingAnalyzer`. The `REDUCE_INPUT_GRAPH` methods for `Goto` and `Branch` are central to this process.

4. **Trace the Workflow:**  Even without seeing the `.cc` file, we can infer the flow:
    * The `LoopUnrollingAnalyzer` analyzes the graph.
    * The `LoopUnrollingReducer` iterates through the graph.
    * When it encounters a loop header (via a `GotoOp`), it consults the `LoopUnrollingAnalyzer`.
    * Based on the analyzer's decision, it either:
        * Removes the loop (`RemoveLoop`).
        * Fully unrolls the loop (`FullyUnrollLoop`).
        * Partially unrolls the loop (`PartiallyUnrollLoop`).
    * The `LoopStackCheckElisionReducer` runs later to clean up stack checks.

5. **Connect to JavaScript:**  The core idea of loop unrolling is a common optimization technique. Think about how it would affect JavaScript code. Simple `for` loops are the prime candidates.

6. **Consider Edge Cases and Potential Issues:**  Loop unrolling can increase code size. There are limits on how much to unroll. Stack checks are related to preventing stack overflow errors. Removing them requires careful analysis.

7. **Address Specific Instructions:**
    * **Functionality Listing:**  Summarize the roles of each key component.
    * **Torque:** Check the file extension (`.h` vs. `.tq`). This is straightforward.
    * **JavaScript Example:**  Create a simple JavaScript loop that would be a good candidate for unrolling. Show the *effect* of unrolling conceptually.
    * **Code Logic Inference:**  Focus on a simple case (e.g., a fully unrolled loop). Provide clear input (the original loop) and the expected output (the unrolled sequence).
    * **Common Programming Errors:** Think about how incorrect loop conditions or off-by-one errors could affect the unrolling process or introduce bugs in the optimized code.

8. **Refine and Structure:**  Organize the information clearly with headings and bullet points. Use precise language. Explain the "why" behind the code, not just the "what."

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the `StaticCanonicalForLoopMatcher` is more general. **Correction:** The comments explicitly state it's loop-unrolling specific, though parts *could* be moved.
* **Initial thought:** Focus solely on the `LoopUnrollingReducer`. **Correction:**  Realize the importance of the `LoopUnrollingAnalyzer` in making decisions.
* **Initial thought:**  Just describe *what* the code does. **Correction:** Explain *why* these optimizations are important for performance.
* **Initial thought:** The JavaScript example should be complex. **Correction:** Keep it simple and illustrate the core concept of repetition removal.
* **Initial thought:**  Only consider successful unrolling. **Correction:** Think about edge cases and potential problems that could arise.
这是一个V8 Turboshaft 编译器的源代码文件，名为 `loop-unrolling-reducer.h`。它定义了一个用于循环展开优化的编译器阶段。

**功能列表:**

1. **循环展开 (Loop Unrolling):** 这是该文件的核心功能。它旨在通过展开循环体来减少循环的开销，从而提高代码执行效率。循环展开包括：
   - **完全展开 (Full Unrolling):**  对于迭代次数在编译时可计算且较小的循环，将循环体重复插入，消除循环结构。
   - **部分展开 (Partial Unrolling):** 对于其他小型内部循环，展开部分迭代，以减少循环开销，同时避免代码过度膨胀。
   - **移除零迭代循环 (Removing Zero-Iteration Loops):**  检测并移除在编译时确定迭代次数为 0 的循环。

2. **静态规范 For 循环匹配 (Static Canonical For Loop Matching):**  识别特定形式的 `for` 循环，例如 `for (let i = cst; i cmp cst; i = i binop cst)`，其中初始值、比较条件和递增/递减操作都涉及常量，以便静态计算迭代次数。

3. **循环分析 (Loop Analysis):** 分析程序图中的循环结构，特别是判断内部循环是否具有固定的（已知的）迭代次数。

4. **栈检查消除 (Stack Check Elision):** 作为循环展开的辅助功能，可以移除某些循环中的栈溢出检查，特别是对于迭代次数较少的循环，因为展开后循环执行的次数减少，发生栈溢出的风险也降低。

**关于文件类型:**

`v8/src/compiler/turboshaft/loop-unrolling-reducer.h` 以 `.h` 结尾，这是一个标准的 C++ 头文件，用于声明类、函数和其他实体。如果它以 `.tq` 结尾，那才是 V8 Torque 源代码。Torque 是一种 V8 使用的领域特定语言，用于定义内置函数和类型。

**与 JavaScript 的关系 (以及 JavaScript 示例):**

循环展开是一种常见的编译器优化技术，可以显著提高 JavaScript 代码的性能，尤其是在处理数组或执行重复性任务时。

**JavaScript 示例:**

假设有以下 JavaScript 代码：

```javascript
let sum = 0;
for (let i = 0; i < 3; i++) {
  sum += i;
}
console.log(sum); // 输出 3
```

`LoopUnrollingReducer` 可能会将这个循环完全展开成类似下面的形式：

```javascript
let sum = 0;
sum += 0;
sum += 1;
sum += 2;
console.log(sum);
```

这样做的好处是消除了循环的控制开销（例如，每次迭代的条件判断和变量递增），从而提高执行速度。

再看一个部分展开的例子：

```javascript
let arr = [1, 2, 3, 4, 5, 6, 7, 8];
for (let i = 0; i < arr.length; i++) {
  console.log(arr[i]);
}
```

`LoopUnrollingReducer` 可能会将这个循环部分展开，例如展开 2 次：

```javascript
let arr = [1, 2, 3, 4, 5, 6, 7, 8];
for (let i = 0; i < arr.length; i += 2) {
  console.log(arr[i]);
  if (i + 1 < arr.length) {
    console.log(arr[i + 1]);
  }
}
```

部分展开可以在一定程度上减少循环开销，同时控制代码大小的增长。

**代码逻辑推理 (假设输入与输出):**

假设 `LoopUnrollingAnalyzer` 分析了一个简单的 for 循环：

**假设输入 (Turboshaft IR 中的表示，简化概念):**

```
Block[B1]: // 循环头
  Phi(i_prev: int) -> i: int
  LessThan(i, 3) -> cond: bool
  Branch(cond, B2, B3)

Block[B2]: // 循环体
  // ... 一些操作 ...
  Add(i, 1) -> next_i: int
  Goto(B1, next_i)

Block[B3]: // 循环出口
  // ... 后续操作 ...
```

**预期输出 (如果完全展开):**

```
Block[B4]: // 展开后的代码
  Const(0) -> i0: int
  // ... 循环体第一次迭代的操作，将 i 替换为 0 ...
  Const(1) -> i1: int
  // ... 循环体第二次迭代的操作，将 i 替换为 1 ...
  Const(2) -> i2: int
  // ... 循环体第三次迭代的操作，将 i 替换为 2 ...
  Goto(B3) // 跳转到原来的循环出口
```

在这个例子中，循环被完全展开，`Phi` 节点被消除，循环头和循环体的操作被复制并内联。

**用户常见的编程错误:**

循环展开作为编译器优化，通常对用户是透明的。但是，某些编程习惯可能会影响循环展开的效果，或者在某些极端情况下，如果编译器对循环的分析不准确，可能会导致意想不到的结果（虽然这种情况非常罕见）。

1. **循环体过于复杂:** 如果循环体包含大量的操作或者复杂的控制流（例如，大量的 `if` 语句或嵌套循环），完全展开可能会导致代码膨胀，甚至降低性能。编译器通常会限制展开的程度。

2. **循环依赖复杂的外部状态:** 如果循环的迭代依赖于难以在编译时预测的外部状态，编译器可能无法安全地进行展开。

3. **人为的“手动展开”:** 有些程序员可能会尝试手动展开循环以提高性能。现代编译器通常比手动展开做得更好，并且手动展开会使代码难以阅读和维护。编译器可以更智能地处理寄存器分配、指令调度等问题。

**示例：可能影响展开的 JavaScript 错误**

虽然不是直接的编程错误，但某些模式会阻止或限制循环展开：

```javascript
let arr = [];
let n = Math.random() * 10; // n 的值在运行时才能确定
for (let i = 0; i < n; i++) {
  arr.push(i);
}
```

在这个例子中，循环的迭代次数 `n` 在编译时是未知的，因此编译器无法进行完全展开。

**涉及用户常见的编程错误 (更直接的例子):**

考虑一个由于循环条件错误可能导致无限循环的情况：

```javascript
let i = 0;
while (i < 10) {
  // 注意：这里缺少 i 的递增，导致无限循环
  console.log(i);
}
```

虽然 `LoopUnrollingReducer` 的主要目标不是修复这种错误，但在某些情况下，如果编译器能够分析出循环永远不会终止，它可能会采取不同的优化策略，或者根本不进行优化，因为它已经进入了无法终止的状态。更准确地说，循环展开通常是在循环能够被安全分析的前提下进行的。

总结来说，`v8/src/compiler/turboshaft/loop-unrolling-reducer.h` 定义了 V8 编译器中一个重要的优化阶段，专注于通过展开循环来提高 JavaScript 代码的执行效率。它涉及到静态分析、模式匹配和代码转换等复杂的操作。

Prompt: 
```
这是目录为v8/src/compiler/turboshaft/loop-unrolling-reducer.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/loop-unrolling-reducer.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMPILER_TURBOSHAFT_LOOP_UNROLLING_REDUCER_H_
#define V8_COMPILER_TURBOSHAFT_LOOP_UNROLLING_REDUCER_H_

#include <optional>

#include "src/base/logging.h"
#include "src/compiler/globals.h"
#include "src/compiler/turboshaft/assembler.h"
#include "src/compiler/turboshaft/copying-phase.h"
#include "src/compiler/turboshaft/index.h"
#include "src/compiler/turboshaft/loop-finder.h"
#include "src/compiler/turboshaft/machine-optimization-reducer.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/phase.h"

namespace v8::internal::compiler::turboshaft {

#include "src/compiler/turboshaft/define-assembler-macros.inc"

// OVERVIEW:
//
// LoopUnrollingReducer fully unrolls small inner loops with a small
// statically-computable number of iterations, partially unrolls other small
// inner loops, and remove loops that we detect as always having 0 iterations.

#ifdef DEBUG
#define TRACE(x)                                                               \
  do {                                                                         \
    if (v8_flags.turboshaft_trace_unrolling) StdoutStream() << x << std::endl; \
  } while (false)
#else
#define TRACE(x)
#endif

class IterationCount {
  enum class Kind { kExact, kApprox, kUnknown };

 public:
  // Loops with an exact number of iteration could be unrolled.
  static IterationCount Exact(size_t count) {
    return IterationCount(Kind::kExact, count);
  }
  // We can remove stack checks from loops with a small number of iterations.
  static IterationCount Approx(size_t count) {
    return IterationCount(Kind::kApprox, count);
  }
  static IterationCount Unknown() { return IterationCount(Kind::kUnknown); }

  IterationCount() : kind_(Kind::kUnknown) {}
  explicit IterationCount(Kind kind) : kind_(kind) {
    DCHECK_NE(kind, Kind::kExact);
  }
  IterationCount(Kind kind, size_t count) : kind_(kind), count_(count) {
    DCHECK_EQ(kind, any_of(Kind::kExact, Kind::kApprox));
  }

  size_t exact_count() const {
    DCHECK_EQ(kind_, Kind::kExact);
    return count_;
  }

  bool IsExact() const { return kind_ == Kind::kExact; }
  bool IsApprox() const { return kind_ == Kind::kApprox; }
  bool IsUnknown() const { return kind_ == Kind::kUnknown; }

  bool IsSmallerThan(size_t max) {
    return (IsExact() || IsApprox()) && count_ < max;
  }

 private:
  Kind kind_;
  size_t count_;
};
std::ostream& operator<<(std::ostream& os, const IterationCount& count);

class V8_EXPORT_PRIVATE StaticCanonicalForLoopMatcher {
  // In the context of this class, a "static canonical for-loop" is one of the
  // form `for (let i = cst; i cmp cst; i = i binop cst)`. That is, a fairly
  // simple for-loop, for which we can statically compute the number of
  // iterations.
  //
  // There is an added constraint that this class can only match loops with few
  // iterations (controlled by the `max_iter_` parameter), for performance
  // reasons (because it's a bit tricky to compute how many iterations a loop
  // has, see the `HasFewerIterationsThan` method).
  //
  // This class and its methods are not in OperationMatcher, even though they
  // could fit there, because they seemed a bit too loop-unrolling specific.
  // However, if they can ever be useful for something else, any of the
  // "MatchXXX" method of this class could be moved to OperationMatcher.
 public:
  explicit StaticCanonicalForLoopMatcher(const OperationMatcher& matcher)
      : matcher_(matcher) {}

  IterationCount GetIterCountIfStaticCanonicalForLoop(
      const Block* header, OpIndex cond_idx, bool loop_if_cond_is) const;

  enum class CmpOp {
    kEqual,
    kSignedLessThan,
    kSignedLessThanOrEqual,
    kUnsignedLessThan,
    kUnsignedLessThanOrEqual,
    kSignedGreaterThan,
    kSignedGreaterThanOrEqual,
    kUnsignedGreaterThan,
    kUnsignedGreaterThanOrEqual,
  };
  static constexpr CmpOp ComparisonKindToCmpOp(ComparisonOp::Kind kind);
  static constexpr CmpOp InvertComparisonOp(CmpOp op);
  enum class BinOp {
    kAdd,
    kMul,
    kSub,
    kBitwiseAnd,
    kBitwiseOr,
    kBitwiseXor,
    kOverflowCheckedAdd,
    kOverflowCheckedMul,
    kOverflowCheckedSub
  };
  static constexpr BinOp BinopFromWordBinopKind(WordBinopOp::Kind kind);
  static constexpr BinOp BinopFromOverflowCheckedBinopKind(
      OverflowCheckedBinopOp::Kind kind);
  static constexpr bool BinopKindIsSupported(WordBinopOp::Kind binop_kind);

 private:
  bool MatchPhiCompareCst(OpIndex cond_idx,
                          StaticCanonicalForLoopMatcher::CmpOp* cmp_op,
                          OpIndex* phi, uint64_t* cst) const;
  bool MatchCheckedOverflowBinop(OpIndex idx, V<Word>* left, V<Word>* right,
                                 BinOp* binop_op,
                                 WordRepresentation* binop_rep) const;
  bool MatchWordBinop(OpIndex idx, V<Word>* left, V<Word>* right,
                      BinOp* binop_op, WordRepresentation* binop_rep) const;
  IterationCount CountIterations(uint64_t equal_cst, CmpOp cmp_op,
                                 uint64_t initial_input, uint64_t binop_cst,
                                 BinOp binop_op, WordRepresentation binop_rep,
                                 bool loop_if_cond_is) const;
  template <class Int>
  IterationCount CountIterationsImpl(
      Int init, Int max, CmpOp cmp_op, Int binop_cst,
      StaticCanonicalForLoopMatcher::BinOp binop_op,
      WordRepresentation binop_rep, bool loop_if_cond_is) const;

  const OperationMatcher& matcher_;

  // When trying to compute the number of iterations of a loop, we simulate the
  // first {kMaxExactIter} iterations of the loop, and check if the loop ends
  // during these first few iterations. This is slightly inneficient, hence the
  // small value for {kMaxExactIter}, but it's simpler than using a formula to
  // compute the number of iterations (in particular because of overflows).
  static constexpr size_t kMaxExactIter = 5;
};
std::ostream& operator<<(std::ostream& os,
                         const StaticCanonicalForLoopMatcher::CmpOp& cmp);
std::ostream& operator<<(std::ostream& os,
                         const StaticCanonicalForLoopMatcher::BinOp& binop);

class V8_EXPORT_PRIVATE LoopUnrollingAnalyzer {
  // LoopUnrollingAnalyzer analyzes the loops of the graph, and in particular
  // tries to figure out if some inner loops have a fixed (and known) number of
  // iterations. In particular, it tries to pattern match loops like
  //
  //    for (let i = 0; i < 4; i++) { ... }
  //
  // where `i++` could alternatively be pretty much any WordBinopOp or
  // OverflowCheckedBinopOp, and `i < 4` could be any ComparisonOp.
  // Such loops, if small enough, could be fully unrolled.
  //
  // Loops that don't have statically-known bounds could still be partially
  // unrolled if they are small enough.
 public:
  LoopUnrollingAnalyzer(Zone* phase_zone, Graph* input_graph, bool is_wasm)
      : input_graph_(input_graph),
        matcher_(*input_graph),
        loop_finder_(phase_zone, input_graph),
        loop_iteration_count_(phase_zone),
        canonical_loop_matcher_(matcher_),
        is_wasm_(is_wasm),
        stack_checks_to_remove_(input_graph->stack_checks_to_remove()) {
    DetectUnrollableLoops();
  }

  bool ShouldFullyUnrollLoop(const Block* loop_header) const {
    DCHECK(loop_header->IsLoop());

    LoopFinder::LoopInfo header_info = loop_finder_.GetLoopInfo(loop_header);
    if (header_info.has_inner_loops) return false;
    if (header_info.op_count > kMaxLoopSizeForFullUnrolling) return false;

    auto iter_count = GetIterationCount(loop_header);
    return iter_count.IsExact() &&
           iter_count.exact_count() < kMaxLoopIterationsForFullUnrolling;
  }

  bool ShouldPartiallyUnrollLoop(const Block* loop_header) const {
    DCHECK(loop_header->IsLoop());
    auto info = loop_finder_.GetLoopInfo(loop_header);
    return !info.has_inner_loops &&
           info.op_count < kMaxLoopSizeForPartialUnrolling;
  }

  size_t GetPartialUnrollCount(const Block* loop_header) const {
    auto info = loop_finder_.GetLoopInfo(loop_header);
    if (is_wasm_) {
      return std::min(
          LoopUnrollingAnalyzer::kMaxPartialUnrollingCount,
          LoopUnrollingAnalyzer::kWasmMaxUnrolledLoopSize / info.op_count);
    }
    return LoopUnrollingAnalyzer::kMaxPartialUnrollingCount;
  }

  bool ShouldRemoveLoop(const Block* loop_header) const {
    auto iter_count = GetIterationCount(loop_header);
    return iter_count.IsExact() && iter_count.exact_count() == 0;
  }

  IterationCount GetIterationCount(const Block* loop_header) const {
    DCHECK(loop_header->IsLoop());
    auto it = loop_iteration_count_.find(loop_header);
    if (it == loop_iteration_count_.end()) return IterationCount::Unknown();
    return it->second;
  }

  ZoneSet<const Block*, LoopFinder::BlockCmp> GetLoopBody(
      const Block* loop_header) {
    return loop_finder_.GetLoopBody(loop_header);
  }

  const Block* GetLoopHeader(const Block* block) {
    return loop_finder_.GetLoopHeader(block);
  }

  bool CanUnrollAtLeastOneLoop() const { return can_unroll_at_least_one_loop_; }

  // TODO(dmercadier): consider tweaking these value for a better size-speed
  // trade-off. In particular, having the number of iterations to unroll be a
  // function of the loop's size and a MaxLoopSize could make sense.
  static constexpr size_t kMaxLoopSizeForFullUnrolling = 150;
  static constexpr size_t kJSMaxLoopSizeForPartialUnrolling = 50;
  static constexpr size_t kWasmMaxLoopSizeForPartialUnrolling = 80;
  static constexpr size_t kWasmMaxUnrolledLoopSize = 240;
  static constexpr size_t kMaxLoopIterationsForFullUnrolling = 4;
  static constexpr size_t kMaxPartialUnrollingCount = 4;
  static constexpr size_t kMaxIterForStackCheckRemoval = 5000;

 private:
  void DetectUnrollableLoops();
  IterationCount GetLoopIterationCount(const LoopFinder::LoopInfo& info) const;

  Graph* input_graph_;
  OperationMatcher matcher_;
  LoopFinder loop_finder_;
  // {loop_iteration_count_} maps loop headers to number of iterations. It
  // doesn't contain entries for loops for which we don't know the number of
  // iterations.
  ZoneUnorderedMap<const Block*, IterationCount> loop_iteration_count_;
  const StaticCanonicalForLoopMatcher canonical_loop_matcher_;
  const bool is_wasm_;
  const size_t kMaxLoopSizeForPartialUnrolling =
      is_wasm_ ? kWasmMaxLoopSizeForPartialUnrolling
               : kJSMaxLoopSizeForPartialUnrolling;
  bool can_unroll_at_least_one_loop_ = false;

  ZoneAbslFlatHashSet<uint32_t>& stack_checks_to_remove_;
};

template <class Next>
class LoopPeelingReducer;

template <class Next>
class LoopStackCheckElisionReducer : public Next {
 public:
  TURBOSHAFT_REDUCER_BOILERPLATE(LoopStackCheckElision)

  void Bind(Block* new_block) {
    Next::Bind(new_block);
    if (!remove_stack_checks_) return;

    if (new_block->IsLoop()) {
      const Block* origin = new_block->OriginForBlockEnd();
      if (origin) {
        if (stack_checks_to_remove_.contains(origin->index().id())) {
          skip_next_stack_check_ = true;
        }
      }
    }
  }

  V<AnyOrNone> REDUCE_INPUT_GRAPH(Call)(V<AnyOrNone> ig_idx,
                                        const CallOp& call) {
    LABEL_BLOCK(no_change) { return Next::ReduceInputGraphCall(ig_idx, call); }
    if (ShouldSkipOptimizationStep()) goto no_change;

    if (skip_next_stack_check_ &&
        call.IsStackCheck(__ input_graph(), broker_,
                          StackCheckKind::kJSIterationBody)) {
      skip_next_stack_check_ = false;
      return {};
    }

    goto no_change;
  }

  V<None> REDUCE_INPUT_GRAPH(JSStackCheck)(V<None> ig_idx,
                                           const JSStackCheckOp& stack_check) {
    if (skip_next_stack_check_ &&
        stack_check.kind == JSStackCheckOp::Kind::kLoop) {
      skip_next_stack_check_ = false;
      return {};
    }
    return Next::ReduceInputGraphJSStackCheck(ig_idx, stack_check);
  }

#if V8_ENABLE_WEBASSEMBLY
  V<None> REDUCE_INPUT_GRAPH(WasmStackCheck)(
      V<None> ig_idx, const WasmStackCheckOp& stack_check) {
    if (skip_next_stack_check_ &&
        stack_check.kind == WasmStackCheckOp::Kind::kLoop) {
      skip_next_stack_check_ = false;
      return {};
    }
    return Next::ReduceInputGraphWasmStackCheck(ig_idx, stack_check);
  }
#endif

 private:
  bool skip_next_stack_check_ = false;

  // The analysis should have ran before the CopyingPhase starts, and stored in
  // `PipelineData::Get().stack_checks_to_remove()` the loops whose stack checks
  // should be removed.
  const ZoneAbslFlatHashSet<uint32_t>& stack_checks_to_remove_ =
      __ input_graph().stack_checks_to_remove();
  bool remove_stack_checks_ = !stack_checks_to_remove_.empty();

  JSHeapBroker* broker_ = __ data() -> broker();
};

template <class Next>
class LoopUnrollingReducer : public Next {
 public:
  TURBOSHAFT_REDUCER_BOILERPLATE(LoopUnrolling)

#if defined(__clang__)
  // LoopUnrolling and LoopPeeling shouldn't be performed in the same phase, see
  // the comment in pipeline.cc where LoopUnrolling is triggered.
  static_assert(!reducer_list_contains<ReducerList, LoopPeelingReducer>::value);

  // TODO(dmercadier): Add static_assert that this is ran as part of a
  // CopyingPhase.
#endif

  V<None> REDUCE_INPUT_GRAPH(Goto)(V<None> ig_idx, const GotoOp& gto) {
    // Note that the "ShouldSkipOptimizationStep" are placed in the parts of
    // this Reduce method triggering the unrolling rather than at the begining.
    // This is because the backedge skipping is not an optimization but a
    // mandatory lowering when unrolling is being performed.
    LABEL_BLOCK(no_change) { return Next::ReduceInputGraphGoto(ig_idx, gto); }

    const Block* dst = gto.destination;
    if (unrolling_ == UnrollingStatus::kNotUnrolling && dst->IsLoop() &&
        !gto.is_backedge) {
      // We trigger unrolling when reaching the GotoOp that jumps to the loop
      // header (note that loop headers only have 2 predecessor, including the
      // backedge), and that isn't the backedge.
      if (ShouldSkipOptimizationStep()) goto no_change;
      if (analyzer_.ShouldRemoveLoop(dst)) {
        RemoveLoop(dst);
        return {};
      } else if (analyzer_.ShouldFullyUnrollLoop(dst)) {
        FullyUnrollLoop(dst);
        return {};
      } else if (analyzer_.ShouldPartiallyUnrollLoop(dst)) {
        PartiallyUnrollLoop(dst);
        return {};
      }
    } else if ((unrolling_ == UnrollingStatus::kUnrolling) &&
               dst == current_loop_header_) {
      // Skipping the backedge of the loop: FullyUnrollLoop and
      // PartiallyUnrollLoop will emit a Goto to the next unrolled iteration.
      return {};
    }
    goto no_change;
  }

  OpIndex REDUCE_INPUT_GRAPH(Branch)(OpIndex ig_idx, const BranchOp& branch) {
    LABEL_BLOCK(no_change) {
      return Next::ReduceInputGraphBranch(ig_idx, branch);
    }

    if (unrolling_ == UnrollingStatus::kRemoveLoop) {
      // We know that the branch of the final inlined header of a fully unrolled
      // loop never actually goes to the loop, so we can replace it by a Goto
      // (so that the non-unrolled loop doesn't get emitted). We still need to
      // figure out if we should Goto to the true or false side of the BranchOp.
      const Block* header = __ current_block()->OriginForBlockEnd();
      bool is_true_in_loop = analyzer_.GetLoopHeader(branch.if_true) == header;
      bool is_false_in_loop =
          analyzer_.GetLoopHeader(branch.if_false) == header;

      if (is_true_in_loop && !is_false_in_loop) {
        __ Goto(__ MapToNewGraph(branch.if_false));
        return OpIndex::Invalid();
      } else if (is_false_in_loop && !is_true_in_loop) {
        __ Goto(__ MapToNewGraph(branch.if_true));
        return OpIndex::Invalid();
      } else {
        // Both the true and false destinations of this block are in the loop,
        // which means that the exit of the loop is later down the graph. We
        // thus still emit the branch, which will lead to the loop being emitted
        // (unless some other reducers in the stack manage to get rid of the
        // loop).
        DCHECK(is_true_in_loop && is_false_in_loop);
      }
    }
    goto no_change;
  }

  V<AnyOrNone> REDUCE_INPUT_GRAPH(Call)(V<AnyOrNone> ig_idx,
                                        const CallOp& call) {
    LABEL_BLOCK(no_change) { return Next::ReduceInputGraphCall(ig_idx, call); }
    if (ShouldSkipOptimizationStep()) goto no_change;

    if (V8_LIKELY(!IsRunningBuiltinPipeline())) {
      if (skip_next_stack_check_ &&
          call.IsStackCheck(__ input_graph(), broker_,
                            StackCheckKind::kJSIterationBody)) {
        // When we unroll a loop, we get rid of its stack checks. (note that
        // we don't do this for the last folded body of partially unrolled
        // loops so that the loop keeps one stack check).
        return {};
      }
    }

    goto no_change;
  }

  V<None> REDUCE_INPUT_GRAPH(JSStackCheck)(V<None> ig_idx,
                                           const JSStackCheckOp& check) {
    if (ShouldSkipOptimizationStep() || !skip_next_stack_check_) {
      return Next::ReduceInputGraphJSStackCheck(ig_idx, check);
    }
    return V<None>::Invalid();
  }

#if V8_ENABLE_WEBASSEMBLY
  V<None> REDUCE_INPUT_GRAPH(WasmStackCheck)(V<None> ig_idx,
                                             const WasmStackCheckOp& check) {
    if (ShouldSkipOptimizationStep() || !skip_next_stack_check_) {
      return Next::ReduceInputGraphWasmStackCheck(ig_idx, check);
    }
    return V<None>::Invalid();
  }
#endif

 private:
  enum class UnrollingStatus {
    // Not currently unrolling a loop.
    kNotUnrolling,
    // Currently unrolling a loop.
    kUnrolling,
    // We use kRemoveLoop in 2 cases:
    //   - When unrolling is finished and we are currently emitting the header
    //     one last time, and should change its final branch into a Goto.
    //   - We decided to remove a loop and will just emit its header.
    // Both cases are fairly similar: we are currently emitting a loop header,
    // and would like to not emit the loop body that follows.
    kRemoveLoop,
  };
  void RemoveLoop(const Block* header);
  void FullyUnrollLoop(const Block* header);
  void PartiallyUnrollLoop(const Block* header);
  void FixLoopPhis(const Block* input_graph_loop, Block* output_graph_loop,
                   const Block* backedge_block);
  bool IsRunningBuiltinPipeline() {
    return __ data() -> pipeline_kind() == TurboshaftPipelineKind::kCSA;
  }
  bool StopUnrollingIfUnreachable(
      std::optional<Block*> output_graph_header = std::nullopt) {
    if (__ generating_unreachable_operations()) {
      // By unrolling the loop, we realized that it was actually exiting early
      // (probably because a Branch inside the loop was using a loop Phi in a
      // condition, and unrolling showed that this loop Phi became true or
      // false), and that lasts iterations were unreachable. We thus don't both
      // unrolling the next iterations of the loop.
      unrolling_ = UnrollingStatus::kNotUnrolling;
      if (output_graph_header.has_value()) {
        // The loop that we're unrolling has a header (which means that we're
        // only partially unrolling), which needs to be turned into a Merge (and
        // its PendingLoopPhis into regular Phis).
        __ FinalizeLoop(*output_graph_header);
      }
      return true;
    }
    return false;
  }

  // The analysis should be ran ahead of time so that the LoopUnrollingPhase
  // doesn't trigger the CopyingPhase if there are no loops to unroll.
  LoopUnrollingAnalyzer& analyzer_ =
      *__ input_graph().loop_unrolling_analyzer();
  // {unrolling_} is true if a loop is currently being unrolled.
  UnrollingStatus unrolling_ = UnrollingStatus::kNotUnrolling;
  bool skip_next_stack_check_ = false;

  const Block* current_loop_header_ = nullptr;
  JSHeapBroker* broker_ = __ data() -> broker();
};

template <class Next>
void LoopUnrollingReducer<Next>::PartiallyUnrollLoop(const Block* header) {
  TRACE("LoopUnrolling: partially unrolling loop at " << header->index().id());
  DCHECK_EQ(unrolling_, UnrollingStatus::kNotUnrolling);
  DCHECK(!skip_next_stack_check_);
  unrolling_ = UnrollingStatus::kUnrolling;

  auto loop_body = analyzer_.GetLoopBody(header);
  current_loop_header_ = header;

  size_t unroll_count = analyzer_.GetPartialUnrollCount(header);
  TRACE("> UnrollCount: " << unroll_count);

  ScopedModification<bool> set_true(__ turn_loop_without_backedge_into_merge(),
                                    false);

  // We remove the stack check of all iterations but the last one.
  // Emitting the 1st iteration of the loop (with a proper loop header). We
  // remove the stack check of all iterations except the last one.
  ScopedModification<bool> skip_stack_checks(&skip_next_stack_check_, true);
  TRACE("> Emitting first iteraton (with header)");
  Block* output_graph_header =
      __ CloneSubGraph(loop_body, /* keep_loop_kinds */ true);
  if (StopUnrollingIfUnreachable(output_graph_header)) {
    TRACE("> Next iteration is unreachable, stopping unrolling");
    return;
  }

  // Emitting the subsequent folded iterations. We set `unrolling_` to
  // kUnrolling so that stack checks are skipped.
  unrolling_ = UnrollingStatus::kUnrolling;
  for (size_t i = 0; i < unroll_count - 1; i++) {
    // We remove the stack check of all iterations but the last one.
    TRACE("> Emitting iteration " << i);
    bool is_last_iteration = i == unroll_count - 2;
    ScopedModification<bool> skip_stack_checks(&skip_next_stack_check_,
                                               !is_last_iteration);

    __ CloneSubGraph(loop_body, /* keep_loop_kinds */ false);
    if (StopUnrollingIfUnreachable(output_graph_header)) {
      TRACE("> Next iteration is unreachable, stopping unrolling");
      return;
    }
  }

  // ReduceInputGraphGoto ignores backedge Gotos while kUnrolling is true, which
  // means that we are still missing the loop's backedge, which we thus emit
  // now.
  DCHECK(output_graph_header->IsLoop());
  Block* backedge_block = __ current_block();
  __ Goto(output_graph_header);
  // We use a custom `FixLoopPhis` because the mapping from old->new is a bit
  // "messed up" by having emitted multiple times the same block. See the
  // comments in `FixLoopPhis` for more details.
  TRACE("> Patching loop phis");
  FixLoopPhis(header, output_graph_header, backedge_block);

  unrolling_ = UnrollingStatus::kNotUnrolling;
  TRACE("> Finished partially unrolling loop " << header->index().id());
}

template <class Next>
void LoopUnrollingReducer<Next>::FixLoopPhis(const Block* input_graph_loop,
                                             Block* output_graph_loop,
                                             const Block* backedge_block) {
  // FixLoopPhis for partially unrolled loops is a bit tricky: the mapping from
  // input Loop Phis to output Loop Phis is in the Variable Snapshot of the
  // header (`output_graph_loop`), but the mapping from the 2nd input of the
  // input graph loop phis to the 2nd input of the output graph loop phis is in
  // the snapshot of the backedge (`backedge_block`).
  // VariableReducer::ReduceGotoOp (which was called right before this function
  // because we emitted the backedge Goto) already set the current snapshot to
  // be at the loop header. So, we start by computing the mapping input loop
  // phis -> output loop phis (using the loop header's snapshot). Then, we
  // restore the backedge snapshot to compute the mapping input graph 2nd phi
  // input to output graph 2nd phi input.
  DCHECK(input_graph_loop->IsLoop());
  DCHECK(output_graph_loop->IsLoop());

  // The mapping InputGraphPhi -> OutputGraphPendingPhi should be retrieved from
  // `output_graph_loop`'s snapshot (the current mapping is for the latest
  // folded loop iteration, not for the loop header).
  __ SealAndSaveVariableSnapshot();
  __ RestoreTemporaryVariableSnapshotAfter(output_graph_loop);
  base::SmallVector<std::pair<const PhiOp*, const OpIndex>, 16> phis;
  for (const Operation& op : __ input_graph().operations(
           input_graph_loop->begin(), input_graph_loop->end())) {
    if (auto* input_phi = op.TryCast<PhiOp>()) {
      OpIndex phi_index =
          __ template MapToNewGraph<true>(__ input_graph().Index(*input_phi));
      if (!phi_index.valid() || !output_graph_loop->Contains(phi_index)) {
        // Unused phis are skipped, so they are not be mapped to anything in
        // the new graph. If the phi is reduced to an operation from a
        // different block, then there is no loop phi in the current loop
        // header to take care of.
        continue;
      }
      phis.push_back({input_phi, phi_index});
    }
  }

  // The mapping for the InputGraphPhi 2nd input should however be retrieved
  // from the last block of the loop.
  __ CloseTemporaryVariableSnapshot();
  __ RestoreTemporaryVariableSnapshotAfter(backedge_block);

  for (auto [input_phi, output_phi_index] : phis) {
    __ FixLoopPhi(*input_phi, output_phi_index, output_graph_loop);
  }

  __ CloseTemporaryVariableSnapshot();
}

template <class Next>
void LoopUnrollingReducer<Next>::RemoveLoop(const Block* header) {
  TRACE("LoopUnrolling: removing loop at " << header->index().id());
  DCHECK_EQ(unrolling_, UnrollingStatus::kNotUnrolling);
  DCHECK(!skip_next_stack_check_);
  // When removing a loop, we still need to emit the header (since it has to
  // always be executed before the 1st iteration anyways), but by setting
  // {unrolling_} to `kRemoveLoop`, the final Branch of the loop will become a
  // Goto to outside the loop.
  unrolling_ = UnrollingStatus::kRemoveLoop;
  __ CloneAndInlineBlock(header);
  unrolling_ = UnrollingStatus::kNotUnrolling;
}

template <class Next>
void LoopUnrollingReducer<Next>::FullyUnrollLoop(const Block* header) {
  TRACE("LoopUnrolling: fully unrolling loop at " << header->index().id());
  DCHECK_EQ(unrolling_, UnrollingStatus::kNotUnrolling);
  DCHECK(!skip_next_stack_check_);
  ScopedModification<bool> skip_stack_checks(&skip_next_stack_check_, true);

  size_t iter_count = analyzer_.GetIterationCount(header).exact_count();
  TRACE("> iter_count: " << iter_count);

  auto loop_body = analyzer_.GetLoopBody(header);
  current_loop_header_ = header;

  unrolling_ = UnrollingStatus::kUnrolling;
  for (size_t i = 0; i < iter_count; i++) {
    TRACE("> Emitting iteration " << i);
    __ CloneSubGraph(loop_body, /* keep_loop_kinds */ false);
    if (StopUnrollingIfUnreachable()) {
      TRACE("> Next iteration is unreachable, stopping unrolling");
      return;
    }
  }

  // The loop actually finishes on the header rather than its last block. We
  // thus inline the header, and we'll replace its final BranchOp by a GotoOp to
  // outside of the loop.
  TRACE("> Emitting the final header");
  unrolling_ = UnrollingStatus::kRemoveLoop;
  __ CloneAndInlineBlock(header);

  unrolling_ = UnrollingStatus::kNotUnrolling;
  TRACE("> Finished fully unrolling loop " << header->index().id());
}

#undef TRACE

#include "src/compiler/turboshaft/undef-assembler-macros.inc"

}  // namespace v8::internal::compiler::turboshaft

#endif  // V8_COMPILER_TURBOSHAFT_LOOP_UNROLLING_REDUCER_H_

"""

```