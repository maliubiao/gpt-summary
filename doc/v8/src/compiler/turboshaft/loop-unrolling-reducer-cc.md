Response:
Let's break down the thought process for analyzing this C++ code and generating the explanation.

1. **Identify the Core Purpose:** The filename `loop-unrolling-reducer.cc` immediately suggests that this code is about loop unrolling, an optimization technique. The `reducer` part implies it's a component within a larger compilation pipeline (likely Turboshaft).

2. **Scan for Key Classes and Functions:** Look for the main classes and their methods. `LoopUnrollingAnalyzer` and `StaticCanonicalForLoopMatcher` stand out. Their methods, like `DetectUnrollableLoops`, `GetLoopIterationCount`, and `GetIterCountIfStaticCanonicalForLoop`, provide clues about their responsibilities.

3. **Understand `LoopUnrollingAnalyzer`:**
    * `DetectUnrollableLoops()`: This is the entry point. It iterates through loops, calculates iteration counts, and determines if a loop can be unrolled (fully or partially). The `can_unroll_at_least_one_loop_` flag is a key indicator.
    * `GetLoopIterationCount()`: This method tries to *statically* determine how many times a loop will run. It checks for a standard `for` loop structure (branch condition). The reliance on `StaticCanonicalForLoopMatcher` is important here.
    * `ShouldFullyUnrollLoop()` and `ShouldPartiallyUnrollLoop()` (though not defined in the snippet) are implied by the logic.

4. **Understand `StaticCanonicalForLoopMatcher`:**
    * The name suggests it's looking for loops with a *specific*, recognizable structure (canonical `for` loops).
    * `MatchPhiCompareCst()`: This is crucial for recognizing the loop's termination condition (`phi cmp constant`). The `phi` represents the loop counter.
    * `MatchCheckedOverflowBinop()` and `MatchWordBinop()`: These methods identify how the loop counter is updated (incremented, decremented, etc.).
    * `GetIterCountIfStaticCanonicalForLoop()`: This is the core logic for calculating the iteration count if the loop matches the canonical form. It uses the `Match` functions to dissect the loop structure.
    * `CountIterationsImpl()` and `CountIterations()`: These functions simulate the loop execution to precisely (or approximately) determine the iteration count for simple loops. This is a fallback or a detailed analysis for matched canonical forms.

5. **Trace the Logic Flow:** Imagine the code executing. `LoopUnrollingAnalyzer` finds a loop. It calls `GetLoopIterationCount`, which in turn uses `StaticCanonicalForLoopMatcher` to analyze the loop's structure. If a canonical `for` loop is found, its iteration count is calculated.

6. **Identify Relationships:**  `LoopUnrollingAnalyzer` depends on `LoopFinder` (from the includes and the `loop_finder_` member) to identify loops in the first place. It also relies heavily on `StaticCanonicalForLoopMatcher` for analysis.

7. **Consider the "Why":**  Why is loop unrolling important? It reduces loop overhead and can improve instruction-level parallelism. Why does the code try to determine the iteration count statically?  Because static analysis allows for more aggressive optimizations.

8. **Think about Edge Cases and Limitations:** The code handles cases where the loop condition or increment is not simple. It has limits on the maximum iterations it will try to analyze precisely (`kMaxExactIter`). It also handles potential overflows during iteration counting.

9. **Relate to JavaScript (if applicable):**  Consider how these optimizations might affect JavaScript code. Simple `for` loops are common in JavaScript, and this code aims to optimize them.

10. **Illustrate with Examples:** Create simple JavaScript examples of loops that *would* be optimized and loops that *might not* be (due to complexity).

11. **Consider Common Programming Errors:** Think about how a programmer might write a loop that would prevent this optimization (e.g., using a complex exit condition or a non-constant increment).

12. **Structure the Explanation:** Organize the findings into logical sections: core functionality, class breakdowns, relationships, JavaScript connection, examples, etc. Use clear and concise language.

13. **Review and Refine:** Read through the explanation to ensure accuracy and clarity. Check for any jargon that needs explanation.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "This just counts loop iterations."  **Correction:** It's not just counting; it's identifying *unrollable* loops by analyzing their structure and iteration count.
* **Focus on individual functions:**  Realize that the interaction between `LoopUnrollingAnalyzer` and `StaticCanonicalForLoopMatcher` is crucial.
* **Overlook the constants:**  Recognize the importance of `kMaxIterForStackCheckRemoval` and `kMaxExactIter` in understanding the optimization limits.
* **Miss the "canonical" aspect:**  Emphasize that the matcher is looking for *specific* `for` loop patterns.
* **Not enough JavaScript context:**  Ensure the JavaScript examples clearly demonstrate the connection to the C++ code.

By following these steps and engaging in self-correction, a comprehensive and accurate explanation of the code can be generated.
这个C++源代码文件 `v8/src/compiler/turboshaft/loop-unrolling-reducer.cc` 的主要功能是**分析和识别可以进行循环展开优化的循环**。它是 Turboshaft 编译器管道中的一个组件，负责在代码生成之前对中间表示（IR）进行优化。

**功能分解:**

1. **循环识别 (Loop Detection):**  它依赖于 `LoopFinder` 类来识别代码中的循环结构。

2. **静态循环分析 (Static Loop Analysis):**  核心功能在于尝试**静态地确定循环的迭代次数**。它使用 `StaticCanonicalForLoopMatcher` 类来匹配特定模式的 `for` 循环结构。这些模式通常是具有简单初始化、条件判断和递增/递减操作的循环。

3. **迭代次数计算 (Iteration Count Calculation):**
   - 对于匹配到的特定模式的循环，它会尝试计算出循环的确切或近似迭代次数。
   - 这通过 `StaticCanonicalForLoopMatcher::GetIterCountIfStaticCanonicalForLoop` 和相关的 `CountIterations` 函数实现。
   - 它会考虑循环的初始值、终止条件、步长以及数据类型（例如，有符号/无符号，32位/64位）。
   - 它会处理一些简单的算术和位运算作为循环的步进操作。

4. **判断是否可以展开 (Unrollability Determination):**
   - 基于计算出的迭代次数，它会判断循环是否适合进行完全展开或部分展开。
   - 完全展开适用于迭代次数较小且可以静态确定的循环。
   - 部分展开适用于迭代次数较多，但仍然可以通过展开一部分来减少循环开销的循环。

5. **移除栈溢出检查 (Stack Check Removal):**  对于迭代次数小于某个阈值 (`kMaxIterForStackCheckRemoval`) 的循环，它会标记这些循环，以便后续阶段可以移除不必要的栈溢出检查。

**关于文件扩展名 `.tq`:**

如果 `v8/src/compiler/turboshaft/loop-unrolling-reducer.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。Torque 是 V8 用来定义运行时内置函数和编译器辅助函数的领域特定语言。由于这里文件后缀是 `.cc`，所以它是标准的 C++ 源代码。

**与 JavaScript 功能的关系:**

循环是 JavaScript 中非常常见的控制流结构，用于重复执行代码块。`loop-unrolling-reducer.cc` 的目标是优化这些循环，从而提高 JavaScript 代码的执行效率。

**JavaScript 示例:**

考虑以下简单的 JavaScript `for` 循环：

```javascript
let sum = 0;
for (let i = 0; i < 10; i++) {
  sum += i;
}
console.log(sum); // 输出 45
```

`loop-unrolling-reducer.cc`  可能会分析这个循环，识别出它的迭代次数是 10，并且步长是 1。由于迭代次数较小，编译器可能会决定完全展开这个循环，将其转换为类似以下的代码：

```javascript
let sum = 0;
sum += 0;
sum += 1;
sum += 2;
sum += 3;
sum += 4;
sum += 5;
sum += 6;
sum += 7;
sum += 8;
sum += 9;
console.log(sum);
```

展开后的代码避免了循环的控制流开销（例如，每次迭代的条件判断和递增操作），从而可能提高执行速度。

**代码逻辑推理：假设输入与输出**

**假设输入:**  一个表示以下 JavaScript 代码的 Turboshaft IR（中间表示）：

```javascript
let result = 0;
for (let i = 5; i < 15; i += 2) {
  result += i;
}
```

**推理过程:**

1. **循环识别:** `LoopFinder` 会识别出 `for` 循环的起始块和相关信息。
2. **模式匹配:** `StaticCanonicalForLoopMatcher` 会尝试匹配该循环的结构：
   - 初始化: `i = 5`
   - 条件: `i < 15` (对应 `CmpOp::kSignedLessThan`, 比较常量 15)
   - 递增: `i += 2` (对应 `BinOp::kAdd`, 步长 2)
3. **迭代次数计算:** `GetIterCountIfStaticCanonicalForLoop` 或 `CountIterations` 会计算迭代次数：
   - 初始值: 5
   - 终止值: 15
   - 步长: 2
   - 迭代次数 = (15 - 5 + 2 - 1) / 2 = 6  (考虑 `<` 的情况)
4. **展开判断:**  如果计算出的迭代次数 (6) 小于完全展开的阈值，则该循环被标记为可完全展开。

**假设输出:**

- `loop_iteration_count_` 中会包含该循环起始块和迭代次数 6 的信息。
- 如果满足展开条件，该循环会被标记为可以展开。

**涉及用户常见的编程错误:**

1. **无限循环:** 用户可能会编写导致无限循环的代码，例如：

   ```javascript
   let i = 0;
   while (i >= 0) {
     console.log(i);
     // 忘记增加 i 的值
   }
   ```

   `loop-unrolling-reducer.cc` 在分析这类循环时，由于无法静态确定迭代次数，将无法进行展开优化。 `GetLoopIterationCount` 中会因为 `!branch` 而返回空。

2. **循环条件依赖于动态值:** 如果循环的终止条件依赖于在循环内部计算的动态值，编译器也难以静态确定迭代次数，例如：

   ```javascript
   let arr = [1, 2, 3, 4, 5];
   for (let i = 0; i < arr.length; i++) {
     if (arr[i] > 3) {
       arr.length = i; // 动态改变数组长度
     }
     console.log(arr[i]);
   }
   ```

   在这种情况下，`StaticCanonicalForLoopMatcher` 很难匹配到预期的模式，迭代次数也无法静态计算。

3. **非标准的步进方式:** 如果循环的步进方式过于复杂，不是简单的加法或减法，例如：

   ```javascript
   for (let i = 1; i < 100; i = i * 2) {
     console.log(i);
   }
   ```

   虽然 `StaticCanonicalForLoopMatcher` 支持乘法，但更复杂的非线性步进可能无法被识别和优化。

总之，`v8/src/compiler/turboshaft/loop-unrolling-reducer.cc` 是 V8 编译器中一个关键的优化组件，它通过静态分析循环结构和计算迭代次数，为后续的循环展开优化提供决策依据，从而提升 JavaScript 代码的性能。

Prompt: 
```
这是目录为v8/src/compiler/turboshaft/loop-unrolling-reducer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/loop-unrolling-reducer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/turboshaft/loop-unrolling-reducer.h"

#include <optional>

#include "src/base/bits.h"
#include "src/compiler/turboshaft/index.h"
#include "src/compiler/turboshaft/loop-finder.h"

#ifdef DEBUG
#define TRACE(x)                                                               \
  do {                                                                         \
    if (v8_flags.turboshaft_trace_unrolling) StdoutStream() << x << std::endl; \
  } while (false)
#else
#define TRACE(x)
#endif

namespace v8::internal::compiler::turboshaft {

using CmpOp = StaticCanonicalForLoopMatcher::CmpOp;
using BinOp = StaticCanonicalForLoopMatcher::BinOp;

void LoopUnrollingAnalyzer::DetectUnrollableLoops() {
  for (const auto& [start, info] : loop_finder_.LoopHeaders()) {
    IterationCount iter_count = GetLoopIterationCount(info);
    TRACE("LoopUnrollingAnalyzer: loop at "
          << start->index() << " ==> iter_count=" << iter_count);
    loop_iteration_count_.insert({start, iter_count});

    if (ShouldFullyUnrollLoop(start) || ShouldPartiallyUnrollLoop(start)) {
      can_unroll_at_least_one_loop_ = true;
    }

    if (iter_count.IsSmallerThan(kMaxIterForStackCheckRemoval)) {
      stack_checks_to_remove_.insert(start->index().id());
    }
  }
}

IterationCount LoopUnrollingAnalyzer::GetLoopIterationCount(
    const LoopFinder::LoopInfo& info) const {
  const Block* start = info.start;
  DCHECK(start->IsLoop());

  // Checking that the condition for the loop can be computed statically, and
  // that the loop contains no more than kMaxLoopIterationsForFullUnrolling
  // iterations.
  const BranchOp* branch =
      start->LastOperation(*input_graph_).TryCast<BranchOp>();
  if (!branch) {
    // This looks like an infinite loop, or like something weird is used to
    // decide whether to loop or not.
    return {};
  }

  // Checking that one of the successor of the loop header is indeed not in the
  // loop (otherwise, the Branch that ends the loop header is not the Branch
  // that decides to exit the loop).
  const Block* if_true_header = loop_finder_.GetLoopHeader(branch->if_true);
  const Block* if_false_header = loop_finder_.GetLoopHeader(branch->if_false);
  if (if_true_header == if_false_header) {
    return {};
  }

  // If {if_true} is in the loop, then we're looping if the condition is true,
  // but if {if_false} is in the loop, then we're looping if the condition is
  // false.
  bool loop_if_cond_is = if_true_header == start;

  return canonical_loop_matcher_.GetIterCountIfStaticCanonicalForLoop(
      start, branch->condition(), loop_if_cond_is);
}

// Tries to match `phi cmp cst` (or `cst cmp phi`).
bool StaticCanonicalForLoopMatcher::MatchPhiCompareCst(
    OpIndex cond_idx, StaticCanonicalForLoopMatcher::CmpOp* cmp_op,
    OpIndex* phi, uint64_t* cst) const {
  const Operation& cond = matcher_.Get(cond_idx);

  if (const ComparisonOp* cmp = cond.TryCast<ComparisonOp>()) {
    *cmp_op = ComparisonKindToCmpOp(cmp->kind);
  } else {
    return false;
  }

  OpIndex left = cond.input(0);
  OpIndex right = cond.input(1);

  if (matcher_.MatchPhi(left, 2)) {
    if (matcher_.MatchUnsignedIntegralConstant(right, cst)) {
      *phi = left;
      return true;
    }
  } else if (matcher_.MatchPhi(right, 2)) {
    if (matcher_.MatchUnsignedIntegralConstant(left, cst)) {
      *cmp_op = InvertComparisonOp(*cmp_op);
      *phi = right;
      return true;
    }
  }
  return false;
}

bool StaticCanonicalForLoopMatcher::MatchCheckedOverflowBinop(
    OpIndex idx, V<Word>* left, V<Word>* right, BinOp* binop_op,
    WordRepresentation* binop_rep) const {
  if (const ProjectionOp* proj = matcher_.TryCast<ProjectionOp>(idx)) {
    if (proj->index != OverflowCheckedBinopOp::kValueIndex) return false;
    if (const OverflowCheckedBinopOp* binop =
            matcher_.TryCast<OverflowCheckedBinopOp>(proj->input())) {
      *left = binop->left();
      *right = binop->right();
      *binop_op = BinopFromOverflowCheckedBinopKind(binop->kind);
      *binop_rep = binop->rep;
      return true;
    }
  }
  return false;
}

bool StaticCanonicalForLoopMatcher::MatchWordBinop(
    OpIndex idx, V<Word>* left, V<Word>* right, BinOp* binop_op,
    WordRepresentation* binop_rep) const {
  WordBinopOp::Kind kind;
  if (matcher_.MatchWordBinop(idx, left, right, &kind, binop_rep) &&
      BinopKindIsSupported(kind)) {
    *binop_op = BinopFromWordBinopKind(kind);
    return true;
  }
  return false;
}

IterationCount
StaticCanonicalForLoopMatcher::GetIterCountIfStaticCanonicalForLoop(
    const Block* header, OpIndex cond_idx, bool loop_if_cond_is) const {
  CmpOp cmp_op;
  OpIndex phi_idx;
  uint64_t cmp_cst;
  if (!MatchPhiCompareCst(cond_idx, &cmp_op, &phi_idx, &cmp_cst)) {
    return {};
  }
  if (!header->Contains(phi_idx)) {
    // The termination condition for this loop is based on a Phi that is defined
    // in another loop.
    return {};
  }

  const PhiOp& phi = matcher_.Cast<PhiOp>(phi_idx);

  // We have: phi(..., ...) cmp_op cmp_cst
  // eg, for (i = ...; i < 42; ...)
  uint64_t phi_cst;
  if (matcher_.MatchUnsignedIntegralConstant(phi.input(0), &phi_cst)) {
    // We have: phi(phi_cst, ...) cmp_op cmp_cst
    // eg, for (i = 0; i < 42; ...)
    V<Word> left, right;
    BinOp binop_op;
    WordRepresentation binop_rep;
    if (MatchWordBinop(phi.input(1), &left, &right, &binop_op, &binop_rep) ||
        MatchCheckedOverflowBinop(phi.input(1), &left, &right, &binop_op,
                                  &binop_rep)) {
      // We have: phi(phi_cst, ... binop_op ...) cmp_op cmp_cst
      // eg, for (i = 0; i < 42; i = ... + ...)
      if (left == phi_idx) {
        // We have: phi(phi_cst, phi binop_op ...) cmp_op cmp_cst
        // eg, for (i = 0; i < 42; i = i + ...)
        uint64_t binop_cst;
        if (matcher_.MatchUnsignedIntegralConstant(right, &binop_cst)) {
          // We have: phi(phi_cst, phi binop_op binop_cst) cmp_op cmp_cst
          // eg, for (i = 0; i < 42; i = i + 2)
          return CountIterations(cmp_cst, cmp_op, phi_cst, binop_cst, binop_op,
                                 binop_rep, loop_if_cond_is);
        }
      } else if (right == phi_idx) {
        // We have: phi(phi_cst, ... binop_op phi) cmp_op cmp_cst
        // eg, for (i = 0; i < 42; i = ... + i)
        uint64_t binop_cst;
        if (matcher_.MatchUnsignedIntegralConstant(left, &binop_cst)) {
          // We have: phi(phi_cst, binop_cst binop_op phi) cmp_op cmp_cst
          // eg, for (i = 0; i < 42; i = 2 + i)
          return CountIterations(cmp_cst, cmp_op, phi_cst, binop_cst, binop_op,
                                 binop_rep, loop_if_cond_is);
        }
      }
    }
  }

  // The condition is not an operation that we support.
  return {};
}

constexpr bool StaticCanonicalForLoopMatcher::BinopKindIsSupported(
    WordBinopOp::Kind binop_kind) {
  switch (binop_kind) {
    // This list needs to be kept in sync with the `Next` function that follows.
    case WordBinopOp::Kind::kAdd:
    case WordBinopOp::Kind::kMul:
    case WordBinopOp::Kind::kSub:
    case WordBinopOp::Kind::kBitwiseAnd:
    case WordBinopOp::Kind::kBitwiseOr:
    case WordBinopOp::Kind::kBitwiseXor:
      return true;
    default:
      return false;
  }
}

constexpr StaticCanonicalForLoopMatcher::BinOp
StaticCanonicalForLoopMatcher::BinopFromWordBinopKind(WordBinopOp::Kind kind) {
  DCHECK(BinopKindIsSupported(kind));
  switch (kind) {
    case WordBinopOp::Kind::kAdd:
      return BinOp::kAdd;
    case WordBinopOp::Kind::kMul:
      return BinOp::kMul;
    case WordBinopOp::Kind::kSub:
      return BinOp::kSub;
    case WordBinopOp::Kind::kBitwiseAnd:
      return BinOp::kBitwiseAnd;
    case WordBinopOp::Kind::kBitwiseOr:
      return BinOp::kBitwiseOr;
    case WordBinopOp::Kind::kBitwiseXor:
      return BinOp::kBitwiseXor;
    default:
      UNREACHABLE();
  }
}

constexpr StaticCanonicalForLoopMatcher::BinOp
StaticCanonicalForLoopMatcher::BinopFromOverflowCheckedBinopKind(
    OverflowCheckedBinopOp::Kind kind) {
  switch (kind) {
    case OverflowCheckedBinopOp::Kind::kSignedAdd:
      return BinOp::kOverflowCheckedAdd;
    case OverflowCheckedBinopOp::Kind::kSignedMul:
      return BinOp::kOverflowCheckedMul;
    case OverflowCheckedBinopOp::Kind::kSignedSub:
      return BinOp::kOverflowCheckedSub;
  }
}

std::ostream& operator<<(std::ostream& os, const IterationCount& count) {
  if (count.IsExact()) {
    return os << "Exact[" << count.exact_count() << "]";
  } else if (count.IsApprox()) {
    return os << "Approx[" << count.exact_count() << "]";
  } else {
    DCHECK(count.IsUnknown());
    return os << "Unknown";
  }
}

std::ostream& operator<<(std::ostream& os, const CmpOp& cmp) {
  switch (cmp) {
    case CmpOp::kEqual:
      return os << "==";
    case CmpOp::kSignedLessThan:
      return os << "<ˢ";
    case CmpOp::kSignedLessThanOrEqual:
      return os << "<=ˢ";
    case CmpOp::kUnsignedLessThan:
      return os << "<ᵘ";
    case CmpOp::kUnsignedLessThanOrEqual:
      return os << "<=ᵘ";
    case CmpOp::kSignedGreaterThan:
      return os << ">ˢ";
    case CmpOp::kSignedGreaterThanOrEqual:
      return os << ">=ˢ";
    case CmpOp::kUnsignedGreaterThan:
      return os << ">ᵘ";
    case CmpOp::kUnsignedGreaterThanOrEqual:
      return os << ">=ᵘ";
  }
}

std::ostream& operator<<(std::ostream& os, const BinOp& binop) {
  switch (binop) {
    case BinOp::kAdd:
      return os << "+";
    case BinOp::kMul:
      return os << "*";
    case BinOp::kSub:
      return os << "-";
    case BinOp::kBitwiseAnd:
      return os << "&";
    case BinOp::kBitwiseOr:
      return os << "|";
    case BinOp::kBitwiseXor:
      return os << "^";
    case BinOp::kOverflowCheckedAdd:
      return os << "+ᵒ";
    case BinOp::kOverflowCheckedMul:
      return os << "*ᵒ";
    case BinOp::kOverflowCheckedSub:
      return os << "-ᵒ";
  }
}

namespace {

template <class Int>
std::optional<Int> Next(Int val, Int incr,
                        StaticCanonicalForLoopMatcher::BinOp binop_op,
                        WordRepresentation binop_rep) {
  switch (binop_op) {
    case BinOp::kBitwiseAnd:
      return val & incr;
    case BinOp::kBitwiseOr:
      return val | incr;
    case BinOp::kBitwiseXor:
      return val ^ incr;
      // Even regular Add/Sub/Mul probably shouldn't under/overflow here, so we
      // check for overflow in all cases (and C++ signed integer overflow is
      // undefined behavior, so have to use something from base::bits anyways).
#define CASE_ARITH(op)                                                        \
  case BinOp::k##op:                                                          \
  case BinOp::kOverflowChecked##op: {                                         \
    if (binop_rep == WordRepresentation::Word32()) {                          \
      int32_t res;                                                            \
      if (base::bits::Signed##op##Overflow32(                                 \
              static_cast<int32_t>(val), static_cast<int32_t>(incr), &res)) { \
        return std::nullopt;                                                  \
      }                                                                       \
      return static_cast<Int>(res);                                           \
    } else {                                                                  \
      DCHECK_EQ(binop_rep, WordRepresentation::Word64());                     \
      int64_t res;                                                            \
      if (base::bits::Signed##op##Overflow64(val, incr, &res)) {              \
        return std::nullopt;                                                  \
      }                                                                       \
      return static_cast<Int>(res);                                           \
    }                                                                         \
  }
      CASE_ARITH(Add)
      CASE_ARITH(Mul)
      CASE_ARITH(Sub)
#undef CASE_CHECKED
  }
}

template <class Int>
bool Cmp(Int val, Int max, CmpOp cmp_op) {
  switch (cmp_op) {
    case CmpOp::kSignedLessThan:
    case CmpOp::kUnsignedLessThan:
      return val < max;
    case CmpOp::kSignedLessThanOrEqual:
    case CmpOp::kUnsignedLessThanOrEqual:
      return val <= max;
    case CmpOp::kSignedGreaterThan:
    case CmpOp::kUnsignedGreaterThan:
      return val > max;
    case CmpOp::kSignedGreaterThanOrEqual:
    case CmpOp::kUnsignedGreaterThanOrEqual:
      return val >= max;
    case CmpOp::kEqual:
      return val == max;
  }
}

template <class Int>
bool SubWillOverflow(Int lhs, Int rhs) {
  if constexpr (std::is_same_v<Int, int32_t> || std::is_same_v<Int, uint32_t>) {
    int32_t unused;
    return base::bits::SignedSubOverflow32(lhs, rhs, &unused);
  } else {
    static_assert(std::is_same_v<Int, int64_t> ||
                  std::is_same_v<Int, uint64_t>);
    int64_t unused;
    return base::bits::SignedSubOverflow64(lhs, rhs, &unused);
  }
}

template <class Int>
bool DivWillOverflow(Int dividend, Int divisor) {
  if constexpr (std::is_unsigned_v<Int>) {
    return false;
  } else {
    return dividend == std::numeric_limits<Int>::min() && divisor == -1;
  }
}

}  // namespace

// Returns true if the loop
// `for (i = init, i cmp_op max; i = i binop_op binop_cst)` has fewer than
// `max_iter_` iterations.
template <class Int>
IterationCount StaticCanonicalForLoopMatcher::CountIterationsImpl(
    Int init, Int max, CmpOp cmp_op, Int binop_cst, BinOp binop_op,
    WordRepresentation binop_rep, bool loop_if_cond_is) const {
  static_assert(std::is_integral_v<Int>);
  DCHECK_EQ(std::is_unsigned_v<Int>,
            (cmp_op == CmpOp::kUnsignedLessThan ||
             cmp_op == CmpOp::kUnsignedLessThanOrEqual ||
             cmp_op == CmpOp::kUnsignedGreaterThan ||
             cmp_op == CmpOp::kUnsignedGreaterThanOrEqual));

  // It's a bit hard to compute the number of iterations without some kind of
  // (simple) SMT solver, especially when taking overflows into account. Thus,
  // we just simulate the evolution of the loop counter: we repeatedly compute
  // `init binop_op binop_cst`, and compare the result with `max`. This is
  // somewhat inefficient, so it should only be done if `kMaxExactIter` is
  // small.
  DCHECK_LE(kMaxExactIter, 10);

  Int curr = init;
  size_t iter_count = 0;
  for (; iter_count < kMaxExactIter; iter_count++) {
    if (Cmp(curr, max, cmp_op) != loop_if_cond_is) {
      return IterationCount::Exact(iter_count);
    }
    if (auto next = Next(curr, binop_cst, binop_op, binop_rep)) {
      curr = *next;
    } else {
      // There was an overflow, bailing out.
      break;
    }
  }

  if (binop_cst == 0) {
    // If {binop_cst} is 0, the loop should either execute a single time or loop
    // infinitely (since the increment is in the form of "i = i op binop_cst"
    // with op being an arithmetic or bitwise binop). If we didn't detect above
    // that it executes a single time, then we are in the latter case.
    return {};
  }

  // Trying to figure out an approximate number of iterations
  if (binop_op == StaticCanonicalForLoopMatcher::BinOp::kAdd) {
    if (cmp_op ==
            any_of(CmpOp::kUnsignedLessThan, CmpOp::kUnsignedLessThanOrEqual,
                   CmpOp::kSignedLessThan, CmpOp::kSignedLessThanOrEqual) &&
        init < max && !SubWillOverflow(max, init) && loop_if_cond_is) {
      // eg, for (int i = 0; i < 42; i += 2)
      if (binop_cst < 0) {
        // Will either loop forever or rely on underflow wrap-around to
        // eventually stop.
        return {};
      }
      DCHECK(!DivWillOverflow(max - init, binop_cst));
      Int quotient = (max - init) / binop_cst;
      DCHECK_GE(quotient, 0);
      return IterationCount::Approx(quotient);
    }
    if (cmp_op == any_of(CmpOp::kUnsignedGreaterThan,
                         CmpOp::kUnsignedGreaterThanOrEqual,
                         CmpOp::kSignedGreaterThan,
                         CmpOp::kSignedGreaterThanOrEqual) &&
        init > max && !SubWillOverflow(max, init) && loop_if_cond_is) {
      // eg, for (int i = 42; i > 0; i += -2)
      if (binop_cst > 0) {
        // Will either loop forever or rely on overflow wrap-around to
        // eventually stop.
        return {};
      }
      if (DivWillOverflow(max - init, binop_cst)) return {};
      Int quotient = (max - init) / binop_cst;
      DCHECK_GE(quotient, 0);
      return IterationCount::Approx(quotient);
    }
    if (cmp_op == CmpOp::kEqual && !SubWillOverflow(max, init) &&
        !loop_if_cond_is) {
      // eg, for (int i = 0;  i != 42; i += 2)
      // or, for (int i = 42; i != 0;  i += -2)
      if (init < max && binop_cst < 0) {
        // Will either loop forever or rely on underflow wrap-around to
        // eventually stop.
        return {};
      }
      if (init > max && binop_cst > 0) {
        // Will either loop forever or rely on overflow wrap-around to
        // eventually stop.
        return {};
      }

      Int remainder = (max - init) % binop_cst;
      if (remainder != 0) {
        // Will loop forever or rely on over/underflow wrap-around to eventually
        // stop.
        return {};
      }

      Int quotient = (max - init) / binop_cst;
      DCHECK_GE(quotient, 0);
      return IterationCount::Approx(quotient);
    }
  }

  return {};
}

// Returns true if the loop
// `for (i = initial_input, i cmp_op cmp_cst; i = i binop_op binop_cst)` has
// fewer than `max_iter_` iterations.
IterationCount StaticCanonicalForLoopMatcher::CountIterations(
    uint64_t cmp_cst, CmpOp cmp_op, uint64_t initial_input, uint64_t binop_cst,
    BinOp binop_op, WordRepresentation binop_rep, bool loop_if_cond_is) const {
  switch (cmp_op) {
    case CmpOp::kSignedLessThan:
    case CmpOp::kSignedLessThanOrEqual:
    case CmpOp::kSignedGreaterThan:
    case CmpOp::kSignedGreaterThanOrEqual:
    case CmpOp::kEqual:
      if (binop_rep == WordRepresentation::Word32()) {
        return CountIterationsImpl<int32_t>(
            static_cast<int32_t>(initial_input), static_cast<int32_t>(cmp_cst),
            cmp_op, static_cast<int32_t>(binop_cst), binop_op, binop_rep,
            loop_if_cond_is);
      } else {
        DCHECK_EQ(binop_rep, WordRepresentation::Word64());
        return CountIterationsImpl<int64_t>(
            static_cast<int64_t>(initial_input), static_cast<int64_t>(cmp_cst),
            cmp_op, static_cast<int64_t>(binop_cst), binop_op, binop_rep,
            loop_if_cond_is);
      }
    case CmpOp::kUnsignedLessThan:
    case CmpOp::kUnsignedLessThanOrEqual:
    case CmpOp::kUnsignedGreaterThan:
    case CmpOp::kUnsignedGreaterThanOrEqual:
      if (binop_rep == WordRepresentation::Word32()) {
        return CountIterationsImpl<uint32_t>(
            static_cast<uint32_t>(initial_input),
            static_cast<uint32_t>(cmp_cst), cmp_op,
            static_cast<uint32_t>(binop_cst), binop_op, binop_rep,
            loop_if_cond_is);
      } else {
        DCHECK_EQ(binop_rep, WordRepresentation::Word64());
        return CountIterationsImpl<uint64_t>(initial_input, cmp_cst, cmp_op,
                                             binop_cst, binop_op, binop_rep,
                                             loop_if_cond_is);
      }
  }
}

constexpr StaticCanonicalForLoopMatcher::CmpOp
StaticCanonicalForLoopMatcher::ComparisonKindToCmpOp(ComparisonOp::Kind kind) {
  switch (kind) {
    case ComparisonOp::Kind::kEqual:
      return CmpOp::kEqual;
    case ComparisonOp::Kind::kSignedLessThan:
      return CmpOp::kSignedLessThan;
    case ComparisonOp::Kind::kSignedLessThanOrEqual:
      return CmpOp::kSignedLessThanOrEqual;
    case ComparisonOp::Kind::kUnsignedLessThan:
      return CmpOp::kUnsignedLessThan;
    case ComparisonOp::Kind::kUnsignedLessThanOrEqual:
      return CmpOp::kUnsignedLessThanOrEqual;
  }
}
constexpr StaticCanonicalForLoopMatcher::CmpOp
StaticCanonicalForLoopMatcher::InvertComparisonOp(CmpOp op) {
  switch (op) {
    case CmpOp::kEqual:
      return CmpOp::kEqual;
    case CmpOp::kSignedLessThan:
      return CmpOp::kSignedGreaterThan;
    case CmpOp::kSignedLessThanOrEqual:
      return CmpOp::kSignedGreaterThanOrEqual;
    case CmpOp::kUnsignedLessThan:
      return CmpOp::kUnsignedGreaterThan;
    case CmpOp::kUnsignedLessThanOrEqual:
      return CmpOp::kUnsignedGreaterThanOrEqual;
    case CmpOp::kSignedGreaterThan:
      return CmpOp::kSignedLessThan;
    case CmpOp::kSignedGreaterThanOrEqual:
      return CmpOp::kSignedLessThanOrEqual;
    case CmpOp::kUnsignedGreaterThan:
      return CmpOp::kUnsignedLessThan;
    case CmpOp::kUnsignedGreaterThanOrEqual:
      return CmpOp::kUnsignedLessThanOrEqual;
  }
}

}  // namespace v8::internal::compiler::turboshaft

"""

```