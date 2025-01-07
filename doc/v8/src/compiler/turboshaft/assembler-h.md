Response:
My thinking process to arrive at the summary of `assembler.h` went something like this:

1. **Understand the Request:** The request asks for the functionality of the provided C++ header file, specifically focusing on its role in the V8 Turboshaft compiler. It also includes a few specific checks related to file extensions and JavaScript connections.

2. **Initial Scan for Keywords:** I immediately scanned the header for prominent keywords and patterns. Things that jumped out were:
    * `#ifndef`, `#define`:  Standard header file guards. Not functional, but organizational.
    * `#include`: A long list of other V8 headers. This suggests the file relies heavily on other parts of the V8 codebase, hinting at its core role in the compilation process.
    * `namespace v8::internal::compiler::turboshaft`: Clearly defines the context of this code within V8.
    * `class AssemblerT`: The central class in the file. This is likely where the main functionality resides.
    * `GotoIf`, `GotoIfNot`, `Label`, `LoopLabel`:  These suggest control flow mechanisms within the assembler.
    * `FOREACH`:  A custom macro for looping, indicating structured code generation.
    * `Range`, `IndexRange`, `Sequence`, `Zip`:  Types of iterators used with `FOREACH`, showing different looping patterns.
    * `ConditionWithHint`:  Indicates conditional branching with optimization hints.
    * `Reduce...`:  Function names like `ReduceFoo` suggest a reduction or transformation process, typical of compiler pipelines.
    * `PhiOp`, `PendingLoopPhiOp`:  Compiler-related concepts for handling data flow at join points in control flow.
    * Comments: I looked for comments providing high-level explanations. The comments about `GotoIf/GotoIfNot` and the `FOREACH` loop were helpful.

3. **Inferring Core Functionality:** Based on the keywords, I started forming a mental model:
    * **Code Generation:** The name "assembler" strongly suggests it's responsible for generating low-level code. The presence of `Goto`, `Label`, and conditional branches reinforces this.
    * **Control Flow:** The various label types and conditional gotos clearly indicate mechanisms for structuring the generated code's control flow. This is essential for implementing loops, conditionals, and other program constructs.
    * **Intermediate Representation:**  The presence of `PhiOp` and the "reduction" pattern (`ReduceFoo`) suggests this assembler operates on an intermediate representation of the code before final machine code generation. Turboshaft is known to be an optimizing compiler, so this fits.
    * **Loop Handling:** The dedicated `LoopLabel` class highlights the importance of efficient loop compilation.
    * **Iteration Abstractions:** The `FOREACH` macro and its associated iterators (`Range`, `IndexRange`, etc.) suggest a higher-level way of expressing common looping patterns, likely making the assembler code more readable and maintainable.
    * **Optimization Hints:** `ConditionWithHint` points to the ability to provide optimization guidance during code generation.

4. **Addressing Specific Requests:**
    * **`.tq` Extension:** I checked if the header name ended in `.tq`. It doesn't, so it's not a Torque file.
    * **JavaScript Relation:**  I considered how this low-level assembler relates to JavaScript. The key connection is that Turboshaft *compiles* JavaScript code. Therefore, the assembler's functionality is crucial for translating JavaScript semantics into efficient machine code. I looked for JavaScript-specific examples in the provided code but didn't find direct ones. I realized I'd need to provide a conceptual JavaScript example demonstrating the *result* of what this assembler would do (e.g., how a JavaScript loop might be compiled using the assembler's looping constructs).
    * **Code Logic and Assumptions:** I looked for specific algorithmic logic but primarily found definitions of data structures and control flow mechanisms. The "assumptions" would be more about *how* the assembler is used within the larger Turboshaft pipeline (e.g., assuming a graph of operations as input).
    * **Common Programming Errors:** I thought about typical errors related to control flow and labels (e.g., jumping to the wrong label, not handling all cases). The comments within the code itself hinted at some potential errors (like `Goto` to a bound block).

5. **Structuring the Summary:** I organized the findings into logical categories:
    * **Core Functionality:** The main purpose of the assembler.
    * **Key Features:**  Specific mechanisms and abstractions it provides.
    * **No Torque Source:** Addressing the file extension check.
    * **JavaScript Relationship:** Explaining the connection to JavaScript compilation.
    * **Code Logic and Assumptions:** Highlighting the focus on control flow.
    * **Common Errors:** Providing examples of potential issues.

6. **Refining the Language:** I used clear and concise language, avoiding overly technical jargon where possible. I tried to connect the C++ concepts to their higher-level purpose in compilation. For example, instead of just saying "it has labels," I explained *why* it has labels (for control flow).

7. **Self-Correction/Refinement:**  Initially, I might have focused too much on the low-level details of individual macros or classes. I then stepped back to emphasize the *overall purpose* and how the different components contribute to that purpose. I also made sure to directly address each point in the original request. For instance, I initially missed the explicit instruction to provide a JavaScript example, so I added that in.

By following these steps, I could dissect the C++ header file, infer its functionality within the V8 compiler, and present a comprehensive summary that addresses the specific points of the request.
```cpp
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMPILER_TURBOSHAFT_ASSEMBLER_H_
#define V8_COMPILER_TURBOSHAFT_ASSEMBLER_H_

#include <cstring>
#include <iomanip>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <type_traits>
#include <utility>

#include "include/v8-source-location.h"
#include "src/base/logging.h"
#include "src/base/macros.h"
#include "src/base/small-vector.h"
#include "src/base/string-format.h"
#include "src/base/template-utils.h"
#include "src/base/vector.h"
#include "src/codegen/callable.h"
#include "src/codegen/code-factory.h"
#include "src/codegen/heap-object-list.h"
#include "src/codegen/reloc-info.h"
#include "src/compiler/access-builder.h"
#include "src/compiler/code-assembler.h"
#include "src/compiler/common-operator.h"
#include "src/compiler/globals.h"
#include "src/compiler/js-heap-broker.h"
#include "src/compiler/simplified-operator.h"
#include "src/compiler/turboshaft/access-builder.h"
#include "src/compiler/turboshaft/builtin-call-descriptors.h"
#include "src/compiler/turboshaft/graph.h"
#include "src/compiler/turboshaft/index.h"
#include "src/compiler/turboshaft/operation-matcher.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/phase.h"
#include "src/compiler/turboshaft/reducer-traits.h"
#include "src/compiler/turboshaft/representations.h"
#include "src/compiler/turboshaft/runtime-call-descriptors.h"
#include "src/compiler/turboshaft/sidetable.h"
#include "src/compiler/turboshaft/snapshot-table.h"
#include "src/compiler/turboshaft/uniform-reducer-adapter.h"
#include "src/compiler/turboshaft/utils.h"
#include "src/compiler/write-barrier-kind.h"
#include "src/flags/flags.h"
#include "src/logging/runtime-call-stats.h"
#include "src/objects/dictionary.h"
#include "src/objects/elements-kind.h"
#include "src/objects/fixed-array.h"
#include "src/objects/heap-number.h"
#include "src/objects/oddball.h"
#include "src/objects/property-cell.h"
#include "src/objects/scope-info.h"
#include "src/objects/swiss-name-dictionary.h"
#include "src/objects/tagged.h"
#include "src/objects/turbofan-types.h"

#ifdef V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-objects.h"
#endif

namespace v8::internal {
enum class Builtin : int32_t;
}

namespace v8::internal::compiler::turboshaft {

#include "src/compiler/turboshaft/define-assembler-macros.inc"

template <class AssemblerT>
class CatchScopeImpl;

// GotoIf(cond, dst) and GotoIfNot(cond, dst) are not guaranteed to actually
// generate a Branch with `dst` as one of the destination, because some reducer
// in the stack could realize that `cond` is statically known and optimize away
// the Branch. Thus, GotoIf and GotoIfNot return a {ConditionalGotoStatus},
// which represents whether a GotoIf/GotoIfNot was emitted as a Branch or a Goto
// (and if a Goto, then to what: `dst` or the fallthrough block).
enum ConditionalGotoStatus {
  kGotoDestination = 1,  // The conditional Goto became an unconditional Goto to
                         // the destination.
  kGotoEliminated = 2,   // The conditional GotoIf/GotoIfNot would never be
                         // executed and only the fallthrough path remains.
  kBranch = 3            // The conditional Goto became a branch.

  // Some examples of this:
  //   GotoIf(true, dst)     ===> kGotoDestination
  //   GotoIf(false, dst)    ===> kGotoEliminated
  //   GotoIf(var, dst)      ===> kBranch
  //   GotoIfNot(true, dst)  ===> kGotoEliminated
  //   GotoIfNot(false, dst) ===> kGotoDestination
  //   GotoIfNot(var, dst)   ===> kBranch
};
static_assert((ConditionalGotoStatus::kGotoDestination |
               ConditionalGotoStatus::kGotoEliminated) ==
              ConditionalGotoStatus::kBranch);

template <typename It, typename A>
concept ForeachIterable = requires(It iterator, A& assembler) {
  { iterator.Begin(assembler) } -> std::same_as<typename It::iterator_type>;
  {
    iterator.IsEnd(assembler, typename It::iterator_type{})
  } -> std::same_as<OptionalV<Word32>>;
  {
    iterator.Advance(assembler, typename It::iterator_type{})
  } -> std::same_as<typename It::iterator_type>;
  {
    iterator.Dereference(assembler, typename It::iterator_type{})
  } -> std::same_as<typename It::value_type>;
};

// `Range<T>` implements the `ForeachIterable` concept to iterate over a range
// of values inside a `FOREACH` loop. The range can be specified with a begin,
// an (exclusive) end and an optional stride.
//
// Example:
//
//   FOREACH(offset, Range(start, end, 4)) {
//     // Load the value at `offset`.
//     auto value = __ Load(offset, LoadOp::Kind::RawAligned(), ...);
//     // ...
//   }
//
template <typename T>
class Range {
 public:
  using value_type = V<T>;
  using iterator_type = value_type;

  Range(ConstOrV<T> begin, ConstOrV<T> end, ConstOrV<T> stride = 1)
      : begin_(begin), end_(end), stride_(stride) {}

  template <typename A>
  iterator_type Begin(A& assembler) const {
    return assembler.resolve(begin_);
  }

  template <typename A>
  OptionalV<Word32> IsEnd(A& assembler, iterator_type current_iterator) const {
    if constexpr (std::is_same_v<T, Word32>) {
      return assembler.Uint32LessThanOrEqual(assembler.resolve(end_),
                                             current_iterator);
    } else {
      static_assert(std::is_same_v<T, Word64>);
      return assembler.Uint64LessThanOrEqual(assembler.resolve(end_),
                                             current_iterator);
    }
  }

  template <typename A>
  iterator_type Advance(A& assembler, iterator_type current_iterator) const {
    if constexpr (std::is_same_v<T, Word32>) {
      return assembler.Word32Add(current_iterator, assembler.resolve(stride_));
    } else {
      static_assert(std::is_same_v<T, Word64>);
      return assembler.Word64Add(current_iterator, assembler.resolve(stride_));
    }
  }

  template <typename A>
  value_type Dereference(A& assembler, iterator_type current_iterator) const {
    return current_iterator;
  }

 private:
  ConstOrV<T> begin_;
  ConstOrV<T> end_;
  ConstOrV<T> stride_;
};

// Deduction guides for `Range`.
template <typename T>
Range(V<T>, V<T>, V<T>) -> Range<T>;
template <typename T>
Range(V<T>, V<T>, typename ConstOrV<T>::constant_type) -> Range<T>;
template <typename T>
Range(V<T>, typename ConstOrV<T>::constant_type,
      typename ConstOrV<T>::constant_type) -> Range<T>;

// `IndexRange<T>` is a short hand for a Range<T> that iterates the range [0,
// count) with steps of 1. This is the ideal iterator to generate a `for(int i =
// 0; i < count; ++i) {}`-style loop.
//
//  Example:
//
//    FOREACH(i, IndexRange(count)) { ... }
//
template <typename T>
class IndexRange : public Range<T> {
 public:
  using base = Range<T>;
  using value_type = base::value_type;
  using iterator_type = base::iterator_type;

  explicit IndexRange(ConstOrV<T> count) : Range<T>(0, count, 1) {}
};

// `Sequence<T>` implements the `ForeachIterable` concept to iterate an
// unlimited sequence of inside a `FOREACH` loop. The iteration begins at the
// given start value and during each iteration the value is incremented by the
// optional `stride` argument. Note that there is no termination condition, so
// the end of the loop needs to be terminated in another way. This could be
// either by a conditional break inside the loop or by combining the `Sequence`
// iterator with another iterator that provides the termination condition (see
// Zip below).
//
// Example:
//
//   FOREACH(index, Sequence<WordPtr>(0)) {
//     // ...
//     V<Object> value = __ Load(object, index, LoadOp::Kind::TaggedBase(),
//                               offset, field_size);
//     GOTO_IF(__ IsSmi(value), done, index);
//   }
//
template <typename T>
class Sequence : private Range<T> {
  using base = Range<T>;

 public:
  using value_type = base::value_type;
  using iterator_type = base::iterator_type;

  explicit Sequence(ConstOrV<T> begin, ConstOrV<T> stride = 1)
      : base(begin, 0, stride) {}

  using base::Advance;
  using base::Begin;
  using base::Dereference;

  template <typename A>
  OptionalV<Word32> IsEnd(A&, iterator_type) const {
    // Sequence doesn't have a termination condition.
    return OptionalV<Word32>::Nullopt();
  }
};

// Deduction guide for `Sequence`.
template <typename T>
Sequence(V<T>, V<T>) -> Sequence<T>;
template <typename T>
Sequence(V<T>, typename ConstOrV<T>::constant_type) -> Sequence<T>;
template <typename T>
Sequence(V<T>) -> Sequence<T>;

// `Zip<T>` implements the `ForeachIterable` concept to iterate multiple
// iterators at the same time inside a `FOREACH` loop. The loop terminates once
// any of the zipped iterators signals end of iteration. The number of iteration
// variables specified in the `FOREACH` loop has to match the number of zipped
// iterators.
//
// Example:
//
//   FOREACH(offset, index, Zip(Range(start, end, 4),
//                              Sequence<Word32>(0)) {
//     // `offset` iterates [start, end) with steps of 4.
//     // `index` counts 0, 1, 2, ...
//   }
//
// NOTE: The generated loop is only controlled by the `offset < end` condition
// as `Sequence` has no upper bound. Hence, the above loop resembles a loop like
// (assuming start, end and therefore offset are WordPtr):
//
//   for(auto [offset, index] = {start, 0};
//       offset < end;
//       offset += 4, ++index) {
//     // ...
//   }
//
template <typename... Iterables>
class Zip {
 public:
  using value_type = std::tuple<typename Iterables::value_type...>;
  using iterator_type = std::tuple<typename Iterables::iterator_type...>;

  explicit Zip(Iterables... iterables) : iterables_(std::move(iterables)...) {}

  template <typename A>
  iterator_type Begin(A& assembler) {
    return base::tuple_map(
        iterables_, [&assembler](auto& it) { return it.Begin(assembler); });
  }

  template <typename A>
  OptionalV<Word32> IsEnd(A& assembler, iterator_type current_iterator) {
    // TODO(nicohartmann): Currently we don't short-circuit the disjunction here
    // because that's slightly more difficult to do with the current `IsEnd`
    // predicate. We can consider making this more powerful if we see use cases.
    auto results = base::tuple_map2(iterables_, current_iterator,
                                    [&assembler](auto& it, auto current) {
                                      return it.IsEnd(assembler, current);
                                    });
    return base::tuple_fold(
        OptionalV<Word32>::Nullopt(), results,
        [&assembler](OptionalV<Word32> acc, OptionalV<Word32> next) {
          if (!next.has_value()) return acc;
          if (!acc.has_value()) return next;
          return OptionalV(
              assembler.Word32BitwiseOr(acc.value(), next.value()));
        });
  }

  template <typename A>
  iterator_type Advance(A& assembler, iterator_type current_iterator) {
    return base::tuple_map2(iterables_, current_iterator,
                            [&assembler](auto& it, auto current) {
                              return it.Advance(assembler, current);
                            });
  }

  template <typename A>
  value_type Dereference(A& assembler, iterator_type current_iterator) {
    return base::tuple_map2(iterables_, current_iterator,
                            [&assembler](auto& it, auto current) {
                              return it.Dereference(assembler, current);
                            });
  }

 private:
  std::tuple<Iterables...> iterables_;
};

// Deduction guide for `Zip`.
template <typename... Iterables>
Zip(Iterables... iterables) -> Zip<Iterables...>;

class ConditionWithHint final {
 public:
  ConditionWithHint(
      V<Word32> condition,
      BranchHint hint = BranchHint::kNone)  // NOLINT(runtime/explicit)
      : condition_(condition), hint_(hint) {}

  template <typename T, typename = std::enable_if_t<std::is_same_v<T, OpIndex>>>
  ConditionWithHint(
      T condition,
      BranchHint hint = BranchHint::kNone)  // NOLINT(runtime/explicit)
      : ConditionWithHint(V<Word32>{condition}, hint) {}

  V<Word32> condition() const { return condition_; }
  BranchHint hint() const { return hint_; }

 private:
  V<Word32> condition_;
  BranchHint hint_;
};

namespace detail {
template <typename A, typename ConstOrValues>
auto ResolveAll(A& assembler, const ConstOrValues& const_or_values) {
  return std::apply(
      [&](auto&... args) { return std::tuple{assembler.resolve(args)...}; },
      const_or_values);
}

template <typename T>
struct IndexTypeFor {
  using type = OpIndex;
};
template <typename T>
struct IndexTypeFor<std::tuple<T>> {
  using type = T;
};

template <typename T>
using index_type_for_t = typename IndexTypeFor<T>::type;

inline bool SuppressUnusedWarning(bool b) { return b; }
template <typename T>
auto unwrap_unary_tuple(std::tuple<T>&& tpl) {
  return std::get<0>(std::forward<std::tuple<T>>(tpl));
}
template <typename T1, typename T2, typename... Rest>
auto unwrap_unary_tuple(std::tuple<T1, T2, Rest...>&& tpl) {
  return tpl;
}
}  // namespace detail

template <bool loop, typename... Ts>
class LabelBase {
 protected:
  static constexpr size_t size = sizeof...(Ts);

  LabelBase(const LabelBase&) = delete;
  LabelBase& operator=(const LabelBase&) = delete;

 public:
  static constexpr bool is_loop = loop;
  using values_t = std::tuple<V<Ts>...>;
  using const_or_values_t = std::tuple<maybe_const_or_v_t<Ts>...>;
  using recorded_values_t = std::tuple<base::SmallVector<V<Ts>, 2>...>;

  Block* block() { return data_.block; }

  bool has_incoming_jump() const { return has_incoming_jump_; }

  template <typename A>
  void Goto(A& assembler, const values_t& values) {
    if (assembler.generating_unreachable_operations()) return;
    has_incoming_jump_ = true;
    Block* current_block = assembler.current_block();
    DCHECK_NOT_NULL(current_block);
    assembler.Goto(data_.block);
    RecordValues(current_block, data_, values);
  }

  template <typename A>
  void GotoIf(A& assembler, OpIndex condition, BranchHint hint,
              const values_t& values) {
    if (assembler.generating_unreachable_operations()) return;
    has_incoming_jump_ = true;
    Block* current_block = assembler.current_block();
    DCHECK_NOT_NULL(current_block);
    if (assembler.GotoIf(condition, data_.block, hint) &
        ConditionalGotoStatus::kGotoDestination) {
      RecordValues(current_block, data_, values);
    }
  }

  template <typename A>
  void GotoIfNot(A& assembler, OpIndex condition, BranchHint hint,
                 const values_t& values) {
    if (assembler.generating_unreachable_operations()) return;
    has_incoming_jump_ = true;
    Block* current_block = assembler.current_block();
    DCHECK_NOT_NULL(current_block);
    if (assembler.GotoIfNot(condition, data_.block, hint) &
        ConditionalGotoStatus::kGotoDestination) {
      RecordValues(current_block, data_, values);
    }
  }

  template <typename A>
  base::prepend_tuple_type<bool, values_t> Bind(A& assembler) {
    DCHECK(!data_.block->IsBound());
    if (!assembler.Bind(data_.block)) {
      return std::tuple_cat(std::tuple{false}, values_t{});
    }
    DCHECK_EQ(data_.block, assembler.current_block());
    return std::tuple_cat(std::tuple{true}, MaterializePhis(assembler));
  }

 protected:
  struct BlockData {
    Block* block;
    base::SmallVector<Block*, 4> predecessors;
    recorded_values_t recorded_values;

    explicit BlockData(Block* block) : block(block) {}
  };

  explicit LabelBase(Block* block) : data_(block) {
    DCHECK_NOT_NULL(data_.block);
  }

  LabelBase(LabelBase&& other) V8_NOEXCEPT
      : data_(std::move(other.data_)),
        has_incoming_jump_(other.has_incoming_jump_) {}

  static void RecordValues(Block* source, BlockData& data,
                           const values_t& values) {
    DCHECK_NOT_NULL(source);
    if (data.block->IsBound()) {
      // Cannot `Goto` to a bound block. If you are trying to construct a
      // loop, use a `LoopLabel` instead!
      UNREACHABLE();
    }
    RecordValuesImpl(data, source, values, std::make_index_sequence<size>());
  }

  template <size_t... indices>
  static void RecordValuesImpl(BlockData& data, Block* source,
                               const values_t& values,
                               std::index_sequence<indices...>) {
#ifdef DEBUG
    std::initializer_list<size_t> sizes{
        std::get<indices>(data.recorded_values).size()...};
    // There a -1 on the PredecessorCounts below, because we've emitted the
    // Goto/Branch before calling RecordValues (which we do because the
    // condition of the Goto might have been constant-folded, resulting in the
    // destination not actually being reachable).
    DCHECK(base::all_equal(
        sizes, static_cast<size_t>(data.block->PredecessorCount() - 1)));
    DCHECK_EQ(data.block->PredecessorCount() - 1, data.predecessors.size());
#endif
    (std::get<indices>(data.recorded_values)
         .push_back(std::get<indices>(values)),
     ...);
    data.predecessors.push_back(source);
  }

  template <typename A>
  values_t MaterializePhis(A& assembler) {
    return MaterializePhisImpl(assembler, data_,
                               std::make_index_sequence<size>());
  }

  template <typename A, size_t... indices>
  static values_t MaterializePhisImpl(A& assembler, BlockData& data,
                                      std::index_sequence<indices...>) {
    size_t predecessor_count = data.block->PredecessorCount();
    DCHECK_EQ(data.predecessors.size(), predecessor_count);
    // If this label has no values, we don't need any Phis.
    if constexpr (size == 0) return values_t{};

    // If this block does not have any predecessors, we shouldn't call this.
    DCHECK_LT(0, predecessor_count);
    // With 1 predecessor, we don't need any Phis.
    if (predecessor_count == 1) {
      return values_t{std::get<indices>(data.recorded_values)[0]...};
    }
    DCHECK_LT(1, predecessor_count);

    // Construct Phis.
    return values_t{assembler.Phi(
        base::VectorOf(std::get<indices>(data.recorded_values)))...};
  }

  BlockData data_;
  bool has_incoming_jump_ = false;
};

template <typename... Ts>
class Label : public LabelBase<false, Ts...> {
  using super = LabelBase<false, Ts...>;

  Label(const Label&) = delete;
  Label& operator=(const Label&) = delete;

 public:
  template <typename Reducer>
  explicit Label(Reducer* reducer) : super(reducer->Asm().NewBlock()) {}

  Label(Label&& other) V8_NOEXCEPT : super(std::move(other)) {}
};

template <typename... Ts>
class LoopLabel : public LabelBase<true, Ts...> {
  using super = LabelBase<true, Ts...>;
  using BlockData = typename super::BlockData;

  LoopLabel(const LoopLabel&) = delete;
  LoopLabel& operator=(const LoopLabel&) = delete;

 public:
  using values_t = typename super::values_t;
  template <typename Reducer>
  explicit LoopLabel(Reducer* reducer)
      : super(reducer->Asm().NewBlock()),
        loop_header_data_{reducer->Asm().NewLoopHeader()} {}

  LoopLabel(LoopLabel&& other) V8_NOEXCEPT
      : super(std::move(other)),
        loop_header_data_(std::move(other.loop_header_data_)),
        pending_loop_phis_(std::move(other.pending_loop_phis_)) {}

  Block* loop_header() const { return loop_header_data_.block; }

  template <typename A>
  void Goto(A& assembler, const values_t& values) {
    if (assembler.generating_unreachable_operations()) return;
    if (!loop_header_data_.block->IsBound()) {
      // If the loop header is not bound yet, we have the forward edge to the
      // loop.
      DCHECK_EQ(0, loop_header_data_.block->PredecessorCount());
      Block* current_block = assembler.current_block();
      DCHECK_NOT_NULL(current_block);
      assembler.Goto(loop_header_data_.block);
      super::RecordValues(current_block, loop_header_data_, values);
    } else {
      // We have a jump back to the loop header and wire it to the single
      // backedge block.
      this->super::Goto(assembler, values);
    }
  }

  template <typename A>
  void GotoIf(A& assembler, OpIndex condition, BranchHint hint,
              const values_t& values) {
    if (assembler.generating_unreachable_operations()) return;
    if (!loop_header_data_.block->IsBound()) {
      // If the loop header is not bound yet, we have the forward edge to the
      // loop.
      DCHECK_EQ(0, loop_header_data_.block->PredecessorCount());
      Block* current_block = assembler.current_block();
      DCHECK_NOT_NULL(current_block);
      if (assembler.GotoIf(condition, loop_header_data_.block, hint) &
          ConditionalGotoStatus::kGotoDestination) {
        super::RecordValues(current_block, loop_header_data_, values);
      }
    } else {
      // We have a jump back to the loop header and wire it to the single
      // backedge block.
      this->super::GotoIf(assembler, condition, hint, values);
    }
  }

  template <typename A>
  void GotoIfNot(A& assembler, OpIndex condition, BranchHint hint,
                 const values_t& values) {
    if (assembler.generating_unreachable_operations()) return;
    if (!loop_header_data_.block->IsBound()) {
      // If the loop header is not bound yet, we have the forward edge to the
      // loop.
      DCHECK_EQ(0, loop_header_data_.block->PredecessorCount());
      Block* current_block = assembler.current_block();
      DCHECK_NOT_NULL(current_block);
      if (assembler.GotoIf(condition, loop_header_data_.block, hint) &
          ConditionalGotoStatus::kGotoDestination) {
        super::RecordValues(current_block, loop_header_data_, values);
      }
    } else {
      // We have a jump back to the loop header and wire it to the single
      // backedge block.
      this->super::GotoIfNot(assembler, condition, hint, values);
    }
  }

  template <typename A>
  base::prepend_tuple_type<bool, values_t> Bind(A& assembler) {
    // LoopLabels must not be bound  using `Bind`, but with `Loop`.
    UNREACHABLE();
  }

  template <typename A>
  base::prepend_tuple_type<bool, values_t> BindLoop(A& assembler) {
    DCHECK(!loop_header_data_.block->IsBound());
    if (!assembler.Bind(loop_header_data_.block)) {
      return std::tuple_cat(std::tuple{false}, values_t{});
    }
    DCHECK_EQ(loop_header_data_.block, assembler.current_block());
    values_t pending_loop_phis =
        MaterializeLoopPhis(assembler, loop_header_data_);
    pending_loop_phis_ = pending_loop_phis;
    return std::tuple_cat(std::tuple{true}, pending_loop_phis);
  }

  template <typename A>
  void EndLoop(A& assembler) {
    // First, we need to bind the backedge block.
    auto bind_result = this->super::Bind(assembler);
    // `Bind` returns a tuple with a `bool` as first entry that indicates
    // whether the block was bound. The rest of the tuple contains the phi
    // values. Check if this block was bound (aka is reachable).
    if (std::get<
Prompt: 
```
这是目录为v8/src/compiler/turboshaft/assembler.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/assembler.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共8部分，请归纳一下它的功能

"""
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMPILER_TURBOSHAFT_ASSEMBLER_H_
#define V8_COMPILER_TURBOSHAFT_ASSEMBLER_H_

#include <cstring>
#include <iomanip>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <type_traits>
#include <utility>

#include "include/v8-source-location.h"
#include "src/base/logging.h"
#include "src/base/macros.h"
#include "src/base/small-vector.h"
#include "src/base/string-format.h"
#include "src/base/template-utils.h"
#include "src/base/vector.h"
#include "src/codegen/callable.h"
#include "src/codegen/code-factory.h"
#include "src/codegen/heap-object-list.h"
#include "src/codegen/reloc-info.h"
#include "src/compiler/access-builder.h"
#include "src/compiler/code-assembler.h"
#include "src/compiler/common-operator.h"
#include "src/compiler/globals.h"
#include "src/compiler/js-heap-broker.h"
#include "src/compiler/simplified-operator.h"
#include "src/compiler/turboshaft/access-builder.h"
#include "src/compiler/turboshaft/builtin-call-descriptors.h"
#include "src/compiler/turboshaft/graph.h"
#include "src/compiler/turboshaft/index.h"
#include "src/compiler/turboshaft/operation-matcher.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/phase.h"
#include "src/compiler/turboshaft/reducer-traits.h"
#include "src/compiler/turboshaft/representations.h"
#include "src/compiler/turboshaft/runtime-call-descriptors.h"
#include "src/compiler/turboshaft/sidetable.h"
#include "src/compiler/turboshaft/snapshot-table.h"
#include "src/compiler/turboshaft/uniform-reducer-adapter.h"
#include "src/compiler/turboshaft/utils.h"
#include "src/compiler/write-barrier-kind.h"
#include "src/flags/flags.h"
#include "src/logging/runtime-call-stats.h"
#include "src/objects/dictionary.h"
#include "src/objects/elements-kind.h"
#include "src/objects/fixed-array.h"
#include "src/objects/heap-number.h"
#include "src/objects/oddball.h"
#include "src/objects/property-cell.h"
#include "src/objects/scope-info.h"
#include "src/objects/swiss-name-dictionary.h"
#include "src/objects/tagged.h"
#include "src/objects/turbofan-types.h"

#ifdef V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-objects.h"
#endif

namespace v8::internal {
enum class Builtin : int32_t;
}

namespace v8::internal::compiler::turboshaft {

#include "src/compiler/turboshaft/define-assembler-macros.inc"

template <class AssemblerT>
class CatchScopeImpl;

// GotoIf(cond, dst) and GotoIfNot(cond, dst) are not guaranteed to actually
// generate a Branch with `dst` as one of the destination, because some reducer
// in the stack could realize that `cond` is statically known and optimize away
// the Branch. Thus, GotoIf and GotoIfNot return a {ConditionalGotoStatus},
// which represents whether a GotoIf/GotoIfNot was emitted as a Branch or a Goto
// (and if a Goto, then to what: `dst` or the fallthrough block).
enum ConditionalGotoStatus {
  kGotoDestination = 1,  // The conditional Goto became an unconditional Goto to
                         // the destination.
  kGotoEliminated = 2,   // The conditional GotoIf/GotoIfNot would never be
                         // executed and only the fallthrough path remains.
  kBranch = 3            // The conditional Goto became a branch.

  // Some examples of this:
  //   GotoIf(true, dst)     ===> kGotoDestination
  //   GotoIf(false, dst)    ===> kGotoEliminated
  //   GotoIf(var, dst)      ===> kBranch
  //   GotoIfNot(true, dst)  ===> kGotoEliminated
  //   GotoIfNot(false, dst) ===> kGotoDestination
  //   GotoIfNot(var, dst)   ===> kBranch
};
static_assert((ConditionalGotoStatus::kGotoDestination |
               ConditionalGotoStatus::kGotoEliminated) ==
              ConditionalGotoStatus::kBranch);

template <typename It, typename A>
concept ForeachIterable = requires(It iterator, A& assembler) {
  { iterator.Begin(assembler) } -> std::same_as<typename It::iterator_type>;
  {
    iterator.IsEnd(assembler, typename It::iterator_type{})
  } -> std::same_as<OptionalV<Word32>>;
  {
    iterator.Advance(assembler, typename It::iterator_type{})
  } -> std::same_as<typename It::iterator_type>;
  {
    iterator.Dereference(assembler, typename It::iterator_type{})
  } -> std::same_as<typename It::value_type>;
};

// `Range<T>` implements the `ForeachIterable` concept to iterate over a range
// of values inside a `FOREACH` loop. The range can be specified with a begin,
// an (exclusive) end and an optional stride.
//
// Example:
//
//   FOREACH(offset, Range(start, end, 4)) {
//     // Load the value at `offset`.
//     auto value = __ Load(offset, LoadOp::Kind::RawAligned(), ...);
//     // ...
//   }
//
template <typename T>
class Range {
 public:
  using value_type = V<T>;
  using iterator_type = value_type;

  Range(ConstOrV<T> begin, ConstOrV<T> end, ConstOrV<T> stride = 1)
      : begin_(begin), end_(end), stride_(stride) {}

  template <typename A>
  iterator_type Begin(A& assembler) const {
    return assembler.resolve(begin_);
  }

  template <typename A>
  OptionalV<Word32> IsEnd(A& assembler, iterator_type current_iterator) const {
    if constexpr (std::is_same_v<T, Word32>) {
      return assembler.Uint32LessThanOrEqual(assembler.resolve(end_),
                                             current_iterator);
    } else {
      static_assert(std::is_same_v<T, Word64>);
      return assembler.Uint64LessThanOrEqual(assembler.resolve(end_),
                                             current_iterator);
    }
  }

  template <typename A>
  iterator_type Advance(A& assembler, iterator_type current_iterator) const {
    if constexpr (std::is_same_v<T, Word32>) {
      return assembler.Word32Add(current_iterator, assembler.resolve(stride_));
    } else {
      static_assert(std::is_same_v<T, Word64>);
      return assembler.Word64Add(current_iterator, assembler.resolve(stride_));
    }
  }

  template <typename A>
  value_type Dereference(A& assembler, iterator_type current_iterator) const {
    return current_iterator;
  }

 private:
  ConstOrV<T> begin_;
  ConstOrV<T> end_;
  ConstOrV<T> stride_;
};

// Deduction guides for `Range`.
template <typename T>
Range(V<T>, V<T>, V<T>) -> Range<T>;
template <typename T>
Range(V<T>, V<T>, typename ConstOrV<T>::constant_type) -> Range<T>;
template <typename T>
Range(V<T>, typename ConstOrV<T>::constant_type,
      typename ConstOrV<T>::constant_type) -> Range<T>;

// `IndexRange<T>` is a short hand for a Range<T> that iterates the range [0,
// count) with steps of 1. This is the ideal iterator to generate a `for(int i =
// 0; i < count; ++i) {}`-style loop.
//
//  Example:
//
//    FOREACH(i, IndexRange(count)) { ... }
//
template <typename T>
class IndexRange : public Range<T> {
 public:
  using base = Range<T>;
  using value_type = base::value_type;
  using iterator_type = base::iterator_type;

  explicit IndexRange(ConstOrV<T> count) : Range<T>(0, count, 1) {}
};

// `Sequence<T>` implements the `ForeachIterable` concept to iterate an
// unlimited sequence of inside a `FOREACH` loop. The iteration begins at the
// given start value and during each iteration the value is incremented by the
// optional `stride` argument. Note that there is no termination condition, so
// the end of the loop needs to be terminated in another way. This could be
// either by a conditional break inside the loop or by combining the `Sequence`
// iterator with another iterator that provides the termination condition (see
// Zip below).
//
// Example:
//
//   FOREACH(index, Sequence<WordPtr>(0)) {
//     // ...
//     V<Object> value = __ Load(object, index, LoadOp::Kind::TaggedBase(),
//                               offset, field_size);
//     GOTO_IF(__ IsSmi(value), done, index);
//   }
//
template <typename T>
class Sequence : private Range<T> {
  using base = Range<T>;

 public:
  using value_type = base::value_type;
  using iterator_type = base::iterator_type;

  explicit Sequence(ConstOrV<T> begin, ConstOrV<T> stride = 1)
      : base(begin, 0, stride) {}

  using base::Advance;
  using base::Begin;
  using base::Dereference;

  template <typename A>
  OptionalV<Word32> IsEnd(A&, iterator_type) const {
    // Sequence doesn't have a termination condition.
    return OptionalV<Word32>::Nullopt();
  }
};

// Deduction guide for `Sequence`.
template <typename T>
Sequence(V<T>, V<T>) -> Sequence<T>;
template <typename T>
Sequence(V<T>, typename ConstOrV<T>::constant_type) -> Sequence<T>;
template <typename T>
Sequence(V<T>) -> Sequence<T>;

// `Zip<T>` implements the `ForeachIterable` concept to iterate multiple
// iterators at the same time inside a `FOREACH` loop. The loop terminates once
// any of the zipped iterators signals end of iteration. The number of iteration
// variables specified in the `FOREACH` loop has to match the number of zipped
// iterators.
//
// Example:
//
//   FOREACH(offset, index, Zip(Range(start, end, 4),
//                              Sequence<Word32>(0)) {
//     // `offset` iterates [start, end) with steps of 4.
//     // `index` counts 0, 1, 2, ...
//   }
//
// NOTE: The generated loop is only controlled by the `offset < end` condition
// as `Sequence` has no upper bound. Hence, the above loop resembles a loop like
// (assuming start, end and therefore offset are WordPtr):
//
//   for(auto [offset, index] = {start, 0};
//       offset < end;
//       offset += 4, ++index) {
//     // ...
//   }
//
template <typename... Iterables>
class Zip {
 public:
  using value_type = std::tuple<typename Iterables::value_type...>;
  using iterator_type = std::tuple<typename Iterables::iterator_type...>;

  explicit Zip(Iterables... iterables) : iterables_(std::move(iterables)...) {}

  template <typename A>
  iterator_type Begin(A& assembler) {
    return base::tuple_map(
        iterables_, [&assembler](auto& it) { return it.Begin(assembler); });
  }

  template <typename A>
  OptionalV<Word32> IsEnd(A& assembler, iterator_type current_iterator) {
    // TODO(nicohartmann): Currently we don't short-circuit the disjunction here
    // because that's slightly more difficult to do with the current `IsEnd`
    // predicate. We can consider making this more powerful if we see use cases.
    auto results = base::tuple_map2(iterables_, current_iterator,
                                    [&assembler](auto& it, auto current) {
                                      return it.IsEnd(assembler, current);
                                    });
    return base::tuple_fold(
        OptionalV<Word32>::Nullopt(), results,
        [&assembler](OptionalV<Word32> acc, OptionalV<Word32> next) {
          if (!next.has_value()) return acc;
          if (!acc.has_value()) return next;
          return OptionalV(
              assembler.Word32BitwiseOr(acc.value(), next.value()));
        });
  }

  template <typename A>
  iterator_type Advance(A& assembler, iterator_type current_iterator) {
    return base::tuple_map2(iterables_, current_iterator,
                            [&assembler](auto& it, auto current) {
                              return it.Advance(assembler, current);
                            });
  }

  template <typename A>
  value_type Dereference(A& assembler, iterator_type current_iterator) {
    return base::tuple_map2(iterables_, current_iterator,
                            [&assembler](auto& it, auto current) {
                              return it.Dereference(assembler, current);
                            });
  }

 private:
  std::tuple<Iterables...> iterables_;
};

// Deduction guide for `Zip`.
template <typename... Iterables>
Zip(Iterables... iterables) -> Zip<Iterables...>;

class ConditionWithHint final {
 public:
  ConditionWithHint(
      V<Word32> condition,
      BranchHint hint = BranchHint::kNone)  // NOLINT(runtime/explicit)
      : condition_(condition), hint_(hint) {}

  template <typename T, typename = std::enable_if_t<std::is_same_v<T, OpIndex>>>
  ConditionWithHint(
      T condition,
      BranchHint hint = BranchHint::kNone)  // NOLINT(runtime/explicit)
      : ConditionWithHint(V<Word32>{condition}, hint) {}

  V<Word32> condition() const { return condition_; }
  BranchHint hint() const { return hint_; }

 private:
  V<Word32> condition_;
  BranchHint hint_;
};

namespace detail {
template <typename A, typename ConstOrValues>
auto ResolveAll(A& assembler, const ConstOrValues& const_or_values) {
  return std::apply(
      [&](auto&... args) { return std::tuple{assembler.resolve(args)...}; },
      const_or_values);
}

template <typename T>
struct IndexTypeFor {
  using type = OpIndex;
};
template <typename T>
struct IndexTypeFor<std::tuple<T>> {
  using type = T;
};

template <typename T>
using index_type_for_t = typename IndexTypeFor<T>::type;

inline bool SuppressUnusedWarning(bool b) { return b; }
template <typename T>
auto unwrap_unary_tuple(std::tuple<T>&& tpl) {
  return std::get<0>(std::forward<std::tuple<T>>(tpl));
}
template <typename T1, typename T2, typename... Rest>
auto unwrap_unary_tuple(std::tuple<T1, T2, Rest...>&& tpl) {
  return tpl;
}
}  // namespace detail

template <bool loop, typename... Ts>
class LabelBase {
 protected:
  static constexpr size_t size = sizeof...(Ts);

  LabelBase(const LabelBase&) = delete;
  LabelBase& operator=(const LabelBase&) = delete;

 public:
  static constexpr bool is_loop = loop;
  using values_t = std::tuple<V<Ts>...>;
  using const_or_values_t = std::tuple<maybe_const_or_v_t<Ts>...>;
  using recorded_values_t = std::tuple<base::SmallVector<V<Ts>, 2>...>;

  Block* block() { return data_.block; }

  bool has_incoming_jump() const { return has_incoming_jump_; }

  template <typename A>
  void Goto(A& assembler, const values_t& values) {
    if (assembler.generating_unreachable_operations()) return;
    has_incoming_jump_ = true;
    Block* current_block = assembler.current_block();
    DCHECK_NOT_NULL(current_block);
    assembler.Goto(data_.block);
    RecordValues(current_block, data_, values);
  }

  template <typename A>
  void GotoIf(A& assembler, OpIndex condition, BranchHint hint,
              const values_t& values) {
    if (assembler.generating_unreachable_operations()) return;
    has_incoming_jump_ = true;
    Block* current_block = assembler.current_block();
    DCHECK_NOT_NULL(current_block);
    if (assembler.GotoIf(condition, data_.block, hint) &
        ConditionalGotoStatus::kGotoDestination) {
      RecordValues(current_block, data_, values);
    }
  }

  template <typename A>
  void GotoIfNot(A& assembler, OpIndex condition, BranchHint hint,
                 const values_t& values) {
    if (assembler.generating_unreachable_operations()) return;
    has_incoming_jump_ = true;
    Block* current_block = assembler.current_block();
    DCHECK_NOT_NULL(current_block);
    if (assembler.GotoIfNot(condition, data_.block, hint) &
        ConditionalGotoStatus::kGotoDestination) {
      RecordValues(current_block, data_, values);
    }
  }

  template <typename A>
  base::prepend_tuple_type<bool, values_t> Bind(A& assembler) {
    DCHECK(!data_.block->IsBound());
    if (!assembler.Bind(data_.block)) {
      return std::tuple_cat(std::tuple{false}, values_t{});
    }
    DCHECK_EQ(data_.block, assembler.current_block());
    return std::tuple_cat(std::tuple{true}, MaterializePhis(assembler));
  }

 protected:
  struct BlockData {
    Block* block;
    base::SmallVector<Block*, 4> predecessors;
    recorded_values_t recorded_values;

    explicit BlockData(Block* block) : block(block) {}
  };

  explicit LabelBase(Block* block) : data_(block) {
    DCHECK_NOT_NULL(data_.block);
  }

  LabelBase(LabelBase&& other) V8_NOEXCEPT
      : data_(std::move(other.data_)),
        has_incoming_jump_(other.has_incoming_jump_) {}

  static void RecordValues(Block* source, BlockData& data,
                           const values_t& values) {
    DCHECK_NOT_NULL(source);
    if (data.block->IsBound()) {
      // Cannot `Goto` to a bound block. If you are trying to construct a
      // loop, use a `LoopLabel` instead!
      UNREACHABLE();
    }
    RecordValuesImpl(data, source, values, std::make_index_sequence<size>());
  }

  template <size_t... indices>
  static void RecordValuesImpl(BlockData& data, Block* source,
                               const values_t& values,
                               std::index_sequence<indices...>) {
#ifdef DEBUG
    std::initializer_list<size_t> sizes{
        std::get<indices>(data.recorded_values).size()...};
    // There a -1 on the PredecessorCounts below, because we've emitted the
    // Goto/Branch before calling RecordValues (which we do because the
    // condition of the Goto might have been constant-folded, resulting in the
    // destination not actually being reachable).
    DCHECK(base::all_equal(
        sizes, static_cast<size_t>(data.block->PredecessorCount() - 1)));
    DCHECK_EQ(data.block->PredecessorCount() - 1, data.predecessors.size());
#endif
    (std::get<indices>(data.recorded_values)
         .push_back(std::get<indices>(values)),
     ...);
    data.predecessors.push_back(source);
  }

  template <typename A>
  values_t MaterializePhis(A& assembler) {
    return MaterializePhisImpl(assembler, data_,
                               std::make_index_sequence<size>());
  }

  template <typename A, size_t... indices>
  static values_t MaterializePhisImpl(A& assembler, BlockData& data,
                                      std::index_sequence<indices...>) {
    size_t predecessor_count = data.block->PredecessorCount();
    DCHECK_EQ(data.predecessors.size(), predecessor_count);
    // If this label has no values, we don't need any Phis.
    if constexpr (size == 0) return values_t{};

    // If this block does not have any predecessors, we shouldn't call this.
    DCHECK_LT(0, predecessor_count);
    // With 1 predecessor, we don't need any Phis.
    if (predecessor_count == 1) {
      return values_t{std::get<indices>(data.recorded_values)[0]...};
    }
    DCHECK_LT(1, predecessor_count);

    // Construct Phis.
    return values_t{assembler.Phi(
        base::VectorOf(std::get<indices>(data.recorded_values)))...};
  }

  BlockData data_;
  bool has_incoming_jump_ = false;
};

template <typename... Ts>
class Label : public LabelBase<false, Ts...> {
  using super = LabelBase<false, Ts...>;

  Label(const Label&) = delete;
  Label& operator=(const Label&) = delete;

 public:
  template <typename Reducer>
  explicit Label(Reducer* reducer) : super(reducer->Asm().NewBlock()) {}

  Label(Label&& other) V8_NOEXCEPT : super(std::move(other)) {}
};

template <typename... Ts>
class LoopLabel : public LabelBase<true, Ts...> {
  using super = LabelBase<true, Ts...>;
  using BlockData = typename super::BlockData;

  LoopLabel(const LoopLabel&) = delete;
  LoopLabel& operator=(const LoopLabel&) = delete;

 public:
  using values_t = typename super::values_t;
  template <typename Reducer>
  explicit LoopLabel(Reducer* reducer)
      : super(reducer->Asm().NewBlock()),
        loop_header_data_{reducer->Asm().NewLoopHeader()} {}

  LoopLabel(LoopLabel&& other) V8_NOEXCEPT
      : super(std::move(other)),
        loop_header_data_(std::move(other.loop_header_data_)),
        pending_loop_phis_(std::move(other.pending_loop_phis_)) {}

  Block* loop_header() const { return loop_header_data_.block; }

  template <typename A>
  void Goto(A& assembler, const values_t& values) {
    if (assembler.generating_unreachable_operations()) return;
    if (!loop_header_data_.block->IsBound()) {
      // If the loop header is not bound yet, we have the forward edge to the
      // loop.
      DCHECK_EQ(0, loop_header_data_.block->PredecessorCount());
      Block* current_block = assembler.current_block();
      DCHECK_NOT_NULL(current_block);
      assembler.Goto(loop_header_data_.block);
      super::RecordValues(current_block, loop_header_data_, values);
    } else {
      // We have a jump back to the loop header and wire it to the single
      // backedge block.
      this->super::Goto(assembler, values);
    }
  }

  template <typename A>
  void GotoIf(A& assembler, OpIndex condition, BranchHint hint,
              const values_t& values) {
    if (assembler.generating_unreachable_operations()) return;
    if (!loop_header_data_.block->IsBound()) {
      // If the loop header is not bound yet, we have the forward edge to the
      // loop.
      DCHECK_EQ(0, loop_header_data_.block->PredecessorCount());
      Block* current_block = assembler.current_block();
      DCHECK_NOT_NULL(current_block);
      if (assembler.GotoIf(condition, loop_header_data_.block, hint) &
          ConditionalGotoStatus::kGotoDestination) {
        super::RecordValues(current_block, loop_header_data_, values);
      }
    } else {
      // We have a jump back to the loop header and wire it to the single
      // backedge block.
      this->super::GotoIf(assembler, condition, hint, values);
    }
  }

  template <typename A>
  void GotoIfNot(A& assembler, OpIndex condition, BranchHint hint,
                 const values_t& values) {
    if (assembler.generating_unreachable_operations()) return;
    if (!loop_header_data_.block->IsBound()) {
      // If the loop header is not bound yet, we have the forward edge to the
      // loop.
      DCHECK_EQ(0, loop_header_data_.block->PredecessorCount());
      Block* current_block = assembler.current_block();
      DCHECK_NOT_NULL(current_block);
      if (assembler.GotoIf(condition, loop_header_data_.block, hint) &
          ConditionalGotoStatus::kGotoDestination) {
        super::RecordValues(current_block, loop_header_data_, values);
      }
    } else {
      // We have a jump back to the loop header and wire it to the single
      // backedge block.
      this->super::GotoIfNot(assembler, condition, hint, values);
    }
  }

  template <typename A>
  base::prepend_tuple_type<bool, values_t> Bind(A& assembler) {
    // LoopLabels must not be bound  using `Bind`, but with `Loop`.
    UNREACHABLE();
  }

  template <typename A>
  base::prepend_tuple_type<bool, values_t> BindLoop(A& assembler) {
    DCHECK(!loop_header_data_.block->IsBound());
    if (!assembler.Bind(loop_header_data_.block)) {
      return std::tuple_cat(std::tuple{false}, values_t{});
    }
    DCHECK_EQ(loop_header_data_.block, assembler.current_block());
    values_t pending_loop_phis =
        MaterializeLoopPhis(assembler, loop_header_data_);
    pending_loop_phis_ = pending_loop_phis;
    return std::tuple_cat(std::tuple{true}, pending_loop_phis);
  }

  template <typename A>
  void EndLoop(A& assembler) {
    // First, we need to bind the backedge block.
    auto bind_result = this->super::Bind(assembler);
    // `Bind` returns a tuple with a `bool` as first entry that indicates
    // whether the block was bound. The rest of the tuple contains the phi
    // values. Check if this block was bound (aka is reachable).
    if (std::get<0>(bind_result)) {
      // The block is bound.
      DCHECK_EQ(assembler.current_block(), this->super::block());
      // Now we build a jump from this block to the loop header.
      // Remove the "bound"-flag from the beginning of the tuple.
      auto values = base::tuple_drop<1>(bind_result);
      assembler.Goto(loop_header_data_.block);
      // Finalize Phis in the loop header.
      FixLoopPhis(assembler, values);
    }
    assembler.FinalizeLoop(loop_header_data_.block);
  }

 private:
  template <typename A>
  static values_t MaterializeLoopPhis(A& assembler, BlockData& data) {
    return MaterializeLoopPhisImpl(assembler, data,
                                   std::make_index_sequence<super::size>());
  }

  template <typename A, size_t... indices>
  static values_t MaterializeLoopPhisImpl(A& assembler, BlockData& data,
                                          std::index_sequence<indices...>) {
    size_t predecessor_count = data.block->PredecessorCount();
    USE(predecessor_count);
    DCHECK_EQ(data.predecessors.size(), predecessor_count);
    // If this label has no values, we don't need any Phis.
    if constexpr (super::size == 0) return typename super::values_t{};

    DCHECK_EQ(predecessor_count, 1);
    auto phis = typename super::values_t{assembler.PendingLoopPhi(
        std::get<indices>(data.recorded_values)[0])...};
    return phis;
  }

  template <typename A>
  void FixLoopPhis(A& assembler, const typename super::values_t& values) {
    DCHECK(loop_header_data_.block->IsBound());
    DCHECK(loop_header_data_.block->IsLoop());
    DCHECK_LE(1, loop_header_data_.predecessors.size());
    DCHECK_LE(loop_header_data_.predecessors.size(), 2);
    FixLoopPhi<0>(assembler, values);
  }

  template <size_t I, typename A>
  void FixLoopPhi(A& assembler, const typename super::values_t& values) {
    if constexpr (I < std::tuple_size_v<typename super::values_t>) {
      OpIndex phi_index = std::get<I>(*pending_loop_phis_);
      PendingLoopPhiOp& pending_loop_phi =
          assembler.output_graph()
              .Get(phi_index)
              .template Cast<PendingLoopPhiOp>();
      DCHECK_EQ(pending_loop_phi.first(),
                std::get<I>(loop_header_data_.recorded_values)[0]);
      assembler.output_graph().template Replace<PhiOp>(
          phi_index,
          base::VectorOf<OpIndex>(
              {pending_loop_phi.first(), std::get<I>(values)}),
          pending_loop_phi.rep);
      FixLoopPhi<I + 1>(assembler, values);
    }
  }

  BlockData loop_header_data_;
  std::optional<values_t> pending_loop_phis_;
};

namespace detail {
template <typename T>
struct LoopLabelForHelper;
template <typename T>
struct LoopLabelForHelper<V<T>> {
  using type = LoopLabel<T>;
};
template <typename... Ts>
struct LoopLabelForHelper<std::tuple<V<Ts>...>> {
  using type = LoopLabel<Ts...>;
};
}  // namespace detail

template <typename T>
using LoopLabelFor = detail::LoopLabelForHelper<T>::type;

Handle<Code> BuiltinCodeHandle(Builtin builtin, Isolate* isolate);

template <typename Next>
class TurboshaftAssemblerOpInterface;

template <typename T>
class Uninitialized {
  static_assert(is_subtype_v<T, HeapObject>);

 public:
  explicit Uninitialized(V<T> object) : object_(object) {}

 private:
  template <typename Next>
  friend class TurboshaftAssemblerOpInterface;

  V<T> object() const {
    DCHECK(object_.has_value());
    return *object_;
  }

  V<T> ReleaseObject() {
    DCHECK(object_.has_value());
    auto temp = *object_;
    object_.reset();
    return temp;
  }

  std::optional<V<T>> object_;
};

// Forward declarations
template <class Assembler>
class GraphVisitor;
template <class Next>
class ValueNumberingReducer;
template <class Next>
class EmitProjectionReducer;

template <typename Reducers>
struct StackBottom {
  using AssemblerType = Assembler<Reducers>;
  using ReducerList = Reducers;
  Assembler<ReducerList>& Asm() {
    return *static_cast<Assembler<ReducerList>*>(this);
  }
};

template <typename ReducerList>
struct ReducerStack {
  static constexpr size_t length = reducer_list_length<ReducerList>::value;
  // We assume a TSReducerBase is at the end of the list.
  static constexpr size_t base_index =
      reducer_list_index_of<ReducerList, TSReducerBase>::value;
  static_assert(base_index == length - 1);
  // Insert a GenericReducerBase before that.
  using WithGeneric =
      reducer_list_insert_at<ReducerList, base_index, GenericReducerBase>::type;
  // If we have a ValueNumberingReducer in the list, we insert at that index,
  // otherwise before the reducer_base.
  static constexpr size_t ep_index =
      reducer_list_index_of<WithGeneric, ValueNumberingReducer,
                            base_index>::value;
  using WithGenericAndEmitProjection =
      reducer_list_insert_at<WithGeneric, ep_index,
                             EmitProjectionReducer>::type;
  static_assert(reducer_list_length<WithGenericAndEmitProjection>::value ==
                length + 2);

  using type = reducer_list_to_stack<WithGenericAndEmitProjection,
                                     StackBottom<ReducerList>>::type;
};

template <typename Next>
class GenericReducerBase;

// TURBOSHAFT_REDUCER_GENERIC_BOILERPLATE should almost never be needed: it
// should only be used by the IR-specific base class, while other reducers
// should simply use `TURBOSHAFT_REDUCER_BOILERPLATE`.
#define TURBOSHAFT_REDUCER_GENERIC_BOILERPLATE(Name)                    \
  using ReducerList = typename Next::ReducerList;                       \
  using assembler_t = compiler::turboshaft::Assembler<ReducerList>;     \
  assembler_t& Asm() { return *static_cast<assembler_t*>(this); }       \
  template <class T>                                                    \
  using ScopedVar = compiler::turboshaft::ScopedVar<T, assembler_t>;    \
  using CatchScope = compiler::turboshaft::CatchScopeImpl<assembler_t>; \
  static constexpr auto& ReducerName() { return #Name; }

// Defines a few helpers to use the Assembler and its stack in Reducers.
#define TURBOSHAFT_REDUCER_BOILERPLATE(Name)   \
  TURBOSHAFT_REDUCER_GENERIC_BOILERPLATE(Name) \
  using node_t = typename Next::node_t;        \
  using block_t = typename Next::block_t;

template <class T, class Assembler>
class Var : protected Variable {
  using value_type = maybe_const_or_v_t<T>;

 public:
  template <typename Reducer>
  explicit Var(Reducer* reducer) : Var(reducer->Asm()) {}

  template <typename Reducer>
  Var(Reducer* reducer, value_type initial_value) : Var(reducer) {
    assembler_.SetVariable(*this, assembler_.resolve(initial_value));
  }

  explicit Var(Assembler& assembler)
      : Variable(assembler.NewVariable(
            static_cast<const RegisterRepresentation&>(V<T>::rep))),
        assembler_(assembler) {}

  Var(const Var&) = delete;
  Var(Var&&) = delete;
  Var& operator=(const Var) = delete;
  Var& operator=(Var&&) = delete;
  ~Var() = default;

  void Set(value_type new_value) {
    assembler_.SetVariable(*this, assembler_.resolve(new_value));
  }
  V<T> Get() const { return assembler_.GetVariable(*this); }

  void operator=(value_type new_value) { Set(new_value); }
  template <typename U,
            typename = std::enable_if_t<
                v_traits<U>::template implicitly_constructible_from<T>::value>>
  operator V<U>() const {
    return Get();
  }
  template <typename U,
            typename = std::enable_if_t<
                v_traits<U>::template implicitly_constructible_from<T>::value>>
  operator OptionalV<U>() const {
    return Get();
  }
  template <typename U,
            typename = std::enable_if_t<
                const_or_v_exists_v<U> &&
                v_traits<U>::template implicitly_constructible_from<T>::value>>
  operator ConstOrV<U>() const {
    return Get();
  }
  operator OpIndex() const { return Get(); }
  operator OptionalOpIndex() const { return Get(); }

 protected:
  Assembler& assembler_;
};

template <typename T, typename Assembler>
class ScopedVar : public Var<T, Assembler> {
  using Base = Var<T, Assembler>;

 public:
  using Base::Base;
  ~ScopedVar() {
    // Explicitly mark the variable as invalid to avoid the creation of
    // unnecessary loop phis.
    this->assembler_.SetVariable(*this, OpIndex::Invalid());
  }

  using Base::operator=;
};

// LABEL_BLOCK is used in Reducers to have a single call forwarding to the next
// reducer without change. A typical use would be:
//
//     OpIndex ReduceFoo(OpIndex arg) {
//       LABEL_BLOCK(no_change) return Next::ReduceFoo(arg);
//       ...
//       if (...) goto no_change;
//       ...
//       if (...) goto no_change;
//       ...
//     }
#define LABEL_BLOCK(label)     \
  for (; false; UNREACHABLE()) \
  label:

// EmitProjectionReducer ensures that projections are always emitted right after
// their input operation. To do so, when an operation with multiple outputs is
// emitted, it always emit its projections, and returns a Tuple of the
// projections.
// It should "towards" the bottom of the stack (so that calling Next::ReduceXXX
// just emits XXX without emitting any operation afterwards, and so that
// Next::ReduceXXX does indeed emit XXX rather than lower/optimize it to some
// other subgraph), but it should be before GlobalValueNumbering, so that
// operations with multiple outputs can still be GVNed.
template <class Next>
class EmitProjectionReducer
    : public UniformReducerAdapter<EmitProjectionReducer, Next> {
 public:
  TURBOSHAFT_REDUCER_BOILERPLATE(EmitProjection)

  V<Object> ReduceCatchBlockBegin() {
    // CatchBlockBegin have a single output, so they never have projections,
    // but additionally split-edge can transform CatchBlockBeginOp into PhiOp,
    // which means that there is no guarantee here tha
"""


```