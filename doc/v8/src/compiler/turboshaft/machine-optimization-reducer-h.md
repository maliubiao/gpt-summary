Response:
My goal is to analyze the provided C++ header file and summarize its functionality, relating it to JavaScript where applicable, providing code examples, and addressing potential user errors.

Here's a breakdown of the thought process:

1. **Identify the Core Purpose:** The initial comment block clearly states the purpose of `MachineOptimizationReducer`: to perform basic, local optimizations on low-level operations within the Turboshaft compiler pipeline. This is analogous to `MachineOperatorReducer` in the older Turbofan compiler. The key is "on-the-fly" and "without requiring type analysis or analyzing uses," meaning it's focused on immediate operand values.

2. **Recognize the Header File Nature:**  The `.h` extension indicates a header file in C++. It defines interfaces and data structures but generally doesn't contain the implementation details. This means I should focus on the *types* of optimizations being described rather than trying to understand complex algorithms within the file itself. The `REDUCE` macros are hints about the core mechanism.

3. **Examine the Examples:** The comment block provides concrete examples of the types of optimizations performed:
    * `a == a` -> `1` (Constant folding for comparisons)
    * `a + 0` -> `a` (Identity element for addition)
    * `a * 2^k` -> `a << k` (Strength reduction for multiplication by powers of two)
    These examples are fundamental and provide a good starting point for explaining the reducer's purpose in simple terms.

4. **Check for Torque:** The prompt specifically asks about `.tq` files. This file is `.h`, so it's *not* a Torque file. This is a direct check based on the file extension.

5. **Relate to JavaScript (if applicable):** The optimizations described are ultimately about making JavaScript code run faster. While the reducer itself is C++, the *effects* are visible in optimized JavaScript. I need to think about JavaScript code patterns that would lead to these kinds of low-level operations. For example:
    * `x === x` in JavaScript relates to the `a == a` optimization.
    * `y + 0` in JavaScript relates to the `a + 0` optimization.
    * `z * 8` in JavaScript relates to the `a * 2^k` optimization.
    It's important to show *how* the C++ optimization benefits JavaScript execution, even if indirectly.

6. **Look for Code Logic/Inference (and potential inputs/outputs):** The `REDUCE` macros and the structure of the `MachineOptimizationReducer` class suggest a pattern of matching operations and potentially replacing them with simpler equivalents. The examples in the comments provide the "input" (the original operation) and the "output" (the optimized operation). I need to generalize this concept. For instance, the `REDUCE(Change)` function suggests handling type conversions. If the input is a constant, the output might be a new constant with the converted type.

7. **Consider User Programming Errors:** The optimizations sometimes address redundant or inefficient code that a programmer might write. Examples:
    * Comparing a variable to itself (`x === x`) is often unintentional or could be simplified.
    * Multiplying by powers of two can be written as shifts for better performance (although modern JavaScript engines are quite good at handling this).
    * Explicitly converting between closely related types (like adding 0) is often unnecessary.

8. **Structure the Summary:** The prompt asks for a summary of the functions. I should synthesize the information gathered into concise points. The key functionalities are:
    * Constant folding (evaluating expressions with constant operands at compile time).
    * Strength reduction (replacing expensive operations with cheaper equivalents).
    * Identity element elimination (removing operations with identity operands).
    * Simplifying type conversions.
    * Bitwise operation optimizations.

9. **Address the "Part 1 of 4" instruction:**  This is a directive to focus *only* on the provided code snippet and its immediate functionality. I should avoid speculating about what might be in the other parts.

10. **Review and Refine:**  After drafting the initial summary, I should reread the provided code and my analysis to ensure accuracy, clarity, and completeness within the scope of the provided header file. For example, I should double-check that my JavaScript examples accurately reflect the C++ optimizations. I should also make sure I'm not going into too much detail about internal V8 implementation specifics that aren't directly evident from the header.

By following these steps, I can produce a comprehensive and accurate summary of the `MachineOptimizationReducer.h` file, addressing all aspects of the prompt. The focus is on understanding the *what* and *why* of these optimizations, even without seeing the actual implementation code.
```cpp
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMPILER_TURBOSHAFT_MACHINE_OPTIMIZATION_REDUCER_H_
#define V8_COMPILER_TURBOSHAFT_MACHINE_OPTIMIZATION_REDUCER_H_

#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>
#include <optional>
#include <type_traits>

#include "include/v8-internal.h"
#include "src/base/bits.h"
#include "src/base/division-by-constant.h"
#include "src/base/functional.h"
#include "src/base/ieee754.h"
#include "src/base/logging.h"
#include "src/base/macros.h"
#include "src/base/overflowing-math.h"
#include "src/base/small-vector.h"
#include "src/base/template-utils.h"
#include "src/base/vector.h"
#include "src/builtins/builtins.h"
#include "src/codegen/machine-type.h"
#include "src/compiler/backend/instruction.h"
#include "src/compiler/compilation-dependencies.h"
#include "src/compiler/js-heap-broker.h"
#include "src/compiler/machine-operator-reducer.h"
#include "src/compiler/turboshaft/assembler.h"
#include "src/compiler/turboshaft/index.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/opmasks.h"
#include "src/compiler/turboshaft/phase.h"
#include "src/compiler/turboshaft/reducer-traits.h"
#include "src/compiler/turboshaft/representations.h"
#include "src/handles/handles.h"
#include "src/numbers/conversions.h"
#include "src/numbers/ieee754.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/simd-shuffle.h"
#endif

namespace v8::internal::compiler::turboshaft {

// ******************************** OVERVIEW ********************************
//
// The MachineOptimizationAssembler performs basic optimizations on low-level
// operations that can be performed on-the-fly, without requiring type analysis
// or analyzing uses. It largely corresponds to MachineOperatorReducer in
// sea-of-nodes Turbofan.
//
// These peephole optimizations are typically very local: they based on the
// immediate inputs of an operation, we try to constant-fold or strength-reduce
// the operation.
//
// Typical examples include:
//
//   * Reducing `a == a` to `1`
//
//   * Reducing `a + 0` to `a`
//
//   * Reducing `a * 2^k` to `a << k`
//

#include "src/compiler/turboshaft/define-assembler-macros.inc"

template <typename>
class VariableReducer;
template <typename>
class GraphVisitor;

namespace detail {

// Represents an operation of the form `(source & mask) == masked_value`.
// where each bit set in masked_value also has to be set in mask.
struct BitfieldCheck {
  OpIndex const source;
  uint32_t const mask;
  uint32_t const masked_value;
  bool const truncate_from_64_bit;

  BitfieldCheck(OpIndex source, uint32_t mask, uint32_t masked_value,
                bool truncate_from_64_bit)
      : source(source),
        mask(mask),
        masked_value(masked_value),
        truncate_from_64_bit(truncate_from_64_bit) {
    CHECK_EQ(masked_value & ~mask, 0);
  }

  static std::optional<BitfieldCheck> Detect(const OperationMatcher& matcher,
                                             const Graph& graph,
                                             OpIndex index) {
    // There are two patterns to check for here:
    // 1. Single-bit checks: `(val >> shift) & 1`, where:
    //    - the shift may be omitted, and/or
    //    - the result may be truncated from 64 to 32
    // 2. Equality checks: `(val & mask) == expected`, where:
    //    - val may be truncated from 64 to 32 before masking (see
    //      ReduceWordEqualForConstantRhs)
    const Operation& op = graph.Get(index);
    if (const ComparisonOp* equal = op.TryCast<Opmask::kWord32Equal>()) {
      if (const WordBinopOp* left_and =
              graph.Get(equal->left()).TryCast<Opmask::kWord32BitwiseAnd>()) {
        uint32_t mask;
        uint32_t masked_value;
        if (matcher.MatchIntegralWord32Constant(left_and->right(), &mask) &&
            matcher.MatchIntegralWord32Constant(equal->right(),
                                                &masked_value)) {
          if ((masked_value & ~mask) != 0) return std::nullopt;
          if (const ChangeOp* truncate =
                  graph.Get(left_and->left())
                      .TryCast<Opmask::kTruncateWord64ToWord32>()) {
            return BitfieldCheck{truncate->input(), mask, masked_value, true};
          } else {
            return BitfieldCheck{left_and->left(), mask, masked_value, false};
          }
        }
      }
    } else if (const ChangeOp* truncate =
                   op.TryCast<Opmask::kTruncateWord64ToWord32>()) {
      return TryDetectShiftAndMaskOneBit<Word64>(matcher, truncate->input());
    } else {
      return TryDetectShiftAndMaskOneBit<Word32>(matcher, index);
    }
    return std::nullopt;
  }

  std::optional<BitfieldCheck> TryCombine(const BitfieldCheck& other) {
    if (source != other.source ||
        truncate_from_64_bit != other.truncate_from_64_bit) {
      return std::nullopt;
    }
    uint32_t overlapping_bits = mask & other.mask;
    // It would be kind of strange to have any overlapping bits, but they can be
    // allowed as long as they don't require opposite values in the same
    // positions.
    if ((masked_value & overlapping_bits) !=
        (other.masked_value & overlapping_bits)) {
      return std::nullopt;
    }
    return BitfieldCheck{source, mask | other.mask,
                         masked_value | other.masked_value,
                         truncate_from_64_bit};
  }

 private:
  template <typename WordType>
  static std::optional<BitfieldCheck> TryDetectShiftAndMaskOneBit(
      const OperationMatcher& matcher, OpIndex index) {
    constexpr WordRepresentation Rep = V<WordType>::rep;
    // Look for the pattern `(val >> shift) & 1`. The shift may be omitted.
    V<WordType> value;
    uint64_t constant;
    if (matcher.MatchBitwiseAndWithConstant(index, &value, &constant, Rep) &&
        constant == 1) {
      OpIndex input;
      if (int shift_amount;
          matcher.MatchConstantRightShift(value, &input, Rep, &shift_amount) &&
          shift_amount >= 0 && shift_amount < 32) {
        uint32_t mask = 1 << shift_amount;
        return BitfieldCheck{input, mask, mask,
                             Rep == WordRepresentation::Word64()};
      }
      return BitfieldCheck{value, 1, 1, Rep == WordRepresentation::Word64()};
    }
    return std::nullopt;
  }
};

}  // namespace detail

template <class Next>
class MachineOptimizationReducer : public Next {
 public:
  TURBOSHAFT_REDUCER_BOILERPLATE(MachineOptimization)
#if defined(__clang__)
  // TODO(dmercadier): this static_assert ensures that the stack contains a
  // VariableReducer. It is currently not very clean, because when GraphVisitor
  // is on the stack, it implicitly adds a VariableReducer that isn't detected
  // by reducer_list_contains. It would be cleaner to have a single "reducer
  // list contains VariableReducer" check that sees the VariableReducer
  // introduced by GraphVisitor.
  static_assert(reducer_list_contains<ReducerList, VariableReducer>::value ||
                reducer_list_contains<ReducerList, GraphVisitor>::value);
#endif

  // TODO(mslekova): Implement ReduceSelect and ReducePhi,
  // by reducing `(f > 0) ? f : -f` to `fabs(f)`.

  OpIndex REDUCE(Change)(OpIndex input, ChangeOp::Kind kind,
                         ChangeOp::Assumption assumption,
                         RegisterRepresentation from,
                         RegisterRepresentation to) {
    if (ShouldSkipOptimizationStep()) {
      return Next::ReduceChange(input, kind, assumption, from, to);
    }
    using Kind = ChangeOp::Kind;
    if (from == WordRepresentation::Word32()) {
      input = TryRemoveWord32ToWord64Conversion(input);
    }
    if (uint64_t value;
        from.IsWord() && matcher_.MatchIntegralWordConstant(
                             input, WordRepresentation(from), &value)) {
      using Rep = RegisterRepresentation;
      switch (multi(kind, from, to)) {
        case multi(Kind::kSignExtend, Rep::Word32(), Rep::Word64()):
          return __ Word64Constant(int64_t{static_cast<int32_t>(value)});
        case multi(Kind::kZeroExtend, Rep::Word32(), Rep::Word64()):
        case multi(Kind::kBitcast, Rep::Word32(), Rep::Word64()):
          return __ Word64Constant(uint64_t{static_cast<uint32_t>(value)});
        case multi(Kind::kBitcast, Rep::Word32(), Rep::Float32()):
          return __ Float32Constant(
              i::Float32::FromBits(static_cast<uint32_t>(value)));
        case multi(Kind::kBitcast, Rep::Word64(), Rep::Float64()):
          return __ Float64Constant(i::Float64::FromBits(value));
        case multi(Kind::kSignedToFloat, Rep::Word32(), Rep::Float64()):
          return __ Float64Constant(
              static_cast<double>(static_cast<int32_t>(value)));
        case multi(Kind::kSignedToFloat, Rep::Word64(), Rep::Float64()):
          return __ Float64Constant(
              static_cast<double>(static_cast<int64_t>(value)));
        case multi(Kind::kUnsignedToFloat, Rep::Word32(), Rep::Float64()):
          return __ Float64Constant(
              static_cast<double>(static_cast<uint32_t>(value)));
        case multi(Kind::kTruncate, Rep::Word64(), Rep::Word32()):
          return __ Word32Constant(static_cast<uint32_t>(value));
        default:
          break;
      }
    }
    if (i::Float32 value; from == RegisterRepresentation::Float32() &&
                          matcher_.MatchFloat32Constant(input, &value)) {
      if (kind == Kind::kFloatConversion &&
          to == RegisterRepresentation::Float64()) {
        return __ Float64Constant(value.get_scalar());
      }
      if (kind == Kind::kBitcast && to == WordRepresentation::Word32()) {
        return __ Word32Constant(value.get_bits());
      }
    }
    if (i::Float64 value; from == RegisterRepresentation::Float64() &&
                          matcher_.MatchFloat64Constant(input, &value)) {
      if (kind == Kind::kFloatConversion &&
          to == RegisterRepresentation::Float32()) {
        return __ Float32Constant(DoubleToFloat32_NoInline(value.get_scalar()));
      }
      if (kind == Kind::kBitcast && to == WordRepresentation::Word64()) {
        return __ Word64Constant(base::bit_cast<uint64_t>(value));
      }
      if (kind == Kind::kSignedFloatTruncateOverflowToMin) {
        double truncated = std::trunc(value.get_scalar());
        if (to == WordRepresentation::Word64()) {
          int64_t result = std::numeric_limits<int64_t>::min();
          if (truncated >= std::numeric_limits<int64_t>::min() &&
              truncated <= kMaxDoubleRepresentableInt64) {
            result = static_cast<int64_t>(truncated);
          }
          return __ Word64Constant(result);
        }
        if (to == WordRepresentation::Word32()) {
          int32_t result = std::numeric_limits<int32_t>::min();
          if (truncated >= std::numeric_limits<int32_t>::min() &&
              truncated <= std::numeric_limits<int32_t>::max()) {
            result = static_cast<int32_t>(truncated);
          }
          return __ Word32Constant(result);
        }
      }
      if (kind == Kind::kJSFloatTruncate &&
          to == WordRepresentation::Word32()) {
        return __ Word32Constant(DoubleToInt32_NoInline(value.get_scalar()));
      }
      if (kind == Kind::kExtractHighHalf) {
        DCHECK_EQ(to, RegisterRepresentation::Word32());
        return __ Word32Constant(static_cast<uint32_t>(value.get_bits() >> 32));
      }
      if (kind == Kind::kExtractLowHalf) {
        DCHECK_EQ(to, RegisterRepresentation::Word32());
        return __ Word32Constant(static_cast<uint32_t>(value.get_bits()));
      }
    }
    if (float value; from == RegisterRepresentation::Float32() &&
                     matcher_.MatchFloat32Constant(input, &value)) {
      if (kind == Kind::kFloatConversion &&
          to == RegisterRepresentation::Float64()) {
        return __ Float64Constant(value);
      }
    }

    const Operation& input_op = matcher_.Get(input);
    if (const ChangeOp* change_op = input_op.TryCast<ChangeOp>()) {
      if (change_op->from == to && change_op->to == from &&
          change_op->IsReversibleBy(kind, signalling_nan_possible)) {
        return change_op->input();
      }
    }
    return Next::ReduceChange(input, kind, assumption, from, to);
  }

  V<Float64> REDUCE(BitcastWord32PairToFloat64)(V<Word32> hi_word32,
                                                V<Word32> lo_word32) {
    if (ShouldSkipOptimizationStep()) {
      return Next::ReduceBitcastWord32PairToFloat64(hi_word32, lo_word32);
    }
    uint32_t lo, hi;
    if (matcher_.MatchIntegralWord32Constant(hi_word32, &hi) &&
        matcher_.MatchIntegralWord32Constant(lo_word32, &lo)) {
      return __ Float64Constant(
          base::bit_cast<double>(uint64_t{hi} << 32 | uint64_t{lo}));
    }
    return Next::ReduceBitcastWord32PairToFloat64(hi_word32, lo_word32);
  }

  OpIndex REDUCE(TaggedBitcast)(OpIndex input, RegisterRepresentation from,
                                RegisterRepresentation to,
                                TaggedBitcastOp::Kind kind) {
    if (ShouldSkipOptimizationStep()) {
      return Next::ReduceTaggedBitcast(input, from, to, kind);
    }
    // A Tagged -> Untagged -> Tagged sequence can be short-cut.
    // An Untagged -> Tagged -> Untagged sequence however cannot be removed,
    // because the GC might have modified the pointer.
    if (auto* input_bitcast = matcher_.TryCast<TaggedBitcastOp>(input)) {
      if (all_of(input_bitcast->to, from) ==
              RegisterRepresentation::WordPtr() &&
          all_of(input_bitcast->from, to) == RegisterRepresentation::Tagged()) {
        return input_bitcast->input();
      }
    }
    // An Untagged -> Smi -> Untagged sequence can be short-cut.
    if (auto* input_bitcast = matcher_.TryCast<TaggedBitcastOp>(input);
        input_bitcast && to.IsWord() &&
        (kind == TaggedBitcastOp::Kind::kSmi ||
         input_bitcast->kind == TaggedBitcastOp::Kind::kSmi)) {
      if (input_bitcast->from == to) return input_bitcast->input();
      if (input_bitcast->from == RegisterRepresentation::Word32()) {
        DCHECK_EQ(to, RegisterRepresentation::Word64());
        return __ BitcastWord32ToWord64(input_bitcast->input());
      }
      DCHECK(input_bitcast->from == RegisterRepresentation::Word64() &&
             to == RegisterRepresentation::Word32());
      return __ TruncateWord64ToWord32(input_bitcast->input());
    }
    // Try to constant-fold TaggedBitcast from Word Constant to Word.
    if (to.IsWord()) {
      if (const ConstantOp* cst = matcher_.TryCast<ConstantOp>(input)) {
        if (cst->kind == ConstantOp::Kind::kWord32 ||
            cst->kind == ConstantOp::Kind::kWord64) {
          if (to == RegisterRepresentation::Word64()) {
            return __ Word64Constant(cst->integral());
          } else {
            DCHECK_EQ(to, RegisterRepresentation::Word32());
            return __ Word32Constant(static_cast<uint32_t>(cst->integral()));
          }
        }
      }
    }
    if (const ConstantOp* cst = matcher_.TryCast<ConstantOp>(input)) {
      // Try to constant-fold Word constant -> Tagged (Smi).
      if (cst->IsIntegral() && to == RegisterRepresentation::Tagged()) {
        if (Smi::IsValid(cst->integral())) {
          return __ SmiConstant(
              i::Tagged<Smi>(static_cast<intptr_t>(cst->integral())));
        }
      }
      // Try to constant-fold Smi -> Untagged.
      if (cst->kind == ConstantOp::Kind::kSmi) {
        if (to == RegisterRepresentation::Word32()) {
          return __ Word32Constant(static_cast<uint32_t>(cst->smi().ptr()));
        } else if (to == RegisterRepresentation::Word64()) {
          return __ Word64Constant(static_cast<uint64_t>(cst->smi().ptr()));
        }
      }
    }
    return Next::ReduceTaggedBitcast(input, from, to, kind);
  }

  V<Float> REDUCE(FloatUnary)(V<Float> input, FloatUnaryOp::Kind kind,
                              FloatRepresentation rep) {
    if (ShouldSkipOptimizationStep()) {
      return Next::ReduceFloatUnary(input, kind, rep);
    }
    if (float k; rep == FloatRepresentation::Float32() &&
                 matcher_.MatchFloat32Constant(input, &k)) {
      if (std::isnan(k) && !signalling_nan_possible) {
        return __ Float32Constant(std::numeric_limits<float>::quiet_NaN());
      }
      switch (kind) {
        case FloatUnaryOp::Kind::kAbs:
          return __ Float32Constant(std::abs(k));
        case FloatUnaryOp::Kind::kNegate:
          return __ Float32Constant(-k);
        case FloatUnaryOp::Kind::kSilenceNaN:
          DCHECK(!std::isnan(k));
          return __ Float32Constant(k);
        case FloatUnaryOp::Kind::kRoundDown:
          return __ Float32Constant(std::floor(k));
        case FloatUnaryOp::Kind::kRoundUp:
          return __ Float32Constant(std::ceil(k));
        case FloatUnaryOp::Kind::kRoundToZero:
          return __ Float32Constant(std::trunc(k));
        case FloatUnaryOp::Kind::kRoundTiesEven:
          DCHECK_EQ(std::nearbyint(1.5), 2);
          DCHECK_EQ(std::nearbyint(2.5), 2);
          return __ Float32Constant(std::nearbyint(k));
        case FloatUnaryOp::Kind::kLog:
          return __ Float32Constant(base::ieee754::log(k));
        case FloatUnaryOp::Kind::kSqrt:
          return __ Float32Constant(std::sqrt(k));
        case FloatUnaryOp::Kind::kExp:
          return __ Float32Constant(base::ieee754::exp(k));
        case FloatUnaryOp::Kind::kExpm1:
          return __ Float32Constant(base::ieee754::expm1(k));
        case FloatUnaryOp::Kind::kSin:
          return __ Float32Constant(SIN_IMPL(k));
        case FloatUnaryOp::Kind::kCos:
          return __ Float32Constant(COS_IMPL(k));
        case FloatUnaryOp::Kind::kSinh:
          return __ Float32Constant(base::ieee754::sinh(k));
        case FloatUnaryOp::Kind::kCosh:
          return __ Float32Constant(base::ieee754::cosh(k));
        case FloatUnaryOp::Kind::kAcos:
          return __ Float32Constant(base::ieee754::acos(k));
        case FloatUnaryOp::Kind::kAsin:
          return __ Float32Constant(base::ieee754::asin(k));
        case FloatUnaryOp::Kind::kAsinh:
          return __ Float32Constant(base::ieee754::asinh(k));
        case FloatUnaryOp::Kind::kAcosh:
          return __ Float32Constant(base::ieee754::acosh(k));
        case FloatUnaryOp::Kind::kTan:
          return __ Float32Constant(base::ieee754::tan(k));
        case FloatUnaryOp::Kind::kTanh:
          return __ Float32Constant(base::ieee754::tanh(k));
        case FloatUnaryOp::Kind::kLog2:
          return __ Float32Constant(base::ieee754::log2(k));
        case FloatUnaryOp::Kind::kLog10:
          return __ Float32Constant(base::ieee754::log10(k));
        case FloatUnaryOp::Kind::kLog1p:
          return __ Float32Constant(base::ieee754::log1p(k));
        case FloatUnaryOp::Kind::kCbrt:
          return __ Float32Constant(base::ieee754::cbrt(k));
        case FloatUnaryOp::Kind::kAtan:
          return __ Float32Constant(base::ieee754::atan(k));
        case FloatUnaryOp::Kind::kAtanh:
          return __ Float32Constant(base::ieee754::atanh(k));
      }
    } else if (double k; rep == FloatRepresentation::Float64() &&
                         matcher_.MatchFloat64Constant(input, &k)) {
      if (std::isnan(k) && !signalling_nan_possible) {
        return __ Float64Constant(std::numeric_limits<double>::quiet_NaN());
      }
      switch (kind) {
        case FloatUnaryOp::Kind::kAbs:
          return __ Float64Constant(std::abs(k));
        case FloatUnaryOp::Kind::kNegate:
          return __ Float64Constant(-k);
        case FloatUnaryOp::Kind::kSilenceNaN:
          DCHECK(!std::isnan(k));
          return __ Float64Constant(k);
        case FloatUnaryOp::Kind::kRoundDown:
          return __ Float64Constant(std::floor(k));
        case FloatUnaryOp::Kind::kRoundUp:
          return __ Float64Constant(std::ceil(k));
        case FloatUnaryOp::Kind::kRoundToZero:
          return __ Float64Constant(std::trunc(k));
        case FloatUnaryOp::Kind::kRoundTiesEven:
          DCHECK_EQ(std::nearbyint(1.5), 2);
          DCHECK_EQ(std::nearbyint(2.5), 2);
          return __ Float64Constant(std::nearbyint(k));
        case FloatUnaryOp::Kind::kLog:
          return __ Float64Constant(base::ieee754::log(k));
        case FloatUnaryOp::Kind::kSqrt:
          return __ Float64Constant(std::sqrt(k));
        case FloatUnaryOp::Kind::kExp:
          return __ Float64Constant(base::ieee754::exp(k));
        case FloatUnaryOp::Kind::kExpm1:
          return __ Float64Constant(base::ieee754::expm1(k));
        case FloatUnaryOp::Kind::kSin:
          return __ Float64Constant(SIN_IMPL(k));
        case FloatUnaryOp::Kind::kCos:
          return __ Float64Constant(COS_IMPL(k));
        case FloatUnaryOp::Kind::kSinh:
          return __ Float64Constant(base::ieee754::sinh(k));
        case FloatUnaryOp::Kind::kCosh:
          return __ Float64Constant(base::ieee754::cosh(k));
        case FloatUnaryOp::Kind::kAcos:
          return __ Float64Constant(base::ieee754::acos(k));
        case FloatUnaryOp::Kind::kAsin:
          return __ Float64Constant(base::ieee754::asin(k));
        case FloatUnaryOp::Kind::kAsinh:
          return __ Float64Constant(base::ieee754::asinh(k));
        case FloatUnaryOp::Kind::kAcosh:
          return __ Float64Constant(base::ieee754::acosh(k));
        case FloatUnaryOp::Kind::kTan:
          return __ Float64Constant(base::ieee754::tan(k));
        case FloatUnaryOp::Kind::kTanh:
          return __ Float64Constant(base::ieee754::tanh(k));
        case FloatUnaryOp::Kind::kLog2:
          return __ Float64Constant(base::ieee754::log2(k));
        case FloatUnaryOp::Kind::kLog10:
          return __ Float64Constant(base::ieee754::log10(k));
        case FloatUnaryOp::Kind::kLog1p:
          return __ Float64Constant(base::ieee754::log1p(k));
        case FloatUnaryOp::Kind::kCbrt:
          return __ Float64Constant(base::ieee754::cbrt(k));
        case FloatUnaryOp::Kind::kAtan:
          return __ Float64Constant(base::ieee754::atan(k));
        case FloatUnaryOp::Kind::kAtanh:
          return __ Float64Constant(base::ieee754::atanh(k));
      }
    }
    return Next::ReduceFloatUnary(input, kind, rep);
  }

  V<Word> REDUCE(WordUnary)(V<Word> input, WordUnaryOp::Kind kind,
                            WordRepresentation rep) {
    if (ShouldSkipOptimizationStep()) {
      return Next::ReduceWordUnary(input, kind, rep);
    }
    if (rep == WordRepresentation::Word32()) {
      input = TryRemoveWord32ToWord64Conversion(input);
    }
    if (uint32_t k; rep == WordRepresentation::Word32() &&
                    matcher_.MatchIntegralWord32Constant(input, &k)) {
      switch (kind) {
        case WordUnaryOp::Kind::kReverseBytes:
          return __ Word32Constant(base::bits::ReverseBytes(k));
        case WordUnaryOp::Kind::kCountLeadingZeros:
          return __ Word32Constant(base::bits::CountLeadingZeros(k));
        case WordUnaryOp::Kind::kCountTrailingZeros:
          return __ Word32Constant(base::bits::CountTrailingZeros(k));
        case WordUnaryOp::Kind::kPopCount:
          return __ Word32Constant(base::bits::CountPopulation(k));
        case WordUnaryOp::Kind::kSignExtend8:
          return __ Word32Constant(int32_t{static_cast<int8_t>(k)});
### 提示词
```
这是目录为v8/src/compiler/turboshaft/machine-optimization-reducer.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/machine-optimization-reducer.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMPILER_TURBOSHAFT_MACHINE_OPTIMIZATION_REDUCER_H_
#define V8_COMPILER_TURBOSHAFT_MACHINE_OPTIMIZATION_REDUCER_H_

#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>
#include <optional>
#include <type_traits>

#include "include/v8-internal.h"
#include "src/base/bits.h"
#include "src/base/division-by-constant.h"
#include "src/base/functional.h"
#include "src/base/ieee754.h"
#include "src/base/logging.h"
#include "src/base/macros.h"
#include "src/base/overflowing-math.h"
#include "src/base/small-vector.h"
#include "src/base/template-utils.h"
#include "src/base/vector.h"
#include "src/builtins/builtins.h"
#include "src/codegen/machine-type.h"
#include "src/compiler/backend/instruction.h"
#include "src/compiler/compilation-dependencies.h"
#include "src/compiler/js-heap-broker.h"
#include "src/compiler/machine-operator-reducer.h"
#include "src/compiler/turboshaft/assembler.h"
#include "src/compiler/turboshaft/index.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/opmasks.h"
#include "src/compiler/turboshaft/phase.h"
#include "src/compiler/turboshaft/reducer-traits.h"
#include "src/compiler/turboshaft/representations.h"
#include "src/handles/handles.h"
#include "src/numbers/conversions.h"
#include "src/numbers/ieee754.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/simd-shuffle.h"
#endif

namespace v8::internal::compiler::turboshaft {

// ******************************** OVERVIEW ********************************
//
// The MachineOptimizationAssembler performs basic optimizations on low-level
// operations that can be performed on-the-fly, without requiring type analysis
// or analyzing uses. It largely corresponds to MachineOperatorReducer in
// sea-of-nodes Turbofan.
//
// These peephole optimizations are typically very local: they based on the
// immediate inputs of an operation, we try to constant-fold or strength-reduce
// the operation.
//
// Typical examples include:
//
//   * Reducing `a == a` to `1`
//
//   * Reducing `a + 0` to `a`
//
//   * Reducing `a * 2^k` to `a << k`
//

#include "src/compiler/turboshaft/define-assembler-macros.inc"

template <typename>
class VariableReducer;
template <typename>
class GraphVisitor;

namespace detail {

// Represents an operation of the form `(source & mask) == masked_value`.
// where each bit set in masked_value also has to be set in mask.
struct BitfieldCheck {
  OpIndex const source;
  uint32_t const mask;
  uint32_t const masked_value;
  bool const truncate_from_64_bit;

  BitfieldCheck(OpIndex source, uint32_t mask, uint32_t masked_value,
                bool truncate_from_64_bit)
      : source(source),
        mask(mask),
        masked_value(masked_value),
        truncate_from_64_bit(truncate_from_64_bit) {
    CHECK_EQ(masked_value & ~mask, 0);
  }

  static std::optional<BitfieldCheck> Detect(const OperationMatcher& matcher,
                                             const Graph& graph,
                                             OpIndex index) {
    // There are two patterns to check for here:
    // 1. Single-bit checks: `(val >> shift) & 1`, where:
    //    - the shift may be omitted, and/or
    //    - the result may be truncated from 64 to 32
    // 2. Equality checks: `(val & mask) == expected`, where:
    //    - val may be truncated from 64 to 32 before masking (see
    //      ReduceWordEqualForConstantRhs)
    const Operation& op = graph.Get(index);
    if (const ComparisonOp* equal = op.TryCast<Opmask::kWord32Equal>()) {
      if (const WordBinopOp* left_and =
              graph.Get(equal->left()).TryCast<Opmask::kWord32BitwiseAnd>()) {
        uint32_t mask;
        uint32_t masked_value;
        if (matcher.MatchIntegralWord32Constant(left_and->right(), &mask) &&
            matcher.MatchIntegralWord32Constant(equal->right(),
                                                &masked_value)) {
          if ((masked_value & ~mask) != 0) return std::nullopt;
          if (const ChangeOp* truncate =
                  graph.Get(left_and->left())
                      .TryCast<Opmask::kTruncateWord64ToWord32>()) {
            return BitfieldCheck{truncate->input(), mask, masked_value, true};
          } else {
            return BitfieldCheck{left_and->left(), mask, masked_value, false};
          }
        }
      }
    } else if (const ChangeOp* truncate =
                   op.TryCast<Opmask::kTruncateWord64ToWord32>()) {
      return TryDetectShiftAndMaskOneBit<Word64>(matcher, truncate->input());
    } else {
      return TryDetectShiftAndMaskOneBit<Word32>(matcher, index);
    }
    return std::nullopt;
  }

  std::optional<BitfieldCheck> TryCombine(const BitfieldCheck& other) {
    if (source != other.source ||
        truncate_from_64_bit != other.truncate_from_64_bit) {
      return std::nullopt;
    }
    uint32_t overlapping_bits = mask & other.mask;
    // It would be kind of strange to have any overlapping bits, but they can be
    // allowed as long as they don't require opposite values in the same
    // positions.
    if ((masked_value & overlapping_bits) !=
        (other.masked_value & overlapping_bits)) {
      return std::nullopt;
    }
    return BitfieldCheck{source, mask | other.mask,
                         masked_value | other.masked_value,
                         truncate_from_64_bit};
  }

 private:
  template <typename WordType>
  static std::optional<BitfieldCheck> TryDetectShiftAndMaskOneBit(
      const OperationMatcher& matcher, OpIndex index) {
    constexpr WordRepresentation Rep = V<WordType>::rep;
    // Look for the pattern `(val >> shift) & 1`. The shift may be omitted.
    V<WordType> value;
    uint64_t constant;
    if (matcher.MatchBitwiseAndWithConstant(index, &value, &constant, Rep) &&
        constant == 1) {
      OpIndex input;
      if (int shift_amount;
          matcher.MatchConstantRightShift(value, &input, Rep, &shift_amount) &&
          shift_amount >= 0 && shift_amount < 32) {
        uint32_t mask = 1 << shift_amount;
        return BitfieldCheck{input, mask, mask,
                             Rep == WordRepresentation::Word64()};
      }
      return BitfieldCheck{value, 1, 1, Rep == WordRepresentation::Word64()};
    }
    return std::nullopt;
  }
};

}  // namespace detail

template <class Next>
class MachineOptimizationReducer : public Next {
 public:
  TURBOSHAFT_REDUCER_BOILERPLATE(MachineOptimization)
#if defined(__clang__)
  // TODO(dmercadier): this static_assert ensures that the stack contains a
  // VariableReducer. It is currently not very clean, because when GraphVisitor
  // is on the stack, it implicitly adds a VariableReducer that isn't detected
  // by reducer_list_contains. It would be cleaner to have a single "reducer
  // list contains VariableReducer" check that sees the VariableReducer
  // introduced by GraphVisitor.
  static_assert(reducer_list_contains<ReducerList, VariableReducer>::value ||
                reducer_list_contains<ReducerList, GraphVisitor>::value);
#endif

  // TODO(mslekova): Implement ReduceSelect and ReducePhi,
  // by reducing `(f > 0) ? f : -f` to `fabs(f)`.

  OpIndex REDUCE(Change)(OpIndex input, ChangeOp::Kind kind,
                         ChangeOp::Assumption assumption,
                         RegisterRepresentation from,
                         RegisterRepresentation to) {
    if (ShouldSkipOptimizationStep()) {
      return Next::ReduceChange(input, kind, assumption, from, to);
    }
    using Kind = ChangeOp::Kind;
    if (from == WordRepresentation::Word32()) {
      input = TryRemoveWord32ToWord64Conversion(input);
    }
    if (uint64_t value;
        from.IsWord() && matcher_.MatchIntegralWordConstant(
                             input, WordRepresentation(from), &value)) {
      using Rep = RegisterRepresentation;
      switch (multi(kind, from, to)) {
        case multi(Kind::kSignExtend, Rep::Word32(), Rep::Word64()):
          return __ Word64Constant(int64_t{static_cast<int32_t>(value)});
        case multi(Kind::kZeroExtend, Rep::Word32(), Rep::Word64()):
        case multi(Kind::kBitcast, Rep::Word32(), Rep::Word64()):
          return __ Word64Constant(uint64_t{static_cast<uint32_t>(value)});
        case multi(Kind::kBitcast, Rep::Word32(), Rep::Float32()):
          return __ Float32Constant(
              i::Float32::FromBits(static_cast<uint32_t>(value)));
        case multi(Kind::kBitcast, Rep::Word64(), Rep::Float64()):
          return __ Float64Constant(i::Float64::FromBits(value));
        case multi(Kind::kSignedToFloat, Rep::Word32(), Rep::Float64()):
          return __ Float64Constant(
              static_cast<double>(static_cast<int32_t>(value)));
        case multi(Kind::kSignedToFloat, Rep::Word64(), Rep::Float64()):
          return __ Float64Constant(
              static_cast<double>(static_cast<int64_t>(value)));
        case multi(Kind::kUnsignedToFloat, Rep::Word32(), Rep::Float64()):
          return __ Float64Constant(
              static_cast<double>(static_cast<uint32_t>(value)));
        case multi(Kind::kTruncate, Rep::Word64(), Rep::Word32()):
          return __ Word32Constant(static_cast<uint32_t>(value));
        default:
          break;
      }
    }
    if (i::Float32 value; from == RegisterRepresentation::Float32() &&
                          matcher_.MatchFloat32Constant(input, &value)) {
      if (kind == Kind::kFloatConversion &&
          to == RegisterRepresentation::Float64()) {
        return __ Float64Constant(value.get_scalar());
      }
      if (kind == Kind::kBitcast && to == WordRepresentation::Word32()) {
        return __ Word32Constant(value.get_bits());
      }
    }
    if (i::Float64 value; from == RegisterRepresentation::Float64() &&
                          matcher_.MatchFloat64Constant(input, &value)) {
      if (kind == Kind::kFloatConversion &&
          to == RegisterRepresentation::Float32()) {
        return __ Float32Constant(DoubleToFloat32_NoInline(value.get_scalar()));
      }
      if (kind == Kind::kBitcast && to == WordRepresentation::Word64()) {
        return __ Word64Constant(base::bit_cast<uint64_t>(value));
      }
      if (kind == Kind::kSignedFloatTruncateOverflowToMin) {
        double truncated = std::trunc(value.get_scalar());
        if (to == WordRepresentation::Word64()) {
          int64_t result = std::numeric_limits<int64_t>::min();
          if (truncated >= std::numeric_limits<int64_t>::min() &&
              truncated <= kMaxDoubleRepresentableInt64) {
            result = static_cast<int64_t>(truncated);
          }
          return __ Word64Constant(result);
        }
        if (to == WordRepresentation::Word32()) {
          int32_t result = std::numeric_limits<int32_t>::min();
          if (truncated >= std::numeric_limits<int32_t>::min() &&
              truncated <= std::numeric_limits<int32_t>::max()) {
            result = static_cast<int32_t>(truncated);
          }
          return __ Word32Constant(result);
        }
      }
      if (kind == Kind::kJSFloatTruncate &&
          to == WordRepresentation::Word32()) {
        return __ Word32Constant(DoubleToInt32_NoInline(value.get_scalar()));
      }
      if (kind == Kind::kExtractHighHalf) {
        DCHECK_EQ(to, RegisterRepresentation::Word32());
        return __ Word32Constant(static_cast<uint32_t>(value.get_bits() >> 32));
      }
      if (kind == Kind::kExtractLowHalf) {
        DCHECK_EQ(to, RegisterRepresentation::Word32());
        return __ Word32Constant(static_cast<uint32_t>(value.get_bits()));
      }
    }
    if (float value; from == RegisterRepresentation::Float32() &&
                     matcher_.MatchFloat32Constant(input, &value)) {
      if (kind == Kind::kFloatConversion &&
          to == RegisterRepresentation::Float64()) {
        return __ Float64Constant(value);
      }
    }

    const Operation& input_op = matcher_.Get(input);
    if (const ChangeOp* change_op = input_op.TryCast<ChangeOp>()) {
      if (change_op->from == to && change_op->to == from &&
          change_op->IsReversibleBy(kind, signalling_nan_possible)) {
        return change_op->input();
      }
    }
    return Next::ReduceChange(input, kind, assumption, from, to);
  }

  V<Float64> REDUCE(BitcastWord32PairToFloat64)(V<Word32> hi_word32,
                                                V<Word32> lo_word32) {
    if (ShouldSkipOptimizationStep()) {
      return Next::ReduceBitcastWord32PairToFloat64(hi_word32, lo_word32);
    }
    uint32_t lo, hi;
    if (matcher_.MatchIntegralWord32Constant(hi_word32, &hi) &&
        matcher_.MatchIntegralWord32Constant(lo_word32, &lo)) {
      return __ Float64Constant(
          base::bit_cast<double>(uint64_t{hi} << 32 | uint64_t{lo}));
    }
    return Next::ReduceBitcastWord32PairToFloat64(hi_word32, lo_word32);
  }

  OpIndex REDUCE(TaggedBitcast)(OpIndex input, RegisterRepresentation from,
                                RegisterRepresentation to,
                                TaggedBitcastOp::Kind kind) {
    if (ShouldSkipOptimizationStep()) {
      return Next::ReduceTaggedBitcast(input, from, to, kind);
    }
    // A Tagged -> Untagged -> Tagged sequence can be short-cut.
    // An Untagged -> Tagged -> Untagged sequence however cannot be removed,
    // because the GC might have modified the pointer.
    if (auto* input_bitcast = matcher_.TryCast<TaggedBitcastOp>(input)) {
      if (all_of(input_bitcast->to, from) ==
              RegisterRepresentation::WordPtr() &&
          all_of(input_bitcast->from, to) == RegisterRepresentation::Tagged()) {
        return input_bitcast->input();
      }
    }
    // An Untagged -> Smi -> Untagged sequence can be short-cut.
    if (auto* input_bitcast = matcher_.TryCast<TaggedBitcastOp>(input);
        input_bitcast && to.IsWord() &&
        (kind == TaggedBitcastOp::Kind::kSmi ||
         input_bitcast->kind == TaggedBitcastOp::Kind::kSmi)) {
      if (input_bitcast->from == to) return input_bitcast->input();
      if (input_bitcast->from == RegisterRepresentation::Word32()) {
        DCHECK_EQ(to, RegisterRepresentation::Word64());
        return __ BitcastWord32ToWord64(input_bitcast->input());
      }
      DCHECK(input_bitcast->from == RegisterRepresentation::Word64() &&
             to == RegisterRepresentation::Word32());
      return __ TruncateWord64ToWord32(input_bitcast->input());
    }
    // Try to constant-fold TaggedBitcast from Word Constant to Word.
    if (to.IsWord()) {
      if (const ConstantOp* cst = matcher_.TryCast<ConstantOp>(input)) {
        if (cst->kind == ConstantOp::Kind::kWord32 ||
            cst->kind == ConstantOp::Kind::kWord64) {
          if (to == RegisterRepresentation::Word64()) {
            return __ Word64Constant(cst->integral());
          } else {
            DCHECK_EQ(to, RegisterRepresentation::Word32());
            return __ Word32Constant(static_cast<uint32_t>(cst->integral()));
          }
        }
      }
    }
    if (const ConstantOp* cst = matcher_.TryCast<ConstantOp>(input)) {
      // Try to constant-fold Word constant -> Tagged (Smi).
      if (cst->IsIntegral() && to == RegisterRepresentation::Tagged()) {
        if (Smi::IsValid(cst->integral())) {
          return __ SmiConstant(
              i::Tagged<Smi>(static_cast<intptr_t>(cst->integral())));
        }
      }
      // Try to constant-fold Smi -> Untagged.
      if (cst->kind == ConstantOp::Kind::kSmi) {
        if (to == RegisterRepresentation::Word32()) {
          return __ Word32Constant(static_cast<uint32_t>(cst->smi().ptr()));
        } else if (to == RegisterRepresentation::Word64()) {
          return __ Word64Constant(static_cast<uint64_t>(cst->smi().ptr()));
        }
      }
    }
    return Next::ReduceTaggedBitcast(input, from, to, kind);
  }

  V<Float> REDUCE(FloatUnary)(V<Float> input, FloatUnaryOp::Kind kind,
                              FloatRepresentation rep) {
    if (ShouldSkipOptimizationStep()) {
      return Next::ReduceFloatUnary(input, kind, rep);
    }
    if (float k; rep == FloatRepresentation::Float32() &&
                 matcher_.MatchFloat32Constant(input, &k)) {
      if (std::isnan(k) && !signalling_nan_possible) {
        return __ Float32Constant(std::numeric_limits<float>::quiet_NaN());
      }
      switch (kind) {
        case FloatUnaryOp::Kind::kAbs:
          return __ Float32Constant(std::abs(k));
        case FloatUnaryOp::Kind::kNegate:
          return __ Float32Constant(-k);
        case FloatUnaryOp::Kind::kSilenceNaN:
          DCHECK(!std::isnan(k));
          return __ Float32Constant(k);
        case FloatUnaryOp::Kind::kRoundDown:
          return __ Float32Constant(std::floor(k));
        case FloatUnaryOp::Kind::kRoundUp:
          return __ Float32Constant(std::ceil(k));
        case FloatUnaryOp::Kind::kRoundToZero:
          return __ Float32Constant(std::trunc(k));
        case FloatUnaryOp::Kind::kRoundTiesEven:
          DCHECK_EQ(std::nearbyint(1.5), 2);
          DCHECK_EQ(std::nearbyint(2.5), 2);
          return __ Float32Constant(std::nearbyint(k));
        case FloatUnaryOp::Kind::kLog:
          return __ Float32Constant(base::ieee754::log(k));
        case FloatUnaryOp::Kind::kSqrt:
          return __ Float32Constant(std::sqrt(k));
        case FloatUnaryOp::Kind::kExp:
          return __ Float32Constant(base::ieee754::exp(k));
        case FloatUnaryOp::Kind::kExpm1:
          return __ Float32Constant(base::ieee754::expm1(k));
        case FloatUnaryOp::Kind::kSin:
          return __ Float32Constant(SIN_IMPL(k));
        case FloatUnaryOp::Kind::kCos:
          return __ Float32Constant(COS_IMPL(k));
        case FloatUnaryOp::Kind::kSinh:
          return __ Float32Constant(base::ieee754::sinh(k));
        case FloatUnaryOp::Kind::kCosh:
          return __ Float32Constant(base::ieee754::cosh(k));
        case FloatUnaryOp::Kind::kAcos:
          return __ Float32Constant(base::ieee754::acos(k));
        case FloatUnaryOp::Kind::kAsin:
          return __ Float32Constant(base::ieee754::asin(k));
        case FloatUnaryOp::Kind::kAsinh:
          return __ Float32Constant(base::ieee754::asinh(k));
        case FloatUnaryOp::Kind::kAcosh:
          return __ Float32Constant(base::ieee754::acosh(k));
        case FloatUnaryOp::Kind::kTan:
          return __ Float32Constant(base::ieee754::tan(k));
        case FloatUnaryOp::Kind::kTanh:
          return __ Float32Constant(base::ieee754::tanh(k));
        case FloatUnaryOp::Kind::kLog2:
          return __ Float32Constant(base::ieee754::log2(k));
        case FloatUnaryOp::Kind::kLog10:
          return __ Float32Constant(base::ieee754::log10(k));
        case FloatUnaryOp::Kind::kLog1p:
          return __ Float32Constant(base::ieee754::log1p(k));
        case FloatUnaryOp::Kind::kCbrt:
          return __ Float32Constant(base::ieee754::cbrt(k));
        case FloatUnaryOp::Kind::kAtan:
          return __ Float32Constant(base::ieee754::atan(k));
        case FloatUnaryOp::Kind::kAtanh:
          return __ Float32Constant(base::ieee754::atanh(k));
      }
    } else if (double k; rep == FloatRepresentation::Float64() &&
                         matcher_.MatchFloat64Constant(input, &k)) {
      if (std::isnan(k) && !signalling_nan_possible) {
        return __ Float64Constant(std::numeric_limits<double>::quiet_NaN());
      }
      switch (kind) {
        case FloatUnaryOp::Kind::kAbs:
          return __ Float64Constant(std::abs(k));
        case FloatUnaryOp::Kind::kNegate:
          return __ Float64Constant(-k);
        case FloatUnaryOp::Kind::kSilenceNaN:
          DCHECK(!std::isnan(k));
          return __ Float64Constant(k);
        case FloatUnaryOp::Kind::kRoundDown:
          return __ Float64Constant(std::floor(k));
        case FloatUnaryOp::Kind::kRoundUp:
          return __ Float64Constant(std::ceil(k));
        case FloatUnaryOp::Kind::kRoundToZero:
          return __ Float64Constant(std::trunc(k));
        case FloatUnaryOp::Kind::kRoundTiesEven:
          DCHECK_EQ(std::nearbyint(1.5), 2);
          DCHECK_EQ(std::nearbyint(2.5), 2);
          return __ Float64Constant(std::nearbyint(k));
        case FloatUnaryOp::Kind::kLog:
          return __ Float64Constant(base::ieee754::log(k));
        case FloatUnaryOp::Kind::kSqrt:
          return __ Float64Constant(std::sqrt(k));
        case FloatUnaryOp::Kind::kExp:
          return __ Float64Constant(base::ieee754::exp(k));
        case FloatUnaryOp::Kind::kExpm1:
          return __ Float64Constant(base::ieee754::expm1(k));
        case FloatUnaryOp::Kind::kSin:
          return __ Float64Constant(SIN_IMPL(k));
        case FloatUnaryOp::Kind::kCos:
          return __ Float64Constant(COS_IMPL(k));
        case FloatUnaryOp::Kind::kSinh:
          return __ Float64Constant(base::ieee754::sinh(k));
        case FloatUnaryOp::Kind::kCosh:
          return __ Float64Constant(base::ieee754::cosh(k));
        case FloatUnaryOp::Kind::kAcos:
          return __ Float64Constant(base::ieee754::acos(k));
        case FloatUnaryOp::Kind::kAsin:
          return __ Float64Constant(base::ieee754::asin(k));
        case FloatUnaryOp::Kind::kAsinh:
          return __ Float64Constant(base::ieee754::asinh(k));
        case FloatUnaryOp::Kind::kAcosh:
          return __ Float64Constant(base::ieee754::acosh(k));
        case FloatUnaryOp::Kind::kTan:
          return __ Float64Constant(base::ieee754::tan(k));
        case FloatUnaryOp::Kind::kTanh:
          return __ Float64Constant(base::ieee754::tanh(k));
        case FloatUnaryOp::Kind::kLog2:
          return __ Float64Constant(base::ieee754::log2(k));
        case FloatUnaryOp::Kind::kLog10:
          return __ Float64Constant(base::ieee754::log10(k));
        case FloatUnaryOp::Kind::kLog1p:
          return __ Float64Constant(base::ieee754::log1p(k));
        case FloatUnaryOp::Kind::kCbrt:
          return __ Float64Constant(base::ieee754::cbrt(k));
        case FloatUnaryOp::Kind::kAtan:
          return __ Float64Constant(base::ieee754::atan(k));
        case FloatUnaryOp::Kind::kAtanh:
          return __ Float64Constant(base::ieee754::atanh(k));
      }
    }
    return Next::ReduceFloatUnary(input, kind, rep);
  }

  V<Word> REDUCE(WordUnary)(V<Word> input, WordUnaryOp::Kind kind,
                            WordRepresentation rep) {
    if (ShouldSkipOptimizationStep()) {
      return Next::ReduceWordUnary(input, kind, rep);
    }
    if (rep == WordRepresentation::Word32()) {
      input = TryRemoveWord32ToWord64Conversion(input);
    }
    if (uint32_t k; rep == WordRepresentation::Word32() &&
                    matcher_.MatchIntegralWord32Constant(input, &k)) {
      switch (kind) {
        case WordUnaryOp::Kind::kReverseBytes:
          return __ Word32Constant(base::bits::ReverseBytes(k));
        case WordUnaryOp::Kind::kCountLeadingZeros:
          return __ Word32Constant(base::bits::CountLeadingZeros(k));
        case WordUnaryOp::Kind::kCountTrailingZeros:
          return __ Word32Constant(base::bits::CountTrailingZeros(k));
        case WordUnaryOp::Kind::kPopCount:
          return __ Word32Constant(base::bits::CountPopulation(k));
        case WordUnaryOp::Kind::kSignExtend8:
          return __ Word32Constant(int32_t{static_cast<int8_t>(k)});
        case WordUnaryOp::Kind::kSignExtend16:
          return __ Word32Constant(int32_t{static_cast<int16_t>(k)});
      }
    } else if (uint64_t k; rep == WordRepresentation::Word64() &&
                           matcher_.MatchIntegralWord64Constant(input, &k)) {
      switch (kind) {
        case WordUnaryOp::Kind::kReverseBytes:
          return __ Word64Constant(base::bits::ReverseBytes(k));
        case WordUnaryOp::Kind::kCountLeadingZeros:
          return __ Word64Constant(uint64_t{base::bits::CountLeadingZeros(k)});
        case WordUnaryOp::Kind::kCountTrailingZeros:
          return __ Word64Constant(uint64_t{base::bits::CountTrailingZeros(k)});
        case WordUnaryOp::Kind::kPopCount:
          return __ Word64Constant(uint64_t{base::bits::CountPopulation(k)});
        case WordUnaryOp::Kind::kSignExtend8:
          return __ Word64Constant(int64_t{static_cast<int8_t>(k)});
        case WordUnaryOp::Kind::kSignExtend16:
          return __ Word64Constant(int64_t{static_cast<int16_t>(k)});
      }
    }
    return Next::ReduceWordUnary(input, kind, rep);
  }

  V<Float> REDUCE(FloatBinop)(V<Float> lhs, V<Float> rhs,
                              FloatBinopOp::Kind kind,
                              FloatRepresentation rep) {
    if (ShouldSkipOptimizationStep()) {
      return Next::ReduceFloatBinop(lhs, rhs, kind, rep);
    }

    using Kind = FloatBinopOp::Kind;

    // Place constant on the right for commutative operators.
    if (FloatBinopOp::IsCommutative(kind) && matcher_.Is<ConstantOp>(lhs) &&
        !matcher_.Is<ConstantOp>(rhs)) {
      return ReduceFloatBinop(rhs, lhs, kind, rep);
    }

    // constant folding
    if (float k1, k2; rep == FloatRepresentation::Float32() &&
                      matcher_.MatchFloat32Constant(lhs, &k1) &&
                      matcher_.MatchFloat32Constant(rhs, &k2)) {
      switch (kind) {
        case Kind::kAdd:
          return __ Float32Constant(k1 + k2);
        case Kind::kMul:
          return __ Float32Constant(k1 * k2);
        case Kind::kSub:
          return __ Float32Constant(k1 - k2);
        case Kind::kMin:
          return __ Float32Constant(JSMin(k1, k2));
        case Kind::kMax:
          return __ Float32Constant(JSMax(k1, k2));
        case Kind::kDiv:
          return __ Float32Constant(k1 / k2);
        case Kind::kPower:
          return __ Float32Constant(internal::math::pow(k1, k2));
        case Kind::kAtan2:
          return __ Float32Constant(base::ieee754::atan2(k1, k2));
        case Kind::kMod:
          UNREACHABLE();
      }
    }
    if (double k1, k2; rep == FloatRepresentation::Float64() &&
                       matcher_.MatchFloat64Constant(lhs, &k1) &&
                       matcher_.MatchFloat64Constant(rhs, &k2)) {
      switch (kind) {
        case Kind::kAdd:
          return __ Float64Constant(k1 + k2);
        case Kind::kMul:
          return __ Float64Constant(k1 * k2);
        case Kind::kSub:
          return __ Float64Constant(k1 - k2);
        case Kind::kMin:
          return __ Float64Constant(JSMin(k1, k2));
        case Kind::kMax:
          return __ Float64Constant(JSMax(k1, k2));
        case Kind::kDiv:
          return __ Float64Constant(k1 / k2);
        case Kind::kMod:
          return __ Float64Constant(Modulo(k1, k2));
        case Kind::kPower:
          return __ Float64Constant(math::pow(k1, k2));
        case Kind::kAtan2:
          return __ Float64Constant(base::ieee754::atan2(k1, k2));
      }
    }

    // lhs <op> NaN  =>  NaN
    if (matcher_.MatchNaN(rhs) ||
        (matcher_.MatchNaN(lhs) && kind != Kind::kPower)) {
      // Return a quiet NaN since Wasm operations could have signalling NaN as
      // input but not as output.
      return __ FloatConstant(std::numeric_limits<double>::quiet_NaN(), rep);
    }

    if (matcher_.Is<ConstantOp>(rhs)) {
      if (kind == Kind::kMul) {
        // lhs * 1  =>  lhs
        if (!signalling_nan_possible && matcher_.MatchFloat(rhs, 1.0)) {
          return lhs;
        }
        // lhs * 2  =>  lhs + lhs
        if (matcher_.MatchFloat(rhs, 2.0)) {
          return __ FloatAdd(lhs, lhs, rep);
        }
        // lhs * -1  =>  -lhs
        if (!signalling_nan_possible && matcher_.MatchFloat(rhs, -1.0)) {
          return __ FloatNegate(lhs, rep);
        }
      }

      if (kind == Kind::kDiv) {
        // lhs / 1  =>  lhs
        if (!signalling_nan_possible && matcher_.MatchFloat(rhs, 1.0)) {
          return lhs;
        }
        // lhs / -1  =>  -lhs
        if (!signalling_nan_possible && matcher_.MatchFloat(rhs, -1.0)) {
          return __ FloatNegate(lhs, rep);
        }
        // All reciprocals of non-denormal powers of two can be represented
        // exactly, so division by power of two can be reduced to
        // multiplication by reciprocal, with the same result.
        // x / k  =>  x * (1 / k)
        if (rep == FloatRepresentation::Float32()) {
          if (float k;
              matcher_.MatchFloat32Constant(rhs, &k) && std::isnormal(k) &&
              k != 0 && std::isfinite(k) &&
              base::bits::IsPowerOfTwo(base::Double(k).Significand())) {
            return __ FloatMul(lhs, __ FloatConstant(1.0 / k, rep), rep);
          }
        } else {
          DCHECK_EQ(rep, FloatRepresentation::Float64());
          if (double k;
              matcher_.MatchFloat64Constant(rhs, &k) && std::isnormal(k) &&
              k != 0 && std::isfinite(k) &&
              base::bits::IsPowerOfTwo(base::Double(k).Significand())) {
            return __ FloatMul(lhs, __ FloatConstant(1.0 / k, rep), rep);
          }
        }
      }

      if (kind == Kind::kMod) {
        // x % 0  =>  NaN
        if (matcher_.MatchFloat(rhs, 0.0)) {
          return __ FloatConstant(std::numeric_limits<double>::quiet_NaN(),
                                  rep);
        }
      }

      if (kind == Kind::kSub) {
        // lhs - +0.0  =>  lhs
        if (!signalling_nan_possible && matcher_.MatchFloat(rhs, +0.0)) {
          return lhs;
        }
      }

      if (kind == Kind::kPower) {
        if (matcher_.MatchFloat(rhs, 0.0) || matcher_.MatchFloat(rhs, -0.0)) {
          // lhs ** 0  ==>  1
          return __ FloatConstant(1.0, rep);
        }
        if (matcher_.MatchFloat(rhs, 2.0)) {
          // lhs ** 2  ==>  lhs * lhs
          return __ FloatMul(lhs, lhs, rep);
        }
        if (matcher_.MatchFloat(rhs, 0.5)) {
          // lhs ** 0.5  ==>  sqrt(lhs)
          // (unless if lhs is -infinity)
          Variable result = __ NewLoopInvariantVariable(rep);
          IF (UNLIKELY(__ FloatLessThanOrEqual(
                  lhs, __ FloatConstant(-V8_INFINITY, rep), rep))) {
            __ SetVariable(result, __ FloatConstant(V8_INFINITY, rep));
          } ELSE {
            __ SetVariable(result, __ FloatSqrt(lhs, rep));
          }

          return __ GetVariable(result);
        }
      }
    }

    if (!signalling_nan_possible && kind == Kind::kSub &&
        matcher_.MatchFloat(lhs, -0.0)) {
      // -0.0 - round_down(-0.0 - y) => round_up(y)
      if (V<Float> a, b, c;
          FloatUnaryOp::IsSupported(FloatUnaryOp::Kind::kRoundUp, rep) &&
          matcher_.MatchFloatRoundDown(rhs, &a, rep) &&
          matcher_.MatchFloatSub(a, &b, &c, rep) &&
          matcher_.MatchFloat(b, -0.0)) {
        return __ FloatRoundUp(c, rep);
      }
      // -0.0 - rhs  =>  -rhs
      return __ FloatNegate(rhs, rep);
    }

    return Next::ReduceFloatBinop(lhs, rhs, kind, rep);
  }

  V<Word> REDUCE(WordBinop)(V<Word> left, V<Word> right, WordBinopOp::Kind kind,
                            WordRepresentation rep) {
    if (ShouldSkipOptimizationStep()) {
      return Next::ReduceWordBinop(left, right, kind, rep);
    }

    using Kind = WordBinopOp::Kind;

    DCHECK_EQ(rep, any_of(WordRepresentation::Word32(),
                          WordRepresentation::Word64()));
    bool is_64 = rep == WordRepresentation::Word64();

    if (!is_64) {
      left = TryRemoveWord32ToWord64Conversion(left);
      right = TryRemoveWord32ToWord64Conversion(right);
    }

    // Place constant on the right for commutative operators.
    if (WordBinopOp::IsCommutative(kind) && matcher_.Is<ConstantOp>(left) &&
        !matcher_.Is<ConstantOp>(right)) {
      return ReduceWordBinop(right, left, kind, rep);
    }
    // constant folding
    if (uint64_t k1, k2; matcher_.MatchIntegralWordConstant(left, rep, &k1) &&
                         matcher_.MatchIntegralWordConstant(right, rep, &k2)) {
      switch (kind) {
        case Kind::kAdd:
          return __ WordConstant(k1 + k2, rep);
        case Kind::kMul:
          return __ WordConstant(k1 * k2, rep);
        case Kind::kBitwiseAnd:
          return __ WordConstant(k1 & k2, rep);
        case Kind::kBitwiseOr:
          return __ WordConstant(k1 | k2, rep);
        case Kind::kBitwiseXor:
          return __ WordConstant(k1 ^ k2, rep);
        case Kind::kSub:
          return __ WordConstant(k1 - k2, rep);
        case Kind::kSignedMulOverflownBits:
          return __ WordConstant(
              is_64 ? base::bits::SignedMulHigh64(static_cast<int64_t>(k1),
                                                  static_cast<int64_t>(k2))
                    : base::bits::SignedMulHigh32(static_cast<int32_t>(k1),
```