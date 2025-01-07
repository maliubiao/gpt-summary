Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/turboshaft/machine-optimization-reducer.h`.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Task:** The code is within a class or struct named `MachineOptimizationReducer`. The name strongly suggests its purpose: to optimize machine-level operations within the Turboshaft compiler pipeline. Specifically, it aims to *reduce* or simplify these operations.

2. **Analyze the Primary Function:** The code primarily focuses on a function called `ReduceWordBinop`. This function takes two word-sized operands (`left`, `right`), a binary operation kind (`kind`), and the representation of the operands (`rep`). This immediately signals that the code is about optimizing binary operations on machine words (integers).

3. **Examine the Optimization Strategies:**  Scan the `ReduceWordBinop` function for common optimization patterns. Key observations:
    * **Constant Folding:**  The code checks if both operands are constants and performs the operation at compile time (e.g., `k1 + k2`).
    * **Identity and Zero Element Elimination:**  It handles cases where one operand is zero or one (e.g., `left + 0` becomes `left`, `left * 0` becomes `0`).
    * **Algebraic Simplifications:** It applies algebraic identities (e.g., `left - k` becomes `left + -k`).
    * **Bitwise Operation Optimizations:**  There's special handling for bitwise AND, OR, and XOR, including recognizing bitfield extractions and combinations.
    * **Shift and Rotate Optimizations:**  It recognizes patterns involving shifts that can be combined into rotate operations.
    * **Division and Modulo Optimizations:** It optimizes division and modulo by constants, including powers of two.
    * **Associativity:** It leverages the associative property of some operations to reorder and potentially constant-fold.

4. **Look for Related Functions:**  The code calls other `Reduce...` functions (e.g., `ReduceSignedDiv`, `ReduceUnsignedDiv`, `ReduceOverflowCheckedBinop`, `ReduceComparison`). This indicates that the reducer handles other types of machine operations as well.

5. **Check for Helper Functions:** The presence of `TryMatchHeapObject` suggests the reducer might interact with tagged values or heap objects, which are common in JavaScript engines. The `IsWord32ConvertedToWord64`, `UndoWord32ToWord64Conversion`, etc., point to handling different word sizes and potential conversions between them.

6. **Infer the Context:** The code resides in the `v8/src/compiler/turboshaft` directory. This places it within V8's compilation pipeline and specifically within the Turboshaft compiler, a relatively newer and more modern compiler in V8.

7. **Address Specific Instructions:**
    * **File Extension:**  The prompt mentions checking for `.tq`. The provided code is `.h`, so it's a C++ header file, not Torque.
    * **JavaScript Relevance:**  The optimizations, though happening at the machine level, directly impact the performance of JavaScript code by making the generated machine code more efficient. Give concrete JavaScript examples that would lead to the optimized machine code.
    * **Code Logic Reasoning:**  Provide an example of constant folding with input and output.
    * **Common Programming Errors:**  Illustrate a common error that these optimizations might mitigate (e.g., unnecessary masking).

8. **Synthesize the Information for the Summary (Part 2):** Combine the individual observations into a concise summary of the `MachineOptimizationReducer`'s role and capabilities. Emphasize that it simplifies machine-level operations for performance gains.

9. **Review and Refine:** Ensure the answer is clear, accurate, and addresses all aspects of the prompt. Use precise terminology where appropriate (e.g., "constant folding," "bitwise operations"). Structure the answer logically with headings and bullet points for readability.
```cpp
                         static_cast<int32_t>(k2)),
              rep);
        case Kind::kUnsignedMulOverflownBits:
          return __ WordConstant(
              is_64 ? base::bits::UnsignedMulHigh64(k1, k2)
                    : base::bits::UnsignedMulHigh32(static_cast<uint32_t>(k1),
                                                    static_cast<uint32_t>(k2)),
              rep);
        case Kind::kSignedDiv:
          return __ WordConstant(
              is_64 ? base::bits::SignedDiv64(k1, k2)
                    : base::bits::SignedDiv32(static_cast<int32_t>(k1),
                                              static_cast<int32_t>(k2)),
              rep);
        case Kind::kUnsignedDiv:
          return __ WordConstant(
              is_64 ? base::bits::UnsignedDiv64(k1, k2)
                    : base::bits::UnsignedDiv32(static_cast<uint32_t>(k1),
                                                static_cast<uint32_t>(k2)),
              rep);
        case Kind::kSignedMod:
          return __ WordConstant(
              is_64 ? base::bits::SignedMod64(k1, k2)
                    : base::bits::SignedMod32(static_cast<int32_t>(k1),
                                              static_cast<int32_t>(k2)),
              rep);
        case Kind::kUnsignedMod:
          return __ WordConstant(
              is_64 ? base::bits::UnsignedMod64(k1, k2)
                    : base::bits::UnsignedMod32(static_cast<uint32_t>(k1),
                                                static_cast<uint32_t>(k2)),
              rep);
      }
    }

    if (kind == WordBinopOp::Kind::kBitwiseAnd &&
        rep == WordRepresentation::Word32()) {
      if (auto right_bitfield = detail::BitfieldCheck::Detect(
              matcher_, __ output_graph(), right)) {
        if (auto left_bitfield = detail::BitfieldCheck::Detect(
                matcher_, __ output_graph(), left)) {
          if (auto combined_bitfield =
                  left_bitfield->TryCombine(*right_bitfield)) {
            OpIndex source = combined_bitfield->source;
            if (combined_bitfield->truncate_from_64_bit) {
              source = __ TruncateWord64ToWord32(source);
            }
            return __ Word32Equal(
                __ Word32BitwiseAnd(source, combined_bitfield->mask),
                combined_bitfield->masked_value);
          }
        }
      }
    }

    if (uint64_t right_value;
        matcher_.MatchIntegralWordConstant(right, rep, &right_value)) {
      // TODO(jkummerow): computing {right_value_signed} could probably be
      // handled by the 4th argument to {MatchIntegralWordConstant}.
      int64_t right_value_signed =
          is_64 ? static_cast<int64_t>(right_value)
                : int64_t{static_cast<int32_t>(right_value)};
      // (a <op> k1) <op> k2  =>  a <op> (k1 <op> k2)
      if (V<Word> a, k1; WordBinopOp::IsAssociative(kind) &&
                         matcher_.MatchWordBinop(left, &a, &k1, kind, rep) &&
                         matcher_.Is<ConstantOp>(k1)) {
        V<Word> k2 = right;
        // This optimization allows to do constant folding of `k1` and `k2`.
        // However, if (a <op> k1) has to be calculated anyways, then constant
        // folding does not save any calculations during runtime, and it may
        // increase register pressure because it extends the lifetime of `a`.
        // Therefore we do the optimization only when `left = (a <op k1)` has no
        // other uses.
        if (matcher_.Get(left).saturated_use_count.IsZero()) {
          return ReduceWordBinop(a, ReduceWordBinop(k1, k2, kind, rep), kind,
                                 rep);
        }
      }
      switch (kind) {
        case Kind::kSub:
          // left - k  =>  left + -k
          return ReduceWordBinop(left, __ WordConstant(-right_value, rep),
                                 Kind::kAdd, rep);
        case Kind::kAdd:
          // left + 0  =>  left
          if (right_value == 0) {
            return left;
          }
          break;
        case Kind::kBitwiseXor:
          // left ^ 0  =>  left
          if (right_value == 0) {
            return left;
          }
          // left ^ 1  =>  left == 0  if left is 0 or 1
          if (right_value == 1 && IsBit(left)) {
            return __ Word32Equal(V<Word32>::Cast(left), 0);
          }
          // (x ^ -1) ^ -1  =>  x
          {
            V<Word> x, y;
            int64_t k;
            if (right_value_signed == -1 &&
                matcher_.MatchBitwiseAnd(left, &x, &y, rep) &&
                matcher_.MatchIntegralWordConstant(y, rep, &k) && k == -1) {
              return x;
            }
          }
          break;
        case Kind::kBitwiseOr:
          // left | 0  =>  left
          if (right_value == 0) {
            return left;
          }
          // left | -1  =>  -1
          if (right_value_signed == -1) {
            return right;
          }
          // (x & K1) | K2 => x | K2 if K2 has ones for every zero bit in K1.
          // This case can be constructed by UpdateWord and UpdateWord32 in CSA.
          {
            V<Word> x, y;
            uint64_t k1;
            uint64_t k2 = right_value;
            if (matcher_.MatchBitwiseAnd(left, &x, &y, rep) &&
                matcher_.MatchIntegralWordConstant(y, rep, &k1) &&
                (k1 | k2) == rep.MaxUnsignedValue()) {
              return __ WordBitwiseOr(x, right, rep);
            }
          }
          break;
        case Kind::kMul:
          // left * 0  =>  0
          if (right_value == 0) {
            return __ WordConstant(0, rep);
          }
          // left * 1  =>  left
          if (right_value == 1) {
            return left;
          }
          // left * -1 => 0 - left
          if (right_value_signed == -1) {
            return __ WordSub(__ WordConstant(0, rep), left, rep);
          }
          // left * 2^k  =>  left << k
          if (base::bits::IsPowerOfTwo(right_value)) {
            return __ ShiftLeft(left, base::bits::WhichPowerOfTwo(right_value),
                                rep);
          }
          break;
        case Kind::kBitwiseAnd:
          // left & -1 => left
          if (right_value_signed == -1) {
            return left;
          }
          // x & 0  =>  0
          if (right_value == 0) {
            return right;
          }

          if (right_value == 1) {
            // (x + x) & 1  =>  0
            V<Word> left_ignore_extensions =
                IsWord32ConvertedToWord64(left)
                    ? UndoWord32ToWord64Conversion(left)
                    : left;
            if (V<Word> a, b;
                matcher_.MatchWordAdd(left_ignore_extensions, &a, &b,
                                      WordRepresentation::Word32()) &&
                a == b) {
              return __ WordConstant(0, rep);
            }

            // CMP & 1  =>  CMP
            if (IsBit(left_ignore_extensions)) {
              return left;
            }

            static_assert(kSmiTagMask == 1);
            // HeapObject & 1 => 1  ("& 1" is a Smi-check)
            if (TryMatchHeapObject(left)) {
              return __ WordConstant(1, rep);
            }
          }

          // asm.js often benefits from these transformations, to optimize out
          // unnecessary memory access alignment masks. Conventions used in
          // the comments below:
          // x, y: arbitrary values
          // K, L, M: arbitrary constants
          // (-1 << K) == mask: the right-hand side of the bitwise AND.
          if (IsNegativePowerOfTwo(right_value_signed)) {
            uint64_t mask = right_value;
            int K = base::bits::CountTrailingZeros64(mask);
            V<Word> x, y;
            {
              int L;
              //   (x << L) & (-1 << K)
              // => x << L               iff L >= K
              if (matcher_.MatchConstantLeftShift(left, &x, rep, &L) &&
                  L >= K) {
                return left;
              }
            }

            if (matcher_.MatchWordAdd(left, &x, &y, rep)) {
              uint64_t L;  // L == (M << K) iff (L & mask) == L.

              //    (x              + (M << K)) & (-1 << K)
              // => (x & (-1 << K)) + (M << K)
              if (matcher_.MatchIntegralWordConstant(y, rep, &L) &&
                  (L & mask) == L) {
                return __ WordAdd(__ WordBitwiseAnd(x, right, rep),
                                  __ WordConstant(L, rep), rep);
              }

              //   (x1 * (M << K) + y) & (-1 << K)
              // => x1 * (M << K) + (y & (-1 << K))
              V<Word> x1, x2, y1, y2;
              if (matcher_.MatchWordMul(x, &x1, &x2, rep) &&
                  matcher_.MatchIntegralWordConstant(x2, rep, &L) &&
                  (L & mask) == L) {
                return __ WordAdd(x, __ WordBitwiseAnd(y, right, rep), rep);
              }
              // Same as above with swapped order:
              //    (x              + y1 * (M << K)) & (-1 << K)
              // => (x & (-1 << K)) + y1 * (M << K)
              if (matcher_.MatchWordMul(y, &y1, &y2, rep) &&
                  matcher_.MatchIntegralWordConstant(y2, rep, &L) &&
                  (L & mask) == L) {
                return __ WordAdd(__ WordBitwiseAnd(x, right, rep), y, rep);
              }

              //   ((x1 << K) + y) & (-1 << K)
              // => (x1 << K) + (y & (-1 << K))
              int K2;
              if (matcher_.MatchConstantLeftShift(x, &x1, rep, &K2) &&
                  K2 == K) {
                return __ WordAdd(x, __ WordBitwiseAnd(y, right, rep), rep);
              }
              // Same as above with swapped order:
              //    (x +              (y1 << K)) & (-1 << K)
              // => (x & (-1 << K)) + (y1 << K)
              if (matcher_.MatchConstantLeftShift(y, &y1, rep, &K2) &&
                  K2 == K) {
                return __ WordAdd(__ WordBitwiseAnd(x, right, rep), y, rep);
              }
            } else if (matcher_.MatchWordMul(left, &x, &y, rep)) {
              // (x * (M << K)) & (-1 << K) => x * (M << K)
              uint64_t L;  // L == (M << K) iff (L & mask) == L.
              if (matcher_.MatchIntegralWordConstant(y, rep, &L) &&
                  (L & mask) == L) {
                return left;
              }
            }
          }
          break;
        case WordBinopOp::Kind::kSignedDiv:
          return ReduceSignedDiv(left, right_value_signed, rep);
        case WordBinopOp::Kind::kUnsignedDiv:
          return ReduceUnsignedDiv(left, right_value, rep);
        case WordBinopOp::Kind::kSignedMod:
          // left % 0  =>  0
          // left % 1  =>  0
          // left % -1  =>  0
          if (right_value_signed == any_of(0, 1, -1)) {
            return __ WordConstant(0, rep);
          }
          if (right_value_signed != rep.MinSignedValue()) {
            right_value_signed = Abs(right_value_signed);
          }
          // left % 2^n  =>  ((left + m) & (2^n - 1)) - m
          // where m = (left >> bits-1) >>> bits-n
          // This is a branch-free version of the following:
          // left >= 0 ? left & (2^n - 1)
          //           : ((left + (2^n - 1)) & (2^n - 1)) - (2^n - 1)
          // Adding and subtracting (2^n - 1) before and after the bitwise-and
          // keeps the result congruent modulo 2^n, but shifts the resulting
          // value range to become -(2^n - 1) ... 0.
          if (base::bits::IsPowerOfTwo(right_value_signed)) {
            uint32_t bits = rep.bit_width();
            uint32_t n = base::bits::WhichPowerOfTwo(right_value_signed);
            V<Word> m = __ ShiftRightLogical(
                __ ShiftRightArithmetic(left, bits - 1, rep), bits - n, rep);
            return __ WordSub(
                __ WordBitwiseAnd(__ WordAdd(left, m, rep),
                                  __ WordConstant(right_value_signed - 1, rep),
                                  rep),
                m, rep);
          }
          // The `IntDiv` with a constant right-hand side will be turned into a
          // multiplication, avoiding the expensive integer division.
          return __ WordSub(
              left, __ WordMul(__ IntDiv(left, right, rep), right, rep), rep);
        case WordBinopOp::Kind::kUnsignedMod:
          // left % 0  =>  0
          // left % 1  =>  0
          if (right_value == 0 || right_value == 1) {
            return __ WordConstant(0, rep);
          }
          // x % 2^n => x & (2^n - 1)
          if (base::bits::IsPowerOfTwo(right_value)) {
            return __ WordBitwiseAnd(
                left, __ WordConstant(right_value - 1, rep), rep);
          }
          // The `UintDiv` with a constant right-hand side will be turned into a
          // multiplication, avoiding the expensive integer division.
          return __ WordSub(
              left, __ WordMul(right, __ UintDiv(left, right, rep), rep), rep);
        case WordBinopOp::Kind::kSignedMulOverflownBits:
        case WordBinopOp::Kind::kUnsignedMulOverflownBits:
          break;
      }
    }

    if (kind == Kind::kAdd) {
      V<Word> x, y, zero;
      // (0 - x) + y => y - x
      if (matcher_.MatchWordSub(left, &zero, &x, rep) &&
          matcher_.MatchZero(zero)) {
        y = right;
        return __ WordSub(y, x, rep);
      }
      // x + (0 - y) => x - y
      if (matcher_.MatchWordSub(right, &zero, &y, rep) &&
          matcher_.MatchZero(zero)) {
        x = left;
        return __ WordSub(x, y, rep);
      }
    }

    // 0 / right  =>  0
    // 0 % right  =>  0
    if (matcher_.MatchZero(left) &&
        kind == any_of(Kind::kSignedDiv, Kind::kUnsignedDiv, Kind::kUnsignedMod,
                       Kind::kSignedMod)) {
      return __ WordConstant(0, rep);
    }

    if (left == right) {
      V<Word> x = left;
      switch (kind) {
        // x & x  =>  x
        // x | x  =>  x
        case WordBinopOp::Kind::kBitwiseAnd:
        case WordBinopOp::Kind::kBitwiseOr:
          return x;
        // x ^ x  =>  0
        // x - x  =>  0
        // x % x  =>  0
        case WordBinopOp::Kind::kBitwiseXor:
        case WordBinopOp::Kind::kSub:
        case WordBinopOp::Kind::kSignedMod:
        case WordBinopOp::Kind::kUnsignedMod:
          return __ WordConstant(0, rep);
        // x / x  =>  x != 0
        case WordBinopOp::Kind::kSignedDiv:
        case WordBinopOp::Kind::kUnsignedDiv: {
          V<Word> zero = __ WordConstant(0, rep);
          V<Word32> result = __ Word32Equal(__ Equal(left, zero, rep), 0);
          return __ ZeroExtendWord32ToRep(result, rep);
        }
        case WordBinopOp::Kind::kAdd:
        case WordBinopOp::Kind::kMul:
        case WordBinopOp::Kind::kSignedMulOverflownBits:
        case WordBinopOp::Kind::kUnsignedMulOverflownBits:
          break;
      }
    }

    if (std::optional<OpIndex> ror = TryReduceToRor(left, right, kind, rep)) {
      return *ror;
    }

    return Next::ReduceWordBinop(left, right, kind, rep);
  }

  bool TryMatchHeapObject(V<Any> idx, int depth = 0) {
    constexpr int kMaxDepth = 2;
    if (depth == kMaxDepth) return false;

    if (matcher_.MatchHeapConstant(idx)) return true;
    if (matcher_.Is<AllocateOp>(idx)) return true;
    if (matcher_.Is<Opmask::kTaggedBitcastHeapObject>(idx)) return true;

    // A Phi whose inputs are all HeapObject is itself a HeapObject.
    if (const PhiOp* phi = matcher_.TryCast<Opmask::kTaggedPhi>(idx)) {
      return base::all_of(phi->inputs(), [depth, this](V<Any> input) {
        return TryMatchHeapObject(input, depth + 1);
      });
    }

    // For anything else, assume that it's not a heap object.
    return false;
  }

  std::optional<V<Word>> TryReduceToRor(V<Word> left, V<Word> right,
                                        WordBinopOp::Kind kind,
                                        WordRepresentation rep) {
    // Recognize rotation, we are matcher_.Matching and transforming as follows
    // (assuming kWord32, kWord64 is handled correspondingly):
    //   x << y         |  x >>> (32 - y)    =>  x ror (32 - y)
    //   x << (32 - y)  |  x >>> y           =>  x ror y
    //   x << y         ^  x >>> (32 - y)    =>  x ror (32 - y)   if 1 <= y < 32
    //   x << (32 - y)  ^  x >>> y           =>  x ror y          if 1 <= y < 32
    // (As well as the commuted forms.)
    // Note the side condition for XOR: the optimization doesn't hold for
    // an effective rotation amount of 0.

    if (!(kind == any_of(WordBinopOp::Kind::kBitwiseOr,
                         WordBinopOp::Kind::kBitwiseXor))) {
      return {};
    }

    const ShiftOp* high = matcher_.TryCast<ShiftOp>(left);
    if (!high) return {};
    const ShiftOp* low = matcher_.TryCast<ShiftOp>(right);
    if (!low) return {};

    if (low->kind == ShiftOp::Kind::kShiftLeft) {
      std::swap(low, high);
    }
    if (high->kind != ShiftOp::Kind::kShiftLeft ||
        low->kind != ShiftOp::Kind::kShiftRightLogical) {
      return {};
    }
    V<Word> x = high->left();
    if (low->left() != x) return {};
    V<Word> amount;
    uint64_t k;
    if (V<Word> a, b; matcher_.MatchWordSub(high->right(), &a, &b, rep) &&
                      matcher_.MatchIntegralWordConstant(a, rep, &k) &&
                      b == low->right() && k == rep.bit_width()) {
      amount = b;
    } else if (V<Word> a, b; matcher_.MatchWordSub(low->right(), &a, &b, rep) &&
                             a == high->right() &&
                             matcher_.MatchIntegralWordConstant(b, rep, &k) &&
                             k == rep.bit_width()) {
      amount = low->right();
    } else if (uint64_t k1, k2;
               matcher_.MatchIntegralWordConstant(high->right(), rep, &k1) &&
               matcher_.MatchIntegralWordConstant(low->right(), rep, &k2) &&
               k1 + k2 == rep.bit_width() && k1 >= 0 && k2 >= 0) {
      if (k1 == 0 || k2 == 0) {
        if (kind == WordBinopOp::Kind::kBitwiseXor) {
          return __ WordConstant(0, rep);
        } else {
          DCHECK_EQ(kind, WordBinopOp::Kind::kBitwiseOr);
          return x;
        }
      }
      return __ RotateRight(x, low->right(), rep);
    } else {
      return {};
    }
    if (kind == WordBinopOp::Kind::kBitwiseOr) {
      return __ RotateRight(x, amount, rep);
    } else {
      DCHECK_EQ(kind, WordBinopOp::Kind::kBitwiseXor);
      // Can't guarantee that rotation amount is not 0.
      return {};
    }
  }

  V<Tuple<Word, Word32>> REDUCE(OverflowCheckedBinop)(
      V<Word> left, V<Word> right, OverflowCheckedBinopOp::Kind kind,
      WordRepresentation rep) {
    if (ShouldSkipOptimizationStep()) {
      return Next::ReduceOverflowCheckedBinop(left, right, kind, rep);
    }
    using Kind = OverflowCheckedBinopOp::Kind;
    if (OverflowCheckedBinopOp::IsCommutative(kind) &&
        matcher_.Is<ConstantOp>(left) && !matcher_.Is<ConstantOp>(right)) {
      return ReduceOverflowCheckedBinop(right, left, kind, rep);
    }
    if (rep == WordRepresentation::Word32()) {
      left = TryRemoveWord32ToWord64Conversion(left);
      right = TryRemoveWord32ToWord64Conversion(right);
    }
    // constant folding
    if (rep == WordRepresentation::Word32()) {
      if (int32_t k1, k2; matcher_.MatchIntegralWord32Constant(left, &k1) &&
                          matcher_.MatchIntegralWord32Constant(right, &k2)) {
        bool overflow;
        int32_t res;
        switch (kind) {
          case OverflowCheckedBinopOp::Kind::kSignedAdd:
            overflow = base::bits::SignedAddOverflow32(k1, k2, &res);
            break;
          case OverflowCheckedBinopOp::Kind::kSignedMul:
            overflow = base::bits::SignedMulOverflow32(k1, k2, &res);
            break;
          case OverflowCheckedBinopOp::Kind::kSignedSub:
            overflow = base::bits::SignedSubOverflow32(k1, k2, &res);
            break;
        }
        return __ Tuple(__ Word32Constant(res), __ Word32Constant(overflow));
      }
    } else {
      DCHECK_EQ(rep, WordRepresentation::Word64());
      if (int64_t k1, k2; matcher_.MatchIntegralWord64Constant(left, &k1) &&
                          matcher_.MatchIntegralWord64Constant(right, &k2)) {
        bool overflow;
        int64_t res;
        switch (kind) {
          case OverflowCheckedBinopOp::Kind::kSignedAdd:
            overflow = base::bits::SignedAddOverflow64(k1, k2, &res);
            break;
          case OverflowCheckedBinopOp::Kind::kSignedMul:
            overflow = base::bits::SignedMulOverflow64(k1, k2, &res);
            break;
          case OverflowCheckedBinopOp::Kind::kSignedSub:
            overflow = base::bits::SignedSubOverflow64(k1, k2, &res);
            break;
        }
        return __ Tuple(__ Word64Constant(res), __ Word32Constant(overflow));
      }
    }

    // left + 0  =>  (left, false)
    // left - 0  =>  (left, false)
    if (kind == any_of(Kind::kSignedAdd, Kind::kSignedSub) &&
        matcher_.MatchZero(right)) {
      return __ Tuple(left, __ Word32Constant(0));
    }

    if (kind == Kind::kSignedMul) {
      if (int64_t k; matcher_.MatchIntegralWordConstant(right, rep, &k)) {
        // left * 0  =>  (0, false)
        if (k == 0) {
          return __ Tuple(__ WordConstant(0, rep), __ Word32Constant(false));
        }
        // left * 1  =>  (left, false)
        if (k == 1) {
          return __ Tuple(left, __ Word32Constant(false));
        }
        // left * -1  =>  0 - left
        if (k == -1) {
          return __ IntSubCheckOverflow(__ WordConstant(0, rep), left, rep);
        }
        // left * 2  =>  left + left
        if (k == 2) {
          return __ IntAddCheckOverflow(left, left, rep);
        }
      }
    }

    // UntagSmi(x) + UntagSmi(x)  =>  (x, false)
    // (where UntagSmi(x) = x >> 1   with a ShiftOutZeros shift)
    if (kind == Kind::kSignedAdd && left == right) {
      uint16_t amount;
      if (V<Word32> x; matcher_.MatchConstantShiftRightArithmeticShiftOutZeros(
                           left, &x, WordRepresentation::Word32(), &amount) &&
                       amount == 1) {
        return __ Tuple(x, __ Word32Constant(0));
      }
    }

    return Next::ReduceOverflowCheckedBinop(left, right, kind, rep);
  }

  V<Word32> REDUCE(Comparison)(V<Any> left, V<Any> right,
                               ComparisonOp::Kind kind,
                               RegisterRepresentation rep) {
    if (ShouldSkipOptimizationStep()) {
      return Next::ReduceComparison(left, right, kind, rep);
    }
    if (kind == ComparisonOp::Kind::kEqual) {
      return ReduceCompareEqual(left, right, rep);
    }
    if (rep == WordRepresentation::Word32()) {
      left = TryRemoveWord32ToWord64Conversion(V<Word>::Cast(left));
      right = TryRemoveWord32ToWord64Conversion(V<Word>::Cast(right));
    }
    using Kind = ComparisonOp::Kind;
    if (left == right &&
        !(rep == any_of(RegisterRepresentation::Float32(),
                        RegisterRepresentation::Float64())) &&
        kind == any_of(Kind::kSignedLessThanOrEqual,
                       Kind::kUnsignedLessThanOrEqual)) {
      switch (kind) {
        case Kind::kEqual:
          UNREACHABLE();
        case Kind::kUnsignedLessThanOrEqual:
        case Kind::kSignedLessThanOrEqual:
          return __ Word32Constant(1);
        case Kind::kUnsignedLessThan:
        case Kind::kSignedLessThan:
          return __ Word32Constant(0);
      }
    }
    // constant folding
    if (matcher_.Is<ConstantOp>(right) && matcher_.Is<ConstantOp>(left)) {
      switch (rep.value()) {
        case RegisterRepresentation::Word32():
        case RegisterRepresentation::Word64(): {
          if (kind ==
              any_of(Kind::kSignedLessThan, Kind::kSignedLessThanOrEqual)) {
            if (int64_t k1, k2; matcher_.MatchIntegralWordConstant(
                                    left, WordRepresentation(rep), &k1) &&
                                matcher_.MatchIntegralWordConstant(
                                    right, WordRepresentation(rep), &k2)) {
              switch (kind) {
                case ComparisonOp::Kind::
Prompt: 
```
这是目录为v8/src/compiler/turboshaft/machine-optimization-reducer.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/machine-optimization-reducer.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
                         static_cast<int32_t>(k2)),
              rep);
        case Kind::kUnsignedMulOverflownBits:
          return __ WordConstant(
              is_64 ? base::bits::UnsignedMulHigh64(k1, k2)
                    : base::bits::UnsignedMulHigh32(static_cast<uint32_t>(k1),
                                                    static_cast<uint32_t>(k2)),
              rep);
        case Kind::kSignedDiv:
          return __ WordConstant(
              is_64 ? base::bits::SignedDiv64(k1, k2)
                    : base::bits::SignedDiv32(static_cast<int32_t>(k1),
                                              static_cast<int32_t>(k2)),
              rep);
        case Kind::kUnsignedDiv:
          return __ WordConstant(
              is_64 ? base::bits::UnsignedDiv64(k1, k2)
                    : base::bits::UnsignedDiv32(static_cast<uint32_t>(k1),
                                                static_cast<uint32_t>(k2)),
              rep);
        case Kind::kSignedMod:
          return __ WordConstant(
              is_64 ? base::bits::SignedMod64(k1, k2)
                    : base::bits::SignedMod32(static_cast<int32_t>(k1),
                                              static_cast<int32_t>(k2)),
              rep);
        case Kind::kUnsignedMod:
          return __ WordConstant(
              is_64 ? base::bits::UnsignedMod64(k1, k2)
                    : base::bits::UnsignedMod32(static_cast<uint32_t>(k1),
                                                static_cast<uint32_t>(k2)),
              rep);
      }
    }

    if (kind == WordBinopOp::Kind::kBitwiseAnd &&
        rep == WordRepresentation::Word32()) {
      if (auto right_bitfield = detail::BitfieldCheck::Detect(
              matcher_, __ output_graph(), right)) {
        if (auto left_bitfield = detail::BitfieldCheck::Detect(
                matcher_, __ output_graph(), left)) {
          if (auto combined_bitfield =
                  left_bitfield->TryCombine(*right_bitfield)) {
            OpIndex source = combined_bitfield->source;
            if (combined_bitfield->truncate_from_64_bit) {
              source = __ TruncateWord64ToWord32(source);
            }
            return __ Word32Equal(
                __ Word32BitwiseAnd(source, combined_bitfield->mask),
                combined_bitfield->masked_value);
          }
        }
      }
    }

    if (uint64_t right_value;
        matcher_.MatchIntegralWordConstant(right, rep, &right_value)) {
      // TODO(jkummerow): computing {right_value_signed} could probably be
      // handled by the 4th argument to {MatchIntegralWordConstant}.
      int64_t right_value_signed =
          is_64 ? static_cast<int64_t>(right_value)
                : int64_t{static_cast<int32_t>(right_value)};
      // (a <op> k1) <op> k2  =>  a <op> (k1 <op> k2)
      if (V<Word> a, k1; WordBinopOp::IsAssociative(kind) &&
                         matcher_.MatchWordBinop(left, &a, &k1, kind, rep) &&
                         matcher_.Is<ConstantOp>(k1)) {
        V<Word> k2 = right;
        // This optimization allows to do constant folding of `k1` and `k2`.
        // However, if (a <op> k1) has to be calculated anyways, then constant
        // folding does not save any calculations during runtime, and it may
        // increase register pressure because it extends the lifetime of `a`.
        // Therefore we do the optimization only when `left = (a <op k1)` has no
        // other uses.
        if (matcher_.Get(left).saturated_use_count.IsZero()) {
          return ReduceWordBinop(a, ReduceWordBinop(k1, k2, kind, rep), kind,
                                 rep);
        }
      }
      switch (kind) {
        case Kind::kSub:
          // left - k  =>  left + -k
          return ReduceWordBinop(left, __ WordConstant(-right_value, rep),
                                 Kind::kAdd, rep);
        case Kind::kAdd:
          // left + 0  =>  left
          if (right_value == 0) {
            return left;
          }
          break;
        case Kind::kBitwiseXor:
          // left ^ 0  =>  left
          if (right_value == 0) {
            return left;
          }
          // left ^ 1  =>  left == 0  if left is 0 or 1
          if (right_value == 1 && IsBit(left)) {
            return __ Word32Equal(V<Word32>::Cast(left), 0);
          }
          // (x ^ -1) ^ -1  =>  x
          {
            V<Word> x, y;
            int64_t k;
            if (right_value_signed == -1 &&
                matcher_.MatchBitwiseAnd(left, &x, &y, rep) &&
                matcher_.MatchIntegralWordConstant(y, rep, &k) && k == -1) {
              return x;
            }
          }
          break;
        case Kind::kBitwiseOr:
          // left | 0  =>  left
          if (right_value == 0) {
            return left;
          }
          // left | -1  =>  -1
          if (right_value_signed == -1) {
            return right;
          }
          // (x & K1) | K2 => x | K2 if K2 has ones for every zero bit in K1.
          // This case can be constructed by UpdateWord and UpdateWord32 in CSA.
          {
            V<Word> x, y;
            uint64_t k1;
            uint64_t k2 = right_value;
            if (matcher_.MatchBitwiseAnd(left, &x, &y, rep) &&
                matcher_.MatchIntegralWordConstant(y, rep, &k1) &&
                (k1 | k2) == rep.MaxUnsignedValue()) {
              return __ WordBitwiseOr(x, right, rep);
            }
          }
          break;
        case Kind::kMul:
          // left * 0  =>  0
          if (right_value == 0) {
            return __ WordConstant(0, rep);
          }
          // left * 1  =>  left
          if (right_value == 1) {
            return left;
          }
          // left * -1 => 0 - left
          if (right_value_signed == -1) {
            return __ WordSub(__ WordConstant(0, rep), left, rep);
          }
          // left * 2^k  =>  left << k
          if (base::bits::IsPowerOfTwo(right_value)) {
            return __ ShiftLeft(left, base::bits::WhichPowerOfTwo(right_value),
                                rep);
          }
          break;
        case Kind::kBitwiseAnd:
          // left & -1 => left
          if (right_value_signed == -1) {
            return left;
          }
          // x & 0  =>  0
          if (right_value == 0) {
            return right;
          }

          if (right_value == 1) {
            // (x + x) & 1  =>  0
            V<Word> left_ignore_extensions =
                IsWord32ConvertedToWord64(left)
                    ? UndoWord32ToWord64Conversion(left)
                    : left;
            if (V<Word> a, b;
                matcher_.MatchWordAdd(left_ignore_extensions, &a, &b,
                                      WordRepresentation::Word32()) &&
                a == b) {
              return __ WordConstant(0, rep);
            }

            // CMP & 1  =>  CMP
            if (IsBit(left_ignore_extensions)) {
              return left;
            }

            static_assert(kSmiTagMask == 1);
            // HeapObject & 1 => 1  ("& 1" is a Smi-check)
            if (TryMatchHeapObject(left)) {
              return __ WordConstant(1, rep);
            }
          }

          // asm.js often benefits from these transformations, to optimize out
          // unnecessary memory access alignment masks. Conventions used in
          // the comments below:
          // x, y: arbitrary values
          // K, L, M: arbitrary constants
          // (-1 << K) == mask: the right-hand side of the bitwise AND.
          if (IsNegativePowerOfTwo(right_value_signed)) {
            uint64_t mask = right_value;
            int K = base::bits::CountTrailingZeros64(mask);
            V<Word> x, y;
            {
              int L;
              //   (x << L) & (-1 << K)
              // => x << L               iff L >= K
              if (matcher_.MatchConstantLeftShift(left, &x, rep, &L) &&
                  L >= K) {
                return left;
              }
            }

            if (matcher_.MatchWordAdd(left, &x, &y, rep)) {
              uint64_t L;  // L == (M << K) iff (L & mask) == L.

              //    (x              + (M << K)) & (-1 << K)
              // => (x & (-1 << K)) + (M << K)
              if (matcher_.MatchIntegralWordConstant(y, rep, &L) &&
                  (L & mask) == L) {
                return __ WordAdd(__ WordBitwiseAnd(x, right, rep),
                                  __ WordConstant(L, rep), rep);
              }

              //   (x1 * (M << K) + y) & (-1 << K)
              // => x1 * (M << K) + (y & (-1 << K))
              V<Word> x1, x2, y1, y2;
              if (matcher_.MatchWordMul(x, &x1, &x2, rep) &&
                  matcher_.MatchIntegralWordConstant(x2, rep, &L) &&
                  (L & mask) == L) {
                return __ WordAdd(x, __ WordBitwiseAnd(y, right, rep), rep);
              }
              // Same as above with swapped order:
              //    (x              + y1 * (M << K)) & (-1 << K)
              // => (x & (-1 << K)) + y1 * (M << K)
              if (matcher_.MatchWordMul(y, &y1, &y2, rep) &&
                  matcher_.MatchIntegralWordConstant(y2, rep, &L) &&
                  (L & mask) == L) {
                return __ WordAdd(__ WordBitwiseAnd(x, right, rep), y, rep);
              }

              //   ((x1 << K) + y) & (-1 << K)
              // => (x1 << K) + (y & (-1 << K))
              int K2;
              if (matcher_.MatchConstantLeftShift(x, &x1, rep, &K2) &&
                  K2 == K) {
                return __ WordAdd(x, __ WordBitwiseAnd(y, right, rep), rep);
              }
              // Same as above with swapped order:
              //    (x +              (y1 << K)) & (-1 << K)
              // => (x & (-1 << K)) + (y1 << K)
              if (matcher_.MatchConstantLeftShift(y, &y1, rep, &K2) &&
                  K2 == K) {
                return __ WordAdd(__ WordBitwiseAnd(x, right, rep), y, rep);
              }
            } else if (matcher_.MatchWordMul(left, &x, &y, rep)) {
              // (x * (M << K)) & (-1 << K) => x * (M << K)
              uint64_t L;  // L == (M << K) iff (L & mask) == L.
              if (matcher_.MatchIntegralWordConstant(y, rep, &L) &&
                  (L & mask) == L) {
                return left;
              }
            }
          }
          break;
        case WordBinopOp::Kind::kSignedDiv:
          return ReduceSignedDiv(left, right_value_signed, rep);
        case WordBinopOp::Kind::kUnsignedDiv:
          return ReduceUnsignedDiv(left, right_value, rep);
        case WordBinopOp::Kind::kSignedMod:
          // left % 0  =>  0
          // left % 1  =>  0
          // left % -1  =>  0
          if (right_value_signed == any_of(0, 1, -1)) {
            return __ WordConstant(0, rep);
          }
          if (right_value_signed != rep.MinSignedValue()) {
            right_value_signed = Abs(right_value_signed);
          }
          // left % 2^n  =>  ((left + m) & (2^n - 1)) - m
          // where m = (left >> bits-1) >>> bits-n
          // This is a branch-free version of the following:
          // left >= 0 ? left & (2^n - 1)
          //           : ((left + (2^n - 1)) & (2^n - 1)) - (2^n - 1)
          // Adding and subtracting (2^n - 1) before and after the bitwise-and
          // keeps the result congruent modulo 2^n, but shifts the resulting
          // value range to become -(2^n - 1) ... 0.
          if (base::bits::IsPowerOfTwo(right_value_signed)) {
            uint32_t bits = rep.bit_width();
            uint32_t n = base::bits::WhichPowerOfTwo(right_value_signed);
            V<Word> m = __ ShiftRightLogical(
                __ ShiftRightArithmetic(left, bits - 1, rep), bits - n, rep);
            return __ WordSub(
                __ WordBitwiseAnd(__ WordAdd(left, m, rep),
                                  __ WordConstant(right_value_signed - 1, rep),
                                  rep),
                m, rep);
          }
          // The `IntDiv` with a constant right-hand side will be turned into a
          // multiplication, avoiding the expensive integer division.
          return __ WordSub(
              left, __ WordMul(__ IntDiv(left, right, rep), right, rep), rep);
        case WordBinopOp::Kind::kUnsignedMod:
          // left % 0  =>  0
          // left % 1  =>  0
          if (right_value == 0 || right_value == 1) {
            return __ WordConstant(0, rep);
          }
          // x % 2^n => x & (2^n - 1)
          if (base::bits::IsPowerOfTwo(right_value)) {
            return __ WordBitwiseAnd(
                left, __ WordConstant(right_value - 1, rep), rep);
          }
          // The `UintDiv` with a constant right-hand side will be turned into a
          // multiplication, avoiding the expensive integer division.
          return __ WordSub(
              left, __ WordMul(right, __ UintDiv(left, right, rep), rep), rep);
        case WordBinopOp::Kind::kSignedMulOverflownBits:
        case WordBinopOp::Kind::kUnsignedMulOverflownBits:
          break;
      }
    }

    if (kind == Kind::kAdd) {
      V<Word> x, y, zero;
      // (0 - x) + y => y - x
      if (matcher_.MatchWordSub(left, &zero, &x, rep) &&
          matcher_.MatchZero(zero)) {
        y = right;
        return __ WordSub(y, x, rep);
      }
      // x + (0 - y) => x - y
      if (matcher_.MatchWordSub(right, &zero, &y, rep) &&
          matcher_.MatchZero(zero)) {
        x = left;
        return __ WordSub(x, y, rep);
      }
    }

    // 0 / right  =>  0
    // 0 % right  =>  0
    if (matcher_.MatchZero(left) &&
        kind == any_of(Kind::kSignedDiv, Kind::kUnsignedDiv, Kind::kUnsignedMod,
                       Kind::kSignedMod)) {
      return __ WordConstant(0, rep);
    }

    if (left == right) {
      V<Word> x = left;
      switch (kind) {
        // x & x  =>  x
        // x | x  =>  x
        case WordBinopOp::Kind::kBitwiseAnd:
        case WordBinopOp::Kind::kBitwiseOr:
          return x;
        // x ^ x  =>  0
        // x - x  =>  0
        // x % x  =>  0
        case WordBinopOp::Kind::kBitwiseXor:
        case WordBinopOp::Kind::kSub:
        case WordBinopOp::Kind::kSignedMod:
        case WordBinopOp::Kind::kUnsignedMod:
          return __ WordConstant(0, rep);
        // x / x  =>  x != 0
        case WordBinopOp::Kind::kSignedDiv:
        case WordBinopOp::Kind::kUnsignedDiv: {
          V<Word> zero = __ WordConstant(0, rep);
          V<Word32> result = __ Word32Equal(__ Equal(left, zero, rep), 0);
          return __ ZeroExtendWord32ToRep(result, rep);
        }
        case WordBinopOp::Kind::kAdd:
        case WordBinopOp::Kind::kMul:
        case WordBinopOp::Kind::kSignedMulOverflownBits:
        case WordBinopOp::Kind::kUnsignedMulOverflownBits:
          break;
      }
    }

    if (std::optional<OpIndex> ror = TryReduceToRor(left, right, kind, rep)) {
      return *ror;
    }

    return Next::ReduceWordBinop(left, right, kind, rep);
  }

  bool TryMatchHeapObject(V<Any> idx, int depth = 0) {
    constexpr int kMaxDepth = 2;
    if (depth == kMaxDepth) return false;

    if (matcher_.MatchHeapConstant(idx)) return true;
    if (matcher_.Is<AllocateOp>(idx)) return true;
    if (matcher_.Is<Opmask::kTaggedBitcastHeapObject>(idx)) return true;

    // A Phi whose inputs are all HeapObject is itself a HeapObject.
    if (const PhiOp* phi = matcher_.TryCast<Opmask::kTaggedPhi>(idx)) {
      return base::all_of(phi->inputs(), [depth, this](V<Any> input) {
        return TryMatchHeapObject(input, depth + 1);
      });
    }

    // For anything else, assume that it's not a heap object.
    return false;
  }

  std::optional<V<Word>> TryReduceToRor(V<Word> left, V<Word> right,
                                        WordBinopOp::Kind kind,
                                        WordRepresentation rep) {
    // Recognize rotation, we are matcher_.Matching and transforming as follows
    // (assuming kWord32, kWord64 is handled correspondingly):
    //   x << y         |  x >>> (32 - y)    =>  x ror (32 - y)
    //   x << (32 - y)  |  x >>> y           =>  x ror y
    //   x << y         ^  x >>> (32 - y)    =>  x ror (32 - y)   if 1 <= y < 32
    //   x << (32 - y)  ^  x >>> y           =>  x ror y          if 1 <= y < 32
    // (As well as the commuted forms.)
    // Note the side condition for XOR: the optimization doesn't hold for
    // an effective rotation amount of 0.

    if (!(kind == any_of(WordBinopOp::Kind::kBitwiseOr,
                         WordBinopOp::Kind::kBitwiseXor))) {
      return {};
    }

    const ShiftOp* high = matcher_.TryCast<ShiftOp>(left);
    if (!high) return {};
    const ShiftOp* low = matcher_.TryCast<ShiftOp>(right);
    if (!low) return {};

    if (low->kind == ShiftOp::Kind::kShiftLeft) {
      std::swap(low, high);
    }
    if (high->kind != ShiftOp::Kind::kShiftLeft ||
        low->kind != ShiftOp::Kind::kShiftRightLogical) {
      return {};
    }
    V<Word> x = high->left();
    if (low->left() != x) return {};
    V<Word> amount;
    uint64_t k;
    if (V<Word> a, b; matcher_.MatchWordSub(high->right(), &a, &b, rep) &&
                      matcher_.MatchIntegralWordConstant(a, rep, &k) &&
                      b == low->right() && k == rep.bit_width()) {
      amount = b;
    } else if (V<Word> a, b; matcher_.MatchWordSub(low->right(), &a, &b, rep) &&
                             a == high->right() &&
                             matcher_.MatchIntegralWordConstant(b, rep, &k) &&
                             k == rep.bit_width()) {
      amount = low->right();
    } else if (uint64_t k1, k2;
               matcher_.MatchIntegralWordConstant(high->right(), rep, &k1) &&
               matcher_.MatchIntegralWordConstant(low->right(), rep, &k2) &&
               k1 + k2 == rep.bit_width() && k1 >= 0 && k2 >= 0) {
      if (k1 == 0 || k2 == 0) {
        if (kind == WordBinopOp::Kind::kBitwiseXor) {
          return __ WordConstant(0, rep);
        } else {
          DCHECK_EQ(kind, WordBinopOp::Kind::kBitwiseOr);
          return x;
        }
      }
      return __ RotateRight(x, low->right(), rep);
    } else {
      return {};
    }
    if (kind == WordBinopOp::Kind::kBitwiseOr) {
      return __ RotateRight(x, amount, rep);
    } else {
      DCHECK_EQ(kind, WordBinopOp::Kind::kBitwiseXor);
      // Can't guarantee that rotation amount is not 0.
      return {};
    }
  }

  V<Tuple<Word, Word32>> REDUCE(OverflowCheckedBinop)(
      V<Word> left, V<Word> right, OverflowCheckedBinopOp::Kind kind,
      WordRepresentation rep) {
    if (ShouldSkipOptimizationStep()) {
      return Next::ReduceOverflowCheckedBinop(left, right, kind, rep);
    }
    using Kind = OverflowCheckedBinopOp::Kind;
    if (OverflowCheckedBinopOp::IsCommutative(kind) &&
        matcher_.Is<ConstantOp>(left) && !matcher_.Is<ConstantOp>(right)) {
      return ReduceOverflowCheckedBinop(right, left, kind, rep);
    }
    if (rep == WordRepresentation::Word32()) {
      left = TryRemoveWord32ToWord64Conversion(left);
      right = TryRemoveWord32ToWord64Conversion(right);
    }
    // constant folding
    if (rep == WordRepresentation::Word32()) {
      if (int32_t k1, k2; matcher_.MatchIntegralWord32Constant(left, &k1) &&
                          matcher_.MatchIntegralWord32Constant(right, &k2)) {
        bool overflow;
        int32_t res;
        switch (kind) {
          case OverflowCheckedBinopOp::Kind::kSignedAdd:
            overflow = base::bits::SignedAddOverflow32(k1, k2, &res);
            break;
          case OverflowCheckedBinopOp::Kind::kSignedMul:
            overflow = base::bits::SignedMulOverflow32(k1, k2, &res);
            break;
          case OverflowCheckedBinopOp::Kind::kSignedSub:
            overflow = base::bits::SignedSubOverflow32(k1, k2, &res);
            break;
        }
        return __ Tuple(__ Word32Constant(res), __ Word32Constant(overflow));
      }
    } else {
      DCHECK_EQ(rep, WordRepresentation::Word64());
      if (int64_t k1, k2; matcher_.MatchIntegralWord64Constant(left, &k1) &&
                          matcher_.MatchIntegralWord64Constant(right, &k2)) {
        bool overflow;
        int64_t res;
        switch (kind) {
          case OverflowCheckedBinopOp::Kind::kSignedAdd:
            overflow = base::bits::SignedAddOverflow64(k1, k2, &res);
            break;
          case OverflowCheckedBinopOp::Kind::kSignedMul:
            overflow = base::bits::SignedMulOverflow64(k1, k2, &res);
            break;
          case OverflowCheckedBinopOp::Kind::kSignedSub:
            overflow = base::bits::SignedSubOverflow64(k1, k2, &res);
            break;
        }
        return __ Tuple(__ Word64Constant(res), __ Word32Constant(overflow));
      }
    }

    // left + 0  =>  (left, false)
    // left - 0  =>  (left, false)
    if (kind == any_of(Kind::kSignedAdd, Kind::kSignedSub) &&
        matcher_.MatchZero(right)) {
      return __ Tuple(left, __ Word32Constant(0));
    }

    if (kind == Kind::kSignedMul) {
      if (int64_t k; matcher_.MatchIntegralWordConstant(right, rep, &k)) {
        // left * 0  =>  (0, false)
        if (k == 0) {
          return __ Tuple(__ WordConstant(0, rep), __ Word32Constant(false));
        }
        // left * 1  =>  (left, false)
        if (k == 1) {
          return __ Tuple(left, __ Word32Constant(false));
        }
        // left * -1  =>  0 - left
        if (k == -1) {
          return __ IntSubCheckOverflow(__ WordConstant(0, rep), left, rep);
        }
        // left * 2  =>  left + left
        if (k == 2) {
          return __ IntAddCheckOverflow(left, left, rep);
        }
      }
    }

    // UntagSmi(x) + UntagSmi(x)  =>  (x, false)
    // (where UntagSmi(x) = x >> 1   with a ShiftOutZeros shift)
    if (kind == Kind::kSignedAdd && left == right) {
      uint16_t amount;
      if (V<Word32> x; matcher_.MatchConstantShiftRightArithmeticShiftOutZeros(
                           left, &x, WordRepresentation::Word32(), &amount) &&
                       amount == 1) {
        return __ Tuple(x, __ Word32Constant(0));
      }
    }

    return Next::ReduceOverflowCheckedBinop(left, right, kind, rep);
  }

  V<Word32> REDUCE(Comparison)(V<Any> left, V<Any> right,
                               ComparisonOp::Kind kind,
                               RegisterRepresentation rep) {
    if (ShouldSkipOptimizationStep()) {
      return Next::ReduceComparison(left, right, kind, rep);
    }
    if (kind == ComparisonOp::Kind::kEqual) {
      return ReduceCompareEqual(left, right, rep);
    }
    if (rep == WordRepresentation::Word32()) {
      left = TryRemoveWord32ToWord64Conversion(V<Word>::Cast(left));
      right = TryRemoveWord32ToWord64Conversion(V<Word>::Cast(right));
    }
    using Kind = ComparisonOp::Kind;
    if (left == right &&
        !(rep == any_of(RegisterRepresentation::Float32(),
                        RegisterRepresentation::Float64())) &&
        kind == any_of(Kind::kSignedLessThanOrEqual,
                       Kind::kUnsignedLessThanOrEqual)) {
      switch (kind) {
        case Kind::kEqual:
          UNREACHABLE();
        case Kind::kUnsignedLessThanOrEqual:
        case Kind::kSignedLessThanOrEqual:
          return __ Word32Constant(1);
        case Kind::kUnsignedLessThan:
        case Kind::kSignedLessThan:
          return __ Word32Constant(0);
      }
    }
    // constant folding
    if (matcher_.Is<ConstantOp>(right) && matcher_.Is<ConstantOp>(left)) {
      switch (rep.value()) {
        case RegisterRepresentation::Word32():
        case RegisterRepresentation::Word64(): {
          if (kind ==
              any_of(Kind::kSignedLessThan, Kind::kSignedLessThanOrEqual)) {
            if (int64_t k1, k2; matcher_.MatchIntegralWordConstant(
                                    left, WordRepresentation(rep), &k1) &&
                                matcher_.MatchIntegralWordConstant(
                                    right, WordRepresentation(rep), &k2)) {
              switch (kind) {
                case ComparisonOp::Kind::kSignedLessThan:
                  return __ Word32Constant(k1 < k2);
                case ComparisonOp::Kind::kSignedLessThanOrEqual:
                  return __ Word32Constant(k1 <= k2);
                case ComparisonOp::Kind::kEqual:
                case ComparisonOp::Kind::kUnsignedLessThan:
                case ComparisonOp::Kind::kUnsignedLessThanOrEqual:
                  UNREACHABLE();
              }
            }
          } else {
            if (uint64_t k1, k2; matcher_.MatchIntegralWordConstant(
                                     left, WordRepresentation(rep), &k1) &&
                                 matcher_.MatchIntegralWordConstant(
                                     right, WordRepresentation(rep), &k2)) {
              switch (kind) {
                case ComparisonOp::Kind::kUnsignedLessThan:
                  return __ Word32Constant(k1 < k2);
                case ComparisonOp::Kind::kUnsignedLessThanOrEqual:
                  return __ Word32Constant(k1 <= k2);
                case ComparisonOp::Kind::kEqual:
                case ComparisonOp::Kind::kSignedLessThan:
                case ComparisonOp::Kind::kSignedLessThanOrEqual:
                  UNREACHABLE();
              }
            }
          }
          break;
        }
        case RegisterRepresentation::Float32(): {
          if (float k1, k2; matcher_.MatchFloat32Constant(left, &k1) &&
                            matcher_.MatchFloat32Constant(right, &k2)) {
            switch (kind) {
              case ComparisonOp::Kind::kSignedLessThan:
                return __ Word32Constant(k1 < k2);
              case ComparisonOp::Kind::kSignedLessThanOrEqual:
                return __ Word32Constant(k1 <= k2);
              case ComparisonOp::Kind::kEqual:
              case ComparisonOp::Kind::kUnsignedLessThan:
              case ComparisonOp::Kind::kUnsignedLessThanOrEqual:
                UNREACHABLE();
            }
          }
          break;
        }
        case RegisterRepresentation::Float64(): {
          if (double k1, k2; matcher_.MatchFloat64Constant(left, &k1) &&
                             matcher_.MatchFloat64Constant(right, &k2)) {
            switch (kind) {
              case ComparisonOp::Kind::kSignedLessThan:
                return __ Word32Constant(k1 < k2);
              case ComparisonOp::Kind::kSignedLessThanOrEqual:
                return __ Word32Constant(k1 <= k2);
              case ComparisonOp::Kind::kEqual:
              case ComparisonOp::Kind::kUnsignedLessThan:
              case ComparisonOp::Kind::kUnsignedLessThanOrEqual:
                UNREACHABLE();
            }
          }
          break;
        }
        default:
          UNREACHABLE();
      }
    }
    if (rep == RegisterRepresentation::Float64() &&
        IsFloat32ConvertedToFloat64(left) &&
        IsFloat32ConvertedToFloat64(right)) {
      return __ Comparison(UndoFloat32ToFloat64Conversion(left),
                           UndoFloat32ToFloat64Conversion(right), kind,
                           RegisterRepresentation::Float32());
    }
    if (rep.IsWord()) {
      WordRepresentation rep_w{rep};
      if (kind == Kind::kUnsignedLessThanOrEqual) {
        // 0 <= x  =>  true
        if (uint64_t k;
            matcher_.MatchIntegralWordConstant(left, rep_w, &k) && k == 0) {
          return __ Word32Constant(1);
        }
        // x <= MaxUint  =>  true
        if (uint64_t k; matcher_.MatchIntegralWordConstant(right, rep_w, &k) &&
                        k == rep.MaxUnsignedValue()) {
          return __ Word32Constant(1);
        }
        // x <= 0  =>  x == 0
        if (uint64_t k;
            matcher_.MatchIntegralWordConstant(right, rep_w, &k) && k == 0) {
          return __ Equal(left, __ WordConstant(0, rep_w), rep_w);
        }
      }
      if (kind == Kind::kUnsignedLessThan) {
        // x < 0  =>  false
        if (uint64_t k;
            matcher_.MatchIntegralWordConstant(right, rep_w, &k) && k == 0) {
          return __ Word32Constant(0);
        }
        // MaxUint < x  =>  true
        if (uint64_t k; matcher_.MatchIntegralWordConstant(left, rep_w, &k) &&
                        k == rep.MaxUnsignedValue()) {
          return __ Word32Constant(0);
        }
      }
      {
        // (x >> k) </<=  (y >> k)  =>  x </<=  y   if shifts reversible
        V<Word> x, y;
        uint16_t k1, k2;
        if (matcher_.MatchConstantShiftRightArithmeticShiftOutZeros(
                left, &x, rep_w, &k1) &&
            matcher_.MatchConstantShiftRightArithmeticShiftOutZeros(
                right, &y, rep_w, &k2) &&
            k1 == k2) {
          return __ Comparison(x, y, kind, rep_w);
        }
      }
      {
        // (x >> k1) </<= k2  =>  x </<= (k2 << k1)  if shifts reversible
        // Only perform the transformation if the shift is not used yet, to
        // avoid keeping both the shift and x alive.
        V<Word> x;
        uint16_t k1;
        int64_t k2;
        if (matcher_.MatchConstantShiftRightArithmeticShiftOutZeros(
                left, &x, rep_w, &k1) &&
            matcher_.MatchIntegralWordConstant(right, rep_w, &k2) &&
            CountLeadingSignBits(k2, rep_w) > k1) {
          if (matcher_.Get(left).saturated_use_count.IsZero()) {
            return __ Comparison(
                x, __ WordConstant(base::bits::Unsigned(k2) << k1, rep_w), kind,
                rep_w);
          } else if constexpr (reducer_list_contains<
                                   ReducerList, ValueNumberingReducer>::value) {
            // If the shift has uses, we only apply the transformation if the
            // result would be GVNed away.
            OpIndex rhs =
                __ WordConstant(base::bits::Unsigned(k2) << k1, rep_w);
            static_assert(ComparisonOp::input_count == 2);
            static_assert(sizeof(ComparisonOp) == 8);
            base::SmallVector<OperationStorageSlot, 32> storage;
            ComparisonOp* cmp =
                CreateOperation<ComparisonOp>(storage, x, rhs, kind, rep_w);
            if (__ WillGVNOp(*cmp)) {
              return __ Comparison(x, rhs, kind, rep_w);
            }
          }
        }
        // k2 </<= (x >> k1)  =>  (k2 << k1) </<= x  if shifts reversible
        // Only perform the transformation if the shift is not used yet, to
        // avoid keeping both the shift and x alive.
        if (matcher_.MatchConstantShiftRightArithmeticShiftOutZeros(
                right, &x, rep_w, &k1) &&
            matcher_.MatchIntegralWordConstant(left, rep_w, &k2) &&
            CountLeadingSignBits(k2, rep_w) > k1) {
          if (matcher_.Get(right).saturated_use_count.IsZero()) {
            return __ Comparison(
                __ WordConstant(base::bits::Unsigned(k2) << k1, rep_w), x, kind,
                rep_w);
          } else if constexpr (reducer_list_contains<
                                   ReducerList, ValueNumberingReducer>::value) {
            // If the shift has uses, we only apply the transformation if the
            // result would be GVNed away.
            OpIndex lhs =
                __ WordConstant(base::bits::Unsigned(k2) << k1, rep_w);
            static_assert(ComparisonOp::input_count == 2);
            static_assert(sizeof(ComparisonOp) == 8);
            base::SmallVector<OperationStorageSlot, 32> storage;
            ComparisonOp* cmp =
                CreateOperation<ComparisonOp>(storage, lhs, x, kind, rep_w);
            if (__ WillGVNOp(*cmp)) {
              return __ Comparison(lhs, x, kind, rep_w);
            }
          }
        }
      }
      // Map 64bit to 32bit comparisons.
      if (rep_w == WordRepresentation::Word64()) {
        std::optional<bool> left_sign_extended;
        std::optional<bool> right_sign_extended;
        if (IsWord32ConvertedToWord64(left, &left_sign_extended) &&
            IsWord32ConvertedToWord64(right, &right_sign_extended)) {
          if (left_sign_extended != true && right_sign_extended != true) {
            // Both sides were zero-extended, so the resulting comparison always
            // behaves unsigned even if it was a signed 64bit comparison.
            auto SetSigned = [](Kind kind, bool is_signed) {
              switch (kind) {
                case Kind::kSignedLessThan:
                case Kind::kUnsignedLessThan:
                  return is_signed ? Kind::kSignedLessThan
                                   : Kind::kUnsignedLessThan;
                case Kind::kSignedLessThanOrEqual:
                case Kind::kUnsignedLessThanOrEqual:
                  return is_signed ? Kind::kSignedLessThanOrEqual
                                   : Kind
"""


```