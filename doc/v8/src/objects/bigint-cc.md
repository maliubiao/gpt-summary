Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/objects/bigint.cc`. I need to analyze the code and identify its main purpose and features related to handling BigInt objects in V8.

Here's a breakdown of the thought process:

1. **Identify the Core Class:** The code prominently features the `BigInt` and `MutableBigInt` classes. This suggests the file is primarily concerned with representing and manipulating arbitrarily large integers.

2. **Distinguish `MutableBigInt`:** The comments explain that `MutableBigInt` is an internal class for step-by-step construction to prevent accidental modification after creation. The `MakeImmutable` function is key for converting `MutableBigInt` to the read-only `BigInt`.

3. **Look for Key Operations:**  Scan the methods within the `BigInt` and `MutableBigInt` classes. Keywords like "New," "Add," "Subtract," "Multiply," "Divide," "Compare," "Shift," "Exponentiate," and "ToString" indicate the supported operations on BigInts.

4. **Trace Initialization and Canonicalization:**  Methods like `NewFromInt`, `NewFromDouble`, `InitializeDigits`, and `Canonicalize` are crucial for understanding how BigInt objects are created and how their internal representation is managed (e.g., trimming leading zeros).

5. **Consider Interactions with JavaScript:** The prompt asks about the relationship with JavaScript. Think about how JavaScript's `BigInt` type would map to these C++ classes. The methods provided likely implement the underlying logic for JavaScript BigInt operations.

6. **Infer Error Handling:** The presence of `ThrowBigIntTooBig` and checks for division by zero indicate mechanisms for handling potential errors in BigInt computations.

7. **Analyze Comparison Logic:** Several comparison methods like `CompareToBigInt`, `EqualToBigInt`, `CompareToString`, `EqualToNumber`, and `CompareToDouble` suggest the code handles comparisons between BigInts and other JavaScript types.

8. **Note Helper Functions:**  Functions like `AbsoluteAddOne`, `AbsoluteSubOne`, and `ToShiftAmount` seem to be internal helpers for simplifying common operations.

9. **Look for Bitwise Operations:**  `BitwiseNot`, `LeftShiftByAbsolute`, and `RightShiftByAbsolute` point to support for bitwise manipulations.

10. **Address the `.tq` Check:** The prompt mentions `.tq` files and Torque. Since this file is `.cc`, it's standard C++, but the prompt highlights the potential existence of Torque implementations elsewhere for similar functionality.

11. **Structure the Summary:** Organize the findings into logical categories like creation, arithmetic operations, comparison, bitwise operations, and conversion. Emphasize the role of `MutableBigInt` and `MakeImmutable`.

12. **Acknowledge Limitations:** Since it's only part of the file, note that the summary is based on the provided snippet and might not be exhaustive.
```cpp
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Parts of the implementation below:

// Copyright (c) 2014 the Dart project authors. Please see the AUTHORS file [1]
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file [2].
//
// [1] https://github.com/dart-lang/sdk/blob/master/AUTHORS
// [2] https://github.com/dart-lang/sdk/blob/master/LICENSE

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file [3].
//
// [3] https://golang.org/LICENSE

#include "src/objects/bigint.h"

#include <atomic>

#include "src/base/numbers/double.h"
#include "src/bigint/bigint.h"
#include "src/execution/isolate-inl.h"
#include "src/execution/isolate-utils-inl.h"
#include "src/heap/factory.h"
#include "src/heap/heap-write-barrier-inl.h"
#include "src/heap/heap.h"
#include "src/numbers/conversions.h"
#include "src/objects/casting.h"
#include "src/objects/heap-number-inl.h"
#include "src/objects/instance-type-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/smi.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8 {
namespace internal {

// The MutableBigInt class is an implementation detail designed to prevent
// accidental mutation of a BigInt after its construction. Step-by-step
// construction of a BigInt must happen in terms of MutableBigInt, the
// final result is then passed through MutableBigInt::MakeImmutable and not
// modified further afterwards.
// Many of the functions in this class use arguments of type {BigIntBase},
// indicating that they will be used in a read-only capacity, and both
// {BigInt} and {MutableBigInt} objects can be passed in.
V8_OBJECT class MutableBigInt : public FreshlyAllocatedBigInt {
 public:
  // Bottleneck for converting MutableBigInts to BigInts.
  static MaybeHandle<BigInt> MakeImmutable(MaybeHandle<MutableBigInt> maybe);
  template <typename Isolate = v8::internal::Isolate>
  static Handle<BigInt> MakeImmutable(Handle<MutableBigInt> result);

  static void Canonicalize(Tagged<MutableBigInt> result);

  // Allocation helpers.
  template <typename IsolateT>
  static MaybeHandle<MutableBigInt> New(
      IsolateT* isolate, uint32_t length,
      AllocationType allocation = AllocationType::kYoung);
  static Handle<BigInt> NewFromInt(Isolate* isolate, int value);
  static Handle<BigInt> NewFromDouble(Isolate* isolate, double value);
  void InitializeDigits(uint32_t length, uint8_t value = 0);
  static Handle<MutableBigInt> Copy(Isolate* isolate,
                                    DirectHandle<BigIntBase> source);
  template <typename IsolateT>
  static Handle<BigInt> Zero(
      IsolateT* isolate, AllocationType allocation = AllocationType::kYoung) {
    // TODO(jkummerow): Consider caching a canonical zero-BigInt.
    return MakeImmutable<IsolateT>(
        New(isolate, 0, allocation).ToHandleChecked());
  }

  // Internal helpers.
  static MaybeHandle<MutableBigInt> AbsoluteAddOne(
      Isolate* isolate, DirectHandle<BigIntBase> x, bool sign,
      Tagged<MutableBigInt> result_storage = {});
  static Handle<MutableBigInt> AbsoluteSubOne(Isolate* isolate,
                                              DirectHandle<BigIntBase> x);

  // Specialized helpers for shift operations.
  static MaybeHandle<BigInt> LeftShiftByAbsolute(Isolate* isolate,
                                                 Handle<BigIntBase> x,
                                                 Handle<BigIntBase> y);
  static Handle<BigInt> RightShiftByAbsolute(Isolate* isolate,
                                             Handle<BigIntBase> x,
                                             Handle<BigIntBase> y);
  static Handle<BigInt> RightShiftByMaximum(Isolate* isolate, bool sign);
  static Maybe<digit_t> ToShiftAmount(Handle<BigIntBase> x);

  static double ToDouble(DirectHandle<BigIntBase> x);
  enum Rounding { kRoundDown, kTie, kRoundUp };
  static Rounding DecideRounding(DirectHandle<BigIntBase> x,
                                 int mantissa_bits_unset, int digit_index,
                                 uint64_t current_digit);

  // Returns the least significant 64 bits, simulating two's complement
  // representation.
  static uint64_t GetRawBits(BigIntBase* x, bool* lossless);

  static inline bool digit_ismax(digit_t x) {
    return static_cast<digit_t>(~x) == 0;
  }

  bigint::RWDigits rw_digits();

  inline void set_sign(bool new_sign) {
    bitfield_.store(
        SignBits::update(bitfield_.load(std::memory_order_relaxed), new_sign),
        std::memory_order_relaxed);
  }
  inline void set_length(uint32_t new_length, ReleaseStoreTag) {
    bitfield_.store(LengthBits::update(
                        bitfield_.load(std::memory_order_relaxed), new_length),
                    std::memory_order_relaxed);
  }
  inline void initialize_bitfield(bool sign, uint32_t length) {
    bitfield_.store(LengthBits::encode(length) | SignBits::encode(sign),
                    std::memory_order_relaxed);
  }
  inline void set_digit(uint32_t n, digit_t value) {
    SLOW_DCHECK(n < length());
    raw_digits()[n].set_value(value);
  }

  void set_64_bits(uint64_t bits);

  static bool IsMutableBigInt(Tagged<MutableBigInt> o) { return IsBigInt(o); }

  static_assert(std::is_same<bigint::digit_t, BigIntBase::digit_t>::value,
                "We must be able to call BigInt library functions");

  NEVER_READ_ONLY_SPACE
} V8_OBJECT_END;

NEVER_READ_ONLY_SPACE_IMPL(MutableBigInt)

template <>
struct CastTraits<MutableBigInt> : public CastTraits<BigInt> {};

bigint::Digits BigIntBase::digits() const {
  return bigint::Digits(reinterpret_cast<const digit_t*>(raw_digits()),
                        length());
}

bigint::RWDigits MutableBigInt::rw_digits() {
  return bigint::RWDigits(reinterpret_cast<digit_t*>(raw_digits()), length());
}

template <typename T, typename Isolate>
MaybeHandle<T> ThrowBigIntTooBig(Isolate* isolate) {
  // If the result of a BigInt computation is truncated to 64 bit, Turbofan
  // can sometimes truncate intermediate results already, which can prevent
  // those from exceeding the maximum length, effectively preventing a
  // RangeError from being thrown. As this is a performance optimization, this
  // behavior is accepted. To prevent the correctness fuzzer from detecting this
  // difference, we crash the program.
  if (v8_flags.correctness_fuzzer_suppressions) {
    FATAL("Aborting on invalid BigInt length");
  }
  THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kBigIntTooBig));
}

template <typename IsolateT>
MaybeHandle<MutableBigInt> MutableBigInt::New(IsolateT* isolate,
                                              uint32_t length,
                                              AllocationType allocation) {
  if (length > BigInt::kMaxLength) {
    return ThrowBigIntTooBig<MutableBigInt>(isolate);
  }
  Handle<MutableBigInt> result =
      Cast<MutableBigInt>(isolate->factory()->NewBigInt(length, allocation));
  result->initialize_bitfield(false, length);
#if DEBUG
  result->InitializeDigits(length, 0xBF);
#endif
  return result;
}

Handle<BigInt> MutableBigInt::NewFromInt(Isolate* isolate, int value) {
  if (value == 0) return Zero(isolate);
  Handle<MutableBigInt> result =
      Cast<MutableBigInt>(isolate->factory()->NewBigInt(1));
  bool sign = value < 0;
  result->initialize_bitfield(sign, 1);
  if (!sign) {
    result->set_digit(0, value);
  } else {
    if (value == kMinInt) {
      static_assert(kMinInt == -kMaxInt - 1);
      result->set_digit(0, static_cast<BigInt::digit_t>(kMaxInt) + 1);
    } else {
      result->set_digit(0, -value);
    }
  }
  return MakeImmutable(result);
}

Handle<BigInt> MutableBigInt::NewFromDouble(Isolate* isolate, double value) {
  DCHECK_EQ(value, std::floor(value));
  if (value == 0) return Zero(isolate);

  bool sign = value < 0;  // -0 was already handled above.
  uint64_t double_bits = base::bit_cast<uint64_t>(value);
  int32_t raw_exponent =
      static_cast<int32_t>(double_bits >>
                           base::Double::kPhysicalSignificandSize) &
      0x7FF;
  DCHECK_NE(raw_exponent, 0x7FF);
  DCHECK_GE(raw_exponent, 0x3FF);
  uint32_t exponent = raw_exponent - 0x3FF;
  uint32_t digits = exponent / kDigitBits + 1;
  Handle<MutableBigInt> result =
      Cast<MutableBigInt>(isolate->factory()->NewBigInt(digits));
  result->initialize_bitfield(sign, digits);

  // We construct a BigInt from the double {value} by shifting its mantissa
  // according to its exponent and mapping the bit pattern onto digits.
  //
  //               <----------- bitlength = exponent + 1 ----------->
  //                <----- 52 ------> <------ trailing zeroes ------>
  // mantissa:     1yyyyyyyyyyyyyyyyy 0000000000000000000000000000000
  // digits:    0001xxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
  //                <-->          <------>
  //          msd_topbit         kDigitBits
  //
  uint64_t mantissa =
      (double_bits & base::Double::kSignificandMask) | base::Double::kHiddenBit;
  const uint32_t kMantissaTopBit =
      base::Double::kSignificandSize - 1;  // 0-indexed.
  // 0-indexed position of most significant bit in the most significant digit.
  uint32_t msd_topbit = exponent % kDigitBits;
  // Number of unused bits in {mantissa}. We'll keep them shifted to the
  // left (i.e. most significant part) of the underlying uint64_t.
  uint32_t remaining_mantissa_bits = 0;
  // Next digit under construction.
  digit_t digit;

  // First, build the MSD by shifting the mantissa appropriately.
  if (msd_topbit < kMantissaTopBit) {
    remaining_mantissa_bits = kMantissaTopBit - msd_topbit;
    digit = mantissa >> remaining_mantissa_bits;
    mantissa = mantissa << (64 - remaining_mantissa_bits);
  } else {
    DCHECK_GE(msd_topbit, kMantissaTopBit);
    digit = mantissa << (msd_topbit - kMantissaTopBit);
    mantissa = 0;
  }
  result->set_digit(digits - 1, digit);
  // Then fill in the rest of the digits.
  static_assert(BigInt::kMaxLength < kMaxInt);
  for (int32_t digit_index = digits - 2; digit_index >= 0; digit_index--) {
    if (remaining_mantissa_bits > 0) {
      remaining_mantissa_bits -= kDigitBits;
      if (sizeof(digit) == 4) {
        digit = mantissa >> 32;
        mantissa = mantissa << 32;
      } else {
        DCHECK_EQ(sizeof(digit), 8);
        digit = mantissa;
        mantissa = 0;
      }
    } else {
      digit = 0;
    }
    result->set_digit(digit_index, digit);
  }
  return MakeImmutable(result);
}

Handle<MutableBigInt> MutableBigInt::Copy(Isolate* isolate,
                                          DirectHandle<BigIntBase> source) {
  uint32_t length = source->length();
  // Allocating a BigInt of the same length as an existing BigInt cannot throw.
  Handle<MutableBigInt> result = New(isolate, length).ToHandleChecked();
  memcpy(result->raw_digits(), source->raw_digits(), length * kDigitSize);
  return result;
}

void MutableBigInt::InitializeDigits(uint32_t length, uint8_t value) {
  memset(raw_digits(), value, length * kDigitSize);
}

MaybeHandle<BigInt> MutableBigInt::MakeImmutable(
    MaybeHandle<MutableBigInt> maybe) {
  Handle<MutableBigInt> result;
  if (!maybe.ToHandle(&result)) return MaybeHandle<BigInt>();
  return MakeImmutable(result);
}

template <typename IsolateT>
Handle<BigInt> MutableBigInt::MakeImmutable(Handle<MutableBigInt> result) {
  MutableBigInt::Canonicalize(*result);
  return Cast<BigInt>(result);
}

void MutableBigInt::Canonicalize(Tagged<MutableBigInt> result) {
  // Check if we need to right-trim any leading zero-digits.
  uint32_t old_length = result->length();
  uint32_t new_length = old_length;
  while (new_length > 0 && result->digit(new_length - 1) == 0) new_length--;
  uint32_t to_trim = old_length - new_length;
  if (to_trim != 0) {
    Heap* heap = result->GetHeap();
    if (!heap->IsLargeObject(result)) {
      uint32_t old_size =
          ALIGN_TO_ALLOCATION_ALIGNMENT(BigInt::SizeFor(old_length));
      uint32_t new_size =
          ALIGN_TO_ALLOCATION_ALIGNMENT(BigInt::SizeFor(new_length));
      heap->NotifyObjectSizeChange(result, old_size, new_size,
                                   ClearRecordedSlots::kNo);
    }
    result->set_length(new_length, kReleaseStore);

    // Canonicalize -0n.
    if (new_length == 0) {
      result->set_sign(false);
      // TODO(jkummerow): If we cache a canonical 0n, return that here.
    }
  }
  DCHECK_IMPLIES(result->length() > 0,
                 result->digit(result->length() - 1) != 0);  // MSD is non-zero.
  // Callers that don't require trimming must ensure this themselves.
  DCHECK_IMPLIES(result->length() == 0, result->sign() == false);
}

template <typename IsolateT>
Handle<BigInt> BigInt::Zero(IsolateT* isolate, AllocationType allocation) {
  return MutableBigInt::Zero(isolate, allocation);
}
template Handle<BigInt> BigInt::Zero(Isolate* isolate,
                                     AllocationType allocation);
template Handle<BigInt> BigInt::Zero(LocalIsolate* isolate,
                                     AllocationType allocation);

Handle<BigInt> BigInt::UnaryMinus(Isolate* isolate, Handle<BigInt> x) {
  // Special case: There is no -0n.
  if (x->is_zero()) {
    return x;
  }
  Handle<MutableBigInt> result = MutableBigInt::Copy(isolate, x);
  result->set_sign(!x->sign());
  return MutableBigInt::MakeImmutable(result);
}

MaybeHandle<BigInt> BigInt::BitwiseNot(Isolate* isolate,
                                       DirectHandle<BigInt> x) {
  MaybeHandle<MutableBigInt> result;
  if (x->sign()) {
    // ~(-x) == ~(~(x-1)) == x-1
    result = MutableBigInt::AbsoluteSubOne(isolate, x);
  } else {
    // ~x == -x-1 == -(x+1)
    result = MutableBigInt::AbsoluteAddOne(isolate, x, true);
  }
  return MutableBigInt::MakeImmutable(result);
}

MaybeHandle<BigInt> BigInt::Exponentiate(Isolate* isolate, Handle<BigInt> base,
                                         DirectHandle<BigInt> exponent) {
  // 1. If exponent is < 0, throw a RangeError exception.
  if (exponent->sign()) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kMustBePositive));
  }
  // 2. If base is 0n and exponent is 0n, return 1n.
  if (exponent->is_zero()) {
    return MutableBigInt::NewFromInt(isolate, 1);
  }
  // 3. Return a BigInt representing the mathematical value of base raised
  //    to the power exponent.
  if (base->is_zero()) return base;
  if (base->length() == 1 && base->digit(0) == 1) {
    // (-1) ** even_number == 1.
    if (base->sign() && (exponent->digit(0) & 1) == 0) {
      return UnaryMinus(isolate, base);
    }
    // (-1) ** odd_number == -1; 1 ** anything == 1.
    return base;
  }
  // For all bases >= 2, very large exponents would lead to unrepresentable
  // results.
  static_assert(kMaxLengthBits < std::numeric_limits<digit_t>::max());
  if (exponent->length() > 1) {
    return ThrowBigIntTooBig<BigInt>(isolate);
  }
  digit_t exp_value = exponent->digit(0);
  if (exp_value == 1) return base;
  if (exp_value >= kMaxLengthBits) {
    return ThrowBigIntTooBig<BigInt>(isolate);
  }
  static_assert(kMaxLengthBits <= kMaxInt);
  int n = static_cast<int>(exp_value);
  if (base->length() == 1 && base->digit(0) == 2) {
    // Fast path for 2^n.
    int needed_digits = 1 + (n / kDigitBits);
    Handle<MutableBigInt> result;
    if (!MutableBigInt::New(isolate, needed_digits).ToHandle(&result)) {
      return MaybeHandle<BigInt>();
    }
    result->InitializeDigits(needed_digits);
    // All bits are zero. Now set the n-th bit.
    digit_t msd = static_cast<digit_t>(1) << (n % kDigitBits);
    result->set_digit(needed_digits - 1, msd);
    // Result is negative for odd powers of -2n.
    if (base->sign()) result->set_sign((n & 1) != 0);
    return MutableBigInt::MakeImmutable(result);
  }
  Handle<BigInt> result;
  Handle<BigInt> running_square = base;
  // This implicitly sets the result's sign correctly.
  if (n & 1) result = base;
  n >>= 1;
  for (; n != 0; n >>= 1) {
    MaybeHandle<BigInt> maybe_result =
        Multiply(isolate, running_square, running_square);
    if (!maybe_result.ToHandle(&running_square)) return maybe_result;
    if (n & 1) {
      if (result.is_null()) {
        result = running_square;
      } else {
        maybe_result = Multiply(isolate, result, running_square);
        if (!maybe_result.ToHandle(&result)) return maybe_result;
      }
    }
  }
  return result;
}

MaybeHandle<BigInt> BigInt::Multiply(Isolate* isolate, Handle<BigInt> x,
                                     Handle<BigInt> y) {
  if (x->is_zero()) return x;
  if (y->is_zero()) return y;
  uint32_t result_length =
      bigint::MultiplyResultLength(x->digits(), y->digits());
  Handle<MutableBigInt> result;
  if (!MutableBigInt::New(isolate, result_length).ToHandle(&result)) {
    return MaybeHandle<BigInt>();
  }
  DisallowGarbageCollection no_gc;
  bigint::Status status = isolate->bigint_processor()->Multiply(
      result->rw_digits(), x->digits(), y->digits());
  if (status == bigint::Status::kInterrupted) {
    AllowGarbageCollection terminating_anyway;
    isolate->TerminateExecution();
    return {};
  }
  result->set_sign(x->sign() != y->sign());
  return MutableBigInt::MakeImmutable(result);
}

MaybeHandle<BigInt> BigInt::Divide(Isolate* isolate, Handle<BigInt> x,
                                   DirectHandle<BigInt> y) {
  // 1. If y is 0n, throw a RangeError exception.
  if (y->is_zero()) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kBigIntDivZero));
  }
  // 2. Let quotient be the mathematical value of x divided by y.
  // 3. Return a BigInt representing quotient rounded towards 0 to the next
  //    integral value.
  if (bigint::Compare(x->digits(), y->digits()) < 0) {
    return Zero(isolate);
  }
  bool result_sign = x->sign() != y->sign();
  if (y->length() == 1 && y->digit(0) == 1) {
    return result_sign == x->sign() ? x : UnaryMinus(isolate, x);
  }
  Handle<MutableBigInt> quotient;
  uint32_t result_length = bigint::DivideResultLength(x->digits(), y->digits());
  if (!MutableBigInt::New(isolate, result_length).ToHandle(&quotient)) {
    return {};
  }
  DisallowGarbageCollection no_gc;
  bigint::Status status = isolate->bigint_processor()->Divide(
      quotient->rw_digits(), x->digits(), y->digits());
  if (status == bigint::Status::kInterrupted) {
    AllowGarbageCollection terminating_anyway;
    isolate->TerminateExecution();
    return {};
  }
  quotient->set_sign(result_sign);
  return MutableBigInt::MakeImmutable(quotient);
}

MaybeHandle<BigInt> BigInt::Remainder(Isolate* isolate, Handle<BigInt> x,
                                      DirectHandle<BigInt> y) {
  // 1. If y is 0n, throw a RangeError exception.
  if (y->is_zero()) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kBigIntDivZero));
  }
  // 2. Return the BigInt representing x modulo y.
  // See https://github.com/tc39/proposal-bigint/issues/84 though.
  if (bigint::Compare(x->digits(), y->digits()) < 0) return x;
  if (y->length() == 1 && y->digit(0) == 1) return Zero(isolate);
  Handle<MutableBigInt> remainder;
  uint32_t result_length = bigint::ModuloResultLength(y->digits());
  if (!MutableBigInt::New(isolate, result_length).ToHandle(&remainder)) {
    return {};
  }
  DisallowGarbageCollection no_gc;
  bigint::Status status = isolate->bigint_processor()->Modulo(
      remainder->rw_digits(), x->digits(), y->digits());
  if (status == bigint::Status::kInterrupted) {
    AllowGarbageCollection terminating_anyway;
    isolate->TerminateExecution();
    return {};
  }
  remainder->set_sign(x->sign());
  return MutableBigInt::MakeImmutable(remainder);
}

MaybeHandle<BigInt> BigInt::Add(Isolate* isolate, Handle<BigInt> x,
                                Handle<BigInt> y) {
  if (x->is_zero()) return y;
  if (y->is_zero()) return x;
  bool xsign = x->sign();
  bool ysign = y->sign();
  uint32_t result_length =
      bigint::AddSignedResultLength(x->length(), y->length(), xsign == ysign);
  Handle<MutableBigInt> result;
  if (!MutableBigInt::New(isolate, result_length).ToHandle(&result)) {
    // Allocation fails when {result_length} exceeds the max BigInt size.
    return {};
  }
  DisallowGarbageCollection no_gc;
  bool result_sign = bigint::AddSigned(result->rw_digits(), x->digits(), xsign,
                                       y->digits(), ysign);
  result->set_sign(result_sign);
  return MutableBigInt::MakeImmutable(result);
}

MaybeHandle<BigInt> BigInt::Subtract(Isolate* isolate, Handle<BigInt> x,
                                     Handle<BigInt> y) {
  if (y->is_zero()) return x;
  if (x->is_zero()) return UnaryMinus(isolate, y);
  bool xsign = x->sign();
  bool ysign = y->sign();
  uint32_t result_length = bigint::SubtractSignedResultLength(
      x->length(), y->length(), xsign == ysign);
  Handle<MutableBigInt> result;
  if (!MutableBigInt::New(isolate, result_length).ToHandle(&result)) {
    // Allocation fails when {result_length} exceeds the max BigInt size.
    return {};
  }
  DisallowGarbageCollection no_gc;
  bool result_sign = bigint::SubtractSigned(result->rw_digits(), x->digits(),
                                            xsign, y->digits(), ysign);
  result->set_sign(result_sign);
  return MutableBigInt::MakeImmutable(result);
}

namespace {

// Produces comparison result for {left_negative} == sign(x) != sign(y).
ComparisonResult UnequalSign(bool left_negative) {
  return left_negative ? ComparisonResult::kLessThan
                       : ComparisonResult::kGreaterThan;
}

// Produces result for |x| > |y|, with {both_negative} == sign(x) == sign(y);
ComparisonResult AbsoluteGreater(bool both_negative) {
  return both_negative ? ComparisonResult::kLessThan
                       : ComparisonResult::kGreaterThan;
}

// Produces result for |x| < |y|, with {both_negative} == sign(x) == sign(y).
ComparisonResult AbsoluteLess(bool both_negative) {
  return both_negative ? ComparisonResult::kGreaterThan
                       : ComparisonResult::kLessThan;
}

}  // namespace

// (Never returns kUndefined.)
ComparisonResult BigInt::CompareToBigInt(DirectHandle<BigInt> x,
                                         DirectHandle<BigInt> y) {
  bool x_sign = x->sign();
  if (x_sign != y->sign()) return UnequalSign(x_sign);

  int result = bigint::Compare(x->digits(), y->digits());
  if (result > 0) return AbsoluteGreater(x_sign);
  if (result < 0) return AbsoluteLess(x_sign);
  return ComparisonResult::kEqual;
}

bool BigInt::EqualToBigInt(Tagged<BigInt> x, Tagged<BigInt> y) {
  if (x->sign() != y->sign()) return false;
  if (x->length() != y->length()) return false;
  for (uint32_t i = 0; i < x->length(); i++) {
    if (x->digit(i) != y->digit(i)) return false;
  }
  return true;
}

MaybeHandle<BigInt> BigInt::Increment(Isolate* isolate,
                                      DirectHandle<BigInt> x) {
  if (x->sign()) {
    Handle<MutableBigInt> result = MutableBigInt::AbsoluteSubOne(isolate, x);
    result->set_sign(true);
    return MutableBigInt::MakeImmutable(result);
  } else {
    return MutableBigInt::MakeImmutable(
        MutableBigInt::AbsoluteAddOne(isolate, x, false));
  }
}

MaybeHandle<BigInt> BigInt::Decrement(Isolate* isolate,
                                      DirectHandle<BigInt> x) {
  MaybeHandle<MutableBigInt> result;
  if (x->sign()) {
    result = MutableBigInt::AbsoluteAddOne(isolate, x, true);
  } else if (x->is_zero()) {
    // TODO(jkummerow): Consider caching a canonical -1n BigInt.
    return MutableBigInt::NewFromInt(isolate, -1);
  } else {
    result = MutableBigInt::AbsoluteSubOne(isolate, x);
  }
  return MutableBigInt::MakeImmutable(result);
}

Maybe<ComparisonResult> BigInt::CompareToString(Isolate* isolate,
                                                DirectHandle<BigInt> x,
                                                Handle<String> y) {
  // a. Let ny be StringToBigInt(y);
  MaybeHandle<BigInt> maybe_ny = StringToBigInt(isolate, y);
  // b. If ny is NaN, return undefined.
  Handle<BigInt> ny;
  if (!maybe_ny.ToHandle(&ny)) {
    if (isolate->has_exception()) {
      return Nothing<ComparisonResult>();
    } else {
      return Just(ComparisonResult::kUndefined);
    }
  }
  // c. Return BigInt::lessThan(x, ny).
  return Just(CompareToBigInt(x, ny));
}

Maybe<bool> BigInt::EqualToString(Isolate* isolate, DirectHandle
Prompt: 
```
这是目录为v8/src/objects/bigint.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/bigint.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Parts of the implementation below:

// Copyright (c) 2014 the Dart project authors.  Please see the AUTHORS file [1]
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file [2].
//
// [1] https://github.com/dart-lang/sdk/blob/master/AUTHORS
// [2] https://github.com/dart-lang/sdk/blob/master/LICENSE

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file [3].
//
// [3] https://golang.org/LICENSE

#include "src/objects/bigint.h"

#include <atomic>

#include "src/base/numbers/double.h"
#include "src/bigint/bigint.h"
#include "src/execution/isolate-inl.h"
#include "src/execution/isolate-utils-inl.h"
#include "src/heap/factory.h"
#include "src/heap/heap-write-barrier-inl.h"
#include "src/heap/heap.h"
#include "src/numbers/conversions.h"
#include "src/objects/casting.h"
#include "src/objects/heap-number-inl.h"
#include "src/objects/instance-type-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/smi.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8 {
namespace internal {

// The MutableBigInt class is an implementation detail designed to prevent
// accidental mutation of a BigInt after its construction. Step-by-step
// construction of a BigInt must happen in terms of MutableBigInt, the
// final result is then passed through MutableBigInt::MakeImmutable and not
// modified further afterwards.
// Many of the functions in this class use arguments of type {BigIntBase},
// indicating that they will be used in a read-only capacity, and both
// {BigInt} and {MutableBigInt} objects can be passed in.
V8_OBJECT class MutableBigInt : public FreshlyAllocatedBigInt {
 public:
  // Bottleneck for converting MutableBigInts to BigInts.
  static MaybeHandle<BigInt> MakeImmutable(MaybeHandle<MutableBigInt> maybe);
  template <typename Isolate = v8::internal::Isolate>
  static Handle<BigInt> MakeImmutable(Handle<MutableBigInt> result);

  static void Canonicalize(Tagged<MutableBigInt> result);

  // Allocation helpers.
  template <typename IsolateT>
  static MaybeHandle<MutableBigInt> New(
      IsolateT* isolate, uint32_t length,
      AllocationType allocation = AllocationType::kYoung);
  static Handle<BigInt> NewFromInt(Isolate* isolate, int value);
  static Handle<BigInt> NewFromDouble(Isolate* isolate, double value);
  void InitializeDigits(uint32_t length, uint8_t value = 0);
  static Handle<MutableBigInt> Copy(Isolate* isolate,
                                    DirectHandle<BigIntBase> source);
  template <typename IsolateT>
  static Handle<BigInt> Zero(
      IsolateT* isolate, AllocationType allocation = AllocationType::kYoung) {
    // TODO(jkummerow): Consider caching a canonical zero-BigInt.
    return MakeImmutable<IsolateT>(
        New(isolate, 0, allocation).ToHandleChecked());
  }

  // Internal helpers.
  static MaybeHandle<MutableBigInt> AbsoluteAddOne(
      Isolate* isolate, DirectHandle<BigIntBase> x, bool sign,
      Tagged<MutableBigInt> result_storage = {});
  static Handle<MutableBigInt> AbsoluteSubOne(Isolate* isolate,
                                              DirectHandle<BigIntBase> x);

  // Specialized helpers for shift operations.
  static MaybeHandle<BigInt> LeftShiftByAbsolute(Isolate* isolate,
                                                 Handle<BigIntBase> x,
                                                 Handle<BigIntBase> y);
  static Handle<BigInt> RightShiftByAbsolute(Isolate* isolate,
                                             Handle<BigIntBase> x,
                                             Handle<BigIntBase> y);
  static Handle<BigInt> RightShiftByMaximum(Isolate* isolate, bool sign);
  static Maybe<digit_t> ToShiftAmount(Handle<BigIntBase> x);

  static double ToDouble(DirectHandle<BigIntBase> x);
  enum Rounding { kRoundDown, kTie, kRoundUp };
  static Rounding DecideRounding(DirectHandle<BigIntBase> x,
                                 int mantissa_bits_unset, int digit_index,
                                 uint64_t current_digit);

  // Returns the least significant 64 bits, simulating two's complement
  // representation.
  static uint64_t GetRawBits(BigIntBase* x, bool* lossless);

  static inline bool digit_ismax(digit_t x) {
    return static_cast<digit_t>(~x) == 0;
  }

  bigint::RWDigits rw_digits();

  inline void set_sign(bool new_sign) {
    bitfield_.store(
        SignBits::update(bitfield_.load(std::memory_order_relaxed), new_sign),
        std::memory_order_relaxed);
  }
  inline void set_length(uint32_t new_length, ReleaseStoreTag) {
    bitfield_.store(LengthBits::update(
                        bitfield_.load(std::memory_order_relaxed), new_length),
                    std::memory_order_relaxed);
  }
  inline void initialize_bitfield(bool sign, uint32_t length) {
    bitfield_.store(LengthBits::encode(length) | SignBits::encode(sign),
                    std::memory_order_relaxed);
  }
  inline void set_digit(uint32_t n, digit_t value) {
    SLOW_DCHECK(n < length());
    raw_digits()[n].set_value(value);
  }

  void set_64_bits(uint64_t bits);

  static bool IsMutableBigInt(Tagged<MutableBigInt> o) { return IsBigInt(o); }

  static_assert(std::is_same<bigint::digit_t, BigIntBase::digit_t>::value,
                "We must be able to call BigInt library functions");

  NEVER_READ_ONLY_SPACE
} V8_OBJECT_END;

NEVER_READ_ONLY_SPACE_IMPL(MutableBigInt)

template <>
struct CastTraits<MutableBigInt> : public CastTraits<BigInt> {};

bigint::Digits BigIntBase::digits() const {
  return bigint::Digits(reinterpret_cast<const digit_t*>(raw_digits()),
                        length());
}

bigint::RWDigits MutableBigInt::rw_digits() {
  return bigint::RWDigits(reinterpret_cast<digit_t*>(raw_digits()), length());
}

template <typename T, typename Isolate>
MaybeHandle<T> ThrowBigIntTooBig(Isolate* isolate) {
  // If the result of a BigInt computation is truncated to 64 bit, Turbofan
  // can sometimes truncate intermediate results already, which can prevent
  // those from exceeding the maximum length, effectively preventing a
  // RangeError from being thrown. As this is a performance optimization, this
  // behavior is accepted. To prevent the correctness fuzzer from detecting this
  // difference, we crash the program.
  if (v8_flags.correctness_fuzzer_suppressions) {
    FATAL("Aborting on invalid BigInt length");
  }
  THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kBigIntTooBig));
}

template <typename IsolateT>
MaybeHandle<MutableBigInt> MutableBigInt::New(IsolateT* isolate,
                                              uint32_t length,
                                              AllocationType allocation) {
  if (length > BigInt::kMaxLength) {
    return ThrowBigIntTooBig<MutableBigInt>(isolate);
  }
  Handle<MutableBigInt> result =
      Cast<MutableBigInt>(isolate->factory()->NewBigInt(length, allocation));
  result->initialize_bitfield(false, length);
#if DEBUG
  result->InitializeDigits(length, 0xBF);
#endif
  return result;
}

Handle<BigInt> MutableBigInt::NewFromInt(Isolate* isolate, int value) {
  if (value == 0) return Zero(isolate);
  Handle<MutableBigInt> result =
      Cast<MutableBigInt>(isolate->factory()->NewBigInt(1));
  bool sign = value < 0;
  result->initialize_bitfield(sign, 1);
  if (!sign) {
    result->set_digit(0, value);
  } else {
    if (value == kMinInt) {
      static_assert(kMinInt == -kMaxInt - 1);
      result->set_digit(0, static_cast<BigInt::digit_t>(kMaxInt) + 1);
    } else {
      result->set_digit(0, -value);
    }
  }
  return MakeImmutable(result);
}

Handle<BigInt> MutableBigInt::NewFromDouble(Isolate* isolate, double value) {
  DCHECK_EQ(value, std::floor(value));
  if (value == 0) return Zero(isolate);

  bool sign = value < 0;  // -0 was already handled above.
  uint64_t double_bits = base::bit_cast<uint64_t>(value);
  int32_t raw_exponent =
      static_cast<int32_t>(double_bits >>
                           base::Double::kPhysicalSignificandSize) &
      0x7FF;
  DCHECK_NE(raw_exponent, 0x7FF);
  DCHECK_GE(raw_exponent, 0x3FF);
  uint32_t exponent = raw_exponent - 0x3FF;
  uint32_t digits = exponent / kDigitBits + 1;
  Handle<MutableBigInt> result =
      Cast<MutableBigInt>(isolate->factory()->NewBigInt(digits));
  result->initialize_bitfield(sign, digits);

  // We construct a BigInt from the double {value} by shifting its mantissa
  // according to its exponent and mapping the bit pattern onto digits.
  //
  //               <----------- bitlength = exponent + 1 ----------->
  //                <----- 52 ------> <------ trailing zeroes ------>
  // mantissa:     1yyyyyyyyyyyyyyyyy 0000000000000000000000000000000
  // digits:    0001xxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
  //                <-->          <------>
  //          msd_topbit         kDigitBits
  //
  uint64_t mantissa =
      (double_bits & base::Double::kSignificandMask) | base::Double::kHiddenBit;
  const uint32_t kMantissaTopBit =
      base::Double::kSignificandSize - 1;  // 0-indexed.
  // 0-indexed position of most significant bit in the most significant digit.
  uint32_t msd_topbit = exponent % kDigitBits;
  // Number of unused bits in {mantissa}. We'll keep them shifted to the
  // left (i.e. most significant part) of the underlying uint64_t.
  uint32_t remaining_mantissa_bits = 0;
  // Next digit under construction.
  digit_t digit;

  // First, build the MSD by shifting the mantissa appropriately.
  if (msd_topbit < kMantissaTopBit) {
    remaining_mantissa_bits = kMantissaTopBit - msd_topbit;
    digit = mantissa >> remaining_mantissa_bits;
    mantissa = mantissa << (64 - remaining_mantissa_bits);
  } else {
    DCHECK_GE(msd_topbit, kMantissaTopBit);
    digit = mantissa << (msd_topbit - kMantissaTopBit);
    mantissa = 0;
  }
  result->set_digit(digits - 1, digit);
  // Then fill in the rest of the digits.
  static_assert(BigInt::kMaxLength < kMaxInt);
  for (int32_t digit_index = digits - 2; digit_index >= 0; digit_index--) {
    if (remaining_mantissa_bits > 0) {
      remaining_mantissa_bits -= kDigitBits;
      if (sizeof(digit) == 4) {
        digit = mantissa >> 32;
        mantissa = mantissa << 32;
      } else {
        DCHECK_EQ(sizeof(digit), 8);
        digit = mantissa;
        mantissa = 0;
      }
    } else {
      digit = 0;
    }
    result->set_digit(digit_index, digit);
  }
  return MakeImmutable(result);
}

Handle<MutableBigInt> MutableBigInt::Copy(Isolate* isolate,
                                          DirectHandle<BigIntBase> source) {
  uint32_t length = source->length();
  // Allocating a BigInt of the same length as an existing BigInt cannot throw.
  Handle<MutableBigInt> result = New(isolate, length).ToHandleChecked();
  memcpy(result->raw_digits(), source->raw_digits(), length * kDigitSize);
  return result;
}

void MutableBigInt::InitializeDigits(uint32_t length, uint8_t value) {
  memset(raw_digits(), value, length * kDigitSize);
}

MaybeHandle<BigInt> MutableBigInt::MakeImmutable(
    MaybeHandle<MutableBigInt> maybe) {
  Handle<MutableBigInt> result;
  if (!maybe.ToHandle(&result)) return MaybeHandle<BigInt>();
  return MakeImmutable(result);
}

template <typename IsolateT>
Handle<BigInt> MutableBigInt::MakeImmutable(Handle<MutableBigInt> result) {
  MutableBigInt::Canonicalize(*result);
  return Cast<BigInt>(result);
}

void MutableBigInt::Canonicalize(Tagged<MutableBigInt> result) {
  // Check if we need to right-trim any leading zero-digits.
  uint32_t old_length = result->length();
  uint32_t new_length = old_length;
  while (new_length > 0 && result->digit(new_length - 1) == 0) new_length--;
  uint32_t to_trim = old_length - new_length;
  if (to_trim != 0) {
    Heap* heap = result->GetHeap();
    if (!heap->IsLargeObject(result)) {
      uint32_t old_size =
          ALIGN_TO_ALLOCATION_ALIGNMENT(BigInt::SizeFor(old_length));
      uint32_t new_size =
          ALIGN_TO_ALLOCATION_ALIGNMENT(BigInt::SizeFor(new_length));
      heap->NotifyObjectSizeChange(result, old_size, new_size,
                                   ClearRecordedSlots::kNo);
    }
    result->set_length(new_length, kReleaseStore);

    // Canonicalize -0n.
    if (new_length == 0) {
      result->set_sign(false);
      // TODO(jkummerow): If we cache a canonical 0n, return that here.
    }
  }
  DCHECK_IMPLIES(result->length() > 0,
                 result->digit(result->length() - 1) != 0);  // MSD is non-zero.
  // Callers that don't require trimming must ensure this themselves.
  DCHECK_IMPLIES(result->length() == 0, result->sign() == false);
}

template <typename IsolateT>
Handle<BigInt> BigInt::Zero(IsolateT* isolate, AllocationType allocation) {
  return MutableBigInt::Zero(isolate, allocation);
}
template Handle<BigInt> BigInt::Zero(Isolate* isolate,
                                     AllocationType allocation);
template Handle<BigInt> BigInt::Zero(LocalIsolate* isolate,
                                     AllocationType allocation);

Handle<BigInt> BigInt::UnaryMinus(Isolate* isolate, Handle<BigInt> x) {
  // Special case: There is no -0n.
  if (x->is_zero()) {
    return x;
  }
  Handle<MutableBigInt> result = MutableBigInt::Copy(isolate, x);
  result->set_sign(!x->sign());
  return MutableBigInt::MakeImmutable(result);
}

MaybeHandle<BigInt> BigInt::BitwiseNot(Isolate* isolate,
                                       DirectHandle<BigInt> x) {
  MaybeHandle<MutableBigInt> result;
  if (x->sign()) {
    // ~(-x) == ~(~(x-1)) == x-1
    result = MutableBigInt::AbsoluteSubOne(isolate, x);
  } else {
    // ~x == -x-1 == -(x+1)
    result = MutableBigInt::AbsoluteAddOne(isolate, x, true);
  }
  return MutableBigInt::MakeImmutable(result);
}

MaybeHandle<BigInt> BigInt::Exponentiate(Isolate* isolate, Handle<BigInt> base,
                                         DirectHandle<BigInt> exponent) {
  // 1. If exponent is < 0, throw a RangeError exception.
  if (exponent->sign()) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kMustBePositive));
  }
  // 2. If base is 0n and exponent is 0n, return 1n.
  if (exponent->is_zero()) {
    return MutableBigInt::NewFromInt(isolate, 1);
  }
  // 3. Return a BigInt representing the mathematical value of base raised
  //    to the power exponent.
  if (base->is_zero()) return base;
  if (base->length() == 1 && base->digit(0) == 1) {
    // (-1) ** even_number == 1.
    if (base->sign() && (exponent->digit(0) & 1) == 0) {
      return UnaryMinus(isolate, base);
    }
    // (-1) ** odd_number == -1; 1 ** anything == 1.
    return base;
  }
  // For all bases >= 2, very large exponents would lead to unrepresentable
  // results.
  static_assert(kMaxLengthBits < std::numeric_limits<digit_t>::max());
  if (exponent->length() > 1) {
    return ThrowBigIntTooBig<BigInt>(isolate);
  }
  digit_t exp_value = exponent->digit(0);
  if (exp_value == 1) return base;
  if (exp_value >= kMaxLengthBits) {
    return ThrowBigIntTooBig<BigInt>(isolate);
  }
  static_assert(kMaxLengthBits <= kMaxInt);
  int n = static_cast<int>(exp_value);
  if (base->length() == 1 && base->digit(0) == 2) {
    // Fast path for 2^n.
    int needed_digits = 1 + (n / kDigitBits);
    Handle<MutableBigInt> result;
    if (!MutableBigInt::New(isolate, needed_digits).ToHandle(&result)) {
      return MaybeHandle<BigInt>();
    }
    result->InitializeDigits(needed_digits);
    // All bits are zero. Now set the n-th bit.
    digit_t msd = static_cast<digit_t>(1) << (n % kDigitBits);
    result->set_digit(needed_digits - 1, msd);
    // Result is negative for odd powers of -2n.
    if (base->sign()) result->set_sign((n & 1) != 0);
    return MutableBigInt::MakeImmutable(result);
  }
  Handle<BigInt> result;
  Handle<BigInt> running_square = base;
  // This implicitly sets the result's sign correctly.
  if (n & 1) result = base;
  n >>= 1;
  for (; n != 0; n >>= 1) {
    MaybeHandle<BigInt> maybe_result =
        Multiply(isolate, running_square, running_square);
    if (!maybe_result.ToHandle(&running_square)) return maybe_result;
    if (n & 1) {
      if (result.is_null()) {
        result = running_square;
      } else {
        maybe_result = Multiply(isolate, result, running_square);
        if (!maybe_result.ToHandle(&result)) return maybe_result;
      }
    }
  }
  return result;
}

MaybeHandle<BigInt> BigInt::Multiply(Isolate* isolate, Handle<BigInt> x,
                                     Handle<BigInt> y) {
  if (x->is_zero()) return x;
  if (y->is_zero()) return y;
  uint32_t result_length =
      bigint::MultiplyResultLength(x->digits(), y->digits());
  Handle<MutableBigInt> result;
  if (!MutableBigInt::New(isolate, result_length).ToHandle(&result)) {
    return MaybeHandle<BigInt>();
  }
  DisallowGarbageCollection no_gc;
  bigint::Status status = isolate->bigint_processor()->Multiply(
      result->rw_digits(), x->digits(), y->digits());
  if (status == bigint::Status::kInterrupted) {
    AllowGarbageCollection terminating_anyway;
    isolate->TerminateExecution();
    return {};
  }
  result->set_sign(x->sign() != y->sign());
  return MutableBigInt::MakeImmutable(result);
}

MaybeHandle<BigInt> BigInt::Divide(Isolate* isolate, Handle<BigInt> x,
                                   DirectHandle<BigInt> y) {
  // 1. If y is 0n, throw a RangeError exception.
  if (y->is_zero()) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kBigIntDivZero));
  }
  // 2. Let quotient be the mathematical value of x divided by y.
  // 3. Return a BigInt representing quotient rounded towards 0 to the next
  //    integral value.
  if (bigint::Compare(x->digits(), y->digits()) < 0) {
    return Zero(isolate);
  }
  bool result_sign = x->sign() != y->sign();
  if (y->length() == 1 && y->digit(0) == 1) {
    return result_sign == x->sign() ? x : UnaryMinus(isolate, x);
  }
  Handle<MutableBigInt> quotient;
  uint32_t result_length = bigint::DivideResultLength(x->digits(), y->digits());
  if (!MutableBigInt::New(isolate, result_length).ToHandle(&quotient)) {
    return {};
  }
  DisallowGarbageCollection no_gc;
  bigint::Status status = isolate->bigint_processor()->Divide(
      quotient->rw_digits(), x->digits(), y->digits());
  if (status == bigint::Status::kInterrupted) {
    AllowGarbageCollection terminating_anyway;
    isolate->TerminateExecution();
    return {};
  }
  quotient->set_sign(result_sign);
  return MutableBigInt::MakeImmutable(quotient);
}

MaybeHandle<BigInt> BigInt::Remainder(Isolate* isolate, Handle<BigInt> x,
                                      DirectHandle<BigInt> y) {
  // 1. If y is 0n, throw a RangeError exception.
  if (y->is_zero()) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kBigIntDivZero));
  }
  // 2. Return the BigInt representing x modulo y.
  // See https://github.com/tc39/proposal-bigint/issues/84 though.
  if (bigint::Compare(x->digits(), y->digits()) < 0) return x;
  if (y->length() == 1 && y->digit(0) == 1) return Zero(isolate);
  Handle<MutableBigInt> remainder;
  uint32_t result_length = bigint::ModuloResultLength(y->digits());
  if (!MutableBigInt::New(isolate, result_length).ToHandle(&remainder)) {
    return {};
  }
  DisallowGarbageCollection no_gc;
  bigint::Status status = isolate->bigint_processor()->Modulo(
      remainder->rw_digits(), x->digits(), y->digits());
  if (status == bigint::Status::kInterrupted) {
    AllowGarbageCollection terminating_anyway;
    isolate->TerminateExecution();
    return {};
  }
  remainder->set_sign(x->sign());
  return MutableBigInt::MakeImmutable(remainder);
}

MaybeHandle<BigInt> BigInt::Add(Isolate* isolate, Handle<BigInt> x,
                                Handle<BigInt> y) {
  if (x->is_zero()) return y;
  if (y->is_zero()) return x;
  bool xsign = x->sign();
  bool ysign = y->sign();
  uint32_t result_length =
      bigint::AddSignedResultLength(x->length(), y->length(), xsign == ysign);
  Handle<MutableBigInt> result;
  if (!MutableBigInt::New(isolate, result_length).ToHandle(&result)) {
    // Allocation fails when {result_length} exceeds the max BigInt size.
    return {};
  }
  DisallowGarbageCollection no_gc;
  bool result_sign = bigint::AddSigned(result->rw_digits(), x->digits(), xsign,
                                       y->digits(), ysign);
  result->set_sign(result_sign);
  return MutableBigInt::MakeImmutable(result);
}

MaybeHandle<BigInt> BigInt::Subtract(Isolate* isolate, Handle<BigInt> x,
                                     Handle<BigInt> y) {
  if (y->is_zero()) return x;
  if (x->is_zero()) return UnaryMinus(isolate, y);
  bool xsign = x->sign();
  bool ysign = y->sign();
  uint32_t result_length = bigint::SubtractSignedResultLength(
      x->length(), y->length(), xsign == ysign);
  Handle<MutableBigInt> result;
  if (!MutableBigInt::New(isolate, result_length).ToHandle(&result)) {
    // Allocation fails when {result_length} exceeds the max BigInt size.
    return {};
  }
  DisallowGarbageCollection no_gc;
  bool result_sign = bigint::SubtractSigned(result->rw_digits(), x->digits(),
                                            xsign, y->digits(), ysign);
  result->set_sign(result_sign);
  return MutableBigInt::MakeImmutable(result);
}

namespace {

// Produces comparison result for {left_negative} == sign(x) != sign(y).
ComparisonResult UnequalSign(bool left_negative) {
  return left_negative ? ComparisonResult::kLessThan
                       : ComparisonResult::kGreaterThan;
}

// Produces result for |x| > |y|, with {both_negative} == sign(x) == sign(y);
ComparisonResult AbsoluteGreater(bool both_negative) {
  return both_negative ? ComparisonResult::kLessThan
                       : ComparisonResult::kGreaterThan;
}

// Produces result for |x| < |y|, with {both_negative} == sign(x) == sign(y).
ComparisonResult AbsoluteLess(bool both_negative) {
  return both_negative ? ComparisonResult::kGreaterThan
                       : ComparisonResult::kLessThan;
}

}  // namespace

// (Never returns kUndefined.)
ComparisonResult BigInt::CompareToBigInt(DirectHandle<BigInt> x,
                                         DirectHandle<BigInt> y) {
  bool x_sign = x->sign();
  if (x_sign != y->sign()) return UnequalSign(x_sign);

  int result = bigint::Compare(x->digits(), y->digits());
  if (result > 0) return AbsoluteGreater(x_sign);
  if (result < 0) return AbsoluteLess(x_sign);
  return ComparisonResult::kEqual;
}

bool BigInt::EqualToBigInt(Tagged<BigInt> x, Tagged<BigInt> y) {
  if (x->sign() != y->sign()) return false;
  if (x->length() != y->length()) return false;
  for (uint32_t i = 0; i < x->length(); i++) {
    if (x->digit(i) != y->digit(i)) return false;
  }
  return true;
}

MaybeHandle<BigInt> BigInt::Increment(Isolate* isolate,
                                      DirectHandle<BigInt> x) {
  if (x->sign()) {
    Handle<MutableBigInt> result = MutableBigInt::AbsoluteSubOne(isolate, x);
    result->set_sign(true);
    return MutableBigInt::MakeImmutable(result);
  } else {
    return MutableBigInt::MakeImmutable(
        MutableBigInt::AbsoluteAddOne(isolate, x, false));
  }
}

MaybeHandle<BigInt> BigInt::Decrement(Isolate* isolate,
                                      DirectHandle<BigInt> x) {
  MaybeHandle<MutableBigInt> result;
  if (x->sign()) {
    result = MutableBigInt::AbsoluteAddOne(isolate, x, true);
  } else if (x->is_zero()) {
    // TODO(jkummerow): Consider caching a canonical -1n BigInt.
    return MutableBigInt::NewFromInt(isolate, -1);
  } else {
    result = MutableBigInt::AbsoluteSubOne(isolate, x);
  }
  return MutableBigInt::MakeImmutable(result);
}

Maybe<ComparisonResult> BigInt::CompareToString(Isolate* isolate,
                                                DirectHandle<BigInt> x,
                                                Handle<String> y) {
  // a. Let ny be StringToBigInt(y);
  MaybeHandle<BigInt> maybe_ny = StringToBigInt(isolate, y);
  // b. If ny is NaN, return undefined.
  Handle<BigInt> ny;
  if (!maybe_ny.ToHandle(&ny)) {
    if (isolate->has_exception()) {
      return Nothing<ComparisonResult>();
    } else {
      return Just(ComparisonResult::kUndefined);
    }
  }
  // c. Return BigInt::lessThan(x, ny).
  return Just(CompareToBigInt(x, ny));
}

Maybe<bool> BigInt::EqualToString(Isolate* isolate, DirectHandle<BigInt> x,
                                  Handle<String> y) {
  // a. Let n be StringToBigInt(y).
  MaybeHandle<BigInt> maybe_n = StringToBigInt(isolate, y);
  // b. If n is NaN, return false.
  Handle<BigInt> n;
  if (!maybe_n.ToHandle(&n)) {
    if (isolate->has_exception()) {
      return Nothing<bool>();
    } else {
      return Just(false);
    }
  }
  // c. Return the result of x == n.
  return Just(EqualToBigInt(*x, *n));
}

bool BigInt::EqualToNumber(DirectHandle<BigInt> x, Handle<Object> y) {
  DCHECK(IsNumber(*y));
  // a. If x or y are any of NaN, +∞, or -∞, return false.
  // b. If the mathematical value of x is equal to the mathematical value of y,
  //    return true, otherwise return false.
  if (IsSmi(*y)) {
    int value = Smi::ToInt(*y);
    if (value == 0) return x->is_zero();
    // Any multi-digit BigInt is bigger than a Smi.
    static_assert(sizeof(digit_t) >= sizeof(value));
    return (x->length() == 1) && (x->sign() == (value < 0)) &&
           (x->digit(0) ==
            static_cast<digit_t>(std::abs(static_cast<int64_t>(value))));
  }
  DCHECK(IsHeapNumber(*y));
  double value = Cast<HeapNumber>(y)->value();
  return CompareToDouble(x, value) == ComparisonResult::kEqual;
}

ComparisonResult BigInt::CompareToNumber(DirectHandle<BigInt> x,
                                         DirectHandle<Object> y) {
  DCHECK(IsNumber(*y));
  if (IsSmi(*y)) {
    bool x_sign = x->sign();
    int y_value = Smi::ToInt(*y);
    bool y_sign = (y_value < 0);
    if (x_sign != y_sign) return UnequalSign(x_sign);

    if (x->is_zero()) {
      DCHECK(!y_sign);
      return y_value == 0 ? ComparisonResult::kEqual
                          : ComparisonResult::kLessThan;
    }
    // Any multi-digit BigInt is bigger than a Smi.
    static_assert(sizeof(digit_t) >= sizeof(y_value));
    if (x->length() > 1) return AbsoluteGreater(x_sign);

    digit_t abs_value = std::abs(static_cast<int64_t>(y_value));
    digit_t x_digit = x->digit(0);
    if (x_digit > abs_value) return AbsoluteGreater(x_sign);
    if (x_digit < abs_value) return AbsoluteLess(x_sign);
    return ComparisonResult::kEqual;
  }
  DCHECK(IsHeapNumber(*y));
  double value = Cast<HeapNumber>(y)->value();
  return CompareToDouble(x, value);
}

ComparisonResult BigInt::CompareToDouble(DirectHandle<BigInt> x, double y) {
  if (std::isnan(y)) return ComparisonResult::kUndefined;
  if (y == V8_INFINITY) return ComparisonResult::kLessThan;
  if (y == -V8_INFINITY) return ComparisonResult::kGreaterThan;
  bool x_sign = x->sign();
  // Note that this is different from the double's sign bit for -0. That's
  // intentional because -0 must be treated like 0.
  bool y_sign = (y < 0);
  if (x_sign != y_sign) return UnequalSign(x_sign);
  if (y == 0) {
    DCHECK(!x_sign);
    return x->is_zero() ? ComparisonResult::kEqual
                        : ComparisonResult::kGreaterThan;
  }
  if (x->is_zero()) {
    DCHECK(!y_sign);
    return ComparisonResult::kLessThan;
  }
  uint64_t double_bits = base::bit_cast<uint64_t>(y);
  int32_t raw_exponent =
      static_cast<int32_t>(double_bits >>
                           base::Double::kPhysicalSignificandSize) &
      0x7FF;
  uint64_t mantissa = double_bits & base::Double::kSignificandMask;
  // Non-finite doubles are handled above.
  DCHECK_NE(raw_exponent, 0x7FF);
  int32_t exponent = raw_exponent - 0x3FF;
  if (exponent < 0) {
    // The absolute value of the double is less than 1. Only 0n has an
    // absolute value smaller than that, but we've already covered that case.
    DCHECK(!x->is_zero());
    return AbsoluteGreater(x_sign);
  }
  uint32_t x_length = x->length();
  digit_t x_msd = x->digit(x_length - 1);
  uint32_t msd_leading_zeros = base::bits::CountLeadingZeros(x_msd);
  uint32_t x_bitlength = x_length * kDigitBits - msd_leading_zeros;
  uint32_t y_bitlength = exponent + 1;
  if (x_bitlength < y_bitlength) return AbsoluteLess(x_sign);
  if (x_bitlength > y_bitlength) return AbsoluteGreater(x_sign);

  // At this point, we know that signs and bit lengths (i.e. position of
  // the most significant bit in exponent-free representation) are identical.
  // {x} is not zero, {y} is finite and not denormal.
  // Now we virtually convert the double to an integer by shifting its
  // mantissa according to its exponent, so it will align with the BigInt {x},
  // and then we compare them bit for bit until we find a difference or the
  // least significant bit.
  //                    <----- 52 ------> <-- virtual trailing zeroes -->
  // y / mantissa:     1yyyyyyyyyyyyyyyyy 0000000000000000000000000000000
  // x / digits:    0001xxxx xxxxxxxx xxxxxxxx ...
  //                    <-->          <------>
  //              msd_topbit         kDigitBits
  //
  mantissa |= base::Double::kHiddenBit;
  const uint32_t kMantissaTopBit = 52;  // 0-indexed.
  // 0-indexed position of {x}'s most significant bit within the {msd}.
  uint32_t msd_topbit = kDigitBits - 1 - msd_leading_zeros;
  DCHECK_EQ(msd_topbit, (x_bitlength - 1) % kDigitBits);
  // Shifted chunk of {mantissa} for comparing with {digit}.
  digit_t compare_mantissa;
  // Number of unprocessed bits in {mantissa}. We'll keep them shifted to
  // the left (i.e. most significant part) of the underlying uint64_t.
  uint32_t remaining_mantissa_bits = 0;

  // First, compare the most significant digit against the beginning of
  // the mantissa.
  if (msd_topbit < kMantissaTopBit) {
    remaining_mantissa_bits = (kMantissaTopBit - msd_topbit);
    compare_mantissa = mantissa >> remaining_mantissa_bits;
    mantissa = mantissa << (64 - remaining_mantissa_bits);
  } else {
    DCHECK_GE(msd_topbit, kMantissaTopBit);
    compare_mantissa = mantissa << (msd_topbit - kMantissaTopBit);
    mantissa = 0;
  }
  if (x_msd > compare_mantissa) return AbsoluteGreater(x_sign);
  if (x_msd < compare_mantissa) return AbsoluteLess(x_sign);

  // Then, compare additional digits against any remaining mantissa bits.
  static_assert(BigInt::kMaxLength < kMaxInt);
  for (int32_t digit_index = x_length - 2; digit_index >= 0; digit_index--) {
    if (remaining_mantissa_bits > 0) {
      remaining_mantissa_bits -= kDigitBits;
      if (sizeof(mantissa) != sizeof(x_msd)) {
        compare_mantissa = mantissa >> (64 - kDigitBits);
        // "& 63" to appease compilers. kDigitBits is 32 here anyway.
        mantissa = mantissa << (kDigitBits & 63);
      } else {
        compare_mantissa = mantissa;
        mantissa = 0;
      }
    } else {
      compare_mantissa = 0;
    }
    digit_t digit = x->digit(digit_index);
    if (digit > compare_mantissa) return AbsoluteGreater(x_sign);
    if (digit < compare_mantissa) return AbsoluteLess(x_sign);
  }

  // Integer parts are equal; check whether {y} has a fractional part.
  if (mantissa != 0) {
    DCHECK_GT(remaining_mantissa_bits, 0);
    return AbsoluteLess(x_sign);
  }
  return ComparisonResult::kEqual;
}

namespace {

void RightTrimString(Isolate* isolate, DirectHandle<SeqOneByteString> string,
                     int chars_allocated, int chars_written) {
  DCHECK_LE(chars_written, chars_allocated);
  if (chars_written == chars_allocated) return;
  int string_size =
      ALIGN_TO_ALLOCATION_ALIGNMENT(SeqOneByteString::SizeFor(chars_allocated));
  int needed_size =
      ALIGN_TO_ALLOCATION_ALIGNMENT(SeqOneByteString::SizeFor(chars_written));
  if (needed_size < string_size && !isolate->heap()->IsLargeObject(*string)) {
    isolate->heap()->NotifyObjectSizeChange(*string, string_size, needed_size,
                                            ClearRecordedSlots::kNo);
  }
  string->set_length(chars_written, kReleaseStore);
}

}  // namespace

MaybeHandle<String> BigInt::ToString(Isolate* isolate,
                                     DirectHandle<BigInt> bigint, int radix,
                                     ShouldThrow should_throw) {
  if (bigint->is_zero()) {
    return isolate->factory()->zero_string();
  }
  const bool sign = bigint->sign();
  uint32_t chars_allocated;
  uint32_t chars_written;
  Handle<SeqOneByteString> result;
  if (bigint->length() == 1 && radix == 10) {
    // Fast path for the most common case, to avoid call/
"""


```