Response:
The user wants a summary of the provided C++ header file, specifically `v8/src/execution/arm64/simulator-arm64.h`.

Here's a breakdown of the request and how to approach it:

1. **Identify the core functionality:** The filename and the initial comments indicate this file defines a simulator for the ARM64 architecture within the V8 JavaScript engine.

2. **Examine the included headers:** These provide clues about the file's dependencies and scope. We see headers related to ARM64 assembly, code generation, decoding, and a generic simulator base.

3. **Analyze the classes and their members:**  The file defines several classes, each with specific responsibilities. We need to go through each class and summarize its purpose and key functionalities.

4. **Check for Torque relevance:** The prompt specifically asks about `.tq` files. This file is `.h`, so it's a standard C++ header, not a Torque source file. We should state this explicitly.

5. **Determine JavaScript relevance:**  Since this is a simulator *within* V8, it directly relates to how JavaScript code is executed on ARM64. We can illustrate this with a simple JavaScript example that the simulator would be responsible for running.

6. **Look for code logic and provide examples:**  The `FPRound` template function is a good example of code logic. We can provide hypothetical inputs and expected outputs to illustrate its behavior.

7. **Identify common programming errors:**  The use of `memcpy` and direct memory manipulation in `SimMemory` can lead to errors if not handled carefully. We can provide examples of such errors.

8. **Address the "part 1 of 4" instruction:** This is a summarization task for *this specific file*. We need to synthesize the information gathered into a concise summary.

**Pre-computation and Pre-analysis:**

* **`FPRound` function:** This is about floating-point rounding. Understanding IEEE 754 and rounding modes is helpful here.
* **`SimMemory` class:** This simulates memory access. It's crucial for the simulator to accurately model reads and writes.
* **`SimSystemRegister` class:** This represents system registers and their behavior, including read-as-zero, write-ignored bits.
* **`SimRegisterBase` and its specializations:**  These simulate general-purpose and vector registers, tracking writes.
* **`LogicVRegister` class:** This provides a higher-level interface for manipulating vector registers, including saturation and rounding logic.
* **`Simulator` class:** This is the main class, orchestrating the simulation. It handles instruction fetching, decoding, and execution, as well as debugging.

**Drafting the Summary:**

Based on the above analysis, we can start drafting the summary points, ensuring we cover all the requirements of the prompt.
```cpp
// Copyright 2013 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_EXECUTION_ARM64_SIMULATOR_ARM64_H_
#define V8_EXECUTION_ARM64_SIMULATOR_ARM64_H_

// globals.h defines USE_SIMULATOR.
#include "src/common/globals.h"

#if defined(USE_SIMULATOR)

#include <stdarg.h>

#include <vector>

#include "src/base/compiler-specific.h"
#include "src/codegen/arm64/assembler-arm64.h"
#include "src/codegen/arm64/decoder-arm64.h"
#include "src/codegen/assembler.h"
#include "src/diagnostics/arm64/disasm-arm64.h"
#include "src/execution/simulator-base.h"
#include "src/utils/allocation.h"
#include "src/utils/utils.h"

namespace v8 {
namespace internal {

// Assemble the specified IEEE-754 components into the target type and apply
// appropriate rounding.
//  sign:     0 = positive, 1 = negative
//  exponent: Unbiased IEEE-754 exponent.
//  mantissa: The mantissa of the input. The top bit (which is not encoded for
//            normal IEEE-754 values) must not be omitted. This bit has the
//            value 'pow(2, exponent)'.
//
// The input value is assumed to be a normalized value. That is, the input may
// not be infinity or NaN. If the source value is subnormal, it must be
// normalized before calling this function such that the highest set bit in the
// mantissa has the value 'pow(2, exponent)'.
//
// Callers should use FPRoundToFloat or FPRoundToDouble directly, rather than
// calling a templated FPRound.
template <class T, int ebits, int mbits>
T FPRound(int64_t sign, int64_t exponent, uint64_t mantissa,
          FPRounding round_mode) {
  static_assert((sizeof(T) * 8) >= (1 + ebits + mbits),
                "destination type T not large enough");
  static_assert(sizeof(T) <= sizeof(uint64_t),
                "maximum size of destination type T is 64 bits");
  static_assert(std::is_unsigned<T>::value,
                "destination type T must be unsigned");

  DCHECK((sign == 0) || (sign == 1));

  // Only FPTieEven and FPRoundOdd rounding modes are implemented.
  DCHECK((round_mode == FPTieEven) || (round_mode == FPRoundOdd));

  // Rounding can promote subnormals to normals, and normals to infinities. For
  // example, a double with exponent 127 (FLT_MAX_EXP) would appear to be
  // encodable as a float, but rounding based on the low-order mantissa bits
  // could make it overflow. With ties-to-even rounding, this value would become
  // an infinity.

  // ---- Rounding Method ----
  //
  // The exponent is irrelevant in the rounding operation, so we treat the
  // lowest-order bit that will fit into the result ('onebit') as having
  // the value '1'. Similarly, the highest-order bit that won't fit into
  // the result ('halfbit') has the value '0.5'. The 'point' sits between
  // 'onebit' and 'halfbit':
  //
  //            These bits fit into the result.
  //               |---------------------|
  //  mantissa = 0bxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  //                                     ||
  //                                    / |
  //                                   /  halfbit
  //                               onebit
  //
  // For subnormal outputs, the range of representable bits is smaller and
  // the position of onebit and halfbit depends on the exponent of the
  // input, but the method is otherwise similar.
  //
  //   onebit(frac)
  //     |
  //     | halfbit(frac)          halfbit(adjusted)
  //     | /                      /
  //     | |                      |
  //  0b00.0 (exact)      -> 0b00.0 (exact)                    -> 0b00
  //  0b00.0...           -> 0b00.0...                         -> 0b00
  //  0b00.1 (exact)      -> 0b00.0111..111                    -> 0b00
  //  0b00.1...           -> 0b00.1...                         -> 0b01
  //  0b01.0 (exact)      -> 0b01.0 (exact)                    -> 0b01
  //  0b01.0...           -> 0b01.0...                         -> 0b01
  //  0b01.1 (exact)      -> 0b01.1 (exact)                    -> 0b10
  //  0b01.1...           -> 0b01.1...                         -> 0b10
  //  0b10.0 (exact)      -> 0b10.0 (exact)                    -> 0b10
  //  0b10.0...           -> 0b10.0...                         -> 0b10
  //  0b10.1 (exact)      -> 0b10.0111..111                    -> 0b10
  //  0b10.1...           -> 0b10.1...                         -> 0b11
  //  0b11.0 (exact)      -> 0b11.0 (exact)                    -> 0b11
  //  ...                   /             |                      /   |
  //                       /              |                     /    |
  //                                                           /     |
  // adjusted = frac - (halfbit(mantissa) & ~onebit(frac));   /      |
  //
  //                   mantissa = (mantissa >> shift) + halfbit(adjusted);

  const int mantissa_offset = 0;
  const int exponent_offset = mantissa_offset + mbits;
  const int sign_offset = exponent_offset + ebits;
  DCHECK_EQ(sign_offset, static_cast<int>(sizeof(T) * 8 - 1));

  // Bail out early for zero inputs.
  if (mantissa == 0) {
    return static_cast<T>(sign << sign_offset);
  }

  // If all bits in the exponent are set, the value is infinite or NaN.
  // This is true for all binary IEEE-754 formats.
  const int infinite_exponent = (1 << ebits) - 1;
  const int max_normal_exponent = infinite_exponent - 1;

  // Apply the exponent bias to encode it for the result. Doing this early makes
  // it easy to detect values that will be infinite or subnormal.
  exponent += max_normal_exponent >> 1;

  if (exponent > max_normal_exponent) {
    // Overflow: the input is too large for the result type to represent.
    if (round_mode == FPTieEven) {
      // FPTieEven rounding mode handles overflows using infinities.
      exponent = infinite_exponent;
      mantissa = 0;
    } else {
      DCHECK_EQ(round_mode, FPRoundOdd);
      // FPRoundOdd rounding mode handles overflows using the largest magnitude
      // normal number.
      exponent = max_normal_exponent;
      mantissa = (UINT64_C(1) << exponent_offset) - 1;
    }
    return static_cast<T>((sign << sign_offset) |
                          (exponent << exponent_offset) |
                          (mantissa << mantissa_offset));
  }

  // Calculate the shift required to move the top mantissa bit to the proper
  // place in the destination type.
  const int highest_significant_bit = 63 - CountLeadingZeros(mantissa, 64);
  int shift = highest_significant_bit - mbits;

  if (exponent <= 0) {
    // The output will be subnormal (before rounding).
    // For subnormal outputs, the shift must be adjusted by the exponent. The +1
    // is necessary because the exponent of a subnormal value (encoded as 0) is
    // the same as the exponent of the smallest normal value (encoded as 1).
    shift += -exponent + 1;

    // Handle inputs that would produce a zero output.
    //
    // Shifts higher than highest_significant_bit+1 will always produce a zero
    // result. A shift of exactly highest_significant_bit+1 might produce a
    // non-zero result after rounding.
    if (shift > (highest_significant_bit + 1)) {
      if (round_mode == FPTieEven) {
        // The result will always be +/-0.0.
        return static_cast<T>(sign << sign_offset);
      } else {
        DCHECK_EQ(round_mode, FPRoundOdd);
        DCHECK_NE(mantissa, 0U);
        // For FPRoundOdd, if the mantissa is too small to represent and
        // non-zero return the next "odd" value.
        return static_cast<T>((sign << sign_offset) | 1);
      }
    }

    // Properly encode the exponent for a subnormal output.
    exponent = 0;
  } else {
    // Clear the topmost mantissa bit, since this is not encoded in IEEE-754
    // normal values.
    mantissa &= ~(UINT64_C(1) << highest_significant_bit);
  }

  if (shift > 0) {
    if (round_mode == FPTieEven) {
      // We have to shift the mantissa to the right. Some precision is lost, so
      // we need to apply rounding.
      uint64_t onebit_mantissa = (mantissa >> (shift)) & 1;
      uint64_t halfbit_mantissa = (mantissa >> (shift - 1)) & 1;
      uint64_t adjustment = (halfbit_mantissa & ~onebit_mantissa);
      uint64_t adjusted = mantissa - adjustment;
      T halfbit_adjusted = (adjusted >> (shift - 1)) & 1;

      T result =
          static_cast<T>((sign << sign_offset) | (exponent << exponent_offset) |
                         ((mantissa >> shift) << mantissa_offset));

      // A very large mantissa can overflow during rounding. If this happens,
      // the exponent should be incremented and the mantissa set to 1.0
      // (encoded as 0). Applying halfbit_adjusted after assembling the float
      // has the nice side-effect that this case is handled for free.
      //
      // This also handles cases where a very large finite value overflows to
      // infinity, or where a very large subnormal value overflows to become
      // normal.
      return result + halfbit_adjusted;
    } else {
      DCHECK_EQ(round_mode, FPRoundOdd);
      // If any bits at position halfbit or below are set, onebit (ie. the
      // bottom bit of the resulting mantissa) must be set.
      uint64_t fractional_bits = mantissa & ((UINT64_C(1) << shift) - 1);
      if (fractional_bits != 0) {
        mantissa |= UINT64_C(1) << shift;
      }

      return static_cast<T>((sign << sign_offset) |
                            (exponent << exponent_offset) |
                            ((mantissa >> shift) << mantissa_offset));
    }
  } else {
    // We have to shift the mantissa to the left (or not at all). The input
    // mantissa is exactly representable in the output mantissa, so apply no
    // rounding correction.
    return static_cast<T>((sign << sign_offset) |
                          (exponent << exponent_offset) |
                          ((mantissa << -shift) << mantissa_offset));
  }
}

class CachePage {
  // TODO(all): Simulate instruction cache.
};

// Representation of memory, with typed getters and setters for access.
class SimMemory {
 public:
  template <typename T>
  static T AddressUntag(T address) {
    // Cast the address using a C-style cast. A reinterpret_cast would be
    // appropriate, but it can't cast one integral type to another.
    uint64_t bits = (uint64_t)address;
    return (T)(bits & ~kAddressTagMask);
  }

  template <typename T, typename A>
  static T Read(A address) {
    T value;
    address = AddressUntag(address);
    DCHECK((sizeof(value) == 1) || (sizeof(value) == 2) ||
           (sizeof(value) == 4) || (sizeof(value) == 8) ||
           (sizeof(value) == 16));
    memcpy(&value, reinterpret_cast<const char*>(address), sizeof(value));
    return value;
  }

  template <typename T, typename A>
  static void Write(A address, T value) {
    address = AddressUntag(address);
    DCHECK((sizeof(value) == 1) || (sizeof(value) == 2) ||
           (sizeof(value) == 4) || (sizeof(value) == 8) ||
           (sizeof(value) == 16));
    memcpy(reinterpret_cast<char*>(address), &value, sizeof(value));
  }
};

// The proper way to initialize a simulated system register (such as NZCV) is as
// follows:
//  SimSystemRegister nzcv = SimSystemRegister::DefaultValueFor(NZCV);
class SimSystemRegister {
 public:
  // The default constructor represents a register which has no writable bits.
  // It is not possible to set its value to anything other than 0.
  SimSystemRegister() : value_(0), write_ignore_mask_(0xffffffff) {}

  uint32_t RawValue() const { return value_; }

  void SetRawValue(uint32_t new_value) {
    value_ = (value_ & write_ignore_mask_) | (new_value & ~write_ignore_mask_);
  }

  uint32_t Bits(int msb, int lsb) const {
    return unsigned_bitextract_32(msb, lsb, value_);
  }

  int32_t SignedBits(int msb, int lsb) const {
    return signed_bitextract_32(msb, lsb, value_);
  }

  void SetBits(int msb, int lsb, uint32_t bits);

  // Default system register values.
  static SimSystemRegister DefaultValueFor(SystemRegister id);

#define DEFINE_GETTER(Name, HighBit, LowBit, Func, Type)                 \
  Type Name() const { return static_cast<Type>(Func(HighBit, LowBit)); } \
  void Set##Name(Type bits) {                                            \
    SetBits(HighBit, LowBit, static_cast<Type>(bits));                   \
  }
#define DEFINE_WRITE_IGNORE_MASK(Name, Mask) \
  static const uint32_t Name##WriteIgnoreMask = ~static_cast<uint32_t>(Mask);
  SYSTEM_REGISTER_FIELDS_LIST(DEFINE_GETTER, DEFINE_WRITE_IGNORE_MASK)
#undef DEFINE_ZERO_BITS
#undef DEFINE_GETTER

 protected:
  // Most system registers only implement a few of the bits in the word. Other
  // bits are "read-as-zero, write-ignored". The write_ignore_mask argument
  // describes the bits which are not modifiable.
  SimSystemRegister(uint32_t value, uint32_t write_ignore_mask)
      : value_(value), write_ignore_mask_(write_ignore_mask) {}

  uint32_t value_;
  uint32_t write_ignore_mask_;
};

// Represent a register (r0-r31, v0-v31).
template <int kSizeInBytes>
class SimRegisterBase {
 public:
  template <typename T>
  void Set(T new_value) {
    static_assert(sizeof(new_value) <= kSizeInBytes,
                  "Size of new_value must be <= size of template type.");
    if (sizeof(new_value) < kSizeInBytes) {
      // All AArch64 registers are zero-extending.
      memset(value_ + sizeof(new_value), 0, kSizeInBytes - sizeof(new_value));
    }
    memcpy(&value_, &new_value, sizeof(T));
    NotifyRegisterWrite();
  }

  // Insert a typed value into a register, leaving the rest of the register
  // unchanged. The lane parameter indicates where in the register the value
  // should be inserted, in the range [ 0, sizeof(value_) / sizeof(T) ), where
  // 0 represents the least significant bits.
  template <typename T>
  void Insert(int lane, T new_value) {
    DCHECK_GE(lane, 0);
    DCHECK_LE(sizeof(new_value) + (lane * sizeof(new_value)),
              static_cast<unsigned>(kSizeInBytes));
    memcpy(&value_[lane * sizeof(new_value)], &new_value, sizeof(new_value));
    NotifyRegisterWrite();
  }

  template <typename T>
  T Get(int lane = 0) const {
    T result;
    DCHECK_GE(lane, 0);
    DCHECK_LE(sizeof(result) + (lane * sizeof(result)),
              static_cast<unsigned>(kSizeInBytes));
    memcpy(&result, &value_[lane * sizeof(result)], sizeof(result));
    return result;
  }

  // TODO(all): Make this return a map of updated bytes, so that we can
  // highlight updated lanes for load-and-insert. (That never happens for scalar
  // code, but NEON has some instructions that can update individual lanes.)
  bool WrittenSinceLastLog() const { return written_since_last_log_; }

  void NotifyRegisterLogged() { written_since_last_log_ = false; }

 protected:
  uint8_t value_[kSizeInBytes];

  // Helpers to aid with register tracing.
  bool written_since_last_log_;

  void NotifyRegisterWrite() { written_since_last_log_ = true; }
};

using SimRegister = SimRegisterBase<kXRegSize>;   // r0-r31
using SimVRegister = SimRegisterBase<kQRegSize>;  // v0-v31

using sim_uint128_t = std::pair<uint64_t, uint64_t>;

// Representation of a vector register, with typed getters and setters for lanes
// and additional information to represent lane state.
class LogicVRegister {
 public:
  inline LogicVRegister(SimVRegister& other)  // NOLINT
      : register_(other) {
    for (unsigned i = 0; i < arraysize(saturated_); i++) {
      saturated_[i] = kNotSaturated;
    }
    for (unsigned i = 0; i < arraysize(round_); i++) {
      round_[i] = false;
    }
  }

  int64_t Int(VectorFormat vform, int index) const {
    int64_t element;
    switch (LaneSizeInBitsFromFormat(vform)) {
      case 8:
        element = register_.Get<int8_t>(index);
        break;
      case 16:
        element = register_.Get<int16_t>(index);
        break;
      case 32:
        element = register_.Get<int32_t>(index);
        break;
      case 64:
        element = register_.Get<int64_t>(index);
        break;
      default:
        UNREACHABLE();
        return 0;
    }
    return element;
  }

  uint64_t Uint(VectorFormat vform, int index) const {
    uint64_t element;
    switch (LaneSizeInBitsFromFormat(vform)) {
      case 8:
        element = register_.Get<uint8_t>(index);
        break;
      case 16:
        element = register_.Get<uint16_t>(index);
        break;
      case 32:
        element = register_.Get<uint32_t>(index);
        break;
      case 64:
        element = register_.Get<uint64_t>(index);
        break;
      default:
        UNREACHABLE();
        return 0;
    }
    return element;
  }

  uint64_t UintLeftJustified(VectorFormat vform, int index) const {
    return Uint(vform, index) << (64 - LaneSizeInBitsFromFormat(vform));
  }

  int64_t IntLeftJustified(VectorFormat vform, int index) const {
    uint64_t value = UintLeftJustified(vform, index);
    int64_t result;
    memcpy(&result, &value, sizeof(result));
    return result;
  }

  void SetInt(VectorFormat vform, int index, int64_t value) const {
    switch (LaneSizeInBitsFromFormat(vform)) {
      case 8:
        register_.Insert(index, static_cast<int8_t>(value));
        break;
      case 16:
        register_.Insert(index, static_cast<int16_t>(value));
        break;
      case 32:
        register_.Insert(index, static_cast<int32_t>(value));
        break;
      case 64:
        register_.Insert(index, static_cast<int64_t>(value));
        break;
      default:
        UNREACHABLE();
        return;
    }
  }

  void SetIntArray(VectorFormat vform, const int64_t* src) const {
    ClearForWrite(vform);
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      SetInt(vform, i, src[i]);
    }
  }

  void SetUint(VectorFormat vform, int index, uint64_t value) const {
    switch (LaneSizeInBitsFromFormat(vform)) {
      case 8:
        register_.Insert(index, static_cast<uint8_t>(value));
        break;
      case 16:
        register_.Insert(index, static_cast<uint16_t>(value));
        break;
      case 32:
        register_.Insert(index, static_cast<uint32_t>(value));
        break;
      case 64:
        register_.Insert(index, static_cast<uint64_t>(value));
        break;
      default:
        UNREACHABLE();
        return;
    }
  }

  void SetUint(VectorFormat vform, int index, sim_uint128_t value) const {
    if (LaneSizeInBitsFromFormat(vform) <= 64) {
      SetUint(vform, index, value.second);
      return;
    }
    DCHECK((vform == kFormat1Q) && (index == 0));
    SetUint(kFormat2D, 0, value.second);
    SetUint(kFormat2D, 1, value.first);
  }

  void SetUintArray(VectorFormat vform, const uint64_t* src) const {
    ClearForWrite(vform);
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      SetUint(vform, i, src[i]);
    }
  }

  void ReadUintFromMem(VectorFormat vform, int index, uint64_t addr) const;

  void WriteUintToMem(VectorFormat vform, int index, uint64_t addr) const;

  template <typename T>
  T Float(int index) const {
    return register_.Get<T>(index);
  }

  template <typename T>
  void SetFloat(int index, T value) const {
    register_.Insert(index, value);
  }

  // When setting a result in a register of size less than Q, the top bits of
  // the Q register must be cleared.
  void ClearForWrite(VectorFormat vform) const {
    unsigned size = RegisterSizeInBytesFromFormat(vform);
    for (unsigned i = size; i < kQRegSize; i++) {
      SetUint(kFormat16B, i, 0);
    }
  }

  // Saturation state for each lane of a vector.
  enum Saturation {
    kNotSaturated = 0,
    kSignedSatPositive = 1 << 0,
    kSignedSatNegative = 1 << 1,
    kSignedSatMask = kSignedSatPositive | kSignedSatNegative,
    kSignedSatUndefined = kSignedSatMask,
    kUnsignedSatPositive = 1 << 2,
    kUnsignedSatNegative = 1 << 3,
    kUnsignedSatMask = kUnsignedSatPositive | kUnsignedSatNegative,
    kUnsignedSatUndefined = kUnsignedSatMask
  };

  // Getters for saturation state.
  Saturation GetSignedSaturation(int index) {
    return static_cast<Saturation>(saturated_[index] & kSignedSatMask);
  }

  Saturation GetUnsignedSaturation(int index) {
    return static_cast<Saturation>(saturated_[index] & kUnsignedSatMask);
  }

  // Setters for saturation state.
  void ClearSat(int index) { saturated_[index] = kNotSaturated; }

  void SetSignedSat(int index, bool positive) {
    SetSatFlag(index, positive ? kSignedSatPositive : kSignedSatNegative);
  }

  void SetUnsignedSat(int index, bool positive) {
    SetSatFlag(index, positive ? kUnsignedSatPositive : kUnsignedSatNegative);
  }

  void SetSatFlag(int index, Saturation sat) {
    saturated_[index] = static_cast<Saturation>(saturated_[index] | sat);
    DCHECK_NE(sat & kUnsignedSatMask, kUnsignedSatUndefined);
    DCHECK_NE(sat & kSignedSatMask, kSignedSatUndefined);
  }

  // Saturate lanes of a vector based on saturation state.
  LogicVRegister& SignedSaturate(VectorFormat vform) {
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      Saturation sat = GetSignedSaturation(i);
      if (sat == kSignedSatPositive) {
        SetInt(vform, i, MaxIntFromFormat(vform));
      } else if (sat == kSignedSatNegative) {
        SetInt(vform, i, MinIntFromFormat(vform));
      }
    }
    return *this;
  }

  LogicVRegister& UnsignedSaturate(VectorFormat vform) {
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      Saturation sat = GetUnsignedSaturation(i);
      if (sat == kUnsignedSatPositive) {
        SetUint(vform, i, MaxUintFromFormat(vform));
      } else if (sat == kUnsignedSatNegative) {
        SetUint(vform, i, 0);
      }
    }
    return *this;
  }

  // Getter for rounding state.
  bool GetRounding(int index) { return round_[index]; }

  // Setter for rounding state.
  void SetRounding(int index, bool round) { round_[index] = round; }

  // Round lanes of a vector based on rounding state.
  LogicVRegister& Round(VectorFormat vform) {
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      SetUint(vform, i, Uint(vform, i) + (GetRounding(i) ? 1 : 0));
    }
    return *this;
  }

  // Unsigned halve lanes of a vector, and use the saturation state to set the
  // top bit.
  LogicVRegister& Uhalve(VectorFormat vform) {
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      uint64_t val = Uint(vform, i);
      SetRounding(i, (val & 1) == 1);
      val >>= 1;
      if (GetUnsignedSaturation(i) != kNotSaturated) {
        // If the operation causes unsigned saturation, the bit shifted into the
        // most significant bit must be set.
        val |= (MaxUintFromFormat(vform) >> 1) + 1;
      }
      SetInt(vform, i, val);
    }
    return *this;
  }

  // Signed halve lanes of a vector, and use the carry state to set the top bit.
  LogicVRegister& Halve(VectorFormat vform) {
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      int64_t val = Int(vform, i);
      SetRounding(i, (val & 1) == 1);
      val >>= 1;
      if (GetSignedSaturation(i) != kNotSaturated) {
        // If the operation causes signed saturation, the sign bit must be
        // inverted.
        val ^= (MaxUintFromFormat(vform) >> 1) + 1;
      }
      SetInt(vform, i, val);
    }
    return *this;
  }

  bool Is(const LogicVRegister& r) const { return &register_ == &r.register_; }

 private:
  SimVRegister& register_;

  // Allocate one saturation state entry per lane; largest register is type Q,
  // and lanes can be a minimum of one byte wide.
  Saturation saturated_[kQRegSize];

  // Allocate one rounding state entry per lane.
  bool round_[kQRegSize];
};

// Using multiple inheritance here is permitted because {DecoderVisitor} is a
// pure interface class with only pure virtual methods.
class Simulator : public DecoderVisitor, public SimulatorBase {
 public:
  static void SetRedirectInstruction(Instruction* instruction);
  static bool ICacheMatch(void* one, void* two) { return false; }
  static void FlushICache(base::CustomMatcherHashMap* i_cache, void* start,
                          size_t size) {
    USE(i_cache);
    USE(start);
    USE(size);
  }

  V8_EXPORT_PRIVATE explicit Simulator(
      Decoder<DispatchingDecoderVisitor>* decoder, Isolate* isolate = nullptr,
      FILE* stream = stderr);
  Simulator();
  V8_EXPORT_PRIVATE ~Simulator();

  // System functions.

  V8_EXPORT_PRIVATE static Simulator* current(v8::internal::Isolate* isolate);

  // A wrapper class that stores an argument for one of the above
Prompt: 
```
这是目录为v8/src/execution/arm64/simulator-arm64.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/arm64/simulator-arm64.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2013 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_EXECUTION_ARM64_SIMULATOR_ARM64_H_
#define V8_EXECUTION_ARM64_SIMULATOR_ARM64_H_

// globals.h defines USE_SIMULATOR.
#include "src/common/globals.h"

#if defined(USE_SIMULATOR)

#include <stdarg.h>

#include <vector>

#include "src/base/compiler-specific.h"
#include "src/codegen/arm64/assembler-arm64.h"
#include "src/codegen/arm64/decoder-arm64.h"
#include "src/codegen/assembler.h"
#include "src/diagnostics/arm64/disasm-arm64.h"
#include "src/execution/simulator-base.h"
#include "src/utils/allocation.h"
#include "src/utils/utils.h"

namespace v8 {
namespace internal {

// Assemble the specified IEEE-754 components into the target type and apply
// appropriate rounding.
//  sign:     0 = positive, 1 = negative
//  exponent: Unbiased IEEE-754 exponent.
//  mantissa: The mantissa of the input. The top bit (which is not encoded for
//            normal IEEE-754 values) must not be omitted. This bit has the
//            value 'pow(2, exponent)'.
//
// The input value is assumed to be a normalized value. That is, the input may
// not be infinity or NaN. If the source value is subnormal, it must be
// normalized before calling this function such that the highest set bit in the
// mantissa has the value 'pow(2, exponent)'.
//
// Callers should use FPRoundToFloat or FPRoundToDouble directly, rather than
// calling a templated FPRound.
template <class T, int ebits, int mbits>
T FPRound(int64_t sign, int64_t exponent, uint64_t mantissa,
          FPRounding round_mode) {
  static_assert((sizeof(T) * 8) >= (1 + ebits + mbits),
                "destination type T not large enough");
  static_assert(sizeof(T) <= sizeof(uint64_t),
                "maximum size of destination type T is 64 bits");
  static_assert(std::is_unsigned<T>::value,
                "destination type T must be unsigned");

  DCHECK((sign == 0) || (sign == 1));

  // Only FPTieEven and FPRoundOdd rounding modes are implemented.
  DCHECK((round_mode == FPTieEven) || (round_mode == FPRoundOdd));

  // Rounding can promote subnormals to normals, and normals to infinities. For
  // example, a double with exponent 127 (FLT_MAX_EXP) would appear to be
  // encodable as a float, but rounding based on the low-order mantissa bits
  // could make it overflow. With ties-to-even rounding, this value would become
  // an infinity.

  // ---- Rounding Method ----
  //
  // The exponent is irrelevant in the rounding operation, so we treat the
  // lowest-order bit that will fit into the result ('onebit') as having
  // the value '1'. Similarly, the highest-order bit that won't fit into
  // the result ('halfbit') has the value '0.5'. The 'point' sits between
  // 'onebit' and 'halfbit':
  //
  //            These bits fit into the result.
  //               |---------------------|
  //  mantissa = 0bxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  //                                     ||
  //                                    / |
  //                                   /  halfbit
  //                               onebit
  //
  // For subnormal outputs, the range of representable bits is smaller and
  // the position of onebit and halfbit depends on the exponent of the
  // input, but the method is otherwise similar.
  //
  //   onebit(frac)
  //     |
  //     | halfbit(frac)          halfbit(adjusted)
  //     | /                      /
  //     | |                      |
  //  0b00.0 (exact)      -> 0b00.0 (exact)                    -> 0b00
  //  0b00.0...           -> 0b00.0...                         -> 0b00
  //  0b00.1 (exact)      -> 0b00.0111..111                    -> 0b00
  //  0b00.1...           -> 0b00.1...                         -> 0b01
  //  0b01.0 (exact)      -> 0b01.0 (exact)                    -> 0b01
  //  0b01.0...           -> 0b01.0...                         -> 0b01
  //  0b01.1 (exact)      -> 0b01.1 (exact)                    -> 0b10
  //  0b01.1...           -> 0b01.1...                         -> 0b10
  //  0b10.0 (exact)      -> 0b10.0 (exact)                    -> 0b10
  //  0b10.0...           -> 0b10.0...                         -> 0b10
  //  0b10.1 (exact)      -> 0b10.0111..111                    -> 0b10
  //  0b10.1...           -> 0b10.1...                         -> 0b11
  //  0b11.0 (exact)      -> 0b11.0 (exact)                    -> 0b11
  //  ...                   /             |                      /   |
  //                       /              |                     /    |
  //                                                           /     |
  // adjusted = frac - (halfbit(mantissa) & ~onebit(frac));   /      |
  //
  //                   mantissa = (mantissa >> shift) + halfbit(adjusted);

  const int mantissa_offset = 0;
  const int exponent_offset = mantissa_offset + mbits;
  const int sign_offset = exponent_offset + ebits;
  DCHECK_EQ(sign_offset, static_cast<int>(sizeof(T) * 8 - 1));

  // Bail out early for zero inputs.
  if (mantissa == 0) {
    return static_cast<T>(sign << sign_offset);
  }

  // If all bits in the exponent are set, the value is infinite or NaN.
  // This is true for all binary IEEE-754 formats.
  const int infinite_exponent = (1 << ebits) - 1;
  const int max_normal_exponent = infinite_exponent - 1;

  // Apply the exponent bias to encode it for the result. Doing this early makes
  // it easy to detect values that will be infinite or subnormal.
  exponent += max_normal_exponent >> 1;

  if (exponent > max_normal_exponent) {
    // Overflow: the input is too large for the result type to represent.
    if (round_mode == FPTieEven) {
      // FPTieEven rounding mode handles overflows using infinities.
      exponent = infinite_exponent;
      mantissa = 0;
    } else {
      DCHECK_EQ(round_mode, FPRoundOdd);
      // FPRoundOdd rounding mode handles overflows using the largest magnitude
      // normal number.
      exponent = max_normal_exponent;
      mantissa = (UINT64_C(1) << exponent_offset) - 1;
    }
    return static_cast<T>((sign << sign_offset) |
                          (exponent << exponent_offset) |
                          (mantissa << mantissa_offset));
  }

  // Calculate the shift required to move the top mantissa bit to the proper
  // place in the destination type.
  const int highest_significant_bit = 63 - CountLeadingZeros(mantissa, 64);
  int shift = highest_significant_bit - mbits;

  if (exponent <= 0) {
    // The output will be subnormal (before rounding).
    // For subnormal outputs, the shift must be adjusted by the exponent. The +1
    // is necessary because the exponent of a subnormal value (encoded as 0) is
    // the same as the exponent of the smallest normal value (encoded as 1).
    shift += -exponent + 1;

    // Handle inputs that would produce a zero output.
    //
    // Shifts higher than highest_significant_bit+1 will always produce a zero
    // result. A shift of exactly highest_significant_bit+1 might produce a
    // non-zero result after rounding.
    if (shift > (highest_significant_bit + 1)) {
      if (round_mode == FPTieEven) {
        // The result will always be +/-0.0.
        return static_cast<T>(sign << sign_offset);
      } else {
        DCHECK_EQ(round_mode, FPRoundOdd);
        DCHECK_NE(mantissa, 0U);
        // For FPRoundOdd, if the mantissa is too small to represent and
        // non-zero return the next "odd" value.
        return static_cast<T>((sign << sign_offset) | 1);
      }
    }

    // Properly encode the exponent for a subnormal output.
    exponent = 0;
  } else {
    // Clear the topmost mantissa bit, since this is not encoded in IEEE-754
    // normal values.
    mantissa &= ~(UINT64_C(1) << highest_significant_bit);
  }

  if (shift > 0) {
    if (round_mode == FPTieEven) {
      // We have to shift the mantissa to the right. Some precision is lost, so
      // we need to apply rounding.
      uint64_t onebit_mantissa = (mantissa >> (shift)) & 1;
      uint64_t halfbit_mantissa = (mantissa >> (shift - 1)) & 1;
      uint64_t adjustment = (halfbit_mantissa & ~onebit_mantissa);
      uint64_t adjusted = mantissa - adjustment;
      T halfbit_adjusted = (adjusted >> (shift - 1)) & 1;

      T result =
          static_cast<T>((sign << sign_offset) | (exponent << exponent_offset) |
                         ((mantissa >> shift) << mantissa_offset));

      // A very large mantissa can overflow during rounding. If this happens,
      // the exponent should be incremented and the mantissa set to 1.0
      // (encoded as 0). Applying halfbit_adjusted after assembling the float
      // has the nice side-effect that this case is handled for free.
      //
      // This also handles cases where a very large finite value overflows to
      // infinity, or where a very large subnormal value overflows to become
      // normal.
      return result + halfbit_adjusted;
    } else {
      DCHECK_EQ(round_mode, FPRoundOdd);
      // If any bits at position halfbit or below are set, onebit (ie. the
      // bottom bit of the resulting mantissa) must be set.
      uint64_t fractional_bits = mantissa & ((UINT64_C(1) << shift) - 1);
      if (fractional_bits != 0) {
        mantissa |= UINT64_C(1) << shift;
      }

      return static_cast<T>((sign << sign_offset) |
                            (exponent << exponent_offset) |
                            ((mantissa >> shift) << mantissa_offset));
    }
  } else {
    // We have to shift the mantissa to the left (or not at all). The input
    // mantissa is exactly representable in the output mantissa, so apply no
    // rounding correction.
    return static_cast<T>((sign << sign_offset) |
                          (exponent << exponent_offset) |
                          ((mantissa << -shift) << mantissa_offset));
  }
}

class CachePage {
  // TODO(all): Simulate instruction cache.
};

// Representation of memory, with typed getters and setters for access.
class SimMemory {
 public:
  template <typename T>
  static T AddressUntag(T address) {
    // Cast the address using a C-style cast. A reinterpret_cast would be
    // appropriate, but it can't cast one integral type to another.
    uint64_t bits = (uint64_t)address;
    return (T)(bits & ~kAddressTagMask);
  }

  template <typename T, typename A>
  static T Read(A address) {
    T value;
    address = AddressUntag(address);
    DCHECK((sizeof(value) == 1) || (sizeof(value) == 2) ||
           (sizeof(value) == 4) || (sizeof(value) == 8) ||
           (sizeof(value) == 16));
    memcpy(&value, reinterpret_cast<const char*>(address), sizeof(value));
    return value;
  }

  template <typename T, typename A>
  static void Write(A address, T value) {
    address = AddressUntag(address);
    DCHECK((sizeof(value) == 1) || (sizeof(value) == 2) ||
           (sizeof(value) == 4) || (sizeof(value) == 8) ||
           (sizeof(value) == 16));
    memcpy(reinterpret_cast<char*>(address), &value, sizeof(value));
  }
};

// The proper way to initialize a simulated system register (such as NZCV) is as
// follows:
//  SimSystemRegister nzcv = SimSystemRegister::DefaultValueFor(NZCV);
class SimSystemRegister {
 public:
  // The default constructor represents a register which has no writable bits.
  // It is not possible to set its value to anything other than 0.
  SimSystemRegister() : value_(0), write_ignore_mask_(0xffffffff) {}

  uint32_t RawValue() const { return value_; }

  void SetRawValue(uint32_t new_value) {
    value_ = (value_ & write_ignore_mask_) | (new_value & ~write_ignore_mask_);
  }

  uint32_t Bits(int msb, int lsb) const {
    return unsigned_bitextract_32(msb, lsb, value_);
  }

  int32_t SignedBits(int msb, int lsb) const {
    return signed_bitextract_32(msb, lsb, value_);
  }

  void SetBits(int msb, int lsb, uint32_t bits);

  // Default system register values.
  static SimSystemRegister DefaultValueFor(SystemRegister id);

#define DEFINE_GETTER(Name, HighBit, LowBit, Func, Type)                 \
  Type Name() const { return static_cast<Type>(Func(HighBit, LowBit)); } \
  void Set##Name(Type bits) {                                            \
    SetBits(HighBit, LowBit, static_cast<Type>(bits));                   \
  }
#define DEFINE_WRITE_IGNORE_MASK(Name, Mask) \
  static const uint32_t Name##WriteIgnoreMask = ~static_cast<uint32_t>(Mask);
  SYSTEM_REGISTER_FIELDS_LIST(DEFINE_GETTER, DEFINE_WRITE_IGNORE_MASK)
#undef DEFINE_ZERO_BITS
#undef DEFINE_GETTER

 protected:
  // Most system registers only implement a few of the bits in the word. Other
  // bits are "read-as-zero, write-ignored". The write_ignore_mask argument
  // describes the bits which are not modifiable.
  SimSystemRegister(uint32_t value, uint32_t write_ignore_mask)
      : value_(value), write_ignore_mask_(write_ignore_mask) {}

  uint32_t value_;
  uint32_t write_ignore_mask_;
};

// Represent a register (r0-r31, v0-v31).
template <int kSizeInBytes>
class SimRegisterBase {
 public:
  template <typename T>
  void Set(T new_value) {
    static_assert(sizeof(new_value) <= kSizeInBytes,
                  "Size of new_value must be <= size of template type.");
    if (sizeof(new_value) < kSizeInBytes) {
      // All AArch64 registers are zero-extending.
      memset(value_ + sizeof(new_value), 0, kSizeInBytes - sizeof(new_value));
    }
    memcpy(&value_, &new_value, sizeof(T));
    NotifyRegisterWrite();
  }

  // Insert a typed value into a register, leaving the rest of the register
  // unchanged. The lane parameter indicates where in the register the value
  // should be inserted, in the range [ 0, sizeof(value_) / sizeof(T) ), where
  // 0 represents the least significant bits.
  template <typename T>
  void Insert(int lane, T new_value) {
    DCHECK_GE(lane, 0);
    DCHECK_LE(sizeof(new_value) + (lane * sizeof(new_value)),
              static_cast<unsigned>(kSizeInBytes));
    memcpy(&value_[lane * sizeof(new_value)], &new_value, sizeof(new_value));
    NotifyRegisterWrite();
  }

  template <typename T>
  T Get(int lane = 0) const {
    T result;
    DCHECK_GE(lane, 0);
    DCHECK_LE(sizeof(result) + (lane * sizeof(result)),
              static_cast<unsigned>(kSizeInBytes));
    memcpy(&result, &value_[lane * sizeof(result)], sizeof(result));
    return result;
  }

  // TODO(all): Make this return a map of updated bytes, so that we can
  // highlight updated lanes for load-and-insert. (That never happens for scalar
  // code, but NEON has some instructions that can update individual lanes.)
  bool WrittenSinceLastLog() const { return written_since_last_log_; }

  void NotifyRegisterLogged() { written_since_last_log_ = false; }

 protected:
  uint8_t value_[kSizeInBytes];

  // Helpers to aid with register tracing.
  bool written_since_last_log_;

  void NotifyRegisterWrite() { written_since_last_log_ = true; }
};

using SimRegister = SimRegisterBase<kXRegSize>;   // r0-r31
using SimVRegister = SimRegisterBase<kQRegSize>;  // v0-v31

using sim_uint128_t = std::pair<uint64_t, uint64_t>;

// Representation of a vector register, with typed getters and setters for lanes
// and additional information to represent lane state.
class LogicVRegister {
 public:
  inline LogicVRegister(SimVRegister& other)  // NOLINT
      : register_(other) {
    for (unsigned i = 0; i < arraysize(saturated_); i++) {
      saturated_[i] = kNotSaturated;
    }
    for (unsigned i = 0; i < arraysize(round_); i++) {
      round_[i] = false;
    }
  }

  int64_t Int(VectorFormat vform, int index) const {
    int64_t element;
    switch (LaneSizeInBitsFromFormat(vform)) {
      case 8:
        element = register_.Get<int8_t>(index);
        break;
      case 16:
        element = register_.Get<int16_t>(index);
        break;
      case 32:
        element = register_.Get<int32_t>(index);
        break;
      case 64:
        element = register_.Get<int64_t>(index);
        break;
      default:
        UNREACHABLE();
        return 0;
    }
    return element;
  }

  uint64_t Uint(VectorFormat vform, int index) const {
    uint64_t element;
    switch (LaneSizeInBitsFromFormat(vform)) {
      case 8:
        element = register_.Get<uint8_t>(index);
        break;
      case 16:
        element = register_.Get<uint16_t>(index);
        break;
      case 32:
        element = register_.Get<uint32_t>(index);
        break;
      case 64:
        element = register_.Get<uint64_t>(index);
        break;
      default:
        UNREACHABLE();
        return 0;
    }
    return element;
  }

  uint64_t UintLeftJustified(VectorFormat vform, int index) const {
    return Uint(vform, index) << (64 - LaneSizeInBitsFromFormat(vform));
  }

  int64_t IntLeftJustified(VectorFormat vform, int index) const {
    uint64_t value = UintLeftJustified(vform, index);
    int64_t result;
    memcpy(&result, &value, sizeof(result));
    return result;
  }

  void SetInt(VectorFormat vform, int index, int64_t value) const {
    switch (LaneSizeInBitsFromFormat(vform)) {
      case 8:
        register_.Insert(index, static_cast<int8_t>(value));
        break;
      case 16:
        register_.Insert(index, static_cast<int16_t>(value));
        break;
      case 32:
        register_.Insert(index, static_cast<int32_t>(value));
        break;
      case 64:
        register_.Insert(index, static_cast<int64_t>(value));
        break;
      default:
        UNREACHABLE();
        return;
    }
  }

  void SetIntArray(VectorFormat vform, const int64_t* src) const {
    ClearForWrite(vform);
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      SetInt(vform, i, src[i]);
    }
  }

  void SetUint(VectorFormat vform, int index, uint64_t value) const {
    switch (LaneSizeInBitsFromFormat(vform)) {
      case 8:
        register_.Insert(index, static_cast<uint8_t>(value));
        break;
      case 16:
        register_.Insert(index, static_cast<uint16_t>(value));
        break;
      case 32:
        register_.Insert(index, static_cast<uint32_t>(value));
        break;
      case 64:
        register_.Insert(index, static_cast<uint64_t>(value));
        break;
      default:
        UNREACHABLE();
        return;
    }
  }

  void SetUint(VectorFormat vform, int index, sim_uint128_t value) const {
    if (LaneSizeInBitsFromFormat(vform) <= 64) {
      SetUint(vform, index, value.second);
      return;
    }
    DCHECK((vform == kFormat1Q) && (index == 0));
    SetUint(kFormat2D, 0, value.second);
    SetUint(kFormat2D, 1, value.first);
  }

  void SetUintArray(VectorFormat vform, const uint64_t* src) const {
    ClearForWrite(vform);
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      SetUint(vform, i, src[i]);
    }
  }

  void ReadUintFromMem(VectorFormat vform, int index, uint64_t addr) const;

  void WriteUintToMem(VectorFormat vform, int index, uint64_t addr) const;

  template <typename T>
  T Float(int index) const {
    return register_.Get<T>(index);
  }

  template <typename T>
  void SetFloat(int index, T value) const {
    register_.Insert(index, value);
  }

  // When setting a result in a register of size less than Q, the top bits of
  // the Q register must be cleared.
  void ClearForWrite(VectorFormat vform) const {
    unsigned size = RegisterSizeInBytesFromFormat(vform);
    for (unsigned i = size; i < kQRegSize; i++) {
      SetUint(kFormat16B, i, 0);
    }
  }

  // Saturation state for each lane of a vector.
  enum Saturation {
    kNotSaturated = 0,
    kSignedSatPositive = 1 << 0,
    kSignedSatNegative = 1 << 1,
    kSignedSatMask = kSignedSatPositive | kSignedSatNegative,
    kSignedSatUndefined = kSignedSatMask,
    kUnsignedSatPositive = 1 << 2,
    kUnsignedSatNegative = 1 << 3,
    kUnsignedSatMask = kUnsignedSatPositive | kUnsignedSatNegative,
    kUnsignedSatUndefined = kUnsignedSatMask
  };

  // Getters for saturation state.
  Saturation GetSignedSaturation(int index) {
    return static_cast<Saturation>(saturated_[index] & kSignedSatMask);
  }

  Saturation GetUnsignedSaturation(int index) {
    return static_cast<Saturation>(saturated_[index] & kUnsignedSatMask);
  }

  // Setters for saturation state.
  void ClearSat(int index) { saturated_[index] = kNotSaturated; }

  void SetSignedSat(int index, bool positive) {
    SetSatFlag(index, positive ? kSignedSatPositive : kSignedSatNegative);
  }

  void SetUnsignedSat(int index, bool positive) {
    SetSatFlag(index, positive ? kUnsignedSatPositive : kUnsignedSatNegative);
  }

  void SetSatFlag(int index, Saturation sat) {
    saturated_[index] = static_cast<Saturation>(saturated_[index] | sat);
    DCHECK_NE(sat & kUnsignedSatMask, kUnsignedSatUndefined);
    DCHECK_NE(sat & kSignedSatMask, kSignedSatUndefined);
  }

  // Saturate lanes of a vector based on saturation state.
  LogicVRegister& SignedSaturate(VectorFormat vform) {
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      Saturation sat = GetSignedSaturation(i);
      if (sat == kSignedSatPositive) {
        SetInt(vform, i, MaxIntFromFormat(vform));
      } else if (sat == kSignedSatNegative) {
        SetInt(vform, i, MinIntFromFormat(vform));
      }
    }
    return *this;
  }

  LogicVRegister& UnsignedSaturate(VectorFormat vform) {
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      Saturation sat = GetUnsignedSaturation(i);
      if (sat == kUnsignedSatPositive) {
        SetUint(vform, i, MaxUintFromFormat(vform));
      } else if (sat == kUnsignedSatNegative) {
        SetUint(vform, i, 0);
      }
    }
    return *this;
  }

  // Getter for rounding state.
  bool GetRounding(int index) { return round_[index]; }

  // Setter for rounding state.
  void SetRounding(int index, bool round) { round_[index] = round; }

  // Round lanes of a vector based on rounding state.
  LogicVRegister& Round(VectorFormat vform) {
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      SetUint(vform, i, Uint(vform, i) + (GetRounding(i) ? 1 : 0));
    }
    return *this;
  }

  // Unsigned halve lanes of a vector, and use the saturation state to set the
  // top bit.
  LogicVRegister& Uhalve(VectorFormat vform) {
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      uint64_t val = Uint(vform, i);
      SetRounding(i, (val & 1) == 1);
      val >>= 1;
      if (GetUnsignedSaturation(i) != kNotSaturated) {
        // If the operation causes unsigned saturation, the bit shifted into the
        // most significant bit must be set.
        val |= (MaxUintFromFormat(vform) >> 1) + 1;
      }
      SetInt(vform, i, val);
    }
    return *this;
  }

  // Signed halve lanes of a vector, and use the carry state to set the top bit.
  LogicVRegister& Halve(VectorFormat vform) {
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      int64_t val = Int(vform, i);
      SetRounding(i, (val & 1) == 1);
      val >>= 1;
      if (GetSignedSaturation(i) != kNotSaturated) {
        // If the operation causes signed saturation, the sign bit must be
        // inverted.
        val ^= (MaxUintFromFormat(vform) >> 1) + 1;
      }
      SetInt(vform, i, val);
    }
    return *this;
  }

  bool Is(const LogicVRegister& r) const { return &register_ == &r.register_; }

 private:
  SimVRegister& register_;

  // Allocate one saturation state entry per lane; largest register is type Q,
  // and lanes can be a minimum of one byte wide.
  Saturation saturated_[kQRegSize];

  // Allocate one rounding state entry per lane.
  bool round_[kQRegSize];
};

// Using multiple inheritance here is permitted because {DecoderVisitor} is a
// pure interface class with only pure virtual methods.
class Simulator : public DecoderVisitor, public SimulatorBase {
 public:
  static void SetRedirectInstruction(Instruction* instruction);
  static bool ICacheMatch(void* one, void* two) { return false; }
  static void FlushICache(base::CustomMatcherHashMap* i_cache, void* start,
                          size_t size) {
    USE(i_cache);
    USE(start);
    USE(size);
  }

  V8_EXPORT_PRIVATE explicit Simulator(
      Decoder<DispatchingDecoderVisitor>* decoder, Isolate* isolate = nullptr,
      FILE* stream = stderr);
  Simulator();
  V8_EXPORT_PRIVATE ~Simulator();

  // System functions.

  V8_EXPORT_PRIVATE static Simulator* current(v8::internal::Isolate* isolate);

  // A wrapper class that stores an argument for one of the above Call
  // functions.
  //
  // Only arguments up to 64 bits in size are supported.
  class CallArgument {
   public:
    template <typename T>
    explicit CallArgument(T argument) {
      bits_ = 0;
      DCHECK(sizeof(argument) <= sizeof(bits_));
      memcpy(&bits_, &argument, sizeof(argument));
      type_ = X_ARG;
    }

    explicit CallArgument(double argument) {
      DCHECK(sizeof(argument) == sizeof(bits_));
      memcpy(&bits_, &argument, sizeof(argument));
      type_ = D_ARG;
    }

    explicit CallArgument(float argument) {
      // TODO(all): CallArgument(float) is untested, remove this check once
      //            tested.
      UNIMPLEMENTED();
      // Make the D register a NaN to try to trap errors if the callee expects a
      // double. If it expects a float, the callee should ignore the top word.
      DCHECK(sizeof(kFP64SignallingNaN) == sizeof(bits_));
      memcpy(&bits_, &kFP64SignallingNaN, sizeof(kFP64SignallingNaN));
      // Write the float payload to the S register.
      DCHECK(sizeof(argument) <= sizeof(bits_));
      memcpy(&bits_, &argument, sizeof(argument));
      type_ = D_ARG;
    }

    // This indicates the end of the arguments list, so that CallArgument
    // objects can be passed into varargs functions.
    static CallArgument End() { return CallArgument(); }

    int64_t bits() const { return bits_; }
    bool IsEnd() const { return type_ == NO_ARG; }
    bool IsX() const { return type_ == X_ARG; }
    bool IsD() const { return type_ == D_ARG; }

   private:
    enum CallArgumentType { X_ARG, D_ARG, NO_ARG };

    // All arguments are aligned to at least 64 bits and we don't support
    // passing bigger arguments, so the payload size can be fixed at 64 bits.
    int64_t bits_;
    CallArgumentType type_;

    CallArgument() { type_ = NO_ARG; }
  };

  // Call an arbitrary function taking an arbitrary number of arguments.
  template <typename Return, typename... Args>
  Return Call(Address entry, Args... args) {
    // Convert all arguments to CallArgument.
    CallArgument call_args[] = {CallArgument(args)..., CallArgument::End()};
    CallImpl(entry, call_args);
    return ReadReturn<Return>();
  }

  // Start the debugging command line.
  void Debug();

  // Executes a single debug command. Takes ownership of the command (so that it
  // can store it for repeat executions), and returns true if the debugger
  // should resume execution after this command completes.
  bool ExecDebugCommand(ArrayUniquePtr<char> command);

  bool GetValue(const char* desc, int64_t* value);

  bool PrintValue(const char* desc);

  // Push an address onto the JS stack.
  V8_EXPORT_PRIVATE uintptr_t PushAddress(uintptr_t address);

  // Pop an address from the JS stack.
  V8_EXPORT_PRIVATE uintptr_t PopAddress();

  // Accessor to the internal simulator stack area. Adds a safety
  // margin to prevent overflows (kAdditionalStackMargin).
  uintptr_t StackLimit(uintptr_t c_limit) const;
  // Return central stack view, without additional safety margins.
  // Users, for example wasm::StackMemory, can add their own.
  base::Vector<uint8_t> GetCentralStackView() const;

  V8_EXPORT_PRIVATE void ResetState();

  void DoRuntimeCall(Instruction* instr);

  // Run the simulator.
  static const Instruction* kEndOfSimAddress;
  void DecodeInstruction();
  void Run();
  V8_EXPORT_PRIVATE void RunFrom(Instruction* start);

  // Simulation helpers.
  template <typename T>
  void set_pc(T new_pc) {
    static_assert(sizeof(T) == sizeof(pc_));
    memcpy(&pc_, &new_pc, sizeof(T));
    pc_modified_ = true;
  }
  Instruction* pc() { return pc_; }

  void increment_pc() {
    if (!pc_modified_) {
      pc_ = pc_->following();
    }

    pc_modified_ = false;
  }

  virtual void Decode(Instruction* instr) { decoder_->Decode(instr); }

  // Branch Target Identification (BTI)
  //
  // Executing an instruction updates PSTATE.BTYPE, as described in the table
  // below. Execution of an instruction on a guarded page is allowed if either:
  // * PSTATE.BTYPE is 00, or
  // * it is a BTI or PACI[AB]SP instruction that accepts the current value of
  //   PSTATE.BTYPE (as described in the table below), or
  // * it is BRK or HLT instruction that causes some higher-priority exception.
  //
  //  --------------------------------------------------------------------------
  //  | Last-executed instruction    | Sets     | Accepted by                  |
  //  |                              | BTYPE to | BTI | BTI j | BTI c | BTI jc |
  //  --------------------------------------------------------------------------
  //  | - BR from an unguarded page. |          |     |       |       |        |
  //  | - BR from guarded page,      |          |     |       |       |        |
  //  |   to x16 or x17.             |    01    |     |   X   |   X   |   X    |
  //  --------------------------------------------------------------------------
  //  | BR from guarded page,        |          |     |       |       |        |
  //  | not to x16 or x17.           |    11    |     |   X   |       |   X    |
  //  --------------------------------------------------------------------------
  //  | BLR                          |    10    |     |       |   X   |   X    |
  //  --------------------------------------------------------------------------
  //  | Any other instruction        |          |     |       |       |        |
  //  |(including RET).              |    00    |  X  |   X   |   X   |   X    |
  //  --------------------------------------------------------------------------
  //
  // PACI[AB]SP is treated either like "BTI c" or "BTI jc", according to the
  // value of SCTLR_EL1.BT0. Details available in ARM DDI 0487E.a, D5-2580.

  enum BType {
    // Set when executing any instruction, except those cases listed below.
    DefaultBType = 0,

    // Set when an indirect branch is taken from an unguarded page, or from a
    // guarded page to ip0 or ip1 (x16 or x17), eg "br ip0".
    BranchFromUnguardedOrToIP = 1,

    // Set when an indirect branch and link (call) is taken, eg. "blr x0".
    BranchAndLink = 2,

    // Set when an indirect branch is taken from a guarded page to a register
    // that is not ip0 or ip1 (x16 or x17), eg, "br x0".
    BranchFromGuardedNotToIP = 3
  };

  BType btype() const { return btype_; }
  void ResetBType() { btype_ = DefaultBType; }
  void set_btype(BType btype) { btype_ = btype; }

  // Helper function to determine BType for branches.
  BType GetBTypeFromInstruction(const Instruction* instr) const;

  bool PcIsInGuardedPage() const { return guard_pages_; }
  void SetGuardedPages(bool guard_pages) { guard_pages_ = guard_pages; }

  void CheckBTypeForPAuth() {
    DCHECK(pc_->IsPAuth());
    Instr instr = pc_->Mask(SystemPAuthMask);
    // Only PACI[AB]SP allowed here, and we only support PACIBSP.
    CHECK(instr == PACIBSP);
    // Check BType allows PACI[AB]SP instructions.
    switch (btype()) {
      case BranchFromGuardedNotToIP:
        // This case depends on the value of SCTLR_EL1.BT0, which we assume
        // here to be set. This makes PACI[AB]SP behave like "BTI c",
        // disallowing its execution when BTYPE is BranchFromGuardedNotToIP
        // (0b11).
        FATAL("Executing PACIBSP with wrong BType.");
      case BranchFromUnguardedOrToIP:
      case BranchAndLink:
        break;
      case DefaultBType:
        UNREACHABLE();
    }
  }

  void CheckBTypeForBti() {
    DCHECK(pc_->IsBti());
    switch (pc_->ImmHint()) {
      case BTI_jc:
        break;
      case BTI: {
        DCHECK(btype() != DefaultBType);
        FATAL("Executing BTI with wrong BType (expected 0, got %d).", btype());
        break;
      }
      case BTI_c:
        if (btype() == BranchFromGuardedNotToIP) {
          FATAL("Executing BTI c with wrong BType (3).");
        }
        break;
      case BTI_j:
        if (btype() == BranchAndLink) {
          FATAL("Executing BTI j with wrong BType (2).");
        }
        break;
      default:
        UNIMPLEMENTED();
    }
  }

  void CheckBType() {
    // On guarded pages, if BType is not zero, take an exception on any
    // instruction other than BTI, PACI[AB]SP, HLT or BRK.
    if (PcIsInGuardedPage() && (btype() != DefaultBType)) {
      if (pc_->IsPAuth()) {
        CheckBTypeForPAuth();
      } els
"""


```