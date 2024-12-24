Response: The user wants me to summarize the functionality of a C++ source code file for the ARM64 simulator in V8.
The file seems to implement logic for simulating ARM64 instructions, particularly those related to floating-point operations and SIMD (Single Instruction, Multiple Data) vector operations.

Here's a breakdown of the file's contents:

1. **Includes**: Standard library headers and V8-specific headers related to simulation and number conversions.
2. **`half` class**: A custom class to represent half-precision floating-point numbers (16-bit). It includes constructors from `float` and `double`, conversion operators, and bit manipulation.
3. **Helper functions**:
    - `FPRoundToDouble`, `FPRoundToFloat`, `FPRoundToFloat16`: Functions likely related to rounding floating-point numbers to different precisions.
4. **`Simulator` class methods**:
    - `FixedToDouble`, `UFixedToDouble`, `FixedToFloat`, `UFixedToFloat`, `FixedToFloat16`, `UFixedToFloat16`: Methods for converting fixed-point numbers to floating-point numbers.
    - `FPToDouble`, `FPToFloat`, `FPToFloat16`: Methods for converting between different floating-point precisions (`float`, `double`, `half`). These methods handle special cases like NaN (Not a Number) and infinity.
    - A large number of methods named after ARM64 SIMD instructions (e.g., `ld1`, `ld2`, `st1`, `add`, `sub`, `mul`, `cmp`, `shl`, `ushr`, etc.). These methods simulate the behavior of the corresponding ARM64 instructions on vector registers. They handle various data types and operations like loading, storing, arithmetic, logical operations, shifts, and comparisons.

Based on this analysis, the file's primary function is to provide a software-based simulation of the ARM64 architecture's floating-point and SIMD instruction set. This is crucial for running and testing V8 on non-ARM64 platforms or in environments where hardware execution is not feasible.

Regarding the relationship with JavaScript, this file is fundamental to how V8 executes JavaScript code that involves numerical computations, especially those that can benefit from SIMD optimizations. JavaScript's `Float32Array`, `Float64Array`, and potentially future SIMD APIs would rely on the underlying architecture's capabilities. This simulator allows V8 to run and test such JavaScript code even on platforms without native ARM64 hardware.
这个C++源代码文件是V8 JavaScript引擎中用于ARM64架构的模拟器的一部分，专门负责模拟ARM64指令的逻辑运算和浮点运算。

更具体地说，这个文件的功能可以归纳为：

1. **提供半精度浮点数 (half) 的支持**:  定义了一个 `half` 类，用于表示16位的浮点数，并提供了与 `float` 和 `double` 之间相互转换的方法。这使得模拟器能够处理涉及半精度浮点数的ARM64指令。

2. **实现定点数与浮点数之间的转换**:  提供了一系列 `FixedToDouble`, `UFixedToDouble`, `FixedToFloat`, `UFixedToFloat`, `FixedToFloat16`, `UFixedToFloat16` 函数，用于将定点数转换为不同精度的浮点数 (`double`, `float`, `half`)。这些函数在模拟涉及定点数和浮点数运算的指令时被使用。

3. **实现不同浮点数精度之间的转换**:  提供 `FPToDouble`, `FPToFloat`, `FPToFloat16` 函数，用于在 `float`, `double`, 和 `half` 之间进行转换。这些函数会处理诸如 NaN (非数字) 和无穷大等特殊情况，并尽可能模拟硬件的行为。

4. **实现ARM64的SIMD (Single Instruction, Multiple Data) 向量指令的模拟逻辑**: 包含了大量的以 `ld`, `st`, `cmp`, `add`, `sub`, `mul`, `shl`, `ushr` 等开头的函数。这些函数模拟了ARM64架构中用于向量运算的指令，例如：
    - `ld1`, `ld2`, `ld3`, `ld4`: 模拟从内存加载数据到向量寄存器的指令。
    - `st1`, `st2`, `st3`, `st4`: 模拟将向量寄存器的数据存储到内存的指令。
    - `cmp`: 模拟向量比较指令。
    - `add`, `sub`, `mul`: 模拟向量加法、减法和乘法指令。
    - `shl`, `ushr`: 模拟向量移位指令。
    - 以及其他的逻辑运算、位运算、最小值/最大值运算等。

**与 JavaScript 的关系以及示例:**

虽然这个文件是 C++ 代码，但它是 V8 引擎的一部分，而 V8 引擎负责执行 JavaScript 代码。这个模拟器使得 V8 能够在不支持 ARM64 指令集的平台上运行和测试，或者在某些开发和调试场景下使用。

当 JavaScript 代码中涉及到数值计算，特别是使用到 `Float32Array`, `Float64Array` 等类型数组进行大规模数值运算时，V8 可能会尝试将这些运算映射到硬件支持的 SIMD 指令上以提高性能。 如果当前运行的平台不是 ARM64，或者 V8 选择了使用模拟器，那么这个文件中的代码就会被用来模拟这些 ARM64 的 SIMD 指令。

**JavaScript 示例:**

假设有以下 JavaScript 代码：

```javascript
const a = new Float32Array([1.0, 2.0, 3.0, 4.0]);
const b = new Float32Array([5.0, 6.0, 7.0, 8.0]);
const c = new Float32Array(4);

for (let i = 0; i < a.length; i++) {
  c[i] = a[i] + b[i];
}

console.log(c); // 输出: Float32Array [ 6, 8, 10, 12 ]
```

在支持 ARM64 硬件的平台上，V8 可能会将循环内的加法操作转换为一个 ARM64 的 SIMD 加法指令，例如 `fadd v0.4s, v1.4s, v2.4s` (假设 `v1` 和 `v2` 存储了 `a` 和 `b` 的数据)。

如果 V8 在一个非 ARM64 平台上运行这个 JavaScript 代码，那么为了模拟 `fadd` 指令的行为，`v8/src/execution/arm64/simulator-logic-arm64.cc` 文件中可能会有类似下面逻辑的 C++ 代码被执行 (简化示例)：

```c++
// 假设 vform 代表浮点数单精度向量格式
void Simulator::fadd(VectorFormat vform, LogicVRegister dst, const LogicVRegister& src1, const LogicVRegister& src2) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    float a = src1.Float(vform, i);
    float b = src2.Float(vform, i);
    dst.SetFloat(vform, i, a + b);
  }
}
```

这段 C++ 代码模拟了将 `src1` 和 `src2` 向量寄存器中对应位置的单精度浮点数相加，并将结果存储到 `dst` 向量寄存器中。

总而言之，这个 C++ 文件是 V8 引擎在非 ARM64 平台上执行涉及到浮点运算和 SIMD 指令的 JavaScript 代码的关键组成部分，它通过软件模拟实现了 ARM64 架构的指令行为。

Prompt: 
```
这是目录为v8/src/execution/arm64/simulator-logic-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/execution/arm64/simulator-arm64.h"

#if defined(USE_SIMULATOR)

#include <cmath>

#include "src/numbers/conversions-inl.h"
#include "third_party/fp16/src/include/fp16.h"

namespace v8 {
namespace internal {

class half {
 public:
  half() : bits_(0) {}
  half(float f) : bits_(fp16_ieee_from_fp32_value(f)) {}
  explicit half(double d) : bits_(DoubleToFloat16(d)) {}
  explicit half(uint16_t b) : bits_(b) {}
  operator float() const { return fp16_ieee_to_fp32_value(bits_); }

  uint16_t bits() const { return bits_; }

 private:
  uint16_t bits_;
};

template <>
half Simulator::FPDefaultNaN<half>() {
  return half(kFP16DefaultNaN);
}

inline half ToQuietNaN(half num) {
  return half(static_cast<uint16_t>(num.bits() | kHQuietNanMask));
}

template <typename T>
bool isnormal(T f) {
  return std::isnormal(f);
}

template <>
bool isnormal(half f) {
  return float16classify(f.bits()) == FP_NORMAL;
}

double copysign(double a, double f) { return std::copysign(a, f); }
float copysign(double a, float f) { return std::copysign(a, f); }
half copysign(double a, half f) {
  return std::copysign(static_cast<float>(a), f);
}

static_assert(sizeof(half) == sizeof(uint16_t), "Half must be 16 bit");

namespace {

// See FPRound for a description of this function.
inline double FPRoundToDouble(int64_t sign, int64_t exponent, uint64_t mantissa,
                              FPRounding round_mode) {
  uint64_t bits = FPRound<uint64_t, kDoubleExponentBits, kDoubleMantissaBits>(
      sign, exponent, mantissa, round_mode);
  return base::bit_cast<double>(bits);
}

// See FPRound for a description of this function.
inline float FPRoundToFloat(int64_t sign, int64_t exponent, uint64_t mantissa,
                            FPRounding round_mode) {
  uint32_t bits = FPRound<uint32_t, kFloatExponentBits, kFloatMantissaBits>(
      sign, exponent, mantissa, round_mode);
  return base::bit_cast<float>(bits);
}

// See FPRound for a description of this function.
inline float16 FPRoundToFloat16(int64_t sign, int64_t exponent,
                                uint64_t mantissa, FPRounding round_mode) {
  return FPRound<float16, kFloat16ExponentBits, kFloat16MantissaBits>(
      sign, exponent, mantissa, round_mode);
}

}  // namespace

double Simulator::FixedToDouble(int64_t src, int fbits, FPRounding round) {
  if (src >= 0) {
    return UFixedToDouble(src, fbits, round);
  } else if (src == INT64_MIN) {
    return -UFixedToDouble(src, fbits, round);
  } else {
    return -UFixedToDouble(-src, fbits, round);
  }
}

double Simulator::UFixedToDouble(uint64_t src, int fbits, FPRounding round) {
  // An input of 0 is a special case because the result is effectively
  // subnormal: The exponent is encoded as 0 and there is no implicit 1 bit.
  if (src == 0) {
    return 0.0;
  }

  // Calculate the exponent. The highest significant bit will have the value
  // 2^exponent.
  const int highest_significant_bit = 63 - CountLeadingZeros(src, 64);
  const int64_t exponent = highest_significant_bit - fbits;

  return FPRoundToDouble(0, exponent, src, round);
}

float Simulator::FixedToFloat(int64_t src, int fbits, FPRounding round) {
  if (src >= 0) {
    return UFixedToFloat(src, fbits, round);
  } else if (src == INT64_MIN) {
    return -UFixedToFloat(src, fbits, round);
  } else {
    return -UFixedToFloat(-src, fbits, round);
  }
}

float Simulator::UFixedToFloat(uint64_t src, int fbits, FPRounding round) {
  // An input of 0 is a special case because the result is effectively
  // subnormal: The exponent is encoded as 0 and there is no implicit 1 bit.
  if (src == 0) {
    return 0.0f;
  }

  // Calculate the exponent. The highest significant bit will have the value
  // 2^exponent.
  const int highest_significant_bit = 63 - CountLeadingZeros(src, 64);
  const int32_t exponent = highest_significant_bit - fbits;

  return FPRoundToFloat(0, exponent, src, round);
}

float16 Simulator::FixedToFloat16(int64_t src, int fbits, FPRounding round) {
  if (src >= 0) {
    return UFixedToFloat16(src, fbits, round);
  } else if (src == INT64_MIN) {
    return -UFixedToFloat16(src, fbits, round);
  } else {
    return -UFixedToFloat16(-src, fbits, round);
  }
}

float16 Simulator::UFixedToFloat16(uint64_t src, int fbits, FPRounding round) {
  // An input of 0 is a special case because the result is effectively
  // subnormal: The exponent is encoded as 0 and there is no implicit 1 bit.
  if (src == 0) {
    return static_cast<float16>(0);
  }

  // Calculate the exponent. The highest significant bit will have the value
  // 2^exponent.
  const int highest_significant_bit = 63 - CountLeadingZeros(src, 64);
  const int16_t exponent = highest_significant_bit - fbits;

  return FPRoundToFloat16(0, exponent, src, round);
}

double Simulator::FPToDouble(float value) {
  switch (std::fpclassify(value)) {
    case FP_NAN: {
      if (IsSignallingNaN(value)) {
        FPProcessException();
      }
      if (DN()) return kFP64DefaultNaN;

      // Convert NaNs as the processor would:
      //  - The sign is propagated.
      //  - The mantissa is transferred entirely, except that the top bit is
      //    forced to '1', making the result a quiet NaN. The unused (low-order)
      //    mantissa bits are set to 0.
      uint32_t raw = base::bit_cast<uint32_t>(value);

      uint64_t sign = raw >> 31;
      uint64_t exponent = (1 << kDoubleExponentBits) - 1;
      uint64_t mantissa = unsigned_bitextract_64(21, 0, raw);

      // Unused low-order bits remain zero.
      mantissa <<= (kDoubleMantissaBits - kFloatMantissaBits);

      // Force a quiet NaN.
      mantissa |= (UINT64_C(1) << (kDoubleMantissaBits - 1));

      return double_pack(sign, exponent, mantissa);
    }

    case FP_ZERO:
    case FP_NORMAL:
    case FP_SUBNORMAL:
    case FP_INFINITE: {
      // All other inputs are preserved in a standard cast, because every value
      // representable using an IEEE-754 float is also representable using an
      // IEEE-754 double.
      return static_cast<double>(value);
    }
  }

  UNREACHABLE();
}

float Simulator::FPToFloat(float16 value) {
  uint32_t sign = value >> 15;
  uint32_t exponent =
      unsigned_bitextract_32(kFloat16MantissaBits + kFloat16ExponentBits - 1,
                             kFloat16MantissaBits, value);
  uint32_t mantissa =
      unsigned_bitextract_32(kFloat16MantissaBits - 1, 0, value);

  switch (float16classify(value)) {
    case FP_ZERO:
      return (sign == 0) ? 0.0f : -0.0f;

    case FP_INFINITE:
      return (sign == 0) ? kFP32PositiveInfinity : kFP32NegativeInfinity;

    case FP_SUBNORMAL: {
      // Calculate shift required to put mantissa into the most-significant bits
      // of the destination mantissa.
      int shift = CountLeadingZeros(mantissa << (32 - 10), 32);

      // Shift mantissa and discard implicit '1'.
      mantissa <<= (kFloatMantissaBits - kFloat16MantissaBits) + shift + 1;
      mantissa &= (1 << kFloatMantissaBits) - 1;

      // Adjust the exponent for the shift applied, and rebias.
      exponent = exponent - shift + (kFloatExponentBias - kFloat16ExponentBias);
      break;
    }

    case FP_NAN: {
      if (IsSignallingNaN(value)) {
        FPProcessException();
      }
      if (DN()) return kFP32DefaultNaN;

      // Convert NaNs as the processor would:
      //  - The sign is propagated.
      //  - The mantissa is transferred entirely, except that the top bit is
      //    forced to '1', making the result a quiet NaN. The unused (low-order)
      //    mantissa bits are set to 0.
      exponent = (1 << kFloatExponentBits) - 1;

      // Increase bits in mantissa, making low-order bits 0.
      mantissa <<= (kFloatMantissaBits - kFloat16MantissaBits);
      mantissa |= 1 << (kFloatMantissaBits - 1);  // Force a quiet NaN.
      break;
    }

    case FP_NORMAL: {
      // Increase bits in mantissa, making low-order bits 0.
      mantissa <<= (kFloatMantissaBits - kFloat16MantissaBits);

      // Change exponent bias.
      exponent += (kFloatExponentBias - kFloat16ExponentBias);
      break;
    }

    default:
      UNREACHABLE();
  }
  return float_pack(sign, exponent, mantissa);
}

float16 Simulator::FPToFloat16(float value, FPRounding round_mode) {
  // Only the FPTieEven rounding mode is implemented.
  DCHECK_EQ(round_mode, FPTieEven);
  USE(round_mode);

  int64_t sign = float_sign(value);
  int64_t exponent =
      static_cast<int64_t>(float_exp(value)) - kFloatExponentBias;
  uint32_t mantissa = float_mantissa(value);

  switch (std::fpclassify(value)) {
    case FP_NAN: {
      if (IsSignallingNaN(value)) {
        FPProcessException();
      }
      if (DN()) return kFP16DefaultNaN;

      // Convert NaNs as the processor would:
      //  - The sign is propagated.
      //  - The mantissa is transferred as much as possible, except that the top
      //    bit is forced to '1', making the result a quiet NaN.
      float16 result =
          (sign == 0) ? kFP16PositiveInfinity : kFP16NegativeInfinity;
      result |= mantissa >> (kFloatMantissaBits - kFloat16MantissaBits);
      result |= (1 << (kFloat16MantissaBits - 1));  // Force a quiet NaN;
      return result;
    }

    case FP_ZERO:
      return (sign == 0) ? 0 : 0x8000;

    case FP_INFINITE:
      return (sign == 0) ? kFP16PositiveInfinity : kFP16NegativeInfinity;

    case FP_NORMAL:
    case FP_SUBNORMAL: {
      // Convert float-to-half as the processor would, assuming that FPCR.FZ
      // (flush-to-zero) is not set.

      // Add the implicit '1' bit to the mantissa.
      mantissa += (1 << kFloatMantissaBits);
      return FPRoundToFloat16(sign, exponent, mantissa, round_mode);
    }
  }

  UNREACHABLE();
}

float16 Simulator::FPToFloat16(double value, FPRounding round_mode) {
  // Only the FPTieEven rounding mode is implemented.
  DCHECK_EQ(round_mode, FPTieEven);
  USE(round_mode);

  int64_t sign = double_sign(value);
  int64_t exponent =
      static_cast<int64_t>(double_exp(value)) - kDoubleExponentBias;
  uint64_t mantissa = double_mantissa(value);

  switch (std::fpclassify(value)) {
    case FP_NAN: {
      if (IsSignallingNaN(value)) {
        FPProcessException();
      }
      if (DN()) return kFP16DefaultNaN;

      // Convert NaNs as the processor would:
      //  - The sign is propagated.
      //  - The mantissa is transferred as much as possible, except that the top
      //    bit is forced to '1', making the result a quiet NaN.
      float16 result =
          (sign == 0) ? kFP16PositiveInfinity : kFP16NegativeInfinity;
      result |= mantissa >> (kDoubleMantissaBits - kFloat16MantissaBits);
      result |= (1 << (kFloat16MantissaBits - 1));  // Force a quiet NaN;
      return result;
    }

    case FP_ZERO:
      return (sign == 0) ? 0 : 0x8000;

    case FP_INFINITE:
      return (sign == 0) ? kFP16PositiveInfinity : kFP16NegativeInfinity;

    case FP_NORMAL:
    case FP_SUBNORMAL: {
      // Convert double-to-half as the processor would, assuming that FPCR.FZ
      // (flush-to-zero) is not set.

      // Add the implicit '1' bit to the mantissa.
      mantissa += (UINT64_C(1) << kDoubleMantissaBits);
      return FPRoundToFloat16(sign, exponent, mantissa, round_mode);
    }
  }

  UNREACHABLE();
}

float Simulator::FPToFloat(double value, FPRounding round_mode) {
  // Only the FPTieEven rounding mode is implemented.
  DCHECK((round_mode == FPTieEven) || (round_mode == FPRoundOdd));
  USE(round_mode);

  switch (std::fpclassify(value)) {
    case FP_NAN: {
      if (IsSignallingNaN(value)) {
        FPProcessException();
      }
      if (DN()) return kFP32DefaultNaN;

      // Convert NaNs as the processor would:
      //  - The sign is propagated.
      //  - The mantissa is transferred as much as possible, except that the
      //    top bit is forced to '1', making the result a quiet NaN.

      uint64_t raw = base::bit_cast<uint64_t>(value);

      uint32_t sign = raw >> 63;
      uint32_t exponent = (1 << 8) - 1;
      uint32_t mantissa = static_cast<uint32_t>(unsigned_bitextract_64(
          50, kDoubleMantissaBits - kFloatMantissaBits, raw));
      mantissa |= (1 << (kFloatMantissaBits - 1));  // Force a quiet NaN.

      return float_pack(sign, exponent, mantissa);
    }

    case FP_ZERO:
    case FP_INFINITE: {
      // In a C++ cast, any value representable in the target type will be
      // unchanged. This is always the case for +/-0.0 and infinities.
      return static_cast<float>(value);
    }

    case FP_NORMAL:
    case FP_SUBNORMAL: {
      // Convert double-to-float as the processor would, assuming that FPCR.FZ
      // (flush-to-zero) is not set.
      uint32_t sign = double_sign(value);
      int64_t exponent =
          static_cast<int64_t>(double_exp(value)) - kDoubleExponentBias;
      uint64_t mantissa = double_mantissa(value);
      if (std::fpclassify(value) == FP_NORMAL) {
        // For normal FP values, add the hidden bit.
        mantissa |= (UINT64_C(1) << kDoubleMantissaBits);
      }
      return FPRoundToFloat(sign, exponent, mantissa, round_mode);
    }
  }

  UNREACHABLE();
}

void Simulator::ld1(VectorFormat vform, LogicVRegister dst, uint64_t addr) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst.ReadUintFromMem(vform, i, addr);
    addr += LaneSizeInBytesFromFormat(vform);
  }
}

void Simulator::ld1(VectorFormat vform, LogicVRegister dst, int index,
                    uint64_t addr) {
  dst.ReadUintFromMem(vform, index, addr);
}

void Simulator::ld1r(VectorFormat vform, LogicVRegister dst, uint64_t addr) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst.ReadUintFromMem(vform, i, addr);
  }
}

void Simulator::ld2(VectorFormat vform, LogicVRegister dst1,
                    LogicVRegister dst2, uint64_t addr1) {
  dst1.ClearForWrite(vform);
  dst2.ClearForWrite(vform);
  int esize = LaneSizeInBytesFromFormat(vform);
  uint64_t addr2 = addr1 + esize;
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst1.ReadUintFromMem(vform, i, addr1);
    dst2.ReadUintFromMem(vform, i, addr2);
    addr1 += 2 * esize;
    addr2 += 2 * esize;
  }
}

void Simulator::ld2(VectorFormat vform, LogicVRegister dst1,
                    LogicVRegister dst2, int index, uint64_t addr1) {
  dst1.ClearForWrite(vform);
  dst2.ClearForWrite(vform);
  uint64_t addr2 = addr1 + LaneSizeInBytesFromFormat(vform);
  dst1.ReadUintFromMem(vform, index, addr1);
  dst2.ReadUintFromMem(vform, index, addr2);
}

void Simulator::ld2r(VectorFormat vform, LogicVRegister dst1,
                     LogicVRegister dst2, uint64_t addr) {
  dst1.ClearForWrite(vform);
  dst2.ClearForWrite(vform);
  uint64_t addr2 = addr + LaneSizeInBytesFromFormat(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst1.ReadUintFromMem(vform, i, addr);
    dst2.ReadUintFromMem(vform, i, addr2);
  }
}

void Simulator::ld3(VectorFormat vform, LogicVRegister dst1,
                    LogicVRegister dst2, LogicVRegister dst3, uint64_t addr1) {
  dst1.ClearForWrite(vform);
  dst2.ClearForWrite(vform);
  dst3.ClearForWrite(vform);
  int esize = LaneSizeInBytesFromFormat(vform);
  uint64_t addr2 = addr1 + esize;
  uint64_t addr3 = addr2 + esize;
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst1.ReadUintFromMem(vform, i, addr1);
    dst2.ReadUintFromMem(vform, i, addr2);
    dst3.ReadUintFromMem(vform, i, addr3);
    addr1 += 3 * esize;
    addr2 += 3 * esize;
    addr3 += 3 * esize;
  }
}

void Simulator::ld3(VectorFormat vform, LogicVRegister dst1,
                    LogicVRegister dst2, LogicVRegister dst3, int index,
                    uint64_t addr1) {
  dst1.ClearForWrite(vform);
  dst2.ClearForWrite(vform);
  dst3.ClearForWrite(vform);
  uint64_t addr2 = addr1 + LaneSizeInBytesFromFormat(vform);
  uint64_t addr3 = addr2 + LaneSizeInBytesFromFormat(vform);
  dst1.ReadUintFromMem(vform, index, addr1);
  dst2.ReadUintFromMem(vform, index, addr2);
  dst3.ReadUintFromMem(vform, index, addr3);
}

void Simulator::ld3r(VectorFormat vform, LogicVRegister dst1,
                     LogicVRegister dst2, LogicVRegister dst3, uint64_t addr) {
  dst1.ClearForWrite(vform);
  dst2.ClearForWrite(vform);
  dst3.ClearForWrite(vform);
  uint64_t addr2 = addr + LaneSizeInBytesFromFormat(vform);
  uint64_t addr3 = addr2 + LaneSizeInBytesFromFormat(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst1.ReadUintFromMem(vform, i, addr);
    dst2.ReadUintFromMem(vform, i, addr2);
    dst3.ReadUintFromMem(vform, i, addr3);
  }
}

void Simulator::ld4(VectorFormat vform, LogicVRegister dst1,
                    LogicVRegister dst2, LogicVRegister dst3,
                    LogicVRegister dst4, uint64_t addr1) {
  dst1.ClearForWrite(vform);
  dst2.ClearForWrite(vform);
  dst3.ClearForWrite(vform);
  dst4.ClearForWrite(vform);
  int esize = LaneSizeInBytesFromFormat(vform);
  uint64_t addr2 = addr1 + esize;
  uint64_t addr3 = addr2 + esize;
  uint64_t addr4 = addr3 + esize;
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst1.ReadUintFromMem(vform, i, addr1);
    dst2.ReadUintFromMem(vform, i, addr2);
    dst3.ReadUintFromMem(vform, i, addr3);
    dst4.ReadUintFromMem(vform, i, addr4);
    addr1 += 4 * esize;
    addr2 += 4 * esize;
    addr3 += 4 * esize;
    addr4 += 4 * esize;
  }
}

void Simulator::ld4(VectorFormat vform, LogicVRegister dst1,
                    LogicVRegister dst2, LogicVRegister dst3,
                    LogicVRegister dst4, int index, uint64_t addr1) {
  dst1.ClearForWrite(vform);
  dst2.ClearForWrite(vform);
  dst3.ClearForWrite(vform);
  dst4.ClearForWrite(vform);
  uint64_t addr2 = addr1 + LaneSizeInBytesFromFormat(vform);
  uint64_t addr3 = addr2 + LaneSizeInBytesFromFormat(vform);
  uint64_t addr4 = addr3 + LaneSizeInBytesFromFormat(vform);
  dst1.ReadUintFromMem(vform, index, addr1);
  dst2.ReadUintFromMem(vform, index, addr2);
  dst3.ReadUintFromMem(vform, index, addr3);
  dst4.ReadUintFromMem(vform, index, addr4);
}

void Simulator::ld4r(VectorFormat vform, LogicVRegister dst1,
                     LogicVRegister dst2, LogicVRegister dst3,
                     LogicVRegister dst4, uint64_t addr) {
  dst1.ClearForWrite(vform);
  dst2.ClearForWrite(vform);
  dst3.ClearForWrite(vform);
  dst4.ClearForWrite(vform);
  uint64_t addr2 = addr + LaneSizeInBytesFromFormat(vform);
  uint64_t addr3 = addr2 + LaneSizeInBytesFromFormat(vform);
  uint64_t addr4 = addr3 + LaneSizeInBytesFromFormat(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst1.ReadUintFromMem(vform, i, addr);
    dst2.ReadUintFromMem(vform, i, addr2);
    dst3.ReadUintFromMem(vform, i, addr3);
    dst4.ReadUintFromMem(vform, i, addr4);
  }
}

void Simulator::st1(VectorFormat vform, LogicVRegister src, uint64_t addr) {
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    src.WriteUintToMem(vform, i, addr);
    addr += LaneSizeInBytesFromFormat(vform);
  }
}

void Simulator::st1(VectorFormat vform, LogicVRegister src, int index,
                    uint64_t addr) {
  src.WriteUintToMem(vform, index, addr);
}

void Simulator::st2(VectorFormat vform, LogicVRegister dst, LogicVRegister dst2,
                    uint64_t addr) {
  int esize = LaneSizeInBytesFromFormat(vform);
  uint64_t addr2 = addr + esize;
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst.WriteUintToMem(vform, i, addr);
    dst2.WriteUintToMem(vform, i, addr2);
    addr += 2 * esize;
    addr2 += 2 * esize;
  }
}

void Simulator::st2(VectorFormat vform, LogicVRegister dst, LogicVRegister dst2,
                    int index, uint64_t addr) {
  int esize = LaneSizeInBytesFromFormat(vform);
  dst.WriteUintToMem(vform, index, addr);
  dst2.WriteUintToMem(vform, index, addr + 1 * esize);
}

void Simulator::st3(VectorFormat vform, LogicVRegister dst, LogicVRegister dst2,
                    LogicVRegister dst3, uint64_t addr) {
  int esize = LaneSizeInBytesFromFormat(vform);
  uint64_t addr2 = addr + esize;
  uint64_t addr3 = addr2 + esize;
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst.WriteUintToMem(vform, i, addr);
    dst2.WriteUintToMem(vform, i, addr2);
    dst3.WriteUintToMem(vform, i, addr3);
    addr += 3 * esize;
    addr2 += 3 * esize;
    addr3 += 3 * esize;
  }
}

void Simulator::st3(VectorFormat vform, LogicVRegister dst, LogicVRegister dst2,
                    LogicVRegister dst3, int index, uint64_t addr) {
  int esize = LaneSizeInBytesFromFormat(vform);
  dst.WriteUintToMem(vform, index, addr);
  dst2.WriteUintToMem(vform, index, addr + 1 * esize);
  dst3.WriteUintToMem(vform, index, addr + 2 * esize);
}

void Simulator::st4(VectorFormat vform, LogicVRegister dst, LogicVRegister dst2,
                    LogicVRegister dst3, LogicVRegister dst4, uint64_t addr) {
  int esize = LaneSizeInBytesFromFormat(vform);
  uint64_t addr2 = addr + esize;
  uint64_t addr3 = addr2 + esize;
  uint64_t addr4 = addr3 + esize;
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst.WriteUintToMem(vform, i, addr);
    dst2.WriteUintToMem(vform, i, addr2);
    dst3.WriteUintToMem(vform, i, addr3);
    dst4.WriteUintToMem(vform, i, addr4);
    addr += 4 * esize;
    addr2 += 4 * esize;
    addr3 += 4 * esize;
    addr4 += 4 * esize;
  }
}

void Simulator::st4(VectorFormat vform, LogicVRegister dst, LogicVRegister dst2,
                    LogicVRegister dst3, LogicVRegister dst4, int index,
                    uint64_t addr) {
  int esize = LaneSizeInBytesFromFormat(vform);
  dst.WriteUintToMem(vform, index, addr);
  dst2.WriteUintToMem(vform, index, addr + 1 * esize);
  dst3.WriteUintToMem(vform, index, addr + 2 * esize);
  dst4.WriteUintToMem(vform, index, addr + 3 * esize);
}

LogicVRegister Simulator::cmp(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src1,
                              const LogicVRegister& src2, Condition cond) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    bool result = false;
    int64_t sa = src1.Int(vform, i);
    int64_t sb = src2.Int(vform, i);
    uint64_t ua = src1.Uint(vform, i);
    uint64_t ub = src2.Uint(vform, i);
    switch (cond) {
      case eq:
        result = (src1.Is(src2) || ua == ub);
        break;
      case ge:
        result = (src1.Is(src2) || sa >= sb);
        break;
      case gt:
        result = (!src1.Is(src2) && sa > sb);
        break;
      case hi:
        result = (!src1.Is(src2) && ua > ub);
        break;
      case hs:
        result = (src1.Is(src2) || ua >= ub);
        break;
      case lt:
        result = (!src1.Is(src2) && sa < sb);
        break;
      case le:
        result = (src1.Is(src2) || sa <= sb);
        break;
      default:
        UNREACHABLE();
    }
    dst.SetUint(vform, i, result ? MaxUintFromFormat(vform) : 0);
  }
  return dst;
}

LogicVRegister Simulator::cmp(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src1, int imm,
                              Condition cond) {
  SimVRegister temp;
  LogicVRegister imm_reg = dup_immediate(vform, temp, imm);
  return cmp(vform, dst, src1, imm_reg, cond);
}

LogicVRegister Simulator::cmptst(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    uint64_t ua = src1.Uint(vform, i);
    uint64_t ub = src2.Uint(vform, i);
    dst.SetUint(vform, i, ((ua & ub) != 0) ? MaxUintFromFormat(vform) : 0);
  }
  return dst;
}

LogicVRegister Simulator::add(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src1,
                              const LogicVRegister& src2) {
  int lane_size = LaneSizeInBitsFromFormat(vform);
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    // Test for unsigned saturation.
    uint64_t ua = src1.UintLeftJustified(vform, i);
    uint64_t ub = src2.UintLeftJustified(vform, i);
    uint64_t ur = ua + ub;
    if (ur < ua) {
      dst.SetUnsignedSat(i, true);
    }

    // Test for signed saturation.
    bool pos_a = (ua >> 63) == 0;
    bool pos_b = (ub >> 63) == 0;
    bool pos_r = (ur >> 63) == 0;
    // If the signs of the operands are the same, but different from the result,
    // there was an overflow.
    if ((pos_a == pos_b) && (pos_a != pos_r)) {
      dst.SetSignedSat(i, pos_a);
    }

    dst.SetInt(vform, i, ur >> (64 - lane_size));
  }
  return dst;
}

LogicVRegister Simulator::addp(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2) {
  SimVRegister temp1, temp2;
  uzp1(vform, temp1, src1, src2);
  uzp2(vform, temp2, src1, src2);
  add(vform, dst, temp1, temp2);
  return dst;
}

LogicVRegister Simulator::mla(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src1,
                              const LogicVRegister& src2) {
  SimVRegister temp;
  mul(vform, temp, src1, src2);
  add(vform, dst, dst, temp);
  return dst;
}

LogicVRegister Simulator::mls(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src1,
                              const LogicVRegister& src2) {
  SimVRegister temp;
  mul(vform, temp, src1, src2);
  sub(vform, dst, dst, temp);
  return dst;
}

LogicVRegister Simulator::mul(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src1,
                              const LogicVRegister& src2) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst.SetUint(vform, i, src1.Uint(vform, i) * src2.Uint(vform, i));
  }
  return dst;
}

LogicVRegister Simulator::mul(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src1,
                              const LogicVRegister& src2, int index) {
  SimVRegister temp;
  VectorFormat indexform = VectorFormatFillQ(vform);
  return mul(vform, dst, src1, dup_element(indexform, temp, src2, index));
}

LogicVRegister Simulator::mla(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src1,
                              const LogicVRegister& src2, int index) {
  SimVRegister temp;
  VectorFormat indexform = VectorFormatFillQ(vform);
  return mla(vform, dst, src1, dup_element(indexform, temp, src2, index));
}

LogicVRegister Simulator::mls(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src1,
                              const LogicVRegister& src2, int index) {
  SimVRegister temp;
  VectorFormat indexform = VectorFormatFillQ(vform);
  return mls(vform, dst, src1, dup_element(indexform, temp, src2, index));
}

LogicVRegister Simulator::smull(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2, int index) {
  SimVRegister temp;
  VectorFormat indexform =
      VectorFormatHalfWidthDoubleLanes(VectorFormatFillQ(vform));
  return smull(vform, dst, src1, dup_element(indexform, temp, src2, index));
}

LogicVRegister Simulator::smull2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2, int index) {
  SimVRegister temp;
  VectorFormat indexform =
      VectorFormatHalfWidthDoubleLanes(VectorFormatFillQ(vform));
  return smull2(vform, dst, src1, dup_element(indexform, temp, src2, index));
}

LogicVRegister Simulator::umull(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2, int index) {
  SimVRegister temp;
  VectorFormat indexform =
      VectorFormatHalfWidthDoubleLanes(VectorFormatFillQ(vform));
  return umull(vform, dst, src1, dup_element(indexform, temp, src2, index));
}

LogicVRegister Simulator::umull2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2, int index) {
  SimVRegister temp;
  VectorFormat indexform =
      VectorFormatHalfWidthDoubleLanes(VectorFormatFillQ(vform));
  return umull2(vform, dst, src1, dup_element(indexform, temp, src2, index));
}

LogicVRegister Simulator::smlal(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2, int index) {
  SimVRegister temp;
  VectorFormat indexform =
      VectorFormatHalfWidthDoubleLanes(VectorFormatFillQ(vform));
  return smlal(vform, dst, src1, dup_element(indexform, temp, src2, index));
}

LogicVRegister Simulator::smlal2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2, int index) {
  SimVRegister temp;
  VectorFormat indexform =
      VectorFormatHalfWidthDoubleLanes(VectorFormatFillQ(vform));
  return smlal2(vform, dst, src1, dup_element(indexform, temp, src2, index));
}

LogicVRegister Simulator::umlal(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2, int index) {
  SimVRegister temp;
  VectorFormat indexform =
      VectorFormatHalfWidthDoubleLanes(VectorFormatFillQ(vform));
  return umlal(vform, dst, src1, dup_element(indexform, temp, src2, index));
}

LogicVRegister Simulator::umlal2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2, int index) {
  SimVRegister temp;
  VectorFormat indexform =
      VectorFormatHalfWidthDoubleLanes(VectorFormatFillQ(vform));
  return umlal2(vform, dst, src1, dup_element(indexform, temp, src2, index));
}

LogicVRegister Simulator::smlsl(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2, int index) {
  SimVRegister temp;
  VectorFormat indexform =
      VectorFormatHalfWidthDoubleLanes(VectorFormatFillQ(vform));
  return smlsl(vform, dst, src1, dup_element(indexform, temp, src2, index));
}

LogicVRegister Simulator::smlsl2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2, int index) {
  SimVRegister temp;
  VectorFormat indexform =
      VectorFormatHalfWidthDoubleLanes(VectorFormatFillQ(vform));
  return smlsl2(vform, dst, src1, dup_element(indexform, temp, src2, index));
}

LogicVRegister Simulator::umlsl(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2, int index) {
  SimVRegister temp;
  VectorFormat indexform =
      VectorFormatHalfWidthDoubleLanes(VectorFormatFillQ(vform));
  return umlsl(vform, dst, src1, dup_element(indexform, temp, src2, index));
}

LogicVRegister Simulator::umlsl2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2, int index) {
  SimVRegister temp;
  VectorFormat indexform =
      VectorFormatHalfWidthDoubleLanes(VectorFormatFillQ(vform));
  return umlsl2(vform, dst, src1, dup_element(indexform, temp, src2, index));
}

LogicVRegister Simulator::sqdmull(VectorFormat vform, LogicVRegister dst,
                                  const LogicVRegister& src1,
                                  const LogicVRegister& src2, int index) {
  SimVRegister temp;
  VectorFormat indexform =
      VectorFormatHalfWidthDoubleLanes(VectorFormatFillQ(vform));
  return sqdmull(vform, dst, src1, dup_element(indexform, temp, src2, index));
}

LogicVRegister Simulator::sqdmull2(VectorFormat vform, LogicVRegister dst,
                                   const LogicVRegister& src1,
                                   const LogicVRegister& src2, int index) {
  SimVRegister temp;
  VectorFormat indexform =
      VectorFormatHalfWidthDoubleLanes(VectorFormatFillQ(vform));
  return sqdmull2(vform, dst, src1, dup_element(indexform, temp, src2, index));
}

LogicVRegister Simulator::sqdmlal(VectorFormat vform, LogicVRegister dst,
                                  const LogicVRegister& src1,
                                  const LogicVRegister& src2, int index) {
  SimVRegister temp;
  VectorFormat indexform =
      VectorFormatHalfWidthDoubleLanes(VectorFormatFillQ(vform));
  return sqdmlal(vform, dst, src1, dup_element(indexform, temp, src2, index));
}

LogicVRegister Simulator::sqdmlal2(VectorFormat vform, LogicVRegister dst,
                                   const LogicVRegister& src1,
                                   const LogicVRegister& src2, int index) {
  SimVRegister temp;
  VectorFormat indexform =
      VectorFormatHalfWidthDoubleLanes(VectorFormatFillQ(vform));
  return sqdmlal2(vform, dst, src1, dup_element(indexform, temp, src2, index));
}

LogicVRegister Simulator::sqdmlsl(VectorFormat vform, LogicVRegister dst,
                                  const LogicVRegister& src1,
                                  const LogicVRegister& src2, int index) {
  SimVRegister temp;
  VectorFormat indexform =
      VectorFormatHalfWidthDoubleLanes(VectorFormatFillQ(vform));
  return sqdmlsl(vform, dst, src1, dup_element(indexform, temp, src2, index));
}

LogicVRegister Simulator::sqdmlsl2(VectorFormat vform, LogicVRegister dst,
                                   const LogicVRegister& src1,
                                   const LogicVRegister& src2, int index) {
  SimVRegister temp;
  VectorFormat indexform =
      VectorFormatHalfWidthDoubleLanes(VectorFormatFillQ(vform));
  return sqdmlsl2(vform, dst, src1, dup_element(indexform, temp, src2, index));
}

LogicVRegister Simulator::sqdmulh(VectorFormat vform, LogicVRegister dst,
                                  const LogicVRegister& src1,
                                  const LogicVRegister& src2, int index) {
  SimVRegister temp;
  VectorFormat indexform = VectorFormatFillQ(vform);
  return sqdmulh(vform, dst, src1, dup_element(indexform, temp, src2, index));
}

LogicVRegister Simulator::sqrdmulh(VectorFormat vform, LogicVRegister dst,
                                   const LogicVRegister& src1,
                                   const LogicVRegister& src2, int index) {
  SimVRegister temp;
  VectorFormat indexform = VectorFormatFillQ(vform);
  return sqrdmulh(vform, dst, src1, dup_element(indexform, temp, src2, index));
}

uint16_t Simulator::PolynomialMult(uint8_t op1, uint8_t op2) {
  return PolynomialMult128(op1, op2, 8).second;
}

LogicVRegister Simulator::pmul(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst.SetUint(vform, i,
                PolynomialMult(src1.Uint(vform, i), src2.Uint(vform, i)));
  }
  return dst;
}

LogicVRegister Simulator::pmull(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2) {
  VectorFormat vform_src = VectorFormatHalfWidth(vform);
  dst.ClearForWrite(vform);
  // Process the elements in reverse to avoid problems when the destination
  // register is the same as a source.
  for (int i = LaneCountFromFormat(vform) - 1; i > -1; i--) {
    dst.SetUint(
        vform, i,
        PolynomialMult128(src1.Uint(vform_src, i), src2.Uint(vform_src, i),
                          LaneSizeInBitsFromFormat(vform_src)));
  }
  return dst;
}

LogicVRegister Simulator::pmull2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src1,
                                 const LogicVRegister& src2) {
  VectorFormat vform_src = VectorFormatHalfWidthDoubleLanes(vform);
  dst.ClearForWrite(vform);
  int lane_count = LaneCountFromFormat(vform);
  for (int i = 0; i < lane_count; i++) {
    dst.SetUint(vform, i,
                PolynomialMult128(src1.Uint(vform_src, lane_count + i),
                                  src2.Uint(vform_src, lane_count + i),
                                  LaneSizeInBitsFromFormat(vform_src)));
  }
  return dst;
}

LogicVRegister Simulator::sub(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src1,
                              const LogicVRegister& src2) {
  int lane_size = LaneSizeInBitsFromFormat(vform);
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    // Test for unsigned saturation.
    uint64_t ua = src1.UintLeftJustified(vform, i);
    uint64_t ub = src2.UintLeftJustified(vform, i);
    uint64_t ur = ua - ub;
    if (ub > ua) {
      dst.SetUnsignedSat(i, false);
    }

    // Test for signed saturation.
    bool pos_a = (ua >> 63) == 0;
    bool pos_b = (ub >> 63) == 0;
    bool pos_r = (ur >> 63) == 0;
    // If the signs of the operands are different, and the sign of the first
    // operand doesn't match the result, there was an overflow.
    if ((pos_a != pos_b) && (pos_a != pos_r)) {
      dst.SetSignedSat(i, pos_a);
    }

    dst.SetInt(vform, i, ur >> (64 - lane_size));
  }
  return dst;
}

LogicVRegister Simulator::and_(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst.SetUint(vform, i, src1.Uint(vform, i) & src2.Uint(vform, i));
  }
  return dst;
}

LogicVRegister Simulator::orr(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src1,
                              const LogicVRegister& src2) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst.SetUint(vform, i, src1.Uint(vform, i) | src2.Uint(vform, i));
  }
  return dst;
}

LogicVRegister Simulator::orn(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src1,
                              const LogicVRegister& src2) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst.SetUint(vform, i, src1.Uint(vform, i) | ~src2.Uint(vform, i));
  }
  return dst;
}

LogicVRegister Simulator::eor(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src1,
                              const LogicVRegister& src2) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst.SetUint(vform, i,
                src1.Is(src2) ? 0 : src1.Uint(vform, i) ^ src2.Uint(vform, i));
  }
  return dst;
}

LogicVRegister Simulator::bic(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src1,
                              const LogicVRegister& src2) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst.SetUint(vform, i, src1.Uint(vform, i) & ~src2.Uint(vform, i));
  }
  return dst;
}

LogicVRegister Simulator::bic(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src, uint64_t imm) {
  uint64_t result[16];
  int laneCount = LaneCountFromFormat(vform);
  for (int i = 0; i < laneCount; ++i) {
    result[i] = src.Uint(vform, i) & ~imm;
  }
  dst.SetUintArray(vform, result);
  return dst;
}

LogicVRegister Simulator::bif(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src1,
                              const LogicVRegister& src2) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    uint64_t operand1 = dst.Uint(vform, i);
    uint64_t operand2 = ~src2.Uint(vform, i);
    uint64_t operand3 = src1.Uint(vform, i);
    uint64_t result = operand1 ^ ((operand1 ^ operand3) & operand2);
    dst.SetUint(vform, i, result);
  }
  return dst;
}

LogicVRegister Simulator::bit(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src1,
                              const LogicVRegister& src2) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    uint64_t operand1 = dst.Uint(vform, i);
    uint64_t operand2 = src2.Uint(vform, i);
    uint64_t operand3 = src1.Uint(vform, i);
    uint64_t result = operand1 ^ ((operand1 ^ operand3) & operand2);
    dst.SetUint(vform, i, result);
  }
  return dst;
}

LogicVRegister Simulator::bsl(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src1,
                              const LogicVRegister& src2) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    uint64_t operand1 = src2.Uint(vform, i);
    uint64_t operand2 = dst.Uint(vform, i);
    uint64_t operand3 = src1.Uint(vform, i);
    uint64_t result = operand1 ^ ((operand1 ^ operand3) & operand2);
    dst.SetUint(vform, i, result);
  }
  return dst;
}

LogicVRegister Simulator::SMinMax(VectorFormat vform, LogicVRegister dst,
                                  const LogicVRegister& src1,
                                  const LogicVRegister& src2, bool max) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    int64_t src1_val = src1.Int(vform, i);
    int64_t src2_val = src2.Int(vform, i);
    int64_t dst_val;
    if (max) {
      dst_val = (src1_val > src2_val) ? src1_val : src2_val;
    } else {
      dst_val = (src1_val < src2_val) ? src1_val : src2_val;
    }
    dst.SetInt(vform, i, dst_val);
  }
  return dst;
}

LogicVRegister Simulator::smax(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2) {
  return SMinMax(vform, dst, src1, src2, true);
}

LogicVRegister Simulator::smin(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2) {
  return SMinMax(vform, dst, src1, src2, false);
}

LogicVRegister Simulator::SMinMaxP(VectorFormat vform, LogicVRegister dst,
                                   const LogicVRegister& src1,
                                   const LogicVRegister& src2, bool max) {
  int lanes = LaneCountFromFormat(vform);
  int64_t result[kMaxLanesPerVector];
  const LogicVRegister* src = &src1;
  for (int j = 0; j < 2; j++) {
    for (int i = 0; i < lanes; i += 2) {
      int64_t first_val = src->Int(vform, i);
      int64_t second_val = src->Int(vform, i + 1);
      int64_t dst_val;
      if (max) {
        dst_val = (first_val > second_val) ? first_val : second_val;
      } else {
        dst_val = (first_val < second_val) ? first_val : second_val;
      }
      DCHECK_LT((i >> 1) + (j * lanes / 2), kMaxLanesPerVector);
      result[(i >> 1) + (j * lanes / 2)] = dst_val;
    }
    src = &src2;
  }
  dst.SetIntArray(vform, result);
  return dst;
}

LogicVRegister Simulator::smaxp(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2) {
  return SMinMaxP(vform, dst, src1, src2, true);
}

LogicVRegister Simulator::sminp(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2) {
  return SMinMaxP(vform, dst, src1, src2, false);
}

LogicVRegister Simulator::addp(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src) {
  DCHECK_EQ(vform, kFormatD);

  uint64_t dst_val = src.Uint(kFormat2D, 0) + src.Uint(kFormat2D, 1);
  dst.ClearForWrite(vform);
  dst.SetUint(vform, 0, dst_val);
  return dst;
}

LogicVRegister Simulator::addv(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src) {
  VectorFormat vform_dst =
      ScalarFormatFromLaneSize(LaneSizeInBitsFromFormat(vform));

  int64_t dst_val = 0;
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst_val += src.Int(vform, i);
  }

  dst.ClearForWrite(vform_dst);
  dst.SetInt(vform_dst, 0, dst_val);
  return dst;
}

LogicVRegister Simulator::saddlv(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src) {
  VectorFormat vform_dst =
      ScalarFormatFromLaneSize(LaneSizeInBitsFromFormat(vform) * 2);

  int64_t dst_val = 0;
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst_val += src.Int(vform, i);
  }

  dst.ClearForWrite(vform_dst);
  dst.SetInt(vform_dst, 0, dst_val);
  return dst;
}

LogicVRegister Simulator::uaddlv(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src) {
  VectorFormat vform_dst =
      ScalarFormatFromLaneSize(LaneSizeInBitsFromFormat(vform) * 2);

  uint64_t dst_val = 0;
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst_val += src.Uint(vform, i);
  }

  dst.ClearForWrite(vform_dst);
  dst.SetUint(vform_dst, 0, dst_val);
  return dst;
}

LogicVRegister Simulator::SMinMaxV(VectorFormat vform, LogicVRegister dst,
                                   const LogicVRegister& src, bool max) {
  int64_t dst_val = max ? INT64_MIN : INT64_MAX;
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    int64_t src_val = src.Int(vform, i);
    if (max) {
      dst_val = (src_val > dst_val) ? src_val : dst_val;
    } else {
      dst_val = (src_val < dst_val) ? src_val : dst_val;
    }
  }
  dst.ClearForWrite(ScalarFormatFromFormat(vform));
  dst.SetInt(vform, 0, dst_val);
  return dst;
}

LogicVRegister Simulator::smaxv(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src) {
  SMinMaxV(vform, dst, src, true);
  return dst;
}

LogicVRegister Simulator::sminv(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src) {
  SMinMaxV(vform, dst, src, false);
  return dst;
}

LogicVRegister Simulator::UMinMax(VectorFormat vform, LogicVRegister dst,
                                  const LogicVRegister& src1,
                                  const LogicVRegister& src2, bool max) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    uint64_t src1_val = src1.Uint(vform, i);
    uint64_t src2_val = src2.Uint(vform, i);
    uint64_t dst_val;
    if (max) {
      dst_val = (src1_val > src2_val) ? src1_val : src2_val;
    } else {
      dst_val = (src1_val < src2_val) ? src1_val : src2_val;
    }
    dst.SetUint(vform, i, dst_val);
  }
  return dst;
}

LogicVRegister Simulator::umax(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2) {
  return UMinMax(vform, dst, src1, src2, true);
}

LogicVRegister Simulator::umin(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2) {
  return UMinMax(vform, dst, src1, src2, false);
}

LogicVRegister Simulator::UMinMaxP(VectorFormat vform, LogicVRegister dst,
                                   const LogicVRegister& src1,
                                   const LogicVRegister& src2, bool max) {
  int lanes = LaneCountFromFormat(vform);
  uint64_t result[kMaxLanesPerVector];
  const LogicVRegister* src = &src1;
  for (int j = 0; j < 2; j++) {
    for (int i = 0; i < LaneCountFromFormat(vform); i += 2) {
      uint64_t first_val = src->Uint(vform, i);
      uint64_t second_val = src->Uint(vform, i + 1);
      uint64_t dst_val;
      if (max) {
        dst_val = (first_val > second_val) ? first_val : second_val;
      } else {
        dst_val = (first_val < second_val) ? first_val : second_val;
      }
      DCHECK_LT((i >> 1) + (j * lanes / 2), kMaxLanesPerVector);
      result[(i >> 1) + (j * lanes / 2)] = dst_val;
    }
    src = &src2;
  }
  dst.SetUintArray(vform, result);
  return dst;
}

LogicVRegister Simulator::umaxp(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2) {
  return UMinMaxP(vform, dst, src1, src2, true);
}

LogicVRegister Simulator::uminp(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2) {
  return UMinMaxP(vform, dst, src1, src2, false);
}

LogicVRegister Simulator::UMinMaxV(VectorFormat vform, LogicVRegister dst,
                                   const LogicVRegister& src, bool max) {
  uint64_t dst_val = max ? 0 : UINT64_MAX;
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    uint64_t src_val = src.Uint(vform, i);
    if (max) {
      dst_val = (src_val > dst_val) ? src_val : dst_val;
    } else {
      dst_val = (src_val < dst_val) ? src_val : dst_val;
    }
  }
  dst.ClearForWrite(ScalarFormatFromFormat(vform));
  dst.SetUint(vform, 0, dst_val);
  return dst;
}

LogicVRegister Simulator::umaxv(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src) {
  UMinMaxV(vform, dst, src, true);
  return dst;
}

LogicVRegister Simulator::uminv(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src) {
  UMinMaxV(vform, dst, src, false);
  return dst;
}

LogicVRegister Simulator::shl(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src, int shift) {
  DCHECK_GE(shift, 0);
  SimVRegister temp;
  LogicVRegister shiftreg = dup_immediate(vform, temp, shift);
  return ushl(vform, dst, src, shiftreg);
}

LogicVRegister Simulator::sshll(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src, int shift) {
  DCHECK_GE(shift, 0);
  SimVRegister temp1, temp2;
  LogicVRegister shiftreg = dup_immediate(vform, temp1, shift);
  LogicVRegister extendedreg = sxtl(vform, temp2, src);
  return sshl(vform, dst, extendedreg, shiftreg);
}

LogicVRegister Simulator::sshll2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src, int shift) {
  DCHECK_GE(shift, 0);
  SimVRegister temp1, temp2;
  LogicVRegister shiftreg = dup_immediate(vform, temp1, shift);
  LogicVRegister extendedreg = sxtl2(vform, temp2, src);
  return sshl(vform, dst, extendedreg, shiftreg);
}

LogicVRegister Simulator::shll(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src) {
  int shift = LaneSizeInBitsFromFormat(vform) / 2;
  return sshll(vform, dst, src, shift);
}

LogicVRegister Simulator::shll2(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src) {
  int shift = LaneSizeInBitsFromFormat(vform) / 2;
  return sshll2(vform, dst, src, shift);
}

LogicVRegister Simulator::ushll(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src, int shift) {
  DCHECK_GE(shift, 0);
  SimVRegister temp1, temp2;
  LogicVRegister shiftreg = dup_immediate(vform, temp1, shift);
  LogicVRegister extendedreg = uxtl(vform, temp2, src);
  return ushl(vform, dst, extendedreg, shiftreg);
}

LogicVRegister Simulator::ushll2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src, int shift) {
  DCHECK_GE(shift, 0);
  SimVRegister temp1, temp2;
  LogicVRegister shiftreg = dup_immediate(vform, temp1, shift);
  LogicVRegister extendedreg = uxtl2(vform, temp2, src);
  return ushl(vform, dst, extendedreg, shiftreg);
}

LogicVRegister Simulator::sli(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src, int shift) {
  dst.ClearForWrite(vform);
  int laneCount = LaneCountFromFormat(vform);
  for (int i = 0; i < laneCount; i++) {
    uint64_t src_lane = src.Uint(vform, i);
    uint64_t dst_lane = dst.Uint(vform, i);
    uint64_t shifted = src_lane << shift;
    uint64_t mask = MaxUintFromFormat(vform) << shift;
    dst.SetUint(vform, i, (dst_lane & ~mask) | shifted);
  }
  return dst;
}

LogicVRegister Simulator::sqshl(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src, int shift) {
  DCHECK_GE(shift, 0);
  SimVRegister temp;
  LogicVRegister shiftreg = dup_immediate(vform, temp, shift);
  return sshl(vform, dst, src, shiftreg).SignedSaturate(vform);
}

LogicVRegister Simulator::uqshl(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src, int shift) {
  DCHECK_GE(shift, 0);
  SimVRegister temp;
  LogicVRegister shiftreg = dup_immediate(vform, temp, shift);
  return ushl(vform, dst, src, shiftreg).UnsignedSaturate(vform);
}

LogicVRegister Simulator::sqshlu(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src, int shift) {
  DCHECK_GE(shift, 0);
  SimVRegister temp;
  LogicVRegister shiftreg = dup_immediate(vform, temp, shift);
  return sshl(vform, dst, src, shiftreg).UnsignedSaturate(vform);
}

LogicVRegister Simulator::sri(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src, int shift) {
  dst.ClearForWrite(vform);
  int laneCount = LaneCountFromFormat(vform);
  DCHECK((shift > 0) &&
         (shift <= static_cast<int>(LaneSizeInBitsFromFormat(vform))));
  for (int i = 0; i < laneCount; i++) {
    uint64_t src_lane = src.Uint(vform, i);
    uint64_t dst_lane = dst.Uint(vform, i);
    uint64_t shifted;
    uint64_t mask;
    if (shift == 64) {
      shifted = 0;
      mask = 0;
    } else {
      shifted = src_lane >> shift;
      mask = MaxUintFromFormat(vform) >> shift;
    }
    dst.SetUint(vform, i, (dst_lane & ~mask) | shifted);
  }
  return dst;
}

LogicVRegister Simulator::ushr(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src, int shift) {
  DCHECK_GE(shift, 0);
  SimVRegister temp;
  LogicVRegister shiftreg = dup_immediate(vform, temp, -shift);
  return ushl(vform, dst, src, shiftreg);
}

LogicVRegister Simulator::sshr(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src, int shift) {
  DCHECK_GE(shift, 0);
  SimVRegister temp;
  LogicVRegister shiftreg = dup_immediate(vform, temp, -shift);
  return sshl(vform, dst, src, shiftreg);
}

LogicVRegister Simulator::ssra(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src, int shift) {
  SimVRegister temp;
  LogicVRegister shifted_reg = sshr(vform, temp, src, shift);
  return add(vform, dst, dst, shifted_reg);
}

LogicVRegister Simulator::usra(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src, int shift) {
  SimVRegister temp;
  LogicVRegister shifted_reg = ushr(vform, temp, src, shift);
  return add(vform, dst, dst, shifted_reg);
}

LogicVRegister Simulator::srsra(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src, int shift) {
  SimVRegister temp;
  LogicVRegister shifted_reg = sshr(vform, temp, src, shift).Round(vform);
  return add(vform, dst, dst, shifted_reg);
}

LogicVRegister Simulator::ursra(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src, int shift) {
  SimVRegister temp;
  LogicVRegister shifted_reg = ushr(vform, temp, src, shift).Round(vform);
  return add(vform, dst, dst, shifted_reg);
}

LogicVRegister Simulator::cls(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src) {
  uint64_t result[16];
  int laneSizeInBits = LaneSizeInBitsFromFormat(vform);
  int laneCount = LaneCountFromFormat(vform);
  for (int i = 0; i < laneCount; i++) {
    result[i] = CountLeadingSignBits(src.Int(vform, i), laneSizeInBits);
  }

  dst.SetUintArray(vform, result);
  return dst;
}

LogicVRegister Simulator::clz(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src) {
  uint64_t result[16];
  int laneSizeInBits = LaneSizeInBitsFromFormat(vform);
  int laneCount = LaneCountFromFormat(vform);
  for (int i = 0; i < laneCount; i++) {
    result[i] = CountLeadingZeros(src.Uint(vform, i), laneSizeInBits);
  }

  dst.SetUintArray(vform, result);
  return dst;
}

LogicVRegister Simulator::cnt(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src) {
  uint64_t result[16];
  int laneSizeInBits = LaneSizeInBitsFromFormat(vform);
  int laneCount = LaneCountFromFormat(vform);
  for (int i = 0; i < laneCount; i++) {
    uint64_t value = src.Uint(vform, i);
    result[i] = 0;
    for (int j = 0; j < laneSizeInBits; j++) {
      result[i] += (value & 1);
      value >>= 1;
    }
  }

  dst.SetUintArray(vform, result);
  return dst;
}

LogicVRegister Simulator::sshl(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    int8_t shift_val = src2.Int(vform, i);
    int64_t lj_src_val = src1.IntLeftJustified(vform, i);

    // Set signed saturation state.
    if ((shift_val > CountLeadingSignBits(lj_src_val, 64)) &&
        (lj_src_val != 0)) {
      dst.SetSignedSat(i, lj_src_val >= 0);
    }

    // Set unsigned saturation state.
    if (lj_src_val < 0) {
      dst.SetUnsignedSat(i, false);
    } else if ((shift_val > CountLeadingZeros(lj_src_val, 64)) &&
               (lj_src_val != 0)) {
      dst.SetUnsignedSat(i, true);
    }

    int64_t src_val = src1.Int(vform, i);
    bool src_is_negative = src_val < 0;
    if (shift_val > 63) {
      dst.SetInt(vform, i, 0);
    } else if (shift_val < -63) {
      dst.SetRounding(i, src_is_negative);
      dst.SetInt(vform, i, src_is_negative ? -1 : 0);
    } else {
      // Use unsigned types for shifts, as behaviour is undefined for signed
      // lhs.
      uint64_t usrc_val = static_cast<uint64_t>(src_val);

      if (shift_val < 0) {
        // Convert to right shift.
        shift_val = -shift_val;

        // Set rounding state by testing most-significant bit shifted out.
        // Rounding only needed on right shifts.
        if (((usrc_val >> (shift_val - 1)) & 1) == 1) {
          dst.SetRounding(i, true);
        }

        usrc_val >>= shift_val;

        if (src_is_negative) {
          // Simulate sign-extension.
          usrc_val |= (~UINT64_C(0) << (64 - shift_val));
        }
      } else {
        usrc_val <<= shift_val;
      }
      dst.SetUint(vform, i, usrc_val);
    }
  }
  return dst;
}

LogicVRegister Simulator::ushl(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    int8_t shift_val = src2.Int(vform, i);
    uint64_t lj_src_val = src1.UintLeftJustified(vform, i);

    // Set saturation state.
    if ((shift_val > CountLeadingZeros(lj_src_val, 64)) && (lj_src_val != 0)) {
      dst.SetUnsignedSat(i, true);
    }

    uint64_t src_val = src1.Uint(vform, i);
    if ((shift_val > 63) || (shift_val < -64)) {
      dst.SetUint(vform, i, 0);
    } else {
      if (shift_val < 0) {
        // Set rounding state. Rounding only needed on right shifts.
        if (((src_val >> (-shift_val - 1)) & 1) == 1) {
          dst.SetRounding(i, true);
        }

        if (shift_val == -64) {
          src_val = 0;
        } else {
          src_val >>= -shift_val;
        }
      } else {
        src_val <<= shift_val;
      }
      dst.SetUint(vform, i, src_val);
    }
  }
  return dst;
}

LogicVRegister Simulator::neg(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    // Test for signed saturation.
    int64_t sa = src.Int(vform, i);
    if (sa == MinIntFromFormat(vform)) {
      dst.SetSignedSat(i, true);
    }
    dst.SetInt(vform, i, (sa == INT64_MIN) ? sa : -sa);
  }
  return dst;
}

LogicVRegister Simulator::suqadd(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    int64_t sa = dst.IntLeftJustified(vform, i);
    uint64_t ub = src.UintLeftJustified(vform, i);
    uint64_t ur = sa + ub;

    int64_t sr = base::bit_cast<int64_t>(ur);
    if (sr < sa) {  // Test for signed positive saturation.
      dst.SetInt(vform, i, MaxIntFromFormat(vform));
    } else {
      dst.SetUint(vform, i, dst.Int(vform, i) + src.Uint(vform, i));
    }
  }
  return dst;
}

LogicVRegister Simulator::usqadd(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    uint64_t ua = dst.UintLeftJustified(vform, i);
    int64_t sb = src.IntLeftJustified(vform, i);
    uint64_t ur = ua + sb;

    if ((sb > 0) && (ur <= ua)) {
      dst.SetUint(vform, i, MaxUintFromFormat(vform));  // Positive saturation.
    } else if ((sb < 0) && (ur >= ua)) {
      dst.SetUint(vform, i, 0);  // Negative saturation.
    } else {
      dst.SetUint(vform, i, dst.Uint(vform, i) + src.Int(vform, i));
    }
  }
  return dst;
}

LogicVRegister Simulator::abs(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    // Test for signed saturation.
    int64_t sa = src.Int(vform, i);
    if (sa == MinIntFromFormat(vform)) {
      dst.SetSignedSat(i, true);
    }
    if (sa < 0) {
      dst.SetInt(vform, i, (sa == INT64_MIN) ? sa : -sa);
    } else {
      dst.SetInt(vform, i, sa);
    }
  }
  return dst;
}

LogicVRegister Simulator::ExtractNarrow(VectorFormat dstform,
                                        LogicVRegister dst, bool dstIsSigned,
                                        const LogicVRegister& src,
                                        bool srcIsSigned) {
  bool upperhalf = false;
  VectorFormat srcform = kFormatUndefined;
  int64_t ssrc[8];
  uint64_t usrc[8];

  switch (dstform) {
    case kFormat8B:
      upperhalf = false;
      srcform = kFormat8H;
      break;
    case kFormat16B:
      upperhalf = true;
      srcform = kFormat8H;
      break;
    case kFormat4H:
      upperhalf = false;
      srcform = kFormat4S;
      break;
    case kFormat8H:
      upperhalf = true;
      srcform = kFormat4S;
      break;
    case kFormat2S:
      upperhalf = false;
      srcform = kFormat2D;
      break;
    case kFormat4S:
      upperhalf = true;
      srcform = kFormat2D;
      break;
    case kFormatB:
      upperhalf = false;
      srcform = kFormatH;
      break;
    case kFormatH:
      upperhalf = false;
      srcform = kFormatS;
      break;
    case kFormatS:
      upperhalf = false;
      srcform = kFormatD;
      break;
    default:
      UNIMPLEMENTED();
  }

  for (int i = 0; i < LaneCountFromFormat(srcform); i++) {
    ssrc[i] = src.Int(srcform, i);
    usrc[i] = src.Uint(srcform, i);
  }

  int offset;
  if (upperhalf) {
    offset = LaneCountFromFormat(dstform) / 2;
  } else {
    offset = 0;
    dst.ClearForWrite(dstform);
  }

  for (int i = 0; i < LaneCountFromFormat(srcform); i++) {
    // Test for signed saturation
    if (ssrc[i] > MaxIntFromFormat(dstform)) {
      dst.SetSignedSat(offset + i, true);
    } else if (ssrc[i] < MinIntFromFormat(dstform)) {
      dst.SetSignedSat(offset + i, false);
    }

    // Test for unsigned saturation
    if (srcIsSigned) {
      if (ssrc[i] > static_cast<int64_t>(MaxUintFromFormat(dstform))) {
        dst.SetUnsignedSat(offset + i, true);
      } else if (ssrc[i] < 0) {
        dst.SetUnsignedSat(offset + i, false);
      }
    } else {
      if (usrc[i] > MaxUintFromFormat(dstform)) {
        dst.SetUnsignedSat(offset + i, true);
      }
    }

    int64_t result;
    if (srcIsSigned) {
      result = ssrc[i] & MaxUintFromFormat(dstform);
    } else {
      result = usrc[i] & MaxUintFromFormat(dstform);
    }

    if (dstIsSigned) {
      dst.SetInt(dstform, offset + i, result);
    } else {
      dst.SetUint(dstform, offset + i, result);
    }
  }
  return dst;
}

LogicVRegister Simulator::xtn(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src) {
  return ExtractNarrow(vform, dst, true, src, true
"""


```