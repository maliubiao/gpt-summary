Response: The user wants to understand the functionality of the C++ code provided, which is the third part of a larger file. The file seems to be related to simulating ARM64 instructions within the V8 JavaScript engine, specifically focusing on floating-point and vector operations. I need to summarize the functionality of this code snippet and illustrate its connection to JavaScript with examples.

**Overall Functionality:**

This code defines a part of the ARM64 instruction simulator within V8. It implements various floating-point and vector (NEON) operations commonly found in ARM64 architecture. These operations are used to execute JavaScript code efficiently, especially when dealing with numerical computations and data processing.

**Breakdown of Functionality in the Provided Snippet:**

1. **Pairwise Floating-Point Operations:** Defines a macro `DEFINE_NEON_FP_PAIR_OP` to generate functions that perform an operation on pairs of floating-point numbers within a vector register. This includes operations like addition, multiplication, etc.
2. **Reduction Operations (FMinMaxV):** Implements functions to find the minimum or maximum value within a vector register. This is done by comparing pairs of elements iteratively.
3. **Lane-Specific Operations (fmul, fmla, fmls, fmulx):** Defines functions that perform fused multiply-add/subtract operations using a specific element (lane) from one of the source registers.
4. **Rounding Operations (frint):** Implements functions to round floating-point numbers in a vector based on different rounding modes.
5. **Floating-Point to Fixed-Point Conversions (fcvts, fcvtu):** Defines functions to convert floating-point numbers to signed and unsigned fixed-point integers with a specified number of fractional bits.
6. **Floating-Point Precision Conversions (fcvtl, fcvtl2, fcvtn, fcvtn2, fcvtxn, fcvtxn2):** Implements functions to convert between different floating-point precisions (half-precision, single-precision, double-precision) within vectors.
7. **Reciprocal and Reciprocal Square Root Estimates (recip_sqrt_estimate, FPRecipSqrtEstimate, frsqrte, recip_estimate, FPRecipEstimate, frecpe, ursqrte, urecpe):** Defines functions to calculate fast approximations of reciprocal and reciprocal square roots.
8. **Special Reciprocal Operation (frecpx):** Implements a special reciprocal operation that modifies the exponent bits.
9. **Fixed-Point to Floating-Point Conversions (scvtf, ucvtf):** Defines functions to convert signed and unsigned fixed-point integers to floating-point numbers.
10. **Dot Product Operation (dot, sdot):** Implements a dot product operation between elements of two vector registers.

**Relationship to JavaScript:**

These low-level simulator functions are crucial for efficiently executing JavaScript code that involves numerical computations, especially when utilizing Typed Arrays or performing operations that can be vectorized. When JavaScript code uses floating-point numbers or performs array manipulations that can be optimized using SIMD (Single Instruction, Multiple Data) techniques, the V8 engine might translate these operations into the corresponding ARM64 instructions, which are then simulated by the functions defined in this file.

**JavaScript Examples:**

```javascript
// Example 1: Basic arithmetic operations that might use vector instructions
const a = new Float32Array([1.0, 2.0, 3.0, 4.0]);
const b = new Float32Array([5.0, 6.0, 7.0, 8.0]);
const c = new Float32Array(4);

for (let i = 0; i < a.length; i++) {
  c[i] = a[i] + b[i]; // V8 might use vector addition here
}

// Example 2: Using Math functions that might involve optimized floating-point operations
const x = Math.sqrt(2.0); // V8 might use a fast reciprocal square root estimate internally

// Example 3: Using Typed Arrays for more explicit control over data
const typedArray1 = new Float64Array([1.5, 2.5, 3.5]);
const typedArray2 = new Float64Array([0.5, 0.6, 0.7]);
const resultDot = typedArray1[0] * typedArray2[0] + typedArray1[1] * typedArray2[1] + typedArray1[2] * typedArray2[2];
// V8 might use a dot product instruction for such operations if the array is large enough.
```

**In essence, this C++ code forms a critical part of V8's ability to execute JavaScript efficiently on ARM64 architectures by providing a software-level simulation of the underlying hardware instructions, especially for floating-point and vector computations.**

这是文件 `v8/src/execution/arm64/simulator-logic-arm64.cc` 的第三部分，它继续定义了 ARM64 架构模拟器中用于执行向量和浮点运算的逻辑。

**主要功能归纳:**

这一部分的代码主要集中在实现各种浮点和向量 (NEON) 指令的模拟逻辑，包括：

1. **浮点数对操作 (Pairwise Operations):** 定义了对向量寄存器中成对的浮点数进行操作的函数，例如加法、乘法等。这些操作通常用于 SIMD (单指令多数据) 处理。
2. **浮点数最小值/最大值归约 (Reduction Operations):** 实现了在向量寄存器中查找最小值或最大值的函数。
3. **浮点数乘法和乘加/乘减运算 (Multiply and Multiply-Accumulate/Subtract):** 定义了使用向量寄存器和一个标量（来自另一个向量寄存器的特定元素）进行浮点数乘法以及乘加/乘减运算的函数。
4. **浮点数舍入 (Rounding):** 提供了根据不同的舍入模式对向量寄存器中的浮点数进行舍入的函数。
5. **浮点数与定点数之间的转换 (Float-to-Fixed and Fixed-to-Float Conversions):** 实现了浮点数到带符号和无符号定点数的转换，以及定点数到浮点数的转换，可以指定小数位数和舍入模式。
6. **浮点数精度转换 (Precision Conversions):** 定义了在不同精度（半精度、单精度、双精度）的浮点数之间进行转换的函数。
7. **倒数和倒数平方根的近似计算 (Reciprocal and Reciprocal Square Root Estimates):** 提供了快速计算浮点数倒数和倒数平方根近似值的函数。这些通常用于性能敏感的图形和科学计算中。
8. **特殊的倒数运算 (Special Reciprocal Operation):** 实现了 `FRECPX` 指令的模拟，该指令返回一个浮点数，其符号位与输入相同，指数位是输入指数位的按位取反。
9. **点积运算 (Dot Product):** 实现了计算两个向量寄存器中元素点积的函数。

**与 JavaScript 的关系及示例:**

虽然这些是底层的 C++ 代码，但它们直接关系到 V8 JavaScript 引擎执行 JavaScript 代码的性能，特别是当涉及到数值计算和数组操作时。当 JavaScript 代码执行涉及浮点数运算或可以使用 SIMD 指令优化的操作时，V8 可能会将这些操作转换为相应的 ARM64 指令，然后由这些模拟器函数执行。

以下是一些 JavaScript 例子，展示了哪些操作可能最终会利用到这些底层的模拟器功能：

```javascript
// 例子 1: 简单的浮点数数组运算
const a = new Float32Array([1.0, 2.0, 3.0, 4.0]);
const b = new Float32Array([5.0, 6.0, 7.0, 8.0]);
const c = new Float32Array(4);

for (let i = 0; i < a.length; i++) {
  c[i] = a[i] + b[i]; // V8 可能会使用向量加法指令来加速
}

// 例子 2: 使用 Math 对象中的函数
const x = Math.sqrt(2.0); // 底层可能使用快速的倒数平方根估算

// 例子 3: 使用 Typed Array 进行更复杂的数值计算
const array1 = new Float64Array([1.0, 2.0, 3.0]);
const array2 = new Float64Array([4.0, 5.0, 6.0]);
let dotProduct = 0;
for (let i = 0; i < array1.length; i++) {
  dotProduct += array1[i] * array2[i]; // 对于较大的数组，V8 可能会使用向量点积指令
}

// 例子 4: 将浮点数转换为整数
const floatValue = 3.14159;
const intValue = Math.floor(floatValue); // 底层可能使用浮点数舍入指令

// 例子 5: 处理颜色或图像数据，可能涉及到向量运算
const colors = new Uint8ClampedArray([255, 0, 0, 0, 255, 0]); // RGB 颜色
// 对颜色通道进行一些操作，V8 可能会尝试向量化这些操作
```

总而言之，`simulator-logic-arm64.cc` 的这部分代码提供了 V8 引擎在 ARM64 架构上执行浮点和向量运算的基础，使得 JavaScript 能够高效地进行数值计算和数据处理。

### 提示词
```
这是目录为v8/src/execution/arm64/simulator-logic-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```
\
  LogicVRegister Simulator::FNP(VectorFormat vform, LogicVRegister dst, \
                                const LogicVRegister& src) {            \
    if (vform == kFormatS) {                                            \
      float result = OP(src.Float<float>(0), src.Float<float>(1));      \
      dst.SetFloat(0, result);                                          \
    } else {                                                            \
      DCHECK_EQ(vform, kFormatD);                                       \
      double result = OP(src.Float<double>(0), src.Float<double>(1));   \
      dst.SetFloat(0, result);                                          \
    }                                                                   \
    dst.ClearForWrite(vform);                                           \
    return dst;                                                         \
  }
NEON_FPPAIRWISE_LIST(DEFINE_NEON_FP_PAIR_OP)
#undef DEFINE_NEON_FP_PAIR_OP

LogicVRegister Simulator::FMinMaxV(VectorFormat vform, LogicVRegister dst,
                                   const LogicVRegister& src, FPMinMaxOp Op) {
  DCHECK_EQ(vform, kFormat4S);
  USE(vform);
  float result1 = (this->*Op)(src.Float<float>(0), src.Float<float>(1));
  float result2 = (this->*Op)(src.Float<float>(2), src.Float<float>(3));
  float result = (this->*Op)(result1, result2);
  dst.ClearForWrite(kFormatS);
  dst.SetFloat<float>(0, result);
  return dst;
}

LogicVRegister Simulator::fmaxv(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src) {
  return FMinMaxV(vform, dst, src, &Simulator::FPMax);
}

LogicVRegister Simulator::fminv(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src) {
  return FMinMaxV(vform, dst, src, &Simulator::FPMin);
}

LogicVRegister Simulator::fmaxnmv(VectorFormat vform, LogicVRegister dst,
                                  const LogicVRegister& src) {
  return FMinMaxV(vform, dst, src, &Simulator::FPMaxNM);
}

LogicVRegister Simulator::fminnmv(VectorFormat vform, LogicVRegister dst,
                                  const LogicVRegister& src) {
  return FMinMaxV(vform, dst, src, &Simulator::FPMinNM);
}

LogicVRegister Simulator::fmul(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2, int index) {
  dst.ClearForWrite(vform);
  SimVRegister temp;
  if (LaneSizeInBytesFromFormat(vform) == kHRegSize) {
    LogicVRegister index_reg = dup_element(kFormat8H, temp, src2, index);
    fmul<half>(vform, dst, src1, index_reg);
  } else if (LaneSizeInBytesFromFormat(vform) == kSRegSize) {
    LogicVRegister index_reg = dup_element(kFormat4S, temp, src2, index);
    fmul<float>(vform, dst, src1, index_reg);
  } else {
    DCHECK_EQ(LaneSizeInBytesFromFormat(vform), kDRegSize);
    LogicVRegister index_reg = dup_element(kFormat2D, temp, src2, index);
    fmul<double>(vform, dst, src1, index_reg);
  }
  return dst;
}

LogicVRegister Simulator::fmla(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2, int index) {
  dst.ClearForWrite(vform);
  SimVRegister temp;
  if (LaneSizeInBytesFromFormat(vform) == kHRegSize) {
    LogicVRegister index_reg = dup_element(kFormat8H, temp, src2, index);
    fmla<half>(vform, dst, src1, index_reg);
  } else if (LaneSizeInBytesFromFormat(vform) == kSRegSize) {
    LogicVRegister index_reg = dup_element(kFormat4S, temp, src2, index);
    fmla<float>(vform, dst, src1, index_reg);
  } else {
    DCHECK_EQ(LaneSizeInBytesFromFormat(vform), kDRegSize);
    LogicVRegister index_reg = dup_element(kFormat2D, temp, src2, index);
    fmla<double>(vform, dst, src1, index_reg);
  }
  return dst;
}

LogicVRegister Simulator::fmls(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2, int index) {
  dst.ClearForWrite(vform);
  SimVRegister temp;
  if (LaneSizeInBytesFromFormat(vform) == kHRegSize) {
    LogicVRegister index_reg = dup_element(kFormat8H, temp, src2, index);
    fmls<half>(vform, dst, src1, index_reg);
  } else if (LaneSizeInBytesFromFormat(vform) == kSRegSize) {
    LogicVRegister index_reg = dup_element(kFormat4S, temp, src2, index);
    fmls<float>(vform, dst, src1, index_reg);
  } else {
    DCHECK_EQ(LaneSizeInBytesFromFormat(vform), kDRegSize);
    LogicVRegister index_reg = dup_element(kFormat2D, temp, src2, index);
    fmls<double>(vform, dst, src1, index_reg);
  }
  return dst;
}

LogicVRegister Simulator::fmulx(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src1,
                                const LogicVRegister& src2, int index) {
  dst.ClearForWrite(vform);
  SimVRegister temp;
  if (LaneSizeInBytesFromFormat(vform) == kHRegSize) {
    LogicVRegister index_reg = dup_element(kFormat8H, temp, src2, index);
    fmulx<half>(vform, dst, src1, index_reg);
  } else if (LaneSizeInBytesFromFormat(vform) == kSRegSize) {
    LogicVRegister index_reg = dup_element(kFormat4S, temp, src2, index);
    fmulx<float>(vform, dst, src1, index_reg);
  } else {
    DCHECK_EQ(LaneSizeInBytesFromFormat(vform), kDRegSize);
    LogicVRegister index_reg = dup_element(kFormat2D, temp, src2, index);
    fmulx<double>(vform, dst, src1, index_reg);
  }
  return dst;
}

LogicVRegister Simulator::frint(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src,
                                FPRounding rounding_mode,
                                bool inexact_exception) {
  dst.ClearForWrite(vform);
  if (LaneSizeInBytesFromFormat(vform) == kHRegSize) {
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      half input = src.Float<half>(i);
      half rounded = FPRoundInt(input, rounding_mode);
      if (inexact_exception && !isnan(input) && (input != rounded)) {
        FPProcessException();
      }
      dst.SetFloat<half>(i, rounded);
    }
  } else if (LaneSizeInBytesFromFormat(vform) == kSRegSize) {
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      float input = src.Float<float>(i);
      float rounded = FPRoundInt(input, rounding_mode);
      if (inexact_exception && !std::isnan(input) && (input != rounded)) {
        FPProcessException();
      }
      dst.SetFloat<float>(i, rounded);
    }
  } else {
    DCHECK_EQ(LaneSizeInBytesFromFormat(vform), kDRegSize);
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      double input = src.Float<double>(i);
      double rounded = FPRoundInt(input, rounding_mode);
      if (inexact_exception && !std::isnan(input) && (input != rounded)) {
        FPProcessException();
      }
      dst.SetFloat<double>(i, rounded);
    }
  }
  return dst;
}

LogicVRegister Simulator::fcvts(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src,
                                FPRounding rounding_mode, int fbits) {
  dst.ClearForWrite(vform);
  if (LaneSizeInBytesFromFormat(vform) == kHRegSize) {
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      half op = src.Float<half>(i) * std::pow(2, fbits);
      dst.SetInt(vform, i, FPToInt16(op, rounding_mode));
    }
  } else if (LaneSizeInBytesFromFormat(vform) == kSRegSize) {
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      float op = src.Float<float>(i) * std::pow(2.0f, fbits);
      dst.SetInt(vform, i, FPToInt32(op, rounding_mode));
    }
  } else {
    DCHECK_EQ(LaneSizeInBytesFromFormat(vform), kDRegSize);
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      double op = src.Float<double>(i) * std::pow(2.0, fbits);
      dst.SetInt(vform, i, FPToInt64(op, rounding_mode));
    }
  }
  return dst;
}

LogicVRegister Simulator::fcvtu(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src,
                                FPRounding rounding_mode, int fbits) {
  dst.ClearForWrite(vform);
  if (LaneSizeInBytesFromFormat(vform) == kHRegSize) {
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      half op = src.Float<half>(i) * std::pow(2.0f, fbits);
      dst.SetUint(vform, i, FPToUInt16(op, rounding_mode));
    }
  } else if (LaneSizeInBytesFromFormat(vform) == kSRegSize) {
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      float op = src.Float<float>(i) * std::pow(2.0f, fbits);
      dst.SetUint(vform, i, FPToUInt32(op, rounding_mode));
    }
  } else {
    DCHECK_EQ(LaneSizeInBytesFromFormat(vform), kDRegSize);
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      double op = src.Float<double>(i) * std::pow(2.0, fbits);
      dst.SetUint(vform, i, FPToUInt64(op, rounding_mode));
    }
  }
  return dst;
}

LogicVRegister Simulator::fcvtl(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src) {
  if (LaneSizeInBytesFromFormat(vform) == kSRegSize) {
    for (int i = LaneCountFromFormat(vform) - 1; i >= 0; i--) {
      dst.SetFloat(i, FPToFloat(src.Float<float16>(i)));
    }
  } else {
    DCHECK_EQ(LaneSizeInBytesFromFormat(vform), kDRegSize);
    for (int i = LaneCountFromFormat(vform) - 1; i >= 0; i--) {
      dst.SetFloat(i, FPToDouble(src.Float<float>(i)));
    }
  }
  return dst;
}

LogicVRegister Simulator::fcvtl2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src) {
  int lane_count = LaneCountFromFormat(vform);
  if (LaneSizeInBytesFromFormat(vform) == kSRegSize) {
    for (int i = 0; i < lane_count; i++) {
      dst.SetFloat(i, FPToFloat(src.Float<float16>(i + lane_count)));
    }
  } else {
    DCHECK_EQ(LaneSizeInBytesFromFormat(vform), kDRegSize);
    for (int i = 0; i < lane_count; i++) {
      dst.SetFloat(i, FPToDouble(src.Float<float>(i + lane_count)));
    }
  }
  return dst;
}

LogicVRegister Simulator::fcvtn(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src) {
  if (LaneSizeInBytesFromFormat(vform) == kHRegSize) {
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      dst.SetFloat(i, FPToFloat16(src.Float<float>(i), FPTieEven));
    }
  } else {
    DCHECK_EQ(LaneSizeInBytesFromFormat(vform), kSRegSize);
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      dst.SetFloat(i, FPToFloat(src.Float<double>(i), FPTieEven));
    }
  }
  dst.ClearForWrite(vform);
  return dst;
}

LogicVRegister Simulator::fcvtn2(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src) {
  int lane_count = LaneCountFromFormat(vform) / 2;
  if (LaneSizeInBytesFromFormat(vform) == kHRegSize) {
    for (int i = lane_count - 1; i >= 0; i--) {
      dst.SetFloat(i + lane_count, FPToFloat16(src.Float<float>(i), FPTieEven));
    }
  } else {
    DCHECK_EQ(LaneSizeInBytesFromFormat(vform), kSRegSize);
    for (int i = lane_count - 1; i >= 0; i--) {
      dst.SetFloat(i + lane_count, FPToFloat(src.Float<double>(i), FPTieEven));
    }
  }
  return dst;
}

LogicVRegister Simulator::fcvtxn(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src) {
  dst.ClearForWrite(vform);
  DCHECK_EQ(LaneSizeInBytesFromFormat(vform), kSRegSize);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    dst.SetFloat(i, FPToFloat(src.Float<double>(i), FPRoundOdd));
  }
  return dst;
}

LogicVRegister Simulator::fcvtxn2(VectorFormat vform, LogicVRegister dst,
                                  const LogicVRegister& src) {
  DCHECK_EQ(LaneSizeInBytesFromFormat(vform), kSRegSize);
  int lane_count = LaneCountFromFormat(vform) / 2;
  for (int i = lane_count - 1; i >= 0; i--) {
    dst.SetFloat(i + lane_count, FPToFloat(src.Float<double>(i), FPRoundOdd));
  }
  return dst;
}

// Based on reference C function recip_sqrt_estimate from ARM ARM.
double Simulator::recip_sqrt_estimate(double a) {
  int q0, q1, s;
  double r;
  if (a < 0.5) {
    q0 = static_cast<int>(a * 512.0);
    r = 1.0 / sqrt((static_cast<double>(q0) + 0.5) / 512.0);
  } else {
    q1 = static_cast<int>(a * 256.0);
    r = 1.0 / sqrt((static_cast<double>(q1) + 0.5) / 256.0);
  }
  s = static_cast<int>(256.0 * r + 0.5);
  return static_cast<double>(s) / 256.0;
}

namespace {

inline uint64_t Bits(uint64_t val, int start_bit, int end_bit) {
  return unsigned_bitextract_64(start_bit, end_bit, val);
}

}  // anonymous namespace

template <typename T>
T Simulator::FPRecipSqrtEstimate(T op) {
  static_assert(std::is_same<float, T>::value || std::is_same<double, T>::value,
                "T must be a float or double");

  if (std::isnan(op)) {
    return FPProcessNaN(op);
  } else if (op == 0.0) {
    if (copysign(1.0, op) < 0.0) {
      return kFP64NegativeInfinity;
    } else {
      return kFP64PositiveInfinity;
    }
  } else if (copysign(1.0, op) < 0.0) {
    FPProcessException();
    return FPDefaultNaN<T>();
  } else if (std::isinf(op)) {
    return 0.0;
  } else {
    uint64_t fraction;
    int32_t exp, result_exp;

    if (sizeof(T) == sizeof(float)) {
      exp = static_cast<int32_t>(float_exp(op));
      fraction = float_mantissa(op);
      fraction <<= 29;
    } else {
      exp = static_cast<int32_t>(double_exp(op));
      fraction = double_mantissa(op);
    }

    if (exp == 0) {
      while (Bits(fraction, 51, 51) == 0) {
        fraction = Bits(fraction, 50, 0) << 1;
        exp -= 1;
      }
      fraction = Bits(fraction, 50, 0) << 1;
    }

    double scaled;
    if (Bits(exp, 0, 0) == 0) {
      scaled = double_pack(0, 1022, Bits(fraction, 51, 44) << 44);
    } else {
      scaled = double_pack(0, 1021, Bits(fraction, 51, 44) << 44);
    }

    if (sizeof(T) == sizeof(float)) {
      result_exp = (380 - exp) / 2;
    } else {
      result_exp = (3068 - exp) / 2;
    }

    uint64_t estimate = base::bit_cast<uint64_t>(recip_sqrt_estimate(scaled));

    if (sizeof(T) == sizeof(float)) {
      uint32_t exp_bits = static_cast<uint32_t>(Bits(result_exp, 7, 0));
      uint32_t est_bits = static_cast<uint32_t>(Bits(estimate, 51, 29));
      return float_pack(0, exp_bits, est_bits);
    } else {
      return double_pack(0, Bits(result_exp, 10, 0), Bits(estimate, 51, 0));
    }
  }
}

LogicVRegister Simulator::frsqrte(VectorFormat vform, LogicVRegister dst,
                                  const LogicVRegister& src) {
  dst.ClearForWrite(vform);
  if (LaneSizeInBytesFromFormat(vform) == kHRegSize) {
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      half input = src.Float<half>(i);
      dst.SetFloat<half>(i, FPRecipSqrtEstimate<float>(input));
    }
  } else if (LaneSizeInBytesFromFormat(vform) == kSRegSize) {
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      float input = src.Float<float>(i);
      dst.SetFloat(i, FPRecipSqrtEstimate<float>(input));
    }
  } else {
    DCHECK_EQ(LaneSizeInBytesFromFormat(vform), kDRegSize);
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      double input = src.Float<double>(i);
      dst.SetFloat(i, FPRecipSqrtEstimate<double>(input));
    }
  }
  return dst;
}

template <typename T>
T Simulator::FPRecipEstimate(T op, FPRounding rounding) {
  static_assert(std::is_same<float, T>::value || std::is_same<double, T>::value,
                "T must be a float or double");
  uint32_t sign;

  if (sizeof(T) == sizeof(float)) {
    sign = float_sign(op);
  } else {
    sign = double_sign(op);
  }

  if (std::isnan(op)) {
    return FPProcessNaN(op);
  } else if (std::isinf(op)) {
    return (sign == 1) ? -0.0 : 0.0;
  } else if (op == 0.0) {
    FPProcessException();  // FPExc_DivideByZero exception.
    return (sign == 1) ? kFP64NegativeInfinity : kFP64PositiveInfinity;
  } else if (((sizeof(T) == sizeof(float)) &&
              (std::fabs(op) < std::pow(2.0, -128.0))) ||
             ((sizeof(T) == sizeof(double)) &&
              (std::fabs(op) < std::pow(2.0, -1024.0)))) {
    bool overflow_to_inf = false;
    switch (rounding) {
      case FPTieEven:
        overflow_to_inf = true;
        break;
      case FPPositiveInfinity:
        overflow_to_inf = (sign == 0);
        break;
      case FPNegativeInfinity:
        overflow_to_inf = (sign == 1);
        break;
      case FPZero:
        overflow_to_inf = false;
        break;
      default:
        break;
    }
    FPProcessException();  // FPExc_Overflow and FPExc_Inexact.
    if (overflow_to_inf) {
      return (sign == 1) ? kFP64NegativeInfinity : kFP64PositiveInfinity;
    } else {
      // Return FPMaxNormal(sign).
      if (sizeof(T) == sizeof(float)) {
        return float_pack(sign, 0xFE, 0x07FFFFF);
      } else {
        return double_pack(sign, 0x7FE, 0x0FFFFFFFFFFFFFl);
      }
    }
  } else {
    uint64_t fraction;
    int32_t exp, result_exp;
    uint32_t sign;

    if (sizeof(T) == sizeof(float)) {
      sign = float_sign(op);
      exp = static_cast<int32_t>(float_exp(op));
      fraction = float_mantissa(op);
      fraction <<= 29;
    } else {
      sign = double_sign(op);
      exp = static_cast<int32_t>(double_exp(op));
      fraction = double_mantissa(op);
    }

    if (exp == 0) {
      if (Bits(fraction, 51, 51) == 0) {
        exp -= 1;
        fraction = Bits(fraction, 49, 0) << 2;
      } else {
        fraction = Bits(fraction, 50, 0) << 1;
      }
    }

    double scaled = double_pack(0, 1022, Bits(fraction, 51, 44) << 44);

    if (sizeof(T) == sizeof(float)) {
      result_exp = 253 - exp;
    } else {
      result_exp = 2045 - exp;
    }

    double estimate = recip_estimate(scaled);

    fraction = double_mantissa(estimate);
    if (result_exp == 0) {
      fraction = (UINT64_C(1) << 51) | Bits(fraction, 51, 1);
    } else if (result_exp == -1) {
      fraction = (UINT64_C(1) << 50) | Bits(fraction, 51, 2);
      result_exp = 0;
    }
    if (sizeof(T) == sizeof(float)) {
      uint32_t exp_bits = static_cast<uint32_t>(Bits(result_exp, 7, 0));
      uint32_t frac_bits = static_cast<uint32_t>(Bits(fraction, 51, 29));
      return float_pack(sign, exp_bits, frac_bits);
    } else {
      return double_pack(sign, Bits(result_exp, 10, 0), Bits(fraction, 51, 0));
    }
  }
}

LogicVRegister Simulator::frecpe(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src, FPRounding round) {
  dst.ClearForWrite(vform);
  if (LaneSizeInBytesFromFormat(vform) == kHRegSize) {
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      half input = src.Float<half>(i);
      dst.SetFloat<half>(i, FPRecipEstimate<float>(input, round));
    }
  } else if (LaneSizeInBytesFromFormat(vform) == kSRegSize) {
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      float input = src.Float<float>(i);
      dst.SetFloat(i, FPRecipEstimate<float>(input, round));
    }
  } else {
    DCHECK_EQ(LaneSizeInBytesFromFormat(vform), kDRegSize);
    for (int i = 0; i < LaneCountFromFormat(vform); i++) {
      double input = src.Float<double>(i);
      dst.SetFloat(i, FPRecipEstimate<double>(input, round));
    }
  }
  return dst;
}

LogicVRegister Simulator::ursqrte(VectorFormat vform, LogicVRegister dst,
                                  const LogicVRegister& src) {
  dst.ClearForWrite(vform);
  uint64_t operand;
  uint32_t result;
  double dp_operand, dp_result;
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    operand = src.Uint(vform, i);
    if (operand <= 0x3FFFFFFF) {
      result = 0xFFFFFFFF;
    } else {
      dp_operand = operand * std::pow(2.0, -32);
      dp_result = recip_sqrt_estimate(dp_operand) * std::pow(2.0, 31);
      result = static_cast<uint32_t>(dp_result);
    }
    dst.SetUint(vform, i, result);
  }
  return dst;
}

// Based on reference C function recip_estimate from ARM ARM.
double Simulator::recip_estimate(double a) {
  int q, s;
  double r;
  q = static_cast<int>(a * 512.0);
  r = 1.0 / ((static_cast<double>(q) + 0.5) / 512.0);
  s = static_cast<int>(256.0 * r + 0.5);
  return static_cast<double>(s) / 256.0;
}

LogicVRegister Simulator::urecpe(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src) {
  dst.ClearForWrite(vform);
  uint64_t operand;
  uint32_t result;
  double dp_operand, dp_result;
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    operand = src.Uint(vform, i);
    if (operand <= 0x7FFFFFFF) {
      result = 0xFFFFFFFF;
    } else {
      dp_operand = operand * std::pow(2.0, -32);
      dp_result = recip_estimate(dp_operand) * std::pow(2.0, 31);
      result = static_cast<uint32_t>(dp_result);
    }
    dst.SetUint(vform, i, result);
  }
  return dst;
}

template <typename T>
LogicVRegister Simulator::frecpx(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src) {
  dst.ClearForWrite(vform);
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    T op = src.Float<T>(i);
    T result;
    if (std::isnan(op)) {
      result = FPProcessNaN(op);
    } else {
      int exp;
      uint32_t sign;
      if (sizeof(T) == sizeof(float)) {
        sign = float_sign(op);
        exp = static_cast<int>(float_exp(op));
        exp = (exp == 0) ? (0xFF - 1) : static_cast<int>(Bits(~exp, 7, 0));
        result = float_pack(sign, exp, 0);
      } else {
        DCHECK_EQ(sizeof(T), sizeof(double));
        sign = double_sign(op);
        exp = static_cast<int>(double_exp(op));
        exp = (exp == 0) ? (0x7FF - 1) : static_cast<int>(Bits(~exp, 10, 0));
        result = double_pack(sign, exp, 0);
      }
    }
    dst.SetFloat(i, result);
  }
  return dst;
}

LogicVRegister Simulator::frecpx(VectorFormat vform, LogicVRegister dst,
                                 const LogicVRegister& src) {
  if (LaneSizeInBytesFromFormat(vform) == kSRegSize) {
    frecpx<float>(vform, dst, src);
  } else {
    DCHECK_EQ(LaneSizeInBytesFromFormat(vform), kDRegSize);
    frecpx<double>(vform, dst, src);
  }
  return dst;
}

LogicVRegister Simulator::scvtf(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src, int fbits,
                                FPRounding round) {
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    if (LaneSizeInBytesFromFormat(vform) == kHRegSize) {
      float16 result = FixedToFloat16(src.Int(kFormatH, i), fbits, round);
      dst.SetFloat<float16>(i, result);
    } else if (LaneSizeInBytesFromFormat(vform) == kSRegSize) {
      float result = FixedToFloat(src.Int(kFormatS, i), fbits, round);
      dst.SetFloat<float>(i, result);
    } else {
      DCHECK_EQ(LaneSizeInBytesFromFormat(vform), kDRegSize);
      double result = FixedToDouble(src.Int(kFormatD, i), fbits, round);
      dst.SetFloat<double>(i, result);
    }
  }
  return dst;
}

LogicVRegister Simulator::ucvtf(VectorFormat vform, LogicVRegister dst,
                                const LogicVRegister& src, int fbits,
                                FPRounding round) {
  for (int i = 0; i < LaneCountFromFormat(vform); i++) {
    if (LaneSizeInBytesFromFormat(vform) == kHRegSize) {
      float16 result = UFixedToFloat16(src.Uint(kFormatH, i), fbits, round);
      dst.SetFloat<float16>(i, result);
    } else if (LaneSizeInBytesFromFormat(vform) == kSRegSize) {
      float result = UFixedToFloat(src.Uint(kFormatS, i), fbits, round);
      dst.SetFloat<float>(i, result);
    } else {
      DCHECK_EQ(LaneSizeInBytesFromFormat(vform), kDRegSize);
      double result = UFixedToDouble(src.Uint(kFormatD, i), fbits, round);
      dst.SetFloat<double>(i, result);
    }
  }
  return dst;
}

LogicVRegister Simulator::dot(VectorFormat vform, LogicVRegister dst,
                              const LogicVRegister& src1,
                              const LogicVRegister& src2, bool is_src1_signed,
                              bool is_src2_signed) {
  VectorFormat quarter_vform =
      VectorFormatHalfWidthDoubleLanes(VectorFormatHalfWidthDoubleLanes(vform));

  dst.ClearForWrite(vform);
  for (int e = 0; e < LaneCountFromFormat(vform); e++) {
    uint64_t result = 0;
    int64_t element1, element2;
    for (int i = 0; i < 4; i++) {
      int index = 4 * e + i;
      if (is_src1_signed) {
        element1 = src1.Int(quarter_vform, index);
      } else {
        element1 = src1.Uint(quarter_vform, index);
      }
      if (is_src2_signed) {
        element2 = src2.Int(quarter_vform, index);
      } else {
        element2 = src2.Uint(quarter_vform, index);
      }
      result += element1 * element2;
    }
    dst.SetUint(vform, e, result + dst.Uint(vform, e));
  }
  return dst;
}

LogicVRegister Simulator::sdot(VectorFormat vform, LogicVRegister dst,
                               const LogicVRegister& src1,
                               const LogicVRegister& src2) {
  return dot(vform, dst, src1, src2, true, true);
}

}  // namespace internal
}  // namespace v8

#endif  // USE_SIMULATOR
```