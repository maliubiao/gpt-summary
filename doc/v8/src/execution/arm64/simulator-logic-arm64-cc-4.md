Response:

### 提示词
```
这是目录为v8/src/execution/arm64/simulator-logic-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/arm64/simulator-logic-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
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