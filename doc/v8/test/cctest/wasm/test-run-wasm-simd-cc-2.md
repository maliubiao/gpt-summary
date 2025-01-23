Response:
The user wants to understand the functionality of the provided C++ code snippet from a V8 source file. They have several specific questions:

1. **Functionality:** What does this code do?
2. **Torque Source:** Is it a Torque file (`.tq`)?
3. **JavaScript Relation:**  Does it relate to JavaScript functionality? If so, provide an example.
4. **Code Logic Inference:** Can I infer the input and output of any code logic?
5. **Common Programming Errors:** Does it relate to common user errors?
6. **Part of a Series:** This is part 3 of 9. Provide a summary of its function within this context.

**Thinking Process:**

1. **Analyze the Code Structure:** The code consists mainly of `WASM_EXEC_TEST` macros. This strongly suggests it's a testing file for WebAssembly (WASM) SIMD operations. Each `WASM_EXEC_TEST` likely tests a specific WASM SIMD instruction.

2. **Identify Key Functions and Macros:**
    * `RunI16x8BinOpTest`, `RunICompareOpConstImmTest`, `RunExtMulTest`, `RunExtMulAddOptimizationTest`, `RunI16x8ShiftOpTest`, `RunShiftAddTestSequence`, `RunI8x16UnOpTest`, `RunI8x16BinOpTest`, `RunI8x16ShiftOpTest`: These are helper functions for setting up and running tests. They take the execution tier and the specific WASM opcode as arguments. The presence of templates suggests these are generic functions.
    * `WASM_EXEC_TEST`:  This macro likely defines a test case.
    * `WASM_SIMD_BINOP`, `WASM_SIMD_UNOP`, `WASM_SIMD_I64x2_REPLACE_LANE`, `WASM_SIMD_I16x8_SPLAT`, `WASM_GLOBAL_SET`, `WASM_LOCAL_SET`, `WASM_ONE`, `WASM_SIMD_CHECK_LANE_S`, `WASM_SIMD_I8x16_SHUFFLE_OP`, `WASM_SIMD_CONSTANT`, `WASM_ZERO`, `WASM_SIMD_SELECT`: These are macros or functions related to building WASM instructions or setting up test conditions.
    * `kExprI16x8GtU`, `kExprI16x8RoundingAverageU`, `kExprI16x8ExtMulLowI8x16S`, etc.: These `kExpr...` constants represent specific WASM SIMD opcodes.

3. **Infer Functionality:** The code tests various binary and unary operations on `i8x16` and `i16x8` SIMD vectors, including arithmetic, comparison, bitwise shifts, saturating arithmetic, extended multiplication, dot product, and shuffles. The tests often involve comparing the results of the WASM operation against expected results calculated using standard C++ functions.

4. **Address Specific Questions:**
    * **Torque Source:** The filename ends in `.cc`, not `.tq`, so it's not a Torque source file.
    * **JavaScript Relation:** WASM SIMD is directly related to JavaScript as JavaScript engines execute WASM code. The tested operations are available in JavaScript through the WASM API.
    * **Code Logic Inference:** I can analyze specific test cases (like the `RunExtMulTest`) to infer input and expected output.
    * **Common Programming Errors:** These tests implicitly check for correct implementations of the WASM specification, which helps catch errors developers might make when implementing WASM engines. The extended multiplication tests, for example, explicitly try to catch errors in selecting the correct halves for multiplication. The saturation tests check for correct handling of overflow conditions.
    * **Part of a Series:**  As part 3, it likely focuses on a specific subset of WASM SIMD operations, possibly integer-based operations on 8-bit and 16-bit lanes, building upon foundational tests in earlier parts and leading to more complex tests in later parts.

5. **Construct the Answer:**  Organize the findings according to the user's questions, providing clear explanations and examples where requested.
```cpp
8GeU) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8GeU, UnsignedGreaterEqual);
}

WASM_EXEC_TEST(I16x8LtU) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8LtU, UnsignedLess);
}

WASM_EXEC_TEST(I16x8LeU) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8LeU, UnsignedLessEqual);
}

WASM_EXEC_TEST(I16x8EqZero) {
  RunICompareOpConstImmTest<int16_t>(execution_tier, kExprI16x8Eq,
                                     kExprI16x8Splat, Equal);
}

WASM_EXEC_TEST(I16x8NeZero) {
  RunICompareOpConstImmTest<int16_t>(execution_tier, kExprI16x8Ne,
                                     kExprI16x8Splat, NotEqual);
}

WASM_EXEC_TEST(I16x8GtZero) {
  RunICompareOpConstImmTest<int16_t>(execution_tier, kExprI16x8GtS,
                                     kExprI16x8Splat, Greater);
}

WASM_EXEC_TEST(I16x8GeZero) {
  RunICompareOpConstImmTest<int16_t>(execution_tier, kExprI16x8GeS,
                                     kExprI16x8Splat, GreaterEqual);
}

WASM_EXEC_TEST(I16x8LtZero) {
  RunICompareOpConstImmTest<int16_t>(execution_tier, kExprI16x8LtS,
                                     kExprI16x8Splat, Less);
}

WASM_EXEC_TEST(I16x8LeZero) {
  RunICompareOpConstImmTest<int16_t>(execution_tier, kExprI16x8LeS,
                                     kExprI16x8Splat, LessEqual);
}

WASM_EXEC_TEST(I16x8RoundingAverageU) {
  RunI16x8BinOpTest<uint16_t>(execution_tier, kExprI16x8RoundingAverageU,
                              RoundingAverageUnsigned);
}

WASM_EXEC_TEST(I16x8Q15MulRSatS) {
  RunI16x8BinOpTest<int16_t>(execution_tier, kExprI16x8Q15MulRSatS,
                             SaturateRoundingQMul<int16_t>);
}

namespace {
enum class MulHalf { kLow, kHigh };

// Helper to run ext mul tests. It will splat 2 input values into 2 v128, call
// the mul op on these operands, and set the result into a global.
// It will zero the top or bottom half of one of the operands, this will catch
// mistakes if we are multiply the incorrect halves.
template <typename S, typename T, typename OpType = T (*)(S, S)>
void RunExtMulTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                   OpType expected_op, WasmOpcode splat, MulHalf half) {
  WasmRunner<int32_t, S, S> r(execution_tier);
  int lane_to_zero = half == MulHalf::kLow ? 1 : 0;
  T* g = r.builder().template AddGlobal<T>(kWasmS128);

  r.Build({WASM_GLOBAL_SET(
               0, WASM_SIMD_BINOP(opcode,
                                  WASM_SIMD_I64x2_REPLACE_LANE(
                                      lane_to_zero,
                                      WASM_SIMD_UNOP(splat, WASM_LOCAL_GET(0)),
                                      WASM_I64V_1(0)),
                                  WASM_SIMD_UNOP(splat, WASM_LOCAL_GET(1)))),
           WASM_ONE});

  constexpr int lanes = kSimd128Size / sizeof(T);
  for (S x : compiler::ValueHelper::GetVector<S>()) {
    for (S y : compiler::ValueHelper::GetVector<S>()) {
      r.Call(x, y);
      T expected = expected_op(x, y);
      for (int i = 0; i < lanes; i++) {
        CHECK_EQ(expected, LANE(g, i));
      }
    }
  }
}
}  // namespace

WASM_EXEC_TEST(I16x8ExtMulLowI8x16S) {
  RunExtMulTest<int8_t, int16_t>(execution_tier, kExprI16x8ExtMulLowI8x16S,
                                 MultiplyLong, kExprI8x16Splat, MulHalf::kLow);
}

WASM_EXEC_TEST(I16x8ExtMulHighI8x16S) {
  RunExtMulTest<int8_t, int16_t>(execution_tier, kExprI16x8ExtMulHighI8x16S,
                                 MultiplyLong, kExprI8x16Splat, MulHalf::kHigh);
}

WASM_EXEC_TEST(I16x8ExtMulLowI8x16U) {
  RunExtMulTest<uint8_t, uint16_t>(execution_tier, kExprI16x8ExtMulLowI8x16U,
                                   MultiplyLong, kExprI8x16Splat,
                                   MulHalf::kLow);
}

WASM_EXEC_TEST(I16x8ExtMulHighI8x16U) {
  RunExtMulTest<uint8_t, uint16_t>(execution_tier, kExprI16x8ExtMulHighI8x16U,
                                   MultiplyLong, kExprI8x16Splat,
                                   MulHalf::kHigh);
}

WASM_EXEC_TEST(I32x4ExtMulLowI16x8S) {
  RunExtMulTest<int16_t, int32_t>(execution_tier, kExprI32x4ExtMulLowI16x8S,
                                  MultiplyLong, kExprI16x8Splat, MulHalf::kLow);
}

WASM_EXEC_TEST(I32x4ExtMulHighI16x8S) {
  RunExtMulTest<int16_t, int32_t>(execution_tier, kExprI32x4ExtMulHighI16x8S,
                                  MultiplyLong, kExprI16x8Splat,
                                  MulHalf::kHigh);
}

WASM_EXEC_TEST(I32x4ExtMulLowI16x8U) {
  RunExtMulTest<uint16_t, uint32_t>(execution_tier, kExprI32x4ExtMulLowI16x8U,
                                    MultiplyLong, kExprI16x8Splat,
                                    MulHalf::kLow);
}

WASM_EXEC_TEST(I32x4ExtMulHighI16x8U) {
  RunExtMulTest<uint16_t, uint32_t>(execution_tier, kExprI32x4ExtMulHighI16x8U,
                                    MultiplyLong, kExprI16x8Splat,
                                    MulHalf::kHigh);
}

WASM_EXEC_TEST(I64x2ExtMulLowI32x4S) {
  RunExtMulTest<int32_t, int64_t>(execution_tier, kExprI64x2ExtMulLowI32x4S,
                                  MultiplyLong, kExprI32x4Splat, MulHalf::kLow);
}

WASM_EXEC_TEST(I64x2ExtMulHighI32x4S) {
  RunExtMulTest<int32_t, int64_t>(execution_tier, kExprI64x2ExtMulHighI32x4S,
                                  MultiplyLong, kExprI32x4Splat,
                                  MulHalf::kHigh);
}

WASM_EXEC_TEST(I64x2ExtMulLowI32x4U) {
  RunExtMulTest<uint32_t, uint64_t>(execution_tier, kExprI64x2ExtMulLowI32x4U,
                                    MultiplyLong, kExprI32x4Splat,
                                    MulHalf::kLow);
}

WASM_EXEC_TEST(I64x2ExtMulHighI32x4U) {
  RunExtMulTest<uint32_t, uint64_t>(execution_tier, kExprI64x2ExtMulHighI32x4U,
                                    MultiplyLong, kExprI32x4Splat,
                                    MulHalf::kHigh);
}

namespace {
// Test add(mul(x, y, z) optimizations.
template <typename S, typename T>
void RunExtMulAddOptimizationTest(TestExecutionTier execution_tier,
                                  WasmOpcode ext_mul, WasmOpcode narrow_splat,
                                  WasmOpcode wide_splat, WasmOpcode wide_add,
                                  std::function<T(T, T)> addop) {
  WasmRunner<int32_t, S, T> r(execution_tier);
  T* g = r.builder().template AddGlobal<T>(kWasmS128);

  // global[0] =
  //   add(
  //     splat(local[1]),
  //     extmul(splat(local[0]), splat(local[0])))
  r.Build(
      {WASM_GLOBAL_SET(
           0, WASM_SIMD_BINOP(
                  wide_add, WASM_SIMD_UNOP(wide_splat, WASM_LOCAL_GET(1)),
                  WASM_SIMD_BINOP(
                      ext_mul, WASM_SIMD_UNOP(narrow_splat, WASM_LOCAL_GET(0)),
                      WASM_SIMD_UNOP(narrow_splat, WASM_LOCAL_GET(0))))),
       WASM_ONE});

  constexpr int lanes = kSimd128Size / sizeof(T);
  for (S x : compiler::ValueHelper::GetVector<S>()) {
    for (T y : compiler::ValueHelper::GetVector<T>()) {
      r.Call(x, y);

      T expected = addop(MultiplyLong<T, S>(x, x), y);
      for (int i = 0; i < lanes; i++) {
        CHECK_EQ(expected, LANE(g, i));
      }
    }
  }
}
}  // namespace

// Helper which defines high/low, signed/unsigned test cases for extmul + add
// optimization.
#define EXTMUL_ADD_OPTIMIZATION_TEST(NarrowType, NarrowShape, WideType,  \
                                     WideShape)                          \
  WASM_EXEC_TEST(WideShape##ExtMulLow##NarrowShape##SAddOptimization) {  \
    RunExtMulAddOptimizationTest<NarrowType, WideType>(                  \
        execution_tier, kExpr##WideShape##ExtMulLow##NarrowShape##S,     \
        kExpr##NarrowShape##Splat, kExpr##WideShape##Splat,              \
        kExpr##WideShape##Add, base::AddWithWraparound<WideType>);       \
  }                                                                      \
  WASM_EXEC_TEST(WideShape##ExtMulHigh##NarrowShape##SAddOptimization) { \
    RunExtMulAddOptimizationTest<NarrowType, WideType>(                  \
        execution_tier, kExpr##WideShape##ExtMulHigh##NarrowShape##S,    \
        kExpr##NarrowShape##Splat, kExpr##WideShape##Splat,              \
        kExpr##WideShape##Add, base::AddWithWraparound<WideType>);       \
  }                                                                      \
  WASM_EXEC_TEST(WideShape##ExtMulLow##NarrowShape##UAddOptimization) {  \
    RunExtMulAddOptimizationTest<u##NarrowType, u##WideType>(            \
        execution_tier, kExpr##WideShape##ExtMulLow##NarrowShape##U,     \
        kExpr##NarrowShape##Splat, kExpr##WideShape##Splat,              \
        kExpr##WideShape##Add, std::plus<u##WideType>());                \
  }                                                                      \
  WASM_EXEC_TEST(WideShape##ExtMulHigh##NarrowShape##UAddOptimization) { \
    RunExtMulAddOptimizationTest<u##NarrowType, u##WideType>(            \
        execution_tier, kExpr##WideShape##ExtMulHigh##NarrowShape##U,    \
        kExpr##NarrowShape##Splat, kExpr##WideShape##Splat,              \
        kExpr##WideShape##Add, std::plus<u##WideType>());                \
  }

EXTMUL_ADD_OPTIMIZATION_TEST(int8_t, I8x16, int16_t, I16x8)
EXTMUL_ADD_OPTIMIZATION_TEST(int16_t, I16x8, int32_t, I32x4)

#undef EXTMUL_ADD_OPTIMIZATION_TEST

WASM_EXEC_TEST(I32x4DotI16x8S) {
  WasmRunner<int32_t, int16_t, int16_t> r(execution_tier);
  int32_t* g = r.builder().template AddGlobal<int32_t>(kWasmS128);
  uint8_t value1 = 0, value2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I16x8_SPLAT(WASM_LOCAL_GET(value1))),
           WASM_LOCAL_SET(temp2, WASM_SIMD_I16x8_SPLAT(WASM_LOCAL_GET(value2))),
           WASM_GLOBAL_SET(
               0, WASM_SIMD_BINOP(kExprI32x4DotI16x8S, WASM_LOCAL_GET(temp1),
                                  WASM_LOCAL_GET(temp2))),
           WASM_ONE});

  for (int16_t x : compiler::ValueHelper::GetVector<int16_t>()) {
    for (int16_t y : compiler::ValueHelper::GetVector<int16_t>()) {
      r.Call(x, y);
      // x * y * 2 can overflow (0x8000), the behavior is to wraparound.
      int32_t expected = base::MulWithWraparound(x * y, 2);
      for (int i = 0; i < 4; i++) {
        CHECK_EQ(expected, LANE(g, i));
      }
    }
  }
}

WASM_EXEC_TEST(I16x8Shl) {
  RunI16x8ShiftOpTest(execution_tier, kExprI16x8Shl, LogicalShiftLeft);
}

WASM_EXEC_TEST(I16x8ShrS) {
  RunI16x8ShiftOpTest(execution_tier, kExprI16x8ShrS, ArithmeticShiftRight);
}

WASM_EXEC_TEST(I16x8ShrU) {
  RunI16x8ShiftOpTest(execution_tier, kExprI16x8ShrU, LogicalShiftRight);
}

WASM_EXEC_TEST(I16x8ShiftAdd) {
  for (int imm = 0; imm <= 16; imm++) {
    RunShiftAddTestSequence<int16_t>(execution_tier, kExprI16x8ShrU,
                                     kExprI16x8Add, kExprI16x8Splat, imm,
                                     LogicalShiftRight);
    RunShiftAddTestSequence<int16_t>(execution_tier, kExprI16x8ShrS,
                                     kExprI16x8Add, kExprI16x8Splat, imm,
                                     ArithmeticShiftRight);
  }
}

WASM_EXEC_TEST(I8x16Neg) {
  RunI8x16UnOpTest(execution_tier, kExprI8x16Neg, base::NegateWithWraparound);
}

WASM_EXEC_TEST(I8x16Abs) {
  RunI8x16UnOpTest(execution_tier, kExprI8x16Abs, Abs);
}

WASM_EXEC_TEST(I8x16Popcnt) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // Global to hold output.
  int8_t* g = r.builder().AddGlobal<int8_t>(kWasmS128);
  // Build fn to splat test value, perform unop, and write the result.
  uint8_t value = 0;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(value))),
           WASM_GLOBAL_SET(
               0, WASM_SIMD_UNOP(kExprI8x16Popcnt, WASM_LOCAL_GET(temp1))),
           WASM_ONE});

  FOR_UINT8_INPUTS(x) {
    r.Call(x);
    unsigned expected = base::bits::CountPopulation(x);
    for (int i = 0; i < 16; i++) {
      CHECK_EQ(expected, LANE(g, i));
    }
  }
}

// Tests both signed and unsigned conversion from I16x8 (packing).
WASM_EXEC_TEST(I8x16ConvertI16x8) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // Create output vectors to hold signed and unsigned results.
  int8_t* g_s = r.builder().AddGlobal<int8_t>(kWasmS128);
  uint8_t* g_u = r.builder().AddGlobal<uint8_t>(kWasmS128);
  // Build fn to splat test value, perform conversions, and write the results.
  uint8_t value = 0;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I16x8_SPLAT(WASM_LOCAL_GET(value))),
           WASM_GLOBAL_SET(0, WASM_SIMD_BINOP(kExprI8x16SConvertI16x8,
                                              WASM_LOCAL_GET(temp1),
                                              WASM_LOCAL_GET(temp1))),
           WASM_GLOBAL_SET(1, WASM_SIMD_BINOP(kExprI8x16UConvertI16x8,
                                              WASM_LOCAL_GET(temp1),
                                              WASM_LOCAL_GET(temp1))),
           WASM_ONE});

  FOR_INT16_INPUTS(x) {
    r.Call(x);
    int8_t expected_signed = base::saturated_cast<int8_t>(x);
    uint8_t expected_unsigned = base::saturated_cast<uint8_t>(x);
    for (int i = 0; i < 16; i++) {
      CHECK_EQ(expected_signed, LANE(g_s, i));
      CHECK_EQ(expected_unsigned, LANE(g_u, i));
    }
  }
}

WASM_EXEC_TEST(I8x16Add) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16Add, base::AddWithWraparound);
}

WASM_EXEC_TEST(I8x16AddSatS) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16AddSatS, SaturateAdd<int8_t>);
}

WASM_EXEC_TEST(I8x16Sub) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16Sub, base::SubWithWraparound);
}

WASM_EXEC_TEST(I8x16SubSatS) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16SubSatS, SaturateSub<int8_t>);
}

WASM_EXEC_TEST(I8x16MinS) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16MinS, Minimum);
}

WASM_EXEC_TEST(I8x16MaxS) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16MaxS, Maximum);
}

WASM_EXEC_TEST(I8x16AddSatU) {
  RunI8x16BinOpTest<uint8_t>(execution_tier, kExprI8x16AddSatU,
                             SaturateAdd<uint8_t>);
}

WASM_EXEC_TEST(I8x16SubSatU) {
  RunI8x16BinOpTest<uint8_t>(execution_tier, kExprI8x16SubSatU,
                             SaturateSub<uint8_t>);
}

WASM_EXEC_TEST(I8x16MinU) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16MinU, UnsignedMinimum);
}

WASM_EXEC_TEST(I8x16MaxU) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16MaxU, UnsignedMaximum);
}

WASM_EXEC_TEST(I8x16Eq) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16Eq, Equal);
}

WASM_EXEC_TEST(I8x16Ne) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16Ne, NotEqual);
}

WASM_EXEC_TEST(I8x16GtS) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16GtS, Greater);
}

WASM_EXEC_TEST(I8x16GeS) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16GeS, GreaterEqual);
}

WASM_EXEC_TEST(I8x16LtS) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16LtS, Less);
}

WASM_EXEC_TEST(I8x16LeS) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16LeS, LessEqual);
}

WASM_EXEC_TEST(I8x16GtU) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16GtU, UnsignedGreater);
}

WASM_EXEC_TEST(I8x16GeU) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16GeU, UnsignedGreaterEqual);
}

WASM_EXEC_TEST(I8x16LtU) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16LtU, UnsignedLess);
}

WASM_EXEC_TEST(I8x16LeU) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16LeU, UnsignedLessEqual);
}

WASM_EXEC_TEST(I8x16EqZero) {
  RunICompareOpConstImmTest<int8_t>(execution_tier, kExprI8x16Eq,
                                    kExprI8x16Splat, Equal);
}

WASM_EXEC_TEST(I8x16NeZero) {
  RunICompareOpConstImmTest<int8_t>(execution_tier, kExprI8x16Ne,
                                    kExprI8x16Splat, NotEqual);
}

WASM_EXEC_TEST(I8x16GtZero) {
  RunICompareOpConstImmTest<int8_t>(execution_tier, kExprI8x16GtS,
                                    kExprI8x16Splat, Greater);
}

WASM_EXEC_TEST(I8x16GeZero) {
  RunICompareOpConstImmTest<int8_t>(execution_tier, kExprI8x16GeS,
                                    kExprI8x16Splat, GreaterEqual);
}

WASM_EXEC_TEST(I8x16LtZero) {
  RunICompareOpConstImmTest<int8_t>(execution_tier, kExprI8x16LtS,
                                    kExprI8x16Splat, Less);
}

WASM_EXEC_TEST(I8x16LeZero) {
  RunICompareOpConstImmTest<int8_t>(execution_tier, kExprI8x16LeS,
                                    kExprI8x16Splat, LessEqual);
}

WASM_EXEC_TEST(I8x16RoundingAverageU) {
  RunI8x16BinOpTest<uint8_t>(execution_tier, kExprI8x16RoundingAverageU,
                             RoundingAverageUnsigned);
}

WASM_EXEC_TEST(I8x16Shl) {
  RunI8x16ShiftOpTest(execution_tier, kExprI8x16Shl, LogicalShiftLeft);
}

WASM_EXEC_TEST(I8x16ShrS) {
  RunI8x16ShiftOpTest(execution_tier, kExprI8x16ShrS, ArithmeticShiftRight);
}

WASM_EXEC_TEST(I8x16ShrU) {
  RunI8x16ShiftOpTest(execution_tier, kExprI8x16ShrU, LogicalShiftRight);
}

WASM_EXEC_TEST(I8x16ShiftAdd) {
  for (int imm = 0; imm <= 8; imm++) {
    RunShiftAddTestSequence<int8_t>(execution_tier, kExprI8x16ShrU,
                                    kExprI8x16Add, kExprI8x16Splat, imm,
                                    LogicalShiftRight);
    RunShiftAddTestSequence<int8_t>(execution_tier, kExprI8x16ShrS,
                                    kExprI8x16Add, kExprI8x16Splat, imm,
                                    ArithmeticShiftRight);
  }
}

// Test Select by making a mask where the 0th and 3rd lanes are true and the
// rest false, and comparing for non-equality with zero to convert to a boolean
// vector.
#define WASM_SIMD_SELECT_TEST(format)                                       \
  WASM_EXEC_TEST(S##format##Select) {                                       \
    WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);                \
    uint8_t val1 = 0;                                                       \
    uint8_t val2 = 1;                                                       \
    uint8_t src1 = r.AllocateLocal(kWasmS128);                              \
    uint8_t src2 = r.AllocateLocal(kWasmS128);                              \
    uint8_t zero = r.AllocateLocal(kWasmS128);                              \
    uint8_t mask = r.AllocateLocal(kWasmS128);                              \
    r.Build(                                                                \
        {WASM_LOCAL_SET(src1,                                               \
                        WASM_SIMD_I##format##_SPLAT(WASM_LOCAL_GET(val1))), \
         WASM_LOCAL_SET(src2,                                               \
                        WASM_SIMD_I##format##_SPLAT(WASM_LOCAL_GET(val2))), \
         WASM_LOCAL_SET(zero, WASM_SIMD_I##format##_SPLAT(WASM_ZERO)),      \
         WASM_LOCAL_SET(mask, WASM_SIMD_I##format##_REPLACE_LANE(           \
                                  1, WASM_LOCAL_GET(zero), WASM_I32V(-1))), \
         WASM_LOCAL_SET(mask, WASM_SIMD_I##format##_REPLACE_LANE(           \
                                  2, WASM_LOCAL_GET(mask), WASM_I32V(-1))), \
         WASM_LOCAL_SET(                                                    \
             mask,                                                          \
             WASM_SIMD_SELECT(                                              \
                 format, WASM_LOCAL_GET(src1), WASM_LOCAL_GET(src2),        \
                 WASM_SIMD_BINOP(kExprI##format##Ne, WASM_LOCAL_GET(mask),  \
                                 WASM_LOCAL_GET(zero)))),                   \
         WASM_SIMD_CHECK_LANE_S(I##format, mask, I32, val2, 0),             \
         WASM_SIMD_
### 提示词
```
这是目录为v8/test/cctest/wasm/test-run-wasm-simd.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/test-run-wasm-simd.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
8GeU) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8GeU, UnsignedGreaterEqual);
}

WASM_EXEC_TEST(I16x8LtU) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8LtU, UnsignedLess);
}

WASM_EXEC_TEST(I16x8LeU) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8LeU, UnsignedLessEqual);
}

WASM_EXEC_TEST(I16x8EqZero) {
  RunICompareOpConstImmTest<int16_t>(execution_tier, kExprI16x8Eq,
                                     kExprI16x8Splat, Equal);
}

WASM_EXEC_TEST(I16x8NeZero) {
  RunICompareOpConstImmTest<int16_t>(execution_tier, kExprI16x8Ne,
                                     kExprI16x8Splat, NotEqual);
}

WASM_EXEC_TEST(I16x8GtZero) {
  RunICompareOpConstImmTest<int16_t>(execution_tier, kExprI16x8GtS,
                                     kExprI16x8Splat, Greater);
}

WASM_EXEC_TEST(I16x8GeZero) {
  RunICompareOpConstImmTest<int16_t>(execution_tier, kExprI16x8GeS,
                                     kExprI16x8Splat, GreaterEqual);
}

WASM_EXEC_TEST(I16x8LtZero) {
  RunICompareOpConstImmTest<int16_t>(execution_tier, kExprI16x8LtS,
                                     kExprI16x8Splat, Less);
}

WASM_EXEC_TEST(I16x8LeZero) {
  RunICompareOpConstImmTest<int16_t>(execution_tier, kExprI16x8LeS,
                                     kExprI16x8Splat, LessEqual);
}

WASM_EXEC_TEST(I16x8RoundingAverageU) {
  RunI16x8BinOpTest<uint16_t>(execution_tier, kExprI16x8RoundingAverageU,
                              RoundingAverageUnsigned);
}

WASM_EXEC_TEST(I16x8Q15MulRSatS) {
  RunI16x8BinOpTest<int16_t>(execution_tier, kExprI16x8Q15MulRSatS,
                             SaturateRoundingQMul<int16_t>);
}

namespace {
enum class MulHalf { kLow, kHigh };

// Helper to run ext mul tests. It will splat 2 input values into 2 v128, call
// the mul op on these operands, and set the result into a global.
// It will zero the top or bottom half of one of the operands, this will catch
// mistakes if we are multiply the incorrect halves.
template <typename S, typename T, typename OpType = T (*)(S, S)>
void RunExtMulTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                   OpType expected_op, WasmOpcode splat, MulHalf half) {
  WasmRunner<int32_t, S, S> r(execution_tier);
  int lane_to_zero = half == MulHalf::kLow ? 1 : 0;
  T* g = r.builder().template AddGlobal<T>(kWasmS128);

  r.Build({WASM_GLOBAL_SET(
               0, WASM_SIMD_BINOP(opcode,
                                  WASM_SIMD_I64x2_REPLACE_LANE(
                                      lane_to_zero,
                                      WASM_SIMD_UNOP(splat, WASM_LOCAL_GET(0)),
                                      WASM_I64V_1(0)),
                                  WASM_SIMD_UNOP(splat, WASM_LOCAL_GET(1)))),
           WASM_ONE});

  constexpr int lanes = kSimd128Size / sizeof(T);
  for (S x : compiler::ValueHelper::GetVector<S>()) {
    for (S y : compiler::ValueHelper::GetVector<S>()) {
      r.Call(x, y);
      T expected = expected_op(x, y);
      for (int i = 0; i < lanes; i++) {
        CHECK_EQ(expected, LANE(g, i));
      }
    }
  }
}
}  // namespace

WASM_EXEC_TEST(I16x8ExtMulLowI8x16S) {
  RunExtMulTest<int8_t, int16_t>(execution_tier, kExprI16x8ExtMulLowI8x16S,
                                 MultiplyLong, kExprI8x16Splat, MulHalf::kLow);
}

WASM_EXEC_TEST(I16x8ExtMulHighI8x16S) {
  RunExtMulTest<int8_t, int16_t>(execution_tier, kExprI16x8ExtMulHighI8x16S,
                                 MultiplyLong, kExprI8x16Splat, MulHalf::kHigh);
}

WASM_EXEC_TEST(I16x8ExtMulLowI8x16U) {
  RunExtMulTest<uint8_t, uint16_t>(execution_tier, kExprI16x8ExtMulLowI8x16U,
                                   MultiplyLong, kExprI8x16Splat,
                                   MulHalf::kLow);
}

WASM_EXEC_TEST(I16x8ExtMulHighI8x16U) {
  RunExtMulTest<uint8_t, uint16_t>(execution_tier, kExprI16x8ExtMulHighI8x16U,
                                   MultiplyLong, kExprI8x16Splat,
                                   MulHalf::kHigh);
}

WASM_EXEC_TEST(I32x4ExtMulLowI16x8S) {
  RunExtMulTest<int16_t, int32_t>(execution_tier, kExprI32x4ExtMulLowI16x8S,
                                  MultiplyLong, kExprI16x8Splat, MulHalf::kLow);
}

WASM_EXEC_TEST(I32x4ExtMulHighI16x8S) {
  RunExtMulTest<int16_t, int32_t>(execution_tier, kExprI32x4ExtMulHighI16x8S,
                                  MultiplyLong, kExprI16x8Splat,
                                  MulHalf::kHigh);
}

WASM_EXEC_TEST(I32x4ExtMulLowI16x8U) {
  RunExtMulTest<uint16_t, uint32_t>(execution_tier, kExprI32x4ExtMulLowI16x8U,
                                    MultiplyLong, kExprI16x8Splat,
                                    MulHalf::kLow);
}

WASM_EXEC_TEST(I32x4ExtMulHighI16x8U) {
  RunExtMulTest<uint16_t, uint32_t>(execution_tier, kExprI32x4ExtMulHighI16x8U,
                                    MultiplyLong, kExprI16x8Splat,
                                    MulHalf::kHigh);
}

WASM_EXEC_TEST(I64x2ExtMulLowI32x4S) {
  RunExtMulTest<int32_t, int64_t>(execution_tier, kExprI64x2ExtMulLowI32x4S,
                                  MultiplyLong, kExprI32x4Splat, MulHalf::kLow);
}

WASM_EXEC_TEST(I64x2ExtMulHighI32x4S) {
  RunExtMulTest<int32_t, int64_t>(execution_tier, kExprI64x2ExtMulHighI32x4S,
                                  MultiplyLong, kExprI32x4Splat,
                                  MulHalf::kHigh);
}

WASM_EXEC_TEST(I64x2ExtMulLowI32x4U) {
  RunExtMulTest<uint32_t, uint64_t>(execution_tier, kExprI64x2ExtMulLowI32x4U,
                                    MultiplyLong, kExprI32x4Splat,
                                    MulHalf::kLow);
}

WASM_EXEC_TEST(I64x2ExtMulHighI32x4U) {
  RunExtMulTest<uint32_t, uint64_t>(execution_tier, kExprI64x2ExtMulHighI32x4U,
                                    MultiplyLong, kExprI32x4Splat,
                                    MulHalf::kHigh);
}

namespace {
// Test add(mul(x, y, z) optimizations.
template <typename S, typename T>
void RunExtMulAddOptimizationTest(TestExecutionTier execution_tier,
                                  WasmOpcode ext_mul, WasmOpcode narrow_splat,
                                  WasmOpcode wide_splat, WasmOpcode wide_add,
                                  std::function<T(T, T)> addop) {
  WasmRunner<int32_t, S, T> r(execution_tier);
  T* g = r.builder().template AddGlobal<T>(kWasmS128);

  // global[0] =
  //   add(
  //     splat(local[1]),
  //     extmul(splat(local[0]), splat(local[0])))
  r.Build(
      {WASM_GLOBAL_SET(
           0, WASM_SIMD_BINOP(
                  wide_add, WASM_SIMD_UNOP(wide_splat, WASM_LOCAL_GET(1)),
                  WASM_SIMD_BINOP(
                      ext_mul, WASM_SIMD_UNOP(narrow_splat, WASM_LOCAL_GET(0)),
                      WASM_SIMD_UNOP(narrow_splat, WASM_LOCAL_GET(0))))),
       WASM_ONE});

  constexpr int lanes = kSimd128Size / sizeof(T);
  for (S x : compiler::ValueHelper::GetVector<S>()) {
    for (T y : compiler::ValueHelper::GetVector<T>()) {
      r.Call(x, y);

      T expected = addop(MultiplyLong<T, S>(x, x), y);
      for (int i = 0; i < lanes; i++) {
        CHECK_EQ(expected, LANE(g, i));
      }
    }
  }
}
}  // namespace

// Helper which defines high/low, signed/unsigned test cases for extmul + add
// optimization.
#define EXTMUL_ADD_OPTIMIZATION_TEST(NarrowType, NarrowShape, WideType,  \
                                     WideShape)                          \
  WASM_EXEC_TEST(WideShape##ExtMulLow##NarrowShape##SAddOptimization) {  \
    RunExtMulAddOptimizationTest<NarrowType, WideType>(                  \
        execution_tier, kExpr##WideShape##ExtMulLow##NarrowShape##S,     \
        kExpr##NarrowShape##Splat, kExpr##WideShape##Splat,              \
        kExpr##WideShape##Add, base::AddWithWraparound<WideType>);       \
  }                                                                      \
  WASM_EXEC_TEST(WideShape##ExtMulHigh##NarrowShape##SAddOptimization) { \
    RunExtMulAddOptimizationTest<NarrowType, WideType>(                  \
        execution_tier, kExpr##WideShape##ExtMulHigh##NarrowShape##S,    \
        kExpr##NarrowShape##Splat, kExpr##WideShape##Splat,              \
        kExpr##WideShape##Add, base::AddWithWraparound<WideType>);       \
  }                                                                      \
  WASM_EXEC_TEST(WideShape##ExtMulLow##NarrowShape##UAddOptimization) {  \
    RunExtMulAddOptimizationTest<u##NarrowType, u##WideType>(            \
        execution_tier, kExpr##WideShape##ExtMulLow##NarrowShape##U,     \
        kExpr##NarrowShape##Splat, kExpr##WideShape##Splat,              \
        kExpr##WideShape##Add, std::plus<u##WideType>());                \
  }                                                                      \
  WASM_EXEC_TEST(WideShape##ExtMulHigh##NarrowShape##UAddOptimization) { \
    RunExtMulAddOptimizationTest<u##NarrowType, u##WideType>(            \
        execution_tier, kExpr##WideShape##ExtMulHigh##NarrowShape##U,    \
        kExpr##NarrowShape##Splat, kExpr##WideShape##Splat,              \
        kExpr##WideShape##Add, std::plus<u##WideType>());                \
  }

EXTMUL_ADD_OPTIMIZATION_TEST(int8_t, I8x16, int16_t, I16x8)
EXTMUL_ADD_OPTIMIZATION_TEST(int16_t, I16x8, int32_t, I32x4)

#undef EXTMUL_ADD_OPTIMIZATION_TEST

WASM_EXEC_TEST(I32x4DotI16x8S) {
  WasmRunner<int32_t, int16_t, int16_t> r(execution_tier);
  int32_t* g = r.builder().template AddGlobal<int32_t>(kWasmS128);
  uint8_t value1 = 0, value2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I16x8_SPLAT(WASM_LOCAL_GET(value1))),
           WASM_LOCAL_SET(temp2, WASM_SIMD_I16x8_SPLAT(WASM_LOCAL_GET(value2))),
           WASM_GLOBAL_SET(
               0, WASM_SIMD_BINOP(kExprI32x4DotI16x8S, WASM_LOCAL_GET(temp1),
                                  WASM_LOCAL_GET(temp2))),
           WASM_ONE});

  for (int16_t x : compiler::ValueHelper::GetVector<int16_t>()) {
    for (int16_t y : compiler::ValueHelper::GetVector<int16_t>()) {
      r.Call(x, y);
      // x * y * 2 can overflow (0x8000), the behavior is to wraparound.
      int32_t expected = base::MulWithWraparound(x * y, 2);
      for (int i = 0; i < 4; i++) {
        CHECK_EQ(expected, LANE(g, i));
      }
    }
  }
}

WASM_EXEC_TEST(I16x8Shl) {
  RunI16x8ShiftOpTest(execution_tier, kExprI16x8Shl, LogicalShiftLeft);
}

WASM_EXEC_TEST(I16x8ShrS) {
  RunI16x8ShiftOpTest(execution_tier, kExprI16x8ShrS, ArithmeticShiftRight);
}

WASM_EXEC_TEST(I16x8ShrU) {
  RunI16x8ShiftOpTest(execution_tier, kExprI16x8ShrU, LogicalShiftRight);
}

WASM_EXEC_TEST(I16x8ShiftAdd) {
  for (int imm = 0; imm <= 16; imm++) {
    RunShiftAddTestSequence<int16_t>(execution_tier, kExprI16x8ShrU,
                                     kExprI16x8Add, kExprI16x8Splat, imm,
                                     LogicalShiftRight);
    RunShiftAddTestSequence<int16_t>(execution_tier, kExprI16x8ShrS,
                                     kExprI16x8Add, kExprI16x8Splat, imm,
                                     ArithmeticShiftRight);
  }
}

WASM_EXEC_TEST(I8x16Neg) {
  RunI8x16UnOpTest(execution_tier, kExprI8x16Neg, base::NegateWithWraparound);
}

WASM_EXEC_TEST(I8x16Abs) {
  RunI8x16UnOpTest(execution_tier, kExprI8x16Abs, Abs);
}

WASM_EXEC_TEST(I8x16Popcnt) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // Global to hold output.
  int8_t* g = r.builder().AddGlobal<int8_t>(kWasmS128);
  // Build fn to splat test value, perform unop, and write the result.
  uint8_t value = 0;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(value))),
           WASM_GLOBAL_SET(
               0, WASM_SIMD_UNOP(kExprI8x16Popcnt, WASM_LOCAL_GET(temp1))),
           WASM_ONE});

  FOR_UINT8_INPUTS(x) {
    r.Call(x);
    unsigned expected = base::bits::CountPopulation(x);
    for (int i = 0; i < 16; i++) {
      CHECK_EQ(expected, LANE(g, i));
    }
  }
}

// Tests both signed and unsigned conversion from I16x8 (packing).
WASM_EXEC_TEST(I8x16ConvertI16x8) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // Create output vectors to hold signed and unsigned results.
  int8_t* g_s = r.builder().AddGlobal<int8_t>(kWasmS128);
  uint8_t* g_u = r.builder().AddGlobal<uint8_t>(kWasmS128);
  // Build fn to splat test value, perform conversions, and write the results.
  uint8_t value = 0;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I16x8_SPLAT(WASM_LOCAL_GET(value))),
           WASM_GLOBAL_SET(0, WASM_SIMD_BINOP(kExprI8x16SConvertI16x8,
                                              WASM_LOCAL_GET(temp1),
                                              WASM_LOCAL_GET(temp1))),
           WASM_GLOBAL_SET(1, WASM_SIMD_BINOP(kExprI8x16UConvertI16x8,
                                              WASM_LOCAL_GET(temp1),
                                              WASM_LOCAL_GET(temp1))),
           WASM_ONE});

  FOR_INT16_INPUTS(x) {
    r.Call(x);
    int8_t expected_signed = base::saturated_cast<int8_t>(x);
    uint8_t expected_unsigned = base::saturated_cast<uint8_t>(x);
    for (int i = 0; i < 16; i++) {
      CHECK_EQ(expected_signed, LANE(g_s, i));
      CHECK_EQ(expected_unsigned, LANE(g_u, i));
    }
  }
}

WASM_EXEC_TEST(I8x16Add) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16Add, base::AddWithWraparound);
}

WASM_EXEC_TEST(I8x16AddSatS) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16AddSatS, SaturateAdd<int8_t>);
}

WASM_EXEC_TEST(I8x16Sub) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16Sub, base::SubWithWraparound);
}

WASM_EXEC_TEST(I8x16SubSatS) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16SubSatS, SaturateSub<int8_t>);
}

WASM_EXEC_TEST(I8x16MinS) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16MinS, Minimum);
}

WASM_EXEC_TEST(I8x16MaxS) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16MaxS, Maximum);
}

WASM_EXEC_TEST(I8x16AddSatU) {
  RunI8x16BinOpTest<uint8_t>(execution_tier, kExprI8x16AddSatU,
                             SaturateAdd<uint8_t>);
}

WASM_EXEC_TEST(I8x16SubSatU) {
  RunI8x16BinOpTest<uint8_t>(execution_tier, kExprI8x16SubSatU,
                             SaturateSub<uint8_t>);
}

WASM_EXEC_TEST(I8x16MinU) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16MinU, UnsignedMinimum);
}

WASM_EXEC_TEST(I8x16MaxU) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16MaxU, UnsignedMaximum);
}

WASM_EXEC_TEST(I8x16Eq) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16Eq, Equal);
}

WASM_EXEC_TEST(I8x16Ne) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16Ne, NotEqual);
}

WASM_EXEC_TEST(I8x16GtS) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16GtS, Greater);
}

WASM_EXEC_TEST(I8x16GeS) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16GeS, GreaterEqual);
}

WASM_EXEC_TEST(I8x16LtS) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16LtS, Less);
}

WASM_EXEC_TEST(I8x16LeS) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16LeS, LessEqual);
}

WASM_EXEC_TEST(I8x16GtU) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16GtU, UnsignedGreater);
}

WASM_EXEC_TEST(I8x16GeU) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16GeU, UnsignedGreaterEqual);
}

WASM_EXEC_TEST(I8x16LtU) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16LtU, UnsignedLess);
}

WASM_EXEC_TEST(I8x16LeU) {
  RunI8x16BinOpTest(execution_tier, kExprI8x16LeU, UnsignedLessEqual);
}

WASM_EXEC_TEST(I8x16EqZero) {
  RunICompareOpConstImmTest<int8_t>(execution_tier, kExprI8x16Eq,
                                    kExprI8x16Splat, Equal);
}

WASM_EXEC_TEST(I8x16NeZero) {
  RunICompareOpConstImmTest<int8_t>(execution_tier, kExprI8x16Ne,
                                    kExprI8x16Splat, NotEqual);
}

WASM_EXEC_TEST(I8x16GtZero) {
  RunICompareOpConstImmTest<int8_t>(execution_tier, kExprI8x16GtS,
                                    kExprI8x16Splat, Greater);
}

WASM_EXEC_TEST(I8x16GeZero) {
  RunICompareOpConstImmTest<int8_t>(execution_tier, kExprI8x16GeS,
                                    kExprI8x16Splat, GreaterEqual);
}

WASM_EXEC_TEST(I8x16LtZero) {
  RunICompareOpConstImmTest<int8_t>(execution_tier, kExprI8x16LtS,
                                    kExprI8x16Splat, Less);
}

WASM_EXEC_TEST(I8x16LeZero) {
  RunICompareOpConstImmTest<int8_t>(execution_tier, kExprI8x16LeS,
                                    kExprI8x16Splat, LessEqual);
}

WASM_EXEC_TEST(I8x16RoundingAverageU) {
  RunI8x16BinOpTest<uint8_t>(execution_tier, kExprI8x16RoundingAverageU,
                             RoundingAverageUnsigned);
}

WASM_EXEC_TEST(I8x16Shl) {
  RunI8x16ShiftOpTest(execution_tier, kExprI8x16Shl, LogicalShiftLeft);
}

WASM_EXEC_TEST(I8x16ShrS) {
  RunI8x16ShiftOpTest(execution_tier, kExprI8x16ShrS, ArithmeticShiftRight);
}

WASM_EXEC_TEST(I8x16ShrU) {
  RunI8x16ShiftOpTest(execution_tier, kExprI8x16ShrU, LogicalShiftRight);
}

WASM_EXEC_TEST(I8x16ShiftAdd) {
  for (int imm = 0; imm <= 8; imm++) {
    RunShiftAddTestSequence<int8_t>(execution_tier, kExprI8x16ShrU,
                                    kExprI8x16Add, kExprI8x16Splat, imm,
                                    LogicalShiftRight);
    RunShiftAddTestSequence<int8_t>(execution_tier, kExprI8x16ShrS,
                                    kExprI8x16Add, kExprI8x16Splat, imm,
                                    ArithmeticShiftRight);
  }
}

// Test Select by making a mask where the 0th and 3rd lanes are true and the
// rest false, and comparing for non-equality with zero to convert to a boolean
// vector.
#define WASM_SIMD_SELECT_TEST(format)                                       \
  WASM_EXEC_TEST(S##format##Select) {                                       \
    WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);                \
    uint8_t val1 = 0;                                                       \
    uint8_t val2 = 1;                                                       \
    uint8_t src1 = r.AllocateLocal(kWasmS128);                              \
    uint8_t src2 = r.AllocateLocal(kWasmS128);                              \
    uint8_t zero = r.AllocateLocal(kWasmS128);                              \
    uint8_t mask = r.AllocateLocal(kWasmS128);                              \
    r.Build(                                                                \
        {WASM_LOCAL_SET(src1,                                               \
                        WASM_SIMD_I##format##_SPLAT(WASM_LOCAL_GET(val1))), \
         WASM_LOCAL_SET(src2,                                               \
                        WASM_SIMD_I##format##_SPLAT(WASM_LOCAL_GET(val2))), \
         WASM_LOCAL_SET(zero, WASM_SIMD_I##format##_SPLAT(WASM_ZERO)),      \
         WASM_LOCAL_SET(mask, WASM_SIMD_I##format##_REPLACE_LANE(           \
                                  1, WASM_LOCAL_GET(zero), WASM_I32V(-1))), \
         WASM_LOCAL_SET(mask, WASM_SIMD_I##format##_REPLACE_LANE(           \
                                  2, WASM_LOCAL_GET(mask), WASM_I32V(-1))), \
         WASM_LOCAL_SET(                                                    \
             mask,                                                          \
             WASM_SIMD_SELECT(                                              \
                 format, WASM_LOCAL_GET(src1), WASM_LOCAL_GET(src2),        \
                 WASM_SIMD_BINOP(kExprI##format##Ne, WASM_LOCAL_GET(mask),  \
                                 WASM_LOCAL_GET(zero)))),                   \
         WASM_SIMD_CHECK_LANE_S(I##format, mask, I32, val2, 0),             \
         WASM_SIMD_CHECK_LANE_S(I##format, mask, I32, val1, 1),             \
         WASM_SIMD_CHECK_LANE_S(I##format, mask, I32, val1, 2),             \
         WASM_SIMD_CHECK_LANE_S(I##format, mask, I32, val2, 3), WASM_ONE}); \
                                                                            \
    CHECK_EQ(1, r.Call(0x12, 0x34));                                        \
  }

WASM_SIMD_SELECT_TEST(32x4)
WASM_SIMD_SELECT_TEST(16x8)
WASM_SIMD_SELECT_TEST(8x16)

// Test Select by making a mask where the 0th and 3rd lanes are non-zero and the
// rest 0. The mask is not the result of a comparison op.
#define WASM_SIMD_NON_CANONICAL_SELECT_TEST(format)                          \
  WASM_EXEC_TEST(S##format##NonCanonicalSelect) {                            \
    WasmRunner<int32_t, int32_t, int32_t, int32_t> r(execution_tier);        \
    uint8_t val1 = 0;                                                        \
    uint8_t val2 = 1;                                                        \
    uint8_t combined = 2;                                                    \
    uint8_t src1 = r.AllocateLocal(kWasmS128);                               \
    uint8_t src2 = r.AllocateLocal(kWasmS128);                               \
    uint8_t zero = r.AllocateLocal(kWasmS128);                               \
    uint8_t mask = r.AllocateLocal(kWasmS128);                               \
    r.Build(                                                                 \
        {WASM_LOCAL_SET(src1,                                                \
                        WASM_SIMD_I##format##_SPLAT(WASM_LOCAL_GET(val1))),  \
         WASM_LOCAL_SET(src2,                                                \
                        WASM_SIMD_I##format##_SPLAT(WASM_LOCAL_GET(val2))),  \
         WASM_LOCAL_SET(zero, WASM_SIMD_I##format##_SPLAT(WASM_ZERO)),       \
         WASM_LOCAL_SET(mask, WASM_SIMD_I##format##_REPLACE_LANE(            \
                                  1, WASM_LOCAL_GET(zero), WASM_I32V(0xF))), \
         WASM_LOCAL_SET(mask, WASM_SIMD_I##format##_REPLACE_LANE(            \
                                  2, WASM_LOCAL_GET(mask), WASM_I32V(0xF))), \
         WASM_LOCAL_SET(mask, WASM_SIMD_SELECT(format, WASM_LOCAL_GET(src1), \
                                               WASM_LOCAL_GET(src2),         \
                                               WASM_LOCAL_GET(mask))),       \
         WASM_SIMD_CHECK_LANE_S(I##format, mask, I32, val2, 0),              \
         WASM_SIMD_CHECK_LANE_S(I##format, mask, I32, combined, 1),          \
         WASM_SIMD_CHECK_LANE_S(I##format, mask, I32, combined, 2),          \
         WASM_SIMD_CHECK_LANE_S(I##format, mask, I32, val2, 3), WASM_ONE});  \
                                                                             \
    CHECK_EQ(1, r.Call(0x12, 0x34, 0x32));                                   \
  }

WASM_SIMD_NON_CANONICAL_SELECT_TEST(32x4)
WASM_SIMD_NON_CANONICAL_SELECT_TEST(16x8)
WASM_SIMD_NON_CANONICAL_SELECT_TEST(8x16)

// Test binary ops with two lane test patterns, all lanes distinct.
template <typename T>
void RunBinaryLaneOpTest(
    TestExecutionTier execution_tier, WasmOpcode simd_op,
    const std::array<T, kSimd128Size / sizeof(T)>& expected) {
  WasmRunner<int32_t> r(execution_tier);
  // Set up two test patterns as globals, e.g. [0, 1, 2, 3] and [4, 5, 6, 7].
  T* src0 = r.builder().AddGlobal<T>(kWasmS128);
  T* src1 = r.builder().AddGlobal<T>(kWasmS128);
  static const int kElems = kSimd128Size / sizeof(T);
  for (int i = 0; i < kElems; i++) {
    LANE(src0, i) = i;
    LANE(src1, i) = kElems + i;
  }
  if (simd_op == kExprI8x16Shuffle) {
    r.Build({WASM_GLOBAL_SET(0, WASM_SIMD_I8x16_SHUFFLE_OP(simd_op, expected,
                                                           WASM_GLOBAL_GET(0),
                                                           WASM_GLOBAL_GET(1))),
             WASM_ONE});
  } else {
    r.Build({WASM_GLOBAL_SET(0, WASM_SIMD_BINOP(simd_op, WASM_GLOBAL_GET(0),
                                                WASM_GLOBAL_GET(1))),
             WASM_ONE});
  }

  CHECK_EQ(1, r.Call());
  for (size_t i = 0; i < expected.size(); i++) {
    CHECK_EQ(LANE(src0, i), expected[i]);
  }
}

// Test shuffle ops.
void RunShuffleOpTest(TestExecutionTier execution_tier, WasmOpcode simd_op,
                      const std::array<int8_t, kSimd128Size>& shuffle) {
  // Test the original shuffle.
  RunBinaryLaneOpTest<int8_t>(execution_tier, simd_op, shuffle);

  // Test a non-canonical (inputs reversed) version of the shuffle.
  std::array<int8_t, kSimd128Size> other_shuffle(shuffle);
  for (size_t i = 0; i < shuffle.size(); ++i) other_shuffle[i] ^= kSimd128Size;
  RunBinaryLaneOpTest<int8_t>(execution_tier, simd_op, other_shuffle);

  // Test the swizzle (one-operand) version of the shuffle.
  std::array<int8_t, kSimd128Size> swizzle(shuffle);
  for (size_t i = 0; i < shuffle.size(); ++i) swizzle[i] &= (kSimd128Size - 1);
  RunBinaryLaneOpTest<int8_t>(execution_tier, simd_op, swizzle);

  // Test the non-canonical swizzle (one-operand) version of the shuffle.
  std::array<int8_t, kSimd128Size> other_swizzle(shuffle);
  for (size_t i = 0; i < shuffle.size(); ++i) other_swizzle[i] |= kSimd128Size;
  RunBinaryLaneOpTest<int8_t>(execution_tier, simd_op, other_swizzle);
}

#define SHUFFLE_LIST(V)  \
  V(S128Identity)        \
  V(S32x4Dup)            \
  V(S32x4ZipLeft)        \
  V(S32x4ZipRight)       \
  V(S32x4UnzipLeft)      \
  V(S32x4UnzipRight)     \
  V(S32x4TransposeLeft)  \
  V(S32x4TransposeRight) \
  V(S32x4OneLaneSwizzle) \
  V(S32x4Reverse)        \
  V(S32x2Reverse)        \
  V(S32x4Irregular)      \
  V(S32x4DupAndCopy)     \
  V(S32x4Rotate)         \
  V(S16x8Dup)            \
  V(S16x8ZipLeft)        \
  V(S16x8ZipRight)       \
  V(S16x8UnzipLeft)      \
  V(S16x8UnzipRight)     \
  V(S16x8TransposeLeft)  \
  V(S16x8TransposeRight) \
  V(S16x4Reverse)        \
  V(S16x2Reverse)        \
  V(S16x8Irregular)      \
  V(S8x16Dup)            \
  V(S8x16ZipLeft)        \
  V(S8x16ZipRight)       \
  V(S8x16UnzipLeft)      \
  V(S8x16UnzipRight)     \
  V(S8x16TransposeLeft)  \
  V(S8x16TransposeRight) \
  V(S8x8Reverse)         \
  V(S8x4Reverse)         \
  V(S8x2Reverse)         \
  V(S8x16Irregular)

enum ShuffleKey {
#define SHUFFLE_ENUM_VALUE(Name) k##Name,
  SHUFFLE_LIST(SHUFFLE_ENUM_VALUE)
#undef SHUFFLE_ENUM_VALUE
      kNumShuffleKeys
};

using ShuffleMap = std::map<ShuffleKey, const Shuffle>;

ShuffleMap test_shuffles = {
    {kS128Identity,
     {{16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}}},
    {kS32x4Dup,
     {{16, 17, 18, 19, 16, 17, 18, 19, 16, 17, 18, 19, 16, 17, 18, 19}}},
    {kS32x4ZipLeft, {{0, 1, 2, 3, 16, 17, 18, 19, 4, 5, 6, 7, 20, 21, 22, 23}}},
    {kS32x4ZipRight,
     {{8, 9, 10, 11, 24, 25, 26, 27, 12, 13, 14, 15, 28, 29, 30, 31}}},
    {kS32x4UnzipLeft,
     {{0, 1, 2, 3, 8, 9, 10, 11, 16, 17, 18, 19, 24, 25, 26, 27}}},
    {kS32x4UnzipRight,
     {{4, 5, 6, 7, 12, 13, 14, 15, 20, 21, 22, 23, 28, 29, 30, 31}}},
    {kS32x4TransposeLeft,
     {{0, 1, 2, 3, 16, 17, 18, 19, 8, 9, 10, 11, 24, 25, 26, 27}}},
    {kS32x4TransposeRight,
     {{4, 5, 6, 7, 20, 21, 22, 23, 12, 13, 14, 15, 28, 29, 30, 31}}},
    {kS32x4OneLaneSwizzle,  // swizzle only
     {{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 7, 6, 5, 4}}},
    {kS32x4Reverse,  // swizzle only
     {{3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12}}},
    {kS32x2Reverse,  // swizzle only
     {{4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11}}},
    {kS32x4Irregular,
     {{0, 1, 2, 3, 16, 17, 18, 19, 16, 17, 18, 19, 20, 21, 22, 23}}},
    {kS32x4DupAndCopy,  // swizzle only
     {{3, 2, 1, 0, 3, 2, 1, 0, 11, 10, 9, 8, 15, 14, 13, 12}}},
    {kS32x4Rotate, {{4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3}}},
    {kS16x8Dup,
     {{18, 19, 18, 19, 18, 19, 18, 19, 18, 19, 18, 19, 18, 19, 18, 19}}},
    {kS16x8ZipLeft, {{0, 1, 16, 17, 2, 3, 18, 19, 4, 5, 20, 21, 6, 7, 22, 23}}},
    {kS16x8ZipRight,
     {{8, 9, 24, 25, 10, 11, 26, 27, 12, 13, 28, 29, 14, 15, 30, 31}}},
    {kS16x8UnzipLeft,
     {{0, 1, 4, 5, 8, 9, 12, 13, 16, 17, 20, 21, 24, 25, 28, 29}}},
    {kS16x8UnzipRight,
     {{2, 3, 6, 7, 10, 11, 14, 15, 18, 19, 22, 23, 26, 27, 30, 31}}},
    {kS16x8TransposeLeft,
     {{0, 1, 16, 17, 4, 5, 20, 21, 8, 9, 24, 25, 12, 13, 28, 29}}},
    {kS16x8TransposeRight,
     {{2, 3, 18, 19, 6, 7, 22, 23, 10, 11, 26, 27, 14, 15, 30, 31}}},
    {kS16x4Reverse,  // swizzle only
     {{6, 7, 4, 5, 2, 3, 0, 1, 14, 15, 12, 13, 10, 11, 8, 9}}},
    {kS16x2Reverse,  // swizzle only
     {{2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13}}},
    {kS16x8Irregular,
     {{0, 1, 16, 17, 16, 17, 0, 1, 4, 5, 20, 21, 6, 7, 22, 23}}},
    {kS8x16Dup,
     {{19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19}}},
    {kS8x16ZipLeft, {{0, 16, 1, 17, 2, 18, 3, 19, 4, 20, 5, 21, 6, 22, 7, 23}}},
    {kS8x16ZipRight,
     {{8, 24, 9, 25, 10, 26, 11, 27, 12, 28, 13, 29, 14, 30, 15, 31}}},
    {kS8x16UnzipLeft,
     {{0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30}}},
    {kS8x16UnzipRight,
     {{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31}}},
    {kS8x16TransposeLeft,
     {{0, 16, 2, 18, 4, 20, 6, 22, 8, 24, 10, 26, 12, 28, 14, 30}}},
    {kS8x16TransposeRight,
     {{1, 17, 3, 19, 5, 21, 7, 23, 9, 25, 11, 27, 13, 29, 15, 31}}},
    {kS8x8Reverse,  // swizzle only
     {{7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8}}},
    {kS8x4Reverse,  // swizzle only
     {{3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12}}},
    {kS8x2Reverse,  // swizzle only
     {{1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14}}},
    {kS8x16Irregular,
     {{0, 16, 0, 16, 2, 18, 3, 19, 4, 20, 5, 21, 6, 22, 7, 23}}},
};

#define SHUFFLE_TEST(Name)                                           \
  WASM_EXEC_TEST(Name) {                                             \
    ShuffleMap::const_iterator it = test_shuffles.find(k##Name);     \
    DCHECK_NE(it, test_shuffles.end());                              \
    RunShuffleOpTest(execution_tier, kExprI8x16Shuffle, it->second); \
  }
SHUFFLE_LIST(SHUFFLE_TEST)
#undef SHUFFLE_TEST
#undef SHUFFLE_LIST

// Test shuffles that blend the two vectors (elements remain in their lanes.)
WASM_EXEC_TEST(S8x16Blend) {
  std::array<int8_t, kSimd128Size> expected;
  for (int bias = 1; bias < kSimd128Size; bias++) {
    for (int i = 0; i < bias; i++) expected[i] = i;
    for (int i = bias; i < kSimd128Size; i++) expected[i] = i + kSimd128Size;
    RunShuffleOpTest(execution_tier, kExprI8x16Shuffle, expected);
  }
}

// Test shuffles that concatenate the two vectors.
WASM_EXEC_TEST(S8x16Concat) {
  std::array<int8_t, kSimd128Size> expected;
  // n is offset or bias of concatenation.
  for (int n = 1; n < kSimd128Size; ++n) {
    int i = 0;
    // last kLanes - n bytes of first vector.
    for (int j = n; j < kSimd128Size; ++j) {
      expected[i++] = j;
    }
    // first n bytes of second vector
    for (int j = 0; j < n; ++j) {
      expected[i++] = j + kSimd128Size;
    }
    RunShuffleOpTest(execution_tier, kExprI8x16Shuffle, expected);
  }
}

WASM_EXEC_TEST(ShuffleShufps) {
  // We reverse engineer the shufps immediates into 8x16 shuffles.
  std::array<int8_t, kSimd128Size> expected;
  for (int mask = 0; mask < 256; mask++) {
    // Each iteration of this loop sets byte[i] of the 32x4 lanes.
    // Low 2 lanes (2-bits each) select from first input.
    uint8_t index0 = (mask & 3) * 4;
    uint8_t index1 = ((mask >> 2) & 3) * 4;
    // Next 2 bits select from src2, so add 16 to the index.
    uint8_t index2 = ((mask >> 4) & 3) * 4 + 16;
    uint8_t index3 = ((mask >> 6) & 3) * 4 + 16;

    for (int i = 0; i < 4; i++) {
      expected[0 + i] = index0 + i;
      expected[4 + i] = index1 + i;
      expected[8 + i] = index2 + i;
      expected[12 + i] = index3 + i;
    }
    RunShuffleOpTest(execution_tier, kExprI8x16Shuffle, expected);
  }
}

WASM_EXEC_TEST(I8x16ShuffleWithZeroInput) {
  WasmRunner<int32_t> r(execution_tier);
  static const int kElems = kSimd128Size / sizeof(uint8_t);
  uint8_t* dst = r.builder().AddGlobal<uint8_t>(kWasmS128);
  uint8_t* src1 = r.builder().AddGlobal<uint8_t>(kWasmS128);

  // src0 is zero, it's used to zero extend src1
  for (int i = 0; i < kElems; i++) {
    LANE(src1, i) = i;
  }

  // Zero extend first 4 elments of src1 to 32 bit
  constexpr std::array<int8_t, 16> shuffle = {16, 1, 2,  3,  17, 5,  6,  7,
                                              18, 9, 10, 11, 19, 13, 14, 15};
  constexpr std::array<int8_t, 16> expected = {0, 0, 0, 0, 1, 0, 0, 0,
                                               2, 0, 0, 0, 3, 0, 0, 0};
  constexpr std::array<int8_t, 16> zeros = {0};

  r.Build(
      {WASM_GLOBAL_SET(0, WASM_SIMD_I8x16_SHUFFLE_OP(kExprI8x16Shuffle, shuffle,
                                                     WASM_SIMD_CONSTANT(zeros),
                                                     WASM_GLOBAL_GET(1))),
       WASM_ONE});
  CHECK_EQ(1, r.Call());
  for (int i = 0; i < kElems; i++) {
    CHECK_EQ(LANE(dst, i), expected[i]);
  }
}

struct SwizzleTestArgs {
  const Shuffle input;
  const Shuffle indices;
  const Shuffle expected;
};

static constexpr SwizzleTestArgs swizzle_test_args[] = {
    {{15, 14,
```