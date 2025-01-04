Response: The user wants a summary of the provided C++ code, which is part of a larger test file for WebAssembly SIMD operations in V8.

**Plan:**
1. Identify the main functionality of the code.
2. Relate this functionality to JavaScript if possible.
3. Since this is part 2 of 5, consider how this part contributes to the overall testing.

**Code Analysis:**
- The code contains a series of `WASM_EXEC_TEST` macros. Each test seems to focus on a specific SIMD operation.
- The operations are related to integer vectors of different sizes (I16x8, I8x16, I32x4, I64x2).
- Common operation types include:
    - Binary operations (add, sub, mul, min, max, eq, ne, gt, ge, lt, le, rounding average, dot product)
    - Unary operations (neg, abs, popcnt)
    - Conversions (packing)
    - Shifts (shl, shrS, shrU)
    - Extended multiplications (`ExtMulLow`, `ExtMulHigh`)
    - Select operation
    - Shuffle operation
    - Swizzle operation
    - Load/Store operations
    - Boolean reductions (AnyTrue, AllTrue)
    - Extract/Replace lane operations

**Relating to JavaScript:**
- These SIMD operations directly correspond to the WebAssembly SIMD proposal, which is accessible through JavaScript's `WebAssembly.SIMD` API.

**Part 2 Contribution:**
- This section appears to be testing integer SIMD operations, focusing on I16x8 and I8x16, and also includes tests for extended multiplication, select, shuffle, and basic load/store functionalities.

**Example (I16x8Add):**
- The C++ test `WASM_EXEC_TEST(I16x8Add)` checks the functionality of adding two I16x8 vectors.
- In JavaScript, this would be equivalent to:

```javascript
const wasmModule = new WebAssembly.Module(binary);
const wasmInstance = new WebAssembly.Instance(wasmModule);
const i16x8_add = wasmInstance.exports.i16x8_add; // Assuming the WASM function is exported

const a = new Uint16Array([1, 2, 3, 4, 5, 6, 7, 8]);
const b = new Uint16Array([9, 10, 11, 12, 13, 14, 15, 16]);
const result = i16x8_add(a, b); // Assuming the WASM function takes two I16x8 and returns one
// result should be equivalent to [10, 12, 14, 16, 18, 20, 22, 24]
```
这个C++代码文件是V8 JavaScript引擎的测试套件的一部分，专门用于测试WebAssembly的SIMD（Single Instruction, Multiple Data）指令的执行。

**具体功能归纳:**

这部分代码主要测试了针对 **i16x8 (16位整数，8个通道)** 和 **i8x16 (8位整数，16个通道)** 类型的SIMD操作。它涵盖了以下几个方面的功能测试：

1. **算术运算:**
   - 加法 (`I16x8Add`, `I8x16Add`)
   - 减法 (`I16x8Sub`, `I8x16Sub`)
   - 乘法 (扩展乘法 `I16x8ExtMulLowI8x16S/U`, `I16x8ExtMulHighI8x16S/U`)
   - 带饱和的加法和减法 (`I16x8AddSatS/U`, `I16x8SubSatS/U`, `I8x16AddSatS/U`, `I8x16SubSatS/U`)
   - 取平均值 (`I16x8RoundingAverageU`, `I8x16RoundingAverageU`)
   - 量化的乘法 (`I16x8Q15MulRSatS`)
   - 点积 (`I32x4DotI16x8S`)

2. **比较运算:**
   - 等于 (`I16x8Eq`, `I8x16Eq`, `I16x8EqZero`, `I8x16EqZero`)
   - 不等于 (`I16x8Ne`, `I8x16Ne`, `I16x8NeZero`, `I8x16NeZero`)
   - 大于 (`I16x8GtS/U`, `I8x16GtS/U`, `I16x8GtZero`, `I8x16GtZero`)
   - 大于等于 (`I16x8GeS/U`, `I8x16GeS/U`, `I16x8GeZero`, `I8x16GeZero`)
   - 小于 (`I16x8LtS/U`, `I8x16LtS/U`, `I16x8LtZero`, `I8x16LtZero`)
   - 小于等于 (`I16x8LeS/U`, `I8x16LeS/U`, `I16x8LeZero`, `I8x16LeZero`)
   - 最小值和最大值 (`I16x8MinS/U`, `I16x8MaxS/U`, `I8x16MinS/U`, `I8x16MaxS/U`)

3. **位运算:**
   - 左移 (`I16x8Shl`, `I8x16Shl`)
   - 有符号右移 (`I16x8ShrS`, `I8x16ShrS`)
   - 无符号右移 (`I16x8ShrU`, `I8x16ShrU`)
   - 移位后加法 (`I16x8ShiftAdd`, `I8x16ShiftAdd`)

4. **其他运算:**
   - 取反 (`I8x16Neg`)
   - 取绝对值 (`I8x16Abs`)
   - 统计popcount (population count，即二进制表示中1的个数) (`I8x16Popcnt`)
   - 打包转换 (从 i16x8 转换为 i8x16) (`I8x16ConvertI16x8`)
   - 选择 (`S32x4Select`, `S16x8Select`, `S8x16Select`, `S32x4NonCanonicalSelect`, `S16x8NonCanonicalSelect`, `S8x16NonCanonicalSelect`)
   - 字节重排 (shuffle) (`S128Identity` 到 `S8x16Irregular` 等一系列测试用例，包括 blend 和 concat)
   - 字节重排 (swizzle) (`I8x16Swizzle`)

5. **优化测试:**
   - 测试了 `add(mul(x, y, z))` 这种模式的扩展乘法加法优化。

**与JavaScript的关系以及JavaScript示例:**

这些测试直接对应了WebAssembly的SIMD特性，这些特性可以通过JavaScript的 `WebAssembly.SIMD` API 来使用。

例如，C++ 中测试的 `I16x8Add` 功能，在 JavaScript 中可以使用 `Int16x8.add()` 方法来实现：

```javascript
// 假设你已经有了一个 WebAssembly 模块的实例
const wasmModule = new WebAssembly.Module(wasmCode); // wasmCode 是你的 WebAssembly 字节码
const wasmInstance = new WebAssembly.Instance(wasmModule);

// 获取导出的函数，该函数执行 i16x8 加法
const addI16x8 = wasmInstance.exports.addI16x8; // 假设 WebAssembly 中导出了名为 addI16x8 的函数

// 创建两个 Int16x8 类型的数组
const a = new Int16Array([1, 2, 3, 4, 5, 6, 7, 8]);
const b = new Int16Array([9, 10, 11, 12, 13, 14, 15, 16]);

// 使用 wasmInstance.exports 中导出的函数执行加法
const result = addI16x8(a, b);

// result 应该是一个表示 [10, 12, 14, 16, 18, 20, 22, 24] 的 Int16x8 类型的数组
console.log(result);
```

再例如，C++ 中测试的 `I8x16Shuffle` 功能，在 JavaScript 中可以使用 `Int8x16.shuffle()` 方法来实现：

```javascript
// 假设你已经有了一个 WebAssembly 模块的实例
const wasmModule = new WebAssembly.Module(wasmCode);
const wasmInstance = new WebAssembly.Instance(wasmModule);

// 获取导出的函数，该函数执行 i8x16 shuffle
const shuffleI8x16 = wasmInstance.exports.shuffleI8x16; // 假设 WebAssembly 中导出了名为 shuffleI8x16 的函数

// 创建一个 Int8x16 类型的数组
const a = new Int8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
const b = new Int8Array([16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]);

// 定义 shuffle 的索引
const shuffleIndices = new Uint8Array([16, 1, 2,  3,  17, 5,  6,  7, 18, 9, 10, 11, 19, 13, 14, 15]);

// 使用 wasmInstance.exports 中导出的函数执行 shuffle
const result = shuffleI8x16(a, b, shuffleIndices);

console.log(result);
```

**作为第2部分的功能：**

作为5个部分中的第2部分，这段代码主要集中在测试 **小整数类型 (i8, i16) 的 SIMD 操作**。它构建了针对这些数据类型的大量基本算术、比较和位运算的测试用例，以及一些更复杂的操作如扩展乘法、选择和重排。这为确保 V8 引擎正确地执行 WebAssembly 中针对这些常见 SIMD 数据类型的指令奠定了基础。后续的部分可能会涵盖更大的整数类型 (i32, i64)、浮点数、以及更高级的 SIMD 功能。

Prompt: 
```
这是目录为v8/test/cctest/wasm/test-run-wasm-simd.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共5部分，请归纳一下它的功能

"""
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
    {{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
     {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
     {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
    {{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
     {15, 0, 14, 1, 13, 2, 12, 3, 11, 4, 10, 5, 9, 6, 8, 7},
     {0, 15, 1, 14, 2, 13, 3, 12, 4, 11, 5, 10, 6, 9, 7, 8}},
    {{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
     {0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30},
     {15, 13, 11, 9, 7, 5, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0}},
    // all indices are out of range
    {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
     {16, 17, 18, 19, 20, 124, 125, 126, 127, -1, -2, -3, -4, -5, -6, -7},
     {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}};

static constexpr base::Vector<const SwizzleTestArgs> swizzle_test_vector =
    base::ArrayVector(swizzle_test_args);

WASM_EXEC_TEST(I8x16Swizzle) {
  // RunBinaryLaneOpTest set up the two globals to be consecutive integers,
  // [0-15] and [16-31]. Using [0-15] as the indices will not sufficiently test
  // swizzle since the expected result is a no-op, using [16-31] will result in
  // all 0s.
  {
    WasmRunner<int32_t> r(execution_tier);
    static const int kElems = kSimd128Size / sizeof(uint8_t);
    uint8_t* dst = r.builder().AddGlobal<uint8_t>(kWasmS128);
    uint8_t* src0 = r.builder().AddGlobal<uint8_t>(kWasmS128);
    uint8_t* src1 = r.builder().AddGlobal<uint8_t>(kWasmS128);
    r.Build({WASM_GLOBAL_SET(
                 0, WASM_SIMD_BINOP(kExprI8x16Swizzle, WASM_GLOBAL_GET(1),
                                    WASM_GLOBAL_GET(2))),
             WASM_ONE});

    for (SwizzleTestArgs si : swizzle_test_vector) {
      for (int i = 0; i < kElems; i++) {
        LANE(src0, i) = si.input[i];
        LANE(src1, i) = si.indices[i];
      }

      CHECK_EQ(1, r.Call());

      for (int i = 0; i < kElems; i++) {
        CHECK_EQ(LANE(dst, i), si.expected[i]);
      }
    }
  }

  {
    // We have an optimization for constant indices, test this case.
    for (SwizzleTestArgs si : swizzle_test_vector) {
      WasmRunner<int32_t> r(execution_tier);
      uint8_t* dst = r.builder().AddGlobal<uint8_t>(kWasmS128);
      uint8_t* src0 = r.builder().AddGlobal<uint8_t>(kWasmS128);
      r.Build({WASM_GLOBAL_SET(
                   0, WASM_SIMD_BINOP(kExprI8x16Swizzle, WASM_GLOBAL_GET(1),
                                      WASM_SIMD_CONSTANT(si.indices))),
               WASM_ONE});

      for (int i = 0; i < kSimd128Size; i++) {
        LANE(src0, i) = si.input[i];
      }

      CHECK_EQ(1, r.Call());

      for (int i = 0; i < kSimd128Size; i++) {
        CHECK_EQ(LANE(dst, i), si.expected[i]);
      }
    }
  }
}

// Combine 3 shuffles a, b, and c by applying both a and b and then applying c
// to those two results.
Shuffle Combine(const Shuffle& a, const Shuffle& b, const Shuffle& c) {
  Shuffle result;
  for (int i = 0; i < kSimd128Size; ++i) {
    result[i] = c[i] < kSimd128Size ? a[c[i]] : b[c[i] - kSimd128Size];
  }
  return result;
}

const Shuffle& GetRandomTestShuffle(v8::base::RandomNumberGenerator* rng) {
  return test_shuffles[static_cast<ShuffleKey>(rng->NextInt(kNumShuffleKeys))];
}

// Test shuffles that are random combinations of 3 test shuffles. Completely
// random shuffles almost always generate the slow general shuffle code, so
// don't exercise as many code paths.
WASM_EXEC_TEST(I8x16ShuffleFuzz) {
  v8::base::RandomNumberGenerator* rng = CcTest::random_number_generator();
  static const int kTests = 100;
  for (int i = 0; i < kTests; ++i) {
    auto shuffle = Combine(GetRandomTestShuffle(rng), GetRandomTestShuffle(rng),
                           GetRandomTestShuffle(rng));
    RunShuffleOpTest(execution_tier, kExprI8x16Shuffle, shuffle);
  }
}

void AppendShuffle(const Shuffle& shuffle, std::vector<uint8_t>* buffer) {
  uint8_t opcode[] = {WASM_SIMD_OP(kExprI8x16Shuffle)};
  for (size_t i = 0; i < arraysize(opcode); ++i) buffer->push_back(opcode[i]);
  for (size_t i = 0; i < kSimd128Size; ++i) buffer->push_back((shuffle[i]));
}

void BuildShuffle(const std::vector<Shuffle>& shuffles,
                  std::vector<uint8_t>* buffer) {
  // Perform the leaf shuffles on globals 0 and 1.
  size_t row_index = (shuffles.size() - 1) / 2;
  for (size_t i = row_index; i < shuffles.size(); ++i) {
    uint8_t operands[] = {WASM_GLOBAL_GET(0), WASM_GLOBAL_GET(1)};
    for (size_t j = 0; j < arraysize(operands); ++j)
      buffer->push_back(operands[j]);
    AppendShuffle(shuffles[i], buffer);
  }
  // Now perform inner shuffles in the correct order on operands on the stack.
  do {
    for (size_t i = row_index / 2; i < row_index; ++i) {
      AppendShuffle(shuffles[i], buffer);
    }
    row_index /= 2;
  } while (row_index != 0);
  uint8_t epilog[] = {kExprGlobalSet, static_cast<uint8_t>(0), WASM_ONE};
  for (size_t j = 0; j < arraysize(epilog); ++j) buffer->push_back(epilog[j]);
}

void RunWasmCode(TestExecutionTier execution_tier,
                 const std::vector<uint8_t>& code,
                 std::array<int8_t, kSimd128Size>* result) {
  WasmRunner<int32_t> r(execution_tier);
  // Set up two test patterns as globals, e.g. [0, 1, 2, 3] and [4, 5, 6, 7].
  int8_t* src0 = r.builder().AddGlobal<int8_t>(kWasmS128);
  int8_t* src1 = r.builder().AddGlobal<int8_t>(kWasmS128);
  for (int i = 0; i < kSimd128Size; ++i) {
    LANE(src0, i) = i;
    LANE(src1, i) = kSimd128Size + i;
  }
  r.Build(code.data(), code.data() + code.size());
  CHECK_EQ(1, r.Call());
  for (size_t i = 0; i < kSimd128Size; i++) {
    (*result)[i] = LANE(src0, i);
  }
}

// Boolean unary operations are 'AllTrue' and 'AnyTrue', which return an integer
// result. Use relational ops on numeric vectors to create the boolean vector
// test inputs. Test inputs with all true, all false, one true, and one false.
#define WASM_SIMD_BOOL_REDUCTION_TEST(format, lanes, int_type)                \
  WASM_EXEC_TEST(ReductionTest##lanes) {                                      \
    WasmRunner<int32_t> r(execution_tier);                                    \
    if (lanes == 2) return;                                                   \
    uint8_t zero = r.AllocateLocal(kWasmS128);                                \
    uint8_t one_one = r.AllocateLocal(kWasmS128);                             \
    uint8_t reduced = r.AllocateLocal(kWasmI32);                              \
    r.Build(                                                                  \
        {WASM_LOCAL_SET(zero, WASM_SIMD_I##format##_SPLAT(int_type(0))),      \
         WASM_LOCAL_SET(                                                      \
             reduced, WASM_SIMD_UNOP(kExprV128AnyTrue,                        \
                                     WASM_SIMD_BINOP(kExprI##format##Eq,      \
                                                     WASM_LOCAL_GET(zero),    \
                                                     WASM_LOCAL_GET(zero)))), \
         WASM_IF(WASM_I32_EQ(WASM_LOCAL_GET(reduced), WASM_ZERO),             \
                 WASM_RETURN(WASM_ZERO)),                                     \
         WASM_LOCAL_SET(                                                      \
             reduced, WASM_SIMD_UNOP(kExprV128AnyTrue,                        \
                                     WASM_SIMD_BINOP(kExprI##format##Ne,      \
                                                     WASM_LOCAL_GET(zero),    \
                                                     WASM_LOCAL_GET(zero)))), \
         WASM_IF(WASM_I32_NE(WASM_LOCAL_GET(reduced), WASM_ZERO),             \
                 WASM_RETURN(WASM_ZERO)),                                     \
         WASM_LOCAL_SET(                                                      \
             reduced, WASM_SIMD_UNOP(kExprI##format##AllTrue,                 \
                                     WASM_SIMD_BINOP(kExprI##format##Eq,      \
                                                     WASM_LOCAL_GET(zero),    \
                                                     WASM_LOCAL_GET(zero)))), \
         WASM_IF(WASM_I32_EQ(WASM_LOCAL_GET(reduced), WASM_ZERO),             \
                 WASM_RETURN(WASM_ZERO)),                                     \
         WASM_LOCAL_SET(                                                      \
             reduced, WASM_SIMD_UNOP(kExprI##format##AllTrue,                 \
                                     WASM_SIMD_BINOP(kExprI##format##Ne,      \
                                                     WASM_LOCAL_GET(zero),    \
                                                     WASM_LOCAL_GET(zero)))), \
         WASM_IF(WASM_I32_NE(WASM_LOCAL_GET(reduced), WASM_ZERO),             \
                 WASM_RETURN(WASM_ZERO)),                                     \
         WASM_LOCAL_SET(one_one,                                              \
                        WASM_SIMD_I##format##_REPLACE_LANE(                   \
                            lanes - 1, WASM_LOCAL_GET(zero), int_type(1))),   \
         WASM_LOCAL_SET(                                                      \
             reduced, WASM_SIMD_UNOP(kExprV128AnyTrue,                        \
                                     WASM_SIMD_BINOP(kExprI##format##Eq,      \
                                                     WASM_LOCAL_GET(one_one), \
                                                     WASM_LOCAL_GET(zero)))), \
         WASM_IF(WASM_I32_EQ(WASM_LOCAL_GET(reduced), WASM_ZERO),             \
                 WASM_RETURN(WASM_ZERO)),                                     \
         WASM_LOCAL_SET(                                                      \
             reduced, WASM_SIMD_UNOP(kExprV128AnyTrue,                        \
                                     WASM_SIMD_BINOP(kExprI##format##Ne,      \
                                                     WASM_LOCAL_GET(one_one), \
                                                     WASM_LOCAL_GET(zero)))), \
         WASM_IF(WASM_I32_EQ(WASM_LOCAL_GET(reduced), WASM_ZERO),             \
                 WASM_RETURN(WASM_ZERO)),                                     \
         WASM_LOCAL_SET(                                                      \
             reduced, WASM_SIMD_UNOP(kExprI##format##AllTrue,                 \
                                     WASM_SIMD_BINOP(kExprI##format##Eq,      \
                                                     WASM_LOCAL_GET(one_one), \
                                                     WASM_LOCAL_GET(zero)))), \
         WASM_IF(WASM_I32_NE(WASM_LOCAL_GET(reduced), WASM_ZERO),             \
                 WASM_RETURN(WASM_ZERO)),                                     \
         WASM_LOCAL_SET(                                                      \
             reduced, WASM_SIMD_UNOP(kExprI##format##AllTrue,                 \
                                     WASM_SIMD_BINOP(kExprI##format##Ne,      \
                                                     WASM_LOCAL_GET(one_one), \
                                                     WASM_LOCAL_GET(zero)))), \
         WASM_IF(WASM_I32_NE(WASM_LOCAL_GET(reduced), WASM_ZERO),             \
                 WASM_RETURN(WASM_ZERO)),                                     \
         WASM_ONE});                                                          \
    CHECK_EQ(1, r.Call());                                                    \
  }

WASM_SIMD_BOOL_REDUCTION_TEST(64x2, 2, WASM_I64V)
WASM_SIMD_BOOL_REDUCTION_TEST(32x4, 4, WASM_I32V)
WASM_SIMD_BOOL_REDUCTION_TEST(16x8, 8, WASM_I32V)
WASM_SIMD_BOOL_REDUCTION_TEST(8x16, 16, WASM_I32V)

WASM_EXEC_TEST(SimdI32x4ExtractWithF32x4) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build(
      {WASM_IF_ELSE_I(WASM_I32_EQ(WASM_SIMD_I32x4_EXTRACT_LANE(
                                      0, WASM_SIMD_F32x4_SPLAT(WASM_F32(30.5))),
                                  WASM_I32_REINTERPRET_F32(WASM_F32(30.5))),
                      WASM_I32V(1), WASM_I32V(0))});
  CHECK_EQ(1, r.Call());
}

WASM_EXEC_TEST(SimdF32x4ExtractWithI32x4) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build(
      {WASM_IF_ELSE_I(WASM_F32_EQ(WASM_SIMD_F32x4_EXTRACT_LANE(
                                      0, WASM_SIMD_I32x4_SPLAT(WASM_I32V(15))),
                                  WASM_F32_REINTERPRET_I32(WASM_I32V(15))),
                      WASM_I32V(1), WASM_I32V(0))});
  CHECK_EQ(1, r.Call());
}

WASM_EXEC_TEST(SimdF32x4ExtractLane) {
  WasmRunner<float> r(execution_tier);
  r.AllocateLocal(kWasmF32);
  r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(0, WASM_SIMD_F32x4_EXTRACT_LANE(
                                 0, WASM_SIMD_F32x4_SPLAT(WASM_F32(30.5)))),
           WASM_LOCAL_SET(1, WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(0))),
           WASM_SIMD_F32x4_EXTRACT_LANE(1, WASM_LOCAL_GET(1))});
  CHECK_EQ(30.5, r.Call());
}

WASM_EXEC_TEST(SimdF32x4AddWithI32x4) {
  // Choose two floating point values whose sum is normal and exactly
  // representable as a float.
  const int kOne = 0x3F800000;
  const int kTwo = 0x40000000;
  WasmRunner<int32_t> r(execution_tier);
  r.Build({WASM_IF_ELSE_I(
      WASM_F32_EQ(
          WASM_SIMD_F32x4_EXTRACT_LANE(
              0, WASM_SIMD_BINOP(kExprF32x4Add,
                                 WASM_SIMD_I32x4_SPLAT(WASM_I32V(kOne)),
                                 WASM_SIMD_I32x4_SPLAT(WASM_I32V(kTwo)))),
          WASM_F32_ADD(WASM_F32_REINTERPRET_I32(WASM_I32V(kOne)),
                       WASM_F32_REINTERPRET_I32(WASM_I32V(kTwo)))),
      WASM_I32V(1), WASM_I32V(0))});
  CHECK_EQ(1, r.Call());
}

WASM_EXEC_TEST(SimdI32x4AddWithF32x4) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build({WASM_IF_ELSE_I(
      WASM_I32_EQ(
          WASM_SIMD_I32x4_EXTRACT_LANE(
              0, WASM_SIMD_BINOP(kExprI32x4Add,
                                 WASM_SIMD_F32x4_SPLAT(WASM_F32(21.25)),
                                 WASM_SIMD_F32x4_SPLAT(WASM_F32(31.5)))),
          WASM_I32_ADD(WASM_I32_REINTERPRET_F32(WASM_F32(21.25)),
                       WASM_I32_REINTERPRET_F32(WASM_F32(31.5)))),
      WASM_I32V(1), WASM_I32V(0))});
  CHECK_EQ(1, r.Call());
}

WASM_EXEC_TEST(SimdI32x4Local) {
  WasmRunner<int32_t> r(execution_tier);
  r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(0, WASM_SIMD_I32x4_SPLAT(WASM_I32V(31))),
           WASM_SIMD_I32x4_EXTRACT_LANE(0, WASM_LOCAL_GET(0))});
  CHECK_EQ(31, r.Call());
}

WASM_EXEC_TEST(SimdI32x4SplatFromExtract) {
  WasmRunner<int32_t> r(execution_tier);
  r.AllocateLocal(kWasmI32);
  r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(0, WASM_SIMD_I32x4_EXTRACT_LANE(
                                 0, WASM_SIMD_I32x4_SPLAT(WASM_I32V(76)))),
           WASM_LOCAL_SET(1, WASM_SIMD_I32x4_SPLAT(WASM_LOCAL_GET(0))),
           WASM_SIMD_I32x4_EXTRACT_LANE(1, WASM_LOCAL_GET(1))});
  CHECK_EQ(76, r.Call());
}

WASM_EXEC_TEST(SimdI32x4For) {
  WasmRunner<int32_t> r(execution_tier);
  r.AllocateLocal(kWasmI32);
  r.AllocateLocal(kWasmS128);
  r.Build(
      {WASM_LOCAL_SET(1, WASM_SIMD_I32x4_SPLAT(WASM_I32V(31))),
       WASM_LOCAL_SET(1, WASM_SIMD_I32x4_REPLACE_LANE(1, WASM_LOCAL_GET(1),
                                                      WASM_I32V(53))),
       WASM_LOCAL_SET(1, WASM_SIMD_I32x4_REPLACE_LANE(2, WASM_LOCAL_GET(1),
                                                      WASM_I32V(23))),
       WASM_LOCAL_SET(0, WASM_I32V(0)),
       WASM_LOOP(
           WASM_LOCAL_SET(1,
                          WASM_SIMD_BINOP(kExprI32x4Add, WASM_LOCAL_GET(1),
                                          WASM_SIMD_I32x4_SPLAT(WASM_I32V(1)))),
           WASM_IF(WASM_I32_NE(WASM_INC_LOCAL(0), WASM_I32V(5)), WASM_BR(1))),
       WASM_LOCAL_SET(0, WASM_I32V(1)),
       WASM_IF(WASM_I32_NE(WASM_SIMD_I32x4_EXTRACT_LANE(0, WASM_LOCAL_GET(1)),
                           WASM_I32V(36)),
               WASM_LOCAL_SET(0, WASM_I32V(0))),
       WASM_IF(WASM_I32_NE(WASM_SIMD_I32x4_EXTRACT_LANE(1, WASM_LOCAL_GET(1)),
                           WASM_I32V(58)),
               WASM_LOCAL_SET(0, WASM_I32V(0))),
       WASM_IF(WASM_I32_NE(WASM_SIMD_I32x4_EXTRACT_LANE(2, WASM_LOCAL_GET(1)),
                           WASM_I32V(28)),
               WASM_LOCAL_SET(0, WASM_I32V(0))),
       WASM_IF(WASM_I32_NE(WASM_SIMD_I32x4_EXTRACT_LANE(3, WASM_LOCAL_GET(1)),
                           WASM_I32V(36)),
               WASM_LOCAL_SET(0, WASM_I32V(0))),
       WASM_LOCAL_GET(0)});
  CHECK_EQ(1, r.Call());
}

WASM_EXEC_TEST(SimdF32x4For) {
  WasmRunner<int32_t> r(execution_tier);
  r.AllocateLocal(kWasmI32);
  r.AllocateLocal(kWasmS128);
  r.Build(
      {WASM_LOCAL_SET(1, WASM_SIMD_F32x4_SPLAT(WASM_F32(21.25))),
       WASM_LOCAL_SET(1, WASM_SIMD_F32x4_REPLACE_LANE(3, WASM_LOCAL_GET(1),
                                                      WASM_F32(19.5))),
       WASM_LOCAL_SET(0, WASM_I32V(0)),
       WASM_LOOP(
           WASM_LOCAL_SET(
               1, WASM_SIMD_BINOP(kExprF32x4Add, WASM_LOCAL_GET(1),
                                  WASM_SIMD_F32x4_SPLAT(WASM_F32(2.0)))),
           WASM_IF(WASM_I32_NE(WASM_INC_LOCAL(0), WASM_I32V(3)), WASM_BR(1))),
       WASM_LOCAL_SET(0, WASM_I32V(1)),
       WASM_IF(WASM_F32_NE(WASM_SIMD_F32x4_EXTRACT_LANE(0, WASM_LOCAL_GET(1)),
                           WASM_F32(27.25)),
               WASM_LOCAL_SET(0, WASM_I32V(0))),
       WASM_IF(WASM_F32_NE(WASM_SIMD_F32x4_EXTRACT_LANE(3, WASM_LOCAL_GET(1)),
                           WASM_F32(25.5)),
               WASM_LOCAL_SET(0, WASM_I32V(0))),
       WASM_LOCAL_GET(0)});
  CHECK_EQ(1, r.Call());
}

template <typename T, int numLanes = 4>
void SetVectorByLanes(T* v, const std::array<T, numLanes>& arr) {
  for (int lane = 0; lane < numLanes; lane++) {
    LANE(v, lane) = arr[lane];
  }
}

template <typename T>
const T GetScalar(T* v, int lane) {
  DCHECK_GE(lane, 0);
  DCHECK_LT(static_cast<uint32_t>(lane), kSimd128Size / sizeof(T));
  return LANE(v, lane);
}

WASM_EXEC_TEST(SimdI32x4GetGlobal) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // Pad the globals with a few unused slots to get a non-zero offset.
  r.builder().AddGlobal<int32_t>(kWasmI32);  // purposefully unused
  r.builder().AddGlobal<int32_t>(kWasmI32);  // purposefully unused
  r.builder().AddGlobal<int32_t>(kWasmI32);  // purposefully unused
  r.builder().AddGlobal<int32_t>(kWasmI32);  // purposefully unused
  int32_t* global = r.builder().AddGlobal<int32_t>(kWasmS128);
  SetVectorByLanes(global, {{0, 1, 2, 3}});
  r.AllocateLocal(kWasmI32);
  r.Build(
      {WASM_LOCAL_SET(1, WASM_I32V(1)),
       WASM_IF(WASM_I32_NE(WASM_I32V(0),
                           WASM_SIMD_I32x4_EXTRACT_LANE(0, WASM_GLOBAL_GET(4))),
               WASM_LOCAL_SET(1, WASM_I32V(0))),
       WASM_IF(WASM_I32_NE(WASM_I32V(1),
                           WASM_SIMD_I32x4_EXTRACT_LANE(1, WASM_GLOBAL_GET(4))),
               WASM_LOCAL_SET(1, WASM_I32V(0))),
       WASM_IF(WASM_I32_NE(WASM_I32V(2),
                           WASM_SIMD_I32x4_EXTRACT_LANE(2, WASM_GLOBAL_GET(4))),
               WASM_LOCAL_SET(1, WASM_I32V(0))),
       WASM_IF(WASM_I32_NE(WASM_I32V(3),
                           WASM_SIMD_I32x4_EXTRACT_LANE(3, WASM_GLOBAL_GET(4))),
               WASM_LOCAL_SET(1, WASM_I32V(0))),
       WASM_LOCAL_GET(1)});
  CHECK_EQ(1, r.Call(0));
}

WASM_EXEC_TEST(SimdI32x4SetGlobal) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // Pad the globals with a few unused slots to get a non-zero offset.
  r.builder().AddGlobal<int32_t>(kWasmI32);  // purposefully unused
  r.builder().AddGlobal<int32_t>(kWasmI32);  // purposefully unused
  r.builder().AddGlobal<int32_t>(kWasmI32);  // purposefully unused
  r.builder().AddGlobal<int32_t>(kWasmI32);  // purposefully unused
  int32_t* global = r.builder().AddGlobal<int32_t>(kWasmS128);
  r.Build({WASM_GLOBAL_SET(4, WASM_SIMD_I32x4_SPLAT(WASM_I32V(23))),
           WASM_GLOBAL_SET(4, WASM_SIMD_I32x4_REPLACE_LANE(
                                  1, WASM_GLOBAL_GET(4), WASM_I32V(34))),
           WASM_GLOBAL_SET(4, WASM_SIMD_I32x4_REPLACE_LANE(
                                  2, WASM_GLOBAL_GET(4), WASM_I32V(45))),
           WASM_GLOBAL_SET(4, WASM_SIMD_I32x4_REPLACE_LANE(
                                  3, WASM_GLOBAL_GET(4), WASM_I32V(56))),
           WASM_I32V(1)});
  CHECK_EQ(1, r.Call(0));
  CHECK_EQ(GetScalar(global, 0), 23);
  CHECK_EQ(GetScalar(global, 1), 34);
  CHECK_EQ(GetScalar(global, 2), 45);
  CHECK_EQ(GetScalar(global, 3), 56);
}

WASM_EXEC_TEST(SimdF32x4GetGlobal) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  float* global = r.builder().AddGlobal<float>(kWasmS128);
  SetVectorByLanes<float>(global, {{0.0, 1.5, 2.25, 3.5}});
  r.AllocateLocal(kWasmI32);
  r.Build(
      {WASM_LOCAL_SET(1, WASM_I32V(1)),
       WASM_IF(WASM_F32_NE(WASM_F32(0.0),
                           WASM_SIMD_F32x4_EXTRACT_LANE(0, WASM_GLOBAL_GET(0))),
               WASM_LOCAL_SET(1, WASM_I32V(0))),
       WASM_IF(WASM_F32_NE(WASM_F32(1.5),
                           WASM_SIMD_F32x4_EXTRACT_LANE(1, WASM_GLOBAL_GET(0))),
               WASM_LOCAL_SET(1, WASM_I32V(0))),
       WASM_IF(WASM_F32_NE(WASM_F32(2.25),
                           WASM_SIMD_F32x4_EXTRACT_LANE(2, WASM_GLOBAL_GET(0))),
               WASM_LOCAL_SET(1, WASM_I32V(0))),
       WASM_IF(WASM_F32_NE(WASM_F32(3.5),
                           WASM_SIMD_F32x4_EXTRACT_LANE(3, WASM_GLOBAL_GET(0))),
               WASM_LOCAL_SET(1, WASM_I32V(0))),
       WASM_LOCAL_GET(1)});
  CHECK_EQ(1, r.Call(0));
}

WASM_EXEC_TEST(SimdF32x4SetGlobal) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  float* global = r.builder().AddGlobal<float>(kWasmS128);
  r.Build({WASM_GLOBAL_SET(0, WASM_SIMD_F32x4_SPLAT(WASM_F32(13.5))),
           WASM_GLOBAL_SET(0, WASM_SIMD_F32x4_REPLACE_LANE(
                                  1, WASM_GLOBAL_GET(0), WASM_F32(45.5))),
           WASM_GLOBAL_SET(0, WASM_SIMD_F32x4_REPLACE_LANE(
                                  2, WASM_GLOBAL_GET(0), WASM_F32(32.25))),
           WASM_GLOBAL_SET(0, WASM_SIMD_F32x4_REPLACE_LANE(
                                  3, WASM_GLOBAL_GET(0), WASM_F32(65.0))),
           WASM_I32V(1)});
  CHECK_EQ(1, r.Call(0));
  CHECK_EQ(GetScalar(global, 0), 13.5f);
  CHECK_EQ(GetScalar(global, 1), 45.5f);
  CHECK_EQ(GetScalar(global, 2), 32.25f);
  CHECK_EQ(GetScalar(global, 3), 65.0f);
}

WASM_EXEC_TEST(SimdLoadStoreLoad) {
  {
    WasmRunner<int32_t> r(execution_tier);
    int32_t* memory =
        r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));
    // Load memory, store it, then reload it and extract the first lane. Use a
    // non-zero offset into the memory of 1 lane (4 bytes) to test indexing.
    r.Build(
        {WASM_SIMD_STORE_MEM(WASM_I32V(8), WASM_SIMD_LOAD_MEM(WASM_I32V(4))),
         WASM_SIMD_I32x4_EXTRACT_LANE(0, WASM_SIMD_LOAD_MEM(WASM_I32V(8)))});

    FOR_INT32_INPUTS(i) {
      int32_t expected = i;
      r.builder().WriteMemory(&memory[1], expected);
      CHECK_EQ(expected, r.Call());
    }
  }

  {
    // OOB tests for loads.
    WasmRunner<int32_t, uint32_t> r(execution_tier);
    r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));
    r.Build({WASM_SIMD_I32x4_EXTRACT_LANE(
        0, WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(0)))});

    for (uint32_t offset = kWasmPageSize - (kSimd128Size - 1);
         offset < kWasmPageSize; ++offset) {
      CHECK_TRAP(r.Call(offset));
    }
  }

  {
    // OOB tests for stores.
    WasmRunner<int32_t, uint32_t> r(execution_tier);
    r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));
    r.Build(
        {WASM_SIMD_STORE_MEM(WASM_LOCAL_GET(0), WASM_SIMD_LOAD_MEM(WASM_ZERO)),
         WASM_ONE});

    for (uint32_t offset = kWasmPageSize - (kSimd128Size - 1);
         offset < kWasmPageSize; ++offset) {
      CHECK_TRAP(r.Call(offset));
    }
  }
}

WASM_EXEC_TEST(SimdLoadStoreLoadMemargOffset) {
  {
    WasmRunner<int32_t> r(execution_tier);
    int32_t* memory =
        r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));
    constexpr uint8_t offset_1 = 4;
    constexpr uint8_t offset_2 = 8;
    // Load from memory at offset_1, store to offset_2, load from offset_2, and
    // extract first lane. We use non-zero memarg offsets to test offset
    // decoding.
    r.Build({WASM_SIMD_STORE_MEM_OFFSET(
                 offset_2, WASM_ZERO,
                 WASM_SIMD_LOAD_MEM_OFFSET(offset_1, WASM_ZERO)),
             WASM_SIMD_I32x4_EXTRACT_LANE(
                 0, WASM_SIMD_LOAD_MEM_OFFSET(offset_2, WASM_ZERO))});

    FOR_INT32_INPUTS(i) {
      int32_t expected = i;
      // Index 1 of memory (int32_t) will be bytes 4 to 8.
      r.builder().WriteMemory(&memory[1], expected);
      CHECK_EQ(expected, r.Call());
    }
  }

  {
    // OOB tests for loads with offsets.
    for (uint32_t offset = kWasmPageSize - (kSimd128Size - 1);
         offset < kWasmPageSize; ++offset) {
      WasmRunner<int32_t> r(execution_tier);
      r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));
      r.Build({WASM_SIMD_I32x4_EXTRACT_LANE(
          0, WASM_SIMD_LOAD_MEM_OFFSET(U32V_3(offset), WASM_ZERO))});
      CHECK_TRAP(r.Call());
    }
  }

  {
    // OOB tests for stores with offsets
    for (uint32_t offset = kWasmPageSize - (kSimd128Size - 1);
         offset < kWasmPageSize; ++offset) {
      WasmRunner<int32_t, uint32_t> r(execution_tier);
      r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));
      r.Build({WASM_SIMD_STORE_MEM_OFFSET(U32V_3(offset), WASM_ZERO,
                                          WASM_SIMD_LOAD_MEM(WASM_ZERO)),
               WASM_ONE});
      CHECK_TRAP(r.Call(offset));
    }
  }
}

// Test a multi-byte opcode with offset values that encode into valid opcodes.
// This is to exercise decoding logic and make sure we get the lengths right.
WASM_EXEC_TEST(S128Load8SplatOffset) {
  // This offset is [82, 22] when encoded, which contains valid opcodes.
  constexpr int offset = 4354;
  WasmRunner<int32_t> r(execution_tier);
  int8_t* memory = r.builder().AddMemoryElems<int8_t>(kWasmPageSize);
  int8_t* global = r.builder().AddGlobal<int8_t>(kWasmS128);
  r.Build({WASM_GLOBAL_SET(
               0, WASM_SIMD_LOAD_OP_OFFSET(kExprS128Load8Splat, WASM_I32V(0),
                                           U32V_2(offset))),
           WASM_ONE});

  // We don't really care about all valid values, so just test for 1.
  int8_t x = 7;
  r.builder().WriteMemory(&memory[offset], x);
  r.Call();
  for (int i = 0; i < 16; i++) {
    CHECK_EQ(x, LANE(global, i));
  }
}

template <typename T>
void RunLoadSplatTest(TestExecutionTier execution_tier, WasmOpcode op) {
  constexpr int lanes = 16 / sizeof(T);
  constexpr int mem_index = 16;  // Load from mem index 16 (bytes).
  {
    WasmRunner<int32_t> r(execution_tier);
    T* memory = r.builder().AddMemoryElems<T>(kWasmPageSize / sizeof(T));
    T* global = r.builder().AddGlobal<T>(kWasmS128);
    r.Build({WASM_GLOBAL_SET(0, WASM_SIMD_LOAD_OP(op, WASM_I32V(mem_index))),
             WASM_ONE});

    for (T x : compiler::ValueHelper::GetVector<T>()) {
      // 16-th byte in memory is lanes-th element (size T) of memory.
      r.builder().WriteMemory(&memory[lanes], x);
      r.Call();
      for (int i = 0; i < lanes; i++) {
        CHECK_EQ(x, LANE(global, i));
      }
    }
  }

  // Test for OOB.
  {
    WasmRunner<int32_t, uint32_t> r(execution_tier);
    r.builder().AddMemoryElems<T>(kWasmPageSize / sizeof(T));
    r.builder().AddGlobal<T>(kWasmS128);

    r.Build({WASM_GLOBAL_SET(0, WASM_SIMD_LOAD_OP(op, WASM_LOCAL_GET(0))),
             WASM_ONE});

    // Load splats load sizeof(T) bytes.
    for (uint32_t offset = kWasmPageSize - (sizeof(T) - 1);
         offset < kWasmPageSize; ++offset) {
      CHECK_TRAP(r.Call(offset));
    }
  }
}

WASM_EXEC_TEST(S128Load8Splat) {
  RunLoadSplatTest<int8_t>(execution_tier, kExprS128Load8Splat);
}

WASM_EXEC_TEST(S128Load16Splat) {
  RunLoadSplatTest<int16_t>(execution_tier, kExprS128Load16Splat);
}

WASM_EXEC_TEST(S128Load32Splat) {
  RunLoadSplatTest<int32_t>(execution_tier, kExprS128Load32Splat);
}

WASM_EXEC_TEST(S128Load64Splat) {
  RunLoadSplatTest<int64_t>(execution_tier, kExprS128Load64Splat);
}

template <typename S, typename T>
void RunLoadExtendTest(TestExecutionTier execution_tier, WasmOpcode op) {
  static_assert(sizeof(S) < sizeof(T),
                "load extend should go from smaller to larger type");
  constexpr int lanes_s = 16 / sizeof(S);
  constexpr int lanes_t = 16 / sizeof(T);
  constexpr int mem_index = 16;  // Load from mem index 16 (bytes).
  // Load extends always load 64 bits, so alignment values can be from 0 to 3.
  for (uint8_t alignment = 0; alignment <= 3; alignment++) {
    WasmRunner<int32_t> r(execution_tier);
    S* memory = r.builder().AddMemoryElems<S>(kWasmPageSize / sizeof(S));
    T* global = r.builder().AddGlobal<T>(kWasmS128);
    r.Build({WASM_GLOBAL_SET(0, WASM_SIMD_LOAD_OP_ALIGNMENT(
                                    op, WASM_I32V(mem_index), alignment)),
             WASM_ONE});

    for (S x : compiler::ValueHelper::GetVector<S>()) {
      for (int i = 0; i < lanes_s; i++) {
        // 16-th byte in memory is lanes-th element (size T) of memory.
        r.builder().WriteMemory(&memory[lanes_s + i], x);
      }
      r.Call();
      for (int i = 0; i < lanes_t; i++) {
        CHECK_EQ(static_cast<T>(x), LANE(global, i));
      }
    }
  }

  // Test for offset.
  {
    WasmRunner<int32_t> r(execution_tier);
    S* memory = r.builder().AddMemoryElems<S>(kWasmPageSize / sizeof(S));
    T* global = r.builder().AddGlobal<T>(kWasmS128);
    constexpr uint8_t offset = sizeof(S);
    r.Build(
        {WASM_GLOBAL_SET(0, WASM_SIMD_LOAD_OP_OFFSET(op, WASM_ZERO, offset)),
         WASM_ONE});

    // Let max_s be the max_s value for type S, we set up the memory as such:
    // memory = [max_s, max_s - 1, ... max_s - (lane_s - 1)].
    constexpr S max_s = std::numeric_limits<S>::max();
    for (int i = 0; i < lanes_s; i++) {
      // Integer promotion due to -, static_cast to narrow.
      r.builder().WriteMemory(&memory[i], static_cast<S>(max_s - i));
    }

    r.Call();

    // Loads will be offset by sizeof(S), so will always start from (max_s - 1).
    for (int i = 0; i < lanes_t; i++) {
      // Integer promotion due to -, static_cast to narrow.
      T expected = static_cast<T>(max_s - i - 1);
      CHECK_EQ(expected, LANE(global, i));
    }
  }

  // Test for OOB.
  {
    WasmRunner<int32_t, uint32_t> r(execution_tier);
    r.builder().AddMemoryElems<S>(kWasmPageSize / sizeof(S));
    r.builder().AddGlobal<T>(kWasmS128);

    r.Build({WASM_GLOBAL_SET(0, WASM_SIMD_LOAD_OP(op, WASM_LOCAL_GET(0))),
             WASM_ONE});

    // Load extends load 8 bytes, so should trap from -7.
    for (uint32_t offset = kWasmPageSize - 7; offset < kWasmPageSize;
         ++offset) {
      CHECK_TRAP(r.Call(offset));
    }
  }
}

WASM_EXEC_TEST(S128Load8x8U) {
  RunLoadExtendTest<uint8_t, uint16_t>(execution_tier, kExprS128Load8x8U);
}

WASM_EXEC_TEST(S128Load8x8S) {
  RunLoadExtendTest<int8_t, int16_t>(execution_tier, kExprS128Load8x8S);
}
WASM_EXEC_TEST(S128Load16x4U) {
  RunLoadExtendTest<uint16_t, uint32_t>(execution_tier, kExprS128Load16x4U);
}

WASM_EXEC_TEST(S128Load16x4S) {
  RunLoadExtendTest<int16_t, int32_t>(execution_tier, kExprS128Load16x4S);
}

WASM_EXEC_TEST(S128Load32x2U) {
  RunLoadExtendTest<uint32_t, uint64_t>(execution_tier, kExprS128Load32x2U);
}

WASM_EXEC_TEST(S128Load32x2S) {
  RunLoadExtendTest<int32_t, int64_t>(execution_tier, kExprS128Load32x2S);
}

template <typename S>
void RunLoadZeroTest(TestExecutionTier execution_tier, WasmOpcode op) {
  constexpr int lanes_s = kSimd128Size / sizeof(S);
  constexpr int mem_index = 16;  // Load from mem index 16 (bytes).
  constexpr S sentinel = S{-1};
  S* memory;
  S* global;

  auto initialize_builder = [=](WasmRunner<int32_t>* r) -> std::tuple<S*, S*> {
    S* memory = r->builder().AddMemoryElems<S>(kWasmPageSize / sizeof(S));
    S* global = r->builder().AddGlobal<S>(kWasmS128);
    r->builder().RandomizeMemory();
    r->builder().WriteMemory(&memory[lanes_s], sentinel);
    return std::make_tuple(memory, global);
  };

  // Check all supported alignments.
  constexpr int max_alignment = base::bits::CountTrailingZeros(sizeof(S));
  for (uint8_t alignment = 0; alignment <= max_alignment; alignment++) {
    WasmRunner<int32_t> r(execution_tier);
    std::tie(memory, global) = initialize_builder(&r);

    r.Build({WASM_GLOBAL_SET(0, WASM_SIMD_LOAD_OP(op, WASM_I32V(mem_index))),
             WASM_ONE});
    r.Call();

    // Only first lane is set to sentinel.
    CHECK_EQ(sentinel, LANE(global, 0));
    // The other lanes are zero.
    for 
"""


```