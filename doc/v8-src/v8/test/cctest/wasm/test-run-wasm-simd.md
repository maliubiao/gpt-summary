Response: The user wants to understand the functionality of the C++ code snippet provided. The file path suggests this code tests the SIMD (Single Instruction, Multiple Data) functionality of WebAssembly within the V8 JavaScript engine.

Here's a breakdown of the thought process to summarize the code:

1. **Identify the core purpose:** The file name `test-run-wasm-simd.cc` strongly indicates that this code is for testing WebAssembly SIMD instructions.

2. **Examine the includes:** The included headers provide clues about the functionalities being tested. We see includes related to:
    * Basic C++ functionalities (`<algorithm>`, `<array>`, etc.)
    * V8 internals (`"src/base/bits.h"`, `"src/codegen/cpu-features.h"`, etc.)
    * WebAssembly specific headers (`"src/wasm/value-type.h"`, `"src/wasm/wasm-opcodes.h"`)
    * Testing frameworks (`"test/cctest/cctest.h"`, `"test/cctest/wasm/wasm-run-utils.h"`)
    * SIMD testing utilities (`"test/cctest/wasm/wasm-simd-utils.h"`).

3. **Analyze the namespace:** The code is within the `v8::internal::wasm::test_run_wasm_simd` namespace, further reinforcing the testing focus.

4. **Look for common patterns and structures:** The code uses a lot of macros like `WASM_EXEC_TEST`, `WASM_IF`, `WASM_RETURN`, `WASM_ZERO`, etc. These suggest a macro-based testing framework for WebAssembly operations. The `WasmRunner` class is likely used to set up and execute WebAssembly code snippets. The use of globals (`r.builder().AddGlobal`) indicates a way to pass data into and out of the WebAssembly modules under test.

5. **Focus on the test names:**  The names of the tests (e.g., `WASM_EXEC_TEST(F32x4Splat)`, `WASM_EXEC_TEST(I64x2Add)`) are highly descriptive and directly correspond to WebAssembly SIMD instructions. This is a strong indication that each test focuses on a specific SIMD operation.

6. **Examine the test logic:** Inside the `WASM_EXEC_TEST` blocks, the code generally follows a pattern:
    * **Setup:** Create a `WasmRunner`, potentially add global variables or memory.
    * **Build:**  Construct a small WebAssembly module using the provided macros. This module typically performs the SIMD operation being tested.
    * **Call:** Execute the WebAssembly module with various input values.
    * **Check:**  Verify the results by comparing the output (often stored in globals) with expected values. The `LANE` macro suggests accessing individual elements within the SIMD vector.

7. **Identify helper functions:**  Functions like `Add`, `Sub`, `Equal`, `LogicalShiftLeft`, etc., are defined to provide reference implementations of the operations being tested, especially for cases where C++ standard library functions might not behave exactly like the WebAssembly instruction (e.g., handling of signed integer overflow).

8. **Infer the overall functionality:** Based on the above observations, the primary function of this code is to test the correctness of the implementation of various WebAssembly SIMD instructions in the V8 engine. It does this by creating small WebAssembly modules that execute these instructions with a range of inputs and then verifying that the output matches the expected behavior.

9. **Consider the relationship with JavaScript:** WebAssembly is designed to be executed within a JavaScript environment. SIMD in WebAssembly aims to provide performance benefits for computationally intensive tasks. Therefore, the SIMD instructions tested here have direct counterparts in the JavaScript WebAssembly API.

10. **Formulate a JavaScript example:** To illustrate the connection with JavaScript, choose a simple SIMD operation (like `f32x4.add`) and demonstrate its equivalent usage in JavaScript.

11. **Structure the summary:** Organize the findings into a clear and concise summary, addressing the core functionality and the relationship with JavaScript. Highlight the testing methodology and the specific aspects being tested (different SIMD types and operations).
这个C++源代码文件 (`v8/test/cctest/wasm/test-run-wasm-simd.cc`) 的功能是**测试 V8 引擎中 WebAssembly SIMD (Single Instruction, Multiple Data) 指令的正确性**。

具体来说，它包含了一系列的测试用例，每个测试用例都针对一个或一组特定的 WebAssembly SIMD 指令进行验证。 这些测试用例会：

1. **构建 WebAssembly 模块**: 使用宏定义 (如 `WASM_EXEC_TEST`, `WASM_SIMD_F32x4_SPLAT`, `WASM_SIMD_F32x4_ADD` 等)  动态生成包含 SIMD 指令的 WebAssembly 代码片段。
2. **执行 WebAssembly 模块**:  通过 `WasmRunner` 类来加载并执行构建的 WebAssembly 模块。
3. **提供输入数据**:  使用不同的输入值 (例如，通过 `FOR_INT32_INPUTS`, `FOR_FLOAT32_INPUTS` 等宏生成) 来测试 SIMD 指令在各种情况下的行为。
4. **验证输出结果**:  将 WebAssembly 模块的输出结果与预期的正确结果进行比较 (通常通过全局变量来获取输出，并使用 `CHECK_EQ` 等宏进行断言)。

**与 JavaScript 的关系：**

WebAssembly 的 SIMD 功能旨在提高 JavaScript 中计算密集型任务的性能。  这些在 C++ 代码中测试的 WebAssembly SIMD 指令，在 JavaScript 中可以通过 `WebAssembly.SIMD` API 来访问。

**JavaScript 例子：**

假设在 C++ 代码中有一个测试用例 `WASM_EXEC_TEST(F32x4Add)`，它测试了 WebAssembly 中 `f32x4.add` 指令的功能。

在 JavaScript 中，你可以使用 `Float32x4.add()` 方法来执行相同的操作：

```javascript
// 创建两个 Float32x4 类型的 SIMD 数据
const a = Float32x4(1.0, 2.0, 3.0, 4.0);
const b = Float32x4(5.0, 6.0, 7.0, 8.0);

// 使用 Float32x4.add() 执行加法运算
const result = Float32x4.add(a, b);

// result 的值将是 Float32x4(6.0, 8.0, 10.0, 12.0)

console.log(result.getX()); // 输出 6.0
console.log(result.getY()); // 输出 8.0
console.log(result.getZ()); // 输出 10.0
console.log(result.getW()); // 输出 12.0
```

**总结一下这个部分的功能：**

这个 C++ 代码文件的第一部分定义了一些辅助函数和宏，并开始编写针对各种 WebAssembly SIMD 指令的测试用例。 这些测试用例涵盖了诸如浮点数和整数的向量化加载、存储、运算（如加法、减法、乘法等）以及比较操作。  它通过在 C++ 环境中模拟执行 WebAssembly 代码，并断言输出结果的正确性，来确保 V8 引擎对这些 SIMD 指令的实现是符合规范的。  这些测试的 WebAssembly SIMD 指令在 JavaScript 中有对应的 `WebAssembly.SIMD` API。

Prompt: 
```
这是目录为v8/test/cctest/wasm/test-run-wasm-simd.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共5部分，请归纳一下它的功能

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#include "src/base/bits.h"
#include "src/base/logging.h"
#include "src/base/macros.h"
#include "src/base/memory.h"
#include "src/base/overflowing-math.h"
#include "src/base/safe_conversions.h"
#include "src/base/utils/random-number-generator.h"
#include "src/base/vector.h"
#include "src/codegen/cpu-features.h"
#include "src/codegen/machine-type.h"
#include "src/common/globals.h"
#include "src/compiler/opcodes.h"
#include "src/flags/flags.h"
#include "src/utils/utils.h"
#include "src/wasm/compilation-environment.h"
#include "src/wasm/value-type.h"
#include "src/wasm/wasm-constants.h"
#include "src/wasm/wasm-opcodes.h"
#include "test/cctest/cctest.h"
#include "test/cctest/wasm/wasm-run-utils.h"
#include "test/cctest/wasm/wasm-simd-utils.h"
#include "test/common/flag-utils.h"
#include "test/common/value-helper.h"
#include "test/common/wasm/flag-utils.h"
#include "test/common/wasm/wasm-macro-gen.h"

namespace v8 {
namespace internal {
namespace wasm {
namespace test_run_wasm_simd {

namespace {

using Shuffle = std::array<int8_t, kSimd128Size>;

// For signed integral types, use base::AddWithWraparound.
template <typename T, typename = typename std::enable_if<
                          std::is_floating_point<T>::value>::type>
T Add(T a, T b) {
  return a + b;
}

// For signed integral types, use base::SubWithWraparound.
template <typename T, typename = typename std::enable_if<
                          std::is_floating_point<T>::value>::type>
T Sub(T a, T b) {
  return a - b;
}

// For signed integral types, use base::MulWithWraparound.
template <typename T, typename = typename std::enable_if<
                          std::is_floating_point<T>::value>::type>
T Mul(T a, T b) {
  return a * b;
}

template <typename T>
T UnsignedMinimum(T a, T b) {
  using UnsignedT = typename std::make_unsigned<T>::type;
  return static_cast<UnsignedT>(a) <= static_cast<UnsignedT>(b) ? a : b;
}

template <typename T>
T UnsignedMaximum(T a, T b) {
  using UnsignedT = typename std::make_unsigned<T>::type;
  return static_cast<UnsignedT>(a) >= static_cast<UnsignedT>(b) ? a : b;
}

template <typename T, typename U = T>
U Equal(T a, T b) {
  return a == b ? -1 : 0;
}

template <>
int32_t Equal(float a, float b) {
  return a == b ? -1 : 0;
}

template <>
int64_t Equal(double a, double b) {
  return a == b ? -1 : 0;
}

template <typename T, typename U = T>
U NotEqual(T a, T b) {
  return a != b ? -1 : 0;
}

template <>
int32_t NotEqual(float a, float b) {
  return a != b ? -1 : 0;
}

template <>
int64_t NotEqual(double a, double b) {
  return a != b ? -1 : 0;
}

template <typename T, typename U = T>
U Less(T a, T b) {
  return a < b ? -1 : 0;
}

template <>
int32_t Less(float a, float b) {
  return a < b ? -1 : 0;
}

template <>
int64_t Less(double a, double b) {
  return a < b ? -1 : 0;
}

template <typename T, typename U = T>
U LessEqual(T a, T b) {
  return a <= b ? -1 : 0;
}

template <>
int32_t LessEqual(float a, float b) {
  return a <= b ? -1 : 0;
}

template <>
int64_t LessEqual(double a, double b) {
  return a <= b ? -1 : 0;
}

template <typename T, typename U = T>
U Greater(T a, T b) {
  return a > b ? -1 : 0;
}

template <>
int32_t Greater(float a, float b) {
  return a > b ? -1 : 0;
}

template <>
int64_t Greater(double a, double b) {
  return a > b ? -1 : 0;
}

template <typename T, typename U = T>
U GreaterEqual(T a, T b) {
  return a >= b ? -1 : 0;
}

template <>
int32_t GreaterEqual(float a, float b) {
  return a >= b ? -1 : 0;
}

template <>
int64_t GreaterEqual(double a, double b) {
  return a >= b ? -1 : 0;
}

template <typename T>
T UnsignedLess(T a, T b) {
  using UnsignedT = typename std::make_unsigned<T>::type;
  return static_cast<UnsignedT>(a) < static_cast<UnsignedT>(b) ? -1 : 0;
}

template <typename T>
T UnsignedLessEqual(T a, T b) {
  using UnsignedT = typename std::make_unsigned<T>::type;
  return static_cast<UnsignedT>(a) <= static_cast<UnsignedT>(b) ? -1 : 0;
}

template <typename T>
T UnsignedGreater(T a, T b) {
  using UnsignedT = typename std::make_unsigned<T>::type;
  return static_cast<UnsignedT>(a) > static_cast<UnsignedT>(b) ? -1 : 0;
}

template <typename T>
T UnsignedGreaterEqual(T a, T b) {
  using UnsignedT = typename std::make_unsigned<T>::type;
  return static_cast<UnsignedT>(a) >= static_cast<UnsignedT>(b) ? -1 : 0;
}

template <typename T>
T LogicalShiftLeft(T a, int shift) {
  using UnsignedT = typename std::make_unsigned<T>::type;
  return static_cast<UnsignedT>(a) << (shift % (sizeof(T) * 8));
}

template <typename T>
T LogicalShiftRight(T a, int shift) {
  using UnsignedT = typename std::make_unsigned<T>::type;
  return static_cast<UnsignedT>(a) >> (shift % (sizeof(T) * 8));
}

// Define our own ArithmeticShiftRight instead of using the one from utils.h
// because the shift amount needs to be taken modulo lane width.
template <typename T>
T ArithmeticShiftRight(T a, int shift) {
  return a >> (shift % (sizeof(T) * 8));
}

template <typename T>
T Abs(T a) {
  return std::abs(a);
}

template <typename T>
T BitwiseNot(T a) {
  return ~a;
}

template <typename T>
T BitwiseAnd(T a, T b) {
  return a & b;
}

template <typename T>
T BitwiseOr(T a, T b) {
  return a | b;
}
template <typename T>
T BitwiseXor(T a, T b) {
  return a ^ b;
}
template <typename T>
T BitwiseAndNot(T a, T b) {
  return a & (~b);
}

template <typename T>
T BitwiseSelect(T a, T b, T c) {
  return (a & c) | (b & ~c);
}

}  // namespace

#define WASM_SIMD_CHECK_LANE_S(TYPE, value, LANE_TYPE, lane_value, lane_index) \
  WASM_IF(WASM_##LANE_TYPE##_NE(WASM_LOCAL_GET(lane_value),                    \
                                WASM_SIMD_##TYPE##_EXTRACT_LANE(               \
                                    lane_index, WASM_LOCAL_GET(value))),       \
          WASM_RETURN(WASM_ZERO))

// Unsigned Extracts are only available for I8x16, I16x8 types
#define WASM_SIMD_CHECK_LANE_U(TYPE, value, LANE_TYPE, lane_value, lane_index) \
  WASM_IF(WASM_##LANE_TYPE##_NE(WASM_LOCAL_GET(lane_value),                    \
                                WASM_SIMD_##TYPE##_EXTRACT_LANE_U(             \
                                    lane_index, WASM_LOCAL_GET(value))),       \
          WASM_RETURN(WASM_ZERO))

WASM_EXEC_TEST(S128Globals) {
  WasmRunner<int32_t> r(execution_tier);
  // Set up a global to hold input and output vectors.
  int32_t* g0 = r.builder().AddGlobal<int32_t>(kWasmS128);
  int32_t* g1 = r.builder().AddGlobal<int32_t>(kWasmS128);
  r.Build({WASM_GLOBAL_SET(1, WASM_GLOBAL_GET(0)), WASM_ONE});

  FOR_INT32_INPUTS(x) {
    for (int i = 0; i < 4; i++) {
      LANE(g0, i) = x;
    }
    r.Call();
    int32_t expected = x;
    for (int i = 0; i < 4; i++) {
      int32_t actual = LANE(g1, i);
      CHECK_EQ(actual, expected);
    }
  }
}

WASM_EXEC_TEST(F32x4Splat) {
  WasmRunner<int32_t, float> r(execution_tier);
  // Set up a global to hold output vector.
  float* g = r.builder().AddGlobal<float>(kWasmS128);
  uint8_t param1 = 0;
  r.Build({WASM_GLOBAL_SET(0, WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(param1))),
           WASM_ONE});

  FOR_FLOAT32_INPUTS(x) {
    r.Call(x);
    float expected = x;
    for (int i = 0; i < 4; i++) {
      float actual = LANE(g, i);
      if (std::isnan(expected)) {
        CHECK(std::isnan(actual));
      } else {
        CHECK_EQ(actual, expected);
      }
    }
  }
}

WASM_EXEC_TEST(F32x4ReplaceLane) {
  WasmRunner<int32_t> r(execution_tier);
  // Set up a global to hold input/output vector.
  float* g = r.builder().AddGlobal<float>(kWasmS128);
  // Build function to replace each lane with its (FP) index.
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_F32x4_SPLAT(WASM_F32(3.14159f))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_F32x4_REPLACE_LANE(
                                     0, WASM_LOCAL_GET(temp1), WASM_F32(0.0f))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_F32x4_REPLACE_LANE(
                                     1, WASM_LOCAL_GET(temp1), WASM_F32(1.0f))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_F32x4_REPLACE_LANE(
                                     2, WASM_LOCAL_GET(temp1), WASM_F32(2.0f))),
           WASM_GLOBAL_SET(0, WASM_SIMD_F32x4_REPLACE_LANE(
                                  3, WASM_LOCAL_GET(temp1), WASM_F32(3.0f))),
           WASM_ONE});

  r.Call();
  for (int i = 0; i < 4; i++) {
    CHECK_EQ(static_cast<float>(i), LANE(g, i));
  }
}

// Tests both signed and unsigned conversion.
WASM_EXEC_TEST(F32x4ConvertI32x4) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // Create two output vectors to hold signed and unsigned results.
  float* g0 = r.builder().AddGlobal<float>(kWasmS128);
  float* g1 = r.builder().AddGlobal<float>(kWasmS128);
  // Build fn to splat test value, perform conversions, and write the results.
  uint8_t value = 0;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I32x4_SPLAT(WASM_LOCAL_GET(value))),
           WASM_GLOBAL_SET(0, WASM_SIMD_UNOP(kExprF32x4SConvertI32x4,
                                             WASM_LOCAL_GET(temp1))),
           WASM_GLOBAL_SET(1, WASM_SIMD_UNOP(kExprF32x4UConvertI32x4,
                                             WASM_LOCAL_GET(temp1))),
           WASM_ONE});

  FOR_INT32_INPUTS(x) {
    r.Call(x);
    float expected_signed = static_cast<float>(x);
    float expected_unsigned = static_cast<float>(static_cast<uint32_t>(x));
    for (int i = 0; i < 4; i++) {
      CHECK_EQ(expected_signed, LANE(g0, i));
      CHECK_EQ(expected_unsigned, LANE(g1, i));
    }
  }
}

template <typename FloatType, typename ScalarType>
void RunF128CompareOpConstImmTest(
    TestExecutionTier execution_tier, WasmOpcode cmp_opcode,
    WasmOpcode splat_opcode, ScalarType (*expected_op)(FloatType, FloatType)) {
  for (FloatType x : compiler::ValueHelper::GetVector<FloatType>()) {
    if (!PlatformCanRepresent(x)) continue;
    WasmRunner<int32_t, FloatType> r(execution_tier);
    // Set up globals to hold mask output for left and right cases
    ScalarType* g1 = r.builder().template AddGlobal<ScalarType>(kWasmS128);
    ScalarType* g2 = r.builder().template AddGlobal<ScalarType>(kWasmS128);
    // Build fn to splat test values, perform compare op on both sides, and
    // write the result.
    uint8_t value = 0;
    uint8_t temp = r.AllocateLocal(kWasmS128);
    uint8_t const_buffer[kSimd128Size];
    for (size_t i = 0; i < kSimd128Size / sizeof(FloatType); i++) {
      WriteLittleEndianValue<FloatType>(
          reinterpret_cast<FloatType*>(&const_buffer[0]) + i, x);
    }
    r.Build(
        {WASM_LOCAL_SET(temp,
                        WASM_SIMD_OPN(splat_opcode, WASM_LOCAL_GET(value))),
         WASM_GLOBAL_SET(
             0, WASM_SIMD_BINOP(cmp_opcode, WASM_SIMD_CONSTANT(const_buffer),
                                WASM_LOCAL_GET(temp))),
         WASM_GLOBAL_SET(1, WASM_SIMD_BINOP(cmp_opcode, WASM_LOCAL_GET(temp),
                                            WASM_SIMD_CONSTANT(const_buffer))),
         WASM_ONE});
    for (FloatType y : compiler::ValueHelper::GetVector<FloatType>()) {
      if (!PlatformCanRepresent(y)) continue;
      FloatType diff = x - y;  // Model comparison as subtraction.
      if (!PlatformCanRepresent(diff)) continue;
      r.Call(y);
      ScalarType expected1 = expected_op(x, y);
      ScalarType expected2 = expected_op(y, x);
      for (size_t i = 0; i < kSimd128Size / sizeof(ScalarType); i++) {
        CHECK_EQ(expected1, LANE(g1, i));
        CHECK_EQ(expected2, LANE(g2, i));
      }
    }
  }
}

WASM_EXEC_TEST(F32x4Abs) {
  RunF32x4UnOpTest(execution_tier, kExprF32x4Abs, std::abs);
}

WASM_EXEC_TEST(F32x4Neg) {
  RunF32x4UnOpTest(execution_tier, kExprF32x4Neg, Negate);
}

WASM_EXEC_TEST(F32x4Sqrt) {
  RunF32x4UnOpTest(execution_tier, kExprF32x4Sqrt, std::sqrt);
}

WASM_EXEC_TEST(F32x4Ceil) {
  RunF32x4UnOpTest(execution_tier, kExprF32x4Ceil, ceilf, true);
}

WASM_EXEC_TEST(F32x4Floor) {
  RunF32x4UnOpTest(execution_tier, kExprF32x4Floor, floorf, true);
}

WASM_EXEC_TEST(F32x4Trunc) {
  RunF32x4UnOpTest(execution_tier, kExprF32x4Trunc, truncf, true);
}

WASM_EXEC_TEST(F32x4NearestInt) {
  RunF32x4UnOpTest(execution_tier, kExprF32x4NearestInt, nearbyintf, true);
}

WASM_EXEC_TEST(F32x4Add) {
  RunF32x4BinOpTest(execution_tier, kExprF32x4Add, Add);
}
WASM_EXEC_TEST(F32x4Sub) {
  RunF32x4BinOpTest(execution_tier, kExprF32x4Sub, Sub);
}
WASM_EXEC_TEST(F32x4Mul) {
  RunF32x4BinOpTest(execution_tier, kExprF32x4Mul, Mul);
}
WASM_EXEC_TEST(F32x4Div) {
  RunF32x4BinOpTest(execution_tier, kExprF32x4Div, base::Divide);
}
WASM_EXEC_TEST(F32x4Min) {
  RunF32x4BinOpTest(execution_tier, kExprF32x4Min, JSMin);
}
WASM_EXEC_TEST(F32x4Max) {
  RunF32x4BinOpTest(execution_tier, kExprF32x4Max, JSMax);
}

WASM_EXEC_TEST(F32x4Pmin) {
  RunF32x4BinOpTest(execution_tier, kExprF32x4Pmin, Minimum);
}

WASM_EXEC_TEST(F32x4Pmax) {
  RunF32x4BinOpTest(execution_tier, kExprF32x4Pmax, Maximum);
}

WASM_EXEC_TEST(F32x4Eq) {
  RunF32x4CompareOpTest(execution_tier, kExprF32x4Eq, Equal);
}

WASM_EXEC_TEST(F32x4Ne) {
  RunF32x4CompareOpTest(execution_tier, kExprF32x4Ne, NotEqual);
}

WASM_EXEC_TEST(F32x4Gt) {
  RunF32x4CompareOpTest(execution_tier, kExprF32x4Gt, Greater);
}

WASM_EXEC_TEST(F32x4Ge) {
  RunF32x4CompareOpTest(execution_tier, kExprF32x4Ge, GreaterEqual);
}

WASM_EXEC_TEST(F32x4Lt) {
  RunF32x4CompareOpTest(execution_tier, kExprF32x4Lt, Less);
}

WASM_EXEC_TEST(F32x4Le) {
  RunF32x4CompareOpTest(execution_tier, kExprF32x4Le, LessEqual);
}

template <typename ScalarType>
void RunShiftAddTestSequence(TestExecutionTier execution_tier,
                             WasmOpcode shiftr_opcode, WasmOpcode add_opcode,
                             WasmOpcode splat_opcode, int32_t imm,
                             ScalarType (*shift_fn)(ScalarType, int32_t)) {
  WasmRunner<int32_t, ScalarType> r(execution_tier);
  // globals to store results for left and right cases
  ScalarType* g1 = r.builder().template AddGlobal<ScalarType>(kWasmS128);
  ScalarType* g2 = r.builder().template AddGlobal<ScalarType>(kWasmS128);
  uint8_t param = 0;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  auto expected_fn = [shift_fn](ScalarType x, ScalarType y, uint32_t imm) {
    return base::AddWithWraparound(x, shift_fn(y, imm));
  };
  r.Build(
      {WASM_LOCAL_SET(temp1,
                      WASM_SIMD_OPN(splat_opcode, WASM_LOCAL_GET(param))),
       WASM_LOCAL_SET(temp2,
                      WASM_SIMD_OPN(splat_opcode, WASM_LOCAL_GET(param))),
       WASM_GLOBAL_SET(0, WASM_SIMD_BINOP(add_opcode,
                                          WASM_SIMD_BINOP(shiftr_opcode,
                                                          WASM_LOCAL_GET(temp2),
                                                          WASM_I32V(imm)),
                                          WASM_LOCAL_GET(temp1))),
       WASM_GLOBAL_SET(1, WASM_SIMD_BINOP(add_opcode, WASM_LOCAL_GET(temp1),
                                          WASM_SIMD_BINOP(shiftr_opcode,
                                                          WASM_LOCAL_GET(temp2),
                                                          WASM_I32V(imm)))),

       WASM_ONE});
  for (ScalarType x : compiler::ValueHelper::GetVector<ScalarType>()) {
    r.Call(x);
    ScalarType expected = expected_fn(x, x, imm);
    for (size_t i = 0; i < kSimd128Size / sizeof(ScalarType); i++) {
      CHECK_EQ(expected, LANE(g1, i));
      CHECK_EQ(expected, LANE(g2, i));
    }
  }
}

WASM_EXEC_TEST(F32x4EqZero) {
  RunF128CompareOpConstImmTest<float, int32_t>(execution_tier, kExprF32x4Eq,
                                               kExprF32x4Splat, Equal);
}

WASM_EXEC_TEST(F32x4NeZero) {
  RunF128CompareOpConstImmTest<float, int32_t>(execution_tier, kExprF32x4Ne,
                                               kExprF32x4Splat, NotEqual);
}

WASM_EXEC_TEST(F32x4GtZero) {
  RunF128CompareOpConstImmTest<float, int32_t>(execution_tier, kExprF32x4Gt,
                                               kExprF32x4Splat, Greater);
}

WASM_EXEC_TEST(F32x4GeZero) {
  RunF128CompareOpConstImmTest<float, int32_t>(execution_tier, kExprF32x4Ge,
                                               kExprF32x4Splat, GreaterEqual);
}

WASM_EXEC_TEST(F32x4LtZero) {
  RunF128CompareOpConstImmTest<float, int32_t>(execution_tier, kExprF32x4Lt,
                                               kExprF32x4Splat, Less);
}

WASM_EXEC_TEST(F32x4LeZero) {
  RunF128CompareOpConstImmTest<float, int32_t>(execution_tier, kExprF32x4Le,
                                               kExprF32x4Splat, LessEqual);
}

WASM_EXEC_TEST(I64x2Splat) {
  WasmRunner<int32_t, int64_t> r(execution_tier);
  // Set up a global to hold output vector.
  int64_t* g = r.builder().AddGlobal<int64_t>(kWasmS128);
  uint8_t param1 = 0;
  r.Build({WASM_GLOBAL_SET(0, WASM_SIMD_I64x2_SPLAT(WASM_LOCAL_GET(param1))),
           WASM_ONE});

  FOR_INT64_INPUTS(x) {
    r.Call(x);
    int64_t expected = x;
    for (int i = 0; i < 2; i++) {
      int64_t actual = LANE(g, i);
      CHECK_EQ(actual, expected);
    }
  }
}

WASM_EXEC_TEST(I64x2ExtractLane) {
  WasmRunner<int64_t> r(execution_tier);
  r.AllocateLocal(kWasmI64);
  r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(
               0, WASM_SIMD_I64x2_EXTRACT_LANE(
                      0, WASM_SIMD_I64x2_SPLAT(WASM_I64V(0xFFFFFFFFFF)))),
           WASM_LOCAL_SET(1, WASM_SIMD_I64x2_SPLAT(WASM_LOCAL_GET(0))),
           WASM_SIMD_I64x2_EXTRACT_LANE(1, WASM_LOCAL_GET(1))});
  CHECK_EQ(0xFFFFFFFFFF, r.Call());
}

WASM_EXEC_TEST(I64x2ReplaceLane) {
  WasmRunner<int32_t> r(execution_tier);
  // Set up a global to hold input/output vector.
  int64_t* g = r.builder().AddGlobal<int64_t>(kWasmS128);
  // Build function to replace each lane with its index.
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I64x2_SPLAT(WASM_I64V(-1))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I64x2_REPLACE_LANE(
                                     0, WASM_LOCAL_GET(temp1), WASM_I64V(0))),
           WASM_GLOBAL_SET(0, WASM_SIMD_I64x2_REPLACE_LANE(
                                  1, WASM_LOCAL_GET(temp1), WASM_I64V(1))),
           WASM_ONE});

  r.Call();
  for (int64_t i = 0; i < 2; i++) {
    CHECK_EQ(i, LANE(g, i));
  }
}

WASM_EXEC_TEST(I64x2Neg) {
  RunI64x2UnOpTest(execution_tier, kExprI64x2Neg, base::NegateWithWraparound);
}

WASM_EXEC_TEST(I64x2Abs) {
  RunI64x2UnOpTest(execution_tier, kExprI64x2Abs, std::abs);
}

WASM_EXEC_TEST(I64x2Shl) {
  RunI64x2ShiftOpTest(execution_tier, kExprI64x2Shl, LogicalShiftLeft);
}

WASM_EXEC_TEST(I64x2ShrS) {
  RunI64x2ShiftOpTest(execution_tier, kExprI64x2ShrS, ArithmeticShiftRight);
}

WASM_EXEC_TEST(I64x2ShrU) {
  RunI64x2ShiftOpTest(execution_tier, kExprI64x2ShrU, LogicalShiftRight);
}

WASM_EXEC_TEST(I64x2ShiftAdd) {
  for (int imm = 0; imm <= 64; imm++) {
    RunShiftAddTestSequence<int64_t>(execution_tier, kExprI64x2ShrU,
                                     kExprI64x2Add, kExprI64x2Splat, imm,
                                     LogicalShiftRight);
    RunShiftAddTestSequence<int64_t>(execution_tier, kExprI64x2ShrS,
                                     kExprI64x2Add, kExprI64x2Splat, imm,
                                     ArithmeticShiftRight);
  }
}

WASM_EXEC_TEST(I64x2Add) {
  RunI64x2BinOpTest(execution_tier, kExprI64x2Add, base::AddWithWraparound);
}

WASM_EXEC_TEST(I64x2Sub) {
  RunI64x2BinOpTest(execution_tier, kExprI64x2Sub, base::SubWithWraparound);
}

WASM_EXEC_TEST(I64x2Eq) {
  RunI64x2BinOpTest(execution_tier, kExprI64x2Eq, Equal);
}

WASM_EXEC_TEST(I64x2Ne) {
  RunI64x2BinOpTest(execution_tier, kExprI64x2Ne, NotEqual);
}

WASM_EXEC_TEST(I64x2LtS) {
  RunI64x2BinOpTest(execution_tier, kExprI64x2LtS, Less);
}

WASM_EXEC_TEST(I64x2LeS) {
  RunI64x2BinOpTest(execution_tier, kExprI64x2LeS, LessEqual);
}

WASM_EXEC_TEST(I64x2GtS) {
  RunI64x2BinOpTest(execution_tier, kExprI64x2GtS, Greater);
}

WASM_EXEC_TEST(I64x2GeS) {
  RunI64x2BinOpTest(execution_tier, kExprI64x2GeS, GreaterEqual);
}

namespace {

template <typename ScalarType>
void RunICompareOpConstImmTest(TestExecutionTier execution_tier,
                               WasmOpcode cmp_opcode, WasmOpcode splat_opcode,
                               ScalarType (*expected_op)(ScalarType,
                                                         ScalarType)) {
  for (ScalarType x : compiler::ValueHelper::GetVector<ScalarType>()) {
    WasmRunner<int32_t, ScalarType> r(execution_tier);
    // Set up global to hold mask output for left and right cases
    ScalarType* g1 = r.builder().template AddGlobal<ScalarType>(kWasmS128);
    ScalarType* g2 = r.builder().template AddGlobal<ScalarType>(kWasmS128);
    // Build fn to splat test values, perform compare op on both sides, and
    // write the result.
    uint8_t value = 0;
    uint8_t temp = r.AllocateLocal(kWasmS128);
    uint8_t const_buffer[kSimd128Size];
    for (size_t i = 0; i < kSimd128Size / sizeof(ScalarType); i++) {
      WriteLittleEndianValue<ScalarType>(
          reinterpret_cast<ScalarType*>(&const_buffer[0]) + i, x);
    }
    r.Build(
        {WASM_LOCAL_SET(temp,
                        WASM_SIMD_OPN(splat_opcode, WASM_LOCAL_GET(value))),
         WASM_GLOBAL_SET(
             0, WASM_SIMD_BINOP(cmp_opcode, WASM_SIMD_CONSTANT(const_buffer),
                                WASM_LOCAL_GET(temp))),
         WASM_GLOBAL_SET(1, WASM_SIMD_BINOP(cmp_opcode, WASM_LOCAL_GET(temp),
                                            WASM_SIMD_CONSTANT(const_buffer))),
         WASM_ONE});
    for (ScalarType y : compiler::ValueHelper::GetVector<ScalarType>()) {
      r.Call(y);
      ScalarType expected1 = expected_op(x, y);
      ScalarType expected2 = expected_op(y, x);
      for (size_t i = 0; i < kSimd128Size / sizeof(ScalarType); i++) {
        CHECK_EQ(expected1, LANE(g1, i));
        CHECK_EQ(expected2, LANE(g2, i));
      }
    }
  }
}

}  // namespace

WASM_EXEC_TEST(I64x2EqZero) {
  RunICompareOpConstImmTest<int64_t>(execution_tier, kExprI64x2Eq,
                                     kExprI64x2Splat, Equal);
}

WASM_EXEC_TEST(I64x2NeZero) {
  RunICompareOpConstImmTest<int64_t>(execution_tier, kExprI64x2Ne,
                                     kExprI64x2Splat, NotEqual);
}

WASM_EXEC_TEST(I64x2GtZero) {
  RunICompareOpConstImmTest<int64_t>(execution_tier, kExprI64x2GtS,
                                     kExprI64x2Splat, Greater);
}

WASM_EXEC_TEST(I64x2GeZero) {
  RunICompareOpConstImmTest<int64_t>(execution_tier, kExprI64x2GeS,
                                     kExprI64x2Splat, GreaterEqual);
}

WASM_EXEC_TEST(I64x2LtZero) {
  RunICompareOpConstImmTest<int64_t>(execution_tier, kExprI64x2LtS,
                                     kExprI64x2Splat, Less);
}

WASM_EXEC_TEST(I64x2LeZero) {
  RunICompareOpConstImmTest<int64_t>(execution_tier, kExprI64x2LeS,
                                     kExprI64x2Splat, LessEqual);
}

WASM_EXEC_TEST(F64x2Splat) {
  WasmRunner<int32_t, double> r(execution_tier);
  // Set up a global to hold output vector.
  double* g = r.builder().AddGlobal<double>(kWasmS128);
  uint8_t param1 = 0;
  r.Build({WASM_GLOBAL_SET(0, WASM_SIMD_F64x2_SPLAT(WASM_LOCAL_GET(param1))),
           WASM_ONE});

  FOR_FLOAT64_INPUTS(x) {
    r.Call(x);
    double expected = x;
    for (int i = 0; i < 2; i++) {
      double actual = LANE(g, i);
      if (std::isnan(expected)) {
        CHECK(std::isnan(actual));
      } else {
        CHECK_EQ(actual, expected);
      }
    }
  }
}

WASM_EXEC_TEST(F64x2ExtractLane) {
  WasmRunner<double, double> r(execution_tier);
  uint8_t param1 = 0;
  uint8_t temp1 = r.AllocateLocal(kWasmF64);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(
               temp1, WASM_SIMD_F64x2_EXTRACT_LANE(
                          0, WASM_SIMD_F64x2_SPLAT(WASM_LOCAL_GET(param1)))),
           WASM_LOCAL_SET(temp2, WASM_SIMD_F64x2_SPLAT(WASM_LOCAL_GET(temp1))),
           WASM_SIMD_F64x2_EXTRACT_LANE(1, WASM_LOCAL_GET(temp2))});
  FOR_FLOAT64_INPUTS(x) {
    double actual = r.Call(x);
    double expected = x;
    if (std::isnan(expected)) {
      CHECK(std::isnan(actual));
    } else {
      CHECK_EQ(actual, expected);
    }
  }
}

WASM_EXEC_TEST(F64x2ReplaceLane) {
  WasmRunner<int32_t> r(execution_tier);
  // Set up globals to hold input/output vector.
  double* g0 = r.builder().AddGlobal<double>(kWasmS128);
  double* g1 = r.builder().AddGlobal<double>(kWasmS128);
  // Build function to replace each lane with its (FP) index.
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_F64x2_SPLAT(WASM_F64(1e100))),
           // Replace lane 0.
           WASM_GLOBAL_SET(0, WASM_SIMD_F64x2_REPLACE_LANE(
                                  0, WASM_LOCAL_GET(temp1), WASM_F64(0.0f))),
           // Replace lane 1.
           WASM_GLOBAL_SET(1, WASM_SIMD_F64x2_REPLACE_LANE(
                                  1, WASM_LOCAL_GET(temp1), WASM_F64(1.0f))),
           WASM_ONE});

  r.Call();
  CHECK_EQ(0., LANE(g0, 0));
  CHECK_EQ(1e100, LANE(g0, 1));
  CHECK_EQ(1e100, LANE(g1, 0));
  CHECK_EQ(1., LANE(g1, 1));
}

WASM_EXEC_TEST(F64x2ExtractLaneWithI64x2) {
  WasmRunner<int64_t> r(execution_tier);
  r.Build({WASM_IF_ELSE_L(
      WASM_F64_EQ(WASM_SIMD_F64x2_EXTRACT_LANE(
                      0, WASM_SIMD_I64x2_SPLAT(WASM_I64V(1e15))),
                  WASM_F64_REINTERPRET_I64(WASM_I64V(1e15))),
      WASM_I64V(1), WASM_I64V(0))});
  CHECK_EQ(1, r.Call());
}

WASM_EXEC_TEST(I64x2ExtractWithF64x2) {
  WasmRunner<int64_t> r(execution_tier);
  r.Build(
      {WASM_IF_ELSE_L(WASM_I64_EQ(WASM_SIMD_I64x2_EXTRACT_LANE(
                                      0, WASM_SIMD_F64x2_SPLAT(WASM_F64(1e15))),
                                  WASM_I64_REINTERPRET_F64(WASM_F64(1e15))),
                      WASM_I64V(1), WASM_I64V(0))});
  CHECK_EQ(1, r.Call());
}

WASM_EXEC_TEST(F64x2Abs) {
  RunF64x2UnOpTest(execution_tier, kExprF64x2Abs, std::abs);
}

WASM_EXEC_TEST(F64x2Neg) {
  RunF64x2UnOpTest(execution_tier, kExprF64x2Neg, Negate);
}

WASM_EXEC_TEST(F64x2Sqrt) {
  RunF64x2UnOpTest(execution_tier, kExprF64x2Sqrt, std::sqrt);
}

WASM_EXEC_TEST(F64x2Ceil) {
  RunF64x2UnOpTest(execution_tier, kExprF64x2Ceil, ceil, true);
}

WASM_EXEC_TEST(F64x2Floor) {
  RunF64x2UnOpTest(execution_tier, kExprF64x2Floor, floor, true);
}

WASM_EXEC_TEST(F64x2Trunc) {
  RunF64x2UnOpTest(execution_tier, kExprF64x2Trunc, trunc, true);
}

WASM_EXEC_TEST(F64x2NearestInt) {
  RunF64x2UnOpTest(execution_tier, kExprF64x2NearestInt, nearbyint, true);
}

template <typename SrcType>
void RunF64x2ConvertLowI32x4Test(TestExecutionTier execution_tier,
                                 WasmOpcode opcode) {
  WasmRunner<int32_t, SrcType> r(execution_tier);
  double* g = r.builder().template AddGlobal<double>(kWasmS128);
  r.Build({WASM_GLOBAL_SET(
               0, WASM_SIMD_UNOP(
                      opcode,
                      // Set top lane of i64x2 == set top 2 lanes of i32x4.
                      WASM_SIMD_I64x2_REPLACE_LANE(
                          1, WASM_SIMD_I32x4_SPLAT(WASM_LOCAL_GET(0)),
                          WASM_ZERO64))),
           WASM_ONE});

  for (SrcType x : compiler::ValueHelper::GetVector<SrcType>()) {
    r.Call(x);
    double expected = static_cast<double>(x);
    for (int i = 0; i < 2; i++) {
      double actual = LANE(g, i);
      CheckDoubleResult(x, x, expected, actual, true);
    }
  }
}

WASM_EXEC_TEST(F64x2ConvertLowI32x4S) {
  RunF64x2ConvertLowI32x4Test<int32_t>(execution_tier,
                                       kExprF64x2ConvertLowI32x4S);
}

WASM_EXEC_TEST(F64x2ConvertLowI32x4U) {
  RunF64x2ConvertLowI32x4Test<uint32_t>(execution_tier,
                                        kExprF64x2ConvertLowI32x4U);
}

template <typename SrcType>
void RunI32x4TruncSatF64x2Test(TestExecutionTier execution_tier,
                               WasmOpcode opcode) {
  WasmRunner<int32_t, double> r(execution_tier);
  SrcType* g = r.builder().AddGlobal<SrcType>(kWasmS128);
  r.Build({WASM_GLOBAL_SET(0, WASM_SIMD_UNOP(opcode, WASM_SIMD_F64x2_SPLAT(
                                                         WASM_LOCAL_GET(0)))),
           WASM_ONE});

  FOR_FLOAT64_INPUTS(x) {
    r.Call(x);
    SrcType expected = base::saturated_cast<SrcType>(x);
    for (int i = 0; i < 2; i++) {
      SrcType actual = LANE(g, i);
      CHECK_EQ(expected, actual);
    }
    // Top lanes are zero-ed.
    for (int i = 2; i < 4; i++) {
      CHECK_EQ(0, LANE(g, i));
    }
  }
}

WASM_EXEC_TEST(I32x4TruncSatF64x2SZero) {
  RunI32x4TruncSatF64x2Test<int32_t>(execution_tier,
                                     kExprI32x4TruncSatF64x2SZero);
}

WASM_EXEC_TEST(I32x4TruncSatF64x2UZero) {
  RunI32x4TruncSatF64x2Test<uint32_t>(execution_tier,
                                      kExprI32x4TruncSatF64x2UZero);
}

WASM_EXEC_TEST(F32x4DemoteF64x2Zero) {
  WasmRunner<int32_t, double> r(execution_tier);
  float* g = r.builder().AddGlobal<float>(kWasmS128);
  r.Build({WASM_GLOBAL_SET(
               0, WASM_SIMD_UNOP(kExprF32x4DemoteF64x2Zero,
                                 WASM_SIMD_F64x2_SPLAT(WASM_LOCAL_GET(0)))),
           WASM_ONE});

  FOR_FLOAT64_INPUTS(x) {
    r.Call(x);
    float expected = DoubleToFloat32(x);
    for (int i = 0; i < 2; i++) {
      float actual = LANE(g, i);
      CheckFloatResult(x, x, expected, actual, true);
    }
    for (int i = 2; i < 4; i++) {
      float actual = LANE(g, i);
      CheckFloatResult(x, x, 0, actual, true);
    }
  }
}

WASM_EXEC_TEST(F64x2PromoteLowF32x4) {
  WasmRunner<int32_t, float> r(execution_tier);
  double* g = r.builder().AddGlobal<double>(kWasmS128);
  r.Build({WASM_GLOBAL_SET(
               0, WASM_SIMD_UNOP(kExprF64x2PromoteLowF32x4,
                                 WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(0)))),
           WASM_ONE});

  FOR_FLOAT32_INPUTS(x) {
    r.Call(x);
    double expected = static_cast<double>(x);
    for (int i = 0; i < 2; i++) {
      double actual = LANE(g, i);
      CheckDoubleResult(x, x, expected, actual, true);
    }
  }
}

// Test F64x2PromoteLowF32x4 with S128Load64Zero optimization (only on some
// architectures). These 2 opcodes should be fused into a single instruction
// with memory operands, which is tested in instruction-selector tests. This
// test checks that we get correct results.
WASM_EXEC_TEST(F64x2PromoteLowF32x4WithS128Load64Zero) {
  {
    WasmRunner<int32_t> r(execution_tier);
    double* g = r.builder().AddGlobal<double>(kWasmS128);
    float* memory =
        r.builder().AddMemoryElems<float>(kWasmPageSize / sizeof(float));
    r.builder().RandomizeMemory();
    r.builder().WriteMemory(&memory[0], 1.0f);
    r.builder().WriteMemory(&memory[1], 3.0f);
    r.builder().WriteMemory(&memory[2], 5.0f);
    r.builder().WriteMemory(&memory[3], 8.0f);

    // Load at 4 (index) + 4 (offset) bytes, which is 2 floats.
    r.Build({WASM_GLOBAL_SET(
                 0, WASM_SIMD_UNOP(kExprF64x2PromoteLowF32x4,
                                   WASM_SIMD_LOAD_OP_OFFSET(kExprS128Load64Zero,
                                                            WASM_I32V(4), 4))),
             WASM_ONE});

    r.Call();
    CHECK_EQ(5.0f, LANE(g, 0));
    CHECK_EQ(8.0f, LANE(g, 1));
  }

  {
    // OOB tests.
    WasmRunner<int32_t> r(execution_tier);
    r.builder().AddGlobal<double>(kWasmS128);
    r.builder().AddMemoryElems<float>(kWasmPageSize / sizeof(float));
    r.Build({WASM_GLOBAL_SET(0, WASM_SIMD_UNOP(kExprF64x2PromoteLowF32x4,
                                               WASM_SIMD_LOAD_OP(
                                                   kExprS128Load64Zero,
                                                   WASM_I32V(kWasmPageSize)))),
             WASM_ONE});

    CHECK_TRAP(r.Call());
  }
}

WASM_EXEC_TEST(F64x2Add) {
  RunF64x2BinOpTest(execution_tier, kExprF64x2Add, Add);
}

WASM_EXEC_TEST(F64x2Sub) {
  RunF64x2BinOpTest(execution_tier, kExprF64x2Sub, Sub);
}

WASM_EXEC_TEST(F64x2Mul) {
  RunF64x2BinOpTest(execution_tier, kExprF64x2Mul, Mul);
}

WASM_EXEC_TEST(F64x2Div) {
  RunF64x2BinOpTest(execution_tier, kExprF64x2Div, base::Divide);
}

WASM_EXEC_TEST(F64x2Pmin) {
  RunF64x2BinOpTest(execution_tier, kExprF64x2Pmin, Minimum);
}

WASM_EXEC_TEST(F64x2Pmax) {
  RunF64x2BinOpTest(execution_tier, kExprF64x2Pmax, Maximum);
}

WASM_EXEC_TEST(F64x2Eq) {
  RunF64x2CompareOpTest(execution_tier, kExprF64x2Eq, Equal);
}

WASM_EXEC_TEST(F64x2Ne) {
  RunF64x2CompareOpTest(execution_tier, kExprF64x2Ne, NotEqual);
}

WASM_EXEC_TEST(F64x2Gt) {
  RunF64x2CompareOpTest(execution_tier, kExprF64x2Gt, Greater);
}

WASM_EXEC_TEST(F64x2Ge) {
  RunF64x2CompareOpTest(execution_tier, kExprF64x2Ge, GreaterEqual);
}

WASM_EXEC_TEST(F64x2Lt) {
  RunF64x2CompareOpTest(execution_tier, kExprF64x2Lt, Less);
}

WASM_EXEC_TEST(F64x2Le) {
  RunF64x2CompareOpTest(execution_tier, kExprF64x2Le, LessEqual);
}

WASM_EXEC_TEST(F64x2EqZero) {
  RunF128CompareOpConstImmTest<double, int64_t>(execution_tier, kExprF64x2Eq,
                                                kExprF64x2Splat, Equal);
}

WASM_EXEC_TEST(F64x2NeZero) {
  RunF128CompareOpConstImmTest<double, int64_t>(execution_tier, kExprF64x2Ne,
                                                kExprF64x2Splat, NotEqual);
}

WASM_EXEC_TEST(F64x2GtZero) {
  RunF128CompareOpConstImmTest<double, int64_t>(execution_tier, kExprF64x2Gt,
                                                kExprF64x2Splat, Greater);
}

WASM_EXEC_TEST(F64x2GeZero) {
  RunF128CompareOpConstImmTest<double, int64_t>(execution_tier, kExprF64x2Ge,
                                                kExprF64x2Splat, GreaterEqual);
}

WASM_EXEC_TEST(F64x2LtZero) {
  RunF128CompareOpConstImmTest<double, int64_t>(execution_tier, kExprF64x2Lt,
                                                kExprF64x2Splat, Less);
}

WASM_EXEC_TEST(F64x2LeZero) {
  RunF128CompareOpConstImmTest<double, int64_t>(execution_tier, kExprF64x2Le,
                                                kExprF64x2Splat, LessEqual);
}

WASM_EXEC_TEST(F64x2Min) {
  RunF64x2BinOpTest(execution_tier, kExprF64x2Min, JSMin);
}

WASM_EXEC_TEST(F64x2Max) {
  RunF64x2BinOpTest(execution_tier, kExprF64x2Max, JSMax);
}

WASM_EXEC_TEST(I64x2Mul) {
  RunI64x2BinOpTest(execution_tier, kExprI64x2Mul, base::MulWithWraparound);
}

WASM_EXEC_TEST(I32x4Splat) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // Set up a global to hold output vector.
  int32_t* g = r.builder().AddGlobal<int32_t>(kWasmS128);
  uint8_t param1 = 0;
  r.Build({WASM_GLOBAL_SET(0, WASM_SIMD_I32x4_SPLAT(WASM_LOCAL_GET(param1))),
           WASM_ONE});

  FOR_INT32_INPUTS(x) {
    r.Call(x);
    int32_t expected = x;
    for (int i = 0; i < 4; i++) {
      int32_t actual = LANE(g, i);
      CHECK_EQ(actual, expected);
    }
  }
}

WASM_EXEC_TEST(I32x4ReplaceLane) {
  WasmRunner<int32_t> r(execution_tier);
  // Set up a global to hold input/output vector.
  int32_t* g = r.builder().AddGlobal<int32_t>(kWasmS128);
  // Build function to replace each lane with its index.
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I32x4_SPLAT(WASM_I32V(-1))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I32x4_REPLACE_LANE(
                                     0, WASM_LOCAL_GET(temp1), WASM_I32V(0))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I32x4_REPLACE_LANE(
                                     1, WASM_LOCAL_GET(temp1), WASM_I32V(1))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I32x4_REPLACE_LANE(
                                     2, WASM_LOCAL_GET(temp1), WASM_I32V(2))),
           WASM_GLOBAL_SET(0, WASM_SIMD_I32x4_REPLACE_LANE(
                                  3, WASM_LOCAL_GET(temp1), WASM_I32V(3))),
           WASM_ONE});

  r.Call();
  for (int32_t i = 0; i < 4; i++) {
    CHECK_EQ(i, LANE(g, i));
  }
}

WASM_EXEC_TEST(I16x8Splat) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // Set up a global to hold output vector.
  int16_t* g = r.builder().AddGlobal<int16_t>(kWasmS128);
  uint8_t param1 = 0;
  r.Build({WASM_GLOBAL_SET(0, WASM_SIMD_I16x8_SPLAT(WASM_LOCAL_GET(param1))),
           WASM_ONE});

  FOR_INT16_INPUTS(x) {
    r.Call(x);
    int16_t expected = x;
    for (int i = 0; i < 8; i++) {
      int16_t actual = LANE(g, i);
      CHECK_EQ(actual, expected);
    }
  }

  // Test values that do not fit in an int16.
  FOR_INT32_INPUTS(x) {
    r.Call(x);
    int16_t expected = truncate_to_int16(x);
    for (int i = 0; i < 8; i++) {
      int16_t actual = LANE(g, i);
      CHECK_EQ(actual, expected);
    }
  }
}

WASM_EXEC_TEST(I16x8ReplaceLane) {
  WasmRunner<int32_t> r(execution_tier);
  // Set up a global to hold input/output vector.
  int16_t* g = r.builder().AddGlobal<int16_t>(kWasmS128);
  // Build function to replace each lane with its index.
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I16x8_SPLAT(WASM_I32V(-1))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I16x8_REPLACE_LANE(
                                     0, WASM_LOCAL_GET(temp1), WASM_I32V(0))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I16x8_REPLACE_LANE(
                                     1, WASM_LOCAL_GET(temp1), WASM_I32V(1))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I16x8_REPLACE_LANE(
                                     2, WASM_LOCAL_GET(temp1), WASM_I32V(2))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I16x8_REPLACE_LANE(
                                     3, WASM_LOCAL_GET(temp1), WASM_I32V(3))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I16x8_REPLACE_LANE(
                                     4, WASM_LOCAL_GET(temp1), WASM_I32V(4))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I16x8_REPLACE_LANE(
                                     5, WASM_LOCAL_GET(temp1), WASM_I32V(5))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I16x8_REPLACE_LANE(
                                     6, WASM_LOCAL_GET(temp1), WASM_I32V(6))),
           WASM_GLOBAL_SET(0, WASM_SIMD_I16x8_REPLACE_LANE(
                                  7, WASM_LOCAL_GET(temp1), WASM_I32V(7))),
           WASM_ONE});

  r.Call();
  for (int16_t i = 0; i < 8; i++) {
    CHECK_EQ(i, LANE(g, i));
  }
}

WASM_EXEC_TEST(I8x16BitMask) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  uint8_t value1 = r.AllocateLocal(kWasmS128);

  r.Build(
      {WASM_LOCAL_SET(value1, WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(0))),
       WASM_LOCAL_SET(value1, WASM_SIMD_I8x16_REPLACE_LANE(
                                  0, WASM_LOCAL_GET(value1), WASM_I32V(0))),
       WASM_LOCAL_SET(value1, WASM_SIMD_I8x16_REPLACE_LANE(
                                  1, WASM_LOCAL_GET(value1), WASM_I32V(-1))),
       WASM_SIMD_UNOP(kExprI8x16BitMask, WASM_LOCAL_GET(value1))});

  FOR_INT8_INPUTS(x) {
    int32_t actual = r.Call(x);
    // Lane 0 is always 0 (positive), lane 1 is always -1.
    int32_t expected = std::signbit(static_cast<double>(x)) ? 0xFFFE : 0x0002;
    CHECK_EQ(actual, expected);
  }
}

WASM_EXEC_TEST(I16x8BitMask) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  uint8_t value1 = r.AllocateLocal(kWasmS128);

  r.Build(
      {WASM_LOCAL_SET(value1, WASM_SIMD_I16x8_SPLAT(WASM_LOCAL_GET(0))),
       WASM_LOCAL_SET(value1, WASM_SIMD_I16x8_REPLACE_LANE(
                                  0, WASM_LOCAL_GET(value1), WASM_I32V(0))),
       WASM_LOCAL_SET(value1, WASM_SIMD_I16x8_REPLACE_LANE(
                                  1, WASM_LOCAL_GET(value1), WASM_I32V(-1))),
       WASM_SIMD_UNOP(kExprI16x8BitMask, WASM_LOCAL_GET(value1))});

  FOR_INT16_INPUTS(x) {
    int32_t actual = r.Call(x);
    // Lane 0 is always 0 (positive), lane 1 is always -1.
    int32_t expected = std::signbit(static_cast<double>(x)) ? 0xFE : 2;
    CHECK_EQ(actual, expected);
  }
}

WASM_EXEC_TEST(I32x4BitMask) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  uint8_t value1 = r.AllocateLocal(kWasmS128);

  r.Build(
      {WASM_LOCAL_SET(value1, WASM_SIMD_I32x4_SPLAT(WASM_LOCAL_GET(0))),
       WASM_LOCAL_SET(value1, WASM_SIMD_I32x4_REPLACE_LANE(
                                  0, WASM_LOCAL_GET(value1), WASM_I32V(0))),
       WASM_LOCAL_SET(value1, WASM_SIMD_I32x4_REPLACE_LANE(
                                  1, WASM_LOCAL_GET(value1), WASM_I32V(-1))),
       WASM_SIMD_UNOP(kExprI32x4BitMask, WASM_LOCAL_GET(value1))});

  FOR_INT32_INPUTS(x) {
    int32_t actual = r.Call(x);
    // Lane 0 is always 0 (positive), lane 1 is always -1.
    int32_t expected = std::signbit(static_cast<double>(x)) ? 0xE : 2;
    CHECK_EQ(actual, expected);
  }
}

WASM_EXEC_TEST(I64x2BitMask) {
  WasmRunner<int32_t, int64_t> r(execution_tier);
  uint8_t value1 = r.AllocateLocal(kWasmS128);

  r.Build(
      {WASM_LOCAL_SET(value1, WASM_SIMD_I64x2_SPLAT(WASM_LOCAL_GET(0))),
       WASM_LOCAL_SET(value1, WASM_SIMD_I64x2_REPLACE_LANE(
                                  0, WASM_LOCAL_GET(value1), WASM_I64V_1(0))),
       WASM_SIMD_UNOP(kExprI64x2BitMask, WASM_LOCAL_GET(value1))});

  for (int64_t x : compiler::ValueHelper::GetVector<int64_t>()) {
    int32_t actual = r.Call(x);
    // Lane 0 is always 0 (positive).
    int32_t expected = std::signbit(static_cast<double>(x)) ? 0x2 : 0x0;
    CHECK_EQ(actual, expected);
  }
}

WASM_EXEC_TEST(I8x16Splat) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // Set up a global to hold output vector.
  int8_t* g = r.builder().AddGlobal<int8_t>(kWasmS128);
  uint8_t param1 = 0;
  r.Build({WASM_GLOBAL_SET(0, WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(param1))),
           WASM_ONE});

  FOR_INT8_INPUTS(x) {
    r.Call(x);
    int8_t expected = x;
    for (int i = 0; i < 16; i++) {
      int8_t actual = LANE(g, i);
      CHECK_EQ(actual, expected);
    }
  }

  // Test values that do not fit in an int16.
  FOR_INT16_INPUTS(x) {
    r.Call(x);
    int8_t expected = truncate_to_int8(x);
    for (int i = 0; i < 16; i++) {
      int8_t actual = LANE(g, i);
      CHECK_EQ(actual, expected);
    }
  }
}

WASM_EXEC_TEST(I8x16ReplaceLane) {
  WasmRunner<int32_t> r(execution_tier);
  // Set up a global to hold input/output vector.
  int8_t* g = r.builder().AddGlobal<int8_t>(kWasmS128);
  // Build function to replace each lane with its index.
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_SPLAT(WASM_I32V(-1))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_REPLACE_LANE(
                                     0, WASM_LOCAL_GET(temp1), WASM_I32V(0))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_REPLACE_LANE(
                                     1, WASM_LOCAL_GET(temp1), WASM_I32V(1))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_REPLACE_LANE(
                                     2, WASM_LOCAL_GET(temp1), WASM_I32V(2))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_REPLACE_LANE(
                                     3, WASM_LOCAL_GET(temp1), WASM_I32V(3))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_REPLACE_LANE(
                                     4, WASM_LOCAL_GET(temp1), WASM_I32V(4))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_REPLACE_LANE(
                                     5, WASM_LOCAL_GET(temp1), WASM_I32V(5))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_REPLACE_LANE(
                                     6, WASM_LOCAL_GET(temp1), WASM_I32V(6))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_REPLACE_LANE(
                                     7, WASM_LOCAL_GET(temp1), WASM_I32V(7))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_REPLACE_LANE(
                                     8, WASM_LOCAL_GET(temp1), WASM_I32V(8))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_REPLACE_LANE(
                                     9, WASM_LOCAL_GET(temp1), WASM_I32V(9))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_REPLACE_LANE(
                                     10, WASM_LOCAL_GET(temp1), WASM_I32V(10))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_REPLACE_LANE(
                                     11, WASM_LOCAL_GET(temp1), WASM_I32V(11))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_REPLACE_LANE(
                                     12, WASM_LOCAL_GET(temp1), WASM_I32V(12))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_REPLACE_LANE(
                                     13, WASM_LOCAL_GET(temp1), WASM_I32V(13))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_REPLACE_LANE(
                                     14, WASM_LOCAL_GET(temp1), WASM_I32V(14))),
           WASM_GLOBAL_SET(0, WASM_SIMD_I8x16_REPLACE_LANE(
                                  15, WASM_LOCAL_GET(temp1), WASM_I32V(15))),
           WASM_ONE});

  r.Call();
  for (int8_t i = 0; i < 16; i++) {
    CHECK_EQ(i, LANE(g, i));
  }
}

// Use doubles to ensure exact conversion.
int32_t ConvertToInt(double val, bool unsigned_integer) {
  if (std::isnan(val)) return 0;
  if (unsigned_integer) {
    if (val < 0) return 0;
    if (val > kMaxUInt32) return kMaxUInt32;
    return static_cast<uint32_t>(val);
  } else {
    if (val < kMinInt) return kMinInt;
    if (val > kMaxInt) return kMaxInt;
    return static_cast<int>(val);
  }
}

// Tests both signed and unsigned conversion.
WASM_EXEC_TEST(I32x4ConvertF32x4) {
  WasmRunner<int32_t, float> r(execution_tier);
  // Create two output vectors to hold signed and unsigned results.
  int32_t* g0 = r.builder().AddGlobal<int32_t>(kWasmS128);
  int32_t* g1 = r.builder().AddGlobal<int32_t>(kWasmS128);
  // Build fn to splat test value, perform conversions, and write the results.
  uint8_t value = 0;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(value))),
           WASM_GLOBAL_SET(0, WASM_SIMD_UNOP(kExprI32x4SConvertF32x4,
                                             WASM_LOCAL_GET(temp1))),
           WASM_GLOBAL_SET(1, WASM_SIMD_UNOP(kExprI32x4UConvertF32x4,
                                             WASM_LOCAL_GET(temp1))),
           WASM_ONE});

  FOR_FLOAT32_INPUTS(x) {
    if (!PlatformCanRepresent(x)) continue;
    r.Call(x);
    int32_t expected_signed = ConvertToInt(x, false);
    int32_t expected_unsigned = ConvertToInt(x, true);
    for (int i = 0; i < 4; i++) {
      CHECK_EQ(expected_signed, LANE(g0, i));
      CHECK_EQ(expected_unsigned, LANE(g1, i));
    }
  }
}

// Tests both signed and unsigned conversion from I16x8 (unpacking).
WASM_EXEC_TEST(I32x4ConvertI16x8) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // Create four output vectors to hold signed and unsigned results.
  int32_t* g0 = r.builder().AddGlobal<int32_t>(kWasmS128);
  int32_t* g1 = r.builder().AddGlobal<int32_t>(kWasmS128);
  int32_t* g2 = r.builder().AddGlobal<int32_t>(kWasmS128);
  int32_t* g3 = r.builder().AddGlobal<int32_t>(kWasmS128);
  // Build fn to splat test value, perform conversions, and write the results.
  uint8_t value = 0;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I16x8_SPLAT(WASM_LOCAL_GET(value))),
           WASM_GLOBAL_SET(0, WASM_SIMD_UNOP(kExprI32x4SConvertI16x8High,
                                             WASM_LOCAL_GET(temp1))),
           WASM_GLOBAL_SET(1, WASM_SIMD_UNOP(kExprI32x4SConvertI16x8Low,
                                             WASM_LOCAL_GET(temp1))),
           WASM_GLOBAL_SET(2, WASM_SIMD_UNOP(kExprI32x4UConvertI16x8High,
                                             WASM_LOCAL_GET(temp1))),
           WASM_GLOBAL_SET(3, WASM_SIMD_UNOP(kExprI32x4UConvertI16x8Low,
                                             WASM_LOCAL_GET(temp1))),
           WASM_ONE});

  FOR_INT16_INPUTS(x) {
    r.Call(x);
    int32_t expected_signed = static_cast<int32_t>(x);
    int32_t expected_unsigned = static_cast<int32_t>(static_cast<uint16_t>(x));
    for (int i = 0; i < 4; i++) {
      CHECK_EQ(expected_signed, LANE(g0, i));
      CHECK_EQ(expected_signed, LANE(g1, i));
      CHECK_EQ(expected_unsigned, LANE(g2, i));
      CHECK_EQ(expected_unsigned, LANE(g3, i));
    }
  }
}

// Tests both signed and unsigned conversion from I32x4 (unpacking).
WASM_EXEC_TEST(I64x2ConvertI32x4) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // Create four output vectors to hold signed and unsigned results.
  int64_t* g0 = r.builder().AddGlobal<int64_t>(kWasmS128);
  int64_t* g1 = r.builder().AddGlobal<int64_t>(kWasmS128);
  uint64_t* g2 = r.builder().AddGlobal<uint64_t>(kWasmS128);
  uint64_t* g3 = r.builder().AddGlobal<uint64_t>(kWasmS128);
  // Build fn to splat test value, perform conversions, and write the results.
  uint8_t value = 0;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I32x4_SPLAT(WASM_LOCAL_GET(value))),
           WASM_GLOBAL_SET(0, WASM_SIMD_UNOP(kExprI64x2SConvertI32x4High,
                                             WASM_LOCAL_GET(temp1))),
           WASM_GLOBAL_SET(1, WASM_SIMD_UNOP(kExprI64x2SConvertI32x4Low,
                                             WASM_LOCAL_GET(temp1))),
           WASM_GLOBAL_SET(2, WASM_SIMD_UNOP(kExprI64x2UConvertI32x4High,
                                             WASM_LOCAL_GET(temp1))),
           WASM_GLOBAL_SET(3, WASM_SIMD_UNOP(kExprI64x2UConvertI32x4Low,
                                             WASM_LOCAL_GET(temp1))),
           WASM_ONE});

  FOR_INT32_INPUTS(x) {
    r.Call(x);
    int64_t expected_signed = static_cast<int64_t>(x);
    uint64_t expected_unsigned =
        static_cast<uint64_t>(static_cast<uint32_t>(x));
    for (int i = 0; i < 2; i++) {
      CHECK_EQ(expected_signed, LANE(g0, i));
      CHECK_EQ(expected_signed, LANE(g1, i));
      CHECK_EQ(expected_unsigned, LANE(g2, i));
      CHECK_EQ(expected_unsigned, LANE(g3, i));
    }
  }
}

WASM_EXEC_TEST(I32x4Neg) {
  RunI32x4UnOpTest(execution_tier, kExprI32x4Neg, base::NegateWithWraparound);
}

WASM_EXEC_TEST(I32x4Abs) {
  RunI32x4UnOpTest(execution_tier, kExprI32x4Abs, std::abs);
}

WASM_EXEC_TEST(S128Not) {
  RunI32x4UnOpTest(execution_tier, kExprS128Not, [](int32_t x) { return ~x; });
}

template <typename Narrow, typename Wide>
void RunExtAddPairwiseTest(TestExecutionTier execution_tier,
                           WasmOpcode ext_add_pairwise, WasmOpcode splat,
                           Shuffle interleaving_shuffle) {
  constexpr int num_lanes = kSimd128Size / sizeof(Wide);
  WasmRunner<int32_t, Narrow, Narrow> r(execution_tier);
  Wide* g = r.builder().template AddGlobal<Wide>(kWasmS128);

  r.Build({WASM_SIMD_I8x16_SHUFFLE_OP(kExprI8x16Shuffle, interleaving_shuffle,
                                      WASM_SIMD_UNOP(splat, WASM_LOCAL_GET(0)),
                                      WASM_SIMD_UNOP(splat, WASM_LOCAL_GET(1))),
           WASM_SIMD_OP(ext_add_pairwise), kExprGlobalSet, 0, WASM_ONE});

  auto v = compiler::ValueHelper::GetVector<Narrow>();
  // Iterate vector from both ends to try and splat two different values.
  for (auto i = v.begin(), j = v.end() - 1; i < v.end(); i++, j--) {
    r.Call(*i, *j);
    Wide expected = AddLong<Wide>(*i, *j);
    for (int l = 0; l < num_lanes; l++) {
      CHECK_EQ(expected, LANE(g, l));
    }
  }
}

// interleave even lanes from one input and odd lanes from another.
constexpr Shuffle interleave_16x8_shuffle = {0, 1, 18, 19, 4,  5,  22, 23,
                                             8, 9, 26, 27, 12, 13, 30, 31};
constexpr Shuffle interleave_8x16_shuffle = {0, 17, 2,  19, 4,  21, 6,  23,
                                             8, 25, 10, 27, 12, 29, 14, 31};

WASM_EXEC_TEST(I32x4ExtAddPairwiseI16x8S) {
  RunExtAddPairwiseTest<int16_t, int32_t>(
      execution_tier, kExprI32x4ExtAddPairwiseI16x8S, kExprI16x8Splat,
      interleave_16x8_shuffle);
}

WASM_EXEC_TEST(I32x4ExtAddPairwiseI16x8U) {
  RunExtAddPairwiseTest<uint16_t, uint32_t>(
      execution_tier, kExprI32x4ExtAddPairwiseI16x8U, kExprI16x8Splat,
      interleave_16x8_shuffle);
}

WASM_EXEC_TEST(I16x8ExtAddPairwiseI8x16S) {
  RunExtAddPairwiseTest<int8_t, int16_t>(
      execution_tier, kExprI16x8ExtAddPairwiseI8x16S, kExprI8x16Splat,
      interleave_8x16_shuffle);
}

WASM_EXEC_TEST(I16x8ExtAddPairwiseI8x16U) {
  RunExtAddPairwiseTest<uint8_t, uint16_t>(
      execution_tier, kExprI16x8ExtAddPairwiseI8x16U, kExprI8x16Splat,
      interleave_8x16_shuffle);
}

WASM_EXEC_TEST(I32x4Add) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4Add, base::AddWithWraparound);
}

WASM_EXEC_TEST(I32x4Sub) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4Sub, base::SubWithWraparound);
}

WASM_EXEC_TEST(I32x4Mul) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4Mul, base::MulWithWraparound);
}

WASM_EXEC_TEST(I32x4MinS) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4MinS, Minimum);
}

WASM_EXEC_TEST(I32x4MaxS) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4MaxS, Maximum);
}

WASM_EXEC_TEST(I32x4MinU) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4MinU, UnsignedMinimum);
}
WASM_EXEC_TEST(I32x4MaxU) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4MaxU,

                    UnsignedMaximum);
}

WASM_EXEC_TEST(S128And) {
  RunI32x4BinOpTest(execution_tier, kExprS128And,
                    [](int32_t x, int32_t y) { return x & y; });
}

enum ConstSide { kConstLeft, kConstRight };

template <typename ScalarType>
using BinOp = ScalarType (*)(ScalarType, ScalarType);
template <typename ScalarType>
void RunS128ConstBinOpTest(TestExecutionTier execution_tier,
                           ConstSide const_side, WasmOpcode binop_opcode,
                           WasmOpcode splat_opcode,
                           BinOp<ScalarType> expected_op) {
  for (ScalarType x : compiler::ValueHelper::GetVector<ScalarType>()) {
    WasmRunner<int32_t, ScalarType> r(execution_tier);
    // Global to hold output.
    ScalarType* g = r.builder().template AddGlobal<ScalarType>(kWasmS128);
    // Build a function to splat one argument into a local,
    // and execute the op with a const as the second argument
    uint8_t value = 0;
    uint8_t temp = r.AllocateLocal(kWasmS128);
    uint8_t const_buffer[16];
    for (size_t i = 0; i < kSimd128Size / sizeof(ScalarType); i++) {
      WriteLittleEndianValue<ScalarType>(
          reinterpret_cast<ScalarType*>(&const_buffer[0]) + i, x);
    }
    switch (const_side) {
      case kConstLeft:
        r.Build({WASM_LOCAL_SET(
                     temp, WASM_SIMD_OPN(splat_opcode, WASM_LOCAL_GET(value))),
                 WASM_GLOBAL_SET(
                     0, WASM_SIMD_BINOP(binop_opcode,
                                        WASM_SIMD_CONSTANT(const_buffer),
                                        WASM_LOCAL_GET(temp))),
                 WASM_ONE});
        break;
      case kConstRight:
        r.Build({WASM_LOCAL_SET(
                     temp, WASM_SIMD_OPN(splat_opcode, WASM_LOCAL_GET(value))),
                 WASM_GLOBAL_SET(
                     0, WASM_SIMD_BINOP(binop_opcode, WASM_LOCAL_GET(temp),
                                        WASM_SIMD_CONSTANT(const_buffer))),
                 WASM_ONE});
        break;
    }
    for (ScalarType y : compiler::ValueHelper::GetVector<ScalarType>()) {
      r.Call(y);
      ScalarType expected =
          (const_side == kConstLeft) ? expected_op(x, y) : expected_op(y, x);
      for (size_t i = 0; i < kSimd128Size / sizeof(ScalarType); i++) {
        CHECK_EQ(expected, LANE(g, i));
      }
    }
  }
}

WASM_EXEC_TEST(S128AndImm) {
  RunS128ConstBinOpTest<int32_t>(execution_tier, kConstLeft, kExprS128And,
                                 kExprI32x4Splat,
                                 [](int32_t x, int32_t y) { return x & y; });
  RunS128ConstBinOpTest<int32_t>(execution_tier, kConstRight, kExprS128And,
                                 kExprI32x4Splat,
                                 [](int32_t x, int32_t y) { return x & y; });
  RunS128ConstBinOpTest<int16_t>(
      execution_tier, kConstLeft, kExprS128And, kExprI16x8Splat,
      [](int16_t x, int16_t y) { return static_cast<int16_t>(x & y); });
  RunS128ConstBinOpTest<int16_t>(
      execution_tier, kConstRight, kExprS128And, kExprI16x8Splat,
      [](int16_t x, int16_t y) { return static_cast<int16_t>(x & y); });
}

WASM_EXEC_TEST(S128Or) {
  RunI32x4BinOpTest(execution_tier, kExprS128Or,
                    [](int32_t x, int32_t y) { return x | y; });
}

WASM_EXEC_TEST(S128Xor) {
  RunI32x4BinOpTest(execution_tier, kExprS128Xor,
                    [](int32_t x, int32_t y) { return x ^ y; });
}

// Bitwise operation, doesn't really matter what simd type we test it with.
WASM_EXEC_TEST(S128AndNot) {
  RunI32x4BinOpTest(execution_tier, kExprS128AndNot,
                    [](int32_t x, int32_t y) { return x & ~y; });
}

WASM_EXEC_TEST(S128AndNotImm) {
  RunS128ConstBinOpTest<int32_t>(execution_tier, kConstLeft, kExprS128AndNot,
                                 kExprI32x4Splat,
                                 [](int32_t x, int32_t y) { return x & ~y; });
  RunS128ConstBinOpTest<int32_t>(execution_tier, kConstRight, kExprS128AndNot,
                                 kExprI32x4Splat,
                                 [](int32_t x, int32_t y) { return x & ~y; });
  RunS128ConstBinOpTest<int16_t>(
      execution_tier, kConstLeft, kExprS128AndNot, kExprI16x8Splat,
      [](int16_t x, int16_t y) { return static_cast<int16_t>(x & ~y); });
  RunS128ConstBinOpTest<int16_t>(
      execution_tier, kConstRight, kExprS128AndNot, kExprI16x8Splat,
      [](int16_t x, int16_t y) { return static_cast<int16_t>(x & ~y); });
}

WASM_EXEC_TEST(I32x4Eq) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4Eq, Equal);
}

WASM_EXEC_TEST(I32x4Ne) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4Ne, NotEqual);
}

WASM_EXEC_TEST(I32x4LtS) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4LtS, Less);
}

WASM_EXEC_TEST(I32x4LeS) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4LeS, LessEqual);
}

WASM_EXEC_TEST(I32x4GtS) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4GtS, Greater);
}

WASM_EXEC_TEST(I32x4GeS) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4GeS, GreaterEqual);
}

WASM_EXEC_TEST(I32x4LtU) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4LtU, UnsignedLess);
}

WASM_EXEC_TEST(I32x4LeU) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4LeU, UnsignedLessEqual);
}

WASM_EXEC_TEST(I32x4GtU) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4GtU, UnsignedGreater);
}

WASM_EXEC_TEST(I32x4GeU) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4GeU, UnsignedGreaterEqual);
}

WASM_EXEC_TEST(I32x4EqZero) {
  RunICompareOpConstImmTest<int32_t>(execution_tier, kExprI32x4Eq,
                                     kExprI32x4Splat, Equal);
}

WASM_EXEC_TEST(I32x4NeZero) {
  RunICompareOpConstImmTest<int32_t>(execution_tier, kExprI32x4Ne,
                                     kExprI32x4Splat, NotEqual);
}

WASM_EXEC_TEST(I32x4GtZero) {
  RunICompareOpConstImmTest<int32_t>(execution_tier, kExprI32x4GtS,
                                     kExprI32x4Splat, Greater);
}

WASM_EXEC_TEST(I32x4GeZero) {
  RunICompareOpConstImmTest<int32_t>(execution_tier, kExprI32x4GeS,
                                     kExprI32x4Splat, GreaterEqual);
}

WASM_EXEC_TEST(I32x4LtZero) {
  RunICompareOpConstImmTest<int32_t>(execution_tier, kExprI32x4LtS,
                                     kExprI32x4Splat, Less);
}

WASM_EXEC_TEST(I32x4LeZero) {
  RunICompareOpConstImmTest<int32_t>(execution_tier, kExprI32x4LeS,
                                     kExprI32x4Splat, LessEqual);
}

WASM_EXEC_TEST(I32x4Shl) {
  RunI32x4ShiftOpTest(execution_tier, kExprI32x4Shl, LogicalShiftLeft);
}

WASM_EXEC_TEST(I32x4ShrS) {
  RunI32x4ShiftOpTest(execution_tier, kExprI32x4ShrS, ArithmeticShiftRight);
}

WASM_EXEC_TEST(I32x4ShrU) {
  RunI32x4ShiftOpTest(execution_tier, kExprI32x4ShrU, LogicalShiftRight);
}

WASM_EXEC_TEST(I32x4ShiftAdd) {
  for (int imm = 0; imm <= 32; imm++) {
    RunShiftAddTestSequence<int32_t>(execution_tier, kExprI32x4ShrU,
                                     kExprI32x4Add, kExprI32x4Splat, imm,
                                     LogicalShiftRight);
    RunShiftAddTestSequence<int32_t>(execution_tier, kExprI32x4ShrS,
                                     kExprI32x4Add, kExprI32x4Splat, imm,
                                     ArithmeticShiftRight);
  }
}

// Tests both signed and unsigned conversion from I8x16 (unpacking).
WASM_EXEC_TEST(I16x8ConvertI8x16) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // Create four output vectors to hold signed and unsigned results.
  int16_t* g0 = r.builder().AddGlobal<int16_t>(kWasmS128);
  int16_t* g1 = r.builder().AddGlobal<int16_t>(kWasmS128);
  int16_t* g2 = r.builder().AddGlobal<int16_t>(kWasmS128);
  int16_t* g3 = r.builder().AddGlobal<int16_t>(kWasmS128);
  // Build fn to splat test value, perform conversions, and write the results.
  uint8_t value = 0;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(value))),
           WASM_GLOBAL_SET(0, WASM_SIMD_UNOP(kExprI16x8SConvertI8x16High,
                                             WASM_LOCAL_GET(temp1))),
           WASM_GLOBAL_SET(1, WASM_SIMD_UNOP(kExprI16x8SConvertI8x16Low,
                                             WASM_LOCAL_GET(temp1))),
           WASM_GLOBAL_SET(2, WASM_SIMD_UNOP(kExprI16x8UConvertI8x16High,
                                             WASM_LOCAL_GET(temp1))),
           WASM_GLOBAL_SET(3, WASM_SIMD_UNOP(kExprI16x8UConvertI8x16Low,
                                             WASM_LOCAL_GET(temp1))),
           WASM_ONE});

  FOR_INT8_INPUTS(x) {
    r.Call(x);
    int16_t expected_signed = static_cast<int16_t>(x);
    int16_t expected_unsigned = static_cast<int16_t>(static_cast<uint8_t>(x));
    for (int i = 0; i < 8; i++) {
      CHECK_EQ(expected_signed, LANE(g0, i));
      CHECK_EQ(expected_signed, LANE(g1, i));
      CHECK_EQ(expected_unsigned, LANE(g2, i));
      CHECK_EQ(expected_unsigned, LANE(g3, i));
    }
  }
}

// Tests both signed and unsigned conversion from I32x4 (packing).
WASM_EXEC_TEST(I16x8ConvertI32x4) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // Create output vectors to hold signed and unsigned results.
  int16_t* g0 = r.builder().AddGlobal<int16_t>(kWasmS128);
  int16_t* g1 = r.builder().AddGlobal<int16_t>(kWasmS128);
  // Build fn to splat test value, perform conversions, and write the results.
  uint8_t value = 0;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I32x4_SPLAT(WASM_LOCAL_GET(value))),
           WASM_GLOBAL_SET(0, WASM_SIMD_BINOP(kExprI16x8SConvertI32x4,
                                              WASM_LOCAL_GET(temp1),
                                              WASM_LOCAL_GET(temp1))),
           WASM_GLOBAL_SET(1, WASM_SIMD_BINOP(kExprI16x8UConvertI32x4,
                                              WASM_LOCAL_GET(temp1),
                                              WASM_LOCAL_GET(temp1))),
           WASM_ONE});

  FOR_INT32_INPUTS(x) {
    r.Call(x);
    int16_t expected_signed = base::saturated_cast<int16_t>(x);
    int16_t expected_unsigned = base::saturated_cast<uint16_t>(x);
    for (int i = 0; i < 8; i++) {
      CHECK_EQ(expected_signed, LANE(g0, i));
      CHECK_EQ(expected_unsigned, LANE(g1, i));
    }
  }
}

WASM_EXEC_TEST(I16x8Neg) {
  RunI16x8UnOpTest(execution_tier, kExprI16x8Neg, base::NegateWithWraparound);
}

WASM_EXEC_TEST(I16x8Abs) {
  RunI16x8UnOpTest(execution_tier, kExprI16x8Abs, Abs);
}

WASM_EXEC_TEST(I16x8Add) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8Add, base::AddWithWraparound);
}

WASM_EXEC_TEST(I16x8AddSatS) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8AddSatS, SaturateAdd<int16_t>);
}

WASM_EXEC_TEST(I16x8Sub) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8Sub, base::SubWithWraparound);
}

WASM_EXEC_TEST(I16x8SubSatS) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8SubSatS, SaturateSub<int16_t>);
}

WASM_EXEC_TEST(I16x8Mul) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8Mul, base::MulWithWraparound);
}

WASM_EXEC_TEST(I16x8MinS) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8MinS, Minimum);
}

WASM_EXEC_TEST(I16x8MaxS) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8MaxS, Maximum);
}

WASM_EXEC_TEST(I16x8AddSatU) {
  RunI16x8BinOpTest<uint16_t>(execution_tier, kExprI16x8AddSatU,
                              SaturateAdd<uint16_t>);
}

WASM_EXEC_TEST(I16x8SubSatU) {
  RunI16x8BinOpTest<uint16_t>(execution_tier, kExprI16x8SubSatU,
                              SaturateSub<uint16_t>);
}

WASM_EXEC_TEST(I16x8MinU) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8MinU, UnsignedMinimum);
}

WASM_EXEC_TEST(I16x8MaxU) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8MaxU, UnsignedMaximum);
}

WASM_EXEC_TEST(I16x8Eq) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8Eq, Equal);
}

WASM_EXEC_TEST(I16x8Ne) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8Ne, NotEqual);
}

WASM_EXEC_TEST(I16x8LtS) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8LtS, Less);
}

WASM_EXEC_TEST(I16x8LeS) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8LeS, LessEqual);
}

WASM_EXEC_TEST(I16x8GtS) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8GtS, Greater);
}

WASM_EXEC_TEST(I16x8GeS) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8GeS, GreaterEqual);
}

WASM_EXEC_TEST(I16x8GtU) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8GtU, UnsignedGreater);
}

WASM_EXEC_TEST(I16x
"""


```