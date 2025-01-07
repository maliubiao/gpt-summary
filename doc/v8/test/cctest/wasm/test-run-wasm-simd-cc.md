Response:
The user wants to understand the functionality of the provided C++ code snippet, which is part of the V8 JavaScript engine's test suite. The specific file is `v8/test/cctest/wasm/test-run-wasm-simd.cc`.

Here's a breakdown of the thought process to generate the response:

1. **Identify the core purpose:** The filename and the `wasm-simd` mentions immediately suggest this code tests WebAssembly SIMD (Single Instruction, Multiple Data) functionality within V8. The `test-run` part implies it executes WASM code and checks the results.

2. **Analyze the includes:** The included headers provide clues about the code's functionality:
    * `<algorithm>`, `<array>`, `<cmath>`, etc.: Standard C++ library headers for common operations.
    * `"src/base/*"`: V8 base library functionalities, likely for low-level operations.
    * `"src/codegen/*"`: Code generation related components, hinting at how WASM SIMD is implemented.
    * `"src/compiler/*"`: Compiler-related components, suggesting the code interacts with the compilation process.
    * `"src/wasm/*"`:  Directly related to WebAssembly within V8, including value types, constants, and opcodes.
    * `"test/cctest/*"`:  Indicates this is part of the V8 testing framework.
    * `"test/cctest/wasm/*"`: Specifically for testing WASM functionality.
    * `"test/common/*"`: Common utilities used in V8 tests.

3. **Examine the namespaces:** The code is within `v8::internal::wasm::test_run_wasm_simd`. This confirms the scope and purpose.

4. **Look for key data structures and functions:**
    * `Shuffle`: An alias for `std::array<int8_t, kSimd128Size>`, indicating it's dealing with SIMD lane shuffling.
    * Template functions like `Add`, `Sub`, `Mul`, `Equal`, etc.: These are overloaded to handle different data types, likely for scalar SIMD lane operations and comparisons. The specializations for `float` and `double` in comparison functions are noteworthy. The comments about `base::AddWithWraparound` for integral types are also important.
    * Macros like `WASM_SIMD_CHECK_LANE_S` and `WASM_SIMD_CHECK_LANE_U`: These look like testing utilities to assert the correctness of SIMD lane extraction.
    * `WASM_EXEC_TEST`:  This strongly suggests the definition of individual test cases. The names of these tests (e.g., `S128Globals`, `F32x4Splat`) are highly indicative of the specific SIMD instructions or features being tested.

5. **Connect the dots:** The code appears to be a series of test cases (`WASM_EXEC_TEST`) that directly exercise different WASM SIMD instructions. These tests involve:
    * Setting up WASM modules with specific SIMD operations.
    * Executing these modules.
    * Comparing the results against expected values calculated in the C++ test code.

6. **Address specific questions from the prompt:**
    * **Functionality:** As stated above, it tests WASM SIMD instructions.
    * **`.tq` extension:** The code snippet is `.cc`, so it's C++, not Torque.
    * **Relationship to JavaScript:** WASM SIMD is exposed to JavaScript through the `WebAssembly.Simd` API. The tests here ensure the underlying V8 implementation correctly handles these operations. A JavaScript example would involve creating WASM modules using the SIMD API and observing their behavior.
    * **Code logic inference (with input/output):**  Each `WASM_EXEC_TEST` represents a specific logic test. For example, `F32x4Splat` tests creating a SIMD vector where all lanes have the same float value. If the input float is `3.14`, the expected output is a `float32x4` vector where all four lanes are `3.14`.
    * **Common programming errors:** While this code isn't directly user-facing, the tested operations relate to common SIMD programming errors like incorrect lane access, type mismatches, and misunderstanding the behavior of specific SIMD instructions (e.g., saturation, wrapping).
    * **Overall function (for part 1):**  This first part sets up foundational elements for testing WASM SIMD. It defines helper functions for comparing SIMD lane values and includes the initial set of test cases focusing on basic SIMD operations.

7. **Structure the response:** Organize the findings into clear points, addressing each part of the user's request. Use bullet points for readability and provide concrete examples where applicable. Ensure the language is clear and concise, avoiding overly technical jargon where possible.
这是 V8 JavaScript 引擎源代码的一部分，专门用于测试 WebAssembly (Wasm) 的 SIMD (Single Instruction, Multiple Data) 功能。

**功能归纳 (针对第 1 部分):**

这个代码文件的主要功能是定义了一系列的 C++ 测试用例，用于验证 V8 引擎在执行 WebAssembly SIMD 指令时的正确性。 它涵盖了以下几个方面：

* **基础 SIMD 操作的测试:**  测试了各种 SIMD 向量类型（如 `f32x4`, `i32x4`, `f64x2`, `i64x2`）的基本操作，例如：
    * **创建:**  例如 `splat` (将一个标量值填充到向量的所有通道)。
    * **访问和修改:**  例如提取 (`extract_lane`) 和替换 (`replace_lane`) 向量中的特定通道。
    * **一元运算:** 例如取绝对值 (`abs`)，取反 (`neg`)，平方根 (`sqrt`)，向上取整 (`ceil`)，向下取整 (`floor`)，截断 (`trunc`)，取最近整数 (`nearest_int`)。
    * **二元运算:** 例如加法 (`add`)，减法 (`sub`)，乘法 (`mul`)，除法 (`div`)，最小值 (`min`)，最大值 (`max`)，按位与、或、异或等。
    * **比较运算:** 例如等于 (`eq`)，不等于 (`ne`)，大于 (`gt`)，大于等于 (`ge`)，小于 (`lt`)，小于等于 (`le`)。
    * **类型转换:** 例如整数到浮点数的转换 (`convert_i32x4`)。
    * **位移操作:** 例如左移 (`shl`)，算术右移 (`shr_s`)，逻辑右移 (`shr_u`)。

* **测试框架集成:**  利用 V8 的测试框架 (`TEST`, `WASM_EXEC_TEST`) 来组织和运行测试用例。

* **辅助函数的定义:**  定义了一些模板函数 (`Add`, `Sub`, `Mul`, `Equal`, `NotEqual`, 等等) 来辅助进行 SIMD 操作的结果验证。这些函数针对不同的数据类型提供了正确的操作语义，特别是对于整数类型的环绕行为和浮点数的比较。

* **常量操作数的测试:**  部分测试用例专门针对 SIMD 指令与常量立即数的操作进行验证。

**关于代码的其他方面：**

* **`.tq` 后缀:**  `v8/test/cctest/wasm/test-run-wasm-simd.cc` 的后缀是 `.cc`，表明这是一个 **C++ 源代码文件**，而不是 Torque 源代码文件 (`.tq`)。

* **与 JavaScript 的关系:**  WebAssembly 的 SIMD 功能最终会暴露给 JavaScript。  这段 C++ 代码测试的是 V8 引擎 **内部** 对这些 SIMD 指令的实现。当 JavaScript 调用 WebAssembly 的 SIMD API 时，V8 引擎会执行相应的底层实现，而这些实现正是通过这样的测试来保证其正确性的。

* **JavaScript 示例:**

```javascript
// 假设浏览器支持 WebAssembly SIMD
const buffer = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, // 魔数和版本
  0x01, 0x00, 0x00, 0x00, // wasm 版本

  // ... 省略模块的其余部分，这里需要包含 SIMD 指令的函数 ...
]);

WebAssembly.instantiate(buffer)
  .then(module => {
    const instance = module.instance;

    // 假设 wasm 模块导出了一个名为 'add_f32x4' 的函数，它接受两个 f32x4 参数并返回一个 f32x4
    const a = new Float32Array([1.0, 2.0, 3.0, 4.0]);
    const b = new Float32Array([5.0, 6.0, 7.0, 8.0]);

    const result = instance.exports.add_f32x4(a, b);

    console.log(result); // 期望输出类似 Float32Array [ 6, 8, 10, 12 ]
  });
```

* **代码逻辑推理 (假设输入与输出):**

   考虑 `WASM_EXEC_TEST(F32x4Add)` 这个测试用例 (尽管代码中只展示了框架，具体实现可能在其他地方)。 假设测试的 WASM 代码执行了 `f32x4.add` 指令。

   **假设输入:**
   * SIMD 向量 1: `[1.0, 2.5, -3.0, 0.7]`
   * SIMD 向量 2: `[0.5, 1.5, 4.0, -1.2]`

   **预期输出:**
   * SIMD 结果向量: `[1.5, 4.0, 1.0, -0.5]` (对应位置的浮点数相加)

* **用户常见的编程错误 (与 SIMD 相关):**

   1. **类型不匹配:**  尝试对不同类型的 SIMD 向量进行操作，例如将 `i32x4` 和 `f32x4` 相加。WebAssembly 会进行类型检查，这样的操作通常会导致编译或运行时错误。

     ```javascript
     // WebAssembly (假设的文本格式)
     (module
       (func $add_mismatch (param $a v128 i32x4) (param $b v128 f32x4) (result v128)
         local.get $a
         local.get $b
         f32x4.add  ;; 类型错误！
       )
       (export "add_mismatch" (func $add_mismatch))
     )
     ```

   2. **错误的通道访问:**  访问超出向量边界的通道索引。SIMD 向量的通道数量是固定的（例如 `f32x4` 有 4 个通道，索引从 0 到 3）。访问不存在的通道会导致错误。

     ```c++
     // C++ (测试代码中可能会检查这种错误)
     // 假设 'vec' 是一个 f32x4 向量
     float value = LANE(vec, 4); // 错误：索引 4 超出范围
     ```

   3. **误解 SIMD 指令的行为:**  不理解特定 SIMD 指令的精确语义，例如饱和运算、环绕运算或比较运算的结果表示。

     ```c++
     // C++ (测试代码可能会验证这些行为)
     int32_t a = std::numeric_limits<int32_t>::max();
     int32_t b = 1;
     int32_t result = base::AddWithWraparound(a, b); // 期望发生环绕
     ```

   4. **不正确的内存对齐:**  某些 SIMD 加载和存储指令可能需要特定级别的内存对齐。如果数据没有正确对齐，可能会导致性能下降或错误。

**总结:**

`v8/test/cctest/wasm/test-run-wasm-simd.cc` 的第 1 部分是 V8 引擎中用于测试 WebAssembly SIMD 功能的核心测试代码，它通过定义各种 C++ 测试用例来验证基本 SIMD 操作的正确性。 这对于确保 V8 引擎能够正确执行 WebAssembly 的 SIMD 代码至关重要。

Prompt: 
```
这是目录为v8/test/cctest/wasm/test-run-wasm-simd.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/test-run-wasm-simd.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共9部分，请归纳一下它的功能

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
  RunF64x2Comp
"""


```