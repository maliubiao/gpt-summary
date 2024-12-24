Response: Let's break down the thought process for analyzing this C++ code and relating it to JavaScript.

1. **Understand the Goal:** The request asks for a summary of the C++ file's functionality and its connection to JavaScript, with a JavaScript example if applicable. The file path `v8/test/cctest/wasm/test-run-wasm-relaxed-simd.cc` immediately tells us it's a test file within the V8 project (the JavaScript engine used in Chrome and Node.js). The "wasm" and "relaxed-simd" parts indicate that it's testing WebAssembly's relaxed SIMD features.

2. **High-Level Structure Scan:** Quickly scan the file for key elements:
    * **Includes:** These tell us about the dependencies and areas of V8 being tested (e.g., `wasm`, `codegen`, `cpu-features`, `test/cctest`).
    * **Namespaces:** The code is within `v8::internal::wasm`, confirming it's internal V8 WebAssembly testing.
    * **Macros like `WASM_EXEC_TEST` and `TEST`:** These clearly mark the individual test cases.
    * **Data Structures:** The `FMOperation` struct and related arrays/vectors are important for understanding the purpose of some tests.
    * **Helper Functions:** Functions like `ExpectFused`, `as_uint8`, and the `RelaxedLaneSelectTest` family provide reusable test logic.
    * **Specific Function Names:**  Names like `F32x4Qfma`, `I8x16RelaxedLaneSelect`, `F32x4RelaxedMin`, and `I32x4RelaxedTruncF64x2SZero` are very informative about the specific WebAssembly instructions being tested.
    * **Conditional Compilation (`#ifdef`, `#if`):**  The presence of `#ifdef V8_ENABLE_WASM_SIMD256_REVEC` indicates tests for 256-bit SIMD extensions.

3. **Identify Core Functionality:** Based on the test names and code structure, the core functionality revolves around testing various **relaxed SIMD instructions** in WebAssembly. Specifically:
    * **Fused Multiply-Add/Subtract (QFMA/QFMS):**  The `FMOperation` struct and the `F32x4Qfma`, `F32x4Qfms`, etc., tests are focused on these operations. The code explicitly checks for "fused" vs. "unfused" behavior, which is a key aspect of these relaxed operations.
    * **Lane Select:** The `RelaxedLaneSelectTest` functions and tests like `I8x16RelaxedLaneSelect` are testing how elements are selected and rearranged within SIMD vectors.
    * **Relaxed Min/Max:**  Tests like `F32x4RelaxedMin` and `F64x2RelaxedMax` are verifying the behavior of relaxed min/max operations on SIMD vectors.
    * **Relaxed Truncation:** Tests with `RelaxedTrunc` in their names are focused on testing the relaxed truncation of floating-point numbers to integers within SIMD vectors.
    * **Relaxed Swizzle:** `I8x16RelaxedSwizzle` tests the rearrangement of bytes within a SIMD vector based on an index vector.
    * **Relaxed Q15 Multiply with Rounding and Saturation:** `I16x8RelaxedQ15MulRS` tests a specific relaxed multiply operation for 16-bit integers.
    * **Dot Product:**  Tests like `I16x8DotI8x16I7x16S` and `I32x4DotI8x16I7x16AddS` verify relaxed dot product operations.
    * **Revectorization (SIMD256):** The `#ifdef V8_ENABLE_WASM_SIMD256_REVEC` section contains tests for 256-bit SIMD variants of some of these relaxed operations, often indicated by names like `F32x8Qfma_turbofan`.

4. **Connect to JavaScript:**  The key connection is that these C++ tests are verifying the *implementation* of WebAssembly features within the V8 JavaScript engine. When a JavaScript engine executes WebAssembly code that uses relaxed SIMD instructions, the engine's implementation (which includes the code being tested here) is responsible for the correct behavior.

5. **Construct the JavaScript Example:** To illustrate the connection, focus on a concrete example. The QFMA/QFMS operations are good choices because they demonstrate the "relaxed" nature well (fused vs. unfused).

    * **Find the Corresponding WebAssembly Instruction:**  The C++ test names (`F32x4Qfma`, `F64x2Qfms`) directly correspond to WebAssembly instructions.
    * **Show the WebAssembly Code:**  Provide a simple example in the WebAssembly text format.
    * **Relate to JavaScript:** Explain how this WebAssembly code would be invoked from JavaScript using the `WebAssembly` API.
    * **Illustrate the "Relaxed" Aspect:**  Explain the difference between the fused and unfused results and why this "relaxed" behavior is significant. Highlight that the C++ tests are ensuring both behaviors are handled correctly depending on the engine's capabilities and optimization levels.

6. **Refine the Summary:** Organize the findings into a clear and concise summary:
    * Start with the main purpose: testing relaxed SIMD.
    * List the specific categories of instructions being tested.
    * Explain the connection to JavaScript.
    * Mention the significance of "relaxed" semantics.
    * Briefly touch upon the role of different execution tiers (Turbofan, Liftoff).
    * Include the 256-bit SIMD testing if the code contains it.

7. **Review and Verify:** Read through the summary and example to ensure they are accurate, clear, and address all parts of the request. For example, double-check the WebAssembly instruction names and the JavaScript API calls. Make sure the explanation of "fused" vs. "unfused" is understandable.

This systematic approach, starting with the big picture and drilling down into specifics, helps to effectively analyze and summarize complex code like this and connect it to related technologies like JavaScript and WebAssembly.
这个C++源代码文件 `v8/test/cctest/wasm/test-run-wasm-relaxed-simd.cc` 的主要功能是**测试 V8 JavaScript 引擎中 WebAssembly 的“relaxed SIMD” 指令的实现是否正确**。

**详细功能归纳:**

1. **测试 Relaxed SIMD 指令:** 该文件包含了大量针对各种 relaxed SIMD 指令的测试用例。这些指令是 WebAssembly SIMD 扩展的一部分，旨在在某些情况下提供更高的性能，但允许结果在不同硬件或配置上略有不同（"relaxed" 的含义）。

2. **测试不同的数据类型和操作:**  测试覆盖了不同的 SIMD 数据类型（如 `f32x4`, `f64x2`, `i8x16`, `i16x8`, `i32x4`, `i64x2`）以及针对这些类型的各种 relaxed SIMD 操作，例如：
    * **融合乘加/减 (QFMA/QFMS):** `F32x4Qfma`, `F32x4Qfms`, `F64x2Qfma`, `F64x2Qfms` 等测试用例验证了融合乘加和乘减操作的正确性，并区分了融合和非融合的计算结果。
    * **车道选择 (Lane Select):** `I8x16RelaxedLaneSelect`, `I16x8RelaxedLaneSelect`, `I32x4RelaxedLaneSelect`, `I64x2RelaxedLaneSelect` 等测试用例测试了从 SIMD 向量中选择特定元素的功能。
    * **宽松的最小值/最大值 (Relaxed Min/Max):** `F32x4RelaxedMin`, `F32x4RelaxedMax`, `F64x2RelaxedMin`, `F64x2RelaxedMax` 测试用例验证了在 SIMD 向量中查找最小值和最大值的操作。
    * **宽松的截断 (Relaxed Truncation):** `I32x4RelaxedTruncF64x2SZero`, `I32x4RelaxedTruncF64x2UZero`, `I32x4RelaxedTruncF32x4S`, `I32x4RelaxedTruncF32x4U` 测试用例测试了将浮点数截断为整数的操作。
    * **宽松的 Swizzle:** `I8x16RelaxedSwizzle` 测试了根据索引向量重新排列 SIMD 向量元素的功能。
    * **宽松的 Q15 乘法 (Relaxed Q15 Multiply):** `I16x8RelaxedQ15MulRS` 测试了带舍入和饱和的 16 位整数乘法。
    * **点积 (Dot Product):** `I16x8DotI8x16I7x16S`, `I32x4DotI8x16I7x16AddS` 测试用例验证了 SIMD 向量的点积运算。

3. **测试不同的执行层:**  测试用例使用了 `WasmRunner` 类，它允许指定不同的 WebAssembly 执行层（例如，TurboFan 优化编译器，Liftoff 解释器）。这确保了 relaxed SIMD 指令在 V8 的不同执行路径上都能正确工作。

4. **检查融合行为:** 对于像 QFMA 和 QFMS 这样的指令，测试明确地检查了是否按照预期进行了融合计算，这取决于目标架构和启用的 CPU 功能（如 FMA3）。

5. **使用助手函数和宏:**  代码使用了许多助手函数和宏来简化测试的编写，例如：
    * `FMOperation` 结构体用于存储融合乘加/减操作的参数和预期结果。
    * `qfma_array`, `qfms_array` 等数组定义了测试用例的具体数值。
    * `WASM_EXEC_TEST` 宏定义了一个 WebAssembly 执行测试。
    * `WASM_SIMD_*` 宏用于生成 WebAssembly 指令。
    * `LANE` 宏用于访问 SIMD 向量中的特定元素。
    * `CheckFloatResult`, `CheckDoubleResult` 等函数用于比较浮点数结果。

6. **针对 SIMD256 扩展的测试 (条件编译):** 代码中包含了 `#ifdef V8_ENABLE_WASM_SIMD256_REVEC` 块，表明还存在针对 256 位 SIMD 扩展的测试用例，例如 `RunWasm_F32x8Qfma_turbofan`, `RunWasm_I64x4RelaxedLaneSelect` 等。这些测试在支持 AVX2 等指令集的架构上运行。

**与 JavaScript 的关系及 JavaScript 示例:**

这个 C++ 文件是 V8 引擎内部的测试代码，它直接测试了 V8 如何执行 WebAssembly 代码中的 relaxed SIMD 指令。 当你在 JavaScript 中运行 WebAssembly 代码，并且该 WebAssembly 代码使用了 relaxed SIMD 指令时，V8 引擎会调用其内部的实现来执行这些指令。 这个 C++ 文件中的测试正是为了确保这些内部实现是正确的。

**JavaScript 示例:**

假设我们有一个使用 `f32x4.qfma` (relaxed fused multiply-add for 4 floats) 指令的 WebAssembly 模块。

```javascript
const wasmCode = `
  (module
    (func (export "qfma_test") (param $a f32x4) (param $b f32x4) (param $c f32x4) (result f32x4)
      local.get $a
      local.get $b
      local.get $c
      f32x4.qfma
    )
  )
`;

const wasmModule = new WebAssembly.Module(new TextEncoder().encode(wasmCode));
const wasmInstance = new WebAssembly.Instance(wasmModule);

const a = new Float32Array([1.0, 2.0, 3.0, 4.0]);
const b = new Float32Array([5.0, 6.0, 7.0, 8.0]);
const c = new Float32Array([9.0, 10.0, 11.0, 12.0]);

const a_vec = new Float32x4(...a);
const b_vec = new Float32x4(...b);
const c_vec = new Float32x4(...c);

const result_vec = wasmInstance.exports.qfma_test(a_vec, b_vec, c_vec);

console.log(result_vec); // 输出类似 Float32x4 { 14, 22, 32, 44 }
// 预期结果: a[i] * b[i] + c[i]
// 1.0 * 5.0 + 9.0 = 14.0
// 2.0 * 6.0 + 10.0 = 22.0
// 3.0 * 7.0 + 11.0 = 32.0
// 4.0 * 8.0 + 12.0 = 44.0
```

在这个 JavaScript 例子中：

1. 我们定义了一个简单的 WebAssembly 模块，其中包含一个名为 `qfma_test` 的函数，该函数接收三个 `f32x4` 类型的参数，并使用 `f32x4.qfma` 指令进行融合乘加运算。
2. 我们在 JavaScript 中加载并实例化了这个 WebAssembly 模块。
3. 我们创建了 `Float32Array` 并将其转换为 `Float32x4` SIMD 向量。
4. 我们调用了 WebAssembly 导出的函数 `qfma_test`，并将 SIMD 向量作为参数传递。
5. V8 引擎在执行 `f32x4.qfma` 指令时，会调用其内部的实现，而 `v8/test/cctest/wasm/test-run-wasm-relaxed-simd.cc` 文件中的 `WASM_EXEC_TEST(F32x4Qfma)` 测试用例正是用于验证这个内部实现的正确性。

**总结:**

`v8/test/cctest/wasm/test-run-wasm-relaxed-simd.cc` 是一个至关重要的测试文件，它确保了 V8 JavaScript 引擎能够正确地执行 WebAssembly 的 relaxed SIMD 指令。这直接关系到使用这些指令的 WebAssembly 应用在 V8 环境中的性能和正确性。当 JavaScript 代码调用使用 relaxed SIMD 指令的 WebAssembly 模块时，这个测试文件所覆盖的 C++ 代码就是幕后英雄，确保一切按预期工作。

Prompt: 
```
这是目录为v8/test/cctest/wasm/test-run-wasm-relaxed-simd.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <type_traits>

#include "src/base/overflowing-math.h"
#include "src/base/safe_conversions.h"
#include "src/codegen/cpu-features.h"
#include "src/common/globals.h"
#include "src/wasm/compilation-environment.h"
#include "test/cctest/cctest.h"
#include "test/cctest/wasm/wasm-run-utils.h"
#include "test/cctest/wasm/wasm-simd-utils.h"
#include "test/common/wasm/flag-utils.h"
#include "test/common/wasm/wasm-macro-gen.h"

namespace v8::internal::wasm {

// Only used for qfma and qfms tests below.

// FMOperation holds the params (a, b, c) for a Multiply-Add or
// Multiply-Subtract operation, and the expected result if the operation was
// fused, rounded only once for the entire operation, or unfused, rounded after
// multiply and again after add/subtract.
template <typename T>
struct FMOperation {
  const T a;
  const T b;
  const T c;
  const T fused_result;
  const T unfused_result;
};

// large_n is large number that overflows T when multiplied by itself, this is a
// useful constant to test fused/unfused behavior.
template <typename T>
constexpr T large_n = T(0);

template <>
constexpr double large_n<double> = 1e200;

template <>
constexpr float large_n<float> = 1e20;

// Fused Multiply-Add performs a * b + c.
template <typename T>
static constexpr FMOperation<T> qfma_array[] = {
    {2.0f, 3.0f, 1.0f, 7.0f, 7.0f},
    // fused: a * b + c = (positive overflow) + -inf = -inf
    // unfused: a * b + c = inf + -inf = NaN
    {large_n<T>, large_n<T>, -std::numeric_limits<T>::infinity(),
     -std::numeric_limits<T>::infinity(), std::numeric_limits<T>::quiet_NaN()},
    // fused: a * b + c = (negative overflow) + inf = inf
    // unfused: a * b + c = -inf + inf = NaN
    {-large_n<T>, large_n<T>, std::numeric_limits<T>::infinity(),
     std::numeric_limits<T>::infinity(), std::numeric_limits<T>::quiet_NaN()},
    // NaN
    {2.0f, 3.0f, std::numeric_limits<T>::quiet_NaN(),
     std::numeric_limits<T>::quiet_NaN(), std::numeric_limits<T>::quiet_NaN()},
    // -NaN
    {2.0f, 3.0f, -std::numeric_limits<T>::quiet_NaN(),
     std::numeric_limits<T>::quiet_NaN(), std::numeric_limits<T>::quiet_NaN()}};

template <typename T>
static constexpr base::Vector<const FMOperation<T>> qfma_vector() {
  return base::ArrayVector(qfma_array<T>);
}

// Fused Multiply-Subtract performs -(a * b) + c.
template <typename T>
static constexpr FMOperation<T> qfms_array[]{
    {2.0f, 3.0f, 1.0f, -5.0f, -5.0f},
    // fused: -(a * b) + c = - (positive overflow) + inf = inf
    // unfused: -(a * b) + c = - inf + inf = NaN
    {large_n<T>, large_n<T>, std::numeric_limits<T>::infinity(),
     std::numeric_limits<T>::infinity(), std::numeric_limits<T>::quiet_NaN()},
    // fused: -(a * b) + c = (negative overflow) + -inf = -inf
    // unfused: -(a * b) + c = -inf - -inf = NaN
    {-large_n<T>, large_n<T>, -std::numeric_limits<T>::infinity(),
     -std::numeric_limits<T>::infinity(), std::numeric_limits<T>::quiet_NaN()},
    // NaN
    {2.0f, 3.0f, std::numeric_limits<T>::quiet_NaN(),
     std::numeric_limits<T>::quiet_NaN(), std::numeric_limits<T>::quiet_NaN()},
    // -NaN
    {2.0f, 3.0f, -std::numeric_limits<T>::quiet_NaN(),
     std::numeric_limits<T>::quiet_NaN(), std::numeric_limits<T>::quiet_NaN()}};

template <typename T>
static constexpr base::Vector<const FMOperation<T>> qfms_vector() {
  return base::ArrayVector(qfms_array<T>);
}

bool ExpectFused(TestExecutionTier tier) {
#if V8_TARGET_ARCH_X64 || V8_TARGET_ARCH_IA32
  // Fused results only when fma3 feature is enabled, and running on TurboFan or
  // Liftoff (which can fall back to TurboFan if FMA is not implemented).
  return CpuFeatures::IsSupported(FMA3) &&
         (tier == TestExecutionTier::kTurbofan ||
          tier == TestExecutionTier::kLiftoff);
#elif V8_TARGET_ARCH_ARM
  // Consistent feature detection for Neonv2 is required before emitting
  // fused instructions on Arm32. Not all Neon enabled Arm32 devices have
  // FMA instructions.
  return false;
#else
  // All ARM64 Neon enabled devices have support for FMA instructions, only the
  // Liftoff/Turbofan tiers emit codegen for fused results.
  return (tier == TestExecutionTier::kTurbofan ||
          tier == TestExecutionTier::kLiftoff);
#endif  // V8_TARGET_ARCH_X64 || V8_TARGET_ARCH_IA32
}

WASM_EXEC_TEST(F32x4Qfma) {
  WasmRunner<int32_t, float, float, float> r(execution_tier);
  // Set up global to hold mask output.
  float* g = r.builder().AddGlobal<float>(kWasmS128);
  // Build fn to splat test values, perform compare op, and write the result.
  uint8_t value1 = 0, value2 = 1, value3 = 2;
  r.Build(
      {WASM_GLOBAL_SET(0, WASM_SIMD_F32x4_QFMA(
                              WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(value1)),
                              WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(value2)),
                              WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(value3)))),
       WASM_ONE});

  for (FMOperation<float> x : qfma_vector<float>()) {
    r.Call(x.a, x.b, x.c);
    float expected =
        ExpectFused(execution_tier) ? x.fused_result : x.unfused_result;
    for (int i = 0; i < 4; i++) {
      float actual = LANE(g, i);
      CheckFloatResult(x.a, x.b, expected, actual, true /* exact */);
    }
  }
}

WASM_EXEC_TEST(F32x4Qfms) {
  WasmRunner<int32_t, float, float, float> r(execution_tier);
  // Set up global to hold mask output.
  float* g = r.builder().AddGlobal<float>(kWasmS128);
  // Build fn to splat test values, perform compare op, and write the result.
  uint8_t value1 = 0, value2 = 1, value3 = 2;
  r.Build(
      {WASM_GLOBAL_SET(0, WASM_SIMD_F32x4_QFMS(
                              WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(value1)),
                              WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(value2)),
                              WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(value3)))),
       WASM_ONE});

  for (FMOperation<float> x : qfms_vector<float>()) {
    r.Call(x.a, x.b, x.c);
    float expected =
        ExpectFused(execution_tier) ? x.fused_result : x.unfused_result;
    for (int i = 0; i < 4; i++) {
      float actual = LANE(g, i);
      CheckFloatResult(x.a, x.b, expected, actual, true /* exact */);
    }
  }
}

WASM_EXEC_TEST(F64x2Qfma) {
  WasmRunner<int32_t, double, double, double> r(execution_tier);
  // Set up global to hold mask output.
  double* g = r.builder().AddGlobal<double>(kWasmS128);
  // Build fn to splat test values, perform compare op, and write the result.
  uint8_t value1 = 0, value2 = 1, value3 = 2;
  r.Build(
      {WASM_GLOBAL_SET(0, WASM_SIMD_F64x2_QFMA(
                              WASM_SIMD_F64x2_SPLAT(WASM_LOCAL_GET(value1)),
                              WASM_SIMD_F64x2_SPLAT(WASM_LOCAL_GET(value2)),
                              WASM_SIMD_F64x2_SPLAT(WASM_LOCAL_GET(value3)))),
       WASM_ONE});

  for (FMOperation<double> x : qfma_vector<double>()) {
    r.Call(x.a, x.b, x.c);
    double expected =
        ExpectFused(execution_tier) ? x.fused_result : x.unfused_result;
    for (int i = 0; i < 2; i++) {
      double actual = LANE(g, i);
      CheckDoubleResult(x.a, x.b, expected, actual, true /* exact */);
    }
  }
}

WASM_EXEC_TEST(F64x2Qfms) {
  WasmRunner<int32_t, double, double, double> r(execution_tier);
  // Set up global to hold mask output.
  double* g = r.builder().AddGlobal<double>(kWasmS128);
  // Build fn to splat test values, perform compare op, and write the result.
  uint8_t value1 = 0, value2 = 1, value3 = 2;
  r.Build(
      {WASM_GLOBAL_SET(0, WASM_SIMD_F64x2_QFMS(
                              WASM_SIMD_F64x2_SPLAT(WASM_LOCAL_GET(value1)),
                              WASM_SIMD_F64x2_SPLAT(WASM_LOCAL_GET(value2)),
                              WASM_SIMD_F64x2_SPLAT(WASM_LOCAL_GET(value3)))),
       WASM_ONE});

  for (FMOperation<double> x : qfms_vector<double>()) {
    r.Call(x.a, x.b, x.c);
    double expected =
        ExpectFused(execution_tier) ? x.fused_result : x.unfused_result;
    for (int i = 0; i < 2; i++) {
      double actual = LANE(g, i);
      CheckDoubleResult(x.a, x.b, expected, actual, true /* exact */);
    }
  }
}

TEST(RunWasm_RegressFmaReg_liftoff) {
  FLAG_SCOPE(liftoff_only);
  TestExecutionTier execution_tier = TestExecutionTier::kLiftoff;
  WasmRunner<int32_t, float, float, float> r(execution_tier);
  uint8_t local = r.AllocateLocal(kWasmS128);
  float* g = r.builder().AddGlobal<float>(kWasmS128);
  uint8_t value1 = 0, value2 = 1, value3 = 2;
  r.Build(
      {// Get the first arg from a local so that the register is blocked even
       // after the arguments have been popped off the stack. This ensures that
       // the first source register is not also the destination.
       WASM_LOCAL_SET(local, WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(value1))),
       WASM_GLOBAL_SET(0, WASM_SIMD_F32x4_QFMA(
                              WASM_LOCAL_GET(local),
                              WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(value2)),
                              WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(value3)))),
       WASM_ONE});

  for (FMOperation<float> x : qfma_vector<float>()) {
    r.Call(x.a, x.b, x.c);
    float expected =
        ExpectFused(execution_tier) ? x.fused_result : x.unfused_result;
    for (int i = 0; i < 4; i++) {
      float actual = LANE(g, i);
      CheckFloatResult(x.a, x.b, expected, actual, true /* exact */);
    }
  }
}

namespace {
// Helper to convert an array of T into an array of uint8_t to be used a v128
// constants.
template <typename T, size_t N = kSimd128Size / sizeof(T)>
std::array<uint8_t, kSimd128Size> as_uint8(const T* src) {
  std::array<uint8_t, kSimd128Size> arr;
  for (size_t i = 0; i < N; i++) {
    WriteLittleEndianValue<T>(reinterpret_cast<T*>(&arr[0]) + i, src[i]);
  }
  return arr;
}

template <typename T, int kElems>
void RelaxedLaneSelectTest(TestExecutionTier execution_tier, const T v1[kElems],
                           const T v2[kElems], const T s[kElems],
                           const T expected[kElems], WasmOpcode laneselect) {
  auto lhs = as_uint8<T>(v1);
  auto rhs = as_uint8<T>(v2);
  auto mask = as_uint8<T>(s);
  WasmRunner<int32_t> r(execution_tier);
  T* dst = r.builder().AddGlobal<T>(kWasmS128);
  r.Build({WASM_GLOBAL_SET(0, WASM_SIMD_OPN(laneselect, WASM_SIMD_CONSTANT(lhs),
                                            WASM_SIMD_CONSTANT(rhs),
                                            WASM_SIMD_CONSTANT(mask))),
           WASM_ONE});

  CHECK_EQ(1, r.Call());
  for (int i = 0; i < kElems; i++) {
    CHECK_EQ(expected[i], LANE(dst, i));
  }
}

}  // namespace

WASM_EXEC_TEST(I8x16RelaxedLaneSelect) {
  constexpr int kElems = 16;
  constexpr uint8_t v1[kElems] = {0, 1, 2,  3,  4,  5,  6,  7,
                                  8, 9, 10, 11, 12, 13, 14, 15};
  constexpr uint8_t v2[kElems] = {16, 17, 18, 19, 20, 21, 22, 23,
                                  24, 25, 26, 27, 28, 29, 30, 31};
  constexpr uint8_t s[kElems] = {0, 0xFF, 0, 0xFF, 0, 0xFF, 0, 0xFF,
                                 0, 0xFF, 0, 0xFF, 0, 0xFF, 0, 0xFF};
  constexpr uint8_t expected[kElems] = {16, 1, 18, 3,  20, 5,  22, 7,
                                        24, 9, 26, 11, 28, 13, 30, 15};
  RelaxedLaneSelectTest<uint8_t, kElems>(execution_tier, v1, v2, s, expected,
                                         kExprI8x16RelaxedLaneSelect);
}

WASM_EXEC_TEST(I16x8RelaxedLaneSelect) {
  constexpr int kElems = 8;
  uint16_t v1[kElems] = {0, 1, 2, 3, 4, 5, 6, 7};
  uint16_t v2[kElems] = {8, 9, 10, 11, 12, 13, 14, 15};
  uint16_t s[kElems] = {0, 0xFFFF, 0, 0xFFFF, 0, 0xFFFF, 0, 0xFFFF};
  constexpr uint16_t expected[kElems] = {8, 1, 10, 3, 12, 5, 14, 7};
  RelaxedLaneSelectTest<uint16_t, kElems>(execution_tier, v1, v2, s, expected,
                                          kExprI16x8RelaxedLaneSelect);
}

WASM_EXEC_TEST(I32x4RelaxedLaneSelect) {
  constexpr int kElems = 4;
  uint32_t v1[kElems] = {0, 1, 2, 3};
  uint32_t v2[kElems] = {4, 5, 6, 7};
  uint32_t s[kElems] = {0, 0xFFFF'FFFF, 0, 0xFFFF'FFFF};
  constexpr uint32_t expected[kElems] = {4, 1, 6, 3};
  RelaxedLaneSelectTest<uint32_t, kElems>(execution_tier, v1, v2, s, expected,
                                          kExprI32x4RelaxedLaneSelect);
}

WASM_EXEC_TEST(I64x2RelaxedLaneSelect) {
  constexpr int kElems = 2;
  uint64_t v1[kElems] = {0, 1};
  uint64_t v2[kElems] = {2, 3};
  uint64_t s[kElems] = {0, 0xFFFF'FFFF'FFFF'FFFF};
  constexpr uint64_t expected[kElems] = {2, 1};
  RelaxedLaneSelectTest<uint64_t, kElems>(execution_tier, v1, v2, s, expected,
                                          kExprI64x2RelaxedLaneSelect);
}

WASM_EXEC_TEST(F32x4RelaxedMin) {
  RunF32x4BinOpTest(execution_tier, kExprF32x4RelaxedMin, Minimum);
}

WASM_EXEC_TEST(F32x4RelaxedMax) {
  RunF32x4BinOpTest(execution_tier, kExprF32x4RelaxedMax, Maximum);
}

WASM_EXEC_TEST(F64x2RelaxedMin) {
  RunF64x2BinOpTest(execution_tier, kExprF64x2RelaxedMin, Minimum);
}

WASM_EXEC_TEST(F64x2RelaxedMax) {
  RunF64x2BinOpTest(execution_tier, kExprF64x2RelaxedMax, Maximum);
}

namespace {
// For relaxed trunc instructions, don't test out of range values.
// FloatType comes later so caller can rely on template argument deduction and
// just pass IntType.
template <typename IntType, typename FloatType>
typename std::enable_if<std::is_floating_point<FloatType>::value, bool>::type
ShouldSkipTestingConstant(FloatType x) {
  return std::isnan(x) || !base::IsValueInRangeForNumericType<IntType>(x) ||
         !PlatformCanRepresent(x);
}

template <typename IntType, typename FloatType>
void IntRelaxedTruncFloatTest(TestExecutionTier execution_tier,
                              WasmOpcode trunc_op, WasmOpcode splat_op) {
  WasmRunner<int, FloatType> r(execution_tier);
  IntType* g0 = r.builder().template AddGlobal<IntType>(kWasmS128);
  constexpr int lanes = kSimd128Size / sizeof(FloatType);

  // global[0] = trunc(splat(local[0])).
  r.Build({WASM_GLOBAL_SET(
               0, WASM_SIMD_UNOP(trunc_op,
                                 WASM_SIMD_UNOP(splat_op, WASM_LOCAL_GET(0)))),
           WASM_ONE});

  for (FloatType x : compiler::ValueHelper::GetVector<FloatType>()) {
    if (ShouldSkipTestingConstant<IntType>(x)) continue;
    CHECK_EQ(1, r.Call(x));
    IntType expected = base::checked_cast<IntType>(x);
    for (int i = 0; i < lanes; i++) {
      CHECK_EQ(expected, LANE(g0, i));
    }
  }
}
}  // namespace

WASM_EXEC_TEST(I32x4RelaxedTruncF64x2SZero) {
  IntRelaxedTruncFloatTest<int32_t, double>(
      execution_tier, kExprI32x4RelaxedTruncF64x2SZero, kExprF64x2Splat);
}

WASM_EXEC_TEST(I32x4RelaxedTruncF64x2UZero) {
  IntRelaxedTruncFloatTest<uint32_t, double>(
      execution_tier, kExprI32x4RelaxedTruncF64x2UZero, kExprF64x2Splat);
}

WASM_EXEC_TEST(I32x4RelaxedTruncF32x4S) {
  IntRelaxedTruncFloatTest<int32_t, float>(
      execution_tier, kExprI32x4RelaxedTruncF32x4S, kExprF32x4Splat);
}

WASM_EXEC_TEST(I32x4RelaxedTruncF32x4U) {
  IntRelaxedTruncFloatTest<uint32_t, float>(
      execution_tier, kExprI32x4RelaxedTruncF32x4U, kExprF32x4Splat);
}

WASM_EXEC_TEST(I8x16RelaxedSwizzle) {
  // Output is only defined for indices in the range [0,15].
  WasmRunner<int32_t> r(execution_tier);
  static const int kElems = kSimd128Size / sizeof(uint8_t);
  uint8_t* dst = r.builder().AddGlobal<uint8_t>(kWasmS128);
  uint8_t* src = r.builder().AddGlobal<uint8_t>(kWasmS128);
  uint8_t* indices = r.builder().AddGlobal<uint8_t>(kWasmS128);
  r.Build({WASM_GLOBAL_SET(
               0, WASM_SIMD_BINOP(kExprI8x16RelaxedSwizzle, WASM_GLOBAL_GET(1),
                                  WASM_GLOBAL_GET(2))),
           WASM_ONE});
  for (int i = 0; i < kElems; i++) {
    LANE(src, i) = kElems - i - 1;
    LANE(indices, i) = kElems - i - 1;
  }
  CHECK_EQ(1, r.Call());
  for (int i = 0; i < kElems; i++) {
    CHECK_EQ(LANE(dst, i), i);
  }
}

WASM_EXEC_TEST(I16x8RelaxedQ15MulRS) {
  WasmRunner<int32_t, int16_t, int16_t> r(execution_tier);
  // Global to hold output.
  int16_t* g = r.builder().template AddGlobal<int16_t>(kWasmS128);
  // Build fn to splat test values, perform binop, and write the result.
  uint8_t value1 = 0, value2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I16x8_SPLAT(WASM_LOCAL_GET(value1))),
           WASM_LOCAL_SET(temp2, WASM_SIMD_I16x8_SPLAT(WASM_LOCAL_GET(value2))),
           WASM_GLOBAL_SET(0, WASM_SIMD_BINOP(kExprI16x8RelaxedQ15MulRS,
                                              WASM_LOCAL_GET(temp1),
                                              WASM_LOCAL_GET(temp2))),
           WASM_ONE});

  for (int16_t x : compiler::ValueHelper::GetVector<int16_t>()) {
    for (int16_t y : compiler::ValueHelper::GetVector<int16_t>()) {
      // Results are dependent on the underlying hardware when both inputs are
      // INT16_MIN, we could do something specific to test for x64/ARM behavior
      // but predictably other supported V8 platforms will have to test specific
      // behavior in that case, given that the lowering is fairly
      // straighforward, and occurence of this in higher level programs is rare,
      // this is okay to skip.
      if (x == INT16_MIN && y == INT16_MIN) break;
      r.Call(x, y);
      int16_t expected = SaturateRoundingQMul(x, y);
      for (int i = 0; i < 8; i++) {
        CHECK_EQ(expected, LANE(g, i));
      }
    }
  }
}

WASM_EXEC_TEST(I16x8DotI8x16I7x16S) {
  WasmRunner<int32_t, int8_t, int8_t> r(execution_tier);
  int16_t* g = r.builder().template AddGlobal<int16_t>(kWasmS128);
  uint8_t value1 = 0, value2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(value1))),
           WASM_LOCAL_SET(temp2, WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(value2))),
           WASM_GLOBAL_SET(0, WASM_SIMD_BINOP(kExprI16x8DotI8x16I7x16S,
                                              WASM_LOCAL_GET(temp1),
                                              WASM_LOCAL_GET(temp2))),
           WASM_ONE});

  for (int8_t x : compiler::ValueHelper::GetVector<int8_t>()) {
    for (int8_t y : compiler::ValueHelper::GetVector<int8_t>()) {
      r.Call(x, y & 0x7F);
      // * 2 because we of (x*y) + (x*y) = 2*x*y
      int16_t expected = base::MulWithWraparound(x * (y & 0x7F), 2);
      for (int i = 0; i < 8; i++) {
        CHECK_EQ(expected, LANE(g, i));
      }
    }
  }
}

WASM_EXEC_TEST(I32x4DotI8x16I7x16AddS) {
  WasmRunner<int32_t, int8_t, int8_t, int32_t> r(execution_tier);
  int32_t* g = r.builder().template AddGlobal<int32_t>(kWasmS128);
  uint8_t value1 = 0, value2 = 1, value3 = 2;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  uint8_t temp3 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(value1))),
           WASM_LOCAL_SET(temp2, WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(value2))),
           WASM_LOCAL_SET(temp3, WASM_SIMD_I32x4_SPLAT(WASM_LOCAL_GET(value3))),
           WASM_GLOBAL_SET(
               0, WASM_SIMD_TERNOP(kExprI32x4DotI8x16I7x16AddS,
                                   WASM_LOCAL_GET(temp1), WASM_LOCAL_GET(temp2),
                                   WASM_LOCAL_GET(temp3))),
           WASM_ONE});

  for (int8_t x : compiler::ValueHelper::GetVector<int8_t>()) {
    for (int8_t y : compiler::ValueHelper::GetVector<int8_t>()) {
      for (int32_t z : compiler::ValueHelper::GetVector<int32_t>()) {
        int32_t expected = base::AddWithWraparound(
            base::MulWithWraparound(x * (y & 0x7F), 4), z);
        r.Call(x, y & 0x7F, z);
        for (int i = 0; i < 4; i++) {
          CHECK_EQ(expected, LANE(g, i));
        }
      }
    }
  }
}

#ifdef V8_ENABLE_WASM_SIMD256_REVEC
TEST(RunWasm_F32x8Qfma_turbofan) {
  if (!CpuFeatures::IsSupported(AVX2)) return;
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  WasmRunner<int32_t, float, float, float> r(TestExecutionTier::kTurbofan);
  float* memory = r.builder().AddMemoryElems<float>(8);

  uint8_t param1 = 0;
  uint8_t param2 = 1;
  uint8_t param3 = 2;

  r.Build(
      {WASM_SIMD_STORE_MEM(
           WASM_ZERO,
           WASM_SIMD_F32x4_QFMA(WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(param1)),
                                WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(param2)),
                                WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(param3)))),
       WASM_SIMD_STORE_MEM_OFFSET(
           16, WASM_ZERO,
           WASM_SIMD_F32x4_QFMA(WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(param1)),
                                WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(param2)),
                                WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(param3)))),
       WASM_ONE});

  for (FMOperation<float> x : qfma_vector<float>()) {
    r.Call(x.a, x.b, x.c);
    float expected = ExpectFused(TestExecutionTier::kTurbofan)
                         ? x.fused_result
                         : x.unfused_result;
    for (int i = 0; i < 4; i++) {
      float actual0 = r.builder().ReadMemory(memory + i);
      float actual1 = r.builder().ReadMemory(memory + 4 + i);
      CheckFloatResult(x.a, x.b, expected, actual0, true /* exact */);
      CheckFloatResult(x.a, x.b, expected, actual1, true /* exact */);
    }
  }
}

TEST(RunWasm_F32x8Qfms_turbofan) {
  if (!CpuFeatures::IsSupported(AVX2)) return;
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  WasmRunner<int32_t, float, float, float> r(TestExecutionTier::kTurbofan);
  float* memory = r.builder().AddMemoryElems<float>(8);

  uint8_t param1 = 0;
  uint8_t param2 = 1;
  uint8_t param3 = 2;

  r.Build(
      {WASM_SIMD_STORE_MEM(
           WASM_ZERO,
           WASM_SIMD_F32x4_QFMS(WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(param1)),
                                WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(param2)),
                                WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(param3)))),
       WASM_SIMD_STORE_MEM_OFFSET(
           16, WASM_ZERO,
           WASM_SIMD_F32x4_QFMS(WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(param1)),
                                WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(param2)),
                                WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(param3)))),
       WASM_ONE});

  for (FMOperation<float> x : qfms_vector<float>()) {
    r.Call(x.a, x.b, x.c);
    float expected = ExpectFused(TestExecutionTier::kTurbofan)
                         ? x.fused_result
                         : x.unfused_result;
    for (int i = 0; i < 4; i++) {
      float actual0 = r.builder().ReadMemory(memory + i);
      float actual1 = r.builder().ReadMemory(memory + 4 + i);
      CheckFloatResult(x.a, x.b, expected, actual0, true /* exact */);
      CheckFloatResult(x.a, x.b, expected, actual1, true /* exact */);
    }
  }
}

TEST(RunWasm_F64x4Qfma_turbofan) {
  if (!CpuFeatures::IsSupported(AVX2)) return;
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  WasmRunner<int32_t, double, double, double> r(TestExecutionTier::kTurbofan);
  double* memory = r.builder().AddMemoryElems<double>(4);

  uint8_t param1 = 0;
  uint8_t param2 = 1;
  uint8_t param3 = 2;

  r.Build(
      {WASM_SIMD_STORE_MEM(
           WASM_ZERO,
           WASM_SIMD_F64x2_QFMA(WASM_SIMD_F64x2_SPLAT(WASM_LOCAL_GET(param1)),
                                WASM_SIMD_F64x2_SPLAT(WASM_LOCAL_GET(param2)),
                                WASM_SIMD_F64x2_SPLAT(WASM_LOCAL_GET(param3)))),
       WASM_SIMD_STORE_MEM_OFFSET(
           16, WASM_ZERO,
           WASM_SIMD_F64x2_QFMA(WASM_SIMD_F64x2_SPLAT(WASM_LOCAL_GET(param1)),
                                WASM_SIMD_F64x2_SPLAT(WASM_LOCAL_GET(param2)),
                                WASM_SIMD_F64x2_SPLAT(WASM_LOCAL_GET(param3)))),
       WASM_ONE});

  for (FMOperation<double> x : qfma_vector<double>()) {
    r.Call(x.a, x.b, x.c);
    double expected = ExpectFused(TestExecutionTier::kTurbofan)
                          ? x.fused_result
                          : x.unfused_result;
    for (int i = 0; i < 2; i++) {
      double actual0 = r.builder().ReadMemory(memory + i);
      double actual1 = r.builder().ReadMemory(memory + 2 + i);
      CheckFloatResult(x.a, x.b, expected, actual0, true /* exact */);
      CheckFloatResult(x.a, x.b, expected, actual1, true /* exact */);
    }
  }
}

TEST(RunWasm_F64x4Qfms_turbofan) {
  if (!CpuFeatures::IsSupported(AVX2)) return;
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  WasmRunner<int32_t, double, double, double> r(TestExecutionTier::kTurbofan);
  double* memory = r.builder().AddMemoryElems<double>(4);

  uint8_t param1 = 0;
  uint8_t param2 = 1;
  uint8_t param3 = 2;

  r.Build(
      {WASM_SIMD_STORE_MEM(
           WASM_ZERO,
           WASM_SIMD_F64x2_QFMS(WASM_SIMD_F64x2_SPLAT(WASM_LOCAL_GET(param1)),
                                WASM_SIMD_F64x2_SPLAT(WASM_LOCAL_GET(param2)),
                                WASM_SIMD_F64x2_SPLAT(WASM_LOCAL_GET(param3)))),
       WASM_SIMD_STORE_MEM_OFFSET(
           16, WASM_ZERO,
           WASM_SIMD_F64x2_QFMS(WASM_SIMD_F64x2_SPLAT(WASM_LOCAL_GET(param1)),
                                WASM_SIMD_F64x2_SPLAT(WASM_LOCAL_GET(param2)),
                                WASM_SIMD_F64x2_SPLAT(WASM_LOCAL_GET(param3)))),
       WASM_ONE});

  for (FMOperation<double> x : qfms_vector<double>()) {
    r.Call(x.a, x.b, x.c);
    double expected = ExpectFused(TestExecutionTier::kTurbofan)
                          ? x.fused_result
                          : x.unfused_result;
    for (int i = 0; i < 2; i++) {
      double actual0 = r.builder().ReadMemory(memory + i);
      double actual1 = r.builder().ReadMemory(memory + 2 + i);
      CheckFloatResult(x.a, x.b, expected, actual0, true /* exact */);
      CheckFloatResult(x.a, x.b, expected, actual1, true /* exact */);
    }
  }
}

template <typename T, int kElems>
void RelaxedLaneSelectRevecTest(const T l1[kElems], const T l2[kElems],
                                const T r1[kElems], const T r2[kElems],
                                const T s1[kElems], const T s2[kElems],
                                const T expected[2 * kElems],
                                WasmOpcode laneselect) {
  if (!CpuFeatures::IsSupported(AVX2)) return;
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  const auto vector_gap = static_cast<int>(16 / sizeof(T));
  WasmRunner<int32_t, int32_t, int32_t, int32_t, int32_t> r(
      TestExecutionTier::kTurbofan);
  T* memory = r.builder().AddMemoryElems<T>(8 * vector_gap);
  uint8_t param1 = 0;
  uint8_t param2 = 1;
  uint8_t param3 = 2;
  uint8_t param4 = 3;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  constexpr uint8_t offset = 16;

  r.Build(
      {WASM_LOCAL_SET(
           temp1,
           WASM_SIMD_OPN(laneselect, WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param1)),
                         WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param2)),
                         WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param3)))),
       WASM_LOCAL_SET(
           temp2,
           WASM_SIMD_OPN(
               laneselect,
               WASM_SIMD_LOAD_MEM_OFFSET(offset, WASM_LOCAL_GET(param1)),
               WASM_SIMD_LOAD_MEM_OFFSET(offset, WASM_LOCAL_GET(param2)),
               WASM_SIMD_LOAD_MEM_OFFSET(offset, WASM_LOCAL_GET(param3)))),
       WASM_SIMD_STORE_MEM(WASM_LOCAL_GET(param4), WASM_LOCAL_GET(temp1)),
       WASM_SIMD_STORE_MEM_OFFSET(offset, WASM_LOCAL_GET(param4),
                                  WASM_LOCAL_GET(temp2)),
       WASM_ONE});
  for (int i = 0; i < static_cast<int>(16 / sizeof(T)); i++) {
    r.builder().WriteMemory(&memory[0 * vector_gap + i], l1[i]);
    r.builder().WriteMemory(&memory[1 * vector_gap + i], l2[i]);
    r.builder().WriteMemory(&memory[2 * vector_gap + i], r1[i]);
    r.builder().WriteMemory(&memory[3 * vector_gap + i], r2[i]);
    r.builder().WriteMemory(&memory[4 * vector_gap + i], s1[i]);
    r.builder().WriteMemory(&memory[5 * vector_gap + i], s2[i]);
  }

  CHECK_EQ(1, r.Call(0, 32, 64, 96));

  for (auto i = 0; i < 2 * kElems; i++) {
    CHECK_EQ(expected[i], memory[6 * vector_gap + i]);
  }
}

TEST(RunWasm_I64x4RelaxedLaneSelect) {
  constexpr int kElems = 2;
  uint64_t l1[kElems] = {0, 1};
  uint64_t l2[kElems] = {2, 3};
  uint64_t r1[kElems] = {4, 5};
  uint64_t r2[kElems] = {6, 7};
  uint64_t s1[kElems] = {0, 0xFFFF'FFFF'FFFF'FFFF};
  uint64_t s2[kElems] = {0xFFFF'FFFF'FFFF'FFFF, 0};
  constexpr uint64_t expected[2 * kElems] = {4, 1, 2, 7};
  RelaxedLaneSelectRevecTest<uint64_t, kElems>(l1, l2, r1, r2, s1, s2, expected,
                                               kExprI64x2RelaxedLaneSelect);
}

TEST(RunWasm_I32x8RelaxedLaneSelect) {
  constexpr int kElems = 4;
  uint32_t l1[kElems] = {0, 1, 2, 3};
  uint32_t l2[kElems] = {8, 9, 10, 11};
  uint32_t r1[kElems] = {4, 5, 6, 7};
  uint32_t r2[kElems] = {12, 13, 14, 15};
  uint32_t s1[kElems] = {0, 0xFFFF'FFFF, 0, 0xFFFF'FFFF};
  uint32_t s2[kElems] = {0, 0xFFFF'FFFF, 0, 0xFFFF'FFFF};
  constexpr uint32_t expected[2 * kElems] = {4, 1, 6, 3, 12, 9, 14, 11};
  RelaxedLaneSelectRevecTest<uint32_t, kElems>(l1, l2, r1, r2, s1, s2, expected,
                                               kExprI32x4RelaxedLaneSelect);
}

TEST(RunWasm_I16x16RelaxedLaneSelect) {
  constexpr int kElems = 8;
  uint16_t l1[kElems] = {0, 1, 2, 3, 4, 5, 6, 7};
  uint16_t r1[kElems] = {8, 9, 10, 11, 12, 13, 14, 15};
  uint16_t l2[kElems] = {16, 17, 18, 19, 20, 21, 22, 23};
  uint16_t r2[kElems] = {24, 25, 26, 27, 28, 29, 30, 31};
  uint16_t s1[kElems] = {0, 0xFFFF, 0, 0xFFFF, 0, 0xFFFF, 0, 0xFFFF};
  uint16_t s2[kElems] = {0xFFFF, 0, 0xFFFF, 0, 0xFFFF, 0, 0xFFFF, 0};
  constexpr uint16_t expected[2 * kElems] = {8,  1,  10, 3,  12, 5,  14, 7,
                                             16, 25, 18, 27, 20, 29, 22, 31};
  RelaxedLaneSelectRevecTest<uint16_t, kElems>(l1, l2, r1, r2, s1, s2, expected,
                                               kExprI16x8RelaxedLaneSelect);
}

TEST(RunWasm_I8x32RelaxedLaneSelect) {
  constexpr int kElems = 16;
  uint8_t l1[kElems] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  uint8_t r1[kElems] = {16, 17, 18, 19, 20, 21, 22, 23,
                        24, 25, 26, 27, 28, 29, 30, 31};
  uint8_t l2[kElems] = {32, 33, 34, 35, 36, 37, 38, 39,
                        40, 41, 42, 43, 44, 45, 46, 47};
  uint8_t r2[kElems] = {48, 49, 50, 51, 52, 53, 54, 55,
                        56, 57, 58, 59, 60, 61, 62, 63};

  uint8_t s1[kElems] = {0, 0xFF, 0, 0xFF, 0, 0xFF, 0, 0xFF,
                        0, 0xFF, 0, 0xFF, 0, 0xFF, 0, 0xFF};
  uint8_t s2[kElems] = {0xFF, 0, 0xFF, 0, 0xFF, 0, 0xFF, 0,
                        0xFF, 0, 0xFF, 0, 0xFF, 0, 0xFF, 0};
  constexpr uint8_t expected[2 * kElems] = {
      16, 1,  18, 3,  20, 5,  22, 7,  24, 9,  26, 11, 28, 13, 30, 15,
      32, 49, 34, 51, 36, 53, 38, 55, 40, 57, 42, 59, 44, 61, 46, 63};
  RelaxedLaneSelectRevecTest<uint8_t, kElems>(l1, l2, r1, r2, s1, s2, expected,
                                              kExprI8x16RelaxedLaneSelect);
}

TEST(RunWasm_I32x8DotI8x32I7x32AddS) {
  if (!CpuFeatures::IsSupported(AVX2)) return;
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  WasmRunner<int32_t, int8_t, int8_t, int32_t> r(TestExecutionTier::kTurbofan);
  int32_t* memory = r.builder().AddMemoryElems<int32_t>(8);
  uint8_t param1 = 0;
  uint8_t param2 = 1;
  uint8_t param3 = 2;
  r.Build({WASM_SIMD_STORE_MEM(
               WASM_ZERO,
               WASM_SIMD_TERNOP(kExprI32x4DotI8x16I7x16AddS,
                                WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(param1)),
                                WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(param2)),
                                WASM_SIMD_I32x4_SPLAT(WASM_LOCAL_GET(param3)))),
           WASM_SIMD_STORE_MEM_OFFSET(
               16, WASM_ZERO,
               WASM_SIMD_TERNOP(kExprI32x4DotI8x16I7x16AddS,
                                WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(param1)),
                                WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(param2)),
                                WASM_SIMD_I32x4_SPLAT(WASM_LOCAL_GET(param3)))),
           WASM_ONE});
  for (int8_t x : compiler::ValueHelper::GetVector<int8_t>()) {
    for (int8_t y : compiler::ValueHelper::GetVector<int8_t>()) {
      for (int32_t z : compiler::ValueHelper::GetVector<int32_t>()) {
        int32_t expected = base::AddWithWraparound(
            base::MulWithWraparound(x * (y & 0x7F), 4), z);
        r.Call(x, y & 0x7F, z);
        for (auto i = 0; i < 4; i++) {
          CHECK_EQ(expected, memory[i]);
          CHECK_EQ(expected, memory[4 + i]);
        }
      }
    }
  }
}

TEST(RunWasm_I16x16DotI8x32I7x32S) {
  if (!CpuFeatures::IsSupported(AVX2)) return;
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  WasmRunner<int32_t, int8_t, int8_t> r(TestExecutionTier::kTurbofan);
  int16_t* memory = r.builder().AddMemoryElems<int16_t>(16);
  uint8_t param1 = 0, param2 = 1;

  r.Build({WASM_SIMD_STORE_MEM(
               WASM_ZERO,
               WASM_SIMD_BINOP(kExprI16x8DotI8x16I7x16S,
                               WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(param1)),
                               WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(param2)))),
           WASM_SIMD_STORE_MEM_OFFSET(
               16, WASM_ZERO,
               WASM_SIMD_BINOP(kExprI16x8DotI8x16I7x16S,
                               WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(param1)),
                               WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(param2)))),
           WASM_ONE});

  for (int8_t x : compiler::ValueHelper::GetVector<int8_t>()) {
    for (int8_t y : compiler::ValueHelper::GetVector<int8_t>()) {
      r.Call(x, y & 0x7F);
      // * 2 because we of (x*y) + (x*y) = 2*x*y
      int16_t expected = base::MulWithWraparound(x * (y & 0x7F), 2);
      CHECK_EQ(expected, memory[0]);
      CHECK_EQ(expected, memory[8]);
    }
  }
}

TEST(RunWasmTurbofan_F32x8RelaxedMin) {
  if (!v8_flags.turboshaft_wasm ||
      !v8_flags.turboshaft_wasm_instruction_selection_staged)
    return;
  RunF32x8BinOpRevecTest(kExprF32x4RelaxedMin, Minimum,
                         compiler::IrOpcode::kF32x8RelaxedMin);
}

TEST(RunWasmTurbofan_F32x8RelaxedMax) {
  if (!v8_flags.turboshaft_wasm ||
      !v8_flags.turboshaft_wasm_instruction_selection_staged)
    return;
  RunF32x8BinOpRevecTest(kExprF32x4RelaxedMax, Maximum,
                         compiler::IrOpcode::kF32x8RelaxedMax);
}

TEST(RunWasmTurbofan_F64x4RelaxedMin) {
  if (!v8_flags.turboshaft_wasm ||
      !v8_flags.turboshaft_wasm_instruction_selection_staged)
    return;
  RunF64x4BinOpRevecTest(kExprF64x2RelaxedMin, Minimum,
                         compiler::IrOpcode::kF64x4RelaxedMin);
}

TEST(RunWasmTurbofan_F64x4RelaxedMax) {
  if (!v8_flags.turboshaft_wasm ||
      !v8_flags.turboshaft_wasm_instruction_selection_staged)
    return;
  RunF64x4BinOpRevecTest(kExprF64x2RelaxedMax, Maximum,
                         compiler::IrOpcode::kF64x4RelaxedMax);
}

template <typename IntType>
void I32x8RelaxedTruncF32x8RevecTest(WasmOpcode trunc_op,
                                     compiler::IrOpcode::Value revec_opcode) {
  if (!CpuFeatures::IsSupported(AVX2)) return;
  EXPERIMENTAL_FLAG_SCOPE(revectorize);

  WasmRunner<int32_t, float> r(TestExecutionTier::kTurbofan);
  IntType* memory = r.builder().AddMemoryElems<IntType>(8);
  uint8_t param1 = 0;

  TSSimd256VerifyScope ts_scope(
      r.zone(), TSSimd256VerifyScope::VerifyHaveOpcode<
                    compiler::turboshaft::Opcode::kSimd256Unary>);
  BUILD_AND_CHECK_REVEC_NODE(
      r, revec_opcode,
      WASM_SIMD_STORE_MEM(
          WASM_ZERO,
          WASM_SIMD_UNOP(trunc_op, WASM_SIMD_UNOP(kExprF32x4Splat,
                                                  WASM_LOCAL_GET(param1)))),
      WASM_SIMD_STORE_MEM_OFFSET(
          16, WASM_ZERO,
          WASM_SIMD_UNOP(trunc_op, WASM_SIMD_UNOP(kExprF32x4Splat,
                                                  WASM_LOCAL_GET(param1)))),
      WASM_ONE);

  for (float x : compiler::ValueHelper::GetVector<float>()) {
    if (ShouldSkipTestingConstant<IntType>(x)) continue;
    CHECK_EQ(1, r.Call(x));
    IntType expected = base::checked_cast<IntType>(x);
    for (int i = 0; i < 8; i++) {
      CHECK_EQ(expected, memory[i]);
    }
  }
}

TEST(RunWasmTurbofan_I32x8RelaxedTruncF32x8U) {
  if (!v8_flags.turboshaft_wasm ||
      !v8_flags.turboshaft_wasm_instruction_selection_staged)
    return;
  I32x8RelaxedTruncF32x8RevecTest<uint32_t>(
      kExprI32x4RelaxedTruncF32x4U,
      compiler::IrOpcode::kI32x8RelaxedTruncF32x8U);
}

TEST(RunWasmTurbofan_I32x8RelaxedTruncF32x8S) {
  if (!v8_flags.turboshaft_wasm ||
      !v8_flags.turboshaft_wasm_instruction_selection_staged)
    return;
  I32x8RelaxedTruncF32x8RevecTest<int32_t>(
      kExprI32x4RelaxedTruncF32x4S,
      compiler::IrOpcode::kI32x8RelaxedTruncF32x8S);
}

#endif  // V8_ENABLE_WASM_SIMD256_REVEC

}  // namespace v8::internal::wasm

"""

```