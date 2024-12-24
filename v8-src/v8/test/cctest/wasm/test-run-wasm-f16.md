Response: The user wants to understand the functionality of the provided C++ code file, specifically `v8/test/cctest/wasm/test-run-wasm-f16.cc`. They are also interested in how this relates to JavaScript and want examples.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The file name and the presence of `WASM_EXEC_TEST` macros strongly suggest this file contains tests for WebAssembly (Wasm) functionality, particularly related to the `f16` (half-precision floating-point) data type.

2. **Analyze the `WASM_EXEC_TEST` blocks:** Each of these blocks likely tests a specific Wasm instruction or operation related to `f16`. Examine the Wasm opcodes used (e.g., `WASM_F16_LOAD_MEM`, `WASM_F16_STORE_MEM`, `WASM_SIMD_F16x8_SPLAT`).

3. **Look for helper functions and data structures:** The code uses `WasmRunner`, `AddMemoryElems`, `AddGlobal`, and helper functions like `fp16_ieee_from_fp32_value` and `fp16_ieee_to_fp32_value`. These provide context about how the tests are set up and how data is being manipulated. The `FOR_FLOAT32_INPUTS` and `FOR_INT16_INPUTS` macros indicate the test inputs.

4. **Infer the functionality being tested from the operations:**
    * `F16Load`:  Loading an `f16` value from Wasm memory.
    * `F16Store`: Storing an `f16` value into Wasm memory.
    * `F16x8Splat`: Creating an `f16x8` (SIMD vector of 8 `f16` values) where all elements have the same value.
    * `F16x8ReplaceLane`: Replacing a specific element (lane) in an `f16x8` vector.
    * `F16x8ExtractLane`: Extracting a specific element from an `f16x8` vector.
    * `F16x8` followed by unary operations (e.g., `Abs`, `Neg`, `Sqrt`): Testing the application of these unary operations on `f16x8` vectors.
    * `F16x8` followed by comparison operations (e.g., `Eq`, `Ne`, `Gt`): Testing element-wise comparisons between `f16x8` vectors.
    * `F16x8` followed by binary operations (e.g., `Add`, `Sub`, `Mul`): Testing element-wise binary operations between `f16x8` vectors.
    * `F16x8ConvertI16x8`: Converting `i16x8` (SIMD vector of 8 signed 16-bit integers) to `f16x8`.
    * `I16x8ConvertF16x8`: Converting `f16x8` to `i16x8`.
    * `F16x8DemoteF32x4Zero`: Converting an `f32x4` (SIMD vector of 4 single-precision floats) to `f16x8`, with the upper 4 lanes being zeroed.
    * `F16x8DemoteF64x2Zero`: Converting an `f64x2` (SIMD vector of 2 double-precision floats) to `f16x8`, with the upper 6 lanes being zeroed.
    * `F32x4PromoteLowF16x8`: Converting the lower 4 lanes of an `f16x8` to an `f32x4`.
    * `F16x8Qfma`: Fused multiply-add operation on `f16x8` vectors.
    * `F16x8Qfms`: Fused multiply-subtract operation on `f16x8` vectors.

5. **Relate to JavaScript:**  Wasm is designed to run in web browsers alongside JavaScript. JavaScript provides the API to load, compile, and execute Wasm modules. The `f16` type, when supported by the JavaScript engine, can be passed between JavaScript and Wasm.

6. **Construct JavaScript examples:** Based on the identified functionalities, create simple JavaScript code snippets that demonstrate equivalent operations or how the Wasm functionality might be used from a JavaScript context. Consider how JavaScript's `WebAssembly` API and typed arrays might interact with `f16` data. Since direct `f16` support in JavaScript is relatively new, also illustrate how one might interact with `f16` data indirectly.

7. **Refine and organize the summary:** Present the findings in a clear and structured manner, starting with the overall purpose of the file and then detailing each tested functionality with corresponding JavaScript examples. Explain the relationship between the C++ test code and the actual Wasm feature and its JavaScript accessibility.
这个C++源代码文件 `v8/test/cctest/wasm/test-run-wasm-f16.cc` 的主要功能是 **测试 V8 JavaScript 引擎中 WebAssembly (Wasm) 对 `f16` (半精度浮点数) 数据类型的支持**。

更具体地说，它包含了一系列 C++ 测试用例，用于验证以下与 Wasm `f16` 相关的操作是否正确实现：

1. **加载和存储 `f16` 值:** 测试从 Wasm 内存中加载 `f16` 类型的值，以及将 `f16` 类型的值存储到 Wasm 内存中。

2. **`f16x8` SIMD 操作:** 测试针对 `f16x8` SIMD (单指令多数据流) 向量的操作，其中 `f16x8` 是一个包含 8 个 `f16` 值的向量。这些操作包括：
   - **`f16x8.splat`:**  将一个 `f32` (单精度浮点数) 值广播到 `f16x8` 向量的所有 8 个元素。
   - **`f16x8.replace_lane`:** 替换 `f16x8` 向量中指定索引的元素。
   - **`f16x8.extract_lane`:** 提取 `f16x8` 向量中指定索引的元素。
   - **`f16x8` 上的算术运算:**  例如绝对值 (`abs`)，取反 (`neg`)，平方根 (`sqrt`)，向上取整 (`ceil`)，向下取整 (`floor`)，截断 (`trunc`)，取最近整数 (`nearest_int`)，加法 (`add`)，减法 (`sub`)，乘法 (`mul`)，除法 (`div`)，最小值 (`min`, `pmin`)，最大值 (`max`, `pmax`)。
   - **`f16x8` 上的比较运算:** 例如等于 (`eq`)，不等于 (`ne`)，大于 (`gt`)，大于等于 (`ge`)，小于 (`lt`)，小于等于 (`le`)。
   - **`f16x8.convert_i16x8_s` 和 `f16x8.convert_i16x8_u`:** 将 `i16x8` (带符号和无符号 16 位整数向量) 转换为 `f16x8`。
   - **`i16x8.convert_f16x8_s_sat` 和 `i16x8.convert_f16x8_u_sat`:** 将 `f16x8` 转换为 `i16x8`，并在超出范围时进行饱和处理。
   - **`f16x8.demote_f32x4_zero`:** 将 `f32x4` (单精度浮点数向量) 转换为 `f16x8`，并将高 4 位设置为零。
   - **`f16x8.demote_f64x2_zero`:** 将 `f64x2` (双精度浮点数向量) 转换为 `f16x8`，并将高 6 位设置为零。
   - **`f32x4.promote_low_f16x8`:** 将 `f16x8` 向量的低 4 位提升为 `f32x4`。
   - **`f16x8.qfma` (Fused Multiply-Add):** 执行 `a * b + c` 的融合乘加运算。
   - **`f16x8.qfms` (Fused Multiply-Subtract):** 执行 `-(a * b) + c` 的融合乘减运算。

**它与 JavaScript 的功能有密切关系，因为 WebAssembly 旨在与 JavaScript 并行运行在 Web 浏览器中。**  JavaScript 可以调用 WebAssembly 模块，反之亦然。  当 JavaScript 引擎支持 Wasm 的 `f16` 类型时，JavaScript 可以与 Wasm 模块之间传递 `f16` 数据。

**JavaScript 示例:**

假设一个 WebAssembly 模块 (用 C++ 编写并编译为 Wasm) 导出了一个函数，该函数接收一个 `f32` 值，并返回一个将该值 splat 到 `f16x8` 向量的结果。  在 JavaScript 中，我们可以这样使用它：

```javascript
async function runWasm() {
  const response = await fetch('your_wasm_module.wasm'); // 替换为你的 Wasm 模块路径
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.instantiate(buffer, {}); // 导入对象为空

  const wasmInstance = module.instance;
  const splatF16x8 = wasmInstance.exports.splat_f16x8; // 假设导出的函数名为 splat_f16x8

  if (splatF16x8) {
    const inputValue = 2.75;
    const result = splatF16x8(inputValue);

    // 'result' 在 JavaScript 中可能表示为一个 Uint16Array 或类似的数据结构，
    // 具体取决于 Wasm 模块如何返回 f16x8 数据。
    // JavaScript 可能需要一些辅助函数来解释 f16 数据。

    console.log("Wasm f16x8 splat result:", result);

    // 进一步处理 f16x8 数据，例如提取 lane 并将其转换回 JavaScript 可用的浮点数
    // (需要根据 f16 的二进制表示进行转换)。
  } else {
    console.error("Wasm 函数 splat_f16x8 未找到");
  }
}

runWasm();
```

**解释:**

1. **加载 Wasm 模块:**  JavaScript 使用 `fetch` API 获取 Wasm 模块，然后使用 `WebAssembly.instantiate` 将其实例化。
2. **访问导出的函数:**  `wasmInstance.exports.splat_f16x8`  访问 Wasm 模块导出的名为 `splat_f16x8` 的函数。这个函数在 C++ 代码中对应的测试可能是 `WASM_EXEC_TEST(F16x8Splat)`.
3. **调用 Wasm 函数:**  我们使用一个 JavaScript 的 `float` 值 `inputValue` 调用 Wasm 函数。
4. **处理结果:**  Wasm 函数返回的结果（`f16x8` 向量）需要在 JavaScript 中进行解释。由于 JavaScript 原生不支持 `f16` 类型，通常会将其表示为 `Uint16Array` (因为 `f16` 是 16 位)。  我们需要额外的逻辑来将这些 16 位值转换回 JavaScript 可以理解的浮点数。

**更高级的 JavaScript 交互:**

如果 JavaScript 引擎提供了对 `WebAssembly.SIMD` 的支持并且支持 `f16x8`，则可以更直接地操作 `f16x8` 值：

```javascript
async function runWasmSimd() {
  const response = await fetch('your_wasm_module.wasm');
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.instantiateStreaming(response, {}); // 使用 instantiateStreaming

  const wasmInstance = module.instance;
  const getF16x8Splat = wasmInstance.exports.get_f16x8_splat; // 假设 Wasm 导出返回 f16x8 的函数

  if (getF16x8Splat) {
    const inputValue = 3.14159;
    const f16x8Result = getF16x8Splat(inputValue);

    // 如果 JavaScript 引擎支持 WebAssembly.SIMD 并且支持 f16x8，
    // f16x8Result 可能是一个 WebAssembly.Simd.Float16x8 对象。
    if (f16x8Result instanceof WebAssembly.Simd.Float16x8) {
      console.log("Wasm f16x8 splat result:", f16x8Result);
      console.log("Lane 0:", f16x8Result.extractLane(0));
      // ... 可以进行其他 SIMD 操作
    } else {
      console.log("Wasm f16x8 result (fallback):", f16x8Result); // 可能是 Uint16Array
    }
  } else {
    console.error("Wasm 函数 get_f16x8_splat 未找到");
  }
}

runWasmSimd();
```

**总结:**

`v8/test/cctest/wasm/test-run-wasm-f16.cc` 文件是 V8 引擎中用于测试 WebAssembly 对 `f16` 类型支持的关键部分。它通过各种测试用例验证了 `f16` 值的加载、存储以及 `f16x8` SIMD 操作的正确性。  这些测试确保了当 JavaScript 代码与使用 `f16` 的 WebAssembly 模块交互时，能够得到预期的结果。 JavaScript 通过 WebAssembly API 与这些功能进行交互，虽然目前 JavaScript 对 `f16` 的原生支持可能还处于发展阶段，但最终的目标是实现 JavaScript 和 WebAssembly 之间 `f16` 数据的无缝传递和操作。

Prompt: 
```
这是目录为v8/test/cctest/wasm/test-run-wasm-f16.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/overflowing-math.h"
#include "src/codegen/assembler-inl.h"
#include "src/numbers/conversions.h"
#include "src/wasm/wasm-opcodes.h"
#include "test/cctest/cctest.h"
#include "test/cctest/wasm/wasm-run-utils.h"
#include "test/cctest/wasm/wasm-simd-utils.h"
#include "test/common/wasm/test-signatures.h"
#include "test/common/wasm/wasm-macro-gen.h"
#include "third_party/fp16/src/include/fp16.h"

namespace v8 {
namespace internal {
namespace wasm {
namespace test_run_wasm_f16 {

WASM_EXEC_TEST(F16Load) {
  i::v8_flags.experimental_wasm_fp16 = true;
  i::v8_flags.turboshaft_wasm = true;
  WasmRunner<float> r(execution_tier);
  uint16_t* memory = r.builder().AddMemoryElems<uint16_t>(4);
  r.Build({WASM_F16_LOAD_MEM(WASM_I32V_1(4))});
  r.builder().WriteMemory(&memory[2], fp16_ieee_from_fp32_value(2.75));
  CHECK_EQ(2.75f, r.Call());
}

WASM_EXEC_TEST(F16Store) {
  i::v8_flags.experimental_wasm_fp16 = true;
  i::v8_flags.turboshaft_wasm = true;
  WasmRunner<int32_t> r(execution_tier);
  uint16_t* memory = r.builder().AddMemoryElems<uint16_t>(4);
  r.Build({WASM_F16_STORE_MEM(WASM_I32V_1(4), WASM_F32(2.75)), WASM_ZERO});
  r.Call();
  CHECK_EQ(r.builder().ReadMemory(&memory[2]), fp16_ieee_from_fp32_value(2.75));
}

WASM_EXEC_TEST(F16x8Splat) {
  i::v8_flags.experimental_wasm_fp16 = true;
  i::v8_flags.turboshaft_wasm = true;
  WasmRunner<int32_t, float> r(execution_tier);
  // Set up a global to hold output vector.
  uint16_t* g = r.builder().AddGlobal<uint16_t>(kWasmS128);
  uint8_t param1 = 0;
  r.Build({WASM_GLOBAL_SET(0, WASM_SIMD_F16x8_SPLAT(WASM_LOCAL_GET(param1))),
           WASM_ONE});

  FOR_FLOAT32_INPUTS(x) {
    r.Call(x);
    uint16_t expected = fp16_ieee_from_fp32_value(x);
    for (int i = 0; i < 8; i++) {
      uint16_t actual = LANE(g, i);
      if (std::isnan(x)) {
        CHECK(isnan(actual));
      } else {
        CHECK_EQ(actual, expected);
      }
    }
  }
}

WASM_EXEC_TEST(F16x8ReplaceLane) {
  i::v8_flags.experimental_wasm_fp16 = true;
  i::v8_flags.turboshaft_wasm = true;
  WasmRunner<int32_t> r(execution_tier);
  // Set up a global to hold output vector.
  uint16_t* g = r.builder().AddGlobal<uint16_t>(kWasmS128);
  // Build function to replace each lane with its (FP) index.
  r.Build({WASM_SIMD_F16x8_SPLAT(WASM_F32(3.14159f)),
           WASM_F32(0.0f),
           WASM_SIMD_OP(kExprF16x8ReplaceLane),
           0,
           WASM_F32(1.0f),
           WASM_SIMD_OP(kExprF16x8ReplaceLane),
           1,
           WASM_F32(2.0f),
           WASM_SIMD_OP(kExprF16x8ReplaceLane),
           2,
           WASM_F32(3.0f),
           WASM_SIMD_OP(kExprF16x8ReplaceLane),
           3,
           WASM_F32(4.0f),
           WASM_SIMD_OP(kExprF16x8ReplaceLane),
           4,
           WASM_F32(5.0f),
           WASM_SIMD_OP(kExprF16x8ReplaceLane),
           5,
           WASM_F32(6.0f),
           WASM_SIMD_OP(kExprF16x8ReplaceLane),
           6,
           WASM_F32(7.0f),
           WASM_SIMD_OP(kExprF16x8ReplaceLane),
           7,
           kExprGlobalSet,
           0,
           WASM_ONE});

  r.Call();
  for (int i = 0; i < 8; i++) {
    CHECK_EQ(fp16_ieee_from_fp32_value(i), LANE(g, i));
  }
}

WASM_EXEC_TEST(F16x8ExtractLane) {
  i::v8_flags.experimental_wasm_fp16 = true;
  i::v8_flags.turboshaft_wasm = true;
  WasmRunner<int32_t> r(execution_tier);
  uint16_t* g = r.builder().AddGlobal<uint16_t>(kWasmS128);
  float* globals[8];
  for (int i = 0; i < 8; i++) {
    LANE(g, i) = fp16_ieee_from_fp32_value(i);
    globals[i] = r.builder().AddGlobal<float>(kWasmF32);
  }

  r.Build(
      {WASM_GLOBAL_SET(1, WASM_SIMD_F16x8_EXTRACT_LANE(0, WASM_GLOBAL_GET(0))),
       WASM_GLOBAL_SET(2, WASM_SIMD_F16x8_EXTRACT_LANE(1, WASM_GLOBAL_GET(0))),
       WASM_GLOBAL_SET(3, WASM_SIMD_F16x8_EXTRACT_LANE(2, WASM_GLOBAL_GET(0))),
       WASM_GLOBAL_SET(4, WASM_SIMD_F16x8_EXTRACT_LANE(3, WASM_GLOBAL_GET(0))),
       WASM_GLOBAL_SET(5, WASM_SIMD_F16x8_EXTRACT_LANE(4, WASM_GLOBAL_GET(0))),
       WASM_GLOBAL_SET(6, WASM_SIMD_F16x8_EXTRACT_LANE(5, WASM_GLOBAL_GET(0))),
       WASM_GLOBAL_SET(7, WASM_SIMD_F16x8_EXTRACT_LANE(6, WASM_GLOBAL_GET(0))),
       WASM_GLOBAL_SET(8, WASM_SIMD_F16x8_EXTRACT_LANE(7, WASM_GLOBAL_GET(0))),
       WASM_ONE});

  r.Call();
  for (int i = 0; i < 8; i++) {
    CHECK_EQ(*globals[i], i);
  }
}

#define UN_OP_LIST(V) \
  V(Abs, std::abs)    \
  V(Neg, -)           \
  V(Sqrt, std::sqrt)  \
  V(Ceil, ceilf)      \
  V(Floor, floorf)    \
  V(Trunc, truncf)    \
  V(NearestInt, nearbyintf)

#define TEST_UN_OP(WasmName, COp)                                          \
  uint16_t WasmName##F16(uint16_t a) {                                     \
    return fp16_ieee_from_fp32_value(COp(fp16_ieee_to_fp32_value(a)));     \
  }                                                                        \
  WASM_EXEC_TEST(F16x8##WasmName) {                                        \
    i::v8_flags.experimental_wasm_fp16 = true;                             \
    i::v8_flags.turboshaft_wasm = true;                                    \
    RunF16x8UnOpTest(execution_tier, kExprF16x8##WasmName, WasmName##F16); \
  }

UN_OP_LIST(TEST_UN_OP)

#undef TEST_UN_OP
#undef UN_OP_LIST

#define CMP_OP_LIST(V) \
  V(Eq, ==)            \
  V(Ne, !=)            \
  V(Gt, >)             \
  V(Ge, >=)            \
  V(Lt, <)             \
  V(Le, <=)

#define TEST_CMP_OP(WasmName, COp)                                             \
  int16_t WasmName(uint16_t a, uint16_t b) {                                   \
    return fp16_ieee_to_fp32_value(a) COp fp16_ieee_to_fp32_value(b) ? -1 : 0; \
  }                                                                            \
  WASM_EXEC_TEST(F16x8##WasmName) {                                            \
    i::v8_flags.experimental_wasm_fp16 = true;                                 \
    i::v8_flags.turboshaft_wasm = true;                                        \
    RunF16x8CompareOpTest(execution_tier, kExprF16x8##WasmName, WasmName);     \
  }

CMP_OP_LIST(TEST_CMP_OP)

#undef TEST_CMP_OP
#undef UN_CMP_LIST

float Add(float a, float b) { return a + b; }
float Sub(float a, float b) { return a - b; }
float Mul(float a, float b) { return a * b; }

#define BIN_OP_LIST(V) \
  V(Add, Add)          \
  V(Sub, Sub)          \
  V(Mul, Mul)          \
  V(Div, base::Divide) \
  V(Min, JSMin)        \
  V(Max, JSMax)        \
  V(Pmin, Minimum)     \
  V(Pmax, Maximum)

#define TEST_BIN_OP(WasmName, COp)                                          \
  uint16_t WasmName##F16(uint16_t a, uint16_t b) {                          \
    return fp16_ieee_from_fp32_value(                                       \
        COp(fp16_ieee_to_fp32_value(a), fp16_ieee_to_fp32_value(b)));       \
  }                                                                         \
  WASM_EXEC_TEST(F16x8##WasmName) {                                         \
    i::v8_flags.experimental_wasm_fp16 = true;                              \
    i::v8_flags.turboshaft_wasm = true;                                     \
    RunF16x8BinOpTest(execution_tier, kExprF16x8##WasmName, WasmName##F16); \
  }

BIN_OP_LIST(TEST_BIN_OP)

#undef TEST_BIN_OP
#undef BIN_OP_LIST

WASM_EXEC_TEST(F16x8ConvertI16x8) {
  i::v8_flags.experimental_wasm_fp16 = true;
  i::v8_flags.turboshaft_wasm = true;
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // Create two output vectors to hold signed and unsigned results.
  uint16_t* g0 = r.builder().AddGlobal<uint16_t>(kWasmS128);
  uint16_t* g1 = r.builder().AddGlobal<uint16_t>(kWasmS128);
  // Build fn to splat test value, perform conversions, and write the results.
  uint8_t value = 0;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I16x8_SPLAT(WASM_LOCAL_GET(value))),
           WASM_GLOBAL_SET(0, WASM_SIMD_UNOP(kExprF16x8SConvertI16x8,
                                             WASM_LOCAL_GET(temp1))),
           WASM_GLOBAL_SET(1, WASM_SIMD_UNOP(kExprF16x8UConvertI16x8,
                                             WASM_LOCAL_GET(temp1))),
           WASM_ONE});

  FOR_INT16_INPUTS(x) {
    r.Call(x);
    uint16_t expected_signed = fp16_ieee_from_fp32_value(x);
    uint16_t expected_unsigned =
        fp16_ieee_from_fp32_value(static_cast<uint16_t>(x));
    for (int i = 0; i < 8; i++) {
      CHECK_EQ(expected_signed, LANE(g0, i));
      CHECK_EQ(expected_unsigned, LANE(g1, i));
    }
  }
}

int16_t ConvertToInt(uint16_t f16, bool unsigned_result) {
  float f32 = fp16_ieee_to_fp32_value(f16);
  if (std::isnan(f32)) return 0;
  if (unsigned_result) {
    if (f32 > float{kMaxUInt16}) return static_cast<uint16_t>(kMaxUInt16);
    if (f32 < 0) return 0;
    return static_cast<uint16_t>(f32);
  } else {
    if (f32 > float{kMaxInt16}) return static_cast<int16_t>(kMaxInt16);
    if (f32 < float{kMinInt16}) return static_cast<int16_t>(kMinInt16);
    return static_cast<int16_t>(f32);
  }
}

// Tests both signed and unsigned conversion.
WASM_EXEC_TEST(I16x8ConvertF16x8) {
  i::v8_flags.experimental_wasm_fp16 = true;
  i::v8_flags.turboshaft_wasm = true;
  WasmRunner<int32_t, float> r(execution_tier);
  // Create two output vectors to hold signed and unsigned results.
  int16_t* g0 = r.builder().AddGlobal<int16_t>(kWasmS128);
  int16_t* g1 = r.builder().AddGlobal<int16_t>(kWasmS128);
  // Build fn to splat test value, perform conversions, and write the results.
  uint8_t value = 0;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_F16x8_SPLAT(WASM_LOCAL_GET(value))),
           WASM_GLOBAL_SET(0, WASM_SIMD_UNOP(kExprI16x8SConvertF16x8,
                                             WASM_LOCAL_GET(temp1))),
           WASM_GLOBAL_SET(1, WASM_SIMD_UNOP(kExprI16x8UConvertF16x8,
                                             WASM_LOCAL_GET(temp1))),
           WASM_ONE});

  FOR_FLOAT32_INPUTS(x) {
    if (!PlatformCanRepresent(x)) continue;
    r.Call(x);
    int16_t expected_signed = ConvertToInt(fp16_ieee_from_fp32_value(x), false);
    int16_t expected_unsigned =
        ConvertToInt(fp16_ieee_from_fp32_value(x), true);
    for (int i = 0; i < 8; i++) {
      CHECK_EQ(expected_signed, LANE(g0, i));
      CHECK_EQ(expected_unsigned, LANE(g1, i));
    }
  }
}

WASM_EXEC_TEST(F16x8DemoteF32x4Zero) {
  i::v8_flags.experimental_wasm_fp16 = true;
  i::v8_flags.turboshaft_wasm = true;
  WasmRunner<int32_t, float> r(execution_tier);
  uint16_t* g = r.builder().AddGlobal<uint16_t>(kWasmS128);
  r.Build({WASM_GLOBAL_SET(
               0, WASM_SIMD_UNOP(kExprF16x8DemoteF32x4Zero,
                                 WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(0)))),
           WASM_ONE});

  FOR_FLOAT32_INPUTS(x) {
    r.Call(x);
    uint16_t expected = fp16_ieee_from_fp32_value(x);
    for (int i = 0; i < 4; i++) {
      uint16_t actual = LANE(g, i);
      CheckFloat16LaneResult(x, x, expected, actual, true);
    }
    for (int i = 4; i < 8; i++) {
      uint16_t actual = LANE(g, i);
      CheckFloat16LaneResult(x, x, 0, actual, true);
    }
  }
}

WASM_EXEC_TEST(F16x8DemoteF64x2Zero) {
  i::v8_flags.experimental_wasm_fp16 = true;
  i::v8_flags.turboshaft_wasm = true;
  WasmRunner<int32_t, double> r(execution_tier);
  uint16_t* g = r.builder().AddGlobal<uint16_t>(kWasmS128);
  r.Build({WASM_GLOBAL_SET(
               0, WASM_SIMD_UNOP(kExprF16x8DemoteF64x2Zero,
                                 WASM_SIMD_F64x2_SPLAT(WASM_LOCAL_GET(0)))),
           WASM_ONE});

  FOR_FLOAT64_INPUTS(x) {
    r.Call(x);
    uint16_t expected = DoubleToFloat16(x);
    for (int i = 0; i < 2; i++) {
      uint16_t actual = LANE(g, i);
      CheckFloat16LaneResult(x, x, expected, actual, true);
    }
    for (int i = 2; i < 8; i++) {
      uint16_t actual = LANE(g, i);
      CheckFloat16LaneResult(x, x, 0, actual, true);
    }
  }
}

WASM_EXEC_TEST(F32x4PromoteLowF16x8) {
  i::v8_flags.experimental_wasm_fp16 = true;
  i::v8_flags.turboshaft_wasm = true;
  WasmRunner<int32_t, float> r(execution_tier);
  float* g = r.builder().AddGlobal<float>(kWasmS128);
  r.Build({WASM_GLOBAL_SET(
               0, WASM_SIMD_UNOP(kExprF32x4PromoteLowF16x8,
                                 WASM_SIMD_F16x8_SPLAT(WASM_LOCAL_GET(0)))),
           WASM_ONE});

  FOR_FLOAT32_INPUTS(x) {
    r.Call(x);
    float expected = fp16_ieee_to_fp32_value(fp16_ieee_from_fp32_value(x));
    for (int i = 0; i < 4; i++) {
      float actual = LANE(g, i);
      CheckFloatResult(x, x, expected, actual, true);
    }
  }
}

struct FMOperation {
  const float a;
  const float b;
  const float c;
  const float fused_result;
};

constexpr float large_n = 1e4;
constexpr float finf = std::numeric_limits<float>::infinity();
constexpr float qNan = std::numeric_limits<float>::quiet_NaN();

// Fused Multiply-Add performs a * b + c.
static FMOperation qfma_array[] = {
    {2.0f, 3.0f, 1.0f, 7.0f},
    // fused: a * b + c = (positive overflow) + -inf = -inf
    // unfused: a * b + c = inf + -inf = NaN
    {large_n, large_n, -finf, -finf},
    // fused: a * b + c = (negative overflow) + inf = inf
    // unfused: a * b + c = -inf + inf = NaN
    {-large_n, large_n, finf, finf},
    // NaN
    {2.0f, 3.0f, qNan, qNan},
    // -NaN
    {2.0f, 3.0f, -qNan, qNan}};

base::Vector<const FMOperation> qfma_vector() {
  return base::ArrayVector(qfma_array);
}

// Fused Multiply-Subtract performs -(a * b) + c.
static FMOperation qfms_array[]{
    {2.0f, 3.0f, 1.0f, -5.0f},
    // fused: -(a * b) + c = - (positive overflow) + inf = inf
    // unfused: -(a * b) + c = - inf + inf = NaN
    {large_n, large_n, finf, finf},
    // fused: -(a * b) + c = (negative overflow) + -inf = -inf
    // unfused: -(a * b) + c = -inf - -inf = NaN
    {-large_n, large_n, -finf, -finf},
    // NaN
    {2.0f, 3.0f, qNan, qNan},
    // -NaN
    {2.0f, 3.0f, -qNan, qNan}};

base::Vector<const FMOperation> qfms_vector() {
  return base::ArrayVector(qfms_array);
}

WASM_EXEC_TEST(F16x8Qfma) {
  i::v8_flags.experimental_wasm_fp16 = true;
  i::v8_flags.turboshaft_wasm = true;
  WasmRunner<int32_t, float, float, float> r(execution_tier);
  // Set up global to hold output.
  uint16_t* g = r.builder().AddGlobal<uint16_t>(kWasmS128);
  uint8_t value1 = 0, value2 = 1, value3 = 2;
  r.Build(
      {WASM_GLOBAL_SET(0, WASM_SIMD_F16x8_QFMA(
                              WASM_SIMD_F16x8_SPLAT(WASM_LOCAL_GET(value1)),
                              WASM_SIMD_F16x8_SPLAT(WASM_LOCAL_GET(value2)),
                              WASM_SIMD_F16x8_SPLAT(WASM_LOCAL_GET(value3)))),
       WASM_ONE});
  for (FMOperation x : qfma_vector()) {
    r.Call(x.a, x.b, x.c);
    uint16_t expected = fp16_ieee_from_fp32_value(x.fused_result);
    for (int i = 0; i < 8; i++) {
      uint16_t actual = LANE(g, i);
      CheckFloat16LaneResult(x.a, x.b, x.c, expected, actual, true /* exact */);
    }
  }
}

WASM_EXEC_TEST(F16x8Qfms) {
  i::v8_flags.experimental_wasm_fp16 = true;
  i::v8_flags.turboshaft_wasm = true;
  WasmRunner<int32_t, float, float, float> r(execution_tier);
  // Set up global to hold output.
  uint16_t* g = r.builder().AddGlobal<uint16_t>(kWasmS128);
  uint8_t value1 = 0, value2 = 1, value3 = 2;
  r.Build(
      {WASM_GLOBAL_SET(0, WASM_SIMD_F16x8_QFMS(
                              WASM_SIMD_F16x8_SPLAT(WASM_LOCAL_GET(value1)),
                              WASM_SIMD_F16x8_SPLAT(WASM_LOCAL_GET(value2)),
                              WASM_SIMD_F16x8_SPLAT(WASM_LOCAL_GET(value3)))),
       WASM_ONE});

  for (FMOperation x : qfms_vector()) {
    r.Call(x.a, x.b, x.c);
    uint16_t expected = fp16_ieee_from_fp32_value(x.fused_result);
    for (int i = 0; i < 8; i++) {
      uint16_t actual = LANE(g, i);
      CheckFloat16LaneResult(x.a, x.b, x.c, expected, actual, true /* exact */);
    }
  }
}

}  // namespace test_run_wasm_f16
}  // namespace wasm
}  // namespace internal
}  // namespace v8

"""

```