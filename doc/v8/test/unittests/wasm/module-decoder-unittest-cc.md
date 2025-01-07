Response:
Let's break down the thought process for analyzing the given C++ code snippet.

**1. Initial Understanding of the Context:**

The first line is crucial: `这是目录为v8/test/unittests/wasm/module-decoder-unittest.cc的一个v8源代码`. This immediately tells us:

* **Location:** The code is part of the V8 JavaScript engine.
* **Purpose:** It's a unit test file specifically for the WebAssembly module decoder.
* **Language:** It's C++ (given the `.cc` extension).

**2. High-Level Goal Identification:**

The prompt asks for the *functionality* of the file. Unit tests have a clear primary purpose: to verify that a specific component of the software works correctly. In this case, it's the `ModuleDecoder`.

**3. Examining Key Includes:**

The `#include` directives provide valuable clues:

* `"src/wasm/module-decoder.h"`:  This is the core component being tested. The unit tests will likely exercise different aspects of this decoder.
* Other includes like `"src/wasm/branch-hint-map.h"`, `"src/wasm/wasm-engine.h"`, `"src/wasm/wasm-features.h"`, `"src/wasm/wasm-limits.h"`, `"src/wasm/wasm-opcodes.h"`: These suggest the scope of the `ModuleDecoder`'s work. It deals with WASM-specific concepts like branch hints, engine interaction, feature flags, limits, and opcodes.
* `"test/common/wasm/flag-utils.h"`, `"test/common/wasm/wasm-macro-gen.h"`: These are test utilities, likely used for setting up test conditions and generating WASM bytecode.
* `"test/unittests/test-utils.h"`, `"testing/gmock-support.h"`: Standard testing frameworks (gtest/gmock) are used for assertions and mocking.

**4. Analyzing Namespaces and Macros:**

The `namespace v8::internal::wasm::module_decoder_unittest` further confirms the purpose. The defined macros (`WASM_INIT_EXPR_I32V_1`, `TYPE_SECTION`, `EXPECT_VERIFIES`, `EXPECT_FAILURE`, etc.) are critical for understanding how the tests are structured. They are essentially shorthand for constructing WASM bytecode snippets and making assertions about the decoder's behavior.

**5. Identifying Core Test Patterns:**

The `TEST_F(WasmModuleVerifyTest, ...)` blocks are the individual test cases. By looking at the names (e.g., `WrongMagic`, `WrongVersion`, `OneGlobal`, `TwoGlobals`, `GlobalInvalidType`), we can start inferring the decoder's responsibilities:

* **Basic Structure:** Handling the WASM module header (magic number, version).
* **Section Decoding:**  Processing different sections of a WASM module (Type, Function, Global, Code, Export, etc.).
* **Data Validation:**  Verifying the correctness of data within sections (e.g., global types, initializers, function signatures).
* **Error Handling:** Checking for invalid or malformed WASM bytecode and producing appropriate errors.
* **Feature Support:** Testing specific WASM features (like SIMD).

**6. Inferring Functionality from Macros and Test Cases:**

* **`WASM_INIT_EXPR_*` macros:** These demonstrate how global variables are initialized with constant expressions. The variety of these macros indicates support for different WASM value types (i32, f32, i64, f64, references).
* **`TYPE_SECTION`, `FUNCTION_SECTION`, `GLOBAL_SECTION`, `CODE_SECTION`, `EXPORT_SECTION` macros:** These directly correspond to the standard WASM module structure, confirming the decoder's role in parsing these sections.
* **`EXPECT_VERIFIES`:** This macro suggests a test case where valid WASM should be successfully decoded.
* **`EXPECT_FAILURE`, `EXPECT_FAILURE_WITH_MSG`:** These macros indicate tests for invalid WASM, where the decoder is expected to report an error. The `_WITH_MSG` variant checks for specific error messages.
* **Test case names like `GlobalInvalidType`, `GlobalInitializer`, `InvalidFuncRefGlobal`:** These explicitly test error conditions.

**7. Addressing Specific Prompt Questions (and refining the analysis):**

* **`.tq` extension:** The code is `.cc`, so it's C++, not Torque.
* **Relationship to JavaScript:** The code *is* part of V8, the JavaScript engine. WASM execution is integrated with JavaScript. While this specific *test* file doesn't directly show JavaScript interaction, the decoder's output is used by the JavaScript engine to run WASM. A concrete JavaScript example would involve loading and executing the WASM modules that these tests verify.
* **Code Logic Inference (Hypothetical Input/Output):** The test cases themselves provide examples of input (WASM bytecode) and expected output (success or failure, and sometimes specific error messages). For example, the `WrongMagic` test takes a modified WASM header and expects a failure.
* **Common Programming Errors:** The tests for invalid WASM (e.g., `GlobalInvalidType`, `GlobalInitializer`) illustrate common errors a WASM *compiler* or code generator might produce. These aren't typically *user* programming errors in JavaScript, but rather errors in the underlying WASM bytecode.
* **Summary of Functionality:** Combining all the observations leads to the conclusion that the file tests the correct decoding and validation of WASM module structure and content by the `ModuleDecoder`.

**8. Structuring the Answer:**

Finally, the information needs to be organized into a clear and comprehensive answer, addressing each part of the prompt. This involves summarizing the key functionalities identified, explaining the purpose of the test file, addressing the `.tq` question, explaining the JavaScript relationship, providing examples of input/output from the tests, and explaining the relevance to common programming errors in the context of WASM generation.
这是一个V8 JavaScript引擎的C++源代码文件，位于`v8/test/unittests/wasm/`目录下，名为`module-decoder-unittest.cc`。从文件名可以推断出，这个文件的主要目的是**测试WebAssembly模块解码器（Module Decoder）的功能**。

下面列举一下它的具体功能：

1. **测试 WASM 模块头的解析:**  例如 `TEST_F(WasmModuleVerifyTest, WrongMagic)` 和 `TEST_F(WasmModuleVerifyTest, WrongVersion)` 测试了当 WASM 模块的魔数（magic number）或版本号错误时，解码器是否能正确识别并报错。

2. **测试 WASM 模块各个 Section 的解析:**  代码中定义了大量的宏，如 `TYPE_SECTION`, `FUNCTION_SECTION`, `GLOBAL_SECTION`, `CODE_SECTION`, `EXPORT_SECTION` 等，对应 WASM 模块的不同组成部分。测试用例针对这些 Section 的各种情况进行测试，例如：
    * **Type Section:** 测试函数签名的解析。
    * **Function Section:** 测试函数索引的解析。
    * **Global Section:** 测试全局变量的定义和初始化，包括不同类型、可变性以及初始化表达式。
    * **Code Section:** 测试函数体的解析。
    * **Export Section:** 测试导出声明的解析。
    * **Import Section:** 测试导入声明的解析。
    * **Memory Section:** 测试内存定义的解析。
    * **Table Section:** 测试表定义的解析。
    * **Element Section:** 测试元素段的解析，用于初始化表的元素。
    * **Data Section:** 测试数据段的解析，用于初始化内存。
    * **Name Section:** 测试名称段的解析，包含模块、函数、局部变量等的名称。
    * **Custom Section:** 测试未知或自定义 Section 的处理。

3. **测试全局变量的初始化表达式:**  测试全局变量的初始值是否能正确解析，包括常量值、对其他全局变量的引用等。例如 `TEST_F(WasmModuleVerifyTest, GlobalInitializer)` 就详细测试了各种全局变量初始化表达式的合法性和错误情况。

4. **测试不同数据类型的支持:**  测试解码器是否能正确处理 WASM 定义的各种数据类型，如 `i32`, `i64`, `f32`, `f64`, `funcref`, `externref`, `eqref`, `structref`, `arrayref` 等。

5. **测试错误处理:**  通过 `EXPECT_FAILURE` 和 `EXPECT_FAILURE_WITH_MSG` 等宏，测试解码器在遇到格式错误、数据越界、类型不匹配等情况时是否能正确识别并报告错误信息。

6. **测试 WASM 的各种特性支持:** 例如 `TEST_F(WasmModuleVerifyTest, S128Global)` 测试了 SIMD 指令的支持。

7. **模糊测试 (通过宏和多种输入):**  虽然这个文件看起来是单元测试，但通过大量的宏定义和不同的输入数据，也隐含有一些模糊测试的思想，尝试用各种各样的 WASM 结构来检验解码器的健壮性。

**v8/test/unittests/wasm/module-decoder-unittest.cc 是否以 `.tq` 结尾？**

根据您提供的信息，文件名是 `module-decoder-unittest.cc`，以 `.cc` 结尾，这表示它是 **C++ 源代码**文件，而不是 V8 Torque 源代码文件（Torque 文件以 `.tq` 结尾）。

**与 JavaScript 的功能关系：**

WebAssembly 旨在在 Web 浏览器中提供接近原生性能的执行能力。V8 是 Chrome 和 Node.js 使用的 JavaScript 引擎，它负责解析、编译和执行 JavaScript 代码。当浏览器或 Node.js 加载一个 WASM 模块时，V8 的 WASM 模块解码器（`module-decoder-unittest.cc` 所测试的组件）会将 WASM 二进制代码解析成 V8 内部可以理解的结构，以便后续的编译和执行。

**JavaScript 示例说明:**

```javascript
// 假设有一个名为 'my_module.wasm' 的 WASM 文件

fetch('my_module.wasm')
  .then(response => response.arrayBuffer())
  .then(bytes => WebAssembly.instantiate(bytes))
  .then(results => {
    const instance = results.instance;
    // 调用 WASM 模块导出的函数
    console.log(instance.exports.add(5, 3));
  });
```

在这个 JavaScript 示例中，`WebAssembly.instantiate(bytes)` 函数的内部就会使用类似 `module-decoder-unittest.cc` 所测试的解码器来解析 `my_module.wasm` 的二进制数据。如果 WASM 文件格式错误，解码器将会报错，导致 `WebAssembly.instantiate` 抛出异常。

**代码逻辑推理 (假设输入与输出):**

**假设输入 (针对 `TEST_F(WasmModuleVerifyTest, OneGlobal)`)：**

```c++
static const uint8_t data[] = {
    SECTION(Global,                     // --
            ENTRY_COUNT(1),             // --
            kI32Code,                   // local type
            0,                          // immutable
            WASM_INIT_EXPR_I32V_1(13))  // init
};
```

这个 `data` 数组表示一个 WASM 模块片段，包含一个 Global Section。这个 Global Section 定义了一个不可变的（immutable）`i32` 类型的全局变量，其初始值为 13。

**预期输出：**

解码器应该成功解析这个 Global Section，并在内部表示中创建一个 `WasmGlobal` 对象，其属性如下：

* `type`: `kWasmI32`
* `offset`: 0 (假设是第一个全局变量)
* `mutability`: `false`
* `initializer`: 包含将常量值 13 压入栈的操作

**涉及用户常见的编程错误 (在 WASM 代码生成阶段):**

这个测试文件主要关注 WASM 解码器本身，而不是用户直接编写的 JavaScript 代码。但是，这些测试覆盖了 WASM 代码生成器（例如 Emscripten 或其他 WASM 编译器）可能产生的常见错误，例如：

1. **魔数或版本号错误:** WASM 文件头部的魔数和版本号必须正确，否则解码器会拒绝解析。
2. **Section 顺序错误或缺失:** WASM 模块的 Section 必须按照规范的顺序排列，某些 Section 是必需的。
3. **类型不匹配:**  例如，全局变量的初始化表达式的类型与全局变量声明的类型不一致。 `TEST_F(WasmModuleVerifyTest, GlobalInitializer)` 中就包含了很多这类测试。
4. **索引越界:**  例如，在 `Element` Section 或 `Code` Section 中引用了不存在的函数或全局变量索引。 `TEST_F(WasmModuleVerifyTest, InvalidFuncRefGlobal)` 就是一个例子。
5. **常量表达式错误:** 全局变量的初始化表达式必须是常量表达式，不能包含一些动态操作。
6. **数据编码错误:**  例如，使用错误的 VarInt 编码。

**归纳一下它的功能 (第 1 部分):**

`v8/test/unittests/wasm/module-decoder-unittest.cc` (第 1 部分) 的主要功能是**对 V8 JavaScript 引擎中 WebAssembly 模块解码器的核心功能进行单元测试**。 它通过构造各种合法的和非法的 WASM 模块片段，并断言解码器的行为是否符合预期，来验证解码器能否正确地解析 WASM 的基本结构（模块头、各种 Section）和内容（类型定义、函数签名、全局变量、初始化表达式等），并有效地处理各种错误情况。 这个部分主要关注了 WASM 模块的基础结构和全局变量的定义。

Prompt: 
```
这是目录为v8/test/unittests/wasm/module-decoder-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/wasm/module-decoder-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/module-decoder.h"

#include "src/wasm/branch-hint-map.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-features.h"
#include "src/wasm/wasm-limits.h"
#include "src/wasm/wasm-opcodes.h"
#include "test/common/wasm/flag-utils.h"
#include "test/common/wasm/wasm-macro-gen.h"
#include "test/unittests/test-utils.h"
#include "testing/gmock-support.h"

using testing::HasSubstr;

namespace v8 {
namespace internal {
namespace wasm {
namespace module_decoder_unittest {

#define WASM_INIT_EXPR_I32V_1(val) WASM_I32V_1(val), kExprEnd
#define WASM_INIT_EXPR_I32V_2(val) WASM_I32V_2(val), kExprEnd
#define WASM_INIT_EXPR_I32V_3(val) WASM_I32V_3(val), kExprEnd
#define WASM_INIT_EXPR_I32V_4(val) WASM_I32V_4(val), kExprEnd
#define WASM_INIT_EXPR_I32V_5(val) WASM_I32V_5(val), kExprEnd
#define WASM_INIT_EXPR_F32(val) WASM_F32(val), kExprEnd
#define WASM_INIT_EXPR_I64(val) WASM_I64(val), kExprEnd
#define WASM_INIT_EXPR_F64(val) WASM_F64(val), kExprEnd
#define WASM_INIT_EXPR_EXTERN_REF_NULL WASM_REF_NULL(kExternRefCode), kExprEnd
#define WASM_INIT_EXPR_FUNC_REF_NULL WASM_REF_NULL(kFuncRefCode), kExprEnd
#define WASM_INIT_EXPR_REF_FUNC(val) WASM_REF_FUNC(val), kExprEnd
#define WASM_INIT_EXPR_GLOBAL(index) WASM_GLOBAL_GET(index), kExprEnd
#define WASM_INIT_EXPR_STRUCT_NEW(index, ...) \
  WASM_STRUCT_NEW(index, __VA_ARGS__), kExprEnd
#define WASM_INIT_EXPR_ARRAY_NEW_FIXED(index, length, ...) \
  WASM_ARRAY_NEW_FIXED(index, length, __VA_ARGS__), kExprEnd

#define REF_NULL_ELEMENT kExprRefNull, kFuncRefCode, kExprEnd
#define REF_FUNC_ELEMENT(v) kExprRefFunc, U32V_1(v), kExprEnd

#define EMPTY_BODY 0
#define NOP_BODY 2, 0, kExprNop

#define SIG_ENTRY_i_i SIG_ENTRY_x_x(kI32Code, kI32Code)

#define UNKNOWN_SECTION(size) 0, U32V_1(size + 5), ADD_COUNT('l', 'u', 'l', 'z')
#define TYPE_SECTION(count, ...) SECTION(Type, U32V_1(count), __VA_ARGS__)
#define FUNCTION_SECTION(count, ...) \
  SECTION(Function, U32V_1(count), __VA_ARGS__)

#define FOO_STRING ADD_COUNT('f', 'o', 'o')
#define NO_LOCAL_NAMES 0

#define EMPTY_TYPE_SECTION SECTION(Type, ENTRY_COUNT(0))
#define EMPTY_FUNCTION_SECTION SECTION(Function, ENTRY_COUNT(0))
#define EMPTY_FUNCTION_BODIES_SECTION SECTION(Code, ENTRY_COUNT(0))
#define SECTION_NAMES(...) \
  SECTION(Unknown, ADD_COUNT('n', 'a', 'm', 'e'), ##__VA_ARGS__)
#define EMPTY_NAMES_SECTION SECTION_NAMES()
#define SECTION_SRC_MAP(...)                                               \
  SECTION(Unknown,                                                         \
          ADD_COUNT('s', 'o', 'u', 'r', 'c', 'e', 'M', 'a', 'p', 'p', 'i', \
                    'n', 'g', 'U', 'R', 'L'),                              \
          ADD_COUNT(__VA_ARGS__))
#define SECTION_COMPILATION_HINTS(...)                                     \
  SECTION(Unknown,                                                         \
          ADD_COUNT('c', 'o', 'm', 'p', 'i', 'l', 'a', 't', 'i', 'o', 'n', \
                    'H', 'i', 'n', 't', 's'),                              \
          ADD_COUNT(__VA_ARGS__))

#define SECTION_BRANCH_HINTS(...)                                          \
  SECTION(Unknown,                                                         \
          ADD_COUNT('m', 'e', 't', 'a', 'd', 'a', 't', 'a', '.', 'c', 'o', \
                    'd', 'e', '.', 'b', 'r', 'a', 'n', 'c', 'h', '_', 'h', \
                    'i', 'n', 't'),                                        \
          __VA_ARGS__)

#define X1(...) __VA_ARGS__
#define X2(...) __VA_ARGS__, __VA_ARGS__
#define X3(...) __VA_ARGS__, __VA_ARGS__, __VA_ARGS__
#define X4(...) __VA_ARGS__, __VA_ARGS__, __VA_ARGS__, __VA_ARGS__

#define ONE_EMPTY_FUNCTION(sig_index) \
  SECTION(Function, ENTRY_COUNT(1), X1(sig_index))

#define TWO_EMPTY_FUNCTIONS(sig_index) \
  SECTION(Function, ENTRY_COUNT(2), X2(sig_index))

#define THREE_EMPTY_FUNCTIONS(sig_index) \
  SECTION(Function, ENTRY_COUNT(3), X3(sig_index))

#define FOUR_EMPTY_FUNCTIONS(sig_index) \
  SECTION(Function, ENTRY_COUNT(4), X4(sig_index))

#define ONE_EMPTY_BODY SECTION(Code, ENTRY_COUNT(1), X1(EMPTY_BODY))
#define TWO_EMPTY_BODIES SECTION(Code, ENTRY_COUNT(2), X2(EMPTY_BODY))
#define THREE_EMPTY_BODIES SECTION(Code, ENTRY_COUNT(3), X3(EMPTY_BODY))
#define FOUR_EMPTY_BODIES SECTION(Code, ENTRY_COUNT(4), X4(EMPTY_BODY))

#define TYPE_SECTION_ONE_SIG_VOID_VOID \
  SECTION(Type, ENTRY_COUNT(1), SIG_ENTRY_v_v)

#define LINEAR_MEMORY_INDEX_0 0

#define EXCEPTION_ENTRY(sig_index) U32V_1(kExceptionAttribute), sig_index

#define FIELD_COUNT(count) U32V_1(count)
#define STRUCT_FIELD(type, mutability) type, (mutability ? 1 : 0)
#define WASM_REF(index) kRefCode, index
#define WASM_OPT_REF(index) kRefNullCode, index
#define WASM_STRUCT_DEF(...) kWasmStructTypeCode, __VA_ARGS__
#define WASM_ARRAY_DEF(type, mutability) \
  kWasmArrayTypeCode, type, (mutability ? 1 : 0)
#define WASM_FUNCTION_DEF(...) kWasmFunctionTypeCode, __VA_ARGS__

#define EXPECT_VERIFIES(data)                                     \
  do {                                                            \
    ModuleResult _result = DecodeModule(base::ArrayVector(data)); \
    EXPECT_OK(_result);                                           \
  } while (false)

#define EXPECT_FAILURE_LEN(data, length)                               \
  do {                                                                 \
    ModuleResult _result = DecodeModule(base::VectorOf(data, length)); \
    EXPECT_FALSE(_result.ok());                                        \
  } while (false)

#define EXPECT_FAILURE(data) EXPECT_FAILURE_LEN(data, sizeof(data))

#define EXPECT_FAILURE_WITH_MSG(data, msg)                        \
  do {                                                            \
    ModuleResult _result = DecodeModule(base::ArrayVector(data)); \
    EXPECT_FALSE(_result.ok());                                   \
    if (!_result.ok()) {                                          \
      EXPECT_THAT(_result.error().message(), HasSubstr(msg));     \
    }                                                             \
  } while (false)

#define EXPECT_OFF_END_FAILURE(data, min)                              \
  do {                                                                 \
    static_assert(min < arraysize(data));                              \
    for (size_t _length = min; _length < arraysize(data); _length++) { \
      EXPECT_FAILURE_LEN(data, _length);                               \
    }                                                                  \
  } while (false)

#define EXPECT_OK(result)                                        \
  do {                                                           \
    if (!result.ok()) {                                          \
      GTEST_NONFATAL_FAILURE_(result.error().message().c_str()); \
      return;                                                    \
    }                                                            \
  } while (false)

#define EXPECT_NOT_OK(result, msg)                           \
  do {                                                       \
    EXPECT_FALSE(result.ok());                               \
    if (!result.ok()) {                                      \
      EXPECT_THAT(result.error().message(), HasSubstr(msg)); \
    }                                                        \
  } while (false)

using Idx = ModuleTypeIndex;

static size_t SizeOfVarInt(size_t value) {
  size_t size = 0;
  do {
    size++;
    value = value >> 7;
  } while (value > 0);
  return size;
}

struct ValueTypePair {
  uint8_t code;
  ValueType type;
} kValueTypes[] = {
    {kI32Code, kWasmI32},                          // --
    {kI64Code, kWasmI64},                          // --
    {kF32Code, kWasmF32},                          // --
    {kF64Code, kWasmF64},                          // --
    {kFuncRefCode, kWasmFuncRef},                  // --
    {kNoFuncCode, kWasmNullFuncRef},               // --
    {kExternRefCode, kWasmExternRef},              // --
    {kNoExternCode, kWasmNullExternRef},           // --
    {kNoExnCode, kWasmNullExnRef},                 // --
    {kAnyRefCode, kWasmAnyRef},                    // --
    {kEqRefCode, kWasmEqRef},                      // --
    {kI31RefCode, kWasmI31Ref},                    // --
    {kStructRefCode, kWasmStructRef},              // --
    {kArrayRefCode, kWasmArrayRef},                // --
    {kNoneCode, kWasmNullRef},                     // --
    {kStringRefCode, kWasmStringRef},              // --
    {kStringViewWtf8Code, kWasmStringViewWtf8},    // --
    {kStringViewWtf16Code, kWasmStringViewWtf16},  // --
    {kStringViewIterCode, kWasmStringViewIter},    // --
};

class WasmModuleVerifyTest : public TestWithIsolateAndZone {
 public:
  WasmEnabledFeatures enabled_features_ = WasmEnabledFeatures::None();

  ModuleResult DecodeModule(base::Vector<const uint8_t> module_bytes) {
    // Add the wasm magic and version number automatically.
    size_t size = module_bytes.size();
    uint8_t header[] = {WASM_MODULE_HEADER};
    size_t total = sizeof(header) + size;
    auto temp = new uint8_t[total];
    memcpy(temp, header, sizeof(header));
    if (size > 0) {
      memcpy(temp + sizeof(header), module_bytes.begin(), size);
    }
    WasmDetectedFeatures unused_detected_features;
    ModuleResult result =
        DecodeWasmModule(enabled_features_, base::VectorOf(temp, total), false,
                         kWasmOrigin, &unused_detected_features);
    delete[] temp;
    return result;
  }
  ModuleResult DecodeModuleNoHeader(base::Vector<const uint8_t> bytes) {
    WasmDetectedFeatures unused_detected_features;
    return DecodeWasmModule(enabled_features_, bytes, false, kWasmOrigin,
                            &unused_detected_features);
  }
};

TEST_F(WasmModuleVerifyTest, WrongMagic) {
  for (uint32_t x = 1; x; x <<= 1) {
    const uint8_t data[] = {U32_LE(kWasmMagic ^ x), U32_LE(kWasmVersion)};
    ModuleResult result = DecodeModuleNoHeader(base::ArrayVector(data));
    EXPECT_FALSE(result.ok());
  }
}

TEST_F(WasmModuleVerifyTest, WrongVersion) {
  for (uint32_t x = 1; x; x <<= 1) {
    const uint8_t data[] = {U32_LE(kWasmMagic), U32_LE(kWasmVersion ^ x)};
    ModuleResult result = DecodeModuleNoHeader(base::ArrayVector(data));
    EXPECT_FALSE(result.ok());
  }
}

TEST_F(WasmModuleVerifyTest, WrongSection) {
  constexpr uint8_t kInvalidSection = 0x1c;
  const uint8_t data[] = {kInvalidSection, 0};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_FALSE(result.ok());
}

TEST_F(WasmModuleVerifyTest, DecodeEmpty) {
  ModuleResult result = DecodeModule(base::VectorOf<uint8_t>(nullptr, 0));
  EXPECT_TRUE(result.ok());
}

TEST_F(WasmModuleVerifyTest, OneGlobal) {
  static const uint8_t data[] = {
      SECTION(Global,                     // --
              ENTRY_COUNT(1),             // --
              kI32Code,                   // local type
              0,                          // immutable
              WASM_INIT_EXPR_I32V_1(13))  // init
  };

  {
    // Should decode to exactly one global.
    ModuleResult result = DecodeModule(base::ArrayVector(data));
    EXPECT_OK(result);
    EXPECT_EQ(1u, result.value()->globals.size());
    EXPECT_EQ(0u, result.value()->functions.size());
    EXPECT_EQ(0u, result.value()->data_segments.size());

    const WasmGlobal* global = &result.value()->globals.back();

    EXPECT_EQ(kWasmI32, global->type);
    EXPECT_EQ(0u, global->offset);
    EXPECT_FALSE(global->mutability);
  }

  EXPECT_OFF_END_FAILURE(data, 1);
}

TEST_F(WasmModuleVerifyTest, S128Global) {
  std::array<uint8_t, kSimd128Size> v = {1, 2,  3,  4,  5,  6,  7, 8,
                                         9, 10, 11, 12, 13, 14, 15};
  static const uint8_t data[] = {SECTION(Global,          // --
                                         ENTRY_COUNT(1),  // --
                                         kS128Code,       // memory type
                                         0,               // immutable
                                         WASM_SIMD_CONSTANT(v.data()),
                                         kExprEnd)};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  if (!CheckHardwareSupportsSimd()) {
    EXPECT_NOT_OK(result, "Wasm SIMD unsupported");
  } else {
    EXPECT_OK(result);
    const WasmGlobal* global = &result.value()->globals.back();
    EXPECT_EQ(kWasmS128, global->type);
    EXPECT_EQ(0u, global->offset);
    EXPECT_FALSE(global->mutability);
  }
}

TEST_F(WasmModuleVerifyTest, ExternRefGlobal) {
  static const uint8_t data[] = {
      // sig#0 ---------------------------------------------------------------
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      // funcs ---------------------------------------------------------------
      TWO_EMPTY_FUNCTIONS(SIG_INDEX(0)),
      SECTION(Global,                          // --
              ENTRY_COUNT(2),                  // --
              kExternRefCode,                  // local type
              0,                               // immutable
              WASM_INIT_EXPR_EXTERN_REF_NULL,  // init
              kFuncRefCode,                    // local type
              0,                               // immutable
              WASM_INIT_EXPR_REF_FUNC(1)),     // init
      SECTION(Element,                         // section name
              ENTRY_COUNT(2),                  // entry count
              DECLARATIVE,                     // flags 0
              kExternalFunction,               // type
              ENTRY_COUNT(1),                  // func entry count
              FUNC_INDEX(0),                   // func index
              DECLARATIVE_WITH_ELEMENTS,       // flags 1
              kFuncRefCode,                    // local type
              ENTRY_COUNT(1),                  // func ref count
              REF_FUNC_ELEMENT(1)),            // func ref
      TWO_EMPTY_BODIES};

  {
    // Should decode to two globals.
    ModuleResult result = DecodeModule(base::ArrayVector(data));
    EXPECT_OK(result);
    EXPECT_EQ(2u, result.value()->globals.size());
    EXPECT_EQ(2u, result.value()->functions.size());
    EXPECT_EQ(0u, result.value()->data_segments.size());

    const WasmGlobal* global = &result.value()->globals[0];
    EXPECT_EQ(kWasmExternRef, global->type);
    EXPECT_FALSE(global->mutability);

    global = &result.value()->globals[1];
    EXPECT_EQ(kWasmFuncRef, global->type);
    EXPECT_FALSE(global->mutability);
  }
}

TEST_F(WasmModuleVerifyTest, FuncRefGlobal) {
  static const uint8_t data[] = {
      // sig#0 ---------------------------------------------------------------
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      // funcs ---------------------------------------------------------------
      TWO_EMPTY_FUNCTIONS(SIG_INDEX(0)),
      SECTION(Global,                        // --
              ENTRY_COUNT(2),                // --
              kFuncRefCode,                  // local type
              0,                             // immutable
              WASM_INIT_EXPR_FUNC_REF_NULL,  // init
              kFuncRefCode,                  // local type
              0,                             // immutable
              WASM_INIT_EXPR_REF_FUNC(1)),   // init
      SECTION(Element,                       // section name
              ENTRY_COUNT(2),                // entry count
              DECLARATIVE,                   // flags 0
              kExternalFunction,             // type
              ENTRY_COUNT(1),                // func entry count
              FUNC_INDEX(0),                 // func index
              DECLARATIVE_WITH_ELEMENTS,     // flags 1
              kFuncRefCode,                  // local type
              ENTRY_COUNT(1),                // func ref count
              REF_FUNC_ELEMENT(1)),          // func ref
      TWO_EMPTY_BODIES};
  {
    // Should decode to two globals.
    ModuleResult result = DecodeModule(base::ArrayVector(data));
    EXPECT_OK(result);
    EXPECT_EQ(2u, result.value()->globals.size());
    EXPECT_EQ(2u, result.value()->functions.size());
    EXPECT_EQ(0u, result.value()->data_segments.size());

    const WasmGlobal* global = &result.value()->globals[0];
    EXPECT_EQ(kWasmFuncRef, global->type);
    EXPECT_FALSE(global->mutability);

    global = &result.value()->globals[1];
    EXPECT_EQ(kWasmFuncRef, global->type);
    EXPECT_FALSE(global->mutability);
  }
}

TEST_F(WasmModuleVerifyTest, InvalidFuncRefGlobal) {
  static const uint8_t data[] = {
      // sig#0 ---------------------------------------------------------------
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      // funcs ---------------------------------------------------------------
      TWO_EMPTY_FUNCTIONS(SIG_INDEX(0)),
      SECTION(Global,                       // --
              ENTRY_COUNT(1),               // --
              kFuncRefCode,                 // local type
              0,                            // immutable
              WASM_INIT_EXPR_REF_FUNC(7)),  // invalid function index
      TWO_EMPTY_BODIES};
  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, ExternRefGlobalWithGlobalInit) {
  static const uint8_t data[] = {
      SECTION(Import,           // --
              ENTRY_COUNT(1),   // number of imports
              ADD_COUNT('m'),   // module name
              ADD_COUNT('f'),   // global name
              kExternalGlobal,  // import kind
              kExternRefCode,   // type
              0),               // mutability
      SECTION(Global,           // --
              ENTRY_COUNT(1),
              kExternRefCode,  // local type
              0,               // immutable
              WASM_INIT_EXPR_GLOBAL(0)),
  };

  {
    // Should decode to exactly one global.
    ModuleResult result = DecodeModule(base::ArrayVector(data));
    EXPECT_OK(result);
    EXPECT_EQ(2u, result.value()->globals.size());
    EXPECT_EQ(0u, result.value()->functions.size());
    EXPECT_EQ(0u, result.value()->data_segments.size());

    const WasmGlobal* global = &result.value()->globals.back();

    EXPECT_EQ(kWasmExternRef, global->type);
    EXPECT_FALSE(global->mutability);
  }
}

TEST_F(WasmModuleVerifyTest, NullGlobalWithGlobalInit) {
  static const uint8_t data[] = {
      SECTION(Import,           // --
              ENTRY_COUNT(1),   // number of imports
              ADD_COUNT('m'),   // module name
              ADD_COUNT('n'),   // global name
              kExternalGlobal,  // import kind
              kExternRefCode,   // type
              0),               // mutability
      SECTION(Global,           // --
              ENTRY_COUNT(1),
              kExternRefCode,  // local type
              0,               // immutable
              WASM_INIT_EXPR_GLOBAL(0)),
  };

  {
    // Should decode to exactly one global.
    ModuleResult result = DecodeModule(base::ArrayVector(data));
    std::cout << result.error().message() << std::endl;
    EXPECT_OK(result);
    EXPECT_EQ(2u, result.value()->globals.size());
    EXPECT_EQ(0u, result.value()->functions.size());
    EXPECT_EQ(0u, result.value()->data_segments.size());

    const WasmGlobal* global = &result.value()->globals.back();

    EXPECT_EQ(kWasmExternRef, global->type);
    EXPECT_FALSE(global->mutability);
  }
}

TEST_F(WasmModuleVerifyTest, GlobalInvalidType) {
  static const uint8_t data[] = {
      SECTION(Global,                      // --
              ENTRY_COUNT(1),              // --
              64,                          // invalid value type
              1,                           // mutable
              WASM_INIT_EXPR_I32V_1(33)),  // init
  };

  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, GlobalInvalidType2) {
  static const uint8_t data[] = {
      SECTION(Global,                      // --
              ENTRY_COUNT(1),              // --
              kVoidCode,                   // invalid value type
              1,                           // mutable
              WASM_INIT_EXPR_I32V_1(33)),  // init
  };

  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, GlobalInitializer) {
  static const uint8_t no_initializer_no_end[] = {
      SECTION(Global,          //--
              ENTRY_COUNT(1),  //--
              kI32Code,        // type
              1)               // mutable
  };
  EXPECT_FAILURE_WITH_MSG(no_initializer_no_end, "Beyond end of code");

  static const uint8_t no_initializer[] = {
      SECTION(Global,          //--
              ENTRY_COUNT(1),  //--
              kI32Code,        // type
              1,               // mutable
              kExprEnd)        // --
  };
  EXPECT_FAILURE_WITH_MSG(
      no_initializer,
      "expected 1 elements on the stack for constant expression, found 0");

  static const uint8_t too_many_initializers_no_end[] = {
      SECTION(Global,           // --
              ENTRY_COUNT(1),   // --
              kI32Code,         // type
              1,                // mutable
              WASM_I32V_1(42),  // one value is good
              WASM_I32V_1(43))  // another value is too much
  };
  EXPECT_FAILURE_WITH_MSG(too_many_initializers_no_end,
                          "constant expression is missing 'end'");

  static const uint8_t too_many_initializers[] = {
      SECTION(Global,           // --
              ENTRY_COUNT(1),   // --
              kI32Code,         // type
              1,                // mutable
              WASM_I32V_1(42),  // one value is good
              WASM_I32V_1(43),  // another value is too much
              kExprEnd)};
  EXPECT_FAILURE_WITH_MSG(
      too_many_initializers,
      "expected 1 elements on the stack for constant expression, found 2");

  static const uint8_t missing_end_opcode[] = {
      SECTION(Global,           // --
              ENTRY_COUNT(1),   // --
              kI32Code,         // type
              1,                // mutable
              WASM_I32V_1(42))  // init value
  };
  EXPECT_FAILURE_WITH_MSG(missing_end_opcode,
                          "constant expression is missing 'end'");

  static const uint8_t referencing_out_of_bounds_global[] = {
      SECTION(Global, ENTRY_COUNT(1),         // --
              kI32Code,                       // type
              1,                              // mutable
              WASM_GLOBAL_GET(42), kExprEnd)  // init value
  };
  EXPECT_FAILURE_WITH_MSG(referencing_out_of_bounds_global,
                          "Invalid global index: 42");

  static const uint8_t referencing_undefined_global[] = {
      SECTION(Global, ENTRY_COUNT(2),        // --
              kI32Code,                      // type
              0,                             // mutable
              WASM_GLOBAL_GET(1), kExprEnd,  // init value
              kI32Code,                      // type
              0,                             // mutable
              WASM_I32V(0), kExprEnd)        // init value
  };
  EXPECT_FAILURE_WITH_MSG(referencing_undefined_global,
                          "Invalid global index: 1");

  {
    static const uint8_t referencing_undefined_global_nested[] = {
        SECTION(Type, ENTRY_COUNT(1), WASM_ARRAY_DEF(kI32Code, true)),
        SECTION(Global, ENTRY_COUNT(2),                      // --
                kRefCode, 0,                                 // type
                0,                                           // mutable
                WASM_ARRAY_NEW_DEFAULT(0,                    // init value
                                       WASM_GLOBAL_GET(1)),  // --
                kExprEnd,                                    // --
                kI32Code,                                    // type
                0,                                           // mutable
                WASM_I32V(10), kExprEnd)                     // init value
    };
    EXPECT_FAILURE_WITH_MSG(referencing_undefined_global_nested,
                            "Invalid global index: 1");
  }

  static const uint8_t referencing_mutable_global[] = {
      SECTION(Global, ENTRY_COUNT(2),        // --
              kI32Code,                      // type
              1,                             // mutable
              WASM_I32V(1), kExprEnd,        // init value
              kI32Code,                      // type
              0,                             // mutable
              WASM_GLOBAL_GET(0), kExprEnd)  // init value
  };
  EXPECT_FAILURE_WITH_MSG(
      referencing_mutable_global,
      "mutable globals cannot be used in constant expressions");

  static const uint8_t referencing_mutable_imported_global[] = {
      SECTION(Import, ENTRY_COUNT(1),          // --
              ADD_COUNT('m'), ADD_COUNT('n'),  // module, name
              kExternalGlobal,                 // --
              kI32Code,                        // type
              1),                              // mutable
      SECTION(Global, ENTRY_COUNT(1),          // --
              kI32Code,                        // type
              0,                               // mutable
              WASM_GLOBAL_GET(0), kExprEnd)    // init value
  };
  EXPECT_FAILURE_WITH_MSG(
      referencing_mutable_imported_global,
      "mutable globals cannot be used in constant expressions");

  static const uint8_t referencing_immutable_imported_global[] = {
      SECTION(Import, ENTRY_COUNT(1),          // --
              ADD_COUNT('m'), ADD_COUNT('n'),  // module, name
              kExternalGlobal,                 // --
              kI32Code,                        // type
              0),                              // mutable
      SECTION(Global, ENTRY_COUNT(1),          // --
              kI32Code,                        // type
              0,                               // mutable
              WASM_GLOBAL_GET(0), kExprEnd)    // init value
  };
  EXPECT_VERIFIES(referencing_immutable_imported_global);

  static const uint8_t referencing_local_global[] = {
      SECTION(Global, ENTRY_COUNT(2),        // --
              kI32Code,                      // type
              0,                             // mutable
              WASM_I32V(1), kExprEnd,        // init value
              kI32Code,                      // type
              0,                             // mutable
              WASM_GLOBAL_GET(0), kExprEnd)  // init value
  };
  EXPECT_VERIFIES(referencing_local_global);
}

TEST_F(WasmModuleVerifyTest, ZeroGlobals) {
  static const uint8_t data[] = {SECTION(Global, ENTRY_COUNT(0))};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);
}

TEST_F(WasmModuleVerifyTest, ExportMutableGlobal) {
  {
    static const uint8_t data[] = {
        SECTION(Global,                         // --
                ENTRY_COUNT(1),                 // --
                kI32Code,                       // local type
                0,                              // immutable
                WASM_INIT_EXPR_I32V_1(13)),     // init
        SECTION(Export,                         // --
                ENTRY_COUNT(1),                 // export count
                ADD_COUNT('n', 'a', 'm', 'e'),  // name
                kExternalGlobal,                // global
                0),                             // global index
    };
    EXPECT_VERIFIES(data);
  }
  {
    static const uint8_t data[] = {
        SECTION(Global,                         // --
                ENTRY_COUNT(1),                 // --
                kI32Code,                       // local type
                1,                              // mutable
                WASM_INIT_EXPR_I32V_1(13)),     // init
        SECTION(Export,                         // --
                ENTRY_COUNT(1),                 // export count
                ADD_COUNT('n', 'a', 'm', 'e'),  // name
                kExternalGlobal,                // global
                0),                             // global index
    };
    EXPECT_VERIFIES(data);
  }
}

static void AppendUint32v(std::vector<uint8_t>* buffer, uint32_t val) {
  while (true) {
    uint32_t next = val >> 7;
    uint32_t out = val & 0x7F;
    if (next) {
      buffer->push_back(static_cast<uint8_t>(0x80 | out));
      val = next;
    } else {
      buffer->push_back(static_cast<uint8_t>(out));
      break;
    }
  }
}

TEST_F(WasmModuleVerifyTest, NGlobals) {
  static const uint8_t data[] = {
      kF32Code,                 // memory type
      0,                        // immutable
      WASM_INIT_EXPR_F32(7.7),  // init
  };

  for (uint32_t i = 0; i < kV8MaxWasmGlobals; i = i * 13 + 1) {
    std::vector<uint8_t> buffer;
    size_t size = SizeOfVarInt(i) + i * sizeof(data);
    const uint8_t globals[] = {kGlobalSectionCode, U32V_5(size)};
    for (size_t g = 0; g != sizeof(globals); ++g) {
      buffer.push_back(globals[g]);
    }
    AppendUint32v(&buffer, i);  // Number of globals.
    for (uint32_t j = 0; j < i; j++) {
      buffer.insert(buffer.end(), data, data + sizeof(data));
    }

    ModuleResult result = DecodeModule(base::VectorOf(buffer));
    EXPECT_OK(result);
  }
}

TEST_F(WasmModuleVerifyTest, TwoGlobals) {
  static const uint8_t data[] = {SECTION(Global,                    // --
                                         ENTRY_COUNT(2),            // --
                                         kF32Code,                  // type
                                         0,                         // immutable
                                         WASM_INIT_EXPR_F32(22.0),  // --
                                         kF64Code,                  // type
                                         1,                         // mutable
                                         WASM_INIT_EXPR_F64(23.0))};  // --

  {
    // Should decode to exactly two globals.
    ModuleResult result = DecodeModule(base::ArrayVector(data));
    EXPECT_OK(result);
    EXPECT_EQ(2u, result.value()->globals.size());
    EXPECT_EQ(0u, result.value()->functions.size());
    EXPECT_EQ(0u, result.value()->data_segments.size());

    const WasmGlobal* g0 = &result.value()->globals[0];

    EXPECT_EQ(kWasmF32, g0->type);
    EXPECT_EQ(0u, g0->offset);
    EXPECT_FALSE(g0->mutability);

    const WasmGlobal* g1 = &result.value()->globals[1];

    EXPECT_EQ(kWasmF64, g1->type);
    EXPECT_EQ(8u, g1->offset);
    EXPECT_TRUE(g1->mutability);
  }

  EXPECT_OFF_END_FAILURE(data, 1);
}

TEST_F(WasmModuleVerifyTest, RefNullGlobal) {
  static const uint8_t data[] = {SECTION(Global, ENTRY_COUNT(1), kFuncRefCode,
                                         1, WASM_REF_NULL(kFuncRefCode),
                                         kExprEnd)};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);
}

TEST_F(WasmModuleVerifyTest, RefNullGlobalInvalid1) {
  static const uint8_t data[] = {SECTION(Global, ENTRY_COUNT(1), kRefNullCode,
                                         0, 1, WASM_REF_NULL(0), kExprEnd)};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_NOT_OK(result, "Type index 0 is out of bounds");
}

TEST_F(WasmModuleVerifyTest, RefNullGlobalInvalid2) {
  static const uint8_t data[] = {SECTION(Global, ENTRY_COUNT(1), kFuncRefCode,
                                         1, kExprRefNull, U32V_5(1000001),
                                         kExprEnd)};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_NOT_OK(result,
                "Type index 1000001 is greater than the maximum number 1000000 "
                "of type definitions supported by V8");
}

TEST_F(WasmModuleVerifyTest, StructNewInitExpr) {
  static const uint8_t basic[] = {
      SECTION(Type, ENTRY_COUNT(1),  // --
              WASM_STRUCT_DEF(FIELD_COUNT(1), STRUCT_FIELD(kI32Code, true))),
      SECTION(Global, ENTRY_COUNT(1),  // --
              kRefCode, 0, 0,          // type, mutability
              WASM_INIT_EXPR_STRUCT_NEW(0, WASM_I32V(42)))};
  EXPECT_VERIFIES(basic);

  static const uint8_t global_args[] = {
      SECTION(Type, ENTRY_COUNT(1),  // --
              WASM_STRUCT_DEF(FIELD_COUNT(1), STRUCT_FIELD(kI32Code, true))),
      SECTION(Global, ENTRY_COUNT(2),     // --
              kI32Code, 0,                // type, mutability
              WASM_INIT_EXPR_I32V_1(10),  // --
              kRefCode, 0, 0,             // type, mutability
              WASM_INIT_EXPR_STRUCT_NEW(0, WASM_GLOBAL_GET(0)))};
  EXPECT_VERIFIES(global_args);

  static const uint8_t type_error[] = {
      SECTION(Type, ENTRY_COUNT(2),  // --
              WASM_STRUCT_DEF(FIELD_COUNT(1), STRUCT_FIELD(kI32Code, true)),
              WASM_STRUCT_DEF(FIELD_COUNT
"""


```