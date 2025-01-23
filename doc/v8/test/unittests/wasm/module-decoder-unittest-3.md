Response: The user is providing a C++ source code file, which is part of the V8 JavaScript engine, specifically related to WebAssembly.
The file is named `module-decoder-unittest.cc` and located in the `v8/test/unittests/wasm/` directory.
The user wants a summary of the file's functionality.
Since the file name includes "unittest" and "module-decoder", it's likely that this file contains unit tests for the WebAssembly module decoder.

Plan:
1. Read through the code to identify the main purpose.
2. Summarize the functionality based on the code's content and file name.
3. Determine if there's a connection to JavaScript functionality.
4. If there is a connection, provide a JavaScript example.
这是针对 V8 JavaScript 引擎中 WebAssembly 模块解码器的单元测试文件。它的主要功能是测试 `src/wasm/module-decoder.h` 中定义的模块解码器的各种场景，以确保解码器能够正确地解析和验证 WebAssembly 模块的二进制格式。

具体来说，这个文件包含了一系列的测试用例，用于验证以下方面：

* **模块头部的解析:** 验证魔数和版本号是否正确。
* **不同 Section 的解码:**  测试各种 WebAssembly section 的解码，例如 Type、Function、Global、Memory、Data、Table、Element、Export、Import 和 Tag 等。
* **数据类型的解析:** 验证不同 WebAssembly 数据类型（如 i32, i64, f32, f64, ref 等）的正确解析。
* **初始化表达式的解析:**  测试全局变量和数据段的初始化表达式是否能被正确解析和验证。
* **错误处理:**  测试解码器在遇到无效或格式错误的 WebAssembly 模块时是否能够正确地报告错误。
* **边界情况测试:**  测试各种边界情况，例如空的 Section，超出限制的值等。
* **特性支持:** 验证特定 WebAssembly 特性（例如 SIMD、引用类型、异常处理等）的解码。
* **类型系统的验证:** 测试类型定义、递归类型、子类型等的正确性。

**与 JavaScript 的功能关系以及 JavaScript 示例:**

WebAssembly 模块最终会在 JavaScript 环境中运行。`module-decoder-unittest.cc` 中测试的模块解码器是 V8 引擎将 WebAssembly 二进制代码转换为 JavaScript 可以理解和执行的内部表示的关键组件。

当你在 JavaScript 中加载一个 WebAssembly 模块时，V8 引擎会使用这个解码器来解析模块的二进制数据。如果解码器出现错误，那么 WebAssembly 模块将无法正确加载或执行。

**JavaScript 示例:**

```javascript
// 一个简单的 WebAssembly 模块的二进制表示 (WAT 格式的等价物：(module (func (export "add") (param i32 i32) (result i32) local.get 0 local.get 1 i32.add)))
const wasmBinary = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, // 魔数
  0x01, 0x00, 0x00, 0x00, // 版本
  0x01, 0x07,             // Type section (7 bytes)
  0x01,                   // Number of type entries
  0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f, // Function type: (i32, i32) => i32
  0x03, 0x02,             // Function section (2 bytes)
  0x01,                   // Number of function declarations
  0x00,                   // Type index (指向上面定义的函数类型)
  0x07, 0x07,             // Export section (7 bytes)
  0x01,                   // Number of exports
  0x03, 0x61, 0x64, 0x64, // Export name: "add"
  0x00,                   // Export kind: function
  0x00,                   // Function index
  0x0a, 0x09,             // Code section (9 bytes)
  0x01,                   // Number of function bodies
  0x07,                   // Body size
  0x00,                   // Number of local declarations
  0x20, 0x00,             // local.get 0
  0x20, 0x01,             // local.get 1
  0x6a,                   // i32.add
  0x0b                    // end
]);

WebAssembly.instantiate(wasmBinary)
  .then(result => {
    const addFunction = result.instance.exports.add;
    console.log(addFunction(5, 3)); // 输出 8
  })
  .catch(error => {
    console.error("Failed to instantiate WebAssembly module:", error);
  });
```

在这个例子中，`WebAssembly.instantiate(wasmBinary)` 函数接收 `wasmBinary` (一个 `Uint8Array`，代表 WebAssembly 模块的二进制数据)。V8 引擎内部的模块解码器（这个单元测试文件正在测试的组件）会解析 `wasmBinary` 的内容，验证其格式是否正确，并将其转换为可以执行的 WebAssembly 模块实例。如果 `wasmBinary` 的格式不正确，解码器会抛出错误，导致 `WebAssembly.instantiate` 的 Promise 被 reject。

`module-decoder-unittest.cc` 中的各种测试用例模拟了各种可能的 `wasmBinary` 的格式，包括正确的和错误的，以确保解码器在各种情况下都能正常工作。

### 提示词
```这是目录为v8/test/unittests/wasm/module-decoder-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```
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
              WASM_STRUCT_DEF(FIELD_COUNT(1), STRUCT_FIELD(kI64Code, true))),
      SECTION(Global, ENTRY_COUNT(1),  // --
              kRefCode, 1, 0,          // type, mutability
              WASM_INIT_EXPR_STRUCT_NEW(0, WASM_I32V(42)))};
  EXPECT_FAILURE_WITH_MSG(
      type_error,
      "type error in constant expression[0] (expected (ref 1), got (ref 0))");
}

TEST_F(WasmModuleVerifyTest, ArrayNewFixedInitExpr) {
  static const uint8_t basic[] = {
      SECTION(Type, ENTRY_COUNT(1), WASM_ARRAY_DEF(kI16Code, true)),
      SECTION(Global, ENTRY_COUNT(1),  // --
              kRefCode, 0, 0,          // type, mutability
              WASM_INIT_EXPR_ARRAY_NEW_FIXED(0, 3, WASM_I32V(10), WASM_I32V(20),
                                             WASM_I32V(30)))};
  EXPECT_VERIFIES(basic);

  static const uint8_t basic_static[] = {
      SECTION(Type, ENTRY_COUNT(1), WASM_ARRAY_DEF(kI16Code, true)),
      SECTION(Global, ENTRY_COUNT(1),  // --
              kRefCode, 0, 0,          // type, mutability
              WASM_INIT_EXPR_ARRAY_NEW_FIXED(0, 3, WASM_I32V(10), WASM_I32V(20),
                                             WASM_I32V(30)))};
  EXPECT_VERIFIES(basic_static);

  static const uint8_t basic_immutable[] = {
      SECTION(Type, ENTRY_COUNT(1), WASM_ARRAY_DEF(kI32Code, false)),
      SECTION(Global, ENTRY_COUNT(1),  // --
              kRefCode, 0, 0,          // type, mutability
              WASM_INIT_EXPR_ARRAY_NEW_FIXED(0, 3, WASM_I32V(10), WASM_I32V(20),
                                             WASM_I32V(30)))};
  EXPECT_VERIFIES(basic_immutable);

  static const uint8_t type_error[] = {
      SECTION(Type, ENTRY_COUNT(2),  // --
              WASM_ARRAY_DEF(kI32Code, true),
              WASM_ARRAY_DEF(WASM_SEQ(kRefCode, 0), true)),
      SECTION(Global, ENTRY_COUNT(1),  // --
              kRefCode, 1, 0,          // type, mutability
              WASM_INIT_EXPR_ARRAY_NEW_FIXED(0, 1, WASM_I32V(42)))};
  EXPECT_FAILURE_WITH_MSG(
      type_error,
      "type error in constant expression[0] (expected (ref 1), got (ref 0))");

  static const uint8_t subexpr_type_error[] = {
      SECTION(Type, ENTRY_COUNT(1), WASM_ARRAY_DEF(kI64Code, true)),
      SECTION(
          Global, ENTRY_COUNT(1),  // --
          kRefCode, 0, 0,          // type, mutability
          WASM_INIT_EXPR_ARRAY_NEW_FIXED(0, 2, WASM_I64V(42), WASM_I32V(142)))};
  EXPECT_FAILURE_WITH_MSG(subexpr_type_error,
                          "array.new_fixed[1] expected type i64, found "
                          "i32.const of type i32");

  static const uint8_t length_error[] = {
      SECTION(Type, ENTRY_COUNT(1), WASM_ARRAY_DEF(kI16Code, true)),
      SECTION(Global, ENTRY_COUNT(1),  // --
              kRefCode, 0, 0,          // type, mutability
              WASM_INIT_EXPR_ARRAY_NEW_FIXED(0, 10, WASM_I32V(10),
                                             WASM_I32V(20), WASM_I32V(30)))};
  EXPECT_FAILURE_WITH_MSG(length_error,
                          "not enough arguments on the stack for "
                          "array.new_fixed (need 10, got 3)");
}

TEST_F(WasmModuleVerifyTest, EmptyStruct) {
  static const uint8_t empty_struct[] = {SECTION(Type, ENTRY_COUNT(1),  // --
                                                 kWasmStructTypeCode,   // --
                                                 U32V_1(0))};  // field count

  EXPECT_VERIFIES(empty_struct);
}

TEST_F(WasmModuleVerifyTest, InvalidStructTypeDef) {
  static const uint8_t all_good[] = {
      SECTION(Type, ENTRY_COUNT(1),  // --
              kWasmStructTypeCode,   // --
              U32V_1(1),             // field count
              kI32Code,              // perfectly valid field type
              1)};                   // mutability
  EXPECT_VERIFIES(all_good);

  static const uint8_t invalid_field_type[] = {
      SECTION(Type, ENTRY_COUNT(1),  // --
              kWasmStructTypeCode,   // --
              U32V_1(1),             // field count
              kWasmArrayTypeCode,    // bogus field type
              1)};                   // mutability
  EXPECT_FAILURE_WITH_MSG(invalid_field_type, "invalid value type");

  static const uint8_t field_type_oob_ref[] = {
      SECTION(Type, ENTRY_COUNT(1),  // --
              kWasmStructTypeCode,   // --
              U32V_1(1),             // field count
              kRefNullCode,          // field type: reference...
              3,                     // ...to nonexistent type
              1)};                   // mutability
  EXPECT_FAILURE_WITH_MSG(field_type_oob_ref, "Type index 3 is out of bounds");

  static const uint8_t field_type_invalid_ref[] = {
      SECTION(Type, ENTRY_COUNT(1),  // --
              kWasmStructTypeCode,   // --
              U32V_1(1),             // field count
              kRefNullCode,          // field type: reference...
              U32V_4(1234567),       // ...to a type > kV8MaxWasmTypes
              1)};                   // mutability
  EXPECT_FAILURE_WITH_MSG(field_type_invalid_ref, "greater than the maximum");

  static const uint8_t field_type_invalid_ref2[] = {
      SECTION(Type, ENTRY_COUNT(1),  // --
              kWasmStructTypeCode,   // --
              U32V_1(1),             // field count
              kRefNullCode,          // field type: reference...
              kI32Code,              // ...to a non-referenceable type
              1)};                   // mutability
  EXPECT_FAILURE_WITH_MSG(field_type_invalid_ref2, "Unknown heap type");

  static const uint8_t not_enough_field_types[] = {
      SECTION(Type, ENTRY_COUNT(1),  // --
              kWasmStructTypeCode,   // --
              U32V_1(2),             // field count
              kI32Code,              // field type 1
              1)};                   // mutability 1
  EXPECT_FAILURE_WITH_MSG(not_enough_field_types, "expected 1 byte");

  static const uint8_t not_enough_field_types2[] = {
      SECTION(Type, ENTRY_COUNT(1),  // --
              kWasmStructTypeCode,   // --
              U32V_1(2),             // field count
              kI32Code,              // field type 1
              1,                     // mutability 1
              kI32Code)};            // field type 2
  EXPECT_FAILURE_WITH_MSG(not_enough_field_types2, "expected 1 byte");

  static const uint8_t invalid_mutability[] = {
      SECTION(Type, ENTRY_COUNT(1),  // --
              kWasmStructTypeCode,   // --
              U32V_1(1),             // field count
              kI32Code,              // field type
              2)};                   // invalid mutability value
  EXPECT_FAILURE_WITH_MSG(invalid_mutability, "invalid mutability");
}

TEST_F(WasmModuleVerifyTest, InvalidArrayTypeDef) {
  static const uint8_t all_good[] = {
      SECTION(Type, ENTRY_COUNT(1),  // --
              kWasmArrayTypeCode,    // --
              kI32Code,              // perfectly valid field type
              1)};                   // mutability
  EXPECT_VERIFIES(all_good);

  static const uint8_t invalid_field_type[] = {
      SECTION(Type, ENTRY_COUNT(1),  // --
              kWasmArrayTypeCode,    // --
              kWasmArrayTypeCode,    // bogus field type
              1)};                   // mutability
  EXPECT_FAILURE_WITH_MSG(invalid_field_type, "invalid value type");

  static const uint8_t field_type_oob_ref[] = {
      SECTION(Type, ENTRY_COUNT(1),  // --
              kWasmArrayTypeCode,    // --
              kRefNullCode,          // field type: reference...
              3,                     // ...to nonexistent type
              1)};                   // mutability
  EXPECT_FAILURE_WITH_MSG(field_type_oob_ref, "Type index 3 is out of bounds");

  static const uint8_t field_type_invalid_ref[] = {
      SECTION(Type, ENTRY_COUNT(1),  // --
              kWasmArrayTypeCode,    // --
              kRefNullCode,          // field type: reference...
              U32V_3(1234567),       // ...to a type > kV8MaxWasmTypes
              1)};                   // mutability
  EXPECT_FAILURE_WITH_MSG(field_type_invalid_ref, "Unknown heap type");

  static const uint8_t field_type_invalid_ref2[] = {
      SECTION(Type, ENTRY_COUNT(1),  // --
              kWasmArrayTypeCode,    // --
              kRefNullCode,          // field type: reference...
              kI32Code,              // ...to a non-referenceable type
              1)};                   // mutability
  EXPECT_FAILURE_WITH_MSG(field_type_invalid_ref2, "Unknown heap type");

  static const uint8_t invalid_mutability[] = {
      SECTION(Type, ENTRY_COUNT(1),  // --
              kWasmArrayTypeCode,    // --
              kI32Code,              // field type
              2)};                   // invalid mutability value
  EXPECT_FAILURE_WITH_MSG(invalid_mutability, "invalid mutability");

  static const uint8_t immutable[] = {SECTION(Type,
                                              ENTRY_COUNT(1),      // --
                                              kWasmArrayTypeCode,  // --
                                              kI32Code,            // field type
                                              0)};  // immmutability
  EXPECT_VERIFIES(immutable);
}

TEST_F(WasmModuleVerifyTest, TypeCanonicalization) {
  static const uint8_t identical_group[] = {
      SECTION(Type,            // --
              ENTRY_COUNT(2),  // two identical rec. groups
              kWasmRecursiveTypeGroupCode, ENTRY_COUNT(1),  // --
              kWasmArrayTypeCode, kI32Code, 0,              // --
              kWasmRecursiveTypeGroupCode, ENTRY_COUNT(1),  // --
              kWasmArrayTypeCode, kI32Code, 0),
      SECTION(Global,                          // --
              ENTRY_COUNT(1), kRefCode, 0, 0,  // Type, mutability
              WASM_ARRAY_NEW_FIXED(1, 1, WASM_I32V(10)),
              kExprEnd)  // initial value
  };

  // Global initializer should verify as identical type in other group
  EXPECT_VERIFIES(identical_group);

  static const uint8_t non_identical_group[] = {
      SECTION(Type,            // --
              ENTRY_COUNT(2),  // two distrinct rec. groups
              kWasmRecursiveTypeGroupCode, ENTRY_COUNT(1),  // --
              kWasmArrayTypeCode, kI32Code, 0,              // --
              kWasmRecursiveTypeGroupCode, ENTRY_COUNT(2),  // --
              kWasmArrayTypeCode, kI32Code, 0,              // --
              kWasmStructTypeCode, ENTRY_COUNT(0)),
      SECTION(Global,                          // --
              ENTRY_COUNT(1), kRefCode, 0, 0,  // Type, mutability
              WASM_ARRAY_NEW_FIXED(1, 1, WASM_I32V(10)),
              kExprEnd)  // initial value
  };

  // Global initializer should not verify as type in distinct rec. group.
  EXPECT_FAILURE_WITH_MSG(
      non_identical_group,
      "type error in constant expression[0] (expected (ref 0), got (ref 1))");

  static const uint8_t empty_group[] = {
      SECTION(Type,            // --
              ENTRY_COUNT(1),  // one rec. group
              kWasmRecursiveTypeGroupCode, ENTRY_COUNT(0))};

  EXPECT_VERIFIES(empty_group);

  static const uint8_t mixed_empty_and_nonempty_groups[] = {SECTION(
      Type,                                         // --
      ENTRY_COUNT(4),                               // one rec. group
      kWasmRecursiveTypeGroupCode, ENTRY_COUNT(0),  // empty
      SIG_ENTRY_v_v,                                // one type
      kWasmRecursiveTypeGroupCode, ENTRY_COUNT(0),  // empty
      SIG_ENTRY_v_v                                 // one type
      )};

  EXPECT_VERIFIES(mixed_empty_and_nonempty_groups);
}

// Tests that all types in a rec. group are checked for supertype validity.
TEST_F(WasmModuleVerifyTest, InvalidSupertypeInRecGroup) {
  static const uint8_t invalid_supertype[] = {
      SECTION(Type, ENTRY_COUNT(1),                         // --
              kWasmRecursiveTypeGroupCode, ENTRY_COUNT(2),  // --
              kWasmSubtypeCode, 0,              // 0 supertypes, non-final
              kWasmArrayTypeCode, kI32Code, 0,  // --
              kWasmSubtypeCode, 1, 0,           // supertype count, supertype
              kWasmArrayTypeCode, kI64Code, 0)};

  EXPECT_FAILURE_WITH_MSG(invalid_supertype,
                          "type 1 has invalid explicit supertype 0");
}

// Tests supertype declaration with 0 supertypes.
TEST_F(WasmModuleVerifyTest, SuperTypeDeclarationWith0Supertypes) {
  static const uint8_t zero_supertypes[] = {
      SECTION(Type, ENTRY_COUNT(1),  // --
              kWasmSubtypeCode, 0,   // supertype count
              kWasmArrayTypeCode, kI32Code, 0)};

  EXPECT_VERIFIES(zero_supertypes);
}

TEST_F(WasmModuleVerifyTest, NoSupertypeSupertype) {
  static const uint8_t no_supertype[] = {
      SECTION(Type, ENTRY_COUNT(1),          // --
              kWasmSubtypeCode, 1,           // supertype count
              0xff, 0xff, 0xff, 0xff, 0x0f,  // supertype = "kNoSuperType"
              kWasmArrayTypeCode, kI32Code, 0)};

  EXPECT_FAILURE_WITH_MSG(no_supertype, "type 0: invalid supertype 4294967295");
}

TEST_F(WasmModuleVerifyTest, NonSpecifiedFinalType) {
  static const uint8_t final_supertype[] = {
      SECTION(Type, ENTRY_COUNT(2),                 // --
              kWasmStructTypeCode, 1, kI32Code, 1,  // --
              kWasmSubtypeCode, 1, 0,               // --
              kWasmStructTypeCode, 2, kI32Code, 1, kI32Code, 1)};
  EXPECT_FAILURE_WITH_MSG(final_supertype, "type 1 extends final type 0");
}

TEST_F(WasmModuleVerifyTest, SpecifiedFinalType) {
  static const uint8_t final_supertype[] = {
      SECTION(Type, ENTRY_COUNT(2),                 // --
              kWasmSubtypeFinalCode, 0,             // --
              kWasmStructTypeCode, 1, kI32Code, 1,  // --
              kWasmSubtypeCode, 1, 0,               // --
              kWasmStructTypeCode, 2, kI32Code, 1, kI32Code, 1)};
  EXPECT_FAILURE_WITH_MSG(final_supertype, "type 1 extends final type 0");
}

TEST_F(WasmModuleVerifyTest, ZeroExceptions) {
  static const uint8_t data[] = {SECTION(Tag, ENTRY_COUNT(0))};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);
  EXPECT_EQ(0u, result.value()->tags.size());
}

TEST_F(WasmModuleVerifyTest, OneI32Exception) {
  static const uint8_t data[] = {
      SECTION(Type, ENTRY_COUNT(1), SIG_ENTRY_v_x(kI32Code)),  // sig#0 (i32)
      SECTION(Tag, ENTRY_COUNT(1),
              EXCEPTION_ENTRY(SIG_INDEX(0)))};  // except[0] (sig#0)
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);
  EXPECT_EQ(1u, result.value()->tags.size());

  const WasmTag& e0 = result.value()->tags.front();
  EXPECT_EQ(1u, e0.sig->parameter_count());
  EXPECT_EQ(kWasmI32, e0.sig->GetParam(0));
}

TEST_F(WasmModuleVerifyTest, TwoExceptions) {
  static const uint8_t data[] = {
      SECTION(Type, ENTRY_COUNT(2),
              SIG_ENTRY_v_x(kI32Code),              // sig#0 (i32)
              SIG_ENTRY_v_xx(kF32Code, kI64Code)),  // sig#1 (f32, i64)
      SECTION(Tag, ENTRY_COUNT(2),
              EXCEPTION_ENTRY(SIG_INDEX(1)),    // except[0] (sig#1)
              EXCEPTION_ENTRY(SIG_INDEX(0)))};  // except[1] (sig#0)
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);
  EXPECT_EQ(2u, result.value()->tags.size());
  const WasmTag& e0 = result.value()->tags.front();
  EXPECT_EQ(2u, e0.sig->parameter_count());
  EXPECT_EQ(kWasmF32, e0.sig->GetParam(0));
  EXPECT_EQ(kWasmI64, e0.sig->GetParam(1));
  const WasmTag& e1 = result.value()->tags.back();
  EXPECT_EQ(kWasmI32, e1.sig->GetParam(0));
}

TEST_F(WasmModuleVerifyTest, Exception_invalid_sig_index) {
  static const uint8_t data[] = {
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      SECTION(Tag, ENTRY_COUNT(1),
              EXCEPTION_ENTRY(
                  SIG_INDEX(23)))};  // except[0] (sig#23 [out-of-bounds])
  // Should fail decoding exception section.
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_NOT_OK(result, "no signature at index 23 (1 types)");
}

TEST_F(WasmModuleVerifyTest, Exception_invalid_sig_return) {
  static const uint8_t data[] = {
      SECTION(Type, ENTRY_COUNT(1), SIG_ENTRY_i_i),
      SECTION(Tag, ENTRY_COUNT(1),
              EXCEPTION_ENTRY(
                  SIG_INDEX(0)))};  // except[0] (sig#0 [invalid-return-type])
  // Should fail decoding exception section.
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_NOT_OK(result, "tag signature 0 has non-void return");
}

TEST_F(WasmModuleVerifyTest, Exception_invalid_attribute) {
  static const uint8_t data[] = {
      SECTION(Type, ENTRY_COUNT(1), SIG_ENTRY_i_i),
      SECTION(Tag, ENTRY_COUNT(1), 23,
              SIG_INDEX(0))};  // except[0] (sig#0) [invalid-attribute]
  // Should fail decoding exception section.
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_NOT_OK(result, "exception attribute 23 not supported");
}

TEST_F(WasmModuleVerifyTest, TagSectionCorrectPlacement) {
  static const uint8_t data[] = {SECTION(Memory, ENTRY_COUNT(0)),
                                 SECTION(Tag, ENTRY_COUNT(0)),
                                 SECTION(Global, ENTRY_COUNT(0))};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);
}

TEST_F(WasmModuleVerifyTest, TagSectionAfterGlobal) {
  static const uint8_t data[] = {SECTION(Global, ENTRY_COUNT(0)),
                                 SECTION(Tag, ENTRY_COUNT(0))};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_NOT_OK(result,
                "The Tag section must appear before the Global section");
}

TEST_F(WasmModuleVerifyTest, TagSectionBeforeMemory) {
  static const uint8_t data[] = {SECTION(Tag, ENTRY_COUNT(0)),
                                 SECTION(Memory, ENTRY_COUNT(0))};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_NOT_OK(result, "unexpected section <Memory>");
}

TEST_F(WasmModuleVerifyTest, TagSectionAfterTableBeforeMemory) {
  static_assert(kMemorySectionCode + 1 == kGlobalSectionCode);
  static const uint8_t data[] = {SECTION(Table, ENTRY_COUNT(0)),
                                 SECTION(Tag, ENTRY_COUNT(0)),
                                 SECTION(Memory, ENTRY_COUNT(0))};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_NOT_OK(result, "unexpected section <Memory>");
}

TEST_F(WasmModuleVerifyTest, TagImport) {
  static const uint8_t data[] = {
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      SECTION(Import,                           // section header
              ENTRY_COUNT(1),                   // number of imports
              ADD_COUNT('m'),                   // module name
              ADD_COUNT('e', 'x'),              // tag name
              kExternalTag,                     // import kind
              EXCEPTION_ENTRY(SIG_INDEX(0)))};  // except[0] (sig#0)
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);
  EXPECT_EQ(1u, result.value()->tags.size());
  EXPECT_EQ(1u, result.value()->import_table.size());
}

TEST_F(WasmModuleVerifyTest, ExceptionExport) {
  static const uint8_t data[] = {
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      SECTION(Tag, ENTRY_COUNT(1),
              EXCEPTION_ENTRY(SIG_INDEX(0))),  // except[0] (sig#0)
      SECTION(Export, ENTRY_COUNT(1),          // --
              NO_NAME,                         // --
              kExternalTag,                    // --
              EXCEPTION_INDEX(0))};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);
  EXPECT_EQ(1u, result.value()->tags.size());
  EXPECT_EQ(1u, result.value()->export_table.size());
}

TEST_F(WasmModuleVerifyTest, OneSignature) {
  {
    static const uint8_t data[] = {TYPE_SECTION_ONE_SIG_VOID_VOID};
    EXPECT_VERIFIES(data);
  }

  {
    static const uint8_t data[] = {
        SECTION(Type, ENTRY_COUNT(1), SIG_ENTRY_i_i)};
    EXPECT_VERIFIES(data);
  }
}

TEST_F(WasmModuleVerifyTest, MultipleSignatures) {
  static const uint8_t data[] = {
      SECTION(Type,                                           // --
              ENTRY_COUNT(3),                                 // --
              SIG_ENTRY_v_v,                                  // void -> void
              SIG_ENTRY_x_x(kI32Code, kF32Code),              // f32 -> i32
              SIG_ENTRY_x_xx(kI32Code, kF64Code, kF64Code)),  // f64,f64 -> i32
  };

  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);
  EXPECT_EQ(3u, result.value()->types.size());
  if (result.value()->types.size() == 3) {
    EXPECT_EQ(0u, result.value()->signature(Idx{0})->return_count());
    EXPECT_EQ(1u, result.value()->signature(Idx{1})->return_count());
    EXPECT_EQ(1u, result.value()->signature(Idx{2})->return_count());

    EXPECT_EQ(0u, result.value()->signature(Idx{0})->parameter_count());
    EXPECT_EQ(1u, result.value()->signature(Idx{1})->parameter_count());
    EXPECT_EQ(2u, result.value()->signature(Idx{2})->parameter_count());
  }

  EXPECT_OFF_END_FAILURE(data, 1);
}

TEST_F(WasmModuleVerifyTest, CanonicalTypeIds) {
  static const uint8_t data[] = {
      SECTION(Type,                               // --
              ENTRY_COUNT(7),                     // --
              WASM_STRUCT_DEF(                    // Struct definition
                  FIELD_COUNT(1),                 // --
                  STRUCT_FIELD(kI32Code, true)),  // --
              SIG_ENTRY_x_x(kI32Code, kF32Code),  // f32 -> i32
              SIG_ENTRY_x_x(kI32Code, kF64Code),  // f64 -> i32
              SIG_ENTRY_x_x(kI32Code, kF32Code),  // f32 -> i32 (again)
              WASM_ARRAY_DEF(kI32Code, true),     // Array definition
              kWasmRecursiveTypeGroupCode, ENTRY_COUNT(1),
              WASM_ARRAY_DEF(kI16Code, true),  // Predefined i16 array
              kWasmRecursiveTypeGroupCode, ENTRY_COUNT(1),
              WASM_ARRAY_DEF(kI8Code, true))  // Predefined i8 array
  };

  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);
  const WasmModule* module = result.value().get();

  EXPECT_EQ(7u, module->types.size());
  EXPECT_EQ(7u, module->isorecursive_canonical_type_ids.size());

  static constexpr uint32_t kBase = TypeCanonicalizer::kNumberOfPredefinedTypes;
  EXPECT_EQ(kBase + 0u, module->isorecursive_canonical_type_ids[0].index);
  EXPECT_EQ(kBase + 1u, module->isorecursive_canonical_type_ids[1].index);
  EXPECT_EQ(kBase + 2u, module->isorecursive_canonical_type_ids[2].index);
  EXPECT_EQ(kBase + 1u, module->isorecursive_canonical_type_ids[3].index);
  EXPECT_EQ(kBase + 3u, module->isorecursive_canonical_type_ids[4].index);

  EXPECT_EQ(TypeCanonicalizer::kPredefinedArrayI16Index,
            module->isorecursive_canonical_type_ids[5]);
  EXPECT_EQ(TypeCanonicalizer::kPredefinedArrayI8Index,
            module->isorecursive_canonical_type_ids[6]);
}

TEST_F(WasmModuleVerifyTest, DataSegmentWithImmutableImportedGlobal) {
  // Import 2 globals so that we can initialize data with a global index != 0.
  const uint8_t data[] = {
      SECTION(Import,           // section header
              ENTRY_COUNT(2),   // number of imports
              ADD_COUNT('m'),   // module name
              ADD_COUNT('f'),   // global name
              kExternalGlobal,  // import kind
              kI32Code,         // type
              0,                // mutability
              ADD_COUNT('n'),   // module name
              ADD_COUNT('g'),   // global name
              kExternalGlobal,  // import kind
              kI32Code,         // type
              0),               // mutability
      SECTION(Memory, ENTRY_COUNT(1), kWithMaximum, 28, 28),
      SECTION(Data, ENTRY_COUNT(1), LINEAR_MEMORY_INDEX_0,
              WASM_INIT_EXPR_GLOBAL(1),  // dest addr
              U32V_1(3),                 // source size
              'a', 'b', 'c')             // data bytes
  };
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);
}

TEST_F(WasmModuleVerifyTest, DataSegmentWithMutableImportedGlobal) {
  // Only an immutable global can be used as an init_expr.
  const uint8_t data[] = {
      SECTION(Import,           // section header
              ENTRY_COUNT(1),   // number of imports
              ADD_COUNT('m'),   // module name
              ADD_COUNT('f'),   // global name
              kExternalGlobal,  // import kind
              kI32Code,         // type
              1),               // mutability
      SECTION(Memory, ENTRY_COUNT(1), kWithMaximum, 28, 28),
      SECTION(Data, ENTRY_COUNT(1), LINEAR_MEMORY_INDEX_0,
              WASM_INIT_EXPR_GLOBAL(0),  // dest addr
              U32V_1(3),                 // source size
              'a', 'b', 'c')             // data bytes
  };
  EXPECT_FAILURE(data);
}
TEST_F(WasmModuleVerifyTest, DataSegmentWithImmutableGlobal) {
  // An immutable global can be used in an init_expr.
  const uint8_t data[] = {
      SECTION(Memory, ENTRY_COUNT(1), kWithMaximum, 28, 28),
      SECTION(Global, ENTRY_COUNT(1),
              kI32Code,                         // local type
              0,                                // immutable
              WASM_INIT_EXPR_I32V_3(0x9BBAA)),  // init
      SECTION(Data, ENTRY_COUNT(1), LINEAR_MEMORY_INDEX_0,
              WASM_INIT_EXPR_GLOBAL(0),  // dest addr
              U32V_1(3),                 // source size
              'a', 'b', 'c')             // data bytes
  };
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);
}

TEST_F(WasmModuleVerifyTest, OneDataSegment) {
  const uint8_t kDataSegmentSourceOffset = 24;
  const uint8_t data[] = {
      SECTION(Memory, ENTRY_COUNT(1), kWithMaximum, 28, 28),
      SECTION(Data, ENTRY_COUNT(1), LINEAR_MEMORY_INDEX_0,
              WASM_INIT_EXPR_I32V_3(0x9BBAA),  // dest addr
              U32V_1(3),                       // source size
              'a', 'b', 'c')                   // data bytes
  };

  {
    EXPECT_VERIFIES(data);
    ModuleResult result = DecodeModule(base::ArrayVector(data));
    EXPECT_OK(result);
    EXPECT_EQ(0u, result.value()->globals.size());
    EXPECT_EQ(0u, result.value()->functions.size());
    EXPECT_EQ(1u, result.value()->data_segments.size());

    const WasmDataSegment* segment = &result.value()->data_segments.back();

    EXPECT_EQ(kDataSegmentSourceOffset, segment->source.offset());
    EXPECT_EQ(3u, segment->source.length());
  }

  EXPECT_OFF_END_FAILURE(data, 14);
}

TEST_F(WasmModuleVerifyTest, TwoDataSegments) {
  const uint8_t kDataSegment0SourceOffset = 24;
  const uint8_t kDataSegment1SourceOffset = kDataSegment0SourceOffset + 11;

  const uint8_t data[] = {
      SECTION(Memory, ENTRY_COUNT(1), kWithMaximum, 28, 28),
      SECTION(Data,
              ENTRY_COUNT(2),  // segment count
              LINEAR_MEMORY_INDEX_0,
              WASM_INIT_EXPR_I32V_3(0x7FFEE),  // #0: dest addr
              U32V_1(4),                       // source size
              1, 2, 3, 4,                      // data bytes
              LINEAR_MEMORY_INDEX_0,
              WASM_INIT_EXPR_I32V_3(0x6DDCC),  // #1: dest addr
              U32V_1(10),                      // source size
              1, 2, 3, 4, 5, 6, 7, 8, 9, 10)   // data bytes
  };

  {
    ModuleResult result = DecodeModule(base::ArrayVector(data));
    EXPECT_OK(result);
    EXPECT_EQ(0u, result.value()->globals.size());
    EXPECT_EQ(0u, result.value()->functions.size());
    EXPECT_EQ(2u, result.value()->data_segments.size());

    const WasmDataSegment* s0 = &result.value()->data_segments[0];
    const WasmDataSegment* s1 = &result.value()->data_segments[1];

    EXPECT_EQ(kDataSegment0SourceOffset, s0->source.offset());
    EXPECT_EQ(4u, s0->source.length());

    EXPECT_EQ(kDataSegment1SourceOffset, s1->source.offset());
    EXPECT_EQ(10u, s1->source.length());
  }

  EXPECT_OFF_END_FAILURE(data, 14);
}

TEST_F(WasmModuleVerifyTest, DataWithoutMemory) {
  const uint8_t data[] = {
      SECTION(Data, ENTRY_COUNT(1), LINEAR_MEMORY_INDEX_0,
              WASM_INIT_EXPR_I32V_3(0x9BBAA),  // dest addr
              U32V_1(3),                       // source size
              'a', 'b', 'c')                   // data bytes
  };
  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, MaxMaximumMemorySize) {
  {
    const uint8_t data[] = {
        SECTION(Memory, ENTRY_COUNT(1), kWithMaximum, 0, U32V_3(65536))};
    EXPECT_VERIFIES(data);
  }
  {
    const uint8_t data[] = {
        SECTION(Memory, ENTRY_COUNT(1), kWithMaximum, 0, U32V_3(65537))};
    EXPECT_FAILURE(data);
  }
}

TEST_F(WasmModuleVerifyTest, InvalidMemoryLimits) {
  {
    const uint8_t kInvalidLimits = 0x15;
    const uint8_t data[] = {
        SECTION(Memory, ENTRY_COUNT(1), kInvalidLimits, 0, 10)};
    EXPECT_FAILURE_WITH_MSG(data, "invalid memory limits flags 0x15");
  }
}

TEST_F(WasmModuleVerifyTest, DataSegment_wrong_init_type) {
  const uint8_t data[] = {
      SECTION(Memory, ENTRY_COUNT(1), kWithMaximum, 28, 28),
      SECTION(Data, ENTRY_COUNT(1), LINEAR_MEMORY_INDEX_0,
              WASM_INIT_EXPR_F64(9.9),  // dest addr
              U32V_1(3),                // source size
              'a', 'b', 'c')            // data bytes
  };

  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, DataSegmentEndOverflow) {
  const uint8_t data[] = {
      SECTION(Memory,  // memory section
              ENTRY_COUNT(1), kWithMaximum, 28, 28),
      SECTION(Data,                      // data section
              ENTRY_COUNT(1),            // one entry
              LINEAR_MEMORY_INDEX_0,     // mem index
              WASM_INIT_EXPR_I32V_1(0),  // offset
              U32V_5(0xFFFFFFFF))        // size
  };

  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, OneIndirectFunction) {
  static const uint8_t data[] = {
      // sig#0 ---------------------------------------------------------------
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      // funcs ---------------------------------------------------------------
      ONE_EMPTY_FUNCTION(SIG_INDEX(0)),
      // table declaration ---------------------------------------------------
      SECTION(Table, ENTRY_COUNT(1), kFuncRefCode, kNoMaximum, 1),
      // code ----------------------------------------------------------------
      ONE_EMPTY_BODY};

  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);
  if (result.ok()) {
    EXPECT_EQ(1u, result.value()->types.size());
    EXPECT_EQ(1u, result.value()->functions.size());
    EXPECT_EQ(1u, result.value()->tables.size());
    EXPECT_EQ(1u, result.value()->tables[0].initial_size);
  }
}

TEST_F(WasmModuleVerifyTest, ElementSectionWithInternalTable) {
  static const uint8_t data[] = {
      // table ---------------------------------------------------------------
      SECTION(Table, ENTRY_COUNT(1), kFuncRefCode, kNoMaximum, 1),
      // elements ------------------------------------------------------------
      SECTION(Element, ENTRY_COUNT(0))};

  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, ElementSectionWithImportedTable) {
  static const uint8_t data[] = {
      // imports -------------------------------------------------------------
      SECTION(Import, ENTRY_COUNT(1),
              ADD_COUNT('m'),  // module name
              ADD_COUNT('t'),  // table name
              kExternalTable,  // import kind
              kFuncRefCode,    // elem_type
              kNoMaximum,      // maximum
              1),              // initial size
      // elements ------------------------------------------------------------
      SECTION(Element, ENTRY_COUNT(0))};

  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, ElementSectionWithoutTable) {
  // Test that an element section without a table causes a validation error.
  static const uint8_t data[] = {
      // elements ------------------------------------------------------------
      SECTION(Element,
              ENTRY_COUNT(1),  // entry count
              0,               // table index
              0,               // offset
              0)               // number of elements
  };

  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, Regression_735887) {
  // Test with an invalid function index in the element section.
  static const uint8_t data[] = {
      // sig#0 ---------------------------------------------------------------
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      // funcs ---------------------------------------------------------------
      ONE_EMPTY_FUNCTION(SIG_INDEX(0)),
      // table declaration ---------------------------------------------------
      SECTION(Table, ENTRY_COUNT(1), kFuncRefCode, kNoMaximum, 1),
      // elements ------------------------------------------------------------
      SECTION(Element,
              ENTRY_COUNT(1),  //
```