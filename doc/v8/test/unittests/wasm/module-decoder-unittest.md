Response: The user wants me to summarize the functionality of the C++ source code file provided. This is the first part of a three-part file.

The provided code is a unit test file for the `ModuleDecoder` in the V8 JavaScript engine's WebAssembly implementation. It defines various helper macros and test cases to verify the correct behavior of the module decoder when parsing different WebAssembly module structures and sections.

Here's a breakdown of the key elements:

1. **Includes:**  It includes necessary headers from the V8 project (`module-decoder.h`, `wasm-engine.h`, etc.) and Google Test framework.
2. **Namespaces:**  It operates within nested namespaces: `v8::internal::wasm::module_decoder_unittest`.
3. **Helper Macros:** A significant portion of the code defines macros to simplify the creation of byte sequences representing WebAssembly module sections (e.g., `TYPE_SECTION`, `FUNCTION_SECTION`, `GLOBAL_SECTION`). These macros handle the structure of sections, including the section code, size, and content. There are also macros for defining initializers for globals (`WASM_INIT_EXPR_*`), function signatures (`SIG_ENTRY_*`), and element expressions (`REF_NULL_ELEMENT`, `REF_FUNC_ELEMENT`).
4. **Test Fixture:**  A test fixture `WasmModuleVerifyTest` is defined, inheriting from `TestWithIsolateAndZone`. This provides a setup for running tests within a V8 isolate. It has a `DecodeModule` method to decode raw byte arrays into a `ModuleResult`.
5. **Basic Magic and Version Tests:** It starts with basic tests to check for correct WebAssembly magic numbers and version.
6. **Section Validation Tests:**  Several tests check for invalid section codes.
7. **Global Section Tests:** A large number of tests focus on validating the decoding of the global section, covering:
    *   Single and multiple globals.
    *   Different global types (i32, f32, f64, s128, externref, funcref).
    *   Global initialization expressions (constants, `ref.null`, `ref.func`, `global.get`, `struct.new`, `array.new_fixed`).
    *   Invalid global types and initializers.
    *   Exporting mutable globals.
8. **Type Section Tests:** Tests for decoding type definitions, including function signatures, struct definitions, array definitions, and recursive type groups. It also tests canonicalization of type IDs.
9. **Data Section Tests:** Tests for decoding data segments, including:
    *   Single and multiple data segments.
    *   Data segment initialization with global variables (both imported and local, checking for mutability restrictions).
    *   Data segments without a memory section.
    *   Invalid memory limits.
    *   Data segment overflow.
10. **Table Section Tests:**  Basic tests related to tables, including indirect functions and element sections with and without tables.
11. **Exception (Tag) Section Tests:** Tests for decoding exception tags, including:
    *   Single and multiple exceptions.
    *   Invalid signature indices and return types for exceptions.
    *   Invalid exception attributes.
    *   Correct placement of the tag section.
    *   Importing and exporting tags.

Essentially, this part of the unit test file thoroughly examines the `ModuleDecoder`'s ability to correctly parse the initial sections of a WebAssembly module (up to the table/element sections), paying close attention to the validity of the data and structure within these sections. It uses a pattern of defining a byte array representing a module section and then asserting whether the `DecodeModule` function succeeds or fails, and in case of failure, checking for specific error messages.
这是 `v8/test/unittests/wasm/module-decoder-unittest.cc` 文件的第一部分，它的主要功能是**测试 WebAssembly 模块解码器 (ModuleDecoder) 的正确性**。

更具体地说，这部分代码通过定义一系列单元测试用例来验证 `ModuleDecoder` 在解析 WebAssembly 模块的各种结构和部分时的行为，包括但不限于：

*   **模块头部 (Magic Number 和 Version)：** 验证解码器是否能正确识别和拒绝错误的 Magic Number 和 Version。
*   **段 (Sections)：** 测试解码器是否能正确处理不同类型的段 (如 Type, Global, Data, Table, Element, Tag 等)，以及处理无效的段。
*   **全局变量 (Globals)：**  详细测试了全局变量的定义和初始化：
    *   各种全局变量的类型 (i32, i64, f32, f64, s128, externref, funcref)。
    *   全局变量的初始化表达式 (常量、`ref.null`、`ref.func`、`global.get`、`struct.new`、`array.new_fixed`)。
    *   无效的全局变量类型和初始化表达式。
    *   导出可变全局变量。
*   **类型 (Types)：** 测试了函数签名、结构体定义、数组定义以及递归类型组的解码。还包括了类型 ID 的规范化测试。
*   **数据段 (Data Segments)：** 测试了数据段的定义和初始化：
    *   使用全局变量作为初始化表达式（包括导入的和本地的，并检查了可变性限制）。
    *   没有内存段的情况下定义数据段。
    *   无效的内存大小限制。
    *   数据段初始化表达式的类型错误。
    *   数据段溢出。
*   **表 (Tables)：** 简单的测试用例，涉及到间接函数调用和元素段与表的交互。
*   **异常 (Tags)：** 测试了异常标签的定义和属性：
    *   合法的异常标签定义。
    *   无效的签名索引和返回类型。
    *   无效的属性。
    *   异常段的正确位置。
    *   导入和导出异常标签。

**总而言之，这第一部分的代码主要关注于验证 `ModuleDecoder` 能否正确解析 WebAssembly 模块的基本结构和数据定义部分，并且能够识别和报告各种错误情况。**  它使用了一系列辅助宏来简化测试用例的编写，并使用了 Google Test 框架来进行断言和验证。  由于这是第一部分，可以推断后续部分会测试模块解码器的其他方面，例如函数定义、代码段等。

### 提示词
```这是目录为v8/test/unittests/wasm/module-decoder-unittest.cc的一个c++源代码文件， 请归纳一下它的功能
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