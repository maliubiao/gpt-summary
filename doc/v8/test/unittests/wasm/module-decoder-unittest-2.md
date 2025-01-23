Response: The user wants to understand the functionality of the C++ code provided, which is the third part of a unit test file for the WebAssembly module decoder in V8.

The code consists of a series of `TEST_F` macros, each defining a specific test case. These test cases aim to verify different aspects of the module decoder, particularly around the validity and correctness of various WebAssembly module sections and their interactions.

Let's break down the functionality based on the test names and the operations within each test:

* **Element Segments:** Several tests focus on element segments, which initialize table entries. These tests cover different kinds of element segments:
    * `PassiveElementSegmentFuncRef`: Tests a passive segment with function references.
    * `PassiveElementSegmentExternRef`: Tests a passive segment with external references.
    * `PassiveElementSegmentWithIndices`: Tests a passive segment with explicit function indices.
    * `DeclarativeElementSegmentFuncRef`: Tests a declarative segment with function references.
    * `DeclarativeElementSegmentWithInvalidIndex`: Tests a declarative segment with an out-of-bounds function index, expecting a failure.

* **Data Count Section:**  A set of tests verifies the placement and correctness of the data count section, which specifies the number of data segments:
    * `DataCountSectionCorrectPlacement`: Checks that the data count section can appear between element and code sections.
    * `DataCountSectionAfterCode`: Checks for failure when the data count section appears after the code section.
    * `DataCountSectionBeforeElement`: Checks for failure when the data count section appears before the element section.
    * `DataCountSectionAfterStartBeforeElement`: Checks for failure when the data count section appears after the start section but before the element section.
    * `MultipleDataCountSections`: Checks for failure when there are multiple data count sections.
    * `DataCountSegmentCountMatch`: Checks for success when the data count matches the number of data segments.
    * `DataCountSegmentCount_greater`: Checks for failure when the data count is greater than the number of data segments.
    * `DataCountSegmentCount_less`: Checks for failure when the data count is less than the number of data segments.
    * `DataCountSegmentCount_omitted`: Checks for failure when the data count section is present but the count doesn't match the data segments.

* **GC (Garbage Collection) Struct IDs:**
    * `GcStructIdsPass`: Tests a scenario with recursive struct definitions, verifying that the decoder handles them correctly.

* **Type Validation:** Tests related to validating type indices in different contexts:
    * `OutOfBoundsTypeInGlobal`: Checks for failure when a global variable refers to an out-of-bounds type index.
    * `OutOfBoundsTypeInType`: Checks for failure when a struct definition refers to an out-of-bounds type index.
    * `RecursiveTypeOutsideRecursiveGroup`: Checks for success when a recursive type refers to another type outside its recursive group.
    * `OutOfBoundsSupertype`: Checks for failure when a subtype definition refers to an out-of-bounds supertype.
    * `ForwardSupertypeSameType`: Checks for failure when a type declares itself as its own supertype within the same recursive group.
    * `ForwardSupertypeSameRecGroup`: Checks for failure when a type declares a sibling type in the same recursive group as its supertype.

* **Global Validation:**
    * `IllegalPackedFields`: Checks for failure when packed fields are used in a global variable declaration (which is not allowed).

* **Memory 64 Validation:**
    * `Memory64DataSegment`: Tests the interaction between enabling the `memory64` feature and using 32-bit or 64-bit addresses in data segments. It checks for expected success and failures based on the feature flag and address size.

* **Shared Memory Validation:** Tests that require the shared memory proposal to be enabled:
    * `InvalidSharedType`: Checks for failure when a shared struct type is defined without the shared memory feature enabled.
    * `InvalidSharedGlobal`: Checks for failure when a shared global variable is defined without the shared memory feature enabled.

**In summary, this part of the unit test file focuses on verifying the correctness and robustness of the WebAssembly module decoder in handling:**

* **Element segments:** Correct parsing and validation of different types of element segments.
* **Data count section:** Correct placement and matching of the data count with the actual number of data segments.
* **Garbage collection types:**  Proper handling of recursive struct definitions.
* **Type references:** Validation of type indices in globals and type definitions.
* **Supertype relationships:** Validation of supertype declarations in recursive type groups.
* **Global variable declarations:** Restrictions on packed fields in global variables.
* **Memory64 feature:** Handling of 32-bit and 64-bit addressing in data segments based on the `memory64` feature flag.
* **Shared memory feature:**  Requirement for the shared memory feature flag for shared types and globals.

It systematically tests various valid and invalid module structures to ensure the decoder behaves as expected and reports errors correctly. The tests use macros to define module sections and expected outcomes (success or failure with specific messages).

这是 `v8/test/unittests/wasm/module-decoder-unittest.cc` 文件的第三部分，主要功能是**测试 WebAssembly 模块解码器的各种边缘情况、错误处理以及对特定 WebAssembly 功能的支持（或不支持）。**

具体来说，这部分测试涵盖了以下几个方面：

1. **元素段（Element Segments）的各种场景：**
   - 测试了被动（Passive）元素段使用 `funcref` 和 `externref` 类型。
   - 测试了被动元素段使用显式的函数索引。
   - 测试了声明式（Declarative）元素段使用 `funcref` 类型。
   - 测试了声明式元素段使用了无效的函数索引，并期望解码失败。

2. **数据计数段（Data Count Section）的正确放置和一致性：**
   - 测试了数据计数段在模块中的合法位置（在元素段和代码段之间）。
   - 测试了数据计数段放置在代码段之后、元素段之前等非法位置，并期望解码失败。
   - 测试了存在多个数据计数段的情况，并期望解码失败。
   - 测试了数据计数段中声明的数量与实际数据段数量一致、过多和过少的情况，并验证解码器是否正确处理。
   - 测试了省略数据计数段的情况。

3. **GC（垃圾回收）相关的类型 ID：**
   - 测试了包含循环引用的结构体定义，验证解码器是否能正确处理。

4. **类型索引的边界检查：**
   - 测试了在全局变量定义中使用了超出范围的类型索引，并期望解码失败。
   - 测试了在类型定义中使用了超出范围的类型索引，并期望解码失败。
   - 测试了递归类型定义引用了外部的类型，这是允许的。
   - 测试了子类型定义中使用了超出范围的父类型索引，并期望解码失败。
   - 测试了子类型定义中使用了与自身相同的类型作为父类型，并期望解码失败。
   - 测试了子类型定义中使用了同一递归组内的其他类型作为父类型，并期望解码失败。

5. **非法的 packed 字段：**
   - 测试了在全局变量定义中使用了非法的 packed 类型（例如 `i16`），并期望解码失败。

6. **Memory64 功能支持的测试：**
   - 针对 `memory64` 功能，测试了数据段的初始化表达式中使用 `i32.const` 和 `i64.const` 的情况，并根据 `memory64` 特性是否启用来验证解码是否成功或失败，以及失败时的错误信息。

7. **Shared Memory 功能支持的测试：**
   - 测试了在未启用 Shared Memory 特性的情况下定义共享的结构体类型，并期望解码失败，并验证错误信息。
   - 测试了在未启用 Shared Memory 特性的情况下定义共享的全局变量，并期望解码失败，并验证错误信息。

**总而言之，这部分单元测试旨在确保 WebAssembly 模块解码器能够正确地：**

- **验证各种模块结构的合法性。**
- **检测并报告各种格式错误和逻辑错误。**
- **处理各种边缘情况和边界条件。**
- **在特定功能启用或未启用时，按照预期的方式进行解码。**

通过这些细致的测试用例，可以提高 WebAssembly 模块解码器的健壮性和可靠性。

### 提示词
```这是目录为v8/test/unittests/wasm/module-decoder-unittest.cc的一个c++源代码文件， 请归纳一下它的功能
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```
ONE_EMPTY_FUNCTION(SIG_INDEX(0)),
      // table declaration -----------------------------------------------------
      SECTION(Table, ENTRY_COUNT(1), kFuncRefCode, kNoMaximum, 1),
      // element segments  -----------------------------------------------------
      SECTION(Element, ENTRY_COUNT(1), PASSIVE_WITH_ELEMENTS, kFuncRefCode,
              U32V_1(3), REF_FUNC_ELEMENT(0), REF_FUNC_ELEMENT(0),
              REF_NULL_ELEMENT),
      // code ------------------------------------------------------------------
      ONE_EMPTY_BODY};
  EXPECT_VERIFIES(data);
  EXPECT_OFF_END_FAILURE(data, arraysize(data) - 5);
}

TEST_F(WasmModuleVerifyTest, PassiveElementSegmentExternRef) {
  static const uint8_t data[] = {
      // sig#0 -----------------------------------------------------------------
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      // funcs -----------------------------------------------------------------
      ONE_EMPTY_FUNCTION(SIG_INDEX(0)),
      // table declaration -----------------------------------------------------
      SECTION(Table, ENTRY_COUNT(1), kFuncRefCode, kNoMaximum, 1),
      // element segments  -----------------------------------------------------
      SECTION(Element, ENTRY_COUNT(1), PASSIVE_WITH_ELEMENTS, kExternRefCode,
              U32V_1(0)),
      // code ------------------------------------------------------------------
      ONE_EMPTY_BODY};
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, PassiveElementSegmentWithIndices) {
  static const uint8_t data[] = {
      // sig#0 -----------------------------------------------------------------
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      // funcs -----------------------------------------------------------------
      ONE_EMPTY_FUNCTION(SIG_INDEX(0)),
      // table declaration -----------------------------------------------------
      SECTION(Table, ENTRY_COUNT(1), kFuncRefCode, kNoMaximum, 1),
      // element segments ------------------------------------------------------
      SECTION(Element, ENTRY_COUNT(1), PASSIVE, kExternalFunction,
              ENTRY_COUNT(3), U32V_1(0), U32V_1(0), U32V_1(0)),
      // code ------------------------------------------------------------------
      ONE_EMPTY_BODY};
  EXPECT_VERIFIES(data);
  EXPECT_OFF_END_FAILURE(data, arraysize(data) - 5);
}

TEST_F(WasmModuleVerifyTest, DeclarativeElementSegmentFuncRef) {
  static const uint8_t data[] = {
      // sig#0 -----------------------------------------------------------------
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      // funcs -----------------------------------------------------------------
      ONE_EMPTY_FUNCTION(SIG_INDEX(0)),
      // element segments  -----------------------------------------------------
      SECTION(Element,                    // section name
              ENTRY_COUNT(1),             // entry count
              DECLARATIVE_WITH_ELEMENTS,  // flags
              kFuncRefCode,               // local type
              U32V_1(0)),                 // func ref count
      // code ------------------------------------------------------------------
      ONE_EMPTY_BODY};
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, DeclarativeElementSegmentWithInvalidIndex) {
  static const uint8_t data[] = {
      // sig#0 -----------------------------------------------------------------
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      // funcs -----------------------------------------------------------------
      ONE_EMPTY_FUNCTION(SIG_INDEX(0)),
      // element segments  -----------------------------------------------------
      SECTION(Element,            // section name
              ENTRY_COUNT(1),     // entry count
              DECLARATIVE,        // flags
              kExternalFunction,  // type
              ENTRY_COUNT(2),     // func index count
              U32V_1(0),          // func index
              U32V_1(1)),         // func index
      // code ------------------------------------------------------------------
      ONE_EMPTY_BODY};
  EXPECT_FAILURE_WITH_MSG(data, "function index 1 out of bounds");
}

TEST_F(WasmModuleVerifyTest, DataCountSectionCorrectPlacement) {
  static const uint8_t data[] = {SECTION(Element, ENTRY_COUNT(0)),
                                 SECTION(DataCount, ENTRY_COUNT(0)),
                                 SECTION(Code, ENTRY_COUNT(0))};
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, DataCountSectionAfterCode) {
  static const uint8_t data[] = {SECTION(Code, ENTRY_COUNT(0)),
                                 SECTION(DataCount, ENTRY_COUNT(0))};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_NOT_OK(result,
                "The DataCount section must appear before the Code section");
}

TEST_F(WasmModuleVerifyTest, DataCountSectionBeforeElement) {
  static const uint8_t data[] = {SECTION(DataCount, ENTRY_COUNT(0)),
                                 SECTION(Element, ENTRY_COUNT(0))};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_NOT_OK(result, "unexpected section <Element>");
}

TEST_F(WasmModuleVerifyTest, DataCountSectionAfterStartBeforeElement) {
  static_assert(kStartSectionCode + 1 == kElementSectionCode);
  static const uint8_t data[] = {
      // We need the start section for this test, but the start section must
      // reference a valid function, which requires the type and function
      // sections too.
      TYPE_SECTION(1, SIG_ENTRY_v_v),      // Type section.
      FUNCTION_SECTION(1, 0),              // Function section.
      SECTION(Start, U32V_1(0)),           // Start section.
      SECTION(DataCount, ENTRY_COUNT(0)),  // DataCount section.
      SECTION(Element, ENTRY_COUNT(0))     // Element section.
  };
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_NOT_OK(result, "unexpected section <Element>");
}

TEST_F(WasmModuleVerifyTest, MultipleDataCountSections) {
  static const uint8_t data[] = {SECTION(DataCount, ENTRY_COUNT(0)),
                                 SECTION(DataCount, ENTRY_COUNT(0))};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_NOT_OK(result, "Multiple DataCount sections not allowed");
}

TEST_F(WasmModuleVerifyTest, DataCountSegmentCountMatch) {
  static const uint8_t data[] = {
      SECTION(Memory, ENTRY_COUNT(1), kNoMaximum, 1),  // Memory section.
      SECTION(DataCount, ENTRY_COUNT(1)),              // DataCount section.
      SECTION(Data, ENTRY_COUNT(1), LINEAR_MEMORY_INDEX_0,  // Data section.
              WASM_INIT_EXPR_I32V_1(12), ADD_COUNT('h', 'i'))};

  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, DataCountSegmentCount_greater) {
  static const uint8_t data[] = {
      SECTION(Memory, ENTRY_COUNT(1), kNoMaximum, 1),  // Memory section.
      SECTION(DataCount, ENTRY_COUNT(3)),              // DataCount section.
      SECTION(Data, ENTRY_COUNT(0))};                  // Data section.
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_NOT_OK(result, "data segments count 0 mismatch (3 expected)");
}

TEST_F(WasmModuleVerifyTest, DataCountSegmentCount_less) {
  static const uint8_t data[] = {
      SECTION(Memory, ENTRY_COUNT(1), kNoMaximum, 1),  // Memory section.
      SECTION(DataCount, ENTRY_COUNT(0)),              // DataCount section.
      SECTION(Data, ENTRY_COUNT(1), LINEAR_MEMORY_INDEX_0,  // Data section.
              WASM_INIT_EXPR_I32V_1(12), ADD_COUNT('a', 'b', 'c'))};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_NOT_OK(result, "data segments count 1 mismatch (0 expected)");
}

TEST_F(WasmModuleVerifyTest, DataCountSegmentCount_omitted) {
  static const uint8_t data[] = {SECTION(Memory, ENTRY_COUNT(1), kNoMaximum, 1),
                                 SECTION(DataCount, ENTRY_COUNT(1))};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_NOT_OK(result, "data segments count 0 mismatch (1 expected)");
}

TEST_F(WasmModuleVerifyTest, GcStructIdsPass) {
  static const uint8_t data[] = {SECTION(
      Type, ENTRY_COUNT(1),                         // One recursive group...
      kWasmRecursiveTypeGroupCode, ENTRY_COUNT(3),  // with three entries.
      WASM_STRUCT_DEF(FIELD_COUNT(3), STRUCT_FIELD(kI32Code, true),
                      STRUCT_FIELD(WASM_OPT_REF(0), true),
                      STRUCT_FIELD(WASM_OPT_REF(1), true)),
      WASM_STRUCT_DEF(FIELD_COUNT(2), STRUCT_FIELD(WASM_OPT_REF(0), true),
                      STRUCT_FIELD(WASM_OPT_REF(2), true)),
      WASM_ARRAY_DEF(WASM_OPT_REF(0), true))};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);
}

TEST_F(WasmModuleVerifyTest, OutOfBoundsTypeInGlobal) {
  static const uint8_t data[] = {
      SECTION(Global, ENTRY_COUNT(1), kRefCode, 0, WASM_REF_NULL(0), kExprEnd)};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_NOT_OK(result, "Type index 0 is out of bounds");
}

TEST_F(WasmModuleVerifyTest, OutOfBoundsTypeInType) {
  static const uint8_t data[] = {
      SECTION(Type, ENTRY_COUNT(1),
              WASM_STRUCT_DEF(
                  FIELD_COUNT(1),
                  STRUCT_FIELD(WASM_REF_TYPE(ValueType::Ref(Idx{1})), true)))};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_NOT_OK(result, "Type index 1 is out of bounds");
}

TEST_F(WasmModuleVerifyTest, RecursiveTypeOutsideRecursiveGroup) {
  static const uint8_t data[] = {SECTION(
      Type, ENTRY_COUNT(1),
      WASM_STRUCT_DEF(
          FIELD_COUNT(1),
          STRUCT_FIELD(WASM_REF_TYPE(ValueType::RefNull(Idx{0})), true)))};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);
}

TEST_F(WasmModuleVerifyTest, OutOfBoundsSupertype) {
  static const uint8_t data[] = {
      SECTION(Type, ENTRY_COUNT(1), kWasmRecursiveTypeGroupCode, ENTRY_COUNT(1),
              kWasmSubtypeCode, ENTRY_COUNT(1), 1,
              WASM_STRUCT_DEF(FIELD_COUNT(1), STRUCT_FIELD(kI32Code, true)))};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_NOT_OK(result, "type 0: invalid supertype 1");
}

TEST_F(WasmModuleVerifyTest, ForwardSupertypeSameType) {
  static const uint8_t data[] = {
      SECTION(Type, ENTRY_COUNT(1), kWasmRecursiveTypeGroupCode, ENTRY_COUNT(1),
              kWasmSubtypeCode, ENTRY_COUNT(1), 0,
              WASM_STRUCT_DEF(FIELD_COUNT(1), STRUCT_FIELD(kI32Code, true)))};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_NOT_OK(result, "type 0: invalid supertype 0");
}

TEST_F(WasmModuleVerifyTest, ForwardSupertypeSameRecGroup) {
  static const uint8_t data[] = {
      SECTION(Type, ENTRY_COUNT(1), kWasmRecursiveTypeGroupCode, ENTRY_COUNT(2),
              kWasmSubtypeCode, ENTRY_COUNT(1), 0,
              WASM_STRUCT_DEF(FIELD_COUNT(1), STRUCT_FIELD(kI32Code, true)),
              WASM_STRUCT_DEF(FIELD_COUNT(1), STRUCT_FIELD(kI32Code, true)))};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_NOT_OK(result, "type 0: invalid supertype 0");
}

TEST_F(WasmModuleVerifyTest, IllegalPackedFields) {
  static const uint8_t data[] = {
      SECTION(Global, ENTRY_COUNT(1), kI16Code, 0, WASM_INIT_EXPR_I32V_1(13))};

  ModuleResult result = DecodeModule(base::ArrayVector(data));

  EXPECT_NOT_OK(result, "invalid value type");
}

TEST_F(WasmModuleVerifyTest, Memory64DataSegment) {
  WASM_FEATURE_SCOPE(memory64);
  for (bool enable_memory64 : {false, true}) {
    for (bool use_memory64 : {false, true}) {
      uint8_t const_opcode = use_memory64 ? kExprI64Const : kExprI32Const;
      const uint8_t data[] = {
          SECTION(Memory, ENTRY_COUNT(1),
                  enable_memory64 ? kMemory64WithMaximum : kWithMaximum, 28,
                  28),
          SECTION(Data, ENTRY_COUNT(1), ACTIVE_NO_INDEX,  // -
                  const_opcode, 0, kExprEnd,              // dest addr
                  U32V_1(3),                              // source size
                  'a', 'b', 'c')                          // data bytes
      };

      if (enable_memory64 == use_memory64) {
        EXPECT_VERIFIES(data);
      } else if (enable_memory64) {
        EXPECT_FAILURE_WITH_MSG(data, "expected i64, got i32");
      } else {
        EXPECT_FAILURE_WITH_MSG(data, "expected i32, got i64");
      }
    }
  }
}

TEST_F(WasmModuleVerifyTest, InvalidSharedType) {
  // Fails if the feature is not enabled.
  const uint8_t data[] = {
      SECTION(Type, ENTRY_COUNT(1),
              WASM_STRUCT_DEF(FIELD_COUNT(1), kRefNullCode, kSharedFlagCode,
                              kAnyRefCode))};

  ModuleResult result = DecodeModule(base::ArrayVector(data));

  EXPECT_NOT_OK(
      result, "invalid heap type 0x65, enable with --experimental-wasm-shared");
}

TEST_F(WasmModuleVerifyTest, InvalidSharedGlobal) {
  // Fails if the feature is not enabled.
  const uint8_t data[] = {
      SECTION(Global, ENTRY_COUNT(1), kI32Code, 0b11, kExprI32Const, 0)};

  ModuleResult result = DecodeModule(base::ArrayVector(data));

  EXPECT_NOT_OK(
      result,
      "invalid global flags 0x3 (enable via --experimental-wasm-shared)");
}

#undef EXPECT_INIT_EXPR
#undef EXPECT_INIT_EXPR_FAIL
#undef WASM_INIT_EXPR_I32V_1
#undef WASM_INIT_EXPR_I32V_2
#undef WASM_INIT_EXPR_I32V_3
#undef WASM_INIT_EXPR_I32V_4
#undef WASM_INIT_EXPR_I32V_5
#undef WASM_INIT_EXPR_F32
#undef WASM_INIT_EXPR_I64
#undef WASM_INIT_EXPR_F64
#undef WASM_INIT_EXPR_EXTERN_REF_NULL
#undef WASM_INIT_EXPR_FUNC_REF_NULL
#undef WASM_INIT_EXPR_REF_FUNC
#undef WASM_INIT_EXPR_GLOBAL
#undef REF_NULL_ELEMENT
#undef REF_FUNC_ELEMENT
#undef EMPTY_BODY
#undef NOP_BODY
#undef SIG_ENTRY_i_i
#undef UNKNOWN_SECTION
#undef ADD_COUNT
#undef SECTION
#undef TYPE_SECTION
#undef FUNCTION_SECTION
#undef FOO_STRING
#undef NO_LOCAL_NAMES
#undef EMPTY_TYPE_SECTION
#undef EMPTY_FUNCTION_SECTION
#undef EMPTY_FUNCTION_BODIES_SECTION
#undef SECTION_NAMES
#undef EMPTY_NAMES_SECTION
#undef SECTION_SRC_MAP
#undef SECTION_COMPILATION_HINTS
#undef X1
#undef X2
#undef X3
#undef X4
#undef ONE_EMPTY_FUNCTION
#undef TWO_EMPTY_FUNCTIONS
#undef THREE_EMPTY_FUNCTIONS
#undef FOUR_EMPTY_FUNCTIONS
#undef ONE_EMPTY_BODY
#undef TWO_EMPTY_BODIES
#undef THREE_EMPTY_BODIES
#undef FOUR_EMPTY_BODIES
#undef TYPE_SECTION_ONE_SIG_VOID_VOID
#undef LINEAR_MEMORY_INDEX_0

#undef FIELD_COUNT
#undef STRUCT_FIELD
#undef WASM_REF
#undef WASM_OPT_REF
#undef WASM_STRUCT_DEF
#undef WASM_ARRAY_DEF
#undef WASM_FUNCTION_DEF
#undef EXCEPTION_ENTRY
#undef EXPECT_VERIFIES
#undef EXPECT_FAILURE_LEN
#undef EXPECT_FAILURE
#undef EXPECT_OFF_END_FAILURE
#undef EXPECT_OK
#undef EXPECT_NOT_OK

}  // namespace module_decoder_unittest
}  // namespace wasm
}  // namespace internal
}  // namespace v8
```