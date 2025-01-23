Response:
The user wants to understand the functionality of the C++ code snippet from `v8/test/unittests/wasm/module-decoder-unittest.cc`.

Here's a breakdown of the request and how to address each point:

1. **List the functionalities:** Analyze each `TEST_F` function to understand what aspect of the WASM module decoder it's testing. These tests typically focus on verifying the correct parsing and validation of different WASM module sections and their combinations.

2. **.tq check:** Check the file extension. It's `.cc`, not `.tq`.

3. **Relationship with JavaScript:** Determine if the tested functionalities have a direct impact on how JavaScript interacts with WASM. WASM modules are loaded and executed within JavaScript environments, so the module decoder is crucial for this interaction.

4. **JavaScript example:** If there's a connection to JavaScript, provide a simple JavaScript code snippet demonstrating the concept.

5. **Code logic inference (input/output):**  For each test, determine the input (the `data` array representing the WASM bytecode) and the expected output (whether the decoding succeeds or fails, and any specific error messages).

6. **Common programming errors:** Identify any scenarios that relate to common mistakes developers might make when creating WASM modules.

7. **Final summarization:**  Provide a concise overview of the overall purpose of the code.

**Mental Sandbox:**

* **Iterate through each `TEST_F` function:**  For each test, identify the WASM section(s) being tested, the expected outcome (`EXPECT_VERIFIES`, `EXPECT_FAILURE_WITH_MSG`, `EXPECT_NOT_OK`), and the conditions being checked.
* **Connect to WASM specifications:** Relate the tests to specific rules and constraints defined in the WebAssembly specification. For example, tests around `DataCount` section placement directly relate to the order of sections in a valid WASM module.
* **Consider the user's perspective:** Think about how a developer might encounter these scenarios when writing or generating WASM code.
* **Formulate JavaScript examples carefully:** Ensure the examples are clear, concise, and directly related to the C++ test.
* **Focus on the "decoder" aspect:** Remember the file name—it's about *decoding*. The tests verify that the decoder correctly handles valid and invalid WASM bytecode.

**Key observations from the code:**

* The code heavily uses helper macros like `SECTION`, `ENTRY_COUNT`, `WASM_INIT_EXPR_I32V_1`, etc., to construct WASM bytecode.
* The tests cover various aspects of WASM module structure, including element segments, data segments, the `DataCount` section, and type declarations (including recursive types).
* There are tests for both valid and invalid WASM modules, focusing on error detection.

**Confidence Checklist:**

* Listed functionalities of the C++ code? Yes.
* Checked for .tq extension? Yes.
* Explained relationship with JavaScript? Yes.
* Provided JavaScript examples where relevant? Yes.
* Described code logic inference with input/output? Yes.
* Pointed out common programming errors? Yes.
* Summarized the overall functionality? Yes.

Strategizing complete. I will now generate the response by elaborating on these points for each test case.
```cpp
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
```

这是目录为 `v8/test/unittests/wasm/module-decoder-unittest.cc` 的一个 v8 源代码。

**它的功能：**

这个 C++ 文件包含了一系列单元测试，用于测试 v8 中 WASM 模块解码器的正确性。具体来说，它测试了解码器在处理各种 WASM 模块结构和特性时的行为，包括：

* **Element 段 (Element Section):**
    * **被动元素段 (Passive Element Segment):** 测试解码器是否正确处理不同类型的被动元素段，包括 `funcref` 和 `externref` 类型，以及带有索引的被动元素段。
    * **声明式元素段 (Declarative Element Segment):** 测试解码器是否正确处理声明式元素段，并能检测出无效的函数索引。
* **DataCount 段 (Data Count Section):**
    * **位置校验:** 测试 `DataCount` 段在 WASM 模块中的正确放置顺序，例如必须在 `Code` 段之前，某些情况下在 `Element` 段之前。
    * **数量匹配:** 测试解码器是否能正确校验 `DataCount` 段声明的数据段数量与实际 `Data` 段的数量是否一致。
* **类型段 (Type Section):**
    * **GC 类型 (Garbage Collection Types):** 测试解码器是否能正确处理结构体和数组的定义，包括递归类型。
    * **类型索引越界:** 测试解码器是否能检测出在 `Global` 和 `Type` 段中引用的类型索引越界的情况。
    * **递归类型校验:** 测试解码器对于递归类型的处理，包括合法的和非法的定义方式。
    * **超类型校验:** 测试解码器是否能检测出无效的超类型索引，包括指向自身或同一递归组内的类型。
* **全局变量段 (Global Section):**
    * **非法 Packed Fields:** 测试解码器是否能检测出全局变量中使用了非法的 packed 类型。
* **数据段 (Data Section):**
    * **Memory64 支持:** 测试在启用和未启用 Memory64 特性的情况下，解码器对使用 i32 或 i64 初始化内存段地址的校验。
* **共享类型和全局变量 (Shared Types and Globals):**
    * 测试在未启用相关实验性特性时，解码器是否能正确拒绝共享类型和全局变量的定义。

**如果 `v8/test/unittests/wasm/module-decoder-unittest.cc` 以 `.tq` 结尾:**

那它将是一个 v8 Torque 源代码文件。Torque 是一种用于编写 v8 内部代码的领域特定语言，它通常用于定义内置函数和类型。

**它与 javascript 的功能有关系:**

是的，`v8/test/unittests/wasm/module-decoder-unittest.cc` 中测试的功能与 JavaScript 的 WASM 集成密切相关。当 JavaScript 代码尝试加载和实例化一个 WASM 模块时，v8 的 WASM 模块解码器负责解析 WASM 字节码并将其转换为 v8 可以执行的内部表示。如果解码器出现错误，WASM 模块将无法正确加载和运行，从而影响 JavaScript 代码的功能。

**JavaScript 举例说明:**

假设一个 WASM 模块定义了一个 `table` 和一个包含函数引用的 `element` 段。在 JavaScript 中，你可以通过 `WebAssembly.instantiate()` 加载这个模块，并使用 `WebAssembly.Table` API 来访问和调用表中的函数：

```javascript
// 假设 wasmCode 是一个包含以下结构的 WASM 模块的 Uint8Array:
// - 定义了一个 table
// - 定义了一个 passive element 段，包含对函数的引用

// ... (wasmCode 的定义) ...

WebAssembly.instantiate(wasmCode)
  .then(module => {
    const instance = module.instance;
    const myTable = instance.exports.myTable; // 假设导出了名为 myTable 的 table

    // 调用表中的函数 (假设索引 0 处有一个函数)
    const myFunction = myTable.get(0);
    if (myFunction) {
      myFunction();
    }
  })
  .catch(error => {
    console.error("Failed to instantiate the module:", error);
  });
```

如果 `module-decoder-unittest.cc` 中的测试失败，意味着解码器在处理某些 WASM 结构时可能存在问题，这可能会导致上述 JavaScript 代码在加载或执行 WASM 模块时抛出错误或产生未预期的行为。

**代码逻辑推理，假设输入与输出:**

以 `TEST_F(WasmModuleVerifyTest, DataCountSectionAfterCode)` 为例：

* **假设输入 (`data`):** 一个 WASM 字节数组，其中 `DataCount` 段出现在 `Code` 段之后。
* **预期输出:** `DecodeModule` 函数返回一个 `ModuleResult`，其状态为 `NOT_OK`，并且错误消息包含 "The DataCount section must appear before the Code section"。

**用户常见的编程错误举例说明:**

* **`DataCountSegmentCount_greater` 测试:**  模拟了用户在 WASM 模块中声明了比实际提供的数据段更多的 `DataCount` 的情况。这是一个常见的错误，可能发生在手动编写或生成 WASM 模块时，对数据段的数量统计错误。
* **`DeclarativeElementSegmentWithInvalidIndex` 测试:**  模拟了用户在声明式元素段中引用了不存在的函数索引。这通常发生在手动编辑 WASM 二进制文件或在代码生成过程中出现逻辑错误时。
* **`Memory64DataSegment` 测试:** 演示了在启用了 Memory64 特性后，如果数据段的初始化表达式仍然使用 i32 常量，则解码器会报错。这突出了在启用新特性后，需要更新 WASM 模块的构造方式。

**归纳一下它的功能 (第 5 部分，共 5 部分):**

`v8/test/unittests/wasm/module-decoder-unittest.cc` 的功能是 **全面测试 v8 中 WASM 模块解码器的正确性和健壮性**。它通过构造各种合法的和非法的 WASM 模块结构，并断言解码器的行为是否符合预期，来确保解码器能够正确解析和验证 WASM 字节码，并且能够有效地检测出常见的 WASM 模块构建错误。 这对于确保 v8 能够安全可靠地执行 WASM 代码至关重要。

### 提示词
```
这是目录为v8/test/unittests/wasm/module-decoder-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/wasm/module-decoder-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
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