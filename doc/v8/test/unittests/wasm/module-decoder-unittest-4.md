Response: The user wants me to summarize the functionality of the C++ code in the provided text.
This is the second part of a three-part file. I should focus on the code related to WebAssembly module decoding and verification, specifically focusing on tests related to table and element sections.
I should also provide a JavaScript example if the C++ code has a corresponding functionality in JavaScript.

Looking at the code, it seems to define various test cases for the `WasmModuleVerifyTest` class. These tests cover:

- **Element Section with Invalid Function Index:** Tests the case where an invalid function index is used in an element segment.
- **One Indirect Function with One Entry:** Tests the case where an element segment initializes a table with a single function.
- **Multiple Indirect Functions:** Tests the case where an element segment initializes a table with multiple functions.
- **Element Section with Multiple Tables:** Tests the ability to initialize multiple tables in the element section.
- **Element Section with Mixed Tables (Imported and Module-Defined):** Tests the ability to initialize both imported and module-defined tables in the element section.
- **Element Section with Multiple Tables in Arbitrary Order:** Tests that the order of table initialization in the element section does not matter.
- **Element Section with Mixed Tables in Arbitrary Order:** Similar to the above but with both imported and module-defined tables.
- **Element Section Initializing ExternRef Table with FuncRef:** Tests that you cannot initialize an `externref` table with `funcref`.
- **Element Section Indexing Elements Table with Narrow Type:** Tests that you cannot use an element segment with a more general type to initialize a table with a narrower type.
- **Element Section Initializing FuncRef Table with FuncRefNull:** Tests initializing a `funcref` table with `funcref null`.
- **Element Section Initializing FuncRef Table with ExternRefNull:** Tests that you cannot initialize a `funcref` table with `externref null`.
- **Element Section Not Initializing ExternRef Imported Table:** Tests that imported `externref` tables cannot be initialized in the element section.
- **Element Section Global Get Out Of Bounds:** Tests accessing a global out of bounds in an element segment.

These tests seem to be specifically designed to ensure the correct parsing and validation of the "element" section of a WebAssembly module, which is responsible for initializing tables with function references or other values.

In JavaScript, the equivalent functionality is handled by the browser's WebAssembly engine during module instantiation. When a WebAssembly module with an element section is instantiated, the JavaScript engine uses the information in the element section to populate the corresponding table(s).
这个C++源代码文件（`v8/test/unittests/wasm/module-decoder-unittest.cc` 的第 2 部分）主要用于测试 WebAssembly 模块解码器中关于 **Element Section (元素段)** 的功能和验证逻辑。

**核心功能归纳:**

该部分代码专注于测试 WebAssembly 模块中 **Element Section** 的各种场景，包括：

1. **验证元素段的语法正确性:**  例如，测试当元素段包含无效的函数索引时，解码器是否能够正确地识别并报错。
2. **测试元素段初始化表格的能力:**  验证元素段是否能够正确地初始化表格（Table）中的条目，包括函数引用（`funcref`）和其他引用类型（如 `externref`）。
3. **测试元素段与不同表格类型的交互:**  验证元素段是否能正确地初始化不同类型的表格，包括：
    * 普通的函数引用表格 (`funcref`)
    * 外部引用表格 (`externref`)
    * 可为空的引用表格 (`(ref null ...)`)
4. **测试元素段处理多个表格的能力:**  验证当 WebAssembly 模块中存在多个表格时，元素段是否能够正确地定位并初始化指定的表格。
5. **测试元素段处理导入表格的能力:**  验证元素段是否能够正确地初始化从外部导入的表格。
6. **测试元素段初始化表达式的正确性:**  验证元素段中用于初始化表格条目的常量表达式（如 `ref.func`, `ref.null`) 是否被正确解析和类型检查。
7. **测试元素段初始化的顺序无关性:**  验证当存在多个元素段初始化多个表格时，它们的顺序是否不会影响最终的结果。
8. **测试元素段的边界情况和错误处理:**  例如，测试当访问超出范围的全局变量或尝试使用不兼容的类型初始化表格时，解码器是否能够正确地报告错误。

**与 JavaScript 的关系及示例:**

在 JavaScript 中，WebAssembly 的 `Table` 对象可以通过 `WebAssembly.instantiate()` 或 `WebAssembly.compile()` 加载的模块中的 Element Section 来初始化。

**C++ 代码中的测试场景对应于 JavaScript 中模块实例化时的行为。**  例如，C++ 代码中测试了当 Element Section 中包含无效函数索引时会发生什么。在 JavaScript 中，如果尝试实例化一个包含这种错误的 WebAssembly 模块，将会抛出一个 `WebAssembly.LinkError` 或其他类型的错误。

**JavaScript 示例:**

假设有一个 WebAssembly 模块 (保存在 `module_bytes` 中) 包含一个表格和一个尝试用无效函数索引初始化的元素段：

```javascript
const module_bytes = new Uint8Array([
  // ... WebAssembly 模块的字节码 ...
  // 包括一个定义了表格和一个包含无效函数索引的元素段
  // ...
]);

WebAssembly.instantiate(module_bytes)
  .then(instance => {
    // 模块实例化成功
    console.log("模块实例化成功:", instance);
  })
  .catch(error => {
    // 模块实例化失败，通常是因为链接错误或验证错误
    console.error("模块实例化失败:", error);
    // 如果模块包含无效的函数索引，可能会抛出一个 LinkError
  });
```

**解释:**

1. `module_bytes` 代表一个包含 WebAssembly 字节码的 `Uint8Array`。
2. `WebAssembly.instantiate(module_bytes)` 尝试编译和实例化这个模块。
3. 如果模块的 Element Section 中包含无效的函数索引（就像 C++ 代码中的测试用例那样），JavaScript 引擎在链接阶段会检测到这个错误，并抛出一个错误，阻止模块的成功实例化。

**总结:**

这部分 C++ 代码是 WebAssembly 引擎测试套件的一部分，它专门用于验证模块解码器在处理 Element Section 时的正确性和健壮性。这些测试确保了当遇到各种合法的和非法的 Element Section 定义时，解码器能够按照 WebAssembly 规范的要求进行处理，并在出现错误时能够正确地报告。这直接关系到 JavaScript 中 WebAssembly 模块实例化的过程，因为浏览器在实例化模块时会依赖于正确的模块解码和验证。

### 提示词
```这是目录为v8/test/unittests/wasm/module-decoder-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```
entry count
              TABLE_INDEX0, WASM_INIT_EXPR_I32V_1(0),
              1,     // elements count
              0x9A)  // invalid I32V as function index
  };

  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, OneIndirectFunction_one_entry) {
  static const uint8_t data[] = {
      // sig#0 ---------------------------------------------------------------
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      // funcs ---------------------------------------------------------------
      ONE_EMPTY_FUNCTION(SIG_INDEX(0)),
      // table declaration ---------------------------------------------------
      SECTION(Table, ENTRY_COUNT(1), kFuncRefCode, kNoMaximum, 1),
      // elements ------------------------------------------------------------
      SECTION(Element,
              ENTRY_COUNT(1),  // entry count
              TABLE_INDEX0, WASM_INIT_EXPR_I32V_1(0),
              1,  // elements count
              FUNC_INDEX(0)),
      // code ----------------------------------------------------------------
      ONE_EMPTY_BODY};

  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);
  EXPECT_EQ(1u, result.value()->types.size());
  EXPECT_EQ(1u, result.value()->functions.size());
  EXPECT_EQ(1u, result.value()->tables.size());
  EXPECT_EQ(1u, result.value()->tables[0].initial_size);
}

TEST_F(WasmModuleVerifyTest, MultipleIndirectFunctions) {
  static const uint8_t data[] = {
      // sig#0 -------------------------------------------------------
      SECTION(Type,
              ENTRY_COUNT(2),            // --
              SIG_ENTRY_v_v,             // void -> void
              SIG_ENTRY_v_x(kI32Code)),  // void -> i32
      // funcs ------------------------------------------------------
      FOUR_EMPTY_FUNCTIONS(SIG_INDEX(0)),
      // table declaration -------------------------------------------
      SECTION(Table, ENTRY_COUNT(1), kFuncRefCode, kNoMaximum, 8),
      // table elements ----------------------------------------------
      SECTION(Element,
              ENTRY_COUNT(1),  // entry count
              TABLE_INDEX0, WASM_INIT_EXPR_I32V_1(0),
              ADD_COUNT(FUNC_INDEX(0), FUNC_INDEX(1), FUNC_INDEX(2),
                        FUNC_INDEX(3), FUNC_INDEX(0), FUNC_INDEX(1),
                        FUNC_INDEX(2), FUNC_INDEX(3))),
      FOUR_EMPTY_BODIES};

  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);
  EXPECT_EQ(2u, result.value()->types.size());
  EXPECT_EQ(4u, result.value()->functions.size());
  EXPECT_EQ(1u, result.value()->tables.size());
  EXPECT_EQ(8u, result.value()->tables[0].initial_size);
}

TEST_F(WasmModuleVerifyTest, ElementSectionMultipleTables) {
  // Test that if we have multiple tables, in the element section we can target
  // and initialize all tables.
  static const uint8_t data[] = {
      // sig#0 ---------------------------------------------------------------
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      // funcs ---------------------------------------------------------------
      ONE_EMPTY_FUNCTION(SIG_INDEX(0)),
      // table declaration ---------------------------------------------------
      SECTION(Table, ENTRY_COUNT(2),         // section header
              kFuncRefCode, kNoMaximum, 5,   // table 0
              kFuncRefCode, kNoMaximum, 9),  // table 1
      // elements ------------------------------------------------------------
      SECTION(Element,
              ENTRY_COUNT(2),            // entry count
              TABLE_INDEX0,              // element for table 0
              WASM_INIT_EXPR_I32V_1(0),  // index
              1,                         // elements count
              FUNC_INDEX(0),             // function
              TABLE_INDEX(1),            // element for table 1
              WASM_INIT_EXPR_I32V_1(7),  // index
              kExternalFunction,         // type
              2,                         // elements count
              FUNC_INDEX(0),             // entry 0
              FUNC_INDEX(0)),            // entry 1
      // code ----------------------------------------------------------------
      ONE_EMPTY_BODY};

  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, ElementSectionMixedTables) {
  // Test that if we have multiple tables, both imported and module-defined, in
  // the element section we can target and initialize all tables.
  static const uint8_t data[] = {
      // sig#0 ---------------------------------------------------------------
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      // imports -------------------------------------------------------------
      SECTION(Import, ENTRY_COUNT(2),
              ADD_COUNT('m'),  // module name
              ADD_COUNT('t'),  // table name
              kExternalTable,  // import kind
              kFuncRefCode,    // elem_type
              kNoMaximum,      // maximum
              5,               // initial size
              ADD_COUNT('m'),  // module name
              ADD_COUNT('s'),  // table name
              kExternalTable,  // import kind
              kFuncRefCode,    // elem_type
              kNoMaximum,      // maximum
              10),             // initial size
      // funcs ---------------------------------------------------------------
      ONE_EMPTY_FUNCTION(SIG_INDEX(0)),
      // table declaration ---------------------------------------------------
      SECTION(Table, ENTRY_COUNT(2),          // section header
              kFuncRefCode, kNoMaximum, 15,   // table 0
              kFuncRefCode, kNoMaximum, 19),  // table 1
      // elements ------------------------------------------------------------
      SECTION(Element,
              4,                          // entry count
              TABLE_INDEX0,               // element for table 0
              WASM_INIT_EXPR_I32V_1(0),   // index
              1,                          // elements count
              FUNC_INDEX(0),              // function
              TABLE_INDEX(1),             // element for table 1
              WASM_INIT_EXPR_I32V_1(7),   // index
              kExternalFunction,          // type
              2,                          // elements count
              FUNC_INDEX(0),              // entry 0
              FUNC_INDEX(0),              // entry 1
              TABLE_INDEX(2),             // element for table 2
              WASM_INIT_EXPR_I32V_1(12),  // index
              kExternalFunction,          // type
              1,                          // elements count
              FUNC_INDEX(0),              // function
              TABLE_INDEX(3),             // element for table 1
              WASM_INIT_EXPR_I32V_1(17),  // index
              kExternalFunction,          // type
              2,                          // elements count
              FUNC_INDEX(0),              // entry 0
              FUNC_INDEX(0)),             // entry 1
      // code ----------------------------------------------------------------
      ONE_EMPTY_BODY};

  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, ElementSectionMultipleTablesArbitraryOrder) {
  // Test that the order in which tables are targeted in the element secion
  // can be arbitrary.
  static const uint8_t data[] = {
      // sig#0 ---------------------------------------------------------------
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      // funcs ---------------------------------------------------------------
      ONE_EMPTY_FUNCTION(SIG_INDEX(0)),
      // table declaration ---------------------------------------------------
      SECTION(Table, ENTRY_COUNT(2),         // section header
              kFuncRefCode, kNoMaximum, 5,   // table 0
              kFuncRefCode, kNoMaximum, 9),  // table 1
      // elements ------------------------------------------------------------
      SECTION(Element,
              ENTRY_COUNT(3),            // entry count
              TABLE_INDEX0,              // element for table 1
              WASM_INIT_EXPR_I32V_1(0),  // index
              1,                         // elements count
              FUNC_INDEX(0),             // function
              TABLE_INDEX(1),            // element for table 0
              WASM_INIT_EXPR_I32V_1(7),  // index
              kExternalFunction,         // type
              2,                         // elements count
              FUNC_INDEX(0),             // entry 0
              FUNC_INDEX(0),             // entry 1
              TABLE_INDEX0,              // element for table 1
              WASM_INIT_EXPR_I32V_1(3),  // index
              1,                         // elements count
              FUNC_INDEX(0)),            // function
      // code ----------------------------------------------------------------
      ONE_EMPTY_BODY};

  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, ElementSectionMixedTablesArbitraryOrder) {
  // Test that the order in which tables are targeted in the element secion can
  // be arbitrary. In this test, tables can be both imported and module-defined.
  static const uint8_t data[] = {
      // sig#0 ---------------------------------------------------------------
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      // imports -------------------------------------------------------------
      SECTION(Import, ENTRY_COUNT(2),
              ADD_COUNT('m'),  // module name
              ADD_COUNT('t'),  // table name
              kExternalTable,  // import kind
              kFuncRefCode,    // elem_type
              kNoMaximum,      // maximum
              5,               // initial size
              ADD_COUNT('m'),  // module name
              ADD_COUNT('s'),  // table name
              kExternalTable,  // import kind
              kFuncRefCode,    // elem_type
              kNoMaximum,      // maximum
              10),             // initial size
      // funcs ---------------------------------------------------------------
      ONE_EMPTY_FUNCTION(SIG_INDEX(0)),
      // table declaration ---------------------------------------------------
      SECTION(Table, ENTRY_COUNT(2),          // section header
              kFuncRefCode, kNoMaximum, 15,   // table 0
              kFuncRefCode, kNoMaximum, 19),  // table 1
      // elements ------------------------------------------------------------
      SECTION(Element,
              4,                          // entry count
              TABLE_INDEX(2),             // element for table 0
              WASM_INIT_EXPR_I32V_1(10),  // index
              kExternalFunction,          // type
              1,                          // elements count
              FUNC_INDEX(0),              // function
              TABLE_INDEX(3),             // element for table 1
              WASM_INIT_EXPR_I32V_1(17),  // index
              kExternalFunction,          // type
              2,                          // elements count
              FUNC_INDEX(0),              // entry 0
              FUNC_INDEX(0),              // entry 1
              TABLE_INDEX0,               // element for table 2
              WASM_INIT_EXPR_I32V_1(2),   // index
              1,                          // elements count
              FUNC_INDEX(0),              // function
              TABLE_INDEX(1),             // element for table 1
              WASM_INIT_EXPR_I32V_1(7),   // index
              kExternalFunction,          // type
              2,                          // elements count
              FUNC_INDEX(0),              // entry 0
              FUNC_INDEX(0)),             // entry 1
      // code ----------------------------------------------------------------
      ONE_EMPTY_BODY};

  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, ElementSectionInitExternRefTableWithFuncRef) {
  static const uint8_t data[] = {
      // sig#0 ---------------------------------------------------------------
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      // funcs ---------------------------------------------------------------
      ONE_EMPTY_FUNCTION(SIG_INDEX(0)),
      // table declaration ---------------------------------------------------
      SECTION(Table, ENTRY_COUNT(2),          // section header
              kExternRefCode, kNoMaximum, 5,  // table 0
              kFuncRefCode, kNoMaximum, 9),   // table 1
      // elements ------------------------------------------------------------
      SECTION(Element,
              ENTRY_COUNT(2),            // entry count
              TABLE_INDEX0,              // element for table 0
              WASM_INIT_EXPR_I32V_1(0),  // index
              1,                         // elements count
              FUNC_INDEX(0),             // function
              TABLE_INDEX(1),            // element for table 1
              WASM_INIT_EXPR_I32V_1(7),  // index
              kExternalFunction,         // type
              2,                         // elements count
              FUNC_INDEX(0),             // entry 0
              FUNC_INDEX(0)),            // entry 1
      // code ----------------------------------------------------------------
      ONE_EMPTY_BODY,
  };

  EXPECT_FAILURE_WITH_MSG(data,
                          "Element segment of type (ref func) is not a subtype "
                          "of referenced table 0 (of type externref)");
}

TEST_F(WasmModuleVerifyTest, ElementSectionIndexElementsTableWithNarrowType) {
  static const uint8_t data[] = {
      // sig#0 ---------------------------------------------------------------
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      // table declaration ---------------------------------------------------
      SECTION(Table, ENTRY_COUNT(1),            // section header
              kRefNullCode, 0, kNoMaximum, 9),  // table 1
      // elements ------------------------------------------------------------
      SECTION(Element,
              ENTRY_COUNT(1),            // entry count
              TABLE_INDEX0,              // element for table 0
              WASM_INIT_EXPR_I32V_1(0),  // index
              1,                         // elements count
              FUNC_INDEX(0))             // function
  };

  EXPECT_FAILURE_WITH_MSG(data,
                          "Element segment of type (ref func) is not a subtype "
                          "of referenced table 0 (of type (ref null 0))");
}

TEST_F(WasmModuleVerifyTest, ElementSectionInitFuncRefTableWithFuncRefNull) {
  static const uint8_t data[] = {
      // table declaration ---------------------------------------------------
      SECTION(Table, ENTRY_COUNT(1),         // section header
              kFuncRefCode, kNoMaximum, 9),  // table 0
      // elements ------------------------------------------------------------
      SECTION(Element,
              ENTRY_COUNT(1),                      // entry count
              ACTIVE_WITH_ELEMENTS, TABLE_INDEX0,  // element for table 0
              WASM_INIT_EXPR_I32V_1(0),            // index
              kFuncRefCode,                        // .
              1,                                   // elements count
              WASM_INIT_EXPR_FUNC_REF_NULL)        // function
  };

  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, ElementSectionInitFuncRefTableWithExternRefNull) {
  static const uint8_t data[] = {
      // table declaration ---------------------------------------------------
      SECTION(Table, ENTRY_COUNT(1),         // section header
              kFuncRefCode, kNoMaximum, 9),  // table 0
      // elements ------------------------------------------------------------
      SECTION(Element,
              ENTRY_COUNT(1),                      // entry count
              ACTIVE_WITH_ELEMENTS, TABLE_INDEX0,  // element for table 0
              WASM_INIT_EXPR_I32V_1(0),            // index
              kFuncRefCode,                        // .
              1,                                   // elements count
              WASM_INIT_EXPR_EXTERN_REF_NULL)      // function
  };

  EXPECT_FAILURE_WITH_MSG(
      data,
      "type error in constant expression[0] (expected funcref, got externref)");
}

TEST_F(WasmModuleVerifyTest, ElementSectionDontInitExternRefImportedTable) {
  // Test that imported tables of type ExternRef cannot be initialized in the
  // elements section.
  static const uint8_t data[] = {
      // sig#0 ---------------------------------------------------------------
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      // imports -------------------------------------------------------------
      SECTION(Import, ENTRY_COUNT(2),
              ADD_COUNT('m'),  // module name
              ADD_COUNT('t'),  // table name
              kExternalTable,  // import kind
              kFuncRefCode,    // elem_type
              kNoMaximum,      // maximum
              5,               // initial size
              ADD_COUNT('m'),  // module name
              ADD_COUNT('s'),  // table name
              kExternalTable,  // import kind
              kExternRefCode,  // elem_type
              kNoMaximum,      // maximum
              10),             // initial size
      // funcs ---------------------------------------------------------------
      ONE_EMPTY_FUNCTION(SIG_INDEX(0)),
      // table declaration ---------------------------------------------------
      SECTION(Table, ENTRY_COUNT(2),          // section header
              kFuncRefCode, kNoMaximum, 15,   // table 0
              kFuncRefCode, kNoMaximum, 19),  // table 1
      // elements ------------------------------------------------------------
      SECTION(Element,
              ENTRY_COUNT(4),             // entry count
              TABLE_INDEX0,               // element for table 0
              WASM_INIT_EXPR_I32V_1(10),  // index
              1,                          // elements count
              FUNC_INDEX(0),              // function
              TABLE_INDEX(1),             // element for table 1
              WASM_INIT_EXPR_I32V_1(17),  // index
              kExternalFunction,          // type
              2,                          // elements count
              FUNC_INDEX(0),              // entry 0
              FUNC_INDEX(0)),             // entry 1
  };

  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, ElementSectionGlobalGetOutOfBounds) {
  static const uint8_t data[] = {
      SECTION(Element, ENTRY_COUNT(1),
              0x05,            // Mode: Passive with expressions-as-elements
              kFuncRefCode,    // type
              ENTRY_COUNT(1),  // element count
              kExprGlobalGet, 0x00, kExprEnd)};  // initial value
  EXPECT_FAILURE_WITH_MSG(data, "Invalid global index: 0");
}

TEST_F(WasmModuleVerifyTest, ExtendedConstantsI32) {
  static const uint8_t data[] = {
      SECTION(Import, ENTRY_COUNT(1),         // one import
              0x01, 'm', 0x01, 'g',           // module, name
              kExternalGlobal, kI32Code, 0),  // type, mutability
      SECTION(Global, ENTRY_COUNT(1),         // one defined global
              kI32Code, 0,                    // type, mutability
              // initializer
              kExprGlobalGet, 0x00, kExprGlobalGet, 0x00, kExprI32Add,
              kExprGlobalGet, 0x00, kExprI32Sub, kExprGlobalGet, 0x00,
              kExprI32Mul, kExprEnd)};
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, ExtendedConstantsI64) {
  static const uint8_t data[] = {
      SECTION(Import, ENTRY_COUNT(1),         // one import
              0x01, 'm', 0x01, 'g',           // module, name
              kExternalGlobal, kI64Code, 0),  // type, mutability
      SECTION(Global, ENTRY_COUNT(1),         // one defined global
              kI64Code, 0,                    // type, mutability
              // initializer
              kExprGlobalGet, 0x00, kExprGlobalGet, 0x00, kExprI64Add,
              kExprGlobalGet, 0x00, kExprI64Sub, kExprGlobalGet, 0x00,
              kExprI64Mul, kExprEnd)};
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, ExtendedConstantsTypeError) {
  static const uint8_t data[] = {
      SECTION(Import, ENTRY_COUNT(1),         // one import
              0x01, 'm', 0x01, 'g',           // module, name
              kExternalGlobal, kI32Code, 0),  // type, mutability
      SECTION(Global, ENTRY_COUNT(1),         // one defined global
              kI32Code, 0,                    // type, mutability
              // initializer
              kExprGlobalGet, 0x00, kExprI64Const, 1, kExprI32Add, kExprEnd)};
  EXPECT_FAILURE_WITH_MSG(
      data, "i32.add[1] expected type i32, found i64.const of type i64");
}

TEST_F(WasmModuleVerifyTest, IndirectFunctionNoFunctions) {
  static const uint8_t data[] = {
      // sig#0 -------------------------------------------------------
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      // indirect table ----------------------------------------------
      SECTION(Table, ENTRY_COUNT(1), 1, 0, 0)};

  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, IndirectFunctionInvalidIndex) {
  static const uint8_t data[] = {
      // sig#0 -------------------------------------------------------
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      // functions ---------------------------------------------------
      ONE_EMPTY_FUNCTION(SIG_INDEX(0)),
      // indirect table ----------------------------------------------
      SECTION(Table, ENTRY_COUNT(1), 1, 1, 0)};

  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, MultipleTables) {
  static const uint8_t data[] = {
      SECTION(Table,           // table section
              ENTRY_COUNT(2),  // 2 tables
              kFuncRefCode,    // table 1: type
              kNoMaximum,      // table 1: no maximum
              10,              // table 1: minimum size
              kExternRefCode,  // table 2: type
              kNoMaximum,      // table 2: no maximum
              11),             // table 2: minimum size
  };

  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);

  EXPECT_EQ(2u, result.value()->tables.size());

  EXPECT_EQ(10u, result.value()->tables[0].initial_size);
  EXPECT_EQ(kWasmFuncRef, result.value()->tables[0].type);

  EXPECT_EQ(11u, result.value()->tables[1].initial_size);
  EXPECT_EQ(kWasmExternRef, result.value()->tables[1].type);
}

TEST_F(WasmModuleVerifyTest, TypedFunctionTable) {
  static const uint8_t data[] = {
      SECTION(Type, ENTRY_COUNT(1), SIG_ENTRY_v_x(kI32Code)),
      SECTION(Table,             // table section
              ENTRY_COUNT(1),    // 1 table
              kRefNullCode, 0,   // table 0: type
              kNoMaximum, 10)};  // table 0: limits

  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);
  EXPECT_EQ(ValueType::RefNull(Idx{0}), result.value()->tables[0].type);
}

TEST_F(WasmModuleVerifyTest, NullableTableIllegalInitializer) {
  static const uint8_t data[] = {
      SECTION(Type, ENTRY_COUNT(1), SIG_ENTRY_v_v),  // type section
      ONE_EMPTY_FUNCTION(0),                         // function section
      SECTION(Table,                                 // table section
              ENTRY_COUNT(1),                        // 1 table
              kRefNullCode, 0,                       // table 0: type
              kNoMaximum, 10,                        // table 0: limits
              kExprRefFunc, 0, kExprEnd)};           // table 0: initializer

  EXPECT_FAILURE_WITH_MSG(
      data,
      "section was shorter than expected size (8 bytes expected, 5 decoded)");
}

TEST_F(WasmModuleVerifyTest, IllegalTableTypes) {
  using Vec = std::vector<uint8_t>;

  static Vec table_types[] = {{kI32Code}, {kF64Code}};

  for (Vec type : table_types) {
    Vec data = {
        SECTION(Type, ENTRY_COUNT(2),
                WASM_STRUCT_DEF(FIELD_COUNT(1), STRUCT_FIELD(kI32Code, true)),
                WASM_ARRAY_DEF(kI32Code, true)),
        kTableSectionCode, static_cast<uint8_t>(type.size() + 3), uint8_t{1}};
    // Last elements are section size and entry count

    // Add table type
    data.insert(data.end(), type.begin(), type.end());
    // Add table limits
    data.insert(data.end(), {uint8_t{0}, uint8_t{10}});

    auto result = DecodeModule(base::VectorOf(data));
    EXPECT_NOT_OK(result, "Only reference types can be used as table types");
  }
}

TEST_F(WasmModuleVerifyTest, TableWithInitializer) {
  static const uint8_t data[] = {
      SECTION(Type, ENTRY_COUNT(1), SIG_ENTRY_v_v),  // type section
      ONE_EMPTY_FUNCTION(0),                         // function section
      SECTION(Table,                                 // table section
              ENTRY_COUNT(1),                        // 1 table
              0x40,                                  // table 0: has initializer
              0x00,                                  // table 0: reserved byte
              kRefNullCode, 0,                       // table 0: type
              kNoMaximum, 10,                        // table 0: limits
              kExprRefFunc, 0, kExprEnd),            // table 0: initial value
      SECTION(Code, ENTRY_COUNT(1), NOP_BODY)};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);
  EXPECT_EQ(ValueType::RefNull(Idx{0}), result.value()->tables[0].type);
}

TEST_F(WasmModuleVerifyTest, NonNullableTable) {
  static const uint8_t data[] = {
      SECTION(Type, ENTRY_COUNT(1), SIG_ENTRY_v_v),  // type section
      ONE_EMPTY_FUNCTION(0),                         // function section
      SECTION(Table,                                 // table section
              ENTRY_COUNT(1),                        // 1 table
              0x40,                                  // table 0: has initializer
              0x00,                                  // table 0: reserved byte
              kRefCode, 0,                           // table 0: type
              kNoMaximum, 10,                        // table 0: limits
              kExprRefFunc, 0, kExprEnd),            // table 0: initial value
      SECTION(Code, ENTRY_COUNT(1), NOP_BODY)};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);
  EXPECT_EQ(ValueType::Ref(Idx{0}), result.value()->tables[0].type);
}

TEST_F(WasmModuleVerifyTest, NonNullableTableNoInitializer) {
  static const uint8_t data[] = {
      SECTION(Type, ENTRY_COUNT(1), SIG_ENTRY_v_x(kI32Code)),
      SECTION(Table,                      // table section
              ENTRY_COUNT(2),             // 2 tables
              kRefCode, 0,                // table 0: type
              kNoMaximum, 10,             // table 0: limits
              kRefCode, 0,                // table 1: type
              kMemory64WithMaximum, 6)};  // table 1: limits

  EXPECT_FAILURE_WITH_MSG(
      data, "Table of non-defaultable table (ref 0) needs initial value");
}

TEST_F(WasmModuleVerifyTest, TieringCompilationHints) {
  WASM_FEATURE_SCOPE(compilation_hints);
  static const uint8_t data[] = {
      TYPE_SECTION(1, SIG_ENTRY_v_v),
      FUNCTION_SECTION(3, 0, 0, 0),
      SECTION_COMPILATION_HINTS(BASELINE_TIER_BASELINE | TOP_TIER_BASELINE,
                                BASELINE_TIER_BASELINE | TOP_TIER_OPTIMIZED,
                                BASELINE_TIER_OPTIMIZED | TOP_TIER_OPTIMIZED),
      SECTION(Code, ENTRY_COUNT(3), NOP_BODY, NOP_BODY, NOP_BODY),
  };

  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);

  EXPECT_EQ(3u, result.value()->compilation_hints.size());
  EXPECT_EQ(WasmCompilationHintStrategy::kDefault,
            result.value()->compilation_hints[0].strategy);
  EXPECT_EQ(WasmCompilationHintTier::kBaseline,
            result.value()->compilation_hints[0].baseline_tier);
  EXPECT_EQ(WasmCompilationHintTier::kBaseline,
            result.value()->compilation_hints[0].top_tier);
  EXPECT_EQ(WasmCompilationHintStrategy::kDefault,
            result.value()->compilation_hints[1].strategy);
  EXPECT_EQ(WasmCompilationHintTier::kBaseline,
            result.value()->compilation_hints[1].baseline_tier);
  EXPECT_EQ(WasmCompilationHintTier::kOptimized,
            result.value()->compilation_hints[1].top_tier);
  EXPECT_EQ(WasmCompilationHintStrategy::kDefault,
            result.value()->compilation_hints[2].strategy);
  EXPECT_EQ(WasmCompilationHintTier::kOptimized,
            result.value()->compilation_hints[2].baseline_tier);
  EXPECT_EQ(WasmCompilationHintTier::kOptimized,
            result.value()->compilation_hints[2].top_tier);
}

TEST_F(WasmModuleVerifyTest, BranchHinting) {
  WASM_FEATURE_SCOPE(branch_hinting);
  static const uint8_t data[] = {
      TYPE_SECTION(1, SIG_ENTRY_v_v), FUNCTION_SECTION(2, 0, 0),
      SECTION_BRANCH_HINTS(ENTRY_COUNT(2), 0 /*func_index*/, ENTRY_COUNT(1),
                           3 /* if offset*/, 1 /*reserved*/, 1 /*likely*/,
                           1 /*func_index*/, ENTRY_COUNT(1),
                           5 /* br_if offset*/, 1 /*reserved*/, 0 /*unlikely*/),
      SECTION(Code, ENTRY_COUNT(2),
              ADD_COUNT(0, /*no locals*/
                        WASM_IF(WASM_I32V_1(1), WASM_NOP), WASM_END),
              ADD_COUNT(0, /*no locals*/
                        WASM_BLOCK(WASM_BR_IF(0, WASM_I32V_1(1))), WASM_END))};

  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);

  EXPECT_EQ(2u, result.value()->branch_hints.size());
  EXPECT_EQ(WasmBranchHint::kLikely,
            result.value()->branch_hints[0].GetHintFor(3));
  EXPECT_EQ(WasmBranchHint::kUnlikely,
            result.value()->branch_hints[1].GetHintFor(5));
}

class WasmSignatureDecodeTest : public TestWithZone {
 public:
  WasmEnabledFeatures enabled_features_ = WasmEnabledFeatures::None();

  const FunctionSig* DecodeSig(base::Vector<const uint8_t> bytes) {
    Result<const FunctionSig*> res =
        DecodeWasmSignatureForTesting(enabled_features_, zone(), bytes);
    EXPECT_TRUE(res.ok()) << res.error().message() << " at offset "
                          << res.error().offset();
    return res.ok() ? res.value() : nullptr;
  }

  V8_NODISCARD testing::AssertionResult DecodeSigError(
      base::Vector<const uint8_t> bytes) {
    Result<const FunctionSig*> res =
        DecodeWasmSignatureForTesting(enabled_features_, zone(), bytes);
    if (res.ok()) {
      return testing::AssertionFailure() << "unexpected valid signature";
    }
    return testing::AssertionSuccess();
  }
};

TEST_F(WasmSignatureDecodeTest, Ok_v_v) {
  static const uint8_t data[] = {SIG_ENTRY_v_v};
  v8::internal::AccountingAllocator allocator;
  Zone zone(&allocator, ZONE_NAME);
  const FunctionSig* sig = DecodeSig(base::ArrayVector(data));

  ASSERT_TRUE(sig != nullptr);
  EXPECT_EQ(0u, sig->parameter_count());
  EXPECT_EQ(0u, sig->return_count());
}

TEST_F(WasmSignatureDecodeTest, Ok_t_v) {
  WASM_FEATURE_SCOPE(stringref);
  WASM_FEATURE_SCOPE(exnref);
  for (size_t i = 0; i < arraysize(kValueTypes); i++) {
    ValueTypePair ret_type = kValueTypes[i];
    const uint8_t data[] = {SIG_ENTRY_x(ret_type.code)};
    const FunctionSig* sig = DecodeSig(base::ArrayVector(data));

    SCOPED_TRACE("Return type " + ret_type.type.name());
    ASSERT_TRUE(sig != nullptr);
    EXPECT_EQ(0u, sig->parameter_count());
    EXPECT_EQ(1u, sig->return_count());
    EXPECT_EQ(ret_type.type, sig->GetReturn());
  }
}

TEST_F(WasmSignatureDecodeTest, Ok_v_t) {
  WASM_FEATURE_SCOPE(stringref);
  WASM_FEATURE_SCOPE(exnref);
  for (size_t i = 0; i < arraysize(kValueTypes); i++) {
    ValueTypePair param_type = kValueTypes[i];
    const uint8_t data[] = {SIG_ENTRY_v_x(param_type.code)};
    const FunctionSig* sig = DecodeSig(base::ArrayVector(data));

    SCOPED_TRACE("Param type " + param_type.type.name());
    ASSERT_TRUE(sig != nullptr);
    EXPECT_EQ(1u, sig->parameter_count());
    EXPECT_EQ(0u, sig->return_count());
    EXPECT_EQ(param_type.type, sig->GetParam(0));
  }
}

TEST_F(WasmSignatureDecodeTest, Ok_t_t) {
  WASM_FEATURE_SCOPE(stringref);
  WASM_FEATURE_SCOPE(exnref);
  for (size_t i = 0; i < arraysize(kValueTypes); i++) {
    ValueTypePair ret_type = kValueTypes[i];
    for (size_t j = 0; j < arraysize(kValueTypes); j++) {
      ValueTypePair param_type = kValueTypes[j];
      const uint8_t data[] = {SIG_ENTRY_x_x(ret_type.code, param_type.code)};
      const FunctionSig* sig = DecodeSig(base::ArrayVector(data));

      SCOPED_TRACE("Param type " + param_type.type.name());
      ASSERT_TRUE(sig != nullptr);
      EXPECT_EQ(1u, sig->parameter_count());
      EXPECT_EQ(1u, sig->return_count());
      EXPECT_EQ(param_type.type, sig->GetParam(0));
      EXPECT_EQ(ret_type.type, sig->GetReturn());
    }
  }
}

TEST_F(WasmSignatureDecodeTest, Ok_i_tt) {
  WASM_FEATURE_SCOPE(stringref);
  WASM_FEATURE_SCOPE(exnref);
  for (size_t i = 0; i < arraysize(kValueTypes); i++) {
    ValueTypePair p0_type = kValueTypes[i];
    for (size_t j = 0; j < arraysize(kValueTypes); j++) {
      ValueTypePair p1_type = kValueTypes[j];
      const uint8_t data[] = {
          SIG_ENTRY_x_xx(kI32Code, p0_type.code, p1_type.code)};
      const FunctionSig* sig = DecodeSig(base::ArrayVector(data));

      SCOPED_TRACE("Signature i32(" + p0_type.type.name() + ", " +
                   p1_type.type.name() + ")");
      ASSERT_TRUE(sig != nullptr);
      EXPECT_EQ(2u, sig->parameter_count());
      EXPECT_EQ(1u, sig->return_count());
      EXPECT_EQ(p0_type.type, sig->GetParam(0));
      EXPECT_EQ(p1_type.type, sig->GetParam(1));
    }
  }
}

TEST_F(WasmSignatureDecodeTest, Ok_tt_tt) {
  WASM_FEATURE_SCOPE(stringref);
  WASM_FEATURE_SCOPE(exnref);
  for (size_t i = 0; i < arraysize(kValueTypes); i++) {
    ValueTypePair p0_type = kValueTypes[i];
    for (size_t j = 0; j < arraysize(kValueTypes); j++) {
      ValueTypePair p1_type = kValueTypes[j];
      const uint8_t data[] = {SIG_ENTRY_xx_xx(p0_type.code, p1_type.code,
                                              p0_type.code, p1_type.code)};
      const FunctionSig* sig = DecodeSig(base::ArrayVector(data));

      SCOPED_TRACE("p0 = " + p0_type.type.name() +
                   ", p1 = " + p1_type.type.name());
      ASSERT_TRUE(sig != nullptr);
      EXPECT_EQ(2u, sig->parameter_count());
      EXPECT_EQ(2u, sig->return_count());
      EXPECT_EQ(p0_type.type, sig->GetParam(0));
      EXPECT_EQ(p1_type.type, sig->GetParam(1));
      EXPECT_EQ(p0_type.type, sig->GetReturn(0));
      EXPECT_EQ(p1_type.type, sig->GetReturn(1));
    }
  }
}

TEST_F(WasmSignatureDecodeTest, Simd) {
  const uint8_t data[] = {SIG_ENTRY_x(kS128Code)};
  if (!CheckHardwareSupportsSimd()) {
    EXPECT_TRUE(DecodeSigError(base::ArrayVector(data)))
        << "Type S128 should not be allowed on this hardware";
  } else {
    const FunctionSig* sig = DecodeSig(base::ArrayVector(data));
    ASSERT_TRUE(sig != nullptr);
    EXPECT_EQ(0u, sig->parameter_count());
    EXPECT_EQ(1u, sig->return_count());
    EXPECT_EQ(kWasmS128, sig->GetReturn());
  }
}

TEST_F(WasmSignatureDecodeTest, TooManyParams) {
  static const uint8_t data[] = {kWasmFunctionTypeCode,
                                 WASM_I32V_3(kV8MaxWasmFunctionParams + 1),
                                 kI32Code, 0};
  EXPECT_TRUE(DecodeSigError(base::ArrayVector(data)));
}

TEST_F(WasmSignatureDecodeTest, TooManyReturns) {
  for (int i = 0; i < 2; i++) {
    uint8_t data[] = {kWasmFunctionTypeCode, 0,
                      WASM_I32V_3(kV8MaxWasmFunctionReturns + 1), kI32Code};
    EXPECT_TRUE(DecodeSigError(base::ArrayVector(data)));
  }
}

TEST_F(WasmSignatureDecodeTest, Fail_off_end) {
  uint8_t data[256];
  for (int p = 0; p <= 255; p = p + 1 + p * 3) {
    for (int i = 0; i <= p; i++) data[i] = kI32Code;
    data[0] = static_cast<uint8_t>(p);

    for (int i = 0; i < p + 1; i++) {
      // Should fall off the end for all signatures.
      EXPECT_TRUE(DecodeSigError(base::ArrayVector(data)));
    }
  }
}

TEST_F(WasmSignatureDecodeTest, Fail_invalid_type) {
  uint8_t kInvalidType = 76;
  for (size_t i = 0;; i++) {
    uint8_t data[] = {SIG_ENTRY_x_xx(kI32Code, kI32Code, kI32Code)};
    if (i >= arraysize(data)) break;
    data[i] = kInvalidType;
    EXPECT_TRUE(DecodeSigError(base::ArrayVector(data)));
  }
}

TEST_F(WasmSignatureDecodeTest, Fail_invalid_ret_type1) {
  static const uint8_t data[] = {SIG_ENTRY_x_x(kVoidCode, kI32Code)};
  EXPECT_TRUE(DecodeSigError(base::ArrayVector(data)));
}

TEST_F(WasmSignatureDecodeTest, Fail_invalid_param_type1) {
  static const uint8_t data[] = {SIG_ENTRY_x_x(kI32Code, kVoidCode)};
  EXPECT_TRUE(DecodeSigError(base::ArrayVector(data)));
}

TEST_F(WasmSignatureDecodeTest, Fail_invalid_param_type2) {
  static const uint8_t data[] = {SIG_ENTRY_x_xx(kI32Code, kI32Code, kVoidCode)};
  EXPECT_TRUE(DecodeSigError(base::ArrayVector(data)));
}

class WasmFunctionVerifyTest : public TestWithIsolateAndZone {
 public:
  FunctionResult DecodeWasmFunction(
      ModuleWireBytes wire_bytes, const WasmModule* module,
      base::Vector<const uint8_t> function_bytes) {
    return DecodeWasmFunctionForTesting(WasmEnabledFeatures::All(), zone(),
                                        wire_bytes, module, function_bytes);
  }
};

TEST_F(WasmFunctionVerifyTest, Ok_v_v_empty) {
  static const uint8_t data[] = {
      SIG_ENTRY_v_v,  // signature entry
      4,              // locals
      3,
      kI32Code,  // --
      4,
      kI64Code,  // --
      5,
      kF32Code,  // --
      6,
      kF64Code,  // --
      kExprEnd   // body
  };

  WasmModule module;
  FunctionResult result =
      DecodeWasmFunction(ModuleWireBytes({}), &module, base::ArrayVector(data));
  EXPECT_OK(result);

  if (result.value() && result.ok()) {
    WasmFunction* function = result.value().get();
    EXPECT_EQ(0u, function->sig->parameter_count());
    EXPECT_EQ(0u, function->sig->return_count());
    EXPECT_EQ(COUNT_ARGS(SIG_ENTRY_v_v), function->code.offset());
    EXPECT_EQ(sizeof(data), function->code.end_offset());
    // TODO(titzer): verify encoding of local declarations
  }
}

TEST_F(WasmModuleVerifyTest, SectionWithoutNameLength) {
  const uint8_t data[] = {1};
  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, EmptyCustomSectionIsInvalid) {
  // An empty custom section is invalid, because at least one byte for the
  // length of the custom section name is required.
  const uint8_t data[] = {
      0,  // unknown section code.
      0   // section length.
  };
  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, TheLoneliestOfValidModulesTheTrulyEmptyOne) {
  const uint8_t data[] = {
      0,  // unknown section code.
      1,  // section length, only one byte for the name length.
      0,  // string length of 0.
          // Empty section name, no content, nothing but sadness.
  };
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, OnlyUnknownSectionEmpty) {
  const uint8_t data[] = {
      UNKNOWN_SECTION(0),
  };
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, OnlyUnknownSectionNonEmpty) {
  const uint8_t data[] = {
      UNKNOWN_SECTION(5),
      0xFF,
      0xFF,
      0xFF,
      0xFF,
      0xFF,  // section data
  };
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, SignatureFollowedByEmptyUnknownSection) {
  const uint8_t data[] = {
      // signatures
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      // -----------------------------------------------------------
      UNKNOWN_SECTION(0)};
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, SignatureFollowedByUnknownSection) {
  const uint8_t data[] = {
      // signatures
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      // -----------------------------------------------------------
      UNKNOWN_SECTION(5),
      0xFF,
      0xFF,
      0xFF,
      0xFF,
      0xFF,
  };
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, UnknownSectionOverflow) {
  static const uint8_t data[] = {
      UNKNOWN_SECTION(9),
      1,
      2,
      3,
      4,
      5,
      6,
      7,
      8,
      9,
      10,  // 10 byte section
  };
  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, UnknownSectionUnderflow) {
  static const uint8_t data[] = {
      UNKNOWN_SECTION(333),
      1,
      2,
      3,
      4,  // 4 byte section
  };
  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, UnknownSectionSkipped) {
  static const uint8_t data[] = {
      UNKNOWN_SECTION(1),
      0,  // one byte section
      SECTION(Global, ENTRY_COUNT(1),
              kI32Code,                    // memory type
              0,                           // exported
              WASM_INIT_EXPR_I32V_1(33)),  // init
  };
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);

  EXPECT_EQ(1u, result.value()->globals.size());
  EXPECT_EQ(0u, result.value()->functions.size());
  EXPECT_EQ(0u, result.value()->data_segments.size());

  const WasmGlobal* global = &result.value()->globals.back();

  EXPECT_EQ(kWasmI32, global->type);
  EXPECT_EQ(0u, global->offset);
}

TEST_F(WasmModuleVerifyTest, ImportTable_empty) {
  static const uint8_t data[] = {SECTION(Type, ENTRY_COUNT(0)),
                                 SECTION(Import, ENTRY_COUNT(0))};
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, ImportTable_nosigs1) {
  static const uint8_t data[] = {SECTION(Import, ENTRY_COUNT(0))};
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, ImportTable_mutable_global) {
  {
    static const uint8_t data[] = {
        SECTION(Import,           // section header
                ENTRY_COUNT(1),   // number of imports
                ADD_COUNT('m'),   // module name
                ADD_COUNT('f'),   // global name
                kExternalGlobal,  // import kind
                kI32Code,         // type
                0),               // mutability
    };
    EXPECT_VERIFIES(data);
  }
  {
    static const uint8_t data[] = {
        SECTION(Import,           // section header
                ENTRY_COUNT(1),   // sig table
                ADD_COUNT('m'),   // module name
                ADD_COUNT('f'),   // global name
                kExternalGlobal,  // import kind
                kI32Code,         // type
                1),               // mutability
    };
    EXPECT_VERIFIES(data);
  }
}

TEST_F(WasmModuleVerifyTest, ImportTable_mutability_malformed) {
  static const uint8_t data[] = {
      SECTION(Import,
              ENTRY_COUNT(1),   // --
              ADD_COUNT('m'),   // module name
              ADD_COUNT('g'),   // global name
              kExternalGlobal,  // import kind
              kI32Code,         // type
              2),               // invalid mutability
  };
  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, ImportTable_nosigs2) {
  static const uint8_t data[] = {
      SECTION(Import, ENTRY_COUNT(1),  // sig table
              ADD_COUNT('m'),          // module name
              ADD_COUNT('f'),          // function name
              kExternalFunction,       // import kind
              SIG_INDEX(0)),           // sig index
  };
  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, ImportTable_invalid_sig) {
  static const uint8_t data[] = {
      SECTION(Type, ENTRY_COUNT(0)),   // --
      SECTION(Import, ENTRY_COUNT(1),  // --
              ADD_COUNT('m'),          // module name
              ADD_COUNT('f'),          // function name
              kExternalFunction,       // import kind
              SIG_INDEX(0)),           // sig index
  };
  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, ImportTable_one_sig) {
  static const uint8_t data[] = {
      // signatures
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      SECTION(Import,
              ENTRY_COUNT(1),     // --
              ADD_COUNT('m'),     // module name
              ADD_COUNT('f'),     // function name
              kExternalFunction,  // import kind
              SIG_INDEX(0)),      // sig index
  };
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, ImportTable_invalid_module) {
  static const uint8_t data[] = {
      // signatures
      TYPE_SECTION_ONE_SIG_VOID_VOID,  // --
      SECTION(Import,                  // --
              ENTRY_COUNT(1),          // --
              NO_NAME,                 // module name
              ADD_COUNT('f'),          // function name
              kExternalFunction,       // import kind
              SIG_INDEX(0),            // sig index
              0),                      // auxiliary data
  };
  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, ImportTable_off_end) {
  static const uint8_t data[] = {
      // signatures
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      SECTION(Import, ENTRY_COUNT(1),
              ADD_COUNT('m'),      // module name
              ADD_COUNT('f'),      // function name
              kExternalFunction),  // import kind
      SIG_INDEX(0),                // sig index (outside import section!)
  };

  EXPECT_OFF_END_FAILURE(data, arraysize(data) - 3);
}

TEST_F(WasmModuleVerifyTest, ExportTable_empty1) {
  static const uint8_t data[] = {                                 // signatures
                                 TYPE_SECTION_ONE_SIG_VOID_VOID,  // --
                                 ONE_EMPTY_FUNCTION(SIG_INDEX(0)),
                                 SECTION(Export, ENTRY_COUNT(0)),  // --
                                 ONE_EMPTY_BODY};

  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);

  EXPECT_EQ(1u, result.value()->functions.size());
  EXPECT_EQ(0u, result.value()->export_table.size());
}

TEST_F(WasmModuleVerifyTest, ExportTable_empty2) {
  static const uint8_t data[] = {SECTION(Type, ENTRY_COUNT(0)),
                                 SECTION(Export, ENTRY_COUNT(0))};
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, ExportTable_NoFunctions2) {
  static const uint8_t data[] = {SECTION(Export, ENTRY_COUNT(0))};
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, ExportTableOne) {
  static const uint8_t data[] = {
      // signatures
      TYPE_SECTION_ONE_SIG_VOID_VOID, ONE_EMPTY_FUNCTION(SIG_INDEX(0)),
      SECTION(Export,
              ENTRY_COUNT(1),     // exports
              NO_NAME,            // --
              kExternalFunction,  // --
              FUNC_INDEX(0)),     // --
      ONE_EMPTY_BODY};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);

  EXPECT_EQ(1u, result.value()->functions.size());
  EXPECT_EQ(1u, result.value()->export_table.size());
}

TEST_F(WasmModuleVerifyTest, ExportNameWithInvalidStringLength) {
  static const uint8_t data[] = {
      // signatures
      TYPE_SECTION_ONE_SIG_VOID_VOID, ONE_EMPTY_FUNCTION(SIG_INDEX(0)),
      SECTION(Export,
              ENTRY_COUNT(1),     // exports
              U32V_1(84),         // invalid string length
              'e',                // --
              kExternalFunction,  // --
              FUNC_INDEX(0),      // --
              0, 0, 0)            // auxiliary data
  };

  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, ExportTableTwo) {
  static const uint8_t data[] = {
      // signatures
      TYPE_SECTION_ONE_SIG_VOID_VOID, ONE_EMPTY_FUNCTION(SIG_INDEX(0)),
      SECTION(Export,
              ENTRY_COUNT(2),                 // exports
              ADD_COUNT('n', 'a', 'm', 'e'),  // --
              kExternalFunction,              // --
              FUNC_INDEX(0),                  // --
              ADD_COUNT('n', 'o', 'm'),       // --
              kExternalFunction,              // --
              FUNC_INDEX(0)),                 // --
      ONE_EMPTY_BODY};

  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);

  EXPECT_EQ(1u, result.value()->functions.size());
  EXPECT_EQ(2u, result.value()->export_table.size());
}

TEST_F(WasmModuleVerifyTest, ExportTableThree) {
  static const uint8_t data[] = {
      // signatures
      TYPE_SECTION_ONE_SIG_VOID_VOID, THREE_EMPTY_FUNCTIONS(SIG_INDEX(0)),
      SECTION(Export,
              ENTRY_COUNT(3),  // exports
              ADD_COUNT('a'),  // --
              kExternalFunction,
              FUNC_INDEX(0),   // --
              ADD_COUNT('b'),  // --
              kExternalFunction,
              FUNC_INDEX(1),   // --
              ADD_COUNT('c'),  // --
              kExternalFunction,
              FUNC_INDEX(2)),  // --
      THREE_EMPTY_BODIES};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_OK(result);

  EXPECT_EQ(3u, result.value()->functions.size());
  EXPECT_EQ(3u, result.value()->export_table.size());
}

TEST_F(WasmModuleVerifyTest, ExportTableThreeOne) {
  for (int i = 0; i < 6; i++) {
    const uint8_t data[] = {
        // signatures
        TYPE_SECTION_ONE_SIG_VOID_VOID, THREE_EMPTY_FUNCTIONS(SIG_INDEX(0)),
        SECTION(Export,
                ENTRY_COUNT(1),       // exports
                ADD_COUNT('e', 'x'),  // --
                kExternalFunction,
                FUNC_INDEX(i)),  // --
        THREE_EMPTY_BODIES};

    if (i < 3) {
      EXPECT_VERIFIES(data);
    } else {
      EXPECT_FAILURE(data);
    }
  }
}

TEST_F(WasmModuleVerifyTest, ExportTableOne_off_end) {
  static const uint8_t data[] = {
      // signatures
      TYPE_SECTION_ONE_SIG_VOID_VOID, ONE_EMPTY_FUNCTION(SIG_INDEX(0)),
      SECTION(Export,
              ENTRY_COUNT(1),  // exports
              NO_NAME,         // --
              kExternalFunction,
              FUNC_INDEX(0),  // --
              0, 0, 0)        // auxiliary data
  };

  EXPECT_OFF_END_FAILURE(data, arraysize(data) - 3);
}

TEST_F(WasmModuleVerifyTest, Regression_648070) {
  static const uint8_t data[] = {
      SECTION(Type, ENTRY_COUNT(0)),         // --
      SECTION(Function, U32V_5(3500228624))  // function count = 3500228624
  };                                         // --
  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, Regression_738097) {
  // The function body size caused an integer overflow in the module decoder.
  static const uint8_t data[] = {
      TYPE_SECTION(1, SIG_ENTRY_v_v),  // --
      FUNCTION_SECTION(1, 0),          // --
      SECTION(Code,                    // --
              ENTRY_COUNT(1),          // --
              U32V_5(0xFFFFFFFF),      // function size,
              0)                       // No real body
  };
  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, FunctionBodySizeLimit) {
  const uint32_t delta = 3;
  for (uint32_t body_size = kV8MaxWasmFunctionSize - delta;
       body_size < kV8MaxWasmFunctionSize + delta; body_size++) {
    uint8_t data[] = {
        TYPE_SECTION(1, SIG_ENTRY_v_v),  // --
        FUNCTION_SECTION(1, 0),          // --
        kCodeSectionCode,                // code section
        U32V_5(1 + body_size + 5),       // section size
        1,                               // # functions
        U32V_5(body_size)                // body size
    };
    size_t total = sizeof(data) + body_size;
    uint8_t* buffer = reinterpret_cast<uint8_t*>(calloc(1, total));
    memcpy(buffer, data, sizeof(data));
    ModuleResult result = DecodeModule(base::VectorOf(buffer, total));
    if (body_size <= kV8MaxWasmFunctionSize) {
      EXPECT_TRUE(result.ok());
    } else {
      EXPECT_FALSE(result.ok());
    }
    free(buffer);
  }
}

TEST_F(WasmModuleVerifyTest, IllegalTypeCode) {
  static const uint8_t data[] = {TYPE_SECTION(1, SIG_ENTRY_v_x(0x41))};
  EXPECT_FAILURE_WITH_MSG(data, "invalid value type");
}

TEST_F(WasmModuleVerifyTest, FunctionBodies_empty) {
  static const uint8_t data[] = {
      EMPTY_TYPE_SECTION,            // --
      EMPTY_FUNCTION_SECTION,        // --
      EMPTY_FUNCTION_BODIES_SECTION  // --
  };
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, FunctionBodies_one_empty) {
  static const uint8_t data[] = {
      TYPE_SECTION(1, SIG_ENTRY_v_v),  // --
      FUNCTION_SECTION(1, 0),          // --
      ONE_EMPTY_BODY                   // --
  };
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, FunctionBodies_one_nop) {
  static const uint8_t data[] = {
      TYPE_SECTION(1, SIG_ENTRY_v_v),          // --
      FUNCTION_SECTION(1, 0),                  // --
      SECTION(Code, ENTRY_COUNT(1), NOP_BODY)  // --
  };
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, FunctionBodies_count_mismatch1) {
  static const uint8_t data[] = {
      TYPE_SECTION(1, SIG_ENTRY_v_v),  // --
      FUNCTION_SECTION(2, 0, 0),       // --
      ONE_EMPTY_BODY                   // --
  };
  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, FunctionBodies_count_mismatch2) {
  static const uint8_t data[] = {
      TYPE_SECTION(1, SIG_ENTRY_v_v),                    // --
      FUNCTION_SECTION(1, 0),                            // --
      SECTION(Code, ENTRY_COUNT(2), NOP_BODY, NOP_BODY)  // --
  };
  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, Names_empty) {
  static const uint8_t data[] = {EMPTY_TYPE_SECTION, EMPTY_FUNCTION_SECTION,
                                 EMPTY_FUNCTION_BODIES_SECTION,
                                 EMPTY_NAMES_SECTION};
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, Names_one_empty) {
  // TODO(wasm): This test does not test anything (corrupt name section does not
  // fail validation).
  static const uint8_t data[] = {
      TYPE_SECTION(1, SIG_ENTRY_v_v),                            // --
      FUNCTION_SECTION(1, 0),                                    // --
      ONE_EMPTY_BODY,                                            // --
      SECTION_NAMES(ENTRY_COUNT(1), FOO_STRING, NO_LOCAL_NAMES)  // --
  };
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, Names_two_empty) {
  // TODO(wasm): This test does not test anything (corrupt name section does not
  // fail validation).
  static const uint8_t data[] = {
      TYPE_SECTION(1, SIG_ENTRY_v_v),             // --
      FUNCTION_SECTION(2, 0, 0),                  // --
      TWO_EMPTY_BODIES,                           // --
      SECTION_NAMES(ENTRY_COUNT(2),               // --
                    FOO_STRING, NO_LOCAL_NAMES,   // --
                    FOO_STRING, NO_LOCAL_NAMES),  // --
  };
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, Regression684855) {
  static const uint8_t data[] = {
      SECTION_NAMES(0xFB,  // functions count
                    0x27,  // |
                    0x00,  // function name length
                    0xFF,  // local names count
                    0xFF,  // |
                    0xFF,  // |
                    0xFF,  // |
                    0xFF,  // |
                    0xFF,  // error: "varint too large"
                    0xFF,  // |
                    0x00,  // --
                    0x00)  // --
  };
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, FunctionSectionWithoutCodeSection) {
  static const uint8_t data[] = {
      TYPE_SECTION(1, SIG_ENTRY_v_v),  // Type section.
      FUNCTION_SECTION(1, 0),          // Function section.
  };
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_NOT_OK(result, "function count is 1, but code section is absent");
}

TEST_F(WasmModuleVerifyTest, CodeSectionWithoutFunctionSection) {
  static const uint8_t data[] = {ONE_EMPTY_BODY};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_NOT_OK(result, "function body count 1 mismatch (0 expected)");
}

TEST_F(WasmModuleVerifyTest, EmptyFunctionSectionWithoutCodeSection) {
  static const uint8_t data[] = {SECTION(Function, ENTRY_COUNT(0))};
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, DoubleNonEmptyFunctionSection) {
  // Regression test for https://crbug.com/1342274.
  static const uint8_t data[] = {TYPE_SECTION(1, SIG_ENTRY_v_v),  // --
                                 FUNCTION_SECTION(1, 0),          // --
                                 FUNCTION_SECTION(1, 0)};
  EXPECT_FAILURE(data);
}

TEST_F(WasmModuleVerifyTest, EmptyCodeSectionWithoutFunctionSection) {
  static const uint8_t data[] = {SECTION(Code, ENTRY_COUNT(0))};
  EXPECT_VERIFIES(data);
}

// TODO(manoskouk): Reintroduce tests deleted in
// https://chromium-review.googlesource.com/c/v8/v8/+/2972910 in some other
// form.

TEST_F(WasmModuleVerifyTest, Multiple_Named_Sections) {
  static const uint8_t data[] = {
      SECTION(Unknown, ADD_COUNT('X'), 17, 18),                    // --
      SECTION(Unknown, ADD_COUNT('f', 'o', 'o'), 5, 6, 7, 8, 9),   // --
      SECTION(Unknown, ADD_COUNT('o', 't', 'h', 'e', 'r'), 7, 8),  // --
  };
  EXPECT_VERIFIES(data);
}

TEST_F(WasmModuleVerifyTest, Section_Name_No_UTF8) {
  static const uint8_t data[] = {SECTION(Unknown, 1, 0xFF, 17, 18)};
  EXPECT_FAILURE(data);
}

class WasmModuleCustomSectionTest : public TestWithIsolateAndZone {
 public:
  void CheckSections(base::Vector<const uint8_t> wire_bytes,
                     const CustomSectionOffset* expected, size_t num_expected) {
    std::vector<CustomSectionOffset> custom_sections =
        DecodeCustomSections(wire_bytes);

    CHECK_EQ(num_expected, custom_sections.size());

    for (size_t i = 0; i < num_expected; i++) {
      EXPECT_EQ(expected[i].section.offset(),
                custom_sections[i].section.offset());
      EXPECT_EQ(expected[i].section.length(),
                custom_sections[i].section.length());
      EXPECT_EQ(expected[i].name.offset(), custom_sections[i].name.offset());
      EXPECT_EQ(expected[i].name.length(), custom_sections[i].name.length());
      EXPECT_EQ(expected[i].payload.offset(),
                custom_sections[i].payload.offset());
      EXPECT_EQ(expected[i].payload.length(),
                custom_sections[i].payload.length());
    }
  }
};

TEST_F(WasmModuleCustomSectionTest, ThreeUnknownSections) {
  static constexpr uint8_t data[] = {
      U32_LE(kWasmMagic),                                  // --
      U32_LE(kWasmVersion),                                // --
      SECTION(Unknown, 1, 'X', 17, 18),                    // --
      SECTION(Unknown, 3, 'f', 'o', 'o', 5, 6, 7, 8, 9),   // --
      SECTION(Unknown, 5, 'o', 't', 'h', 'e', 'r', 7, 8),  // --
  };

  static const CustomSectionOffset expected[] = {
      // section, name, payload
      {{10, 4}, {11, 1}, {12, 2}},  // --
      {{16, 9}, {17, 3}, {20, 5}},  // --
      {{27, 8}, {28, 5}, {33, 2}},  // --
  };

  CheckSections(base::ArrayVector(data), expected, arraysize(expected));
}

TEST_F(WasmModuleCustomSectionTest, TwoKnownTwoUnknownSections) {
  static const uint8_t data[] = {
      U32_LE(kWasmMagic),                                          // --
      U32_LE(kWasmVersion),                                        // --
      TYPE_SECTION(2, SIG_ENTRY_v_v, SIG_ENTRY_v_v),               // --
      SECTION(Unknown, ADD_COUNT('X'), 17, 18),                    // --
      ONE_EMPTY_FUNCTION(SIG_INDEX(0)),                            // --
      SECTION(Unknown, ADD_COUNT('o', 't', 'h', 'e', 'r'), 7, 8),  // --
  };

  static const CustomSectionOffset expected[] = {
      // section, name, payload
      {{19, 4}, {20, 1}, {21, 2}},  // --
      {{29, 8}, {30, 5}, {35, 2}},  // --
  };

  CheckSections(base::ArrayVector(data), expected, arraysize(expected));
}

TEST_F(WasmModuleVerifyTest, SourceMappingURLSection) {
  static const uint8_t data[] = {
      WASM_MODULE_HEADER,
      SECTION_SRC_MAP('s', 'r', 'c', '/', 'x', 'y', 'z', '.', 'c')};
  ModuleResult result = DecodeModuleNoHeader(base::ArrayVector(data));
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(3u, result.value()->debug_symbols.size());
  EXPECT_EQ(
      WasmDebugSymbols::Type::SourceMap,
      result.value()->debug_symbols[WasmDebugSymbols::Type::SourceMap].type);
  EXPECT_EQ(WasmDebugSymbols::Type::None,
            result.value()
                ->debug_symbols[WasmDebugSymbols::Type::EmbeddedDWARF]
                .type);
  EXPECT_EQ(WasmDebugSymbols::Type::None,
            result.value()
                ->debug_symbols[WasmDebugSymbols::Type::ExternalDWARF]
                .type);
  ModuleWireBytes wire_bytes(base::ArrayVector(data));
  WasmName external_url = wire_bytes.GetNameOrNull(
      result.value()
          ->debug_symbols[WasmDebugSymbols::Type::SourceMap]
          .external_url);
  EXPECT_EQ("src/xyz.c", std::string(external_url.data(), external_url.size()));
}

TEST_F(WasmModuleVerifyTest, BadSourceMappingURLSection) {
  static const uint8_t data[] = {
      WASM_MODULE_HEADER,
      SECTION_SRC_MAP('s', 'r', 'c', '/', 'x', 0xff, 'z', '.', 'c')};
  ModuleResult result = DecodeModuleNoHeader(base::ArrayVector(data));
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(3u, result.value()->debug_symbols.size());
  for (size_t i = 0; i < result.value()->debug_symbols.size(); ++i) {
    EXPECT_EQ(WasmDebugSymbols::Type::None,
              result.value()->debug_symbols[i].type);
    EXPECT_EQ(0u, result.value()->debug_symbols[i].external_url.length());
  }
}

TEST_F(WasmModuleVerifyTest, MultipleSourceMappingURLSections) {
  static const uint8_t data[] = {WASM_MODULE_HEADER,
                                 SECTION_SRC_MAP('a', 'b', 'c'),
                                 SECTION_SRC_MAP('p', 'q', 'r')};
  ModuleResult result = DecodeModuleNoHeader(base::ArrayVector(data));
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(
      WasmDebugSymbols::Type::SourceMap,
      result.value()->debug_symbols[WasmDebugSymbols::Type::SourceMap].type);
  EXPECT_EQ(WasmDebugSymbols::Type::None,
            result.value()
                ->debug_symbols[WasmDebugSymbols::Type::EmbeddedDWARF]
                .type);
  EXPECT_EQ(WasmDebugSymbols::Type::None,
            result.value()
                ->debug_symbols[WasmDebugSymbols::Type::ExternalDWARF]
                .type);
  ModuleWireBytes wire_bytes(base::ArrayVector(data));
  WasmName external_url = wire_bytes.GetNameOrNull(
      result.value()
          ->debug_symbols[WasmDebugSymbols::Type::SourceMap]
          .external_url);
  EXPECT_EQ("abc", std::string(external_url.data(), external_url.size()));
}

TEST_F(WasmModuleVerifyTest, MultipleNameSections) {
  static const uint8_t data[] = {
      SECTION_NAMES(0, ADD_COUNT(ADD_COUNT('a', 'b', 'c'))),
      SECTION_NAMES(0, ADD_COUNT(ADD_COUNT('p', 'q', 'r', 's')))};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(3u, result.value()->name.length());
}

TEST_F(WasmModuleVerifyTest, BadNameSection) {
  static const uint8_t data[] = {SECTION_NAMES(
      0, ADD_COUNT(ADD_COUNT('s', 'r', 'c', '/', 'x', 0xff, 'z', '.', 'c')))};
  ModuleResult result = DecodeModule(base::ArrayVector(data));
  EXPECT_TRUE(result.ok());
  EXPECT_EQ(0u, result.value()->name.length());
}

TEST_F(WasmModuleVerifyTest, PassiveDataSegment) {
  static const uint8_t data[] = {
      // memory declaration ----------------------------------------------------
      SECTION(Memory, ENTRY_COUNT(1), kNoMaximum, 1),
      // data segments  --------------------------------------------------------
      SECTION(Data, ENTRY_COUNT(1), PASSIVE, ADD_COUNT('h', 'i')),
  };
  EXPECT_VERIFIES(data);
  EXPECT_OFF_END_FAILURE(data, arraysize(data) - 5);
}

TEST_F(WasmModuleVerifyTest, ActiveElementSegmentWithElements) {
  static const uint8_t data[] = {
      // sig#0 -----------------------------------------------------------------
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      // funcs -----------------------------------------------------------------
      ONE_EMPTY_FUNCTION(SIG_INDEX(0)),
      // table declaration -----------------------------------------------------
      SECTION(Table, ENTRY_COUNT(1), kFuncRefCode, kNoMaximum, 1),
      // element segments  -----------------------------------------------------
      SECTION(Element, ENTRY_COUNT(1), ACTIVE_WITH_ELEMENTS, TABLE_INDEX0,
              WASM_INIT_EXPR_I32V_1(0), kFuncRefCode, U32V_1(3),
              REF_FUNC_ELEMENT(0), REF_FUNC_ELEMENT(0), REF_NULL_ELEMENT),
      // code ------------------------------------------------------------------
      ONE_EMPTY_BODY};
  EXPECT_VERIFIES(data);
  EXPECT_OFF_END_FAILURE(data, arraysize(data) - 5);
}

TEST_F(WasmModuleVerifyTest, Table64ActiveElementSegmentWithElements) {
  WASM_FEATURE_SCOPE(memory64);
  for (bool enable_table64 : {false, true}) {
    for (bool use_table64 : {false, true}) {
      uint8_t const_opcode = use_table64 ? kExprI64Const : kExprI32Const;
      const uint8_t data[] = {
          // sig#0 -------------------------------------------------------
          TYPE_SECTION_ONE_SIG_VOID_VOID,
          // funcs -------------------------------------------------------
          ONE_EMPTY_FUNCTION(SIG_INDEX(0)),
          // table declaration -------------------------------------------
          SECTION(Table, ENTRY_COUNT(1), kFuncRefCode,
                  enable_table64 ? kMemory64WithMaximum : kWithMaximum, 20, 28),
          // element segments --------------------------------------------
          SECTION(Element, ENTRY_COUNT(1), ACTIVE_WITH_ELEMENTS, TABLE_INDEX0,
                  const_opcode, 0, kExprEnd, kFuncRefCode, U32V_1(3),
                  REF_FUNC_ELEMENT(0), REF_FUNC_ELEMENT(0), REF_NULL_ELEMENT),
          // code --------------------------------------------------------
          ONE_EMPTY_BODY};
      if (enable_table64 == use_table64) {
        EXPECT_VERIFIES(data);
      } else if (enable_table64) {
        EXPECT_FAILURE_WITH_MSG(data, "expected i64, got i32");
      } else {
        EXPECT_FAILURE_WITH_MSG(data, "expected i32, got i64");
      }
    }
  }
}

TEST_F(WasmModuleVerifyTest, PassiveElementSegment) {
  static const uint8_t data[] = {
      // sig#0 -----------------------------------------------------------------
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      // funcs -----------------------------------------------------------------
```