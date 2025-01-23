Response:
The user wants a summary of the functionality of the C++ code provided, which is a unit test file for the WASM module decoder in the V8 JavaScript engine.

Here's a breakdown of how to approach this:

1. **Identify the Core Purpose:** The filename `module-decoder-unittest.cc` clearly indicates this is a test suite for the module decoder. Unit tests focus on verifying individual components in isolation.

2. **Examine Test Case Names:** The `TEST_F` macros define individual test cases. The names of these tests are descriptive and provide clues about the specific scenarios being tested. Look for patterns in the naming. For example, many tests involve "ElementSection," "Table," "IndirectFunction," etc.

3. **Analyze the Test Structure:** Each test case generally follows a pattern:
    * **Setup (`static const uint8_t data[] = { ... }`):**  Defines a byte array representing a WASM module. These byte arrays are crafted to test specific aspects of the decoder.
    * **Action (`ModuleResult result = DecodeModule(base::ArrayVector(data));` or `EXPECT_VERIFIES(data);` or `EXPECT_FAILURE(data);`):**  Calls the `DecodeModule` function (or a helper like `EXPECT_VERIFIES` which implicitly decodes) to process the WASM module data.
    * **Assertions (`EXPECT_OK(result);`, `EXPECT_EQ(...)`, `EXPECT_FAILURE_WITH_MSG(...)`):** Verifies the outcome of the decoding process. These assertions check for success or failure, and in case of success, validate the parsed module structure (e.g., number of types, functions, tables). Failure tests often check for specific error messages.

4. **Categorize Functionality Based on Test Cases:** Group the test cases based on the WASM features or concepts they are testing. Common themes emerge, such as:
    * Table decoding (including different table types, sizes, and initialization)
    * Element section processing (linking functions to table entries, handling different table types, import/defined tables)
    * Indirect function calls
    * Global variable initialization
    * Error handling (invalid module structures, type mismatches)
    * Advanced features like compilation hints and branch hinting.

5. **Address Specific User Questions:**
    * **Functionality:**  Summarize the categories identified in step 4.
    * **.tq extension:** The prompt provides the information that `.tq` files are related to Torque, but this file is `.cc`, so it's C++.
    * **JavaScript relationship:** Explain how WASM relates to JavaScript (it runs in the same engine, can interact). Provide a simple example of calling a WASM function from JavaScript.
    * **Code logic inference:**  Choose a simple test case (like `OneIndirectFunction_one_entry`) and demonstrate how the input byte array leads to the expected output (module structure).
    * **Common programming errors:** Identify scenarios that trigger failure tests. These often represent common mistakes in WASM module creation (e.g., incorrect indices, type mismatches).
    * **Part 3 of 5:** Acknowledge this and focus on summarizing the functionality covered in this specific part of the file.

6. **Refine the Summary:**  Organize the summary logically, using clear and concise language. Avoid overly technical jargon where possible, or explain it if necessary.
这是对 `v8/test/unittests/wasm/module-decoder-unittest.cc` 源代码的功能归纳，重点是第3部分的内容。

**功能归纳 (第3部分):**

这部分代码主要集中在测试 WebAssembly 模块解码器中关于 **Table (表) 和 Element (元素)** 部分的功能，特别是涉及到以下几个方面：

1. **Table 的定义和验证:**
   - 测试定义不同类型的 Table，例如 `funcref` 和 `externref`。
   - 测试 Table 的大小限制 (`initial_size`, `maximum`)。
   - 测试声明多个 Table 的情况。
   - 测试 Table 类型是否可以为 `ref null`。
   - 测试 Table 是否可以有初始值 (initializer)。
   - 测试非 nullable 的 Table 必须有初始值。
   - 测试 Table 定义中非法类型的情况。

2. **Element Section 的处理和验证:**
   - 测试 Element Segment 如何初始化 Table 的条目。
   - 测试 Element Segment 可以针对多个 Table 进行初始化。
   - 测试 Element Segment 可以以任意顺序初始化多个 Table。
   - 测试 Element Segment 可以初始化导入的 Table 和模块定义的 Table。
   - 测试 Element Segment 中使用的函数索引是否有效。
   - 测试 Element Segment 初始化 `externref` 类型的 Table 时，如果尝试使用 `funcref` 类型的值会失败。
   - 测试 Element Segment 初始化类型更窄的 Table 时会失败（例如，尝试用 `funcref` 初始化 `(ref null 0)` 类型的 Table）。
   - 测试 Element Segment 可以用 `funcref null` 初始化 `funcref` 类型的 Table。
   - 测试 Element Segment 不能用 `externref null` 初始化 `funcref` 类型的 Table。
   - 测试 Element Segment 不能初始化导入的 `externref` 类型的 Table。
   - 测试 Element Segment 中使用 `global.get` 时，索引超出范围会失败。

3. **常量表达式的扩展验证:**
   - 测试在 Global 变量的初始化表达式中使用 `global.get` 和算术运算（`i32.add`, `i64.add` 等）。
   - 测试常量表达式中的类型错误会被检测出来。

4. **Indirect Function 调用相关的 Table 验证:**
   - 测试没有函数定义的模块中定义 Indirect Table 会失败。
   - 测试 Indirect Table 的索引超出函数定义范围会失败。

5. **其他功能:**
   - 测试模块中可以定义多个 Table，并验证其属性。
   - 测试可以定义指定类型的 Table，例如 `(ref null 0)`。
   - 测试可以定义带有编译提示 (Tiering Compilation Hints) 的模块。
   - 测试可以定义带有分支预测提示 (Branch Hinting) 的模块。

6. **Wasm Signature 的解码测试:**
   - 测试 Wasm 函数签名的正确解码，包括不同的参数和返回值类型组合。

**与 JavaScript 的关系 (Element Section):**

Element Section 定义了 Table 中初始的函数引用。在 JavaScript 中，可以通过 WebAssembly 的 Table 对象来访问和调用这些函数。

**JavaScript 示例:**

假设有一个 WASM 模块定义了一个 Table 并用 Element Section 初始化了一些函数，我们可以用 JavaScript 来获取 Table 对象，然后调用其中的函数：

```javascript
async function runWasm() {
  const response = await fetch('your_module.wasm'); // 假设你的 wasm 文件叫 your_module.wasm
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.instantiate(buffer);
  const instance = module.instance;

  // 假设 WASM 模块导出了一个名为 'myTable' 的 Table 对象
  const wasmTable = instance.exports.myTable;

  // 假设 Table 的第一个条目是一个函数
  const functionFromTable = wasmTable.get(0);

  // 调用 Table 中获取的函数
  if (functionFromTable) {
    functionFromTable(); // 假设该函数没有参数
  }
}

runWasm();
```

**代码逻辑推理 (OneIndirectFunction_one_entry):**

**假设输入 (data 数组):**

```c++
static const uint8_t data[] = {
    // sig#0 ---------------------------------------------------------------
    TYPE_SECTION_ONE_SIG_VOID_VOID, // 定义一个 void -> void 的函数签名
    // funcs ---------------------------------------------------------------
    ONE_EMPTY_FUNCTION(SIG_INDEX(0)), // 定义一个使用签名 #0 的空函数
    // table declaration ---------------------------------------------------
    SECTION(Table, ENTRY_COUNT(1), kFuncRefCode, kNoMaximum, 1), // 定义一个大小为 1 的 funcref 类型的 Table
    // elements ------------------------------------------------------------
    SECTION(Element,
            ENTRY_COUNT(1),  // entry count
            TABLE_INDEX0, WASM_INIT_EXPR_I32V_1(0),
            1,  // elements count
            FUNC_INDEX(0)), // 将函数索引 0 放入 Table 索引 0 的位置
    // code ----------------------------------------------------------------
    ONE_EMPTY_BODY}; // 定义一个空的 code section (虽然本例中没用到)
```

**预期输出:**

`DecodeModule` 函数应该成功解析这个模块，并且解析结果 `result.value()` 应该包含以下信息：

- `types.size()` 为 1 (一个函数签名)。
- `functions.size()` 为 1 (一个函数定义)。
- `tables.size()` 为 1 (一个 Table 定义)。
- `tables[0].initial_size` 为 1 (Table 的初始大小为 1)。

**用户常见的编程错误 (Element Section 初始化错误):**

一个常见的编程错误是在 Element Section 中尝试使用与 Table 类型不兼容的值进行初始化。

**示例:**

```c++
TEST_F(WasmModuleVerifyTest, ElementSectionInitExternRefTableWithFuncRef) {
  static const uint8_t data[] = {
      // sig#0 ---------------------------------------------------------------
      TYPE_SECTION_ONE_SIG_VOID_VOID,
      // funcs ---------------------------------------------------------------
      ONE_EMPTY_FUNCTION(SIG_INDEX(0)),
      // table declaration ---------------------------------------------------
      SECTION(Table, ENTRY_COUNT(2),          // section header
              kExternRefCode, kNoMaximum, 5,  // table 0 是 externref 类型
              kFuncRefCode, kNoMaximum, 9),   // table 1 是 funcref 类型
      // elements ------------------------------------------------------------
      SECTION(Element,
              ENTRY_COUNT(2),            // entry count
              TABLE_INDEX0,              // 针对 table 0
              WASM_INIT_EXPR_I32V_1(0),  // index
              1,                         // elements count
              FUNC_INDEX(0),             // 尝试用函数索引初始化 externref 类型的 table
              TABLE_INDEX(1),            // 针对 table 1
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
```

在这个例子中，`table 0` 被声明为 `externref` 类型，但是 Element Section 尝试用 `FUNC_INDEX(0)` (本质上是一个 `funcref`) 来初始化它，这将导致解码器报错，因为 `funcref` 不是 `externref` 的子类型。这是一个用户在手动创建 WASM 模块时容易犯的类型不匹配的错误。

### 提示词
```
这是目录为v8/test/unittests/wasm/module-decoder-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/wasm/module-decoder-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
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
    for (size_t j = 0; j <
```