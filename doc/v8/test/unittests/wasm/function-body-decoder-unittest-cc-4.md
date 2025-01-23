Response:
My thinking process to arrive at the summary of the provided C++ code went something like this:

1. **Identify the Core Purpose:** The file name `function-body-decoder-unittest.cc` immediately signals its purpose: testing the function body decoder. The `TEST_F` macros confirm that this is a unit test file. The "wasm" in the path further specifies that it's testing the WebAssembly function body decoder.

2. **Scan for Key Keywords and Patterns:** I looked for recurring patterns and keywords within the test cases. I noticed:
    * `TEST_F(FunctionBodyDecoderTest, ...)`:  Indicates individual test cases within the `FunctionBodyDecoderTest` fixture.
    * `builder.Add...`:  Suggests the setup of a WebAssembly module or function environment. Specifically, I saw `AddTable`, `AddPassiveElementSegment`, `AddDeclarativeElementSegment`, `AddFunction`, `AddStruct`, `AddArray`, `AddException`, and `AddLocals`. This points towards testing the decoder's ability to handle various WebAssembly constructs.
    * `ExpectValidates(...)`: This is a crucial indicator of a successful decoding and validation scenario. It implies the provided byte sequence represents a valid WebAssembly instruction sequence.
    * `ExpectFailure(...)`: This indicates a test case designed to ensure the decoder correctly identifies invalid or disallowed WebAssembly instruction sequences.
    * `WASM_...`: This prefix strongly suggests WebAssembly bytecode instructions. Examples include `WASM_MEMORY_INIT`, `WASM_TABLE_INIT`, `WASM_ELEM_DROP`, `WASM_REF_FUNC`, `WASM_TABLE_COPY`, `WASM_TABLE_GROW`, `WASM_TABLE_SIZE`, `WASM_TABLE_FILL`, `WASM_STRUCT_NEW`, `WASM_STRUCT_GET`, `WASM_STRUCT_SET`, `WASM_ARRAY_NEW`, `WASM_ARRAY_GET`, `WASM_ARRAY_SET`, `WASM_REF_EQ`, `WASM_REF_AS_NON_NULL`, `WASM_REF_NULL`, `WASM_REF_IS_NULL`, `WASM_BR_ON_NULL`, `WASM_BR_ON_NON_NULL`. These provide a direct insight into the specific WebAssembly features being tested.

3. **Categorize the Test Cases:**  Based on the `TEST_F` names and the WebAssembly instructions used within them, I started grouping the tests by the features they were exercising:
    * Memory operations (`MemoryInit`)
    * Table operations (`TableInit`, `TableCopy`, `TableGrow`, `TableSize`, `TableFill`)
    * Element segment operations (`ElemDrop`)
    * Reference types (`RefFuncDeclared`, `RefFuncUndeclared`, `RefEq`, `RefAsNonNull`, `RefNull`, `RefIsNull`, `BrOnNull`, `BrOnNonNull`)
    * Struct and Array operations (`StructOrArrayNewDefault`, `GCStruct`, `GCArray`, `UnpackPackedTypes`)
    * Local variables and initialization (`DefaultableLocal`, `NonDefaultableLocals`)

4. **Infer Functionality from Test Cases:** For each category, I analyzed what the `ExpectValidates` and `ExpectFailure` calls were testing. For instance, the `TableInit` tests check the correct usage of `table.init` with valid table and element segment indices, while the `TableInitWrongType` test ensures a type mismatch is caught. Similarly, the `NonDefaultableLocals` tests explore the decoder's handling of uninitialized local variables.

5. **Identify Connections to JavaScript (if any):**  While this specific code is C++ unit tests, the underlying features being tested directly relate to WebAssembly's functionality, which is tightly integrated with JavaScript in web browsers. I looked for WebAssembly features that have direct equivalents or close parallels in JavaScript. For example, WebAssembly tables and memory can be manipulated via JavaScript's `WebAssembly.Table` and `WebAssembly.Memory` objects. Reference types in WebAssembly have begun to be exposed in JavaScript as well.

6. **Construct Hypothetical Input and Output:** For test cases involving logic, I considered what inputs would lead to a successful validation (`ExpectValidates`) and what inputs would cause a failure (`ExpectFailure`). This helps illustrate the expected behavior of the decoder. For example, in `TableInit`, providing valid table and element segment indices should validate, while providing an out-of-bounds index should fail.

7. **Identify Common Programming Errors:**  The `ExpectFailure` test cases often highlight potential programming errors developers might make when writing WebAssembly. Examples include using incorrect indices, type mismatches, and accessing uninitialized variables.

8. **Synthesize a Summary:**  Finally, I combined my observations into a concise summary, focusing on the major areas of functionality being tested and the overall goal of the unit tests. I emphasized that the code validates the correct decoding and error detection capabilities of the function body decoder for various WebAssembly instructions and features. I also mentioned the connection to JavaScript and highlighted examples of potential programming errors. Because it was part 5 of 7, I also specifically noted that this section focuses on memory/table operations, reference types, and GC features (structs and arrays).

By following these steps, I could effectively analyze the C++ unit test code and extract its core functionalities and purpose. The focus was on understanding *what* the code was testing, not necessarily the intricate details of the C++ implementation itself.
好的，这是对提供的V8源代码片段（第5部分）的功能归纳：

**功能归纳：**

这个代码片段主要集中测试 V8 中 WebAssembly 函数体解码器对于以下 WebAssembly 特性的处理和验证：

* **内存操作指令:**
    * `memory.init`:  测试 `memory.init` 指令的正确解码和验证，包括合法的和非法的索引情况。
    * `memory.copy`: 测试 `memory.copy` 指令的正确解码和验证。
    * `memory.fill`: 测试 `memory.fill` 指令的正确解码和验证。

* **表格操作指令:**
    * `table.init`: 测试 `table.init` 指令的正确解码和验证，包括合法的和非法的表格索引、元素段索引以及类型匹配情况。
    * `elem.drop`: 测试 `elem.drop` 指令的正确解码和验证。
    * `table.copy`: 测试 `table.copy` 指令的正确解码和验证，包括同类型表格拷贝和跨类型表格拷贝（预期失败）。
    * `table.grow`: 测试 `table.grow` 指令的正确解码和验证，包括不同类型的表格增长，以及对表格索引的验证。
    * `table.size`: 测试 `table.size` 指令的正确解码和验证。
    * `table.fill`: 测试 `table.fill` 指令的正确解码和验证，包括不同类型的表格填充，以及对表格索引的验证。

* **引用类型相关指令:**
    * `ref.func`: 测试 `ref.func` 指令，包括对已声明和未声明函数索引的处理。
    * `ref.eq`: 测试 `ref.eq` 指令，用于比较引用类型的相等性，并验证其参数类型必须是 `eqref` 或 `(ref null shared eq)` 的子类型。
    * `ref.as_non_null`: 测试 `ref.as_non_null` 指令，用于将可空引用转换为不可空引用，并确保操作对象是引用类型。
    * `ref.null`: 测试 `ref.null` 指令，用于创建一个空引用，并验证其参数是有效的堆类型。
    * `ref.is_null`: 测试 `ref.is_null` 指令，用于检查引用是否为空，并确保操作对象是引用类型。
    * `br_on_null`: 测试 `br_on_null` 指令，当引用为空时进行分支跳转，并验证栈上的类型和分支目标。
    * `br_on_non_null`: 测试 `br_on_non_null` 指令，当引用非空时进行分支跳转，并验证栈上的类型和分支目标。

* **垃圾回收 (GC) 相关指令 (结构体和数组):**
    * `struct.new`: 测试 `struct.new` 指令，用于创建新的结构体实例，并验证参数类型和结构体索引。
    * `struct.get`: 测试 `struct.get` 指令，用于获取结构体字段的值，并验证字段索引和结构体类型。
    * `struct.set`: 测试 `struct.set` 指令，用于设置结构体字段的值，并验证字段索引、结构体类型和字段的可变性。
    * `struct.new_default`: 测试 `struct.new_default` 指令，用于创建具有默认值的结构体实例，并验证结构体字段是否可默认。
    * `array.new`: 测试 `array.new` 指令，用于创建新的数组实例，并验证初始化值类型和数组长度类型。
    * `array.get`: 测试 `array.get` 指令，用于获取数组元素的值，并验证索引类型和数组类型。
    * `array.set`: 测试 `array.set` 指令，用于设置数组元素的值，并验证索引类型、数组类型和元素类型。
    * `array.new_default`: 测试 `array.new_default` 指令，用于创建具有默认值的数组实例，并验证数组元素是否可默认。

* **局部变量:**
    * 测试可默认（defaultable）和不可默认（non-defaultable）的局部变量的声明和使用。重点测试了对不可默认局部变量的初始化和作用域管理，确保在使用前被正确赋值。

* **其他:**
    * `table.init` 指令处理声明式元素段（declarative element segment）的情况。
    * 元素段索引被解释为无符号数的情况。
    * 解包打包类型（unpack packed types）的支持，例如从 i8 和 i16 组成的结构体中提取值。

**与 JavaScript 的关系 (示例):**

这些 WebAssembly 指令在 JavaScript 中可以通过 `WebAssembly` API 进行操作，或者在 WebAssembly 模块内部被调用。 例如：

```javascript
// 假设你已经加载了一个 WebAssembly 模块实例
const instance = await WebAssembly.instantiateStreaming(fetch('module.wasm'));
const exports = instance.exports;

// 对应 WASM_MEMORY_INIT
const memory = exports.memory;
const buffer = new Uint8Array(memory.buffer);
buffer.fill(0); // 类似用 0 初始化内存

// 对应 WASM_TABLE_INIT (需要先在 WebAssembly 模块中定义 table 和 element segment)
// ...

// 对应 WASM_REF_FUNC
const wasmFunction = exports.exported_function; // 假设 WebAssembly 导出了一个函数

// 对应 WASM_STRUCT_NEW (需要 WebAssembly 的 GC 特性支持)
// 如果 WebAssembly 模块导出了创建结构体的方法，可以在 JavaScript 中调用
// 例如： const myStruct = exports.create_my_struct(10);

// 对应 WASM_ARRAY_NEW (需要 WebAssembly 的 GC 特性支持)
// 例如： const myArray = exports.create_my_array(5);
```

**代码逻辑推理 (假设输入与输出):**

以 `TEST_F(FunctionBodyDecoderTest, TableInit)` 为例：

**假设输入 (WebAssembly 字节码):**

```
// 假设 builder 已经添加了一个 table 和一个 passive element segment
WASM_TABLE_INIT(0, 0, WASM_ZERO, WASM_ZERO, WASM_ZERO)
```

**预期输出 (验证结果):**

`ExpectValidates` 会成功，因为提供的字节码代表了一个合法的 `table.init` 指令，它将索引为 0 的元素段的内容初始化到索引为 0 的表格中，偏移量和初始化长度都为 0。

**假设输入 (非法的 WebAssembly 字节码):**

```
// 假设 builder 只添加了一个 table，而这里尝试初始化到索引为 1 的表格
WASM_TABLE_INIT(1, 0, WASM_ZERO, WASM_ZERO, WASM_ZERO)
```

**预期输出 (验证结果):**

`ExpectFailure` 会被触发，因为表格索引 1 超出了已定义的表格范围。

**用户常见的编程错误 (示例):**

* **索引错误:** 尝试访问超出内存或表格范围的索引（例如 `WASM_MEMORY0_COPY(WASM_I32V(1000), WASM_I32V(0), WASM_I32V(65536))`，如果内存大小小于 65536）。
* **类型不匹配:**  在表格初始化或填充时，尝试使用与表格或元素段类型不兼容的值（例如，将 `funcref` 的值尝试放入 `externref` 的表格中）。
* **未初始化的局部变量:**  在启用了不可默认局部变量的情况下，尝试读取尚未赋值的局部变量。
* **结构体/数组操作错误:**
    * 使用错误的字段索引访问结构体。
    * 尝试设置不可变结构体或数组的字段。
    * 创建结构体或数组时提供错误的参数类型或数量。
* **引用类型错误:**  在需要不可空引用的地方使用了空引用，或者在需要特定引用类型的地方使用了不兼容的引用类型。

**总结:**

这个代码片段是 V8 中 WebAssembly 函数体解码器单元测试的一部分，专注于验证解码器对于内存操作、表格操作、引用类型操作以及垃圾回收相关指令的正确解析和验证，包括对合法指令的成功解码和对非法指令的正确识别和报告错误。 它也涵盖了局部变量的初始化和作用域管理，以及一些更细致的特性，例如声明式元素段和打包类型的处理。 通过大量的测试用例，它旨在确保 V8 能够健壮且正确地处理各种 WebAssembly 代码结构。

### 提示词
```
这是目录为v8/test/unittests/wasm/function-body-decoder-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/wasm/function-body-decoder-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
_MEMORY_INIT(0, WASM_ZERO, WASM_ZERO, WASM_ZERO)});
  ExpectFailure(sigs.v_v(),
                {WASM_MEMORY0_COPY(WASM_ZERO, WASM_ZERO, WASM_ZERO)});
  ExpectFailure(sigs.v_v(),
                {WASM_MEMORY_FILL(WASM_ZERO, WASM_ZERO, WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, TableInit) {
  builder.AddTable(wasm::kWasmFuncRef);
  builder.AddPassiveElementSegment(wasm::kWasmFuncRef);

  ExpectValidates(sigs.v_v(),
                  {WASM_TABLE_INIT(0, 0, WASM_ZERO, WASM_ZERO, WASM_ZERO)});
  ExpectFailure(sigs.v_v(),
                {WASM_TABLE_INIT(0, 1, WASM_ZERO, WASM_ZERO, WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, TableInitWrongType) {
  uint32_t table_index = builder.AddTable(wasm::kWasmFuncRef);
  uint32_t element_index =
      builder.AddPassiveElementSegment(wasm::kWasmExternRef);
  ExpectFailure(sigs.v_v(), {WASM_TABLE_INIT(table_index, element_index,
                                             WASM_ZERO, WASM_ZERO, WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, TableInitInvalid) {
  builder.AddTable(wasm::kWasmFuncRef);
  builder.AddPassiveElementSegment(wasm::kWasmFuncRef);

  uint8_t code[] = {WASM_TABLE_INIT(0, 0, WASM_ZERO, WASM_ZERO, WASM_ZERO),
                    WASM_END};
  for (size_t i = 0; i <= arraysize(code); ++i) {
    Validate(i == arraysize(code), sigs.v_v(), base::VectorOf(code, i),
             kOmitEnd);
  }
}

TEST_F(FunctionBodyDecoderTest, ElemDrop) {
  builder.AddTable(wasm::kWasmFuncRef);
  builder.AddPassiveElementSegment(wasm::kWasmFuncRef);

  ExpectValidates(sigs.v_v(), {WASM_ELEM_DROP(0)});
  ExpectFailure(sigs.v_v(), {WASM_ELEM_DROP(1)});
}

TEST_F(FunctionBodyDecoderTest, TableInitDeclarativeElem) {
  builder.AddTable(wasm::kWasmFuncRef);
  builder.AddDeclarativeElementSegment();
  uint8_t code[] = {WASM_TABLE_INIT(0, 0, WASM_ZERO, WASM_ZERO, WASM_ZERO),
                    WASM_END};
  for (size_t i = 0; i <= arraysize(code); ++i) {
    Validate(i == arraysize(code), sigs.v_v(), base::VectorOf(code, i),
             kOmitEnd);
  }
}

TEST_F(FunctionBodyDecoderTest, DeclarativeElemDrop) {
  builder.AddTable(wasm::kWasmFuncRef);
  builder.AddDeclarativeElementSegment();
  ExpectValidates(sigs.v_v(), {WASM_ELEM_DROP(0)});
  ExpectFailure(sigs.v_v(), {WASM_ELEM_DROP(1)});
}

TEST_F(FunctionBodyDecoderTest, RefFuncDeclared) {
  uint8_t function_index = builder.AddFunction(sigs.v_i());
  ExpectValidates(sigs.c_v(), {WASM_REF_FUNC(function_index)});
}

TEST_F(FunctionBodyDecoderTest, RefFuncUndeclared) {
  uint8_t function_index = builder.AddFunction(sigs.v_i(), false);
  ExpectFailure(sigs.c_v(), {WASM_REF_FUNC(function_index)});
}

TEST_F(FunctionBodyDecoderTest, ElemSegmentIndexUnsigned) {
  builder.AddTable(wasm::kWasmFuncRef);
  for (int i = 0; i < 65; ++i) {
    builder.AddPassiveElementSegment(wasm::kWasmFuncRef);
  }

  // Make sure that the index is interpreted as an unsigned number; 64 is
  // interpreted as -64 when decoded as a signed LEB.
  ExpectValidates(sigs.v_v(),
                  {WASM_TABLE_INIT(0, 64, WASM_ZERO, WASM_ZERO, WASM_ZERO)});
  ExpectValidates(sigs.v_v(), {WASM_ELEM_DROP(64)});
}

TEST_F(FunctionBodyDecoderTest, TableCopy) {
  uint8_t table_index = builder.AddTable(wasm::kWasmVoid);

  ExpectValidates(sigs.v_v(),
                  {WASM_TABLE_COPY(table_index, table_index, WASM_ZERO,
                                   WASM_ZERO, WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, TableCopyWrongType) {
  uint8_t dst_table_index = builder.AddTable(wasm::kWasmFuncRef);
  uint8_t src_table_index = builder.AddTable(wasm::kWasmExternRef);
  ExpectFailure(sigs.v_v(), {WASM_TABLE_COPY(dst_table_index, src_table_index,
                                             WASM_ZERO, WASM_ZERO, WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, TableGrow) {
  uint8_t tab_func = builder.AddTable(kWasmFuncRef, 10, true, 20);
  uint8_t tab_ref = builder.AddTable(kWasmExternRef, 10, true, 20);

  ExpectValidates(
      sigs.i_c(),
      {WASM_TABLE_GROW(tab_func, WASM_REF_NULL(kFuncRefCode), WASM_ONE)});
  ExpectValidates(
      sigs.i_a(),
      {WASM_TABLE_GROW(tab_ref, WASM_REF_NULL(kExternRefCode), WASM_ONE)});
  // FuncRef table cannot be initialized with an ExternRef value.
  ExpectFailure(sigs.i_a(),
                {WASM_TABLE_GROW(tab_func, WASM_LOCAL_GET(0), WASM_ONE)});
  // ExternRef table cannot be initialized with a FuncRef value.
  ExpectFailure(sigs.i_c(),
                {WASM_TABLE_GROW(tab_ref, WASM_LOCAL_GET(0), WASM_ONE)});
  // Check that the table index gets verified.
  ExpectFailure(
      sigs.i_a(),
      {WASM_TABLE_GROW(tab_ref + 2, WASM_REF_NULL(kExternRefCode), WASM_ONE)});
}

TEST_F(FunctionBodyDecoderTest, TableSize) {
  int tab = builder.AddTable(kWasmFuncRef, 10, true, 20);
  ExpectValidates(sigs.i_v(), {WASM_TABLE_SIZE(tab)});
  ExpectFailure(sigs.i_v(), {WASM_TABLE_SIZE(tab + 2)});
}

TEST_F(FunctionBodyDecoderTest, TableFill) {
  uint8_t tab_func = builder.AddTable(kWasmFuncRef, 10, true, 20);
  uint8_t tab_ref = builder.AddTable(kWasmExternRef, 10, true, 20);
  ExpectValidates(sigs.v_c(),
                  {WASM_TABLE_FILL(tab_func, WASM_ONE,
                                   WASM_REF_NULL(kFuncRefCode), WASM_ONE)});
  ExpectValidates(sigs.v_a(),
                  {WASM_TABLE_FILL(tab_ref, WASM_ONE,
                                   WASM_REF_NULL(kExternRefCode), WASM_ONE)});
  // FuncRef table cannot be initialized with an ExternRef value.
  ExpectFailure(sigs.v_a(), {WASM_TABLE_FILL(tab_func, WASM_ONE,
                                             WASM_LOCAL_GET(0), WASM_ONE)});
  // ExternRef table cannot be initialized with a FuncRef value.
  ExpectFailure(sigs.v_c(), {WASM_TABLE_FILL(tab_ref, WASM_ONE,
                                             WASM_LOCAL_GET(0), WASM_ONE)});
  // Check that the table index gets verified.
  ExpectFailure(sigs.v_a(),
                {WASM_TABLE_FILL(tab_ref + 2, WASM_ONE,
                                 WASM_REF_NULL(kExternRefCode), WASM_ONE)});
}

TEST_F(FunctionBodyDecoderTest, TableOpsWithoutTable) {
  ExpectFailure(sigs.i_v(),
                {WASM_TABLE_GROW(0, WASM_REF_NULL(kExternRefCode), WASM_ONE)});
  ExpectFailure(sigs.i_v(), {WASM_TABLE_SIZE(0)});
  ExpectFailure(
      sigs.i_a(),
      {WASM_TABLE_FILL(0, WASM_ONE, WASM_REF_NULL(kExternRefCode), WASM_ONE)});
  builder.AddPassiveElementSegment(wasm::kWasmFuncRef);
  ExpectFailure(sigs.v_v(),
                {WASM_TABLE_INIT(0, 0, WASM_ZERO, WASM_ZERO, WASM_ZERO)});
  ExpectFailure(sigs.v_v(),
                {WASM_TABLE_COPY(0, 0, WASM_ZERO, WASM_ZERO, WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, TableCopyMultiTable) {
  {
    TestModuleBuilder builder;
    builder.AddTable(kWasmExternRef, 10, true, 20);
    builder.AddPassiveElementSegment(wasm::kWasmFuncRef);
    module = builder.module();
    // We added one table, therefore table.copy on table 0 should work.
    int table_src = 0;
    int table_dst = 0;
    ExpectValidates(sigs.v_v(),
                    {WASM_TABLE_COPY(table_dst, table_src, WASM_ZERO, WASM_ZERO,
                                     WASM_ZERO)});
    // There is only one table, so table.copy on table 1 should fail.
    table_src = 0;
    table_dst = 1;
    ExpectFailure(sigs.v_v(), {WASM_TABLE_COPY(table_dst, table_src, WASM_ZERO,
                                               WASM_ZERO, WASM_ZERO)});
    table_src = 1;
    table_dst = 0;
    ExpectFailure(sigs.v_v(), {WASM_TABLE_COPY(table_dst, table_src, WASM_ZERO,
                                               WASM_ZERO, WASM_ZERO)});
  }
  {
    TestModuleBuilder builder;
    builder.AddTable(kWasmExternRef, 10, true, 20);
    builder.AddTable(kWasmExternRef, 10, true, 20);
    builder.AddPassiveElementSegment(wasm::kWasmFuncRef);
    module = builder.module();
    // We added two tables, therefore table.copy on table 0 should work.
    int table_src = 0;
    int table_dst = 0;
    ExpectValidates(sigs.v_v(),
                    {WASM_TABLE_COPY(table_dst, table_src, WASM_ZERO, WASM_ZERO,
                                     WASM_ZERO)});
    // Also table.copy on table 1 should work now.
    table_src = 1;
    table_dst = 0;
    ExpectValidates(sigs.v_v(),
                    {WASM_TABLE_COPY(table_dst, table_src, WASM_ZERO, WASM_ZERO,
                                     WASM_ZERO)});
    table_src = 0;
    table_dst = 1;
    ExpectValidates(sigs.v_v(),
                    {WASM_TABLE_COPY(table_dst, table_src, WASM_ZERO, WASM_ZERO,
                                     WASM_ZERO)});
  }
}

TEST_F(FunctionBodyDecoderTest, TableInitMultiTable) {
  {
    TestModuleBuilder builder;
    builder.AddTable(kWasmExternRef, 10, true, 20);
    builder.AddPassiveElementSegment(wasm::kWasmExternRef);
    module = builder.module();
    // We added one table, therefore table.init on table 0 should work.
    int table_index = 0;
    ExpectValidates(sigs.v_v(), {WASM_TABLE_INIT(table_index, 0, WASM_ZERO,
                                                 WASM_ZERO, WASM_ZERO)});
    // There is only one table, so table.init on table 1 should fail.
    table_index = 1;
    ExpectFailure(sigs.v_v(), {WASM_TABLE_INIT(table_index, 0, WASM_ZERO,
                                               WASM_ZERO, WASM_ZERO)});
  }
  {
    TestModuleBuilder builder;
    builder.AddTable(kWasmExternRef, 10, true, 20);
    builder.AddTable(kWasmExternRef, 10, true, 20);
    builder.AddPassiveElementSegment(wasm::kWasmExternRef);
    module = builder.module();
    // We added two tables, therefore table.init on table 0 should work.
    int table_index = 0;
    ExpectValidates(sigs.v_v(), {WASM_TABLE_INIT(table_index, 0, WASM_ZERO,
                                                 WASM_ZERO, WASM_ZERO)});
    // Also table.init on table 1 should work now.
    table_index = 1;
    ExpectValidates(sigs.v_v(), {WASM_TABLE_INIT(table_index, 0, WASM_ZERO,
                                                 WASM_ZERO, WASM_ZERO)});
  }
}

TEST_F(FunctionBodyDecoderTest, UnpackPackedTypes) {
  {
    TestModuleBuilder builder;
    ModuleTypeIndex type_index =
        builder.AddStruct({F(kWasmI8, true), F(kWasmI16, false)});
    module = builder.module();
    ExpectValidates(sigs.v_v(),
                    {WASM_STRUCT_SET(type_index, 0,
                                     WASM_STRUCT_NEW(type_index, WASM_I32V(1),
                                                     WASM_I32V(42)),
                                     WASM_I32V(-1))});
  }
  {
    TestModuleBuilder builder;
    ModuleTypeIndex type_index = builder.AddArray(kWasmI8, true);
    module = builder.module();
    ExpectValidates(
        sigs.v_v(),
        {WASM_ARRAY_SET(type_index,
                        WASM_ARRAY_NEW(type_index, WASM_I32V(10), WASM_I32V(5)),
                        WASM_I32V(3), WASM_I32V(12345678))});
  }
}

ValueType ref(ModuleTypeIndex type_index) { return ValueType::Ref(type_index); }
ValueType ref(HeapType::Representation repr) { return ValueType::Ref(repr); }
ValueType refNull(ModuleTypeIndex type_index) {
  return ValueType::RefNull(type_index);
}
ValueType refNull(HeapType::Representation repr) {
  return ValueType::RefNull(repr);
}

TEST_F(FunctionBodyDecoderTest, StructOrArrayNewDefault) {
  TestModuleBuilder builder;
  ModuleTypeIndex struct_index = builder.AddStruct({F(kWasmI32, true)});
  ModuleTypeIndex struct_non_def_index =
      builder.AddStruct({F(ref(struct_index), true)});
  ModuleTypeIndex struct_immutable_index =
      builder.AddStruct({F(kWasmI32, false)});
  ModuleTypeIndex array_index = builder.AddArray(kWasmI32, true);
  ModuleTypeIndex array_non_def_index =
      builder.AddArray(ref(array_index), true);
  ModuleTypeIndex array_immutable_index = builder.AddArray(kWasmI32, false);

  module = builder.module();

  ExpectValidates(sigs.v_v(),
                  {WASM_STRUCT_NEW_DEFAULT(struct_index), WASM_DROP});
  ExpectFailure(sigs.v_v(),
                {WASM_STRUCT_NEW_DEFAULT(struct_non_def_index), WASM_DROP},
                kAppendEnd,
                "struct.new_default: struct type 1 has field 0 of "
                "non-defaultable type (ref 0)");
  ExpectValidates(sigs.v_v(),
                  {WASM_STRUCT_NEW_DEFAULT(struct_immutable_index), WASM_DROP});
  ExpectValidates(
      sigs.v_v(),
      {WASM_ARRAY_NEW_DEFAULT(array_index, WASM_I32V(3)), WASM_DROP});
  ExpectFailure(
      sigs.v_v(),
      {WASM_ARRAY_NEW_DEFAULT(array_non_def_index, WASM_I32V(3)), WASM_DROP},
      kAppendEnd,
      "array.new_default: array type 4 has non-defaultable element type (ref "
      "3)");
  ExpectValidates(
      sigs.v_v(),
      {WASM_ARRAY_NEW_DEFAULT(array_immutable_index, WASM_I32V(3)), WASM_DROP});
}

TEST_F(FunctionBodyDecoderTest, DefaultableLocal) {
  AddLocals(kWasmExternRef, 1);
  ExpectValidates(sigs.v_v(), {});
}

TEST_F(FunctionBodyDecoderTest, NonDefaultableLocals) {
  WASM_FEATURE_SCOPE(legacy_eh);
  ModuleTypeIndex struct_type_index = builder.AddStruct({F(kWasmI32, true)});
  ValueType rep = ref(struct_type_index);
  FunctionSig sig(0, 1, &rep);
  AddLocals(rep, 2);
  uint8_t ex = builder.AddException(sigs.v_v());
  // Declaring non-defaultable locals is fine.
  ExpectValidates(&sig, {});
  // Loading from an uninitialized non-defaultable local fails.
  ExpectFailure(&sig, {WASM_LOCAL_GET(1), WASM_DROP}, kAppendEnd,
                "uninitialized non-defaultable local: 1");
  // Loading from an initialized local is fine.
  ExpectValidates(&sig, {WASM_LOCAL_SET(1, WASM_LOCAL_GET(0)),
                         WASM_LOCAL_GET(1), WASM_DROP});
  ExpectValidates(&sig, {WASM_LOCAL_TEE(1, WASM_LOCAL_GET(0)),
                         WASM_LOCAL_GET(1), WASM_DROP, WASM_DROP});
  // Non-nullable locals must be initialized with non-null values.
  ExpectFailure(&sig, {WASM_LOCAL_SET(1, WASM_REF_NULL(struct_type_index))},
                kAppendEnd,
                "expected type (ref 0), found ref.null of type (ref null 0)");
  // Initialization is propagated into inner blocks.
  ExpectValidates(
      &sig,
      {WASM_LOCAL_SET(1, WASM_LOCAL_GET(0)),
       WASM_BLOCK(WASM_LOCAL_GET(1), WASM_DROP),
       WASM_LOOP(WASM_LOCAL_GET(1), WASM_DROP),
       WASM_IF_ELSE(WASM_ZERO, WASM_SEQ(WASM_LOCAL_GET(1), WASM_DROP),
                    WASM_SEQ(WASM_LOCAL_GET(1), WASM_DROP)),
       kExprTry, kVoidCode, WASM_LOCAL_GET(1), WASM_DROP, kExprCatch, ex,
       WASM_LOCAL_GET(1), WASM_DROP, kExprEnd, WASM_LOCAL_GET(1), WASM_DROP});
  // Initialization is forgotten at the end of a block.
  ExpectFailure(&sig,
                {WASM_LOCAL_SET(1, WASM_LOCAL_GET(0)),
                 WASM_BLOCK(WASM_LOCAL_SET(2, WASM_LOCAL_GET(0))),
                 WASM_LOCAL_GET(1), WASM_DROP,   // OK
                 WASM_LOCAL_GET(2), WASM_DROP},  // Error
                kAppendEnd, "uninitialized non-defaultable local: 2");
  // Initialization is forgotten at the end of if/else, even if both
  // branches initialized the local.
  ExpectFailure(&sig,
                {WASM_IF_ELSE(WASM_ZERO, WASM_LOCAL_SET(1, WASM_LOCAL_GET(0)),
                              WASM_LOCAL_SET(1, WASM_LOCAL_GET(0))),
                 WASM_LOCAL_GET(1), WASM_DROP},
                kAppendEnd, "uninitialized non-defaultable local: 1");
  // Initialization does not carry from the "then" branch to the "else" branch.
  ExpectFailure(&sig,
                {WASM_IF_ELSE(WASM_ONE, WASM_LOCAL_SET(1, WASM_LOCAL_GET(0)),
                              WASM_SEQ(WASM_LOCAL_GET(1), WASM_DROP))},
                kAppendEnd, "uninitialized non-defaultable local: 1");
  // Initialization is forgotten at the end of a loop.
  ExpectFailure(&sig,
                {WASM_LOOP(WASM_LOCAL_SET(1, WASM_LOCAL_GET(0))),
                 WASM_LOCAL_GET(1), WASM_DROP},
                kAppendEnd, "uninitialized non-defaultable local: 1");
  // Initialization is forgotten at the end of a try, with or without catch.
  ExpectFailure(&sig,
                {kExprTry, kVoidCode, WASM_LOCAL_SET(1, WASM_LOCAL_GET(0)),
                 kExprEnd, WASM_LOCAL_GET(1), WASM_DROP},
                kAppendEnd, "uninitialized non-defaultable local: 1");
  ExpectFailure(&sig,
                {kExprTry, kVoidCode, WASM_LOCAL_SET(1, WASM_LOCAL_GET(0)),
                 kExprCatch, ex, WASM_LOCAL_SET(1, WASM_LOCAL_GET(0)), kExprEnd,
                 WASM_LOCAL_GET(1), WASM_DROP},
                kAppendEnd, "uninitialized non-defaultable local: 1");
  ExpectFailure(&sig,
                {kExprTry, kVoidCode, WASM_LOCAL_SET(1, WASM_LOCAL_GET(0)),
                 kExprCatchAll, WASM_LOCAL_SET(1, WASM_LOCAL_GET(0)), kExprEnd,
                 WASM_LOCAL_GET(1), WASM_DROP},
                kAppendEnd, "uninitialized non-defaultable local: 1");
  // Initialization does not carry from a "try" block to its "catch" block.
  ExpectFailure(&sig,
                {kExprTry, kVoidCode, WASM_LOCAL_SET(1, WASM_LOCAL_GET(0)),
                 kExprCatch, ex, WASM_LOCAL_GET(1), WASM_DROP, kExprEnd},
                kAppendEnd, "uninitialized non-defaultable local: 1");
}

TEST_F(FunctionBodyDecoderTest, RefEq) {
  WASM_FEATURE_SCOPE(exnref);

  ModuleTypeIndex struct_type_index = builder.AddStruct({F(kWasmI32, true)});
  ValueType eqref_subtypes[] = {kWasmEqRef,
                                kWasmI31Ref,
                                kWasmI31Ref.AsNonNull(),
                                kWasmEqRef.AsNonNull(),
                                kWasmStructRef,
                                kWasmArrayRef,
                                refNull(HeapType::kEqShared),
                                refNull(HeapType::kI31Shared),
                                ref(HeapType::kStructShared),
                                ref(HeapType::kArrayShared),
                                ref(struct_type_index),
                                refNull(struct_type_index)};
  ValueType non_eqref_subtypes[] = {kWasmI32,
                                    kWasmI64,
                                    kWasmF32,
                                    kWasmF64,
                                    kWasmS128,
                                    kWasmFuncRef,
                                    kWasmExternRef,
                                    kWasmAnyRef,
                                    kWasmExnRef,
                                    ref(HeapType::kExtern),
                                    ref(HeapType::kAny),
                                    ref(HeapType::kFunc),
                                    ref(HeapType::kExn),
                                    refNull(HeapType::kExternShared),
                                    refNull(HeapType::kAnyShared),
                                    refNull(HeapType::kFuncShared),
                                    refNull(HeapType::kExnShared)};

  for (ValueType type1 : eqref_subtypes) {
    for (ValueType type2 : eqref_subtypes) {
      ValueType reps[] = {kWasmI32, type1, type2};
      FunctionSig sig(1, 2, reps);
      ExpectValidates(&sig,
                      {WASM_REF_EQ(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
    }
  }

  for (ValueType type1 : eqref_subtypes) {
    for (ValueType type2 : non_eqref_subtypes) {
      ValueType reps[] = {kWasmI32, type1, type2};
      FunctionSig sig(1, 2, reps);
      ExpectFailure(&sig, {WASM_REF_EQ(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))},
                    kAppendEnd,
                    "expected either eqref or (ref null shared eq), found "
                    "local.get of type");
      ExpectFailure(&sig, {WASM_REF_EQ(WASM_LOCAL_GET(1), WASM_LOCAL_GET(0))},
                    kAppendEnd,
                    "expected either eqref or (ref null shared eq), found "
                    "local.get of type");
    }
  }
}

using HeapRep = HeapType::Representation;

HeapRep Repr(ModuleTypeIndex type_index) {
  return HeapType(type_index).representation();
}

TEST_F(FunctionBodyDecoderTest, RefAsNonNull) {
  WASM_FEATURE_SCOPE(exnref);

  HeapRep struct_type_index = Repr(builder.AddStruct({F(kWasmI32, true)}));
  HeapRep array_type_index = Repr(builder.AddArray(kWasmI32, true));
  HeapRep heap_types[] = {
      struct_type_index, array_type_index,  HeapType::kExn, HeapType::kFunc,
      HeapType::kEq,     HeapType::kExtern, HeapType::kAny, HeapType::kI31};

  ValueType non_compatible_types[] = {kWasmI32, kWasmI64, kWasmF32, kWasmF64,
                                      kWasmS128};

  // It works with nullable types.
  for (HeapRep heap_type : heap_types) {
    ValueType reprs[] = {ValueType::Ref(heap_type),
                         ValueType::RefNull(heap_type)};
    FunctionSig sig(1, 1, reprs);
    ExpectValidates(&sig, {WASM_REF_AS_NON_NULL(WASM_LOCAL_GET(0))});
  }

  // It works with non-nullable types.
  for (HeapRep heap_type : heap_types) {
    ValueType reprs[] = {ValueType::Ref(heap_type), ValueType::Ref(heap_type)};
    FunctionSig sig(1, 1, reprs);
    ExpectValidates(&sig, {WASM_REF_AS_NON_NULL(WASM_LOCAL_GET(0))});
  }

  // It fails with other types.
  for (ValueType type : non_compatible_types) {
    FunctionSig sig(0, 1, &type);
    ExpectFailure(
        &sig, {WASM_REF_AS_NON_NULL(WASM_LOCAL_GET(0)), kExprDrop}, kAppendEnd,
        "ref.as_non_null[0] expected reference type, found local.get of type");
  }
}

TEST_F(FunctionBodyDecoderTest, RefNull) {
  WASM_FEATURE_SCOPE(exnref);

  HeapRep struct_type_index = Repr(builder.AddStruct({F(kWasmI32, true)}));
  HeapRep array_type_index = Repr(builder.AddArray(kWasmI32, true));
  HeapRep type_reprs[] = {
      struct_type_index, array_type_index, HeapType::kExn,
      HeapType::kFunc,   HeapType::kEq,    HeapType::kExtern,
      HeapType::kAny,    HeapType::kI31,   HeapType::kNone};
  // It works with heap types.
  for (HeapRep type_repr : type_reprs) {
    const ValueType type = ValueType::RefNull(type_repr);
    const FunctionSig sig(1, 0, &type);
    ExpectValidates(&sig, {WASM_REF_NULL(WASM_HEAP_TYPE(HeapType(type_repr)))});
  }
  // It fails for undeclared types.
  ExpectFailure(sigs.v_v(), {WASM_REF_NULL(42), kExprDrop}, kAppendEnd,
                "Type index 42 is out of bounds");
}

TEST_F(FunctionBodyDecoderTest, RefIsNull) {
  ExpectValidates(sigs.i_i(),
                  {WASM_REF_IS_NULL(WASM_REF_NULL(kExternRefCode))});
  ExpectFailure(
      sigs.i_i(), {WASM_REF_IS_NULL(WASM_LOCAL_GET(0))}, kAppendEnd,
      "ref.is_null[0] expected reference type, found local.get of type i32");

  HeapRep struct_type_index = Repr(builder.AddStruct({F(kWasmI32, true)}));
  HeapRep array_type_index = Repr(builder.AddArray(kWasmI32, true));
  HeapRep heap_types[] = {struct_type_index, array_type_index,  HeapType::kFunc,
                          HeapType::kEq,     HeapType::kExtern, HeapType::kAny,
                          HeapType::kI31};

  for (HeapRep heap_type : heap_types) {
    const ValueType types[] = {kWasmI32, ValueType::RefNull(heap_type)};
    const FunctionSig sig(1, 1, types);
    // It works for nullable references.
    ExpectValidates(&sig, {WASM_REF_IS_NULL(WASM_LOCAL_GET(0))});
    // It works for non-nullable references.
    ExpectValidates(
        &sig, {WASM_REF_IS_NULL(WASM_REF_AS_NON_NULL(WASM_LOCAL_GET(0)))});
  }

  // It fails if the argument type is not a reference type.
  ExpectFailure(
      sigs.v_v(), {WASM_REF_IS_NULL(WASM_I32V(0)), kExprDrop}, kAppendEnd,
      "ref.is_null[0] expected reference type, found i32.const of type i32");
}

TEST_F(FunctionBodyDecoderTest, BrOnNull) {
  HeapRep struct_type_index = Repr(builder.AddStruct({F(kWasmI32, true)}));
  HeapRep array_type_index = Repr(builder.AddArray(kWasmI32, true));
  HeapRep type_reprs[] = {struct_type_index, array_type_index,  HeapType::kFunc,
                          HeapType::kEq,     HeapType::kExtern, HeapType::kAny,
                          HeapType::kI31,    HeapType::kNone};

  for (HeapRep type_repr : type_reprs) {
    const ValueType reps[] = {ValueType::Ref(type_repr),
                              ValueType::RefNull(type_repr)};
    const FunctionSig sig(1, 1, reps);
    ExpectValidates(
        &sig, {WASM_BLOCK_R(reps[0], WASM_REF_AS_NON_NULL(WASM_LOCAL_GET(0)),
                            WASM_BR_ON_NULL(0, WASM_LOCAL_GET(0)), WASM_I32V(0),
                            kExprSelectWithType, 1, WASM_REF_TYPE(reps[0]))});
    // Should have block return value on stack before calling br_on_null.
    ExpectFailure(&sig,
                  {WASM_BLOCK_R(reps[0], WASM_BR_ON_NULL(0, WASM_LOCAL_GET(0)),
                                WASM_I32V(0), kExprSelectWithType, 1,
                                WASM_REF_TYPE(reps[0]))},
                  kAppendEnd,
                  "expected 1 elements on the stack for branch, found 0");
  }
}

TEST_F(FunctionBodyDecoderTest, BrOnNonNull) {
  HeapRep struct_type_index = Repr(builder.AddStruct({F(kWasmI32, true)}));
  HeapRep array_type_index = Repr(builder.AddArray(kWasmI32, true));
  HeapRep type_reprs[] = {struct_type_index, array_type_index,  HeapType::kFunc,
                          HeapType::kEq,     HeapType::kExtern, HeapType::kAny,
                          HeapType::kI31};

  for (HeapRep type_repr : type_reprs) {
    const ValueType reps[] = {ValueType::Ref(type_repr),
                              ValueType::RefNull(type_repr)};
    const FunctionSig sig(1, 1, reps);
    ExpectValidates(
        &sig,
        {WASM_BLOCK_R(reps[0], WASM_BR_ON_NON_NULL(0, WASM_LOCAL_GET(0)),
                      WASM_RETURN(WASM_REF_AS_NON_NULL(WASM_LOCAL_GET(0))))});

    // Wrong branch type.
    ExpectFailure(
        &sig,
        {WASM_BLOCK_I(WASM_BR_ON_NON_NULL(0, WASM_LOCAL_GET(0)),
                      WASM_RETURN(WASM_REF_AS_NON_NULL(WASM_LOCAL_GET(0))))},
        kAppendEnd,
        ("type error in branch[0] (expected i32, got " + reps[0].name() + ")")
            .c_str());

    // br_on_non_null does not leave a value on the stack.
    ExpectFailure(&sig, {WASM_BR_ON_NON_NULL(0, WASM_LOCAL_GET(0))}, kAppendEnd,
                  "expected 1 elements on the stack for fallthru, found 0");
  }
}

TEST_F(FunctionBodyDecoderTest, GCStruct) {
  ModuleTypeIndex struct_type_index = builder.AddStruct({F(kWasmI32, true)});
  ModuleTypeIndex array_type_index = builder.AddArray(kWasmI32, true);
  ModuleTypeIndex immutable_struct_type_index =
      builder.AddStruct({F(kWasmI32, false)});
  uint8_t field_index = 0;

  ValueType struct_type = ValueType::Ref(struct_type_index);
  ValueType reps_i_r[] = {kWasmI32, struct_type};
  ValueType reps_f_r[] = {kWasmF32, struct_type};
  const FunctionSig sig_i_r(1, 1, reps_i_r);
  const FunctionSig sig_v_r(0, 1, &struct_type);
  const FunctionSig sig_r_v(1, 0, &struct_type);
  const FunctionSig sig_f_r(1, 1, reps_f_r);

  /** struct.new **/
  ExpectValidates(&sig_r_v, {WASM_STRUCT_NEW(struct_type_index, WASM_I32V(0))});
  // Too few arguments.
  ExpectFailure(&sig_r_v,
                {WASM_GC_OP(kExprStructNew), ToByte(struct_type_index)},
                kAppendEnd,
                "not enough arguments on the stack for struct.new "
                "(need 1, got 0)");
  // Too many arguments.
  ExpectFailure(
      &sig_r_v,
      {WASM_STRUCT_NEW(struct_type_index, WASM_I32V(0), WASM_I32V(1))},
      kAppendEnd, "expected 1 elements on the stack for fallthru, found 2");
  // Mistyped arguments.
  ExpectFailure(&sig_v_r,
                {WASM_STRUCT_NEW(struct_type_index, WASM_LOCAL_GET(0))},
                kAppendEnd,
                "struct.new[0] expected type i32, found local.get of "
                "type (ref 0)");
  // Wrongly typed index.
  ExpectFailure(sigs.v_v(),
                {WASM_STRUCT_NEW(array_type_index, WASM_I32V(0)), kExprDrop},
                kAppendEnd, "invalid struct index: 1");
  // Out-of-bounds index.
  ExpectFailure(sigs.v_v(), {WASM_STRUCT_NEW(42, WASM_I32V(0)), kExprDrop},
                kAppendEnd, "invalid struct index: 42");

  /** struct.get **/
  ExpectValidates(&sig_i_r, {WASM_STRUCT_GET(struct_type_index, field_index,
                                             WASM_LOCAL_GET(0))});
  // With non-nullable struct.
  ExpectValidates(&sig_i_r,
                  {WASM_STRUCT_GET(struct_type_index, field_index,
                                   WASM_REF_AS_NON_NULL(WASM_LOCAL_GET(0)))});
  // Wrong index.
  ExpectFailure(
      &sig_v_r,
      {WASM_STRUCT_GET(struct_type_index, field_index + 1, WASM_LOCAL_GET(0)),
       kExprDrop},
      kAppendEnd, "invalid field index: 1");
  // Mistyped expected type.
  ExpectFailure(
      &sig_f_r,
      {WASM_STRUCT_GET(struct_type_index, field_index, WASM_LOCAL_GET(0))},
      kAppendEnd, "type error in fallthru[0] (expected f32, got i32)");

  /** struct.set **/
  ExpectValidates(&sig_v_r, {WASM_STRUCT_SET(struct_type_index, field_index,
                                             WASM_LOCAL_GET(0), WASM_I32V(0))});
  // Non-nullable struct.
  ExpectValidates(
      &sig_v_r,
      {WASM_STRUCT_SET(struct_type_index, field_index,
                       WASM_REF_AS_NON_NULL(WASM_LOCAL_GET(0)), WASM_I32V(0))});
  // Wrong index.
  ExpectFailure(&sig_v_r,
                {WASM_STRUCT_SET(struct_type_index, field_index + 1,
                                 WASM_LOCAL_GET(0), WASM_I32V(0))},
                kAppendEnd, "invalid field index: 1");
  // Mistyped input.
  ExpectFailure(&sig_v_r,
                {WASM_STRUCT_SET(struct_type_index, field_index,
                                 WASM_LOCAL_GET(0), WASM_I64V(0))},
                kAppendEnd,
                "struct.set[1] expected type i32, found i64.const of type i64");
  // Expecting output.
  ExpectFailure(&sig_i_r,
                {WASM_STRUCT_SET(struct_type_index, field_index,
                                 WASM_LOCAL_GET(0), WASM_I32V(0))},
                kAppendEnd,
                "expected 1 elements on the stack for fallthru, found 0");
  // Setting immutable field.
  ExpectFailure(sigs.v_v(),
                {WASM_STRUCT_SET(
                    immutable_struct_type_index, field_index,
                    WASM_STRUCT_NEW(immutable_struct_type_index, WASM_I32V(42)),
                    WASM_I32V(0))},
                kAppendEnd, "struct.set: Field 0 of type 2 is immutable.");

  // struct.get_s/u fail
  ExpectFailure(
      &sig_i_r,
      {WASM_STRUCT_GET_S(struct_type_index, field_index, WASM_LOCAL_GET(0))},
      kAppendEnd,
      "struct.get_s: Immediate field 0 of type 0 has non-packed type i32. Use "
      "struct.get instead.");

  ExpectFailure(
      &sig_i_r,
      {WASM_STRUCT_GET_U(struct_type_index, field_index, WASM_LOCAL_GET(0))},
      kAppendEnd,
      "struct.get_u: Immediate field 0 of type 0 has non-packed type i32. Use "
      "struct.get instead.");
}

TEST_F(FunctionBodyDecoderTest, GCArray) {
  ModuleTypeIndex array_type_index = builder.AddArray(kWasmFuncRef, true);
  ModuleTypeIndex struct_type_index = builder.AddStruct({F(kWasmI32, false)});
  ModuleTypeIndex immutable_array_type_index =
      builder.AddArray(kWasmI32, false);

  ValueType array_type = ValueType::Ref(array_type_index);
  ValueType immutable_array_type = ValueType::Ref(immutable_array_type_index);
  ValueType reps_c_r[] = {kWasmFuncRef, array_type};
  ValueType reps_f_r[] = {kWasmF32, array_type};
  ValueType reps_i_r[] = {kWasmI32, array_type};
  ValueType reps_i_a[] = {kWasmI32, kWasmArrayRef};
  ValueType reps_i_s[] = {kWasmI32, ValueType::Ref(struct_type_index)};
  const FunctionSig sig_c_r(1, 1, reps_c_r);
  const FunctionSig sig_v_r(0, 1, &array_type);
  const FunctionSig sig_v_r2(0, 1, &immutable_array_type);
  const FunctionSig sig_r_v(1, 0, &array_type);
  const FunctionSig sig_f_r(1, 1, reps_f_r);
  const FunctionSig sig_v_cr(0, 2, reps_c_r);
  const FunctionSig sig_i_r(1, 1, reps_i_r);
  const FunctionSig sig_i_a(1, 1, reps_i_a);
  const FunctionSig sig_i_s(1, 1, reps_i_s);

  /** array.new **/
  ExpectValidates(&sig_r_v,
                  {WASM_ARRAY_NEW(array_type_index, WASM_REF_NULL(kFuncRefCode),
                                  WASM_I32V(10))});
  // Too few arguments.
  ExpectFailure(
      &sig_r_v,
      {WASM_I32V(10), WASM_GC_OP(kExprArrayNew), ToByte(array_type_index)},
      kAppendEnd,
      "not enough arguments on the stack for array.new "
      "(need 2, got 1)");
  // Mistyped initializer.
  ExpectFailure(&sig_r_v,
                {WASM_ARRAY_NEW(array_type_index, WASM_REF_NULL(kExternRefCode),
                                WASM_I32V(10))},
                kAppendEnd,
                "array.new[0] expected type funcref, found ref.null "
                "of type externref");
  // Mistyped length.
  ExpectFailure(&sig_r_v,
                {WASM_ARRAY_NEW(array_type_index, WASM_REF_NULL(kFuncRefCode),
                                WASM_I64V(5))},
                kAppendEnd,
                "array.new[1] e
```