Response: The user wants a summary of the C++ source code file `v8/test/unittests/wasm/function-body-decoder-unittest.cc`.
This is the third part of a four-part file.

The file seems to contain unit tests for a function body decoder for WebAssembly.
The tests check if the decoder correctly handles various WebAssembly instructions, especially related to memory operations, table operations, and the new GC features like struct and array manipulation, as well as reference types and related instructions.

The previous parts likely covered other categories of WebAssembly instructions. This part focuses on:
- Memory initialization and copy operations.
- Table initialization and element drop.
- `ref.func`.
- Table copy, grow, size, and fill.
- Operations on tables without tables.
- Unpacking packed types.
- `struct.new_default` and `array.new_default`.
- Defaultable locals and the initialization of non-defaultable locals.
- `ref.eq`, `ref.as_non_null`, `ref.null`, `ref.is_null`.
- `br_on_null` and `br_on_non_null`.
- GC instructions: `struct.new`, `struct.get`, `struct.set`, `array.new`, `array.get`, `array.set`, `array.len`.
- Packed fields in structs and arrays.
- Packed types as locals (expecting failure).
- `ref.test` and `ref.cast`.
- `br_on_cast` and `br_on_cast_fail`.
- `br` with bottom types.
- `local.tee` typing.
- Merging nullable types in loops.
- Regression test related to local count.
- `drop` on an empty stack.
- `any.convert_extern` and `extern.convert_any`.
- Branch table iterator tests.
- Opcode length tests.

If there is a relation to JavaScript, it would be in how these WebAssembly features are used or interact with JavaScript's runtime environment when WebAssembly modules are executed. For example, when JavaScript calls a WebAssembly function that uses these instructions, or when WebAssembly code manipulates data that is shared with JavaScript.
这个C++源代码文件（`v8/test/unittests/wasm/function-body-decoder-unittest.cc`）是V8 JavaScript引擎中用于测试WebAssembly函数体解码器的单元测试。作为第3部分，它延续了对不同WebAssembly指令进行验证的功能，主要集中在以下几个方面：

**功能归纳：**

这部分单元测试主要覆盖了以下WebAssembly指令及其在解码过程中的正确性校验：

* **内存操作 (Memory Operations):**
    * `memory.init`: 初始化内存段。测试了正确的初始化以及索引超出范围的情况。
    * `memory.copy`: 复制内存区域。测试了正确的复制操作以及在没有内存或内存索引错误时的失败情况。
    * `memory.fill`: 用指定的值填充内存区域。测试了正确的填充操作以及在没有内存时的失败情况。

* **表操作 (Table Operations):**
    * `table.init`: 使用元素段初始化表。测试了正确的初始化，错误的元素段索引，以及元素类型不匹配的情况。
    * `elem.drop`: 丢弃一个元素段。测试了正确的丢弃以及索引超出范围的情况。
    * `table.copy`: 复制表中的一部分到另一部分。测试了相同类型表之间的复制，以及不同类型表之间的失败情况。
    * `table.grow`: 增加表的大小。测试了使用 `funcref` 和 `externref` 类型的表，以及类型不匹配和表索引错误的情况。
    * `table.size`: 获取表的大小。测试了正确的获取大小以及表索引错误的情况。
    * `table.fill`: 用指定的值填充表的一部分。测试了使用 `funcref` 和 `externref` 类型的表，以及类型不匹配和表索引错误的情况。

* **引用类型相关 (Reference Types):**
    * `ref.func`: 获取一个函数的引用。测试了声明的和未声明的函数引用。
    * `ref.eq`: 比较两个引用是否相等。测试了可以比较 `eqref` 的子类型，以及不能比较非 `eqref` 的类型。
    * `ref.as_non_null`: 将一个可空引用转换为非空引用（如果非空）。测试了各种可空和非空引用类型。
    * `ref.null`: 创建一个空引用。测试了不同堆类型的空引用。
    * `ref.is_null`: 检查一个引用是否为空。测试了可空和非空引用。
    * `br_on_null`: 如果引用为空则跳转。测试了各种引用类型。
    * `br_on_non_null`: 如果引用非空则跳转。测试了各种引用类型。

* **垃圾回收 (GC) 相关指令 (Garbage Collection):**
    * `struct.new`: 创建一个新的结构体实例。测试了参数数量和类型匹配的情况。
    * `struct.get`: 获取结构体字段的值。测试了索引和类型匹配的情况。
    * `struct.set`: 设置结构体字段的值。测试了索引、类型匹配以及修改不可变字段的情况。
    * `struct.new_default`: 创建一个具有默认值的结构体实例。测试了可默认和不可默认字段的情况。
    * `array.new`: 创建一个新的数组实例。测试了初始化值和长度的类型匹配。
    * `array.get`: 获取数组元素的值。测试了索引和类型匹配的情况。
    * `array.set`: 设置数组元素的值。测试了索引、类型匹配以及修改不可变数组的情况。
    * `array.len`: 获取数组的长度。测试了参数类型和返回值类型。
    * `array.new_default`: 创建一个具有默认值的数组实例。测试了元素类型是否可默认的情况。
    * `struct.get_s`/`struct.get_u`: 获取有符号/无符号的打包结构体字段。测试了正确的操作和对非打包类型的错误使用。
    * `array.get_s`/`array.get_u`: 获取有符号/无符号的打包数组元素。测试了正确的操作和对非打包类型的错误使用。
    * `struct.new_default`: 创建默认的结构体。
    * `array.new_default`: 创建默认的数组。
    * `ref.test`: 测试一个引用是否是指定类型的实例。
    * `ref.cast`: 将一个引用转换为指定类型。
    * `br_on_cast`: 如果引用是指定类型则跳转。
    * `br_on_cast_fail`: 如果引用不是指定类型则跳转。
    * `any.convert_extern`: 将 `externref` 转换为 `anyref`。
    * `extern.convert_any`: 将 `anyref` 转换为 `externref`。

* **其他指令:**
    * `local.tee`: 设置局部变量的值，并将该值推送到操作数栈上。测试了类型匹配。
    * `drop`: 从操作数栈中移除一个值。测试了在空栈上执行 `drop` 的情况。

* **本地变量 (Locals):**
    * 测试了可默认类型和不可默认类型作为本地变量的情况，以及对未初始化不可默认本地变量的访问。

* **打包类型 (Packed Types):**
    * 测试了对打包类型结构体和数组的创建、设置和获取操作。
    * 测试了打包类型不能直接作为本地变量。

* **分支表 (Branch Table):**
    * 测试了分支表指令 `br_table` 的长度计算和错误处理。

* **操作码长度 (Opcode Length):**
    * 测试了各种 WebAssembly 操作码的长度计算。

**与 JavaScript 的关系及示例:**

虽然这个文件本身是 C++ 代码，用于测试 V8 引擎的内部实现，但它测试的 WebAssembly 功能与 JavaScript 在 WebAssembly 模块的执行过程中密切相关。

**例如，`table.init` 和 `ref.func` 指令在 JavaScript 中可以这样体现：**

假设有一个 WebAssembly 模块，其中定义了一个表和一个函数：

```wasm
(module
  (table funcref (export "my_table"))
  (func $my_func (export "my_exported_func") (result i32)
    i32.const 42)
  (elem declare func $my_func)
  (func (export "init_table")
    i32.const 0  ;; offset
    i32.const 0  ;; element index
    i32.const 1  ;; length
    table.init 0 0))
```

在 JavaScript 中，你可以实例化这个模块并调用 `init_table` 来初始化表，然后通过表调用 `my_exported_func`：

```javascript
const wasmCode = /* 上面的 wasm 代码的二进制表示 */;
const wasmModule = new WebAssembly.Module(wasmCode);
const wasmInstance = new WebAssembly.Instance(wasmModule, {});

// 初始化表
wasmInstance.exports.init_table();

// 获取导出的表
const table = wasmInstance.exports.my_table;

// 获取表中的函数引用
const funcRef = table.get(0);

// 调用表中的函数
const result = funcRef(); // result 将是 42
console.log(result);
```

在这个例子中，WebAssembly 的 `table.init` 指令将 `elem` 段中的函数 `$my_func` 的引用放入了导出的表 `my_table` 中。`ref.func` 指令（虽然在这个 wasm 代码中没有显式使用 `ref.func` 操作码，但在 `elem` 段中隐式地引用了函数）在内部起作用，创建了对函数的引用。JavaScript 通过 `table.get()` 获取这个引用并像调用普通 JavaScript 函数一样调用它。

**再例如，`memory.copy` 指令：**

```wasm
(module
  (memory (export "memory") 1)
  (data (i32.const 0) "hello")
  (func (export "copy_memory")
    i32.const 0  ;; dest offset
    i32.const 0  ;; src offset
    i32.const 5  ;; length
    memory.copy 0 0))
```

在 JavaScript 中：

```javascript
const wasmCode = /* 上面的 wasm 代码的二进制表示 */;
const wasmModule = new WebAssembly.Module(wasmCode);
const wasmInstance = new WebAssembly.Instance(wasmModule, {});

const memory = wasmInstance.exports.memory;
const memoryView = new Uint8Array(memory.buffer);

console.log(String.fromCharCode(...memoryView.slice(0, 5))); // 输出 "hello"

wasmInstance.exports.copy_memory();

console.log(String.fromCharCode(...memoryView.slice(0, 5))); // 仍然输出 "hello"，因为复制到相同位置
```

这个测试文件中的单元测试确保了 V8 引擎能够正确解码和处理这些 WebAssembly 指令，使得 JavaScript 能够可靠地与 WebAssembly 模块进行交互。总而言之，这个文件是 V8 引擎中保证 WebAssembly 功能正确实现的基石。

### 提示词
```这是目录为v8/test/unittests/wasm/function-body-decoder-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```
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
                "array.new[1] expected type i32, found i64.const of type i64");
  // Wrong type index.
  ExpectFailure(sigs.v_v(),
                {WASM_ARRAY_NEW(struct_type_index, WASM_REF_NULL(kFuncRefCode),
                                WASM_I32V(10)),
                 kExprDrop},
                kAppendEnd, "invalid array index: 1");

  /** array.get **/
  ExpectValidates(&sig_c_r, {WASM_ARRAY_GET(array_type_index, WASM_LOCAL_GET(0),
                                            WASM_I32V(5))});
  // With non-nullable array type.
  ExpectValidates(
      &sig_c_r,
      {WASM_ARRAY_GET(array_type_index, WASM_REF_AS_NON_NULL(WASM_LOCAL_GET(0)),
                      WASM_I32V(5))});
  // Wrongly typed index.
  ExpectFailure(
      &sig_v_r,
      {WASM_ARRAY_GET(array_type_index, WASM_LOCAL_GET(0), WASM_I64V(5)),
       kExprDrop},
      kAppendEnd,
      "array.get[1] expected type i32, found i64.const of type i64");
  // Mistyped expected type.
  ExpectFailure(
      &sig_f_r,
      {WASM_ARRAY_GET(array_type_index, WASM_LOCAL_GET(0), WASM_I32V(5))},
      kAppendEnd, "type error in fallthru[0] (expected f32, got funcref)");

  // array.get_s/u fail.
  ExpectFailure(
      &sig_c_r,
      {WASM_ARRAY_GET_S(array_type_index, WASM_LOCAL_GET(0), WASM_I32V(5))},
      kAppendEnd,
      "array.get_s: Immediate array type 0 has non-packed type funcref. Use "
      "array.get instead.");
  ExpectFailure(
      &sig_c_r,
      {WASM_ARRAY_GET_U(array_type_index, WASM_LOCAL_GET(0), WASM_I32V(5))},
      kAppendEnd,
      "array.get_u: Immediate array type 0 has non-packed type funcref. Use "
      "array.get instead.");

  /** array.set **/
  ExpectValidates(&sig_v_r,
                  {WASM_ARRAY_SET(array_type_index, WASM_LOCAL_GET(0),
                                  WASM_I32V(42), WASM_REF_NULL(kFuncRefCode))});
  // With non-nullable array type.
  ExpectValidates(
      &sig_v_cr,
      {WASM_ARRAY_SET(array_type_index, WASM_LOCAL_GET(1), WASM_I32V(42),
                      WASM_REF_AS_NON_NULL(WASM_LOCAL_GET(0)))});
  // Non-array type index.
  ExpectFailure(&sig_v_cr,
                {WASM_ARRAY_SET(struct_type_index, WASM_LOCAL_GET(1),
                                WASM_I32V(42), WASM_LOCAL_GET(0))},
                kAppendEnd, "invalid array index: 1");
  // Wrongly typed index.
  ExpectFailure(&sig_v_cr,
                {WASM_ARRAY_SET(array_type_index, WASM_LOCAL_GET(1),
                                WASM_I64V(42), WASM_LOCAL_GET(0))},
                kAppendEnd,
                "array.set[1] expected type i32, found i64.const of type i64");
  // Wrongly typed value.
  ExpectFailure(
      &sig_v_cr,
      {WASM_ARRAY_SET(array_type_index, WASM_LOCAL_GET(1), WASM_I32V(42),
                      WASM_I64V(0))},
      kAppendEnd,
      "array.set[2] expected type funcref, found i64.const of type i64");

  /** array.len **/
  // Works both with conrete array types and arrayref.
  ExpectValidates(&sig_i_r, {WASM_ARRAY_LEN(WASM_LOCAL_GET(0))});
  ExpectValidates(&sig_i_a, {WASM_ARRAY_LEN(WASM_LOCAL_GET(0))});
  // Wrong return type.
  ExpectFailure(&sig_f_r, {WASM_ARRAY_LEN(WASM_LOCAL_GET(0))}, kAppendEnd,
                "type error in fallthru[0] (expected f32, got i32)");
  // Non-array argument.
  ExpectFailure(
      &sig_i_s, {WASM_ARRAY_LEN(WASM_LOCAL_GET(0))}, kAppendEnd,
      "array.len[0] expected type arrayref, found local.get of type (ref 1)");

  // Immutable array.
  // Allocating and reading is OK:
  ExpectValidates(
      sigs.i_v(),
      {WASM_ARRAY_GET(
          immutable_array_type_index,
          WASM_ARRAY_NEW_FIXED(immutable_array_type_index, 1, WASM_I32V(42)),
          WASM_I32V(0))});
  // Writing fails:
  ExpectFailure(&sig_v_r2,
                {WASM_ARRAY_SET(immutable_array_type_index, WASM_LOCAL_GET(0),
                                WASM_I32V(0), WASM_I32V(42))},
                kAppendEnd, "array.set: immediate array type 2 is immutable");
}

TEST_F(FunctionBodyDecoderTest, PackedFields) {
  ModuleTypeIndex array_type_index = builder.AddArray(kWasmI8, true);
  ModuleTypeIndex struct_type_index = builder.AddStruct({F(kWasmI16, true)});
  uint8_t field_index = 0;

  // *.new with packed fields works.
  ExpectValidates(sigs.v_v(),
                  {WASM_ARRAY_NEW(array_type_index, WASM_I32V(0), WASM_I32V(5)),
                   kExprDrop});
  ExpectValidates(
      sigs.v_v(),
      {WASM_STRUCT_NEW(struct_type_index, WASM_I32V(42)), kExprDrop});
  // It can't unpack types other that i32.
  ExpectFailure(
      sigs.v_v(),
      {WASM_ARRAY_NEW(array_type_index, WASM_I64V(0), WASM_I32V(5)), kExprDrop},
      kAppendEnd,
      "array.new[0] expected type i32, found i64.const of type i64");
  ExpectFailure(sigs.v_v(),
                {WASM_STRUCT_NEW(struct_type_index, WASM_I64V(42)), kExprDrop},
                kAppendEnd,
                "struct.new[0] expected type i32, found i64.const of type i64");

  // *.set with packed fields works.
  ExpectValidates(sigs.v_v(), {WASM_ARRAY_SET(array_type_index,
                                              WASM_REF_NULL(array_type_index),
                                              WASM_I32V(0), WASM_I32V(5))});
  ExpectValidates(sigs.v_v(), {WASM_STRUCT_SET(struct_type_index, field_index,
                                               WASM_REF_NULL(struct_type_index),
                                               WASM_I32V(42))});
  // It can't unpack into types other that i32.
  ExpectFailure(
      sigs.v_v(),
      {WASM_ARRAY_SET(array_type_index, WASM_REF_NULL(array_type_index),
                      WASM_I32V(0), WASM_I64V(5))},
      kAppendEnd,
      "array.set[2] expected type i32, found i64.const of type i64");
  ExpectFailure(
      sigs.v_v(),
      {WASM_STRUCT_NEW(struct_type_index, field_index,
                       WASM_REF_NULL(struct_type_index), WASM_I64V(42))},
      kAppendEnd,
      "struct.new[0] expected type i32, found i64.const of type i64");

  // *.get_s/u works.
  ExpectValidates(sigs.i_v(), {WASM_ARRAY_GET_S(array_type_index,
                                                WASM_REF_NULL(array_type_index),
                                                WASM_I32V(0))});
  ExpectValidates(sigs.i_v(), {WASM_ARRAY_GET_U(array_type_index,
                                                WASM_REF_NULL(array_type_index),
                                                WASM_I32V(0))});
  ExpectValidates(sigs.i_v(),
                  {WASM_STRUCT_GET_S(struct_type_index, field_index,
                                     WASM_REF_NULL(struct_type_index))});
  ExpectValidates(sigs.i_v(),
                  {WASM_STRUCT_GET_U(struct_type_index, field_index,
                                     WASM_REF_NULL(struct_type_index))});

  // *.get fails.
  ExpectFailure(sigs.i_v(),
                {WASM_ARRAY_GET(array_type_index,
                                WASM_REF_NULL(array_type_index), WASM_I32V(0))},
                kAppendEnd,
                "array.get: Immediate array type 0 has packed type i8. Use "
                "array.get_s or array.get_u instead.");
  ExpectFailure(sigs.i_v(),
                {WASM_STRUCT_GET(struct_type_index, field_index,
                                 WASM_REF_NULL(struct_type_index))},
                kAppendEnd,
                "struct.get: Immediate field 0 of type 1 has packed type i16. "
                "Use struct.get_s or struct.get_u instead.");
}

TEST_F(FunctionBodyDecoderTest, PackedTypesAsLocals) {
  AddLocals(kWasmI8, 1);
  ExpectFailure(sigs.v_v(), {}, kAppendEnd, "invalid value type");
}

TEST_F(FunctionBodyDecoderTest, RefTestCast) {
  WASM_FEATURE_SCOPE(exnref);

  HeapType array_heap = HeapType(builder.AddArray(kWasmI8, true));
  HeapType super_struct_heap = HeapType(builder.AddStruct({F(kWasmI16, true)}));

  HeapType sub_struct_heap =
      HeapType(builder.AddStruct({F(kWasmI16, true), F(kWasmI32, false)}));

  HeapType func_heap_1 = HeapType(builder.AddSignature(sigs.i_i()));
  HeapType func_heap_2 = HeapType(builder.AddSignature(sigs.i_v()));

  std::tuple<HeapType, HeapType, bool> tests[] = {
      std::make_tuple(HeapType(HeapType::kArray), array_heap, true),
      std::make_tuple(HeapType(HeapType::kStruct), super_struct_heap, true),
      std::make_tuple(HeapType(HeapType::kFunc), func_heap_1, true),
      std::make_tuple(func_heap_1, func_heap_1, true),
      std::make_tuple(func_heap_1, func_heap_2, true),
      std::make_tuple(super_struct_heap, sub_struct_heap, true),
      std::make_tuple(array_heap, sub_struct_heap, true),
      std::make_tuple(super_struct_heap, func_heap_1, false),
      std::make_tuple(HeapType(HeapType::kEq), super_struct_heap, true),
      std::make_tuple(HeapType(HeapType::kExtern), func_heap_1, false),
      std::make_tuple(HeapType(HeapType::kAny), array_heap, true),
      std::make_tuple(HeapType(HeapType::kI31), array_heap, true),
      std::make_tuple(HeapType(HeapType::kNone), array_heap, true),
      std::make_tuple(HeapType(HeapType::kNone), func_heap_1, false),
      std::make_tuple(HeapType(HeapType::kExn), HeapType(HeapType::kExtern),
                      false),
      std::make_tuple(HeapType(HeapType::kExn), HeapType(HeapType::kAny),
                      false),
  };

  for (auto [from_heap, to_heap, should_pass] : tests) {
    SCOPED_TRACE("from_heap = " + from_heap.name() +
                 ", to_heap = " + to_heap.name());

    ValueType test_reps[] = {kWasmI32, ValueType::RefNull(from_heap)};
    FunctionSig test_sig(1, 1, test_reps);

    ValueType cast_reps[] = {ValueType::RefNull(to_heap),
                             ValueType::RefNull(from_heap)};
    FunctionSig cast_sig(1, 1, cast_reps);

    if (should_pass) {
      ExpectValidates(&test_sig, {WASM_REF_TEST(WASM_LOCAL_GET(0),
                                                WASM_HEAP_TYPE(to_heap))});
      ExpectValidates(&cast_sig, {WASM_REF_CAST(WASM_LOCAL_GET(0),
                                                WASM_HEAP_TYPE(to_heap))});
      ExpectValidates(&test_sig, {WASM_REF_TEST_NULL(WASM_LOCAL_GET(0),
                                                     WASM_HEAP_TYPE(to_heap))});
      ExpectValidates(&cast_sig, {WASM_REF_CAST_NULL(WASM_LOCAL_GET(0),
                                                     WASM_HEAP_TYPE(to_heap))});
    } else {
      std::string error_message =
          "local.get of type " + cast_reps[1].name() +
          " has to be in the same reference type hierarchy as (ref " +
          to_heap.name() + ")";
      ExpectFailure(&test_sig,
                    {WASM_REF_TEST(WASM_LOCAL_GET(0), WASM_HEAP_TYPE(to_heap))},
                    kAppendEnd,
                    ("Invalid types for ref.test: " + error_message).c_str());
      ExpectFailure(&cast_sig,
                    {WASM_REF_CAST(WASM_LOCAL_GET(0), WASM_HEAP_TYPE(to_heap))},
                    kAppendEnd,
                    ("Invalid types for ref.cast: " + error_message).c_str());
      ExpectFailure(
          &test_sig,
          {WASM_REF_TEST_NULL(WASM_LOCAL_GET(0), WASM_HEAP_TYPE(to_heap))},
          kAppendEnd,
          ("Invalid types for ref.test null: " + error_message).c_str());
      ExpectFailure(
          &cast_sig,
          {WASM_REF_CAST_NULL(WASM_LOCAL_GET(0), WASM_HEAP_TYPE(to_heap))},
          kAppendEnd,
          ("Invalid types for ref.cast null: " + error_message).c_str());
    }
  }

  // Trivial type error.
  ExpectFailure(
      sigs.v_v(),
      {WASM_REF_TEST(WASM_I32V(1), array_heap.representation()), kExprDrop},
      kAppendEnd,
      "Invalid types for ref.test: i32.const of type i32 has to be "
      "in the same reference type hierarchy as (ref 0)");
  ExpectFailure(
      sigs.v_v(),
      {WASM_REF_CAST(WASM_I32V(1), array_heap.representation()), kExprDrop},
      kAppendEnd,
      "Invalid types for ref.cast: i32.const of type i32 has to be "
      "in the same reference type hierarchy as (ref 0)");
}

TEST_F(FunctionBodyDecoderTest, BrOnCastOrCastFail) {
  ModuleTypeIndex super_struct = builder.AddStruct({F(kWasmI16, true)});
  ModuleTypeIndex sub_struct =
      builder.AddStruct({F(kWasmI16, true), F(kWasmI32, false)}, super_struct);

  ValueType supertype = ValueType::RefNull(super_struct);
  ValueType subtype = ValueType::RefNull(sub_struct);

  ExpectValidates(
      FunctionSig::Build(this->zone(), {kWasmI32, subtype}, {supertype}),
      {WASM_I32V(42), WASM_LOCAL_GET(0),
       WASM_BR_ON_CAST(0, super_struct, sub_struct), WASM_GC_OP(kExprRefCast),
       ToByte(sub_struct)});
  ExpectValidates(
      FunctionSig::Build(this->zone(), {kWasmI32, subtype}, {supertype}),
      {WASM_I32V(42), WASM_LOCAL_GET(0),
       WASM_BR_ON_CAST(0, super_struct, sub_struct), WASM_GC_OP(kExprRefCast),
       ToByte(sub_struct)});
  ExpectValidates(
      FunctionSig::Build(this->zone(), {kWasmI32, supertype}, {supertype}),
      {WASM_I32V(42), WASM_LOCAL_GET(0),
       WASM_BR_ON_CAST_FAIL(0, super_struct, sub_struct)});
  ExpectValidates(
      FunctionSig::Build(this->zone(), {kWasmI32, supertype}, {supertype}),
      {WASM_I32V(42), WASM_LOCAL_GET(0),
       WASM_BR_ON_CAST_FAIL_NULL(0, super_struct, sub_struct)});

  // Wrong branch type.
  ExpectFailure(
      FunctionSig::Build(this->zone(), {}, {supertype}),
      {WASM_LOCAL_GET(0), WASM_BR_ON_CAST(0, super_struct, sub_struct),
       WASM_UNREACHABLE},
      kAppendEnd, "br_on_cast must target a branch of arity at least 1");
  ExpectFailure(
      FunctionSig::Build(this->zone(), {subtype}, {supertype}),
      {WASM_I32V(42), WASM_LOCAL_GET(0),
       WASM_BR_ON_CAST_FAIL(0, super_struct, sub_struct)},
      kAppendEnd,
      "type error in branch[0] (expected (ref null 1), got (ref null 0))");
  ExpectFailure(FunctionSig::Build(this->zone(), {subtype}, {supertype}),
                {WASM_I32V(42), WASM_LOCAL_GET(0),
                 WASM_BR_ON_CAST_FAIL_NULL(0, super_struct, sub_struct)},
                kAppendEnd,
                "type error in branch[0] (expected (ref null 1), got (ref 0))");

  // Wrong fallthrough type.
  ExpectFailure(
      FunctionSig::Build(this->zone(), {subtype}, {supertype}),
      {WASM_LOCAL_GET(0), WASM_BR_ON_CAST(0, super_struct, sub_struct)},
      kAppendEnd,
      "type error in fallthru[0] (expected (ref null 1), got (ref null 0))");
  ExpectFailure(
      FunctionSig::Build(this->zone(), {supertype}, {supertype}),
      {WASM_BLOCK_I(WASM_LOCAL_GET(0),
                    WASM_BR_ON_CAST_FAIL(0, super_struct, sub_struct))},
      kAppendEnd, "type error in branch[0] (expected i32, got (ref null 0))");
  ExpectFailure(
      FunctionSig::Build(this->zone(), {supertype}, {supertype}),
      {WASM_BLOCK_I(WASM_LOCAL_GET(0),
                    WASM_BR_ON_CAST_FAIL_NULL(0, super_struct, sub_struct))},
      kAppendEnd, "type error in branch[0] (expected i32, got (ref 0))");

  // Wrong argument type.
  ExpectFailure(
      FunctionSig::Build(this->zone(), {subtype}, {kWasmExternRef}),
      {WASM_LOCAL_GET(0), WASM_BR_ON_CAST(0, super_struct, sub_struct),
       WASM_GC_OP(kExprRefCast), ToByte(sub_struct)},
      kAppendEnd,
      "br_on_cast[0] expected type (ref null 0), found local.get of type "
      "externref");
  ExpectFailure(
      FunctionSig::Build(this->zone(), {subtype}, {kWasmExternRef}),
      {WASM_LOCAL_GET(0), WASM_BR_ON_CAST_NULL(0, super_struct, sub_struct),
       WASM_GC_OP(kExprRefCast), ToByte(sub_struct)},
      kAppendEnd,
      "br_on_cast[0] expected type (ref null 0), found local.get of type "
      "externref");
  ExpectFailure(
      FunctionSig::Build(this->zone(), {supertype}, {kWasmExternRef}),
      {WASM_LOCAL_GET(0), WASM_BR_ON_CAST_FAIL(0, super_struct, sub_struct)},
      kAppendEnd,
      "br_on_cast_fail[0] expected type (ref null 0), found local.get of type "
      "externref");
  ExpectFailure(
      FunctionSig::Build(this->zone(), {supertype}, {kWasmExternRef}),
      {WASM_LOCAL_GET(0),
       WASM_BR_ON_CAST_FAIL_NULL(0, super_struct, sub_struct)},
      kAppendEnd,
      "br_on_cast_fail[0] expected type (ref null 0), found local.get of "
      "type externref");

  // Wrong immediate type.
  ExpectFailure(
      FunctionSig::Build(this->zone(), {subtype}, {kWasmExternRef}),
      {WASM_LOCAL_GET(0), WASM_BR_ON_CAST(0, kExternRefCode, sub_struct),
       WASM_GC_OP(kExprRefCast), ToByte(sub_struct)},
      kAppendEnd,
      "invalid types for br_on_cast: (ref 1) is not a subtype of externref");
  ExpectFailure(
      FunctionSig::Build(this->zone(), {subtype}, {kWasmExternRef}),
      {WASM_LOCAL_GET(0), WASM_BR_ON_CAST_NULL(0, kExternRefCode, sub_struct),
       WASM_GC_OP(kExprRefCast), ToByte(sub_struct)},
      kAppendEnd,
      "invalid types for br_on_cast: (ref null 1) is not a subtype of "
      "externref");
  ExpectFailure(
      FunctionSig::Build(this->zone(), {supertype}, {kWasmExternRef}),
      {WASM_LOCAL_GET(0), WASM_BR_ON_CAST_FAIL(0, kExternRefCode, sub_struct)},
      kAppendEnd,
      "invalid types for br_on_cast_fail: (ref 1) is not a subtype of "
      "externref");
  ExpectFailure(
      FunctionSig::Build(this->zone(), {supertype}, {kWasmExternRef}),
      {WASM_LOCAL_GET(0),
       WASM_BR_ON_CAST_FAIL_NULL(0, kExternRefCode, sub_struct)},
      kAppendEnd,
      "invalid types for br_on_cast_fail: (ref null 1) is not a subtype "
      "of externref");
}

TEST_F(FunctionBodyDecoderTest, BrOnAbstractType) {
  ValueType kNonNullableFunc = ValueType::Ref(HeapType::kFunc);

  ExpectValidates(
      FunctionSig::Build(this->zone(), {kWasmStructRef}, {kWasmAnyRef}),
      {WASM_LOCAL_GET(0), WASM_BR_ON_CAST(0, kAnyRefCode, kStructRefCode),
       WASM_GC_OP(kExprRefCast), kStructRefCode});
  ExpectValidates(
      FunctionSig::Build(this->zone(), {kWasmAnyRef}, {kWasmAnyRef}),
      {WASM_LOCAL_GET(0),
       WASM_BR_ON_CAST_FAIL(0, kAnyRefCode, kStructRefCode)});
  ExpectValidates(
      FunctionSig::Build(this->zone(), {kWasmI31Ref}, {kWasmAnyRef}),
      {WASM_LOCAL_GET(0), WASM_BR_ON_CAST(0, kAnyRefCode, kI31RefCode),
       WASM_GC_OP(kExprRefCast), kI31RefCode});
  ExpectValidates(
      FunctionSig::Build(this->zone(), {kWasmAnyRef}, {kWasmAnyRef}),
      {WASM_LOCAL_GET(0), WASM_BR_ON_CAST_FAIL(0, kAnyRefCode, kI31RefCode)});

  // Wrong branch type.
  ExpectFailure(
      FunctionSig::Build(this->zone(), {}, {kWasmAnyRef}),
      {WASM_LOCAL_GET(0), WASM_BR_ON_CAST(0, kAnyRefCode, kStructRefCode),
       WASM_UNREACHABLE},
      kAppendEnd, "br_on_cast must target a branch of arity at least 1");
  ExpectFailure(
      FunctionSig::Build(this->zone(), {kNonNullableFunc}, {kWasmAnyRef}),
      {WASM_LOCAL_GET(0), WASM_BR_ON_CAST_FAIL(0, kAnyRefCode, kStructRefCode)},
      kAppendEnd, "type error in branch[0] (expected (ref func), got anyref)");

  // Wrong fallthrough type.
  ExpectFailure(
      FunctionSig::Build(this->zone(), {kWasmStructRef}, {kWasmAnyRef}),
      {WASM_LOCAL_GET(0), WASM_BR_ON_CAST(0, kAnyRefCode, kStructRefCode)},
      kAppendEnd, "type error in fallthru[0] (expected structref, got anyref)");
  ExpectFailure(
      FunctionSig::Build(this->zone(), {kWasmAnyRef}, {kWasmAnyRef}),
      {WASM_BLOCK_I(WASM_LOCAL_GET(0),
                    WASM_BR_ON_CAST_FAIL(0, kAnyRefCode, kStructRefCode))},
      kAppendEnd, "type error in branch[0] (expected i32, got anyref)");

  // Argument type error.
  ExpectFailure(
      FunctionSig::Build(this->zone(), {kWasmI31Ref}, {kWasmI32}),
      {WASM_LOCAL_GET(0), WASM_BR_ON_CAST(0, kAnyRefCode, kI31RefCode),
       WASM_GC_OP(kExprRefCast), kI31RefCode},
      kAppendEnd,
      "br_on_cast[0] expected type anyref, found local.get of type i32");
}

TEST_F(FunctionBodyDecoderTest, BrWithBottom) {
  // Merging an unsatisfiable non-nullable (ref none) into a target that
  // expects a non-null struct is OK.
  ExpectValidates(
      FunctionSig::Build(this->zone(), {ValueType::Ref(HeapType::kStruct)},
                         {ValueType::Ref(HeapType::kStruct)}),
      {WASM_BR_ON_NON_NULL(0, WASM_REF_NULL(ValueTypeCode::kNoneCode)),
       WASM_LOCAL_GET(0)});
  // Merging the same value into a target that expects a value outside
  // the "anyref" hierarchy is invalid...
  ExpectFailure(
      FunctionSig::Build(this->zone(), {kWasmFuncRef}, {kWasmFuncRef}),
      {WASM_BR_ON_NON_NULL(0, WASM_REF_NULL(ValueTypeCode::kNoneCode)),
       WASM_LOCAL_GET(0)},
      kAppendEnd, "type error in branch[0] (expected funcref, got (ref none))");
  // ...because it would have to be a (ref nofunc) in that case.
  ExpectValidates(
      FunctionSig::Build(this->zone(), {kWasmFuncRef}, {kWasmFuncRef}),
      {WASM_BR_ON_NON_NULL(0, WASM_REF_NULL(ValueTypeCode::kNoFuncCode)),
       WASM_LOCAL_GET(0)});
  // (ref nofunc) in turn doesn't match anyref.
  ExpectFailure(
      FunctionSig::Build(this->zone(), {kWasmAnyRef}, {kWasmAnyRef}),
      {WASM_BR_ON_NON_NULL(0, WASM_REF_NULL(ValueTypeCode::kNoFuncCode)),
       WASM_LOCAL_GET(0)},
      kAppendEnd,
      "type error in branch[0] (expected anyref, got (ref nofunc))");
}

TEST_F(FunctionBodyDecoderTest, LocalTeeTyping) {
  ModuleTypeIndex array_type = builder.AddArray(kWasmI8, true);

  ValueType types[] = {ValueType::Ref(array_type)};
  FunctionSig sig(1, 0, types);

  AddLocals(ValueType::RefNull(array_type), 1);

  ExpectFailure(
      &sig,
      {WASM_LOCAL_TEE(0, WASM_ARRAY_NEW_DEFAULT(array_type, WASM_I32V(5)))},
      kAppendEnd, "expected (ref 0), got (ref null 0)");
}

TEST_F(FunctionBodyDecoderTest, MergeNullableTypes) {
  ModuleTypeIndex struct_type_index = builder.AddStruct({F(kWasmI32, true)});
  ValueType struct_type = refNull(struct_type_index);
  FunctionSig loop_sig(0, 1, &struct_type);
  ModuleTypeIndex loop_sig_index = builder.AddSignature(&loop_sig);
  // Verifies that when a loop consuming a nullable type is entered with a
  // statically known non-null value on the stack, its {start_merge_} can
  // consume null values later.
  // Regression test for crbug.com/1234453.
  ExpectValidates(sigs.v_v(),
                  {WASM_GC_OP(kExprStructNewDefault), ToByte(struct_type_index),
                   WASM_LOOP_X(loop_sig_index, kExprDrop, kExprRefNull,
                               ToByte(struct_type_index), kExprBr, 0)});
}

// This tests that num_locals_ in decoder remains consistent, even if we fail
// mid-DecodeLocals().
TEST_F(FunctionBodyDecoderTest, Regress_1154439) {
  AddLocals(kWasmI32, 1);
  AddLocals(kWasmI64, 1000000);
  ExpectFailure(sigs.v_v(), {}, kAppendEnd, "local count too large");
}

TEST_F(FunctionBodyDecoderTest, DropOnEmptyStack) {
  // Valid code:
  ExpectValidates(sigs.v_v(), {kExprI32Const, 1, kExprDrop}, kAppendEnd);
  // Invalid code (dropping from empty stack):
  ExpectFailure(sigs.v_v(), {kExprDrop}, kAppendEnd,
                "not enough arguments on the stack for drop");
  // Valid code (dropping from empty stack in unreachable code):
  ExpectValidates(sigs.v_v(), {kExprUnreachable, kExprDrop}, kAppendEnd);
}

TEST_F(FunctionBodyDecoderTest, AnyConvertExtern) {
  ExpectValidates(FunctionSig::Build(zone(), {kWasmAnyRef}, {}),
                  {WASM_GC_ANY_CONVERT_EXTERN(WASM_REF_NULL(kNoExternCode))});
  ExpectValidates(FunctionSig::Build(zone(), {kWasmAnyRef}, {kWasmExternRef}),
                  {WASM_GC_ANY_CONVERT_EXTERN(WASM_LOCAL_GET(0))});
  ExpectValidates(
      FunctionSig::Build(zone(), {kWasmAnyRef}, {kWasmExternRef.AsNonNull()}),
      {WASM_GC_ANY_CONVERT_EXTERN(WASM_LOCAL_GET(0))});
  ExpectFailure(FunctionSig::Build(zone(), {kWasmAnyRef}, {}),
                {WASM_GC_ANY_CONVERT_EXTERN(kExprNop)}, kAppendEnd,
                "not enough arguments on the stack for any.convert_extern "
                "(need 1, got 0)");
  ExpectFailure(
      FunctionSig::Build(zone(), {kWasmAnyRef.AsNonNull()}, {kWasmExternRef}),
      {WASM_GC_ANY_CONVERT_EXTERN(WASM_LOCAL_GET(0))}, kAppendEnd,
      "type error in fallthru[0] (expected (ref any), got anyref)");
  ExpectFailure(FunctionSig::Build(zone(), {kWasmAnyRef}, {kWasmAnyRef}),
                {WASM_GC_ANY_CONVERT_EXTERN(WASM_LOCAL_GET(0))}, kAppendEnd,
                "any.convert_extern[0] expected type externref, found "
                "local.get of type anyref");
}

TEST_F(FunctionBodyDecoderTest, ExternConvertAny) {
  ExpectValidates(FunctionSig::Build(zone(), {kWasmExternRef}, {}),
                  {WASM_GC_EXTERN_CONVERT_ANY(WASM_REF_NULL(kNoneCode))});
  ExpectValidates(FunctionSig::Build(zone(), {kWasmExternRef}, {kWasmAnyRef}),
                  {WASM_GC_EXTERN_CONVERT_ANY(WASM_LOCAL_GET(0))});
  ExpectValidates(
      FunctionSig::Build(zone(), {kWasmExternRef}, {kWasmAnyRef.AsNonNull()}),
      {WASM_GC_EXTERN_CONVERT_ANY(WASM_LOCAL_GET(0))});
  ExpectFailure(FunctionSig::Build(zone(), {kWasmExternRef}, {}),
                {WASM_GC_EXTERN_CONVERT_ANY(kExprNop)}, kAppendEnd,
                "not enough arguments on the stack for extern.convert_any "
                "(need 1, got 0)");
  ExpectFailure(
      FunctionSig::Build(zone(), {kWasmExternRef.AsNonNull()}, {kWasmAnyRef}),
      {WASM_GC_EXTERN_CONVERT_ANY(WASM_LOCAL_GET(0))}, kAppendEnd,
      "type error in fallthru[0] (expected (ref extern), got externref)");
  ExpectFailure(FunctionSig::Build(zone(), {kWasmExternRef}, {kWasmExternRef}),
                {WASM_GC_EXTERN_CONVERT_ANY(WASM_LOCAL_GET(0))}, kAppendEnd,
                "extern.convert_any[0] expected type anyref, found "
                "local.get of type externref");
}

class BranchTableIteratorTest : public TestWithZone {
 public:
  BranchTableIteratorTest() : TestWithZone() {}
  void CheckBrTableSize(const uint8_t* start, const uint8_t* end) {
    Decoder decoder(start, end);
    BranchTableImmediate operand(&decoder, start + 1, Decoder::kFullValidation);
    BranchTableIterator<Decoder::FullValidationTag> iterator(&decoder, operand);
    EXPECT_EQ(end - start - 1u, iterator.length());
    EXPECT_OK(decoder);
  }
  void CheckBrTableError(const uint8_t* start, const uint8_t* end) {
    Decoder decoder(start, end);
    BranchTableImmediate operand(&decoder, start + 1, Decoder::kFullValidation);
    BranchTableIterator<Decoder::FullValidationTag> iterator(&decoder, operand);
    iterator.length();
    EXPECT_FALSE(decoder.ok());
  }
};

#define CHECK_BR_TABLE_LENGTH(...)                       \
  {                                                      \
    static uint8_t code[] = {kExprBrTable, __VA_ARGS__}; \
    CheckBrTableSize(code, code + sizeof(code));         \
  }

#define CHECK_BR_TABLE_ERROR(...)                        \
  {                                                      \
    static uint8_t code[] = {kExprBrTable, __VA_ARGS__}; \
    CheckBrTableError(code, code + sizeof(code));        \
  }

TEST_F(BranchTableIteratorTest, count0) {
  CHECK_BR_TABLE_LENGTH(0, U32V_1(1));
  CHECK_BR_TABLE_LENGTH(0, U32V_2(200));
  CHECK_BR_TABLE_LENGTH(0, U32V_3(30000));
  CHECK_BR_TABLE_LENGTH(0, U32V_4(400000));

  CHECK_BR_TABLE_LENGTH(0, U32V_1(2));
  CHECK_BR_TABLE_LENGTH(0, U32V_2(300));
  CHECK_BR_TABLE_LENGTH(0, U32V_3(40000));
  CHECK_BR_TABLE_LENGTH(0, U32V_4(500000));
}

TEST_F(BranchTableIteratorTest, count1) {
  CHECK_BR_TABLE_LENGTH(1, U32V_1(1), U32V_1(6));
  CHECK_BR_TABLE_LENGTH(1, U32V_2(200), U32V_1(8));
  CHECK_BR_TABLE_LENGTH(1, U32V_3(30000), U32V_1(9));
  CHECK_BR_TABLE_LENGTH(1, U32V_4(400000), U32V_1(11));

  CHECK_BR_TABLE_LENGTH(1, U32V_1(2), U32V_2(6));
  CHECK_BR_TABLE_LENGTH(1, U32V_2(300), U32V_2(7));
  CHECK_BR_TABLE_LENGTH(1, U32V_3(40000), U32V_2(8));
  CHECK_BR_TABLE_LENGTH(1, U32V_4(500000), U32V_2(9));
}

TEST_F(BranchTableIteratorTest, error0) {
  CHECK_BR_TABLE_ERROR(0);
  CHECK_BR_TABLE_ERROR(1, U32V_1(33));
}

#undef CHECK_BR_TABLE_LENGTH
#undef CHECK_BR_TABLE_ERROR

struct PrintOpcodes {
  const uint8_t* start;
  const uint8_t* end;
};
std::ostream& operator<<(std::ostream& out, const PrintOpcodes& range) {
  out << "First opcode: \""
      << WasmOpcodes::OpcodeName(static_cast<WasmOpcode>(*range.start))
      << "\"\nall bytes: [";
  for (const uint8_t* b = range.start; b < range.end; ++b) {
    out << (b == range.start ? "" : ", ") << uint32_t{*b} << "/"
        << AsHex(*b, 2, true);
  }
  return out << "]";
}

class WasmOpcodeLengthTest : public TestWithZone {
 public:
  WasmOpcodeLengthTest() : TestWithZone() {}

  template <typename... Bytes>
  void ExpectLength(unsigned expected, Bytes... bytes) {
    const uint8_t code[] = {
        static_cast<uint8_t>(bytes)..., 0, 0, 0, 0, 0, 0, 0, 0};
    EXPECT_EQ(expected, OpcodeLength(code, code + sizeof(code)))
        << PrintOpcodes{code, code + sizeof...(bytes)};
  }

  // Helper to check for prefixed opcodes, which can have multiple bytes.
  void ExpectLengthPrefixed(unsigned operands, WasmOpcode opcode) {
    uint8_t prefix = WasmOpcodes::ExtractPrefix(opcode);
    DCHECK(WasmOpcodes::IsPrefixOpcode(static_cast<WasmOpcode>(prefix)));
    uint16_t index = ExtractPrefixedOpcodeBytes(opcode);
    uint8_t encoded[2] = {0, 0};
    uint8_t* p = encoded;
    unsigned len = static_cast<unsigned>(LEBHelper::sizeof_u32v(index));
    DCHECK_GE(2, len);
    LEBHelper::write_u32v(&p, index);
    // length of index, + number of operands + prefix bye
    ExpectLength(len + operands + 1, prefix, encoded[0], encoded[1]);
  }

  template <typename... Bytes>
  void ExpectFailure(Bytes... bytes) {
    const uint8_t code[] = {
        static_cast<uint8_t>(bytes)..., 0, 0, 0, 0, 0, 0, 0, 0};
    WasmDetectedFeatures detected_features;
    constexpr bool kIsShared = false;  // TODO(14616): Extend this.
    WasmDecoder<Decoder::FullValidationTag> decoder(
        this->zone(), nullptr, WasmEnabledFeatures::None(), &detected_features,
        nullptr, kIsShared, code, code + sizeof(code), 0);
    WasmDecoder<Decoder::FullValidationTag>::OpcodeLength(&decoder, code);
    EXPECT_TRUE(decoder.failed());
  }

  void ExpectNonFailure(WasmOpcode opcode) {
    uint8_t maybe_prefix = WasmOpcodes::ExtractPrefix(opcode);
    uint8_t bytes[32]{0};
    if (WasmOpcodes::IsPrefixOpcode(static_cast<WasmOpcode>(maybe_prefix))) {
      bytes[0] = maybe_prefix;
      uint16_t index = ExtractPrefixedOpcodeBytes(opcode);
      uint8_t* p = &bytes[1];
      LEBHelper::write_u32v(&p, index);
    } else {
      DCHECK_LE(static_cast<uint32_t>(opcode), 0xFF);
      bytes[0] = static_cast<uint8_t>(opcode);
      // Special case: select_with_type insists on a {1} immediate.
      if (opcode == kExprSelectWithType) {
        bytes[1] = 1;
        bytes[2] = kAnyRefCode;
      }
    }
    WasmDetectedFeatures detected;
    constexpr bool kIsShared = false;  // TODO(14616): Extend this.
    WasmDecoder<Decoder::FullValidationTag> decoder(
        this->zone(), nullptr, WasmEnabledFeatures::All(), &detected, nullptr,
        kIsShared, bytes, bytes + sizeof(bytes), 0);
    WasmDecoder<Decoder::FullValidationTag>::OpcodeLength(&decoder, bytes);
    EXPECT_TRUE(decoder.ok())
        << opcode << " aka " << WasmOpcodes::OpcodeName(opcode) << ": "
        << decoder.error().message();
  }
};

TEST_F(WasmOpcodeLengthTest, AllOpcodesImplemented) {
  // Make sure we didn't forget to add an opcode to the switch statements
  // in the {OpcodeLength} function. Due to nested handling of prefixed
  // opcodes, and the desire to support invalid modules, we can't rely on
  // compiler warnings for non-exhaustive cases lists here.
#define OPCODE(opcode, ...) ExpectNonFailure(kExpr##opcode);
  FOREACH_OPCODE(OPCODE)
#undef OPCODE
}

TEST_F(WasmOpcodeLengthTest, Statements) {
  ExpectLength(1, kExprNop);
  ExpectLength(1, kExprElse);
  ExpectLength(1, kExprEnd);
  ExpectLength(1, kExprSelect);
  ExpectLength(2, kExprCatch);
  ExpectLength(2, kExprDelegate);
  ExpectLength(2, kExprRethrow);
  ExpectLength(2, kExprBr);
  ExpectLength(2, kExprBrIf);
  ExpectLength(2, kExprThrow);
  ExpectLength(2, kExprBlock, kI32Code);
  ExpectLength(2, kExprLoop, kI32Code);
  ExpectLength(2, kExprIf, kI32Code);
  ExpectLength(2, kExprTry, kI32Code);
}

TEST_F(WasmOpcodeLengthTest, MiscExpressions) {
  ExpectLength(5, kExprF32Const);
  ExpectLength(9, kExprF64Const);
  ExpectLength(2, kExprRefNull);
  ExpectLength(2, kExprLocalGet);
  ExpectLength(2, kExprLocalSet);
  ExpectLength(2, kExprGlobalGet);
  ExpectLength(2, kExprGlobalSet);
  ExpectLength(2, kExprCallFunction);
  ExpectLength(3, kExprCallIndirect);
  ExpectLength(3, kExprSelectWithType, 1, kI32Code);
}

TEST_F(WasmOpcodeLengthTest, I32Const) {
  ExpectLength(2, kExprI32Const, U32V_1(1));
  ExpectLength(3, kExprI32Const, U32V_2(999));
  ExpectLength(4, kExprI32Const, U32V_3(9999));
  ExpectLength(5, kExprI32Const, U32V_4(999999));
  ExpectLength(6, kExprI32Const, U32V_5(99999999));
}

TEST_F(WasmOpcodeLengthTest, I64Const) {
  ExpectLength(2, kExprI64Const, U32V_1(1));
  ExpectLength(3, kExpr
```