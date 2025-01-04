Response: The user has provided a C++ source code file in multiple parts and is asking for a summary of its functionality. This is part 2 of 4. The file name `function-body-decoder-unittest.cc` strongly suggests this file contains unit tests for a component that decodes WebAssembly function bodies.

**Mental Sandbox:**

1. **High-Level Functionality:** The code is testing the `FunctionBodyDecoder`. This likely involves feeding various byte sequences representing Wasm instructions to the decoder and verifying the decoder's behavior (success or failure).

2. **Focus of Part 2:** Looking at the test names in this section, there's a heavy focus on function calls, both direct and indirect, including `return_call` and `call_indirect`. There are also tests for multi-return functions, global variable access, table operations (`table.set`, `table.get`, `call_indirect_table`), memory operations (`memory.grow`), control flow instructions (breaks, `br_table`), `select`, `throw`, and basic exception handling (`try`, `catch`, `rethrow`, `delegate`, `throw_ref`, `try_table`).

3. **Relationship to JavaScript:** WebAssembly is designed to be a compilation target for languages like C/C++ and can run in JavaScript environments. The tests likely validate that the decoding process correctly interprets Wasm instructions that correspond to JavaScript's function calling mechanisms, variable access, and control flow.

4. **Code Structure:** The tests use a testing framework (likely Google Test, given `TEST_F`). Each test case sets up a scenario (e.g., calling a function with a mismatched signature) and uses `ExpectValidates` or `ExpectFailure` to assert the decoder's behavior. The `builder` object is likely used to construct a minimal Wasm module for testing.

5. **Specific Instruction Tests:** The test names reveal various Wasm instructions being tested: `WASM_CALL_FUNCTION`, `WASM_RETURN_CALL_FUNCTION`, `WASM_CALL_INDIRECT`, `WASM_RETURN_CALL_INDIRECT`, `WASM_GLOBAL_GET`, `WASM_GLOBAL_SET`, `WASM_TABLE_SET`, `WASM_TABLE_GET`, `WASM_MEMORY_GROW`, `WASM_BR`, `WASM_BRV`, `WASM_BR_TABLE`, `WASM_SELECT`, `kExprThrow`, `kExprTry`, `kExprCatch`, `kExprRethrow`, `kExprDelegate`, `kExprThrowRef`, `kExprTryTable`, and more.

6. **Generating JavaScript Examples:** To demonstrate the relationship with JavaScript, I need to think about what these Wasm instructions translate to conceptually in JS. For example:
    * `WASM_CALL_FUNCTION` is like calling a JS function.
    * `WASM_GLOBAL_GET` is like accessing a global variable in JS.
    * `WASM_TABLE_SET` is like setting an element in a JS array or object.
    * `WASM_BR` is like a `break` statement in a JS loop or block.
    * `WASM_SELECT` is like the ternary operator (`condition ? value1 : value2`) in JS.
    * `kExprThrow` is like the `throw` statement in JS.
    * `kExprTry` and `kExprCatch` are like `try...catch` blocks in JS.

**Refinement of Summary:**

The initial thought is correct. This part focuses heavily on validating function calls and control flow. It's important to highlight that the tests check for both valid and invalid Wasm bytecode sequences to ensure the decoder correctly handles errors. The JavaScript examples need to be concise and illustrate the corresponding high-level behavior.

**Final Conclusion:** This part of the unit test focuses on validating the function body decoder's ability to correctly interpret various WebAssembly instructions related to function calls (direct, indirect, return calls), accessing global variables, table operations, memory manipulation, control flow (breaks, branching), selection, and exception handling. The tests cover both valid and invalid bytecode sequences to ensure robust error detection.
这是 `v8/test/unittests/wasm/function-body-decoder-unittest.cc` 文件的第二部分，主要侧重于测试 WebAssembly 函数体解码器对以下特性的处理：

**核心功能归纳:**

* **函数调用 (Function Calls):**
    * **直接调用 (`call_function`):** 测试直接调用已定义的函数，包括参数数量和类型匹配的情况，以及签名不匹配导致验证失败的情况。
    * **返回调用 (`return_call_function`):**  测试从当前函数直接返回到另一个函数的调用，类似于尾调用优化。测试了参数匹配和签名不匹配的情况。
    * **间接调用 (`call_indirect`):** 测试通过函数表进行间接调用，包括指定签名索引、越界访问、签名不匹配以及在没有函数表时的处理。
    * **带 Table 的间接调用 (`call_indirect_table`):** 测试指定特定 Table 进行间接调用，并验证了 Table 类型与调用签名之间的关系，包括函数子类型的情况。
    * **导入函数调用 (Import Calls):** 测试调用导入的外部函数，并验证了签名匹配的要求。

* **全局变量 (Globals):**
    * **获取全局变量 (`global.get`):** 测试获取不同类型的全局变量（i32, i64, f32, f64, ref, externref, funcref, exnref），并验证了类型匹配。
    * **设置全局变量 (`global.set`):** 测试设置不同类型的全局变量，包括可变和不可变全局变量的验证。

* **Table 操作 (Table Operations):**
    * **设置 Table 元素 (`table.set`):** 测试向 Table 中设置不同类型的引用（externref, funcref, typed funcref），并验证了类型匹配和越界访问的情况。
    * **获取 Table 元素 (`table.get`):** 测试从 Table 中获取不同类型的引用，并验证了类型匹配。

* **内存操作 (Memory Operations):**
    * **内存增长 (`memory.grow`):** 测试内存增长指令，并验证了参数类型。

* **控制流 (Control Flow):**
    * **`br` (break):** 测试无条件跳转指令，包括在不同嵌套层级和多返回值情况下的验证。
    * **`br_if` (break if):** 测试条件跳转指令，包括条件类型和返回值类型的验证。
    * **`br_table` (break table):** 测试分支表指令，包括索引类型、目标标签有效性、返回值类型匹配等。

* **选择指令 (`select`):** 测试 `select` 指令，验证了操作数类型一致性，以及带类型和不带类型的 `select` 指令。

* **异常处理 (Exception Handling - 需要特性支持):**
    * **`throw`:** 测试抛出异常指令，并验证了异常索引的有效性。
    * **`try...catch` (legacy):** 测试传统的 `try...catch` 结构，包括 `catch` 和 `catch_all` 的使用。
    * **`rethrow` (legacy):** 测试在 `catch` 块中重新抛出异常。
    * **`delegate` (legacy):** 测试 `try...delegate` 结构，将异常处理委托给外层 `try` 块。
    * **`throw_ref` (exnref 特性):** 测试抛出异常引用。
    * **`try_table` (exnref 特性):** 测试新的 `try_table` 结构，可以捕获特定类型的异常或所有异常引用。

* **多返回值 (Multi-Value Blocks):** 测试带有参数的 Block 和 Loop，验证了参数的传递和类型匹配。

* **Memory 初始化和 Data Drop (Bulk Memory Operations):** 测试 `memory.init` 和 `data.drop` 指令。

* **Memory Copy 和 Fill:** 测试 `memory.copy` 和 `memory.fill` 指令。

**与 JavaScript 的关系 (及其 JavaScript 示例):**

这些测试直接关系到 JavaScript 引擎如何执行 WebAssembly 代码。  WebAssembly 的指令在 JavaScript 虚拟机中会被翻译成相应的操作。

* **函数调用:**  Wasm 的函数调用指令类似于 JavaScript 中的函数调用。
    ```javascript
    function wasmFunction(a, b) {
      // ... wasm 指令 ...
      return a + b;
    }

    let result = wasmFunction(10, 20); // 对应 WASM_CALL_FUNCTION
    ```

* **全局变量:** Wasm 的全局变量可以与 JavaScript 的全局变量或模块作用域内的变量进行交互。
    ```javascript
    // Wasm module 中定义了一个 i32 类型的全局变量
    let wasmGlobal = wasmModule.exports.globalVar; // 对应 WASM_GLOBAL_GET

    wasmModule.exports.setGlobalVar(42); // 对应 WASM_GLOBAL_SET
    ```

* **Table 操作:** Wasm 的 Table 类似于 JavaScript 中的数组或可以存储函数引用的结构。
    ```javascript
    // Wasm module 中定义了一个函数表
    let funcTable = wasmModule.exports.functionTable;

    let func = funcTable.get(0); // 对应 WASM_TABLE_GET
    func(5); // 间接调用，类似于 WASM_CALL_INDIRECT

    funcTable.set(1, anotherWasmFunction); // 对应 WASM_TABLE_SET
    ```

* **内存操作:** Wasm 的线性内存可以被 JavaScript 通过 `WebAssembly.Memory` 对象访问和操作。
    ```javascript
    let memory = wasmModule.exports.memory;
    let buffer = new Uint8Array(memory.buffer);
    buffer[0] = 10; // 类似于 Wasm 的内存存储指令

    memory.grow(1); // 对应 WASM_MEMORY_GROW
    ```

* **控制流:** Wasm 的控制流指令与 JavaScript 的控制流语句有对应关系。
    ```javascript
    // WASM_BR 类似于 JavaScript 的 break
    for (let i = 0; i < 10; i++) {
      if (i > 5) {
        break;
      }
      // ...
    }

    // WASM_BR_IF 类似于 JavaScript 的 if 语句结合 break
    for (let i = 0; i < 10; i++) {
      if (condition) {
        break;
      }
      // ...
    }

    // WASM_SELECT 类似于 JavaScript 的三元运算符
    let result = condition ? value1 : value2; // 对应 WASM_SELECT
    ```

* **异常处理:** Wasm 的异常处理机制与 JavaScript 的 `try...catch` 类似。
    ```javascript
    try {
      // 对应 Wasm 中可能抛出异常的操作
      wasmModule.exports.mightThrow(); // 对应 WASM_THROW
    } catch (e) {
      // 处理异常
      console.error("Caught an exception:", e);
    }
    ```

**总结:**

这部分单元测试深入验证了 WebAssembly 函数体解码器在处理各种函数调用方式、全局变量访问、Table 操作、内存管理、控制流以及异常处理等核心功能时的正确性。这些功能都直接影响着 JavaScript 引擎执行 WebAssembly 代码的行为，确保了 WebAssembly 代码在 JavaScript 环境中能够安全可靠地运行。

Prompt: ```这是目录为v8/test/unittests/wasm/function-body-decoder-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
lidates(&sig, {WASM_RETURN_CALL_FUNCTION0(0)});
}

TEST_F(FunctionBodyDecoderTest, ReturnCallsWithMismatchedSigs) {
  const FunctionSig* sig = sigs.i_i();

  builder.AddFunction(sigs.i_f());
  builder.AddFunction(sigs.f_f());

  ExpectFailure(sig, {WASM_RETURN_CALL_FUNCTION(0, WASM_I32V_1(17))});
  ExpectFailure(sig, {WASM_RETURN_CALL_FUNCTION(0, WASM_I64V_1(27))});
  ExpectFailure(sig, {WASM_RETURN_CALL_FUNCTION(0, WASM_F64(37.2))});

  ExpectFailure(sig, {WASM_RETURN_CALL_FUNCTION(1, WASM_F64(37.2))});
  ExpectFailure(sig, {WASM_RETURN_CALL_FUNCTION(1, WASM_F32(37.2))});
  ExpectFailure(sig, {WASM_RETURN_CALL_FUNCTION(1, WASM_I32V_1(17))});
}

TEST_F(FunctionBodyDecoderTest, SimpleIndirectReturnCalls) {
  const FunctionSig* sig = sigs.i_i();
  builder.AddTable(kWasmFuncRef, 20, true, 30);

  ModuleTypeIndex sig0 = builder.AddSignature(sigs.i_v());
  ModuleTypeIndex sig1 = builder.AddSignature(sigs.i_i());
  ModuleTypeIndex sig2 = builder.AddSignature(sigs.i_ii());

  ExpectValidates(sig, {WASM_RETURN_CALL_INDIRECT(sig0, WASM_ZERO)});
  ExpectValidates(
      sig, {WASM_RETURN_CALL_INDIRECT(sig1, WASM_I32V_1(22), WASM_ZERO)});
  ExpectValidates(sig, {WASM_RETURN_CALL_INDIRECT(sig2, WASM_I32V_1(32),
                                                  WASM_I32V_2(72), WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, IndirectReturnCallsOutOfBounds) {
  const FunctionSig* sig = sigs.i_i();
  builder.AddTable(kWasmFuncRef, 20, false, 20);

  ExpectFailure(sig, {WASM_RETURN_CALL_INDIRECT(0, WASM_ZERO)});
  builder.AddSignature(sigs.i_v());
  ExpectValidates(sig, {WASM_RETURN_CALL_INDIRECT(0, WASM_ZERO)});

  ExpectFailure(sig,
                {WASM_RETURN_CALL_INDIRECT(1, WASM_I32V_1(22), WASM_ZERO)});
  builder.AddSignature(sigs.i_i());
  ExpectValidates(sig,
                  {WASM_RETURN_CALL_INDIRECT(1, WASM_I32V_1(27), WASM_ZERO)});

  ExpectFailure(sig,
                {WASM_RETURN_CALL_INDIRECT(2, WASM_I32V_1(27), WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, IndirectReturnCallsWithMismatchedSigs3) {
  const FunctionSig* sig = sigs.i_i();
  builder.AddTable(wasm::kWasmVoid);

  ModuleTypeIndex sig0 = builder.AddSignature(sigs.i_f());

  ExpectFailure(sig,
                {WASM_RETURN_CALL_INDIRECT(sig0, WASM_I32V_1(17), WASM_ZERO)});
  ExpectFailure(sig,
                {WASM_RETURN_CALL_INDIRECT(sig0, WASM_I64V_1(27), WASM_ZERO)});
  ExpectFailure(sig,
                {WASM_RETURN_CALL_INDIRECT(sig0, WASM_F64(37.2), WASM_ZERO)});

  ExpectFailure(sig, {WASM_RETURN_CALL_INDIRECT(sig0, WASM_I32V_1(17))});
  ExpectFailure(sig, {WASM_RETURN_CALL_INDIRECT(sig0, WASM_I64V_1(27))});
  ExpectFailure(sig, {WASM_RETURN_CALL_INDIRECT(sig0, WASM_F64(37.2))});

  ModuleTypeIndex sig1 = builder.AddSignature(sigs.i_d());

  ExpectFailure(sig,
                {WASM_RETURN_CALL_INDIRECT(sig1, WASM_I32V_1(16), WASM_ZERO)});
  ExpectFailure(sig,
                {WASM_RETURN_CALL_INDIRECT(sig1, WASM_I64V_1(16), WASM_ZERO)});
  ExpectFailure(sig,
                {WASM_RETURN_CALL_INDIRECT(sig1, WASM_F32(17.6), WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, IndirectReturnCallsWithoutTableCrash) {
  const FunctionSig* sig = sigs.i_i();

  ModuleTypeIndex sig0 = builder.AddSignature(sigs.i_v());
  ModuleTypeIndex sig1 = builder.AddSignature(sigs.i_i());
  ModuleTypeIndex sig2 = builder.AddSignature(sigs.i_ii());

  ExpectFailure(sig, {WASM_RETURN_CALL_INDIRECT(sig0, WASM_ZERO)});
  ExpectFailure(sig,
                {WASM_RETURN_CALL_INDIRECT(sig1, WASM_I32V_1(22), WASM_ZERO)});
  ExpectFailure(sig, {WASM_RETURN_CALL_INDIRECT(sig2, WASM_I32V_1(32),
                                                WASM_I32V_2(72), WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, IncompleteIndirectReturnCall) {
  const FunctionSig* sig = sigs.i_i();
  builder.AddTable(wasm::kWasmVoid);

  static uint8_t code[] = {kExprReturnCallIndirect};
  ExpectFailure(sig, base::ArrayVector(code), kOmitEnd);
}

TEST_F(FunctionBodyDecoderTest, MultiReturn) {
  ValueType storage[] = {kWasmI32, kWasmI32};
  FunctionSig sig_ii_v(2, 0, storage);
  FunctionSig sig_v_ii(0, 2, storage);

  builder.AddFunction(&sig_v_ii);
  builder.AddFunction(&sig_ii_v);

  ExpectValidates(&sig_ii_v, {WASM_CALL_FUNCTION0(1)});
  ExpectValidates(sigs.v_v(), {WASM_CALL_FUNCTION0(1), WASM_DROP, WASM_DROP});
  ExpectValidates(sigs.v_v(), {WASM_CALL_FUNCTION0(1), kExprCallFunction, 0});
}

TEST_F(FunctionBodyDecoderTest, MultiReturnType) {
  for (size_t a = 0; a < arraysize(kValueTypes); a++) {
    for (size_t b = 0; b < arraysize(kValueTypes); b++) {
      for (size_t c = 0; c < arraysize(kValueTypes); c++) {
        for (size_t d = 0; d < arraysize(kValueTypes); d++) {
          ValueType storage_ab[] = {kValueTypes[a], kValueTypes[b]};
          FunctionSig sig_ab_v(2, 0, storage_ab);
          ValueType storage_cd[] = {kValueTypes[c], kValueTypes[d]};
          FunctionSig sig_cd_v(2, 0, storage_cd);

          TestModuleBuilder builder;
          module = builder.module();
          builder.AddFunction(&sig_cd_v);

          ExpectValidates(&sig_cd_v, {WASM_CALL_FUNCTION0(0)});

          if (IsSubtypeOf(kValueTypes[c], kValueTypes[a], module) &&
              IsSubtypeOf(kValueTypes[d], kValueTypes[b], module)) {
            ExpectValidates(&sig_ab_v, {WASM_CALL_FUNCTION0(0)});
          } else {
            ExpectFailure(&sig_ab_v, {WASM_CALL_FUNCTION0(0)});
          }
        }
      }
    }
  }
}

TEST_F(FunctionBodyDecoderTest, SimpleIndirectCalls) {
  const FunctionSig* sig = sigs.i_i();
  builder.AddTable(kWasmFuncRef, 20, false, 20);

  ModuleTypeIndex sig0 = builder.AddSignature(sigs.i_v());
  ModuleTypeIndex sig1 = builder.AddSignature(sigs.i_i());
  ModuleTypeIndex sig2 = builder.AddSignature(sigs.i_ii());

  ExpectValidates(sig, {WASM_CALL_INDIRECT(sig0, WASM_ZERO)});
  ExpectValidates(sig, {WASM_CALL_INDIRECT(sig1, WASM_I32V_1(22), WASM_ZERO)});
  ExpectValidates(sig, {WASM_CALL_INDIRECT(sig2, WASM_I32V_1(32),
                                           WASM_I32V_2(72), WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, IndirectCallsOutOfBounds) {
  const FunctionSig* sig = sigs.i_i();
  builder.AddTable(kWasmFuncRef, 20, false, 20);

  ExpectFailure(sig, {WASM_CALL_INDIRECT(0, WASM_ZERO)});
  builder.AddSignature(sigs.i_v());
  ExpectValidates(sig, {WASM_CALL_INDIRECT(0, WASM_ZERO)});

  ExpectFailure(sig, {WASM_CALL_INDIRECT(1, WASM_I32V_1(22), WASM_ZERO)});
  builder.AddSignature(sigs.i_i());
  ExpectValidates(sig, {WASM_CALL_INDIRECT(1, WASM_I32V_1(27), WASM_ZERO)});

  ExpectFailure(sig, {WASM_CALL_INDIRECT(2, WASM_I32V_1(27), WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, IndirectCallsWithMismatchedSigs1) {
  const FunctionSig* sig = sigs.i_i();
  builder.AddTable(wasm::kWasmVoid);

  ModuleTypeIndex sig0 = builder.AddSignature(sigs.i_f());

  ExpectFailure(sig, {WASM_CALL_INDIRECT(sig0, WASM_I32V_1(17), WASM_ZERO)});
  ExpectFailure(sig, {WASM_CALL_INDIRECT(sig0, WASM_I64V_1(27), WASM_ZERO)});
  ExpectFailure(sig, {WASM_CALL_INDIRECT(sig0, WASM_F64(37.2), WASM_ZERO)});

  ExpectFailure(sig, {WASM_CALL_INDIRECT(sig0, WASM_I32V_1(17))});
  ExpectFailure(sig, {WASM_CALL_INDIRECT(sig0, WASM_I64V_1(27))});
  ExpectFailure(sig, {WASM_CALL_INDIRECT(sig0, WASM_F64(37.2))});

  uint8_t sig1 = builder.AddFunction(sigs.i_d());

  ExpectFailure(sig, {WASM_CALL_INDIRECT(sig1, WASM_I32V_1(16), WASM_ZERO)});
  ExpectFailure(sig, {WASM_CALL_INDIRECT(sig1, WASM_I64V_1(16), WASM_ZERO)});
  ExpectFailure(sig, {WASM_CALL_INDIRECT(sig1, WASM_F32(17.6), WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, IndirectCallsWithMismatchedSigs2) {
  ModuleTypeIndex table_type_index = builder.AddSignature(sigs.i_i());
  uint8_t table_index = builder.AddTable(ValueType::RefNull(table_type_index));

  ExpectValidates(sigs.i_v(),
                  {WASM_CALL_INDIRECT_TABLE(table_index, table_type_index,
                                            WASM_I32V_1(42), WASM_ZERO)});

  ModuleTypeIndex wrong_type_index = builder.AddSignature(sigs.i_ii());
  // Note: this would trap at runtime, but does validate.
  ExpectValidates(
      sigs.i_v(),
      {WASM_CALL_INDIRECT_TABLE(table_index, wrong_type_index, WASM_I32V_1(41),
                                WASM_I32V_1(42), WASM_ZERO)});

  uint8_t non_function_table_index = builder.AddTable(kWasmExternRef);
  ExpectFailure(
      sigs.i_v(),
      {WASM_CALL_INDIRECT_TABLE(non_function_table_index, table_type_index,
                                WASM_I32V_1(42), WASM_ZERO)},
      kAppendEnd,
      "call_indirect: immediate table #1 is not of a function type");
}

TEST_F(FunctionBodyDecoderTest, TablesWithFunctionSubtyping) {
  ModuleTypeIndex empty_struct = builder.AddStruct({});
  ModuleTypeIndex super_struct =
      builder.AddStruct({F(kWasmI32, true)}, empty_struct);
  ModuleTypeIndex sub_struct =
      builder.AddStruct({F(kWasmI32, true), F(kWasmF64, true)}, super_struct);

  ModuleTypeIndex table_supertype = builder.AddSignature(
      FunctionSig::Build(zone(), {ValueType::RefNull(empty_struct)},
                         {ValueType::RefNull(sub_struct)}));
  ModuleTypeIndex table_type = builder.AddSignature(
      FunctionSig::Build(zone(), {ValueType::RefNull(super_struct)},
                         {ValueType::RefNull(sub_struct)}),
      table_supertype);
  auto function_sig =
      FunctionSig::Build(zone(), {ValueType::RefNull(sub_struct)},
                         {ValueType::RefNull(super_struct)});
  ModuleTypeIndex function_type =
      builder.AddSignature(function_sig, table_type);

  uint8_t function = builder.AddFunction(function_type);

  uint8_t table = builder.AddTable(ValueType::RefNull(table_type));

  // We can call-indirect from a typed function table with an immediate type
  // that is a subtype of the table type.
  ExpectValidates(
      FunctionSig::Build(zone(), {ValueType::RefNull(sub_struct)}, {}),
      {WASM_CALL_INDIRECT_TABLE(table, function_type,
                                WASM_STRUCT_NEW_DEFAULT(super_struct),
                                WASM_ZERO)});

  // table.set's subtyping works as expected.
  ExpectValidates(sigs.v_i(), {WASM_TABLE_SET(0, WASM_LOCAL_GET(0),
                                              WASM_REF_FUNC(function))});
  // table.get's subtyping works as expected.
  ExpectValidates(
      FunctionSig::Build(zone(), {ValueType::RefNull(table_supertype)},
                         {kWasmI32}),
      {WASM_TABLE_GET(0, WASM_LOCAL_GET(0))});
}

TEST_F(FunctionBodyDecoderTest, IndirectCallsWithoutTableCrash) {
  const FunctionSig* sig = sigs.i_i();

  ModuleTypeIndex sig0 = builder.AddSignature(sigs.i_v());
  ModuleTypeIndex sig1 = builder.AddSignature(sigs.i_i());
  ModuleTypeIndex sig2 = builder.AddSignature(sigs.i_ii());

  ExpectFailure(sig, {WASM_CALL_INDIRECT(sig0, WASM_ZERO)});
  ExpectFailure(sig, {WASM_CALL_INDIRECT(sig1, WASM_I32V_1(22), WASM_ZERO)});
  ExpectFailure(sig, {WASM_CALL_INDIRECT(sig2, WASM_I32V_1(32), WASM_I32V_2(72),
                                         WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, IncompleteIndirectCall) {
  const FunctionSig* sig = sigs.i_i();
  builder.AddTable(wasm::kWasmVoid);

  static uint8_t code[] = {kExprCallIndirect};
  ExpectFailure(sig, base::ArrayVector(code), kOmitEnd);
}

TEST_F(FunctionBodyDecoderTest, IncompleteStore) {
  const FunctionSig* sig = sigs.i_i();
  builder.AddMemory();
  builder.AddTable(wasm::kWasmVoid);

  static uint8_t code[] = {kExprI32StoreMem};
  ExpectFailure(sig, base::ArrayVector(code), kOmitEnd);
}

TEST_F(FunctionBodyDecoderTest, IncompleteI8x16Shuffle) {
  const FunctionSig* sig = sigs.i_i();
  builder.AddMemory();
  builder.AddTable(wasm::kWasmVoid);

  static uint8_t code[] = {kSimdPrefix,
                           static_cast<uint8_t>(kExprI8x16Shuffle & 0xff)};
  ExpectFailure(sig, base::ArrayVector(code), kOmitEnd);
}

TEST_F(FunctionBodyDecoderTest, SimpleImportCalls) {
  const FunctionSig* sig = sigs.i_i();

  uint8_t f0 = builder.AddImport(sigs.i_v());
  uint8_t f1 = builder.AddImport(sigs.i_i());
  uint8_t f2 = builder.AddImport(sigs.i_ii());

  ExpectValidates(sig, {WASM_CALL_FUNCTION0(f0)});
  ExpectValidates(sig, {WASM_CALL_FUNCTION(f1, WASM_I32V_1(22))});
  ExpectValidates(sig,
                  {WASM_CALL_FUNCTION(f2, WASM_I32V_1(32), WASM_I32V_2(72))});
}

TEST_F(FunctionBodyDecoderTest, ImportCallsWithMismatchedSigs3) {
  const FunctionSig* sig = sigs.i_i();

  uint8_t f0 = builder.AddImport(sigs.i_f());

  ExpectFailure(sig, {WASM_CALL_FUNCTION0(f0)});
  ExpectFailure(sig, {WASM_CALL_FUNCTION(f0, WASM_I32V_1(17))});
  ExpectFailure(sig, {WASM_CALL_FUNCTION(f0, WASM_I64V_1(27))});
  ExpectFailure(sig, {WASM_CALL_FUNCTION(f0, WASM_F64(37.2))});

  uint8_t f1 = builder.AddImport(sigs.i_d());

  ExpectFailure(sig, {WASM_CALL_FUNCTION0(f1)});
  ExpectFailure(sig, {WASM_CALL_FUNCTION(f1, WASM_I32V_1(16))});
  ExpectFailure(sig, {WASM_CALL_FUNCTION(f1, WASM_I64V_1(16))});
  ExpectFailure(sig, {WASM_CALL_FUNCTION(f1, WASM_F32(17.6))});
}

TEST_F(FunctionBodyDecoderTest, Int32Globals) {
  const FunctionSig* sig = sigs.i_i();

  builder.AddGlobal(kWasmI32);

  ExpectValidates(sig, {WASM_GLOBAL_GET(0)});
  ExpectFailure(sig, {WASM_GLOBAL_SET(0, WASM_LOCAL_GET(0))});
  ExpectValidates(sig, {WASM_GLOBAL_SET(0, WASM_LOCAL_GET(0)), WASM_ZERO});
}

TEST_F(FunctionBodyDecoderTest, ImmutableGlobal) {
  const FunctionSig* sig = sigs.v_v();

  uint32_t g0 = builder.AddGlobal(kWasmI32, true);
  uint32_t g1 = builder.AddGlobal(kWasmI32, false);

  ExpectValidates(sig, {WASM_GLOBAL_SET(g0, WASM_ZERO)});
  ExpectFailure(sig, {WASM_GLOBAL_SET(g1, WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, Int32Globals_fail) {
  const FunctionSig* sig = sigs.i_i();

  builder.AddGlobal(kWasmI64);
  builder.AddGlobal(kWasmI64);
  builder.AddGlobal(kWasmF32);
  builder.AddGlobal(kWasmF64);

  ExpectFailure(sig, {WASM_GLOBAL_GET(0)});
  ExpectFailure(sig, {WASM_GLOBAL_GET(1)});
  ExpectFailure(sig, {WASM_GLOBAL_GET(2)});
  ExpectFailure(sig, {WASM_GLOBAL_GET(3)});

  ExpectFailure(sig, {WASM_GLOBAL_SET(0, WASM_LOCAL_GET(0)), WASM_ZERO});
  ExpectFailure(sig, {WASM_GLOBAL_SET(1, WASM_LOCAL_GET(0)), WASM_ZERO});
  ExpectFailure(sig, {WASM_GLOBAL_SET(2, WASM_LOCAL_GET(0)), WASM_ZERO});
  ExpectFailure(sig, {WASM_GLOBAL_SET(3, WASM_LOCAL_GET(0)), WASM_ZERO});
}

TEST_F(FunctionBodyDecoderTest, Int64Globals) {
  const FunctionSig* sig = sigs.l_l();

  builder.AddGlobal(kWasmI64);
  builder.AddGlobal(kWasmI64);

  ExpectValidates(sig, {WASM_GLOBAL_GET(0)});
  ExpectValidates(sig, {WASM_GLOBAL_GET(1)});

  ExpectValidates(sig,
                  {WASM_GLOBAL_SET(0, WASM_LOCAL_GET(0)), WASM_LOCAL_GET(0)});
  ExpectValidates(sig,
                  {WASM_GLOBAL_SET(1, WASM_LOCAL_GET(0)), WASM_LOCAL_GET(0)});
}

TEST_F(FunctionBodyDecoderTest, Float32Globals) {
  const FunctionSig* sig = sigs.f_ff();

  builder.AddGlobal(kWasmF32);

  ExpectValidates(sig, {WASM_GLOBAL_GET(0)});
  ExpectValidates(sig,
                  {WASM_GLOBAL_SET(0, WASM_LOCAL_GET(0)), WASM_LOCAL_GET(0)});
}

TEST_F(FunctionBodyDecoderTest, Float64Globals) {
  const FunctionSig* sig = sigs.d_dd();

  builder.AddGlobal(kWasmF64);

  ExpectValidates(sig, {WASM_GLOBAL_GET(0)});
  ExpectValidates(sig,
                  {WASM_GLOBAL_SET(0, WASM_LOCAL_GET(0)), WASM_LOCAL_GET(0)});
}

TEST_F(FunctionBodyDecoderTest, NullRefGlobals) {
  ValueType nullRefs[] = {kWasmNullRef, kWasmNullRef, kWasmNullRef};
  FunctionSig sig(1, 2, nullRefs);
  builder.AddGlobal(kWasmNullRef);
  ExpectValidates(&sig, {WASM_GLOBAL_GET(0)});
  ExpectValidates(&sig,
                  {WASM_GLOBAL_SET(0, WASM_LOCAL_GET(0)), WASM_LOCAL_GET(0)});
  ExpectValidates(
      &sig, {WASM_GLOBAL_SET(0, WASM_REF_NULL(kNoneCode)), WASM_LOCAL_GET(0)});
}

TEST_F(FunctionBodyDecoderTest, NullExternRefGlobals) {
  ValueType nullExternRefs[] = {kWasmNullExternRef, kWasmNullExternRef,
                                kWasmNullExternRef};
  FunctionSig sig(1, 2, nullExternRefs);
  builder.AddGlobal(kWasmNullExternRef);
  ExpectValidates(&sig, {WASM_GLOBAL_GET(0)});
  ExpectValidates(&sig,
                  {WASM_GLOBAL_SET(0, WASM_LOCAL_GET(0)), WASM_LOCAL_GET(0)});
  ExpectValidates(&sig, {WASM_GLOBAL_SET(0, WASM_REF_NULL(kNoExternCode)),
                         WASM_LOCAL_GET(0)});
}

TEST_F(FunctionBodyDecoderTest, NullFuncRefGlobals) {
  ValueType nullFuncRefs[] = {kWasmNullFuncRef, kWasmNullFuncRef,
                              kWasmNullFuncRef};
  FunctionSig sig(1, 2, nullFuncRefs);
  builder.AddGlobal(kWasmNullFuncRef);
  ExpectValidates(&sig, {WASM_GLOBAL_GET(0)});
  ExpectValidates(&sig,
                  {WASM_GLOBAL_SET(0, WASM_LOCAL_GET(0)), WASM_LOCAL_GET(0)});
  ExpectValidates(&sig, {WASM_GLOBAL_SET(0, WASM_REF_NULL(kNoFuncCode)),
                         WASM_LOCAL_GET(0)});
}

TEST_F(FunctionBodyDecoderTest, NullExnRefGlobals) {
  WASM_FEATURE_SCOPE(exnref);
  ValueType nullFuncRefs[] = {kWasmNullExnRef, kWasmNullExnRef,
                              kWasmNullExnRef};
  FunctionSig sig(1, 2, nullFuncRefs);
  builder.AddGlobal(kWasmNullExnRef);
  ExpectValidates(&sig, {WASM_GLOBAL_GET(0)});
  ExpectValidates(&sig,
                  {WASM_GLOBAL_SET(0, WASM_LOCAL_GET(0)), WASM_LOCAL_GET(0)});
  ExpectValidates(
      &sig, {WASM_GLOBAL_SET(0, WASM_REF_NULL(kNoExnCode)), WASM_LOCAL_GET(0)});
}

TEST_F(FunctionBodyDecoderTest, AllGetGlobalCombinations) {
  for (size_t i = 0; i < arraysize(kValueTypes); i++) {
    ValueType local_type = kValueTypes[i];
    for (size_t j = 0; j < arraysize(kValueTypes); j++) {
      ValueType global_type = kValueTypes[j];
      FunctionSig sig(1, 0, &local_type);
      TestModuleBuilder builder;
      module = builder.module();
      builder.AddGlobal(global_type);
      Validate(IsSubtypeOf(global_type, local_type, module), &sig,
               {WASM_GLOBAL_GET(0)});
    }
  }
}

TEST_F(FunctionBodyDecoderTest, AllSetGlobalCombinations) {
  for (size_t i = 0; i < arraysize(kValueTypes); i++) {
    ValueType local_type = kValueTypes[i];
    for (size_t j = 0; j < arraysize(kValueTypes); j++) {
      ValueType global_type = kValueTypes[j];
      FunctionSig sig(0, 1, &local_type);
      TestModuleBuilder builder;
      module = builder.module();
      builder.AddGlobal(global_type);
      Validate(IsSubtypeOf(local_type, global_type, module), &sig,
               {WASM_GLOBAL_SET(0, WASM_LOCAL_GET(0))});
    }
  }
}

TEST_F(FunctionBodyDecoderTest, TableSet) {
  ModuleTypeIndex tab_type = builder.AddSignature(sigs.i_i());
  uint8_t tab_ref1 = builder.AddTable(kWasmExternRef, 10, true, 20);
  uint8_t tab_func1 = builder.AddTable(kWasmFuncRef, 20, true, 30);
  uint8_t tab_func2 = builder.AddTable(kWasmFuncRef, 10, false, 20);
  uint8_t tab_ref2 = builder.AddTable(kWasmExternRef, 10, false, 20);
  uint8_t tab_typed_func =
      builder.AddTable(ValueType::RefNull(tab_type), 10, false, 20);

  ValueType sig_types[]{kWasmExternRef, kWasmFuncRef, kWasmI32,
                        ValueType::Ref(tab_type)};
  FunctionSig sig(0, 4, sig_types);
  uint8_t local_ref = 0;
  uint8_t local_func = 1;
  uint8_t local_int = 2;
  uint8_t local_typed_func = 3;

  ExpectValidates(&sig, {WASM_TABLE_SET(tab_ref1, WASM_I32V(6),
                                        WASM_LOCAL_GET(local_ref))});
  ExpectValidates(&sig, {WASM_TABLE_SET(tab_func1, WASM_I32V(5),
                                        WASM_LOCAL_GET(local_func))});
  ExpectValidates(&sig, {WASM_TABLE_SET(tab_func2, WASM_I32V(7),
                                        WASM_LOCAL_GET(local_func))});
  ExpectValidates(&sig, {WASM_TABLE_SET(tab_ref2, WASM_I32V(8),
                                        WASM_LOCAL_GET(local_ref))});
  ExpectValidates(&sig, {WASM_TABLE_SET(tab_typed_func, WASM_I32V(8),
                                        WASM_LOCAL_GET(local_typed_func))});
  ExpectValidates(&sig, {WASM_TABLE_SET(tab_func1, WASM_I32V(8),
                                        WASM_LOCAL_GET(local_typed_func))});

  // Only values of the correct type can be set to a table.
  ExpectFailure(&sig, {WASM_TABLE_SET(tab_ref1, WASM_I32V(4),
                                      WASM_LOCAL_GET(local_func))});
  ExpectFailure(&sig, {WASM_TABLE_SET(tab_func1, WASM_I32V(9),
                                      WASM_LOCAL_GET(local_ref))});
  ExpectFailure(&sig, {WASM_TABLE_SET(tab_func2, WASM_I32V(3),
                                      WASM_LOCAL_GET(local_ref))});
  ExpectFailure(&sig, {WASM_TABLE_SET(tab_ref2, WASM_I32V(2),
                                      WASM_LOCAL_GET(local_func))});
  ExpectFailure(&sig, {WASM_TABLE_SET(tab_ref1, WASM_I32V(9),
                                      WASM_LOCAL_GET(local_int))});
  ExpectFailure(&sig, {WASM_TABLE_SET(tab_func1, WASM_I32V(3),
                                      WASM_LOCAL_GET(local_int))});
  ExpectFailure(&sig, {WASM_TABLE_SET(tab_typed_func, WASM_I32V(3),
                                      WASM_LOCAL_GET(local_func))});

  // Out-of-bounds table index should fail.
  uint8_t oob_tab = 37;
  ExpectFailure(
      &sig, {WASM_TABLE_SET(oob_tab, WASM_I32V(9), WASM_LOCAL_GET(local_ref))});
  ExpectFailure(&sig, {WASM_TABLE_SET(oob_tab, WASM_I32V(3),
                                      WASM_LOCAL_GET(local_func))});
}

TEST_F(FunctionBodyDecoderTest, TableGet) {
  ModuleTypeIndex tab_type = builder.AddSignature(sigs.i_i());
  uint8_t tab_ref1 = builder.AddTable(kWasmExternRef, 10, true, 20);
  uint8_t tab_func1 = builder.AddTable(kWasmFuncRef, 20, true, 30);
  uint8_t tab_func2 = builder.AddTable(kWasmFuncRef, 10, false, 20);
  uint8_t tab_ref2 = builder.AddTable(kWasmExternRef, 10, false, 20);
  uint8_t tab_typed_func =
      builder.AddTable(ValueType::RefNull(tab_type), 10, false, 20);

  ValueType sig_types[]{kWasmExternRef, kWasmFuncRef, kWasmI32,
                        ValueType::RefNull(tab_type)};
  FunctionSig sig(0, 4, sig_types);
  uint8_t local_ref = 0;
  uint8_t local_func = 1;
  uint8_t local_int = 2;
  uint8_t local_typed_func = 3;

  ExpectValidates(
      &sig,
      {WASM_LOCAL_SET(local_ref, WASM_TABLE_GET(tab_ref1, WASM_I32V(6)))});
  ExpectValidates(
      &sig,
      {WASM_LOCAL_SET(local_ref, WASM_TABLE_GET(tab_ref2, WASM_I32V(8)))});
  ExpectValidates(
      &sig,
      {WASM_LOCAL_SET(local_func, WASM_TABLE_GET(tab_func1, WASM_I32V(5)))});
  ExpectValidates(
      &sig,
      {WASM_LOCAL_SET(local_func, WASM_TABLE_GET(tab_func2, WASM_I32V(7)))});
  ExpectValidates(
      &sig, {WASM_LOCAL_SET(local_ref, WASM_SEQ(WASM_I32V(6), kExprTableGet,
                                                U32V_2(tab_ref1)))});
  ExpectValidates(
      &sig, {WASM_LOCAL_SET(local_func,
                            WASM_TABLE_GET(tab_typed_func, WASM_I32V(7)))});
  ExpectValidates(
      &sig, {WASM_LOCAL_SET(local_typed_func,
                            WASM_TABLE_GET(tab_typed_func, WASM_I32V(7)))});

  // We cannot store references as any other type.
  ExpectFailure(&sig, {WASM_LOCAL_SET(local_func,
                                      WASM_TABLE_GET(tab_ref1, WASM_I32V(4)))});
  ExpectFailure(&sig, {WASM_LOCAL_SET(
                          local_ref, WASM_TABLE_GET(tab_func1, WASM_I32V(9)))});
  ExpectFailure(&sig, {WASM_LOCAL_SET(
                          local_ref, WASM_TABLE_GET(tab_func2, WASM_I32V(3)))});
  ExpectFailure(&sig, {WASM_LOCAL_SET(local_func,
                                      WASM_TABLE_GET(tab_ref2, WASM_I32V(2)))});

  ExpectFailure(&sig, {WASM_LOCAL_SET(local_int,
                                      WASM_TABLE_GET(tab_ref1, WASM_I32V(9)))});
  ExpectFailure(&sig, {WASM_LOCAL_SET(
                          local_int, WASM_TABLE_GET(tab_func1, WASM_I32V(3)))});
  ExpectFailure(&sig,
                {WASM_LOCAL_SET(local_typed_func,
                                WASM_TABLE_GET(tab_func1, WASM_I32V(3)))});

  // Out-of-bounds table index should fail.
  uint8_t oob_tab = 37;
  ExpectFailure(
      &sig, {WASM_LOCAL_SET(local_ref, WASM_TABLE_GET(oob_tab, WASM_I32V(9)))});
  ExpectFailure(&sig, {WASM_LOCAL_SET(local_func,
                                      WASM_TABLE_GET(oob_tab, WASM_I32V(3)))});
}

TEST_F(FunctionBodyDecoderTest, MultiTableCallIndirect) {
  uint8_t tab_ref = builder.AddTable(kWasmExternRef, 10, true, 20);
  uint8_t tab_func = builder.AddTable(kWasmFuncRef, 20, true, 30);

  ValueType sig_types[]{kWasmExternRef, kWasmFuncRef, kWasmI32};
  FunctionSig sig(0, 3, sig_types);
  uint8_t sig_index = builder.AddSignature(sigs.i_v()).index;

  // We can store funcref values as externref, but not the other way around.
  ExpectValidates(sigs.i_v(),
                  {kExprI32Const, 0, kExprCallIndirect, sig_index, tab_func});

  ExpectFailure(sigs.i_v(),
                {kExprI32Const, 0, kExprCallIndirect, sig_index, tab_ref});
}

TEST_F(FunctionBodyDecoderTest, WasmMemoryGrow) {
  builder.AddMemory();

  uint8_t code[] = {WASM_LOCAL_GET(0), kExprMemoryGrow, 0};
  ExpectValidates(sigs.i_i(), code);
  ExpectFailure(sigs.i_d(), code);
}

TEST_F(FunctionBodyDecoderTest, BreakEnd) {
  ExpectValidates(
      sigs.i_i(),
      {WASM_BLOCK_I(WASM_I32_ADD(WASM_BRV(0, WASM_ZERO), WASM_ZERO))});
  ExpectValidates(
      sigs.i_i(),
      {WASM_BLOCK_I(WASM_I32_ADD(WASM_ZERO, WASM_BRV(0, WASM_ZERO)))});
}

TEST_F(FunctionBodyDecoderTest, BreakIfBinop) {
  ExpectValidates(sigs.i_i(),
                  {WASM_BLOCK_I(WASM_I32_ADD(
                      WASM_BRV_IF(0, WASM_ZERO, WASM_ZERO), WASM_ZERO))});
  ExpectValidates(sigs.i_i(),
                  {WASM_BLOCK_I(WASM_I32_ADD(
                      WASM_ZERO, WASM_BRV_IF(0, WASM_ZERO, WASM_ZERO)))});
  ExpectValidates(
      sigs.f_ff(),
      {WASM_BLOCK_F(WASM_F32_ABS(WASM_BRV_IF(0, WASM_F32(0.0f), WASM_ZERO)))});
}

TEST_F(FunctionBodyDecoderTest, BreakIfBinop_fail) {
  ExpectFailure(
      sigs.f_ff(),
      {WASM_BLOCK_F(WASM_F32_ABS(WASM_BRV_IF(0, WASM_ZERO, WASM_ZERO)))});
  ExpectFailure(
      sigs.i_i(),
      {WASM_BLOCK_I(WASM_F32_ABS(WASM_BRV_IF(0, WASM_F32(0.0f), WASM_ZERO)))});
}

TEST_F(FunctionBodyDecoderTest, BreakIfUnrNarrow) {
  ExpectFailure(
      sigs.f_ff(),
      {WASM_BLOCK_I(WASM_BRV_IF(0, WASM_UNREACHABLE, WASM_UNREACHABLE),
                    WASM_RETURN0),
       WASM_F32(0.0)});
}

TEST_F(FunctionBodyDecoderTest, BreakNesting1) {
  for (int i = 0; i < 5; i++) {
    // (block[2] (loop[2] (if (get p) break[N]) (set p 1)) p)
    uint8_t code[] = {WASM_BLOCK_I(
        WASM_LOOP(WASM_IF(WASM_LOCAL_GET(0), WASM_BRV(i + 1, WASM_ZERO)),
                  WASM_LOCAL_SET(0, WASM_I32V_1(1))),
        WASM_ZERO)};
    Validate(i < 3, sigs.i_i(), code);
  }
}

TEST_F(FunctionBodyDecoderTest, BreakNesting2) {
  for (int i = 0; i < 7; i++) {
    uint8_t code[] = {B1(WASM_LOOP(WASM_IF(WASM_ZERO, WASM_BR(i)), WASM_NOP))};
    Validate(i <= 3, sigs.v_v(), code);
  }
}

TEST_F(FunctionBodyDecoderTest, BreakNesting3) {
  for (int i = 0; i < 7; i++) {
    // (block[1] (loop[1] (block[1] (if 0 break[N])
    uint8_t code[] = {
        WASM_BLOCK(WASM_LOOP(B1(WASM_IF(WASM_ZERO, WASM_BR(i + 1)))))};
    Validate(i < 4, sigs.v_v(), code);
  }
}

TEST_F(FunctionBodyDecoderTest, BreaksWithMultipleTypes) {
  ExpectFailure(sigs.i_i(),
                {B2(WASM_BRV_IF_ZERO(0, WASM_I32V_1(7)), WASM_F32(7.7))});

  ExpectFailure(sigs.i_i(), {B2(WASM_BRV_IF_ZERO(0, WASM_I32V_1(7)),
                                WASM_BRV_IF_ZERO(0, WASM_F32(7.7)))});
  ExpectFailure(sigs.i_i(), {B3(WASM_BRV_IF_ZERO(0, WASM_I32V_1(8)),
                                WASM_BRV_IF_ZERO(0, WASM_I32V_1(0)),
                                WASM_BRV_IF_ZERO(0, WASM_F32(7.7)))});
  ExpectFailure(sigs.i_i(), {B3(WASM_BRV_IF_ZERO(0, WASM_I32V_1(9)),
                                WASM_BRV_IF_ZERO(0, WASM_F32(7.7)),
                                WASM_BRV_IF_ZERO(0, WASM_I32V_1(11)))});
}

TEST_F(FunctionBodyDecoderTest, BreakNesting_6_levels) {
  for (int mask = 0; mask < 64; mask++) {
    for (int i = 0; i < 14; i++) {
      uint8_t code[] = {WASM_BLOCK(WASM_BLOCK(
          WASM_BLOCK(WASM_BLOCK(WASM_BLOCK(WASM_BLOCK(WASM_BR(i)))))))};

      int depth = 6;
      int m = mask;
      for (size_t pos = 0; pos < sizeof(code) - 1; pos++) {
        if (code[pos] != kExprBlock) continue;
        if (m & 1) {
          code[pos] = kExprLoop;
          code[pos + 1] = kVoidCode;
        }
        m >>= 1;
      }

      Validate(i <= depth, sigs.v_v(), code);
    }
  }
}

TEST_F(FunctionBodyDecoderTest, Break_TypeCheck) {
  for (const FunctionSig* sig :
       {sigs.i_i(), sigs.l_l(), sigs.f_ff(), sigs.d_dd()}) {
    // unify X and X => OK
    uint8_t code[] = {WASM_BLOCK_T(
        sig->GetReturn(), WASM_IF(WASM_ZERO, WASM_BRV(0, WASM_LOCAL_GET(0))),
        WASM_LOCAL_GET(0))};
    ExpectValidates(sig, code);
  }

  // unify i32 and f32 => fail
  ExpectFailure(sigs.i_i(),
                {WASM_BLOCK_I(WASM_IF(WASM_ZERO, WASM_BRV(0, WASM_ZERO)),
                              WASM_F32(1.2))});

  // unify f64 and f64 => OK
  ExpectValidates(
      sigs.d_dd(),
      {WASM_BLOCK_D(WASM_IF(WASM_ZERO, WASM_BRV(0, WASM_LOCAL_GET(0))),
                    WASM_F64(1.2))});
}

TEST_F(FunctionBodyDecoderTest, Break_TypeCheckAll1) {
  for (size_t i = 0; i < arraysize(kValueTypes); i++) {
    for (size_t j = 0; j < arraysize(kValueTypes); j++) {
      ValueType storage[] = {kValueTypes[i], kValueTypes[i], kValueTypes[j]};
      FunctionSig sig(1, 2, storage);
      uint8_t code[] = {WASM_BLOCK_T(
          sig.GetReturn(), WASM_IF(WASM_ZERO, WASM_BRV(0, WASM_LOCAL_GET(0))),
          WASM_LOCAL_GET(1))};

      Validate(IsSubtypeOf(kValueTypes[j], kValueTypes[i], module), &sig, code);
    }
  }
}

TEST_F(FunctionBodyDecoderTest, Break_TypeCheckAll2) {
  for (size_t i = 0; i < arraysize(kValueTypes); i++) {
    for (size_t j = 0; j < arraysize(kValueTypes); j++) {
      ValueType storage[] = {kValueTypes[i], kValueTypes[i], kValueTypes[j]};
      FunctionSig sig(1, 2, storage);
      uint8_t code[] = {WASM_IF_ELSE_T(sig.GetReturn(0), WASM_ZERO,
                                       WASM_BRV_IF_ZERO(0, WASM_LOCAL_GET(0)),
                                       WASM_LOCAL_GET(1))};

      Validate(IsSubtypeOf(kValueTypes[j], kValueTypes[i], module), &sig, code);
    }
  }
}

TEST_F(FunctionBodyDecoderTest, Break_TypeCheckAll3) {
  for (size_t i = 0; i < arraysize(kValueTypes); i++) {
    for (size_t j = 0; j < arraysize(kValueTypes); j++) {
      ValueType storage[] = {kValueTypes[i], kValueTypes[i], kValueTypes[j]};
      FunctionSig sig(1, 2, storage);
      uint8_t code[] = {WASM_IF_ELSE_T(sig.GetReturn(), WASM_ZERO,
                                       WASM_LOCAL_GET(1),
                                       WASM_BRV_IF_ZERO(0, WASM_LOCAL_GET(0)))};

      Validate(IsSubtypeOf(kValueTypes[j], kValueTypes[i], module), &sig, code);
    }
  }
}

TEST_F(FunctionBodyDecoderTest, Break_Unify) {
  for (int which = 0; which < 2; which++) {
    for (size_t i = 0; i < arraysize(kValueTypes); i++) {
      ValueType type = kValueTypes[i];
      ValueType storage[] = {kWasmI32, kWasmI32, type};
      FunctionSig sig(1, 2, storage);

      uint8_t code1[] = {WASM_BLOCK_T(
          type, WASM_IF(WASM_ZERO, WASM_BRV(1, WASM_LOCAL_GET(which))),
          WASM_LOCAL_GET(which ^ 1))};

      Validate(type == kWasmI32, &sig, code1);
    }
  }
}

TEST_F(FunctionBodyDecoderTest, BreakIf_cond_type) {
  for (size_t i = 0; i < arraysize(kValueTypes); i++) {
    for (size_t j = 0; j < arraysize(kValueTypes); j++) {
      ValueType types[] = {kValueTypes[i], kValueTypes[i], kValueTypes[j]};
      FunctionSig sig(1, 2, types);
      uint8_t code[] = {WASM_BLOCK_T(
          types[0], WASM_BRV_IF(0, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)))};

      Validate(types[2] == kWasmI32, &sig, code);
    }
  }
}

TEST_F(FunctionBodyDecoderTest, BreakIf_val_type) {
  for (size_t i = 0; i < arraysize(kValueTypes); i++) {
    for (size_t j = 0; j < arraysize(kValueTypes); j++) {
      ValueType types[] = {kValueTypes[i], kValueTypes[i], kValueTypes[j],
                           kWasmI32};
      FunctionSig sig(1, 3, types);
      uint8_t code[] = {WASM_BLOCK_T(
          types[1], WASM_BRV_IF(0, WASM_LOCAL_GET(1), WASM_LOCAL_GET(2)),
          WASM_DROP, WASM_LOCAL_GET(0))};

      Validate(IsSubtypeOf(kValueTypes[j], kValueTypes[i], module), &sig, code);
    }
  }
}

TEST_F(FunctionBodyDecoderTest, BreakIf_Unify) {
  for (int which = 0; which < 2; which++) {
    for (size_t i = 0; i < arraysize(kValueTypes); i++) {
      ValueType type = kValueTypes[i];
      ValueType storage[] = {kWasmI32, kWasmI32, type};
      FunctionSig sig(1, 2, storage);
      uint8_t code[] = {WASM_BLOCK_I(WASM_BRV_IF_ZERO(0, WASM_LOCAL_GET(which)),
                                     WASM_DROP, WASM_LOCAL_GET(which ^ 1))};

      Validate(type == kWasmI32, &sig, code);
    }
  }
}

TEST_F(FunctionBodyDecoderTest, BrTable0) {
  ExpectFailure(sigs.v_v(), {kExprBrTable, 0, BR_TARGET(0)});
}

TEST_F(FunctionBodyDecoderTest, BrTable0b) {
  static uint8_t code[] = {kExprI32Const, 11, kExprBrTable, 0, BR_TARGET(0)};
  ExpectValidates(sigs.v_v(), code);
  ExpectFailure(sigs.i_i(), code);
}

TEST_F(FunctionBodyDecoderTest, BrTable0c) {
  static uint8_t code[] = {kExprI32Const, 11, kExprBrTable, 0, BR_TARGET(1)};
  ExpectFailure(sigs.v_v(), code);
  ExpectFailure(sigs.i_i(), code);
}

TEST_F(FunctionBodyDecoderTest, BrTable1a) {
  ExpectValidates(sigs.v_v(),
                  {B1(WASM_BR_TABLE(WASM_I32V_2(67), 0, BR_TARGET(0)))});
}

TEST_F(FunctionBodyDecoderTest, BrTable1b) {
  static uint8_t code[] = {B1(WASM_BR_TABLE(WASM_ZERO, 0, BR_TARGET(0)))};
  ExpectValidates(sigs.v_v(), code);
  ExpectFailure(sigs.i_i(), code);
  ExpectFailure(sigs.f_ff(), code);
  ExpectFailure(sigs.d_dd(), code);
}

TEST_F(FunctionBodyDecoderTest, BrTable2a) {
  ExpectValidates(
      sigs.v_v(),
      {B1(WASM_BR_TABLE(WASM_I32V_2(67), 1, BR_TARGET(0), BR_TARGET(0)))});
}

TEST_F(FunctionBodyDecoderTest, BrTable2b) {
  ExpectValidates(sigs.v_v(),
                  {WASM_BLOCK(WASM_BLOCK(WASM_BR_TABLE(
                      WASM_I32V_2(67), 1, BR_TARGET(0), BR_TARGET(1))))});
}

TEST_F(FunctionBodyDecoderTest, BrTableSubtyping) {
  ModuleTypeIndex supertype1 = builder.AddStruct({F(kWasmI8, true)});
  ModuleTypeIndex supertype2 =
      builder.AddStruct({F(kWasmI8, true), F(kWasmI16, false)}, supertype1);
  ModuleTypeIndex subtype = builder.AddStruct(
      {F(kWasmI8, true), F(kWasmI16, false), F(kWasmI32, true)}, supertype2);
  ExpectValidates(
      sigs.v_v(),
      {WASM_BLOCK_R(wasm::ValueType::Ref(supertype1),
                    WASM_BLOCK_R(wasm::ValueType::Ref(supertype2),
                                 WASM_STRUCT_NEW(subtype, WASM_I32V(10),
                                                 WASM_I32V(20), WASM_I32V(30)),
                                 WASM_BR_TABLE(WASM_I32V(5), 1, BR_TARGET(0),
                                               BR_TARGET(1))),
                    WASM_UNREACHABLE),
       WASM_DROP});
}

TEST_F(FunctionBodyDecoderTest, BrTable_off_end) {
  static uint8_t code[] = {
      B1(WASM_BR_TABLE(WASM_LOCAL_GET(0), 0, BR_TARGET(0)))};
  for (size_t len = 1; len < sizeof(code); len++) {
    ExpectFailure(sigs.i_i(), base::VectorOf(code, len), kAppendEnd);
    ExpectFailure(sigs.i_i(), base::VectorOf(code, len), kOmitEnd);
  }
}

TEST_F(FunctionBodyDecoderTest, BrTable_invalid_br1) {
  for (int depth = 0; depth < 4; depth++) {
    uint8_t code[] = {
        B1(WASM_BR_TABLE(WASM_LOCAL_GET(0), 0, BR_TARGET(depth)))};
    Validate(depth <= 1, sigs.v_i(), code);
  }
}

TEST_F(FunctionBodyDecoderTest, BrTable_invalid_br2) {
  for (int depth = 0; depth < 7; depth++) {
    uint8_t code[] = {
        WASM_LOOP(WASM_BR_TABLE(WASM_LOCAL_GET(0), 0, BR_TARGET(depth)))};
    Validate(depth < 2, sigs.v_i(), code);
  }
}

TEST_F(FunctionBodyDecoderTest, BrTable_arity_mismatch1) {
  ExpectFailure(
      sigs.v_v(),
      {WASM_BLOCK(WASM_BLOCK_I(
          WASM_ONE, WASM_BR_TABLE(WASM_ONE, 1, BR_TARGET(0), BR_TARGET(1))))});
}

TEST_F(FunctionBodyDecoderTest, BrTable_arity_mismatch2) {
  ExpectFailure(
      sigs.v_v(),
      {WASM_BLOCK_I(WASM_BLOCK(
          WASM_ONE, WASM_BR_TABLE(WASM_ONE, 1, BR_TARGET(0), BR_TARGET(1))))});
}

TEST_F(FunctionBodyDecoderTest, BrTable_arity_mismatch_loop1) {
  ExpectFailure(
      sigs.v_v(),
      {WASM_LOOP(WASM_BLOCK_I(
          WASM_ONE, WASM_BR_TABLE(WASM_ONE, 1, BR_TARGET(0), BR_TARGET(1))))});
}

TEST_F(FunctionBodyDecoderTest, BrTable_arity_mismatch_loop2) {
  ExpectFailure(
      sigs.v_v(),
      {WASM_BLOCK_I(WASM_LOOP(
          WASM_ONE, WASM_BR_TABLE(WASM_ONE, 1, BR_TARGET(0), BR_TARGET(1))))});
}

TEST_F(FunctionBodyDecoderTest, BrTable_loop_block) {
  ExpectValidates(
      sigs.v_v(),
      {WASM_LOOP(WASM_BLOCK(
          WASM_ONE, WASM_BR_TABLE(WASM_ONE, 1, BR_TARGET(0), BR_TARGET(1))))});
}

TEST_F(FunctionBodyDecoderTest, BrTable_block_loop) {
  ExpectValidates(
      sigs.v_v(),
      {WASM_LOOP(WASM_BLOCK(
          WASM_ONE, WASM_BR_TABLE(WASM_ONE, 1, BR_TARGET(0), BR_TARGET(1))))});
}

TEST_F(FunctionBodyDecoderTest, BrTable_type_mismatch1) {
  ExpectFailure(
      sigs.v_v(),
      {WASM_BLOCK_I(WASM_BLOCK_F(
          WASM_ONE, WASM_BR_TABLE(WASM_ONE, 1, BR_TARGET(0), BR_TARGET(1))))});
}

TEST_F(FunctionBodyDecoderTest, BrTable_type_mismatch2) {
  ExpectFailure(
      sigs.v_v(),
      {WASM_BLOCK_F(WASM_BLOCK_I(
          WASM_ONE, WASM_BR_TABLE(WASM_ONE, 1, BR_TARGET(0), BR_TARGET(1))))});
}

TEST_F(FunctionBodyDecoderTest, BrTable_type_mismatch_unreachable) {
  ExpectFailure(sigs.v_v(),
                {WASM_BLOCK_F(WASM_BLOCK_I(
                    WASM_UNREACHABLE,
                    WASM_BR_TABLE(WASM_ONE, 1, BR_TARGET(0), BR_TARGET(1))))});
}

TEST_F(FunctionBodyDecoderTest, BrUnreachable1) {
  ExpectValidates(sigs.v_i(),
                  {WASM_LOCAL_GET(0), kExprBrTable, 0, BR_TARGET(0)});
}

TEST_F(FunctionBodyDecoderTest, BrUnreachable2) {
  ExpectValidates(sigs.v_i(),
                  {WASM_LOCAL_GET(0), kExprBrTable, 0, BR_TARGET(0), WASM_NOP});
  ExpectFailure(sigs.v_i(),
                {WASM_LOCAL_GET(0), kExprBrTable, 0, BR_TARGET(0), WASM_ZERO});
}

TEST_F(FunctionBodyDecoderTest, Brv1) {
  ExpectValidates(sigs.i_i(), {WASM_BLOCK_I(WASM_BRV(0, WASM_ZERO))});
  ExpectValidates(sigs.i_i(),
                  {WASM_BLOCK_I(WASM_LOOP_I(WASM_BRV(2, WASM_ZERO)))});
}

TEST_F(FunctionBodyDecoderTest, Brv1_type) {
  ExpectValidates(sigs.i_ii(), {WASM_BLOCK_I(WASM_BRV(0, WASM_LOCAL_GET(0)))});
  ExpectValidates(sigs.l_ll(), {WASM_BLOCK_L(WASM_BRV(0, WASM_LOCAL_GET(0)))});
  ExpectValidates(sigs.f_ff(), {WASM_BLOCK_F(WASM_BRV(0, WASM_LOCAL_GET(0)))});
  ExpectValidates(sigs.d_dd(), {WASM_BLOCK_D(WASM_BRV(0, WASM_LOCAL_GET(0)))});
}

TEST_F(FunctionBodyDecoderTest, Brv1_type_n) {
  ExpectFailure(sigs.i_f(), {WASM_BLOCK_I(WASM_BRV(0, WASM_LOCAL_GET(0)))});
  ExpectFailure(sigs.i_d(), {WASM_BLOCK_I(WASM_BRV(0, WASM_LOCAL_GET(0)))});
}

TEST_F(FunctionBodyDecoderTest, BrvIf1) {
  ExpectValidates(sigs.i_v(), {WASM_BLOCK_I(WASM_BRV_IF_ZERO(0, WASM_ZERO))});
}

TEST_F(FunctionBodyDecoderTest, BrvIf1_type) {
  ExpectValidates(sigs.i_i(),
                  {WASM_BLOCK_I(WASM_BRV_IF_ZERO(0, WASM_LOCAL_GET(0)))});
  ExpectValidates(sigs.l_l(),
                  {WASM_BLOCK_L(WASM_BRV_IF_ZERO(0, WASM_LOCAL_GET(0)))});
  ExpectValidates(sigs.f_ff(),
                  {WASM_BLOCK_F(WASM_BRV_IF_ZERO(0, WASM_LOCAL_GET(0)))});
  ExpectValidates(sigs.d_dd(),
                  {WASM_BLOCK_D(WASM_BRV_IF_ZERO(0, WASM_LOCAL_GET(0)))});
}

TEST_F(FunctionBodyDecoderTest, BrvIf1_type_n) {
  ExpectFailure(sigs.i_f(),
                {WASM_BLOCK_I(WASM_BRV_IF_ZERO(0, WASM_LOCAL_GET(0)))});
  ExpectFailure(sigs.i_d(),
                {WASM_BLOCK_I(WASM_BRV_IF_ZERO(0, WASM_LOCAL_GET(0)))});
}

TEST_F(FunctionBodyDecoderTest, Select) {
  ExpectValidates(sigs.i_i(), {WASM_SELECT(WASM_LOCAL_GET(0), WASM_LOCAL_GET(0),
                                           WASM_ZERO)});
  ExpectValidates(sigs.f_ff(),
                  {WASM_SELECT(WASM_F32(0.0), WASM_F32(0.0), WASM_ZERO)});
  ExpectValidates(sigs.d_dd(),
                  {WASM_SELECT(WASM_F64(0.0), WASM_F64(0.0), WASM_ZERO)});
  ExpectValidates(sigs.l_l(),
                  {WASM_SELECT(WASM_I64V_1(0), WASM_I64V_1(0), WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, Select_needs_value_type) {
  ExpectFailure(sigs.a_a(),
                {WASM_SELECT(WASM_LOCAL_GET(0), WASM_LOCAL_GET(0), WASM_ZERO)});
  ExpectFailure(sigs.c_c(),
                {WASM_SELECT(WASM_LOCAL_GET(0), WASM_LOCAL_GET(0), WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, Select_fail1) {
  ExpectFailure(sigs.i_i(), {WASM_SELECT(WASM_F32(0.0), WASM_LOCAL_GET(0),
                                         WASM_LOCAL_GET(0))});
  ExpectFailure(sigs.i_i(), {WASM_SELECT(WASM_LOCAL_GET(0), WASM_F32(0.0),
                                         WASM_LOCAL_GET(0))});
  ExpectFailure(sigs.i_i(), {WASM_SELECT(WASM_LOCAL_GET(0), WASM_LOCAL_GET(0),
                                         WASM_F32(0.0))});
}

TEST_F(FunctionBodyDecoderTest, Select_fail2) {
  for (size_t i = 0; i < arraysize(kValueTypes); i++) {
    ValueType type = kValueTypes[i];
    if (type == kWasmI32) continue;
    // Select without specified type is only allowed for number types.
    if (type == kWasmExternRef) continue;

    ValueType types[] = {type, kWasmI32, type};
    FunctionSig sig(1, 2, types);

    ExpectValidates(&sig, {WASM_SELECT(WASM_LOCAL_GET(1), WASM_LOCAL_GET(1),
                                       WASM_LOCAL_GET(0))});

    ExpectFailure(&sig, {WASM_SELECT(WASM_LOCAL_GET(1), WASM_LOCAL_GET(0),
                                     WASM_LOCAL_GET(0))});

    ExpectFailure(&sig, {WASM_SELECT(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                                     WASM_LOCAL_GET(0))});

    ExpectFailure(&sig, {WASM_SELECT(WASM_LOCAL_GET(0), WASM_LOCAL_GET(0),
                                     WASM_LOCAL_GET(1))});
  }
}

TEST_F(FunctionBodyDecoderTest, Select_TypeCheck) {
  ExpectFailure(sigs.i_i(), {WASM_SELECT(WASM_F32(9.9), WASM_LOCAL_GET(0),
                                         WASM_LOCAL_GET(0))});

  ExpectFailure(sigs.i_i(), {WASM_SELECT(WASM_LOCAL_GET(0), WASM_F64(0.25),
                                         WASM_LOCAL_GET(0))});

  ExpectFailure(sigs.i_i(), {WASM_SELECT(WASM_F32(9.9), WASM_LOCAL_GET(0),
                                         WASM_I64V_1(0))});
}

TEST_F(FunctionBodyDecoderTest, SelectWithType) {
  ExpectValidates(sigs.i_i(), {WASM_SELECT_I(WASM_LOCAL_GET(0),
                                             WASM_LOCAL_GET(0), WASM_ZERO)});
  ExpectValidates(sigs.f_ff(),
                  {WASM_SELECT_F(WASM_F32(0.0), WASM_F32(0.0), WASM_ZERO)});
  ExpectValidates(sigs.d_dd(),
                  {WASM_SELECT_D(WASM_F64(0.0), WASM_F64(0.0), WASM_ZERO)});
  ExpectValidates(sigs.l_l(),
                  {WASM_SELECT_L(WASM_I64V_1(0), WASM_I64V_1(0), WASM_ZERO)});
  ExpectValidates(sigs.a_a(),
                  {WASM_SELECT_R(WASM_REF_NULL(kExternRefCode),
                                 WASM_REF_NULL(kExternRefCode), WASM_ZERO)});
  ExpectValidates(sigs.c_c(),
                  {WASM_SELECT_A(WASM_REF_NULL(kFuncRefCode),
                                 WASM_REF_NULL(kFuncRefCode), WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, SelectWithType_fail) {
  ExpectFailure(sigs.i_i(), {WASM_SELECT_F(WASM_LOCAL_GET(0), WASM_LOCAL_GET(0),
                                           WASM_ZERO)});
  ExpectFailure(sigs.f_ff(),
                {WASM_SELECT_D(WASM_F32(0.0), WASM_F32(0.0), WASM_ZERO)});
  ExpectFailure(sigs.d_dd(),
                {WASM_SELECT_L(WASM_F64(0.0), WASM_F64(0.0), WASM_ZERO)});
  ExpectFailure(sigs.l_l(),
                {WASM_SELECT_I(WASM_I64V_1(0), WASM_I64V_1(0), WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, Throw) {
  uint8_t ex1 = builder.AddException(sigs.v_v());
  uint8_t ex2 = builder.AddException(sigs.v_i());
  uint8_t ex3 = builder.AddException(sigs.v_ii());
  ExpectValidates(sigs.v_v(), {kExprThrow, ex1});
  ExpectValidates(sigs.v_v(), {WASM_I32V(0), kExprThrow, ex2});
  ExpectFailure(sigs.v_v(), {WASM_F32(0.0), kExprThrow, ex2});
  ExpectValidates(sigs.v_v(), {WASM_I32V(0), WASM_I32V(0), kExprThrow, ex3});
  ExpectFailure(sigs.v_v(), {WASM_F32(0.0), WASM_I32V(0), kExprThrow, ex3});
  ExpectFailure(sigs.v_v(), {kExprThrow, 99});
}

TEST_F(FunctionBodyDecoderTest, ThrowUnreachable) {
  uint8_t ex1 = builder.AddException(sigs.v_v());
  uint8_t ex2 = builder.AddException(sigs.v_i());
  ExpectValidates(sigs.i_i(), {WASM_LOCAL_GET(0), kExprThrow, ex1, WASM_NOP});
  ExpectValidates(sigs.v_i(), {WASM_LOCAL_GET(0), kExprThrow, ex2, WASM_NOP});
  ExpectValidates(sigs.i_i(), {WASM_LOCAL_GET(0), kExprThrow, ex1, WASM_ZERO});
  ExpectFailure(sigs.v_i(), {WASM_LOCAL_GET(0), kExprThrow, ex2, WASM_ZERO});
  ExpectFailure(sigs.i_i(),
                {WASM_LOCAL_GET(0), kExprThrow, ex1, WASM_F32(0.0)});
  ExpectFailure(sigs.v_i(),
                {WASM_LOCAL_GET(0), kExprThrow, ex2, WASM_F32(0.0)});
}

#define WASM_TRY_OP kExprTry, kVoidCode

TEST_F(FunctionBodyDecoderTest, TryCatch) {
  WASM_FEATURE_SCOPE(legacy_eh);
  uint8_t ex = builder.AddException(sigs.v_v());
  ExpectValidates(sigs.v_v(), {WASM_TRY_OP, kExprCatch, ex, kExprEnd});
  ExpectValidates(sigs.v_v(),
                  {WASM_TRY_OP, kExprCatch, ex, kExprCatchAll, kExprEnd});
  ExpectValidates(sigs.v_v(), {WASM_TRY_OP, kExprEnd}, kAppendEnd);
  ExpectFailure(sigs.v_v(),
                {WASM_TRY_OP, kExprCatchAll, kExprCatch, ex, kExprEnd},
                kAppendEnd, "catch after catch-all for try");
  ExpectFailure(sigs.v_v(),
                {WASM_TRY_OP, kExprCatchAll, kExprCatchAll, kExprEnd},
                kAppendEnd, "catch-all already present for try");
  ExpectFailure(sigs.v_v(), {kExprCatch, ex, kExprEnd}, kAppendEnd,
                "catch does not match a try");
}

TEST_F(FunctionBodyDecoderTest, Rethrow) {
  WASM_FEATURE_SCOPE(legacy_eh);

  ExpectValidates(sigs.v_v(),
                  {WASM_TRY_OP, kExprCatchAll, kExprRethrow, 0, kExprEnd});
  ExpectFailure(sigs.v_v(),
                {WASM_TRY_OP, kExprRethrow, 0, kExprCatch, kExprEnd},
                kAppendEnd, "rethrow not targeting catch or catch-all");
  ExpectFailure(sigs.v_v(), {WASM_BLOCK(kExprRethrow, 0)}, kAppendEnd,
                "rethrow not targeting catch or catch-all");
  ExpectFailure(sigs.v_v(), {kExprRethrow, 0}, kAppendEnd,
                "rethrow not targeting catch or catch-all");
}

TEST_F(FunctionBodyDecoderTest, TryDelegate) {
  WASM_FEATURE_SCOPE(legacy_eh);
  uint8_t ex = builder.AddException(sigs.v_v());

  ExpectValidates(sigs.v_v(), {WASM_TRY_OP,
                               WASM_TRY_DELEGATE(WASM_STMTS(kExprThrow, ex), 0),
                               kExprCatch, ex, kExprEnd});
  ExpectValidates(
      sigs.v_v(),
      {WASM_BLOCK(WASM_TRY_OP, WASM_TRY_DELEGATE(WASM_STMTS(kExprThrow, ex), 2),
                  kExprCatch, ex, kExprEnd)});
  ExpectValidates(sigs.v_v(),
                  {WASM_TRY_OP, kExprCatch, ex,
                   WASM_TRY_DELEGATE(WASM_STMTS(kExprThrow, ex), 0), kExprEnd},
                  kAppendEnd);
  ExpectValidates(sigs.v_v(),
                  {WASM_TRY_OP,
                   WASM_BLOCK(WASM_TRY_DELEGATE(WASM_STMTS(kExprThrow, ex), 0)),
                   kExprCatch, ex, kExprEnd},
                  kAppendEnd);

  ExpectFailure(
      sigs.v_v(),
      {WASM_BLOCK(WASM_TRY_OP, WASM_TRY_DELEGATE(WASM_STMTS(kExprThrow, ex), 3),
                  kExprCatch, ex, kExprEnd)},
      kAppendEnd, "invalid branch depth: 3");
  ExpectFailure(
      sigs.v_v(),
      {WASM_TRY_OP, WASM_TRY_OP, kExprCatch, ex, kExprDelegate, 0, kExprEnd},
      kAppendEnd, "delegate does not match a try");
  ExpectFailure(
      sigs.v_v(),
      {WASM_TRY_OP, WASM_TRY_OP, kExprCatchAll, kExprDelegate, 1, kExprEnd},
      kAppendEnd, "delegate does not match a try");
}

#undef WASM_TRY_OP

#define WASM_TRY_TABLE_OP kExprTryTable, kVoidCode

TEST_F(FunctionBodyDecoderTest, ThrowRef) {
  WASM_FEATURE_SCOPE(exnref);
  ExpectValidates(sigs.v_v(), {kExprBlock, kExnRefCode, WASM_TRY_TABLE_OP,
                               U32V_1(1), CatchKind::kCatchAllRef, 0, kExprEnd,
                               kExprBr, 1, kExprEnd, kExprThrowRef});
  ExpectValidates(sigs.v_v(), {kExprBlock, kVoidCode, kExprUnreachable,
                               kExprThrowRef, kExprEnd});
  ExpectFailure(
      sigs.v_v(),
      {WASM_REF_NULL(WASM_HEAP_TYPE(HeapType(HeapType::kExtern))),
       kExprThrowRef},
      kAppendEnd,
      "throw_ref[0] expected type exnref, found ref.null of type externref");
}

TEST_F(FunctionBodyDecoderTest, TryTable) {
  WASM_FEATURE_SCOPE(exnref);
  uint8_t ex = builder.AddException(sigs.v_v());
  ExpectValidates(sigs.v_v(),
                  {WASM_TRY_TABLE_OP, U32V_1(1), CatchKind::kCatch, ex,
                   U32V_1(0), kExprEnd},
                  kAppendEnd);
  ExpectValidates(sigs.v_v(),
                  {kExprBlock, kExnRefCode, WASM_TRY_TABLE_OP, U32V_1(1),
                   CatchKind::kCatchRef, ex, U32V_1(0), kExprEnd,
                   kExprUnreachable, kExprEnd, kExprDrop},
                  kAppendEnd);
  ExpectValidates(sigs.v_v(),
                  {WASM_TRY_TABLE_OP, U32V_1(1), CatchKind::kCatchAll,
                   U32V_1(0), kExprEnd, kExprUnreachable},
                  kAppendEnd);
  ExpectValidates(sigs.v_v(),
                  {kExprBlock, kExnRefCode, WASM_TRY_TABLE_OP, U32V_1(1),
                   CatchKind::kCatchAllRef, U32V_1(0), kExprEnd,
                   kExprUnreachable, kExprEnd, kExprDrop},
                  kAppendEnd);
  // All catch kinds at the same time.
  ExpectValidates(
      sigs.v_v(),
      {kExprBlock, kExnRefCode, WASM_TRY_TABLE_OP, U32V_1(4), CatchKind::kCatch,
       ex, U32V_1(1), CatchKind::kCatchRef, ex, U32V_1(0), CatchKind::kCatchAll,
       U32V_1(1), CatchKind::kCatchAllRef, U32V_1(0), kExprEnd,
       kExprUnreachable, kExprEnd, kExprDrop},
      kAppendEnd);
  // Duplicate catch-all.
  ExpectValidates(
      sigs.v_v(),
      {kExprBlock, kExnRefCode, WASM_TRY_TABLE_OP, U32V_1(4),
       CatchKind::kCatchAll, U32V_1(1), CatchKind::kCatchAll, U32V_1(1),
       CatchKind::kCatchAllRef, U32V_1(0), CatchKind::kCatchAllRef, U32V_1(0),
       kExprEnd, kExprUnreachable, kExprEnd, kExprDrop},
      kAppendEnd);
  // Catch-all before catch.
  ExpectValidates(
      sigs.v_v(),
      {WASM_TRY_TABLE_OP, U32V_1(2), CatchKind::kCatchAll, U32V_1(0),
       CatchKind::kCatch, ex, U32V_1(0), kExprEnd, kExprUnreachable},
      kAppendEnd);
  // Non-nullable exnref.
  ValueType kNonNullableExnRef = ValueType::Ref(HeapType::kExn);
  auto sig = FixedSizeSignature<ValueType>::Returns(kNonNullableExnRef);
  ModuleTypeIndex sig_id = builder.AddSignature(&sig);
  ExpectValidates(sigs.v_v(),
                  {kExprBlock, ToByte(sig_id), WASM_TRY_TABLE_OP, U32V_1(1),
                   CatchKind::kCatchRef, ex, U32V_1(0), kExprEnd,
                   kExprUnreachable, kExprEnd, kExprDrop},
                  kAppendEnd);

  constexpr uint8_t kInvalidCatchKind = kLastCatchKind + 1;
  ExpectFailure(sigs.v_v(),
                {WASM_TRY_TABLE_OP, U32V_1(1), kInvalidCatchKind, ex, U32V_1(0),
                 kExprEnd},
                kAppendEnd, "invalid catch kind in try table");
  // Branching to an exnref block with ref-less catch.
  ExpectFailure(sigs.v_v(),
                {kExprBlock, kExnRefCode, WASM_TRY_TABLE_OP, U32V_1(1), kCatch,
                 ex, U32V_1(0), kExprEnd, kExprUnreachable, kExprEnd},
                kAppendEnd,
                "catch kind generates 0 operands, target block expects 1");
  // Branching to a void block with catch-ref.
  ExpectFailure(sigs.v_v(),
                {kExprBlock, kVoidCode, WASM_TRY_TABLE_OP, U32V_1(1), kCatchRef,
                 ex, U32V_1(0), kExprEnd, kExprUnreachable, kExprEnd},
                kAppendEnd,
                "catch kind generates 1 operand, target block expects 0");
}

TEST_F(FunctionBodyDecoderTest, MultiValBlock1) {
  ModuleTypeIndex sig0 = builder.AddSignature(sigs.ii_v());
  ExpectValidates(
      sigs.i_ii(),
      {WASM_BLOCK_X(sig0, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)), kExprI32Add});
  ExpectFailure(sigs.i_ii(), {WASM_BLOCK_X(sig0, WASM_NOP), kExprI32Add},
                kAppendEnd,
                "expected 2 elements on the stack for fallthru, found 0");
  ExpectFailure(
      sigs.i_ii(), {WASM_BLOCK_X(sig0, WASM_LOCAL_GET(0)), kExprI32Add},
      kAppendEnd, "expected 2 elements on the stack for fallthru, found 1");
  ExpectFailure(sigs.i_ii(),
                {WASM_BLOCK_X(sig0, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                              WASM_LOCAL_GET(0)),
                 kExprI32Add},
                kAppendEnd,
                "expected 2 elements on the stack for fallthru, found 3");
  ExpectFailure(
      sigs.i_ii(),
      {WASM_BLOCK_X(sig0, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)), kExprF32Add},
      kAppendEnd, "f32.add[0] expected type f32, found block of type i32");

  ModuleTypeIndex sig1 = builder.AddSignature(sigs.v_i());
  ExpectFailure(
      sigs.v_i(),
      {WASM_LOCAL_GET(0), WASM_BLOCK(WASM_BLOCK_X(sig1, WASM_UNREACHABLE))},
      kAppendEnd,
      "not enough arguments on the stack for block (need 1, got 0)");
}

TEST_F(FunctionBodyDecoderTest, MultiValBlock2) {
  ModuleTypeIndex sig0 = builder.AddSignature(sigs.ii_v());
  ExpectValidates(sigs.i_ii(),
                  {WASM_BLOCK_X(sig0, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)),
                   WASM_I32_ADD(WASM_NOP, WASM_NOP)});
  ExpectFailure(sigs.i_ii(), {WASM_BLOCK_X(sig0, WASM_NOP),
                              WASM_I32_ADD(WASM_NOP, WASM_NOP)});
  ExpectFailure(sigs.i_ii(), {WASM_BLOCK_X(sig0, WASM_LOCAL_GET(0)),
                              WASM_I32_ADD(WASM_NOP, WASM_NOP)});
  ExpectFailure(sigs.i_ii(),
                {WASM_BLOCK_X(sig0, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                              WASM_LOCAL_GET(0)),
                 WASM_I32_ADD(WASM_NOP, WASM_NOP)});
  ExpectFailure(sigs.i_ii(),
                {WASM_BLOCK_X(sig0, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)),
                 WASM_F32_ADD(WASM_NOP, WASM_NOP)});
}

TEST_F(FunctionBodyDecoderTest, MultiValBlockBr) {
  ModuleTypeIndex sig0 = builder.AddSignature(sigs.ii_v());
  ExpectFailure(sigs.i_ii(), {WASM_BLOCK_X(sig0, WASM_LOCAL_GET(0), WASM_BR(0)),
                              kExprI32Add});
  ExpectValidates(sigs.i_ii(), {WASM_BLOCK_X(sig0, WASM_LOCAL_GET(0),
                                             WASM_LOCAL_GET(1), WASM_BR(0)),
                                kExprI32Add});
}

TEST_F(FunctionBodyDecoderTest, MultiValLoop1) {
  ModuleTypeIndex sig0 = builder.AddSignature(sigs.ii_v());
  ExpectValidates(
      sigs.i_ii(),
      {WASM_LOOP_X(sig0, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)), kExprI32Add});
  ExpectFailure(sigs.i_ii(), {WASM_LOOP_X(sig0, WASM_NOP), kExprI32Add});
  ExpectFailure(sigs.i_ii(),
                {WASM_LOOP_X(sig0, WASM_LOCAL_GET(0)), kExprI32Add});
  ExpectFailure(sigs.i_ii(), {WASM_LOOP_X(sig0, WASM_LOCAL_GET(0),
                                          WASM_LOCAL_GET(1), WASM_LOCAL_GET(0)),
                              kExprI32Add});
  ExpectFailure(
      sigs.i_ii(),
      {WASM_LOOP_X(sig0, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)), kExprF32Add});
}

TEST_F(FunctionBodyDecoderTest, MultiValIf) {
  ModuleTypeIndex sig0 = builder.AddSignature(sigs.ii_v());
  ExpectValidates(
      sigs.i_ii(),
      {WASM_IF_ELSE_X(sig0, WASM_LOCAL_GET(0),
                      WASM_SEQ(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)),
                      WASM_SEQ(WASM_LOCAL_GET(1), WASM_LOCAL_GET(0))),
       kExprI32Add});
  ExpectFailure(sigs.i_ii(),
                {WASM_IF_ELSE_X(sig0, WASM_LOCAL_GET(0), WASM_NOP, WASM_NOP),
                 kExprI32Add});
  ExpectFailure(sigs.i_ii(),
                {WASM_IF_ELSE_X(sig0, WASM_LOCAL_GET(0), WASM_NOP,
                                WASM_SEQ(WASM_LOCAL_GET(1), WASM_LOCAL_GET(0))),
                 kExprI32Add});
  ExpectFailure(
      sigs.i_ii(),
      {WASM_IF_ELSE_X(sig0, WASM_LOCAL_GET(0),
                      WASM_SEQ(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)), WASM_NOP),
       kExprI32Add});
  ExpectFailure(sigs.i_ii(),
                {WASM_IF_ELSE_X(sig0, WASM_LOCAL_GET(0), WASM_LOCAL_GET(0),
                                WASM_LOCAL_GET(1)),
                 kExprI32Add});
  ExpectFailure(sigs.i_ii(),
                {WASM_IF_ELSE_X(sig0, WASM_LOCAL_GET(0), WASM_LOCAL_GET(0),
                                WASM_SEQ(WASM_LOCAL_GET(1), WASM_LOCAL_GET(0))),
                 kExprI32Add});
  ExpectFailure(sigs.i_ii(),
                {WASM_IF_ELSE_X(sig0, WASM_LOCAL_GET(0),
                                WASM_SEQ(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)),
                                WASM_LOCAL_GET(1)),
                 kExprI32Add});
  ExpectFailure(
      sigs.i_ii(),
      {WASM_IF_ELSE_X(
           sig0, WASM_LOCAL_GET(0),
           WASM_SEQ(WASM_LOCAL_GET(0), WASM_LOCAL_GET(0), WASM_LOCAL_GET(0)),
           WASM_SEQ(WASM_LOCAL_GET(1), WASM_LOCAL_GET(0), WASM_LOCAL_GET(0))),
       kExprI32Add});
  ExpectFailure(sigs.i_ii(),
                {WASM_IF_ELSE_X(sig0, WASM_LOCAL_GET(0),
                                WASM_SEQ(WASM_LOCAL_GET(0), WASM_LOCAL_GET(0),
                                         WASM_LOCAL_GET(0)),
                                WASM_SEQ(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))),
                 kExprI32Add});
  ExpectFailure(sigs.i_ii(),
                {WASM_IF_ELSE_X(sig0, WASM_LOCAL_GET(0),
                                WASM_SEQ(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)),
                                WASM_SEQ(WASM_LOCAL_GET(1), WASM_LOCAL_GET(1),
                                         WASM_LOCAL_GET(1))),
                 kExprI32Add});
  ExpectFailure(sigs.i_ii(),
                {WASM_IF_ELSE_X(sig0, WASM_LOCAL_GET(0),
                                WASM_SEQ(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)),
                                WASM_SEQ(WASM_LOCAL_GET(1), WASM_LOCAL_GET(0))),
                 kExprF32Add});
}

TEST_F(FunctionBodyDecoderTest, BlockParam) {
  ModuleTypeIndex sig1 = builder.AddSignature(sigs.i_i());
  ModuleTypeIndex sig2 = builder.AddSignature(sigs.i_ii());
  ExpectValidates(
      sigs.i_ii(),
      {WASM_LOCAL_GET(0), WASM_BLOCK_X(sig1, WASM_LOCAL_GET(1),
                                       WASM_I32_ADD(WASM_NOP, WASM_NOP))});
  ExpectValidates(sigs.i_ii(),
                  {WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                   WASM_BLOCK_X(sig2, WASM_I32_ADD(WASM_NOP, WASM_NOP))});
  ExpectValidates(sigs.i_ii(), {WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                                WASM_BLOCK_X(sig1, WASM_NOP),
                                WASM_I32_ADD(WASM_NOP, WASM_NOP)});
  ExpectFailure(sigs.i_ii(),
                {WASM_BLOCK_X(sig1, WASM_NOP), WASM_RETURN(WASM_LOCAL_GET(0))});
  ExpectFailure(sigs.i_ii(), {WASM_BLOCK_X(sig1, WASM_LOCAL_GET(0)),
                              WASM_RETURN(WASM_LOCAL_GET(0))});
  ExpectFailure(
      sigs.i_ii(),
      {WASM_LOCAL_GET(0), WASM_BLOCK_X(sig2, WASM_I32_ADD(WASM_NOP, WASM_NOP)),
       WASM_RETURN(WASM_LOCAL_GET(0))});
  ExpectFailure(sigs.i_ii(),
                {WASM_LOCAL_GET(0), WASM_BLOCK_X(sig1, WASM_F32_NEG(WASM_NOP)),
                 WASM_RETURN(WASM_LOCAL_GET(0))});
}

TEST_F(FunctionBodyDecoderTest, LoopParam) {
  ModuleTypeIndex sig1 = builder.AddSignature(sigs.i_i());
  ModuleTypeIndex sig2 = builder.AddSignature(sigs.i_ii());
  ExpectValidates(sigs.i_ii(), {WASM_LOCAL_GET(0),
                                WASM_LOOP_X(sig1, WASM_LOCAL_GET(1),
                                            WASM_I32_ADD(WASM_NOP, WASM_NOP))});
  ExpectValidates(sigs.i_ii(),
                  {WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                   WASM_LOOP_X(sig2, WASM_I32_ADD(WASM_NOP, WASM_NOP))});
  ExpectValidates(sigs.i_ii(), {WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                                WASM_LOOP_X(sig1, WASM_NOP),
                                WASM_I32_ADD(WASM_NOP, WASM_NOP)});
  ExpectFailure(sigs.i_ii(),
                {WASM_LOOP_X(sig1, WASM_NOP), WASM_RETURN(WASM_LOCAL_GET(0))});
  ExpectFailure(sigs.i_ii(), {WASM_LOOP_X(sig1, WASM_LOCAL_GET(0)),
                              WASM_RETURN(WASM_LOCAL_GET(0))});
  ExpectFailure(
      sigs.i_ii(),
      {WASM_LOCAL_GET(0), WASM_LOOP_X(sig2, WASM_I32_ADD(WASM_NOP, WASM_NOP)),
       WASM_RETURN(WASM_LOCAL_GET(0))});
  ExpectFailure(sigs.i_ii(),
                {WASM_LOCAL_GET(0), WASM_LOOP_X(sig1, WASM_F32_NEG(WASM_NOP)),
                 WASM_RETURN(WASM_LOCAL_GET(0))});
}

TEST_F(FunctionBodyDecoderTest, LoopParamBr) {
  ModuleTypeIndex sig1 = builder.AddSignature(sigs.i_i());
  ModuleTypeIndex sig2 = builder.AddSignature(sigs.i_ii());
  ExpectValidates(sigs.i_ii(),
                  {WASM_LOCAL_GET(0), WASM_LOOP_X(sig1, WASM_BR(0))});
  ExpectValidates(
      sigs.i_ii(),
      {WASM_LOCAL_GET(0), WASM_LOOP_X(sig1, WASM_BRV(0, WASM_LOCAL_GET(1)))});
  ExpectValidates(sigs.i_ii(), {WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                                WASM_LOOP_X(sig2, WASM_BR(0))});
  ExpectValidates(
      sigs.i_ii(),
      {WASM_LOCAL_GET(0), WASM_LOOP_X(sig1, WASM_BLOCK_X(sig1, WASM_BR(1)))});
  ExpectFailure(sigs.i_ii(),
                {WASM_LOCAL_GET(0), WASM_LOOP_X(sig1, WASM_BLOCK(WASM_BR(1))),
                 WASM_RETURN(WASM_LOCAL_GET(0))});
  ExpectFailure(sigs.i_ii(), {WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                              WASM_LOOP_X(sig2, WASM_BLOCK_X(sig1, WASM_BR(1))),
                              WASM_RETURN(WASM_LOCAL_GET(0))});
}

TEST_F(FunctionBodyDecoderTest, IfParam) {
  ModuleTypeIndex sig1 = builder.AddSignature(sigs.i_i());
  ModuleTypeIndex sig2 = builder.AddSignature(sigs.i_ii());
  ExpectValidates(sigs.i_ii(),
                  {WASM_LOCAL_GET(0),
                   WASM_IF_X(sig1, WASM_LOCAL_GET(0),
                             WASM_I32_ADD(WASM_NOP, WASM_LOCAL_GET(1)))});
  ExpectValidates(sigs.i_ii(),
                  {WASM_LOCAL_GET(0),
                   WASM_IF_ELSE_X(sig1, WASM_LOCAL_GET(0),
                                  WASM_I32_ADD(WASM_NOP, WASM_LOCAL_GET(1)),
                                  WASM_I32_EQZ(WASM_NOP))});
  ExpectValidates(
      sigs.i_ii(),
      {WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
       WASM_IF_ELSE_X(sig2, WASM_LOCAL_GET(0), WASM_I32_ADD(WASM_NOP, WASM_NOP),
                      WASM_I32_MUL(WASM_NOP, WASM_NOP))});
  ExpectValidates(sigs.i_ii(), {WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                                WASM_IF_X(sig1, WASM_LOCAL_GET(0), WASM_NOP),
                                WASM_I32_ADD(WASM_NOP, WASM_NOP)});
  ExpectValidates(sigs.i_ii(),
                  {WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                   WASM_IF_ELSE_X(sig1, WASM_LOCAL_GET(0), WASM_NOP,
                                  WASM_I32_EQZ(WASM_NOP)),
                   WASM_I32_ADD(WASM_NOP, WASM_NOP)});
}

TEST_F(FunctionBodyDecoderTest, Regression709741) {
  AddLocals(kWasmI32, kV8MaxWasmFunctionLocals - 1);
  ExpectValidates(sigs.v_v(), {WASM_NOP});
  uint8_t code[] = {WASM_NOP, WASM_END};

  for (size_t i = 0; i < arraysize(code); ++i) {
    constexpr bool kIsShared = false;
    FunctionBody body(sigs.v_v(), 0, code, code + i, kIsShared);
    WasmDetectedFeatures unused_detected_features;
    DecodeResult result =
        ValidateFunctionBody(this->zone(), WasmEnabledFeatures::All(), module,
                             &unused_detected_features, body);
    if (result.ok()) {
      std::ostringstream str;
      str << "Expected verification to fail";
    }
  }
}

TEST_F(FunctionBodyDecoderTest, MemoryInit) {
  builder.AddMemory();
  builder.SetDataSegmentCount(1);

  ExpectValidates(sigs.v_v(),
                  {WASM_MEMORY_INIT(0, WASM_ZERO, WASM_ZERO, WASM_ZERO)});
  ExpectFailure(sigs.v_v(),
                {WASM_TABLE_INIT(0, 1, WASM_ZERO, WASM_ZERO, WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, MemoryInitInvalid) {
  builder.AddMemory();
  builder.SetDataSegmentCount(1);

  uint8_t code[] = {WASM_MEMORY_INIT(0, WASM_ZERO, WASM_ZERO, WASM_ZERO),
                    WASM_END};
  for (size_t i = 0; i <= arraysize(code); ++i) {
    Validate(i == arraysize(code), sigs.v_v(), base::VectorOf(code, i),
             kOmitEnd);
  }
}

TEST_F(FunctionBodyDecoderTest, DataDrop) {
  builder.AddMemory();
  builder.SetDataSegmentCount(1);

  ExpectValidates(sigs.v_v(), {WASM_DATA_DROP(0)});
  ExpectFailure(sigs.v_v(), {WASM_DATA_DROP(1)});
}

TEST_F(FunctionBodyDecoderTest, DataSegmentIndexUnsigned) {
  builder.AddMemory();
  builder.SetDataSegmentCount(65);

  // Make sure that the index is interpreted as an unsigned number; 64 is
  // interpreted as -64 when decoded as a signed LEB.
  ExpectValidates(sigs.v_v(),
                  {WASM_MEMORY_INIT(64, WASM_ZERO, WASM_ZERO, WASM_ZERO)});
  ExpectValidates(sigs.v_v(), {WASM_DATA_DROP(64)});
}

TEST_F(FunctionBodyDecoderTest, MemoryCopy) {
  builder.AddMemory();

  ExpectValidates(sigs.v_v(),
                  {WASM_MEMORY0_COPY(WASM_ZERO, WASM_ZERO, WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, MemoryFill) {
  builder.AddMemory();

  ExpectValidates(sigs.v_v(),
                  {WASM_MEMORY_FILL(WASM_ZERO, WASM_ZERO, WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, BulkMemoryOpsWithoutMemory) {
  ExpectFailure(sigs.v_v(),
                {WASM
"""

```