Response:
The user wants a summary of the functionality of the provided C++ code snippet. The code is part of the V8 JavaScript engine and appears to be testing the WebAssembly function body decoder.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Subject:** The code uses `TEST_F(FunctionBodyDecoderTest, ...)` which clearly indicates this is a unit test suite for something related to `FunctionBodyDecoder`. Given the `wasm` directory, the subject is the WebAssembly function body decoder.

2. **Analyze the Test Names:**  The test names are very descriptive and provide direct clues about what each test is examining. Keywords like "ReturnCalls," "IndirectReturnCalls," "SimpleIndirectCalls," "ImportCalls," "Globals," "TableSet," "TableGet," "Break," "MemoryGrow,"  all point to specific WebAssembly features or opcodes being tested.

3. **Categorize Functionality by Test Groups:** The tests can be grouped logically based on the WebAssembly feature they address:
    * **Calls:** Direct calls (`ReturnCalls`), indirect calls (`IndirectReturnCalls`, `SimpleIndirectCalls`, `MultiTableCallIndirect`), and import calls (`SimpleImportCalls`).
    * **Globals:** Getting and setting global variables (`Int32Globals`, `Int64Globals`, `Float32Globals`, `Float64Globals`, `NullRefGlobals`, etc.).
    * **Tables:** Operations on tables like setting and getting elements (`TableSet`, `TableGet`).
    * **Control Flow:**  Testing `break` instructions and their behavior within blocks and loops (`BreakEnd`, `BreakIfBinop`, `BreakNesting`, `BreaksWithMultipleTypes`, `Break_TypeCheck`).
    * **Memory:** Operations on WebAssembly memory (`WasmMemoryGrow`).
    * **Error Handling/Validation:**  Tests with names including "Failure" or explicitly checking for mismatched signatures or out-of-bounds accesses imply testing the decoder's validation logic.

4. **Look for Patterns and Common Themes:**  Many tests follow a similar structure:
    * Set up a `FunctionSig` (function signature) to define the expected input and output types.
    * Use a `TestModuleBuilder` to create a minimal WebAssembly module with necessary elements (functions, tables, globals, imports).
    * Use `ExpectValidates` to assert that a given sequence of WebAssembly bytecode is considered valid by the decoder under the specified signature.
    * Use `ExpectFailure` to assert that a given bytecode sequence is considered invalid and potentially check for specific error messages.
    * Often, tests involve checking for type mismatches or boundary conditions.

5. **Address Specific Instructions from the Prompt:**
    * **".tq" extension:** The code is C++, not Torque.
    * **JavaScript Relationship:**  WebAssembly executes within a JavaScript environment. The calls tested here correspond to invoking WebAssembly functions from within WebAssembly or potentially from JavaScript. Examples are needed to illustrate this interaction.
    * **Code Logic Inference:**  Many tests involve conditional execution (e.g., `WASM_IF`) and branching (`WASM_BR`, `WASM_BRV`). Hypothetical inputs and outputs for these control flow scenarios are needed.
    * **Common Programming Errors:**  Type mismatches, out-of-bounds access, and incorrect function call arguments are clearly being tested, representing common errors.

6. **Synthesize the Summary:** Combine the identified categories and themes into a concise description of the code's purpose. Highlight the testing of various WebAssembly features and the validation logic.

7. **Refine and Organize:**  Structure the summary logically, starting with the overall purpose and then detailing the specific areas covered by the tests. Use clear and concise language. Address all points raised in the prompt. Ensure the language emphasizes the "testing" nature of the code.这是一个V8源代码文件，用于测试WebAssembly函数体解码器的功能。 它不是以`.tq`结尾，所以不是V8 Torque源代码。

**功能归纳:**

这个代码片段是 `v8/test/unittests/wasm/function-body-decoder-unittest.cc` 文件的一部分，专注于测试 WebAssembly 函数体解码器在处理各种函数调用相关的指令时的正确性。 具体来说，它测试了以下功能：

* **返回调用 (Return Calls):**
    * 直接返回调用 (`return_call_function`): 测试了签名匹配和不匹配的情况。
    * 间接返回调用 (`return_call_indirect`): 测试了在有和没有函数表的情况下，以及签名匹配和不匹配，以及索引越界的情况。

* **普通调用 (Calls):**
    * 直接函数调用 (`call_function`): 测试了调用具有多个返回值的函数，以及返回值类型子类型的情况。
    * 间接函数调用 (`call_indirect`): 测试了在有和没有函数表的情况下，以及签名匹配和不匹配，以及索引越界的情况。 还测试了使用 `call_indirect_table` 指令以及表类型子类型的情况。
    * 调用导入函数 (`call_function`): 测试了调用导入函数时签名匹配和不匹配的情况。

* **全局变量 (Globals):**
    * 获取和设置各种类型的全局变量 (i32, i64, f32, f64, ref null)。
    * 测试不可变全局变量的设置操作。
    * 测试获取和设置全局变量时类型匹配的情况。

* **表操作 (Tables):**
    * 设置表元素 (`table_set`): 测试了设置各种类型的引用（externref, funcref）到表中的正确性，以及类型匹配和索引越界的情况。
    * 获取表元素 (`table_get`): 测试了从表中获取各种类型的引用，以及类型匹配和索引越界的情况。

* **`call_indirect` 与多表 (Multi-Table `call_indirect`):** 测试了在有多个表的情况下使用 `call_indirect` 的行为。

* **内存操作 (Memory Operations):**
    * 测试 `memory.grow` 指令的校验。

* **控制流 (Control Flow):**
    * `br` (break): 测试了带返回值的 `brv` 指令在 `block` 和 `loop` 中的使用，以及类型匹配的情况。
    * `br_if` (break if): 测试了带返回值的 `brv_if` 指令在 `block` 中的使用，以及条件类型和返回值类型匹配的情况。
    * 测试了多层嵌套的 `block` 和 `loop` 中 `br` 指令的行为。

**JavaScript 示例 (与函数调用相关):**

虽然这个 C++ 代码测试的是 WebAssembly 的解码器，但它验证的指令最终会在 JavaScript 环境中执行。以下是一些与测试的调用功能相关的 JavaScript 例子：

```javascript
// 假设我们有一个编译好的 WebAssembly 模块实例 'wasmInstance'

// 直接调用 WebAssembly 导出函数
const result1 = wasmInstance.exports.exported_function(10);

// 如果 WebAssembly 函数有多个返回值，在 JS 中会返回一个包含所有返回值的对象
// 例如，如果 WebAssembly 函数返回两个 i32
// const { value1, value2 } = wasmInstance.exports.exported_multi_return();

// 间接调用需要先获取函数表
const table = wasmInstance.exports.table; // 假设导出了一个名为 'table' 的函数表

// 假设 table 中索引 0 处有一个函数
const functionToCall = table.get(0);

// 调用函数表中的函数
const result2 = functionToCall(20);

// 调用导入的 JavaScript 函数 (需要在 WebAssembly 模块导入对象中提供)
// 例如，在实例化 WebAssembly 模块时：
// const importObject = {
//   module: {
//     imported_function: (arg) => { console.log("JS function called with:", arg); }
//   }
// };
// const wasmInstance = await WebAssembly.instantiate(wasmCode, importObject);
// wasmInstance.exports.calling_import(30);
```

**代码逻辑推理示例 (假设输入与输出):**

考虑 `TEST_F(FunctionBodyDecoderTest, SimpleIndirectReturnCalls)` 这个测试。

**假设输入:**

* 当前函数的签名 `sig` 是 `i_i()` (接收一个 i32 参数，返回一个 i32 值)。
* 函数表 `builder.AddTable(kWasmFuncRef, 20, true, 30)` 已创建。
* 定义了三个函数签名: `sig0` (i_v), `sig1` (i_i), `sig2` (i_ii)。

**测试的 WebAssembly 指令:**

* `WASM_RETURN_CALL_INDIRECT(sig0, WASM_ZERO)`: 间接调用函数表中索引为 0 的函数，假设该函数的签名是 `sig0` (接收 0 个参数，返回 i32)。由于当前函数期望返回 i32，而调用的函数也返回 i32，因此应该验证通过。
* `WASM_RETURN_CALL_INDIRECT(sig1, WASM_I32V_1(22), WASM_ZERO)`: 间接调用函数表中索引为 0 的函数，假设签名是 `sig1` (接收一个 i32 参数，返回 i32)，并传递参数 22。 由于当前函数期望返回 i32，而调用的函数也返回 i32，因此应该验证通过。
* `WASM_RETURN_CALL_INDIRECT(sig2, WASM_I32V_1(32), WASM_I32V_2(72), WASM_ZERO)`: 间接调用函数表中索引为 0 的函数，假设签名是 `sig2` (接收两个 i32 参数，返回 i32)，并传递参数 32 和 72。由于当前函数期望返回 i32，而调用的函数也返回 i32，因此应该验证通过。

**预期输出:** `ExpectValidates` 会断言这些指令序列是合法的，解码器应该成功解析。

**用户常见的编程错误示例:**

与这些测试相关的常见 WebAssembly 编程错误包括：

* **函数签名不匹配:**  尝试调用一个函数，但传递的参数类型或数量与函数定义的签名不符，或者被调用函数的返回值类型与调用者期望的类型不符。 这在 `ReturnCallsWithMismatchedSigs` 和 `IndirectReturnCallsWithMismatchedSigs3` 等测试中被重点测试。

  ```c++
  // WebAssembly 代码 (假设被调用的函数期望接收一个 i32 参数)
  // ...
  (func (param i32) ...)

  // 错误的调用：没有传递参数
  {WASM_CALL_FUNCTION0(0)} // 假设索引 0 的函数是上述函数

  // 错误的调用：传递了错误的参数类型
  {WASM_CALL_FUNCTION(0, WASM_F32(1.0f))}
  ```

* **间接调用时函数表索引越界:** 尝试调用函数表中的一个不存在的索引。这在 `IndirectReturnCallsOutOfBounds` 和 `IndirectCallsOutOfBounds` 等测试中被测试。

  ```c++
  // 假设函数表大小为 10
  {WASM_CALL_INDIRECT(0, WASM_ZERO)} // 假设索引 0 的签名存在，但表大小不够大
  ```

* **尝试设置表元素时类型不匹配:** 尝试将一个不符合表元素类型的引用值设置到表中。这在 `TableSet` 测试中被测试。

  ```c++
  // 假设表 tab_ref1 的类型是 externref
  // 尝试将一个 funcref 设置到 externref 表中
  {WASM_TABLE_SET(tab_ref1, WASM_I32V(6), WASM_LOCAL_GET(local_func))}
  ```

* **在需要返回值的地方没有提供返回值 (或提供了错误类型的返回值):**  特别是在 `brv` 和 `return` 指令中。这在 `Break_TypeCheck` 等测试中被测试。

  ```c++
  // 假设 block 期望一个 i32 返回值
  {WASM_BLOCK_I(WASM_IF(WASM_ZERO, WASM_BR(0)))} // 错误：br 没有返回值
  {WASM_BLOCK_I(WASM_IF(WASM_ZERO, WASM_BRV(0, WASM_F32(1.0f))))} // 错误：返回值类型不匹配
  ```

总结来说，这个代码片段是 WebAssembly 函数体解码器的单元测试，主要验证了解码器在处理各种函数调用、全局变量访问、表操作和控制流指令时的正确性，包括对类型匹配、边界条件和错误情况的校验。

Prompt: 
```
这是目录为v8/test/unittests/wasm/function-body-decoder-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/wasm/function-body-decoder-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共7部分，请归纳一下它的功能

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
                                     WASM_DROP, WASM_LOCAL_GET(whi
"""


```