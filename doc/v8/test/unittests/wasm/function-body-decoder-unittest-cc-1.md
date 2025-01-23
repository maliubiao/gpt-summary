Response:
The user wants a summary of the functionality of the provided C++ code snippet. The code is a unit test file for a WebAssembly function body decoder.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the core purpose:** The filename `function-body-decoder-unittest.cc` immediately suggests this is testing the functionality of a component that decodes WebAssembly function bodies. The "unittest" part confirms this.

2. **Scan the test names:**  The `TEST_F` macros define individual test cases. Reading through the names provides a good overview of what aspects are being tested:
    * `Block_falloff`, `Block_type`, `Block_end`, `Block_nested`, `BlockBreak`: Testing different scenarios for `block` instructions.
    * `If_startArityMismatch`, `IfBreak`, `IfElseBreak`, `Block_else`, `IfNop`, `If_end`, `If_falloff1`, `IfElseNop`, `IfBlock1`, `IfBlock1b`, `IfBlock2a`, `IfBlock2b`, `IfElseSet`:  Testing various aspects of `if` and `if-else` instructions.
    * `Loop0`, `Loop1`, `Loop2`, `Loop1_continue`, `Loop1_break`, `Loop2_continue`, `Loop2_break`, `InfiniteLoop1`, `InfiniteLoop2`, `Loop2_unreachable`, `LoopType`, `LoopType_void`, `LoopType_fail`:  Testing `loop` instructions.
    * `ReturnVoid1`, `ReturnVoid2`, `ReturnVoid3`: Testing `return` instructions in void functions.
    * `Unreachable1`, `Unreachable2`, `UnreachableLoop1`, `Unreachable_binop1`, `Unreachable_binop2`, `Unreachable_select1`, `Unreachable_select2`, `UnreachableRefTypes`: Testing the `unreachable` instruction.
    * `If1`, `If_off_end`, `If_type1`, `If_type2`, `If_type3`, `If_type4`, `If_type5`: More detailed testing of `if` and `if-else` with different types.
    * `Int64Local_param`, `Int64Locals`: Testing handling of 64-bit integer local variables.
    * `Int32Binops`, `DoubleBinops`, `FloatBinops`: Testing binary operations for different data types.
    * `TypeConversions`: Testing type conversion instructions.
    * `MacrosVoid`, `MacrosContinue`, `MacrosVariadic`, `MacrosNestedBlocks`, `MultipleReturn`, `MultipleReturn_fallthru`, `MacrosInt32`, `MacrosInt64`: Testing helper macros for generating WASM bytecode.
    * `AllSimpleExpressions`:  A broad test of simple WASM expressions.
    * `MemorySize`, `LoadMemOffset`, `LoadMemAlignment`, `StoreMemOffset`, `StoreMemOffset_void`, `LoadMemOffset_varint`, `StoreMemOffset_varint`, `AllLoadMemCombinations`, `AllStoreMemCombinations`: Testing memory-related instructions (size, load, store).
    * `SimpleCalls`, `CallsWithTooFewArguments`, `CallsWithMismatchedSigs2`, `CallsWithMismatchedSigs3`, `SimpleReturnCalls`, `ReturnCallsWithTooFewArguments`, `ReturnCallWithSubtype`: Testing function call instructions.

3. **Categorize the functionalities:** Group similar test cases together to form broader functional areas. The test names already provide good hints. This leads to categories like:
    * Block instructions
    * If/Else instructions
    * Loop instructions
    * Return instructions
    * Unreachable instruction
    * Local variables
    * Binary operations
    * Type conversions
    * Memory access instructions
    * Function calls

4. **Generalize and summarize:**  For each category, summarize the main testing goal. For instance, for "If/Else instructions," the goal is to ensure the decoder correctly handles various `if` and `if-else` constructs, including nested ones, different break scenarios, and type checking.

5. **Address the specific instructions:** The prompt asks for mentions of JavaScript interaction, Torque, code logic, and common errors.
    * **JavaScript:** Since this is WebAssembly, there's an inherent connection to JavaScript (as WASM runs in JS environments). The tests ensure the WASM code, once decoded, behaves correctly when invoked from JavaScript.
    * **Torque:** The prompt specifically asks about `.tq` files. The response should acknowledge that this file is C++, not Torque.
    * **Code Logic:**  The tests inherently involve logical reasoning about the control flow and data manipulation within WASM functions. The `ExpectValidates` and `ExpectFailure` checks are the core of this logic. Examples can be created based on the test cases (though the prompt only requires listing the *functionality*).
    * **Common Errors:**  The `ExpectFailure` tests are specifically designed to catch common programming errors in WASM, like type mismatches, incorrect branching, or missing `end` markers.

6. **Structure the summary:** Organize the findings into clear sections addressing the prompt's requirements.

7. **Review and refine:** Ensure the summary is accurate, comprehensive (given the snippet), and easy to understand. Make sure it directly answers all parts of the prompt. For example, initially, I might have missed explicitly mentioning type checking, but reviewing the test names reveals tests like `If_type1` which highlights this aspect. Similarly, the `ExpectFailure` tests clearly point towards the testing of error handling.
好的，这是对提供的 V8 源代码片段（`v8/test/unittests/wasm/function-body-decoder-unittest.cc` 的一部分）的功能归纳：

**功能归纳（第 2 部分）：**

这个代码片段主要集中在测试 WebAssembly 函数体解码器对 **控制流指令** 和 **局部变量操作** 的处理是否正确。具体来说，它测试了以下指令和场景：

* **`if` 和 `if-else` 指令：**
    * **基本功能：**  验证 `if` 和 `if-else` 指令的基本语法和执行逻辑。
    * **分支目标：** 测试 `if` 分支和 `else` 分支中 `br`（break）指令的目标是否正确。
    * **`else` 块：**  测试 `else` 块的正确使用，包括缺少 `else` 的情况。
    * **空操作：** 验证 `if` 分支或 `else` 分支为空操作 (`nop`) 的情况。
    * **块结构：** 测试 `if` 和 `if-else` 语句中嵌套 `block` 结构的情况。
    * **类型检查：** 验证 `if` 条件表达式的类型必须是 `i32`。
    * **返回值：** 测试 `if-else` 表达式的返回值类型是否一致。
    * **代码边界：** 测试 `if` 和 `if-else` 指令代码的完整性，防止读取越界。

* **`loop` 指令：**
    * **基本功能：** 验证 `loop` 指令的基本语法。
    * **`continue` 和 `break`：** 测试在 `loop` 中使用 `br 0` (continue) 和 `br 1` (break) 的行为。
    * **无限循环：** 验证可以创建无限循环。
    * **类型参数：** 测试 `loop` 指令可以携带返回值类型。
    * **类型检查：**  验证带返回值类型的 `loop` 必须返回相应类型的值。

* **`return` 指令：**
    * **`void` 返回：** 测试函数返回类型为 `void` 时，函数体的正确结束方式。
    * **返回值的缺失/多余：** 测试当函数有返回值时，是否缺少或多余返回值会导致验证失败。

* **`unreachable` 指令：**
    * **基本功能：** 验证 `unreachable` 指令的正确性。
    * **控制流：** 测试 `unreachable` 指令对控制流的影响，例如在 `block` 和 `loop` 中的行为。
    * **与运算符结合：** 测试 `unreachable` 与二元运算符 (`and`) 和 `select` 指令的结合。
    * **引用类型：** 测试 `unreachable` 指令在涉及引用类型操作时的行为，例如 `ref.is_null`, `ref.as_non_null`, `call_ref`, `return_call_ref`, 垃圾回收相关的指令 (`struct.new`, `array.new` 等), `br_on_null`, `ref.test`, `ref.cast`。
    * **类型栈：** 专门测试 `unreachable` 如何影响类型栈的合并，修复了一个相关的 bug。

* **局部变量操作：**
    * **`local.get` 和 `local.set`：** 测试获取和设置局部变量的值。
    * **`i64` 类型：**  特别测试了 `i64` 类型局部变量的处理。

* **二元和一元运算符：**
    * **各种算术和比较运算符：**  测试了 `i32`、`i64`、`f32`、`f64` 的各种二元运算符（加、减、乘、除、余数、位运算、比较等）。
    * **类型转换：** 测试了各种类型转换指令 (`i32.convert_s/u_f32/f64`, `f64.convert_s/u_i32`, `f64.convert_f32`, `f32.convert_s/u_i32`, `f32.convert_f64`)。

* **宏的使用：**
    * **简化测试代码：** 使用宏 (`WASM_IF`, `WASM_LOOP`, `B1`, `B2`, `WASM_LOCAL_SET` 等) 来简化 WebAssembly 字节码的构建，并测试这些宏的正确性。
    * **测试多返回值：**  测试了模拟多返回值的宏。

* **内存访问指令：**
    * **`memory.size`：** 测试获取内存大小的指令。
    * **`*.load` 和 `*.store`：** 测试各种类型的内存加载和存储指令，包括不同的偏移量和对齐方式。
    * **偏移量和对齐：**  测试偏移量和对齐参数的正确编码和解码。
    * **所有组合：** 测试了不同值类型和内存类型的加载和存储组合。

* **函数调用指令：**
    * **`call_function`：** 测试直接函数调用指令。
    * **`return_call_function`：** 测试尾调用指令。
    * **参数数量和类型检查：**  测试函数调用时参数数量不足或类型不匹配的情况。
    * **子类型关系：**  测试返回值存在子类型关系的函数调用。

**关于其他问题：**

* **`.tq` 结尾：**  `v8/test/unittests/wasm/function-body-decoder-unittest.cc` 以 `.cc` 结尾，因此它是一个 **C++** 源代码文件，而不是 Torque (`.tq`) 文件。

* **与 JavaScript 的关系：**  WebAssembly 的主要用途是在 JavaScript 虚拟机中运行。这个单元测试确保了 V8 的 WebAssembly 解码器能够正确解析 WebAssembly 的字节码，这对于在 JavaScript 环境中执行 WebAssembly 代码至关重要。

   **JavaScript 示例：**

   ```javascript
   const wasmBytes = new Uint8Array([
     0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // WASM 头部
     0x01, 0x07, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f, // 类型段：定义一个函数签名 i32 -> i32
     0x03, 0x02, 0x01, 0x00,                         // 函数段：定义一个函数，使用签名 0
     0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x10, 0x00, 0x0b  // 代码段：函数体 (local.get 0, return)
   ]);

   WebAssembly.instantiate(wasmBytes).then(module => {
     const instance = module.instance;
     const result = instance.exports.f(10); // 调用导出的函数
     console.log(result); // 输出 10
   });
   ```
   这个 JavaScript 代码加载了一段简单的 WebAssembly 代码，该代码定义了一个接受一个 `i32` 参数并返回该参数的函数。`function-body-decoder-unittest.cc` 中的测试确保 V8 能够正确解析类似这样的 WebAssembly 函数体。

* **代码逻辑推理：**  每个 `TEST_F` 都有其特定的假设输入（WebAssembly 字节码）和期望的输出（验证成功或失败）。

   **假设输入与输出示例 (基于 `TEST_F(FunctionBodyDecoderTest, IfBreak)`):**

   * **假设输入 (字节码):**  对于 `ExpectValidates(sigs.v_i(), {WASM_IF(WASM_LOCAL_GET(0), WASM_BR(0))});`， 假设输入的 WebAssembly 函数体包含一个 `if` 指令，条件是获取局部变量 0，如果条件为真，则执行 `br 0` (跳出当前块)。
   * **预期输出:**  验证器应该成功验证这段代码，因为 `br 0` 的目标是合法的（跳出当前的 `if` 块）。

* **用户常见的编程错误：** 这些单元测试旨在捕获用户在编写 WebAssembly 代码时容易犯的错误，例如：
    * **类型不匹配：**  例如，在需要 `i32` 条件的地方使用了 `f32`。
    * **控制流错误：** 例如，`br` 指令的目标标签不存在或超出范围。
    * **缺少 `end` 标记：**  例如，`block` 或 `if` 语句缺少 `end` 指令。
    * **返回值处理错误：**  函数声明了返回值，但函数体没有返回相应的值，或者返回了错误类型的值。
    * **内存访问越界：**  虽然这个测试主要关注解码，但解码的正确性是防止运行时内存访问错误的基石。
    * **函数调用参数错误：** 调用函数时提供的参数数量或类型不正确。

总而言之，这个代码片段是 V8 WebAssembly 实现中至关重要的一部分，它通过大量的单元测试来保证函数体解码器的正确性和健壮性，从而确保 WebAssembly 代码能够在 V8 引擎中安全可靠地执行。

### 提示词
```
这是目录为v8/test/unittests/wasm/function-body-decoder-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/wasm/function-body-decoder-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
"start-arity and end-arity of one-armed if must match");
}

TEST_F(FunctionBodyDecoderTest, IfBreak) {
  ExpectValidates(sigs.v_i(), {WASM_IF(WASM_LOCAL_GET(0), WASM_BR(0))});
  ExpectValidates(sigs.v_i(), {WASM_IF(WASM_LOCAL_GET(0), WASM_BR(1))});
  ExpectFailure(sigs.v_i(), {WASM_IF(WASM_LOCAL_GET(0), WASM_BR(2))});
}

TEST_F(FunctionBodyDecoderTest, IfElseBreak) {
  ExpectValidates(sigs.v_i(),
                  {WASM_IF_ELSE(WASM_LOCAL_GET(0), WASM_NOP, WASM_BR(0))});
  ExpectValidates(sigs.v_i(),
                  {WASM_IF_ELSE(WASM_LOCAL_GET(0), WASM_NOP, WASM_BR(1))});
  ExpectFailure(sigs.v_i(),
                {WASM_IF_ELSE(WASM_LOCAL_GET(0), WASM_NOP, WASM_BR(2))});
}

TEST_F(FunctionBodyDecoderTest, Block_else) {
  uint8_t code[] = {kExprI32Const, 0, kExprBlock, kExprElse, kExprEnd};
  ExpectFailure(sigs.v_v(), code);
  ExpectFailure(sigs.i_i(), code);
}

TEST_F(FunctionBodyDecoderTest, IfNop) {
  ExpectValidates(sigs.v_i(), {WASM_IF(WASM_LOCAL_GET(0), WASM_NOP)});
  ExpectValidates(sigs.v_i(),
                  {WASM_IF_ELSE(WASM_LOCAL_GET(0), WASM_NOP, WASM_NOP)});
}

TEST_F(FunctionBodyDecoderTest, If_end) {
  ExpectValidates(sigs.v_i(), {kExprLocalGet, 0, WASM_IF_OP, kExprEnd});
  ExpectFailure(sigs.v_i(), {kExprLocalGet, 0, WASM_IF_OP, kExprEnd, kExprEnd});
}

TEST_F(FunctionBodyDecoderTest, If_falloff1) {
  ExpectFailure(sigs.v_i(), {kExprLocalGet, 0, kExprIf});
  ExpectFailure(sigs.v_i(), {kExprLocalGet, 0, WASM_IF_OP});
  ExpectFailure(sigs.v_i(),
                {kExprLocalGet, 0, WASM_IF_OP, kExprNop, kExprElse});
}

TEST_F(FunctionBodyDecoderTest, IfElseNop) {
  ExpectValidates(sigs.v_i(),
                  {WASM_IF_ELSE(WASM_LOCAL_GET(0), WASM_LOCAL_SET(0, WASM_ZERO),
                                WASM_NOP)});
}

TEST_F(FunctionBodyDecoderTest, IfBlock1) {
  ExpectValidates(sigs.v_i(),
                  {WASM_IF_ELSE(WASM_LOCAL_GET(0),
                                B1(WASM_LOCAL_SET(0, WASM_ZERO)), WASM_NOP)});
}

TEST_F(FunctionBodyDecoderTest, IfBlock1b) {
  ExpectValidates(sigs.v_i(), {WASM_IF(WASM_LOCAL_GET(0),
                                       B1(WASM_LOCAL_SET(0, WASM_ZERO)))});
}

TEST_F(FunctionBodyDecoderTest, IfBlock2a) {
  ExpectValidates(sigs.v_i(), {WASM_IF(WASM_LOCAL_GET(0),
                                       B2(WASM_LOCAL_SET(0, WASM_ZERO),
                                          WASM_LOCAL_SET(0, WASM_ZERO)))});
}

TEST_F(FunctionBodyDecoderTest, IfBlock2b) {
  ExpectValidates(sigs.v_i(), {WASM_IF_ELSE(WASM_LOCAL_GET(0),
                                            B2(WASM_LOCAL_SET(0, WASM_ZERO),
                                               WASM_LOCAL_SET(0, WASM_ZERO)),
                                            WASM_NOP)});
}

TEST_F(FunctionBodyDecoderTest, IfElseSet) {
  ExpectValidates(sigs.v_i(),
                  {WASM_IF_ELSE(WASM_LOCAL_GET(0), WASM_LOCAL_SET(0, WASM_ZERO),
                                WASM_LOCAL_SET(0, WASM_I32V_1(1)))});
}

TEST_F(FunctionBodyDecoderTest, Loop0) {
  ExpectValidates(sigs.v_v(), {WASM_LOOP_OP, kExprEnd});
}

TEST_F(FunctionBodyDecoderTest, Loop1) {
  static const uint8_t code[] = {WASM_LOOP(WASM_LOCAL_SET(0, WASM_ZERO))};
  ExpectValidates(sigs.v_i(), code);
  ExpectFailure(sigs.v_v(), code);
  ExpectFailure(sigs.f_ff(), code);
}

TEST_F(FunctionBodyDecoderTest, Loop2) {
  ExpectValidates(sigs.v_i(), {WASM_LOOP(WASM_LOCAL_SET(0, WASM_ZERO),
                                         WASM_LOCAL_SET(0, WASM_ZERO))});
}

TEST_F(FunctionBodyDecoderTest, Loop1_continue) {
  ExpectValidates(sigs.v_v(), {WASM_LOOP(WASM_BR(0))});
}

TEST_F(FunctionBodyDecoderTest, Loop1_break) {
  ExpectValidates(sigs.v_v(), {WASM_LOOP(WASM_BR(1))});
}

TEST_F(FunctionBodyDecoderTest, Loop2_continue) {
  ExpectValidates(sigs.v_i(),
                  {WASM_LOOP(WASM_LOCAL_SET(0, WASM_ZERO), WASM_BR(0))});
}

TEST_F(FunctionBodyDecoderTest, Loop2_break) {
  ExpectValidates(sigs.v_i(),
                  {WASM_LOOP(WASM_LOCAL_SET(0, WASM_ZERO), WASM_BR(1))});
}

TEST_F(FunctionBodyDecoderTest, InfiniteLoop1) {
  ExpectValidates(sigs.i_i(), {WASM_LOOP(WASM_BR(0)), WASM_ZERO});
  ExpectValidates(sigs.i_i(), {WASM_LOOP(WASM_BR(0)), WASM_ZERO});
  ExpectValidates(sigs.i_i(), {WASM_LOOP_I(WASM_BRV(1, WASM_ZERO))});
}

TEST_F(FunctionBodyDecoderTest, InfiniteLoop2) {
  ExpectFailure(sigs.i_i(), {WASM_LOOP(WASM_BR(0), WASM_ZERO), WASM_ZERO});
}

TEST_F(FunctionBodyDecoderTest, Loop2_unreachable) {
  ExpectValidates(sigs.i_i(), {WASM_LOOP_I(WASM_BR(0), WASM_NOP)});
}

TEST_F(FunctionBodyDecoderTest, LoopType) {
  ExpectValidates(sigs.i_i(), {WASM_LOOP_I(WASM_LOCAL_GET(0))});
  ExpectValidates(sigs.l_l(), {WASM_LOOP_L(WASM_LOCAL_GET(0))});
  ExpectValidates(sigs.f_f(), {WASM_LOOP_F(WASM_LOCAL_GET(0))});
  ExpectValidates(sigs.d_d(), {WASM_LOOP_D(WASM_LOCAL_GET(0))});
}

TEST_F(FunctionBodyDecoderTest, LoopType_void) {
  ExpectFailure(sigs.v_v(), {WASM_LOOP_I(WASM_ZERO)});
  ExpectFailure(sigs.v_v(), {WASM_LOOP_L(WASM_I64V_1(0))});
  ExpectFailure(sigs.v_v(), {WASM_LOOP_F(WASM_F32(0.0))});
  ExpectFailure(sigs.v_v(), {WASM_LOOP_D(WASM_F64(1.1))});
}

TEST_F(FunctionBodyDecoderTest, LoopType_fail) {
  ExpectFailure(sigs.i_i(), {WASM_LOOP_L(WASM_I64V_1(0))});
  ExpectFailure(sigs.i_i(), {WASM_LOOP_F(WASM_F32(0.0))});
  ExpectFailure(sigs.i_i(), {WASM_LOOP_D(WASM_F64(1.1))});

  ExpectFailure(sigs.l_l(), {WASM_LOOP_I(WASM_ZERO)});
  ExpectFailure(sigs.l_l(), {WASM_LOOP_F(WASM_F32(0.0))});
  ExpectFailure(sigs.l_l(), {WASM_LOOP_D(WASM_F64(1.1))});

  ExpectFailure(sigs.f_ff(), {WASM_LOOP_I(WASM_ZERO)});
  ExpectFailure(sigs.f_ff(), {WASM_LOOP_L(WASM_I64V_1(0))});
  ExpectFailure(sigs.f_ff(), {WASM_LOOP_D(WASM_F64(1.1))});

  ExpectFailure(sigs.d_dd(), {WASM_LOOP_I(WASM_ZERO)});
  ExpectFailure(sigs.d_dd(), {WASM_LOOP_L(WASM_I64V_1(0))});
  ExpectFailure(sigs.d_dd(), {WASM_LOOP_F(WASM_F32(0.0))});
}

TEST_F(FunctionBodyDecoderTest, ReturnVoid1) {
  static const uint8_t code[] = {kExprNop};
  ExpectValidates(sigs.v_v(), code);
  ExpectFailure(sigs.i_i(), code);
  ExpectFailure(sigs.i_f(), code);
}

TEST_F(FunctionBodyDecoderTest, ReturnVoid2) {
  static const uint8_t code[] = {WASM_BLOCK(WASM_BR(0))};
  ExpectValidates(sigs.v_v(), code);
  ExpectFailure(sigs.i_i(), code);
  ExpectFailure(sigs.i_f(), code);
}

TEST_F(FunctionBodyDecoderTest, ReturnVoid3) {
  ExpectFailure(sigs.v_v(), {kExprI32Const, 0});
  ExpectFailure(sigs.v_v(), {kExprI64Const, 0});
  ExpectFailure(sigs.v_v(), {kExprF32Const, 0, 0, 0, 0});
  ExpectFailure(sigs.v_v(), {kExprF64Const, 0, 0, 0, 0, 0, 0, 0, 0});
  ExpectFailure(sigs.v_v(), {kExprRefNull});
  ExpectFailure(sigs.v_v(), {kExprRefFunc, 0});

  ExpectFailure(sigs.v_i(), {kExprLocalGet, 0});
}

TEST_F(FunctionBodyDecoderTest, Unreachable1) {
  ExpectValidates(sigs.v_v(), {WASM_UNREACHABLE});
  ExpectValidates(sigs.v_v(), {WASM_UNREACHABLE, WASM_UNREACHABLE});
  ExpectValidates(sigs.i_i(), {WASM_UNREACHABLE, WASM_ZERO});
}

TEST_F(FunctionBodyDecoderTest, Unreachable2) {
  ExpectFailure(sigs.v_v(), {B2(WASM_UNREACHABLE, WASM_ZERO)});
  ExpectFailure(sigs.v_v(), {B2(WASM_BR(0), WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, UnreachableLoop1) {
  ExpectFailure(sigs.v_v(), {WASM_LOOP(WASM_UNREACHABLE, WASM_ZERO)});
  ExpectFailure(sigs.v_v(), {WASM_LOOP(WASM_BR(0), WASM_ZERO)});
  ExpectValidates(sigs.v_v(), {WASM_LOOP(WASM_UNREACHABLE, WASM_NOP)});
  ExpectValidates(sigs.v_v(), {WASM_LOOP(WASM_BR(0), WASM_NOP)});
}

TEST_F(FunctionBodyDecoderTest, Unreachable_binop1) {
  ExpectValidates(sigs.i_i(), {WASM_I32_AND(WASM_ZERO, WASM_UNREACHABLE)});
  ExpectValidates(sigs.i_i(), {WASM_I32_AND(WASM_UNREACHABLE, WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, Unreachable_binop2) {
  ExpectValidates(sigs.i_i(), {WASM_I32_AND(WASM_F32(0.0), WASM_UNREACHABLE)});
  ExpectFailure(sigs.i_i(), {WASM_I32_AND(WASM_UNREACHABLE, WASM_F32(0.0))});
}

TEST_F(FunctionBodyDecoderTest, Unreachable_select1) {
  ExpectValidates(sigs.i_i(),
                  {WASM_SELECT(WASM_UNREACHABLE, WASM_ZERO, WASM_ZERO)});
  ExpectValidates(sigs.i_i(),
                  {WASM_SELECT(WASM_ZERO, WASM_UNREACHABLE, WASM_ZERO)});
  ExpectValidates(sigs.i_i(),
                  {WASM_SELECT(WASM_ZERO, WASM_ZERO, WASM_UNREACHABLE)});
}

TEST_F(FunctionBodyDecoderTest, Unreachable_select2) {
  ExpectValidates(sigs.i_i(),
                  {WASM_SELECT(WASM_F32(0.0), WASM_UNREACHABLE, WASM_ZERO)});
  ExpectFailure(sigs.i_i(),
                {WASM_SELECT(WASM_UNREACHABLE, WASM_F32(0.0), WASM_ZERO)});
  ExpectFailure(sigs.i_i(),
                {WASM_SELECT(WASM_UNREACHABLE, WASM_ZERO, WASM_F32(0.0))});
}

TEST_F(FunctionBodyDecoderTest, UnreachableRefTypes) {
  ModuleTypeIndex sig_index = builder.AddSignature(sigs.i_ii());
  uint8_t function_index = builder.AddFunction(sig_index);
  ModuleTypeIndex struct_index =
      builder.AddStruct({F(kWasmI32, true), F(kWasmI64, true)});
  ModuleTypeIndex array_index = builder.AddArray(kWasmI32, true);

  ValueType struct_type = ValueType::Ref(struct_index);
  ValueType struct_type_null = ValueType::RefNull(struct_index);
  FunctionSig sig_v_s(0, 1, &struct_type);
  uint8_t struct_consumer = builder.AddFunction(&sig_v_s);
  uint8_t struct_consumer2 = builder.AddFunction(
      FunctionSig::Build(zone(), {kWasmI32}, {struct_type, struct_type}));

  ExpectValidates(sigs.i_v(), {WASM_UNREACHABLE, kExprRefIsNull});
  ExpectValidates(sigs.v_v(), {WASM_UNREACHABLE, kExprRefAsNonNull, kExprDrop});

  ExpectValidates(sigs.i_v(),
                  {WASM_UNREACHABLE, kExprCallRef, ToByte(sig_index)});
  ExpectValidates(sigs.i_v(), {WASM_UNREACHABLE, WASM_REF_FUNC(function_index),
                               kExprCallRef, ToByte(sig_index)});
  ExpectValidates(sigs.i_v(),
                  {WASM_UNREACHABLE, kExprReturnCallRef, ToByte(sig_index)});

  ExpectValidates(sigs.v_v(),
                  {WASM_UNREACHABLE, WASM_GC_OP(kExprStructNew),
                   ToByte(struct_index), kExprCallFunction, struct_consumer});
  ExpectValidates(sigs.v_v(),
                  {WASM_UNREACHABLE, WASM_I64V(42), WASM_GC_OP(kExprStructNew),
                   ToByte(struct_index), kExprCallFunction, struct_consumer});
  ExpectValidates(sigs.v_v(),
                  {WASM_UNREACHABLE, WASM_GC_OP(kExprStructNewDefault),
                   ToByte(struct_index), kExprDrop});
  ExpectValidates(sigs.v_v(),
                  {WASM_UNREACHABLE, WASM_GC_OP(kExprStructNewDefault),
                   ToByte(struct_index), kExprCallFunction, struct_consumer});

  ExpectValidates(sigs.v_v(), {WASM_UNREACHABLE, WASM_GC_OP(kExprArrayNew),
                               ToByte(array_index), kExprDrop});
  ExpectValidates(sigs.v_v(),
                  {WASM_UNREACHABLE, WASM_I32V(42), WASM_GC_OP(kExprArrayNew),
                   ToByte(array_index), kExprDrop});
  ExpectValidates(sigs.v_v(),
                  {WASM_UNREACHABLE, WASM_GC_OP(kExprArrayNewDefault),
                   ToByte(array_index), kExprDrop});

  ExpectValidates(sigs.i_v(), {WASM_UNREACHABLE, WASM_GC_OP(kExprRefTest),
                               ToByte(struct_index)});
  ExpectValidates(sigs.i_v(),
                  {WASM_UNREACHABLE, WASM_GC_OP(kExprRefTest), kEqRefCode});

  ExpectValidates(sigs.v_v(), {WASM_UNREACHABLE, WASM_GC_OP(kExprRefCast),
                               ToByte(struct_index), kExprDrop});

  ExpectValidates(sigs.v_v(), {WASM_UNREACHABLE, kExprBrOnNull, 0, WASM_DROP});

  ExpectValidates(&sig_v_s, {WASM_UNREACHABLE, WASM_LOCAL_GET(0), kExprBrOnNull,
                             0, kExprCallFunction, struct_consumer});

  ExpectValidates(
      FunctionSig::Build(zone(), {struct_type}, {}),
      {WASM_UNREACHABLE, WASM_GC_OP(kExprRefCast), ToByte(struct_index)});

  ExpectValidates(FunctionSig::Build(zone(), {kWasmStructRef}, {}),
                  {WASM_UNREACHABLE, WASM_GC_OP(kExprRefCast), kStructRefCode});

  ExpectValidates(FunctionSig::Build(zone(), {}, {struct_type_null}),
                  {WASM_UNREACHABLE, WASM_LOCAL_GET(0), kExprBrOnNull, 0,
                   kExprCallFunction, struct_consumer});

  ExpectFailure(
      sigs.v_v(), {WASM_UNREACHABLE, WASM_I32V(42), kExprBrOnNull, 0},
      kAppendEnd,
      "br_on_null[0] expected object reference, found i32.const of type i32");

  // This tests for a bug where {TypeCheckStackAgainstMerge} did not insert
  // unreachable values into the stack correctly.
  ExpectValidates(FunctionSig::Build(zone(), {kWasmI32}, {struct_type_null}),
                  {WASM_BLOCK_R(struct_type_null, kExprUnreachable,   // --
                                kExprLocalGet, 0, kExprRefAsNonNull,  // --
                                kExprLocalGet, 0, kExprBrOnNull, 0,   // --
                                kExprCallFunction, struct_consumer2,  // --
                                kExprBr, 1),
                   kExprDrop, WASM_I32V(1)});
}

TEST_F(FunctionBodyDecoderTest, If1) {
  ExpectValidates(sigs.i_i(), {WASM_IF_ELSE_I(WASM_LOCAL_GET(0), WASM_I32V_1(9),
                                              WASM_I32V_1(8))});
  ExpectValidates(sigs.i_i(), {WASM_IF_ELSE_I(WASM_LOCAL_GET(0), WASM_I32V_1(9),
                                              WASM_LOCAL_GET(0))});
  ExpectValidates(
      sigs.i_i(),
      {WASM_IF_ELSE_I(WASM_LOCAL_GET(0), WASM_LOCAL_GET(0), WASM_I32V_1(8))});
}

TEST_F(FunctionBodyDecoderTest, If_off_end) {
  static const uint8_t kCode[] = {
      WASM_IF_ELSE(WASM_LOCAL_GET(0), WASM_LOCAL_GET(0), WASM_LOCAL_GET(0))};
  for (size_t len = 3; len < arraysize(kCode); len++) {
    ExpectFailure(sigs.i_i(), base::VectorOf(kCode, len), kAppendEnd);
    ExpectFailure(sigs.i_i(), base::VectorOf(kCode, len), kOmitEnd);
  }
}

TEST_F(FunctionBodyDecoderTest, If_type1) {
  // float|double ? 1 : 2
  static const uint8_t kCode[] = {
      WASM_IF_ELSE_I(WASM_LOCAL_GET(0), WASM_I32V_1(0), WASM_I32V_1(2))};
  ExpectValidates(sigs.i_i(), kCode);
  ExpectFailure(sigs.i_f(), kCode);
  ExpectFailure(sigs.i_d(), kCode);
}

TEST_F(FunctionBodyDecoderTest, If_type2) {
  // 1 ? float|double : 2
  static const uint8_t kCode[] = {
      WASM_IF_ELSE_I(WASM_I32V_1(1), WASM_LOCAL_GET(0), WASM_I32V_1(1))};
  ExpectValidates(sigs.i_i(), kCode);
  ExpectFailure(sigs.i_f(), kCode);
  ExpectFailure(sigs.i_d(), kCode);
}

TEST_F(FunctionBodyDecoderTest, If_type3) {
  // stmt ? 0 : 1
  static const uint8_t kCode[] = {
      WASM_IF_ELSE_I(WASM_NOP, WASM_I32V_1(0), WASM_I32V_1(1))};
  ExpectFailure(sigs.i_i(), kCode);
  ExpectFailure(sigs.i_f(), kCode);
  ExpectFailure(sigs.i_d(), kCode);
}

TEST_F(FunctionBodyDecoderTest, If_type4) {
  // 0 ? stmt : 1
  static const uint8_t kCode[] = {
      WASM_IF_ELSE_I(WASM_LOCAL_GET(0), WASM_NOP, WASM_I32V_1(1))};
  ExpectFailure(sigs.i_i(), kCode);
  ExpectFailure(sigs.i_f(), kCode);
  ExpectFailure(sigs.i_d(), kCode);
}

TEST_F(FunctionBodyDecoderTest, If_type5) {
  // 0 ? 1 : stmt
  static const uint8_t kCode[] = {
      WASM_IF_ELSE_I(WASM_ZERO, WASM_I32V_1(1), WASM_NOP)};
  ExpectFailure(sigs.i_i(), kCode);
  ExpectFailure(sigs.i_f(), kCode);
  ExpectFailure(sigs.i_d(), kCode);
}

TEST_F(FunctionBodyDecoderTest, Int64Local_param) {
  ExpectValidates(sigs.l_l(), kCodeGetLocal0);
}

TEST_F(FunctionBodyDecoderTest, Int64Locals) {
  for (uint8_t i = 1; i < 8; i++) {
    AddLocals(kWasmI64, 1);
    for (uint8_t j = 0; j < i; j++) {
      ExpectValidates(sigs.l_v(), {WASM_LOCAL_GET(j)});
    }
  }
}

TEST_F(FunctionBodyDecoderTest, Int32Binops) {
  TestBinop(kExprI32Add, sigs.i_ii());
  TestBinop(kExprI32Sub, sigs.i_ii());
  TestBinop(kExprI32Mul, sigs.i_ii());
  TestBinop(kExprI32DivS, sigs.i_ii());
  TestBinop(kExprI32DivU, sigs.i_ii());
  TestBinop(kExprI32RemS, sigs.i_ii());
  TestBinop(kExprI32RemU, sigs.i_ii());
  TestBinop(kExprI32And, sigs.i_ii());
  TestBinop(kExprI32Ior, sigs.i_ii());
  TestBinop(kExprI32Xor, sigs.i_ii());
  TestBinop(kExprI32Shl, sigs.i_ii());
  TestBinop(kExprI32ShrU, sigs.i_ii());
  TestBinop(kExprI32ShrS, sigs.i_ii());
  TestBinop(kExprI32Eq, sigs.i_ii());
  TestBinop(kExprI32LtS, sigs.i_ii());
  TestBinop(kExprI32LeS, sigs.i_ii());
  TestBinop(kExprI32LtU, sigs.i_ii());
  TestBinop(kExprI32LeU, sigs.i_ii());
}

TEST_F(FunctionBodyDecoderTest, DoubleBinops) {
  TestBinop(kExprF64Add, sigs.d_dd());
  TestBinop(kExprF64Sub, sigs.d_dd());
  TestBinop(kExprF64Mul, sigs.d_dd());
  TestBinop(kExprF64Div, sigs.d_dd());

  TestBinop(kExprF64Eq, sigs.i_dd());
  TestBinop(kExprF64Lt, sigs.i_dd());
  TestBinop(kExprF64Le, sigs.i_dd());
}

TEST_F(FunctionBodyDecoderTest, FloatBinops) {
  TestBinop(kExprF32Add, sigs.f_ff());
  TestBinop(kExprF32Sub, sigs.f_ff());
  TestBinop(kExprF32Mul, sigs.f_ff());
  TestBinop(kExprF32Div, sigs.f_ff());

  TestBinop(kExprF32Eq, sigs.i_ff());
  TestBinop(kExprF32Lt, sigs.i_ff());
  TestBinop(kExprF32Le, sigs.i_ff());
}

TEST_F(FunctionBodyDecoderTest, TypeConversions) {
  TestUnop(kExprI32SConvertF32, kWasmI32, kWasmF32);
  TestUnop(kExprI32SConvertF64, kWasmI32, kWasmF64);
  TestUnop(kExprI32UConvertF32, kWasmI32, kWasmF32);
  TestUnop(kExprI32UConvertF64, kWasmI32, kWasmF64);
  TestUnop(kExprF64SConvertI32, kWasmF64, kWasmI32);
  TestUnop(kExprF64UConvertI32, kWasmF64, kWasmI32);
  TestUnop(kExprF64ConvertF32, kWasmF64, kWasmF32);
  TestUnop(kExprF32SConvertI32, kWasmF32, kWasmI32);
  TestUnop(kExprF32UConvertI32, kWasmF32, kWasmI32);
  TestUnop(kExprF32ConvertF64, kWasmF32, kWasmF64);
}

TEST_F(FunctionBodyDecoderTest, MacrosVoid) {
  builder.AddMemory();
  ExpectValidates(sigs.v_i(), {WASM_LOCAL_SET(0, WASM_I32V_3(87348))});
  ExpectValidates(
      sigs.v_i(),
      {WASM_STORE_MEM(MachineType::Int32(), WASM_I32V_1(24), WASM_I32V_1(40))});
  ExpectValidates(sigs.v_i(), {WASM_IF(WASM_LOCAL_GET(0), WASM_NOP)});
  ExpectValidates(sigs.v_i(),
                  {WASM_IF_ELSE(WASM_LOCAL_GET(0), WASM_NOP, WASM_NOP)});
  ExpectValidates(sigs.v_v(), {WASM_NOP});
  ExpectValidates(sigs.v_v(), {B1(WASM_NOP)});
  ExpectValidates(sigs.v_v(), {WASM_LOOP(WASM_NOP)});
  ExpectValidates(sigs.v_v(), {WASM_LOOP(WASM_BR(0))});
}

TEST_F(FunctionBodyDecoderTest, MacrosContinue) {
  ExpectValidates(sigs.v_v(), {WASM_LOOP(WASM_CONTINUE(0))});
}

TEST_F(FunctionBodyDecoderTest, MacrosVariadic) {
  ExpectValidates(sigs.v_v(), {B2(WASM_NOP, WASM_NOP)});
  ExpectValidates(sigs.v_v(), {B3(WASM_NOP, WASM_NOP, WASM_NOP)});
  ExpectValidates(sigs.v_v(), {WASM_LOOP(WASM_NOP, WASM_NOP)});
  ExpectValidates(sigs.v_v(), {WASM_LOOP(WASM_NOP, WASM_NOP, WASM_NOP)});
}

TEST_F(FunctionBodyDecoderTest, MacrosNestedBlocks) {
  ExpectValidates(sigs.v_v(), {B2(WASM_NOP, B2(WASM_NOP, WASM_NOP))});
  ExpectValidates(sigs.v_v(), {B3(WASM_NOP,                   // --
                                  B2(WASM_NOP, WASM_NOP),     // --
                                  B2(WASM_NOP, WASM_NOP))});  // --
  ExpectValidates(sigs.v_v(), {B1(B1(B2(WASM_NOP, WASM_NOP)))});
}

TEST_F(FunctionBodyDecoderTest, MultipleReturn) {
  static ValueType kIntTypes5[] = {kWasmI32, kWasmI32, kWasmI32, kWasmI32,
                                   kWasmI32};
  FunctionSig sig_ii_v(2, 0, kIntTypes5);
  ExpectValidates(&sig_ii_v, {WASM_RETURN(WASM_ZERO, WASM_ONE)});
  ExpectFailure(&sig_ii_v, {WASM_RETURN(WASM_ZERO)});

  FunctionSig sig_iii_v(3, 0, kIntTypes5);
  ExpectValidates(&sig_iii_v,
                  {WASM_RETURN(WASM_ZERO, WASM_ONE, WASM_I32V_1(44))});
  ExpectFailure(&sig_iii_v, {WASM_RETURN(WASM_ZERO, WASM_ONE)});
}

TEST_F(FunctionBodyDecoderTest, MultipleReturn_fallthru) {
  static ValueType kIntTypes5[] = {kWasmI32, kWasmI32, kWasmI32, kWasmI32,
                                   kWasmI32};
  FunctionSig sig_ii_v(2, 0, kIntTypes5);

  ExpectValidates(&sig_ii_v, {WASM_ZERO, WASM_ONE});
  ExpectFailure(&sig_ii_v, {WASM_ZERO});

  FunctionSig sig_iii_v(3, 0, kIntTypes5);
  ExpectValidates(&sig_iii_v, {WASM_ZERO, WASM_ONE, WASM_I32V_1(44)});
  ExpectFailure(&sig_iii_v, {WASM_ZERO, WASM_ONE});
}

TEST_F(FunctionBodyDecoderTest, MacrosInt32) {
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_ADD(WASM_LOCAL_GET(0), WASM_I32V_1(12))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_SUB(WASM_LOCAL_GET(0), WASM_I32V_1(13))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_MUL(WASM_LOCAL_GET(0), WASM_I32V_1(14))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_DIVS(WASM_LOCAL_GET(0), WASM_I32V_1(15))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_DIVU(WASM_LOCAL_GET(0), WASM_I32V_1(16))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_REMS(WASM_LOCAL_GET(0), WASM_I32V_1(17))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_REMU(WASM_LOCAL_GET(0), WASM_I32V_1(18))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_AND(WASM_LOCAL_GET(0), WASM_I32V_1(19))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_IOR(WASM_LOCAL_GET(0), WASM_I32V_1(20))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_XOR(WASM_LOCAL_GET(0), WASM_I32V_1(21))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_SHL(WASM_LOCAL_GET(0), WASM_I32V_1(22))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_SHR(WASM_LOCAL_GET(0), WASM_I32V_1(23))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_SAR(WASM_LOCAL_GET(0), WASM_I32V_1(24))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_ROR(WASM_LOCAL_GET(0), WASM_I32V_1(24))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_ROL(WASM_LOCAL_GET(0), WASM_I32V_1(24))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_EQ(WASM_LOCAL_GET(0), WASM_I32V_1(25))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_NE(WASM_LOCAL_GET(0), WASM_I32V_1(25))});

  ExpectValidates(sigs.i_i(),
                  {WASM_I32_LTS(WASM_LOCAL_GET(0), WASM_I32V_1(26))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_LES(WASM_LOCAL_GET(0), WASM_I32V_1(27))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_LTU(WASM_LOCAL_GET(0), WASM_I32V_1(28))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_LEU(WASM_LOCAL_GET(0), WASM_I32V_1(29))});

  ExpectValidates(sigs.i_i(),
                  {WASM_I32_GTS(WASM_LOCAL_GET(0), WASM_I32V_1(26))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_GES(WASM_LOCAL_GET(0), WASM_I32V_1(27))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_GTU(WASM_LOCAL_GET(0), WASM_I32V_1(28))});
  ExpectValidates(sigs.i_i(),
                  {WASM_I32_GEU(WASM_LOCAL_GET(0), WASM_I32V_1(29))});
}

TEST_F(FunctionBodyDecoderTest, MacrosInt64) {
  ExpectValidates(sigs.l_ll(),
                  {WASM_I64_ADD(WASM_LOCAL_GET(0), WASM_I64V_1(12))});
  ExpectValidates(sigs.l_ll(),
                  {WASM_I64_SUB(WASM_LOCAL_GET(0), WASM_I64V_1(13))});
  ExpectValidates(sigs.l_ll(),
                  {WASM_I64_MUL(WASM_LOCAL_GET(0), WASM_I64V_1(14))});
  ExpectValidates(sigs.l_ll(),
                  {WASM_I64_DIVS(WASM_LOCAL_GET(0), WASM_I64V_1(15))});
  ExpectValidates(sigs.l_ll(),
                  {WASM_I64_DIVU(WASM_LOCAL_GET(0), WASM_I64V_1(16))});
  ExpectValidates(sigs.l_ll(),
                  {WASM_I64_REMS(WASM_LOCAL_GET(0), WASM_I64V_1(17))});
  ExpectValidates(sigs.l_ll(),
                  {WASM_I64_REMU(WASM_LOCAL_GET(0), WASM_I64V_1(18))});
  ExpectValidates(sigs.l_ll(),
                  {WASM_I64_AND(WASM_LOCAL_GET(0), WASM_I64V_1(19))});
  ExpectValidates(sigs.l_ll(),
                  {WASM_I64_IOR(WASM_LOCAL_GET(0), WASM_I64V_1(20))});
  ExpectValidates(sigs.l_ll(),
                  {WASM_I64_XOR(WASM_LOCAL_GET(0), WASM_I64V_1(21))});

  ExpectValidates(sigs.l_ll(),
                  {WASM_I64_SHL(WASM_LOCAL_GET(0), WASM_I64V_1(22))});
  ExpectValidates(sigs.l_ll(),
                  {WASM_I64_SHR(WASM_LOCAL_GET(0), WASM_I64V_1(23))});
  ExpectValidates(sigs.l_ll(),
                  {WASM_I64_SAR(WASM_LOCAL_GET(0), WASM_I64V_1(24))});
  ExpectValidates(sigs.l_ll(),
                  {WASM_I64_ROR(WASM_LOCAL_GET(0), WASM_I64V_1(24))});
  ExpectValidates(sigs.l_ll(),
                  {WASM_I64_ROL(WASM_LOCAL_GET(0), WASM_I64V_1(24))});

  ExpectValidates(sigs.i_ll(),
                  {WASM_I64_LTS(WASM_LOCAL_GET(0), WASM_I64V_1(26))});
  ExpectValidates(sigs.i_ll(),
                  {WASM_I64_LES(WASM_LOCAL_GET(0), WASM_I64V_1(27))});
  ExpectValidates(sigs.i_ll(),
                  {WASM_I64_LTU(WASM_LOCAL_GET(0), WASM_I64V_1(28))});
  ExpectValidates(sigs.i_ll(),
                  {WASM_I64_LEU(WASM_LOCAL_GET(0), WASM_I64V_1(29))});

  ExpectValidates(sigs.i_ll(),
                  {WASM_I64_GTS(WASM_LOCAL_GET(0), WASM_I64V_1(26))});
  ExpectValidates(sigs.i_ll(),
                  {WASM_I64_GES(WASM_LOCAL_GET(0), WASM_I64V_1(27))});
  ExpectValidates(sigs.i_ll(),
                  {WASM_I64_GTU(WASM_LOCAL_GET(0), WASM_I64V_1(28))});
  ExpectValidates(sigs.i_ll(),
                  {WASM_I64_GEU(WASM_LOCAL_GET(0), WASM_I64V_1(29))});

  ExpectValidates(sigs.i_ll(),
                  {WASM_I64_EQ(WASM_LOCAL_GET(0), WASM_I64V_1(25))});
  ExpectValidates(sigs.i_ll(),
                  {WASM_I64_NE(WASM_LOCAL_GET(0), WASM_I64V_1(25))});
}

TEST_F(FunctionBodyDecoderTest, AllSimpleExpressions) {
// Test all simple expressions which are described by a signature.
#define DECODE_TEST(name, opcode, sig, ...)                       \
  {                                                               \
    const FunctionSig* sig = WasmOpcodes::Signature(kExpr##name); \
    if (sig->parameter_count() == 1) {                            \
      TestUnop(kExpr##name, sig);                                 \
    } else {                                                      \
      TestBinop(kExpr##name, sig);                                \
    }                                                             \
  }

  FOREACH_SIMPLE_OPCODE(DECODE_TEST);

#undef DECODE_TEST
}

TEST_F(FunctionBodyDecoderTest, MemorySize) {
  builder.AddMemory();
  uint8_t code[] = {kExprMemorySize, 0};
  ExpectValidates(sigs.i_i(), code);
  ExpectFailure(sigs.f_ff(), code);
}

TEST_F(FunctionBodyDecoderTest, LoadMemOffset) {
  builder.AddMemory();
  for (int offset = 0; offset < 128; offset += 7) {
    uint8_t code[] = {kExprI32Const, 0, kExprI32LoadMem, ZERO_ALIGNMENT,
                      static_cast<uint8_t>(offset)};
    ExpectValidates(sigs.i_i(), code);
  }
}

TEST_F(FunctionBodyDecoderTest, LoadMemAlignment) {
  builder.AddMemory();
  struct {
    WasmOpcode instruction;
    uint32_t maximum_aligment;
  } values[] = {
      {kExprI32LoadMem8U, 0},   // --
      {kExprI32LoadMem8S, 0},   // --
      {kExprI32LoadMem16U, 1},  // --
      {kExprI32LoadMem16S, 1},  // --
      {kExprI64LoadMem8U, 0},   // --
      {kExprI64LoadMem8S, 0},   // --
      {kExprI64LoadMem16U, 1},  // --
      {kExprI64LoadMem16S, 1},  // --
      {kExprI64LoadMem32U, 2},  // --
      {kExprI64LoadMem32S, 2},  // --
      {kExprI32LoadMem, 2},     // --
      {kExprI64LoadMem, 3},     // --
      {kExprF32LoadMem, 2},     // --
      {kExprF64LoadMem, 3},     // --
  };

  for (size_t i = 0; i < arraysize(values); i++) {
    for (uint8_t alignment = 0; alignment <= 4; alignment++) {
      uint8_t code[] = {WASM_ZERO, static_cast<uint8_t>(values[i].instruction),
                        alignment, ZERO_OFFSET, WASM_DROP};
      Validate(alignment <= values[i].maximum_aligment, sigs.v_i(), code);
    }
  }
}

TEST_F(FunctionBodyDecoderTest, StoreMemOffset) {
  builder.AddMemory();
  for (uint8_t offset = 0; offset < 128; offset += 7) {
    uint8_t code[] = {WASM_STORE_MEM_OFFSET(MachineType::Int32(), offset,
                                            WASM_ZERO, WASM_ZERO)};
    ExpectValidates(sigs.v_i(), code);
  }
}

TEST_F(FunctionBodyDecoderTest, StoreMemOffset_void) {
  builder.AddMemory();
  ExpectFailure(sigs.i_i(), {WASM_STORE_MEM_OFFSET(MachineType::Int32(), 0,
                                                   WASM_ZERO, WASM_ZERO)});
}

TEST_F(FunctionBodyDecoderTest, LoadMemOffset_varint) {
  builder.AddMemory();
  ExpectValidates(sigs.i_i(),
                  {WASM_ZERO, kExprI32LoadMem, ZERO_ALIGNMENT, U32V_1(0x45)});
  ExpectValidates(sigs.i_i(),
                  {WASM_ZERO, kExprI32LoadMem, ZERO_ALIGNMENT, U32V_2(0x3999)});
  ExpectValidates(sigs.i_i(), {WASM_ZERO, kExprI32LoadMem, ZERO_ALIGNMENT,
                               U32V_3(0x344445)});
  ExpectValidates(sigs.i_i(), {WASM_ZERO, kExprI32LoadMem, ZERO_ALIGNMENT,
                               U32V_4(0x36666667)});
}

TEST_F(FunctionBodyDecoderTest, StoreMemOffset_varint) {
  builder.AddMemory();
  ExpectValidates(sigs.v_i(), {WASM_ZERO, WASM_ZERO, kExprI32StoreMem,
                               ZERO_ALIGNMENT, U32V_1(0x33)});
  ExpectValidates(sigs.v_i(), {WASM_ZERO, WASM_ZERO, kExprI32StoreMem,
                               ZERO_ALIGNMENT, U32V_2(0x1111)});
  ExpectValidates(sigs.v_i(), {WASM_ZERO, WASM_ZERO, kExprI32StoreMem,
                               ZERO_ALIGNMENT, U32V_3(0x222222)});
  ExpectValidates(sigs.v_i(), {WASM_ZERO, WASM_ZERO, kExprI32StoreMem,
                               ZERO_ALIGNMENT, U32V_4(0x44444444)});
}

TEST_F(FunctionBodyDecoderTest, AllLoadMemCombinations) {
  builder.AddMemory();
  for (size_t i = 0; i < arraysize(kValueTypes); i++) {
    ValueType local_type = kValueTypes[i];
    for (size_t j = 0; j < arraysize(machineTypes); j++) {
      MachineType mem_type = machineTypes[j];
      uint8_t code[] = {WASM_LOAD_MEM(mem_type, WASM_ZERO)};
      FunctionSig sig(1, 0, &local_type);
      Validate(local_type == ValueType::For(mem_type), &sig, code);
    }
  }
}

TEST_F(FunctionBodyDecoderTest, AllStoreMemCombinations) {
  builder.AddMemory();
  for (size_t i = 0; i < arraysize(kValueTypes); i++) {
    ValueType local_type = kValueTypes[i];
    for (size_t j = 0; j < arraysize(machineTypes); j++) {
      MachineType mem_type = machineTypes[j];
      uint8_t code[] = {WASM_STORE_MEM(mem_type, WASM_ZERO, WASM_LOCAL_GET(0))};
      FunctionSig sig(0, 1, &local_type);
      Validate(local_type == ValueType::For(mem_type), &sig, code);
    }
  }
}

TEST_F(FunctionBodyDecoderTest, SimpleCalls) {
  const FunctionSig* sig = sigs.i_i();

  builder.AddFunction(sigs.i_v());
  builder.AddFunction(sigs.i_i());
  builder.AddFunction(sigs.i_ii());

  ExpectValidates(sig, {WASM_CALL_FUNCTION0(0)});
  ExpectValidates(sig, {WASM_CALL_FUNCTION(1, WASM_I32V_1(27))});
  ExpectValidates(sig,
                  {WASM_CALL_FUNCTION(2, WASM_I32V_1(37), WASM_I32V_2(77))});
}

TEST_F(FunctionBodyDecoderTest, CallsWithTooFewArguments) {
  const FunctionSig* sig = sigs.i_i();

  builder.AddFunction(sigs.i_i());
  builder.AddFunction(sigs.i_ii());
  builder.AddFunction(sigs.f_ff());

  ExpectFailure(sig, {WASM_CALL_FUNCTION0(0)});
  ExpectFailure(sig, {WASM_CALL_FUNCTION(1, WASM_ZERO)});
  ExpectFailure(sig, {WASM_CALL_FUNCTION(2, WASM_LOCAL_GET(0))});
}

TEST_F(FunctionBodyDecoderTest, CallsWithMismatchedSigs2) {
  const FunctionSig* sig = sigs.i_i();

  builder.AddFunction(sigs.i_i());

  ExpectFailure(sig, {WASM_CALL_FUNCTION(0, WASM_I64V_1(17))});
  ExpectFailure(sig, {WASM_CALL_FUNCTION(0, WASM_F32(17.1))});
  ExpectFailure(sig, {WASM_CALL_FUNCTION(0, WASM_F64(17.1))});
}

TEST_F(FunctionBodyDecoderTest, CallsWithMismatchedSigs3) {
  const FunctionSig* sig = sigs.i_i();

  builder.AddFunction(sigs.i_f());

  ExpectFailure(sig, {WASM_CALL_FUNCTION(0, WASM_I32V_1(17))});
  ExpectFailure(sig, {WASM_CALL_FUNCTION(0, WASM_I64V_1(27))});
  ExpectFailure(sig, {WASM_CALL_FUNCTION(0, WASM_F64(37.2))});

  builder.AddFunction(sigs.i_d());

  ExpectFailure(sig, {WASM_CALL_FUNCTION(1, WASM_I32V_1(16))});
  ExpectFailure(sig, {WASM_CALL_FUNCTION(1, WASM_I64V_1(16))});
  ExpectFailure(sig, {WASM_CALL_FUNCTION(1, WASM_F32(17.6))});
}

TEST_F(FunctionBodyDecoderTest, SimpleReturnCalls) {
  const FunctionSig* sig = sigs.i_i();

  builder.AddFunction(sigs.i_v());
  builder.AddFunction(sigs.i_i());
  builder.AddFunction(sigs.i_ii());

  ExpectValidates(sig, {WASM_RETURN_CALL_FUNCTION0(0)});
  ExpectValidates(sig, {WASM_RETURN_CALL_FUNCTION(1, WASM_I32V_1(27))});
  ExpectValidates(
      sig, {WASM_RETURN_CALL_FUNCTION(2, WASM_I32V_1(37), WASM_I32V_2(77))});
}

TEST_F(FunctionBodyDecoderTest, ReturnCallsWithTooFewArguments) {
  const FunctionSig* sig = sigs.i_i();

  builder.AddFunction(sigs.i_i());
  builder.AddFunction(sigs.i_ii());
  builder.AddFunction(sigs.f_ff());

  ExpectFailure(sig, {WASM_RETURN_CALL_FUNCTION0(0)});
  ExpectFailure(sig, {WASM_RETURN_CALL_FUNCTION(1, WASM_ZERO)});
  ExpectFailure(sig, {WASM_RETURN_CALL_FUNCTION(2, WASM_LOCAL_GET(0))});
}

TEST_F(FunctionBodyDecoderTest, ReturnCallWithSubtype) {
  auto sig = MakeSig::Returns(kWasmAnyRef);
  auto callee_sig = MakeSig::Returns(kWasmAnyRef.AsNonNull());
  builder.AddFunction(&callee_sig);

  ExpectVa
```