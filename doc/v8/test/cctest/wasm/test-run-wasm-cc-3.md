Response:
Let's break down the thought process for analyzing this code snippet.

1. **Understand the Goal:** The core request is to understand the functionality of the provided C++ code snippet, which is part of the V8 JavaScript engine's testing framework for WebAssembly. Specifically, the goal is to describe what it does, relate it to JavaScript (if applicable), identify potential errors, and summarize its overall purpose within the context of the larger file.

2. **Identify the Core Structure:** The code consists primarily of `WASM_EXEC_TEST` macros. This is the first key observation. Knowing this is a testing framework is crucial. Each `WASM_EXEC_TEST` likely defines an individual test case.

3. **Analyze Individual Test Cases (Iterative Approach):**  Start examining the tests one by one. Look for patterns and common elements.

    * **`MultiReturnSelect_i64` and `MultiReturnSelect_f64`:** These seem to test a feature related to functions returning multiple values. The names suggest `select` operation on these multi-return values. The `RunMultiReturnSelect` function is a helper, and the arrays define input values. Note the `#ifndef V8_TARGET_BIG_ENDIAN` suggests endianness might be a factor.

    * **`ExprBlock2a` through `ExprBlock_ManualSwitch_brif`:** These test different ways of using `WASM_BLOCK_I` (blocks that return a value) and conditional branching (`WASM_IF`, `WASM_BRV`, `WASM_BRV_IFD`). The `CHECK_EQ` calls confirm the expected return values based on the input. The `ExprBlock_ManualSwitch` tests a series of conditional branches mimicking a switch statement.

    * **`If_nested`:**  Straightforward test of nested `if-else` statements.

    * **`ExprBlock_if` and `ExprBlock_nested_ifs`:** More examples of blocks and conditional execution, this time with `if-else` and branching out of the block.

    * **`SimpleCallIndirect` through `CallIndirect_canonical`:** These test indirect function calls (`WASM_CALL_INDIRECT`). They involve setting up function signatures, function tables, and then calling functions indirectly through an index. Notice the `CHECK_TRAP` for cases where the index is out of bounds or the signature doesn't match.

    * **`Regress_PushReturns`, `Regress_EnsureArguments`, `Regress_PushControl`:** Tests of specific regression scenarios. The names hint at the issues being addressed. These tests often have more complex function signatures or control flow.

    * **Floating-Point Tests (`F32Floor` to `F64MaxSameValue`):** These test various floating-point operations (`floor`, `ceil`, `trunc`, `nearbyint`, `min`, `max`). The `FOR_FLOAT32_INPUTS` and `FOR_FLOAT64_INPUTS` macros indicate a systematic testing of various floating-point values. Note the platform-specific workaround for AIX.

    * **Type Conversion Tests (`I32SConvertF32` to `I32UConvertSatF64`):** Tests the conversion between floating-point and integer types, including signed and unsigned conversions, and the saturating versions. The `is_inbounds` check and `CHECK_TRAP32` highlight potential overflow or invalid conversion scenarios.

    * **Bit Manipulation (`F64CopySign`, `F32CopySign`):** Tests the `copysign` function.

    * **`CompileCallIndirectMany`:** This tests the compilation of indirect calls with a large number of parameters, likely to ensure register allocation and code generation handle this case correctly.

    * **More Control Flow and Edge Cases (`Int32RemS_dead`, `BrToLoopWithValue`, etc.):** Tests various control flow constructs like loops (`WASM_LOOP_I`), branches (`WASM_BR`, `WASM_BR_IF`), and unreachable code (`WASM_UNREACHABLE`). These often check for correct stack manipulation and handling of edge cases.

    * **`BinOpOnDifferentRegisters` (Template):** This is a more complex test case using a template. It aims to verify that binary operations work correctly when the operands are in different registers. It initializes local variables, performs the operation, and then checks if other local variables were corrupted. This is a good example of testing compiler optimizations and register allocation.

4. **Identify Common Themes and Functionality:** After analyzing several test cases, patterns emerge:

    * **Testing WebAssembly Opcode Semantics:** The code extensively uses `WASM_*` macros which directly correspond to WebAssembly opcodes. The tests verify the correct behavior of these opcodes.
    * **Control Flow Testing:** A significant portion tests branching, loops, blocks, and conditional execution.
    * **Data Type Operations:** Tests cover integer and floating-point arithmetic, conversions, and bit manipulation.
    * **Indirect Calls:** A dedicated section tests the functionality of indirect function calls.
    * **Error Handling (Trapping):**  The `CHECK_TRAP` and `CHECK_TRAP32` macros demonstrate testing for expected runtime errors.
    * **Register Allocation (Implicit):** The `BinOpOnDifferentRegisters` test specifically targets scenarios where operands might be in different registers.

5. **Address Specific Questions from the Prompt:**

    * **Functionality:** List the observed functionalities (as done above).
    * **`.tq` Extension:**  The code uses `.cc`, so it's not Torque.
    * **JavaScript Relationship:**  While this is C++ testing *WebAssembly*, which is often used in conjunction with JavaScript, the *direct* link in this code is the testing of the WebAssembly implementation *within* V8 (the JavaScript engine). Examples would involve how JavaScript code can compile to and execute WebAssembly.
    * **Code Logic Inference:** Provide examples of input and expected output for some of the simpler tests (like `ExprBlock2a`).
    * **Common Programming Errors:** Think about the kinds of errors developers make when working with WebAssembly or similar low-level concepts (e.g., incorrect type conversions, out-of-bounds access, stack underflow/overflow, incorrect function signatures for indirect calls).
    * **Summary:**  Synthesize the key functionalities into a concise summary.

6. **Structure the Output:** Organize the findings into clear sections addressing each part of the prompt. Use bullet points and code examples where appropriate.

7. **Refine and Review:**  Read through the generated explanation to ensure clarity, accuracy, and completeness. Double-check that all aspects of the prompt have been addressed. For instance, initially, I might focus heavily on the opcodes, but then remember the prompt asked about JavaScript, so I'd add a section connecting WebAssembly to JavaScript within the V8 context.

This iterative process of examining individual tests, identifying patterns, and connecting them to the broader purpose of the code allows for a comprehensive understanding of the given snippet.这是提供的 `v8/test/cctest/wasm/test-run-wasm.cc` 源代码的第 4 部分，其主要功能是 **测试 WebAssembly 指令的执行和相关特性**。 它通过编写不同的 WebAssembly 代码片段，并在 V8 引擎中执行它们，然后断言执行结果是否符合预期来验证 V8 的 WebAssembly 实现的正确性。

**功能列表:**

* **测试多返回值选择 (MultiReturnSelect):**  测试当 WebAssembly 函数返回多个值时，如何正确地选择和使用这些值。它针对 `int64_t` 和 `double` 两种类型进行了测试。
* **测试表达式块 (ExprBlock):**  测试 WebAssembly 中的 `block` 结构，特别是当 `block` 表达式返回一个值时，以及结合 `if` 和 `br_if` 指令时的行为。包括：
    * 简单的 `if` 语句在 `block` 中的使用。
    * 使用 `br_if` 从 `block` 中带值跳出。
    * 使用多个嵌套的 `if` 语句模拟 `switch` 结构。
    * 使用 `brv_ifd` (branch if default) 指令。
* **测试嵌套的 `if` 语句 (If_nested):**  验证嵌套 `if-else` 语句的执行逻辑。
* **测试带返回值的 `block` 结合 `if-else` (ExprBlock_if, ExprBlock_nested_ifs):** 测试 `if-else` 语句在带返回值的 `block` 中使用，并测试嵌套的情况。
* **测试间接调用 (SimpleCallIndirect, MultipleCallIndirect, CallIndirect_EmptyTable, CallIndirect_canonical):**  验证 WebAssembly 的间接函数调用机制，包括：
    * 通过函数表索引调用函数。
    * 测试调用时参数和返回值的处理。
    * 测试空函数表的情况。
    * 测试使用不同的签名进行间接调用。
* **回归测试 (Regress_PushReturns, Regress_EnsureArguments, Regress_PushControl):**  包含了一些回归测试，用于验证之前修复的 Bug 是否再次出现。这些测试通常针对特定的代码生成或执行路径。
* **测试浮点数运算 (F32Floor, F32Ceil, F32Trunc, F32NearestInt, F64Floor, F64Ceil, F64Trunc, F64NearestInt, F32Min, F32Max, F64Min, F64Max):**  测试各种单精度 (`float`) 和双精度 (`double`) 浮点数运算指令，例如取整、最小值、最大值等。
* **测试浮点数到整数的转换 (I32SConvertF32, I32SConvertSatF32, I32SConvertF64, I32SConvertSatF64, I32UConvertF32, I32UConvertSatF32, I32UConvertF64, I32UConvertSatF64):** 测试将浮点数转换为有符号和无符号 32 位整数的指令，包括饱和转换，即当转换结果超出整数范围时，会截断到最大或最小值。
* **测试浮点数符号复制 (F64CopySign, F32CopySign):** 测试将一个浮点数的符号复制到另一个浮点数的指令。
* **编译大量参数的间接调用 (CompileCallIndirectMany):**  这是一个编译时测试，确保当间接调用具有大量参数时，编译器能够正确处理。
* **测试整数求余运算 (Int32RemS_dead):** 测试有符号整数的求余运算，并包含了一些边缘情况，例如除数为零的情况。
* **测试带值的跳转到循环 (BrToLoopWithValue):** 验证 `br` 指令跳转到循环并携带值的行为。
* **测试不带值的跳转到循环 (BrToLoopWithoutValue):** 验证 `br` 指令跳转到循环但不携带值的行为。
* **测试带值的循环 (LoopsWithValues):** 测试循环结构返回一个值的行为。
* **测试 `unreachable` 指令后的栈状态 (InvalidStackAfterUnreachable):** 确保在执行 `unreachable` 指令后，栈状态是无效的，后续操作会触发错误。
* **测试 `br` 指令后的栈状态 (InvalidStackAfterBr):** 确保在执行 `br` 指令后，栈状态是正确的。
* **测试 `return` 指令后的栈状态 (InvalidStackAfterReturn):** 确保在执行 `return` 指令后，栈状态是正确的。
* **测试跳转到不可达代码 (BranchOverUnreachableCode, BranchOverUnreachableCodeInLoop0, BranchOverUnreachableCodeInLoop1, BranchOverUnreachableCodeInLoop2):** 测试在控制流跳转后遇到不可达代码的情况，确保执行不会进入这些代码。
* **测试不可达代码中的块和 `if` 语句 (BlockInsideUnreachable, IfInsideUnreachable):**  测试在 `unreachable` 代码块中包含 `block` 和 `if` 语句的情况。
* **测试空函数表的间接调用 (IndirectNull, IndirectNullTyped):** 测试当间接调用的索引指向空条目或 `ref.null` 时会触发陷阱。
* **测试在不同寄存器上执行二元运算 (BinOpOnDifferentRegisters):**  这是一个模板测试函数，用于测试各种二元运算指令（例如加法、减法、乘法、移位、除法、求余等）在操作数位于不同寄存器时的正确性。这对于确保代码生成器的正确性至关重要。

**如果 `v8/test/cctest/wasm/test-run-wasm.cc` 以 `.tq` 结尾:**

那么它将是一个 **V8 Torque 源代码**。Torque 是 V8 用来定义内置函数和运行时函数的领域特定语言。 如果是 `.tq` 文件，它将包含使用 Torque 语法编写的函数定义，这些函数会在 V8 引擎内部执行。 然而，这个文件是 `.cc`，所以它是 C++ 源代码。

**与 JavaScript 的关系:**

WebAssembly 旨在与 JavaScript 一起运行在 Web 浏览器和其他环境中。这个 C++ 文件测试的是 V8 引擎中 WebAssembly 的实现。当 JavaScript 代码加载并执行 WebAssembly 模块时，V8 引擎会解析并运行这些 WebAssembly 代码。

**JavaScript 示例:**

```javascript
// 假设有一个简单的 WebAssembly 模块，将两个整数相加
// (这只是一个概念示例，实际的 WASM 模块需要编译生成)
const wasmCode = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // WASM 标头
  0x01, 0x07, 0x01, 0x00, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f, // 类型定义: (i32, i32) -> i32
  0x03, 0x02, 0x01, 0x00, // 函数定义: 引用类型索引 0
  0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b, // 函数体: local.get 0, local.get 1, i32.add, end
  0x07, 0x08, 0x01, 0x04, 0x61, 0x64, 0x64, 0x00, 0x00, // 导出 "add" 函数
]);

WebAssembly.instantiate(wasmCode)
  .then(module => {
    const add = module.instance.exports.add;
    const result = add(5, 10);
    console.log(result); // 输出 15
  });
```

在这个 JavaScript 例子中，`wasmCode` 代表一个简单的 WebAssembly 模块。`WebAssembly.instantiate` 函数会编译和实例化这个模块。模块的导出项（在这个例子中是 `add` 函数）可以被 JavaScript 调用。`v8/test/cctest/wasm/test-run-wasm.cc` 中的测试就是为了确保 V8 能够正确地执行像 `i32.add` 这样的 WebAssembly 指令，就像上面例子中的那样。

**代码逻辑推理示例:**

**测试用例:** `ExprBlock2a`

**假设输入:**  `execution_tier` (表示执行层级，例如解释器或编译器)

**Wasm 代码:**
```wasm
{WASM_BLOCK_I(WASM_IF(WASM_LOCAL_GET(0), WASM_BRV(1, WASM_I32V_1(1))),
              WASM_I32V_1(1))}
```

**逻辑分析:**

1. 创建一个带返回值的 `block`。
2. 在 `block` 内部，有一个 `if` 语句。
3. `if` 语句的条件是 `WASM_LOCAL_GET(0)`，即获取本地变量 0 的值。
4. 如果本地变量 0 的值为真（非零），则执行 `WASM_BRV(1, WASM_I32V_1(1))`。这表示跳出外层 `block`，并带回值 `1`。
5. 如果本地变量 0 的值为假（零），则 `if` 语句不执行跳出，程序会继续执行 `block` 中的下一个语句 `WASM_I32V_1(1)`，这将作为 `block` 的返回值。

**预期输出:**

* `CHECK_EQ(1, r.Call(0));`  当输入为 `0` 时，`if` 条件为假，`block` 返回 `1`。
* `CHECK_EQ(1, r.Call(1));`  当输入为 `1` 时，`if` 条件为真，跳出 `block` 并返回 `1`。

**用户常见的编程错误示例:**

* **类型不匹配的间接调用:** 在使用 `WASM_CALL_INDIRECT` 时，如果提供的函数表索引超出了范围，或者调用的函数签名与函数表中该索引处的函数签名不匹配，就会导致运行时错误 (trap)。

```c++
// 错误示例：尝试使用错误的签名调用间接函数
WASM_EXEC_TEST(CallIndirectTypeError) {
  TestSignatures sigs;
  WasmRunner<int32_t, int32_t> r(execution_tier);

  WasmFunctionCompiler& t1 = r.NewFunction(sigs.i_v()); // 函数签名 int -> void
  t1.Build({});
  t1.SetSigIndex(ModuleTypeIndex{1});

  // 签名表，包含一个 i->v 的签名
  r.builder().AddSignature(sigs.i_i()); // 签名 0: int -> int
  r.builder().AddSignature(sigs.i_v()); // 签名 1: int -> void

  // 函数表，索引 0 指向 t1 (i->v)
  uint16_t indirect_function_table[] = {static_cast<uint16_t>(t1.function_index())};
  r.builder().AddIndirectFunctionTable(indirect_function_table, arraysize(indirect_function_table));

  // 尝试使用 i->i 的签名 (索引 0) 调用函数表中的函数
  r.Build({WASM_CALL_INDIRECT(0, WASM_I32V_1(10), WASM_I32V_1(0))});

  // 这将导致陷阱，因为函数表中的函数签名是 i->v，而调用时使用了 i->i 的签名
  CHECK_TRAP(r.Call(0));
}
```

在这个例子中，`t1` 函数的签名是接受一个 `int` 参数，没有返回值 (`i_v`)。但是，`WASM_CALL_INDIRECT` 指令尝试使用一个接受一个 `int` 参数并返回一个 `int` 值的签名 (签名索引 0)。这会导致类型不匹配，从而在运行时触发陷阱。

**归纳一下它的功能:**

这部分 `v8/test/cctest/wasm/test-run-wasm.cc` 源代码主要负责 **对 V8 引擎的 WebAssembly 执行能力进行细致的功能测试**。它涵盖了 WebAssembly 的核心指令、控制流结构、数据类型操作以及与其他 WebAssembly 特性的交互（例如间接调用）。通过大量的独立测试用例，它旨在验证 V8 引擎能够正确地解释和执行各种合法的 WebAssembly 代码，并能够正确地处理错误情况。 这些测试是确保 V8 引擎作为 WebAssembly 运行时环境的健壮性和合规性的关键组成部分。

### 提示词
```
这是目录为v8/test/cctest/wasm/test-run-wasm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/test-run-wasm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
4_t inputs[] = {33333338888, 44444446666, -555555553333,
                                   -77777771111};
  RunMultiReturnSelect<int64_t>(execution_tier, inputs);
#endif
}

WASM_EXEC_TEST(MultiReturnSelect_f64) {
  static const double inputs[] = {3.333333, 44444.44, -55.555555, -7777.777};
  RunMultiReturnSelect<double>(execution_tier, inputs);
}

WASM_EXEC_TEST(ExprBlock2a) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_BLOCK_I(WASM_IF(WASM_LOCAL_GET(0), WASM_BRV(1, WASM_I32V_1(1))),
                        WASM_I32V_1(1))});
  CHECK_EQ(1, r.Call(0));
  CHECK_EQ(1, r.Call(1));
}

WASM_EXEC_TEST(ExprBlock2b) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_BLOCK_I(WASM_IF(WASM_LOCAL_GET(0), WASM_BRV(1, WASM_I32V_1(1))),
                        WASM_I32V_1(2))});
  CHECK_EQ(2, r.Call(0));
  CHECK_EQ(1, r.Call(1));
}

WASM_EXEC_TEST(ExprBlock2c) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_BLOCK_I(WASM_BRV_IFD(0, WASM_I32V_1(1), WASM_LOCAL_GET(0)),
                        WASM_I32V_1(1))});
  CHECK_EQ(1, r.Call(0));
  CHECK_EQ(1, r.Call(1));
}

WASM_EXEC_TEST(ExprBlock2d) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_BLOCK_I(WASM_BRV_IFD(0, WASM_I32V_1(1), WASM_LOCAL_GET(0)),
                        WASM_I32V_1(2))});
  CHECK_EQ(2, r.Call(0));
  CHECK_EQ(1, r.Call(1));
}

WASM_EXEC_TEST(ExprBlock_ManualSwitch) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_BLOCK_I(WASM_IF(WASM_I32_EQ(WASM_LOCAL_GET(0), WASM_I32V_1(1)),
                                WASM_BRV(1, WASM_I32V_1(11))),
                        WASM_IF(WASM_I32_EQ(WASM_LOCAL_GET(0), WASM_I32V_1(2)),
                                WASM_BRV(1, WASM_I32V_1(12))),
                        WASM_IF(WASM_I32_EQ(WASM_LOCAL_GET(0), WASM_I32V_1(3)),
                                WASM_BRV(1, WASM_I32V_1(13))),
                        WASM_IF(WASM_I32_EQ(WASM_LOCAL_GET(0), WASM_I32V_1(4)),
                                WASM_BRV(1, WASM_I32V_1(14))),
                        WASM_IF(WASM_I32_EQ(WASM_LOCAL_GET(0), WASM_I32V_1(5)),
                                WASM_BRV(1, WASM_I32V_1(15))),
                        WASM_I32V_2(99))});
  CHECK_EQ(99, r.Call(0));
  CHECK_EQ(11, r.Call(1));
  CHECK_EQ(12, r.Call(2));
  CHECK_EQ(13, r.Call(3));
  CHECK_EQ(14, r.Call(4));
  CHECK_EQ(15, r.Call(5));
  CHECK_EQ(99, r.Call(6));
}

WASM_EXEC_TEST(ExprBlock_ManualSwitch_brif) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_BLOCK_I(
      WASM_BRV_IFD(0, WASM_I32V_1(11),
                   WASM_I32_EQ(WASM_LOCAL_GET(0), WASM_I32V_1(1))),
      WASM_BRV_IFD(0, WASM_I32V_1(12),
                   WASM_I32_EQ(WASM_LOCAL_GET(0), WASM_I32V_1(2))),
      WASM_BRV_IFD(0, WASM_I32V_1(13),
                   WASM_I32_EQ(WASM_LOCAL_GET(0), WASM_I32V_1(3))),
      WASM_BRV_IFD(0, WASM_I32V_1(14),
                   WASM_I32_EQ(WASM_LOCAL_GET(0), WASM_I32V_1(4))),
      WASM_BRV_IFD(0, WASM_I32V_1(15),
                   WASM_I32_EQ(WASM_LOCAL_GET(0), WASM_I32V_1(5))),
      WASM_I32V_2(99))});
  CHECK_EQ(99, r.Call(0));
  CHECK_EQ(11, r.Call(1));
  CHECK_EQ(12, r.Call(2));
  CHECK_EQ(13, r.Call(3));
  CHECK_EQ(14, r.Call(4));
  CHECK_EQ(15, r.Call(5));
  CHECK_EQ(99, r.Call(6));
}

WASM_EXEC_TEST(If_nested) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);

  r.Build({WASM_IF_ELSE_I(
      WASM_LOCAL_GET(0),
      WASM_IF_ELSE_I(WASM_LOCAL_GET(1), WASM_I32V_1(11), WASM_I32V_1(12)),
      WASM_IF_ELSE_I(WASM_LOCAL_GET(1), WASM_I32V_1(13), WASM_I32V_1(14)))});

  CHECK_EQ(11, r.Call(1, 1));
  CHECK_EQ(12, r.Call(1, 0));
  CHECK_EQ(13, r.Call(0, 1));
  CHECK_EQ(14, r.Call(0, 0));
}

WASM_EXEC_TEST(ExprBlock_if) {
  WasmRunner<int32_t, int32_t> r(execution_tier);

  r.Build({WASM_BLOCK_I(WASM_IF_ELSE_I(WASM_LOCAL_GET(0),
                                       WASM_BRV(0, WASM_I32V_1(11)),
                                       WASM_BRV(1, WASM_I32V_1(14))))});

  CHECK_EQ(11, r.Call(1));
  CHECK_EQ(14, r.Call(0));
}

WASM_EXEC_TEST(ExprBlock_nested_ifs) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);

  r.Build({WASM_BLOCK_I(WASM_IF_ELSE_I(
      WASM_LOCAL_GET(0),
      WASM_IF_ELSE_I(WASM_LOCAL_GET(1), WASM_BRV(0, WASM_I32V_1(11)),
                     WASM_BRV(1, WASM_I32V_1(12))),
      WASM_IF_ELSE_I(WASM_LOCAL_GET(1), WASM_BRV(0, WASM_I32V_1(13)),
                     WASM_BRV(1, WASM_I32V_1(14)))))});

  CHECK_EQ(11, r.Call(1, 1));
  CHECK_EQ(12, r.Call(1, 0));
  CHECK_EQ(13, r.Call(0, 1));
  CHECK_EQ(14, r.Call(0, 0));
}

WASM_EXEC_TEST(SimpleCallIndirect) {
  TestSignatures sigs;
  WasmRunner<int32_t, int32_t> r(execution_tier);

  WasmFunctionCompiler& t1 = r.NewFunction(sigs.i_ii());
  t1.Build({WASM_I32_ADD(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  t1.SetSigIndex(ModuleTypeIndex{1});

  WasmFunctionCompiler& t2 = r.NewFunction(sigs.i_ii());
  t2.Build({WASM_I32_SUB(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  t2.SetSigIndex(ModuleTypeIndex{1});

  // Signature table.
  r.builder().AddSignature(sigs.f_ff());
  r.builder().AddSignature(sigs.i_ii());
  r.builder().AddSignature(sigs.d_dd());

  // Function table.
  uint16_t indirect_function_table[] = {
      static_cast<uint16_t>(t1.function_index()),
      static_cast<uint16_t>(t2.function_index())};
  r.builder().AddIndirectFunctionTable(indirect_function_table,
                                       arraysize(indirect_function_table));

  // Build the caller function.
  r.Build({WASM_CALL_INDIRECT(1, WASM_I32V_2(66), WASM_I32V_1(22),
                              WASM_LOCAL_GET(0))});

  CHECK_EQ(88, r.Call(0));
  CHECK_EQ(44, r.Call(1));
  CHECK_TRAP(r.Call(2));
}

WASM_EXEC_TEST(MultipleCallIndirect) {
  TestSignatures sigs;
  WasmRunner<int32_t, int32_t, int32_t, int32_t> r(execution_tier);

  WasmFunctionCompiler& t1 = r.NewFunction(sigs.i_ii());
  t1.Build({WASM_I32_ADD(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  t1.SetSigIndex(ModuleTypeIndex{1});

  WasmFunctionCompiler& t2 = r.NewFunction(sigs.i_ii());
  t2.Build({WASM_I32_SUB(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  t2.SetSigIndex(ModuleTypeIndex{1});

  // Signature table.
  r.builder().AddSignature(sigs.f_ff());
  r.builder().AddSignature(sigs.i_ii());
  r.builder().AddSignature(sigs.d_dd());

  // Function table.
  uint16_t indirect_function_table[] = {
      static_cast<uint16_t>(t1.function_index()),
      static_cast<uint16_t>(t2.function_index())};
  r.builder().AddIndirectFunctionTable(indirect_function_table,
                                       arraysize(indirect_function_table));

  // Build the caller function.
  r.Build(
      {WASM_I32_ADD(WASM_CALL_INDIRECT(1, WASM_LOCAL_GET(1), WASM_LOCAL_GET(2),
                                       WASM_LOCAL_GET(0)),
                    WASM_CALL_INDIRECT(1, WASM_LOCAL_GET(2), WASM_LOCAL_GET(0),
                                       WASM_LOCAL_GET(1)))});

  CHECK_EQ(5, r.Call(0, 1, 2));
  CHECK_EQ(19, r.Call(0, 1, 9));
  CHECK_EQ(1, r.Call(1, 0, 2));
  CHECK_EQ(1, r.Call(1, 0, 9));

  CHECK_TRAP(r.Call(0, 2, 1));
  CHECK_TRAP(r.Call(1, 2, 0));
  CHECK_TRAP(r.Call(2, 0, 1));
  CHECK_TRAP(r.Call(2, 1, 0));
}

WASM_EXEC_TEST(CallIndirect_EmptyTable) {
  TestSignatures sigs;
  WasmRunner<int32_t, int32_t> r(execution_tier);

  // One function.
  WasmFunctionCompiler& t1 = r.NewFunction(sigs.i_ii());
  t1.Build({WASM_I32_ADD(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  t1.SetSigIndex(ModuleTypeIndex{1});

  // Signature table.
  r.builder().AddSignature(sigs.f_ff());
  r.builder().AddSignature(sigs.i_ii());
  r.builder().AddIndirectFunctionTable(nullptr, 0);

  // Build the caller function.
  r.Build({WASM_CALL_INDIRECT(1, WASM_I32V_2(66), WASM_I32V_1(22),
                              WASM_LOCAL_GET(0))});

  CHECK_TRAP(r.Call(0));
  CHECK_TRAP(r.Call(1));
  CHECK_TRAP(r.Call(2));
}

WASM_EXEC_TEST(CallIndirect_canonical) {
  TestSignatures sigs;
  WasmRunner<int32_t, int32_t> r(execution_tier);

  WasmFunctionCompiler& t1 = r.NewFunction(sigs.i_ii());
  t1.Build({WASM_I32_ADD(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});

  WasmFunctionCompiler& t2 = r.NewFunction(sigs.i_ii());
  t2.Build({WASM_I32_SUB(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});

  WasmFunctionCompiler& t3 = r.NewFunction(sigs.f_ff());
  t3.Build({WASM_F32_SUB(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});

  // Function table.
  uint16_t i1 = static_cast<uint16_t>(t1.function_index());
  uint16_t i2 = static_cast<uint16_t>(t2.function_index());
  uint16_t i3 = static_cast<uint16_t>(t3.function_index());
  uint16_t indirect_function_table[] = {i1, i2, i3, i1, i2};

  r.builder().AddIndirectFunctionTable(indirect_function_table,
                                       arraysize(indirect_function_table));

  // Build the caller function.
  r.Build({WASM_CALL_INDIRECT(1, WASM_I32V_2(77), WASM_I32V_1(11),
                              WASM_LOCAL_GET(0))});

  CHECK_EQ(88, r.Call(0));
  CHECK_EQ(66, r.Call(1));
  CHECK_TRAP(r.Call(2));
  CHECK_EQ(88, r.Call(3));
  CHECK_EQ(66, r.Call(4));
  CHECK_TRAP(r.Call(5));
}

WASM_EXEC_TEST(Regress_PushReturns) {
  ValueType kSigTypes[] = {kWasmI32, kWasmI32, kWasmI32, kWasmI32,
                           kWasmI32, kWasmI32, kWasmI32, kWasmI32,
                           kWasmI32, kWasmI32, kWasmI32, kWasmI32};
  FunctionSig sig(12, 0, kSigTypes);
  WasmRunner<int32_t> r(execution_tier);

  WasmFunctionCompiler& f1 = r.NewFunction(&sig);
  f1.Build({WASM_I32V(1), WASM_I32V(2), WASM_I32V(3), WASM_I32V(4),
            WASM_I32V(5), WASM_I32V(6), WASM_I32V(7), WASM_I32V(8),
            WASM_I32V(9), WASM_I32V(10), WASM_I32V(11), WASM_I32V(12)});

  r.Build({WASM_CALL_FUNCTION0(f1.function_index()), WASM_DROP, WASM_DROP,
           WASM_DROP, WASM_DROP, WASM_DROP, WASM_DROP, WASM_DROP, WASM_DROP,
           WASM_DROP, WASM_DROP, WASM_DROP});
  CHECK_EQ(1, r.Call());
}

WASM_EXEC_TEST(Regress_EnsureArguments) {
  ValueType kSigTypes[] = {kWasmI32, kWasmI32, kWasmI32, kWasmI32,
                           kWasmI32, kWasmI32, kWasmI32, kWasmI32,
                           kWasmI32, kWasmI32, kWasmI32, kWasmI32};
  FunctionSig sig(0, 12, kSigTypes);
  WasmRunner<int32_t> r(execution_tier);

  WasmFunctionCompiler& f2 = r.NewFunction(&sig);
  f2.Build({kExprReturn});

  r.Build({WASM_I32V(42), kExprReturn,
           WASM_CALL_FUNCTION(f2.function_index(), WASM_I32V(1))});
  CHECK_EQ(42, r.Call());
}

WASM_EXEC_TEST(Regress_PushControl) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build({WASM_I32V(42), WASM_IF(WASM_I32V(0), WASM_UNREACHABLE, kExprIf,
                                  kVoidCode, kExprEnd)});
  CHECK_EQ(42, r.Call());
}

WASM_EXEC_TEST(F32Floor) {
  WasmRunner<float, float> r(execution_tier);
  r.Build({WASM_F32_FLOOR(WASM_LOCAL_GET(0))});

  FOR_FLOAT32_INPUTS(i) { CHECK_FLOAT_EQ(floorf(i), r.Call(i)); }
}

WASM_EXEC_TEST(F32Ceil) {
  WasmRunner<float, float> r(execution_tier);
  r.Build({WASM_F32_CEIL(WASM_LOCAL_GET(0))});

  FOR_FLOAT32_INPUTS(i) { CHECK_FLOAT_EQ(ceilf(i), r.Call(i)); }
}

WASM_EXEC_TEST(F32Trunc) {
  WasmRunner<float, float> r(execution_tier);
  r.Build({WASM_F32_TRUNC(WASM_LOCAL_GET(0))});

  FOR_FLOAT32_INPUTS(i) { CHECK_FLOAT_EQ(truncf(i), r.Call(i)); }
}

WASM_EXEC_TEST(F32NearestInt) {
  WasmRunner<float, float> r(execution_tier);
  r.Build({WASM_F32_NEARESTINT(WASM_LOCAL_GET(0))});

  FOR_FLOAT32_INPUTS(i) {
    float value = nearbyintf(i);
#if V8_OS_AIX
    value = FpOpWorkaround<float>(i, value);
#endif
    CHECK_FLOAT_EQ(value, r.Call(i));
  }
}

WASM_EXEC_TEST(F64Floor) {
  WasmRunner<double, double> r(execution_tier);
  r.Build({WASM_F64_FLOOR(WASM_LOCAL_GET(0))});

  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(floor(i), r.Call(i)); }
}

WASM_EXEC_TEST(F64Ceil) {
  WasmRunner<double, double> r(execution_tier);
  r.Build({WASM_F64_CEIL(WASM_LOCAL_GET(0))});

  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(ceil(i), r.Call(i)); }
}

WASM_EXEC_TEST(F64Trunc) {
  WasmRunner<double, double> r(execution_tier);
  r.Build({WASM_F64_TRUNC(WASM_LOCAL_GET(0))});

  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(trunc(i), r.Call(i)); }
}

WASM_EXEC_TEST(F64NearestInt) {
  WasmRunner<double, double> r(execution_tier);
  r.Build({WASM_F64_NEARESTINT(WASM_LOCAL_GET(0))});

  FOR_FLOAT64_INPUTS(i) {
    double value = nearbyint(i);
#if V8_OS_AIX
    value = FpOpWorkaround<double>(i, value);
#endif
    CHECK_DOUBLE_EQ(value, r.Call(i));
  }
}

WASM_EXEC_TEST(F32Min) {
  WasmRunner<float, float, float> r(execution_tier);
  r.Build({WASM_F32_MIN(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});

  FOR_FLOAT32_INPUTS(i) {
    FOR_FLOAT32_INPUTS(j) { CHECK_DOUBLE_EQ(JSMin(i, j), r.Call(i, j)); }
  }
}

WASM_EXEC_TEST(F32MinSameValue) {
  WasmRunner<float, float> r(execution_tier);
  r.Build({WASM_F32_MIN(WASM_LOCAL_GET(0), WASM_LOCAL_GET(0))});
  float result = r.Call(5.0f);
  CHECK_FLOAT_EQ(5.0f, result);
}

WASM_EXEC_TEST(F64Min) {
  WasmRunner<double, double, double> r(execution_tier);
  r.Build({WASM_F64_MIN(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});

  FOR_FLOAT64_INPUTS(i) {
    FOR_FLOAT64_INPUTS(j) { CHECK_DOUBLE_EQ(JSMin(i, j), r.Call(i, j)); }
  }
}

WASM_EXEC_TEST(F64MinSameValue) {
  WasmRunner<double, double> r(execution_tier);
  r.Build({WASM_F64_MIN(WASM_LOCAL_GET(0), WASM_LOCAL_GET(0))});
  double result = r.Call(5.0);
  CHECK_DOUBLE_EQ(5.0, result);
}

WASM_EXEC_TEST(F32Max) {
  WasmRunner<float, float, float> r(execution_tier);
  r.Build({WASM_F32_MAX(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});

  FOR_FLOAT32_INPUTS(i) {
    FOR_FLOAT32_INPUTS(j) { CHECK_FLOAT_EQ(JSMax(i, j), r.Call(i, j)); }
  }
}

WASM_EXEC_TEST(F32MaxSameValue) {
  WasmRunner<float, float> r(execution_tier);
  r.Build({WASM_F32_MAX(WASM_LOCAL_GET(0), WASM_LOCAL_GET(0))});
  float result = r.Call(5.0f);
  CHECK_FLOAT_EQ(5.0f, result);
}

WASM_EXEC_TEST(F64Max) {
  WasmRunner<double, double, double> r(execution_tier);
  r.Build({WASM_F64_MAX(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});

  FOR_FLOAT64_INPUTS(i) {
    FOR_FLOAT64_INPUTS(j) {
      double result = r.Call(i, j);
      CHECK_DOUBLE_EQ(JSMax(i, j), result);
    }
  }
}

WASM_EXEC_TEST(F64MaxSameValue) {
  WasmRunner<double, double> r(execution_tier);
  r.Build({WASM_F64_MAX(WASM_LOCAL_GET(0), WASM_LOCAL_GET(0))});
  double result = r.Call(5.0);
  CHECK_DOUBLE_EQ(5.0, result);
}

WASM_EXEC_TEST(I32SConvertF32) {
  WasmRunner<int32_t, float> r(execution_tier);
  r.Build({WASM_I32_SCONVERT_F32(WASM_LOCAL_GET(0))});

  FOR_FLOAT32_INPUTS(i) {
    if (is_inbounds<int32_t>(i)) {
      CHECK_EQ(static_cast<int32_t>(i), r.Call(i));
    } else {
      CHECK_TRAP32(r.Call(i));
    }
  }
}

WASM_EXEC_TEST(I32SConvertSatF32) {
  WasmRunner<int32_t, float> r(execution_tier);
  r.Build({WASM_I32_SCONVERT_SAT_F32(WASM_LOCAL_GET(0))});

  FOR_FLOAT32_INPUTS(i) {
    int32_t expected =
        is_inbounds<int32_t>(i)
            ? static_cast<int32_t>(i)
            : std::isnan(i) ? 0
                            : i < 0.0 ? std::numeric_limits<int32_t>::min()
                                      : std::numeric_limits<int32_t>::max();
    int32_t found = r.Call(i);
    CHECK_EQ(expected, found);
  }
}

WASM_EXEC_TEST(I32SConvertF64) {
  WasmRunner<int32_t, double> r(execution_tier);
  r.Build({WASM_I32_SCONVERT_F64(WASM_LOCAL_GET(0))});

  FOR_FLOAT64_INPUTS(i) {
    if (is_inbounds<int32_t>(i)) {
      CHECK_EQ(static_cast<int32_t>(i), r.Call(i));
    } else {
      CHECK_TRAP32(r.Call(i));
    }
  }
}

WASM_EXEC_TEST(I32SConvertSatF64) {
  WasmRunner<int32_t, double> r(execution_tier);
  r.Build({WASM_I32_SCONVERT_SAT_F64(WASM_LOCAL_GET(0))});
  FOR_FLOAT64_INPUTS(i) {
    int32_t expected =
        is_inbounds<int32_t>(i)
            ? static_cast<int32_t>(i)
            : std::isnan(i) ? 0
                            : i < 0.0 ? std::numeric_limits<int32_t>::min()
                                      : std::numeric_limits<int32_t>::max();
    int32_t found = r.Call(i);
    CHECK_EQ(expected, found);
  }
}

WASM_EXEC_TEST(I32UConvertF32) {
  WasmRunner<uint32_t, float> r(execution_tier);
  r.Build({WASM_I32_UCONVERT_F32(WASM_LOCAL_GET(0))});
  FOR_FLOAT32_INPUTS(i) {
    if (is_inbounds<uint32_t>(i)) {
      CHECK_EQ(static_cast<uint32_t>(i), r.Call(i));
    } else {
      CHECK_TRAP32(r.Call(i));
    }
  }
}

WASM_EXEC_TEST(I32UConvertSatF32) {
  WasmRunner<uint32_t, float> r(execution_tier);
  r.Build({WASM_I32_UCONVERT_SAT_F32(WASM_LOCAL_GET(0))});
  FOR_FLOAT32_INPUTS(i) {
    int32_t expected =
        is_inbounds<uint32_t>(i)
            ? static_cast<uint32_t>(i)
            : std::isnan(i) ? 0
                            : i < 0.0 ? std::numeric_limits<uint32_t>::min()
                                      : std::numeric_limits<uint32_t>::max();
    int32_t found = r.Call(i);
    CHECK_EQ(expected, found);
  }
}

WASM_EXEC_TEST(I32UConvertF64) {
  WasmRunner<uint32_t, double> r(execution_tier);
  r.Build({WASM_I32_UCONVERT_F64(WASM_LOCAL_GET(0))});
  FOR_FLOAT64_INPUTS(i) {
    if (is_inbounds<uint32_t>(i)) {
      CHECK_EQ(static_cast<uint32_t>(i), r.Call(i));
    } else {
      CHECK_TRAP32(r.Call(i));
    }
  }
}

WASM_EXEC_TEST(I32UConvertSatF64) {
  WasmRunner<uint32_t, double> r(execution_tier);
  r.Build({WASM_I32_UCONVERT_SAT_F64(WASM_LOCAL_GET(0))});
  FOR_FLOAT64_INPUTS(i) {
    int32_t expected =
        is_inbounds<uint32_t>(i)
            ? static_cast<uint32_t>(i)
            : std::isnan(i) ? 0
                            : i < 0.0 ? std::numeric_limits<uint32_t>::min()
                                      : std::numeric_limits<uint32_t>::max();
    int32_t found = r.Call(i);
    CHECK_EQ(expected, found);
  }
}

WASM_EXEC_TEST(F64CopySign) {
  WasmRunner<double, double, double> r(execution_tier);
  r.Build({WASM_F64_COPYSIGN(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});

  FOR_FLOAT64_INPUTS(i) {
    FOR_FLOAT64_INPUTS(j) { CHECK_DOUBLE_EQ(copysign(i, j), r.Call(i, j)); }
  }
}

WASM_EXEC_TEST(F32CopySign) {
  WasmRunner<float, float, float> r(execution_tier);
  r.Build({WASM_F32_COPYSIGN(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});

  FOR_FLOAT32_INPUTS(i) {
    FOR_FLOAT32_INPUTS(j) { CHECK_FLOAT_EQ(copysignf(i, j), r.Call(i, j)); }
  }
}

static void CompileCallIndirectMany(TestExecutionTier tier, ValueType param) {
  // Make sure we don't run out of registers when compiling indirect calls
  // with many many parameters.
  TestSignatures sigs;
  for (uint8_t num_params = 0; num_params < 40; ++num_params) {
    WasmRunner<void> r(tier);
    FunctionSig* sig = sigs.many(r.zone(), kWasmVoid, param, num_params);

    r.builder().AddSignature(sig);
    r.builder().AddSignature(sig);
    r.builder().AddIndirectFunctionTable(nullptr, 0);

    WasmFunctionCompiler& t = r.NewFunction(sig);

    std::vector<uint8_t> code;
    for (uint8_t p = 0; p < num_params; ++p) {
      ADD_CODE(code, kExprLocalGet, p);
    }
    ADD_CODE(code, kExprI32Const, 0);
    ADD_CODE(code, kExprCallIndirect, 1, TABLE_ZERO);

    t.Build(base::VectorOf(code));
  }
}

WASM_COMPILED_EXEC_TEST(Compile_Wasm_CallIndirect_Many_i32) {
  CompileCallIndirectMany(execution_tier, kWasmI32);
}

WASM_COMPILED_EXEC_TEST(Compile_Wasm_CallIndirect_Many_f32) {
  CompileCallIndirectMany(execution_tier, kWasmF32);
}

WASM_COMPILED_EXEC_TEST(Compile_Wasm_CallIndirect_Many_f64) {
  CompileCallIndirectMany(execution_tier, kWasmF64);
}

WASM_EXEC_TEST(Int32RemS_dead) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  r.Build({WASM_I32_REMS(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)), WASM_DROP,
           WASM_ZERO});
  const int32_t kMin = std::numeric_limits<int32_t>::min();
  CHECK_EQ(0, r.Call(133, 100));
  CHECK_EQ(0, r.Call(kMin, -1));
  CHECK_EQ(0, r.Call(0, 1));
  CHECK_TRAP(r.Call(100, 0));
  CHECK_TRAP(r.Call(-1001, 0));
  CHECK_TRAP(r.Call(kMin, 0));
}

WASM_EXEC_TEST(BrToLoopWithValue) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  // Subtracts <1> times 3 from <0> and returns the result.
  r.Build({// loop i32
           kExprLoop, kI32Code,
           // decrement <0> by 3.
           WASM_LOCAL_SET(0, WASM_I32_SUB(WASM_LOCAL_GET(0), WASM_I32V_1(3))),
           // decrement <1> by 1.
           WASM_LOCAL_SET(1, WASM_I32_SUB(WASM_LOCAL_GET(1), WASM_ONE)),
           // load return value <0>, br_if will drop if if the branch is taken.
           WASM_LOCAL_GET(0),
           // continue loop if <1> is != 0.
           WASM_BR_IF(0, WASM_LOCAL_GET(1)),
           // end of loop, value loaded above is the return value.
           kExprEnd});
  CHECK_EQ(12, r.Call(27, 5));
}

WASM_EXEC_TEST(BrToLoopWithoutValue) {
  // This was broken in the interpreter, see http://crbug.com/715454
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build(
      {kExprLoop, kI32Code,  // loop i32
       WASM_LOCAL_SET(0, WASM_I32_SUB(WASM_LOCAL_GET(0), WASM_ONE)),  // dec <0>
       WASM_BR_IF(0, WASM_LOCAL_GET(0)),  // br_if <0> != 0
       kExprUnreachable,                  // unreachable
       kExprEnd});                        // end
  CHECK_TRAP32(r.Call(2));
}

WASM_EXEC_TEST(LoopsWithValues) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build({WASM_LOOP_I(WASM_LOOP_I(WASM_ONE), WASM_ONE, kExprI32Add)});
  CHECK_EQ(2, r.Call());
}

WASM_EXEC_TEST(InvalidStackAfterUnreachable) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build({kExprUnreachable, kExprI32Add});
  CHECK_TRAP32(r.Call());
}

WASM_EXEC_TEST(InvalidStackAfterBr) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build({WASM_BRV(0, WASM_I32V_1(27)), kExprI32Add});
  CHECK_EQ(27, r.Call());
}

WASM_EXEC_TEST(InvalidStackAfterReturn) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build({WASM_RETURN(WASM_I32V_1(17)), kExprI32Add});
  CHECK_EQ(17, r.Call());
}

WASM_EXEC_TEST(BranchOverUnreachableCode) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build({// Start a block which breaks in the middle (hence unreachable code
           // afterwards) and continue execution after this block.
           WASM_BLOCK_I(WASM_BRV(0, WASM_I32V_1(17)), kExprI32Add),
           // Add one to the 17 returned from the block.
           WASM_ONE, kExprI32Add});
  CHECK_EQ(18, r.Call());
}

WASM_EXEC_TEST(BranchOverUnreachableCodeInLoop0) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build(
      {WASM_BLOCK_I(
           // Start a loop which breaks in the middle (hence unreachable code
           // afterwards) and continue execution after this loop.
           // This should validate even though there is no value on the stack
           // at the end of the loop.
           WASM_LOOP_I(WASM_BRV(1, WASM_I32V_1(17)))),
       // Add one to the 17 returned from the block.
       WASM_ONE, kExprI32Add});
  CHECK_EQ(18, r.Call());
}

WASM_EXEC_TEST(BranchOverUnreachableCodeInLoop1) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build(
      {WASM_BLOCK_I(
           // Start a loop which breaks in the middle (hence unreachable code
           // afterwards) and continue execution after this loop.
           // Even though unreachable, the loop leaves one value on the stack.
           WASM_LOOP_I(WASM_BRV(1, WASM_I32V_1(17)), WASM_ONE)),
       // Add one to the 17 returned from the block.
       WASM_ONE, kExprI32Add});
  CHECK_EQ(18, r.Call());
}

WASM_EXEC_TEST(BranchOverUnreachableCodeInLoop2) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build(
      {WASM_BLOCK_I(
           // Start a loop which breaks in the middle (hence unreachable code
           // afterwards) and continue execution after this loop.
           // The unreachable code is allowed to pop non-existing values off
           // the stack and push back the result.
           WASM_LOOP_I(WASM_BRV(1, WASM_I32V_1(17)), kExprI32Add)),
       // Add one to the 17 returned from the block.
       WASM_ONE, kExprI32Add});
  CHECK_EQ(18, r.Call());
}

WASM_EXEC_TEST(BlockInsideUnreachable) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build({WASM_RETURN(WASM_I32V_1(17)), WASM_BLOCK(WASM_BR(0))});
  CHECK_EQ(17, r.Call());
}

WASM_EXEC_TEST(IfInsideUnreachable) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build(
      {WASM_RETURN(WASM_I32V_1(17)),
       WASM_IF_ELSE_I(WASM_ONE, WASM_BRV(0, WASM_ONE), WASM_RETURN(WASM_ONE))});
  CHECK_EQ(17, r.Call());
}

WASM_EXEC_TEST(IndirectNull) {
  WasmRunner<int32_t> r(execution_tier);
  FunctionSig sig(1, 0, &kWasmI32);
  ModuleTypeIndex sig_index = r.builder().AddSignature(&sig);
  r.builder().AddIndirectFunctionTable(nullptr, 1);

  r.Build({WASM_CALL_INDIRECT(sig_index, WASM_I32V(0))});

  CHECK_TRAP(r.Call());
}

WASM_EXEC_TEST(IndirectNullTyped) {
  WasmRunner<int32_t> r(execution_tier);
  FunctionSig sig(1, 0, &kWasmI32);
  ModuleTypeIndex sig_index = r.builder().AddSignature(&sig);
  r.builder().AddIndirectFunctionTable(nullptr, 1,
                                       ValueType::RefNull(sig_index));

  r.Build({WASM_CALL_INDIRECT(sig_index, WASM_I32V(0))});

  CHECK_TRAP(r.Call());
}

// This test targets binops in Liftoff.
// Initialize a number of local variables to force them into different
// registers, then perform a binary operation on two of the locals.
// Afterwards, write back all locals to memory, to check that their value was
// not overwritten.
template <typename ctype>
void BinOpOnDifferentRegisters(
    TestExecutionTier execution_tier, ValueType type,
    base::Vector<const ctype> inputs, WasmOpcode opcode,
    std::function<ctype(ctype, ctype, bool*)> expect_fn) {
  static constexpr int kMaxNumLocals = 8;
  for (int num_locals = 1; num_locals < kMaxNumLocals; ++num_locals) {
    // {init_locals_code} is shared by all code generated in the loop below.
    std::vector<uint8_t> init_locals_code;
    // Load from memory into the locals.
    for (int i = 0; i < num_locals; ++i) {
      ADD_CODE(
          init_locals_code,
          WASM_LOCAL_SET(i, WASM_LOAD_MEM(type.machine_type(),
                                          WASM_I32V_2(sizeof(ctype) * i))));
    }
    // {write_locals_code} is shared by all code generated in the loop below.
    std::vector<uint8_t> write_locals_code;
    // Write locals back into memory, shifted by one element to the right.
    for (int i = 0; i < num_locals; ++i) {
      ADD_CODE(write_locals_code,
               WASM_STORE_MEM(type.machine_type(),
                              WASM_I32V_2(sizeof(ctype) * (i + 1)),
                              WASM_LOCAL_GET(i)));
    }
    for (int lhs = 0; lhs < num_locals; ++lhs) {
      for (int rhs = 0; rhs < num_locals; ++rhs) {
        WasmRunner<int32_t> r(execution_tier);
        ctype* memory =
            r.builder().AddMemoryElems<ctype>(kWasmPageSize / sizeof(ctype));
        for (int i = 0; i < num_locals; ++i) {
          r.AllocateLocal(type);
        }
        std::vector<uint8_t> code(init_locals_code);
        ADD_CODE(code,
                 // Store the result of the binary operation at memory[0].
                 WASM_STORE_MEM(type.machine_type(), WASM_ZERO,
                                WASM_BINOP(opcode, WASM_LOCAL_GET(lhs),
                                           WASM_LOCAL_GET(rhs))),
                 // Return 0.
                 WASM_ZERO);
        code.insert(code.end(), write_locals_code.begin(),
                    write_locals_code.end());
        r.Build(base::VectorOf(code));
        for (ctype lhs_value : inputs) {
          for (ctype rhs_value : inputs) {
            if (lhs == rhs) lhs_value = rhs_value;
            for (int i = 0; i < num_locals; ++i) {
              ctype value =
                  i == lhs ? lhs_value
                           : i == rhs ? rhs_value : static_cast<ctype>(i + 47);
              WriteLittleEndianValue<ctype>(&memory[i], value);
            }
            bool trap = false;
            int64_t expect = expect_fn(lhs_value, rhs_value, &trap);
            if (trap) {
              CHECK_TRAP(r.Call());
              continue;
            }
            CHECK_EQ(0, r.Call());
            CHECK_EQ(expect, ReadLittleEndianValue<ctype>(&memory[0]));
            for (int i = 0; i < num_locals; ++i) {
              ctype value =
                  i == lhs ? lhs_value
                           : i == rhs ? rhs_value : static_cast<ctype>(i + 47);
              CHECK_EQ(value, ReadLittleEndianValue<ctype>(&memory[i + 1]));
            }
          }
        }
      }
    }
  }
}

// Keep this list small, the BinOpOnDifferentRegisters test is running long
// enough already.
static constexpr int32_t kSome32BitInputs[] = {
    0, 1, -1, 31, static_cast<int32_t>(0xff112233)};
static constexpr int64_t kSome64BitInputs[] = {
    0, 1, -1, 31, 63, 0x100000000, static_cast<int64_t>(0xff11223344556677)};

WASM_EXEC_TEST(I32AddOnDifferentRegisters) {
  BinOpOnDifferentRegisters<int32_t>(
      execution_tier, kWasmI32, base::ArrayVector(kSome32BitInputs),
      kExprI32Add,
      [](int32_t lhs, int32_t rhs, bool* trap) { return lhs + rhs; });
}

WASM_EXEC_TEST(I32SubOnDifferentRegisters) {
  BinOpOnDifferentRegisters<int32_t>(
      execution_tier, kWasmI32, base::ArrayVector(kSome32BitInputs),
      kExprI32Sub,
      [](int32_t lhs, int32_t rhs, bool* trap) { return lhs - rhs; });
}

WASM_EXEC_TEST(I32MulOnDifferentRegisters) {
  BinOpOnDifferentRegisters<int32_t>(
      execution_tier, kWasmI32, base::ArrayVector(kSome32BitInputs),
      kExprI32Mul, [](int32_t lhs, int32_t rhs, bool* trap) {
        return base::MulWithWraparound(lhs, rhs);
      });
}

WASM_EXEC_TEST(I32ShlOnDifferentRegisters) {
  BinOpOnDifferentRegisters<int32_t>(
      execution_tier, kWasmI32, base::ArrayVector(kSome32BitInputs),
      kExprI32Shl, [](int32_t lhs, int32_t rhs, bool* trap) {
        return base::ShlWithWraparound(lhs, rhs);
      });
}

WASM_EXEC_TEST(I32ShrSOnDifferentRegisters) {
  BinOpOnDifferentRegisters<int32_t>(
      execution_tier, kWasmI32, base::ArrayVector(kSome32BitInputs),
      kExprI32ShrS,
      [](int32_t lhs, int32_t rhs, bool* trap) { return lhs >> (rhs & 31); });
}

WASM_EXEC_TEST(I32ShrUOnDifferentRegisters) {
  BinOpOnDifferentRegisters<int32_t>(
      execution_tier, kWasmI32, base::ArrayVector(kSome32BitInputs),
      kExprI32ShrU, [](int32_t lhs, int32_t rhs, bool* trap) {
        return static_cast<uint32_t>(lhs) >> (rhs & 31);
      });
}

WASM_EXEC_TEST(I32DivSOnDifferentRegisters) {
  BinOpOnDifferentRegisters<int32_t>(
      execution_tier, kWasmI32, base::ArrayVector(kSome32BitInputs),
      kExprI32DivS, [](int32_t lhs, int32_t rhs, bool* trap) {
        *trap = rhs == 0;
        return *trap ? 0 : lhs / rhs;
      });
}

WASM_EXEC_TEST(I32DivUOnDifferentRegisters) {
  BinOpOnDifferentRegisters<int32_t>(
      execution_tier, kWasmI32, base::ArrayVector(kSome32BitInputs),
      kExprI32DivU, [](uint32_t lhs, uint32_t rhs, bool* trap) {
        *trap = rhs == 0;
        return *trap ? 0 : lhs / rhs;
      });
}

WASM_EXEC_TEST(I32RemSOnDifferentRegisters) {
  BinOpOnDifferentRegisters<int32_t>(
      execution_tier, kWasmI32, base::ArrayVector(kSome32BitInputs),
      kExprI32RemS, [](int32_t lhs, int32_t rhs, bool* trap) {
        *trap = rhs == 0;
        return *trap || rhs == -1 ? 0 : lhs % rhs;
      });
}

WASM_EXEC_TEST(I32RemUOnDifferentRegisters) {
  BinOpOnDifferentRegisters<int32_t>(
      execution_tier, kWasmI32, base::ArrayVector(kSome32BitInputs),
      kExprI32RemU, [](uint32_t lhs, uint32_t rhs, bool* trap) {
        *trap = rhs == 0;
        return *trap ? 0 : lhs % rhs;
      });
}

WASM_EXEC_TEST(I64AddOnDifferentRegisters) {
  BinOpOnDifferentRegisters<int64_t>(
      execution_tier, kWasmI64, base::ArrayVector(kSome64BitInputs),
      kExprI64Add,
      [](int64_t lhs, int64_t rhs, bool* trap) { return lhs + rhs; });
}

WASM_EXEC_TEST(I64SubOnDifferentRegisters) {
  BinOpOnDifferentRegisters<int64_t>(
      execution_tier, kWasmI64, base::ArrayVector(kSome64BitInputs),
      kExprI64Sub,
      [](int64_t lhs, int64_t rhs, bool* trap) { return lhs - rhs; });
}

WASM_EXEC_TEST(I64MulOnDifferentRegisters) {
  BinOpOnDifferentRegisters<int64_t>(
      execution_tier, kWasmI64, base::ArrayVector(kSome64BitInputs),
      kExprI64Mul, [](int64_t lhs, int64_t rhs, bool* trap) {
        return base::MulWithWraparound(lhs, rhs);
      });
}

WASM_EXEC_TEST(I64ShlOnDifferentRegisters) {
  BinOpOnDifferentRegisters<int64_t>(
      execution_tier, kWasmI64, base::ArrayVector(kSome64BitInputs),
      kExprI64Shl, [](int64_t lhs, int64_t rhs, bool* trap) {
        return base::ShlWithWraparound(lhs, rhs);
      });
}

WASM_EXEC_TEST(I64ShrSOnDifferentRegisters) {
  BinOpOnDifferentRegisters<int64_t>(
      execution_tier, kWasmI64, base::ArrayVector(kSome64BitInputs),
      kExprI64ShrS,
      [](int64_t lhs, int64_t rhs, bool* trap) { return lhs >> (rhs & 63); });
}

WASM_EXEC_TEST(I64ShrUOnDifferentRegisters) {
  BinOpOnDifferentRegisters<int64_t>(
      execution_tier, kWa
```