Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript examples.

1. **Understand the Goal:** The primary request is to understand the *functionality* of the C++ code and relate it to JavaScript if possible. The specific file name, `test-run-wasm-exceptions.cc`, immediately suggests the focus is on testing WebAssembly exception handling.

2. **Identify Key Structures and Patterns:**  Scanning the code reveals several recurring patterns:
    * `WASM_EXEC_TEST(...)`: This macro clearly defines individual test cases. Each test case seems to have a descriptive name (e.g., `TryCatchThrow`, `TryMultiCatchThrow`).
    * `TestSignatures sigs;`:  This suggests dealing with function signatures, which are fundamental to WebAssembly.
    * `WasmRunner<...> r(execution_tier);`: This looks like a helper class for building and executing WebAssembly modules within the test framework. The template arguments likely define the function signature of the main test function.
    * `r.builder().AddException(...)`: This is a strong indicator that the code is explicitly creating and managing WebAssembly exceptions.
    * `WASM_TRY_CATCH_T`, `WASM_TRY_CATCH_ALL_T`, `WASM_THROW`, `WASM_RETHROW`, `WASM_TRY_DELEGATE_T`: These look like macros representing the different WebAssembly exception handling opcodes.
    * `r.Build({...})`: This likely constructs the WebAssembly bytecode for the test function. The content within the braces seems to be the actual WebAssembly instructions (using the macros).
    * `r.CheckCallViaJS(...)` and `r.CheckCallViaJSTraps()`: These methods indicate that the tests involve calling the WebAssembly code from JavaScript and checking the results or if a trap occurred.
    * `WasmFunctionCompiler`:  This suggests the creation of helper functions within the WebAssembly module.

3. **Analyze Individual Test Cases:**  Now, the strategy is to go through each `WASM_EXEC_TEST` block and understand what it's testing. Look at the macros used within `r.Build({...})` and the arguments passed to `r.CheckCallViaJS(...)`.

    * **`TryCatchThrow`**: A simple try-catch block in WebAssembly, throwing a defined exception.
    * **`TryCatchThrowWithValue`**: Similar, but the `THROW` seems to have an associated value. *Correction during thought process:* It seems like the *try* block has a value before the throw, and the catch doesn't handle a value in this case. The output of the try is the result.
    * **`TryMultiCatchThrow`**: Tests catching different specific exceptions.
    * **`TryCatchAllThrow`**: Tests catching *any* exception.
    * **`TryCatchCatchAllThrow`**: Combines specific catch and a catch-all.
    * **`TryImplicitRethrow`**: Demonstrates an inner try-catch where the inner catch doesn't handle the exception, causing it to be propagated to the outer catch.
    * **`TryDelegate`**: Introduces the concept of `try_delegate`, where an exception is handled in an enclosing scope.
    * **`TestCatchlessTry`**:  A try block without a catch, indicating potential cleanup or fall-through behavior.
    * **`TryCatchRethrow`**: Shows how to explicitly re-throw an exception within a catch block.
    * **`TryDelegateToCaller`**:  Delegates the exception handling to the calling function. This likely involves the JavaScript caller.
    * **`TryCatchCallDirect`**: Tests exceptions thrown from a directly called WebAssembly function.
    * **`TryCatchAllCallDirect`**: Similar, but with a catch-all.
    * **`TryCatchCallIndirect`**: Tests exceptions from an indirectly called WebAssembly function (via a function table).
    * **`TryCatchAllCallIndirect`**: Similar, but with a catch-all.
    * **`TryCatchCallExternal`**: Tests catching exceptions thrown from JavaScript functions called from WebAssembly.
    * **`TryCatchAllCallExternal`**: Similar, but with a catch-all.
    * **Tests involving `TestTrapNotCaught`**: These test cases demonstrate that certain WebAssembly traps (like `unreachable`, memory out-of-bounds, division by zero) are *not* caught by `try...catch_all`. This is an important distinction.
    * **`TestStackOverflowNotCaught`**:  Confirms that stack overflow is a fatal error (trap) and not caught by WebAssembly exception handling.

4. **Generalize and Summarize:**  Based on the analysis of the individual tests, formulate a general description of the file's purpose. Highlight the core functionalities being tested: basic `try...catch`, catching specific and all exceptions, re-throwing, delegation, interaction with function calls (direct, indirect, external), and the distinction between WebAssembly exceptions and traps.

5. **Relate to JavaScript:** The key connection to JavaScript is the interoperability of WebAssembly exceptions with JavaScript exceptions.

    * **`throw` in WebAssembly is like `throw` in JavaScript:**  Show a simple direct analogy.
    * **`try...catch` in WebAssembly is like `try...catch` in JavaScript:**  Illustrate the similar structure and behavior.
    * **Calling JavaScript from WebAssembly can throw JavaScript exceptions:**  Demonstrate this scenario and how WebAssembly can catch these exceptions (using `catch_all`).

6. **Refine and Organize:** Ensure the summary is clear, concise, and addresses the prompt's requirements. Organize the JavaScript examples logically and provide clear explanations. Emphasize the differences between WebAssembly exceptions and traps.

7. **Self-Correction/Refinement:** During the process, I might realize a previous assumption was slightly off (like the `TryCatchThrowWithValue` case). Reviewing the code and the test assertions helps correct these misunderstandings. Also, pay attention to the specifics of the macros and opcodes – for example, `kWasmI32` indicates the data type. The comments in the code are also helpful.

By following this systematic approach, breaking down the code into smaller, understandable units, and focusing on the core concepts being tested, it's possible to generate an accurate and informative summary along with illustrative JavaScript examples.
这个C++源代码文件 `test-run-wasm-exceptions.cc` 是 V8 JavaScript 引擎的测试文件，专门用于测试 WebAssembly (Wasm) 的异常处理机制。

**功能归纳:**

该文件通过一系列的测试用例，验证了 WebAssembly 的 `try`, `catch`, `throw`, `rethrow`, 和 `delegate` 等异常处理操作符的正确性。它测试了以下几个关键方面：

1. **基本的 `try...catch` 机制:**  验证 Wasm 代码是否能够捕获由 `throw` 抛出的异常。
2. **捕获特定类型的异常:**  测试 Wasm 是否能够捕获特定类型的异常（通过 `catch` 操作符）。
3. **捕获所有异常 (`catch_all`):**  测试 Wasm 是否能够捕获任何类型的异常。
4. **嵌套的 `try...catch` 结构:**  验证嵌套的异常处理结构是否按预期工作。
5. **异常的重新抛出 (`rethrow`):** 测试在 `catch` 块中重新抛出异常的行为。
6. **异常的委托 (`delegate`):**  测试将异常处理委托给调用栈上层帧的功能。
7. **在函数调用中抛出和捕获异常:** 测试在直接调用、间接调用以及调用外部 JavaScript 函数时抛出和捕获异常的情况。
8. **WebAssembly traps 与异常的区别:** 验证了某些 WebAssembly 的 trap (例如 `unreachable`, 内存越界, 除零错误等) **不会** 被 `catch_all` 捕获，这表明 trap 是更严重的错误。
9. **栈溢出错误:** 验证了栈溢出错误也不会被 WebAssembly 的 `catch_all` 捕获，它会导致程序终止。

**与 JavaScript 的关系及 JavaScript 示例:**

WebAssembly 的异常处理机制与 JavaScript 的 `try...catch` 语句非常相似，它们都允许代码在发生错误时进行处理，而不是直接崩溃。这个测试文件验证了 V8 引擎在执行 Wasm 代码时，其异常处理机制的实现是否符合 Wasm 规范，并且能够与 JavaScript 的异常处理进行交互（例如，从 Wasm 中调用 JavaScript 函数并捕获 JavaScript 抛出的异常）。

**JavaScript 示例:**

假设我们有一个简单的 WebAssembly 模块，它定义了一个抛出异常的函数和一个尝试捕获该异常的函数。

```javascript
// 假设 'wasmModule' 是一个已经加载并实例化的 WebAssembly 模块

const throwException = wasmModule.instance.exports.throw_exception;
const tryCatchException = wasmModule.instance.exports.try_catch_exception;

// 在 WebAssembly 模块中定义的异常的标识符 (在 C++ 代码中通过 `AddException` 创建)
// 这只是一个假设，实际中可能需要通过某种方式传递或约定
const exceptionIdentifier = 0; // 假设这是第一个添加的异常的标识符

// 尝试调用抛出异常的 Wasm 函数，并使用 JavaScript 的 try...catch 捕获
try {
  throwException();
} catch (error) {
  console.log("JavaScript caught a Wasm exception:", error);
  // 这里的 error 对象可能包含有关 Wasm 异常的信息，具体取决于 V8 的实现
}

// 调用 Wasm 中定义的尝试捕获异常的函数
const result = tryCatchException();
console.log("Result from Wasm try-catch:", result);

// 如果 `tryCatchException` 在 Wasm 内部成功捕获了异常并返回了一个特定的值，
// 那么 result 应该等于该值。
```

**对应的 WebAssembly (伪代码) 概念:**

虽然我们无法直接展示编译后的 WebAssembly 二进制代码，但可以模拟其结构：

```wasm
;; 假设在 WebAssembly 模块中定义了以下函数 (对应 C++ 测试代码中的构建)

(module
  (type $v_v (func))
  (type $i32_i32 (func (param i32) (result i32)))

  ;; 定义一个异常
  (exception $my_exception (type $v_v))

  (func $throw_exception (export "throw_exception")
    throw $my_exception
  )

  (func $try_catch_exception (export "try_catch_exception") (result i32)
    (try (result i32)
      i32.const 42  ;; 尝试块中的正常执行路径
      throw $my_exception
    catch $my_exception
      i32.const 23  ;; 捕获到异常后的处理逻辑
    end
  )

  ;; ... 其他函数和定义
)
```

**总结:**

`test-run-wasm-exceptions.cc` 这个文件是 V8 引擎中用于测试 WebAssembly 异常处理功能的重要组成部分。它确保了 V8 能够正确地执行 Wasm 的异常处理指令，并且能够与 JavaScript 的异常处理机制协同工作，从而保证了 WebAssembly 代码在 JavaScript 环境中的健壮性和可靠性。通过这些测试，开发者可以确信当 Wasm 代码抛出异常时，V8 引擎能够按照 WebAssembly 规范进行处理，并允许 JavaScript 代码进行适当的响应。

Prompt: 
```
这是目录为v8/test/cctest/wasm/test-run-wasm-exceptions.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "include/v8-function.h"
#include "src/api/api-inl.h"
#include "test/cctest/wasm/wasm-atomics-utils.h"
#include "test/common/wasm/test-signatures.h"
#include "test/common/wasm/wasm-macro-gen.h"

namespace v8::internal::wasm {

WASM_EXEC_TEST(TryCatchThrow) {
  TestSignatures sigs;
  WasmRunner<uint32_t, uint32_t> r(execution_tier);
  uint8_t except = r.builder().AddException(sigs.v_v());
  constexpr uint32_t kResult0 = 23;
  constexpr uint32_t kResult1 = 42;

  // Build the main test function.
  r.Build({WASM_TRY_CATCH_T(
      kWasmI32,
      WASM_STMTS(WASM_I32V(kResult1),
                 WASM_IF(WASM_I32_EQZ(WASM_LOCAL_GET(0)), WASM_THROW(except))),
      WASM_STMTS(WASM_I32V(kResult0)), except)});

  // Need to call through JS to allow for creation of stack traces.
  r.CheckCallViaJS(kResult0, 0);
  r.CheckCallViaJS(kResult1, 1);
}

WASM_EXEC_TEST(TryCatchThrowWithValue) {
  TestSignatures sigs;
  WasmRunner<uint32_t, uint32_t> r(execution_tier);
  uint8_t except = r.builder().AddException(sigs.v_i());
  constexpr uint32_t kResult0 = 23;
  constexpr uint32_t kResult1 = 42;

  // Build the main test function.
  r.Build({WASM_TRY_CATCH_T(
      kWasmI32,
      WASM_STMTS(WASM_I32V(kResult1),
                 WASM_IF(WASM_I32_EQZ(WASM_LOCAL_GET(0)), WASM_I32V(kResult0),
                         WASM_THROW(except))),
      WASM_STMTS(kExprNop), except)});

  // Need to call through JS to allow for creation of stack traces.
  r.CheckCallViaJS(kResult0, 0);
  r.CheckCallViaJS(kResult1, 1);
}

WASM_EXEC_TEST(TryMultiCatchThrow) {
  TestSignatures sigs;
  WasmRunner<uint32_t, uint32_t> r(execution_tier);
  uint8_t except1 = r.builder().AddException(sigs.v_v());
  uint8_t except2 = r.builder().AddException(sigs.v_v());
  constexpr uint32_t kResult0 = 23;
  constexpr uint32_t kResult1 = 42;
  constexpr uint32_t kResult2 = 51;

  // Build the main test function.
  r.Build(
      {kExprTry, static_cast<uint8_t>((kWasmI32).value_type_code()),
       WASM_STMTS(WASM_I32V(kResult2),
                  WASM_IF(WASM_I32_EQZ(WASM_LOCAL_GET(0)), WASM_THROW(except1)),
                  WASM_IF(WASM_I32_EQ(WASM_LOCAL_GET(0), WASM_I32V(1)),
                          WASM_THROW(except2))),
       kExprCatch, except1, WASM_STMTS(WASM_I32V(kResult0)), kExprCatch,
       except2, WASM_STMTS(WASM_I32V(kResult1)), kExprEnd});

  // Need to call through JS to allow for creation of stack traces.
  r.CheckCallViaJS(kResult0, 0);
  r.CheckCallViaJS(kResult1, 1);
  r.CheckCallViaJS(kResult2, 2);
}

WASM_EXEC_TEST(TryCatchAllThrow) {
  TestSignatures sigs;
  WasmRunner<uint32_t, uint32_t> r(execution_tier);
  uint8_t except = r.builder().AddException(sigs.v_v());
  constexpr uint32_t kResult0 = 23;
  constexpr uint32_t kResult1 = 42;

  // Build the main test function.
  r.Build(
      {kExprTry, static_cast<uint8_t>((kWasmI32).value_type_code()),
       WASM_STMTS(WASM_I32V(kResult1),
                  WASM_IF(WASM_I32_EQZ(WASM_LOCAL_GET(0)), WASM_THROW(except))),
       kExprCatchAll, WASM_I32V(kResult0), kExprEnd});

  // Need to call through JS to allow for creation of stack traces.
  r.CheckCallViaJS(kResult0, 0);
  r.CheckCallViaJS(kResult1, 1);
}

WASM_EXEC_TEST(TryCatchCatchAllThrow) {
  TestSignatures sigs;
  WasmRunner<uint32_t, uint32_t> r(execution_tier);
  uint8_t except1 = r.builder().AddException(sigs.v_v());
  uint8_t except2 = r.builder().AddException(sigs.v_v());
  constexpr uint32_t kResult0 = 23;
  constexpr uint32_t kResult1 = 42;
  constexpr uint32_t kResult2 = 51;

  // Build the main test function.
  r.Build(
      {kExprTry, static_cast<uint8_t>((kWasmI32).value_type_code()),
       WASM_STMTS(WASM_I32V(kResult2),
                  WASM_IF(WASM_I32_EQZ(WASM_LOCAL_GET(0)), WASM_THROW(except1)),
                  WASM_IF(WASM_I32_EQ(WASM_LOCAL_GET(0), WASM_I32V(1)),
                          WASM_THROW(except2))),
       kExprCatch, except1, WASM_I32V(kResult0), kExprCatchAll,
       WASM_I32V(kResult1), kExprEnd});

  // Need to call through JS to allow for creation of stack traces.
  r.CheckCallViaJS(kResult0, 0);
  r.CheckCallViaJS(kResult1, 1);
  r.CheckCallViaJS(kResult2, 2);
}

WASM_EXEC_TEST(TryImplicitRethrow) {
  TestSignatures sigs;
  WasmRunner<uint32_t, uint32_t> r(execution_tier);
  uint8_t except1 = r.builder().AddException(sigs.v_v());
  uint8_t except2 = r.builder().AddException(sigs.v_v());
  constexpr uint32_t kResult0 = 23;
  constexpr uint32_t kResult1 = 42;
  constexpr uint32_t kResult2 = 51;

  // Build the main test function.
  r.Build({WASM_TRY_CATCH_T(
      kWasmI32,
      WASM_TRY_CATCH_T(kWasmI32,
                       WASM_STMTS(WASM_I32V(kResult1),
                                  WASM_IF(WASM_I32_EQZ(WASM_LOCAL_GET(0)),
                                          WASM_THROW(except2))),
                       WASM_STMTS(WASM_I32V(kResult2)), except1),
      WASM_I32V(kResult0), except2)});

  // Need to call through JS to allow for creation of stack traces.
  r.CheckCallViaJS(kResult0, 0);
  r.CheckCallViaJS(kResult1, 1);
}

WASM_EXEC_TEST(TryDelegate) {
  TestSignatures sigs;
  WasmRunner<uint32_t, uint32_t> r(execution_tier);
  uint8_t except = r.builder().AddException(sigs.v_v());
  constexpr uint32_t kResult0 = 23;
  constexpr uint32_t kResult1 = 42;

  // Build the main test function.
  r.Build({WASM_TRY_CATCH_T(
      kWasmI32,
      WASM_TRY_DELEGATE_T(kWasmI32,
                          WASM_STMTS(WASM_I32V(kResult1),
                                     WASM_IF(WASM_I32_EQZ(WASM_LOCAL_GET(0)),
                                             WASM_THROW(except))),
                          0),
      WASM_I32V(kResult0), except)});

  // Need to call through JS to allow for creation of stack traces.
  r.CheckCallViaJS(kResult0, 0);
  r.CheckCallViaJS(kResult1, 1);
}

WASM_EXEC_TEST(TestCatchlessTry) {
  TestSignatures sigs;
  WasmRunner<uint32_t> r(execution_tier);
  uint8_t except = r.builder().AddException(sigs.v_i());
  r.Build({WASM_TRY_CATCH_T(
      kWasmI32,
      WASM_TRY_T(kWasmI32, WASM_STMTS(WASM_I32V(0), WASM_THROW(except))),
      WASM_NOP, except)});
  r.CheckCallViaJS(0);
}

WASM_EXEC_TEST(TryCatchRethrow) {
  TestSignatures sigs;
  WasmRunner<uint32_t, uint32_t> r(execution_tier);
  uint8_t except1 = r.builder().AddException(sigs.v_v());
  uint8_t except2 = r.builder().AddException(sigs.v_v());
  constexpr uint32_t kResult0 = 23;
  constexpr uint32_t kResult1 = 42;
  constexpr uint32_t kUnreachable = 51;

  // Build the main test function.
  r.Build({WASM_TRY_CATCH_CATCH_T(
      kWasmI32,
      WASM_TRY_CATCH_T(
          kWasmI32, WASM_THROW(except2),
          WASM_TRY_CATCH_T(
              kWasmI32, WASM_THROW(except1),
              WASM_STMTS(WASM_I32V(kUnreachable),
                         WASM_IF_ELSE(WASM_I32_EQZ(WASM_LOCAL_GET(0)),
                                      WASM_RETHROW(1), WASM_RETHROW(2))),
              except1),
          except2),
      except1, WASM_I32V(kResult0), except2, WASM_I32V(kResult1))});

  // Need to call through JS to allow for creation of stack traces.
  r.CheckCallViaJS(kResult0, 0);
  r.CheckCallViaJS(kResult1, 1);
}

WASM_EXEC_TEST(TryDelegateToCaller) {
  TestSignatures sigs;
  WasmRunner<uint32_t, uint32_t> r(execution_tier);
  uint8_t except = r.builder().AddException(sigs.v_v());
  constexpr uint32_t kResult0 = 23;
  constexpr uint32_t kResult1 = 42;

  // Build the main test function.
  r.Build({WASM_TRY_CATCH_T(
      kWasmI32,
      WASM_TRY_DELEGATE_T(kWasmI32,
                          WASM_STMTS(WASM_I32V(kResult1),
                                     WASM_IF(WASM_I32_EQZ(WASM_LOCAL_GET(0)),
                                             WASM_THROW(except))),
                          1),
      WASM_I32V(kResult0), except)});

  // Need to call through JS to allow for creation of stack traces.
  constexpr int64_t trap = 0xDEADBEEF;
  r.CheckCallViaJS(trap, 0);
  r.CheckCallViaJS(kResult1, 1);
}

WASM_EXEC_TEST(TryCatchCallDirect) {
  TestSignatures sigs;
  WasmRunner<uint32_t, uint32_t> r(execution_tier);
  uint8_t except = r.builder().AddException(sigs.v_v());
  constexpr uint32_t kResult0 = 23;
  constexpr uint32_t kResult1 = 42;

  // Build a throwing helper function.
  WasmFunctionCompiler& throw_func = r.NewFunction(sigs.i_ii());
  throw_func.Build({WASM_THROW(except)});

  // Build the main test function.
  r.Build({WASM_TRY_CATCH_T(
      kWasmI32,
      WASM_STMTS(
          WASM_I32V(kResult1),
          WASM_IF(WASM_I32_EQZ(WASM_LOCAL_GET(0)),
                  WASM_STMTS(WASM_CALL_FUNCTION(throw_func.function_index(),
                                                WASM_I32V(7), WASM_I32V(9)),
                             WASM_DROP))),
      WASM_STMTS(WASM_I32V(kResult0)), except)});

  // Need to call through JS to allow for creation of stack traces.
  r.CheckCallViaJS(kResult0, 0);
  r.CheckCallViaJS(kResult1, 1);
}

WASM_EXEC_TEST(TryCatchAllCallDirect) {
  TestSignatures sigs;
  WasmRunner<uint32_t, uint32_t> r(execution_tier);
  uint8_t except = r.builder().AddException(sigs.v_v());
  constexpr uint32_t kResult0 = 23;
  constexpr uint32_t kResult1 = 42;

  // Build a throwing helper function.
  WasmFunctionCompiler& throw_func = r.NewFunction(sigs.i_ii());
  throw_func.Build({WASM_THROW(except)});

  // Build the main test function.
  r.Build({WASM_TRY_CATCH_ALL_T(
      kWasmI32,
      WASM_STMTS(
          WASM_I32V(kResult1),
          WASM_IF(WASM_I32_EQZ(WASM_LOCAL_GET(0)),
                  WASM_STMTS(WASM_CALL_FUNCTION(throw_func.function_index(),
                                                WASM_I32V(7), WASM_I32V(9)),
                             WASM_DROP))),
      WASM_STMTS(WASM_I32V(kResult0)))});

  // Need to call through JS to allow for creation of stack traces.
  r.CheckCallViaJS(kResult0, 0);
  r.CheckCallViaJS(kResult1, 1);
}

WASM_EXEC_TEST(TryCatchCallIndirect) {
  TestSignatures sigs;
  WasmRunner<uint32_t, uint32_t> r(execution_tier);
  uint8_t except = r.builder().AddException(sigs.v_v());
  constexpr uint32_t kResult0 = 23;
  constexpr uint32_t kResult1 = 42;

  // Build a throwing helper function.
  WasmFunctionCompiler& throw_func = r.NewFunction(sigs.i_ii());
  throw_func.Build({WASM_THROW(except)});

  // Add an indirect function table.
  uint16_t indirect_function_table[] = {
      static_cast<uint16_t>(throw_func.function_index())};
  r.builder().AddIndirectFunctionTable(indirect_function_table,
                                       arraysize(indirect_function_table));

  // Build the main test function.
  r.Build({WASM_TRY_CATCH_T(
      kWasmI32,
      WASM_STMTS(WASM_I32V(kResult1),
                 WASM_IF(WASM_I32_EQZ(WASM_LOCAL_GET(0)),
                         WASM_STMTS(WASM_CALL_INDIRECT(
                                        throw_func.sig_index(), WASM_I32V(7),
                                        WASM_I32V(9), WASM_LOCAL_GET(0)),
                                    WASM_DROP))),
      WASM_I32V(kResult0), except)});

  // Need to call through JS to allow for creation of stack traces.
  r.CheckCallViaJS(kResult0, 0);
  r.CheckCallViaJS(kResult1, 1);
}

WASM_EXEC_TEST(TryCatchAllCallIndirect) {
  TestSignatures sigs;
  WasmRunner<uint32_t, uint32_t> r(execution_tier);
  uint8_t except = r.builder().AddException(sigs.v_v());
  constexpr uint32_t kResult0 = 23;
  constexpr uint32_t kResult1 = 42;

  // Build a throwing helper function.
  WasmFunctionCompiler& throw_func = r.NewFunction(sigs.i_ii());
  throw_func.Build({WASM_THROW(except)});

  // Add an indirect function table.
  uint16_t indirect_function_table[] = {
      static_cast<uint16_t>(throw_func.function_index())};
  r.builder().AddIndirectFunctionTable(indirect_function_table,
                                       arraysize(indirect_function_table));

  // Build the main test function.
  r.Build({WASM_TRY_CATCH_ALL_T(
      kWasmI32,
      WASM_STMTS(WASM_I32V(kResult1),
                 WASM_IF(WASM_I32_EQZ(WASM_LOCAL_GET(0)),
                         WASM_STMTS(WASM_CALL_INDIRECT(
                                        throw_func.sig_index(), WASM_I32V(7),
                                        WASM_I32V(9), WASM_LOCAL_GET(0)),
                                    WASM_DROP))),
      WASM_I32V(kResult0))});

  // Need to call through JS to allow for creation of stack traces.
  r.CheckCallViaJS(kResult0, 0);
  r.CheckCallViaJS(kResult1, 1);
}

WASM_COMPILED_EXEC_TEST(TryCatchCallExternal) {
  TestSignatures sigs;
  HandleScope scope(CcTest::InitIsolateOnce());
  const char* source = "(function() { throw 'ball'; })";
  Handle<JSFunction> js_function = Cast<JSFunction>(v8::Utils::OpenHandle(
      *v8::Local<v8::Function>::Cast(CompileRun(source))));
  ManuallyImportedJSFunction import = {sigs.i_ii(), js_function};
  WasmRunner<uint32_t, uint32_t> r(execution_tier, kWasmOrigin, &import);
  constexpr uint32_t kResult0 = 23;
  constexpr uint32_t kResult1 = 42;
  constexpr uint32_t kJSFunc = 0;

  // Build the main test function.
  r.Build({WASM_TRY_CATCH_ALL_T(
      kWasmI32,
      WASM_STMTS(WASM_I32V(kResult1),
                 WASM_IF(WASM_I32_EQZ(WASM_LOCAL_GET(0)),
                         WASM_STMTS(WASM_CALL_FUNCTION(kJSFunc, WASM_I32V(7),
                                                       WASM_I32V(9)),
                                    WASM_DROP))),
      WASM_I32V(kResult0))});

  // Need to call through JS to allow for creation of stack traces.
  r.CheckCallViaJS(kResult0, 0);
  r.CheckCallViaJS(kResult1, 1);
}

WASM_COMPILED_EXEC_TEST(TryCatchAllCallExternal) {
  TestSignatures sigs;
  HandleScope scope(CcTest::InitIsolateOnce());
  const char* source = "(function() { throw 'ball'; })";
  Handle<JSFunction> js_function = Cast<JSFunction>(v8::Utils::OpenHandle(
      *v8::Local<v8::Function>::Cast(CompileRun(source))));
  ManuallyImportedJSFunction import = {sigs.i_ii(), js_function};
  WasmRunner<uint32_t, uint32_t> r(execution_tier, kWasmOrigin, &import);
  constexpr uint32_t kResult0 = 23;
  constexpr uint32_t kResult1 = 42;
  constexpr uint32_t kJSFunc = 0;

  // Build the main test function.
  r.Build({WASM_TRY_CATCH_ALL_T(
      kWasmI32,
      WASM_STMTS(WASM_I32V(kResult1),
                 WASM_IF(WASM_I32_EQZ(WASM_LOCAL_GET(0)),
                         WASM_STMTS(WASM_CALL_FUNCTION(kJSFunc, WASM_I32V(7),
                                                       WASM_I32V(9)),
                                    WASM_DROP))),
      WASM_I32V(kResult0))});

  // Need to call through JS to allow for creation of stack traces.
  r.CheckCallViaJS(kResult0, 0);
  r.CheckCallViaJS(kResult1, 1);
}

namespace {

void TestTrapNotCaught(uint8_t* code, size_t code_size,
                       TestExecutionTier execution_tier) {
  TestSignatures sigs;
  WasmRunner<uint32_t> r(execution_tier, kWasmOrigin, nullptr, "main");
  r.builder().AddMemory(kWasmPageSize);
  constexpr uint32_t kResultSuccess = 23;
  constexpr uint32_t kResultCaught = 47;

  // Add an indirect function table.
  const int kTableSize = 2;
  r.builder().AddIndirectFunctionTable(nullptr, kTableSize);

  // Build a trapping helper function.
  WasmFunctionCompiler& trap_func = r.NewFunction(sigs.i_ii());
  trap_func.Build(base::VectorOf(code, code_size));

  // Build the main test function.
  r.Build({WASM_TRY_CATCH_ALL_T(
      kWasmI32,
      WASM_STMTS(WASM_I32V(kResultSuccess),
                 WASM_CALL_FUNCTION(trap_func.function_index(), WASM_I32V(7),
                                    WASM_I32V(9)),
                 WASM_DROP),
      WASM_STMTS(WASM_I32V(kResultCaught)))});

  // Need to call through JS to allow for creation of stack traces.
  r.CheckCallViaJSTraps();
}

}  // namespace

WASM_EXEC_TEST(TryCatchTrapUnreachable) {
  uint8_t code[] = {WASM_UNREACHABLE};
  TestTrapNotCaught(code, arraysize(code), execution_tier);
}

WASM_EXEC_TEST(TryCatchTrapMemOutOfBounds) {
  uint8_t code[] = {WASM_LOAD_MEM(MachineType::Int32(), WASM_I32V_1(-1))};
  TestTrapNotCaught(code, arraysize(code), execution_tier);
}

WASM_EXEC_TEST(TryCatchTrapDivByZero) {
  uint8_t code[] = {WASM_I32_DIVS(WASM_LOCAL_GET(0), WASM_I32V_1(0))};
  TestTrapNotCaught(code, arraysize(code), execution_tier);
}

WASM_EXEC_TEST(TryCatchTrapRemByZero) {
  uint8_t code[] = {WASM_I32_REMS(WASM_LOCAL_GET(0), WASM_I32V_1(0))};
  TestTrapNotCaught(code, arraysize(code), execution_tier);
}

WASM_EXEC_TEST(TryCatchTrapTableFill) {
  int table_index = 0;
  int length = 10;  // OOB.
  int start = 10;   // OOB.
  uint8_t code[] = {
      WASM_TABLE_FILL(table_index, WASM_I32V(length),
                      WASM_REF_NULL(kFuncRefCode), WASM_I32V(start)),
      WASM_I32V_1(42)};
  TestTrapNotCaught(code, arraysize(code), execution_tier);
}

namespace {
// TODO(cleanup): Define in cctest.h and re-use where appropriate.
class IsolateScope {
 public:
  IsolateScope() {
    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
    isolate_ = v8::Isolate::New(create_params);
    isolate_->Enter();
  }

  ~IsolateScope() {
    isolate_->Exit();
    isolate_->Dispose();
  }

  v8::Isolate* isolate() { return isolate_; }
  Isolate* i_isolate() { return reinterpret_cast<Isolate*>(isolate_); }

 private:
  v8::Isolate* isolate_;
};
}  // namespace

UNINITIALIZED_WASM_EXEC_TEST(TestStackOverflowNotCaught) {
  TestSignatures sigs;
  // v8_flags.stack_size must be set before isolate initialization.
  FlagScope<int32_t> stack_size(&v8_flags.stack_size, 8);

  IsolateScope isolate_scope;
  LocalContext context(isolate_scope.isolate());

  WasmRunner<uint32_t> r(execution_tier, kWasmOrigin, nullptr, "main",
                         isolate_scope.i_isolate());

  // Build a function that calls itself until stack overflow.
  WasmFunctionCompiler& stack_overflow = r.NewFunction(sigs.v_v());
  stack_overflow.Build({kExprCallFunction,
                        static_cast<uint8_t>(stack_overflow.function_index())});

  // Build the main test function.
  r.Build({WASM_TRY_CATCH_ALL_T(
      kWasmI32,
      WASM_STMTS(WASM_I32V(1), kExprCallFunction,
                 static_cast<uint8_t>(stack_overflow.function_index())),
      WASM_STMTS(WASM_I32V(1)))});

  // Need to call through JS to allow for creation of stack traces.
  r.CheckCallViaJSTraps();
}

}  // namespace v8::internal::wasm

"""

```