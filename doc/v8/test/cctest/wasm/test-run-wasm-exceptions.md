Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understand the Goal:** The request asks for a functional description of a V8 source code file (`test-run-wasm-exceptions.cc`), its relationship to JavaScript, potential Torque involvement, code logic analysis with examples, and common programming errors it might expose.

2. **Initial Assessment:** The filename `test-run-wasm-exceptions.cc` immediately suggests that this file contains tests related to WebAssembly (Wasm) exception handling within V8. The `.cc` extension confirms it's a C++ source file. The copyright notice reinforces it's part of the V8 project.

3. **Identify Key V8/Wasm Concepts:**  Scanning the `#include` directives and the code itself reveals several important V8 and Wasm concepts being used:
    * `v8-function.h`:  Indicates interaction with V8 functions.
    * `api-inl.h`:  Likely involves V8 API usage.
    * `wasm-atomics-utils.h`:  Potentially related to atomic operations in Wasm (though not heavily used in this particular file).
    * `test-signatures.h`: Suggests the code defines and uses function signatures for testing.
    * `wasm-macro-gen.h`:  Strong indicator of macros used to generate Wasm bytecode within the tests, simplifying the creation of Wasm modules.
    * `WASM_EXEC_TEST`:  A macro likely used to define individual test cases.
    * `WasmRunner`: A helper class for setting up and running Wasm modules in tests.
    * `TryCatch`, `Throw`, `Rethrow`, `Delegate`:  Keywords pointing directly to Wasm exception handling mechanisms.

4. **Analyze Individual Test Cases (WASM_EXEC_TEST):**  The core of the file consists of multiple functions defined using the `WASM_EXEC_TEST` macro. Each of these functions represents a distinct test case for Wasm exception handling. A systematic examination of each test is crucial:

    * **Identify the Scenario:**  What specific exception handling feature is being tested (e.g., `try...catch`, `try...catchall`, `rethrow`, `delegate`)?
    * **Examine the Wasm Bytecode:** The code within `r.Build({...})` uses macros like `WASM_TRY_CATCH_T`, `WASM_THROW`, `WASM_RETHROW`, etc. These macros generate the actual Wasm bytecode for the test. Understanding the meaning of these macros is essential.
    * **Analyze the Input/Output:** Each test calls `r.CheckCallViaJS(...)`. This indicates that the Wasm function is being called from JavaScript (or through a V8 testing harness that simulates a JS call). The arguments to `CheckCallViaJS` represent the expected output for different input values (given as arguments to the Wasm function).
    * **Look for Edge Cases:** Some tests are designed to test specific edge cases, such as throwing and catching exceptions with values, multiple catch blocks, or delegating exception handling.

5. **Determine JavaScript Relevance:** The presence of `r.CheckCallViaJS(...)` in almost every test case immediately establishes a strong link to JavaScript. The tests explicitly call the Wasm functions from a JavaScript context. Furthermore, the comments mention the need to call through JS to allow for the creation of stack traces, indicating a direct connection between Wasm exceptions and JavaScript's error handling mechanisms. To illustrate this, provide a simple JavaScript example of calling a Wasm function that might throw and catching the resulting exception.

6. **Check for Torque:** The request specifically asks about Torque. A quick search for `.tq` file extensions or Torque-specific keywords (like `builtin`) within the provided code reveals no such elements. Therefore, it's safe to conclude that this specific file doesn't use Torque.

7. **Infer Code Logic and Examples:**  Based on the analysis of individual test cases, we can infer the underlying logic of Wasm exception handling. For example, the `TryCatchThrow` test demonstrates the basic `try...catch` mechanism. By looking at the `WASM_IF` condition, we can determine when an exception is thrown and what the expected outcome is. Constructing "Assume input" and "Expected output" scenarios for a few representative tests helps solidify understanding.

8. **Identify Potential Programming Errors:** The tests themselves often highlight scenarios that could lead to errors. For example, the `TryCatchTrapUnreachable`, `TryCatchTrapMemOutOfBounds`, etc., tests demonstrate that certain Wasm instructions can cause traps (runtime errors) if not handled correctly. A common programming error would be failing to anticipate and handle such traps, leading to unexpected program termination. Another error is incorrect exception handling logic (e.g., catching the wrong type of exception or not rethrowing when necessary).

9. **Structure the Answer:** Organize the findings into logical sections based on the original request: functionality, Torque relevance, JavaScript examples, code logic examples, and common programming errors. Use clear and concise language, and provide concrete examples where possible.

10. **Review and Refine:**  Read through the generated answer to ensure accuracy, completeness, and clarity. Check for any inconsistencies or areas where further explanation might be needed. For example, ensure the JavaScript example accurately reflects how Wasm modules are instantiated and called in JavaScript.

By following these steps, a comprehensive and accurate analysis of the provided V8 source code can be achieved. The process involves understanding the context, identifying key concepts, analyzing individual components, drawing connections to JavaScript and potential error scenarios, and finally, organizing the findings into a well-structured response.
好的，让我们来分析一下 `v8/test/cctest/wasm/test-run-wasm-exceptions.cc` 这个 V8 源代码文件的功能。

**文件功能概述**

`v8/test/cctest/wasm/test-run-wasm-exceptions.cc`  是一个 C++ 文件，它包含了针对 V8 中 WebAssembly (Wasm) 异常处理功能的集成测试。  这个文件中的测试用例旨在验证 Wasm 的 `try`, `catch`, `throw`, `rethrow`, 和 `delegate` 等异常处理机制是否按预期工作。

**具体功能点列举**

这个文件中的每个 `WASM_EXEC_TEST` 宏定义了一个独立的测试用例，以下是这些测试用例涵盖的功能：

1. **`TryCatchThrow`**:
   - 测试基本的 `try...catch` 结构，当 `throw` 语句被执行时，控制流是否能正确跳转到 `catch` 块。
   - 验证在 `try` 块中抛出异常后，`catch` 块中的代码会被执行。

2. **`TryCatchThrowWithValue`**:
   - 测试抛出带有值的异常，但这里的 `catch` 块并没有接收或使用这个值，主要关注控制流的跳转。

3. **`TryMultiCatchThrow`**:
   - 测试带有多个 `catch` 块的 `try` 结构。
   - 验证根据抛出的异常类型（通过不同的异常索引），控制流会跳转到匹配的 `catch` 块。

4. **`TryCatchAllThrow`**:
   - 测试 `catchall` 块，它可以捕获任何类型的异常，无论其具体类型如何。

5. **`TryCatchCatchAllThrow`**:
   - 测试 `catch` 块和 `catchall` 块的组合使用，验证当有特定类型的 `catch` 块时，`catchall` 是否只在没有匹配的 `catch` 块时执行。

6. **`TryImplicitRethrow`**:
   - 测试嵌套的 `try...catch` 结构以及隐式的重新抛出行为。
   - 当内部的 `catch` 块没有处理异常时，异常会被自动向上传递到外部的 `catch` 块。

7. **`TryDelegate`**:
   - 测试 `try...delegate` 结构，它允许将异常处理委托给调用栈上的上一层 `try` 块。

8. **`TestCatchlessTry`**:
   - 测试只有 `try` 块而没有 `catch` 块的情况，这通常用于确保在没有处理程序的情况下，异常能够正确地传播。

9. **`TryCatchRethrow`**:
   - 测试在 `catch` 块中使用 `rethrow` 语句，将捕获的异常再次抛出，以便更上层的 `try...catch` 结构能够处理它。

10. **`TryDelegateToCaller`**:
    - 类似于 `TryDelegate`，但可能更侧重于验证委托给调用者的机制和行为，可能涉及跨函数调用边界的异常处理。

11. **`TryCatchCallDirect`**:
    - 测试在 `try` 块中直接调用一个会抛出异常的 WebAssembly 函数，并确保异常能被正确的 `catch` 块捕获。

12. **`TryCatchAllCallDirect`**:
    - 与 `TryCatchCallDirect` 类似，但使用 `catchall` 块来捕获来自直接调用的函数的异常。

13. **`TryCatchCallIndirect`**:
    - 测试通过函数指针表（indirect function table）间接调用一个会抛出异常的 WebAssembly 函数，并验证异常处理机制。

14. **`TryCatchAllCallIndirect`**:
    - 与 `TryCatchCallIndirect` 类似，但使用 `catchall` 块捕获异常。

15. **`TryCatchCallExternal` 和 `TryCatchAllCallExternal`**:
    - 测试从 WebAssembly 代码中调用 JavaScript 函数，并且这个 JavaScript 函数抛出一个 JavaScript 异常（例如，`throw 'ball';`）。
    - 验证 Wasm 的异常处理机制能否捕获来自外部 JavaScript 调用的异常。

16. **`TryCatchTrapUnreachable`, `TryCatchTrapMemOutOfBounds`, `TryCatchTrapDivByZero`, `TryCatchTrapRemByZero`, `TryCatchTrapTableFill`**:
    - 这些测试用例验证 `try...catchall` 结构是否能够捕获由 Wasm 指令引起的 “陷阱”（traps），例如：
        - `unreachable` 指令
        - 内存越界访问
        - 除零错误
        - 表填充错误

17. **`TestStackOverflowNotCaught`**:
    - 这个测试验证栈溢出错误是否 *不会* 被 Wasm 的 `try...catchall` 捕获。栈溢出通常被认为是无法恢复的错误，由 V8 虚拟机自身处理。

**是否为 Torque 源代码**

`v8/test/cctest/wasm/test-run-wasm-exceptions.cc` 以 `.cc` 结尾，明确指出这是一个 **C++** 源代码文件，而不是 Torque 源代码文件。Torque 源代码文件通常以 `.tq` 结尾。

**与 JavaScript 的功能关系 (及 JavaScript 示例)**

这个文件中的测试用例直接关系到 JavaScript 与 WebAssembly 的互操作性，特别是关于异常处理方面。当 Wasm 模块在 JavaScript 环境中运行时，Wasm 中抛出的异常需要能够被 JavaScript 感知和处理，反之亦然（尽管在这个文件中，主要关注 Wasm 捕获来自 Wasm 或 JavaScript 的异常）。

**JavaScript 示例：**

```javascript
async function runWasm() {
  try {
    const response = await fetch('your_wasm_module.wasm');
    const buffer = await response.arrayBuffer();
    const module = await WebAssembly.instantiate(buffer);
    const instance = module.instance;

    // 假设 Wasm 模块中有一个函数可能会抛出异常
    instance.exports.mayThrowException(0); // 假设参数为 0 时会抛出异常

    console.log("Wasm 函数执行成功，没有抛出异常。");
  } catch (e) {
    console.error("捕获到来自 Wasm 的异常:", e);
  }
}

runWasm();
```

在这个例子中，JavaScript 代码尝试调用一个 WebAssembly 函数 `mayThrowException`。如果该 Wasm 函数内部执行了 `throw` 操作，JavaScript 的 `catch` 块会捕获这个异常。V8 的 Wasm 异常处理机制负责将 Wasm 异常转换为 JavaScript 可以理解的错误。

反过来，`TryCatchCallExternal` 和 `TryCatchAllCallExternal` 测试用例验证了 Wasm 代码如何捕获 JavaScript 抛出的异常。

**代码逻辑推理 (假设输入与输出)**

以 `TryCatchThrow` 测试为例：

**假设输入：**  `WasmRunner` 的调用参数为 `0` 和 `1`。

**代码逻辑：**

```c++
  r.Build({WASM_TRY_CATCH_T(
      kWasmI32,
      WASM_STMTS(WASM_I32V(kResult1),
                 WASM_IF(WASM_I32_EQZ(WASM_LOCAL_GET(0)), WASM_THROW(except))),
      WASM_STMTS(WASM_I32V(kResult0)), except)});
```

- 如果输入为 `0` (`WASM_LOCAL_GET(0)` 为 0)，则 `WASM_I32_EQZ` 的结果为真，`WASM_THROW(except)` 会被执行，抛出一个异常。控制流跳转到 `catch` 块，`WASM_I32V(kResult0)` 被执行，函数返回 `kResult0` (23)。
- 如果输入为 `1` (`WASM_LOCAL_GET(0)` 为 1)，则 `WASM_I32_EQZ` 的结果为假，`WASM_THROW(except)` 不会被执行。`try` 块中的 `WASM_I32V(kResult1)` 被执行，函数返回 `kResult1` (42)。

**预期输出：**

- `r.CheckCallViaJS(kResult0, 0);`  当输入为 `0` 时，预期返回 `23`。
- `r.CheckCallViaJS(kResult1, 1);`  当输入为 `1` 时，预期返回 `42`。

**用户常见的编程错误示例**

1. **忘记处理异常：**  在 Wasm 中，如果抛出了异常而没有合适的 `try...catch` 块来捕获它，程序的执行会终止（trap）。这类似于未捕获的 JavaScript 异常导致程序崩溃。

   ```wasm
   ;; 假设以下 Wasm 代码在一个没有 try...catch 的函数中
   (throw $my_exception)
   ```

2. **捕获了错误的异常类型：**  在使用多个 `catch` 块时，如果抛出的异常类型与任何 `catch` 块声明的类型都不匹配，异常将不会被捕获，可能会导致程序终止或被更上层的 `catchall` 捕获。

   ```wasm
   (try
     (throw $exception_a)
   catch $exception_b
     (i32.const 1) ;; 这个 catch 块不会被执行
   end)
   ```

3. **在不需要重新抛出时重新抛出：**  在 `catch` 块中不必要地使用 `rethrow` 可能会导致异常被传播到不希望处理它的地方，或者导致无限循环（如果重新抛出的异常又被同一个 `try...catch` 捕获）。

4. **在异步操作中对异常处理的理解不足：** 虽然这个文件主要关注同步的异常处理，但在涉及 JavaScript Promise 或异步 Wasm 操作时，异常的处理方式可能会更加复杂，需要仔细考虑异常如何在异步边界上传播。

5. **混淆 Wasm 陷阱和异常：**  Wasm 的 “陷阱”（例如，除零错误、内存访问错误）与显式抛出的异常是不同的。`try...catch` 块可以捕获显式抛出的异常，而某些类型的陷阱可能需要使用 `catchall` 来捕获，或者根本无法被 Wasm 的 `try...catch` 结构捕获（如栈溢出）。

总而言之，`v8/test/cctest/wasm/test-run-wasm-exceptions.cc` 是一个关键的测试文件，用于确保 V8 中 WebAssembly 异常处理功能的正确性和可靠性，它覆盖了各种异常处理场景和与 JavaScript 的互操作。

### 提示词
```
这是目录为v8/test/cctest/wasm/test-run-wasm-exceptions.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/test-run-wasm-exceptions.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
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
```