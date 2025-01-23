Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Understanding the Goal:**

The primary goal is to understand the *functionality* of the `compiler-unittest.cc` file in the V8 project. This means identifying what aspects of the compiler it tests. The prompt also has specific constraints about handling `.tq` files, JavaScript relations, logic, errors, and finally, summarizing the functionality for Part 1.

**2. Initial Scan and Keyword Identification:**

The first step is to quickly scan the code for prominent keywords and patterns. This helps to get a high-level understanding. I see:

* `#include`: Standard C++ includes, including V8-specific headers like `"src/codegen/compiler.h"`, `"include/v8-function.h"`, etc. This immediately tells me it's C++ code interacting with the V8 engine.
* `namespace v8 { namespace internal {`:  This confirms it's within the V8 project's internal structure.
* `TEST_F(CompilerTest, ...)`:  This is the telltale sign of Google Test unit tests. Each `TEST_F` defines a specific test case.
* `Compile(const char* source)`: A function that compiles JavaScript source code. This is a core function for this test file.
* `Execution::CallScript(...)`:  Used to execute compiled JavaScript.
* `SetGlobalProperty(...)`, `GetGlobalProperty(...)`: Functions to interact with the global object in JavaScript.
* Simple arithmetic and control flow examples within the `Compile` calls (`"result = %d + 1;"`, `"result = x + y;"`, `"if (x < 0) ..."` etc.).
* More complex JavaScript examples involving objects, functions, constructors, and error handling.
* Mentions of "Turbofan" (an optimizing compiler in V8).
*  `%PrepareFunctionForOptimization`, `%OptimizeFunctionOnNextCall`:  Native syntax hinting at testing optimization pathways.
* `CompileFunction(...)`: A specific V8 API for compiling functions.
*  Script origin (`v8::ScriptOrigin`).
* Eager vs. lazy compilation (`kEagerCompile`, `kNoCompileOptions`).

**3. Grouping Tests by Functionality:**

Based on the keywords and examples, I can start grouping the tests to understand their focus:

* **Basic Compilation and Execution:** `Inc`, `Add`, `Abs`, `Sum`. These tests compile simple JavaScript snippets and check the results.
* **Interaction with Global Scope:** The use of `SetGlobalProperty` and `GetGlobalProperty` in `Add`, `Abs`, and `Sum` suggests tests focused on how compiled code interacts with the global object.
* **Control Flow and Language Features:** The `Abs` and `Sum` tests cover `if` statements and `while` loops. The `Stuff` test covers object creation, comparisons, function definitions, and constructors.
* **Error Handling:** `UncaughtThrow` tests how the compiler handles exceptions.
* **Calling Built-ins and GC:** `C2JSFrames` is specifically designed to test interactions between C++ and JavaScript, including garbage collection.
* **Script Metadata:** `Regression236` and `GetScriptLineNumber` test how the compiler handles script information like line numbers.
* **Optimization and Feedback:** `FeedbackVectorPreservedAcrossRecompiles`, `FeedbackVectorUnaffectedByScopeChanges`, and `OptimizedCodeSharing1` are clearly focused on testing the optimization pipeline and how feedback is managed during recompilation and across closures.
* **`CompileFunction` API:**  The tests prefixed with `CompileFunction` directly test the functionality and various aspects of the `v8::ScriptCompiler::CompileFunction` API. This includes arguments, context extensions, comments, error handling, script origin, and `toString()` behavior.
* **Invocation Counting:** `InvocationCount` tests the feedback mechanism related to function call counts.
* **Eager Compilation:** `ShallowEagerCompilation` and `DeepEagerCompilation` are specifically about testing different modes of eager compilation.
* **Memory Management (Implicit):** While not explicitly stated as a test objective, `DeepEagerCompilationPeakMemory` hints at observing memory usage patterns during compilation.

**4. Addressing Specific Prompt Requirements:**

* **`.tq` files:** The code explicitly checks for the `.tq` extension and correctly identifies that this file is C++.
* **JavaScript Examples:**  The prompt requires relating the functionality to JavaScript. For each group of tests, I can construct simple JavaScript examples that illustrate the tested concepts. For instance, for `Inc`, the JavaScript equivalent is `result = x + 1;`.
* **Logic Inference (Input/Output):** For the simpler tests, I can provide clear input values and expected outputs. For example, `Inc(3)` should output `4.0`.
* **Common Programming Errors:**  I look for patterns that could relate to typical JavaScript mistakes. The `UncaughtThrow` test directly demonstrates a common error. The `CompileFunctionNonIdentifierArgs` test touches on syntax errors. The `CompileFunctionQuirks` test with `"use strict"` highlights differences between strict and non-strict mode.
* **Summary for Part 1:**  The final step is to synthesize the identified functionalities into a concise summary for the first part of the analysis.

**5. Iterative Refinement and Verification:**

Throughout this process, I constantly re-read the code and the prompt to ensure I'm capturing all the nuances. I double-check my assumptions and ensure the JavaScript examples accurately reflect the C++ test cases. For instance, initially, I might just say "tests basic arithmetic," but then I refine it to be more specific, like "tests the compiler's ability to handle basic arithmetic operations like addition."

**Self-Correction Example:**

Initially, I might overlook the significance of the `%PrepareFunctionForOptimization` and `%OptimizeFunctionOnNextCall` hints. Upon closer inspection and understanding their purpose in V8's optimization pipeline, I'd realize that these tests are specifically targeting the *optimization* aspects of the compiler, not just basic compilation. This would lead to a more accurate categorization and description of those tests.
好的，让我们来分析一下 `v8/test/unittests/compiler/compiler-unittest.cc` 文件的功能。

**文件功能归纳:**

`v8/test/unittests/compiler/compiler-unittest.cc` 是 V8 JavaScript 引擎的单元测试文件，专注于测试 V8 编译器 (`src/codegen/compiler.h`) 的各项功能。  它通过编写一系列的 C++ 测试用例，来验证编译器在不同场景下的行为是否符合预期。

**具体功能点:**

1. **基本的代码编译和执行:**
   - 测试了编译简单的 JavaScript 代码片段并执行的能力，例如加法、减法、条件语句、循环等。
   -  `Inc`, `Add`, `Abs`, `Sum` 等 `TEST_F` 用例就是这类测试。

2. **全局作用域交互:**
   - 测试了编译后的 JavaScript 代码如何与全局作用域进行交互，包括读取和设置全局变量。
   - `SetGlobalProperty` 和 `GetGlobalProperty` 函数用于辅助测试。

3. **复杂 JavaScript 特性测试:**
   -  测试了编译器处理更复杂的 JavaScript 特性的能力，例如对象创建、属性访问、函数定义、构造函数等。
   - `Stuff` 这个 `TEST_F` 用例涵盖了这些特性。

4. **异常处理:**
   - 测试了编译器如何处理 JavaScript 中的异常 (`throw`)。
   - `UncaughtThrow` 用例验证了当代码抛出未捕获的异常时，V8 的行为是否正确。

5. **C++ 和 JavaScript 的交互 (Built-in 函数调用):**
   - 测试了从 C++ 代码调用 JavaScript 内置函数（例如 `gc()`, `print()`）的能力，以及在这种调用过程中可能发生的垃圾回收等情况。
   - `C2JSFrames` 用例模拟了这种场景。

6. **脚本元数据测试:**
   - 测试了编译器对脚本元数据的处理，例如获取脚本的行号等信息。
   - `Regression236` 和 `GetScriptLineNumber` 用例关注这方面。

7. **优化和反馈向量:**
   - 测试了 V8 的优化管道，包括类型反馈的收集和在重新编译后是否能被正确保留和使用。
   - `FeedbackVectorPreservedAcrossRecompiles`, `FeedbackVectorUnaffectedByScopeChanges`, `OptimizedCodeSharing1` 等用例都与此相关。

8. **`v8::ScriptCompiler::CompileFunction` API 测试:**
   -  测试了 V8 提供的 `CompileFunction` API 的各种用法，包括编译独立函数、传递上下文扩展、指定参数、处理注释、处理错误情况以及生成 `toString()` 输出等。
   -  以 `CompileFunction` 开头的多个 `TEST_F` 用例都属于此类。

9. **调用计数 (Invocation Count):**
   - 测试了反馈向量中记录的函数调用次数是否正确。
   - `InvocationCount` 用例用于验证此功能。

10. **Eager 编译测试:**
    - 测试了 V8 的 eager 编译模式，验证了在 eager 编译模式下代码是否被正确编译和执行。
    - `ShallowEagerCompilation` 和 `DeepEagerCompilation` 用例测试了不同深度的 eager 编译。

**关于文件名的说明:**

你提供的代码是 `.cc` 结尾，这是一个标准的 C++ 源文件扩展名。如果文件以 `.tq` 结尾，那它才是 V8 Torque 源代码。所以，根据你提供的信息，`v8/test/unittests/compiler/compiler-unittest.cc` 是 **C++ 源代码**。

**与 JavaScript 功能的关系及示例:**

这个 C++ 文件直接测试了 V8 编译器的功能，而编译器是将 JavaScript 代码转换为机器码的关键组件。  因此，这个文件中的每一个测试用例都间接地与 JavaScript 的功能有关。

**JavaScript 示例:**

让我们结合一些 `TEST_F` 用例来举例说明：

* **`TEST_F(CompilerTest, Inc)`:**
   - **对应 JavaScript 功能:** 加法运算。
   - **C++ 代码逻辑:** 编译并执行 JavaScript 代码 `"result = 3 + 1;"`，然后检查全局变量 `result` 的值是否为 4。
   - **JavaScript 示例:**
     ```javascript
     let result = 3 + 1;
     console.log(result); // 输出 4
     ```

* **`TEST_F(CompilerTest, Add)`:**
   - **对应 JavaScript 功能:**  变量赋值和加法运算。
   - **C++ 代码逻辑:** 先设置全局变量 `x` 和 `y` 的值，然后编译并执行 JavaScript 代码 `"result = x + y;"`，最后检查 `result` 的值。
   - **JavaScript 示例:**
     ```javascript
     let x = 2;
     let y = 3;
     let result = x + y;
     console.log(result); // 输出 5
     ```

* **`TEST_F(CompilerTest, Abs)`:**
   - **对应 JavaScript 功能:** 条件语句 (`if`) 和取反运算。
   - **C++ 代码逻辑:** 设置全局变量 `x`，编译并执行包含 `if` 语句的 JavaScript 代码，计算绝对值。
   - **JavaScript 示例:**
     ```javascript
     let x = -3;
     let result;
     if (x < 0) {
       result = -x;
     } else {
       result = x;
     }
     console.log(result); // 输出 3
     ```

* **`TEST_F(CompilerTest, Sum)`:**
   - **对应 JavaScript 功能:** 循环语句 (`while`) 和变量累加。
   - **C++ 代码逻辑:** 设置全局变量 `n`，编译并执行包含 `while` 循环的 JavaScript 代码，计算 1 到 n 的和。
   - **JavaScript 示例:**
     ```javascript
     let n = 100;
     let s = 0;
     while (n > 0) {
       s += n;
       n -= 1;
     }
     console.log(s); // 输出 5050
     ```

* **`TEST_F(CompilerTest, Stuff)`:**
   - **对应 JavaScript 功能:** 对象创建、属性访问、比较运算符、函数定义、构造函数等。
   - **C++ 代码逻辑:**  编译并执行一段包含了多种 JavaScript 特性的代码，并检查最终结果。
   - **JavaScript 示例:**  （与 C++ 代码中的 JavaScript 字符串内容一致）
     ```javascript
     r = 0;
     a = new Object();
     if (a == a) r+=1;
     if (a != new Object()) r+=2;
     a.x = 42;
     if (a.x == 42) r+=4;
     function foo() { var x = 87; return x; }
     if (foo() == 87) r+=8;
     function bar() { var x; x = 99; return x; }
     if (bar() == 99) r+=16;
     function baz() { var x = 1, y, z = 2; y = 3; return x + y + z; }
     if (baz() == 6) r+=32;
     function Cons0() { this.x = 42; this.y = 87; }
     if (new Cons0().x == 42) r+=64;
     if (new Cons0().y == 87) r+=128;
     function Cons2(x, y) { this.sum = x + y; }
     if (new Cons2(3,4).sum == 7) r+=256;
     ```

* **`TEST_F(CompilerTest, UncaughtThrow)`:**
   - **对应 JavaScript 功能:** 抛出异常 (`throw`)。
   - **C++ 代码逻辑:** 编译并执行 `throw 42;`，然后检查 V8 是否捕获了异常，并且异常值是否为 42。
   - **JavaScript 示例:**
     ```javascript
     throw 42;
     ```

**代码逻辑推理 (假设输入与输出):**

对于像 `Inc`, `Add`, `Abs`, `Sum` 这样的简单测试，我们可以很容易地进行逻辑推理。

* **`Inc`:**
    - **假设输入:** `x = 3`
    - **JavaScript 代码:** `"result = 3 + 1;"`
    - **预期输出:** 全局变量 `result` 的值为 `4.0`

* **`Add`:**
    - **假设输入:** `x = 2`, `y = 3`
    - **JavaScript 代码:** `"result = x + y;"`
    - **预期输出:** 全局变量 `result` 的值为 `5.0`

* **`Abs`:**
    - **假设输入:** `x = -3`
    - **JavaScript 代码:** `"if (x < 0) result = -x; else result = x;"`
    - **预期输出:** 全局变量 `result` 的值为 `3.0`

* **`Sum`:**
    - **假设输入:** `n = 100`
    - **JavaScript 代码:** `"s = 0; while (n > 0) { s += n; n -= 1; }; result = s;"`
    - **预期输出:** 全局变量 `result` 的值为 `5050.0`

**涉及用户常见的编程错误 (举例说明):**

虽然这个文件主要测试编译器本身，但其中一些测试间接地涉及了用户可能犯的编程错误：

* **未捕获的异常 (`UncaughtThrow`):**  在 JavaScript 中，如果 `throw` 抛出的异常没有被 `try...catch` 捕获，会导致程序终止。`UncaughtThrow` 测试了 V8 在这种情况下的行为。
    ```javascript
    // 常见的错误：忘记捕获可能抛出的异常
    function potentiallyFailingFunction() {
      if (Math.random() < 0.5) {
        throw new Error("Something went wrong!");
      }
      return "Success!";
    }

    // 如果不进行 try...catch，当 potentiallyFailingFunction 抛出异常时，程序会崩溃
    // potentiallyFailingFunction();

    try {
      let result = potentiallyFailingFunction();
      console.log(result);
    } catch (error) {
      console.error("An error occurred:", error.message);
    }
    ```

* **类型错误 (`CompilerTest, CompileFunctionRenderCallSite`):**  尝试调用一个非函数的值会导致 `TypeError`。这个测试用例模拟了这种情况，例如尝试调用数组元素。
    ```javascript
    // 常见的错误：尝试调用非函数
    let a = [1, 2, 3];
    // a[0] 是数字 1，不是函数，尝试调用会抛出 TypeError
    // a[0]();

    try {
      a[0]();
    } catch (e) {
      console.error(e); // 输出 "TypeError: a[0] is not a function"
    }
    ```

* **严格模式下的语法错误 (`CompilerTest, CompileFunctionQuirks`):**  在严格模式下，一些在非严格模式下允许的语法会报错，例如以 `0` 开头的数字被认为是八进制。
    ```javascript
    // 非严格模式下，077 是八进制数 63
    console.log(077); // 输出 63

    // 严格模式下，这会被认为是语法错误
    "use strict";
    // let a = 077; // SyntaxError: Octal literals are not allowed in strict mode.
    ```

**总结 (第 1 部分功能归纳):**

`v8/test/unittests/compiler/compiler-unittest.cc` 文件的主要功能是 **对 V8 JavaScript 引擎的编译器进行全面的单元测试**。它涵盖了从基本的代码编译执行、全局作用域交互，到复杂的语言特性、异常处理、C++/JavaScript 互操作、脚本元数据处理、优化管道验证以及 `CompileFunction` API 测试等多个方面。 这些测试用例旨在确保编译器在各种场景下都能正确地将 JavaScript 代码转换为可执行的机器码，并且能够按照语言规范和 V8 引擎的设计预期运行。 此外，部分测试也间接反映了用户在编写 JavaScript 代码时可能遇到的常见编程错误。

### 提示词
```
这是目录为v8/test/unittests/compiler/compiler-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/compiler-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/codegen/compiler.h"

#include <stdlib.h>
#include <wchar.h>

#include <memory>

#include "include/v8-function.h"
#include "include/v8-local-handle.h"
#include "include/v8-profiler.h"
#include "include/v8-script.h"
#include "src/api/api-inl.h"
#include "src/codegen/compilation-cache.h"
#include "src/codegen/script-details.h"
#include "src/heap/factory.h"
#include "src/objects/allocation-site-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/shared-function-info.h"
#include "test/unittests/heap/heap-utils.h"  // For ManualGCScope.
#include "test/unittests/test-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {

using CompilerTest = TestWithContext;
namespace internal {

static Handle<Object> GetGlobalProperty(const char* name) {
  Isolate* isolate = reinterpret_cast<i::Isolate*>(v8::Isolate::GetCurrent());
  return JSReceiver::GetProperty(isolate, isolate->global_object(), name)
      .ToHandleChecked();
}

static void SetGlobalProperty(const char* name, Tagged<Object> value) {
  Isolate* isolate = reinterpret_cast<i::Isolate*>(v8::Isolate::GetCurrent());
  Handle<Object> object(value, isolate);
  Handle<String> internalized_name =
      isolate->factory()->InternalizeUtf8String(name);
  Handle<JSObject> global(isolate->context()->global_object(), isolate);
  Runtime::SetObjectProperty(isolate, global, internalized_name, object,
                             StoreOrigin::kMaybeKeyed, Just(kDontThrow))
      .Check();
}

static Handle<JSFunction> Compile(const char* source) {
  Isolate* isolate = reinterpret_cast<i::Isolate*>(v8::Isolate::GetCurrent());
  Handle<String> source_code = isolate->factory()
                                   ->NewStringFromUtf8(base::CStrVector(source))
                                   .ToHandleChecked();
  ScriptCompiler::CompilationDetails compilation_details;
  DirectHandle<SharedFunctionInfo> shared =
      Compiler::GetSharedFunctionInfoForScript(
          isolate, source_code, ScriptDetails(),
          v8::ScriptCompiler::kNoCompileOptions,
          ScriptCompiler::kNoCacheNoReason, NOT_NATIVES_CODE,
          &compilation_details)
          .ToHandleChecked();
  return Factory::JSFunctionBuilder{isolate, shared, isolate->native_context()}
      .Build();
}

static double Inc(Isolate* isolate, int x) {
  const char* source = "result = %d + 1;";
  base::EmbeddedVector<char, 512> buffer;
  SNPrintF(buffer, source, x);

  Handle<JSFunction> fun = Compile(buffer.begin());
  if (fun.is_null()) return -1;

  Handle<JSObject> global(isolate->context()->global_object(), isolate);
  Execution::CallScript(isolate, fun, global,
                        isolate->factory()->empty_fixed_array())
      .Check();
  return Object::NumberValue(*GetGlobalProperty("result"));
}

TEST_F(CompilerTest, Inc) {
  v8::HandleScope scope(isolate());
  EXPECT_EQ(4.0, Inc(i_isolate(), 3));
}

static double Add(Isolate* isolate, int x, int y) {
  Handle<JSFunction> fun = Compile("result = x + y;");
  if (fun.is_null()) return -1;

  SetGlobalProperty("x", Smi::FromInt(x));
  SetGlobalProperty("y", Smi::FromInt(y));
  Handle<JSObject> global(isolate->context()->global_object(), isolate);
  Execution::CallScript(isolate, fun, global,
                        isolate->factory()->empty_fixed_array())
      .Check();
  return Object::NumberValue(*GetGlobalProperty("result"));
}

TEST_F(CompilerTest, Add) {
  v8::HandleScope scope(isolate());
  EXPECT_EQ(5.0, Add(i_isolate(), 2, 3));
}

static double Abs(Isolate* isolate, int x) {
  Handle<JSFunction> fun = Compile("if (x < 0) result = -x; else result = x;");
  if (fun.is_null()) return -1;

  SetGlobalProperty("x", Smi::FromInt(x));
  Handle<JSObject> global(isolate->context()->global_object(), isolate);
  Execution::CallScript(isolate, fun, global,
                        isolate->factory()->empty_fixed_array())
      .Check();
  return Object::NumberValue(*GetGlobalProperty("result"));
}

TEST_F(CompilerTest, Abs) {
  v8::HandleScope scope(isolate());
  EXPECT_EQ(3.0, Abs(i_isolate(), -3));
}

static double Sum(Isolate* isolate, int n) {
  Handle<JSFunction> fun =
      Compile("s = 0; while (n > 0) { s += n; n -= 1; }; result = s;");
  if (fun.is_null()) return -1;

  SetGlobalProperty("n", Smi::FromInt(n));
  Handle<JSObject> global(isolate->context()->global_object(), isolate);
  Execution::CallScript(isolate, fun, global,
                        isolate->factory()->empty_fixed_array())
      .Check();
  return Object::NumberValue(*GetGlobalProperty("result"));
}

TEST_F(CompilerTest, Sum) {
  v8::HandleScope scope(isolate());
  EXPECT_EQ(5050.0, Sum(i_isolate(), 100));
}

using CompilerPrintTest = WithPrintExtensionMixin<v8::TestWithIsolate>;

TEST_F(CompilerPrintTest, Print) {
  v8::HandleScope scope(isolate());
  const char* extension_names[1] = {
      WithPrintExtensionMixin::kPrintExtensionName};
  v8::ExtensionConfiguration config(1, extension_names);
  v8::Local<v8::Context> context = v8::Context::New(isolate(), &config);
  v8::Context::Scope context_scope(context);
  const char* source = "for (n = 0; n < 100; ++n) print(n, 1, 2);";
  Handle<JSFunction> fun = Compile(source);
  if (fun.is_null()) return;
  Handle<JSObject> global(i_isolate()->context()->global_object(), i_isolate());
  Execution::CallScript(i_isolate(), fun, global,
                        i_isolate()->factory()->empty_fixed_array())
      .Check();
}

// The following test method stems from my coding efforts today. It
// tests all the functionality I have added to the compiler today
TEST_F(CompilerTest, Stuff) {
  v8::HandleScope scope(isolate());
  const char* source =
      "r = 0;\n"
      "a = new Object;\n"
      "if (a == a) r+=1;\n"             // 1
      "if (a != new Object()) r+=2;\n"  // 2
      "a.x = 42;\n"
      "if (a.x == 42) r+=4;\n"  // 4
      "function foo() { var x = 87; return x; }\n"
      "if (foo() == 87) r+=8;\n"  // 8
      "function bar() { var x; x = 99; return x; }\n"
      "if (bar() == 99) r+=16;\n"  // 16
      "function baz() { var x = 1, y, z = 2; y = 3; return x + y + z; }\n"
      "if (baz() == 6) r+=32;\n"  // 32
      "function Cons0() { this.x = 42; this.y = 87; }\n"
      "if (new Cons0().x == 42) r+=64;\n"   // 64
      "if (new Cons0().y == 87) r+=128;\n"  // 128
      "function Cons2(x, y) { this.sum = x + y; }\n"
      "if (new Cons2(3,4).sum == 7) r+=256;";  // 256

  Handle<JSFunction> fun = Compile(source);
  EXPECT_TRUE(!fun.is_null());
  Handle<JSObject> global(i_isolate()->context()->global_object(), i_isolate());
  Execution::CallScript(i_isolate(), fun, global,
                        i_isolate()->factory()->empty_fixed_array())
      .Check();
  EXPECT_EQ(511.0, Object::NumberValue(*GetGlobalProperty("r")));
}

TEST_F(CompilerTest, UncaughtThrow) {
  v8::HandleScope scope(isolate());

  const char* source = "throw 42;";
  Handle<JSFunction> fun = Compile(source);
  EXPECT_TRUE(!fun.is_null());
  Isolate* isolate = fun->GetIsolate();
  Handle<JSObject> global(isolate->context()->global_object(), isolate);
  EXPECT_TRUE(Execution::CallScript(isolate, fun, global,
                                    isolate->factory()->empty_fixed_array())
                  .is_null());
  EXPECT_EQ(42.0, Object::NumberValue(isolate->exception()));
}

using CompilerC2JSFramesTest = WithPrintExtensionMixin<v8::TestWithIsolate>;

// Tests calling a builtin function from C/C++ code, and the builtin function
// performs GC. It creates a stack frame looks like following:
//   | C (PerformGC) |
//   |   JS-to-C     |
//   |      JS       |
//   |   C-to-JS     |
TEST_F(CompilerC2JSFramesTest, C2JSFrames) {
  v8_flags.expose_gc = true;
  v8::HandleScope scope(isolate());
  const char* extension_names[2] = {
      "v8/gc", WithPrintExtensionMixin::kPrintExtensionName};
  v8::ExtensionConfiguration config(2, extension_names);
  v8::Local<v8::Context> context = v8::Context::New(isolate(), &config);
  v8::Context::Scope context_scope(context);

  const char* source = "function foo(a) { gc(), print(a); }";

  Handle<JSFunction> fun0 = Compile(source);
  EXPECT_TRUE(!fun0.is_null());
  Isolate* isolate = fun0->GetIsolate();

  // Run the generated code to populate the global object with 'foo'.
  Handle<JSObject> global(isolate->context()->global_object(), isolate);
  Execution::CallScript(isolate, fun0, global,
                        isolate->factory()->empty_fixed_array())
      .Check();

  Handle<Object> fun1 =
      JSReceiver::GetProperty(isolate, isolate->global_object(), "foo")
          .ToHandleChecked();
  EXPECT_TRUE(IsJSFunction(*fun1));

  Handle<Object> argv[] = {
      isolate->factory()->InternalizeString(base::StaticCharVector("hello"))};
  Execution::Call(isolate, Cast<JSFunction>(fun1), global, arraysize(argv),
                  argv)
      .Check();
}

// Regression 236. Calling InitLineEnds on a Script with undefined
// source resulted in crash.
TEST_F(CompilerTest, Regression236) {
  Factory* factory = i_isolate()->factory();
  v8::HandleScope scope(isolate());

  DirectHandle<Script> script = factory->NewScript(factory->undefined_value());
  EXPECT_EQ(-1, Script::GetLineNumber(script, 0));
  EXPECT_EQ(-1, Script::GetLineNumber(script, 100));
  EXPECT_EQ(-1, Script::GetLineNumber(script, -1));
}

TEST_F(CompilerTest, GetScriptLineNumber) {
  v8::HandleScope scope(isolate());
  v8::ScriptOrigin origin = v8::ScriptOrigin(NewString("test"));
  const char function_f[] = "function f() {}";
  const int max_rows = 1000;
  const int buffer_size = max_rows + sizeof(function_f);
  base::ScopedVector<char> buffer(buffer_size);
  memset(buffer.begin(), '\n', buffer_size - 1);
  buffer[buffer_size - 1] = '\0';

  for (int i = 0; i < max_rows; ++i) {
    if (i > 0) buffer[i - 1] = '\n';
    MemCopy(&buffer[i], function_f, sizeof(function_f) - 1);
    v8::Local<v8::String> script_body = NewString(buffer.begin());
    v8::Script::Compile(context(), script_body, &origin)
        .ToLocalChecked()
        ->Run(context())
        .ToLocalChecked();
    v8::Local<v8::Function> f = v8::Local<v8::Function>::Cast(
        context()->Global()->Get(context(), NewString("f")).ToLocalChecked());
    EXPECT_EQ(i, f->GetScriptLineNumber());
  }
}

TEST_F(CompilerTest, FeedbackVectorPreservedAcrossRecompiles) {
  if (i::v8_flags.always_turbofan || !i::v8_flags.turbofan) return;
  i::v8_flags.allow_natives_syntax = true;
  if (!i_isolate()->use_optimizer()) return;
  v8::HandleScope scope(isolate());

  // Make sure function f has a call that uses a type feedback slot.
  RunJS(
      "function fun() {};"
      "fun1 = fun;"
      "%PrepareFunctionForOptimization(f);"
      "function f(a) { a(); } f(fun1);");

  DirectHandle<JSFunction> f = Cast<
      JSFunction>(v8::Utils::OpenDirectHandle(*v8::Local<v8::Function>::Cast(
      context()->Global()->Get(context(), NewString("f")).ToLocalChecked())));

  // Verify that we gathered feedback.
  DirectHandle<FeedbackVector> feedback_vector(f->feedback_vector(),
                                               f->GetIsolate());
  EXPECT_TRUE(!feedback_vector->is_empty());
  FeedbackSlot slot_for_a(0);
  Tagged<MaybeObject> object = feedback_vector->Get(slot_for_a);
  {
    Tagged<HeapObject> heap_object;
    EXPECT_TRUE(object.GetHeapObjectIfWeak(&heap_object));
    EXPECT_TRUE(IsJSFunction(heap_object));
  }

  RunJS("%OptimizeFunctionOnNextCall(f); f(fun1);");

  // Verify that the feedback is still "gathered" despite a recompilation
  // of the full code.
  EXPECT_TRUE(f->HasAttachedOptimizedCode(i_isolate()));
  object = f->feedback_vector()->Get(slot_for_a);
  {
    Tagged<HeapObject> heap_object;
    EXPECT_TRUE(object.GetHeapObjectIfWeak(&heap_object));
    EXPECT_TRUE(IsJSFunction(heap_object));
  }
}

TEST_F(CompilerTest, FeedbackVectorUnaffectedByScopeChanges) {
  if (i::v8_flags.always_turbofan || !i::v8_flags.lazy ||
      i::v8_flags.lite_mode) {
    return;
  }
  v8::HandleScope scope(isolate());

  RunJS(
      "function builder() {"
      "  call_target = function() { return 3; };"
      "  return (function() {"
      "    eval('');"
      "    return function() {"
      "      'use strict';"
      "      call_target();"
      "    }"
      "  })();"
      "}"
      "morphing_call = builder();");

  DirectHandle<JSFunction> f = Cast<JSFunction>(
      v8::Utils::OpenDirectHandle(*v8::Local<v8::Function>::Cast(
          context()
              ->Global()
              ->Get(context(), NewString("morphing_call"))
              .ToLocalChecked())));

  // If we are compiling lazily then it should not be compiled, and so no
  // feedback vector allocated yet.
  EXPECT_TRUE(!f->shared()->is_compiled());

  RunJS("morphing_call();");

  // Now a feedback vector / closure feedback cell array is allocated.
  EXPECT_TRUE(f->shared()->is_compiled());
  EXPECT_TRUE(f->has_feedback_vector() || f->has_closure_feedback_cell_array());
}

// Test that optimized code for different closures is actually shared.
TEST_F(CompilerTest, OptimizedCodeSharing1) {
  v8_flags.stress_compaction = false;
  v8_flags.allow_natives_syntax = true;
  v8::HandleScope scope(isolate());
  for (int i = 0; i < 3; i++) {
    context()
        ->Global()
        ->Set(context(), NewString("x"), v8::Integer::New(isolate(), i))
        .FromJust();
    RunJS(
        "function MakeClosure() {"
        "  return function() { return x; };"
        "}"
        "var closure0 = MakeClosure();"
        "var closure1 = MakeClosure();"  // We only share optimized code
                                         // if there are at least two closures.
        "%PrepareFunctionForOptimization(closure0);"
        "%DebugPrint(closure0());"
        "%OptimizeFunctionOnNextCall(closure0);"
        "%DebugPrint(closure0());"
        "closure1();"
        "var closure2 = MakeClosure(); closure2();");
    DirectHandle<JSFunction> fun1 = Cast<JSFunction>(
        v8::Utils::OpenDirectHandle(*v8::Local<v8::Function>::Cast(
            context()
                ->Global()
                ->Get(context(), NewString("closure1"))
                .ToLocalChecked())));
    DirectHandle<JSFunction> fun2 = Cast<JSFunction>(
        v8::Utils::OpenDirectHandle(*v8::Local<v8::Function>::Cast(
            context()
                ->Global()
                ->Get(context(), NewString("closure2"))
                .ToLocalChecked())));
    EXPECT_TRUE(fun1->HasAttachedOptimizedCode(i_isolate()) ||
                !i_isolate()->use_optimizer());
    EXPECT_TRUE(fun2->HasAttachedOptimizedCode(i_isolate()) ||
                !i_isolate()->use_optimizer());
    EXPECT_EQ(fun1->code(i_isolate()), fun2->code(i_isolate()));
  }
}

TEST_F(CompilerTest, CompileFunction) {
  if (i::v8_flags.always_turbofan) return;
  v8::HandleScope scope(isolate());
  RunJS("var r = 10;");
  v8::Local<v8::Object> math = v8::Local<v8::Object>::Cast(
      context()->Global()->Get(context(), NewString("Math")).ToLocalChecked());
  v8::ScriptCompiler::Source script_source(
      NewString("a = PI * r * r;"
                "x = r * cos(PI);"
                "y = r * sin(PI / 2);"));
  v8::Local<v8::Function> fun =
      v8::ScriptCompiler::CompileFunction(context(), &script_source, 0, nullptr,
                                          1, &math)
          .ToLocalChecked();
  EXPECT_TRUE(!fun.IsEmpty());

  i::DisallowCompilation no_compile(i_isolate());
  fun->Call(context(), context()->Global(), 0, nullptr).ToLocalChecked();
  EXPECT_TRUE(context()->Global()->Has(context(), NewString("a")).FromJust());
  v8::Local<v8::Value> a =
      context()->Global()->Get(context(), NewString("a")).ToLocalChecked();
  EXPECT_TRUE(a->IsNumber());
  EXPECT_TRUE(context()->Global()->Has(context(), NewString("x")).FromJust());
  v8::Local<v8::Value> x =
      context()->Global()->Get(context(), NewString("x")).ToLocalChecked();
  EXPECT_TRUE(x->IsNumber());
  EXPECT_TRUE(context()->Global()->Has(context(), NewString("y")).FromJust());
  v8::Local<v8::Value> y =
      context()->Global()->Get(context(), NewString("y")).ToLocalChecked();
  EXPECT_TRUE(y->IsNumber());
  EXPECT_EQ(314.1592653589793, a->NumberValue(context()).FromJust());
  EXPECT_EQ(-10.0, x->NumberValue(context()).FromJust());
  EXPECT_EQ(10.0, y->NumberValue(context()).FromJust());
}

TEST_F(CompilerTest, CompileFunctionComplex) {
  v8::HandleScope scope(isolate());
  RunJS(
      "var x = 1;"
      "var y = 2;"
      "var z = 4;"
      "var a = {x: 8, y: 16};"
      "var b = {x: 32};");
  v8::Local<v8::Object> ext[2];
  ext[0] = v8::Local<v8::Object>::Cast(
      context()->Global()->Get(context(), NewString("a")).ToLocalChecked());
  ext[1] = v8::Local<v8::Object>::Cast(
      context()->Global()->Get(context(), NewString("b")).ToLocalChecked());
  v8::ScriptCompiler::Source script_source(NewString("result = x + y + z"));
  v8::Local<v8::Function> fun =
      v8::ScriptCompiler::CompileFunction(context(), &script_source, 0, nullptr,
                                          2, ext)
          .ToLocalChecked();
  EXPECT_TRUE(!fun.IsEmpty());
  fun->Call(context(), context()->Global(), 0, nullptr).ToLocalChecked();
  EXPECT_TRUE(
      context()->Global()->Has(context(), NewString("result")).FromJust());
  v8::Local<v8::Value> result =
      context()->Global()->Get(context(), NewString("result")).ToLocalChecked();
  EXPECT_TRUE(result->IsNumber());
  EXPECT_EQ(52.0, result->NumberValue(context()).FromJust());
}

TEST_F(CompilerTest, CompileFunctionArgs) {
  v8::HandleScope scope(isolate());
  RunJS("var a = {x: 23};");
  v8::Local<v8::Object> ext[1];
  ext[0] = v8::Local<v8::Object>::Cast(
      context()->Global()->Get(context(), NewString("a")).ToLocalChecked());
  v8::ScriptCompiler::Source script_source(NewString("result = x + abc"));
  v8::Local<v8::String> arg = NewString("abc");
  v8::Local<v8::Function> fun = v8::ScriptCompiler::CompileFunction(
                                    context(), &script_source, 1, &arg, 1, ext)
                                    .ToLocalChecked();
  EXPECT_EQ(1, fun->Get(context(), NewString("length"))
                   .ToLocalChecked()
                   ->ToInt32(context())
                   .ToLocalChecked()
                   ->Value());
  v8::Local<v8::Value> arg_value = v8::Number::New(isolate(), 42.0);
  fun->Call(context(), context()->Global(), 1, &arg_value).ToLocalChecked();
  EXPECT_TRUE(
      context()->Global()->Has(context(), NewString("result")).FromJust());
  v8::Local<v8::Value> result =
      context()->Global()->Get(context(), NewString("result")).ToLocalChecked();
  EXPECT_TRUE(result->IsNumber());
  EXPECT_EQ(65.0, result->NumberValue(context()).FromJust());
}

TEST_F(CompilerTest, CompileFunctionComments) {
  v8::HandleScope scope(isolate());
  RunJS("var a = {x: 23, y: 1, z: 2};");
  v8::Local<v8::Object> ext[1];
  ext[0] = v8::Local<v8::Object>::Cast(
      context()->Global()->Get(context(), NewString("a")).ToLocalChecked());
  v8::Local<v8::String> source =
      RunJS("'result = /* y + */ x + a\\u4e00 // + z'").As<v8::String>();
  v8::ScriptCompiler::Source script_source(source);
  v8::Local<v8::String> arg = RunJS("'a\\u4e00'").As<v8::String>();
  v8::Local<v8::Function> fun = v8::ScriptCompiler::CompileFunction(
                                    context(), &script_source, 1, &arg, 1, ext)
                                    .ToLocalChecked();
  EXPECT_TRUE(!fun.IsEmpty());
  v8::Local<v8::Value> arg_value = v8::Number::New(isolate(), 42.0);
  fun->Call(context(), context()->Global(), 1, &arg_value).ToLocalChecked();
  EXPECT_TRUE(
      context()->Global()->Has(context(), NewString("result")).FromJust());
  v8::Local<v8::Value> result =
      context()->Global()->Get(context(), NewString("result")).ToLocalChecked();
  EXPECT_TRUE(result->IsNumber());
  EXPECT_EQ(65.0, result->NumberValue(context()).FromJust());
}

TEST_F(CompilerTest, CompileFunctionNonIdentifierArgs) {
  v8::HandleScope scope(isolate());
  v8::ScriptCompiler::Source script_source(NewString("result = 1"));
  v8::Local<v8::String> arg = NewString("b }");
  EXPECT_TRUE(
      v8::ScriptCompiler::CompileFunction(context(), &script_source, 1, &arg)
          .IsEmpty());
}

TEST_F(CompilerTest, CompileFunctionRenderCallSite) {
  v8::HandleScope scope(isolate());
  static const char* source1 =
      "try {"
      "  var a = [];"
      "  a[0]();"
      "} catch (e) {"
      "  return e.toString();"
      "}";
  static const char* expect1 = "TypeError: a[0] is not a function";
  static const char* source2 =
      "try {"
      "  (function() {"
      "    var a = [];"
      "    a[0]();"
      "  })()"
      "} catch (e) {"
      "  return e.toString();"
      "}";
  static const char* expect2 = "TypeError: a[0] is not a function";
  {
    v8::ScriptCompiler::Source script_source(NewString(source1));
    v8::Local<v8::Function> fun =
        v8::ScriptCompiler::CompileFunction(context(), &script_source)
            .ToLocalChecked();
    EXPECT_TRUE(!fun.IsEmpty());
    v8::Local<v8::Value> result =
        fun->Call(context(), context()->Global(), 0, nullptr).ToLocalChecked();
    EXPECT_TRUE(result->IsString());
    EXPECT_TRUE(v8::Local<v8::String>::Cast(result)
                    ->Equals(context(), NewString(expect1))
                    .FromJust());
  }
  {
    v8::ScriptCompiler::Source script_source(NewString(source2));
    v8::Local<v8::Function> fun =
        v8::ScriptCompiler::CompileFunction(context(), &script_source)
            .ToLocalChecked();
    v8::Local<v8::Value> result =
        fun->Call(context(), context()->Global(), 0, nullptr).ToLocalChecked();
    EXPECT_TRUE(result->IsString());
    EXPECT_TRUE(v8::Local<v8::String>::Cast(result)
                    ->Equals(context(), NewString(expect2))
                    .FromJust());
  }
}

TEST_F(CompilerTest, CompileFunctionQuirks) {
  v8::HandleScope scope(isolate());
  {
    static const char* source =
        "[x, y] = ['ab', 'cd'];"
        "return x + y";
    static const char* expect = "abcd";
    v8::ScriptCompiler::Source script_source(NewString(source));
    v8::Local<v8::Function> fun =
        v8::ScriptCompiler::CompileFunction(context(), &script_source)
            .ToLocalChecked();
    v8::Local<v8::Value> result =
        fun->Call(context(), context()->Global(), 0, nullptr).ToLocalChecked();
    EXPECT_TRUE(result->IsString());
    EXPECT_TRUE(v8::Local<v8::String>::Cast(result)
                    ->Equals(context(), NewString(expect))
                    .FromJust());
  }
  {
    static const char* source = "'use strict'; var a = 077";
    v8::ScriptCompiler::Source script_source(NewString(source));
    v8::TryCatch try_catch(isolate());
    EXPECT_TRUE(v8::ScriptCompiler::CompileFunction(context(), &script_source)
                    .IsEmpty());
    EXPECT_TRUE(try_catch.HasCaught());
  }
  {
    static const char* source = "{ let x; { var x } }";
    v8::ScriptCompiler::Source script_source(NewString(source));
    v8::TryCatch try_catch(isolate());
    EXPECT_TRUE(v8::ScriptCompiler::CompileFunction(context(), &script_source)
                    .IsEmpty());
    EXPECT_TRUE(try_catch.HasCaught());
  }
}

TEST_F(CompilerTest, CompileFunctionScriptOrigin) {
  v8::HandleScope scope(isolate());
  v8::ScriptOrigin origin(NewString("test"), 22, 41);
  v8::ScriptCompiler::Source script_source(NewString("throw new Error()"),
                                           origin);
  v8::Local<v8::Function> fun =
      v8::ScriptCompiler::CompileFunction(context(), &script_source)
          .ToLocalChecked();
  EXPECT_TRUE(!fun.IsEmpty());
  auto fun_i = i::Cast<i::JSFunction>(Utils::OpenHandle(*fun));
  EXPECT_TRUE(IsSharedFunctionInfo(fun_i->shared()));
  EXPECT_TRUE(
      Utils::ToLocal(
          i::handle(i::Cast<i::Script>(fun_i->shared()->script())->name(),
                    i_isolate()))
          ->StrictEquals(NewString("test")));
  v8::TryCatch try_catch(isolate());
  isolate()->SetCaptureStackTraceForUncaughtExceptions(true);
  EXPECT_TRUE(fun->Call(context(), context()->Global(), 0, nullptr).IsEmpty());
  EXPECT_TRUE(try_catch.HasCaught());
  EXPECT_TRUE(!try_catch.Exception().IsEmpty());
  v8::Local<v8::StackTrace> stack =
      v8::Exception::GetStackTrace(try_catch.Exception());
  EXPECT_TRUE(!stack.IsEmpty());
  EXPECT_GT(stack->GetFrameCount(), 0);
  v8::Local<v8::StackFrame> frame = stack->GetFrame(isolate(), 0);
  EXPECT_EQ(23, frame->GetLineNumber());
  EXPECT_EQ(42 + strlen("throw "), static_cast<unsigned>(frame->GetColumn()));
}

TEST_F(CompilerTest, CompileFunctionFunctionToString) {
#define CHECK_NOT_CAUGHT(__local_context__, try_catch, __op__)                 \
  do {                                                                         \
    const char* op = (__op__);                                                 \
    if (try_catch.HasCaught()) {                                               \
      v8::String::Utf8Value error(isolate(), try_catch.Exception()             \
                                                 ->ToString(__local_context__) \
                                                 .ToLocalChecked());           \
      FATAL("Unexpected exception thrown during %s:\n\t%s\n", op, *error);     \
    }                                                                          \
  } while (false)

  {
    v8::HandleScope scope(isolate());

    // Regression test for v8:6190
    {
      v8::ScriptOrigin origin(NewString("test"), 22, 41);
      v8::ScriptCompiler::Source script_source(NewString("return event"),
                                               origin);

      v8::Local<v8::String> params[] = {NewString("event")};
      v8::TryCatch try_catch(isolate());
      v8::MaybeLocal<v8::Function> maybe_fun =
          v8::ScriptCompiler::CompileFunction(context(), &script_source,
                                              arraysize(params), params);

      CHECK_NOT_CAUGHT(context(), try_catch,
                       "v8::ScriptCompiler::CompileFunction");

      v8::Local<v8::Function> fun = maybe_fun.ToLocalChecked();
      EXPECT_TRUE(!fun.IsEmpty());
      EXPECT_TRUE(!try_catch.HasCaught());
      v8::Local<v8::String> result = fun->ToString(context()).ToLocalChecked();
      v8::Local<v8::String> expected = NewString(
          "function (event) {\n"
          "return event\n"
          "}");
      EXPECT_TRUE(expected->Equals(context(), result).FromJust());
    }

    // With no parameters:
    {
      v8::ScriptOrigin origin(NewString("test"), 17, 31);
      v8::ScriptCompiler::Source script_source(NewString("return 0"), origin);

      v8::TryCatch try_catch(isolate());
      v8::MaybeLocal<v8::Function> maybe_fun =
          v8::ScriptCompiler::CompileFunction(context(), &script_source);

      CHECK_NOT_CAUGHT(context(), try_catch,
                       "v8::ScriptCompiler::CompileFunction");

      v8::Local<v8::Function> fun = maybe_fun.ToLocalChecked();
      EXPECT_TRUE(!fun.IsEmpty());
      EXPECT_TRUE(!try_catch.HasCaught());
      v8::Local<v8::String> result = fun->ToString(context()).ToLocalChecked();
      v8::Local<v8::String> expected = NewString(
          "function () {\n"
          "return 0\n"
          "}");
      EXPECT_TRUE(expected->Equals(context(), result).FromJust());
    }

    // With a name:
    {
      v8::ScriptOrigin origin(NewString("test"), 17, 31);
      v8::ScriptCompiler::Source script_source(NewString("return 0"), origin);

      v8::TryCatch try_catch(isolate());
      v8::MaybeLocal<v8::Function> maybe_fun =
          v8::ScriptCompiler::CompileFunction(context(), &script_source);

      CHECK_NOT_CAUGHT(context(), try_catch,
                       "v8::ScriptCompiler::CompileFunction");

      v8::Local<v8::Function> fun = maybe_fun.ToLocalChecked();
      EXPECT_TRUE(!fun.IsEmpty());
      EXPECT_TRUE(!try_catch.HasCaught());

      fun->SetName(NewString("onclick"));

      v8::Local<v8::String> result = fun->ToString(context()).ToLocalChecked();
      v8::Local<v8::String> expected = NewString(
          "function onclick() {\n"
          "return 0\n"
          "}");
      EXPECT_TRUE(expected->Equals(context(), result).FromJust());
    }
  }
#undef CHECK_NOT_CAUGHT
}

TEST_F(CompilerTest, InvocationCount) {
  if (v8_flags.lite_mode) return;
  v8_flags.allow_natives_syntax = true;
  v8_flags.always_turbofan = false;
  v8::HandleScope scope(isolate());

  RunJS(
      "function bar() {};"
      "%EnsureFeedbackVectorForFunction(bar);"
      "function foo() { return bar(); };"
      "%EnsureFeedbackVectorForFunction(foo);"
      "foo();");
  DirectHandle<JSFunction> foo = Cast<JSFunction>(GetGlobalProperty("foo"));
  EXPECT_EQ(1, foo->feedback_vector()->invocation_count());
  RunJS("foo()");
  EXPECT_EQ(2, foo->feedback_vector()->invocation_count());
  RunJS("bar()");
  EXPECT_EQ(2, foo->feedback_vector()->invocation_count());
  RunJS("foo(); foo()");
  EXPECT_EQ(4, foo->feedback_vector()->invocation_count());
}

TEST_F(CompilerTest, ShallowEagerCompilation) {
  i::v8_flags.always_turbofan = false;
  v8::HandleScope scope(isolate());
  v8::Local<v8::String> source = NewString(
      "function f(x) {"
      "  return x + x;"
      "}"
      "f(2)");
  v8::ScriptCompiler::Source script_source(source);
  v8::Local<v8::Script> script =
      v8::ScriptCompiler::Compile(context(), &script_source,
                                  v8::ScriptCompiler::kEagerCompile)
          .ToLocalChecked();
  {
    v8::internal::DisallowCompilation no_compile_expected(i_isolate());
    v8::Local<v8::Value> result = script->Run(context()).ToLocalChecked();
    EXPECT_EQ(4, result->Int32Value(context()).FromJust());
  }
}

TEST_F(CompilerTest, DeepEagerCompilation) {
  i::v8_flags.always_turbofan = false;
  v8::HandleScope scope(isolate());
  v8::Local<v8::String> source = NewString(
      "function f(x) {"
      "  function g(x) {"
      "    function h(x) {"
      "      return x ** x;"
      "    }"
      "    return h(x) * h(x);"
      "  }"
      "  return g(x) + g(x);"
      "}"
      "f(2)");
  v8::ScriptCompiler::Source script_source(source);
  v8::Local<v8::Script> script =
      v8::ScriptCompiler::Compile(context(), &script_source,
                                  v8::ScriptCompiler::kEagerCompile)
          .ToLocalChecked();
  {
    v8::internal::DisallowCompilation no_compile_expected(i_isolate());
    v8::Local<v8::Value> result = script->Run(context()).ToLocalChecked();
    EXPECT_EQ(32, result->Int32Value(context()).FromJust());
  }
}

TEST_F(CompilerTest, DeepEagerCompilationPeakMemory) {
  i::v8_flags.always_turbofan = false;
  v8::HandleScope scope(isolate());
  v8::Local<v8::String> source = NewString(
      "function f() {"
      "  function g1() {"
      "    function h1() {"
      "      function i1() {}"
      "      function i2() {}"
      "    }"
      "    function h2() {"
      "      function i1() {}"
      "      function i2() {}"
      "    }"
      "  }"
      "  function g2() {"
      "    function h1() {"
      "      function i1() {}"
      "      function i2() {}"
      "    }"
      "    function h2() {"
      "      function i1() {}"
      "      function i2() {}"
      "    }"
      "  }"
      "}");
  v8::ScriptCompiler::Source script_source(source);
  i_isolate()->compilation_cache()->DisableScriptAndEval();

  v8::HeapStatistics heap_statistics;
  isolate()->GetHeapStatistics(&heap_statistics);
  size_t peak_mem_after_init = heap_statistics.peak_malloced_memory();
  printf("peak memory after init:          %8zu\n", peak_mem_after_init);

  // Peak memory during lazy compilation should converge to the same value
  // (usually after 1-2 iterations).
  std::vector<size_t> peak_mem_after_lazy_compile;
  const int kNumLazyCompiles = 5;
  for (int i = 0; i < kNumLazyCompiles; i++) {
    v8::ScriptCompiler::Compile(context(), &script_source,
                                v8::ScriptCompiler::kNoCompileOptions)
        .ToLocalChecked();

    isolate()->GetHeapStatistics(&heap_statistics);
    size_t peak_mem = heap_statistics.peak_malloced_memory();
    printf("peak memory after lazy compile:  %8zu\n", peak_mem);
    peak_mem_after_lazy_compile.push_back(peak_mem);
  }
  size_t peak_mem_after_first_lazy_compile = peak_mem_after_lazy_compile[0];
  size_t peak_mem_after_second_to_last_lazy_compile =
      peak_mem_after_lazy_compile[kNumLazyCompiles - 2];
  size_t peak_mem_after_last_lazy_compile =
      peak_mem_after_lazy_compile[kNumLazyCompiles - 1];

  v8::ScriptCompiler::Compile(context(), &script_source,
                              v
```