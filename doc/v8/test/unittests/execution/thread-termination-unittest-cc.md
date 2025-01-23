Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understanding the Goal:** The core request is to understand the functionality of the `thread-termination-unittest.cc` file within the V8 JavaScript engine. Specifically, how it tests the termination of JavaScript execution.

2. **Initial Scan - Identifying Key Components:**  A quick scan of the code reveals:
    * **Copyright Header:** Standard boilerplate, not directly relevant to the functionality.
    * **Includes:**  These are crucial. They hint at the areas the code interacts with:
        * `v8-function.h`, `v8-locker.h`, `v8.h`: Basic V8 API elements.
        * `api-inl.h`: Internal V8 API.
        * `platform.h`: OS-level threading primitives.
        * `debug-interface.h`: Debugging functionalities.
        * `interrupts-scope.h`: Managing execution interrupts.
        * `isolate.h`:  The central V8 execution environment.
        * `objects-inl.h`: Internal V8 object representations.
        * `test-utils.h`, `gmock-support.h`, `gtest.h`:  Testing infrastructure.
    * **Namespace `v8`:**  This confirms it's part of the V8 codebase.
    * **Global Variable `semaphore`:**  Suggests inter-thread communication and synchronization.
    * **`TerminatorThread` Class:**  A thread whose purpose is likely to trigger termination.
    * **Various Functions (e.g., `Signal`, `DoLoop`, `Fail`, `Loop`, `TerminateCurrentThread`):**  These seem to be JavaScript-callable functions used in the tests.
    * **`ThreadTerminationTest` Class:**  The main test fixture, using Google Test.
    * **Test Cases (`TEST_F`):**  Individual tests for different termination scenarios.

3. **Deconstructing Key Classes and Functions:**

    * **`TerminatorThread`:** The constructor takes an `Isolate*`. The `Run()` method waits on the `semaphore` and then calls `isolate_->TerminateExecution()`. This strongly suggests a test where one thread triggers termination in another.

    * **`Signal`:** This function signals the `semaphore`. It's called from JavaScript, creating the link between JavaScript execution and the terminator thread.

    * **`CompileRun`:**  A utility function to compile and run JavaScript code within a given context. This is a common pattern in V8 testing.

    * **`DoLoop`:** This function runs a JavaScript loop. The key is the `terminate()` call within the loop (conditionally executed once). It uses `TryCatch` to handle the termination exception. The checks after `CompileRun` verify that an exception was caught, but it's a *termination* exception (null exception, empty message).

    * **`Fail`:**  Simply calls `UNREACHABLE()`. Used to mark code paths that should *not* be executed.

    * **`Loop`:** Calls `doloop()`, encapsulating it within a `try...catch` block (which also shouldn't be reached in a successful termination test).

    * **`TerminateCurrentThread`:** Directly calls `info.GetIsolate()->TerminateExecution()`, indicating self-termination.

    * **`ThreadTerminationTest`:**
        * `TestTerminatingFromOtherThread`: Sets up the `semaphore` and `TerminatorThread`, runs JavaScript that signals the semaphore, and joins the terminator thread.
        * `TestTerminatingFromCurrentThread`: Runs JavaScript that directly calls `terminate()`.
        * `CreateGlobalTemplate`: Creates a global object template with the test functions exposed to JavaScript.

4. **Analyzing Test Cases:** Each `TEST_F` focuses on a specific termination scenario:
    * **`TerminateOnlyV8ThreadFromThreadItself`:** Tests self-termination within a loop.
    * **`TerminateOnlyV8ThreadFromThreadItselfNoLoop`:** Self-termination in a loop without function calls.
    * **`TerminateOnlyV8ThreadFromOtherThread`:** Termination triggered by a separate thread.
    * **`TerminateJsonStringify`, `TerminateBigInt...`:**  Termination during specific built-in operations. This is important for ensuring robustness.
    * **`TerminateLoadICException`:** Termination during property access (related to Inline Caches).
    * **`TerminateCancelTerminateFromThreadItself`:** Tests the ability to cancel a termination request.
    * **`TerminateFromOtherThreadWhileMicrotaskRunning`:** Tests interaction with microtasks.
    * **`PostponeTerminateException`:** Tests how termination interacts with interrupt postponement.
    * **`ErrorObjectAfterTermination`:** Checks if error objects can be created after termination.
    * **`TerminationInInnerTryCall`:** Termination within `TryCall` (an internal V8 mechanism).
    * **`TerminateAndTryCall`:**  Termination followed by another `TryCall`.
    * **`TerminateConsole`:** Termination during console operations.
    * **`TerminationClearArrayJoinStack`:** Termination during `Array.prototype.join`.
    * **`TerminateRegExp`:** Termination during regular expression execution.
    * **`TerminateInMicrotask`, `TerminateInApiMicrotask`:** Termination occurring within microtasks.

5. **Connecting to JavaScript and Common Errors:**

    * **JavaScript Example:**  The `DoLoop` function's JavaScript source provides a direct example of how `terminate()` is called.
    * **Common Errors:** Thinking about what could go wrong when terminating execution leads to scenarios like: infinite loops, resource leaks if cleanup isn't handled, and unexpected behavior if termination isn't properly propagated. The tests cover these implicitly.

6. **Code Logic Inference (Hypothetical Input/Output):**  For `TestTerminatingFromOtherThread`:
    * **Input (Conceptual):** JavaScript code with `loop()` and `terminate()`, a separate thread waiting on a semaphore.
    * **Output:** The JavaScript execution terminates prematurely, the `TryCatch` in `DoLoop` catches a termination exception (but it's a special kind – null exception, empty message). The test verifies that `IsExecutionTerminating()` becomes true.

7. **Torque Consideration:**  The initial prompt asks about `.tq` files. The analysis confirms that `thread-termination-unittest.cc` is a C++ file, *not* a Torque file. Torque is a TypeScript-like language used for implementing V8's built-in functions. If it were a Torque file, the structure and syntax would be different, focusing on type-safe bytecode generation.

8. **Structuring the Answer:** Finally, organize the findings into clear sections: functionality, JavaScript relation, code logic, common errors, and the Torque clarification. Use clear and concise language, explaining technical terms where necessary.

**Self-Correction/Refinement During the Process:**

* **Initial Assumption:**  Initially, I might have focused too much on the threading aspects. Realizing the tests cover various scenarios (built-ins, microtasks, etc.) broadens the understanding.
* **Clarifying Termination Exceptions:**  It's crucial to highlight that the caught exceptions are *termination* exceptions, which are different from regular JavaScript exceptions.
* **Emphasizing Test Coverage:** The sheer number and variety of test cases indicate the importance of robust termination handling in V8.

By following this detailed analysis, we can effectively understand the purpose and workings of the `thread-termination-unittest.cc` file.
这个C++源代码文件 `v8/test/unittests/execution/thread-termination-unittest.cc` 的主要功能是**测试 V8 JavaScript 引擎中线程终止的机制**。它包含了一系列单元测试，用于验证在各种情况下如何正确地终止 JavaScript 代码的执行，以及终止后引擎的状态。

**具体功能点:**

1. **测试从当前线程终止执行：**  测试 JavaScript 代码自身调用 `terminate()` 方法来终止执行的情况。这包括在普通循环和没有函数调用的循环中终止。

2. **测试从其他线程终止执行：**  测试一个独立的线程调用 V8 的 API 来终止另一个正在执行 JavaScript 代码的线程。这模拟了在多线程环境中控制脚本执行的情况。

3. **测试在特定 JavaScript 操作中终止执行：** 针对一些特定的 JavaScript 操作（例如 `JSON.stringify`、BigInt 的运算和转换）进行测试，确保在这些操作执行过程中可以被正确终止。

4. **测试在优化代码中终止执行：** 验证即使在 V8 优化后的代码中（例如使用 `%PrepareFunctionForOptimization` 和 `%OptimizeFunctionOnNextCall` 优化的 BigInt 运算），线程终止机制也能正常工作。

5. **测试终止执行的异常处理：**  验证当线程终止时，V8 如何抛出和处理相应的异常。特别关注了终止异常与普通 JavaScript 异常的不同之处。

6. **测试取消终止执行：**  测试在请求终止执行后，是否可以取消终止，并恢复脚本的执行。

7. **测试终止执行与微任务的交互：**  验证当终止执行发生时，正在执行的微任务和待执行的微任务会如何处理。

8. **测试在 API 回调中请求终止：** 模拟在 V8 的 C++ API 回调函数中调用 `TerminateExecution()` 的情况。

9. **测试在 `TryCall` 内部终止：**  `TryCall` 是 V8 内部用于调用 JavaScript 函数的机制。测试在这种内部调用中触发终止的情况。

10. **测试在控制台操作中终止：**  验证在执行 `console.log()` 等控制台方法时能否被终止。

11. **测试在数组 `join` 操作中终止：**  针对数组的 `join()` 方法进行测试，确保在 `toString()` 方法可能导致无限循环的情况下可以正确终止。

12. **测试在正则表达式执行中终止：** 验证在执行耗时的正则表达式匹配时，线程终止机制是否有效。

13. **测试在微任务中触发终止：**  测试在 Promise 的 `then` 回调等微任务中调用 `terminate()` 的情况。

14. **测试在 API 微任务中触发终止：**  验证通过 V8 C++ API 注册的微任务中调用 `TerminateExecution()` 的情况。

15. **测试延迟终止异常：**  测试使用 `PostponeInterruptsScope` 延迟终止执行的效果，以及与 API 中断的交互。

**关于文件后缀和 Torque：**

你提到如果文件以 `.tq` 结尾，那就是 V8 Torque 源代码。  **`v8/test/unittests/execution/thread-termination-unittest.cc` 的确是以 `.cc` 结尾，所以它是 C++ 源代码，而不是 Torque 源代码。** Torque 用于实现 V8 的内置函数，而这个文件是用来测试 V8 的执行机制的。

**与 JavaScript 的关系及举例：**

这个 C++ 文件测试的是 V8 执行 JavaScript 代码时的线程终止功能。其中定义了一些 C++ 函数，这些函数可以作为全局变量注入到 JavaScript 环境中，以便在 JavaScript 代码中触发终止等操作。

例如，在 `ThreadTerminationTest` 类中，`CreateGlobalTemplate` 方法创建了一个全局对象模板，并将 `TerminateCurrentThread` 和 `DoLoop` 等 C++ 函数暴露给 JavaScript：

```c++
Local<ObjectTemplate> CreateGlobalTemplate(Isolate* isolate,
                                             FunctionCallback terminate,
                                             FunctionCallback doloop) {
  Local<ObjectTemplate> global = ObjectTemplate::New(isolate);
  global->Set(NewString("terminate"),
              FunctionTemplate::New(isolate, terminate));
  global->Set(NewString("fail"), FunctionTemplate::New(isolate, Fail));
  global->Set(NewString("loop"), FunctionTemplate::New(isolate, Loop));
  global->Set(NewString("doloop"), FunctionTemplate::New(isolate, doloop));
  return global;
}
```

在 JavaScript 中，就可以调用这些全局函数来测试线程终止：

```javascript
// 在测试用例中，JavaScript 代码可能会像这样：
terminate(); // 调用 C++ 的 TerminateCurrentThread 函数来终止当前线程

function loop() {
  try {
    doloop(); // 调用 C++ 的 DoLoop 函数，其中会调用 terminate()
    fail();   // 调用 C++ 的 Fail 函数，如果执行到这里说明终止失败
  } catch (e) {
    fail();   // 同上
  }
}

function doloop() {
  var term = true;
  try {
    while(true) {
      if (term) terminate(); // 首次循环调用 terminate()
      term = false;
    }
    fail(); // 不应该执行到这里
  } catch(e) {
    fail(); // 捕获终止异常，但不应该在这里处理
  }
}
```

**代码逻辑推理（假设输入与输出）：**

以 `TEST_F(ThreadTerminationTest, TerminateOnlyV8ThreadFromThreadItself)` 这个测试用例为例：

**假设输入:**

* JavaScript 代码: `try { loop(); fail(); } catch(e) { fail(); }`
* 全局函数 `terminate()` (C++ `TerminateCurrentThread`) 可以被调用。
* 全局函数 `loop()` (C++ `Loop`) 会调用 `doloop()`，其中会执行 `terminate()`。
* V8 引擎正常运行。

**预期输出:**

1. JavaScript 代码开始执行。
2. 进入 `loop()` 函数。
3. `loop()` 函数调用 `doloop()`。
4. 在 `doloop()` 中，`terminate()` 被调用，导致当前 JavaScript 线程终止执行。
5. V8 引擎会捕获到终止执行的信号，并抛出一个特殊的异常（但这个异常在 `TryCatch` 中被认为是终止，`try_catch.HasCaught()` 为 true，但 `try_catch.Exception()->IsNull()` 为 true，`try_catch.Message().IsEmpty()` 为 true）。
6. `TryRunJS` 返回一个空的 `MaybeLocal<Value>`，表示执行被终止。
7. 断言 `CHECK(result.IsEmpty());` 会通过。
8. 后续的断言会验证引擎状态是否符合预期（例如，可以再次运行代码）。

**用户常见的编程错误示例：**

1. **无限循环导致程序无响应：** 用户编写了死循环的 JavaScript 代码，导致浏览器或 Node.js 进程无响应。V8 的线程终止机制可以用来中断这种失控的执行。

   ```javascript
   // 错误的示例：无限循环
   while (true) {
     // ... 没有退出条件
   }
   ```

2. **长时间运行的脚本阻塞 UI 线程：** 在浏览器环境中，如果 JavaScript 代码执行时间过长，会阻塞用户界面。开发者可能需要手动实现某种超时或终止机制，V8 提供的终止功能可以作为底层支持。

3. **资源泄露：**  在一些复杂的 JavaScript 应用中，如果代码在异常情况下没有正确清理资源（例如，关闭数据库连接、释放文件句柄），可能会导致资源泄露。虽然线程终止可以中断执行，但它并不能保证资源的完全清理。开发者仍然需要使用 `try...finally` 等机制来确保资源得到释放。

4. **不理解异步操作导致的复杂状态：** 在涉及 `setTimeout`、`setInterval` 或 `Promise` 等异步操作的代码中，如果需要终止执行，开发者需要考虑如何取消这些待执行的异步任务，仅仅终止当前线程可能不够。

**总结:**

`v8/test/unittests/execution/thread-termination-unittest.cc` 是一个关键的测试文件，它全面地验证了 V8 JavaScript 引擎的线程终止功能，确保引擎在各种场景下都能正确、安全地终止 JavaScript 代码的执行。这对于提高 V8 的健壮性和可靠性至关重要。

### 提示词
```
这是目录为v8/test/unittests/execution/thread-termination-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/execution/thread-termination-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2009 the V8 project authors. All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//     * Neither the name of Google Inc. nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "include/v8-function.h"
#include "include/v8-locker.h"
#include "src/api/api-inl.h"
#include "src/base/platform/platform.h"
#include "src/debug/debug-interface.h"
#include "src/execution/interrupts-scope.h"
#include "src/execution/isolate.h"
#include "src/init/v8.h"
#include "src/objects/objects-inl.h"
#include "test/unittests/test-utils.h"
#include "testing/gmock-support.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {

base::Semaphore* semaphore = nullptr;

class TerminatorThread : public base::Thread {
 public:
  explicit TerminatorThread(i::Isolate* isolate)
      : Thread(Options("TerminatorThread")),
        isolate_(reinterpret_cast<Isolate*>(isolate)) {}
  void Run() override {
    semaphore->Wait();
    CHECK(!isolate_->IsExecutionTerminating());
    isolate_->TerminateExecution();
  }

 private:
  Isolate* isolate_;
};

void Signal(const FunctionCallbackInfo<Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  semaphore->Signal();
}

MaybeLocal<Value> CompileRun(Local<Context> context, Local<String> source) {
  Local<Script> script = Script::Compile(context, source).ToLocalChecked();
  return script->Run(context);
}

MaybeLocal<Value> CompileRun(Local<Context> context, const char* source) {
  return CompileRun(
      context,
      String::NewFromUtf8(context->GetIsolate(), source).ToLocalChecked());
}

void DoLoop(const FunctionCallbackInfo<Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  TryCatch try_catch(info.GetIsolate());
  CHECK(!info.GetIsolate()->IsExecutionTerminating());
  MaybeLocal<Value> result = CompileRun(info.GetIsolate()->GetCurrentContext(),
                                        "function f() {"
                                        "  var term = true;"
                                        "  try {"
                                        "    while(true) {"
                                        "      if (term) terminate();"
                                        "      term = false;"
                                        "    }"
                                        "    fail();"
                                        "  } catch(e) {"
                                        "    fail();"
                                        "  }"
                                        "}"
                                        "f()");
  CHECK(result.IsEmpty());
  CHECK(try_catch.HasCaught());
  CHECK(try_catch.Exception()->IsNull());
  CHECK(try_catch.Message().IsEmpty());
  CHECK(!try_catch.CanContinue());
  CHECK(info.GetIsolate()->IsExecutionTerminating());
}

void Fail(const FunctionCallbackInfo<Value>& info) { UNREACHABLE(); }

void Loop(const FunctionCallbackInfo<Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  CHECK(!info.GetIsolate()->IsExecutionTerminating());
  MaybeLocal<Value> result =
      CompileRun(info.GetIsolate()->GetCurrentContext(),
                 "try { doloop(); fail(); } catch(e) { fail(); }");
  CHECK(result.IsEmpty());
  CHECK(info.GetIsolate()->IsExecutionTerminating());
}

void TerminateCurrentThread(const FunctionCallbackInfo<Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  CHECK(!info.GetIsolate()->IsExecutionTerminating());
  info.GetIsolate()->TerminateExecution();
}

class ThreadTerminationTest : public TestWithIsolate {
 public:
  void TestTerminatingFromOtherThread(const char* source) {
    semaphore = new base::Semaphore(0);
    TerminatorThread thread(i_isolate());
    CHECK(thread.Start());

    HandleScope scope(isolate());
    Local<ObjectTemplate> global =
        CreateGlobalTemplate(isolate(), Signal, DoLoop);
    Local<Context> context = Context::New(isolate(), nullptr, global);
    Context::Scope context_scope(context);
    CHECK(!isolate()->IsExecutionTerminating());
    MaybeLocal<Value> result = TryRunJS(source);
    CHECK(result.IsEmpty());
    thread.Join();
    delete semaphore;
    semaphore = nullptr;
  }

  void TestTerminatingFromCurrentThread(const char* source) {
    HandleScope scope(isolate());
    Local<ObjectTemplate> global =
        CreateGlobalTemplate(isolate(), TerminateCurrentThread, DoLoop);
    Local<Context> context = Context::New(isolate(), nullptr, global);
    Context::Scope context_scope(context);
    CHECK(!isolate()->IsExecutionTerminating());
    MaybeLocal<Value> result = TryRunJS(source);
    CHECK(result.IsEmpty());
  }

  Local<ObjectTemplate> CreateGlobalTemplate(Isolate* isolate,
                                             FunctionCallback terminate,
                                             FunctionCallback doloop) {
    Local<ObjectTemplate> global = ObjectTemplate::New(isolate);
    global->Set(NewString("terminate"),
                FunctionTemplate::New(isolate, terminate));
    global->Set(NewString("fail"), FunctionTemplate::New(isolate, Fail));
    global->Set(NewString("loop"), FunctionTemplate::New(isolate, Loop));
    global->Set(NewString("doloop"), FunctionTemplate::New(isolate, doloop));
    return global;
  }
};

void DoLoopNoCall(const FunctionCallbackInfo<Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  TryCatch try_catch(info.GetIsolate());
  CHECK(!info.GetIsolate()->IsExecutionTerminating());
  MaybeLocal<Value> result = CompileRun(info.GetIsolate()->GetCurrentContext(),
                                        "var term = true;"
                                        "while(true) {"
                                        "  if (term) terminate();"
                                        "  term = false;"
                                        "}");
  CHECK(result.IsEmpty());
  CHECK(try_catch.HasCaught());
  CHECK(try_catch.Exception()->IsNull());
  CHECK(try_catch.Message().IsEmpty());
  CHECK(!try_catch.CanContinue());
  CHECK(info.GetIsolate()->IsExecutionTerminating());
}

// Test that a single thread of JavaScript execution can terminate
// itself.
TEST_F(ThreadTerminationTest, TerminateOnlyV8ThreadFromThreadItself) {
  HandleScope scope(isolate());
  Local<ObjectTemplate> global =
      CreateGlobalTemplate(isolate(), TerminateCurrentThread, DoLoop);
  Local<Context> context = Context::New(isolate(), nullptr, global);
  Context::Scope context_scope(context);
  CHECK(!isolate()->IsExecutionTerminating());
  // Run a loop that will be infinite if thread termination does not work.
  MaybeLocal<Value> result =
      TryRunJS("try { loop(); fail(); } catch(e) { fail(); }");
  CHECK(result.IsEmpty());
  // Test that we can run the code again after thread termination.
  CHECK(!isolate()->IsExecutionTerminating());
  result = TryRunJS("try { loop(); fail(); } catch(e) { fail(); }");
  CHECK(result.IsEmpty());
}

// Test that a single thread of JavaScript execution can terminate
// itself in a loop that performs no calls.
TEST_F(ThreadTerminationTest, TerminateOnlyV8ThreadFromThreadItselfNoLoop) {
  HandleScope scope(isolate());
  Local<ObjectTemplate> global =
      CreateGlobalTemplate(isolate(), TerminateCurrentThread, DoLoopNoCall);
  Local<Context> context = Context::New(isolate(), nullptr, global);
  Context::Scope context_scope(context);
  CHECK(!isolate()->IsExecutionTerminating());
  // Run a loop that will be infinite if thread termination does not work.
  static const char* source = "try { loop(); fail(); } catch(e) { fail(); }";
  MaybeLocal<Value> result = TryRunJS(source);
  CHECK(result.IsEmpty());
  CHECK(!isolate()->IsExecutionTerminating());
  // Test that we can run the code again after thread termination.
  result = TryRunJS(source);
  CHECK(result.IsEmpty());
}

// Test that a single thread of JavaScript execution can be terminated
// from the side by another thread.
TEST_F(ThreadTerminationTest, TerminateOnlyV8ThreadFromOtherThread) {
  // Run a loop that will be infinite if thread termination does not work.
  TestTerminatingFromOtherThread(
      "try { loop(); fail(); } catch(e) { fail(); }");
}

// Test that execution can be terminated from within JSON.stringify.
TEST_F(ThreadTerminationTest, TerminateJsonStringify) {
  TestTerminatingFromCurrentThread(
      "var x = [];"
      "x[2**31]=1;"
      "terminate();"
      "JSON.stringify(x);"
      "fail();");
}

TEST_F(ThreadTerminationTest, TerminateBigIntMultiplication) {
  TestTerminatingFromCurrentThread(
      "terminate();"
      "var a = 5n ** 555555n;"
      "var b = 3n ** 3333333n;"
      "a * b;"
      "fail();");
}

TEST_F(ThreadTerminationTest, TerminateOptimizedBigIntMultiplication) {
  i::v8_flags.allow_natives_syntax = true;
  TestTerminatingFromCurrentThread(
      "function foo(a, b) { return a * b; }"
      "%PrepareFunctionForOptimization(foo);"
      "foo(1n, 2n);"
      "foo(1n, 2n);"
      "%OptimizeFunctionOnNextCall(foo);"
      "foo(1n, 2n);"
      "var a = 5n ** 555555n;"
      "var b = 3n ** 3333333n;"
      "terminate();"
      "foo(a, b);"
      "fail();");
}

TEST_F(ThreadTerminationTest, TerminateBigIntDivision) {
  TestTerminatingFromCurrentThread(
      "var a = 2n ** 2222222n;"
      "var b = 3n ** 333333n;"
      "terminate();"
      "a / b;"
      "fail();");
}

TEST_F(ThreadTerminationTest, TerminateOptimizedBigIntDivision) {
  i::v8_flags.allow_natives_syntax = true;
  TestTerminatingFromCurrentThread(
      "function foo(a, b) { return a / b; }"
      "%PrepareFunctionForOptimization(foo);"
      "foo(3n, 2n);"
      "foo(3n, 2n);"
      "%OptimizeFunctionOnNextCall(foo);"
      "foo(3n, 2n);"
      "var a = 2n ** 2222222n;"
      "var b = 3n ** 333333n;"
      "terminate();"
      "foo(a, b);"
      "fail();");
}

TEST_F(ThreadTerminationTest, TerminateBigIntToString) {
  TestTerminatingFromCurrentThread(
      "var a = 2n ** 2222222n;"
      "terminate();"
      "a.toString();"
      "fail();");
}

TEST_F(ThreadTerminationTest, TerminateBigIntFromString) {
  TestTerminatingFromCurrentThread(
      "var a = '12344567890'.repeat(100000);\n"
      "terminate();\n"
      "BigInt(a);\n"
      "fail();\n");
}

void LoopGetProperty(const FunctionCallbackInfo<Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  TryCatch try_catch(info.GetIsolate());
  CHECK(!info.GetIsolate()->IsExecutionTerminating());
  MaybeLocal<Value> result =
      CompileRun(info.GetIsolate()->GetCurrentContext(),
                 "function f() {"
                 "  try {"
                 "    while(true) {"
                 "      terminate_or_return_object().x;"
                 "    }"
                 "    fail();"
                 "  } catch(e) {"
                 "    (function() {})();"  // trigger stack check.
                 "    fail();"
                 "  }"
                 "}"
                 "f()");
  CHECK(result.IsEmpty());
  CHECK(try_catch.HasCaught());
  CHECK(try_catch.Exception()->IsNull());
  CHECK(try_catch.Message().IsEmpty());
  CHECK(!try_catch.CanContinue());
  CHECK(info.GetIsolate()->IsExecutionTerminating());
}

int call_count = 0;

void TerminateOrReturnObject(const FunctionCallbackInfo<Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  if (++call_count == 10) {
    CHECK(!info.GetIsolate()->IsExecutionTerminating());
    info.GetIsolate()->TerminateExecution();
    return;
  }
  Local<Object> result = Object::New(info.GetIsolate());
  Local<Context> context = info.GetIsolate()->GetCurrentContext();
  Maybe<bool> val = result->Set(
      context, String::NewFromUtf8(context->GetIsolate(), "x").ToLocalChecked(),
      Integer::New(info.GetIsolate(), 42));
  CHECK(val.FromJust());
  info.GetReturnValue().Set(result);
}

// Test that we correctly handle termination exceptions if they are
// triggered by the creation of error objects in connection with ICs.
TEST_F(ThreadTerminationTest, TerminateLoadICException) {
  HandleScope scope(isolate());
  Local<ObjectTemplate> global = ObjectTemplate::New(isolate());
  global->Set(NewString("terminate_or_return_object"),
              FunctionTemplate::New(isolate(), TerminateOrReturnObject));
  global->Set(NewString("fail"), FunctionTemplate::New(isolate(), Fail));
  global->Set(NewString("loop"),
              FunctionTemplate::New(isolate(), LoopGetProperty));

  Local<Context> context = Context::New(isolate(), nullptr, global);
  Context::Scope context_scope(context);
  CHECK(!isolate()->IsExecutionTerminating());
  // Run a loop that will be infinite if thread termination does not work.
  static const char* source = "try { loop(); fail(); } catch(e) { fail(); }";
  call_count = 0;
  MaybeLocal<Value> result = CompileRun(isolate()->GetCurrentContext(), source);
  CHECK(result.IsEmpty());
  // Test that we can run the code again after thread termination.
  CHECK(!isolate()->IsExecutionTerminating());
  call_count = 0;
  result = CompileRun(isolate()->GetCurrentContext(), source);
  CHECK(result.IsEmpty());
}

Persistent<String> reenter_script_1;
Persistent<String> reenter_script_2;

void DoLoopCancelTerminate(const FunctionCallbackInfo<Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  Isolate* isolate = info.GetIsolate();
  TryCatch try_catch(isolate);
  CHECK(!isolate->IsExecutionTerminating());
  MaybeLocal<Value> result = CompileRun(isolate->GetCurrentContext(),
                                        "var term = true;"
                                        "while(true) {"
                                        "  if (term) terminate();"
                                        "  term = false;"
                                        "}"
                                        "fail();");
  CHECK(result.IsEmpty());
  CHECK(try_catch.HasCaught());
  CHECK(try_catch.Exception()->IsNull());
  CHECK(try_catch.Message().IsEmpty());
  CHECK(!try_catch.CanContinue());
  CHECK(isolate->IsExecutionTerminating());
  CHECK(try_catch.HasTerminated());
  isolate->CancelTerminateExecution();
  CHECK(!isolate->IsExecutionTerminating());
}

// Test that a single thread of JavaScript execution can terminate
// itself and then resume execution.
TEST_F(ThreadTerminationTest, TerminateCancelTerminateFromThreadItself) {
  HandleScope scope(isolate());
  Local<ObjectTemplate> global = CreateGlobalTemplate(
      isolate(), TerminateCurrentThread, DoLoopCancelTerminate);
  Local<Context> context = Context::New(isolate(), nullptr, global);
  Context::Scope context_scope(context);
  CHECK(!isolate()->IsExecutionTerminating());
  // Check that execution completed with correct return value.
  Local<Value> result =
      CompileRun(isolate()->GetCurrentContext(),
                 "try { doloop(); } catch(e) { fail(); } 'completed';")
          .ToLocalChecked();
  CHECK(result->Equals(isolate()->GetCurrentContext(), NewString("completed"))
            .FromJust());
}

void MicrotaskShouldNotRun(const FunctionCallbackInfo<Value>& info) {
  UNREACHABLE();
}

void MicrotaskLoopForever(const FunctionCallbackInfo<Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  Isolate* isolate = info.GetIsolate();
  HandleScope scope(isolate);
  // Enqueue another should-not-run task to ensure we clean out the queue
  // when we terminate.
  isolate->EnqueueMicrotask(
      Function::New(isolate->GetCurrentContext(), MicrotaskShouldNotRun)
          .ToLocalChecked());
  CompileRun(isolate->GetCurrentContext(), "terminate(); while (true) { }");
  CHECK(isolate->IsExecutionTerminating());
}

TEST_F(ThreadTerminationTest, TerminateFromOtherThreadWhileMicrotaskRunning) {
  semaphore = new base::Semaphore(0);
  TerminatorThread thread(i_isolate());
  CHECK(thread.Start());

  isolate()->SetMicrotasksPolicy(MicrotasksPolicy::kExplicit);
  HandleScope scope(isolate());
  Local<ObjectTemplate> global =
      CreateGlobalTemplate(isolate(), Signal, DoLoop);
  Local<Context> context = Context::New(isolate(), nullptr, global);
  Context::Scope context_scope(context);
  isolate()->EnqueueMicrotask(
      Function::New(isolate()->GetCurrentContext(), MicrotaskLoopForever)
          .ToLocalChecked());
  // The second task should never be run because we bail out if we're
  // terminating.
  isolate()->EnqueueMicrotask(
      Function::New(isolate()->GetCurrentContext(), MicrotaskShouldNotRun)
          .ToLocalChecked());
  isolate()->PerformMicrotaskCheckpoint();

  isolate()->CancelTerminateExecution();
  // Should not run MicrotaskShouldNotRun.
  isolate()->PerformMicrotaskCheckpoint();

  thread.Join();
  delete semaphore;
  semaphore = nullptr;
}

static int callback_counter = 0;

static void CounterCallback(Isolate* isolate, void* data) {
  callback_counter++;
}

TEST_F(ThreadTerminationTest, PostponeTerminateException) {
  HandleScope scope(isolate());
  Local<ObjectTemplate> global =
      CreateGlobalTemplate(isolate(), TerminateCurrentThread, DoLoop);
  Local<Context> context = Context::New(isolate(), nullptr, global);
  Context::Scope context_scope(context);

  TryCatch try_catch(isolate());
  static const char* terminate_and_loop =
      "terminate(); for (var i = 0; i < 10000; i++);";

  {  // Postpone terminate execution interrupts.
    i::PostponeInterruptsScope p1(i_isolate(),
                                  i::StackGuard::TERMINATE_EXECUTION);

    // API interrupts should still be triggered.
    isolate()->RequestInterrupt(&CounterCallback, nullptr);
    CHECK_EQ(0, callback_counter);
    RunJS(terminate_and_loop);
    CHECK(!try_catch.HasTerminated());
    CHECK_EQ(1, callback_counter);

    {  // Postpone API interrupts as well.
      i::PostponeInterruptsScope p2(i_isolate(), i::StackGuard::API_INTERRUPT);

      // None of the two interrupts should trigger.
      isolate()->RequestInterrupt(&CounterCallback, nullptr);
      RunJS(terminate_and_loop);
      CHECK(!try_catch.HasTerminated());
      CHECK_EQ(1, callback_counter);
    }

    // Now the previously requested API interrupt should trigger.
    RunJS(terminate_and_loop);
    CHECK(!try_catch.HasTerminated());
    CHECK_EQ(2, callback_counter);
  }

  // Now the previously requested terminate execution interrupt should trigger.
  TryRunJS("for (var i = 0; i < 10000; i++);");
  CHECK(try_catch.HasTerminated());
  CHECK_EQ(2, callback_counter);
}

static void AssertFinishedCodeRun(Isolate* isolate) {
  TryCatch try_catch(isolate);
  CompileRun(isolate->GetCurrentContext(), "for (var i = 0; i < 10000; i++);");
  CHECK(!try_catch.HasTerminated());
}

void RequestTermianteAndCallAPI(const FunctionCallbackInfo<Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  info.GetIsolate()->TerminateExecution();
  AssertFinishedCodeRun(info.GetIsolate());
}

TEST_F(ThreadTerminationTest, ErrorObjectAfterTermination) {
  HandleScope scope(isolate());
  Local<Context> context = Context::New(isolate());
  Context::Scope context_scope(context);
  isolate()->TerminateExecution();
  Local<Value> error = Exception::Error(NewString("error"));
  CHECK(error->IsNativeError());
}

void InnerTryCallTerminate(const FunctionCallbackInfo<Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  CHECK(!info.GetIsolate()->IsExecutionTerminating());
  Isolate* isolate = info.GetIsolate();
  Local<Object> global = isolate->GetCurrentContext()->Global();
  Local<Function> loop = Local<Function>::Cast(
      global
          ->Get(isolate->GetCurrentContext(),
                String::NewFromUtf8(isolate, "loop").ToLocalChecked())
          .ToLocalChecked());
  i::MaybeHandle<i::Object> exception;
  i::MaybeHandle<i::Object> result = i::Execution::TryCall(
      reinterpret_cast<i::Isolate*>(isolate), Utils::OpenHandle((*loop)),
      Utils::OpenHandle((*global)), 0, nullptr,
      i::Execution::MessageHandling::kReport, &exception);
  CHECK(result.is_null());
  CHECK(exception.is_null());
  // TryCall reschedules the termination exception.
  CHECK(info.GetIsolate()->IsExecutionTerminating());
}

TEST_F(ThreadTerminationTest, TerminationInInnerTryCall) {
  HandleScope scope(isolate());
  Local<ObjectTemplate> global_template =
      CreateGlobalTemplate(isolate(), TerminateCurrentThread, DoLoopNoCall);
  global_template->Set(NewString("inner_try_call_terminate"),
                       FunctionTemplate::New(isolate(), InnerTryCallTerminate));
  Local<Context> context = Context::New(isolate(), nullptr, global_template);
  Context::Scope context_scope(context);
  {
    TryCatch try_catch(isolate());
    TryRunJS("inner_try_call_terminate()");
    CHECK(try_catch.HasTerminated());
    // Any further exectutions in this TryCatch scope would fail.
    CHECK(isolate()->IsExecutionTerminating());
  }
  // Leaving the TryCatch cleared the termination exception.
  Maybe<int32_t> result =
      RunJS("2 + 2")->Int32Value(isolate()->GetCurrentContext());
  CHECK_EQ(4, result.FromJust());
  CHECK(!isolate()->IsExecutionTerminating());
}

TEST_F(ThreadTerminationTest, TerminateAndTryCall) {
  i::v8_flags.allow_natives_syntax = true;
  HandleScope scope(isolate());
  Local<ObjectTemplate> global = CreateGlobalTemplate(
      isolate(), TerminateCurrentThread, DoLoopCancelTerminate);
  Local<Context> context = Context::New(isolate(), nullptr, global);
  Context::Scope context_scope(context);
  CHECK(!isolate()->IsExecutionTerminating());
  {
    TryCatch try_catch(isolate());
    CHECK(!isolate()->IsExecutionTerminating());
    // Terminate execution has been triggered inside TryCall, but re-requested
    // to trigger later.
    CHECK(TryRunJS("terminate(); reference_error();").IsEmpty());
    CHECK(try_catch.HasCaught());
    CHECK(!isolate()->IsExecutionTerminating());
    Local<Value> value =
        context->Global()
            ->Get(isolate()->GetCurrentContext(), NewString("terminate"))
            .ToLocalChecked();
    CHECK(value->IsFunction());
    // Any further executions in this TryCatch scope fail.
    CHECK(!isolate()->IsExecutionTerminating());
    CHECK(TryRunJS("1 + 1").IsEmpty());
    CHECK(isolate()->IsExecutionTerminating());
  }
  // Leaving the TryCatch cleared the termination exception.
  Maybe<int32_t> result =
      RunJS("2 + 2")->Int32Value(isolate()->GetCurrentContext());
  CHECK_EQ(4, result.FromJust());
  CHECK(!isolate()->IsExecutionTerminating());
}

class ConsoleImpl : public debug::ConsoleDelegate {
 private:
  void Log(const debug::ConsoleCallArguments& info,
           const debug::ConsoleContext&) override {
    CompileRun(Isolate::GetCurrent()->GetCurrentContext(), "1 + 1");
  }
};

TEST_F(ThreadTerminationTest, TerminateConsole) {
  i::v8_flags.allow_natives_syntax = true;
  ConsoleImpl console;
  debug::SetConsoleDelegate(isolate(), &console);
  HandleScope scope(isolate());
  Local<ObjectTemplate> global = CreateGlobalTemplate(
      isolate(), TerminateCurrentThread, DoLoopCancelTerminate);
  Local<Context> context = Context::New(isolate(), nullptr, global);
  Context::Scope context_scope(context);
  {
    // setup console global.
    HandleScope scope(isolate());
    Local<String> name = String::NewFromUtf8Literal(
        isolate(), "console", NewStringType::kInternalized);
    Local<Value> console =
        context->GetExtrasBindingObject()->Get(context, name).ToLocalChecked();
    context->Global()->Set(context, name, console).FromJust();
  }

  CHECK(!isolate()->IsExecutionTerminating());
  TryCatch try_catch(isolate());
  CHECK(!isolate()->IsExecutionTerminating());
  CHECK(TryRunJS("terminate(); console.log(); fail();").IsEmpty());
  CHECK(try_catch.HasCaught());
  CHECK(isolate()->IsExecutionTerminating());
}

TEST_F(ThreadTerminationTest, TerminationClearArrayJoinStack) {
  internal::v8_flags.allow_natives_syntax = true;
  HandleScope scope(isolate());
  Local<ObjectTemplate> global_template =
      CreateGlobalTemplate(isolate(), TerminateCurrentThread, DoLoopNoCall);
  {
    Local<Context> context = Context::New(isolate(), nullptr, global_template);
    Context::Scope context_scope(context);
    {
      TryCatch try_catch(isolate());
      TryRunJS(
          "var error = false;"
          "var a = [{toString(){if(error)loop()}}];"
          "function Join(){ return a.join();}; "
          "%PrepareFunctionForOptimization(Join);"
          "Join();"
          "%OptimizeFunctionOnNextCall(Join);"
          "error = true;"
          "Join();");
      CHECK(try_catch.HasTerminated());
      CHECK(isolate()->IsExecutionTerminating());
    }
    EXPECT_THAT(RunJS("a[0] = 1; Join();"), testing::IsString("1"));
  }
  {
    Local<Context> context = Context::New(isolate(), nullptr, global_template);
    Context::Scope context_scope(context);
    {
      TryCatch try_catch(isolate());
      TryRunJS(
          "var a = [{toString(){loop()}}];"
          "function Join(){ return a.join();}; "
          "Join();");
      CHECK(try_catch.HasTerminated());
      CHECK(isolate()->IsExecutionTerminating());
    }
    EXPECT_THAT(RunJS("a[0] = 1; Join();"), testing::IsString("1"));
  }
  {
    ConsoleImpl console;
    debug::SetConsoleDelegate(isolate(), &console);
    HandleScope scope(isolate());
    Local<Context> context = Context::New(isolate(), nullptr, global_template);
    Context::Scope context_scope(context);
    {
      // setup console global.
      HandleScope scope(isolate());
      Local<String> name = String::NewFromUtf8Literal(
          isolate(), "console", NewStringType::kInternalized);
      Local<Value> console = context->GetExtrasBindingObject()
                                 ->Get(context, name)
                                 .ToLocalChecked();
      context->Global()->Set(context, name, console).FromJust();
    }
    CHECK(!isolate()->IsExecutionTerminating());
    {
      TryCatch try_catch(isolate());
      CHECK(!isolate()->IsExecutionTerminating());
      CHECK(TryRunJS("var a = [{toString(){terminate();console.log();fail()}}];"
                     "function Join() {return a.join();}"
                     "Join();")
                .IsEmpty());
      CHECK(try_catch.HasCaught());
      CHECK(isolate()->IsExecutionTerminating());
    }
    EXPECT_THAT(RunJS("a[0] = 1; Join();"), testing::IsString("1"));
  }
}

class TerminatorSleeperThread : public base::Thread {
 public:
  explicit TerminatorSleeperThread(Isolate* isolate, int sleep_ms)
      : Thread(Options("TerminatorSlepperThread")),
        isolate_(isolate),
        sleep_ms_(sleep_ms) {}
  void Run() override {
    base::OS::Sleep(base::TimeDelta::FromMilliseconds(sleep_ms_));
    isolate_->TerminateExecution();
  }

 private:
  Isolate* isolate_;
  int sleep_ms_;
};

TEST_F(ThreadTerminationTest, TerminateRegExp) {
  i::v8_flags.allow_natives_syntax = true;
  // We want to be stuck regexp execution, so no fallback to linear-time
  // engine.
  // TODO(mbid,v8:10765): Find a way to test interrupt support of the
  // experimental engine.
  i::v8_flags.enable_experimental_regexp_engine_on_excessive_backtracks = false;

  HandleScope scope(isolate());
  Local<ObjectTemplate> global = CreateGlobalTemplate(
      isolate(), TerminateCurrentThread, DoLoopCancelTerminate);
  Local<Context> context = Context::New(isolate(), nullptr, global);
  Context::Scope context_scope(context);
  CHECK(!isolate()->IsExecutionTerminating());
  TryCatch try_catch(isolate());
  CHECK(!isolate()->IsExecutionTerminating());
  CHECK(!RunJS("var re = /(x+)+y$/; re.test('x');").IsEmpty());
  CHECK(!isolate()->IsExecutionTerminating());
  TerminatorSleeperThread terminator(isolate(), 100);
  CHECK(terminator.Start());
  CHECK(TryRunJS("re.test('xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'); fail();")
            .IsEmpty());
  CHECK(try_catch.HasCaught());
  CHECK(isolate()->IsExecutionTerminating());
}

TEST_F(ThreadTerminationTest, TerminateInMicrotask) {
  Locker locker(isolate());
  isolate()->SetMicrotasksPolicy(MicrotasksPolicy::kExplicit);
  HandleScope scope(isolate());
  Local<ObjectTemplate> global = CreateGlobalTemplate(
      isolate(), TerminateCurrentThread, DoLoopCancelTerminate);
  Local<Context> context1 = Context::New(isolate(), nullptr, global);
  Local<Context> context2 = Context::New(isolate(), nullptr, global);
  {
    TryCatch try_catch(isolate());
    {
      Context::Scope context_scope(context1);
      CHECK(!isolate()->IsExecutionTerminating());
      CHECK(!RunJS("Promise.resolve().then(function() {"
                   "terminate(); loop(); fail();})")
                 .IsEmpty());
      CHECK(!try_catch.HasCaught());
    }
    {
      Context::Scope context_scope(context2);
      CHECK(context2 == isolate()->GetCurrentContext());
      CHECK(context2 == isolate()->GetEnteredOrMicrotaskContext());
      CHECK(!isolate()->IsExecutionTerminating());
      isolate()->PerformMicrotaskCheckpoint();
      CHECK(context2 == isolate()->GetCurrentContext());
      CHECK(context2 == isolate()->GetEnteredOrMicrotaskContext());
      CHECK(try_catch.HasCaught());
      CHECK(try_catch.HasTerminated());
      // Any further exectutions in this TryCatch scope would fail.
      CHECK(isolate()->IsExecutionTerminating());
      CHECK(!i_isolate()->stack_guard()->CheckTerminateExecution());
    }
  }
  CHECK(!i_isolate()->stack_guard()->CheckTerminateExecution());
  CHECK(!isolate()->IsExecutionTerminating());
}

void TerminationMicrotask(void* data) {
  Isolate::GetCurrent()->TerminateExecution();
  CompileRun(Isolate::GetCurrent()->GetCurrentContext(), "");
}

void UnreachableMicrotask(void* data) { UNREACHABLE(); }

TEST_F(ThreadTerminationTest, TerminateInApiMicrotask) {
  Locker locker(isolate());
  isolate()->SetMicrotasksPolicy(MicrotasksPolicy::kExplicit);
  HandleScope scope(isolate());
  Local<ObjectTemplate> global = CreateGlobalTemplate(
      isolate(), TerminateCurrentThread, DoLoopCancelTerminate);
  Local<Context> context = Context::New(isolate(), nullptr, global);
  {
    TryCatch try_catch(isolate());
    Context::Scope context_scope(context);
    CHECK(!isolate()->IsExecutionTerminating());
    isolate()->EnqueueMicrotask(TerminationMicrotask);
    isolate()->EnqueueMicrotask(UnreachableMicrotask);
    isolate()->PerformMicrotaskCheckpoint();
    CHECK(try_catch.HasCaught());
    CHECK(try_catch.HasTerminated());
    CHECK(isolate()->IsExecutionTerminating());
  }
  CHECK(!isolate()->IsExecutionTerminating());
}

}  // namespace v8
```