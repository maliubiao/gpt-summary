Response:
The user wants to understand the functionality of the provided C++ code snippet, which is part of the V8 JavaScript engine's test suite, specifically the `test-debug.cc` file. The request is broken down into several sub-questions:

1. **General Functionality:** What does this code do?
2. **Torque Source:** Is it a Torque source file (determined by the `.tq` extension)?
3. **JavaScript Relation:** If it relates to JavaScript functionality, provide JavaScript examples.
4. **Code Logic Inference:** Are there code logic examples with inputs and outputs?
5. **Common Programming Errors:** Does it highlight common programming errors?
6. **Part Number:** This is part 1 of 8.
7. **Summarization:**  Provide a summary of the functionality.

Let's analyze the code snippet to answer these questions:

* **Headers:** The included headers (`v8-extension.h`, `v8-function.h`, `v8-json.h`, `v8-locker.h`, internal V8 headers, `cctest.h`) strongly suggest this code is for testing debugging features within V8.
* **Helper Functions:** Functions like `CompileFunction`, `HasBreakInfo`, `SetBreakPoint`, `ClearBreakPoint`, `ChangeBreakOnException`, and `PrepareStep` directly manipulate debugging functionalities.
* **Debug Event Handlers:** The `DebugEventCounter`, `DebugEventBreakPointCollectGarbage`, `DebugEventBreak`, and `DebugEventBreakMax` classes are implementations of `v8::debug::DebugDelegate`, which are used to intercept and handle debug events. These handlers perform actions like counting breakpoints, triggering garbage collection, and re-issuing breaks.
* **TEST Macros:** The use of `TEST(...)` indicates this is part of the V8 testing framework. The test names (e.g., `DebugInfo`, `BreakPointICStore`, `BreakPointCondition`) clearly point to testing various debugging scenarios.

**Plan:**

1. **Address the .tq extension question:**  Explicitly state that it's not a Torque file based on the `.cc` extension.
2. **Focus on the debugging functionality:**  Emphasize that the code tests the V8 debugger.
3. **Provide JavaScript examples:** Illustrate how the tested debugging features would be used from a JavaScript perspective (setting breakpoints, stepping, etc.).
4. **Give an example of code logic inference:**  Show a simple test case with a breakpoint and how the `break_point_hit_count` variable would change.
5. **Consider common debugging errors:**  Relate the tests to scenarios where developers use debugging tools to find errors.
6. **Acknowledge the part number.**
7. **Summarize the findings.**
好的，让我们来分析一下这段V8源代码 `v8/test/cctest/test-debug.cc` 的功能。

**1. 功能列举:**

这段代码的主要功能是 **测试 V8 JavaScript 引擎的调试 (debug) 功能**。它通过一系列的 C++ 测试用例来验证 V8 调试器的各种特性，例如：

* **断点设置与清除:**  测试在不同位置（函数起始、IC 调用点、内置函数等）设置和清除断点的功能。
* **断点条件:** 测试带有条件的断点是否能正确触发。
* **调试信息管理:**  测试 V8 如何跟踪正在被调试的函数的信息。
* **调试事件处理:**  测试在断点命中时触发自定义事件处理程序的功能，例如计数断点命中次数、执行垃圾回收等。
* **单步执行:**  虽然代码中声明了 `PrepareStep` 函数，但这段代码本身并没有直接演示单步执行的测试用例，后续的片段可能会涉及。
* **内置函数调试:** 测试对 V8 内置函数（如 `String.prototype.repeat`，`Math.sin` 等）设置断点的能力。
* **内联函数调试:** 测试对被内联的内置函数设置断点的能力。
* **垃圾回收与调试:** 测试在垃圾回收发生时，断点是否仍然有效。
* **并发优化与调试:** 测试在并发优化场景下，断点行为是否正常。

**2. 关于 .tq 结尾:**

正如代码注释中所示，`v8/test/cctest/test-debug.cc` 的文件扩展名是 `.cc`，这表明它是一个 **C++ 源代码文件**。如果文件名以 `.tq` 结尾，那才表示它是一个 **V8 Torque 源代码文件**。

**3. 与 JavaScript 功能的关系及示例:**

`v8/test/cctest/test-debug.cc` 中测试的功能直接对应于开发者在调试 JavaScript 代码时使用的功能。例如，设置断点允许开发者在代码执行到特定位置时暂停，查看变量的值和执行流程。

以下是一些 JavaScript 示例，展示了与这段 C++ 测试代码相关的调试概念：

```javascript
function foo() { // 在这里可以设置断点
  let a = 1;
  let b = 2;
  return a + b;
}

function bar() {
  console.log("Hello from bar"); // 可以在这里设置断点
}

function main() {
  foo();
  bar();
}

main();
```

* **设置断点:**  开发者可以在 `foo` 函数的开始或 `bar` 函数的 `console.log` 语句处设置断点。当 JavaScript 引擎执行到这些位置时，调试器会暂停执行。
* **条件断点:**  类似于 C++ 代码中的 `SetBreakPoint(foo, 0, "a == true")`，开发者可以在浏览器的开发者工具中设置条件断点，例如只在变量 `a` 的值为 `true` 时暂停。
* **内置函数调试:**  开发者理论上（不同调试器支持程度不同）可以在内置函数内部设置断点，例如在 `String.prototype.repeat` 的实现中。
* **单步执行:**  开发者可以使用调试器的 "Step Over"、"Step Into"、"Step Out" 等功能逐行执行代码，这对应于 C++ 代码中的 `PrepareStep` 函数将准备执行的下一步操作。

**4. 代码逻辑推理 (假设输入与输出):**

让我们看一个简单的测试用例 `TEST(BreakPointICStore)`：

**假设输入:**

* 运行以下 JavaScript 代码：
  ```javascript
  function foo(){bar=0;}
  foo();
  foo();
  ```
* 在 `foo` 函数的开头设置一个断点。

**代码逻辑推理:**

测试代码会执行 `foo()` 函数。由于在 `foo` 的开头设置了断点，每次调用 `foo` 时，`break_point_hit_count` 变量应该会递增。

**预期输出:**

* 第一次调用 `foo()` 后，`break_point_hit_count` 的值为 1。
* 第二次调用 `foo()` 后，`break_point_hit_count` 的值为 2。

**5. 涉及用户常见的编程错误:**

虽然这段代码主要是测试调试器本身，但调试器的存在就是为了帮助开发者定位和修复编程错误。常见的编程错误包括：

* **逻辑错误:** 代码没有按照预期的方式执行，导致结果不正确。断点可以帮助开发者追踪代码的执行流程，查看变量的值，从而找到逻辑错误所在。
  ```javascript
  function calculateSum(a, b) {
    return a - b; // 错误：应该是 a + b
  }
  console.log(calculateSum(5, 2)); // 期望输出 7，实际输出 3
  ```
* **运行时错误:**  例如 `TypeError`、`ReferenceError` 等。断点可以帮助开发者在错误发生前暂停执行，查看当时的上下文，理解错误发生的原因。
  ```javascript
  function accessUndefinedProperty(obj) {
    return obj.name.length; // 如果 obj 没有 name 属性，会抛出 TypeError
  }
  let myObject = {};
  console.log(accessUndefinedProperty(myObject));
  ```
* **异步问题:**  调试异步代码（例如使用 `setTimeout`、Promises 等）可能会比较复杂。调试器可以帮助开发者理解异步操作的执行顺序和时间。

**6. 这是第1部分，共8部分，请归纳一下它的功能:**

作为第 1 部分，这段代码主要 **集中在测试 V8 调试器的基础断点功能**，包括：

* **基本断点的设置和清除。**
* **在不同代码位置（例如 IC 调用点）设置断点的能力。**
* **带条件的断点。**
* **调试器对内置函数的支持。**
* **垃圾回收发生时断点的持久性。**

后续的 7 个部分很可能会扩展到测试调试器的其他功能，例如单步执行、查看调用栈、修改变量值、处理异常断点等等。

总而言之，`v8/test/cctest/test-debug.cc` 的这段代码是 V8 团队用来确保其 JavaScript 调试器按预期工作的自动化测试用例。它覆盖了调试器的核心功能，并使用 C++ 编写测试来模拟各种 JavaScript 调试场景。

Prompt: 
```
这是目录为v8/test/cctest/test-debug.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-debug.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共8部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
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

#include <stdlib.h>

#include "include/v8-extension.h"
#include "include/v8-function.h"
#include "include/v8-json.h"
#include "include/v8-locker.h"
#include "src/api/api-inl.h"
#include "src/base/strings.h"
#include "src/codegen/compilation-cache.h"
#include "src/debug/debug-interface.h"
#include "src/debug/debug-scopes.h"
#include "src/debug/debug.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/frames-inl.h"
#include "src/execution/microtask-queue.h"
#include "src/objects/objects-inl.h"
#include "src/utils/utils.h"
#include "test/cctest/cctest.h"
#include "test/cctest/heap/heap-utils.h"

using ::v8::internal::DirectHandle;
using ::v8::internal::Handle;
using ::v8::internal::StepInto;  // From StepAction enum
using ::v8::internal::StepNone;  // From StepAction enum
using ::v8::internal::StepOut;   // From StepAction enum
using ::v8::internal::StepOver;  // From StepAction enum

// --- H e l p e r   F u n c t i o n s

// Compile and run the supplied source and return the requested function.
static v8::Local<v8::Function> CompileFunction(v8::Isolate* isolate,
                                               const char* source,
                                               const char* function_name) {
  CompileRunChecked(isolate, source);
  v8::Local<v8::String> name = v8_str(isolate, function_name);
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  v8::MaybeLocal<v8::Value> maybe_function =
      context->Global()->Get(context, name);
  return v8::Local<v8::Function>::Cast(maybe_function.ToLocalChecked());
}


// Compile and run the supplied source and return the requested function.
static v8::Local<v8::Function> CompileFunction(LocalContext* env,
                                               const char* source,
                                               const char* function_name) {
  return CompileFunction((*env)->GetIsolate(), source, function_name);
}

// Is there any debug info for the function?
static bool HasBreakInfo(v8::Local<v8::Function> fun) {
  DirectHandle<v8::internal::JSFunction> f =
      Cast<v8::internal::JSFunction>(v8::Utils::OpenDirectHandle(*fun));
  return f->shared()->HasBreakInfo(f->GetIsolate());
}

// Set a break point in a function with a position relative to function start,
// and return the associated break point number.
static i::Handle<i::BreakPoint> SetBreakPoint(v8::Local<v8::Function> fun,
                                              int position,
                                              const char* condition = nullptr) {
  i::DirectHandle<i::JSFunction> function =
      i::Cast<i::JSFunction>(v8::Utils::OpenDirectHandle(*fun));
  position += function->shared()->StartPosition();
  static int break_point_index = 0;
  i::Isolate* isolate = function->GetIsolate();
  i::DirectHandle<i::String> condition_string =
      condition ? isolate->factory()->NewStringFromAsciiChecked(condition)
                : isolate->factory()->empty_string();
  i::Debug* debug = isolate->debug();
  i::Handle<i::BreakPoint> break_point =
      isolate->factory()->NewBreakPoint(++break_point_index, condition_string);

  debug->SetBreakpoint(handle(function->shared(), isolate), break_point,
                       &position);
  return break_point;
}

static void ClearBreakPoint(i::DirectHandle<i::BreakPoint> break_point) {
  v8::internal::Isolate* isolate = CcTest::i_isolate();
  v8::internal::Debug* debug = isolate->debug();
  debug->ClearBreakPoint(break_point);
}

// Change break on exception.
static void ChangeBreakOnException(v8::Isolate* isolate, bool caught,
                                   bool uncaught) {
  v8::internal::Debug* debug =
      reinterpret_cast<v8::internal::Isolate*>(isolate)->debug();
  debug->ChangeBreakOnException(v8::internal::BreakCaughtException, caught);
  debug->ChangeBreakOnException(v8::internal::BreakUncaughtException, uncaught);
}

// Prepare to step to next break location.
static void PrepareStep(i::StepAction step_action) {
  v8::internal::Debug* debug = CcTest::i_isolate()->debug();
  debug->PrepareStep(step_action);
}

// This function is in namespace v8::internal to be friend with class
// v8::internal::Debug.
namespace v8 {
namespace internal {

Handle<FixedArray> GetDebuggedFunctions() {
  i::Isolate* isolate = CcTest::i_isolate();
  DebugInfoCollection* infos = &isolate->debug()->debug_infos_;

  int count = static_cast<int>(infos->Size());
  Handle<FixedArray> debugged_functions =
      CcTest::i_isolate()->factory()->NewFixedArray(count);

  int i = 0;
  DebugInfoCollection::Iterator it(infos);
  for (; it.HasNext(); it.Advance()) {
    DirectHandle<DebugInfo> debug_info(it.Next(), isolate);
    debugged_functions->set(i++, *debug_info);
  }

  return debugged_functions;
}

// Check that the debugger has been fully unloaded.
void CheckDebuggerUnloaded() {
  // Check that the debugger context is cleared and that there is no debug
  // information stored for the debugger.
  CHECK_EQ(CcTest::i_isolate()->debug()->debug_infos_.Size(), 0);

  // Collect garbage to ensure weak handles are cleared.
  {
    // We need to invoke GC without stack, otherwise some objects may not be
    // reclaimed because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    heap::InvokeMajorGC(CcTest::heap());
    heap::InvokeMajorGC(CcTest::heap());
  }

  // Iterate the heap and check that there are no debugger related objects left.
  HeapObjectIterator iterator(CcTest::heap());
  for (Tagged<HeapObject> obj = iterator.Next(); !obj.is_null();
       obj = iterator.Next()) {
    CHECK(!IsDebugInfo(obj));
  }
}


}  // namespace internal
}  // namespace v8


// Check that the debugger has been fully unloaded.
static void CheckDebuggerUnloaded() { v8::internal::CheckDebuggerUnloaded(); }

// --- D e b u g   E v e n t   H a n d l e r s
// ---
// --- The different tests uses a number of debug event handlers.
// ---

// Debug event handler which counts a number of events.
int break_point_hit_count = 0;
int break_point_hit_count_deoptimize = 0;
class DebugEventCounter : public v8::debug::DebugDelegate {
 public:
  void BreakProgramRequested(v8::Local<v8::Context>,
                             const std::vector<v8::debug::BreakpointId>&,
                             v8::debug::BreakReasons break_reasons) override {
    break_point_hit_count++;
    // Perform a full deoptimization when the specified number of
    // breaks have been hit.
    if (break_point_hit_count == break_point_hit_count_deoptimize) {
      i::Deoptimizer::DeoptimizeAll(CcTest::i_isolate());
    }
    if (step_action_ != StepNone) PrepareStep(step_action_);
  }

  void set_step_action(i::StepAction step_action) {
    step_action_ = step_action;
  }

 private:
  i::StepAction step_action_ = StepNone;
};

// Debug event handler which performs a garbage collection.
class DebugEventBreakPointCollectGarbage : public v8::debug::DebugDelegate {
 public:
  void BreakProgramRequested(v8::Local<v8::Context>,
                             const std::vector<v8::debug::BreakpointId>&,
                             v8::debug::BreakReasons break_reasons) override {
    // Perform a garbage collection when break point is hit and continue. Based
    // on the number of break points hit either scavenge or mark compact
    // collector is used.
    break_point_hit_count++;
    if (break_point_hit_count % 2 == 0) {
      // Scavenge.
      i::heap::InvokeMinorGC(CcTest::heap());
    } else {
      // Mark sweep compact.
      i::heap::InvokeMajorGC(CcTest::heap());
    }
  }
};

// Debug event handler which re-issues a debug break and calls the garbage
// collector to have the heap verified.
class DebugEventBreak : public v8::debug::DebugDelegate {
 public:
  void BreakProgramRequested(v8::Local<v8::Context>,
                             const std::vector<v8::debug::BreakpointId>&,
                             v8::debug::BreakReasons break_reasons) override {
    // Count the number of breaks.
    break_point_hit_count++;

    // Run the garbage collector to enforce heap verification if option
    // --verify-heap is set.
    i::heap::InvokeMinorGC(CcTest::heap());

    // Set the break flag again to come back here as soon as possible.
    v8::debug::SetBreakOnNextFunctionCall(CcTest::isolate());
  }
};

v8::debug::BreakReasons break_right_now_reasons = {};
static void BreakRightNow(v8::Isolate* isolate, void*) {
  v8::debug::BreakRightNow(isolate, break_right_now_reasons);
}

// Debug event handler which re-issues a debug break until a limit has been
// reached.
int max_break_point_hit_count = 0;
bool terminate_after_max_break_point_hit = false;
class DebugEventBreakMax : public v8::debug::DebugDelegate {
 public:
  void BreakProgramRequested(v8::Local<v8::Context>,
                             const std::vector<v8::debug::BreakpointId>&,
                             v8::debug::BreakReasons break_reasons) override {
    v8::Isolate* v8_isolate = CcTest::isolate();
    v8::internal::Isolate* isolate = CcTest::i_isolate();
    if (break_point_hit_count < max_break_point_hit_count) {
      // Count the number of breaks.
      break_point_hit_count++;

      // Set the break flag again to come back here as soon as possible.
      v8_isolate->RequestInterrupt(BreakRightNow, nullptr);

    } else if (terminate_after_max_break_point_hit) {
      // Terminate execution after the last break if requested.
      v8_isolate->TerminateExecution();
    }

    // Perform a full deoptimization when the specified number of
    // breaks have been hit.
    if (break_point_hit_count == break_point_hit_count_deoptimize) {
      i::Deoptimizer::DeoptimizeAll(isolate);
    }
  }
};

// --- T h e   A c t u a l   T e s t s

// Test that the debug info in the VM is in sync with the functions being
// debugged.
TEST(DebugInfo) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  // Create a couple of functions for the test.
  v8::Local<v8::Function> foo =
      CompileFunction(&env, "function foo(){}", "foo");
  v8::Local<v8::Function> bar =
      CompileFunction(&env, "function bar(){}", "bar");
  // Initially no functions are debugged.
  CHECK_EQ(0, v8::internal::GetDebuggedFunctions()->length());
  CHECK(!HasBreakInfo(foo));
  CHECK(!HasBreakInfo(bar));
  EnableDebugger(env->GetIsolate());
  // One function (foo) is debugged.
  i::DirectHandle<i::BreakPoint> bp1 = SetBreakPoint(foo, 0);
  CHECK_EQ(1, v8::internal::GetDebuggedFunctions()->length());
  CHECK(HasBreakInfo(foo));
  CHECK(!HasBreakInfo(bar));
  // Two functions are debugged.
  i::DirectHandle<i::BreakPoint> bp2 = SetBreakPoint(bar, 0);
  CHECK_EQ(2, v8::internal::GetDebuggedFunctions()->length());
  CHECK(HasBreakInfo(foo));
  CHECK(HasBreakInfo(bar));
  // One function (bar) is debugged.
  ClearBreakPoint(bp1);
  CHECK_EQ(1, v8::internal::GetDebuggedFunctions()->length());
  CHECK(!HasBreakInfo(foo));
  CHECK(HasBreakInfo(bar));
  // No functions are debugged.
  ClearBreakPoint(bp2);
  DisableDebugger(env->GetIsolate());
  CHECK_EQ(0, v8::internal::GetDebuggedFunctions()->length());
  CHECK(!HasBreakInfo(foo));
  CHECK(!HasBreakInfo(bar));
}


// Test that a break point can be set at an IC store location.
TEST(BreakPointICStore) {
  break_point_hit_count = 0;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  v8::Local<v8::Function> foo =
      CompileFunction(&env, "function foo(){bar=0;}", "foo");

  // Run without breakpoints.
  foo->Call(env.local(), env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(0, break_point_hit_count);

  // Run with breakpoint
  i::DirectHandle<i::BreakPoint> bp = SetBreakPoint(foo, 0);
  foo->Call(env.local(), env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(1, break_point_hit_count);
  foo->Call(env.local(), env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(2, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  foo->Call(env.local(), env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(2, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

// Test that a break point can be set at an IC store location.
TEST(BreakPointCondition) {
  break_point_hit_count = 0;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  CompileRun("var a = false");
  v8::Local<v8::Function> foo =
      CompileFunction(&env, "function foo() { return 1 }", "foo");
  // Run without breakpoints.
  CompileRun("foo()");
  CHECK_EQ(0, break_point_hit_count);

  // Run with breakpoint
  i::DirectHandle<i::BreakPoint> bp = SetBreakPoint(foo, 0, "a == true");
  CompileRun("foo()");
  CHECK_EQ(0, break_point_hit_count);

  CompileRun("a = true");
  CompileRun("foo()");
  CHECK_EQ(1, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  CompileRun("foo()");
  CHECK_EQ(1, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

// Test that a break point can be set at an IC load location.
TEST(BreakPointICLoad) {
  break_point_hit_count = 0;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  CompileRunChecked(env->GetIsolate(), "bar=1");
  v8::Local<v8::Function> foo =
      CompileFunction(&env, "function foo(){var x=bar;}", "foo");

  // Run without breakpoints.
  foo->Call(env.local(), env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(0, break_point_hit_count);

  // Run with breakpoint.
  i::DirectHandle<i::BreakPoint> bp = SetBreakPoint(foo, 0);
  foo->Call(env.local(), env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(1, break_point_hit_count);
  foo->Call(env.local(), env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(2, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  foo->Call(env.local(), env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(2, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


// Test that a break point can be set at an IC call location.
TEST(BreakPointICCall) {
  break_point_hit_count = 0;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  CompileRunChecked(env->GetIsolate(), "function bar(){}");
  v8::Local<v8::Function> foo =
      CompileFunction(&env, "function foo(){bar();}", "foo");

  // Run without breakpoints.
  foo->Call(env.local(), env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(0, break_point_hit_count);

  // Run with breakpoint
  i::DirectHandle<i::BreakPoint> bp = SetBreakPoint(foo, 0);
  foo->Call(env.local(), env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(1, break_point_hit_count);
  foo->Call(env.local(), env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(2, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  foo->Call(env.local(), env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(2, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


// Test that a break point can be set at an IC call location and survive a GC.
TEST(BreakPointICCallWithGC) {
  break_point_hit_count = 0;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  DebugEventBreakPointCollectGarbage delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  CompileRunChecked(env->GetIsolate(), "function bar(){return 1;}");
  v8::Local<v8::Function> foo =
      CompileFunction(&env, "function foo(){return bar();}", "foo");
  v8::Local<v8::Context> context = env.local();

  // Run without breakpoints.
  CHECK_EQ(1, foo->Call(context, env->Global(), 0, nullptr)
                  .ToLocalChecked()
                  ->Int32Value(context)
                  .FromJust());
  CHECK_EQ(0, break_point_hit_count);

  // Run with breakpoint.
  i::DirectHandle<i::BreakPoint> bp = SetBreakPoint(foo, 0);
  CHECK_EQ(1, foo->Call(context, env->Global(), 0, nullptr)
                  .ToLocalChecked()
                  ->Int32Value(context)
                  .FromJust());
  CHECK_EQ(1, break_point_hit_count);
  CHECK_EQ(1, foo->Call(context, env->Global(), 0, nullptr)
                  .ToLocalChecked()
                  ->Int32Value(context)
                  .FromJust());
  CHECK_EQ(2, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(2, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


// Test that a break point can be set at an IC call location and survive a GC.
TEST(BreakPointConstructCallWithGC) {
  break_point_hit_count = 0;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  DebugEventBreakPointCollectGarbage delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  CompileRunChecked(env->GetIsolate(), "function bar(){ this.x = 1;}");
  v8::Local<v8::Function> foo =
      CompileFunction(&env, "function foo(){return new bar(1).x;}", "foo");
  v8::Local<v8::Context> context = env.local();

  // Run without breakpoints.
  CHECK_EQ(1, foo->Call(context, env->Global(), 0, nullptr)
                  .ToLocalChecked()
                  ->Int32Value(context)
                  .FromJust());
  CHECK_EQ(0, break_point_hit_count);

  // Run with breakpoint.
  i::DirectHandle<i::BreakPoint> bp = SetBreakPoint(foo, 0);
  CHECK_EQ(1, foo->Call(context, env->Global(), 0, nullptr)
                  .ToLocalChecked()
                  ->Int32Value(context)
                  .FromJust());
  CHECK_EQ(1, break_point_hit_count);
  CHECK_EQ(1, foo->Call(context, env->Global(), 0, nullptr)
                  .ToLocalChecked()
                  ->Int32Value(context)
                  .FromJust());
  CHECK_EQ(2, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(2, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


TEST(BreakPointBuiltin) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  v8::Local<v8::Function> builtin;
  i::DirectHandle<i::BreakPoint> bp;

  // === Test simple builtin ===
  break_point_hit_count = 0;
  builtin = CompileRun("String.prototype.repeat").As<v8::Function>();

  // Run with breakpoint.
  bp = SetBreakPoint(builtin, 0, "this != 1");
  ExpectString("'b'.repeat(10)", "bbbbbbbbbb");
  CHECK_EQ(1, break_point_hit_count);

  ExpectString("'b'.repeat(10)", "bbbbbbbbbb");
  CHECK_EQ(2, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  ExpectString("'b'.repeat(10)", "bbbbbbbbbb");
  CHECK_EQ(2, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(BreakPointApiIntrinsics) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  // === Test that using API-exposed functions won't trigger breakpoints ===
  {
    v8::Local<v8::Function> weakmap_get =
        CompileRun("WeakMap.prototype.get").As<v8::Function>();
    SetBreakPoint(weakmap_get, 0);
    v8::Local<v8::Function> weakmap_set =
        CompileRun("WeakMap.prototype.set").As<v8::Function>();
    SetBreakPoint(weakmap_set, 0);

    // Run with breakpoint.
    break_point_hit_count = 0;
    CompileRun("var w = new WeakMap(); w.set(w, 1); w.get(w);");
    CHECK_EQ(2, break_point_hit_count);

    break_point_hit_count = 0;
    v8::Local<v8::debug::EphemeronTable> weakmap =
        v8::debug::EphemeronTable::New(env->GetIsolate());
    v8::Local<v8::Object> key = v8::Object::New(env->GetIsolate());
    CHECK(!weakmap->Set(env->GetIsolate(), key, v8_num(1)).IsEmpty());
    CHECK(!weakmap->Get(env->GetIsolate(), key).IsEmpty());
    CHECK_EQ(0, break_point_hit_count);
  }

  {
    v8::Local<v8::Function> object_to_string =
        CompileRun("Object.prototype.toString").As<v8::Function>();
    SetBreakPoint(object_to_string, 0);

    // Run with breakpoint.
    break_point_hit_count = 0;
    CompileRun("var o = {}; o.toString();");
    CHECK_EQ(1, break_point_hit_count);

    break_point_hit_count = 0;
    v8::Local<v8::Object> object = v8::Object::New(env->GetIsolate());
    CHECK(!object->ObjectProtoToString(env.local()).IsEmpty());
    CHECK_EQ(0, break_point_hit_count);
  }

  {
    v8::Local<v8::Function> map_set =
        CompileRun("Map.prototype.set").As<v8::Function>();
    v8::Local<v8::Function> map_get =
        CompileRun("Map.prototype.get").As<v8::Function>();
    v8::Local<v8::Function> map_has =
        CompileRun("Map.prototype.has").As<v8::Function>();
    v8::Local<v8::Function> map_delete =
        CompileRun("Map.prototype.delete").As<v8::Function>();
    SetBreakPoint(map_set, 0);
    SetBreakPoint(map_get, 0);
    SetBreakPoint(map_has, 0);
    SetBreakPoint(map_delete, 0);

    // Run with breakpoint.
    break_point_hit_count = 0;
    CompileRun(
        "var m = new Map(); m.set(m, 1); m.get(m); m.has(m); m.delete(m);");
    CHECK_EQ(4, break_point_hit_count);

    break_point_hit_count = 0;
    v8::Local<v8::Map> map = v8::Map::New(env->GetIsolate());
    CHECK(!map->Set(env.local(), map, v8_num(1)).IsEmpty());
    CHECK(!map->Get(env.local(), map).IsEmpty());
    CHECK(map->Has(env.local(), map).FromJust());
    CHECK(map->Delete(env.local(), map).FromJust());
    CHECK_EQ(0, break_point_hit_count);
  }

  {
    v8::Local<v8::Function> set_add =
        CompileRun("Set.prototype.add").As<v8::Function>();
    v8::Local<v8::Function> set_get =
        CompileRun("Set.prototype.has").As<v8::Function>();
    v8::Local<v8::Function> set_delete =
        CompileRun("Set.prototype.delete").As<v8::Function>();
    SetBreakPoint(set_add, 0);
    SetBreakPoint(set_get, 0);
    SetBreakPoint(set_delete, 0);

    // Run with breakpoint.
    break_point_hit_count = 0;
    CompileRun("var s = new Set(); s.add(s); s.has(s); s.delete(s);");
    CHECK_EQ(3, break_point_hit_count);

    break_point_hit_count = 0;
    v8::Local<v8::Set> set = v8::Set::New(env->GetIsolate());
    CHECK(!set->Add(env.local(), set).IsEmpty());
    CHECK(set->Has(env.local(), set).FromJust());
    CHECK(set->Delete(env.local(), set).FromJust());
    CHECK_EQ(0, break_point_hit_count);
  }

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(BreakPointJSBuiltin) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  v8::Local<v8::Function> builtin;
  i::DirectHandle<i::BreakPoint> bp;

  // === Test JS builtin ===
  break_point_hit_count = 0;
  builtin = CompileRun("Array.prototype.sort").As<v8::Function>();

  // Run with breakpoint.
  bp = SetBreakPoint(builtin, 0);
  CompileRun("[1,2,3].sort()");
  CHECK_EQ(1, break_point_hit_count);

  CompileRun("[1,2,3].sort()");
  CHECK_EQ(2, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  CompileRun("[1,2,3].sort()");
  CHECK_EQ(2, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(BreakPointBoundBuiltin) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  v8::Local<v8::Function> builtin;
  i::DirectHandle<i::BreakPoint> bp;

  // === Test bound function from a builtin ===
  break_point_hit_count = 0;
  builtin = CompileRun(
                "var boundrepeat = String.prototype.repeat.bind('a');"
                "String.prototype.repeat")
                .As<v8::Function>();
  ExpectString("boundrepeat(10)", "aaaaaaaaaa");
  CHECK_EQ(0, break_point_hit_count);

  // Run with breakpoint.
  bp = SetBreakPoint(builtin, 0);
  ExpectString("boundrepeat(10)", "aaaaaaaaaa");
  CHECK_EQ(1, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  ExpectString("boundrepeat(10)", "aaaaaaaaaa");
  CHECK_EQ(1, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(BreakPointConstructorBuiltin) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  v8::Local<v8::Function> builtin;
  i::DirectHandle<i::BreakPoint> bp;

  // === Test Promise constructor ===
  break_point_hit_count = 0;
  builtin = CompileRun("Promise").As<v8::Function>();
  ExpectString("(new Promise(()=>{})).toString()", "[object Promise]");
  CHECK_EQ(0, break_point_hit_count);

  // Run with breakpoint.
  bp = SetBreakPoint(builtin, 0, "this != 1");
  ExpectString("(new Promise(()=>{})).toString()", "[object Promise]");
  CHECK_EQ(1, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  ExpectString("(new Promise(()=>{})).toString()", "[object Promise]");
  CHECK_EQ(1, break_point_hit_count);

  // === Test Object constructor ===
  break_point_hit_count = 0;
  builtin = CompileRun("Object").As<v8::Function>();
  CompileRun("new Object()");
  CHECK_EQ(0, break_point_hit_count);

  // Run with breakpoint.
  bp = SetBreakPoint(builtin, 0);
  CompileRun("new Object()");
  CHECK_EQ(1, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  CompileRun("new Object()");
  CHECK_EQ(1, break_point_hit_count);

  // === Test Number constructor ===
  break_point_hit_count = 0;
  builtin = CompileRun("Number").As<v8::Function>();
  CompileRun("new Number()");
  CHECK_EQ(0, break_point_hit_count);

  // Run with breakpoint.
  bp = SetBreakPoint(builtin, 0);
  CompileRun("new Number()");
  CHECK_EQ(1, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  CompileRun("new Number()");
  CHECK_EQ(1, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(BreakPointInlinedBuiltin) {
  i::v8_flags.allow_natives_syntax = true;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  v8::Local<v8::Function> builtin;
  i::DirectHandle<i::BreakPoint> bp;

  // === Test inlined builtin ===
  break_point_hit_count = 0;
  builtin = CompileRun("Math.sin").As<v8::Function>();
  CompileRun("function test(x) { return 1 + Math.sin(x) }");
  CompileRun(
      "%PrepareFunctionForOptimization(test);"
      "test(0.5); test(0.6);"
      "%OptimizeFunctionOnNextCall(test); test(0.7);");
  CHECK_EQ(0, break_point_hit_count);

  // Run with breakpoint.
  bp = SetBreakPoint(builtin, 0, "this != 1");
  CompileRun("Math.sin(0.1);");
  CHECK_EQ(1, break_point_hit_count);
  CompileRun("test(0.2);");
  CHECK_EQ(2, break_point_hit_count);

  // Re-optimize.
  CompileRun(
      "%PrepareFunctionForOptimization(test);"
      "%OptimizeFunctionOnNextCall(test);");
  ExpectBoolean("test(0.3) < 2", true);
  CHECK_EQ(3, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  CompileRun("test(0.3);");
  CHECK_EQ(3, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(BreakPointInlineBoundBuiltin) {
  i::v8_flags.allow_natives_syntax = true;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  v8::Local<v8::Function> builtin;
  i::DirectHandle<i::BreakPoint> bp;

  // === Test inlined bound builtin ===
  break_point_hit_count = 0;

  builtin = CompileRun(
                "var boundrepeat = String.prototype.repeat.bind('a');"
                "String.prototype.repeat")
                .As<v8::Function>();
  CompileRun("function test(x) { return 'a' + boundrepeat(x) }");
  CompileRun(
      "%PrepareFunctionForOptimization(test);"
      "test(4); test(5);"
      "%OptimizeFunctionOnNextCall(test); test(6);");
  CHECK_EQ(0, break_point_hit_count);

  // Run with breakpoint.
  bp = SetBreakPoint(builtin, 0, "this != 1");
  CompileRun("'a'.repeat(2);");
  CHECK_EQ(1, break_point_hit_count);
  CompileRun("test(7);");
  CHECK_EQ(2, break_point_hit_count);

  // Re-optimize.
  CompileRun(
      "%PrepareFunctionForOptimization(f);"
      "%OptimizeFunctionOnNextCall(test);");
  CompileRun("test(8);");
  CHECK_EQ(3, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  CompileRun("test(9);");
  CHECK_EQ(3, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(BreakPointInlinedConstructorBuiltin) {
  i::v8_flags.allow_natives_syntax = true;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  v8::Local<v8::Function> builtin;
  i::DirectHandle<i::BreakPoint> bp;

  // === Test inlined constructor builtin (regular construct builtin) ===
  break_point_hit_count = 0;
  builtin = CompileRun("Promise").As<v8::Function>();
  CompileRun("function test(x) { return new Promise(()=>x); }");
  CompileRun(
      "%PrepareFunctionForOptimization(test);"
      "test(4); test(5);"
      "%OptimizeFunctionOnNextCall(test); test(6);");
  CHECK_EQ(0, break_point_hit_count);

  // Run with breakpoint.
  bp = SetBreakPoint(builtin, 0, "this != 1");
  CompileRun("new Promise(()=>{});");
  CHECK_EQ(1, break_point_hit_count);
  CompileRun("test(7);");
  CHECK_EQ(2, break_point_hit_count);

  // Re-optimize.
  CompileRun(
      "%PrepareFunctionForOptimization(f);"
      "%OptimizeFunctionOnNextCall(test);");
  CompileRun("test(8);");
  CHECK_EQ(3, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  CompileRun("test(9);");
  CHECK_EQ(3, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(BreakPointBuiltinConcurrentOpt) {
  i::v8_flags.allow_natives_syntax = true;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  v8::Local<v8::Function> builtin;
  i::DirectHandle<i::BreakPoint> bp;

  // === Test concurrent optimization ===
  break_point_hit_count = 0;
  builtin = CompileRun("Math.sin").As<v8::Function>();
  CompileRun("function test(x) { return 1 + Math.sin(x) }");
  CompileRun(
      "%PrepareFunctionForOpti
"""


```