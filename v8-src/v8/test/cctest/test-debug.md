Response: The user wants me to summarize the functionality of the C++ code provided in the first part of the file `v8/test/cctest/test-debug.cc`.
This file seems to contain tests for the debugging functionality of the V8 JavaScript engine.
It includes setting breakpoints, stepping through code, handling debug events, and testing these features with various JavaScript constructs.

I need to identify the main functionalities being tested in this first part of the file.
It appears to be focused on:
1. **Basic breakpoint functionality:** Setting, clearing breakpoints, conditional breakpoints.
2. **Breakpoints in different code locations:** IC (Inline Cache) stores, loads, calls, builtin functions, API functions.
3. **Interaction with garbage collection:** Ensuring breakpoints survive GC.
4. **Debugger statement:** Testing the `debugger` statement and breakpoints on it.
5. **Stepping:** Basic linear stepping functionality.

I will also need to provide Javascript examples to illustrate how these debugging features relate to Javascript code execution.
这个C++代码文件是V8 JavaScript引擎的调试功能测试套件的一部分。这个特定的部分（第1部分）主要关注以下功能点的测试：

1. **断点基础功能**:
   - 测试断点的设置和清除 (`SetBreakPoint`, `ClearBreakPoint`).
   - 测试断点是否能在函数起始位置正确设置.
   - 测试带条件的断点 (`SetBreakPoint` with a condition string).

2. **不同类型的代码位置断点**:
   - 测试在内联缓存 (IC) 的存储操作 (`BreakPointICStore`)，加载操作 (`BreakPointICLoad`)，调用操作 (`BreakPointICCall`) 上设置断点。
   - 测试在内置函数 (built-in functions) 上设置断点 (`BreakPointBuiltin`, `BreakPointJSBuiltin`, `BreakPointBoundBuiltin`, `BreakPointConstructorBuiltin`, `BreakPointInlinedBuiltin`, `BreakPointInlineBoundBuiltin`, `BreakPointInlinedConstructorBuiltin`, `BreakPointBuiltinConcurrentOpt`, `BreakPointBuiltinTFOperator`, `BreakPointBuiltinNewContext`).
   - 测试在C++ API 定义的函数上设置断点 (`BreakPointApiFunction`, `BreakPointApiConstructor`, `BreakPointApiGetter`, `BreakPointApiSetter`, `BreakPointApiAccessor`, `BreakPointInlineApiFunction`).

3. **断点与垃圾回收的交互**:
   - 测试在垃圾回收过程中断点是否仍然有效 (`BreakPointICCallWithGC`, `BreakPointConstructCallWithGC`, `GCDuringBreakPointProcessing`, `BreakPointSurviveGC`).

4. **`debugger` 语句**:
   - 测试 `debugger` 语句是否能触发断点 (`DebuggerStatement`).
   - 测试在 `debugger` 语句上设置断点 (`DebuggerStatementBreakpoint`).

5. **代码生成限制下的条件断点**:
   - 测试当禁止从字符串生成代码时，条件断点是否仍然有效 (`ConditionalBreakpointWithCodeGenerationDisallowed`).

6. **代码单步执行**:
   - 测试基本的线性单步执行功能 (`DebugStepLinear`).

以下是一些与上述 C++ 代码测试功能相关的 JavaScript 示例：

**1. 断点基础功能：**

```javascript
function myFunction(a, b) { // 可以在这里设置断点
  let sum = a + b;
  return sum; // 也可以在这里设置断点
}

myFunction(5, 10);
```

**2. 不同类型的代码位置断点：**

* **IC 存储断点:**

```javascript
var obj = {};
function foo() {
  obj.prop = 1; // 测试在这里设置断点
}
foo();
```

* **IC 加载断点:**

```javascript
var obj = { prop: 1 };
function foo() {
  var x = obj.prop; // 测试在这里设置断点
  return x;
}
foo();
```

* **IC 调用断点:**

```javascript
function bar() {
  return 5;
}
function foo() {
  bar(); // 测试在这里设置断点
}
foo();
```

* **内置函数断点:**

```javascript
var str = "hello";
str.repeat(3); // 测试在 String.prototype.repeat 的实现中设置断点
```

* **API 函数断点:**

假设有一个通过 C++ API 注册到 V8 的函数 `nativeFunction`:

```javascript
nativeFunction(10); // 测试在 nativeFunction 的 C++ 实现中设置断点
```

* **Getter/Setter 断点:**

```javascript
var obj = {
  _value: 0,
  get myProp() { // 测试在 getter 函数中设置断点
    return this._value;
  },
  set myProp(newValue) { // 测试在 setter 函数中设置断点
    this._value = newValue;
  }
};

obj.myProp = 5;
console.log(obj.myProp);
```

**3. 断点与垃圾回收的交互：**

（这类功能通常不需要直接的 JavaScript 代码示例，因为它是 V8 引擎内部的处理机制。测试确保即使在垃圾回收发生时，断点仍然有效。）

**4. `debugger` 语句：**

```javascript
function myFunction(a) {
  debugger; // 代码执行到这里会暂停，触发断点
  return a * 2;
}

myFunction(5);
```

**5. 代码生成限制下的条件断点：**

```javascript
function foo(x) {
  var y = 10;
  return x + y; // 设置条件断点，例如当 x > 5 时暂停
}

foo(3);
foo(7);
```

**6. 代码单步执行：**

（单步执行是通过调试器提供的功能，允许开发者逐行执行代码。）

总而言之，这个 C++ 测试文件的第一部分专注于 V8 引擎在处理各种 JavaScript 调试场景时的核心断点功能，确保断点在不同的代码位置、与垃圾回收交互以及在特定的限制条件下都能正常工作。

Prompt: 
```
这是目录为v8/test/cctest/test-debug.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共4部分，请归纳一下它的功能

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
      "%PrepareFunctionForOptimization(test);"
      "test(0.5); test(0.6);"
      "%DisableOptimizationFinalization();"
      "%OptimizeFunctionOnNextCall(test, 'concurrent');"
      "test(0.7);");
  CHECK_EQ(0, break_point_hit_count);

  // Run with breakpoint.
  bp = SetBreakPoint(builtin, 0);
  // Have the concurrent compile job finish now.
  CompileRun(
      "%FinalizeOptimization();"
      "%GetOptimizationStatus(test);");
  CompileRun("test(0.2);");
  CHECK_EQ(1, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  CompileRun("test(0.3);");
  CHECK_EQ(1, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(BreakPointBuiltinTFOperator) {
  i::v8_flags.allow_natives_syntax = true;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  v8::Local<v8::Function> builtin;
  i::DirectHandle<i::BreakPoint> bp;

  // === Test builtin represented as operator ===
  break_point_hit_count = 0;
  builtin = CompileRun("String.prototype.indexOf").As<v8::Function>();
  CompileRun("function test(x) { return 1 + 'foo'.indexOf(x) }");
  CompileRun(
      "%PrepareFunctionForOptimization(f);"
      "test('a'); test('b');"
      "%OptimizeFunctionOnNextCall(test); test('c');");
  CHECK_EQ(0, break_point_hit_count);

  // Run with breakpoint.
  bp = SetBreakPoint(builtin, 0);
  CompileRun("'bar'.indexOf('x');");
  CHECK_EQ(1, break_point_hit_count);
  CompileRun("test('d');");
  CHECK_EQ(2, break_point_hit_count);

  // Re-optimize.
  CompileRun(
      "%PrepareFunctionForOptimization(f);"
      "%OptimizeFunctionOnNextCall(test);");
  CompileRun("test('e');");
  CHECK_EQ(3, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  CompileRun("test('f');");
  CHECK_EQ(3, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(BreakPointBuiltinNewContext) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  v8::Local<v8::Function> builtin;
  i::DirectHandle<i::BreakPoint> bp;

  // === Test builtin from a new context ===
  break_point_hit_count = 0;
  builtin = CompileRun("String.prototype.repeat").As<v8::Function>();
  CompileRun("'a'.repeat(10)");
  CHECK_EQ(0, break_point_hit_count);
  // Set breakpoint.
  bp = SetBreakPoint(builtin, 0);

  {
    // Create and use new context after breakpoint has been set.
    v8::HandleScope handle_scope(env->GetIsolate());
    v8::Local<v8::Context> new_context = v8::Context::New(env->GetIsolate());
    v8::Context::Scope context_scope(new_context);

    // Run with breakpoint.
    CompileRun("'b'.repeat(10)");
    CHECK_EQ(1, break_point_hit_count);

    CompileRun("'b'.repeat(10)");
    CHECK_EQ(2, break_point_hit_count);

    // Run without breakpoints.
    ClearBreakPoint(bp);
    CompileRun("'b'.repeat(10)");
    CHECK_EQ(2, break_point_hit_count);
  }

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

void NoOpFunctionCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  info.GetReturnValue().Set(v8_num(2));
}

TEST(BreakPointApiFunction) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  i::DirectHandle<i::BreakPoint> bp;

  v8::Local<v8::FunctionTemplate> function_template =
      v8::FunctionTemplate::New(env->GetIsolate(), NoOpFunctionCallback);

  v8::Local<v8::Function> function =
      function_template->GetFunction(env.local()).ToLocalChecked();

  env->Global()->Set(env.local(), v8_str("f"), function).ToChecked();

  // === Test simple builtin ===
  break_point_hit_count = 0;

  // Run with breakpoint.
  bp = SetBreakPoint(function, 0, "this != 1");
  ExpectInt32("f()", 2);
  CHECK_EQ(1, break_point_hit_count);

  ExpectInt32("f()", 2);
  CHECK_EQ(2, break_point_hit_count);

  // Direct call through API does not trigger breakpoint.
  function->Call(env.local(), v8::Undefined(env->GetIsolate()), 0, nullptr)
      .ToLocalChecked();
  CHECK_EQ(2, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  ExpectInt32("f()", 2);
  CHECK_EQ(2, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(BreakPointApiConstructor) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  i::DirectHandle<i::BreakPoint> bp;

  v8::Local<v8::FunctionTemplate> function_template =
      v8::FunctionTemplate::New(env->GetIsolate(), NoOpFunctionCallback);

  v8::Local<v8::Function> function =
      function_template->GetFunction(env.local()).ToLocalChecked();

  env->Global()->Set(env.local(), v8_str("f"), function).ToChecked();

  // === Test simple builtin ===
  break_point_hit_count = 0;

  // Run with breakpoint.
  bp = SetBreakPoint(function, 0, "this != 1");
  CompileRun("new f()");
  CHECK_EQ(1, break_point_hit_count);
  CompileRun("new f()");
  CHECK_EQ(2, break_point_hit_count);

  // Direct call through API does not trigger breakpoint.
  function->NewInstance(env.local()).ToLocalChecked();
  CHECK_EQ(2, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  CompileRun("new f()");
  CHECK_EQ(2, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

void GetWrapperCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  info.GetReturnValue().Set(
      info[0]
          .As<v8::Object>()
          ->Get(info.GetIsolate()->GetCurrentContext(), info[1])
          .ToLocalChecked());
}

TEST(BreakPointApiGetter) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  i::DirectHandle<i::BreakPoint> bp;

  v8::Local<v8::FunctionTemplate> function_template =
      v8::FunctionTemplate::New(env->GetIsolate(), NoOpFunctionCallback);
  v8::Local<v8::FunctionTemplate> get_template =
      v8::FunctionTemplate::New(env->GetIsolate(), GetWrapperCallback);

  v8::Local<v8::Function> function =
      function_template->GetFunction(env.local()).ToLocalChecked();
  v8::Local<v8::Function> get =
      get_template->GetFunction(env.local()).ToLocalChecked();

  env->Global()->Set(env.local(), v8_str("f"), function).ToChecked();
  env->Global()->Set(env.local(), v8_str("get_wrapper"), get).ToChecked();
  CompileRun(
      "var o = {};"
      "Object.defineProperty(o, 'f', { get: f, enumerable: true });");

  // === Test API builtin as getter ===
  break_point_hit_count = 0;

  // Run with breakpoint.
  bp = SetBreakPoint(function, 0);
  CompileRun("get_wrapper(o, 'f')");
  CHECK_EQ(0, break_point_hit_count);

  CompileRun("o.f");
  CHECK_EQ(1, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  CompileRun("get_wrapper(o, 'f', 2)");
  CompileRun("o.f");
  CHECK_EQ(1, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

void SetWrapperCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  CHECK(info[0]
            .As<v8::Object>()
            ->Set(info.GetIsolate()->GetCurrentContext(), info[1], info[2])
            .FromJust());
}

TEST(BreakPointApiSetter) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  i::DirectHandle<i::BreakPoint> bp;

  v8::Local<v8::FunctionTemplate> function_template =
      v8::FunctionTemplate::New(env->GetIsolate(), NoOpFunctionCallback);
  v8::Local<v8::FunctionTemplate> set_template =
      v8::FunctionTemplate::New(env->GetIsolate(), SetWrapperCallback);

  v8::Local<v8::Function> function =
      function_template->GetFunction(env.local()).ToLocalChecked();
  v8::Local<v8::Function> set =
      set_template->GetFunction(env.local()).ToLocalChecked();

  env->Global()->Set(env.local(), v8_str("f"), function).ToChecked();
  env->Global()->Set(env.local(), v8_str("set_wrapper"), set).ToChecked();

  CompileRun(
      "var o = {};"
      "Object.defineProperty(o, 'f', { set: f, enumerable: true });");

  // === Test API builtin as setter ===
  break_point_hit_count = 0;

  // Run with breakpoint.
  bp = SetBreakPoint(function, 0);

  CompileRun("o.f = 3");
  CHECK_EQ(1, break_point_hit_count);

  CompileRun("set_wrapper(o, 'f', 2)");
  CHECK_EQ(1, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  CompileRun("o.f = 3");
  CHECK_EQ(1, break_point_hit_count);

  // === Test API builtin as setter, with condition ===
  break_point_hit_count = 0;

  // Run with breakpoint.
  bp = SetBreakPoint(function, 0, "arguments[0] == 3");
  CompileRun("set_wrapper(o, 'f', 2)");
  CHECK_EQ(0, break_point_hit_count);

  CompileRun("set_wrapper(o, 'f', 3)");
  CHECK_EQ(0, break_point_hit_count);

  CompileRun("o.f = 3");
  CHECK_EQ(1, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  CompileRun("set_wrapper(o, 'f', 2)");
  CompileRun("o.f = 3");
  CHECK_EQ(1, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(BreakPointApiAccessor) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  i::DirectHandle<i::BreakPoint> bp;

  // Create 'foo' class, with a hidden property.
  v8::Local<v8::ObjectTemplate> obj_template =
      v8::ObjectTemplate::New(env->GetIsolate());
  v8::Local<v8::FunctionTemplate> accessor_template =
      v8::FunctionTemplate::New(env->GetIsolate(), NoOpFunctionCallback);
  obj_template->SetAccessorProperty(v8_str("f"), accessor_template,
                                    accessor_template);
  v8::Local<v8::Object> obj =
      obj_template->NewInstance(env.local()).ToLocalChecked();
  env->Global()->Set(env.local(), v8_str("o"), obj).ToChecked();

  v8::Local<v8::Function> function =
      CompileRun("Object.getOwnPropertyDescriptor(o, 'f').set")
          .As<v8::Function>();

  // === Test API accessor ===
  break_point_hit_count = 0;

  CompileRun("function get_loop() { for (var i = 0; i < 10; i++) o.f }");
  CompileRun("function set_loop() { for (var i = 0; i < 10; i++) o.f = 2 }");

  CompileRun("get_loop(); set_loop();");  // Initialize ICs.

  // Run with breakpoint.
  bp = SetBreakPoint(function, 0);

  CompileRun("o.f = 3");
  CHECK_EQ(1, break_point_hit_count);

  CompileRun("o.f");
  CHECK_EQ(2, break_point_hit_count);

  CompileRun("for (var i = 0; i < 10; i++) o.f");
  CHECK_EQ(12, break_point_hit_count);

  CompileRun("get_loop();");
  CHECK_EQ(22, break_point_hit_count);

  CompileRun("for (var i = 0; i < 10; i++) o.f = 2");
  CHECK_EQ(32, break_point_hit_count);

  CompileRun("set_loop();");
  CHECK_EQ(42, break_point_hit_count);

  // Test that the break point also works when we install the function
  // template on a new property (with a fresh AccessorPair instance).
  v8::Local<v8::ObjectTemplate> baz_template =
      v8::ObjectTemplate::New(env->GetIsolate());
  baz_template->SetAccessorProperty(v8_str("g"), accessor_template,
                                    accessor_template);
  v8::Local<v8::Object> baz =
      baz_template->NewInstance(env.local()).ToLocalChecked();
  env->Global()->Set(env.local(), v8_str("b"), baz).ToChecked();

  CompileRun("b.g = 4");
  CHECK_EQ(43, break_point_hit_count);

  CompileRun("b.g");
  CHECK_EQ(44, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  CompileRun("o.f = 3");
  CompileRun("o.f");
  CHECK_EQ(44, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(Regress1163547) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  i::DirectHandle<i::BreakPoint> bp;

  auto constructor_tmpl = v8::FunctionTemplate::New(env->GetIsolate());
  auto prototype_tmpl = constructor_tmpl->PrototypeTemplate();
  auto accessor_tmpl =
      v8::FunctionTemplate::New(env->GetIsolate(), NoOpFunctionCallback);
  prototype_tmpl->SetAccessorProperty(v8_str("f"), accessor_tmpl);

  auto constructor =
      constructor_tmpl->GetFunction(env.local()).ToLocalChecked();
  env->Global()->Set(env.local(), v8_str("C"), constructor).ToChecked();

  CompileRun("o = new C();");
  v8::Local<v8::Function> function =
      CompileRun("Object.getOwnPropertyDescriptor(C.prototype, 'f').get")
          .As<v8::Function>();

  // === Test API accessor ===
  break_point_hit_count = 0;

  // At this point, the C.prototype - which holds the "f" accessor - is in
  // dictionary mode.
  auto constructor_fun =
      Cast<i::JSFunction>(v8::Utils::OpenHandle(*constructor));
  CHECK(
      !i::Cast<i::JSObject>(constructor_fun->prototype())->HasFastProperties());

  // Run with breakpoint.
  bp = SetBreakPoint(function, 0);

  CompileRun("o.f");
  CHECK_EQ(1, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(BreakPointOnLazyAccessorInNewContexts) {
  // Check that breakpoints on a lazy accessor still get hit after creating new
  // contexts.
  // Regression test for parts of http://crbug.com/1368554.
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(isolate, &delegate);

  auto accessor_tmpl = v8::FunctionTemplate::New(isolate, NoOpFunctionCallback);
  accessor_tmpl->SetClassName(v8_str("get f"));
  auto object_tmpl = v8::ObjectTemplate::New(isolate);
  object_tmpl->SetAccessorProperty(v8_str("f"), accessor_tmpl);

  {
    v8::Local<v8::Context> context1 = v8::Context::New(isolate);
    context1->Global()
        ->Set(context1, v8_str("o"),
              object_tmpl->NewInstance(context1).ToLocalChecked())
        .ToChecked();
    v8::Context::Scope context_scope(context1);

    // 1. Set the breakpoint
    v8::Local<v8::Function> function =
        CompileRun(context1, "Object.getOwnPropertyDescriptor(o, 'f').get")
            .ToLocalChecked()
            .As<v8::Function>();
    SetBreakPoint(function, 0);

    // 2. Run and check that we hit the breakpoint
    break_point_hit_count = 0;
    CompileRun(context1, "o.f");
    CHECK_EQ(1, break_point_hit_count);
  }

  {
    // Create a second context and check that we also hit the breakpoint
    // without setting it again.
    v8::Local<v8::Context> context2 = v8::Context::New(isolate);
    context2->Global()
        ->Set(context2, v8_str("o"),
              object_tmpl->NewInstance(context2).ToLocalChecked())
        .ToChecked();
    v8::Context::Scope context_scope(context2);

    CompileRun(context2, "o.f");
    CHECK_EQ(2, break_point_hit_count);
  }

  {
    // Create a third context, but this time we use a global template instead
    // and let the bootstrapper initialize "o" instead.
    auto global_tmpl = v8::ObjectTemplate::New(isolate);
    global_tmpl->Set(v8_str("o"), object_tmpl);
    v8::Local<v8::Context> context3 =
        v8::Context::New(isolate, nullptr, global_tmpl);
    v8::Context::Scope context_scope(context3);

    CompileRun(context3, "o.f");
    CHECK_EQ(3, break_point_hit_count);
  }

  v8::debug::SetDebugDelegate(isolate, nullptr);
  CheckDebuggerUnloaded();
}

TEST(BreakPointInlineApiFunction) {
  i::v8_flags.allow_natives_syntax = true;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  i::DirectHandle<i::BreakPoint> bp;

  v8::Local<v8::FunctionTemplate> function_template =
      v8::FunctionTemplate::New(env->GetIsolate(), NoOpFunctionCallback);

  v8::Local<v8::Function> function =
      function_template->GetFunction(env.local()).ToLocalChecked();

  env->Global()->Set(env.local(), v8_str("f"), function).ToChecked();
  CompileRun(
      "function g() { return 1 +  f(); };"
      "%PrepareFunctionForOptimization(g);");

  // === Test simple builtin ===
  break_point_hit_count = 0;

  // Run with breakpoint.
  bp = SetBreakPoint(function, 0);
  ExpectInt32("g()", 3);
  CHECK_EQ(1, break_point_hit_count);

  ExpectInt32("g()", 3);
  CHECK_EQ(2, break_point_hit_count);

  CompileRun("%OptimizeFunctionOnNextCall(g)");
  ExpectInt32("g()", 3);
  CHECK_EQ(3, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  ExpectInt32("g()", 3);
  CHECK_EQ(3, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

// Test that a break point can be set at a return store location.
TEST(BreakPointConditionBuiltin) {
  i::v8_flags.allow_natives_syntax = true;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  v8::Local<v8::Function> builtin;
  i::DirectHandle<i::BreakPoint> bp;

  // === Test global variable ===
  break_point_hit_count = 0;
  builtin = CompileRun("String.prototype.repeat").As<v8::Function>();
  CompileRun("var condition = false");
  CompileRun("'a'.repeat(10)");
  CHECK_EQ(0, break_point_hit_count);

  // Run with breakpoint.
  bp = SetBreakPoint(builtin, 0, "condition == true");
  CompileRun("'b'.repeat(10)");
  CHECK_EQ(0, break_point_hit_count);

  CompileRun("condition = true");
  CompileRun("'b'.repeat(10)");
  CHECK_EQ(1, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  CompileRun("'b'.repeat(10)");
  CHECK_EQ(1, break_point_hit_count);

  // === Test arguments ===
  break_point_hit_count = 0;
  builtin = CompileRun("String.prototype.repeat").As<v8::Function>();
  CompileRun("function f(x) { return 'a'.repeat(x * 2); }");
  CHECK_EQ(0, break_point_hit_count);

  // Run with breakpoint.
  bp = SetBreakPoint(builtin, 0, "arguments[0] == 20");
  ExpectString("f(5)", "aaaaaaaaaa");
  CHECK_EQ(0, break_point_hit_count);

  ExpectString("f(10)", "aaaaaaaaaaaaaaaaaaaa");
  CHECK_EQ(1, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  ExpectString("f(10)", "aaaaaaaaaaaaaaaaaaaa");
  CHECK_EQ(1, break_point_hit_count);

  // === Test adapted arguments ===
  break_point_hit_count = 0;
  builtin = CompileRun("String.prototype.repeat").As<v8::Function>();
  CompileRun("function f(x) { return 'a'.repeat(x * 2, x); }");
  CHECK_EQ(0, break_point_hit_count);

  // Run with breakpoint.
  bp = SetBreakPoint(builtin, 0,
                     "arguments[1] == 10 && arguments[2] == undefined");
  ExpectString("f(5)", "aaaaaaaaaa");
  CHECK_EQ(0, break_point_hit_count);

  ExpectString("f(10)", "aaaaaaaaaaaaaaaaaaaa");
  CHECK_EQ(1, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  ExpectString("f(10)", "aaaaaaaaaaaaaaaaaaaa");
  CHECK_EQ(1, break_point_hit_count);

  // === Test var-arg builtins ===
  break_point_hit_count = 0;
  builtin = CompileRun("String.fromCharCode").As<v8::Function>();
  CompileRun("function f() { return String.fromCharCode(1, 2, 3); }");
  CHECK_EQ(0, break_point_hit_count);

  // Run with breakpoint.
  bp = SetBreakPoint(builtin, 0, "arguments.length == 3 && arguments[1] == 2");
  CompileRun("f(1, 2, 3)");
  CHECK_EQ(1, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  CompileRun("f(1, 2, 3)");
  CHECK_EQ(1, break_point_hit_count);

  // === Test rest arguments ===
  break_point_hit_count = 0;
  builtin = CompileRun("String.fromCharCode").As<v8::Function>();
  CompileRun("function f(...info) { return String.fromCharCode(...info); }");
  CHECK_EQ(0, break_point_hit_count);

  // Run with breakpoint.
  bp = SetBreakPoint(builtin, 0, "arguments.length == 3 && arguments[1] == 2");
  CompileRun("f(1, 2, 3)");
  CHECK_EQ(1, break_point_hit_count);

  ClearBreakPoint(bp);
  CompileRun("f(1, 3, 3)");
  CHECK_EQ(1, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  CompileRun("f(1, 2, 3)");
  CHECK_EQ(1, break_point_hit_count);

  // === Test receiver ===
  break_point_hit_count = 0;
  builtin = CompileRun("String.prototype.repeat").As<v8::Function>();
  CompileRun("function f(x) { return x.repeat(10); }");
  CHECK_EQ(0, break_point_hit_count);

  // Run with breakpoint.
  bp = SetBreakPoint(builtin, 0, "this == 'a'");
  ExpectString("f('b')", "bbbbbbbbbb");
  CHECK_EQ(0, break_point_hit_count);

  ExpectString("f('a')", "aaaaaaaaaa");
  CHECK_EQ(1, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  ExpectString("f('a')", "aaaaaaaaaa");
  CHECK_EQ(1, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(BreakPointInlining) {
  i::v8_flags.allow_natives_syntax = true;
  break_point_hit_count = 0;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  break_point_hit_count = 0;
  v8::Local<v8::Function> inlinee =
      CompileRun("function f(x) { return x*2; } f").As<v8::Function>();
  CompileRun("function test(x) { return 1 + f(x) }");
  CompileRun(
      "%PrepareFunctionForOptimization(test);"
      "test(0.5); test(0.6);"
      "%OptimizeFunctionOnNextCall(test); test(0.7);");
  CHECK_EQ(0, break_point_hit_count);

  // Run with breakpoint.
  i::DirectHandle<i::BreakPoint> bp = SetBreakPoint(inlinee, 0);
  CompileRun("f(0.1);");
  CHECK_EQ(1, break_point_hit_count);
  CompileRun("test(0.2);");
  CHECK_EQ(2, break_point_hit_count);

  // Re-optimize.
  CompileRun(
      "%PrepareFunctionForOptimization(test);"
      "%OptimizeFunctionOnNextCall(test);");
  CompileRun("test(0.3);");
  CHECK_EQ(3, break_point_hit_count);

  // Run without breakpoints.
  ClearBreakPoint(bp);
  CompileRun("test(0.3);");
  CHECK_EQ(3, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

static void CallWithBreakPoints(v8::Local<v8::Context> context,
                                v8::Local<v8::Object> recv,
                                v8::Local<v8::Function> f,
                                int break_point_count, int call_count) {
  break_point_hit_count = 0;
  for (int i = 0; i < call_count; i++) {
    f->Call(context, recv, 0, nullptr).ToLocalChecked();
    CHECK_EQ((i + 1) * break_point_count, break_point_hit_count);
  }
}


// Test GC during break point processing.
TEST(GCDuringBreakPointProcessing) {
  break_point_hit_count = 0;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Local<v8::Context> context = env.local();

  DebugEventBreakPointCollectGarbage delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  v8::Local<v8::Function> foo;

  // Test IC store break point with garbage collection.
  foo = CompileFunction(&env, "function foo(){bar=0;}", "foo");
  SetBreakPoint(foo, 0);
  CallWithBreakPoints(context, env->Global(), foo, 1, 10);

  // Test IC load break point with garbage collection.
  foo = CompileFunction(&env, "bar=1;function foo(){var x=bar;}", "foo");
  SetBreakPoint(foo, 0);
  CallWithBreakPoints(context, env->Global(), foo, 1, 10);

  // Test IC call break point with garbage collection.
  foo = CompileFunction(&env, "function bar(){};function foo(){bar();}", "foo");
  SetBreakPoint(foo, 0);
  CallWithBreakPoints(context, env->Global(), foo, 1, 10);

  // Test return break point with garbage collection.
  foo = CompileFunction(&env, "function foo(){}", "foo");
  SetBreakPoint(foo, 0);
  CallWithBreakPoints(context, env->Global(), foo, 1, 25);

  // Test debug break slot break point with garbage collection.
  foo = CompileFunction(&env, "function foo(){var a;}", "foo");
  SetBreakPoint(foo, 0);
  CallWithBreakPoints(context, env->Global(), foo, 1, 25);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


// Call the function three times with different garbage collections in between
// and make sure that the break point survives.
static void CallAndGC(v8::Local<v8::Context> context,
                      v8::Local<v8::Object> recv, v8::Local<v8::Function> f) {
  break_point_hit_count = 0;

  for (int i = 0; i < 3; i++) {
    // Call function.
    f->Call(context, recv, 0, nullptr).ToLocalChecked();
    CHECK_EQ(1 + i * 3, break_point_hit_count);

    // Scavenge and call function.
    i::heap::InvokeMinorGC(CcTest::heap());
    f->Call(context, recv, 0, nullptr).ToLocalChecked();
    CHECK_EQ(2 + i * 3, break_point_hit_count);

    // Mark sweep (and perhaps compact) and call function.
    i::heap::InvokeMajorGC(CcTest::heap());
    f->Call(context, recv, 0, nullptr).ToLocalChecked();
    CHECK_EQ(3 + i * 3, break_point_hit_count);
  }
}


// Test that a break point can be set at a return store location.
TEST(BreakPointSurviveGC) {
  break_point_hit_count = 0;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Local<v8::Context> context = env.local();

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  v8::Local<v8::Function> foo;

  // Test IC store break point with garbage collection.
  {
    CompileFunction(&env, "function foo(){}", "foo");
    foo = CompileFunction(&env, "function foo(){bar=0;}", "foo");
    SetBreakPoint(foo, 0);
  }
  CallAndGC(context, env->Global(), foo);

  // Test IC load break point with garbage collection.
  {
    CompileFunction(&env, "function foo(){}", "foo");
    foo = CompileFunction(&env, "bar=1;function foo(){var x=bar;}", "foo");
    SetBreakPoint(foo, 0);
  }
  CallAndGC(context, env->Global(), foo);

  // Test IC call break point with garbage collection.
  {
    CompileFunction(&env, "function foo(){}", "foo");
    foo = CompileFunction(&env,
                          "function bar(){};function foo(){bar();}",
                          "foo");
    SetBreakPoint(foo, 0);
  }
  CallAndGC(context, env->Global(), foo);

  // Test return break point with garbage collection.
  {
    CompileFunction(&env, "function foo(){}", "foo");
    foo = CompileFunction(&env, "function foo(){}", "foo");
    SetBreakPoint(foo, 0);
  }
  CallAndGC(context, env->Global(), foo);

  // Test non IC break point with garbage collection.
  {
    CompileFunction(&env, "function foo(){}", "foo");
    foo = CompileFunction(&env, "function foo(){var bar=0;}", "foo");
    SetBreakPoint(foo, 0);
  }
  CallAndGC(context, env->Global(), foo);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

// Test that the debugger statement causes a break.
TEST(DebuggerStatement) {
  break_point_hit_count = 0;
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
  v8::Local<v8::Context> context = env.local();
  v8::Script::Compile(context,
                      v8_str(env->GetIsolate(), "function bar(){debugger}"))
      .ToLocalChecked()
      ->Run(context)
      .ToLocalChecked();
  v8::Script::Compile(
      context, v8_str(env->GetIsolate(), "function foo(){debugger;debugger;}"))
      .ToLocalChecked()
      ->Run(context)
      .ToLocalChecked();
  v8::Local<v8::Function> foo = v8::Local<v8::Function>::Cast(
      env->Global()
          ->Get(context, v8_str(env->GetIsolate(), "foo"))
          .ToLocalChecked());
  v8::Local<v8::Function> bar = v8::Local<v8::Function>::Cast(
      env->Global()
          ->Get(context, v8_str(env->GetIsolate(), "bar"))
          .ToLocalChecked());

  // Run function with debugger statement
  bar->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(1, break_point_hit_count);

  // Run function with two debugger statement
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(3, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


// Test setting a breakpoint on the debugger statement.
TEST(DebuggerStatementBreakpoint) {
    break_point_hit_count = 0;
    LocalContext env;
    v8::HandleScope scope(env->GetIsolate());
    v8::Local<v8::Context> context = env.local();
    DebugEventCounter delegate;
    v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);
    v8::Script::Compile(context,
                        v8_str(env->GetIsolate(), "function foo(){debugger;}"))
        .ToLocalChecked()
        ->Run(context)
        .ToLocalChecked();
    v8::Local<v8::Function> foo = v8::Local<v8::Function>::Cast(
        env->Global()
            ->Get(context, v8_str(env->GetIsolate(), "foo"))
            .ToLocalChecked());

    // The debugger statement triggers breakpoint hit
    foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
    CHECK_EQ(1, break_point_hit_count);

    i::DirectHandle<i::BreakPoint> bp = SetBreakPoint(foo, 0);

    // Set breakpoint does not duplicate hits
    foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
    CHECK_EQ(2, break_point_hit_count);

    ClearBreakPoint(bp);
    v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
    CheckDebuggerUnloaded();
}


// Test that the conditional breakpoints work event if code generation from
// strings is prohibited in the debugee context.
TEST(ConditionalBreakpointWithCodeGenerationDisallowed) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  v8::Local<v8::Context> context = env.local();
  v8::Local<v8::Function> foo = CompileFunction(&env,
    "function foo(x) {\n"
    "  var s = 'String value2';\n"
    "  return s + x;\n"
    "}",
    "foo");

  // Set conditional breakpoint with condition 'true'.
  SetBreakPoint(foo, 4, "true");

  break_point_hit_count = 0;
  env->AllowCodeGenerationFromStrings(false);
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();
  CHECK_EQ(1, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}


// Simple test of the stepping mechanism using only store ICs.
TEST(DebugStepLinear) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Create a function for testing stepping.
  v8::Local<v8::Function> foo = CompileFunction(&env,
                                                "function foo(){a=1;b=1;c=1;}",
                                                "foo");

  // Run foo to allow it to get optimized.
  CompileRun("a=0; b=0; c=0; foo();");

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  SetBreakPoint(foo, 3);

  run_step.set_step_action(StepInto);
  break_point_hit_count = 0;
  v8::Local<v8::Context> context = env.local();
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // With stepping all break locations are hit.
  CHECK_EQ(4, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

TEST(DebugCountLinear) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Create a function for testing stepping.
  v8::Local<v8::Function> foo =
      CompileFunction(&env, "function foo(){a=1;b=1;c=1;}", "foo");

  // Run foo to allow it to get optimized.
  CompileRun("a=0; b=0; c=0; foo();");

  // Register a debug event listener which just counts.
  DebugEventCounter delegate;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &delegate);

  SetBreakPoint(foo, 3);
  break_point_hit_count = 0;
  v8::Local<v8::Context> context = env.local();
  foo->Call(context, env->Global(), 0, nullptr).ToLocalChecked();

  // Without stepping only active break points are hit.
  CHECK_EQ(1, break_point_hit_count);

  v8::debug::SetDebugDelegate(env->GetIsolate(), nullptr);
  CheckDebuggerUnloaded();
}

// Test of the stepping mechanism for keyed load in a loop.
TEST(DebugStepKeyedLoadLoop) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  // Register a debug event listener which steps and counts.
  DebugEventCounter run_step;
  v8::debug::SetDebugDelegate(env->GetIsolate(), &run_step);

  // Create 
"""


```