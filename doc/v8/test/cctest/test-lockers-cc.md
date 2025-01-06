Response:
Let's break down the thought process for analyzing the given C++ code.

1. **Initial Understanding of the File Path:** The path `v8/test/cctest/test-lockers.cc` immediately suggests this is a test file within the V8 project. The `test` directory confirms this. `cctest` likely stands for C++ tests (as opposed to JS tests). `test-lockers.cc` hints that the tests focus on the locking mechanisms within V8.

2. **Scanning for Key V8 APIs:**  A quick scan of the `#include` directives and the code itself reveals several crucial V8 APIs related to concurrency and isolates:
    * `include/v8-locker.h`:  This is the most direct indicator, pointing to the `v8::Locker` and `v8::Unlocker` classes.
    * `include/v8-isolate.h`:  Isolates are V8's fundamental unit of execution, and the code clearly manipulates them (creation, disposal, entering, exiting).
    * `include/v8-context.h`: Contexts are within isolates, and the code creates and scopes them.
    * `src/base/platform/platform.h`: This likely involves threading primitives.
    * `src/objects/objects-inl.h`, `src/strings/unicode-inl.h`:  These suggest interaction with V8's internal object representation and string handling, though less central to the locking aspect.
    * `include/v8-extension.h`, `include/v8-function.h`: These point to the ability to create extensions and bind C++ functions to JavaScript, used in some test cases.

3. **Identifying Core Functionality:** The presence of `TEST()` macros (from `test/cctest/cctest.h`) confirms that this file contains unit tests. The names of the test functions provide clues about the functionalities being tested:
    * `LazyDeoptimizationMultithread`, `EagerDeoptimizationMultithread`:  These clearly relate to how deoptimization interacts with multiple threads and locking.
    * `KangarooIsolates`:  This suggests testing the ability to "migrate" an isolate between threads.
    * `IsolateLockingStress`, `IsolateNestedLocking`:  These are stress tests for locking an isolate from multiple threads and with nested locks.
    * `SeparateIsolatesLocksNonexclusive`: Tests locking of different isolates concurrently.
    * `LockerUnlocker`, `LockTwiceAndUnlock`, `LockAndUnlockDifferentIsolates`, `LockUnlockLockMultithreaded`, `LockUnlockLockDefaultIsolateMultithreaded`: These test various combinations and nesting of `Locker` and `Unlocker`.
    * `ExtensionsRegistration`: Tests concurrent registration of V8 extensions.

4. **Analyzing Helper Classes and Functions:** The code defines several helper classes:
    * `DeoptimizeCodeThread`: A thread specifically designed to trigger deoptimization.
    * `KangarooThread`: A thread to demonstrate isolate migration.
    * `JoinableThread`: A base class for creating joinable threads, simplifying thread management in the tests.
    * Various specific thread classes inheriting from `JoinableThread` (e.g., `IsolateLockingThreadWithLocalContext`). These encapsulate specific locking and execution scenarios.

    The functions `UnlockForDeoptimization` and `UnlockForDeoptimizationIfReady` are crucial for orchestrating deoptimization from another thread within the tests. `CalcFibAndCheck` is a utility to run and check a simple JavaScript function.

5. **Understanding the Test Logic:** The general pattern in the tests involves:
    * Creating one or more `v8::Isolate` instances.
    * Creating `v8::Context` objects within the isolates.
    * Spawning multiple threads that perform operations requiring locking (e.g., running JavaScript code).
    * Using `v8::Locker` and `v8::Unlocker` to manage access to the isolates from different threads.
    * Assertions (`CHECK`, `CHECK_EQ`) to verify the expected behavior.

6. **Considering Javascript Interaction:**  The tests execute JavaScript code using `CompileRun`. The functions `UnlockForDeoptimization` and `UnlockForDeoptimizationIfReady` are called from JavaScript, demonstrating a bridge between C++ locking mechanisms and JavaScript execution. The deoptimization tests explicitly trigger deoptimization via JavaScript.

7. **Thinking About Potential Errors:** The tests themselves are designed to catch errors related to improper locking. Common errors would include:
    * **Deadlocks:**  If locks are acquired in an inconsistent order, leading to threads waiting for each other indefinitely. Nested locking tests address this.
    * **Race conditions:**  If shared resources (like V8 isolates) are accessed without proper locking, leading to unpredictable behavior. The stress tests aim to expose these.
    * **Using V8 APIs without a Locker:**  Many V8 operations require holding a `Locker` for the associated `Isolate`. The tests implicitly check this by verifying successful execution.
    * **Incorrect use of Unlocker:**  Using `Unlocker` without a corresponding `Locker`, or incorrect nesting, could lead to crashes or unexpected behavior.

8. **Checking for `.tq` Extension:** The file name ends in `.cc`, *not* `.tq`. Therefore, it is a C++ source file, not a Torque file.

9. **Structuring the Answer:**  Based on the analysis, the answer should cover:
    * The file's purpose (testing V8's locking mechanisms).
    * Key functionalities illustrated by the tests.
    * The relationship to JavaScript (calling C++ from JS to control locking, triggering deoptimization).
    * Examples of potential programming errors the tests aim to prevent.
    * Confirmation that it's a C++ file, not a Torque file.

This systematic approach, starting with high-level understanding and drilling down into specific details, helps to thoroughly analyze and explain the functionality of the given V8 source code.
This C++ source file, `v8/test/cctest/test-lockers.cc`, is part of the V8 JavaScript engine's test suite. Its primary function is to **test the correctness and robustness of V8's locking mechanisms**, specifically the `v8::Locker` and `v8::Unlocker` classes. These classes are crucial for managing concurrent access to V8 isolates and their associated resources from multiple threads.

Here's a breakdown of its functionalities:

**1. Testing Basic Locking and Unlocking:**

* The tests demonstrate how to acquire and release locks on V8 isolates using `v8::Locker` and `v8::Unlocker`.
* They verify that when a lock is held by one thread, other threads attempting to acquire the same lock will be blocked until the lock is released.

**2. Testing Nested Locking:**

* The `IsolateNestedLocking` test checks if a thread can acquire the same lock multiple times without deadlocking. This is important because V8's locking is re-entrant.

**3. Testing Locking Across Multiple Isolates:**

* The `SeparateIsolatesLocksNonexclusive` and `LockAndUnlockDifferentIsolates` tests verify that locking one isolate does not prevent other threads from locking and operating on different isolates. This highlights the independence of isolates.

**4. Testing the Interaction of Locking with Deoptimization:**

* Several tests (`LazyDeoptimizationMultithread`, `LazyDeoptimizationMultithreadWithNatives`, `EagerDeoptimizationMultithread`) are designed to test how locking interacts with V8's deoptimization process.
* These tests involve one thread holding a lock while another thread triggers the deoptimization of a function being executed in the first thread. This ensures that deoptimization can happen correctly even under concurrent scenarios.

**5. Testing Isolate Migration (Less Directly):**

* The `KangarooIsolates` test demonstrates the possibility of "migrating" an isolate between threads. While it doesn't directly test `Locker` in the most intricate way, it showcases how an isolate can be used and then disposed of by a different thread, which relies on correct locking internally.

**6. Stress Testing Locking:**

* The `IsolateLockingStress` test creates a large number of threads that all attempt to acquire a lock on the same isolate concurrently. This helps to stress-test the locking implementation and ensure its stability under high contention.

**7. Testing `Unlocker` within a `Locker`:**

* Tests like `LockerUnlocker`, `LockTwiceAndUnlock`, and `LockUnlockLockMultithreaded` specifically examine the usage of `v8::Unlocker` to temporarily release a lock held by a `v8::Locker`. This is useful for allowing other threads to perform certain operations while the current thread still conceptually "owns" the isolate.

**8. Testing Extension Registration Concurrency:**

* The `ExtensionsRegistration` test verifies that V8 can handle concurrent registration of extensions in different isolates without issues.

**Is `v8/test/cctest/test-lockers.cc` a Torque Source File?**

No, the filename ends with `.cc`, which is the standard extension for C++ source files. If it were a V8 Torque source file, it would end with `.tq`.

**Relationship to JavaScript and Examples:**

While this is a C++ test file, the functionality it tests directly impacts how you can safely use the V8 engine from multiple threads in applications that embed V8.

**JavaScript Example Illustrating the Need for Locking:**

Imagine you have a JavaScript object shared between multiple threads interacting with V8:

```javascript
// This is illustrative and won't directly run in the C++ test context
let sharedCounter = 0;

function incrementCounter() {
  // Without proper locking, multiple threads could increment the counter
  // at the same time, leading to race conditions and incorrect results.
  sharedCounter++;
}
```

In a multithreaded environment embedding V8, if you call `incrementCounter()` from multiple threads without any synchronization mechanism, the final value of `sharedCounter` might be incorrect due to race conditions.

V8's `v8::Locker` in the embedding C++ code provides the necessary synchronization to protect access to V8's internal state (and indirectly, the state of JavaScript objects):

```c++
// C++ code embedding V8
#include <v8.h>
#include <thread>

void IncrementCounter(v8::Isolate* isolate) {
  v8::Locker locker(isolate); // Acquire the lock
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::Context> context = v8::Context::New(isolate);
  v8::Context::Scope context_scope(context);

  // Run the JavaScript incrementCounter function
  v8::Local<v8::String> source = v8::String::NewFromUtf8Literal(isolate, "incrementCounter()");
  v8::Local<v8::Script> script = v8::Script::Compile(context, source).ToLocalChecked();
  script->Run(context);
}

int main() {
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = v8::ArrayBuffer::Allocator::NewDefaultAllocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);

  // Create a global function in the context
  {
    v8::Locker locker(isolate);
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    v8::Context::Scope context_scope(context);
    v8::Local<v8::Object> global = context->Global();
    global->Set(context, v8::String::NewFromUtf8Literal(isolate, "incrementCounter"),
                v8::FunctionTemplate::New(isolate, [](const v8::FunctionCallbackInfo<v8::Value>& info){
                  //  Implementation of incrementCounter (as shown in JS)
                  v8::Isolate* isolate = info.GetIsolate();
                  v8::Local<v8::Context> context = isolate->GetCurrentContext();
                  v8::Local<v8::Value> globalVar;
                  if (context->Global()->Get(context, v8::String::NewFromUtf8Literal(isolate, "sharedCounter")).ToLocal(&globalVar) && globalVar->IsNumber()) {
                    int currentValue = globalVar->NumberValue(context).FromJust();
                    context->Global()->Set(context, v8::String::NewFromUtf8Literal(isolate, "sharedCounter"), v8::Number::New(isolate, currentValue + 1));
                  } else {
                    context->Global()->Set(context, v8::String::NewFromUtf8Literal(isolate, "sharedCounter"), v8::Number::New(isolate, 1));
                  }
                })->GetFunction(context).ToLocalChecked()).Check();
  }

  std::thread thread1(IncrementCounter, isolate);
  std::thread thread2(IncrementCounter, isolate);

  thread1.join();
  thread2.join();

  // ... (access and check the value of sharedCounter - requires locking) ...

  isolate->Dispose();
  delete create_params.array_buffer_allocator;
  return 0;
}
```

In this C++ example, the `v8::Locker` ensures that only one thread can execute JavaScript code within the isolate at a time, preventing the race condition in `incrementCounter()`.

**Code Logic Reasoning (with Hypothetical Input/Output):**

Let's take the `LazyDeoptimizationMultithread` test as an example:

**Hypothetical Input:**

1. Two threads are involved: the main test thread and `DeoptimizeCodeThread`.
2. The main thread optimizes a JavaScript function `f`.
3. The `DeoptimizeCodeThread` is given the JavaScript code `"obj = { y: 0, x: 1 };"` to run.
4. The JavaScript function `g` in the main thread, when `b` is true, calls the C++ function `unlock_for_deoptimization`.

**Logic Flow:**

1. The main thread runs JavaScript, optimizing function `f`.
2. The main thread sets `b = true` and calls `f()`.
3. Inside `f()`, `g()` is called.
4. Since `b` is true, `g()` calls the C++ function `unlock_for_deoptimization`.
5. `unlock_for_deoptimization` exits the isolate and unlocks it using `v8::Unlocker`.
6. It then starts the `DeoptimizeCodeThread`, which runs `"obj = { y: 0, x: 1 };"`. This code triggers deoptimization of `f`.
7. The main thread waits for the `DeoptimizeCodeThread` to finish (using `Join()`).
8. After the `DeoptimizeCodeThread` finishes (and deoptimization is likely complete), the main thread re-enters the isolate.
9. The execution of `g()` continues, returning to `f()`.
10. The test then checks if the result of `f()` is correct (`1`). This verifies that even though `f` was deoptimized in another thread, the execution continues correctly in the main thread after re-acquiring the lock.

**Hypothetical Output (Assertions):**

* `CHECK(v->IsNumber())` will be true.
* `CHECK_EQ(1, static_cast<int>(v->NumberValue(context).FromJust()))` will be true.

**Common Programming Errors the Tests Help Prevent:**

* **Deadlocks:**  If locks are not released correctly or if multiple locks are acquired in a conflicting order, it can lead to deadlocks where threads are blocked indefinitely. The nested locking tests specifically target this.
* **Race Conditions:** Accessing shared V8 resources (like objects or the isolate itself) from multiple threads without proper locking can lead to unpredictable behavior and data corruption. The stress tests and tests involving deoptimization aim to expose such race conditions.
* **Using V8 APIs Without a Locker:** Many V8 API calls require that the calling thread holds a `v8::Locker` for the associated isolate. Failing to do so can lead to crashes or undefined behavior. The tests implicitly verify this by ensuring that API calls within locked sections succeed.
* **Incorrect Use of `Unlocker`:**  Using `v8::Unlocker` without a corresponding `v8::Locker` or in an incorrect scope can lead to serious errors. The tests that combine `Locker` and `Unlocker` in various ways ensure the correct usage of these classes.
* **Forgetting to Re-enter the Isolate:** When using `Unlocker`, it's crucial to re-enter the isolate using `isolate->Enter()` before continuing to use V8 APIs. The tests ensure this pattern is followed.

In summary, `v8/test/cctest/test-lockers.cc` plays a vital role in ensuring the thread-safety and reliability of the V8 JavaScript engine by thoroughly testing its locking mechanisms under various concurrent scenarios, including interactions with deoptimization and isolate management.

Prompt: 
```
这是目录为v8/test/cctest/test-lockers.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-lockers.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2007-2011 the V8 project authors. All rights reserved.
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

#include <limits.h>

#include <memory>

#include "include/v8-extension.h"
#include "include/v8-function.h"
#include "include/v8-locker.h"
#include "src/base/platform/platform.h"
#include "src/objects/objects-inl.h"
#include "src/strings/unicode-inl.h"
#include "test/cctest/cctest.h"

namespace {

class DeoptimizeCodeThread : public v8::base::Thread {
 public:
  DeoptimizeCodeThread(v8::Isolate* isolate, v8::Local<v8::Context> context,
                       const char* trigger)
      : Thread(Options("DeoptimizeCodeThread")),
        isolate_(isolate),
        context_(isolate, context),
        source_(trigger) {}

  void Run() override {
    v8::Locker locker(isolate_);
    isolate_->Enter();
    {
      v8::HandleScope handle_scope(isolate_);
      v8::Local<v8::Context> context =
          v8::Local<v8::Context>::New(isolate_, context_);
      v8::Context::Scope context_scope(context);
      // This code triggers deoptimization of some function that will be
      // used in a different thread.
      CompileRun(source_);
    }
    isolate_->Exit();
  }

 private:
  v8::Isolate* isolate_;
  v8::Persistent<v8::Context> context_;
  // The code that triggers the deoptimization.
  const char* source_;
};

void UnlockForDeoptimization(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  v8::Isolate* isolate = info.GetIsolate();
  // Gets the pointer to the thread that will trigger the deoptimization of the
  // code.
  DeoptimizeCodeThread* deoptimizer =
      reinterpret_cast<DeoptimizeCodeThread*>(isolate->GetData(0));
  {
    // Exits and unlocks the isolate.
    isolate->Exit();
    v8::Unlocker unlocker(isolate);
    // Starts the deoptimizing thread.
    CHECK(deoptimizer->Start());
    // Waits for deoptimization to finish.
    deoptimizer->Join();
  }
  // The deoptimizing thread has finished its work, and the isolate
  // will now be used by the current thread.
  isolate->Enter();
}

void UnlockForDeoptimizationIfReady(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  v8::Isolate* isolate = info.GetIsolate();
  bool* ready_to_deoptimize = reinterpret_cast<bool*>(isolate->GetData(1));
  if (*ready_to_deoptimize) {
    // The test should enter here only once, so put the flag back to false.
    *ready_to_deoptimize = false;
    // Gets the pointer to the thread that will trigger the deoptimization of
    // the code.
    DeoptimizeCodeThread* deoptimizer =
        reinterpret_cast<DeoptimizeCodeThread*>(isolate->GetData(0));
    {
      // Exits and unlocks the thread.
      isolate->Exit();
      v8::Unlocker unlocker(isolate);
      // Starts the thread that deoptimizes the function.
      CHECK(deoptimizer->Start());
      // Waits for the deoptimizing thread to finish.
      deoptimizer->Join();
    }
    // The deoptimizing thread has finished its work, and the isolate
    // will now be used by the current thread.
    isolate->Enter();
  }
}
}  // namespace

namespace v8 {
namespace internal {
namespace test_lockers {

TEST(LazyDeoptimizationMultithread) {
  i::v8_flags.allow_natives_syntax = true;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  {
    v8::Locker locker(isolate);
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    const char* trigger_deopt = "obj = { y: 0, x: 1 };";

    // We use the isolate to pass arguments to the UnlockForDeoptimization
    // function. Namely, we pass a pointer to the deoptimizing thread.
    DeoptimizeCodeThread deoptimize_thread(isolate, context, trigger_deopt);
    isolate->SetData(0, &deoptimize_thread);
    v8::Context::Scope context_scope(context);

    // Create the function templace for C++ code that is invoked from
    // JavaScript code.
    Local<v8::FunctionTemplate> fun_templ =
        v8::FunctionTemplate::New(isolate, UnlockForDeoptimization);
    Local<Function> fun = fun_templ->GetFunction(context).ToLocalChecked();
    CHECK(context->Global()
              ->Set(context, v8_str("unlock_for_deoptimization"), fun)
              .FromJust());

    // Optimizes a function f, which will be deoptimized in another
    // thread.
    CompileRun(
        "var b = false; var obj = { x: 1 };"
        "function f() { g(); return obj.x; }"
        "function g() { if (b) { unlock_for_deoptimization(); } }"
        "%NeverOptimizeFunction(g);"
        "%PrepareFunctionForOptimization(f);"
        "f(); f(); %OptimizeFunctionOnNextCall(f);"
        "f();");

    // Trigger the unlocking.
    Local<Value> v = CompileRun("b = true; f();");

    // Once the isolate has been unlocked, the thread will wait for the
    // other thread to finish its task. Once this happens, this thread
    // continues with its execution, that is, with the execution of the
    // function g, which then returns to f. The function f should have
    // also been deoptimized. If the replacement did not happen on this
    // thread's stack, then the test will fail here.
    CHECK(v->IsNumber());
    CHECK_EQ(1, static_cast<int>(v->NumberValue(context).FromJust()));
  }
  isolate->Dispose();
}

TEST(LazyDeoptimizationMultithreadWithNatives) {
  i::v8_flags.allow_natives_syntax = true;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  {
    v8::Locker locker(isolate);
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    const char* trigger_deopt = "%DeoptimizeFunction(f);";

    // We use the isolate to pass arguments to the UnlockForDeoptimization
    // function. Namely, we pass a pointer to the deoptimizing thread.
    DeoptimizeCodeThread deoptimize_thread(isolate, context, trigger_deopt);
    isolate->SetData(0, &deoptimize_thread);
    bool ready_to_deopt = false;
    isolate->SetData(1, &ready_to_deopt);
    v8::Context::Scope context_scope(context);

    // Create the function templace for C++ code that is invoked from
    // JavaScript code.
    Local<v8::FunctionTemplate> fun_templ =
        v8::FunctionTemplate::New(isolate, UnlockForDeoptimizationIfReady);
    Local<Function> fun = fun_templ->GetFunction(context).ToLocalChecked();
    CHECK(context->Global()
              ->Set(context, v8_str("unlock_for_deoptimization"), fun)
              .FromJust());

    // Optimizes a function f, which will be deoptimized in another
    // thread.
    CompileRun(
        "var obj = { x: 1 };"
        "function f() { g(); return obj.x;}"
        "function g() { "
        "  unlock_for_deoptimization(); }"
        "%NeverOptimizeFunction(g);"
        "%PrepareFunctionForOptimization(f);"
        "f(); f(); %OptimizeFunctionOnNextCall(f);");

    // Trigger the unlocking.
    ready_to_deopt = true;
    isolate->SetData(1, &ready_to_deopt);
    Local<Value> v = CompileRun("f();");

    // Once the isolate has been unlocked, the thread will wait for the
    // other thread to finish its task. Once this happens, this thread
    // continues with its execution, that is, with the execution of the
    // function g, which then returns to f. The function f should have
    // also been deoptimized. Otherwise, the test will fail here.
    CHECK(v->IsNumber());
    CHECK_EQ(1, static_cast<int>(v->NumberValue(context).FromJust()));
  }
  isolate->Dispose();
}

TEST(EagerDeoptimizationMultithread) {
  i::v8_flags.allow_natives_syntax = true;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  {
    v8::Locker locker(isolate);
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    const char* trigger_deopt = "f({y: 0, x: 1});";

    // We use the isolate to pass arguments to the UnlockForDeoptimization
    // function. Namely, we pass a pointer to the deoptimizing thread.
    DeoptimizeCodeThread deoptimize_thread(isolate, context, trigger_deopt);
    isolate->SetData(0, &deoptimize_thread);
    bool ready_to_deopt = false;
    isolate->SetData(1, &ready_to_deopt);
    v8::Context::Scope context_scope(context);

    // Create the function templace for C++ code that is invoked from
    // JavaScript code.
    Local<v8::FunctionTemplate> fun_templ =
        v8::FunctionTemplate::New(isolate, UnlockForDeoptimizationIfReady);
    Local<Function> fun = fun_templ->GetFunction(context).ToLocalChecked();
    CHECK(context->Global()
              ->Set(context, v8_str("unlock_for_deoptimization"), fun)
              .FromJust());

    // Optimizes a function f, which will be deoptimized by another thread.
    CompileRun(
        "function f(obj) { unlock_for_deoptimization(); return obj.x; }"
        "%PrepareFunctionForOptimization(f);"
        "f({x: 1}); f({x: 1});"
        "%OptimizeFunctionOnNextCall(f);"
        "f({x: 1});");

    // Trigger the unlocking.
    ready_to_deopt = true;
    isolate->SetData(1, &ready_to_deopt);
    Local<Value> v = CompileRun("f({x: 1});");

    // Once the isolate has been unlocked, the thread will wait for the
    // other thread to finish its task. Once this happens, this thread
    // continues with its execution, that is, with the execution of the
    // function g, which then returns to f. The function f should have
    // also been deoptimized. Otherwise, the test will fail here.
    CHECK(v->IsNumber());
    CHECK_EQ(1, static_cast<int>(v->NumberValue(context).FromJust()));
  }
  isolate->Dispose();
}

// Migrating an isolate
class KangarooThread : public v8::base::Thread {
 public:
  KangarooThread(v8::Isolate* isolate, v8::Local<v8::Context> context)
      : Thread(Options("KangarooThread")),
        isolate_(isolate),
        context_(isolate, context) {}

  void Run() override {
    {
      v8::Locker locker(isolate_);
      v8::Isolate::Scope isolate_scope(isolate_);
      v8::HandleScope scope(isolate_);
      v8::Local<v8::Context> context =
          v8::Local<v8::Context>::New(isolate_, context_);
      v8::Context::Scope context_scope(context);
      Local<Value> v = CompileRun("getValue()");
      CHECK(v->IsNumber());
      CHECK_EQ(30, static_cast<int>(v->NumberValue(context).FromJust()));
    }
    {
      v8::Locker locker(isolate_);
      v8::Isolate::Scope isolate_scope(isolate_);
      v8::HandleScope scope(isolate_);
      v8::Local<v8::Context> context =
          v8::Local<v8::Context>::New(isolate_, context_);
      v8::Context::Scope context_scope(context);
      Local<Value> v = CompileRun("getValue()");
      CHECK(v->IsNumber());
      CHECK_EQ(30, static_cast<int>(v->NumberValue(context).FromJust()));
    }
    isolate_->Dispose();
  }

 private:
  v8::Isolate* isolate_;
  v8::Persistent<v8::Context> context_;
};


// Migrates an isolate from one thread to another
TEST(KangarooIsolates) {
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  std::unique_ptr<KangarooThread> thread1;
  {
    v8::Locker locker(isolate);
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    v8::Context::Scope context_scope(context);
    CompileRun("function getValue() { return 30; }");
    thread1.reset(new KangarooThread(isolate, context));
  }
  CHECK(thread1->Start());
  thread1->Join();
}


static void CalcFibAndCheck(v8::Local<v8::Context> context) {
  Local<Value> v = CompileRun("function fib(n) {"
                              "  if (n <= 2) return 1;"
                              "  return fib(n-1) + fib(n-2);"
                              "}"
                              "fib(10)");
  CHECK(v->IsNumber());
  CHECK_EQ(55, static_cast<int>(v->NumberValue(context).FromJust()));
}

class JoinableThread {
 public:
  explicit JoinableThread(const char* name)
    : name_(name),
      semaphore_(0),
      thread_(this) {
  }

  virtual ~JoinableThread() = default;
  JoinableThread(const JoinableThread&) = delete;
  JoinableThread& operator=(const JoinableThread&) = delete;

  void Start() { CHECK(thread_.Start()); }

  void Join() {
    semaphore_.Wait();
    thread_.Join();
  }

  virtual void Run() = 0;

 private:
  class ThreadWithSemaphore : public v8::base::Thread {
   public:
    explicit ThreadWithSemaphore(JoinableThread* joinable_thread)
        : Thread(Options(joinable_thread->name_)),
          joinable_thread_(joinable_thread) {}

    void Run() override {
      joinable_thread_->Run();
      joinable_thread_->semaphore_.Signal();
    }

   private:
    JoinableThread* joinable_thread_;
  };

  const char* name_;
  v8::base::Semaphore semaphore_;
  ThreadWithSemaphore thread_;

  friend class ThreadWithSemaphore;
};


class IsolateLockingThreadWithLocalContext : public JoinableThread {
 public:
  explicit IsolateLockingThreadWithLocalContext(v8::Isolate* isolate)
    : JoinableThread("IsolateLockingThread"),
      isolate_(isolate) {
  }

  void Run() override {
    v8::Locker locker(isolate_);
    v8::Isolate::Scope isolate_scope(isolate_);
    v8::HandleScope handle_scope(isolate_);
    LocalContext local_context(isolate_);
    CalcFibAndCheck(local_context.local());
  }
 private:
  v8::Isolate* isolate_;
};

static void StartJoinAndDeleteThreads(
    const std::vector<JoinableThread*>& threads) {
  for (const auto& thread : threads) {
    thread->Start();
  }
  for (const auto& thread : threads) {
    thread->Join();
  }
  for (const auto& thread : threads) {
    delete thread;
  }
}


// Run many threads all locking on the same isolate
TEST(IsolateLockingStress) {
  i::v8_flags.always_turbofan = false;
#if V8_TARGET_ARCH_MIPS
  const int kNThreads = 50;
#else
  const int kNThreads = 100;
#endif
  std::vector<JoinableThread*> threads;
  threads.reserve(kNThreads);
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  for (int i = 0; i < kNThreads; i++) {
    threads.push_back(new IsolateLockingThreadWithLocalContext(isolate));
  }
  StartJoinAndDeleteThreads(threads);
  isolate->Dispose();
}


class IsolateNestedLockingThread : public JoinableThread {
 public:
  explicit IsolateNestedLockingThread(v8::Isolate* isolate)
    : JoinableThread("IsolateNestedLocking"), isolate_(isolate) {
  }
  void Run() override {
    v8::Locker lock(isolate_);
    v8::Isolate::Scope isolate_scope(isolate_);
    v8::HandleScope handle_scope(isolate_);
    LocalContext local_context(isolate_);
    {
      v8::Locker another_lock(isolate_);
      CalcFibAndCheck(local_context.local());
    }
    {
      v8::Locker another_lock(isolate_);
      CalcFibAndCheck(local_context.local());
    }
  }
 private:
  v8::Isolate* isolate_;
};


// Run  many threads with nested locks
TEST(IsolateNestedLocking) {
  i::v8_flags.always_turbofan = false;
#if V8_TARGET_ARCH_MIPS
  const int kNThreads = 50;
#else
  const int kNThreads = 100;
#endif
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  std::vector<JoinableThread*> threads;
  threads.reserve(kNThreads);
  for (int i = 0; i < kNThreads; i++) {
    threads.push_back(new IsolateNestedLockingThread(isolate));
  }
  StartJoinAndDeleteThreads(threads);
  isolate->Dispose();
}


class SeparateIsolatesLocksNonexclusiveThread : public JoinableThread {
 public:
  SeparateIsolatesLocksNonexclusiveThread(v8::Isolate* isolate1,
                                          v8::Isolate* isolate2)
    : JoinableThread("SeparateIsolatesLocksNonexclusiveThread"),
      isolate1_(isolate1), isolate2_(isolate2) {
  }

  void Run() override {
    v8::Locker lock(isolate1_);
    v8::Isolate::Scope isolate_scope(isolate1_);
    v8::HandleScope handle_scope(isolate1_);
    LocalContext local_context(isolate1_);

    IsolateLockingThreadWithLocalContext threadB(isolate2_);
    threadB.Start();
    CalcFibAndCheck(local_context.local());
    threadB.Join();
  }
 private:
  v8::Isolate* isolate1_;
  v8::Isolate* isolate2_;
};


// Run parallel threads that lock and access different isolates in parallel
TEST(SeparateIsolatesLocksNonexclusive) {
  v8_flags.always_turbofan = false;
#if V8_TARGET_ARCH_ARM || V8_TARGET_ARCH_S390X
  const int kNThreads = 50;
#else
  const int kNThreads = 100;
#endif
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate1 = v8::Isolate::New(create_params);
  v8::Isolate* isolate2 = v8::Isolate::New(create_params);
  std::vector<JoinableThread*> threads;
  threads.reserve(kNThreads);
  for (int i = 0; i < kNThreads; i++) {
    threads.push_back(
        new SeparateIsolatesLocksNonexclusiveThread(isolate1, isolate2));
  }
  StartJoinAndDeleteThreads(threads);
  isolate2->Dispose();
  isolate1->Dispose();
}

class LockIsolateAndCalculateFibSharedContextThread : public JoinableThread {
 public:
  explicit LockIsolateAndCalculateFibSharedContextThread(
      v8::Isolate* isolate, v8::Local<v8::Context> context)
      : JoinableThread("LockIsolateAndCalculateFibThread"),
        isolate_(isolate),
        context_(isolate, context) {}

  void Run() override {
    v8::Locker lock(isolate_);
    v8::Isolate::Scope isolate_scope(isolate_);
    v8::HandleScope handle_scope(isolate_);
    v8::Local<v8::Context> context =
        v8::Local<v8::Context>::New(isolate_, context_);
    v8::Context::Scope context_scope(context);
    CalcFibAndCheck(context);
  }
 private:
  v8::Isolate* isolate_;
  v8::Persistent<v8::Context> context_;
};

class LockerUnlockerThread : public JoinableThread {
 public:
  explicit LockerUnlockerThread(v8::Isolate* isolate)
    : JoinableThread("LockerUnlockerThread"),
      isolate_(isolate) {
  }

  void Run() override {
    isolate_->DiscardThreadSpecificMetadata();  // No-op
    {
      v8::Locker lock(isolate_);
      v8::Isolate::Scope isolate_scope(isolate_);
      v8::HandleScope handle_scope(isolate_);
      v8::Local<v8::Context> context = v8::Context::New(isolate_);
      {
        v8::Context::Scope context_scope(context);
        CalcFibAndCheck(context);
      }
      {
        LockIsolateAndCalculateFibSharedContextThread thread(isolate_, context);
        isolate_->Exit();
        v8::Unlocker unlocker(isolate_);
        thread.Start();
        thread.Join();
      }
      isolate_->Enter();
      {
        v8::Context::Scope context_scope(context);
        CalcFibAndCheck(context);
      }
    }
    isolate_->DiscardThreadSpecificMetadata();
    isolate_->DiscardThreadSpecificMetadata();  // No-op
  }

 private:
  v8::Isolate* isolate_;
};


// Use unlocker inside of a Locker, multiple threads.
TEST(LockerUnlocker) {
  v8_flags.always_turbofan = false;
#if V8_TARGET_ARCH_ARM || V8_TARGET_ARCH_S390X
  const int kNThreads = 50;
#else
  const int kNThreads = 100;
#endif
  std::vector<JoinableThread*> threads;
  threads.reserve(kNThreads);
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  for (int i = 0; i < kNThreads; i++) {
    threads.push_back(new LockerUnlockerThread(isolate));
  }
  StartJoinAndDeleteThreads(threads);
  isolate->Dispose();
}

class LockTwiceAndUnlockThread : public JoinableThread {
 public:
  explicit LockTwiceAndUnlockThread(v8::Isolate* isolate)
    : JoinableThread("LockTwiceAndUnlockThread"),
      isolate_(isolate) {
  }

  void Run() override {
    v8::Locker lock(isolate_);
    v8::Isolate::Scope isolate_scope(isolate_);
    v8::HandleScope handle_scope(isolate_);
    v8::Local<v8::Context> context = v8::Context::New(isolate_);
    {
      v8::Context::Scope context_scope(context);
      CalcFibAndCheck(context);
    }
    {
      v8::Locker second_lock(isolate_);
      {
        LockIsolateAndCalculateFibSharedContextThread thread(isolate_, context);
        isolate_->Exit();
        v8::Unlocker unlocker(isolate_);
        thread.Start();
        thread.Join();
      }
    }
    isolate_->Enter();
    {
      v8::Context::Scope context_scope(context);
      CalcFibAndCheck(context);
    }
  }

 private:
  v8::Isolate* isolate_;
};


// Use Unlocker inside two Lockers.
TEST(LockTwiceAndUnlock) {
  v8_flags.always_turbofan = false;
#if V8_TARGET_ARCH_ARM || V8_TARGET_ARCH_S390X
  const int kNThreads = 50;
#else
  const int kNThreads = 100;
#endif
  std::vector<JoinableThread*> threads;
  threads.reserve(kNThreads);
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  for (int i = 0; i < kNThreads; i++) {
    threads.push_back(new LockTwiceAndUnlockThread(isolate));
  }
  StartJoinAndDeleteThreads(threads);
  isolate->Dispose();
}

class LockAndUnlockDifferentIsolatesThread : public JoinableThread {
 public:
  LockAndUnlockDifferentIsolatesThread(v8::Isolate* isolate1,
                                       v8::Isolate* isolate2)
    : JoinableThread("LockAndUnlockDifferentIsolatesThread"),
      isolate1_(isolate1),
      isolate2_(isolate2) {
  }

  void Run() override {
    std::unique_ptr<LockIsolateAndCalculateFibSharedContextThread> thread;
    v8::Locker lock1(isolate1_);
    CHECK(v8::Locker::IsLocked(isolate1_));
    CHECK(!v8::Locker::IsLocked(isolate2_));
    {
      v8::Isolate::Scope isolate_scope(isolate1_);
      v8::HandleScope handle_scope(isolate1_);
      v8::Local<v8::Context> context1 = v8::Context::New(isolate1_);
      {
        v8::Context::Scope context_scope(context1);
        CalcFibAndCheck(context1);
      }
      thread.reset(new LockIsolateAndCalculateFibSharedContextThread(isolate1_,
                                                                     context1));
    }
    v8::Locker lock2(isolate2_);
    CHECK(v8::Locker::IsLocked(isolate1_));
    CHECK(v8::Locker::IsLocked(isolate2_));
    {
      v8::Isolate::Scope isolate_scope(isolate2_);
      v8::HandleScope handle_scope(isolate2_);
      v8::Local<v8::Context> context2 = v8::Context::New(isolate2_);
      {
        v8::Context::Scope context_scope(context2);
        CalcFibAndCheck(context2);
      }
      v8::Unlocker unlock1(isolate1_);
      CHECK(!v8::Locker::IsLocked(isolate1_));
      CHECK(v8::Locker::IsLocked(isolate2_));
      v8::Context::Scope context_scope(context2);
      thread->Start();
      CalcFibAndCheck(context2);
      thread->Join();
    }
  }

 private:
  v8::Isolate* isolate1_;
  v8::Isolate* isolate2_;
};


// Lock two isolates and unlock one of them.
TEST(LockAndUnlockDifferentIsolates) {
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate1 = v8::Isolate::New(create_params);
  v8::Isolate* isolate2 = v8::Isolate::New(create_params);
  LockAndUnlockDifferentIsolatesThread thread(isolate1, isolate2);
  thread.Start();
  thread.Join();
  isolate2->Dispose();
  isolate1->Dispose();
}

class LockUnlockLockThread : public JoinableThread {
 public:
  LockUnlockLockThread(v8::Isolate* isolate, v8::Local<v8::Context> context)
      : JoinableThread("LockUnlockLockThread"),
        isolate_(isolate),
        context_(isolate, context) {}

  void Run() override {
    v8::Locker lock1(isolate_);
    CHECK(v8::Locker::IsLocked(isolate_));
    CHECK(!v8::Locker::IsLocked(CcTest::isolate()));
    {
      v8::Isolate::Scope isolate_scope(isolate_);
      v8::HandleScope handle_scope(isolate_);
      v8::Local<v8::Context> context =
          v8::Local<v8::Context>::New(isolate_, context_);
      v8::Context::Scope context_scope(context);
      CalcFibAndCheck(context);
    }
    {
      v8::Unlocker unlock1(isolate_);
      CHECK(!v8::Locker::IsLocked(isolate_));
      CHECK(!v8::Locker::IsLocked(CcTest::isolate()));
      {
        v8::Locker lock2(isolate_);
        v8::Isolate::Scope isolate_scope(isolate_);
        v8::HandleScope handle_scope(isolate_);
        CHECK(v8::Locker::IsLocked(isolate_));
        CHECK(!v8::Locker::IsLocked(CcTest::isolate()));
        v8::Local<v8::Context> context =
            v8::Local<v8::Context>::New(isolate_, context_);
        v8::Context::Scope context_scope(context);
        CalcFibAndCheck(context);
      }
    }
  }

 private:
  v8::Isolate* isolate_;
  v8::Persistent<v8::Context> context_;
};


// Locker inside an Unlocker inside a Locker.
TEST(LockUnlockLockMultithreaded) {
#if V8_TARGET_ARCH_MIPS
  const int kNThreads = 50;
#else
  const int kNThreads = 100;
#endif
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  std::vector<JoinableThread*> threads;
  threads.reserve(kNThreads);
  {
    v8::Locker locker_(isolate);
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    for (int i = 0; i < kNThreads; i++) {
      threads.push_back(new LockUnlockLockThread(isolate, context));
    }
  }
  StartJoinAndDeleteThreads(threads);
  isolate->Dispose();
}

class LockUnlockLockDefaultIsolateThread : public JoinableThread {
 public:
  explicit LockUnlockLockDefaultIsolateThread(v8::Local<v8::Context> context)
      : JoinableThread("LockUnlockLockDefaultIsolateThread"),
        context_(CcTest::isolate(), context) {}

  void Run() override {
    v8::Locker lock1(CcTest::isolate());
    {
      v8::Isolate::Scope isolate_scope(CcTest::isolate());
      v8::HandleScope handle_scope(CcTest::isolate());
      v8::Local<v8::Context> context =
          v8::Local<v8::Context>::New(CcTest::isolate(), context_);
      v8::Context::Scope context_scope(context);
      CalcFibAndCheck(context);
    }
    {
      v8::Unlocker unlock1(CcTest::isolate());
      {
        v8::Locker lock2(CcTest::isolate());
        v8::Isolate::Scope isolate_scope(CcTest::isolate());
        v8::HandleScope handle_scope(CcTest::isolate());
        v8::Local<v8::Context> context =
            v8::Local<v8::Context>::New(CcTest::isolate(), context_);
        v8::Context::Scope context_scope(context);
        CalcFibAndCheck(context);
      }
    }
  }

 private:
  v8::Persistent<v8::Context> context_;
};


// Locker inside an Unlocker inside a Locker for default isolate.
TEST(LockUnlockLockDefaultIsolateMultithreaded) {
#if V8_TARGET_ARCH_MIPS
  const int kNThreads = 50;
#else
  const int kNThreads = 100;
#endif
  std::vector<JoinableThread*> threads;
  threads.reserve(kNThreads);
  CcTest::isolate()->Exit();
  {
    v8::Locker locker_(CcTest::isolate());
    v8::Isolate::Scope isolate_scope(CcTest::isolate());
    v8::HandleScope handle_scope(CcTest::isolate());
    Local<v8::Context> context = v8::Context::New(CcTest::isolate());
    for (int i = 0; i < kNThreads; i++) {
      threads.push_back(new LockUnlockLockDefaultIsolateThread(context));
    }
  }
  StartJoinAndDeleteThreads(threads);
  CcTest::isolate()->Enter();
}


TEST(Regress1433) {
  for (int i = 0; i < 10; i++) {
    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
    v8::Isolate* isolate = v8::Isolate::New(create_params);
    {
      v8::Locker lock(isolate);
      v8::Isolate::Scope isolate_scope(isolate);
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      v8::Local<v8::String> source = v8_str("1+1");
      v8::Local<v8::Script> script =
          v8::Script::Compile(context, source).ToLocalChecked();
      v8::Local<v8::Value> result = script->Run(context).ToLocalChecked();
      v8::String::Utf8Value utf8(isolate, result);
    }
    isolate->Dispose();
  }
}


static const char* kSimpleExtensionSource =
  "(function Foo() {"
  "  return 4;"
  "})() ";

class IsolateGenesisThread : public JoinableThread {
 public:
  IsolateGenesisThread(int count, const char* extension_names[])
    : JoinableThread("IsolateGenesisThread"),
      count_(count),
      extension_names_(extension_names)
  {}

  void Run() override {
    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
    v8::Isolate* isolate = v8::Isolate::New(create_params);
    {
      v8::Isolate::Scope isolate_scope(isolate);
      v8::ExtensionConfiguration extensions(count_, extension_names_);
      v8::HandleScope handle_scope(isolate);
      v8::Context::New(isolate, &extensions);
    }
    isolate->Dispose();
  }

 private:
  int count_;
  const char** extension_names_;
};


// Test installing extensions in separate isolates concurrently.
// http://code.google.com/p/v8/issues/detail?id=1821
TEST(ExtensionsRegistration) {
#if V8_TARGET_ARCH_ARM || V8_TARGET_ARCH_MIPS
  const int kNThreads = 10;
#else
  const int kNThreads = 40;
#endif
  const char* extension_names[] = {"test0", "test1", "test2", "test3",
                                   "test4", "test5", "test6", "test7"};
  for (const char* name : extension_names) {
    v8::RegisterExtension(
        std::make_unique<v8::Extension>(name, kSimpleExtensionSource));
  }
  std::vector<JoinableThread*> threads;
  threads.reserve(kNThreads);
  for (int i = 0; i < kNThreads; i++) {
    threads.push_back(new IsolateGenesisThread(8, extension_names));
  }
  StartJoinAndDeleteThreads(threads);
}

}  // namespace test_lockers
}  // namespace internal
}  // namespace v8

"""

```