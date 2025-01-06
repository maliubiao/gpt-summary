Response: The user wants to understand the functionality of the C++ code in `v8/test/cctest/test-lockers.cc`. I need to analyze the code and identify its main purpose. It seems to be testing the locking mechanisms (like `v8::Locker` and `v8::Unlocker`) within the V8 engine, particularly in multi-threaded scenarios.

Key observations from the code:

1. **Includes:**  It includes V8 headers related to isolates, contexts, lockers, and extensions, along with threading primitives.
2. **Test Structure:** The code uses the `TEST` macro, indicating it's a unit test file.
3. **Threads:** It creates and manages multiple threads (`DeoptimizeCodeThread`, `KangarooThread`, `IsolateLockingThreadWithLocalContext`, etc.).
4. **Lockers and Unlockers:** The core of the tests involves creating `v8::Locker` and `v8::Unlocker` objects.
5. **Isolates and Contexts:** The tests manipulate `v8::Isolate` and `v8::Context` objects, which are fundamental to V8's execution environment.
6. **Deoptimization:** Some tests specifically focus on deoptimization in a multi-threaded context.
7. **JavaScript Interaction:**  The code interacts with JavaScript by compiling and running JavaScript code using `CompileRun`. Some tests also register C++ functions that can be called from JavaScript.

Based on these observations, the primary function of the file is to **test the correctness and robustness of V8's locking mechanisms when multiple threads are involved**. This includes testing scenarios like:

* Basic locking and unlocking of isolates.
* Nested locking.
* Locking and unlocking different isolates.
* Using `Unlocker` within a `Locker`.
* Multi-threaded access to isolates and contexts.
* Interactions between locking and JavaScript execution (including deoptimization).
* Migrating isolates between threads.
* Concurrent isolate creation with extensions.

Now, regarding the relationship with JavaScript, the locking mechanisms in V8 are crucial for ensuring thread safety when JavaScript code is executed in a multi-threaded environment. When a thread needs to access V8's internal data structures or execute JavaScript code within a specific isolate, it needs to acquire a lock for that isolate. This prevents race conditions and ensures data consistency.

To illustrate this with a JavaScript example, consider a scenario where you're using Node.js worker threads (which internally use V8 isolates). If multiple worker threads try to access or modify shared data within the same V8 isolate without proper locking, it can lead to unpredictable behavior.

Let's craft a JavaScript example to demonstrate the need for locking conceptually, even though direct `v8::Locker` usage isn't exposed in standard JavaScript APIs. The example will highlight a potential race condition without a locking mechanism.
这个C++源代码文件 `v8/test/cctest/test-lockers.cc` 的主要功能是**测试 V8 JavaScript 引擎的锁机制 (Locker 和 Unlocker) 在多线程环境下的正确性和稳定性**。

更具体地说，它测试了以下场景：

1. **基本的 Locker 和 Unlocker 的使用:**  测试在单个线程和多个线程中获取和释放 Isolate 锁的行为。
2. **嵌套锁:** 测试在已经持有 Isolate 锁的情况下再次获取锁 (Locker 的可重入性)。
3. **跨 Isolate 锁:** 测试在不同的 Isolate 上分别获取锁，以及在一个 Isolate 上持有锁的情况下尝试访问另一个 Isolate 的行为。
4. **在 Locker 内部使用 Unlocker:** 测试在持有锁的情况下临时释放锁，然后重新获取锁的机制。
5. **多线程环境下的并发访问:**  创建多个线程并发地尝试获取同一个或不同的 Isolate 的锁，以验证锁机制的并发安全性。
6. **Isolate 的迁移:** 测试将 Isolate 从一个线程迁移到另一个线程的能力。
7. **与 JavaScript 执行的交互:** 测试在持有锁的情况下执行 JavaScript 代码，以及在 JavaScript 代码中触发锁的释放和重新获取。
8. **延迟和积极去优化与锁的交互:**  模拟在持有锁的线程中，另一个线程触发 JavaScript 函数的去优化，并验证锁机制是否能正确处理这种情况。
9. **并发创建包含扩展的 Isolate:** 测试在多线程环境下并发创建并初始化包含 V8 扩展的 Isolate。

**与 JavaScript 的关系以及 JavaScript 例子:**

虽然 `v8::Locker` 和 `v8::Unlocker` 是 V8 引擎的 C++ 接口，JavaScript 开发者通常不会直接使用它们。但是，V8 的锁机制对于 JavaScript 在多线程环境下的正确执行至关重要。

在 Node.js 环境中，当使用 Worker 线程时，每个 Worker 线程都有自己的 V8 Isolate。  V8 的锁机制确保了不同 Isolate 之间的数据隔离和线程安全。

**模拟一个可能需要锁的场景 (尽管 JavaScript 中锁是隐式的):**

假设我们有一个共享的 JavaScript 对象，并在多个 Node.js Worker 线程中对其进行操作。如果没有某种形式的同步机制（在 V8 内部是由 Locker 实现的），可能会出现竞态条件：

```javascript
// main.js
const { Worker, isMainThread, parentPort } = require('worker_threads');

if (isMainThread) {
  const sharedData = { count: 0 };
  const numWorkers = 4;

  for (let i = 0; i < numWorkers; i++) {
    const worker = new Worker('./worker.js', { workerData: sharedData });
    worker.on('message', (message) => {
      console.log(`Worker ${i} says: ${message}`);
    });
  }
}

// worker.js
const { workerData } = require('worker_threads');

for (let i = 0; i < 10000; i++) {
  workerData.count++; // 多个线程同时修改共享数据，可能出现问题
}

parentPort.postMessage(`Count incremented.`);
```

在上面的例子中，`sharedData` 对象被传递给多个 Worker 线程。每个线程都会递增 `sharedData.count`。  尽管这个例子在 Node.js 的 Worker 模型下，由于数据是拷贝传递的，不会直接出现 V8 锁需要解决的竞态条件。

**为了更贴切地说明 V8 锁的作用，我们可以想象一个 V8 内部的场景，或者使用一些可以跨线程共享 V8 对象的机制（虽然标准 JavaScript API 中不常用）：**

假设有一个 C++ 扩展，它创建了一个可以在不同线程的 JavaScript 代码中访问的 V8 对象。  如果没有适当的锁，以下 JavaScript 代码可能会导致问题：

```javascript
// 假设有一个 C++ 扩展提供了一个名为 'sharedObject' 的全局对象
// 并且这个对象的状态可以被修改

function incrementCounter() {
  // 在 V8 内部，访问和修改 sharedObject 的状态需要获取锁
  sharedObject.counter++;
}

// 线程 1
incrementCounter();
incrementCounter();

// 线程 2 (同时执行)
incrementCounter();
```

在这种情况下，如果线程 1 和线程 2 同时调用 `incrementCounter()`，并且没有 V8 的锁机制来保护 `sharedObject.counter` 的访问和修改，那么最终的 `counter` 值可能是 2 或 3，而不是预期的 3。 V8 的 `Locker` 和 `Unlocker` 确保了在访问和修改 V8 内部对象时的线程安全性。

**总结:**

虽然 JavaScript 开发者不直接使用 `v8::Locker` 和 `v8::Unlocker`，但这些底层的锁机制对于 V8 引擎在多线程环境下运行 JavaScript 代码的正确性和稳定性至关重要。 `test-lockers.cc` 文件通过各种测试用例，验证了这些锁机制的正确性，从而保证了 JavaScript 在并发环境下的可靠执行。这对于 Node.js 的 Worker 线程、以及任何嵌入了 V8 并在多线程环境中运行 JavaScript 的应用程序来说都是非常关键的。

Prompt: 
```
这是目录为v8/test/cctest/test-lockers.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

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