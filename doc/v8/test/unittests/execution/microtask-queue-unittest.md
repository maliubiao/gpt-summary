Response: Let's break down the thought process for analyzing the C++ code and creating the JavaScript analogy.

**1. Understanding the Core Purpose:**

The first thing to recognize is the file name: `microtask-queue-unittest.cc`. The "unittest" part is key. This file isn't *implementing* the microtask queue, it's *testing* its implementation. Therefore, the primary function of this code is to verify the behavior of the `MicrotaskQueue` class.

**2. Identifying Key Classes and Concepts:**

Scan the includes and the code itself for prominent class names and important concepts. Here's what stands out:

* `MicrotaskQueue`: This is the central class being tested.
* `Microtask`:  These are the individual units of work being queued.
* `Promise`:  Promises are explicitly mentioned and used in the tests. This strongly suggests a connection to JavaScript's asynchronous operations.
* `Context`:  The concept of different JavaScript execution contexts appears.
* `RunMicrotasks`:  A method that seems to execute the queued microtasks.
* `EnqueueMicrotask`: A method to add tasks to the queue.
* `DetachGlobal`: A method related to disconnecting a queue from a context.
* `PromiseHook`:  Mentioned as a way to switch promise implementations.
* `CallableTask`, `PromiseFulfillReactionJobTask`, `PromiseRejectReactionJobTask`, `PromiseResolveThenableJobTask`: These are specific types of microtasks, revealing the underlying mechanism.

**3. Analyzing the Tests:**

Go through the individual `TEST_P` functions. Each test focuses on a specific aspect of the `MicrotaskQueue`:

* `EnqueueAndRun`: Basic queuing and execution.
* `BufferGrowth`: How the queue expands as more tasks are added.
* `InstanceChain`: How multiple `MicrotaskQueue` instances are linked.
* `VisitRoot`: Interaction with garbage collection (rooting).
* `PromiseHandlerContext`:  How the context of promise handlers is handled.
* `DetachGlobal_*`: A series of tests exploring the behavior when a context is detached, focusing on preventing unintended executions and memory leaks.
* `MicrotasksScope`:  A mechanism for running microtasks within a defined scope.

**4. Inferring Functionality from Tests:**

Based on the tests, we can start to infer the functionalities of the `MicrotaskQueue`:

* **Queuing:**  It can hold a collection of microtasks.
* **Execution:** It provides a way to run these tasks.
* **FIFO (Implicit):** The tests imply tasks are executed in the order they are enqueued.
* **Context Awareness:** Microtasks are associated with a specific JavaScript context.
* **Deferred Execution:** Microtasks are not executed immediately but at a later time.
* **Garbage Collection Integration:** The queue needs to prevent microtasks from being prematurely garbage collected.
* **Handling Detachment:** When a context is detached, associated microtasks should be handled gracefully (likely canceled or prevented from running).
* **Promise Integration:**  It plays a crucial role in the implementation of JavaScript Promises.

**5. Connecting to JavaScript:**

The presence of `Promise` and the nature of the tests strongly suggest a link to JavaScript's event loop and asynchronous operations. Microtasks in V8 are the underlying mechanism for implementing Promises and other asynchronous constructs.

* **`Promise.then()`/`.catch()`:**  The tests with `PromiseFulfillReactionJobTask` and `PromiseRejectReactionJobTask` clearly indicate that the `MicrotaskQueue` is used to schedule the execution of the `then` and `catch` callbacks.
* **`Promise.resolve()` with thenables:** The `PromiseResolveThenableJobTask` test shows how the queue handles the resolution of promises with custom `then` methods.
* **`queueMicrotask()` (inferred):** While not explicitly tested with `queueMicrotask` in the C++ code, the general concept of scheduling small, asynchronous tasks aligns perfectly with what `queueMicrotask()` does in JavaScript.

**6. Creating the JavaScript Analogy:**

Now, translate the C++ concepts and test scenarios into JavaScript:

* **`MicrotaskQueue` ->  JavaScript's internal microtask queue:** This is not directly exposed, but the concept exists.
* **`Microtask` ->  The callbacks passed to `Promise.then()`, `Promise.catch()`, or `queueMicrotask()`:** These represent the units of work.
* **`EnqueueMicrotask` ->  Calling `Promise.then()`, `Promise.catch()`, or `queueMicrotask()`:** These are the ways to schedule microtasks.
* **`RunMicrotasks` -> The JavaScript engine's event loop processing the microtask queue after the current task:** This is the implicit mechanism in JavaScript.
* **`DetachGlobal` ->  Closing a browser tab or navigating away from a page:**  This analogy helps understand the idea of an execution environment being destroyed.

**7. Refining the JavaScript Examples:**

Construct simple JavaScript code snippets that illustrate the same principles tested in the C++ code. For example:

* Show how `Promise.then()` schedules a microtask.
* Demonstrate the order of execution of multiple `Promise.then()` callbacks.
* Illustrate the impact of detaching a context (analogous to a closed tab) on pending microtasks.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Is this about a specific JavaScript API?  **Correction:** It's about the *underlying implementation* in V8, which powers JavaScript's asynchronous features.
* **Focusing too much on the C++ details:** **Correction:**  Shift the focus to the *behavior* being tested and how that translates to JavaScript.
* **Missing the `queueMicrotask()` connection:** **Correction:** Realize that while the tests focus on Promises, the `MicrotaskQueue` is a more general concept, and `queueMicrotask()` is a direct way to use it.

By following this thought process, moving from the specific C++ code to the broader concepts and then mapping those concepts to familiar JavaScript features, we can arrive at a clear and accurate summary of the C++ file's purpose and its relevance to JavaScript.
这个C++源代码文件 `v8/test/unittests/execution/microtask-queue-unittest.cc` 是V8 JavaScript引擎的**单元测试文件**，专门用于测试 `MicrotaskQueue` 类的功能。

**功能归纳:**

该文件的主要功能是测试 `MicrotaskQueue` 类的以下特性：

1. **微任务的入队和执行:** 测试微任务能否被正确地添加到队列中，并按照先进先出的顺序执行。
2. **队列的容量增长:** 测试当队列满时，其内部缓冲区能否动态增长以容纳更多的微任务。
3. **微任务队列的链接:**  测试多个 `MicrotaskQueue` 实例如何形成双向链表结构，用于管理不同上下文的微任务。
4. **微任务的垃圾回收:** 测试微任务是否会被正确地标记为根对象，防止在垃圾回收时被意外回收。
5. **Promise处理器的上下文:** 测试 Promise 的 `then` 或 `catch` 回调函数（作为微任务执行）的上下文是否正确设置。
6. **上下文分离 (`DetachGlobal`) 的影响:**  测试当一个 JavaScript 执行上下文被分离后，与其关联的微任务队列的行为，例如：
    - 分离后是否还能添加新的微任务。
    - 分离后尝试运行微任务会发生什么（例如，是否会被取消）。
    - 与分离上下文关联的 Promise 链的处理。
7. **微任务作用域 (`MicrotasksScope`):** 测试在特定的作用域内运行微任务的能力。

**与 JavaScript 功能的关系以及 JavaScript 示例:**

`MicrotaskQueue` 是 V8 引擎实现 JavaScript 中微任务机制的核心组件。微任务是异步操作的一种形式，它在当前任务执行完毕后，但在浏览器重新渲染页面之前执行。

以下是一些与 `MicrotaskQueue` 相关的 JavaScript 功能，并用示例说明：

**1. Promise:**

JavaScript 的 `Promise` 是最常见的微任务来源。当一个 Promise 被解决（resolve）或拒绝（reject）时，它的 `then` 或 `catch` 回调函数会被放入微任务队列等待执行。

```javascript
console.log('开始');

Promise.resolve().then(() => {
  console.log('Promise 回调');
});

console.log('结束');

// 输出顺序：
// 开始
// 结束
// Promise 回调
```

在这个例子中，`Promise.resolve().then()` 会将回调函数放入微任务队列。`console.log('结束')` 会先执行完毕，然后事件循环会处理微任务队列，执行 `console.log('Promise 回调')`。

**2. `queueMicrotask()`:**

JavaScript 提供了 `queueMicrotask()` 函数，允许开发者直接将一个函数放入微任务队列。

```javascript
console.log('开始');

queueMicrotask(() => {
  console.log('queueMicrotask 回调');
});

console.log('结束');

// 输出顺序：
// 开始
// 结束
// queueMicrotask 回调
```

与 Promise 类似，`queueMicrotask` 注册的回调也会在当前任务完成后，但在浏览器重新渲染前执行。

**3. `async/await` (底层使用 Promise 和微任务):**

`async/await` 是基于 Promise 构建的语法糖，它的 `await` 表达式实际上会暂停函数的执行，并将剩余部分放入微任务队列。

```javascript
async function myFunction() {
  console.log('函数开始');
  await Promise.resolve();
  console.log('await 之后');
  return '完成';
}

console.log('主程序开始');
myFunction().then(result => console.log(result));
console.log('主程序结束');

// 输出顺序：
// 主程序开始
// 函数开始
// 主程序结束
// await 之后
// 完成
```

在这个例子中，当执行到 `await Promise.resolve()` 时，`myFunction` 函数会暂停，并将 `console.log('await 之后')` 和 `return '完成'` 放入微任务队列。

**4. 上下文分离 (`DetachGlobal`) 的概念:**

虽然 JavaScript 本身没有直接的 `DetachGlobal` API，但其背后的概念与浏览器标签页或 iframe 的关闭类似。当一个标签页或 iframe 关闭时，与该环境关联的待执行的异步操作（包括微任务）可能会被取消或不再执行。

在 `MicrotaskQueueTest` 中对 `DetachGlobal` 的测试，正是为了确保 V8 引擎在处理这类场景时，能够正确地清理资源，避免内存泄漏或错误的行为。

**总结:**

`v8/test/unittests/execution/microtask-queue-unittest.cc` 这个 C++ 文件通过各种单元测试，验证了 V8 引擎中 `MicrotaskQueue` 类的正确性和健壮性。这直接关系到 JavaScript 中 Promise、`queueMicrotask` 和 `async/await` 等异步功能的可靠运行。理解这个测试文件有助于深入理解 JavaScript 异步机制的底层实现原理。

Prompt: 
```
这是目录为v8/test/unittests/execution/microtask-queue-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/execution/microtask-queue.h"

#include <algorithm>
#include <functional>
#include <memory>
#include <vector>

#include "include/v8-function.h"
#include "src/heap/factory.h"
#include "src/objects/foreign.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/js-objects-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/promise-inl.h"
#include "src/objects/visitors.h"
#include "test/unittests/test-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {
namespace internal {

using Closure = std::function<void()>;

void RunStdFunction(void* data) {
  std::unique_ptr<Closure> f(static_cast<Closure*>(data));
  (*f)();
}

template <typename TMixin>
class WithFinalizationRegistryMixin : public TMixin {
 public:
  WithFinalizationRegistryMixin() = default;
  ~WithFinalizationRegistryMixin() override = default;
  WithFinalizationRegistryMixin(const WithFinalizationRegistryMixin&) = delete;
  WithFinalizationRegistryMixin& operator=(
      const WithFinalizationRegistryMixin&) = delete;

  static void SetUpTestSuite() {
    CHECK_NULL(save_flags_);
    save_flags_ = new SaveFlags();
    v8_flags.expose_gc = true;
    v8_flags.allow_natives_syntax = true;
    TMixin::SetUpTestSuite();
  }

  static void TearDownTestSuite() {
    TMixin::TearDownTestSuite();
    CHECK_NOT_NULL(save_flags_);
    delete save_flags_;
    save_flags_ = nullptr;
  }

 private:
  static SaveFlags* save_flags_;
};

template <typename TMixin>
SaveFlags* WithFinalizationRegistryMixin<TMixin>::save_flags_ = nullptr;

using TestWithNativeContextAndFinalizationRegistry =  //
    WithInternalIsolateMixin<                         //
        WithContextMixin<                             //
            WithFinalizationRegistryMixin<            //
                WithIsolateScopeMixin<                //
                    WithIsolateMixin<                 //
                        WithDefaultPlatformMixin<     //
                            ::testing::Test>>>>>>;

namespace {

void DummyPromiseHook(PromiseHookType type, Local<Promise> promise,
                      Local<Value> parent) {}

}  // namespace

class MicrotaskQueueTest : public TestWithNativeContextAndFinalizationRegistry,
                           public ::testing::WithParamInterface<bool> {
 public:
  template <typename F>
  Handle<Microtask> NewMicrotask(F&& f) {
    DirectHandle<Foreign> runner = factory()->NewForeign<kMicrotaskCallbackTag>(
        reinterpret_cast<Address>(&RunStdFunction));
    DirectHandle<Foreign> data =
        factory()->NewForeign<kMicrotaskCallbackDataTag>(
            reinterpret_cast<Address>(new Closure(std::forward<F>(f))));
    return factory()->NewCallbackTask(runner, data);
  }

  void SetUp() override {
    microtask_queue_ = MicrotaskQueue::New(isolate());
    native_context()->set_microtask_queue(isolate(), microtask_queue());

    if (GetParam()) {
      // Use a PromiseHook to switch the implementation to ResolvePromise
      // runtime, instead of ResolvePromise builtin.
      v8_isolate()->SetPromiseHook(&DummyPromiseHook);
    }
  }

  void TearDown() override {
    if (microtask_queue()) {
      microtask_queue()->RunMicrotasks(isolate());
      context()->DetachGlobal();
    }
  }

  MicrotaskQueue* microtask_queue() const { return microtask_queue_.get(); }

  void ClearTestMicrotaskQueue() {
    context()->DetachGlobal();
    microtask_queue_ = nullptr;
  }

  template <size_t N>
  Handle<Name> NameFromChars(const char (&chars)[N]) {
    return isolate()->factory()->NewStringFromStaticChars(chars);
  }

 private:
  std::unique_ptr<MicrotaskQueue> microtask_queue_;
};

class RecordingVisitor : public RootVisitor {
 public:
  RecordingVisitor() = default;
  ~RecordingVisitor() override = default;

  void VisitRootPointers(Root root, const char* description,
                         FullObjectSlot start, FullObjectSlot end) override {
    for (FullObjectSlot current = start; current != end; ++current) {
      visited_.push_back(*current);
    }
  }

  const std::vector<Tagged<Object>>& visited() const { return visited_; }

 private:
  std::vector<Tagged<Object>> visited_;
};

// Sanity check. Ensure a microtask is stored in a queue and run.
TEST_P(MicrotaskQueueTest, EnqueueAndRun) {
  bool ran = false;
  EXPECT_EQ(0, microtask_queue()->capacity());
  EXPECT_EQ(0, microtask_queue()->size());
  microtask_queue()->EnqueueMicrotask(*NewMicrotask([this, &ran] {
    EXPECT_FALSE(ran);
    ran = true;
    EXPECT_TRUE(microtask_queue()->HasMicrotasksSuppressions());
  }));
  EXPECT_EQ(MicrotaskQueue::kMinimumCapacity, microtask_queue()->capacity());
  EXPECT_EQ(1, microtask_queue()->size());
  EXPECT_EQ(1, microtask_queue()->RunMicrotasks(isolate()));
  EXPECT_TRUE(ran);
  EXPECT_EQ(0, microtask_queue()->size());
}

// Check for a buffer growth.
TEST_P(MicrotaskQueueTest, BufferGrowth) {
  int count = 0;

  // Enqueue and flush the queue first to have non-zero |start_|.
  microtask_queue()->EnqueueMicrotask(
      *NewMicrotask([&count] { EXPECT_EQ(0, count++); }));
  EXPECT_EQ(1, microtask_queue()->RunMicrotasks(isolate()));

  EXPECT_LT(0, microtask_queue()->capacity());
  EXPECT_EQ(0, microtask_queue()->size());
  EXPECT_EQ(1, microtask_queue()->start());

  // Fill the queue with Microtasks.
  for (int i = 1; i <= MicrotaskQueue::kMinimumCapacity; ++i) {
    microtask_queue()->EnqueueMicrotask(
        *NewMicrotask([&count, i] { EXPECT_EQ(i, count++); }));
  }
  EXPECT_EQ(MicrotaskQueue::kMinimumCapacity, microtask_queue()->capacity());
  EXPECT_EQ(MicrotaskQueue::kMinimumCapacity, microtask_queue()->size());

  // Add another to grow the ring buffer.
  microtask_queue()->EnqueueMicrotask(*NewMicrotask(
      [&] { EXPECT_EQ(MicrotaskQueue::kMinimumCapacity + 1, count++); }));

  EXPECT_LT(MicrotaskQueue::kMinimumCapacity, microtask_queue()->capacity());
  EXPECT_EQ(MicrotaskQueue::kMinimumCapacity + 1, microtask_queue()->size());

  // Run all pending Microtasks to ensure they run in the proper order.
  EXPECT_EQ(MicrotaskQueue::kMinimumCapacity + 1,
            microtask_queue()->RunMicrotasks(isolate()));
  EXPECT_EQ(MicrotaskQueue::kMinimumCapacity + 2, count);
}

// MicrotaskQueue instances form a doubly linked list.
TEST_P(MicrotaskQueueTest, InstanceChain) {
  ClearTestMicrotaskQueue();

  MicrotaskQueue* default_mtq = isolate()->default_microtask_queue();
  ASSERT_TRUE(default_mtq);
  EXPECT_EQ(default_mtq, default_mtq->next());
  EXPECT_EQ(default_mtq, default_mtq->prev());

  // Create two instances, and check their connection.
  // The list contains all instances in the creation order, and the next of the
  // last instance is the first instance:
  //   default_mtq -> mtq1 -> mtq2 -> default_mtq.
  std::unique_ptr<MicrotaskQueue> mtq1 = MicrotaskQueue::New(isolate());
  std::unique_ptr<MicrotaskQueue> mtq2 = MicrotaskQueue::New(isolate());
  EXPECT_EQ(default_mtq->next(), mtq1.get());
  EXPECT_EQ(mtq1->next(), mtq2.get());
  EXPECT_EQ(mtq2->next(), default_mtq);
  EXPECT_EQ(default_mtq, mtq1->prev());
  EXPECT_EQ(mtq1.get(), mtq2->prev());
  EXPECT_EQ(mtq2.get(), default_mtq->prev());

  // Deleted item should be also removed from the list.
  mtq1 = nullptr;
  EXPECT_EQ(default_mtq->next(), mtq2.get());
  EXPECT_EQ(mtq2->next(), default_mtq);
  EXPECT_EQ(default_mtq, mtq2->prev());
  EXPECT_EQ(mtq2.get(), default_mtq->prev());
}

// Pending Microtasks in MicrotaskQueues are strong roots. Ensure they are
// visited exactly once.
TEST_P(MicrotaskQueueTest, VisitRoot) {
  // Ensure that the ring buffer has separate in-use region.
  for (int i = 0; i < MicrotaskQueue::kMinimumCapacity / 2 + 1; ++i) {
    microtask_queue()->EnqueueMicrotask(*NewMicrotask([] {}));
  }
  EXPECT_EQ(MicrotaskQueue::kMinimumCapacity / 2 + 1,
            microtask_queue()->RunMicrotasks(isolate()));

  std::vector<Tagged<Object>> expected;
  for (int i = 0; i < MicrotaskQueue::kMinimumCapacity / 2 + 1; ++i) {
    DirectHandle<Microtask> microtask = NewMicrotask([] {});
    expected.push_back(*microtask);
    microtask_queue()->EnqueueMicrotask(*microtask);
  }
  EXPECT_GT(microtask_queue()->start() + microtask_queue()->size(),
            microtask_queue()->capacity());

  RecordingVisitor visitor;
  microtask_queue()->IterateMicrotasks(&visitor);

  std::vector<Tagged<Object>> actual = visitor.visited();
  std::sort(expected.begin(), expected.end());
  std::sort(actual.begin(), actual.end());
  EXPECT_EQ(expected, actual);
}

TEST_P(MicrotaskQueueTest, PromiseHandlerContext) {
  microtask_queue()->set_microtasks_policy(MicrotasksPolicy::kExplicit);
  Local<v8::Context> v8_context2 = v8::Context::New(v8_isolate());
  Local<v8::Context> v8_context3 = v8::Context::New(v8_isolate());
  Local<v8::Context> v8_context4 = v8::Context::New(v8_isolate());
  DirectHandle<Context> context2 =
      Utils::OpenDirectHandle(*v8_context2, isolate());
  DirectHandle<Context> context3 =
      Utils::OpenDirectHandle(*v8_context3, isolate());
  DirectHandle<Context> context4 =
      Utils::OpenDirectHandle(*v8_context3, isolate());
  context2->native_context()->set_microtask_queue(isolate(), microtask_queue());
  context3->native_context()->set_microtask_queue(isolate(), microtask_queue());
  context4->native_context()->set_microtask_queue(isolate(), microtask_queue());

  Handle<JSFunction> handler;
  Handle<JSProxy> proxy;
  Handle<JSProxy> revoked_proxy;
  Handle<JSBoundFunction> bound;

  // Create a JSFunction on |context2|
  {
    v8::Context::Scope scope(v8_context2);
    handler = RunJS<JSFunction>("()=>{}");
    EXPECT_EQ(*context2,
              *JSReceiver::GetContextForMicrotask(handler).ToHandleChecked());
  }

  // Create a JSProxy on |context3|.
  {
    v8::Context::Scope scope(v8_context3);
    ASSERT_TRUE(
        v8_context3->Global()
            ->Set(v8_context3, NewString("handler"), Utils::ToLocal(handler))
            .FromJust());
    proxy = RunJS<JSProxy>("new Proxy(handler, {})");
    revoked_proxy = RunJS<JSProxy>(
        "let {proxy, revoke} = Proxy.revocable(handler, {});"
        "revoke();"
        "proxy");
    EXPECT_EQ(*context2,
              *JSReceiver::GetContextForMicrotask(proxy).ToHandleChecked());
    EXPECT_TRUE(JSReceiver::GetContextForMicrotask(revoked_proxy).is_null());
  }

  // Create a JSBoundFunction on |context4|.
  // Note that its CreationContext and ContextForTaskCancellation is |context2|.
  {
    v8::Context::Scope scope(v8_context4);
    ASSERT_TRUE(
        v8_context4->Global()
            ->Set(v8_context4, NewString("handler"), Utils::ToLocal(handler))
            .FromJust());
    bound = RunJS<JSBoundFunction>("handler.bind()");
    EXPECT_EQ(*context2,
              *JSReceiver::GetContextForMicrotask(bound).ToHandleChecked());
  }

  // Give the objects to the main context.
  SetGlobalProperty("handler", Utils::ToLocal(handler));
  SetGlobalProperty("proxy", Utils::ToLocal(proxy));
  SetGlobalProperty("revoked_proxy", Utils::ToLocal(revoked_proxy));
  SetGlobalProperty("bound", Utils::ToLocal(Cast<JSReceiver>(bound)));
  RunJS(
      "Promise.resolve().then(handler);"
      "Promise.reject().catch(proxy);"
      "Promise.resolve().then(revoked_proxy);"
      "Promise.resolve().then(bound);");

  ASSERT_EQ(4, microtask_queue()->size());
  Handle<Microtask> microtask1(microtask_queue()->get(0), isolate());
  ASSERT_TRUE(IsPromiseFulfillReactionJobTask(*microtask1));
  EXPECT_EQ(*context2,
            Cast<PromiseFulfillReactionJobTask>(microtask1)->context());

  Handle<Microtask> microtask2(microtask_queue()->get(1), isolate());
  ASSERT_TRUE(IsPromiseRejectReactionJobTask(*microtask2));
  EXPECT_EQ(*context2,
            Cast<PromiseRejectReactionJobTask>(microtask2)->context());

  Handle<Microtask> microtask3(microtask_queue()->get(2), isolate());
  ASSERT_TRUE(IsPromiseFulfillReactionJobTask(*microtask3));
  // |microtask3| corresponds to a PromiseReaction for |revoked_proxy|.
  // As |revoked_proxy| doesn't have a context, the current context should be
  // used as the fallback context.
  EXPECT_EQ(*native_context(),
            Cast<PromiseFulfillReactionJobTask>(microtask3)->context());

  Handle<Microtask> microtask4(microtask_queue()->get(3), isolate());
  ASSERT_TRUE(IsPromiseFulfillReactionJobTask(*microtask4));
  EXPECT_EQ(*context2,
            Cast<PromiseFulfillReactionJobTask>(microtask4)->context());

  v8_context4->DetachGlobal();
  v8_context3->DetachGlobal();
  v8_context2->DetachGlobal();
}

TEST_P(MicrotaskQueueTest, DetachGlobal_Enqueue) {
  EXPECT_EQ(0, microtask_queue()->size());

  // Detach MicrotaskQueue from the current context.
  context()->DetachGlobal();

  // No microtask should be enqueued after DetachGlobal call.
  EXPECT_EQ(0, microtask_queue()->size());
  RunJS("Promise.resolve().then(()=>{})");
  EXPECT_EQ(0, microtask_queue()->size());
}

TEST_P(MicrotaskQueueTest, DetachGlobal_Run) {
  microtask_queue()->set_microtasks_policy(MicrotasksPolicy::kExplicit);
  EXPECT_EQ(0, microtask_queue()->size());

  // Enqueue microtasks to the current context.
  Handle<JSArray> ran = RunJS<JSArray>(
      "var ran = [false, false, false, false];"
      "Promise.resolve().then(() => { ran[0] = true; });"
      "Promise.reject().catch(() => { ran[1] = true; });"
      "ran");

  DirectHandle<JSFunction> function =
      RunJS<JSFunction>("(function() { ran[2] = true; })");
  DirectHandle<CallableTask> callable =
      factory()->NewCallableTask(function, Utils::OpenHandle(*context()));
  microtask_queue()->EnqueueMicrotask(*callable);

  // The handler should not run at this point.
  const int kNumExpectedTasks = 3;
  for (int i = 0; i < kNumExpectedTasks; ++i) {
    EXPECT_TRUE(
        IsFalse(*Object::GetElement(isolate(), ran, i).ToHandleChecked()));
  }
  EXPECT_EQ(kNumExpectedTasks, microtask_queue()->size());

  // Detach MicrotaskQueue from the current context.
  context()->DetachGlobal();

  // RunMicrotasks processes pending Microtasks, but Microtasks that are
  // associated to a detached context should be cancelled and should not take
  // effect.
  microtask_queue()->RunMicrotasks(isolate());
  EXPECT_EQ(0, microtask_queue()->size());
  for (int i = 0; i < kNumExpectedTasks; ++i) {
    EXPECT_TRUE(
        IsFalse(*Object::GetElement(isolate(), ran, i).ToHandleChecked()));
  }
}

TEST_P(MicrotaskQueueTest, DetachGlobal_PromiseResolveThenableJobTask) {
  microtask_queue()->set_microtasks_policy(MicrotasksPolicy::kExplicit);
  RunJS(
      "var resolve;"
      "var promise = new Promise(r => { resolve = r; });"
      "promise.then(() => {});"
      "resolve({});");

  // A PromiseResolveThenableJobTask is pending in the MicrotaskQueue.
  EXPECT_EQ(1, microtask_queue()->size());

  // Detach MicrotaskQueue from the current context.
  context()->DetachGlobal();

  // RunMicrotasks processes the pending Microtask, but Microtasks that are
  // associated to a detached context should be cancelled and should not take
  // effect.
  // As PromiseResolveThenableJobTask queues another task for resolution,
  // the return value is 2 if it ran.
  EXPECT_EQ(1, microtask_queue()->RunMicrotasks(isolate()));
  EXPECT_EQ(0, microtask_queue()->size());
}

TEST_P(MicrotaskQueueTest, DetachGlobal_ResolveThenableForeignThen) {
  microtask_queue()->set_microtasks_policy(MicrotasksPolicy::kExplicit);
  Handle<JSArray> result = RunJS<JSArray>(
      "let result = [false];"
      "result");
  Handle<JSFunction> then = RunJS<JSFunction>("() => { result[0] = true; }");

  DirectHandle<JSPromise> stale_promise;

  {
    // Create a context with its own microtask queue.
    std::unique_ptr<MicrotaskQueue> sub_microtask_queue =
        MicrotaskQueue::New(isolate());
    sub_microtask_queue->set_microtasks_policy(MicrotasksPolicy::kExplicit);
    Local<v8::Context> sub_context = v8::Context::New(
        v8_isolate(),
        /* extensions= */ nullptr,
        /* global_template= */ MaybeLocal<ObjectTemplate>(),
        /* global_object= */ MaybeLocal<Value>(),
        /* internal_fields_deserializer= */ DeserializeInternalFieldsCallback(),
        sub_microtask_queue.get());

    {
      v8::Context::Scope scope(sub_context);
      CHECK(sub_context->Global()
                ->Set(sub_context, NewString("then"),
                      Utils::ToLocal(Cast<JSReceiver>(then)))
                .FromJust());

      ASSERT_EQ(0, microtask_queue()->size());
      ASSERT_EQ(0, sub_microtask_queue->size());
      ASSERT_TRUE(
          IsFalse(*Object::GetElement(isolate(), result, 0).ToHandleChecked()));

      // With a regular thenable, a microtask is queued on the sub-context.
      RunJS<JSPromise>("Promise.resolve({ then: cb => cb(1) })");
      EXPECT_EQ(0, microtask_queue()->size());
      EXPECT_EQ(1, sub_microtask_queue->size());
      EXPECT_TRUE(
          IsFalse(*Object::GetElement(isolate(), result, 0).ToHandleChecked()));

      // But when the `then` method comes from another context, a microtask is
      // instead queued on the main context.
      stale_promise = RunJS<JSPromise>("Promise.resolve({ then })");
      EXPECT_EQ(1, microtask_queue()->size());
      EXPECT_EQ(1, sub_microtask_queue->size());
      EXPECT_TRUE(
          IsFalse(*Object::GetElement(isolate(), result, 0).ToHandleChecked()));
    }

    sub_context->DetachGlobal();
  }

  EXPECT_EQ(1, microtask_queue()->size());
  EXPECT_TRUE(
      IsFalse(*Object::GetElement(isolate(), result, 0).ToHandleChecked()));

  EXPECT_EQ(1, microtask_queue()->RunMicrotasks(isolate()));
  EXPECT_EQ(0, microtask_queue()->size());
  EXPECT_TRUE(
      IsTrue(*Object::GetElement(isolate(), result, 0).ToHandleChecked()));
}

TEST_P(MicrotaskQueueTest, DetachGlobal_HandlerContext) {
  // EnqueueMicrotask should use the context associated to the handler instead
  // of the current context. E.g.
  //   // At Context A.
  //   let resolved = Promise.resolve();
  //   // Call DetachGlobal on A, so that microtasks associated to A is
  //   // cancelled.
  //
  //   // At Context B.
  //   let handler = () => {
  //     console.log("here");
  //   };
  //   // The microtask to run |handler| should be associated to B instead of A,
  //   // so that handler runs even |resolved| is on the detached context A.
  //   resolved.then(handler);

  Handle<JSReceiver> results = isolate()->factory()->NewJSObjectWithNullProto();

  // These belong to a stale Context.
  Handle<JSPromise> stale_resolved_promise;
  Handle<JSPromise> stale_rejected_promise;
  Handle<JSReceiver> stale_handler;

  Local<v8::Context> sub_context = v8::Context::New(v8_isolate());
  {
    v8::Context::Scope scope(sub_context);
    stale_resolved_promise = RunJS<JSPromise>("Promise.resolve()");
    stale_rejected_promise = RunJS<JSPromise>("Promise.reject()");
    stale_handler = RunJS<JSReceiver>(
        "(results, label) => {"
        "  results[label] = true;"
        "}");
  }
  // DetachGlobal() cancells all microtasks associated to the context.
  sub_context->DetachGlobal();
  sub_context.Clear();

  SetGlobalProperty("results", Utils::ToLocal(results));
  SetGlobalProperty("stale_resolved_promise",
                    Utils::ToLocal(Cast<JSReceiver>(stale_resolved_promise)));
  SetGlobalProperty("stale_rejected_promise",
                    Utils::ToLocal(Cast<JSReceiver>(stale_rejected_promise)));
  SetGlobalProperty("stale_handler", Utils::ToLocal(stale_handler));

  // Set valid handlers to stale promises.
  RunJS(
      "stale_resolved_promise.then(() => {"
      "  results['stale_resolved_promise'] = true;"
      "})");
  RunJS(
      "stale_rejected_promise.catch(() => {"
      "  results['stale_rejected_promise'] = true;"
      "})");
  microtask_queue()->RunMicrotasks(isolate());
  EXPECT_TRUE(JSReceiver::HasProperty(isolate(), results,
                                      NameFromChars("stale_resolved_promise"))
                  .FromJust());
  EXPECT_TRUE(JSReceiver::HasProperty(isolate(), results,
                                      NameFromChars("stale_rejected_promise"))
                  .FromJust());

  // Set stale handlers to valid promises.
  RunJS(
      "Promise.resolve("
      "    stale_handler.bind(null, results, 'stale_handler_resolve'))");
  RunJS(
      "Promise.reject("
      "    stale_handler.bind(null, results, 'stale_handler_reject'))");
  microtask_queue()->RunMicrotasks(isolate());
  EXPECT_FALSE(JSReceiver::HasProperty(isolate(), results,
                                       NameFromChars("stale_handler_resolve"))
                   .FromJust());
  EXPECT_FALSE(JSReceiver::HasProperty(isolate(), results,
                                       NameFromChars("stale_handler_reject"))
                   .FromJust());
}

TEST_P(MicrotaskQueueTest, DetachGlobal_Chain) {
  Handle<JSPromise> stale_rejected_promise;

  Local<v8::Context> sub_context = v8::Context::New(v8_isolate());
  {
    v8::Context::Scope scope(sub_context);
    stale_rejected_promise = RunJS<JSPromise>("Promise.reject()");
  }
  sub_context->DetachGlobal();
  sub_context.Clear();

  SetGlobalProperty("stale_rejected_promise",
                    Utils::ToLocal(Cast<JSReceiver>(stale_rejected_promise)));
  Handle<JSArray> result = RunJS<JSArray>(
      "let result = [false];"
      "stale_rejected_promise"
      "  .then(() => {})"
      "  .catch(() => {"
      "    result[0] = true;"
      "  });"
      "result");
  microtask_queue()->RunMicrotasks(isolate());
  EXPECT_TRUE(
      IsTrue(*Object::GetElement(isolate(), result, 0).ToHandleChecked()));
}

TEST_P(MicrotaskQueueTest, DetachGlobal_InactiveHandler) {
  Local<v8::Context> sub_context = v8::Context::New(v8_isolate());
  Utils::OpenHandle(*sub_context)
      ->native_context()
      ->set_microtask_queue(isolate(), microtask_queue());

  Handle<JSArray> result;
  Handle<JSFunction> stale_handler;
  DirectHandle<JSPromise> stale_promise;
  {
    v8::Context::Scope scope(sub_context);
    result = RunJS<JSArray>("var result = [false, false]; result");
    stale_handler = RunJS<JSFunction>("() => { result[0] = true; }");
    stale_promise = RunJS<JSPromise>(
        "var stale_promise = new Promise(()=>{});"
        "stale_promise");
    RunJS("stale_promise.then(() => { result [1] = true; });");
  }
  sub_context->DetachGlobal();
  sub_context.Clear();

  // The context of |stale_handler| and |stale_promise| is detached at this
  // point.
  // Ensure that resolution handling for |stale_handler| is cancelled without
  // crash. Also, the resolution of |stale_promise| is also cancelled.

  SetGlobalProperty("stale_handler", Utils::ToLocal(stale_handler));
  RunJS("%EnqueueMicrotask(stale_handler)");

  v8_isolate()->EnqueueMicrotask(Utils::ToLocal(stale_handler));

  JSPromise::Fulfill(
      stale_promise,
      handle(ReadOnlyRoots(isolate()).undefined_value(), isolate()));

  microtask_queue()->RunMicrotasks(isolate());
  EXPECT_TRUE(
      IsFalse(*Object::GetElement(isolate(), result, 0).ToHandleChecked()));
  EXPECT_TRUE(
      IsFalse(*Object::GetElement(isolate(), result, 1).ToHandleChecked()));
}

TEST_P(MicrotaskQueueTest, MicrotasksScope) {
  ASSERT_NE(isolate()->default_microtask_queue(), microtask_queue());
  microtask_queue()->set_microtasks_policy(MicrotasksPolicy::kScoped);

  bool ran = false;
  {
    MicrotasksScope scope(v8_isolate(), microtask_queue(),
                          MicrotasksScope::kRunMicrotasks);
    microtask_queue()->EnqueueMicrotask(*NewMicrotask([&ran]() {
      EXPECT_FALSE(ran);
      ran = true;
    }));
  }
  EXPECT_TRUE(ran);
}

INSTANTIATE_TEST_SUITE_P(
    , MicrotaskQueueTest, ::testing::Values(false, true),
    [](const ::testing::TestParamInfo<MicrotaskQueueTest::ParamType>& info) {
      return info.param ? "runtime" : "builtin";
    });

}  // namespace internal
}  // namespace v8

"""

```