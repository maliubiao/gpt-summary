Response:
Let's break down the thought process for analyzing this C++ unittest file.

**1. Initial Scan for Key Information:**

The first thing I do is quickly skim the file for obvious clues. I look for:

* **File Path and Name:** `v8/test/unittests/execution/microtask-queue-unittest.cc`. This immediately tells me it's a unit test for the `MicrotaskQueue` functionality in V8's execution engine. The "unittest" part is crucial.
* **Includes:** The included headers (`#include ...`) give insights into the classes and concepts being tested. I see `microtask-queue.h`, `v8-function.h`, `objects/...`, `promise-inl.h`, `testing/gtest/include/gtest/gtest.h`. These point towards testing the core microtask queue mechanism, interaction with JavaScript functions and promises, and the use of Google Test for assertions.
* **Namespaces:** `v8::internal`. This indicates it's testing internal implementation details of V8, not the public API.
* **Test Class:** `class MicrotaskQueueTest : public TestWithNativeContextAndFinalizationRegistry, public ::testing::WithParamInterface<bool>`. This confirms it's a Google Test fixture. The `WithParamInterface<bool>` suggests the tests are parameterized, likely to test different scenarios (in this case, "runtime" vs. "builtin" Promise handling).
* **Helper Functions/Classes:** I notice `RunStdFunction`, `WithFinalizationRegistryMixin`, `RecordingVisitor`, `NewMicrotask`. These are likely utility functions to set up the test environment and interact with the `MicrotaskQueue`.
* **`TEST_P` Macros:** These confirm the parameterized tests.
* **Keywords/Concepts:** "Enqueue," "Run," "Buffer Growth," "Instance Chain," "Visit Root," "PromiseHandlerContext," "DetachGlobal," "MicrotasksScope." These are strong indicators of the specific functionalities being tested.

**2. Understanding the Purpose of the Test File:**

Based on the initial scan, the core purpose of this file is to rigorously test the `MicrotaskQueue` class in V8's internal execution engine. This involves verifying its ability to:

* Enqueue and execute microtasks.
* Handle buffer growth correctly.
* Manage multiple `MicrotaskQueue` instances and their linking.
* Integrate with the garbage collection system (root visiting).
* Handle microtasks related to Promises (then/catch).
* Manage microtasks across different JavaScript contexts.
* Deal with detaching contexts and its impact on microtask execution.
* Support scoped microtask execution.

**3. Analyzing Individual Tests (Mental Walkthrough):**

Now I start to look at the individual `TEST_P` blocks. For each test, I try to understand:

* **What is being set up?** (e.g., creating microtasks, multiple contexts, promises)
* **What action is being performed on the `MicrotaskQueue`?** (e.g., `EnqueueMicrotask`, `RunMicrotasks`, `DetachGlobal`)
* **What is being asserted?** (e.g., checking if a microtask ran, the queue size, the order of execution, the context of a microtask)

For example, for `EnqueueAndRun`:

* **Setup:**  A boolean `ran` is initialized to `false`.
* **Action:** A microtask is enqueued that sets `ran` to `true`.
* **Assertions:** It checks the initial queue size and capacity, verifies that `ran` becomes `true` after running microtasks, and checks the queue size again.

For `DetachGlobal_Enqueue`:

* **Setup:**  An empty microtask queue.
* **Action:** Detaches the current context and then tries to enqueue a promise microtask.
* **Assertion:**  Verifies that the queue remains empty after detaching and attempting to enqueue.

**4. Connecting to JavaScript Concepts:**

Because the tests involve Promises and other JavaScript features, I consider how these tests relate to the JavaScript developer's experience. This leads to the "relation to JavaScript functionality" section. I think about the practical implications of microtasks (e.g., order of execution, dealing with asynchronous operations, how promises are handled).

**5. Considering Potential Programming Errors:**

Based on the tested scenarios (especially `DetachGlobal`), I think about common programming errors related to asynchronous JavaScript and how V8's microtask queue helps or could be misused. Detaching contexts and not understanding the lifecycle of microtasks associated with those contexts is a prime example.

**6. Addressing Specific Instructions:**

Finally, I go back to the original prompt and make sure I've addressed all the specific requirements:

* **List functionalities:** This comes directly from analyzing the test names and what they assert.
* **`.tq` check:** A simple check based on the filename.
* **JavaScript examples:**  I need to provide concrete JavaScript code snippets that illustrate the concepts being tested.
* **Code logic reasoning (input/output):**  For some tests, I can make assumptions about the input (e.g., enqueuing a specific number of tasks) and predict the output (e.g., the number of tasks run). This is more applicable to simpler tests.
* **Common programming errors:**  This requires thinking about how the tested functionalities can be misused or misunderstood by developers.

**Self-Correction/Refinement During Analysis:**

* **Initial Misinterpretation:** I might initially focus too much on low-level details of the C++ code. I need to constantly remind myself that this is a *test* file and focus on the *behavior* being tested.
* **Overlooking Connections:** I might miss the connection between a specific test and a common JavaScript pattern. I need to consciously try to bridge that gap.
* **Insufficient Detail:**  My initial description of a test might be too high-level. I need to go back and be more specific about the assertions being made.

By following this systematic approach, I can effectively analyze the C++ unit test file and provide a comprehensive explanation of its functionalities and relevance to JavaScript.
This C++ source code file, `v8/test/unittests/execution/microtask-queue-unittest.cc`, is a **unit test file** for the `MicrotaskQueue` class within the V8 JavaScript engine. Its primary function is to verify the correctness and robustness of the `MicrotaskQueue` implementation.

Here's a breakdown of its functionalities:

**Core Functionalities Tested:**

* **Enqueueing and Running Microtasks:** The tests verify that microtasks can be added to the queue and executed correctly in the order they were enqueued.
* **Microtask Queue Growth:** Tests ensure that the internal buffer of the microtask queue can dynamically grow as more microtasks are added.
* **Microtask Queue Instance Management:** Tests explore how multiple `MicrotaskQueue` instances are linked together in a doubly linked list and how instances are added and removed.
* **Garbage Collection Integration (Root Visiting):** The tests verify that the `MicrotaskQueue` correctly registers its pending microtasks as "roots" for the garbage collector, preventing them from being prematurely collected.
* **Promise Handling:**  A significant portion of the tests focuses on how the `MicrotaskQueue` interacts with Promises, specifically testing the execution of `then` and `catch` callbacks.
* **Context Awareness:** Tests examine how microtasks are associated with specific JavaScript contexts and how context switching affects their execution.
* **Detaching Contexts:**  Tests rigorously check the behavior of the `MicrotaskQueue` when a JavaScript context is detached. This includes ensuring that microtasks associated with detached contexts are correctly cancelled or handled to prevent crashes or unexpected behavior.
* **Microtask Scope:** Tests verify the functionality of `MicrotasksScope`, allowing for explicit control over when microtasks are run.
* **Promise Hooks:** The parameterized tests (using `::testing::WithParamInterface<bool>`) allow testing with and without a custom Promise hook, potentially changing the underlying Promise resolution mechanism (builtin vs. runtime).

**Relation to JavaScript Functionality (with JavaScript examples):**

The `MicrotaskQueue` is a fundamental part of JavaScript's asynchronous execution model. It's the mechanism used to schedule and execute tasks that should run after the current synchronous code has completed but before the event loop proceeds to the next "tick."  This is crucial for Promises, `async/await`, and other asynchronous operations.

Here are some examples of how the tests relate to JavaScript functionality:

* **Promises:**
   ```javascript
   Promise.resolve().then(() => {
     console.log("This will run in a microtask.");
   });
   console.log("This will run first.");
   ```
   The tests like `EnqueueAndRun`, `PromiseHandlerContext`, and many of the `DetachGlobal` tests directly exercise how the `MicrotaskQueue` handles the callbacks associated with `Promise.then` and `Promise.catch`.

* **`async/await` (implicitly):** While not explicitly mentioned as a separate test category, `async/await` is built on top of Promises. The tests for Promise handling indirectly verify aspects of `async/await` behavior as well.

* **Queueing Order:**
   ```javascript
   Promise.resolve().then(() => console.log("Microtask 1"));
   Promise.resolve().then(() => console.log("Microtask 2"));
   ```
   Tests like `EnqueueAndRun` and `BufferGrowth` ensure that microtasks are executed in the order they were added to the queue, as expected by JavaScript developers.

* **Context Isolation:**
   ```javascript
   // In one context:
   let promise = Promise.resolve();

   // In another context:
   promise.then(() => { console.log("This runs in the context of the promise's creation."); });
   ```
   Tests like `PromiseHandlerContext` and the `DetachGlobal` tests explore how the `MicrotaskQueue` manages microtasks when they involve objects or callbacks created in different JavaScript contexts.

**Code Logic Reasoning (with Hypothetical Input and Output):**

Let's take the `EnqueueAndRun` test as an example:

**Hypothetical Input:**

1. An empty `MicrotaskQueue`.
2. A microtask that sets a boolean variable `ran` to `true`.

**Code Logic:**

1. `microtask_queue()->EnqueueMicrotask(*NewMicrotask([this, &ran] { ... }));`  This line adds the microtask to the queue.
2. `microtask_queue()->RunMicrotasks(isolate());` This line executes all the microtasks in the queue.

**Expected Output:**

1. Before enqueueing: `microtask_queue()->size()` is 0.
2. After enqueueing: `microtask_queue()->size()` is 1.
3. After running microtasks: `ran` is `true`, and `microtask_queue()->size()` is 0.
4. During the microtask execution, `microtask_queue()->HasMicrotasksSuppressions()` should be `true` (this is a specific internal detail being checked).

**User-Visible Programming Errors Addressed by These Tests:**

These tests help prevent various common programming errors related to asynchronous JavaScript, especially concerning Promises and context management:

* **Incorrect Execution Order of Promises:**  Without a correctly functioning `MicrotaskQueue`, Promises might not resolve or reject in the expected order, leading to unpredictable application behavior. The tests ensure the FIFO (First-In, First-Out) nature of microtask execution.
* **Memory Leaks due to Unreachable Promises:** If the `MicrotaskQueue` doesn't properly register pending microtasks as GC roots, Promises and their associated data might be garbage collected prematurely, leading to crashes or unexpected behavior. The `VisitRoot` test addresses this.
* **Crashes or Unexpected Behavior when Working with Multiple Contexts:** JavaScript applications can involve multiple execution contexts (e.g., iframes, web workers, or embedded VMs). If the `MicrotaskQueue` doesn't handle context switching and detachment correctly, it could lead to errors when Promises or other asynchronous operations span different contexts. The `PromiseHandlerContext` and `DetachGlobal` tests are crucial for this.
* **Unintended Side Effects After Context Detachment:**  If microtasks associated with a detached context were to still run, they could cause unexpected side effects in other parts of the application. The `DetachGlobal` tests ensure that these microtasks are correctly cancelled.
* **Issues with Thenables from Different Contexts:** The `DetachGlobal_ResolveThenableForeignThen` test specifically addresses a scenario where a Promise interacts with a "thenable" (an object with a `then` method) that originates from a different JavaScript context. This is a more nuanced scenario that could lead to errors if not handled correctly.

**In summary, `v8/test/unittests/execution/microtask-queue-unittest.cc` is a vital component of V8's testing infrastructure, ensuring the reliable and predictable behavior of JavaScript's asynchronous execution model by thoroughly testing the internal workings of the `MicrotaskQueue`.**

Regarding your specific question about the `.tq` extension:

> 如果v8/test/unittests/execution/microtask-queue-unittest.cc以.tq结尾，那它是个v8 torque源代码

**No, if the file ended with `.tq`, it would indeed be a V8 Torque source code file.** Torque is V8's internal language for implementing built-in functions. Since the file ends in `.cc`, it's a standard C++ source file containing unit tests.

### 提示词
```
这是目录为v8/test/unittests/execution/microtask-queue-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/execution/microtask-queue-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
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
```