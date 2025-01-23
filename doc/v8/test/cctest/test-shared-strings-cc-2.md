Response:
The user wants me to analyze a C++ source code file related to V8's shared strings functionality. I need to understand the code's purpose, check if it could be a Torque file (based on file extension), relate it to JavaScript if applicable, provide logic reasoning with examples, discuss common programming errors, and summarize its functionality.

**Plan:**

1. **Analyze the C++ Code:** Read through the provided code snippets, focusing on the test names and the operations performed within each test. Identify the core functionality being tested.
2. **Check for Torque:** Verify if the filename ends with `.tq`.
3. **Relate to JavaScript:** Determine if the tested functionalities directly correspond to JavaScript features. If so, provide illustrative JavaScript examples.
4. **Logic Reasoning:**  For specific code sections, especially those involving concurrent operations or GC, devise hypothetical inputs and expected outputs.
5. **Common Errors:** Identify potential programming errors that the tests might be preventing or highlighting, and provide examples.
6. **Summarize Functionality:** Condense the findings into a concise summary of the code's purpose.
这是对V8源代码文件 `v8/test/cctest/test-shared-strings.cc` 的第三部分分析。

**功能列举:**

这部分代码主要关注于 V8 中共享字符串的并发外部化、内部化以及与垃圾回收（GC）的交互。具体功能包括：

1. **并发外部化测试 (Concurrent Externalization):**
   - 测试在多个线程并发地将字符串外部化（即将字符串的内容存储在 V8 堆外）到共享字符串表时的行为。
   - 分别测试了使用唯一资源和共享资源的情况。
   - 验证了外部化后字符串及其关联资源的状态，以及 GC 后的清理情况。

2. **并发外部化与已死亡字符串的测试 (Concurrent Externalization with Dead Strings):**
   - 测试当某些字符串在外部化后变为 "死亡" 状态（例如，被替换为空字符串）时，并发外部化的行为。
   - 验证 GC 如何处理这些已死亡字符串的外部资源，以及是否会发生内存泄漏。
   - 测试了在 GC 过程中是否进行字符串状态转换 (`transition_strings_during_gc_with_stack`) 对资源回收的影响。

3. **并发外部化与内部化测试 (Concurrent Externalization and Internalization):**
   - 测试并发地进行字符串外部化和内部化（即将外部化的字符串重新加载到 V8 堆内）时的行为。
   - 分别测试了内部化时命中（字符串已存在）和未命中（字符串不存在）共享字符串表的情况。
   - 验证了在并发操作和 GC 后，字符串的状态（是否为 ThinString，是否内部化，是否外部化）以及关联资源的状态。

4. **共享字符串在全局句柄中的测试 (SharedStringInGlobalHandle):**
   - 测试将共享字符串存储在全局句柄中，并在 GC 后全局句柄是否仍然有效。这验证了共享字符串的生命周期管理。

5. **客户端全局句柄中的共享字符串测试 (SharedStringInClientGlobalHandle):**
   - 测试在不同的 V8 Isolate（客户端 Isolate）中创建共享字符串，并通过全局句柄在主 Isolate 中访问的情况。
   - 验证了在客户端 Isolate 被销毁后，全局句柄是否会被正确释放。

6. **跨客户端页面晋升的 Old-to-Shared 注册测试 (RegisterOldToSharedForPromotedPageFromClient):**
   - 测试当客户端 Isolate 的新生代对象（包含指向共享堆中共享字符串的引用）晋升到老生代时，是否正确地在老生代到共享堆的 remembered set 中注册了该引用。
   - 这对于跨堆垃圾回收至关重要。

7. **增量标记期间客户端页面晋升的 Old-to-Shared 注册测试 (RegisterOldToSharedForPromotedPageFromClientDuringIncrementalMarking):**
   - 与上述类似，但发生在共享堆进行增量标记的过程中，测试 remembered set 的更新是否能正确处理并发的页面晋升。

8. **客户端 Remembered Set 保留共享对象测试 (SharedObjectRetainedByClientRememberedSet):**
   - 测试客户端 Isolate 的 remembered set 是否能正确地保持对共享堆中共享字符串的引用，防止其被不必要的 GC 回收。

9. **回归测试 (Regress1424955):**
   - 这是一个针对特定 Bug 的回归测试，涉及到在客户端 Isolate 正在进行 Full GC 的扫尾阶段时，主 Isolate 发起 Minor GC 的情况，用于确保 V8 的并发 GC 机制的正确性。

10. **保护外部字符串表添加字符串测试 (ProtectExternalStringTableAddString):**
    - 测试在多线程环境下，向外部字符串表中添加字符串时的线程安全性。

**关于文件类型:**

`v8/test/cctest/test-shared-strings.cc` 以 `.cc` 结尾，因此它是一个 **V8 C++ 源代码文件**，而不是 Torque 文件。

**与 Javascript 的关系 (示例):**

共享字符串是 V8 优化内存使用的一种方式，特别是在多个上下文或 Isolate 之间共享相同的字符串字面量时。 虽然 C++ 代码直接操作 V8 的内部结构，但其影响可以在 JavaScript 中观察到。

```javascript
// 在 JavaScript 中创建相同的字符串字面量
const str1 = "foobar";
const str2 = "foobar";

// 在 V8 内部，如果启用了共享字符串表，
// str1 和 str2 可能会指向同一个共享的字符串对象，
// 从而节省内存。

// 外部化可以理解为将字符串的内容移动到堆外，
// 但这对于 JavaScript 开发者通常是透明的。
```

**代码逻辑推理 (假设输入与输出):**

以 `TestConcurrentExternalization` 为例：

**假设输入:**

- 启用共享字符串表 (`v8_flags.shared_string_table = true`).
- 创建 4 个线程 (`kThreads = 4`).
- 创建 4096 个共享的单字节字符串 (`kStrings = 4096`).
- `share_resources` 分别为 `true` 和 `false`（对应 `ConcurrentExternalizationWithSharedResources` 和 `ConcurrentExternalizationWithUniqueResources` 测试）。

**预期输出:**

- 所有线程成功完成外部化操作。
- 在 GC 后，所有字符串的资源都处于预期的状态：如果 `share_resources` 为 `true`，则所有线程共享的资源应该仍然存活；如果 `share_resources` 为 `false`，则每个线程独立的资源也应该存活。
- `CheckStringAndResource` 函数会验证字符串是否被外部化，以及关联的外部资源是否存活。

**用户常见的编程错误 (示例):**

在多线程环境下操作共享资源时，常见的编程错误包括：

1. **数据竞争 (Data Race):** 多个线程同时访问和修改同一个共享资源，可能导致数据不一致。
   ```c++
   // 错误示例：多个线程同时修改同一个外部资源的状态
   // 没有适当的同步机制
   void ConcurrentExternalizationThread::Run() override {
     for (auto* resource : resources_) {
       resource->MarkAsDisposed(); // 多个线程可能同时调用
     }
   }
   ```

2. **死锁 (Deadlock):** 多个线程互相等待对方释放资源，导致所有线程都被阻塞。
   ```c++
   // 假设有两个锁 lockA 和 lockB
   // 线程 1 获取 lockA，尝试获取 lockB
   // 线程 2 获取 lockB，尝试获取 lockA
   // 可能会发生死锁
   ```

3. **资源泄漏 (Resource Leak):** 在外部化字符串后，没有正确地管理外部资源的生命周期，导致资源无法被释放。
   ```c++
   // 错误示例：在字符串被 GC 回收后，没有释放外部资源
   void CheckStringAndResource(...) {
     if (!should_be_alive) {
       // 忘记释放资源
     }
   }
   ```

**功能归纳:**

这部分 `test-shared-strings.cc` 代码主要用于 **测试 V8 引擎在处理共享字符串的并发外部化、内部化以及与垃圾回收机制交互时的正确性和线程安全性**。它涵盖了多种场景，包括资源共享、已死亡字符串的处理、与客户端 Isolate 的交互以及针对特定 Bug 的回归测试，旨在确保 V8 的共享字符串功能能够稳定可靠地工作，并防止潜在的并发问题和内存泄漏。

### 提示词
```
这是目录为v8/test/cctest/test-shared-strings.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-shared-strings.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
ve = 1;
      }
    } else {
      expected_alive = 0;
    }
    CHECK_EQ(alive_resources, expected_alive);
  }
}

}  // namespace

void TestConcurrentExternalization(bool share_resources) {
  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  ExternalResourceFactory resource_factory;
  MultiClientIsolateTest test;

  constexpr int kThreads = 4;
  constexpr int kStrings = 4096;
  constexpr int kLOStrings = 16;

  Isolate* i_isolate = test.i_main_isolate();
  Factory* factory = i_isolate->factory();

  HandleScope scope(i_isolate);

  IndirectHandle<FixedArray> shared_strings = CreateSharedOneByteStrings(
      i_isolate, factory, kStrings - kLOStrings, kLOStrings,
      sizeof(UncachedExternalString), false);

  ParkingSemaphore sema_ready(0);
  ParkingSemaphore sema_execute_start(0);
  ParkingSemaphore sema_execute_complete(0);
  std::vector<std::unique_ptr<ConcurrentExternalizationThread>> threads;
  std::vector<OneByteResource*> shared_resources;

  if (share_resources) {
    CreateExternalResources(i_isolate, shared_strings, shared_resources,
                            resource_factory);
  }

  for (int i = 0; i < kThreads; i++) {
    std::vector<OneByteResource*> local_resources;
    if (share_resources) {
      local_resources = shared_resources;
    } else {
      CreateExternalResources(i_isolate, shared_strings, local_resources,
                              resource_factory);
    }
    auto thread = std::make_unique<ConcurrentExternalizationThread>(
        &test, shared_strings, local_resources, share_resources, &sema_ready,
        &sema_execute_start, &sema_execute_complete);
    CHECK(thread->Start());
    threads.push_back(std::move(thread));
  }

  LocalIsolate* local_isolate = i_isolate->main_thread_local_isolate();
  for (int i = 0; i < kThreads; i++) {
    sema_ready.ParkedWait(local_isolate);
  }
  for (int i = 0; i < kThreads; i++) {
    sema_execute_start.Signal();
  }
  for (int i = 0; i < kThreads; i++) {
    sema_execute_complete.ParkedWait(local_isolate);
  }

  TriggerGCWithTransitions(i_isolate->heap());

  for (int i = 0; i < shared_strings->length(); i++) {
    DirectHandle<String> input_string(Cast<String>(shared_strings->get(i)),
                                      i_isolate);
    Tagged<String> string = *input_string;
    CheckStringAndResource(string, i, true, {}, true, share_resources, threads);
  }

  ParkingThread::ParkedJoinAll(local_isolate, threads);
}

UNINITIALIZED_TEST(ConcurrentExternalizationWithUniqueResources) {
  TestConcurrentExternalization(false);
}

UNINITIALIZED_TEST(ConcurrentExternalizationWithSharedResources) {
  TestConcurrentExternalization(true);
}

void TestConcurrentExternalizationWithDeadStrings(bool share_resources,
                                                  bool transition_with_stack) {
  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  ExternalResourceFactory resource_factory;
  MultiClientIsolateTest test;

  constexpr int kThreads = 4;
  constexpr int kStrings = 12;
  constexpr int kLOStrings = 2;

  Isolate* i_isolate = test.i_main_isolate();
  Factory* factory = i_isolate->factory();

  ManualGCScope manual_gc_scope(i_isolate);
  HandleScope scope(i_isolate);

  IndirectHandle<FixedArray> shared_strings = CreateSharedOneByteStrings(
      i_isolate, factory, kStrings - kLOStrings, kLOStrings,
      sizeof(UncachedExternalString), false);

  ParkingSemaphore sema_ready(0);
  ParkingSemaphore sema_execute_start(0);
  ParkingSemaphore sema_execute_complete(0);
  std::vector<std::unique_ptr<ConcurrentExternalizationThread>> threads;
  std::vector<OneByteResource*> shared_resources;

  if (share_resources) {
    CreateExternalResources(i_isolate, shared_strings, shared_resources,
                            resource_factory);
  }

  for (int i = 0; i < kThreads; i++) {
    std::vector<OneByteResource*> local_resources;
    if (share_resources) {
      local_resources = shared_resources;
    } else {
      CreateExternalResources(i_isolate, shared_strings, local_resources,
                              resource_factory);
    }
    auto thread = std::make_unique<ConcurrentExternalizationThread>(
        &test, shared_strings, local_resources, share_resources, &sema_ready,
        &sema_execute_start, &sema_execute_complete);
    CHECK(thread->Start());
    threads.push_back(std::move(thread));
  }

  LocalIsolate* local_isolate = i_isolate->main_thread_local_isolate();
  for (int i = 0; i < kThreads; i++) {
    sema_ready.ParkedWait(local_isolate);
  }
  for (int i = 0; i < kThreads; i++) {
    sema_execute_start.Signal();
  }
  for (int i = 0; i < kThreads; i++) {
    sema_execute_complete.ParkedWait(local_isolate);
  }

  DirectHandle<String> empty_string(
      ReadOnlyRoots(i_isolate->heap()).empty_string(), i_isolate);
  for (int i = 0; i < shared_strings->length(); i++) {
    DirectHandle<String> input_string(Cast<String>(shared_strings->get(i)),
                                      i_isolate);
    // Patch every third string to empty. The next GC will dispose the external
    // resources.
    if (i % 3 == 0) {
      input_string.PatchValue(*empty_string);
      shared_strings->set(i, *input_string);
    }
  }

  v8_flags.transition_strings_during_gc_with_stack = transition_with_stack;
  i_isolate->heap()->CollectGarbageShared(i_isolate->main_thread_local_heap(),
                                          GarbageCollectionReason::kTesting);

  for (int i = 0; i < shared_strings->length(); i++) {
    DirectHandle<String> input_string(Cast<String>(shared_strings->get(i)),
                                      i_isolate);
    const bool should_be_alive = i % 3 != 0;
    Tagged<String> string = *input_string;
    CheckStringAndResource(string, i, should_be_alive, *empty_string,
                           transition_with_stack, share_resources, threads);
  }

  // If we didn't test transitions during GC with stack, trigger another GC
  // (allowing transitions with stack) to ensure everything is handled
  // correctly.
  if (!transition_with_stack) {
    v8_flags.transition_strings_during_gc_with_stack = true;

    i_isolate->heap()->CollectGarbageShared(i_isolate->main_thread_local_heap(),
                                            GarbageCollectionReason::kTesting);

    for (int i = 0; i < shared_strings->length(); i++) {
      DirectHandle<String> input_string(Cast<String>(shared_strings->get(i)),
                                        i_isolate);
      const bool should_be_alive = i % 3 != 0;
      Tagged<String> string = *input_string;
      CheckStringAndResource(string, i, should_be_alive, *empty_string, true,
                             share_resources, threads);
    }
  }

  ParkingThread::ParkedJoinAll(local_isolate, threads);
}

UNINITIALIZED_TEST(
    ExternalizationWithDeadStringsAndUniqueResourcesTransitionWithStack) {
  TestConcurrentExternalizationWithDeadStrings(false, true);
}

UNINITIALIZED_TEST(
    ExternalizationWithDeadStringsAndSharedResourcesTransitionWithStack) {
  TestConcurrentExternalizationWithDeadStrings(true, true);
}

UNINITIALIZED_TEST(ExternalizationWithDeadStringsAndUniqueResources) {
  TestConcurrentExternalizationWithDeadStrings(false, false);
}

UNINITIALIZED_TEST(ExternalizationWithDeadStringsAndSharedResources) {
  TestConcurrentExternalizationWithDeadStrings(true, false);
}

void TestConcurrentExternalizationAndInternalization(
    TestHitOrMiss hit_or_miss) {
  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  ExternalResourceFactory resource_factory;
  MultiClientIsolateTest test;

  constexpr int kInternalizationThreads = 4;
  constexpr int kExternalizationThreads = 4;
  constexpr int kTotalThreads =
      kInternalizationThreads + kExternalizationThreads;
  constexpr int kStrings = 4096;
  constexpr int kLOStrings = 16;

  Isolate* i_isolate = test.i_main_isolate();
  Factory* factory = i_isolate->factory();

  HandleScope scope(i_isolate);

  IndirectHandle<FixedArray> shared_strings = CreateSharedOneByteStrings(
      i_isolate, factory, kStrings - kLOStrings, kLOStrings,
      sizeof(UncachedExternalString), hit_or_miss == kTestHit);

  ParkingSemaphore sema_ready(0);
  ParkingSemaphore sema_execute_start(0);
  ParkingSemaphore sema_execute_complete(0);
  std::vector<std::unique_ptr<ConcurrentStringThreadBase>> threads;
  for (int i = 0; i < kInternalizationThreads; i++) {
    auto thread = std::make_unique<ConcurrentInternalizationThread>(
        &test, shared_strings, hit_or_miss, &sema_ready, &sema_execute_start,
        &sema_execute_complete);
    CHECK(thread->Start());
    threads.push_back(std::move(thread));
  }
  for (int i = 0; i < kExternalizationThreads; i++) {
    std::vector<OneByteResource*> resources;
    CreateExternalResources(i_isolate, shared_strings, resources,
                            resource_factory);
    auto thread = std::make_unique<ConcurrentExternalizationThread>(
        &test, shared_strings, resources, false, &sema_ready,
        &sema_execute_start, &sema_execute_complete);
    CHECK(thread->Start());
    threads.push_back(std::move(thread));
  }

  LocalIsolate* local_isolate = i_isolate->main_thread_local_isolate();
  for (int i = 0; i < kTotalThreads; i++) {
    sema_ready.ParkedWait(local_isolate);
  }
  for (int i = 0; i < kTotalThreads; i++) {
    sema_execute_start.Signal();
  }
  for (int i = 0; i < kTotalThreads; i++) {
    sema_execute_complete.ParkedWait(local_isolate);
  }

  TriggerGCWithTransitions(i_isolate->heap());

  for (int i = 0; i < shared_strings->length(); i++) {
    DirectHandle<String> input_string(Cast<String>(shared_strings->get(i)),
                                      i_isolate);
    Tagged<String> string = *input_string;
    if (hit_or_miss == kTestHit) {
      CHECK(IsThinString(string));
      string = Cast<ThinString>(string)->actual();
    }
    int alive_resources = 0;
    for (int t = kInternalizationThreads; t < kTotalThreads; t++) {
      ConcurrentExternalizationThread* thread =
          reinterpret_cast<ConcurrentExternalizationThread*>(threads[t].get());
      if (!thread->Resource(i)->IsDisposed()) {
        alive_resources++;
      }
    }

    StringShape shape(string);
    CHECK(shape.IsInternalized());
    // Check at most one external resource is alive.
    // If internalization happens on an external string and we already have an
    // internalized string with the same content, we turn it into a ThinString
    // and dispose the resource.
    CHECK_LE(alive_resources, 1);
    CHECK_EQ(shape.IsExternal(), alive_resources);
    CHECK(string->HasHashCode());
  }

  ParkingThread::ParkedJoinAll(local_isolate, threads);
}

UNINITIALIZED_TEST(ConcurrentExternalizationAndInternalizationMiss) {
  TestConcurrentExternalizationAndInternalization(kTestMiss);
}

UNINITIALIZED_TEST(ConcurrentExternalizationAndInternalizationHit) {
  TestConcurrentExternalizationAndInternalization(kTestHit);
}

UNINITIALIZED_TEST(SharedStringInGlobalHandle) {
  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  MultiClientIsolateTest test;
  Isolate* i_isolate = test.i_main_isolate();
  Factory* factory = i_isolate->factory();

  HandleScope handle_scope(i_isolate);
  Handle<String> shared_string =
      factory->NewStringFromAsciiChecked("foobar", AllocationType::kSharedOld);
  CHECK(HeapLayout::InWritableSharedSpace(*shared_string));
  v8::Local<v8::String> lh_shared_string = Utils::ToLocal(shared_string);
  v8::Global<v8::String> gh_shared_string(test.main_isolate(),
                                          lh_shared_string);
  gh_shared_string.SetWeak();

  heap::InvokeMajorGC(i_isolate->heap());

  CHECK(!gh_shared_string.IsEmpty());
}

class WakeupTask : public CancelableTask {
 public:
  explicit WakeupTask(Isolate* isolate, int& wakeup_counter)
      : CancelableTask(isolate), wakeup_counter_(wakeup_counter) {}

 private:
  // v8::internal::CancelableTask overrides.
  void RunInternal() override { (wakeup_counter_)++; }

  int& wakeup_counter_;
};

class WorkerIsolateThread : public v8::base::Thread {
 public:
  WorkerIsolateThread(const char* name, MultiClientIsolateTest* test)
      : v8::base::Thread(base::Thread::Options(name)), test_(test) {}

  void Run() override {
    v8::Isolate* client = test_->NewClientIsolate();
    Isolate* i_client = reinterpret_cast<Isolate*>(client);
    Factory* factory = i_client->factory();

    v8::Global<v8::String> gh_shared_string;

    {
      v8::Isolate::Scope isolate_scope(client);
      HandleScope handle_scope(i_client);
      Handle<String> shared_string = factory->NewStringFromAsciiChecked(
          "foobar", AllocationType::kSharedOld);
      CHECK(HeapLayout::InWritableSharedSpace(*shared_string));
      v8::Local<v8::String> lh_shared_string = Utils::ToLocal(shared_string);
      gh_shared_string.Reset(test_->main_isolate(), lh_shared_string);
      gh_shared_string.SetWeak();
    }

    {
      // We need to invoke GC without stack, otherwise some objects may survive.
      DisableConservativeStackScanningScopeForTesting no_stack_scanning(
          i_client->heap());
      i_client->heap()->CollectGarbageShared(i_client->main_thread_local_heap(),
                                             GarbageCollectionReason::kTesting);
    }

    CHECK(gh_shared_string.IsEmpty());
    client->Dispose();

    V8::GetCurrentPlatform()
        ->GetForegroundTaskRunner(test_->main_isolate())
        ->PostTask(std::make_unique<WakeupTask>(
            test_->i_main_isolate(), test_->main_isolate_wakeup_counter()));
  }

 private:
  MultiClientIsolateTest* test_;
};

UNINITIALIZED_TEST(SharedStringInClientGlobalHandle) {
  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  MultiClientIsolateTest test;
  ManualGCScope manual_gc_scope(test.i_main_isolate());
  WorkerIsolateThread thread("worker", &test);
  CHECK(thread.Start());

  while (test.main_isolate_wakeup_counter() < 1) {
    v8::platform::PumpMessageLoop(
        i::V8::GetCurrentPlatform(), test.main_isolate(),
        v8::platform::MessageLoopBehavior::kWaitForWork);
  }

  thread.Join();
}

class ClientIsolateThreadForPagePromotions : public v8::base::Thread {
 public:
  // Expects a ManualGCScope to be in scope while `Run()` is executed.
  ClientIsolateThreadForPagePromotions(const char* name,
                                       MultiClientIsolateTest* test,
                                       Handle<String>* shared_string,
                                       const ManualGCScope& witness)
      : v8::base::Thread(base::Thread::Options(name)),
        test_(test),
        shared_string_(shared_string) {}

  void Run() override {
    CHECK(v8_flags.minor_ms);
    v8::Isolate* client = test_->NewClientIsolate();
    Isolate* i_client = reinterpret_cast<Isolate*>(client);
    Factory* factory = i_client->factory();
    Heap* heap = i_client->heap();

    {
      v8::Isolate::Scope isolate_scope(client);
      HandleScope handle_scope(i_client);

      DirectHandle<FixedArray> young_object =
          factory->NewFixedArray(1, AllocationType::kYoung);
      CHECK(HeapLayout::InYoungGeneration(*young_object));
      Address young_object_address = young_object->address();

      DirectHandleVector<FixedArray> handles(i_client);
      // Make the whole page transition from new->old, getting the buffers
      // processed in the sweeper (relying on marking information) instead of
      // processing during newspace evacuation.
      heap::FillCurrentPage(heap->new_space(), &handles);

      CHECK(!heap->Contains(**shared_string_));
      CHECK(heap->SharedHeapContains(**shared_string_));
      young_object->set(0, **shared_string_);

      heap::EmptyNewSpaceUsingGC(heap);
      heap->CompleteSweepingFull();

      // Object should get promoted using page promotion, so address should
      // remain the same.
      CHECK(!HeapLayout::InYoungGeneration(*young_object));
      CHECK(heap->Contains(*young_object));
      CHECK_EQ(young_object_address, young_object->address());

      // Since the GC promoted that string into shared heap, it also needs to
      // create an OLD_TO_SHARED slot.
      ObjectSlot slot = young_object->RawFieldOfFirstElement();
      CHECK(RememberedSet<OLD_TO_SHARED>::Contains(
          MutablePageMetadata::FromHeapObject(*young_object), slot.address()));
    }

    client->Dispose();

    V8::GetCurrentPlatform()
        ->GetForegroundTaskRunner(test_->main_isolate())
        ->PostTask(std::make_unique<WakeupTask>(
            test_->i_main_isolate(), test_->main_isolate_wakeup_counter()));
  }

 private:
  MultiClientIsolateTest* test_;
  Handle<String>* shared_string_;
};

UNINITIALIZED_TEST(RegisterOldToSharedForPromotedPageFromClient) {
  if (v8_flags.single_generation) return;
  if (!v8_flags.minor_ms) return;

  v8_flags.stress_concurrent_allocation = false;  // For SealCurrentObjects.
  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  ManualGCScope manual_gc_scope;
  heap::ManualEvacuationCandidatesSelectionScope
      manual_evacuation_candidate_selection_scope(manual_gc_scope);

  MultiClientIsolateTest test;

  Isolate* i_isolate = test.i_main_isolate();
  Isolate* shared_isolate = i_isolate->shared_space_isolate();
  Heap* shared_heap = shared_isolate->heap();

  HandleScope scope(i_isolate);

  const char raw_one_byte[] = "foo";
  Handle<String> shared_string =
      i_isolate->factory()->NewStringFromAsciiChecked(
          raw_one_byte, AllocationType::kSharedOld);
  CHECK(shared_heap->Contains(*shared_string));

  ClientIsolateThreadForPagePromotions thread("worker", &test, &shared_string,
                                              manual_gc_scope);
  CHECK(thread.Start());

  while (test.main_isolate_wakeup_counter() < 1) {
    v8::platform::PumpMessageLoop(
        i::V8::GetCurrentPlatform(), test.main_isolate(),
        v8::platform::MessageLoopBehavior::kWaitForWork);
  }

  thread.Join();
}

UNINITIALIZED_TEST(
    RegisterOldToSharedForPromotedPageFromClientDuringIncrementalMarking) {
  if (v8_flags.single_generation) return;
  if (!v8_flags.minor_ms) return;

  v8_flags.stress_concurrent_allocation = false;  // For SealCurrentObjects.
  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  ManualGCScope manual_gc_scope;
  heap::ManualEvacuationCandidatesSelectionScope
      manual_evacuation_candidate_selection_scope(manual_gc_scope);
  v8_flags.incremental_marking_task =
      false;  // Prevent the incremental GC from finishing and finalizing in a
              // task.

  MultiClientIsolateTest test;

  Isolate* i_isolate = test.i_main_isolate();
  Isolate* shared_isolate = i_isolate->shared_space_isolate();
  Heap* shared_heap = shared_isolate->heap();

  HandleScope scope(i_isolate);

  const char raw_one_byte[] = "foo";
  Handle<String> shared_string =
      i_isolate->factory()->NewStringFromAsciiChecked(
          raw_one_byte, AllocationType::kSharedOld);
  CHECK(shared_heap->Contains(*shared_string));

  // Start an incremental shared GC such that shared_string resides on an
  // evacuation candidate.
  heap::ForceEvacuationCandidate(PageMetadata::FromHeapObject(*shared_string));
  i::IncrementalMarking* marking = shared_heap->incremental_marking();
  CHECK(marking->IsStopped());
  {
    SafepointScope safepoint_scope(shared_isolate,
                                   kGlobalSafepointForSharedSpaceIsolate);
    shared_heap->tracer()->StartCycle(
        GarbageCollector::MARK_COMPACTOR, GarbageCollectionReason::kTesting,
        "collector cctest", GCTracer::MarkingType::kIncremental);
    marking->Start(GarbageCollector::MARK_COMPACTOR,
                   i::GarbageCollectionReason::kTesting);
  }

  ClientIsolateThreadForPagePromotions thread("worker", &test, &shared_string,
                                              manual_gc_scope);
  CHECK(thread.Start());

  while (test.main_isolate_wakeup_counter() < 1) {
    v8::platform::PumpMessageLoop(
        i::V8::GetCurrentPlatform(), test.main_isolate(),
        v8::platform::MessageLoopBehavior::kWaitForWork);
  }

  thread.Join();
}

class ClientIsolateThreadForRetainingByRememberedSet : public v8::base::Thread {
 public:
  // Expects a ManualGCScope to be in scope while `Run()` is executed.
  ClientIsolateThreadForRetainingByRememberedSet(
      const char* name, MultiClientIsolateTest* test,
      Persistent<v8::String>* weak_ref, const ManualGCScope& witness)
      : v8::base::Thread(base::Thread::Options(name)),
        test_(test),
        weak_ref_(weak_ref) {}

  void Run() override {
    CHECK(v8_flags.minor_ms);
    client_isolate_ = test_->NewClientIsolate();
    Isolate* i_client = reinterpret_cast<Isolate*>(client_isolate_);
    Factory* factory = i_client->factory();
    Heap* heap = i_client->heap();

    {
      v8::Isolate::Scope isolate_scope(client_isolate_);
      HandleScope scope(i_client);

      IndirectHandle<FixedArray> young_object =
          factory->NewFixedArray(1, AllocationType::kYoung);
      CHECK(HeapLayout::InYoungGeneration(*young_object));
      Address young_object_address = young_object->address();

      DirectHandleVector<FixedArray> handles(i_client);
      // Make the whole page transition from new->old, getting the buffers
      // processed in the sweeper (relying on marking information) instead of
      // processing during newspace evacuation.
      heap::FillCurrentPage(heap->new_space(), &handles);

      // Create a new to shared reference.
      CHECK(!weak_ref_->IsEmpty());
      IndirectHandle<String> shared_string =
          Utils::OpenHandle<v8::String, String>(
              weak_ref_->Get(client_isolate_));
      CHECK(!heap->Contains(*shared_string));
      CHECK(heap->SharedHeapContains(*shared_string));
      young_object->set(0, *shared_string);

      heap::EmptyNewSpaceUsingGC(heap);

      // Object should get promoted using page promotion, so address should
      // remain the same.
      CHECK(!HeapLayout::InYoungGeneration(*young_object));
      CHECK(heap->Contains(*young_object));
      CHECK_EQ(young_object_address, young_object->address());

      // GC should still be in progress (unless heap verification is enabled).
      CHECK_IMPLIES(!v8_flags.verify_heap, heap->sweeping_in_progress());

      // Inform main thread that the client is set up and is doing a GC.
      V8::GetCurrentPlatform()
          ->GetForegroundTaskRunner(test_->main_isolate())
          ->PostTask(std::make_unique<WakeupTask>(
              test_->i_main_isolate(), test_->main_isolate_wakeup_counter()));

      // We need to ensure that the shared GC does not scan the stack for this
      // client, otherwise some objects may survive.
      DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);

      // Wait for main thread to do a shared GC.
      while (wakeup_counter_ < 1) {
        v8::platform::PumpMessageLoop(
            i::V8::GetCurrentPlatform(), isolate(),
            v8::platform::MessageLoopBehavior::kWaitForWork);
      }

      // Since the GC promoted that string into shared heap, it also needs to
      // create an OLD_TO_SHARED slot.
      ObjectSlot slot = young_object->RawFieldOfFirstElement();
      CHECK(RememberedSet<OLD_TO_SHARED>::Contains(
          MutablePageMetadata::FromHeapObject(*young_object), slot.address()));
    }

    client_isolate_->Dispose();

    // Inform main thread that client is finished.
    V8::GetCurrentPlatform()
        ->GetForegroundTaskRunner(test_->main_isolate())
        ->PostTask(std::make_unique<WakeupTask>(
            test_->i_main_isolate(), test_->main_isolate_wakeup_counter()));
  }

  v8::Isolate* isolate() const {
    DCHECK_NOT_NULL(client_isolate_);
    return client_isolate_;
  }

  int& wakeup_counter() { return wakeup_counter_; }

 private:
  MultiClientIsolateTest* test_;
  Persistent<v8::String>* weak_ref_;
  v8::Isolate* client_isolate_;
  int wakeup_counter_ = 0;
};

UNINITIALIZED_TEST(SharedObjectRetainedByClientRememberedSet) {
  if (v8_flags.single_generation) return;
  if (!v8_flags.minor_ms) return;

  v8_flags.stress_concurrent_allocation = false;  // For SealCurrentObjects.
  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  ManualGCScope manual_gc_scope;
  heap::ManualEvacuationCandidatesSelectionScope
      manual_evacuation_candidate_selection_scope(manual_gc_scope);

  MultiClientIsolateTest test;

  v8::Isolate* isolate = test.main_isolate();
  Isolate* i_isolate = test.i_main_isolate();
  Isolate* shared_isolate = i_isolate->shared_space_isolate();
  Heap* shared_heap = shared_isolate->heap();

  // We need to invoke GC without stack, otherwise some objects may survive.
  DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      shared_heap);

  // Create two weak references to Strings. One should die, the other should be
  // kept alive by the client isolate.
  Persistent<v8::String> live_weak_ref;
  Persistent<v8::String> dead_weak_ref;
  {
    HandleScope scope(i_isolate);
    const char raw_one_byte[] = "foo";

    Handle<String> live_shared_string =
        i_isolate->factory()->NewStringFromAsciiChecked(
            raw_one_byte, AllocationType::kSharedOld);
    CHECK(shared_heap->Contains(*live_shared_string));
    live_weak_ref.Reset(isolate, Utils::ToLocal(live_shared_string));
    live_weak_ref.SetWeak();

    Handle<String> dead_shared_string =
        i_isolate->factory()->NewStringFromAsciiChecked(
            raw_one_byte, AllocationType::kSharedOld);
    CHECK(shared_heap->Contains(*dead_shared_string));
    dead_weak_ref.Reset(isolate, Utils::ToLocal(dead_shared_string));
    dead_weak_ref.SetWeak();
  }

  ClientIsolateThreadForRetainingByRememberedSet thread(
      "worker", &test, &live_weak_ref, manual_gc_scope);
  CHECK(thread.Start());

  // Wait for client isolate to allocate objects and start a GC.
  while (test.main_isolate_wakeup_counter() < 1) {
    v8::platform::PumpMessageLoop(
        i::V8::GetCurrentPlatform(), test.main_isolate(),
        v8::platform::MessageLoopBehavior::kWaitForWork);
  }

  // Do shared GC. The live weak ref should be kept alive via an OLD_TO_SHARED
  // slot in the client isolate.
  CHECK(!live_weak_ref.IsEmpty());
  CHECK(!dead_weak_ref.IsEmpty());
  heap::CollectSharedGarbage(i_isolate->heap());
  CHECK(!live_weak_ref.IsEmpty());
  CHECK(dead_weak_ref.IsEmpty());

  // Inform client that shared GC is finished.
  auto thread_wakeup_task = std::make_unique<WakeupTask>(
      reinterpret_cast<Isolate*>(thread.isolate()), thread.wakeup_counter());
  V8::GetCurrentPlatform()
      ->GetForegroundTaskRunner(thread.isolate())
      ->PostTask(std::move(thread_wakeup_task));

  while (test.main_isolate_wakeup_counter() < 2) {
    v8::platform::PumpMessageLoop(
        i::V8::GetCurrentPlatform(), test.main_isolate(),
        v8::platform::MessageLoopBehavior::kWaitForWork);
  }

  thread.Join();
}

class Regress1424955ClientIsolateThread : public v8::base::Thread {
 public:
  Regress1424955ClientIsolateThread(const char* name,
                                    MultiClientIsolateTest* test)
      : v8::base::Thread(base::Thread::Options(name)), test_(test) {}

  void Run() override {
    client_isolate_ = test_->NewClientIsolate();
    Isolate* i_client = reinterpret_cast<Isolate*>(client_isolate_);
    Heap* i_client_heap = i_client->heap();
    Factory* factory = i_client->factory();

    {
      // Allocate an object so that there is work for the sweeper. Otherwise,
      // starting a minor GC after a full GC may finalize sweeping since it is
      // out of work.
      v8::Isolate::Scope isolate_scope(client_isolate_);
      HandleScope handle_scope(i_client);
      Handle<FixedArray> array =
          factory->NewFixedArray(64, AllocationType::kOld);
      USE(array);

      // Start sweeping.
      heap::InvokeMajorGC(i_client_heap);
      CHECK(i_client_heap->sweeping_in_progress());

      // Inform the initiator thread it's time to request a global safepoint.
      V8::GetCurrentPlatform()
          ->GetForegroundTaskRunner(test_->main_isolate())
          ->PostTask(std::make_unique<WakeupTask>(
              test_->i_main_isolate(), test_->main_isolate_wakeup_counter()));

      // Wait for the initiator thread to request a global safepoint.
      while (!i_client->shared_space_isolate()
                  ->global_safepoint()
                  ->IsRequestedForTesting()) {
        v8::base::OS::Sleep(v8::base::TimeDelta::FromMilliseconds(1));
      }

      // Start a minor GC. This will cause this client isolate to join the
      // global safepoint. At which point, the initiator isolate will try to
      // finalize sweeping on behalf of this client isolate.
      heap::InvokeMinorGC(i_client_heap);
    }

    // Wait for the initiator isolate to finish the shared GC.
    while (wakeup_counter_ < 1) {
      v8::platform::PumpMessageLoop(
          i::V8::GetCurrentPlatform(), client_isolate_,
          v8::platform::MessageLoopBehavior::kWaitForWork);
    }

    client_isolate_->Dispose();

    V8::GetCurrentPlatform()
        ->GetForegroundTaskRunner(test_->main_isolate())
        ->PostTask(std::make_unique<WakeupTask>(
            test_->i_main_isolate(), test_->main_isolate_wakeup_counter()));
  }

  v8::Isolate* isolate() const {
    DCHECK_NOT_NULL(client_isolate_);
    return client_isolate_;
  }

  int& wakeup_counter() { return wakeup_counter_; }

 private:
  MultiClientIsolateTest* test_;
  v8::Isolate* client_isolate_;
  int wakeup_counter_ = 0;
};

UNINITIALIZED_TEST(Regress1424955) {
  if (v8_flags.single_generation) return;
  // When heap verification is enabled, sweeping is finalized in the atomic
  // pause. This issue requires that sweeping is still in progress after the
  // atomic pause is finished.
  if (v8_flags.verify_heap) return;
  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  ManualGCScope manual_gc_scope;

  MultiClientIsolateTest test;
  Regress1424955ClientIsolateThread thread("worker", &test);
  CHECK(thread.Start());

  // Wait for client thread to start sweeping.
  while (test.main_isolate_wakeup_counter() < 1) {
    v8::platform::PumpMessageLoop(
        i::V8::GetCurrentPlatform(), test.main_isolate(),
        v8::platform::MessageLoopBehavior::kWaitForWork);
  }

  // Client isolate waits for this isolate to request a global safepoint and
  // then triggers a minor GC.
  heap::CollectSharedGarbage(test.i_main_isolate()->heap());
  V8::GetCurrentPlatform()
      ->GetForegroundTaskRunner(thread.isolate())
      ->PostTask(std::make_unique<WakeupTask>(
          reinterpret_cast<Isolate*>(thread.isolate()),
          thread.wakeup_counter()));

  // Wait for client isolate to finish the minor GC and dispose of its isolate.
  while (test.main_isolate_wakeup_counter() < 2) {
    v8::platform::PumpMessageLoop(
        i::V8::GetCurrentPlatform(), test.main_isolate(),
        v8::platform::MessageLoopBehavior::kWaitForWork);
  }

  thread.Join();
}

class ProtectExternalStringTableAddStringClientIsolateThread
    : public v8::base::Thread {
 public:
  ProtectExternalStringTableAddStringClientIsolateThread(
      const char* name, MultiClientIsolateTest* test, v8::Isolate* isolate)
      : v8::base::Thread(base::Thread::Options(name)),
        test_(test),
        isolate_(isolate),
        i_isolate_(reinterpret_cast<Isolate*>(isolate)) {}

  void Run() override {
    const char* text = "worker_external_string";

    {
      v8::Isolate::Scope isolate_scope(isolate_);

      for (int i = 0; i < 1'000; i++) {
        HandleScope scope(i_isolate_);
        DirectHandle<String> string =
            i_isolate_->factory()->NewStringFromAsciiChecked(
                text, AllocationType::kOld);
        CHECK(HeapLayout::InWritableSharedSpace(*string));
        CHECK(!string->IsShared());
        CHECK(
            string->MakeExternal(i_isolate_, new StaticOneByteResource(text)));
        CHECK(IsExternalOneByteString(*string));
      }
    }

    isolate_->Dispose();

    V8::GetCurrentPlatform()
        ->GetForegroundTaskRunner(test_->main_isolate())
        ->PostTask(std::make_unique<WakeupTask>(
            test_->i_main_isolate(), test_->main_isolate_wakeup_counter()));
  }

 private:
  MultiClientIsolateTest* test_;
  v8::Isolate* isolate_;
  Isolate* i_isolate_;
};

UNINITIALIZED_TEST(ProtectExternalStringTableAddString) {
  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  ManualGCScope manual_gc_scope;

  MultiClientIsolateTest test;
  v8::Isolate
```