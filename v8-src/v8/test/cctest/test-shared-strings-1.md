Response: The user wants a summary of the C++ code provided, focusing on its functionality and its relationship with JavaScript.

**Plan:**

1. **Identify the main purpose of the code:** Look for keywords and test names to understand what the code is testing. "shared strings", "externalization", "internalization", "concurrent" are strong indicators.
2. **Summarize the core functionality:** Describe what the tests are doing with shared strings, especially concerning external and internal representations.
3. **Look for connections to JavaScript:** Determine how the concepts being tested in the C++ code relate to JavaScript's string handling.
4. **Provide JavaScript examples:** Illustrate the connection using simple JavaScript code snippets.
这段C++代码文件 `v8/test/cctest/test-shared-strings.cc` 的主要功能是**测试V8引擎中共享字符串 (shared strings) 的相关特性，特别是关于字符串的外部化 (externalization) 和内部化 (internalization) 以及在并发场景下的行为**。

以下是更详细的归纳：

* **共享字符串 (Shared Strings):**  代码测试了在多个Isolate（V8的隔离执行上下文）之间共享字符串的能力。共享字符串存储在特殊的共享堆中，可以减少内存占用，因为相同的字符串在不同的Isolate中只需要存储一份。
* **外部化 (Externalization):**  指的是将字符串的内容存储在V8堆外部的资源中（例如，一个C++对象），而不是直接存储在V8的堆中。这样做可以避免在V8垃圾回收时移动或复制大量的字符串数据，特别是对于很大的字符串。
* **内部化 (Internalization):** 指的是将外部化的字符串重新加载到V8的堆中，使其成为一个普通的V8字符串对象。内部化通常发生在需要访问字符串的具体内容时。
* **并发测试 (Concurrent Testing):**  代码使用了多线程来模拟并发场景，测试在多个线程同时进行字符串的外部化和内部化时，V8引擎的共享字符串机制是否能正确工作，是否存在竞态条件或内存安全问题。
* **垃圾回收 (Garbage Collection):**  测试中频繁地触发垃圾回收，以验证在垃圾回收过程中，共享字符串的外部化和内部化状态能否被正确处理，以及相关的外部资源是否能被正确释放。
* **测试各种场景:** 代码包含了多个测试用例，覆盖了不同的场景，例如：
    * 并发地外部化字符串，并验证最终状态。
    * 并发地外部化字符串，并在部分字符串变为“死亡”状态（例如，被替换为空字符串）后，验证垃圾回收的处理。
    * 并发地进行字符串的外部化和内部化，测试两者之间的交互。
    * 测试共享字符串在全局句柄 (Global Handle) 中的行为。
    * 测试客户端Isolate（与主Isolate共享堆的Isolate）中对共享字符串的操作，例如通过弱引用持有共享字符串。
    * 测试在客户端Isolate中进行垃圾回收时，如何与共享堆中的共享字符串交互。

**与JavaScript的功能关系以及JavaScript示例:**

虽然这些是底层的C++测试，但它们直接关系到JavaScript中字符串的创建和使用，特别是在涉及到内存管理和性能优化方面。

* **JavaScript字符串的内部表示:** 在JavaScript中创建的字符串，在V8引擎的底层实现中，有可能被存储为共享字符串，特别是当在不同的Realm或Context中创建相同的字符串时。
* **外部字符串 (External Strings):** JavaScript中的某些字符串操作可能会导致字符串被外部化。例如，从外部资源（如文件）读取大量文本数据时，V8可能会将其表示为外部字符串以提高效率。

**JavaScript 示例:**

```javascript
// 假设在不同的iframe或者worker中创建相同的字符串
const iframe1 = document.createElement('iframe');
document.body.appendChild(iframe1);
const iframe2 = document.createElement('iframe');
document.body.appendChild(iframe2);

iframe1.contentWindow.postMessage("hello", "*");
iframe2.contentWindow.postMessage("hello", "*");

// V8引擎在底层可能会将 "hello" 存储为共享字符串

// 从外部资源读取数据，可能导致外部字符串的创建
fetch('large_text_file.txt')
  .then(response => response.text())
  .then(text => {
    // 'text' 变量可能在V8底层被表示为外部字符串
    console.log(text.length);
  });

// 在某些情况下，对外部字符串进行操作可能会触发内部化
const externalString = 'large string from external source'; // 假设这是个外部字符串
const substring = externalString.substring(0, 5); // 访问子字符串可能需要内部化
console.log(substring);
```

**总结第2部分的功能:**

这段代码主要侧重于以下几个方面的测试：

1. **并发环境下的外部化和内部化:** 深入测试了在多线程并发访问和修改共享字符串时，外部化和内部化机制的稳定性和正确性，包括资源竞争、内存安全等方面。
2. **共享字符串与垃圾回收的交互:**  详细测试了在垃圾回收过程中，共享字符串的不同状态（包括存活和死亡的字符串）及其关联的外部资源如何被管理和回收，以及是否会产生内存泄漏或其他问题。
3. **客户端Isolate对共享字符串的影响:**  模拟了在多个客户端Isolate与主Isolate共享堆的情况下，客户端Isolate对共享字符串的操作（例如，通过全局句柄持有、在客户端Isolate内部的垃圾回收）如何影响共享字符串的生命周期和状态。
4. **回归测试:** 包含了对特定bug（例如 Regress1424955）的回归测试，确保之前修复的问题不会再次出现。
5. **压力测试:**  部分测试用例使用了较大的循环次数，用于进行压力测试，检测在高负载情况下共享字符串机制的健壮性。

总而言之，这部分代码深入探索了V8引擎中共享字符串机制在复杂并发场景和垃圾回收压力下的行为，确保其稳定性和可靠性。 这对于JavaScript引擎的性能和内存管理至关重要。

Prompt: 
```
这是目录为v8/test/cctest/test-shared-strings.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
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
  v8::Isolate* client = test.NewClientIsolate();
  ProtectExternalStringTableAddStringClientIsolateThread thread("worker", &test,
                                                                client);
  CHECK(thread.Start());
  Isolate* isolate = test.i_main_isolate();
  HandleScope scope(isolate);

  for (int i = 0; i < 1'000; i++) {
    isolate->factory()
        ->NewExternalStringFromOneByte(
            new StaticOneByteResource("main_external_string"))
        .Check();
  }

  // Wait for client isolate to finish the minor GC and dispose of its isolate.
  while (test.main_isolate_wakeup_counter() < 1) {
    v8::platform::PumpMessageLoop(
        i::V8::GetCurrentPlatform(), test.main_isolate(),
        v8::platform::MessageLoopBehavior::kWaitForWork);
  }

  thread.Join();
}

}  // namespace test_shared_strings
}  // namespace internal
}  // namespace v8

#endif  // V8_CAN_CREATE_SHARED_HEAP_BOOL &&
        // !COMPRESS_POINTERS_IN_MULTIPLE_CAGES_BOOL

"""


```