Response: The user wants a summary of the C++ code in `v8/test/cctest/heap/test-heap.cc`, specifically the fourth part of a five-part file. The summary should describe the functionality of this code and, if relevant, provide JavaScript examples to illustrate the connection to JavaScript.

Here's a breakdown of how to approach this:

1. **Skim the code:** Quickly read through the code to identify the main categories of tests. Look for `TEST` and `HEAP_TEST` macros which indicate individual test cases. Pay attention to the names of the tests, as they often hint at the functionality being tested.

2. **Group related tests:**  Organize the tests based on the heap feature or functionality they are testing. For example, tests related to GC (major/minor), allocation counters, weak references, stack traces, memory pressure, etc.

3. **Summarize each group:** For each group of related tests, write a concise description of the functionality being exercised. Focus on what the tests are verifying about the V8 heap.

4. **Identify JavaScript connections:** Look for code that uses `CompileRun` to execute JavaScript code within the C++ tests. This indicates a direct relationship between the C++ heap functionality and how it affects JavaScript behavior.

5. **Provide JavaScript examples:** For the tests that involve running JavaScript, create simple JavaScript code snippets that demonstrate the functionality being tested. The examples should be clear and directly related to the C++ test's purpose.

6. **Review and refine:**  Check the summary for clarity, accuracy, and completeness. Ensure that the JavaScript examples accurately reflect the C++ test functionality. Since this is part 4 of 5, make sure the summary is specific to this section and doesn't overlap significantly with what might be in other parts.
这是 `v8/test/cctest/heap/test-heap.cc` 源代码文件的第 4 部分，它主要包含了一系列 C++ 单元测试，用于测试 V8 引擎的堆管理功能。  这些测试覆盖了堆的各种方面，包括垃圾回收（GC）、内存分配、弱引用、堆快照、堆迭代器以及与 JavaScript 交互相关的行为。

以下是这部分代码功能的归纳：

**核心功能测试：**

* **弱引用和垃圾回收 (Weak References and GC):** 测试了弱引用在垃圾回收过程中的行为。例如，`TEST(Regress442710)` 和 `TEST(Regress3877)` 验证了在特定场景下，垃圾回收是否正确地清除了不再需要的弱引用。
* **堆快照 (Heap Snapshot):** `HEAP_TEST(NumberStringCacheSize)` 检查了堆快照中数字到字符串缓存的大小是否符合预期。
* **保留 Map (Retained Maps):** `TEST(MapRetaining)` 和 `TEST(RetainedMapsCleanup)` 测试了在增量标记期间，Map 对象是否能够被正确地保留和清理。这涉及到 V8 的优化策略，以避免在 GC 期间重新创建频繁使用的 Map 对象。
* **堆栈跟踪预处理 (Preprocess StackTrace):** `TEST(PreprocessStackTrace)` 验证了在垃圾回收后，堆栈跟踪信息是否仍然可用，并且某些对象（如 InstructionStream）是否被正确处理。
* **内存分配计数器 (Allocation Counters):** `TEST(NewSpaceAllocationCounter)` 和 `TEST(OldSpaceAllocationCounter)` 测试了新老生代空间的内存分配计数器是否正确地跟踪内存分配。
* **消息对象泄漏 (Message Object Leak):** `TEST(MessageObjectLeak)` 旨在检测在异常处理过程中是否存在消息对象的内存泄漏。
* **共享函数信息 (Shared Function Info):** `TEST(CanonicalSharedFunctionInfo)` 测试了共享函数信息在代码移除和垃圾回收后的规范性，确保相同定义的函数共享相同的内部表示。
* **脚本迭代器 (Script Iterator):** `TEST(ScriptIterator)` 验证了可以通过迭代器正确地遍历堆中的所有脚本对象。
* **ByteArray 分配 (ByteArray Allocation):** `HEAP_TEST(Regress587004)` 和 `HEAP_TEST(Regress589413)` 测试了在特定条件下 ByteArray 的分配和垃圾回收行为，特别是与大对象堆和增量标记的交互。
* **FixedArray 的 RightTrim 操作 (RightTrim FixedArray):** `TEST(Regress598319)`, `TEST(Regress609761)`, 和 `TEST(LiveBytes)` 以及后续的 `TEST(ContinuousRightTrimFixedArrayInBlackArea)` 和 `TEST(RightTrimFixedArrayWithBlackAllocatedPages)` 测试了对 FixedArray 进行缩减操作 (`RightTrim`) 的正确性，尤其是在增量标记和黑分配页面的情况下。
* **内存压力通知 (Memory Pressure Notification):** `TEST(Regress618958)` 测试了 V8 如何响应内存压力通知并触发垃圾回收。
* **新生代大对象 (Young Generation Large Objects):** `TEST(YoungGenerationLargeObjectAllocationScavenge)`、`TEST(YoungGenerationLargeObjectAllocationMarkCompact)` 和 `TEST(YoungGenerationLargeObjectAllocationReleaseScavenger)` 测试了新生代大对象的分配和在 Minor GC 和 Major GC 中的晋升行为。
* **未提交的 Large Object 内存 (Uncommit Unused Large Object Memory):** `TEST(UncommitUnusedLargeObjectMemory)` 验证了 V8 是否能够回收 Large Object 中未使用的已提交内存。
* **Remembered Set 测试 (Remembered Set Tests):**  `TEST(RememberedSet_InsertOnWriteBarrier)`、`TEST(RememberedSet_InsertInLargePage)`、`TEST(RememberedSet_RemoveStaleOnScavenge)`、`TEST(RememberedSet_OldToOld)` 和 `TEST(RememberedSetRemoveRange)` 测试了 Remembered Set 的功能，Remembered Set 用于跟踪跨代指针，以优化垃圾回收。
* **增量标记相关测试 (Incremental Marking Related Tests):**  大量的测试都涉及到增量标记，例如 `HEAP_TEST(Regress670675)`, `HEAP_TEST(RegressMissingWriteBarrierInAllocate)`, `HEAP_TEST(MarkCompactEpochCounter)` 等，验证了在增量标记期间的各种堆操作的正确性。
* **内存溢出测试 (Out Of Memory Tests):** `UNINITIALIZED_TEST(OutOfMemory)`, `UNINITIALIZED_TEST(OutOfMemoryIneffectiveGC)`, 和 `UNINITIALIZED_TEST(OutOfMemoryIneffectiveGCRunningJS)` 测试了在内存不足情况下的 V8 行为，包括 OOM 回调和对无效 GC 的检测。
* **Scavenger 相关测试 (Scavenger Related Tests):** `HEAP_TEST(Regress779503)` 确保 Scavenger（新生代垃圾回收器）不会在处理页面的同时扫描该页面，以避免内存损坏。
* **Heap Limit 相关测试 (Heap Limit Related Tests):** `UNINITIALIZED_TEST(OutOfMemorySmallObjects)` 和 `UNINITIALIZED_TEST(OutOfMemoryLargeObjects)` 测试了当达到堆限制时 V8 的行为，并验证了相关的回调机制。

**与 JavaScript 的关系和示例：**

很多测试都通过 `CompileRun()` 函数执行 JavaScript 代码来触发或验证堆的行为。以下是一些示例说明：

1. **弱引用 (`TEST(Regress442710)`)：**
   ```javascript
   let weak_map = new WeakMap();
   let key = {};
   weak_map.set(key, 1);
   // 在 C++ 代码中会模拟增量标记和 GC
   ```
   这个测试在 JavaScript 中创建了一个 `WeakMap`，并在 C++ 代码中模拟 GC，验证 `WeakMap` 的条目是否在键不再可达时被正确清理。

2. **Map 保留 (`TEST(MapRetaining)`)：**
   ```javascript
   function createObject() {
     return { x: 10 };
   }
   // C++ 代码会创建一个 NativeContext 并关联 retained maps
   let obj = createObject();
   // C++ 代码会模拟 GC，检查 obj 的 Map 是否被保留
   ```
   这个测试创建了一个 JavaScript 对象，C++ 代码会检查在 GC 过程中，该对象的 Map 是否被保留，这是 V8 为了优化性能所做的。

3. **堆栈跟踪 (`TEST(PreprocessStackTrace)`)：**
   ```javascript
   try {
     throw new Error();
   } catch (e) {
     console.log(e.stack);
   }
   // C++ 代码会获取堆栈信息并进行检查
   ```
   这个测试在 JavaScript 中抛出一个错误，然后在 C++ 代码中检查捕获到的异常的堆栈跟踪信息，验证其在 GC 后的完整性。

4. **共享函数信息 (`TEST(CanonicalSharedFunctionInfo)`)：**
   ```javascript
   function f() { return function g() {}; }
   var g1 = f();
   // C++ 代码会移除 f 的代码并进行 GC
   var g2 = f();
   // C++ 代码会检查 g1 和 g2 的共享函数信息是否相同
   ```
   这个测试验证了即使在函数代码被移除并进行 GC 后，通过相同方式创建的内部函数仍然共享相同的共享函数信息。

**总结:**

总的来说，这部分代码是一个深入的 V8 堆管理功能测试套件。它通过 C++ 代码直接操作堆的内部结构，并结合执行 JavaScript 代码来验证各种 GC 场景、内存分配策略、以及与 JavaScript 对象模型相关的行为是否符合预期。这些测试对于确保 V8 引擎的稳定性和性能至关重要。

### 提示词
```
这是目录为v8/test/cctest/heap/test-heap.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```
mentally mark the backing store.
  DirectHandle<JSReceiver> obj =
      v8::Utils::OpenDirectHandle(*v8::Local<v8::Object>::Cast(result));
  DirectHandle<JSWeakCollection> weak_map(Cast<JSWeakCollection>(*obj),
                                          isolate);
  SimulateIncrementalMarking(heap);
  // Stash the backing store in a handle.
  DirectHandle<Object> save(weak_map->table(), isolate);
  // The following line will update the backing store.
  CompileRun(
      "for (var i = 0; i < 50; i++) {"
      "  weak_map.set(future_keys[i], i);"
      "}");
  heap::InvokeMajorGC(heap);
}

TEST(Regress442710) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();

  HandleScope sc(isolate);
  Handle<JSGlobalObject> global(CcTest::i_isolate()->context()->global_object(),
                                isolate);
  Handle<JSArray> array = factory->NewJSArray(2);

  Handle<String> name = factory->InternalizeUtf8String("testArray");
  Object::SetProperty(isolate, global, name, array).Check();
  CompileRun("testArray[0] = 1; testArray[1] = 2; testArray.shift();");
  heap::InvokeMajorGC(CcTest::heap());
}

HEAP_TEST(NumberStringCacheSize) {
  // Test that the number-string cache has not been resized in the snapshot.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  if (!isolate->snapshot_available()) return;
  Heap* heap = isolate->heap();
  CHECK_EQ(Heap::kInitialNumberStringCacheSize * 2,
           heap->number_string_cache()->length());
}

TEST(Regress3877) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  Heap* heap = isolate->heap();
  HandleScope scope(isolate);
  CompileRun("function cls() { this.x = 10; }");
  DirectHandle<WeakFixedArray> weak_prototype_holder =
      factory->NewWeakFixedArray(1);
  {
    HandleScope inner_scope(isolate);
    v8::Local<v8::Value> result = CompileRun("cls.prototype");
    DirectHandle<JSReceiver> proto =
        v8::Utils::OpenDirectHandle(*v8::Local<v8::Object>::Cast(result));
    weak_prototype_holder->set(0, MakeWeak(*proto));
  }
  CHECK(!weak_prototype_holder->get(0).IsCleared());
  CompileRun(
      "var a = { };"
      "a.x = new cls();"
      "cls.prototype = null;");
  for (int i = 0; i < 4; i++) {
    heap::InvokeMajorGC(heap);
  }
  // The map of a.x keeps prototype alive
  CHECK(!weak_prototype_holder->get(0).IsCleared());
  // Detach the map (by promoting it to a prototype).
  CompileRun("var b = {}; b.__proto__ = a.x");
  // Change the map of a.x and make the previous map garbage collectable.
  CompileRun("a.x.__proto__ = {};");
  for (int i = 0; i < 4; i++) {
    // We need to invoke GC without stack, otherwise some objects may not be
    // reclaimed because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMajorGC(heap);
  }
  CHECK(weak_prototype_holder->get(0).IsCleared());
}

Handle<WeakFixedArray> AddRetainedMap(Isolate* isolate,
                                      DirectHandle<NativeContext> context) {
  HandleScope inner_scope(isolate);
  DirectHandle<Map> map = Map::Create(isolate, 1);
  v8::Local<v8::Value> result =
      CompileRun("(function () { return {x : 10}; })();");
  Handle<JSReceiver> proto =
      v8::Utils::OpenHandle(*v8::Local<v8::Object>::Cast(result));
  Map::SetPrototype(isolate, map, proto);
  GlobalHandleVector<Map> maps(isolate->heap());
  maps.Push(*map);
  isolate->heap()->AddRetainedMaps(context, std::move(maps));
  Handle<WeakFixedArray> array = isolate->factory()->NewWeakFixedArray(1);
  array->set(0, MakeWeak(*map));
  return inner_scope.CloseAndEscape(array);
}

void CheckMapRetainingFor(int n) {
  v8_flags.retain_maps_for_n_gc = n;
  v8::Isolate* isolate = CcTest::isolate();
  Isolate* i_isolate = CcTest::i_isolate();
  Heap* heap = i_isolate->heap();

  IndirectHandle<NativeContext> native_context;
  // This global is used to visit the object's constructor alive when starting
  // incremental marking. The native context keeps the constructor alive. The
  // constructor needs to be alive to retain the map.
  v8::Global<v8::Context> global_ctxt;

  {
    v8::Local<v8::Context> ctx = v8::Context::New(isolate);
    IndirectHandle<Context> context = Utils::OpenIndirectHandle(*ctx);
    CHECK(IsNativeContext(*context));
    native_context = Cast<NativeContext>(context);
    global_ctxt.Reset(isolate, ctx);
    ctx->Enter();
  }

  IndirectHandle<WeakFixedArray> array_with_map =
      AddRetainedMap(i_isolate, native_context);
  CHECK(array_with_map->get(0).IsWeak());
  for (int i = 0; i < n; i++) {
    heap::SimulateIncrementalMarking(heap);
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMajorGC(heap);
  }
  CHECK(array_with_map->get(0).IsWeak());
  {
    heap::SimulateIncrementalMarking(heap);
    // In this test, we need to invoke GC without stack, otherwise some objects
    // may not be reclaimed because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMajorGC(heap);
  }
  CHECK(array_with_map->get(0).IsCleared());

  global_ctxt.Get(isolate)->Exit();
}

TEST(MapRetaining) {
  if (!v8_flags.incremental_marking) return;
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  CheckMapRetainingFor(v8_flags.retain_maps_for_n_gc);
  CheckMapRetainingFor(0);
  CheckMapRetainingFor(1);
  CheckMapRetainingFor(7);
}

TEST(RetainedMapsCleanup) {
  if (!v8_flags.incremental_marking) return;
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  v8::Local<v8::Context> ctx = v8::Context::New(CcTest::isolate());
  Handle<Context> context = Utils::OpenHandle(*ctx);
  CHECK(IsNativeContext(*context));
  DirectHandle<NativeContext> native_context = Cast<NativeContext>(context);

  ctx->Enter();
  DirectHandle<WeakFixedArray> array_with_map =
      AddRetainedMap(isolate, native_context);
  CHECK(array_with_map->get(0).IsWeak());
  heap->NotifyContextDisposed(true);
  heap::InvokeMajorGC(heap);
  ctx->Exit();

  CHECK_EQ(ReadOnlyRoots(heap).empty_weak_array_list(),
           native_context->retained_maps());
}

TEST(PreprocessStackTrace) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  v8::TryCatch try_catch(CcTest::isolate());
  CompileRun("throw new Error();");
  CHECK(try_catch.HasCaught());
  Isolate* isolate = CcTest::i_isolate();
  Handle<JSAny> exception =
      Cast<JSAny>(v8::Utils::OpenHandle(*try_catch.Exception()));
  Handle<Name> key = isolate->factory()->error_stack_symbol();
  Handle<JSAny> stack_trace = Cast<JSAny>(
      Object::GetProperty(isolate, exception, key).ToHandleChecked());
  DirectHandle<Object> code =
      Object::GetElement(isolate, stack_trace, 3).ToHandleChecked();
  CHECK(IsInstructionStream(*code));

  heap::InvokeMemoryReducingMajorGCs(CcTest::heap());

  DirectHandle<Object> pos =
      Object::GetElement(isolate, stack_trace, 3).ToHandleChecked();
  CHECK(IsSmi(*pos));

  DirectHandle<FixedArray> frame_array = Cast<FixedArray>(stack_trace);
  int array_length = frame_array->length();
  for (int i = 0; i < array_length; i++) {
    DirectHandle<Object> element =
        Object::GetElement(isolate, stack_trace, i).ToHandleChecked();
    CHECK(!IsInstructionStream(*element));
  }
}

void AllocateInSpace(Isolate* isolate, size_t bytes, AllocationSpace space) {
  CHECK_LE(OFFSET_OF_DATA_START(FixedArray), bytes);
  CHECK(IsAligned(bytes, kTaggedSize));
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);
  AlwaysAllocateScopeForTesting always_allocate(isolate->heap());
  int elements = static_cast<int>((bytes - OFFSET_OF_DATA_START(FixedArray)) /
                                  kTaggedSize);
  DirectHandle<FixedArray> array = factory->NewFixedArray(
      elements,
      space == NEW_SPACE ? AllocationType::kYoung : AllocationType::kOld);
  CHECK((space == NEW_SPACE) == HeapLayout::InYoungGeneration(*array));
  CHECK_EQ(bytes, static_cast<size_t>(array->Size()));
}

TEST(NewSpaceAllocationCounter) {
  if (v8_flags.single_generation) return;
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  heap->FreeMainThreadLinearAllocationAreas();
  size_t counter1 = heap->NewSpaceAllocationCounter();
  heap::EmptyNewSpaceUsingGC(heap);  // Ensure new space is empty.
  const size_t kSize = 1024;
  AllocateInSpace(isolate, kSize, NEW_SPACE);
  heap->FreeMainThreadLinearAllocationAreas();
  size_t counter2 = heap->NewSpaceAllocationCounter();
  CHECK_EQ(kSize, counter2 - counter1);
  heap::InvokeMinorGC(heap);
  size_t counter3 = heap->NewSpaceAllocationCounter();
  CHECK_EQ(0U, counter3 - counter2);
  // Test counter overflow.
  heap->FreeMainThreadLinearAllocationAreas();
  size_t max_counter = static_cast<size_t>(-1);
  heap->SetNewSpaceAllocationCounterForTesting(max_counter - 10 * kSize);
  size_t start = heap->NewSpaceAllocationCounter();
  for (int i = 0; i < 20; i++) {
    AllocateInSpace(isolate, kSize, NEW_SPACE);
    heap->FreeMainThreadLinearAllocationAreas();
    size_t counter = heap->NewSpaceAllocationCounter();
    CHECK_EQ(kSize, counter - start);
    start = counter;
  }
}

TEST(OldSpaceAllocationCounter) {
  // Using the string forwarding table can free allocations during sweeping, due
  // to ThinString trimming, thus failing this test.
  // The flag (and handling of the forwarding table/ThinString transitions in
  // young gen) is only temporary so we just skip this test for now.
  if (v8_flags.always_use_string_forwarding_table) return;
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  // Disable LAB, such that calculations with SizeOfObjects() and object size
  // are correct.
  heap->DisableInlineAllocation();
  heap::EmptyNewSpaceUsingGC(heap);
  size_t counter1 = heap->OldGenerationAllocationCounter();
  const size_t kSize = 1024;
  AllocateInSpace(isolate, kSize, OLD_SPACE);
  size_t counter2 = heap->OldGenerationAllocationCounter();
  // TODO(ulan): replace all CHECK_LE with CHECK_EQ after v8:4148 is fixed.
  CHECK_LE(kSize, counter2 - counter1);
  heap::InvokeMinorGC(heap);
  size_t counter3 = heap->OldGenerationAllocationCounter();
  CHECK_EQ(0u, counter3 - counter2);
  AllocateInSpace(isolate, kSize, OLD_SPACE);
  heap::InvokeMajorGC(heap);
  size_t counter4 = heap->OldGenerationAllocationCounter();
  CHECK_LE(kSize, counter4 - counter3);
  // Test counter overflow.
  size_t max_counter = static_cast<size_t>(-1);
  heap->set_old_generation_allocation_counter_at_last_gc(max_counter -
                                                         10 * kSize);
  size_t start = heap->OldGenerationAllocationCounter();
  for (int i = 0; i < 20; i++) {
    AllocateInSpace(isolate, kSize, OLD_SPACE);
    size_t counter = heap->OldGenerationAllocationCounter();
    CHECK_LE(kSize, counter - start);
    start = counter;
  }
}

static void CheckLeak(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  Isolate* isolate = CcTest::i_isolate();
  Tagged<Object> message(
      *reinterpret_cast<Address*>(isolate->pending_message_address()));
  CHECK(IsTheHole(message, isolate));
}

TEST(MessageObjectLeak) {
  CcTest::InitializeVM();
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> global = v8::ObjectTemplate::New(isolate);
  global->Set(isolate, "check", v8::FunctionTemplate::New(isolate, CheckLeak));
  v8::Local<v8::Context> context = v8::Context::New(isolate, nullptr, global);
  v8::Context::Scope cscope(context);

  const char* test =
      "try {"
      "  throw 'message 1';"
      "} catch (e) {"
      "}"
      "check();"
      "L: try {"
      "  throw 'message 2';"
      "} finally {"
      "  break L;"
      "}"
      "check();";
  CompileRun(test);

  const char* flag = "--turbo-filter=*";
  FlagList::SetFlagsFromString(flag, strlen(flag));
  v8_flags.always_turbofan = true;

  CompileRun(test);
}

static void CheckEqualSharedFunctionInfos(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  Handle<Object> obj1 = v8::Utils::OpenHandle(*info[0]);
  Handle<Object> obj2 = v8::Utils::OpenHandle(*info[1]);
  DirectHandle<JSFunction> fun1 = Cast<JSFunction>(obj1);
  DirectHandle<JSFunction> fun2 = Cast<JSFunction>(obj2);
  CHECK(fun1->shared() == fun2->shared());
}

static void RemoveCodeAndGC(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  Isolate* isolate = CcTest::i_isolate();
  Handle<Object> obj = v8::Utils::OpenHandle(*info[0]);
  DirectHandle<JSFunction> fun = Cast<JSFunction>(obj);
  // Bytecode is code too.
  SharedFunctionInfo::DiscardCompiled(isolate, handle(fun->shared(), isolate));
  fun->UpdateCode(*BUILTIN_CODE(isolate, CompileLazy));
  heap::InvokeMemoryReducingMajorGCs(CcTest::heap());
}

TEST(CanonicalSharedFunctionInfo) {
  CcTest::InitializeVM();
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> global = v8::ObjectTemplate::New(isolate);
  global->Set(
      isolate, "check",
      v8::FunctionTemplate::New(isolate, CheckEqualSharedFunctionInfos));
  global->Set(isolate, "remove",
              v8::FunctionTemplate::New(isolate, RemoveCodeAndGC));
  v8::Local<v8::Context> context = v8::Context::New(isolate, nullptr, global);
  v8::Context::Scope cscope(context);
  CompileRun(
      "function f() { return function g() {}; }"
      "var g1 = f();"
      "remove(f);"
      "var g2 = f();"
      "check(g1, g2);");

  CompileRun(
      "function f() { return (function() { return function g() {}; })(); }"
      "var g1 = f();"
      "remove(f);"
      "var g2 = f();"
      "check(g1, g2);");
}

TEST(ScriptIterator) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = CcTest::heap();
  LocalContext context;

  heap::InvokeMajorGC(heap);

  int script_count = 0;
  {
    HeapObjectIterator it(heap);
    for (Tagged<HeapObject> obj = it.Next(); !obj.is_null(); obj = it.Next()) {
      if (IsScript(obj)) script_count++;
    }
  }

  {
    Script::Iterator iterator(isolate);
    for (Tagged<Script> script = iterator.Next(); !script.is_null();
         script = iterator.Next()) {
      script_count--;
    }
  }

  CHECK_EQ(0, script_count);
}

// This is the same as Factory::NewByteArray, except it doesn't retry on
// allocation failure.
AllocationResult HeapTester::AllocateByteArrayForTest(
    Heap* heap, int length, AllocationType allocation_type) {
  DCHECK(length >= 0 && length <= ByteArray::kMaxLength);
  int size = ByteArray::SizeFor(length);
  Tagged<HeapObject> result;
  {
    AllocationResult allocation = heap->AllocateRaw(size, allocation_type);
    if (!allocation.To(&result)) return allocation;
  }

  result->set_map_after_allocation(heap->isolate(),
                                   ReadOnlyRoots(heap).byte_array_map(),
                                   SKIP_WRITE_BARRIER);
  Cast<ByteArray>(result)->set_length(length);
  return AllocationResult::FromObject(result);
}

bool HeapTester::CodeEnsureLinearAllocationArea(Heap* heap, int size_in_bytes) {
  MainAllocator* allocator = heap->allocator()->code_space_allocator();
  return allocator->EnsureAllocationForTesting(
      size_in_bytes, AllocationAlignment::kTaggedAligned,
      AllocationOrigin::kRuntime);
}

HEAP_TEST(Regress587004) {
  if (v8_flags.single_generation) return;
  ManualGCScope manual_gc_scope;
#ifdef VERIFY_HEAP
  v8_flags.verify_heap = false;
#endif
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Heap* heap = CcTest::heap();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  const int N = (kMaxRegularHeapObjectSize - OFFSET_OF_DATA_START(FixedArray)) /
                kTaggedSize;
  DirectHandle<FixedArray> array =
      factory->NewFixedArray(N, AllocationType::kOld);
  CHECK(heap->old_space()->Contains(*array));
  DirectHandle<Object> number = factory->NewHeapNumber(1.0);
  CHECK(HeapLayout::InYoungGeneration(*number));
  for (int i = 0; i < N; i++) {
    array->set(i, *number);
  }
  heap::InvokeMajorGC(heap);
  heap::SimulateFullSpace(heap->old_space());
  heap->RightTrimArray(*array, 1, N);
  heap->EnsureSweepingCompleted(Heap::SweepingForcedFinalizationMode::kV8Only);
  Tagged<ByteArray> byte_array;
  const int M = 256;
  // Don't allow old space expansion. The test works without this flag too,
  // but becomes very slow.
  heap->set_force_oom(true);
  while (
      AllocateByteArrayForTest(heap, M, AllocationType::kOld).To(&byte_array)) {
    for (int j = 0; j < M; j++) {
      byte_array->set(j, 0x31);
    }
  }
  // Re-enable old space expansion to avoid OOM crash.
  heap->set_force_oom(false);
  heap::InvokeMinorGC(heap);
}

HEAP_TEST(Regress589413) {
  if (!v8_flags.incremental_marking || v8_flags.stress_concurrent_allocation)
    return;
  v8_flags.stress_compaction = true;
  ManualGCScope manual_gc_scope;
  heap::ManualEvacuationCandidatesSelectionScope
      manual_evacuation_candidate_selection_scope(manual_gc_scope);
  v8_flags.parallel_compaction = false;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Heap* heap = CcTest::heap();
  // Get the heap in clean state.
  heap::InvokeMajorGC(heap);
  heap::InvokeMajorGC(heap);
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  // Fill the new space with byte arrays with elements looking like pointers.
  const int M = 256;
  Tagged<ByteArray> byte_array;
  PageMetadata* young_page = nullptr;
  while (AllocateByteArrayForTest(heap, M, AllocationType::kYoung)
             .To(&byte_array)) {
    // Only allocate objects on one young page as a rough estimate on
    // how much memory can be promoted into the old generation.
    // Otherwise we would crash when forcing promotion of all young
    // live objects.
    if (!young_page) young_page = PageMetadata::FromHeapObject(byte_array);
    if (PageMetadata::FromHeapObject(byte_array) != young_page) break;

    for (int j = 0; j < M; j++) {
      byte_array->set(j, 0x31);
    }
    // Add the array in root set.
    handle(byte_array, isolate);
  }
  auto reset_oom = [](void* heap, size_t limit, size_t) -> size_t {
    reinterpret_cast<Heap*>(heap)->set_force_oom(false);
    return limit;
  };
  heap->AddNearHeapLimitCallback(reset_oom, heap);

  {
    // Ensure that incremental marking is not started unexpectedly.
    AlwaysAllocateScopeForTesting always_allocate(isolate->heap());

    // Make sure the byte arrays will be promoted on the next GC.
    heap::InvokeMinorGC(heap);
    // This number is close to large free list category threshold.
    const int N = 0x3EEE;

    std::vector<Tagged<FixedArray>> arrays;
    std::set<PageMetadata*> pages;
    Tagged<FixedArray> array;
    // Fill all pages with fixed arrays.
    heap->set_force_oom(true);
    while (
        AllocateFixedArrayForTest(heap, N, AllocationType::kOld).To(&array)) {
      arrays.push_back(array);
      pages.insert(PageMetadata::FromHeapObject(array));
      // Add the array in root set.
      handle(array, isolate);
    }
    heap->set_force_oom(false);
    size_t initial_pages = pages.size();
    // Expand and fill two pages with fixed array to ensure enough space both
    // the young objects and the evacuation candidate pages.
    while (
        AllocateFixedArrayForTest(heap, N, AllocationType::kOld).To(&array)) {
      arrays.push_back(array);
      pages.insert(PageMetadata::FromHeapObject(array));
      // Add the array in root set.
      handle(array, isolate);
      // Do not expand anymore.
      if (pages.size() - initial_pages == 2) {
        heap->set_force_oom(true);
      }
    }
    // Expand and mark the new page as evacuation candidate.
    heap->set_force_oom(false);
    {
      DirectHandle<HeapObject> ec_obj =
          factory->NewFixedArray(5000, AllocationType::kOld);
      PageMetadata* ec_page = PageMetadata::FromHeapObject(*ec_obj);
      heap::ForceEvacuationCandidate(ec_page);
      // Make all arrays point to evacuation candidate so that
      // slots are recorded for them.
      for (size_t j = 0; j < arrays.size(); j++) {
        array = arrays[j];
        for (int i = 0; i < N; i++) {
          array->set(i, *ec_obj);
        }
      }
    }
    CHECK(heap->incremental_marking()->IsStopped());
    heap::SimulateIncrementalMarking(heap);
    for (size_t j = 0; j < arrays.size(); j++) {
      heap->RightTrimArray(arrays[j], 1, N);
    }
  }

  // Force allocation from the free list.
  heap->set_force_oom(true);
  heap::InvokeMajorGC(heap);
  heap->RemoveNearHeapLimitCallback(reset_oom, 0);
}

TEST(Regress598319) {
  if (!v8_flags.incremental_marking) return;
  ManualGCScope manual_gc_scope;
  // This test ensures that no white objects can cross the progress bar of large
  // objects during incremental marking. It checks this by using Shift() during
  // incremental marking.
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Heap* heap = CcTest::heap();
  Isolate* isolate = heap->isolate();

  // The size of the array should be larger than kProgressBarScanningChunk.
  const int kNumberOfObjects =
      std::max(FixedArray::kMaxRegularLength + 1, 128 * KB);

  struct Arr {
    Arr(Isolate* isolate, int number_of_objects) {
      root = isolate->factory()->NewFixedArray(1, AllocationType::kOld);
      {
        // Temporary scope to avoid getting any other objects into the root set.
        v8::HandleScope new_scope(CcTest::isolate());
        DirectHandle<FixedArray> tmp = isolate->factory()->NewFixedArray(
            number_of_objects, AllocationType::kOld);
        root->set(0, *tmp);
        for (int i = 0; i < get()->length(); i++) {
          tmp = isolate->factory()->NewFixedArray(100, AllocationType::kOld);
          get()->set(i, *tmp);
        }
      }
      global_root.Reset(CcTest::isolate(), Utils::ToLocal(Cast<Object>(root)));
    }

    Tagged<FixedArray> get() { return Cast<FixedArray>(root->get(0)); }

    Handle<FixedArray> root;

    // Store array in global as well to make it part of the root set when
    // starting incremental marking.
    v8::Global<Value> global_root;
  } arr(isolate, kNumberOfObjects);

  CHECK_EQ(arr.get()->length(), kNumberOfObjects);
  CHECK(heap->lo_space()->Contains(arr.get()));
  LargePageMetadata* page = LargePageMetadata::FromHeapObject(arr.get());
  CHECK_NOT_NULL(page);

  // GC to cleanup state
  heap::InvokeMajorGC(heap);
  if (heap->sweeping_in_progress()) {
    heap->EnsureSweepingCompleted(
        Heap::SweepingForcedFinalizationMode::kV8Only);
  }

  CHECK(heap->lo_space()->Contains(arr.get()));
  IncrementalMarking* marking = heap->incremental_marking();
  MarkingState* marking_state = heap->marking_state();
  CHECK(marking_state->IsUnmarked(arr.get()));
  for (int i = 0; i < arr.get()->length(); i++) {
    Tagged<HeapObject> arr_value = Cast<HeapObject>(arr.get()->get(i));
    CHECK(marking_state->IsUnmarked(arr_value));
  }

  // Start incremental marking.
  CHECK(marking->IsMarking() || marking->IsStopped());
  if (marking->IsStopped()) {
    heap->StartIncrementalMarking(i::GCFlag::kNoFlags,
                                  i::GarbageCollectionReason::kTesting);
  }
  CHECK(marking->IsMarking());

  // Check that we have not marked the interesting array during root scanning.
  for (int i = 0; i < arr.get()->length(); i++) {
    Tagged<HeapObject> arr_value = Cast<HeapObject>(arr.get()->get(i));
    CHECK(marking_state->IsUnmarked(arr_value));
  }

  // Now we search for a state where we are in incremental marking and have
  // only partially marked the large object.
  static constexpr auto kSmallStepSize =
      v8::base::TimeDelta::FromMillisecondsD(0.1);
  static constexpr size_t kSmallMaxBytesToMark = 100;
  while (!marking->IsMajorMarkingComplete()) {
    marking->AdvanceForTesting(kSmallStepSize, kSmallMaxBytesToMark);
    MarkingProgressTracker& progress_tracker = page->MarkingProgressTracker();
    if (progress_tracker.IsEnabled() &&
        progress_tracker.GetCurrentChunkForTesting() > 0) {
      CHECK_NE(progress_tracker.GetCurrentChunkForTesting(), arr.get()->Size());
      {
        // Shift by 1, effectively moving one white object across the progress
        // bar, meaning that we will miss marking it.
        v8::HandleScope new_scope(CcTest::isolate());
        Handle<JSArray> js_array = isolate->factory()->NewJSArrayWithElements(
            Handle<FixedArray>(arr.get(), isolate));
        js_array->GetElementsAccessor()->Shift(js_array).Check();
      }
      break;
    }
  }

  IsolateSafepointScope safepoint_scope(heap);
  MarkingBarrier::PublishAll(heap);

  // Finish marking with bigger steps to speed up test.
  static constexpr auto kLargeStepSize =
      v8::base::TimeDelta::FromMilliseconds(1000);
  while (!marking->IsMajorMarkingComplete()) {
    marking->AdvanceForTesting(kLargeStepSize);
  }
  CHECK(marking->IsMajorMarkingComplete());

  // All objects need to be black after marking. If a white object crossed the
  // progress bar, we would fail here.
  for (int i = 0; i < arr.get()->length(); i++) {
    Tagged<HeapObject> arr_value = Cast<HeapObject>(arr.get()->get(i));
    CHECK(HeapLayout::InReadOnlySpace(arr_value) ||
          marking_state->IsMarked(arr_value));
  }
}

Handle<FixedArray> ShrinkArrayAndCheckSize(Heap* heap, int length) {
  // Make sure there is no garbage and the compilation cache is empty.
  for (int i = 0; i < 5; i++) {
    heap::InvokeMajorGC(heap);
  }
  heap->EnsureSweepingCompleted(Heap::SweepingForcedFinalizationMode::kV8Only);
  // Disable LAB, such that calculations with SizeOfObjects() and object size
  // are correct.
  heap->DisableInlineAllocation();
  size_t size_before_allocation = heap->SizeOfObjects();
  Handle<FixedArray> array =
      heap->isolate()->factory()->NewFixedArray(length, AllocationType::kOld);
  size_t size_after_allocation = heap->SizeOfObjects();
  CHECK_EQ(size_after_allocation, size_before_allocation + array->Size());
  array->RightTrim(heap->isolate(), 1);
  size_t size_after_shrinking = heap->SizeOfObjects();
  // Shrinking does not change the space size immediately.
  CHECK_EQ(size_after_allocation, size_after_shrinking);
  // GC and sweeping updates the size to acccount for shrinking.
  heap::InvokeMajorGC(heap);
  heap->EnsureSweepingCompleted(Heap::SweepingForcedFinalizationMode::kV8Only);
  intptr_t size_after_gc = heap->SizeOfObjects();
  CHECK_EQ(size_after_gc, size_before_allocation + array->Size());
  return array;
}

TEST(Regress609761) {
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Heap* heap = CcTest::heap();
  int length = kMaxRegularHeapObjectSize / kTaggedSize + 1;
  DirectHandle<FixedArray> array = ShrinkArrayAndCheckSize(heap, length);
  CHECK(heap->lo_space()->Contains(*array));
}

TEST(LiveBytes) {
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Heap* heap = CcTest::heap();
  DirectHandle<FixedArray> array = ShrinkArrayAndCheckSize(heap, 2000);
  CHECK(heap->old_space()->Contains(*array));
}

TEST(Regress615489) {
  if (!v8_flags.incremental_marking) return;
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Heap* heap = CcTest::heap();
  Isolate* isolate = heap->isolate();
  heap::InvokeMajorGC(heap);

  i::IncrementalMarking* marking = heap->incremental_marking();
  if (heap->sweeping_in_progress()) {
    heap->EnsureSweepingCompleted(
        Heap::SweepingForcedFinalizationMode::kV8Only);
  }
  CHECK(marking->IsMarking() || marking->IsStopped());
  if (marking->IsStopped()) {
    heap->StartIncrementalMarking(i::GCFlag::kNoFlags,
                                  i::GarbageCollectionReason::kTesting);
  }
  CHECK(marking->IsMarking());
  CHECK(marking->black_allocation());
  {
    AlwaysAllocateScopeForTesting always_allocate(heap);
    v8::HandleScope inner(CcTest::isolate());
    isolate->factory()->NewFixedArray(500, AllocationType::kOld)->Size();
  }
  static constexpr auto kStepSize = v8::base::TimeDelta::FromMilliseconds(100);
  while (!marking->IsMajorMarkingComplete()) {
    marking->AdvanceForTesting(kStepSize);
  }
  CHECK(marking->IsMajorMarkingComplete());
  intptr_t size_before = heap->SizeOfObjects();
  heap::InvokeMajorGC(heap);
  intptr_t size_after = heap->SizeOfObjects();
  // Live size does not increase after garbage collection.
  CHECK_LE(size_after, size_before);
}

class StaticOneByteResource : public v8::String::ExternalOneByteStringResource {
 public:
  explicit StaticOneByteResource(const char* data) : data_(data) {}

  ~StaticOneByteResource() override = default;

  const char* data() const override { return data_; }

  size_t length() const override { return strlen(data_); }

 private:
  const char* data_;
};

TEST(Regress631969) {
  if (!v8_flags.incremental_marking || v8_flags.separate_gc_phases) return;
  ManualGCScope manual_gc_scope;
  heap::ManualEvacuationCandidatesSelectionScope
      manual_evacuation_candidate_selection_scope(manual_gc_scope);
  v8_flags.parallel_compaction = false;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Heap* heap = CcTest::heap();
  // Get the heap in clean state.
  heap::InvokeMajorGC(heap);
  heap::InvokeMajorGC(heap);
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  // Allocate two strings in a fresh page and mark the page as evacuation
  // candidate.
  heap::SimulateFullSpace(heap->old_space());
  Handle<String> s1 =
      factory->NewStringFromStaticChars("123456789", AllocationType::kOld);
  Handle<String> s2 =
      factory->NewStringFromStaticChars("01234", AllocationType::kOld);
  heap::ForceEvacuationCandidate(PageMetadata::FromHeapObject(*s1));

  heap::SimulateIncrementalMarking(heap, false);

  // Allocate a cons string and promote it to a fresh page in the old space.
  Handle<String> s3 = factory->NewConsString(s1, s2).ToHandleChecked();
  heap::EmptyNewSpaceUsingGC(heap);

  heap::SimulateIncrementalMarking(heap, false);

  // Finish incremental marking.
  static constexpr auto kStepSize = v8::base::TimeDelta::FromMilliseconds(100);
  IncrementalMarking* marking = heap->incremental_marking();
  while (!marking->IsMajorMarkingComplete()) {
    marking->AdvanceForTesting(kStepSize);
  }

  {
    StaticOneByteResource external_string("12345678901234");
    s3->MakeExternal(isolate, &external_string);
    heap::InvokeMajorGC(heap);
    // This avoids the GC from trying to free stack allocated resources.
    i::Cast<i::ExternalOneByteString>(s3)->SetResource(isolate, nullptr);
  }
}

TEST(ContinuousRightTrimFixedArrayInBlackArea) {
  if (v8_flags.black_allocated_pages) return;
  if (!v8_flags.incremental_marking) return;
  v8_flags.stress_concurrent_allocation = false;  // For SimulateFullSpace.
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Heap* heap = CcTest::heap();
  Isolate* isolate = CcTest::i_isolate();
  heap::InvokeMajorGC(heap);

  i::IncrementalMarking* marking = heap->incremental_marking();
  if (heap->sweeping_in_progress()) {
    heap->EnsureSweepingCompleted(
        Heap::SweepingForcedFinalizationMode::kV8Only);
  }
  CHECK(marking->IsMarking() || marking->IsStopped());
  if (marking->IsStopped()) {
    heap->StartIncrementalMarking(i::GCFlag::kNoFlags,
                                  i::GarbageCollectionReason::kTesting);
  }
  CHECK(marking->IsMarking());
  CHECK(marking->black_allocation());

  // Ensure that we allocate a new page, set up a bump pointer area, and
  // perform the allocation in a black area.
  heap::SimulateFullSpace(heap->old_space());
  isolate->factory()->NewFixedArray(10, AllocationType::kOld);

  // Allocate the fixed array that will be trimmed later.
  DirectHandle<FixedArray> array =
      isolate->factory()->NewFixedArray(100, AllocationType::kOld);
  Address start_address = array->address();
  Address end_address = start_address + array->Size();
  PageMetadata* page = PageMetadata::FromAddress(start_address);
  NonAtomicMarkingState* marking_state = heap->non_atomic_marking_state();
  CHECK(marking_state->IsMarked(*array));
  CHECK(page->marking_bitmap()->AllBitsSetInRange(
      MarkingBitmap::AddressToIndex(start_address),
      MarkingBitmap::LimitAddressToIndex(end_address)));
  CHECK(heap->old_space()->Contains(*array));

  // Trim it once by one word to check that the trimmed area gets unmarked.
  Address previous = end_address - kTaggedSize;
  isolate->heap()->RightTrimArray(*array, 99, 100);

  Tagged<HeapObject> filler = HeapObject::FromAddress(previous);
  CHECK(IsFreeSpaceOrFiller(filler));

  // Trim 10 times by one, two, and three word.
  for (int i = 1; i <= 3; i++) {
    for (int j = 0; j < 10; j++) {
      previous -= kTaggedSize * i;
      int old_capacity = array->capacity();
      int new_capacity = old_capacity - i;
      isolate->heap()->RightTrimArray(*array, new_capacity, old_capacity);
      filler = HeapObject::FromAddress(previous);
      CHECK(IsFreeSpaceOrFiller(filler));
      CHECK(marking_state->IsUnmarked(filler));
    }
  }

  heap::InvokeAtomicMajorGC(heap);
}

TEST(RightTrimFixedArrayWithBlackAllocatedPages) {
  if (!v8_flags.black_allocated_pages) return;
  if (!v8_flags.incremental_marking) return;
  v8_flags.stress_concurrent_allocation = false;  // For SimulateFullSpace.
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Heap* heap = CcTest::heap();
  Isolate* isolate = CcTest::i_isolate();
  heap::InvokeMajorGC(heap);

  i::IncrementalMarking* marking = heap->incremental_marking();
  if (heap->sweeping_in_progress()) {
    heap->EnsureSweepingCompleted(
        Heap::SweepingForcedFinalizationMode::kV8Only);
  }
  CHECK(marking->IsMarking() || marking->IsStopped());
  if (marking->IsStopped()) {
    heap->StartIncrementalMarking(i::GCFlag::kNoFlags,
                                  i::GarbageCollectionReason::kTesting);
  }
  CHECK(marking->IsMarking());
  CHECK(marking->black_allocation());

  // Ensure that we allocate a new page, set up a bump pointer area, and
  // perform the allocation in a black area.
  heap::SimulateFullSpace(heap->old_space());
  isolate->factory()->NewFixedArray(10, AllocationType::kOld);

  // Allocate the fixed array that will be trimmed later.
  DirectHandle<FixedArray> array =
      isolate->factory()->NewFixedArray(100, AllocationType::kOld);
  Address start_address = array->address();
  Address end_address = start_address + array->Size();
  PageMetadata* page = PageMetadata::FromAddress(start_address);
  CHECK(page->Chunk()->IsFlagSet(MemoryChunk::BLACK_ALLOCATED));
  CHECK(heap->old_space()->Contains(*array));

  // Trim it once by one word, which shouldn't affect the BLACK_ALLOCATED flag.
  Address previous = end_address - kTaggedSize;
  isolate->heap()->RightTrimArray(*array, 99, 100);

  Tagged<HeapObject> filler = HeapObject::FromAddress(previous);
  CHECK(IsFreeSpaceOrFiller(filler));
  CHECK(page->Chunk()->IsFlagSet(MemoryChunk::BLACK_ALLOCATED));

  heap::InvokeAtomicMajorGC(heap);
  CHECK(!page->Chunk()->IsFlagSet(MemoryChunk::BLACK_ALLOCATED));

  heap->StartIncrementalMarking(i::GCFlag::kNoFlags,
                                i::GarbageCollectionReason::kTesting);

  // Allocate the large fixed array that will be trimmed later.
  array = isolate->factory()->NewFixedArray(200000, AllocationType::kOld);
  start_address = array->address();
  end_address = start_address + array->Size();
  CHECK(heap->lo_space()->Contains(*array));
  page = PageMetadata::FromAddress(start_address);
  CHECK(!page->Chunk()->IsFlagSet(MemoryChunk::BLACK_ALLOCATED));

  heap::InvokeAtomicMajorGC(heap);
  CHECK(!page->Chunk()->IsFlagSet(MemoryChunk::BLACK_ALLOCATED));
}

TEST(Regress618958) {
  if (!v8_flags.incremental_marking) return;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Heap* heap = CcTest::heap();
  bool isolate_is_locked = true;
  CcTest::isolate()->AdjustAmountOfExternalAllocatedMemory(100 * MB);
  int mark_sweep_count_before = heap->ms_count();
  heap->MemoryPressureNotification(MemoryPressureLevel::kCritical,
                                   isolate_is_locked);
  int mark_sweep_count_after = heap->ms_count();
  int mark_sweeps_performed = mark_sweep_count_after - mark_sweep_count_before;
  // The memory pressuer handler either performed two GCs or performed one and
  // started incremental marking.
  CHECK(mark_sweeps_performed == 2 ||
        (mark_sweeps_performed == 1 &&
         !heap->incremental_marking()->IsStopped()));
}

TEST(YoungGenerationLargeObjectAllocationScavenge) {
  if (v8_flags.minor_ms) return;
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Heap* heap = CcTest::heap();
  Isolate* isolate = heap->isolate();
  if (!isolate->serializer_enabled()) return;

  // TODO(hpayer): Update the test as soon as we have a tenure limit for LO.
  DirectHandle<FixedArray> array_small =
      isolate->factory()->NewFixedArray(200000);
  MemoryChunk* chunk = MemoryChunk::FromHeapObject(*array_small);
  CHECK_EQ(NEW_LO_SPACE,
           MutablePageMetadata::cast(chunk->Metadata())->owner_identity());
  CHECK(chunk->IsFlagSet(MemoryChunk::LARGE_PAGE));
  CHECK(chunk->IsFlagSet(MemoryChunk::TO_PAGE));

  DirectHandle<Object> number = isolate->factory()->NewHeapNumber(123.456);
  array_small->set(0, *number);

  heap::InvokeMinorGC(heap);

  // After the first young generation GC array_small will be in the old
  // generation large object space.
  chunk = MemoryChunk::FromHeapObject(*array_small);
  CHECK_EQ(LO_SPACE,
           MutablePageMetadata::cast(chunk->Metadata())->owner_identity());
  CHECK(!chunk->InYoungGeneration());

  heap::InvokeMemoryReducingMajorGCs(heap);
}

TEST(YoungGenerationLargeObjectAllocationMarkCompact) {
  if (v8_flags.minor_ms) return;
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Heap* heap = CcTest::heap();
  Isolate* isolate = heap->isolate();
  if (!isolate->serializer_enabled()) return;

  // TODO(hpayer): Update the test as soon as we have a tenure limit for LO.
  DirectHandle<FixedArray> array_small =
      isolate->factory()->NewFixedArray(200000);
  MemoryChunk* chunk = MemoryChunk::FromHeapObject(*array_small);
  CHECK_EQ(NEW_LO_SPACE,
           MutablePageMetadata::cast(chunk->Metadata())->owner_identity());
  CHECK(chunk->IsFlagSet(MemoryChunk::LARGE_PAGE));
  CHECK(chunk->IsFlagSet(MemoryChunk::TO_PAGE));

  DirectHandle<Object> number = isolate->factory()->NewHeapNumber(123.456);
  array_small->set(0, *number);

  heap::InvokeMajorGC(heap);

  // After the first full GC array_small will be in the old generation
  // large object space.
  chunk = MemoryChunk::FromHeapObject(*array_small);
  CHECK_EQ(LO_SPACE,
           MutablePageMetadata::cast(chunk->Metadata())->owner_identity());
  CHECK(!chunk->InYoungGeneration());

  heap::InvokeMemoryReducingMajorGCs(heap);
}

TEST(YoungGenerationLargeObjectAllocationReleaseScavenger) {
  if (v8_flags.minor_ms) return;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Heap* heap = CcTest::heap();
  Isolate* isolate = heap->isolate();
  if (!isolate->serializer_enabled()) return;

  {
    HandleScope new_scope(isolate);
    for (int i = 0; i < 10; i++) {
      DirectHandle<FixedArray> array_small =
          isolate->factory()->NewFixedArray(20000);
      MemoryChunk* chunk = MemoryChunk::FromHeapObject(*array_small);
      CHECK_EQ(NEW_LO_SPACE,
               MutablePageMetadata::cast(chunk->Metadata())->owner_identity());
      CHECK(chunk->IsFlagSet(MemoryChunk::TO_PAGE));
    }
  }

  heap::InvokeMinorGC(heap);
  CHECK(isolate->heap()->new_lo_space()->IsEmpty());
  CHECK_EQ(0, isolate->heap()->new_lo_space()->Size());
  CHECK_EQ(0, isolate->heap()->new_lo_space()->SizeOfObjects());
  CHECK(isolate->heap()->lo_space()->IsEmpty());
  CHECK_EQ(0, isolate->heap()->lo_space()->Size());
  CHECK_EQ(0, isolate->heap()->lo_space()->SizeOfObjects());
}

TEST(UncommitUnusedLargeObjectMemory) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Heap* heap = CcTest::heap();
  Isolate* isolate = heap->isolate();

  DirectHandle<FixedArray> array =
      isolate->factory()->NewFixedArray(200000, AllocationType::kOld);
  MemoryChunk* chunk = MemoryChunk::FromHeapObject(*array);
  CHECK_EQ(MutablePageMetadata::cast(chunk->Metadata())->owner_identity(),
           LO_SPACE);

  intptr_t size_before = array->Size();
  size_t committed_memory_before =
      MutablePageMetadata::cast(chunk->Metadata())->CommittedPhysicalMemory();

  array->RightTrim(isolate, 1);
  CHECK(array->Size() < size_before);

  heap::InvokeMajorGC(heap);
  CHECK(
      MutablePageMetadata::cast(chunk->Metadata())->CommittedPhysicalMemory() <
      committed_memory_before);
  size_t shrinked_size = RoundUp(
      (array->address() - chunk->address()) + array->Size(), CommitPageSize());
  CHECK_EQ(
      shrinked_size,
      MutablePageMetadata::cast(chunk->Metadata())->CommittedPhysicalMemory());
}

template <RememberedSetType direction>
static size_t GetRememberedSetSize(Tagged<HeapObject> obj) {
  size_t count = 0;
  auto chunk = MutablePageMetadata::FromHeapObject(obj);
  RememberedSet<direction>::Iterate(
      chunk,
      [&count](MaybeObjectSlot slot) {
        count++;
        return KEEP_SLOT;
      },
      SlotSet::KEEP_EMPTY_BUCKETS);
  return count;
}

TEST(RememberedSet_InsertOnWriteBarrier) {
  if (v8_flags.single_generation) return;
  v8_flags.stress_concurrent_allocation = false;  // For SealCurrentObjects.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  Heap* heap = isolate->heap();
  heap::SealCurrentObjects(heap);
  HandleScope scope(isolate);

  // Allocate an object in old space.
  DirectHandle<FixedArray> arr =
      factory->NewFixedArray(3, AllocationType::kOld);

  // Add into 'arr' references to young objects.
  {
    HandleScope scope_inner(isolate);
    DirectHandle<Object> number = factory->NewHeapNumber(42);
    arr->set(0, *number);
    arr->set(1, *number);
    arr->set(2, *number);
    DirectHandle<Object> number_other = factory->NewHeapNumber(24);
    arr->set(2, *number_other);
  }
  // Remembered sets track *slots* pages with cross-generational pointers, so
  // must have recorded three of them each exactly once.
  CHECK_EQ(3, GetRememberedSetSize<OLD_TO_NEW>(*arr));
}

TEST(RememberedSet_InsertInLargePage) {
  if (v8_flags.single_generation) return;
  v8_flags.stress_concurrent_allocation = false;  // For SealCurrentObjects.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  Heap* heap = isolate->heap();
  heap::SealCurrentObjects(heap);
  HandleScope scope(isolate);

  // Allocate an object in Large space.
  const int count = std::max(FixedArray::kMaxRegularLength + 1, 128 * KB);
  DirectHandle<FixedArray> arr =
      factory->NewFixedArray(count, AllocationType::kOld);
  CHECK(heap->lo_space()->Contains(*arr));
  CHECK_EQ(0, GetRememberedSetSize<OLD_TO_NEW>(*arr));

  // Create OLD_TO_NEW references from the large object so that the
  // corresponding slots end up in different SlotSets.
  {
    HandleScope short_lived(isolate);
    DirectHandle<Object> number = factory->NewHeapNumber(42);
    arr->set(0, *number);
    arr->set(count - 1, *number);
  }
  CHECK_EQ(2, GetRememberedSetSize<OLD_TO_NEW>(*arr));
}

TEST(RememberedSet_RemoveStaleOnScavenge) {
  if (v8_flags.single_generation || v8_flags.stress_incremental_marking) return;
  v8_flags.stress_concurrent_allocation = false;  // For SealCurrentObjects.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  Heap* heap = isolate->heap();
  heap::SealCurrentObjects(heap);
  HandleScope scope(isolate);

  // Allocate an object in old space and add into it references to young.
  DirectHandle<FixedArray> arr =
      factory->NewFixedArray(3, AllocationType::kOld);
  {
    HandleScope scope_inner(isolate);
    DirectHandle<Object> number = factory->NewHeapNumber(42);
    arr->set(0, *number);  // will be trimmed away
    arr->set(1, *number);  // will be replaced with #undefined
    arr->set(2, *number);  // will be promoted into old
  }
  CHECK_EQ(3, GetRememberedSetSize<OLD_TO_NEW>(*arr));

  arr->set(1, ReadOnlyRoots(CcTest::heap()).undefined_value());
  DirectHandle<FixedArrayBase> tail(heap->LeftTrimFixedArray(*arr, 1), isolate);

  // None of the actions above should have updated the remembered set.
  CHECK_EQ(3, GetRememberedSetSize<OLD_TO_NEW>(*tail));

  // Run GC to promote the remaining young object and fixup the stale entries in
  // the remembered set.
  heap::EmptyNewSpaceUsingGC(heap);
  CHECK_EQ(0, GetRememberedSetSize<OLD_TO_NEW>(*tail));
}

// The OLD_TO_OLD remembered set is created temporary by GC and is cleared at
// the end of the pass. There is no way to observe it so the test only checks
// that compaction has happened and otherwise relies on code's self-validation.
TEST(RememberedSet_OldToOld) {
  if (v8_flags.stress_incremental_marking) return;
  v8_flags.stress_concurrent_allocation = false;  // For SealCurrentObjects.
  ManualGCScope manual_gc_scope;
  heap::ManualEvacuationCandidatesSelectionScope
      manual_evacuation_candidate_selection_scope(manual_gc_scope);
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  Heap* heap = isolate->heap();
  heap::SealCurrentObjects(heap);
  HandleScope scope(isolate);

  IndirectHandle<FixedArray> arr =
      factory->NewFixedArray(10, AllocationType::kOld);
  {
    HandleScope short_lived(isolate);
    factory->NewFixedArray(100, AllocationType::kOld);
  }
  IndirectHandle<Object> ref =
      factory->NewFixedArray(100, AllocationType::kOld);
  arr->set(0, *ref);

  // To force compaction of the old space, fill it with garbage and start a new
  // page (so that the page with 'arr' becomes subject to compaction).
  {
    HandleScope short_lived(isolate);
    heap::SimulateFullSpace(heap->old_space());
    factory->NewFixedArray(100, AllocationType::kOld);
  }

  heap::ForceEvacuationCandidate(PageMetadata::FromHeapObject(*arr));
  const auto prev_location = *arr;

  {
    // This GC pass will evacuate the page with 'arr'/'ref' so it will have to
    // create OLD_TO_OLD remembered set to track the reference.
    // We need to invoke GC without stack, otherwise no compaction is performed.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMajorGC(heap);
  }
  CHECK_NE(prev_location.ptr(), arr->ptr());
}

TEST(RememberedSetRemoveRange) {
  if (v8_flags.single_generation) return;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Heap* heap = CcTest::heap();
  Isolate* isolate = heap->isolate();

  DirectHandle<FixedArray> array = isolate->factory()->NewFixedArray(
      PageMetadata::kPageSize / kTaggedSize, AllocationType::kOld);
  MutablePageMetadata* chunk = MutablePageMetadata::FromHeapObject(*array);
  CHECK_EQ(chunk->owner_identity(), LO_SPACE);
  Address start = array->address();
  // Maps slot to boolean indicator of whether the slot should be in the set.
  std::map<Address, bool> slots;
  slots[start + 0] = true;
  slots[start + kTaggedSize] = true;
  slots[start + PageMetadata::kPageSize - kTaggedSize] = true;
  slots[start + PageMetadata::kPageSize] = true;
  slots[start + PageMetadata::kPageSize + kTaggedSize] = true;
  slots[chunk->area_end() - kTaggedSize] = true;

  for (auto x : slots) {
    RememberedSet<OLD_TO_NEW>::Insert<AccessMode::ATOMIC>(
        chunk, chunk->Offset(x.first));
  }

  RememberedSet<OLD_TO_NEW>::Iterate(
      chunk,
      [&slots](MaybeObjectSlot slot) {
        CHECK(slots[slot.address()]);
        return KEEP_SLOT;
      },
      SlotSet::FREE_EMPTY_BUCKETS);

  RememberedSet<OLD_TO_NEW>::RemoveRange(chunk, start, start + kTaggedSize,
                                         SlotSet::FREE_EMPTY_BUCKETS);
  slots[start] = false;
  RememberedSet<OLD_TO_NEW>::Iterate(
      chunk,
      [&slots](MaybeObjectSlot slot) {
        CHECK(slots[slot.address()]);
        return KEEP_SLOT;
      },
      SlotSet::FREE_EMPTY_BUCKETS);

  RememberedSet<OLD_TO_NEW>::RemoveRange(chunk, start + kTaggedSize,
                                         start + PageMetadata::kPageSize,
                                         SlotSet::FREE_EMPTY_BUCKETS);
  slots[start + kTaggedSize] = false;
  slots[start + PageMetadata::kPageSize - kTaggedSize] = false;
  RememberedSet<OLD_TO_NEW>::Iterate(
      chunk,
      [&slots](MaybeObjectSlot slot) {
        CHECK(slots[slot.address()]);
        return KEEP_SLOT;
      },
      SlotSet::FREE_EMPTY_BUCKETS);

  RememberedSet<OLD_TO_NEW>::RemoveRange(
      chunk, start, start + PageMetadata::kPageSize + kTaggedSize,
      SlotSet::FREE_EMPTY_BUCKETS);
  slots[start + PageMetadata::kPageSize] = false;
  RememberedSet<OLD_TO_NEW>::Iterate(
      chunk,
      [&slots](MaybeObjectSlot slot) {
        CHECK(slots[slot.address()]);
        return KEEP_SLOT;
      },
      SlotSet::FREE_EMPTY_BUCKETS);

  RememberedSet<OLD_TO_NEW>::RemoveRange(chunk, chunk->area_end() - kTaggedSize,
                                         chunk->area_end(),
                                         SlotSet::FREE_EMPTY_BUCKETS);
  slots[chunk->area_end() - kTaggedSize] = false;
  RememberedSet<OLD_TO_NEW>::Iterate(
      chunk,
      [&slots](MaybeObjectSlot slot) {
        CHECK(slots[slot.address()]);
        return KEEP_SLOT;
      },
      SlotSet::FREE_EMPTY_BUCKETS);
}

HEAP_TEST(Regress670675) {
  if (!v8_flags.incremental_marking) return;
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Heap* heap = CcTest::heap();
  Isolate* isolate = heap->isolate();
  heap::InvokeMajorGC(heap);

  if (heap->sweeping_in_progress()) {
    heap->EnsureSweepingCompleted(
        Heap::SweepingForcedFinalizationMode::kV8Only);
  }
  heap->tracer()->StopFullCycleIfNeeded();
  i::IncrementalMarking* marking = CcTest::heap()->incremental_marking();
  if (marking->IsStopped()) {
    IsolateSafepointScope safepoint_scope(heap);
    heap->tracer()->StartCycle(
        GarbageCollector::MARK_COMPACTOR, GarbageCollectionReason::kTesting,
        "collector cctest", GCTracer::MarkingType::kIncremental);
    marking->Start(GarbageCollector::MARK_COMPACTOR,
                   i::GarbageCollectionReason::kTesting);
  }
  size_t array_length = 128 * KB;
  size_t n = heap->OldGenerationSpaceAvailable() / array_length;
  for (size_t i = 0; i < n + 60; i++) {
    {
      HandleScope inner_scope(isolate);
      isolate->factory()->NewFixedArray(static_cast<int>(array_length),
                                        AllocationType::kOld);
    }
    if (marking->IsStopped()) break;
    marking->AdvanceForTesting(v8::base::TimeDelta::FromMillisecondsD(0.1));
  }
  DCHECK(marking->IsStopped());
}

HEAP_TEST(RegressMissingWriteBarrierInAllocate) {
  if (!v8_flags.incremental_marking) return;
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  LocalContext env;
  v8::HandleScope scope(CcTest::isolate());
  Heap* heap = CcTest::heap();
  Isolate* isolate = heap->isolate();
  heap::InvokeMajorGC(heap);
  heap::SimulateIncrementalMarking(heap, false);
  DirectHandle<Map> map;
  {
    AlwaysAllocateScopeForTesting always_allocate(heap);
    map = isolate->factory()->NewContextfulMapForCurrentContext(
        JS_OBJECT_TYPE, JSObject::kHeaderSize);
  }
  CHECK(heap->incremental_marking()->black_allocation());
  DirectHandle<JSObject> object;
  {
    AlwaysAllocateScopeForTesting always_allocate(heap);
    object = direct_handle(Cast<JSObject>(isolate->factory()->NewForTest(
                               map, AllocationType::kOld)),
                           isolate);
  }
  // Initialize backing stores to ensure object is valid.
  ReadOnlyRoots roots(isolate);
  object->set_raw_properties_or_hash(roots.empty_property_array(),
                                     SKIP_WRITE_BARRIER);
  object->set_elements(roots.empty_fixed_array(), SKIP_WRITE_BARRIER);

  // The object is black. If Factory::New sets the map without write-barrier,
  // then the map is white and will be freed prematurely.
  heap::SimulateIncrementalMarking(heap, true);
  heap::InvokeMajorGC(heap);
  if (heap->sweeping_in_progress()) {
    heap->EnsureSweepingCompleted(
        Heap::SweepingForcedFinalizationMode::kV8Only);
  }
  CHECK(IsMap(object->map()));
}

HEAP_TEST(MarkCompactEpochCounter) {
  if (!v8_flags.incremental_marking) return;
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Heap* heap = CcTest::heap();
  unsigned epoch0 = heap->mark_compact_collector()->epoch();
  heap::InvokeMajorGC(heap);
  unsigned epoch1 = heap->mark_compact_collector()->epoch();
  CHECK_EQ(epoch0 + 1, epoch1);
  heap::SimulateIncrementalMarking(heap, true);
  heap::InvokeMajorGC(heap);
  unsigned epoch2 = heap->mark_compact_collector()->epoch();
  CHECK_EQ(epoch1 + 1, epoch2);
  heap::InvokeMinorGC(heap);
  unsigned epoch3 = heap->mark_compact_collector()->epoch();
  CHECK_EQ(epoch2, epoch3);
}

UNINITIALIZED_TEST(ReinitializeStringHashSeed) {
  // Enable rehashing and create an isolate and context.
  i::v8_flags.rehash_snapshot = true;
  for (int i = 1; i < 3; i++) {
    i::v8_flags.hash_seed = 1337 * i;
    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
    v8::Isolate* isolate = v8::Isolate::New(create_params);
    {
      v8::Isolate::Scope isolate_scope(isolate);
      CHECK_EQ(static_cast<uint64_t>(1337 * i),
               HashSeed(reinterpret_cast<i::Isolate*>(isolate)));
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      CHECK(!context.IsEmpty());
      v8::Context::Scope context_scope(context);
    }
    isolate->Dispose();
  }
}

const int kHeapLimit = 100 * MB;
Isolate* oom_isolate = nullptr;

void OOMCallback(const char* location, const OOMDetails&) {
  Heap* heap = oom_isolate->heap();
  size_t kSlack = heap->new_space() ? heap->MaxSemiSpaceSize() : 0;
  CHECK_LE(heap->OldGenerationCapacity(), kHeapLimit + kSlack);
  base::OS::ExitProcess(0);
}

UNINITIALIZED_TEST(OutOfMemory) {
  if (v8_flags.stress_incremental_marking) return;
#ifdef VERIFY_HEAP
  if (v8_flags.verify_heap) return;
#endif
  v8_flags.max_old_space_size = kHeapLimit / MB;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  v8::Isolate::Scope isolate_scope(isolate);
  Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate);
  oom_isolate = i_isolate;
  isolate->SetOOMErrorHandler(OOMCallback);
  {
    PtrComprCageAccessScope ptr_compr_cage_access_scope(i_isolate);
    Factory* factory = i_isolate->factory();
    HandleScope handle_scope(i_isolate);
    while (true) {
      factory->NewFixedArray(100);
    }
  }
}

UNINITIALIZED_TEST(OutOfMemoryIneffectiveGC) {
  if (!v8_flags.detect_ineffective_gcs_near_heap_limit) return;
  if (v8_flags.stress_incremental_marking ||
      v8_flags.stress_concurrent_allocation)
    return;
#ifdef VERIFY_HEAP
  if (v8_flags.verify_heap) return;
#endif

  v8_flags.max_old_space_size = kHeapLimit / MB;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate);
  oom_isolate = i_isolate;
  isolate->SetOOMErrorHandler(OOMCallback);
  Factory* factory = i_isolate->factory();
  Heap* heap = i_isolate->heap();
  {
    v8::Isolate::Scope isolate_scope(isolate);
    PtrComprCageAccessScope ptr_compr_cage_access_scope(i_isolate);
    heap::InvokeMajorGC(heap);

    HandleScope scope(i_isolate);
    while (heap->OldGenerationSizeOfObjects() <
           heap->MaxOldGenerationSize() * 0.9) {
      factory->NewFixedArray(100, AllocationType::kOld);
    }
    {
      int initial_ms_count = heap->ms_count();
      int ineffective_ms_start = initial_ms_count;
      while (heap->ms_count() < initial_ms_count + 10) {
        HandleScope inner_scope(i_isolate);
        factory->NewFixedArray(30000, AllocationType::kOld);
        if (heap->tracer()->AverageMarkCompactMutatorUtilization() >= 0.3) {
          ineffective_ms_start = heap->ms_count() + 1;
        }
      }
      int consecutive_ineffective_ms = heap->ms_count() - ineffective_ms_start;
      CHECK_IMPLIES(
          consecutive_ineffective_ms >= 4,
          heap->tracer()->AverageMarkCompactMutatorUtilization() >= 0.3);
    }
  }
  isolate->Dispose();
}

UNINITIALIZED_TEST(OutOfMemoryIneffectiveGCRunningJS) {
  if (!v8_flags.detect_ineffective_gcs_near_heap_limit) return;
  if (v8_flags.stress_incremental_marking) return;

  v8_flags.max_old_space_size = 10;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate);
  oom_isolate = i_isolate;

  isolate->SetOOMErrorHandler(OOMCallback);

  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);
  v8::Context::New(isolate)->Enter();

  // Test that source positions are not collected as part of a failing GC, which
  // will fail as allocation is disallowed. If the test works, this should call
  // OOMCallback and terminate without crashing.
  CompileRun(R"javascript(
      var array = [];
      for(var i = 20000; i < 40000; ++i) {
        array.push(new Array(i));
      }
      )javascript");

  FATAL("Should not get here as OOMCallback should be called");
}

HEAP_TEST(Regress779503) {
  // The following regression test ensures that the Scavenger does not allocate
  // over invalid slots. More specific, the Scavenger should not sweep a page
  // that it currently processes because it might allocate over the currently
  // processed slot.
  if (v8_flags.single_generation) return;
  v8_flags.stress_concurrent_allocation = false;  // For SealCurrentObjects.
  const int kArraySize = 2048;
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = CcTest::heap();
  heap::SealCurrentObjects(heap);
  {
    HandleScope handle_scope(isolate);
    // The byte array filled with kHeapObjectTag ensures that we cannot read
    // from the slot again and interpret it as heap value. Doing so will crash.
    DirectHandle<ByteArray> byte_array =
        isolate->factory()->NewByteArray(kArraySize);
    CHECK(HeapLayout::InYoungGeneration(*byte_array));
    for (int i = 0; i < kArraySize; i++) {
      byte_array->set(i, kHeapObjectTag);
    }

    {
      HandleScope new_scope(isolate);
      // The FixedArray in old space serves as space for slots.
      DirectHandle<FixedArray> fixed_array =
          isolate->factory()->NewFixedArray(kArraySize, AllocationType::kOld);
      CHECK(!HeapLayout::InYoungGeneration(*fixed_array));
      for (int i = 0; i < kArraySize; i++) {
        fixed_array->set(i, *byte_array);
      }
    }
    // Delay sweeper tasks to allow the scavenger to sweep the page it is
    // currently scavenging.
    heap->delay_sweeper_tasks_for_testing_ = true;
    heap::InvokeMajorGC(heap);
    CHECK(!HeapLayout::InYoungGeneration(*byte_array));
  }
  // Scavenging and sweeping the same page will crash as slots will be
  // overridden.
  heap::InvokeMinorGC(heap);
  heap->delay_sweeper_tasks_for_testing_ = false;
}

struct OutOfMemoryState {
  Heap* heap;
  bool oom_triggered;
  size_t old_generation_capacity_at_oom;
  size_t memory_allocator_size_at_oom;
  size_t new_space_capacity_at_oom;
  size_t new_lo_space_size_at_oom;
  size_t current_heap_limit;
  size_t initial_heap_limit;
};

size_t NearHeapLimitCallback(void* raw_state, size_t current_heap_limit,
                             size_t initial_heap_limit) {
  OutOfMemoryState* state = static_cast<OutOfMemoryState*>(raw_state);
  Heap* heap = state->heap;
  state->oom_triggered = true;
  state->old_generation_capacity_at_oom = heap->OldGenerationCapacity();
  state->memory_allocator_size_at_oom = heap->memory_allocator()->Size();
  state->new_space_capacity_at_oom =
      heap->new_space() ? heap->new_space()->Capacity() : 0;
  state->new_lo_space_size_at_oom =
      heap->new_lo_space() ? heap->new_lo_space()->Size() : 0;
  state->current_heap_limit = current_heap_limit;
  state->initial_heap_limit = initial_heap_limit;
  return initial_heap_limit + 100 * MB;
}

size_t MemoryAllocatorSizeFromHeapCapacity(size_t capacity) {
  // Size to capacity factor.
  double factor = PageMetadata::kPageSize * 1.0 /
                  MemoryChunkLayout::AllocatableMemoryInDataPage();
  // Some tables (e.g. deoptimization table) are allocated directly with the
  // memory allocator. Allow some slack to account for them.
  size_t slack = 5 * MB;
  return static_cast<size_t>(capacity * factor) + slack;
}

UNINITIALIZED_TEST(OutOfMemorySmallObjects) {
  if (v8_flags.stress_incremental_marking) return;
#ifdef VERIFY_HEAP
  if (v8_flags.verify_heap) return;
#endif
  const size_t kOldGenerationLimit = 50 * MB;
  v8_flags.max_old_space_size = kOldGenerationLimit / MB;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate);
  Heap* heap = i_isolate->heap();
  Factory* factory = i_isolate->factory();
  OutOfMemoryState state;
  state.heap = heap;
  state.oom_triggered = false;
  heap->AddNearHeapLimitCallback(NearHeapLimitCallback, &state);
  {
    PtrComprCageAccessScope ptr_compr_cage_access_scope(i_isolate);

    v8::Isolate::Scope isolate_scope(isolate);
    HandleScope handle_scope(i_isolate);
    while (!state.oom_triggered) {
      factory->NewFixedArray(100);
    }
  }
  CHECK_LE(state.old_generation_capacity_at_oom,
           kOldGenerationLimit + heap->MaxSemiSpaceSize());
  CHECK_LE(kOldGenerationLimit,
           state.old_generation_capacity_at_oom + heap->MaxSemiSpaceSize());
  CHECK_LE(
      state.memory_allocator_size_at_oom,
      MemoryAllocatorSizeFromHeapCapacity(state.old_generation_capacity_at_oom +
                                          2 * state.new_space_capacity_at_oom));
  isolate->Dispose();
}

UNINITIALIZED_TEST(OutOfMemoryLargeObjects) {
  if (v8_flags.stress_incremental_marking) return;
#ifdef VERIFY_HEAP
  if (v8_flags.verify_heap) return;
#endif
  const size_t kOldGenerationLimit = 50 * MB;
  v8_flags.max_old_space_size = kOldGenerationLimit / MB;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate);
  Heap* heap = i_isolate->heap();
  Factory* factory = i_isolate->factory();
  OutOfMemoryState state;
  state.heap = heap;
  state.oom_triggered = false;
  heap->AddNearHeapLimitCallback(NearHeapLimitCallback, &state);
  {
    v8::Isolate::Scope isolate_scope(isolate);
    PtrComprCageAccessScope ptr_compr_cage_access_scope(i_isolate);
    const int kFixedArrayLength = 1000000;
    {
      HandleScope handle_scope(i_isolate);
      while (!state.oom_triggered) {
        factory->NewFixedArray(kFixedArrayLength);
      }
    }
    CHECK_LE(state.old_generation_capacity_at_oom,
             kOldGenerationLimit + state.new_space_capacity_at_oom +
                 state.new_lo_space_size_at_oom +
                 FixedArray::SizeFor(kFixedArrayLength));
    CHECK_LE(kOldGenerationLimit, state.old_generation_capacity_at_oom +
                                      state.new_space_capacity_at_oom +
                                      state.new_lo_space_size_at_oom +
                                      FixedArray::SizeFor(kFixedArrayLength));
    CHECK_LE(state.memory_allocator_size_at_oom,
             MemoryAllocatorSizeFromHeapCapacity(
                 state.old_generation_capacity_at_oom +
                 2 * state.new_space_capacity_at_oom +
                 state.new_lo_space_size_at_oom));
  }
  isolate->Dispose();
}

UNINITIALIZED_TEST(RestoreHeapLimit) {
  if (v8_flags.stress_incremental_marking) return;
#ifdef VERIFY_HEAP
  if (v8_flags.verify_heap) return;
#endif
  ManualGCScope manual_gc_scope;
  const siz
```