Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/test/cctest/heap/test-heap.cc`. The summary should include:

1. **Overall purpose:** What does this section of the test file do?
2. **Specific functionalities:** List the individual test cases and their goals.
3. **Torque source:** Check if the filename ends with `.tq`.
4. **JavaScript relation:** If any test relates to JavaScript features, demonstrate with an example.
5. **Logic inference:** If there's code logic that can be demonstrated with inputs and outputs, provide an example.
6. **Common programming errors:** If any test relates to common programming errors, give an example.
7. **Context within the whole file:** This is part 7 of 9, so relate its function to the broader testing goals of the file.

Let's break down the code snippet and address each point:

**1. Overall Purpose:**

This section of `test-heap.cc` focuses on testing various aspects of the V8 heap, especially related to garbage collection (major and minor GCs), incremental marking, memory management (allocation counters, space sizes), and object lifecycle (weak references, retained maps). It aims to ensure the heap behaves correctly under different scenarios and avoids potential bugs like memory leaks or incorrect object handling during GC.

**2. Specific Functionalities (Test Cases):**

* **`TEST(Regress442710)`:** Tests a regression related to array shifting and major GC.
* **`HEAP_TEST(NumberStringCacheSize)`:** Verifies the size of the number-string cache after snapshot creation.
* **`TEST(Regress3877)`:** Tests the interaction between weak prototypes, object maps, and garbage collection.
* **`TEST(MapRetaining)` and `TEST(RetainedMapsCleanup)`:**  Test the mechanism for retaining maps across GCs and their cleanup when contexts are disposed, related to incremental marking.
* **`TEST(PreprocessStackTrace)`:** Tests how stack traces are processed and potentially optimized during garbage collection.
* **`TEST(NewSpaceAllocationCounter)` and `TEST(OldSpaceAllocationCounter)`:** Test the accuracy of the allocation counters for new and old spaces.
* **`TEST(MessageObjectLeak)`:** Checks for potential memory leaks related to message objects in try-catch and finally blocks.
* **`TEST(CanonicalSharedFunctionInfo)`:** Tests the canonicalization of `SharedFunctionInfo` objects after code removal and GC.
* **`TEST(ScriptIterator)`:** Verifies the functionality of the script iterator.
* **`HEAP_TEST(Regress587004)` and `HEAP_TEST(Regress589413)`:** Test specific regression scenarios related to object allocation and incremental marking.
* **`TEST(Regress598319)`:** Tests a scenario involving large object allocation, incremental marking, and array shifting to ensure no objects are missed during marking.
* **`TEST(Regress609761)` and `TEST(LiveBytes)`:** Test the behavior of shrinking large fixed arrays and the reported live bytes.
* **`TEST(Regress615489)`:** Tests that live object size doesn't increase after garbage collection during incremental marking.
* **`TEST(Regress631969)`:** Tests a specific scenario involving external strings, cons strings, and incremental marking.
* **`TEST(ContinuousRightTrimFixedArrayInBlackArea)`:** Tests the trimming of fixed arrays allocated in the black allocation area during incremental marking.

**3. Torque Source:**

The filename `v8/test/cctest/heap/test-heap.cc` ends with `.cc`, not `.tq`. Therefore, it's a C++ source file, not a Torque source file.

**4. JavaScript Relation:**

Many of these tests directly relate to JavaScript features and their impact on the heap. Here are a few examples:

* **`TEST(Regress442710)`:** The test uses `testArray.shift()`, which is a JavaScript array method.
  ```javascript
  let testArray = [1, 2];
  testArray.shift(); // Removes the first element, testArray becomes [2]
  ```
* **`TEST(Regress3877)`:**  This test manipulates JavaScript prototypes using `cls.prototype = null` and `a.x.__proto__ = {};`.
  ```javascript
  function cls() { this.x = 10; }
  cls.prototype = { y: 20 };
  var a = { x: new cls() };
  console.log(a.x.y); // Output: 20
  cls.prototype = null;
  console.log(a.x.y); // Output: undefined (because the prototype is now null)
  var b = {};
  b.__proto__ = a.x; // Sets b's prototype to the object a.x
  ```
* **`TEST(CanonicalSharedFunctionInfo)`:** The test creates and compares JavaScript functions.
  ```javascript
  function f() { return function g() {}; }
  var g1 = f();
  var g2 = f();
  console.log(g1 === g2); // Output: false (initially, different instances)
  // After potentially canonicalizing, the test checks if they are the same underlying SharedFunctionInfo.
  ```

**5. Logic Inference:**

* **`TEST(Regress442710)`:**
    * **Input:** A JavaScript array `[1, 2]`.
    * **Action:** `shift()` is called on the array, removing the first element. A major GC is invoked.
    * **Expected Output:** The heap should remain consistent after the shift and GC. The specific test likely checks internal heap structures.
* **`TEST(Regress3877)`:**
    * **Input:** A class `cls` and an object `a` with an instance of `cls`.
    * **Action:** The prototype of `cls` is initially set, then set to `null`. An object `b` has its prototype set to `a.x`. The prototype of `a.x` is changed. Multiple major GCs are invoked.
    * **Expected Output:** The weak reference to the initial prototype of `cls` should eventually be cleared after the map of `a.x` changes and the old prototype becomes unreachable.

**6. Common Programming Errors:**

* **Memory Leaks (related to `TEST(MessageObjectLeak)`):** Forgetting to release resources or not handling exceptions properly can lead to memory leaks. The `MessageObjectLeak` test specifically checks if message objects created during exception handling are correctly cleaned up.
  ```javascript
  try {
    // Potential resource allocation
    throw new Error("Something went wrong");
  } catch (e) {
    // If the catch block doesn't properly release resources associated with the error, it could lead to a leak.
  }
  ```
* **Incorrect Prototype Handling (related to `TEST(Regress3877)`):**  Incorrectly manipulating prototypes can lead to unexpected behavior and potentially memory leaks if objects are kept alive longer than intended.
* **Issues with Weak References:**  Misunderstanding how weak references work and when they are cleared can lead to bugs. The tests involving `WeakFixedArray` and `MakeWeak` are designed to ensure weak references are handled correctly during garbage collection.

**7.归纳一下它的功能 (Summary of its Functionality):**

This seventh part of the `test-heap.cc` file focuses on rigorous testing of V8's heap management and garbage collection mechanisms. It includes tests for specific bug regressions, the correctness of allocation counters, the lifecycle of objects (especially those involving weak references and prototypes), and the robustness of the heap under various conditions, including incremental marking and different allocation scenarios. The tests use JavaScript code snippets to trigger specific heap behaviors and then verify the internal state of the V8 heap. This section, like the others, is crucial for ensuring the stability and correctness of V8's memory management, which directly impacts the performance and reliability of JavaScript execution. It delves into more complex scenarios involving interactions between different heap features and advanced garbage collection techniques like incremental marking.

这是 `v8/test/cctest/heap/test-heap.cc` 源代码的第 7 部分，主要功能是**深入测试 V8 堆的各种特性，特别是与垃圾回收（GC）相关的场景，包括增量标记、内存分配计数、弱引用、以及一些特定的回归测试用例。**

以下是更详细的列举：

* **`TEST(Regress442710)`**:  测试一个回归用例，涉及到弱引用的集合（`WeakMap` 的底层实现）和数组的 `shift()` 操作。它模拟了增量标记过程，并检查在 `WeakMap` 的底层存储被修改后，GC 是否能正确处理。

* **`TEST(NumberStringCacheSize)`**: 测试数字到字符串的缓存大小在快照创建后是否保持不变。这主要是为了确保在快照加载后，一些内部数据结构的状态是预期的。

* **`TEST(Regress3877)`**: 测试与弱原型相关的回归用例。它创建了一个带有原型的类，并使用弱引用来持有该原型。然后，通过修改对象的原型链和触发 GC，来验证弱引用是否能正确地被清除。

* **`TEST(MapRetaining)` 和 `TEST(RetainedMapsCleanup)`**:  这两个测试与增量标记有关，测试了 V8 如何在 GC 过程中保留对象的 `Map` (对象布局信息)。`MapRetaining` 测试在多次 GC 后，`Map` 是否会被保留，而 `RetainedMapsCleanup` 测试当关联的上下文被销毁时，保留的 `Map` 是否会被清理。

* **`TEST(PreprocessStackTrace)`**: 测试堆在内存减少的 GC 过程中，如何预处理堆栈跟踪信息。它抛出一个异常，获取堆栈跟踪，然后触发 GC，检查堆栈跟踪中的代码信息是否被正确处理。

* **`TEST(NewSpaceAllocationCounter)` 和 `TEST(OldSpaceAllocationCounter)`**: 这两个测试分别检查新生代和老生代的内存分配计数器是否准确。它们通过分配内存，触发 GC，并检查计数器的变化来验证。

* **`TEST(MessageObjectLeak)`**:  测试在 `try...catch...finally` 结构中抛出异常时，与异常消息相关的对象是否存在内存泄漏。

* **`TEST(CanonicalSharedFunctionInfo)`**: 测试 `SharedFunctionInfo` 对象的规范化。当一个函数被多次定义并执行后，V8 可能会共享相同的 `SharedFunctionInfo` 对象以节省内存。这个测试验证了在移除代码并进行 GC 后，这种规范化是否仍然有效。

* **`TEST(ScriptIterator)`**: 测试 `Script` 对象的迭代器是否能够正确地遍历堆中的所有脚本对象。

* **`HEAP_TEST(Regress587004)`**:  这是一个堆测试，意味着它可能会触发 GC。此测试似乎与大对象的分配、GC 和数组的修剪操作有关。它模拟了一种可能导致问题的场景，并验证堆的行为是否符合预期。

* **`HEAP_TEST(Regress589413)`**:  又一个堆测试，与增量标记和并发分配有关。它填充新生代，然后强制进行 minor GC，接着在老生代分配大量对象，并强制进行增量标记，最后进行 major GC，以此来测试特定的场景。

* **`TEST(Regress598319)`**: 测试在增量标记过程中，对大数组执行 `shift()` 操作时，是否会遗漏标记对象。

* **`TEST(Regress609761)` 和 `TEST(LiveBytes)`**:  这两个测试都与调整 `FixedArray` 的大小有关。`Regress609761` 测试了调整超大数组大小的情况，而 `LiveBytes` 似乎检查了 GC 后剩余的活跃字节数。

* **`TEST(Regress615489)`**: 测试在增量标记期间进行黑分配（直接分配到已标记区域）时，GC 后的活跃对象大小不会增加。

* **`TEST(Regress631969)`**: 测试一个涉及外部字符串、ConsString 和增量标记的特定场景。

* **`TEST(ContinuousRightTrimFixedArrayInBlackArea)`**: 测试在增量标记期间，连续地修剪分配在黑色区域的 `FixedArray` 是否能正常工作。

**如果 `v8/test/cctest/heap/test-heap.cc` 以 `.tq` 结尾**，那么它将是一个 **V8 Torque 源代码**。 Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。然而，根据文件名，它是一个 `.cc` 文件，因此是 C++ 源代码。

**如果它与 javascript 的功能有关系，请用 javascript 举例说明:**

* **`TEST(Regress442710)`**:  涉及到 `WeakMap` 和数组的 `shift()` 方法。
  ```javascript
  const weakMap = new WeakMap();
  const key1 = {};
  const key2 = {};
  weakMap.set(key1, 1);
  weakMap.set(key2, 2);

  const arr = [10, 20, 30];
  arr.shift(); // arr 现在是 [20, 30]
  ```

* **`TEST(Regress3877)`**: 涉及到 JavaScript 的原型链。
  ```javascript
  function cls() {
    this.x = 10;
  }
  const obj = new cls();
  console.log(obj.x); // 输出 10
  console.log(obj.prototype); // 输出 undefined，实例没有 prototype 属性
  console.log(cls.prototype); // 输出 cls 的原型对象
  cls.prototype = null; // 修改 cls 的原型
  ```

* **`TEST(CanonicalSharedFunctionInfo)`**:  涉及到 JavaScript 函数的定义和执行。
  ```javascript
  function f() {
    return function g() {};
  }
  const g1 = f();
  const g2 = f();
  console.log(g1 === g2); // 通常情况下，g1 和 g2 是不同的函数对象
  ```

**如果有代码逻辑推理，请给出假设输入与输出:**

* **`TEST(NewSpaceAllocationCounter)`**:
    * **假设输入:** 在新生代分配了 1024 字节的数据。
    * **预期输出:** 新生代的分配计数器应该增加 1024。在进行 minor GC 后，计数器应该被重置为 0。

* **`TEST(OldSpaceAllocationCounter)`**:
    * **假设输入:** 在老生代分配了 2048 字节的数据。
    * **预期输出:** 老生代的分配计数器应该增加 2048。在进行 minor GC 后，计数器不会被重置。在进行 major GC 后，计数器会被重置。

**如果涉及用户常见的编程错误，请举例说明:**

* **内存泄漏 (与 `TEST(MessageObjectLeak)` 相关):**
  ```javascript
  function potentiallyLeakyFunction() {
    try {
      const obj = { data: new Array(1000000) }; // 分配大量内存
      throw new Error("Something went wrong");
    } catch (e) {
      // 如果在这里没有正确释放 obj 的引用，可能会导致内存泄漏。
      console.error("Caught an error:", e);
    }
  }
  potentiallyLeakyFunction();
  ```
* **原型链的错误使用 (与 `TEST(Regress3877)` 相关):**
  ```javascript
  function Parent() {
    this.value = 10;
  }
  function Child() {}
  Child.prototype = Parent.prototype; // 错误地共享了 Parent 的原型对象
  const child1 = new Child();
  const parent = new Parent();
  Child.prototype.newValue = 20; // 修改 Child 的原型也会影响 parent
  console.log(child1.newValue); // 输出 20
  console.log(parent.newValue); // 输出 20，这可能是非预期的
  ```

**这是第7部分，共9部分，请归纳一下它的功能:**

作为 `test-heap.cc` 文件的一部分，这第七部分的功能是**对 V8 堆的健壮性和正确性进行更深入和细致的测试**。它涵盖了垃圾回收的关键方面，包括增量标记的正确性、内存分配的准确性、以及在特定场景下（例如操作弱引用、修改原型链、处理异常等）堆的行为是否符合预期。这些测试通常会模拟一些复杂的场景和边缘情况，以确保 V8 的堆管理机制在各种条件下都能稳定可靠地运行，从而保障 JavaScript 代码的执行效率和稳定性。 这部分测试更偏向于底层和细节，用于发现潜在的、不容易被普通功能测试发现的 bug。

### 提示词
```
这是目录为v8/test/cctest/heap/test-heap.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/heap/test-heap.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
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
  NonAtomicMarkingState* ma
```