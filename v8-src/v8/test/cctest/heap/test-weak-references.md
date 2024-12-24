Response: Let's break down the thought process for analyzing this C++ test file for V8's weak references.

1. **Understand the Goal:** The primary goal is to figure out what this C++ code is testing. It's in the `v8/test/cctest/heap/` directory, specifically `test-weak-references.cc`. This strongly suggests it's testing the functionality of weak references within V8's heap management.

2. **Identify Key Concepts:** The file name itself gives away the core concept: "weak references". As I read through the code, I'd look for related terms and concepts:
    * `Weak` (e.g., `MakeWeak`)
    * `IsCleared()`
    * `GetHeapObjectIfWeak()`
    * `WeakFixedArray`, `WeakArrayList`
    * Garbage Collection (`InvokeMajorGC`, `InvokeMinorGC`)
    * Object lifetimes (going out of scope)
    * Different memory spaces (young generation, old space)
    * Incremental Marking

3. **Examine the Test Structure:**  The code is structured as a series of `TEST()` macros. Each `TEST()` function likely focuses on a specific aspect of weak reference behavior. This provides a good roadmap for understanding the different scenarios being tested.

4. **Analyze Individual Tests (Iterative Process):**  I'd go through each test function, one by one, trying to grasp its purpose.

    * **`WeakReferencesBasic`:** This seems like a fundamental test. It creates a `LoadHandler`, stores a regular object, then stores a *weak* reference to a `Code` object. It then triggers garbage collection and checks if the weak reference behaves as expected (remains valid as long as the target object is alive, clears when the target is garbage collected). The usage of `MakeWeak` is a crucial indicator here.

    * **`WeakReferencesOldToOld`, `WeakReferencesOldToNew`, `WeakReferencesOldToNewScavenged`, `WeakReferencesOldToCleared`:** These tests likely explore how weak references behave when the weak reference itself and the target object reside in different parts of the heap (old space vs. new space) and how different types of garbage collection affect them (major GC, minor GC/scavenge).

    * **`ObjectMovesBeforeClearingWeakField`:** This test name hints at the interaction between object movement (during garbage collection) and the clearing of weak references. The `SimulateIncrementalMarking` gives a clue about the specific GC mechanism being tested.

    * **`ObjectWithWeakFieldDies`:** This seems to check what happens when an object *containing* a weak reference is itself garbage collected.

    * **`ObjectWithWeakReferencePromoted`, `ObjectWithClearedWeakReferencePromoted`:** These tests investigate the behavior of weak references when objects are "promoted" from the young generation to the old generation during garbage collection.

    * **`WeakReferenceWriteBarrier`:** The term "write barrier" is related to how the garbage collector tracks object references. This test likely verifies that updating a weak reference triggers the write barrier, ensuring the target object is considered live during marking.

    * **`EmptyWeakArray`, `WeakArraysBasic`, `WeakArrayListBasic`, `WeakArrayListRemove`:** These tests focus on specific data structures designed to hold weak references: `WeakFixedArray` and `WeakArrayList`. They test basic operations like creation, adding elements (both strong and weak), and removal.

    * **`Regress7768`:** Tests with names like "Regress..." usually address specific bug fixes. This one involves function optimization and deoptimization, suggesting a scenario where weak references in compiled code were problematic.

    * **`PrototypeUsersBasic`, `PrototypeUsersCompacted`:**  These seem to be testing a higher-level abstraction built on top of weak references, possibly related to tracking objects that inherit from a specific prototype.

5. **Identify Relationships to JavaScript:** After understanding the C++ tests, the next step is to connect them to JavaScript. Weak references are a JavaScript feature. The key is to think about *why* V8 would need to implement weak references at the C++ level. The most common reason is to allow JavaScript objects to refer to other JavaScript objects without preventing the garbage collection of the referred-to object.

6. **Formulate JavaScript Examples:** For each major test category, I'd try to construct a corresponding JavaScript scenario that would exhibit the tested behavior.

    * **Basic Weak Reference:** Use `WeakRef`.
    * **Weak Collections:** Use `WeakMap` and `WeakSet`.
    * **Object Lifecycles and GC:** Demonstrate how the weak reference doesn't prevent GC.
    * **Callbacks (like `PrototypeUsersCompacted`):**  This requires thinking about scenarios where V8 needs to be notified when a weakly held object is collected (e.g., finalizers).

7. **Refine and Organize:** Finally, I'd organize the findings into a clear and concise summary, explaining the purpose of the C++ tests and illustrating the connection to JavaScript with relevant examples. I'd group related tests together for better clarity.

**Self-Correction/Refinement during the process:**

* **Initial Misinterpretations:** I might initially misunderstand the purpose of a specific test. For example, I might not immediately grasp the significance of "write barriers."  Further reading of the code comments or related documentation would be necessary to correct my understanding.
* **JavaScript Example Difficulty:**  Sometimes, creating a direct JavaScript equivalent of a low-level C++ test might be challenging. In such cases, I'd focus on illustrating the *concept* being tested rather than a perfect 1:1 mapping.
* **Focus on Functionality:** The goal isn't to understand every single line of C++ code, but rather the *functionality* being tested and how it relates to the higher-level JavaScript API.

By following these steps, combining code analysis with knowledge of garbage collection and JavaScript features, I can effectively summarize the functionality of this C++ test file and its relevance to JavaScript.
这个C++源代码文件 `test-weak-references.cc` 是 V8 JavaScript 引擎的测试文件，专门用于测试 **弱引用 (weak references)** 相关的特性。

**功能归纳:**

该文件包含了一系列单元测试，旨在验证 V8 引擎中弱引用的各种行为和机制，包括：

1. **基本的弱引用操作:**
   - 创建弱引用。
   - 检查弱引用是否指向一个对象。
   - 在目标对象被垃圾回收后，弱引用是否会被清除（变为 cleared）。

2. **不同内存区域的弱引用:**
   - 弱引用和目标对象都在年轻代 (Young Generation)。
   - 弱引用和目标对象都在老年代 (Old Generation)。
   - 弱引用在老年代，目标对象在年轻代。
   - 测试在不同代之间的垃圾回收过程对弱引用的影响。

3. **垃圾回收对弱引用的影响:**
   - 主要垃圾回收 (Major GC, Mark-Compact) 如何清除不可达的弱引用。
   - 次要垃圾回收 (Minor GC, Scavenger) 对弱引用的处理 (通常 Scavenger 会将弱引用视为强引用，以确保在新生代 GC 时不会过早清除)。
   - 增量标记 (Incremental Marking) 场景下弱引用的处理，包括对象移动和弱引用清除的时机。

4. **包含弱引用的对象的生命周期:**
   - 当包含弱引用的对象自身被垃圾回收时，是否会正确处理其内部的弱引用。

5. **弱引用与写屏障 (Write Barrier):**
   - 测试在更新弱引用时，写屏障机制是否能正确地处理，确保被弱引用的对象在增量标记阶段不会被错误地标记为垃圾。

6. **弱引用数组 (WeakFixedArray) 和弱引用列表 (WeakArrayList):**
   - 测试专门用于存储弱引用的数据结构的功能，例如创建、添加元素（强引用和弱引用）、删除元素以及垃圾回收对这些数组/列表的影响。

7. **原型用户 (Prototype Users):**
   - 测试一种特定的弱引用使用场景，用于跟踪哪些对象以某个特定对象为原型。

8. **回归测试 (Regress7768):**
   - 包含针对特定 bug (issue 7768) 的修复进行的测试，涉及到函数优化、去优化和弱引用。

**与 JavaScript 的关系及示例:**

弱引用是 JavaScript 中一个重要的概念，用于解决对象之间循环引用导致内存泄漏的问题，以及在不阻止对象被垃圾回收的情况下观察对象的状态。V8 作为 JavaScript 引擎，其 C++ 代码自然包含了对 JavaScript 弱引用特性的实现和测试。

**JavaScript 中的弱引用主要体现在以下几种形式：**

1. **`WeakRef`:**  允许你持有一个对另一个对象的 *弱* 引用。如果该对象只剩下弱引用指向它，垃圾回收器就可以回收该对象。你可以使用 `deref()` 方法尝试获取该对象，如果对象已被回收，则返回 `undefined`。

   ```javascript
   let target = { value: 42 };
   let weakTarget = new WeakRef(target);

   console.log(weakTarget.deref()?.value); // 输出 42

   target = null; // 解除强引用

   // 触发垃圾回收 (实际情况中，GC 的触发时机不确定)
   // ...

   console.log(weakTarget.deref()); // 可能输出 undefined，取决于 target 是否已被回收
   ```

2. **`WeakMap`:**  一个键值对集合，其中 **键** 是弱持有的。这意味着如果一个对象作为 `WeakMap` 的键，并且没有其他强引用指向该对象，则该对象可以被垃圾回收，并且在回收后，该键值对也会从 `WeakMap` 中移除。

   ```javascript
   let key = { id: 1 };
   let weakMap = new WeakMap();
   weakMap.set(key, 'some value');

   console.log(weakMap.has(key)); // 输出 true

   key = null; // 解除对键的强引用

   // 触发垃圾回收
   // ...

   console.log(weakMap.has(key)); // 输出 false，因为 key 指向的对象已被回收
   ```

3. **`WeakSet`:**  类似于 `Set`，但它存储的是对象的弱持有。如果一个对象只被 `WeakSet` 持有，那么它可以被垃圾回收，并且会自动从 `WeakSet` 中移除。

   ```javascript
   let obj = { name: 'example' };
   let weakSet = new WeakSet();
   weakSet.add(obj);

   console.log(weakSet.has(obj)); // 输出 true

   obj = null; // 解除强引用

   // 触发垃圾回收
   // ...

   console.log(weakSet.has(obj)); // 输出 false
   ```

**`test-weak-references.cc` 中的测试用例与这些 JavaScript 特性直接相关。** 例如：

- **`WeakReferencesBasic`** 测试了 `MakeWeak` 和弱引用的基本行为，这对应于 JavaScript 中 `WeakRef` 的核心概念。
- **`WeakArraysBasic` 和 `WeakArrayListBasic`** 测试了 V8 内部用于实现类似 `WeakMap` 和 `WeakSet` 功能的数据结构。
- **关于垃圾回收的测试 (例如 `ObjectMovesBeforeClearingWeakField`)** 验证了 V8 的垃圾回收机制如何正确处理弱引用，确保它们在对象不再被强引用时能够被清除，这直接影响了 `WeakRef`、`WeakMap` 和 `WeakSet` 在 JavaScript 中的行为。

总而言之，`test-weak-references.cc` 是 V8 引擎中一个关键的测试文件，它深入测试了弱引用这一重要的内存管理特性，确保了 JavaScript 中 `WeakRef`、`WeakMap` 和 `WeakSet` 等功能的正确性和可靠性。

Prompt: 
```
这是目录为v8/test/cctest/heap/test-weak-references.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/api/api-inl.h"
#include "src/codegen/assembler-inl.h"
#include "src/execution/isolate.h"
#include "src/heap/factory.h"
#include "src/heap/heap-inl.h"
#include "src/ic/handler-configuration.h"
#include "src/objects/data-handler-inl.h"
#include "src/objects/smi.h"
#include "test/cctest/cctest.h"
#include "test/cctest/heap/heap-tester.h"
#include "test/cctest/heap/heap-utils.h"

namespace v8 {
namespace internal {
namespace heap {

Handle<LoadHandler> CreateLoadHandlerForTest(
    Factory* factory, AllocationType allocation = AllocationType::kYoung) {
  Handle<LoadHandler> result = factory->NewLoadHandler(1, allocation);
  result->set_smi_handler(Smi::zero());
  result->set_validity_cell(Smi::zero());
  result->set_data1(Smi::zero());
  return result;
}

TEST(WeakReferencesBasic) {
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      CcTest::heap());
  HandleScope outer_scope(isolate);

  IndirectHandle<LoadHandler> lh = CreateLoadHandlerForTest(factory);

  if (!v8_flags.single_generation) CHECK(HeapLayout::InYoungGeneration(*lh));

  Tagged<MaybeObject> code_object = lh->data1();
  CHECK(IsSmi(code_object));
  heap::InvokeMajorGC(CcTest::heap());
  CHECK(!HeapLayout::InYoungGeneration(*lh));
  CHECK_EQ(code_object, lh->data1());

  {
    HandleScope inner_scope(isolate);

    // Create a new Code.
    Assembler assm(isolate->allocator(), AssemblerOptions{});
    assm.nop();  // supported on all architectures
    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    IndirectHandle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
    CHECK(IsCode(*code));

    // We cannot store the Code object itself into the tagged field as it will
    // be located outside of the main pointer compression cage when the sandbox
    // is enabled. So instead we use the Code's wrapper object.
    lh->set_data1(MakeWeak(code->wrapper()));
    Tagged<HeapObject> code_wrapper_heap_object;
    CHECK(lh->data1().GetHeapObjectIfWeak(&code_wrapper_heap_object));
    CHECK_EQ(code->wrapper(), code_wrapper_heap_object);

    heap::InvokeMajorGC(CcTest::heap());

    CHECK(lh->data1().GetHeapObjectIfWeak(&code_wrapper_heap_object));
    CHECK_EQ(code->wrapper(), code_wrapper_heap_object);
  }  // code will go out of scope.

  heap::InvokeMajorGC(CcTest::heap());
  CHECK(lh->data1().IsCleared());
}

TEST(WeakReferencesOldToOld) {
  // Like WeakReferencesBasic, but the updated weak slot is in the old space,
  // and referring to an old space object.
  ManualGCScope manual_gc_scope;
  heap::ManualEvacuationCandidatesSelectionScope
      manual_evacuation_candidate_selection_scope(manual_gc_scope);
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  Heap* heap = isolate->heap();

  HandleScope outer_scope(isolate);
  DirectHandle<LoadHandler> lh =
      CreateLoadHandlerForTest(factory, AllocationType::kOld);
  CHECK(heap->InOldSpace(*lh));

  // Create a new FixedArray which the LoadHandler will point to.
  DirectHandle<FixedArray> fixed_array =
      factory->NewFixedArray(1, AllocationType::kOld);
  CHECK(heap->InOldSpace(*fixed_array));
  lh->set_data1(MakeWeak(*fixed_array));

  PageMetadata* page_before_gc = PageMetadata::FromHeapObject(*fixed_array);
  heap::ForceEvacuationCandidate(page_before_gc);
  heap::InvokeMajorGC(heap);
  CHECK(heap->InOldSpace(*fixed_array));

  Tagged<HeapObject> heap_object;
  CHECK(lh->data1().GetHeapObjectIfWeak(&heap_object));
  CHECK_EQ(heap_object, *fixed_array);
}

TEST(WeakReferencesOldToNew) {
  // Like WeakReferencesBasic, but the updated weak slot is in the old space,
  // and referring to an new space object.
  if (v8_flags.single_generation) return;
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  Heap* heap = isolate->heap();

  HandleScope outer_scope(isolate);
  DirectHandle<LoadHandler> lh =
      CreateLoadHandlerForTest(factory, AllocationType::kOld);
  CHECK(heap->InOldSpace(*lh));

  // Create a new FixedArray which the LoadHandler will point to.
  DirectHandle<FixedArray> fixed_array = factory->NewFixedArray(1);
  CHECK(HeapLayout::InYoungGeneration(*fixed_array));
  lh->set_data1(MakeWeak(*fixed_array));

  heap::InvokeMajorGC(heap);

  Tagged<HeapObject> heap_object;
  CHECK(lh->data1().GetHeapObjectIfWeak(&heap_object));
  CHECK_EQ(heap_object, *fixed_array);
}

TEST(WeakReferencesOldToNewScavenged) {
  if (v8_flags.single_generation) return;
  // Like WeakReferencesBasic, but the updated weak slot is in the old space,
  // and referring to an new space object, which is then scavenged.
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  Heap* heap = isolate->heap();

  HandleScope outer_scope(isolate);
  DirectHandle<LoadHandler> lh =
      CreateLoadHandlerForTest(factory, AllocationType::kOld);
  CHECK(heap->InOldSpace(*lh));

  // Create a new FixedArray which the LoadHandler will point to.
  DirectHandle<FixedArray> fixed_array = factory->NewFixedArray(1);
  CHECK(HeapLayout::InYoungGeneration(*fixed_array));
  lh->set_data1(MakeWeak(*fixed_array));

  heap::InvokeMinorGC(heap);

  Tagged<HeapObject> heap_object;
  CHECK(lh->data1().GetHeapObjectIfWeak(&heap_object));
  CHECK_EQ(heap_object, *fixed_array);
}

TEST(WeakReferencesOldToCleared) {
  // Like WeakReferencesBasic, but the updated weak slot is in the old space,
  // and is cleared.
  ManualGCScope manual_gc_scope;
  heap::ManualEvacuationCandidatesSelectionScope
      manual_evacuation_candidate_selection_scope(manual_gc_scope);
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  Heap* heap = isolate->heap();

  HandleScope outer_scope(isolate);
  DirectHandle<LoadHandler> lh =
      CreateLoadHandlerForTest(factory, AllocationType::kOld);
  CHECK(heap->InOldSpace(*lh));
  lh->set_data1(ClearedValue(isolate));

  heap::InvokeMajorGC(heap);
  CHECK(lh->data1().IsCleared());
}

TEST(ObjectMovesBeforeClearingWeakField) {
  if (!v8_flags.incremental_marking || v8_flags.single_generation ||
      v8_flags.separate_gc_phases) {
    return;
  }
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  Heap* heap = isolate->heap();
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);

  HandleScope outer_scope(isolate);
  IndirectHandle<LoadHandler> lh = CreateLoadHandlerForTest(factory);
  CHECK(InCorrectGeneration(*lh));
  Address lh_object_location = lh->address();
  {
    HandleScope inner_scope(isolate);
    // Create a new FixedArray which the LoadHandler will point to.
    IndirectHandle<FixedArray> fixed_array = factory->NewFixedArray(1);
    CHECK(HeapLayout::InYoungGeneration(*fixed_array));
    lh->set_data1(MakeWeak(*fixed_array));
    // inner_scope will go out of scope, so when marking the next time,
    // *fixed_array will stay white.
  }

  // Do marking steps; this will store *lh into the list for later processing
  // (since it points to a white object).
  SimulateIncrementalMarking(heap, true);

  // Scavenger will move *lh.
  heap::InvokeMinorGC(heap);
  CHECK_NE(lh_object_location, lh.address());
  CHECK(lh->data1().IsWeak());

  // Now we try to clear *lh.
  heap::InvokeMajorGC(heap);
  CHECK(lh->data1().IsCleared());
}

TEST(ObjectWithWeakFieldDies) {
  if (!v8_flags.incremental_marking) {
    return;
  }
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  Heap* heap = isolate->heap();

  {
    HandleScope outer_scope(isolate);
    DirectHandle<LoadHandler> lh = CreateLoadHandlerForTest(factory);
    CHECK(InCorrectGeneration(*lh));
    {
      HandleScope inner_scope(isolate);
      // Create a new FixedArray which the LoadHandler will point to.
      DirectHandle<FixedArray> fixed_array = factory->NewFixedArray(1);
      CHECK(InCorrectGeneration(*fixed_array));
      lh->set_data1(MakeWeak(*fixed_array));
      // inner_scope will go out of scope, so when marking the next time,
      // *fixed_array will stay white.
    }

    // Do marking steps; this will store *lh into the list for later processing
    // (since it points to a white object).
    SimulateIncrementalMarking(heap, true);
  }  // outer_scope goes out of scope

  // lh will die
  heap::InvokeMinorGC(heap);

  // This used to crash when processing the dead weak reference.
  heap::InvokeMajorGC(heap);
}

TEST(ObjectWithWeakReferencePromoted) {
  if (v8_flags.single_generation) return;
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  Heap* heap = isolate->heap();

  HandleScope outer_scope(isolate);
  DirectHandle<LoadHandler> lh = CreateLoadHandlerForTest(factory);
  CHECK(HeapLayout::InYoungGeneration(*lh));

  // Create a new FixedArray which the LoadHandler will point to.
  DirectHandle<FixedArray> fixed_array = factory->NewFixedArray(1);
  CHECK(HeapLayout::InYoungGeneration(*fixed_array));
  lh->set_data1(MakeWeak(*fixed_array));

  heap::EmptyNewSpaceUsingGC(heap);
  CHECK(heap->InOldSpace(*lh));
  CHECK(heap->InOldSpace(*fixed_array));

  Tagged<HeapObject> heap_object;
  CHECK(lh->data1().GetHeapObjectIfWeak(&heap_object));
  CHECK_EQ(heap_object, *fixed_array);
}

TEST(ObjectWithClearedWeakReferencePromoted) {
  if (v8_flags.single_generation || v8_flags.stress_incremental_marking) return;
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  Heap* heap = isolate->heap();

  HandleScope outer_scope(isolate);
  DirectHandle<LoadHandler> lh = CreateLoadHandlerForTest(factory);
  CHECK(HeapLayout::InYoungGeneration(*lh));

  lh->set_data1(ClearedValue(isolate));

  heap::EmptyNewSpaceUsingGC(heap);
  CHECK(heap->InOldSpace(*lh));
  CHECK(lh->data1().IsCleared());

  heap::InvokeMajorGC(heap);
  CHECK(lh->data1().IsCleared());
}

TEST(WeakReferenceWriteBarrier) {
  if (!v8_flags.incremental_marking) {
    return;
  }

  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  Heap* heap = isolate->heap();

  HandleScope outer_scope(isolate);
  Handle<LoadHandler> lh = CreateLoadHandlerForTest(factory);
  CHECK(InCorrectGeneration(*lh));

  v8::Global<Value> global_lh(CcTest::isolate(), Utils::ToLocal(lh));

  {
    HandleScope inner_scope(isolate);

    // Create a new FixedArray which the LoadHandler will point to.
    DirectHandle<FixedArray> fixed_array1 = factory->NewFixedArray(1);
    CHECK(InCorrectGeneration(*fixed_array1));
    lh->set_data1(MakeWeak(*fixed_array1));

    SimulateIncrementalMarking(heap, true);

    DirectHandle<FixedArray> fixed_array2 = factory->NewFixedArray(1);
    CHECK(InCorrectGeneration(*fixed_array2));
    // This write will trigger the write barrier.
    lh->set_data1(MakeWeak(*fixed_array2));
  }

  heap::InvokeMajorGC(heap);

  // Check that the write barrier treated the weak reference as strong.
  CHECK(lh->data1().IsWeak());
}

TEST(EmptyWeakArray) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  HandleScope outer_scope(isolate);

  DirectHandle<WeakFixedArray> array = factory->empty_weak_fixed_array();
  CHECK(IsWeakFixedArray(*array));
  CHECK(!IsFixedArray(*array));
  CHECK_EQ(array->length(), 0);
}

TEST(WeakArraysBasic) {
  if (v8_flags.single_generation) return;

  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  Heap* heap = isolate->heap();
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
  HandleScope outer_scope(isolate);

  const int length = 4;
  IndirectHandle<WeakFixedArray> array = factory->NewWeakFixedArray(length);
  CHECK(IsWeakFixedArray(*array));
  CHECK(!IsFixedArray(*array));
  CHECK_EQ(array->length(), length);

  CHECK(HeapLayout::InYoungGeneration(*array));

  for (int i = 0; i < length; ++i) {
    Tagged<HeapObject> heap_object;
    CHECK(array->get(i).GetHeapObjectIfStrong(&heap_object));
    CHECK_EQ(heap_object, ReadOnlyRoots(heap).undefined_value());
  }

  IndirectHandle<HeapObject> saved;
  {
    HandleScope inner_scope(isolate);
    IndirectHandle<FixedArray> index0 = factory->NewFixedArray(1);
    index0->set(0, Smi::FromInt(2016));
    IndirectHandle<FixedArray> index1 = factory->NewFixedArray(1);
    index1->set(0, Smi::FromInt(2017));

    IndirectHandle<FixedArray> index2 = factory->NewFixedArray(1);
    index2->set(0, Smi::FromInt(2018));
    IndirectHandle<FixedArray> index3 = factory->NewFixedArray(1);
    index3->set(0, Smi::FromInt(2019));

    array->set(0, MakeWeak(*index0));
    array->set(1, MakeWeak(*index1));
    array->set(2, *index2);
    array->set(3, MakeWeak(*index3));
    saved = inner_scope.CloseAndEscape(index1);
  }  // inner_scope goes out of scope.

  // The references are only cleared by the mark-compact (scavenger treats weak
  // references as strong). Thus we need to GC until the array reaches old
  // space.

  // TODO(marja): update this when/if we do handle weak references in the new
  // space.
  heap::InvokeMinorGC(heap);
  Tagged<HeapObject> heap_object;
  CHECK(array->get(0).GetHeapObjectIfWeak(&heap_object));
  CHECK_EQ(Cast<Smi>(Cast<FixedArray>(heap_object)->get(0)).value(), 2016);
  CHECK(array->get(1).GetHeapObjectIfWeak(&heap_object));
  CHECK_EQ(Cast<Smi>(Cast<FixedArray>(heap_object)->get(0)).value(), 2017);
  CHECK(array->get(2).GetHeapObjectIfStrong(&heap_object));
  CHECK_EQ(Cast<Smi>(Cast<FixedArray>(heap_object)->get(0)).value(), 2018);
  CHECK(array->get(3).GetHeapObjectIfWeak(&heap_object));
  CHECK_EQ(Cast<Smi>(Cast<FixedArray>(heap_object)->get(0)).value(), 2019);

  heap::InvokeMajorGC(heap);
  CHECK(heap->InOldSpace(*array));
  CHECK(array->get(0).IsCleared());
  CHECK(array->get(1).GetHeapObjectIfWeak(&heap_object));
  CHECK_EQ(Cast<Smi>(Cast<FixedArray>(heap_object)->get(0)).value(), 2017);
  CHECK(array->get(2).GetHeapObjectIfStrong(&heap_object));
  CHECK_EQ(Cast<Smi>(Cast<FixedArray>(heap_object)->get(0)).value(), 2018);
  CHECK(array->get(3).IsCleared());
}

TEST(WeakArrayListBasic) {
  if (v8_flags.single_generation) return;

  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  Heap* heap = isolate->heap();
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
  HandleScope outer_scope(isolate);

  Handle<WeakArrayList> array(ReadOnlyRoots(heap).empty_weak_array_list(),
                              isolate);
  CHECK(IsWeakArrayList(*array));
  CHECK(!IsFixedArray(*array));
  CHECK(!IsWeakFixedArray(*array));
  CHECK_EQ(array->length(), 0);

  Handle<FixedArray> index2 = factory->NewFixedArray(1);
  index2->set(0, Smi::FromInt(2017));

  {
    HandleScope inner_scope(isolate);
    Handle<FixedArray> index0 = factory->NewFixedArray(1);
    index0->set(0, Smi::FromInt(2016));
    Handle<FixedArray> index4 = factory->NewFixedArray(1);
    index4->set(0, Smi::FromInt(2018));
    Handle<FixedArray> index6 = factory->NewFixedArray(1);
    index6->set(0, Smi::FromInt(2019));

    array = WeakArrayList::AddToEnd(isolate, array,
                                    MaybeObjectDirectHandle::Weak(index0));
    array = WeakArrayList::AddToEnd(
        isolate, array, MaybeObjectDirectHandle(Smi::FromInt(1), isolate));
    CHECK_EQ(array->length(), 2);

    array = WeakArrayList::AddToEnd(isolate, array,
                                    MaybeObjectDirectHandle::Weak(index2));
    array = WeakArrayList::AddToEnd(
        isolate, array, MaybeObjectDirectHandle(Smi::FromInt(3), isolate));
    CHECK_EQ(array->length(), 4);

    array = WeakArrayList::AddToEnd(isolate, array,
                                    MaybeObjectDirectHandle::Weak(index4));
    array = WeakArrayList::AddToEnd(
        isolate, array, MaybeObjectDirectHandle(Smi::FromInt(5), isolate));
    CHECK_EQ(array->length(), 6);

    array = WeakArrayList::AddToEnd(isolate, array,
                                    MaybeObjectDirectHandle::Weak(index6));
    array = WeakArrayList::AddToEnd(
        isolate, array, MaybeObjectDirectHandle(Smi::FromInt(7), isolate));
    CHECK_EQ(array->length(), 8);

    CHECK(InCorrectGeneration(*array));

    CHECK_EQ(array->get(0), MakeWeak(*index0));
    CHECK_EQ(array->get(1).ToSmi().value(), 1);

    CHECK_EQ(array->get(2), MakeWeak(*index2));
    CHECK_EQ(array->get(3).ToSmi().value(), 3);

    CHECK_EQ(array->get(4), MakeWeak(*index4));
    CHECK_EQ(array->get(5).ToSmi().value(), 5);

    CHECK_EQ(array->get(6), MakeWeak(*index6));
    array = inner_scope.CloseAndEscape(array);
  }  // inner_scope goes out of scope.

  // The references are only cleared by the mark-compact (scavenger treats weak
  // references as strong). Thus we need to GC until the array reaches old
  // space.

  // TODO(marja): update this when/if we do handle weak references in the new
  // space.
  heap::InvokeMinorGC(heap);
  Tagged<HeapObject> heap_object;
  CHECK_EQ(array->length(), 8);
  CHECK(array->get(0).GetHeapObjectIfWeak(&heap_object));
  CHECK_EQ(Cast<Smi>(Cast<FixedArray>(heap_object)->get(0)).value(), 2016);
  CHECK_EQ(array->get(1).ToSmi().value(), 1);

  CHECK(array->get(2).GetHeapObjectIfWeak(&heap_object));
  CHECK_EQ(Cast<Smi>(Cast<FixedArray>(heap_object)->get(0)).value(), 2017);
  CHECK_EQ(array->get(3).ToSmi().value(), 3);

  CHECK(array->get(4).GetHeapObjectIfWeak(&heap_object));
  CHECK_EQ(Cast<Smi>(Cast<FixedArray>(heap_object)->get(0)).value(), 2018);
  CHECK_EQ(array->get(5).ToSmi().value(), 5);

  CHECK(array->get(6).GetHeapObjectIfWeak(&heap_object));
  CHECK_EQ(Cast<Smi>(Cast<FixedArray>(heap_object)->get(0)).value(), 2019);
  CHECK_EQ(array->get(7).ToSmi().value(), 7);

  heap::InvokeMajorGC(heap);
  CHECK(heap->InOldSpace(*array));
  CHECK_EQ(array->length(), 8);
  CHECK(array->get(0).IsCleared());
  CHECK_EQ(array->get(1).ToSmi().value(), 1);

  CHECK(array->get(2).GetHeapObjectIfWeak(&heap_object));
  CHECK_EQ(Cast<Smi>(Cast<FixedArray>(heap_object)->get(0)).value(), 2017);
  CHECK_EQ(array->get(3).ToSmi().value(), 3);

  CHECK(array->get(4).IsCleared());
  CHECK_EQ(array->get(5).ToSmi().value(), 5);

  CHECK(array->get(6).IsCleared());
  CHECK_EQ(array->get(7).ToSmi().value(), 7);
}

TEST(WeakArrayListRemove) {
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  Heap* heap = isolate->heap();
  HandleScope outer_scope(isolate);

  Handle<WeakArrayList> array(ReadOnlyRoots(heap).empty_weak_array_list(),
                              isolate);

  Handle<FixedArray> elem0 = factory->NewFixedArray(1);
  Handle<FixedArray> elem1 = factory->NewFixedArray(1);
  Handle<FixedArray> elem2 = factory->NewFixedArray(1);

  array = WeakArrayList::AddToEnd(isolate, array,
                                  MaybeObjectDirectHandle::Weak(elem0));
  array = WeakArrayList::AddToEnd(isolate, array,
                                  MaybeObjectDirectHandle::Weak(elem1));
  array = WeakArrayList::AddToEnd(isolate, array,
                                  MaybeObjectDirectHandle::Weak(elem2));

  CHECK_EQ(array->length(), 3);
  CHECK_EQ(array->get(0), MakeWeak(*elem0));
  CHECK_EQ(array->get(1), MakeWeak(*elem1));
  CHECK_EQ(array->get(2), MakeWeak(*elem2));

  CHECK(array->RemoveOne(MaybeObjectDirectHandle::Weak(elem1)));

  CHECK_EQ(array->length(), 2);
  CHECK_EQ(array->get(0), MakeWeak(*elem0));
  CHECK_EQ(array->get(1), MakeWeak(*elem2));

  CHECK(!array->RemoveOne(MaybeObjectDirectHandle::Weak(elem1)));

  CHECK_EQ(array->length(), 2);
  CHECK_EQ(array->get(0), MakeWeak(*elem0));
  CHECK_EQ(array->get(1), MakeWeak(*elem2));

  CHECK(array->RemoveOne(MaybeObjectDirectHandle::Weak(elem0)));

  CHECK_EQ(array->length(), 1);
  CHECK_EQ(array->get(0), MakeWeak(*elem2));

  CHECK(array->RemoveOne(MaybeObjectDirectHandle::Weak(elem2)));

  CHECK_EQ(array->length(), 0);
}

TEST(Regress7768) {
  i::v8_flags.allow_natives_syntax = true;
  i::v8_flags.turbo_inlining = false;
  if (!v8_flags.incremental_marking) {
    return;
  }
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  LocalContext context;
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  HandleScope outer_scope(isolate);
  // Create an optimized code which will contain a weak reference to another
  // function ("f"). The weak reference is the only reference to the function.
  CompileRun(
      "function myfunc(f) { f(); } "
      "%PrepareFunctionForOptimization(myfunc); "
      "(function wrapper() { "
      "   function f() {}; myfunc(f); myfunc(f); "
      "   %OptimizeFunctionOnNextCall(myfunc); myfunc(f); "
      "   %ClearFunctionFeedback(wrapper);"
      "})(); "
      "%ClearFunctionFeedback(myfunc);");

  // Do marking steps; this will store the objects pointed by myfunc for later
  // processing.
  SimulateIncrementalMarking(heap, true);

  // Deoptimize the code; now the pointers inside it will be replaced with
  // undefined, and the weak_objects_in_code is the only place pointing to the
  // function f.
  CompileRun("%DeoptimizeFunction(myfunc);");

  // The object pointed to by the weak reference won't be scavenged.
  heap::InvokeMinorGC(heap);

  // Make sure the memory where it's stored is invalidated, so that we'll crash
  // if we try to access it.
  HeapTester::UncommitUnusedMemory(heap);

  // This used to crash when processing the dead weak reference.
  heap::InvokeMajorGC(heap);
}

TEST(PrototypeUsersBasic) {
  CcTest::InitializeVM();
  LocalContext context;
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  Heap* heap = isolate->heap();
  HandleScope outer_scope(isolate);

  Handle<WeakArrayList> array(ReadOnlyRoots(heap).empty_weak_array_list(),
                              isolate);

  // Add some objects into the array.
  int index = -1;
  {
    DirectHandle<Map> map = factory->NewContextfulMapForCurrentContext(
        JS_OBJECT_TYPE, JSObject::kHeaderSize);
    array = PrototypeUsers::Add(isolate, array, map, &index);
    CHECK_EQ(array->length(), index + 1);
  }
  CHECK_EQ(index, 1);

  int empty_index = index;
  PrototypeUsers::MarkSlotEmpty(*array, empty_index);

  // Even though we have an empty slot, we still add to the end.
  int last_index = index;
  int old_capacity = array->capacity();
  while (!array->IsFull()) {
    DirectHandle<Map> map = factory->NewContextfulMapForCurrentContext(
        JS_OBJECT_TYPE, JSObject::kHeaderSize);
    array = PrototypeUsers::Add(isolate, array, map, &index);
    CHECK_EQ(index, last_index + 1);
    CHECK_EQ(array->length(), index + 1);
    last_index = index;
  }

  // The next addition will fill the empty slot.
  {
    DirectHandle<Map> map = factory->NewContextfulMapForCurrentContext(
        JS_OBJECT_TYPE, JSObject::kHeaderSize);
    array = PrototypeUsers::Add(isolate, array, map, &index);
  }
  CHECK_EQ(index, empty_index);

  // The next addition will make the arrow grow again.
  {
    DirectHandle<Map> map = factory->NewContextfulMapForCurrentContext(
        JS_OBJECT_TYPE, JSObject::kHeaderSize);
    array = PrototypeUsers::Add(isolate, array, map, &index);
    CHECK_EQ(array->length(), index + 1);
    last_index = index;
  }
  CHECK_GT(array->capacity(), old_capacity);

  // Make multiple slots empty.
  int empty_index1 = 1;
  int empty_index2 = 2;
  PrototypeUsers::MarkSlotEmpty(*array, empty_index1);
  PrototypeUsers::MarkSlotEmpty(*array, empty_index2);

  // Fill the array (still adding to the end)
  old_capacity = array->capacity();
  while (!array->IsFull()) {
    DirectHandle<Map> map = factory->NewContextfulMapForCurrentContext(
        JS_OBJECT_TYPE, JSObject::kHeaderSize);
    array = PrototypeUsers::Add(isolate, array, map, &index);
    CHECK_EQ(index, last_index + 1);
    CHECK_EQ(array->length(), index + 1);
    last_index = index;
  }

  // Make sure we use the empty slots in (reverse) order.
  {
    DirectHandle<Map> map = factory->NewContextfulMapForCurrentContext(
        JS_OBJECT_TYPE, JSObject::kHeaderSize);
    array = PrototypeUsers::Add(isolate, array, map, &index);
  }
  CHECK_EQ(index, empty_index2);

  {
    DirectHandle<Map> map = factory->NewContextfulMapForCurrentContext(
        JS_OBJECT_TYPE, JSObject::kHeaderSize);
    array = PrototypeUsers::Add(isolate, array, map, &index);
  }
  CHECK_EQ(index, empty_index1);
}

namespace {

Tagged<HeapObject> saved_heap_object;

static void TestCompactCallback(Tagged<HeapObject> value, int old_index,
                                int new_index) {
  saved_heap_object = value;
  CHECK_EQ(old_index, 2);
  CHECK_EQ(new_index, 1);
}

}  // namespace

TEST(PrototypeUsersCompacted) {
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  LocalContext context;
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  Heap* heap = isolate->heap();
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
  HandleScope outer_scope(isolate);

  Handle<WeakArrayList> array(ReadOnlyRoots(heap).empty_weak_array_list(),
                              isolate);

  // Add some objects into the array.
  int index = -1;
  DirectHandle<Map> map_cleared_by_user =
      factory->NewContextfulMapForCurrentContext(JS_OBJECT_TYPE,
                                                 JSObject::kHeaderSize);
  array = PrototypeUsers::Add(isolate, array, map_cleared_by_user, &index);
  CHECK_EQ(index, 1);
  DirectHandle<Map> live_map = factory->NewContextfulMapForCurrentContext(
      JS_OBJECT_TYPE, JSObject::kHeaderSize);
  array = PrototypeUsers::Add(isolate, array, live_map, &index);
  CHECK_EQ(index, 2);
  {
    HandleScope inner_scope(isolate);
    DirectHandle<Map> soon_dead_map =
        factory->NewContextfulMapForCurrentContext(JS_OBJECT_TYPE,
                                                   JSObject::kHeaderSize);
    array = PrototypeUsers::Add(isolate, array, soon_dead_map, &index);
    CHECK_EQ(index, 3);

    array = inner_scope.CloseAndEscape(array);
  }

  PrototypeUsers::MarkSlotEmpty(*array, 1);
  heap::InvokeMajorGC(heap);
  CHECK(array->get(3).IsCleared());

  CHECK_EQ(array->length(), 3 + PrototypeUsers::kFirstIndex);
  Tagged<WeakArrayList> new_array =
      PrototypeUsers::Compact(array, heap, TestCompactCallback);
  CHECK_EQ(new_array->length(), 1 + PrototypeUsers::kFirstIndex);
  CHECK_EQ(saved_heap_object, *live_map);
}

}  // namespace heap
}  // namespace internal
}  // namespace v8

"""

```