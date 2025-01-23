Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Understanding the Goal:**

The core request is to understand what the C++ file `test-weak-references.cc` does within the V8 context. This means figuring out its purpose, how it works, and if it relates to JavaScript concepts.

**2. Initial Code Scan (Keywords and Structure):**

I'd start by quickly scanning the code for familiar C++ testing constructs and V8-specific keywords.

* **`// Copyright`**:  Standard copyright notice, confirms it's V8 code.
* **`#include`**: Includes various V8 headers like `api-inl.h`, `isolate.h`, `heap-inl.h`, `objects/`, and importantly, test-related headers like `test/cctest/cctest.h` and `test/cctest/heap/`. The inclusion of `heap-inl.h` and `objects/` strongly suggests this file is about heap management.
* **`namespace v8 { namespace internal { namespace heap {`**: This namespace structure clearly indicates the code is deeply embedded within V8's internal heap management system.
* **`TEST(...) { ... }`**:  These are the core units of testing in the V8 CCTests framework. Each `TEST` block isolates a specific aspect of functionality.
* **`ManualGCScope`**:  This is a strong hint that the tests are directly controlling garbage collection.
* **`CcTest::InitializeVM()`**: Sets up the V8 virtual machine for testing.
* **`Isolate* isolate = CcTest::i_isolate();`**: Obtains the current V8 isolate, the fundamental unit of execution.
* **`Factory* factory = isolate->factory();`**: Accesses the factory for creating V8 objects.
* **`HandleScope`**: Manages the lifetime of V8 `Handle`s, preventing memory leaks.
* **`MakeWeak(...)`**: A crucial keyword directly related to weak references.
* **`lh->set_data1(...)`**:  Indicates manipulation of object properties.
* **`lh->data1().GetHeapObjectIfWeak(...)`**:  Verifies if a weak reference is still valid.
* **`heap::InvokeMajorGC(...)`, `heap::InvokeMinorGC(...)`**: Explicitly triggers different types of garbage collection.
* **`SimulateIncrementalMarking(...)`**:  Deals with the incremental marking phase of garbage collection.
* **`WeakFixedArray`, `WeakArrayList`, `PrototypeUsers`**:  These data structures directly relate to weak references and their use within V8.

**3. Inferring the Core Functionality:**

Based on the keywords and structure, it's clear this file is dedicated to testing the implementation and behavior of *weak references* within V8's heap. The individual `TEST` cases likely cover different scenarios and edge cases related to how weak references interact with garbage collection.

**4. Analyzing Individual `TEST` Cases:**

I'd go through each `TEST` function, trying to understand its specific focus:

* **`WeakReferencesBasic`**: A fundamental test of creating, using, and observing the clearing of a weak reference during GC.
* **`WeakReferencesOldToOld`, `WeakReferencesOldToNew`, `WeakReferencesOldToNewScavenged`**: These explore how weak references behave when the referencing and referenced objects are in different generations (old space vs. young space) and under different GC scenarios (major vs. minor/scavenge).
* **`WeakReferencesOldToCleared`**: Tests explicitly setting a weak reference to a cleared state.
* **`ObjectMovesBeforeClearingWeakField`**: Focuses on the interaction between object movement (during scavenge) and the clearing of weak references during concurrent GC.
* **`ObjectWithWeakFieldDies`**:  Tests the scenario where the object *holding* the weak reference becomes garbage.
* **`ObjectWithWeakReferencePromoted`, `ObjectWithClearedWeakReferencePromoted`**: Examines weak references when objects are promoted from young to old generation.
* **`WeakReferenceWriteBarrier`**: Tests the write barrier's role in ensuring weak references are correctly handled during concurrent marking.
* **`EmptyWeakArray`, `WeakArraysBasic`, `WeakArrayListBasic`, `WeakArrayListRemove`**: These focus on specific data structures for holding weak references (weak arrays and weak array lists) and their basic operations.
* **`Regress7768`**:  Likely a regression test for a specific bug related to weak references in optimized code. The use of `%PrepareFunctionForOptimization` and `%DeoptimizeFunction` points to testing the interaction between the compiler and garbage collector.
* **`PrototypeUsersBasic`, `PrototypeUsersCompacted`**: These tests explore a specific use case of weak references, likely related to tracking objects that inherit from a prototype.

**5. Connecting to JavaScript (if applicable):**

The core concept of weak references is present in JavaScript through the `WeakRef` and `WeakMap`/`WeakSet` objects. I'd consider how the C++ tests relate to the observable behavior of these JavaScript features. For example:

* A C++ test showing a weak reference being cleared after GC directly corresponds to a `WeakRef`'s `deref()` method returning `undefined` in JavaScript after the referenced object is collected.
* Tests involving `WeakFixedArray` and `WeakArrayList` in C++ are the underlying mechanisms for `WeakMap` and `WeakSet` in JavaScript.

**6. Code Logic Inference (Hypothetical Input/Output):**

For tests like `WeakReferencesBasic`, I'd think about the expected state transitions:

* **Input:** Create a `LoadHandler` with a weak reference to a `Code` object.
* **Action:** Trigger major GC.
* **Expected Output:** The weak reference should remain valid as long as the `Code` object is reachable. After the `Code` object goes out of scope and another GC occurs, the weak reference should be cleared.

**7. Common Programming Errors:**

Relating back to JavaScript, common errors when using weak references include:

* **Assuming immediate cleanup:**  Weak references don't guarantee immediate garbage collection.
* **Accidentally holding strong references:** If there are other strong references to the target object, the weak reference won't be cleared.
* **Misunderstanding the timing of callbacks (in the context of `FinalizationRegistry`, which is related):**  Finalization callbacks associated with weak references might not execute immediately after the object becomes weakly reachable.

**8. Refining the Explanation:**

Finally, I'd structure the explanation clearly, addressing each part of the prompt:

* **Functionality:**  Provide a high-level overview and then details of each test case.
* **Torque:** Check the file extension.
* **JavaScript Relationship:**  Explain the connection and provide illustrative examples.
* **Code Logic:**  Give concrete input/output scenarios for relevant tests.
* **Common Errors:**  List common pitfalls related to weak references in a general programming context (and specifically JavaScript, given the context).
Based on the provided V8 source code file `v8/test/cctest/heap/test-weak-references.cc`, here's a breakdown of its functionality:

**Core Functionality:**

This C++ file contains unit tests specifically designed to verify the correct implementation and behavior of **weak references** within V8's garbage collection (GC) system. Weak references are a mechanism that allows an object to hold a reference to another object without preventing the referenced object from being garbage collected if there are no other strong references to it.

Here's a breakdown of the key aspects being tested:

* **Basic Weak Reference Functionality:**  Testing the fundamental creation, setting, and clearing of weak references during both major (full) and minor (scavenge) garbage collection cycles.
* **Weak References Across Generations:**  Examining how weak references behave when the referencing object and the referenced object reside in different memory generations (young generation, old generation). This includes scenarios where the referenced object is promoted from young to old space.
* **Interaction with Garbage Collection Phases:** Testing how weak references are handled during different phases of garbage collection, including incremental marking, scavenging, and full GC.
* **Write Barriers for Weak References:** Ensuring that the write barrier mechanism correctly handles updates to weak references, particularly during concurrent garbage collection. The write barrier is crucial for maintaining the consistency of the heap during concurrent operations.
* **Weak Containers (WeakFixedArray and WeakArrayList):**  Testing specialized data structures designed to hold weak references. These tests verify how elements in these arrays are cleared when the referenced objects are garbage collected.
* **Prototype User Tracking (PrototypeUsers):**  Testing a specific use case of weak references for tracking objects that inherit from a particular prototype. This likely involves ensuring that when a prototype is no longer strongly referenced, the references to its users are cleared.
* **Regression Tests:** Including tests that specifically address previously identified bugs related to weak references (e.g., `Regress7768`).
* **Scenarios Involving Object Movement:** Checking how weak references are updated when the objects holding them are moved in memory during garbage collection (specifically during scavenging).
* **Scenarios Where the Referencing Object Dies:** Testing the case where the object holding the weak reference itself becomes garbage.

**Is it a Torque file?**

No, the file extension is `.cc`, which is the standard extension for C++ source files. If it were a Torque file, it would have the `.tq` extension.

**Relationship to JavaScript Functionality:**

Weak references in C++ within V8 are the underlying mechanism that enables similar concepts in JavaScript:

* **`WeakRef`:** The `WeakRef` object in JavaScript allows you to hold a weak reference to another object. The C++ tests in this file are fundamentally testing the machinery that makes `WeakRef` work.
* **`WeakMap` and `WeakSet`:** These JavaScript collections hold keys (for `WeakMap`) or values (for `WeakSet`) weakly. The `WeakFixedArray` and `WeakArrayList` tests in the C++ code are directly related to the internal implementation of these JavaScript features.

**JavaScript Example:**

```javascript
let target = { data: "important" };
const weakTarget = new WeakRef(target);

console.log(weakTarget.deref()?.data); // Output: "important"

// Remove the strong reference
target = null;

// Force garbage collection (not guaranteed to happen immediately)
// In a real browser, this happens automatically.
if (global.gc) {
  global.gc();
}

console.log(weakTarget.deref()); // Output: undefined (or the object if GC hasn't run yet)

const map = new WeakMap();
let key = {};
let value = { info: "some info" };
map.set(key, value);

console.log(map.get(key)); // Output: { info: "some info" }

key = null;

if (global.gc) {
  global.gc();
}

console.log(map.get({})); // Output: undefined (because the original 'key' is gone)
```

**Code Logic Inference (Hypothetical Input and Output):**

Let's take the `TEST(WeakReferencesBasic)` as an example:

**Hypothetical Input:**

1. Create a `LoadHandler` object (`lh`).
2. Create a `Code` object.
3. Create a weak reference from `lh` to the `wrapper` of the `Code` object.

**Actions:**

1. Invoke a major garbage collection.
2. The `Code` object is still reachable within the inner scope.
3. The inner scope ends, and the strong reference to the `Code` object is gone.
4. Invoke another major garbage collection.

**Expected Output:**

1. After the first major GC, the weak reference in `lh` still points to the `Code` object's wrapper.
2. After the second major GC (after the `Code` object is no longer strongly reachable), the weak reference in `lh` is cleared (becomes a cleared value).

**Common Programming Errors (Related to Weak References):**

While the C++ code tests the *implementation* of weak references, here are some common programming errors developers might encounter when *using* weak references (especially in JavaScript):

* **Assuming Immediate Cleanup:**  A common mistake is to expect a weakly referenced object to be garbage collected *immediately* after its strong references are gone. Garbage collection is non-deterministic, and the timing can vary.
* **Accidentally Holding Strong References:** If there are still unintended strong references to the target object, the weak reference will not be cleared. This can happen due to closures, global variables, or other parts of the program unexpectedly keeping a reference.
    ```javascript
    let target = { data: "important" };
    const weakTarget = new WeakRef(target);

    // Oops, accidentally created a strong reference in a closure
    const checkTarget = () => console.log(target?.data);

    target = null;
    if (global.gc) global.gc();

    console.log(weakTarget.deref()); // Might still be the object because 'checkTarget' holds a reference
    ```
* **Misunderstanding WeakMap/WeakSet Key Identity:** For `WeakMap` and `WeakSet`, the key (for `WeakMap`) or the value (for `WeakSet`) must be an object. Primitive values cannot be used as weak keys/values because they are not subject to garbage collection in the same way.
    ```javascript
    const weakMap = new WeakMap();
    weakMap.set("a string", {}); // This won't work as intended. The string is not weakly held.

    let keyObj = {};
    weakMap.set(keyObj, { data: 1 });
    keyObj = null;
    // The entry in weakMap associated with the *original* keyObj will eventually be removed.
    ```
* **Trying to Iterate Over Weak Collections:**  `WeakMap` and `WeakSet` are not iterable. This is because the presence of an entry depends on the garbage collection status of the key/value. If you could iterate, you might get inconsistent results as items are garbage collected during iteration.

In summary, `v8/test/cctest/heap/test-weak-references.cc` is a crucial part of V8's testing infrastructure, ensuring the robustness and correctness of its weak reference implementation, which directly underpins important memory management features in both the V8 engine and JavaScript itself.

### 提示词
```
这是目录为v8/test/cctest/heap/test-weak-references.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/heap/test-weak-references.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```