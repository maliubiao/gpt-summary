Response:
Let's break down the thought process for analyzing the provided C++ code snippet and generating the response.

**1. Initial Understanding of the Request:**

The core request is to analyze a C++ source file (`v8/test/cctest/heap/test-heap.cc`) from the V8 JavaScript engine and describe its functionality. Specific instructions include checking for Torque files (`.tq`), relating functionality to JavaScript, providing examples, handling code logic, identifying common programming errors, and summarizing the overall purpose. This is part 9 of a larger series, so the summary should reflect that.

**2. High-Level Overview of the Code:**

A quick scan reveals that the code is primarily composed of `TEST` macros. This strongly suggests that it's a unit test file. The test names often include keywords like "Regress," "Memory," "Allocate," and "GarbageCollection," which point towards testing the V8 heap management system.

**3. Analyzing Individual Tests (Iterative Process):**

For each `TEST` block, the analysis should follow a pattern:

* **Identify the Test Name and Keywords:** This gives a strong hint about the test's purpose (e.g., `MemoryReducerActivationForSmallHeaps` clearly tests the memory reducer).
* **Examine the Code within the Test:** Look for key V8 API calls and the assertions (`CHECK`, `CHECK_EQ`, `CHECK_LE`, `CHECK_NULL`).
* **Determine the Functionality Being Tested:**  Based on the API calls and assertions, deduce what aspect of the heap is being exercised. For example, `heap->NewFixedArray()` suggests memory allocation, `heap->MemoryPressureNotification()` tests memory pressure handling, and `heap::InvokeMajorGC()` tests garbage collection.
* **Relate to JavaScript (If Possible):** Consider how the tested C++ functionality translates to JavaScript behavior. This might involve memory allocation, garbage collection, or performance characteristics.
* **Construct a JavaScript Example (If Applicable):**  Create a concise JavaScript snippet that demonstrates the underlying concept.
* **Infer Code Logic (If Present):**  If the test involves a sequence of actions, identify the assumptions and expected outcomes. This often involves setting up specific heap states and then triggering an event.
* **Identify Potential Programming Errors:**  Think about common mistakes a developer might make related to the tested functionality (e.g., memory leaks, unexpected garbage collection behavior).
* **Note any Specific Conditions or Flags:** Pay attention to `if` statements that check V8 flags (`v8_flags.incremental_marking`, `v8_flags.memory_reducer`, etc.). These indicate specific scenarios being tested.

**Example of Detailed Analysis for `TEST(Regress8617)`:**

1. **Test Name:** `Regress8617` (likely a test for a specific bug fix).
2. **Keywords:** "incremental_marking," "Mark-Compact," "descriptor array."
3. **Code Examination:**
   - Checks `v8_flags.incremental_marking`.
   - Uses `SimulateFullSpace` and `EmptyNewSpaceUsingGC` to control heap state.
   - Compiles and runs JavaScript code snippets using `CompileRun`.
   - Manipulates object properties (`obj.method`, `obj.bar`).
   - Uses `ForceEvacuationCandidate` to influence object movement during GC.
   - Calls `SimulateIncrementalMarking` and `InvokeMajorGC`.
4. **Functionality:** Tests a specific scenario involving incremental marking, object migration during Mark-Compact garbage collection, and the handling of descriptor arrays. The test aims to reproduce a bug where a stale pointer might be left in a descriptor array after object movement.
5. **JavaScript Relation:**  Relates to how JavaScript objects and their properties are managed in memory and how garbage collection can move objects.
6. **JavaScript Example:**  Shows how adding and accessing properties can trigger the underlying heap operations.
7. **Code Logic:**  A sequence of steps is carefully orchestrated to trigger the bug: create an object with a function reference, force the function to move, start incremental marking, modify the object's properties, trigger a scavenge, and then a full GC.
8. **Potential Error:**  Highlights the risk of stale pointers if memory management isn't handled correctly during garbage collection, especially with incremental marking.

**4. Handling Special Instructions:**

* **`.tq` Check:**  A simple string check within the test name or a general check for `.tq` extension.
* **JavaScript Examples:**  Construct simple, illustrative JavaScript code.
* **Code Logic Inference:** Describe the setup, actions, and expected outcomes.
* **Common Programming Errors:** Brainstorm related errors that developers might encounter.

**5. Summarization (Part 9 of 9):**

Since this is the final part, the summary should consolidate the findings from all the tests in this specific file. Emphasize the focus on heap testing, including garbage collection, memory limits, object allocation, and bug regressions. Since it's part of a larger series, acknowledge that this file contributes to the broader testing of V8's heap.

**6. Review and Refinement:**

After the initial analysis, review the generated description for clarity, accuracy, and completeness. Ensure that all aspects of the prompt have been addressed. For instance, double-check that the JavaScript examples are relevant and easy to understand.

**Self-Correction/Refinement Example During Analysis:**

Initially, when looking at the `Regress8617` test, I might just think "it's about incremental marking."  However, a closer look at the manipulation of `obj.method` and `obj.bar`, and the mention of "descriptor array," would lead to a more specific understanding of the bug related to how property access and garbage collection interact. This iterative refinement is crucial for accurate analysis.
This C++ source code file, `v8/test/cctest/heap/test-heap.cc`, is a crucial part of the V8 JavaScript engine's testing infrastructure. Its primary function is to **test various aspects of V8's heap management system**. Let's break down its functionalities based on the provided code snippets:

**Core Functionalities Tested:**

* **Heap Limits and Out-of-Memory Scenarios:**
    * The `OOMWithHeapLimit` test checks how the heap behaves when approaching its memory limit. It simulates allocating a large number of fixed arrays until an out-of-memory condition is triggered.
    * It verifies that a callback function (`NearHeapLimitCallback`) is invoked when the limit is near and that the heap limit can be automatically restored.
    * It uses `MemoryPressureNotification` to simulate external memory pressure.
* **Memory Uncommitment:**
    * `UncommitUnusedMemory` demonstrates how V8 can release unused memory from the heap (specifically the new space and pooled chunks).
* **Managed Objects and Finalization:**
    * `Regress8014` tests the handling of managed external memory. It creates a large number of `Managed` objects with a custom deleter and checks that the number of garbage collections triggered remains within an acceptable range. This verifies that finalization of external resources works correctly.
* **Incremental Marking and Mark-Compact Garbage Collection:**
    * `Regress8617` is a regression test for a bug related to incremental marking and Mark-Compact garbage collection. It simulates a specific sequence of operations involving object creation, property assignment, and garbage collection phases to trigger a previously identified bug related to stale pointers in descriptor arrays.
* **Memory Reducer:**
    * `MemoryReducerActivationForSmallHeaps` verifies that the memory reducer (a mechanism to reduce memory usage) is activated when the old generation heap size exceeds a certain threshold.
* **External Backing Store Allocation:**
    * `AllocateExternalBackingStore` tests the allocation of external memory that is tracked by the V8 heap. It specifically checks the behavior when the allocation fails.
* **Code Object Registry:**
    * `CodeObjectRegistry` tests the mechanism for tracking code objects in memory, ensuring that code objects remain accessible even after garbage collection. It specifically disables compaction to prevent code movement during the test.
* **Scavenging (Minor Garbage Collection):**
    * `Regress9701` tests the behavior of the scavenger (the garbage collector for the young generation) under heavy allocation of short-lived objects (array buffers). It verifies that only scavenges occur and no full garbage collections are triggered.
* **Heap Limit Configuration:**
    * `HugeHeapLimit` and `HeapLimit` (UNINITIALIZED_TESTs) test the ability to configure the maximum heap size when creating a V8 isolate. They verify that the actual maximum old generation size matches the expected value based on the provided constraints.
* **Jitless Mode:**
    * `NoCodeRangeInJitlessMode` verifies that in "jitless" mode (where dynamic code generation is disabled), there is no dedicated code region in the heap.
* **Garbage Collection with Local Heaps:**
    * `GarbageCollectionWithLocalHeap` tests garbage collection interactions when using local heaps (per-thread heaps).
* **Incremental Marking and Byte Arrays:**
    * `Regress10698` is another regression test for incremental marking. It focuses on a specific scenario involving byte array allocation and how the mark-bit pattern is handled during incremental marking.
* **Large Object Allocation:**
    * `CodeLargeObjectSpace` and `CodeLargeObjectSpace64k` test the allocation of large code objects (objects exceeding a certain size threshold). They verify that these objects are allocated in the large object space and that allocation tracking works correctly. The `CodeLargeObjectSpace64k` test simulates a system with a specific OS page size.
* **Pending Allocation Tracking:**
    * `IsPendingAllocationNewSpace`, `IsPendingAllocationNewLOSpace`, `IsPendingAllocationOldSpace`, and `IsPendingAllocationLOSpace` test the `IsPendingAllocation` API, which checks if an object's allocation is still pending (not yet fully committed to the heap). They test this for different heap spaces (new space, large object space, old space).
* **Code Page Compaction:**
    * `Regress10900` tests a scenario involving code page compaction during garbage collection. It allocates multiple code objects to fill code pages and then triggers a memory-reducing garbage collection to ensure that code page compaction doesn't lead to errors.
* **Runtime Stats and Garbage Collection Metrics:**
    * `Regress11181`, `LongTaskStatsFullAtomic`, `LongTaskStatsFullIncremental`, and `LongTaskStatsYoung` test the collection of runtime statistics related to garbage collection. They trigger different types of garbage collections and verify that the corresponding time metrics are recorded correctly.

**If `v8/test/cctest/heap/test-heap.cc` ended with `.tq`:**

If the file ended with `.tq`, it would be a **V8 Torque source code file**. Torque is V8's internal language for writing low-level built-in functions and runtime code. This file, however, is `.cc`, indicating C++ code for testing.

**Relationship to JavaScript and Examples:**

Many of the functionalities tested in this file directly impact JavaScript's behavior, especially regarding memory management and performance. Here are some examples:

* **Heap Limits and OOM:** When JavaScript code attempts to allocate more memory than available, V8's heap limit mechanisms (tested by `OOMWithHeapLimit`) come into play, potentially leading to `OutOfMemoryError` exceptions in the JavaScript runtime.

   ```javascript
   // Example of potentially triggering an OOM error
   let largeArray = [];
   try {
     for (let i = 0; i < 1e9; i++) {
       largeArray.push(i);
     }
   } catch (e) {
     console.error("Caught an error:", e); // Might be an OutOfMemoryError
   }
   ```

* **Garbage Collection:** The tests for different garbage collection strategies (scavenging, Mark-Compact, incremental marking) directly relate to how V8 reclaims unused memory in JavaScript. Developers don't directly control GC, but understanding its behavior is crucial for performance.

   ```javascript
   // JavaScript code creates objects that will eventually be garbage collected
   function createGarbage() {
     let obj1 = { data: new Array(100000).fill(0) };
     let obj2 = { moreData: "some string" };
     // obj1 and obj2 are now eligible for garbage collection when they are no longer reachable
   }
   createGarbage();
   ```

* **Memory Pressure:** The `MemoryPressureNotification` test simulates how V8 responds to external memory pressure, which can affect garbage collection aggressiveness and overall performance.

* **Large Object Allocation:**  When JavaScript creates large objects (e.g., large arrays or strings), V8's large object allocation mechanisms (tested by `CodeLargeObjectSpace`) are used.

   ```javascript
   // Example of creating a potentially large object
   let veryLargeArray = new Array(10000000);
   ```

**Code Logic Inference (Example: `Regress8617`):**

* **Assumption:** A specific sequence of operations involving object creation, property assignment, and incremental marking can expose a bug related to stale pointers in descriptor arrays.
* **Input:**  The test sets up a scenario where a function is created in old space, an object is created referencing this function, and incremental marking is initiated. Then, a new property is added to the object.
* **Output:** The test expects that after a full garbage collection, accessing the original function through the object's property (`obj.method()`) will still work correctly, indicating that the pointer in the descriptor array was updated correctly during garbage collection. If the bug were present, this access would likely crash or produce an incorrect result.

**Common Programming Errors (Related to Tested Functionalities):**

* **Memory Leaks:**  While JavaScript has automatic garbage collection, unintentional memory leaks can still occur if objects are kept alive longer than necessary (e.g., through closures or global variables). The garbage collection tests in this file help ensure V8's GC can handle various object lifecycle scenarios.
* **Performance Issues due to Excessive Allocation:**  Creating too many short-lived objects can put pressure on the garbage collector and impact performance. The `Regress9701` test indirectly relates to this by testing the efficiency of the young generation garbage collector.
* **Unexpected Behavior with Finalizers:** If external resources are managed through finalizers (like in `Regress8014`), errors in the finalizer logic or incorrect assumptions about when finalizers run can lead to resource leaks or other issues.
* **Stale Pointers (Addressed by Regression Tests):**  Bugs like the one targeted by `Regress8617` highlight the potential for errors in garbage collection implementations that can lead to dangling pointers or incorrect memory access.

**归纳一下它的功能 (Summary of its Functionality):**

This `v8/test/cctest/heap/test-heap.cc` file serves as a **comprehensive suite of unit tests for V8's heap management system**. It rigorously examines various aspects of the heap, including:

* **Memory Allocation and Deallocation:** Testing different allocation strategies and the release of unused memory.
* **Garbage Collection:** Verifying the correctness and efficiency of minor (scavenge) and major (Mark-Compact, incremental marking) garbage collection algorithms.
* **Heap Limits and Out-of-Memory Handling:** Ensuring proper behavior when memory limits are approached and during out-of-memory situations.
* **Object Management:** Testing the creation, tracking, and finalization of objects, including managed external memory.
* **Code Object Handling:**  Verifying the mechanisms for managing and accessing compiled code in the heap.
* **Regression Testing:**  Specifically targeting and preventing the reoccurrence of previously identified bugs in the heap management code.
* **Performance-Related Aspects:**  Indirectly assessing the performance of memory management through tests like those involving memory pressure and allocation patterns.
* **Configuration and Mode-Specific Behavior:** Testing heap behavior under different configurations (e.g., heap limits, jitless mode).
* **Runtime Statistics and Metrics:**  Ensuring accurate collection of GC-related performance data.

Essentially, this file plays a vital role in ensuring the **stability, correctness, and performance** of V8's memory management, which is fundamental to the reliable execution of JavaScript code. As part 9 of 9, it represents a significant contribution to the overall testing effort for V8's heap functionality.

Prompt: 
```
这是目录为v8/test/cctest/heap/test-heap.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/heap/test-heap.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第9部分，共9部分，请归纳一下它的功能

"""
e_t kOldGenerationLimit = 50 * MB;
  v8_flags.max_old_space_size = kOldGenerationLimit / MB;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate);
  Heap* heap = i_isolate->heap();
  Factory* factory = i_isolate->factory();

  {
    v8::Isolate::Scope isolate_scope(isolate);
    PtrComprCageAccessScope ptr_compr_cage_access_scope(i_isolate);

    // In this test, we need to invoke GC without stack, otherwise some objects
    // may not be reclaimed because of conservative stack scanning and the heap
    // limit may be reached.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);

    OutOfMemoryState state;
    state.heap = heap;
    state.oom_triggered = false;
    heap->AddNearHeapLimitCallback(NearHeapLimitCallback, &state);
    heap->AutomaticallyRestoreInitialHeapLimit(0.5);
    const int kFixedArrayLength = 1000000;
    {
      HandleScope handle_scope(i_isolate);
      while (!state.oom_triggered) {
        factory->NewFixedArray(kFixedArrayLength);
      }
    }
    heap->MemoryPressureNotification(MemoryPressureLevel::kCritical, true);
    state.oom_triggered = false;
    {
      HandleScope handle_scope(i_isolate);
      while (!state.oom_triggered) {
        factory->NewFixedArray(kFixedArrayLength);
      }
    }
    CHECK_EQ(state.current_heap_limit, state.initial_heap_limit);
  }

  isolate->Dispose();
}

void HeapTester::UncommitUnusedMemory(Heap* heap) {
  if (!v8_flags.minor_ms) SemiSpaceNewSpace::From(heap->new_space())->Shrink();
  heap->memory_allocator()->pool()->ReleasePooledChunks();
}

class DeleteNative {
 public:
  static constexpr ExternalPointerTag kManagedTag = kGenericManagedTag;
  static void Deleter(void* arg) {
    delete reinterpret_cast<DeleteNative*>(arg);
  }
};

TEST(Regress8014) {
  Isolate* isolate = CcTest::InitIsolateOnce();
  Heap* heap = isolate->heap();
  {
    HandleScope scope(isolate);
    for (int i = 0; i < 10000; i++) {
      auto handle = Managed<DeleteNative>::From(
          isolate, 1000000, std::make_shared<DeleteNative>());
      USE(handle);
    }
  }
  int ms_count = heap->ms_count();
  heap->MemoryPressureNotification(MemoryPressureLevel::kCritical, true);
  // Several GCs can be triggred by the above call.
  // The bad case triggers 10000 GCs.
  CHECK_LE(heap->ms_count(), ms_count + 10);
}

TEST(Regress8617) {
  if (!v8_flags.incremental_marking) return;
  ManualGCScope manual_gc_scope;
  heap::ManualEvacuationCandidatesSelectionScope
      manual_evacuation_candidate_selection_scope(manual_gc_scope);
  LocalContext env;
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  HandleScope scope(isolate);
  heap::SimulateFullSpace(heap->old_space());
  // Step 1. Create a function and ensure that it is in the old space.
  DirectHandle<Object> foo =
      v8::Utils::OpenDirectHandle(*CompileRun("function foo() { return 42; };"
                                              "foo;"));
  if (HeapLayout::InYoungGeneration(*foo)) {
    heap::EmptyNewSpaceUsingGC(heap);
  }
  // Step 2. Create an object with a reference to foo in the descriptor array.
  CompileRun(
      "var obj = {};"
      "obj.method = foo;"
      "obj;");
  // Step 3. Make sure that foo moves during Mark-Compact.
  PageMetadata* ec_page = PageMetadata::FromAddress((*foo).ptr());
  heap::ForceEvacuationCandidate(ec_page);
  // Step 4. Start incremental marking.
  heap::SimulateIncrementalMarking(heap, false);
  CHECK(ec_page->Chunk()->IsEvacuationCandidate());
  // Step 5. Install a new descriptor array on the map of the object.
  // This runs the marking barrier for the descriptor array.
  // In the bad case it sets the number of marked descriptors but does not
  // change the color of the descriptor array.
  CompileRun("obj.bar = 10;");
  // Step 6. Promote the descriptor array to old space. During promotion
  // the Scavenger will not record the slot of foo in the descriptor array.
  heap::EmptyNewSpaceUsingGC(heap);
  // Step 7. Complete the Mark-Compact.
  heap::InvokeMajorGC(heap);
  // Step 8. Use the descriptor for foo, which contains a stale pointer.
  CompileRun("obj.method()");
}

HEAP_TEST(MemoryReducerActivationForSmallHeaps) {
  if (v8_flags.single_generation || !v8_flags.memory_reducer) return;
  ManualGCScope manual_gc_scope;
  LocalContext env;
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  CHECK_EQ(heap->memory_reducer()->state_.id(), MemoryReducer::kUninit);
  HandleScope scope(isolate);
  const size_t kActivationThreshold = 1 * MB;
  size_t initial_capacity = heap->OldGenerationCapacity();
  while (heap->OldGenerationCapacity() <
         initial_capacity + kActivationThreshold) {
    isolate->factory()->NewFixedArray(1 * KB, AllocationType::kOld);
  }
  CHECK_EQ(heap->memory_reducer()->state_.id(), MemoryReducer::kWait);
}

TEST(AllocateExternalBackingStore) {
  ManualGCScope manual_gc_scope;
  LocalContext env;
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  int initial_ms_count = heap->ms_count();
  void* result =
      heap->AllocateExternalBackingStore([](size_t) { return nullptr; }, 10);
  CHECK_NULL(result);
  // At least two GCs should happen.
  CHECK_LE(2, heap->ms_count() - initial_ms_count);
}

TEST(CodeObjectRegistry) {
  // We turn off compaction to ensure that code is not moving.
  v8_flags.compact = false;

  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();

  DirectHandle<InstructionStream> code1;
  HandleScope outer_scope(heap->isolate());
  Address code2_address;
  {
    // Ensure that both code objects end up on the same page.
    CHECK(HeapTester::CodeEnsureLinearAllocationArea(
        heap, MemoryChunkLayout::MaxRegularCodeObjectSize()));
    code1 = DummyOptimizedCode(isolate);
    DirectHandle<InstructionStream> code2 = DummyOptimizedCode(isolate);
    code2_address = code2->address();

    CHECK_EQ(MutablePageMetadata::FromHeapObject(*code1),
             MutablePageMetadata::FromHeapObject(*code2));
    CHECK(MutablePageMetadata::FromHeapObject(*code1)->Contains(
        code1->address()));
    CHECK(MutablePageMetadata::FromHeapObject(*code2)->Contains(
        code2->address()));
  }
  heap::InvokeMemoryReducingMajorGCs(heap);
  CHECK(
      MutablePageMetadata::FromHeapObject(*code1)->Contains(code1->address()));
  CHECK(
      MutablePageMetadata::FromAddress(code2_address)->Contains(code2_address));
}

TEST(Regress9701) {
  ManualGCScope manual_gc_scope;
  if (!v8_flags.incremental_marking || v8_flags.separate_gc_phases) return;
  CcTest::InitializeVM();
  Heap* heap = CcTest::heap();
  // Start with an empty new space.
  heap::EmptyNewSpaceUsingGC(heap);

  int mark_sweep_count_before = heap->ms_count();
  // Allocate many short living array buffers.
  for (int i = 0; i < 1000; i++) {
    HandleScope scope(heap->isolate());
    CcTest::i_isolate()->factory()->NewJSArrayBufferAndBackingStore(
        64 * KB, InitializedFlag::kZeroInitialized);
  }
  int mark_sweep_count_after = heap->ms_count();
  // We expect only scavenges, no full GCs.
  CHECK_EQ(mark_sweep_count_before, mark_sweep_count_after);
}

#if defined(V8_TARGET_ARCH_64_BIT) && !defined(V8_OS_ANDROID)
UNINITIALIZED_TEST(HugeHeapLimit) {
  uint64_t kMemoryGB = 16;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  create_params.constraints.ConfigureDefaults(kMemoryGB * GB, kMemoryGB * GB);
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate);
#ifdef V8_COMPRESS_POINTERS
  size_t kExpectedHeapLimit = Heap::AllocatorLimitOnMaxOldGenerationSize();
#else
  size_t kExpectedHeapLimit = size_t{4} * GB;
#endif
  CHECK_EQ(kExpectedHeapLimit, i_isolate->heap()->MaxOldGenerationSize());
  CHECK_LT(size_t{3} * GB, i_isolate->heap()->MaxOldGenerationSize());
  isolate->Dispose();
}
#endif

UNINITIALIZED_TEST(HeapLimit) {
  uint64_t kMemoryGB = 8;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  create_params.constraints.ConfigureDefaults(kMemoryGB * GB, kMemoryGB * GB);
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate);
#if defined(V8_TARGET_ARCH_64_BIT) && !defined(V8_OS_ANDROID)
  size_t kExpectedHeapLimit = size_t{2} * GB;
#else
  size_t kExpectedHeapLimit = size_t{1} * GB;
#endif
  CHECK_EQ(kExpectedHeapLimit, i_isolate->heap()->MaxOldGenerationSize());
  isolate->Dispose();
}

TEST(NoCodeRangeInJitlessMode) {
  if (!v8_flags.jitless) return;
  CcTest::InitializeVM();
  CHECK(CcTest::i_isolate()->heap()->code_region().is_empty());
}

TEST(GarbageCollectionWithLocalHeap) {
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();

  LocalHeap* local_heap = CcTest::i_isolate()->main_thread_local_heap();

  heap::InvokeMajorGC(CcTest::heap());
  local_heap->ExecuteWhileParked([]() { /* nothing */ });
  heap::InvokeMajorGC(CcTest::heap());
}

TEST(Regress10698) {
  if (!v8_flags.incremental_marking) return;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  Factory* factory = isolate->factory();
  HandleScope handle_scope(isolate);
  // This is modeled after the manual allocation folding of heap numbers in
  // JSON parser (See commit ba7b25e).
  // Step 1. Allocate a byte array in the old space.
  DirectHandle<ByteArray> array =
      factory->NewByteArray(kTaggedSize, AllocationType::kOld);
  // Step 2. Start incremental marking.
  SimulateIncrementalMarking(heap, false);
  // Step 3. Allocate another byte array. It will be black.
  factory->NewByteArray(kTaggedSize, AllocationType::kOld);
  Address address = reinterpret_cast<Address>(array->begin());
  Tagged<HeapObject> filler = HeapObject::FromAddress(address);
  // Step 4. Set the filler at the end of the first array.
  // It will have an impossible markbit pattern because the second markbit
  // will be taken from the second array.
  filler->set_map_after_allocation(isolate, *factory->one_pointer_filler_map());
}

class TestAllocationTracker : public HeapObjectAllocationTracker {
 public:
  explicit TestAllocationTracker(int expected_size)
      : expected_size_(expected_size) {}

  void AllocationEvent(Address addr, int size) {
    CHECK(expected_size_ == size);
    address_ = addr;
  }

  Address address() { return address_; }

 private:
  int expected_size_;
  Address address_;
};

HEAP_TEST(CodeLargeObjectSpace) {
  Heap* heap = CcTest::heap();
  int size_in_bytes =
      heap->MaxRegularHeapObjectSize(AllocationType::kCode) + kTaggedSize;
  TestAllocationTracker allocation_tracker{size_in_bytes};
  heap->AddHeapObjectAllocationTracker(&allocation_tracker);

  Tagged<HeapObject> obj;
  {
    AllocationResult allocation = heap->AllocateRaw(
        size_in_bytes, AllocationType::kCode, AllocationOrigin::kRuntime);
    CHECK(allocation.To(&obj));
    CHECK_EQ(allocation.ToAddress(), allocation_tracker.address());
    ThreadIsolation::RegisterInstructionStreamAllocation(obj.address(),
                                                         size_in_bytes);

    heap->CreateFillerObjectAt(obj.address(), size_in_bytes);
  }

  CHECK(Heap::IsLargeObject(obj));
  heap->RemoveHeapObjectAllocationTracker(&allocation_tracker);
}

UNINITIALIZED_HEAP_TEST(CodeLargeObjectSpace64k) {
  // Simulate having a system with 64k OS pages.
  i::v8_flags.v8_os_page_size = 64;

  // Initialize the isolate manually to make sure --v8-os-page-size is taken
  // into account.
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  i::Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate);
  Heap* heap = i_isolate->heap();
  PtrComprCageAccessScope ptr_compr_cage_access_scope(i_isolate);

  // Allocate a regular code object.
  {
    int size_in_bytes =
        heap->MaxRegularHeapObjectSize(AllocationType::kCode) - kTaggedSize;
    TestAllocationTracker allocation_tracker{size_in_bytes};
    heap->AddHeapObjectAllocationTracker(&allocation_tracker);

    Tagged<HeapObject> obj;
    {
      AllocationResult allocation = heap->AllocateRaw(
          size_in_bytes, AllocationType::kCode, AllocationOrigin::kRuntime);
      CHECK(allocation.To(&obj));
      CHECK_EQ(allocation.ToAddress(), allocation_tracker.address());
      ThreadIsolation::RegisterInstructionStreamAllocation(obj.address(),
                                                           size_in_bytes);

      heap->CreateFillerObjectAt(obj.address(), size_in_bytes);
    }

    CHECK(!Heap::IsLargeObject(obj));
    heap->RemoveHeapObjectAllocationTracker(&allocation_tracker);
  }

  // Allocate a large code object.
  {
    int size_in_bytes =
        heap->MaxRegularHeapObjectSize(AllocationType::kCode) + kTaggedSize;
    TestAllocationTracker allocation_tracker{size_in_bytes};
    heap->AddHeapObjectAllocationTracker(&allocation_tracker);

    Tagged<HeapObject> obj;
    {
      AllocationResult allocation = heap->AllocateRaw(
          size_in_bytes, AllocationType::kCode, AllocationOrigin::kRuntime);
      CHECK(allocation.To(&obj));
      CHECK_EQ(allocation.ToAddress(), allocation_tracker.address());
      ThreadIsolation::RegisterInstructionStreamAllocation(obj.address(),
                                                           size_in_bytes);

      heap->CreateFillerObjectAt(obj.address(), size_in_bytes);
    }

    CHECK(Heap::IsLargeObject(obj));
    heap->RemoveHeapObjectAllocationTracker(&allocation_tracker);
  }

  isolate->Dispose();
}

TEST(IsPendingAllocationNewSpace) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  Factory* factory = isolate->factory();
  HandleScope handle_scope(isolate);
  DirectHandle<FixedArray> object =
      factory->NewFixedArray(5, AllocationType::kYoung);
  CHECK(heap->IsPendingAllocation(*object));
  heap->PublishMainThreadPendingAllocations();
  CHECK(!heap->IsPendingAllocation(*object));
}

TEST(IsPendingAllocationNewLOSpace) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  Factory* factory = isolate->factory();
  HandleScope handle_scope(isolate);
  DirectHandle<FixedArray> object = factory->NewFixedArray(
      FixedArray::kMaxRegularLength + 1, AllocationType::kYoung);
  CHECK(heap->IsPendingAllocation(*object));
  heap->PublishMainThreadPendingAllocations();
  CHECK(!heap->IsPendingAllocation(*object));
}

TEST(IsPendingAllocationOldSpace) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  Factory* factory = isolate->factory();
  HandleScope handle_scope(isolate);
  DirectHandle<FixedArray> object =
      factory->NewFixedArray(5, AllocationType::kOld);
  CHECK(heap->IsPendingAllocation(*object));
  heap->PublishMainThreadPendingAllocations();
  CHECK(!heap->IsPendingAllocation(*object));
}

TEST(IsPendingAllocationLOSpace) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  Factory* factory = isolate->factory();
  HandleScope handle_scope(isolate);
  DirectHandle<FixedArray> object = factory->NewFixedArray(
      FixedArray::kMaxRegularLength + 1, AllocationType::kOld);
  CHECK(heap->IsPendingAllocation(*object));
  heap->PublishMainThreadPendingAllocations();
  CHECK(!heap->IsPendingAllocation(*object));
}

TEST(Regress10900) {
  v8_flags.compact_on_every_full_gc = true;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  HandleScope handle_scope(isolate);
  uint8_t buffer[i::Assembler::kDefaultBufferSize];
  MacroAssembler masm(isolate, v8::internal::CodeObjectRequired::kYes,
                      ExternalAssemblerBuffer(buffer, sizeof(buffer)));
#if V8_TARGET_ARCH_ARM64
  UseScratchRegisterScope temps(&masm);
  Register tmp = temps.AcquireX();
  masm.Mov(tmp, Operand(static_cast<int32_t>(
                    ReadOnlyRoots(heap).undefined_value().ptr())));
  masm.Push(tmp, tmp);
#else
  masm.Push(ReadOnlyRoots(heap).undefined_value_handle());
#endif
  CodeDesc desc;
  masm.GetCode(isolate, &desc);
  {
    DirectHandle<Code> code;
    for (int i = 0; i < 100; i++) {
      // Generate multiple code pages.
      code = Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
    }
  }
  // Force garbage collection that compacts code pages and triggers
  // an assertion in Isolate::AddCodeMemoryRange before the bug fix.
  heap::InvokeMemoryReducingMajorGCs(heap);
}

namespace {
void GenerateGarbage() {
  const char* source =
      "let roots = [];"
      "for (let i = 0; i < 100; i++) roots.push(new Array(1000).fill(0));"
      "roots.push(new Array(1000000).fill(0));"
      "roots;";
  CompileRun(source);
}

}  // anonymous namespace

TEST(Regress11181) {
  v8_flags.compact_on_every_full_gc = true;
  CcTest::InitializeVM();
  TracingFlags::runtime_stats.store(
      v8::tracing::TracingCategoryObserver::ENABLED_BY_NATIVE,
      std::memory_order_relaxed);
  v8::HandleScope scope(CcTest::isolate());
  GenerateGarbage();
  heap::InvokeMemoryReducingMajorGCs(CcTest::heap());
}

TEST(LongTaskStatsFullAtomic) {
  CcTest::InitializeVM();
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(CcTest::isolate());
  GenerateGarbage();
  v8::metrics::LongTaskStats::Reset(isolate);
  CHECK_EQ(0u, v8::metrics::LongTaskStats::Get(isolate)
                   .gc_full_atomic_wall_clock_duration_us);
  for (int i = 0; i < 10; ++i) {
    heap::InvokeMemoryReducingMajorGCs(CcTest::heap());
  }
  CHECK_LT(0u, v8::metrics::LongTaskStats::Get(isolate)
                   .gc_full_atomic_wall_clock_duration_us);
  v8::metrics::LongTaskStats::Reset(isolate);
  CHECK_EQ(0u, v8::metrics::LongTaskStats::Get(isolate)
                   .gc_full_atomic_wall_clock_duration_us);
}

TEST(LongTaskStatsFullIncremental) {
  if (!v8_flags.incremental_marking) return;
  CcTest::InitializeVM();
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(CcTest::isolate());
  GenerateGarbage();
  v8::metrics::LongTaskStats::Reset(isolate);
  CHECK_EQ(0u, v8::metrics::LongTaskStats::Get(isolate)
                   .gc_full_incremental_wall_clock_duration_us);
  for (int i = 0; i < 10; ++i) {
    heap::SimulateIncrementalMarking(CcTest::heap());
    heap::InvokeMemoryReducingMajorGCs(CcTest::heap());
  }
  CHECK_LT(0u, v8::metrics::LongTaskStats::Get(isolate)
                   .gc_full_incremental_wall_clock_duration_us);
  v8::metrics::LongTaskStats::Reset(isolate);
  CHECK_EQ(0u, v8::metrics::LongTaskStats::Get(isolate)
                   .gc_full_incremental_wall_clock_duration_us);
}

TEST(LongTaskStatsYoung) {
  if (v8_flags.single_generation) return;
  CcTest::InitializeVM();
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(CcTest::isolate());
  GenerateGarbage();
  v8::metrics::LongTaskStats::Reset(isolate);
  CHECK_EQ(
      0u,
      v8::metrics::LongTaskStats::Get(isolate).gc_young_wall_clock_duration_us);
  for (int i = 0; i < 10; ++i) {
    heap::InvokeMinorGC(CcTest::heap());
  }
  CHECK_LT(
      0u,
      v8::metrics::LongTaskStats::Get(isolate).gc_young_wall_clock_duration_us);
  v8::metrics::LongTaskStats::Reset(isolate);
  CHECK_EQ(
      0u,
      v8::metrics::LongTaskStats::Get(isolate).gc_young_wall_clock_duration_us);
}

}  // namespace heap
}  // namespace internal
}  // namespace v8

#undef __

"""


```