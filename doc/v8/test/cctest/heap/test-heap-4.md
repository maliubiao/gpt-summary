Response: The user wants a summary of the C++ source code file `v8/test/cctest/heap/test-heap.cc`, which is part 5 of 5. This implies I should focus on the functionalities covered in this specific part. The user also wants to know if and how the code relates to JavaScript, with a JavaScript example if applicable.

The code consists of several `TEST` and `HEAP_TEST` blocks. These are likely unit tests for the V8 JavaScript engine's heap management functionality. Each test focuses on a specific aspect of the heap, like garbage collection, memory limits, object allocation, and interaction with other V8 features like incremental marking.

Here's a breakdown of the functionalities covered by the tests:

*   **Heap Limit and OOM Handling:** Testing how the heap reacts when approaching its limit and how it handles out-of-memory scenarios.
*   **Memory Management and GC:**  Various tests trigger and examine different garbage collection mechanisms (minor GC, major GC, incremental marking) and their effects on object movement and memory reclamation.
*   **External Backing Stores:** Testing the allocation of external memory used for ArrayBuffers.
*   **Code Object Registry:**  Verifying the management of compiled code in the heap.
*   **Memory Reducer:** Testing the activation of the memory reducer in low-memory situations.
*   **Object Allocation Tracking:**  Verifying the correct allocation of objects in different memory spaces (young, old, large object space, code space).
*   **Pending Allocations:** Testing the tracking of objects that have been allocated but not yet fully committed.
*   **Heap Compaction:** Testing the heap compaction process during garbage collection.
*   **Local Heaps:** Testing interactions with thread-local heaps.
*   **Long Task Stats:**  Measuring the time spent in different types of garbage collection.

Several tests directly relate to garbage collection and memory management, which are fundamental to how JavaScript manages memory automatically. I can create a JavaScript example to illustrate how these concepts manifest in the language.
这个C++源代码文件 `v8/test/cctest/heap/test-heap.cc` 是V8 JavaScript引擎的堆内存管理功能的单元测试的第五部分。它包含了一系列的测试用例，用于验证V8堆的各种特性和功能，特别是关于内存限制、垃圾回收、对象分配和一些特定的回归问题的修复。

以下是这个部分的主要功能归纳：

*   **测试堆限制和OOM（Out Of Memory）处理:**  测试了当堆接近其最大容量时，V8的反应以及如何处理内存溢出的情况，包括使用 `NearHeapLimitCallback` 和 `MemoryPressureNotification` 来模拟和处理内存压力。
*   **测试非提交未使用内存:** 验证了释放堆中未使用的内存的功能。
*   **测试托管的外部内存:**  测试了如何管理由C++代码分配，但由V8跟踪生命周期的外部内存。
*   **回归测试 (Regress8014, Regress8617, Regress9701, Regress10698, Regress10900, Regress11181):**  这些测试用例旨在重现并验证已修复的特定bug，涉及到对象移动、增量标记、代码对象的管理、以及特定场景下的垃圾回收行为。
*   **测试内存优化器 (MemoryReducer):**  验证了在小堆内存情况下，内存优化器是否会被正确激活。
*   **测试外部内存分配:**  测试了 `AllocateExternalBackingStore` 函数，用于分配外部内存（通常用于 `ArrayBuffer`）。
*   **测试代码对象注册:** 验证了V8如何管理和跟踪已编译的代码对象，并确保在垃圾回收后代码对象仍然有效。
*   **测试不同堆空间的分配:**  包括在老生代 (old space)、新生代 (new space) 以及大对象堆 (large object space) 中分配对象，并验证其行为。
*   **测试在Jitless模式下的行为:** 验证了在没有即时编译（JIT）的情况下，代码区域是否为空。
*   **测试本地堆 (LocalHeap) 的垃圾回收:**  验证了与线程本地堆相关的垃圾回收行为。
*   **测试对象分配追踪:** 验证了在特定内存空间（如代码大对象空间）中的对象分配是否符合预期。
*   **测试待处理的分配:**  验证了V8如何跟踪已分配但尚未完全提交的对象。
*   **测试长任务统计:**  测试了V8如何统计不同类型的垃圾回收所花费的时间。

**与JavaScript的功能关系及示例:**

这个文件中的测试用例直接关系到JavaScript的内存管理机制。JavaScript是一门具有自动垃圾回收的语言，开发者不需要手动管理内存的分配和释放。V8引擎负责在后台执行垃圾回收，回收不再被使用的内存。

以下是一些与JavaScript功能相关的测试用例及其对应的JavaScript概念：

1. **堆限制和OOM处理 (`HEAP_TEST(NearHeapLimit)`):** 当JavaScript代码尝试分配超过堆内存限制的对象时，会导致程序崩溃或抛出错误。

    ```javascript
    // 假设当前的堆内存限制很小
    let arr = [];
    try {
      while (true) {
        arr.push(new Array(1000000).fill(0)); // 不断分配大数组
      }
    } catch (e) {
      console.error("Out of memory:", e); // 可能会抛出 RangeError: Maximum call stack size exceeded 或其他 OOM 相关的错误
    }
    ```

2. **垃圾回收 (`TEST(Regress8617)`, `HEAP_TEST(MemoryReducerActivationForSmallHeaps)` 等):** JavaScript引擎会自动回收不再被引用的对象，释放内存。

    ```javascript
    function createGarbage() {
      let obj1 = { data: new Array(1000000).fill(0) }; // 创建一个大对象
      let obj2 = { ref: obj1 }; // obj2 引用 obj1
      obj1 = null; // 解除 obj1 的引用，但 obj1 仍然被 obj2 引用，不会被立即回收
      return obj2;
    }

    let myObj = createGarbage();
    myObj = null; // 现在 myObj 和其内部引用的对象都可以被垃圾回收了
    ```

3. **外部内存分配 (`TEST(AllocateExternalBackingStore)`):**  JavaScript的 `ArrayBuffer` 对象会使用外部内存来存储二进制数据。V8需要有效地管理这些外部内存。

    ```javascript
    let buffer = new ArrayBuffer(1024); // 分配 1KB 的外部内存
    let view = new Uint8Array(buffer); // 创建一个指向该外部内存的视图
    ```

4. **代码对象管理 (`TEST(CodeObjectRegistry)`, `TEST(Regress10900)`):**  当JavaScript代码被执行时，V8会将其编译成机器码。这些编译后的代码需要被存储和管理在堆内存中。

    ```javascript
    function add(a, b) {
      return a + b;
    }

    // 当 add 函数被调用多次后，V8可能会对其进行优化编译，生成更高效的机器码。
    add(1, 2);
    add(3, 4);
    add(5, 6);
    ```

5. **待处理的分配 (`TEST(IsPendingAllocationNewSpace)`, `TEST(IsPendingAllocationOldSpace)`):** V8可能会采用一些优化策略，例如在后台线程中进行分配。在分配完成并提交到主线程之前，这些分配处于待处理状态。这在JavaScript中是透明的，但V8内部需要管理这些状态。

总而言之，这个C++测试文件深入测试了V8引擎的底层内存管理机制，这些机制对于保证JavaScript程序的性能和稳定性至关重要。虽然JavaScript开发者通常不需要直接关心这些细节，但V8的这些内部工作保证了JavaScript的自动内存管理和高效执行。

Prompt: 
```
这是目录为v8/test/cctest/heap/test-heap.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第5部分，共5部分，请归纳一下它的功能

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