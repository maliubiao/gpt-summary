Response: The user wants a summary of the C++ code provided.
The code seems to be part of V8's testing framework, specifically for testing heap functionalities.

I will go through the code and identify the main functionalities being tested. The code seems to focus on:
1. **Compilation Cache Regeneration**: Testing scenarios where the compilation cache is regenerated after script execution.
2. **Internal Weak Lists**: Testing the behavior of weak lists used to track native contexts and how they are garbage collected.
3. **Size of Objects**: Testing the accuracy of `SizeOfObjects()` and related functions, including cases with large RegExp objects.
4. **Object Alignment**: Testing different allocation alignments and the creation of filler objects.
5. **Pretenuring**: Testing object pretenuring in optimized code, specifically for various literal types and object properties.
6. **Map Transitions**: Testing the behavior of map transitions during garbage collection.
7. **Page Release**: Testing the release of over-reserved pages during garbage collection.
8. **Write Barriers**: Testing the `instanceof` stub's write barrier behavior during incremental marking.
9. **GC Flags**: Testing the setting and resetting of garbage collection flags.
10. **HeapObjectIterator**: Comparing the results of `SizeOfObjects()` with the iteration over heap objects.
11. **Leak Prevention**: Testing mechanisms to prevent leaking native contexts through optimized code (via maps and functions).

For the JavaScript example, I will choose one of the tested features, like compilation cache regeneration, and demonstrate how it can be observed in JavaScript.
This C++ code snippet is part of V8's testing framework and focuses on testing the **compilation cache regeneration** functionality and its interaction with different compilation strategies (eager vs. lazy) and garbage collection.

Here's a breakdown of the functionality:

* **Testing Compilation Cache Regeneration:** The core function `CompilationCacheRegeneration` tests how V8 reuses or regenerates the compilation cache for JavaScript functions after a full garbage collection. It specifically checks scenarios where:
    * The root SharedFunctionInfo (representing the top-level script) is either retained or flushed from the cache.
    * Eagerly compiled functions (compiled immediately) and lazy compiled functions (compiled on first call) are handled.
* **Scenarios:** The code uses boolean flags (`flush_root_sfi`, `flush_lazy_sfi`, `flush_eager_sfi`) to simulate different garbage collection scenarios affecting the retention of compiled code in the cache.
* **Verifying Compilation States:**  The tests check whether `SharedFunctionInfo` objects (which hold compiled code information) are compiled or not after running the script and after garbage collection. It also verifies that if a `SharedFunctionInfo` was expected to be retained, it's the same instance when the script is run again.
* **Reachability from Script:** The code verifies that the root `SharedFunctionInfo` remains reachable from the `Script` object under the expected conditions.

**Relationship to JavaScript (with example):**

The compilation cache is an internal optimization in V8 that significantly speeds up the execution of JavaScript code, especially after page reloads or when the same script is run multiple times. Here's how the tested scenarios relate to JavaScript behavior:

Imagine this JavaScript code:

```javascript
function eagerFunction() {
  return 1 + 1;
}

function lazyFunction() {
  console.log("This is a lazy function.");
  return 2 + 2;
}

eagerFunction(); // This might trigger eager compilation

globalThis.lazyFunction = lazyFunction;
globalThis.eagerFunction = eagerFunction;
```

Now, consider the scenarios tested in the C++ code:

1. **Initial Execution:** When this script runs for the first time, `eagerFunction` might be compiled immediately (eager compilation). `lazyFunction` will likely be marked for lazy compilation, meaning its actual compilation is deferred until it's called.

2. **Garbage Collection (simulated by `flush_root_sfi`, `flush_lazy_sfi`, `flush_eager_sfi`):**  A full garbage collection might decide to discard compiled code to free up memory. This is what the flags in the C++ test simulate.

3. **Second Execution:** When the script (or the functions within it) is called again:
    * **If the compilation cache for `eagerFunction` was retained:** V8 can directly reuse the compiled code, making the execution very fast.
    * **If the compilation cache for `eagerFunction` was flushed:** V8 needs to recompile `eagerFunction`.
    * **If `lazyFunction` was never called before the GC:** It will be compiled when it's first called after the GC.
    * **If `lazyFunction` was called before the GC, and its compiled code was retained:** V8 reuses the compiled code.
    * **If `lazyFunction` was called before the GC, but its compiled code was flushed:** V8 needs to recompile it when called again.

**JavaScript Example Illustrating Compilation Cache (Conceptual):**

While you can't directly control or inspect the compilation cache from JavaScript, you can observe the performance implications:

```javascript
function expensiveCalculation() {
  let result = 0;
  for (let i = 0; i < 1000000; i++) {
    result += Math.sqrt(i);
  }
  return result;
}

console.time("First call");
expensiveCalculation();
console.timeEnd("First call");

// Simulate a scenario where the compilation cache might be relevant (e.g., page reload)

console.time("Second call");
expensiveCalculation();
console.timeEnd("Second call");
```

In a real browser or Node.js environment, the "Second call" will often be significantly faster than the "First call" because V8 likely reused the compiled code for `expensiveCalculation` from its compilation cache. The C++ tests are designed to rigorously verify the correctness of this caching mechanism under various garbage collection pressures.

Prompt: 
```
这是目录为v8/test/cctest/heap/test-heap.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共5部分，请归纳一下它的功能

"""
olate());

    // The lazy function should still not be compiled.
    DirectHandle<SharedFunctionInfo> lazy_sfi =
        GetSharedFunctionInfo(lazy_function.Get(CcTest::isolate()));
    CHECK(!lazy_sfi->is_compiled());

    // The eager function may have had its bytecode flushed.
    DirectHandle<SharedFunctionInfo> eager_sfi =
        GetSharedFunctionInfo(eager_function.Get(CcTest::isolate()));
    CHECK_EQ(!flush_eager_sfi, eager_sfi->is_compiled());

    // Check whether the root SharedFunctionInfo is still reachable from the
    // Script.
    DirectHandle<Script> script(Cast<Script>(lazy_sfi->script()), isolate);
    bool root_sfi_still_exists = false;
    Tagged<MaybeObject> maybe_root_sfi =
        script->infos()->get(kFunctionLiteralIdTopLevel);
    if (Tagged<HeapObject> sfi_or_undefined;
        maybe_root_sfi.GetHeapObject(&sfi_or_undefined)) {
      root_sfi_still_exists = !IsUndefined(sfi_or_undefined);
    }
    CHECK_EQ(root_sfi_should_still_exist, root_sfi_still_exists);
  }

  {
    // Run the script again and check that no SharedFunctionInfos were
    // duplicated, and that the expected ones were compiled.
    v8::HandleScope scope(CcTest::isolate());
    v8::Local<v8::Context> context =
        v8::Isolate::GetCurrent()->GetCurrentContext();
    v8::Local<v8::Script> script = v8_compile(v8_str(source));

    // The script should be compiled by now.
    DirectHandle<SharedFunctionInfo> script_sfi = GetSharedFunctionInfo(script);
    CHECK(script_sfi->is_compiled());

    // This compilation should not have created a new root SharedFunctionInfo if
    // one already existed.
    if (retain_root_sfi) {
      DirectHandle<SharedFunctionInfo> old_script_sfi =
          GetSharedFunctionInfo(outer_function.Get(CcTest::isolate()));
      CHECK_EQ(*old_script_sfi, *script_sfi);
    }

    DirectHandle<SharedFunctionInfo> old_lazy_sfi =
        GetSharedFunctionInfo(lazy_function.Get(CcTest::isolate()));
    CHECK(!old_lazy_sfi->is_compiled());

    // The only way for the eager function to be uncompiled at this point is if
    // it was flushed but the root function was not.
    DirectHandle<SharedFunctionInfo> old_eager_sfi =
        GetSharedFunctionInfo(eager_function.Get(CcTest::isolate()));
    CHECK_EQ(!(flush_eager_sfi && !flush_root_sfi),
             old_eager_sfi->is_compiled());

    v8::Local<v8::Value> result = script->Run(context).ToLocalChecked();

    // Check that both functions reused the existing SharedFunctionInfos.
    v8::Local<v8::Object> result_obj =
        result->ToObject(context).ToLocalChecked();
    v8::Local<v8::Value> lazy_function_value =
        result_obj->GetRealNamedProperty(context, v8_str("lazyFunction"))
            .ToLocalChecked();
    CHECK(lazy_function_value->IsFunction());
    DirectHandle<SharedFunctionInfo> lazy_sfi =
        GetSharedFunctionInfo(lazy_function_value);
    CHECK_EQ(*old_lazy_sfi, *lazy_sfi);
    v8::Local<v8::Value> eager_function_value =
        result_obj->GetRealNamedProperty(context, v8_str("eagerFunction"))
            .ToLocalChecked();
    CHECK(eager_function_value->IsFunction());
    DirectHandle<SharedFunctionInfo> eager_sfi =
        GetSharedFunctionInfo(eager_function_value);
    CHECK_EQ(*old_eager_sfi, *eager_sfi);
  }
}

}  // namespace

TEST(CompilationCacheRegeneration0) {
  CompilationCacheRegeneration(false, false, false);
}
TEST(CompilationCacheRegeneration1) {
  CompilationCacheRegeneration(false, false, true);
}
TEST(CompilationCacheRegeneration2) {
  CompilationCacheRegeneration(false, true, false);
}
TEST(CompilationCacheRegeneration3) {
  CompilationCacheRegeneration(false, true, true);
}
TEST(CompilationCacheRegeneration4) {
  CompilationCacheRegeneration(true, false, false);
}
TEST(CompilationCacheRegeneration5) {
  CompilationCacheRegeneration(true, false, true);
}
TEST(CompilationCacheRegeneration6) {
  CompilationCacheRegeneration(true, true, false);
}
TEST(CompilationCacheRegeneration7) {
  CompilationCacheRegeneration(true, true, true);
}

static void OptimizeEmptyFunction(const char* name) {
  HandleScope scope(CcTest::i_isolate());
  base::EmbeddedVector<char, 256> source;
  base::SNPrintF(source,
                 "function %s() { return 0; }"
                 "%%PrepareFunctionForOptimization(%s);"
                 "%s(); %s();"
                 "%%OptimizeFunctionOnNextCall(%s);"
                 "%s();",
                 name, name, name, name, name, name);
  CompileRun(source.begin());
}

// Count the number of native contexts in the weak list of native contexts.
int CountNativeContexts() {
  int count = 0;
  Tagged<Object> object = CcTest::heap()->native_contexts_list();
  while (!IsUndefined(object, CcTest::i_isolate())) {
    count++;
    object = Cast<Context>(object)->next_context_link();
  }
  return count;
}

TEST(TestInternalWeakLists) {
  v8_flags.always_turbofan = false;
  v8_flags.allow_natives_syntax = true;

  // Some flags turn Scavenge collections into Mark-sweep collections
  // and hence are incompatible with this test case.
  if (v8_flags.gc_global || v8_flags.stress_compaction ||
      v8_flags.stress_incremental_marking || v8_flags.single_generation ||
      v8_flags.separate_gc_phases || v8_flags.stress_concurrent_allocation)
    return;
  v8_flags.retain_maps_for_n_gc = 0;

  static const int kNumTestContexts = 10;

  ManualGCScope manual_gc_scope;
  v8::Isolate* v8_isolate = CcTest::isolate();
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = CcTest::heap();
  HandleScope scope(isolate);
  v8::Global<v8::Context> ctx[kNumTestContexts];
  if (!isolate->use_optimizer()) return;

  CHECK_EQ(0, CountNativeContexts());

  // Create a number of global contests which gets linked together.
  for (int i = 0; i < kNumTestContexts; i++) {
    // Create a handle scope so no contexts or function objects get stuck in the
    // outer handle scope.
    HandleScope new_scope(isolate);

    ctx[i].Reset(v8_isolate, v8::Context::New(v8_isolate));

    // Collect garbage that might have been created by one of the
    // installed extensions.
    isolate->compilation_cache()->Clear();
    {
      // In this test, we need to invoke GC without stack, otherwise some
      // objects may not be reclaimed because of conservative stack scanning.
      DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
      heap::InvokeMajorGC(heap);
    }

    CHECK_EQ(i + 1, CountNativeContexts());

    ctx[i].Get(v8_isolate)->Enter();

    OptimizeEmptyFunction("f1");
    OptimizeEmptyFunction("f2");
    OptimizeEmptyFunction("f3");
    OptimizeEmptyFunction("f4");
    OptimizeEmptyFunction("f5");

    // Remove function f1, and
    CompileRun("f1=null");

    // Scavenge treats these references as strong.
    for (int j = 0; j < 10; j++) {
      DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
      heap::InvokeMinorGC(heap);
    }

    // Mark compact handles the weak references.
    isolate->compilation_cache()->Clear();
    {
      DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
      heap::InvokeMajorGC(heap);
    }

    // Get rid of f3 and f5 in the same way.
    CompileRun("f3=null");
    {
      DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
      for (int j = 0; j < 10; j++) {
        heap::InvokeMinorGC(heap);
      }
      heap::InvokeMajorGC(heap);
    }
    CompileRun("f5=null");
    {
      DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
      for (int j = 0; j < 10; j++) {
        heap::InvokeMinorGC(heap);
      }
      heap::InvokeMajorGC(heap);
    }
    ctx[i].Get(v8_isolate)->Exit();
  }

  // Force compilation cache cleanup.
  heap->NotifyContextDisposed(true);
  {
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMajorGC(heap);
  }

  // Dispose the native contexts one by one.
  for (int i = 0; i < kNumTestContexts; i++) {
    ctx[i].Reset();

    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);

    // Scavenge treats these references as strong.
    for (int j = 0; j < 10; j++) {
      heap::InvokeMinorGC(heap);
      CHECK_EQ(kNumTestContexts - i, CountNativeContexts());
    }
    // Mark-compact handles the weak references.
    heap::InvokeMajorGC(heap);

    CHECK_EQ(kNumTestContexts - i - 1, CountNativeContexts());
  }

  CHECK_EQ(0, CountNativeContexts());
}

TEST(TestSizeOfRegExpCode) {
  if (!v8_flags.regexp_optimization) return;
  v8_flags.stress_concurrent_allocation = false;

  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = CcTest::heap();
  HandleScope scope(isolate);

  LocalContext context;

  // Adjust source below and this check to match
  // RegExp::kRegExpTooLargeToOptimize.
  CHECK_EQ(i::RegExp::kRegExpTooLargeToOptimize, 20 * KB);

  // Compile a regexp that is much larger if we are using regexp optimizations.
  CompileRun(
      "var reg_exp_source = '(?:a|bc|def|ghij|klmno|pqrstu)';"
      "var half_size_reg_exp;"
      "while (reg_exp_source.length < 20 * 1024) {"
      "  half_size_reg_exp = reg_exp_source;"
      "  reg_exp_source = reg_exp_source + reg_exp_source;"
      "}"
      // Flatten string.
      "reg_exp_source.match(/f/);");

  {
    // In this test, we need to invoke GC without stack, otherwise some objects
    // may not be reclaimed because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    // Get initial heap size after several full GCs, which will stabilize
    // the heap size and return with sweeping finished completely.
    heap::InvokeMemoryReducingMajorGCs(heap);
    if (heap->sweeping_in_progress()) {
      heap->EnsureSweepingCompleted(
          Heap::SweepingForcedFinalizationMode::kV8Only);
    }
  }
  int initial_size = static_cast<int>(heap->SizeOfObjects());

  CompileRun("'foo'.match(reg_exp_source);");
  {
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMemoryReducingMajorGCs(heap);
  }
  int size_with_regexp = static_cast<int>(heap->SizeOfObjects());

  CompileRun("'foo'.match(half_size_reg_exp);");
  {
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMemoryReducingMajorGCs(heap);
  }
  int size_with_optimized_regexp = static_cast<int>(heap->SizeOfObjects());

  int size_of_regexp_code = size_with_regexp - initial_size;

  // On some platforms the debug-code flag causes huge amounts of regexp code
  // to be emitted, breaking this test.
  if (!v8_flags.debug_code) {
    CHECK_LE(size_of_regexp_code, 1 * MB);
  }

  // Small regexp is half the size, but compiles to more than twice the code
  // due to the optimization steps.
  CHECK_GE(size_with_optimized_regexp,
           size_with_regexp + size_of_regexp_code * 2);
}

HEAP_TEST(TestSizeOfObjects) {
  v8_flags.stress_concurrent_allocation = false;
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = CcTest::heap();

  // Disable LAB, such that calculations with SizeOfObjects() and object size
  // are correct.
  heap->DisableInlineAllocation();

  // Get initial heap size after several full GCs, which will stabilize
  // the heap size and return with sweeping finished completely.
  {
    // In this test, we need to invoke GC without stack, otherwise some objects
    // may not be reclaimed because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMemoryReducingMajorGCs(heap);
    if (heap->sweeping_in_progress()) {
      heap->EnsureSweepingCompleted(
          Heap::SweepingForcedFinalizationMode::kV8Only);
    }
  }
  int initial_size = static_cast<int>(heap->SizeOfObjects());

  {
    HandleScope scope(isolate);
    // Allocate objects on several different old-space pages so that
    // concurrent sweeper threads will be busy sweeping the old space on
    // subsequent GC runs.
    AlwaysAllocateScopeForTesting always_allocate(heap);
    int filler_size = static_cast<int>(FixedArray::SizeFor(8192));
    for (int i = 1; i <= 100; i++) {
      isolate->factory()->NewFixedArray(8192, AllocationType::kOld);
      CHECK_EQ(initial_size + i * filler_size,
               static_cast<int>(heap->SizeOfObjects()));
    }
  }

  // The heap size should go back to initial size after a full GC, even
  // though sweeping didn't finish yet.
  {
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMajorGC(heap);
  }
  // Normally sweeping would not be complete here, but no guarantees.
  CHECK_EQ(initial_size, static_cast<int>(heap->SizeOfObjects()));
  // Waiting for sweeper threads should not change heap size.
  if (heap->sweeping_in_progress()) {
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap->EnsureSweepingCompleted(
        Heap::SweepingForcedFinalizationMode::kV8Only);
  }
  CHECK_EQ(initial_size, static_cast<int>(heap->SizeOfObjects()));
}

TEST(TestAlignmentCalculations) {
  // Maximum fill amounts are consistent.
  int maximum_double_misalignment = kDoubleSize - kTaggedSize;
  int max_word_fill = Heap::GetMaximumFillToAlign(kTaggedAligned);
  CHECK_EQ(0, max_word_fill);
  int max_double_fill = Heap::GetMaximumFillToAlign(kDoubleAligned);
  CHECK_EQ(maximum_double_misalignment, max_double_fill);
  int max_double_unaligned_fill = Heap::GetMaximumFillToAlign(kDoubleUnaligned);
  CHECK_EQ(maximum_double_misalignment, max_double_unaligned_fill);

  Address base = kNullAddress;
  int fill = 0;

  // Word alignment never requires fill.
  fill = Heap::GetFillToAlign(base, kTaggedAligned);
  CHECK_EQ(0, fill);
  fill = Heap::GetFillToAlign(base + kTaggedSize, kTaggedAligned);
  CHECK_EQ(0, fill);

  // No fill is required when address is double aligned.
  fill = Heap::GetFillToAlign(base, kDoubleAligned);
  CHECK_EQ(0, fill);
  // Fill is required if address is not double aligned.
  fill = Heap::GetFillToAlign(base + kTaggedSize, kDoubleAligned);
  CHECK_EQ(maximum_double_misalignment, fill);
  // kDoubleUnaligned has the opposite fill amounts.
  fill = Heap::GetFillToAlign(base, kDoubleUnaligned);
  CHECK_EQ(maximum_double_misalignment, fill);
  fill = Heap::GetFillToAlign(base + kTaggedSize, kDoubleUnaligned);
  CHECK_EQ(0, fill);
}

static Tagged<HeapObject> AllocateAligned(MainAllocator* allocator, int size,
                                          AllocationAlignment alignment) {
  Heap* heap = CcTest::heap();
  AllocationResult allocation = allocator->AllocateRawForceAlignmentForTesting(
      size, alignment, AllocationOrigin::kRuntime);
  Tagged<HeapObject> obj;
  allocation.To(&obj);
  heap->CreateFillerObjectAt(obj.address(), size);
  return obj;
}

TEST(TestAlignedAllocation) {
  if (v8_flags.single_generation) return;
  // Double misalignment is 4 on 32-bit platforms or when pointer compression
  // is enabled, 0 on 64-bit ones when pointer compression is disabled.
  const intptr_t double_misalignment = kDoubleSize - kTaggedSize;
  Address start;
  Tagged<HeapObject> obj;
  Tagged<HeapObject> filler;
  if (double_misalignment) {
    MainAllocator* allocator =
        CcTest::heap()->allocator()->new_space_allocator();

    // Make one allocation to force allocating an allocation area. Using
    // kDoubleSize to not change space alignment
    USE(allocator->AllocateRaw(kDoubleSize, kDoubleAligned,
                               AllocationOrigin::kRuntime));

    // Allocate a pointer sized object that must be double aligned at an
    // aligned address.
    start = allocator->AlignTopForTesting(kDoubleAligned, 0);
    obj = AllocateAligned(allocator, kTaggedSize, kDoubleAligned);
    CHECK(IsAligned(obj.address(), kDoubleAlignment));
    // There is no filler.
    CHECK_EQ(start, obj.address());

    // Allocate a second pointer sized object that must be double aligned at an
    // unaligned address.
    start = allocator->AlignTopForTesting(kDoubleAligned, kTaggedSize);
    obj = AllocateAligned(allocator, kTaggedSize, kDoubleAligned);
    CHECK(IsAligned(obj.address(), kDoubleAlignment));
    // There is a filler object before the object.
    filler = HeapObject::FromAddress(start);
    CHECK(obj != filler && IsFreeSpaceOrFiller(filler) &&
          filler->Size() == kTaggedSize);
    CHECK_EQ(start + double_misalignment, obj->address());

    // Similarly for kDoubleUnaligned.
    start = allocator->AlignTopForTesting(kDoubleUnaligned, 0);
    obj = AllocateAligned(allocator, kTaggedSize, kDoubleUnaligned);
    CHECK(IsAligned(obj.address() + kTaggedSize, kDoubleAlignment));
    CHECK_EQ(start, obj->address());

    start = allocator->AlignTopForTesting(kDoubleUnaligned, kTaggedSize);
    obj = AllocateAligned(allocator, kTaggedSize, kDoubleUnaligned);
    CHECK(IsAligned(obj.address() + kTaggedSize, kDoubleAlignment));
    // There is a filler object before the object.
    filler = HeapObject::FromAddress(start);
    CHECK(obj != filler && IsFreeSpaceOrFiller(filler) &&
          filler->Size() == kTaggedSize);
    CHECK_EQ(start + kTaggedSize, obj->address());
  }
}

static Tagged<HeapObject> OldSpaceAllocateAligned(
    int size, AllocationAlignment alignment) {
  Heap* heap = CcTest::heap();
  AllocationResult allocation =
      heap->allocator()
          ->old_space_allocator()
          ->AllocateRawForceAlignmentForTesting(size, alignment,
                                                AllocationOrigin::kRuntime);
  Tagged<HeapObject> obj;
  allocation.To(&obj);
  heap->CreateFillerObjectAt(obj.address(), size);
  return obj;
}

// Get old space allocation into the desired alignment.
static Address AlignOldSpace(AllocationAlignment alignment, int offset) {
  Address* top_addr = CcTest::heap()->OldSpaceAllocationTopAddress();
  int fill = Heap::GetFillToAlign(*top_addr, alignment);
  int allocation = fill + offset;
  if (allocation) {
    OldSpaceAllocateAligned(allocation, kTaggedAligned);
  }
  Address top = *top_addr;
  // Now force the remaining allocation onto the free list.
  CcTest::heap()->FreeMainThreadLinearAllocationAreas();
  return top;
}

// Test the case where allocation must be done from the free list, so filler
// may precede or follow the object.
TEST(TestAlignedOverAllocation) {
  if (v8_flags.stress_concurrent_allocation) return;
  ManualGCScope manual_gc_scope;
  Heap* heap = CcTest::heap();
  // Test checks for fillers before and behind objects and requires a fresh
  // page and empty free list.
  heap::AbandonCurrentlyFreeMemory(heap->old_space());
  // Allocate a dummy object to properly set up the linear allocation info.
  AllocationResult dummy =
      heap->allocator()->old_space_allocator()->AllocateRaw(
          kTaggedSize, kTaggedAligned, AllocationOrigin::kRuntime);
  CHECK(!dummy.IsFailure());
  heap->CreateFillerObjectAt(dummy.ToObjectChecked().address(), kTaggedSize);

  // Double misalignment is 4 on 32-bit platforms or when pointer compression
  // is enabled, 0 on 64-bit ones when pointer compression is disabled.
  const intptr_t double_misalignment = kDoubleSize - kTaggedSize;
  Address start;
  Tagged<HeapObject> obj;
  Tagged<HeapObject> filler;
  if (double_misalignment) {
    start = AlignOldSpace(kDoubleAligned, 0);
    obj = OldSpaceAllocateAligned(kTaggedSize, kDoubleAligned);
    // The object is aligned.
    CHECK(IsAligned(obj.address(), kDoubleAlignment));
    // Try the opposite alignment case.
    start = AlignOldSpace(kDoubleAligned, kTaggedSize);
    obj = OldSpaceAllocateAligned(kTaggedSize, kDoubleAligned);
    CHECK(IsAligned(obj.address(), kDoubleAlignment));
    filler = HeapObject::FromAddress(start);
    CHECK(obj != filler);
    CHECK(IsFreeSpaceOrFiller(filler));
    CHECK_EQ(kTaggedSize, filler->Size());
    CHECK(obj != filler && IsFreeSpaceOrFiller(filler) &&
          filler->Size() == kTaggedSize);

    // Similarly for kDoubleUnaligned.
    start = AlignOldSpace(kDoubleUnaligned, 0);
    obj = OldSpaceAllocateAligned(kTaggedSize, kDoubleUnaligned);
    // The object is aligned.
    CHECK(IsAligned(obj.address() + kTaggedSize, kDoubleAlignment));
    // Try the opposite alignment case.
    start = AlignOldSpace(kDoubleUnaligned, kTaggedSize);
    obj = OldSpaceAllocateAligned(kTaggedSize, kDoubleUnaligned);
    CHECK(IsAligned(obj.address() + kTaggedSize, kDoubleAlignment));
    filler = HeapObject::FromAddress(start);
    CHECK(obj != filler && IsFreeSpaceOrFiller(filler) &&
          filler->Size() == kTaggedSize);
  }
}

TEST(HeapNumberAlignment) {
  if (!v8_flags.allocation_site_pretenuring) return;
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  Heap* heap = isolate->heap();
  HandleScope sc(isolate);

  const auto required_alignment =
      HeapObject::RequiredAlignment(*factory->heap_number_map());
  const int maximum_misalignment =
      Heap::GetMaximumFillToAlign(required_alignment);

  for (int offset = 0; offset <= maximum_misalignment; offset += kTaggedSize) {
    if (!v8_flags.single_generation) {
      heap->allocator()->new_space_allocator()->AlignTopForTesting(
          required_alignment, offset);
      DirectHandle<Object> number_new = factory->NewNumber(1.000123);
      CHECK(IsHeapNumber(*number_new));
      CHECK(HeapLayout::InYoungGeneration(*number_new));
      CHECK_EQ(0, Heap::GetFillToAlign(Cast<HeapObject>(*number_new).address(),
                                       required_alignment));
    }

    AlignOldSpace(required_alignment, offset);
    DirectHandle<Object> number_old =
        factory->NewNumber<AllocationType::kOld>(1.000321);
    CHECK(IsHeapNumber(*number_old));
    CHECK(heap->InOldSpace(*number_old));
    CHECK_EQ(0, Heap::GetFillToAlign(Cast<HeapObject>(*number_old).address(),
                                     required_alignment));
  }
}

TEST(TestSizeOfObjectsVsHeapObjectIteratorPrecision) {
  CcTest::InitializeVM();
  // Disable LAB, such that calculations with SizeOfObjects() and object size
  // are correct.
  CcTest::heap()->DisableInlineAllocation();
  HeapObjectIterator iterator(CcTest::heap());
  PtrComprCageBase cage_base(CcTest::i_isolate());
  intptr_t size_of_objects_1 = CcTest::heap()->SizeOfObjects();
  intptr_t size_of_objects_2 = 0;
  for (Tagged<HeapObject> obj = iterator.Next(); !obj.is_null();
       obj = iterator.Next()) {
    if (!IsFreeSpace(obj, cage_base)) {
      size_of_objects_2 += obj->Size(cage_base);
    }
  }
  // Delta must be within 5% of the larger result.
  // TODO(gc): Tighten this up by distinguishing between byte
  // arrays that are real and those that merely mark free space
  // on the heap.
  if (size_of_objects_1 > size_of_objects_2) {
    intptr_t delta = size_of_objects_1 - size_of_objects_2;
    PrintF("Heap::SizeOfObjects: %" V8PRIdPTR
           ", "
           "Iterator: %" V8PRIdPTR
           ", "
           "delta: %" V8PRIdPTR "\n",
           size_of_objects_1, size_of_objects_2, delta);
    CHECK_GT(size_of_objects_1 / 20, delta);
  } else {
    intptr_t delta = size_of_objects_2 - size_of_objects_1;
    PrintF("Heap::SizeOfObjects: %" V8PRIdPTR
           ", "
           "Iterator: %" V8PRIdPTR
           ", "
           "delta: %" V8PRIdPTR "\n",
           size_of_objects_1, size_of_objects_2, delta);
    CHECK_GT(size_of_objects_2 / 20, delta);
  }
}

static int NumberOfGlobalObjects() {
  int count = 0;
  HeapObjectIterator iterator(CcTest::heap());
  for (Tagged<HeapObject> obj = iterator.Next(); !obj.is_null();
       obj = iterator.Next()) {
    if (IsJSGlobalObject(obj)) count++;
  }
  return count;
}

// Test that we don't embed maps from foreign contexts into
// optimized code.
TEST(LeakNativeContextViaMap) {
  v8_flags.allow_natives_syntax = true;
  v8::Isolate* isolate = CcTest::isolate();
  Heap* heap = CcTest::heap();
  v8::HandleScope outer_scope(isolate);
  v8::Persistent<v8::Context> ctx1p;
  v8::Persistent<v8::Context> ctx2p;
  {
    v8::HandleScope scope(isolate);
    ctx1p.Reset(isolate, v8::Context::New(isolate));
    ctx2p.Reset(isolate, v8::Context::New(isolate));
    v8::Local<v8::Context>::New(isolate, ctx1p)->Enter();
  }

  {
    // In this test, we need to invoke GC without stack, otherwise some objects
    // may not be reclaimed because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMemoryReducingMajorGCs(heap);
  }
  CHECK_EQ(2, NumberOfGlobalObjects());

  {
    v8::HandleScope inner_scope(isolate);
    CompileRun("var v = {x: 42}");
    v8::Local<v8::Context> ctx1 = v8::Local<v8::Context>::New(isolate, ctx1p);
    v8::Local<v8::Context> ctx2 = v8::Local<v8::Context>::New(isolate, ctx2p);
    v8::Local<v8::Value> v =
        ctx1->Global()->Get(ctx1, v8_str("v")).ToLocalChecked();
    ctx2->Enter();
    CHECK(ctx2->Global()->Set(ctx2, v8_str("o"), v).FromJust());
    v8::Local<v8::Value> res = CompileRun(
        "function f() { return o.x; }"
        "%PrepareFunctionForOptimization(f);"
        "for (var i = 0; i < 10; ++i) f();"
        "%OptimizeFunctionOnNextCall(f);"
        "f();");
    CHECK_EQ(42, res->Int32Value(ctx2).FromJust());
    CHECK(ctx2->Global()
              ->Set(ctx2, v8_str("o"), v8::Int32::New(isolate, 0))
              .FromJust());
    ctx2->Exit();
    v8::Local<v8::Context>::New(isolate, ctx1)->Exit();
    ctx1p.Reset();
    isolate->ContextDisposedNotification();
  }
  {
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMemoryReducingMajorGCs(heap);
  }
  CHECK_EQ(1, NumberOfGlobalObjects());
  ctx2p.Reset();
  {
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMemoryReducingMajorGCs(heap);
  }
  CHECK_EQ(0, NumberOfGlobalObjects());
}

// Test that we don't embed functions from foreign contexts into
// optimized code.
TEST(LeakNativeContextViaFunction) {
  v8_flags.allow_natives_syntax = true;
  v8::Isolate* isolate = CcTest::isolate();
  Heap* heap = CcTest::heap();
  v8::HandleScope outer_scope(isolate);
  v8::Persistent<v8::Context> ctx1p;
  v8::Persistent<v8::Context> ctx2p;
  {
    v8::HandleScope scope(isolate);
    ctx1p.Reset(isolate, v8::Context::New(isolate));
    ctx2p.Reset(isolate, v8::Context::New(isolate));
    v8::Local<v8::Context>::New(isolate, ctx1p)->Enter();
  }

  {
    // In this test, we need to invoke GC without stack, otherwise some objects
    // may not be reclaimed because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMemoryReducingMajorGCs(heap);
  }
  CHECK_EQ(2, NumberOfGlobalObjects());

  {
    v8::HandleScope inner_scope(isolate);
    CompileRun("var v = function() { return 42; }");
    v8::Local<v8::Context> ctx1 = v8::Local<v8::Context>::New(isolate, ctx1p);
    v8::Local<v8::Context> ctx2 = v8::Local<v8::Context>::New(isolate, ctx2p);
    v8::Local<v8::Value> v =
        ctx1->Global()->Get(ctx1, v8_str("v")).ToLocalChecked();
    ctx2->Enter();
    CHECK(ctx2->Global()->Set(ctx2, v8_str("o"), v).FromJust());
    v8::Local<v8::Value> res = CompileRun(
        "function f(x) { return x(); }"
        "%PrepareFunctionForOptimization(f);"
        "for (var i = 0; i < 10; ++i) f(o);"
        "%OptimizeFunctionOnNextCall(f);"
        "f(o);");
    CHECK_EQ(42, res->Int32Value(ctx2).FromJust());
    CHECK(ctx2->Global()
              ->Set(ctx2, v8_str("o"), v8::Int32::New(isolate, 0))
              .FromJust());
    ctx2->Exit();
    ctx1->Exit();
    ctx1p.Reset();
    isolate->ContextDisposedNotification();
  }
  {
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMemoryReducingMajorGCs(heap);
  }
  CHECK_EQ(1, NumberOfGlobalObjects());
  ctx2p.Reset();
  {
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMemoryReducingMajorGCs(heap);
  }
  CHECK_EQ(0, NumberOfGlobalObjects());
}

TEST(LeakNativeContextViaMapKeyed) {
  v8_flags.allow_natives_syntax = true;
  v8::Isolate* isolate = CcTest::isolate();
  Heap* heap = CcTest::heap();
  v8::HandleScope outer_scope(isolate);
  v8::Persistent<v8::Context> ctx1p;
  v8::Persistent<v8::Context> ctx2p;
  {
    v8::HandleScope scope(isolate);
    ctx1p.Reset(isolate, v8::Context::New(isolate));
    ctx2p.Reset(isolate, v8::Context::New(isolate));
    v8::Local<v8::Context>::New(isolate, ctx1p)->Enter();
  }

  {
    // In this test, we need to invoke GC without stack, otherwise some objects
    // may not be reclaimed because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMemoryReducingMajorGCs(heap);
  }
  CHECK_EQ(2, NumberOfGlobalObjects());

  {
    v8::HandleScope inner_scope(isolate);
    CompileRun("var v = [42, 43]");
    v8::Local<v8::Context> ctx1 = v8::Local<v8::Context>::New(isolate, ctx1p);
    v8::Local<v8::Context> ctx2 = v8::Local<v8::Context>::New(isolate, ctx2p);
    v8::Local<v8::Value> v =
        ctx1->Global()->Get(ctx1, v8_str("v")).ToLocalChecked();
    ctx2->Enter();
    CHECK(ctx2->Global()->Set(ctx2, v8_str("o"), v).FromJust());
    v8::Local<v8::Value> res = CompileRun(
        "function f() { return o[0]; }"
        "%PrepareFunctionForOptimization(f);"
        "for (var i = 0; i < 10; ++i) f();"
        "%OptimizeFunctionOnNextCall(f);"
        "f();");
    CHECK_EQ(42, res->Int32Value(ctx2).FromJust());
    CHECK(ctx2->Global()
              ->Set(ctx2, v8_str("o"), v8::Int32::New(isolate, 0))
              .FromJust());
    ctx2->Exit();
    ctx1->Exit();
    ctx1p.Reset();
    isolate->ContextDisposedNotification();
  }
  {
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMemoryReducingMajorGCs(heap);
  }
  CHECK_EQ(1, NumberOfGlobalObjects());
  ctx2p.Reset();
  {
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMemoryReducingMajorGCs(heap);
  }
  CHECK_EQ(0, NumberOfGlobalObjects());
}

TEST(LeakNativeContextViaMapProto) {
  v8_flags.allow_natives_syntax = true;
  v8::Isolate* isolate = CcTest::isolate();
  Heap* heap = CcTest::heap();
  v8::HandleScope outer_scope(isolate);
  v8::Persistent<v8::Context> ctx1p;
  v8::Persistent<v8::Context> ctx2p;
  {
    v8::HandleScope scope(isolate);
    ctx1p.Reset(isolate, v8::Context::New(isolate));
    ctx2p.Reset(isolate, v8::Context::New(isolate));
    v8::Local<v8::Context>::New(isolate, ctx1p)->Enter();
  }

  {
    // In this test, we need to invoke GC without stack, otherwise some objects
    // may not be reclaimed because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMemoryReducingMajorGCs(heap);
  }
  CHECK_EQ(2, NumberOfGlobalObjects());

  {
    v8::HandleScope inner_scope(isolate);
    CompileRun("var v = { y: 42}");
    v8::Local<v8::Context> ctx1 = v8::Local<v8::Context>::New(isolate, ctx1p);
    v8::Local<v8::Context> ctx2 = v8::Local<v8::Context>::New(isolate, ctx2p);
    v8::Local<v8::Value> v =
        ctx1->Global()->Get(ctx1, v8_str("v")).ToLocalChecked();
    ctx2->Enter();
    CHECK(ctx2->Global()->Set(ctx2, v8_str("o"), v).FromJust());
    v8::Local<v8::Value> res = CompileRun(
        "function f() {"
        "  var p = {x: 42};"
        "  p.__proto__ = o;"
        "  return p.x;"
        "}"
        "%PrepareFunctionForOptimization(f);"
        "for (var i = 0; i < 10; ++i) f();"
        "%OptimizeFunctionOnNextCall(f);"
        "f();");
    CHECK_EQ(42, res->Int32Value(ctx2).FromJust());
    CHECK(ctx2->Global()
              ->Set(ctx2, v8_str("o"), v8::Int32::New(isolate, 0))
              .FromJust());
    ctx2->Exit();
    ctx1->Exit();
    ctx1p.Reset();
    isolate->ContextDisposedNotification();
  }
  {
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMemoryReducingMajorGCs(heap);
  }
  CHECK_EQ(1, NumberOfGlobalObjects());
  ctx2p.Reset();
  {
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMemoryReducingMajorGCs(heap);
  }
  CHECK_EQ(0, NumberOfGlobalObjects());
}

TEST(InstanceOfStubWriteBarrier) {
  if (!v8_flags.incremental_marking) return;
  ManualGCScope manual_gc_scope;
  v8_flags.allow_natives_syntax = true;
#ifdef VERIFY_HEAP
  v8_flags.verify_heap = true;
#endif

  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  if (!isolate->use_optimizer()) return;
  if (v8_flags.force_marking_deque_overflows) return;
  v8::HandleScope outer_scope(CcTest::isolate());
  v8::Local<v8::Context> ctx = CcTest::isolate()->GetCurrentContext();

  // Store native context in global as well to make it part of the root set when
  // starting incremental marking. This will ensure that function will be part
  // of the transitive closure during incremental marking.
  v8::Global<v8::Context> global_ctx(CcTest::isolate(), ctx);

  {
    v8::HandleScope scope(CcTest::isolate());
    CompileRun(
        "function foo () { }"
        "function mkbar () { return new (new Function(\"\")) (); }"
        "function f (x) { return (x instanceof foo); }"
        "function g () { f(mkbar()); }"
        "%PrepareFunctionForOptimization(f);"
        "f(new foo()); f(new foo());"
        "%OptimizeFunctionOnNextCall(f);"
        "f(new foo()); g();");
  }

  IncrementalMarking* marking = CcTest::heap()->incremental_marking();
  marking->Stop();
  CcTest::heap()->StartIncrementalMarking(i::GCFlag::kNoFlags,
                                          i::GarbageCollectionReason::kTesting);

  i::DirectHandle<JSFunction> f = i::Cast<JSFunction>(
      v8::Utils::OpenDirectHandle(*v8::Local<v8::Function>::Cast(
          CcTest::global()->Get(ctx, v8_str("f")).ToLocalChecked())));

  CHECK(f->HasAttachedOptimizedCode(isolate));

  MarkingState* marking_state = CcTest::heap()->marking_state();

  static constexpr auto kStepSize = v8::base::TimeDelta::FromMilliseconds(100);
  while (!marking_state->IsMarked(f->code(isolate))) {
    // Discard any pending GC requests otherwise we will get GC when we enter
    // code below.
    CHECK(!marking->IsMajorMarkingComplete());
    marking->AdvanceForTesting(kStepSize);
  }

  CHECK(marking->IsMarking());

  {
    v8::HandleScope scope(CcTest::isolate());
    v8::Local<v8::Object> global = CcTest::global();
    v8::Local<v8::Function> g = v8::Local<v8::Function>::Cast(
        global->Get(ctx, v8_str("g")).ToLocalChecked());
    g->Call(ctx, global, 0, nullptr).ToLocalChecked();
  }

  heap::InvokeMajorGC(CcTest::heap());
}

HEAP_TEST(GCFlags) {
  if (!v8_flags.incremental_marking) return;
  CcTest::InitializeVM();
  Heap* heap = CcTest::heap();

  heap->current_gc_flags_ = GCFlag::kNoFlags;
  // Check whether we appropriately reset flags after GC.
  heap::InvokeMajorGC(CcTest::heap(), GCFlag::kReduceMemoryFootprint);
  CHECK_EQ(heap->current_gc_flags_, GCFlag::kNoFlags);

  if (heap->sweeping_in_progress()) {
    heap->EnsureSweepingCompleted(
        Heap::SweepingForcedFinalizationMode::kV8Only);
  }

  IncrementalMarking* marking = heap->incremental_marking();
  marking->Stop();
  heap->StartIncrementalMarking(GCFlag::kReduceMemoryFootprint,
                                GarbageCollectionReason::kTesting);
  CHECK(heap->current_gc_flags_ & GCFlag::kReduceMemoryFootprint);

  if (!v8_flags.separate_gc_phases) {
    heap::InvokeMinorGC(heap);
    // NewSpace scavenges should not overwrite the flags.
    CHECK(heap->current_gc_flags_ & GCFlag::kReduceMemoryFootprint);
  }

  heap::InvokeMajorGC(heap, GCFlag::kNoFlags);
  CHECK_EQ(heap->current_gc_flags_, GCFlag::kNoFlags);
}

HEAP_TEST(Regress845060) {
  if (v8_flags.single_generation) return;
  // Regression test for crbug.com/845060, where a raw pointer to a string's
  // data was kept across an allocation. If the allocation causes GC and
  // moves the string, such raw pointers become invalid.
  v8_flags.allow_natives_syntax = true;
  v8_flags.stress_incremental_marking = false;
  v8_flags.stress_compaction = false;
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  LocalContext context;
  v8::HandleScope scope(CcTest::isolate());
  Heap* heap = CcTest::heap();

  // Preparation: create a string in new space.
  Local<Value> str = CompileRun("var str = (new Array(10000)).join('x'); str");
  CHECK(HeapLayout::InYoungGeneration(*v8::Utils::OpenDirectHandle(*str)));

  // Use kReduceMemoryFootprintMask to unmap from space after scavenging.
  heap->StartIncrementalMarking(i::GCFlag::kReduceMemoryFootprint,
                                GarbageCollectionReason::kTesting);

  // Run the test (which allocates results) until the original string was
  // promoted to old space. Unmapping of from_space causes accesses to any
  // stale raw pointers to crash.
  CompileRun("while (%InYoungGeneration(str)) { str.split(''); }");
  CHECK(!HeapLayout::InYoungGeneration(*v8::Utils::OpenDirectHandle(*str)));
}

TEST(OptimizedPretenuringAllocationFolding) {
  v8_flags.allow_natives_syntax = true;
  v8_flags.expose_gc = true;
  CcTest::InitializeVM();
  if (!CcTest::i_isolate()->use_optimizer() || v8_flags.always_turbofan) return;
  if (v8_flags.gc_global || v8_flags.stress_compaction ||
      v8_flags.stress_incremental_marking || v8_flags.single_generation ||
      v8_flags.stress_concurrent_allocation)
    return;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> ctx = CcTest::isolate()->GetCurrentContext();
  ManualGCScope manual_gc_scope;
  GrowNewSpaceToMaximumCapacity(CcTest::heap());

  base::ScopedVector<char> source(1024);
  base::SNPrintF(source,
                 "var number_elements = %d;"
                 "var elements = new Array();"
                 "function f() {"
                 "  for (var i = 0; i < number_elements; i++) {"
                 "    elements[i] = [[{}], [1.1]];"
                 "  }"
                 "  return elements[number_elements-1]"
                 "};"
                 "%%PrepareFunctionForOptimization(f);"
                 "f(); gc();"
                 "f(); f();"
                 "%%OptimizeFunctionOnNextCall(f);"
                 "f();",
                 kPretenureCreationCount);

  v8::Local<v8::Value> res = CompileRun(source.begin());

  v8::Local<v8::Value> int_array =
      v8::Object::Cast(*res)->Get(ctx, v8_str("0")).ToLocalChecked();
  i::DirectHandle<JSObject> int_array_handle = i::Cast<JSObject>(
      v8::Utils::OpenDirectHandle(*v8::Local<v8::Object>::Cast(int_array)));
  v8::Local<v8::Value> double_array =
      v8::Object::Cast(*res)->Get(ctx, v8_str("1")).ToLocalChecked();
  i::DirectHandle<JSObject> double_array_handle = i::Cast<JSObject>(
      v8::Utils::OpenDirectHandle(*v8::Local<v8::Object>::Cast(double_array)));

  i::DirectHandle<JSReceiver> o =
      v8::Utils::OpenDirectHandle(*v8::Local<v8::Object>::Cast(res));
  CHECK(CcTest::heap()->InOldSpace(*o));
  CHECK(CcTest::heap()->InOldSpace(*int_array_handle));
  CHECK(CcTest::heap()->InOldSpace(int_array_handle->elements()));
  CHECK(CcTest::heap()->InOldSpace(*double_array_handle));
  CHECK(CcTest::heap()->InOldSpace(double_array_handle->elements()));
}

TEST(OptimizedPretenuringObjectArrayLiterals) {
  v8_flags.allow_natives_syntax = true;
  v8_flags.expose_gc = true;
  CcTest::InitializeVM();
  if (!CcTest::i_isolate()->use_optimizer() || v8_flags.always_turbofan) return;
  if (v8_flags.gc_global || v8_flags.stress_compaction ||
      v8_flags.stress_incremental_marking || v8_flags.single_generation ||
      v8_flags.stress_concurrent_allocation) {
    return;
  }
  v8::HandleScope scope(CcTest::isolate());
  ManualGCScope manual_gc_scope;
  GrowNewSpaceToMaximumCapacity(CcTest::heap());

  base::ScopedVector<char> source(1024);
  base::SNPrintF(source,
                 "var number_elements = %d;"
                 "var elements = new Array(number_elements);"
                 "function f() {"
                 "  for (var i = 0; i < number_elements; i++) {"
                 "    elements[i] = [{}, {}, {}];"
                 "  }"
                 "  return elements[number_elements - 1];"
                 "};"
                 "%%PrepareFunctionForOptimization(f);"
                 "f(); gc();"
                 "f(); f();"
                 "%%OptimizeFunctionOnNextCall(f);"
                 "f();",
                 kPretenureCreationCount);

  v8::Local<v8::Value> res = CompileRun(source.begin());

  i::DirectHandle<JSObject> o = Cast<JSObject>(
      v8::Utils::OpenDirectHandle(*v8::Local<v8::Object>::Cast(res)));

  CHECK(CcTest::heap()->InOldSpace(o->elements()));
  CHECK(CcTest::heap()->InOldSpace(*o));
}

TEST(OptimizedPretenuringNestedInObjectProperties) {
  v8_flags.allow_natives_syntax = true;
  v8_flags.expose_gc = true;
  CcTest::InitializeVM();
  if (!CcTest::i_isolate()->use_optimizer() || v8_flags.always_turbofan) return;
  if (v8_flags.gc_global || v8_flags.stress_compaction ||
      v8_flags.stress_incremental_marking || v8_flags.single_generation ||
      v8_flags.stress_concurrent_allocation) {
    return;
  }
  v8::HandleScope scope(CcTest::isolate());
  ManualGCScope manual_gc_scope;
  GrowNewSpaceToMaximumCapacity(CcTest::heap());

  // Keep the nested literal alive while its root is freed
  base::ScopedVector<char> source(1024);
  base::SNPrintF(
      source,
      "let number_elements = %d;"
      "let elements = new Array(number_elements);"
      "function f() {"
      "  for (let i = 0; i < number_elements; i++) {"
      "     let l =  {a: {b: {c: {d: {e: 2.2}, e: 3.3}, g: {h: 1.1}}}}; "
      "    elements[i] = l.a.b.c.d;"
      "  }"
      "  return elements[number_elements-1];"
      "};"
      "%%PrepareFunctionForOptimization(f);"
      "f(); gc(); gc();"
      "f(); f();"
      "%%OptimizeFunctionOnNextCall(f);"
      "f();",
      kPretenureCreationCount);

  v8::Local<v8::Value> res = CompileRun(source.begin());

  i::DirectHandle<JSObject> o = Cast<JSObject>(
      v8::Utils::OpenDirectHandle(*v8::Local<v8::Object>::Cast(res)));

  // Nested literal sites are only pretenured if the top level
  // literal is pretenured
  CHECK(HeapLayout::InYoungGeneration(*o));
}

TEST(OptimizedPretenuringMixedInObjectProperties) {
  v8_flags.allow_natives_syntax = true;
  v8_flags.expose_gc = true;
  CcTest::InitializeVM();
  if (!CcTest::i_isolate()->use_optimizer() || v8_flags.always_turbofan) return;
  if (v8_flags.gc_global || v8_flags.stress_compaction ||
      v8_flags.stress_incremental_marking || v8_flags.single_generation ||
      v8_flags.stress_concurrent_allocation)
    return;
  v8::HandleScope scope(CcTest::isolate());
  ManualGCScope manual_gc_scope;
  GrowNewSpaceToMaximumCapacity(CcTest::heap());

  base::ScopedVector<char> source(1024);
  base::SNPrintF(source,
                 "var number_elements = %d;"
                 "var elements = new Array(number_elements);"
                 "function f() {"
                 "  for (var i = 0; i < number_elements; i++) {"
                 "    elements[i] = {a: {c: 2.2, d: {}}, b: 1.1};"
                 "  }"
                 "  return elements[number_elements - 1];"
                 "};"
                 "%%PrepareFunctionForOptimization(f);"
                 "f(); gc();"
                 "f(); f();"
                 "%%OptimizeFunctionOnNextCall(f);"
                 "f();",
                 kPretenureCreationCount);

  v8::Local<v8::Value> res = CompileRun(source.begin());

  i::DirectHandle<JSObject> o = Cast<JSObject>(
      v8::Utils::OpenDirectHandle(*v8::Local<v8::Object>::Cast(res)));

  CHECK(CcTest::heap()->InOldSpace(*o));
  FieldIndex idx1 = FieldIndex::ForPropertyIndex(o->map(), 0);
  FieldIndex idx2 = FieldIndex::ForPropertyIndex(o->map(), 1);
  CHECK(CcTest::heap()->InOldSpace(o->RawFastPropertyAt(idx1)));
  CHECK(CcTest::heap()->InOldSpace(o->RawFastPropertyAt(idx2)));

  Tagged<JSObject> inner_object = Cast<JSObject>(o->RawFastPropertyAt(idx1));
  CHECK(CcTest::heap()->InOldSpace(inner_object));
  CHECK(CcTest::heap()->InOldSpace(inner_object->RawFastPropertyAt(idx1)));
  CHECK(CcTest::heap()->InOldSpace(inner_object->RawFastPropertyAt(idx2)));
}

TEST(OptimizedPretenuringDoubleArrayProperties) {
  v8_flags.allow_natives_syntax = true;
  v8_flags.expose_gc = true;
  CcTest::InitializeVM();
  if (!CcTest::i_isolate()->use_optimizer() || v8_flags.always_turbofan) return;
  if (v8_flags.gc_global || v8_flags.stress_compaction ||
      v8_flags.stress_incremental_marking || v8_flags.single_generation ||
      v8_flags.stress_concurrent_allocation)
    return;
  v8::HandleScope scope(CcTest::isolate());
  ManualGCScope manual_gc_scope;
  GrowNewSpaceToMaximumCapacity(CcTest::heap());

  base::ScopedVector<char> source(1024);
  base::SNPrintF(source,
                 "var number_elements = %d;"
                 "var elements = new Array(number_elements);"
                 "function f() {"
                 "  for (var i = 0; i < number_elements; i++) {"
                 "    elements[i] = {a: 1.1, b: 2.2};"
                 "  }"
                 "  return elements[i - 1];"
                 "};"
                 "%%PrepareFunctionForOptimization(f);"
                 "f(); gc();"
                 "f(); f();"
                 "%%OptimizeFunctionOnNextCall(f);"
                 "f();",
                 kPretenureCreationCount);

  v8::Local<v8::Value> res = CompileRun(source.begin());

  i::DirectHandle<JSObject> o = Cast<JSObject>(
      v8::Utils::OpenDirectHandle(*v8::Local<v8::Object>::Cast(res)));

  CHECK(CcTest::heap()->InOldSpace(*o));
  CHECK_EQ(o->property_array(),
           ReadOnlyRoots(CcTest::heap()).empty_property_array());
}

TEST(OptimizedPretenuringDoubleArrayLiterals) {
  v8_flags.allow_natives_syntax = true;
  v8_flags.expose_gc = true;
  CcTest::InitializeVM();
  if (!CcTest::i_isolate()->use_optimizer() || v8_flags.always_turbofan) return;
  if (v8_flags.gc_global || v8_flags.stress_compaction ||
      v8_flags.stress_incremental_marking || v8_flags.single_generation ||
      v8_flags.stress_concurrent_allocation)
    return;
  v8::HandleScope scope(CcTest::isolate());
  ManualGCScope manual_gc_scope;
  GrowNewSpaceToMaximumCapacity(CcTest::heap());

  base::ScopedVector<char> source(1024);
  base::SNPrintF(source,
                 "var number_elements = %d;"
                 "var elements = new Array(number_elements);"
                 "function f() {"
                 "  for (var i = 0; i < number_elements; i++) {"
                 "    elements[i] = [1.1, 2.2, 3.3];"
                 "  }"
                 "  return elements[number_elements - 1];"
                 "};"
                 "%%PrepareFunctionForOptimization(f);"
                 "f(); gc();"
                 "f(); f();"
                 "%%OptimizeFunctionOnNextCall(f);"
                 "f();",
                 kPretenureCreationCount);

  v8::Local<v8::Value> res = CompileRun(source.begin());

  i::DirectHandle<JSObject> o = Cast<JSObject>(
      v8::Utils::OpenDirectHandle(*v8::Local<v8::Object>::Cast(res)));

  CHECK(CcTest::heap()->InOldSpace(o->elements()));
  CHECK(CcTest::heap()->InOldSpace(*o));
}

TEST(OptimizedPretenuringNestedMixedArrayLiterals) {
  v8_flags.allow_natives_syntax = true;
  v8_flags.expose_gc = true;
  CcTest::InitializeVM();
  if (!CcTest::i_isolate()->use_optimizer() || v8_flags.always_turbofan) return;
  if (v8_flags.gc_global || v8_flags.stress_compaction ||
      v8_flags.stress_incremental_marking || v8_flags.single_generation ||
      v8_flags.stress_concurrent_allocation)
    return;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> ctx = CcTest::isolate()->GetCurrentContext();
  ManualGCScope manual_gc_scope;
  GrowNewSpaceToMaximumCapacity(CcTest::heap());

  base::ScopedVector<char> source(1024);
  base::SNPrintF(source,
                 "var number_elements = %d;"
                 "var elements = new Array(number_elements);"
                 "function f() {"
                 "  for (var i = 0; i < number_elements; i++) {"
                 "    elements[i] = [[{}, {}, {}], [1.1, 2.2, 3.3]];"
                 "  }"
                 "  return elements[number_elements - 1];"
                 "};"
                 "%%PrepareFunctionForOptimization(f);"
                 "f(); gc();"
                 "f(); f();"
                 "%%OptimizeFunctionOnNextCall(f);"
                 "f();",
                 kPretenureCreationCount);

  v8::Local<v8::Value> res = CompileRun(source.begin());

  v8::Local<v8::Value> int_array =
      v8::Object::Cast(*res)->Get(ctx, v8_str("0")).ToLocalChecked();
  i::DirectHandle<JSObject> int_array_handle = i::Cast<JSObject>(
      v8::Utils::OpenDirectHandle(*v8::Local<v8::Object>::Cast(int_array)));
  v8::Local<v8::Value> double_array =
      v8::Object::Cast(*res)->Get(ctx, v8_str("1")).ToLocalChecked();
  i::DirectHandle<JSObject> double_array_handle = i::Cast<JSObject>(
      v8::Utils::OpenDirectHandle(*v8::Local<v8::Object>::Cast(double_array)));

  DirectHandle<JSObject> o = Cast<JSObject>(
      v8::Utils::OpenDirectHandle(*v8::Local<v8::Object>::Cast(res)));
  CHECK(CcTest::heap()->InOldSpace(*o));
  CHECK(CcTest::heap()->InOldSpace(*int_array_handle));
  CHECK(CcTest::heap()->InOldSpace(int_array_handle->elements()));
  CHECK(CcTest::heap()->InOldSpace(*double_array_handle));
  CHECK(CcTest::heap()->InOldSpace(double_array_handle->elements()));
}

TEST(OptimizedPretenuringNestedObjectLiterals) {
  v8_flags.allow_natives_syntax = true;
  v8_flags.expose_gc = true;
  CcTest::InitializeVM();
  if (!CcTest::i_isolate()->use_optimizer() || v8_flags.always_turbofan) return;
  if (v8_flags.gc_global || v8_flags.stress_compaction ||
      v8_flags.stress_incremental_marking || v8_flags.single_generation ||
      v8_flags.stress_concurrent_allocation)
    return;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> ctx = CcTest::isolate()->GetCurrentContext();
  ManualGCScope manual_gc_scope;
  GrowNewSpaceToMaximumCapacity(CcTest::heap());

  base::ScopedVector<char> source(1024);
  base::SNPrintF(source,
                 "var number_elements = %d;"
                 "var elements = new Array(number_elements);"
                 "function f() {"
                 "  for (var i = 0; i < number_elements; i++) {"
                 "    elements[i] = [[{}, {}, {}],[{}, {}, {}]];"
                 "  }"
                 "  return elements[number_elements - 1];"
                 "};"
                 "%%PrepareFunctionForOptimization(f);"
                 "f(); gc();"
                 "f(); f();"
                 "%%OptimizeFunctionOnNextCall(f);"
                 "f();",
                 kPretenureCreationCount);

  v8::Local<v8::Value> res = CompileRun(source.begin());

  v8::Local<v8::Value> int_array_1 =
      v8::Object::Cast(*res)->Get(ctx, v8_str("0")).ToLocalChecked();
  DirectHandle<JSObject> int_array_handle_1 = Cast<JSObject>(
      v8::Utils::OpenDirectHandle(*v8::Local<v8::Object>::Cast(int_array_1)));
  v8::Local<v8::Value> int_array_2 =
      v8::Object::Cast(*res)->Get(ctx, v8_str("1")).ToLocalChecked();
  DirectHandle<JSObject> int_array_handle_2 = Cast<JSObject>(
      v8::Utils::OpenDirectHandle(*v8::Local<v8::Object>::Cast(int_array_2)));

  DirectHandle<JSObject> o = Cast<JSObject>(
      v8::Utils::OpenDirectHandle(*v8::Local<v8::Object>::Cast(res)));
  CHECK(CcTest::heap()->InOldSpace(*o));
  CHECK(CcTest::heap()->InOldSpace(*int_array_handle_1));
  CHECK(CcTest::heap()->InOldSpace(int_array_handle_1->elements()));
  CHECK(CcTest::heap()->InOldSpace(*int_array_handle_2));
  CHECK(CcTest::heap()->InOldSpace(int_array_handle_2->elements()));
}

TEST(OptimizedPretenuringNestedDoubleLiterals) {
  v8_flags.allow_natives_syntax = true;
  v8_flags.expose_gc = true;
  CcTest::InitializeVM();
  if (!CcTest::i_isolate()->use_optimizer() || v8_flags.always_turbofan) return;
  if (v8_flags.gc_global || v8_flags.stress_compaction ||
      v8_flags.stress_incremental_marking || v8_flags.single_generation ||
      v8_flags.stress_concurrent_allocation)
    return;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> ctx = CcTest::isolate()->GetCurrentContext();
  ManualGCScope manual_gc_scope;
  GrowNewSpaceToMaximumCapacity(CcTest::heap());

  base::ScopedVector<char> source(1024);
  base::SNPrintF(source,
                 "var number_elements = %d;"
                 "var elements = new Array(number_elements);"
                 "function f() {"
                 "  for (var i = 0; i < number_elements; i++) {"
                 "    elements[i] = [[1.1, 1.2, 1.3],[2.1, 2.2, 2.3]];"
                 "  }"
                 "  return elements[number_elements - 1];"
                 "};"
                 "%%PrepareFunctionForOptimization(f);"
                 "f(); gc();"
                 "f(); f();"
                 "%%OptimizeFunctionOnNextCall(f);"
                 "f();",
                 kPretenureCreationCount);

  v8::Local<v8::Value> res = CompileRun(source.begin());

  v8::Local<v8::Value> double_array_1 =
      v8::Object::Cast(*res)->Get(ctx, v8_str("0")).ToLocalChecked();
  i::DirectHandle<JSObject> double_array_handle_1 =
      i::Cast<JSObject>(v8::Utils::OpenDirectHandle(
          *v8::Local<v8::Object>::Cast(double_array_1)));
  v8::Local<v8::Value> double_array_2 =
      v8::Object::Cast(*res)->Get(ctx, v8_str("1")).ToLocalChecked();
  i::DirectHandle<JSObject> double_array_handle_2 =
      Cast<JSObject>(v8::Utils::OpenDirectHandle(
          *v8::Local<v8::Object>::Cast(double_array_2)));

  i::DirectHandle<JSObject> o = Cast<JSObject>(
      v8::Utils::OpenDirectHandle(*v8::Local<v8::Object>::Cast(res)));
  CHECK(CcTest::heap()->InOldSpace(*o));
  CHECK(CcTest::heap()->InOldSpace(*double_array_handle_1));
  CHECK(CcTest::heap()->InOldSpace(double_array_handle_1->elements()));
  CHECK(CcTest::heap()->InOldSpace(*double_array_handle_2));
  CHECK(CcTest::heap()->InOldSpace(double_array_handle_2->elements()));
}

// Test regular array literals allocation.
TEST(OptimizedAllocationArrayLiterals) {
  v8_flags.allow_natives_syntax = true;
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  if (!CcTest::i_isolate()->use_optimizer() || v8_flags.always_turbofan) return;
  if (v8_flags.gc_global || v8_flags.stress_compaction ||
      v8_flags.stress_incremental_marking)
    return;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> ctx = CcTest::isolate()->GetCurrentContext();
  v8::Local<v8::Value> res = CompileRun(
      "function f() {"
      "  var numbers = new Array(1, 2, 3);"
      "  numbers[0] = 3.14;"
      "  return numbers;"
      "};"
      "%PrepareFunctionForOptimization(f);"
      "f(); f(); f();"
      "%OptimizeFunctionOnNextCall(f);"
      "f();");
  CHECK_EQ(static_cast<int>(3.14), v8::Object::Cast(*res)
                                       ->Get(ctx, v8_str("0"))
                                       .ToLocalChecked()
                                       ->Int32Value(ctx)
                                       .FromJust());

  i::DirectHandle<JSObject> o = Cast<JSObject>(
      v8::Utils::OpenDirectHandle(*v8::Local<v8::Object>::Cast(res)));

  CHECK(InCorrectGeneration(o->elements()));
}

static int CountMapTransitions(i::Isolate* isolate, Tagged<Map> map) {
  return TransitionsAccessor(isolate, map).NumberOfTransitions();
}

// Test that map transitions are cleared and maps are collected with
// incremental marking as well.
TEST(Regress1465) {
  if (!v8_flags.incremental_marking) return;
  v8_flags.stress_compaction = false;
  v8_flags.stress_incremental_marking = false;
  v8_flags.allow_natives_syntax = true;
  v8_flags.trace_incremental_marking = true;
  v8_flags.retain_maps_for_n_gc = 0;
  CcTest::InitializeVM();
  v8::Isolate* isolate = CcTest::isolate();
  i::Isolate* i_isolate = CcTest::i_isolate();
  Heap* heap = CcTest::heap();
  v8::HandleScope scope(isolate);
  static const int transitions_count = 256;

  CompileRun("function F() {}");
  {
    AlwaysAllocateScopeForTesting always_allocate(heap);
    for (int i = 0; i < transitions_count; i++) {
      base::EmbeddedVector<char, 64> buffer;
      base::SNPrintF(buffer, "var o = new F; o.prop%d = %d;", i, i);
      CompileRun(buffer.begin());
    }
    CompileRun("var root = new F;");
  }

  i::IndirectHandle<JSReceiver> root =
      v8::Utils::OpenIndirectHandle(*v8::Local<v8::Object>::Cast(
          CcTest::global()
              ->Get(isolate->GetCurrentContext(), v8_str("root"))
              .ToLocalChecked()));

  // Count number of live transitions before marking.
  int transitions_before = CountMapTransitions(i_isolate, root->map());
  CompileRun("%DebugPrint(root);");
  CHECK_EQ(transitions_count, transitions_before);

  heap::SimulateIncrementalMarking(heap);
  {
    // In this test, we need to invoke GC without stack, otherwise some objects
    // may not be reclaimed because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMajorGC(heap);
  }

  // Count number of live transitions after marking.  Note that one transition
  // is left, because 'o' still holds an instance of one transition target.
  int transitions_after = CountMapTransitions(i_isolate, root->map());
  CompileRun("%DebugPrint(root);");
  CHECK_EQ(1, transitions_after);
}

static i::Handle<JSObject> GetByName(const char* name) {
  return i::Cast<i::JSObject>(
      v8::Utils::OpenHandle(*v8::Local<v8::Object>::Cast(
          CcTest::global()
              ->Get(CcTest::isolate()->GetCurrentContext(), v8_str(name))
              .ToLocalChecked())));
}

#ifdef DEBUG
static void AddTransitions(int transitions_count) {
  AlwaysAllocateScopeForTesting always_allocate(CcTest::i_isolate()->heap());
  for (int i = 0; i < transitions_count; i++) {
    base::EmbeddedVector<char, 64> buffer;
    base::SNPrintF(buffer, "var o = new F; o.prop%d = %d;", i, i);
    CompileRun(buffer.begin());
  }
}

static void AddPropertyTo(int gc_count, Handle<JSObject> object,
                          const char* property_name) {
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  Handle<String> prop_name = factory->InternalizeUtf8String(property_name);
  Handle<Smi> twenty_three(Smi::FromInt(23), isolate);
  HeapAllocator::SetAllocationGcInterval(gc_count);
  v8_flags.gc_global = true;
  v8_flags.retain_maps_for_n_gc = 0;
  CcTest::heap()->set_allocation_timeout(gc_count);
  Object::SetProperty(isolate, object, prop_name, twenty_three).Check();
}

TEST(TransitionArrayShrinksDuringAllocToZero) {
  v8_flags.stress_compaction = false;
  v8_flags.stress_incremental_marking = false;
  v8_flags.allow_natives_syntax = true;
  CcTest::InitializeVM();
  i::Isolate* i_isolate = CcTest::i_isolate();
  v8::HandleScope scope(CcTest::isolate());
  static const int transitions_count = 10;
  CompileRun("function F() { }");
  AddTransitions(transitions_count);
  CompileRun("var root = new F;");
  IndirectHandle<JSObject> root = GetByName("root");

  // Count number of live transitions before marking.
  int transitions_before = CountMapTransitions(i_isolate, root->map());
  CHECK_EQ(transitions_count, transitions_before);

  // Get rid of o
  CompileRun(
      "o = new F;"
      "root = new F");
  root = GetByName("root");
  AddPropertyTo(2, root, "funny");
  {
    // We need to invoke GC without stack, otherwise some objects may not be
    // reclaimed because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    heap::InvokeMinorGC(CcTest::heap());
  }

  // Count number of live transitions after marking.  Note that one transition
  // is left, because 'o' still holds an instance of one transition target.
  int transitions_after =
      CountMapTransitions(i_isolate, Cast<Map>(root->map()->GetBackPointer()));
  CHECK_EQ(1, transitions_after);
}

TEST(TransitionArrayShrinksDuringAllocToOne) {
  v8_flags.stress_compaction = false;
  v8_flags.stress_incremental_marking = false;
  v8_flags.allow_natives_syntax = true;
  CcTest::InitializeVM();
  i::Isolate* i_isolate = CcTest::i_isolate();
  v8::HandleScope scope(CcTest::isolate());
  static const int transitions_count = 10;
  CompileRun("function F() {}");
  AddTransitions(transitions_count);
  CompileRun("var root = new F;");
  IndirectHandle<JSObject> root = GetByName("root");

  // Count number of live transitions before marking.
  int transitions_before = CountMapTransitions(i_isolate, root->map());
  CHECK_EQ(transitions_count, transitions_before);

  root = GetByName("root");
  AddPropertyTo(2, root, "funny");
  {
    // We need to invoke GC without stack, otherwise some objects may not be
    // reclaimed because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    heap::InvokeMinorGC(CcTest::heap());
  }

  // Count number of live transitions after marking.  Note that one transition
  // is left, because 'o' still holds an instance of one transition target.
  int transitions_after =
      CountMapTransitions(i_isolate, Cast<Map>(root->map()->GetBackPointer()));
  CHECK_EQ(2, transitions_after);
}

TEST(TransitionArrayShrinksDuringAllocToOnePropertyFound) {
  v8_flags.stress_compaction = false;
  v8_flags.stress_incremental_marking = false;
  v8_flags.allow_natives_syntax = true;
  CcTest::InitializeVM();
  i::Isolate* i_isolate = CcTest::i_isolate();
  v8::HandleScope scope(CcTest::isolate());
  static const int transitions_count = 10;
  CompileRun("function F() {}");
  AddTransitions(transitions_count);
  CompileRun("var root = new F;");
  Handle<JSObject> root = GetByName("root");

  // Count number of live transitions before marking.
  int transitions_before = CountMapTransitions(i_isolate, root->map());
  CHECK_EQ(transitions_count, transitions_before);

  root = GetByName("root");
  AddPropertyTo(0, root, "prop9");
  heap::InvokeMajorGC(CcTest::heap());

  // Count number of live transitions after marking.  Note that one transition
  // is left, because 'o' still holds an instance of one transition target.
  int transitions_after =
      CountMapTransitions(i_isolate, Cast<Map>(root->map()->GetBackPointer()));
  CHECK_EQ(1, transitions_after);
}
#endif  // DEBUG

TEST(ReleaseOverReservedPages) {
  if (!v8_flags.compact) return;
  v8_flags.trace_gc = true;
  // The optimizer can allocate stuff, messing up the test.
#if !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
  v8_flags.turbofan = false;
  v8_flags.always_turbofan = false;
#endif  // !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
  // - Parallel compaction increases fragmentation, depending on how existing
  //   memory is distributed. Since this is non-deterministic because of
  //   concurrent sweeping, we disable it for this test.
  // - Concurrent sweeping adds non determinism, depending on when memory is
  //   available for further reuse.
  // - Fast evacuation of pages may result in a different page count in old
  //   space.
  ManualGCScope manual_gc_scope;
  v8_flags.page_promotion = false;
  v8_flags.parallel_compaction = false;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  // If there's snapshot available, we don't know whether 20 small arrays will
  // fit on the initial pages.
  if (!isolate->snapshot_available()) return;
  Factory* factory = isolate->factory();
  Heap* heap = isolate->heap();
  v8::HandleScope scope(CcTest::isolate());

  // Ensure that the young generation is empty.
  {
    // In this test, we need to invoke GC without stack, otherwise some objects
    // may not be reclaimed because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::EmptyNewSpaceUsingGC(heap);
  }
  static const int number_of_test_pages = 20;

  // Prepare many pages with low live-bytes count.
  PagedSpace* old_space = heap->old_space();
  const int initial_page_count = old_space->CountTotalPages();
  const int overall_page_count = number_of_test_pages + initial_page_count;
  for (int i = 0; i < number_of_test_pages; i++) {
    AlwaysAllocateScopeForTesting always_allocate(heap);
    {
      DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
      heap::SimulateFullSpace(old_space);
    }
    factory->NewFixedArray(1, AllocationType::kOld);
  }
  CHECK_EQ(overall_page_count, old_space->CountTotalPages());

  DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);

  // Triggering one GC will cause a lot of garbage to be discovered but
  // even spread across all allocated pages.
  heap::InvokeMajorGC(heap);
  CHECK_GE(overall_page_count, old_space->CountTotalPages());

  // Triggering subsequent GCs should cause at least half of the pages
  // to be released to the OS after at most two cycles.
  heap::InvokeMajorGC(heap);
  CHECK_GE(overall_page_count, old_space->CountTotalPages());
  heap::InvokeMajorGC(heap);
  CHECK_GE(number_of_test_pages,
           (old_space->CountTotalPages() - initial_page_count) * 2);

  // Triggering a last-resort GC should cause all pages to be released to the
  // OS so that other processes can seize the memory.  If we get a failure here
  // where there are 2 pages left
"""


```