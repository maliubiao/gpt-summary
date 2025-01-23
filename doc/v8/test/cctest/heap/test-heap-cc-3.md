Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/test/cctest/heap/test-heap.cc`.

Here's a breakdown of how to address each of the user's requirements:

1. **List its functions:**  I need to analyze the code and identify the tests being performed. The `HEAP_TEST` and `TEST` macros indicate individual test functions.

2. **Check for Torque source:** I need to explicitly check if the filename ends with `.tq`. This is a straightforward check.

3. **Relate to Javascript:**  Since these are tests related to the V8 heap, many tests will involve running Javascript code to trigger specific heap behaviors. I should look for examples of `CompileRun` which executes Javascript.

4. **Provide Javascript examples:** When a test manipulates the heap via Javascript, I need to extract those Javascript snippets and explain what they do in relation to the test.

5. **Code logic reasoning (input/output):** For tests that involve more complex logic or assertions, I need to deduce the intended input conditions and the expected output or state. This often involves analyzing the setup and the `CHECK` statements.

6. **Common programming errors:**  Some tests might be specifically designed to catch or demonstrate common errors related to memory management in Javascript. I need to identify these scenarios and explain the potential pitfalls.

7. **Part of a series:**  The user mentions this is part 4 of 9. This context isn't directly relevant to summarizing the functionality of *this specific snippet*, but it's good to keep in mind.

8. **Summarize the functionality:** Based on the analysis of all the tests, I need to provide a concise overall summary of what this section of the test file is designed to verify. This will likely focus on heap behavior under various conditions, especially related to garbage collection and optimization.

**Mental Walkthrough of the Code:**

* I'll go through each `HEAP_TEST` and `TEST` block.
* For each test, I'll try to understand the core goal. What aspect of the heap is being tested?
* I'll look for calls to `CompileRun` to see the Javascript involved.
* I'll pay attention to `CHECK` statements to understand the expected outcomes.
* I'll identify any setup steps (like initializing the VM or setting flags).
* I'll look for patterns like preparing functions for optimization.
* I'll consider if a test relates to specific GC scenarios (incremental marking, minor/major GC).
* I'll watch for tests that seem designed to trigger edge cases or potential bugs (like the `Regress845060` test).

**Pre-computation/Pre-analysis:**

* The presence of `v8_flags` suggests that many tests involve configuring specific V8 runtime behaviors.
* The use of `ManualGCScope` indicates tests that explicitly trigger garbage collection.
* The `OptimizedPretenuring*` tests suggest verification of how the compiler optimizes object allocation by pre-allocating in old space.
* The tests involving map transitions indicate verification of map management during garbage collection.

By following these steps, I should be able to generate a comprehensive summary that addresses all the user's requirements.
Let's break down the functionality of the provided C++ code snippet from `v8/test/cctest/heap/test-heap.cc`.

**Overall Functionality:**

This section of `test-heap.cc` primarily focuses on testing various aspects of V8's garbage collection (GC) and heap management, particularly related to:

* **Incremental Marking:** How the incremental marking process affects object marking and the interaction between Javascript execution and the garbage collector.
* **GC Flags:**  Ensuring GC flags are correctly set and reset during different types of garbage collection.
* **Regression Tests:** Specifically addressing and fixing previously identified bugs, such as memory corruption issues related to raw pointers and string promotion.
* **Optimized Allocation (Pretenuring):** Verifying that the V8 optimizer can correctly pre-allocate objects in old space during function optimization, which can improve performance. This includes tests for various object types like arrays, objects with properties, and nested literals.
* **Map Transitions:** Testing that map transitions (used for optimizing object property access) are correctly managed and collected during garbage collection, especially incremental marking.
* **Releasing Over-Reserved Pages:**  Checking that the heap can release unused memory pages back to the operating system after garbage collection.

**Specific Test Breakdown:**

1. **`HEAP_TEST(IncrementalMarkingAndCodePointers)`:**
   - **Functionality:** This test verifies that when incremental marking is active, optimized code (specifically for the function `f`) is correctly marked as reachable during the incremental marking process. It ensures that the execution of Javascript code (`g()`) which relies on this optimized code works correctly even during incremental marking.
   - **JavaScript Example:**
     ```javascript
     function foo () { }
     function mkbar () { return new (new Function("")) (); }
     function f (x) { return (x instanceof foo); }
     function g () { f(mkbar()); }
     %PrepareFunctionForOptimization(f);
     f(new foo()); f(new foo());
     %OptimizeFunctionOnNextCall(f);
     f(new foo()); g();
     ```
     - `foo`: A simple constructor function.
     - `mkbar`: Creates a new anonymous object.
     - `f`: Checks if an object is an instance of `foo`. This function is prepared for and then optimized by V8.
     - `g`: Calls `f` with an object created by `mkbar`.
     - The test ensures that even though `mkbar`'s result is not directly related to `foo`, the optimized `f` function handles it correctly during incremental marking.
   - **Code Logic Reasoning:**
     - **Assumption:** Incremental marking is enabled.
     - **Input:** The Javascript code snippet above is executed.
     - **Output:** The test checks that the optimized code for `f` is marked during incremental marking, allowing `g()` to execute without issues.
   - **User Common Programming Error (Indirectly Related):** This test touches on the importance of V8's garbage collection correctly identifying reachable code. A common error could be relying on objects or code to stay alive indefinitely without considering garbage collection, which could lead to unexpected behavior if V8's GC wasn't working correctly.

2. **`HEAP_TEST(GCFlags)`:**
   - **Functionality:**  This test checks that GC flags (like `kReduceMemoryFootprint`) are correctly set before a garbage collection and then reset to the default (`kNoFlags`) afterwards. It also verifies that minor GCs (scavenges) don't overwrite existing GC flags set for a major GC.
   - **Code Logic Reasoning:**
     - **Assumption:** Incremental marking is enabled.
     - **Input:**  Calls to `InvokeMajorGC` and `InvokeMinorGC` with specific GC flags.
     - **Output:**  Assertions (`CHECK_EQ`, `CHECK`) verifying the `current_gc_flags_` of the heap at different points.

3. **`HEAP_TEST(Regress845060)`:**
   - **Functionality:** This is a regression test for a specific bug where a raw pointer to a string's data could become invalid after a garbage collection that moves the string. The test creates a string in new space and then forces its promotion to old space while accessing it, aiming to trigger the bug if it wasn't fixed.
   - **JavaScript Example:**
     ```javascript
     var str = (new Array(10000)).join('x'); // Creates a string
     while (%InYoungGeneration(str)) { str.split(''); } // Forces allocation and potential GC
     ```
   - **Code Logic Reasoning:**
     - **Assumption:**  The bug (keeping raw pointers across GC) could lead to crashes when the string is moved.
     - **Input:**  The Javascript code is executed, potentially triggering a garbage collection.
     - **Output:** The test checks that the string is eventually promoted to old space without crashing, indicating the bug is fixed.
   - **User Common Programming Error:**  This highlights the danger of manually managing memory or relying on raw pointers to V8 objects, which can be invalidated by garbage collection. V8's managed memory model generally prevents users from needing to do this directly in JavaScript, but this test ensures the internal workings are sound.

4. **`TEST(OptimizedPretenuringAllocationFolding)`**, **`TEST(OptimizedPretenuringObjectArrayLiterals)`**, **`TEST(OptimizedPretenuringNestedInObjectProperties)`**, **`TEST(OptimizedPretenuringMixedInObjectProperties)`**, **`TEST(OptimizedPretenuringDoubleArrayProperties)`**, **`TEST(OptimizedPretenuringDoubleArrayLiterals)`**, **`TEST(OptimizedPretenuringNestedMixedArrayLiterals)`**, **`TEST(OptimizedPretenuringNestedObjectLiterals)`**, **`TEST(OptimizedPretenuringNestedDoubleLiterals)`:**
   - **Functionality:** These tests focus on "pretenuring," an optimization where the compiler predicts that certain objects will live long and allocates them directly in old space, skipping the usual young generation allocation. This can reduce the frequency of minor GCs. Each test targets a slightly different scenario:
     - `AllocationFolding`:  Tests pretenuring of arrays containing other arrays with different element types.
     - `ObjectArrayLiterals`: Tests pretenuring of arrays containing objects.
     - `NestedInObjectProperties`: Tests pretenuring of nested object literals within object properties (note: in this specific test, nested literals are *not* pretenured if the top-level isn't).
     - `MixedInObjectProperties`: Tests pretenuring when an object has both object and primitive properties.
     - `DoubleArrayProperties`: Tests pretenuring of objects with double (floating-point) properties.
     - `DoubleArrayLiterals`: Tests pretenuring of arrays containing double values.
     - `NestedMixedArrayLiterals`: Tests pretenuring of nested arrays with mixed element types.
     - `NestedObjectLiterals`: Tests pretenuring of nested arrays of objects.
     - `NestedDoubleLiterals`: Tests pretenuring of nested arrays of double values.
   - **JavaScript Example (Common Pattern):**
     ```javascript
     var number_elements = %d; // Some constant value
     var elements = new Array(number_elements);
     function f() {
       for (var i = 0; i < number_elements; i++) {
         elements[i] = /* Some object or array literal */;
       }
       return elements[number_elements - 1];
     };
     %PrepareFunctionForOptimization(f);
     f(); gc(); // Call to trigger potential pretenuring
     f(); f();
     %OptimizeFunctionOnNextCall(f);
     f();
     ```
   - **Code Logic Reasoning:**
     - **Assumption:** The `%PrepareFunctionForOptimization` and `%OptimizeFunctionOnNextCall` intrinsics trigger optimization.
     - **Input:** The Javascript code that creates specific object or array structures.
     - **Output:** The tests use `CHECK(CcTest::heap()->InOldSpace(...))` to verify that the created objects and their internal structures (like backing stores for arrays) are allocated in old space after optimization.
   - **User Common Programming Error (Indirectly Related):** While pretenuring is an optimization handled by V8, understanding how object creation patterns can influence performance is important. Creating many short-lived objects can put pressure on the young generation, while patterns leading to pretenuring can be more efficient for long-lived data.

5. **`TEST(OptimizedAllocationArrayLiterals)`:**
   - **Functionality:** This test checks the optimized allocation of regular array literals (not necessarily pretenuring in old space, but efficient allocation).
   - **JavaScript Example:**
     ```javascript
     function f() {
       var numbers = new Array(1, 2, 3);
       numbers[0] = 3.14; // Forces a double array
       return numbers;
     };
     %PrepareFunctionForOptimization(f);
     f(); f(); f();
     %OptimizeFunctionOnNextCall(f);
     f();
     ```
   - **Code Logic Reasoning:**
     - **Assumption:** Optimization leads to efficient array allocation.
     - **Input:** Javascript code creating and modifying an array.
     - **Output:** `CHECK(InCorrectGeneration(o->elements()))` verifies that the array's backing store is allocated in the expected generation (likely young generation in this case, as it's not explicitly testing pretenuring to old space).

6. **`TEST(Regress1465)`:**
   - **Functionality:** This is a regression test related to map transitions. It verifies that map transitions, which are created as objects evolve (e.g., adding properties), are correctly cleared and the associated maps are collected during incremental marking and garbage collection.
   - **JavaScript Example:**
     ```javascript
     function F() {}
     // ... loop adding properties to instances of F ...
     var o = new F; o.prop0 = 0;
     var root = new F;
     ```
   - **Code Logic Reasoning:**
     - **Assumption:**  Map transitions consume memory and should be collectable.
     - **Input:** Javascript code creating objects and adding properties, followed by triggering incremental marking and a major GC.
     - **Output:** The test counts the number of map transitions before and after GC, ensuring that the number decreases after garbage collection.

7. **`TEST(TransitionArrayShrinksDuringAllocToZero)`**, **`TEST(TransitionArrayShrinksDuringAllocToOne)`**, **`TEST(TransitionArrayShrinksDuringAllocToOnePropertyFound)`:**
   - **Functionality:** These tests (under `#ifdef DEBUG`) explore how the transition array within a map shrinks during allocation and garbage collection. They focus on scenarios where transitions become unreachable.
   - **JavaScript Example (Common Pattern):**
     ```javascript
     function F() {}
     // ... add multiple properties to instances of F ...
     var root = new F;
     // ... later, potentially make some transitions unreachable ...
     ```
   - **Code Logic Reasoning:**
     - **Assumption:** Unreachable map transitions should be garbage collected.
     - **Input:** Javascript code manipulating object properties and triggering GCs.
     - **Output:** The tests check the number of map transitions after specific GC events, verifying that unreachable transitions are removed.

8. **`TEST(ReleaseOverReservedPages)`:**
   - **Functionality:** This test verifies that the heap can release over-reserved memory pages back to the operating system after garbage collection, especially after a period of high allocation followed by the collection of those objects. This is important for efficient memory usage.
   - **Code Logic Reasoning:**
     - **Assumption:**  The heap should not hold onto excessive memory when it's no longer needed.
     - **Input:**  Allocate many objects to fill up pages, then trigger garbage collection to reclaim them.
     - **Output:** The test checks the number of total pages in the old generation before and after garbage collection, verifying that pages are released.

**In summary, this section of the `test-heap.cc` file meticulously tests various aspects of V8's heap management and garbage collection mechanisms, including incremental marking, GC flag handling, regression fixes, optimized allocation strategies (pretenuring), map transition management, and the ability to release unused memory pages.** It uses a combination of C++ test infrastructure and embedded JavaScript code to simulate real-world scenarios and ensure the robustness and efficiency of V8's memory management.

### 提示词
```
这是目录为v8/test/cctest/heap/test-heap.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/heap/test-heap.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
te()->GetCurrentContext();

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
```