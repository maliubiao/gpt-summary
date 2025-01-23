Response:
The user wants a summary of the functionality of the C++ code in `v8/test/cctest/heap/test-heap.cc`. They also have specific questions about the file type, relation to JavaScript, code logic, common programming errors, and want examples where appropriate. The provided code snippet is the 6th part of a 9-part file.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Purpose:** The file is located within the `v8/test/cctest/heap/` directory, suggesting it contains C++ tests related to V8's heap management. The `test-heap.cc` filename further confirms this.

2. **Analyze the Code Snippet:**  Scan through the provided C++ code. Look for keywords like `TEST`, `CHECK_EQ`, `CompileRun`, `InvokeMajorGC`, and specific V8 internal types like `AllocationSite`, `FeedbackVector`, `Code`, `Map`, etc.

3. **Categorize Functionality:** Group the tests based on the V8 heap features they seem to be testing. From the snippet, the major themes appear to be:
    * **Allocation Sites:**  Creation, optimization, and how garbage collection affects them.
    * **Optimized Code:** How garbage collection interacts with optimized code, especially regarding embedded objects and cells.
    * **Weak References:** Testing weak references within optimized code and inline caches (ICs).
    * **Inline Caches (ICs):**  Testing the state of ICs (monomorphic, polymorphic) after garbage collection.
    * **Garbage Collection Triggers and Scenarios:**  Testing specific GC behaviors under various conditions (e.g., full space, OOM).
    * **Regressions:**  Addressing specific bug fixes related to heap management (e.g., `Regress538257`, `Regress357137`).

4. **Address Specific Questions:**

    * **File Type:**  The filename ends with `.cc`, indicating it's a C++ source file, not a Torque file.
    * **Relationship to JavaScript:**  The tests use `CompileRun`, which executes JavaScript code within the V8 environment. The tests are designed to observe how JavaScript execution affects the underlying C++ heap management.
    * **JavaScript Examples:** For each category, think of a simple JavaScript scenario that would trigger the V8 heap behavior being tested. For instance, creating arrays and objects triggers allocation site creation. Optimizing functions involves V8's internal optimization process. Accessing object properties triggers ICs.
    * **Code Logic/Assumptions:** For snippets with conditional checks or specific sequences, identify the assumptions and expected outcomes. For example, tests involving garbage collection often assume that objects without strong references will be collected.
    * **Common Programming Errors:**  Relate the tests to potential user-level programming mistakes. While the tests are internal, some scenarios (like relying on objects in optimized code to stay alive indefinitely without proper referencing) have parallels in user code.
    * **Part 6 of 9:**  Acknowledge the context and indicate that this is a portion of a larger test suite.

5. **Synthesize the Summary:** Combine the categorized functionalities and the answers to the specific questions into a concise summary. Emphasize that this section focuses on testing the interactions between JavaScript execution and V8's heap management, especially concerning allocation sites, optimized code, weak references, and garbage collection triggers.

6. **Refine and Organize:**  Structure the answer logically with clear headings for each aspect. Provide concrete JavaScript examples where applicable. Ensure the language is clear and avoids overly technical jargon where possible.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus only on the individual tests.
* **Correction:**  Group similar tests to identify broader themes and functionalities being validated.
* **Initial thought:** Provide very technical explanations of V8 internals.
* **Correction:**  Simplify explanations and relate them to observable JavaScript behavior where possible to make the answer more understandable.
* **Initial thought:**  Miss the connection between `CompileRun` and JavaScript.
* **Correction:** Recognize `CompileRun` as the mechanism for executing JavaScript within the C++ test environment and highlight this relationship.
This section of `v8/test/cctest/heap/test-heap.cc` primarily focuses on **testing various aspects of V8's heap management, specifically related to allocation sites, optimized code, and the behavior of weak references during garbage collection.**

Here's a breakdown of its functionalities:

**Core Functionalities Tested:**

* **Allocation Site Creation and Management:**
    * Verifies that allocation sites (which track where objects are allocated) are created correctly for different JavaScript constructs like array and object literals.
    * Tests that allocation sites are created lazily for object literals.
    * Checks the number of full (fat) and slim allocation sites created.
    * Examines how garbage collection affects allocation sites and the dependent code associated with them.

* **Interaction of Optimized Code and Garbage Collection:**
    * Asserts that cells (memory locations holding values) embedded in optimized code are treated as weak references. This means that if the only reference to an object is from an optimized function's cell, the garbage collector can reclaim that object, and the optimized code will be deoptimized.
    * Similarly, verifies that objects embedded in optimized code are also treated as weak references.
    * Tests this behavior for code that is eagerly deoptimized (deoptimized explicitly).
    * Checks that new space (young generation) objects referenced by optimized code can still be collected during a major GC.

* **Weak References in Various Heap Structures:**
    * Tests the behavior of weak references in the context of feedback vectors (used for inline caching). Specifically, it checks if a weak reference to a constructor function within a feedback vector is cleared after the constructor becomes unreachable and a garbage collection occurs.
    * Examines the weakness of maps stored in inline caches (ICs) for various operations like property loads, keyed loads, property stores, keyed stores, and comparisons with `null`. The tests ensure that if the only reference to a prototype map is held by an IC, that map can be garbage collected.

* **Persistence of Inline Cache (IC) States after GC:**
    * Checks that the state of an IC (Monomorphic or Polymorphic) persists correctly after a garbage collection cycle.

* **Specific Regression Tests:**
    * Includes tests for specific bug fixes (regressions), such as `Regress538257`, `Regress357137`, `Regress507979`, and `Regress388880`. These tests aim to prevent those specific issues from reappearing.

* **Memory Pressure and OOM Handling:**
    * Tests scenarios where memory allocation is limited to trigger Out-of-Memory (OOM) errors and verify the expected behavior (e.g., in CEntry stubs).

* **Interrupt Handling and Stack Overflow Simulation:**
    * Includes a test that simulates a stack overflow using interrupts to verify proper handling.

**If `v8/test/cctest/heap/test-heap.cc` ended with `.tq`, it would be a v8 Torque source code.** Torque is V8's internal language for writing low-level built-in functions. Since the file ends with `.cc`, it's a standard C++ source file.

**Relationship to JavaScript with Examples:**

Yes, this code has a direct relationship to JavaScript. The C++ tests manipulate V8's internal heap structures in response to JavaScript code execution. The `CompileRun(source)` function executes the provided JavaScript code within the V8 environment.

Here are some JavaScript examples illustrating the concepts being tested:

* **Allocation Site Creation (Array Literals):**
   ```javascript
   function createArray() {
     return []; // Creates an empty array, leading to allocation site creation.
   }
   %EnsureFeedbackVectorForFunction(createArray);
   createArray();
   ```

* **Allocation Site Creation (Object Literals):**
   ```javascript
   function createObject() {
     return {}; // Creates an empty object, initially no allocation site.
   }
   %EnsureFeedbackVectorForFunction(createObject);
   createObject();
   ```

* **Optimized Code and Weak References:**
   ```javascript
   function outer() {
     let data = { value: 10 }; // 'data' might be embedded in optimized 'inner'
     function inner() {
       return data.value;
     }
     %PrepareFunctionForOptimization(inner);
     inner();
     inner();
     inner();
     %OptimizeFunctionOnNextCall(inner);
     inner();
     return inner;
   }
   let optimizedInner = outer();
   // If 'data' is only referenced weakly by optimizedInner, GC can collect it.
   ```

* **Weak References in Inline Caches (LoadIC):**
   ```javascript
   function loadProperty(obj) {
     return obj.name;
   }
   %EnsureFeedbackVectorForFunction(loadProperty);
   let proto = { name: 'test' };
   let obj = Object.create(proto);
   loadProperty(obj); // This call might create an IC referencing 'proto'
   loadProperty(obj);
   loadProperty(obj);
   // If 'proto' becomes unreachable otherwise, the weak reference in the IC should allow it to be garbage collected.
   ```

**Code Logic Inference with Assumptions:**

**Example 1: `TEST(CellsInOptimizedCodeAreWeak)`**

* **Assumption:**  If a function `bar` is optimized and relies on a cell (e.g., for a closure variable), and the only reference to the object in that cell is from the optimized code, then a major GC should be able to reclaim that object.
* **Input:** The JavaScript code defines functions `bar` and `foo`, optimizes `bar`, and `bar` calls `foo`. The `foo` function uses `with`, which can lead to cells being embedded in the optimized code for `bar`.
* **Output:** After several major GCs, the optimized code for `bar` (`code`) should be marked for deoptimization (`code->marked_for_deoptimization()`) and its embedded objects cleared (`code->embedded_objects_cleared()`). This confirms that the cell holding the reference to `foo` was considered weak, allowing `foo` to be potentially collected.

**Example 2: `TEST(AllocationSiteCreation)` (Array Literals)**

* **Assumption:** Creating an array literal in JavaScript will lead to the creation of an allocation site to track future allocations of similar arrays.
* **Input:** JavaScript code with functions that return array literals (e.g., `return [];`, `return [1, 2];`, `return [[1], [2]];`).
* **Output:** The `CheckNumberOfAllocations` function verifies that the expected number of full and slim allocation sites are created after executing the JavaScript code. For example, `return [[1], [2]];` is expected to create one full allocation site for the outer array and two slim allocation sites for the inner arrays.

**User Common Programming Errors (Related Concepts):**

While these are internal tests, they touch upon concepts related to common programming errors:

* **Memory Leaks due to Strong References:** If a user accidentally maintains strong references to objects they no longer need, the garbage collector cannot reclaim them, leading to memory leaks. The tests for weak references highlight how V8 handles situations where references should *not* prevent garbage collection.
* **Unexpected Deoptimizations:**  Relying on objects being present in optimized code without ensuring they have other strong references can lead to unexpected deoptimizations, impacting performance. The tests in this section verify that V8's behavior in these scenarios is correct.

**Summary of Functionality (Part 6 of 9):**

This part of `v8/test/cctest/heap/test-heap.cc` rigorously tests the core mechanisms of V8's heap management, particularly focusing on how allocation sites are created and managed, how garbage collection interacts with optimized code by treating embedded objects and cells as weak references, and how weak references are used within inline caches to allow for efficient memory reclamation. It also includes regression tests for specific bug fixes and explores scenarios involving memory pressure and interrupt handling. The overarching goal is to ensure the stability, correctness, and efficiency of V8's memory management.

### 提示词
```
这是目录为v8/test/cctest/heap/test-heap.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/heap/test-heap.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
psSlotOffset).ToSmi();
    CHECK_EQ(static_cast<DependentCode::DependencyGroups>(groups.value()),
             DependentCode::kAllocationSiteTransitionChangedGroup |
                 DependentCode::kAllocationSiteTenuringChangedGroup);
  }

  // Now make sure that a gc should get rid of the function, even though we
  // still have the allocation site alive.
  for (int i = 0; i < 4; i++) {
    // We need to invoke GC without stack, otherwise some objects may not be
    // reclaimed because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMajorGC(heap);
  }

  // The site still exists because of our global handle, but the code is no
  // longer referred to by dependent_code().
  CHECK(site->dependent_code()->Get(0).IsCleared());
}

void CheckNumberOfAllocations(Heap* heap, const char* source,
                              int expected_full_alloc,
                              int expected_slim_alloc) {
  int prev_fat_alloc_count = AllocationSitesCount(heap);
  int prev_slim_alloc_count = SlimAllocationSiteCount(heap);

  CompileRun(source);

  int fat_alloc_sites = AllocationSitesCount(heap) - prev_fat_alloc_count;
  int slim_alloc_sites = SlimAllocationSiteCount(heap) - prev_slim_alloc_count;

  CHECK_EQ(expected_full_alloc, fat_alloc_sites);
  CHECK_EQ(expected_slim_alloc, slim_alloc_sites);
}

TEST(AllocationSiteCreation) {
  v8_flags.always_turbofan = false;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  HandleScope scope(isolate);
  i::v8_flags.allow_natives_syntax = true;

  // Array literals.
  CheckNumberOfAllocations(heap,
                           "function f1() {"
                           "  return []; "
                           "};"
                           "%EnsureFeedbackVectorForFunction(f1); f1();",
                           1, 0);
  CheckNumberOfAllocations(heap,
                           "function f2() {"
                           "  return [1, 2];"
                           "};"
                           "%EnsureFeedbackVectorForFunction(f2); f2();",
                           1, 0);
  CheckNumberOfAllocations(heap,
                           "function f3() {"
                           "  return [[1], [2]];"
                           "};"
                           "%EnsureFeedbackVectorForFunction(f3); f3();",
                           1, 2);
  CheckNumberOfAllocations(heap,
                           "function f4() { "
                           "return [0, [1, 1.1, 1.2, "
                           "], 1.5, [2.1, 2.2], 3];"
                           "};"
                           "%EnsureFeedbackVectorForFunction(f4); f4();",
                           1, 2);

  // Object literals have lazy AllocationSites
  CheckNumberOfAllocations(heap,
                           "function f5() {"
                           " return {};"
                           "};"
                           "%EnsureFeedbackVectorForFunction(f5); f5();",
                           0, 0);

  // No AllocationSites are created for the empty object literal.
  for (int i = 0; i < 5; i++) {
    CheckNumberOfAllocations(heap, "f5(); ", 0, 0);
  }

  CheckNumberOfAllocations(heap,
                           "function f6() {"
                           "  return {a:1};"
                           "};"
                           "%EnsureFeedbackVectorForFunction(f6); f6();",
                           0, 0);

  CheckNumberOfAllocations(heap, "f6(); ", 1, 0);

  CheckNumberOfAllocations(heap,
                           "function f7() {"
                           "  return {a:1, b:2};"
                           "};"
                           "%EnsureFeedbackVectorForFunction(f7); f7(); ",
                           0, 0);
  CheckNumberOfAllocations(heap, "f7(); ", 1, 0);

  // No Allocation sites are created for object subliterals
  CheckNumberOfAllocations(heap,
                           "function f8() {"
                           "return {a:{}, b:{ a:2, c:{ d:{f:{}}} } }; "
                           "};"
                           "%EnsureFeedbackVectorForFunction(f8); f8();",
                           0, 0);
  CheckNumberOfAllocations(heap, "f8(); ", 1, 0);

  // We currently eagerly create allocation sites if there are sub-arrays.
  // Allocation sites are created only for array subliterals
  CheckNumberOfAllocations(heap,
                           "function f9() {"
                           "return {a:[1, 2, 3], b:{ a:2, c:{ d:{f:[]} } }}; "
                           "};"
                           "%EnsureFeedbackVectorForFunction(f9); f9(); ",
                           1, 2);

  // No new AllocationSites created on the second invocation.
  CheckNumberOfAllocations(heap, "f9(); ", 0, 0);
}

TEST(CellsInOptimizedCodeAreWeak) {
  if (v8_flags.always_turbofan) return;
  v8_flags.allow_natives_syntax = true;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  v8::internal::Heap* heap = CcTest::heap();

  if (!isolate->use_optimizer()) return;
  HandleScope outer_scope(heap->isolate());
  IndirectHandle<Code> code;
  {
    LocalContext context;
    HandleScope scope(heap->isolate());

    CompileRun(
        "bar = (function() {"
        "  function bar() {"
        "    return foo(1);"
        "  };"
        "  %PrepareFunctionForOptimization(bar);"
        "  var foo = function(x) { with (x) { return 1 + x; } };"
        "  %NeverOptimizeFunction(foo);"
        "  bar(foo);"
        "  bar(foo);"
        "  bar(foo);"
        "  %OptimizeFunctionOnNextCall(bar);"
        "  bar(foo);"
        "  return bar;})();");

    DirectHandle<JSFunction> bar = Cast<JSFunction>(v8::Utils::OpenDirectHandle(
        *v8::Local<v8::Function>::Cast(CcTest::global()
                                           ->Get(context.local(), v8_str("bar"))
                                           .ToLocalChecked())));
    code = handle(bar->code(isolate), isolate);
    code = scope.CloseAndEscape(code);
  }

  // Now make sure that a gc should get rid of the function
  for (int i = 0; i < 4; i++) {
    // We need to invoke GC without stack, otherwise some objects may not be
    // reclaimed because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMajorGC(heap);
  }

  CHECK(code->marked_for_deoptimization());
  CHECK(code->embedded_objects_cleared());
}

TEST(ObjectsInOptimizedCodeAreWeak) {
  if (v8_flags.always_turbofan) return;
  v8_flags.allow_natives_syntax = true;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  v8::internal::Heap* heap = CcTest::heap();

  if (!isolate->use_optimizer()) return;
  HandleScope outer_scope(heap->isolate());
  IndirectHandle<Code> code;
  {
    LocalContext context;
    HandleScope scope(heap->isolate());

    CompileRun(
        "function bar() {"
        "  return foo(1);"
        "};"
        "%PrepareFunctionForOptimization(bar);"
        "function foo(x) { with (x) { return 1 + x; } };"
        "%NeverOptimizeFunction(foo);"
        "bar();"
        "bar();"
        "bar();"
        "%OptimizeFunctionOnNextCall(bar);"
        "bar();");

    DirectHandle<JSFunction> bar = Cast<JSFunction>(v8::Utils::OpenDirectHandle(
        *v8::Local<v8::Function>::Cast(CcTest::global()
                                           ->Get(context.local(), v8_str("bar"))
                                           .ToLocalChecked())));
    code = handle(bar->code(isolate), isolate);
    code = scope.CloseAndEscape(code);
  }

  // Now make sure that a gc should get rid of the function
  for (int i = 0; i < 4; i++) {
    // We need to invoke GC without stack, otherwise some objects may not be
    // reclaimed because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMajorGC(heap);
  }

  CHECK(code->marked_for_deoptimization());
  CHECK(code->embedded_objects_cleared());
}

TEST(NewSpaceObjectsInOptimizedCode) {
  if (v8_flags.always_turbofan || v8_flags.single_generation) return;
  v8_flags.allow_natives_syntax = true;
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  v8::internal::Heap* heap = CcTest::heap();

  if (!isolate->use_optimizer()) return;
  HandleScope outer_scope(isolate);
  IndirectHandle<Code> code;
  {
    LocalContext context;
    HandleScope scope(isolate);

    CompileRun(
        "var foo;"
        "var bar;"
        "(function() {"
        "  function foo_func(x) { with (x) { return 1 + x; } };"
        "  %NeverOptimizeFunction(foo_func);"
        "  function bar_func() {"
        "    return foo(1);"
        "  };"
        "  %PrepareFunctionForOptimization(bar_func);"
        "  bar = bar_func;"
        "  foo = foo_func;"
        "  bar_func();"
        "  bar_func();"
        "  bar_func();"
        "  %OptimizeFunctionOnNextCall(bar_func);"
        "  bar_func();"
        "})();");

    DirectHandle<JSFunction> bar = Cast<JSFunction>(v8::Utils::OpenDirectHandle(
        *v8::Local<v8::Function>::Cast(CcTest::global()
                                           ->Get(context.local(), v8_str("bar"))
                                           .ToLocalChecked())));

    DirectHandle<JSFunction> foo = Cast<JSFunction>(v8::Utils::OpenDirectHandle(
        *v8::Local<v8::Function>::Cast(CcTest::global()
                                           ->Get(context.local(), v8_str("foo"))
                                           .ToLocalChecked())));

    CHECK(HeapLayout::InYoungGeneration(*foo));
    heap::InvokeMajorGC(heap);
    CHECK(!HeapLayout::InYoungGeneration(*foo));
#ifdef VERIFY_HEAP
    HeapVerifier::VerifyHeap(CcTest::heap());
#endif
    CHECK(!bar->code(isolate)->marked_for_deoptimization());
    code = handle(bar->code(isolate), isolate);
    code = scope.CloseAndEscape(code);
  }

  // Now make sure that a gc should get rid of the function
  for (int i = 0; i < 4; i++) {
    // We need to invoke GC without stack, otherwise some objects may not be
    // reclaimed because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMajorGC(heap);
  }

  CHECK(code->marked_for_deoptimization());
  CHECK(code->embedded_objects_cleared());
}

TEST(ObjectsInEagerlyDeoptimizedCodeAreWeak) {
  if (v8_flags.always_turbofan) return;
  v8_flags.allow_natives_syntax = true;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  v8::internal::Heap* heap = CcTest::heap();

  if (!isolate->use_optimizer()) return;
  HandleScope outer_scope(heap->isolate());
  IndirectHandle<Code> code;
  {
    LocalContext context;
    HandleScope scope(heap->isolate());

    CompileRun(
        "function bar() {"
        "  return foo(1);"
        "};"
        "function foo(x) { with (x) { return 1 + x; } };"
        "%NeverOptimizeFunction(foo);"
        "%PrepareFunctionForOptimization(bar);"
        "bar();"
        "bar();"
        "bar();"
        "%OptimizeFunctionOnNextCall(bar);"
        "bar();"
        "%DeoptimizeFunction(bar);");

    DirectHandle<JSFunction> bar = Cast<JSFunction>(v8::Utils::OpenDirectHandle(
        *v8::Local<v8::Function>::Cast(CcTest::global()
                                           ->Get(context.local(), v8_str("bar"))
                                           .ToLocalChecked())));
    code = handle(bar->code(isolate), isolate);
    code = scope.CloseAndEscape(code);
  }

  CHECK(code->marked_for_deoptimization());

  // Now make sure that a gc should get rid of the function
  for (int i = 0; i < 4; i++) {
    // We need to invoke GC without stack, otherwise some objects may not be
    // reclaimed because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMajorGC(heap);
  }

  CHECK(code->marked_for_deoptimization());
  CHECK(code->embedded_objects_cleared());
}

static Handle<InstructionStream> DummyOptimizedCode(Isolate* isolate) {
  uint8_t buffer[i::Assembler::kDefaultBufferSize];
  MacroAssembler masm(isolate, v8::internal::CodeObjectRequired::kYes,
                      ExternalAssemblerBuffer(buffer, sizeof(buffer)));
  CodeDesc desc;
#if V8_TARGET_ARCH_ARM64
  UseScratchRegisterScope temps(&masm);
  Register tmp = temps.AcquireX();
  masm.Mov(tmp, Operand(isolate->factory()->undefined_value()));
  masm.Push(tmp, tmp);
#else
  masm.Push(isolate->factory()->undefined_value());
  masm.Push(isolate->factory()->undefined_value());
#endif
  masm.Drop(2);
  masm.GetCode(isolate, &desc);
  Handle<InstructionStream> code(
      Factory::CodeBuilder(isolate, desc, CodeKind::TURBOFAN_JS)
          .set_self_reference(masm.CodeObject())
          .set_empty_source_position_table()
          .set_deoptimization_data(DeoptimizationData::Empty(isolate))
          .Build()
          ->instruction_stream(),
      isolate);
  CHECK(IsInstructionStream(*code));
  return code;
}

static bool weak_ic_cleared = false;

static void ClearWeakIC(
    const v8::WeakCallbackInfo<v8::Persistent<v8::Object>>& data) {
  printf("clear weak is called\n");
  weak_ic_cleared = true;
  data.GetParameter()->Reset();
}

TEST(WeakFunctionInConstructor) {
  if (v8_flags.always_turbofan) return;
  v8_flags.stress_compaction = false;
  v8_flags.stress_incremental_marking = false;
  v8_flags.allow_natives_syntax = true;
  CcTest::InitializeVM();
  v8::Isolate* isolate = CcTest::isolate();
  v8::internal::Heap* heap = CcTest::heap();
  LocalContext env;
  v8::HandleScope scope(isolate);

  CompileRun(
      "function createObj(obj) {"
      "  return new obj();"
      "}");
  i::IndirectHandle<JSFunction> createObj = Cast<JSFunction>(
      v8::Utils::OpenIndirectHandle(*v8::Local<v8::Function>::Cast(
          CcTest::global()
              ->Get(env.local(), v8_str("createObj"))
              .ToLocalChecked())));

  v8::Persistent<v8::Object> garbage;
  {
    v8::HandleScope new_scope(isolate);
    const char* source =
        " (function() {"
        "   function hat() { this.x = 5; }"
        "   %EnsureFeedbackVectorForFunction(hat);"
        "   %EnsureFeedbackVectorForFunction(createObj);"
        "   createObj(hat);"
        "   createObj(hat);"
        "   return hat;"
        " })();";
    garbage.Reset(isolate, CompileRun(env.local(), source)
                               .ToLocalChecked()
                               ->ToObject(env.local())
                               .ToLocalChecked());
  }
  weak_ic_cleared = false;
  garbage.SetWeak(&garbage, &ClearWeakIC, v8::WeakCallbackType::kParameter);
  {
    // In this test, we need to invoke GC without stack, otherwise some objects
    // may not be reclaimed because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMajorGC(heap);
  }
  CHECK(weak_ic_cleared);

  // We've determined the constructor in createObj has had it's weak cell
  // cleared. Now, verify that one additional call with a new function
  // allows monomorphicity.
  IndirectHandle<FeedbackVector> feedback_vector(createObj->feedback_vector(),
                                                 CcTest::i_isolate());
  for (int i = 0; i < 20; i++) {
    Tagged<MaybeObject> slot_value = feedback_vector->Get(FeedbackSlot(0));
    CHECK(slot_value.IsWeakOrCleared());
    if (slot_value.IsCleared()) break;
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMajorGC(heap);
  }

  Tagged<MaybeObject> slot_value = feedback_vector->Get(FeedbackSlot(0));
  CHECK(slot_value.IsCleared());
  CompileRun(
      "function coat() { this.x = 6; }"
      "createObj(coat);");
  slot_value = feedback_vector->Get(FeedbackSlot(0));
  CHECK(slot_value.IsWeak());
}

// Checks that the value returned by execution of the source is weak.
void CheckWeakness(const char* source) {
  v8_flags.stress_compaction = false;
  v8_flags.stress_incremental_marking = false;
  v8_flags.allow_natives_syntax = true;
  CcTest::InitializeVM();
  v8::Isolate* isolate = CcTest::isolate();
  Heap* heap = CcTest::heap();
  LocalContext env;
  v8::HandleScope scope(isolate);
  v8::Persistent<v8::Object> garbage;
  {
    v8::HandleScope new_scope(isolate);
    garbage.Reset(isolate, CompileRun(env.local(), source)
                               .ToLocalChecked()
                               ->ToObject(env.local())
                               .ToLocalChecked());
  }
  weak_ic_cleared = false;
  garbage.SetWeak(&garbage, &ClearWeakIC, v8::WeakCallbackType::kParameter);
  {
    // We need to invoke GC without stack, otherwise some objects may not be
    // reclaimed because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMajorGC(heap);
  }
  CHECK(weak_ic_cleared);
}

// Each of the following "weak IC" tests creates an IC that embeds a map with
// the prototype pointing to _proto_ and checks that the _proto_ dies on GC.
TEST(WeakMapInMonomorphicLoadIC) {
  CheckWeakness(
      "function loadIC(obj) {"
      "  return obj.name;"
      "}"
      "%EnsureFeedbackVectorForFunction(loadIC);"
      " (function() {"
      "   var proto = {'name' : 'weak'};"
      "   var obj = Object.create(proto);"
      "   loadIC(obj);"
      "   loadIC(obj);"
      "   loadIC(obj);"
      "   return proto;"
      " })();");
}

TEST(WeakMapInPolymorphicLoadIC) {
  CheckWeakness(
      "function loadIC(obj) {"
      "  return obj.name;"
      "}"
      "%EnsureFeedbackVectorForFunction(loadIC);"
      " (function() {"
      "   var proto = {'name' : 'weak'};"
      "   var obj = Object.create(proto);"
      "   loadIC(obj);"
      "   loadIC(obj);"
      "   loadIC(obj);"
      "   var poly = Object.create(proto);"
      "   poly.x = true;"
      "   loadIC(poly);"
      "   return proto;"
      " })();");
}

TEST(WeakMapInMonomorphicKeyedLoadIC) {
  CheckWeakness(
      "function keyedLoadIC(obj, field) {"
      "  return obj[field];"
      "}"
      "%EnsureFeedbackVectorForFunction(keyedLoadIC);"
      " (function() {"
      "   var proto = {'name' : 'weak'};"
      "   var obj = Object.create(proto);"
      "   keyedLoadIC(obj, 'name');"
      "   keyedLoadIC(obj, 'name');"
      "   keyedLoadIC(obj, 'name');"
      "   return proto;"
      " })();");
}

TEST(WeakMapInPolymorphicKeyedLoadIC) {
  CheckWeakness(
      "function keyedLoadIC(obj, field) {"
      "  return obj[field];"
      "}"
      "%EnsureFeedbackVectorForFunction(keyedLoadIC);"
      " (function() {"
      "   var proto = {'name' : 'weak'};"
      "   var obj = Object.create(proto);"
      "   keyedLoadIC(obj, 'name');"
      "   keyedLoadIC(obj, 'name');"
      "   keyedLoadIC(obj, 'name');"
      "   var poly = Object.create(proto);"
      "   poly.x = true;"
      "   keyedLoadIC(poly, 'name');"
      "   return proto;"
      " })();");
}

TEST(WeakMapInMonomorphicStoreIC) {
  CheckWeakness(
      "function storeIC(obj, value) {"
      "  obj.name = value;"
      "}"
      "%EnsureFeedbackVectorForFunction(storeIC);"
      " (function() {"
      "   var proto = {'name' : 'weak'};"
      "   var obj = Object.create(proto);"
      "   storeIC(obj, 'x');"
      "   storeIC(obj, 'x');"
      "   storeIC(obj, 'x');"
      "   return proto;"
      " })();");
}

TEST(WeakMapInPolymorphicStoreIC) {
  CheckWeakness(
      "function storeIC(obj, value) {"
      "  obj.name = value;"
      "}"
      "%EnsureFeedbackVectorForFunction(storeIC);"
      " (function() {"
      "   var proto = {'name' : 'weak'};"
      "   var obj = Object.create(proto);"
      "   storeIC(obj, 'x');"
      "   storeIC(obj, 'x');"
      "   storeIC(obj, 'x');"
      "   var poly = Object.create(proto);"
      "   poly.x = true;"
      "   storeIC(poly, 'x');"
      "   return proto;"
      " })();");
}

TEST(WeakMapInMonomorphicKeyedStoreIC) {
  CheckWeakness(
      "function keyedStoreIC(obj, field, value) {"
      "  obj[field] = value;"
      "}"
      "%EnsureFeedbackVectorForFunction(keyedStoreIC);"
      " (function() {"
      "   var proto = {'name' : 'weak'};"
      "   var obj = Object.create(proto);"
      "   keyedStoreIC(obj, 'x');"
      "   keyedStoreIC(obj, 'x');"
      "   keyedStoreIC(obj, 'x');"
      "   return proto;"
      " })();");
}

TEST(WeakMapInPolymorphicKeyedStoreIC) {
  CheckWeakness(
      "function keyedStoreIC(obj, field, value) {"
      "  obj[field] = value;"
      "}"
      "%EnsureFeedbackVectorForFunction(keyedStoreIC);"
      " (function() {"
      "   var proto = {'name' : 'weak'};"
      "   var obj = Object.create(proto);"
      "   keyedStoreIC(obj, 'x');"
      "   keyedStoreIC(obj, 'x');"
      "   keyedStoreIC(obj, 'x');"
      "   var poly = Object.create(proto);"
      "   poly.x = true;"
      "   keyedStoreIC(poly, 'x');"
      "   return proto;"
      " })();");
}

TEST(WeakMapInMonomorphicCompareNilIC) {
  v8_flags.allow_natives_syntax = true;
  CheckWeakness(
      "function compareNilIC(obj) {"
      "  return obj == null;"
      "}"
      "%EnsureFeedbackVectorForFunction(compareNilIC);"
      " (function() {"
      "   var proto = {'name' : 'weak'};"
      "   var obj = Object.create(proto);"
      "   compareNilIC(obj);"
      "   compareNilIC(obj);"
      "   compareNilIC(obj);"
      "   return proto;"
      " })();");
}

Handle<JSFunction> GetFunctionByName(Isolate* isolate, const char* name) {
  Handle<String> str = isolate->factory()->InternalizeUtf8String(name);
  Handle<Object> obj =
      Object::GetProperty(isolate, isolate->global_object(), str)
          .ToHandleChecked();
  return Cast<JSFunction>(obj);
}

void CheckIC(DirectHandle<JSFunction> function, int slot_index,
             InlineCacheState state) {
  Tagged<FeedbackVector> vector = function->feedback_vector();
  FeedbackSlot slot(slot_index);
  FeedbackNexus nexus(CcTest::i_isolate(), vector, slot);
  CHECK_EQ(nexus.ic_state(), state);
}

TEST(MonomorphicStaysMonomorphicAfterGC) {
  if (!v8_flags.use_ic) return;
  if (v8_flags.always_turbofan) return;
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  v8::HandleScope scope(CcTest::isolate());
  v8_flags.allow_natives_syntax = true;
  CompileRun(
      "function loadIC(obj) {"
      "  return obj.name;"
      "}"
      "%EnsureFeedbackVectorForFunction(loadIC);"
      "function testIC() {"
      "  var proto = {'name' : 'weak'};"
      "  var obj = Object.create(proto);"
      "  loadIC(obj);"
      "  loadIC(obj);"
      "  loadIC(obj);"
      "  return proto;"
      "};");
  DirectHandle<JSFunction> loadIC = GetFunctionByName(isolate, "loadIC");
  {
    v8::HandleScope new_scope(CcTest::isolate());
    CompileRun("(testIC())");
  }
  heap::InvokeMajorGC(CcTest::heap());
  CheckIC(loadIC, 0, InlineCacheState::MONOMORPHIC);
  {
    v8::HandleScope new_scope(CcTest::isolate());
    CompileRun("(testIC())");
  }
  CheckIC(loadIC, 0, InlineCacheState::MONOMORPHIC);
}

TEST(PolymorphicStaysPolymorphicAfterGC) {
  if (!v8_flags.use_ic) return;
  if (v8_flags.always_turbofan) return;
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  v8::HandleScope scope(CcTest::isolate());
  v8_flags.allow_natives_syntax = true;
  CompileRun(
      "function loadIC(obj) {"
      "  return obj.name;"
      "}"
      "%EnsureFeedbackVectorForFunction(loadIC);"
      "function testIC() {"
      "  var proto = {'name' : 'weak'};"
      "  var obj = Object.create(proto);"
      "  loadIC(obj);"
      "  loadIC(obj);"
      "  loadIC(obj);"
      "  var poly = Object.create(proto);"
      "  poly.x = true;"
      "  loadIC(poly);"
      "  return proto;"
      "};");
  DirectHandle<JSFunction> loadIC = GetFunctionByName(isolate, "loadIC");
  {
    v8::HandleScope new_scope(CcTest::isolate());
    CompileRun("(testIC())");
  }
  heap::InvokeMajorGC(CcTest::heap());
  CheckIC(loadIC, 0, InlineCacheState::POLYMORPHIC);
  {
    v8::HandleScope new_scope(CcTest::isolate());
    CompileRun("(testIC())");
  }
  CheckIC(loadIC, 0, InlineCacheState::POLYMORPHIC);
}

#ifdef DEBUG
TEST(AddInstructionChangesNewSpacePromotion) {
  v8_flags.allow_natives_syntax = true;
  v8_flags.expose_gc = true;
  v8_flags.stress_compaction = true;
  HeapAllocator::SetAllocationGcInterval(1000);
  CcTest::InitializeVM();
  if (!v8_flags.allocation_site_pretenuring) return;
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  LocalContext env;
  CompileRun(
      "function add(a, b) {"
      "  return a + b;"
      "}"
      "add(1, 2);"
      "add(\"a\", \"b\");"
      "var oldSpaceObject;"
      "gc();"
      "function crash(x) {"
      "  var object = {a: null, b: null};"
      "  var result = add(1.5, x | 0);"
      "  object.a = result;"
      "  oldSpaceObject = object;"
      "  return object;"
      "}"
      "%PrepareFunctionForOptimization(crash);"
      "crash(1);"
      "crash(1);"
      "%OptimizeFunctionOnNextCall(crash);"
      "crash(1);");

  v8::Local<v8::Object> global = CcTest::global();
  v8::Local<v8::Function> g = v8::Local<v8::Function>::Cast(
      global->Get(env.local(), v8_str("crash")).ToLocalChecked());
  v8::Local<v8::Value> info1[] = {v8_num(1)};
  heap->DisableInlineAllocation();
  heap->set_allocation_timeout(1);
  g->Call(env.local(), global, 1, info1).ToLocalChecked();
  heap::InvokeMajorGC(heap);
}

void OnFatalErrorExpectOOM(const char* location, const char* message) {
  // Exit with 0 if the location matches our expectation.
  exit(strcmp(location, "CALL_AND_RETRY_LAST"));
}

TEST(CEntryStubOOM) {
  v8_flags.allow_natives_syntax = true;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  CcTest::isolate()->SetFatalErrorHandler(OnFatalErrorExpectOOM);

  v8::Local<v8::Value> result = CompileRun(
      "%SetAllocationTimeout(1, 1);"
      "var a = [];"
      "a.__proto__ = [];"
      "a.unshift(1)");

  CHECK(result->IsNumber());
}

#endif  // DEBUG

static void InterruptCallback357137(v8::Isolate* isolate, void* data) { }

static void RequestInterrupt(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  CcTest::isolate()->RequestInterrupt(&InterruptCallback357137, nullptr);
}

HEAP_TEST(Regress538257) {
  ManualGCScope manual_gc_scope;
  heap::ManualEvacuationCandidatesSelectionScope
      manual_evacuation_candidate_selection_scope(manual_gc_scope);
  v8::Isolate::CreateParams create_params;
  // Set heap limits.
  create_params.constraints.set_max_young_generation_size_in_bytes(3 * MB);
#ifdef DEBUG
  create_params.constraints.set_max_old_generation_size_in_bytes(20 * MB);
#else
  create_params.constraints.set_max_old_generation_size_in_bytes(6 * MB);
#endif
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  isolate->Enter();
  {
    i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
    Heap* heap = i_isolate->heap();
    HandleScope handle_scope(i_isolate);
    PagedSpace* old_space = heap->old_space();
    const int kMaxObjects = 10000;
    const int kFixedArrayLen = 512;
    Handle<FixedArray> objects[kMaxObjects];
    for (int i = 0; (i < kMaxObjects) &&
                    heap->CanExpandOldGeneration(old_space->AreaSize());
         i++) {
      objects[i] = i_isolate->factory()->NewFixedArray(kFixedArrayLen,
                                                       AllocationType::kOld);
      heap::ForceEvacuationCandidate(PageMetadata::FromHeapObject(*objects[i]));
    }
    heap::SimulateFullSpace(old_space);
    heap::InvokeMajorGC(heap);
    // If we get this far, we've successfully aborted compaction. Any further
    // allocations might trigger OOM.
  }
  isolate->Exit();
  isolate->Dispose();
}

TEST(Regress357137) {
  CcTest::InitializeVM();
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope hscope(isolate);
  v8::Local<v8::ObjectTemplate> global = v8::ObjectTemplate::New(isolate);
  global->Set(isolate, "interrupt",
              v8::FunctionTemplate::New(isolate, RequestInterrupt));
  v8::Local<v8::Context> context = v8::Context::New(isolate, nullptr, global);
  CHECK(!context.IsEmpty());
  v8::Context::Scope cscope(context);

  v8::Local<v8::Value> result = CompileRun(
      "var locals = '';"
      "for (var i = 0; i < 512; i++) locals += 'var v' + i + '= 42;';"
      "eval('function f() {' + locals + 'return function() { return v0; }; }');"
      "interrupt();"  // This triggers a fake stack overflow in f.
      "f()()");
  CHECK_EQ(42.0, result->ToNumber(context).ToLocalChecked()->Value());
}

TEST(Regress507979) {
  const int kFixedArrayLen = 10;
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope handle_scope(isolate);

  DirectHandle<FixedArray> o1 =
      isolate->factory()->NewFixedArray(kFixedArrayLen);
  DirectHandle<FixedArray> o2 =
      isolate->factory()->NewFixedArray(kFixedArrayLen);
  CHECK(InCorrectGeneration(*o1));
  CHECK(InCorrectGeneration(*o2));

  HeapObjectIterator it(isolate->heap(),
                        i::HeapObjectIterator::kFilterUnreachable);

  // Replace parts of an object placed before a live object with a filler. This
  // way the filler object shares the mark bits with the following live object.
  o1->RightTrim(isolate, kFixedArrayLen - 1);

  for (Tagged<HeapObject> obj = it.Next(); !obj.is_null(); obj = it.Next()) {
    // Let's not optimize the loop away.
    CHECK_NE(obj.address(), kNullAddress);
  }
}

TEST(Regress388880) {
  if (!v8_flags.incremental_marking) return;
  v8_flags.stress_incremental_marking = false;
  v8_flags.expose_gc = true;
  v8_flags.stress_concurrent_allocation = false;  // For SimulateFullSpace.
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  Heap* heap = isolate->heap();

  Handle<Map> map1 = Map::Create(isolate, 1);
  Handle<String> name = factory->NewStringFromStaticChars("foo");
  name = factory->InternalizeString(name);
  DirectHandle<Map> map2 =
      Map::CopyWithField(isolate, map1, name, FieldType::Any(isolate), NONE,
                         PropertyConstness::kMutable, Representation::Tagged(),
                         OMIT_TRANSITION)
          .ToHandleChecked();

  size_t desired_offset = PageMetadata::kPageSize - map1->instance_size();

  // Allocate padding objects in old pointer space so, that object allocated
  // afterwards would end at the end of the page.
  heap::SimulateFullSpace(heap->old_space());
  size_t padding_size =
      desired_offset - MemoryChunkLayout::ObjectStartOffsetInDataPage();
  heap::CreatePadding(heap, static_cast<int>(padding_size),
                      AllocationType::kOld);

  DirectHandle<JSObject> o =
      factory->NewJSObjectFromMap(map1, AllocationType::kOld);
  o->set_raw_properties_or_hash(*factory->empty_fixed_array());

  // Ensure that the object allocated where we need it.
  PageMetadata* page = PageMetadata::FromHeapObject(*o);
  CHECK_EQ(desired_offset, page->Offset(o->address()));

  // Now we have an object right at the end of the page.

  // Enable incremental marking to trigger actions in Heap::AdjustLiveBytes()
  // that would cause crash.
  IncrementalMarking* marking = CcTest::heap()->incremental_marking();
  marking->Stop();
  CcTest::heap()->StartIncrementalMarking(i::GCFlag::kNoFlags,
                                          i::GarbageCollectionReason::kTesting);
  CHECK(marking->IsMarking());

  // Now everything is set up for crashing in JSObject::MigrateFastToFast()
  // when it calls heap->AdjustLiveBytes(...).
  JSObject::MigrateToMap(isolate, o, map2);
}

TEST(Regress3631) {
  if (!v8_flags.incremental_marking) return;
  v8_flags.expose_gc = true;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  IncrementalMarking* marking = CcTest::heap()->incremental_marking();
  v8::Local<v8::Value> result = CompileRun(
      "var weak_map = new WeakMap();"
      "var future_keys = [];"
      "for (var i = 0; i < 50; i++) {"
      "  var key = {'k' : i + 0.1};"
      "  weak_map.set(key, 1);"
      "  future_keys.push({'x' : i + 0.2});"
      "}"
      "weak_map");
  if (marking->IsStopped()) {
    CcTest::heap()->StartIncrementalMarking(
        i::GCFlag::kNoFlags, i::GarbageCollectionReason::kTesting);
  }
  // Incre
```