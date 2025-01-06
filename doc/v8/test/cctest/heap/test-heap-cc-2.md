Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/test/cctest/heap/test-heap.cc`.

Here's a breakdown of the thought process to generate the response:

1. **Identify the file's purpose:** The file is `test-heap.cc`, located in the `v8/test/cctest/heap/` directory. This strongly suggests it contains tests related to V8's heap management.

2. **Scan for test names and their logic:** The code is structured with `TEST(...)` and `HEAP_TEST(...)` macros, indicating individual test cases. Read through each test case to understand its goal. Look for keywords like `CompilationCache`, `WeakLists`, `RegExp`, `SizeOfObjects`, `Alignment`, `NativeContext`, and `WriteBarrier`.

3. **Group related tests:**  Notice that some tests have sequential numbering (e.g., `CompilationCacheRegeneration0` to `CompilationCacheRegeneration7`), suggesting they test variations of the same functionality.

4. **Abstract the test logic:** For each group or individual test, determine the core functionality being tested. For example, the `CompilationCacheRegeneration` tests are about how the compilation cache behaves across script executions and garbage collection.

5. **Check for JavaScript relationships:** Many tests involve compiling and running JavaScript code snippets using `CompileRun()`. Analyze these snippets to understand what JavaScript features are being tested in relation to heap behavior.

6. **Look for code logic and assumptions:** Some tests involve direct manipulation of V8's internal data structures and flags (e.g., `CountNativeContexts()`, setting `v8_flags`). Identify the assumptions and expected outcomes of these manipulations.

7. **Identify potential programming errors:** Certain tests, especially those dealing with memory management and external contexts, might implicitly highlight potential errors developers could make. For example, leaking native contexts.

8. **Address specific instructions:**
    * **`.tq` extension:**  Explicitly state that the file is C++ and not Torque.
    * **JavaScript examples:** Provide concise JavaScript examples illustrating the concepts being tested (e.g., function compilation, object creation).
    * **Input/output assumptions:**  For tests involving direct manipulation, create simple scenarios to illustrate the expected input and output.
    * **Common errors:** Give concrete examples of user errors related to the tested areas (e.g., not disposing of contexts).

9. **Consider the "Part 3 of 9" instruction:** Since this is part of a larger file, the summary should focus on the functionality present in this specific snippet and acknowledge that other parts likely cover different aspects of heap testing.

10. **Structure the summary:** Organize the findings logically, grouping related tests together. Use clear and concise language.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** "This file tests various aspects of the V8 heap."  **Refinement:** Be more specific about *which* aspects, like compilation caching, weak lists, object size calculation, alignment, and interactions with native contexts.
* **Initial thought (for JavaScript examples):**  Just show the code from the test. **Refinement:**  Simplify the JavaScript examples to highlight the relevant concept without the V8 testing overhead.
* **Initial thought (for errors):**  Vague statement like "memory leaks." **Refinement:** Pinpoint the specific scenario of leaking native contexts.

By following this process, the detailed and informative summary of the code's functionality can be constructed.
这是 `v8/test/cctest/heap/test-heap.cc` 源代码的第三部分，主要关注以下几个方面的功能测试：

**1. 编译缓存的再生 (Compilation Cache Regeneration):**

* **功能:** 测试在脚本执行后，当某些条件发生（例如，触发垃圾回收）时，编译后的函数信息（SharedFunctionInfo）是否能够正确地被保留或重新生成。
* **测试场景:**  通过 `CompilationCacheRegeneration` 函数，针对不同的 `flush_eager_sfi` (是否刷新急切编译的函数), `flush_root_sfi` (是否刷新根函数), 和 `retain_root_sfi` (是否保留根函数) 的组合进行测试。
* **代码逻辑推理 (假设输入与输出):**
    * **假设输入:** 一个包含两个函数的 JavaScript 脚本，一个立即执行（eager），一个延迟执行（lazy）。在首次运行后，模拟可能导致编译信息被刷新的情况。
    * **输出:** 验证在第二次运行时，`SharedFunctionInfo` 是否被正确地重用或重新编译。例如，延迟执行的函数在首次运行时不应该被编译，但在第二次运行时，如果编译缓存有效，则应该重用之前的 `SharedFunctionInfo`。
* **与 JavaScript 的关系:**  编译缓存直接影响 JavaScript 函数的执行效率。V8 会缓存编译后的代码，以便后续调用时可以更快地执行。
    * **JavaScript 示例:**
    ```javascript
    function eagerFunction() { return 1; } // 可能会立即编译
    function lazyFunction() { return 2; }  // 可能会延迟编译

    eagerFunction(); // 触发 eagerFunction 的编译

    // ... 模拟可能导致编译信息刷新的操作 ...

    lazyFunction(); // 触发 lazyFunction 的编译，检查是否使用了缓存
    ```

**2. 内部弱列表的测试 (Test Internal Weak Lists):**

* **功能:** 测试 V8 内部用于管理弱引用的数据结构，例如用于跟踪 Native Contexts 的弱列表是否能够正确地添加、移除元素，并在垃圾回收时正确处理。
* **测试场景:** 创建多个 Native Contexts，编译并优化一些函数，然后模拟垃圾回收，观察 Native Contexts 的数量是否符合预期。
* **代码逻辑推理 (假设输入与输出):**
    * **假设输入:**  创建 `kNumTestContexts` (例如 10) 个 Native Contexts。
    * **输出:** 每次创建 Context 后，`CountNativeContexts()` 的值应该递增。当 Context 被销毁后，该值应该递减。垃圾回收过程应该能正确回收不再使用的 Context。
* **用户常见的编程错误:**  未能正确地释放 Native Contexts，导致内存泄漏。
    * **JavaScript 示例 (虽然不是直接的 JavaScript 错误，但说明了 Context 的重要性):**
    ```javascript
    // 在 Node.js 环境中创建多个 Context (模拟)
    const vm = require('vm');
    let contexts = [];
    for (let i = 0; i < 5; i++) {
      const context = vm.createContext({ value: i });
      contexts.push(context);
      // 如果不手动处理，这些 context 的资源需要在 GC 时释放
    }
    ```

**3. 正则表达式代码大小的测试 (Test Size Of RegExp Code):**

* **功能:** 测试编译后的正则表达式代码的大小，并验证优化是否会影响代码大小。
* **测试场景:** 编译一个很大的正则表达式，然后编译一个相对小的正则表达式，比较它们在堆上的占用空间。
* **代码逻辑推理 (假设输入与输出):**
    * **假设输入:** 一个非常长的正则表达式字符串和一个相对短的正则表达式字符串。
    * **输出:**  编译后的长正则表达式的代码大小应该比初始堆大小增加较多。优化后的小正则表达式的代码大小可能会比未优化时大，因为优化引入了额外的代码。
* **与 JavaScript 的关系:** 正则表达式是 JavaScript 中常用的功能。过大的正则表达式可能会导致性能问题和内存占用过高。
    * **JavaScript 示例:**
    ```javascript
    const longRegex = /aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/;
    const shortRegex = /abc/;

    // V8 内部会编译这些正则表达式
    ```

**4. 对象大小的测试 (Test Size Of Objects):**

* **功能:** 测试 `Heap::SizeOfObjects()` 方法的准确性，该方法用于计算堆上所有对象的总大小。
* **测试场景:**  分配一些对象，然后调用 `Heap::SizeOfObjects()`，验证返回的大小是否符合预期。
* **代码逻辑推理 (假设输入与输出):**
    * **假设输入:**  在堆上分配一定数量和大小的对象。
    * **输出:** `Heap::SizeOfObjects()` 的返回值应该等于所有分配对象的大小之和。

**5. 对齐计算的测试 (Test Alignment Calculations):**

* **功能:** 测试 V8 内部用于计算内存对齐的工具函数的正确性，确保对象在堆上按照正确的边界进行分配。
* **测试场景:** 针对不同的对齐要求和起始地址，测试 `Heap::GetFillToAlign()` 等函数的返回值。

**6. 对齐分配的测试 (Test Aligned Allocation & Test Aligned Over Allocation):**

* **功能:** 测试 V8 的堆分配器在需要特定内存对齐时是否能正确地分配内存，包括在线性分配缓冲区和空闲列表分配的场景。
* **测试场景:**  分配需要双字对齐的对象，并验证分配的地址是否符合要求，以及在需要填充字节时是否正确添加了填充对象。
* **代码逻辑推理 (假设输入与输出):**
    * **假设输入:**  请求分配一个需要双字对齐的 `kTaggedSize` 大小的对象。
    * **输出:**  分配的对象的起始地址应该是 8 字节对齐的（在 64 位系统上）。如果需要填充，会在对象前面添加填充对象。

**7. HeapNumber 对齐的测试 (HeapNumberAlignment):**

* **功能:** 特别测试 `HeapNumber` 对象在堆上的对齐情况。
* **测试场景:**  在新空间和老空间分配 `HeapNumber` 对象，并验证它们是否按照要求的对齐方式分配。

**8. `SizeOfObjects` 与 `HeapObjectIterator` 精度的测试 (Test SizeOfObjectsVsHeapObjectIteratorPrecision):**

* **功能:** 比较 `Heap::SizeOfObjects()` 的结果和通过遍历堆中所有对象计算的大小，以验证两者的一致性。

**9. 防止通过 Map 泄漏 Native Context (LeakNativeContextViaMap, LeakNativeContextViaFunction, LeakNativeContextViaMapKeyed, LeakNativeContextViaMapProto):**

* **功能:** 测试 V8 的优化器是否会错误地将来自不同 Native Contexts 的 Map 或函数嵌入到优化后的代码中，这可能导致内存泄漏。
* **测试场景:**  创建两个不同的 Native Contexts，在一个 Context 中创建对象或函数，然后在另一个 Context 中使用并优化相关代码，观察是否会持有对第一个 Context 的引用。
* **用户常见的编程错误:**  在不同的 Context 之间不正确地共享对象或函数，可能导致意外的引用和内存泄漏。

**10. `InstanceOf` Stub 写屏障的测试 (InstanceOfStubWriteBarrier):**

* **功能:**  测试 `instanceof` 操作的 Stub 代码中的写屏障是否正确工作，这对于增量标记垃圾回收器至关重要，以确保对象图的正确性。

**总结 (本部分功能归纳):**

这部分 `test-heap.cc` 集中测试了 V8 堆管理的多个核心方面，涵盖了编译缓存的生命周期管理、内部弱引用的处理、对象内存占用和对齐、以及防止跨 Context 泄漏等关键功能。这些测试确保了 V8 堆的正确性、效率和安全性，对于保证 JavaScript 程序的稳定运行至关重要。 它主要关注的是**编译缓存的再生机制、堆内部数据结构的正确性（例如弱列表）、内存分配的对齐策略以及防止跨上下文信息泄露的机制**。

Prompt: 
```
这是目录为v8/test/cctest/heap/test-heap.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/heap/test-heap.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共9部分，请归纳一下它的功能

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
  v8::Local<v8::Context> ctx = CcTest::isola
"""


```