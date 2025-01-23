Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/test/cctest/heap/test-heap.cc`. They also want to know:
1. If the file ended in `.tq`, would it be Torque code?
2. If the code relates to Javascript, provide a Javascript example.
3. If there's code logic, provide an example with inputs and outputs.
4. If it demonstrates common programming errors, give an example.
5. A summary of the code's function, considering it's part 5 of 9.

**Thinking Process:**

1. **Identify the core functionality:** The code consists of various `TEST` macros, indicating it's a unit test file. The tests focus on the V8 heap, specifically its behavior under different conditions like garbage collection (GC), incremental marking, and optimizations.

2. **Categorize the tests:** I'll group the tests by the feature they are exercising:
    * **Basic GC:** `CountForcedGC`
    * **Object Printing:** `PrintSharedFunctionInfo` (conditional)
    * **Incremental Marking and ICs (Inline Caches):** `IncrementalMarkingPreservesMonomorphicCallIC`, `IncrementalMarkingPreservesMonomorphicConstructor`, `IncrementalMarkingPreservesMonomorphicIC`, `IncrementalMarkingPreservesPolymorphicIC`, `ContextDisposeDoesntClearPolymorphicIC`
    * **Stack Trace Handling:** `ReleaseStackTraceData`, `DetailedErrorStackTrace`, `DetailedErrorStackTraceInline`, `DetailedErrorStackTraceBuiltinExitNoAdaptation`, `DetailedErrorStackTraceBuiltinExitWithAdaptation`, `DetailedErrorStackTraceBuiltinExitArrayShift`
    * **Edge Cases/Regressions:** `Regress169928`
    * **Large Objects and Incremental Marking:** `LargeObjectSlotRecording`, `IncrementalMarkingStepMakesBigProgressWithLargeObjects`
    * **Persistent Handles and Fillers:** `PersistentHandles`, `DoNotEvacuateFillersFromPersistentHandles`, `DoNotPromoteFillersFromPersistentHandles`
    * **Disabling Inline Allocation:** `DisableInlineAllocation`
    * **Allocation Site Tracking:** `EnsureAllocationSiteDependentCodesProcessed`

3. **Address each specific request:**
    * **.tq ending:**  Yes, files ending in `.tq` in V8 typically are Torque files.
    * **Javascript relation:**  Many tests directly relate to Javascript concepts like function calls, object properties, error handling, and array creation. I will provide examples for relevant tests.
    * **Code logic inference:** Some tests have clear setup and assertions. I'll choose a simpler one (like `CountForcedGC`) for a hypothetical input/output.
    * **Common programming errors:**  The stack trace tests indirectly touch upon errors. I'll focus on the type of errors that trigger stack traces, which could stem from programmer mistakes.
    * **Part 5 of 9:**  Given the types of tests in this section, it seems to focus heavily on the interaction of garbage collection (especially incremental marking), optimization techniques (like inline caching and inlining), and error reporting mechanisms.

4. **Structure the answer:** I will organize the response with clear headings for each point, making it easy to read and understand.

5. **Review and refine:**  Ensure the Javascript examples are correct and relevant. Double-check the assumptions and reasoning. Make sure the summary accurately reflects the content of this specific section.
This section of the `test-heap.cc` file in V8 focuses on testing various aspects of the V8 heap, particularly how it behaves under different garbage collection scenarios and optimization techniques. Here's a breakdown of its functionalities:

**Core Functionalities Demonstrated by the Tests:**

* **Forced Garbage Collection Counting:**  Tests that the V8 engine correctly counts the number of times a garbage collection is explicitly forced using the `gc()` JavaScript function.
* **Shared Function Information Printing:** (Conditional - based on `OBJECT_PRINT` macro) Tests the ability to print information about shared function objects, which hold metadata about functions.
* **Incremental Marking and Inline Caches (ICs):** A significant portion of the tests focuses on how incremental marking (a garbage collection technique) interacts with inline caches. These tests verify that:
    * Incremental marking doesn't invalidate or corrupt monomorphic call ICs (where a function is called on objects of the same type).
    * Incremental marking doesn't clear monomorphic constructor ICs.
    * Incremental marking preserves both monomorphic and polymorphic ICs (where a function is called on objects of different types).
    * Disposing of a context doesn't unexpectedly clear polymorphic ICs.
* **Stack Trace Data Release:** Tests that the data associated with error stack traces (like source code information) is released from memory after the stack trace is accessed for the first time. This is important for memory management.
* **Detailed Error Stack Traces:**  Tests the functionality of capturing detailed error stack traces, including the arguments passed to functions in the call stack. This is crucial for debugging. These tests cover scenarios with:
    * Interpreted functions.
    * Optimized functions with inlined calls.
    * Built-in functions (both those that adapt arguments and those that don't).
* **Regression Testing:** Includes a test (`Regress169928`) to verify a specific bug fix related to object allocation and garbage collection.
* **Large Object Handling:** Tests how incremental marking handles large objects and ensures that references from large objects to other objects are correctly updated after garbage collection moves those objects.
* **Persistent Handles:** Tests the behavior of persistent handles, which are a way to keep objects alive across garbage collections. It checks that these handles correctly prevent objects from being collected.
* **Fillers and Persistent Handles:** Tests that "fillers" (unused memory regions created during array trimming) are not mistakenly kept alive by persistent handles.
* **Incremental Marking Progress with Large Objects:** Tests that incremental marking makes significant progress when dealing with large objects.
* **Disabling Inline Allocation:** Tests the functionality to temporarily disable inline allocation of objects, which can be useful for debugging or performance analysis.
* **Allocation Site Tracking:** Tests the mechanism for tracking allocation sites, which are points in the code where objects are allocated. This is used for optimization and performance monitoring.

**1. If v8/test/cctest/heap/test-heap.cc ended in .tq:**

Yes, if the file `v8/test/cctest/heap/test-heap.cc` ended in `.tq`, it would likely be a **V8 Torque source code file**. Torque is V8's internal language for implementing built-in functions and runtime components.

**2. If it relates to javascript functionality, please use javascript to illustrate:**

Many tests in this section directly relate to JavaScript behavior. Here are a few examples:

* **`CountForcedGC`:**  This test verifies the counting of explicit garbage collections initiated from JavaScript:

   ```javascript
   // JavaScript code that would trigger the forced GC being counted
   gc();
   gc();
   ```

* **`IncrementalMarkingPreservesMonomorphicCallIC`:** This test relates to how V8 optimizes function calls based on the types of objects they are called with. Consider this JavaScript:

   ```javascript
   function fun() {};
   function f(a) { a(); }

   f(new fun()); // First call, V8 might mark this as monomorphic for `fun`

   // Later, after incremental marking, calling `f` again with the same type
   f(new fun()); // Should still benefit from the monomorphic IC
   ```

* **`DetailedErrorStackTrace`:** This tests how detailed stack traces are captured when errors occur in JavaScript:

   ```javascript
   function func1(arg1) {
     let err = new Error();
     throw err;
   }
   function func2(arg1, arg2) {
     func1(42);
   }
   function main(arg1, arg2) {
     func2(arg1, false);
   }
   var foo = {};
   main(foo); // This will throw an error, and the test checks the stack trace
   ```

**3. If there is code logic inference, please give hypothetical input and output:**

Let's take the `CountForcedGC` test as an example:

**Hypothetical Input:**

The JavaScript code `gc(); gc();` is executed. The `MockUseCounterCallback` is set up to increment `forced_gc_counter` when a forced GC event occurs.

**Hypothetical Output:**

The assertion `CHECK_GT(forced_gc_counter, 0);` will pass, and more specifically, `forced_gc_counter` will be equal to 2 after the `CompileRun(source);` line.

**4. If it involves common programming errors, please provide an example:**

While the tests themselves are designed to verify correct behavior, some tests touch upon scenarios that can arise from programmer errors:

* **Stack Overflow:** The `ReleaseStackTraceData` test uses a recursive function that causes a stack overflow. This is a classic programming error:

   ```javascript
   function f() { f(); } // Recursive function with no base case
   try {
     f();
   } catch (e) {
     // Error caught
   }
   ```

* **Incorrect Use of Built-in Functions:** The `DetailedErrorStackTraceBuiltinExitNoAdaptation` and `DetailedErrorStackTraceBuiltinExitWithAdaptation` tests implicitly demonstrate errors that can occur when built-in functions are called with incorrect arguments (though the tests trigger these errors intentionally). For example, calling `Number.prototype.toFixed()` with invalid precision values will throw an error.

**5. This is part 5 of 9, please summarize its function:**

Considering that this is part 5 of 9, and based on the types of tests present, this section of `test-heap.cc` primarily focuses on:

* **Garbage Collection Robustness:**  Ensuring that different garbage collection mechanisms (especially incremental marking) work correctly and don't corrupt the heap or invalidate optimizations.
* **Optimization Verification:** Validating that optimizations like inline caching are preserved and function as expected during garbage collection cycles.
* **Error Handling and Debugging:**  Testing the mechanisms for capturing and managing error information, particularly stack traces, which are crucial for debugging JavaScript code.
* **Memory Management:**  Verifying aspects of memory management, such as the release of resources associated with stack traces and the correct handling of persistent handles.

It seems like this part builds upon foundational heap tests and delves into more complex interactions between garbage collection, optimization, and error reporting within the V8 engine.

### 提示词
```
这是目录为v8/test/cctest/heap/test-heap.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/heap/test-heap.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
instead of 1, then we should increase the
  // size of the first page a little in SizeOfFirstPage in spaces.cc.  The
  // first page should be small in order to reduce memory used when the VM
  // boots, but if the 20 small arrays don't fit on the first page then that's
  // an indication that it is too small.
  heap::InvokeMemoryReducingMajorGCs(heap);
  CHECK_GE(initial_page_count, old_space->CountTotalPages());
}

static int forced_gc_counter = 0;

void MockUseCounterCallback(v8::Isolate* isolate,
                            v8::Isolate::UseCounterFeature feature) {
  isolate->GetCurrentContext();
  if (feature == v8::Isolate::kForcedGC) {
    forced_gc_counter++;
  }
}

TEST(CountForcedGC) {
  v8_flags.expose_gc = true;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  v8::HandleScope scope(CcTest::isolate());

  isolate->SetUseCounterCallback(MockUseCounterCallback);

  forced_gc_counter = 0;
  const char* source = "gc();";
  CompileRun(source);
  CHECK_GT(forced_gc_counter, 0);
}

#ifdef OBJECT_PRINT
TEST(PrintSharedFunctionInfo) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> ctx = CcTest::isolate()->GetCurrentContext();
  const char* source =
      "f = function() { return 987654321; }\n"
      "g = function() { return 123456789; }\n";
  CompileRun(source);
  i::DirectHandle<JSFunction> g = i::Cast<JSFunction>(
      v8::Utils::OpenDirectHandle(*v8::Local<v8::Function>::Cast(
          CcTest::global()->Get(ctx, v8_str("g")).ToLocalChecked())));

  StdoutStream os;
  Print(g->shared(), os);
  os << std::endl;
}
#endif  // OBJECT_PRINT

TEST(IncrementalMarkingPreservesMonomorphicCallIC) {
  if (!v8_flags.use_ic) return;
  if (!v8_flags.incremental_marking) return;
  if (v8_flags.always_turbofan) return;
  v8_flags.allow_natives_syntax = true;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Value> fun1, fun2;
  v8::Local<v8::Context> ctx = CcTest::isolate()->GetCurrentContext();
  {
    CompileRun("function fun() {};");
    fun1 = CcTest::global()->Get(ctx, v8_str("fun")).ToLocalChecked();
  }

  {
    CompileRun("function fun() {};");
    fun2 = CcTest::global()->Get(ctx, v8_str("fun")).ToLocalChecked();
  }

  // Prepare function f that contains type feedback for the two closures.
  CHECK(CcTest::global()->Set(ctx, v8_str("fun1"), fun1).FromJust());
  CHECK(CcTest::global()->Set(ctx, v8_str("fun2"), fun2).FromJust());
  CompileRun(
      "function f(a, b) { a(); b(); } %EnsureFeedbackVectorForFunction(f); "
      "f(fun1, fun2);");

  DirectHandle<JSFunction> f = Cast<JSFunction>(
      v8::Utils::OpenDirectHandle(*v8::Local<v8::Function>::Cast(
          CcTest::global()->Get(ctx, v8_str("f")).ToLocalChecked())));

  Handle<FeedbackVector> feedback_vector(f->feedback_vector(), f->GetIsolate());
  FeedbackVectorHelper feedback_helper(feedback_vector);

  int expected_slots = 2;
  CHECK_EQ(expected_slots, feedback_helper.slot_count());
  int slot1 = 0;
  int slot2 = 1;
  CHECK(feedback_vector->Get(feedback_helper.slot(slot1)).IsWeak());
  CHECK(feedback_vector->Get(feedback_helper.slot(slot2)).IsWeak());

  heap::SimulateIncrementalMarking(CcTest::heap());
  heap::InvokeMajorGC(CcTest::heap());

  CHECK(feedback_vector->Get(feedback_helper.slot(slot1)).IsWeak());
  CHECK(feedback_vector->Get(feedback_helper.slot(slot2)).IsWeak());
}

static void CheckVectorIC(DirectHandle<JSFunction> f, int slot_index,
                          InlineCacheState desired_state) {
  Handle<FeedbackVector> vector =
      Handle<FeedbackVector>(f->feedback_vector(), f->GetIsolate());
  FeedbackVectorHelper helper(vector);
  FeedbackSlot slot = helper.slot(slot_index);
  FeedbackNexus nexus(CcTest::i_isolate(), vector, slot);
  CHECK(nexus.ic_state() == desired_state);
}

TEST(IncrementalMarkingPreservesMonomorphicConstructor) {
  if (!v8_flags.incremental_marking) return;
  if (v8_flags.always_turbofan) return;
  v8_flags.allow_natives_syntax = true;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> ctx = CcTest::isolate()->GetCurrentContext();
  // Prepare function f that contains a monomorphic IC for object
  // originating from the same native context.
  CompileRun(
      "function fun() { this.x = 1; };"
      "function f(o) { return new o(); }"
      "%EnsureFeedbackVectorForFunction(f);"
      "f(fun); f(fun);");
  DirectHandle<JSFunction> f = Cast<JSFunction>(
      v8::Utils::OpenDirectHandle(*v8::Local<v8::Function>::Cast(
          CcTest::global()->Get(ctx, v8_str("f")).ToLocalChecked())));

  DirectHandle<FeedbackVector> vector(f->feedback_vector(), f->GetIsolate());
  CHECK(vector->Get(FeedbackSlot(0)).IsWeakOrCleared());

  heap::SimulateIncrementalMarking(CcTest::heap());
  heap::InvokeMajorGC(CcTest::heap());

  CHECK(vector->Get(FeedbackSlot(0)).IsWeakOrCleared());
}

TEST(IncrementalMarkingPreservesMonomorphicIC) {
  if (!v8_flags.use_ic) return;
  if (!v8_flags.incremental_marking) return;
  if (v8_flags.always_turbofan) return;
  v8_flags.allow_natives_syntax = true;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> ctx = CcTest::isolate()->GetCurrentContext();
  // Prepare function f that contains a monomorphic IC for object
  // originating from the same native context.
  CompileRun(
      "function fun() { this.x = 1; }; var obj = new fun();"
      "%EnsureFeedbackVectorForFunction(f);"
      "function f(o) { return o.x; } f(obj); f(obj);");
  DirectHandle<JSFunction> f = Cast<JSFunction>(
      v8::Utils::OpenDirectHandle(*v8::Local<v8::Function>::Cast(
          CcTest::global()->Get(ctx, v8_str("f")).ToLocalChecked())));

  CheckVectorIC(f, 0, InlineCacheState::MONOMORPHIC);

  heap::SimulateIncrementalMarking(CcTest::heap());
  heap::InvokeMajorGC(CcTest::heap());

  CheckVectorIC(f, 0, InlineCacheState::MONOMORPHIC);
}

TEST(IncrementalMarkingPreservesPolymorphicIC) {
  if (!v8_flags.use_ic) return;
  if (!v8_flags.incremental_marking) return;
  if (v8_flags.always_turbofan) return;
  v8_flags.allow_natives_syntax = true;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Value> obj1, obj2;
  v8::Local<v8::Context> ctx = CcTest::isolate()->GetCurrentContext();

  {
    LocalContext env;
    CompileRun("function fun() { this.x = 1; }; var obj = new fun();");
    obj1 = env->Global()->Get(env.local(), v8_str("obj")).ToLocalChecked();
  }

  {
    LocalContext env;
    CompileRun("function fun() { this.x = 2; }; var obj = new fun();");
    obj2 = env->Global()->Get(env.local(), v8_str("obj")).ToLocalChecked();
  }

  // Prepare function f that contains a polymorphic IC for objects
  // originating from two different native contexts.
  CHECK(CcTest::global()->Set(ctx, v8_str("obj1"), obj1).FromJust());
  CHECK(CcTest::global()->Set(ctx, v8_str("obj2"), obj2).FromJust());
  CompileRun(
      "function f(o) { return o.x; }; "
      "%EnsureFeedbackVectorForFunction(f);"
      "f(obj1); f(obj1); f(obj2);");
  DirectHandle<JSFunction> f = Cast<JSFunction>(
      v8::Utils::OpenDirectHandle(*v8::Local<v8::Function>::Cast(
          CcTest::global()->Get(ctx, v8_str("f")).ToLocalChecked())));

  CheckVectorIC(f, 0, InlineCacheState::POLYMORPHIC);

  // Fire context dispose notification.
  heap::SimulateIncrementalMarking(CcTest::heap());
  heap::InvokeMajorGC(CcTest::heap());

  CheckVectorIC(f, 0, InlineCacheState::POLYMORPHIC);
}

TEST(ContextDisposeDoesntClearPolymorphicIC) {
  if (!v8_flags.use_ic) return;
  if (!v8_flags.incremental_marking) return;
  if (v8_flags.always_turbofan) return;
  v8_flags.allow_natives_syntax = true;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Value> obj1, obj2;
  v8::Local<v8::Context> ctx = CcTest::isolate()->GetCurrentContext();

  {
    LocalContext env;
    CompileRun("function fun() { this.x = 1; }; var obj = new fun();");
    obj1 = env->Global()->Get(env.local(), v8_str("obj")).ToLocalChecked();
  }

  {
    LocalContext env;
    CompileRun("function fun() { this.x = 2; }; var obj = new fun();");
    obj2 = env->Global()->Get(env.local(), v8_str("obj")).ToLocalChecked();
  }

  // Prepare function f that contains a polymorphic IC for objects
  // originating from two different native contexts.
  CHECK(CcTest::global()->Set(ctx, v8_str("obj1"), obj1).FromJust());
  CHECK(CcTest::global()->Set(ctx, v8_str("obj2"), obj2).FromJust());
  CompileRun(
      "function f(o) { return o.x; }; "
      "%EnsureFeedbackVectorForFunction(f);"
      "f(obj1); f(obj1); f(obj2);");
  DirectHandle<JSFunction> f = Cast<JSFunction>(
      v8::Utils::OpenDirectHandle(*v8::Local<v8::Function>::Cast(
          CcTest::global()->Get(ctx, v8_str("f")).ToLocalChecked())));

  CheckVectorIC(f, 0, InlineCacheState::POLYMORPHIC);

  // Fire context dispose notification.
  CcTest::isolate()->ContextDisposedNotification();
  heap::SimulateIncrementalMarking(CcTest::heap());
  heap::InvokeMajorGC(CcTest::heap());

  CheckVectorIC(f, 0, InlineCacheState::POLYMORPHIC);
}

class SourceResource : public v8::String::ExternalOneByteStringResource {
 public:
  explicit SourceResource(const char* data)
    : data_(data), length_(strlen(data)) { }

  void Dispose() override {
    i::DeleteArray(data_);
    data_ = nullptr;
  }

  const char* data() const override { return data_; }

  size_t length() const override { return length_; }

  bool IsDisposed() { return data_ == nullptr; }

 private:
  const char* data_;
  size_t length_;
};

void ReleaseStackTraceDataTest(v8::Isolate* isolate, const char* source,
                               const char* accessor) {
  // Test that the data retained by the Error.stack accessor is released
  // after the first time the accessor is fired.  We use external string
  // to check whether the data is being released since the external string
  // resource's callback is fired when the external string is GC'ed.
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  i::Heap* heap = i_isolate->heap();
  v8::HandleScope scope(isolate);

  SourceResource* resource = new SourceResource(i::StrDup(source));
  {
    v8::HandleScope new_scope(isolate);
    v8::Local<v8::Context> ctx = isolate->GetCurrentContext();
    v8::Local<v8::String> source_string =
        v8::String::NewExternalOneByte(isolate, resource).ToLocalChecked();
    heap::InvokeMemoryReducingMajorGCs(heap);
    v8::Script::Compile(ctx, source_string)
        .ToLocalChecked()
        ->Run(ctx)
        .ToLocalChecked();
    CHECK(!resource->IsDisposed());
  }
  CHECK(!resource->IsDisposed());

  CompileRun(accessor);

  {
    // We need to invoke GC without stack, otherwise some objects may not be
    // reclaimed because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMemoryReducingMajorGCs(heap);
  }

  // External source has been released.
  CHECK(resource->IsDisposed());
  delete resource;
}

UNINITIALIZED_TEST(ReleaseStackTraceData) {
#ifndef V8_LITE_MODE
  // ICs retain objects.
  v8_flags.use_ic = false;
#endif  // V8_LITE_MODE
  v8_flags.concurrent_recompilation = false;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    v8::Context::New(isolate)->Enter();
    static const char* source1 =
        "var error = null;            "
        /* Normal Error */
        "try {                        "
        "  throw new Error();         "
        "} catch (e) {                "
        "  error = e;                 "
        "}                            ";
    static const char* source2 =
        "var error = null;            "
        /* Stack overflow */
        "try {                        "
        "  (function f() { f(); })(); "
        "} catch (e) {                "
        "  error = e;                 "
        "}                            ";
    static const char* source3 =
        "var error = null;            "
        /* Normal Error */
        "try {                        "
        /* as prototype */
        "  throw new Error();         "
        "} catch (e) {                "
        "  error = {};                "
        "  error.__proto__ = e;       "
        "}                            ";
    static const char* source4 =
        "var error = null;            "
        /* Stack overflow */
        "try {                        "
        /* as prototype   */
        "  (function f() { f(); })(); "
        "} catch (e) {                "
        "  error = {};                "
        "  error.__proto__ = e;       "
        "}                            ";
    static const char* getter = "error.stack";
    static const char* setter = "error.stack = 0";

    ReleaseStackTraceDataTest(isolate, source1, setter);
    ReleaseStackTraceDataTest(isolate, source2, setter);
    // We do not test source3 and source4 with setter, since the setter is
    // supposed to (untypically) write to the receiver, not the holder.  This is
    // to emulate the behavior of a data property.

    ReleaseStackTraceDataTest(isolate, source1, getter);
    ReleaseStackTraceDataTest(isolate, source2, getter);
    ReleaseStackTraceDataTest(isolate, source3, getter);
    ReleaseStackTraceDataTest(isolate, source4, getter);
  }
  isolate->Dispose();
}

// TODO(mmarchini) also write tests for async/await and Promise.all
void DetailedErrorStackTraceTest(const char* src,
                                 std::function<void(Handle<FixedArray>)> test) {
  v8_flags.detailed_error_stack_trace = true;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  v8::TryCatch try_catch(CcTest::isolate());
  CompileRun(src);

  CHECK(try_catch.HasCaught());
  Handle<Object> exception = v8::Utils::OpenHandle(*try_catch.Exception());

  test(CcTest::i_isolate()->GetSimpleStackTrace(Cast<JSReceiver>(exception)));
}

Tagged<FixedArray> ParametersOf(DirectHandle<FixedArray> stack_trace,
                                int frame_index) {
  return Cast<CallSiteInfo>(stack_trace->get(frame_index))->parameters();
}

// * Test interpreted function error
TEST(DetailedErrorStackTrace) {
  static const char* source =
      "function func1(arg1) {       "
      "  let err = new Error();     "
      "  throw err;                 "
      "}                            "
      "function func2(arg1, arg2) { "
      "  func1(42);                 "
      "}                            "
      "class Foo {};                "
      "function main(arg1, arg2) {  "
      "  func2(arg1, false);        "
      "}                            "
      "var foo = new Foo();         "
      "main(foo);                   ";

  DetailedErrorStackTraceTest(source, [](DirectHandle<FixedArray> stack_trace) {
    Tagged<FixedArray> foo_parameters = ParametersOf(stack_trace, 0);
    CHECK_EQ(foo_parameters->length(), 1);
    CHECK(IsSmi(foo_parameters->get(0)));
    CHECK_EQ(Smi::ToInt(foo_parameters->get(0)), 42);

    Tagged<FixedArray> bar_parameters = ParametersOf(stack_trace, 1);
    CHECK_EQ(bar_parameters->length(), 2);
    CHECK(IsJSObject(bar_parameters->get(0)));
    CHECK(IsBoolean(bar_parameters->get(1)));
    DirectHandle<Object> foo = Cast<Object>(GetByName("foo"));
    CHECK_EQ(bar_parameters->get(0), *foo);
    CHECK(!Object::BooleanValue(bar_parameters->get(1), CcTest::i_isolate()));

    Tagged<FixedArray> main_parameters = ParametersOf(stack_trace, 2);
    CHECK_EQ(main_parameters->length(), 2);
    CHECK(IsJSObject(main_parameters->get(0)));
    CHECK(IsUndefined(main_parameters->get(1)));
    CHECK_EQ(main_parameters->get(0), *foo);
  });
}

// * Test optimized function with inline frame error
TEST(DetailedErrorStackTraceInline) {
  v8_flags.allow_natives_syntax = true;
  static const char* source =
      "function add(x) {                     "
      " if (x == 42)                         "
      "  throw new Error();                  "
      " return x + x;                        "
      "}                                     "
      "add(0);                               "
      "add(1);                               "
      "function foo(x) {                     "
      " return add(x + 1)                    "
      "}                                     "
      "%PrepareFunctionForOptimization(foo); "
      "foo(40);                              "
      "%OptimizeFunctionOnNextCall(foo);     "
      "foo(41);                              ";

  DetailedErrorStackTraceTest(source, [](DirectHandle<FixedArray> stack_trace) {
    Tagged<FixedArray> parameters_add = ParametersOf(stack_trace, 0);
    CHECK_EQ(parameters_add->length(), 1);
    CHECK(IsSmi(parameters_add->get(0)));
    CHECK_EQ(Smi::ToInt(parameters_add->get(0)), 42);

    Tagged<FixedArray> parameters_foo = ParametersOf(stack_trace, 1);
    CHECK_EQ(parameters_foo->length(), 1);
    CHECK(IsSmi(parameters_foo->get(0)));
    CHECK_EQ(Smi::ToInt(parameters_foo->get(0)), 41);
  });
}

// * Test builtin exit error
TEST(DetailedErrorStackTraceBuiltinExitNoAdaptation) {
  // The test needs to call CPP builtin that doesn't adapt arguments and might
  // throw an exception under certain conditions.
  CHECK(Builtins::IsCpp(Builtin::kNumberPrototypeToFixed));
  CHECK_EQ(Builtins::GetFormalParameterCount(Builtin::kNumberPrototypeToFixed),
           kDontAdaptArgumentsSentinel);

  static const char* source =
      "function test(arg1) {                     "
      "  (new Number()).toFixed(arg1, 42, -153); "
      "}                                         "
      "test(9999);                               ";

  DetailedErrorStackTraceTest(source, [](DirectHandle<FixedArray> stack_trace) {
    Tagged<FixedArray> parameters = ParametersOf(stack_trace, 0);

    CHECK_EQ(parameters->length(), 3);
    CHECK_EQ(Smi::ToInt(parameters->get(0)), 9999);
    CHECK_EQ(Smi::ToInt(parameters->get(1)), 42);
    CHECK_EQ(Smi::ToInt(parameters->get(2)), -153);
  });
}

TEST(DetailedErrorStackTraceBuiltinExitWithAdaptation) {
  // The test needs to call CPP builtin that adapts arguments and might
  // throw an exception under certain conditions.
  CHECK(Builtins::IsCpp(Builtin::kObjectDefineProperty));
  CHECK_EQ(Builtins::GetFormalParameterCount(Builtin::kObjectDefineProperty),
           JSParameterCount(3));

  static const char* source =
      "function test() {                  "
      "  Object.defineProperty(153, -42); "
      "}                                  "
      "test();                            ";

  DetailedErrorStackTraceTest(source, [](DirectHandle<FixedArray> stack_trace) {
    Tagged<FixedArray> parameters = ParametersOf(stack_trace, 0);

    CHECK_EQ(parameters->length(), 3);
    CHECK_EQ(Smi::ToInt(parameters->get(0)), 153);
    CHECK_EQ(Smi::ToInt(parameters->get(1)), -42);
    CHECK(IsUndefined(parameters->get(2)));
  });
}

// Ensure that inlined call of CPP builtin works correctly with stack traces.
// See https://crbug.com/v8/14409.
TEST(DetailedErrorStackTraceBuiltinExitArrayShift) {
  v8_flags.allow_natives_syntax = true;
  CHECK(Builtins::IsCpp(Builtin::kArrayShift));
  CHECK_EQ(Builtins::GetFormalParameterCount(Builtin::kArrayShift),
           kDontAdaptArgumentsSentinel);

  constexpr int slow_path_length = JSArray::kMaxCopyElements + 20;
  base::ScopedVector<char> source(1024);
  base::SNPrintF(source,
                 "var length = %d;"
                 "var array = new Array(length);"
                 "var ro_array = Object.freeze(new Array(length));"
                 "function test(a) {"
                 "  return a.shift(55, 77, 99);"
                 "};"
                 "%%PrepareFunctionForOptimization(test);"
                 "test(array);"
                 "%%OptimizeFunctionOnNextCall(test);"
                 "test(ro_array);",
                 slow_path_length);

  DetailedErrorStackTraceTest(
      source.begin(), [](DirectHandle<FixedArray> stack_trace) {
        Tagged<FixedArray> parameters = ParametersOf(stack_trace, 0);

        CHECK_EQ(parameters->length(), 3);
        CHECK_EQ(Smi::ToInt(parameters->get(0)), 55);
        CHECK_EQ(Smi::ToInt(parameters->get(1)), 77);
        CHECK_EQ(Smi::ToInt(parameters->get(2)), 99);
      });
}

TEST(Regress169928) {
  v8_flags.allow_natives_syntax = true;
#if !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
  v8_flags.turbofan = false;
#endif  // !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  LocalContext env;
  Factory* factory = isolate->factory();
  v8::HandleScope scope(CcTest::isolate());

  // Some flags turn Scavenge collections into Mark-sweep collections
  // and hence are incompatible with this test case.
  if (v8_flags.gc_global || v8_flags.stress_compaction ||
      v8_flags.stress_incremental_marking || v8_flags.single_generation ||
      v8_flags.minor_ms)
    return;

  // Prepare the environment
  CompileRun(
      "function fastliteralcase(literal, value) {"
      "    literal[0] = value;"
      "    return literal;"
      "}"
      "function get_standard_literal() {"
      "    var literal = [1, 2, 3];"
      "    return literal;"
      "}"
      "obj = fastliteralcase(get_standard_literal(), 1);"
      "obj = fastliteralcase(get_standard_literal(), 1.5);"
      "obj = fastliteralcase(get_standard_literal(), 2);");

  // prepare the heap
  v8::Local<v8::String> mote_code_string =
      v8_str("fastliteralcase(mote, 2.5);");

  v8::Local<v8::String> array_name = v8_str("mote");
  CHECK(CcTest::global()
            ->Set(env.local(), array_name, v8::Int32::New(CcTest::isolate(), 0))
            .FromJust());

  // First make sure we flip spaces
  heap::InvokeMinorGC(CcTest::heap());

  // Allocate the object.
  DirectHandle<FixedArray> array_data =
      factory->NewFixedArray(2, AllocationType::kYoung);
  array_data->set(0, Smi::FromInt(1));
  array_data->set(1, Smi::FromInt(2));

  heap::FillCurrentPageButNBytes(
      SemiSpaceNewSpace::From(CcTest::heap()->new_space()),
      JSArray::kHeaderSize + AllocationMemento::kSize + kTaggedSize);

  Handle<JSArray> array =
      factory->NewJSArrayWithElements(array_data, PACKED_SMI_ELEMENTS);

  CHECK_EQ(Smi::FromInt(2), array->length());
  CHECK(array->HasSmiOrObjectElements());

  // We need filler the size of AllocationMemento object, plus an extra
  // fill pointer value.
  Tagged<HeapObject> obj;
  AllocationResult allocation =
      CcTest::heap()->allocator()->new_space_allocator()->AllocateRaw(
          AllocationMemento::kSize + kTaggedSize, kTaggedAligned,
          AllocationOrigin::kRuntime);
  CHECK(allocation.To(&obj));
  Address addr_obj = obj.address();
  CcTest::heap()->CreateFillerObjectAt(addr_obj,
                                       AllocationMemento::kSize + kTaggedSize);

  // Give the array a name, making sure not to allocate strings.
  v8::Local<v8::Object> array_obj = v8::Utils::ToLocal(array);
  CHECK(CcTest::global()->Set(env.local(), array_name, array_obj).FromJust());

  // This should crash with a protection violation if we are running a build
  // with the bug.
  AlwaysAllocateScopeForTesting aa_scope(isolate->heap());
  v8::Script::Compile(env.local(), mote_code_string)
      .ToLocalChecked()
      ->Run(env.local())
      .ToLocalChecked();
}

TEST(LargeObjectSlotRecording) {
  if (!v8_flags.incremental_marking) return;
  if (!v8_flags.compact) return;
  ManualGCScope manual_gc_scope;
  heap::ManualEvacuationCandidatesSelectionScope
      manual_evacuation_candidate_selection_scope(manual_gc_scope);
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  HandleScope scope(isolate);

  // Create an object on an evacuation candidate.
  heap::SimulateFullSpace(heap->old_space());
  IndirectHandle<FixedArray> lit =
      isolate->factory()->NewFixedArray(4, AllocationType::kOld);
  PageMetadata* evac_page = PageMetadata::FromHeapObject(*lit);
  heap::ForceEvacuationCandidate(evac_page);
  Tagged<FixedArray> old_location = *lit;

  // Allocate a large object.
  int size = std::max(1000000, kMaxRegularHeapObjectSize + KB);
  CHECK_LT(kMaxRegularHeapObjectSize, size);
  IndirectHandle<FixedArray> lo =
      isolate->factory()->NewFixedArray(size, AllocationType::kOld);
  CHECK(heap->lo_space()->Contains(*lo));

  // Start incremental marking to active write barrier.
  heap::SimulateIncrementalMarking(heap, false);

  // Create references from the large object to the object on the evacuation
  // candidate.
  const int kStep = size / 10;
  for (int i = 0; i < size; i += kStep) {
    lo->set(i, *lit);
    CHECK(lo->get(i) == old_location);
  }

  heap::SimulateIncrementalMarking(heap, true);

  // Move the evacuation candidate object.
  {
    // We need to invoke GC without stack, otherwise no compaction is performed.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMajorGC(heap);
  }

  // Verify that the pointers in the large object got updated.
  for (int i = 0; i < size; i += kStep) {
    CHECK_EQ(lo->get(i).ptr(), lit->ptr());
    CHECK_NE(lo->get(i).ptr(), old_location.ptr());
  }
}

class DummyVisitor : public RootVisitor {
 public:
  void VisitRootPointers(Root root, const char* description,
                         FullObjectSlot start, FullObjectSlot end) override {}
};

TEST(PersistentHandles) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  v8::HandleScope scope(reinterpret_cast<v8::Isolate*>(isolate));
  HandleScopeData* data = isolate->handle_scope_data();
  IndirectHandle<Object> init(ReadOnlyRoots(heap).empty_string(), isolate);
  while (data->next < data->limit) {
    IndirectHandle<Object> obj(ReadOnlyRoots(heap).empty_string(), isolate);
  }
  // An entire block of handles has been filled.
  // Next handle would require a new block.
  CHECK(data->next == data->limit);

  PersistentHandlesScope persistent(isolate);
  DummyVisitor visitor;
  isolate->handle_scope_implementer()->Iterate(&visitor);
  persistent.Detach();
}

static void TestFillersFromPersistentHandles(bool promote) {
  // We assume that the fillers can only arise when left-trimming arrays.
  ManualGCScope manual_gc_scope;
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  v8::HandleScope scope(reinterpret_cast<v8::Isolate*>(isolate));

  const size_t n = 10;
  DirectHandle<FixedArray> array = isolate->factory()->NewFixedArray(n);

  if (promote) {
    // Age the array so it's ready for promotion on next GC.
    heap::InvokeMinorGC(heap);
  }
  CHECK(HeapLayout::InYoungGeneration(*array));

  PersistentHandlesScope persistent_scope(isolate);

  // Trim the array three times to different sizes so all kinds of fillers are
  // created and tracked by the persistent handles.
  DirectHandle<FixedArrayBase> filler_1(*array, isolate);
  DirectHandle<FixedArrayBase> filler_2(heap->LeftTrimFixedArray(*filler_1, 1),
                                        isolate);
  DirectHandle<FixedArrayBase> filler_3(heap->LeftTrimFixedArray(*filler_2, 2),
                                        isolate);
  DirectHandle<FixedArrayBase> tail(heap->LeftTrimFixedArray(*filler_3, 3),
                                    isolate);

  std::unique_ptr<PersistentHandles> persistent_handles(
      persistent_scope.Detach());

  // GC should retain the trimmed array but drop all of the three fillers.
  heap::InvokeMinorGC(heap);
  if (!v8_flags.single_generation) {
    if (promote) {
      CHECK(heap->InOldSpace(*tail));
    } else {
      CHECK(HeapLayout::InYoungGeneration(*tail));
    }
  }
  CHECK_EQ(n - 6, tail->length());
  CHECK(!IsHeapObject(*filler_1));
  CHECK(!IsHeapObject(*filler_2));
  CHECK(!IsHeapObject(*filler_3));
}

TEST(DoNotEvacuateFillersFromPersistentHandles) {
  if (v8_flags.single_generation || v8_flags.move_object_start) return;
  TestFillersFromPersistentHandles(false /*promote*/);
}

TEST(DoNotPromoteFillersFromPersistentHandles) {
  if (v8_flags.single_generation || v8_flags.move_object_start) return;
  TestFillersFromPersistentHandles(true /*promote*/);
}

TEST(IncrementalMarkingStepMakesBigProgressWithLargeObjects) {
  if (!v8_flags.incremental_marking) return;
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  CompileRun(
      "function f(n) {"
      "    var a = new Array(n);"
      "    for (var i = 0; i < n; i += 100) a[i] = i;"
      "};"
      "f(10 * 1024 * 1024);");
  IncrementalMarking* marking = CcTest::heap()->incremental_marking();
  if (marking->IsStopped()) {
    CcTest::heap()->StartIncrementalMarking(
        i::GCFlag::kNoFlags, i::GarbageCollectionReason::kTesting);
  }
  heap::SimulateIncrementalMarking(CcTest::heap());
  CHECK(marking->IsMajorMarkingComplete());
}

TEST(DisableInlineAllocation) {
  v8_flags.allow_natives_syntax = true;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  CompileRun(
      "function test() {"
      "  var x = [];"
      "  for (var i = 0; i < 10; i++) {"
      "    x[i] = [ {}, [1,2,3], [1,x,3] ];"
      "  }"
      "}"
      "function run() {"
      "  %PrepareFunctionForOptimization(test);"
      "  %OptimizeFunctionOnNextCall(test);"
      "  test();"
      "  %DeoptimizeFunction(test);"
      "}");

  // Warm-up with inline allocation enabled.
  CompileRun("test(); test(); run();");

  // Run test with inline allocation disabled.
  CcTest::heap()->DisableInlineAllocation();
  CompileRun("run()");

  // Run test with inline allocation re-enabled.
  CcTest::heap()->EnableInlineAllocation();
  CompileRun("run()");
}

static int AllocationSitesCount(Heap* heap) {
  int count = 0;
  for (Tagged<Object> site = heap->allocation_sites_list();
       IsAllocationSite(site);) {
    Tagged<AllocationSite> cur = Cast<AllocationSite>(site);
    CHECK(cur->HasWeakNext());
    site = cur->weak_next();
    count++;
  }
  return count;
}

static int SlimAllocationSiteCount(Heap* heap) {
  int count = 0;
  for (Tagged<Object> weak_list = heap->allocation_sites_list();
       IsAllocationSite(weak_list);) {
    Tagged<AllocationSite> weak_cur = Cast<AllocationSite>(weak_list);
    for (Tagged<Object> site = weak_cur->nested_site();
         IsAllocationSite(site);) {
      Tagged<AllocationSite> cur = Cast<AllocationSite>(site);
      CHECK(!cur->HasWeakNext());
      site = cur->nested_site();
      count++;
    }
    weak_list = weak_cur->weak_next();
  }
  return count;
}

TEST(EnsureAllocationSiteDependentCodesProcessed) {
  if (v8_flags.always_turbofan || !V8_ALLOCATION_SITE_TRACKING_BOOL) {
    return;
  }
  v8_flags.allow_natives_syntax = true;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  v8::internal::Heap* heap = CcTest::heap();
  GlobalHandles* global_handles = isolate->global_handles();

  if (!isolate->use_optimizer()) return;

  // The allocation site at the head of the list is ours.
  IndirectHandle<AllocationSite> site;
  {
    LocalContext context;
    v8::HandleScope scope(context->GetIsolate());

    int count = AllocationSitesCount(heap);
    CompileRun(
        "var bar = function() { return (new Array()); };"
        "%PrepareFunctionForOptimization(bar);"
        "var a = bar();"
        "bar();"
        "bar();");

    // One allocation site should have been created.
    int new_count = AllocationSitesCount(heap);
    CHECK_EQ(new_count, (count + 1));
    site = Cast<AllocationSite>(global_handles->Create(
        Cast<AllocationSite>(heap->allocation_sites_list())));

    CompileRun("%OptimizeFunctionOnNextCall(bar); bar();");

    IndirectHandle<JSFunction> bar_handle = Cast<JSFunction>(
        v8::Utils::OpenIndirectHandle(*v8::Local<v8::Function>::Cast(
            CcTest::global()
                ->Get(context.local(), v8_str("bar"))
                .ToLocalChecked())));

    // Expect a dependent code object for transitioning and pretenuring.
    Tagged<DependentCode> dependency = site->dependent_code();
    CHECK_NE(dependency,
             DependentCode::empty_dependent_code(ReadOnlyRoots(isolate)));
    CHECK_EQ(dependency->length(), DependentCode::kSlotsPerEntry);
    Tagged<MaybeObject> code =
        dependency->Get(0 + DependentCode::kCodeSlotOffset);
    CHECK(code.IsWeak());
    CHECK_EQ(bar_handle->code(isolate),
             Cast<CodeWrapper>(code.GetHeapObjectAssumeWeak())->code(isolate));
    Tagged<Smi> groups =
        dependency->Get(0 + DependentCode::kGrou
```