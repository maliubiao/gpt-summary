Response: The user wants me to summarize the functionality of the C++ code provided.
The code is a part of the V8 JavaScript engine's test suite, specifically testing the heap management.
It covers various aspects of the heap, including garbage collection (major and minor), incremental marking, handling of weak references, allocation sites, stack traces, and interactions with optimized code.
It also touches upon potential issues and regressions related to heap management.

To summarize the functionality of this part, I will go through each `TEST` block and describe its purpose. I will also look for relationships with JavaScript functionality and provide examples if found.
这个C++代码片段主要用于测试V8 JavaScript引擎的堆管理功能，特别是与垃圾回收、内存分配和对象生命周期相关的特性。以下是代码片段中各个测试用例的功能归纳：

* **`TEST(CountForcedGC)`**:  测试 `gc()` JavaScript 函数是否会触发 V8 的 `UseCounterCallback` 并递增 `forced_gc_counter` 计数器。这与 JavaScript 中手动触发垃圾回收的功能相关。
    ```javascript
    gc(); // 调用此函数会触发测试中的计数器增加
    ```

* **`TEST(PrintSharedFunctionInfo)`**:  这个测试在启用了 `OBJECT_PRINT` 宏的情况下，编译并运行一段 JavaScript 代码，然后打印其中一个函数的共享信息 (`SharedFunctionInfo`)。这与 JavaScript 中函数的内部表示有关，但用户通常无法直接访问。

* **`TEST(IncrementalMarkingPreservesMonomorphicCallIC)`**: 测试在增量标记垃圾回收过程中，单态调用点内联缓存 (Monomorphic Call IC) 的信息是否得到保留。这与 JavaScript 引擎的性能优化机制有关，当一个函数调用始终指向同一个目标时，会进行优化。

* **`TEST(IncrementalMarkingPreservesMonomorphicConstructor)`**: 测试在增量标记垃圾回收过程中，单态构造函数调用的内联缓存是否得到保留。这类似于上一个测试，但针对的是 `new` 操作符。

* **`TEST(IncrementalMarkingPreservesMonomorphicIC)`**: 测试在增量标记垃圾回收过程中，单态属性访问的内联缓存是否得到保留。这涉及到 JavaScript 中对象的属性访问优化。
    ```javascript
    function fun() { this.x = 1; };
    var obj = new fun();
    function f(o) { return o.x; } // 访问 obj.x，会形成单态内联缓存
    f(obj); f(obj);
    ```

* **`TEST(IncrementalMarkingPreservesPolymorphicIC)`**: 测试在增量标记垃圾回收过程中，多态属性访问的内联缓存是否得到保留。当属性访问的目标对象类型不一致时，会形成多态内联缓存。
    ```javascript
    // obj1 和 obj2 是不同构造函数的实例
    function fun1() { this.x = 1; }; var obj1 = new fun1();
    function fun2() { this.x = 2; }; var obj2 = new fun2();
    function f(o) { return o.x; }; // 访问不同类型对象的 x 属性，会形成多态内联缓存
    f(obj1); f(obj1); f(obj2);
    ```

* **`TEST(ContextDisposeDoesntClearPolymorphicIC)`**: 测试在上下文被销毁后，多态属性访问的内联缓存是否仍然保留。这涉及到 V8 中上下文的概念和垃圾回收的交互。

* **`UNINITIALIZED_TEST(ReleaseStackTraceData)`**:  测试错误堆栈信息占用的数据在第一次访问后是否被释放。这与 JavaScript 中 `Error.stack` 属性的实现有关，为了节省内存，实际的堆栈信息可能在需要时才生成和保留。
    ```javascript
    try {
      throw new Error();
    } catch (e) {
      console.log(e.stack); // 第一次访问 e.stack 后，相关数据应被释放
    }
    ```

* **`TEST(DetailedErrorStackTrace)`**: 测试在详细错误堆栈信息开启的情况下，捕获的错误对象是否包含函数调用的参数信息。这涉及到 JavaScript 错误处理和调试功能。
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
    main(foo); // 捕获的错误堆栈信息应包含 main 和 func2 的参数
    ```

* **`TEST(DetailedErrorStackTraceInline)`**:  类似于上一个测试，但针对的是包含内联函数调用的情况。

* **`TEST(DetailedErrorStackTraceBuiltinExitNoAdaptation)`**: 测试调用 C++ 内置函数时，详细错误堆栈信息是否能正确捕获参数。

* **`TEST(DetailedErrorStackTraceBuiltinExitWithAdaptation)`**: 类似于上一个测试，但针对的是需要参数适配的 C++ 内置函数。

* **`TEST(DetailedErrorStackTraceBuiltinExitArrayShift)`**: 测试内联调用 C++ 内置函数 `Array.shift()` 时，错误堆栈信息是否正确。

* **`TEST(Regress169928)`**: 这是一个回归测试，用于防止特定 bug 的再次出现，该 bug 与数组字面量和垃圾回收有关。

* **`TEST(LargeObjectSlotRecording)`**: 测试在增量标记垃圾回收期间，对大型对象中的槽位记录是否正确更新，特别是当它们指向需要疏散的对象时。

* **`TEST(PersistentHandles)`**: 测试持久句柄的作用域，确保在持久句柄存在时，相关对象不会被垃圾回收。这与 V8 的 C++ API 使用有关，JavaScript 代码本身没有直接对应。

* **`TEST(DoNotEvacuateFillersFromPersistentHandles)`** 和 **`TEST(DoNotPromoteFillersFromPersistentHandles)`**: 测试持久句柄是否会阻止填充对象在垃圾回收过程中被疏散或晋升。填充对象是由于数组收缩等操作产生的。

* **`TEST(IncrementalMarkingStepMakesBigProgressWithLargeObjects)`**:  测试增量标记垃圾回收在处理大型对象时是否能取得显著进展。

* **`TEST(DisableInlineAllocation)`**: 测试禁用内联分配后，代码的执行情况。内联分配是一种性能优化手段。

* **`TEST(EnsureAllocationSiteDependentCodesProcessed)`**: 测试垃圾回收是否会处理与分配点相关的代码，即使分配点本身仍然存活。

* **`TEST(AllocationSiteCreation)`**: 测试各种 JavaScript 代码结构（如数组字面量、对象字面量）是否会创建相应的分配点，用于优化对象分配。
    ```javascript
    function f1() { return []; } // 数组字面量会创建分配点
    function f5() { return {}; } // 对象字面量在首次执行后会创建分配点
    ```

* **`TEST(CellsInOptimizedCodeAreWeak)`** 和 **`TEST(ObjectsInOptimizedCodeAreWeak)`**: 测试优化后的代码中引用的 Cell 和对象是否是弱引用，允许垃圾回收器回收不再使用的对象。

* **`TEST(NewSpaceObjectsInOptimizedCode)`**: 测试新生代对象在优化后的代码中是否被正确处理，包括垃圾回收后的晋升。

* **`TEST(ObjectsInEagerlyDeoptimizedCodeAreWeak)`**: 测试被主动反优化的代码中引用的对象是否是弱引用。

* **`TEST(WeakFunctionInConstructor)`**: 测试在构造函数调用中，反馈向量中对构造函数的弱引用是否在垃圾回收后被清除。
    ```javascript
    function createObj(obj) { return new obj(); }
    function hat() { this.x = 5; }
    createObj(hat); // hat 的弱引用会被记录
    ```

* **多个 `TEST(WeakMapIn...)`**:  这些测试用例验证在不同类型的内联缓存 (IC) 中嵌入的 Map 是否是弱引用，确保当 Map 不再被其他地方引用时，可以被垃圾回收。这些 IC 包括单态和多态的属性加载、属性存储、键值加载和键值存储以及与 `null` 的比较。

* **`TEST(MonomorphicStaysMonomorphicAfterGC)`** 和 **`TEST(PolymorphicStaysPolymorphicAfterGC)`**: 测试垃圾回收后，单态和多态内联缓存的状态是否得到保留。

* **`TEST(AddInstructionChangesNewSpacePromotion)`**: 这是一个调试测试，可能用于检测指令添加是否会影响新生代对象的晋升。

* **`TEST(CEntryStubOOM)`**:  测试在 C++ 入口桩 (CEntryStub) 中是否能正确处理内存溢出 (OOM) 的情况。

* **`HEAP_TEST(Regress538257)`**: 这是一个堆相关的回归测试，用于防止特定的内存管理 bug。

* **`TEST(Regress357137)`**: 另一个回归测试，可能与中断处理和栈溢出有关。

* **`TEST(Regress507979)`**:  一个回归测试，用于检查在垃圾回收过程中，对对象进行部分填充是否会导致问题。

* **`TEST(Regress388880)`**:  测试增量标记垃圾回收与对象迁移的交互，防止特定崩溃。

* **`TEST(Regress3631)`**: 测试增量标记垃圾回收与 `WeakMap` 的交互。

总而言之，这个代码片段是 V8 引擎堆管理功能的一个详尽的测试集，涵盖了垃圾回收的各个阶段和优化策略，以及它们与 JavaScript 代码执行的交互。这些测试确保了 V8 引擎的内存管理的正确性和健壮性。

### 提示词
```
这是目录为v8/test/cctest/heap/test-heap.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```
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
        dependency->Get(0 + DependentCode::kGroupsSlotOffset).ToSmi();
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