Response:
Let's break down the thought process for analyzing this code snippet and generating the response.

1. **Understand the Goal:** The primary goal is to analyze the provided C++ code (specifically, a portion of a V8 test file) and describe its functionality, relating it to JavaScript where applicable. The prompt also includes specific constraints about Torque files, JavaScript examples, logic reasoning, common errors, and the fact that this is part 4 of a 6-part series.

2. **Initial Scan and Keyword Recognition:** Quickly scan the code for keywords and patterns. Notice things like `TEST(`, `Isolate*`, `CodeAssemblerTester`, `CodeStubAssembler`, `PromiseBuiltinsAssembler`, `FunctionTester`,  `CHECK_EQ`, `CHECK`, `Smi::FromInt`, `ReadOnlyRoots`, `JSArray`, `JSPromise`, `PromiseCapability`, `DirectHandle`, `Handle`, `TNode`, `Label`, `Return`, `GotoIf`, `LoadBufferData`, `Word32And`, `IsWhiteSpaceOrLineTerminator`, `BranchIfNumberRelationalComparison`, `IsNumberArrayIndex`, `NumberMin`, `NumberMax`.

3. **Identify Core Components:**  Based on the keywords, identify the main components:
    * **`TEST(...)` blocks:** These are clearly unit tests. Each `TEST` focuses on a specific functionality.
    * **Assembler Classes (`CodeStubAssembler`, `PromiseBuiltinsAssembler`, `AppendJSArrayCodeStubAssembler`):**  These are used to generate low-level code stubs for V8. This is a key piece of information – the tests are verifying the correct generation and behavior of these stubs.
    * **`CodeAssemblerTester` and `FunctionTester`:** These are helper classes for setting up the testing environment and executing the generated code stubs.
    * **V8 Specific Types (`Isolate*`, `Handle<Object>`, `Smi`, `Map`, `JSPromise`, etc.):**  These indicate the code interacts directly with V8's internal representation of JavaScript objects and values.
    * **Assertions (`CHECK_EQ`, `CHECK`):**  These verify the correctness of the generated code's behavior.

4. **Categorize Test Functionality:**  Group the tests based on the operations they are testing. This involves reading the test names and the code within each `TEST` block. Examples:
    * **Array Appending:** Tests related to `AppendJSArrayCodeStubAssembler` clearly deal with appending elements to JavaScript arrays.
    * **Promise Operations:** Tests involving `PromiseBuiltinsAssembler`, `JSPromise`, `PromiseCapability` are about promise creation and handling.
    * **Symbol Checks:** Tests with names like `IsSymbol` and `IsPrivateSymbol` check the type of symbols.
    * **Direct Memory Access:** Tests named `DirectMemoryTest...` are testing the ability to load data directly from memory buffers.
    * **String/Character Checks:** `IsWhiteSpaceOrLineTerminator` tests character properties.
    * **Number Operations:** `BranchIfNumberRelationalComparison`, `IsNumberArrayIndex`, `NumberMinMax` test numeric comparisons and operations.

5. **Relate to JavaScript (where applicable):** For each category, think about the corresponding JavaScript functionality.
    * **Array Appending:**  Relates directly to `array.push()`.
    * **Promise Operations:** Connects to `new Promise()`, `Promise.resolve()`, `Promise.reject()`, and the overall promise lifecycle.
    * **Symbol Checks:**  Corresponds to `Symbol()` and `Symbol.for()`.
    * **Other tests (Direct Memory, String/Character, Number Operations):** While these don't have direct one-to-one JavaScript equivalents at the *user* level, they are fundamental operations that underpin JavaScript's behavior. It's important to acknowledge this connection even if a direct example isn't readily apparent.

6. **Illustrate with JavaScript Examples:**  Provide concise JavaScript code snippets to demonstrate the high-level behavior that the C++ tests are verifying at a lower level.

7. **Infer Logic and Provide Input/Output Examples:** For tests that have a clear logical flow (like `BuildAppendJSArray...`),  hypothesize the input values and the expected output based on the test's purpose. For example, in the array appending tests, the initial and final array sizes are important.

8. **Identify Potential Programming Errors:** Think about common mistakes developers make that relate to the tested functionality.
    * **Array Appending:**  Incorrectly assuming array size or type.
    * **Promises:**  Not handling rejections, forgetting to return from `then` or `catch`.
    * **Type Checks:**  Incorrectly assuming the type of a variable.

9. **Address Specific Prompt Requirements:** Ensure all parts of the prompt are addressed:
    * **Torque:** Explicitly state that `.cc` means it's C++, not Torque.
    * **Part of a Series:** Acknowledge that this is part 4 of 6 and tailor the summary accordingly. Avoid repeating information that might have been covered in earlier parts (though without seeing those parts, this is somewhat speculative).

10. **Summarize Functionality:**  Provide a concise summary of the code snippet's overall purpose, focusing on what it tests (low-level code generation for various JavaScript operations).

11. **Review and Refine:**  Read through the generated response to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that could be explained better. For instance, initially, I might focus too much on the C++ details, but then refine it to better connect with JavaScript concepts. Also, ensure the language is precise and avoids jargon where possible, or explains it when necessary.

**(Self-Correction Example during the process):** Initially, I might just list the tests and what they seem to be doing individually. However, the prompt asks for a *summary of the functionality*. This requires grouping related tests, identifying common themes (like "testing array appending logic in the code stub assembler"), and explaining the *overall purpose* of this section of the test suite. Therefore, I'd adjust my approach to synthesize a higher-level understanding rather than just listing individual test details.
```cpp
NumParams));
    AppendJSArrayCodeStubAssembler m(asm_tester.state(), kind);
    m.TestAppendJSArrayImpl(
        isolate, &asm_tester, Handle<Object>(o1, isolate),
        Handle<Object>(o2, isolate), Handle<Object>(o3, isolate),
        Handle<Object>(o4, isolate), initial_size, result_size);
  }

 private:
  static const int kNumParams = 4;
  ElementsKind kind_;
};

TEST(BuildAppendJSArrayFastElement) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  AppendJSArrayCodeStubAssembler::TestAppendJSArray(
      isolate, PACKED_ELEMENTS, Smi::FromInt(3), Smi::FromInt(4),
      Smi::FromInt(5), Smi::FromInt(6), 6, 6);
}

TEST(BuildAppendJSArrayFastElementGrow) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  AppendJSArrayCodeStubAssembler::TestAppendJSArray(
      isolate, PACKED_ELEMENTS, Smi::FromInt(3), Smi::FromInt(4),
      Smi::FromInt(5), Smi::FromInt(6), 2, 6);
}

TEST(BuildAppendJSArrayFastSmiElement) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  AppendJSArrayCodeStubAssembler::TestAppendJSArray(
      isolate, PACKED_SMI_ELEMENTS, Smi::FromInt(3), Smi::FromInt(4),
      Smi::FromInt(5), Smi::FromInt(6), 6, 6);
}

TEST(BuildAppendJSArrayFastSmiElementGrow) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  AppendJSArrayCodeStubAssembler::TestAppendJSArray(
      isolate, PACKED_SMI_ELEMENTS, Smi::FromInt(3), Smi::FromInt(4),
      Smi::FromInt(5), Smi::FromInt(6), 2, 6);
}

TEST(BuildAppendJSArrayFastSmiElementObject) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  AppendJSArrayCodeStubAssembler::TestAppendJSArray(
      isolate, PACKED_SMI_ELEMENTS, Smi::FromInt(3), Smi::FromInt(4),
      ReadOnlyRoots(isolate).undefined_value(), Smi::FromInt(6), 6, 4);
}

TEST(BuildAppendJSArrayFastSmiElementObjectGrow) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  AppendJSArrayCodeStubAssembler::TestAppendJSArray(
      isolate, PACKED_SMI_ELEMENTS, Smi::FromInt(3), Smi::FromInt(4),
      ReadOnlyRoots(isolate).undefined_value(), Smi::FromInt(6), 2, 4);
}

TEST(BuildAppendJSArrayFastDoubleElements) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  AppendJSArrayCodeStubAssembler::TestAppendJSArray(
      isolate, PACKED_DOUBLE_ELEMENTS, Smi::FromInt(3), Smi::FromInt(4),
      Smi::FromInt(5), Smi::FromInt(6), 6, 6);
}

TEST(BuildAppendJSArrayFastDoubleElementsGrow) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  AppendJSArrayCodeStubAssembler::TestAppendJSArray(
      isolate, PACKED_DOUBLE_ELEMENTS, Smi::FromInt(3), Smi::FromInt(4),
      Smi::FromInt(5), Smi::FromInt(6), 2, 6);
}

TEST(BuildAppendJSArrayFastDoubleElementsObject) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  AppendJSArrayCodeStubAssembler::TestAppendJSArray(
      isolate, PACKED_DOUBLE_ELEMENTS, Smi::FromInt(3), Smi::FromInt(4),
      ReadOnlyRoots(isolate).undefined_value(), Smi::FromInt(6), 6, 4);
}

namespace {

template <typename Stub, typename... Args>
void Recompile(Args... args) {
  Stub stub(args...);
  stub.DeleteStubFromCacheForTesting();
  stub.GetCode();
}

}  // namespace

void CustomPromiseHook(v8::PromiseHookType type, v8::Local<v8::Promise> promise,
                       v8::Local<v8::Value> parentPromise) {}

TEST(IsPromiseHookEnabled) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  m.Return(
      m.SelectBooleanConstant(
          m.IsIsolatePromiseHookEnabledOrHasAsyncEventDelegate()));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  DirectHandle<Object> result =
      ft.Call(isolate->factory()->undefined_value()).ToHandleChecked();
  CHECK_EQ(ReadOnlyRoots(isolate).false_value(), *result);

  isolate->SetPromiseHook(CustomPromiseHook);
  result = ft.Call(isolate->factory()->undefined_value()).ToHandleChecked();
  CHECK_EQ(ReadOnlyRoots(isolate).true_value(), *result);

  isolate->SetPromiseHook(nullptr);
  result = ft.Call(isolate->factory()->undefined_value()).ToHandleChecked();
  CHECK_EQ(ReadOnlyRoots(isolate).false_value(), *result);
}

TEST(NewJSPromise) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  PromiseBuiltinsAssembler m(asm_tester.state());

  auto context = m.GetJSContextParameter();
  const TNode<JSPromise> promise = m.NewJSPromise(context);
  m.Return(promise);

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  DirectHandle<Object> result =
      ft.Call(isolate->factory()->undefined_value()).ToHandleChecked();
  CHECK(IsJSPromise(*result));
}

TEST(NewJSPromise2) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  PromiseBuiltinsAssembler m(asm_tester.state());

  auto context = m.GetJSContextParameter();
  const TNode<JSPromise> promise =
      m.NewJSPromise(context, v8::Promise::kRejected, m.SmiConstant(1));
  m.Return(promise);

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  Handle<Object> result =
      ft.Call(isolate->factory()->undefined_value()).ToHandleChecked();
  CHECK(IsJSPromise(*result));
  DirectHandle<JSPromise> js_promise = Cast<JSPromise>(result);
  CHECK_EQ(v8::Promise::kRejected, js_promise->status());
  CHECK_EQ(Smi::FromInt(1), js_promise->result());
  CHECK(!js_promise->has_handler());
}

TEST(IsSymbol) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  auto symbol = m.Parameter<HeapObject>(1);
  m.Return(m.SelectBooleanConstant(m.IsSymbol(symbol)));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  DirectHandle<Object> result =
      ft.Call(isolate->factory()->NewSymbol()).ToHandleChecked();
  CHECK_EQ(ReadOnlyRoots(isolate).true_value(), *result);

  result = ft.Call(isolate->factory()->empty_string()).ToHandleChecked();
  CHECK_EQ(ReadOnlyRoots(isolate).false_value(), *result);
}

TEST(IsPrivateSymbol) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  auto symbol = m.Parameter<HeapObject>(1);
  m.Return(m.SelectBooleanConstant(m.IsPrivateSymbol(symbol)));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  DirectHandle<Object> result =
      ft.Call(isolate->factory()->NewSymbol()).ToHandleChecked();
  CHECK_EQ(ReadOnlyRoots(isolate).false_value(), *result);

  result = ft.Call(isolate->factory()->empty_string()).ToHandleChecked();
  CHECK_EQ(ReadOnlyRoots(isolate).false_value(), *result);

  result = ft.Call(isolate->factory()->NewPrivateSymbol()).ToHandleChecked();
  CHECK_EQ(ReadOnlyRoots(isolate).true_value(), *result);
}

TEST(PromiseHasHandler) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  PromiseBuiltinsAssembler m(asm_tester.state());

  auto context = m.GetJSContextParameter();
  const TNode<JSPromise> promise =
      m.NewJSPromise(context, m.UndefinedConstant());
  m.Return(m.SelectBooleanConstant(m.PromiseHasHandler(promise)));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  DirectHandle<Object> result =
      ft.Call(isolate->factory()->undefined_value()).ToHandleChecked();
  CHECK_EQ(ReadOnlyRoots(isolate).false_value(), *result);
}

TEST(CreatePromiseResolvingFunctionsContext) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  PromiseBuiltinsAssembler m(asm_tester.state());

  auto context = m.GetJSContextParameter();
  const TNode<NativeContext> native_context = m.LoadNativeContext(context);
  const TNode<JSPromise> promise =
      m.NewJSPromise(context, m.UndefinedConstant());
  const TNode<Context> promise_context =
      m.CreatePromiseResolvingFunctionsContext(
          context, promise, m.BooleanConstant(false), native_context);
  m.Return(promise_context);

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  Handle<Object> result = ft.Call().ToHandleChecked();
  CHECK(IsContext(*result));
  DirectHandle<Context> context_js = Cast<Context>(result);
  CHECK_EQ(isolate->root(RootIndex::kEmptyScopeInfo), context_js->scope_info());
  CHECK_EQ(*isolate->native_context(), context_js->native_context());
  CHECK(IsJSPromise(context_js->get(PromiseBuiltins::kPromiseSlot)));
  CHECK_EQ(ReadOnlyRoots(isolate).false_value(),
           context_js->get(PromiseBuiltins::kDebugEventSlot));
}

TEST(CreatePromiseResolvingFunctions) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  PromiseBuiltinsAssembler m(asm_tester.state());

  auto context = m.GetJSContextParameter();
  const TNode<NativeContext> native_context = m.LoadNativeContext(context);
  const TNode<JSPromise> promise =
      m.NewJSPromise(context, m.UndefinedConstant());
  PromiseResolvingFunctions funcs = m.CreatePromiseResolvingFunctions(
      context, promise, m.BooleanConstant(false), native_context);
  TNode<JSFunction> resolve = funcs.resolve;
  TNode<JSFunction> reject = funcs.reject;
  TNode<IntPtrT> const kSize = m.IntPtrConstant(2);
  TNode<FixedArray> const arr =
      m.Cast(m.AllocateFixedArray(PACKED_ELEMENTS, kSize));
  m.StoreFixedArrayElement(arr, 0, resolve);
  m.StoreFixedArrayElement(arr, 1, reject);
  m.Return(arr);

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  Handle<Object> result_obj =
      ft.Call(isolate->factory()->undefined_value()).ToHandleChecked();
  CHECK(IsFixedArray(*result_obj));
  DirectHandle<FixedArray> result_arr = Cast<FixedArray>(result_obj);
  CHECK(IsJSFunction(result_arr->get(0)));
  CHECK(IsJSFunction(result_arr->get(1)));
}

TEST(NewElementsCapacity) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());
  m.Return(m.SmiTag(
      m.CalculateNewElementsCapacity(m.SmiUntag(m.Parameter<Smi>(1)))));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  Handle<Smi> test_value = Handle<Smi>(Smi::FromInt(1), isolate);
  Tagged<Smi> result_obj = *ft.CallChecked<Smi>(test_value);
  CHECK_EQ(
      result_obj.value(),
      static_cast<int>(JSObject::NewElementsCapacity((*test_value).value())));
  test_value = Handle<Smi>(Smi::FromInt(1), isolate);
  result_obj = *ft.CallChecked<Smi>(test_value);
  CHECK_EQ(
      result_obj.value(),
      static_cast<int>(JSObject::NewElementsCapacity((*test_value).value())));
  test_value = Handle<Smi>(Smi::FromInt(2), isolate);
  result_obj = *ft.CallChecked<Smi>(test_value);
  CHECK_EQ(
      result_obj.value(),
      static_cast<int>(JSObject::NewElementsCapacity((*test_value).value())));
  test_value = Handle<Smi>(Smi::FromInt(1025), isolate);
  result_obj = *ft.CallChecked<Smi>(test_value);
  CHECK_EQ(
      result_obj.value(),
      static_cast<int>(JSObject::NewElementsCapacity((*test_value).value())));
}

TEST(NewElementsCapacitySmi) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());
  m.Return(m.CalculateNewElementsCapacity(m.UncheckedParameter<Smi>(1)));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  Handle<Smi> test_value = Handle<Smi>(Smi::FromInt(0), isolate);
  Tagged<Smi> result_obj = *ft.CallChecked<Smi>(test_value);
  CHECK_EQ(
      result_obj.value(),
      static_cast<int>(JSObject::NewElementsCapacity((*test_value).value())));
  test_value = Handle<Smi>(Smi::FromInt(1), isolate);
  result_obj = *ft.CallChecked<Smi>(test_value);
  CHECK_EQ(
      result_obj.value(),
      static_cast<int>(JSObject::NewElementsCapacity((*test_value).value())));
  test_value = Handle<Smi>(Smi::FromInt(2), isolate);
  result_obj = *ft.CallChecked<Smi>(test_value);
  CHECK_EQ(
      result_obj.value(),
      static_cast<int>(JSObject::NewElementsCapacity((*test_value).value())));
  test_value = Handle<Smi>(Smi::FromInt(1025), isolate);
  result_obj = *ft.CallChecked<Smi>(test_value);
  CHECK_EQ(
      result_obj.value(),
      static_cast<int>(JSObject::NewElementsCapacity((*test_value).value())));
}

TEST(AllocateRootFunctionWithContext) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  PromiseBuiltinsAssembler m(asm_tester.state());

  const auto context = m.GetJSContextParameter();
  const TNode<NativeContext> native_context = m.LoadNativeContext(context);
  const TNode<JSPromise> promise =
      m.NewJSPromise(context, m.UndefinedConstant());
  TNode<Context> promise_context = m.CreatePromiseResolvingFunctionsContext(
      context, promise, m.BooleanConstant(false), native_context);
  const TNode<JSFunction> resolve = m.AllocateRootFunctionWithContext(
      RootIndex::kPromiseCapabilityDefaultResolveSharedFun, promise_context,
      native_context);
  m.Return(resolve);

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  Handle<Object> result_obj =
      ft.Call(isolate->factory()->undefined_value()).ToHandleChecked();
  CHECK(IsJSFunction(*result_obj));
  DirectHandle<JSFunction> fun = Cast<JSFunction>(result_obj);
  CHECK_EQ(ReadOnlyRoots(isolate).empty_property_array(),
           fun->property_array());
  CHECK_EQ(ReadOnlyRoots(isolate).empty_fixed_array(), fun->elements());
  CHECK_EQ(isolate->heap()->many_closures_cell(), fun->raw_feedback_cell());
  CHECK(!fun->has_prototype_slot());
  CHECK_EQ(*isolate->factory()->promise_capability_default_resolve_shared_fun(),
           fun->shared());
  CHECK_EQ(isolate->factory()
               ->promise_capability_default_resolve_shared_fun()
               ->GetCode(isolate),
           fun->code(isolate));
}

TEST(CreatePromiseGetCapabilitiesExecutorContext) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  PromiseBuiltinsAssembler m(asm_tester.state());

  auto context = m.GetJSContextParameter();
  TNode<NativeContext> native_context = m.LoadNativeContext(context);

  TNode<PromiseCapability> capability = m.CreatePromiseCapability(
      m.UndefinedConstant(), m.UndefinedConstant(), m.UndefinedConstant());
  TNode<Context> executor_context =
      m.CreatePromiseCapabilitiesExecutorContext(native_context, capability);
  m.Return(executor_context);

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  Handle<Object> result_obj =
      ft.Call(isolate->factory()->undefined_value()).ToHandleChecked();
  CHECK(IsContext(*result_obj));
  DirectHandle<Context> context_js = Cast<Context>(result_obj);
  CHECK_EQ(PromiseBuiltins::kCapabilitiesContextLength, context_js->length());
  CHECK_EQ(isolate->root(RootIndex::kEmptyScopeInfo), context_js->scope_info());
  CHECK_EQ(*isolate->native_context(), context_js->native_context());
  CHECK(IsPromiseCapability(context_js->get(PromiseBuiltins::kCapabilitySlot)));
}

TEST(NewPromiseCapability) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  {  // Builtin Promise
    const int kNumParams = 0;
    CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
    PromiseBuiltinsAssembler m(asm_tester.state());

    auto context = m.GetJSContextParameter();
    const TNode<NativeContext> native_context = m.LoadNativeContext(context);
    const TNode<Object> promise_constructor =
        m.LoadContextElement(native_context, Context::PROMISE_FUNCTION_INDEX);

    const TNode<True> debug_event = m.TrueConstant();
    const TNode<Object> capability =
        m.CallBuiltin(Builtin::kNewPromiseCapability, context,
                      promise_constructor, debug_event);
    m.Return(capability);

    FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

    Handle<Object> result_obj = ft.Call().ToHandleChecked();
    CHECK(IsPromiseCapability(*result_obj));
    DirectHandle<PromiseCapability> result =
        Cast<PromiseCapability>(result_obj);

    CHECK(IsJSPromise(result->promise()));
    CHECK(IsJSFunction(result->resolve()));
    CHECK(IsJSFunction(result->reject()));
    CHECK_EQ(
        *isolate->factory()->promise_capability_default_reject_shared_fun(),
        Cast<JSFunction>(result->reject())->shared());
    CHECK_EQ(
        *isolate->factory()->promise_capability_default_resolve_shared_fun(),
        Cast<JSFunction>(result->resolve())->shared());

    Handle<JSFunction> callbacks[] = {
        handle(Cast<JSFunction>(result->resolve()), isolate),
        handle(Cast<JSFunction>(result->reject()), isolate)};

    for (auto&& callback : callbacks) {
      DirectHandle<Context> callback_context(Cast<Context>(callback->context()),
                                             isolate);
      CHECK_EQ(isolate->root(RootIndex::kEmptyScopeInfo),
               callback_context->scope_info());
      CHECK_EQ(*isolate->native_context(), callback_context->native_context());
      CHECK_EQ(PromiseBuiltins::kPromiseContextLength,
               callback_context->length());
      CHECK_EQ(callback_context->get(PromiseBuiltins::kPromiseSlot),
               result->promise());
    }
  }

  {  // Custom Promise
    const int kNumParams = 1;
    CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
    PromiseBuiltinsAssembler m(asm_tester.state());

    auto context = m.GetJSContextParameter();

    auto constructor = m.Parameter<Object>(1);
    const TNode<True> debug_event = m.TrueConstant();
    const TNode<Object> capability = m.CallBuiltin(
        Builtin::kNewPromiseCapability, context, constructor, debug_event);
    m.Return(capability);

    FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

    Handle<JSFunction> constructor_fn =
        Cast<JSFunction>(v8::Utils::OpenHandle(*CompileRun(
            "(function FakePromise(executor) {"
            "  var self = this;"
            "  function resolve(value) { self.resolvedValue = value; }"
            "  function reject(reason) { self.rejectedReason = reason; }"
            "  executor(resolve, reject);"
            "})")));

    Handle<Object> result_obj = ft.Call(constructor_fn).ToHandleChecked();
    CHECK(IsPromiseCapability(*result_obj));
    DirectHandle<PromiseCapability> result =
        Cast<PromiseCapability>(result_obj);

    CHECK(IsJSObject(result->promise()));
    Handle<JSObject> promise(Cast<JSObject>(result->promise()), isolate);
    CHECK_EQ(constructor_fn->prototype_or_initial_map(kAcquireLoad),
             promise->map());
    CHECK(IsJSFunction(result->resolve()));
    CHECK(IsJSFunction(result->reject()));

    Handle<String> resolved_str =
        isolate->factory()->NewStringFromAsciiChecked("resolvedStr");
    Handle<String> rejected_str =
        isolate->factory()->NewStringFromAsciiChecked("rejectedStr");

    Handle<Object> argv1[] = {resolved_str};
    DirectHandle<Object> ret =
        Execution::Call(isolate, handle(result->resolve(), isolate),
                        isolate->factory()->undefined_value(), 1, argv1)
            .ToHandleChecked();

    DirectHandle<Object> prop1 =
        JSReceiver::GetProperty(isolate, promise, "resolvedValue")
            .ToHandleChecked();
    CHECK_EQ(*resolved_str, *prop1);

    Handle<Object> argv2[] = {rejected_str};
    ret = Execution::Call(isolate, handle(result->reject(), isolate),
                          isolate->factory()->undefined_value(), 1, argv2)
              .ToHandleChecked();
    DirectHandle<Object> prop2 =
        JSReceiver::GetProperty(isolate, promise, "rejectedReason")
            .ToHandleChecked();
    CHECK_EQ(*rejected_str, *prop2);
  }
}

TEST(DirectMemoryTest8BitWord32Immediate) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());
  int8_t buffer[] = {1, 2, 4, 8, 17, 33, 65, 127};
  const int element_count = 8;
  Label bad(&m);

  TNode<RawPtrT> buffer_node = m.PointerConstant(buffer);
  for (size_t i = 0; i < element_count; ++i) {
    for (size_t j = 0; j < element_count; ++j) {
      TNode<Uint8T> loaded =
          m.LoadBufferData<Uint8T>(buffer_node, static_cast<int>(i));
      TNode<Word32T> masked = m.Word32And(loaded, m.Int32Constant(buffer[j]));
      if ((buffer[j] & buffer[i]) != 0) {
        m.GotoIf(m.Word32Equal(masked, m.Int32Constant(0)), &bad);
      } else {
        m.GotoIf(m.Word32NotEqual(masked, m.Int32Constant(0)), &bad);
      }
    }
  }

  m.Return(m.SmiConstant(1));

  m.BIND(&bad);
  m.Return(m.SmiConstant(0));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  CHECK_EQ(1, (*ft.CallChecked<Smi>()).value());
}

TEST(DirectMemoryTest16BitWord32Immediate) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());
  int16_t buffer[] = {156, 2234, 4544, 8444, 1723, 3888, 658, 1278};
  const int element_count = 8;
  Label bad(&m);

  TNode<RawPtrT> buffer_node = m.PointerConstant(buffer);
  for (size_t i = 0; i < element_count; ++i) {
    for (size_t j = 0; j < element_count; ++j) {
      TNode<Uint16T> loaded = m.LoadBufferData<Uint16T>(
          buffer_node, static_cast<int>(i * sizeof(int16_t)));
      TNode<Word32T> masked = m.Word32And(loaded, m.Int32Constant(buffer[j]));
      if ((buffer[j] & buffer[i]) != 0) {
        m.GotoIf(m.Word32Equal(masked, m.Int32Constant(0)), &bad);
      } else {
        m
Prompt: 
```
这是目录为v8/test/cctest/test-code-stub-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-code-stub-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能

"""
NumParams));
    AppendJSArrayCodeStubAssembler m(asm_tester.state(), kind);
    m.TestAppendJSArrayImpl(
        isolate, &asm_tester, Handle<Object>(o1, isolate),
        Handle<Object>(o2, isolate), Handle<Object>(o3, isolate),
        Handle<Object>(o4, isolate), initial_size, result_size);
  }

 private:
  static const int kNumParams = 4;
  ElementsKind kind_;
};

TEST(BuildAppendJSArrayFastElement) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  AppendJSArrayCodeStubAssembler::TestAppendJSArray(
      isolate, PACKED_ELEMENTS, Smi::FromInt(3), Smi::FromInt(4),
      Smi::FromInt(5), Smi::FromInt(6), 6, 6);
}

TEST(BuildAppendJSArrayFastElementGrow) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  AppendJSArrayCodeStubAssembler::TestAppendJSArray(
      isolate, PACKED_ELEMENTS, Smi::FromInt(3), Smi::FromInt(4),
      Smi::FromInt(5), Smi::FromInt(6), 2, 6);
}

TEST(BuildAppendJSArrayFastSmiElement) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  AppendJSArrayCodeStubAssembler::TestAppendJSArray(
      isolate, PACKED_SMI_ELEMENTS, Smi::FromInt(3), Smi::FromInt(4),
      Smi::FromInt(5), Smi::FromInt(6), 6, 6);
}

TEST(BuildAppendJSArrayFastSmiElementGrow) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  AppendJSArrayCodeStubAssembler::TestAppendJSArray(
      isolate, PACKED_SMI_ELEMENTS, Smi::FromInt(3), Smi::FromInt(4),
      Smi::FromInt(5), Smi::FromInt(6), 2, 6);
}

TEST(BuildAppendJSArrayFastSmiElementObject) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  AppendJSArrayCodeStubAssembler::TestAppendJSArray(
      isolate, PACKED_SMI_ELEMENTS, Smi::FromInt(3), Smi::FromInt(4),
      ReadOnlyRoots(isolate).undefined_value(), Smi::FromInt(6), 6, 4);
}

TEST(BuildAppendJSArrayFastSmiElementObjectGrow) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  AppendJSArrayCodeStubAssembler::TestAppendJSArray(
      isolate, PACKED_SMI_ELEMENTS, Smi::FromInt(3), Smi::FromInt(4),
      ReadOnlyRoots(isolate).undefined_value(), Smi::FromInt(6), 2, 4);
}

TEST(BuildAppendJSArrayFastDoubleElements) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  AppendJSArrayCodeStubAssembler::TestAppendJSArray(
      isolate, PACKED_DOUBLE_ELEMENTS, Smi::FromInt(3), Smi::FromInt(4),
      Smi::FromInt(5), Smi::FromInt(6), 6, 6);
}

TEST(BuildAppendJSArrayFastDoubleElementsGrow) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  AppendJSArrayCodeStubAssembler::TestAppendJSArray(
      isolate, PACKED_DOUBLE_ELEMENTS, Smi::FromInt(3), Smi::FromInt(4),
      Smi::FromInt(5), Smi::FromInt(6), 2, 6);
}

TEST(BuildAppendJSArrayFastDoubleElementsObject) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  AppendJSArrayCodeStubAssembler::TestAppendJSArray(
      isolate, PACKED_DOUBLE_ELEMENTS, Smi::FromInt(3), Smi::FromInt(4),
      ReadOnlyRoots(isolate).undefined_value(), Smi::FromInt(6), 6, 4);
}

namespace {

template <typename Stub, typename... Args>
void Recompile(Args... args) {
  Stub stub(args...);
  stub.DeleteStubFromCacheForTesting();
  stub.GetCode();
}

}  // namespace

void CustomPromiseHook(v8::PromiseHookType type, v8::Local<v8::Promise> promise,
                       v8::Local<v8::Value> parentPromise) {}

TEST(IsPromiseHookEnabled) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  m.Return(
      m.SelectBooleanConstant(
          m.IsIsolatePromiseHookEnabledOrHasAsyncEventDelegate()));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  DirectHandle<Object> result =
      ft.Call(isolate->factory()->undefined_value()).ToHandleChecked();
  CHECK_EQ(ReadOnlyRoots(isolate).false_value(), *result);

  isolate->SetPromiseHook(CustomPromiseHook);
  result = ft.Call(isolate->factory()->undefined_value()).ToHandleChecked();
  CHECK_EQ(ReadOnlyRoots(isolate).true_value(), *result);

  isolate->SetPromiseHook(nullptr);
  result = ft.Call(isolate->factory()->undefined_value()).ToHandleChecked();
  CHECK_EQ(ReadOnlyRoots(isolate).false_value(), *result);
}

TEST(NewJSPromise) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  PromiseBuiltinsAssembler m(asm_tester.state());

  auto context = m.GetJSContextParameter();
  const TNode<JSPromise> promise = m.NewJSPromise(context);
  m.Return(promise);

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  DirectHandle<Object> result =
      ft.Call(isolate->factory()->undefined_value()).ToHandleChecked();
  CHECK(IsJSPromise(*result));
}

TEST(NewJSPromise2) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  PromiseBuiltinsAssembler m(asm_tester.state());

  auto context = m.GetJSContextParameter();
  const TNode<JSPromise> promise =
      m.NewJSPromise(context, v8::Promise::kRejected, m.SmiConstant(1));
  m.Return(promise);

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  Handle<Object> result =
      ft.Call(isolate->factory()->undefined_value()).ToHandleChecked();
  CHECK(IsJSPromise(*result));
  DirectHandle<JSPromise> js_promise = Cast<JSPromise>(result);
  CHECK_EQ(v8::Promise::kRejected, js_promise->status());
  CHECK_EQ(Smi::FromInt(1), js_promise->result());
  CHECK(!js_promise->has_handler());
}

TEST(IsSymbol) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  auto symbol = m.Parameter<HeapObject>(1);
  m.Return(m.SelectBooleanConstant(m.IsSymbol(symbol)));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  DirectHandle<Object> result =
      ft.Call(isolate->factory()->NewSymbol()).ToHandleChecked();
  CHECK_EQ(ReadOnlyRoots(isolate).true_value(), *result);

  result = ft.Call(isolate->factory()->empty_string()).ToHandleChecked();
  CHECK_EQ(ReadOnlyRoots(isolate).false_value(), *result);
}

TEST(IsPrivateSymbol) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  auto symbol = m.Parameter<HeapObject>(1);
  m.Return(m.SelectBooleanConstant(m.IsPrivateSymbol(symbol)));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  DirectHandle<Object> result =
      ft.Call(isolate->factory()->NewSymbol()).ToHandleChecked();
  CHECK_EQ(ReadOnlyRoots(isolate).false_value(), *result);

  result = ft.Call(isolate->factory()->empty_string()).ToHandleChecked();
  CHECK_EQ(ReadOnlyRoots(isolate).false_value(), *result);

  result = ft.Call(isolate->factory()->NewPrivateSymbol()).ToHandleChecked();
  CHECK_EQ(ReadOnlyRoots(isolate).true_value(), *result);
}

TEST(PromiseHasHandler) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  PromiseBuiltinsAssembler m(asm_tester.state());

  auto context = m.GetJSContextParameter();
  const TNode<JSPromise> promise =
      m.NewJSPromise(context, m.UndefinedConstant());
  m.Return(m.SelectBooleanConstant(m.PromiseHasHandler(promise)));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  DirectHandle<Object> result =
      ft.Call(isolate->factory()->undefined_value()).ToHandleChecked();
  CHECK_EQ(ReadOnlyRoots(isolate).false_value(), *result);
}

TEST(CreatePromiseResolvingFunctionsContext) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  PromiseBuiltinsAssembler m(asm_tester.state());

  auto context = m.GetJSContextParameter();
  const TNode<NativeContext> native_context = m.LoadNativeContext(context);
  const TNode<JSPromise> promise =
      m.NewJSPromise(context, m.UndefinedConstant());
  const TNode<Context> promise_context =
      m.CreatePromiseResolvingFunctionsContext(
          context, promise, m.BooleanConstant(false), native_context);
  m.Return(promise_context);

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  Handle<Object> result = ft.Call().ToHandleChecked();
  CHECK(IsContext(*result));
  DirectHandle<Context> context_js = Cast<Context>(result);
  CHECK_EQ(isolate->root(RootIndex::kEmptyScopeInfo), context_js->scope_info());
  CHECK_EQ(*isolate->native_context(), context_js->native_context());
  CHECK(IsJSPromise(context_js->get(PromiseBuiltins::kPromiseSlot)));
  CHECK_EQ(ReadOnlyRoots(isolate).false_value(),
           context_js->get(PromiseBuiltins::kDebugEventSlot));
}

TEST(CreatePromiseResolvingFunctions) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  PromiseBuiltinsAssembler m(asm_tester.state());

  auto context = m.GetJSContextParameter();
  const TNode<NativeContext> native_context = m.LoadNativeContext(context);
  const TNode<JSPromise> promise =
      m.NewJSPromise(context, m.UndefinedConstant());
  PromiseResolvingFunctions funcs = m.CreatePromiseResolvingFunctions(
      context, promise, m.BooleanConstant(false), native_context);
  TNode<JSFunction> resolve = funcs.resolve;
  TNode<JSFunction> reject = funcs.reject;
  TNode<IntPtrT> const kSize = m.IntPtrConstant(2);
  TNode<FixedArray> const arr =
      m.Cast(m.AllocateFixedArray(PACKED_ELEMENTS, kSize));
  m.StoreFixedArrayElement(arr, 0, resolve);
  m.StoreFixedArrayElement(arr, 1, reject);
  m.Return(arr);

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  Handle<Object> result_obj =
      ft.Call(isolate->factory()->undefined_value()).ToHandleChecked();
  CHECK(IsFixedArray(*result_obj));
  DirectHandle<FixedArray> result_arr = Cast<FixedArray>(result_obj);
  CHECK(IsJSFunction(result_arr->get(0)));
  CHECK(IsJSFunction(result_arr->get(1)));
}

TEST(NewElementsCapacity) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());
  m.Return(m.SmiTag(
      m.CalculateNewElementsCapacity(m.SmiUntag(m.Parameter<Smi>(1)))));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  Handle<Smi> test_value = Handle<Smi>(Smi::FromInt(1), isolate);
  Tagged<Smi> result_obj = *ft.CallChecked<Smi>(test_value);
  CHECK_EQ(
      result_obj.value(),
      static_cast<int>(JSObject::NewElementsCapacity((*test_value).value())));
  test_value = Handle<Smi>(Smi::FromInt(1), isolate);
  result_obj = *ft.CallChecked<Smi>(test_value);
  CHECK_EQ(
      result_obj.value(),
      static_cast<int>(JSObject::NewElementsCapacity((*test_value).value())));
  test_value = Handle<Smi>(Smi::FromInt(2), isolate);
  result_obj = *ft.CallChecked<Smi>(test_value);
  CHECK_EQ(
      result_obj.value(),
      static_cast<int>(JSObject::NewElementsCapacity((*test_value).value())));
  test_value = Handle<Smi>(Smi::FromInt(1025), isolate);
  result_obj = *ft.CallChecked<Smi>(test_value);
  CHECK_EQ(
      result_obj.value(),
      static_cast<int>(JSObject::NewElementsCapacity((*test_value).value())));
}

TEST(NewElementsCapacitySmi) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());
  m.Return(m.CalculateNewElementsCapacity(m.UncheckedParameter<Smi>(1)));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  Handle<Smi> test_value = Handle<Smi>(Smi::FromInt(0), isolate);
  Tagged<Smi> result_obj = *ft.CallChecked<Smi>(test_value);
  CHECK_EQ(
      result_obj.value(),
      static_cast<int>(JSObject::NewElementsCapacity((*test_value).value())));
  test_value = Handle<Smi>(Smi::FromInt(1), isolate);
  result_obj = *ft.CallChecked<Smi>(test_value);
  CHECK_EQ(
      result_obj.value(),
      static_cast<int>(JSObject::NewElementsCapacity((*test_value).value())));
  test_value = Handle<Smi>(Smi::FromInt(2), isolate);
  result_obj = *ft.CallChecked<Smi>(test_value);
  CHECK_EQ(
      result_obj.value(),
      static_cast<int>(JSObject::NewElementsCapacity((*test_value).value())));
  test_value = Handle<Smi>(Smi::FromInt(1025), isolate);
  result_obj = *ft.CallChecked<Smi>(test_value);
  CHECK_EQ(
      result_obj.value(),
      static_cast<int>(JSObject::NewElementsCapacity((*test_value).value())));
}

TEST(AllocateRootFunctionWithContext) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  PromiseBuiltinsAssembler m(asm_tester.state());

  const auto context = m.GetJSContextParameter();
  const TNode<NativeContext> native_context = m.LoadNativeContext(context);
  const TNode<JSPromise> promise =
      m.NewJSPromise(context, m.UndefinedConstant());
  TNode<Context> promise_context = m.CreatePromiseResolvingFunctionsContext(
      context, promise, m.BooleanConstant(false), native_context);
  const TNode<JSFunction> resolve = m.AllocateRootFunctionWithContext(
      RootIndex::kPromiseCapabilityDefaultResolveSharedFun, promise_context,
      native_context);
  m.Return(resolve);

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  Handle<Object> result_obj =
      ft.Call(isolate->factory()->undefined_value()).ToHandleChecked();
  CHECK(IsJSFunction(*result_obj));
  DirectHandle<JSFunction> fun = Cast<JSFunction>(result_obj);
  CHECK_EQ(ReadOnlyRoots(isolate).empty_property_array(),
           fun->property_array());
  CHECK_EQ(ReadOnlyRoots(isolate).empty_fixed_array(), fun->elements());
  CHECK_EQ(isolate->heap()->many_closures_cell(), fun->raw_feedback_cell());
  CHECK(!fun->has_prototype_slot());
  CHECK_EQ(*isolate->factory()->promise_capability_default_resolve_shared_fun(),
           fun->shared());
  CHECK_EQ(isolate->factory()
               ->promise_capability_default_resolve_shared_fun()
               ->GetCode(isolate),
           fun->code(isolate));
}

TEST(CreatePromiseGetCapabilitiesExecutorContext) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  PromiseBuiltinsAssembler m(asm_tester.state());

  auto context = m.GetJSContextParameter();
  TNode<NativeContext> native_context = m.LoadNativeContext(context);

  TNode<PromiseCapability> capability = m.CreatePromiseCapability(
      m.UndefinedConstant(), m.UndefinedConstant(), m.UndefinedConstant());
  TNode<Context> executor_context =
      m.CreatePromiseCapabilitiesExecutorContext(native_context, capability);
  m.Return(executor_context);

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  Handle<Object> result_obj =
      ft.Call(isolate->factory()->undefined_value()).ToHandleChecked();
  CHECK(IsContext(*result_obj));
  DirectHandle<Context> context_js = Cast<Context>(result_obj);
  CHECK_EQ(PromiseBuiltins::kCapabilitiesContextLength, context_js->length());
  CHECK_EQ(isolate->root(RootIndex::kEmptyScopeInfo), context_js->scope_info());
  CHECK_EQ(*isolate->native_context(), context_js->native_context());
  CHECK(IsPromiseCapability(context_js->get(PromiseBuiltins::kCapabilitySlot)));
}

TEST(NewPromiseCapability) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  {  // Builtin Promise
    const int kNumParams = 0;
    CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
    PromiseBuiltinsAssembler m(asm_tester.state());

    auto context = m.GetJSContextParameter();
    const TNode<NativeContext> native_context = m.LoadNativeContext(context);
    const TNode<Object> promise_constructor =
        m.LoadContextElement(native_context, Context::PROMISE_FUNCTION_INDEX);

    const TNode<True> debug_event = m.TrueConstant();
    const TNode<Object> capability =
        m.CallBuiltin(Builtin::kNewPromiseCapability, context,
                      promise_constructor, debug_event);
    m.Return(capability);

    FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

    Handle<Object> result_obj = ft.Call().ToHandleChecked();
    CHECK(IsPromiseCapability(*result_obj));
    DirectHandle<PromiseCapability> result =
        Cast<PromiseCapability>(result_obj);

    CHECK(IsJSPromise(result->promise()));
    CHECK(IsJSFunction(result->resolve()));
    CHECK(IsJSFunction(result->reject()));
    CHECK_EQ(
        *isolate->factory()->promise_capability_default_reject_shared_fun(),
        Cast<JSFunction>(result->reject())->shared());
    CHECK_EQ(
        *isolate->factory()->promise_capability_default_resolve_shared_fun(),
        Cast<JSFunction>(result->resolve())->shared());

    Handle<JSFunction> callbacks[] = {
        handle(Cast<JSFunction>(result->resolve()), isolate),
        handle(Cast<JSFunction>(result->reject()), isolate)};

    for (auto&& callback : callbacks) {
      DirectHandle<Context> callback_context(Cast<Context>(callback->context()),
                                             isolate);
      CHECK_EQ(isolate->root(RootIndex::kEmptyScopeInfo),
               callback_context->scope_info());
      CHECK_EQ(*isolate->native_context(), callback_context->native_context());
      CHECK_EQ(PromiseBuiltins::kPromiseContextLength,
               callback_context->length());
      CHECK_EQ(callback_context->get(PromiseBuiltins::kPromiseSlot),
               result->promise());
    }
  }

  {  // Custom Promise
    const int kNumParams = 1;
    CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
    PromiseBuiltinsAssembler m(asm_tester.state());

    auto context = m.GetJSContextParameter();

    auto constructor = m.Parameter<Object>(1);
    const TNode<True> debug_event = m.TrueConstant();
    const TNode<Object> capability = m.CallBuiltin(
        Builtin::kNewPromiseCapability, context, constructor, debug_event);
    m.Return(capability);

    FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

    Handle<JSFunction> constructor_fn =
        Cast<JSFunction>(v8::Utils::OpenHandle(*CompileRun(
            "(function FakePromise(executor) {"
            "  var self = this;"
            "  function resolve(value) { self.resolvedValue = value; }"
            "  function reject(reason) { self.rejectedReason = reason; }"
            "  executor(resolve, reject);"
            "})")));

    Handle<Object> result_obj = ft.Call(constructor_fn).ToHandleChecked();
    CHECK(IsPromiseCapability(*result_obj));
    DirectHandle<PromiseCapability> result =
        Cast<PromiseCapability>(result_obj);

    CHECK(IsJSObject(result->promise()));
    Handle<JSObject> promise(Cast<JSObject>(result->promise()), isolate);
    CHECK_EQ(constructor_fn->prototype_or_initial_map(kAcquireLoad),
             promise->map());
    CHECK(IsJSFunction(result->resolve()));
    CHECK(IsJSFunction(result->reject()));

    Handle<String> resolved_str =
        isolate->factory()->NewStringFromAsciiChecked("resolvedStr");
    Handle<String> rejected_str =
        isolate->factory()->NewStringFromAsciiChecked("rejectedStr");

    Handle<Object> argv1[] = {resolved_str};
    DirectHandle<Object> ret =
        Execution::Call(isolate, handle(result->resolve(), isolate),
                        isolate->factory()->undefined_value(), 1, argv1)
            .ToHandleChecked();

    DirectHandle<Object> prop1 =
        JSReceiver::GetProperty(isolate, promise, "resolvedValue")
            .ToHandleChecked();
    CHECK_EQ(*resolved_str, *prop1);

    Handle<Object> argv2[] = {rejected_str};
    ret = Execution::Call(isolate, handle(result->reject(), isolate),
                          isolate->factory()->undefined_value(), 1, argv2)
              .ToHandleChecked();
    DirectHandle<Object> prop2 =
        JSReceiver::GetProperty(isolate, promise, "rejectedReason")
            .ToHandleChecked();
    CHECK_EQ(*rejected_str, *prop2);
  }
}

TEST(DirectMemoryTest8BitWord32Immediate) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());
  int8_t buffer[] = {1, 2, 4, 8, 17, 33, 65, 127};
  const int element_count = 8;
  Label bad(&m);

  TNode<RawPtrT> buffer_node = m.PointerConstant(buffer);
  for (size_t i = 0; i < element_count; ++i) {
    for (size_t j = 0; j < element_count; ++j) {
      TNode<Uint8T> loaded =
          m.LoadBufferData<Uint8T>(buffer_node, static_cast<int>(i));
      TNode<Word32T> masked = m.Word32And(loaded, m.Int32Constant(buffer[j]));
      if ((buffer[j] & buffer[i]) != 0) {
        m.GotoIf(m.Word32Equal(masked, m.Int32Constant(0)), &bad);
      } else {
        m.GotoIf(m.Word32NotEqual(masked, m.Int32Constant(0)), &bad);
      }
    }
  }

  m.Return(m.SmiConstant(1));

  m.BIND(&bad);
  m.Return(m.SmiConstant(0));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  CHECK_EQ(1, (*ft.CallChecked<Smi>()).value());
}

TEST(DirectMemoryTest16BitWord32Immediate) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());
  int16_t buffer[] = {156, 2234, 4544, 8444, 1723, 3888, 658, 1278};
  const int element_count = 8;
  Label bad(&m);

  TNode<RawPtrT> buffer_node = m.PointerConstant(buffer);
  for (size_t i = 0; i < element_count; ++i) {
    for (size_t j = 0; j < element_count; ++j) {
      TNode<Uint16T> loaded = m.LoadBufferData<Uint16T>(
          buffer_node, static_cast<int>(i * sizeof(int16_t)));
      TNode<Word32T> masked = m.Word32And(loaded, m.Int32Constant(buffer[j]));
      if ((buffer[j] & buffer[i]) != 0) {
        m.GotoIf(m.Word32Equal(masked, m.Int32Constant(0)), &bad);
      } else {
        m.GotoIf(m.Word32NotEqual(masked, m.Int32Constant(0)), &bad);
      }
    }
  }

  m.Return(m.SmiConstant(1));

  m.BIND(&bad);
  m.Return(m.SmiConstant(0));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  CHECK_EQ(1, (*ft.CallChecked<Smi>()).value());
}

TEST(DirectMemoryTest8BitWord32) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());
  int8_t buffer[] = {1, 2, 4, 8, 17, 33, 65, 127, 67, 38};
  const int element_count = 10;
  Label bad(&m);
  TNode<Uint32T> constants[element_count];

  TNode<RawPtrT> buffer_node = m.PointerConstant(buffer);
  for (size_t i = 0; i < element_count; ++i) {
    constants[i] = m.LoadBufferData<Uint8T>(buffer_node, static_cast<int>(i));
  }

  for (size_t i = 0; i < element_count; ++i) {
    for (size_t j = 0; j < element_count; ++j) {
      TNode<Uint8T> loaded =
          m.LoadBufferData<Uint8T>(buffer_node, static_cast<int>(i));
      TNode<Word32T> masked = m.Word32And(loaded, constants[j]);
      if ((buffer[j] & buffer[i]) != 0) {
        m.GotoIf(m.Word32Equal(masked, m.Int32Constant(0)), &bad);
      } else {
        m.GotoIf(m.Word32NotEqual(masked, m.Int32Constant(0)), &bad);
      }

      masked = m.Word32And(constants[i], constants[j]);
      if ((buffer[j] & buffer[i]) != 0) {
        m.GotoIf(m.Word32Equal(masked, m.Int32Constant(0)), &bad);
      } else {
        m.GotoIf(m.Word32NotEqual(masked, m.Int32Constant(0)), &bad);
      }
    }
  }

  m.Return(m.SmiConstant(1));

  m.BIND(&bad);
  m.Return(m.SmiConstant(0));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  CHECK_EQ(1, (*ft.CallChecked<Smi>()).value());
}

TEST(DirectMemoryTest16BitWord32) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());
  int16_t buffer[] = {1, 2, 4, 8, 12345, 33, 65, 255, 67, 3823};
  const int element_count = 10;
  Label bad(&m);
  TNode<Uint32T> constants[element_count];

  TNode<RawPtrT> buffer_node1 = m.PointerConstant(buffer);
  for (size_t i = 0; i < element_count; ++i) {
    constants[i] = m.LoadBufferData<Uint16T>(
        buffer_node1, static_cast<int>(i * sizeof(int16_t)));
  }
  TNode<RawPtrT> buffer_node2 = m.PointerConstant(buffer);

  for (size_t i = 0; i < element_count; ++i) {
    for (size_t j = 0; j < element_count; ++j) {
      TNode<Uint16T> loaded = m.LoadBufferData<Uint16T>(
          buffer_node1, static_cast<int>(i * sizeof(int16_t)));
      TNode<Word32T> masked = m.Word32And(loaded, constants[j]);
      if ((buffer[j] & buffer[i]) != 0) {
        m.GotoIf(m.Word32Equal(masked, m.Int32Constant(0)), &bad);
      } else {
        m.GotoIf(m.Word32NotEqual(masked, m.Int32Constant(0)), &bad);
      }

      // Force a memory access relative to a high-number register.
      loaded = m.LoadBufferData<Uint16T>(buffer_node2,
                                         static_cast<int>(i * sizeof(int16_t)));
      masked = m.Word32And(loaded, constants[j]);
      if ((buffer[j] & buffer[i]) != 0) {
        m.GotoIf(m.Word32Equal(masked, m.Int32Constant(0)), &bad);
      } else {
        m.GotoIf(m.Word32NotEqual(masked, m.Int32Constant(0)), &bad);
      }

      masked = m.Word32And(constants[i], constants[j]);
      if ((buffer[j] & buffer[i]) != 0) {
        m.GotoIf(m.Word32Equal(masked, m.Int32Constant(0)), &bad);
      } else {
        m.GotoIf(m.Word32NotEqual(masked, m.Int32Constant(0)), &bad);
      }
    }
  }

  m.Return(m.SmiConstant(1));

  m.BIND(&bad);
  m.Return(m.SmiConstant(0));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  CHECK_EQ(1, (*ft.CallChecked<Smi>()).value());
}

TEST(LoadJSArrayElementsMap) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  {
    CodeStubAssembler m(asm_tester.state());
    auto context = m.GetJSContextParameter();
    TNode<NativeContext> native_context = m.LoadNativeContext(context);
    TNode<Int32T> kind = m.SmiToInt32(m.Parameter<Smi>(1));
    m.Return(m.LoadJSArrayElementsMap(kind, native_context));
  }

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  for (int kind = 0; kind <= HOLEY_DOUBLE_ELEMENTS; kind++) {
    DirectHandle<Map> csa_result =
        ft.CallChecked<Map>(handle(Smi::FromInt(kind), isolate));
    ElementsKind elements_kind = static_cast<ElementsKind>(kind);
    DirectHandle<Map> result(
        isolate->native_context()->GetInitialJSArrayMap(elements_kind),
        isolate);
    CHECK_EQ(*csa_result, *result);
  }
}

TEST(IsWhiteSpaceOrLineTerminator) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));

  {  // Returns true if whitespace, false otherwise.
    CodeStubAssembler m(asm_tester.state());
    Label if_true(&m), if_false(&m);
    m.Branch(m.IsWhiteSpaceOrLineTerminator(
                 m.UncheckedCast<Uint16T>(m.SmiToInt32(m.Parameter<Smi>(1)))),
             &if_true, &if_false);
    m.BIND(&if_true);
    m.Return(m.TrueConstant());
    m.BIND(&if_false);
    m.Return(m.FalseConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  Handle<Object> true_value = ft.true_value();
  Handle<Object> false_value = ft.false_value();

  for (base::uc16 c = 0; c < 0xFFFF; c++) {
    DirectHandle<Object> expected_value =
        IsWhiteSpaceOrLineTerminator(c) ? true_value : false_value;
    ft.CheckCall(expected_value, handle(Smi::FromInt(c), isolate));
  }
}

TEST(BranchIfNumberRelationalComparison) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  Factory* f = isolate->factory();
  const int kNumParams = 2;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  {
    CodeStubAssembler m(asm_tester.state());
    Label return_true(&m), return_false(&m);
    m.BranchIfNumberRelationalComparison(
        Operation::kGreaterThanOrEqual, m.Parameter<Number>(1),
        m.Parameter<Number>(2), &return_true, &return_false);
    m.BIND(&return_true);
    m.Return(m.BooleanConstant(true));
    m.BIND(&return_false);
    m.Return(m.BooleanConstant(false));
  }

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  ft.CheckTrue(f->NewNumber(0), f->NewNumber(0));
  ft.CheckTrue(f->NewNumber(1), f->NewNumber(0));
  ft.CheckTrue(f->NewNumber(1), f->NewNumber(1));
  ft.CheckFalse(f->NewNumber(0), f->NewNumber(1));
  ft.CheckFalse(f->NewNumber(-1), f->NewNumber(0));
  ft.CheckTrue(f->NewNumber(-1), f->NewNumber(-1));

  ft.CheckTrue(f->NewNumber(-1), f->NewNumber(-1.5));
  ft.CheckFalse(f->NewNumber(-1.5), f->NewNumber(-1));
  ft.CheckTrue(f->NewNumber(-1.5), f->NewNumber(-1.5));
}

TEST(IsNumberArrayIndex) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  {
    CodeStubAssembler m(asm_tester.state());
    auto number = m.Parameter<Number>(1);
    m.Return(
        m.SmiFromInt32(m.UncheckedCast<Int32T>(m.IsNumberArrayIndex(number))));
  }

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  double indices[] = {Smi::kMinValue,
                      -11,
                      -1,
                      0,
                      1,
                      2,
                      Smi::kMaxValue,
                      -11.0,
                      -11.1,
                      -2.0,
                      -1.0,
                      -0.0,
                      0.0,
                      0.00001,
                      0.1,
                      1,
                      2,
                      Smi::kMinValue - 1.0,
                      Smi::kMinValue + 1.0,
                      Smi::kMinValue + 1.2,
                      kMaxInt + 1.2,
                      kMaxInt - 10.0,
                      kMaxInt - 1.0,
                      kMaxInt,
                      kMaxInt + 1.0,
                      kMaxInt + 10.0};

  for (size_t i = 0; i < arraysize(indices); i++) {
    Handle<Object> index = isolate->factory()->NewNumber(indices[i]);
    uint32_t array_index;
    CHECK_EQ(Object::ToArrayIndex(*index, &array_index),
             ((*ft.CallChecked<Smi>(index)).value() == 1));
  }
}

TEST(NumberMinMax) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 2;
  CodeAssemblerTester asm_tester_min(isolate, JSParameterCount(kNumParams));
  {
    CodeStubAssembler m(asm_tester_min.state());
    m.Return(m.NumberMin(m.Parameter<Number>(1), m.Parameter<Number>(2)));
  }
  FunctionTester ft_min(asm_tester_min.GenerateCode(), kNumParams);

  CodeAssemblerTester asm_tester_max(isolate, JSParameterCount(kNumParams));
  {
    CodeStubAssembler m(asm_tester_max.state());
    m.Return(m.NumberMax(m.Parameter<Number>(1), m.Parameter<Number>(2)));
  }
  FunctionTester ft_max(asm_tester_max.GenerateCode(), kNumParams);

  // Test smi values.
  Handle<Smi> smi_1(Smi::FromInt(1), isolate);
  Handle<Smi> smi_2(Smi::FromInt(2), isolate);
  Handle<Smi> smi_5(Smi::FromInt(5), isolate);
  CHECK_EQ((*ft_min.CallChecked<Smi>(smi_1, smi_2)).value(), 1);
  CHECK_EQ((*ft_min.CallChecked<Smi>(smi_2, smi_1)).value(), 1);
  CHECK_EQ((*ft_max.CallChecked<Smi>(smi_1, smi_2)).value(), 2);
  CHECK_EQ((*ft_max.CallChecked<Smi>(smi_2, smi_1)).value(), 2);

  // Test double values.
  Handle<Object> double_a = isolate->factory()->NewNumber(2.5);
  Handle<Object> double_b = isolate->factory()->NewNumber(3.5);
  Handle<Object> nan =
      isolate->factory()->NewNumber(std::numeric_limits<double>::quiet_NaN());
  Handle<Object> infinity = isolate->factory()->NewNumber(V8_INFINITY);

  CHECK_EQ(ft_min.CallChecked<HeapNumber>(double_a, double_b)->value(), 2.5);
  CHECK_EQ(ft_min.CallChecked<HeapNumber>(double_b, double_a)->value(), 2.5);
  CHECK_EQ(ft_min.CallChecked<HeapNumber>(infinity, double_a)->value(), 2.5);
  CHECK_EQ(ft_min.CallChecked<HeapNumber>(double_a, infinity)->value(), 2.5);
  CHECK(std::isnan(ft_min.CallChecked<HeapNumber>(nan, double_a)->value()));
  CHECK(std::isnan(ft_min.CallChecked<HeapNumber>(double_a, nan)->value()));

  CHECK_EQ(ft_max.CallChecked<HeapNumber>(double_a, double_b)->value(), 3.5);
  CHECK_EQ(ft_max.CallChecked<HeapNumber>(double_b, double_a)->value(), 3.5);
  CHECK_EQ(ft_max.CallChecked<HeapNumber>(infinity, double_a)->value(),
           V8_INFINITY);
  CHECK_EQ(ft_max.CallChecked<HeapNumber>(double_a, infinity)->value(),
           V8_INFINITY);
  CHECK(std::isnan(ft_max.CallChecked<HeapNumber>(nan, double_a)->value()));
  CHECK(std::isnan(ft_max.CallChecked<HeapNumber>(double_a, nan)->va
"""


```