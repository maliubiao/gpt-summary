Response: The user wants me to summarize the functionality of the C++ code in `v8/test/cctest/test-api.cc`, specifically part 17 of 18.

The code seems to be testing the V8 C++ API, focusing on how C++ functions can be called from JavaScript, especially the "fast API calls" feature.

Here's a breakdown of the code snippets:

1. **`ReturnValueChecker`**:  Checks if a fast or slow callback was executed. This is used to verify if the fast path for API calls is taken.
2. **`AllocationChecker`**:  Verifies fast API calls work even when there's memory allocation and garbage collection within the C++ callback. It checks if the allocation happens correctly from C++ or when triggered by JavaScript (`gc()`).
3. **`ThrowInReentrantJSChecker`**:  Checks how exceptions thrown from within a fast API callback are handled in JavaScript.
4. **`CheckFastReturnValue`**: A helper function to set up a test and verify if a fast API call returns the expected value.
5. **`CallAndDeopt`**:  Tests if calling a fast API function with an incompatible argument type (causing deoptimization) works correctly.
6. **`CallNoOptions`**: Tests fast API calls without specifying any special options.
7. **`CallNoConvertReceiver`**: Tests fast API calls where the receiver object isn't automatically converted.
8. **`CallWithLessArguments`, `CallWithMoreArguments`**: Tests if fast API calls are bypassed when the number of arguments is incorrect.
9. **`FastApiCallWithAllocationAndGC` tests**: Specific tests for allocation and garbage collection within fast API calls, triggered either from C++ or JavaScript.
10. **`FastApiCallWithThrowInReentrantCode` test**:  Specifically tests the case where an exception is thrown from a fast API call that re-enters JavaScript.
11. **`RecursiveReentrantJSChecker` and `FastApiCallRecursion` tests**:  Tests how fast API calls handle recursive calls back into JavaScript, including cases with and without exceptions.
12. **`CallWithUnexpectedReceiverType`, `CallWithUnexpectedObjectType`**: Tests how fast API calls behave when the receiver object or an object argument has an unexpected type.
13. **`TestCFunctionInfo` and `CheckDynamicTypeInfo`**:  Deals with inspecting the type information of C++ functions used for fast API calls.
14. **`FastApiStackSlot` test**: Tests the interaction of fast API calls with stack slots, possibly related to optimization and on-stack replacement (OSR).
15. **`FastApiCalls` test**: A comprehensive test suite covering various scenarios for fast API calls with different data types (integers, floats, booleans), including boundary conditions, type mismatches, and return values.
16. **`SeqOneByteStringChecker` and `FastApiCallsString` test**: Tests fast API calls with `v8::FastOneByteString` arguments, focusing on handling different string encodings.
17. **`FastApiCallsFromWasm` test**: Tests fast API calls originating from WebAssembly code.
18. **`FastApiOverloadResolution` test**:  Tests how V8 resolves overloaded C++ functions for fast API calls.
19. **`Recorder_GetContext` test**: Tests the functionality for retrieving V8 contexts using their IDs, likely related to performance monitoring or debugging.
20. **`MetricsRecorder` and `TriggerMainThreadMetricsEvent`, `TriggerDelayedMainThreadMetricsEvent`, `TriggerThreadSafeMetricsEvent` tests**: Tests the V8 metrics recording system, specifically how events from the main thread and other threads are captured.
21. **`SetupCodeLike`**: A helper function likely used to set up JavaScript objects that mimic code-like structures, possibly for testing source code information.

Considering this is part 17 of 18, the code is likely wrapping up more advanced or specific test cases. The inclusion of WebAssembly and metrics recording suggests a focus on integration and performance aspects.
这个C++源代码文件 (`v8/test/cctest/test-api.cc`) 的第 17 部分主要关注 **V8 引擎的快速 API 调用 (Fast API Calls) 功能的测试，并涉及到 WebAssembly 的集成以及 V8 的性能指标记录功能。**

具体来说，这部分代码涵盖了以下功能测试：

1. **快速 API 调用与字符串参数：**  测试 C++ 函数作为快速 API 被 JavaScript 调用时，如何处理 `v8::FastOneByteString` 类型的字符串参数，以及不同返回值类型的 C++ 函数在这种场景下的工作情况。

2. **从 WebAssembly 调用快速 API：**  验证 WebAssembly 模块能否正确地调用通过快速 API 机制暴露的 C++ 函数。

3. **快速 API 调用的重载解析：**  测试 V8 引擎如何解析和选择正确的重载 C++ 函数，当多个 C++ 函数具有相同的名字但不同的参数类型时。

4. **V8 上下文 (Context) 及其 ID 的管理：**  测试 `v8::metrics::Recorder::GetContextId` 和 `v8::metrics::Recorder::GetContext` 功能，用于获取和管理 V8 上下文的唯一标识符。这对于性能分析和监控非常重要。

5. **V8 性能指标记录：**  测试 V8 引擎的性能指标记录功能，例如 `v8::metrics::WasmModuleDecoded` 和 `v8::metrics::WasmModulesPerIsolate` 事件的触发和记录。这包括在主线程和非主线程中记录事件，以及延迟记录事件的测试。

6. **设置类似代码的对象：** 提供了一个 `SetupCodeLike` 函数，用于在 JavaScript 中创建类似代码结构的对象，可能用于测试与代码结构相关的 API 功能。

**与 JavaScript 的关系和示例说明：**

快速 API 调用是 V8 提供的一种优化机制，允许 JavaScript 代码高效地调用 C++ 函数。通过 `v8::FunctionTemplate::SetCallHandler` 等 API 设置 C++ 函数作为回调，并使用 `v8::FastApiCallbackOptions` 等配置选项，V8 可以尝试优化这些调用路径，避免通常的 JavaScript 函数调用开销。

**JavaScript 示例：**

假设我们在 C++ 中定义了一个函数 `MultiplyByTwo`，它接收一个整数并返回其两倍的值，并将其注册为快速 API：

```c++
// C++ 代码
#include <v8.h>

using namespace v8;

void MultiplyByTwo(const FunctionCallbackInfo<Value>& info) {
  Isolate* isolate = info.GetIsolate();
  Local<Context> context = isolate->GetCurrentContext();

  if (info.Length() < 1 || !info[0]->IsInt32()) {
    isolate->ThrowException(
        String::NewFromUtf8Literal(isolate, "Invalid argument"));
    return;
  }

  int32_t num = info[0]->Int32Value(context).FromJust();
  int32_t result = num * 2;
  info.GetReturnValue().Set(Int32::New(isolate, result));
}

// ... 在初始化 V8 时注册 MultiplyByTwo 作为快速 API ...
Local<FunctionTemplate> tpl = FunctionTemplate::New(isolate, MultiplyByTwo);
// ... 设置快速 API 回调选项 ...
```

现在，在 JavaScript 中，我们可以调用这个 C++ 函数，V8 可能会选择快速 API 调用路径：

```javascript
// JavaScript 代码
function callMultiply(x) {
  return MultiplyByTwo(x); // 假设 C++ 函数被绑定到全局对象 MultiplyByTwo
}

console.log(callMultiply(5)); // 输出 10

// 触发优化，使后续调用更有可能走快速路径
%PrepareFunctionForOptimization(callMultiply);
callMultiply(10);
%OptimizeFunctionOnNextCall(callMultiply);
console.log(callMultiply(15)); // 更有可能通过快速 API 调用
```

在这个例子中，`MultiplyByTwo` 是在 C++ 中实现的，并通过 V8 的 API 暴露给 JavaScript。`callMultiply` 函数在 JavaScript 中调用 `MultiplyByTwo`。V8 引擎会尝试优化 `callMultiply` 的执行，如果满足条件，就会使用快速 API 调用机制来执行对 C++ `MultiplyByTwo` 函数的调用，从而提高性能。

总而言之，这个代码文件的第 17 部分深入测试了 V8 引擎中一些高级和重要的功能，特别是快速 API 调用及其与 WebAssembly 的集成，以及 V8 的性能监控能力。这些功能对于构建高性能的 JavaScript 应用和嵌入 V8 引擎的项目至关重要。

### 提示词
```
这是目录为v8/test/cctest/test-api.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第17部分，共18部分，请归纳一下它的功能
```

### 源代码
```
> receiver, T arg,
                        v8::FastApiCallbackOptions& options) {
    ReturnValueChecker<T>* receiver_ptr =
        GetInternalField<ReturnValueChecker<T>>(*receiver);
    receiver_ptr->SetCallFast();
    return arg;
  }

  static void SlowCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
    CHECK(i::ValidateCallbackInfo(info));
    v8::Object* receiver_obj =
        v8::Object::Cast(*info.HolderSoonToBeDeprecated());
    ReturnValueChecker<T>* receiver_ptr =
        GetInternalField<ReturnValueChecker<T>>(receiver_obj);
    receiver_ptr->SetCallSlow();
    info.GetReturnValue().Set(info[0]);
  }
};

struct AllocationChecker : BasicApiChecker<int32_t, AllocationChecker, void> {
  enum GCLocation {
    kFromC,
    kFromJS,
  };

  explicit AllocationChecker(i::Isolate* isolate, int32_t expected_argument,
                             GCLocation gc_location,
                             v8::Local<v8::Context> context)
      : isolate_(isolate),
        expected_argument_(expected_argument),
        gc_location_(gc_location),
        context_(context) {}

  static void FastCallback(v8::Local<v8::Object> receiver, int32_t argument,
                           v8::FastApiCallbackOptions& options) {
    AllocationChecker* receiver_ptr =
        GetInternalField<AllocationChecker>(*receiver);
    CHECK_EQ(receiver_ptr->expected_argument_, argument);
    receiver_ptr->SetCallFast();
    i::Isolate* isolate = receiver_ptr->isolate_;
    i::HandleScope handle_scope(isolate);
    i::DirectHandle<i::HeapNumber> number =
        isolate->factory()->NewHeapNumber(argument);
    if (receiver_ptr->gc_location_ == kFromC) {
      isolate->heap()->CollectGarbage(i::OLD_SPACE,
                                      i::GarbageCollectionReason::kTesting);
    } else {
      v8::Context::Scope context_scope(receiver_ptr->context_);
      CompileRun("gc();");
    }
    CHECK_EQ(receiver_ptr, GetInternalField<AllocationChecker>(*receiver));
    CHECK_EQ(receiver_ptr->expected_argument_, number->value());
  }

  static void SlowCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
    CHECK(i::ValidateCallbackInfo(info));
    v8::Object* receiver_obj =
        v8::Object::Cast(*info.HolderSoonToBeDeprecated());
    AllocationChecker* receiver_ptr =
        GetInternalField<AllocationChecker>(receiver_obj);
    receiver_ptr->SetCallSlow();
    info.GetReturnValue().Set(info[0]);
  }

 private:
  i::Isolate* isolate_;
  int32_t expected_argument_;
  GCLocation gc_location_;
  v8::Local<v8::Context> context_;
};

struct ThrowInReentrantJSChecker
    : BasicApiChecker<int32_t, ThrowInReentrantJSChecker, void> {
  explicit ThrowInReentrantJSChecker(i::Isolate* isolate,
                                     v8::Local<v8::Context> context)
      : isolate_(isolate), context_(context) {}

  static void FastCallback(v8::Local<v8::Object> receiver, int32_t argument,
                           v8::FastApiCallbackOptions& options) {
    ThrowInReentrantJSChecker* receiver_ptr =
        GetInternalField<ThrowInReentrantJSChecker>(*receiver);
    receiver_ptr->SetCallFast();
    i::Isolate* isolate = receiver_ptr->isolate_;
    i::HandleScope handle_scope(isolate);
    v8::Context::Scope context_scope(receiver_ptr->context_);
    CompileRun("throw 'FastCallback exception';");
  }

  static void SlowCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
    CHECK(i::ValidateCallbackInfo(info));
    v8::Object* receiver_obj =
        v8::Object::Cast(*info.HolderSoonToBeDeprecated());
    ThrowInReentrantJSChecker* receiver_ptr =
        GetInternalField<ThrowInReentrantJSChecker>(receiver_obj);
    receiver_ptr->SetCallSlow();
    v8::Isolate* isolate = info.GetIsolate();
    v8::HandleScope handle_scope(isolate);
    v8::Context::Scope context_scope(receiver_ptr->context_);
    info.GetReturnValue().Set(isolate->ThrowException(
        v8::String::NewFromUtf8(isolate, "SlowCallback exception")
            .ToLocalChecked()));
  }

 private:
  i::Isolate* isolate_;
  v8::Local<v8::Context> context_;
};

template <typename T>
void CheckFastReturnValue(v8::Local<v8::Value> expected_value,
                          ApiCheckerResultFlags expected_path) {
  LocalContext env;
  ReturnValueChecker<T> checker{};

  bool has_caught = SetupTest<T, ReturnValueChecker<T>, T>(
      expected_value, &env, &checker,
      "function func(arg) { return receiver.api_func(arg); }"
      "%PrepareFunctionForOptimization(func);"
      "func(value);");
  CHECK(!has_caught);
  checker.Reset();

  v8::Isolate* isolate = CcTest::isolate();
  v8::TryCatch try_catch(isolate);
  v8::Local<v8::Value> result = CompileRun(
      "%OptimizeFunctionOnNextCall(func);"
      "func(value);");

  CHECK_EQ(expected_path == ApiCheckerResult::kSlowCalled,
           !checker.DidCallFast());
  CHECK_EQ(expected_path == ApiCheckerResult::kFastCalled,
           !checker.DidCallSlow());
  CHECK(checker.DidCallFast() || checker.DidCallSlow());

  CHECK(result->SameValue(expected_value));
}

void CallAndDeopt() {
  LocalContext env;
  v8::Local<v8::Value> initial_value(v8_num(42));
  ApiNumberChecker<int32_t> checker(42);
  SetupTest(initial_value, &env, &checker,
            "function func(arg) { return receiver.api_func(arg); }"
            "%PrepareFunctionForOptimization(func);"
            "func(value);"
            "%OptimizeFunctionOnNextCall(func);"
            "func(value);");

  v8::Local<v8::Value> function = CompileRun(
      "try { func(BigInt(42)); } catch(e) {}"
      "%PrepareFunctionForOptimization(func);"
      "%OptimizeFunctionOnNextCall(func);"
      "func(value);"
      "func;");
  CHECK(function->IsFunction());
  i::DirectHandle<i::JSFunction> ifunction =
      i::Cast<i::JSFunction>(v8::Utils::OpenDirectHandle(*function));
  CHECK(ifunction->HasAttachedOptimizedCode(CcTest::i_isolate()));
}

void CallNoOptions(int32_t expected_value) {
  LocalContext env;
  v8::Local<v8::Value> initial_value(v8_num(42));
  ApiNumberChecker<int32_t> checker(expected_value, Behavior::kNoException);
  SetupTest(initial_value, &env, &checker,
            "function func(arg) { return receiver.api_func(arg); }"
            "%PrepareFunctionForOptimization(func);"
            "func(value);"
            "%OptimizeFunctionOnNextCall(func);"
            "func(value);",
            false);

  CHECK(checker.DidCallFast());
  CHECK_EQ(checker.fast_value_, expected_value);
}

void CallNoConvertReceiver(int32_t expected_value) {
  LocalContext env;
  v8::Local<v8::Value> initial_value(v8_num(42));
  ApiNumberChecker<int32_t> checker(expected_value, Behavior::kNoException);
  SetupTest(initial_value, &env, &checker,
            "function func(arg) { return receiver.api_func(arg); }"
            "%PrepareFunctionForOptimization(func);"
            "func(value);"
            "%OptimizeFunctionOnNextCall(func);"
            "func(value);",
            true, false);

  CHECK(checker.DidCallFast());
  CHECK_EQ(checker.fast_value_, expected_value);
}

void CallWithLessArguments() {
  LocalContext env;
  v8::Local<v8::Value> initial_value(v8_num(42));
  ApiNumberChecker<int32_t> checker(42, Behavior::kNoException, 0);
  SetupTest(initial_value, &env, &checker,
            "function func() { return receiver.api_func(); }"
            "%PrepareFunctionForOptimization(func);"
            "func();"
            "%OptimizeFunctionOnNextCall(func);"
            "func();");

  // Passing not enough arguments should not go through the fast path.
  CHECK(checker.DidCallSlow());
}

void CallWithMoreArguments() {
  LocalContext env;
  v8::Local<v8::Value> initial_value(v8_num(42));
  ApiNumberChecker<int32_t> checker(42, Behavior::kNoException, 2);
  SetupTest(initial_value, &env, &checker,
            "function func(arg) { receiver.api_func(arg, arg); }"
            "%PrepareFunctionForOptimization(func);"
            "func(value);"
            "%OptimizeFunctionOnNextCall(func);"
            "func(value);");

  // Passing too many arguments should result in a regular call.
  CHECK(checker.DidCallSlow());
}

namespace {
void FastApiCallWithAllocationAndGC(AllocationChecker::GCLocation gc_location) {
  if (i::v8_flags.jitless) return;
  if (i::v8_flags.disable_optimizing_compilers) return;

  i::v8_flags.turbofan = true;
  i::v8_flags.turbo_fast_api_calls = true;
  i::v8_flags.allow_natives_syntax = true;
  // Disable --always_turbofan, otherwise we haven't generated the necessary
  // feedback to go down the "best optimization" path for the fast call.
  i::v8_flags.always_turbofan = false;
  i::v8_flags.allow_allocation_in_fast_api_call = true;
  i::v8_flags.expose_gc = true;
  i::FlagList::EnforceFlagImplications();

  CcTest::InitializeVM();
  v8::Isolate* isolate = CcTest::isolate();

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  i_isolate->set_embedder_wrapper_type_index(kV8WrapperTypeIndex);
  i_isolate->set_embedder_wrapper_object_index(kV8WrapperObjectIndex);

  v8::HandleScope scope(isolate);

  LocalContext env;
  v8::Local<v8::Value> initial_value(v8_num(42));
  AllocationChecker checker(i_isolate, 42, gc_location,
                            isolate->GetCurrentContext());
  SetupTest(initial_value, &env, &checker,
            "function func(arg) { receiver.api_func(arg); }"
            "function wrapper(){"
            "%PrepareFunctionForOptimization(func);"
            "func(value);"
            "%OptimizeFunctionOnNextCall(func);"
            "func(value);"
            "}wrapper(value);");

  CHECK(checker.DidCallFast());
}
}  // namespace

TEST(FastApiCallWithAllocationAndGCInC) {
  FastApiCallWithAllocationAndGC(AllocationChecker::GCLocation::kFromC);
}

TEST(FastApiCallWithAllocationAndGCInJS) {
  FastApiCallWithAllocationAndGC(AllocationChecker::GCLocation::kFromJS);
}

TEST(FastApiCallWithThrowInReentrantCode) {
  if (i::v8_flags.jitless) return;
  if (i::v8_flags.disable_optimizing_compilers) return;

  i::v8_flags.turbofan = true;
  i::v8_flags.turbo_fast_api_calls = true;
  i::v8_flags.allow_natives_syntax = true;
  // Disable --always_turbofan, otherwise we haven't generated the necessary
  // feedback to go down the "best optimization" path for the fast call.
  i::v8_flags.always_turbofan = false;
  i::v8_flags.allow_allocation_in_fast_api_call = true;
  i::FlagList::EnforceFlagImplications();

  CcTest::InitializeVM();
  v8::Isolate* isolate = CcTest::isolate();

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  i_isolate->set_embedder_wrapper_type_index(kV8WrapperTypeIndex);
  i_isolate->set_embedder_wrapper_object_index(kV8WrapperObjectIndex);

  v8::HandleScope scope(isolate);

  LocalContext env;
  v8::Local<v8::Value> initial_value(v8_num(42));
  ThrowInReentrantJSChecker checker(i_isolate, env.local());
  bool result = SetupTest(initial_value, &env, &checker,
                          "function func(arg) {"
                          "  try {"
                          "    receiver.api_func(arg);"
                          "    return false;"
                          "  } catch(e) { return true;}"
                          "}"
                          "function wrapper(){"
                          "%PrepareFunctionForOptimization(func);"
                          "func(value);"
                          "%OptimizeFunctionOnNextCall(func);"
                          "if (func(value)) throw 'exception happened';"
                          "}wrapper(value);");
  CHECK(result);
  CHECK(checker.DidCallFast());
}

namespace {
void DoFastReentrantCall(i::Isolate* i_isolate, LocalContext* env, int* sum,
                         int value, bool inner_most_throws);

struct RecursiveReentrantJSChecker
    : BasicApiChecker<int32_t, RecursiveReentrantJSChecker, void> {
  RecursiveReentrantJSChecker(i::Isolate* isolate, LocalContext* env, int* sum,
                              bool inner_most_throws)
      : isolate_(isolate),
        env_(env),
        sum_(sum),
        inner_most_throws_(inner_most_throws) {}

  static void FastCallback(v8::Local<v8::Object> receiver, int32_t argument,
                           v8::FastApiCallbackOptions& options) {
    RecursiveReentrantJSChecker* receiver_ptr =
        GetInternalField<RecursiveReentrantJSChecker>(*receiver);
    receiver_ptr->SetCallFast();
    *(receiver_ptr->sum_) += argument;
    i::Isolate* isolate = receiver_ptr->isolate_;
    i::HandleScope handle_scope(isolate);
    v8::Context::Scope context_scope(receiver_ptr->env_->local());
    if (argument > 1) {
      DoFastReentrantCall(receiver_ptr->isolate_, receiver_ptr->env_,
                          receiver_ptr->sum_, argument - 1,
                          receiver_ptr->inner_most_throws_);
      if (receiver_ptr->isolate_->has_exception()) return;
    } else if (receiver_ptr->inner_most_throws_) {
      reinterpret_cast<v8::Isolate*>(receiver_ptr->isolate_)
          ->ThrowError("Throw exception");
    }
  }

  static void SlowCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
    CHECK(i::ValidateCallbackInfo(info));
    v8::Object* receiver_obj =
        v8::Object::Cast(*info.HolderSoonToBeDeprecated());
    RecursiveReentrantJSChecker* receiver_ptr =
        GetInternalField<RecursiveReentrantJSChecker>(receiver_obj);
    receiver_ptr->SetCallSlow();
    v8::Isolate* isolate = info.GetIsolate();
    v8::HandleScope handle_scope(isolate);
    v8::Context::Scope context_scope(receiver_ptr->env_->local());
    info.GetReturnValue().Set(v8_num(0));
  }

 private:
  i::Isolate* isolate_;
  LocalContext* env_;
  int* sum_;
  bool inner_most_throws_;
};

void DoFastReentrantCall(i::Isolate* i_isolate, LocalContext* env, int* sum,
                         int value, bool inner_most_throws) {
  v8::Local<v8::Value> initial_value(v8_num(value));
  RecursiveReentrantJSChecker checker(i_isolate, env, sum, inner_most_throws);
  SetupTest(initial_value, env, &checker,
            "function func(arg) {"
            "  receiver.api_func(arg);"
            "}"
            "function wrapper(){"
            "%PrepareFunctionForOptimization(func);"
            "func(value);"
            "%OptimizeFunctionOnNextCall(func);"
            "func(value);"
            "}wrapper(value);",
            true, true, false);
}

void FastApiCallRecursion(bool inner_most_throws) {
  if (i::v8_flags.jitless) return;
  if (i::v8_flags.disable_optimizing_compilers) return;

  i::v8_flags.turbofan = true;
  i::v8_flags.turbo_fast_api_calls = true;
  i::v8_flags.allow_natives_syntax = true;
  // Disable --always_turbofan, otherwise we haven't generated the necessary
  // feedback to go down the "best optimization" path for the fast call.
  i::v8_flags.always_turbofan = false;
  i::v8_flags.allow_allocation_in_fast_api_call = true;
  i::FlagList::EnforceFlagImplications();

  CcTest::InitializeVM();
  v8::Isolate* isolate = CcTest::isolate();

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  i_isolate->set_embedder_wrapper_type_index(kV8WrapperTypeIndex);
  i_isolate->set_embedder_wrapper_object_index(kV8WrapperObjectIndex);

  v8::HandleScope scope(isolate);

  LocalContext env;
  int sum = 0;
  v8::TryCatch try_catch(isolate);
  printf("Do reentrant call now\n");
  DoFastReentrantCall(i_isolate, &env, &sum, 6, inner_most_throws);
  CHECK_EQ(try_catch.HasCaught(), inner_most_throws);
  CHECK_EQ(sum, 21);
}

}  // namespace

TEST(FastApiCallRecursionWithException) { FastApiCallRecursion(true); }

TEST(FastApiCallRecursionNoException) { FastApiCallRecursion(false); }

void CallWithUnexpectedReceiverType(v8::Local<v8::Value> receiver) {
  LocalContext env;
  ApiNumberChecker<int32_t> checker(42);
  bool has_caught =
      SetupTest(receiver, &env, &checker,
                "function func(arg) { receiver.api_func.apply(value, arg); }"
                "%PrepareFunctionForOptimization(func);"
                "func(value);"
                "%OptimizeFunctionOnNextCall(func);"
                "func(value);");
  CHECK(has_caught);
  // The slow and fast callbacks were called actually, but aborted early.
  CHECK(!checker.DidCallSlow());
  CHECK(!checker.DidCallFast());
}

void CallWithUnexpectedObjectType(v8::Local<v8::Value> receiver) {
  LocalContext env;
  UnexpectedObjectChecker checker;
  SetupTest(receiver, &env, &checker,
            "function func(arg) { receiver.api_func(arg); }"
            "%PrepareFunctionForOptimization(func);"
            "func(value);"
            "%OptimizeFunctionOnNextCall(func);"
            "func(value);");
  CHECK(checker.DidCallFast());
  CHECK(checker.DidCallSlow());
}

class TestCFunctionInfo : public v8::CFunctionInfo {
  static constexpr unsigned int kArgCount = 2u;

 public:
  TestCFunctionInfo()
      : v8::CFunctionInfo(v8::CTypeInfo(v8::CTypeInfo::Type::kVoid), kArgCount,
                          arg_info_storage_),
        arg_info_storage_{
            v8::CTypeInfo(v8::CTypeInfo::Type::kV8Value),
            v8::CTypeInfo(v8::CTypeInfo::Type::kBool),
        } {}

 private:
  const v8::CTypeInfo arg_info_storage_[kArgCount];
};

void CheckDynamicTypeInfo() {
  LocalContext env;

  static TestCFunctionInfo type_info;
  v8::CFunction c_func = v8::CFunction(
      reinterpret_cast<const void*>(ApiNumberChecker<bool>::FastCallback),
      &type_info);
  CHECK_EQ(c_func.ArgumentCount(), 2);
  CHECK_EQ(c_func.ArgumentInfo(0).GetType(), v8::CTypeInfo::Type::kV8Value);
  CHECK_EQ(c_func.ArgumentInfo(1).GetType(), v8::CTypeInfo::Type::kBool);
  CHECK_EQ(c_func.ReturnInfo().GetType(), v8::CTypeInfo::Type::kVoid);
}
}  // namespace
#endif  // !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)

TEST(FastApiStackSlot) {
#if !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
  if (i::v8_flags.jitless) return;
  if (i::v8_flags.disable_optimizing_compilers) return;

  i::v8_flags.turbofan = true;
  i::v8_flags.turbo_fast_api_calls = true;
  i::v8_flags.allow_natives_syntax = true;
  // Disable --always_turbofan, otherwise we haven't generated the necessary
  // feedback to go down the "best optimization" path for the fast call.
  i::v8_flags.always_turbofan = false;
  i::FlagList::EnforceFlagImplications();

  v8::Isolate* isolate = CcTest::isolate();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  i_isolate->set_embedder_wrapper_type_index(kV8WrapperTypeIndex);
  i_isolate->set_embedder_wrapper_object_index(kV8WrapperObjectIndex);

  v8::HandleScope scope(isolate);
  LocalContext env;

  int test_value = 42;
  ApiNumberChecker<int32_t> checker(test_value, Behavior::kNoException);

  bool has_caught = SetupTest<int32_t, ApiNumberChecker<int32_t>>(
      v8_num(test_value), &env, &checker,
      "function func(arg) {"
      " let foo = 128;"
      " for (let i = 0; i < 100; ++i) {"
      "  let bar = true;"
      "  if (i == 10) %OptimizeOsr();"
      "  try { receiver.api_func(arg) } catch(_) {};"
      "  try { receiver.api_func(arg) } catch(_) {};"
      " };"
      " return foo;"
      "};");
  checker.Reset();

  v8::TryCatch try_catch(isolate);
  v8::Local<v8::Value> foo =
      CompileRun("%PrepareFunctionForOptimization(func); func(value);");
  CHECK(foo->IsNumber());
  CHECK_EQ(128, foo->ToInt32(env.local()).ToLocalChecked()->Value());

  // TODO(v8:13600): Re-enable these checks and verify `try_catch.HasCaught()`.
  // CHECK(checker.DidCallFast());
  // CHECK_EQ(checker.fast_value_, test_value);
  CHECK(checker.DidCallSlow());
  CHECK_EQ(false, has_caught);
  int32_t slow_value_typed = checker.slow_value_.ToChecked();
  CHECK_EQ(slow_value_typed, test_value);
#endif  // !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
}

TEST(FastApiCalls) {
#if !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
  if (i::v8_flags.jitless) return;
  if (i::v8_flags.disable_optimizing_compilers) return;

  i::v8_flags.turbofan = true;
  i::v8_flags.turbo_fast_api_calls = true;
  i::v8_flags.allow_natives_syntax = true;
  i::v8_flags.fast_api_allow_float_in_sim = true;
  // Disable --always_turbofan, otherwise we haven't generated the necessary
  // feedback to go down the "best optimization" path for the fast call.
  i::v8_flags.always_turbofan = false;
  i::FlagList::EnforceFlagImplications();

  CcTest::InitializeVM();
  v8::Isolate* isolate = CcTest::isolate();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  i_isolate->set_embedder_wrapper_type_index(kV8WrapperTypeIndex);
  i_isolate->set_embedder_wrapper_object_index(kV8WrapperObjectIndex);

  v8::HandleScope scope(isolate);
  LocalContext env;

  // Main cases (the value fits in the type)
  CallAndCheck<int32_t>(-42, Behavior::kNoException,
                        ApiCheckerResult::kFastCalled, v8_num(-42));
  CallAndCheck<uint32_t>(i::Smi::kMaxValue, Behavior::kNoException,
                         ApiCheckerResult::kFastCalled,
                         v8_num(i::Smi::kMaxValue));
  CallAndCheck<bool>(false, Behavior::kNoException,
                     ApiCheckerResult::kFastCalled,
                     v8::Boolean::New(isolate, false));
  CallAndCheck<bool>(true, Behavior::kNoException,
                     ApiCheckerResult::kFastCalled,
                     v8::Boolean::New(isolate, true));

#ifdef V8_ENABLE_FP_PARAMS_IN_C_LINKAGE
  CallAndCheck<float>(3.14f, Behavior::kNoException,
                      ApiCheckerResult::kFastCalled, v8_num(3.14));
  CallAndCheck<double>(3.14, Behavior::kNoException,
                       ApiCheckerResult::kFastCalled, v8_num(3.14));
#else
  CallAndCheck<float>(3.14f, Behavior::kNoException,
                      ApiCheckerResult::kSlowCalled, v8_num(3.14));
  CallAndCheck<double>(3.14, Behavior::kNoException,
                       ApiCheckerResult::kSlowCalled, v8_num(3.14));
#endif

  // Corner cases (the value is out of bounds or of different type) - int32_t
  CallAndCheck<int32_t>(0, Behavior::kNoException,
                        ApiCheckerResult::kFastCalled, v8_num(-0.0));
  CallAndCheck<int32_t>(0, Behavior::kNoException,
                        ApiCheckerResult::kFastCalled,
                        v8_num(std::numeric_limits<double>::quiet_NaN()));
  CallAndCheck<int32_t>(0, Behavior::kNoException,
                        ApiCheckerResult::kFastCalled,
                        v8_num(std::numeric_limits<double>::infinity()));
  CallAndCheck<int32_t>(0, Behavior::kNoException,
                        ApiCheckerResult::kSlowCalled, v8_str("some_string"));
  CallAndCheck<int32_t>(0, Behavior::kNoException,
                        ApiCheckerResult::kSlowCalled,
                        CompileRun("new Proxy({}, {});"));
  CallAndCheck<int32_t>(0, Behavior::kNoException,
                        ApiCheckerResult::kSlowCalled,
                        v8::Object::New(isolate));
  CallAndCheck<int32_t>(0, Behavior::kNoException,
                        ApiCheckerResult::kSlowCalled, v8::Array::New(isolate));
  CallAndCheck<int32_t>(0, Behavior::kException, ApiCheckerResult::kSlowCalled,
                        v8::BigInt::New(isolate, 42));
  CallAndCheck<int32_t>(std::numeric_limits<int32_t>::min(),
                        Behavior::kNoException, ApiCheckerResult::kFastCalled,
                        v8_num(std::numeric_limits<int32_t>::min()));
  CallAndCheck<int32_t>(
      std::numeric_limits<int32_t>::min(), Behavior::kNoException,
      ApiCheckerResult::kFastCalled,
      v8_num(static_cast<double>(std::numeric_limits<int32_t>::max()) + 1));

  CallAndCheck<int32_t>(3, Behavior::kNoException,
                        ApiCheckerResult::kFastCalled, v8_num(3.14));

  // Corner cases - uint32_t
  CallAndCheck<uint32_t>(0, Behavior::kNoException,
                         ApiCheckerResult::kFastCalled, v8_num(-0.0));
  CallAndCheck<uint32_t>(0, Behavior::kNoException,
                         ApiCheckerResult::kFastCalled,
                         v8_num(std::numeric_limits<double>::quiet_NaN()));
  CallAndCheck<uint32_t>(0, Behavior::kNoException,
                         ApiCheckerResult::kFastCalled,
                         v8_num(std::numeric_limits<double>::infinity()));
  CallAndCheck<uint32_t>(0, Behavior::kNoException,
                         ApiCheckerResult::kSlowCalled, v8_str("some_string"));
  CallAndCheck<uint32_t>(0, Behavior::kNoException,
                         ApiCheckerResult::kSlowCalled,
                         v8::Object::New(isolate));
  CallAndCheck<uint32_t>(0, Behavior::kNoException,
                         ApiCheckerResult::kSlowCalled,
                         v8::Array::New(isolate));
  CallAndCheck<uint32_t>(0, Behavior::kException, ApiCheckerResult::kSlowCalled,
                         v8::BigInt::New(isolate, 42));
  CallAndCheck<uint32_t>(std::numeric_limits<uint32_t>::min(),
                         Behavior::kNoException, ApiCheckerResult::kFastCalled,
                         v8_num(std::numeric_limits<uint32_t>::max() + 1));
  CallAndCheck<uint32_t>(3, Behavior::kNoException,
                         ApiCheckerResult::kFastCalled, v8_num(3.14));

  // Both 32- and 64-bit platforms should execute the following tests
  // through the slow path.
  // Corner cases - int64
  CallAndCheck<int64_t>(0, Behavior::kNoException,
                        ApiCheckerResult::kSlowCalled, v8_num(std::pow(2, 65)));
  CallAndCheck<int64_t>(8192, Behavior::kNoException,
                        ApiCheckerResult::kSlowCalled,
                        v8_num(std::pow(2, 65) + 8192));
  CallAndCheck<int64_t>(0, Behavior::kNoException,
                        ApiCheckerResult::kSlowCalled,
                        v8_num(std::pow(2, 1023)));
  CallAndCheck<int64_t>(0, Behavior::kNoException,
                        ApiCheckerResult::kSlowCalled,
                        v8_num(std::numeric_limits<double>::quiet_NaN()));
  CallAndCheck<int64_t>(0, Behavior::kNoException,
                        ApiCheckerResult::kSlowCalled,
                        v8_num(std::numeric_limits<double>::infinity()));
  CallAndCheck<int64_t>(0, Behavior::kNoException,
                        ApiCheckerResult::kSlowCalled, v8_str("some_string"));
  CallAndCheck<int64_t>(0, Behavior::kNoException,
                        ApiCheckerResult::kSlowCalled,
                        CompileRun("new Proxy({}, {});"));
  CallAndCheck<int64_t>(0, Behavior::kNoException,
                        ApiCheckerResult::kSlowCalled,
                        v8::Object::New(isolate));
  CallAndCheck<int64_t>(0, Behavior::kNoException,
                        ApiCheckerResult::kSlowCalled, v8::Array::New(isolate));
  CallAndCheck<int64_t>(0, Behavior::kException, ApiCheckerResult::kSlowCalled,
                        v8::BigInt::New(isolate, 42));
  CallAndCheck<int64_t>(3, Behavior::kNoException,
                        ApiCheckerResult::kSlowCalled, v8_num(3.14));
  CallAndCheck<int64_t>(
      0, Behavior::kNoException, ApiCheckerResult::kSlowCalled,
      v8_num(static_cast<double>(std::numeric_limits<int64_t>::max()) * 2 +
             3.14));
  CallAndCheck<int64_t>(0, Behavior::kNoException,
                        ApiCheckerResult::kSlowCalled,
                        v8_num(static_cast<double>(1ull << 63) * 2));
  CallAndCheck<int64_t>(4096, Behavior::kNoException,
                        ApiCheckerResult::kSlowCalled,
                        v8_num(static_cast<double>(1ull << 63) * 2 + 4096));
  CallAndCheck<int64_t>(std::numeric_limits<int64_t>::min() + 4096,
                        Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                        v8_num(static_cast<double>(1ull << 63) * 3 + 4096));

  // Corner cases - uint64_t
  CallAndCheck<uint64_t>(static_cast<double>(1ull << 63) * 2 - 2048,
                         Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                         v8_num(static_cast<double>(1ull << 63) * 2 - 2048));
  // TODO(mslekova): We deopt for unsafe integers, but ultimately we want to
  // stay on the fast path.
  CallAndCheck<uint64_t>(0, Behavior::kNoException,
                         ApiCheckerResult::kSlowCalled,
                         v8_num(static_cast<double>(1ull << 63) * 2));
  CallAndCheck<uint64_t>(0, Behavior::kNoException,
                         ApiCheckerResult::kSlowCalled,
                         v8_num(std::numeric_limits<double>::quiet_NaN()));
  CallAndCheck<uint64_t>(0, Behavior::kNoException,
                         ApiCheckerResult::kSlowCalled,
                         v8_num(std::numeric_limits<double>::infinity()));
  CallAndCheck<uint64_t>(0, Behavior::kNoException,
                         ApiCheckerResult::kSlowCalled, v8_str("some_string"));
  CallAndCheck<uint64_t>(0, Behavior::kNoException,
                         ApiCheckerResult::kSlowCalled,
                         CompileRun("new Proxy({}, {});"));
  CallAndCheck<uint64_t>(0, Behavior::kNoException,
                         ApiCheckerResult::kSlowCalled,
                         v8::Object::New(isolate));
  CallAndCheck<uint64_t>(0, Behavior::kNoException,
                         ApiCheckerResult::kSlowCalled,
                         v8::Array::New(isolate));
  CallAndCheck<uint64_t>(0, Behavior::kException, ApiCheckerResult::kSlowCalled,
                         v8::BigInt::New(isolate, 42));
  CallAndCheck<uint64_t>(3, Behavior::kNoException,
                         ApiCheckerResult::kSlowCalled, v8_num(3.14));
  CallAndCheck<uint64_t>(4096, Behavior::kNoException,
                         ApiCheckerResult::kSlowCalled,
                         v8_num(static_cast<double>(1ull << 63) * 2 + 4096));
  CallAndCheck<uint64_t>(static_cast<double>(1ull << 63) + 4096,
                         Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                         v8_num(static_cast<double>(1ull << 63) * 3 + 4096));

  // The following int64/uint64 tests are platform-dependent, because Turbofan
  // currently doesn't support 64-bit integers on 32-bit architectures. So if
  // we attempt to follow the fast path on them, this leads to unsupported
  // situations, e.g. attempting to call IA32OperandConverter::ToImmediate
  // for a 64-bit operand.
#ifdef V8_TARGET_ARCH_64_BIT
  ApiCheckerResult expected_path_for_64bit_test = ApiCheckerResult::kFastCalled;
#else
  ApiCheckerResult expected_path_for_64bit_test = ApiCheckerResult::kSlowCalled;
#endif
  // Corner cases - int64
  CallAndCheck<int64_t>(static_cast<int64_t>(i::Smi::kMaxValue) + 1,
                        Behavior::kNoException, expected_path_for_64bit_test,
                        v8_num(static_cast<int64_t>(i::Smi::kMaxValue) + 1));
  CallAndCheck<int64_t>(std::numeric_limits<int64_t>::min(),
                        Behavior::kNoException, expected_path_for_64bit_test,
                        v8_num(std::numeric_limits<int64_t>::min()));
  CallAndCheck<int64_t>(1ll << 62, Behavior::kNoException,
                        expected_path_for_64bit_test, v8_num(1ll << 62));
  CallAndCheck<int64_t>(i::kMaxSafeInteger, Behavior::kNoException,
                        expected_path_for_64bit_test,
                        v8_num(i::kMaxSafeInteger));
  CallAndCheck<int64_t>(-i::kMaxSafeInteger, Behavior::kNoException,
                        expected_path_for_64bit_test,
                        v8_num(-i::kMaxSafeInteger));
  CallAndCheck<int64_t>((1ull << 63) - 1024, Behavior::kNoException,
                        expected_path_for_64bit_test,
                        v8_num((1ull << 63) - 1024));
  CallAndCheck<int64_t>(0, Behavior::kNoException, expected_path_for_64bit_test,
                        v8_num(-0.0));

  // Corner cases - uint64_t
  CallAndCheck<uint64_t>(static_cast<uint64_t>(i::Smi::kMaxValue) + 1,
                         Behavior::kNoException, expected_path_for_64bit_test,
                         v8_num(static_cast<uint64_t>(i::Smi::kMaxValue) + 1));
  CallAndCheck<uint64_t>(std::numeric_limits<uint64_t>::min(),
                         Behavior::kNoException, expected_path_for_64bit_test,
                         v8_num(std::numeric_limits<uint64_t>::min()));
  CallAndCheck<uint64_t>(1ll << 62, Behavior::kNoException,
                         expected_path_for_64bit_test, v8_num(1ll << 62));
  CallAndCheck<uint64_t>(
      std::numeric_limits<uint64_t>::max() - ((1ll << 62) - 1),
      Behavior::kNoException, expected_path_for_64bit_test,
      v8_num(-(1ll << 62)));
  CallAndCheck<uint64_t>(i::kMaxSafeIntegerUint64, Behavior::kNoException,
                         expected_path_for_64bit_test,
                         v8_num(i::kMaxSafeInteger));
  CallAndCheck<uint64_t>(
      std::numeric_limits<uint64_t>::max() - (i::kMaxSafeIntegerUint64 - 1),
      Behavior::kNoException, expected_path_for_64bit_test,
      v8_num(-i::kMaxSafeInteger));
  CallAndCheck<uint64_t>(0, Behavior::kNoException,
                         expected_path_for_64bit_test, v8_num(-0.0));

  // TODO(mslekova): We deopt for unsafe integers, but ultimately we want to
  // stay on the fast path.
  CallAndCheck<int64_t>(std::numeric_limits<int64_t>::min(),
                        Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                        v8_num(1ull << 63));
  CallAndCheck<int64_t>(
      std::numeric_limits<int64_t>::min(), Behavior::kNoException,
      ApiCheckerResult::kSlowCalled,
      v8_num(static_cast<double>(std::numeric_limits<int64_t>::max()) + 3.14));
  CallAndCheck<int64_t>(std::numeric_limits<int64_t>::min(),
                        Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                        v8_num(static_cast<double>(1ull << 63)));
  CallAndCheck<int64_t>(std::numeric_limits<int64_t>::min(),
                        Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                        v8_num(-static_cast<double>(1ll << 63)));
  CallAndCheck<uint64_t>(1ull << 63, Behavior::kNoException,
                         ApiCheckerResult::kSlowCalled,
                         v8_num(static_cast<double>(1ull << 63)));

  // Corner cases - float and double
#ifdef V8_ENABLE_FP_PARAMS_IN_C_LINKAGE
  // Source:
  // https://en.wikipedia.org/wiki/Single-precision_floating-point_format#Precision_limitations_on_integer_values
  constexpr float kMaxSafeFloat = 16777215;  // 2^24-1
  CallAndCheck<float>(std::numeric_limits<float>::min(), Behavior::kNoException,
                      ApiCheckerResult::kFastCalled,
                      v8_num(std::numeric_limits<float>::min()));
  CallAndCheck<float>(-kMaxSafeFloat, Behavior::kNoException,
                      ApiCheckerResult::kFastCalled, v8_num(-kMaxSafeFloat));
  CallAndCheck<float>(-0.0f, Behavior::kNoException,
                      ApiCheckerResult::kFastCalled, v8_num(-0.0));
  CallAndCheck<float>(0.0f, Behavior::kNoException,
                      ApiCheckerResult::kFastCalled, v8_num(0.0));
  CallAndCheck<float>(kMaxSafeFloat, Behavior::kNoException,
                      ApiCheckerResult::kFastCalled, v8_num(kMaxSafeFloat));
  CallAndCheck<float>(std::numeric_limits<float>::max(), Behavior::kNoException,
                      ApiCheckerResult::kFastCalled,
                      v8_num(std::numeric_limits<float>::max()));
  CallAndCheck<float>(std::numeric_limits<float>::quiet_NaN(),
                      Behavior::kNoException, ApiCheckerResult::kFastCalled,
                      v8_num(std::numeric_limits<float>::quiet_NaN()));
  CallAndCheck<float>(std::numeric_limits<float>::infinity(),
                      Behavior::kNoException, ApiCheckerResult::kFastCalled,
                      v8_num(std::numeric_limits<float>::infinity()));
  CallAndCheck<float>(std::numeric_limits<float>::quiet_NaN(),
                      Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                      v8_str("some_string"));
  CallAndCheck<float>(std::numeric_limits<float>::quiet_NaN(),
                      Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                      CompileRun("new Proxy({}, {});"));
  CallAndCheck<float>(std::numeric_limits<float>::quiet_NaN(),
                      Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                      v8::Object::New(isolate));
  CallAndCheck<float>(0, Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                      v8::Array::New(isolate));
  CallAndCheck<float>(std::numeric_limits<float>::quiet_NaN(),
                      Behavior::kException, ApiCheckerResult::kSlowCalled,
                      v8::BigInt::New(isolate, 42));
  CallAndCheck<float>(-std::numeric_limits<float>::infinity(),
                      Behavior::kNoException, ApiCheckerResult::kFastCalled,
                      v8_num(-std::numeric_limits<double>::max()));
  CallAndCheck<float>(std::numeric_limits<float>::infinity(),
                      Behavior::kNoException, ApiCheckerResult::kFastCalled,
                      v8_num(std::numeric_limits<double>::max()));
  CallAndCheck<float>(kMaxSafeFloat + 1.0f, Behavior::kNoException,
                      ApiCheckerResult::kFastCalled,
                      v8_num(static_cast<double>(kMaxSafeFloat) + 2.0));

  CallAndCheck<double>(std::numeric_limits<double>::min(),
                       Behavior::kNoException, ApiCheckerResult::kFastCalled,
                       v8_num(std::numeric_limits<double>::min()));
  CallAndCheck<double>(-i::kMaxSafeInteger, Behavior::kNoException,
                       ApiCheckerResult::kFastCalled,
                       v8_num(-i::kMaxSafeInteger));
  CallAndCheck<double>(std::numeric_limits<float>::min(),
                       Behavior::kNoException, ApiCheckerResult::kFastCalled,
                       v8_num(std::numeric_limits<float>::min()));
  CallAndCheck<double>(-0.0, Behavior::kNoException,
                       ApiCheckerResult::kFastCalled, v8_num(-0.0));
  CallAndCheck<double>(0.0, Behavior::kNoException,
                       ApiCheckerResult::kFastCalled, v8_num(0.0));
  CallAndCheck<double>(std::numeric_limits<float>::max(),
                       Behavior::kNoException, ApiCheckerResult::kFastCalled,
                       v8_num(std::numeric_limits<float>::max()));
  CallAndCheck<double>(i::kMaxSafeInteger, Behavior::kNoException,
                       ApiCheckerResult::kFastCalled,
                       v8_num(i::kMaxSafeInteger));
  CallAndCheck<double>(i::kMaxSafeInteger + 1, Behavior::kNoException,
                       ApiCheckerResult::kFastCalled,
                       v8_num(i::kMaxSafeInteger + 1));
  CallAndCheck<double>(std::numeric_limits<double>::max(),
                       Behavior::kNoException, ApiCheckerResult::kFastCalled,
                       v8_num(std::numeric_limits<double>::max()));
  CallAndCheck<double>(std::numeric_limits<double>::quiet_NaN(),
                       Behavior::kNoException, ApiCheckerResult::kFastCalled,
                       v8_num(std::numeric_limits<double>::quiet_NaN()));
  CallAndCheck<double>(std::numeric_limits<double>::infinity(),
                       Behavior::kNoException, ApiCheckerResult::kFastCalled,
                       v8_num(std::numeric_limits<double>::infinity()));
  CallAndCheck<double>(std::numeric_limits<double>::quiet_NaN(),
                       Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                       v8_str("some_string"));
  CallAndCheck<double>(std::numeric_limits<double>::quiet_NaN(),
                       Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                       CompileRun("new Proxy({}, {});"));
  CallAndCheck<double>(std::numeric_limits<double>::quiet_NaN(),
                       Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                       v8::Object::New(isolate));
  CallAndCheck<double>(0, Behavior::kNoException, ApiCheckerResult::kSlowCalled,
                       v8::Array::New(isolate));
  CallAndCheck<double>(std::numeric_limits<double>::quiet_NaN(),
                       Behavior::kException, ApiCheckerResult::kSlowCalled,
                       v8::BigInt::New(isolate, 42));
#endif

  // Corner cases - bool
  CallAndCheck<bool>(false, Behavior::kNoException,
                     ApiCheckerResult::kFastCalled, v8::Undefined(isolate));
  CallAndCheck<bool>(false, Behavior::kNoException,
                     ApiCheckerResult::kFastCalled, v8::Null(isolate));
  CallAndCheck<bool>(false, Behavior::kNoException,
                     ApiCheckerResult::kFastCalled, v8_num(0));
  CallAndCheck<bool>(true, Behavior::kNoException,
                     ApiCheckerResult::kFastCalled, v8_num(42));
  CallAndCheck<bool>(false, Behavior::kNoException,
                     ApiCheckerResult::kFastCalled, v8_str(""));
  CallAndCheck<bool>(true, Behavior::kNoException,
                     ApiCheckerResult::kFastCalled, v8_str("some_string"));
  CallAndCheck<bool>(true, Behavior::kNoException,
                     ApiCheckerResult::kFastCalled, v8::Symbol::New(isolate));
  CallAndCheck<bool>(false, Behavior::kNoException,
                     ApiCheckerResult::kFastCalled,
                     v8::BigInt::New(isolate, 0));
  CallAndCheck<bool>(true, Behavior::kNoException,
                     ApiCheckerResult::kFastCalled,
                     v8::BigInt::New(isolate, 42));
  CallAndCheck<bool>(true, Behavior::kNoException,
                     ApiCheckerResult::kFastCalled, v8::Object::New(isolate));

  // Test return values
  CheckFastReturnValue<bool>(v8::Boolean::New(isolate, true),
                             ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<bool>(v8::Boolean::New(isolate, false),
                             ApiCheckerResult::kFastCalled);

  CheckFastReturnValue<int32_t>(v8_num(0), ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<int32_t>(v8_num(std::numeric_limits<int32_t>::min()),
                                ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<int32_t>(v8_num(std::numeric_limits<int32_t>::max()),
                                ApiCheckerResult::kFastCalled);

  CheckFastReturnValue<uint32_t>(v8_num(0), ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<uint32_t>(v8_num(std::numeric_limits<uint32_t>::min()),
                                 ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<uint32_t>(v8_num(std::numeric_limits<uint32_t>::max()),
                                 ApiCheckerResult::kFastCalled);

#ifdef V8_ENABLE_FP_PARAMS_IN_C_LINKAGE
  CheckFastReturnValue<float>(v8_num(0), ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<float>(v8_num(-0.0), ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<float>(v8_num(std::numeric_limits<float>::quiet_NaN()),
                              ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<float>(v8_num(std::numeric_limits<float>::infinity()),
                              ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<float>(v8_num(std::numeric_limits<float>::min()),
                              ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<float>(v8_num(std::numeric_limits<float>::max()),
                              ApiCheckerResult::kFastCalled);

  CheckFastReturnValue<double>(v8_num(0), ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<double>(v8_num(-0.0), ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<double>(v8_num(std::numeric_limits<double>::quiet_NaN()),
                               ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<double>(v8_num(std::numeric_limits<double>::infinity()),
                               ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<double>(v8_num(std::numeric_limits<double>::min()),
                               ApiCheckerResult::kFastCalled);
  CheckFastReturnValue<double>(v8_num(std::numeric_limits<double>::max()),
                               ApiCheckerResult::kFastCalled);
#endif  // V8_ENABLE_FP_PARAMS_IN_C_LINKAGE

  // Check for the deopt loop protection
  CallAndDeopt();

  // Test callbacks without options
  CallNoOptions(42);

  // Test callback requesting access checks
  CallNoConvertReceiver(42);

  CheckDynamicTypeInfo();

  // Throw an exception.
  CallAndCheck<int32_t>(42, Behavior::kException, ApiCheckerResult::kFastCalled,
                        v8_num(42), Behavior::kException);

  CallAndCheck<int32_t>(44, Behavior::kNoException,
                        ApiCheckerResult::kFastCalled, v8_num(44),
                        Behavior::kNoException);

  // Wrong number of arguments
  CallWithLessArguments();
  CallWithMoreArguments();

  // Wrong types of receiver
  CallWithUnexpectedReceiverType(v8_num(123));
  CallWithUnexpectedReceiverType(v8_str("str"));
  CallWithUnexpectedReceiverType(CompileRun("new Proxy({}, {});"));

  // Wrong types for argument of type object
  CallWithUnexpectedObjectType(v8_num(123));
  CallWithUnexpectedObjectType(v8_str("str"));
  CallWithUnexpectedObjectType(CompileRun("new Proxy({}, {});"));

  CheckApiObjectArg();
  CheckFastCallsWithConstructor();

  // TODO(mslekova): Restructure the tests so that the fast optimized calls
  // are compared against the slow optimized calls.
  // TODO(mslekova): Add tests for FTI that requires access check.
#endif  // !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
}

template <typename Ret, v8::CFunctionInfo::Int64Representation Int64Repr =
                            v8::CFunctionInfo::Int64Representation::kNumber>
struct SeqOneByteStringChecker {
  static void Test(std::function<Ret()> f) {
    LocalContext env;
    v8::Isolate* isolate = CcTest::isolate();

    static v8::CFunction c_function =
        v8::CFunction::Make(FastCallback, Int64Repr);
    v8::Local<v8::FunctionTemplate> checker_templ = v8::FunctionTemplate::New(
        isolate, SlowCallback, {}, {}, 1, v8::ConstructorBehavior::kThrow,
        v8::SideEffectType::kHasSideEffect, &c_function);

    v8::Local<v8::ObjectTemplate> object_template =
        v8::ObjectTemplate::New(isolate);
    object_template->SetInternalFieldCount(kV8WrapperObjectIndex + 1);
    object_template->Set(isolate, "api_func", checker_templ);

    SeqOneByteStringChecker checker{f};

    v8::Local<v8::Object> object =
        object_template->NewInstance(env.local()).ToLocalChecked();
    object->SetAlignedPointerInInternalField(kV8WrapperObjectIndex,
                                             reinterpret_cast<void*>(&checker));
    CHECK((*env)
              ->Global()
              ->Set(env.local(), v8_str("receiver"), object)
              .FromJust());

    v8::TryCatch try_catch(isolate);
    CompileRun(
        "function func(arg) { return receiver.api_func(arg); }"
        "%PrepareFunctionForOptimization(func);"
        "func('');");
    CHECK(!try_catch.HasCaught());
    CHECK(checker.DidCallSlow());
    checker.Reset();

    CompileRun(
        "%OptimizeFunctionOnNextCall(func);"
        "const fastr = func('');");
    CHECK(!try_catch.HasCaught());
    CHECK(checker.DidCallFast());
    checker.Reset();

    // Call func with two-byte string to take slow path
    CompileRun("const slowr = func('\\u{1F4A9}');");
    CHECK(!try_catch.HasCaught());
    CHECK(checker.DidCallSlow());

    if constexpr (std::is_same_v<Ret, void*>) {
      CompileRun(
          "if (typeof slowr !== 'object') { throw new Error(`${slowr} is not "
          "object`) }");
    } else {
      CompileRun(
          "if (!Object.is(fastr, slowr)) { throw new Error(`${slowr} is not "
          "${fastr}`); }");
    }
    CHECK(!try_catch.HasCaught());
  }

  static Ret FastCallback(v8::Local<v8::Object> receiver,
                          const v8::FastOneByteString& string) {
    SeqOneByteStringChecker* receiver_ptr =
        GetInternalField<SeqOneByteStringChecker>(*receiver);
    receiver_ptr->result_ |= ApiCheckerResult::kFastCalled;

    return receiver_ptr->func_();
  }

  static void SlowCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
    v8::Object* receiver_obj = v8::Object::Cast(*info.This());
    SeqOneByteStringChecker* receiver_ptr =
        GetInternalField<SeqOneByteStringChecker>(receiver_obj);
    receiver_ptr->result_ |= ApiCheckerResult::kSlowCalled;

    CHECK(info[0]->IsString());
    if constexpr (std::is_void<Ret>::value) {
      // do nothing
    } else if constexpr (std::is_same_v<Ret, void*>) {
      info.GetReturnValue().Set(
          v8::External::New(info.GetIsolate(), receiver_ptr->func_()));
    } else if constexpr (sizeof(Ret) == 8 &&
                         Int64Repr ==
                             v8::CFunctionInfo::Int64Representation::kBigInt) {
      if constexpr (std::is_same_v<Ret, int64_t>) {
        info.GetReturnValue().Set(
            v8::BigInt::New(info.GetIsolate(), receiver_ptr->func_()));
      } else {
        info.GetReturnValue().Set(v8::BigInt::NewFromUnsigned(
            info.GetIsolate(), receiver_ptr->func_()));
      }
    } else if constexpr (std::is_same_v<Ret, uint64_t>) {
      info.GetReturnValue().Set(v8::Number::New(
          info.GetIsolate(), static_cast<double>(receiver_ptr->func_())));
    } else {
      info.GetReturnValue().Set(receiver_ptr->func_());
    }
  }

  explicit SeqOneByteStringChecker(std::function<Ret()> f) : func_(f) {}

  bool DidCallFast() const { return (result_ & ApiCheckerResult::kFastCalled); }
  bool DidCallSlow() const { return (result_ & ApiCheckerResult::kSlowCalled); }

  void Reset() { result_ = ApiCheckerResult::kNotCalled; }

 private:
  std::function<Ret()> func_;
  ApiCheckerResultFlags result_ = ApiCheckerResult::kNotCalled;
};

TEST(FastApiCallsString) {
#if !defined(V8_LITE_MODE) &&                          \
    !defined(V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS) && \
    defined(V8_ENABLE_TURBOFAN)
  if (i::v8_flags.jitless) return;
  if (i::v8_flags.disable_optimizing_compilers) return;

  i::v8_flags.turbofan = true;
  i::v8_flags.turbo_fast_api_calls = true;
  i::v8_flags.allow_natives_syntax = true;
  i::v8_flags.fast_api_allow_float_in_sim = true;
  // Disable --always_turbofan, otherwise we haven't generated the necessary
  // feedback to go down the "best optimization" path for the fast call.
  i::v8_flags.always_turbofan = false;
  i::FlagList::EnforceFlagImplications();

  CcTest::InitializeVM();
  v8::Isolate* isolate = CcTest::isolate();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  i_isolate->set_embedder_wrapper_type_index(kV8WrapperTypeIndex);
  i_isolate->set_embedder_wrapper_object_index(kV8WrapperObjectIndex);

  v8::HandleScope scope(isolate);
  LocalContext env;

  SeqOneByteStringChecker<void>::Test([]() {});

  SeqOneByteStringChecker<void*>::Test(
      []() { return reinterpret_cast<void*>(0xFF); });

  SeqOneByteStringChecker<bool>::Test([]() { return true; });
  SeqOneByteStringChecker<bool>::Test([]() { return false; });

  SeqOneByteStringChecker<int32_t>::Test([]() { return 0; });
  SeqOneByteStringChecker<int32_t>::Test(
      []() { return std::numeric_limits<int32_t>::min(); });
  SeqOneByteStringChecker<int32_t>::Test(
      []() { return std::numeric_limits<int32_t>::max(); });

  SeqOneByteStringChecker<uint32_t>::Test([]() { return 0; });
  SeqOneByteStringChecker<uint32_t>::Test(
      []() { return std::numeric_limits<uint32_t>::min(); });
  SeqOneByteStringChecker<uint32_t>::Test(
      []() { return std::numeric_limits<uint32_t>::max(); });

#ifdef V8_ENABLE_FP_PARAMS_IN_C_LINKAGE
  SeqOneByteStringChecker<float>::Test([]() { return 0; });
  SeqOneByteStringChecker<float>::Test(
      []() { return std::numeric_limits<float>::quiet_NaN(); });
  SeqOneByteStringChecker<float>::Test(
      []() { return std::numeric_limits<float>::infinity(); });
  SeqOneByteStringChecker<float>::Test(
      []() { return std::numeric_limits<float>::min(); });
  SeqOneByteStringChecker<float>::Test(
      []() { return std::numeric_limits<float>::max(); });

  SeqOneByteStringChecker<double>::Test([]() { return 0; });
  SeqOneByteStringChecker<double>::Test(
      []() { return std::numeric_limits<double>::quiet_NaN(); });
  SeqOneByteStringChecker<double>::Test(
      []() { return std::numeric_limits<double>::infinity(); });
  SeqOneByteStringChecker<double>::Test(
      []() { return std::numeric_limits<double>::min(); });
  SeqOneByteStringChecker<double>::Test(
      []() { return std::numeric_limits<double>::max(); });
#endif  // V8_ENABLE_FP_PARAMS_IN_C_LINKAGE

#ifdef V8_TARGET_ARCH_64_BIT
  SeqOneByteStringChecker<
      int64_t, v8::CFunctionInfo::Int64Representation::kNumber>::Test([]() {
    return 0;
  });
  SeqOneByteStringChecker<
      int64_t, v8::CFunctionInfo::Int64Representation::kNumber>::Test([]() {
    return std::numeric_limits<int64_t>::min();
  });
  SeqOneByteStringChecker<
      int64_t, v8::CFunctionInfo::Int64Representation::kNumber>::Test([]() {
    // The highest int64_t representable as double.
    return 0x7ffffffffffff000L;
  });

  SeqOneByteStringChecker<
      int64_t, v8::CFunctionInfo::Int64Representation::kBigInt>::Test([]() {
    return 0;
  });
  SeqOneByteStringChecker<
      int64_t, v8::CFunctionInfo::Int64Representation::kBigInt>::Test([]() {
    return std::numeric_limits<int64_t>::min();
  });
  SeqOneByteStringChecker<
      int64_t, v8::CFunctionInfo::Int64Representation::kBigInt>::Test([]() {
    return std::numeric_limits<int64_t>::max();
  });

  SeqOneByteStringChecker<
      uint64_t, v8::CFunctionInfo::Int64Representation::kNumber>::Test([]() {
    return 0;
  });
  SeqOneByteStringChecker<
      uint64_t, v8::CFunctionInfo::Int64Representation::kNumber>::Test([]() {
    return std::numeric_limits<uint64_t>::min();
  });
  SeqOneByteStringChecker<
      uint64_t, v8::CFunctionInfo::Int64Representation::kNumber>::Test([]() {
    // The highest uint64 representable as double.
    return 0xfffffffffffff000UL;
  });

  SeqOneByteStringChecker<
      uint64_t, v8::CFunctionInfo::Int64Representation::kBigInt>::Test([]() {
    return 0;
  });
  SeqOneByteStringChecker<
      uint64_t, v8::CFunctionInfo::Int64Representation::kBigInt>::Test([]() {
    return std::numeric_limits<uint64_t>::min();
  });
  SeqOneByteStringChecker<
      uint64_t, v8::CFunctionInfo::Int64Representation::kBigInt>::Test([]() {
    return std::numeric_limits<uint64_t>::max();
  });
#endif  // V8_TARGET_ARCH_64_BIT

#endif  // !defined(V8_LITE_MODE) &&
        // !defined(V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS) &&
        // defined(V8_ENABLE_TURBOFAN)
}

#if V8_ENABLE_WEBASSEMBLY
TEST(FastApiCallsFromWasm) {
  if (i::v8_flags.jitless) return;
  if (i::v8_flags.disable_optimizing_compilers) return;

  i::v8_flags.liftoff = false;
  i::v8_flags.turboshaft_wasm = true;
  i::v8_flags.wasm_fast_api = true;
  i::v8_flags.turbo_fast_api_calls = true;
  i::v8_flags.wasm_lazy_compilation = true;
  i::v8_flags.fast_api_allow_float_in_sim = true;
  i::FlagList::EnforceFlagImplications();

  CcTest::InitializeVM();
  v8::Isolate* isolate = CcTest::isolate();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  i_isolate->set_embedder_wrapper_type_index(kV8WrapperTypeIndex);
  i_isolate->set_embedder_wrapper_object_index(kV8WrapperObjectIndex);

  v8::HandleScope scope(isolate);
  LocalContext env;

  CallAndCheckFromWasm();
}
#endif
#if !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
namespace {
static Trivial* UnwrapTrivialObject(Local<Object> object) {
  i::Address addr = i::ValueHelper::ValueAsAddress(*object);
  auto instance_type = i::Internals::GetInstanceType(addr);
  bool is_valid =
      (v8::base::IsInRange(instance_type, i::Internals::kFirstJSApiObjectType,
                           i::Internals::kLastJSApiObjectType) ||
       instance_type == i::Internals::kJSSpecialApiObjectType);
  if (!is_valid) {
    return nullptr;
  }
  Trivial* wrapped = static_cast<Trivial*>(
      object->GetAlignedPointerFromInternalField(kV8WrapperObjectIndex));
  CHECK_NOT_NULL(wrapped);
  return wrapped;
}

void FastCallback2JSArray(v8::Local<v8::Object> receiver, int arg0,
                          v8::Local<v8::Array> arg1) {
  Trivial* self = UnwrapTrivialObject(receiver);
  CHECK_NOT_NULL(self);
  CHECK_EQ(arg0, arg1->Length());
  self->set_x(arg0);
}

void FastCallback3SwappedParams(v8::Local<v8::Object> receiver,
                                v8::Local<v8::Array> arg0, int arg1) {}

void FastCallback4Scalar(v8::Local<v8::Object> receiver, int arg0, float arg1) {
}

void FastCallback5DifferentArity(v8::Local<v8::Object> receiver, int arg0,
                                 v8::Local<v8::Array> arg1, float arg2) {}

}  // namespace
#endif  // !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)

START_ALLOW_USE_DEPRECATED()
TEST(FastApiOverloadResolution) {
#if !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
  if (i::v8_flags.jitless) return;
  if (i::v8_flags.disable_optimizing_compilers) return;

  i::v8_flags.turbofan = true;
  i::v8_flags.turbo_fast_api_calls = true;
  i::v8_flags.allow_natives_syntax = true;
  // Disable --always_turbofan, otherwise we haven't generated the necessary
  // feedback to go down the "best optimization" path for the fast call.
  i::v8_flags.always_turbofan = false;
  i::FlagList::EnforceFlagImplications();

  v8::CFunction js_array_callback =
      v8::CFunctionBuilder().Fn(FastCallback2JSArray).Build();

  v8::CFunction swapped_params_callback =
      v8::CFunctionBuilder().Fn(FastCallback3SwappedParams).Build();

  // Check that difference in > 1 position is not possible.
  CHECK_EQ(v8::CFunction::OverloadResolution::kImpossible,
           js_array_callback.GetOverloadResolution(&swapped_params_callback));

  v8::CFunction scalar_callback =
      v8::CFunctionBuilder().Fn(FastCallback4Scalar).Build();

  // Check that resolving when there is a scalar at the difference position
  // is not possible.
  CHECK_EQ(v8::CFunction::OverloadResolution::kImpossible,
           js_array_callback.GetOverloadResolution(&scalar_callback));

  v8::CFunction diff_arity_callback =
      v8::CFunctionBuilder().Fn(FastCallback5DifferentArity).Build();

  // Check that overload resolution between different number of arguments
  // is possible.
  CHECK_EQ(v8::CFunction::OverloadResolution::kAtCompileTime,
           js_array_callback.GetOverloadResolution(&diff_arity_callback));

#endif  // !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
}
END_ALLOW_USE_DEPRECATED()

TEST(Recorder_GetContext) {
  using v8::Context;
  using v8::Local;
  using v8::MaybeLocal;

  // Set up isolate and context.
  v8::Isolate* iso = CcTest::isolate();

  v8::metrics::Recorder::ContextId original_id;
  std::vector<v8::metrics::Recorder::ContextId> ids;
  {
    v8::HandleScope scope(iso);
    Local<Context> context = Context::New(iso);

    // Ensure that we get a valid context id.
    original_id = v8::metrics::Recorder::GetContextId(context);
    CHECK(!original_id.IsEmpty());

    // Request many context ids to ensure correct growth behavior.
    for (size_t count = 0; count < 50; ++count) {
      Local<Context> temp_context = Context::New(iso);
      ids.push_back(v8::metrics::Recorder::GetContextId(temp_context));
    }
    for (const v8::metrics::Recorder::ContextId& id : ids) {
      CHECK(!v8::metrics::Recorder::GetContext(iso, id).IsEmpty());
    }

    // Ensure that we can get the context from the context id.
    MaybeLocal<Context> retrieved_context =
        v8::metrics::Recorder::GetContext(iso, original_id);
    CHECK_EQ(context, retrieved_context.ToLocalChecked());

    // Ensure that an empty context id returns an empty handle.
    retrieved_context = v8::metrics::Recorder::GetContext(
        iso, v8::metrics::Recorder::ContextId::Empty());
    CHECK(retrieved_context.IsEmpty());

    // Ensure that repeated context id accesses return the same context id.
    v8::metrics::Recorder::ContextId new_id =
        v8::metrics::Recorder::GetContextId(context);
    CHECK_EQ(original_id, new_id);
  }

  {
    // We need to invoke GC without stack, otherwise some objects may not be
    // reclaimed because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    // Invalidate the context and therefore the context id.
    i::heap::InvokeAtomicMajorGC(CcTest::heap());
  }

  // Ensure that a stale context id returns an empty handle.
  {
    v8::HandleScope scope(iso);
    MaybeLocal<Context> retrieved_context =
        v8::metrics::Recorder::GetContext(iso, original_id);
    CHECK(retrieved_context.IsEmpty());

    for (const v8::metrics::Recorder::ContextId& id : ids) {
      CHECK(v8::metrics::Recorder::GetContext(iso, id).IsEmpty());
    }
  }
}

namespace {

class MetricsRecorder : public v8::metrics::Recorder {
 public:
  v8::Isolate* isolate_;
  size_t count_ = 0;
  size_t module_count_ = 0;
  int64_t time_in_us_ = -1;

  explicit MetricsRecorder(v8::Isolate* isolate) : isolate_(isolate) {}

  void AddMainThreadEvent(const v8::metrics::WasmModuleDecoded& event,
                          v8::metrics::Recorder::ContextId id) override {
    if (v8::metrics::Recorder::GetContext(isolate_, id).IsEmpty()) return;
    ++count_;
    time_in_us_ = event.wall_clock_duration_in_us;
  }

  void AddThreadSafeEvent(
      const v8::metrics::WasmModulesPerIsolate& event) override {
    ++count_;
    module_count_ = event.count;
  }
};

}  // namespace

TEST(TriggerMainThreadMetricsEvent) {
  using v8::Context;
  using v8::Local;
  using v8::MaybeLocal;

  // Set up isolate and context.
  v8::Isolate* iso = CcTest::isolate();
  i::Isolate* i_iso = reinterpret_cast<i::Isolate*>(iso);
  CHECK(i_iso->metrics_recorder());
  v8::metrics::WasmModuleDecoded event;
  v8::metrics::Recorder::ContextId context_id;
  std::shared_ptr<MetricsRecorder> recorder =
      std::make_shared<MetricsRecorder>(iso);
  iso->SetMetricsRecorder(recorder);
  {
    v8::HandleScope scope(iso);
    Local<Context> context = Context::New(iso);
    context_id = v8::metrics::Recorder::GetContextId(context);

    // Check that event submission works.
    {
      i::metrics::TimedScope<v8::metrics::WasmModuleDecoded> timed_scope(
          &event);
      v8::base::OS::Sleep(v8::base::TimeDelta::FromMilliseconds(100));
    }
    i_iso->metrics_recorder()->AddMainThreadEvent(event, context_id);
    CHECK_EQ(recorder->count_, 1);  // Increased.
    CHECK_GT(recorder->time_in_us_, 100);
  }

  {
    // We need to invoke GC without stack, otherwise some objects may not be
    // reclaimed because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    i::heap::InvokeAtomicMajorGC(CcTest::heap());
  }

  // Check that event submission doesn't break even if the context id is
  // invalid.
  i_iso->metrics_recorder()->AddMainThreadEvent(event, context_id);
  CHECK_EQ(recorder->count_, 1);  // Unchanged.
}

TEST(TriggerDelayedMainThreadMetricsEvent) {
  using v8::Context;
  using v8::Local;
  using v8::MaybeLocal;
  i::v8_flags.stress_concurrent_allocation = false;

  // Set up isolate and context.
  v8::Isolate* iso = CcTest::isolate();
  i::Isolate* i_iso = reinterpret_cast<i::Isolate*>(iso);
  CHECK(i_iso->metrics_recorder());
  v8::metrics::WasmModuleDecoded event;
  v8::metrics::Recorder::ContextId context_id;
  std::shared_ptr<MetricsRecorder> recorder =
      std::make_shared<MetricsRecorder>(iso);
  iso->SetMetricsRecorder(recorder);
  {
    v8::HandleScope scope(iso);
    Local<Context> context = Context::New(iso);
    context_id = v8::metrics::Recorder::GetContextId(context);

    // Check that event submission works.
    {
      i::metrics::TimedScope<v8::metrics::WasmModuleDecoded> timed_scope(
          &event);
      v8::base::OS::Sleep(v8::base::TimeDelta::FromMilliseconds(100));
    }
    i_iso->metrics_recorder()->DelayMainThreadEvent(event, context_id);
    CHECK_EQ(recorder->count_, 0);        // Unchanged.
    CHECK_EQ(recorder->time_in_us_, -1);  // Unchanged.
    v8::base::OS::Sleep(v8::base::TimeDelta::FromMilliseconds(1100));
    while (v8::platform::PumpMessageLoop(i::V8::GetCurrentPlatform(), iso)) {
    }
    CHECK_EQ(recorder->count_, 1);  // Increased.
    CHECK_GT(recorder->time_in_us_, 100);
  }

  {
    // We need to invoke GC without stack, otherwise some objects may not be
    // reclaimed because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    i::heap::InvokeAtomicMajorGC(CcTest::heap());
  }

  // Check that event submission doesn't break even if the context id is
  // invalid.
  i_iso->metrics_recorder()->DelayMainThreadEvent(event, context_id);
  v8::base::OS::Sleep(v8::base::TimeDelta::FromMilliseconds(1100));
  while (v8::platform::PumpMessageLoop(i::V8::GetCurrentPlatform(), iso)) {
  }
  CHECK_EQ(recorder->count_, 1);  // Unchanged.
}

TEST(TriggerThreadSafeMetricsEvent) {
  // Set up isolate and context.
  v8::Isolate* iso = CcTest::isolate();
  i::Isolate* i_iso = reinterpret_cast<i::Isolate*>(iso);
  CHECK(i_iso->metrics_recorder());
  v8::metrics::WasmModulesPerIsolate event;
  std::shared_ptr<MetricsRecorder> recorder =
      std::make_shared<MetricsRecorder>(iso);
  iso->SetMetricsRecorder(recorder);

  // Check that event submission works.
  event.count = 42;
  i_iso->metrics_recorder()->AddThreadSafeEvent(event);
  CHECK_EQ(recorder->count_, 1);  // Increased.
  CHECK_EQ(recorder->module_count_, 42);
}

void SetupCodeLike(LocalContext* env, const char* name,
                   v8::Local<v8::FunctionTemplate> to_string,
                   bool is_code_like) {
  // Setup a JS construct
```