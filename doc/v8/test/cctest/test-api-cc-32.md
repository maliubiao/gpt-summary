Response:
Let's break down the thought process for analyzing this C++ code snippet from `v8/test/cctest/test-api.cc`.

**1. Initial Understanding - The Big Picture**

The filename `test-api.cc` immediately suggests this is a test file for the V8 JavaScript engine's API. The presence of `cctest` reinforces that this is a core V8 test. The overall goal is likely to verify that the V8 API works as expected, especially regarding how C++ code interacts with JavaScript.

**2. Identifying Key Structures and Patterns**

Scanning the code, I look for recurring patterns and important data structures:

* **`BasicApiChecker` template:** This is clearly a base class for various checkers. It seems designed to track whether "fast" or "slow" API callbacks are executed. The `SetCallFast()` and `SetCallSlow()` methods, along with the `DidCallFast()` and `DidCallSlow()` methods, confirm this. The template parameters `<T, Derived, Arg>` likely represent the data type being checked, the derived class itself (for CRTP), and an argument type (though some specializations like `void` exist).
* **Specific Checker Structs (e.g., `ReturnValueChecker`, `AllocationChecker`, `ThrowInReentrantJSChecker`, `RecursiveReentrantJSChecker`, `UnexpectedObjectChecker`, `ApiNumberChecker`):** These are concrete implementations of the `BasicApiChecker` template, each with a specific purpose. Their names are quite descriptive.
* **`FastCallback` and `SlowCallback` static methods:**  These are the core of the API interaction. The "Fast" version takes arguments directly, while the "Slow" version uses `v8::FunctionCallbackInfo`. This strongly suggests testing optimized vs. non-optimized API calls.
* **`SetupTest` function (implicitly used):**  The code repeatedly calls `SetupTest`. This function (defined elsewhere, but its usage is clear) sets up the V8 environment, creates a receiver object with the API function, and runs JavaScript code that calls the API function.
* **`CompileRun` function:**  This function runs JavaScript code within the test environment. It's frequently used for setting up tests, triggering optimizations (`%PrepareFunctionForOptimization`, `%OptimizeFunctionOnNextCall`), and sometimes for operations like garbage collection (`gc();`).
* **`v8::Local` and `v8::HandleScope`:** Standard V8 API for managing object lifetimes.
* **`i::Isolate`:**  Internal V8 isolate, indicating interaction with V8 internals.
* **Macros/Flags:**  The code uses `i::v8_flags` to enable/disable specific V8 features like Turbofan and fast API calls. This highlights testing different configurations.

**3. Analyzing Individual Checker Functionality**

Now I go through each checker struct to understand its specific role:

* **`ReturnValueChecker`:** Checks if the return value from the API call is correctly passed back. The fast path simply returns the argument, while the slow path sets the return value using `info.GetReturnValue().Set(info[0])`.
* **`AllocationChecker`:**  Verifies behavior when memory allocation occurs within a fast API call. It triggers garbage collection (either from C++ or JavaScript) and checks if the object and its internal field remain consistent.
* **`ThrowInReentrantJSChecker`:** Tests how exceptions thrown from within a fast API call (which re-enters JavaScript) are handled. The fast path throws a string, the slow path throws a V8 `String` exception.
* **`RecursiveReentrantJSChecker`:** Examines recursive calls from the fast API callback back into JavaScript. It increments a sum and can optionally throw an exception in the innermost call.
* **`UnexpectedObjectChecker`:**  Seems designed to test scenarios where the receiver object passed to the API call is not of the expected type.
* **`ApiNumberChecker`:** A general-purpose checker for numeric types, allowing control over whether exceptions are expected and the number of arguments.

**4. Connecting Code to JavaScript Concepts**

For each checker, I consider how its actions relate to JavaScript:

* **Fast vs. Slow Calls:**  This directly relates to V8's optimization pipeline. Fast API calls are designed to be more efficient when certain conditions are met.
* **Garbage Collection:** The `AllocationChecker` demonstrates how C++ code can trigger GC and how that interacts with JavaScript.
* **Exceptions:**  The `ThrowInReentrantJSChecker` and `RecursiveReentrantJSChecker` are about exception handling across the C++/JavaScript boundary.
* **Receiver Object (`this`):** The API calls are made on a `receiver` object, which is the `this` value in the JavaScript function. The checkers use internal fields of this object to store their state.
* **Function Arguments:**  The tests explore passing different numbers and types of arguments to the API functions.

**5. Inferring Functionality of Helper Functions**

Based on their usage:

* **`CheckFastReturnValue`:**  Specifically checks if the fast path is taken and if the return value is as expected.
* **`CallAndDeopt`:** Tests a scenario where a fast API call initially works but then deoptimizes due to a type change.
* **`CallNoOptions`, `CallNoConvertReceiver`, `CallWithLessArguments`, `CallWithMoreArguments`:** These test different variations of how API calls are made, focusing on the impact of options and argument counts.
* **`FastApiCallWithAllocationAndGC`, `FastApiCallWithThrowInReentrantCode`, `FastApiCallRecursion`:**  These are higher-level test functions that orchestrate scenarios using the specific checkers.
* **`CallWithUnexpectedReceiverType`, `CallWithUnexpectedObjectType`:** Focus on error handling when the receiver is not what's expected.
* **`CheckDynamicTypeInfo`:** Examines the metadata associated with C++ functions exposed to JavaScript.

**6. Considering Potential Errors**

Based on the scenarios being tested, I can identify common programming errors:

* **Incorrect Argument Types:** Passing the wrong type of argument to a fast API call.
* **Incorrect Number of Arguments:** Mismatched argument counts between the C++ function and the JavaScript call.
* **Incorrect Receiver Type:** Calling an API function on an object that doesn't have the expected internal structure.
* **Memory Management Issues:** Although not directly shown in this snippet, the `AllocationChecker` hints at potential issues if memory isn't handled correctly in fast API calls.
* **Exception Handling:** Failing to properly catch or propagate exceptions across the C++/JavaScript boundary.

**7. Synthesizing the Summary**

Finally, I combine all the observations to create a concise summary, focusing on the key aspects of the code's functionality.

**Self-Correction/Refinement During the Process:**

* Initially, I might not fully grasp the purpose of every checker. As I analyze their `FastCallback` and `SlowCallback` implementations, their intent becomes clearer.
* I might initially miss the significance of the `%PrepareFunctionForOptimization` and `%OptimizeFunctionOnNextCall` calls. Realizing their connection to the fast/slow paths is crucial.
* I pay close attention to the checks (`CHECK`, `CHECK_EQ`) within the code, as these directly reveal what the tests are verifying.

By following this structured analysis, combining code inspection with knowledge of V8 and JavaScript concepts, I can effectively understand and summarize the functionality of the provided C++ code snippet.
目录 `v8/test/cctest/test-api.cc` 的第 33 部分主要关注 **V8 引擎的 C++ API 的快速调用（Fast API Calls）机制的测试**。

以下是该部分代码的功能归纳：

**主要功能：测试 V8 的 Fast API Call 功能**

Fast API Call 是 V8 优化 C++ 代码与 JavaScript 代码交互的一种机制，允许在满足特定条件时，C++ 函数以更高效的方式被 JavaScript 调用，避免常规的函数调用开销。

**具体测试点：**

1. **基本 Fast API Call 的调用和验证：**
   - 定义了多个辅助的结构体（如 `ReturnValueChecker`, `AllocationChecker`, `ThrowInReentrantJSChecker`, `RecursiveReentrantJSChecker`, `ApiNumberChecker` 等），这些结构体作为 C++ 对象的内部字段，用于跟踪 Fast API Call 和 Slow API Call 的执行情况。
   - 使用 `SetupTest` 模板函数来设置测试环境，将 C++ 函数绑定到 JavaScript 对象上。
   - 通过 JavaScript 代码调用绑定的 C++ 函数，并断言是否按照预期执行了 Fast API Call 或 Slow API Call。
   - 验证 Fast API Call 的返回值是否正确传递。

2. **不同数据类型的 Fast API Call：**
   - 测试了 `int32_t`, `uint32_t`, `bool`, `float`, `double`, `int64_t`, `uint64_t` 等不同 C++ 数据类型作为 Fast API Call 参数和返回值的情况。
   - 验证了在数据类型匹配时是否能走 Fast Path，以及在类型不匹配或超出范围时是否会回退到 Slow Path 或抛出异常。

3. **Fast API Call 中的内存分配和垃圾回收：**
   - `AllocationChecker` 结构体测试了在 Fast API Call 中进行内存分配，并触发垃圾回收 (GC) 的场景。
   - 验证了在 GC 后，对象的状态和内部字段是否仍然有效，以及 Fast API Call 是否能正常完成。

4. **Fast API Call 中的异常处理：**
   - `ThrowInReentrantJSChecker` 结构体测试了在 Fast API Call 中抛出 JavaScript 异常的情况。
   - 验证了异常是否能够正确地被 JavaScript 代码捕获。

5. **Fast API Call 的递归调用：**
   - `RecursiveReentrantJSChecker` 结构体测试了从 Fast API Call 中递归调用 JavaScript 代码的场景。
   - 验证了递归调用是否能正常执行，以及在递归调用中抛出异常时的处理。

6. **Fast API Call 的参数和接收者验证：**
   - 测试了传递不同数量的参数给 Fast API Call 的情况，验证了参数数量不匹配时会回退到 Slow Path。
   - 测试了使用意外的接收者类型或对象类型调用 Fast API Call 的情况，验证了 V8 的处理机制（通常会回退到 Slow Path 或抛出异常）。

7. **C Function Info 的动态类型信息：**
   - `CheckDynamicTypeInfo` 函数测试了 `v8::CFunctionInfo` 类的使用，用于指定 C++ 函数的参数和返回类型信息。

8. **Fast API Call 与栈槽优化 (Stack Slot Optimization)：**
   - `TEST(FastApiStackSlot)` 测试用例验证了 Fast API Call 与 V8 的栈槽优化是否能良好地协同工作。

**如果 `v8/test/cctest/test-api.cc` 以 `.tq` 结尾：**

如果文件以 `.tq` 结尾，那它将是 V8 的 **Torque** 源代码。Torque 是一种类型化的中间语言，用于编写 V8 的内置函数（Builtins）。当前的文件名是 `.cc`，所以它是 C++ 源代码。

**与 JavaScript 功能的关系和示例：**

该部分代码直接测试了 JavaScript 如何调用 C++ 函数，以及 V8 如何优化这种调用。以下 JavaScript 示例展示了如何调用通过 Fast API 机制绑定的 C++ 函数：

```javascript
// 假设在 C++ 代码中，你将一个名为 'api_func' 的 C++ 函数绑定到了一个 JavaScript 对象的原型上。

let receiver = {}; // 创建一个 JavaScript 对象

// ... (在 C++ 代码中设置 receiver 的内部字段并绑定 'api_func')

function callFastApi(arg) {
  return receiver.api_func(arg); // 调用绑定的 C++ 函数
}

// V8 的优化机制会尝试将符合条件的 'receiver.api_func(arg)' 调用优化为 Fast API Call

// 进行一些预热调用，让 V8 有机会进行优化
callFastApi(10);
callFastApi(20);

// 触发优化
%PrepareFunctionForOptimization(callFastApi);
callFastApi(30);
%OptimizeFunctionOnNextCall(callFastApi);
let result = callFastApi(40); // 此时可能会执行 Fast API Call

console.log(result);
```

**代码逻辑推理和假设输入/输出：**

以 `ReturnValueChecker` 为例：

**假设输入：**

- C++ 端创建 `ReturnValueChecker<int32_t>` 对象，并将其指针存储在 JavaScript 对象的内部字段中。
- JavaScript 调用绑定的 `api_func` 并传入一个整数参数，例如 `42`。

**代码逻辑推理：**

- 如果 V8 决定执行 Fast API Call，则会调用 `ReturnValueChecker<int32_t>::FastCallback`。
- `FastCallback` 会将 `call_fast_` 设置为 `true` 并直接返回传入的参数 `42`。
- 如果 V8 执行 Slow API Call，则会调用 `ReturnValueChecker<int32_t>::SlowCallback`。
- `SlowCallback` 会将 `call_slow_` 设置为 `true`，并通过 `info.GetReturnValue().Set(info[0])` 将传入的参数 `42` 设置为 JavaScript 的返回值。

**预期输出：**

- 如果是 Fast API Call，`checker.DidCallFast()` 返回 `true`，`checker.DidCallSlow()` 返回 `false`，JavaScript 函数调用返回 `42`。
- 如果是 Slow API Call，`checker.DidCallFast()` 返回 `false`，`checker.DidCallSlow()` 返回 `true`，JavaScript 函数调用返回 `42`。

**用户常见的编程错误示例：**

1. **C++ 函数签名与 JavaScript 调用不匹配：**
   - 例如，C++ 函数期望一个 `int32_t` 参数，但在 JavaScript 中传入了字符串。这会导致类型转换错误或回退到 Slow Path。

   ```javascript
   // C++ 函数期望一个整数
   receiver.api_func("not an integer");
   ```

2. **忘记在 C++ 端正确处理 JavaScript 的 `v8::Local` 对象：**
   - 在 Slow API Call 中，通过 `info` 获取的 `v8::Local` 对象需要正确地管理其生命周期，否则可能导致内存泄漏或访问已释放的内存。

3. **在 Fast API Call 中执行可能导致异常的操作，但未进行适当处理：**
   - Fast API Call 的设计目标是高效，通常不包含复杂的异常处理逻辑。如果在 Fast API Call 中执行可能抛出异常的操作（例如，访问空指针），可能导致程序崩溃。

4. **假设 Fast API Call 总是会被执行：**
   - V8 会根据运行时的条件动态地决定是否执行 Fast API Call。开发者不应假设某个 API 调用总是会走 Fast Path。

**总结第 33 部分的功能：**

第 33 部分的 `v8/test/cctest/test-api.cc` 代码专注于 **全面地测试 V8 引擎的 Fast API Call 机制**。它通过定义各种场景和使用不同的数据类型，验证了 Fast API Call 在不同情况下的行为，包括正常调用、数据类型转换、内存分配、垃圾回收、异常处理以及递归调用等。这些测试确保了 V8 的 Fast API Call 功能的正确性和健壮性，为高效的 C++ 与 JavaScript 代码交互提供了保障。

Prompt: 
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第33部分，共36部分，请归纳一下它的功能

"""
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
  CallAndCheck<uint64_t>(0, Behavior
"""


```