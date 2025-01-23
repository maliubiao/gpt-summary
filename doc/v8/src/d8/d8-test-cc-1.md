Response:
The user wants a summary of the provided C++ code snippet, which is part of `v8/src/d8/d8-test.cc`. The code defines a class `FastCApiObject` and functions to expose its functionalities to JavaScript through V8's C++ API.

Here's a breakdown of the thought process to analyze the code and generate the summary:

1. **Identify the core component:** The code centers around the `FastCApiObject` class. This is the primary entity being manipulated and accessed.

2. **Analyze `FastCApiObject`'s members:**  The class has member variables `fast_call_count_` and `slow_call_count_`, suggesting it's tracking how often its methods are called via "fast" and "slow" paths. It also has a boolean `supports_fp_params_`.

3. **Examine the static methods of `FastCApiObject`:**  These methods are the interface exposed to JavaScript. Group them by functionality:
    * **Error Handling:** `ThrowNoFallbackFastCallback`, `ThrowFallbackSlowCallback` - related to error handling and fallbacks.
    * **String Manipulation:** `CopyStringFastCallback`, `CopyStringSlowCallback` - copying strings.
    * **Arithmetic Operations (various types):**  `AddAllFastCallback`, `AddAllSlowCallback`, `AddAllSequenceFastCallback`, `AddAllSequenceSlowCallback`, `AddAllTypedArrayFastCallback`, `AddAllTypedArraySlowCallback`, `AddAllFastCallbackNoOptions`, `AddAll32BitIntFastCallback_8Args`, `AddAll32BitIntFastCallback_6Args`, `AddAll32BitIntFastCallback_5Args`, `AddAll32BitIntSlowCallback`, `Add32BitIntFastCallback`, `Add32BitIntSlowCallback`, `sumInt64FastCallback`, `sumInt64AsNumberSlowCallback`, `sumInt64AsBigIntSlowCallback`, `sumUint64FastCallback`, `sumUint64AsNumberSlowCallback`, `sumUint64AsBigIntSlowCallback`. Notice the variations in argument types (numbers, typed arrays, BigInts), the presence of "fast" and "slow" callbacks, and overloads.
    * **Annotation/Type Checking:** `AddAllAnnotateFastCallback`, `AddAllAnnotateSlowCallback`, `EnforceRangeCompare`, `EnforceRangeCompareSlowCallback`, `ClampCompare`, `ClampCompareSlowCallback`. These methods seem related to enforcing constraints or providing type information.
    * **Object Inspection:** `IsFastCApiObjectFastCallback`, `IsFastCApiObjectSlowCallback`, `AssertIsExternal`. These appear to check the nature of JavaScript objects.
    * **Pointer Handling:** `GetPointerFastCallback`, `GetPointerSlowCallback`, `GetNullPointerFastCallback`, `GetNullPointerSlowCallback`, `PassPointerFastCallback`, `PassPointerSlowCallback`, `ComparePointersFastCallback`, `ComparePointersSlowCallback`. This indicates interaction with raw memory or external resources.
    * **Wasm Memory:** `TestWasmMemoryFastCallback`, `TestWasmMemorySlowCallback`. This suggests a link to WebAssembly.
    * **Counters:** `FastCallCount`, `SlowCallCount`, `ResetCounts`. These manage the call counters.
    * **Feature Detection:** `SupportsFPParams`. Checks for floating-point parameter support.

4. **Analyze `CreateFastCAPIObject`:** This function is called when a new `FastCAPIObject` is created from JavaScript. It sets up internal fields and accessor properties.

5. **Analyze `Shell::CreateTestFastCApiTemplate`:** This function is crucial for exposing the C++ object to JavaScript. It creates a `FunctionTemplate` which defines the JavaScript constructor and its prototype methods. It uses `CFunction::Make` to associate the fast C++ functions with the JavaScript methods. The presence of both "fast" and "slow" callbacks is a key pattern.

6. **Identify key concepts and patterns:**
    * **Fast and Slow Callbacks:**  The consistent presence of "fast" and "slow" callbacks suggests an optimization strategy. Fast callbacks are likely optimized for performance, while slow callbacks handle more complex scenarios or type checking.
    * **CFunction:** The use of `CFunction::Make` indicates direct binding of C++ functions to JavaScript.
    * **Templates:** The use of C++ templates (e.g., `ClampCompare<IntegerT>`) allows for code reuse with different integer types.
    * **Type Annotations/Enforcement:** The methods with "Annotate," "EnforceRange," and "Clamp" in their names demonstrate mechanisms for type checking and value clamping.
    * **Pointer Manipulation:** Several methods deal with raw pointers, likely for interacting with external memory or resources.
    * **Wasm Integration:** The "TestWasmMemory" methods point to integration with WebAssembly.

7. **Relate to JavaScript:** Consider how the C++ functionality would be used from JavaScript. For example, the `add_all` methods likely correspond to adding numbers in JavaScript. The pointer-related methods would involve passing and receiving pointers to/from JavaScript.

8. **Address specific instructions:**
    * **.tq extension:** The code is `.cc`, so it's standard C++, not Torque.
    * **JavaScript relationship:** Provide JavaScript examples demonstrating how some of the C++ functions might be called.
    * **Code logic and assumptions:**  Give examples of input and output for some of the simpler functions.
    * **Common programming errors:**  Mention potential errors like incorrect argument types or out-of-range values.

9. **Synthesize the summary:** Combine the findings into a concise description of the code's functionality, highlighting the key features and patterns observed. Emphasize the role of `FastCApiObject` as a bridge between C++ and JavaScript.

10. **Review and refine:**  Ensure the summary is accurate, clear, and addresses all aspects of the prompt. Make sure to specifically address the "Part 2" instruction by summarizing the *provided* code.
```cpp
  h)
            .Build();
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "clamp_compare_i32",
        FunctionTemplate::New(
            isolate, FastCApiObject::ClampCompareSlowCallback<int32_t>,
            Local<Value>(), signature, 1, ConstructorBehavior::kThrow,
            SideEffectType::kHasSideEffect, &clamp_compare_i32_c_func));

    CFunction clamp_compare_u32_c_func =
        CFunctionBuilder()
            .Fn(FastCApiObject::ClampCompare<uint32_t>)
            .Arg<3, v8::CTypeInfo::Flags::kClampBit>()
#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
            .Patch(FastCApiObject::ClampCompareU32Patch)
#endif  // V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
            .Build();
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "clamp_compare_u32",
        FunctionTemplate::New(
            isolate, FastCApiObject::ClampCompareSlowCallback<uint32_t>,
            Local<Value>(), signature, 1, ConstructorBehavior::kThrow,
            SideEffectType::kHasSideEffect, &clamp_compare_u32_c_func));

    CFunction clamp_compare_i64_c_func =
        CFunctionBuilder()
            .Fn(FastCApiObject::ClampCompare<int64_t>)
            .Arg<3, v8::CTypeInfo::Flags::kClampBit>()
#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
            .Patch(FastCApiObject::ClampCompareI64Patch)
#endif  // V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
            .Build();
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "clamp_compare_i64",
        FunctionTemplate::New(
            isolate, FastCApiObject::ClampCompareSlowCallback<int64_t>,
            Local<Value>(), signature, 1, ConstructorBehavior::kThrow,
            SideEffectType::kHasSideEffect, &clamp_compare_i64_c_func));

    CFunction clamp_compare_u64_c_func =
        CFunctionBuilder()
            .Fn(FastCApiObject::ClampCompare<uint64_t>)
            .Arg<3, v8::CTypeInfo::Flags::kClampBit>()
#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
            .Patch(FastCApiObject::ClampCompareU64Patch)
#endif  // V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
            .Build();
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "clamp_compare_u64",
        FunctionTemplate::New(
            isolate, FastCApiObject::ClampCompareSlowCallback<uint64_t>,
            Local<Value>(), signature, 1, ConstructorBehavior::kThrow,
            SideEffectType::kHasSideEffect, &clamp_compare_u64_c_func));

    CFunction is_fast_c_api_object_func = CFunction::Make(
        FastCApiObject::IsFastCApiObjectFastCallback V8_IF_USE_SIMULATOR(
            FastCApiObject::IsFastCApiObjectFastCallbackPatch));
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "is_valid_api_object",
        FunctionTemplate::New(isolate,
                              FastCApiObject::IsFastCApiObjectSlowCallback,
                              Local<Value>(), signature, 1,
                              ConstructorBehavior::kThrow,
                              SideEffectType::kHasSideEffect,
                              &is_fast_c_api_object_func));

    CFunction test_wasm_memory_func = CFunction::Make(
        FastCApiObject::TestWasmMemoryFastCallback V8_IF_USE_SIMULATOR(
            FastCApiObject::TestWasmMemoryFastCallbackPatch));
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "test_wasm_memory",
        FunctionTemplate::New(isolate, FastCApiObject::TestWasmMemorySlowCallback,
                              Local<Value>(), signature, 1,
                              ConstructorBehavior::kThrow,
                              SideEffectType::kHasSideEffect,
                              &test_wasm_memory_func));

    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "assert_is_external",
        FunctionTemplate::New(isolate, FastCApiObject::AssertIsExternal));

    CFunction get_pointer_func = CFunction::Make(
        FastCApiObject::GetPointerFastCallback V8_IF_USE_SIMULATOR(
            FastCApiObject::GetPointerFastCallbackPatch));
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "get_pointer",
        FunctionTemplate::New(isolate, FastCApiObject::GetPointerSlowCallback,
                              Local<Value>(), signature, 0,
                              ConstructorBehavior::kThrow,
                              SideEffectType::kHasSideEffect, &get_pointer_func));

    CFunction get_null_pointer_func = CFunction::Make(
        FastCApiObject::GetNullPointerFastCallback V8_IF_USE_SIMULATOR(
            FastCApiObject::GetNullPointerFastCallbackPatch));
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "get_null_pointer",
        FunctionTemplate::New(isolate,
                              FastCApiObject::GetNullPointerSlowCallback,
                              Local<Value>(), signature, 0,
                              ConstructorBehavior::kThrow,
                              SideEffectType::kHasSideEffect,
                              &get_null_pointer_func));

    CFunction pass_pointer_func = CFunction::Make(
        FastCApiObject::PassPointerFastCallback V8_IF_USE_SIMULATOR(
            FastCApiObject::PassPointerFastCallbackPatch));
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "pass_pointer",
        FunctionTemplate::New(isolate, FastCApiObject::PassPointerSlowCallback,
                              Local<Value>(), signature, 1,
                              ConstructorBehavior::kThrow,
                              SideEffectType::kHasSideEffect, &pass_pointer_func));

    CFunction compare_pointers_func = CFunction::Make(
        FastCApiObject::ComparePointersFastCallback V8_IF_USE_SIMULATOR(
            FastCApiObject::ComparePointersFastCallbackPatch));
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "compare_pointers",
        FunctionTemplate::New(isolate,
                              FastCApiObject::ComparePointersSlowCallback,
                              Local<Value>(), signature, 2,
                              ConstructorBehavior::kThrow,
                              SideEffectType::kHasSideEffect,
                              &compare_pointers_func));

    CFunction sum_int64_func = CFunction::Make(
        FastCApiObject::sumInt64FastCallback V8_IF_USE_SIMULATOR(
            FastCApiObject::sumInt64FastCallbackPatch),
        CFunctionInfo::Int64Representation::kNumber);
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "sum_int64",
        FunctionTemplate::New(isolate,
                              FastCApiObject::sumInt64AsNumberSlowCallback,
                              Local<Value>(), signature, 2,
                              ConstructorBehavior::kThrow,
                              SideEffectType::kHasSideEffect, &sum_int64_func));
    CFunction sum_int64_as_bigint_func = CFunction::Make(
        FastCApiObject::sumInt64FastCallback V8_IF_USE_SIMULATOR(
            FastCApiObject::sumInt64FastCallbackPatch),
        CFunctionInfo::Int64Representation::kBigInt);
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "sum_int64_as_bigint",
        FunctionTemplate::New(isolate,
                              FastCApiObject::sumInt64AsBigIntSlowCallback,
                              Local<Value>(), signature, 2,
                              ConstructorBehavior::kThrow,
                              SideEffectType::kHasSideEffect,
                              &sum_int64_as_bigint_func));

    CFunction sum_uint64_func = CFunction::Make(
        FastCApiObject::sumUint64FastCallback V8_IF_USE_SIMULATOR(
            FastCApiObject::sumUint64FastCallbackPatch),
        CFunctionInfo::Int64Representation::kNumber);
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "sum_uint64",
        FunctionTemplate::New(isolate,
                              FastCApiObject::sumUint64AsNumberSlowCallback,
                              Local<Value>(), signature, 2,
                              ConstructorBehavior::kThrow,
                              SideEffectType::kHasSideEffect, &sum_uint64_func));

    CFunction sum_uint64_as_bigint_func = CFunction::Make(
        FastCApiObject::sumUint64FastCallback V8_IF_USE_SIMULATOR(
            FastCApiObject::sumUint64FastCallbackPatch),
        CFunctionInfo::Int64Representation::kBigInt);
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "sum_uint64_as_bigint",
        FunctionTemplate::New(isolate,
                              FastCApiObject::sumUint64AsBigIntSlowCallback,
                              Local<Value>(), signature, 2,
                              ConstructorBehavior::kThrow,
                              SideEffectType::kHasSideEffect,
                              &sum_uint64_as_bigint_func));

    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "fast_call_count",
        FunctionTemplate::New(isolate, FastCApiObject::FastCallCount));
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "slow_call_count",
        FunctionTemplate::New(isolate, FastCApiObject::SlowCallCount));
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "reset_counts",
        FunctionTemplate::New(isolate, FastCApiObject::ResetCounts));
  }
  api_obj_ctor->InstanceTemplate()->SetInternalFieldCount(2);
  api_obj_ctor->SetClassName(
      String::NewFromUtf8Literal(isolate, "TestFastCAPIObject"));
  return api_obj_ctor;
}

}  // namespace v8

```

## 功能归纳 (基于提供的代码片段)

这是 `v8/src/d8/d8-test.cc` 的一部分代码，主要定义了一个名为 `FastCApiObject` 的 C++ 类，并将其部分功能通过 V8 的 C++ API 暴露给 JavaScript 环境。

**`FastCApiObject` 的核心功能包括：**

1. **测试 V8 的 Fast C-API 功能：**  该类的设计目的是为了测试 V8 引擎中 "Fast C-API" 的各种特性。Fast C-API 允许 JavaScript 直接调用优化的 C++ 函数，以提高性能。

2. **提供多种类型的函数调用：**  该类提供了多种静态方法，这些方法对应了 JavaScript 中可以调用的函数。这些方法涵盖了不同的参数类型（例如，基本类型、对象、字符串、TypedArray、BigInt、指针等），并且通常成对出现 "FastCallback" 和 "SlowCallback"。
    * **FastCallback:**  是优化的、更快速的 C++ 函数入口。
    * **SlowCallback:**  是标准的、更通用的 V8 回调函数，用于处理更复杂的情况或作为 FastCallback 的回退。

3. **测试参数传递和返回值：**  通过不同的方法，测试了 JavaScript 如何向 C++ 传递参数，以及 C++ 如何向 JavaScript 返回值。这包括基本类型的值传递，以及对象、字符串、TypedArray 和指针的传递。

4. **测试类型注解和约束：**  代码中包含了一些用于测试类型注解和约束的方法，例如 `EnforceRangeCompare` 和 `ClampCompare`。这些方法使用 V8 的 CTypeInfo 功能来指定参数的类型和范围，并测试 V8 是否能正确地执行这些约束。

5. **测试 C++ 函数重载：**  通过 `overloaded_add_all_32bit_int` 等方法，测试了 JavaScript 调用具有不同参数数量的重载 C++ 函数的能力。

6. **测试 WebAssembly (Wasm) 互操作性：**  `TestWasmMemoryFastCallback` 及其关联的方法用于测试 JavaScript 如何与 WebAssembly 模块的内存进行交互。

7. **测试指针操作：**  `get_pointer`, `pass_pointer`, `compare_pointers` 等方法用于测试 JavaScript 和 C++ 之间传递和比较指针的能力。

8. **统计函数调用次数：**  `fast_call_count_` 和 `slow_call_count_` 成员变量用于跟踪 Fast C-API 和标准回调函数的调用次数，方便测试和验证。

**与 JavaScript 的关系：**

在 JavaScript 中，可以通过创建一个 `TestFastCAPIObject` 的实例，然后调用其原型上的方法来触发 C++ 代码的执行。

```javascript
// 假设在 d8 环境中已经加载了相关的 C++ 绑定
let obj = new TestFastCAPIObject();

// 调用一个将两个数字相加的 C++ 函数 (假设对应 sum_int64)
let sumResult = obj.sum_int64(5, 10);
console.log(sumResult); // 输出 15

// 调用一个复制字符串的 C++ 函数 (假设对应 copy_string)
let copiedString = obj.copy_string("hello");
console.log(copiedString); // 输出 "hello"

// 调用一个测试 WebAssembly 内存访问的函数
// 需要先在对象上设置 wasm_memory 属性
// obj.wasm_memory = ... (某个 WebAssembly.Memory 对象)
// obj.test_wasm_memory(0);

// 获取 C++ 对象的指针
let pointer = obj.get_pointer();
console.log(pointer); // 输出一个表示指针的值

// 检查一个对象是否是 Fast C-API 对象
let isValid = obj.is_valid_api_object({});
console.log(isValid); // 输出 false
let isValidSelf = obj.is_valid_api_object(obj);
console.log(isValidSelf); // 输出 true

// 获取 fast call 和 slow call 的计数
console.log(obj.fast_call_count);
console.log(obj.slow_call_count);
```

**代码逻辑推理 (示例):**

**假设输入：** 调用 `obj.sum_int64(5, 10)`

**输出：**  C++ 的 `FastCApiObject::sumInt64FastCallback` 或 `FastCApiObject::sumInt64AsNumberSlowCallback` 会被调用，计算 `5 + 10`，并将结果 `15` 作为 JavaScript 的 Number 返回。

**涉及用户常见的编程错误 (示例):**

1. **类型不匹配：** 如果 JavaScript 传递给 C++ 函数的参数类型与 C++ 期望的类型不符，可能会导致错误或类型转换问题。例如，如果 `sum_int64` 期望的是 Number，但传递了字符串，则在 `sumInt64AsNumberSlowCallback` 中会抛出错误。

   ```javascript
   // 错误示例：传递字符串而不是数字
   // obj.sum_int64("5", "10"); // 会抛出错误
   ```

2. **超出范围的值：**  对于有类型约束的方法，如果传递的值超出允许的范围，可能会导致错误或被截断。例如，对于使用了 `kEnforceRangeBit` 注解的函数，传递超出范围的数字可能会导致异常。

   ```javascript
   // 假设 enforce_range_compare_i32 期望第二个参数在某个范围内
   // obj.enforce_range_compare_i32(true, 10000000000); // 可能超出 int32 范围
   ```

3. **忘记设置必要的属性：**  例如，在使用 `test_wasm_memory` 之前，必须先在对象上设置 `wasm_memory` 属性，否则会抛出错误。

   ```javascript
   // 错误示例：忘记设置 wasm_memory
   // let obj = new TestFastCAPIObject();
   // obj.test_wasm_memory(0); // 会抛出错误
   ```

**功能归纳 (第 2 部分的总结):**

这部分代码主要集中在 **`FastCApiObject` 类的定义及其与 JavaScript 的绑定**。它详细展示了如何通过 V8 的 C++ API 将 C++ 函数暴露给 JavaScript 环境，并涵盖了多种参数类型、返回值、类型注解、函数重载以及与 WebAssembly 和指针的互操作。  核心目的是为了测试和演示 V8 引擎的 Fast C-API 功能。

### 提示词
```
这是目录为v8/src/d8/d8-test.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/d8/d8-test.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
template <typename IntegerT>
  static double ClampCompare(Local<Object> receiver, bool in_range,
                             double real_arg, IntegerT checked_arg,
                             FastApiCallbackOptions& options) {
    FastCApiObject* self = UnwrapObject(receiver);
    CHECK_NOT_NULL(self);
    self->fast_call_count_++;

    double result = ClampCompareCompute(in_range, real_arg, checked_arg);
    return static_cast<double>(result);
  }

  template <typename IntegerT>
  static void ClampCompareSlowCallback(
      const FunctionCallbackInfo<Value>& info) {
    DCHECK(i::ValidateCallbackInfo(info));
    Isolate* isolate = info.GetIsolate();

    FastCApiObject* self = UnwrapObject(info.This());
    CHECK_SELF_OR_THROW_SLOW();
    self->slow_call_count_++;

    double real_arg = 0;
    if (info.Length() > 1 && info[1]->IsNumber()) {
      real_arg = info[1]->NumberValue(isolate->GetCurrentContext()).FromJust();
    }
    double checked_arg_dbl = std::numeric_limits<double>::max();
    if (info.Length() > 2 && info[2]->IsNumber()) {
      checked_arg_dbl = info[2].As<Number>()->Value();
    }
    bool in_range =
        info[0]->IsBoolean() && info[0]->BooleanValue(isolate) &&
        base::IsValueInRangeForNumericType<IntegerT>(real_arg) &&
        base::IsValueInRangeForNumericType<IntegerT>(checked_arg_dbl);

    IntegerT checked_arg = std::numeric_limits<IntegerT>::max();
    if (in_range) {
      if (checked_arg_dbl != std::numeric_limits<double>::max()) {
        checked_arg = static_cast<IntegerT>(checked_arg_dbl);
      }
      double result = ClampCompareCompute(in_range, real_arg, checked_arg);
      info.GetReturnValue().Set(Number::New(isolate, result));
    } else {
      IntegerT clamped = std::numeric_limits<IntegerT>::max();
      if (std::isnan(checked_arg_dbl) || std::isnan(real_arg)) {
        clamped = 0;
      } else {
        IntegerT lower_bound = std::numeric_limits<IntegerT>::min();
        IntegerT upper_bound = std::numeric_limits<IntegerT>::max();
        if (lower_bound < internal::kMinSafeInteger) {
          lower_bound = static_cast<IntegerT>(internal::kMinSafeInteger);
        }
        if (upper_bound > internal::kMaxSafeInteger) {
          upper_bound = static_cast<IntegerT>(internal::kMaxSafeInteger);
        }

        clamped = std::clamp(real_arg, static_cast<double>(lower_bound),
                             static_cast<double>(upper_bound));
      }
      info.GetReturnValue().Set(Number::New(isolate, clamped));
    }
  }

  static bool IsFastCApiObjectFastCallback(v8::Local<v8::Object> receiver,
                                           v8::Local<v8::Value> arg,
                                           FastApiCallbackOptions& options) {
    FastCApiObject* self = UnwrapObject(receiver);
    CHECK_SELF_OR_THROW_FAST_OPTIONS(false);

    self->fast_call_count_++;

    if (!arg->IsObject()) {
      return false;
    }
    Local<Object> object = arg.As<Object>();
    if (!IsValidApiObject(object)) return false;

    Isolate* isolate = options.isolate;
    HandleScope handle_scope(isolate);
    return PerIsolateData::Get(isolate)
        ->GetTestApiObjectCtor()
        ->IsLeafTemplateForApiObject(object);
  }

  static void IsFastCApiObjectSlowCallback(
      const FunctionCallbackInfo<Value>& info) {
    DCHECK(i::ValidateCallbackInfo(info));
    Isolate* isolate = info.GetIsolate();

    FastCApiObject* self = UnwrapObject(info.This());
    CHECK_SELF_OR_THROW_SLOW();
    self->slow_call_count_++;

    HandleScope handle_scope(isolate);

    bool result = false;
    if (info.Length() < 1) {
      info.GetIsolate()->ThrowError(
          "is_valid_api_object should be called with an argument");
      return;
    }
    if (info[0]->IsObject()) {
      Local<Object> object = info[0].As<Object>();
      if (!IsValidApiObject(object)) {
        result = false;
      } else {
        result = PerIsolateData::Get(info.GetIsolate())
                     ->GetTestApiObjectCtor()
                     ->IsLeafTemplateForApiObject(object);
      }
    }

    info.GetReturnValue().Set(result);
  }

  static bool TestWasmMemoryFastCallback(Local<Object> receiver,
                                         uint32_t address,
                                         FastApiCallbackOptions& options) {
    FastCApiObject* self = UnwrapObject(receiver);
    CHECK_SELF_OR_THROW_FAST_OPTIONS(false);
    self->fast_call_count_++;

    if (i::v8_flags.fuzzing) {
      return true;
    }
    v8::Isolate* isolate = receiver->GetIsolate();
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Context> context = isolate->GetCurrentContext();
    v8::Local<v8::String> mem_string =
        v8::String::NewFromUtf8(isolate, "wasm_memory").ToLocalChecked();
    v8::Local<v8::Value> mem;
    if (!receiver->Get(context, mem_string).ToLocal(&mem)) {
      isolate->ThrowError(
          "wasm_memory was used when the WebAssembly.Memory was not set on the "
          "receiver.");
    }

    v8::Local<v8::WasmMemoryObject> wasm_memory =
        mem.As<v8::WasmMemoryObject>();
    reinterpret_cast<uint8_t*>(wasm_memory->Buffer()->Data())[address] = 42;

    return true;
  }

  static void TestWasmMemorySlowCallback(
      const FunctionCallbackInfo<Value>& info) {
    DCHECK(i::ValidateCallbackInfo(info));
    FastCApiObject* self = UnwrapObject(info.This());
    CHECK_SELF_OR_THROW_SLOW();
    self->slow_call_count_++;

    info.GetIsolate()->ThrowError("should be unreachable from wasm");
  }

  static void AssertIsExternal(const FunctionCallbackInfo<Value>& info) {
    DCHECK(i::ValidateCallbackInfo(info));
    FastCApiObject* self = UnwrapObject(info.This());
    CHECK_SELF_OR_THROW_SLOW();

    Local<Value> value = info[0];

    if (!value->IsExternal()) {
      info.GetIsolate()->ThrowError("Did not get an external.");
    }
  }

  static void* GetPointerFastCallback(Local<Object> receiver,
                                      FastApiCallbackOptions& options) {
    FastCApiObject* self = UnwrapObject(receiver);
    CHECK_SELF_OR_THROW_FAST_OPTIONS(nullptr);
    self->fast_call_count_++;

    return static_cast<void*>(self);
  }

  static void GetPointerSlowCallback(const FunctionCallbackInfo<Value>& info) {
    DCHECK(i::ValidateCallbackInfo(info));
    Isolate* isolate = info.GetIsolate();
    FastCApiObject* self = UnwrapObject(info.This());
    CHECK_SELF_OR_THROW_SLOW();
    self->slow_call_count_++;

    info.GetReturnValue().Set(External::New(isolate, static_cast<void*>(self)));
  }

  static void* GetNullPointerFastCallback(Local<Object> receiver,
                                          FastApiCallbackOptions& options) {
    FastCApiObject* self = UnwrapObject(receiver);
    CHECK_SELF_OR_THROW_FAST_OPTIONS(nullptr);
    self->fast_call_count_++;

    return nullptr;
  }

  static void GetNullPointerSlowCallback(
      const FunctionCallbackInfo<Value>& info) {
    DCHECK(i::ValidateCallbackInfo(info));
    Isolate* isolate = info.GetIsolate();
    FastCApiObject* self = UnwrapObject(info.This());
    CHECK_SELF_OR_THROW_SLOW();
    self->slow_call_count_++;

    info.GetReturnValue().Set(v8::Null(isolate));
  }

  static void* PassPointerFastCallback(Local<Object> receiver, void* pointer,
                                       FastApiCallbackOptions& options) {
    FastCApiObject* self = UnwrapObject(receiver);
    CHECK_SELF_OR_THROW_FAST_OPTIONS(nullptr);
    self->fast_call_count_++;

    return pointer;
  }

  static void PassPointerSlowCallback(const FunctionCallbackInfo<Value>& info) {
    DCHECK(i::ValidateCallbackInfo(info));
    FastCApiObject* self = UnwrapObject(info.This());
    CHECK_SELF_OR_THROW_SLOW();
    self->slow_call_count_++;

    if (info.Length() != 1) {
      info.GetIsolate()->ThrowError(
          "Invalid number of arguments, expected one.");
      return;
    }

    Local<Value> maybe_external = info[0].As<Value>();

    if (maybe_external->IsNull()) {
      info.GetReturnValue().Set(maybe_external);
      return;
    }
    if (!maybe_external->IsExternal()) {
      info.GetIsolate()->ThrowError("Did not get an external.");
      return;
    }

    Local<External> external = info[0].As<External>();

    info.GetReturnValue().Set(external);
  }

  static bool ComparePointersFastCallback(Local<Object> receiver,
                                          void* pointer_a, void* pointer_b,
                                          FastApiCallbackOptions& options) {
    FastCApiObject* self = UnwrapObject(receiver);
    CHECK_SELF_OR_THROW_FAST_OPTIONS(false);
    self->fast_call_count_++;

    return pointer_a == pointer_b;
  }

  static void ComparePointersSlowCallback(
      const FunctionCallbackInfo<Value>& info) {
    DCHECK(i::ValidateCallbackInfo(info));
    FastCApiObject* self = UnwrapObject(info.This());
    CHECK_SELF_OR_THROW_SLOW();
    self->slow_call_count_++;

    if (info.Length() != 2) {
      info.GetIsolate()->ThrowError(
          "Invalid number of arguments, expected two.");
      return;
    }

    Local<Value> value_a = info[0];
    Local<Value> value_b = info[1];

    void* pointer_a;
    if (value_a->IsNull()) {
      pointer_a = nullptr;
    } else if (value_a->IsExternal()) {
      pointer_a = value_a.As<External>()->Value();
    } else {
      info.GetIsolate()->ThrowError(
          "Did not get an external as first parameter.");
      return;
    }

    void* pointer_b;
    if (value_b->IsNull()) {
      pointer_b = nullptr;
    } else if (value_b->IsExternal()) {
      pointer_b = value_b.As<External>()->Value();
    } else {
      info.GetIsolate()->ThrowError(
          "Did not get an external as second parameter.");
      return;
    }

    info.GetReturnValue().Set(pointer_a == pointer_b);
  }

  static int64_t sumInt64FastCallback(Local<Object> receiver, int64_t a,
                                      int64_t b,
                                      FastApiCallbackOptions& options) {
    FastCApiObject* self = UnwrapObject(receiver);
    CHECK_SELF_OR_THROW_FAST_OPTIONS(0);
    self->fast_call_count_++;

    return a + b;
  }

  template <typename T>
  static bool Convert(double value, T* out_result) {
    if (!base::IsValueInRangeForNumericType<T>(value)) return false;
    *out_result = static_cast<T>(value);
    return true;
  }

  static void sumInt64AsNumberSlowCallback(
      const FunctionCallbackInfo<Value>& info) {
    Isolate* isolate = info.GetIsolate();
    FastCApiObject* self = UnwrapObject(info.This());
    CHECK_SELF_OR_THROW_SLOW();
    self->slow_call_count_++;

    if (info.Length() != 2) {
      info.GetIsolate()->ThrowError(
          "Invalid number of arguments, expected two.");
      return;
    }

    Local<Value> value_a = info[0];
    Local<Value> value_b = info[1];

    if (!value_a->IsNumber()) {
      info.GetIsolate()->ThrowError("Did not get a number as first parameter.");
      return;
    }
    int64_t a;
    if (!Convert(value_a.As<Number>()->Value(), &a)) {
      info.GetIsolate()->ThrowError("First number is out of int64_t range.");
      return;
    }

    if (!value_b->IsNumber()) {
      info.GetIsolate()->ThrowError(
          "Did not get a number as second parameter.");
      return;
    }
    int64_t b;
    if (!Convert(value_b.As<Number>()->Value(), &b)) {
      info.GetIsolate()->ThrowError("Second number is out of int64_t range.");
      return;
    }

    info.GetReturnValue().Set(Number::New(isolate, static_cast<double>(a + b)));
  }

  static void sumInt64AsBigIntSlowCallback(
      const FunctionCallbackInfo<Value>& info) {
    Isolate* isolate = info.GetIsolate();
    FastCApiObject* self = UnwrapObject(info.This());
    CHECK_SELF_OR_THROW_SLOW();
    self->slow_call_count_++;

    if (info.Length() != 2) {
      info.GetIsolate()->ThrowError(
          "Invalid number of arguments, expected two.");
      return;
    }

    Local<Value> value_a = info[0];
    Local<Value> value_b = info[1];

    int64_t a;
    if (value_a->IsBigInt()) {
      a = static_cast<int64_t>(value_a.As<BigInt>()->Int64Value());
    } else {
      info.GetIsolate()->ThrowError("Did not get a BigInt as first parameter.");
      return;
    }

    int64_t b;
    if (value_b->IsBigInt()) {
      b = static_cast<int64_t>(value_b.As<BigInt>()->Int64Value());
    } else {
      info.GetIsolate()->ThrowError(
          "Did not get a BigInt as second parameter.");
      return;
    }

    info.GetReturnValue().Set(BigInt::New(isolate, a + b));
  }

  static uint64_t sumUint64FastCallback(Local<Object> receiver, uint64_t a,
                                        uint64_t b,
                                        FastApiCallbackOptions& options) {
    FastCApiObject* self = UnwrapObject(receiver);
    CHECK_SELF_OR_THROW_FAST_OPTIONS(0);
    self->fast_call_count_++;
    // This CHECK here is unnecessary, but it keeps this function from getting
    // merged with `sumInt64FastCallback`. There is a test which relies on
    // `sumUint64FastCallback` and `sumInt64FastCallback` being different call
    // targets.
    CHECK_GT(self->fast_call_count_, 0);
    return a + b;
  }

  static void sumUint64AsNumberSlowCallback(
      const FunctionCallbackInfo<Value>& info) {
    Isolate* isolate = info.GetIsolate();
    FastCApiObject* self = UnwrapObject(info.This());
    CHECK_SELF_OR_THROW_SLOW();
    self->slow_call_count_++;

    if (info.Length() != 2) {
      info.GetIsolate()->ThrowError(
          "Invalid number of arguments, expected two.");
      return;
    }

    Local<Value> value_a = info[0];
    Local<Value> value_b = info[1];

    if (!value_a->IsNumber()) {
      info.GetIsolate()->ThrowError("Did not get a number as first parameter.");
      return;
    }
    uint64_t a;
    if (!Convert(value_a.As<Number>()->Value(), &a)) {
      info.GetIsolate()->ThrowError("First number is out of uint64_t range.");
      return;
    }

    if (!value_b->IsNumber()) {
      info.GetIsolate()->ThrowError(
          "Did not get a number as second parameter.");
      return;
    }
    uint64_t b;
    if (!Convert(value_b.As<Number>()->Value(), &b)) {
      info.GetIsolate()->ThrowError("Second number is out of uint64_t range.");
      return;
    }

    info.GetReturnValue().Set(Number::New(isolate, static_cast<double>(a + b)));
  }

  static void sumUint64AsBigIntSlowCallback(
      const FunctionCallbackInfo<Value>& info) {
    Isolate* isolate = info.GetIsolate();
    FastCApiObject* self = UnwrapObject(info.This());
    CHECK_SELF_OR_THROW_SLOW();
    self->slow_call_count_++;

    if (info.Length() != 2) {
      info.GetIsolate()->ThrowError(
          "Invalid number of arguments, expected two.");
      return;
    }

    Local<Value> value_a = info[0];
    Local<Value> value_b = info[1];

    uint64_t a;
    if (value_a->IsBigInt()) {
      a = static_cast<uint64_t>(value_a.As<BigInt>()->Uint64Value());
    } else {
      info.GetIsolate()->ThrowError("Did not get a BigInt as first parameter.");
      return;
    }

    uint64_t b;
    if (value_b->IsBigInt()) {
      b = static_cast<uint64_t>(value_b.As<BigInt>()->Uint64Value());
    } else {
      info.GetIsolate()->ThrowError(
          "Did not get a BigInt as second parameter.");
      return;
    }

    info.GetReturnValue().Set(BigInt::NewFromUnsigned(isolate, a + b));
  }

  static void FastCallCount(const FunctionCallbackInfo<Value>& info) {
    FastCApiObject* self = UnwrapObject(info.This());
    CHECK_SELF_OR_THROW_SLOW();
    info.GetReturnValue().Set(
        Number::New(info.GetIsolate(), self->fast_call_count()));
  }
  static void SlowCallCount(const FunctionCallbackInfo<Value>& info) {
    DCHECK(i::ValidateCallbackInfo(info));
    FastCApiObject* self = UnwrapObject(info.This());
    CHECK_SELF_OR_THROW_SLOW();
    info.GetReturnValue().Set(
        Number::New(info.GetIsolate(), self->slow_call_count()));
  }
  static void ResetCounts(const FunctionCallbackInfo<Value>& info) {
    DCHECK(i::ValidateCallbackInfo(info));
    FastCApiObject* self = UnwrapObject(info.This());
    CHECK_SELF_OR_THROW_SLOW();
    self->reset_counts();
    info.GetReturnValue().Set(Undefined(info.GetIsolate()));
  }
  static void SupportsFPParams(const FunctionCallbackInfo<Value>& info) {
    DCHECK(i::ValidateCallbackInfo(info));
    FastCApiObject* self = UnwrapObject(info.This());
    CHECK_SELF_OR_THROW_SLOW();
    info.GetReturnValue().Set(self->supports_fp_params_);
  }

  int fast_call_count() const { return fast_call_count_; }
  int slow_call_count() const { return slow_call_count_; }
  void reset_counts() {
    fast_call_count_ = 0;
    slow_call_count_ = 0;
  }

  static const int kV8WrapperObjectIndex = 1;

 private:
  static bool IsValidApiObject(Local<Object> object) {
    if (object->IsInt32()) return false;
    auto instance_type = i::Internals::GetInstanceType(
        internal::ValueHelper::ValueAsAddress(*object));
    return (base::IsInRange(instance_type, i::Internals::kFirstJSApiObjectType,
                            i::Internals::kLastJSApiObjectType) ||
            instance_type == i::Internals::kJSSpecialApiObjectType);
  }
  static FastCApiObject* UnwrapObject(Local<Object> object) {
    if (!IsValidApiObject(object)) {
      return nullptr;
    }
    if (object->InternalFieldCount() <= kV8WrapperObjectIndex) {
      return nullptr;
    }
    FastCApiObject* wrapped = reinterpret_cast<FastCApiObject*>(
        object->GetAlignedPointerFromInternalField(kV8WrapperObjectIndex));
    CHECK_NOT_NULL(wrapped);
    return wrapped;
  }

  int fast_call_count_ = 0, slow_call_count_ = 0;
#ifdef V8_ENABLE_FP_PARAMS_IN_C_LINKAGE
  bool supports_fp_params_ = true;
#else   // V8_ENABLE_FP_PARAMS_IN_C_LINKAGE
  bool supports_fp_params_ = false;
#endif  // V8_ENABLE_FP_PARAMS_IN_C_LINKAGE
};

#undef CHECK_SELF_OR_THROW_SLOW
#undef CHECK_SELF_OR_THROW_FAST
#undef CHECK_SELF_OR_THROW_FAST_OPTIONS

// The object is statically initialized for simplicity, typically the embedder
// will take care of managing their C++ objects lifetime.
thread_local FastCApiObject kFastCApiObject;
}  // namespace

// static
FastCApiObject& FastCApiObject::instance() { return kFastCApiObject; }

void CreateFastCAPIObject(const FunctionCallbackInfo<Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  if (!info.IsConstructCall()) {
    info.GetIsolate()->ThrowError(
        "FastCAPI helper must be constructed with new.");
    return;
  }
  Local<Object> api_object = info.This();
  api_object->SetAlignedPointerInInternalField(
      FastCApiObject::kV8WrapperObjectIndex,
      reinterpret_cast<void*>(&kFastCApiObject));
  api_object->SetAccessorProperty(
      String::NewFromUtf8Literal(info.GetIsolate(), "supports_fp_params"),
      FunctionTemplate::New(info.GetIsolate(), FastCApiObject::SupportsFPParams)
          ->GetFunction(api_object->GetCreationContext(info.GetIsolate())
                            .ToLocalChecked())
          .ToLocalChecked());
}

Local<FunctionTemplate> Shell::CreateTestFastCApiTemplate(Isolate* isolate) {
  Local<FunctionTemplate> api_obj_ctor =
      FunctionTemplate::New(isolate, CreateFastCAPIObject);
  PerIsolateData::Get(isolate)->SetTestApiObjectCtor(api_obj_ctor);
  Local<Signature> signature = Signature::New(isolate, api_obj_ctor);
  {
    CFunction throw_no_fallback_func = CFunction::Make(
        FastCApiObject::ThrowNoFallbackFastCallback V8_IF_USE_SIMULATOR(
            FastCApiObject::ThrowNoFallbackFastCallbackPatch));
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "throw_no_fallback",
        FunctionTemplate::New(
            isolate, FastCApiObject::ThrowFallbackSlowCallback, Local<Value>(),
            Local<Signature>(), 1, ConstructorBehavior::kThrow,
            SideEffectType::kHasSideEffect, &throw_no_fallback_func));

    CFunction copy_str_func = CFunction::Make(
        FastCApiObject::CopyStringFastCallback V8_IF_USE_SIMULATOR(
            FastCApiObject::CopyStringFastCallbackPatch));
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "copy_string",
        FunctionTemplate::New(isolate, FastCApiObject::CopyStringSlowCallback,
                              Local<Value>(), signature, 1,
                              ConstructorBehavior::kThrow,
                              SideEffectType::kHasSideEffect, &copy_str_func));

    CFunction add_all_c_func =
        CFunction::Make(FastCApiObject::AddAllFastCallback V8_IF_USE_SIMULATOR(
            FastCApiObject::AddAllFastCallbackPatch));
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "add_all",
        FunctionTemplate::New(isolate, FastCApiObject::AddAllSlowCallback,
                              Local<Value>(), signature, 1,
                              ConstructorBehavior::kThrow,
                              SideEffectType::kHasSideEffect, &add_all_c_func));

    CFunction add_all_seq_c_func = CFunction::Make(
        FastCApiObject::AddAllSequenceFastCallback V8_IF_USE_SIMULATOR(
            FastCApiObject::AddAllSequenceFastCallbackPatch));
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "add_all_sequence",
        FunctionTemplate::New(
            isolate, FastCApiObject::AddAllSequenceSlowCallback, Local<Value>(),
            signature, 1, ConstructorBehavior::kThrow,
            SideEffectType::kHasSideEffect, &add_all_seq_c_func));

    CFunction add_all_uint8_typed_array_c_func = CFunction::Make(
        FastCApiObject::AddAllTypedArrayFastCallback<uint8_t>
            V8_IF_USE_SIMULATOR(
                FastCApiObject::AddAllTypedArrayFastCallbackPatch<uint8_t>));

    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "add_all_uint8_typed_array",
        FunctionTemplate::New(
            isolate, FastCApiObject::AddAllTypedArraySlowCallback,
            Local<Value>(), signature, 1, ConstructorBehavior::kThrow,
            SideEffectType::kHasSideEffect, &add_all_uint8_typed_array_c_func));

    CFunction add_all_int32_typed_array_c_func = CFunction::Make(
        FastCApiObject::AddAllTypedArrayFastCallback<int32_t>
            V8_IF_USE_SIMULATOR(
                FastCApiObject::AddAllTypedArrayFastCallbackPatch<int32_t>));

    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "add_all_int32_typed_array",
        FunctionTemplate::New(
            isolate, FastCApiObject::AddAllTypedArraySlowCallback,
            Local<Value>(), signature, 1, ConstructorBehavior::kThrow,
            SideEffectType::kHasSideEffect, &add_all_int32_typed_array_c_func));

    CFunction add_all_int64_typed_array_c_func = CFunction::Make(
        FastCApiObject::AddAllTypedArrayFastCallback<int64_t>
            V8_IF_USE_SIMULATOR(
                FastCApiObject::AddAllTypedArrayFastCallbackPatch<int64_t>));
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "add_all_int64_typed_array",
        FunctionTemplate::New(
            isolate, FastCApiObject::AddAllTypedArraySlowCallback,
            Local<Value>(), signature, 1, ConstructorBehavior::kThrow,
            SideEffectType::kHasSideEffect, &add_all_int64_typed_array_c_func));

    CFunction add_all_uint64_typed_array_c_func = CFunction::Make(
        FastCApiObject::AddAllTypedArrayFastCallback<uint64_t>
            V8_IF_USE_SIMULATOR(
                FastCApiObject::AddAllTypedArrayFastCallbackPatch<uint64_t>));
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "add_all_uint64_typed_array",
        FunctionTemplate::New(
            isolate, FastCApiObject::AddAllTypedArraySlowCallback,
            Local<Value>(), signature, 1, ConstructorBehavior::kThrow,
            SideEffectType::kHasSideEffect,
            &add_all_uint64_typed_array_c_func));

    CFunction add_all_uint32_typed_array_c_func = CFunction::Make(
        FastCApiObject::AddAllTypedArrayFastCallback<uint32_t>
            V8_IF_USE_SIMULATOR(
                FastCApiObject::AddAllTypedArrayFastCallbackPatch<uint32_t>));
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "add_all_uint32_typed_array",
        FunctionTemplate::New(
            isolate, FastCApiObject::AddAllTypedArraySlowCallback,
            Local<Value>(), signature, 1, ConstructorBehavior::kThrow,
            SideEffectType::kHasSideEffect,
            &add_all_uint32_typed_array_c_func));

    CFunction add_all_float32_typed_array_c_func = CFunction::Make(
        FastCApiObject::AddAllTypedArrayFastCallback<float> V8_IF_USE_SIMULATOR(
            FastCApiObject::AddAllTypedArrayFastCallbackPatch<float>));
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "add_all_float32_typed_array",
        FunctionTemplate::New(
            isolate, FastCApiObject::AddAllTypedArraySlowCallback,
            Local<Value>(), signature, 1, ConstructorBehavior::kThrow,
            SideEffectType::kHasSideEffect,
            &add_all_float32_typed_array_c_func));

    CFunction add_all_no_options_c_func = CFunction::Make(
        FastCApiObject::AddAllFastCallbackNoOptions V8_IF_USE_SIMULATOR(
            FastCApiObject::AddAllFastCallbackNoOptionsPatch),
        CFunctionInfo::Int64Representation::kBigInt);
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "add_all_no_options",
        FunctionTemplate::New(
            isolate, FastCApiObject::AddAllSlowCallback, Local<Value>(),
            Local<Signature>(), 1, ConstructorBehavior::kThrow,
            SideEffectType::kHasSideEffect, &add_all_no_options_c_func));

    CFunction add_all_float64_typed_array_c_func = CFunction::Make(
        FastCApiObject::AddAllTypedArrayFastCallback<double>
            V8_IF_USE_SIMULATOR(
                FastCApiObject::AddAllTypedArrayFastCallbackPatch<double>));
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "add_all_float64_typed_array",
        FunctionTemplate::New(
            isolate, FastCApiObject::AddAllTypedArraySlowCallback,
            Local<Value>(), signature, 1, ConstructorBehavior::kThrow,
            SideEffectType::kHasSideEffect,
            &add_all_float64_typed_array_c_func));

    const CFunction add_all_overloads[] = {
        add_all_seq_c_func,
        add_all_no_options_c_func,
    };
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "add_all_overload",
        FunctionTemplate::NewWithCFunctionOverloads(
            isolate, FastCApiObject::AddAllSequenceSlowCallback, Local<Value>(),
            signature, 1, ConstructorBehavior::kThrow,
            SideEffectType::kHasSideEffect, {add_all_overloads, 2}));

    CFunction add_all_32bit_int_8args_c_func = CFunction::Make(
        FastCApiObject::AddAll32BitIntFastCallback_8Args V8_IF_USE_SIMULATOR(
            FastCApiObject::AddAll32BitIntFastCallback_8ArgsPatch));
    CFunction add_all_32bit_int_6args_c_func = CFunction::Make(
        FastCApiObject::AddAll32BitIntFastCallback_6Args V8_IF_USE_SIMULATOR(
            FastCApiObject::AddAll32BitIntFastCallback_6ArgsPatch));
    CFunction add_all_32bit_int_5args_c_func = CFunction::Make(
        FastCApiObject::AddAll32BitIntFastCallback_5Args V8_IF_USE_SIMULATOR(
            FastCApiObject::AddAll32BitIntFastCallback_5ArgsPatch));
    const CFunction c_function_overloads[] = {add_all_32bit_int_6args_c_func,
                                              add_all_32bit_int_5args_c_func};

    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "overloaded_add_all_32bit_int",
        FunctionTemplate::NewWithCFunctionOverloads(
            isolate, FastCApiObject::AddAll32BitIntSlowCallback, Local<Value>(),
            signature, 1, ConstructorBehavior::kThrow,
            SideEffectType::kHasSideEffect, {c_function_overloads, 2}));

    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "overloaded_add_all_8args",
        FunctionTemplate::New(
            isolate, FastCApiObject::AddAll32BitIntSlowCallback, Local<Value>(),
            signature, 1, ConstructorBehavior::kThrow,
            SideEffectType::kHasSideEffect, &add_all_32bit_int_8args_c_func));

    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "overloaded_add_all_32bit_int_no_sig",
        FunctionTemplate::NewWithCFunctionOverloads(
            isolate, FastCApiObject::AddAll32BitIntSlowCallback, Local<Value>(),
            Local<Signature>(), 1, ConstructorBehavior::kThrow,
            SideEffectType::kHasSideEffect, {c_function_overloads, 2}));

    CFunction add_32bit_int_c_func = CFunction::Make(
        FastCApiObject::Add32BitIntFastCallback V8_IF_USE_SIMULATOR(
            FastCApiObject::Add32BitIntFastCallbackPatch));
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "add_32bit_int",
        FunctionTemplate::New(
            isolate, FastCApiObject::Add32BitIntSlowCallback, Local<Value>(),
            signature, 1, ConstructorBehavior::kThrow,
            SideEffectType::kHasSideEffect, &add_32bit_int_c_func));

    CFunction add_all_annotate_c_func = CFunction::Make(
        FastCApiObject::AddAllAnnotateFastCallback<
            v8::CTypeInfo::Flags::kEnforceRangeBit>
            V8_IF_USE_SIMULATOR(FastCApiObject::AddAllAnnotateFastCallbackPatch<
                                v8::CTypeInfo::Flags::kEnforceRangeBit>));
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "add_all_annotate_enforce_range",
        FunctionTemplate::New(
            isolate, FastCApiObject::AddAllAnnotateSlowCallback, Local<Value>(),
            signature, 1, ConstructorBehavior::kThrow,
            SideEffectType::kHasSideEffect, &add_all_annotate_c_func));

    // Testing enforce range annotation.

    CFunction enforce_range_compare_i32_c_func =
        CFunctionBuilder()
            .Fn(FastCApiObject::EnforceRangeCompare<int32_t>)
            .Arg<2, v8::CTypeInfo::Flags::kEnforceRangeBit>()
#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
            .Patch(FastCApiObject::EnforceRangeCompareI32Patch)
#endif  // V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
            .Build();
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "enforce_range_compare_i32",
        FunctionTemplate::New(
            isolate, FastCApiObject::EnforceRangeCompareSlowCallback<int32_t>,
            Local<Value>(), signature, 1, ConstructorBehavior::kThrow,
            SideEffectType::kHasSideEffect, &enforce_range_compare_i32_c_func));

    CFunction enforce_range_compare_u32_c_func =
        CFunctionBuilder()
            .Fn(FastCApiObject::EnforceRangeCompare<uint32_t>)
            .Arg<2, v8::CTypeInfo::Flags::kEnforceRangeBit>()
#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
            .Patch(FastCApiObject::EnforceRangeCompareU32Patch)
#endif  // V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
            .Build();
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "enforce_range_compare_u32",
        FunctionTemplate::New(
            isolate, FastCApiObject::EnforceRangeCompareSlowCallback<uint32_t>,
            Local<Value>(), signature, 1, ConstructorBehavior::kThrow,
            SideEffectType::kHasSideEffect, &enforce_range_compare_u32_c_func));

    CFunction enforce_range_compare_i64_c_func =
        CFunctionBuilder()
            .Fn(FastCApiObject::EnforceRangeCompare<int64_t>)
            .Arg<2, v8::CTypeInfo::Flags::kEnforceRangeBit>()
#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
            .Patch(FastCApiObject::EnforceRangeCompareI64Patch)
#endif  // V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
            .Build();
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "enforce_range_compare_i64",
        FunctionTemplate::New(
            isolate, FastCApiObject::EnforceRangeCompareSlowCallback<int64_t>,
            Local<Value>(), signature, 1, ConstructorBehavior::kThrow,
            SideEffectType::kHasSideEffect, &enforce_range_compare_i64_c_func));

    CFunction enforce_range_compare_u64_c_func =
        CFunctionBuilder()
            .Fn(FastCApiObject::EnforceRangeCompare<uint64_t>)
            .Arg<2, v8::CTypeInfo::Flags::kEnforceRangeBit>()
#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
            .Patch(FastCApiObject::EnforceRangeCompareU64Patch)
#endif  // V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
            .Build();
    api_obj_ctor->PrototypeTemplate()->Set(
        isolate, "enforce_range_compare_u64",
        FunctionTemplate::New(
            isolate, FastCApiObject::EnforceRangeCompareSlowCallback<uint64_t>,
            Local<Value>(), signature, 1, ConstructorBehavior::kThrow,
            SideEffectType::kHasSideEffect, &enforce_range_compare_u64_c_func));

    // Testing clamp annotation.

    CFunction clamp_compare_i32_c_func =
        CFunctionBuilder()
            .Fn(FastCApiObject::ClampCompare<int32_t>)
            .Arg<3, v8::CTypeInfo::Flags::kClampBit>()
#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
            .Patc
```