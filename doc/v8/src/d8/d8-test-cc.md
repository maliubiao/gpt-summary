Response:
The user wants to understand the functionality of the provided C++ code snippet, which is a part of the V8 JavaScript engine. The file `v8/src/d8/d8-test.cc` seems to be related to testing the "fast API calls" feature in V8.

Here's a plan to address the user's request:

1. **Identify the core functionality:** Based on the comments and class names, the primary goal is to test fast C API calls in V8. This includes invoking C++ functions from JavaScript and observing the behavior.

2. **Analyze the `FastCApiObject` class:** This class seems to encapsulate the C++ functions that are intended to be called from JavaScript. Pay attention to the "FastCallback" and "SlowCallback" suffixes, which likely indicate different execution paths.

3. **Explain the purpose of the macros:**  `CHECK_SELF_OR_THROW_FAST_OPTIONS`, `CHECK_SELF_OR_THROW_FAST`, and `CHECK_SELF_OR_THROW_SLOW` are used for error handling when the `this` pointer is null, suggesting these methods are meant to be called on instances of `FastCApiObject`.

4. **Illustrate with JavaScript examples:** For each C++ function, create a corresponding JavaScript example demonstrating how it might be invoked and what the expected behavior is.

5. **Demonstrate code logic and input/output:** For functions with clear logic (like `AddAllFastCallback`), provide example inputs and expected outputs.

6. **Highlight potential programming errors:** Identify common mistakes users might make when interacting with these APIs (e.g., incorrect argument types, array sizes).

7. **Address the `.tq` file check:** Explain that `.tq` files are for Torque, a V8-specific language for implementing built-in functions. This file is `.cc`, so it's C++, not Torque.

8. **Summarize the functionality:**  Provide a concise summary of the file's purpose based on the analysis.
好的，根据你提供的 V8 源代码 `v8/src/d8/d8-test.cc` 的片段，我可以归纳一下它的功能：

**功能归纳：**

这个 C++ 文件 (`v8/src/d8/d8-test.cc`) 的主要功能是为 V8 的 d8 测试框架提供对 **快速 C API 调用 (Fast API Calls)** 的测试支持。它定义了一个名为 `FastCApiObject` 的 C++ 类，该类包含了一系列静态方法，这些方法可以被 JavaScript 代码通过特定的 V8 机制（Fast API Calls）快速调用。

**详细功能点：**

1. **提供测试基础设施:**  该文件创建了一个可以在 JavaScript 中访问的对象 (`d8.test.fast_c_api`)，用于测试 Fast API Calls 的功能。

2. **模拟快速和慢速 C API 调用:**  `FastCApiObject` 类中定义了多种静态方法，分别模拟了快速调用（以 `FastCallback` 结尾）和慢速调用（以 `SlowCallback` 结尾）两种场景。

3. **异常处理测试:**  一些方法（例如 `ThrowNoFallbackFastCallback` 和 `ThrowFallbackSlowCallback`) 故意抛出异常，用于测试 Fast API Calls 的异常处理机制。

4. **参数传递测试:**  其他方法用于测试不同类型的参数如何在 JavaScript 和 C++ 之间传递，例如：
   - 基本类型 (int32_t, uint32_t, int64_t, uint64_t, float, double)
   - 字符串 (`FastOneByteString`)
   - 对象 (`Local<Object>`)
   - 数组 (`Local<Array>`) 和类型化数组 (`Local<TypedArray>`)
   - `FastApiCallbackOptions` (用于传递调用选项)

5. **计数器功能:** `FastCApiObject` 内部维护了 `fast_call_count_` 和 `slow_call_count_` 成员变量，用于记录快速和慢速调用的次数。JavaScript 代码可以通过 `d8.test.fast_c_api` 对象查询和重置这些计数器。

6. **模拟不同的 Fast API 调用签名:**  文件中定义了具有不同参数数量和类型的 Fast Callback，用于测试 V8 对各种 Fast API 调用签名的支持。

**关于文件后缀和 Torque：**

你提到如果 `v8/src/d8/d8-test.cc` 以 `.tq` 结尾，那它就是一个 V8 Torque 源代码。这是一个正确的判断。然而，这个文件以 `.cc` 结尾，所以它是一个标准的 C++ 源代码文件，而不是 Torque 文件。

**与 JavaScript 功能的关系及举例：**

`v8/src/d8/d8-test.cc` 中的代码旨在测试 V8 的 Fast API Calls 功能，这允许 JavaScript 代码以更高效的方式调用 C++ 函数。

**JavaScript 示例：**

假设 V8 内部将 `FastCApiObject` 的实例暴露为 `d8.test.fast_c_api` 对象，并且其中一个方法 `AddAllFastCallbackNoOptions` 被绑定到一个名为 `addAllNoOptions` 的属性上，那么你可以像这样在 JavaScript 中调用它：

```javascript
// 假设已经初始化了 d8 环境

// 调用一个没有选项参数的快速 C API 回调
let result = d8.test.fast_c_api.addAllNoOptions(1, 2, 3, 4, 5.5, 6.6);
console.log(result); // 输出计算结果

// 调用一个会抛出异常的快速 C API 回调
try {
  d8.test.fast_c_api.throwNoFallback();
} catch (e) {
  console.log(e.message); // 输出 "Exception from fast callback"
}

// 获取快速和慢速调用计数
console.log(d8.test.fast_c_api.fastCallCount);
console.log(d8.test.fast_c_api.slowCallCount);

// 重置计数器
d8.test.fast_c_api.resetCounters();
```

**代码逻辑推理及假设输入与输出：**

以 `AddAllFastCallbackNoOptions` 方法为例：

```c++
  static double AddAllFastCallbackNoOptions(Local<Object> receiver,
                                            int32_t arg_i32, uint32_t arg_u32,
                                            int64_t arg_i64, uint64_t arg_u64,
                                            float arg_f32, double arg_f64) {
    FastCApiObject* self = UnwrapObject(receiver);
    if (!self) {
      self = &FastCApiObject::instance();
    }
    self->fast_call_count_++;

    return static_cast<double>(arg_i32) + static_cast<double>(arg_u32) +
           static_cast<double>(arg_i64) + static_cast<double>(arg_u64) +
           static_cast<double>(arg_f32) + arg_f64;
  }
```

**假设输入：**

- `arg_i32`: -10
- `arg_u32`: 20
- `arg_i64`: -30
- `arg_u64`: 40
- `arg_f32`: 50.5
- `arg_f64`: 60.6

**预期输出：**

```
-10.0 + 20.0 + -30.0 + 40.0 + 50.5 + 60.6 = 131.1
```

**涉及用户常见的编程错误：**

1. **参数类型不匹配:**  在 JavaScript 中调用 Fast API 时，如果传递的参数类型与 C++ 函数期望的类型不匹配，可能会导致错误或类型转换问题。例如，C++ 期望一个 `int32_t`，但 JavaScript 传递了一个字符串。

   ```javascript
   // 假设 addAllNoOptions 期望第一个参数是 int32
   // 错误的调用，传递了字符串
   d8.test.fast_c_api.addAllNoOptions("hello", 2, 3, 4, 5.5, 6.6);
   ```

2. **参数数量错误:**  Fast API 调用需要精确匹配 C++ 函数的参数数量。

   ```javascript
   // 错误的调用，参数太少
   d8.test.fast_c_api.addAllNoOptions(1, 2, 3, 4, 5.5);
   ```

3. **类型化数组使用不当:**  对于接受类型化数组的方法，确保传递的是正确的类型化数组，并且长度和元素类型符合预期。

   ```javascript
   // 假设 copyStringFastCallback 期望第二个参数是 Uint8Array
   let notUint8Array = [1, 2, 3];
   let uint8Array = new Uint8Array(10);
   try {
       d8.test.fast_c_api.copyString("source", notUint8Array, uint8Array); // 错误：类型不匹配
   } catch (e) {
       console.error(e.message);
   }
   ```

4. **未处理异常:** 如果 Fast API 调用可能抛出异常，JavaScript 代码需要使用 `try...catch` 块来捕获和处理这些异常。

   ```javascript
   try {
       d8.test.fast_c_api.potentiallyThrowingFunction();
   } catch (error) {
       console.error("Fast API 调用发生错误:", error.message);
   }
   ```

这只是对提供的代码片段的功能的初步分析和归纳。要完全理解其功能，需要结合 V8 引擎的 Fast API Calls 机制以及 d8 测试框架的上下文进行更深入的研究。

Prompt: 
```
这是目录为v8/src/d8/d8-test.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/d8/d8-test.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/d8/d8.h"

#include "include/v8-fast-api-calls.h"
#include "include/v8-template.h"
#include "src/api/api-inl.h"

// This file exposes a d8.test.fast_c_api object, which adds testing facility
// for writing mjsunit tests that exercise fast API calls.
// The fast_c_api object also supports querying the number of fast/slow calls
// and resetting these counters.

namespace v8 {
namespace {

#define CHECK_SELF_OR_THROW_FAST_OPTIONS(return_value)                      \
  if (!self) {                                                              \
    HandleScope handle_scope(options.isolate);                              \
    options.isolate->ThrowError(                                            \
        "This method is not defined on objects inheriting from FastCAPI."); \
    return return_value;                                                    \
  }

#define CHECK_SELF_OR_THROW_FAST(return_value)                              \
  if (!self) {                                                              \
    receiver->GetIsolate()->ThrowError(                                     \
        "This method is not defined on objects inheriting from FastCAPI."); \
    return return_value;                                                    \
  }

#define CHECK_SELF_OR_THROW_SLOW()                                          \
  if (!self) {                                                              \
    info.GetIsolate()->ThrowError(                                          \
        "This method is not defined on objects inheriting from FastCAPI."); \
    return;                                                                 \
  }

class FastCApiObject {
 public:
  static FastCApiObject& instance();

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
  static AnyCType ThrowNoFallbackFastCallbackPatch(AnyCType receiver) {
    AnyCType ret;
    ThrowNoFallbackFastCallback(receiver.object_value);
    return ret;
  }

#endif  //  V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS

  static int ThrowNoFallbackFastCallback(Local<Object> receiver) {
    FastCApiObject* self = UnwrapObject(receiver);
    if (!self) {
      self = &FastCApiObject::instance();
    }
    self->fast_call_count_++;
    v8::Isolate* isolate = v8::Isolate::GetCurrent();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> context = isolate->GetCurrentContext();
    v8::Context::Scope context_scope(context);
    isolate->ThrowError("Exception from fast callback");
    return 0;
  }

  static void ThrowFallbackSlowCallback(
      const FunctionCallbackInfo<Value>& info) {
    DCHECK(i::ValidateCallbackInfo(info));
    FastCApiObject* self = UnwrapObject(info.This());
    CHECK_SELF_OR_THROW_SLOW();
    self->slow_call_count_++;

    info.GetIsolate()->ThrowError("Exception from slow callback");
  }

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
  static AnyCType CopyStringFastCallbackPatch(AnyCType receiver,
                                              AnyCType source, AnyCType out,
                                              AnyCType options) {
    AnyCType ret;
    CopyStringFastCallback(receiver.object_value, *source.string_value,
                           out.object_value, *options.options_value);
    return ret;
  }

#endif  //  V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
  static void CopyStringFastCallback(Local<Object> receiver,
                                     const FastOneByteString& source,
                                     Local<Object> out,
                                     FastApiCallbackOptions& options) {
    FastCApiObject* self = UnwrapObject(receiver);
    self->fast_call_count_++;

    HandleScope handle_scope(options.isolate);
    if (!out->IsUint8Array()) {
      options.isolate->ThrowError(
          "Invalid parameter, the second parameter has to be a a Uint8Array.");
      return;
    }
    Local<Uint8Array> array = out.As<Uint8Array>();
    if (array->Length() < source.length) {
      options.isolate->ThrowError(
          "Invalid parameter, destination array is too small.");
      return;
    }
    uint8_t* memory =
        reinterpret_cast<uint8_t*>(out.As<Uint8Array>()->Buffer()->Data());
    memcpy(memory, source.data, source.length);
  }

  static void CopyStringSlowCallback(const FunctionCallbackInfo<Value>& info) {
    FastCApiObject* self = UnwrapObject(info.This());
    CHECK_SELF_OR_THROW_SLOW();
    self->slow_call_count_++;
  }
#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
  static AnyCType AddAllFastCallbackPatch(AnyCType receiver,
                                          AnyCType arg_i32, AnyCType arg_u32,
                                          AnyCType arg_i64, AnyCType arg_u64,
                                          AnyCType arg_f32, AnyCType arg_f64,
                                          AnyCType options) {
    AnyCType ret;
    ret.double_value = AddAllFastCallback(
        receiver.object_value, arg_i32.int32_value, arg_u32.uint32_value,
        arg_i64.int64_value, arg_u64.uint64_value, arg_f32.float_value,
        arg_f64.double_value, *options.options_value);
    return ret;
  }

#endif  //  V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
  static double AddAllFastCallback(Local<Object> receiver, int32_t arg_i32,
                                   uint32_t arg_u32, int64_t arg_i64,
                                   uint64_t arg_u64, float arg_f32,
                                   double arg_f64,
                                   FastApiCallbackOptions& options) {
    FastCApiObject* self = UnwrapObject(receiver);
    CHECK_SELF_OR_THROW_FAST_OPTIONS(0);
    self->fast_call_count_++;

    return static_cast<double>(arg_i32) + static_cast<double>(arg_u32) +
           static_cast<double>(arg_i64) + static_cast<double>(arg_u64) +
           static_cast<double>(arg_f32) + arg_f64;
  }

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
  static AnyCType AddAllFastCallbackNoOptionsPatch(
      AnyCType receiver, AnyCType arg_i32, AnyCType arg_u32, AnyCType arg_i64,
      AnyCType arg_u64, AnyCType arg_f32, AnyCType arg_f64) {
    AnyCType ret;
    ret.double_value = AddAllFastCallbackNoOptions(
        receiver.object_value, arg_i32.int32_value, arg_u32.uint32_value,
        arg_i64.int64_value, arg_u64.uint64_value, arg_f32.float_value,
        arg_f64.double_value);
    return ret;
  }
#endif  //  V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
  static double AddAllFastCallbackNoOptions(Local<Object> receiver,
                                            int32_t arg_i32, uint32_t arg_u32,
                                            int64_t arg_i64, uint64_t arg_u64,
                                            float arg_f32, double arg_f64) {
    FastCApiObject* self = UnwrapObject(receiver);
    if (!self) {
      self = &FastCApiObject::instance();
    }
    self->fast_call_count_++;

    return static_cast<double>(arg_i32) + static_cast<double>(arg_u32) +
           static_cast<double>(arg_i64) + static_cast<double>(arg_u64) +
           static_cast<double>(arg_f32) + arg_f64;
  }

  static void AddAllSlowCallback(const FunctionCallbackInfo<Value>& info) {
    Isolate* isolate = info.GetIsolate();

    FastCApiObject* self = UnwrapObject(info.This());
    CHECK_SELF_OR_THROW_SLOW();
    self->slow_call_count_++;

    HandleScope handle_scope(isolate);

    double sum = 0;
    if (info.Length() > 0 && info[0]->IsNumber()) {
      sum += info[0]->Int32Value(isolate->GetCurrentContext()).FromJust();
    }
    if (info.Length() > 1 && info[1]->IsNumber()) {
      sum += info[1]->Uint32Value(isolate->GetCurrentContext()).FromJust();
    }
    if (info.Length() > 2 && info[2]->IsNumber()) {
      sum += info[2]->IntegerValue(isolate->GetCurrentContext()).FromJust();
    }
    if (info.Length() > 3 && info[3]->IsNumber()) {
      sum += info[3]->IntegerValue(isolate->GetCurrentContext()).FromJust();
    }
    if (info.Length() > 4 && info[4]->IsNumber()) {
      sum += info[4]->NumberValue(isolate->GetCurrentContext()).FromJust();
    } else {
      sum += std::numeric_limits<double>::quiet_NaN();
    }
    if (info.Length() > 5 && info[5]->IsNumber()) {
      sum += info[5]->NumberValue(isolate->GetCurrentContext()).FromJust();
    } else {
      sum += std::numeric_limits<double>::quiet_NaN();
    }

    info.GetReturnValue().Set(Number::New(isolate, sum));
  }

#ifdef V8_ENABLE_FP_PARAMS_IN_C_LINKAGE
  typedef double Type;
#else
  typedef int32_t Type;
#endif  // V8_ENABLE_FP_PARAMS_IN_C_LINKAGE
#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
  static AnyCType AddAllSequenceFastCallbackPatch(AnyCType receiver,
                                                  AnyCType seq_arg,
                                                  AnyCType options) {
    AnyCType ret;
#ifdef V8_ENABLE_FP_PARAMS_IN_C_LINKAGE
    ret.double_value = AddAllSequenceFastCallback(
        receiver.object_value, seq_arg.sequence_value, *options.options_value);
#else
    ret.int32_value = AddAllSequenceFastCallback(
        receiver.object_value, seq_arg.sequence_value, *options.options_value);
#endif  // V8_ENABLE_FP_PARAMS_IN_C_LINKAGE
    return ret;
  }
#endif  //  V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS

  static Type AddAllSequenceJSArrayHelper(v8::Isolate* isolate,
                                          Local<Array> seq_arg) {
    Type sum = 0;
    uint32_t length = seq_arg->Length();
    if (length > 1024) {
      isolate->ThrowError(
          "Invalid length of array, must be between 0 and 1024.");
      return sum;
    }

    for (uint32_t i = 0; i < length; ++i) {
      v8::MaybeLocal<v8::Value> maybe_element =
          seq_arg->Get(isolate->GetCurrentContext(),
                       v8::Integer::NewFromUnsigned(isolate, i));
      if (maybe_element.IsEmpty()) return sum;

      v8::Local<v8::Value> element = maybe_element.ToLocalChecked();
      if (element->IsNumber()) {
        double value = element->ToNumber(isolate->GetCurrentContext())
                           .ToLocalChecked()
                           ->Value();
        sum += value;
      } else if (element->IsUndefined()) {
        // Hole: ignore the element.
      } else {
        isolate->ThrowError("unexpected element type in JSArray");
        return sum;
      }
    }
    return sum;
  }

  static Type AddAllSequenceFastCallback(Local<Object> receiver,
                                         Local<Object> seq_arg,
                                         FastApiCallbackOptions& options) {
    if (seq_arg->IsUint32Array()) {
      return AddAllTypedArrayFastCallback<uint32_t>(receiver, seq_arg, options);
    }

    FastCApiObject* self = UnwrapObject(receiver);
    CHECK_SELF_OR_THROW_FAST_OPTIONS(0);
    self->fast_call_count_++;

    HandleScope handle_scope(options.isolate);
    if (!seq_arg->IsArray()) {
      options.isolate->ThrowError(
          "This method expects an array as a first argument.");
      return 0;
    }
    Local<Array> array = seq_arg.As<Array>();
    uint32_t length = array->Length();
    if (length > 1024) {
      receiver->GetIsolate()->ThrowError(
          "Invalid length of array, must be between 0 and 1024.");
      return 0;
    }

    Type buffer[1024];
    bool result = TryToCopyAndConvertArrayToCppBuffer<
        CTypeInfoBuilder<Type>::Build().GetId(), Type>(array, buffer, 1024);
    if (!result) {
      return AddAllSequenceJSArrayHelper(receiver->GetIsolate(), array);
    }
    DCHECK_EQ(array->Length(), length);

    Type sum = 0;
    for (uint32_t i = 0; i < length; ++i) {
      sum += buffer[i];
    }

    return sum;
  }

  static void AddAllSequenceSlowCallback(
      const FunctionCallbackInfo<Value>& info) {
    DCHECK(i::ValidateCallbackInfo(info));
    Isolate* isolate = info.GetIsolate();

    FastCApiObject* self = UnwrapObject(info.This());
    CHECK_SELF_OR_THROW_SLOW();

    HandleScope handle_scope(isolate);

    if (info.Length() < 1) {
      self->slow_call_count_++;
      isolate->ThrowError("This method expects at least 1 arguments.");
      return;
    }
    if (info[0]->IsTypedArray()) {
      AddAllTypedArraySlowCallback(info);
      return;
    }
    if (info[0]->IsNumber()) {
      AddAllSlowCallback(info);
      return;
    }
    self->slow_call_count_++;
    if (info[0]->IsUndefined()) {
      Type dummy_result = 0;
      info.GetReturnValue().Set(Number::New(isolate, dummy_result));
      return;
    }
    if (!info[0]->IsArray()) {
      isolate->ThrowError("This method expects an array as a first argument.");
      return;
    }
    Local<Array> seq_arg = info[0].As<Array>();
    Type sum = AddAllSequenceJSArrayHelper(isolate, seq_arg);

    info.GetReturnValue().Set(Number::New(isolate, sum));
  }
#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS

  template <typename T>
  static AnyCType AddAllTypedArrayFastCallbackPatch(AnyCType receiver,
                                                    AnyCType typed_array_arg,
                                                    AnyCType options) {
    AnyCType ret;
#ifdef V8_ENABLE_FP_PARAMS_IN_C_LINKAGE
    ret.double_value = AddAllTypedArrayFastCallback<T>(
        receiver.object_value, typed_array_arg.object_value,
        *options.options_value);
#else
    ret.int32_value = AddAllTypedArrayFastCallback<T>(
        receiver.object_value, typed_array_arg.object_value,
        *options.options_value);
#endif  // V8_ENABLE_FP_PARAMS_IN_C_LINKAGE
    return ret;
  }
#endif  //  V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
  template <typename T>
  static Type AddAllTypedArrayFastCallback(Local<Object> receiver,
                                           Local<Value> typed_array_arg,
                                           FastApiCallbackOptions& options) {
    FastCApiObject* self = UnwrapObject(receiver);
    CHECK_SELF_OR_THROW_FAST_OPTIONS(0);
    self->fast_call_count_++;

    HandleScope handle_scope(options.isolate);
    if (!typed_array_arg->IsTypedArray()) {
      options.isolate->ThrowError(
          "This method expects a TypedArray as a first argument.");
      return 0;
    }
    T* memory = reinterpret_cast<T*>(
        typed_array_arg.As<TypedArray>()->Buffer()->Data());
    size_t length = typed_array_arg.As<TypedArray>()->ByteLength() / sizeof(T);
    double sum = 0;
    for (size_t i = 0; i < length; ++i) {
      sum += static_cast<double>(memory[i]);
    }
    return static_cast<Type>(sum);
  }

  static void AddAllTypedArraySlowCallback(
      const FunctionCallbackInfo<Value>& info) {
    DCHECK(i::ValidateCallbackInfo(info));
    Isolate* isolate = info.GetIsolate();

    FastCApiObject* self = UnwrapObject(info.This());
    CHECK_SELF_OR_THROW_SLOW();
    self->slow_call_count_++;

    HandleScope handle_scope(isolate);

    if (info.Length() < 1) {
      isolate->ThrowError("This method expects at least 1 arguments.");
      return;
    }
    if (!info[0]->IsTypedArray()) {
      isolate->ThrowError(
          "This method expects a TypedArray as a second argument.");
      return;
    }

    Local<TypedArray> typed_array_arg = info[0].As<TypedArray>();
    size_t length = typed_array_arg->Length();

    void* data = typed_array_arg->Buffer()->GetBackingStore()->Data();
    if (typed_array_arg->IsUint8Array() || typed_array_arg->IsInt32Array() ||
        typed_array_arg->IsUint32Array() ||
        typed_array_arg->IsBigInt64Array() ||
        typed_array_arg->IsBigUint64Array()) {
      int64_t sum = 0;
      for (unsigned i = 0; i < length; ++i) {
        if (typed_array_arg->IsUint8Array()) {
          sum += static_cast<uint8_t*>(data)[i];
        } else if (typed_array_arg->IsInt32Array()) {
          sum += static_cast<int32_t*>(data)[i];
        } else if (typed_array_arg->IsUint32Array()) {
          sum += static_cast<uint32_t*>(data)[i];
        } else if (typed_array_arg->IsBigInt64Array()) {
          sum += static_cast<int64_t*>(data)[i];
        } else if (typed_array_arg->IsBigUint64Array()) {
          sum += static_cast<uint64_t*>(data)[i];
        }
      }
      info.GetReturnValue().Set(Number::New(isolate, sum));
    } else if (typed_array_arg->IsFloat32Array() ||
               typed_array_arg->IsFloat64Array()) {
      double sum = 0;
      for (unsigned i = 0; i < length; ++i) {
        if (typed_array_arg->IsFloat32Array()) {
          sum += static_cast<float*>(data)[i];
        } else if (typed_array_arg->IsFloat64Array()) {
          sum += static_cast<double*>(data)[i];
        }
      }
      info.GetReturnValue().Set(Number::New(isolate, sum));
    } else {
      isolate->ThrowError("TypedArray type is not supported.");
      return;
    }
  }

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
  static AnyCType Add32BitIntFastCallbackPatch(AnyCType receiver,
                                               AnyCType arg_i32,
                                               AnyCType arg_u32,
                                               AnyCType options) {
    AnyCType ret;
    ret.int32_value =
        Add32BitIntFastCallback(receiver.object_value, arg_i32.int32_value,
                                arg_u32.uint32_value, *options.options_value);
    return ret;
  }
#endif  //  V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS

  static int Add32BitIntFastCallback(v8::Local<v8::Object> receiver,
                                     int32_t arg_i32, uint32_t arg_u32,
                                     FastApiCallbackOptions& options) {
    FastCApiObject* self = UnwrapObject(receiver);
    CHECK_SELF_OR_THROW_FAST_OPTIONS(0);
    self->fast_call_count_++;

    return arg_i32 + arg_u32;
  }
  static void Add32BitIntSlowCallback(const FunctionCallbackInfo<Value>& info) {
    DCHECK(i::ValidateCallbackInfo(info));
    Isolate* isolate = info.GetIsolate();

    FastCApiObject* self = UnwrapObject(info.This());
    CHECK_SELF_OR_THROW_SLOW();
    self->slow_call_count_++;

    HandleScope handle_scope(isolate);

    double sum = 0;
    if (info.Length() > 0 && info[0]->IsNumber()) {
      sum += info[0]->Int32Value(isolate->GetCurrentContext()).FromJust();
    }
    if (info.Length() > 1 && info[1]->IsNumber()) {
      sum += info[1]->Uint32Value(isolate->GetCurrentContext()).FromJust();
    }

    info.GetReturnValue().Set(Number::New(isolate, sum));
  }

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
  static AnyCType AddAll32BitIntFastCallback_8ArgsPatch(
      AnyCType receiver, AnyCType arg1_i32, AnyCType arg2_i32,
      AnyCType arg3_i32, AnyCType arg4_u32, AnyCType arg5_u32,
      AnyCType arg6_u32, AnyCType arg7_u32, AnyCType arg8_u32,
      AnyCType options) {
    AnyCType ret;
    ret.int32_value = AddAll32BitIntFastCallback_8Args(
        receiver.object_value, arg1_i32.int32_value, arg2_i32.int32_value,
        arg3_i32.int32_value, arg4_u32.uint32_value, arg5_u32.uint32_value,
        arg6_u32.uint32_value, arg7_u32.uint32_value, arg8_u32.uint32_value,
        *options.options_value);
    return ret;
  }
  static AnyCType AddAll32BitIntFastCallback_6ArgsPatch(
      AnyCType receiver, AnyCType arg1_i32, AnyCType arg2_i32,
      AnyCType arg3_i32, AnyCType arg4_u32, AnyCType arg5_u32,
      AnyCType arg6_u32, AnyCType options) {
    AnyCType ret;
    ret.int32_value = AddAll32BitIntFastCallback_6Args(
        receiver.object_value, arg1_i32.int32_value, arg2_i32.int32_value,
        arg3_i32.int32_value, arg4_u32.uint32_value, arg5_u32.uint32_value,
        arg6_u32.uint32_value, *options.options_value);
    return ret;
  }
  static AnyCType AddAll32BitIntFastCallback_5ArgsPatch(
      AnyCType receiver, AnyCType arg1_i32, AnyCType arg2_i32,
      AnyCType arg3_i32, AnyCType arg4_u32, AnyCType arg5_u32,
      AnyCType options) {
    AnyCType arg6;
    arg6.uint32_value = 0;
    return AddAll32BitIntFastCallback_6ArgsPatch(receiver, arg1_i32, arg2_i32,
                                                 arg3_i32, arg4_u32, arg5_u32,
                                                 arg6, options);
  }
#endif  //  V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS

  static int AddAll32BitIntFastCallback_8Args(
      Local<Object> receiver, int32_t arg1_i32, int32_t arg2_i32,
      int32_t arg3_i32, uint32_t arg4_u32, uint32_t arg5_u32, uint32_t arg6_u32,
      uint32_t arg7_u32, uint32_t arg8_u32, FastApiCallbackOptions& options) {
    FastCApiObject* self = UnwrapObject(receiver);
    CHECK_SELF_OR_THROW_FAST_OPTIONS(0);
    self->fast_call_count_++;

    int64_t result = static_cast<int64_t>(arg1_i32) + arg2_i32 + arg3_i32 +
                     arg4_u32 + arg5_u32 + arg6_u32 + arg7_u32 + arg8_u32;
    if (result > INT_MAX) return INT_MAX;
    if (result < INT_MIN) return INT_MIN;
    return static_cast<int>(result);
  }
  static int AddAll32BitIntFastCallback_6Args(
      Local<Object> receiver, int32_t arg1_i32, int32_t arg2_i32,
      int32_t arg3_i32, uint32_t arg4_u32, uint32_t arg5_u32, uint32_t arg6_u32,
      FastApiCallbackOptions& options) {
    FastCApiObject* self = UnwrapObject(receiver);
    CHECK_SELF_OR_THROW_FAST_OPTIONS(0);
    self->fast_call_count_++;

    int64_t result = static_cast<int64_t>(arg1_i32) + arg2_i32 + arg3_i32 +
                     arg4_u32 + arg5_u32 + arg6_u32;
    if (result > INT_MAX) return INT_MAX;
    if (result < INT_MIN) return INT_MIN;
    return static_cast<int>(result);
  }
  static int AddAll32BitIntFastCallback_5Args(
      Local<Object> receiver, int32_t arg1_i32, int32_t arg2_i32,
      int32_t arg3_i32, uint32_t arg4_u32, uint32_t arg5_u32,
      FastApiCallbackOptions& options) {
    return AddAll32BitIntFastCallback_6Args(
        receiver, arg1_i32, arg2_i32, arg3_i32, arg4_u32, arg5_u32, 0, options);
  }
  static void AddAll32BitIntSlowCallback(
      const FunctionCallbackInfo<Value>& info) {
    DCHECK(i::ValidateCallbackInfo(info));
    Isolate* isolate = info.GetIsolate();

    FastCApiObject* self = UnwrapObject(info.This());
    CHECK_SELF_OR_THROW_SLOW();
    self->slow_call_count_++;

    HandleScope handle_scope(isolate);

    Local<Context> context = isolate->GetCurrentContext();
    double sum = 0;
    if (info.Length() > 0 && info[0]->IsNumber()) {
      sum += info[0]->Int32Value(context).FromJust();
    }
    if (info.Length() > 1 && info[1]->IsNumber()) {
      sum += info[1]->Int32Value(context).FromJust();
    }
    if (info.Length() > 2 && info[2]->IsNumber()) {
      sum += info[2]->Int32Value(context).FromJust();
    }
    if (info.Length() > 3 && info[3]->IsNumber()) {
      sum += info[3]->Uint32Value(context).FromJust();
    }
    if (info.Length() > 4 && info[4]->IsNumber()) {
      sum += info[4]->Uint32Value(context).FromJust();
    }
    if (info.Length() > 5 && info[5]->IsNumber()) {
      sum += info[5]->Uint32Value(context).FromJust();
    }
    if (info.Length() > 7 && info[6]->IsNumber() && info[7]->IsNumber()) {
      // info[6] and info[7] only get handled together, because we want to
      // have functions in the list of overloads with 6 parameters and with 8
      // parameters, but not with 7 parameters.
      sum += info[6]->Uint32Value(context).FromJust();
      sum += info[7]->Uint32Value(context).FromJust();
    }

    info.GetReturnValue().Set(Number::New(isolate, sum));
  }

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
  template <v8::CTypeInfo::Flags flags>
  static AnyCType AddAllAnnotateFastCallbackPatch(
      AnyCType receiver, AnyCType arg_i32, AnyCType arg_u32, AnyCType arg_i64,
      AnyCType arg_u64, AnyCType options) {
    AnyCType ret;
    ret.double_value = AddAllAnnotateFastCallback<flags>(
        receiver.object_value, arg_i32.int32_value, arg_u32.uint32_value,
        arg_i64.int64_value, arg_u64.uint64_value, *options.options_value);
    return ret;
  }
#endif  //  V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS

  template <v8::CTypeInfo::Flags flags>
  static double AddAllAnnotateFastCallback(Local<Object> receiver,
                                           int32_t arg_i32, uint32_t arg_u32,
                                           int64_t arg_i64, uint64_t arg_u64,
                                           FastApiCallbackOptions& options) {
    FastCApiObject* self = UnwrapObject(receiver);
    CHECK_NOT_NULL(self);
    self->fast_call_count_++;

    return static_cast<double>(arg_i32) + static_cast<double>(arg_u32) +
           static_cast<double>(arg_i64) + static_cast<double>(arg_u64);
  }

  static void AddAllAnnotateSlowCallback(
      const FunctionCallbackInfo<Value>& info) {
    DCHECK(i::ValidateCallbackInfo(info));
    Isolate* isolate = info.GetIsolate();

    FastCApiObject* self = UnwrapObject(info.This());
    CHECK_SELF_OR_THROW_SLOW();
    self->slow_call_count_++;

    HandleScope handle_scope(isolate);

    double sum = 0;
    if (info.Length() > 1 && info[1]->IsNumber()) {
      sum += info[1]->Int32Value(isolate->GetCurrentContext()).FromJust();
    }
    if (info.Length() > 2 && info[2]->IsNumber()) {
      sum += info[2]->Uint32Value(isolate->GetCurrentContext()).FromJust();
    }
    if (info.Length() > 3 && info[3]->IsNumber()) {
      sum += info[3]->IntegerValue(isolate->GetCurrentContext()).FromJust();
    }
    if (info.Length() > 4 && info[4]->IsNumber()) {
      sum += info[4]->IntegerValue(isolate->GetCurrentContext()).FromJust();
    }

    info.GetReturnValue().Set(Number::New(isolate, sum));
  }

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
  static AnyCType EnforceRangeCompareI32Patch(AnyCType receiver,
                                              AnyCType real_arg,
                                              AnyCType checked_arg,
                                              AnyCType options) {
    AnyCType ret;
    ret.bool_value = EnforceRangeCompare<int32_t>(
        receiver.object_value, real_arg.double_value, checked_arg.int32_value,
        *options.options_value);
    return ret;
  }
  static AnyCType EnforceRangeCompareU32Patch(AnyCType receiver,
                                              AnyCType real_arg,
                                              AnyCType checked_arg,
                                              AnyCType options) {
    AnyCType ret;
    ret.bool_value = EnforceRangeCompare<uint32_t>(
        receiver.object_value, real_arg.double_value, checked_arg.uint32_value,
        *options.options_value);
    return ret;
  }
  static AnyCType EnforceRangeCompareI64Patch(AnyCType receiver,
                                              AnyCType real_arg,
                                              AnyCType checked_arg,
                                              AnyCType options) {
    AnyCType ret;
    ret.bool_value = EnforceRangeCompare<int64_t>(
        receiver.object_value, real_arg.double_value, checked_arg.int64_value,
        *options.options_value);
    return ret;
  }
  static AnyCType EnforceRangeCompareU64Patch(AnyCType receiver,
                                              AnyCType real_arg,
                                              AnyCType checked_arg,
                                              AnyCType options) {
    AnyCType ret;
    ret.bool_value = EnforceRangeCompare<uint64_t>(
        receiver.object_value, real_arg.double_value, checked_arg.uint64_value,
        *options.options_value);
    return ret;
  }
#endif  //  V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS

  template <typename IntegerT>
  static bool EnforceRangeCompare(Local<Object> receiver, double real_arg,
                                  IntegerT checked_arg,
                                  FastApiCallbackOptions& options) {
    FastCApiObject* self = UnwrapObject(receiver);
    CHECK_NOT_NULL(self);
    self->fast_call_count_++;

    return static_cast<IntegerT>(real_arg) == checked_arg;
  }

  template <typename IntegerT>
  static void EnforceRangeCompareSlowCallback(
      const FunctionCallbackInfo<Value>& info) {
    DCHECK(i::ValidateCallbackInfo(info));
    Isolate* isolate = info.GetIsolate();

    FastCApiObject* self = UnwrapObject(info.This());
    CHECK_SELF_OR_THROW_SLOW();
    self->slow_call_count_++;

    HandleScope handle_scope(isolate);

    double real_arg = 0;
    if (info.Length() > 0 && info[0]->IsNumber()) {
      real_arg = info[0]->NumberValue(isolate->GetCurrentContext()).FromJust();
    }
    // Special range checks for int64 and uint64. uint64_max rounds to 2^64 when
    // converted to double, so 2^64 would be considered within uint64 range even
    // though it's not. For int64 the same happens with 2^63.
    bool in_range =
        !std::isnan(real_arg) && real_arg < std::pow(2.0, 64) &&
        (real_arg < std::pow(2.0, 63) ||
         std::pow(2.0, 63) <
             static_cast<double>(std::numeric_limits<IntegerT>::max())) &&
        real_arg <= static_cast<double>(std::numeric_limits<IntegerT>::max()) &&
        real_arg >= static_cast<double>(std::numeric_limits<IntegerT>::min());
    if (in_range) {
      IntegerT checked_arg = 0;
      if (info.Length() > 1 && info[1]->IsNumber()) {
        checked_arg =
            info[1]->NumberValue(isolate->GetCurrentContext()).FromJust();
      }
      info.GetReturnValue().Set(static_cast<IntegerT>(real_arg) == checked_arg);
    } else {
      info.GetIsolate()->ThrowError("Argument out of range.");
    }
  }

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
  static AnyCType ClampCompareI32Patch(AnyCType receiver, AnyCType in_range,
                                       AnyCType real_arg, AnyCType checked_arg,
                                       AnyCType options) {
    AnyCType ret;
    ret.double_value = ClampCompare<int32_t>(
        receiver.object_value, in_range.bool_value, real_arg.double_value,
        checked_arg.int32_value, *options.options_value);
    return ret;
  }
  static AnyCType ClampCompareU32Patch(AnyCType receiver, AnyCType in_range,
                                       AnyCType real_arg, AnyCType checked_arg,
                                       AnyCType options) {
    AnyCType ret;
    ret.double_value = ClampCompare<uint32_t>(
        receiver.object_value, in_range.bool_value, real_arg.double_value,
        checked_arg.uint32_value, *options.options_value);
    return ret;
  }
  static AnyCType ClampCompareI64Patch(AnyCType receiver, AnyCType in_range,
                                       AnyCType real_arg, AnyCType checked_arg,
                                       AnyCType options) {
    AnyCType ret;
    ret.double_value = ClampCompare<int64_t>(
        receiver.object_value, in_range.bool_value, real_arg.double_value,
        checked_arg.int64_value, *options.options_value);
    return ret;
  }
  static AnyCType ClampCompareU64Patch(AnyCType receiver, AnyCType in_range,
                                       AnyCType real_arg, AnyCType checked_arg,
                                       AnyCType options) {
    AnyCType ret;
    ret.double_value = ClampCompare<uint64_t>(
        receiver.object_value, in_range.bool_value, real_arg.double_value,
        checked_arg.uint64_value, *options.options_value);
    return ret;
  }
#endif  //  V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS

  template <typename IntegerT>
  static double ClampCompareCompute(bool in_range, double real_arg,
                                    IntegerT checked_arg) {
    if (i::v8_flags.fuzzing) {
      return static_cast<double>(checked_arg);
    }
    if (!in_range) {
      IntegerT lower_bound = std::numeric_limits<IntegerT>::min();
      IntegerT upper_bound = std::numeric_limits<IntegerT>::max();
      if (lower_bound < internal::kMinSafeInteger) {
        lower_bound = static_cast<IntegerT>(internal::kMinSafeInteger);
      }
      if (upper_bound > internal::kMaxSafeInteger) {
        upper_bound = static_cast<IntegerT>(internal::kMaxSafeInteger);
      }
      CHECK(!std::isnan(real_arg));
      if (real_arg < static_cast<double>(lower_bound)) {
        CHECK_EQ(lower_bound, checked_arg);
      } else if (real_arg > static_cast<double>(upper_bound)) {
        CHECK_EQ(upper_bound, checked_arg);
      } else {
        FATAL("Expected value to be out of range.");
      }
    } else if (!std::isnan(real_arg)) {
      if (real_arg != checked_arg) {
        // Check if rounding towards nearest even number happened.
        double diff = std::fabs(real_arg - checked_arg);
        CHECK_LE(diff, 0.5);
        if (diff == 0) {
          // Check if rounding towards nearest even number happened.
          CHECK_EQ(0, checked_arg % 2);
        } else if (checked_arg % 2 == 1) {
          // Behave as if rounding towards nearest even number *has*
          // happened (as it does on the fast path).
          checked_arg += 1;
        }
      } else {
        CHECK_EQ(static_cast<IntegerT>(real_arg), checked_arg);
      }
    }
    return checked_arg;
  }
"""


```