Response:
The user wants me to analyze a C++ source code file `v8/src/wasm/wasm-js.cc` from the V8 JavaScript engine and describe its functionalities. I need to pay attention to whether the file could be a Torque file (based on its extension), its relation to JavaScript, and provide examples, code logic reasoning, common errors, and a summary of its functionality as part 3 of a 5-part analysis.

**Plan:**

1. **Analyze the code snippets:** I will go through the provided code snippets and identify the main functionalities implemented. These seem to revolve around the JavaScript API for WebAssembly, specifically related to `WebAssembly.Memory`, `WebAssembly.Global`, `WebAssembly.Tag`, `WebAssembly.Exception`, and `WebAssembly.Function`.
2. **Check for Torque:**  The prompt explicitly states that if the file ends with `.tq`, it's a Torque file. This file ends with `.cc`, so it's C++.
3. **JavaScript Relation and Examples:**  I will identify the JavaScript APIs that are being implemented and provide corresponding JavaScript usage examples.
4. **Code Logic Reasoning:** For the more complex functions, I will try to deduce the logic with assumed inputs and outputs.
5. **Common Programming Errors:** I will look for error handling patterns in the code that might correspond to common user mistakes.
6. **Summarize Functionality:** I will synthesize the identified functionalities into a concise summary.
这是 `v8/src/wasm/wasm-js.cc` 的第三部分代码，它主要负责实现 WebAssembly 的 JavaScript API。基于提供的代码片段，我们可以归纳出以下功能：

**核心功能归纳:**

这部分代码主要实现了以下 WebAssembly JavaScript API 的构造函数和相关逻辑：

*   **`WebAssembly.Memory`**:  用于创建 WebAssembly 线性内存的实例。它处理 `initial` 和 `maximum` 属性，以及 `shared` 属性，并进行参数校验和内存分配。
*   **`WebAssembly.Global`**: 用于创建 WebAssembly 全局变量的实例。它处理 `mutable` 和 `value` 属性，并设置全局变量的初始值。
*   **`WebAssembly.Tag`**: 用于创建 WebAssembly 异常标签的实例。它解析 `parameters` 属性来定义异常的参数类型。
*   **`WebAssembly.Exception`**: 用于创建 WebAssembly 异常实例。它接收一个 `WebAssembly.Tag` 实例和一个包含异常值的可迭代对象作为参数。
*   **`WebAssembly.Function`**: 用于创建一个包装 JavaScript 函数的 WebAssembly 函数实例。它解析 `parameters` 和 `results` 属性来定义函数的签名。
*   **`WebAssembly.promising(Function)`**:  将一个 WebAssembly 导出的函数包装成一个返回 Promise 的函数。
*   **`WebAssembly.Suspending(Function)`**:  创建一个可以暂停和恢复执行的 WebAssembly 函数包装器。

**关于文件类型:**

`v8/src/wasm/wasm-js.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 V8 Torque 源代码。

**与 JavaScript 的关系及示例:**

这段 C++ 代码直接对应于 WebAssembly 的 JavaScript API。它提供了在 JavaScript 中创建和操作 WebAssembly 构造（如内存、全局变量、函数等）的能力。

**`WebAssembly.Memory` 示例:**

```javascript
// 创建一个初始大小为 1 个内存页的 WebAssembly 内存
const memory = new WebAssembly.Memory({ initial: 1 });

// 创建一个初始大小为 1，最大大小为 10 的共享内存
const sharedMemory = new WebAssembly.Memory({ initial: 1, maximum: 10, shared: true });
```

**`WebAssembly.Global` 示例:**

```javascript
// 创建一个不可变的 i32 类型的全局变量，初始值为 42
const globalI32 = new WebAssembly.Global({ value: 'i32', mutable: false }, 42);

// 创建一个可变的 f64 类型的全局变量，初始值为 3.14
const globalF64 = new WebAssembly.Global({ value: 'f64', mutable: true }, 3.14);
```

**`WebAssembly.Tag` 示例:**

```javascript
// 定义一个带有一个 i32 参数的异常标签
const tag = new WebAssembly.Tag({ parameters: ['i32'] });
```

**`WebAssembly.Exception` 示例:**

```javascript
const tag = new WebAssembly.Tag({ parameters: ['i32'] });
// 抛出一个带有值 10 的异常
const exception = new WebAssembly.Exception(tag, [10]);
```

**`WebAssembly.Function` 示例:**

```javascript
// 定义一个接收两个 i32 参数并返回一个 i32 结果的函数类型
const functionType = { parameters: ['i32', 'i32'], results: ['i32'] };

// 创建一个包装 JavaScript 加法函数的 WebAssembly 函数实例
const addFunction = new WebAssembly.Function(functionType, (a, b) => a + b);
```

**`WebAssembly.promising` 示例:**

```javascript
// 假设 'exportedWasmFunction' 是一个从 WebAssembly 模块导出的函数
const promisingFunction = WebAssembly.promising(exportedWasmFunction);

// 调用 promisingFunction 将返回一个 Promise
promisingFunction(1, 2).then(result => console.log(result));
```

**`WebAssembly.Suspending` 示例:**

```javascript
async function myAsyncFunction() {
  console.log("开始执行");
  await new Promise(resolve => setTimeout(resolve, 1000));
  console.log("继续执行");
  return 42;
}

const suspendingFunction = new WebAssembly.Suspending(myAsyncFunction);
```

**代码逻辑推理及假设输入与输出:**

**`WebAssemblyMemoryImpl` 函数逻辑推理:**

*   **假设输入:**
    *   `descriptor`:  一个 JavaScript 对象，例如 `{ initial: 2, maximum: 5, shared: false }`。
    *   info 是 `WebAssembly.Memory` 构造函数的调用信息。
*   **处理过程:**
    1. 解析 `descriptor` 对象的 `initial`（或 `minimum`）、`maximum` 和 `shared` 属性。
    2. 进行参数校验，例如确保 `initial` 和 `maximum` 在有效范围内，以及当 `shared` 为 true 时 `maximum` 必须存在。
    3. 调用 `i::WasmMemoryObject::New` 分配内存。
    4. 如果构造函数被子类调用，则调整原型链。
    5. 如果是共享内存，则冻结 `ArrayBuffer`。
*   **假设输出:**  一个新的 `WebAssembly.Memory` 实例，其内部包含一个分配好的 `ArrayBuffer`。如果参数无效，则抛出 `TypeError` 或 `RangeError`。

**涉及用户常见的编程错误:**

*   **`WebAssembly.Memory`:**
    *   未提供 `initial` 属性或提供的 `initial` 值不是数字或超出范围。
    *   尝试创建共享内存时没有提供 `maximum` 属性。
    *   提供的 `maximum` 值小于 `initial` 值。
*   **`WebAssembly.Global`:**
    *   `value` 属性指定的类型不是有效的 WebAssembly 类型字符串（例如，拼写错误或使用了不支持的类型）。
    *   尝试创建一个不可变全局变量后尝试修改它的值（这会在 WebAssembly 模块内部发生，此代码负责创建）。
    *   为非默认值类型的全局变量（例如引用类型）创建时没有提供初始值。
*   **`WebAssembly.Tag`:**
    *   `parameters` 属性不是数组或数组中的元素不是有效的 WebAssembly 类型字符串。
    *   参数数量超过了 WebAssembly 的限制。
*   **`WebAssembly.Exception`:**
    *   第一个参数不是 `WebAssembly.Tag` 的实例。
    *   提供的异常值数组的长度与 `WebAssembly.Tag` 定义的参数数量不匹配。
    *   提供的异常值的类型与 `WebAssembly.Tag` 定义的参数类型不匹配。
*   **`WebAssembly.Function`:**
    *   `parameters` 或 `results` 属性不是数组或数组中的元素不是有效的 WebAssembly 类型字符串。
    *   参数或返回值数量超过了 WebAssembly 的限制。
    *   第二个参数不是一个函数。
*   **`WebAssembly.promising` 或 `WebAssembly.Suspending`:**
    *   传递的参数不是一个函数。
    *   尝试包装一个不是 WebAssembly 导出的函数（对于 `promising`）。

总而言之，这段代码是 V8 引擎中实现 WebAssembly JavaScript API 的关键部分，它负责将 JavaScript 的请求转换为底层的 WebAssembly 构造和操作。它对参数进行了严格的校验，以防止用户在使用 API 时出现错误。

### 提示词
```
这是目录为v8/src/wasm/wasm-js.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wasm-js.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
be in integer range. That's the type
  // {WasmMemoryObject::New} uses.
  static_assert(i::wasm::kSpecMaxMemory32Pages < i::kMaxInt);
  static_assert(i::wasm::kSpecMaxMemory64Pages < i::kMaxInt);

  // Parse the 'initial' or 'minimum' property of the `descriptor`.
  std::optional<uint64_t> maybe_initial =
      GetInitialOrMinimumProperty(isolate, &thrower, context, descriptor,
                                  address_type, max_supported_pages);
  if (!maybe_initial) {
    return js_api_scope.AssertException();
  }
  uint64_t initial = *maybe_initial;

  // Parse the 'maximum' property of the `descriptor`.
  auto maybe_maybe_maximum = GetOptionalAddressValue(
      &thrower, context, descriptor, v8_str(isolate, "maximum"), address_type,
      initial, max_supported_pages);
  if (!maybe_maybe_maximum) {
    return js_api_scope.AssertException();
  }
  std::optional<uint64_t> maybe_maximum = *maybe_maybe_maximum;

  // Parse the 'shared' property of the `descriptor`.
  v8::Local<v8::Value> value;
  if (!descriptor->Get(context, v8_str(isolate, "shared")).ToLocal(&value)) {
    return js_api_scope.AssertException();
  }

  auto shared = value->BooleanValue(isolate) ? i::SharedFlag::kShared
                                             : i::SharedFlag::kNotShared;

  // Throw TypeError if shared is true, and the descriptor has no "maximum".
  if (shared == i::SharedFlag::kShared && !maybe_maximum.has_value()) {
    thrower.TypeError("If shared is true, maximum property should be defined.");
    return;
  }

  i::Handle<i::JSObject> memory_obj;
  if (!i::WasmMemoryObject::New(i_isolate, static_cast<int>(initial),
                                maybe_maximum ? static_cast<int>(*maybe_maximum)
                                              : i::WasmMemoryObject::kNoMaximum,
                                shared, address_type)
           .ToHandle(&memory_obj)) {
    thrower.RangeError("could not allocate memory");
    return;
  }

  // The infrastructure for `new Foo` calls allocates an object, which is
  // available here as {info.This()}. We're going to discard this object
  // and use {memory_obj} instead, but it does have the correct prototype,
  // which we must harvest from it. This makes a difference when the JS
  // constructor function wasn't {WebAssembly.Memory} directly, but some
  // subclass: {memory_obj} has {WebAssembly.Memory}'s prototype at this
  // point, so we must overwrite that with the correct prototype for {Foo}.
  if (!TransferPrototype(i_isolate, memory_obj,
                         Utils::OpenHandle(*info.This()))) {
    return js_api_scope.AssertException();
  }

  if (shared == i::SharedFlag::kShared) {
    i::Handle<i::JSArrayBuffer> buffer(
        i::Cast<i::WasmMemoryObject>(memory_obj)->array_buffer(), i_isolate);
    Maybe<bool> result =
        buffer->SetIntegrityLevel(i_isolate, buffer, i::FROZEN, i::kDontThrow);
    if (!result.FromJust()) {
      thrower.TypeError(
          "Status of setting SetIntegrityLevel of buffer is false.");
      return;
    }
  }
  info.GetReturnValue().Set(Utils::ToLocal(memory_obj));
}

// Determines the type encoded in a value type property (e.g. type reflection).
// Returns false if there was an exception, true upon success. On success the
// outgoing {type} is set accordingly, or set to {wasm::kWasmVoid} in case the
// type could not be properly recognized.
std::optional<i::wasm::ValueType> GetValueType(
    Isolate* isolate, MaybeLocal<Value> maybe, Local<Context> context,
    WasmEnabledFeatures enabled_features) {
  v8::Local<v8::Value> value;
  if (!maybe.ToLocal(&value)) return std::nullopt;
  i::Handle<i::String> string;
  if (!i::Object::ToString(reinterpret_cast<i::Isolate*>(isolate),
                           Utils::OpenHandle(*value))
           .ToHandle(&string)) {
    return std::nullopt;
  }
  if (string->IsEqualTo(base::CStrVector("i32"))) {
    return i::wasm::kWasmI32;
  } else if (string->IsEqualTo(base::CStrVector("f32"))) {
    return i::wasm::kWasmF32;
  } else if (string->IsEqualTo(base::CStrVector("i64"))) {
    return i::wasm::kWasmI64;
  } else if (string->IsEqualTo(base::CStrVector("f64"))) {
    return i::wasm::kWasmF64;
  } else if (string->IsEqualTo(base::CStrVector("v128"))) {
    return i::wasm::kWasmS128;
  } else if (string->IsEqualTo(base::CStrVector("externref"))) {
    return i::wasm::kWasmExternRef;
  } else if (enabled_features.has_type_reflection() &&
             string->IsEqualTo(base::CStrVector("funcref"))) {
    // The type reflection proposal renames "anyfunc" to "funcref", and makes
    // "anyfunc" an alias of "funcref".
    return i::wasm::kWasmFuncRef;
  } else if (string->IsEqualTo(base::CStrVector("anyfunc"))) {
    // The JS api spec uses 'anyfunc' instead of 'funcref'.
    return i::wasm::kWasmFuncRef;
  } else if (string->IsEqualTo(base::CStrVector("eqref"))) {
    return i::wasm::kWasmEqRef;
  } else if (enabled_features.has_stringref() &&
             string->IsEqualTo(base::CStrVector("stringref"))) {
    return i::wasm::kWasmStringRef;
  } else if (string->IsEqualTo(base::CStrVector("anyref"))) {
    return i::wasm::kWasmAnyRef;
  } else if (string->IsEqualTo(base::CStrVector("structref"))) {
    return i::wasm::kWasmStructRef;
  } else if (string->IsEqualTo(base::CStrVector("arrayref"))) {
    return i::wasm::kWasmArrayRef;
  } else if (string->IsEqualTo(base::CStrVector("i31ref"))) {
    return i::wasm::kWasmI31Ref;
  } else if (enabled_features.has_exnref() &&
             string->IsEqualTo(base::CStrVector("exnref"))) {
    return i::wasm::kWasmExnRef;
  }
  // Unrecognized type.
  return i::wasm::kWasmVoid;
}

namespace {

bool ToI32(Local<v8::Value> value, Local<Context> context, int32_t* i32_value) {
  if (!value->IsUndefined()) {
    v8::Local<v8::Int32> int32_value;
    if (!value->ToInt32(context).ToLocal(&int32_value)) return false;
    if (!int32_value->Int32Value(context).To(i32_value)) return false;
  }
  return true;
}

bool ToI64(Local<v8::Value> value, Local<Context> context, int64_t* i64_value) {
  if (!value->IsUndefined()) {
    v8::Local<v8::BigInt> bigint_value;
    if (!value->ToBigInt(context).ToLocal(&bigint_value)) return false;
    *i64_value = bigint_value->Int64Value();
  }
  return true;
}

bool ToF32(Local<v8::Value> value, Local<Context> context, float* f32_value) {
  if (!value->IsUndefined()) {
    double f64_value = 0;
    v8::Local<v8::Number> number_value;
    if (!value->ToNumber(context).ToLocal(&number_value)) return false;
    if (!number_value->NumberValue(context).To(&f64_value)) return false;
    *f32_value = i::DoubleToFloat32(f64_value);
  }
  return true;
}

bool ToF64(Local<v8::Value> value, Local<Context> context, double* f64_value) {
  if (!value->IsUndefined()) {
    v8::Local<v8::Number> number_value;
    if (!value->ToNumber(context).ToLocal(&number_value)) return false;
    if (!number_value->NumberValue(context).To(f64_value)) return false;
  }
  return true;
}
}  // namespace

// WebAssembly.Global
void WebAssemblyGlobalImpl(const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.Global()"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();

  if (!info.IsConstructCall()) {
    thrower.TypeError("WebAssembly.Global must be invoked with 'new'");
    return;
  }
  if (!info[0]->IsObject()) {
    thrower.TypeError("Argument 0 must be a global descriptor");
    return;
  }
  Local<Context> context = isolate->GetCurrentContext();
  Local<v8::Object> descriptor = Local<Object>::Cast(info[0]);
  auto enabled_features = WasmEnabledFeatures::FromIsolate(i_isolate);

  // The descriptor's 'mutable'.
  bool is_mutable;
  {
    v8::Local<v8::Value> value;
    if (!descriptor->Get(context, v8_str(isolate, "mutable")).ToLocal(&value)) {
      return js_api_scope.AssertException();
    }
    is_mutable = value->BooleanValue(isolate);
  }

  // The descriptor's type, called 'value'. It is called 'value' because this
  // descriptor is planned to be re-used as the global's type for reflection,
  // so calling it 'type' is redundant.
  i::wasm::ValueType type;
  {
    v8::MaybeLocal<v8::Value> maybe =
        descriptor->Get(context, v8_str(isolate, "value"));
    std::optional<i::wasm::ValueType> maybe_type =
        GetValueType(isolate, maybe, context, enabled_features);
    if (!maybe_type) return js_api_scope.AssertException();
    type = *maybe_type;
    if (type == i::wasm::kWasmVoid) {
      thrower.TypeError(
          "Descriptor property 'value' must be a WebAssembly type");
      return;
    }
  }

  const uint32_t offset = 0;
  i::MaybeHandle<i::WasmGlobalObject> maybe_global_obj =
      i::WasmGlobalObject::New(
          i_isolate, i::Handle<i::WasmTrustedInstanceData>(),
          i::MaybeHandle<i::JSArrayBuffer>(), i::MaybeHandle<i::FixedArray>(),
          type, offset, is_mutable);

  i::Handle<i::WasmGlobalObject> global_obj;
  if (!maybe_global_obj.ToHandle(&global_obj)) {
    return js_api_scope.AssertException();
  }

  // The infrastructure for `new Foo` calls allocates an object, which is
  // available here as {info.This()}. We're going to discard this object
  // and use {global_obj} instead, but it does have the correct prototype,
  // which we must harvest from it. This makes a difference when the JS
  // constructor function wasn't {WebAssembly.Global} directly, but some
  // subclass: {global_obj} has {WebAssembly.Global}'s prototype at this
  // point, so we must overwrite that with the correct prototype for {Foo}.
  if (!TransferPrototype(i_isolate, global_obj,
                         Utils::OpenHandle(*info.This()))) {
    return js_api_scope.AssertException();
  }

  // Convert value to a WebAssembly value, the default value is 0.
  Local<v8::Value> value = Local<Value>::Cast(info[1]);
  switch (type.kind()) {
    case i::wasm::kI32: {
      int32_t i32_value = 0;
      if (!ToI32(value, context, &i32_value)) {
        return js_api_scope.AssertException();
      }
      global_obj->SetI32(i32_value);
      break;
    }
    case i::wasm::kI64: {
      int64_t i64_value = 0;
      if (!ToI64(value, context, &i64_value)) {
        return js_api_scope.AssertException();
      }
      global_obj->SetI64(i64_value);
      break;
    }
    case i::wasm::kF32: {
      float f32_value = 0;
      if (!ToF32(value, context, &f32_value)) {
        return js_api_scope.AssertException();
      }
      global_obj->SetF32(f32_value);
      break;
    }
    case i::wasm::kF64: {
      double f64_value = 0;
      if (!ToF64(value, context, &f64_value)) {
        return js_api_scope.AssertException();
      }
      global_obj->SetF64(f64_value);
      break;
    }
    case i::wasm::kRef:
      if (info.Length() < 2) {
        thrower.TypeError("Non-defaultable global needs initial value");
        return;
      }
      [[fallthrough]];
    case i::wasm::kRefNull: {
      // We need the wasm default value {null} over {undefined}.
      i::Handle<i::Object> value_handle;
      if (info.Length() < 2) {
        value_handle = DefaultReferenceValue(i_isolate, type);
      } else {
        value_handle = Utils::OpenHandle(*value);
        const char* error_message;
        // While the JS API generally allows indexed types, it currently has
        // no way to specify such types in `new WebAssembly.Global(...)`.
        // TODO(14034): Fix this if that changes.
        DCHECK(!type.has_index());
        i::wasm::CanonicalValueType canonical_type{type};
        if (!i::wasm::JSToWasmObject(i_isolate, value_handle, canonical_type,
                                     &error_message)
                 .ToHandle(&value_handle)) {
          thrower.TypeError("%s", error_message);
          return;
        }
      }
      global_obj->SetRef(value_handle);
      break;
    }
    case i::wasm::kS128: {
      thrower.TypeError(
          "A global of type 'v128' cannot be created in JavaScript");
      return;
    }
    case i::wasm::kRtt:
    case i::wasm::kI8:
    case i::wasm::kI16:
    case i::wasm::kF16:
    case i::wasm::kVoid:
    case i::wasm::kTop:
    case i::wasm::kBottom:
      UNREACHABLE();
  }

  i::Handle<i::JSObject> global_js_object(global_obj);
  info.GetReturnValue().Set(Utils::ToLocal(global_js_object));
}

namespace {

uint32_t GetIterableLength(i::Isolate* isolate, Local<Context> context,
                           Local<Object> iterable) {
  Local<String> length = Utils::ToLocal(isolate->factory()->length_string());
  MaybeLocal<Value> property = iterable->Get(context, length);
  if (property.IsEmpty()) return i::kMaxUInt32;
  MaybeLocal<Uint32> number = property.ToLocalChecked()->ToArrayIndex(context);
  if (number.IsEmpty()) return i::kMaxUInt32;
  DCHECK_NE(i::kMaxUInt32, number.ToLocalChecked()->Value());
  return number.ToLocalChecked()->Value();
}

}  // namespace

// WebAssembly.Tag
void WebAssemblyTagImpl(const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.Tag()"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();

  if (!info.IsConstructCall()) {
    thrower.TypeError("WebAssembly.Tag must be invoked with 'new'");
    return;
  }
  if (!info[0]->IsObject()) {
    thrower.TypeError("Argument 0 must be a tag type");
    return;
  }

  Local<Object> event_type = Local<Object>::Cast(info[0]);
  Local<Context> context = isolate->GetCurrentContext();
  auto enabled_features = WasmEnabledFeatures::FromIsolate(i_isolate);

  // Load the 'parameters' property of the event type.
  Local<String> parameters_key = v8_str(isolate, "parameters");
  v8::MaybeLocal<v8::Value> parameters_maybe =
      event_type->Get(context, parameters_key);
  v8::Local<v8::Value> parameters_value;
  if (!parameters_maybe.ToLocal(&parameters_value) ||
      !parameters_value->IsObject()) {
    thrower.TypeError("Argument 0 must be a tag type with 'parameters'");
    return;
  }
  Local<Object> parameters = parameters_value.As<Object>();
  uint32_t parameters_len = GetIterableLength(i_isolate, context, parameters);
  if (parameters_len == i::kMaxUInt32) {
    thrower.TypeError("Argument 0 contains parameters without 'length'");
    return;
  }
  if (parameters_len > i::wasm::kV8MaxWasmFunctionParams) {
    thrower.TypeError("Argument 0 contains too many parameters");
    return;
  }

  // Decode the tag type and construct a signature.
  std::vector<i::wasm::ValueType> param_types(parameters_len,
                                              i::wasm::kWasmVoid);
  for (uint32_t i = 0; i < parameters_len; ++i) {
    i::wasm::ValueType& type = param_types[i];
    MaybeLocal<Value> maybe = parameters->Get(context, i);
    std::optional<i::wasm::ValueType> maybe_type =
        GetValueType(isolate, maybe, context, enabled_features);
    if (!maybe_type) return;
    type = *maybe_type;
    if (type == i::wasm::kWasmVoid) {
      thrower.TypeError(
          "Argument 0 parameter type at index #%u must be a value type", i);
      return;
    }
  }
  const i::wasm::FunctionSig sig{0, parameters_len, param_types.data()};
  // Set the tag index to 0. It is only used for debugging purposes, and has no
  // meaningful value when declared outside of a wasm module.
  auto tag = i::WasmExceptionTag::New(i_isolate, 0);

  i::wasm::CanonicalTypeIndex type_index =
      i::wasm::GetWasmEngine()->type_canonicalizer()->AddRecursiveGroup(&sig);

  i::Handle<i::JSObject> tag_object =
      i::WasmTagObject::New(i_isolate, &sig, type_index, tag,
                            i::Handle<i::WasmTrustedInstanceData>());
  info.GetReturnValue().Set(Utils::ToLocal(tag_object));
}

namespace {

uint32_t GetEncodedSize(i::DirectHandle<i::WasmTagObject> tag_object) {
  auto serialized_sig = tag_object->serialized_signature();
  i::wasm::WasmTagSig sig{
      0, static_cast<size_t>(serialized_sig->length()),
      reinterpret_cast<i::wasm::ValueType*>(serialized_sig->begin())};
  return i::WasmExceptionPackage::GetEncodedSize(&sig);
}

V8_WARN_UNUSED_RESULT bool EncodeExceptionValues(
    v8::Isolate* isolate,
    i::DirectHandle<i::PodArray<i::wasm::ValueType>> signature,
    i::DirectHandle<i::WasmTagObject> tag_object, const Local<Value>& arg,
    ErrorThrower* thrower, i::DirectHandle<i::FixedArray> values_out) {
  Local<Context> context = isolate->GetCurrentContext();
  uint32_t index = 0;
  if (!arg->IsObject()) {
    thrower->TypeError("Exception values must be an iterable object");
    return false;
  }
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  auto values = arg.As<Object>();
  uint32_t length = GetIterableLength(i_isolate, context, values);
  if (length == i::kMaxUInt32) {
    thrower->TypeError("Exception values argument has no length");
    return false;
  }
  if (length != static_cast<uint32_t>(signature->length())) {
    thrower->TypeError(
        "Number of exception values does not match signature length");
    return false;
  }
  for (int i = 0; i < signature->length(); ++i) {
    Local<Value> value;
    if (!values->Get(context, i).ToLocal(&value)) return false;
    i::wasm::ValueType type = signature->get(i);
    switch (type.kind()) {
      case i::wasm::kI32: {
        int32_t i32 = 0;
        if (!ToI32(value, context, &i32)) return false;
        i::EncodeI32ExceptionValue(values_out, &index, i32);
        break;
      }
      case i::wasm::kI64: {
        int64_t i64 = 0;
        if (!ToI64(value, context, &i64)) return false;
        i::EncodeI64ExceptionValue(values_out, &index, i64);
        break;
      }
      case i::wasm::kF32: {
        float f32 = 0;
        if (!ToF32(value, context, &f32)) return false;
        int32_t i32 = base::bit_cast<int32_t>(f32);
        i::EncodeI32ExceptionValue(values_out, &index, i32);
        break;
      }
      case i::wasm::kF64: {
        double f64 = 0;
        if (!ToF64(value, context, &f64)) return false;
        int64_t i64 = base::bit_cast<int64_t>(f64);
        i::EncodeI64ExceptionValue(values_out, &index, i64);
        break;
      }
      case i::wasm::kRef:
      case i::wasm::kRefNull: {
        const char* error_message;
        i::Handle<i::Object> value_handle = Utils::OpenHandle(*value);
        i::wasm::CanonicalValueType canonical_type;
        if (type.has_index()) {
          // Canonicalize the type using the tag's original module.
          // Indexed types are guaranteed to come from an instance.
          CHECK(tag_object->has_trusted_data());
          i::Tagged<i::WasmTrustedInstanceData> wtid =
              tag_object->trusted_data(i_isolate);
          const i::wasm::WasmModule* module = wtid->module();
          i::wasm::CanonicalTypeIndex index =
              module->canonical_type_id(type.ref_index());
          canonical_type =
              i::wasm::CanonicalValueType::FromIndex(type.kind(), index);
        } else {
          canonical_type = i::wasm::CanonicalValueType{type};
        }
        if (!i::wasm::JSToWasmObject(i_isolate, value_handle, canonical_type,
                                     &error_message)
                 .ToHandle(&value_handle)) {
          thrower->TypeError("%s", error_message);
          return false;
        }
        values_out->set(index++, *value_handle);
        break;
      }
      case i::wasm::kRtt:
      case i::wasm::kI8:
      case i::wasm::kI16:
      case i::wasm::kF16:
      case i::wasm::kVoid:
      case i::wasm::kTop:
      case i::wasm::kBottom:
      case i::wasm::kS128:
        UNREACHABLE();
    }
  }
  return true;
}

}  // namespace

void WebAssemblyExceptionImpl(const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.Exception()"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();

  if (!info.IsConstructCall()) {
    thrower.TypeError("WebAssembly.Exception must be invoked with 'new'");
    return;
  }
  if (!info[0]->IsObject()) {
    thrower.TypeError("Argument 0 must be a WebAssembly tag");
    return;
  }
  i::DirectHandle<i::Object> arg0 = Utils::OpenDirectHandle(*info[0]);
  if (!IsWasmTagObject(i::Cast<i::HeapObject>(*arg0))) {
    thrower.TypeError("Argument 0 must be a WebAssembly tag");
    return;
  }
  auto tag_object = i::Cast<i::WasmTagObject>(arg0);
  i::DirectHandle<i::WasmExceptionTag> tag(
      i::Cast<i::WasmExceptionTag>(tag_object->tag()), i_isolate);
  auto js_tag = i::Cast<i::WasmTagObject>(i_isolate->context()->wasm_js_tag());
  if (*tag == js_tag->tag()) {
    thrower.TypeError("Argument 0 cannot be WebAssembly.JSTag");
    return;
  }
  uint32_t size = GetEncodedSize(tag_object);
  i::Handle<i::WasmExceptionPackage> runtime_exception =
      i::WasmExceptionPackage::New(i_isolate, tag, size);
  // The constructor above should guarantee that the cast below succeeds.
  i::DirectHandle<i::FixedArray> values =
      i::Cast<i::FixedArray>(i::WasmExceptionPackage::GetExceptionValues(
          i_isolate, runtime_exception));
  i::DirectHandle<i::PodArray<i::wasm::ValueType>> signature(
      tag_object->serialized_signature(), i_isolate);
  if (!EncodeExceptionValues(isolate, signature, tag_object, info[1], &thrower,
                             values)) {
    return js_api_scope.AssertException();
  }

  // Third argument: optional ExceptionOption ({traceStack: <bool>}).
  if (!info[2]->IsNullOrUndefined() && !info[2]->IsObject()) {
    thrower.TypeError("Argument 2 is not an object");
    return;
  }
  if (info[2]->IsObject()) {
    Local<Context> context = isolate->GetCurrentContext();
    Local<Object> trace_stack_obj = Local<Object>::Cast(info[2]);
    Local<String> trace_stack_key = v8_str(isolate, "traceStack");
    v8::Local<Value> trace_stack_value;
    if (!trace_stack_obj->Get(context, trace_stack_key)
             .ToLocal(&trace_stack_value)) {
      return js_api_scope.AssertException();
    }
    if (trace_stack_value->BooleanValue(isolate)) {
      auto caller = Utils::OpenHandle(*info.NewTarget());

      i::Handle<i::Object> capture_result;
      if (!i::ErrorUtils::CaptureStackTrace(i_isolate, runtime_exception,
                                            i::SKIP_NONE, caller)
               .ToHandle(&capture_result)) {
        return js_api_scope.AssertException();
      }
    }
  }

  info.GetReturnValue().Set(
      Utils::ToLocal(i::Cast<i::Object>(runtime_exception)));
}

i::Handle<i::JSFunction> NewPromisingWasmExportedFunction(
    i::Isolate* i_isolate, i::DirectHandle<i::WasmExportedFunctionData> data,
    ErrorThrower& thrower) {
  i::DirectHandle<i::WasmTrustedInstanceData> trusted_instance_data{
      data->instance_data(), i_isolate};
  int func_index = data->function_index();
  const i::wasm::WasmModule* module = trusted_instance_data->module();
  i::wasm::ModuleTypeIndex sig_index = module->functions[func_index].sig_index;
  const i::wasm::CanonicalSig* sig =
      i::wasm::GetTypeCanonicalizer()->LookupFunctionSignature(
          module->canonical_sig_id(sig_index));
  i::DirectHandle<i::Code> wrapper;
  if (!internal::wasm::IsJSCompatibleSignature(sig)) {
    // If the signature is incompatible with JS, the original export will have
    // compiled an incompatible signature wrapper, so just reuse that.
    wrapper =
        i::DirectHandle<i::Code>(data->wrapper_code(i_isolate), i_isolate);
  } else {
    wrapper = BUILTIN_CODE(i_isolate, WasmPromising);
  }

  // TODO(14034): Create funcref RTTs lazily?
  i::DirectHandle<i::Map> rtt{
      i::Cast<i::Map>(
          trusted_instance_data->managed_object_maps()->get(sig_index.index)),
      i_isolate};

  int num_imported_functions = module->num_imported_functions;
  i::DirectHandle<i::TrustedObject> implicit_arg;
  if (func_index >= num_imported_functions) {
    implicit_arg = trusted_instance_data;
  } else {
    implicit_arg = i_isolate->factory()->NewWasmImportData(direct_handle(
        i::Cast<i::WasmImportData>(
            trusted_instance_data->dispatch_table_for_imports()->implicit_arg(
                func_index)),
        i_isolate));
  }

#if V8_ENABLE_SANDBOX
  uint64_t signature_hash =
      i::wasm::SignatureHasher::Hash(module->functions[func_index].sig);
#else
  uintptr_t signature_hash = 0;
#endif

  i::DirectHandle<i::WasmInternalFunction> internal =
      i_isolate->factory()->NewWasmInternalFunction(implicit_arg, func_index,
                                                    signature_hash);
  i::DirectHandle<i::WasmFuncRef> func_ref =
      i_isolate->factory()->NewWasmFuncRef(internal, rtt);
  internal->set_call_target(trusted_instance_data->GetCallTarget(func_index));
  if (func_index < num_imported_functions) {
    i::Cast<i::WasmImportData>(implicit_arg)->set_call_origin(*func_ref);
  }

  i::Handle<i::JSFunction> result = i::WasmExportedFunction::New(
      i_isolate, trusted_instance_data, func_ref, internal,
      static_cast<int>(data->sig()->parameter_count()), wrapper);
  return result;
}

// WebAssembly.Function
void WebAssemblyFunction(const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.Function()"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();

  if (!info.IsConstructCall()) {
    thrower.TypeError("WebAssembly.Function must be invoked with 'new'");
    return;
  }
  if (!info[0]->IsObject()) {
    thrower.TypeError("Argument 0 must be a function type");
    return;
  }
  Local<Object> function_type = Local<Object>::Cast(info[0]);
  Local<Context> context = isolate->GetCurrentContext();
  auto enabled_features = WasmEnabledFeatures::FromIsolate(i_isolate);

  // Load the 'parameters' property of the function type.
  Local<String> parameters_key = v8_str(isolate, "parameters");
  v8::MaybeLocal<v8::Value> parameters_maybe =
      function_type->Get(context, parameters_key);
  v8::Local<v8::Value> parameters_value;
  if (!parameters_maybe.ToLocal(&parameters_value) ||
      !parameters_value->IsObject()) {
    thrower.TypeError("Argument 0 must be a function type with 'parameters'");
    return;
  }
  Local<Object> parameters = parameters_value.As<Object>();
  uint32_t parameters_len = GetIterableLength(i_isolate, context, parameters);
  if (parameters_len == i::kMaxUInt32) {
    thrower.TypeError("Argument 0 contains parameters without 'length'");
    return;
  }
  if (parameters_len > i::wasm::kV8MaxWasmFunctionParams) {
    thrower.TypeError("Argument 0 contains too many parameters");
    return;
  }

  // Load the 'results' property of the function type.
  v8::Local<v8::Value> results_value;
  if (!function_type->Get(context, v8_str(isolate, "results"))
           .ToLocal(&results_value)) {
    return js_api_scope.AssertException();
  }
  if (!results_value->IsObject()) {
    thrower.TypeError("Argument 0 must be a function type with 'results'");
    return;
  }
  Local<Object> results = results_value.As<Object>();
  uint32_t results_len = GetIterableLength(i_isolate, context, results);
  if (results_len == i::kMaxUInt32) {
    thrower.TypeError("Argument 0 contains results without 'length'");
    return;
  }
  if (results_len > i::wasm::kV8MaxWasmFunctionReturns) {
    thrower.TypeError("Argument 0 contains too many results");
    return;
  }

  // Decode the function type and construct a signature.
  i::Zone zone(i_isolate->allocator(), ZONE_NAME);
  i::wasm::FunctionSig::Builder builder(&zone, results_len, parameters_len);
  for (uint32_t i = 0; i < parameters_len; ++i) {
    MaybeLocal<Value> maybe = parameters->Get(context, i);
    std::optional<i::wasm::ValueType> maybe_type =
        GetValueType(isolate, maybe, context, enabled_features);
    if (!maybe_type) return;
    i::wasm::ValueType type = *maybe_type;
    if (type == i::wasm::kWasmVoid) {
      thrower.TypeError(
          "Argument 0 parameter type at index #%u must be a value type", i);
      return;
    }
    builder.AddParam(type);
  }
  for (uint32_t i = 0; i < results_len; ++i) {
    MaybeLocal<Value> maybe = results->Get(context, i);
    std::optional<i::wasm::ValueType> maybe_type =
        GetValueType(isolate, maybe, context, enabled_features);
    if (!maybe_type) return js_api_scope.AssertException();
    i::wasm::ValueType type = *maybe_type;
    if (type == i::wasm::kWasmVoid) {
      thrower.TypeError(
          "Argument 0 result type at index #%u must be a value type", i);
      return;
    }
    builder.AddReturn(type);
  }

  if (!info[1]->IsObject()) {
    thrower.TypeError("Argument 1 must be a function");
    return;
  }
  const i::wasm::FunctionSig* sig = builder.Get();
  i::wasm::Suspend suspend = i::wasm::kNoSuspend;

  i::Handle<i::JSReceiver> callable = Utils::OpenHandle(*info[1].As<Object>());
  if (i::IsWasmSuspendingObject(*callable)) {
    suspend = i::wasm::kSuspend;
    callable = handle(i::Cast<i::WasmSuspendingObject>(*callable)->callable(),
                      i_isolate);
    DCHECK(i::IsCallable(*callable));
  } else if (!i::IsCallable(*callable)) {
    thrower.TypeError("Argument 1 must be a function");
    return;
  }

  i::Handle<i::JSFunction> result =
      i::WasmJSFunction::New(i_isolate, sig, callable, suspend);
  info.GetReturnValue().Set(Utils::ToLocal(result));
}

// WebAssembly.promising(Function) -> Function
void WebAssemblyPromising(const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.promising()"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();
  i_isolate->CountUsage(v8::Isolate::kWasmJavaScriptPromiseIntegration);

  if (!info[0]->IsFunction()) {
    thrower.TypeError("Argument 0 must be a function");
    return;
  }
  i::DirectHandle<i::JSReceiver> callable =
      Utils::OpenDirectHandle(*info[0].As<Function>());

  if (!i::WasmExportedFunction::IsWasmExportedFunction(*callable)) {
    thrower.TypeError("Argument 0 must be a WebAssembly exported function");
    return;
  }
  auto wasm_exported_function = i::Cast<i::WasmExportedFunction>(*callable);
  i::DirectHandle<i::WasmExportedFunctionData> data(
      wasm_exported_function->shared()->wasm_exported_function_data(),
      i_isolate);
  if (data->instance_data()->module_object()->is_asm_js()) {
    thrower.TypeError("Argument 0 must be a WebAssembly exported function");
    return;
  }
  i::Handle<i::JSFunction> result =
      NewPromisingWasmExportedFunction(i_isolate, data, thrower);
  info.GetReturnValue().Set(Utils::ToLocal(i::Cast<i::JSObject>(result)));
}

// WebAssembly.Suspending(Function) -> Suspending
void WebAssemblySuspendingImpl(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.Suspending()"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();
  i_isolate->CountUsage(v8::Isolate::kWasmJavaScriptPromiseIntegration);

  if (!info.IsConstructCall()) {
    thrower.TypeError("WebAssembly.Suspending must be invoked with 'new'");
    return;
  }
  if (!info[0]->IsFunction()) {
    thrower.TypeError("Argument 0 must be a function");
    return;
  }

  i::DirectHandle<i::JSReceiver> callable =
      Utils::OpenDirectHandle(*info[0].As<Function>());

  if (i::WasmExportedFunction::IsWasmExportedFunction(*callable) ||
      i::WasmJSFunction::IsWasmJSFunction(*callable)) {
    thrower.TypeError("Argument 0 must not be a WebAssembly function");
    return;
  }

  i::Handle<i::WasmSuspendingObject> result =
      i::WasmSuspendingObject::New(i_isolate, callable);
  info.GetReturnValue().Set(Utils::ToLocal(i::Cast<i::JSObject>(result)));
}

// WebAssembly.Function.prototype.type() -> FunctionType
void WebAssemblyFunctionType(const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.Function.type()"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();

  i::Handle<i::JSObject> type;

  i::Handle<i::Object> fun = Utils::OpenHandle(*info.This());
  if (i::WasmExportedFunction::IsWasmExportedFunction(*fun)) {
    auto wasm_exported_function = i::Cast<i::WasmExportedFunction>(fun);
    i::Tagged<i::WasmExportedFunctionData> data =
        wasm_exported_function->shared()->wasm_exported_function_data();
    // Note: while {zone} is only referenced directly in the if-block below,
    // its lifetime must exceed that of {sig}.
    // TODO(42210967): Creating a Zone just to create a modified copy of a
    // single signature is rather expensive. It would be good to find a more
    // efficient approach, if this function is ever considered performance
    // relevant.
    i::Zone zone(i_isolate->allocator(), ZONE_NAME);
    const i::wasm::FunctionSig* sig =
        data->instance_data()->module()->functions[data->function_index()].sig;
    i::wasm::Promise promise_flags =
        i::WasmFunctionData::
```