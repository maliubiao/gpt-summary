Response: The user wants me to summarize the functionality of the C++ code snippet provided. This is the second part of a three-part file, so I should focus on the functions defined in this specific section.

The code deals with the implementation of JavaScript APIs for WebAssembly within the V8 engine. It defines how JavaScript interacts with various WebAssembly concepts like memory, globals, tables, tags, exceptions, and functions.

I need to identify the core functionalities implemented in this part and, if applicable, provide JavaScript examples to illustrate their usage.
这是 `v8/src/wasm/wasm-js.cc` 文件的一部分，主要负责实现 WebAssembly 的 JavaScript API。 这部分代码主要关注以下几个 WebAssembly 核心概念的 JavaScript 绑定：

1. **WebAssembly.Memory**:  提供创建和操作 WebAssembly 内存的接口。
    *   实现了 `WebAssembly.Memory` 构造函数，允许通过 JavaScript 创建 WebAssembly 内存实例。
    *   处理 `initial` (或 `minimum`) 和 `maximum` 属性来定义内存的大小。
    *   处理 `shared` 属性来创建共享内存。
    *   提供 `grow` 方法来增加内存的大小。
    *   提供 `buffer` 属性来访问内存的 `ArrayBuffer`。
    *   提供 `type` 方法返回内存的类型信息。

    **JavaScript 示例:**

    ```javascript
    // 创建一个初始大小为 1 个 Wasm 页面的内存
    const memory = new WebAssembly.Memory({ initial: 1 });

    // 获取内存的 ArrayBuffer
    const buffer = memory.buffer;

    // 增加内存大小到 2 个 Wasm 页面
    memory.grow(1);

    // 获取内存类型信息
    const memoryType = memory.type();
    console.log(memoryType.initial); // 输出: 2
    ```

2. **WebAssembly.Global**:  提供创建和访问 WebAssembly 全局变量的接口。
    *   实现了 `WebAssembly.Global` 构造函数，允许通过 JavaScript 创建 WebAssembly 全局变量实例。
    *   处理 `mutable` 属性来定义全局变量是否可变。
    *   处理 `value` 属性来定义全局变量的类型。
    *   实现了全局变量的获取 (`value` getter 和 `valueOf` 方法) 和设置 (`value` setter) 操作。
    *   提供 `type` 方法返回全局变量的类型信息。

    **JavaScript 示例:**

    ```javascript
    // 创建一个不可变的 i32 类型的全局变量，初始值为 42
    const globalI32 = new WebAssembly.Global({ value: 'i32' }, 42);

    // 获取全局变量的值
    console.log(globalI32.value); // 输出: 42

    // 创建一个可变的 f64 类型的全局变量
    const mutableGlobalF64 = new WebAssembly.Global({ value: 'f64', mutable: true }, 3.14);

    // 设置可变全局变量的值
    mutableGlobalF64.value = 2.71;
    console.log(mutableGlobalF64.value); // 输出: 2.71
    ```

3. **WebAssembly.Tag**: 提供创建 WebAssembly 异常标签的接口。
    *   实现了 `WebAssembly.Tag` 构造函数，允许通过 JavaScript 创建异常标签实例。
    *   处理 `parameters` 属性来定义异常携带的参数类型。
    *   提供 `type` 方法返回标签的类型信息（即异常的签名）。

    **JavaScript 示例:**

    ```javascript
    // 创建一个没有参数的异常标签
    const tag1 = new WebAssembly.Tag({ parameters: [] });

    // 创建一个带有 i32 和 f64 参数的异常标签
    const tag2 = new WebAssembly.Tag({ parameters: ['i32', 'f64'] });
    ```

4. **WebAssembly.Exception**: 提供创建 WebAssembly 异常实例的接口。
    *   实现了 `WebAssembly.Exception` 构造函数，允许通过 JavaScript 创建异常实例。
    *   需要一个 `WebAssembly.Tag` 实例作为第一个参数，用于指定异常的类型。
    *   第二个参数是包含异常值的可迭代对象，值的类型需要与标签定义的参数类型匹配。
    *   提供 `getArg` 方法来获取异常的参数值。
    *   提供 `is` 方法来判断一个异常是否是指定的标签类型的异常。

    **JavaScript 示例:**

    ```javascript
    // 创建一个带有 i32 参数的异常标签
    const tag = new WebAssembly.Tag({ parameters: ['i32'] });

    // 创建一个异常实例，携带值为 10 的 i32 参数
    const exception = new WebAssembly.Exception(tag, [10]);

    // 判断异常是否是 tag 类型的
    console.log(exception.is(tag)); // 输出: true

    // 获取异常的第一个参数值
    console.log(exception.getArg(tag, 0)); // 输出: 10
    ```

5. **WebAssembly.Function**: 提供创建 WebAssembly 函数包装器的接口。
    *   实现了 `WebAssembly.Function` 构造函数，允许将 JavaScript 函数转换为可以在 WebAssembly 中调用的函数。
    *   需要一个函数类型对象作为第一个参数，定义了函数的参数和返回值类型。
    *   需要一个 JavaScript 函数作为第二个参数，作为 WebAssembly 函数的实现。
    *   提供 `type` 方法返回函数的类型信息。

    **JavaScript 示例:**

    ```javascript
    // 定义一个函数类型，接收一个 i32 参数并返回一个 f64 值
    const functionType = { parameters: ['i32'], results: ['f64'] };

    // 定义一个 JavaScript 函数
    function jsFunction(x) {
      return x * 1.5;
    }

    // 创建一个 WebAssembly 函数包装器
    const wasmFunction = new WebAssembly.Function(functionType, jsFunction);

    // 获取 WebAssembly 函数的类型信息
    const wasmFunctionType = wasmFunction.type();
    console.log(wasmFunctionType.parameters); // 输出: ['i32']
    console.log(wasmFunctionType.results);    // 输出: ['f64']
    ```

6. **WebAssembly.promising**:  将一个返回值的 WebAssembly 导出函数包装成返回 Promise 的函数。

    **JavaScript 示例:**

    ```javascript
    // 假设 instance 是一个 WebAssembly.Instance 的实例，其中有一个名为 'exported_function' 的导出函数
    const promisingFunction = WebAssembly.promising(instance.exports.exported_function);

    // 调用 promisingFunction 将返回一个 Promise
    promisingFunction(arg1, arg2).then(result => {
      console.log(result);
    });
    ```

7. **WebAssembly.Suspending**: 创建一个暂停对象，用于标记一个 JavaScript 函数可以被 WebAssembly 同步调用并可能暂停。

    **JavaScript 示例:**

    ```javascript
    async function suspendingFunction() {
      // ... 一些异步操作 ...
      return 42;
    }

    const suspendingObject = new WebAssembly.Suspending(suspendingFunction);
    ```

这部分代码还包含了一些辅助函数，例如 `GetValueType` 用于将字符串转换为 WebAssembly 的值类型，以及一些用于类型转换的辅助函数 (如 `ToI32`, `ToF64` 等)。此外，它还定义了一些内部的辅助函数和常量，用于设置构造函数和原型对象。

总而言之，这段代码是 V8 引擎中实现 WebAssembly JavaScript API 的关键部分，它允许 JavaScript 代码与 WebAssembly 的内存、全局变量、表、异常和函数进行交互。
Prompt: 
```
这是目录为v8/src/wasm/wasm-js.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
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
        i::WasmFunctionData::PromiseField::decode(data->js_promise_flags());
    if (promise_flags == i::wasm::kPromise) {
      // The wrapper function returns a promise as an externref instead of the
      // original return type.
      size_t param_count = sig->parameter_count();
      i::wasm::FunctionSig::Builder builder(&zone, 1, param_count);
      for (size_t i = 0; i < param_count; ++i) {
        builder.AddParam(sig->GetParam(i));
      }
      builder.AddReturn(i::wasm::kWasmExternRef);
      sig = builder.Get();
    }
    type = i::wasm::GetTypeForFunction(i_isolate, sig);
  } else if (i::WasmJSFunction::IsWasmJSFunction(*fun)) {
    const i::wasm::CanonicalSig* sig = i::Cast<i::WasmJSFunction>(fun)
                                           ->shared()
                                           ->wasm_js_function_data()
                                           ->GetSignature();
    type = i::wasm::GetTypeForFunction(i_isolate, sig);
  } else {
    thrower.TypeError("Receiver must be a WebAssembly.Function");
    return;
  }

  info.GetReturnValue().Set(Utils::ToLocal(type));
}

constexpr const char* kName_WasmGlobalObject = "WebAssembly.Global";
constexpr const char* kName_WasmMemoryObject = "WebAssembly.Memory";
constexpr const char* kName_WasmInstanceObject = "WebAssembly.Instance";
constexpr const char* kName_WasmTableObject = "WebAssembly.Table";
constexpr const char* kName_WasmTagObject = "WebAssembly.Tag";
constexpr const char* kName_WasmExceptionPackage = "WebAssembly.Exception";

#define EXTRACT_THIS(var, WasmType)                                  \
  i::Handle<i::WasmType> var;                                        \
  {                                                                  \
    i::Handle<i::Object> this_arg = Utils::OpenHandle(*info.This()); \
    if (!Is##WasmType(*this_arg)) {                                  \
      thrower.TypeError("Receiver is not a %s", kName_##WasmType);   \
      return;                                                        \
    }                                                                \
    var = i::Cast<i::WasmType>(this_arg);                            \
  }

void WebAssemblyInstanceGetExportsImpl(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.Instance.exports()"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();
  EXTRACT_THIS(receiver, WasmInstanceObject);
  i::Handle<i::JSObject> exports_object(receiver->exports_object(), i_isolate);

  info.GetReturnValue().Set(Utils::ToLocal(exports_object));
}

void WebAssemblyTableGetLengthImpl(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.Table.length()"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();
  EXTRACT_THIS(receiver, WasmTableObject);

  int length = receiver->current_length();
  DCHECK_LE(0, length);
  info.GetReturnValue().Set(
      AddressValueFromUnsigned(isolate, receiver->address_type(), length));
}

// WebAssembly.Table.grow(num, init_value = null) -> num
void WebAssemblyTableGrowImpl(const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.Table.grow()"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();
  Local<Context> context = isolate->GetCurrentContext();
  EXTRACT_THIS(receiver, WasmTableObject);

  std::optional<uint64_t> maybe_grow_by = AddressValueToU64(
      &thrower, context, info[0], "Argument 0", receiver->address_type());
  if (!maybe_grow_by) return js_api_scope.AssertException();
  uint64_t grow_by = *maybe_grow_by;

  i::Handle<i::Object> init_value;

  if (info.Length() >= 2) {
    init_value = Utils::OpenHandle(*info[1]);
    const char* error_message;
    if (!i::WasmTableObject::JSToWasmElement(i_isolate, receiver, init_value,
                                             &error_message)
             .ToHandle(&init_value)) {
      thrower.TypeError("Argument 1 is invalid: %s", error_message);
      return;
    }
  } else if (receiver->type().is_non_nullable()) {
    thrower.TypeError(
        "Argument 1 must be specified for non-nullable element type");
    return;
  } else {
    init_value = DefaultReferenceValue(i_isolate, receiver->type());
  }

  static_assert(i::wasm::kV8MaxWasmTableSize <= i::kMaxUInt32);
  int old_size = grow_by > i::wasm::kV8MaxWasmTableSize
                     ? -1
                     : i::WasmTableObject::Grow(i_isolate, receiver,
                                                static_cast<uint32_t>(grow_by),
                                                init_value);
  if (old_size < 0) {
    thrower.RangeError("failed to grow table by %" PRIu64, grow_by);
    return;
  }
  info.GetReturnValue().Set(
      AddressValueFromUnsigned(isolate, receiver->address_type(), old_size));
}

namespace {
V8_WARN_UNUSED_RESULT bool WasmObjectToJSReturnValue(
    v8::ReturnValue<v8::Value>& return_value, i::Handle<i::Object> value,
    i::wasm::ValueType type, i::Isolate* isolate, ErrorThrower* thrower) {
  switch (type.heap_type().representation()) {
    case internal::wasm::HeapType::kStringViewWtf8:
      thrower->TypeError("%s", "stringview_wtf8 has no JS representation");
      return false;
    case internal::wasm::HeapType::kStringViewWtf16:
      thrower->TypeError("%s", "stringview_wtf16 has no JS representation");
      return false;
    case internal::wasm::HeapType::kStringViewIter:
      thrower->TypeError("%s", "stringview_iter has no JS representation");
      return false;
    case internal::wasm::HeapType::kExn:
    case internal::wasm::HeapType::kNoExn:
      thrower->TypeError("invalid type %s", type.name().c_str());
      return false;
    default:
      return_value.Set(Utils::ToLocal(i::wasm::WasmToJSObject(isolate, value)));
      return true;
  }
}
}  // namespace

// WebAssembly.Table.get(num) -> any
void WebAssemblyTableGetImpl(const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.Table.get()"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();
  Local<Context> context = isolate->GetCurrentContext();
  EXTRACT_THIS(receiver, WasmTableObject);

  std::optional<uint64_t> maybe_address = AddressValueToU64(
      &thrower, context, info[0], "Argument 0", receiver->address_type());
  if (!maybe_address) return;
  uint64_t address = *maybe_address;

  if (address > i::kMaxUInt32 ||
      !receiver->is_in_bounds(static_cast<uint32_t>(address))) {
    thrower.RangeError("invalid address %" PRIu64 " in %s table of size %d",
                       address, receiver->type().name().c_str(),
                       receiver->current_length());
    return;
  }

  i::Handle<i::Object> result = i::WasmTableObject::Get(
      i_isolate, receiver, static_cast<uint32_t>(address));

  v8::ReturnValue<v8::Value> return_value = info.GetReturnValue();
  if (!WasmObjectToJSReturnValue(return_value, result, receiver->type(),
                                 i_isolate, &thrower)) {
    return js_api_scope.AssertException();
  }
}

// WebAssembly.Table.set(num, any)
void WebAssemblyTableSetImpl(const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.Table.set()"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();
  Local<Context> context = isolate->GetCurrentContext();
  EXTRACT_THIS(table_object, WasmTableObject);

  std::optional<uint64_t> maybe_address = AddressValueToU64(
      &thrower, context, info[0], "Argument 0", table_object->address_type());
  if (!maybe_address) return js_api_scope.AssertException();
  uint64_t address = *maybe_address;

  if (address > i::kMaxUInt32 ||
      !table_object->is_in_bounds(static_cast<uint32_t>(address))) {
    thrower.RangeError("invalid address %" PRIu64 " in %s table of size %d",
                       address, table_object->type().name().c_str(),
                       table_object->current_length());
    return;
  }

  i::Handle<i::Object> element;
  if (info.Length() >= 2) {
    element = Utils::OpenHandle(*info[1]);
    const char* error_message;
    if (!i::WasmTableObject::JSToWasmElement(i_isolate, table_object, element,
                                             &error_message)
             .ToHandle(&element)) {
      thrower.TypeError("Argument 1 is invalid for table: %s", error_message);
      return;
    }
  } else if (table_object->type().is_defaultable()) {
    element = DefaultReferenceValue(i_isolate, table_object->type());
  } else {
    thrower.TypeError("Table of non-defaultable type %s needs explicit element",
                      table_object->type().name().c_str());
    return;
  }

  i::WasmTableObject::Set(i_isolate, table_object,
                          static_cast<uint32_t>(address), element);
}

// WebAssembly.Table.type() -> TableType
void WebAssemblyTableType(const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.Table.type()"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();
  EXTRACT_THIS(table, WasmTableObject);
  std::optional<uint64_t> max_size = table->maximum_length_u64();
  auto type = i::wasm::GetTypeForTable(i_isolate, table->type(),
                                       table->current_length(), max_size,
                                       table->address_type());
  info.GetReturnValue().Set(Utils::ToLocal(type));
}

// WebAssembly.Memory.grow(num) -> num
void WebAssemblyMemoryGrowImpl(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.Memory.grow()"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();
  Local<Context> context = isolate->GetCurrentContext();
  EXTRACT_THIS(receiver, WasmMemoryObject);

  std::optional<uint64_t> maybe_delta_pages = AddressValueToU64(
      &thrower, context, info[0], "Argument 0", receiver->address_type());
  if (!maybe_delta_pages) return js_api_scope.AssertException();
  uint64_t delta_pages = *maybe_delta_pages;

  i::DirectHandle<i::JSArrayBuffer> old_buffer(receiver->array_buffer(),
                                               i_isolate);

  uint64_t old_pages = old_buffer->byte_length() / i::wasm::kWasmPageSize;
  uint64_t max_pages = receiver->maximum_pages();

  if (delta_pages > max_pages - old_pages) {
    thrower.RangeError("Maximum memory size exceeded");
    return;
  }

  static_assert(i::wasm::kV8MaxWasmMemory64Pages <= i::kMaxUInt32);
  int32_t ret = i::WasmMemoryObject::Grow(i_isolate, receiver,
                                          static_cast<uint32_t>(delta_pages));
  if (ret == -1) {
    thrower.RangeError("Unable to grow instance memory");
    return;
  }
  info.GetReturnValue().Set(
      AddressValueFromUnsigned(isolate, receiver->address_type(), ret));
}

// WebAssembly.Memory.buffer -> ArrayBuffer
void WebAssemblyMemoryGetBufferImpl(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.Memory.buffer"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();
  EXTRACT_THIS(receiver, WasmMemoryObject);

  i::DirectHandle<i::Object> buffer_obj(receiver->array_buffer(), i_isolate);
  DCHECK(IsJSArrayBuffer(*buffer_obj));
  i::Handle<i::JSArrayBuffer> buffer(i::Cast<i::JSArrayBuffer>(*buffer_obj),
                                     i_isolate);
  if (buffer->is_shared()) {
    // TODO(gdeepti): More needed here for when cached buffer, and current
    // buffer are out of sync, handle that here when bounds checks, and Grow
    // are handled correctly.
    Maybe<bool> result =
        buffer->SetIntegrityLevel(i_isolate, buffer, i::FROZEN, i::kDontThrow);
    if (!result.FromJust()) {
      thrower.TypeError(
          "Status of setting SetIntegrityLevel of buffer is false.");
      return;
    }
  }
  v8::ReturnValue<v8::Value> return_value = info.GetReturnValue();
  return_value.Set(Utils::ToLocal(buffer));
}

// WebAssembly.Memory.type() -> MemoryType
void WebAssemblyMemoryType(const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.Memory.type()"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();
  EXTRACT_THIS(memory, WasmMemoryObject);

  i::DirectHandle<i::JSArrayBuffer> buffer(memory->array_buffer(), i_isolate);
  size_t curr_size = buffer->byte_length() / i::wasm::kWasmPageSize;
  DCHECK_LE(curr_size, std::numeric_limits<uint32_t>::max());
  uint32_t min_size = static_cast<uint32_t>(curr_size);
  std::optional<uint32_t> max_size;
  if (memory->has_maximum_pages()) {
    uint64_t max_size64 = memory->maximum_pages();
    DCHECK_LE(max_size64, std::numeric_limits<uint32_t>::max());
    max_size.emplace(static_cast<uint32_t>(max_size64));
  }
  bool shared = buffer->is_shared();
  auto type = i::wasm::GetTypeForMemory(i_isolate, min_size, max_size, shared,
                                        memory->address_type());
  info.GetReturnValue().Set(Utils::ToLocal(type));
}

// WebAssembly.Tag.type() -> FunctionType
void WebAssemblyTagType(const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.Tag.type()"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();
  EXTRACT_THIS(tag, WasmTagObject);

  int n = tag->serialized_signature()->length();
  std::vector<i::wasm::ValueType> data(n);
  if (n > 0) {
    tag->serialized_signature()->copy_out(0, data.data(), n);
  }
  const i::wasm::FunctionSig sig{0, data.size(), data.data()};
  constexpr bool kForException = true;
  auto type = i::wasm::GetTypeForFunction(i_isolate, &sig, kForException);
  info.GetReturnValue().Set(Utils::ToLocal(type));
}

void WebAssemblyExceptionGetArgImpl(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.Exception.getArg()"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();
  EXTRACT_THIS(exception, WasmExceptionPackage);

  i::Handle<i::WasmTagObject> tag_object;
  if (!GetFirstArgumentAsTag(info, &thrower).ToHandle(&tag_object)) {
    return js_api_scope.AssertException();
  }
  Local<Context> context = isolate->GetCurrentContext();
  std::optional<uint32_t> maybe_index =
      EnforceUint32("Index", info[1], context, &thrower);
  if (!maybe_index) return js_api_scope.AssertException();
  uint32_t index = *maybe_index;
  auto maybe_values =
      i::WasmExceptionPackage::GetExceptionValues(i_isolate, exception);

  auto this_tag =
      i::WasmExceptionPackage::GetExceptionTag(i_isolate, exception);
  DCHECK(IsWasmExceptionTag(*this_tag));
  if (tag_object->tag() != *this_tag) {
    thrower.TypeError("First argument does not match the exception tag");
    return;
  }

  DCHECK(!IsUndefined(*maybe_values));
  auto values = i::Cast<i::FixedArray>(maybe_values);
  auto signature = tag_object->serialized_signature();
  if (index >= static_cast<uint32_t>(signature->length())) {
    thrower.RangeError("Index out of range");
    return;
  }
  // First, find the index in the values array.
  uint32_t decode_index = 0;
  // Since the bounds check above passed, the cast to int is safe.
  for (int i = 0; i < static_cast<int>(index); ++i) {
    switch (signature->get(i).kind()) {
      case i::wasm::kI32:
      case i::wasm::kF32:
        decode_index += 2;
        break;
      case i::wasm::kI64:
      case i::wasm::kF64:
        decode_index += 4;
        break;
      case i::wasm::kRef:
      case i::wasm::kRefNull:
        decode_index++;
        break;
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
  // Decode the value at {decode_index}.
  Local<Value> result;
  switch (signature->get(index).kind()) {
    case i::wasm::kI32: {
      uint32_t u32_bits = 0;
      i::DecodeI32ExceptionValue(values, &decode_index, &u32_bits);
      int32_t i32 = static_cast<int32_t>(u32_bits);
      result = v8::Integer::New(isolate, i32);
      break;
    }
    case i::wasm::kI64: {
      uint64_t u64_bits = 0;
      i::DecodeI64ExceptionValue(values, &decode_index, &u64_bits);
      int64_t i64 = static_cast<int64_t>(u64_bits);
      result = v8::BigInt::New(isolate, i64);
      break;
    }
    case i::wasm::kF32: {
      uint32_t f32_bits = 0;
      DecodeI32ExceptionValue(values, &decode_index, &f32_bits);
      float f32 = base::bit_cast<float>(f32_bits);
      result = v8::Number::New(isolate, f32);
      break;
    }
    case i::wasm::kF64: {
      uint64_t f64_bits = 0;
      DecodeI64ExceptionValue(values, &decode_index, &f64_bits);
      double f64 = base::bit_cast<double>(f64_bits);
      result = v8::Number::New(isolate, f64);
      break;
    }
    case i::wasm::kRef:
    case i::wasm::kRefNull: {
      i::Handle<i::Object> obj = handle(values->get(decode_index), i_isolate);
      ReturnValue<Value> return_value = info.GetReturnValue();
      if (!WasmObjectToJSReturnValue(return_value, obj, signature->get(index),
                                     i_isolate, &thrower)) {
        return js_api_scope.AssertException();
      }
      return;
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
  info.GetReturnValue().Set(result);
}

void WebAssemblyExceptionIsImpl(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.Exception.is()"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();
  EXTRACT_THIS(exception, WasmExceptionPackage);

  auto tag = i::WasmExceptionPackage::GetExceptionTag(i_isolate, exception);
  DCHECK(IsWasmExceptionTag(*tag));

  i::Handle<i::WasmTagObject> tag_object;
  if (!GetFirstArgumentAsTag(info, &thrower).ToHandle(&tag_object)) {
    return js_api_scope.AssertException();
  }
  info.GetReturnValue().Set(tag_object->tag() == *tag);
}

void WebAssemblyGlobalGetValueCommon(WasmJSApiScope& js_api_scope) {
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();
  auto& info = js_api_scope.callback_info();  // Needed by EXTRACT_THIS.
  EXTRACT_THIS(receiver, WasmGlobalObject);

  v8::ReturnValue<v8::Value> return_value = info.GetReturnValue();

  switch (receiver->type().kind()) {
    case i::wasm::kI32:
      return_value.Set(receiver->GetI32());
      break;
    case i::wasm::kI64: {
      Local<BigInt> value = BigInt::New(isolate, receiver->GetI64());
      return_value.Set(value);
      break;
    }
    case i::wasm::kF32:
      return_value.Set(receiver->GetF32());
      break;
    case i::wasm::kF64:
      return_value.Set(receiver->GetF64());
      break;
    case i::wasm::kS128:
      thrower.TypeError("Can't get the value of s128 WebAssembly.Global");
      break;
    case i::wasm::kRef:
    case i::wasm::kRefNull:
      if (!WasmObjectToJSReturnValue(return_value, receiver->GetRef(),
                                     receiver->type(), i_isolate, &thrower)) {
        return js_api_scope.AssertException();
      }
      break;
    case i::wasm::kRtt:
    case i::wasm::kI8:
    case i::wasm::kI16:
    case i::wasm::kF16:
    case i::wasm::kTop:
    case i::wasm::kBottom:
    case i::wasm::kVoid:
      UNREACHABLE();
  }
}

// WebAssembly.Global.valueOf() -> num
void WebAssemblyGlobalValueOfImpl(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.Global.valueOf()"};
  return WebAssemblyGlobalGetValueCommon(js_api_scope);
}

// get WebAssembly.Global.value -> num
void WebAssemblyGlobalGetValueImpl(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "get WebAssembly.Global.value)"};
  return WebAssemblyGlobalGetValueCommon(js_api_scope);
}

// set WebAssembly.Global.value(num)
void WebAssemblyGlobalSetValueImpl(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "set WebAssembly.Global.value)"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();
  EXTRACT_THIS(receiver, WasmGlobalObject);

  if (!receiver->is_mutable()) {
    thrower.TypeError("Can't set the value of an immutable global.");
    return;
  }
  if (info.Length() == 0) {
    thrower.TypeError("Argument 0 is required");
    return;
  }

  Local<Context> context = isolate->GetCurrentContext();
  switch (receiver->type().kind()) {
    case i::wasm::kI32: {
      int32_t i32_value = 0;
      if (!info[0]->Int32Value(context).To(&i32_value)) {
        return js_api_scope.AssertException();
      }
      receiver->SetI32(i32_value);
      break;
    }
    case i::wasm::kI64: {
      v8::Local<v8::BigInt> bigint_value;
      if (!info[0]->ToBigInt(context).ToLocal(&bigint_value)) {
        return js_api_scope.AssertException();
      }
      receiver->SetI64(bigint_value->Int64Value());
      break;
    }
    case i::wasm::kF32: {
      double f64_value = 0;
      if (!info[0]->NumberValue(context).To(&f64_value)) {
        return js_api_scope.AssertException();
      }
      receiver->SetF32(i::DoubleToFloat32(f64_value));
      break;
    }
    case i::wasm::kF64: {
      double f64_value = 0;
      if (!info[0]->NumberValue(context).To(&f64_value)) {
        return js_api_scope.AssertException();
      }
      receiver->SetF64(f64_value);
      break;
    }
    case i::wasm::kS128:
      thrower.TypeError("Can't set the value of s128 WebAssembly.Global");
      break;
    case i::wasm::kRef:
    case i::wasm::kRefNull: {
      const i::wasm::WasmModule* module =
          receiver->has_trusted_data()
              ? receiver->trusted_data(i_isolate)->module()
              : nullptr;
      i::Handle<i::Object> value = Utils::OpenHandle(*info[0]);
      const char* error_message;
      if (!i::wasm::JSToWasmObject(i_isolate, module, value, receiver->type(),
                                   &error_message)
               .ToHandle(&value)) {
        thrower.TypeError("%s", error_message);
        return;
      }
      receiver->SetRef(value);
      return;
    }
    case i::wasm::kRtt:
    case i::wasm::kI8:
    case i::wasm::kI16:
    case i::wasm::kF16:
    case i::wasm::kTop:
    case i::wasm::kBottom:
    case i::wasm::kVoid:
      UNREACHABLE();
  }
}

// WebAssembly.Global.type() -> GlobalType
void WebAssemblyGlobalType(const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.Global.type())"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();
  EXTRACT_THIS(global, WasmGlobalObject);

  auto type = i::wasm::GetTypeForGlobal(i_isolate, global->is_mutable(),
                                        global->type());
  info.GetReturnValue().Set(Utils::ToLocal(type));
}

}  // namespace

namespace internal {
namespace wasm {

// Define the callbacks in v8::internal::wasm namespace. The implementation is
// in v8::internal directly.
#define DEF_WASM_JS_EXTERNAL_REFERENCE(Name)                   \
  void Name(const v8::FunctionCallbackInfo<v8::Value>& info) { \
    Name##Impl(info);                                          \
  }
WASM_JS_EXTERNAL_REFERENCE_LIST(DEF_WASM_JS_EXTERNAL_REFERENCE)
#undef DEF_WASM_JS_EXTERNAL_REFERENCE

}  // namespace wasm
}  // namespace internal

// TODO(titzer): we use the API to create the function template because the
// internal guts are too ugly to replicate here.
static i::Handle<i::FunctionTemplateInfo> NewFunctionTemplate(
    i::Isolate* i_isolate, FunctionCallback func, bool has_prototype,
    SideEffectType side_effect_type = SideEffectType::kHasSideEffect) {
  Isolate* isolate = reinterpret_cast<Isolate*>(i_isolate);
  ConstructorBehavior behavior =
      has_prototype ? ConstructorBehavior::kAllow : ConstructorBehavior::kThrow;
  Local<FunctionTemplate> templ = FunctionTemplate::New(
      isolate, func, {}, {}, 0, behavior, side_effect_type);
  if (has_prototype) templ->ReadOnlyPrototype();
  return v8::Utils::OpenHandle(*templ);
}

static i::Handle<i::ObjectTemplateInfo> NewObjectTemplate(
    i::Isolate* i_isolate) {
  Isolate* isolate = reinterpret_cast<Isolate*>(i_isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  return v8::Utils::OpenHandle(*templ);
}

namespace internal {
namespace {

Handle<JSFunction> CreateFunc(
    Isolate* isolate, Handle<String> name, FunctionCallback func,
    bool has_prototype,
    SideEffectType side_effect_type = SideEffectType::kHasSideEffect,
    Handle<FunctionTemplateInfo> parent = {}) {
  Handle<FunctionTemplateInfo> temp =
      NewFunctionTemplate(isolate, func, has_prototype, side_effect_type);

  if (!parent.is_null()) {
    DCHECK(has_prototype);
    FunctionTemplateInfo::SetParentTemplate(isolate, temp, parent);
  }

  Handle<JSFunction> function =
      ApiNatives::InstantiateFunction(isolate, temp, name).ToHandleChecked();
  DCHECK(function->shared()->HasSharedName());
  return function;
}

Handle<JSFunction> InstallFunc(
    Isolate* isolate, Handle<JSObject> object, Handle<String> name,
    FunctionCallback func, int length, bool has_prototype = false,
    PropertyAttributes attributes = NONE,
    SideEffectType side_effect_type = SideEffectType::kHasSideEffect) {
  Handle<JSFunction> function =
      CreateFunc(isolate, name, func, has_prototype, side_effect_type);
  function->shared()->set_length(length);
  CHECK(!JSObject::HasRealNamedProperty(isolate, object, name).FromMaybe(true));
  CHECK(object->map()->is_extensible());
  JSObject::AddProperty(isolate, object, name, function, attributes);
  return function;
}

Handle<JSFunction> InstallFunc(
    Isolate* isolate, Handle<JSObject> object, const char* str,
    FunctionCallback func, int length, bool has_prototype = false,
    PropertyAttributes attributes = NONE,
    SideEffectType side_effect_type = SideEffectType::kHasSideEffect) {
  Handle<String> name = v8_str(isolate, str);
  return InstallFunc(isolate, object, name, func, length, has_prototype,
                     attributes, side_effect_type);
}

Handle<JSFunction> InstallConstructorFunc(Isolate* isolate,
                                          Handle<JSObject> object,
                                          const char* str,
                                          FunctionCallback func) {
  return InstallFunc(isolate, object, str, func, 1, true, DONT_ENUM,
                     SideEffectType::kHasNoSideEffect);
}

Handle<String> GetterName(Isolate* isolate, Handle<String> name) {
  return Name::ToFunctionName(isolate, name, isolate->factory()->get_string())
      .ToHandleChecked();
}

void InstallGetter(Isolate* isolate, Handle<JSObject> object, const char* str,
                   FunctionCallback func) {
  Handle<String> name = v8_str(isolate, str);
  Handle<JSFunction> function =
      CreateFunc(isolate, GetterName(isolate, name), func, false,
                 SideEffectType::kHasNoSideEffect);

  Utils::ToLocal(object)->SetAccessorProperty(Utils::ToLocal(name),
                                              Utils::ToLocal(function),
                                              Local<Function>(), v8::None);
}

Handle<String> SetterName(Isolate* isolate, Handle<String> name) {
  return Name::ToFunctionName(isolate, name, isolate->factory()->set_string())
      .ToHandleChecked();
}

void InstallGetterSetter(Isolate* isolate, Handle<JSObject> object,
                         const char* str, FunctionCallback getter,
                         FunctionCallback setter) {
  Handle<String> name = v8_str(isolate, str);
  Handle<JSFunction> getter_func =
      CreateFunc(isolate, GetterName(isolate, name), getter, false,
                 SideEffectType::kHasNoSideEffect);
  Handle<JSFunction> setter_func =
      CreateFunc(isolate, SetterName(isolate, name), setter, false);
  setter_func->shared()->set_length(1);

  Utils::ToLocal(object)->SetAccessorProperty(
      Utils::ToLocal(name), Utils::ToLocal(getter_func),
      Utils::ToLocal(setter_func), v8::None);
}

// Assigns a dummy instance template to the given constructor function. Used to
// make sure the implicit receivers for the constructors in this file have an
// instance type different from the internal one, they allocate the resulting
// object explicitly and ignore implicit receiver.
void SetDummyInstanceTemplate(Isolate* isolate, DirectHandle<JSFunction> fun) {
  DirectHandle<ObjectTemplateInfo> instance_template =
      NewObjectTemplate(isolate);
  FunctionTemplateInfo::SetInstanceTemplate(
      isolate, direct_handle(fun->shared()->api_func_data(), isolate),
      instance_template);
}

Handle<JSObject> SetupConstructor(Isolate* isolate,
                                  Handle<JSFunction> constructor,
                                  InstanceType instance_type, int instance_size,
                                  const char* name = nullptr,
                                  int in_object_properties = 0) {
  SetDummyInstanceTemplate(isolate, constructor);
  JSFunction::EnsureHasInitialMap(constructor);
  Handle<JSObject> proto(Cast<JSObject>(constructor->instance_prototype()),
                         isolate);
  Handle<Map> map = isolate->factory()->NewContextfulMap(
      constructor, instance_type, instance_size, TERMINAL_FAST_ELEMENTS_KIND,
      in_object_properties);
  JSFunction::SetInitialMap(isolate, constructor, map, proto);
  constexpr PropertyAttributes ro_attributes =
      static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY);
  if (name) {
    JSObject::AddProperty(isolate, proto,
                          isolate->factory()->to_string_tag_symbol(),
                          v8_str(isolate, name), ro_attributes);
  }
  return proto;
}

constexpr wasm::ValueType kWasmExceptionTagParams[] = {
    wasm::kWasmExternRef,
};
constexpr wasm::FunctionSig kWasmExceptionTagSignature{
    0, arraysize(kWasmExceptionTagParams), kWasmExceptionTagParams};
}  // namespace

// static
void WasmJs::PrepareForSnapshot(Isolate* isolate) {
  DirectHandle<JSGlobalObject> global = isolate->global_object();
  Handle<NativeContext> native_context(global->native_context(), isolate);

  CHECK(IsUndefined(native_context->get(Context::WASM_WEBASSEMBLY_OBJECT_INDEX),
                    isolate));
  CHECK(IsUndefined(native_context->get(Context::WASM_MODULE_CONSTRUCTOR_INDEX),
                    isolate));

  Factory* const f = isolate->factory();
  static constexpr PropertyAttributes ro_attributes =
      static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY);

  // Create the WebAssembly object.
  Handle<JSObject> webassembly;
  {
    Handle<String> WebAssembly_string = v8_str(isolate, "WebAssembly");
    // Not supposed to be called, hence using the kIllegal builtin as code.
    Handle<SharedFunctionInfo> sfi = f->NewSharedFunctionInfoForBuiltin(
        WebAssembly_string, Builtin::kIllegal, 0, kDontAdapt);
    sfi->set_language_mode(LanguageMode::kStrict);

    Handle<JSFunction> ctor =
        Factory::JSFunctionBuilder{isolate, sfi, native_context}.Build();
    JSFunction::SetPrototype(ctor, isolate->initial_object_prototype());
    webassembly = f->NewJSObject(ctor, AllocationType::kOld);
    native_context->set_wasm_webassembly_object(*webassembly);

    JSObject::AddProperty(isolate, webassembly, f->to_string_tag_symbol(),
                          WebAssembly_string, ro_attributes);
    InstallFunc(isolate, webassembly, "compile", wasm::WebAssemblyCompile, 1);
    InstallFunc(isolate, webassembly, "validate", wasm::WebAssemblyValidate, 1);
    InstallFunc(isolate, webassembly, "instantiate",
                wasm::WebAssemblyInstantiate, 1);
  }

  // Create the Module object.
  InstallModule(isolate, webassembly);

  // Create the Instance object.
  {
    Handle<JSFunction> instance_constructor = InstallConstructorFunc(
        isolate, webassembly, "Instance", wasm::WebAssemblyInstance);
    Handle<JSObject> instance_proto = SetupConstructor(
        isolate, instance_constructor, WASM_INSTANCE_OBJECT_TYPE,
        WasmInstanceObject::kHeaderSize, "WebAssembly.Instance");
    native_context->set_wasm_instance_constructor(*instance_constructor);
    InstallGetter(isolate, instance_proto, "exports",
                  wasm::WebAssemblyInstanceGetExports);
  }

  // Create the Table object.
  {
    Handle<JSFunction> table_constructor = InstallConstructorFunc(
        isolate, webassembly, "Table", wasm::WebAssemblyTable);
    Handle<JSObject> table_proto =
        SetupConstructor(isolate, table_construct
"""


```