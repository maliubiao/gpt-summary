Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/wasm/wasm-js.cc`. The summary should cover:

1. **General Functions:**  What does this code do?
2. **Torque Source Check:** Does the file extension indicate a Torque source file?
3. **JavaScript Relationship:** If the code interacts with JavaScript, provide JavaScript examples.
4. **Logic Inference:**  If there's logic, give examples with inputs and outputs.
5. **Common Errors:**  Point out typical programming mistakes users might make.
6. **Overall Function (Part 4/5):** Summarize the role of this specific section.

**Plan:**

1. **Analyze the Code:** Read through the provided C++ code, identifying the functions and their purpose. Focus on the V8 API calls and the `WebAssembly` namespace interactions.
2. **Torque Check:**  Check if the file extension is `.tq`.
3. **JavaScript Interaction:**  Identify functions that are called from JavaScript or expose functionality to JavaScript. Provide illustrative JavaScript examples.
4. **Logic Inference:**  Look for functions with clear input-output relationships (e.g., `WebAssemblyTableGetLengthImpl`, `WebAssemblyTableGrowImpl`). Create simple test cases.
5. **Common Errors:**  Pinpoint common mistakes when using the WebAssembly JavaScript API, as reflected in the error handling within the C++ code (e.g., incorrect argument types, out-of-bounds access).
6. **Part 4 Summary:**  Focus on the specific functionalities present in this excerpt, noting the objects and methods being implemented.

**Observations from the code:**

* The code defines implementations for various `WebAssembly` API methods (e.g., `WebAssembly.Function.prototype.type`, `WebAssembly.Instance.prototype.exports`, `WebAssembly.Table.prototype.grow`, `WebAssembly.Memory.prototype.grow`, `WebAssembly.Global.prototype.value`).
* It handles interactions between JavaScript values and WebAssembly types.
* It includes error handling for incorrect usage.
* It uses macros like `EXTRACT_THIS` for type checking.
* It prepares the `WebAssembly` namespace for use.
这是 `v8/src/wasm/wasm-js.cc` 源代码的**第四部分**，它主要负责实现 WebAssembly JavaScript API 中各种 WebAssembly 对象的**方法和属性的获取/设置操作**。

**功能列举:**

* **`WebAssembly.Function.prototype.type()` 的实现:**  获取 WebAssembly 函数的类型签名。
* **`WebAssembly.Instance.prototype.exports()` 的实现:** 获取 WebAssembly 实例的导出对象。
* **`WebAssembly.Table.prototype.length` 的实现:** 获取 WebAssembly 表的当前长度。
* **`WebAssembly.Table.prototype.grow(num, init_value)` 的实现:** 增加 WebAssembly 表的容量。
* **`WebAssembly.Table.prototype.get(index)` 的实现:** 获取 WebAssembly 表中指定索引的元素。
* **`WebAssembly.Table.prototype.set(index, value)` 的实现:** 设置 WebAssembly 表中指定索引的元素。
* **`WebAssembly.Table.prototype.type()` 的实现:** 获取 WebAssembly 表的类型信息。
* **`WebAssembly.Memory.prototype.grow(delta)` 的实现:** 增加 WebAssembly 内存的大小。
* **`WebAssembly.Memory.prototype.buffer` 的实现:** 获取 WebAssembly 内存的 ArrayBuffer 视图。
* **`WebAssembly.Memory.prototype.type()` 的实现:** 获取 WebAssembly 内存的类型信息。
* **`WebAssembly.Tag.prototype.type()` 的实现:** 获取 WebAssembly 标签（用于异常处理）的类型信息。
* **`WebAssembly.Exception.prototype.getArg(tag, index)` 的实现:** 获取 WebAssembly 异常对象中指定索引的参数值。
* **`WebAssembly.Exception.prototype.is(tag)` 的实现:** 检查一个 WebAssembly 异常对象是否与给定的标签匹配。
* **`WebAssembly.Global.prototype.valueOf()` 和 `get WebAssembly.Global.value` 的实现:** 获取 WebAssembly 全局变量的值。
* **`set WebAssembly.Global.value(value)` 的实现:** 设置 WebAssembly 可变全局变量的值。
* **`WebAssembly.Global.prototype.type()` 的实现:** 获取 WebAssembly 全局变量的类型信息。
* **准备 WebAssembly 命名空间:** 创建 `WebAssembly` 全局对象，并注册 `compile`, `validate`, `instantiate` 等静态方法。
* **创建 Module, Instance, Table 等构造函数:** 为 `WebAssembly.Module`, `WebAssembly.Instance`, `WebAssembly.Table` 等对象创建 JavaScript 构造函数。
* **设置原型对象:** 为上述构造函数设置原型对象，并定义原型对象上的属性和方法。

**Torque 源代码:**

`v8/src/wasm/wasm-js.cc` 的文件扩展名是 `.cc`，所以**它不是一个 v8 Torque 源代码**。Torque 源代码的文件扩展名是 `.tq`。

**与 JavaScript 的关系及示例:**

这段 C++ 代码直接实现了 WebAssembly JavaScript API 的功能，这些功能可以通过 JavaScript 代码来调用。

```javascript
// 获取 WebAssembly 函数的类型
const wasmCode = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 5, 1, 96, 0, 1, 127, 3, 2, 1, 0, 7, 8, 1, 4, 102, 117, 110, 99, 0, 0, 10, 4, 1, 2, 0, 11]);
const wasmModule = new WebAssembly.Module(wasmCode);
const instance = new WebAssembly.Instance(wasmModule);
const func = instance.exports.func;
console.log(func.type()); // 输出类似： "() => i32"

// 获取 WebAssembly 实例的导出对象
console.log(instance.exports);

// 获取 WebAssembly 表的长度
const table = new WebAssembly.Table({ initial: 10, element: 'anyfunc' });
console.log(table.length); // 输出 10

// 增加 WebAssembly 表的容量
table.grow(5);
console.log(table.length); // 输出 15

// 获取和设置 WebAssembly 表的元素
table.set(0, func);
console.log(table.get(0)); // 输出 [Function: func]

// 获取 WebAssembly 内存的 buffer
const memory = new WebAssembly.Memory({ initial: 1 });
const buffer = memory.buffer;
console.log(buffer); // 输出 ArrayBuffer

// 增加 WebAssembly 内存的大小
memory.grow(1);
console.log(memory.buffer.byteLength); // 输出 131072 (2 pages * 65536 bytes/page)

// 获取和设置 WebAssembly 全局变量的值
const global = new WebAssembly.Global({ value: 'i32', mutable: true }, 42);
console.log(global.value); // 输出 42
global.value = 100;
console.log(global.value); // 输出 100
```

**代码逻辑推理及示例:**

**假设输入:** 一个 WebAssembly 表对象 `table`，当前长度为 5。

**调用 `table.grow(3)`:**

* C++ 代码中的 `WebAssemblyTableGrowImpl` 函数会被调用。
* `maybe_grow_by` 将会是 3。
* `old_size` 将会是 5。
* 表的内部容量会增加 3。
* **输出:** 返回值是 5 (增长前的长度)。

**假设输入:** 一个 WebAssembly 表对象 `table`，元素类型为 `externref`，没有提供 `init_value`。

**调用 `table.grow(2)`:**

* C++ 代码中的 `WebAssemblyTableGrowImpl` 函数会被调用。
* 由于元素类型是 `externref` (可为空引用)，且没有提供 `init_value`，`init_value` 将会被设置为默认的空引用。
* 表的内部容量会增加 2，新增的元素会被初始化为空引用。
* **输出:** 返回增长前的长度。

**用户常见的编程错误及示例:**

* **尝试访问超出 WebAssembly 表范围的索引:**

```javascript
const table = new WebAssembly.Table({ initial: 5, element: 'anyfunc' });
console.log(table.get(10)); // 抛出 RangeError: invalid address 10 in externref table of size 5
table.set(6, () => {}); // 抛出 RangeError: invalid address 6 in externref table of size 5
```

* **向不可变的 WebAssembly 全局变量赋值:**

```javascript
const global = new WebAssembly.Global({ value: 'i32', mutable: false }, 42);
global.value = 100; // 抛出 TypeError: Can't set the value of an immutable global.
```

* **向 WebAssembly 表中设置错误类型的元素:**

```javascript
const table = new WebAssembly.Table({ initial: 5, element: 'i32' });
table.set(0, "hello"); // 抛出 TypeError: Argument 1 is invalid for table: ...
```

* **调用 `WebAssembly.Table.grow` 时，对于非 nullable 类型的表没有提供初始化值:**

```javascript
const table = new WebAssembly.Table({ initial: 5, element: 'i32' });
table.grow(2); // 抛出 TypeError: Argument 1 must be specified for non-nullable element type
```

**第 4 部分的功能归纳:**

这部分代码主要负责实现 WebAssembly JavaScript API 中各种 WebAssembly 对象（如 Function, Instance, Table, Memory, Global, Tag, Exception）的**属性访问器 (getters) 和方法**。它将 JavaScript 的调用转发到 V8 内部的 WebAssembly 实现，并处理类型转换、错误检查等操作，使得 JavaScript 可以方便地与 WebAssembly 代码进行交互。  这部分是 WebAssembly 与 JavaScript 桥梁的关键组成部分。

Prompt: 
```
这是目录为v8/src/wasm/wasm-js.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wasm-js.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能

"""
PromiseField::decode(data->js_promise_flags());
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