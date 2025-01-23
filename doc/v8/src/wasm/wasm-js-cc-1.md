Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/wasm/wasm-js.cc`.

Here's a breakdown of the code's actions and how to address the user's request:

1. **Identify Core Functionality:** The code defines implementations for various JavaScript APIs related to WebAssembly. These include:
    - Compiling WebAssembly code (`WebAssembly.compileStreaming`, `WebAssembly.compile`).
    - Validating WebAssembly code (`WebAssembly.validate`).
    - Creating WebAssembly modules (`WebAssembly.Module`).
    - Inspecting module imports and exports (`WebAssembly.Module.imports`, `WebAssembly.Module.exports`, `WebAssembly.Module.customSections`).
    - Creating WebAssembly instances (`WebAssembly.Instance`, `WebAssembly.instantiateStreaming`, `WebAssembly.instantiate`).
    - Creating WebAssembly tables (`WebAssembly.Table`).
    - Creating WebAssembly memories (`WebAssembly.Memory`).

2. **Check for `.tq` extension:** The user asks about `.tq` files. The provided code is `.cc`, so this part is not applicable.

3. **JavaScript Relationship and Examples:**  The code directly implements JavaScript functionality. For each API, a JavaScript example demonstrating its usage would be helpful.

4. **Code Logic and Input/Output:** For functions like validation or compilation, showing example input (Wasm bytecode) and expected output (boolean for validation, a `WebAssembly.Module` for compilation) is relevant. Instantiation involves modules and imports, so showing those as input and an `WebAssembly.Instance` as output makes sense.

5. **Common Programming Errors:**  Think about typical mistakes developers make when working with these APIs:
    - Passing invalid Wasm bytecode.
    - Providing incorrect import objects.
    - Using `new` incorrectly with `WebAssembly.Module`.
    - Type mismatches when creating tables or memories.

6. **Overall Summary (for Part 2):**  Focus on the functions covered in this specific snippet. It primarily deals with module creation, validation, inspection, and the synchronous instantiation process, as well as the beginning of the streaming process.

**Plan for generating the response:**

* Start with a general summary of the code's purpose.
* For each implemented WebAssembly API:
    * Briefly describe its function.
    * Provide a JavaScript usage example.
    * If applicable, give an input/output example (simplified).
    * Mention common programming errors.
* Specifically address the `.tq` question.
* Conclude with the summary for this specific part of the code.
这是 `v8/src/wasm/wasm-js.cc` 源代码的第 2 部分，主要负责实现与 WebAssembly 相关的 JavaScript API。  延续上一部分，它继续定义了用于编译、验证、实例化 WebAssembly 模块以及创建 WebAssembly 表和内存的功能。

**功能归纳:**

这部分代码主要实现了以下 WebAssembly JavaScript API 的功能：

1. **`WebAssembly.compileStreaming(source)`**:  这是一个异步函数，接收一个 `Response` 对象或一个解析为 `Response` 对象的 `Promise` 作为输入，用于流式编译 WebAssembly 代码。它返回一个 `Promise`，该 `Promise` 会在编译成功后解析为一个 `WebAssembly.Module` 对象。
2. **`WebAssembly.validate(bytes)`**:  用于同步地验证一段字节数组是否是有效的 WebAssembly 二进制代码。它返回一个布尔值，`true` 表示有效，`false` 表示无效。
3. **`new WebAssembly.Module(bytes)`**:  这是一个构造函数，用于同步地创建一个 `WebAssembly.Module` 对象，该对象代表已编译的 WebAssembly 代码。它接收一个包含 WebAssembly 字节码的 `ArrayBuffer` 或 `TypedArray` 作为输入。
4. **`WebAssembly.Module.imports(module)`**:  静态方法，接收一个 `WebAssembly.Module` 对象，返回一个数组，该数组描述了模块的导入（imports）。
5. **`WebAssembly.Module.exports(module)`**:  静态方法，接收一个 `WebAssembly.Module` 对象，返回一个数组，该数组描述了模块的导出（exports）。
6. **`WebAssembly.Module.customSections(module, name)`**:  静态方法，接收一个 `WebAssembly.Module` 对象和一个字符串名称，返回一个包含具有指定名称的自定义 section 内容的数组。
7. **`new WebAssembly.Instance(module, importObject)`**:  这是一个构造函数，用于同步地创建一个 `WebAssembly.Instance` 对象，该对象是 WebAssembly 模块的实例，允许执行其中的代码。它接收一个 `WebAssembly.Module` 对象和一个包含导入值的 `importObject` 作为输入。
8. **`WebAssembly.instantiateStreaming(source, importObject)`**: 这是一个异步函数，结合了编译和实例化。它接收一个 `Response` 对象或一个解析为 `Response` 对象的 `Promise` 和一个可选的 `importObject` 作为输入。它返回一个 `Promise`，该 `Promise` 会在编译和实例化成功后解析为一个包含 `module` 和 `instance` 属性的对象。
9. **`WebAssembly.instantiate(moduleOrBytes, importObject)`**: 这是一个可以同步或异步执行的函数，用于编译和实例化 WebAssembly 代码。它可以接收一个 `WebAssembly.Module` 对象或包含 WebAssembly 字节码的 `ArrayBuffer` 或 `TypedArray`，以及一个可选的 `importObject` 作为输入。它返回一个 `Promise`，该 `Promise` 会在编译和实例化成功后解析为一个包含 `module` 和 `instance` 属性的对象，或者直接返回一个 `WebAssembly.Instance` 对象（如果第一个参数是 `WebAssembly.Module`）。
10. **`new WebAssembly.Table(descriptor)`**: 这是一个构造函数，用于创建一个 `WebAssembly.Table` 对象，代表一个可调整大小的类型化引用数组。它接收一个描述表属性的对象作为输入，例如 `element`（元素的类型，如 `anyfunc` 或 `externref`）、`initial`（初始大小）和可选的 `maximum`（最大大小）。
11. **`new WebAssembly.Memory(descriptor)`**: 这是一个构造函数，用于创建一个 `WebAssembly.Memory` 对象，代表一段可调整大小的原始字节缓冲区。它接收一个描述内存属性的对象作为输入，例如 `initial`（初始大小，单位为 WebAssembly 页，每页 64KB）和可选的 `maximum`（最大大小）。

**关于 `.tq` 文件:**

代码文件以 `.cc` 结尾，因此它是一个 C++ 源代码文件，而不是 Torque 源代码文件。如果以 `.tq` 结尾，则表示它是一个使用 V8 的 Torque 语言编写的文件，Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。

**与 JavaScript 功能的关系及示例:**

这里列出的所有函数都直接对应于 WebAssembly 的 JavaScript API。

**示例:**

* **`WebAssembly.compileStreaming`**:
  ```javascript
  fetch('module.wasm')
    .then(response => WebAssembly.compileStreaming(response))
    .then(module => console.log("模块编译成功:", module));
  ```

* **`WebAssembly.validate`**:
  ```javascript
  const buffer = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]); // 一个简单的 WASM 头部
  const isValid = WebAssembly.validate(buffer);
  console.log("模块是否有效:", isValid); // 输出: 模块是否有效: true
  ```

* **`new WebAssembly.Module`**:
  ```javascript
  const buffer = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]);
  const module = new WebAssembly.Module(buffer);
  console.log("创建的模块:", module);
  ```

* **`WebAssembly.Module.imports` 和 `WebAssembly.Module.exports`**:
  ```javascript
  const buffer = new Uint8Array([...]); // 包含导入和导出的 WASM 字节码
  const module = new WebAssembly.Module(buffer);
  const imports = WebAssembly.Module.imports(module);
  const exports = WebAssembly.Module.exports(module);
  console.log("模块导入:", imports);
  console.log("模块导出:", exports);
  ```

* **`new WebAssembly.Instance`**:
  ```javascript
  const buffer = new Uint8Array([...]);
  const module = new WebAssembly.Module(buffer);
  const importObject = {
    env: {
      add: (a, b) => a + b
    }
  };
  const instance = new WebAssembly.Instance(module, importObject);
  console.log("创建的实例:", instance);
  ```

* **`WebAssembly.instantiateStreaming`**:
  ```javascript
  fetch('module.wasm')
    .then(response => WebAssembly.instantiateStreaming(response, { env: { add: (a, b) => a + b } }))
    .then(result => {
      console.log("模块:", result.module);
      console.log("实例:", result.instance);
    });
  ```

* **`WebAssembly.instantiate`**:
  ```javascript
  const buffer = new Uint8Array([...]);
  WebAssembly.instantiate(buffer, { env: { add: (a, b) => a + b } })
    .then(result => {
      console.log("模块:", result.module);
      console.log("实例:", result.instance);
    });

  const module = new WebAssembly.Module(buffer);
  const instance2 = new WebAssembly.Instance(module);
  console.log("同步创建的实例:", instance2);
  ```

* **`new WebAssembly.Table`**:
  ```javascript
  const table = new WebAssembly.Table({ initial: 10, element: 'anyfunc' });
  console.log("创建的表:", table);
  ```

* **`new WebAssembly.Memory`**:
  ```javascript
  const memory = new WebAssembly.Memory({ initial: 10 }); // 初始 10 页，即 640KB
  console.log("创建的内存:", memory);
  ```

**代码逻辑推理（假设输入与输出）:**

* **`WebAssembly.validate`**:
    * **假设输入**: `bytes = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0])` (有效的 WASM 头部)
    * **输出**: `true`
    * **假设输入**: `bytes = new Uint8Array([1, 2, 3, 4])` (无效的 WASM 数据)
    * **输出**: `false`

* **`new WebAssembly.Module`**:
    * **假设输入**: `bytes = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 0, 1, 0, 1, 0])` (一个非常简单的有效 WASM 模块)
    * **输出**: 一个 `WebAssembly.Module` 对象，表示已编译的模块。

**用户常见的编程错误:**

* **在不需要 `new` 的地方使用 `new WebAssembly.compileStreaming()` 或 `new WebAssembly.validate()`**: 这些是函数，不是构造函数。
* **传递无效的 WebAssembly 字节码给 `WebAssembly.Module` 或 `WebAssembly.instantiate`**:  会导致编译错误。
* **在实例化时提供的 `importObject` 与模块的导入不匹配**: 缺少必要的导入或导入类型不正确会导致实例化错误。
* **尝试同步实例化一个非常大的模块，导致主线程阻塞**:  应该考虑使用异步的 `instantiateStreaming` 或 `instantiate`。
* **创建 `WebAssembly.Table` 或 `WebAssembly.Memory` 时，`initial` 或 `maximum` 的值超出限制**:  会导致抛出错误。
* **创建 `WebAssembly.Table` 时 `element` 属性使用了无效的值**: 只能是 WebAssembly 的引用类型，如 `anyfunc`、`externref` 等。
* **在 `WebAssembly.Table` 初始化时提供与 `element` 类型不兼容的初始值**: 例如，尝试用数字初始化 `anyfunc` 类型的表。

总的来说，这部分 `v8/src/wasm/wasm-js.cc` 代码是 V8 引擎中实现核心 WebAssembly JavaScript API 的关键组成部分，它负责处理 WebAssembly 代码的编译、验证、实例化以及相关对象的创建和管理。

### 提示词
```
这是目录为v8/src/wasm/wasm-js.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wasm-js.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
data)), 1));

  // The parameter may be of type {Response} or of type {Promise<Response>}.
  // Treat either case of parameter as Promise.resolve(parameter)
  // as per https://www.w3.org/2001/tag/doc/promises-guide#resolve-arguments

  // Ending with:
  //    return Promise.resolve(parameter).then(compile_callback);
  ASSIGN(Promise::Resolver, input_resolver, Promise::Resolver::New(context));
  if (!input_resolver->Resolve(context, info[0]).IsJust()) return;

  // We do not have any use of the result here. The {compile_callback} will
  // start streaming compilation, which will eventually resolve the promise we
  // set as result value.
  USE(input_resolver->GetPromise()->Then(context, compile_callback,
                                         reject_callback));
}

// WebAssembly.validate(bytes, options) -> bool
void WebAssemblyValidateImpl(const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.validate()"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();
  v8::ReturnValue<v8::Value> return_value = info.GetReturnValue();

  bool is_shared = false;
  auto bytes = GetFirstArgumentAsBytes(info, i::wasm::max_module_size(),
                                       &thrower, &is_shared);
  if (bytes == kNoWireBytes) {
    js_api_scope.AssertException();
    // Propagate anything except wasm exceptions.
    if (!thrower.wasm_error()) return;
    // Clear wasm exceptions; return false instead.
    thrower.Reset();
    return_value.Set(v8::False(isolate));
    return;
  }

  auto enabled_features = WasmEnabledFeatures::FromIsolate(i_isolate);
  CompileTimeImports compile_imports =
      ArgumentToCompileOptions(info[1], i_isolate, enabled_features);
  if (i_isolate->has_exception()) {
    if (i_isolate->is_execution_terminating()) return;
    i_isolate->clear_exception();
    return_value.Set(v8::False(isolate));
    return;
  }
  bool validated = false;
  if (is_shared) {
    // Make a copy of the wire bytes to avoid concurrent modification.
    std::unique_ptr<uint8_t[]> copy(new uint8_t[bytes.length()]);
    memcpy(copy.get(), bytes.start(), bytes.length());
    i::wasm::ModuleWireBytes bytes_copy(copy.get(),
                                        copy.get() + bytes.length());
    validated = i::wasm::GetWasmEngine()->SyncValidate(
        i_isolate, enabled_features, std::move(compile_imports), bytes_copy);
  } else {
    // The wire bytes are not shared, OK to use them directly.
    validated = i::wasm::GetWasmEngine()->SyncValidate(
        i_isolate, enabled_features, std::move(compile_imports), bytes);
  }

  return_value.Set(validated);
}

namespace {
bool TransferPrototype(i::Isolate* isolate, i::Handle<i::JSObject> destination,
                       i::Handle<i::JSReceiver> source) {
  i::MaybeHandle<i::HeapObject> maybe_prototype =
      i::JSObject::GetPrototype(isolate, source);
  i::Handle<i::HeapObject> prototype;
  if (maybe_prototype.ToHandle(&prototype)) {
    Maybe<bool> result = i::JSObject::SetPrototype(
        isolate, destination, prototype,
        /*from_javascript=*/false, internal::kThrowOnError);
    if (!result.FromJust()) {
      DCHECK(isolate->has_exception());
      return false;
    }
  }
  return true;
}
}  // namespace

// new WebAssembly.Module(bytes, options) -> WebAssembly.Module
void WebAssemblyModuleImpl(const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.Module()"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();
  if (i_isolate->wasm_module_callback()(info)) return;
  RecordCompilationMethod(i_isolate, kSyncCompilation);

  if (!info.IsConstructCall()) {
    thrower.TypeError("WebAssembly.Module must be invoked with 'new'");
    return;
  }
  i::Handle<i::NativeContext> native_context = i_isolate->native_context();
  if (!i::wasm::IsWasmCodegenAllowed(i_isolate, native_context)) {
    i::DirectHandle<i::String> error =
        i::wasm::ErrorStringForCodegen(i_isolate, native_context);
    thrower.CompileError("%s", error->ToCString().get());
    return;
  }

  bool is_shared = false;
  auto bytes = GetFirstArgumentAsBytes(info, i::wasm::max_module_size(),
                                       &thrower, &is_shared);

  if (bytes == kNoWireBytes) return js_api_scope.AssertException();

  auto enabled_features = WasmEnabledFeatures::FromIsolate(i_isolate);
  CompileTimeImports compile_imports =
      ArgumentToCompileOptions(info[1], i_isolate, enabled_features);
  if (i_isolate->has_exception()) {
    // TODO(14179): Does this need different error message handling?
    return;
  }
  i::MaybeHandle<i::WasmModuleObject> maybe_module_obj;
  if (is_shared) {
    // Make a copy of the wire bytes to avoid concurrent modification.
    std::unique_ptr<uint8_t[]> copy(new uint8_t[bytes.length()]);
    // Use relaxed reads (and writes, which is unnecessary here) to avoid TSan
    // reports on concurrent modifications of the SAB.
    base::Relaxed_Memcpy(reinterpret_cast<base::Atomic8*>(copy.get()),
                         reinterpret_cast<const base::Atomic8*>(bytes.start()),
                         bytes.length());
    i::wasm::ModuleWireBytes bytes_copy(copy.get(),
                                        copy.get() + bytes.length());
    maybe_module_obj = i::wasm::GetWasmEngine()->SyncCompile(
        i_isolate, enabled_features, std::move(compile_imports), &thrower,
        bytes_copy);
  } else {
    // The wire bytes are not shared, OK to use them directly.
    maybe_module_obj = i::wasm::GetWasmEngine()->SyncCompile(
        i_isolate, enabled_features, std::move(compile_imports), &thrower,
        bytes);
  }

  i::Handle<i::WasmModuleObject> module_obj;
  if (!maybe_module_obj.ToHandle(&module_obj)) return;

  // The infrastructure for `new Foo` calls allocates an object, which is
  // available here as {info.This()}. We're going to discard this object
  // and use {module_obj} instead, but it does have the correct prototype,
  // which we must harvest from it. This makes a difference when the JS
  // constructor function wasn't {WebAssembly.Module} directly, but some
  // subclass: {module_obj} has {WebAssembly.Module}'s prototype at this
  // point, so we must overwrite that with the correct prototype for {Foo}.
  if (!TransferPrototype(i_isolate, module_obj,
                         Utils::OpenHandle(*info.This()))) {
    return;
  }

  v8::ReturnValue<v8::Value> return_value = info.GetReturnValue();
  return_value.Set(Utils::ToLocal(module_obj));
}

// WebAssembly.Module.imports(module) -> Array<Import>
void WebAssemblyModuleImportsImpl(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.Module.imports()"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();

  i::Handle<i::WasmModuleObject> module_object;
  if (!GetFirstArgumentAsModule(info, &thrower).ToHandle(&module_object)) {
    return js_api_scope.AssertException();
  }
  auto imports = i::wasm::GetImports(i_isolate, module_object);
  info.GetReturnValue().Set(Utils::ToLocal(imports));
}

// WebAssembly.Module.exports(module) -> Array<Export>
void WebAssemblyModuleExportsImpl(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.Module.exports()"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();

  i::Handle<i::WasmModuleObject> module_object;
  if (!GetFirstArgumentAsModule(info, &thrower).ToHandle(&module_object)) {
    return js_api_scope.AssertException();
  }
  auto exports = i::wasm::GetExports(i_isolate, module_object);
  info.GetReturnValue().Set(Utils::ToLocal(exports));
}

// WebAssembly.Module.customSections(module, name) -> Array<Section>
void WebAssemblyModuleCustomSectionsImpl(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.Module.customSections()"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();

  i::Handle<i::WasmModuleObject> module_object;
  if (!GetFirstArgumentAsModule(info, &thrower).ToHandle(&module_object)) {
    return js_api_scope.AssertException();
  }

  if (info[1]->IsUndefined()) {
    thrower.TypeError("Argument 1 is required");
    return;
  }

  i::Handle<i::Object> name;
  if (!i::Object::ToString(i_isolate, Utils::OpenHandle(*info[1]))
           .ToHandle(&name)) {
    return js_api_scope.AssertException();
  }
  auto custom_sections = i::wasm::GetCustomSections(
      i_isolate, module_object, i::Cast<i::String>(name), &thrower);
  if (thrower.error()) return;
  info.GetReturnValue().Set(Utils::ToLocal(custom_sections));
}

// new WebAssembly.Instance(module, imports) -> WebAssembly.Instance
void WebAssemblyInstanceImpl(const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.Instance()"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();
  RecordCompilationMethod(i_isolate, kAsyncInstantiation);
  i_isolate->CountUsage(
      v8::Isolate::UseCounterFeature::kWebAssemblyInstantiation);

  if (i_isolate->wasm_instance_callback()(info)) return;

  i::Handle<i::JSObject> instance_obj;
  {
    if (!info.IsConstructCall()) {
      thrower.TypeError("WebAssembly.Instance must be invoked with 'new'");
      return;
    }

    i::Handle<i::WasmModuleObject> module_object;
    if (!GetFirstArgumentAsModule(info, &thrower).ToHandle(&module_object)) {
      return js_api_scope.AssertException();
    }

    Local<Value> ffi = info[1];

    if (!ffi->IsUndefined() && !ffi->IsObject()) {
      thrower.TypeError("Argument 1 must be an object");
      return;
    }

    if (!i::wasm::GetWasmEngine()
             ->SyncInstantiate(i_isolate, &thrower, module_object,
                               ImportsAsMaybeReceiver(ffi),
                               i::MaybeHandle<i::JSArrayBuffer>())
             .ToHandle(&instance_obj)) {
      return js_api_scope.AssertException();
    }
  }

  // The infrastructure for `new Foo` calls allocates an object, which is
  // available here as {info.This()}. We're going to discard this object
  // and use {instance_obj} instead, but it does have the correct prototype,
  // which we must harvest from it. This makes a difference when the JS
  // constructor function wasn't {WebAssembly.Instance} directly, but some
  // subclass: {instance_obj} has {WebAssembly.Instance}'s prototype at this
  // point, so we must overwrite that with the correct prototype for {Foo}.
  if (!TransferPrototype(i_isolate, instance_obj,
                         Utils::OpenHandle(*info.This()))) {
    return js_api_scope.AssertException();
  }

  info.GetReturnValue().Set(Utils::ToLocal(instance_obj));
}

// WebAssembly.instantiateStreaming(
//     Response | Promise<Response> [, imports [, options]])
//   -> Promise<ResultObject>
// (where ResultObject has a "module" and an "instance" field)
void WebAssemblyInstantiateStreaming(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.instantiateStreaming()"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();
  RecordCompilationMethod(i_isolate, kStreamingInstantiation);
  i_isolate->CountUsage(
      v8::Isolate::UseCounterFeature::kWebAssemblyInstantiation);

  Local<Context> context = isolate->GetCurrentContext();

  // Create and assign the return value of this function.
  ASSIGN(Promise::Resolver, result_resolver, Promise::Resolver::New(context));
  Local<Promise> promise = result_resolver->GetPromise();
  v8::ReturnValue<v8::Value> return_value = info.GetReturnValue();
  return_value.Set(promise);

  // Create an InstantiateResultResolver in case there is an issue with the
  // passed parameters.
  std::unique_ptr<i::wasm::InstantiationResultResolver> resolver(
      new InstantiateModuleResultResolver(isolate, context, result_resolver));

  i::Handle<i::NativeContext> native_context = i_isolate->native_context();
  if (!i::wasm::IsWasmCodegenAllowed(i_isolate, native_context)) {
    i::DirectHandle<i::String> error =
        i::wasm::ErrorStringForCodegen(i_isolate, native_context);
    thrower.CompileError("%s", error->ToCString().get());
    resolver->OnInstantiationFailed(thrower.Reify());
    return;
  }

  // If info.Length < 2, this will be undefined - see FunctionCallbackInfo.
  Local<Value> ffi = info[1];

  if (!ffi->IsUndefined() && !ffi->IsObject()) {
    thrower.TypeError("Argument 1 must be an object");
    resolver->OnInstantiationFailed(thrower.Reify());
    return;
  }

  // We start compilation now, we have no use for the
  // {InstantiationResultResolver}.
  resolver.reset();

  std::shared_ptr<i::wasm::CompilationResultResolver> compilation_resolver(
      new AsyncInstantiateCompileResultResolver(isolate, context,
                                                result_resolver, ffi));

  auto enabled_features = WasmEnabledFeatures::FromIsolate(i_isolate);
  CompileTimeImports compile_imports =
      ArgumentToCompileOptions(info[2], i_isolate, enabled_features);
  if (i_isolate->has_exception()) {
    if (i_isolate->is_execution_terminating()) return;
    compilation_resolver->OnCompilationFailed(
        handle(i_isolate->exception(), i_isolate));
    i_isolate->clear_exception();
    return;
  }

  // Allocate the streaming decoder in a Managed so we can pass it to the
  // embedder.
  i::Handle<i::Managed<WasmStreaming>> data = i::Managed<WasmStreaming>::From(
      i_isolate, 0,
      std::make_shared<WasmStreaming>(
          std::make_unique<WasmStreaming::WasmStreamingImpl>(
              i_isolate, js_api_scope.api_name(), std::move(compile_imports),
              compilation_resolver)));

  DCHECK_NOT_NULL(i_isolate->wasm_streaming_callback());
  ASSIGN(v8::Function, compile_callback,
         v8::Function::New(context, i_isolate->wasm_streaming_callback(),
                           Utils::ToLocal(i::Cast<i::Object>(data)), 1));
  ASSIGN(v8::Function, reject_callback,
         v8::Function::New(context, WasmStreamingPromiseFailedCallback,
                           Utils::ToLocal(i::Cast<i::Object>(data)), 1));

  // The parameter may be of type {Response} or of type {Promise<Response>}.
  // Treat either case of parameter as Promise.resolve(parameter)
  // as per https://www.w3.org/2001/tag/doc/promises-guide#resolve-arguments

  // Ending with:
  //    return Promise.resolve(parameter).then(compile_callback);
  ASSIGN(Promise::Resolver, input_resolver, Promise::Resolver::New(context));
  if (!input_resolver->Resolve(context, info[0]).IsJust()) return;

  // We do not have any use of the result here. The {compile_callback} will
  // start streaming compilation, which will eventually resolve the promise we
  // set as result value.
  USE(input_resolver->GetPromise()->Then(context, compile_callback,
                                         reject_callback));
}

// WebAssembly.instantiate(module, imports) -> WebAssembly.Instance
// WebAssembly.instantiate(bytes, imports, options) ->
//     {module: WebAssembly.Module, instance: WebAssembly.Instance}
void WebAssemblyInstantiateImpl(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.instantiate()"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();
  i_isolate->CountUsage(
      v8::Isolate::UseCounterFeature::kWebAssemblyInstantiation);

  Local<Context> context = isolate->GetCurrentContext();

  ASSIGN(Promise::Resolver, promise_resolver, Promise::Resolver::New(context));
  Local<Promise> promise = promise_resolver->GetPromise();
  info.GetReturnValue().Set(promise);

  std::unique_ptr<i::wasm::InstantiationResultResolver> resolver(
      new InstantiateModuleResultResolver(isolate, context, promise_resolver));

  Local<Value> first_arg_value = info[0];
  i::Handle<i::Object> first_arg = Utils::OpenHandle(*first_arg_value);
  if (!IsJSObject(*first_arg)) {
    thrower.TypeError(
        "Argument 0 must be a buffer source or a WebAssembly.Module object");
    resolver->OnInstantiationFailed(thrower.Reify());
    return;
  }

  // If info.Length < 2, this will be undefined - see FunctionCallbackInfo.
  Local<Value> ffi = info[1];

  if (!ffi->IsUndefined() && !ffi->IsObject()) {
    thrower.TypeError("Argument 1 must be an object");
    resolver->OnInstantiationFailed(thrower.Reify());
    return;
  }

  if (IsWasmModuleObject(*first_arg)) {
    i::Handle<i::WasmModuleObject> module_obj =
        i::Cast<i::WasmModuleObject>(first_arg);

    i::wasm::GetWasmEngine()->AsyncInstantiate(i_isolate, std::move(resolver),
                                               module_obj,
                                               ImportsAsMaybeReceiver(ffi));
    return;
  }

  bool is_shared = false;
  auto bytes = GetFirstArgumentAsBytes(info, i::wasm::max_module_size(),
                                       &thrower, &is_shared);
  if (bytes == kNoWireBytes) {
    resolver->OnInstantiationFailed(thrower.Reify());
    return;
  }

  // We start compilation now, we have no use for the
  // {InstantiationResultResolver}.
  resolver.reset();

  std::shared_ptr<i::wasm::CompilationResultResolver> compilation_resolver(
      new AsyncInstantiateCompileResultResolver(isolate, context,
                                                promise_resolver, ffi));

  // The first parameter is a buffer source, we have to check if we are allowed
  // to compile it.
  i::Handle<i::NativeContext> native_context = i_isolate->native_context();
  if (!i::wasm::IsWasmCodegenAllowed(i_isolate, native_context)) {
    i::DirectHandle<i::String> error =
        i::wasm::ErrorStringForCodegen(i_isolate, native_context);
    thrower.CompileError("%s", error->ToCString().get());
    compilation_resolver->OnCompilationFailed(thrower.Reify());
    return;
  }

  auto enabled_features = WasmEnabledFeatures::FromIsolate(i_isolate);
  CompileTimeImports compile_imports =
      ArgumentToCompileOptions(info[2], i_isolate, enabled_features);
  if (i_isolate->has_exception()) {
    if (i_isolate->is_execution_terminating()) return;
    compilation_resolver->OnCompilationFailed(
        handle(i_isolate->exception(), i_isolate));
    i_isolate->clear_exception();
    return;
  }

  // Asynchronous compilation handles copying wire bytes if necessary.
  i::wasm::GetWasmEngine()->AsyncCompile(i_isolate, enabled_features,
                                         std::move(compile_imports),
                                         std::move(compilation_resolver), bytes,
                                         is_shared, js_api_scope.api_name());
}

namespace {
// {AddressValueToU64} as defined in the memory64 js-api spec.
// Returns std::nullopt on error (exception or error set in the thrower), and
// the address value otherwise.
template <typename Name>
std::optional<uint64_t> AddressValueToU64(ErrorThrower* thrower,
                                          Local<Context> context,
                                          v8::Local<v8::Value> value,
                                          Name property_name,
                                          AddressType address_type) {
  switch (address_type) {
    case AddressType::kI32:
      return EnforceUint32(property_name, value, context, thrower);
    case AddressType::kI64:
      return EnforceBigIntUint64(property_name, value, context, thrower);
  }
}

// {AddressValueToU64} plus additional bounds checks.
std::optional<uint64_t> AddressValueToBoundedU64(
    ErrorThrower* thrower, Local<Context> context, v8::Local<v8::Value> value,
    i::Handle<i::String> property_name, AddressType address_type,
    uint64_t lower_bound, uint64_t upper_bound) {
  std::optional<uint64_t> maybe_address_value =
      AddressValueToU64(thrower, context, value, property_name, address_type);
  if (!maybe_address_value) return std::nullopt;
  uint64_t address_value = *maybe_address_value;

  if (address_value < lower_bound) {
    thrower->RangeError(
        "Property '%s': value %" PRIu64 " is below the lower bound %" PRIx64,
        property_name->ToCString().get(), address_value, lower_bound);
    return std::nullopt;
  }

  if (address_value > upper_bound) {
    thrower->RangeError(
        "Property '%s': value %" PRIu64 " is above the upper bound %" PRIu64,
        property_name->ToCString().get(), address_value, upper_bound);
    return std::nullopt;
  }

  return address_value;
}

// Returns std::nullopt on error (exception or error set in the thrower).
// The inner optional is std::nullopt if the property did not exist, and the
// address value otherwise.
std::optional<std::optional<uint64_t>> GetOptionalAddressValue(
    ErrorThrower* thrower, Local<Context> context, Local<v8::Object> descriptor,
    Local<String> property, AddressType address_type, int64_t lower_bound,
    uint64_t upper_bound) {
  v8::Local<v8::Value> value;
  if (!descriptor->Get(context, property).ToLocal(&value)) {
    return std::nullopt;
  }

  // Web IDL: dictionary presence
  // https://heycam.github.io/webidl/#dfn-present
  if (value->IsUndefined()) {
    // No exception, but no value either.
    return std::optional<uint64_t>{};
  }

  i::Handle<i::String> property_name = v8::Utils::OpenHandle(*property);

  std::optional<uint64_t> maybe_address_value =
      AddressValueToBoundedU64(thrower, context, value, property_name,
                               address_type, lower_bound, upper_bound);
  if (!maybe_address_value) return std::nullopt;
  return *maybe_address_value;
}

// Fetch 'initial' or 'minimum' property from `descriptor`. If both are
// provided, a TypeError is thrown.
// Returns std::nullopt on error (exception or error set in the thrower).
// TODO(aseemgarg): change behavior when the following bug is resolved:
// https://github.com/WebAssembly/js-types/issues/6
std::optional<uint64_t> GetInitialOrMinimumProperty(
    v8::Isolate* isolate, ErrorThrower* thrower, Local<Context> context,
    Local<v8::Object> descriptor, AddressType address_type,
    uint64_t upper_bound) {
  auto maybe_maybe_initial = GetOptionalAddressValue(
      thrower, context, descriptor, v8_str(isolate, "initial"), address_type, 0,
      upper_bound);
  if (!maybe_maybe_initial) return std::nullopt;
  std::optional<uint64_t> maybe_initial = *maybe_maybe_initial;

  auto enabled_features =
      WasmEnabledFeatures::FromIsolate(reinterpret_cast<i::Isolate*>(isolate));
  if (enabled_features.has_type_reflection()) {
    auto maybe_maybe_minimum = GetOptionalAddressValue(
        thrower, context, descriptor, v8_str(isolate, "minimum"), address_type,
        0, upper_bound);
    if (!maybe_maybe_minimum) return std::nullopt;
    std::optional<uint64_t> maybe_minimum = *maybe_maybe_minimum;

    if (maybe_initial && maybe_minimum) {
      thrower->TypeError(
          "The properties 'initial' and 'minimum' are not allowed at the same "
          "time");
      return std::nullopt;
    }
    if (maybe_minimum) {
      // Only 'minimum' exists, so we use 'minimum' as 'initial'.
      return *maybe_minimum;
    }
  }
  if (!maybe_initial) {
    // TODO(aseemgarg): update error message when the spec issue is resolved.
    thrower->TypeError("Property 'initial' is required");
    return std::nullopt;
  }
  return *maybe_initial;
}

v8::Local<Value> AddressValueFromUnsigned(Isolate* isolate,
                                          i::wasm::AddressType type,
                                          unsigned value) {
  return type == i::wasm::AddressType::kI64
             ? BigInt::NewFromUnsigned(isolate, value).As<Value>()
             : Integer::NewFromUnsigned(isolate, value).As<Value>();
}

i::Handle<i::HeapObject> DefaultReferenceValue(i::Isolate* isolate,
                                               i::wasm::ValueType type) {
  DCHECK(type.is_object_reference());
  // Use undefined for JS type (externref) but null for wasm types as wasm does
  // not know undefined.
  if (type.heap_representation() == i::wasm::HeapType::kExtern) {
    return isolate->factory()->undefined_value();
  } else if (!type.use_wasm_null()) {
    return isolate->factory()->null_value();
  }
  return isolate->factory()->wasm_null();
}

// Read the address type from a Memory or Table descriptor.
std::optional<AddressType> GetAddressType(Isolate* isolate,
                                          Local<Context> context,
                                          Local<v8::Object> descriptor,
                                          ErrorThrower* thrower) {
  v8::Local<v8::Value> address_value;
  if (!descriptor->Get(context, v8_str(isolate, "address"))
           .ToLocal(&address_value)) {
    return std::nullopt;
  }

  if (address_value->IsUndefined()) return AddressType::kI32;

  i::Handle<i::String> address;
  if (!i::Object::ToString(reinterpret_cast<i::Isolate*>(isolate),
                           Utils::OpenHandle(*address_value))
           .ToHandle(&address)) {
    return std::nullopt;
  }

  if (address->IsEqualTo(base::CStrVector("i64"))) return AddressType::kI64;
  if (address->IsEqualTo(base::CStrVector("i32"))) return AddressType::kI32;

  thrower->TypeError("Unknown address type '%s'; pass 'i32' or 'i64'",
                     address->ToCString().get());
  return std::nullopt;
}
}  // namespace

// new WebAssembly.Table(descriptor) -> WebAssembly.Table
void WebAssemblyTableImpl(const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.Table()"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();

  if (!info.IsConstructCall()) {
    thrower.TypeError("WebAssembly.Table must be invoked with 'new'");
    return;
  }
  if (!info[0]->IsObject()) {
    thrower.TypeError("Argument 0 must be a table descriptor");
    return;
  }
  Local<Context> context = isolate->GetCurrentContext();
  Local<v8::Object> descriptor = Local<Object>::Cast(info[0]);
  i::wasm::ValueType type;
  // Parse the 'element' property of the `descriptor`.
  {
    v8::Local<v8::Value> value;
    if (!descriptor->Get(context, v8_str(isolate, "element")).ToLocal(&value)) {
      return js_api_scope.AssertException();
    }
    i::Handle<i::String> string;
    if (!i::Object::ToString(reinterpret_cast<i::Isolate*>(isolate),
                             Utils::OpenHandle(*value))
             .ToHandle(&string)) {
      return js_api_scope.AssertException();
    }
    auto enabled_features = WasmEnabledFeatures::FromIsolate(i_isolate);
    // The JS api uses 'anyfunc' instead of 'funcref'.
    if (string->IsEqualTo(base::CStrVector("anyfunc"))) {
      type = i::wasm::kWasmFuncRef;
    } else if (enabled_features.has_type_reflection() &&
               string->IsEqualTo(base::CStrVector("funcref"))) {
      // With the type reflection proposal, "funcref" replaces "anyfunc",
      // and anyfunc just becomes an alias for "funcref".
      type = i::wasm::kWasmFuncRef;
    } else if (string->IsEqualTo(base::CStrVector("externref"))) {
      type = i::wasm::kWasmExternRef;
    } else if (enabled_features.has_stringref() &&
               string->IsEqualTo(base::CStrVector("stringref"))) {
      type = i::wasm::kWasmStringRef;
    } else if (string->IsEqualTo(base::CStrVector("anyref"))) {
      type = i::wasm::kWasmAnyRef;
    } else if (string->IsEqualTo(base::CStrVector("eqref"))) {
      type = i::wasm::kWasmEqRef;
    } else if (string->IsEqualTo(base::CStrVector("structref"))) {
      type = i::wasm::kWasmStructRef;
    } else if (string->IsEqualTo(base::CStrVector("arrayref"))) {
      type = i::wasm::kWasmArrayRef;
    } else if (string->IsEqualTo(base::CStrVector("i31ref"))) {
      type = i::wasm::kWasmI31Ref;
    } else {
      thrower.TypeError(
          "Descriptor property 'element' must be a WebAssembly reference type");
      return;
    }
    // TODO(14616): Support shared types.
  }

  // Parse the 'address' property of the `descriptor`.
  std::optional<AddressType> maybe_address_type =
      GetAddressType(isolate, context, descriptor, &thrower);
  if (!maybe_address_type) {
    DCHECK(i_isolate->has_exception() || thrower.error());
    return;
  }
  AddressType address_type = *maybe_address_type;

  // Parse the 'initial' or 'minimum' property of the `descriptor`.
  std::optional<uint64_t> maybe_initial = GetInitialOrMinimumProperty(
      isolate, &thrower, context, descriptor, address_type,
      i::wasm::max_table_init_entries());
  if (!maybe_initial) return js_api_scope.AssertException();
  static_assert(i::wasm::kV8MaxWasmTableInitEntries <= i::kMaxUInt32);
  uint32_t initial = static_cast<uint32_t>(*maybe_initial);

  // Parse the 'maximum' property of the `descriptor`.
  uint64_t kNoMaximum = i::kMaxUInt64;
  auto maybe_maybe_maximum = GetOptionalAddressValue(
      &thrower, context, descriptor, v8_str(isolate, "maximum"), address_type,
      initial, kNoMaximum);
  if (!maybe_maybe_maximum) return js_api_scope.AssertException();
  std::optional<uint64_t> maybe_maximum = *maybe_maybe_maximum;

  i::Handle<i::WasmTableObject> table_obj = i::WasmTableObject::New(
      i_isolate, i::Handle<i::WasmTrustedInstanceData>(), type, initial,
      maybe_maximum.has_value(),
      maybe_maximum.value_or(0) /* note: unused if previous param is false */,
      DefaultReferenceValue(i_isolate, type), address_type);

  // The infrastructure for `new Foo` calls allocates an object, which is
  // available here as {info.This()}. We're going to discard this object
  // and use {table_obj} instead, but it does have the correct prototype,
  // which we must harvest from it. This makes a difference when the JS
  // constructor function wasn't {WebAssembly.Table} directly, but some
  // subclass: {table_obj} has {WebAssembly.Table}'s prototype at this
  // point, so we must overwrite that with the correct prototype for {Foo}.
  if (!TransferPrototype(i_isolate, table_obj,
                         Utils::OpenHandle(*info.This()))) {
    return js_api_scope.AssertException();
  }

  if (initial > 0 && info.Length() >= 2 && !info[1]->IsUndefined()) {
    i::Handle<i::Object> element = Utils::OpenHandle(*info[1]);
    const char* error_message;
    if (!i::WasmTableObject::JSToWasmElement(i_isolate, table_obj, element,
                                             &error_message)
             .ToHandle(&element)) {
      thrower.TypeError(
          "Argument 2 must be undefined or a value of type compatible "
          "with the type of the new table: %s.",
          error_message);
      return;
    }
    for (uint32_t index = 0; index < static_cast<uint32_t>(initial); ++index) {
      i::WasmTableObject::Set(i_isolate, table_obj, index, element);
    }
  } else if (initial > 0) {
    switch (table_obj->type().heap_representation()) {
      case i::wasm::HeapType::kString:
        thrower.TypeError(
            "Missing initial value when creating stringref table");
        return;
      case i::wasm::HeapType::kStringViewWtf8:
        thrower.TypeError("stringview_wtf8 has no JS representation");
        return;
      case i::wasm::HeapType::kStringViewWtf16:
        thrower.TypeError("stringview_wtf16 has no JS representation");
        return;
      case i::wasm::HeapType::kStringViewIter:
        thrower.TypeError("stringview_iter has no JS representation");
        return;
      default:
        break;
    }
  }
  v8::ReturnValue<v8::Value> return_value = info.GetReturnValue();
  return_value.Set(Utils::ToLocal(i::Cast<i::JSObject>(table_obj)));
}

// new WebAssembly.Memory(descriptor) -> WebAssembly.Memory
void WebAssemblyMemoryImpl(const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.Memory()"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();

  if (!info.IsConstructCall()) {
    thrower.TypeError("WebAssembly.Memory must be invoked with 'new'");
    return;
  }
  if (!info[0]->IsObject()) {
    thrower.TypeError("Argument 0 must be a memory descriptor");
    return;
  }
  Local<Context> context = isolate->GetCurrentContext();
  Local<v8::Object> descriptor = Local<Object>::Cast(info[0]);

  // Parse the 'address' property of the `descriptor`.
  std::optional<AddressType> maybe_address_type =
      GetAddressType(isolate, context, descriptor, &thrower);
  if (!maybe_address_type) return js_api_scope.AssertException();
  AddressType address_type = *maybe_address_type;
  uint64_t max_supported_pages = address_type == AddressType::kI64
                                     ? i::wasm::kSpecMaxMemory64Pages
                                     : i::wasm::kSpecMaxMemory32Pages;
  // {max_supported_pages} will actually
```