Response: The user wants a summary of the C++ source code file `v8/src/wasm/wasm-js.cc`. The request specifically asks to identify the file's functionality and to illustrate any connections to JavaScript using examples. Since this is part 1 of 3, the summary should focus on the features and functionalities present in this specific segment of the code.

Based on the included headers and the initial part of the code, the file seems to be responsible for:

1. **Bridging the gap between WebAssembly and JavaScript in V8.**  This is evident from the file name and the inclusion of headers like `v8-wasm.h`, `v8-promise.h`, and `include/v8-function.h`.

2. **Implementing the JavaScript API for WebAssembly.**  The code defines functions that correspond to global WebAssembly functions and constructors, such as `WebAssembly.compile`, `WebAssembly.instantiate`, `WebAssembly.Module`, `WebAssembly.Instance`, `WebAssembly.Table`, and `WebAssembly.Memory`.

3. **Handling asynchronous compilation and instantiation of WebAssembly modules.** The `WasmStreaming` class and the `AsyncCompilationResolver` and `Instantiate*ResultResolver` classes strongly suggest this.

4. **Managing the streaming compilation process.** The `WasmStreaming` class and its internal implementation seem dedicated to handling byte streams for WebAssembly compilation.

5. **Handling the transfer of WebAssembly modules and instances between C++ and JavaScript.** The use of `v8::Local` and `v8::Handle` indicates interaction with V8's object model.

6. **Validating and compiling WebAssembly bytecode.** The presence of `GetFirstArgumentAsBytes` and the calls to `i::wasm::GetWasmEngine()->AsyncCompile` and `i::wasm::GetWasmEngine()->SyncCompile` point to this.

7. **Exposing module metadata like imports, exports, and custom sections.** The functions `WebAssemblyModuleImportsImpl`, `WebAssemblyModuleExportsImpl`, and `WebAssemblyModuleCustomSectionsImpl` suggest this functionality.

8. **Creating WebAssembly Table and Memory objects.** The implementations for `WebAssemblyTableImpl` and `WebAssemblyMemoryImpl` are present.

**JavaScript Examples Brainstorming:**

To demonstrate the connection to JavaScript, examples of how these C++ functions are invoked from JavaScript are necessary. This would involve showing the usage of the `WebAssembly` API.

*   `WebAssembly.compile`:  Demonstrate compiling raw bytecode.
*   `WebAssembly.instantiate`: Show instantiating a compiled module or directly from bytecode.
*   `WebAssembly.Module`: Show creating a `WebAssembly.Module` object.
*   `WebAssembly.Instance`: Show creating a `WebAssembly.Instance` object.
*   `WebAssembly.compileStreaming`:  Demonstrate streaming compilation.
*   `WebAssembly.instantiateStreaming`: Demonstrate streaming instantiation.
*   `WebAssembly.validate`: Show validating WebAssembly bytecode.
*   `WebAssembly.Module.imports`, `WebAssembly.Module.exports`, `WebAssembly.Module.customSections`: Show how to access module metadata.
*   `WebAssembly.Table`: Show creating a `WebAssembly.Table` object.
*   `WebAssembly.Memory`: Show creating a `WebAssembly.Memory` object.
这个C++源代码文件 `v8/src/wasm/wasm-js.cc` 的主要功能是 **实现了 V8 引擎中 WebAssembly 的 JavaScript API 绑定**。 它是 V8 中连接 JavaScript 和 WebAssembly 运行时环境的关键部分。

具体来说，从这段代码中可以看出它负责以下几个方面：

1. **定义了 `WasmStreaming` 类及其实现：**  这个类用于处理 WebAssembly 模块的流式编译。它允许逐步接收 WebAssembly 字节码，并在接收过程中进行编译，从而提高加载速度。

2. **实现了 WebAssembly 的全局函数：**  这段代码包含了对诸如 `WebAssembly.compile`、`WebAssembly.compileStreaming`、`WebAssembly.validate` 和 `WebAssembly.instantiate` 等全局 WebAssembly 函数的 C++ 实现。这些实现负责接收 JavaScript 传递的参数（例如字节码、导入对象等），调用 V8 内部的 WebAssembly 编译和实例化逻辑，并将结果返回给 JavaScript。

3. **实现了 WebAssembly 的构造函数：**  代码中实现了 `WebAssembly.Module` 和 `WebAssembly.Instance` 的构造函数。这些构造函数允许 JavaScript 代码创建 WebAssembly 模块和实例对象。

4. **实现了 `WebAssembly.Module` 的静态方法：**  这段代码实现了 `WebAssembly.Module.imports`、`WebAssembly.Module.exports` 和 `WebAssembly.Module.customSections` 等静态方法，允许 JavaScript 代码获取 WebAssembly 模块的导入、导出和自定义段信息。

5. **实现了 `WebAssembly.Table` 的构造函数：**  代码中实现了 `WebAssembly.Table` 的构造函数，允许 JavaScript 代码创建 WebAssembly 表对象。

6. **实现了 `WebAssembly.Memory` 的构造函数：**  代码中实现了 `WebAssembly.Memory` 的构造函数，允许 JavaScript 代码创建 WebAssembly 内存对象。

7. **处理 JavaScript 和 WebAssembly 之间的数据转换：**  例如，`GetFirstArgumentAsBytes` 函数负责将 JavaScript 中的 ArrayBuffer 或 TypedArray 转换为 C++ 中可以处理的字节数组。

8. **处理异步操作：**  通过 `Promise` 和 `CompilationResultResolver` 等类，实现了 WebAssembly 模块的异步编译和实例化，允许 JavaScript 代码在后台编译和实例化模块，而不会阻塞主线程。

**与 JavaScript 功能的关系及举例说明：**

这个 C++ 文件直接对应了 JavaScript 中 `WebAssembly` 全局对象及其相关 API。  它使得 JavaScript 代码能够加载、编译、实例化和与 WebAssembly 模块进行交互。

**示例：**

**1. `WebAssembly.compile` (对应 C++ 中的 `WebAssemblyCompileImpl`)：**

```javascript
const wasmCode = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, ...]); // WebAssembly 字节码
WebAssembly.compile(wasmCode)
  .then(module => {
    console.log("模块编译成功", module);
  })
  .catch(error => {
    console.error("模块编译失败", error);
  });
```

这个 JavaScript 代码调用了 `WebAssembly.compile` 函数，并将一个包含 WebAssembly 字节码的 `Uint8Array` 传递给它。在 C++ 层面，`WebAssemblyCompileImpl` 函数会被调用，它会接收这个字节数组并启动异步编译过程。

**2. `WebAssembly.instantiate` (对应 C++ 中的 `WebAssemblyInstantiateImpl`)：**

```javascript
const wasmCode = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, ...]);
WebAssembly.instantiate(wasmCode, {
  imports: {
    module: {
      func: () => { console.log("来自 JavaScript 的调用"); }
    }
  }
})
  .then(result => {
    console.log("模块实例化成功", result.instance.exports.exported_function());
  })
  .catch(error => {
    console.error("模块实例化失败", error);
  });
```

这个 JavaScript 代码调用了 `WebAssembly.instantiate` 函数，传入了 WebAssembly 字节码和一个包含导入对象的 JavaScript 对象。在 C++ 层面，`WebAssemblyInstantiateImpl` 函数会处理字节码的编译（如果尚未编译）和模块的实例化，并将导入对象传递给 WebAssembly 实例。

**3. `WebAssembly.Module` 构造函数 (对应 C++ 中的 `WebAssemblyModuleImpl`)：**

```javascript
const wasmCode = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, ...]);
const wasmModule = new WebAssembly.Module(wasmCode);
console.log("创建了 WebAssembly 模块", wasmModule);
```

这段 JavaScript 代码使用 `new WebAssembly.Module()` 创建了一个 WebAssembly 模块对象。在 C++ 层面，`WebAssemblyModuleImpl` 函数会被调用，负责编译给定的字节码并创建一个 `WasmModuleObject`。

**总结:**

总而言之， `v8/src/wasm/wasm-js.cc` 的第一部分代码主要负责实现 V8 引擎中与 WebAssembly 编译、实例化以及模块和实例对象创建相关的 JavaScript API，并处理 JavaScript 和 WebAssembly 之间的数据和异步流程。它使得 JavaScript 能够利用 WebAssembly 的性能优势。

Prompt: 
```
这是目录为v8/src/wasm/wasm-js.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/wasm-js.h"

#include <cinttypes>
#include <cstring>
#include <optional>

#include "include/v8-function.h"
#include "include/v8-persistent-handle.h"
#include "include/v8-promise.h"
#include "include/v8-wasm.h"
#include "src/api/api-inl.h"
#include "src/api/api-natives.h"
#include "src/base/logging.h"
#include "src/execution/execution.h"
#include "src/execution/isolate.h"
#include "src/execution/messages.h"
#include "src/flags/flags.h"
#include "src/handles/handles.h"
#include "src/heap/factory.h"
#include "src/objects/fixed-array.h"
#include "src/objects/instance-type.h"
#include "src/objects/js-function.h"
#include "src/objects/managed-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/shared-function-info.h"
#include "src/objects/templates.h"
#include "src/wasm/function-compiler.h"
#include "src/wasm/signature-hashing.h"
#include "src/wasm/streaming-decoder.h"
#include "src/wasm/value-type.h"
#include "src/wasm/wasm-debug.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-limits.h"
#include "src/wasm/wasm-objects-inl.h"
#include "src/wasm/wasm-serialization.h"
#include "src/wasm/wasm-value.h"

namespace v8 {

using i::wasm::AddressType;
using i::wasm::CompileTimeImport;
using i::wasm::CompileTimeImports;
using i::wasm::ErrorThrower;
using i::wasm::WasmEnabledFeatures;

namespace internal {

// Note: The implementation of this function is in runtime-wasm.cc, in order
// to be able to use helpers that aren't visible outside that file.
void ToUtf8Lossy(Isolate* isolate, Handle<String> string, std::string& out);

}  // namespace internal

class WasmStreaming::WasmStreamingImpl {
 public:
  WasmStreamingImpl(
      i::Isolate* isolate, const char* api_method_name,
      CompileTimeImports compile_imports,
      std::shared_ptr<internal::wasm::CompilationResultResolver> resolver)
      : i_isolate_(isolate),
        enabled_features_(WasmEnabledFeatures::FromIsolate(i_isolate_)),
        streaming_decoder_(i::wasm::GetWasmEngine()->StartStreamingCompilation(
            i_isolate_, enabled_features_, std::move(compile_imports),
            handle(i_isolate_->context(), i_isolate_), api_method_name,
            resolver)),
        resolver_(std::move(resolver)) {}

  void OnBytesReceived(const uint8_t* bytes, size_t size) {
    streaming_decoder_->OnBytesReceived(base::VectorOf(bytes, size));
  }
  void Finish(bool can_use_compiled_module) {
    streaming_decoder_->Finish(can_use_compiled_module);
  }

  void Abort(MaybeLocal<Value> exception) {
    i::HandleScope scope(i_isolate_);
    streaming_decoder_->Abort();

    // If no exception value is provided, we do not reject the promise. This can
    // happen when streaming compilation gets aborted when no script execution
    // is allowed anymore, e.g. when a browser tab gets refreshed.
    if (exception.IsEmpty()) return;

    resolver_->OnCompilationFailed(
        Utils::OpenHandle(*exception.ToLocalChecked()));
  }

  bool SetCompiledModuleBytes(base::Vector<const uint8_t> bytes) {
    if (!i::wasm::IsSupportedVersion(bytes, enabled_features_)) return false;
    streaming_decoder_->SetCompiledModuleBytes(bytes);
    return true;
  }

  void SetMoreFunctionsCanBeSerializedCallback(
      std::function<void(CompiledWasmModule)> callback) {
    streaming_decoder_->SetMoreFunctionsCanBeSerializedCallback(
        [callback = std::move(callback),
         url = streaming_decoder_->shared_url()](
            const std::shared_ptr<i::wasm::NativeModule>& native_module) {
          callback(CompiledWasmModule{native_module, url->data(), url->size()});
        });
  }

  void SetUrl(base::Vector<const char> url) { streaming_decoder_->SetUrl(url); }

 private:
  i::Isolate* const i_isolate_;
  const WasmEnabledFeatures enabled_features_;
  const std::shared_ptr<internal::wasm::StreamingDecoder> streaming_decoder_;
  const std::shared_ptr<internal::wasm::CompilationResultResolver> resolver_;
};

WasmStreaming::WasmStreaming(std::unique_ptr<WasmStreamingImpl> impl)
    : impl_(std::move(impl)) {
  TRACE_EVENT0("v8.wasm", "wasm.InitializeStreaming");
}

// The destructor is defined here because we have a unique_ptr with forward
// declaration.
WasmStreaming::~WasmStreaming() = default;

void WasmStreaming::OnBytesReceived(const uint8_t* bytes, size_t size) {
  TRACE_EVENT1("v8.wasm", "wasm.OnBytesReceived", "bytes", size);
  impl_->OnBytesReceived(bytes, size);
}

void WasmStreaming::Finish(bool can_use_compiled_module) {
  TRACE_EVENT0("v8.wasm", "wasm.FinishStreaming");
  impl_->Finish(can_use_compiled_module);
}

void WasmStreaming::Abort(MaybeLocal<Value> exception) {
  TRACE_EVENT0("v8.wasm", "wasm.AbortStreaming");
  impl_->Abort(exception);
}

bool WasmStreaming::SetCompiledModuleBytes(const uint8_t* bytes, size_t size) {
  TRACE_EVENT0("v8.wasm", "wasm.SetCompiledModuleBytes");
  return impl_->SetCompiledModuleBytes(base::VectorOf(bytes, size));
}

void WasmStreaming::SetMoreFunctionsCanBeSerializedCallback(
    std::function<void(CompiledWasmModule)> callback) {
  impl_->SetMoreFunctionsCanBeSerializedCallback(std::move(callback));
}

void WasmStreaming::SetUrl(const char* url, size_t length) {
  DCHECK_EQ('\0', url[length]);  // {url} is null-terminated.
  TRACE_EVENT1("v8.wasm", "wasm.SetUrl", "url", url);
  impl_->SetUrl(base::VectorOf(url, length));
}

// static
std::shared_ptr<WasmStreaming> WasmStreaming::Unpack(Isolate* isolate,
                                                     Local<Value> value) {
  TRACE_EVENT0("v8.wasm", "wasm.WasmStreaming.Unpack");
  i::HandleScope scope(reinterpret_cast<i::Isolate*>(isolate));
  auto managed = i::Cast<i::Managed<WasmStreaming>>(Utils::OpenHandle(*value));
  return managed->get();
}

namespace {

#define ASSIGN(type, var, expr)                          \
  Local<type> var;                                       \
  do {                                                   \
    if (!expr.ToLocal(&var)) {                           \
      DCHECK(i_isolate->has_exception());                \
      return;                                            \
    } else {                                             \
      if (i_isolate->is_execution_terminating()) return; \
      DCHECK(!i_isolate->has_exception());               \
    }                                                    \
  } while (false)

i::Handle<i::String> v8_str(i::Isolate* isolate, const char* str) {
  return isolate->factory()->NewStringFromAsciiChecked(str);
}
Local<String> v8_str(Isolate* isolate, const char* str) {
  return Utils::ToLocal(v8_str(reinterpret_cast<i::Isolate*>(isolate), str));
}

#define GET_FIRST_ARGUMENT_AS(Type)                                  \
  i::MaybeHandle<i::Wasm##Type##Object> GetFirstArgumentAs##Type(    \
      const v8::FunctionCallbackInfo<v8::Value>& info,               \
      ErrorThrower* thrower) {                                       \
    i::Handle<i::Object> arg0 = Utils::OpenHandle(*info[0]);         \
    if (!IsWasm##Type##Object(*arg0)) {                              \
      thrower->TypeError("Argument 0 must be a WebAssembly." #Type); \
      return {};                                                     \
    }                                                                \
    return i::Cast<i::Wasm##Type##Object>(arg0);                     \
  }

GET_FIRST_ARGUMENT_AS(Module)
GET_FIRST_ARGUMENT_AS(Tag)

#undef GET_FIRST_ARGUMENT_AS

static constexpr i::wasm::ModuleWireBytes kNoWireBytes{nullptr, nullptr};

i::wasm::ModuleWireBytes GetFirstArgumentAsBytes(
    const v8::FunctionCallbackInfo<v8::Value>& info, size_t max_length,
    ErrorThrower* thrower, bool* is_shared) {
  const uint8_t* start = nullptr;
  size_t length = 0;
  v8::Local<v8::Value> source = info[0];
  if (source->IsArrayBuffer()) {
    // A raw array buffer was passed.
    Local<ArrayBuffer> buffer = Local<ArrayBuffer>::Cast(source);
    auto backing_store = buffer->GetBackingStore();

    start = reinterpret_cast<const uint8_t*>(backing_store->Data());
    length = backing_store->ByteLength();
    *is_shared = buffer->IsSharedArrayBuffer();
  } else if (source->IsTypedArray()) {
    // A TypedArray was passed.
    Local<TypedArray> array = Local<TypedArray>::Cast(source);
    Local<ArrayBuffer> buffer = array->Buffer();

    auto backing_store = buffer->GetBackingStore();

    start = reinterpret_cast<const uint8_t*>(backing_store->Data()) +
            array->ByteOffset();
    length = array->ByteLength();
    *is_shared = buffer->IsSharedArrayBuffer();
  } else {
    thrower->TypeError("Argument 0 must be a buffer source");
    return kNoWireBytes;
  }
  DCHECK_IMPLIES(length, start != nullptr);
  if (length == 0) {
    thrower->CompileError("BufferSource argument is empty");
    return kNoWireBytes;
  }
  if (length > max_length) {
    // The spec requires a CompileError for implementation-defined limits, see
    // https://webassembly.github.io/spec/js-api/index.html#limits.
    thrower->CompileError("buffer source exceeds maximum size of %zu (is %zu)",
                          max_length, length);
    return kNoWireBytes;
  }
  return i::wasm::ModuleWireBytes(start, start + length);
}

namespace {
i::MaybeHandle<i::JSReceiver> ImportsAsMaybeReceiver(Local<Value> ffi) {
  if (ffi->IsUndefined()) return {};

  Local<Object> obj = Local<Object>::Cast(ffi);
  return i::Cast<i::JSReceiver>(v8::Utils::OpenHandle(*obj));
}

// This class resolves the result of WebAssembly.compile. It just places the
// compilation result in the supplied {promise}.
class AsyncCompilationResolver : public i::wasm::CompilationResultResolver {
 public:
  AsyncCompilationResolver(Isolate* isolate, Local<Context> context,
                           Local<Promise::Resolver> promise_resolver)
      : isolate_(isolate),
        context_(isolate, context),
        promise_resolver_(isolate, promise_resolver) {
    context_.SetWeak();
    promise_resolver_.AnnotateStrongRetainer(kGlobalPromiseHandle);
  }

  void OnCompilationSucceeded(i::Handle<i::WasmModuleObject> result) override {
    if (finished_) return;
    finished_ = true;
    if (context_.IsEmpty()) return;
    auto callback = reinterpret_cast<i::Isolate*>(isolate_)
                        ->wasm_async_resolve_promise_callback();
    CHECK(callback);
    callback(isolate_, context_.Get(isolate_), promise_resolver_.Get(isolate_),
             Utils::ToLocal(i::Cast<i::Object>(result)),
             WasmAsyncSuccess::kSuccess);
  }

  void OnCompilationFailed(i::Handle<i::Object> error_reason) override {
    if (finished_) return;
    finished_ = true;
    if (context_.IsEmpty()) return;
    auto callback = reinterpret_cast<i::Isolate*>(isolate_)
                        ->wasm_async_resolve_promise_callback();
    CHECK(callback);
    callback(isolate_, context_.Get(isolate_), promise_resolver_.Get(isolate_),
             Utils::ToLocal(error_reason), WasmAsyncSuccess::kFail);
  }

 private:
  static constexpr char kGlobalPromiseHandle[] =
      "AsyncCompilationResolver::promise_";
  bool finished_ = false;
  Isolate* isolate_;
  Global<Context> context_;
  Global<Promise::Resolver> promise_resolver_;
};

constexpr char AsyncCompilationResolver::kGlobalPromiseHandle[];

// This class resolves the result of WebAssembly.instantiate(module, imports).
// It just places the instantiation result in the supplied {promise}.
class InstantiateModuleResultResolver
    : public i::wasm::InstantiationResultResolver {
 public:
  InstantiateModuleResultResolver(Isolate* isolate, Local<Context> context,
                                  Local<Promise::Resolver> promise_resolver)
      : isolate_(isolate),
        context_(isolate, context),
        promise_resolver_(isolate, promise_resolver) {
    context_.SetWeak();
    promise_resolver_.AnnotateStrongRetainer(kGlobalPromiseHandle);
  }

  void OnInstantiationSucceeded(
      i::Handle<i::WasmInstanceObject> instance) override {
    if (context_.IsEmpty()) return;
    auto callback = reinterpret_cast<i::Isolate*>(isolate_)
                        ->wasm_async_resolve_promise_callback();
    CHECK(callback);
    callback(isolate_, context_.Get(isolate_), promise_resolver_.Get(isolate_),
             Utils::ToLocal(i::Cast<i::Object>(instance)),
             WasmAsyncSuccess::kSuccess);
  }

  void OnInstantiationFailed(i::Handle<i::Object> error_reason) override {
    if (context_.IsEmpty()) return;
    auto callback = reinterpret_cast<i::Isolate*>(isolate_)
                        ->wasm_async_resolve_promise_callback();
    CHECK(callback);
    callback(isolate_, context_.Get(isolate_), promise_resolver_.Get(isolate_),
             Utils::ToLocal(error_reason), WasmAsyncSuccess::kFail);
  }

 private:
  static constexpr char kGlobalPromiseHandle[] =
      "InstantiateModuleResultResolver::promise_";
  Isolate* isolate_;
  Global<Context> context_;
  Global<Promise::Resolver> promise_resolver_;
};

constexpr char InstantiateModuleResultResolver::kGlobalPromiseHandle[];

// This class resolves the result of WebAssembly.instantiate(bytes, imports).
// For that it creates a new {JSObject} which contains both the provided
// {WasmModuleObject} and the resulting {WebAssemblyInstanceObject} itself.
class InstantiateBytesResultResolver
    : public i::wasm::InstantiationResultResolver {
 public:
  InstantiateBytesResultResolver(Isolate* isolate, Local<Context> context,
                                 Local<Promise::Resolver> promise_resolver,
                                 Local<Value> module)
      : isolate_(isolate),
        context_(isolate, context),
        promise_resolver_(isolate, promise_resolver),
        module_(isolate, module) {
    context_.SetWeak();
    promise_resolver_.AnnotateStrongRetainer(kGlobalPromiseHandle);
    module_.AnnotateStrongRetainer(kGlobalModuleHandle);
  }

  void OnInstantiationSucceeded(
      i::Handle<i::WasmInstanceObject> instance) override {
    if (context_.IsEmpty()) return;
    Local<Context> context = context_.Get(isolate_);
    WasmAsyncSuccess success = WasmAsyncSuccess::kSuccess;

    // The result is a JSObject with 2 fields which contain the
    // WasmInstanceObject and the WasmModuleObject.
    Local<Object> result = Object::New(isolate_);
    if (V8_UNLIKELY(result
                        ->CreateDataProperty(context,
                                             v8_str(isolate_, "module"),
                                             module_.Get(isolate_))
                        .IsNothing())) {
      i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate_);
      // We assume that a TerminationException is the only reason why
      // `CreateDataProperty` can fail here. We should revisit
      // https://crbug.com/1515227 again if this CHECK fails.
      CHECK(i::IsTerminationException(i_isolate->exception()));
      result = Utils::ToLocal(
          handle(i::Cast<i::JSObject>(i_isolate->exception()), i_isolate));
      success = WasmAsyncSuccess::kFail;
    }
    if (V8_UNLIKELY(result
                        ->CreateDataProperty(
                            context, v8_str(isolate_, "instance"),
                            Utils::ToLocal(i::Cast<i::Object>(instance)))
                        .IsNothing())) {
      i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate_);
      CHECK(i::IsTerminationException(i_isolate->exception()));
      result = Utils::ToLocal(
          handle(i::Cast<i::JSObject>(i_isolate->exception()), i_isolate));
      success = WasmAsyncSuccess::kFail;
    }

    auto callback = reinterpret_cast<i::Isolate*>(isolate_)
                        ->wasm_async_resolve_promise_callback();
    CHECK(callback);
    callback(isolate_, context, promise_resolver_.Get(isolate_), result,
             success);
  }

  void OnInstantiationFailed(i::Handle<i::Object> error_reason) override {
    if (context_.IsEmpty()) return;
    auto callback = reinterpret_cast<i::Isolate*>(isolate_)
                        ->wasm_async_resolve_promise_callback();
    CHECK(callback);
    callback(isolate_, context_.Get(isolate_), promise_resolver_.Get(isolate_),
             Utils::ToLocal(error_reason), WasmAsyncSuccess::kFail);
  }

 private:
  static constexpr char kGlobalPromiseHandle[] =
      "InstantiateBytesResultResolver::promise_";
  static constexpr char kGlobalModuleHandle[] =
      "InstantiateBytesResultResolver::module_";
  Isolate* isolate_;
  Global<Context> context_;
  Global<Promise::Resolver> promise_resolver_;
  Global<Value> module_;
};

constexpr char InstantiateBytesResultResolver::kGlobalPromiseHandle[];
constexpr char InstantiateBytesResultResolver::kGlobalModuleHandle[];

// This class is the {CompilationResultResolver} for
// WebAssembly.instantiate(bytes, imports). When compilation finishes,
// {AsyncInstantiate} is started on the compilation result.
class AsyncInstantiateCompileResultResolver
    : public i::wasm::CompilationResultResolver {
 public:
  AsyncInstantiateCompileResultResolver(
      Isolate* isolate, Local<Context> context,
      Local<Promise::Resolver> promise_resolver, Local<Value> imports)
      : isolate_(isolate),
        context_(isolate, context),
        promise_resolver_(isolate, promise_resolver),
        imports_(isolate, imports) {
    context_.SetWeak();
    promise_resolver_.AnnotateStrongRetainer(kGlobalPromiseHandle);
    imports_.AnnotateStrongRetainer(kGlobalImportsHandle);
  }

  void OnCompilationSucceeded(i::Handle<i::WasmModuleObject> result) override {
    if (finished_) return;
    finished_ = true;
    i::wasm::GetWasmEngine()->AsyncInstantiate(
        reinterpret_cast<i::Isolate*>(isolate_),
        std::make_unique<InstantiateBytesResultResolver>(
            isolate_, context_.Get(isolate_), promise_resolver_.Get(isolate_),
            Utils::ToLocal(i::Cast<i::Object>(result))),
        result, ImportsAsMaybeReceiver(imports_.Get(isolate_)));
  }

  void OnCompilationFailed(i::Handle<i::Object> error_reason) override {
    if (finished_) return;
    finished_ = true;
    if (context_.IsEmpty()) return;
    auto callback = reinterpret_cast<i::Isolate*>(isolate_)
                        ->wasm_async_resolve_promise_callback();
    CHECK(callback);
    callback(isolate_, context_.Get(isolate_), promise_resolver_.Get(isolate_),
             Utils::ToLocal(error_reason), WasmAsyncSuccess::kFail);
  }

 private:
  static constexpr char kGlobalPromiseHandle[] =
      "AsyncInstantiateCompileResultResolver::promise_";
  static constexpr char kGlobalImportsHandle[] =
      "AsyncInstantiateCompileResultResolver::module_";
  bool finished_ = false;
  Isolate* isolate_;
  Global<Context> context_;
  Global<Promise::Resolver> promise_resolver_;
  Global<Value> imports_;
};

constexpr char AsyncInstantiateCompileResultResolver::kGlobalPromiseHandle[];
constexpr char AsyncInstantiateCompileResultResolver::kGlobalImportsHandle[];

// TODO(clemensb): Make this less inefficient.
std::string ToString(const char* name) { return std::string(name); }

std::string ToString(const i::DirectHandle<i::String> name) {
  return std::string("Property '") + name->ToCString().get() + "'";
}

// Web IDL: '[EnforceRange] unsigned long'
// https://heycam.github.io/webidl/#EnforceRange
template <typename Name>
std::optional<uint32_t> EnforceUint32(Name argument_name, Local<v8::Value> v,
                                      Local<Context> context,
                                      ErrorThrower* thrower) {
  double double_number;
  if (!v->NumberValue(context).To(&double_number)) {
    thrower->TypeError("%s must be convertible to a number",
                       ToString(argument_name).c_str());
    return std::nullopt;
  }
  if (!std::isfinite(double_number)) {
    thrower->TypeError("%s must be convertible to a valid number",
                       ToString(argument_name).c_str());
    return std::nullopt;
  }
  if (double_number < 0) {
    thrower->TypeError("%s must be non-negative",
                       ToString(argument_name).c_str());
    return std::nullopt;
  }
  if (double_number > std::numeric_limits<uint32_t>::max()) {
    thrower->TypeError("%s must be in the unsigned long range",
                       ToString(argument_name).c_str());
    return std::nullopt;
  }

  return static_cast<uint32_t>(double_number);
}

// First step of AddressValueToU64, for addrtype == "i64".
template <typename Name>
std::optional<uint64_t> EnforceBigIntUint64(Name argument_name, Local<Value> v,
                                            Local<Context> context,
                                            ErrorThrower* thrower) {
  // Use the internal API, as v8::Value::ToBigInt clears exceptions.
  i::Handle<i::BigInt> bigint;
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  if (!i::BigInt::FromObject(i_isolate, Utils::OpenHandle(*v))
           .ToHandle(&bigint)) {
    return std::nullopt;
  }

  bool lossless;
  uint64_t result = bigint->AsUint64(&lossless);
  if (!lossless) {
    thrower->TypeError("%s must be in u64 range",
                       ToString(argument_name).c_str());
    return std::nullopt;
  }

  return result;
}

// The enum values need to match "WasmCompilationMethod" in
// tools/metrics/histograms/enums.xml.
enum CompilationMethod {
  kSyncCompilation = 0,
  kAsyncCompilation = 1,
  kStreamingCompilation = 2,
  kAsyncInstantiation = 3,
  kStreamingInstantiation = 4,
};

void RecordCompilationMethod(i::Isolate* isolate, CompilationMethod method) {
  isolate->counters()->wasm_compilation_method()->AddSample(method);
}

CompileTimeImports ArgumentToCompileOptions(
    Local<Value> arg_value, i::Isolate* isolate,
    WasmEnabledFeatures enabled_features) {
  if (!enabled_features.has_imported_strings()) return {};
  i::Handle<i::Object> arg = Utils::OpenHandle(*arg_value);
  if (!i::IsJSReceiver(*arg)) return {};
  i::Handle<i::JSReceiver> receiver = i::Cast<i::JSReceiver>(arg);
  CompileTimeImports result;

  // ==================== Builtins ====================
  i::Handle<i::JSAny> builtins;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, builtins,
                                   i::Cast<i::JSAny>(i::JSReceiver::GetProperty(
                                       isolate, receiver, "builtins")),
                                   {});
  if (i::IsJSReceiver(*builtins)) {
    i::Handle<i::Object> length_obj;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, length_obj,
        i::Object::GetLengthFromArrayLike(isolate,
                                          i::Cast<i::JSReceiver>(builtins)),
        {});
    double raw_length = i::Object::NumberValue(*length_obj);
    // Technically we should probably iterate up to 2^53-1 if {length_obj} says
    // so, but lengths above 2^32 probably don't happen in practice (and would
    // be very slow if they do), so just use a saturating to-uint32 conversion
    // for simplicity.
    uint32_t len = raw_length >= i::kMaxUInt32
                       ? i::kMaxUInt32
                       : static_cast<uint32_t>(raw_length);
    for (uint32_t i = 0; i < len; i++) {
      i::LookupIterator it(isolate, builtins, i);
      Maybe<bool> maybe_found = i::JSReceiver::HasProperty(&it);
      MAYBE_RETURN(maybe_found, {});
      if (!maybe_found.FromJust()) continue;
      i::Handle<i::Object> value;
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, value,
                                       i::Object::GetProperty(&it), {});
      if (i::IsString(*value)) {
        i::Tagged<i::String> builtin = i::Cast<i::String>(*value);
        // TODO(jkummerow): We could make other string comparisons to known
        // constants in this file more efficient by migrating them to this
        // style (rather than `...->StringEquals(v8_str(...))`).
        if (builtin->IsEqualTo(base::CStrVector("js-string"))) {
          result.Add(CompileTimeImport::kJsString);
          continue;
        }
        if (enabled_features.has_imported_strings_utf8()) {
          if (builtin->IsEqualTo(base::CStrVector("text-encoder"))) {
            result.Add(CompileTimeImport::kTextEncoder);
            continue;
          }
          if (builtin->IsEqualTo(base::CStrVector("text-decoder"))) {
            result.Add(CompileTimeImport::kTextDecoder);
            continue;
          }
        }
      }
    }
  }

  // ==================== String constants ====================
  i::Handle<i::String> importedStringConstants =
      isolate->factory()->InternalizeUtf8String("importedStringConstants");
  if (i::JSReceiver::HasProperty(isolate, receiver, importedStringConstants)
          .FromMaybe(false)) {
    i::Handle<i::Object> constants_value;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, constants_value,
        i::JSReceiver::GetProperty(isolate, receiver, importedStringConstants),
        {});
    if (i::IsString(*constants_value)) {
      i::ToUtf8Lossy(isolate, i::Cast<i::String>(constants_value),
                     result.constants_module());
      result.Add(CompileTimeImport::kStringConstants);
    }
  }

  return result;
}

// A scope object with accessors and destructur DCHECKs to be used in
// implementations of Wasm JS-API methods.
class WasmJSApiScope {
 public:
  explicit WasmJSApiScope(
      const v8::FunctionCallbackInfo<v8::Value>& callback_info,
      const char* api_name)
      : callback_info_(callback_info),
        isolate_{callback_info.GetIsolate()},
        handle_scope_{isolate_},
        thrower_{reinterpret_cast<i::Isolate*>(isolate_), api_name} {
    DCHECK(i::ValidateCallbackInfo(callback_info));
  }

  WasmJSApiScope(const WasmJSApiScope&) = delete;
  WasmJSApiScope& operator=(const WasmJSApiScope&) = delete;

#if DEBUG
  ~WasmJSApiScope() {
    // If there was an exception we should not have a return value set.
    DCHECK_IMPLIES(i_isolate()->has_exception() || thrower_.error(),
                   callback_info_.GetReturnValue().Get()->IsUndefined());
  }
#endif

  void AssertException() const {
    DCHECK(callback_info_.GetReturnValue().Get()->IsUndefined());
    DCHECK(i_isolate()->has_exception() || thrower_.error());
  }

  const v8::FunctionCallbackInfo<v8::Value>& callback_info() {
    return callback_info_;
  }

  const char* api_name() const { return thrower_.context_name(); }

  // Accessor for all essential fields. To be decomposed into individual aliases
  // via structured binding.
  std::tuple<v8::Isolate*, i::Isolate*, ErrorThrower&> isolates_and_thrower() {
    return {isolate_, i_isolate(), thrower_};
  }

 private:
  i::Isolate* i_isolate() const {
    return reinterpret_cast<i::Isolate*>(isolate_);
  }

  const v8::FunctionCallbackInfo<v8::Value>& callback_info_;
  v8::Isolate* const isolate_;
  HandleScope handle_scope_;
  ErrorThrower thrower_;
};

}  // namespace

// WebAssembly.compile(bytes, options) -> Promise
void WebAssemblyCompileImpl(const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.compile()"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();
  RecordCompilationMethod(i_isolate, kAsyncCompilation);

  Local<Context> context = isolate->GetCurrentContext();
  ASSIGN(Promise::Resolver, promise_resolver, Promise::Resolver::New(context));
  Local<Promise> promise = promise_resolver->GetPromise();
  v8::ReturnValue<v8::Value> return_value = info.GetReturnValue();
  return_value.Set(promise);

  std::shared_ptr<i::wasm::CompilationResultResolver> resolver(
      new AsyncCompilationResolver(isolate, context, promise_resolver));

  i::Handle<i::NativeContext> native_context = i_isolate->native_context();
  if (!i::wasm::IsWasmCodegenAllowed(i_isolate, native_context)) {
    i::DirectHandle<i::String> error =
        i::wasm::ErrorStringForCodegen(i_isolate, native_context);
    thrower.CompileError("%s", error->ToCString().get());
    resolver->OnCompilationFailed(thrower.Reify());
    return;
  }

  bool is_shared = false;
  auto bytes = GetFirstArgumentAsBytes(info, i::wasm::max_module_size(),
                                       &thrower, &is_shared);
  if (bytes == kNoWireBytes) {
    resolver->OnCompilationFailed(thrower.Reify());
    return;
  }
  auto enabled_features = WasmEnabledFeatures::FromIsolate(i_isolate);
  CompileTimeImports compile_imports =
      ArgumentToCompileOptions(info[1], i_isolate, enabled_features);
  if (i_isolate->has_exception()) {
    if (i_isolate->is_execution_terminating()) return;
    resolver->OnCompilationFailed(handle(i_isolate->exception(), i_isolate));
    i_isolate->clear_exception();
    return;
  }
  // Asynchronous compilation handles copying wire bytes if necessary.
  i::wasm::GetWasmEngine()->AsyncCompile(
      i_isolate, enabled_features, std::move(compile_imports),
      std::move(resolver), bytes, is_shared, js_api_scope.api_name());
}

void WasmStreamingCallbackForTesting(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.compile()"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();

  std::shared_ptr<v8::WasmStreaming> streaming =
      v8::WasmStreaming::Unpack(info.GetIsolate(), info.Data());

  bool is_shared = false;
  // We don't check the buffer length up front, to allow d8 to test that the
  // streaming decoder implementation handles overly large inputs correctly.
  size_t unlimited = std::numeric_limits<size_t>::max();
  i::wasm::ModuleWireBytes bytes =
      GetFirstArgumentAsBytes(info, unlimited, &thrower, &is_shared);
  if (bytes == kNoWireBytes) {
    streaming->Abort(Utils::ToLocal(thrower.Reify()));
    return;
  }
  streaming->OnBytesReceived(bytes.start(), bytes.length());
  streaming->Finish();
  CHECK(!thrower.error());
}

void WasmStreamingPromiseFailedCallback(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  std::shared_ptr<v8::WasmStreaming> streaming =
      v8::WasmStreaming::Unpack(info.GetIsolate(), info.Data());
  streaming->Abort(info[0]);
}

// WebAssembly.compileStreaming(Response | Promise<Response>, options)
//   -> Promise<WebAssembly.Module>
void WebAssemblyCompileStreaming(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  WasmJSApiScope js_api_scope{info, "WebAssembly.compileStreaming()"};
  auto [isolate, i_isolate, thrower] = js_api_scope.isolates_and_thrower();
  RecordCompilationMethod(i_isolate, kStreamingCompilation);
  Local<Context> context = isolate->GetCurrentContext();

  // Create and assign the return value of this function.
  ASSIGN(Promise::Resolver, promise_resolver, Promise::Resolver::New(context));
  Local<Promise> promise = promise_resolver->GetPromise();
  v8::ReturnValue<v8::Value> return_value = info.GetReturnValue();
  return_value.Set(promise);

  // Prepare the CompilationResultResolver for the compilation.
  auto resolver = std::make_shared<AsyncCompilationResolver>(isolate, context,
                                                             promise_resolver);

  i::Handle<i::NativeContext> native_context = i_isolate->native_context();
  if (!i::wasm::IsWasmCodegenAllowed(i_isolate, native_context)) {
    i::DirectHandle<i::String> error =
        i::wasm::ErrorStringForCodegen(i_isolate, native_context);
    thrower.CompileError("%s", error->ToCString().get());
    resolver->OnCompilationFailed(thrower.Reify());
    return;
  }

  auto enabled_features = WasmEnabledFeatures::FromIsolate(i_isolate);
  CompileTimeImports compile_imports =
      ArgumentToCompileOptions(info[1], i_isolate, enabled_features);
  if (i_isolate->has_exception()) {
    if (i_isolate->is_execution_terminating()) return;
    resolver->OnCompilationFailed(handle(i_isolate->exception(), i_isolate));
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
              resolver)));

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
"""


```