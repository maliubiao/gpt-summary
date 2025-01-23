Response:
The user wants to understand the functionality of the provided C++ code snippet, which is a part of the V8 JavaScript engine, specifically the `v8/src/wasm/wasm-js.cc` file.

Here's a breakdown of the thought process to analyze the code and address the user's request:

1. **High-Level Understanding:** The file name "wasm-js.cc" suggests that this code bridges the gap between WebAssembly and JavaScript within V8. It likely handles the JavaScript API for interacting with WebAssembly.

2. **Scanning for Keywords and Structures:**  Look for important terms and patterns:
    * `#include`: This confirms it's C++ code and reveals dependencies on other V8 components (e.g., `wasm.h`, `v8-wasm.h`, `v8-promise.h`).
    * `namespace v8`, `namespace internal`:  V8's internal organization.
    * `class WasmStreaming`:  A key class likely related to streaming compilation of WebAssembly modules.
    * `WebAssemblyCompileImpl`, `WebAssemblyCompileStreaming`: Function names strongly suggesting implementations of the JavaScript `WebAssembly.compile` and `WebAssembly.compileStreaming` APIs.
    * `Promise`, `Promise::Resolver`:  Indicates asynchronous operations and handling of results.
    * `ErrorThrower`:  For reporting errors.
    * `CompileTimeImports`: Related to module compilation options, possibly for importing JavaScript functions or other features into WebAssembly.
    * `AsyncCompilationResolver`, `InstantiateModuleResultResolver`, `InstantiateBytesResultResolver`, `AsyncInstantiateCompileResultResolver`: Classes responsible for handling the results of asynchronous WebAssembly operations.
    * `GetFirstArgumentAsBytes`, `GetFirstArgumentAsModule`: Helper functions for validating input arguments.

3. **Analyzing `WasmStreaming`:**  This class seems central to handling streaming compilation.
    * `WasmStreamingImpl`:  Likely the implementation details hidden behind the `WasmStreaming` interface.
    * `OnBytesReceived`, `Finish`, `Abort`:  Methods indicating the stages of the streaming compilation process.
    * `SetCompiledModuleBytes`, `SetMoreFunctionsCanBeSerializedCallback`, `SetUrl`:  Additional controls and information provided during streaming.
    * The constructor takes `CompileTimeImports`, which reinforces the idea that this is part of the compilation pipeline.

4. **Focusing on `WebAssemblyCompileImpl` and `WebAssemblyCompileStreaming`:** These functions are the entry points for the JavaScript APIs.
    * They take `v8::FunctionCallbackInfo`, the standard V8 mechanism for handling JavaScript function calls.
    * They create `Promise` objects, confirming their asynchronous nature.
    * They use `CompilationResultResolver` instances to manage the outcome of the compilation.
    * `WebAssemblyCompileImpl` takes raw bytes as input.
    * `WebAssemblyCompileStreaming` seems to handle a `Response` or `Promise<Response>`, indicating it works with network requests or similar asynchronous data sources.

5. **Identifying Key Functionalities:** Based on the analysis so far, the primary functions are:
    * **Asynchronous compilation:**  `WebAssembly.compile`
    * **Streaming compilation:** `WebAssembly.compileStreaming`

6. **Considering JavaScript Relationships:** The code interacts with JavaScript through:
    * Taking JavaScript values as arguments (e.g., `ArrayBuffer`, `TypedArray`, import objects).
    * Returning `Promise` objects to JavaScript.
    * Using callbacks to resolve or reject these promises.
    * The `CompileTimeImports` structure suggests importing JavaScript functionalities into WebAssembly.

7. **Generating JavaScript Examples:**  Illustrate the use of `WebAssembly.compile` and `WebAssembly.compileStreaming`. Show how to handle the returned promises.

8. **Thinking about Logic and Input/Output:**
    * **`WebAssembly.compile`:** Input is raw bytes, output is a `WebAssembly.Module` wrapped in a promise.
    * **`WebAssembly.compileStreaming`:** Input is a `Response` or a promise of a `Response`, output is a `WebAssembly.Module` wrapped in a promise.

9. **Considering Common Programming Errors:** Focus on mistakes users might make when working with these APIs:
    * Providing incorrect input types (e.g., not a buffer source).
    * Handling promise rejections improperly.
    * Not understanding asynchronous behavior.

10. **归纳功能 (Summarizing Functionality):** Combine the identified functionalities into a concise summary.

11. **Addressing Specific Instructions:**
    * **`.tq` Check:** Explicitly state that the file does not end with `.tq`.
    * **JavaScript Relationship:** Provide detailed JavaScript examples.
    * **Logic and Input/Output:** Describe the expected inputs and outputs for the core functions.
    * **Common Errors:** Illustrate typical user mistakes.
    * **Part 1 Summary:** Create a summary specifically for this part of the code.

By following this thought process, which involves code scanning, keyword analysis, understanding the flow of execution, and relating the C++ code to JavaScript concepts, it's possible to accurately determine the functionality of the `v8/src/wasm/wasm-js.cc` file and address all aspects of the user's request.
```cpp
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
      
### 提示词
```
这是目录为v8/src/wasm/wasm-js.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wasm-js.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
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
                           Utils::ToLocal(i::Cast<i::Object>(
```