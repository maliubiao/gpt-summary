Response:
The user wants a summary of the functionality of the provided C++ code. I need to go through the code and identify the key features and purposes of the functions defined in the `v8/src/runtime/runtime-test-wasm.cc` file.

Here's a breakdown of the functionalities I can see:

1. **Wasm Compilation Control:** Functions like `Runtime_SetWasmCompileControls` and related helper functions manage limits and permissions for WebAssembly module compilation.
2. **Wasm Instantiation Control:** Similarly, `Runtime_SetWasmInstantiateControls` handles restrictions on instantiating Wasm modules.
3. **Debugging and Tracing:** Functions like `Runtime_WasmTraceEnter`, `Runtime_WasmTraceExit`, and `Runtime_WasmTraceMemory` are related to tracing the execution of Wasm code, potentially for debugging or profiling.
4. **Wrapper Counting:** Functions like `Runtime_CountUnoptimizedWasmToJSWrapper` and `Runtime_HasUnoptimizedWasmToJSWrapper` appear to be for testing or internal analysis of the wrappers used when calling between JavaScript and WebAssembly.
5. **Code Kind Checks:** Functions like `Runtime_IsAsmWasmCode` and `Runtime_IsWasmCode` check the type of the compiled code associated with a JavaScript function.
6. **Trap Handling:** Functions like `Runtime_IsWasmTrapHandlerEnabled`, `Runtime_IsThreadInWasm`, and `Runtime_GetWasmRecoveredTrapCount` deal with the trap handler, a mechanism for handling errors within WebAssembly.
7. **Exception Handling:** Functions like `Runtime_GetWasmExceptionTagId` and `Runtime_GetWasmExceptionValues` are involved in inspecting WebAssembly exceptions.
8. **Serialization/Deserialization:**  `Runtime_SerializeWasmModule` and `Runtime_DeserializeWasmModule` handle the process of serializing and deserializing compiled WebAssembly modules.
9. **Instance Counting:** `Runtime_WasmGetNumberOfInstances` counts the number of instances of a given WebAssembly module.
10. **Code Space Information:** `Runtime_WasmNumCodeSpaces` provides information about the memory spaces used by a WebAssembly module.
11. **Tiering Up:** `Runtime_WasmTierUpFunction` appears to force the "tier-up" process, where a WebAssembly function might be optimized further after initial compilation.
12. **Wasm Object Creation:** `Runtime_WasmStruct` and `Runtime_WasmArray` are used to create instances of WebAssembly struct and array types for testing purposes.
13. **Debugging State Management:** `Runtime_WasmEnterDebugging` and `Runtime_WasmLeaveDebugging` likely control some debugging state related to WebAssembly.

The code seems to be a collection of runtime functions primarily used for testing and internal debugging of the V8 WebAssembly implementation.

Since the file name ends with `.cc` and not `.tq`, it's C++ code, not Torque.

Many functions deal with internal V8 concepts and are not directly related to typical JavaScript usage. However, the compilation and instantiation controls have a connection to how JavaScript loads and executes WebAssembly.

I need to formulate the summary based on these observations.
```cpp
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cinttypes>
#include <type_traits>

#include "include/v8-wasm.h"
#include "src/base/memory.h"
#include "src/base/platform/mutex.h"
#include "src/builtins/builtins-inl.h"
#include "src/execution/arguments-inl.h"
#include "src/execution/frames-inl.h"
#include "src/heap/heap-inl.h"
#include "src/objects/property-descriptor.h"
#include "src/objects/smi.h"
#include "src/trap-handler/trap-handler.h"
#include "src/wasm/function-body-decoder.h"
#include "src/wasm/fuzzing/random-module-generation.h"
#include "src/wasm/memory-tracing.h"
#include "src/wasm/module-compiler.h"
#include "src/wasm/wasm-code-manager.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-objects-inl.h"
#include "src/wasm/wasm-result.h"
#include "src/wasm/wasm-serialization.h"

namespace v8::internal {

namespace {
V8_WARN_UNUSED_RESULT Tagged<Object> CrashUnlessFuzzing(Isolate* isolate) {
  CHECK(v8_flags.fuzzing);
  return ReadOnlyRoots(isolate).undefined_value();
}

struct WasmCompileControls {
  uint32_t MaxWasmBufferSize = std::numeric_limits<uint32_t>::max();
  bool AllowAnySizeForAsync = true;
};
using WasmCompileControlsMap = std::map<v8::Isolate*, WasmCompileControls>;

// We need per-isolate controls, because we sometimes run tests in multiple
// isolates concurrently. Methods need to hold the accompanying mutex on access.
// To avoid upsetting the static initializer count, we lazy initialize this.
DEFINE_LAZY_LEAKY_OBJECT_GETTER(WasmCompileControlsMap,
                                GetPerIsolateWasmControls)
base::LazyMutex g_PerIsolateWasmControlsMutex = LAZY_MUTEX_INITIALIZER;

bool IsWasmCompileAllowed(v8::Isolate* isolate, v8::Local<v8::Value> value,
                          bool is_async) {
  base::MutexGuard guard(g_PerIsolateWasmControlsMutex.Pointer());
  DCHECK_GT(GetPerIsolateWasmControls()->count(isolate), 0);
  const WasmCompileControls& ctrls = GetPerIsolateWasmControls()->at(isolate);
  return (is_async && ctrls.AllowAnySizeForAsync) ||
         (value->IsArrayBuffer() && value.As<v8::ArrayBuffer>()->ByteLength() <=
                                        ctrls.MaxWasmBufferSize) ||
         (value->IsArrayBufferView() &&
          value.As<v8::ArrayBufferView>()->ByteLength() <=
              ctrls.MaxWasmBufferSize);
}

// Use the compile controls for instantiation, too
bool IsWasmInstantiateAllowed(v8::Isolate* isolate,
                              v8::Local<v8::Value> module_or_bytes,
                              bool is_async) {
  base::MutexGuard guard(g_PerIsolateWasmControlsMutex.Pointer());
  DCHECK_GT(GetPerIsolateWasmControls()->count(isolate), 0);
  const WasmCompileControls& ctrls = GetPerIsolateWasmControls()->at(isolate);
  if (is_async && ctrls.AllowAnySizeForAsync) return true;
  if (!module_or_bytes->IsWasmModuleObject()) {
    return IsWasmCompileAllowed(isolate, module_or_bytes, is_async);
  }
  v8::Local<v8::WasmModuleObject> module =
      v8::Local<v8::WasmModuleObject>::Cast(module_or_bytes);
  return static_cast<uint32_t>(
             module->GetCompiledModule().GetWireBytesRef().size()) <=
         ctrls.MaxWasmBufferSize;
}

v8::Local<v8::Value> NewRangeException(v8::Isolate* isolate,
                                       const char* message) {
  return v8::Exception::RangeError(
      v8::String::NewFromOneByte(isolate,
                                 reinterpret_cast<const uint8_t*>(message))
          .ToLocalChecked());
}

void ThrowRangeException(v8::Isolate* isolate, const char* message) {
  isolate->ThrowException(NewRangeException(isolate, message));
}

bool WasmModuleOverride(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(ValidateCallbackInfo(info));
  if (IsWasmCompileAllowed(info.GetIsolate(), info[0], false)) return false;
  ThrowRangeException(info.GetIsolate(), "Sync compile not allowed");
  return true;
}

bool WasmInstanceOverride(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(ValidateCallbackInfo(info));
  if (IsWasmInstantiateAllowed(info.GetIsolate(), info[0], false)) return false;
  ThrowRangeException(info.GetIsolate(), "Sync instantiate not allowed");
  return true;
}

}  // namespace

// Returns a callable object. The object returns the difference of its two
// parameters when it is called.
RUNTIME_FUNCTION(Runtime_SetWasmCompileControls) {
  HandleScope scope(isolate);
  if (args.length() != 2 || !IsSmi(args[0]) || !IsBoolean(args[1])) {
    return CrashUnlessFuzzing(isolate);
  }
  v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate);
  int block_size = args.smi_value_at(0);
  bool allow_async = Cast<Boolean>(args[1])->ToBool(isolate);
  base::MutexGuard guard(g_PerIsolateWasmControlsMutex.Pointer());
  WasmCompileControls& ctrl = (*GetPerIsolateWasmControls())[v8_isolate];
  ctrl.AllowAnySizeForAsync = allow_async;
  ctrl.MaxWasmBufferSize = static_cast<uint32_t>(block_size);
  v8_isolate->SetWasmModuleCallback(WasmModuleOverride);
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_SetWasmInstantiateControls) {
  HandleScope scope(isolate);
  v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate);
  v8_isolate->SetWasmInstanceCallback(WasmInstanceOverride);
  return ReadOnlyRoots(isolate).undefined_value();
}

namespace {

void PrintIndentation(int stack_size) {
  const int max_display = 80;
  if (stack_size <= max_display) {
    PrintF("%4d:%*s", stack_size, stack_size, "");
  } else {
    PrintF("%4d:%*s", stack_size, max_display, "...");
  }
}

int WasmStackSize(Isolate* isolate) {
  // TODO(wasm): Fix this for mixed JS/Wasm stacks with both --trace and
  // --trace-wasm.
  int n = 0;
  for (DebuggableStackFrameIterator it(isolate); !it.done(); it.Advance()) {
    if (it.is_wasm()) n++;
  }
  return n;
}

}  // namespace

RUNTIME_FUNCTION(Runtime_CountUnoptimizedWasmToJSWrapper) {
  SealHandleScope shs(isolate);
  if (args.length() != 1 || !IsWasmInstanceObject(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  Tagged<WasmInstanceObject> instance_object =
      Cast<WasmInstanceObject>(args[0]);
  Tagged<WasmTrustedInstanceData> trusted_data =
      instance_object->trusted_data(isolate);
  Address wrapper_start = isolate->builtins()
                              ->code(Builtin::kWasmToJsWrapperAsm)
                              ->instruction_start();
  int result = 0;
  Tagged<WasmDispatchTable> dispatch_table =
      trusted_data->dispatch_table_for_imports();
  int import_count = dispatch_table->length();
  for (int i = 0; i < import_count; ++i) {
    if (dispatch_table->target(i) == wrapper_start) {
      ++result;
    }
  }
  Tagged<ProtectedFixedArray> dispatch_tables = trusted_data->dispatch_tables();
  int table_count = dispatch_tables->length();
  for (int table_index = 0; table_index < table_count; ++table_index) {
    if (dispatch_tables->get(table_index) == Smi::zero()) continue;
    Tagged<WasmDispatchTable> table =
        Cast<WasmDispatchTable>(dispatch_tables->get(table_index));
    int table_size = table->length();
    for (int entry_index = 0; entry_index < table_size; ++entry_index) {
      if (table->target(entry_index) == wrapper_start) ++result;
    }
  }
  return Smi::FromInt(result);
}

RUNTIME_FUNCTION(Runtime_HasUnoptimizedWasmToJSWrapper) {
  SealHandleScope shs{isolate};
  if (args.length() != 1 || !IsJSFunction(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  Tagged<JSFunction> function = Cast<JSFunction>(args[0]);
  Tagged<SharedFunctionInfo> sfi = function->shared();
  if (!sfi->HasWasmFunctionData()) return isolate->heap()->ToBoolean(false);
  Tagged<WasmFunctionData> func_data = sfi->wasm_function_data();
  Address call_target = func_data->internal()->call_target();

  Address wrapper = Builtins::EntryOf(Builtin::kWasmToJsWrapperAsm, isolate);
  return isolate->heap()->ToBoolean(call_target == wrapper);
}

RUNTIME_FUNCTION(Runtime_HasUnoptimizedJSToJSWrapper) {
  HandleScope shs(isolate);
  if (args.length() != 1) {
    return CrashUnlessFuzzing(isolate);
  }
  Handle<Object> param = args.at<Object>(0);
  if (!WasmJSFunction::IsWasmJSFunction(*param)) {
    return isolate->heap()->ToBoolean(false);
  }
  auto wasm_js_function = Cast<WasmJSFunction>(param);
  DirectHandle<WasmJSFunctionData> function_data(
      wasm_js_function->shared()->wasm_js_function_data(), isolate);

  DirectHandle<JSFunction> external_function =
      WasmInternalFunction::GetOrCreateExternal(
          handle(function_data->internal(), isolate));
  DirectHandle<Code> external_function_code(external_function->code(isolate),
                                            isolate);
  DirectHandle<Code> function_data_code(function_data->wrapper_code(isolate),
                                        isolate);
  Tagged<Code> wrapper = isolate->builtins()->code(Builtin::kJSToJSWrapper);
  // TODO(saelo): we have to use full pointer comparison here until all Code
  // objects are located in trusted space. Currently, builtin Code objects are
  // still inside the main pointer compression cage.
  static_assert(!kAllCodeObjectsLiveInTrustedSpace);
  if (!wrapper.SafeEquals(*external_function_code)) {
    return isolate->heap()->ToBoolean(false);
  }
  if (wrapper != *function_data_code) {
    return isolate->heap()->ToBoolean(false);
  }

  return isolate->heap()->ToBoolean(true);
}

RUNTIME_FUNCTION(Runtime_WasmTraceEnter) {
  HandleScope shs(isolate);
  // This isn't exposed to fuzzers so doesn't need to handle invalid arguments.
  DCHECK_EQ(0, args.length());
  PrintIndentation(WasmStackSize(isolate));

  // Find the caller wasm frame.
  wasm::WasmCodeRefScope wasm_code_ref_scope;
  DebuggableStackFrameIterator it(isolate);
  DCHECK(!it.done());
  DCHECK(it.is_wasm());
#if V8_ENABLE_DRUMBRAKE
  DCHECK(!it.is_wasm_interpreter_entry());
#endif  // V8_ENABLE_DRUMBRAKE
  WasmFrame* frame = WasmFrame::cast(it.frame());

  // Find the function name.
  int func_index = frame->function_index();
  const wasm::WasmModule* module = frame->trusted_instance_data()->module();
  wasm::ModuleWireBytes wire_bytes =
      wasm::ModuleWireBytes(frame->native_module()->wire_bytes());
  wasm::WireBytesRef name_ref =
      module->lazily_generated_names.LookupFunctionName(wire_bytes, func_index);
  wasm::WasmName name = wire_bytes.GetNameOrNull(name_ref);

  wasm::WasmCode* code = frame->wasm_code();
  PrintF(code->is_liftoff() ? "~" : "*");

  if (name.empty()) {
    PrintF("wasm-function[%d] {\n", func_index);
  } else {
    PrintF("wasm-function[%d] \"%.*s\" {\n", func_index, name.length(),
           name.begin());
  }

  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_WasmTraceExit) {
  HandleScope shs(isolate);
  // This isn't exposed to fuzzers so doesn't need to handle invalid arguments.
  DCHECK_EQ(1, args.length());
  Tagged<Smi> return_addr_smi = Cast<Smi>(args[0]);

  PrintIndentation(WasmStackSize(isolate));
  PrintF("}");

  // Find the caller wasm frame.
  wasm::WasmCodeRefScope wasm_code_ref_scope;
  DebuggableStackFrameIterator it(isolate);
  DCHECK(!it.done());
  DCHECK(it.is_wasm());
#if V8_ENABLE_DRUMBRAKE
  DCHECK(!it.is_wasm_interpreter_entry());
#endif  // V8_ENABLE_DRUMBRAKE
  WasmFrame* frame = WasmFrame::cast(it.frame());
  int func_index = frame->function_index();
  const wasm::WasmModule* module = frame->trusted_instance_data()->module();
  const wasm::FunctionSig* sig = module->functions[func_index].sig;

  size_t num_returns = sig->return_count();
  // If we have no returns, we should have passed {Smi::zero()}.
  DCHECK_IMPLIES(num_returns == 0, IsZero(return_addr_smi));
  if (num_returns == 1) {
    wasm::ValueType return_type = sig->GetReturn(0);
    switch (return_type.kind()) {
      case wasm::kI32: {
        int32_t value =
            base::ReadUnalignedValue<int32_t>(return_addr_smi.ptr());
        PrintF(" -> %d\n", value);
        break;
      }
      case wasm::kI64: {
        int64_t value =
            base::ReadUnalignedValue<int64_t>(return_addr_smi.ptr());
        PrintF(" -> %" PRId64 "\n", value);
        break;
      }
      case wasm::kF32: {
        float value = base::ReadUnalignedValue<float>(return_addr_smi.ptr());
        PrintF(" -> %f\n", value);
        break;
      }
      case wasm::kF64: {
        double value = base::ReadUnalignedValue<double>(return_addr_smi.ptr());
        PrintF(" -> %f\n", value);
        break;
      }
      default:
        PrintF(" -> Unsupported type\n");
        break;
    }
  } else {
    // TODO(wasm) Handle multiple return values.
    PrintF("\n");
  }

  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_IsAsmWasmCode) {
  SealHandleScope shs(isolate);
  if (args.length() != 1 || !IsJSFunction(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  auto function = Cast<JSFunction>(args[0]);
  if (!function->shared()->HasAsmWasmData()) {
    return ReadOnlyRoots(isolate).false_value();
  }
  if (function->shared()->HasBuiltinId() &&
      function->shared()->builtin_id() == Builtin::kInstantiateAsmJs) {
    // Hasn't been compiled yet.
    return ReadOnlyRoots(isolate).false_value();
  }
  return ReadOnlyRoots(isolate).true_value();
}

namespace {

bool DisallowWasmCodegenFromStringsCallback(v8::Local<v8::Context> context,
                                            v8::Local<v8::String> source) {
  return false;
}

}  // namespace

RUNTIME_FUNCTION(Runtime_DisallowWasmCodegen) {
  SealHandleScope shs(isolate);
  if (args.length() != 1 || !IsBoolean(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  bool flag = Cast<Boolean>(args[0])->ToBool(isolate);
  v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate);
  v8_isolate->SetAllowWasmCodeGenerationCallback(
      flag ? DisallowWasmCodegenFromStringsCallback : nullptr);
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_IsWasmCode) {
  SealHandleScope shs(isolate);
  if (args.length() != 1 || !IsJSFunction(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  auto function = Cast<JSFunction>(args[0]);
  Tagged<Code> code = function->code(isolate);
  bool is_js_to_wasm = code->kind() == CodeKind::JS_TO_WASM_FUNCTION ||
                       (code->builtin_id() == Builtin::kJSToWasmWrapper);
#if V8_ENABLE_DRUMBRAKE
  // TODO(paolosev@microsoft.com) - Implement an empty
  // GenericJSToWasmInterpreterWrapper also when V8_ENABLE_DRUMBRAKE is not
  // defined to get rid of these #ifdefs.
  is_js_to_wasm =
      is_js_to_wasm ||
      (code->builtin_id() == Builtin::kGenericJSToWasmInterpreterWrapper);
#endif  // V8_ENABLE_DRUMBRAKE
  return isolate->heap()->ToBoolean(is_js_to_wasm);
}

RUNTIME_FUNCTION(Runtime_IsWasmTrapHandlerEnabled) {
  DisallowGarbageCollection no_gc;
  return isolate->heap()->ToBoolean(trap_handler::IsTrapHandlerEnabled());
}

RUNTIME_FUNCTION(Runtime_IsWasmPartialOOBWriteNoop) {
  DisallowGarbageCollection no_gc;
  return isolate->heap()->ToBoolean(wasm::kPartialOOBWritesAreNoops);
}

RUNTIME_FUNCTION(Runtime_IsThreadInWasm) {
  DisallowGarbageCollection no_gc;
  return isolate->heap()->ToBoolean(trap_handler::IsThreadInWasm());
}

RUNTIME_FUNCTION(Runtime_GetWasmRecoveredTrapCount) {
  HandleScope scope(isolate);
  size_t trap_count = trap_handler::GetRecoveredTrapCount();
  return *isolate->factory()->NewNumberFromSize(trap_count);
}

RUNTIME_FUNCTION(Runtime_GetWasmExceptionTagId) {
  HandleScope scope(isolate);
  if (args.length() != 2 || !IsWasmExceptionPackage(args[0]) ||
      !IsWasmInstanceObject(args[1]) ||
      !args.at<WasmInstanceObject>(1)
           ->trusted_data(isolate)
           ->has_tags_table()) {
    return CrashUnlessFuzzing(isolate);
  }
  Handle<WasmExceptionPackage> exception = args.at<WasmExceptionPackage>(0);
  DirectHandle<WasmInstanceObject> instance_object =
      args.at<WasmInstanceObject>(1);
  DirectHandle<WasmTrustedInstanceData> trusted_data(
      instance_object->trusted_data(isolate), isolate);
  DirectHandle<Object> tag =
      WasmExceptionPackage::GetExceptionTag(isolate, exception);
  CHECK(IsWasmExceptionTag(*tag));
  DirectHandle<FixedArray> tags_table(trusted_data->tags_table(), isolate);
  for (int index = 0; index < tags_table->length(); ++index) {
    if (tags_table->get(index) == *tag) return Smi::FromInt(index);
  }
  return CrashUnlessFuzzing(isolate);
}

RUNTIME_FUNCTION(Runtime_GetWasmExceptionValues) {
  HandleScope scope(isolate);
  if (args.length() != 1 || !IsWasmExceptionPackage(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  Handle<WasmExceptionPackage> exception = args.at<WasmExceptionPackage>(0);
  Handle<Object> values_obj =
      WasmExceptionPackage::GetExceptionValues(isolate, exception);
  if (!IsFixedArray(*values_obj)) {
    // Only called with correct input (unless fuzzing).
    return CrashUnlessFuzzing(isolate);
  }
  auto values = Cast<FixedArray>(values_obj);
  DirectHandle<FixedArray> externalized_values =
      isolate->factory()->NewFixedArray(values->length());
  for (int i = 0; i < values->length(); i++) {
    Handle<Object> value(values->get(i), isolate);
    if (!IsSmi(*value)) {
      // Note: This will leak string views to JS. This should be fine for a
      // debugging function.
      value = wasm::WasmToJSObject(isolate, value);
    }
    externalized_values->set(i, *value);
  }
  return *isolate->factory()->NewJSArrayWithElements(externalized_values);
}

RUNTIME_FUNCTION(Runtime_SerializeWasmModule) {
  HandleScope scope(isolate);
  if (args.length() != 1 || !IsWasmModuleObject(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  DirectHandle<WasmModuleObject> module_obj = args.at<WasmModuleObject>(0);

  wasm::NativeModule* native_module = module_obj->native_module();
  DCHECK(!native_module->compilation_state()->failed());

  wasm::WasmSerializer wasm_serializer(native_module);
  size_t byte_length = wasm_serializer.GetSerializedNativeModuleSize();

  DirectHandle<JSArrayBuffer> array_buffer =
      isolate->factory()
          ->NewJSArrayBufferAndBackingStore(byte_length,
                                            InitializedFlag::kUninitialized)
          .ToHandleChecked();

  bool serialized_successfully = wasm_serializer.SerializeNativeModule(
      {static_cast<uint8_t*>(array_buffer->backing_store()), byte_length});
  CHECK(serialized_successfully || v8_flags.fuzzing);
  return *array_buffer;
}

// Take an array buffer and attempt to reconstruct a compiled wasm module.
// Return undefined if unsuccessful.
RUNTIME_FUNCTION(Runtime_DeserializeWasmModule) {
  HandleScope scope(isolate);
  // This isn't exposed to fuzzers so doesn't need to handle invalid arguments.
  CHECK_EQ(2, args.length());
  CHECK(IsJSArrayBuffer(args[0]));
  CHECK(IsJSTypedArray(args[1]));

  DirectHandle<JSArrayBuffer> buffer = args.at<JSArrayBuffer>(0);
  DirectHandle<JSTypedArray> wire_bytes = args.at<JSTypedArray>(1);
  CHECK(!buffer->was_detached());
  CHECK(!wire_bytes->WasDetached());

  DirectHandle<JSArrayBuffer> wire_bytes_buffer = wire_bytes->GetBuffer();
  base::Vector<const uint8_t> wire_bytes_vec{
      reinterpret_cast<const uint8_t*>(wire_bytes_buffer->backing_store()) +
          wire_bytes->byte_offset(),
      wire_bytes->byte_length()};
  base::Vector<uint8_t> buffer_vec{
      reinterpret_cast<uint8_t*>(buffer->backing_store()),
      buffer->byte_length()};

  // Note that {wasm::DeserializeNativeModule} will allocate. We assume the
  // JSArrayBuffer backing store doesn't get relocated.
  wasm::CompileTimeImports compile_imports{};
  MaybeHandle<WasmModuleObject> maybe_module_object =
      wasm::DeserializeNativeModule(isolate, buffer_vec, wire_bytes_vec,
                                    compile_imports, {});
  Handle<WasmModuleObject> module_object;
  if (!maybe_module_object.ToHandle(&module_object)) {
    return ReadOnlyRoots(isolate).undefined_value();
  }
  return *module_object;
}

RUNTIME_FUNCTION(Runtime_WasmGetNumberOfInstances) {
  SealHandleScope shs(isolate);
  if (args.length() != 1 || !IsWasmModuleObject(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  DirectHandle<WasmModuleObject> module_obj = args.at<WasmModuleObject>(0);
  int instance_count = 0;
  Tagged<WeakArrayList> weak_instance_list =
      module_obj->script()->wasm_weak_instance_list();
  for (int i = 0; i < weak_instance_list->length(); ++i) {
    if (weak_instance_list->Get(i).IsWeak()) instance_count++;
  }
  return Smi::FromInt(instance_count);
}

RUNTIME_FUNCTION(Runtime_WasmNumCodeSpaces) {
  HandleScope scope(isolate);
  if (args.length() != 1 || !IsJSObject(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  DirectHandle<JSObject> argument = args.at<JSObject>(0);
  wasm::NativeModule* native_module;
  if (IsWasmInstanceObject(*argument)) {
    native_module = Cast<WasmInstanceObject>(*argument)
                        ->trusted_data(isolate)
                        ->native_module();
  } else if (IsWasmModuleObject(*argument)) {
    native_module = Cast<WasmModuleObject>(*argument)->native_module();
  } else {
    return CrashUnlessFuzzing(isolate);
  }
  size_t num_spaces = native_module->GetNumberOfCodeSpacesForTesting();
  return *isolate->factory()->NewNumberFromSize(num_spaces);
}

namespace {

template <typename T1, typename T2 = T1>
void PrintRep(Address address, const char* str) {
  PrintF("%4s:", str);
  const auto t1 = base::ReadLittleEndianValue<T1>(address);
  if constexpr (std::is_floating_point_v<T1>) {
    PrintF("%f", t1);
  } else if constexpr (sizeof(T1) > sizeof(uint32_t)) {
    PrintF("%" PRIu64, t1);
  } else {
    PrintF("%u", t1);
  }
  const auto t2 = base::ReadLittleEndianValue<T2>(address);
  if constexpr (sizeof(T1) > sizeof(uint32_t)) {
    PrintF(" / %016" PRIx64 "\n", t2);
  } else {
    PrintF(" / %0*x\n", static_cast<int>(2 * sizeof(T2)), t2);
  }
}

}  // namespace

RUNTIME_FUNCTION(Runtime_WasmTraceMemory) {
  SealHandleScope scope(isolate);
  if (args.length() != 1 || !IsSmi(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  DisallowGarbageCollection no_gc;
  auto info_addr = Cast<Smi>(args[0]);

  wasm::MemoryTracingInfo* info =
      reinterpret_cast<wasm::MemoryTracingInfo*>(info_addr.ptr());

  // Find the caller wasm frame.
  wasm::WasmCodeRefScope wasm_code_ref_scope;
  DebuggableStackFrameIterator it(isolate);
  DCHECK(!it.done());
  DCHECK(it.is_wasm());
#if V8_ENABLE_DRUMBRAKE
  DCHECK(!it.is_wasm_interpreter_entry());
#endif  // V8_ENABLE_DRUMBRAKE
  WasmFrame* frame = WasmFrame::cast(it.frame());

  PrintF("%-11s func:%6d:0x%-4x %s %016" PRIuPTR " val: ",
         ExecutionTierToString(frame->wasm_code()->is_liftoff()
                                   ? wasm::ExecutionTier::kLiftoff
                                   : wasm::ExecutionTier::kTurbofan),
         frame->function_index(), frame->position(),
         // Note: The extra leading space makes " store to" the same width as
         // "load from".
         info->is_store ? " store to" : "load from", info->offset);
  // TODO(14259): Fix for multi-memory.
  const Address address =
      reinterpret_cast<Address>(frame->trusted_instance_data()
                                    ->memory_object(0)
                                    ->array_buffer()
                                    ->backing_store()) +
      info->offset;
  switch (static_cast<MachineRepresentation>(info->mem_rep)) {
    case MachineRepresentation::kWord8:
      PrintRep<uint8_t>(address, "i8");
      break;
    case MachineRepresentation::kWord16:
      PrintRep<uint16_t>(address, "i16");
      break;
    case MachineRepresentation::kWord32:
      PrintRep<uint32_t>(address, "i32");
      break;
    case MachineRepresentation::kWord64:
      PrintRep<uint64_t>(address, "i64");
      break
### 提示词
```
这是目录为v8/src/runtime/runtime-test-wasm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/runtime/runtime-test-wasm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cinttypes>
#include <type_traits>

#include "include/v8-wasm.h"
#include "src/base/memory.h"
#include "src/base/platform/mutex.h"
#include "src/builtins/builtins-inl.h"
#include "src/execution/arguments-inl.h"
#include "src/execution/frames-inl.h"
#include "src/heap/heap-inl.h"
#include "src/objects/property-descriptor.h"
#include "src/objects/smi.h"
#include "src/trap-handler/trap-handler.h"
#include "src/wasm/function-body-decoder.h"
#include "src/wasm/fuzzing/random-module-generation.h"
#include "src/wasm/memory-tracing.h"
#include "src/wasm/module-compiler.h"
#include "src/wasm/wasm-code-manager.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-objects-inl.h"
#include "src/wasm/wasm-result.h"
#include "src/wasm/wasm-serialization.h"

namespace v8::internal {

namespace {
V8_WARN_UNUSED_RESULT Tagged<Object> CrashUnlessFuzzing(Isolate* isolate) {
  CHECK(v8_flags.fuzzing);
  return ReadOnlyRoots(isolate).undefined_value();
}

struct WasmCompileControls {
  uint32_t MaxWasmBufferSize = std::numeric_limits<uint32_t>::max();
  bool AllowAnySizeForAsync = true;
};
using WasmCompileControlsMap = std::map<v8::Isolate*, WasmCompileControls>;

// We need per-isolate controls, because we sometimes run tests in multiple
// isolates concurrently. Methods need to hold the accompanying mutex on access.
// To avoid upsetting the static initializer count, we lazy initialize this.
DEFINE_LAZY_LEAKY_OBJECT_GETTER(WasmCompileControlsMap,
                                GetPerIsolateWasmControls)
base::LazyMutex g_PerIsolateWasmControlsMutex = LAZY_MUTEX_INITIALIZER;

bool IsWasmCompileAllowed(v8::Isolate* isolate, v8::Local<v8::Value> value,
                          bool is_async) {
  base::MutexGuard guard(g_PerIsolateWasmControlsMutex.Pointer());
  DCHECK_GT(GetPerIsolateWasmControls()->count(isolate), 0);
  const WasmCompileControls& ctrls = GetPerIsolateWasmControls()->at(isolate);
  return (is_async && ctrls.AllowAnySizeForAsync) ||
         (value->IsArrayBuffer() && value.As<v8::ArrayBuffer>()->ByteLength() <=
                                        ctrls.MaxWasmBufferSize) ||
         (value->IsArrayBufferView() &&
          value.As<v8::ArrayBufferView>()->ByteLength() <=
              ctrls.MaxWasmBufferSize);
}

// Use the compile controls for instantiation, too
bool IsWasmInstantiateAllowed(v8::Isolate* isolate,
                              v8::Local<v8::Value> module_or_bytes,
                              bool is_async) {
  base::MutexGuard guard(g_PerIsolateWasmControlsMutex.Pointer());
  DCHECK_GT(GetPerIsolateWasmControls()->count(isolate), 0);
  const WasmCompileControls& ctrls = GetPerIsolateWasmControls()->at(isolate);
  if (is_async && ctrls.AllowAnySizeForAsync) return true;
  if (!module_or_bytes->IsWasmModuleObject()) {
    return IsWasmCompileAllowed(isolate, module_or_bytes, is_async);
  }
  v8::Local<v8::WasmModuleObject> module =
      v8::Local<v8::WasmModuleObject>::Cast(module_or_bytes);
  return static_cast<uint32_t>(
             module->GetCompiledModule().GetWireBytesRef().size()) <=
         ctrls.MaxWasmBufferSize;
}

v8::Local<v8::Value> NewRangeException(v8::Isolate* isolate,
                                       const char* message) {
  return v8::Exception::RangeError(
      v8::String::NewFromOneByte(isolate,
                                 reinterpret_cast<const uint8_t*>(message))
          .ToLocalChecked());
}

void ThrowRangeException(v8::Isolate* isolate, const char* message) {
  isolate->ThrowException(NewRangeException(isolate, message));
}

bool WasmModuleOverride(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(ValidateCallbackInfo(info));
  if (IsWasmCompileAllowed(info.GetIsolate(), info[0], false)) return false;
  ThrowRangeException(info.GetIsolate(), "Sync compile not allowed");
  return true;
}

bool WasmInstanceOverride(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(ValidateCallbackInfo(info));
  if (IsWasmInstantiateAllowed(info.GetIsolate(), info[0], false)) return false;
  ThrowRangeException(info.GetIsolate(), "Sync instantiate not allowed");
  return true;
}

}  // namespace

// Returns a callable object. The object returns the difference of its two
// parameters when it is called.
RUNTIME_FUNCTION(Runtime_SetWasmCompileControls) {
  HandleScope scope(isolate);
  if (args.length() != 2 || !IsSmi(args[0]) || !IsBoolean(args[1])) {
    return CrashUnlessFuzzing(isolate);
  }
  v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate);
  int block_size = args.smi_value_at(0);
  bool allow_async = Cast<Boolean>(args[1])->ToBool(isolate);
  base::MutexGuard guard(g_PerIsolateWasmControlsMutex.Pointer());
  WasmCompileControls& ctrl = (*GetPerIsolateWasmControls())[v8_isolate];
  ctrl.AllowAnySizeForAsync = allow_async;
  ctrl.MaxWasmBufferSize = static_cast<uint32_t>(block_size);
  v8_isolate->SetWasmModuleCallback(WasmModuleOverride);
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_SetWasmInstantiateControls) {
  HandleScope scope(isolate);
  v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate);
  v8_isolate->SetWasmInstanceCallback(WasmInstanceOverride);
  return ReadOnlyRoots(isolate).undefined_value();
}

namespace {

void PrintIndentation(int stack_size) {
  const int max_display = 80;
  if (stack_size <= max_display) {
    PrintF("%4d:%*s", stack_size, stack_size, "");
  } else {
    PrintF("%4d:%*s", stack_size, max_display, "...");
  }
}

int WasmStackSize(Isolate* isolate) {
  // TODO(wasm): Fix this for mixed JS/Wasm stacks with both --trace and
  // --trace-wasm.
  int n = 0;
  for (DebuggableStackFrameIterator it(isolate); !it.done(); it.Advance()) {
    if (it.is_wasm()) n++;
  }
  return n;
}

}  // namespace

RUNTIME_FUNCTION(Runtime_CountUnoptimizedWasmToJSWrapper) {
  SealHandleScope shs(isolate);
  if (args.length() != 1 || !IsWasmInstanceObject(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  Tagged<WasmInstanceObject> instance_object =
      Cast<WasmInstanceObject>(args[0]);
  Tagged<WasmTrustedInstanceData> trusted_data =
      instance_object->trusted_data(isolate);
  Address wrapper_start = isolate->builtins()
                              ->code(Builtin::kWasmToJsWrapperAsm)
                              ->instruction_start();
  int result = 0;
  Tagged<WasmDispatchTable> dispatch_table =
      trusted_data->dispatch_table_for_imports();
  int import_count = dispatch_table->length();
  for (int i = 0; i < import_count; ++i) {
    if (dispatch_table->target(i) == wrapper_start) {
      ++result;
    }
  }
  Tagged<ProtectedFixedArray> dispatch_tables = trusted_data->dispatch_tables();
  int table_count = dispatch_tables->length();
  for (int table_index = 0; table_index < table_count; ++table_index) {
    if (dispatch_tables->get(table_index) == Smi::zero()) continue;
    Tagged<WasmDispatchTable> table =
        Cast<WasmDispatchTable>(dispatch_tables->get(table_index));
    int table_size = table->length();
    for (int entry_index = 0; entry_index < table_size; ++entry_index) {
      if (table->target(entry_index) == wrapper_start) ++result;
    }
  }
  return Smi::FromInt(result);
}

RUNTIME_FUNCTION(Runtime_HasUnoptimizedWasmToJSWrapper) {
  SealHandleScope shs{isolate};
  if (args.length() != 1 || !IsJSFunction(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  Tagged<JSFunction> function = Cast<JSFunction>(args[0]);
  Tagged<SharedFunctionInfo> sfi = function->shared();
  if (!sfi->HasWasmFunctionData()) return isolate->heap()->ToBoolean(false);
  Tagged<WasmFunctionData> func_data = sfi->wasm_function_data();
  Address call_target = func_data->internal()->call_target();

  Address wrapper = Builtins::EntryOf(Builtin::kWasmToJsWrapperAsm, isolate);
  return isolate->heap()->ToBoolean(call_target == wrapper);
}

RUNTIME_FUNCTION(Runtime_HasUnoptimizedJSToJSWrapper) {
  HandleScope shs(isolate);
  if (args.length() != 1) {
    return CrashUnlessFuzzing(isolate);
  }
  Handle<Object> param = args.at<Object>(0);
  if (!WasmJSFunction::IsWasmJSFunction(*param)) {
    return isolate->heap()->ToBoolean(false);
  }
  auto wasm_js_function = Cast<WasmJSFunction>(param);
  DirectHandle<WasmJSFunctionData> function_data(
      wasm_js_function->shared()->wasm_js_function_data(), isolate);

  DirectHandle<JSFunction> external_function =
      WasmInternalFunction::GetOrCreateExternal(
          handle(function_data->internal(), isolate));
  DirectHandle<Code> external_function_code(external_function->code(isolate),
                                            isolate);
  DirectHandle<Code> function_data_code(function_data->wrapper_code(isolate),
                                        isolate);
  Tagged<Code> wrapper = isolate->builtins()->code(Builtin::kJSToJSWrapper);
  // TODO(saelo): we have to use full pointer comparison here until all Code
  // objects are located in trusted space. Currently, builtin Code objects are
  // still inside the main pointer compression cage.
  static_assert(!kAllCodeObjectsLiveInTrustedSpace);
  if (!wrapper.SafeEquals(*external_function_code)) {
    return isolate->heap()->ToBoolean(false);
  }
  if (wrapper != *function_data_code) {
    return isolate->heap()->ToBoolean(false);
  }

  return isolate->heap()->ToBoolean(true);
}

RUNTIME_FUNCTION(Runtime_WasmTraceEnter) {
  HandleScope shs(isolate);
  // This isn't exposed to fuzzers so doesn't need to handle invalid arguments.
  DCHECK_EQ(0, args.length());
  PrintIndentation(WasmStackSize(isolate));

  // Find the caller wasm frame.
  wasm::WasmCodeRefScope wasm_code_ref_scope;
  DebuggableStackFrameIterator it(isolate);
  DCHECK(!it.done());
  DCHECK(it.is_wasm());
#if V8_ENABLE_DRUMBRAKE
  DCHECK(!it.is_wasm_interpreter_entry());
#endif  // V8_ENABLE_DRUMBRAKE
  WasmFrame* frame = WasmFrame::cast(it.frame());

  // Find the function name.
  int func_index = frame->function_index();
  const wasm::WasmModule* module = frame->trusted_instance_data()->module();
  wasm::ModuleWireBytes wire_bytes =
      wasm::ModuleWireBytes(frame->native_module()->wire_bytes());
  wasm::WireBytesRef name_ref =
      module->lazily_generated_names.LookupFunctionName(wire_bytes, func_index);
  wasm::WasmName name = wire_bytes.GetNameOrNull(name_ref);

  wasm::WasmCode* code = frame->wasm_code();
  PrintF(code->is_liftoff() ? "~" : "*");

  if (name.empty()) {
    PrintF("wasm-function[%d] {\n", func_index);
  } else {
    PrintF("wasm-function[%d] \"%.*s\" {\n", func_index, name.length(),
           name.begin());
  }

  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_WasmTraceExit) {
  HandleScope shs(isolate);
  // This isn't exposed to fuzzers so doesn't need to handle invalid arguments.
  DCHECK_EQ(1, args.length());
  Tagged<Smi> return_addr_smi = Cast<Smi>(args[0]);

  PrintIndentation(WasmStackSize(isolate));
  PrintF("}");

  // Find the caller wasm frame.
  wasm::WasmCodeRefScope wasm_code_ref_scope;
  DebuggableStackFrameIterator it(isolate);
  DCHECK(!it.done());
  DCHECK(it.is_wasm());
#if V8_ENABLE_DRUMBRAKE
  DCHECK(!it.is_wasm_interpreter_entry());
#endif  // V8_ENABLE_DRUMBRAKE
  WasmFrame* frame = WasmFrame::cast(it.frame());
  int func_index = frame->function_index();
  const wasm::WasmModule* module = frame->trusted_instance_data()->module();
  const wasm::FunctionSig* sig = module->functions[func_index].sig;

  size_t num_returns = sig->return_count();
  // If we have no returns, we should have passed {Smi::zero()}.
  DCHECK_IMPLIES(num_returns == 0, IsZero(return_addr_smi));
  if (num_returns == 1) {
    wasm::ValueType return_type = sig->GetReturn(0);
    switch (return_type.kind()) {
      case wasm::kI32: {
        int32_t value =
            base::ReadUnalignedValue<int32_t>(return_addr_smi.ptr());
        PrintF(" -> %d\n", value);
        break;
      }
      case wasm::kI64: {
        int64_t value =
            base::ReadUnalignedValue<int64_t>(return_addr_smi.ptr());
        PrintF(" -> %" PRId64 "\n", value);
        break;
      }
      case wasm::kF32: {
        float value = base::ReadUnalignedValue<float>(return_addr_smi.ptr());
        PrintF(" -> %f\n", value);
        break;
      }
      case wasm::kF64: {
        double value = base::ReadUnalignedValue<double>(return_addr_smi.ptr());
        PrintF(" -> %f\n", value);
        break;
      }
      default:
        PrintF(" -> Unsupported type\n");
        break;
    }
  } else {
    // TODO(wasm) Handle multiple return values.
    PrintF("\n");
  }

  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_IsAsmWasmCode) {
  SealHandleScope shs(isolate);
  if (args.length() != 1 || !IsJSFunction(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  auto function = Cast<JSFunction>(args[0]);
  if (!function->shared()->HasAsmWasmData()) {
    return ReadOnlyRoots(isolate).false_value();
  }
  if (function->shared()->HasBuiltinId() &&
      function->shared()->builtin_id() == Builtin::kInstantiateAsmJs) {
    // Hasn't been compiled yet.
    return ReadOnlyRoots(isolate).false_value();
  }
  return ReadOnlyRoots(isolate).true_value();
}

namespace {

bool DisallowWasmCodegenFromStringsCallback(v8::Local<v8::Context> context,
                                            v8::Local<v8::String> source) {
  return false;
}

}  // namespace

RUNTIME_FUNCTION(Runtime_DisallowWasmCodegen) {
  SealHandleScope shs(isolate);
  if (args.length() != 1 || !IsBoolean(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  bool flag = Cast<Boolean>(args[0])->ToBool(isolate);
  v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate);
  v8_isolate->SetAllowWasmCodeGenerationCallback(
      flag ? DisallowWasmCodegenFromStringsCallback : nullptr);
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_IsWasmCode) {
  SealHandleScope shs(isolate);
  if (args.length() != 1 || !IsJSFunction(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  auto function = Cast<JSFunction>(args[0]);
  Tagged<Code> code = function->code(isolate);
  bool is_js_to_wasm = code->kind() == CodeKind::JS_TO_WASM_FUNCTION ||
                       (code->builtin_id() == Builtin::kJSToWasmWrapper);
#if V8_ENABLE_DRUMBRAKE
  // TODO(paolosev@microsoft.com) - Implement an empty
  // GenericJSToWasmInterpreterWrapper also when V8_ENABLE_DRUMBRAKE is not
  // defined to get rid of these #ifdefs.
  is_js_to_wasm =
      is_js_to_wasm ||
      (code->builtin_id() == Builtin::kGenericJSToWasmInterpreterWrapper);
#endif  // V8_ENABLE_DRUMBRAKE
  return isolate->heap()->ToBoolean(is_js_to_wasm);
}

RUNTIME_FUNCTION(Runtime_IsWasmTrapHandlerEnabled) {
  DisallowGarbageCollection no_gc;
  return isolate->heap()->ToBoolean(trap_handler::IsTrapHandlerEnabled());
}

RUNTIME_FUNCTION(Runtime_IsWasmPartialOOBWriteNoop) {
  DisallowGarbageCollection no_gc;
  return isolate->heap()->ToBoolean(wasm::kPartialOOBWritesAreNoops);
}

RUNTIME_FUNCTION(Runtime_IsThreadInWasm) {
  DisallowGarbageCollection no_gc;
  return isolate->heap()->ToBoolean(trap_handler::IsThreadInWasm());
}

RUNTIME_FUNCTION(Runtime_GetWasmRecoveredTrapCount) {
  HandleScope scope(isolate);
  size_t trap_count = trap_handler::GetRecoveredTrapCount();
  return *isolate->factory()->NewNumberFromSize(trap_count);
}

RUNTIME_FUNCTION(Runtime_GetWasmExceptionTagId) {
  HandleScope scope(isolate);
  if (args.length() != 2 || !IsWasmExceptionPackage(args[0]) ||
      !IsWasmInstanceObject(args[1]) ||
      !args.at<WasmInstanceObject>(1)
           ->trusted_data(isolate)
           ->has_tags_table()) {
    return CrashUnlessFuzzing(isolate);
  }
  Handle<WasmExceptionPackage> exception = args.at<WasmExceptionPackage>(0);
  DirectHandle<WasmInstanceObject> instance_object =
      args.at<WasmInstanceObject>(1);
  DirectHandle<WasmTrustedInstanceData> trusted_data(
      instance_object->trusted_data(isolate), isolate);
  DirectHandle<Object> tag =
      WasmExceptionPackage::GetExceptionTag(isolate, exception);
  CHECK(IsWasmExceptionTag(*tag));
  DirectHandle<FixedArray> tags_table(trusted_data->tags_table(), isolate);
  for (int index = 0; index < tags_table->length(); ++index) {
    if (tags_table->get(index) == *tag) return Smi::FromInt(index);
  }
  return CrashUnlessFuzzing(isolate);
}

RUNTIME_FUNCTION(Runtime_GetWasmExceptionValues) {
  HandleScope scope(isolate);
  if (args.length() != 1 || !IsWasmExceptionPackage(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  Handle<WasmExceptionPackage> exception = args.at<WasmExceptionPackage>(0);
  Handle<Object> values_obj =
      WasmExceptionPackage::GetExceptionValues(isolate, exception);
  if (!IsFixedArray(*values_obj)) {
    // Only called with correct input (unless fuzzing).
    return CrashUnlessFuzzing(isolate);
  }
  auto values = Cast<FixedArray>(values_obj);
  DirectHandle<FixedArray> externalized_values =
      isolate->factory()->NewFixedArray(values->length());
  for (int i = 0; i < values->length(); i++) {
    Handle<Object> value(values->get(i), isolate);
    if (!IsSmi(*value)) {
      // Note: This will leak string views to JS. This should be fine for a
      // debugging function.
      value = wasm::WasmToJSObject(isolate, value);
    }
    externalized_values->set(i, *value);
  }
  return *isolate->factory()->NewJSArrayWithElements(externalized_values);
}

RUNTIME_FUNCTION(Runtime_SerializeWasmModule) {
  HandleScope scope(isolate);
  if (args.length() != 1 || !IsWasmModuleObject(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  DirectHandle<WasmModuleObject> module_obj = args.at<WasmModuleObject>(0);

  wasm::NativeModule* native_module = module_obj->native_module();
  DCHECK(!native_module->compilation_state()->failed());

  wasm::WasmSerializer wasm_serializer(native_module);
  size_t byte_length = wasm_serializer.GetSerializedNativeModuleSize();

  DirectHandle<JSArrayBuffer> array_buffer =
      isolate->factory()
          ->NewJSArrayBufferAndBackingStore(byte_length,
                                            InitializedFlag::kUninitialized)
          .ToHandleChecked();

  bool serialized_successfully = wasm_serializer.SerializeNativeModule(
      {static_cast<uint8_t*>(array_buffer->backing_store()), byte_length});
  CHECK(serialized_successfully || v8_flags.fuzzing);
  return *array_buffer;
}

// Take an array buffer and attempt to reconstruct a compiled wasm module.
// Return undefined if unsuccessful.
RUNTIME_FUNCTION(Runtime_DeserializeWasmModule) {
  HandleScope scope(isolate);
  // This isn't exposed to fuzzers so doesn't need to handle invalid arguments.
  CHECK_EQ(2, args.length());
  CHECK(IsJSArrayBuffer(args[0]));
  CHECK(IsJSTypedArray(args[1]));

  DirectHandle<JSArrayBuffer> buffer = args.at<JSArrayBuffer>(0);
  DirectHandle<JSTypedArray> wire_bytes = args.at<JSTypedArray>(1);
  CHECK(!buffer->was_detached());
  CHECK(!wire_bytes->WasDetached());

  DirectHandle<JSArrayBuffer> wire_bytes_buffer = wire_bytes->GetBuffer();
  base::Vector<const uint8_t> wire_bytes_vec{
      reinterpret_cast<const uint8_t*>(wire_bytes_buffer->backing_store()) +
          wire_bytes->byte_offset(),
      wire_bytes->byte_length()};
  base::Vector<uint8_t> buffer_vec{
      reinterpret_cast<uint8_t*>(buffer->backing_store()),
      buffer->byte_length()};

  // Note that {wasm::DeserializeNativeModule} will allocate. We assume the
  // JSArrayBuffer backing store doesn't get relocated.
  wasm::CompileTimeImports compile_imports{};
  MaybeHandle<WasmModuleObject> maybe_module_object =
      wasm::DeserializeNativeModule(isolate, buffer_vec, wire_bytes_vec,
                                    compile_imports, {});
  Handle<WasmModuleObject> module_object;
  if (!maybe_module_object.ToHandle(&module_object)) {
    return ReadOnlyRoots(isolate).undefined_value();
  }
  return *module_object;
}

RUNTIME_FUNCTION(Runtime_WasmGetNumberOfInstances) {
  SealHandleScope shs(isolate);
  if (args.length() != 1 || !IsWasmModuleObject(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  DirectHandle<WasmModuleObject> module_obj = args.at<WasmModuleObject>(0);
  int instance_count = 0;
  Tagged<WeakArrayList> weak_instance_list =
      module_obj->script()->wasm_weak_instance_list();
  for (int i = 0; i < weak_instance_list->length(); ++i) {
    if (weak_instance_list->Get(i).IsWeak()) instance_count++;
  }
  return Smi::FromInt(instance_count);
}

RUNTIME_FUNCTION(Runtime_WasmNumCodeSpaces) {
  HandleScope scope(isolate);
  if (args.length() != 1 || !IsJSObject(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  DirectHandle<JSObject> argument = args.at<JSObject>(0);
  wasm::NativeModule* native_module;
  if (IsWasmInstanceObject(*argument)) {
    native_module = Cast<WasmInstanceObject>(*argument)
                        ->trusted_data(isolate)
                        ->native_module();
  } else if (IsWasmModuleObject(*argument)) {
    native_module = Cast<WasmModuleObject>(*argument)->native_module();
  } else {
    return CrashUnlessFuzzing(isolate);
  }
  size_t num_spaces = native_module->GetNumberOfCodeSpacesForTesting();
  return *isolate->factory()->NewNumberFromSize(num_spaces);
}

namespace {

template <typename T1, typename T2 = T1>
void PrintRep(Address address, const char* str) {
  PrintF("%4s:", str);
  const auto t1 = base::ReadLittleEndianValue<T1>(address);
  if constexpr (std::is_floating_point_v<T1>) {
    PrintF("%f", t1);
  } else if constexpr (sizeof(T1) > sizeof(uint32_t)) {
    PrintF("%" PRIu64, t1);
  } else {
    PrintF("%u", t1);
  }
  const auto t2 = base::ReadLittleEndianValue<T2>(address);
  if constexpr (sizeof(T1) > sizeof(uint32_t)) {
    PrintF(" / %016" PRIx64 "\n", t2);
  } else {
    PrintF(" / %0*x\n", static_cast<int>(2 * sizeof(T2)), t2);
  }
}

}  // namespace

RUNTIME_FUNCTION(Runtime_WasmTraceMemory) {
  SealHandleScope scope(isolate);
  if (args.length() != 1 || !IsSmi(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  DisallowGarbageCollection no_gc;
  auto info_addr = Cast<Smi>(args[0]);

  wasm::MemoryTracingInfo* info =
      reinterpret_cast<wasm::MemoryTracingInfo*>(info_addr.ptr());

  // Find the caller wasm frame.
  wasm::WasmCodeRefScope wasm_code_ref_scope;
  DebuggableStackFrameIterator it(isolate);
  DCHECK(!it.done());
  DCHECK(it.is_wasm());
#if V8_ENABLE_DRUMBRAKE
  DCHECK(!it.is_wasm_interpreter_entry());
#endif  // V8_ENABLE_DRUMBRAKE
  WasmFrame* frame = WasmFrame::cast(it.frame());

  PrintF("%-11s func:%6d:0x%-4x %s %016" PRIuPTR " val: ",
         ExecutionTierToString(frame->wasm_code()->is_liftoff()
                                   ? wasm::ExecutionTier::kLiftoff
                                   : wasm::ExecutionTier::kTurbofan),
         frame->function_index(), frame->position(),
         // Note: The extra leading space makes " store to" the same width as
         // "load from".
         info->is_store ? " store to" : "load from", info->offset);
  // TODO(14259): Fix for multi-memory.
  const Address address =
      reinterpret_cast<Address>(frame->trusted_instance_data()
                                    ->memory_object(0)
                                    ->array_buffer()
                                    ->backing_store()) +
      info->offset;
  switch (static_cast<MachineRepresentation>(info->mem_rep)) {
    case MachineRepresentation::kWord8:
      PrintRep<uint8_t>(address, "i8");
      break;
    case MachineRepresentation::kWord16:
      PrintRep<uint16_t>(address, "i16");
      break;
    case MachineRepresentation::kWord32:
      PrintRep<uint32_t>(address, "i32");
      break;
    case MachineRepresentation::kWord64:
      PrintRep<uint64_t>(address, "i64");
      break;
    case MachineRepresentation::kFloat32:
      PrintRep<float, uint32_t>(address, "f32");
      break;
    case MachineRepresentation::kFloat64:
      PrintRep<double, uint64_t>(address, "f64");
      break;
    case MachineRepresentation::kSimd128: {
      const auto a = base::ReadLittleEndianValue<uint32_t>(address);
      const auto b = base::ReadLittleEndianValue<uint32_t>(address + 4);
      const auto c = base::ReadLittleEndianValue<uint32_t>(address + 8);
      const auto d = base::ReadLittleEndianValue<uint32_t>(address + 12);
      PrintF("s128:%u %u %u %u / %08x %08x %08x %08x\n", a, b, c, d, a, b, c,
             d);
      break;
    }
    default:
      PrintF("unknown\n");
      break;
  }

  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_WasmTierUpFunction) {
  DCHECK(!v8_flags.wasm_jitless);

  HandleScope scope(isolate);
  if (args.length() != 1 || !IsJSFunction(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  Handle<JSFunction> function = args.at<JSFunction>(0);
  if (!WasmExportedFunction::IsWasmExportedFunction(*function)) {
    return CrashUnlessFuzzing(isolate);
  }
  auto exp_fun = Cast<WasmExportedFunction>(function);
  auto func_data = exp_fun->shared()->wasm_exported_function_data();
  Tagged<WasmTrustedInstanceData> trusted_data = func_data->instance_data();
  int func_index = func_data->function_index();
  const wasm::WasmModule* module = trusted_data->module();
  if (static_cast<uint32_t>(func_index) < module->num_imported_functions) {
    return CrashUnlessFuzzing(isolate);
  }
  if (!module->function_was_validated(func_index)) {
    DCHECK(v8_flags.wasm_lazy_validation);
    Zone validation_zone(isolate->allocator(), ZONE_NAME);
    wasm::WasmDetectedFeatures unused_detected_features;
    const wasm::WasmFunction* func = &module->functions[func_index];
    bool is_shared = module->type(func->sig_index).is_shared;
    base::Vector<const uint8_t> wire_bytes =
        trusted_data->native_module()->wire_bytes();
    wasm::FunctionBody body{func->sig, func->code.offset(),
                            wire_bytes.begin() + func->code.offset(),
                            wire_bytes.begin() + func->code.end_offset(),
                            is_shared};
    if (ValidateFunctionBody(&validation_zone,
                             trusted_data->native_module()->enabled_features(),
                             module, &unused_detected_features, body)
            .failed()) {
      return CrashUnlessFuzzing(isolate);
    }
    module->set_function_validated(func_index);
  }
  wasm::TierUpNowForTesting(isolate, trusted_data, func_index);
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_WasmNull) {
  // This isn't exposed to fuzzers. (Wasm nulls may not appear in JS.)
  HandleScope scope(isolate);
  return ReadOnlyRoots(isolate).wasm_null();
}

static Tagged<Object> CreateWasmObject(Isolate* isolate,
                                       base::Vector<const uint8_t> module_bytes,
                                       bool is_struct) {
  if (module_bytes.size() > v8_flags.wasm_max_module_size) {
    return CrashUnlessFuzzing(isolate);
  }
  // Create and compile the wasm module.
  wasm::ErrorThrower thrower(isolate, "CreateWasmObject");
  wasm::ModuleWireBytes bytes(base::VectorOf(module_bytes));
  wasm::WasmEngine* engine = wasm::GetWasmEngine();
  MaybeHandle<WasmModuleObject> maybe_module_object =
      engine->SyncCompile(isolate, wasm::WasmEnabledFeatures(),
                          wasm::CompileTimeImports(), &thrower, bytes);
  CHECK(!thrower.error());
  Handle<WasmModuleObject> module_object;
  if (!maybe_module_object.ToHandle(&module_object)) {
    DCHECK(isolate->has_exception());
    return ReadOnlyRoots(isolate).exception();
  }
  // Instantiate the module.
  MaybeHandle<WasmInstanceObject> maybe_instance = engine->SyncInstantiate(
      isolate, &thrower, module_object, Handle<JSReceiver>::null(),
      MaybeHandle<JSArrayBuffer>());
  CHECK(!thrower.error());
  Handle<WasmInstanceObject> instance;
  if (!maybe_instance.ToHandle(&instance)) {
    DCHECK(isolate->has_exception());
    return ReadOnlyRoots(isolate).exception();
  }
  wasm::WasmValue value(int64_t{0x7AADF00DBAADF00D});
  wasm::ModuleTypeIndex type_index{0};
  Tagged<Map> map = Tagged<Map>::cast(
      instance->trusted_data(isolate)->managed_object_maps()->get(
          type_index.index));
  if (is_struct) {
    const wasm::StructType* struct_type =
        instance->module()->struct_type(type_index);
    DCHECK_EQ(struct_type->field_count(), 1);
    DCHECK_EQ(struct_type->field(0), wasm::kWasmI64);
    return *isolate->factory()->NewWasmStruct(struct_type, &value,
                                              handle(map, isolate));
  } else {
    DCHECK_EQ(instance->module()->array_type(type_index)->element_type(),
              wasm::kWasmI64);
    return *isolate->factory()->NewWasmArray(wasm::kWasmI64, 1, value,
                                             handle(map, isolate));
  }
}

// In jitless mode we don't support creation of real wasm objects (they require
// a NativeModule and instantiating that is not supported in jitless), so this
// function creates a frozen JS object that should behave the same as a wasm
// object within JS.
static Tagged<Object> CreateDummyWasmLookAlikeForFuzzing(Isolate* isolate) {
  Handle<JSObject> obj = isolate->factory()->NewJSObjectWithNullProto();
  CHECK(IsJSReceiver(*obj));
  MAYBE_RETURN(JSReceiver::SetIntegrityLevel(isolate, Cast<JSReceiver>(obj),
                                             FROZEN, kThrowOnError),
               ReadOnlyRoots(isolate).exception());
  return *obj;
}

// Creates a new wasm struct with one i64 (value 0x7AADF00DBAADF00D).
RUNTIME_FUNCTION(Runtime_WasmStruct) {
  HandleScope scope(isolate);
  if (v8_flags.jitless) {
    return CreateDummyWasmLookAlikeForFuzzing(isolate);
  }
  /* Recreate with:
    d8.file.execute('test/mjsunit/wasm/wasm-module-builder.js');
    let builder = new WasmModuleBuilder();
    let struct = builder.addStruct([makeField(kWasmI64, false)]);
    builder.instantiate();
  */
  static constexpr uint8_t wasm_module_bytes[] = {
      0x00, 0x61, 0x73, 0x6d,  // wasm magic
      0x01, 0x00, 0x00, 0x00,  // wasm version
      0x01,                    // section kind: Type
      0x07,                    // section length 7
      0x01, 0x50, 0x00,        // types count 1:  subtype extensible,
                               // supertype count 0
      0x5f, 0x01, 0x7e, 0x00,  //  kind: struct, field count 1:  i64 immutable
  };
  return CreateWasmObject(isolate, base::VectorOf(wasm_module_bytes), true);
}

// Creates a new wasm array of type i64 with one element (0x7AADF00DBAADF00D).
RUNTIME_FUNCTION(Runtime_WasmArray) {
  HandleScope scope(isolate);
  if (v8_flags.jitless) {
    return CreateDummyWasmLookAlikeForFuzzing(isolate);
  }
  /* Recreate with:
    d8.file.execute('test/mjsunit/wasm/wasm-module-builder.js');
    let builder = new WasmModuleBuilder();
    let array = builder.addArray(kWasmI64, false);
    builder.instantiate();
  */
  static constexpr uint8_t wasm_module_bytes[] = {
      0x00, 0x61, 0x73, 0x6d,  // wasm magic
      0x01, 0x00, 0x00, 0x00,  // wasm version
      0x01,                    // section kind: Type
      0x06,                    // section length 6
      0x01, 0x50, 0x00,        // types count 1:  subtype extensible,
                               // supertype count 0
      0x5e, 0x7e, 0x00,        //  kind: array i64 immutable
  };
  return CreateWasmObject(isolate, base::VectorOf(wasm_module_bytes), false);
}

RUNTIME_FUNCTION(Runtime_WasmEnterDebugging) {
  HandleScope scope(isolate);
  wasm::GetWasmEngine()->EnterDebuggingForIsolate(isolate);
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_WasmLeaveDebugging) {
  HandleScope scope(isolate);
  wasm::GetWasmEngine()->LeaveDebuggingForIsolate(isolate);
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_IsWasmDebugFunction) {
  HandleScope scope(isolate);
  if (args.length() != 1 || !IsJSFunction(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  Handle<JSFunction> function = args.at<JSFunction>(0);
  if (!WasmExportedFunction::IsWasmExportedFunction(*function)) {
    return CrashUnlessFuzzing(isolate);
  }
  auto exp_fun = Cast<WasmExportedFunction>(function);
  auto data = exp_fun->shared()->wasm_exported_function_data();
  wasm::NativeModule* native_module = data->instance_data()->native_module();
  uint32_t func_index = data->function_index();
  if (static_cast<uint32_t>(func_index) <
      data->instance_data()->module()->num_imported_functions) {
    return CrashUnlessFuzzing(isolate);
  }
  wasm::WasmCodeRefScope code_ref_scope;
  wasm::WasmCode* code
```