Response: The user wants a summary of the C++ code provided.
The code is located in `v8/src/wasm/module-instantiate.cc` and seems to be related to the instantiation process of WebAssembly modules within the V8 JavaScript engine.

The code includes various helper functions and a main class `InstanceBuilder` that handles the different steps involved in creating a WebAssembly instance.

Key functionalities likely include:
- Creating the `WasmInstanceObject`.
- Handling imports (functions, tables, globals, memories).
- Allocating memory for the instance.
- Initializing globals and tables.
- Processing exports.
- Executing the start function.
- Integration with JavaScript concepts like `JSReceiver`, `JSArrayBuffer`, and `SharedFunctionInfo`.

Since this is part 1 of 3, the summary should focus on the functionalities covered in this specific segment.

Based on the included headers and the code itself, this part seems to be heavily focused on setting up the basic structures of the `WasmInstanceObject`, handling memory allocation, processing imports (specifically looking up and resolving them, including handling "fast API" calls), and creating maps for managed objects (related to the GC proposal).
这个C++源代码文件（`v8/src/wasm/module-instantiate.cc`）的主要功能是**负责 WebAssembly 模块的实例化过程**。  它定义了创建 `WasmInstanceObject` 的步骤，这个对象代表了 WebAssembly 模块的一个运行实例。

具体来说，在这第一部分的代码中，主要涉及以下功能：

1. **创建基础的 WasmInstanceObject 和相关数据结构:**
   - 它创建了 `WasmTrustedInstanceData`，用于存储实例的受信任数据。
   - 它为 WebAssembly 模块中的结构体（struct）和数组（array）创建了对应的 JavaScript `Map` 对象，这些 `Map` 用于管理这些类型的实例。
   - 它处理共享类型（shared types）的 `Map` 创建。

2. **处理 WebAssembly 模块的导入 (Imports):**
   - 它包含了 `ResolvedWasmImport` 类，用于解析和处理导入的函数、全局变量、表和内存。
   - 它实现了查找导入值的功能 (`LookupImport`, `LookupImportAsm`)，这些值通常来自外部 JavaScript 环境。
   - 它特别关注了**WebAssembly 的快速 API 调用 (Fast API calls)** 的处理，这是一种优化技术，允许 WebAssembly 直接调用某些特定的 JavaScript API 函数，而无需经过完整的 JavaScript 调用栈。
   - 它通过 `IsSupportedWasmFastApiFunction` 函数来判断一个 JavaScript 函数是否可以作为快速 API 函数被调用。
   - 它还处理了绑定函数 (`ResolveBoundJSFastApiFunction`) 作为导入的情况，并尝试识别和优化对已知内置函数的调用 (`CheckForWellKnownImport`)，例如 `DataView` 的方法、`String.prototype.indexOf` 等。

3. **内存管理:**
   - 它包含了分配 WebAssembly 模块内存的功能 (`AllocateMemory`)。

**与 JavaScript 的关系及示例:**

这个文件中的代码直接与 JavaScript 的功能紧密相关，因为它负责将 WebAssembly 模块连接到 JavaScript 环境。

**JavaScript 示例 (关于 Fast API Call):**

假设有一个 WebAssembly 模块想要导入 JavaScript 的 `Math.sqrt` 函数。  `module-instantiate.cc` 中的代码会尝试识别 `Math.sqrt` 是否符合快速 API 调用的条件。

```javascript
// JavaScript 代码
const importObject = {
  Math: {
    sqrt: Math.sqrt
  }
};

WebAssembly.instantiateStreaming(fetch('my_module.wasm'), importObject)
  .then(result => {
    // 可以调用导出的 WebAssembly 函数，该函数内部会调用 Math.sqrt
    console.log(result.instance.exports.my_wasm_function(9));
  });
```

在这个例子中，当 `WebAssembly.instantiateStreaming` 被调用时，`module-instantiate.cc` 中的代码会检查 `importObject.Math.sqrt`。如果 `Math.sqrt` 符合快速 API 调用的条件（例如，参数和返回值类型匹配），V8 可能会生成优化的代码，允许 WebAssembly 代码直接调用 `Math.sqrt` 的底层实现，而无需经过昂贵的 JavaScript 函数调用。

**JavaScript 示例 (关于创建 Map):**

如果 WebAssembly 模块定义了一个结构体类型，例如：

```wasm
(module
  (type $my_struct (struct (field i32)))
  (global $my_global (ref $my_struct) (ref.null $my_struct))
  (export "my_global" (global $my_global))
)
```

`module-instantiate.cc` 中的 `CreateStructMap` 函数会被调用，为 `$my_struct` 创建一个对应的 JavaScript `Map` 对象。 当你在 JavaScript 中访问这个 WebAssembly 模块导出的全局变量时，如果需要创建一个该结构体的实例，V8 会使用这个 `Map` 对象来创建相应的 JavaScript 对象。

总而言之，这个代码文件的第一部分主要关注于 WebAssembly 实例创建的早期阶段，包括设置基本结构、处理模块的外部依赖（imports），以及为 WebAssembly 的类型系统（特别是结构体和数组）与 JavaScript 的对象模型之间建立桥梁。

### 提示词
```
这是目录为v8/src/wasm/module-instantiate.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/module-instantiate.h"

#include "src/api/api-inl.h"
#include "src/asmjs/asm-js.h"
#include "src/base/atomicops.h"
#include "src/codegen/compiler.h"
#include "src/compiler/wasm-compiler.h"
#include "src/logging/counters-scopes.h"
#include "src/logging/metrics.h"
#include "src/numbers/conversions-inl.h"
#include "src/objects/descriptor-array-inl.h"
#include "src/objects/property-descriptor.h"
#include "src/objects/torque-defined-classes.h"
#include "src/tracing/trace-event.h"
#include "src/utils/utils.h"
#include "src/wasm/code-space-access.h"
#include "src/wasm/compilation-environment-inl.h"
#include "src/wasm/constant-expression-interface.h"
#include "src/wasm/module-compiler.h"
#include "src/wasm/module-decoder-impl.h"
#include "src/wasm/pgo.h"
#include "src/wasm/wasm-constants.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-external-refs.h"
#include "src/wasm/wasm-import-wrapper-cache.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-objects-inl.h"
#include "src/wasm/wasm-opcodes-inl.h"
#include "src/wasm/wasm-subtyping.h"

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
#include "src/execution/simulator-base.h"
#endif  // V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS

#define TRACE(...)                                          \
  do {                                                      \
    if (v8_flags.trace_wasm_instances) PrintF(__VA_ARGS__); \
  } while (false)

namespace v8::internal::wasm {

namespace {

uint8_t* raw_buffer_ptr(MaybeHandle<JSArrayBuffer> buffer, int offset) {
  return static_cast<uint8_t*>(buffer.ToHandleChecked()->backing_store()) +
         offset;
}

Handle<Map> CreateStructMap(Isolate* isolate, const WasmModule* module,
                            ModuleTypeIndex struct_index,
                            Handle<Map> opt_rtt_parent,
                            DirectHandle<WasmTrustedInstanceData> trusted_data,
                            Handle<WasmInstanceObject> instance) {
  const wasm::StructType* type = module->struct_type(struct_index);
  const int inobject_properties = 0;
  // We have to use the variable size sentinel because the instance size
  // stored directly in a Map is capped at 255 pointer sizes.
  const int map_instance_size = kVariableSizeSentinel;
  const InstanceType instance_type = WASM_STRUCT_TYPE;
  // TODO(jkummerow): If NO_ELEMENTS were supported, we could use that here.
  const ElementsKind elements_kind = TERMINAL_FAST_ELEMENTS_KIND;
  DirectHandle<WasmTypeInfo> type_info = isolate->factory()->NewWasmTypeInfo(
      reinterpret_cast<Address>(type), opt_rtt_parent, trusted_data,
      struct_index);
  Handle<Map> map = isolate->factory()->NewContextfulMap(
      instance, instance_type, map_instance_size, elements_kind,
      inobject_properties);
  map->set_wasm_type_info(*type_info);
  map->SetInstanceDescriptors(isolate,
                              *isolate->factory()->empty_descriptor_array(), 0,
                              SKIP_WRITE_BARRIER);
  map->set_is_extensible(false);
  const int real_instance_size = WasmStruct::Size(type);
  WasmStruct::EncodeInstanceSizeInMap(real_instance_size, *map);
  return map;
}

Handle<Map> CreateArrayMap(Isolate* isolate, const WasmModule* module,
                           ModuleTypeIndex array_index,
                           Handle<Map> opt_rtt_parent,
                           DirectHandle<WasmTrustedInstanceData> trusted_data,
                           Handle<WasmInstanceObject> instance) {
  const wasm::ArrayType* type = module->array_type(array_index);
  const int inobject_properties = 0;
  const int instance_size = kVariableSizeSentinel;
  const InstanceType instance_type = WASM_ARRAY_TYPE;
  const ElementsKind elements_kind = TERMINAL_FAST_ELEMENTS_KIND;
  DirectHandle<WasmTypeInfo> type_info = isolate->factory()->NewWasmTypeInfo(
      reinterpret_cast<Address>(type), opt_rtt_parent, trusted_data,
      array_index);
  Handle<Map> map = isolate->factory()->NewContextfulMap(
      instance, instance_type, instance_size, elements_kind,
      inobject_properties);
  map->set_wasm_type_info(*type_info);
  map->SetInstanceDescriptors(isolate,
                              *isolate->factory()->empty_descriptor_array(), 0,
                              SKIP_WRITE_BARRIER);
  map->set_is_extensible(false);
  WasmArray::EncodeElementSizeInMap(type->element_type().value_kind_size(),
                                    *map);
  return map;
}

}  // namespace

void CreateMapForType(Isolate* isolate, const WasmModule* module,
                      ModuleTypeIndex type_index,
                      Handle<WasmTrustedInstanceData> trusted_data,
                      Handle<WasmInstanceObject> instance,
                      Handle<FixedArray> maybe_shared_maps) {
  // Recursive calls for supertypes may already have created this map.
  if (IsMap(maybe_shared_maps->get(type_index.index))) return;

  CanonicalTypeIndex canonical_type_index =
      module->canonical_type_id(type_index);

  // Try to find the canonical map for this type in the isolate store.
  DirectHandle<WeakFixedArray> canonical_rtts =
      direct_handle(isolate->heap()->wasm_canonical_rtts(), isolate);
  DCHECK_GT(static_cast<uint32_t>(canonical_rtts->length()),
            canonical_type_index.index);
  Tagged<MaybeObject> maybe_canonical_map =
      canonical_rtts->get(canonical_type_index.index);
  if (!maybe_canonical_map.IsCleared()) {
    maybe_shared_maps->set(type_index.index,
                           maybe_canonical_map.GetHeapObjectAssumeWeak());
    return;
  }

  Handle<Map> rtt_parent;
  // If the type with {type_index} has an explicit supertype, make sure the
  // map for that supertype is created first, so that the supertypes list
  // that's cached on every RTT can be set up correctly.
  ModuleTypeIndex supertype = module->supertype(type_index);
  if (supertype.valid()) {
    // This recursion is safe, because kV8MaxRttSubtypingDepth limits the
    // number of recursive steps, so we won't overflow the stack.
    CreateMapForType(isolate, module, supertype, trusted_data, instance,
                     maybe_shared_maps);
    // We look up the supertype in {maybe_shared_maps} as a shared type can only
    // inherit from a shared type and vice verca.
    rtt_parent =
        handle(Cast<Map>(maybe_shared_maps->get(supertype.index)), isolate);
  }
  DirectHandle<Map> map;
  switch (module->type(type_index).kind) {
    case TypeDefinition::kStruct:
      map = CreateStructMap(isolate, module, type_index, rtt_parent,
                            trusted_data, instance);
      break;
    case TypeDefinition::kArray:
      map = CreateArrayMap(isolate, module, type_index, rtt_parent,
                           trusted_data, instance);
      break;
    case TypeDefinition::kFunction:
      map = CreateFuncRefMap(isolate, rtt_parent);
      break;
  }
  canonical_rtts->set(canonical_type_index.index, MakeWeak(*map));
  maybe_shared_maps->set(type_index.index, *map);
}

namespace {

bool CompareWithNormalizedCType(const CTypeInfo& info,
                                CanonicalValueType expected,
                                CFunctionInfo::Int64Representation int64_rep) {
  MachineType t = MachineType::TypeForCType(info);
  // Wasm representation of bool is i32 instead of i1.
  if (t.semantic() == MachineSemantic::kBool) {
    return expected == kCanonicalI32;
  }
  if (info.GetType() == CTypeInfo::Type::kSeqOneByteString) {
    // WebAssembly does not support one byte strings in fast API calls as
    // runtime type checks are not supported so far.
    return false;
  }

  if (t.representation() == MachineRepresentation::kWord64) {
    if (int64_rep == CFunctionInfo::Int64Representation::kBigInt) {
      return expected == kCanonicalI64;
    }
    DCHECK_EQ(int64_rep, CFunctionInfo::Int64Representation::kNumber);
    return expected == kCanonicalI32 || expected == kCanonicalF32 ||
           expected == kCanonicalF64;
  }
  return t.representation() == expected.machine_representation();
}

enum class ReceiverKind { kFirstParamIsReceiver, kAnyReceiver };

bool IsSupportedWasmFastApiFunction(Isolate* isolate,
                                    const wasm::CanonicalSig* expected_sig,
                                    Tagged<SharedFunctionInfo> shared,
                                    ReceiverKind receiver_kind,
                                    int* out_index) {
  if (!shared->IsApiFunction()) {
    return false;
  }
  if (shared->api_func_data()->GetCFunctionsCount() == 0) {
    return false;
  }
  if (receiver_kind == ReceiverKind::kAnyReceiver &&
      !shared->api_func_data()->accept_any_receiver()) {
    return false;
  }
  if (receiver_kind == ReceiverKind::kAnyReceiver &&
      !IsUndefined(shared->api_func_data()->signature())) {
    // TODO(wasm): CFunctionInfo* signature check.
    return false;
  }

  const auto log_imported_function_mismatch = [&shared, isolate](
                                                  int func_index,
                                                  const char* reason) {
    if (v8_flags.trace_opt) {
      CodeTracer::Scope scope(isolate->GetCodeTracer());
      PrintF(scope.file(), "[disabled optimization for ");
      ShortPrint(*shared, scope.file());
      PrintF(scope.file(),
             " for C function %d, reason: the signature of the imported "
             "function in the Wasm module doesn't match that of the Fast API "
             "function (%s)]\n",
             func_index, reason);
    }
  };

  // C functions only have one return value.
  if (expected_sig->return_count() > 1) {
    // Here and below, we log when the function we call is declared as an Api
    // function but we cannot optimize the call, which might be unxepected. In
    // that case we use the "slow" path making a normal Wasm->JS call and
    // calling the "slow" callback specified in FunctionTemplate::New().
    log_imported_function_mismatch(0, "too many return values");
    return false;
  }

  for (int c_func_id = 0, end = shared->api_func_data()->GetCFunctionsCount();
       c_func_id < end; ++c_func_id) {
    const CFunctionInfo* info =
        shared->api_func_data()->GetCSignature(isolate, c_func_id);
    if (!compiler::IsFastCallSupportedSignature(info)) {
      log_imported_function_mismatch(c_func_id,
                                     "signature not supported by the fast API");
      continue;
    }

    CTypeInfo return_info = info->ReturnInfo();
    // Unsupported if return type doesn't match.
    if (expected_sig->return_count() == 0 &&
        return_info.GetType() != CTypeInfo::Type::kVoid) {
      log_imported_function_mismatch(c_func_id, "too few return values");
      continue;
    }
    // Unsupported if return type doesn't match.
    if (expected_sig->return_count() == 1) {
      if (return_info.GetType() == CTypeInfo::Type::kVoid) {
        log_imported_function_mismatch(c_func_id, "too many return values");
        continue;
      }
      if (!CompareWithNormalizedCType(return_info, expected_sig->GetReturn(0),
                                      info->GetInt64Representation())) {
        log_imported_function_mismatch(c_func_id, "mismatching return value");
        continue;
      }
    }

    if (receiver_kind == ReceiverKind::kFirstParamIsReceiver) {
      if (expected_sig->parameter_count() < 1) {
        log_imported_function_mismatch(
            c_func_id, "at least one parameter is needed as the receiver");
        continue;
      }
      if (!expected_sig->GetParam(0).is_reference()) {
        log_imported_function_mismatch(c_func_id,
                                       "the receiver has to be a reference");
        continue;
      }
    }

    int param_offset =
        receiver_kind == ReceiverKind::kFirstParamIsReceiver ? 1 : 0;
    // Unsupported if arity doesn't match.
    if (expected_sig->parameter_count() - param_offset !=
        info->ArgumentCount() - 1) {
      log_imported_function_mismatch(c_func_id, "mismatched arity");
      continue;
    }
    // Unsupported if any argument types don't match.
    bool param_mismatch = false;
    for (unsigned int i = 0; i < expected_sig->parameter_count() - param_offset;
         ++i) {
      int sig_index = i + param_offset;
      // Arg 0 is the receiver, skip over it since either the receiver does not
      // matter, or we already checked it above.
      CTypeInfo arg = info->ArgumentInfo(i + 1);
      if (!CompareWithNormalizedCType(arg, expected_sig->GetParam(sig_index),
                                      info->GetInt64Representation())) {
        log_imported_function_mismatch(c_func_id, "parameter type mismatch");
        param_mismatch = true;
        break;
      }
      if (arg.GetSequenceType() == CTypeInfo::SequenceType::kIsSequence) {
        log_imported_function_mismatch(c_func_id,
                                       "sequence types are not allowed");
        param_mismatch = true;
        break;
      }
    }
    if (param_mismatch) {
      continue;
    }
    *out_index = c_func_id;
    return true;
  }
  return false;
}

bool ResolveBoundJSFastApiFunction(const wasm::CanonicalSig* expected_sig,
                                   DirectHandle<JSReceiver> callable) {
  DirectHandle<JSFunction> target;
  if (IsJSBoundFunction(*callable)) {
    auto bound_target = Cast<JSBoundFunction>(callable);
    // Nested bound functions and arguments not supported yet.
    if (bound_target->bound_arguments()->length() > 0) {
      return false;
    }
    if (IsJSBoundFunction(bound_target->bound_target_function())) {
      return false;
    }
    DirectHandle<JSReceiver> bound_target_function(
        bound_target->bound_target_function(), callable->GetIsolate());
    if (!IsJSFunction(*bound_target_function)) {
      return false;
    }
    target = Cast<JSFunction>(bound_target_function);
  } else if (IsJSFunction(*callable)) {
    target = Cast<JSFunction>(callable);
  } else {
    return false;
  }

  Isolate* isolate = target->GetIsolate();
  DirectHandle<SharedFunctionInfo> shared(target->shared(), isolate);
  int api_function_index = -1;
  // The fast API call wrapper currently does not support function overloading.
  // Therefore, if the matching function is not function 0, the fast API cannot
  // be used.
  return IsSupportedWasmFastApiFunction(isolate, expected_sig, *shared,
                                        ReceiverKind::kAnyReceiver,
                                        &api_function_index) &&
         api_function_index == 0;
}

bool IsStringRef(wasm::CanonicalValueType type) {
  return type.is_reference_to(wasm::HeapType::kString);
}

bool IsExternRef(wasm::CanonicalValueType type) {
  return type.is_reference_to(wasm::HeapType::kExtern);
}

bool IsStringOrExternRef(wasm::CanonicalValueType type) {
  return IsStringRef(type) || IsExternRef(type);
}

bool IsDataViewGetterSig(const wasm::CanonicalSig* sig,
                         wasm::CanonicalValueType return_type) {
  return sig->parameter_count() == 3 && sig->return_count() == 1 &&
         sig->GetParam(0) == wasm::kCanonicalExternRef &&
         sig->GetParam(1) == wasm::kCanonicalI32 &&
         sig->GetParam(2) == wasm::kCanonicalI32 &&
         sig->GetReturn(0) == return_type;
}

bool IsDataViewSetterSig(const wasm::CanonicalSig* sig,
                         wasm::CanonicalValueType value_type) {
  return sig->parameter_count() == 4 && sig->return_count() == 0 &&
         sig->GetParam(0) == wasm::kCanonicalExternRef &&
         sig->GetParam(1) == wasm::kCanonicalI32 &&
         sig->GetParam(2) == value_type &&
         sig->GetParam(3) == wasm::kCanonicalI32;
}

const MachineSignature* GetFunctionSigForFastApiImport(
    Zone* zone, const CFunctionInfo* info) {
  uint32_t arg_count = info->ArgumentCount();
  uint32_t ret_count =
      info->ReturnInfo().GetType() == CTypeInfo::Type::kVoid ? 0 : 1;
  constexpr uint32_t param_offset = 1;

  MachineSignature::Builder sig_builder(zone, ret_count,
                                        arg_count - param_offset);
  if (ret_count) {
    sig_builder.AddReturn(MachineType::TypeForCType(info->ReturnInfo()));
  }

  for (uint32_t i = param_offset; i < arg_count; ++i) {
    sig_builder.AddParam(MachineType::TypeForCType(info->ArgumentInfo(i)));
  }
  return sig_builder.Get();
}

// This detects imports of the forms:
// - `Function.prototype.call.bind(foo)`, where `foo` is something that has a
//   Builtin id.
// - JSFunction with Builtin id (e.g. `parseFloat`).
WellKnownImport CheckForWellKnownImport(
    DirectHandle<WasmTrustedInstanceData> trusted_instance_data, int func_index,
    DirectHandle<JSReceiver> callable, const wasm::CanonicalSig* sig) {
  WellKnownImport kGeneric = WellKnownImport::kGeneric;  // "using" is C++20.
  if (trusted_instance_data.is_null()) return kGeneric;
  // Check for plain JS functions.
  if (IsJSFunction(*callable)) {
    Tagged<SharedFunctionInfo> sfi = Cast<JSFunction>(*callable)->shared();
    if (!sfi->HasBuiltinId()) return kGeneric;
    // This needs to be a separate switch because it allows other cases than
    // the one below. Merging them would be invalid, because we would then
    // recognize receiver-requiring methods even when they're (erroneously)
    // being imported such that they don't get a receiver.
    switch (sfi->builtin_id()) {
        // =================================================================
        // String-related imports that aren't part of the JS String Builtins
        // proposal.
      case Builtin::kNumberParseFloat:
        if (sig->parameter_count() == 1 && sig->return_count() == 1 &&
            IsStringRef(sig->GetParam(0)) &&
            sig->GetReturn(0) == wasm::kCanonicalF64) {
          return WellKnownImport::kParseFloat;
        }
        break;
      default:
        break;
    }
    return kGeneric;
  }

  // Check for bound JS functions.
  // First part: check that the callable is a bound function whose target
  // is {Function.prototype.call}, and which only binds a receiver.
  if (!IsJSBoundFunction(*callable)) return kGeneric;
  auto bound = Cast<JSBoundFunction>(callable);
  if (bound->bound_arguments()->length() != 0) return kGeneric;
  if (!IsJSFunction(bound->bound_target_function())) return kGeneric;
  Tagged<SharedFunctionInfo> sfi =
      Cast<JSFunction>(bound->bound_target_function())->shared();
  if (!sfi->HasBuiltinId()) return kGeneric;
  if (sfi->builtin_id() != Builtin::kFunctionPrototypeCall) return kGeneric;
  // Second part: check if the bound receiver is one of the builtins for which
  // we have special-cased support.
  Tagged<Object> bound_this = bound->bound_this();
  if (!IsJSFunction(bound_this)) return kGeneric;
  sfi = Cast<JSFunction>(bound_this)->shared();
  Isolate* isolate = Cast<JSFunction>(bound_this)->GetIsolate();
  int out_api_function_index = -1;
  if (v8_flags.wasm_fast_api &&
      IsSupportedWasmFastApiFunction(isolate, sig, sfi,
                                     ReceiverKind::kFirstParamIsReceiver,
                                     &out_api_function_index)) {
    Tagged<FunctionTemplateInfo> func_data = sfi->api_func_data();
    NativeModule* native_module = trusted_instance_data->native_module();
    if (!native_module->TrySetFastApiCallTarget(
            func_index,
            func_data->GetCFunction(isolate, out_api_function_index))) {
      return kGeneric;
    }
#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
    Address c_functions[] = {func_data->GetCFunction(isolate, 0)};
    const v8::CFunctionInfo* const c_signatures[] = {
        func_data->GetCSignature(isolate, 0)};
    isolate->simulator_data()->RegisterFunctionsAndSignatures(c_functions,
                                                              c_signatures, 1);
#endif  //  V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
    // Store the signature of the C++ function in the native_module. We check
    // first if the signature already exists in the native_module such that we
    // do not create a copy of the signature unnecessarily. Since
    // `has_fast_api_signature` and `set_fast_api_signature` don't happen
    // atomically, it is still possible that multiple copies of the signature
    // get created. However, the `TrySetFastApiCallTarget` above guarantees that
    // if there are concurrent calls to `set_cast_api_signature`, then all calls
    // would store the same signature to the native module.
    if (!native_module->has_fast_api_signature(func_index)) {
      native_module->set_fast_api_signature(
          func_index,
          GetFunctionSigForFastApiImport(
              &native_module->module()->signature_zone,
              func_data->GetCSignature(isolate, out_api_function_index)));
    }

    DirectHandle<HeapObject> js_signature(sfi->api_func_data()->signature(),
                                          isolate);
    DirectHandle<Object> callback_data(
        sfi->api_func_data()->callback_data(kAcquireLoad), isolate);
    DirectHandle<WasmFastApiCallData> fast_api_call_data =
        isolate->factory()->NewWasmFastApiCallData(js_signature, callback_data);
    trusted_instance_data->well_known_imports()->set(func_index,
                                                     *fast_api_call_data);
    return WellKnownImport::kFastAPICall;
  }
  if (!sfi->HasBuiltinId()) return kGeneric;
  switch (sfi->builtin_id()) {
#if V8_INTL_SUPPORT
    case Builtin::kStringPrototypeToLocaleLowerCase:
      if (sig->parameter_count() == 2 && sig->return_count() == 1 &&
          IsStringRef(sig->GetParam(0)) && IsStringRef(sig->GetParam(1)) &&
          IsStringRef(sig->GetReturn(0))) {
        DCHECK_GE(func_index, 0);
        trusted_instance_data->well_known_imports()->set(func_index,
                                                         bound_this);
        return WellKnownImport::kStringToLocaleLowerCaseStringref;
      }
      break;
    case Builtin::kStringPrototypeToLowerCaseIntl:
      if (sig->parameter_count() == 1 && sig->return_count() == 1 &&
          IsStringRef(sig->GetParam(0)) && IsStringRef(sig->GetReturn(0))) {
        return WellKnownImport::kStringToLowerCaseStringref;
      } else if (sig->parameter_count() == 1 && sig->return_count() == 1 &&
                 sig->GetParam(0) == wasm::kCanonicalExternRef &&
                 sig->GetReturn(0) == wasm::kCanonicalExternRef) {
        return WellKnownImport::kStringToLowerCaseImported;
      }
      break;
#endif
    case Builtin::kDataViewPrototypeGetBigInt64:
      if (IsDataViewGetterSig(sig, wasm::kCanonicalI64)) {
        return WellKnownImport::kDataViewGetBigInt64;
      }
      break;
    case Builtin::kDataViewPrototypeGetBigUint64:
      if (IsDataViewGetterSig(sig, wasm::kCanonicalI64)) {
        return WellKnownImport::kDataViewGetBigUint64;
      }
      break;
    case Builtin::kDataViewPrototypeGetFloat32:
      if (IsDataViewGetterSig(sig, wasm::kCanonicalF32)) {
        return WellKnownImport::kDataViewGetFloat32;
      }
      break;
    case Builtin::kDataViewPrototypeGetFloat64:
      if (IsDataViewGetterSig(sig, wasm::kCanonicalF64)) {
        return WellKnownImport::kDataViewGetFloat64;
      }
      break;
    case Builtin::kDataViewPrototypeGetInt8:
      if (sig->parameter_count() == 2 && sig->return_count() == 1 &&
          sig->GetParam(0) == wasm::kCanonicalExternRef &&
          sig->GetParam(1) == wasm::kCanonicalI32 &&
          sig->GetReturn(0) == wasm::kCanonicalI32) {
        return WellKnownImport::kDataViewGetInt8;
      }
      break;
    case Builtin::kDataViewPrototypeGetInt16:
      if (IsDataViewGetterSig(sig, wasm::kCanonicalI32)) {
        return WellKnownImport::kDataViewGetInt16;
      }
      break;
    case Builtin::kDataViewPrototypeGetInt32:
      if (IsDataViewGetterSig(sig, wasm::kCanonicalI32)) {
        return WellKnownImport::kDataViewGetInt32;
      }
      break;
    case Builtin::kDataViewPrototypeGetUint8:
      if (sig->parameter_count() == 2 && sig->return_count() == 1 &&
          sig->GetParam(0) == wasm::kCanonicalExternRef &&
          sig->GetParam(1) == wasm::kCanonicalI32 &&
          sig->GetReturn(0) == wasm::kCanonicalI32) {
        return WellKnownImport::kDataViewGetUint8;
      }
      break;
    case Builtin::kDataViewPrototypeGetUint16:
      if (IsDataViewGetterSig(sig, wasm::kCanonicalI32)) {
        return WellKnownImport::kDataViewGetUint16;
      }
      break;
    case Builtin::kDataViewPrototypeGetUint32:
      if (IsDataViewGetterSig(sig, wasm::kCanonicalI32)) {
        return WellKnownImport::kDataViewGetUint32;
      }
      break;

    case Builtin::kDataViewPrototypeSetBigInt64:
      if (IsDataViewSetterSig(sig, wasm::kCanonicalI64)) {
        return WellKnownImport::kDataViewSetBigInt64;
      }
      break;
    case Builtin::kDataViewPrototypeSetBigUint64:
      if (IsDataViewSetterSig(sig, wasm::kCanonicalI64)) {
        return WellKnownImport::kDataViewSetBigUint64;
      }
      break;
    case Builtin::kDataViewPrototypeSetFloat32:
      if (IsDataViewSetterSig(sig, wasm::kCanonicalF32)) {
        return WellKnownImport::kDataViewSetFloat32;
      }
      break;
    case Builtin::kDataViewPrototypeSetFloat64:
      if (IsDataViewSetterSig(sig, wasm::kCanonicalF64)) {
        return WellKnownImport::kDataViewSetFloat64;
      }
      break;
    case Builtin::kDataViewPrototypeSetInt8:
      if (sig->parameter_count() == 3 && sig->return_count() == 0 &&
          sig->GetParam(0) == wasm::kCanonicalExternRef &&
          sig->GetParam(1) == wasm::kCanonicalI32 &&
          sig->GetParam(2) == wasm::kCanonicalI32) {
        return WellKnownImport::kDataViewSetInt8;
      }
      break;
    case Builtin::kDataViewPrototypeSetInt16:
      if (IsDataViewSetterSig(sig, wasm::kCanonicalI32)) {
        return WellKnownImport::kDataViewSetInt16;
      }
      break;
    case Builtin::kDataViewPrototypeSetInt32:
      if (IsDataViewSetterSig(sig, wasm::kCanonicalI32)) {
        return WellKnownImport::kDataViewSetInt32;
      }
      break;
    case Builtin::kDataViewPrototypeSetUint8:
      if (sig->parameter_count() == 3 && sig->return_count() == 0 &&
          sig->GetParam(0) == wasm::kCanonicalExternRef &&
          sig->GetParam(1) == wasm::kCanonicalI32 &&
          sig->GetParam(2) == wasm::kCanonicalI32) {
        return WellKnownImport::kDataViewSetUint8;
      }
      break;
    case Builtin::kDataViewPrototypeSetUint16:
      if (IsDataViewSetterSig(sig, wasm::kCanonicalI32)) {
        return WellKnownImport::kDataViewSetUint16;
      }
      break;
    case Builtin::kDataViewPrototypeSetUint32:
      if (IsDataViewSetterSig(sig, wasm::kCanonicalI32)) {
        return WellKnownImport::kDataViewSetUint32;
      }
      break;
    case Builtin::kDataViewPrototypeGetByteLength:
      if (sig->parameter_count() == 1 && sig->return_count() == 1 &&
          sig->GetParam(0) == wasm::kCanonicalExternRef &&
          sig->GetReturn(0) == kCanonicalF64) {
        return WellKnownImport::kDataViewByteLength;
      }
      break;
    case Builtin::kNumberPrototypeToString:
      if (sig->parameter_count() == 2 && sig->return_count() == 1 &&
          sig->GetParam(0) == wasm::kCanonicalI32 &&
          sig->GetParam(1) == wasm::kCanonicalI32 &&
          IsStringOrExternRef(sig->GetReturn(0))) {
        return WellKnownImport::kIntToString;
      }
      if (sig->parameter_count() == 1 && sig->return_count() == 1 &&
          sig->GetParam(0) == wasm::kCanonicalF64 &&
          IsStringOrExternRef(sig->GetReturn(0))) {
        return WellKnownImport::kDoubleToString;
      }
      break;
    case Builtin::kStringPrototypeIndexOf:
      // (string, string, i32) -> (i32).
      if (sig->parameter_count() == 3 && sig->return_count() == 1 &&
          IsStringRef(sig->GetParam(0)) && IsStringRef(sig->GetParam(1)) &&
          sig->GetParam(2) == wasm::kCanonicalI32 &&
          sig->GetReturn(0) == wasm::kCanonicalI32) {
        return WellKnownImport::kStringIndexOf;
      } else if (sig->parameter_count() == 3 && sig->return_count() == 1 &&
                 sig->GetParam(0) == wasm::kCanonicalExternRef &&
                 sig->GetParam(1) == wasm::kCanonicalExternRef &&
                 sig->GetParam(2) == wasm::kCanonicalI32 &&
                 sig->GetReturn(0) == wasm::kCanonicalI32) {
        return WellKnownImport::kStringIndexOfImported;
      }
      break;
    default:
      break;
  }
  return kGeneric;
}

}  // namespace

ResolvedWasmImport::ResolvedWasmImport(
    DirectHandle<WasmTrustedInstanceData> trusted_instance_data, int func_index,
    Handle<JSReceiver> callable, const wasm::CanonicalSig* expected_sig,
    CanonicalTypeIndex expected_sig_id, WellKnownImport preknown_import) {
  DCHECK_EQ(expected_sig, wasm::GetTypeCanonicalizer()->LookupFunctionSignature(
                              expected_sig_id));
  SetCallable(callable->GetIsolate(), callable);
  kind_ = ComputeKind(trusted_instance_data, func_index, expected_sig,
                      expected_sig_id, preknown_import);
}

void ResolvedWasmImport::SetCallable(Isolate* isolate,
                                     Tagged<JSReceiver> callable) {
  SetCallable(isolate, handle(callable, isolate));
}
void ResolvedWasmImport::SetCallable(Isolate* isolate,
                                     Handle<JSReceiver> callable) {
  callable_ = callable;
  trusted_function_data_ = {};
  if (!IsJSFunction(*callable)) return;
  Tagged<SharedFunctionInfo> sfi = Cast<JSFunction>(*callable_)->shared();
  if (sfi->HasWasmFunctionData()) {
    trusted_function_data_ = handle(sfi->wasm_function_data(), isolate);
  }
}

ImportCallKind ResolvedWasmImport::ComputeKind(
    DirectHandle<WasmTrustedInstanceData> trusted_instance_data, int func_index,
    const wasm::CanonicalSig* expected_sig, CanonicalTypeIndex expected_sig_id,
    WellKnownImport preknown_import) {
  // If we already have a compile-time import, simply pass that through.
  if (IsCompileTimeImport(preknown_import)) {
    well_known_status_ = preknown_import;
    DCHECK(IsJSFunction(*callable_));
    DCHECK_EQ(Cast<JSFunction>(*callable_)
                  ->shared()
                  ->internal_formal_parameter_count_without_receiver(),
              expected_sig->parameter_count());
    return ImportCallKind::kJSFunctionArityMatch;
  }
  Isolate* isolate = callable_->GetIsolate();
  if (IsWasmSuspendingObject(*callable_)) {
    suspend_ = kSuspend;
    SetCallable(isolate, Cast<WasmSuspendingObject>(*callable_)->callable());
  }
  if (!trusted_function_data_.is_null() &&
      IsWasmExportedFunctionData(*trusted_function_data_)) {
    Tagged<WasmExportedFunctionData> data =
        Cast<WasmExportedFunctionData>(*trusted_function_data_);
    if (!data->MatchesSignature(expected_sig_id)) {
      return ImportCallKind::kLinkError;
    }
    uint32_t func_index = static_cast<uint32_t>(data->function_index());
    if (func_index >= data->instance_data()->module()->num_imported_functions) {
      return ImportCallKind::kWasmToWasm;
    }
    // Resolve the shortcut to the underlying callable and continue.
    ImportedFunctionEntry entry(handle(data->instance_data(), isolate),
                                func_index);
    suspend_ = static_cast<Suspend>(
        Cast<WasmImportData>(entry.implicit_arg())->suspend());
    SetCallable(isolate, entry.callable());
  }
  if (!trusted_function_data_.is_null() &&
      IsWasmJSFunctionData(*trusted_function_data_)) {
    Tagged<WasmJSFunctionData> js_function_data =
        Cast<WasmJSFunctionData>(*trusted_function_data_);
    suspend_ = js_function_data->GetSuspend();
    if (!js_function_data->MatchesSignature(expected_sig_id)) {
      return ImportCallKind::kLinkError;
    }
    // Resolve the short-cut to the underlying callable and continue.
    SetCallable(isolate, js_function_data->GetCallable());
  }
  if (WasmCapiFunction::IsWasmCapiFunction(*callable_)) {
    // TODO(jkummerow): Update this to follow the style of the other kinds of
    // functions.
    auto capi_function = Cast<WasmCapiFunction>(callable_);
    if (!capi_function->MatchesSignature(expected_sig_id)) {
      return ImportCallKind::kLinkError;
    }
    return ImportCallKind::kWasmToCapi;
  }
  // Assuming we are calling to JS, check whether this would be a runtime error.
  if (!wasm::IsJSCompatibleSignature(expected_sig)) {
    return ImportCallKind::kRuntimeTypeError;
  }
  // Check if this can be a JS fast API call.
  if (v8_flags.turbo_fast_api_calls &&
      ResolveBoundJSFastApiFunction(expected_sig, callable_)) {
    return ImportCallKind::kWasmToJSFastApi;
  }
  well_known_status_ = CheckForWellKnownImport(
      trusted_instance_data, func_index, callable_, expected_sig);
  if (well_known_status_ == WellKnownImport::kLinkError) {
    return ImportCallKind::kLinkError;
  }
  // TODO(jkummerow): It would be nice to return {kJSFunctionArityMatch} here
  // whenever {well_known_status_ != kGeneric}, so that the generic wrapper
  // can be used instead of a compiled wrapper; but that requires adding
  // support for calling bound functions to the generic wrapper first.

  // For JavaScript calls, determine whether the target has an arity match.
  if (IsJSFunction(*callable_)) {
    auto function = Cast<JSFunction>(callable_);
    DirectHandle<SharedFunctionInfo> shared(function->shared(), isolate);

// Check for math intrinsics.
#define COMPARE_SIG_FOR_BUILTIN(name)                                     \
  {                                                                       \
    const wasm::FunctionSig* sig =                                        \
        wasm::WasmOpcodes::Signature(wasm::kExpr##name);                  \
    if (!sig) sig = wasm::WasmOpcodes::AsmjsSignature(wasm::kExpr##name); \
    DCHECK_NOT_NULL(sig);                                                 \
    if (EquivalentNumericSig(expected_sig, sig)) {                        \
      return ImportCallKind::k##name;                                     \
    }                                                                     \
  }
#define COMPARE_SIG_FOR_BUILTIN_F64(name) \
  case Builtin::kMath##name:              \
    COMPARE_SIG_FOR_BUILTIN(F64##name);   \
    break;
#define COMPARE_SIG_FOR_BUILTIN_F32_F64(name) \
  case Builtin::kMath##name:                  \
    COMPARE_SIG_FOR_BUILTIN(F64##name);       \
    COMPARE_SIG_FOR_BUILTIN(F32##name);       \
    break;

    if (v8_flags.wasm_math_intrinsics && shared->HasBuiltinId()) {
      switch (shared->builtin_id()) {
        COMPARE_SIG_FOR_BUILTIN_F64(Acos);
        COMPARE_SIG_FOR_BUILTIN_F64(Asin);
        COMPARE_SIG_FOR_BUILTIN_F64(Atan);
        COMPARE_SIG_FOR_BUILTIN_F64(Cos);
        COMPARE_SIG_FOR_BUILTIN_F64(Sin);
        COMPARE_SIG_FOR_BUILTIN_F64(Tan);
        COMPARE_SIG_FOR_BUILTIN_F64(Exp);
        COMPARE_SIG_FOR_BUILTIN_F64(Log);
        COMPARE_SIG_FOR_BUILTIN_F64(Atan2);
        COMPARE_SIG_FOR_BUILTIN_F64(Pow);
        COMPARE_SIG_FOR_BUILTIN_F32_F64(Min);
        COMPARE_SIG_FOR_BUILTIN_F32_F64(Max);
        COMPARE_SIG_FOR_BUILTIN_F32_F64(Abs);
        COMPARE_SIG_FOR_BUILTIN_F32_F64(Ceil);
        COMPARE_SIG_FOR_BUILTIN_F32_F64(Floor);
        COMPARE_SIG_FOR_BUILTIN_F32_F64(Sqrt);
        case Builtin::kMathFround:
          COMPARE_SIG_FOR_BUILTIN(F32ConvertF64);
          break;
        default:
          break;
      }
    }

#undef COMPARE_SIG_FOR_BUILTIN
#undef COMPARE_SIG_FOR_BUILTIN_F64
#undef COMPARE_SIG_FOR_BUILTIN_F32_F64

    if (IsClassConstructor(shared->kind())) {
      // Class constructor will throw anyway.
      return ImportCallKind::kUseCallBuiltin;
    }

    if (shared->internal_formal_parameter_count_without_receiver() ==
        expected_sig->parameter_count()) {
      return ImportCallKind::kJSFunctionArityMatch;
    }

    return ImportCallKind::kJSFunctionArityMismatch;
  }
  // Unknown case. Use the call builtin.
  return ImportCallKind::kUseCallBuiltin;
}

// A helper class to simplify instantiating a module from a module object.
// It closes over the {Isolate}, the {ErrorThrower}, etc.
class InstanceBuilder {
 public:
  InstanceBuilder(Isolate* isolate, v8::metrics::Recorder::ContextId context_id,
                  ErrorThrower* thrower, Handle<WasmModuleObject> module_object,
                  MaybeHandle<JSReceiver> ffi,
                  MaybeHandle<JSArrayBuffer> memory_buffer);

  // Build an instance, in all of its glory.
  MaybeHandle<WasmInstanceObject> Build();
  // Run the start function, if any.
  bool ExecuteStartFunction();

 private:
  Isolate* isolate_;
  v8::metrics::Recorder::ContextId context_id_;
  const WasmEnabledFeatures enabled_;
  const WasmModule* const module_;
  ErrorThrower* thrower_;
  Handle<WasmModuleObject> module_object_;
  MaybeHandle<JSReceiver> ffi_;
  MaybeHandle<JSArrayBuffer> asmjs_memory_buffer_;
  Handle<JSArrayBuffer> untagged_globals_;
  Handle<JSArrayBuffer> shared_untagged_globals_;
  Handle<FixedArray> tagged_globals_;
  Handle<FixedArray> shared_tagged_globals_;
  std::vector<IndirectHandle<WasmTagObject>> tags_wrappers_;
  std::vector<IndirectHandle<WasmTagObject>> shared_tags_wrappers_;
  Handle<JSFunction> start_function_;
  std::vector<IndirectHandle<Object>> sanitized_imports_;
  std::vector<WellKnownImport> well_known_imports_;
  // We pass this {Zone} to the temporary {WasmFullDecoder} we allocate during
  // each call to {EvaluateConstantExpression}, and reset it after each such
  // call. This has been found to improve performance a bit over allocating a
  // new {Zone} each time.
  Zone init_expr_zone_;

  std::string ImportName(uint32_t index) {
    const WasmImport& import = module_->import_table[index];
    const char* wire_bytes_start = reinterpret_cast<const char*>(
        module_object_->native_module()->wire_bytes().data());
    std::ostringstream oss;
    oss << "Import #" << index << " \"";
    oss.write(wire_bytes_start + import.module_name.offset(),
              import.module_name.length());
    oss << "\" \"";
    oss.write(wire_bytes_start + import.field_name.offset(),
              import.field_name.length());
    oss << "\"";
    return oss.str();
  }

  std::string ImportName(uint32_t index, DirectHandle<String> module_name) {
    std::ostringstream oss;
    oss << "Import #" << index << " \"" << module_name->ToCString().get()
        << "\"";
    return oss.str();
  }

  // Look up an import value in the {ffi_} object.
  MaybeHandle<Object> LookupImport(uint32_t index, Handle<String> module_name,
                                   Handle<String> import_name);

  // Look up an import value in the {ffi_} object specifically for linking an
  // asm.js module. This only performs non-observable lookups, which allows
  // falling back to JavaScript proper (and hence re-executing all lookups) if
  // module instantiation fails.
  MaybeHandle<Object> LookupImportAsm(uint32_t index,
                                      Handle<String> import_name);

  // Load data segments into the memory.
  void LoadDataSegments(
      Handle<WasmTrustedInstanceData> trusted_instance_data,
      Handle<WasmTrustedInstanceData> shared_trusted_instance_data);

  void WriteGlobalValue(const WasmGlobal& global, const WasmValue& value);

  void SanitizeImports();

  // Allocate the memory.
  MaybeHandle<WasmMemoryObject> AllocateMemory(uint32_t memory_index);

  // Processes a single imported function.
  bool ProcessImportedFunction(
      Handle<WasmTrustedInstanceData> trusted_instance_data, int import_index,
      int func_index, Handle<Object> value, WellKnownImport preknown_import);

  // Initialize imported tables of type funcref.
  bool InitializeImportedIndirectFunctionTable(
      DirectHandle<WasmTrustedInstanceData> trusted_instance_data,
      int table_index, int import_index,
      DirectHandle<WasmTableObject> table_object);

  // Process a single imported table.
  bool ProcessImportedTable(
      DirectHandle<WasmTrustedInstanceData> trusted_instance_data,
      int import_index, int table_index, Handle<Object> value);

  // Process a single imported global.
  bool ProcessImportedGlobal(
      DirectHandle<WasmTrustedInstanceData> trusted_instance_data,
      int import_index, int global_index, Handle<Object> value);

  // Process a single imported WasmGlobalObject.
  bool ProcessImportedWasmGlobalObject(
      DirectHandle<WasmTrustedInstanceData> trusted_instance_data,
      int import_index, const WasmGlobal& global,
      DirectHandle<WasmGlobalObject> global_object);

  // Process the imports, including functions, tables, globals, and memory, in
  // order, loading them from the {ffi_} object. Returns the number of imported
  // functions, or {-1} on error.
  int ProcessImports(
      Handle<WasmTrustedInstanceData> trusted_instance_data,
      Handle<WasmTrustedInstanceData> shared_trusted_instance_data);

  // Process all imported memories, placing the WasmMemoryObjects in the
  // supplied {FixedArray}.
  bool ProcessImportedMemories(
      DirectHandle<FixedArray> imported_memory_objects);

  template <typename T>
  T* GetRawUntaggedGlobalPtr(const WasmGlobal& global);

  // Process initialization of globals.
  void InitGlobals(
      Handle<WasmTrustedInstanceData> trusted_instance_data,
      Handle<WasmTrustedInstanceData> shared_trusted_instance_data);

  // Process the exports, creating wrappers for functions, tables, memories,
  // and globals.
  void ProcessExports(
      Handle<WasmTrustedInstanceData> trusted_instance_data,
      Handle<WasmTrustedInstanceData> shared_trusted_instance_data);

  void SetTableInitialValues(
      Handle<WasmTrustedInstanceData> trusted_instance_data,
      Handle<WasmTrustedInstanceData> shared_trusted_instance_data);

  void LoadTableSegments(
      Handle<WasmTrustedInstanceData> trusted_instance_data,
      Handle<WasmTrustedInstanceData> shared_trusted_instance_data);

  // Creates new tags. Note that some tags might already exist if they were
  // imported, those tags will be re-used.
  void InitializeTags(
      DirectHandle<WasmTrustedInstanceData> trusted_instance_data);
};

namespace {
class WriteOutPGOTask : public v8::Task {
 public:
  explicit WriteOutPGOTask(std::weak_ptr<NativeModule> native_module)
      : native_module_(std::move(native_module)) {}

  void Run() final {
    std::shared_ptr<NativeModule> native_module = native_module_.lock();
    if (!native_module) return;
    DumpProfileToFile(native_module->module(), native_module->wire_bytes(),
                      native_module->tiering_budget_array());
    Schedule(std::move(native_module_));
  }

  static void Schedule(std::weak_ptr<NativeModule> native_module) {
    // Write out PGO info every 10 seconds.
    V8::GetCurrentPlatform()->CallDelayedOnWorkerThread(
        std::make_unique<WriteOutPGOTask>(std::move(native_module)), 10.0);
  }

 private:
  const std::weak_ptr<NativeModule> native_module_;
};

}  // namespace

MaybeHandle<WasmInstanceObject> InstantiateToInstanceObject(
    Isolate* isolate, ErrorThrower* thrower,
    Handle<WasmModuleObject> module_object, MaybeHandle<JSReceiver> imports,
    MaybeHandle<JSArrayBuffer> memory_buffer) {
  v8::metrics::Recorder::ContextId context_id =
      isolate->GetOrRegisterRecorderContextId(isolate->native_context());
  InstanceBuilder builder(isolate, context_id, thrower, module_object, imports,
                          memory_buffer);
  MaybeHandle<WasmInstanceObject> instance_object = builder.Build();
  if (!instance_object.is_null()) {
    const std::shared_ptr<NativeModule>& native_module =
        module_object->shared_native_module();
    if (v8_flags.experimental_wasm_pgo_to_file &&
        native_module->ShouldPgoDataBeWritten() &&
        native_module->module()->num_declared_functions > 0) {
      WriteOutPGOTask::Schedule(native_module);
    }
    if (builder.ExecuteStartFunction()) {
      return instance_object;
    }
  }
  DCHECK(isolate->has_exception() || thrower->error());
  return {};
}

InstanceBuilder::InstanceBuilder(Isolate* isolate,
                                 v8::metrics::Recorder::ContextId context_id,
                                 ErrorThrower* thrower,
                                 Handle<WasmModuleObject> module_object,
                                 MaybeHandle<JSReceiver> ffi,
                                 MaybeHandle<JSArrayBuffer> asmjs_memory_buffer)
    : isolate_(isolate),
      context_id_(context_id),
      enabled_(module_object->native_module()->enabled_features()),
      module_(module_object->module()),
      thrower_(thrower),
      module_object_(module_object),
      ffi_(ffi),
      asmjs_memory_buffer_(asmjs_memory_buffer),
      init_expr_zone_(isolate_->allocator(), "constant expression zone") {
  sanitized_imports_.reserve(module_->import_table.size());
  well_known_imports_.reserve(module_->num_imported_functions);
}

// Build an instance, in all of its glory.
MaybeHandle<WasmInstanceObject> InstanceBuilder::Build() {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.wasm.detailed"),
               "wasm.InstanceBuilder.Build");
  // Will check whether {ffi_} is available.
  SanitizeImports();
  if (thrower_->error()) return {};

  // From here on, we expect the build pipeline to run without exiting to JS.
  DisallowJavascriptExecution no_js(isolate_);
  // Start a timer for instantiation time, if we have a high resolution timer.
  base::ElapsedTimer timer;
  if (base::TimeTicks::IsHighResolution()) {
    timer.Start();
  }
  v8::metrics::WasmModuleInstantiated wasm_module_instantiated;
  NativeModule* native_module = module_object_->native_module();

  //--------------------------------------------------------------------------
  // Create the WebAssembly.Instance object.
  //--------------------------------------------------------------------------
  TRACE("New module instantiation for %p\n", native_module);
  Handle<WasmTrustedInstanceData> trusted_data =
      WasmTrustedInstanceData::New(isolate_, module_object_, false);
  Handle<WasmInstanceObject> instance_object{trusted_data->instance_object(),
                                             isolate_};
  bool shared = module_object_->module()->has_shared_part;
  Handle<WasmTrustedInstanceData> shared_trusted_data;
  if (shared) {
    shared_trusted_data =
        WasmTrustedInstanceData::New(isolate_, module_object_, true);
    trusted_data->set_shared_part(*shared_trusted_data);
  }

  //--------------------------------------------------------------------------
  // Set up the memory buffers and memory objects and attach them to the
  // instance.
  //--------------------------------------------------------------------------
  if (is_asmjs_module(module_)) {
    CHECK_EQ(1, module_->memories.size());
    Handle<JSArrayBuffer> buffer;
    if (!asmjs_memory_buffer_.ToHandle(&buffer)) {
      // Use an empty JSArrayBuffer for degenerate asm.js modules.
      MaybeHandle<JSArrayBuffer> new_buffer =
          isolate_->factory()->NewJSArrayBufferAndBackingStore(
              0, InitializedFlag::kUninitialized);
      if (!new_buffer.ToHandle(&buffer)) {
        thrower_->RangeError("Out of memory: asm.js memory");
        return {};
      }
      buffer->set_is_detachable(false);
    }
    // asm.js instantiation should have changed the state of the buffer (or we
    // set it above).
    CHECK(!buffer->is_detachable());

    // The maximum number of pages isn't strictly necessary for memory
    // objects used for asm.js, as they are never visible, but we might
    // as well make it accurate.
    auto maximum_pages =
        static_cast<int>(RoundUp(buffer->byte_length(), wasm::kWasmPageSize) /
                         wasm::kWasmPageSize);
    DirectHandle<WasmMemoryObject> memory_object = WasmMemoryObject::New(
        isolate_, buffer, maximum_pages, AddressType::kI32);
    constexpr int kMemoryIndexZero = 0;
    WasmMemoryObject::UseInInstance(isolate_, memory_object, trusted_data,
                                    shared_trusted_data, kMemoryIndexZero);
    trusted_data->memory_objects()->set(kMemoryIndexZero, *memory_object);
  } else {
    CHECK(asmjs_memory_buffer_.is_null());
    DirectHandle<FixedArray> memory_objects{trusted_data->memory_objects(),
                                            isolate_};
    // First process all imported memories, then allocate non-imported ones.
    if (!ProcessImportedMemories(memory_objects)) {
      return {};
    }
    // Actual Wasm modules can have multiple memories.
    static_assert(kV8MaxWasmMemories <= kMaxUInt32);
    uint32_t num_memories = static_cast<uint32_t>(module_->memories.size());
    for (uint32_t memory_index = 0; memory_index < num_memories;
         ++memory_index) {
      Handle<WasmMemoryObject> memory_object;
      if (!IsUndefined(memory_objects->get(memory_index))) {
        memory_object =
            handle(Cast<WasmMemoryObject>(memory_objects->get(memory_index)),
                   isolate_);
      } else if (AllocateMemory(memory_index).ToHandle(&memory_object)) {
        memory_objects->set(memory_index, *memory_object);
      } else {
        DCHECK(isolate_->has_exception() || thrower_->error());
        return {};
      }
      WasmMemoryObject::UseInInstance(isolate_, memory_object, trusted_data,
                                      shared_trusted_data, memory_index);
    }
  }

  //--------------------------------------------------------------------------
  // Set up the globals for the new instance.
  //--------------------------------------------------------------------------
  uint32_t untagged_globals_buffer_size = module_->untagged_globals_buffer_size;
  if (untagged_globals_buffer_size > 0) {
    MaybeHandle<JSArrayBuffer> result =
        isolate_->factory()->NewJSArrayBufferAndBackingStore(
            untagged_globals_buffer_size, InitializedFlag::kZeroInitialized,
            AllocationType::kOld);

    if (!result.ToHandle(&untagged_globals_)) {
      thrower_->RangeError("Out of memory: wasm globals");
      return {};
    }

    trusted_data->set_untagged_globals_buffer(*untagged_globals_);
    trusted_data->set_globals_start(
        reinterpret_cast<uint8_t*>(untagged_globals_->backing_store()));

    // TODO(14616): Do this only if we have a shared untagged global.
    if (shared) {
      MaybeHandle<JSArrayBuffer> shared_result =
          isolate_->factory()->NewJSArrayBufferAndBackingStore(
              untagged_globals_buffer_size, InitializedFlag::kZeroInitialized,
              AllocationType::kOld);

      if (!shared_result.ToHandle(&shared_untagged_globals_)) {
        thrower_->RangeError("Out of memory: wasm globals");
        return {};
      }

      shared_trusted_data->set_untagged_globals_buffer(
          *shared_untagged_globals_);
      shared_trusted_data->set_globals_start(reinterpret_cast<uint8_t*>(
          shared_untagged_globals_->backing_store()));
    }
  }

  uint32_t tagged_globals_buffer_size = module_->tagged_globals_buffer_size;
  if (tagged_globals_buffer_size > 0) {
    tagged_globals_ = isolate_->factory()->NewFixedArray(
        static_cast<int>(tagged_globals_buffer_size));
    trusted_data->set_tagged_globals_buffer(*tagged_globals_);
    if (shared) {
      shared_tagged_globals_ = isolate_->factory()->NewFixedArray(
          static_cast<int>(tagged_globals_buffer_size));
      shared_trusted_data->set_tagged_globals_buffer(*shared_tagged_globals_);
    }
  }

  //--------------------------------------------------------------------------
  // Set up the array of references to imported globals' array buffers.
  //--------------------------------------------------------------------------
  if (module_->num_imported_mutable_globals > 0) {
    // TODO(binji): This allocates one slot for each mutable global, which is
    // more than required if multiple globals are imported from the same
    // module.
    DirectHandle<FixedArray> buffers_array = isolate_->factory()->NewFixedArray(
        module_->num_imported_mutable_globals, AllocationType::kOld);
    trusted_data->set_imported_mutable_globals_buffers(*buffers_array);
    if (shared) {
      DirectHandle<FixedArray> shared_buffers_array =
          isolate_->factory()->NewFixedArray(
              module_->num_imported_mutable_globals, AllocationType::kOld);
      shared_trusted_data->set_imported_mutable_globals_buffers(
          *shared_buffers_array);
    }
  }

  //--------------------------------------------------------------------------
  // Set up the tag table used for exception tag checks.
  //--------------------------------------------------------------------------
  int tags_count = static_cast<int>(module_->tags.size());
  if (tags_count > 0) {
    DirectHandle<FixedArray> tag_table =
        isolate_->factory()->NewFixedArray(tags_count, AllocationType::kOld);
    trusted_data->set_tags_table(*tag_table);
    tags_wrappers_.resize(tags_count);
    if (shared) {
      DirectHandle<FixedArray> shared_tag_table =
          isolate_->factory()->NewFixedArray(tags_count, AllocationType::kOld);
      shared_trusted_data->set_tags_table(*shared_tag_table);
      shared_tags_wrappers_.resize(tags_count);
    }
  }

  //--------------------------------------------------------------------------
  // Set up table storage space.
  //--------------------------------------------------------------------------
  int table_count = static_cast<int>(module_->tables.size());
  {
    Handle<FixedArray> tables = isolate_->factory()->NewFixedArray(table_count);
    Handle<FixedArray> shared_tables =
        shared ? isolate_->factory()->NewFixedArray(table_count)
               : Handle<FixedArray>();
    for (int i = module_->num_imported_tables; i < table_count; i++) {
      const WasmTable& table = module_->tables[i];
      // Initialize tables with null for now. We will initialize non-defaultable
      // tables later, in {SetTableInitialValues}.
      DirectHandle<WasmTableObject> table_obj = WasmTableObject::New(
          isolate_, table.shared ? shared_trusted_data : trusted_data,
          table.type, table.initial_size, table.has_maximum_size,
          table.maximum_size,
          table.type.use_wasm_null()
              ? Handle<HeapObject>{isolate_->factory()->wasm_null()}
              : Handle<HeapObject>{isolate_->factory()->null_value()},
          table.address_type);
      (table.shared ? shared_tables : tables)->set(i, *table_obj);
    }
    trusted_data->set_tables(*tables);
    if (shared) shared_trusted_data->set_tables(*shared_tables);
  }

  if (table_count > 0) {
    Handle<ProtectedFixedArray> dispatch_tables =
        isolate_->factory()->NewProtectedFixedArray(table_count);
    Handle<ProtectedFixedArray> shared_dispatch_tables =
        shared ? isolate_->factory()->NewProtectedFixedArray(table_count)
               : Handle<ProtectedFixedArray>();
    for (int i = 0; i < table_count; ++i) {
      const WasmTable& table = module_->tables[i];
      if (!IsSubtypeOf(table.type, kWasmFuncRef, module_) &&
          !IsSubtypeOf(table.type, ValueType::RefNull(HeapType::kFuncShared),
                       module_)) {
        continue;
      }
      DirectHandle<WasmDispatchTable> dispatch_table =
          WasmDispatchTable::New(isolate_, table.initial_size);
      (table.shared ? shared_dispatch_tables : dispatch_tables)
          ->set(i, *dispatch_table);
    }
    trusted_data->set_dispatch_tables(*dispatch_tables);
    if (dispatch_tables->get(0) != Smi::zero()) {
      trusted_data->set_dispatch_table0(
          Cast<WasmDispatchTable>(dispatch_tables->get(0)));
    }
    if (shared) {
      shared_trusted_data->set_dispatch_tables(*shared_dispatch_tables);
      if (shared_dispatch_tables->get(0) != Smi::zero()) {
        shared_trusted_data->set_dispatch_table0(
            Cast<WasmDispatchTable>(shared_dispatch_tables->get(0)));
      }
    }
  }

  //--------------------------------------------------------------------------
  // Process the imports for the module.
  //--------------------------------------------------------------------------
  if (!module_->import_table.empty()) {
    int num_imported_functions =
        ProcessImports(trusted_data, shared_trusted_data);
    if (num_imported_functions < 0) return {};
    wasm_module_instantiated.imported_function_count = num_imported_functions;
  }

  //--------------------------------------------------------------------------
  // Create maps for managed objects (GC proposal).
  // Must happen before {InitGlobals} because globals can refer to these maps.
  //--------------------------------------------------------------------------
  if (!module_->isorecursive_canonical_type_ids.empty()) {
    // Make sure all canonical indices have been set.
    DCHECK(module_->MaxCanonicalTypeIndex().valid());
    TypeCanonicalizer::PrepareForCanonicalTypeId(
        isolate_, module_->MaxCanonicalTypeIndex());
  }
  Handle<FixedArray> non_shared_maps = isolate_->factory()->NewFixedArray(
      static_cast<int>(module_->types.size()));
  Handle<FixedArray> shared_maps =
      shared ? isolate_->factory()->NewFixedArray(
                   static_cast<int>(module_->types.size()))
             : Handle<FixedArray>();
  for (uint32_t index = 0; index < module_->types.size(); index++) {
    bool shared = module_->types[index].is_shared;
    CreateMapForType(isolate_, module_, ModuleTypeIndex{index},
                     shared ? shared_trusted_data : trusted_data,
                     instance_object, shared ? shared_maps : non_shared_maps);
  }
  trusted_data->set_managed_object_maps(*non_shared_maps);
  if (shared) shared_trusted_data->set_managed_object_maps(*shared_maps);
#if DEBUG
  for (uint32_t i = 0; i < module_->types.size(); i++) {
    DirectHandle<FixedArray> maps =
        module_->types[i].is_shared ? shared_maps : non_shared_maps;
    Tagged<Object> o = maps->get(i);
    DCHECK(IsMap(o));
    Tagged<Map> map = Cast<Map>(o);
    ModuleTypeIndex index{i};
    if (module_->has_signature(index)) {
      DCHECK_EQ(map->instance_type(), WASM_FUNC_REF_TYPE);
    } else if (module_->has_array(index)) {
      DCHECK_EQ(map->instance_type(), WASM_ARRAY_TYPE);
    } else if (module_->has_struct(index)) {
      DCHECK_EQ(map->instance_type(), WASM_STRUCT_TYPE);
    }
  }
#endif

  //--------------------------------------------------------------------------
  // Allocate the array that will hold type feedback vectors.
  //--------------------------------------------------------------------------
  if (v8_flags.wasm_inlining) {
    int num_functions = static_cast<int>(module_->num_declared_functions);
    // Zero-fill the array so we can do a quick Smi-check to test if a given
    // slot was initialized.
    DirectHandle<FixedArray> vectors =
        isolate_->factory()->NewFixedArrayWithZeroes(num_functions,
                                                     AllocationType::kOld);
    trusted_data->set_feedback_vectors(*vectors);
    if (shared) {
      DirectHandle<FixedArray> shared_vectors =
          isolate_->factory()->NewFixedArrayWithZeroes(num_functions,
                                                       AllocationType::kOld);
      shared_trusted_data->set_feedback_vectors(*shared_vectors);
    }
  }

  //--------------------------------------------------------------------------
  // Process the initialization for the module's globals.
  //--------------------------------------------------------------------------
  InitGlobals(trusted_data, shared_trusted_data);

  //--------------------------------------------------------------------------
  // Initialize the indirect function tables and dispatch tables. We do this
  // before initializing non-defaultable tables and loading element segments, so
  // that indirect function tables in this module are included in the updates
  // when we do so.
  //--------------------------------------------------------------------------
  for (int table_index = 0;
       table_index < static_cast<int>(module_->tables.size()); ++table_index) {
    const WasmTable& table = module_->tables[table_index];

    if (!IsSubtypeOf(table.type, kWasmFuncRef, module_) &&
        !IsSubtypeOf(table.type, ValueType::RefNull(HeapType::kFuncShared),
                     module_)) {
      continue;
    }
    WasmTrustedInstanceData::EnsureMinimumDispatchTableSize(
        isolate_, table.shared ? shared_trusted_data : trusted_data,
        table_index, table.initial_size);
    auto table_object =
        handle(Cast<WasmTableObject>(
                   (table.shared ? shared_trusted_data : trusted_data)
                       ->tables()
                       ->get(table_index)),
               isolate_);
    WasmTableObject::AddUse(isolate_, table_object,
                            handle(trusted_data->instance_object(), isolate_),
                            table_index);
  }

  //--------------------------------------------------------------------------
  // Initialize non-defaultable tables.
  //--------------------------------------------------------------------------
  SetTableInitialValues(trusted_data, shared_trusted_data);

  //--------------------------------------------------------------------------
  // Initialize the tags table.
  //--------------------------------------------------------------------------
  if (tags_count > 0) {
    InitializeTags(trusted_data);
  }

  //--------------------------------------------------------------------------
  // Set up the exports object for the new instance.
  //--------------------------------------------------------------------------
  ProcessExports(trusted_data, shared_trusted_data);
  if (thrower_->error()) return {};

  //--------------------------------------------------------------------------
  // Set up uninitialized element segments.
  //--------------------------------------------------------------------------
  if (!module_->elem_segments.empty()) {
    Handle<FixedArray> elements = isolate_->factory()->NewFixedArray(
        static_cast<int>(module_->elem_segments.size()));
    Handle<FixedArray> shared_elements =
        shared ? isolate_->factory()->NewFixedArray(
                     static_cast<int>(module_->elem_segments.size()))
               : Handle<FixedArray>();
    for (int i = 0; i < static_cast<int>(module_->elem_segments.size()); i++) {
      // Initialize declarative segments as empty. The rest remain
      // uninitialized.
      bool is_declarative = module_->elem_segments[i].status ==
                            WasmElemSegment::kStatusDeclarative;
      (module_->elem_segments[i].shared ? shared_elements : elements)
          ->set(i, is_declarative
                       ? Cast<Object>(*isolate_->factory()->empty_fixed_array())
                       : *isolate_->factory()->undefined_value());
    }
    trusted_data->set_element_segments(*elements);
    if (shared) shared_trusted_data->set_element_segments(*shared_elements);
  }

  //--------------------------------------------------------------------------
  // Load element segments into tables.
  //--------------------------------------------------------------------------
  if (table_count > 0) {
    LoadTableSegments(trusted_data, shared_trusted_data);
    if (thrower_->error()) return {};
  }

  //--------------------------------------------------------------------------
  // Initialize the memory by loading data segments.
  //--------------------------------------------------------------------------
  if (!module_->data_segments.empty()) {
    LoadDataSegments(trusted_data, shared_trusted_data);
    if (thrower_->error()) return {};
  }

  //--------------------------------------------------------------------------
  // Create a wrapper for the start function.
  //--------------------------------------------------------------------------
  if (module_->start_function_index >= 0) {
    int start_index = module_->start_function_index;
    auto& function = module_->functions[start_index];

    DCHECK(start_function_.is_null());
    if (function.imported) {
      ImportedFunctionEntry entry(trusted_data, module_->start_function_index);
      Tagged<Object> callable = entry.maybe_callable();
      if (IsJSFunction(callable)) {
        // If the start function was imported and calls into Blink, we have
        // to pretend that the V8 API was used to enter its correct context.
        // In order to simplify entering the context in {ExecuteStartFunction}
        // below, we just record the callable as the start function.
        start_function_ = handle(Cast<JSFunction>(callable), isolate_);
      }
    }
    if (start_function_.is_null()) {
      // TODO(clemensb): Don't generate an exported function for the start
      // function. Use CWasmEntry instead.
      bool function_is_shared = module_->type(function.sig_index).is_shared;
      DirectHandle<WasmFuncRef> func_ref =
          WasmTrustedInstanceData::GetOrCreateFuncRef(
              isolate_, function_is_shared ? shared_trusted_data : trusted_data,
              start_index);
      DirectHandle<WasmInternalFunction> internal{func_ref->internal(isolate_),
                                                  isolate_};
      start_function_ = WasmInternalFunction::GetOrCreateExternal(internal);
    }
  }

  DCHECK(!isolate_->
```