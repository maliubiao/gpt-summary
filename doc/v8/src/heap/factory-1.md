Response: The user wants a summary of the C++ code provided.
The code is part of `v8/src/heap/factory.cc` and seems to be related to object creation in the V8 JavaScript engine.
I should identify the key functionalities of this code snippet.
Since this is part 2 of 4, it's likely focusing on a specific set of object types.
The code contains methods like `NewWasmTrustedInstanceData`, `NewWasmDispatchTable`, `NewWasmTypeInfo`, `NewWasmImportData`, etc. This suggests a significant portion deals with WebAssembly related object creation.
There are also functions like `NewCell`, `NewFeedbackCell`, `NewPropertyCell`, which are more general heap objects.
The code also has functions for creating `Map` objects, which are crucial for object structure in V8.
Functions related to copying objects (`CopyJSObject`, `CopyFixedArray`, etc.) are also present.
Error object creation functions (`NewError`, `NewTypeError`, etc.) are included.
Finally, there are functions for creating specific JS objects like `NewJSObject`, `NewJSGlobalObject`, and `NewExternal`.

Based on the function names, the primary focus of this part seems to be:
1. **WebAssembly object creation:**  Functions starting with `NewWasm...` are dedicated to creating various WebAssembly-related objects.
2. **Core heap object creation:** Functions like `NewCell`, `NewFeedbackCell`, `NewPropertyCell` are for creating fundamental heap objects used in V8's internal representation.
3. **Map creation:** The `NewMap` family of functions handles the creation of `Map` objects, which define the structure and type of JavaScript objects.
4. **Object copying:** Functions like `CopyJSObject` and `CopyFixedArray` provide mechanisms for creating copies of existing objects.
5. **Error object creation:** The `NewError` family is responsible for creating different types of JavaScript error objects.
6. **General JavaScript object creation:** Functions like `NewJSObject`, `NewJSGlobalObject`, and `NewExternal` are used to create various JavaScript objects.

To illustrate the connection to JavaScript, I can pick a few of these functionalities and show how they manifest in JavaScript. For example, `NewWasm...` functions are related to how WebAssembly modules and instances are created in JavaScript. `NewError` is directly related to throwing errors in JavaScript. `NewJSObject` is the fundamental mechanism for creating plain JavaScript objects.
这个C++代码文件（`v8/src/heap/factory.cc` 的一部分）的主要功能是**创建和初始化各种V8堆中的对象**。它提供了一系列工厂方法，用于分配内存并设置对象的初始状态。

从这个部分的代码来看，其主要关注以下几个方面的对象创建：

1. **WebAssembly 相关对象:** 包含创建 WebAssembly 模块实例数据 (`WasmTrustedInstanceData`)，分发表 (`WasmDispatchTable`)，类型信息 (`WasmTypeInfo`)，导入数据 (`WasmImportData`)，快速API调用数据 (`WasmFastApiCallData`)，内部函数 (`WasmInternalFunction`)，函数引用 (`WasmFuncRef`)，JS函数数据 (`WasmJSFunctionData`)，恢复数据 (`WasmResumeData`)，暂停器对象 (`WasmSuspenderObject`)，导出函数数据 (`WasmExportedFunctionData`)，C API 函数数据 (`WasmCapiFunctionData`)，数组 (`WasmArray`)，结构体 (`WasmStruct`) 和 continuation 对象 (`WasmContinuationObject`) 的方法。

2. **基本的堆对象:** 包含创建 `Cell`，`FeedbackCell` 和 `PropertyCell` 的方法。这些是 V8 内部用于存储变量和属性的关键数据结构。

3. **Map 对象:** 提供了多种 `NewMap` 方法，用于创建 `Map` 对象。`Map` 对象定义了 JavaScript 对象的结构和布局，例如属性和类型信息。

4. **TransitionArray 对象:** 用于存储对象属性的转换信息。

5. **AllocationSite 对象:** 用于在对象分配时跟踪相关信息，用于性能优化和内联缓存。

6. **对象的复制和增长:** 提供了 `CopyJSObject` 和 `CopyFixedArray` 等方法，用于创建现有对象的副本，并可能在复制过程中调整大小。

7. **错误对象:** 包含 `NewError`, `NewTypeError`, `NewRangeError` 等方法，用于创建不同类型的 JavaScript 错误对象。

8. **特定的 JavaScript 对象:**  包含创建 `JSObject`，`JSGlobalObject` 和 `JSExternal` 对象的方法。

**它与 JavaScript 的功能的关系，以及 JavaScript 示例:**

这个文件中的 C++ 代码是 V8 引擎实现 JavaScript 功能的基础。当 JavaScript 代码执行时，V8 引擎会调用这些工厂方法来创建和管理内存中的对象，以表示 JavaScript 中的各种值和结构。

以下是一些与这段 C++ 代码功能相关的 JavaScript 示例：

**1. WebAssembly 相关对象:**

```javascript
// 当你加载和实例化一个 WebAssembly 模块时，
// V8 内部会使用 NewWasm... 系列的函数来创建相关的对象。
WebAssembly.instantiateStreaming(fetch('my_module.wasm'))
  .then(result => {
    const wasmInstance = result.instance;
    // wasmInstance 在 V8 内部就对应着一个 WasmInstanceObject，
    // 而其内部的数据（例如导入的函数等）则是由 NewWasmImportData 等函数创建的。
    wasmInstance.exports.exported_function();
  });
```

**2. 基本的堆对象 (例如 `Cell` 和 `PropertyCell`):**

这些对象在 JavaScript 中通常是不可见的，但它们是引擎内部管理变量和属性的关键。例如，当你在 JavaScript 中声明一个变量时：

```javascript
let x = 10;
```

V8 可能会在堆上分配一个 `Cell` 对象来存储 `x` 的值。当你访问对象的属性时：

```javascript
const obj = { name: "Alice" };
console.log(obj.name);
```

V8 内部可能会使用 `PropertyCell` 来存储属性 `name` 及其对应的值 "Alice"。

**3. Map 对象:**

当你创建一个新的 JavaScript 对象时，V8 会为其关联一个 `Map` 对象来描述其结构：

```javascript
const person = { name: "Bob", age: 30 };
const person2 = { name: "Charlie", age: 25 };
```

`person` 和 `person2` 可能会共享相同的 `Map` 对象，因为它们具有相同的属性结构（`name` 和 `age`）。V8 的 `NewMap` 函数负责创建和管理这些 `Map` 对象。

**4. 错误对象:**

当你抛出一个错误时，例如：

```javascript
throw new TypeError("Invalid type");
```

V8 内部会调用 `NewTypeError` 函数来创建一个 `TypeError` 对象的实例。

**5. 一般的 JavaScript 对象:**

当你创建一个新的普通 JavaScript 对象时：

```javascript
const emptyObj = {};
```

V8 会调用 `NewJSObjectFromMap` 函数，并使用 `object_function` 的初始 `Map` 来创建 `emptyObj`。

总而言之，这个 C++ 代码文件是 V8 引擎实现 JavaScript 语言特性的幕后功臣。它负责对象的创建和内存管理，使得 JavaScript 代码能够在 V8 引擎中高效地运行。虽然 JavaScript 开发者通常不会直接与这些底层的 C++ 代码交互，但理解它们的功能有助于更深入地理解 JavaScript 引擎的工作原理。

Prompt: 
```
这是目录为v8/src/heap/factory.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
ECK(IsCallable(*then));
  auto microtask = NewStructInternal<PromiseResolveThenableJobTask>(
      PROMISE_RESOLVE_THENABLE_JOB_TASK_TYPE, AllocationType::kYoung);
  DisallowGarbageCollection no_gc;
  microtask->set_promise_to_resolve(*promise_to_resolve, SKIP_WRITE_BARRIER);
  microtask->set_thenable(*thenable, SKIP_WRITE_BARRIER);
  microtask->set_then(*then, SKIP_WRITE_BARRIER);
  microtask->set_context(*context, SKIP_WRITE_BARRIER);
#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  microtask->set_continuation_preserved_embedder_data(
      isolate()->isolate_data()->continuation_preserved_embedder_data(),
      SKIP_WRITE_BARRIER);
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  return handle(microtask, isolate());
}

#if V8_ENABLE_WEBASSEMBLY

Handle<WasmTrustedInstanceData> Factory::NewWasmTrustedInstanceData() {
  Tagged<WasmTrustedInstanceData> result =
      Cast<WasmTrustedInstanceData>(AllocateRawWithImmortalMap(
          WasmTrustedInstanceData::kSize, AllocationType::kTrusted,
          read_only_roots().wasm_trusted_instance_data_map()));
  DisallowGarbageCollection no_gc;
  result->init_self_indirect_pointer(isolate());
  result->clear_padding();
  for (int offset : WasmTrustedInstanceData::kTaggedFieldOffsets) {
    result->RawField(offset).store(read_only_roots().undefined_value());
  }
  return handle(result, isolate());
}

Handle<WasmDispatchTable> Factory::NewWasmDispatchTable(int length) {
  CHECK_LE(length, WasmDispatchTable::kMaxLength);

  // TODO(jkummerow): Any chance to get a better estimate?
  size_t estimated_offheap_size = 0;
  Handle<TrustedManaged<WasmDispatchTableData>> offheap_data =
      TrustedManaged<WasmDispatchTableData>::From(
          isolate(), estimated_offheap_size,
          std::make_shared<WasmDispatchTableData>());

  int bytes = WasmDispatchTable::SizeFor(length);
  Tagged<WasmDispatchTable> result = UncheckedCast<WasmDispatchTable>(
      AllocateRawWithImmortalMap(bytes, AllocationType::kTrusted,
                                 read_only_roots().wasm_dispatch_table_map()));
  result->WriteField<int>(WasmDispatchTable::kLengthOffset, length);
  result->WriteField<int>(WasmDispatchTable::kCapacityOffset, length);
  result->set_protected_offheap_data(*offheap_data);
  for (int i = 0; i < length; ++i) {
    result->Clear(i, WasmDispatchTable::kNewEntry);
    result->clear_entry_padding(i);
  }
  return handle(result, isolate());
}

Handle<WasmTypeInfo> Factory::NewWasmTypeInfo(
    Address type_address, Handle<Map> opt_parent,
    DirectHandle<WasmTrustedInstanceData> opt_trusted_data,
    wasm::ModuleTypeIndex type_index) {
  // We pretenure WasmTypeInfo objects for two reasons:
  // (1) They are referenced by Maps, which are assumed to be long-lived,
  //     so pretenuring the WTI is a bit more efficient.
  // (2) The object visitors need to read the WasmTypeInfo to find tagged
  //     fields in Wasm structs; in the middle of a GC cycle that's only
  //     safe to do if the WTI is in old space.
  std::vector<Handle<Object>> supertypes;
  if (opt_parent.is_null()) {
    supertypes.resize(wasm::kMinimumSupertypeArraySize, undefined_value());
  } else {
    DirectHandle<WasmTypeInfo> parent_type_info(opt_parent->wasm_type_info(),
                                                isolate());
    int first_undefined_index = -1;
    for (int i = 0; i < parent_type_info->supertypes_length(); i++) {
      Handle<Object> supertype =
          handle(parent_type_info->supertypes(i), isolate());
      if (IsUndefined(*supertype) && first_undefined_index == -1) {
        first_undefined_index = i;
      }
      supertypes.emplace_back(supertype);
    }
    if (first_undefined_index >= 0) {
      supertypes[first_undefined_index] = opt_parent;
    } else {
      supertypes.emplace_back(opt_parent);
    }
  }
  Tagged<Map> map = *wasm_type_info_map();
  Tagged<WasmTypeInfo> result = Cast<WasmTypeInfo>(AllocateRawWithImmortalMap(
      WasmTypeInfo::SizeFor(static_cast<int>(supertypes.size())),
      AllocationType::kOld, map));
  DisallowGarbageCollection no_gc;
  result->set_supertypes_length(static_cast<int>(supertypes.size()));
  for (size_t i = 0; i < supertypes.size(); i++) {
    result->set_supertypes(static_cast<int>(i), *supertypes[i]);
  }
  result->init_native_type(isolate(), type_address);
  if (opt_trusted_data.is_null()) {
    result->clear_trusted_data();
  } else {
    result->set_trusted_data(*opt_trusted_data);
  }
  result->set_module_type_index(type_index.index);
  return handle(result, isolate());
}

Handle<WasmImportData> Factory::NewWasmImportData(
    DirectHandle<HeapObject> callable, wasm::Suspend suspend,
    MaybeDirectHandle<WasmTrustedInstanceData> instance_data,
    const wasm::CanonicalSig* sig) {
  Tagged<Map> map = *wasm_import_data_map();
  auto result = Cast<WasmImportData>(AllocateRawWithImmortalMap(
      map->instance_size(), AllocationType::kTrusted, map));
  DisallowGarbageCollection no_gc;
  result->set_native_context(*isolate()->native_context());
  result->set_callable(Cast<UnionOf<Undefined, JSReceiver>>(*callable));
  result->set_suspend(suspend);
  if (instance_data.is_null()) {
    result->clear_instance_data();
  } else {
    result->set_instance_data(*instance_data.ToHandleChecked());
  }
  result->set_wrapper_budget(v8_flags.wasm_wrapper_tiering_budget);
  result->set_call_origin(Smi::FromInt(WasmImportData::kInvalidCallOrigin));
  result->set_sig(sig);
  return handle(result, isolate());
}

Handle<WasmImportData> Factory::NewWasmImportData(
    DirectHandle<WasmImportData> import_data) {
  return NewWasmImportData(handle(import_data->callable(), isolate()),
                           static_cast<wasm::Suspend>(import_data->suspend()),
                           handle(import_data->instance_data(), isolate()),
                           import_data->sig());
}

Handle<WasmFastApiCallData> Factory::NewWasmFastApiCallData(
    DirectHandle<HeapObject> signature, DirectHandle<Object> callback_data) {
  Tagged<Map> map = *wasm_fast_api_call_data_map();
  auto result = Cast<WasmFastApiCallData>(AllocateRawWithImmortalMap(
      map->instance_size(), AllocationType::kOld, map));
  result->set_signature(*signature);
  result->set_callback_data(*callback_data);
  result->set_cached_map(read_only_roots().null_value());
  return handle(result, isolate());
}

Handle<WasmInternalFunction> Factory::NewWasmInternalFunction(
    DirectHandle<TrustedObject> implicit_arg, int function_index,
    uintptr_t signature_hash) {
  Tagged<WasmInternalFunction> internal =
      Cast<WasmInternalFunction>(AllocateRawWithImmortalMap(
          WasmInternalFunction::kSize, AllocationType::kTrusted,
          *wasm_internal_function_map()));
  internal->init_self_indirect_pointer(isolate());
  {
    DisallowGarbageCollection no_gc;
    internal->set_call_target(wasm::kInvalidWasmCodePointer);
    DCHECK(IsWasmTrustedInstanceData(*implicit_arg) ||
           IsWasmImportData(*implicit_arg));
    internal->set_implicit_arg(*implicit_arg);
#if V8_ENABLE_SANDBOX
    internal->set_signature_hash(signature_hash);
#endif  // V8_SANDBOX
    // Default values, will be overwritten by the caller.
    internal->set_function_index(function_index);
    internal->set_external(*undefined_value());
  }

  return handle(internal, isolate());
}

Handle<WasmFuncRef> Factory::NewWasmFuncRef(
    DirectHandle<WasmInternalFunction> internal_function,
    DirectHandle<Map> rtt) {
  Tagged<HeapObject> raw =
      AllocateRaw(WasmFuncRef::kSize, AllocationType::kOld);
  DisallowGarbageCollection no_gc;
  DCHECK_EQ(WASM_FUNC_REF_TYPE, rtt->instance_type());
  DCHECK_EQ(WasmFuncRef::kSize, rtt->instance_size());
  raw->set_map_after_allocation(isolate(), *rtt);
  Tagged<WasmFuncRef> func_ref = Cast<WasmFuncRef>(raw);
  func_ref->set_internal(*internal_function);
  return handle(func_ref, isolate());
}

Handle<WasmJSFunctionData> Factory::NewWasmJSFunctionData(
    wasm::CanonicalTypeIndex sig_index, DirectHandle<JSReceiver> callable,
    DirectHandle<Code> wrapper_code, DirectHandle<Map> rtt,
    wasm::Suspend suspend, wasm::Promise promise, uintptr_t signature_hash) {
  // TODO(clemensb): Should this be passed instead of looked up here?
  const wasm::CanonicalSig* sig =
      wasm::GetTypeCanonicalizer()->LookupFunctionSignature(sig_index);
  DirectHandle<WasmImportData> import_data = NewWasmImportData(
      callable, suspend, DirectHandle<WasmTrustedInstanceData>(), sig);

  // Rough guess for a wrapper that may be shared with other users of it.
  constexpr size_t kOffheapDataSizeEstimate = 100;
  DirectHandle<TrustedManaged<WasmJSFunctionData::OffheapData>> offheap_data =
      TrustedManaged<WasmJSFunctionData::OffheapData>::From(
          isolate(), kOffheapDataSizeEstimate,
          std::make_shared<WasmJSFunctionData::OffheapData>());

  DirectHandle<WasmInternalFunction> internal =
      NewWasmInternalFunction(import_data, -1, signature_hash);
  DirectHandle<WasmFuncRef> func_ref = NewWasmFuncRef(internal, rtt);
  WasmImportData::SetFuncRefAsCallOrigin(import_data, func_ref);
  Tagged<Map> map = *wasm_js_function_data_map();
  Tagged<WasmJSFunctionData> result =
      Cast<WasmJSFunctionData>(AllocateRawWithImmortalMap(
          map->instance_size(), AllocationType::kTrusted, map));
  result->init_self_indirect_pointer(isolate());
  DisallowGarbageCollection no_gc;
  result->set_func_ref(*func_ref);
  result->set_internal(*internal);
  result->set_wrapper_code(*wrapper_code);
  result->set_canonical_sig_index(sig_index.index);
  result->set_js_promise_flags(WasmFunctionData::SuspendField::encode(suspend) |
                               WasmFunctionData::PromiseField::encode(promise));
  result->set_protected_offheap_data(*offheap_data);
  return handle(result, isolate());
}

Handle<WasmResumeData> Factory::NewWasmResumeData(
    DirectHandle<WasmSuspenderObject> suspender, wasm::OnResume on_resume) {
  Tagged<Map> map = *wasm_resume_data_map();
  Tagged<WasmResumeData> result =
      Cast<WasmResumeData>(AllocateRawWithImmortalMap(
          map->instance_size(), AllocationType::kOld, map));
  DisallowGarbageCollection no_gc;
  result->set_suspender(*suspender);
  result->set_on_resume(static_cast<int>(on_resume));
  return handle(result, isolate());
}

Handle<WasmSuspenderObject> Factory::NewWasmSuspenderObject() {
  DirectHandle<JSPromise> promise = NewJSPromise();
  Tagged<Map> map = *wasm_suspender_object_map();
  Tagged<WasmSuspenderObject> obj =
      Cast<WasmSuspenderObject>(AllocateRawWithImmortalMap(
          map->instance_size(), AllocationType::kOld, map));
  auto suspender = handle(obj, isolate());
  // Ensure that all properties are initialized before the allocation below.
  suspender->set_continuation(*undefined_value());
  suspender->set_parent(*undefined_value());
  suspender->set_promise(*promise);
  suspender->set_resume(*undefined_value());
  suspender->set_reject(*undefined_value());
  suspender->set_state(WasmSuspenderObject::kInactive);
  // Instantiate the callable object which resumes this Suspender. This will be
  // used implicitly as the onFulfilled callback of the returned JS promise.
  DirectHandle<WasmResumeData> resume_data =
      NewWasmResumeData(suspender, wasm::OnResume::kContinue);
  Handle<SharedFunctionInfo> resume_sfi =
      NewSharedFunctionInfoForWasmResume(resume_data);
  Handle<Context> context(isolate()->native_context());
  DirectHandle<JSObject> resume =
      Factory::JSFunctionBuilder{isolate(), resume_sfi, context}.Build();

  DirectHandle<WasmResumeData> reject_data =
      isolate()->factory()->NewWasmResumeData(suspender,
                                              wasm::OnResume::kThrow);
  Handle<SharedFunctionInfo> reject_sfi =
      isolate()->factory()->NewSharedFunctionInfoForWasmResume(reject_data);
  DirectHandle<JSObject> reject =
      Factory::JSFunctionBuilder{isolate(), reject_sfi, context}.Build();
  suspender->set_resume(*resume);
  suspender->set_reject(*reject);
  return suspender;
}

Handle<WasmExportedFunctionData> Factory::NewWasmExportedFunctionData(
    DirectHandle<Code> export_wrapper,
    DirectHandle<WasmTrustedInstanceData> instance_data,
    DirectHandle<WasmFuncRef> func_ref,
    DirectHandle<WasmInternalFunction> internal_function,
    const wasm::CanonicalSig* sig, wasm::CanonicalTypeIndex type_index,
    int wrapper_budget, wasm::Promise promise) {
  int func_index = internal_function->function_index();
  DirectHandle<Cell> wrapper_budget_cell =
      NewCell(Smi::FromInt(wrapper_budget));
  Tagged<Map> map = *wasm_exported_function_data_map();
  Tagged<WasmExportedFunctionData> result =
      Cast<WasmExportedFunctionData>(AllocateRawWithImmortalMap(
          map->instance_size(), AllocationType::kTrusted, map));
  result->init_self_indirect_pointer(isolate());
  DisallowGarbageCollection no_gc;
  result->set_func_ref(*func_ref);
  result->set_internal(*internal_function);
  result->set_wrapper_code(*export_wrapper);
  result->set_instance_data(*instance_data);
  result->set_function_index(func_index);
  result->set_sig(sig);
  result->set_canonical_type_index(type_index.index);
  result->set_wrapper_budget(*wrapper_budget_cell);
  // We can't skip the write barrier because Code objects are not immovable.
  result->set_c_wrapper_code(*BUILTIN_CODE(isolate(), Illegal),
                             UPDATE_WRITE_BARRIER);
  result->set_packed_args_size(0);
  result->set_js_promise_flags(
      WasmFunctionData::SuspendField::encode(wasm::kNoSuspend) |
      WasmFunctionData::PromiseField::encode(promise));
  return handle(result, isolate());
}

Handle<WasmCapiFunctionData> Factory::NewWasmCapiFunctionData(
    Address call_target, DirectHandle<Foreign> embedder_data,
    DirectHandle<Code> wrapper_code, DirectHandle<Map> rtt,
    wasm::CanonicalTypeIndex sig_index, const wasm::CanonicalSig* sig,
    uintptr_t signature_hash) {
  DirectHandle<WasmImportData> import_data =
      NewWasmImportData(undefined_value(), wasm::kNoSuspend,
                        DirectHandle<WasmTrustedInstanceData>(), sig);
  DirectHandle<WasmInternalFunction> internal =
      NewWasmInternalFunction(import_data, -1, signature_hash);
  DirectHandle<WasmFuncRef> func_ref = NewWasmFuncRef(internal, rtt);
  WasmImportData::SetFuncRefAsCallOrigin(import_data, func_ref);
#ifdef V8_ENABLE_WASM_CODE_POINTER_TABLE
  internal->set_call_target(
      wasm::GetProcessWideWasmCodePointerTable()
          ->GetOrCreateHandleForNativeFunction(call_target));
#else
  internal->set_call_target(call_target);
#endif
  Tagged<Map> map = *wasm_capi_function_data_map();
  Tagged<WasmCapiFunctionData> result =
      Cast<WasmCapiFunctionData>(AllocateRawWithImmortalMap(
          map->instance_size(), AllocationType::kTrusted, map));
  result->init_self_indirect_pointer(isolate());
  DisallowGarbageCollection no_gc;
  result->set_func_ref(*func_ref);
  result->set_internal(*internal);
  result->set_canonical_sig_index(sig_index.index);
  result->set_wrapper_code(*wrapper_code);
  result->set_embedder_data(*embedder_data);
  result->set_sig(sig);
  result->set_js_promise_flags(
      WasmFunctionData::SuspendField::encode(wasm::kNoSuspend) |
      WasmFunctionData::PromiseField::encode(wasm::kNoPromise));
  return handle(result, isolate());
}

Tagged<WasmArray> Factory::NewWasmArrayUninitialized(uint32_t length,
                                                     DirectHandle<Map> map) {
  Tagged<HeapObject> raw =
      AllocateRaw(WasmArray::SizeFor(*map, length), AllocationType::kYoung);
  DisallowGarbageCollection no_gc;
  raw->set_map_after_allocation(isolate(), *map);
  Tagged<WasmArray> result = Cast<WasmArray>(raw);
  result->set_raw_properties_or_hash(*empty_fixed_array(), kRelaxedStore);
  result->set_length(length);
  return result;
}

Handle<WasmArray> Factory::NewWasmArray(wasm::ValueType element_type,
                                        uint32_t length,
                                        wasm::WasmValue initial_value,
                                        DirectHandle<Map> map) {
  Tagged<WasmArray> result = NewWasmArrayUninitialized(length, map);
  DisallowGarbageCollection no_gc;
  if (element_type.is_numeric()) {
    if (initial_value.zero_byte_representation()) {
      memset(reinterpret_cast<void*>(result->ElementAddress(0)), 0,
             length * element_type.value_kind_size());
    } else {
      wasm::WasmValue packed = initial_value.Packed(element_type);
      for (uint32_t i = 0; i < length; i++) {
        Address address = result->ElementAddress(i);
        packed.CopyTo(reinterpret_cast<uint8_t*>(address));
      }
    }
  } else {
    for (uint32_t i = 0; i < length; i++) {
      result->SetTaggedElement(i, initial_value.to_ref());
    }
  }
  return handle(result, isolate());
}

Handle<WasmArray> Factory::NewWasmArrayFromElements(
    const wasm::ArrayType* type, base::Vector<wasm::WasmValue> elements,
    DirectHandle<Map> map) {
  uint32_t length = static_cast<uint32_t>(elements.size());
  Tagged<WasmArray> result = NewWasmArrayUninitialized(length, map);
  DisallowGarbageCollection no_gc;
  if (type->element_type().is_numeric()) {
    for (uint32_t i = 0; i < length; i++) {
      Address address = result->ElementAddress(i);
      elements[i]
          .Packed(type->element_type())
          .CopyTo(reinterpret_cast<uint8_t*>(address));
    }
  } else {
    for (uint32_t i = 0; i < length; i++) {
      result->SetTaggedElement(i, elements[i].to_ref());
    }
  }
  return handle(result, isolate());
}

Handle<WasmArray> Factory::NewWasmArrayFromMemory(uint32_t length,
                                                  DirectHandle<Map> map,
                                                  Address source) {
  wasm::ValueType element_type =
      reinterpret_cast<wasm::ArrayType*>(map->wasm_type_info()->native_type())
          ->element_type();
  DCHECK(element_type.is_numeric());
  Tagged<WasmArray> result = NewWasmArrayUninitialized(length, map);
  DisallowGarbageCollection no_gc;
#if V8_TARGET_BIG_ENDIAN
  MemCopyAndSwitchEndianness(reinterpret_cast<void*>(result->ElementAddress(0)),
                             reinterpret_cast<void*>(source), length,
                             element_type.value_kind_size());
#else
  MemCopy(reinterpret_cast<void*>(result->ElementAddress(0)),
          reinterpret_cast<void*>(source),
          length * element_type.value_kind_size());
#endif

  return handle(result, isolate());
}

Handle<Object> Factory::NewWasmArrayFromElementSegment(
    Handle<WasmTrustedInstanceData> trusted_instance_data,
    Handle<WasmTrustedInstanceData> shared_trusted_instance_data,
    uint32_t segment_index, uint32_t start_offset, uint32_t length,
    DirectHandle<Map> map) {
  DCHECK(WasmArray::type(*map)->element_type().is_reference());

  // If the element segment has not been initialized yet, lazily initialize it
  // now.
  AccountingAllocator allocator;
  Zone zone(&allocator, ZONE_NAME);
  std::optional<MessageTemplate> opt_error = wasm::InitializeElementSegment(
      &zone, isolate(), trusted_instance_data, shared_trusted_instance_data,
      segment_index);
  if (opt_error.has_value()) {
    return handle(Smi::FromEnum(opt_error.value()), isolate());
  }

  DirectHandle<FixedArray> elements =
      handle(Cast<FixedArray>(
                 trusted_instance_data->element_segments()->get(segment_index)),
             isolate());

  Tagged<WasmArray> result = NewWasmArrayUninitialized(length, map);
  DisallowGarbageCollection no_gc;
  if (length > 0) {
    isolate()->heap()->CopyRange(result, result->ElementSlot(0),
                                 elements->RawFieldOfElementAt(start_offset),
                                 length, SKIP_WRITE_BARRIER);
  }
  return handle(result, isolate());
}

#if V8_ENABLE_DRUMBRAKE
Handle<WasmStruct> Factory::NewWasmStructUninitialized(
    const wasm::StructType* type, Handle<Map> map) {
  Tagged<HeapObject> raw =
      AllocateRaw(WasmStruct::Size(type), AllocationType::kYoung);
  raw->set_map_after_allocation(*map);
  Tagged<WasmStruct> result = Cast<WasmStruct>(raw);
  result->set_raw_properties_or_hash(*empty_fixed_array(), kRelaxedStore);
  return handle(result, isolate());
}
#endif  // V8_ENABLE_DRUMBRAKE

Handle<WasmStruct> Factory::NewWasmStruct(const wasm::StructType* type,
                                          wasm::WasmValue* args,
                                          DirectHandle<Map> map) {
  Tagged<HeapObject> raw =
      AllocateRaw(WasmStruct::Size(type), AllocationType::kYoung);
  raw->set_map_after_allocation(isolate(), *map);
  Tagged<WasmStruct> result = Cast<WasmStruct>(raw);
  result->set_raw_properties_or_hash(*empty_fixed_array(), kRelaxedStore);
  for (uint32_t i = 0; i < type->field_count(); i++) {
    int offset = type->field_offset(i);
    if (type->field(i).is_numeric()) {
      Address address = result->RawFieldAddress(offset);
      args[i]
          .Packed(type->field(i))
          .CopyTo(reinterpret_cast<uint8_t*>(address));
    } else {
      offset += WasmStruct::kHeaderSize;
      TaggedField<Object>::store(result, offset, *args[i].to_ref());
    }
  }
  return handle(result, isolate());
}

Handle<WasmContinuationObject> Factory::NewWasmContinuationObject(
    Address jmpbuf, wasm::StackMemory* stack, DirectHandle<HeapObject> parent,
    AllocationType allocation) {
  Tagged<Map> map = *wasm_continuation_object_map();
  auto result = Cast<WasmContinuationObject>(
      AllocateRawWithImmortalMap(map->instance_size(), allocation, map));
  result->init_jmpbuf(isolate(), jmpbuf);
  result->init_stack(isolate(), reinterpret_cast<Address>(stack));
  result->set_parent(Cast<UnionOf<Undefined, WasmContinuationObject>>(*parent));
  return handle(result, isolate());
}

Handle<SharedFunctionInfo>
Factory::NewSharedFunctionInfoForWasmExportedFunction(
    DirectHandle<String> name, DirectHandle<WasmExportedFunctionData> data,
    int len, AdaptArguments adapt) {
  return NewSharedFunctionInfo(name, data, Builtin::kNoBuiltinId, len, adapt);
}

Handle<SharedFunctionInfo> Factory::NewSharedFunctionInfoForWasmJSFunction(
    DirectHandle<String> name, DirectHandle<WasmJSFunctionData> data) {
  return NewSharedFunctionInfo(name, data, Builtin::kNoBuiltinId, 0,
                               kDontAdapt);
}

Handle<SharedFunctionInfo> Factory::NewSharedFunctionInfoForWasmResume(
    DirectHandle<WasmResumeData> data) {
  return NewSharedFunctionInfo({}, data, Builtin::kNoBuiltinId, 0, kDontAdapt);
}

Handle<SharedFunctionInfo> Factory::NewSharedFunctionInfoForWasmCapiFunction(
    DirectHandle<WasmCapiFunctionData> data) {
  return NewSharedFunctionInfo(MaybeHandle<String>(), data,
                               Builtin::kNoBuiltinId, 0, kDontAdapt,
                               FunctionKind::kConciseMethod);
}
#endif  // V8_ENABLE_WEBASSEMBLY

Handle<Cell> Factory::NewCell(Tagged<Smi> value) {
  static_assert(Cell::kSize <= kMaxRegularHeapObjectSize);
  Tagged<Cell> result = Cast<Cell>(AllocateRawWithImmortalMap(
      Cell::kSize, AllocationType::kOld, *cell_map()));
  DisallowGarbageCollection no_gc;
  result->set_value(value, WriteBarrierMode::SKIP_WRITE_BARRIER);
  return handle(result, isolate());
}

Handle<Cell> Factory::NewCell() {
  static_assert(Cell::kSize <= kMaxRegularHeapObjectSize);
  Tagged<Cell> result = Cast<Cell>(AllocateRawWithImmortalMap(
      Cell::kSize, AllocationType::kOld, *cell_map()));
  result->set_value(read_only_roots().undefined_value(),
                    WriteBarrierMode::SKIP_WRITE_BARRIER);
  return handle(result, isolate());
}

Handle<FeedbackCell> Factory::NewNoClosuresCell() {
  Tagged<FeedbackCell> result = Cast<FeedbackCell>(AllocateRawWithImmortalMap(
      FeedbackCell::kAlignedSize, AllocationType::kOld,
      *no_closures_cell_map()));
  DisallowGarbageCollection no_gc;
  result->set_value(read_only_roots().undefined_value());
  result->clear_interrupt_budget();
#ifdef V8_ENABLE_LEAPTIERING
  result->clear_dispatch_handle();
#endif  // V8_ENABLE_LEAPTIERING
  result->clear_padding();
  return handle(result, isolate());
}

Handle<FeedbackCell> Factory::NewOneClosureCell(
    DirectHandle<ClosureFeedbackCellArray> value) {
  Tagged<FeedbackCell> result = Cast<FeedbackCell>(AllocateRawWithImmortalMap(
      FeedbackCell::kAlignedSize, AllocationType::kOld,
      *one_closure_cell_map()));
  DisallowGarbageCollection no_gc;
  result->set_value(*value);
  result->clear_interrupt_budget();
#ifdef V8_ENABLE_LEAPTIERING
  result->clear_dispatch_handle();
#endif  // V8_ENABLE_LEAPTIERING
  result->clear_padding();
  return handle(result, isolate());
}

Handle<FeedbackCell> Factory::NewManyClosuresCell() {
  Tagged<FeedbackCell> result = Cast<FeedbackCell>(AllocateRawWithImmortalMap(
      FeedbackCell::kAlignedSize, AllocationType::kOld,
      *many_closures_cell_map()));
  DisallowGarbageCollection no_gc;
  result->set_value(read_only_roots().undefined_value());
  result->clear_interrupt_budget();
#ifdef V8_ENABLE_LEAPTIERING
  result->clear_dispatch_handle();
#endif  // V8_ENABLE_LEAPTIERING
  result->clear_padding();
  return handle(result, isolate());
}

Handle<PropertyCell> Factory::NewPropertyCell(DirectHandle<Name> name,
                                              PropertyDetails details,
                                              DirectHandle<Object> value,
                                              AllocationType allocation) {
  DCHECK(IsUniqueName(*name));
  static_assert(PropertyCell::kSize <= kMaxRegularHeapObjectSize);
  Tagged<PropertyCell> cell = Cast<PropertyCell>(AllocateRawWithImmortalMap(
      PropertyCell::kSize, allocation, *global_property_cell_map()));
  DisallowGarbageCollection no_gc;
  cell->set_dependent_code(
      DependentCode::empty_dependent_code(ReadOnlyRoots(isolate())),
      SKIP_WRITE_BARRIER);
  WriteBarrierMode mode = allocation == AllocationType::kYoung
                              ? SKIP_WRITE_BARRIER
                              : UPDATE_WRITE_BARRIER;
  cell->set_name(*name, mode);
  cell->set_value(*value, mode);
  cell->set_property_details_raw(details.AsSmi(), SKIP_WRITE_BARRIER);
  return handle(cell, isolate());
}

Handle<ContextSidePropertyCell> Factory::NewContextSidePropertyCell(
    ContextSidePropertyCell::Property property, AllocationType allocation) {
  static_assert(ContextSidePropertyCell::kSize <= kMaxRegularHeapObjectSize);
  Tagged<ContextSidePropertyCell> cell = Cast<ContextSidePropertyCell>(
      AllocateRawWithImmortalMap(ContextSidePropertyCell::kSize, allocation,
                                 *global_context_side_property_cell_map()));
  DisallowGarbageCollection no_gc;
  cell->set_context_side_property_raw(Smi::FromInt(property), kReleaseStore);
  cell->set_dependent_code(
      DependentCode::empty_dependent_code(ReadOnlyRoots(isolate())),
      SKIP_WRITE_BARRIER);
  return handle(cell, isolate());
}

Handle<PropertyCell> Factory::NewProtector() {
  return NewPropertyCell(
      empty_string(), PropertyDetails::Empty(PropertyCellType::kConstantType),
      handle(Smi::FromInt(Protectors::kProtectorValid), isolate()));
}

Handle<TransitionArray> Factory::NewTransitionArray(int number_of_transitions,
                                                    int slack) {
  int capacity = TransitionArray::LengthFor(number_of_transitions + slack);
  Handle<TransitionArray> array = Cast<TransitionArray>(
      NewWeakFixedArrayWithMap(read_only_roots().transition_array_map(),
                               capacity, AllocationType::kOld));
  // Transition arrays are AllocationType::kOld. When black allocation is on we
  // have to add the transition array to the list of
  // encountered_transition_arrays.
  Heap* heap = isolate()->heap();
  if (heap->incremental_marking()->black_allocation()) {
    heap->mark_compact_collector()->AddTransitionArray(*array);
  }
  array->WeakFixedArray::set(TransitionArray::kPrototypeTransitionsIndex,
                             Smi::zero());
  array->WeakFixedArray::set(TransitionArray::kSideStepTransitionsIndex,
                             Smi::zero());
  array->WeakFixedArray::set(TransitionArray::kTransitionLengthIndex,
                             Smi::FromInt(number_of_transitions));
  return array;
}

Handle<AllocationSite> Factory::NewAllocationSite(bool with_weak_next) {
  DirectHandle<Map> map = with_weak_next
                              ? allocation_site_map()
                              : allocation_site_without_weaknext_map();
  Handle<AllocationSite> site(
      Cast<AllocationSite>(New(map, AllocationType::kOld)), isolate());
  site->Initialize();

  if (with_weak_next) {
    // Link the site
    site->set_weak_next(isolate()->heap()->allocation_sites_list());
    isolate()->heap()->set_allocation_sites_list(*site);
  }
  return site;
}

template <typename MetaMapProviderFunc>
Handle<Map> Factory::NewMapImpl(MetaMapProviderFunc&& meta_map_provider,
                                InstanceType type, int instance_size,
                                ElementsKind elements_kind,
                                int inobject_properties,
                                AllocationType allocation_type) {
  static_assert(LAST_JS_OBJECT_TYPE == LAST_TYPE);
  DCHECK(!InstanceTypeChecker::MayHaveMapCheckFastCase(type));
  DCHECK_IMPLIES(InstanceTypeChecker::IsJSObject(type) &&
                     !Map::CanHaveFastTransitionableElementsKind(type),
                 IsDictionaryElementsKind(elements_kind) ||
                     IsTerminalElementsKind(elements_kind) ||
                     IsSharedArrayElementsKind(elements_kind));
  DCHECK(allocation_type == AllocationType::kMap ||
         allocation_type == AllocationType::kSharedMap);
  Tagged<HeapObject> result =
      allocator()->AllocateRawWith<HeapAllocator::kRetryOrFail>(
          Map::kSize, allocation_type);
  DisallowGarbageCollection no_gc;
  ReadOnlyRoots roots(isolate());
  result->set_map_after_allocation(isolate(), meta_map_provider());

#if V8_STATIC_ROOTS_BOOL
  CHECK_IMPLIES(InstanceTypeChecker::IsJSReceiver(type),
                V8HeapCompressionScheme::CompressObject(result.ptr()) >
                    InstanceTypeChecker::kNonJsReceiverMapLimit);
#endif
  isolate()->counters()->maps_created()->Increment();
  return handle(InitializeMap(Cast<Map>(result), type, instance_size,
                              elements_kind, inobject_properties, roots),
                isolate());
}

Tagged<Map> Factory::InitializeMap(Tagged<Map> map, InstanceType type,
                                   int instance_size,
                                   ElementsKind elements_kind,
                                   int inobject_properties,
                                   ReadOnlyRoots roots) {
  DisallowGarbageCollection no_gc;
  map->set_bit_field(0);
  map->set_bit_field2(Map::Bits2::NewTargetIsBaseBit::encode(true));
  int bit_field3 =
      Map::Bits3::EnumLengthBits::encode(kInvalidEnumCacheSentinel) |
      Map::Bits3::OwnsDescriptorsBit::encode(true) |
      Map::Bits3::ConstructionCounterBits::encode(Map::kNoSlackTracking) |
      Map::Bits3::IsExtensibleBit::encode(true);
  map->set_bit_field3(bit_field3);
  map->set_instance_type(type);
  map->init_prototype_and_constructor_or_back_pointer(roots);
  map->set_instance_size(instance_size);
  if (InstanceTypeChecker::IsJSObject(type)) {
    // Shared space JS objects have fixed layout and can have RO maps. No other
    // JS objects have RO maps.
    DCHECK_IMPLIES(!IsAlwaysSharedSpaceJSObjectMap(*map),
                   !ReadOnlyHeap::Contains(map));
    map->SetInObjectPropertiesStartInWords(instance_size / kTaggedSize -
                                           inobject_properties);
    DCHECK_EQ(map->GetInObjectProperties(), inobject_properties);
    map->set_prototype_validity_cell(roots.invalid_prototype_validity_cell(),
                                     kRelaxedStore);
  } else {
    DCHECK_EQ(inobject_properties, 0);
    map->set_inobject_properties_start_or_constructor_function_index(0);
    map->set_prototype_validity_cell(Map::kPrototypeChainValidSmi,
                                     kRelaxedStore, SKIP_WRITE_BARRIER);
  }
  map->set_dependent_code(DependentCode::empty_dependent_code(roots),
                          SKIP_WRITE_BARRIER);
  map->set_raw_transitions(Smi::zero(), SKIP_WRITE_BARRIER);
  map->SetInObjectUnusedPropertyFields(inobject_properties);
  map->SetInstanceDescriptors(isolate(), roots.empty_descriptor_array(), 0,
                              SKIP_WRITE_BARRIER);
  // Must be called only after |instance_type| and |instance_size| are set.
  map->set_visitor_id(Map::GetVisitorId(map));
  DCHECK(!map->is_in_retained_map_list());
  map->clear_padding();
  map->set_elements_kind(elements_kind);
  if (V8_UNLIKELY(v8_flags.log_maps)) {
    LOG(isolate(), MapCreate(map));
  }
  return map;
}

Handle<Map> Factory::NewMap(Handle<HeapObject> meta_map_holder,
                            InstanceType type, int instance_size,
                            ElementsKind elements_kind, int inobject_properties,
                            AllocationType allocation_type) {
  auto meta_map_provider = [=] {
    // Tie new map to the same native context as given |meta_map_holder| object.
    Tagged<Map> meta_map = meta_map_holder->map();
    DCHECK(IsMapMap(meta_map));
    return meta_map;
  };
  Handle<Map> map =
      NewMapImpl(meta_map_provider, type, instance_size, elements_kind,
                 inobject_properties, allocation_type);
  return map;
}

Handle<Map> Factory::NewMapWithMetaMap(Handle<Map> meta_map, InstanceType type,
                                       int instance_size,
                                       ElementsKind elements_kind,
                                       int inobject_properties,
                                       AllocationType allocation_type) {
  DCHECK_EQ(*meta_map, meta_map->map());
  auto meta_map_provider = [=] {
    // Use given meta map.
    return *meta_map;
  };
  Handle<Map> map =
      NewMapImpl(meta_map_provider, type, instance_size, elements_kind,
                 inobject_properties, allocation_type);
  return map;
}

Handle<Map> Factory::NewContextfulMap(
    Handle<JSReceiver> creation_context_holder, InstanceType type,
    int instance_size, ElementsKind elements_kind, int inobject_properties,
    AllocationType allocation_type) {
  auto meta_map_provider = [=] {
    // Tie new map to the creation context of given |creation_context_holder|
    // object.
    Tagged<Map> meta_map = creation_context_holder->map()->map();
    DCHECK(IsMapMap(meta_map));
    return meta_map;
  };
  Handle<Map> map =
      NewMapImpl(meta_map_provider, type, instance_size, elements_kind,
                 inobject_properties, allocation_type);
  return map;
}

Handle<Map> Factory::NewContextfulMap(Handle<NativeContext> native_context,
                                      InstanceType type, int instance_size,
                                      ElementsKind elements_kind,
                                      int inobject_properties,
                                      AllocationType allocation_type) {
  DCHECK(InstanceTypeChecker::IsNativeContextSpecific(type) ||
         InstanceTypeChecker::IsMap(type));
  auto meta_map_provider = [=] {
    // Tie new map to given native context.
    return native_context->meta_map();
  };
  Handle<Map> map =
      NewMapImpl(meta_map_provider, type, instance_size, elements_kind,
                 inobject_properties, allocation_type);
  return map;
}

Handle<Map> Factory::NewContextfulMapForCurrentContext(
    InstanceType type, int instance_size, ElementsKind elements_kind,
    int inobject_properties, AllocationType allocation_type) {
  DCHECK(InstanceTypeChecker::IsNativeContextSpecific(type) ||
         InstanceTypeChecker::IsMap(type));
  auto meta_map_provider = [=, this] {
    // Tie new map to current native context.
    return isolate()->raw_native_context()->meta_map();
  };
  Handle<Map> map =
      NewMapImpl(meta_map_provider, type, instance_size, elements_kind,
                 inobject_properties, allocation_type);
  return map;
}

Handle<Map> Factory::NewContextlessMap(InstanceType type, int instance_size,
                                       ElementsKind elements_kind,
                                       int inobject_properties,
                                       AllocationType allocation_type) {
  DCHECK(!InstanceTypeChecker::IsNativeContextSpecific(type) ||
         type == NATIVE_CONTEXT_TYPE ||   // just during NativeContext creation.
         type == JS_GLOBAL_PROXY_TYPE ||  // might be a placeholder object.
         type == JS_SPECIAL_API_OBJECT_TYPE ||  // might be a remote Api object.
         InstanceTypeChecker::IsMap(type));
  auto meta_map_provider = [=, this] {
    // The new map is not tied to any context.
    return ReadOnlyRoots(isolate()).meta_map();
  };
  Handle<Map> map =
      NewMapImpl(meta_map_provider, type, instance_size, elements_kind,
                 inobject_properties, allocation_type);
  return map;
}

Handle<JSObject> Factory::CopyJSObject(DirectHandle<JSObject> source) {
  return CopyJSObjectWithAllocationSite(source, Handle<AllocationSite>());
}

Handle<JSObject> Factory::CopyJSObjectWithAllocationSite(
    DirectHandle<JSObject> source, DirectHandle<AllocationSite> site) {
  DirectHandle<Map> map(source->map(), isolate());

  // We can only clone regexps, normal objects, api objects, errors or arrays.
  // Copying anything else will break invariants.
  InstanceType instance_type = map->instance_type();
  bool is_clonable_js_type =
      instance_type == JS_REG_EXP_TYPE || instance_type == JS_OBJECT_TYPE ||
      instance_type == JS_ERROR_TYPE || instance_type == JS_ARRAY_TYPE ||
      instance_type == JS_SPECIAL_API_OBJECT_TYPE ||
      InstanceTypeChecker::IsJSApiObject(instance_type);
  bool is_clonable_wasm_type = false;
#if V8_ENABLE_WEBASSEMBLY
  is_clonable_wasm_type = instance_type == WASM_GLOBAL_OBJECT_TYPE ||
                          instance_type == WASM_INSTANCE_OBJECT_TYPE ||
                          instance_type == WASM_MEMORY_OBJECT_TYPE ||
                          instance_type == WASM_MODULE_OBJECT_TYPE ||
                          instance_type == WASM_TABLE_OBJECT_TYPE;
#endif  // V8_ENABLE_WEBASSEMBLY
  CHECK(is_clonable_js_type || is_clonable_wasm_type);

  DCHECK(site.is_null() || AllocationSite::CanTrack(instance_type));

  int object_size = map->instance_size();
  int aligned_object_size = ALIGN_TO_ALLOCATION_ALIGNMENT(object_size);
  int adjusted_object_size = aligned_object_size;
  if (!site.is_null()) {
    DCHECK(V8_ALLOCATION_SITE_TRACKING_BOOL);
    adjusted_object_size +=
        ALIGN_TO_ALLOCATION_ALIGNMENT(AllocationMemento::kSize);
  }
  Tagged<HeapObject> raw_clone =
      allocator()->AllocateRawWith<HeapAllocator::kRetryOrFail>(
          adjusted_object_size, AllocationType::kYoung);

  DCHECK_NEWLY_ALLOCATED_OBJECT_IS_YOUNG(isolate(), raw_clone);

  Heap::CopyBlock(raw_clone.address(), source->address(), object_size);
  Handle<JSObject> clone(Cast<JSObject>(raw_clone), isolate());

  if (v8_flags.enable_unconditional_write_barriers) {
    // By default, we shouldn't need to update the write barrier here, as the
    // clone will be allocated in new space.
    const ObjectSlot start(raw_clone.address());
    const ObjectSlot end(raw_clone.address() + object_size);
    WriteBarrier::ForRange(isolate()->heap(), raw_clone, start, end);
  }
  if (!site.is_null()) {
    Tagged<AllocationMemento> alloc_memento = UncheckedCast<AllocationMemento>(
        Tagged<Object>(raw_clone.ptr() + aligned_object_size));
    InitializeAllocationMemento(alloc_memento, *site);
  }

  SLOW_DCHECK(clone->GetElementsKind() == source->GetElementsKind());
  Tagged<FixedArrayBase> elements = source->elements();
  // Update elements if necessary.
  if (elements->length() > 0) {
    Tagged<FixedArrayBase> elem;
    if (elements->map() == *fixed_cow_array_map()) {
      elem = elements;
    } else if (source->HasDoubleElements()) {
      elem = *CopyFixedDoubleArray(
          handle(Cast<FixedDoubleArray>(elements), isolate()));
    } else {
      elem = *CopyFixedArray(handle(Cast<FixedArray>(elements), isolate()));
    }
    clone->set_elements(elem);
  }

  // Update properties if necessary.
  if (source->HasFastProperties()) {
    Tagged<PropertyArray> properties = source->property_array();
    if (properties->length() > 0) {
      // TODO(gsathya): Do not copy hash code.
      DirectHandle<PropertyArray> prop =
          CopyArrayWithMap(direct_handle(properties, isolate()),
                           direct_handle(properties->map(), isolate()));
      clone->set_raw_properties_or_hash(*prop, kRelaxedStore);
    }
  } else {
    DirectHandle<Object> copied_properties;
    if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      copied_properties = SwissNameDictionary::ShallowCopy(
          isolate(), handle(source->property_dictionary_swiss(), isolate()));
    } else {
      copied_properties =
          CopyFixedArray(handle(source->property_dictionary(), isolate()));
    }
    clone->set_raw_properties_or_hash(*copied_properties, kRelaxedStore);
  }
  return clone;
}

namespace {
template <typename T>
void initialize_length(Tagged<T> array, int length) {
  array->set_length(length);
}

template <>
void initialize_length<PropertyArray>(Tagged<PropertyArray> array, int length) {
  array->initialize_length(length);
}

inline void InitEmbedderFields(Tagged<JSObject> obj,
                               Tagged<Object> initial_value) {
  for (int i = 0; i < obj->GetEmbedderFieldCount(); i++) {
    EmbedderDataSlot(obj, i).Initialize(initial_value);
  }
}

}  // namespace

template <typename T>
Handle<T> Factory::CopyArrayWithMap(DirectHandle<T> src, DirectHandle<Map> map,
                                    AllocationType allocation) {
  int len = src->length();
  Tagged<HeapObject> new_object = AllocateRawFixedArray(len, allocation);
  DisallowGarbageCollection no_gc;
  new_object->set_map_after_allocation(isolate(), *map, SKIP_WRITE_BARRIER);
  Tagged<T> result = Cast<T>(new_object);
  initialize_length(result, len);
  // Copy the content.
  WriteBarrierMode mode = result->GetWriteBarrierMode(no_gc);
  T::CopyElements(isolate(), result, 0, *src, 0, len, mode);
  return handle(result, isolate());
}

template <typename T>
Handle<T> Factory::CopyArrayAndGrow(DirectHandle<T> src, int grow_by,
                                    AllocationType allocation) {
  DCHECK_LT(0, grow_by);
  DCHECK_LE(grow_by, kMaxInt - src->length());
  int old_len = src->length();
  int new_len = old_len + grow_by;
  // TODO(jgruber,v8:14345): Use T::Allocate instead.
  Tagged<HeapObject> new_object = AllocateRawFixedArray(new_len, allocation);
  DisallowGarbageCollection no_gc;
  new_object->set_map_after_allocation(isolate(), src->map(),
                                       SKIP_WRITE_BARRIER);
  Tagged<T> result = Cast<T>(new_object);
  initialize_length(result, new_len);
  // Copy the content.
  WriteBarrierMode mode = result->GetWriteBarrierMode(no_gc);
  T::CopyElements(isolate(), result, 0, *src, 0, old_len, mode);
  // TODO(jgruber,v8:14345): Enable the static assert once all T's support it:
  // static_assert(T::kElementSize == kTaggedSize);
  MemsetTagged(ObjectSlot(result->RawFieldOfElementAt(old_len)),
               read_only_roots().undefined_value(), grow_by);
  return handle(result, isolate());
}

Handle<FixedArray> Factory::CopyFixedArrayWithMap(
    DirectHandle<FixedArray> array, DirectHandle<Map> map,
    AllocationType allocation) {
  return CopyArrayWithMap(array, map, allocation);
}

Handle<WeakArrayList> Factory::NewUninitializedWeakArrayList(
    int capacity, AllocationType allocation) {
  DCHECK_LE(0, capacity);
  if (capacity == 0) return empty_weak_array_list();

  Tagged<HeapObject> heap_object =
      AllocateRawWeakArrayList(capacity, allocation);
  DisallowGarbageCollection no_gc;
  heap_object->set_map_after_allocation(isolate(), *weak_array_list_map(),
                                        SKIP_WRITE_BARRIER);
  Tagged<WeakArrayList> result = Cast<WeakArrayList>(heap_object);
  result->set_length(0);
  result->set_capacity(capacity);
  return handle(result, isolate());
}

Handle<WeakArrayList> Factory::NewWeakArrayList(int capacity,
                                                AllocationType allocation) {
  Handle<WeakArrayList> result =
      NewUninitializedWeakArrayList(capacity, allocation);
  MemsetTagged(ObjectSlot(result->data_start()),
               read_only_roots().undefined_value(), capacity);
  return result;
}

Handle<FixedArray> Factory::CopyFixedArrayAndGrow(
    DirectHandle<FixedArray> array, int grow_by, AllocationType allocation) {
  return CopyArrayAndGrow(array, grow_by, allocation);
}

Handle<WeakFixedArray> Factory::CopyWeakFixedArray(
    DirectHandle<WeakFixedArray> src) {
  DCHECK(!IsTransitionArray(*src));  // Compacted by GC, this code doesn't work
  return CopyArrayWithMap(src, weak_fixed_array_map(), AllocationType::kOld);
}

Handle<WeakFixedArray> Factory::CopyWeakFixedArrayAndGrow(
    DirectHandle<WeakFixedArray> src, int grow_by) {
  DCHECK(!IsTransitionArray(*src));  // Compacted by GC, this code doesn't work
  return CopyArrayAndGrow(src, grow_by, AllocationType::kOld);
}

Handle<WeakArrayList> Factory::CopyWeakArrayListAndGrow(
    DirectHandle<WeakArrayList> src, int grow_by, AllocationType allocation) {
  int old_capacity = src->capacity();
  int new_capacity = old_capacity + grow_by;
  DCHECK_GE(new_capacity, old_capacity);
  Handle<WeakArrayList> result =
      NewUninitializedWeakArrayList(new_capacity, allocation);
  DisallowGarbageCollection no_gc;
  Tagged<WeakArrayList> raw = *result;
  int old_len = src->length();
  raw->set_length(old_len);
  // Copy the content.
  WriteBarrierMode mode = raw->GetWriteBarrierMode(no_gc);
  raw->CopyElements(isolate(), 0, *src, 0, old_len, mode);
  MemsetTagged(ObjectSlot(raw->data_start() + old_len),
               read_only_roots().undefined_value(), new_capacity - old_len);
  return result;
}

Handle<WeakArrayList> Factory::CompactWeakArrayList(
    DirectHandle<WeakArrayList> src, int new_capacity,
    AllocationType allocation) {
  Handle<WeakArrayList> result =
      NewUninitializedWeakArrayList(new_capacity, allocation);

  // Copy the content.
  DisallowGarbageCollection no_gc;
  Tagged<WeakArrayList> raw_src = *src;
  Tagged<WeakArrayList> raw_result = *result;
  WriteBarrierMode mode = raw_result->GetWriteBarrierMode(no_gc);
  int copy_to = 0, length = raw_src->length();
  for (int i = 0; i < length; i++) {
    Tagged<MaybeObject> element = raw_src->Get(i);
    if (element.IsCleared()) continue;
    raw_result->Set(copy_to++, element, mode);
  }
  raw_result->set_length(copy_to);

  MemsetTagged(ObjectSlot(raw_result->data_start() + copy_to),
               read_only_roots().undefined_value(), new_capacity - copy_to);
  return result;
}

Handle<PropertyArray> Factory::CopyPropertyArrayAndGrow(
    DirectHandle<PropertyArray> array, int grow_by) {
  return CopyArrayAndGrow(array, grow_by, AllocationType::kYoung);
}

Handle<FixedArray> Factory::CopyFixedArrayUpTo(DirectHandle<FixedArray> array,
                                               int new_len,
                                               AllocationType allocation) {
  DCHECK_LE(0, new_len);
  DCHECK_LE(new_len, array->length());
  if (new_len == 0) return empty_fixed_array();
  Tagged<HeapObject> heap_object = AllocateRawFixedArray(new_len, allocation);
  DisallowGarbageCollection no_gc;
  heap_object->set_map_after_allocation(isolate(), *fixed_array_map(),
                                        SKIP_WRITE_BARRIER);
  Tagged<FixedArray> result = Cast<FixedArray>(heap_object);
  result->set_length(new_len);
  // Copy the content.
  WriteBarrierMode mode = result->GetWriteBarrierMode(no_gc);
  result->CopyElements(isolate(), 0, *array, 0, new_len, mode);
  return handle(result, isolate());
}

Handle<FixedArray> Factory::CopyFixedArray(Handle<FixedArray> array) {
  if (array->length() == 0) return array;
  return CopyArrayWithMap(DirectHandle<FixedArray>(array),
                          direct_handle(array->map(), isolate()));
}

Handle<FixedDoubleArray> Factory::CopyFixedDoubleArray(
    Handle<FixedDoubleArray> array) {
  int len = array->length();
  if (len == 0) return array;
  Handle<FixedDoubleArray> result =
      Cast<FixedDoubleArray>(NewFixedDoubleArray(len));
  Heap::CopyBlock(
      result->address() + offsetof(FixedDoubleArray, length_),
      array->address() + offsetof(FixedDoubleArray, length_),
      FixedDoubleArray::SizeFor(len) - offsetof(FixedDoubleArray, length_));
  return result;
}

Handle<HeapNumber> Factory::NewHeapNumberForCodeAssembler(double value) {
  ReadOnlyRoots roots(isolate());
  auto num = roots.FindHeapNumber(value);
  if (!num.is_null()) return num;
  // Add known HeapNumber constants to the read only roots. This ensures
  // r/o snapshots to be deterministic.
  DCHECK(!CanAllocateInReadOnlySpace());
  return NewHeapNumber<AllocationType::kOld>(value);
}

Handle<JSObject> Factory::NewError(
    Handle<JSFunction> constructor, MessageTemplate template_index,
    base::Vector<const DirectHandle<Object>> args) {
  HandleScope scope(isolate());

  return scope.CloseAndEscape(ErrorUtils::MakeGenericError(
      isolate(), constructor, template_index, args, SKIP_NONE));
}

Handle<JSObject> Factory::NewError(Handle<JSFunction> constructor,
                                   DirectHandle<String> message,
                                   Handle<Object> options) {
  // Construct a new error object. If an exception is thrown, use the exception
  // as the result.

  Handle<Object> no_caller;
  if (options.is_null()) options = undefined_value();
  return ErrorUtils::Construct(isolate(), constructor, constructor, message,
                               options, SKIP_NONE, no_caller,
                               ErrorUtils::StackTraceCollection::kEnabled)
      .ToHandleChecked();
}

Handle<JSObject> Factory::ShadowRealmNewTypeErrorCopy(
    Handle<Object> original, MessageTemplate template_index,
    base::Vector<const DirectHandle<Object>> args) {
  return ErrorUtils::ShadowRealmConstructTypeErrorCopy(isolate(), original,
                                                       template_index, args);
}

Handle<Object> Factory::NewInvalidStringLengthError() {
  if (v8_flags.correctness_fuzzer_suppressions) {
    FATAL("Aborting on invalid string length");
  }
  // Invalidate the "string length" protector.
  if (Protectors::IsStringLengthOverflowLookupChainIntact(isolate())) {
    Protectors::InvalidateStringLengthOverflowLookupChain(isolate());
  }
  return NewRangeError(MessageTemplate::kInvalidStringLength);
}

Handle<JSObject> Factory::NewSuppressedErrorAtDisposal(
    Isolate* isolate, Handle<Object> error, Handle<Object> suppressed_error) {
  Handle<JSObject> err =
      NewSuppressedError(MessageTemplate::kSuppressedErrorDuringDisposal);

  JSObject::SetOwnPropertyIgnoreAttributes(
      err, isolate->factory()->error_string(), error, DONT_ENUM)
      .Assert();

  JSObject::SetOwnPropertyIgnoreAttributes(
      err, isolate->factory()->suppressed_string(), suppressed_error, DONT_ENUM)
      .Assert();

  return err;
}

#define DEFINE_ERROR(NAME, name)                                         \
  Handle<JSObject> Factory::New##NAME(                                   \
      MessageTemplate template_index,                                    \
      base::Vector<const DirectHandle<Object>> args) {                   \
    return NewError(isolate()->name##_function(), template_index, args); \
  }
DEFINE_ERROR(Error, error)
DEFINE_ERROR(EvalError, eval_error)
DEFINE_ERROR(RangeError, range_error)
DEFINE_ERROR(ReferenceError, reference_error)
DEFINE_ERROR(SyntaxError, syntax_error)
DEFINE_ERROR(SuppressedError, suppressed_error)
DEFINE_ERROR(TypeError, type_error)
DEFINE_ERROR(WasmCompileError, wasm_compile_error)
DEFINE_ERROR(WasmLinkError, wasm_link_error)
DEFINE_ERROR(WasmRuntimeError, wasm_runtime_error)
#undef DEFINE_ERROR

Handle<JSObject> Factory::NewFunctionPrototype(
    DirectHandle<JSFunction> function) {
  // Make sure to use globals from the function's context, since the function
  // can be from a different context.
  DirectHandle<NativeContext> native_context(function->native_context(),
                                             isolate());
  DirectHandle<Map> new_map;
  if (V8_UNLIKELY(IsAsyncGeneratorFunction(function->shared()->kind()))) {
    new_map = direct_handle(
        native_context->async_generator_object_prototype_map(), isolate());
  } else if (IsResumableFunction(function->shared()->kind())) {
    // Generator and async function prototypes can share maps since they
    // don't have "constructor" properties.
    new_map = direct_handle(native_context->generator_object_prototype_map(),
                            isolate());
  } else {
    // Each function prototype gets a fresh map to avoid unwanted sharing of
    // maps between prototypes of different constructors.
    DirectHandle<JSFunction> object_function(native_context->object_function(),
                                             isolate());
    DCHECK(object_function->has_initial_map());
    new_map = direct_handle(object_function->initial_map(), isolate());
  }

  DCHECK(!new_map->is_prototype_map());
  Handle<JSObject> prototype = NewJSObjectFromMap(new_map);

  if (!IsResumableFunction(function->shared()->kind())) {
    JSObject::AddProperty(isolate(), prototype, constructor_string(), function,
                          DONT_ENUM);
  }

  return prototype;
}

Handle<JSObject> Factory::NewExternal(void* value,
                                      AllocationType allocation_type) {
  auto external = Cast<JSExternalObject>(
      NewJSObjectFromMap(external_map(), allocation_type));
  external->init_value(isolate(), value);
  return external;
}

Handle<Code> Factory::NewCodeObjectForEmbeddedBuiltin(DirectHandle<Code> code,
                                                      Address off_heap_entry) {
  CHECK_NOT_NULL(isolate()->embedded_blob_code());
  CHECK_NE(0, isolate()->embedded_blob_code_size());
  CHECK(Builtins::IsIsolateIndependentBuiltin(*code));

  DCHECK(code->has_instruction_stream());  // Just generated as on-heap code.
  DCHECK(Builtins::IsBuiltinId(code->builtin_id()));
  DCHECK_EQ(code->inlined_bytecode_size(), 0);
  DCHECK_EQ(code->osr_offset(), BytecodeOffset::None());
  DCHECK_EQ(code->raw_deoptimization_data_or_interpreter_data(), Smi::zero());
  // .. because we don't explicitly initialize these flags:
  DCHECK(!code->marked_for_deoptimization());
  DCHECK(!code->can_have_weak_objects());
  DCHECK(!code->embedded_objects_cleared());
  // This check would fail. We explicitly clear any existing position tables
  // below. Note this isn't strictly necessary - we could keep the position
  // tables if we'd properly allocate them into RO space when needed.
  // DCHECK_EQ(code->raw_position_table(), *empty_byte_array());

  NewCodeOptions new_code_options = {
      code->kind(),
      code->builtin_id(),
      code->is_context_specialized(),
      code->is_turbofanned(),
      code->parameter_count(),
      code->instruction_size(),
      code->metadata_size(),
      code->inlined_bytecode_size(),
      code->osr_offset(),
      code->handler_table_offset(),
      code->constant_pool_offset(),
      code->code_comments_offset(),
      code->builtin_jump_table_info_offset(),
      code->unwinding_info_offset(),
      MaybeHandle<TrustedObject>{},
      MaybeHandle<DeoptimizationData>{},
      /*bytecode_offset_table=*/MaybeHandle<TrustedByteArray>{},
      /*source_position_table=*/MaybeHandle<TrustedByteArray>{},
      MaybeHandle<InstructionStream>{},
      off_heap_entry,
  };

  return NewCode(new_code_options);
}

Handle<BytecodeArray> Factory::CopyBytecodeArray(
    DirectHandle<BytecodeArray> source) {
  DirectHandle<BytecodeWrapper> wrapper = NewBytecodeWrapper();
  int size = BytecodeArray::SizeFor(source->length());
  Tagged<BytecodeArray> copy = Cast<BytecodeArray>(AllocateRawWithImmortalMap(
      size, AllocationType::kTrusted, *bytecode_array_map()));
  DisallowGarbageCollection no_gc;
  Tagged<BytecodeArray> raw_source = *source;
  copy->init_self_indirect_pointer(isolate());
  copy->set_length(raw_source->length());
  copy->set_frame_size(raw_source->frame_size());
  copy->set_parameter_count(raw_source->parameter_count());
  copy->set_max_arguments(raw_source->max_arguments());
  copy->set_incoming_new_target_or_generator_register(
      raw_source->incoming_new_target_or_generator_register());
  copy->set_constant_pool(raw_source->constant_pool());
  copy->set_handler_table(raw_source->handler_table());
  copy->set_wrapper(*wrapper);
  if (raw_source->has_source_position_table(kAcquireLoad)) {
    copy->set_source_position_table(
        raw_source->source_position_table(kAcquireLoad), kReleaseStore);
  } else {
    copy->clear_source_position_table(kReleaseStore);
  }
  raw_source->CopyBytecodesTo(copy);
  wrapper->set_bytecode(copy);
  return handle(copy, isolate());
}

Handle<JSObject> Factory::NewJSObject(Handle<JSFunction> constructor,
                                      AllocationType allocation,
                                      NewJSObjectType new_js_object_type) {
  JSFunction::EnsureHasInitialMap(constructor);
  DirectHandle<Map> map(constructor->initial_map(), isolate());
  // NewJSObjectFromMap does not support creating dictionary mode objects. Need
  // to use NewSlowJSObjectFromMap instead.
  DCHECK(!map->is_dictionary_map());
  return NewJSObjectFromMap(map, allocation,
                            DirectHandle<AllocationSite>::null(),
                            new_js_object_type);
}

Handle<JSObject> Factory::NewSlowJSObjectWithNullProto() {
  Handle<JSObject> result =
      NewSlowJSObjectFromMap(isolate()->slow_object_with_null_prototype_map());
  return result;
}

Handle<JSObject> Factory::NewJSObjectWithNullProto() {
  Handle<Map> map(isolate()->object_function()->initial_map(), isolate());
  DirectHandle<Map> map_with_null_proto =
      Map::TransitionRootMapToPrototypeForNewObject(isolate(), map,
                                                    null_value());
  return NewJSObjectFromMap(map_with_null_proto);
}

Handle<JSGlobalObject> Factory::NewJSGlobalObject(
    DirectHandle<JSFunction> constructor) {
  DCHECK(constructor->has_initial_map());
  Handle<Map> map(constructor->initial_map(), isolate());
  DCHECK(map->is_dictionary_map());

  // Make sure no field properties are described in the initial map.
  // This guarantees us that normalizing the properties does not
  // require us to change property values to PropertyCells.
  DCHECK_EQ(map->NextFreePropertyIndex(), 0);

  // Make sure we don't have a ton of pre-allocated slots in the
  // global objects. They will be unused once we normalize the object.
  DCHECK_EQ(map->UnusedPropertyFields(), 0);
  DCHECK_EQ(map->GetInObjectProperties(), 0);

  // Initial size of the backing store to avoid resize of the storage during
  // bootstrapping. The size differs between the JS global object ad the
  // builtins object.
  int initial_size = 64;

  // Allocate a dictionary object for backing storage.
  int at_least_space_for = map->NumberOfOwnDescriptors() * 2 + initial_size;
  Handle<GlobalDictionary> dictionary =
      GlobalDictionary::New(isolate(), at_least_space_for);

  // The global object might be created from an object template with accessors.
  // Fill these accessors into the dictionary.
  DirectHandle<DescriptorArray> descs(map->instance_descriptors(isolate()),
                                      isolate());
  for (InternalIndex i : map->IterateOwnDescriptors()) {
    PropertyDetails details = descs->GetDetails(i);
    // Only accessors are expected.
    DCHECK_EQ(PropertyKind::kAccessor, details.kind());
    PropertyDetails d(PropertyKind::kAccessor, details.attributes(),
                      PropertyCellType::kMutable);
    Handle<Name> name(descs->GetKey(i), isolate());
    DirectHandle<Object> value(descs->GetStrongValue(i), isolate());
    Handle<PropertyCell> cell = NewPropertyCell(name, d, value);
    // |dictionary| already contains enough space for all properties.
    USE(GlobalDictionary::Add(isolate(), dictionary, name, cell, d));
  }

  // Allocate the global object and initialize it with the backing store.
  Handle<JSGlobalObject> global(
      Cast<JSGlobalObject>(New(map, AllocationType::kOld)), isolate());
  InitializeJSObjectFromMap(*global, *dictionary, *map,
                            NewJSObjectType::kAPIWrapper);

  // Create a new map for the global object.
  DirectHandle<Map> new_map = Map::CopyDropDescriptors(isolate(), map);
  Tagged<Map> raw_map = *new_map;
  raw_map->set_may_have_interesting_properties(true);
  raw_map->set_is_dictionary_map(true);
  LOG(isolate(), MapDetails(raw_map));

  // Set up the global object as a normalized object.
  global->set_global_dictionary(*dictionary, kReleaseStore);
  global->set_map(isolate(), raw_map, kReleaseStore);

  // Make sure result is a global object with properties in dictionary.
  DCHECK(IsJSGlobalObject(*global) && !global->HasFastProperties());
  return global;
}

void Factory::InitializeCppHeapWrapper(Tagged<JSObject> obj) {
  DCHECK(IsJSApiWrapperObject(obj));
  DCHECK(IsJSAPIObjectWithEmbedderSlots(obj) || IsJSSpecialObject(obj));
  static_assert(JSSpecialObject::kCppHeapWrappableOffset ==
                JSAPIObjectWithEmbedderSlots::kCppHeapWrappableOffset);
  obj->SetupLazilyInitializedCppHeapPointerField(
      JSAPIObjectWithEmbedderSlots::kCppHeapWrappableOffset);
}

void Factory::InitializeJSObjectFromMap(Tagged<JSObject> obj,
                                        Tagged<Object> properties,
                                        Tagged<Map> map,
                                        NewJSObjectType new_js_object_type) {
  DisallowGarbageCollection no_gc;
  obj->set_raw_properties_or_hash(properties, kRelaxedStore);
  obj->initialize_elements();
  // TODO(1240798): Initialize the object's body using valid initial values
  // according to the object's initial map.  For example, if the map's
  // instance type is JS_ARRAY_TYPE, the length field should be initialized
  // to a number (e.g. Smi::zero()) and the elements initialized to a
  // fixed array (e.g. Heap::empty_fixed_array()).  Currently, the object
  // verification code has to cope with (temporarily) invalid objects.  See
  // for example, JSArray::JSArrayVerify).
  DCHECK_EQ(IsJSApiWrapperObject(map),
            new_js_object_type == NewJSObjectType::kAPIWrapper);
  InitializeJSObjectBody(obj, map,
                         new_js_object_type == NewJSObjectType::kNoAPIWrapper
                             ? JSObject::kHeaderSize
                             : JSAPIObjectWithEmbedderSlots::kHeaderSize);
  if (new_js_object_type == NewJSObjectType::kAPIWrapper) {
    InitializeCppHeapWrapper(obj);
  }
}

void Factory::InitializeJSObjectBody(Tagged<JSObject> obj, Tagged<Map> map,
                                     int start_offset) {
  DisallowGarbageCollection no_gc;
  if (start_offset == map->instance_size()) return;
  DCHECK_LT(start_offset, map->instance_size());

  // We cannot always fill with one_pointer_filler_map because objects
  // created from API functions expect their embedder fields to be initialized
  // with undefined_value.
  // Pre-allocated fields need to be initialized with undefined_value as well
  // so that object accesses before the constructor completes (e.g. in the
  // debugger) will not cause a crash.

  // In case of Array subclassing the |map| could already be transitioned
  // to different elements kind from the initial map on which we track slack.
  bool in_progress = map->IsInobjectSlackTrackingInProgress();
  obj->InitializeBody(map, start_offset, in_progress,
                      ReadOnlyRoots(isolate()).one_pointer_filler_map_word(),
                      *undefined_value());
  if (in_progress) {
    map->FindRootMap(isolate())->InobjectSlackTrackingStep(isolate());
  }
}

Handle<JSObject> Factory::NewJSObjectFromMap(
    DirectHandle<Map> map, AllocationType allocation,
    DirectHandle<AllocationSite> allocation_site,
    NewJSObjectType new_js_object_type) {
  // JSFunctions should be allocated using AllocateFunction to be
  // properly initialized.
  DCHECK(!InstanceTypeChecker::IsJSFunction(*map));

  // Both types of global objects should be allocated using
  // AllocateGlobalObject to be properly initialized.
  DCHECK_NE(map->instance_type(), JS_GLOBAL_OBJECT_TYPE);

  Tagged<JSObject> js_obj = Cast<JSObject>(
      AllocateRawWithAllocationSite(map, allocation, allocation_site));

  InitializeJSObjectFromMap(js_obj, *empty_fixed_array(), *map,
                            new_js_object_type);

  DCHECK(js_obj->HasFastElements() ||
         (isolate()->bootstrapper()->IsActive() ||
          *map == isolate()
                      ->raw_native_context()
                      ->js_array_template_literal_object_map()) ||
         js_obj->HasTypedArrayOrRabGsabTypedArrayElements() ||
         js_obj->HasFastStringWrapperElements() ||
         js_obj->HasFastArgumentsElements() ||
         js_obj->
"""


```