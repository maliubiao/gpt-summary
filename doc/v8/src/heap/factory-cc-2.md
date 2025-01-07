Response:
My thinking process to address the request goes like this:

1. **Understand the Core Request:** The user wants to understand the functionality of the provided C++ code snippet from `v8/src/heap/factory.cc`. The request also includes specific constraints about handling Torque, JavaScript relationships, code logic, common errors, and summarizing the functionality. It's part 3 of a 7-part series, so focusing on this specific snippet is key.

2. **Initial Code Scan and Keyword Recognition:** I quickly scan the code looking for keywords and patterns. I see things like `NewStructInternal`, `WasmTrustedInstanceData`, `WasmDispatchTable`, `WasmTypeInfo`, `WasmImportData`, `WasmFastApiCallData`, `WasmInternalFunction`, `WasmFuncRef`, `WasmJSFunctionData`, `WasmResumeData`, `WasmSuspenderObject`, `WasmExportedFunctionData`, `WasmCapiFunctionData`, `WasmArray`, `WasmStruct`, `WasmContinuationObject`, `NewCell`, `NewFeedbackCell`, `NewPropertyCell`, `NewTransitionArray`, `NewAllocationSite`, and `NewMapImpl`. The repeated use of `Factory::New...` strongly suggests this code is about creating and initializing various V8 internal objects. The "Wasm" prefix is also prominent, indicating WebAssembly related object creation.

3. **Categorize Functionality:** Based on the keywords, I start to group the functions by the type of object they create. This immediately reveals two major categories:
    * **Promise/Microtask Related:** `NewPromiseResolveThenableJobTask`
    * **WebAssembly Related:**  A large number of functions starting with `NewWasm...`

4. **Analyze Each Function (or Group of Similar Functions):** I go through each function (or closely related groups) and try to deduce its purpose. I pay attention to:
    * **Return Type:**  What kind of object is being created (e.g., `Handle<PromiseResolveThenableJobTask>`, `Handle<WasmTrustedInstanceData>`). The `Handle<>` indicates these are managed V8 objects.
    * **Parameters:** What information is needed to create the object? This gives clues about the object's properties and how it's used.
    * **Internal Logic:**  What are the key steps in the function?  Are fields being set? Is memory being allocated? Are there checks or assertions? The `AllocateRawWithImmortalMap` pattern is a strong indicator of allocating objects in specific memory spaces with associated maps (object type metadata).
    * **Naming Conventions:** The names themselves are often very descriptive (e.g., `NewWasmExportedFunctionData`).

5. **Address Specific Constraints:**  As I analyze, I keep the user's specific requirements in mind:

    * **Torque:** The prompt explicitly asks about `.tq` files. I note that this file is `.cc`, so it's not Torque.
    * **JavaScript Relationship:** For functions that seem related to JavaScript concepts (like Promises), I try to provide a simple JavaScript analogy. For WebAssembly-related functions, the connection is less direct but can be explained in terms of how WebAssembly interacts with JavaScript.
    * **Code Logic and Examples:**  For some functions, simple input/output examples are possible (though often the internal state of V8 objects makes concrete examples complex). I focus on illustrating the *purpose* rather than providing executable code.
    * **Common Programming Errors:** I think about how the creation or use of these internal objects *might* relate to errors a JavaScript developer could encounter (even if they don't directly manipulate these objects).
    * **Summarization:** The final step is to synthesize the information into a concise summary.

6. **Refine and Organize:**  I organize my findings logically, using headings and bullet points for clarity. I ensure the language is clear and avoids excessive technical jargon where possible.

**Self-Correction/Refinement Example during the Process:**

Initially, I might just list the functions. However, I realize that grouping them by category (Promises, WebAssembly, etc.) makes the explanation much clearer. I also realize that for the WebAssembly functions, a high-level explanation of their roles in the WebAssembly execution pipeline is more helpful than trying to go into minute detail about each field. I also recognize that providing *direct* JavaScript equivalents for many of the Wasm objects isn't really feasible or accurate, so I shift to explaining the conceptual relationship. I might also initially focus too much on the low-level memory allocation details and then correct to emphasize the *purpose* of the object being created.

By following these steps, iteratively analyzing the code, and keeping the user's constraints in mind, I arrive at the comprehensive explanation provided in the example answer.
好的，让我们来分析一下 `v8/src/heap/factory.cc` 的这段代码片段的功能。

**核心功能归纳：**

这段代码的主要功能是为 V8 引擎创建和初始化各种内部对象。这些对象在 V8 的执行过程中扮演着不同的角色，例如管理异步操作、支持 WebAssembly、存储函数信息等等。 `Factory` 类是 V8 中负责对象创建的核心组件之一。

**具体功能分解：**

1. **`NewPromiseResolveThenableJobTask`**:
   - **功能:** 创建并初始化一个 `PromiseResolveThenableJobTask` 对象。这个对象用于表示当 Promise 的 `then` 方法接收到一个 thenable 对象（具有 `then` 方法的对象）时，需要执行的微任务。
   - **JavaScript 关联:** 当你在 JavaScript 中使用 `Promise.resolve(thenable)` 并且 `thenable` 不是一个 Promise 时，V8 会创建一个微任务来处理 `thenable` 的 `then` 方法。
   - **JavaScript 示例:**
     ```javascript
     const thenable = {
       then: (resolve, reject) => {
         resolve('resolved by thenable');
       }
     };
     Promise.resolve(thenable).then(value => console.log(value)); // 输出: resolved by thenable
     ```
   - **代码逻辑推理:**
     - **假设输入:** 一个待解决的 Promise 对象 `promise_to_resolve`，一个 thenable 对象 `thenable`，thenable 的 `then` 方法 `then`，以及当前的上下文 `context`。
     - **输出:** 一个指向新创建的 `PromiseResolveThenableJobTask` 对象的句柄 `Handle<PromiseResolveThenableJobTask>`。
     - 代码首先断言 `then` 是可调用的 (`IsCallable(*then)`)。然后，它分配一个新的 `PromiseResolveThenableJobTask` 结构体，并设置其内部字段，例如待解决的 Promise、thenable 对象、`then` 方法和上下文。

2. **WebAssembly 相关对象创建 (`#if V8_ENABLE_WEBASSEMBLY`)**:
   - 这部分代码包含了多个以 `NewWasm...` 开头的函数，它们负责创建和初始化与 WebAssembly 相关的各种内部对象。
   - **`NewWasmTrustedInstanceData`**: 创建 WebAssembly 实例的受信任数据。
   - **`NewWasmDispatchTable`**: 创建 WebAssembly 的分发表格，用于间接调用。
   - **`NewWasmTypeInfo`**: 创建 WebAssembly 类型的元数据信息。
   - **`NewWasmImportData`**: 创建 WebAssembly 导入函数的元数据。
   - **`NewWasmFastApiCallData`**: 创建 WebAssembly Fast API 调用的数据。
   - **`NewWasmInternalFunction`**: 创建 WebAssembly 内部函数的表示。
   - **`NewWasmFuncRef`**: 创建 WebAssembly 函数引用的表示。
   - **`NewWasmJSFunctionData`**: 创建包装 JavaScript 函数的 WebAssembly 函数数据。
   - **`NewWasmResumeData`**: 创建用于 WebAssembly 挂起和恢复的数据。
   - **`NewWasmSuspenderObject`**: 创建 WebAssembly 挂起器对象。
   - **`NewWasmExportedFunctionData`**: 创建 WebAssembly 导出函数的元数据。
   - **`NewWasmCapiFunctionData`**: 创建 WebAssembly C API 函数的数据。
   - **`NewWasmArrayUninitialized` / `NewWasmArray` / `NewWasmArrayFromElements` / `NewWasmArrayFromMemory` / `NewWasmArrayFromElementSegment`**: 创建不同方式初始化的 WebAssembly 数组。
   - **`NewWasmStructUninitialized` / `NewWasmStruct`**: 创建 WebAssembly 结构体。
   - **`NewWasmContinuationObject`**: 创建 WebAssembly Continuation 对象，用于实现非本地控制流。
   - **`NewSharedFunctionInfoForWasmExportedFunction` / `NewSharedFunctionInfoForWasmJSFunction` / `NewSharedFunctionInfoForWasmResume` / `NewSharedFunctionInfoForWasmCapiFunction`**:  为 WebAssembly 相关函数创建 `SharedFunctionInfo` 对象，这是 V8 中函数元数据的核心结构。
   - **JavaScript 关联:** 这些对象对于在 JavaScript 中运行 WebAssembly 代码至关重要。当你加载和实例化一个 WebAssembly 模块时，V8 内部会创建这些对象来管理 WebAssembly 的执行、内存和函数调用。
   - **代码逻辑推理 (以 `NewWasmDispatchTable` 为例):**
     - **假设输入:**  分发表格的长度 `length`。
     - **输出:**  一个指向新创建的 `WasmDispatchTable` 对象的句柄 `Handle<WasmDispatchTable>`。
     - 代码首先检查长度是否在允许范围内。然后，它估算了离堆数据的大小（TODO 部分表示这部分可以优化）。接着，它分配了 `WasmDispatchTable` 对象所需的内存，并设置了长度、容量以及指向离堆数据的指针。最后，它清空了表格中的条目。

3. **其他对象创建:**
   - **`NewCell`**: 创建一个 `Cell` 对象，用于存储可变的值，通常用于实现闭包变量。
   - **`NewFeedbackCell`**: 创建一个 `FeedbackCell` 对象，用于存储函数的反馈信息，用于优化。
   - **`NewPropertyCell`**: 创建一个 `PropertyCell` 对象，用于存储全局对象的属性。
   - **`NewContextSidePropertyCell`**: 创建一个 `ContextSidePropertyCell` 对象，用于存储与上下文相关的属性。
   - **`NewProtector`**: 创建一个 Protector 对象，用于优化对象形状的转换。
   - **`NewTransitionArray`**: 创建一个 `TransitionArray` 对象，用于存储对象属性转换的信息。
   - **`NewAllocationSite`**: 创建一个 `AllocationSite` 对象，用于跟踪对象的分配位置，用于内联缓存优化。
   - **`NewMapImpl` / `InitializeMap`**:  创建和初始化 `Map` 对象，`Map` 是 V8 中描述对象形状（例如属性和类型）的关键结构。
   - **JavaScript 关联:** 这些对象在 V8 引擎的内部运作中扮演着基础性的角色，支撑着 JavaScript 代码的执行和优化。

**关于 `.tq` 后缀:**

如果 `v8/src/heap/factory.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**。 Torque 是一种 V8 自研的领域特定语言，用于生成高效的 C++ 代码，特别是用于实现内置函数和运行时代码。 当前文件以 `.cc` 结尾，表明它是标准的 C++ 源代码。

**用户常见的编程错误 (可能间接相关):**

虽然用户通常不直接操作 `factory.cc` 中创建的对象，但理解这些对象的用途可以帮助理解某些性能问题或错误的原因。例如：

- **过度创建对象:** 在循环或高频调用的代码中，如果 V8 频繁地创建和销毁对象，可能会导致性能下降和垃圾回收压力增大。这与 `Factory` 类的功能密切相关，因为它负责对象的创建。
- **Promise 使用不当:** 对 Promise 的理解不足可能导致意外的行为，例如未处理的 rejection。了解 `PromiseResolveThenableJobTask` 的作用有助于理解 Promise 链的执行机制。
- **WebAssembly 互操作问题:**  在 JavaScript 和 WebAssembly 之间进行互操作时，类型不匹配或参数传递错误可能会导致问题。理解 `WasmImportData`、`WasmExportedFunctionData` 等对象的结构有助于调试这些问题。

**假设输入与输出 (以 `NewCell` 为例):**

- **假设输入:** 一个 `Tagged<Smi>` 值，例如 `Smi::FromInt(10)`。
- **输出:** 一个 `Handle<Cell>`，指向新创建的 `Cell` 对象，并且该 `Cell` 对象内部存储了输入的值 `10`。

**总结 `factory.cc` 的功能 (针对此部分代码):**

这段 `v8/src/heap/factory.cc` 的代码片段主要负责 **创建和初始化 V8 引擎内部使用的各种堆对象**。  它提供了用于创建 Promise 微任务、各种 WebAssembly 相关数据结构、以及其他基础的 V8 内部对象（如 Cell、FeedbackCell、PropertyCell、Map 等）的工厂方法。 这些对象是 V8 引擎实现 JavaScript 语言特性和 WebAssembly 支持的基础构建块。

作为第 3 部分，这段代码专注于对象创建的具体实现细节，与其他部分（可能涉及对象布局、垃圾回收、代码生成等）共同构成了 V8 堆管理和对象生命周期的完整图景。

Prompt: 
```
这是目录为v8/src/heap/factory.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/factory.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共7部分，请归纳一下它的功能

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
  DCHECK(
"""


```