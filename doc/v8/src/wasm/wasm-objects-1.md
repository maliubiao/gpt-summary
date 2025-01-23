Response: The user wants to understand the functionality of the C++ source code file `v8/src/wasm/wasm-objects.cc`, specifically the second part of it. I need to analyze the provided code snippet and summarize its purpose. If the code interacts with JavaScript, I should illustrate this interaction with JavaScript examples.

The code snippet defines various classes and static methods related to WebAssembly objects within the V8 JavaScript engine. It appears to handle:

- **Data Segment Initialization**: Setting up data segments from the compiled WebAssembly module.
- **Function Call Targets**: Retrieving the target address for function calls, considering imports and JITless mode.
- **Table Operations**: Copying and initializing entries in WebAssembly tables.
- **Function References**: Creating and retrieving function references, potentially involving generic wrappers for imports.
- **Internal Functions and External Representations**: Managing the relationship between internal function representations and their JavaScript function counterparts.
- **Import Handling**: Mechanisms for importing JavaScript functions into WebAssembly tables and setting call origins for imports.
- **Global Variable Access**: Getting and setting values of WebAssembly global variables.
- **Struct and Array Access**: Getting values from struct fields and array elements.
- **Tag Objects**: Creating and managing WebAssembly tag objects for exceptions.
- **Dispatch Tables**: Implementing dispatch tables for indirect calls, including managing wrappers.
- **C API Functions**: Handling WebAssembly C API functions.
- **Exception Packages**: Creating and accessing WebAssembly exception packages.
- **Continuations**: Managing WebAssembly continuations.
- **Type Conversions**: Converting between JavaScript objects and WebAssembly values.

Based on these observations, I can formulate a summary of the file's functionality and provide relevant JavaScript examples where applicable.
这是 `v8/src/wasm/wasm-objects.cc` 源代码文件的第二部分，主要负责定义和实现与 WebAssembly 对象相关的各种操作和工具函数。它涵盖了 WebAssembly 实例的运行时数据管理、函数调用、表操作、类型转换以及与 JavaScript 的互操作等方面。

**功能归纳：**

1. **数据段处理：** 初始化 WebAssembly 实例的数据段，包括被动数据段的指针和大小。
2. **函数调用目标获取：**  `GetCallTarget` 方法用于获取指定函数索引的调用目标地址，区分导入函数和本地函数，并考虑 JITless 模式。
3. **表操作：**
    - `CopyTableEntries` 实现了 WebAssembly 表之间复制条目的功能。
    - `InitTableEntries` 实现了用元素段的数据初始化 WebAssembly 表的功能。
4. **函数引用管理：**
    - 提供了 `GetOrCreateFuncRef` 方法来创建或获取 WebAssembly 函数引用 (`WasmFuncRef`)。这涉及到处理导入函数和本地函数，并可能创建泛型包装器 (`generic wrapper`) 以便在 JavaScript 中调用。
5. **内部函数与外部函数：**
    - `GetOrCreateExternal` 方法用于创建或获取 `WasmInternalFunction` 对应的 JavaScript 函数表示 (`JSFunction`)，这是 WebAssembly 函数暴露给 JavaScript 的方式。
6. **导入函数处理：**
    - 提供了 `ImportWasmJSFunctionIntoTable` 方法，允许将 JavaScript 函数导入到 WebAssembly 的表中。这涉及到创建调用包装器 (`call wrapper`) 来处理 JavaScript 和 WebAssembly 之间的调用约定差异。
    - `WasmImportData` 类提供了设置和检查调用来源 (`CallOrigin`) 的方法，用于跟踪导入调用的来源。
7. **全局变量访问：** `GetGlobalStorage` 和 `GetGlobalBufferAndIndex` 用于获取 WebAssembly 全局变量的存储位置和值。
8. **结构体和数组访问：** `WasmStruct::GetFieldValue` 和 `WasmArray::GetElement` 用于访问 WebAssembly 结构体字段和数组元素的值。
9. **标签对象 (Tag Objects)：** `WasmTagObject` 用于表示 WebAssembly 的异常标签，提供了创建和匹配签名的方法。
10. **分发表 (Dispatch Table)：** `WasmDispatchTable` 用于存储间接调用的目标地址和其他元数据，包括动态增长、设置和清除条目的功能，并管理调用包装器的生命周期。
11. **C API 函数：** `WasmCapiFunction` 用于表示 WebAssembly C API 函数，提供了创建和匹配签名的方法。
12. **异常处理：** `WasmExceptionPackage` 用于表示 WebAssembly 异常，提供了创建和访问异常标签和值的方法。
13. **Continuation 对象：** `WasmContinuationObject` 用于表示 WebAssembly 的 Continuation，用于支持非本地控制流。
14. **类型转换：** 提供了 `JSToWasmObject` 和 `WasmToJSObject` 函数，用于在 JavaScript 对象和 WebAssembly 对象之间进行转换。

**与 JavaScript 的关系及示例：**

这个文件中的代码是 V8 引擎实现 WebAssembly 支持的关键部分，它允许 JavaScript 代码与 WebAssembly 代码进行互操作。以下是一些 JavaScript 示例，展示了这些 C++ 代码背后的功能：

**示例 1：获取 WebAssembly 导出函数的 JavaScript 表示**

```javascript
const wasmCode = new Uint8Array([
  0, 97, 115, 109, 1, 0, 0, 0, 1, 5, 1, 96, 0, 1, 127, 3, 2, 1, 0, 7, 7, 1, 3,
  100, 111, 50, 0, 10, 4, 1, 2, 0, 11,
]);
const wasmModule = new WebAssembly.Module(wasmCode);
const wasmInstance = new WebAssembly.Instance(wasmModule);

// 获取导出的函数 "do2"
const exportedFunction = wasmInstance.exports.do2;

console.log(typeof exportedFunction); // 输出 "function"

// 调用导出的函数
console.log(exportedFunction());
```

在这个例子中，当 JavaScript 代码访问 `wasmInstance.exports.do2` 时，V8 引擎会利用 `WasmExportedFunction::New` 等 C++ 代码创建与 WebAssembly 函数对应的 JavaScript 函数对象。

**示例 2：将 JavaScript 函数导入到 WebAssembly 表中**

```javascript
const importObject = {
  imports: {
    imported_func: (arg) => {
      console.log("JavaScript function called with:", arg);
      return arg * 2;
    },
  },
};

const wasmCode = new Uint8Array([
  0, 97, 115, 109, 1, 0, 0, 0, 1, 6, 1, 96, 1, 127, 1, 127, 2, 7, 1, 3, 105,
  109, 112, 7, 105, 109, 112, 111, 114, 116, 101, 100, 95, 102, 117, 110, 99,
  0, 0, 3, 2, 1, 0, 7, 7, 1, 3, 99, 97, 108, 0, 0, 10, 6, 1, 4, 0, 32, 0, 11,
]);
const wasmModule = new WebAssembly.Module(wasmCode);
const wasmInstance = new WebAssembly.Instance(wasmModule, importObject);

// 调用 WebAssembly 代码，它会调用导入的 JavaScript 函数
wasmInstance.exports.call();
```

在这个例子中，当 WebAssembly 代码调用导入的函数 `imported_func` 时，V8 引擎会使用 `WasmImportData` 等 C++ 代码来处理调用，并将控制权传递给 JavaScript 函数。`ImportWasmJSFunctionIntoTable` 等方法可能在模块实例化时被调用，以设置导入函数的调用机制。

**示例 3：使用 WebAssembly 表**

```javascript
const wasmCode = new Uint8Array([
  // ... (省略 WebAssembly 代码，包含一个表和一个调用表的函数)
]);
const wasmModule = new WebAssembly.Module(wasmCode);
const wasmInstance = new WebAssembly.Instance(wasmModule, {
  js: {
    f1: () => console.log("f1 called"),
    f2: () => console.log("f2 called"),
  },
});

// 获取表对象
const table = wasmInstance.exports.my_table;

// 获取表中的函数引用
const funcRef0 = table.get(0);
const funcRef1 = table.get(1);

// 调用表中的函数
wasmInstance.exports.call_from_table(0); // 调用 f1
wasmInstance.exports.call_from_table(1); // 调用 f2
```

在这个例子中，`WasmDispatchTable` 类在幕后管理 WebAssembly 的表，存储函数引用。`table.get(index)` 操作会涉及到 C++ 代码中访问 `WasmDispatchTable` 的逻辑，而 `call_from_table` 函数的执行则会用到 `GetCallTarget` 来获取表中函数的调用目标。

总而言之，`v8/src/wasm/wasm-objects.cc` 的第二部分是 V8 引擎中 WebAssembly 对象模型的核心实现，它定义了各种 WebAssembly 对象的结构和行为，并提供了与 JavaScript 互操作的关键机制。这些 C++ 代码使得 JavaScript 能够加载、实例化和执行 WebAssembly 模块，并与 WebAssembly 代码进行函数调用和数据共享。

### 提示词
```
这是目录为v8/src/wasm/wasm-objects.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```
::Vector<const uint8_t> wire_bytes = native_module->wire_bytes();
  uint32_t num_data_segments = module->num_declared_data_segments;
  // The number of declared data segments will be zero if there is no DataCount
  // section. These arrays will not be allocated nor initialized in that case,
  // since they cannot be used (since the validator checks that number of
  // declared data segments when validating the memory.init and memory.drop
  // instructions).
  DCHECK(num_data_segments == 0 ||
         num_data_segments == module->data_segments.size());
  for (uint32_t i = 0; i < num_data_segments; ++i) {
    const wasm::WasmDataSegment& segment = module->data_segments[i];
    // Initialize the pointer and size of passive segments.
    auto source_bytes = wire_bytes.SubVector(segment.source.offset(),
                                             segment.source.end_offset());
    data_segment_starts()->set(i,
                               reinterpret_cast<Address>(source_bytes.begin()));
    // Set the active segments to being already dropped, since memory.init on
    // a dropped passive segment and an active segment have the same
    // behavior.
    data_segment_sizes()->set(static_cast<int>(i),
                              segment.active ? 0 : source_bytes.length());
  }
}

WasmCodePointer WasmTrustedInstanceData::GetCallTarget(uint32_t func_index) {
  wasm::NativeModule* native_module = this->native_module();
  SBXCHECK_BOUNDS(func_index, native_module->num_functions());
  if (func_index < native_module->num_imported_functions()) {
    return dispatch_table_for_imports()->target(func_index);
  }

  if (v8_flags.wasm_jitless) {
    return 0;
  }

  return native_module->GetIndirectCallTarget(func_index);
}

// static
bool WasmTrustedInstanceData::CopyTableEntries(
    Isolate* isolate,
    DirectHandle<WasmTrustedInstanceData> trusted_instance_data,
    uint32_t table_dst_index, uint32_t table_src_index, uint32_t dst,
    uint32_t src, uint32_t count) {
  CHECK_LT(table_dst_index, trusted_instance_data->tables()->length());
  CHECK_LT(table_src_index, trusted_instance_data->tables()->length());
  auto table_dst =
      direct_handle(Cast<WasmTableObject>(
                        trusted_instance_data->tables()->get(table_dst_index)),
                    isolate);
  auto table_src =
      direct_handle(Cast<WasmTableObject>(
                        trusted_instance_data->tables()->get(table_src_index)),
                    isolate);
  uint32_t max_dst = table_dst->current_length();
  uint32_t max_src = table_src->current_length();
  bool copy_backward = src < dst;
  if (!base::IsInBounds(dst, count, max_dst) ||
      !base::IsInBounds(src, count, max_src)) {
    return false;
  }

  // no-op
  if ((dst == src && table_dst_index == table_src_index) || count == 0) {
    return true;
  }

  for (uint32_t i = 0; i < count; ++i) {
    uint32_t src_index = copy_backward ? (src + count - i - 1) : src + i;
    uint32_t dst_index = copy_backward ? (dst + count - i - 1) : dst + i;
    auto value = WasmTableObject::Get(isolate, table_src, src_index);
    WasmTableObject::Set(isolate, table_dst, dst_index, value);
  }
  return true;
}

// static
std::optional<MessageTemplate> WasmTrustedInstanceData::InitTableEntries(
    Isolate* isolate, Handle<WasmTrustedInstanceData> trusted_instance_data,
    Handle<WasmTrustedInstanceData> shared_trusted_instance_data,
    uint32_t table_index, uint32_t segment_index, uint32_t dst, uint32_t src,
    uint32_t count) {
  AccountingAllocator allocator;
  // This {Zone} will be used only by the temporary WasmFullDecoder allocated
  // down the line from this call. Therefore it is safe to stack-allocate it
  // here.
  Zone zone(&allocator, "LoadElemSegment");

  const WasmModule* module = trusted_instance_data->module();

  bool table_is_shared = module->tables[table_index].shared;
  bool segment_is_shared = module->elem_segments[segment_index].shared;

  DirectHandle<WasmTableObject> table_object(
      Cast<WasmTableObject>((table_is_shared ? shared_trusted_instance_data
                                             : trusted_instance_data)
                                ->tables()
                                ->get(table_index)),
      isolate);

  // If needed, try to lazily initialize the element segment.
  std::optional<MessageTemplate> opt_error = wasm::InitializeElementSegment(
      &zone, isolate, trusted_instance_data, shared_trusted_instance_data,
      segment_index);
  if (opt_error.has_value()) return opt_error;

  DirectHandle<FixedArray> elem_segment(
      Cast<FixedArray>((segment_is_shared ? shared_trusted_instance_data
                                          : trusted_instance_data)
                           ->element_segments()
                           ->get(segment_index)),
      isolate);
  if (!base::IsInBounds<uint64_t>(dst, count, table_object->current_length())) {
    return {MessageTemplate::kWasmTrapTableOutOfBounds};
  }
  if (!base::IsInBounds<uint64_t>(src, count, elem_segment->length())) {
    return {MessageTemplate::kWasmTrapElementSegmentOutOfBounds};
  }

  for (size_t i = 0; i < count; i++) {
    WasmTableObject::Set(
        isolate, table_object, static_cast<int>(dst + i),
        direct_handle(elem_segment->get(static_cast<int>(src + i)), isolate));
  }

  return {};
}

bool WasmTrustedInstanceData::try_get_func_ref(int index,
                                               Tagged<WasmFuncRef>* result) {
  Tagged<Object> val = func_refs()->get(index);
  if (IsSmi(val)) return false;
  *result = Cast<WasmFuncRef>(val);
  return true;
}

Handle<WasmFuncRef> WasmTrustedInstanceData::GetOrCreateFuncRef(
    Isolate* isolate,
    DirectHandle<WasmTrustedInstanceData> trusted_instance_data,
    int function_index) {
  Tagged<WasmFuncRef> existing_func_ref;
  if (trusted_instance_data->try_get_func_ref(function_index,
                                              &existing_func_ref)) {
    return handle(existing_func_ref, isolate);
  }

  const WasmModule* module = trusted_instance_data->module();
  bool is_import =
      function_index < static_cast<int>(module->num_imported_functions);
  wasm::ModuleTypeIndex sig_index = module->functions[function_index].sig_index;
  wasm::CanonicalTypeIndex canonical_sig_id =
      module->canonical_sig_id(sig_index);
  const wasm::CanonicalSig* sig =
      wasm::GetTypeCanonicalizer()->LookupFunctionSignature(canonical_sig_id);
  DirectHandle<TrustedObject> implicit_arg =
      is_import ? direct_handle(
                      Cast<TrustedObject>(
                          trusted_instance_data->dispatch_table_for_imports()
                              ->implicit_arg(function_index)),
                      isolate)
                : trusted_instance_data;

  bool setup_new_ref_with_generic_wrapper = false;
  if (v8_flags.wasm_generic_wrapper && IsWasmImportData(*implicit_arg)) {
    // Only set up the generic wrapper if it is compatible with the import call
    // kind, which we compute below.
    auto import_data = Cast<WasmImportData>(implicit_arg);
    const wasm::WellKnownImportsList& preknown_imports =
        module->type_feedback.well_known_imports;
    auto callable =
        handle<JSReceiver>(Cast<JSReceiver>(import_data->callable()), isolate);
    wasm::ResolvedWasmImport resolved(trusted_instance_data, function_index,
                                      callable, sig, canonical_sig_id,
                                      preknown_imports.get(function_index));
    setup_new_ref_with_generic_wrapper =
        UseGenericWasmToJSWrapper(resolved.kind(), sig, resolved.suspend());
  }

  if (setup_new_ref_with_generic_wrapper) {
    auto import_data = Cast<WasmImportData>(implicit_arg);
    implicit_arg = isolate->factory()->NewWasmImportData(import_data);
  }

  // TODO(14034): Create funcref RTTs lazily?
  DirectHandle<Map> rtt{
      Cast<Map>(
          trusted_instance_data->managed_object_maps()->get(sig_index.index)),
      isolate};

#if V8_ENABLE_SANDBOX
  uint64_t signature_hash =
      wasm::SignatureHasher::Hash(module->functions[function_index].sig);
#else
  uintptr_t signature_hash = 0;
#endif

  DirectHandle<WasmInternalFunction> internal_function =
      isolate->factory()->NewWasmInternalFunction(implicit_arg, function_index,
                                                  signature_hash);
  Handle<WasmFuncRef> func_ref =
      isolate->factory()->NewWasmFuncRef(internal_function, rtt);
  trusted_instance_data->func_refs()->set(function_index, *func_ref);

  if (setup_new_ref_with_generic_wrapper) {
    auto import_data = Cast<WasmImportData>(implicit_arg);
    WasmCodePointer wrapper_entry;
    if (wasm::IsJSCompatibleSignature(sig)) {
      DCHECK(UseGenericWasmToJSWrapper(wasm::kDefaultImportCallKind, sig,
                                       wasm::Suspend::kNoSuspend));
      WasmImportData::SetFuncRefAsCallOrigin(import_data, func_ref);
      wrapper_entry =
          wasm::GetBuiltinCodePointer<Builtin::kWasmToJsWrapperAsm>(isolate);
    } else {
      wrapper_entry =
          wasm::GetBuiltinCodePointer<Builtin::kWasmToJsWrapperInvalidSig>(
              isolate);
    }
    // Wrapper code does not move, so we store the call target directly in the
    // internal function.
    internal_function->set_call_target(wrapper_entry);
  } else {
    internal_function->set_call_target(
        trusted_instance_data->GetCallTarget(function_index));
  }

  return func_ref;
}

bool WasmInternalFunction::try_get_external(Tagged<JSFunction>* result) {
  if (IsUndefined(external())) return false;
  *result = Cast<JSFunction>(external());
  return true;
}

// static
Handle<JSFunction> WasmInternalFunction::GetOrCreateExternal(
    DirectHandle<WasmInternalFunction> internal) {
  Isolate* isolate = GetIsolateFromWritableObject(*internal);

  Tagged<JSFunction> existing_external;
  if (internal->try_get_external(&existing_external)) {
    return handle(existing_external, isolate);
  }

  // {this} can either be:
  // - a declared function, i.e. {implicit_arg()} is a WasmTrustedInstanceData,
  // - or an imported callable, i.e. {implicit_arg()} is a WasmImportData which
  //   refers to the imported instance.
  // It cannot be a JS/C API function as for those, the external function is set
  // at creation.
  DirectHandle<TrustedObject> implicit_arg{internal->implicit_arg(), isolate};
  DirectHandle<WasmTrustedInstanceData> instance_data =
      IsWasmTrustedInstanceData(*implicit_arg)
          ? Cast<WasmTrustedInstanceData>(implicit_arg)
          : direct_handle(Cast<WasmImportData>(*implicit_arg)->instance_data(),
                          isolate);
  const WasmModule* module = instance_data->module();
  const WasmFunction& function = module->functions[internal->function_index()];
  wasm::CanonicalTypeIndex sig_id =
      module->canonical_sig_id(function.sig_index);
  const wasm::CanonicalSig* sig =
      wasm::GetTypeCanonicalizer()->LookupFunctionSignature(sig_id);
  wasm::TypeCanonicalizer::PrepareForCanonicalTypeId(isolate, sig_id);
  int wrapper_index = sig_id.index;

  Tagged<MaybeObject> entry =
      isolate->heap()->js_to_wasm_wrappers()->get(wrapper_index);

  DirectHandle<Code> wrapper_code;
  // {entry} can be cleared or a weak reference to a ready {CodeWrapper}.
  if (!entry.IsCleared()) {
    wrapper_code = direct_handle(
        Cast<CodeWrapper>(entry.GetHeapObjectAssumeWeak())->code(isolate),
        isolate);
#if V8_ENABLE_DRUMBRAKE
  } else if (v8_flags.wasm_jitless) {
    wrapper_code = isolate->builtins()->code_handle(
        Builtin::kGenericJSToWasmInterpreterWrapper);
#endif  // V8_ENABLE_DRUMBRAKE
  } else if (CanUseGenericJsToWasmWrapper(module, sig)) {
    if (v8_flags.stress_wasm_stack_switching) {
      wrapper_code =
          isolate->builtins()->code_handle(Builtin::kWasmStressSwitch);
    } else {
      wrapper_code =
          isolate->builtins()->code_handle(Builtin::kJSToWasmWrapper);
    }
  } else {
    // The wrapper does not exist yet; compile it now.
    wrapper_code = wasm::JSToWasmWrapperCompilationUnit::CompileJSToWasmWrapper(
        isolate, sig, sig_id);
    // This should have added an entry in the per-isolate cache.
    DCHECK_EQ(MakeWeak(wrapper_code->wrapper()),
              isolate->heap()->js_to_wasm_wrappers()->get(wrapper_index));
  }
  DirectHandle<WasmFuncRef> func_ref{
      Cast<WasmFuncRef>(
          instance_data->func_refs()->get(internal->function_index())),
      isolate};
  DCHECK_EQ(func_ref->internal(isolate), *internal);
  auto result = WasmExportedFunction::New(
      isolate, instance_data, func_ref, internal,
      static_cast<int>(sig->parameter_count()), wrapper_code);

  internal->set_external(*result);
  return result;
}

// static
void WasmImportData::SetImportIndexAsCallOrigin(
    DirectHandle<WasmImportData> import_data, int entry_index) {
  import_data->set_call_origin(Smi::FromInt(-entry_index - 1));
}

// static
void WasmImportData::SetIndexInTableAsCallOrigin(
    DirectHandle<WasmImportData> import_data, int entry_index) {
  import_data->set_call_origin(Smi::FromInt(entry_index + 1));
}

// static
bool WasmImportData::CallOriginIsImportIndex(Tagged<Smi> call_origin) {
  return call_origin.value() < 0;
}

// static
bool WasmImportData::CallOriginIsIndexInTable(Tagged<Smi> call_origin) {
  return call_origin.value() > 0;
}

// static
int WasmImportData::CallOriginAsIndex(Tagged<Smi> call_origin) {
  int raw_index = call_origin.value();
  CHECK_NE(raw_index, kInvalidCallOrigin);
  if (raw_index < 0) {
    raw_index = -raw_index;
  }
  return raw_index - 1;
}

// static
void WasmImportData::SetCrossInstanceTableIndexAsCallOrigin(
    Isolate* isolate, DirectHandle<WasmImportData> import_data,
    DirectHandle<WasmInstanceObject> instance_object, int entry_index) {
  DirectHandle<Tuple2> tuple = isolate->factory()->NewTuple2(
      instance_object, direct_handle(Smi::FromInt(entry_index + 1), isolate),
      AllocationType::kOld);
  import_data->set_call_origin(*tuple);
}

// static
void WasmImportData::SetFuncRefAsCallOrigin(
    DirectHandle<WasmImportData> import_data,
    DirectHandle<WasmFuncRef> func_ref) {
  import_data->set_call_origin(*func_ref);
}

// static
void WasmTrustedInstanceData::ImportWasmJSFunctionIntoTable(
    Isolate* isolate,
    DirectHandle<WasmTrustedInstanceData> trusted_instance_data,
    int table_index, int entry_index,
    DirectHandle<WasmJSFunction> js_function) {
  Tagged<WasmJSFunctionData> function_data =
      js_function->shared()->wasm_js_function_data();
  // Get the function's canonical signature index. Note that the function's
  // signature may not be present in the importing module.
  wasm::CanonicalTypeIndex sig_id = function_data->sig_index();
  const wasm::CanonicalSig* sig =
      wasm::GetWasmEngine()->type_canonicalizer()->LookupFunctionSignature(
          sig_id);

  Handle<JSReceiver> callable(function_data->GetCallable(), isolate);
  wasm::Suspend suspend = function_data->GetSuspend();
  wasm::WasmCodeRefScope code_ref_scope;

  SBXCHECK(FunctionSigMatchesTable(sig_id, trusted_instance_data->module(),
                                   table_index));

  wasm::ResolvedWasmImport resolved({}, -1, callable, sig, sig_id,
                                    wasm::WellKnownImport::kUninstantiated);
  wasm::ImportCallKind kind = resolved.kind();
  callable = resolved.callable();  // Update to ultimate target.
  DCHECK_NE(wasm::ImportCallKind::kLinkError, kind);
  int expected_arity = static_cast<int>(sig->parameter_count());
  if (kind == wasm::ImportCallKind ::kJSFunctionArityMismatch) {
    expected_arity = Cast<JSFunction>(callable)
                         ->shared()
                         ->internal_formal_parameter_count_without_receiver();
  }

  wasm::WasmImportWrapperCache* cache = wasm::GetWasmImportWrapperCache();
  wasm::WasmCode* wasm_code =
      cache->MaybeGet(kind, sig_id, expected_arity, suspend);
  WasmCodePointer call_target;
  if (wasm_code) {
    call_target = wasm_code->code_pointer();
  } else if (UseGenericWasmToJSWrapper(kind, sig, resolved.suspend())) {
    call_target =
        wasm::GetBuiltinCodePointer<Builtin::kWasmToJsWrapperAsm>(isolate);
  } else {
    constexpr bool kNoSourcePositions = false;
    wasm_code = cache->CompileWasmImportCallWrapper(isolate, kind, sig, sig_id,
                                                    kNoSourcePositions,
                                                    expected_arity, suspend);
    call_target = wasm_code->code_pointer();
  }

  // Update the dispatch table.
  DirectHandle<WasmImportData> import_data =
      isolate->factory()->NewWasmImportData(callable, suspend,
                                            trusted_instance_data, sig);

  WasmImportData::SetIndexInTableAsCallOrigin(import_data, entry_index);
  Tagged<WasmDispatchTable> table =
      trusted_instance_data->dispatch_table(table_index);
  DCHECK(
      wasm_code ||
      call_target ==
          wasm::GetBuiltinCodePointer<Builtin::kWasmToJsWrapperAsm>(isolate));
  table->Set(entry_index, *import_data, call_target, sig_id,
#if V8_ENABLE_DRUMBRAKE
             WasmDispatchTable::kInvalidFunctionIndex,
#endif  // V8_ENABLE_DRUMBRAKE
             wasm_code, wasm_code ? IsAWrapper::kYes : IsAWrapper::kNo,
             WasmDispatchTable::kExistingEntry);
}

uint8_t* WasmTrustedInstanceData::GetGlobalStorage(
    const wasm::WasmGlobal& global) {
  DCHECK(!global.type.is_reference());
  if (global.mutability && global.imported) {
    return reinterpret_cast<uint8_t*>(
        imported_mutable_globals()->get_sandboxed_pointer(global.index));
  }
  return globals_start() + global.offset;
}

std::pair<Tagged<FixedArray>, uint32_t>
WasmTrustedInstanceData::GetGlobalBufferAndIndex(
    const wasm::WasmGlobal& global) {
  DisallowGarbageCollection no_gc;
  DCHECK(global.type.is_reference());
  if (global.mutability && global.imported) {
    Tagged<FixedArray> buffer =
        Cast<FixedArray>(imported_mutable_globals_buffers()->get(global.index));
    Address idx = imported_mutable_globals()->get(global.index);
    DCHECK_LE(idx, std::numeric_limits<uint32_t>::max());
    return {buffer, static_cast<uint32_t>(idx)};
  }
  return {tagged_globals_buffer(), global.offset};
}

wasm::WasmValue WasmTrustedInstanceData::GetGlobalValue(
    Isolate* isolate, const wasm::WasmGlobal& global) {
  DisallowGarbageCollection no_gc;
  if (global.type.is_reference()) {
    Tagged<FixedArray> global_buffer;  // The buffer of the global.
    uint32_t global_index = 0;         // The index into the buffer.
    std::tie(global_buffer, global_index) = GetGlobalBufferAndIndex(global);
    return wasm::WasmValue(handle(global_buffer->get(global_index), isolate),
                           global.type, module());
  }
  Address ptr = reinterpret_cast<Address>(GetGlobalStorage(global));
  switch (global.type.kind()) {
#define CASE_TYPE(valuetype, ctype) \
  case wasm::valuetype:             \
    return wasm::WasmValue(base::ReadUnalignedValue<ctype>(ptr));
    FOREACH_WASMVALUE_CTYPES(CASE_TYPE)
#undef CASE_TYPE
    default:
      UNREACHABLE();
  }
}

wasm::WasmValue WasmStruct::GetFieldValue(uint32_t index) {
  wasm::ValueType field_type = type()->field(index);
  int field_offset = WasmStruct::kHeaderSize + type()->field_offset(index);
  Address field_address = GetFieldAddress(field_offset);
  switch (field_type.kind()) {
#define CASE_TYPE(valuetype, ctype) \
  case wasm::valuetype:             \
    return wasm::WasmValue(base::ReadUnalignedValue<ctype>(field_address));
    CASE_TYPE(kI8, int8_t)
    CASE_TYPE(kI16, int16_t)
    FOREACH_WASMVALUE_CTYPES(CASE_TYPE)
#undef CASE_TYPE
    case wasm::kF16:
      return wasm::WasmValue(fp16_ieee_to_fp32_value(
          base::ReadUnalignedValue<uint16_t>(field_address)));
    case wasm::kRef:
    case wasm::kRefNull: {
      Handle<Object> ref(TaggedField<Object>::load(*this, field_offset),
                         GetIsolateFromWritableObject(*this));
      return wasm::WasmValue(ref, field_type, module());
    }
    case wasm::kRtt:
    case wasm::kVoid:
    case wasm::kTop:
    case wasm::kBottom:
      UNREACHABLE();
  }
}

wasm::WasmValue WasmArray::GetElement(uint32_t index) {
  wasm::ValueType element_type = type()->element_type();
  int element_offset =
      WasmArray::kHeaderSize + index * element_type.value_kind_size();
  Address element_address = GetFieldAddress(element_offset);
  switch (element_type.kind()) {
#define CASE_TYPE(value_type, ctype) \
  case wasm::value_type:             \
    return wasm::WasmValue(base::ReadUnalignedValue<ctype>(element_address));
    CASE_TYPE(kI8, int8_t)
    CASE_TYPE(kI16, int16_t)
    FOREACH_WASMVALUE_CTYPES(CASE_TYPE)
#undef CASE_TYPE
    case wasm::kF16:
      return wasm::WasmValue(fp16_ieee_to_fp32_value(
          base::ReadUnalignedValue<uint16_t>(element_address)));
    case wasm::kRef:
    case wasm::kRefNull: {
      Handle<Object> ref(TaggedField<Object>::load(*this, element_offset),
                         GetIsolateFromWritableObject(*this));
      return wasm::WasmValue(ref, element_type, module());
    }
    case wasm::kRtt:
    case wasm::kVoid:
    case wasm::kTop:
    case wasm::kBottom:
      UNREACHABLE();
  }
}

void WasmArray::SetTaggedElement(uint32_t index, DirectHandle<Object> value,
                                 WriteBarrierMode mode) {
  DCHECK(type()->element_type().is_reference());
  TaggedField<Object>::store(*this, element_offset(index), *value);
  CONDITIONAL_WRITE_BARRIER(*this, element_offset(index), *value, mode);
}

// static
Handle<WasmTagObject> WasmTagObject::New(
    Isolate* isolate, const wasm::FunctionSig* sig,
    wasm::CanonicalTypeIndex type_index, DirectHandle<HeapObject> tag,
    DirectHandle<WasmTrustedInstanceData> trusted_data) {
  Handle<JSFunction> tag_cons(isolate->native_context()->wasm_tag_constructor(),
                              isolate);

  // Serialize the signature.
  DCHECK_EQ(0, sig->return_count());
  DCHECK_LE(sig->parameter_count(), std::numeric_limits<int>::max());
  int sig_size = static_cast<int>(sig->parameter_count());
  DirectHandle<PodArray<wasm::ValueType>> serialized_sig =
      PodArray<wasm::ValueType>::New(isolate, sig_size, AllocationType::kOld);
  int index = 0;  // Index into the {PodArray} above.
  for (wasm::ValueType param : sig->parameters()) {
    serialized_sig->set(index++, param);
  }

  Handle<JSObject> tag_object =
      isolate->factory()->NewJSObject(tag_cons, AllocationType::kOld);
  Handle<WasmTagObject> tag_wrapper = Cast<WasmTagObject>(tag_object);
  tag_wrapper->set_serialized_signature(*serialized_sig);
  tag_wrapper->set_canonical_type_index(type_index.index);
  tag_wrapper->set_tag(*tag);
  if (!trusted_data.is_null()) {
    tag_wrapper->set_trusted_data(*trusted_data);
  } else {
    tag_wrapper->clear_trusted_data();
  }

  return tag_wrapper;
}

bool WasmTagObject::MatchesSignature(wasm::CanonicalTypeIndex expected_index) {
  return wasm::CanonicalTypeIndex{static_cast<uint32_t>(
             this->canonical_type_index())} == expected_index;
}

const wasm::CanonicalSig* WasmCapiFunction::sig() const {
  return shared()->wasm_capi_function_data()->sig();
}

WasmDispatchTableData::~WasmDispatchTableData() {
  if (wrappers_.empty()) return;
  std::vector<wasm::WasmCode*> codes;
  for (auto [address, entry] : wrappers_) {
    DCHECK_LT(0, entry.count);
    if (entry.code) codes.push_back(entry.code);
  }
  wasm::WasmCode::DecrementRefCount(base::VectorOf(codes));
}

void WasmDispatchTableData::Add(WasmCodePointer call_target,
                                wasm::WasmCode* wrapper_if_known,
                                IsAWrapper contextual_knowledge) {
  // If the caller knows that the call_target is not a wrapper, return
  // immediately. Note: we *could* remember this fact for the benefit of
  // later calls to {Remove()} by putting a {nullptr} entry into the
  // {lookup_cache_}, but for real-world cases we're aware of that's not
  // worth the memory consumption: overwriting of existing function entries
  // is exceedingly rare.
  if (contextual_knowledge == IsAWrapper::kNo) {
    DCHECK_NULL(wrapper_if_known);
    DCHECK_NULL(wasm::GetWasmImportWrapperCache()->FindWrapper(call_target));
    DCHECK(!wrappers_.count(call_target) ||
           wrappers_.find(call_target)->second.code == nullptr);
    return;
  }

  // Perform lookup and insertion in a single operation; we never have to update
  // existing entries.
  auto [wrapper_cache, was_inserted] =
      wrappers_.emplace(call_target, WrapperEntry{wrapper_if_known});
  auto& [wrapper_code, count] = wrapper_cache->second;
  DCHECK(wrapper_if_known == nullptr || wrapper_if_known == wrapper_code);
  if (was_inserted) {
    if (wrapper_if_known == nullptr) {
      // No cache entry, and we are not sure if this is a wrapper. So we have to
      // perform the relatively expensive mutex-protected lookup to find out.
      DCHECK_NULL(wrapper_code);
      wrapper_code =
          wasm::GetWasmImportWrapperCache()->FindWrapper(call_target);
      DCHECK_IMPLIES(contextual_knowledge == IsAWrapper::kYes,
                     wrapper_code != nullptr);
      if (!wrapper_code) return;  // Not a wrapper.
    }
    // We added a wrapper to the table; increment its ref-count.
    DCHECK_EQ(1, count);
    wrapper_code->IncRef();
  } else {
    // We already knew if this was a wrapper or not.
    DCHECK_IMPLIES(wrapper_code == nullptr, wrapper_if_known == nullptr);
    if (wrapper_code == nullptr) return;  // Not a wrapper.
    DCHECK_LE(1, count);
    ++count;
  }
}

void WasmDispatchTableData::Remove(WasmCodePointer call_target) {
  if (call_target == wasm::kInvalidWasmCodePointer) return;
  auto entry = wrappers_.find(call_target);
  if (entry == wrappers_.end()) {
    // This is certainly not a wrapper.
    DCHECK_NULL(wasm::GetWasmImportWrapperCache()->FindWrapper(call_target));
    return;
  }
  auto& [wrapper_code, count] = entry->second;
  if (!wrapper_code) {
    // Avoid leaking memory by removing the entry. We don't know for sure if
    // this was the last entry with {call_target} but we can always add it back.
    wrappers_.erase(entry);
    return;
  }

  if (count == 1) {
    // This was the last reference to this wrapper in this table.
    // TODO(clemensb): We should speed this up by doing
    // {WasmCodeRefScope::AddRef} and then {DecRefOnLiveCode}.
    wasm::WasmCode::DecrementRefCount({&wrapper_code, 1});
    wrappers_.erase(entry);
  } else {
    --count;
  }
}

void WasmDispatchTable::Set(int index, Tagged<Object> implicit_arg,
                            WasmCodePointer call_target,
                            wasm::CanonicalTypeIndex sig_id,
#if V8_ENABLE_DRUMBRAKE
                            uint32_t function_index,
#endif  // V8_ENABLE_DRUMBRAKE
                            wasm::WasmCode* wrapper_if_known,
                            IsAWrapper contextual_knowledge,
                            NewOrExistingEntry new_or_existing) {
  if (implicit_arg == Smi::zero()) {
    DCHECK_EQ(wasm::kInvalidWasmCodePointer, call_target);
    Clear(index, new_or_existing);
    return;
  }

  SBXCHECK_BOUNDS(index, length());
  DCHECK(IsWasmImportData(implicit_arg) ||
         IsWasmTrustedInstanceData(implicit_arg));
  const int offset = OffsetOf(index);
  if (!v8_flags.wasm_jitless) {
    WasmDispatchTableData* offheap_data = this->offheap_data();
    // When overwriting an existing entry, we must decrement the refcount
    // of any overwritten wrappers. When initializing an entry, we must not
    // read uninitialized memory.
    if (new_or_existing == kExistingEntry) {
      WasmCodePointer old_target =
          ReadField<WasmCodePointer>(offset + kTargetBias);
      offheap_data->Remove(old_target);
    }
    offheap_data->Add(call_target, wrapper_if_known, contextual_knowledge);
  }
  WriteProtectedPointerField(offset + kImplicitArgBias,
                             Cast<TrustedObject>(implicit_arg));
  CONDITIONAL_WRITE_BARRIER(*this, offset + kImplicitArgBias, implicit_arg,
                            UPDATE_WRITE_BARRIER);
  if (v8_flags.wasm_jitless) {
#if V8_ENABLE_DRUMBRAKE
    // Ignore call_target, not used in jitless mode.
    WriteField<int>(offset + kFunctionIndexBias, function_index);
#endif  // V8_ENABLE_DRUMBRAKE
  } else {
    WriteField<WasmCodePointer>(offset + kTargetBias, call_target);
  }
  WriteField<uint32_t>(offset + kSigBias, sig_id.index);
}

void WasmDispatchTable::SetForImport(int index,
                                     Tagged<TrustedObject> implicit_arg,
                                     WasmCodePointer call_target,
                                     wasm::WasmCode* wrapper_if_known,
                                     IsAWrapper contextual_knowledge) {
  SBXCHECK_BOUNDS(index, length());
  DCHECK(IsWasmImportData(implicit_arg) ||
         IsWasmTrustedInstanceData(implicit_arg));
  DCHECK(kNullAddress != call_target || v8_flags.wasm_jitless);
  const int offset = OffsetOf(index);
  WriteProtectedPointerField(offset + kImplicitArgBias,
                             Cast<TrustedObject>(implicit_arg));
  CONDITIONAL_WRITE_BARRIER(*this, offset + kImplicitArgBias, implicit_arg,
                            UPDATE_WRITE_BARRIER);
  if (!v8_flags.wasm_jitless) {
    offheap_data()->Add(call_target, wrapper_if_known, contextual_knowledge);
    WriteField<WasmCodePointer>(offset + kTargetBias, call_target);
  } else {
    // Ignore call_target, not used in jitless mode.
  }
  // Leave the signature untouched, it is unused for imports.
  DCHECK_EQ(-1, ReadField<int>(offset + kSigBias));
}

void WasmDispatchTable::Clear(int index, NewOrExistingEntry new_or_existing) {
  SBXCHECK_BOUNDS(index, length());
  const int offset = OffsetOf(index);
  // When clearing an existing entry, we must update the refcount of any
  // wrappers. When clear-initializing new entries, we must not read
  // uninitialized memory.
  if (new_or_existing == kExistingEntry) {
    WasmCodePointer old_target =
        ReadField<WasmCodePointer>(offset + kTargetBias);
    offheap_data()->Remove(old_target);
  }
  ClearProtectedPointerField(offset + kImplicitArgBias);
  WriteField<WasmCodePointer>(offset + kTargetBias,
                              wasm::kInvalidWasmCodePointer);
  WriteField<int>(offset + kSigBias, -1);
}

void WasmDispatchTable::InstallCompiledWrapper(int index,
                                               wasm::WasmCode* wrapper) {
  SBXCHECK_BOUNDS(index, length());
  if (v8_flags.wasm_jitless) return;  // Nothing to do.

  WasmCodePointer call_target = wrapper->code_pointer();
  offheap_data()->Add(call_target, wrapper, IsAWrapper::kYes);
  const int offset = OffsetOf(index) + kTargetBias;
  WriteField<WasmCodePointer>(offset, call_target);
}

// static
Handle<WasmDispatchTable> WasmDispatchTable::New(Isolate* isolate, int length) {
  return isolate->factory()->NewWasmDispatchTable(length);
}

// static
Handle<WasmDispatchTable> WasmDispatchTable::Grow(
    Isolate* isolate, Handle<WasmDispatchTable> old_table, int new_length) {
  int old_length = old_table->length();
  // This method should only be called if we actually grow.
  DCHECK_LT(old_length, new_length);

  int old_capacity = old_table->capacity();
  if (new_length < old_table->capacity()) {
    RELEASE_WRITE_INT32_FIELD(*old_table, kLengthOffset, new_length);
    // All fields within the old capacity are already cleared (see below).
    return old_table;
  }

  // Grow table exponentially to guarantee amortized constant allocation and gc
  // time.
  int max_grow = WasmDispatchTable::kMaxLength - old_length;
  int min_grow = new_length - old_capacity;
  CHECK_LE(min_grow, max_grow);
  // Grow by old capacity, and at least by 8. Clamp to min_grow and max_grow.
  int exponential_grow = std::max(old_capacity, 8);
  int grow = std::clamp(exponential_grow, min_grow, max_grow);
  int new_capacity = old_capacity + grow;
  Handle<WasmDispatchTable> new_table =
      WasmDispatchTable::New(isolate, new_capacity);

  // Writing non-atomically is fine here because this is a freshly allocated
  // object.
  new_table->WriteField<int>(kLengthOffset, new_length);
  for (int i = 0; i < old_length; ++i) {
    WasmCodePointer call_target = old_table->target(i);
    new_table->Set(i, old_table->implicit_arg(i), call_target,
                   old_table->sig(i),
#if V8_ENABLE_DRUMBRAKE
                   old_table->function_index(i),
#endif  // V8_ENABLE_DRUMBRAKE
                   nullptr, IsAWrapper::kMaybe, WasmDispatchTable::kNewEntry);
  }
  return new_table;
}

bool WasmCapiFunction::MatchesSignature(
    wasm::CanonicalTypeIndex other_canonical_sig_index) const {
#if DEBUG
  // TODO(14034): Change this if indexed types are allowed.
  for (wasm::CanonicalValueType type : this->sig()->all()) {
    CHECK(!type.has_index());
  }
#endif
  // TODO(14034): Check for subtyping instead if C API functions can define
  // signature supertype.
  return shared()->wasm_capi_function_data()->sig_index() ==
         other_canonical_sig_index;
}

// static
Handle<WasmExceptionPackage> WasmExceptionPackage::New(
    Isolate* isolate, DirectHandle<WasmExceptionTag> exception_tag, int size) {
  DirectHandle<FixedArray> values = isolate->factory()->NewFixedArray(size);
  return New(isolate, exception_tag, values);
}

Handle<WasmExceptionPackage> WasmExceptionPackage::New(
    Isolate* isolate, DirectHandle<WasmExceptionTag> exception_tag,
    DirectHandle<FixedArray> values) {
  Handle<JSFunction> exception_cons(
      isolate->native_context()->wasm_exception_constructor(), isolate);
  Handle<JSObject> exception = isolate->factory()->NewJSObject(exception_cons);
  exception->InObjectPropertyAtPut(kTagIndex, *exception_tag);
  exception->InObjectPropertyAtPut(kValuesIndex, *values);
  return Cast<WasmExceptionPackage>(exception);
}

// static
Handle<Object> WasmExceptionPackage::GetExceptionTag(
    Isolate* isolate, Handle<WasmExceptionPackage> exception_package) {
  Handle<Object> tag;
  if (JSReceiver::GetProperty(isolate, exception_package,
                              isolate->factory()->wasm_exception_tag_symbol())
          .ToHandle(&tag)) {
    return tag;
  }
  return ReadOnlyRoots(isolate).undefined_value_handle();
}

// static
Handle<Object> WasmExceptionPackage::GetExceptionValues(
    Isolate* isolate, Handle<WasmExceptionPackage> exception_package) {
  Handle<Object> values;
  if (JSReceiver::GetProperty(
          isolate, exception_package,
          isolate->factory()->wasm_exception_values_symbol())
          .ToHandle(&values)) {
    DCHECK_IMPLIES(!IsUndefined(*values), IsFixedArray(*values));
    return values;
  }
  return ReadOnlyRoots(isolate).undefined_value_handle();
}

void EncodeI32ExceptionValue(DirectHandle<FixedArray> encoded_values,
                             uint32_t* encoded_index, uint32_t value) {
  encoded_values->set((*encoded_index)++, Smi::FromInt(value >> 16));
  encoded_values->set((*encoded_index)++, Smi::FromInt(value & 0xffff));
}

void EncodeI64ExceptionValue(DirectHandle<FixedArray> encoded_values,
                             uint32_t* encoded_index, uint64_t value) {
  EncodeI32ExceptionValue(encoded_values, encoded_index,
                          static_cast<uint32_t>(value >> 32));
  EncodeI32ExceptionValue(encoded_values, encoded_index,
                          static_cast<uint32_t>(value));
}

void DecodeI32ExceptionValue(DirectHandle<FixedArray> encoded_values,
                             uint32_t* encoded_index, uint32_t* value) {
  uint32_t msb = Cast<Smi>(encoded_values->get((*encoded_index)++)).value();
  uint32_t lsb = Cast<Smi>(encoded_values->get((*encoded_index)++)).value();
  *value = (msb << 16) | (lsb & 0xffff);
}

void DecodeI64ExceptionValue(DirectHandle<FixedArray> encoded_values,
                             uint32_t* encoded_index, uint64_t* value) {
  uint32_t lsb = 0, msb = 0;
  DecodeI32ExceptionValue(encoded_values, encoded_index, &msb);
  DecodeI32ExceptionValue(encoded_values, encoded_index, &lsb);
  *value = (static_cast<uint64_t>(msb) << 32) | static_cast<uint64_t>(lsb);
}

// static
Handle<WasmContinuationObject> WasmContinuationObject::New(
    Isolate* isolate, wasm::StackMemory* stack,
    wasm::JumpBuffer::StackState state, DirectHandle<HeapObject> parent,
    AllocationType allocation_type) {
  stack->jmpbuf()->stack_limit = stack->jslimit();
  stack->jmpbuf()->sp = stack->base();
  stack->jmpbuf()->fp = kNullAddress;
  stack->jmpbuf()->state = state;
  wasm::JumpBuffer* jmpbuf = stack->jmpbuf();
  Handle<WasmContinuationObject> result =
      isolate->factory()->NewWasmContinuationObject(
          reinterpret_cast<Address>(jmpbuf), stack, parent, allocation_type);
  return result;
}

bool UseGenericWasmToJSWrapper(wasm::ImportCallKind kind,
                               const wasm::CanonicalSig* sig,
                               wasm::Suspend suspend) {
  if (kind != wasm::ImportCallKind::kJSFunctionArityMatch &&
      kind != wasm::ImportCallKind::kJSFunctionArityMismatch) {
    return false;
  }
  DCHECK(wasm::IsJSCompatibleSignature(sig));
#if !V8_TARGET_ARCH_X64 && !V8_TARGET_ARCH_ARM64 && !V8_TARGET_ARCH_ARM && \
    !V8_TARGET_ARCH_IA32 && !V8_TARGET_ARCH_RISCV64 &&                     \
    !V8_TARGET_ARCH_RISCV32 && !V8_TARGET_ARCH_PPC64 &&                    \
    !V8_TARGET_ARCH_S390X && !V8_TARGET_ARCH_LOONG64 && !V8_TARGET_ARCH_MIPS64
  return false;
#else
  if (suspend != wasm::Suspend::kNoSuspend) return false;

  return v8_flags.wasm_generic_wrapper;
#endif
}

// static
Handle<WasmContinuationObject> WasmContinuationObject::New(
    Isolate* isolate, wasm::StackMemory* stack,
    wasm::JumpBuffer::StackState state, AllocationType allocation_type) {
  auto parent = ReadOnlyRoots(isolate).undefined_value();
  return New(isolate, stack, state, handle(parent, isolate), allocation_type);
}
#ifdef DEBUG

namespace {

constexpr uint32_t kBytesPerExceptionValuesArrayElement = 2;

size_t ComputeEncodedElementSize(wasm::ValueType type) {
  size_t byte_size = type.value_kind_size();
  DCHECK_EQ(byte_size % kBytesPerExceptionValuesArrayElement, 0);
  DCHECK_LE(1, byte_size / kBytesPerExceptionValuesArrayElement);
  return byte_size / kBytesPerExceptionValuesArrayElement;
}

}  // namespace

#endif  // DEBUG

// static
uint32_t WasmExceptionPackage::GetEncodedSize(const wasm::WasmTag* tag) {
  return GetEncodedSize(tag->sig);
}

// static
uint32_t WasmExceptionPackage::GetEncodedSize(const wasm::WasmTagSig* sig) {
  uint32_t encoded_size = 0;
  for (size_t i = 0; i < sig->parameter_count(); ++i) {
    switch (sig->GetParam(i).kind()) {
      case wasm::kI32:
      case wasm::kF32:
        DCHECK_EQ(2, ComputeEncodedElementSize(sig->GetParam(i)));
        encoded_size += 2;
        break;
      case wasm::kI64:
      case wasm::kF64:
        DCHECK_EQ(4, ComputeEncodedElementSize(sig->GetParam(i)));
        encoded_size += 4;
        break;
      case wasm::kS128:
        DCHECK_EQ(8, ComputeEncodedElementSize(sig->GetParam(i)));
        encoded_size += 8;
        break;
      case wasm::kRef:
      case wasm::kRefNull:
        encoded_size += 1;
        break;
      case wasm::kRtt:
      case wasm::kVoid:
      case wasm::kTop:
      case wasm::kBottom:
      case wasm::kI8:
      case wasm::kI16:
      case wasm::kF16:
        UNREACHABLE();
    }
  }
  return encoded_size;
}

bool WasmExportedFunction::IsWasmExportedFunction(Tagged<Object> object) {
  if (!IsJSFunction(object)) return false;
  Tagged<JSFunction> js_function = Cast<JSFunction>(object);
  Tagged<Code> code = js_function->code(GetIsolateForSandbox(js_function));
  if (CodeKind::JS_TO_WASM_FUNCTION != code->kind() &&
#if V8_ENABLE_DRUMBRAKE
      code->builtin_id() != Builtin::kGenericJSToWasmInterpreterWrapper &&
#endif  // V8_ENABLE_DRUMBRAKE
      code->builtin_id() != Builtin::kJSToWasmWrapper &&
      code->builtin_id() != Builtin::kWasmPromising &&
      code->builtin_id() != Builtin::kWasmStressSwitch) {
    return false;
  }
  DCHECK(js_function->shared()->HasWasmExportedFunctionData());
  return true;
}

bool WasmCapiFunction::IsWasmCapiFunction(Tagged<Object> object) {
  if (!IsJSFunction(object)) return false;
  Tagged<JSFunction> js_function = Cast<JSFunction>(object);
  // TODO(jkummerow): Enable this when there is a JavaScript wrapper
  // able to call this function.
  // if (js_function->code()->kind() != CodeKind::WASM_TO_CAPI_FUNCTION) {
  //   return false;
  // }
  // DCHECK(js_function->shared()->HasWasmCapiFunctionData());
  // return true;
  return js_function->shared()->HasWasmCapiFunctionData();
}

Handle<WasmCapiFunction> WasmCapiFunction::New(
    Isolate* isolate, Address call_target, DirectHandle<Foreign> embedder_data,
    wasm::CanonicalTypeIndex sig_index, const wasm::CanonicalSig* sig,
    uintptr_t signature_hash) {
  // TODO(jkummerow): Install a JavaScript wrapper. For now, calling
  // these functions directly is unsupported; they can only be called
  // from Wasm code.

  // To support simulator builds, we potentially have to redirect the
  // call target (which is an address pointing into the C++ binary).
  call_target = ExternalReference::Create(call_target).address();

  DirectHandle<Map> rtt = isolate->factory()->wasm_func_ref_map();
  DirectHandle<WasmCapiFunctionData> fun_data =
      isolate->factory()->NewWasmCapiFunctionData(
          call_target, embedder_data, BUILTIN_CODE(isolate, Illegal), rtt,
          sig_index, sig, signature_hash);
  Handle<SharedFunctionInfo> shared =
      isolate->factory()->NewSharedFunctionInfoForWasmCapiFunction(fun_data);
  Handle<JSFunction> result =
      Factory::JSFunctionBuilder{isolate, shared, isolate->native_context()}
          .Build();
  fun_data->internal()->set_external(*result);
  return Cast<WasmCapiFunction>(result);
}

Handle<WasmExportedFunction> WasmExportedFunction::New(
    Isolate* isolate, DirectHandle<WasmTrustedInstanceData> instance_data,
    DirectHandle<WasmFuncRef> func_ref,
    DirectHandle<WasmInternalFunction> internal_function, int arity,
    DirectHandle<Code> export_wrapper) {
  DCHECK(CodeKind::JS_TO_WASM_FUNCTION == export_wrapper->kind() ||
         (export_wrapper->is_builtin() &&
          (export_wrapper->builtin_id() == Builtin::kJSToWasmWrapper ||
#if V8_ENABLE_DRUMBRAKE
           export_wrapper->builtin_id() ==
               Builtin::kGenericJSToWasmInterpreterWrapper ||
#endif  // V8_ENABLE_DRUMBRAKE
           export_wrapper->builtin_id() == Builtin::kWasmPromising ||
           export_wrapper->builtin_id() == Builtin::kWasmStressSwitch)));
  int func_index = internal_function->function_index();
  Factory* factory = isolate->factory();
  DirectHandle<Map> rtt;
  wasm::Promise promise =
      export_wrapper->builtin_id() == Builtin::kWasmPromising
          ? wasm::kPromise
          : wasm::kNoPromise;
  const wasm::WasmModule* module = instance_data->module();
  wasm::CanonicalTypeIndex sig_id =
      module->canonical_sig_id(module->functions[func_index].sig_index);
  const wasm::CanonicalSig* sig =
      wasm::GetTypeCanonicalizer()->LookupFunctionSignature(sig_id);
  DirectHandle<WasmExportedFunctionData> function_data =
      factory->NewWasmExportedFunctionData(
          export_wrapper, instance_data, func_ref, internal_function, sig,
          sig_id, v8_flags.wasm_wrapper_tiering_budget, promise);

#if V8_ENABLE_DRUMBRAKE
  if (v8_flags.wasm_jitless) {
    uint32_t aligned_size =
        wasm::WasmBytecode::JSToWasmWrapperPackedArraySize(sig);
    bool hasRefArgs = wasm::WasmBytecode::RefArgsCount(sig) > 0;
    bool hasRefRets = wasm::WasmBytecode::RefRetsCount(sig) > 0;
    function_data->set_packed_args_size(
        wasm::WasmInterpreterRuntime::PackedArgsSizeField::encode(
            aligned_size) |
        wasm::WasmInterpreterRuntime::HasRefArgsField::encode(hasRefArgs) |
        wasm::WasmInterpreterRuntime::HasRefRetsField::encode(hasRefRets));
  }
#endif  // V8_ENABLE_DRUMBRAKE

  MaybeHandle<String> maybe_name;
  bool is_asm_js_module = is_asmjs_module(module);
  if (is_asm_js_module) {
    // We can use the function name only for asm.js. For WebAssembly, the
    // function name is specified as the function_index.toString().
    maybe_name = WasmModuleObject::GetFunctionNameOrNull(
        isolate, handle(instance_data->module_object(), isolate), func_index);
  }
  Handle<String> name;
  if (!maybe_name.ToHandle(&name)) {
    base::EmbeddedVector<char, 16> buffer;
    int length = SNPrintF(buffer, "%d", func_index);
    name = factory
               ->NewStringFromOneByte(
                   base::Vector<uint8_t>::cast(buffer.SubVector(0, length)))
               .ToHandleChecked();
  }
  Handle<Map> function_map;
  switch (module->origin) {
    case wasm::kWasmOrigin:
      function_map = isolate->wasm_exported_function_map();
      break;
    case wasm::kAsmJsSloppyOrigin:
      function_map = isolate->sloppy_function_map();
      break;
    case wasm::kAsmJsStrictOrigin:
      function_map = isolate->strict_function_map();
      break;
  }

  Handle<NativeContext> context(isolate->native_context());
  Handle<SharedFunctionInfo> shared =
      factory->NewSharedFunctionInfoForWasmExportedFunction(name, function_data,
                                                            arity, kAdapt);

  Handle<JSFunction> js_function =
      Factory::JSFunctionBuilder{isolate, shared, context}
          .set_map(function_map)
          .Build();

  // According to the spec, exported functions should not have a [[Construct]]
  // method. This does not apply to functions exported from asm.js however.
  DCHECK_EQ(is_asm_js_module, IsConstructor(*js_function));
  if (instance_data->has_instance_object()) {
    shared->set_script(instance_data->module_object()->script(), kReleaseStore);
  } else {
    shared->set_script(*isolate->factory()->undefined_value(), kReleaseStore);
  }
  function_data->internal()->set_external(*js_function);
  return Cast<WasmExportedFunction>(js_function);
}

bool WasmExportedFunctionData::MatchesSignature(
    wasm::CanonicalTypeIndex other_canonical_type_index) {
  return wasm::GetTypeCanonicalizer()->IsCanonicalSubtype(
      sig_index(), other_canonical_type_index);
}

// static
std::unique_ptr<char[]> WasmExportedFunction::GetDebugName(
    const wasm::CanonicalSig* sig) {
  constexpr const char kPrefix[] = "js-to-wasm:";
  // prefix + parameters + delimiter + returns + zero byte
  size_t len = strlen(kPrefix) + sig->all().size() + 2;
  auto buffer = base::OwnedVector<char>::New(len);
  memcpy(buffer.begin(), kPrefix, strlen(kPrefix));
  PrintSignature(buffer.as_vector() + strlen(kPrefix), sig);
  return buffer.ReleaseData();
}

// static
bool WasmJSFunction::IsWasmJSFunction(Tagged<Object> object) {
  if (!IsJSFunction(object)) return false;
  Tagged<JSFunction> js_function = Cast<JSFunction>(object);
  return js_function->shared()->HasWasmJSFunctionData();
}

Handle<Map> CreateFuncRefMap(Isolate* isolate, Handle<Map> opt_rtt_parent) {
  const int inobject_properties = 0;
  const InstanceType instance_type = WASM_FUNC_REF_TYPE;
  const ElementsKind elements_kind = TERMINAL_FAST_ELEMENTS_KIND;
  DirectHandle<WasmTypeInfo> type_info = isolate->factory()->NewWasmTypeInfo(
      kNullAddress, opt_rtt_parent, Handle<WasmTrustedInstanceData>(),
      wasm::ModuleTypeIndex::Invalid());
  constexpr int kInstanceSize = WasmFuncRef::kSize;
  DCHECK_EQ(
      kInstanceSize,
      Cast<Map>(isolate->root(RootIndex::kWasmFuncRefMap))->instance_size());
  Handle<Map> map = isolate->factory()->NewContextlessMap(
      instance_type, kInstanceSize, elements_kind, inobject_properties);
  map->set_wasm_type_info(*type_info);
  return map;
}

Handle<WasmJSFunction> WasmJSFunction::New(Isolate* isolate,
                                           const wasm::FunctionSig* sig,
                                           Handle<JSReceiver> callable,
                                           wasm::Suspend suspend) {
  DCHECK_LE(sig->all().size(), kMaxInt);
  int parameter_count = static_cast<int>(sig->parameter_count());
  Factory* factory = isolate->factory();

  DirectHandle<Map> rtt;
  Handle<NativeContext> context(isolate->native_context());

  static_assert(wasm::kMaxCanonicalTypes <= kMaxInt);
  // TODO(clemensb): Merge the next two lines into a single call.
  wasm::CanonicalTypeIndex sig_id =
      wasm::GetTypeCanonicalizer()->AddRecursiveGroup(sig);
  const wasm::CanonicalSig* canonical_sig =
      wasm::GetTypeCanonicalizer()->LookupFunctionSignature(sig_id);

  wasm::TypeCanonicalizer::PrepareForCanonicalTypeId(isolate, sig_id);

  DirectHandle<WeakFixedArray> canonical_rtts(
      isolate->heap()->wasm_canonical_rtts(), isolate);

  Tagged<MaybeObject> maybe_canonical_map = canonical_rtts->get(sig_id.index);

  if (!maybe_canonical_map.IsCleared()) {
    rtt = direct_handle(
        Cast<Map>(maybe_canonical_map.GetHeapObjectAssumeWeak()), isolate);
  } else {
    rtt = CreateFuncRefMap(isolate, Handle<Map>());
    canonical_rtts->set(sig_id.index, MakeWeak(*rtt));
  }

  DirectHandle<Code> js_to_js_wrapper_code =
      wasm::IsJSCompatibleSignature(canonical_sig)
          ? isolate->builtins()->code_handle(Builtin::kJSToJSWrapper)
          : isolate->builtins()->code_handle(Builtin::kJSToJSWrapperInvalidSig);

#if V8_ENABLE_SANDBOX
  uint64_t signature_hash = wasm::SignatureHasher::Hash(sig);
#else
  uintptr_t signature_hash = 0;
#endif

  DirectHandle<WasmJSFunctionData> function_data =
      factory->NewWasmJSFunctionData(sig_id, callable, js_to_js_wrapper_code,
                                     rtt, suspend, wasm::kNoPromise,
                                     signature_hash);
  DirectHandle<WasmInternalFunction> internal_function{
      function_data->internal(), isolate};

  if (!wasm::IsJSCompatibleSignature(canonical_sig)) {
    internal_function->set_call_target(
        wasm::GetBuiltinCodePointer<Builtin::kWasmToJsWrapperInvalidSig>(
            isolate));
#if V8_ENABLE_DRUMBRAKE
  } else if (v8_flags.wasm_jitless) {
    function_data->func_ref()->internal(isolate)->set_call_target(
        wasm::GetBuiltinCodePointer<
            Builtin::kGenericWasmToJSInterpreterWrapper>(isolate));
#endif  // V8_ENABLE_DRUMBRAKE
  } else {
    int expected_arity = parameter_count;
    wasm::ImportCallKind kind;
    if (IsJSFunction(*callable)) {
      Tagged<SharedFunctionInfo> shared = Cast<JSFunction>(callable)->shared();
      expected_arity =
          shared->internal_formal_parameter_count_without_receiver();
      if (expected_arity == parameter_count) {
        kind = wasm::ImportCallKind::kJSFunctionArityMatch;
      } else {
        kind = wasm::ImportCallKind::kJSFunctionArityMismatch;
      }
    } else {
      kind = wasm::ImportCallKind::kUseCallBuiltin;
    }
    wasm::WasmCodeRefScope code_ref_scope;
    wasm::WasmImportWrapperCache* cache = wasm::GetWasmImportWrapperCache();
    wasm::WasmCode* wrapper =
        cache->MaybeGet(kind, sig_id, expected_arity, suspend);
    if (wrapper) {
      internal_function->set_call_target(wrapper->code_pointer());
      function_data->offheap_data()->set_wrapper(wrapper);
    } else if (UseGenericWasmToJSWrapper(kind, canonical_sig, suspend)) {
      internal_function->set_call_target(
          wasm::GetBuiltinCodePointer<Builtin::kWasmToJsWrapperAsm>(isolate));
    } else {
      // Initialize the import wrapper cache if that hasn't happened yet.
      cache->LazyInitialize(isolate);
      constexpr bool kNoSourcePositions = false;
      wrapper = cache->CompileWasmImportCallWrapper(
          isolate, kind, canonical_sig, sig_id, kNoSourcePositions,
          expected_arity, suspend);
      internal_function->set_call_target(wrapper->code_pointer());
      function_data->offheap_data()->set_wrapper(wrapper);
    }
  }

  Handle<String> name = factory->Function_string();
  if (IsJSFunction(*callable)) {
    name = JSFunction::GetDebugName(Cast<JSFunction>(callable));
    name = String::Flatten(isolate, name);
  }
  Handle<SharedFunctionInfo> shared =
      factory->NewSharedFunctionInfoForWasmJSFunction(name, function_data);
  shared->set_internal_formal_parameter_count(
      JSParameterCount(parameter_count));
  Handle<JSFunction> js_function =
      Factory::JSFunctionBuilder{isolate, shared, context}
          .set_map(isolate->wasm_exported_function_map())
          .Build();
  internal_function->set_external(*js_function);
  return Cast<WasmJSFunction>(js_function);
}

void WasmJSFunctionData::OffheapData::set_wrapper(wasm::WasmCode* wrapper) {
  DCHECK_NULL(wrapper_);  // We shouldn't overwrite existing wrappers.
  wrapper_ = wrapper;
  wrapper->IncRef();
}

WasmJSFunctionData::OffheapData::~OffheapData() {
  if (wrapper_) {
    wasm::WasmCode::DecrementRefCount({&wrapper_, 1});
  }
}

Tagged<JSReceiver> WasmJSFunctionData::GetCallable() const {
  return Cast<JSReceiver>(
      Cast<WasmImportData>(internal()->implicit_arg())->callable());
}

wasm::Suspend WasmJSFunctionData::GetSuspend() const {
  return static_cast<wasm::Suspend>(
      Cast<WasmImportData>(internal()->implicit_arg())->suspend());
}

const wasm::CanonicalSig* WasmJSFunctionData::GetSignature() const {
  return wasm::GetWasmEngine()->type_canonicalizer()->LookupFunctionSignature(
      sig_index());
}

bool WasmJSFunctionData::MatchesSignature(
    wasm::CanonicalTypeIndex other_canonical_sig_index) const {
#if DEBUG
  // TODO(14034): Change this if indexed types are allowed.
  const wasm::CanonicalSig* sig = GetSignature();
  for (wasm::CanonicalValueType type : sig->all()) CHECK(!type.has_index());
#endif
  // TODO(14034): Check for subtyping instead if WebAssembly.Function can define
  // signature supertype.
  return sig_index() == other_canonical_sig_index;
}

bool WasmExternalFunction::IsWasmExternalFunction(Tagged<Object> object) {
  return WasmExportedFunction::IsWasmExportedFunction(object) ||
         WasmJSFunction::IsWasmJSFunction(object) ||
         WasmCapiFunction::IsWasmCapiFunction(object);
}

Handle<WasmExceptionTag> WasmExceptionTag::New(Isolate* isolate, int index) {
  auto result = Cast<WasmExceptionTag>(isolate->factory()->NewStruct(
      WASM_EXCEPTION_TAG_TYPE, AllocationType::kOld));
  result->set_index(index);
  return result;
}

Handle<AsmWasmData> AsmWasmData::New(
    Isolate* isolate, std::shared_ptr<wasm::NativeModule> native_module,
    DirectHandle<HeapNumber> uses_bitset) {
  const WasmModule* module = native_module->module();
  const bool kUsesLiftoff = false;
  size_t memory_estimate =
      wasm::WasmCodeManager::EstimateNativeModuleCodeSize(
          module, kUsesLiftoff, wasm::kNoDynamicTiering) +
      wasm::WasmCodeManager::EstimateNativeModuleMetaDataSize(module);
  DirectHandle<Managed<wasm::NativeModule>> managed_native_module =
      Managed<wasm::NativeModule>::From(isolate, memory_estimate,
                                        std::move(native_module));
  auto result = Cast<AsmWasmData>(
      isolate->factory()->NewStruct(ASM_WASM_DATA_TYPE, AllocationType::kOld));
  result->set_managed_native_module(*managed_native_module);
  result->set_uses_bitset(*uses_bitset);
  return result;
}

namespace {
constexpr int32_t kInt31MaxValue = 0x3fffffff;
constexpr int32_t kInt31MinValue = -kInt31MaxValue - 1;

// Tries to canonicalize a HeapNumber to an i31ref Smi. Returns the original
// HeapNumber if it fails.
Handle<Object> CanonicalizeHeapNumber(Handle<Object> number, Isolate* isolate) {
  double double_value = Cast<HeapNumber>(number)->value();
  if (double_value >= kInt31MinValue && double_value <= kInt31MaxValue &&
      !IsMinusZero(double_value) &&
      double_value == FastI2D(FastD2I(double_value))) {
    return handle(Smi::FromInt(FastD2I(double_value)), isolate);
  }
  return number;
}

// Tries to canonicalize a Smi into an i31 Smi. Returns a HeapNumber if it
// fails.
Handle<Object> CanonicalizeSmi(Handle<Object> smi, Isolate* isolate) {
  if constexpr (SmiValuesAre31Bits()) return smi;

  int32_t value = Cast<Smi>(*smi).value();

  if (value <= kInt31MaxValue && value >= kInt31MinValue) {
    return smi;
  } else {
    return isolate->factory()->NewHeapNumber(value);
  }
}
}  // namespace

namespace wasm {
MaybeHandle<Object> JSToWasmObject(Isolate* isolate, Handle<Object> value,
                                   CanonicalValueType expected,
                                   const char** error_message) {
  DCHECK(expected.is_object_reference());
  if (expected.kind() == kRefNull && IsNull(*value, isolate)) {
    switch (expected.heap_representation()) {
      case HeapType::kStringViewWtf8:
        *error_message = "stringview_wtf8 has no JS representation";
        return {};
      case HeapType::kStringViewWtf16:
        *error_message = "stringview_wtf16 has no JS representation";
        return {};
      case HeapType::kStringViewIter:
        *error_message = "stringview_iter has no JS representation";
        return {};
      case HeapType::kExn:
        *error_message = "invalid type (ref null exn)";
        return {};
      case HeapType::kNoExn:
        *error_message = "invalid type (ref null noexn)";
        return {};
      default:
        return expected.use_wasm_null() ? isolate->factory()->wasm_null()
                                        : value;
    }
  }

  switch (expected.heap_representation_non_shared()) {
    case HeapType::kFunc: {
      if (!(WasmExternalFunction::IsWasmExternalFunction(*value) ||
            WasmCapiFunction::IsWasmCapiFunction(*value))) {
        *error_message =
            "function-typed object must be null (if nullable) or a Wasm "
            "function object";
        return {};
      }
      return handle(
          Cast<JSFunction>(*value)->shared()->wasm_function_data()->func_ref(),
          isolate);
    }
    case HeapType::kExtern: {
      if (!IsNull(*value, isolate)) return value;
      *error_message = "null is not allowed for (ref extern)";
      return {};
    }
    case HeapType::kAny: {
      if (IsSmi(*value)) return CanonicalizeSmi(value, isolate);
      if (IsHeapNumber(*value)) {
        return CanonicalizeHeapNumber(value, isolate);
      }
      if (!IsNull(*value, isolate)) return value;
      *error_message = "null is not allowed for (ref any)";
      return {};
    }
    case HeapType::kExn:
      *error_message = "invalid type (ref exn)";
      return {};
    case HeapType::kStruct: {
      if (IsWasmStruct(*value)) {
        return value;
      }
      *error_message =
          "structref object must be null (if nullable) or a wasm struct";
      return {};
    }
    case HeapType::kArray: {
      if (IsWasmArray(*value)) {
        return value;
      }
      *error_message =
          "arrayref object must be null (if nullable) or a wasm array";
      return {};
    }
    case HeapType::kEq: {
      if (IsSmi(*value)) {
        Handle<Object> truncated = CanonicalizeSmi(value, isolate);
        if (IsSmi(*truncated)) return truncated;
      } else if (IsHeapNumber(*value)) {
        Handle<Object> truncated = CanonicalizeHeapNumber(value, isolate);
        if (IsSmi(*truncated)) return truncated;
      } else if (IsWasmStruct(*value) || IsWasmArray(*value)) {
        return value;
      }
      *error_message =
          "eqref object must be null (if nullable), or a wasm "
          "struct/array, or a Number that fits in i31ref range";
      return {};
    }
    case HeapType::kI31: {
      if (IsSmi(*value)) {
        Handle<Object> truncated = CanonicalizeSmi(value, isolate);
        if (IsSmi(*truncated)) return truncated;
      } else if (IsHeapNumber(*value)) {
        Handle<Object> truncated = CanonicalizeHeapNumber(value, isolate);
        if (IsSmi(*truncated)) return truncated;
      }
      *error_message =
          "i31ref object must be null (if nullable) or a Number that fits "
          "in i31ref range";
      return {};
    }
    case HeapType::kString:
      if (IsString(*value)) return value;
      *error_message = "wrong type (expected a string)";
      return {};
    case HeapType::kStringViewWtf8:
      *error_message = "stringview_wtf8 has no JS representation";
      return {};
    case HeapType::kStringViewWtf16:
      *error_message = "stringview_wtf16 has no JS representation";
      return {};
    case HeapType::kStringViewIter:
      *error_message = "stringview_iter has no JS representation";
      return {};
    case HeapType::kNoFunc:
    case HeapType::kNoExtern:
    case HeapType::kNoExn:
    case HeapType::kNone: {
      *error_message = "only null allowed for null types";
      return {};
    }
    default: {
      DCHECK(expected.has_index());
      CanonicalTypeIndex canonical_index = expected.ref_index();
      auto type_canonicalizer = GetWasmEngine()->type_canonicalizer();

      if (WasmExportedFunction::IsWasmExportedFunction(*value)) {
        Tagged<WasmExportedFunction> function =
            Cast<WasmExportedFunction>(*value);
        CanonicalTypeIndex real_type_index =
            function->shared()->wasm_exported_function_data()->sig_index();
        if (!type_canonicalizer->IsCanonicalSubtype(real_type_index,
                                                    canonical_index)) {
          *error_message =
              "assigned exported function has to be a subtype of the "
              "expected type";
          return {};
        }
        return handle(Cast<WasmExternalFunction>(*value)->func_ref(), isolate);
      } else if (WasmJSFunction::IsWasmJSFunction(*value)) {
        if (!Cast<WasmJSFunction>(*value)
                 ->shared()
                 ->wasm_js_function_data()
                 ->MatchesSignature(canonical_index)) {
          *error_message =
              "assigned WebAssembly.Function has to be a subtype of the "
              "expected type";
          return {};
        }
        return handle(Cast<WasmExternalFunction>(*value)->func_ref(), isolate);
      } else if (WasmCapiFunction::IsWasmCapiFunction(*value)) {
        if (!Cast<WasmCapiFunction>(*value)->MatchesSignature(
                canonical_index)) {
          *error_message =
              "assigned C API function has to be a subtype of the expected "
              "type";
          return {};
        }
        return handle(Cast<WasmExternalFunction>(*value)->func_ref(), isolate);
      } else if (IsWasmStruct(*value) || IsWasmArray(*value)) {
        auto wasm_obj = Cast<WasmObject>(value);
        Tagged<WasmTypeInfo> type_info = wasm_obj->map()->wasm_type_info();
        ModuleTypeIndex real_idx = type_info->type_index();
        const WasmModule* real_module =
            type_info->trusted_data(isolate)->module();
        CanonicalTypeIndex real_canonical_index =
            real_module->canonical_type_id(real_idx);
        if (!type_canonicalizer->IsCanonicalSubtype(real_canonical_index,
                                                    canonical_index)) {
          *error_message = "object is not a subtype of expected type";
          return {};
        }
        return value;
      } else {
        *error_message = "JS object does not match expected wasm type";
        return {};
      }
    }
  }
}

// Utility which canonicalizes {expected} in addition.
MaybeHandle<Object> JSToWasmObject(Isolate* isolate, const WasmModule* module,
                                   Handle<Object> value, ValueType expected,
                                   const char** error_message) {
  CanonicalValueType canonical;
  if (expected.has_index()) {
    CanonicalTypeIndex index = module->canonical_type_id(expected.ref_index());
    canonical = CanonicalValueType::FromIndex(expected.kind(), index);
  } else {
    canonical = CanonicalValueType{expected};
  }
  return JSToWasmObject(isolate, value, canonical, error_message);
}

Handle<Object> WasmToJSObject(Isolate* isolate, Handle<Object> value) {
  if (IsWasmNull(*value)) {
    return isolate->factory()->null_value();
  } else if (IsWasmFuncRef(*value)) {
    return i::WasmInternalFunction::GetOrCreateExternal(
        i::handle(i::Cast<i::WasmFuncRef>(*value)->internal(isolate), isolate));
  } else {
    return value;
  }
}

}  // namespace wasm

}  // namespace internal
}  // namespace v8

#include "src/objects/object-macros-undef.h"
#undef TRACE_IFT
```