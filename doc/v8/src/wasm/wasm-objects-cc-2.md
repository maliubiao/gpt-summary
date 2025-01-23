Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/wasm/wasm-objects.cc`.

Here's a breakdown of the code's main responsibilities:

1. **Initialization of Data Segments:**  The code initializes data segments of a WebAssembly module. This involves setting up pointers to the raw data in the module's bytecode.

2. **Retrieving Call Targets:**  It provides a mechanism to get the memory address of a function to be called, handling both imported and locally defined functions. It also considers the `wasm_jitless` flag.

3. **Table Operations (Copy and Initialization):**  Functions are provided to copy entries between WebAssembly tables and to initialize table entries from element segments. These functions include bounds checking and handle shared tables.

4. **Function References:** The code deals with the creation and retrieval of function references (`WasmFuncRef`), which are used to represent functions as first-class values in WebAssembly. This includes handling imports and potentially creating generic wrappers for them.

5. **External Function Creation:**  It manages the creation of JavaScript `JSFunction` objects that wrap WebAssembly internal functions. This involves the use of JSToWasm wrappers for type conversion and calling conventions.

6. **Import Data Management:**  Functions are included to manage `WasmImportData`, which holds information about imported WebAssembly functions. This includes setting the "call origin" to track how the import was invoked (e.g., directly, through a table).

7. **Importing JS Functions into Tables:** The code enables the importing of JavaScript functions into WebAssembly tables, handling signature matching and creating appropriate wrappers.

8. **Global Variable Access:** It provides methods to get the storage location and values of WebAssembly global variables.

9. **Struct and Array Access:** The code includes functions to read values from fields of WebAssembly structs and elements of arrays.

10. **Tag Object Creation:** It facilitates the creation of `WasmTagObject` instances, which represent WebAssembly exception tags.

11. **Dispatch Table Management:** The code includes a `WasmDispatchTable` to store information needed for indirect calls. It handles adding, removing, and updating entries in the dispatch table, including managing the lifecycle of call wrappers.

Essentially, this code snippet is a core part of the V8 engine's WebAssembly implementation, focused on managing the runtime representation of WebAssembly modules, functions, tables, globals, and other entities, and enabling interoperability with JavaScript.
好的，我们来归纳一下 `v8/src/wasm/wasm-objects.cc` 这个代码片段的功能。

**核心功能归纳:**

这段代码主要负责管理和操作 V8 中 WebAssembly 相关的对象，特别是与 WebAssembly 实例数据 (`WasmTrustedInstanceData`) 相关的操作。它涵盖了以下几个关键方面：

1. **数据段初始化:**
   -  负责将 WebAssembly 模块的 WireBytes 中的数据复制到实例的数据段中。
   -  区分主动和被动数据段，并进行相应的初始化。

2. **函数调用目标获取:**
   -  提供 `GetCallTarget` 方法来获取指定函数索引的调用目标地址。
   -  区分导入函数和本地函数，并根据 `v8_flags.wasm_jitless` 标志返回不同的结果。

3. **表格操作:**
   -  `CopyTableEntries` 方法用于在不同的 WebAssembly 表格之间复制条目。它会进行边界检查，并处理向前和向后复制的情况。
   -  `InitTableEntries` 方法用于使用元素段的数据初始化 WebAssembly 表格的条目。它也涉及边界检查，并能处理共享表格和共享元素段的情况。

4. **函数引用 (`WasmFuncRef`) 的管理:**
   -  `try_get_func_ref` 尝试获取已存在的函数引用。
   -  `GetOrCreateFuncRef` 用于获取或创建指定函数的函数引用。这包括处理导入函数，并可能根据需要创建泛型包装器 (`generic wrapper`)。

5. **外部 JavaScript 函数 (`JSFunction`) 的创建:**
   -  `WasmInternalFunction::try_get_external` 尝试获取内部函数对应的外部 JavaScript 函数。
   -  `WasmInternalFunction::GetOrCreateExternal` 用于获取或创建 WebAssembly 内部函数对应的外部 JavaScript 函数。这涉及到 JSToWasm 包装器的创建和缓存。

6. **导入数据 (`WasmImportData`) 的管理:**
   -  提供了 `SetImportIndexAsCallOrigin`, `SetIndexInTableAsCallOrigin`, `SetCrossInstanceTableIndexAsCallOrigin`, 和 `SetFuncRefAsCallOrigin` 等静态方法来设置导入函数的调用来源信息。
   -  提供了 `CallOriginIsImportIndex` 和 `CallOriginIsIndexInTable` 来检查调用来源的类型。
   -  `CallOriginAsIndex` 用于获取调用来源的索引。

7. **将 JavaScript 函数导入 WebAssembly 表格:**
   -  `WasmTrustedInstanceData::ImportWasmJSFunctionIntoTable` 方法允许将 JavaScript 函数导入到 WebAssembly 表格中。这包括签名匹配、包装器创建等复杂逻辑。

8. **全局变量访问:**
   -  `GetGlobalStorage` 用于获取全局变量的存储地址。
   -  `GetGlobalBufferAndIndex` 用于获取引用类型全局变量的缓冲区和索引。
   -  `GetGlobalValue` 用于获取全局变量的值。

9. **结构体 (`WasmStruct`) 和数组 (`WasmArray`) 访问:**
   -  `WasmStruct::GetFieldValue` 用于获取结构体字段的值。
   -  `WasmArray::GetElement` 用于获取数组元素的值。
   -  `WasmArray::SetTaggedElement` 用于设置数组中的对象引用。

10. **标签对象 (`WasmTagObject`) 的创建:**
    - `WasmTagObject::New` 用于创建表示 WebAssembly 异常标签的对象。

11. **分发表 (`WasmDispatchTable`) 的管理:**
    -  `WasmDispatchTableData` 类用于管理分发表的底层数据，包括包装器的引用计数。
    -  `WasmDispatchTable::Set`, `WasmDispatchTable::SetForImport`, `WasmDispatchTable::Clear`, `WasmDispatchTable::InstallCompiledWrapper`, `WasmDispatchTable::New`, 和 `WasmDispatchTable::Grow` 等方法用于操作分发表的条目和大小。

**与 JavaScript 的关系:**

这段代码是 V8 引擎 WebAssembly 实现的关键部分，直接影响着 WebAssembly 代码在 JavaScript 环境中的执行和互操作性。例如：

```javascript
// 假设有一个 WebAssembly 模块实例 instance

// 获取 WebAssembly 导出的函数
const exportedFunction = instance.exports.myFunction;

// 调用 WebAssembly 导出的函数，可能会涉及到 GetCallTarget 获取调用目标
exportedFunction();

// WebAssembly 中调用导入的 JavaScript 函数，可能会涉及到 WasmImportData 的管理
// 以及 ImportWasmJSFunctionIntoTable 的使用

// 创建一个 WebAssembly 表格
const table = new WebAssembly.Table({ initial: 10, element: 'funcref' });

// 将 WebAssembly 函数引用放入表格，可能涉及到 GetOrCreateFuncRef
// table.set(0, instance.exports.anotherFunction);

// 从表格中调用函数，可能涉及到分发表的管理
// table.get(0)();
```

**代码逻辑推理示例:**

**假设输入:**

- `native_module`: 一个指向已加载的 WebAssembly 本地模块的指针。
- `module`: 一个指向 WebAssembly 模块描述符的指针。
- `num_declared_data_segments`: 模块声明的数据段数量，假设为 2。
- `module->data_segments`: 一个包含两个数据段信息的向量，每个数据段包含 `source.offset()`, `source.end_offset()`, 和 `active` 标志。

**预期输出:**

`WasmTrustedInstanceData` 中的 `data_segment_starts_` 和 `data_segment_sizes_` 成员会被初始化：

- `data_segment_starts_` 的第一个元素会指向第一个数据段在 `native_module->wire_bytes()` 中的起始地址。
- `data_segment_starts_` 的第二个元素会指向第二个数据段在 `native_module->wire_bytes()` 中的起始地址。
- `data_segment_sizes_` 的第一个元素会是第一个数据段的长度（如果 `active` 为 false）或 0（如果 `active` 为 true）。
- `data_segment_sizes_` 的第二个元素会是第二个数据段的长度（如果 `active` 为 false）或 0（如果 `active` 为 true）。

**用户常见的编程错误 (可能导致相关代码执行错误):**

1. **表格操作越界:** 在 JavaScript 中操作 WebAssembly 表格时，如果索引超出表格的当前大小，会导致运行时错误。`CopyTableEntries` 和 `InitTableEntries` 中的边界检查可以防止 WebAssembly 内部的越界访问，但 JavaScript 代码仍然可能触发。

   ```javascript
   const table = new WebAssembly.Table({ initial: 5, element: 'funcref' });
   // 错误：尝试访问超出表格大小的索引
   table.get(10); // 抛出 RangeError
   ```

2. **类型不匹配的函数引用赋值:**  尝试将一个不兼容的函数引用赋值给表格条目会导致错误。`ImportWasmJSFunctionIntoTable` 中会进行签名匹配，但如果 JavaScript 代码尝试手动设置，可能会出错。

   ```javascript
   const table = new WebAssembly.Table({ initial: 1, element: 'funcref' });
   const func = () => {};
   // 错误：尝试将 JavaScript 函数直接赋值给 funcref 表格
   // (通常需要通过 WebAssembly 模块的导入机制)
   // table.set(0, func); // 这通常不会直接工作
   ```

3. **全局变量访问错误的类型:**  在 JavaScript 中访问 WebAssembly 全局变量时，如果假设了错误的类型，可能会导致意外的结果或错误。

   ```javascript
   // 假设 WebAssembly 模块导出一个 i32 类型的全局变量 'myGlobal'
   // 错误：假设全局变量是浮点数
   const globalValue = instance.exports.myGlobal;
   console.log(globalValue + 0.5); // 如果 globalValue 不是数字，可能会得到 NaN
   ```

**这段代码是第 3 部分，共 4 部分，其功能是管理和操作 WebAssembly 实例的各种运行时数据结构，为 WebAssembly 代码的执行提供必要的支持。它连接了 WebAssembly 的底层表示和 V8 的 JavaScript 环境，实现了互操作性。**

### 提示词
```
这是目录为v8/src/wasm/wasm-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wasm-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
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
    wasm::CanonicalTypeIndex other_c
```