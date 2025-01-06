Response: The user wants to understand the functionality of the C++ code snippet provided. This is the second part of a three-part series, suggesting the previous part likely dealt with the initial stages of module instantiation, and the next part will probably cover the final stages or related operations.

The code focuses on the later stages of WebAssembly module instantiation within the V8 JavaScript engine. It covers aspects like:

1. **Executing the start function**:  If the module has a start function, this section handles its execution.
2. **Looking up imports**: This involves finding the JavaScript values corresponding to imported WebAssembly entities (functions, globals, tables, memories). It differentiates between regular imports and those for asm.js modules.
3. **Loading data segments**:  This part copies data from the module's data segments into the linear memory of the instance.
4. **Initializing globals**:  It sets the initial values of the module's global variables.
5. **Processing exports**: This involves creating JavaScript wrappers for the exported WebAssembly entities, making them accessible from JavaScript.
6. **Initializing table elements**:  It sets the initial values in the module's tables, potentially involving function references or other values.
7. **Loading table segments**: Similar to data segments, this populates the module's tables with initial data.

To illustrate the connection with JavaScript, I need to show how these operations relate to the JavaScript API for WebAssembly.
```javascript
// 假设你已经编译了一个 WebAssembly 模块并获得了 module 对象
// 例如：
// const response = await fetch('my_module.wasm');
// const buffer = await response.arrayBuffer();
// const module = await WebAssembly.compile(buffer);

// 导入对象，包含需要导入的函数、全局变量、表和内存
const importObject = {
  // 导入名为 'env' 的模块
  env: {
    // 导入名为 'imported_func' 的函数
    imported_func: function(arg) {
      console.log('JavaScript function called with:', arg);
    },
    // 导入名为 'imported_global' 的全局变量
    imported_global: 42,
    // 导入名为 'memory' 的内存
    memory: new WebAssembly.Memory({ initial: 1 }),
    // 导入名为 'table' 的表
    table: new WebAssembly.Table({ initial: 2, element: 'anyfunc' })
  }
};

// 实例化 WebAssembly 模块，需要传入模块对象和导入对象
// InstanceBuilder::Instantiate(Handle<WasmModuleObject> module_object, ...)
// 在 C++ 代码中，`InstanceBuilder::Instantiate` 函数负责创建模块的实例。
// 它接收编译好的 `module_object_` 和导入对象 `ffi_`。
// 这对应于 JavaScript 中的 `WebAssembly.instantiate`。
const instance = await WebAssembly.instantiate(module, importObject);

// 执行 start 函数
// InstanceBuilder::ExecuteStartFunction()
// 如果 WebAssembly 模块定义了 start 函数，在实例化后会自动执行。
// 这部分 C++ 代码就是处理 start 函数的执行。
// 在 JavaScript 中，你不需要显式调用 start 函数，它会在实例化时自动运行。

// 查找导入值
// InstanceBuilder::LookupImport(uint32_t index, Handle<String> module_name, Handle<String> import_name)
// 这部分 C++ 代码负责在导入对象 `ffi_` 中查找与 WebAssembly 模块声明的导入相匹配的值。
// 例如，当 WebAssembly 模块声明要导入 'env' 模块的 'imported_func' 函数时，
// `LookupImport` 函数会在 `importObject.env.imported_func` 中查找。

// 加载数据段
// InstanceBuilder::LoadDataSegments(Handle<WasmTrustedInstanceData> trusted_instance_data, ...)
// WebAssembly 模块可以包含数据段，用于初始化内存。
// `LoadDataSegments` 函数将这些数据复制到实例的内存中。
// 在 JavaScript 中，你不需要手动加载数据段，`WebAssembly.instantiate` 会处理。
// 例如，如果 WebAssembly 模块有一个数据段将字符串 "hello" 写入内存地址 0，
// 实例化后，你可以通过 JavaScript 访问该内存：
// const memory = new Uint8Array(instance.exports.memory.buffer);
// const decoder = new TextDecoder();
// console.log(decoder.decode(memory.subarray(0, 5))); // 输出 "hello"

// 写入全局变量值
// InstanceBuilder::WriteGlobalValue(const WasmGlobal& global, const WasmValue& value)
// WebAssembly 模块可以声明全局变量，`WriteGlobalValue` 函数负责设置这些全局变量的初始值。
// 例如，如果 WebAssembly 模块声明了一个初始值为 10 的全局变量，
// `WriteGlobalValue` 会将 10 写入相应的内存位置。

// 处理导出
// InstanceBuilder::ProcessExports(Handle<WasmTrustedInstanceData> trusted_instance_data, ...)
// WebAssembly 模块可以导出函数、内存、表和全局变量。
// `ProcessExports` 函数创建 JavaScript 对象，以便从 JavaScript 中访问这些导出项。
// 例如，如果 WebAssembly 模块导出了一个名为 'exported_func' 的函数和一个名为 'exported_memory' 的内存，
// 实例化后，你可以通过 `instance.exports.exported_func` 和 `instance.exports.exported_memory` 访问它们。
const exportedFunction = instance.exports.exported_func;
const exportedMemory = instance.exports.memory;

// 设置表初始值
// InstanceBuilder::SetTableInitialValues(Handle<WasmTrustedInstanceData> trusted_instance_data, ...)
// WebAssembly 模块可以声明表，并指定初始值。
// `SetTableInitialValues` 函数负责设置表中的初始元素。
// 例如，如果 WebAssembly 模块声明了一个包含两个元素的表，初始值为两个不同的 WebAssembly 函数，
// `SetTableInitialValues` 会将这些函数引用添加到表中。

// 加载表段
// InstanceBuilder::LoadTableSegments(Handle<WasmTrustedInstanceData> trusted_instance_data, ...)
// 类似于数据段，WebAssembly 模块可以包含表段，用于初始化表的内容。
// `LoadTableSegments` 函数将表段中的元素添加到相应的表中。
// 例如，如果 WebAssembly 模块有一个表段，用于初始化一个函数表的前三个元素，
// `LoadTableSegments` 会将指定的函数引用添加到该表的前三个位置。

// ... (后续代码)
```

**功能归纳：**

这段 C++ 代码是 V8 引擎中 WebAssembly 模块实例化过程的关键部分，它负责完成以下任务：

1. **执行模块的启动函数 (start function)**：如果模块定义了启动函数，则在此阶段执行。
2. **查找和解析导入 (Lookup Imports)**：根据模块的导入声明，在提供的 JavaScript 导入对象中查找相应的值（函数、全局变量、表、内存）。
3. **加载数据段 (Load Data Segments)**：将模块中定义的数据段的内容复制到实例的线性内存中，用于初始化内存数据。
4. **初始化全局变量 (Init Globals)**：设置模块中声明的全局变量的初始值。
5. **处理导出 (Process Exports)**：创建 JavaScript 对象，并将模块的导出项（函数、表、内存、全局变量）添加到该对象中，使其可以从 JavaScript 中访问。
6. **设置表的初始值 (Set Table Initial Values)**：如果模块的表有初始值表达式，则计算并设置表中的初始元素。
7. **加载表段 (Load Table Segments)**：将模块中定义的表段的内容添加到相应的表中，用于初始化表元素。

总而言之，这段代码在 WebAssembly 模块实例化过程中起着至关重要的作用，它连接了 WebAssembly 模块的二进制表示和 JavaScript 环境，使得 JavaScript 可以与 WebAssembly 模块进行交互。它处理了模块实例化后期的关键步骤，例如数据和表的初始化以及导出项的暴露。

Prompt: 
```
这是目录为v8/src/wasm/module-instantiate.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
has_exception());
  TRACE("Successfully built instance for module %p\n",
        module_object_->native_module());
  wasm_module_instantiated.success = true;
  if (timer.IsStarted()) {
    base::TimeDelta instantiation_time = timer.Elapsed();
    wasm_module_instantiated.wall_clock_duration_in_us =
        instantiation_time.InMicroseconds();
    SELECT_WASM_COUNTER(isolate_->counters(), module_->origin, wasm_instantiate,
                        module_time)
        ->AddTimedSample(instantiation_time);
    isolate_->metrics_recorder()->DelayMainThreadEvent(wasm_module_instantiated,
                                                       context_id_);
  }

#if V8_ENABLE_DRUMBRAKE
  // Skip this event because not (yet) supported by Chromium.

  // v8::metrics::WasmInterpreterJitStatus jit_status;
  // jit_status.jitless = v8_flags.wasm_jitless;
  // isolate_->metrics_recorder()->DelayMainThreadEvent(jit_status,
  // context_id_);
#endif  // V8_ENABLE_DRUMBRAKE

  return instance_object;
}

bool InstanceBuilder::ExecuteStartFunction() {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.wasm.detailed"),
               "wasm.ExecuteStartFunction");
  if (start_function_.is_null()) return true;  // No start function.

  HandleScope scope(isolate_);
  // In case the start function calls out to Blink, we have to make sure that
  // the correct "entered context" is available. This is the equivalent of
  // v8::Context::Enter() and must happen in addition to the function call
  // sequence doing the compiled version of "isolate->set_context(...)".
  HandleScopeImplementer* hsi = isolate_->handle_scope_implementer();
  hsi->EnterContext(start_function_->native_context());

  // Call the JS function.
  Handle<Object> undefined = isolate_->factory()->undefined_value();
  MaybeHandle<Object> retval =
      Execution::Call(isolate_, start_function_, undefined, 0, nullptr);
  hsi->LeaveContext();
  // {start_function_} has to be called only once.
  start_function_ = {};

  if (retval.is_null()) {
    DCHECK(isolate_->has_exception());
    return false;
  }
  return true;
}

// Look up an import value in the {ffi_} object.
MaybeHandle<Object> InstanceBuilder::LookupImport(uint32_t index,
                                                  Handle<String> module_name,
                                                  Handle<String> import_name) {
  // The caller checked that the ffi object is present; and we checked in
  // the JS-API layer that the ffi object, if present, is a JSObject.
  DCHECK(!ffi_.is_null());
  // Look up the module first.
  Handle<Object> module;
  Handle<JSReceiver> module_recv;
  if (!Object::GetPropertyOrElement(isolate_, ffi_.ToHandleChecked(),
                                    module_name)
           .ToHandle(&module) ||
      !TryCast<JSReceiver>(module, &module_recv)) {
    const char* error = module.is_null()
                            ? "module not found"
                            : "module is not an object or function";
    thrower_->TypeError("%s: %s", ImportName(index, module_name).c_str(),
                        error);
    return {};
  }

  MaybeHandle<Object> value =
      Object::GetPropertyOrElement(isolate_, module_recv, import_name);
  if (value.is_null()) {
    thrower_->LinkError("%s: import not found", ImportName(index).c_str());
    return {};
  }

  return value;
}

namespace {
bool HasDefaultToNumberBehaviour(Isolate* isolate,
                                 Handle<JSFunction> function) {
  // Disallow providing a [Symbol.toPrimitive] member.
  LookupIterator to_primitive_it{isolate, function,
                                 isolate->factory()->to_primitive_symbol()};
  if (to_primitive_it.state() != LookupIterator::NOT_FOUND) return false;

  // The {valueOf} member must be the default "ObjectPrototypeValueOf".
  LookupIterator value_of_it{isolate, function,
                             isolate->factory()->valueOf_string()};
  if (value_of_it.state() != LookupIterator::DATA) return false;
  Handle<Object> value_of = value_of_it.GetDataValue();
  if (!IsJSFunction(*value_of)) return false;
  Builtin value_of_builtin_id =
      Cast<JSFunction>(value_of)->code(isolate)->builtin_id();
  if (value_of_builtin_id != Builtin::kObjectPrototypeValueOf) return false;

  // The {toString} member must be the default "FunctionPrototypeToString".
  LookupIterator to_string_it{isolate, function,
                              isolate->factory()->toString_string()};
  if (to_string_it.state() != LookupIterator::DATA) return false;
  Handle<Object> to_string = to_string_it.GetDataValue();
  if (!IsJSFunction(*to_string)) return false;
  Builtin to_string_builtin_id =
      Cast<JSFunction>(to_string)->code(isolate)->builtin_id();
  if (to_string_builtin_id != Builtin::kFunctionPrototypeToString) return false;

  // Just a default function, which will convert to "Nan". Accept this.
  return true;
}

bool MaybeMarkError(ValueOrError value, ErrorThrower* thrower) {
  if (is_error(value)) {
    thrower->RuntimeError("%s",
                          MessageFormatter::TemplateString(to_error(value)));
    return true;
  }
  return false;
}
}  // namespace

// Look up an import value in the {ffi_} object specifically for linking an
// asm.js module. This only performs non-observable lookups, which allows
// falling back to JavaScript proper (and hence re-executing all lookups) if
// module instantiation fails.
MaybeHandle<Object> InstanceBuilder::LookupImportAsm(
    uint32_t index, Handle<String> import_name) {
  // The caller checked that the ffi object is present.
  DCHECK(!ffi_.is_null());

  // Perform lookup of the given {import_name} without causing any observable
  // side-effect. We only accept accesses that resolve to data properties,
  // which is indicated by the asm.js spec in section 7 ("Linking") as well.
  PropertyKey key(isolate_, Cast<Name>(import_name));
  LookupIterator it(isolate_, ffi_.ToHandleChecked(), key);
  switch (it.state()) {
    case LookupIterator::ACCESS_CHECK:
    case LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND:
    case LookupIterator::INTERCEPTOR:
    case LookupIterator::JSPROXY:
    case LookupIterator::WASM_OBJECT:
    case LookupIterator::ACCESSOR:
    case LookupIterator::TRANSITION:
      thrower_->LinkError("%s: not a data property",
                          ImportName(index, import_name).c_str());
      return {};
    case LookupIterator::NOT_FOUND:
      // Accepting missing properties as undefined does not cause any
      // observable difference from JavaScript semantics, we are lenient.
      return isolate_->factory()->undefined_value();
    case LookupIterator::DATA: {
      Handle<Object> value = it.GetDataValue();
      // For legacy reasons, we accept functions for imported globals (see
      // {ProcessImportedGlobal}), but only if we can easily determine that
      // their Number-conversion is side effect free and returns NaN (which is
      // the case as long as "valueOf" (or others) are not overwritten).
      if (IsJSFunction(*value) &&
          module_->import_table[index].kind == kExternalGlobal &&
          !HasDefaultToNumberBehaviour(isolate_, Cast<JSFunction>(value))) {
        thrower_->LinkError("%s: function has special ToNumber behaviour",
                            ImportName(index, import_name).c_str());
        return {};
      }
      return value;
    }
  }
}

// Load data segments into the memory.
// TODO(14616): Consider what to do with shared memories.
void InstanceBuilder::LoadDataSegments(
    Handle<WasmTrustedInstanceData> trusted_instance_data,
    Handle<WasmTrustedInstanceData> shared_trusted_instance_data) {
  base::Vector<const uint8_t> wire_bytes =
      module_object_->native_module()->wire_bytes();
  for (const WasmDataSegment& segment : module_->data_segments) {
    uint32_t size = segment.source.length();

    // Passive segments are not copied during instantiation.
    if (!segment.active) continue;

    const WasmMemory& dst_memory = module_->memories[segment.memory_index];
    size_t dest_offset;
    ValueOrError result = EvaluateConstantExpression(
        &init_expr_zone_, segment.dest_addr,
        dst_memory.is_memory64() ? kWasmI64 : kWasmI32, module_, isolate_,
        trusted_instance_data, shared_trusted_instance_data);
    if (MaybeMarkError(result, thrower_)) return;
    if (dst_memory.is_memory64()) {
      uint64_t dest_offset_64 = to_value(result).to_u64();

      // Clamp to {std::numeric_limits<size_t>::max()}, which is always an
      // invalid offset, so we always fail the bounds check below.
      DCHECK_GT(std::numeric_limits<size_t>::max(), dst_memory.max_memory_size);
      dest_offset = static_cast<size_t>(std::min(
          dest_offset_64, uint64_t{std::numeric_limits<size_t>::max()}));
    } else {
      dest_offset = to_value(result).to_u32();
    }

    size_t memory_size =
        trusted_instance_data->memory_size(segment.memory_index);
    if (!base::IsInBounds<size_t>(dest_offset, size, memory_size)) {
      size_t segment_index = &segment - module_->data_segments.data();
      thrower_->RuntimeError(
          "data segment %zu is out of bounds (offset %zu, "
          "length %u, memory size %zu)",
          segment_index, dest_offset, size, memory_size);
      return;
    }

    uint8_t* memory_base =
        trusted_instance_data->memory_base(segment.memory_index);
    std::memcpy(memory_base + dest_offset,
                wire_bytes.begin() + segment.source.offset(), size);
  }
}

void InstanceBuilder::WriteGlobalValue(const WasmGlobal& global,
                                       const WasmValue& value) {
  TRACE("init [globals_start=%p + %u] = %s, type = %s\n",
        global.type.is_reference()
            ? reinterpret_cast<uint8_t*>(tagged_globals_->address())
            : raw_buffer_ptr(untagged_globals_, 0),
        global.offset, value.to_string().c_str(), global.type.name().c_str());
  DCHECK(
      global.mutability
          ? EquivalentTypes(value.type(), global.type, value.module(), module_)
          : IsSubtypeOf(value.type(), global.type, value.module(), module_));
  if (global.type.is_numeric()) {
    value.CopyTo(GetRawUntaggedGlobalPtr<uint8_t>(global));
  } else {
    tagged_globals_->set(global.offset, *value.to_ref());
  }
}

// Returns the name, Builtin ID, and "length" (in the JSFunction sense, i.e.
// number of parameters) for the function representing the given import.
std::tuple<const char*, Builtin, int> NameBuiltinLength(WellKnownImport wki) {
#define CASE(CamelName, name, length)       \
  case WellKnownImport::kString##CamelName: \
    return std::make_tuple(name, Builtin::kWebAssemblyString##CamelName, length)
  switch (wki) {
    CASE(Cast, "cast", 1);
    CASE(CharCodeAt, "charCodeAt", 2);
    CASE(CodePointAt, "codePointAt", 2);
    CASE(Compare, "compare", 2);
    CASE(Concat, "concat", 2);
    CASE(Equals, "equals", 2);
    CASE(FromCharCode, "fromCharCode", 1);
    CASE(FromCodePoint, "fromCodePoint", 1);
    CASE(FromUtf8Array, "decodeStringFromUTF8Array", 3);
    CASE(FromWtf16Array, "fromCharCodeArray", 3);
    CASE(IntoUtf8Array, "encodeStringIntoUTF8Array", 3);
    CASE(Length, "length", 1);
    CASE(MeasureUtf8, "measureStringAsUTF8", 1);
    CASE(Substring, "substring", 3);
    CASE(Test, "test", 1);
    CASE(ToUtf8Array, "encodeStringToUTF8Array", 1);
    CASE(ToWtf16Array, "intoCharCodeArray", 3);
    default:
      UNREACHABLE();  // Only call this for compile-time imports.
  }
#undef CASE
}

Handle<JSFunction> CreateFunctionForCompileTimeImport(Isolate* isolate,
                                                      WellKnownImport wki) {
  auto [name, builtin, length] = NameBuiltinLength(wki);
  Factory* factory = isolate->factory();
  Handle<NativeContext> context(isolate->native_context());
  Handle<Map> map = isolate->strict_function_without_prototype_map();
  Handle<String> name_str = factory->InternalizeUtf8String(name);
  Handle<SharedFunctionInfo> info = factory->NewSharedFunctionInfoForBuiltin(
      name_str, builtin, length, kAdapt);
  info->set_native(true);
  info->set_language_mode(LanguageMode::kStrict);
  Handle<JSFunction> fun =
      Factory::JSFunctionBuilder{isolate, info, context}.set_map(map).Build();
  return fun;
}

void InstanceBuilder::SanitizeImports() {
  NativeModule* native_module = module_object_->native_module();
  base::Vector<const uint8_t> wire_bytes = native_module->wire_bytes();
  const WellKnownImportsList& well_known_imports =
      module_->type_feedback.well_known_imports;
  const std::string& magic_string_constants =
      native_module->compile_imports().constants_module();
  const bool has_magic_string_constants =
      native_module->compile_imports().contains(
          CompileTimeImport::kStringConstants);
  for (uint32_t index = 0; index < module_->import_table.size(); ++index) {
    const WasmImport& import = module_->import_table[index];

    if (import.kind == kExternalGlobal && has_magic_string_constants &&
        import.module_name.length() == magic_string_constants.size() &&
        std::equal(magic_string_constants.begin(), magic_string_constants.end(),
                   wire_bytes.begin() + import.module_name.offset())) {
      Handle<String> value = WasmModuleObject::ExtractUtf8StringFromModuleBytes(
          isolate_, wire_bytes, import.field_name, kNoInternalize);
      sanitized_imports_.push_back(value);
      continue;
    }

    if (import.kind == kExternalFunction) {
      WellKnownImport wki = well_known_imports.get(import.index);
      if (IsCompileTimeImport(wki)) {
        Handle<JSFunction> fun =
            CreateFunctionForCompileTimeImport(isolate_, wki);
        sanitized_imports_.push_back(fun);
        continue;
      }
    }

    if (ffi_.is_null()) {
      // No point in continuing if we don't have an imports object.
      thrower_->TypeError(
          "Imports argument must be present and must be an object");
      return;
    }

    Handle<String> module_name =
        WasmModuleObject::ExtractUtf8StringFromModuleBytes(
            isolate_, wire_bytes, import.module_name, kInternalize);

    Handle<String> import_name =
        WasmModuleObject::ExtractUtf8StringFromModuleBytes(
            isolate_, wire_bytes, import.field_name, kInternalize);

    MaybeHandle<Object> result =
        is_asmjs_module(module_)
            ? LookupImportAsm(index, import_name)
            : LookupImport(index, module_name, import_name);
    if (thrower_->error()) {
      return;
    }
    Handle<Object> value = result.ToHandleChecked();
    sanitized_imports_.push_back(value);
  }
}

bool InstanceBuilder::ProcessImportedFunction(
    Handle<WasmTrustedInstanceData> trusted_instance_data, int import_index,
    int func_index, Handle<Object> value, WellKnownImport preknown_import) {
  // Function imports must be callable.
  if (!IsCallable(*value)) {
    if (!IsWasmSuspendingObject(*value)) {
      thrower_->LinkError("%s: function import requires a callable",
                          ImportName(import_index).c_str());
      return false;
    }
    DCHECK(IsCallable(Cast<WasmSuspendingObject>(*value)->callable()));
  }
  // Store any {WasmExternalFunction} callable in the instance before the call
  // is resolved to preserve its identity. This handles exported functions as
  // well as functions constructed via other means (e.g. WebAssembly.Function).
  if (WasmExternalFunction::IsWasmExternalFunction(*value)) {
    trusted_instance_data->func_refs()->set(
        func_index, Cast<WasmExternalFunction>(*value)->func_ref());
  }
  auto js_receiver = Cast<JSReceiver>(value);
  CanonicalTypeIndex sig_index =
      module_->canonical_sig_id(module_->functions[func_index].sig_index);
  const CanonicalSig* expected_sig =
      GetTypeCanonicalizer()->LookupFunctionSignature(sig_index);
  ResolvedWasmImport resolved(trusted_instance_data, func_index, js_receiver,
                              expected_sig, sig_index, preknown_import);
  if (resolved.well_known_status() != WellKnownImport::kGeneric &&
      v8_flags.trace_wasm_inlining) {
    PrintF("[import %d is well-known built-in %s]\n", import_index,
           WellKnownImportName(resolved.well_known_status()));
  }
  well_known_imports_.push_back(resolved.well_known_status());
  ImportCallKind kind = resolved.kind();
  js_receiver = resolved.callable();
  Handle<WasmFunctionData> trusted_function_data =
      resolved.trusted_function_data();
  ImportedFunctionEntry imported_entry(trusted_instance_data, func_index);
  switch (kind) {
    case ImportCallKind::kRuntimeTypeError:
      imported_entry.SetGenericWasmToJs(isolate_, js_receiver,
                                        resolved.suspend(), expected_sig);
      break;
    case ImportCallKind::kLinkError:
      thrower_->LinkError(
          "%s: imported function does not match the expected type",
          ImportName(import_index).c_str());
      return false;
    case ImportCallKind::kWasmToWasm: {
      // The imported function is a Wasm function from another instance.
      auto function_data =
          Cast<WasmExportedFunctionData>(trusted_function_data);
      // The import reference is the trusted instance data itself.
      Tagged<WasmTrustedInstanceData> instance_data =
          function_data->instance_data();
      WasmCodePointer imported_target =
          instance_data->GetCallTarget(function_data->function_index());
      imported_entry.SetWasmToWasm(instance_data, imported_target
#if V8_ENABLE_DRUMBRAKE
                                   ,
                                   function_data->function_index()
#endif  // V8_ENABLE_DRUMBRAKE
      );
      break;
    }
    case ImportCallKind::kWasmToCapi: {
      int expected_arity = static_cast<int>(expected_sig->parameter_count());
      WasmImportWrapperCache* cache = GetWasmImportWrapperCache();
      WasmCodeRefScope code_ref_scope;
      WasmCode* wasm_code =
          cache->MaybeGet(kind, sig_index, expected_arity, kNoSuspend);
      if (wasm_code == nullptr) {
        {
          WasmImportWrapperCache::ModificationScope cache_scope(cache);
          WasmCompilationResult result =
              compiler::CompileWasmCapiCallWrapper(expected_sig);
          WasmImportWrapperCache::CacheKey key(kind, sig_index, expected_arity,
                                               kNoSuspend);
          wasm_code = cache_scope.AddWrapper(
              key, std::move(result), WasmCode::Kind::kWasmToCapiWrapper);
        }
        // To avoid lock order inversion, code printing must happen after the
        // end of the {cache_scope}.
        wasm_code->MaybePrint();
        isolate_->counters()->wasm_generated_code_size()->Increment(
            wasm_code->instructions().length());
        isolate_->counters()->wasm_reloc_size()->Increment(
            wasm_code->reloc_info().length());
      }

      // We re-use the SetCompiledWasmToJs infrastructure because it passes the
      // callable to the wrapper, which we need to get the function data.
      imported_entry.SetCompiledWasmToJs(isolate_, js_receiver, wasm_code,
                                         kNoSuspend, expected_sig);
      break;
    }
    case ImportCallKind::kWasmToJSFastApi: {
      DCHECK(IsJSFunction(*js_receiver) || IsJSBoundFunction(*js_receiver));
      WasmCodeRefScope code_ref_scope;
      // Note: the wrapper we're about to compile is specific to this
      // instantiation, so it cannot be shared. However, its lifetime must
      // be managed by the WasmImportWrapperCache, so that it can be used
      // in WasmDispatchTables whose lifetime might exceed that of this
      // instance's NativeModule.
      // So the {CacheKey} is a dummy, and we don't look for an existing
      // wrapper. Key collisions are not a concern because lifetimes are
      // determined by refcounting.
      WasmCompilationResult result =
          compiler::CompileWasmJSFastCallWrapper(expected_sig, js_receiver);
      WasmCode* wasm_code;
      {
        WasmImportWrapperCache::ModificationScope cache_scope(
            GetWasmImportWrapperCache());
        WasmImportWrapperCache::CacheKey dummy_key(kind, CanonicalTypeIndex{0},
                                                   0, kNoSuspend);
        wasm_code = cache_scope.AddWrapper(dummy_key, std::move(result),
                                           WasmCode::Kind::kWasmToJsWrapper);
      }
      // To avoid lock order inversion, code printing must happen after the
      // end of the {cache_scope}.
      wasm_code->MaybePrint();
      imported_entry.SetCompiledWasmToJs(isolate_, js_receiver, wasm_code,
                                         kNoSuspend, expected_sig);
      break;
    }
    default: {
      // The imported function is a callable.
      if (UseGenericWasmToJSWrapper(kind, expected_sig, resolved.suspend())) {
        DCHECK(kind == ImportCallKind::kJSFunctionArityMatch ||
               kind == ImportCallKind::kJSFunctionArityMismatch);
        imported_entry.SetGenericWasmToJs(isolate_, js_receiver,
                                          resolved.suspend(), expected_sig);
        break;
      }
      if (v8_flags.wasm_jitless) {
        WasmCode* no_code = nullptr;
        imported_entry.SetCompiledWasmToJs(isolate_, js_receiver, no_code,
                                           resolved.suspend(), expected_sig);
        break;
      }
      int expected_arity = static_cast<int>(expected_sig->parameter_count());
      if (kind == ImportCallKind::kJSFunctionArityMismatch) {
        auto function = Cast<JSFunction>(js_receiver);
        Tagged<SharedFunctionInfo> shared = function->shared();
        expected_arity =
            shared->internal_formal_parameter_count_without_receiver();
      }

      WasmImportWrapperCache* cache = GetWasmImportWrapperCache();
      WasmCodeRefScope code_ref_scope;
      WasmCode* wasm_code =
          cache->MaybeGet(kind, sig_index, expected_arity, resolved.suspend());
      if (!wasm_code) {
        // This should be a very rare fallback case. We expect that the
        // generic wrapper will be used (see above).
        bool source_positions =
            is_asmjs_module(trusted_instance_data->module());
        wasm_code = cache->CompileWasmImportCallWrapper(
            isolate_, kind, expected_sig, sig_index, source_positions,
            expected_arity, resolved.suspend());
      }

      DCHECK_NOT_NULL(wasm_code);
      if (wasm_code->kind() == WasmCode::kWasmToJsWrapper) {
        // Wasm to JS wrappers are treated specially in the import table.
        imported_entry.SetCompiledWasmToJs(isolate_, js_receiver, wasm_code,
                                           resolved.suspend(), expected_sig);
      } else {
        // Wasm math intrinsics are compiled as regular Wasm functions.
        DCHECK(kind >= ImportCallKind::kFirstMathIntrinsic &&
               kind <= ImportCallKind::kLastMathIntrinsic);
        imported_entry.SetWasmToWasm(*trusted_instance_data,
                                     wasm_code->code_pointer()
#if V8_ENABLE_DRUMBRAKE
                                         ,
                                     -1
#endif  // V8_ENABLE_DRUMBRAKE
        );
      }
      break;
    }
  }
  return true;
}

bool InstanceBuilder::InitializeImportedIndirectFunctionTable(
    DirectHandle<WasmTrustedInstanceData> trusted_instance_data,
    int table_index, int import_index,
    DirectHandle<WasmTableObject> table_object) {
  int imported_table_size = table_object->current_length();
  // Allocate a new dispatch table.
  WasmTrustedInstanceData::EnsureMinimumDispatchTableSize(
      isolate_, trusted_instance_data, table_index, imported_table_size);
  // Initialize the dispatch table with the (foreign) JS functions
  // that are already in the table.
  for (int i = 0; i < imported_table_size; ++i) {
    bool is_valid;
    bool is_null;
    MaybeHandle<WasmTrustedInstanceData> maybe_target_instance_data;
    int function_index;
    MaybeDirectHandle<WasmJSFunction> maybe_js_function;
    WasmTableObject::GetFunctionTableEntry(
        isolate_, table_object, i, &is_valid, &is_null,
        &maybe_target_instance_data, &function_index, &maybe_js_function);
    if (!is_valid) {
      thrower_->LinkError("table import %d[%d] is not a wasm function",
                          import_index, i);
      return false;
    }
    if (is_null) continue;
    DirectHandle<WasmJSFunction> js_function;
    if (maybe_js_function.ToHandle(&js_function)) {
      WasmTrustedInstanceData::ImportWasmJSFunctionIntoTable(
          isolate_, trusted_instance_data, table_index, i, js_function);
      continue;
    }

    Handle<WasmTrustedInstanceData> target_instance_data =
        maybe_target_instance_data.ToHandleChecked();
    const WasmModule* target_module = target_instance_data->module();
    const WasmFunction& function = target_module->functions[function_index];

    FunctionTargetAndImplicitArg entry(isolate_, target_instance_data,
                                       function_index);
    Handle<Object> implicit_arg = entry.implicit_arg();
    if (v8_flags.wasm_generic_wrapper && IsWasmImportData(*implicit_arg)) {
      auto orig_import_data = Cast<WasmImportData>(implicit_arg);
      Handle<WasmImportData> new_import_data =
          isolate_->factory()->NewWasmImportData(orig_import_data);
      // TODO(42204563): Avoid crashing if the instance object is not available.
      CHECK(trusted_instance_data->has_instance_object());
      WasmImportData::SetCrossInstanceTableIndexAsCallOrigin(
          isolate_, new_import_data,
          direct_handle(trusted_instance_data->instance_object(), isolate_), i);
      implicit_arg = new_import_data;
    }

    CanonicalTypeIndex sig_index =
        target_module->canonical_sig_id(function.sig_index);
    SBXCHECK(FunctionSigMatchesTable(sig_index, trusted_instance_data->module(),
                                     table_index));

    trusted_instance_data->dispatch_table(table_index)
        ->Set(i, *implicit_arg, entry.call_target(), sig_index,
#if V8_ENABLE_DRUMBRAKE
              entry.target_func_index(),
#endif  // V8_ENABLE_DRUMBRAKE
              nullptr, IsAWrapper::kMaybe, WasmDispatchTable::kNewEntry);
  }
  return true;
}

bool InstanceBuilder::ProcessImportedTable(
    DirectHandle<WasmTrustedInstanceData> trusted_instance_data,
    int import_index, int table_index, Handle<Object> value) {
  if (!IsWasmTableObject(*value)) {
    thrower_->LinkError("%s: table import requires a WebAssembly.Table",
                        ImportName(import_index).c_str());
    return false;
  }
  const WasmTable& table = module_->tables[table_index];

  DirectHandle<WasmTableObject> table_object = Cast<WasmTableObject>(value);

  uint32_t imported_table_size =
      static_cast<uint32_t>(table_object->current_length());
  if (imported_table_size < table.initial_size) {
    thrower_->LinkError("table import %d is smaller than initial %u, got %u",
                        import_index, table.initial_size, imported_table_size);
    return false;
  }

  if (table.has_maximum_size) {
    std::optional<uint64_t> max_size = table_object->maximum_length_u64();
    if (!max_size) {
      thrower_->LinkError(
          "table import %d has no maximum length; required: %" PRIu64,
          import_index, table.maximum_size);
      return false;
    }
    if (*max_size > table.maximum_size) {
      thrower_->LinkError("table import %d has a larger maximum size %" PRIx64
                          " than the module's declared maximum %" PRIu64,
                          import_index, *max_size, table.maximum_size);
      return false;
    }
  }

  if (table.address_type != table_object->address_type()) {
    thrower_->LinkError("cannot import %s table as %s",
                        AddressTypeToStr(table_object->address_type()),
                        AddressTypeToStr(table.address_type));
    return false;
  }

  const WasmModule* table_type_module =
      table_object->has_trusted_data()
          ? table_object->trusted_data(isolate_)->module()
          : trusted_instance_data->module();

  if (!EquivalentTypes(table.type, table_object->type(), module_,
                       table_type_module)) {
    thrower_->LinkError("%s: imported table does not match the expected type",
                        ImportName(import_index).c_str());
    return false;
  }

  if (IsSubtypeOf(table.type, kWasmFuncRef, module_) &&
      !InitializeImportedIndirectFunctionTable(
          trusted_instance_data, table_index, import_index, table_object)) {
    return false;
  }

  trusted_instance_data->tables()->set(table_index, *value);
  return true;
}

bool InstanceBuilder::ProcessImportedWasmGlobalObject(
    DirectHandle<WasmTrustedInstanceData> trusted_instance_data,
    int import_index, const WasmGlobal& global,
    DirectHandle<WasmGlobalObject> global_object) {
  if (static_cast<bool>(global_object->is_mutable()) != global.mutability) {
    thrower_->LinkError(
        "%s: imported global does not match the expected mutability",
        ImportName(import_index).c_str());
    return false;
  }

  const WasmModule* global_type_module =
      global_object->has_trusted_data()
          ? global_object->trusted_data(isolate_)->module()
          : trusted_instance_data->module();

  bool valid_type =
      global.mutability
          ? EquivalentTypes(global_object->type(), global.type,
                            global_type_module, trusted_instance_data->module())
          : IsSubtypeOf(global_object->type(), global.type, global_type_module,
                        trusted_instance_data->module());

  if (!valid_type) {
    thrower_->LinkError("%s: imported global does not match the expected type",
                        ImportName(import_index).c_str());
    return false;
  }
  if (global.mutability) {
    DCHECK_LT(global.index, module_->num_imported_mutable_globals);
    Handle<Object> buffer;
    if (global.type.is_reference()) {
      static_assert(sizeof(global_object->offset()) <= sizeof(Address),
                    "The offset into the globals buffer does not fit into "
                    "the imported_mutable_globals array");
      buffer = handle(global_object->tagged_buffer(), isolate_);
      // For externref globals we use a relative offset, not an absolute
      // address.
      trusted_instance_data->imported_mutable_globals()->set(
          global.index, global_object->offset());
    } else {
      buffer = handle(global_object->untagged_buffer(), isolate_);
      // It is safe in this case to store the raw pointer to the buffer
      // since the backing store of the JSArrayBuffer will not be
      // relocated.
      Address address = reinterpret_cast<Address>(
          raw_buffer_ptr(Cast<JSArrayBuffer>(buffer), global_object->offset()));
      trusted_instance_data->imported_mutable_globals()->set_sandboxed_pointer(
          global.index, address);
    }
    trusted_instance_data->imported_mutable_globals_buffers()->set(global.index,
                                                                   *buffer);
    return true;
  }

  WasmValue value;
  switch (global_object->type().kind()) {
    case kI32:
      value = WasmValue(global_object->GetI32());
      break;
    case kI64:
      value = WasmValue(global_object->GetI64());
      break;
    case kF32:
      value = WasmValue(global_object->GetF32());
      break;
    case kF64:
      value = WasmValue(global_object->GetF64());
      break;
    case kS128:
      value = WasmValue(global_object->GetS128RawBytes(), kWasmS128);
      break;
    case kRef:
    case kRefNull:
      value = WasmValue(global_object->GetRef(), global.type, module_);
      break;
    case kVoid:
    case kTop:
    case kBottom:
    case kRtt:
    case kI8:
    case kI16:
    case kF16:
      UNREACHABLE();
  }

  WriteGlobalValue(global, value);
  return true;
}

bool InstanceBuilder::ProcessImportedGlobal(
    DirectHandle<WasmTrustedInstanceData> trusted_instance_data,
    int import_index, int global_index, Handle<Object> value) {
  // Immutable global imports are converted to numbers and written into
  // the {untagged_globals_} array buffer.
  //
  // Mutable global imports instead have their backing array buffers
  // referenced by this instance, and store the address of the imported
  // global in the {imported_mutable_globals_} array.
  const WasmGlobal& global = module_->globals[global_index];

  // SIMD proposal allows modules to define an imported v128 global, and only
  // supports importing a WebAssembly.Global object for this global, but also
  // defines constructing a WebAssembly.Global of v128 to be a TypeError.
  // We *should* never hit this case in the JS API, but the module should should
  // be allowed to declare such a global (no validation error).
  if (global.type == kWasmS128 && !IsWasmGlobalObject(*value)) {
    thrower_->LinkError(
        "%s: global import of type v128 must be a WebAssembly.Global",
        ImportName(import_index).c_str());
    return false;
  }

  if (is_asmjs_module(module_)) {
    // Accepting {JSFunction} on top of just primitive values here is a
    // workaround to support legacy asm.js code with broken binding. Note
    // that using {NaN} (or Smi::zero()) here is what using the observable
    // conversion via {ToPrimitive} would produce as well. {LookupImportAsm}
    // checked via {HasDefaultToNumberBehaviour} that "valueOf" or friends have
    // not been patched.
    if (IsJSFunction(*value)) value = isolate_->factory()->nan_value();
    if (IsPrimitive(*value)) {
      MaybeHandle<Object> converted = global.type == kWasmI32
                                          ? Object::ToInt32(isolate_, value)
                                          : Object::ToNumber(isolate_, value);
      if (!converted.ToHandle(&value)) {
        // Conversion is known to fail for Symbols and BigInts.
        thrower_->LinkError("%s: global import must be a number",
                            ImportName(import_index).c_str());
        return false;
      }
    }
  }

  if (IsWasmGlobalObject(*value)) {
    auto global_object = Cast<WasmGlobalObject>(value);
    return ProcessImportedWasmGlobalObject(trusted_instance_data, import_index,
                                           global, global_object);
  }

  if (global.mutability) {
    thrower_->LinkError(
        "%s: imported mutable global must be a WebAssembly.Global object",
        ImportName(import_index).c_str());
    return false;
  }

  if (global.type.is_reference()) {
    const char* error_message;
    Handle<Object> wasm_value;
    if (!wasm::JSToWasmObject(isolate_, module_, value, global.type,
                              &error_message)
             .ToHandle(&wasm_value)) {
      thrower_->LinkError("%s: %s", ImportName(import_index).c_str(),
                          error_message);
      return false;
    }
    WriteGlobalValue(global, WasmValue(wasm_value, global.type, module_));
    return true;
  }

  if (IsNumber(*value) && global.type != kWasmI64) {
    double number_value = Object::NumberValue(*value);
    // The Wasm-BigInt proposal currently says that i64 globals may
    // only be initialized with BigInts. See:
    // https://github.com/WebAssembly/JS-BigInt-integration/issues/12
    WasmValue wasm_value =
        global.type == kWasmI32   ? WasmValue(DoubleToInt32(number_value))
        : global.type == kWasmF32 ? WasmValue(DoubleToFloat32(number_value))
                                  : WasmValue(number_value);
    WriteGlobalValue(global, wasm_value);
    return true;
  }

  if (global.type == kWasmI64 && IsBigInt(*value)) {
    WriteGlobalValue(global, WasmValue(Cast<BigInt>(*value)->AsInt64()));
    return true;
  }

  thrower_->LinkError(
      "%s: global import must be a number, valid Wasm reference, or "
      "WebAssembly.Global object",
      ImportName(import_index).c_str());
  return false;
}

// Process the imports, including functions, tables, globals, and memory, in
// order, loading them from the {ffi_} object. Returns the number of imported
// functions.
int InstanceBuilder::ProcessImports(
    Handle<WasmTrustedInstanceData> trusted_instance_data,
    Handle<WasmTrustedInstanceData> shared_trusted_instance_data) {
  int num_imported_functions = 0;
  int num_imported_tables = 0;

  DCHECK_EQ(module_->import_table.size(), sanitized_imports_.size());

  const WellKnownImportsList& preknown_imports =
      module_->type_feedback.well_known_imports;
  int num_imports = static_cast<int>(module_->import_table.size());
  for (int index = 0; index < num_imports; ++index) {
    const WasmImport& import = module_->import_table[index];

    Handle<Object> value = sanitized_imports_[index];

    switch (import.kind) {
      case kExternalFunction: {
        uint32_t func_index = import.index;
        DCHECK_EQ(num_imported_functions, func_index);
        ModuleTypeIndex sig_index = module_->functions[func_index].sig_index;
        bool function_is_shared = module_->type(sig_index).is_shared;
        if (!ProcessImportedFunction(
                function_is_shared ? shared_trusted_instance_data
                                   : trusted_instance_data,
                index, func_index, value, preknown_imports.get(func_index))) {
          return -1;
        }
        num_imported_functions++;
        break;
      }
      case kExternalTable: {
        uint32_t table_index = import.index;
        DCHECK_EQ(table_index, num_imported_tables);
        bool table_is_shared = module_->tables[table_index].shared;
        if (!ProcessImportedTable(table_is_shared ? shared_trusted_instance_data
                                                  : trusted_instance_data,
                                  index, table_index, value)) {
          return -1;
        }
        num_imported_tables++;
        USE(num_imported_tables);
        break;
      }
      case kExternalMemory:
        // Imported memories are already handled earlier via
        // {ProcessImportedMemories}.
        break;
      case kExternalGlobal: {
        bool global_is_shared = module_->globals[import.index].shared;
        if (!ProcessImportedGlobal(global_is_shared
                                       ? shared_trusted_instance_data
                                       : trusted_instance_data,
                                   index, import.index, value)) {
          return -1;
        }
        break;
      }
      case kExternalTag: {
        // TODO(14616): Implement shared tags.
        if (!IsWasmTagObject(*value)) {
          thrower_->LinkError("%s: tag import requires a WebAssembly.Tag",
                              ImportName(index).c_str());
          return -1;
        }
        Handle<WasmTagObject> imported_tag = Cast<WasmTagObject>(value);
        if (!imported_tag->MatchesSignature(module_->canonical_sig_id(
                module_->tags[import.index].sig_index))) {
          thrower_->LinkError(
              "%s: imported tag does not match the expected type",
              ImportName(index).c_str());
          return -1;
        }
        Tagged<Object> tag = imported_tag->tag();
        DCHECK(IsUndefined(
            trusted_instance_data->tags_table()->get(import.index)));
        trusted_instance_data->tags_table()->set(import.index, tag);
        tags_wrappers_[import.index] = imported_tag;
        break;
      }
      default:
        UNREACHABLE();
    }
  }
  if (num_imported_functions > 0) {
    module_object_->native_module()->UpdateWellKnownImports(
        base::VectorOf(well_known_imports_));
  }
  return num_imported_functions;
}

bool InstanceBuilder::ProcessImportedMemories(
    DirectHandle<FixedArray> imported_memory_objects) {
  DCHECK_EQ(module_->import_table.size(), sanitized_imports_.size());

  int num_imports = static_cast<int>(module_->import_table.size());
  for (int import_index = 0; import_index < num_imports; ++import_index) {
    const WasmImport& import = module_->import_table[import_index];

    if (import.kind != kExternalMemory) continue;

    DirectHandle<Object> value = sanitized_imports_[import_index];

    if (!IsWasmMemoryObject(*value)) {
      thrower_->LinkError(
          "%s: memory import must be a WebAssembly.Memory object",
          ImportName(import_index).c_str());
      return false;
    }
    uint32_t memory_index = import.index;
    auto memory_object = Cast<WasmMemoryObject>(value);

    DirectHandle<JSArrayBuffer> buffer{memory_object->array_buffer(), isolate_};
    uint32_t imported_cur_pages =
        static_cast<uint32_t>(buffer->byte_length() / kWasmPageSize);
    const WasmMemory* memory = &module_->memories[memory_index];
    if (memory->address_type != memory_object->address_type()) {
      thrower_->LinkError("cannot import %s memory as %s",
                          AddressTypeToStr(memory_object->address_type()),
                          AddressTypeToStr(memory->address_type));
      return false;
    }
    if (imported_cur_pages < memory->initial_pages) {
      thrower_->LinkError(
          "%s: memory import has %u pages which is smaller than the declared "
          "initial of %u",
          ImportName(import_index).c_str(), imported_cur_pages,
          memory->initial_pages);
      return false;
    }
    int32_t imported_maximum_pages = memory_object->maximum_pages();
    if (memory->has_maximum_pages) {
      if (imported_maximum_pages < 0) {
        thrower_->LinkError(
            "%s: memory import has no maximum limit, expected at most %u",
            ImportName(import_index).c_str(), imported_maximum_pages);
        return false;
      }
      if (static_cast<uint64_t>(imported_maximum_pages) >
          memory->maximum_pages) {
        thrower_->LinkError(
            "%s: memory import has a larger maximum size %u than the "
            "module's declared maximum %" PRIu64,
            ImportName(import_index).c_str(), imported_maximum_pages,
            memory->maximum_pages);
        return false;
      }
    }
    if (memory->is_shared != buffer->is_shared()) {
      thrower_->LinkError(
          "%s: mismatch in shared state of memory, declared = %d, imported = "
          "%d",
          ImportName(import_index).c_str(), memory->is_shared,
          buffer->is_shared());
      return false;
    }

    DCHECK_EQ(ReadOnlyRoots{isolate_}.undefined_value(),
              imported_memory_objects->get(memory_index));
    imported_memory_objects->set(memory_index, *memory_object);
  }
  return true;
}

template <typename T>
T* InstanceBuilder::GetRawUntaggedGlobalPtr(const WasmGlobal& global) {
  return reinterpret_cast<T*>(raw_buffer_ptr(
      global.shared ? shared_untagged_globals_ : untagged_globals_,
      global.offset));
}

// Process initialization of globals.
void InstanceBuilder::InitGlobals(
    Handle<WasmTrustedInstanceData> trusted_instance_data,
    Handle<WasmTrustedInstanceData> shared_trusted_instance_data) {
  for (const WasmGlobal& global : module_->globals) {
    if (global.mutability && global.imported) continue;
    // Happens with imported globals.
    if (!global.init.is_set()) continue;

    ValueOrError result = EvaluateConstantExpression(
        &init_expr_zone_, global.init, global.type, module_, isolate_,
        trusted_instance_data, shared_trusted_instance_data);
    if (MaybeMarkError(result, thrower_)) return;

    if (global.type.is_reference()) {
      (global.shared ? shared_tagged_globals_ : tagged_globals_)
          ->set(global.offset, *to_value(result).to_ref());
    } else {
      to_value(result).CopyTo(GetRawUntaggedGlobalPtr<uint8_t>(global));
    }
  }
}

// Allocate memory for a module instance as a new JSArrayBuffer.
MaybeHandle<WasmMemoryObject> InstanceBuilder::AllocateMemory(
    uint32_t memory_index) {
  const WasmMemory& memory = module_->memories[memory_index];
  int initial_pages = static_cast<int>(memory.initial_pages);
  int maximum_pages = memory.has_maximum_pages
                          ? static_cast<int>(memory.maximum_pages)
                          : WasmMemoryObject::kNoMaximum;
  auto shared = memory.is_shared ? SharedFlag::kShared : SharedFlag::kNotShared;

  MaybeHandle<WasmMemoryObject> maybe_memory_object = WasmMemoryObject::New(
      isolate_, initial_pages, maximum_pages, shared, memory.address_type);
  if (maybe_memory_object.is_null()) {
    thrower_->RangeError(
        "Out of memory: Cannot allocate Wasm memory for new instance");
    return {};
  }
  return maybe_memory_object;
}

// Process the exports, creating wrappers for functions, tables, memories,
// globals, and exceptions.
void InstanceBuilder::ProcessExports(
    Handle<WasmTrustedInstanceData> trusted_instance_data,
    Handle<WasmTrustedInstanceData> shared_trusted_instance_data) {
  std::unordered_map<int, IndirectHandle<Object>> imported_globals;

  // If an imported WebAssembly function or global gets exported, the export
  // has to be identical to to import. Therefore we cache all imported
  // WebAssembly functions in the instance, and all imported globals in a map
  // here.
  for (size_t index = 0, end = module_->import_table.size(); index < end;
       ++index) {
    const WasmImport& import = module_->import_table[index];
    if (import.kind == kExternalFunction) {
      DirectHandle<Object> value = sanitized_imports_[index];
      if (WasmExternalFunction::IsWasmExternalFunction(*value)) {
        trusted_instance_data->func_refs()->set(
            import.index, Cast<WasmExternalFunction>(*value)->func_ref());
      }
    } else if (import.kind == kExternalGlobal) {
      Handle<Object> value = sanitized_imports_[index];
      if (IsWasmGlobalObject(*value)) {
        imported_globals[import.index] = value;
      }
    }
  }

  Handle<WasmInstanceObject> instance_object{
      trusted_instance_data->instance_object(), isolate_};
  Handle<JSObject> exports_object =
      handle(instance_object->exports_object(), isolate_);
  MaybeHandle<String> single_function_name;
  bool is_asm_js = is_asmjs_module(module_);
  if (is_asm_js) {
    Handle<JSFunction> object_function = Handle<JSFunction>(
        isolate_->native_context()->object_function(), isolate_);
    exports_object = isolate_->factory()->NewJSObject(object_function);
    single_function_name =
        isolate_->factory()->InternalizeUtf8String(AsmJs::kSingleFunctionName);
    instance_object->set_exports_object(*exports_object);
  }

  // Switch the exports object to dictionary mode and allocate enough storage
  // for the expected number of exports.
  DCHECK(exports_object->HasFastProperties());
  JSObject::NormalizeProperties(
      isolate_, exports_object, KEEP_INOBJECT_PROPERTIES,
      static_cast<int>(module_->export_table.size()), "WasmExportsObject");

  PropertyDescriptor desc;
  desc.set_writable(is_asm_js);
  desc.set_enumerable(true);
  desc.set_configurable(is_asm_js);

  const PropertyDetails details{PropertyKind::kData, desc.ToAttributes(),
                                PropertyConstness::kMutable};

  // Process each export in the export table.
  for (const WasmExport& exp : module_->export_table) {
    Handle<String> name = WasmModuleObject::ExtractUtf8StringFromModuleBytes(
        isolate_, module_object_, exp.name, kInternalize);
    Handle<JSAny> value;
    switch (exp.kind) {
      case kExternalFunction: {
        // Wrap and export the code as a JSFunction.
        bool shared = module_->function_is_shared(exp.index);
        DirectHandle<WasmFuncRef> func_ref =
            WasmTrustedInstanceData::GetOrCreateFuncRef(
                isolate_,
                shared ? shared_trusted_instance_data : trusted_instance_data,
                exp.index);
        DirectHandle<WasmInternalFunction> internal_function{
            func_ref->internal(isolate_), isolate_};
        Handle<JSFunction> wasm_external_function =
            WasmInternalFunction::GetOrCreateExternal(internal_function);
        value = wasm_external_function;

        if (is_asm_js &&
            String::Equals(isolate_, name,
                           single_function_name.ToHandleChecked())) {
          desc.set_value(value);
          CHECK(JSReceiver::DefineOwnProperty(isolate_, instance_object, name,
                                              &desc, Just(kThrowOnError))
                    .FromMaybe(false));
          continue;
        }
        break;
      }
      case kExternalTable: {
        bool shared = module_->tables[exp.index].shared;
        DirectHandle<WasmTrustedInstanceData> data =
            shared ? shared_trusted_instance_data : trusted_instance_data;
        value = handle(Cast<JSAny>(data->tables()->get(exp.index)), isolate_);
        break;
      }
      case kExternalMemory: {
        // Export the memory as a WebAssembly.Memory object. A WasmMemoryObject
        // should already be available if the module has memory, since we always
        // create or import it when building an WasmInstanceObject.
        value =
            handle(trusted_instance_data->memory_object(exp.index), isolate_);
        break;
      }
      case kExternalGlobal: {
        const WasmGlobal& global = module_->globals[exp.index];
        DirectHandle<WasmTrustedInstanceData>
            maybe_shared_trusted_instance_data =
                global.shared ? shared_trusted_instance_data
                              : trusted_instance_data;
        if (global.imported) {
          auto cached_global = imported_globals.find(exp.index);
          if (cached_global != imported_globals.end()) {
            value = Cast<JSAny>(cached_global->second);
            break;
          }
        }
        Handle<JSArrayBuffer> untagged_buffer;
        Handle<FixedArray> tagged_buffer;
        uint32_t offset;

        if (global.mutability && global.imported) {
          DirectHandle<FixedArray> buffers_array(
              maybe_shared_trusted_instance_data
                  ->imported_mutable_globals_buffers(),
              isolate_);
          if (global.type.is_reference()) {
            tagged_buffer = handle(
                Cast<FixedArray>(buffers_array->get(global.index)), isolate_);
            // For externref globals we store the relative offset in the
            // imported_mutable_globals array instead of an absolute address.
            offset = static_cast<uint32_t>(
                maybe_shared_trusted_instance_data->imported_mutable_globals()
                    ->get(global.index));
          } else {
            untagged_buffer =
                handle(Cast<JSArrayBuffer>(buffers_array->get(global.index)),
                       isolate_);
            Address global_addr =
                maybe_shared_trusted_instance_data->imported_mutable_globals()
                    ->get_sandboxed_pointer(global.index);

            size_t buffer_size = untagged_buffer->byte_length();
            Address backing_store =
                reinterpret_cast<Address>(untagged_buffer->backing_store());
            CHECK(global_addr >= backing_store &&
                  global_addr < backing_store + buffer_size);
            offset = static_cast<uint32_t>(global_addr - backing_store);
          }
        } else {
          if (global.type.is_reference()) {
            tagged_buffer = handle(
                maybe_shared_trusted_instance_data->tagged_globals_buffer(),
                isolate_);
          } else {
            untagged_buffer = handle(
                maybe_shared_trusted_instance_data->untagged_globals_buffer(),
                isolate_);
          }
          offset = global.offset;
        }

        // Since the global's array untagged_buffer is always provided,
        // allocation should never fail.
        Handle<WasmGlobalObject> global_obj =
            WasmGlobalObject::New(isolate_,
                                  global.shared ? shared_trusted_instance_data
                                                : trusted_instance_data,
                                  untagged_buffer, tagged_buffer, global.type,
                                  offset, global.mutability)
                .ToHandleChecked();
        value = global_obj;
        break;
      }
      case kExternalTag: {
        const WasmTag& tag = module_->tags[exp.index];
        Handle<WasmTagObject> wrapper = tags_wrappers_[exp.index];
        if (wrapper.is_null()) {
          DirectHandle<HeapObject> tag_object(
              Cast<HeapObject>(
                  trusted_instance_data->tags_table()->get(exp.index)),
              isolate_);
          CanonicalTypeIndex sig_index =
              module_->canonical_sig_id(tag.sig_index);
          // TODO(42204563): Support shared tags.
          wrapper = WasmTagObject::New(isolate_, tag.sig, sig_index, tag_object,
                                       trusted_instance_data);
          tags_wrappers_[exp.index] = wrapper;
        }
        value = wrapper;
        break;
      }
      default:
        UNREACHABLE();
    }

    uint32_t index;
    if (V8_UNLIKELY(name->AsArrayIndex(&index))) {
      // Add a data element.
      JSObject::AddDataElement(exports_object, index, value,
                               details.attributes());
    } else {
      // Add a property to the dictionary.
      JSObject::SetNormalizedProperty(exports_object, name, value, details);
    }
  }

  // Switch back to fast properties if possible.
  JSObject::MigrateSlowToFast(exports_object, 0, "WasmExportsObjectFinished");

  if (module_->origin == kWasmOrigin) {
    CHECK(JSReceiver::SetIntegrityLevel(isolate_, exports_object, FROZEN,
                                        kDontThrow)
              .FromMaybe(false));
  }
}

namespace {
V8_INLINE void SetFunctionTablePlaceholder(
    Isolate* isolate,
    DirectHandle<WasmTrustedInstanceData> trusted_instance_data,
    DirectHandle<WasmTableObject> table_object, uint32_t entry_index,
    uint32_t func_index) {
  const WasmModule* module = trusted_instance_data->module();
  const WasmFunction* function = &module->functions[func_index];
  Tagged<WasmFuncRef> func_ref;
  if (trusted_instance_data->try_get_func_ref(func_index, &func_ref)) {
    table_object->entries()->set(entry_index, *func_ref);
  } else {
    WasmTableObject::SetFunctionTablePlaceholder(
        isolate, table_object, entry_index, trusted_instance_data, func_index);
  }
  WasmTableObject::UpdateDispatchTables(isolate, table_object, entry_index,
                                        function, trusted_instance_data
#if V8_ENABLE_DRUMBRAKE
                                        ,
                                        func_index
#endif  // V8_ENABLE_DRUMBRAKE
  );
}

V8_INLINE void SetFunctionTableNullEntry(
    Isolate* isolate, DirectHandle<WasmTableObject> table_object,
    uint32_t entry_index) {
  table_object->entries()->set(entry_index, ReadOnlyRoots{isolate}.wasm_null());
  table_object->ClearDispatchTables(entry_index);
}
}  // namespace

void InstanceBuilder::SetTableInitialValues(
    Handle<WasmTrustedInstanceData> trusted_instance_data,
    Handle<WasmTrustedInstanceData> shared_trusted_instance_data) {
  for (int table_index = 0;
       table_index < static_cast<int>(module_->tables.size()); ++table_index) {
    const WasmTable& table = module_->tables[table_index];
    Handle<WasmTrustedInstanceData> maybe_shared_trusted_instance_data =
        table.shared ? shared_trusted_instance_data : trusted_instance_data;
    if (table.initial_value.is_set()) {
      auto table_object = handle(
          Cast<WasmTableObject>(
              maybe_shared_trusted_instance_data->tables()->get(table_index)),
          isolate_);
      bool is_function_table = IsSubtypeOf(table.type, kWasmFuncRef, module_);
      if (is_function_table &&
          table.initial_value.kind() == ConstantExpression::kRefFunc) {
        for (uint32_t entry_index = 0; entry_index < table.initial_size;
             entry_index++) {
          SetFunctionTablePlaceholder(
              isolate_, maybe_shared_trusted_instance_data, table_object,
              entry_index, table.initial_value.index());
        }
      } else if (is_function_table &&
                 table.initial_value.kind() == ConstantExpression::kRefNull) {
        for (uint32_t entry_index = 0; entry_index < table.initial_size;
             entry_index++) {
          SetFunctionTableNullEntry(isolate_, table_object, entry_index);
        }
      } else {
        ValueOrError result = EvaluateConstantExpression(
            &init_expr_zone_, table.initial_value, table.type, module_,
            isolate_, maybe_shared_trusted_instance_data,
            shared_trusted_instance_data);
        if (MaybeMarkError(result, thrower_)) return;
        for (uint32_t entry_index = 0; entry_index < table.initial_size;
             entry_index++) {
          WasmTableObject::Set(isolate_, table_object, entry_index,
                               to_value(result).to_ref());
        }
      }
    }
  }
}

namespace {

enum FunctionComputationMode { kLazyFunctionsAndNull, kStrictFunctionsAndNull };

// If {function_mode == kLazyFunctionsAndNull}, may return a function index
// instead of computing a function object, and {WasmValue(-1)} instead of null.
// Assumes the underlying module is verified.
// Resets {zone}, so make sure it contains no useful data.
ValueOrError ConsumeElementSegmentEntry(
    Zone* zone, Isolate* isolate,
    Handle<WasmTrustedInstanceData> trusted_instance_data,
    Handle<WasmTrustedInstanceData> shared_trusted_instance_data,
    const WasmElemSegment& segment, Decoder& decoder,
    FunctionComputationMode function_mode) {
  const WasmModule* module = trusted_instance_data->module();
  if (segment.element_type == WasmElemSegment::kFunctionIndexElements) {
    uint32_t function_index = decoder.consume_u32v();
    return function_mode == kStrictFunctionsAndNull
               ? EvaluateConstantExpression(
                     zone, ConstantExpression::RefFunc(function_index),
                     segment.type, module, isolate, trusted_instance_data,
                     shared_trusted_instance_data)
               : ValueOrError(WasmValue(function_index));
  }

  switch (static_cast<WasmOpcode>(*decoder.pc())) {
    case kExprRefFunc: {
      auto [function_index, length] =
          decoder.read_u32v<Decoder::FullValidationTag>(decoder.pc() + 1,
                                                        "ref.func");
      if (V8_LIKELY(decoder.lookahead(1 + length, kExprEnd))) {
        decoder.consume_bytes(length + 2);
        return function_mode == kStrictFunctionsAndNull
                   ? EvaluateConstantExpression(
                         zone, ConstantExpression::RefFunc(function_index),
                         segment.type, module, isolate, trusted_instance_data,
                         shared_trusted_instance_data)
                   : ValueOrError(WasmValue(function_index));
      }
      break;
    }
    case kExprRefNull: {
      auto [heap_type, length] =
          value_type_reader::read_heap_type<Decoder::FullValidationTag>(
              &decoder, decoder.pc() + 1, WasmEnabledFeatures::All());
      if (V8_LIKELY(decoder.lookahead(1 + length, kExprEnd))) {
        decoder.consume_bytes(length + 2);
        return function_mode == kStrictFunctionsAndNull
                   ? EvaluateConstantExpression(zone,
                                                ConstantExpression::RefNull(
                                                    heap_type.representation()),
                                                segment.type, module, isolate,
                                                trusted_instance_data,
                                                shared_trusted_instance_data)
                   : WasmValue(int32_t{-1});
      }
      break;
    }
    default:
      break;
  }

  auto sig = FixedSizeSignature<ValueType>::Returns(segment.type);
  constexpr bool kIsShared = false;  // TODO(14616): Is this correct?
  FunctionBody body(&sig, decoder.pc_offset(), decoder.pc(), decoder.end(),
                    kIsShared);
  WasmDetectedFeatures detected;
  ValueOrError result;
  {
    // We need a scope for the decoder because its destructor resets some Zone
    // elements, which has to be done before we reset the Zone afterwards.
    // We use FullValidationTag so we do not have to create another template
    // instance of WasmFullDecoder, which would cost us >50Kb binary code
    // size.
    WasmFullDecoder<Decoder::FullValidationTag, ConstantExpressionInterface,
                    kConstantExpression>
        full_decoder(zone, trusted_instance_data->module(),
                     WasmEnabledFeatures::All(), &detected, body,
                     trusted_instance_data->module(), isolate,
                     trusted_instance_data, shared_trusted_instance_data);

    full_decoder.DecodeFunctionBody();

    decoder.consume_bytes(static_cast<int>(full_decoder.pc() - decoder.pc()));

    result = full_decoder.interface().has_error()
                 ? ValueOrError(full_decoder.interface().error())
                 : ValueOrError(full_decoder.interface().computed_value());
  }

  zone->Reset();

  return result;
}

}  // namespace

std::optional<MessageTemplate> InitializeElementSegment(
    Zone* zone, Isolate* isolate,
    Handle<WasmTrustedInstanceData> trusted_instance_data,
    Handle<WasmTrustedInstanceData> shared_trusted_instance_data,
    uint32_t segment_index) {
  bool shared =
      trusted_instance_data->module()->elem_segments[segment_index].shared;
  DirectHandle<WasmTrustedInstanceData> data =
      shared ? shared_trusted_instance_data : trusted_instance_data;
  if (!IsUndefined(data->element_segments()->get(segment_index))) return {};

  const NativeModule* native_module = data->native_module();
  const WasmModule* module = native_module->module();
  const WasmElemSegment& elem_segment = module->elem_segments[segment_index];

  base::Vector<const uint8_t> module_bytes = native_module->wire_bytes();

  Decoder decoder(module_bytes);
  decoder.consume_bytes(elem_segment.elements_wire_bytes_offset);

  DirectHandle<FixedArray> result =
      isolate->factory()->NewFixedArray(elem_segment.element_count);

  for (size_t i = 0; i < elem_segment.element_count; ++i) {
    ValueOrError value = ConsumeElementSegmentEntry(
        zone, isolate, trusted_instance_data, shared_trusted_instance_data,
        elem_segment, decoder, kStrictFunctionsAndNull);
    if (is_error(value)) return {to_error(value)};
    result->set(static_cast<int>(i), *to_value(value).to_ref());
  }

  data->element_segments()->set(segment_index, *result);

  return {};
}

void InstanceBuilder::LoadTableSegments(
    Handle<WasmTrustedInstanceData> trusted_instance_data,
    Handle<WasmTrustedInstanceData> shared_trusted_instance_data) {
  for (uint32_t segment_index = 0;
       segment_index < module_->elem_segments.size(); ++segment_index) {
    const WasmElemSegment& elem_segment = module_->elem_segments[segment_index];
    // Passive segments are not copied during instantiation.
    if (elem_segment.status != WasmElemSegment::kStatusActive) continue;

    const uint32_t table_index = elem_segment.table_index;

    const WasmTable* table = &module_->tables[table_index];
    size_t dest_offset;
    ValueOrError result = EvaluateConstantExpression(
        &init_expr_zone_, elem_segment.offset,
        table->is_table64() ? kWasmI64 : kWasmI32, module_, isolate_,
        trusted_instance_data, shared_trusted_instance_data);
    if (MaybeMarkError(result, thrower_)) return;
    if (table->is_table64()) {
      uint64_t dest_offset_64 = to_value(result).to_u64();
      // Clamp to {std::numeric_limits<size_t>::max()}, which is always an
      // invalid offset, so we always fail the bounds check below.
      DCHECK_GT(std::numeric_limits<size_t>::max(),
                v8_flags.wasm_max_table_size);
      dest_offset = static_cast<size_t>(std::min(
          dest_offset_64, uint64_t{std::numeric_limits<size_t>::max()}));
    } else {
      dest_offset = to_value(result).to_u32();
    }

    const size_t count = elem_segment.element_count;

    DirectHandle<WasmTableObject> table_object(
        Cast<WasmTableObject>((table->shared ? shared_trusted_instance_data
                                             : trusted_instance_data)
                                  ->tables()
                                  ->get(table_index)),
        isolate_);
    if (!base::IsInBounds<size_t>(dest_offset, count,
                                  table_object->current_length())) {
      thrower_->RuntimeError("%s",
                             MessageFormatter::TemplateString(
                                 MessageTemplate::kWasmTrapTableOutOfBounds));
      return;
    }

    base::Vector<const uint8_t> module_bytes =
        trusted_instance_data->native_module()->wire_bytes();
    Decoder decoder(module_bytes);
    decoder.consume_bytes(elem_segment.elements_wire_bytes_offset);

    bool is_function_table =
        IsSubtypeOf(module_->tables[table_index].type, kWasmFuncRef, module_);

    if (is_function_table) {
      for (size_t i = 0; i < count; i++) {
        int entry_index = static_cast<int>(dest_offset + i);
        ValueOrError computed_element = ConsumeElementSegmentEntry(
            &init_expr_zone_, isolate_, trusted_instance_data,
            shared_trusted_instance_data, elem_segment, decoder,
"""


```