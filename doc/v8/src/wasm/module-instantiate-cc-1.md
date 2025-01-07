Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/wasm/module-instantiate.cc`. I need to analyze the code and identify its main purpose and key operations.

Here's a breakdown of the code's actions:

1. **`GetImportCallKind` Function:** This function determines the type of call to be made for an imported function. It checks for various scenarios:
    - Wasm-to-JS Fast API calls.
    - Well-known imports (like Math functions).
    - Arity match or mismatch for JavaScript functions.
    - Class constructors.
    - Defaulting to a generic call builtin.

2. **`InstanceBuilder` Class:** This class is responsible for building a WebAssembly instance object. Key functionalities include:
    - **Initialization:** Takes the isolate, module object, imports, and memory buffer as input.
    - **Building the instance:**  Creates the `WasmInstanceObject`, sets up memory, globals, tables, and processes imports and exports.
    - **Executing the start function:** Runs the module's start function if it exists.
    - **Helper methods:** Various private methods handle specific aspects of instance creation, like looking up imports, loading data segments, initializing globals, and processing exports.

3. **`WriteOutPGOTask` Class:**  This class is responsible for periodically writing out Profile-Guided Optimization (PGO) data to a file.

4. **`InstantiateToInstanceObject` Function:** This function serves as the entry point for instantiating a WebAssembly module. It creates an `InstanceBuilder` and attempts to build the instance.

Based on this analysis, the core function of this code is the **instantiation of a WebAssembly module**. It involves creating the necessary data structures and linking the module with its imports.
这是 v8 源代码 `v8/src/wasm/module-instantiate.cc` 的一部分，主要负责 **处理 WebAssembly 模块的导入 (imports) 并决定如何调用这些导入的函数**。

以下是代码片段功能的归纳：

1. **`GetImportCallKind` 函数:**  这个函数的核心功能是判断一个导入的函数应该以哪种方式被调用。它会根据导入的类型和签名，以及预先知道的信息（`well_known_status_`），来决定最优的调用方式。
    - 它会检查是否是 **Wasm 到 JS 的快速 API 调用 (`kWasmToJSFastApi`)**。
    - 它会检查是否是 **预定义的内置导入 (`CheckForWellKnownImport`)**，例如 `Math.sin`，`Math.cos` 等。
    - 对于 JavaScript 函数，它会检查 **导入的函数参数数量是否与期望的签名匹配 (`kJSFunctionArityMatch`)**，如果不匹配则标记为 `kJSFunctionArityMismatch`。
    - 它还会识别 **JavaScript 类构造函数 (`IsClassConstructor`)**。
    - 对于一些特定的 `Math` 对象内置函数，它会直接返回相应的类型，例如 `kF64Acos`, `kF64Sin` 等，以便进行更高效的调用。
    - 如果以上情况都不满足，则默认使用 **通用的调用方式 (`kUseCallBuiltin`)**。

2. **`InstanceBuilder` 类 (部分代码):**  这部分代码是 `InstanceBuilder` 类的一部分，该类负责构建 WebAssembly 实例对象。这部分代码主要关注 **处理模块的导入**。
    - **`ImportName` 方法:**  用于生成易于理解的导入名称字符串，方便调试和错误报告。
    - **`SanitizeImports` 方法:** (虽然代码中没有完整展示，但提到会检查 `ffi_` 是否可用) 这通常涉及到对导入进行初步的校验和处理。
    - **`ProcessImports` 方法:** (虽然代码中没有完整展示，但在注释中提到) 这是处理所有导入的核心方法，包括函数、表、全局变量和内存。它会调用 `LookupImport` 来查找导入的值，并调用 `ProcessImportedFunction`、`ProcessImportedTable`、`ProcessImportedGlobal` 等方法来处理不同类型的导入。
    - **`ProcessImportedFunction` 方法:**  处理单个导入的函数，会调用 `GetImportCallKind` 来确定调用方式。
    - **`ProcessImportedMemories` 方法:** 处理导入的内存对象。
    - **`AllocateMemory` 方法:**  为 WebAssembly 模块分配内存。

**如果 `v8/src/wasm/module-instantiate.cc` 以 `.tq` 结尾，那它是个 v8 Torque 源代码。**  当前的片段是 `.cc` 文件，所以是 C++ 源代码。 Torque 是一种 V8 自定义的语言，用于生成高效的 JavaScript 内置函数。

**它与 JavaScript 的功能有关系，因为 WebAssembly 模块经常需要与 JavaScript 代码进行交互，特别是通过导入 (imports)。**

**JavaScript 举例说明:**

假设有一个 WebAssembly 模块定义了一个需要导入的函数：

```wat
(module
  (import "env" "consoleLog" (func $log (param i32)))
  (func (export "add") (param $a i32) (param $b i32) (result i32)
    local.get $a
    local.get $b
    i32.add
    call $log (i32.const 123) ; 调用导入的函数
  )
)
```

在 JavaScript 中，你可以提供这个导入：

```javascript
const importObject = {
  env: {
    consoleLog: (value) => console.log("Wasm says:", value)
  }
};

WebAssembly.instantiateStreaming(fetch('module.wasm'), importObject)
  .then(results => {
    results.instance.exports.add(5, 10); // 调用 wasm 导出的函数，会触发导入的 consoleLog
  });
```

当 V8 执行 `WebAssembly.instantiateStreaming` 时，`v8/src/wasm/module-instantiate.cc` 中的代码就会负责处理 `"env"` 模块下的 `"consoleLog"` 导入。`GetImportCallKind` 会判断 `importObject.env.consoleLog` 是一个 JavaScript 函数，并根据其参数数量等信息，决定如何高效地从 WebAssembly 代码中调用它。

**代码逻辑推理与假设输入/输出:**

**假设输入:**

- `trusted_instance_data`: 一个指向 `WasmTrustedInstanceData` 对象的指针，包含模块实例的受信任数据。
- `func_index`: 导入函数在模块导入表中的索引。
- `callable_`: 一个 `MaybeHandle<Object>`，表示要导入的 JavaScript 函数对象。
- `expected_sig`: 指向期望的导入函数签名的指针。

**假设 `callable_` 是一个 JavaScript 函数 `(x, y) => x + y`，并且 `expected_sig` 定义的参数数量为 2。**

**输出:** `GetImportCallKind` 函数会返回 `ImportCallKind::kJSFunctionArityMatch`，因为导入的 JavaScript 函数的参数数量与期望的签名匹配。

**假设 `callable_` 是一个 JavaScript 函数 `(x) => x * 2`，但 `expected_sig` 定义的参数数量为 2。**

**输出:** `GetImportCallKind` 函数会返回 `ImportCallKind::kJSFunctionArityMismatch`，因为导入的 JavaScript 函数的参数数量与期望的签名不匹配。

**用户常见的编程错误:**

一个常见的编程错误是在 JavaScript 中提供的导入函数的签名与 WebAssembly 模块中声明的导入签名不匹配。

**例如:**

WebAssembly 模块声明导入一个接受两个 i32 参数的函数：

```wat
(module
  (import "env" "add" (func $add (param i32 i32)))
  (func (export "callAdd") (param $a i32) (param $b i32)
    local.get $a
    local.get $b
    call $add
  )
)
```

但 JavaScript 提供的导入函数只接受一个参数：

```javascript
const importObject = {
  env: {
    add: (x) => console.log("Received:", x)
  }
};

WebAssembly.instantiateStreaming(fetch('module.wasm'), importObject)
  .then(results => {
    results.instance.exports.callAdd(5, 10); // 调用时会出错
  });
```

在这种情况下，`GetImportCallKind` 会检测到参数数量不匹配，虽然它不会直接抛出错误，但后续的调用可能会导致运行时错误或类型错误。V8 通常会在实例化阶段或调用时进行检查，并抛出 `LinkError` 或其他类型的错误。

**总结代码片段的功能:**

总而言之，这部分 `v8/src/wasm/module-instantiate.cc` 代码片段的核心功能是 **处理 WebAssembly 模块的导入，特别是判断如何高效地调用导入的 JavaScript 函数或其他外部资源**。它通过检查导入的类型、签名和预定义信息，来选择最优的调用方式，并能检测出一些常见的导入错误，例如参数数量不匹配。这对于 WebAssembly 与 JavaScript 的互操作性至关重要。

Prompt: 
```
这是目录为v8/src/wasm/module-instantiate.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/module-instantiate.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能

"""
 {
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
"""


```