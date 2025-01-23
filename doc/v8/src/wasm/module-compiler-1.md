Response: The user has provided a C++ source code snippet from `v8/src/wasm/module-compiler.cc`. They are asking for a summary of its functionality, focusing on its relation to JavaScript, and to provide a JavaScript example if a connection exists. This is the second part of a three-part sequence.

Based on the provided code, I can identify several key functionalities:

1. **Tiered Compilation:** The code manages different compilation tiers (Liftoff, TurboFan) for WebAssembly functions, aiming for faster initial execution (Liftoff) and optimized performance later (TurboFan).
2. **Background Compilation:** It utilizes background threads for compilation to avoid blocking the main JavaScript thread.
3. **Compilation Units:** The code breaks down the compilation process into smaller units that can be processed concurrently.
4. **Type Feedback:** It mentions `TransitiveTypeFeedbackProcessor`, suggesting the collection and use of runtime type information to optimize TurboFan compilation.
5. **Feature Detection:** The code tracks and reports the usage of various WebAssembly features (e.g., shared memory, SIMD, threads) using use counters.
6. **Built-in Imports Validation:** It validates the signatures of imported functions with specific module names like `wasm:js-string` and `wasm:text-encoder`, indicating integration with JavaScript APIs.
7. **Error Handling:**  The code includes error checking and reporting mechanisms.
8. **Testing Helpers:** Functions like `TierUpNowForTesting`, `TierUpAllForTesting`, and `InitializeCompilationForTesting` suggest the inclusion of testing utilities.
9. **Asynchronous Compilation:**  The presence of `AsyncCompileJob` and related classes indicates support for asynchronous compilation of WebAssembly modules.
10. **Streaming Compilation:** The mention of `StreamingProcessor` suggests support for compiling WebAssembly modules as they are being downloaded.
11. **Native Module Caching:** The code interacts with a `NativeModuleCache` to potentially reuse previously compiled modules.

The connection to JavaScript is evident in the handling of built-in imports and the asynchronous compilation process, which directly impacts how WebAssembly modules are loaded and executed within a JavaScript environment.

For the JavaScript example, I can illustrate the interaction with built-in imports or the asynchronous compilation process.
这是 `v8/src/wasm/module-compiler.cc` 文件的第二部分，主要负责 WebAssembly 模块的编译和优化过程中的以下功能：

**1. WebAssembly 函数的分层编译（Tiered Compilation）：**

*   代码中出现了 `TierUpNowForTesting` 和 `TierUpAllForTesting` 函数，以及 `AddTopTierPriorityCompilationUnit`，表明它支持将 WebAssembly 函数从较低的编译层级（例如，基线 Liftoff）提升到更高的优化层级（TurboFan）。
*   `TransitiveTypeFeedbackProcessor::Process` 的调用表明，它利用运行时的类型反馈信息来指导更高层级的代码生成，从而提高性能。

**2. 后台编译管理：**

*   `ExecuteCompilationUnits` 函数是后台编译任务的核心，它从编译队列中获取编译单元并执行编译。
*   `BackgroundCompileJob` 类定义了后台编译任务，用于在单独的线程上执行 WebAssembly 代码的编译。
*   通过 `CompilationUnitQueues` 和 `CompilationStateImpl` 来管理编译单元和编译状态。

**3. 特性检测和使用计数：**

*   `PublishDetectedFeatures` 函数用于记录 WebAssembly 模块中使用的各种特性（例如，共享内存、SIMD、线程等），并使用 `isolate->CountUsage` 来更新 V8 的使用计数器。这有助于 V8 团队了解 WebAssembly 特性的使用情况。

**4. 内置导入的验证和设置：**

*   `ValidateAndSetBuiltinImports` 函数用于验证特定模块名（例如 `"wasm:js-string"`, `"wasm:text-encoder"`, `"wasm:text-decoder"`) 的导入函数的签名是否符合预期。
*   如果验证通过，这些内置导入的状态会被记录在 `module->well_known_imports` 中，以便在后续的执行过程中进行优化处理。

**5. 编译任务的初始化和管理：**

*   `InitializeCompilation` 函数用于初始化编译过程，创建 `CompilationUnitBuilder`。
*   `CompileNativeModule` 函数是同步编译 WebAssembly 模块的入口点，它负责初始化编译单元，并等待基线编译完成。

**6. 异步编译：**

*   `AsyncCompileJob` 类负责 WebAssembly 模块的异步编译。
*   `CreateStreamingDecoder` 和 `AsyncStreamingProcessor` 表明它支持流式编译，即在模块下载的同时进行编译。
*   通过 `CompileStep` 和相关的子类（如 `DecodeModule`, `PrepareAndStartCompile`, `FinishCompilation`）来组织异步编译的各个阶段。

**7. 编译结果的回调和通知：**

*   `CompilationTimeCallback` 用于记录编译时间，并将编译事件发送到性能指标记录器。
*   `CompilationStateCallback` 用于在异步编译过程中处理编译事件，例如基线编译完成或编译失败。

**8. 模块缓存：**

*   `GetOrCompileNewNativeModule` 函数会尝试从缓存中获取已编译的 `NativeModule`，如果不存在则进行编译。
*   `GetWasmEngine()->UpdateNativeModuleCache` 用于更新模块缓存。

**与 JavaScript 的关系以及 JavaScript 示例：**

这个文件直接关系到 JavaScript 中如何加载和执行 WebAssembly 模块。特别是，内置导入的验证和设置功能，以及异步编译和流式编译的实现，都直接影响了 JavaScript API 中 `WebAssembly.instantiate` 和 `WebAssembly.compileStreaming` 等方法的工作方式。

**JavaScript 示例 (关于内置导入):**

假设 WebAssembly 模块导入了一个名为 `fromCharCode` 的函数，模块名为 `"wasm:js-string"`。在 `v8/src/wasm/module-compiler.cc` 中，`ValidateAndSetBuiltinImports` 函数会检查这个导入的签名是否与 JavaScript 的 `String.fromCharCode` 方法的签名一致。

```javascript
// JavaScript 代码
const importObject = {
  "wasm:js-string": {
    "fromCharCode": String.fromCharCode // 提供 JavaScript 的 String.fromCharCode
  }
};

WebAssembly.instantiateStreaming(fetch('my_wasm_module.wasm'), importObject)
  .then(results => {
    // 使用导出的函数
  });
```

在这个例子中，当 V8 编译 `my_wasm_module.wasm` 时，`ValidateAndSetBuiltinImports` 会识别出 `"wasm:js-string"` 模块下的 `"fromCharCode"` 导入，并验证它的类型是否匹配 `kSig_e_i` (`{kRefExtern, kI32}` 作为参数，返回 `kRefExtern`)。这确保了 WebAssembly 代码能够安全且正确地调用 JavaScript 的内置函数。

**总结来说，`v8/src/wasm/module-compiler.cc` 的这部分代码负责 WebAssembly 模块编译的核心逻辑，包括分层编译、后台处理、特性检测、与 JavaScript 的集成（通过内置导入），以及异步和流式编译的支持，这些都直接影响了 WebAssembly 在 JavaScript 环境中的性能和可用性。**

### 提示词
```
这是目录为v8/src/wasm/module-compiler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```
// Before adding the tier-up unit or increasing priority, process type
  // feedback for best code generation.
  if (v8_flags.wasm_inlining) {
    // TODO(jkummerow): we could have collisions here if different instances
    // of the same module have collected different feedback. If that ever
    // becomes a problem, figure out a solution.
    TransitiveTypeFeedbackProcessor::Process(isolate, trusted_instance_data,
                                             func_index);
  }

  compilation_state->AddTopTierPriorityCompilationUnit(tiering_unit, priority);
}

void TierUpNowForTesting(Isolate* isolate,
                         Tagged<WasmTrustedInstanceData> trusted_instance_data,
                         int func_index) {
  NativeModule* native_module = trusted_instance_data->native_module();
  if (v8_flags.wasm_inlining) {
    TransitiveTypeFeedbackProcessor::Process(isolate, trusted_instance_data,
                                             func_index);
  }
  wasm::GetWasmEngine()->CompileFunction(isolate->counters(), native_module,
                                         func_index,
                                         wasm::ExecutionTier::kTurbofan);
  CHECK(!native_module->compilation_state()->failed());
}

void TierUpAllForTesting(
    Isolate* isolate, Tagged<WasmTrustedInstanceData> trusted_instance_data) {
  NativeModule* native_module = trusted_instance_data->native_module();
  const WasmModule* mod = native_module->module();
  WasmCodeRefScope code_ref_scope;

  uint32_t start = mod->num_imported_functions;
  uint32_t end = start + mod->num_declared_functions;
  for (uint32_t func_index = start; func_index < end; func_index++) {
    if (!native_module->HasCodeWithTier(func_index, ExecutionTier::kTurbofan)) {
      TierUpNowForTesting(isolate, trusted_instance_data, func_index);
    }
  }
}

void InitializeCompilationForTesting(NativeModule* native_module) {
  Impl(native_module->compilation_state())
      ->InitializeCompilationProgress(nullptr);
}

void PublishDetectedFeatures(WasmDetectedFeatures detected_features,
                             Isolate* isolate, bool is_initial_compilation) {
  using Feature = v8::Isolate::UseCounterFeature;
  static constexpr std::pair<WasmDetectedFeature, Feature> kUseCounters[] = {
      {WasmDetectedFeature::shared_memory, Feature::kWasmSharedMemory},
      {WasmDetectedFeature::reftypes, Feature::kWasmRefTypes},
      {WasmDetectedFeature::simd, Feature::kWasmSimdOpcodes},
      {WasmDetectedFeature::threads, Feature::kWasmThreadOpcodes},
      {WasmDetectedFeature::legacy_eh, Feature::kWasmExceptionHandling},
      {WasmDetectedFeature::memory64, Feature::kWasmMemory64},
      {WasmDetectedFeature::multi_memory, Feature::kWasmMultiMemory},
      {WasmDetectedFeature::gc, Feature::kWasmGC},
      {WasmDetectedFeature::imported_strings, Feature::kWasmImportedStrings},
      {WasmDetectedFeature::imported_strings_utf8,
       Feature::kWasmImportedStringsUtf8},
      {WasmDetectedFeature::return_call, Feature::kWasmReturnCall},
      {WasmDetectedFeature::extended_const, Feature::kWasmExtendedConst},
      {WasmDetectedFeature::relaxed_simd, Feature::kWasmRelaxedSimd},
      {WasmDetectedFeature::type_reflection, Feature::kWasmTypeReflection},
      {WasmDetectedFeature::exnref, Feature::kWasmExnRef},
      {WasmDetectedFeature::typed_funcref, Feature::kWasmTypedFuncRef},
      {WasmDetectedFeature::jspi, Feature::kWasmJavaScriptPromiseIntegration},
  };

  // Check that every staging or shipping feature has a use counter as that is
  // the main point of tracking used features.
  auto check_use_counter = [](WasmDetectedFeature feat) constexpr -> bool {
    // Some features intentionally do not have a use counter.
    constexpr WasmDetectedFeature kIntentionallyNoUseCounter[] = {
        WasmDetectedFeature::stringref,    // Deprecated / unlikely to ship.
        WasmDetectedFeature::js_inlining,  // Not a user-visible feature.
    };
    for (auto no_use_counter_feature : kIntentionallyNoUseCounter) {
      if (feat == no_use_counter_feature) return true;
    }
    for (auto [feature, use_counter] : kUseCounters) {
      if (feat == feature) return true;
    }
    return false;
  };
#define CHECK_USE_COUNTER(feat, ...) \
  static_assert(check_use_counter(WasmDetectedFeature::feat));
  FOREACH_WASM_STAGING_FEATURE_FLAG(CHECK_USE_COUNTER)
  FOREACH_WASM_SHIPPED_FEATURE_FLAG(CHECK_USE_COUNTER)
  FOREACH_WASM_NON_FLAG_FEATURE(CHECK_USE_COUNTER)
#undef CHECK_USE_COUNTER

  static constexpr size_t kMaxFeatures = arraysize(kUseCounters) + 1;
  base::SmallVector<Feature, kMaxFeatures> use_counter_features;
  if (is_initial_compilation) {
    // Always set the WasmModuleCompilation feature as a baseline for the other
    // features. Note that we also track instantiation, but the number of
    // compilations and instantiations are pretty unrelated.
    use_counter_features.push_back(Feature::kWasmModuleCompilation);
  }

  for (auto [wasm_feature, feature] : kUseCounters) {
    if (!detected_features.contains(wasm_feature)) continue;
    use_counter_features.push_back(feature);
  }
  if (use_counter_features.empty()) return;

  isolate->CountUsage(base::VectorOf(use_counter_features));

  // Help differential fuzzers avoid detecting known/intentional platform-
  // specific differences.
  if (v8_flags.correctness_fuzzer_suppressions) {
    if (detected_features.has_relaxed_simd()) {
      PrintF("Warning: This run cannot be compared across architectures.\n");
    }
  }
}

namespace {

bool IsI16Array(wasm::ValueType type, const WasmModule* module) {
  if (!type.is_object_reference() || !type.has_index()) return false;
  ModuleTypeIndex reftype = type.ref_index();
  if (!module->has_array(reftype)) return false;
  return module->canonical_type_id(reftype) ==
         TypeCanonicalizer::kPredefinedArrayI16Index;
}

bool IsI8Array(wasm::ValueType type, const WasmModule* module,
               bool allow_nullable) {
  if (!type.is_object_reference() || !type.has_index()) return false;
  if (!allow_nullable && type.is_nullable()) return false;
  ModuleTypeIndex reftype = type.ref_index();
  if (!module->has_array(reftype)) return false;
  return module->canonical_type_id(reftype) ==
         TypeCanonicalizer::kPredefinedArrayI8Index;
}

// Returns the start offset of a given import, for use in error messages.
// The module_name payload is preceded by an i32v giving its length. That i32v
// is preceded by another i32v, which is either a type index (specifying the
// type of the previous import) or the imports count (in case of the first
// import). So we scan backwards as long as we find non-last LEB bytes there.
uint32_t ImportStartOffset(base::Vector<const uint8_t> wire_bytes,
                           uint32_t module_name_start) {
  DCHECK_LT(0, module_name_start);
  uint32_t offset = module_name_start - 1;  // Last byte of the string length.
  DCHECK_EQ(wire_bytes[offset] & 0x80, 0);
  while (offset > 0 && (wire_bytes[offset - 1] & 0x80) != 0) {
    offset--;
  }
  return offset;
}

}  // namespace

// Validates the signatures of recognized compile-time imports, and stores
// them on the {module}'s {well_known_imports} list.
WasmError ValidateAndSetBuiltinImports(const WasmModule* module,
                                       base::Vector<const uint8_t> wire_bytes,
                                       const CompileTimeImports& imports,
                                       WasmDetectedFeatures* detected) {
  DCHECK_EQ(module->origin, kWasmOrigin);
  if (imports.empty()) return {};

  static constexpr ValueType kRefExtern = ValueType::Ref(HeapType::kExtern);
  static constexpr ValueType kExternRef = kWasmExternRef;
  static constexpr ValueType kI32 = kWasmI32;

  // Shorthands: "r" = nullable "externref", "e" = non-nullable "ref extern".
  static constexpr ValueType kReps_e_i[] = {kRefExtern, kI32};
  static constexpr ValueType kReps_e_rr[] = {kRefExtern, kExternRef,
                                             kExternRef};
  static constexpr ValueType kReps_e_rii[] = {kRefExtern, kExternRef, kI32,
                                              kI32};
  static constexpr ValueType kReps_i_ri[] = {kI32, kExternRef, kI32};
  static constexpr ValueType kReps_i_rr[] = {kI32, kExternRef, kExternRef};

  static constexpr FunctionSig kSig_e_i(1, 1, kReps_e_i);
  static constexpr FunctionSig kSig_e_r(1, 1, kReps_e_rr);
  static constexpr FunctionSig kSig_e_rr(1, 2, kReps_e_rr);
  static constexpr FunctionSig kSig_e_rii(1, 3, kReps_e_rii);

  static constexpr FunctionSig kSig_i_r(1, 1, kReps_i_ri);
  static constexpr FunctionSig kSig_i_ri(1, 2, kReps_i_ri);
  static constexpr FunctionSig kSig_i_rr(1, 2, kReps_i_rr);

  std::vector<WellKnownImport> statuses;
  statuses.reserve(module->num_imported_functions);
  for (size_t i = 0; i < module->import_table.size(); i++) {
    const WasmImport& import = module->import_table[i];

    // When magic string imports are requested, check that imports with the
    // string constant module name are globals of the right type.
    if (imports.has_string_constants(wire_bytes.SubVector(
            import.module_name.offset(), import.module_name.end_offset()))) {
      if (import.kind != kExternalGlobal ||
          !module->globals[import.index].type.is_reference_to(
              HeapType::kExtern) ||
          module->globals[import.index].mutability != false) {
        TruncatedUserString<> name(
            wire_bytes.data() + import.field_name.offset(),
            import.field_name.length());
        return WasmError(
            ImportStartOffset(wire_bytes, import.module_name.offset()),
            "String constant import #%zu \"%.*s\" must be an immutable global "
            "subtyping externref",
            i, name.length(), name.start());
      }
    }

    // Check compile-time imported functions.
    if (import.kind != kExternalFunction) continue;
    base::Vector<const uint8_t> module_name = wire_bytes.SubVector(
        import.module_name.offset(), import.module_name.end_offset());
    constexpr size_t kMinInterestingLength = 10;
    if (module_name.size() < kMinInterestingLength ||
        module_name.SubVector(0, 5) != base::StaticOneByteVector("wasm:")) {
      statuses.push_back(WellKnownImport::kUninstantiated);
      continue;
    }
    base::Vector<const uint8_t> collection = module_name.SubVectorFrom(5);
    WellKnownImport status = WellKnownImport::kUninstantiated;
    const WasmFunction& func = module->functions[import.index];
    const FunctionSig* sig = func.sig;
    WireBytesRef field_name = import.field_name;
    base::Vector<const uint8_t> name =
        wire_bytes.SubVector(field_name.offset(), field_name.end_offset());
    if (collection == base::StaticOneByteVector("js-string") &&
        imports.contains(CompileTimeImport::kJsString)) {
#define RETURN_ERROR(module_name_string, import_name)                     \
  uint32_t error_offset =                                                 \
      ImportStartOffset(wire_bytes, import.module_name.offset());         \
  return WasmError(error_offset,                                          \
                   "Imported builtin function \"wasm:" module_name_string \
                   "\" \"" import_name "\" has incorrect signature")

#define CHECK_SIG(import_name, kSigName, kEnumName)      \
  if (name == base::StaticOneByteVector(#import_name)) { \
    if (*sig != kSigName) {                              \
      RETURN_ERROR("js-string", #import_name);           \
    }                                                    \
    status = WellKnownImport::kEnumName;                 \
    detected->add_imported_strings();                    \
  } else  // NOLINT(readability/braces)

      CHECK_SIG(cast, kSig_e_r, kStringCast)
      CHECK_SIG(test, kSig_i_r, kStringTest)
      CHECK_SIG(fromCharCode, kSig_e_i, kStringFromCharCode)
      CHECK_SIG(fromCodePoint, kSig_e_i, kStringFromCodePoint)
      CHECK_SIG(charCodeAt, kSig_i_ri, kStringCharCodeAt)
      CHECK_SIG(codePointAt, kSig_i_ri, kStringCodePointAt)
      CHECK_SIG(length, kSig_i_r, kStringLength)
      CHECK_SIG(concat, kSig_e_rr, kStringConcat)
      CHECK_SIG(substring, kSig_e_rii, kStringSubstring)
      CHECK_SIG(equals, kSig_i_rr, kStringEquals)
      CHECK_SIG(compare, kSig_i_rr, kStringCompare)
      if (name == base::StaticOneByteVector("fromCharCodeArray")) {
        if (sig->parameter_count() != 3 || sig->return_count() != 1 ||
            !IsI16Array(sig->GetParam(0), module) ||  // --
            sig->GetParam(1) != kI32 ||               // --
            sig->GetParam(2) != kI32 ||               // --
            sig->GetReturn() != kRefExtern) {
          RETURN_ERROR("js-string", "fromCharCodeArray");
        }
        detected->add_imported_strings();
        status = WellKnownImport::kStringFromWtf16Array;
      } else if (name == base::StaticOneByteVector("intoCharCodeArray")) {
        if (sig->parameter_count() != 3 || sig->return_count() != 1 ||
            sig->GetParam(0) != kExternRef ||
            !IsI16Array(sig->GetParam(1), module) ||  // --
            sig->GetParam(2) != kI32 ||               // --
            sig->GetReturn() != kI32) {
          RETURN_ERROR("js-string", "intoCharCodeArray");
        }
        status = WellKnownImport::kStringToWtf16Array;
        detected->add_imported_strings();
      }
#undef CHECK_SIG
    } else if (collection == base::StaticOneByteVector("text-encoder") &&
               imports.contains(CompileTimeImport::kTextEncoder)) {
      if (name == base::StaticOneByteVector("measureStringAsUTF8")) {
        if (*sig != kSig_i_r) {
          RETURN_ERROR("text-encoder", "measureStringAsUTF8");
        }
        status = WellKnownImport::kStringMeasureUtf8;
        detected->add_imported_strings_utf8();
      } else if (name ==
                 base::StaticOneByteVector("encodeStringIntoUTF8Array")) {
        if (sig->parameter_count() != 3 || sig->return_count() != 1 ||
            sig->GetParam(0) != kExternRef ||              // --
            !IsI8Array(sig->GetParam(1), module, true) ||  // --
            sig->GetParam(2) != kI32 ||                    // --
            sig->GetReturn() != kI32) {
          RETURN_ERROR("text-encoder", "encodeStringIntoUTF8Array");
        }
        status = WellKnownImport::kStringIntoUtf8Array;
        detected->add_imported_strings_utf8();
      } else if (name == base::StaticOneByteVector("encodeStringToUTF8Array")) {
        if (sig->parameter_count() != 1 || sig->return_count() != 1 ||
            sig->GetParam(0) != kExternRef ||
            !IsI8Array(sig->GetReturn(), module, false)) {
          RETURN_ERROR("text-encoder", "encodeStringToUTF8Array");
        }
        status = WellKnownImport::kStringToUtf8Array;
        detected->add_imported_strings_utf8();
      }
    } else if (collection == base::StaticOneByteVector("text-decoder") &&
               imports.contains(CompileTimeImport::kTextDecoder)) {
      if (name == base::StaticOneByteVector("decodeStringFromUTF8Array")) {
        if (sig->parameter_count() != 3 || sig->return_count() != 1 ||
            !IsI8Array(sig->GetParam(0), module, true) ||  // --
            sig->GetParam(1) != kI32 ||                    // --
            sig->GetParam(2) != kI32 ||                    // --
            sig->GetReturn() != kRefExtern) {
          RETURN_ERROR("text-decoder", "decodeStringFromUTF8Array");
        }
        status = WellKnownImport::kStringFromUtf8Array;
        detected->add_imported_strings_utf8();
      }
    }
#undef RETURN_ERROR
    statuses.push_back(status);
  }
  // We're operating on a fresh WasmModule instance here, so we don't need to
  // check for incompatibilities with previously seen imports.
  DCHECK_EQ(module->num_imported_functions, statuses.size());
  // The "Initialize" call is currently only safe when the decoder has allocated
  // storage, which it allocates when there is an imports section.
  if (module->num_imported_functions != 0) {
    module->type_feedback.well_known_imports.Initialize(
        base::VectorOf(statuses));
  }
  return {};
}

namespace {

enum CompilationExecutionResult : int8_t { kNoMoreUnits, kYield };

const char* GetCompilationEventName(const WasmCompilationUnit& unit,
                                    const CompilationEnv& env) {
  ExecutionTier tier = unit.tier();
  if (tier == ExecutionTier::kLiftoff) {
    return "wasm.BaselineCompilation";
  }
  if (tier == ExecutionTier::kTurbofan) {
    return "wasm.TopTierCompilation";
  }
  if (unit.func_index() <
      static_cast<int>(env.module->num_imported_functions)) {
    return "wasm.WasmToJSWrapperCompilation";
  }
  return "wasm.OtherCompilation";
}

constexpr uint8_t kMainTaskId = 0;

// Run by the {BackgroundCompileJob} (on any thread).
CompilationExecutionResult ExecuteCompilationUnits(
    std::weak_ptr<NativeModule> native_module, Counters* counters,
    JobDelegate* delegate, CompilationTier tier) {
  TRACE_EVENT0("v8.wasm", "wasm.ExecuteCompilationUnits");

  // Compilation must be disabled in jitless mode.
  CHECK(!v8_flags.wasm_jitless);

  // These fields are initialized in a {BackgroundCompileScope} before
  // starting compilation.
  std::optional<CompilationEnv> env;
  std::shared_ptr<WireBytesStorage> wire_bytes;
  std::shared_ptr<const WasmModule> module;
  // Task 0 is any main thread (there might be multiple from multiple isolates),
  // worker threads start at 1 (thus the "+ 1").
  static_assert(kMainTaskId == 0);
  int task_id = delegate ? (int{delegate->GetTaskId()} + 1) : kMainTaskId;
  DCHECK_LE(0, task_id);
  CompilationUnitQueues::Queue* queue;
  std::optional<WasmCompilationUnit> unit;

  WasmDetectedFeatures global_detected_features;

  // Preparation (synchronized): Initialize the fields above and get the first
  // compilation unit.
  {
    BackgroundCompileScope compile_scope(native_module);
    if (compile_scope.cancelled()) return kYield;
    env.emplace(CompilationEnv::ForModule(compile_scope.native_module()));
    wire_bytes = compile_scope.compilation_state()->GetWireBytesStorage();
    module = compile_scope.native_module()->shared_module();
    queue = compile_scope.compilation_state()->GetQueueForCompileTask(task_id);
    unit =
        compile_scope.compilation_state()->GetNextCompilationUnit(queue, tier);
    if (!unit) return kNoMoreUnits;
  }
  TRACE_COMPILE("ExecuteCompilationUnits (task id %d)\n", task_id);

  std::vector<WasmCompilationResult> results_to_publish;
  while (true) {
    ExecutionTier current_tier = unit->tier();
    const char* event_name = GetCompilationEventName(unit.value(), env.value());
    TRACE_EVENT0("v8.wasm", event_name);
    while (unit->tier() == current_tier) {
      // Track detected features on a per-function basis before collecting them
      // into {global_detected_features}.
      WasmDetectedFeatures per_function_detected_features;
      // (asynchronous): Execute the compilation.
      WasmCompilationResult result =
          unit->ExecuteCompilation(&env.value(), wire_bytes.get(), counters,
                                   &per_function_detected_features);
      global_detected_features.Add(per_function_detected_features);
      bool compilation_succeeded = result.succeeded();
      ExecutionTier result_tier = result.result_tier;
      // We don't eagerly compile import wrappers any more.
      DCHECK_GE(unit->func_index(), env->module->num_imported_functions);
      results_to_publish.emplace_back(std::move(result));

      bool yield = delegate && delegate->ShouldYield();

      // (synchronized): Publish the compilation result and get the next unit.
      BackgroundCompileScope compile_scope(native_module);
      if (compile_scope.cancelled()) return kYield;

      if (!compilation_succeeded) {
        compile_scope.compilation_state()->SetError();
        return kNoMoreUnits;
      }

      if (!unit->for_debugging() && result_tier != current_tier) {
        compile_scope.native_module()->AddLiftoffBailout();
      }

      // Yield or get next unit.
      if (yield ||
          !(unit = compile_scope.compilation_state()->GetNextCompilationUnit(
                queue, tier))) {
        std::vector<std::unique_ptr<WasmCode>> unpublished_code =
            compile_scope.native_module()->AddCompiledCode(
                base::VectorOf(results_to_publish));
        results_to_publish.clear();
        compile_scope.compilation_state()->SchedulePublishCompilationResults(
            std::move(unpublished_code), tier);
        compile_scope.compilation_state()->OnCompilationStopped(
            global_detected_features);
        return yield ? kYield : kNoMoreUnits;
      }

      // Publish after finishing a certain amount of units, to avoid
      // contention when all threads publish at the end.
      bool batch_full =
          queue->ShouldPublish(static_cast<int>(results_to_publish.size()));
      // Also publish each time the compilation tier changes from Liftoff to
      // TurboFan, such that we immediately publish the baseline compilation
      // results to start execution, and do not wait for a batch to fill up.
      bool liftoff_finished = unit->tier() != current_tier &&
                              unit->tier() == ExecutionTier::kTurbofan;
      if (batch_full || liftoff_finished) {
        std::vector<std::unique_ptr<WasmCode>> unpublished_code =
            compile_scope.native_module()->AddCompiledCode(
                base::VectorOf(results_to_publish));
        results_to_publish.clear();
        compile_scope.compilation_state()->SchedulePublishCompilationResults(
            std::move(unpublished_code), tier);
      }
    }
  }
  UNREACHABLE();
}

std::unique_ptr<CompilationUnitBuilder> InitializeCompilation(
    Isolate* isolate, NativeModule* native_module,
    ProfileInformation* pgo_info) {
  CompilationStateImpl* compilation_state =
      Impl(native_module->compilation_state());
  auto builder = std::make_unique<CompilationUnitBuilder>(native_module);
  compilation_state->InitializeCompilationProgress(pgo_info);
  return builder;
}

bool MayCompriseLazyFunctions(const WasmModule* module,
                              WasmEnabledFeatures enabled_features) {
  if (IsLazyModule(module)) return true;
  if (enabled_features.has_compilation_hints()) return true;
#ifdef ENABLE_SLOW_DCHECKS
  int start = module->num_imported_functions;
  int end = start + module->num_declared_functions;
  for (int func_index = start; func_index < end; func_index++) {
    SLOW_DCHECK(GetCompileStrategy(module, enabled_features, func_index,
                                   false) != CompileStrategy::kLazy);
  }
#endif
  return false;
}

class CompilationTimeCallback : public CompilationEventCallback {
 public:
  enum CompileMode { kSynchronous, kAsync, kStreaming };
  explicit CompilationTimeCallback(
      std::shared_ptr<Counters> async_counters,
      std::shared_ptr<metrics::Recorder> metrics_recorder,
      v8::metrics::Recorder::ContextId context_id,
      std::weak_ptr<NativeModule> native_module, CompileMode compile_mode)
      : start_time_(base::TimeTicks::Now()),
        async_counters_(std::move(async_counters)),
        metrics_recorder_(std::move(metrics_recorder)),
        context_id_(context_id),
        native_module_(std::move(native_module)),
        compile_mode_(compile_mode) {}

  void call(CompilationEvent compilation_event) override {
    DCHECK(base::TimeTicks::IsHighResolution());
    std::shared_ptr<NativeModule> native_module = native_module_.lock();
    if (!native_module) return;
    auto now = base::TimeTicks::Now();
    auto duration = now - start_time_;
    if (compilation_event == CompilationEvent::kFinishedBaselineCompilation) {
      // Reset {start_time_} to measure tier-up time.
      start_time_ = now;
      if (compile_mode_ != kSynchronous) {
        TimedHistogram* histogram =
            compile_mode_ == kAsync
                ? async_counters_->wasm_async_compile_wasm_module_time()
                : async_counters_->wasm_streaming_compile_wasm_module_time();
        histogram->AddSample(static_cast<int>(duration.InMicroseconds()));
      }

      v8::metrics::WasmModuleCompiled event{
          (compile_mode_ != kSynchronous),         // async
          (compile_mode_ == kStreaming),           // streamed
          false,                                   // cached
          false,                                   // deserialized
          v8_flags.wasm_lazy_compilation,          // lazy
          true,                                    // success
          native_module->liftoff_code_size(),      // code_size_in_bytes
          native_module->liftoff_bailout_count(),  // liftoff_bailout_count
          duration.InMicroseconds()};              // wall_clock_duration_in_us
      metrics_recorder_->DelayMainThreadEvent(event, context_id_);
    }
    if (compilation_event == CompilationEvent::kFailedCompilation) {
      v8::metrics::WasmModuleCompiled event{
          (compile_mode_ != kSynchronous),         // async
          (compile_mode_ == kStreaming),           // streamed
          false,                                   // cached
          false,                                   // deserialized
          v8_flags.wasm_lazy_compilation,          // lazy
          false,                                   // success
          native_module->liftoff_code_size(),      // code_size_in_bytes
          native_module->liftoff_bailout_count(),  // liftoff_bailout_count
          duration.InMicroseconds()};              // wall_clock_duration_in_us
      metrics_recorder_->DelayMainThreadEvent(event, context_id_);
    }
  }

 private:
  base::TimeTicks start_time_;
  const std::shared_ptr<Counters> async_counters_;
  std::shared_ptr<metrics::Recorder> metrics_recorder_;
  v8::metrics::Recorder::ContextId context_id_;
  std::weak_ptr<NativeModule> native_module_;
  const CompileMode compile_mode_;
};

WasmError ValidateFunctions(const WasmModule* module,
                            base::Vector<const uint8_t> wire_bytes,
                            WasmEnabledFeatures enabled_features,
                            OnlyLazyFunctions only_lazy_functions,
                            WasmDetectedFeatures* detected_features) {
  DCHECK_EQ(module->origin, kWasmOrigin);
  if (only_lazy_functions &&
      !MayCompriseLazyFunctions(module, enabled_features)) {
    return {};
  }

  std::function<bool(int)> filter;  // Initially empty for "all functions".
  if (only_lazy_functions) {
    const bool is_lazy_module = IsLazyModule(module);
    filter = [module, enabled_features, is_lazy_module](int func_index) {
      CompileStrategy strategy = GetCompileStrategy(module, enabled_features,
                                                    func_index, is_lazy_module);
      return strategy == CompileStrategy::kLazy ||
             strategy == CompileStrategy::kLazyBaselineEagerTopTier;
    };
  }
  // Call {ValidateFunctions} in the module decoder.
  return ValidateFunctions(module, enabled_features, wire_bytes, filter,
                           detected_features);
}

WasmError ValidateFunctions(const NativeModule& native_module,
                            OnlyLazyFunctions only_lazy_functions) {
  WasmDetectedFeatures detected_features;
  WasmError result =
      ValidateFunctions(native_module.module(), native_module.wire_bytes(),
                        native_module.enabled_features(), only_lazy_functions,
                        &detected_features);
  if (!result.has_error()) {
    // This function is called before the NativeModule is finished; all detected
    // features will be published afterwards anyway, so ignore the return value
    // here.
    USE(native_module.compilation_state()->UpdateDetectedFeatures(
        detected_features));
  }
  return result;
}

void CompileNativeModule(Isolate* isolate,
                         v8::metrics::Recorder::ContextId context_id,
                         ErrorThrower* thrower,
                         std::shared_ptr<NativeModule> native_module,
                         ProfileInformation* pgo_info) {
  CHECK(!v8_flags.jitless || v8_flags.wasm_jitless);
  const WasmModule* module = native_module->module();

  // The callback captures a shared ptr to the semaphore.
  auto* compilation_state = Impl(native_module->compilation_state());
  if (base::TimeTicks::IsHighResolution()) {
    compilation_state->AddCallback(std::make_unique<CompilationTimeCallback>(
        isolate->async_counters(), isolate->metrics_recorder(), context_id,
        native_module, CompilationTimeCallback::kSynchronous));
  }

  // Initialize the compilation units and kick off background compile tasks.
  std::unique_ptr<CompilationUnitBuilder> builder =
      InitializeCompilation(isolate, native_module.get(), pgo_info);
  compilation_state->InitializeCompilationUnits(std::move(builder));

  // Validate wasm modules for lazy compilation if requested. Never validate
  // asm.js modules as these are valid by construction (additionally a CHECK
  // will catch this during lazy compilation).
  if (!v8_flags.wasm_lazy_validation && module->origin == kWasmOrigin) {
    DCHECK(!thrower->error());
    if (WasmError validation_error =
            ValidateFunctions(*native_module, kOnlyLazyFunctions)) {
      thrower->CompileFailed(std::move(validation_error));
      return;
    }
  }

  if (!compilation_state->failed()) {
    compilation_state->WaitForCompilationEvent(
        CompilationEvent::kFinishedBaselineCompilation);
  }

  if (compilation_state->failed()) {
    DCHECK_IMPLIES(IsLazyModule(module), !v8_flags.wasm_lazy_validation);
    WasmError validation_error =
        ValidateFunctions(*native_module, kAllFunctions);
    CHECK(validation_error.has_error());
    thrower->CompileFailed(std::move(validation_error));
  }
}

class BackgroundCompileJob final : public JobTask {
 public:
  explicit BackgroundCompileJob(std::weak_ptr<NativeModule> native_module,
                                std::shared_ptr<Counters> async_counters,
                                CompilationTier tier)
      : native_module_(std::move(native_module)),
        engine_barrier_(GetWasmEngine()->GetBarrierForBackgroundCompile()),
        async_counters_(std::move(async_counters)),
        tier_(tier) {}

  void Run(JobDelegate* delegate) override {
    auto engine_scope = engine_barrier_->TryLock();
    if (!engine_scope) return;
    ExecuteCompilationUnits(native_module_, async_counters_.get(), delegate,
                            tier_);
  }

  size_t GetMaxConcurrency(size_t worker_count) const override {
    BackgroundCompileScope compile_scope(native_module_);
    if (compile_scope.cancelled()) return 0;
    size_t flag_limit = static_cast<size_t>(
        std::max(1, v8_flags.wasm_num_compilation_tasks.value()));
    // NumOutstandingCompilations() does not reflect the units that running
    // workers are processing, thus add the current worker count to that number.
    return std::min(flag_limit,
                    worker_count + compile_scope.compilation_state()
                                       ->NumOutstandingCompilations(tier_));
  }

 private:
  std::weak_ptr<NativeModule> native_module_;
  std::shared_ptr<OperationsBarrier> engine_barrier_;
  const std::shared_ptr<Counters> async_counters_;
  const CompilationTier tier_;
};

std::shared_ptr<NativeModule> GetOrCompileNewNativeModule(
    Isolate* isolate, WasmEnabledFeatures enabled_features,
    WasmDetectedFeatures detected_features, CompileTimeImports compile_imports,
    ErrorThrower* thrower, std::shared_ptr<const WasmModule> module,
    ModuleWireBytes wire_bytes, int compilation_id,
    v8::metrics::Recorder::ContextId context_id, ProfileInformation* pgo_info) {
  base::OwnedVector<uint8_t> wire_bytes_copy =
      base::OwnedVector<uint8_t>::Of(wire_bytes.module_bytes());
  // Prefer {wire_bytes_copy} to {wire_bytes.module_bytes()} for the temporary
  // cache key. When we eventually install the module in the cache, the wire
  // bytes of the temporary key and the new key have the same base pointer and
  // we can skip the full bytes comparison.
  std::shared_ptr<NativeModule> native_module =
      GetWasmEngine()->MaybeGetNativeModule(module->origin,
                                            wire_bytes_copy.as_vector(),
                                            compile_imports, isolate);
  if (native_module) return native_module;

  // Otherwise compile a new NativeModule.
  std::optional<TimedHistogramScope> wasm_compile_module_time_scope;
  if (base::TimeTicks::IsHighResolution()) {
    wasm_compile_module_time_scope.emplace(SELECT_WASM_COUNTER(
        isolate->counters(), module->origin, wasm_compile, module_time));
  }

  const bool include_liftoff =
      module->origin == kWasmOrigin && v8_flags.liftoff;
  size_t code_size_estimate =
      wasm::WasmCodeManager::EstimateNativeModuleCodeSize(
          module.get(), include_liftoff,
          DynamicTiering{v8_flags.wasm_dynamic_tiering.value()});
  native_module = GetWasmEngine()->NewNativeModule(
      isolate, enabled_features, detected_features, std::move(compile_imports),
      module, code_size_estimate);
  native_module->SetWireBytes(std::move(wire_bytes_copy));
  native_module->compilation_state()->set_compilation_id(compilation_id);

  if (!v8_flags.wasm_jitless) {
    // Compile / validate the new module.
    CompileNativeModule(isolate, context_id, thrower, native_module, pgo_info);
  }

  if (thrower->error()) {
    GetWasmEngine()->UpdateNativeModuleCache(true, std::move(native_module),
                                             isolate);
    return {};
  }

  // Finally, put the new module in the cache; this can return the passed
  // NativeModule pointer, or another one (for a previously cached module).
  return GetWasmEngine()->UpdateNativeModuleCache(false, native_module,
                                                  isolate);
}

}  // namespace

std::shared_ptr<NativeModule> CompileToNativeModule(
    Isolate* isolate, WasmEnabledFeatures enabled_features,
    WasmDetectedFeatures detected_features, CompileTimeImports compile_imports,
    ErrorThrower* thrower, std::shared_ptr<const WasmModule> module,
    ModuleWireBytes wire_bytes, int compilation_id,
    v8::metrics::Recorder::ContextId context_id, ProfileInformation* pgo_info) {
  std::shared_ptr<NativeModule> native_module = GetOrCompileNewNativeModule(
      isolate, enabled_features, detected_features, std::move(compile_imports),
      thrower, module, wire_bytes, compilation_id, context_id, pgo_info);
  if (!native_module) return {};

  // Ensure that the code objects are logged before returning.
  GetWasmEngine()->LogOutstandingCodesForIsolate(isolate);

  // Now publish all detected features of this module in the current isolate.
  PublishDetectedFeatures(
      native_module->compilation_state()->detected_features(), isolate, true);

  return native_module;
}

AsyncCompileJob::AsyncCompileJob(
    Isolate* isolate, WasmEnabledFeatures enabled_features,
    CompileTimeImports compile_imports, base::OwnedVector<const uint8_t> bytes,
    DirectHandle<Context> context,
    DirectHandle<NativeContext> incumbent_context, const char* api_method_name,
    std::shared_ptr<CompilationResultResolver> resolver, int compilation_id)
    : isolate_(isolate),
      api_method_name_(api_method_name),
      enabled_features_(enabled_features),
      compile_imports_(std::move(compile_imports)),
      dynamic_tiering_(DynamicTiering{v8_flags.wasm_dynamic_tiering.value()}),
      start_time_(base::TimeTicks::Now()),
      bytes_copy_(std::move(bytes)),
      wire_bytes_(bytes_copy_.as_vector()),
      resolver_(std::move(resolver)),
      compilation_id_(compilation_id) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.wasm.detailed"),
               "wasm.AsyncCompileJob");
  CHECK(v8_flags.wasm_async_compilation);
  CHECK(!v8_flags.jitless || v8_flags.wasm_jitless);
  v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate);
  v8::Platform* platform = V8::GetCurrentPlatform();
  foreground_task_runner_ = platform->GetForegroundTaskRunner(v8_isolate);
  native_context_ =
      isolate->global_handles()->Create(context->native_context());
  incumbent_context_ = isolate->global_handles()->Create(*incumbent_context);
  DCHECK(IsNativeContext(*native_context_));
  context_id_ = isolate->GetOrRegisterRecorderContextId(native_context_);
  metrics_event_.async = true;
}

void AsyncCompileJob::Start() {
  DoAsync<DecodeModule>(isolate_->counters(),
                        isolate_->metrics_recorder());  // --
}

void AsyncCompileJob::Abort() {
  // Removing this job will trigger the destructor, which will cancel all
  // compilation.
  GetWasmEngine()->RemoveCompileJob(this);
}

// {ValidateFunctionsStreamingJobData} holds information that is shared between
// the {AsyncStreamingProcessor} and the {ValidateFunctionsStreamingJob}. It
// lives in the {AsyncStreamingProcessor} and is updated from both classes.
struct ValidateFunctionsStreamingJobData {
  struct Unit {
    // {func_index == -1} represents an "invalid" unit.
    int func_index = -1;
    base::Vector<const uint8_t> code;

    // Check whether the unit is valid.
    operator bool() const {
      DCHECK_LE(-1, func_index);
      return func_index >= 0;
    }
  };

  void Initialize(int num_declared_functions) {
    DCHECK_NULL(units);
    units = base::OwnedVector<Unit>::NewForOverwrite(num_declared_functions);
    // Initially {next == end}.
    next_available_unit.store(units.begin(), std::memory_order_relaxed);
    end_of_available_units.store(units.begin(), std::memory_order_relaxed);
  }

  void AddUnit(int declared_func_index, base::Vector<const uint8_t> code,
               JobHandle* job_handle) {
    DCHECK_NOT_NULL(units);
    // Write new unit to {*end}, then increment {end}. There is only one thread
    // adding new units, so no further synchronization needed.
    Unit* ptr = end_of_available_units.load(std::memory_order_relaxed);
    // Check invariant: {next <= end}.
    DCHECK_LE(next_available_unit.load(std::memory_order_relaxed), ptr);
    *ptr++ = {declared_func_index, code};
    // Use release semantics, so whoever loads this pointer (using acquire
    // semantics) sees all our previous stores.
    end_of_available_units.store(ptr, std::memory_order_release);
    size_t total_units_added = ptr - units.begin();
    // Periodically notify concurrency increase. This has overhead, so avoid
    // calling it too often. As long as threads are still running they will
    // continue processing new units anyway, and if background threads validate
    // faster than we can add units, then only notifying after increasingly long
    // delays is the right thing to do to avoid too many small validation tasks.
    // We notify on each power of two after 16 units, and every 16k units (just
    // to have *some* upper limit and avoiding to pile up too many units).
    // Additionally, notify after receiving the last unit of the module.
    if ((total_units_added >= 16 &&
         base::bits::IsPowerOfTwo(total_units_added)) ||
        (total_units_added % (16 * 1024)) == 0 || ptr == units.end()) {
      job_handle->NotifyConcurrencyIncrease();
    }
  }

  size_t NumOutstandingUnits() const {
    Unit* next = next_available_unit.load(std::memory_order_relaxed);
    Unit* end = end_of_available_units.load(std::memory_order_relaxed);
    DCHECK_LE(next, end);
    return end - next;
  }

  // Retrieve one unit to validate; returns an "invalid" unit if nothing is in
  // the queue.
  Unit GetUnit() {
    // Use an acquire load to synchronize with the store in {AddUnit}. All units
    // before this {end} are fully initialized and ready to execute.
    Unit* end = end_of_available_units.load(std::memory_order_acquire);
    Unit* next = next_available_unit.load(std::memory_order_relaxed);
    while (next < end) {
      if (next_available_unit.compare_exchange_weak(
              next, next + 1, std::memory_order_relaxed)) {
        return *next;
      }
      // Otherwise retry with updated {next} pointer.
    }
    return {};
  }

  void UpdateDetectedFeatures(WasmDetectedFeatures new_detected_features) {
    WasmDetectedFeatures old_features =
        detected_features.load(std::memory_order_relaxed);
    while (!detected_features.compare_exchange_weak(
        old_features, old_features | new_detected_features,
        std::memory_order_relaxed)) {
      // Retry with updated {old_features}.
    }
  }

  base::OwnedVector<Unit> units;
  std::atomic<Unit*> next_available_unit;
  std::atomic<Unit*> end_of_available_units;
  std::atomic<bool> found_error{false};
  std::atomic<WasmDetectedFeatures> detected_features;
};

class ValidateFunctionsStreamingJob final : public JobTask {
 public:
  ValidateFunctionsStreamingJob(const WasmModule* module,
                                WasmEnabledFeatures enabled_features,
                                ValidateFunctionsStreamingJobData* data)
      : module_(module), enabled_features_(enabled_features), data_(data) {}

  void Run(JobDelegate* delegate) override {
    TRACE_EVENT0("v8.wasm", "wasm.ValidateFunctionsStreaming");
    using Unit = ValidateFunctionsStreamingJobData::Unit;
    Zone validation_zone{GetWasmEngine()->allocator(), ZONE_NAME};
    WasmDetectedFeatures detected_features;
    while (Unit unit = data_->GetUnit()) {
      validation_zone.Reset();
      DecodeResult result = ValidateSingleFunction(
          &validation_zone, module_, unit.func_index, unit.code,
          enabled_features_, &detected_features);

      if (result.failed()) {
        data_->found_error.store(true, std::memory_order_relaxed);
        break;
      }
      // After validating one function, check if we should yield.
      if (delegate->ShouldYield()) break;
    }

    data_->UpdateDetectedFeatures(detected_features);
  }

  size_t GetMaxConcurrency(size_t worker_count) const override {
    return worker_count + data_->NumOutstandingUnits();
  }

 private:
  const WasmModule* const module_;
  const WasmEnabledFeatures enabled_features_;
  ValidateFunctionsStreamingJobData* data_;
};

class AsyncStreamingProcessor final : public StreamingProcessor {
 public:
  explicit AsyncStreamingProcessor(AsyncCompileJob* job);

  bool ProcessModuleHeader(base::Vector<const uint8_t> bytes) override;

  bool ProcessSection(SectionCode section_code,
                      base::Vector<const uint8_t> bytes,
                      uint32_t offset) override;

  bool ProcessCodeSectionHeader(int num_functions,
                                uint32_t functions_mismatch_error_offset,
                                std::shared_ptr<WireBytesStorage>,
                                int code_section_start,
                                int code_section_length) override;

  bool ProcessFunctionBody(base::Vector<const uint8_t> bytes,
                           uint32_t offset) override;

  void OnFinishedChunk() override;

  void OnFinishedStream(base::OwnedVector<const uint8_t> bytes,
                        bool after_error) override;

  void OnAbort() override;

  bool Deserialize(base::Vector<const uint8_t> wire_bytes,
                   base::Vector<const uint8_t> module_bytes) override;

 private:
  void CommitCompilationUnits();

  ModuleDecoder decoder_;
  AsyncCompileJob* job_;
  std::unique_ptr<CompilationUnitBuilder> compilation_unit_builder_;
  int num_functions_ = 0;
  bool prefix_cache_hit_ = false;
  bool before_code_section_ = true;
  ValidateFunctionsStreamingJobData validate_functions_job_data_;
  std::unique_ptr<JobHandle> validate_functions_job_handle_;

  // Running hash of the wire bytes up to code section size, but excluding the
  // code section itself. Used by the {NativeModuleCache} to detect potential
  // duplicate modules.
  size_t prefix_hash_ = 0;
};

std::shared_ptr<StreamingDecoder> AsyncCompileJob::CreateStreamingDecoder() {
  DCHECK_NULL(stream_);
  stream_ = StreamingDecoder::CreateAsyncStreamingDecoder(
      std::make_unique<AsyncStreamingProcessor>(this));
  return stream_;
}

AsyncCompileJob::~AsyncCompileJob() {
  // Note: This destructor always runs on the foreground thread of the isolate.
  background_task_manager_.CancelAndWait();
  // If initial compilation did not finish yet we can abort it.
  if (native_module_) {
    Impl(native_module_->compilation_state())
        ->CancelCompilation(CompilationStateImpl::kCancelInitialCompilation);
  }
  // Tell the streaming decoder that the AsyncCompileJob is not available
  // anymore.
  if (stream_) stream_->NotifyCompilationDiscarded();
  CancelPendingForegroundTask();
  isolate_->global_handles()->Destroy(native_context_.location());
  isolate_->global_handles()->Destroy(incumbent_context_.location());
  if (!module_object_.is_null()) {
    isolate_->global_handles()->Destroy(module_object_.location());
  }
}

void AsyncCompileJob::CreateNativeModule(
    std::shared_ptr<const WasmModule> module, size_t code_size_estimate) {
  // Embedder usage count for declared shared memories.
  const bool has_shared_memory =
      std::any_of(module->memories.begin(), module->memories.end(),
                  [](auto& memory) { return memory.is_shared; });
  if (has_shared_memory) {
    isolate_->CountUsage(v8::Isolate::UseCounterFeature::kWasmSharedMemory);
  }

  // Create the module object and populate with compiled functions and
  // information needed at instantiation time.

  native_module_ = GetWasmEngine()->NewNativeModule(
      isolate_, enabled_features_, detected_features_,
      std::move(compile_imports_), std::move(module), code_size_estimate);
  native_module_->SetWireBytes(std::move(bytes_copy_));
  native_module_->compilation_state()->set_compilation_id(compilation_id_);
}

bool AsyncCompileJob::GetOrCreateNativeModule(
    std::shared_ptr<const WasmModule> module, size_t code_size_estimate) {
  native_module_ = GetWasmEngine()->MaybeGetNativeModule(
      module->origin, wire_bytes_.module_bytes(), compile_imports_, isolate_);
  if (native_module_ == nullptr) {
    CreateNativeModule(std::move(module), code_size_estimate);
    return false;
  }
  return true;
}

void AsyncCompileJob::PrepareRuntimeObjects() {
  // Create heap objects for script and module bytes to be stored in the
  // module object. Asm.js is not compiled asynchronously.
  DCHECK(module_object_.is_null());
  auto source_url =
      stream_ ? base::VectorOf(stream_->url()) : base::Vector<const char>();
  auto script =
      GetWasmEngine()->GetOrCreateScript(isolate_, native_module_, source_url);
  DirectHandle<WasmModuleObject> module_object =
      WasmModuleObject::New(isolate_, native_module_, script);

  module_object_ = isolate_->global_handles()->Create(*module_object);
}

// This function assumes that it is executed in a HandleScope, and that a
// context is set on the isolate.
void AsyncCompileJob::FinishCompile(bool is_after_cache_hit) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.wasm.detailed"),
               "wasm.FinishAsyncCompile");
  if (stream_) {
    stream_->NotifyNativeModuleCreated(native_module_);
  }
  const WasmModule* module = native_module_->module();
  auto compilation_state = Impl(native_module_->compilation_state());

  // Update the compilation state with feature detected during module decoding
  // and (potentially) validation. We will publish all features below, in the
  // current isolate, so ignore the return value here.
  USE(compilation_state->UpdateDetectedFeatures(detected_features_));

  // If experimental PGO via files is enabled, load profile information now that
  // we have all wire bytes and know that the module is valid.
  if (V8_UNLIKELY(v8_flags.experimental_wasm_pgo_from_file)) {
    std::unique_ptr<ProfileInformation> pgo_info =
        LoadProfileFromFile(module, native_module_->wire_bytes());
    if (pgo_info) {
      compilation_state->ApplyPgoInfoLate(pgo_info.get());
    }
  }

  bool is_after_deserialization = !module_object_.is_null();
  if (!is_after_deserialization) {
    PrepareRuntimeObjects();
  }

  // Measure duration of baseline compilation or deserialization from cache.
  if (base::TimeTicks::IsHighResolution()) {
    base::TimeDelta duration = base::TimeTicks::Now() - start_time_;
    int duration_usecs = static_cast<int>(duration.InMicroseconds());
    isolate_->counters()->wasm_streaming_finish_wasm_module_time()->AddSample(
        duration_usecs);

    if (is_after_cache_hit || is_after_deserialization) {
      v8::metrics::WasmModuleCompiled event{
          true,                                     // async
          true,                                     // streamed
          is_after_cache_hit,                       // cached
          is_after_deserialization,                 // deserialized
          v8_flags.wasm_lazy_compilation,           // lazy
          !compilation_state->failed(),             // success
          native_module_->turbofan_code_size(),     // code_size_in_bytes
          native_module_->liftoff_bailout_count(),  // liftoff_bailout_count
          duration.InMicroseconds()};               // wall_clock_duration_in_us
      isolate_->metrics_recorder()->DelayMainThreadEvent(event, context_id_);
    }
  }

  DCHECK(!isolate_->context().is_null());
  // Finish the wasm script now and make it public to the debugger.
  DirectHandle<Script> script(module_object_->script(), isolate_);
  auto sourcemap_symbol =
      module->debug_symbols[WasmDebugSymbols::Type::SourceMap];
  if (script->type() == Script::Type::kWasm &&
      sourcemap_symbol.type != WasmDebugSymbols::Type::None &&
      !sourcemap_symbol.external_url.is_empty()) {
    ModuleWireBytes wire_bytes(native_module_->wire_bytes());
    MaybeHandle<String> src_map_str = isolate_->factory()->NewStringFromUtf8(
        wire_bytes.GetNameOrNull(sourcemap_symbol.external_url),
        AllocationType::kOld);
    script->set_source_mapping_url(*src_map_str.ToHandleChecked());
  }
  {
    TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.wasm.detailed"),
                 "wasm.Debug.OnAfterCompile");
    isolate_->debug()->OnAfterCompile(script);
  }

  // Publish the detected features in this isolate, once initial compilation
  // is done. Validate should have detected all features, unless lazy validation
  // is enabled.
  PublishDetectedFeatures(compilation_state->detected_features(), isolate_,
                          true);

  // We might need debug code for the module, if the debugger was enabled while
  // streaming compilation was running. Since handling this while compiling via
  // streaming is tricky, we just remove all code which may have been generated,
  // and compile debug code lazily.
  if (native_module_->IsInDebugState()) {
    WasmCodeRefScope ref_scope;
    native_module_->RemoveCompiledCode(
        NativeModule::RemoveFilter::kRemoveNonDebugCode);
  }

  // Finally, log all generated code (it does not matter if this happens
  // repeatedly in case the script is shared).
  native_module_->LogWasmCodes(isolate_, module_object_->script());

  FinishSuccessfully();
}

void AsyncCompileJob::Failed() {
  // {job} keeps the {this} pointer alive.
  std::unique_ptr<AsyncCompileJob> job =
      GetWasmEngine()->RemoveCompileJob(this);

  // Revalidate the whole module to produce a deterministic error message.
  constexpr bool kValidate = true;
  WasmDetectedFeatures unused_detected_features;
  ModuleResult result =
      DecodeWasmModule(enabled_features_, wire_bytes_.module_bytes(), kValidate,
                       kWasmOrigin, &unused_detected_features);
  ErrorThrower thrower(isolate_, api_method_name_);
  if (result.failed()) {
    thrower.CompileFailed(std::move(result).error());
  } else {
    // The only possible reason why {result} might be okay is if the failure
    // was due to compile-time imports checking.
    CHECK(!job->compile_imports_.empty());
    WasmError error = ValidateAndSetBuiltinImports(
        result.value().get(), wire_bytes_.module_bytes(), job->compile_imports_,
        &unused_detected_features);
    CHECK(error.has_error());
    thrower.CompileError("%s", error.message().c_str());
  }
  resolver_->OnCompilationFailed(thrower.Reify());
}

class AsyncCompileJob::CompilationStateCallback
    : public CompilationEventCallback {
 public:
  explicit CompilationStateCallback(AsyncCompileJob* job) : job_(job) {}

  void call(CompilationEvent event) override {
    // This callback is only being called from a foreground task.
    switch (event) {
      case CompilationEvent::kFinishedBaselineCompilation:
        DCHECK(!last_event_.has_value());
        if (job_->DecrementAndCheckFinisherCount()) {
          // Install the native module in the cache, or reuse a conflicting one.
          // If we get a conflicting module, wait until we are back in the
          // main thread to update {job_->native_module_} to avoid a data race.
          std::shared_ptr<NativeModule> cached_native_module =
              GetWasmEngine()->UpdateNativeModuleCache(
                  false, job_->native_module_, job_->isolate_);
          if (cached_native_module == job_->native_module_) {
            // There was no cached module.
            cached_native_module = nullptr;
          }
          job_->DoSync<FinishCompilation>(std::move(cached_native_module));
        }
        break;
      case CompilationEvent::kFinishedCompilationChunk:
        DCHECK(CompilationEvent::kFinishedBaselineCompilation == last_event_ ||
               CompilationEvent::kFinishedCompilationChunk == last_event_);
        break;
      case CompilationEvent::kFailedCompilation:
        DCHECK(!last_event_.has_value());
        if (job_->DecrementAndCheckFinisherCount()) {
          // Don't update {job_->native_module_} to avoid data races with other
          // compilation threads. Use a copy of the shared pointer instead.
          GetWasmEngine()->UpdateNativeModuleCache(true, job_->native_module_,
                                                   job_->isolate_);
          job_->DoSync<Fail>();
        }
        break;
    }
#ifdef DEBUG
    last_event_ = event;
#endif
  }

 private:
  AsyncCompileJob* job_;
#ifdef DEBUG
  // This will be modified by different threads, but they externally
  // synchronize, so no explicit synchronization (currently) needed here.
  std::optional<CompilationEvent> last_event_;
#endif
};

// A closure to run a compilation step (either as foreground or background
// task) and schedule the next step(s), if any.
class AsyncCompileJob::CompileStep {
 public:
  virtual ~CompileStep() = default;

  void Run(AsyncCompileJob* job, bool on_foreground) {
    if (on_foreground) {
      HandleScope scope(job->isolate_);
      SaveAndSwitchContext saved_context(job->isolate_, *job->native_context_);
      RunInForeground(job);
    } else {
      RunInBackground(job);
    }
  }

  virtual void RunInForeground(AsyncCompileJob*) { UNREACHABLE(); }
  virtual void RunInBackground(AsyncCompileJob*) { UNREACHABLE(); }
};

class AsyncCompileJob::CompileTask : public CancelableTask {
 public:
  CompileTask(AsyncCompileJob* job, bool on_foreground)
      // We only manage the background tasks with the {CancelableTaskManager} of
      // the {AsyncCompileJob}. Foreground tasks are managed by the system's
      // {CancelableTaskManager}. Background tasks cannot spawn tasks managed by
      // their own task manager.
      : CancelableTask(on_foreground ? job->isolate_->cancelable_task_manager()
                                     : &job->background_task_manager_),
        job_(job),
        on_foreground_(on_foreground) {}

  ~CompileTask() override {
    if (job_ != nullptr && on_foreground_) ResetPendingForegroundTask();
  }

  void RunInternal() final {
    if (!job_) return;
    if (on_foreground_) ResetPendingForegroundTask();
    job_->step_->Run(job_, on_foreground_);
    // After execution, reset {job_} such that we don't try to reset the pending
    // foreground task when the task is deleted.
    job_ = nullptr;
  }

  void Cancel() {
    DCHECK_NOT_NULL(job_);
    job_ = nullptr;
  }

 private:
  // {job_} will be cleared to cancel a pending task.
  AsyncCompileJob* job_;
  bool on_foreground_;

  void ResetPendingForegroundTask() const {
    DCHECK_EQ(this, job_->pending_foreground_task_);
    job_->pending_foreground_task_ = nullptr;
  }
};

void AsyncCompileJob::StartForegroundTask() {
  DCHECK_NULL(pending_foreground_task_);

  auto new_task = std::make_unique<CompileTask>(this, true);
  pending_foreground_task_ = new_task.get();
  foreground_task_runner_->PostTask(std::move(new_task));
}

void AsyncCompileJob::ExecuteForegroundTaskImmediately() {
  DCHECK_NULL(pending_foreground_task_);

  auto new_task = std::make_unique<CompileTask>(this, true);
  pending_foreground_task_ = new_task.get();
  new_task->Run();
}

void AsyncCompileJob::CancelPendingForegroundTask() {
  if (!pending_foreground_task_) return;
  pending_foreground_task_->Cancel();
  pending_foreground_task_ = nullptr;
}

void AsyncCompileJob::StartBackgroundTask() {
  auto task = std::make_unique<CompileTask>(this, false);

  // If --wasm-num-compilation-tasks=0 is passed, do only spawn foreground
  // tasks. This is used to make timing deterministic.
  if (v8_flags.wasm_num_compilation_tasks > 0) {
    V8::GetCurrentPlatform()->CallBlockingTaskOnWorkerThread(std::move(task));
  } else {
    foreground_task_runner_->PostTask(std::move(task));
  }
}

template <typename Step,
          AsyncCompileJob::UseExistingForegroundTask use_existing_fg_task,
          typename... Args>
void AsyncCompileJob::DoSync(Args&&... args) {
  NextStep<Step>(std::forward<Args>(args)...);
  if (use_existing_fg_task && pending_foreground_task_ != nullptr) return;
  StartForegroundTask();
}

template <typename Step, typename... Args>
void AsyncCompileJob::DoImmediately(Args&&... args) {
  NextStep<Step>(std::forward<Args>(args)...);
  ExecuteForegroundTaskImmediately();
}

template <typename Step, typename... Args>
void AsyncCompileJob::DoAsync(Args&&... args) {
  NextStep<Step>(std::forward<Args>(args)...);
  StartBackgroundTask();
}

template <typename Step, typename... Args>
void AsyncCompileJob::NextStep(Args&&... args) {
  step_.reset(new Step(std::forward<Args>(args)...));
}

//==========================================================================
// Step 1: (async) Decode the module.
//==========================================================================
class AsyncCompileJob::DecodeModule : public AsyncCompileJob::CompileStep {
 public:
  explicit DecodeModule(Counters* counters,
                        std::shared_ptr<metrics::Recorder> metrics_recorder)
      : counters_(counters), metrics_recorder_(std::move(metrics_recorder)) {}

  void RunInBackground(AsyncCompileJob* job) override {
    ModuleResult result;
    {
      DisallowHandleAllocation no_handle;
      DisallowGarbageCollection no_gc;
      // Decode the module bytes.
      TRACE_COMPILE("(1) Decoding module...\n");
      TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.wasm.detailed"),
                   "wasm.DecodeModule");
      auto enabled_features = job->enabled_features_;
      result = DecodeWasmModule(
          enabled_features, job->wire_bytes_.module_bytes(), false, kWasmOrigin,
          counters_, metrics_recorder_, job->context_id(),
          DecodingMethod::kAsync, &job->detected_features_);

      // Validate lazy functions here if requested.
      if (result.ok() && !v8_flags.wasm_lazy_validation) {
        const WasmModule* module = result.value().get();
        if (WasmError validation_error = ValidateFunctions(
                module, job->wire_bytes_.module_bytes(), job->enabled_features_,
                kOnlyLazyFunctions, &job->detected_features_)) {
          result = ModuleResult{std::move(validation_error)};
        }
      }
      if (result.ok()) {
        const WasmModule* module = result.value().get();
        if (WasmError error = ValidateAndSetBuiltinImports(
                module, job->wire_bytes_.module_bytes(), job->compile_imports_,
                &job->detected_features_)) {
          result = ModuleResult{std::move(error)};
        }
      }
    }
    if (result.failed()) {
      // Decoding failure; reject the promise and clean up.
      job->DoSync<Fail>();
    } else {
      // Decode passed.
      std::shared_ptr<WasmModule> module = std::move(result).value();
      const bool include_liftoff = v8_flags.liftoff;
      size_t code_size_estimate =
          wasm::WasmCodeManager::EstimateNativeModuleCodeSize(
              module.get(), include_liftoff, job->dynamic_tiering_);
      job->DoSync<PrepareAndStartCompile>(
          std::move(module), true /* start_compilation */,
          true /* lazy_functions_are_validated */, code_size_estimate);
    }
  }

 private:
  Counters* const counters_;
  std::shared_ptr<metrics::Recorder> metrics_recorder_;
};

//==========================================================================
// Step 2 (sync): Create heap-allocated data and start compilation.
//==========================================================================
class AsyncCompileJob::PrepareAndStartCompile : public CompileStep {
 public:
  PrepareAndStartCompile(std::shared_ptr<const WasmModule> module,
                         bool start_compilation,
                         bool lazy_functions_are_validated,
                         size_t code_size_estimate)
      : module_(std::move(module)),
        start_compilation_(start_compilation),
        lazy_functions_are_validated_(lazy_functions_are_validated),
        code_size_estimate_(code_size_estimate) {}

 private:
  void RunInForeground(AsyncCompileJob* job) override {
    TRACE_COMPILE("(2) Prepare and start compile...\n");

    const bool streaming = job->wire_bytes_.length() == 0;
    if (streaming) {
      // Streaming compilation already checked for cache hits.
      job->CreateNativeModule(module_, code_size_estimate_);
    } else if (job->GetOrCreateNativeModule(std::move(module_),
                                            code_size_estimate_)) {
      job->FinishCompile(true);
      return;
    } else if (!lazy_functions_are_validated_) {
      // If we are not streaming and did not get a cache hit, we might have hit
      // the path where the streaming decoder got a prefix cache hit, but the
      // module then turned out to be invalid, and we are running it through
      // non-streaming decoding again. In this case, function bodies have not
      // been validated yet (would have happened in the {DecodeModule} phase
      // if we would not come via the non-streaming path). Thus do this now.
      // Note that we only need to validate lazily compiled functions, others
      // will be validated during eager compilation.
      DCHECK(start_compilation_);
      if (!v8_flags.wasm_lazy_validation &&
          ValidateFunctions(*job->native_module_, kOnlyLazyFunctions)
              .has_error()) {
        job->Failed();
        return;
      }
    }

    // Make sure all compilation tasks stopped running. Decoding (async step)
    // is done.
    job->background_task_manager_.CancelAndWait();

    CompilationStateImpl* compilation_state =
        Impl(job->native_module_->compilation_state());
    compilation_state->AddCallback(
        std::make_unique<CompilationStateCallback>(job));
    if (base::TimeTicks::IsHighResolution()) {
      auto compile_mode = job->stream_ == nullptr
                              ? CompilationTimeCallback::kAsync
                              : CompilationTimeCallback::kStreaming;
      compilation_state->AddCallback(std::make_unique<CompilationTimeCallback>(
          job->isolate_->async_counters(), job->isolate_->metrics_recorder(),
          job->context_id_, job->native_module_, compile_mode));
    }

    if (start_compilation_) {
      // TODO(13209): Use PGO for async compilation, if available.
      constexpr ProfileInformation* kNoProfileInformation = nullptr;
      std::unique_ptr<CompilationUnitBuilder> builder = InitializeCompilation(
          job->isolate(), job->native_module_.get(), kNoProfileInformation);
      compilation_state->InitializeCompilationUnits(std::move(builder));
      // In single-threaded mode there are no worker tasks that will do the
      // compilation. We call {WaitForCompilationEvent} here so that the main
      // thread participates and finishes the compilation.
      if (v8_flags.wasm_num_compilation_tasks == 0 || v8_flags.wasm_jitless) {
        compilation_state->WaitForCompilationEvent(
            CompilationEvent::kFinishedBaselineCompilation);
      }
    }
  }

  const std::shared_ptr<const WasmModule> module_;
  const bool start_compilation_;
  const bool lazy_functions_are_validated_;
  const size_t code_size_estimate_;
};

//==========================================================================
// Step 3 (sync): Compilation finished.
//==========================================================================
class AsyncCompileJob::FinishCompilation : public CompileStep {
 public:
  explicit FinishCompilation(std::shared_ptr<NativeModule> cached_native_module)
      : cached_native_module_(std::move(cached_native_module)) {}

 private:
  void RunInForeground(AsyncCompileJob* job) override {
    TRACE_COMPILE("(3) Compilation finished\n");
    if
```