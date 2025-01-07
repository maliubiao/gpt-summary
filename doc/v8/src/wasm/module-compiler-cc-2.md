Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The user wants a comprehensive description of the `v8/src/wasm/module-compiler.cc` file, focusing on its functionalities, potential JavaScript connections, logic inferences, common programming errors, and a concise summary. The user also provided specific instructions about how to identify Torque files.

2. **Initial Assessment of the Code Snippet:** I quickly scanned the provided C++ code. Key observations:
    * It's definitely C++, not Torque (`.tq` extension is mentioned as the indicator for Torque).
    * It deals with WebAssembly (`wasm` namespace, `WasmModule`, `ExecutionTier`, etc.).
    * It involves compilation stages (`Liftoff`, `Turbofan`).
    * There's logic for tiering up (optimizing) WebAssembly functions.
    * It interacts with V8's infrastructure (`Isolate`, `Counters`, `metrics::Recorder`).
    * It handles feature detection and usage counting.
    * It validates imported functions.
    * It manages background compilation tasks.

3. **Break Down the Functionalities:** I went through the code block by block, identifying the purpose of each function or significant code section:
    * **`AddCompilationUnit`:**  Adds a unit of work (compiling a function) to a queue, with prioritization and type feedback processing.
    * **`TierUpNowForTesting` and `TierUpAllForTesting`:** Force immediate compilation of specific or all functions for testing purposes.
    * **`InitializeCompilationForTesting`:** Sets up the compilation process for testing.
    * **`PublishDetectedFeatures`:** Records which WebAssembly features are used in the module using V8's usage counters. This is crucial for understanding real-world usage and informing feature prioritization.
    * **`IsI16Array` and `IsI8Array`:** Helper functions to check the type of array parameters, likely used for validating built-in function signatures.
    * **`ImportStartOffset`:** A utility to find the starting offset of an import declaration in the raw byte stream, important for accurate error reporting.
    * **`ValidateAndSetBuiltinImports`:** A significant function that checks the signatures of imported functions with specific "wasm:" prefixes (like "wasm:js-string" or "wasm:text-encoder"). This is how V8 connects WebAssembly to JavaScript's built-in functionalities.
    * **`ExecuteCompilationUnits`:** The core logic for actually running the compilation process, likely in background threads. It manages a queue of compilation units, executes them, and publishes the results.
    * **`InitializeCompilation`:** Sets up the initial state for compilation.
    * **`MayCompriseLazyFunctions`:** Determines if a module might contain functions that are compiled on-demand (lazily).
    * **`CompilationTimeCallback`:** A callback to record compilation timing metrics, used for performance analysis.
    * **`ValidateFunctions` (two versions):**  Performs validation of the WebAssembly functions' code and structure.
    * **`CompileNativeModule`:** The main entry point for initiating the compilation of a WebAssembly module.
    * **`BackgroundCompileJob`:** A task that can be run in a background thread to perform compilation.
    * **`GetOrCompileNewNativeModule`:** Checks if a module has already been compiled (and cached) or needs to be compiled from scratch.

4. **JavaScript Connections:** The `ValidateAndSetBuiltinImports` function is the key area connecting to JavaScript. I specifically looked for the `"wasm:js-string"` and `"wasm:text-encoder"` prefixes. This immediately tells me that WebAssembly modules can import functions that interact with JavaScript strings and the Text Encoder/Decoder APIs. I then crafted JavaScript examples illustrating how these imported functions could be used from the WebAssembly side. I focused on practical examples, like converting between WebAssembly memory and JavaScript strings.

5. **Logic Inference (Hypothetical Input/Output):**  For `AddCompilationUnit`, I imagined a scenario where a function needed to be compiled. The input would be the function index and its priority. The output would be adding this compilation task to the appropriate queue. For `ValidateAndSetBuiltinImports`, a good example would be a WebAssembly module importing `wasm:js-string:length`. The input is the module's import table; the output is validation of the signature and potentially marking it as a `WellKnownImport`.

6. **Common Programming Errors:** I thought about what could go wrong in WebAssembly development that this code might address. Incorrect import signatures are a common mistake. I created an example of a WebAssembly module importing a function with a mismatched signature to demonstrate this.

7. **Torque Check:** The prompt explicitly asked about the `.tq` extension. I confirmed that the provided code is `.cc` (C++) and therefore *not* a Torque file.

8. **Summary:**  I synthesized the key functionalities into a concise summary, focusing on the major roles of the `module-compiler.cc` file within the V8 WebAssembly compilation pipeline.

9. **Structure and Formatting:** I organized the information into clear sections as requested by the user, using headings and bullet points for readability. I made sure to address each specific requirement of the prompt.

10. **Review and Refine:** I reread my answer to ensure accuracy, clarity, and completeness, checking that it directly addressed all parts of the user's request. I paid attention to terminology and made sure to use accurate WebAssembly and V8 vocabulary.
好的，这是对 `v8/src/wasm/module-compiler.cc` 代码片段的功能进行分析和归纳：

**文件类型判断：**

*   `v8/src/wasm/module-compiler.cc` 以 `.cc` 结尾，表明它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件。

**功能列举：**

这段代码片段主要负责 WebAssembly 模块的 **编译管理和优化**。具体功能包括：

1. **管理编译单元 (Compilation Units):**
    *   `AddCompilationUnit`:  负责向编译队列添加需要编译的 WebAssembly 函数。
    *   它允许在添加编译单元时指定优先级 (`priority`)，以便 V8 可以优先编译更重要的函数。
    *   它还处理 **类型反馈 (Type Feedback)**，用于改进代码生成。如果启用了内联 (`v8_flags.wasm_inlining`)，它会使用 `TransitiveTypeFeedbackProcessor` 来处理类型反馈信息，这有助于后续的优化编译。

2. **按需触发编译 (Tier-Up):**
    *   `TierUpNowForTesting`:  用于测试目的，立即将指定的 WebAssembly 函数提升到更高的优化层级（通常是 TurboFan）。
    *   `TierUpAllForTesting`:  用于测试目的，将模块中的所有声明的 WebAssembly 函数提升到更高的优化层级。

3. **初始化编译 (Initialize Compilation):**
    *   `InitializeCompilationForTesting`:  用于测试目的，初始化模块的编译进度。

4. **发布检测到的特性 (Publish Detected Features):**
    *   `PublishDetectedFeatures`:  记录 WebAssembly 模块中使用的各种特性（例如，共享内存、引用类型、SIMD 等）。
    *   它使用 V8 的 `Isolate::CountUsage` 机制来统计这些特性的使用情况，这对于 V8 团队了解 WebAssembly 特性的采用情况非常重要。
    *   它还会根据检测到的特性，在某些情况下输出警告信息（例如，使用了 relaxed-simd，这可能导致跨架构比较结果不一致）。

5. **辅助函数 (Helper Functions):**
    *   `IsI16Array`, `IsI8Array`: 检查 ValueType 是否为特定的数组类型 (i16 或 i8)。这通常用于验证导入函数的签名。
    *   `ImportStartOffset`:  用于计算导入声明在字节码中的起始偏移量，用于生成更精确的错误消息。

6. **验证和设置内置导入 (Validate and Set Builtin Imports):**
    *   `ValidateAndSetBuiltinImports`:  验证导入的函数签名是否与 V8 预期的签名一致，特别是针对那些以 `"wasm:"` 开头的特殊导入（例如，与 JavaScript 字符串操作相关的导入）。
    *   它将验证通过的内置导入标记为 `WellKnownImport`，以便 V8 可以进行特殊处理。

7. **执行编译单元 (Execute Compilation Units):**
    *   `ExecuteCompilationUnits`:  负责执行实际的 WebAssembly 函数编译工作，通常在后台线程中进行。
    *   它管理编译队列，获取编译单元，调用相应的编译器 (`Liftoff` 或 `TurboFan`)，并发布编译结果。
    *   它还处理编译失败的情况。

8. **初始化编译 (Initialize Compilation - 更通用版本):**
    *   `InitializeCompilation`:  更通用的版本，用于初始化模块的编译，创建 `CompilationUnitBuilder`。

9. **判断是否包含延迟编译函数 (May Comprise Lazy Functions):**
    *   `MayCompriseLazyFunctions`:  判断模块是否可能包含需要延迟编译的函数。

10. **编译时间回调 (Compilation Time Callback):**
    *   `CompilationTimeCallback`:  一个回调类，用于记录 WebAssembly 模块的编译时间，以便进行性能分析。

11. **验证函数 (Validate Functions):**
    *   `ValidateFunctions`:  验证 WebAssembly 模块中的函数定义是否符合规范。可以只验证延迟编译的函数，也可以验证所有函数。

12. **编译原生模块 (Compile Native Module):**
    *   `CompileNativeModule`:  主函数，用于启动 WebAssembly 模块的同步编译过程。它会初始化编译单元，并等待基线编译完成。如果发生错误，它会进行完整的验证并抛出异常。

13. **后台编译任务 (Background Compile Job):**
    *   `BackgroundCompileJob`:  一个可以作为后台任务运行的类，用于执行 WebAssembly 模块的异步编译。

14. **获取或编译新的原生模块 (Get Or Compile New Native Module):**
    *   `GetOrCompileNewNativeModule`:  尝试从缓存中获取已编译的 `NativeModule`，如果不存在，则启动新的编译过程。

**与 JavaScript 的关系及示例：**

`v8/src/wasm/module-compiler.cc` 中与 JavaScript 功能关系最密切的部分是 `ValidateAndSetBuiltinImports` 函数。它允许 WebAssembly 模块导入一些与 JavaScript 交互的内置函数。

**JavaScript 示例：**

假设一个 WebAssembly 模块导入了 `wasm:js-string:length` 函数，用于获取 JavaScript 字符串的长度。

```javascript
// JavaScript 代码
const wasmCode = `
  (module
    (import "wasm:js-string" "length" (func $string_length (param (ref null extern)) (result i32)))
    (func (export "getStringLength") (param (ref null extern)) (result i32)
      local.get 0
      call $string_length
    )
  )
`;

const wasmModule = new WebAssembly.Module(Uint8Array.from(atob(wasmCode), c => c.charCodeAt(0)));
const wasmInstance = new WebAssembly.Instance(wasmModule, {
  "wasm:js-string": {
    "length": (str) => {
      if (str === null) return 0;
      return String(str).length;
    }
  }
});

const jsString = "Hello";
const length = wasmInstance.exports.getStringLength(jsString);
console.log(length); // 输出: 5
```

在这个例子中，WebAssembly 模块声明了一个导入函数 `string_length`，它对应于 JavaScript 环境中 `wasm:js-string` 模块的 `length` 导出。当 WebAssembly 代码调用这个导入函数时，实际上会调用 JavaScript 提供的实现。

**代码逻辑推理及假设输入输出：**

**场景：`AddCompilationUnit`**

*   **假设输入:**
    *   `tiering_unit`: 一个表示要编译的 WebAssembly 函数的结构体，例如包含函数索引。
    *   `priority`:  一个整数，表示编译的优先级，例如 `1` (高优先级) 或 `0` (普通优先级)。
    *   假设 `v8_flags.wasm_inlining` 为 `true`，并且存在一些类型反馈数据。
    *   `func_index`: 要编译的函数的索引，例如 `5`。
    *   `trusted_instance_data`:  包含模块实例数据的对象。

*   **代码逻辑推理:**
    1. 检查 `v8_flags.wasm_inlining` 是否为真。
    2. 如果为真，调用 `TransitiveTypeFeedbackProcessor::Process`，使用 `trusted_instance_data` 和 `func_index` 来处理类型反馈。
    3. 调用 `compilation_state->AddTopTierPriorityCompilationUnit`，将 `tiering_unit` 和 `priority` 添加到编译队列中。

*   **假设输出:**  函数索引为 `5` 的编译单元被添加到编译队列中，并且可能已经根据类型反馈进行了优化标记。

**用户常见的编程错误：**

在与 `v8/src/wasm/module-compiler.cc` 相关的上下文中，用户常见的编程错误通常发生在 WebAssembly 模块的编写和导入配置上：

1. **导入函数签名不匹配:**  WebAssembly 模块声明的导入函数签名与 JavaScript 提供的实现签名不一致。

    ```javascript
    // WebAssembly (错误的签名)
    const wasmCodeBadImport = `
      (module
        (import "host" "add" (func $add (param i32) (result i32))) ;; 缺少一个参数
        (func (export "callAdd") (param i32) (result i32)
          local.get 0
          call $add
        )
      )
    `;

    // JavaScript
    const jsImports = {
      host: {
        add: (a, b) => a + b // JavaScript 实现需要两个参数
      }
    };

    // 这将导致实例化错误
    try {
      const badModule = new WebAssembly.Module(Uint8Array.from(atob(wasmCodeBadImport), c => c.charCodeAt(0)));
      const badInstance = new WebAssembly.Instance(badModule, jsImports);
    } catch (e) {
      console.error("Error:", e); // 输出错误信息，指示导入签名不匹配
    }
    ```

2. **导入模块或导出名称错误:**  在 JavaScript 中提供的导入对象中，模块名或导出名与 WebAssembly 模块中声明的导入不一致。

    ```javascript
    // WebAssembly
    const wasmCodeWrongName = `
      (module
        (import "my_module" "my_function" (func $my_func (param i32) (result i32)))
        (func (export "callFunc") (param i32) (result i32)
          local.get 0
          call $my_func
        )
      )
    `;

    // JavaScript (错误的模块名)
    const jsImportsWrongName = {
      "other_module": { // 模块名不匹配
        "my_function": (x) => x * 2
      }
    };

    try {
      const wrongNameModule = new WebAssembly.Module(Uint8Array.from(atob(wasmCodeWrongName), c => c.charCodeAt(0)));
      const wrongNameInstance = new WebAssembly.Instance(wrongNameModule, jsImportsWrongName);
    } catch (e) {
      console.error("Error:", e); // 输出错误信息，指示找不到导入
    }
    ```

**功能归纳（第 3 部分，共 6 部分）：**

作为 WebAssembly 编译流程的第三部分，`v8/src/wasm/module-compiler.cc` 的这段代码主要负责 **编译任务的管理和优化**。它接收需要编译的 WebAssembly 函数，根据优先级和类型反馈信息进行处理，并将编译任务添加到队列中。此外，它还处理测试场景下的强制编译，并负责记录模块中使用的 WebAssembly 特性。一个重要的功能是验证和设置内置的导入函数，这使得 WebAssembly 能够与 JavaScript 环境进行互操作。总而言之，这部分代码是 V8 WebAssembly 引擎中负责高效、正确编译 WebAssembly 代码的关键组件。

Prompt: 
```
这是目录为v8/src/wasm/module-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/module-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能

"""


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
        isol
"""


```