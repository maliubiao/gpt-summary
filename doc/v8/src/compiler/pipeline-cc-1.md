Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/pipeline.cc`.

Here's a breakdown of the request and how to address it:

1. **Identify the core functionality:** The code is part of the V8 compiler pipeline, specifically dealing with optimization and code generation.
2. **List key actions:** Go through the code and identify the major steps involved, like optimizing the Turboshaft graph, generating code, and finalizing the job.
3. **Address the `.tq` question:**  Confirm that the code is C++ and not Torque based on the file extension.
4. **Look for JavaScript relevance:**  Scan for mentions of JavaScript concepts or operations. Note that this section focuses on compiler internals, so direct JS examples might be limited. However, the entire process is *for* JavaScript execution.
5. **Code logic and inference:**  Focus on the `PipelineCompilationJob::OptimizeGraph` and `PipelineCompilationJob::FinalizeJobImpl` methods. Analyze the conditional logic and return values.
6. **Common programming errors:** Think about what could go wrong in a compilation pipeline. Bailouts and retries due to various reasons (code generation failure, detached context, deprecated maps, dependency changes) are mentioned.
7. **Part 2 of 6:** Emphasize that this is a continuation and build upon the previous parts (although we don't have them).

**Mental Sandbox:**

* **Direct JS example:** While the code is compiler-specific, the *purpose* is to optimize JavaScript. A simple JS function could be used to illustrate what this pipeline works on.
* **Code logic inference:**  Focus on the `if` conditions and the return values (`FAILED`, `SUCCEEDED`, `AbortOptimization`, `RetryOptimization`).
* **Common errors:** The bail-out reasons in `FinalizeJobImpl` directly point to potential issues.

**Constraint Checklist & Confidence Score:**

* 列举一下它的功能: Yes
* 如果v8/src/compiler/pipeline.cc以.tq结尾，那它是个v8 torque源代码: Yes
* 如果它与javascript的功能有关系，请用javascript举例说明: Yes
* 如果有代码逻辑推理，请给出假设输入与输出: Yes
* 如果涉及用户常见的编程错误，请举例说明: Yes
* 这是第2部分，共6部分，请归纳一下它的功能: Yes

Confidence Score: 5/5

Strategizing complete. I will now generate the response based on the identified functionalities, the provided constraints, and the insights gained from the mental sandbox.
这是 `v8/src/compiler/pipeline.cc` 源代码的第二部分，主要功能集中在执行优化图和最终生成代码的步骤，并处理编译作业的最终化。

**功能归纳:**

这部分代码主要负责以下功能：

1. **优化 Turboshaft 图 (Optimize Turboshaft Graph):**
   - 调用 `turboshaft_pipeline.OptimizeTurboshaftGraph(linkage_)` 对使用 Turboshaft 编译器构建的图进行优化。
   - 如果优化失败，则返回 `FAILED` 状态。

2. **生成代码 (Generate Code):**
   - 根据是否启用了 Turboshaft 指令选择（`v8_flags.turboshaft_instruction_selection`），调用 `GenerateCodeFromTurboshaftGraph` 函数来基于优化后的图生成机器码。
   - 该函数接收 Turboshaft pipeline、传统的 pipeline 对象、以及 OSR (On-Stack Replacement) 辅助指针作为参数。
   - 如果代码生成成功，则返回 `SUCCEEDED`，否则返回 `FAILED`。

3. **最终化编译作业 (Finalize Job):**
   - `FinalizeJobImpl` 函数负责编译作业的最终处理，包括：
     - **获取生成的代码:** 调用 `turboshaft_pipeline.FinalizeCode()` (如果使用了 Turboshaft 指令选择) 或 `pipeline_.FinalizeCode()` 获取最终生成的机器码。
     - **处理代码生成失败:** 如果代码生成失败，且之前没有设置失败原因，则调用 `AbortOptimization` 并设置 `BailoutReason::kCodeGenerationFailed`。
     - **检查 NativeContext:** 确保代码关联的 NativeContext 没有被 detached，如果 detached 则调用 `AbortOptimization` 并设置 `BailoutReason::kDetachedNativeContext`。
     - **检查废弃的 Map:** 调用 `CheckNoDeprecatedMaps` 检查生成的代码是否引用了已废弃的 Map，如果存在则调用 `RetryOptimization` 并设置 `BailoutReason::kConcurrentMapDeprecation`。
     - **提交依赖 (Commit Dependencies):** 调用 `turboshaft_pipeline.CommitDependencies(code)` 或 `pipeline_.CommitDependencies(code)` 提交代码的依赖关系。如果提交失败，则调用 `RetryOptimization` 并设置 `BailoutReason::kBailedOutDueToDependencyChange`。
     - **设置编译结果:** 将生成的代码 (`code`) 设置到 `compilation_info()` 中。
     - **收集保留的 Map:** 调用 `CollectRetainedMaps` 收集代码中引用的 Map。
     - **注册弱对象:** 调用 `RegisterWeakObjectsInOptimizedCode` 注册优化的代码中的弱对象。
     - 最终返回 `SUCCEEDED` 或 `FAILED` 状态。

**关于 .tq 结尾的文件:**

如果 `v8/src/compiler/pipeline.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**。但这部分代码的扩展名是 `.cc`，表明它是 **C++ 源代码**。Torque 用于定义 V8 内部的运行时函数和一些底层的操作。

**与 JavaScript 的关系及示例:**

这段代码是 V8 编译器管道的一部分，负责将 JavaScript 代码编译成高效的机器码。虽然这段 C++ 代码本身不包含 JavaScript 代码，但它的执行是为了优化和生成 JavaScript 代码。

**JavaScript 示例:**

假设有以下简单的 JavaScript 函数：

```javascript
function add(a, b) {
  return a + b;
}
```

当 V8 尝试优化这个函数时，`v8/src/compiler/pipeline.cc` 中的代码就会被执行。Turboshaft 优化器可能会分析 `a` 和 `b` 的类型，如果能确定它们是数字，就可以生成更高效的加法指令，而不是通用的加法操作。最终生成的机器码将直接执行 `a + b` 的操作。

**代码逻辑推理:**

**假设输入:**

* `turboshaft_pipeline.OptimizeTurboshaftGraph(linkage_)` 返回 `true` (优化成功)。
* `v8_flags.turboshaft_instruction_selection` 为 `true`。
* `GenerateCodeFromTurboshaftGraph` 函数成功生成代码。
* `pipeline_.FinalizeCode()` 成功生成代码。
* `compilation_info()->native_context()` 指向一个有效的、未 detached 的 NativeContext。
* `CheckNoDeprecatedMaps(code, isolate)` 返回 `true`。
* `turboshaft_pipeline.CommitDependencies(code)` 或 `pipeline_.CommitDependencies(code)` 返回 `true`。

**输出:**

* `PipelineCompilationJob::OptimizeGraph` 返回 `SUCCEEDED`。
* `PipelineCompilationJob::FinalizeJobImpl` 返回 `SUCCEEDED`，并将生成的代码设置到 `compilation_info()` 中。

**假设输入 (失败情况):**

* `turboshaft_pipeline.OptimizeTurboshaftGraph(linkage_)` 返回 `false` (优化失败)。

**输出:**

* `PipelineCompilationJob::OptimizeGraph` 返回 `FAILED`。后续的代码生成和最终化步骤不会执行。

**涉及用户常见的编程错误:**

虽然这段代码是编译器内部的，但它处理的一些情况与用户可能遇到的编程错误间接相关：

1. **类型错误:** 如果 JavaScript 代码中的变量类型不一致，或者发生了意外的类型转换，编译器可能难以优化，甚至导致优化失败。例如：

   ```javascript
   function combine(a, b) {
     return a + b; // 如果 a 是数字，b 是字符串，会发生隐式类型转换
   }
   ```

2. **使用已废弃的特性:**  虽然用户不会直接操作 V8 的 Map，但如果 JavaScript 代码依赖于一些 V8 内部实现细节（这种情况比较少见），而这些实现细节涉及到 Map 的结构变化，可能会导致编译器生成依赖于已废弃 Map 的代码，从而触发 `RetryOptimization(BailoutReason::kConcurrentMapDeprecation)`。

3. **并发问题和依赖变更:** 在复杂的 JavaScript 应用中，对象的结构和属性可能会在编译期间发生变化。如果编译器依赖于某个对象的特定结构，而这个结构在编译过程中被其他线程修改，就会导致 `RetryOptimization(BailoutReason::kBailedOutDueToDependencyChange)`。

4. ** detached 的 NativeContext:** 这通常发生在一些高级用法中，例如在扩展或嵌入 V8 的场景下，如果 NativeContext 被意外地分离，会导致编译失败。这通常不是用户常见的直接编程错误，而是与 V8 的生命周期管理有关。

总而言之，这部分 `v8/src/compiler/pipeline.cc` 代码是 V8 编译器优化的核心组成部分，负责将高级的中间表示转换为可执行的机器码，并处理编译过程中可能出现的各种情况和错误。

### 提示词
```
这是目录为v8/src/compiler/pipeline.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/pipeline.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
}

  if (!turboshaft_pipeline.OptimizeTurboshaftGraph(linkage_)) {
    return FAILED;
  }

#ifdef TARGET_SUPPORTS_TURBOSHAFT_INSTRUCTION_SELECTION
  bool use_turboshaft_instruction_selection =
      v8_flags.turboshaft_instruction_selection;
#else
  bool use_turboshaft_instruction_selection = false;
#endif

  const bool success = GenerateCodeFromTurboshaftGraph(
      use_turboshaft_instruction_selection, linkage_, turboshaft_pipeline,
      &pipeline_, data_.osr_helper_ptr());
  return success ? SUCCEEDED : FAILED;
}

PipelineCompilationJob::Status PipelineCompilationJob::FinalizeJobImpl(
    Isolate* isolate) {
  // Ensure that the RuntimeCallStats table of main thread is available for
  // phases happening during PrepareJob.
  PipelineJobScope scope(&data_, isolate->counters()->runtime_call_stats());
  RCS_SCOPE(isolate, RuntimeCallCounterId::kOptimizeFinalizePipelineJob);
  Handle<Code> code;
  DirectHandle<NativeContext> context;
#ifdef TARGET_SUPPORTS_TURBOSHAFT_INSTRUCTION_SELECTION
  if (v8_flags.turboshaft_instruction_selection) {
    turboshaft::Pipeline turboshaft_pipeline(&turboshaft_data_);
    MaybeHandle<Code> maybe_code = turboshaft_pipeline.FinalizeCode();
    if (!maybe_code.ToHandle(&code)) {
      if (compilation_info()->bailout_reason() == BailoutReason::kNoReason) {
        return AbortOptimization(BailoutReason::kCodeGenerationFailed);
      }
      return FAILED;
    }
    context =
        Handle<NativeContext>(compilation_info()->native_context(), isolate);
    if (context->IsDetached()) {
      return AbortOptimization(BailoutReason::kDetachedNativeContext);
    }
    if (!CheckNoDeprecatedMaps(code, isolate)) {
      return RetryOptimization(BailoutReason::kConcurrentMapDeprecation);
    }
    if (!turboshaft_pipeline.CommitDependencies(code)) {
      return RetryOptimization(BailoutReason::kBailedOutDueToDependencyChange);
    }
  } else {
#endif
    MaybeHandle<Code> maybe_code = pipeline_.FinalizeCode();
    if (!maybe_code.ToHandle(&code)) {
      if (compilation_info()->bailout_reason() == BailoutReason::kNoReason) {
        return AbortOptimization(BailoutReason::kCodeGenerationFailed);
      }
      return FAILED;
    }
    context =
        Handle<NativeContext>(compilation_info()->native_context(), isolate);
    if (context->IsDetached()) {
      return AbortOptimization(BailoutReason::kDetachedNativeContext);
    }
    if (!CheckNoDeprecatedMaps(code, isolate)) {
      return RetryOptimization(BailoutReason::kConcurrentMapDeprecation);
    }
    if (!pipeline_.CommitDependencies(code)) {
      return RetryOptimization(BailoutReason::kBailedOutDueToDependencyChange);
    }
#ifdef TARGET_SUPPORTS_TURBOSHAFT_INSTRUCTION_SELECTION
  }
#endif
  compilation_info()->SetCode(code);
  GlobalHandleVector<Map> maps = CollectRetainedMaps(isolate, code);
  RegisterWeakObjectsInOptimizedCode(isolate, context, code, std::move(maps));
  return SUCCEEDED;
}

template <turboshaft::TurbofanPhase Phase, typename... Args>
auto PipelineImpl::Run(Args&&... args) {
#ifdef V8_RUNTIME_CALL_STATS
  PipelineRunScope scope(this->data_, Phase::phase_name(),
                         Phase::kRuntimeCallCounterId, Phase::kCounterMode);
#else
  PipelineRunScope scope(this->data_, Phase::phase_name());
#endif
  Phase phase;
  static_assert(Phase::kKind == PhaseKind::kTurbofan);
  return phase.Run(this->data_, scope.zone(), std::forward<Args>(args)...);
}

struct GraphBuilderPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(BytecodeGraphBuilder)

  void Run(TFPipelineData* data, Zone* temp_zone, Linkage* linkage) {
    BytecodeGraphBuilderFlags flags;
    if (data->info()->analyze_environment_liveness()) {
      flags |= BytecodeGraphBuilderFlag::kAnalyzeEnvironmentLiveness;
    }
    if (data->info()->bailout_on_uninitialized()) {
      flags |= BytecodeGraphBuilderFlag::kBailoutOnUninitialized;
    }

    JSHeapBroker* broker = data->broker();
    UnparkedScopeIfNeeded scope(broker);
    JSFunctionRef closure = MakeRef(broker, data->info()->closure());
    BytecodeArrayRef bytecode = MakeRef(broker, data->info()->bytecode_array());
    CallFrequency frequency(1.0f);
    BuildGraphFromBytecode(
        broker, temp_zone, closure.shared(broker), bytecode,
        closure.raw_feedback_cell(broker), data->info()->osr_offset(),
        data->jsgraph(), frequency, data->source_positions(),
        data->node_origins(), SourcePosition::kNotInlined,
        data->info()->code_kind(), flags, &data->info()->tick_counter(),
        ObserveNodeInfo{data->observe_node_manager(),
                        data->info()->node_observer()});

    // We need to be certain that the parameter count reported by our output
    // Code object matches what the code we compile expects. Otherwise, this
    // may lead to effectively signature mismatches during function calls. This
    // CHECK is a defense-in-depth measure to ensure this doesn't happen.
    SBXCHECK_EQ(
        StartNode(data->jsgraph()->graph()->start()).FormalParameterCount(),
        linkage->GetIncomingDescriptor()->ParameterSlotCount());
  }
};

struct InliningPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(Inlining)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    OptimizedCompilationInfo* info = data->info();
    GraphReducer graph_reducer(temp_zone, data->graph(), &info->tick_counter(),
                               data->broker(), data->jsgraph()->Dead(),
                               data->observe_node_manager());
    DeadCodeElimination dead_code_elimination(&graph_reducer, data->graph(),
                                              data->common(), temp_zone);
    CheckpointElimination checkpoint_elimination(&graph_reducer);
    CommonOperatorReducer common_reducer(
        &graph_reducer, data->graph(), data->broker(), data->common(),
        data->machine(), temp_zone, BranchSemantics::kJS);
    JSCallReducer::Flags call_reducer_flags = JSCallReducer::kNoFlags;
    if (data->info()->bailout_on_uninitialized()) {
      call_reducer_flags |= JSCallReducer::kBailoutOnUninitialized;
    }
    if (data->info()->inline_js_wasm_calls() && data->info()->inlining()) {
      call_reducer_flags |= JSCallReducer::kInlineJSToWasmCalls;
    }
    JSCallReducer call_reducer(&graph_reducer, data->jsgraph(), data->broker(),
                               temp_zone, call_reducer_flags);
    JSContextSpecialization context_specialization(
        &graph_reducer, data->jsgraph(), data->broker(),
        data->specialization_context(),
        data->info()->function_context_specializing()
            ? data->info()->closure()
            : MaybeHandle<JSFunction>());
    JSNativeContextSpecialization::Flags flags =
        JSNativeContextSpecialization::kNoFlags;
    if (data->info()->bailout_on_uninitialized()) {
      flags |= JSNativeContextSpecialization::kBailoutOnUninitialized;
    }
    // Passing the OptimizedCompilationInfo's shared zone here as
    // JSNativeContextSpecialization allocates out-of-heap objects
    // that need to live until code generation.
    JSNativeContextSpecialization native_context_specialization(
        &graph_reducer, data->jsgraph(), data->broker(), flags, temp_zone,
        info->zone());
    JSInliningHeuristic inlining(
        &graph_reducer, temp_zone, data->info(), data->jsgraph(),
        data->broker(), data->source_positions(), data->node_origins(),
        JSInliningHeuristic::kJSOnly, nullptr, nullptr);

    JSIntrinsicLowering intrinsic_lowering(&graph_reducer, data->jsgraph(),
                                           data->broker());
    AddReducer(data, &graph_reducer, &dead_code_elimination);
    AddReducer(data, &graph_reducer, &checkpoint_elimination);
    AddReducer(data, &graph_reducer, &common_reducer);
    AddReducer(data, &graph_reducer, &native_context_specialization);
    AddReducer(data, &graph_reducer, &context_specialization);
    AddReducer(data, &graph_reducer, &intrinsic_lowering);
    AddReducer(data, &graph_reducer, &call_reducer);
    if (data->info()->inlining()) {
      AddReducer(data, &graph_reducer, &inlining);
    }
    graph_reducer.ReduceGraph();
    info->set_inlined_bytecode_size(inlining.total_inlined_bytecode_size());

#if V8_ENABLE_WEBASSEMBLY
    // Not forwarding this information to the TurboFan pipeline data here later
    // skips `JSWasmInliningPhase` if there are no JS-to-Wasm functions calls.
    if (call_reducer.has_js_wasm_calls()) {
      const wasm::WasmModule* wasm_module =
          call_reducer.wasm_module_for_inlining();
      DCHECK_NOT_NULL(wasm_module);
      data->set_wasm_module_for_inlining(wasm_module);
      // Enable source positions if not enabled yet. While JS only uses the
      // source position table for tracing, profiling, ..., wasm needs it at
      // compile time for keeping track of source locations for wasm traps.
      // Note: By not setting data->info()->set_source_positions(), even with
      // wasm inlining, source positions shouldn't be kept alive after
      // compilation is finished (if not for tracing, ...)
      if (!data->source_positions()->IsEnabled()) {
        data->source_positions()->Enable();
        data->source_positions()->AddDecorator();
      }
    }
#endif
  }
};

#if V8_ENABLE_WEBASSEMBLY
struct JSWasmInliningPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(JSWasmInlining)
  void Run(TFPipelineData* data, Zone* temp_zone) {
    DCHECK(data->has_js_wasm_calls());
    DCHECK_NOT_NULL(data->wasm_module_for_inlining());

    OptimizedCompilationInfo* info = data->info();
    GraphReducer graph_reducer(temp_zone, data->graph(), &info->tick_counter(),
                               data->broker(), data->jsgraph()->Dead());
    DeadCodeElimination dead_code_elimination(&graph_reducer, data->graph(),
                                              data->common(), temp_zone);
    CommonOperatorReducer common_reducer(
        &graph_reducer, data->graph(), data->broker(), data->common(),
        data->machine(), temp_zone, BranchSemantics::kMachine);
    // If we want to inline in Turboshaft instead (i.e., later in the
    // pipeline), only inline the wrapper here in TurboFan.
    // TODO(dlehmann,353475584): Long-term, also inline the JS-to-Wasm wrappers
    // in Turboshaft (or in Maglev, depending on the shared frontend).
    JSInliningHeuristic::Mode mode =
        (v8_flags.turboshaft_wasm_in_js_inlining)
            ? JSInliningHeuristic::kWasmWrappersOnly
            : JSInliningHeuristic::kWasmFullInlining;
    JSInliningHeuristic inlining(
        &graph_reducer, temp_zone, data->info(), data->jsgraph(),
        data->broker(), data->source_positions(), data->node_origins(), mode,
        data->wasm_module_for_inlining(), data->js_wasm_calls_sidetable());
    AddReducer(data, &graph_reducer, &dead_code_elimination);
    AddReducer(data, &graph_reducer, &common_reducer);
    AddReducer(data, &graph_reducer, &inlining);
    graph_reducer.ReduceGraph();
  }
};

struct JSWasmLoweringPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(JSWasmLowering)
  void Run(TFPipelineData* data, Zone* temp_zone) {
    DCHECK(data->has_js_wasm_calls());
    DCHECK_NOT_NULL(data->wasm_module_for_inlining());

    OptimizedCompilationInfo* info = data->info();
    GraphReducer graph_reducer(temp_zone, data->graph(), &info->tick_counter(),
                               data->broker(), data->jsgraph()->Dead());
    // The Wasm trap handler is not supported in JavaScript.
    const bool disable_trap_handler = true;
    WasmGCLowering lowering(&graph_reducer, data->jsgraph(),
                            data->wasm_module_for_inlining(),
                            disable_trap_handler, data->source_positions());
    AddReducer(data, &graph_reducer, &lowering);
    graph_reducer.ReduceGraph();
  }
};
#endif  // V8_ENABLE_WEBASSEMBLY

struct EarlyGraphTrimmingPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(EarlyGraphTrimming)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    GraphTrimmer trimmer(temp_zone, data->graph());
    NodeVector roots(temp_zone);
    data->jsgraph()->GetCachedNodes(&roots);
    UnparkedScopeIfNeeded scope(data->broker(), v8_flags.trace_turbo_trimming);
    trimmer.TrimGraph(roots.begin(), roots.end());
  }
};

struct TyperPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(Typer)

  void Run(TFPipelineData* data, Zone* temp_zone, Typer* typer) {
    NodeVector roots(temp_zone);
    data->jsgraph()->GetCachedNodes(&roots);

    // Make sure we always type True and False. Needed for escape analysis.
    roots.push_back(data->jsgraph()->TrueConstant());
    roots.push_back(data->jsgraph()->FalseConstant());

    LoopVariableOptimizer induction_vars(data->jsgraph()->graph(),
                                         data->common(), temp_zone);
    if (v8_flags.turbo_loop_variable) induction_vars.Run();

    // The typer inspects heap objects, so we need to unpark the local heap.
    UnparkedScopeIfNeeded scope(data->broker());
    typer->Run(roots, &induction_vars);
  }
};

struct UntyperPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(Untyper)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    class RemoveTypeReducer final : public Reducer {
     public:
      const char* reducer_name() const override { return "RemoveTypeReducer"; }
      Reduction Reduce(Node* node) final {
        if (NodeProperties::IsTyped(node)) {
          NodeProperties::RemoveType(node);
          return Changed(node);
        }
        return NoChange();
      }
    };

    NodeVector roots(temp_zone);
    data->jsgraph()->GetCachedNodes(&roots);
    for (Node* node : roots) {
      NodeProperties::RemoveType(node);
    }

    GraphReducer graph_reducer(
        temp_zone, data->graph(), &data->info()->tick_counter(), data->broker(),
        data->jsgraph()->Dead(), data->observe_node_manager());
    RemoveTypeReducer remove_type_reducer;
    AddReducer(data, &graph_reducer, &remove_type_reducer);
    graph_reducer.ReduceGraph();
  }
};

struct HeapBrokerInitializationPhase {
  DECL_MAIN_THREAD_PIPELINE_PHASE_CONSTANTS(HeapBrokerInitialization)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    data->broker()->AttachCompilationInfo(data->info());
    data->broker()->InitializeAndStartSerializing(data->native_context());
  }
};

struct TypedLoweringPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(TypedLowering)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    GraphReducer graph_reducer(
        temp_zone, data->graph(), &data->info()->tick_counter(), data->broker(),
        data->jsgraph()->Dead(), data->observe_node_manager());
    DeadCodeElimination dead_code_elimination(&graph_reducer, data->graph(),
                                              data->common(), temp_zone);
    JSCreateLowering create_lowering(&graph_reducer, data->jsgraph(),
                                     data->broker(), temp_zone);
    JSTypedLowering typed_lowering(&graph_reducer, data->jsgraph(),
                                   data->broker(), temp_zone);
    ConstantFoldingReducer constant_folding_reducer(
        &graph_reducer, data->jsgraph(), data->broker());
    TypedOptimization typed_optimization(&graph_reducer, data->dependencies(),
                                         data->jsgraph(), data->broker());
    SimplifiedOperatorReducer simple_reducer(
        &graph_reducer, data->jsgraph(), data->broker(), BranchSemantics::kJS);
    CheckpointElimination checkpoint_elimination(&graph_reducer);
    CommonOperatorReducer common_reducer(
        &graph_reducer, data->graph(), data->broker(), data->common(),
        data->machine(), temp_zone, BranchSemantics::kJS);
    AddReducer(data, &graph_reducer, &dead_code_elimination);

    AddReducer(data, &graph_reducer, &create_lowering);
    AddReducer(data, &graph_reducer, &constant_folding_reducer);
    AddReducer(data, &graph_reducer, &typed_lowering);
    AddReducer(data, &graph_reducer, &typed_optimization);
    AddReducer(data, &graph_reducer, &simple_reducer);
    AddReducer(data, &graph_reducer, &checkpoint_elimination);
    AddReducer(data, &graph_reducer, &common_reducer);

    // ConstantFoldingReducer, JSCreateLowering, JSTypedLowering, and
    // TypedOptimization access the heap.
    UnparkedScopeIfNeeded scope(data->broker());

    graph_reducer.ReduceGraph();
  }
};

struct EscapeAnalysisPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(EscapeAnalysis)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    EscapeAnalysis escape_analysis(data->jsgraph(),
                                   &data->info()->tick_counter(), temp_zone);
    escape_analysis.ReduceGraph();

    GraphReducer reducer(temp_zone, data->graph(),
                         &data->info()->tick_counter(), data->broker(),
                         data->jsgraph()->Dead(), data->observe_node_manager());
    EscapeAnalysisReducer escape_reducer(
        &reducer, data->jsgraph(), data->broker(),
        escape_analysis.analysis_result(), temp_zone);

    AddReducer(data, &reducer, &escape_reducer);

    // EscapeAnalysisReducer accesses the heap.
    UnparkedScopeIfNeeded scope(data->broker());

    reducer.ReduceGraph();
    // TODO(turbofan): Turn this into a debug mode check once we have
    // confidence.
    escape_reducer.VerifyReplacement();
  }
};

struct TypeAssertionsPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(TypeAssertions)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    Schedule* schedule = Scheduler::ComputeSchedule(
        temp_zone, data->graph(), Scheduler::kTempSchedule,
        &data->info()->tick_counter(), data->profile_data());

    AddTypeAssertions(data->jsgraph(), schedule, temp_zone);
  }
};

struct SimplifiedLoweringPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(SimplifiedLowering)

  void Run(TFPipelineData* data, Zone* temp_zone, Linkage* linkage) {
    SimplifiedLowering lowering(data->jsgraph(), data->broker(), temp_zone,
                                data->source_positions(), data->node_origins(),
                                &data->info()->tick_counter(), linkage,
                                data->info(), data->observe_node_manager());

    // RepresentationChanger accesses the heap.
    UnparkedScopeIfNeeded scope(data->broker());

    lowering.LowerAllNodes();
  }
};

struct LoopPeelingPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(LoopPeeling)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    GraphTrimmer trimmer(temp_zone, data->graph());
    NodeVector roots(temp_zone);
    data->jsgraph()->GetCachedNodes(&roots);
    {
      UnparkedScopeIfNeeded scope(data->broker(),
                                  v8_flags.trace_turbo_trimming);
      trimmer.TrimGraph(roots.begin(), roots.end());
    }

    LoopTree* loop_tree = LoopFinder::BuildLoopTree(
        data->jsgraph()->graph(), &data->info()->tick_counter(), temp_zone);
    // We call the typer inside of PeelInnerLoopsOfTree which inspects heap
    // objects, so we need to unpark the local heap.
    UnparkedScopeIfNeeded scope(data->broker());
    LoopPeeler(data->graph(), data->common(), loop_tree, temp_zone,
               data->source_positions(), data->node_origins())
        .PeelInnerLoopsOfTree();
  }
};

#if V8_ENABLE_WEBASSEMBLY
struct WasmInliningPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(WasmInlining)

  void Run(TFPipelineData* data, Zone* temp_zone, wasm::CompilationEnv* env,
           WasmCompilationData& compilation_data,
           ZoneVector<WasmInliningPosition>* inlining_positions,
           wasm::WasmDetectedFeatures* detected) {
    if (!WasmInliner::graph_size_allows_inlining(
            env->module, data->graph()->NodeCount(),
            v8_flags.wasm_inlining_budget)) {
      return;
    }
    GraphReducer graph_reducer(
        temp_zone, data->graph(), &data->info()->tick_counter(), data->broker(),
        data->jsgraph()->Dead(), data->observe_node_manager());
    DeadCodeElimination dead(&graph_reducer, data->graph(), data->common(),
                             temp_zone);
    std::unique_ptr<char[]> debug_name = data->info()->GetDebugName();
    WasmInliner inliner(&graph_reducer, env, compilation_data, data->mcgraph(),
                        debug_name.get(), inlining_positions, detected);
    AddReducer(data, &graph_reducer, &dead);
    AddReducer(data, &graph_reducer, &inliner);
    graph_reducer.ReduceGraph();
  }
};

namespace {
void EliminateLoopExits(std::vector<compiler::WasmLoopInfo>* loop_infos) {
  for (WasmLoopInfo& loop_info : *loop_infos) {
    std::unordered_set<Node*> loop_exits;
    // We collect exits into a set first because we are not allowed to mutate
    // them while iterating uses().
    for (Node* use : loop_info.header->uses()) {
      if (use->opcode() == IrOpcode::kLoopExit) {
        loop_exits.insert(use);
      }
    }
    for (Node* use : loop_exits) {
      LoopPeeler::EliminateLoopExit(use);
    }
  }
}
}  // namespace

struct WasmLoopUnrollingPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(WasmLoopUnrolling)

  void Run(TFPipelineData* data, Zone* temp_zone,
           std::vector<compiler::WasmLoopInfo>* loop_infos) {
    if (loop_infos->empty()) return;
    AllNodes all_nodes(temp_zone, data->graph(), data->graph()->end());
    for (WasmLoopInfo& loop_info : *loop_infos) {
      if (!loop_info.can_be_innermost) continue;
      if (!all_nodes.IsReachable(loop_info.header)) continue;
      ZoneUnorderedSet<Node*>* loop =
          LoopFinder::FindSmallInnermostLoopFromHeader(
              loop_info.header, all_nodes, temp_zone,
              // Only discover the loop until its size is the maximum unrolled
              // size for its depth.
              maximum_unrollable_size(loop_info.nesting_depth),
              LoopFinder::Purpose::kLoopUnrolling);
      if (loop == nullptr) continue;
      UnrollLoop(loop_info.header, loop, loop_info.nesting_depth, data->graph(),
                 data->common(), temp_zone, data->source_positions(),
                 data->node_origins());
    }

    EliminateLoopExits(loop_infos);
  }
};

struct WasmLoopPeelingPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(WasmLoopPeeling)

  void Run(TFPipelineData* data, Zone* temp_zone,
           std::vector<compiler::WasmLoopInfo>* loop_infos) {
    AllNodes all_nodes(temp_zone, data->graph());
    for (WasmLoopInfo& loop_info : *loop_infos) {
      if (loop_info.can_be_innermost) {
        ZoneUnorderedSet<Node*>* loop =
            LoopFinder::FindSmallInnermostLoopFromHeader(
                loop_info.header, all_nodes, temp_zone,
                v8_flags.wasm_loop_peeling_max_size,
                LoopFinder::Purpose::kLoopPeeling);
        if (loop == nullptr) continue;
        if (v8_flags.trace_wasm_loop_peeling) {
          CodeTracer::StreamScope tracing_scope(data->GetCodeTracer());
          auto& os = tracing_scope.stream();
          os << "Peeling loop at " << loop_info.header->id() << ", size "
             << loop->size() << std::endl;
        }
        PeelWasmLoop(loop_info.header, loop, data->graph(), data->common(),
                     temp_zone, data->source_positions(), data->node_origins());
      }
    }
    // If we are going to unroll later, keep loop exits.
    if (!v8_flags.wasm_loop_unrolling) EliminateLoopExits(loop_infos);
  }
};
#endif  // V8_ENABLE_WEBASSEMBLY

struct LoopExitEliminationPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(LoopExitElimination)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    LoopPeeler::EliminateLoopExits(data->graph(), temp_zone);
  }
};

struct GenericLoweringPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(GenericLowering)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    GraphReducer graph_reducer(
        temp_zone, data->graph(), &data->info()->tick_counter(), data->broker(),
        data->jsgraph()->Dead(), data->observe_node_manager());
    JSGenericLowering generic_lowering(data->jsgraph(), &graph_reducer,
                                       data->broker());
    AddReducer(data, &graph_reducer, &generic_lowering);

    // JSGEnericLowering accesses the heap due to ObjectRef's type checks.
    UnparkedScopeIfNeeded scope(data->broker());

    graph_reducer.ReduceGraph();
  }
};

struct EarlyOptimizationPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(EarlyOptimization)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    GraphReducer graph_reducer(
        temp_zone, data->graph(), &data->info()->tick_counter(), data->broker(),
        data->jsgraph()->Dead(), data->observe_node_manager());
    DeadCodeElimination dead_code_elimination(&graph_reducer, data->graph(),
                                              data->common(), temp_zone);
    SimplifiedOperatorReducer simple_reducer(&graph_reducer, data->jsgraph(),
                                             data->broker(),
                                             BranchSemantics::kMachine);
    RedundancyElimination redundancy_elimination(&graph_reducer,
                                                 data->jsgraph(), temp_zone);
    ValueNumberingReducer value_numbering(temp_zone, data->graph()->zone());
    MachineOperatorReducer machine_reducer(
        &graph_reducer, data->jsgraph(),
        MachineOperatorReducer::kPropagateSignallingNan);
    CommonOperatorReducer common_reducer(
        &graph_reducer, data->graph(), data->broker(), data->common(),
        data->machine(), temp_zone, BranchSemantics::kMachine);
    AddReducer(data, &graph_reducer, &dead_code_elimination);
    AddReducer(data, &graph_reducer, &simple_reducer);
    AddReducer(data, &graph_reducer, &redundancy_elimination);
    AddReducer(data, &graph_reducer, &machine_reducer);
    AddReducer(data, &graph_reducer, &common_reducer);
    AddReducer(data, &graph_reducer, &value_numbering);
    graph_reducer.ReduceGraph();
  }
};

struct LoadEliminationPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(LoadElimination)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    GraphReducer graph_reducer(
        temp_zone, data->graph(), &data->info()->tick_counter(), data->broker(),
        data->jsgraph()->Dead(), data->observe_node_manager());
    BranchElimination branch_condition_elimination(
        &graph_reducer, data->jsgraph(), temp_zone, BranchElimination::kEARLY);
    DeadCodeElimination dead_code_elimination(&graph_reducer, data->graph(),
                                              data->common(), temp_zone);
    RedundancyElimination redundancy_elimination(&graph_reducer,
                                                 data->jsgraph(), temp_zone);
    LoadElimination load_elimination(&graph_reducer, data->broker(),
                                     data->jsgraph(), temp_zone);
    CheckpointElimination checkpoint_elimination(&graph_reducer);
    ValueNumberingReducer value_numbering(temp_zone, data->graph()->zone());
    CommonOperatorReducer common_reducer(
        &graph_reducer, data->graph(), data->broker(), data->common(),
        data->machine(), temp_zone, BranchSemantics::kJS);
    TypedOptimization typed_optimization(&graph_reducer, data->dependencies(),
                                         data->jsgraph(), data->broker());
    ConstantFoldingReducer constant_folding_reducer(
        &graph_reducer, data->jsgraph(), data->broker());
    TypeNarrowingReducer type_narrowing_reducer(&graph_reducer, data->jsgraph(),
                                                data->broker());

    AddReducer(data, &graph_reducer, &branch_condition_elimination);
    AddReducer(data, &graph_reducer, &dead_code_elimination);
    AddReducer(data, &graph_reducer, &redundancy_elimination);
    AddReducer(data, &graph_reducer, &load_elimination);
    AddReducer(data, &graph_reducer, &type_narrowing_reducer);
    AddReducer(data, &graph_reducer, &constant_folding_reducer);
    AddReducer(data, &graph_reducer, &typed_optimization);
    AddReducer(data, &graph_reducer, &checkpoint_elimination);
    AddReducer(data, &graph_reducer, &common_reducer);
    AddReducer(data, &graph_reducer, &value_numbering);

    // ConstantFoldingReducer and TypedOptimization access the heap.
    UnparkedScopeIfNeeded scope(data->broker());

    graph_reducer.ReduceGraph();
  }
};

struct MemoryOptimizationPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(MemoryOptimization)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    // The memory optimizer requires the graphs to be trimmed, so trim now.
    GraphTrimmer trimmer(temp_zone, data->graph());
    NodeVector roots(temp_zone);
    data->jsgraph()->GetCachedNodes(&roots);
    {
      UnparkedScopeIfNeeded scope(data->broker(),
                                  v8_flags.trace_turbo_trimming);
      trimmer.TrimGraph(roots.begin(), roots.end());
    }

    // Optimize allocations and load/store operations.
#if V8_ENABLE_WEBASSEMBLY
    bool is_wasm = data->info()->IsWasm() || data->info()->IsWasmBuiltin();
#else
    bool is_wasm = false;
#endif
    MemoryOptimizer optimizer(
        data->broker(), data->jsgraph(), temp_zone,
        data->info()->allocation_folding()
            ? MemoryLowering::AllocationFolding::kDoAllocationFolding
            : MemoryLowering::AllocationFolding::kDontAllocationFolding,
        data->debug_name(), &data->info()->tick_counter(), is_wasm);
    optimizer.Optimize();
  }
};

struct MachineOperatorOptimizationPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(MachineOperatorOptimization)

  void Run(TFPipelineData* data, Zone* temp_zone,
           MachineOperatorReducer::SignallingNanPropagation
               signalling_nan_propagation) {
    GraphReducer graph_reducer(
        temp_zone, data->graph(), &data->info()->tick_counter(), data->broker(),
        data->jsgraph()->Dead(), data->observe_node_manager());
    ValueNumberingReducer value_numbering(temp_zone, data->graph()->zone());
    MachineOperatorReducer machine_reducer(&graph_reducer, data->jsgraph(),
                                           signalling_nan_propagation);
    PairLoadStoreReducer pair_load_store_reducer(
        &graph_reducer, data->jsgraph(), data->isolate());

    AddReducer(data, &graph_reducer, &machine_reducer);
    AddReducer(data, &graph_reducer, &value_numbering);
    if (data->machine()->SupportsLoadStorePairs()) {
      AddReducer(data, &graph_reducer, &pair_load_store_reducer);
    }
    graph_reducer.ReduceGraph();
  }
};

struct WasmBaseOptimizationPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(WasmBaseOptimization)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    GraphReducer graph_reducer(
        temp_zone, data->graph(), &data->info()->tick_counter(), data->broker(),
        data->mcgraph()->Dead(), data->observe_node_manager());
    ValueNumberingReducer value_numbering(temp_zone, data->graph()->zone());
    AddReducer(data, &graph_reducer, &value_numbering);
    graph_reducer.ReduceGraph();
  }
};

struct DecompressionOptimizationPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(DecompressionOptimization)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    if (!COMPRESS_POINTERS_BOOL) return;
    DecompressionOptimizer decompression_optimizer(
        temp_zone, data->graph(), data->common(), data->machine());
    decompression_optimizer.Reduce();
  }
};

struct BranchConditionDuplicationPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(BranchConditionDuplication)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    BranchConditionDuplicator compare_zero_branch_optimizer(temp_zone,
                                                            data->graph());
    compare_zero_branch_optimizer.Reduce();
  }
};

#if V8_ENABLE_WEBASSEMBLY
struct WasmTypingPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(WasmTyping)

  void Run(TFPipelineData* data, Zone* temp_zone, uint32_t function_index) {
    MachineGraph* mcgraph = data->mcgraph() ? data->mcgraph() : data->jsgraph();
    GraphReducer graph_reducer(
        temp_zone, data->graph(), &data->info()->tick_counter(), data->broker(),
        data->jsgraph()->Dead(), data->observe_node_manager());
    WasmTyper typer(&graph_reducer, mcgraph, function_index);
    AddReducer(data, &graph_reducer, &typer);
    graph_reducer.ReduceGraph();
  }
};

struct WasmGCOptimizationPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(WasmGCOptimization)

  void Run(TFPipelineData* data, Zone* temp_zone,
           const wasm::WasmModule* module, MachineGraph* mcgraph) {
    GraphReducer graph_reducer(
        temp_zone, data->graph(), &data->info()->tick_counter(), data->broker(),
        data->jsgraph()->Dead(), data->observe_node_manager());
    WasmLoadElimination load_elimination(&graph_reducer, data->jsgraph(),
                                         temp_zone);
    WasmGCOperatorReducer wasm_gc(&graph_reducer, temp_zone, mcgraph, module,
                                  data->source_positions());
    DeadCodeElimination dead_code_elimination(&graph_reducer, data->graph(),
                                              data->common(), temp_zone);
    AddReducer
```