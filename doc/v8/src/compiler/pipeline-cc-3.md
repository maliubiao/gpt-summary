Response:
My thinking process to answer the request goes through these stages:

1. **Understand the Core Request:** The main goal is to analyze the provided C++ code snippet (`v8/src/compiler/pipeline.cc`, part 4/6) and explain its functionality in a concise and understandable way. The request also asks for specific information like whether it's Torque, its relation to JavaScript (with examples), code logic inference, potential errors, and a summary.

2. **Initial Scan and Keyword Spotting:** I quickly read through the code, looking for recurring keywords and patterns. Terms like `turboshaft`, `Pipeline`, `Phase`, `Graph`, `Wasm`, `Code`, `Builtin`, `Optimize`, `Lowering`, `GenerateCode`, and file names like `GraphBuilderPhase`, `InliningPhase`, etc., stand out. This gives me a high-level understanding that this code is related to a compilation pipeline, likely for WebAssembly and potentially JavaScript, using a component named "Turboshaft".

3. **Identify Key Functionalities:** Based on the keywords and the structure of the code (a series of `Run` calls with phase names), I deduce the core functionalities:
    * **Compilation Pipeline Management:** The `PipelineImpl` class and its `Run` method suggest a system for executing a series of compilation steps.
    * **Graph Processing:** The frequent mention of "Graph" and phases like `GraphBuilderPhase`, `VerifyGraphPhase`, `PrintGraphPhase`, `EarlyGraphTrimmingPhase` indicates that the code operates on a graph representation of the code being compiled.
    * **Optimization:** Phases like `InliningPhase`, `LoopPeelingPhase`, `LoadEliminationPhase`, `EscapeAnalysisPhase`, `MemoryOptimizationPhase`, `WasmOptimizePhase` clearly point to optimization steps.
    * **Lowering:** Phases like `TypedLoweringPhase`, `SimplifiedLoweringPhase`, `GenericLoweringPhase`, `Int64LoweringPhase`, `DebugFeatureLoweringPhase`, `JSWasmLoweringPhase` indicate the process of converting the high-level graph into a lower-level representation closer to machine code.
    * **Code Generation:** Functions like `GenerateCodeForCodeStub`, `GenerateCodeForTurboshaftBuiltin`, `GenerateCodeForWasmNativeStub`, and the presence of instruction selection phases suggest the code is responsible for generating the final machine code.
    * **WebAssembly Support:**  The numerous mentions of `Wasm` and specific WebAssembly-related phases confirm that a significant part of this code deals with compiling WebAssembly.
    * **Profiling Data Handling (PGO):** The presence of `HashGraphForPGO` and logic around `profile_data` indicates support for Profile-Guided Optimization.

4. **Address Specific Questions:**

    * **Torque:**  I check for the `.tq` extension. The snippet doesn't end in `.tq`, so I conclude it's not a Torque source file.
    * **JavaScript Relation:**  I look for connections between the compilation process and JavaScript. The presence of phases like `InliningPhase` (inlining JavaScript functions) and the overall context of V8 as a JavaScript engine strongly suggest a relationship. I look for specific examples. The `Typer::kThisIsReceiver` and `Typer::kNewTargetIsReceiver` flags, related to `this` and `new.target` in JavaScript, provide good examples.
    * **Code Logic Inference:**  I focus on parts of the code that demonstrate a logical flow. The conditional execution of `WasmOptimizePhase` based on `v8_flags.wasm_opt` and `Int64LoweringPhase` based on `Is64()` are clear examples. I construct a simple "if-else" scenario as an example.
    * **Common Programming Errors:** I think about potential issues that could arise in a compilation pipeline. Incorrect assumptions about types after lowering (addressed by the `UntyperPhase`) are a relevant example. I formulate a scenario where a developer might try to access type information too late in the process.
    * **Function Summarization:** I synthesize the information gathered in the previous steps to provide a concise summary of the code's role.

5. **Refine and Organize:** I structure the answer logically, grouping related functionalities together. I use clear headings and bullet points to improve readability. I ensure the language is precise and avoids jargon where possible, while still being technically accurate. I double-check that all aspects of the original request are addressed. For instance, explicitly stating it's part 4 of 6 is important.

6. **Iterative Refinement (Internal):**  While writing, I constantly review my understanding and the code snippet. If something is unclear, I go back to the code and re-examine it. For example, the purpose of `WasmDeadCodeEliminationPhase` being more than just optimization required a closer look at the comment.

By following this process, I can systematically analyze the code and generate a comprehensive and accurate answer that addresses all the requirements of the request. The key is to break down the complex task into smaller, manageable steps and use the structure of the code itself as a guide.
好的，我们来分析一下 `v8/src/compiler/pipeline.cc` 这个文件的第 4 部分代码的功能。

**主要功能归纳:**

这段代码主要负责 **TurboFan 和 Turboshaft 编译管道中用于生成代码的各个阶段和步骤**，特别是针对 **Wasm (WebAssembly) 和 CSA (CodeStubAssembler) 的代码生成流程**。它定义了如何构建、优化和最终生成机器码，并包含了对性能分析（PGO）的支持。

**具体功能点:**

1. **Turboshaft 集成 (Wasm):**  这部分代码处理了使用 Turboshaft 编译器编译 WebAssembly 代码的流程。它创建 `turboshaft::Pipeline` 对象，并运行一系列 Turboshaft 的优化和降低阶段。
    *  例如，`turboshaft_pipeline.Run<turboshaft::WasmOptimizePhase>();`  运行 Turboshaft 的 Wasm 代码优化阶段。
    *  针对 64 位架构和调试模式有不同的处理逻辑。
    *  最终调用 `GenerateCodeFromTurboshaftGraph` 函数来从 Turboshaft 生成的代码图生成最终代码。

2. **Wasm Wrapper 的 Finalization:**  `WasmTurboshaftWrapperCompilationJob::FinalizeJobImpl` 函数负责 WebAssembly wrapper 代码生成的最后阶段，它会根据是否使用了 Turboshaft 的指令选择来调用不同的 FinalizeWrapperCompilation 函数。

3. **图的打印和验证:** `PipelineImpl::RunPrintAndVerify` 函数用于在编译过程中的特定阶段打印图的结构（用于调试和分析）并进行验证，确保图的正确性。

4. **Heap Broker 的初始化:** `PipelineImpl::InitializeHeapBroker` 函数初始化 Heap Broker，这是一个用于在编译过程中访问堆信息的组件。它还处理一些追踪和调试信息的输出。

5. **图的创建 (TurboFan):** `PipelineImpl::CreateGraph` 函数负责构建 TurboFan 的代码图。
    *  它运行 `GraphBuilderPhase` 来初步构建图。
    *  运行 `InliningPhase` 来执行函数内联优化。
    *  设置 `Typer` 的一些标志，用于类型推断。

6. **图的优化 (TurboFan):** `PipelineImpl::OptimizeTurbofanGraph` 函数执行 TurboFan 代码图的各种优化和降低阶段。
    *  包括早期图裁剪 (`EarlyGraphTrimmingPhase`)。
    *  类型推断 (`TyperPhase`) 和类型降低 (`TypedLoweringPhase`)。
    *  循环优化 (`LoopPeelingPhase`, `LoopExitEliminationPhase`)。
    *  加载消除 (`LoadEliminationPhase`)。
    *  逃逸分析 (`EscapeAnalysisPhase`)。
    *  类型断言 (`TypeAssertionsPhase`)。
    *  简化降低 (`SimplifiedLoweringPhase`)。
    *  对包含 JS-Wasm 调用的代码进行特殊处理 (`JSWasmInliningPhase`, `WasmTypingPhase`, `WasmGCOptimizationPhase`, `JSWasmLoweringPhase`, `WasmOptimizationPhase`)。
    *  通用降低 (`GenericLoweringPhase`)。

7. **代码块构建:** `PipelineImpl::OptimizeTurbofanGraph` 的最后部分启动代码块的构建，并运行早期的优化阶段 (`EarlyOptimizationPhase`)。

8. **PGO (Profile-Guided Optimization) 支持:**  代码中包含 `HashGraphForPGO` 函数，用于计算代码图的哈希值，这对于在运行时收集性能数据并在后续编译中应用这些数据进行优化非常重要。它还包含验证 PGO 数据的逻辑 (`ValidateProfileData`).

9. **CSA (CodeStubAssembler) 代码生成:**  `Pipeline::GenerateCodeForCodeStub` 函数处理使用 CSA 生成代码的流程。
    *  它创建 `TFPipelineData` 和 `PipelineImpl` 对象。
    *  可以选择使用 Turboshaft 进行 CSA 代码生成 (`v8_flags.turboshaft_csa`)。
    *  否则，会运行一系列 TurboFan 的 CSA 优化阶段 (`CsaEarlyOptimizationPhase`, `MemoryOptimizationPhase`, `CsaOptimizationPhase`, `DecompressionOptimizationPhase`, `BranchConditionDuplicationPhase`).
    *  最终调用 `SelectInstructionsAndAssemble` 或 `GenerateCode` 来生成机器码。

10. **Turboshaft Builtin 的代码生成:** `Pipeline::GenerateCodeForTurboshaftBuiltin` 函数处理使用 Turboshaft 直接生成 Builtin 函数的代码。

11. **Wasm Native Stub 的代码生成:** `Pipeline::GenerateCodeForWasmNativeStub` 和 `Pipeline::GenerateCodeForWasmNativeStubFromTurboshaft` 函数处理 WebAssembly 原生桩代码的生成，分别使用 TurboFan 和 Turboshaft。

**关于请求中的问题:**

* **`.tq` 结尾:**  代码片段中没有显示文件结尾，但根据上下文（C++ 代码和涉及 TurboFan/Turboshaft），这个文件是 `.cc` (C++ 源代码) 文件，而不是 `.tq` (Torque 源代码)。

* **与 Javascript 的关系:**  `v8/src/compiler/pipeline.cc` 是 V8 引擎编译器的核心部分，负责将 JavaScript 代码（以及 WebAssembly 代码）编译成可执行的机器码。
    * **JavaScript 例子:**  虽然这段 C++ 代码本身不是 JavaScript，但它处理的编译过程是针对 JavaScript 代码的。例如，`InliningPhase` 就是将一个函数调用处的代码直接嵌入到调用者函数中，这是 JavaScript 引擎常见的优化手段。

    ```javascript
    function add(a, b) {
      return a + b;
    }

    function calculate() {
      let x = 5;
      let y = 10;
      let sum = add(x, y); // 这里可能发生内联
      return sum * 2;
    }
    ```

    在 `calculate` 函数的编译过程中，如果启用了内联优化，`add(x, y)` 的代码可能会被直接插入到 `calculate` 函数中，避免函数调用的开销。

* **代码逻辑推理:**

    **假设输入:**  `v8_flags.wasm_opt` 为 `true`，并且正在编译一个 WebAssembly 模块的 wrapper 函数。

    **输出:**  `turboshaft_pipeline.Run<turboshaft::WasmOptimizePhase>();` 这行代码会被执行，从而运行 Turboshaft 的 WebAssembly 优化阶段。

    **假设输入:**  当前运行的架构不是 64 位 (`!Is64()` 为 `true`)。

    **输出:**  `turboshaft_pipeline.Run<turboshaft::Int64LoweringPhase>();` 这行代码会被执行，从而进行 64 位整数的降低处理，因为在非 64 位架构上需要特殊处理 64 位整数。

* **用户常见的编程错误:**  这段代码是编译器内部的实现，用户通常不会直接编写这样的代码。但是，理解编译器的行为可以帮助开发者避免一些性能陷阱。例如，过多的函数调用可能会导致性能下降，而编译器（如 TurboFan 的内联优化）会尝试解决这个问题。

* **功能归纳 (第 4 部分):**  这段代码主要负责 TurboFan 和 Turboshaft 编译管道中的核心代码生成流程，包括各种优化、降低阶段，以及最终生成机器码的步骤。它特别关注 WebAssembly 和 CSA 的代码生成，并包含了对性能分析的支持。

希望这个分析能够帮助你理解 `v8/src/compiler/pipeline.cc` 的这一部分代码的功能。

### 提示词
```
这是目录为v8/src/compiler/pipeline.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/pipeline.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
tracing is not enabled,
    // because it may not yet be initialized then and doing so from the
    // background thread is not threadsafe.
    code_tracer = turboshaft_data_.GetCodeTracer();
  }
  Zone printing_zone(&allocator, ZONE_NAME);
  turboshaft::PrintTurboshaftGraph(&turboshaft_data_, &printing_zone,
                                   code_tracer, "Graph generation");

  turboshaft::Pipeline turboshaft_pipeline(&turboshaft_data_);
  // Skip the LoopUnrolling, WasmGCOptimize and WasmLowering phases for
  // wrappers.
  // TODO(14108): Do we need value numbering if wasm_opt is turned off?
  if (v8_flags.wasm_opt) {
    turboshaft_pipeline.Run<turboshaft::WasmOptimizePhase>();
  }

  if (!Is64()) {
    turboshaft_pipeline.Run<turboshaft::Int64LoweringPhase>();
  }

  // This is more than an optimization currently: We need it to sort blocks to
  // work around a bug in RecreateSchedulePhase.
  turboshaft_pipeline.Run<turboshaft::WasmDeadCodeEliminationPhase>();

  if (V8_UNLIKELY(v8_flags.turboshaft_enable_debug_features)) {
    // This phase has to run very late to allow all previous phases to use
    // debug features.
    turboshaft_pipeline.Run<turboshaft::DebugFeatureLoweringPhase>();
  }

  turboshaft_pipeline.BeginPhaseKind("V8.InstructionSelection");

#ifdef TARGET_SUPPORTS_TURBOSHAFT_INSTRUCTION_SELECTION
  bool use_turboshaft_instruction_selection =
      v8_flags.turboshaft_wasm_instruction_selection_staged;
#else
  bool use_turboshaft_instruction_selection =
      v8_flags.turboshaft_wasm_instruction_selection_experimental;
#endif

  const bool success = GenerateCodeFromTurboshaftGraph(
      use_turboshaft_instruction_selection, &linkage, turboshaft_pipeline,
      &pipeline_);
  return success ? SUCCEEDED : FAILED;
}

CompilationJob::Status WasmTurboshaftWrapperCompilationJob::FinalizeJobImpl(
    Isolate* isolate) {
#ifdef TARGET_SUPPORTS_TURBOSHAFT_INSTRUCTION_SELECTION
  bool use_turboshaft_instruction_selection =
      v8_flags.turboshaft_wasm_instruction_selection_staged;
#else
  bool use_turboshaft_instruction_selection =
      v8_flags.turboshaft_wasm_instruction_selection_experimental;
#endif

  if (use_turboshaft_instruction_selection) {
    return FinalizeWrapperCompilation(
        &turboshaft_data_, &info_, call_descriptor_, isolate,
        "WasmTurboshaftWrapperCompilationJob::FinalizeJobImpl");
  } else {
    return FinalizeWrapperCompilation(
        &pipeline_, &info_, call_descriptor_, isolate,
        "WasmTurboshaftWrapperCompilationJob::FinalizeJobImpl");
  }
}

#endif  // V8_ENABLE_WEBASSEMBLY

void PipelineImpl::RunPrintAndVerify(const char* phase, bool untyped) {
  if (info()->trace_turbo_json() || info()->trace_turbo_graph()) {
    Run<PrintGraphPhase>(phase);
  }
  if (v8_flags.turbo_verify) {
    Run<VerifyGraphPhase>(untyped);
  }
}

void PipelineImpl::InitializeHeapBroker() {
  TFPipelineData* data = data_;

  data->BeginPhaseKind("V8.TFBrokerInitAndSerialization");

  if (info()->trace_turbo_json() || info()->trace_turbo_graph()) {
    CodeTracer::StreamScope tracing_scope(data->GetCodeTracer());
    tracing_scope.stream()
        << "---------------------------------------------------\n"
        << "Begin compiling method " << info()->GetDebugName().get()
        << " using TurboFan" << std::endl;
  }
  if (info()->trace_turbo_json()) {
    TurboCfgFile tcf(isolate());
    tcf << AsC1VCompilation(info());
  }
  if (data->info()->bytecode_array()->SourcePositionTable()->DataSize() == 0) {
    data->source_positions()->Disable();
  }
  data->source_positions()->AddDecorator();
  if (data->info()->trace_turbo_json()) {
    data->node_origins()->AddDecorator();
  }

  Run<HeapBrokerInitializationPhase>();
  data->broker()->StopSerializing();
  data->EndPhaseKind();
}

bool PipelineImpl::CreateGraph(Linkage* linkage) {
  DCHECK(!v8_flags.turboshaft_from_maglev);
  TFPipelineData* data = this->data_;
  UnparkedScopeIfNeeded unparked_scope(data->broker());

  data->BeginPhaseKind("V8.TFGraphCreation");

  Run<GraphBuilderPhase>(linkage);
  RunPrintAndVerify(GraphBuilderPhase::phase_name(), true);

  // Perform function context specialization and inlining (if enabled).
  Run<InliningPhase>();
  RunPrintAndVerify(InliningPhase::phase_name(), true);

  // Determine the Typer operation flags.
  {
    SharedFunctionInfoRef shared_info =
        MakeRef(data->broker(), info()->shared_info());
    if (is_sloppy(shared_info.language_mode()) &&
        shared_info.IsUserJavaScript()) {
      // Sloppy mode functions always have an Object for this.
      data->AddTyperFlag(Typer::kThisIsReceiver);
    }
    if (IsClassConstructor(shared_info.kind())) {
      // Class constructors cannot be [[Call]]ed.
      data->AddTyperFlag(Typer::kNewTargetIsReceiver);
    }
  }

  data->EndPhaseKind();

  return true;
}

bool PipelineImpl::OptimizeTurbofanGraph(Linkage* linkage) {
  DCHECK(!v8_flags.turboshaft_from_maglev);
  TFPipelineData* data = this->data_;

  data->BeginPhaseKind("V8.TFLowering");

  // Trim the graph before typing to ensure all nodes are typed.
  Run<EarlyGraphTrimmingPhase>();
  RunPrintAndVerify(EarlyGraphTrimmingPhase::phase_name(), true);

  // Type the graph and keep the Typer running such that new nodes get
  // automatically typed when they are created.
  Run<TyperPhase>(data->CreateTyper());
  RunPrintAndVerify(TyperPhase::phase_name());

  Run<TypedLoweringPhase>();
  RunPrintAndVerify(TypedLoweringPhase::phase_name());

  if (data->info()->loop_peeling()) {
    Run<LoopPeelingPhase>();
    RunPrintAndVerify(LoopPeelingPhase::phase_name(), true);
  } else {
    Run<LoopExitEliminationPhase>();
    RunPrintAndVerify(LoopExitEliminationPhase::phase_name(), true);
  }

  if (v8_flags.turbo_load_elimination) {
    Run<LoadEliminationPhase>();
    RunPrintAndVerify(LoadEliminationPhase::phase_name());
  }
  data->DeleteTyper();

  if (v8_flags.turbo_escape) {
    Run<EscapeAnalysisPhase>();
    RunPrintAndVerify(EscapeAnalysisPhase::phase_name());
  }

  if (v8_flags.assert_types) {
    Run<TypeAssertionsPhase>();
    RunPrintAndVerify(TypeAssertionsPhase::phase_name());
  }

  // Perform simplified lowering. This has to run w/o the Typer decorator,
  // because we cannot compute meaningful types anyways, and the computed
  // types might even conflict with the representation/truncation logic.
  Run<SimplifiedLoweringPhase>(linkage);
  RunPrintAndVerify(SimplifiedLoweringPhase::phase_name(), true);

#if V8_ENABLE_WEBASSEMBLY
  if (data->has_js_wasm_calls()) {
    DCHECK(data->info()->inline_js_wasm_calls());
    Run<JSWasmInliningPhase>();
    RunPrintAndVerify(JSWasmInliningPhase::phase_name(), true);
    Run<WasmTypingPhase>(-1);
    RunPrintAndVerify(WasmTypingPhase::phase_name(), true);
    if (v8_flags.wasm_opt) {
      Run<WasmGCOptimizationPhase>(data->wasm_module_for_inlining(),
                                   data->jsgraph());
      RunPrintAndVerify(WasmGCOptimizationPhase::phase_name(), true);
    }
    Run<JSWasmLoweringPhase>();
    RunPrintAndVerify(JSWasmLoweringPhase::phase_name(), true);
    if (v8_flags.turbo_optimize_inlined_js_wasm_wrappers && v8_flags.wasm_opt) {
      wasm::WasmDetectedFeatures detected({wasm::WasmDetectedFeature::gc});
      Run<WasmOptimizationPhase>(MachineOperatorReducer::kSilenceSignallingNan,
                                 detected);
      RunPrintAndVerify(WasmOptimizationPhase::phase_name(), true);
    }
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  // From now on it is invalid to look at types on the nodes, because the
  // types on the nodes might not make sense after representation selection
  // due to the way we handle truncations; if we'd want to look at types
  // afterwards we'd essentially need to re-type (large portions of) the
  // graph.

  // In order to catch bugs related to type access after this point, we now
  // remove the types from the nodes (currently only in Debug builds).
#ifdef DEBUG
  Run<UntyperPhase>();
  RunPrintAndVerify(UntyperPhase::phase_name(), true);
#endif

  // Run generic lowering pass.
  Run<GenericLoweringPhase>();
  RunPrintAndVerify(GenericLoweringPhase::phase_name(), true);

  data->BeginPhaseKind("V8.TFBlockBuilding");

  data->InitializeFrameData(linkage->GetIncomingDescriptor());

  // Run early optimization pass.
  Run<EarlyOptimizationPhase>();
  RunPrintAndVerify(EarlyOptimizationPhase::phase_name(), true);

  data->source_positions()->RemoveDecorator();
  if (data->info()->trace_turbo_json()) {
    data->node_origins()->RemoveDecorator();
  }

  ComputeScheduledGraph();

  return true;
}

namespace {

int HashGraphForPGO(const turboshaft::Graph* graph) {
  size_t hash = 0;
  for (const turboshaft::Operation& op : graph->AllOperations()) {
    VisitOperation(op, [&hash, &graph](const auto& derived) {
      const auto op_hash =
          derived.hash_value(turboshaft::HashingStrategy::kMakeSnapshotStable);
      hash = turboshaft::fast_hash_combine(hash, op_hash);
      // Use for tracing while developing:
      constexpr bool kTraceHashing = false;
      if constexpr (kTraceHashing) {
        std::cout << "[" << std::setw(3) << graph->Index(derived)
                  << "] Type: " << std::setw(30)
                  << turboshaft::OpcodeName(
                         turboshaft::operation_to_opcode_v<decltype(derived)>);
        std::cout << " + 0x" << std::setw(20) << std::left << std::hex
                  << op_hash << " => 0x" << hash << std::dec << std::endl;
      }
    });
  }
  return Tagged<Smi>(IntToSmi(static_cast<int>(hash))).value();
}

// Compute a hash of the given graph, in a way that should provide the same
// result in multiple runs of mksnapshot, meaning the hash cannot depend on any
// external pointer values or uncompressed heap constants. This hash can be used
// to reject profiling data if the builtin's current code doesn't match the
// version that was profiled. Hash collisions are not catastrophic; in the worst
// case, we just defer some blocks that ideally shouldn't be deferred. The
// result value is in the valid Smi range.
int HashGraphForPGO(const Graph* graph) {
  AccountingAllocator allocator;
  Zone local_zone(&allocator, ZONE_NAME);

  constexpr NodeId kUnassigned = static_cast<NodeId>(-1);

  constexpr uint8_t kUnvisited = 0;
  constexpr uint8_t kOnStack = 1;
  constexpr uint8_t kVisited = 2;

  // Do a depth-first post-order traversal of the graph. For every node, hash:
  //
  //   - the node's traversal number
  //   - the opcode
  //   - the number of inputs
  //   - each input node's traversal number
  //
  // What's a traversal number? We can't use node IDs because they're not stable
  // build-to-build, so we assign a new number for each node as it is visited.

  ZoneVector<uint8_t> state(graph->NodeCount(), kUnvisited, &local_zone);
  ZoneVector<NodeId> traversal_numbers(graph->NodeCount(), kUnassigned,
                                       &local_zone);
  ZoneStack<Node*> stack(&local_zone);

  NodeId visited_count = 0;
  size_t hash = 0;

  stack.push(graph->end());
  state[graph->end()->id()] = kOnStack;
  traversal_numbers[graph->end()->id()] = visited_count++;
  while (!stack.empty()) {
    Node* n = stack.top();
    bool pop = true;
    for (Node* const i : n->inputs()) {
      if (state[i->id()] == kUnvisited) {
        state[i->id()] = kOnStack;
        traversal_numbers[i->id()] = visited_count++;
        stack.push(i);
        pop = false;
        break;
      }
    }
    if (pop) {
      state[n->id()] = kVisited;
      stack.pop();
      hash = base::hash_combine(hash, traversal_numbers[n->id()], n->opcode(),
                                n->InputCount());
      for (Node* const i : n->inputs()) {
        DCHECK(traversal_numbers[i->id()] != kUnassigned);
        hash = base::hash_combine(hash, traversal_numbers[i->id()]);
      }
    }
  }
  return Tagged<Smi>(IntToSmi(static_cast<int>(hash))).value();
}

template <typename Graph>
int ComputeInitialGraphHash(Builtin builtin,
                            const ProfileDataFromFile* profile_data,
                            const Graph* graph) {
  int initial_graph_hash = 0;
  if (v8_flags.turbo_profiling || v8_flags.dump_builtins_hashes_to_file ||
      profile_data != nullptr) {
    initial_graph_hash = HashGraphForPGO(graph);
    if (v8_flags.dump_builtins_hashes_to_file) {
      std::ofstream out(v8_flags.dump_builtins_hashes_to_file,
                        std::ios_base::app);
      out << "Builtin: " << Builtins::name(builtin) << ", hash: 0x" << std::hex
          << initial_graph_hash << std::endl;
    }
  }
  return initial_graph_hash;
}

const ProfileDataFromFile* ValidateProfileData(
    const ProfileDataFromFile* profile_data, int initial_graph_hash,
    const char* debug_name) {
  if (profile_data != nullptr && profile_data->hash() != initial_graph_hash) {
    if (v8_flags.reorder_builtins) {
      BuiltinsCallGraph::Get()->set_all_hash_matched(false);
    }
    if (v8_flags.abort_on_bad_builtin_profile_data ||
        v8_flags.warn_about_builtin_profile_data) {
      base::EmbeddedVector<char, 256> msg;
      SNPrintF(msg,
               "Rejected profile data for %s due to function change. "
               "Please use tools/builtins-pgo/generate.py to refresh it.",
               debug_name);
      if (v8_flags.abort_on_bad_builtin_profile_data) {
        // mksnapshot might fail here because of the following reasons:
        // * builtins were changed since the builtins profile generation,
        // * current build options affect builtins code and they don't match
        //   the options used for building the profile (for example, it might
        //   be because of gn argument 'dcheck_always_on=true').
        // To fix the issue one must either update the builtins PGO profiles
        // (see tools/builtins-pgo/generate.py) or disable builtins PGO by
        // setting gn argument v8_builtins_profiling_log_file="".
        // One might also need to update the tools/builtins-pgo/generate.py if
        // the set of default release arguments has changed.
        FATAL("%s", msg.begin());
      } else {
        PrintF("%s\n", msg.begin());
      }
    }
#ifdef LOG_BUILTIN_BLOCK_COUNT
    if (v8_flags.turbo_log_builtins_count_input) {
      PrintF("The hash came from execution count file for %s was not match!\n",
             debug_name);
    }
#endif
    return nullptr;
  }
  return profile_data;
}

}  // namespace

// TODO(nicohartmann): Move more of this to turboshaft::Pipeline eventually.
MaybeHandle<Code> Pipeline::GenerateCodeForCodeStub(
    Isolate* isolate, CallDescriptor* call_descriptor, Graph* graph,
    JSGraph* jsgraph, SourcePositionTable* source_positions, CodeKind kind,
    const char* debug_name, Builtin builtin, const AssemblerOptions& options,
    const ProfileDataFromFile* profile_data) {
  OptimizedCompilationInfo info(base::CStrVector(debug_name), graph->zone(),
                                kind);

  info.set_builtin(builtin);

  // Construct a pipeline for scheduling and code generation.
  ZoneStats zone_stats(isolate->allocator());
  NodeOriginTable node_origins(graph);
  JumpOptimizationInfo jump_opt;
  bool should_optimize_jumps =
      isolate->serializer_enabled() && v8_flags.turbo_rewrite_far_jumps &&
      !v8_flags.turbo_profiling && !v8_flags.dump_builtins_hashes_to_file;
  JumpOptimizationInfo* jump_optimization_info =
      should_optimize_jumps ? &jump_opt : nullptr;
  TFPipelineData data(&zone_stats, &info, isolate, isolate->allocator(), graph,
                      jsgraph, nullptr, source_positions, &node_origins,
                      jump_optimization_info, options, profile_data);
  PipelineJobScope scope(&data, isolate->counters()->runtime_call_stats());
  RCS_SCOPE(isolate, RuntimeCallCounterId::kOptimizeCode);
  data.set_verify_graph(v8_flags.verify_csa);
  std::unique_ptr<TurbofanPipelineStatistics> pipeline_statistics;
  if (v8_flags.turbo_stats || v8_flags.turbo_stats_nvp) {
    pipeline_statistics.reset(new TurbofanPipelineStatistics(
        &info, isolate->GetTurboStatistics(), &zone_stats));
    pipeline_statistics->BeginPhaseKind("V8.TFStubCodegen");
  }

  PipelineImpl pipeline(&data);

  // Trace initial graph (if requested).
  if (info.trace_turbo_json() || info.trace_turbo_graph()) {
    CodeTracer::StreamScope tracing_scope(data.GetCodeTracer());
    tracing_scope.stream()
        << "---------------------------------------------------\n"
        << "Begin compiling " << debug_name << " using TurboFan" << std::endl;
    if (info.trace_turbo_json()) {
      TurboJsonFile json_of(&info, std::ios_base::trunc);
      json_of << "{\"function\" : ";
      JsonPrintFunctionSource(json_of, -1, info.GetDebugName(),
                              Handle<Script>(), isolate,
                              Handle<SharedFunctionInfo>());
      json_of << ",\n\"phases\":[";
    }
    pipeline.Run<PrintGraphPhase>("V8.TFMachineCode");
  }

  // Validate pgo profile.
  const int initial_graph_hash =
      ComputeInitialGraphHash(builtin, profile_data, data.graph());
  profile_data =
      ValidateProfileData(profile_data, initial_graph_hash, debug_name);
  data.set_profile_data(profile_data);

  if (v8_flags.turboshaft_csa) {
    pipeline.ComputeScheduledGraph();
    DCHECK_NULL(data.frame());
    DCHECK_NOT_NULL(data.schedule());

    turboshaft::PipelineData turboshaft_data(
        data.zone_stats(), turboshaft::TurboshaftPipelineKind::kCSA,
        data.isolate(), data.info(), options, data.start_source_position());

    turboshaft::BuiltinPipeline turboshaft_pipeline(&turboshaft_data);
    Linkage linkage(call_descriptor);
    CHECK(turboshaft_pipeline.CreateGraphFromTurbofan(&data, &linkage));

    turboshaft_pipeline.OptimizeBuiltin();

    CHECK_NULL(data.osr_helper_ptr());

    return turboshaft_pipeline.GenerateCode(&linkage, data.osr_helper_ptr(),
                                            jump_optimization_info,
                                            profile_data, initial_graph_hash);
  } else {
    // TODO(nicohartmann): Remove once `--turboshaft-csa` is the default.
    pipeline.Run<CsaEarlyOptimizationPhase>();
    pipeline.RunPrintAndVerify(CsaEarlyOptimizationPhase::phase_name(), true);

    // Optimize memory access and allocation operations.
    pipeline.Run<MemoryOptimizationPhase>();
    pipeline.RunPrintAndVerify(MemoryOptimizationPhase::phase_name(), true);

    pipeline.Run<CsaOptimizationPhase>();
    pipeline.RunPrintAndVerify(CsaOptimizationPhase::phase_name(), true);

    pipeline.Run<DecompressionOptimizationPhase>();
    pipeline.RunPrintAndVerify(DecompressionOptimizationPhase::phase_name(),
                               true);

    pipeline.Run<BranchConditionDuplicationPhase>();
    pipeline.RunPrintAndVerify(BranchConditionDuplicationPhase::phase_name(),
                               true);

    pipeline.Run<VerifyGraphPhase>(true);

    pipeline.ComputeScheduledGraph();
    DCHECK_NOT_NULL(data.schedule());

    // First run code generation on a copy of the pipeline, in order to be able
    // to repeat it for jump optimization. The first run has to happen on a
    // temporary pipeline to avoid deletion of zones on the main pipeline.
    TFPipelineData second_data(
        &zone_stats, &info, isolate, isolate->allocator(), data.graph(),
        data.jsgraph(), data.schedule(), data.source_positions(),
        data.node_origins(), data.jump_optimization_info(), options,
        profile_data);
    PipelineJobScope second_scope(&second_data,
                                  isolate->counters()->runtime_call_stats());
    second_data.set_verify_graph(v8_flags.verify_csa);
    PipelineImpl second_pipeline(&second_data);
    second_pipeline.SelectInstructionsAndAssemble(call_descriptor);

    if (v8_flags.turbo_profiling) {
      info.profiler_data()->SetHash(initial_graph_hash);
    }

    if (jump_opt.is_optimizable()) {
      jump_opt.set_optimizing();
      return pipeline.GenerateCode(call_descriptor);
    } else {
      return second_pipeline.FinalizeCode();
    }
  }
}

MaybeHandle<Code> Pipeline::GenerateCodeForTurboshaftBuiltin(
    turboshaft::PipelineData* turboshaft_data, CallDescriptor* call_descriptor,
    Builtin builtin, const char* debug_name,
    const ProfileDataFromFile* profile_data) {
  DCHECK_EQ(builtin, turboshaft_data->info()->builtin());
  Isolate* isolate = turboshaft_data->isolate();

#if V8_ENABLE_EXPERIMENTAL_TSA_BUILTINS
// TODO(nicohartmann): Use during development and remove afterwards.
#ifdef DEBUG
  std::cout << "=== Generating Builtin '" << debug_name
            << "' with Turboshaft ===" << std::endl;
#endif

#endif

  // Initialize JumpOptimizationInfo if required.
  JumpOptimizationInfo jump_opt;
  bool should_optimize_jumps =
      isolate->serializer_enabled() && v8_flags.turbo_rewrite_far_jumps &&
      !v8_flags.turbo_profiling && !v8_flags.dump_builtins_hashes_to_file;
  JumpOptimizationInfo* jump_optimization_info =
      should_optimize_jumps ? &jump_opt : nullptr;

  PipelineJobScope scope(turboshaft_data,
                         isolate->counters()->runtime_call_stats());
  RCS_SCOPE(isolate, RuntimeCallCounterId::kOptimizeCode);

  std::unique_ptr<TurbofanPipelineStatistics> pipeline_statistics(
      CreatePipelineStatistics(Handle<Script>::null(), turboshaft_data->info(),
                               isolate, turboshaft_data->zone_stats()));

  turboshaft::BuiltinPipeline turboshaft_pipeline(turboshaft_data);
  OptimizedCompilationInfo* info = turboshaft_data->info();
  if (info->trace_turbo_graph() || info->trace_turbo_json()) {
    turboshaft::ZoneWithName<turboshaft::kTempZoneName> print_zone(
        turboshaft_data->zone_stats(), turboshaft::kTempZoneName);
    std::vector<char> name_buffer(strlen("TSA: ") + strlen(debug_name) + 1);
    memcpy(name_buffer.data(), "TSA: ", 5);
    memcpy(name_buffer.data() + 5, debug_name, strlen(debug_name));
    turboshaft_pipeline.PrintGraph(print_zone, name_buffer.data());
  }

  // Validate pgo profile.
  const int initial_graph_hash =
      ComputeInitialGraphHash(builtin, profile_data, &turboshaft_data->graph());
  profile_data =
      ValidateProfileData(profile_data, initial_graph_hash, debug_name);

  turboshaft_pipeline.OptimizeBuiltin();
  Linkage linkage(call_descriptor);
  return turboshaft_pipeline.GenerateCode(&linkage, {}, jump_optimization_info,
                                          profile_data, initial_graph_hash);
}

#if V8_ENABLE_WEBASSEMBLY

namespace {

wasm::WasmCompilationResult WrapperCompilationResult(
    CodeGenerator* code_generator, CallDescriptor* call_descriptor,
    CodeKind kind) {
  wasm::WasmCompilationResult result;
  code_generator->masm()->GetCode(
      nullptr, &result.code_desc, code_generator->safepoint_table_builder(),
      static_cast<int>(code_generator->handler_table_offset()));
  result.instr_buffer = code_generator->masm()->ReleaseBuffer();
  result.source_positions = code_generator->GetSourcePositionTable();
  result.protected_instructions_data =
      code_generator->GetProtectedInstructionsData();
  result.frame_slot_count = code_generator->frame()->GetTotalFrameSlotCount();
  result.tagged_parameter_slots = call_descriptor->GetTaggedParameterSlots();
  result.result_tier = wasm::ExecutionTier::kTurbofan;
  if (kind == CodeKind::WASM_TO_JS_FUNCTION) {
    result.kind = wasm::WasmCompilationResult::kWasmToJsWrapper;
  }
  return result;
}

void TraceFinishWrapperCompilation(OptimizedCompilationInfo& info,
                                   CodeTracer* code_tracer,
                                   const wasm::WasmCompilationResult& result,
                                   CodeGenerator* code_generator) {
  if (info.trace_turbo_json()) {
    TurboJsonFile json_of(&info, std::ios_base::app);
    json_of << "{\"name\":\"disassembly\",\"type\":\"disassembly\""
            << BlockStartsAsJSON{&code_generator->block_starts()}
            << "\"data\":\"";
#ifdef ENABLE_DISASSEMBLER
    std::stringstream disassembler_stream;
    Disassembler::Decode(
        nullptr, disassembler_stream, result.code_desc.buffer,
        result.code_desc.buffer + result.code_desc.safepoint_table_offset,
        CodeReference(&result.code_desc));
    for (auto const c : disassembler_stream.str()) {
      json_of << AsEscapedUC16ForJSON(c);
    }
#endif  // ENABLE_DISASSEMBLER
    json_of << "\"}\n]";
    json_of << "\n}";
  }

  if (info.trace_turbo_json() || info.trace_turbo_graph()) {
    CodeTracer::StreamScope tracing_scope(code_tracer);
    tracing_scope.stream()
        << "---------------------------------------------------\n"
        << "Finished compiling method " << info.GetDebugName().get()
        << " using TurboFan" << std::endl;
  }
}

}  // namespace

// static
wasm::WasmCompilationResult Pipeline::GenerateCodeForWasmNativeStub(
    CallDescriptor* call_descriptor, MachineGraph* mcgraph, CodeKind kind,
    const char* debug_name, const AssemblerOptions& options,
    SourcePositionTable* source_positions) {
  Graph* graph = mcgraph->graph();
  OptimizedCompilationInfo info(base::CStrVector(debug_name), graph->zone(),
                                kind);
  // Construct a pipeline for scheduling and code generation.
  wasm::WasmEngine* wasm_engine = wasm::GetWasmEngine();
  ZoneStats zone_stats(wasm_engine->allocator());
  NodeOriginTable* node_positions = graph->zone()->New<NodeOriginTable>(graph);
  TFPipelineData data(&zone_stats, wasm_engine, &info, mcgraph, nullptr,
                      source_positions, node_positions, options);
  std::unique_ptr<TurbofanPipelineStatistics> pipeline_statistics;
  if (v8_flags.turbo_stats || v8_flags.turbo_stats_nvp) {
    pipeline_statistics.reset(new TurbofanPipelineStatistics(
        &info, wasm_engine->GetOrCreateTurboStatistics(), &zone_stats));
    pipeline_statistics->BeginPhaseKind("V8.WasmStubCodegen");
  }
  TraceWrapperCompilation("TurboFan", &info, &data);

  PipelineImpl pipeline(&data);
  pipeline.RunPrintAndVerify("V8.WasmNativeStubMachineCode", true);

  pipeline.Run<MemoryOptimizationPhase>();
  pipeline.RunPrintAndVerify(MemoryOptimizationPhase::phase_name(), true);

  pipeline.ComputeScheduledGraph();

  Linkage linkage(call_descriptor);
  CHECK(pipeline.SelectInstructions(&linkage));
  pipeline.AssembleCode(&linkage);

  auto result = WrapperCompilationResult(pipeline.code_generator(),
                                         call_descriptor, kind);
  DCHECK(result.succeeded());
  CodeTracer* code_tracer = nullptr;
  if (info.trace_turbo_json() || info.trace_turbo_graph()) {
    code_tracer = data.GetCodeTracer();
  }
  TraceFinishWrapperCompilation(info, code_tracer, result,
                                pipeline.code_generator());
  return result;
}

// static
wasm::WasmCompilationResult
Pipeline::GenerateCodeForWasmNativeStubFromTurboshaft(
    const wasm::CanonicalSig* sig, wasm::WrapperCompilationInfo wrapper_info,
    const char* debug_name, const AssemblerOptions& options,
    SourcePositionTable* source_positions) {
  wasm::WasmEngine* wasm_engine = wasm::GetWasmEngine();
  Zone zone(wasm_engine->allocator(), ZONE_NAME, kCompressGraphZone);
  WasmCallKind call_kind =
      wrapper_info.code_kind == CodeKind::WASM_TO_JS_FUNCTION
          ? WasmCallKind::kWasmImportWrapper
          : WasmCallKind::kWasmCapiFunction;
  CallDescriptor* call_descriptor =
      GetWasmCallDescriptor(&zone, sig, call_kind);
  if (!Is64()) {
    call_descriptor = GetI32WasmCallDescriptor(&zone, call_descriptor);
  }
  Linkage linkage(call_descriptor);
  OptimizedCompilationInfo info(base::CStrVector(debug_name), &zone,
                                wrapper_info.code_kind);
  ZoneStats zone_stats(wasm_engine->allocator());
  TFPipelineData data(&zone_stats, &info, nullptr,
                      wasm::GetWasmEngine()->allocator(), nullptr, nullptr,
                      nullptr, nullptr, nullptr, nullptr, options, nullptr);
  std::unique_ptr<TurbofanPipelineStatistics> pipeline_statistics;
  if (v8_flags.turbo_stats || v8_flags.turbo_stats_nvp) {
    pipeline_statistics.reset(new TurbofanPipelineStatistics(
        &info, wasm_engine->GetOrCreateTurboStatistics(), &zone_stats));
    pipeline_statistics->BeginPhaseKind("V8.WasmStubCodegen");
  }
  TraceWrapperCompilation("Turboshaft", &info, &data);

  PipelineImpl pipeline(&data);

  {
    turboshaft::PipelineData turboshaft_data(
        &zone_stats, turboshaft::TurboshaftPipelineKind::kWasm, nullptr, &info,
        options);
    turboshaft_data.SetIsWasmWrapper(sig);
    AccountingAllocator allocator;
    turboshaft_data.InitializeGraphComponent(source_positions);
    BuildWasmWrapper(&turboshaft_data, &allocator, turboshaft_data.graph(), sig,
                     wrapper_info);
    CodeTracer* code_tracer = nullptr;
    if (info.trace_turbo_graph()) {
      // NOTE: We must not call `GetCodeTracer` if tracing is not enabled,
      // because it may not yet be initialized then and doing so from the
      // background thread is not threadsafe.
      code_tracer = data.GetCodeTracer();
    }
    Zone printing_zone(&allocator, ZONE_NAME);
    turboshaft::PrintTurboshaftGraph(&turboshaft_data, &printing_zone,
                                     code_tracer, "Graph generation");

    // Skip the LoopUnrolling, WasmGCOptimize and WasmLowering phases for
    // wrappers.
    // TODO(14108): Do we need value numbering if wasm_opt is turned off?
    turboshaft::Pipeline turboshaft_pipeline(&turboshaft_data);
    if (v8_flags.wasm_opt) {
      turboshaft_pipeline.Run<turboshaft::WasmOptimizePhase>();
    }

    if (!Is64()) {
      turboshaft_pipeline.Run<turboshaft::Int64LoweringPhase>();
    }

    // This is more than an optimization currently: We need it to sort blocks to
    // work around a bug in RecreateSchedulePhase.
    turboshaft_pipeline.Run<turboshaft::WasmDeadCodeEliminationPhase>();

    if (V8_UNLIKELY(v8_flags.turboshaft_enable_debug_features)) {
      // This phase has to run very late to allow all previous phases to use
      // debug features.
      turboshaft_pipeline.Run<turboshaft::DebugFeatureLoweringPhase>();
    }

    data.BeginPhaseKind("V8.InstructionSelection");

#ifdef TARGET_SUPPORTS_TURBOSHAFT_INSTRUCTION_SELECTION
    bool use_turboshaft_instruction_selection =
        v8_flags.turboshaft_wasm_instruction_selection_staged;
#else
    bool use_turboshaft_instruction_selection =
        v8_flags.turboshaft_wasm_instruction_selection_experimental;
#endif

    const bool success = GenerateCodeFromTurboshaftGraph(
        use_turboshaft_instruction_selection, &linkage, turboshaft_pipeline,
        &pipeline, data.osr_helper_ptr());
    CHECK(success);

    if (use_turboshaft_instruction_selection) {
      auto result =
          WrapperCompilationResult(turboshaft_data.code_generator(),
                                   call_descriptor, wrapper_info.code_kind);
      DCHECK(result.succeeded());

      CodeTracer* code_tracer = nullptr;
      if (info.trace_turbo_json() || info.trace_turbo_graph()) {
        code_tracer = turboshaft_data.GetCodeTracer();
      }
      TraceFinishWrapperCompilation(info, code_tracer, result,
                                    turboshaft_data.code_generator());
      return result;
    } else {
      auto result = WrapperCompilationResult(
          pipeline.code_generator(), call_descriptor, wrapper_info.code_kind);
      DCHECK(result.succeeded());

      CodeTracer* code_tracer = nullptr;
      if (info.trace_turbo_json() || info.trace_turbo_graph()) {
        code_tracer = data.GetCodeTracer();
      }
      TraceFinishWrapperCompilation(info, code_tracer, result,
                                    pipeline.code_generator());
      return result;
    }
  }
}

namespace {

void LowerInt64(const wasm::FunctionSig* sig, MachineGraph* mcgraph,
                SimplifiedOperatorBuilder* simplified, PipelineImpl& pipeline) {
  if (mcgraph->machine()->Is64()) return;

  Signature<MachineRepresentation>::Builder builder(
      mcgraph->zone(), sig->return_count(), sig->parameter_count());
  for (auto ret : sig->returns()) {
    builder.AddReturn(ret.machine_representation());
  }
  for (auto param : sig->parameters()) {
    builder.AddParam(param.machine_representation());
  }
  Signature<MachineRepresentation>* signature = builder.Get();

  Int64Lowering r(mcgraph->graph(), mcgraph->machine(), mcgraph->common(),
                  simplified, mcgraph->zone(), signature);
  r.LowerGraph();
  pipeline.RunPrintAndVerify("V8.Int64Lowering", true);
}

base::OwnedVector<uint8_t> SerializeInliningPositions(
    const ZoneVector<WasmInliningPosition>& positions) {
  const size_t entry_size = sizeof positions[0].in
```