Response: The user wants to understand the functionality of the provided C++ code snippet, which is the second part of a three-part file. The file seems to define different optimization phases within the V8 JavaScript engine's Turbofan compiler pipeline.

**Plan:**

1. **Identify the core concept:** The code defines structs that represent different phases in an optimization pipeline. Each struct has a `Run` method that performs specific optimizations.
2. **Summarize each phase:** Briefly describe what each `Run` method does, focusing on the types of optimizations performed (e.g., dead code elimination, branch elimination, register allocation).
3. **Connect to JavaScript:** If a phase directly relates to how JavaScript code is optimized, provide a simple JavaScript example illustrating the benefit of that optimization.
这是v8/src/compiler/pipeline.cc文件的第二部分，延续了第一部分定义编译优化管道中各个阶段的概念。本部分主要定义了以下几个关键的编译优化阶段：

**核心功能：定义和实现了多种编译优化阶段，这些阶段是V8的Turbofan编译器在将JavaScript代码或WebAssembly代码转换为机器码过程中执行的。**

**具体阶段功能归纳：**

* **`WasmGCLoweringPhase`:**  针对WebAssembly的垃圾回收（GC）相关操作进行底层转换。它将高级的Wasm GC指令转换为更底层的、机器可执行的操作。
* **`WasmOptimizationPhase`:**  对WebAssembly代码进行优化。它包含多个优化子阶段，例如机器操作符简化、死代码消除、公共子表达式消除、值编号以及加载消除等。这个阶段分两个回合运行，分别侧重于加载消除和分支消除，以避免性能问题。
* **`WasmJSLoweringPhase`:**  将WebAssembly特定的操作转换为更通用的JavaScript操作。这可能涉及到与JavaScript环境交互所需的桥接代码的生成。
* **`CsaEarlyOptimizationPhase`:**  针对CodeStubAssembler (CSA) 生成的代码进行早期优化。类似于 `WasmOptimizationPhase`，它也包含加载消除和分支消除等优化。
* **`CsaOptimizationPhase`:**  对CSA生成的代码进行进一步优化，包括分支消除、死代码消除、机器操作符简化、公共子表达式消除、值编号以及成对加载/存储优化（如果目标架构支持）。
* **`ComputeSchedulePhase`:**  计算指令的执行顺序（调度）。它决定了在目标机器上以何种顺序执行各个操作，以提高性能。
* **`RevectorizePhase` (启用 `V8_ENABLE_WASM_SIMD256_REVEC` 时):**  针对WebAssembly SIMD (Single Instruction, Multiple Data) 指令进行重新向量化，以提高并行执行效率。
* **`InstructionSelectionPhase`:**  将图中的节点（表示操作）映射到目标机器的指令。这个阶段会根据目标架构选择合适的机器指令。
* **`BitcastElisionPhase`:**  消除不必要的类型转换操作 (bitcast)。如果一个值的位模式在不同类型之间没有实际变化，则可以消除转换操作。
* **寄存器分配相关阶段 (`MeetRegisterConstraintsPhase`, `ResolvePhisPhase`, `BuildLiveRangesPhase`, `BuildBundlesPhase`, `AllocateGeneralRegistersPhase`, `AllocateFPRegistersPhase`, `AllocateSimd128RegistersPhase`, `DecideSpillingModePhase`, `AssignSpillSlotsPhase`, `CommitAssignmentPhase`, `PopulateReferenceMapsPhase`, `ConnectRangesPhase`, `ResolveControlFlowPhase`):**  这些阶段负责将程序中的变量分配到目标机器的寄存器中。这是一个复杂的过程，需要考虑寄存器的使用限制、变量的生命周期以及控制流等因素。如果寄存器不足，则需要进行溢出 (spilling)，即将部分变量存储到内存中。
* **`OptimizeMovesPhase`:**  优化数据移动指令，例如消除冗余的移动操作。
* **`FrameElisionPhase`:**  省略不必要的栈帧创建和销毁操作，以提高函数调用的效率。
* **`JumpThreadingPhase`:**  优化跳转指令，例如将跳转到另一个跳转指令的情况优化为直接跳转到最终目标。
* **`AssembleCodePhase`:**  将选择好的机器指令组装成最终的机器码。
* **`FinalizeCodePhase`:**  完成代码生成的最后步骤，例如生成代码对象。
* **`PrintGraphPhase`:**  用于调试和诊断，将当前的编译器中间表示（图）打印出来，方便开发者理解编译过程中的变化。
* **`VerifyGraphPhase`:**  用于验证编译器中间表示的正确性，帮助发现编译器中的错误。

**与 JavaScript 功能的关系及 JavaScript 示例：**

这些优化阶段的目标都是提升 JavaScript 代码的执行效率。虽然这些阶段在 C++ 代码中实现，但它们直接影响着 JavaScript 代码的性能。

例如，`DeadCodeElimination` 阶段会移除永远不会被执行到的 JavaScript 代码，从而减少生成的机器码大小，并可能减少执行时间。

```javascript
function example(x) {
  if (x > 10) {
    console.log("x is greater than 10");
    return x * 2;
  } else {
    // 这部分代码在 x 始终大于 10 的情况下永远不会执行
    console.log("x is not greater than 10");
    return x + 5;
  }
  // 这行代码无论如何都不会执行到，会被 DeadCodeElimination 移除
  console.log("This will never be printed");
}

example(15); // 假设在实际运行中，example 总是以大于 10 的参数调用
```

在这个例子中，如果 `example` 函数在实际运行中总是以大于 10 的参数调用，那么 `else` 语句块中的代码将永远不会被执行到。`DeadCodeElimination` 阶段会识别出这种情况，并从最终生成的机器码中移除 `console.log("x is not greater than 10");` 和 `return x + 5;` 这两行对应的机器指令，以及最后的 `console.log("This will never be printed");`。

另一个例子是 `BranchElimination` 阶段。如果编译器能够确定某个条件表达式的结果在编译时总是为真或假，那么它可以消除不必要的条件分支。

```javascript
const isDebugMode = false;

function logMessage(message) {
  if (isDebugMode) {
    console.log("Debug:", message);
  }
}

logMessage("Something happened");
```

在这个例子中，`isDebugMode` 在编译时是常量 `false`。`BranchElimination` 阶段会识别出 `if (isDebugMode)` 的条件永远为假，因此可以完全移除 `if` 语句块中的代码，避免生成不必要的条件跳转指令。

**总结：**

这部分代码定义了 V8 编译器中用于优化 JavaScript 和 WebAssembly 代码的关键步骤。这些阶段通过各种技术，例如消除冗余代码、简化操作、优化内存访问和寄存器分配等，最终生成高效的机器码，从而提高 JavaScript 代码的执行速度。 这些优化对开发者来说是透明的，但它们是 V8 引擎实现高性能的关键组成部分。

Prompt: 
```
这是目录为v8/src/compiler/pipeline.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
(data, &graph_reducer, &load_elimination);
    AddReducer(data, &graph_reducer, &wasm_gc);
    AddReducer(data, &graph_reducer, &dead_code_elimination);
    graph_reducer.ReduceGraph();
  }
};

struct SimplifyLoopsPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(SimplifyLoops)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    GraphReducer graph_reducer(
        temp_zone, data->graph(), &data->info()->tick_counter(), data->broker(),
        data->jsgraph()->Dead(), data->observe_node_manager());
    SimplifyTFLoops simplify_loops(&graph_reducer, data->mcgraph());
    AddReducer(data, &graph_reducer, &simplify_loops);
    graph_reducer.ReduceGraph();
  }
};

struct WasmGCLoweringPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(WasmGCLowering)

  void Run(TFPipelineData* data, Zone* temp_zone,
           const wasm::WasmModule* module) {
    GraphReducer graph_reducer(
        temp_zone, data->graph(), &data->info()->tick_counter(), data->broker(),
        data->jsgraph()->Dead(), data->observe_node_manager());
    WasmGCLowering lowering(&graph_reducer, data->mcgraph(), module, false,
                            data->source_positions());
    DeadCodeElimination dead_code_elimination(&graph_reducer, data->graph(),
                                              data->common(), temp_zone);
    AddReducer(data, &graph_reducer, &lowering);
    AddReducer(data, &graph_reducer, &dead_code_elimination);
    graph_reducer.ReduceGraph();
  }
};

struct WasmOptimizationPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(WasmOptimization)

  void Run(TFPipelineData* data, Zone* temp_zone,
           MachineOperatorReducer::SignallingNanPropagation
               signalling_nan_propagation,
           wasm::WasmDetectedFeatures detected_features) {
    // Run optimizations in two rounds: First one around load elimination and
    // then one around branch elimination. This is because those two
    // optimizations sometimes display quadratic complexity when run together.
    // We only need load elimination for managed objects.
    if (detected_features.has_gc()) {
      GraphReducer graph_reducer(temp_zone, data->graph(),
                                 &data->info()->tick_counter(), data->broker(),
                                 data->jsgraph()->Dead(),
                                 data->observe_node_manager());
      MachineOperatorReducer machine_reducer(&graph_reducer, data->jsgraph(),
                                             signalling_nan_propagation);
      DeadCodeElimination dead_code_elimination(&graph_reducer, data->graph(),
                                                data->common(), temp_zone);
      CommonOperatorReducer common_reducer(
          &graph_reducer, data->graph(), data->broker(), data->common(),
          data->machine(), temp_zone, BranchSemantics::kMachine);
      ValueNumberingReducer value_numbering(temp_zone, data->graph()->zone());
      CsaLoadElimination load_elimination(&graph_reducer, data->jsgraph(),
                                          temp_zone);
      WasmEscapeAnalysis escape(&graph_reducer, data->mcgraph());
      AddReducer(data, &graph_reducer, &machine_reducer);
      AddReducer(data, &graph_reducer, &dead_code_elimination);
      AddReducer(data, &graph_reducer, &common_reducer);
      AddReducer(data, &graph_reducer, &value_numbering);
      AddReducer(data, &graph_reducer, &load_elimination);
      AddReducer(data, &graph_reducer, &escape);
      graph_reducer.ReduceGraph();
    }
    {
      GraphReducer graph_reducer(temp_zone, data->graph(),
                                 &data->info()->tick_counter(), data->broker(),
                                 data->jsgraph()->Dead(),
                                 data->observe_node_manager());
      MachineOperatorReducer machine_reducer(&graph_reducer, data->jsgraph(),
                                             signalling_nan_propagation);
      DeadCodeElimination dead_code_elimination(&graph_reducer, data->graph(),
                                                data->common(), temp_zone);
      CommonOperatorReducer common_reducer(
          &graph_reducer, data->graph(), data->broker(), data->common(),
          data->machine(), temp_zone, BranchSemantics::kMachine);
      ValueNumberingReducer value_numbering(temp_zone, data->graph()->zone());
      BranchElimination branch_condition_elimination(
          &graph_reducer, data->jsgraph(), temp_zone);
      AddReducer(data, &graph_reducer, &machine_reducer);
      AddReducer(data, &graph_reducer, &dead_code_elimination);
      AddReducer(data, &graph_reducer, &common_reducer);
      AddReducer(data, &graph_reducer, &value_numbering);
      AddReducer(data, &graph_reducer, &branch_condition_elimination);
      graph_reducer.ReduceGraph();
    }
  }
};

struct WasmJSLoweringPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(WasmJSLowering)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    GraphReducer graph_reducer(
        temp_zone, data->graph(), &data->info()->tick_counter(), data->broker(),
        data->jsgraph()->Dead(), data->observe_node_manager());
    WasmJSLowering lowering(&graph_reducer, data->jsgraph(),
                            data->source_positions());
    AddReducer(data, &graph_reducer, &lowering);
    graph_reducer.ReduceGraph();
  }
};
#endif  // V8_ENABLE_WEBASSEMBLY

struct CsaEarlyOptimizationPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(CSAEarlyOptimization)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    // Run optimizations in two rounds: First one around load elimination and
    // then one around branch elimination. This is because those two
    // optimizations sometimes display quadratic complexity when run together.
    {
      GraphReducer graph_reducer(temp_zone, data->graph(),
                                 &data->info()->tick_counter(), data->broker(),
                                 data->jsgraph()->Dead(),
                                 data->observe_node_manager());
      MachineOperatorReducer machine_reducer(
          &graph_reducer, data->jsgraph(),
          MachineOperatorReducer::kPropagateSignallingNan);
      DeadCodeElimination dead_code_elimination(&graph_reducer, data->graph(),
                                                data->common(), temp_zone);
      CommonOperatorReducer common_reducer(
          &graph_reducer, data->graph(), data->broker(), data->common(),
          data->machine(), temp_zone, BranchSemantics::kMachine);
      ValueNumberingReducer value_numbering(temp_zone, data->graph()->zone());
      CsaLoadElimination load_elimination(&graph_reducer, data->jsgraph(),
                                          temp_zone);
      AddReducer(data, &graph_reducer, &machine_reducer);
      AddReducer(data, &graph_reducer, &dead_code_elimination);
      AddReducer(data, &graph_reducer, &common_reducer);
      AddReducer(data, &graph_reducer, &value_numbering);
      AddReducer(data, &graph_reducer, &load_elimination);
      graph_reducer.ReduceGraph();
    }
    {
      GraphReducer graph_reducer(temp_zone, data->graph(),
                                 &data->info()->tick_counter(), data->broker(),
                                 data->jsgraph()->Dead(),
                                 data->observe_node_manager());
      MachineOperatorReducer machine_reducer(
          &graph_reducer, data->jsgraph(),
          MachineOperatorReducer::kPropagateSignallingNan);
      DeadCodeElimination dead_code_elimination(&graph_reducer, data->graph(),
                                                data->common(), temp_zone);
      CommonOperatorReducer common_reducer(
          &graph_reducer, data->graph(), data->broker(), data->common(),
          data->machine(), temp_zone, BranchSemantics::kMachine);
      ValueNumberingReducer value_numbering(temp_zone, data->graph()->zone());
      BranchElimination branch_condition_elimination(
          &graph_reducer, data->jsgraph(), temp_zone);
      AddReducer(data, &graph_reducer, &machine_reducer);
      AddReducer(data, &graph_reducer, &dead_code_elimination);
      AddReducer(data, &graph_reducer, &common_reducer);
      AddReducer(data, &graph_reducer, &value_numbering);
      AddReducer(data, &graph_reducer, &branch_condition_elimination);
      graph_reducer.ReduceGraph();
    }
  }
};

struct CsaOptimizationPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(CSAOptimization)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    GraphReducer graph_reducer(
        temp_zone, data->graph(), &data->info()->tick_counter(), data->broker(),
        data->jsgraph()->Dead(), data->observe_node_manager());
    BranchElimination branch_condition_elimination(&graph_reducer,
                                                   data->jsgraph(), temp_zone);
    DeadCodeElimination dead_code_elimination(&graph_reducer, data->graph(),
                                              data->common(), temp_zone);
    MachineOperatorReducer machine_reducer(
        &graph_reducer, data->jsgraph(),
        MachineOperatorReducer::kPropagateSignallingNan);
    CommonOperatorReducer common_reducer(
        &graph_reducer, data->graph(), data->broker(), data->common(),
        data->machine(), temp_zone, BranchSemantics::kMachine);
    ValueNumberingReducer value_numbering(temp_zone, data->graph()->zone());
    PairLoadStoreReducer pair_load_store_reducer(
        &graph_reducer, data->jsgraph(), data->isolate());
    AddReducer(data, &graph_reducer, &branch_condition_elimination);
    AddReducer(data, &graph_reducer, &dead_code_elimination);
    AddReducer(data, &graph_reducer, &machine_reducer);
    AddReducer(data, &graph_reducer, &common_reducer);
    AddReducer(data, &graph_reducer, &value_numbering);
    if (data->machine()->SupportsLoadStorePairs()) {
      AddReducer(data, &graph_reducer, &pair_load_store_reducer);
    }
    graph_reducer.ReduceGraph();
  }
};

struct ComputeSchedulePhase {
  DECL_PIPELINE_PHASE_CONSTANTS(Scheduling)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    Schedule* schedule = Scheduler::ComputeSchedule(
        temp_zone, data->graph(),
        data->info()->splitting() ? Scheduler::kSplitNodes
                                  : Scheduler::kNoFlags,
        &data->info()->tick_counter(), data->profile_data());
    data->set_schedule(schedule);
  }
};

#if V8_ENABLE_WASM_SIMD256_REVEC
struct RevectorizePhase {
  DECL_PIPELINE_PHASE_CONSTANTS(Revectorizer)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    Revectorizer revec(temp_zone, data->graph(), data->mcgraph(),
                       data->source_positions());
    revec.TryRevectorize(data->info()->GetDebugName().get());
  }
};
#endif  // V8_ENABLE_WASM_SIMD256_REVEC

struct InstructionSelectionPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(SelectInstructions)

  std::optional<BailoutReason> Run(TFPipelineData* data, Zone* temp_zone,
                                   Linkage* linkage) {
    InstructionSelector selector = InstructionSelector::ForTurbofan(
        temp_zone, data->graph()->NodeCount(), linkage, data->sequence(),
        data->schedule(), data->source_positions(), data->frame(),
        data->info()->switch_jump_table()
            ? InstructionSelector::kEnableSwitchJumpTable
            : InstructionSelector::kDisableSwitchJumpTable,
        &data->info()->tick_counter(), data->broker(),
        data->address_of_max_unoptimized_frame_height(),
        data->address_of_max_pushed_argument_count(),
        data->info()->source_positions()
            ? InstructionSelector::kAllSourcePositions
            : InstructionSelector::kCallSourcePositions,
        InstructionSelector::SupportedFeatures(),
        v8_flags.turbo_instruction_scheduling
            ? InstructionSelector::kEnableScheduling
            : InstructionSelector::kDisableScheduling,
        data->assembler_options().enable_root_relative_access
            ? InstructionSelector::kEnableRootsRelativeAddressing
            : InstructionSelector::kDisableRootsRelativeAddressing,
        data->info()->trace_turbo_json()
            ? InstructionSelector::kEnableTraceTurboJson
            : InstructionSelector::kDisableTraceTurboJson);
    if (std::optional<BailoutReason> bailout = selector.SelectInstructions()) {
      return bailout;
    }
    if (data->info()->trace_turbo_json()) {
      TurboJsonFile json_of(data->info(), std::ios_base::app);
      json_of << "{\"name\":\"" << phase_name()
              << "\",\"type\":\"instructions\""
              << InstructionRangesAsJSON{data->sequence(),
                                         &selector.instr_origins()}
              << "},\n";
    }
    return std::nullopt;
  }
};

struct BitcastElisionPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(BitcastElision)

  void Run(TFPipelineData* data, Zone* temp_zone, bool is_builtin) {
    BitcastElider bitcast_optimizer(temp_zone, data->graph(), is_builtin);
    bitcast_optimizer.Reduce();
  }
};

struct MeetRegisterConstraintsPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(MeetRegisterConstraints)
  void Run(TFPipelineData* data, Zone* temp_zone) {
    ConstraintBuilder builder(data->register_allocation_data());
    builder.MeetRegisterConstraints();
  }
};

struct ResolvePhisPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(ResolvePhis)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    ConstraintBuilder builder(data->register_allocation_data());
    builder.ResolvePhis();
  }
};

struct BuildLiveRangesPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(BuildLiveRanges)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    LiveRangeBuilder builder(data->register_allocation_data(), temp_zone);
    builder.BuildLiveRanges();
  }
};

struct BuildBundlesPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(BuildLiveRangeBundles)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    BundleBuilder builder(data->register_allocation_data());
    builder.BuildBundles();
  }
};

template <typename RegAllocator>
struct AllocateGeneralRegistersPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(AllocateGeneralRegisters)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    RegAllocator allocator(data->register_allocation_data(),
                           RegisterKind::kGeneral, temp_zone);
    allocator.AllocateRegisters();
  }
};

template <typename RegAllocator>
struct AllocateFPRegistersPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(AllocateFPRegisters)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    RegAllocator allocator(data->register_allocation_data(),
                           RegisterKind::kDouble, temp_zone);
    allocator.AllocateRegisters();
  }
};

template <typename RegAllocator>
struct AllocateSimd128RegistersPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(AllocateSimd128Registers)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    RegAllocator allocator(data->register_allocation_data(),
                           RegisterKind::kSimd128, temp_zone);
    allocator.AllocateRegisters();
  }
};

struct DecideSpillingModePhase {
  DECL_PIPELINE_PHASE_CONSTANTS(DecideSpillingMode)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    OperandAssigner assigner(data->register_allocation_data());
    assigner.DecideSpillingMode();
  }
};

struct AssignSpillSlotsPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(AssignSpillSlots)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    OperandAssigner assigner(data->register_allocation_data());
    assigner.AssignSpillSlots();
  }
};

struct CommitAssignmentPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(CommitAssignment)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    OperandAssigner assigner(data->register_allocation_data());
    assigner.CommitAssignment();
  }
};

struct PopulateReferenceMapsPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(PopulateReferenceMaps)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    ReferenceMapPopulator populator(data->register_allocation_data());
    populator.PopulateReferenceMaps();
  }
};

struct ConnectRangesPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(ConnectRanges)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    LiveRangeConnector connector(data->register_allocation_data());
    connector.ConnectRanges(temp_zone);
  }
};

struct ResolveControlFlowPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(ResolveControlFlow)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    LiveRangeConnector connector(data->register_allocation_data());
    connector.ResolveControlFlow(temp_zone);
  }
};

struct OptimizeMovesPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(OptimizeMoves)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    MoveOptimizer move_optimizer(temp_zone, data->sequence());
    move_optimizer.Run();
  }
};

struct FrameElisionPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(FrameElision)

  void Run(TFPipelineData* data, Zone* temp_zone, bool has_dummy_end_block) {
#if V8_ENABLE_WEBASSEMBLY
    bool is_wasm_to_js =
        data->info()->code_kind() == CodeKind::WASM_TO_JS_FUNCTION ||
        data->info()->builtin() == Builtin::kWasmToJsWrapperCSA;
#else
    bool is_wasm_to_js = false;
#endif
    FrameElider(data->sequence(), has_dummy_end_block, is_wasm_to_js).Run();
  }
};

struct JumpThreadingPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(JumpThreading)

  void Run(TFPipelineData* data, Zone* temp_zone, bool frame_at_start) {
    ZoneVector<RpoNumber> result(temp_zone);
    if (JumpThreading::ComputeForwarding(temp_zone, &result, data->sequence(),
                                         frame_at_start)) {
      JumpThreading::ApplyForwarding(temp_zone, result, data->sequence());
    }
  }
};

struct AssembleCodePhase {
  DECL_PIPELINE_PHASE_CONSTANTS(AssembleCode)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    data->code_generator()->AssembleCode();
  }
};

struct FinalizeCodePhase {
  DECL_MAIN_THREAD_PIPELINE_PHASE_CONSTANTS(FinalizeCode)

  void Run(TFPipelineData* data, Zone* temp_zone) {
    data->set_code(data->code_generator()->FinalizeCode());
  }
};

struct PrintGraphPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(PrintGraph)

  void Run(TFPipelineData* data, Zone* temp_zone, const char* phase) {
    OptimizedCompilationInfo* info = data->info();
    Graph* graph = data->graph();
    if (info->trace_turbo_json()) {  // Print JSON.
      UnparkedScopeIfNeeded scope(data->broker());
      AllowHandleDereference allow_deref;

      TurboJsonFile json_of(info, std::ios_base::app);
      json_of << "{\"name\":\"" << phase << "\",\"type\":\"graph\",\"data\":"
              << AsJSON(*graph, data->source_positions(), data->node_origins())
              << "},\n";
    }

    if (info->trace_turbo_scheduled()) {
      AccountingAllocator allocator;
      Schedule* schedule = data->schedule();
      if (schedule == nullptr) {
        schedule = Scheduler::ComputeSchedule(
            temp_zone, data->graph(), Scheduler::kNoFlags,
            &info->tick_counter(), data->profile_data());
      }

      UnparkedScopeIfNeeded scope(data->broker());
      AllowHandleDereference allow_deref;
      CodeTracer::StreamScope tracing_scope(data->GetCodeTracer());
      tracing_scope.stream()
          << "----- Graph after " << phase << " ----- " << std::endl
          << AsScheduledGraph(schedule);
    } else if (info->trace_turbo_graph()) {  // Simple textual RPO.
      UnparkedScopeIfNeeded scope(data->broker());
      AllowHandleDereference allow_deref;
      CodeTracer::StreamScope tracing_scope(data->GetCodeTracer());
      tracing_scope.stream()
          << "----- Graph after " << phase << " ----- " << std::endl
          << AsRPO(*graph);
    }
  }
};

struct VerifyGraphPhase {
  DECL_PIPELINE_PHASE_CONSTANTS(VerifyGraph)

  void Run(TFPipelineData* data, Zone* temp_zone, const bool untyped,
           bool values_only = false) {
    Verifier::CodeType code_type;
    switch (data->info()->code_kind()) {
      case CodeKind::WASM_FUNCTION:
      case CodeKind::WASM_TO_CAPI_FUNCTION:
      case CodeKind::WASM_TO_JS_FUNCTION:
      case CodeKind::JS_TO_WASM_FUNCTION:
      case CodeKind::C_WASM_ENTRY:
        code_type = Verifier::kWasm;
        break;
      default:
        code_type = Verifier::kDefault;
    }
    Verifier::Run(data->graph(), !untyped ? Verifier::TYPED : Verifier::UNTYPED,
                  values_only ? Verifier::kValuesOnly : Verifier::kAll,
                  code_type);
  }
};

#undef DECL_MAIN_THREAD_PIPELINE_PHASE_CONSTANTS
#undef DECL_PIPELINE_PHASE_CONSTANTS
#undef DECL_PIPELINE_PHASE_CONSTANTS_HELPER

#if V8_ENABLE_WEBASSEMBLY
class WasmHeapStubCompilationJob final : public TurbofanCompilationJob {
 public:
  WasmHeapStubCompilationJob(Isolate* isolate, CallDescriptor* call_descriptor,
                             std::unique_ptr<Zone> zone, Graph* graph,
                             CodeKind kind, std::unique_ptr<char[]> debug_name,
                             const AssemblerOptions& options)
      // Note that the OptimizedCompilationInfo is not initialized at the time
      // we pass it to the CompilationJob constructor, but it is not
      // dereferenced there.
      : TurbofanCompilationJob(&info_, CompilationJob::State::kReadyToExecute),
        debug_name_(std::move(debug_name)),
        info_(base::CStrVector(debug_name_.get()), graph->zone(), kind),
        call_descriptor_(call_descriptor),
        zone_stats_(zone->allocator()),
        zone_(std::move(zone)),
        graph_(graph),
        data_(&zone_stats_, &info_, isolate, wasm::GetWasmEngine()->allocator(),
              graph_, nullptr, nullptr, nullptr,
              zone_->New<NodeOriginTable>(graph_), nullptr, options, nullptr),
        pipeline_(&data_) {}

  WasmHeapStubCompilationJob(const WasmHeapStubCompilationJob&) = delete;
  WasmHeapStubCompilationJob& operator=(const WasmHeapStubCompilationJob&) =
      delete;

 protected:
  Status PrepareJobImpl(Isolate* isolate) final;
  Status ExecuteJobImpl(RuntimeCallStats* stats,
                        LocalIsolate* local_isolate) final;
  Status FinalizeJobImpl(Isolate* isolate) final;

 private:
  std::unique_ptr<char[]> debug_name_;
  OptimizedCompilationInfo info_;
  CallDescriptor* call_descriptor_;
  ZoneStats zone_stats_;
  std::unique_ptr<Zone> zone_;
  Graph* graph_;
  TFPipelineData data_;
  PipelineImpl pipeline_;
};

#if V8_ENABLE_WEBASSEMBLY
class WasmTurboshaftWrapperCompilationJob final
    : public turboshaft::TurboshaftCompilationJob {
 public:
  WasmTurboshaftWrapperCompilationJob(Isolate* isolate,
                                      const wasm::CanonicalSig* sig,
                                      wasm::WrapperCompilationInfo wrapper_info,
                                      std::unique_ptr<char[]> debug_name,
                                      const AssemblerOptions& options)
      // Note that the OptimizedCompilationInfo is not initialized at the time
      // we pass it to the CompilationJob constructor, but it is not
      // dereferenced there.
      : TurboshaftCompilationJob(&info_,
                                 CompilationJob::State::kReadyToExecute),
        zone_(wasm::GetWasmEngine()->allocator(), ZONE_NAME),
        debug_name_(std::move(debug_name)),
        info_(base::CStrVector(debug_name_.get()), &zone_,
              wrapper_info.code_kind),
        sig_(sig),
        wrapper_info_(wrapper_info),
        zone_stats_(zone_.allocator()),
        turboshaft_data_(
            &zone_stats_,
            wrapper_info_.code_kind == CodeKind::JS_TO_WASM_FUNCTION
                ? turboshaft::TurboshaftPipelineKind::kJSToWasm
                : turboshaft::TurboshaftPipelineKind::kWasm,
            isolate, &info_, options),
        data_(&zone_stats_, &info_, isolate, wasm::GetWasmEngine()->allocator(),
              nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, options,
              nullptr),
        pipeline_(&data_) {
    if (wrapper_info_.code_kind == CodeKind::WASM_TO_JS_FUNCTION) {
      call_descriptor_ = compiler::GetWasmCallDescriptor(
          &zone_, sig, WasmCallKind::kWasmImportWrapper);
      if (!Is64()) {
        call_descriptor_ = GetI32WasmCallDescriptor(&zone_, call_descriptor_);
      }
    } else {
      DCHECK_EQ(wrapper_info_.code_kind, CodeKind::JS_TO_WASM_FUNCTION);
      call_descriptor_ = Linkage::GetJSCallDescriptor(
          &zone_, false, static_cast<int>(sig->parameter_count()) + 1,
          CallDescriptor::kNoFlags);
    }
  }

  WasmTurboshaftWrapperCompilationJob(
      const WasmTurboshaftWrapperCompilationJob&) = delete;
  WasmTurboshaftWrapperCompilationJob& operator=(
      const WasmTurboshaftWrapperCompilationJob&) = delete;

 protected:
  Status PrepareJobImpl(Isolate* isolate) final;
  Status ExecuteJobImpl(RuntimeCallStats* stats,
                        LocalIsolate* local_isolate) final;
  Status FinalizeJobImpl(Isolate* isolate) final;

 private:
  Zone zone_;
  std::unique_ptr<char[]> debug_name_;
  OptimizedCompilationInfo info_;
  const wasm::CanonicalSig* sig_;
  wasm::WrapperCompilationInfo wrapper_info_;
  CallDescriptor* call_descriptor_;  // Incoming call descriptor.
  ZoneStats zone_stats_;
  turboshaft::PipelineData turboshaft_data_;
  TFPipelineData data_;
  PipelineImpl pipeline_;
};

// static
std::unique_ptr<TurbofanCompilationJob> Pipeline::NewWasmHeapStubCompilationJob(
    Isolate* isolate, CallDescriptor* call_descriptor,
    std::unique_ptr<Zone> zone, Graph* graph, CodeKind kind,
    std::unique_ptr<char[]> debug_name, const AssemblerOptions& options) {
  return std::make_unique<WasmHeapStubCompilationJob>(
      isolate, call_descriptor, std::move(zone), graph, kind,
      std::move(debug_name), options);
}

// static
std::unique_ptr<turboshaft::TurboshaftCompilationJob>
Pipeline::NewWasmTurboshaftWrapperCompilationJob(
    Isolate* isolate, const wasm::CanonicalSig* sig,
    wasm::WrapperCompilationInfo wrapper_info,
    std::unique_ptr<char[]> debug_name, const AssemblerOptions& options) {
  return std::make_unique<WasmTurboshaftWrapperCompilationJob>(
      isolate, sig, wrapper_info, std::move(debug_name), options);
}
#endif

CompilationJob::Status WasmHeapStubCompilationJob::PrepareJobImpl(
    Isolate* isolate) {
  UNREACHABLE();
}

namespace {
// Temporary helpers for logic shared by the TurboFan and Turboshaft wrapper
// compilation jobs. Remove them once wrappers are fully ported to Turboshaft.
void TraceWrapperCompilation(const char* compiler,
                             OptimizedCompilationInfo* info,
                             TFPipelineData* data) {
  if (info->trace_turbo_json() || info->trace_turbo_graph()) {
    CodeTracer::StreamScope tracing_scope(data->GetCodeTracer());
    tracing_scope.stream()
        << "---------------------------------------------------\n"
        << "Begin compiling method " << info->GetDebugName().get() << " using "
        << compiler << std::endl;
  }
  if (!v8_flags.turboshaft_wasm_wrappers && info->trace_turbo_graph()) {
    // Simple textual RPO.
    StdoutStream{} << "-- wasm stub " << CodeKindToString(info->code_kind())
                   << " graph -- " << std::endl
                   << AsRPO(*data->graph());
  }

  if (info->trace_turbo_json()) {
    TurboJsonFile json_of(info, std::ios_base::trunc);
    json_of << "{\"function\":\"" << info->GetDebugName().get()
            << "\", \"source\":\"\",\n\"phases\":[";
  }
}

void TraceWrapperCompilation(OptimizedCompilationInfo* info,
                             turboshaft::PipelineData* data) {
  if (info->trace_turbo_json() || info->trace_turbo_graph()) {
    CodeTracer::StreamScope tracing_scope(data->GetCodeTracer());
    tracing_scope.stream()
        << "---------------------------------------------------\n"
        << "Begin compiling method " << info->GetDebugName().get()
        << " using Turboshaft" << std::endl;
  }

  if (info->trace_turbo_json()) {
    TurboJsonFile json_of(info, std::ios_base::trunc);
    json_of << "{\"function\":\"" << info->GetDebugName().get()
            << "\", \"source\":\"\",\n\"phases\":[";
  }
}

CompilationJob::Status FinalizeWrapperCompilation(
    PipelineImpl* pipeline, OptimizedCompilationInfo* info,
    CallDescriptor* call_descriptor, Isolate* isolate,
    const char* method_name) {
  Handle<Code> code;
  if (!pipeline->FinalizeCode(call_descriptor).ToHandle(&code)) {
    V8::FatalProcessOutOfMemory(isolate, method_name);
  }
  DCHECK_NULL(pipeline->data()->dependencies());
  info->SetCode(code);
#ifdef ENABLE_DISASSEMBLER
  if (v8_flags.print_wasm_code) {
    CodeTracer::StreamScope tracing_scope(isolate->GetCodeTracer());
    code->Disassemble(info->GetDebugName().get(), tracing_scope.stream(),
                      isolate);
  }
#endif

    if (isolate->IsLoggingCodeCreation()) {
      PROFILE(isolate, CodeCreateEvent(LogEventListener::CodeTag::kStub,
                                       Cast<AbstractCode>(code),
                                       info->GetDebugName().get()));
    }
    // Set the wasm-to-js specific code fields needed to scan the incoming stack
    // parameters.
    if (code->kind() == CodeKind::WASM_TO_JS_FUNCTION) {
      code->set_wasm_js_tagged_parameter_count(
          call_descriptor->GetTaggedParameterSlots() & 0xffff);
      code->set_wasm_js_first_tagged_parameter(
          call_descriptor->GetTaggedParameterSlots() >> 16);
    }
    return CompilationJob::SUCCEEDED;
}

CompilationJob::Status FinalizeWrapperCompilation(
    turboshaft::PipelineData* turboshaft_data, OptimizedCompilationInfo* info,
    CallDescriptor* call_descriptor, Isolate* isolate,
    const char* method_name) {
  Handle<Code> code;
  turboshaft::Pipeline pipeline(turboshaft_data);
  if (!pipeline.FinalizeCode(call_descriptor).ToHandle(&code)) {
    V8::FatalProcessOutOfMemory(isolate, method_name);
  }
  DCHECK_NULL(turboshaft_data->depedencies());
  info->SetCode(code);
#ifdef ENABLE_DISASSEMBLER
  if (v8_flags.print_wasm_code) {
    CodeTracer::StreamScope tracing_scope(isolate->GetCodeTracer());
    code->Disassemble(info->GetDebugName().get(), tracing_scope.stream(),
                      isolate);
  }
#endif

  if (isolate->IsLoggingCodeCreation()) {
    PROFILE(isolate, CodeCreateEvent(LogEventListener::CodeTag::kStub,
                                     Cast<AbstractCode>(code),
                                     info->GetDebugName().get()));
  }
  if (code->kind() == CodeKind::WASM_TO_JS_FUNCTION) {
    code->set_wasm_js_tagged_parameter_count(
        call_descriptor->GetTaggedParameterSlots() & 0xffff);
    code->set_wasm_js_first_tagged_parameter(
        call_descriptor->GetTaggedParameterSlots() >> 16);
  }
  return CompilationJob::SUCCEEDED;
}
}  // namespace

CompilationJob::Status WasmHeapStubCompilationJob::ExecuteJobImpl(
    RuntimeCallStats* stats, LocalIsolate* local_isolate) {
  std::unique_ptr<TurbofanPipelineStatistics> pipeline_statistics;
  if (v8_flags.turbo_stats || v8_flags.turbo_stats_nvp) {
    pipeline_statistics.reset(new TurbofanPipelineStatistics(
        &info_, wasm::GetWasmEngine()->GetOrCreateTurboStatistics(),
        &zone_stats_));
    pipeline_statistics->BeginPhaseKind("V8.WasmStubCodegen");
  }
  TraceWrapperCompilation("Turbofan", &info_, &data_);
  pipeline_.RunPrintAndVerify("V8.WasmMachineCode", true);
  pipeline_.Run<MemoryOptimizationPhase>();
  pipeline_.ComputeScheduledGraph();
  if (pipeline_.SelectInstructionsAndAssemble(call_descriptor_)) {
    return CompilationJob::SUCCEEDED;
  }
  return CompilationJob::FAILED;
}

CompilationJob::Status WasmHeapStubCompilationJob::FinalizeJobImpl(
    Isolate* isolate) {
  return FinalizeWrapperCompilation(
      &pipeline_, &info_, call_descriptor_, isolate,
      "WasmHeapStubCompilationJob::FinalizeJobImpl");
}

CompilationJob::Status WasmTurboshaftWrapperCompilationJob::PrepareJobImpl(
    Isolate* isolate) {
  UNREACHABLE();
}

CompilationJob::Status WasmTurboshaftWrapperCompilationJob::ExecuteJobImpl(
    RuntimeCallStats* stats, LocalIsolate* local_isolate) {
  std::unique_ptr<TurbofanPipelineStatistics> pipeline_statistics;
  if (v8_flags.turbo_stats || v8_flags.turbo_stats_nvp) {
    pipeline_statistics.reset(new TurbofanPipelineStatistics(
        &info_, wasm::GetWasmEngine()->GetOrCreateTurboStatistics(),
        &zone_stats_));
    pipeline_statistics->BeginPhaseKind("V8.WasmStubCodegen");
  }
  TraceWrapperCompilation(&info_, &turboshaft_data_);
  Linkage linkage(call_descriptor_);

  turboshaft_data_.set_pipeline_statistics(pipeline_statistics.get());
  turboshaft_data_.SetIsWasmWrapper(sig_);

  AccountingAllocator allocator;
  turboshaft_data_.InitializeGraphComponent(nullptr);
  BuildWasmWrapper(&turboshaft_data_, &allocator, turboshaft_data_.graph(),
                   sig_, wrapper_info_);
  CodeTracer* code_tracer = nullptr;
  if (info_.trace_turbo_graph()) {
    // NOTE: We must not call `GetCodeTracer` if tracing is not enabled,
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
"""


```