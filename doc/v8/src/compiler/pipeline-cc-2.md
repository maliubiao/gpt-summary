Response:
My thinking process to analyze the provided C++ code snippet and fulfill the request goes like this:

1. **Understand the Goal:** The main goal is to analyze a portion of `v8/src/compiler/pipeline.cc` and describe its functionality, relating it to JavaScript if possible, and identifying potential user errors. The specific request emphasizes summarizing the functionality of *this particular section* (part 3 of 6).

2. **High-Level Structure Scan:** I first scanned the code for structural patterns. I noticed it's primarily composed of `struct` definitions, each named like `[Something]Phase`. These structs have a common pattern:
    * `DECL_PIPELINE_PHASE_CONSTANTS(...)`:  Likely a macro for defining constants related to the phase name.
    * `Run(...)`: A method that takes `TFPipelineData* data` and a `Zone* temp_zone` as arguments (sometimes with additional parameters).
    * Inside `Run`, there's a pattern of creating a `GraphReducer`, adding "reducers" to it using `AddReducer`, and then calling `graph_reducer.ReduceGraph()`.

3. **Identify Core Concepts:**  The repeated use of `GraphReducer`, `AddReducer`, and `ReduceGraph()` strongly suggests that this code deals with optimizing a program's intermediate representation (likely a control-flow graph). The "reducers" are probably individual optimization passes.

4. **Analyze Individual Phases:** I went through each `Phase` struct and tried to infer its purpose based on its name:
    * `SimplifyLoopsPhase`:  Likely focuses on simplifying loop structures in the graph.
    * `WasmGCLoweringPhase`:  Seems related to WebAssembly's garbage collection and lowering high-level GC operations to lower-level ones.
    * `WasmOptimizationPhase`:  A general optimization phase, potentially specific to WebAssembly. The comments mention two rounds of optimization (load elimination and branch elimination).
    * `WasmJSLoweringPhase`:  Appears to be about lowering WebAssembly-specific constructs to JavaScript-compatible ones.
    * `CsaEarlyOptimizationPhase`:  An early optimization phase, likely for CodeStubAssembler (CSA) generated code. Similar two-round structure as `WasmOptimizationPhase`.
    * `CsaOptimizationPhase`:  A later optimization phase for CSA code.
    * `ComputeSchedulePhase`:  Responsible for generating a schedule for the instructions in the graph, likely for better performance on the target architecture.
    * `RevectorizePhase`: Seems specific to WebAssembly SIMD (Single Instruction, Multiple Data) and involves rearranging operations for better vectorization.
    * `InstructionSelectionPhase`: A crucial phase where the abstract operations in the graph are translated into concrete machine instructions for the target architecture.
    * `BitcastElisionPhase`: Focuses on removing unnecessary bitcast operations.

5. **Connect to V8's Compilation Pipeline:** Knowing that this code resides in `v8/src/compiler/pipeline.cc`, I deduced that these phases represent distinct stages in V8's compilation process. The `TFPipelineData` likely holds the state that is passed between these phases.

6. **Relate to JavaScript (Where Possible):**  Many of these optimization phases are not directly visible in JavaScript code. However, I could reason about their *effects*:
    * Loop simplification can improve the performance of JavaScript `for` and `while` loops.
    * Dead code elimination removes unused code, making JavaScript execution faster and reducing memory usage.
    * Branch elimination optimizes conditional statements (`if`, `else`).
    * Instruction selection directly impacts how JavaScript code is executed by the underlying processor.

7. **Identify Potential Programming Errors:** I considered how JavaScript developers might write code that these optimization phases would act upon or where errors might arise:
    * Unnecessary type conversions could be targets for `BitcastElisionPhase`.
    * Complex or inefficient loops could be targets for `SimplifyLoopsPhase`.
    * Redundant calculations could be eliminated by the various optimization phases.
    * Overly complex conditional logic could be simplified by `BranchElimination`.

8. **Address Specific Constraints:**
    * **`.tq` Extension:** I noted that the code doesn't have a `.tq` extension, so it's regular C++ code, not Torque.
    * **JavaScript Examples:**  I provided simple JavaScript examples to illustrate the *effects* of the optimizations, even though the code itself doesn't directly manipulate JavaScript syntax.
    * **Input/Output (Hypothetical):** For some phases, I could give simple hypothetical examples of how the graph might change. For instance, a redundant calculation being removed.
    * **User Errors:**  I provided examples of JavaScript code patterns that might be improved by these optimization phases.

9. **Focus on Part 3:**  I paid close attention to the specific phases included in the provided snippet. My summary emphasized the functionality of *these* phases.

10. **Structure the Output:** I organized my answer into clear sections according to the prompt's requirements: Functionality, `.tq` check, JavaScript relation, Code logic, User errors, and Summary.

11. **Refine and Review:** I reviewed my answer for clarity, accuracy, and completeness, ensuring it addressed all aspects of the prompt. I tried to use precise terminology related to compilers and optimization where appropriate. I double-checked that my JavaScript examples were relevant.
这是目录为 `v8/src/compiler/pipeline.cc` 的 V8 源代码的第三部分。根据你提供的代码片段，我们可以归纳一下它的功能：

**主要功能：定义了多个编译器优化阶段（Phases），这些阶段是 Turbofan 编译管道的一部分，用于对中间表示（通常是图结构）进行转换和优化，最终生成高效的机器码。**

**详细功能分解：**

这段代码定义了一系列独立的结构体，每个结构体代表一个编译优化阶段。每个阶段都实现了 `Run` 方法，该方法接收 `TFPipelineData` 对象和一个 `Zone` 对象作为参数。`TFPipelineData` 包含了编译过程中的各种数据，例如抽象语法树（AST）转换成的图表示、类型信息、配置选项等。`Zone` 用于内存管理。

以下是每个阶段的具体功能：

* **`SimplifyLoopsPhase`**:  此阶段的目的是简化控制流图中的循环结构。这可能包括循环展开、循环不变代码外提等优化，以提高循环的执行效率。
* **`WasmGCLoweringPhase`**:  这个阶段专门针对 WebAssembly，负责将 WebAssembly 的垃圾回收（GC）相关的高级操作转换为更底层的操作，使其更容易被后续的编译阶段处理。
* **`WasmOptimizationPhase`**:  这是 WebAssembly 特定的优化阶段。它运行多轮优化，重点关注加载消除和分支消除。这是因为同时进行这两种优化有时会产生较高的复杂度。对于包含 GC 的 WebAssembly 模块，它还会进行逃逸分析。
* **`WasmJSLoweringPhase`**:  这个阶段负责将 WebAssembly 特有的结构“降低”到更通用的 JavaScript 可以理解的形式。这可能涉及到将 WebAssembly 的特定操作转换为 JavaScript 运行时可以处理的等效操作。
* **`CsaEarlyOptimizationPhase`**:  针对 CodeStubAssembler (CSA) 生成的代码的早期优化阶段。它也采用了类似于 `WasmOptimizationPhase` 的多轮优化策略，先进行加载消除，再进行分支消除。
* **`CsaOptimizationPhase`**:  针对 CSA 代码的后续优化阶段。它包括分支消除、死代码消除、机器相关的操作简化、公共子表达式消除和配对加载/存储优化（如果目标架构支持）。
* **`ComputeSchedulePhase`**:  此阶段负责计算指令的执行顺序（调度）。调度旨在优化指令在目标处理器上的执行效率，例如利用指令级并行性。
* **`RevectorizePhase`**:  这个阶段主要针对支持 SIMD (Single Instruction, Multiple Data) 的架构，尝试对代码进行重构，使其能够更好地利用 SIMD 指令进行并行计算，提高性能。
* **`InstructionSelectionPhase`**:  这是一个关键阶段，负责将图中的抽象操作符映射到目标架构的实际机器指令。它会考虑目标架构的特性，例如是否支持跳转表等。
* **`BitcastElisionPhase`**:  此阶段的目标是消除不必要的位转换操作。当一个值的表示形式在不同的类型之间转换时，如果实际上不需要进行任何实际的位操作，就可以消除这些转换。

**关于你的问题：**

* **`.tq` 结尾：**  `v8/src/compiler/pipeline.cc` 以 `.cc` 结尾，因此它是一个 **V8 C++ 源代码**，而不是 Torque 源代码。 Torque 源代码通常以 `.tq` 结尾。
* **与 JavaScript 的关系：**  这些编译优化阶段直接作用于 V8 编译 JavaScript 代码的过程中。当 V8 执行 JavaScript 代码时，Turbofan 编译器会将 JavaScript 代码转换成高效的机器码。这些阶段的目标就是提高生成的机器码的性能。

**JavaScript 举例说明：**

尽管这些阶段是在编译器的内部工作，用户无法直接控制，但它们优化的代码正是我们编写的 JavaScript 代码。以下是一些例子，说明这些阶段可能如何影响 JavaScript 代码的执行：

```javascript
function add(a, b) {
  let x = a + b; // 简单加法
  let y = a + b; // 重复计算
  return x;
}

function loopExample(arr) {
  let sum = 0;
  for (let i = 0; i < arr.length; i++) {
    sum += arr[i];
  }
  return sum;
}

function branchExample(condition) {
  if (condition) {
    return 1;
  } else {
    return 0;
  }
}
```

* **`CsaOptimizationPhase` (公共子表达式消除):** 在 `add` 函数中，`a + b` 被计算了两次。优化器可能会识别出这是相同的表达式，只计算一次并将结果复用，从而提高效率。
* **`SimplifyLoopsPhase`:** 在 `loopExample` 函数中，优化器可能会进行循环展开或将循环不变量外提，例如 `arr.length` 在循环中不会改变，可以提前计算。
* **`CsaOptimizationPhase` (分支消除):** 在 `branchExample` 函数中，如果编译器能推断出 `condition` 的值在特定情况下总是真或假，就可以直接消除 `if` 或 `else` 分支，生成更简洁的代码。

* **`InstructionSelectionPhase` (SIMD):** 如果 `arr` 是一个数字数组，并且运行在支持 SIMD 的架构上，编译器可能会生成 SIMD 指令来并行处理数组中的多个元素，从而加速 `loopExample` 的执行。

* **`BitcastElisionPhase`:** 考虑 JavaScript 中数字的表示。如果一个数字在内部表示之间进行了不必要的转换（例如，从整数表示到浮点数表示，但实际上没有精度损失），这个阶段可能会消除这些转换。

**代码逻辑推理和假设输入输出：**

以 `SimplifyLoopsPhase` 为例：

**假设输入 (控制流图的一部分):**

```
Block A:
  ...
  goto Block B

Block B:
  ...
  condition = ...
  if condition then goto Block C else goto Block D

Block C:
  ...
  goto Block B // 回到循环头部

Block D:
  ...
  goto Block E
```

这是一个典型的循环结构。

**假设输出 (优化后的控制流图):**

`SimplifyLoopsPhase` 可能会对这个结构进行转换，例如：

* **循环展开:** 如果循环体很小，它可以将循环体复制多次，减少循环的跳转开销。
* **循环不变代码外提:** 如果 Block B 中的某些计算在循环中保持不变，可以将它们移到循环之前。

具体的输出取决于具体的优化策略和循环的特性。

**用户常见的编程错误：**

这些优化阶段也能在一定程度上缓解用户的一些编程错误带来的性能影响，但无法完全消除。以下是一些例子：

* **重复计算:** 就像 `add` 函数的例子，虽然优化器可以消除重复计算，但最好还是在编写代码时避免。
* **低效的循环:**  例如，在循环内部进行不必要的对象创建或复杂的计算。虽然 `SimplifyLoopsPhase` 可以进行优化，但编写更高效的循环仍然是更好的选择。
* **不必要的类型转换:**  虽然 `BitcastElisionPhase` 可以消除一些，但频繁进行不必要的类型转换仍然可能影响性能。

**总结 (针对第 3 部分):**

这部分代码定义了 V8 Turbofan 编译器管道中的多个关键优化阶段，这些阶段专注于对代码的控制流和数据流进行分析和转换，以生成更高效的机器码。这些阶段包括循环简化、WebAssembly 特定的 lowering 和优化、CSA 代码的早期和后续优化、指令调度、向量化以及位转换消除。它们共同作用，提升 JavaScript 和 WebAssembly 代码的执行性能。

### 提示词
```
这是目录为v8/src/compiler/pipeline.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/pipeline.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
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
    // NOTE: We must not call `GetCodeTracer` if
```