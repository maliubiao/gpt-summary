Response: The user wants me to summarize the functionality of the C++ source code file `v8/src/compiler/pipeline.cc`.
This file seems to be a central part of the V8 compiler pipeline, specifically for the Turbofan and potentially Turboshaft optimizing compilers.

Here's a breakdown of my thought process to arrive at the summary:

1. **Identify the Core Purpose:** The file name `pipeline.cc` strongly suggests it's about the compilation pipeline. The numerous `#include` directives for various compiler phases (e.g., `bytecode-graph-builder.h`, `inlining-heuristic.h`, `instruction-selector.h`, `register-allocator.h`) confirm this.

2. **Key Entities:**  Look for important classes and data structures. `PipelineImpl` and `PipelineCompilationJob` appear to be central. `TFPipelineData` and `turboshaft::PipelineData` likely hold the state of the pipeline. The inclusion of `JSGraph`, `MachineGraph`, and `Schedule` points to the intermediate representations used.

3. **Phases of Compilation:** The included headers provide strong clues about the different phases involved. Terms like "GraphBuilder," "Inlining," "TypedLowering," "SimplifiedLowering," "InstructionSelector," "RegisterAllocator," and "CodeGenerator" are very indicative of compiler stages. The presence of "turboshaft" related headers indicates the integration of the newer Turboshaft compiler.

4. **Relationship to JavaScript:** The file operates on bytecode (`bytecode-graph-builder.h`) generated from JavaScript code. The various optimization and lowering phases transform this representation until it can be translated to machine code. The inclusion of files like `js-call-reducer.h`, `js-context-specialization.h`, `js-typed-lowering.h` explicitly links it to JavaScript.

5. **Turbofan vs. Turboshaft:**  The code has sections related to both Turbofan and Turboshaft. It appears there's a mechanism to switch between them or potentially transition from one to the other during compilation.

6. **Example Construction:**  To illustrate the connection to JavaScript, I need a simple JavaScript code snippet that would go through the compilation pipeline. A function with some basic operations and perhaps a function call would be a good starting point. Then, I can speculate (based on the file's content) how the pipeline might process it.

7. **Structure and Organization:** The file seems to define classes and functions to manage the compilation process. The `PipelineImpl` class seems to orchestrate the different phases.

8. **Refine the Summary:** Based on these observations, I can start drafting a summary, focusing on the core functionality and the relationship to JavaScript. I should mention the different phases, the role of Turbofan and Turboshaft, and the overall goal of generating optimized machine code.

9. **Iterate and Improve:** After the initial draft, I'll review it to ensure accuracy and clarity. I'll check if I've captured the key aspects of the file and if the JavaScript example is relevant and understandable.

By following these steps, I can arrive at a comprehensive and accurate summary of the provided C++ code. The focus on identifying keywords, understanding compiler concepts, and connecting the code to its JavaScript roots is crucial.
This C++ source code file, `v8/src/compiler/pipeline.cc`, is a core component of the V8 JavaScript engine's **compilation pipeline**. Specifically, it seems to focus on the **Turbofan optimizing compiler** and its integration with the newer **Turboshaft compiler**.

Here's a breakdown of its functionality:

* **Orchestrates the compilation process:** This file defines the sequence of steps (or "pipeline") that JavaScript code goes through to be compiled into optimized machine code. It manages the execution of various compiler phases.
* **Defines compiler phases:**  It includes headers for numerous compiler phases, indicating that this file is responsible for coordinating them. These phases cover a wide range of optimizations and transformations, including:
    * **Graph building:** Creating an intermediate representation of the code (likely a control flow graph).
    * **Inlining:** Replacing function calls with the actual function body to improve performance.
    * **Type analysis and specialization:** Inferring and utilizing type information to generate more efficient code.
    * **Lowering:** Transforming high-level operations into lower-level machine-specific instructions.
    * **Optimization:** Applying various techniques to improve the generated code's efficiency (e.g., dead code elimination, constant folding, loop optimizations).
    * **Instruction selection:** Choosing specific machine instructions to implement the operations.
    * **Register allocation:** Assigning variables to CPU registers for faster access.
    * **Code generation:** Emitting the final machine code.
* **Manages compiler state:** The file likely uses data structures and classes to hold the intermediate results and configuration settings throughout the compilation process. The presence of `TFPipelineData` suggests a structure specifically for managing data within the Turbofan pipeline.
* **Integrates Turbofan and Turboshaft:**  The inclusion of `src/compiler/turboshaft/...` headers indicates that this file manages the interaction or transition between the older Turbofan compiler and the newer Turboshaft compiler. It might be responsible for deciding which compiler to use or for converting the intermediate representation between the two.
* **Handles compilation jobs:** The `PipelineCompilationJob` class suggests that compilation is treated as a job, allowing for asynchronous or background compilation.
* **Provides debugging and tracing features:** The inclusion of headers related to tracing, statistics, and code printing suggests that this file incorporates mechanisms for debugging and analyzing the compilation process.

**Relationship to JavaScript and Example:**

This file is fundamental to how V8 executes JavaScript efficiently. When JavaScript code is run, V8 initially interprets it. For frequently executed ("hot") code, V8 uses optimizing compilers like Turbofan (and increasingly Turboshaft) to generate highly optimized machine code.

Here's a simplified illustration of how this file's functionality relates to a JavaScript example:

**JavaScript Code:**

```javascript
function add(a, b) {
  return a + b;
}

for (let i = 0; i < 10000; i++) {
  add(i, 1);
}
```

**How `pipeline.cc` (specifically Turbofan/Turboshaft) might process this:**

1. **Bytecode Generation:** V8 first compiles the JavaScript into bytecode (not directly handled in this file).
2. **Graph Building:** The `BytecodeGraphBuilder` (included in the file) would create a graph representation of the `add` function and the loop.
3. **Inlining:** If the `add` function is called frequently within the loop, the inliner might decide to replace the `add(i, 1)` call with the actual `a + b` operation within the loop's graph.
4. **Type Specialization:**  Turbofan/Turboshaft might infer that `a` and `b` are likely numbers in this context and generate code optimized for number addition.
5. **Loop Optimization:**  The loop might be optimized, for example, by unrolling it or performing strength reduction.
6. **Lowering:** The abstract addition operation `+` would be lowered to specific machine instructions for adding numbers on the target architecture.
7. **Register Allocation:** The compiler would assign the variables `i`, `a`, `b`, and the result to CPU registers.
8. **Code Generation:** Finally, machine code would be generated that directly performs the optimized addition within the loop.

**In essence, `v8/src/compiler/pipeline.cc` is responsible for taking the high-level description of the JavaScript code and transforming it into low-level, highly efficient machine instructions that can be directly executed by the CPU.**  It's the brain of the optimizing compilation process in V8.

### 提示词
```
这是目录为v8/src/compiler/pipeline.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/pipeline.h"

#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>

#include "src/builtins/builtins.h"
#include "src/builtins/profile-data-reader.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/bailout-reason.h"
#include "src/codegen/compiler.h"
#include "src/codegen/optimized-compilation-info.h"
#include "src/codegen/register-configuration.h"
#include "src/codegen/reloc-info.h"
#include "src/common/globals.h"
#include "src/common/high-allocation-throughput-scope.h"
#include "src/compiler/add-type-assertions-reducer.h"
#include "src/compiler/all-nodes.h"
#include "src/compiler/backend/bitcast-elider.h"
#include "src/compiler/backend/code-generator.h"
#include "src/compiler/backend/frame-elider.h"
#include "src/compiler/backend/instruction-selector.h"
#include "src/compiler/backend/instruction.h"
#include "src/compiler/backend/jump-threading.h"
#include "src/compiler/backend/move-optimizer.h"
#include "src/compiler/backend/register-allocator-verifier.h"
#include "src/compiler/backend/register-allocator.h"
#include "src/compiler/basic-block-instrumentor.h"
#include "src/compiler/branch-condition-duplicator.h"
#include "src/compiler/branch-elimination.h"
#include "src/compiler/bytecode-graph-builder.h"
#include "src/compiler/checkpoint-elimination.h"
#include "src/compiler/common-operator-reducer.h"
#include "src/compiler/common-operator.h"
#include "src/compiler/compilation-dependencies.h"
#include "src/compiler/compiler-source-position-table.h"
#include "src/compiler/constant-folding-reducer.h"
#include "src/compiler/csa-load-elimination.h"
#include "src/compiler/dead-code-elimination.h"
#include "src/compiler/decompression-optimizer.h"
#include "src/compiler/escape-analysis-reducer.h"
#include "src/compiler/escape-analysis.h"
#include "src/compiler/graph-trimmer.h"
#include "src/compiler/js-call-reducer.h"
#include "src/compiler/js-context-specialization.h"
#include "src/compiler/js-create-lowering.h"
#include "src/compiler/js-generic-lowering.h"
#include "src/compiler/js-heap-broker.h"
#include "src/compiler/js-inlining-heuristic.h"
#include "src/compiler/js-intrinsic-lowering.h"
#include "src/compiler/js-native-context-specialization.h"
#include "src/compiler/js-typed-lowering.h"
#include "src/compiler/late-escape-analysis.h"
#include "src/compiler/linkage.h"
#include "src/compiler/load-elimination.h"
#include "src/compiler/loop-analysis.h"
#include "src/compiler/loop-peeling.h"
#include "src/compiler/loop-unrolling.h"
#include "src/compiler/loop-variable-optimizer.h"
#include "src/compiler/machine-graph-verifier.h"
#include "src/compiler/machine-operator-reducer.h"
#include "src/compiler/memory-optimizer.h"
#include "src/compiler/node-observer.h"
#include "src/compiler/node-origin-table.h"
#include "src/compiler/osr.h"
#include "src/compiler/pair-load-store-reducer.h"
#include "src/compiler/phase.h"
#include "src/compiler/pipeline-data-inl.h"
#include "src/compiler/pipeline-statistics.h"
#include "src/compiler/redundancy-elimination.h"
#include "src/compiler/schedule.h"
#include "src/compiler/scheduler.h"
#include "src/compiler/select-lowering.h"
#include "src/compiler/simplified-lowering.h"
#include "src/compiler/simplified-operator-reducer.h"
#include "src/compiler/simplified-operator.h"
#include "src/compiler/turbofan-graph-visualizer.h"
#include "src/compiler/turbofan-typer.h"
#include "src/compiler/turboshaft/build-graph-phase.h"
#include "src/compiler/turboshaft/code-elimination-and-simplification-phase.h"
#include "src/compiler/turboshaft/csa-optimize-phase.h"
#include "src/compiler/turboshaft/debug-feature-lowering-phase.h"
#include "src/compiler/turboshaft/decompression-optimization-phase.h"
#include "src/compiler/turboshaft/instruction-selection-phase.h"
#include "src/compiler/turboshaft/loop-peeling-phase.h"
#include "src/compiler/turboshaft/loop-unrolling-phase.h"
#include "src/compiler/turboshaft/machine-lowering-phase.h"
#include "src/compiler/turboshaft/maglev-graph-building-phase.h"
#include "src/compiler/turboshaft/optimize-phase.h"
#include "src/compiler/turboshaft/phase.h"
#include "src/compiler/turboshaft/pipelines.h"
#include "src/compiler/turboshaft/recreate-schedule-phase.h"
#include "src/compiler/turboshaft/register-allocation-phase.h"
#include "src/compiler/turboshaft/simplify-tf-loops.h"
#include "src/compiler/turboshaft/store-store-elimination-phase.h"
#include "src/compiler/turboshaft/tracing.h"
#include "src/compiler/turboshaft/type-assertions-phase.h"
#include "src/compiler/turboshaft/typed-optimizations-phase.h"
#include "src/compiler/type-narrowing-reducer.h"
#include "src/compiler/typed-optimization.h"
#include "src/compiler/value-numbering-reducer.h"
#include "src/compiler/verifier.h"
#include "src/compiler/zone-stats.h"
#include "src/diagnostics/code-tracer.h"
#include "src/diagnostics/disassembler.h"
#include "src/flags/flags.h"
#include "src/handles/handles-inl.h"
#include "src/heap/local-heap.h"
#include "src/logging/code-events.h"
#include "src/logging/counters.h"
#include "src/logging/runtime-call-stats-scope.h"
#include "src/logging/runtime-call-stats.h"
#include "src/objects/code-kind.h"
#include "src/objects/shared-function-info.h"
#include "src/objects/string-inl.h"
#include "src/tracing/trace-event.h"
#include "src/utils/ostreams.h"
#include "src/utils/utils.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/compiler/int64-lowering.h"
#include "src/compiler/turboshaft/int64-lowering-phase.h"
#include "src/compiler/turboshaft/wasm-dead-code-elimination-phase.h"
#include "src/compiler/turboshaft/wasm-gc-optimize-phase.h"
#include "src/compiler/turboshaft/wasm-lowering-phase.h"
#include "src/compiler/turboshaft/wasm-optimize-phase.h"
#include "src/compiler/turboshaft/wasm-turboshaft-compiler.h"
#include "src/compiler/wasm-compiler.h"
#include "src/compiler/wasm-escape-analysis.h"
#include "src/compiler/wasm-gc-lowering.h"
#include "src/compiler/wasm-gc-operator-reducer.h"
#include "src/compiler/wasm-inlining.h"
#include "src/compiler/wasm-js-lowering.h"
#include "src/compiler/wasm-load-elimination.h"
#include "src/compiler/wasm-loop-peeling.h"
#include "src/compiler/wasm-typer.h"
#include "src/wasm/function-body-decoder.h"
#include "src/wasm/function-compiler.h"
#include "src/wasm/turboshaft-graph-interface.h"
#include "src/wasm/wasm-builtin-list.h"
#include "src/wasm/wasm-disassembler.h"
#include "src/wasm/wasm-engine.h"
#endif  // V8_ENABLE_WEBASSEMBLY

#if V8_ENABLE_WASM_SIMD256_REVEC
#include "src/compiler/revectorizer.h"
#include "src/compiler/turboshaft/wasm-revec-phase.h"
#endif  // V8_ENABLE_WASM_SIMD256_REVEC

// Set this for all targets that support instruction selection directly on
// Turboshaft graphs.
#define TARGET_SUPPORTS_TURBOSHAFT_INSTRUCTION_SELECTION 1

namespace v8 {
namespace internal {
namespace compiler {

static constexpr char kMachineGraphVerifierZoneName[] =
    "machine-graph-verifier-zone";
static constexpr char kPipelineCompilationJobZoneName[] =
    "pipeline-compilation-job-zone";

class PipelineImpl final {
 public:
  explicit PipelineImpl(TFPipelineData* data) : data_(data) {}

  // Helpers for executing pipeline phases.
  template <turboshaft::TurbofanPhase Phase, typename... Args>
  auto Run(Args&&... args);

  // Step A.1. Initialize the heap broker.
  void InitializeHeapBroker();

  // Step A.2. Run the graph creation and initial optimization passes.
  bool CreateGraph(Linkage* linkage);

  // Step B. Run the concurrent optimization passes.
  bool OptimizeTurbofanGraph(Linkage* linkage);

  // Substep B.1. Produce a scheduled graph.
  void ComputeScheduledGraph();

#if V8_ENABLE_WASM_SIMD256_REVEC
  void Revectorize();
#endif  // V8_ENABLE_WASM_SIMD256_REVEC

  // Substep B.2. Select instructions from a scheduled graph.
  bool SelectInstructions(Linkage* linkage);

  // Substep B.3. Run register allocation on the instruction sequence.
  bool AllocateRegisters(CallDescriptor* call_descriptor,
                         bool has_dummy_end_block);

  // Step C. Run the code assembly pass.
  void AssembleCode(Linkage* linkage);

  // Step D. Run the code finalization pass.
  MaybeHandle<Code> FinalizeCode(bool retire_broker = true);

  // Step E. Ensure all embedded maps are non-deprecated using
  // CheckNoDeprecatedMaps.

  // Step F. Install any code dependencies.
  bool CommitDependencies(Handle<Code> code);

  void VerifyGeneratedCodeIsIdempotent();
  void RunPrintAndVerify(const char* phase, bool untyped = false);
  bool SelectInstructionsAndAssemble(CallDescriptor* call_descriptor);
  MaybeHandle<Code> GenerateCode(CallDescriptor* call_descriptor);
  void AllocateRegisters(const RegisterConfiguration* config,
                         CallDescriptor* call_descriptor, bool run_verifier);

  TFPipelineData* data() const { return data_; }
  OptimizedCompilationInfo* info() const;
  Isolate* isolate() const;
  CodeGenerator* code_generator() const;

  ObserveNodeManager* observe_node_manager() const;

 private:
  TFPipelineData* const data_;
};

namespace {

class SourcePositionWrapper final : public Reducer {
 public:
  SourcePositionWrapper(Reducer* reducer, SourcePositionTable* table)
      : reducer_(reducer), table_(table) {}
  ~SourcePositionWrapper() final = default;
  SourcePositionWrapper(const SourcePositionWrapper&) = delete;
  SourcePositionWrapper& operator=(const SourcePositionWrapper&) = delete;

  const char* reducer_name() const override { return reducer_->reducer_name(); }

  Reduction Reduce(Node* node) final {
    SourcePosition const pos = table_->GetSourcePosition(node);
    SourcePositionTable::Scope position(table_, pos);
    return reducer_->Reduce(node, nullptr);
  }

  void Finalize() final { reducer_->Finalize(); }

 private:
  Reducer* const reducer_;
  SourcePositionTable* const table_;
};

class NodeOriginsWrapper final : public Reducer {
 public:
  NodeOriginsWrapper(Reducer* reducer, NodeOriginTable* table)
      : reducer_(reducer), table_(table) {}
  ~NodeOriginsWrapper() final = default;
  NodeOriginsWrapper(const NodeOriginsWrapper&) = delete;
  NodeOriginsWrapper& operator=(const NodeOriginsWrapper&) = delete;

  const char* reducer_name() const override { return reducer_->reducer_name(); }

  Reduction Reduce(Node* node) final {
    NodeOriginTable::Scope position(table_, reducer_name(), node);
    return reducer_->Reduce(node, nullptr);
  }

  void Finalize() final { reducer_->Finalize(); }

 private:
  Reducer* const reducer_;
  NodeOriginTable* const table_;
};

class V8_NODISCARD PipelineRunScope {
 public:
#ifdef V8_RUNTIME_CALL_STATS
  PipelineRunScope(
      TFPipelineData* data, const char* phase_name,
      RuntimeCallCounterId runtime_call_counter_id,
      RuntimeCallStats::CounterMode counter_mode = RuntimeCallStats::kExact)
      : phase_scope_(data->pipeline_statistics(), phase_name),
        zone_scope_(data->zone_stats(), phase_name),
        origin_scope_(data->node_origins(), phase_name),
        runtime_call_timer_scope(data->runtime_call_stats(),
                                 runtime_call_counter_id, counter_mode) {
    DCHECK_NOT_NULL(phase_name);
  }
#else   // V8_RUNTIME_CALL_STATS
  PipelineRunScope(TFPipelineData* data, const char* phase_name)
      : phase_scope_(data->pipeline_statistics(), phase_name),
        zone_scope_(data->zone_stats(), phase_name),
        origin_scope_(data->node_origins(), phase_name) {
    DCHECK_NOT_NULL(phase_name);
  }
#endif  // V8_RUNTIME_CALL_STATS

  Zone* zone() { return zone_scope_.zone(); }

 private:
  PhaseScope phase_scope_;
  ZoneStats::Scope zone_scope_;
  NodeOriginTable::PhaseScope origin_scope_;
#ifdef V8_RUNTIME_CALL_STATS
  RuntimeCallTimerScope runtime_call_timer_scope;
#endif  // V8_RUNTIME_CALL_STATS
};

// LocalIsolateScope encapsulates the phase where persistent handles are
// attached to the LocalHeap inside {local_isolate}.
class V8_NODISCARD LocalIsolateScope {
 public:
  explicit LocalIsolateScope(JSHeapBroker* broker,
                             OptimizedCompilationInfo* info,
                             LocalIsolate* local_isolate)
      : broker_(broker), info_(info) {
    broker_->AttachLocalIsolate(info_, local_isolate);
    info_->tick_counter().AttachLocalHeap(local_isolate->heap());
  }

  ~LocalIsolateScope() {
    info_->tick_counter().DetachLocalHeap();
    broker_->DetachLocalIsolate(info_);
  }

 private:
  JSHeapBroker* broker_;
  OptimizedCompilationInfo* info_;
};

void PrintFunctionSource(OptimizedCompilationInfo* info, Isolate* isolate,
                         int source_id,
                         DirectHandle<SharedFunctionInfo> shared) {
  if (!IsUndefined(shared->script(), isolate)) {
    DirectHandle<Script> script(Cast<Script>(shared->script()), isolate);

    if (!IsUndefined(script->source(), isolate)) {
      CodeTracer::StreamScope tracing_scope(isolate->GetCodeTracer());
      Tagged<Object> source_name = script->name();
      auto& os = tracing_scope.stream();
      os << "--- FUNCTION SOURCE (";
      if (IsString(source_name)) {
        os << Cast<String>(source_name)->ToCString().get() << ":";
      }
      os << shared->DebugNameCStr().get() << ") id{";
      os << info->optimization_id() << "," << source_id << "} start{";
      os << shared->StartPosition() << "} ---\n";
      {
        DisallowGarbageCollection no_gc;
        int start = shared->StartPosition();
        int len = shared->EndPosition() - start;
        SubStringRange source(Cast<String>(script->source()), no_gc, start,
                              len);
        for (auto c : source) {
          os << AsReversiblyEscapedUC16(c);
        }
      }

      os << "\n--- END ---\n";
    }
  }
}

// Print information for the given inlining: which function was inlined and
// where the inlining occurred.
void PrintInlinedFunctionInfo(
    OptimizedCompilationInfo* info, Isolate* isolate, int source_id,
    int inlining_id, const OptimizedCompilationInfo::InlinedFunctionHolder& h) {
  CodeTracer::StreamScope tracing_scope(isolate->GetCodeTracer());
  auto& os = tracing_scope.stream();
  os << "INLINE (" << h.shared_info->DebugNameCStr().get() << ") id{"
     << info->optimization_id() << "," << source_id << "} AS " << inlining_id
     << " AT ";
  const SourcePosition position = h.position.position;
  if (position.IsKnown()) {
    os << "<" << position.InliningId() << ":" << position.ScriptOffset() << ">";
  } else {
    os << "<?>";
  }
  os << std::endl;
}

// Print the source of all functions that participated in this optimizing
// compilation. For inlined functions print source position of their inlining.
void PrintParticipatingSource(OptimizedCompilationInfo* info,
                              Isolate* isolate) {
  SourceIdAssigner id_assigner(info->inlined_functions().size());
  PrintFunctionSource(info, isolate, -1, info->shared_info());
  const auto& inlined = info->inlined_functions();
  for (unsigned id = 0; id < inlined.size(); id++) {
    const int source_id = id_assigner.GetIdFor(inlined[id].shared_info);
    PrintFunctionSource(info, isolate, source_id, inlined[id].shared_info);
    PrintInlinedFunctionInfo(info, isolate, source_id, id, inlined[id]);
  }
}

void TraceScheduleAndVerify(OptimizedCompilationInfo* info,
                            TFPipelineData* data, Schedule* schedule,
                            const char* phase_name) {
  RCS_SCOPE(data->runtime_call_stats(),
            RuntimeCallCounterId::kOptimizeTraceScheduleAndVerify,
            RuntimeCallStats::kThreadSpecific);
  TRACE_EVENT0(TurbofanPipelineStatistics::kTraceCategory,
               "V8.TraceScheduleAndVerify");

  TraceSchedule(info, data, schedule, phase_name);

  if (v8_flags.turbo_verify) ScheduleVerifier::Run(schedule);
}

void AddReducer(TFPipelineData* data, GraphReducer* graph_reducer,
                Reducer* reducer) {
  if (data->info()->source_positions()) {
    SourcePositionWrapper* const wrapper =
        data->graph_zone()->New<SourcePositionWrapper>(
            reducer, data->source_positions());
    reducer = wrapper;
  }
  if (data->info()->trace_turbo_json()) {
    NodeOriginsWrapper* const wrapper =
        data->graph_zone()->New<NodeOriginsWrapper>(reducer,
                                                    data->node_origins());
    reducer = wrapper;
  }

  graph_reducer->AddReducer(reducer);
}

TurbofanPipelineStatistics* CreatePipelineStatistics(
    Handle<Script> script, OptimizedCompilationInfo* info, Isolate* isolate,
    ZoneStats* zone_stats) {
  TurbofanPipelineStatistics* pipeline_statistics = nullptr;

  bool tracing_enabled;
  TRACE_EVENT_CATEGORY_GROUP_ENABLED(TRACE_DISABLED_BY_DEFAULT("v8.turbofan"),
                                     &tracing_enabled);
  if (tracing_enabled || v8_flags.turbo_stats || v8_flags.turbo_stats_nvp) {
    pipeline_statistics = new TurbofanPipelineStatistics(
        info, isolate->GetTurboStatistics(), zone_stats);
    pipeline_statistics->BeginPhaseKind("V8.TFInitializing");
  }

  if (info->trace_turbo_json()) {
    TurboJsonFile json_of(info, std::ios_base::trunc);
    json_of << "{\"function\" : ";
    JsonPrintFunctionSource(json_of, -1, info->GetDebugName(), script, isolate,
                            info->shared_info());
    json_of << ",\n\"phases\":[";
  }

  return pipeline_statistics;
}

#if V8_ENABLE_WEBASSEMBLY
TurbofanPipelineStatistics* CreatePipelineStatistics(
    WasmCompilationData& compilation_data, const wasm::WasmModule* wasm_module,
    OptimizedCompilationInfo* info, ZoneStats* zone_stats) {
  TurbofanPipelineStatistics* pipeline_statistics = nullptr;

  bool tracing_enabled;
  TRACE_EVENT_CATEGORY_GROUP_ENABLED(
      TRACE_DISABLED_BY_DEFAULT("v8.wasm.turbofan"), &tracing_enabled);
  if (tracing_enabled || v8_flags.turbo_stats_wasm) {
    pipeline_statistics = new TurbofanPipelineStatistics(
        info, wasm::GetWasmEngine()->GetOrCreateTurboStatistics(), zone_stats);
    pipeline_statistics->BeginPhaseKind("V8.WasmInitializing");
  }

  if (info->trace_turbo_json()) {
    TurboJsonFile json_of(info, std::ios_base::trunc);
    std::unique_ptr<char[]> function_name = info->GetDebugName();
    json_of << "{\"function\":\"" << function_name.get() << "\", \"source\":\"";
    std::ostringstream disassembly;
    std::vector<uint32_t> source_positions;
    base::Vector<const uint8_t> function_bytes{compilation_data.func_body.start,
                                               compilation_data.body_size()};
    base::Vector<const uint8_t> module_bytes{nullptr, 0};
    std::optional<wasm::ModuleWireBytes> maybe_wire_bytes =
        compilation_data.wire_bytes_storage->GetModuleBytes();
    if (maybe_wire_bytes) module_bytes = maybe_wire_bytes->module_bytes();

    wasm::DisassembleFunction(
        wasm_module, compilation_data.func_index, function_bytes, module_bytes,
        compilation_data.func_body.offset, disassembly, &source_positions);
    for (const auto& c : disassembly.str()) {
      json_of << AsEscapedUC16ForJSON(c);
    }
    json_of << "\",\n\"sourceLineToBytecodePosition\" : [";
    bool insert_comma = false;
    for (auto val : source_positions) {
      if (insert_comma) {
        json_of << ", ";
      }
      json_of << val;
      insert_comma = true;
    }
    json_of << "],\n\"phases\":[";
  }

  return pipeline_statistics;
}
#endif  // V8_ENABLE_WEBASSEMBLY

// This runs instruction selection, register allocation and code generation.
// If {use_turboshaft_instruction_selection} is set, then instruction selection
// will run on the Turboshaft input graph directly. Otherwise, the graph is
// translated back to TurboFan sea-of-nodes and we run the backend on that.
[[nodiscard]] bool GenerateCodeFromTurboshaftGraph(
    bool use_turboshaft_instruction_selection, Linkage* linkage,
    turboshaft::Pipeline& turboshaft_pipeline,
    PipelineImpl* turbofan_pipeline = nullptr,
    std::shared_ptr<OsrHelper> osr_helper = {}) {
  DCHECK_IMPLIES(!use_turboshaft_instruction_selection, turbofan_pipeline);

  if (use_turboshaft_instruction_selection) {
    turboshaft::PipelineData* turboshaft_data = turboshaft_pipeline.data();
    turboshaft_data->InitializeCodegenComponent(osr_helper);
    // Run Turboshaft instruction selection.
    turboshaft_pipeline.PrepareForInstructionSelection();
    if (!turboshaft_pipeline.SelectInstructions(linkage)) return false;
    // We can release the graph now.
    turboshaft_data->ClearGraphComponent();

    turboshaft_pipeline.AllocateRegisters(linkage->GetIncomingDescriptor());
    turboshaft_pipeline.AssembleCode(linkage);
    return true;
  } else {
    // Otherwise, reconstruct a Turbofan graph. Note that this will
    // automatically release {turboshaft_data}'s graph component.
    turboshaft_pipeline.RecreateTurbofanGraph(turbofan_pipeline->data(),
                                              linkage);

    // And run code generation on that.
    if (!turbofan_pipeline->SelectInstructions(linkage)) return false;
    turbofan_pipeline->AssembleCode(linkage);
    return true;
  }
}

}  // namespace

class PipelineCompilationJob final : public TurbofanCompilationJob {
 public:
  PipelineCompilationJob(Isolate* isolate,
                         Handle<SharedFunctionInfo> shared_info,
                         Handle<JSFunction> function, BytecodeOffset osr_offset,
                         CodeKind code_kind);
  ~PipelineCompilationJob() final;
  PipelineCompilationJob(const PipelineCompilationJob&) = delete;
  PipelineCompilationJob& operator=(const PipelineCompilationJob&) = delete;

 protected:
  Status PrepareJobImpl(Isolate* isolate) final;
  Status ExecuteJobImpl(RuntimeCallStats* stats,
                        LocalIsolate* local_isolate) final;
  Status FinalizeJobImpl(Isolate* isolate) final;

 private:
  Zone zone_;
  ZoneStats zone_stats_;
  OptimizedCompilationInfo compilation_info_;
  std::unique_ptr<TurbofanPipelineStatistics> pipeline_statistics_;
  TFPipelineData data_;
  turboshaft::PipelineData turboshaft_data_;
  PipelineImpl pipeline_;
  Linkage* linkage_;
};

PipelineCompilationJob::PipelineCompilationJob(
    Isolate* isolate, Handle<SharedFunctionInfo> shared_info,
    Handle<JSFunction> function, BytecodeOffset osr_offset, CodeKind code_kind)
    // Note that the OptimizedCompilationInfo is not initialized at the time
    // we pass it to the CompilationJob constructor, but it is not
    // dereferenced there.
    : TurbofanCompilationJob(&compilation_info_,
                             CompilationJob::State::kReadyToPrepare),
      zone_(isolate->allocator(), kPipelineCompilationJobZoneName),
      zone_stats_(isolate->allocator()),
      compilation_info_(&zone_, isolate, shared_info, function, code_kind,
                        osr_offset),
      pipeline_statistics_(CreatePipelineStatistics(
          handle(Cast<Script>(shared_info->script()), isolate),
          compilation_info(), isolate, &zone_stats_)),
      data_(&zone_stats_, isolate, compilation_info(),
            pipeline_statistics_.get()),
      turboshaft_data_(&zone_stats_, turboshaft::TurboshaftPipelineKind::kJS,
                       isolate, compilation_info(),
                       AssemblerOptions::Default(isolate)),
      pipeline_(&data_),
      linkage_(nullptr) {
  turboshaft_data_.set_pipeline_statistics(pipeline_statistics_.get());
}

PipelineCompilationJob::~PipelineCompilationJob() = default;

void TraceSchedule(OptimizedCompilationInfo* info, TFPipelineData* data,
                   Schedule* schedule, const char* phase_name) {
  if (info->trace_turbo_json()) {
    UnparkedScopeIfNeeded scope(data->broker());
    AllowHandleDereference allow_deref;

    TurboJsonFile json_of(info, std::ios_base::app);
    json_of << "{\"name\":\"" << phase_name << "\",\"type\":\"schedule\""
            << ",\"data\":\"";
    std::stringstream schedule_stream;
    schedule_stream << *schedule;
    std::string schedule_string(schedule_stream.str());
    for (const auto& c : schedule_string) {
      json_of << AsEscapedUC16ForJSON(c);
    }
    json_of << "\"},\n";
  }

  if (info->trace_turbo_graph() || v8_flags.trace_turbo_scheduler) {
    UnparkedScopeIfNeeded scope(data->broker());
    AllowHandleDereference allow_deref;

    CodeTracer::StreamScope tracing_scope(data->GetCodeTracer());
    tracing_scope.stream() << "----- " << phase_name << " -----\n" << *schedule;
  }
}

// Print the code after compiling it.
void PrintCode(Isolate* isolate, DirectHandle<Code> code,
               OptimizedCompilationInfo* info) {
  if (v8_flags.print_opt_source && info->IsOptimizing()) {
    PrintParticipatingSource(info, isolate);
  }

#ifdef ENABLE_DISASSEMBLER
  const bool print_code =
      v8_flags.print_code ||
      (info->IsOptimizing() && v8_flags.print_opt_code &&
       info->shared_info()->PassesFilter(v8_flags.print_opt_code_filter));
  if (print_code) {
    std::unique_ptr<char[]> debug_name = info->GetDebugName();
    CodeTracer::StreamScope tracing_scope(isolate->GetCodeTracer());
    std::ostream& os = tracing_scope.stream();

    // Print the source code if available.
    const bool print_source = info->IsOptimizing();
    if (print_source) {
      DirectHandle<SharedFunctionInfo> shared = info->shared_info();
      if (IsScript(shared->script()) &&
          !IsUndefined(Cast<Script>(shared->script())->source(), isolate)) {
        os << "--- Raw source ---\n";
        StringCharacterStream stream(
            Cast<String>(Cast<Script>(shared->script())->source()),
            shared->StartPosition());
        // fun->end_position() points to the last character in the stream. We
        // need to compensate by adding one to calculate the length.
        int source_len = shared->EndPosition() - shared->StartPosition() + 1;
        for (int i = 0; i < source_len; i++) {
          if (stream.HasMore()) {
            os << AsReversiblyEscapedUC16(stream.GetNext());
          }
        }
        os << "\n\n";
      }
    }
    if (info->IsOptimizing()) {
      os << "--- Optimized code ---\n"
         << "optimization_id = " << info->optimization_id() << "\n";
    } else {
      os << "--- Code ---\n";
    }
    if (print_source) {
      DirectHandle<SharedFunctionInfo> shared = info->shared_info();
      os << "source_position = " << shared->StartPosition() << "\n";
    }
    code->Disassemble(debug_name.get(), os, isolate);
    os << "--- End code ---\n";
  }
#endif  // ENABLE_DISASSEMBLER
}

// The CheckMaps node can migrate objects with deprecated maps. Afterwards, we
// check the resulting object against a fixed list of maps known at compile
// time. This is problematic if we made any assumptions about an object with the
// deprecated map, as it now changed shape. Therefore, we want to avoid
// embedding deprecated maps, as objects with these maps can be changed by
// CheckMaps.
// The following code only checks for deprecated maps at the end of compilation,
// but doesn't protect us against the embedded maps becoming deprecated later.
// However, this is enough, since if the map becomes deprecated later, it will
// migrate to a new map not yet known at compile time, so if we migrate to it as
// part of a CheckMaps, this check will always fail afterwards and deoptimize.
// This in turn relies on a runtime invariant that map migrations always target
// newly allocated maps.
bool CheckNoDeprecatedMaps(DirectHandle<Code> code, Isolate* isolate) {
  int mode_mask = RelocInfo::EmbeddedObjectModeMask();
  for (RelocIterator it(*code, mode_mask); !it.done(); it.next()) {
    DCHECK(RelocInfo::IsEmbeddedObjectMode(it.rinfo()->rmode()));
    Tagged<HeapObject> obj = it.rinfo()->target_object(isolate);
    if (IsMap(obj) && Cast<Map>(obj)->is_deprecated()) {
      return false;
    }
  }
  return true;
}

namespace {
// Ensure that the RuntimeStats table is set on the PipelineData for
// duration of the job phase and unset immediately afterwards. Each job
// needs to set the correct RuntimeCallStats table depending on whether it
// is running on a background or foreground thread.
class V8_NODISCARD PipelineJobScope {
 public:
  PipelineJobScope(TFPipelineData* data, RuntimeCallStats* stats)
      : data_(data), current_broker_(data_->broker()) {
    data_->set_runtime_call_stats(stats);
  }
  PipelineJobScope(turboshaft::PipelineData* turboshaft_data,
                   RuntimeCallStats* stats)
      : turboshaft_data_(turboshaft_data),
        current_broker_(turboshaft_data_->broker()) {
    turboshaft_data_->set_runtime_call_stats(stats);
  }

  ~PipelineJobScope() {
    if (data_) data_->set_runtime_call_stats(nullptr);
    if (turboshaft_data_) turboshaft_data_->set_runtime_call_stats(nullptr);
  }

 private:
  HighAllocationThroughputScope high_throughput_scope_{
      V8::GetCurrentPlatform()};
  TFPipelineData* data_ = nullptr;
  turboshaft::PipelineData* turboshaft_data_ = nullptr;
  CurrentHeapBrokerScope current_broker_;
};
}  // namespace

PipelineCompilationJob::Status PipelineCompilationJob::PrepareJobImpl(
    Isolate* isolate) {
  // Ensure that the RuntimeCallStats table of main thread is available for
  // phases happening during PrepareJob.
  PipelineJobScope scope(&data_, isolate->counters()->runtime_call_stats());

  if (compilation_info()->bytecode_array()->length() >
      v8_flags.max_optimized_bytecode_size) {
    return AbortOptimization(BailoutReason::kFunctionTooBig);
  }

  if (!v8_flags.always_turbofan) {
    compilation_info()->set_bailout_on_uninitialized();
  }
  if (v8_flags.turbo_loop_peeling) {
    compilation_info()->set_loop_peeling();
  }
  if (v8_flags.turbo_inlining) {
    compilation_info()->set_inlining();
  }
  if (v8_flags.turbo_allocation_folding) {
    compilation_info()->set_allocation_folding();
  }

  // Determine whether to specialize the code for the function's context.
  // We can't do this in the case of OSR, because we want to cache the
  // generated code on the native context keyed on SharedFunctionInfo.
  // TODO(mythria): Check if it is better to key the OSR cache on JSFunction and
  // allow context specialization for OSR code.
  if (!compilation_info()
           ->shared_info()
           ->function_context_independent_compiled() &&
      compilation_info()->closure()->raw_feedback_cell()->map() ==
          ReadOnlyRoots(isolate).one_closure_cell_map() &&
      !compilation_info()->is_osr()) {
    compilation_info()->set_function_context_specializing();
    data_.ChooseSpecializationContext();
  }

  if (compilation_info()->source_positions()) {
    SharedFunctionInfo::EnsureSourcePositionsAvailable(
        isolate, compilation_info()->shared_info());
  }

  data_.set_start_source_position(
      compilation_info()->shared_info()->StartPosition());

  linkage_ = compilation_info()->zone()->New<Linkage>(
      Linkage::ComputeIncoming(compilation_info()->zone(), compilation_info()));

  if (compilation_info()->is_osr()) data_.InitializeOsrHelper();

  // InitializeHeapBroker() and CreateGraph() may already use
  // IsPendingAllocation.
  isolate->heap()->PublishMainThreadPendingAllocations();

  pipeline_.InitializeHeapBroker();

  // Serialization may have allocated.
  isolate->heap()->PublishMainThreadPendingAllocations();

  return SUCCEEDED;
}

PipelineCompilationJob::Status PipelineCompilationJob::ExecuteJobImpl(
    RuntimeCallStats* stats, LocalIsolate* local_isolate) {
  // Ensure that the RuntimeCallStats table is only available during execution
  // and not during finalization as that might be on a different thread.
  PipelineJobScope scope(&data_, stats);
  LocalIsolateScope local_isolate_scope(data_.broker(), data_.info(),
                                        local_isolate);

  turboshaft_data_.InitializeBrokerAndDependencies(data_.broker_ptr(),
                                                   data_.dependencies());
  turboshaft::Pipeline turboshaft_pipeline(&turboshaft_data_);

  if (V8_UNLIKELY(v8_flags.turboshaft_from_maglev)) {
    if (!turboshaft_pipeline.CreateGraphWithMaglev(linkage_)) {
      return AbortOptimization(BailoutReason::kGraphBuildingFailed);
    }
  } else {
    if (!pipeline_.CreateGraph(linkage_)) {
      return AbortOptimization(BailoutReason::kGraphBuildingFailed);
    }

    // We selectively Unpark inside OptimizeTurbofanGraph.
    if (!pipeline_.OptimizeTurbofanGraph(linkage_)) return FAILED;

    // We convert the turbofan graph to turboshaft.
    if (!turboshaft_pipeline.CreateGraphFromTurbofan(&data_, linkage_)) {
      data_.EndPhaseKind();
      return FAILED;
    }
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