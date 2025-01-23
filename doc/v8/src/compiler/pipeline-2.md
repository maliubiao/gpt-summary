Response: The user wants a summary of the C++ code in `v8/src/compiler/pipeline.cc`, specifically focusing on its function within the V8 compilation pipeline, especially its relationship with JavaScript. Since this is the third part of a three-part request, I should ensure the summary aligns with and extends the summaries provided for the previous parts.

**Key areas to focus on in this part of the code:**

* **Wasm Compilation:**  The code contains functions for compiling WebAssembly (`GenerateCodeForWasmFunction`, `GenerateWasmCodeFromTurboshaftGraph`). This is a significant part of its functionality.
* **Turboshaft Integration:**  The code explicitly mentions and integrates the "Turboshaft" compiler, a next-generation compiler for V8.
* **Testing Infrastructure:** Functions like `GenerateCodeForTesting` and `GenerateTurboshaftCodeForTesting` suggest the file plays a role in V8's internal testing framework.
* **Register Allocation:** The presence of `AllocateRegistersForTesting` and the detailed register allocation process within `PipelineImpl::AllocateRegisters` indicates this file manages how registers are assigned during compilation.
* **Code Generation:**  Functions like `AssembleCode` and `FinalizeCode` are responsible for generating the final machine code.
* **Phases of Compilation:** The code explicitly calls different "phases" of the compilation pipeline (e.g., `WasmInliningPhase`, `WasmOptimizationPhase`, `InstructionSelectionPhase`).
* **Debugging and Tracing:** The code includes flags and mechanisms for tracing compilation steps (`v8_flags.trace_wasm_compilation_times`, `data.info()->trace_turbo_json()`).

**Connecting to JavaScript:**

The compilation of JavaScript code, although not explicitly detailed in this snippet, is the *ultimate* goal. The Wasm compilation functions are triggered by JavaScript code that loads and executes Wasm modules. The testing and internal compilation functions are used to develop and verify the compiler that handles JavaScript.

**Example JavaScript for Wasm interaction:**

I need to provide a simple JavaScript example that demonstrates how the Wasm compilation functions in this file would be involved. Loading and instantiating a Wasm module is a good starting point.
Based on the provided C++ code snippet from `v8/src/compiler/pipeline.cc`, here's a summary of its functionality, continuing from the previous parts:

**Core Functionality (Part 3): Finalizing Compilation and Wasm Support**

This part of the `pipeline.cc` file primarily deals with the later stages of the compilation pipeline, specifically focusing on:

1. **WebAssembly (Wasm) Code Generation:** It contains dedicated functions (`GenerateCodeForWasmFunction` and `GenerateWasmCodeFromTurboshaftGraph`) for compiling WebAssembly code. These functions orchestrate the compilation process for Wasm modules, leveraging both the traditional TurboFan pipeline and the newer Turboshaft pipeline. This includes steps like:
    * **Optimization Phases:** Running various optimization passes specifically tailored for Wasm, such as inlining, loop peeling/unrolling, and optimizations related to garbage collection (GC) and memory management.
    * **Lowering:** Transforming high-level Wasm operations into lower-level machine instructions.
    * **Instruction Selection:** Choosing specific machine instructions to implement the Wasm code.
    * **Code Assembly:**  Generating the final machine code for the Wasm function.
    * **Metadata Generation:** Creating metadata like source position information, inlining positions, and deoptimization data.

2. **Turboshaft Integration:** It actively integrates the Turboshaft compiler for Wasm compilation. This involves building a Turboshaft graph from the intermediate representation and running Turboshaft-specific optimization and lowering passes. It also includes a conditional switch to use Turboshaft's instruction selection if enabled.

3. **Testing Infrastructure:** It provides functions (`GenerateCodeForTesting`, `GenerateTurboshaftCodeForTesting`) used for internal testing of the TurboFan and Turboshaft compilers. These functions allow for controlled compilation scenarios and verification of the compilation process.

4. **Register Allocation:** This part of the code includes the actual register allocation process (`AllocateRegisters`, `AllocateRegistersForTesting`). It manages how virtual registers are mapped to physical machine registers, a crucial step in generating efficient machine code. It includes various phases of register allocation like live range analysis, building bundles, and handling spilling.

5. **Finalizing Code Generation:** Functions like `AssembleCode` take the selected instructions and generate the raw machine code. `FinalizeCode` performs the final steps, including committing dependencies, setting the generated code in the `OptimizedCompilationInfo`, and potentially disassembling the code for debugging or tracing.

6. **Compilation Job Management:**  The `NewCompilationJob` function creates a `PipelineCompilationJob` which encapsulates the work needed to compile a JavaScript function using the pipeline.

7. **Tracing and Debugging:** It includes mechanisms for tracing the compilation process, outputting JSON representations of intermediate states, and disassembling the generated code. This helps in understanding and debugging the compiler.

**Relationship to JavaScript (with JavaScript examples):**

While this specific file primarily focuses on the *how* of compilation, it is fundamentally tied to JavaScript execution. Here's how it relates, particularly concerning the Wasm functionalities:

* **Loading and Instantiating Wasm Modules:** When JavaScript code loads and instantiates a WebAssembly module, V8 needs to compile the Wasm bytecode into executable machine code. The functions in this file, like `GenerateCodeForWasmFunction` or `GenerateWasmCodeFromTurboshaftGraph`, are directly responsible for this process.

```javascript
// Example of loading and instantiating a WebAssembly module
fetch('my_module.wasm')
  .then(response => response.arrayBuffer())
  .then(bytes => WebAssembly.instantiate(bytes))
  .then(results => {
    // The 'results.instance.exports' contains the compiled and exported
    // functions from the Wasm module. The compilation of 'my_module.wasm'
    // would involve the code in pipeline.cc.
    const exportedFunction = results.instance.exports.my_wasm_function;
    console.log(exportedFunction(10, 20));
  });
```

* **Calling Wasm Functions from JavaScript:** Once a Wasm module is instantiated, JavaScript can call the exported Wasm functions. The code generated by the functions in `pipeline.cc` is what gets executed when these calls happen.

```javascript
// Assuming 'results' from the previous example
const exportedFunction = results.instance.exports.my_wasm_function;
const result = exportedFunction(5, 7); // This will execute the compiled Wasm code
console.log(result);
```

* **JIT Compilation of JavaScript:** While the explicit JavaScript compilation flow isn't fully detailed in this snippet, the underlying principles and many of the optimization phases are shared. When V8's TurboFan or Turboshaft compiles JavaScript functions, it goes through similar stages of graph building, optimization, instruction selection, and register allocation.

In essence, this part of `pipeline.cc` is a crucial component in V8's ability to efficiently execute both JavaScript and WebAssembly code. It handles the complex task of transforming source code (or bytecode in the case of Wasm) into optimized machine instructions that the CPU can understand and execute. The integration of Turboshaft represents an ongoing effort to further improve the performance of both JavaScript and WebAssembly within V8.

### 提示词
```
这是目录为v8/src/compiler/pipeline.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```
linee_func_index +
                            sizeof positions[0].was_tail_call +
                            sizeof positions[0].caller_pos;
  auto result = base::OwnedVector<uint8_t>::New(positions.size() * entry_size);
  uint8_t* iter = result.begin();
  for (const auto& [func_index, was_tail_call, caller_pos] : positions) {
    size_t index_size = sizeof func_index;
    std::memcpy(iter, &func_index, index_size);
    iter += index_size;
    size_t was_tail_call_size = sizeof was_tail_call;
    std::memcpy(iter, &was_tail_call, was_tail_call_size);
    iter += was_tail_call_size;
    size_t pos_size = sizeof caller_pos;
    std::memcpy(iter, &caller_pos, pos_size);
    iter += pos_size;
  }
  DCHECK_EQ(iter, result.end());
  return result;
}

}  // namespace

// static
void Pipeline::GenerateCodeForWasmFunction(
    OptimizedCompilationInfo* info, wasm::CompilationEnv* env,
    WasmCompilationData& compilation_data, MachineGraph* mcgraph,
    CallDescriptor* call_descriptor,
    ZoneVector<WasmInliningPosition>* inlining_positions,
    wasm::WasmDetectedFeatures* detected) {
  // This code is only used if `--no-turboshaft-wasm` is passed.
  CHECK(!v8_flags.turboshaft_wasm);

  auto* wasm_engine = wasm::GetWasmEngine();
  const wasm::WasmModule* module = env->module;
  base::TimeTicks start_time;
  if (V8_UNLIKELY(v8_flags.trace_wasm_compilation_times)) {
    start_time = base::TimeTicks::Now();
  }
  ZoneStats zone_stats(wasm_engine->allocator());
  std::unique_ptr<TurbofanPipelineStatistics> pipeline_statistics(
      CreatePipelineStatistics(compilation_data, module, info, &zone_stats));
  TFPipelineData data(&zone_stats, wasm_engine, info, mcgraph,
                      pipeline_statistics.get(),
                      compilation_data.source_positions,
                      compilation_data.node_origins, WasmAssemblerOptions());

  PipelineImpl pipeline(&data);

  if (data.info()->trace_turbo_json() || data.info()->trace_turbo_graph()) {
    CodeTracer::StreamScope tracing_scope(data.GetCodeTracer());
    tracing_scope.stream()
        << "---------------------------------------------------\n"
        << "Begin compiling method " << data.info()->GetDebugName().get()
        << " using TurboFan" << std::endl;
  }

  pipeline.RunPrintAndVerify("V8.WasmMachineCode", true);

#if V8_ENABLE_WASM_SIMD256_REVEC
  if (v8_flags.experimental_wasm_revectorize) {
    pipeline.Revectorize();
    pipeline.RunPrintAndVerify("V8.WasmRevec", true);
  }
#endif  // V8_ENABLE_WASM_SIMD256_REVEC

  data.BeginPhaseKind("V8.WasmOptimization");

  const bool is_asm_js = is_asmjs_module(module);
  // Disable inlining for Wasm modules generated from asm.js, since we do not
  // have correct stack traces then (and possibly other missing parts).
  if (v8_flags.wasm_inlining && !is_asm_js) {
    pipeline.Run<WasmInliningPhase>(env, compilation_data, inlining_positions,
                                    detected);
    pipeline.RunPrintAndVerify(WasmInliningPhase::phase_name(), true);
  }
  if (v8_flags.wasm_loop_peeling) {
    pipeline.Run<WasmLoopPeelingPhase>(compilation_data.loop_infos);
    pipeline.RunPrintAndVerify(WasmLoopPeelingPhase::phase_name(), true);
  }
  if (v8_flags.wasm_loop_unrolling) {
    pipeline.Run<WasmLoopUnrollingPhase>(compilation_data.loop_infos);
    pipeline.RunPrintAndVerify(WasmLoopUnrollingPhase::phase_name(), true);
  }
  MachineOperatorReducer::SignallingNanPropagation signalling_nan_propagation =
      is_asm_js ? MachineOperatorReducer::kPropagateSignallingNan
                : MachineOperatorReducer::kSilenceSignallingNan;

#define DETECTED_IMPLIES_ENABLED(feature, ...) \
  DCHECK_IMPLIES(detected->has_##feature(), enabled.has_##feature());
  wasm::WasmEnabledFeatures enabled = env->enabled_features;
  FOREACH_WASM_FEATURE_FLAG(DETECTED_IMPLIES_ENABLED)
  USE(enabled);
#undef DETECTED_IMPLIES_ENABLED

  if (detected->has_gc() || detected->has_stringref() ||
      detected->has_imported_strings() ||
      detected->has_imported_strings_utf8()) {
    pipeline.Run<WasmTypingPhase>(compilation_data.func_index);
    pipeline.RunPrintAndVerify(WasmTypingPhase::phase_name(), true);
    if (v8_flags.wasm_opt) {
      pipeline.Run<WasmGCOptimizationPhase>(module, data.mcgraph());
      pipeline.RunPrintAndVerify(WasmGCOptimizationPhase::phase_name(), true);
    }
  }

  // These proposals use gc nodes.
  if (detected->has_gc() || detected->has_typed_funcref() ||
      detected->has_stringref() || detected->has_reftypes() ||
      detected->has_imported_strings() ||
      detected->has_imported_strings_utf8()) {
    pipeline.Run<WasmGCLoweringPhase>(module);
    pipeline.RunPrintAndVerify(WasmGCLoweringPhase::phase_name(), true);
  }

  // Int64Lowering must happen after inlining (otherwise inlining would have
  // to invoke it separately for the inlined function body).
  // It must also happen after WasmGCLowering, otherwise it would have to
  // add type annotations to nodes it creates, and handle wasm-gc nodes.
  LowerInt64(compilation_data.func_body.sig, mcgraph, data.simplified(),
             pipeline);

  if (v8_flags.wasm_opt || is_asm_js) {
    pipeline.Run<WasmOptimizationPhase>(signalling_nan_propagation, *detected);
    pipeline.RunPrintAndVerify(WasmOptimizationPhase::phase_name(), true);
  } else {
    pipeline.Run<WasmBaseOptimizationPhase>();
    pipeline.RunPrintAndVerify(WasmBaseOptimizationPhase::phase_name(), true);
  }

  pipeline.Run<MemoryOptimizationPhase>();
  pipeline.RunPrintAndVerify(MemoryOptimizationPhase::phase_name(), true);

  if (detected->has_gc() && v8_flags.wasm_opt) {
    // Run value numbering and machine operator reducer to optimize load/store
    // address computation (in particular, reuse the address computation
    // whenever possible).
    pipeline.Run<MachineOperatorOptimizationPhase>(signalling_nan_propagation);
    pipeline.RunPrintAndVerify(MachineOperatorOptimizationPhase::phase_name(),
                               true);
    pipeline.Run<DecompressionOptimizationPhase>();
    pipeline.RunPrintAndVerify(DecompressionOptimizationPhase::phase_name(),
                               true);
  }

  if (v8_flags.wasm_opt) {
    pipeline.Run<BranchConditionDuplicationPhase>();
    pipeline.RunPrintAndVerify(BranchConditionDuplicationPhase::phase_name(),
                               true);
  }

  if (v8_flags.turbo_splitting && !is_asm_js) {
    data.info()->set_splitting();
  }

  if (data.node_origins()) {
    data.node_origins()->RemoveDecorator();
  }

  data.BeginPhaseKind("V8.InstructionSelection");
  pipeline.ComputeScheduledGraph();

  Linkage linkage(call_descriptor);

  if (!pipeline.SelectInstructions(&linkage)) return;
  pipeline.AssembleCode(&linkage);

  auto result = std::make_unique<wasm::WasmCompilationResult>();
  CodeGenerator* code_generator = pipeline.code_generator();
  code_generator->masm()->GetCode(
      nullptr, &result->code_desc, code_generator->safepoint_table_builder(),
      static_cast<int>(code_generator->handler_table_offset()));

  result->instr_buffer = code_generator->masm()->ReleaseBuffer();
  result->frame_slot_count = code_generator->frame()->GetTotalFrameSlotCount();
  result->tagged_parameter_slots = call_descriptor->GetTaggedParameterSlots();
  result->source_positions = code_generator->GetSourcePositionTable();
  result->inlining_positions = SerializeInliningPositions(*inlining_positions);
  result->protected_instructions_data =
      code_generator->GetProtectedInstructionsData();
  result->result_tier = wasm::ExecutionTier::kTurbofan;

  if (data.info()->trace_turbo_json()) {
    TurboJsonFile json_of(data.info(), std::ios_base::app);
    json_of << "{\"name\":\"disassembly\",\"type\":\"disassembly\""
            << BlockStartsAsJSON{&code_generator->block_starts()}
            << "\"data\":\"";
#ifdef ENABLE_DISASSEMBLER
    std::stringstream disassembler_stream;
    Disassembler::Decode(
        nullptr, disassembler_stream, result->code_desc.buffer,
        result->code_desc.buffer + result->code_desc.safepoint_table_offset,
        CodeReference(&result->code_desc));
    for (auto const c : disassembler_stream.str()) {
      json_of << AsEscapedUC16ForJSON(c);
    }
#endif  // ENABLE_DISASSEMBLER
    json_of << "\"}\n],\n";
    JsonPrintAllSourceWithPositionsWasm(json_of, module,
                                        compilation_data.wire_bytes_storage,
                                        base::VectorOf(*inlining_positions));
    json_of << "}";
    json_of << "\n}";
  }

  if (data.info()->trace_turbo_json() || data.info()->trace_turbo_graph()) {
    CodeTracer::StreamScope tracing_scope(data.GetCodeTracer());
    tracing_scope.stream()
        << "---------------------------------------------------\n"
        << "Finished compiling method " << data.info()->GetDebugName().get()
        << " using TurboFan" << std::endl;
  }

  if (V8_UNLIKELY(v8_flags.trace_wasm_compilation_times)) {
    base::TimeDelta time = base::TimeTicks::Now() - start_time;
    int codesize = result->code_desc.body_size();
    StdoutStream{} << "Compiled function "
                   << reinterpret_cast<const void*>(module) << "#"
                   << compilation_data.func_index << " using TurboFan, took "
                   << time.InMilliseconds() << " ms and "
                   << zone_stats.GetMaxAllocatedBytes() << " / "
                   << zone_stats.GetTotalAllocatedBytes()
                   << " max/total bytes; bodysize "
                   << compilation_data.body_size() << " codesize " << codesize
                   << " name " << data.info()->GetDebugName().get()
                   << std::endl;
  }

  DCHECK(result->succeeded());
  info->SetWasmCompilationResult(std::move(result));
}

// static
bool Pipeline::GenerateWasmCodeFromTurboshaftGraph(
    OptimizedCompilationInfo* info, wasm::CompilationEnv* env,
    WasmCompilationData& compilation_data, MachineGraph* mcgraph,
    wasm::WasmDetectedFeatures* detected, CallDescriptor* call_descriptor) {
  auto* wasm_engine = wasm::GetWasmEngine();
  const wasm::WasmModule* module = env->module;
  base::TimeTicks start_time;
  if (V8_UNLIKELY(v8_flags.trace_wasm_compilation_times)) {
    start_time = base::TimeTicks::Now();
  }
  ZoneStats zone_stats(wasm_engine->allocator());
  std::unique_ptr<TurbofanPipelineStatistics> pipeline_statistics(
      CreatePipelineStatistics(compilation_data, module, info, &zone_stats));
  AssemblerOptions options = WasmAssemblerOptions();
  TFPipelineData data(&zone_stats, wasm_engine, info, mcgraph,
                      pipeline_statistics.get(),
                      compilation_data.source_positions,
                      compilation_data.node_origins, options);

  PipelineImpl pipeline(&data);

  if (data.info()->trace_turbo_json() || data.info()->trace_turbo_graph()) {
    CodeTracer::StreamScope tracing_scope(data.GetCodeTracer());
    tracing_scope.stream()
        << "---------------------------------------------------\n"
        << "Begin compiling method " << data.info()->GetDebugName().get()
        << " using Turboshaft" << std::endl;
  }

  if (mcgraph->machine()->Is32()) {
    call_descriptor =
        GetI32WasmCallDescriptor(mcgraph->zone(), call_descriptor);
  }
  Linkage linkage(call_descriptor);

  Zone inlining_positions_zone(wasm_engine->allocator(), ZONE_NAME);
  ZoneVector<WasmInliningPosition> inlining_positions(&inlining_positions_zone);

  turboshaft::PipelineData turboshaft_data(
      &zone_stats, turboshaft::TurboshaftPipelineKind::kWasm, nullptr, info,
      options);
  turboshaft_data.set_pipeline_statistics(pipeline_statistics.get());
  const wasm::FunctionSig* sig = compilation_data.func_body.sig;
  turboshaft_data.SetIsWasmFunction(env->module, sig,
                                    compilation_data.func_body.is_shared);
  DCHECK_NOT_NULL(turboshaft_data.wasm_module());

  // TODO(nicohartmann): This only works here because source positions are not
  // actually allocated inside the graph zone of TFPipelineData. We should
  // properly allocate source positions inside Turboshaft's graph zone right
  // from the beginning.
  turboshaft_data.InitializeGraphComponent(data.source_positions());

  AccountingAllocator allocator;
  wasm::BuildTSGraph(&turboshaft_data, &allocator, env, detected,
                     turboshaft_data.graph(), compilation_data.func_body,
                     compilation_data.wire_bytes_storage,
                     compilation_data.assumptions, &inlining_positions,
                     compilation_data.func_index);
  CodeTracer* code_tracer = nullptr;
  if (turboshaft_data.info()->trace_turbo_graph()) {
    // NOTE: We must not call `GetCodeTracer` if tracing is not enabled,
    // because it may not yet be initialized then and doing so from the
    // background thread is not threadsafe.
    code_tracer = data.GetCodeTracer();
  }
  Zone printing_zone(&allocator, ZONE_NAME);
  turboshaft::PrintTurboshaftGraph(&turboshaft_data, &printing_zone,
                                   code_tracer, "Graph generation");

  data.BeginPhaseKind("V8.WasmOptimization");
  turboshaft::Pipeline turboshaft_pipeline(&turboshaft_data);
#ifdef V8_ENABLE_WASM_SIMD256_REVEC
  {
    bool cpu_feature_support = false;
#ifdef V8_TARGET_ARCH_X64
    if (CpuFeatures::IsSupported(AVX) && CpuFeatures::IsSupported(AVX2)) {
      cpu_feature_support = true;
    }
#endif
    if (v8_flags.experimental_wasm_revectorize && cpu_feature_support &&
        detected->has_simd() && !env->enabled_features.has_memory64()) {
      if (v8_flags.trace_wasm_revectorize) {
        std::cout << "Begin revec function "
                  << data.info()->GetDebugName().get() << std::endl;
      }
      turboshaft_pipeline.Run<turboshaft::WasmRevecPhase>();
      if (v8_flags.trace_wasm_revectorize) {
        std::cout << "Finished revec function "
                  << data.info()->GetDebugName().get() << std::endl;
      }
    }
  }
#endif  // V8_ENABLE_WASM_SIMD256_REVEC
  const bool uses_wasm_gc_features =
      detected->has_gc() || detected->has_typed_funcref() ||
      detected->has_stringref() || detected->has_imported_strings() ||
      detected->has_imported_strings_utf8();
  if (v8_flags.wasm_loop_peeling && uses_wasm_gc_features) {
    turboshaft_pipeline.Run<turboshaft::LoopPeelingPhase>();
  }

  if (v8_flags.wasm_loop_unrolling) {
    turboshaft_pipeline.Run<turboshaft::LoopUnrollingPhase>();
  }

  if (v8_flags.wasm_opt && uses_wasm_gc_features) {
    turboshaft_pipeline.Run<turboshaft::WasmGCOptimizePhase>();
  }

  // TODO(mliedtke): This phase could be merged with the WasmGCOptimizePhase
  // if wasm_opt is enabled to improve compile time. Consider potential code
  // size increase.
  turboshaft_pipeline.Run<turboshaft::WasmLoweringPhase>();

  // TODO(14108): Do we need value numbering if wasm_opt is turned off?
  const bool is_asm_js = is_asmjs_module(module);
  if (v8_flags.wasm_opt || is_asm_js) {
    turboshaft_pipeline.Run<turboshaft::WasmOptimizePhase>();
  }

  if (mcgraph->machine()->Is32()) {
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
  if (!success) return false;

  CodeGenerator* code_generator;
  if (use_turboshaft_instruction_selection) {
    code_generator = turboshaft_data.code_generator();
  } else {
    code_generator = pipeline.code_generator();
  }

  auto result = std::make_unique<wasm::WasmCompilationResult>();
  code_generator->masm()->GetCode(
      nullptr, &result->code_desc, code_generator->safepoint_table_builder(),
      static_cast<int>(code_generator->handler_table_offset()));

  result->instr_buffer = code_generator->masm()->ReleaseBuffer();
  result->frame_slot_count = code_generator->frame()->GetTotalFrameSlotCount();
  result->tagged_parameter_slots = call_descriptor->GetTaggedParameterSlots();
  result->source_positions = code_generator->GetSourcePositionTable();
  result->inlining_positions = SerializeInliningPositions(inlining_positions);
  result->protected_instructions_data =
      code_generator->GetProtectedInstructionsData();
  result->deopt_data = code_generator->GenerateWasmDeoptimizationData();
  result->result_tier = wasm::ExecutionTier::kTurbofan;

  if (data.info()->trace_turbo_json()) {
    TurboJsonFile json_of(data.info(), std::ios_base::app);
    json_of << "{\"name\":\"disassembly\",\"type\":\"disassembly\""
            << BlockStartsAsJSON{&code_generator->block_starts()}
            << "\"data\":\"";
#ifdef ENABLE_DISASSEMBLER
    std::stringstream disassembler_stream;
    Disassembler::Decode(
        nullptr, disassembler_stream, result->code_desc.buffer,
        result->code_desc.buffer + result->code_desc.safepoint_table_offset,
        CodeReference(&result->code_desc));
    for (auto const c : disassembler_stream.str()) {
      json_of << AsEscapedUC16ForJSON(c);
    }
#endif  // ENABLE_DISASSEMBLER
    json_of << "\"}\n],\n";
    JsonPrintAllSourceWithPositionsWasm(json_of, module,
                                        compilation_data.wire_bytes_storage,
                                        base::VectorOf(inlining_positions));
    json_of << "}";
    json_of << "\n}";
  }

  if (data.info()->trace_turbo_json() || data.info()->trace_turbo_graph()) {
    CodeTracer::StreamScope tracing_scope(data.GetCodeTracer());
    tracing_scope.stream()
        << "---------------------------------------------------\n"
        << "Finished compiling method " << data.info()->GetDebugName().get()
        << " using Turboshaft" << std::endl;
  }

  if (V8_UNLIKELY(v8_flags.trace_wasm_compilation_times)) {
    base::TimeDelta time = base::TimeTicks::Now() - start_time;
    int codesize = result->code_desc.body_size();
    StdoutStream{} << "Compiled function "
                   << reinterpret_cast<const void*>(module) << "#"
                   << compilation_data.func_index << " using TurboFan, took "
                   << time.InMilliseconds() << " ms and "
                   << zone_stats.GetMaxAllocatedBytes() << " / "
                   << zone_stats.GetTotalAllocatedBytes()
                   << " max/total bytes; bodysize "
                   << compilation_data.body_size() << " codesize " << codesize
                   << " name " << data.info()->GetDebugName().get()
                   << std::endl;
  }

  DCHECK(result->succeeded());
  info->SetWasmCompilationResult(std::move(result));
  return true;
}
#endif  // V8_ENABLE_WEBASSEMBLY

// static
MaybeHandle<Code> Pipeline::GenerateCodeForTesting(
    OptimizedCompilationInfo* info, Isolate* isolate) {
  ZoneStats zone_stats(isolate->allocator());
  std::unique_ptr<TurbofanPipelineStatistics> pipeline_statistics(
      CreatePipelineStatistics(Handle<Script>::null(), info, isolate,
                               &zone_stats));

  TFPipelineData data(&zone_stats, isolate, info, pipeline_statistics.get());
  turboshaft::PipelineData turboshaft_data(
      &zone_stats, turboshaft::TurboshaftPipelineKind::kJS, isolate, info,
      AssemblerOptions::Default(isolate));
  turboshaft_data.set_pipeline_statistics(pipeline_statistics.get());
  PipelineJobScope scope(&data, isolate->counters()->runtime_call_stats());
  PipelineImpl pipeline(&data);
  turboshaft::Pipeline turboshaft_pipeline(&turboshaft_data);

  Linkage linkage(Linkage::ComputeIncoming(data.instruction_zone(), info));

  {
    CompilationHandleScope compilation_scope(isolate, info);
    info->ReopenAndCanonicalizeHandlesInNewScope(isolate);
    pipeline.InitializeHeapBroker();
  }

  {
    LocalIsolateScope local_isolate_scope(data.broker(), info,
                                          isolate->main_thread_local_isolate());
    if (!pipeline.CreateGraph(&linkage)) return {};
    // We selectively Unpark inside OptimizeTurbofanGraph.
    if (!pipeline.OptimizeTurbofanGraph(&linkage)) return {};

    // We convert the turbofan graph to turboshaft.
    turboshaft_data.InitializeBrokerAndDependencies(data.broker_ptr(),
                                                    data.dependencies());
    if (!turboshaft_pipeline.CreateGraphFromTurbofan(&data, &linkage)) {
      data.EndPhaseKind();
      return {};
    }

    if (!turboshaft_pipeline.OptimizeTurboshaftGraph(&linkage)) {
      return {};
    }

#ifdef TARGET_SUPPORTS_TURBOSHAFT_INSTRUCTION_SELECTION
    bool use_turboshaft_instruction_selection =
        v8_flags.turboshaft_instruction_selection;
#else
    bool use_turboshaft_instruction_selection = false;
#endif

    const bool success = GenerateCodeFromTurboshaftGraph(
        use_turboshaft_instruction_selection, &linkage, turboshaft_pipeline,
        &pipeline, data.osr_helper_ptr());
    if (!success) return {};

    if (use_turboshaft_instruction_selection) {
      Handle<Code> code;
      if (turboshaft_pipeline.FinalizeCode().ToHandle(&code) &&
          turboshaft_pipeline.CommitDependencies(code)) {
        return code;
      }
      return {};
    } else {
      Handle<Code> code;
      if (pipeline.FinalizeCode().ToHandle(&code) &&
          pipeline.CommitDependencies(code)) {
        return code;
      }
      return {};
    }
  }
}

// static
MaybeHandle<Code> Pipeline::GenerateCodeForTesting(
    OptimizedCompilationInfo* info, Isolate* isolate,
    CallDescriptor* call_descriptor, Graph* graph,
    const AssemblerOptions& options, Schedule* schedule) {
  // Construct a pipeline for scheduling and code generation.
  ZoneStats zone_stats(isolate->allocator());
  NodeOriginTable* node_positions = info->zone()->New<NodeOriginTable>(graph);
  TFPipelineData data(&zone_stats, info, isolate, isolate->allocator(), graph,
                      nullptr, schedule, nullptr, node_positions, nullptr,
                      options, nullptr);
  PipelineJobScope scope(&data, isolate->counters()->runtime_call_stats());
  std::unique_ptr<TurbofanPipelineStatistics> pipeline_statistics;
  if (v8_flags.turbo_stats || v8_flags.turbo_stats_nvp) {
    pipeline_statistics.reset(new TurbofanPipelineStatistics(
        info, isolate->GetTurboStatistics(), &zone_stats));
    pipeline_statistics->BeginPhaseKind("V8.TFTestCodegen");
  }

  PipelineImpl pipeline(&data);

  if (info->trace_turbo_json()) {
    TurboJsonFile json_of(info, std::ios_base::trunc);
    json_of << "{\"function\":\"" << info->GetDebugName().get()
            << "\", \"source\":\"\",\n\"phases\":[";
  }
  // TODO(rossberg): Should this really be untyped?
  pipeline.RunPrintAndVerify("V8.TFMachineCode", true);

  // Ensure we have a schedule.
  if (data.schedule() == nullptr) {
    pipeline.ComputeScheduledGraph();
  }

  Handle<Code> code;
  if (pipeline.GenerateCode(call_descriptor).ToHandle(&code) &&
      pipeline.CommitDependencies(code)) {
    return code;
  }
  return {};
}

// static
MaybeHandle<Code> Pipeline::GenerateTurboshaftCodeForTesting(
    CallDescriptor* call_descriptor, turboshaft::PipelineData* data) {
  Isolate* isolate = data->isolate();
  OptimizedCompilationInfo* info = data->info();
  PipelineJobScope scope(data, isolate->counters()->runtime_call_stats());
  std::unique_ptr<TurbofanPipelineStatistics> pipeline_statistics;
  if (v8_flags.turbo_stats || v8_flags.turbo_stats_nvp) {
    pipeline_statistics.reset(new TurbofanPipelineStatistics(
        info, isolate->GetTurboStatistics(), data->zone_stats()));
    pipeline_statistics->BeginPhaseKind("V8.TFTestCodegen");
  }

  turboshaft::Pipeline pipeline(data);

  if (info->trace_turbo_json()) {
    {
      TurboJsonFile json_of(info, std::ios_base::trunc);
      json_of << "{\"function\":\"" << info->GetDebugName().get()
              << "\", \"source\":\"\",\n\"phases\":[";
    }
    {
      UnparkedScopeIfNeeded scope(data->broker());
      AllowHandleDereference allow_deref;

      TurboJsonFile json_of(data->info(), std::ios_base::app);
      turboshaft::PrintTurboshaftGraphForTurbolizer(
          json_of, data->graph(), "V8.TSMachineCode", data->node_origins(),
          data->graph_zone());
    }
  }

  info->tick_counter().TickAndMaybeEnterSafepoint();

  data->InitializeCodegenComponent(nullptr);

  Handle<Code> code;
  if (pipeline.GenerateCode(call_descriptor).ToHandle(&code) &&
      pipeline.CommitDependencies(code)) {
    return code;
  }
  return {};
}

// static
std::unique_ptr<TurbofanCompilationJob> Pipeline::NewCompilationJob(
    Isolate* isolate, Handle<JSFunction> function, CodeKind code_kind,
    bool has_script, BytecodeOffset osr_offset) {
  Handle<SharedFunctionInfo> shared(function->shared(), isolate);
  return std::make_unique<PipelineCompilationJob>(isolate, shared, function,
                                                  osr_offset, code_kind);
}

void Pipeline::AllocateRegistersForTesting(const RegisterConfiguration* config,
                                           InstructionSequence* sequence,
                                           bool run_verifier) {
  OptimizedCompilationInfo info(base::ArrayVector("testing"), sequence->zone(),
                                CodeKind::FOR_TESTING);
  ZoneStats zone_stats(sequence->isolate()->allocator());
  TFPipelineData data(&zone_stats, &info, sequence->isolate(), sequence);
  data.InitializeFrameData(nullptr);

  if (info.trace_turbo_json()) {
    TurboJsonFile json_of(&info, std::ios_base::trunc);
    json_of << "{\"function\":\"" << info.GetDebugName().get()
            << "\", \"source\":\"\",\n\"phases\":[";
  }

  // TODO(nicohartmann): Should migrate this to turboshaft::Pipeline eventually.
  PipelineImpl pipeline(&data);
  pipeline.AllocateRegisters(config, nullptr, run_verifier);
}

void PipelineImpl::ComputeScheduledGraph() {
  TFPipelineData* data = this->data_;

  // We should only schedule the graph if it is not scheduled yet.
  DCHECK_NULL(data->schedule());

  Run<ComputeSchedulePhase>();
  TraceScheduleAndVerify(data->info(), data, data->schedule(), "schedule");
}

#if V8_ENABLE_WASM_SIMD256_REVEC
void PipelineImpl::Revectorize() { Run<RevectorizePhase>(); }
#endif  // V8_ENABLE_WASM_SIMD256_REVEC

bool PipelineImpl::SelectInstructions(Linkage* linkage) {
  auto call_descriptor = linkage->GetIncomingDescriptor();
  TFPipelineData* data = this->data_;

  // We should have a scheduled graph.
  DCHECK_NOT_NULL(data->graph());
  DCHECK_NOT_NULL(data->schedule());

  if (v8_flags.reorder_builtins && Builtins::IsBuiltinId(info()->builtin())) {
    UnparkedScopeIfNeeded unparked_scope(data->broker());
    BasicBlockCallGraphProfiler::StoreCallGraph(info(), data->schedule());
  }

  if (v8_flags.turbo_profiling) {
    UnparkedScopeIfNeeded unparked_scope(data->broker());
    data->info()->set_profiler_data(BasicBlockInstrumentor::Instrument(
        info(), data->graph(), data->schedule(), data->isolate()));
  }

  bool verify_stub_graph =
      data->verify_graph() ||
      (v8_flags.turbo_verify_machine_graph != nullptr &&
       (!strcmp(v8_flags.turbo_verify_machine_graph, "*") ||
        !strcmp(v8_flags.turbo_verify_machine_graph, data->debug_name())));
  // Jump optimization runs instruction selection twice, but the instruction
  // selector mutates nodes like swapping the inputs of a load, which can
  // violate the machine graph verification rules. So we skip the second
  // verification on a graph that already verified before.
  auto jump_opt = data->jump_optimization_info();
  if (jump_opt && jump_opt->is_optimizing()) {
    verify_stub_graph = false;
  }
  if (verify_stub_graph) {
    if (v8_flags.trace_verify_csa) {
      UnparkedScopeIfNeeded scope(data->broker());
      AllowHandleDereference allow_deref;
      CodeTracer::StreamScope tracing_scope(data->GetCodeTracer());
      tracing_scope.stream()
          << "--------------------------------------------------\n"
          << "--- Verifying " << data->debug_name()
          << " generated by TurboFan\n"
          << "--------------------------------------------------\n"
          << *data->schedule()
          << "--------------------------------------------------\n"
          << "--- End of " << data->debug_name() << " generated by TurboFan\n"
          << "--------------------------------------------------\n";
    }
    // TODO(jgruber): The parameter is called is_stub but actually contains
    // something different. Update either the name or its contents.
    bool is_stub = !data->info()->IsOptimizing();
#if V8_ENABLE_WEBASSEMBLY
    if (data->info()->IsWasm()) is_stub = false;
#endif  // V8_ENABLE_WEBASSEMBLY
    Zone temp_zone(data->allocator(), kMachineGraphVerifierZoneName);
    MachineGraphVerifier::Run(data->graph(), data->schedule(), linkage, is_stub,
                              data->debug_name(), &temp_zone);
  }

  Run<BitcastElisionPhase>(Builtins::IsBuiltinId(data->info()->builtin()));

  data->InitializeInstructionSequence(call_descriptor);

  // Depending on which code path led us to this function, the frame may or
  // may not have been initialized. If it hasn't yet, initialize it now.
  if (!data->frame()) {
    data->InitializeFrameData(call_descriptor);
  }
  // Select and schedule instructions covering the scheduled graph.
  if (std::optional<BailoutReason> bailout =
          Run<InstructionSelectionPhase>(linkage)) {
    info()->AbortOptimization(*bailout);
    data->EndPhaseKind();
    return false;
  }

  if (info()->trace_turbo_json() && !data->MayHaveUnverifiableGraph()) {
    UnparkedScopeIfNeeded scope(data->broker());
    AllowHandleDereference allow_deref;
    TurboCfgFile tcf(isolate());
    tcf << AsC1V("CodeGen", data->schedule(), data->source_positions(),
                 data->sequence());
  }

  if (info()->trace_turbo_json()) {
    std::ostringstream source_position_output;
    // Output source position information before the graph is deleted.
    if (data_->source_positions() != nullptr) {
      data_->source_positions()->PrintJson(source_position_output);
    } else {
      source_position_output << "{}";
    }
    source_position_output << ",\n\"nodeOrigins\" : ";
    data_->node_origins()->PrintJson(source_position_output);
    data_->set_source_position_output(source_position_output.str());
  }

  data->DeleteGraphZone();

  return AllocateRegisters(call_descriptor, true);
}

bool PipelineImpl::AllocateRegisters(CallDescriptor* call_descriptor,
                                     bool has_dummy_end_block) {
  TFPipelineData* data = this->data_;
  DCHECK_NOT_NULL(data->sequence());

  data->BeginPhaseKind("V8.TFRegisterAllocation");

  bool run_verifier = v8_flags.turbo_verify_allocation;

  // Allocate registers.

  const RegisterConfiguration* config = RegisterConfiguration::Default();
  std::unique_ptr<const RegisterConfiguration> restricted_config;
  if (call_descriptor->HasRestrictedAllocatableRegisters()) {
    RegList registers = call_descriptor->AllocatableRegisters();
    DCHECK_LT(0, registers.Count());
    restricted_config.reset(
        RegisterConfiguration::RestrictGeneralRegisters(registers));
    config = restricted_config.get();
  }
  AllocateRegisters(config, call_descriptor, run_verifier);

  // Verify the instruction sequence has the same hash in two stages.
  VerifyGeneratedCodeIsIdempotent();

  Run<FrameElisionPhase>(has_dummy_end_block);

  // TODO(mtrofin): move this off to the register allocator.
  bool generate_frame_at_start =
      data_->sequence()->instruction_blocks().front()->must_construct_frame();
  // Optimimize jumps.
  if (v8_flags.turbo_jt) {
    Run<JumpThreadingPhase>(generate_frame_at_start);
  }

  data->EndPhaseKind();

  return true;
}

void PipelineImpl::VerifyGeneratedCodeIsIdempotent() {
  TFPipelineData* data = this->data_;
  JumpOptimizationInfo* jump_opt = data->jump_optimization_info();
  if (jump_opt == nullptr) return;

  InstructionSequence* code = data->sequence();
  int instruction_blocks = code->InstructionBlockCount();
  int virtual_registers = code->VirtualRegisterCount();
  size_t hash_code = base::hash_combine(instruction_blocks, virtual_registers);
  for (auto instr : *code) {
    hash_code = base::hash_combine(hash_code, instr->opcode(),
                                   instr->InputCount(), instr->OutputCount());
  }
  for (int i = 0; i < virtual_registers; i++) {
    hash_code = base::hash_combine(hash_code, code->GetRepresentation(i));
  }
  if (jump_opt->is_collecting()) {
    jump_opt->hash_code = hash_code;
  } else {
    CHECK_EQ(hash_code, jump_opt->hash_code);
  }
}

void PipelineImpl::AssembleCode(Linkage* linkage) {
  TFPipelineData* data = this->data_;
  data->BeginPhaseKind("V8.TFCodeGeneration");
  data->InitializeCodeGenerator(linkage);

  UnparkedScopeIfNeeded unparked_scope(data->broker());

  Run<AssembleCodePhase>();
  if (data->info()->trace_turbo_json()) {
    TurboJsonFile json_of(data->info(), std::ios_base::app);
    json_of << "{\"name\":\"code generation\""
            << ", \"type\":\"instructions\""
            << InstructionStartsAsJSON{&data->code_generator()->instr_starts()}
            << TurbolizerCodeOffsetsInfoAsJSON{
                   &data->code_generator()->offsets_info()};
    json_of << "},\n";
  }
  data->DeleteInstructionZone();
  data->EndPhaseKind();
}

MaybeHandle<Code> PipelineImpl::FinalizeCode(bool retire_broker) {
  TFPipelineData* data = this->data_;
  data->BeginPhaseKind("V8.TFFinalizeCode");
  if (data->broker() && retire_broker) {
    data->broker()->Retire();
  }
  Run<FinalizeCodePhase>();

  MaybeHandle<Code> maybe_code = data->code();
  Handle<Code> code;
  if (!maybe_code.ToHandle(&code)) {
    return maybe_code;
  }

  info()->SetCode(code);
  PrintCode(isolate(), code, info());

  // Functions with many inline candidates are sensitive to correct call
  // frequency feedback and should therefore not be tiered up early.
  if (v8_flags.profile_guided_optimization &&
      info()->could_not_inline_all_candidates() &&
      info()->shared_info()->cached_tiering_decision() !=
          CachedTieringDecision::kDelayMaglev) {
    info()->shared_info()->set_cached_tiering_decision(
        CachedTieringDecision::kNormal);
  }

  if (info()->trace_turbo_json()) {
    TurboJsonFile json_of(info(), std::ios_base::app);

    json_of << "{\"name\":\"disassembly\",\"type\":\"disassembly\""
            << BlockStartsAsJSON{&data->code_generator()->block_starts()}
            << "\"data\":\"";
#ifdef ENABLE_DISASSEMBLER
    std::stringstream disassembly_stream;
    code->Disassemble(nullptr, disassembly_stream, isolate());
    std::string disassembly_string(disassembly_stream.str());
    for (const auto& c : disassembly_string) {
      json_of << AsEscapedUC16ForJSON(c);
    }
#endif  // ENABLE_DISASSEMBLER
    json_of << "\"}\n],\n";
    json_of << "\"nodePositions\":";
    // TODO(nicohartmann@): We should try to always provide source positions.
    json_of << (data->source_position_output().empty()
                    ? "{}"
                    : data->source_position_output())
            << ",\n";
    JsonPrintAllSourceWithPositions(json_of, data->info(), isolate());
    if (info()->has_bytecode_array()) {
      json_of << ",\n";
      JsonPrintAllBytecodeSources(json_of, info());
    }
    json_of << "\n}";
  }
  if (info()->trace_turbo_json() || info()->trace_turbo_graph()) {
    CodeTracer::StreamScope tracing_scope(data->GetCodeTracer());
    tracing_scope.stream()
        << "---------------------------------------------------\n"
        << "Finished compiling method " << info()->GetDebugName().get()
        << " using TurboFan" << std::endl;
  }
  data->EndPhaseKind();
  return code;
}

bool PipelineImpl::SelectInstructionsAndAssemble(
    CallDescriptor* call_descriptor) {
  Linkage linkage(call_descriptor);

  // Perform instruction selection and register allocation.
  if (!SelectInstructions(&linkage)) return false;

  // Generate the final machine code.
  AssembleCode(&linkage);
  return true;
}

MaybeHandle<Code> PipelineImpl::GenerateCode(CallDescriptor* call_descriptor) {
  if (!SelectInstructionsAndAssemble(call_descriptor)) {
    return MaybeHandle<Code>();
  }
  return FinalizeCode();
}

bool PipelineImpl::CommitDependencies(Handle<Code> code) {
  return data_->dependencies() == nullptr ||
         data_->dependencies()->Commit(code);
}

namespace {

void TraceSequence(OptimizedCompilationInfo* info, TFPipelineData* data,
                   const char* phase_name) {
  if (info->trace_turbo_json()) {
    UnparkedScopeIfNeeded scope(data->broker());
    AllowHandleDereference allow_deref;
    TurboJsonFile json_of(info, std::ios_base::app);
    json_of << "{\"name\":\"" << phase_name << "\",\"type\":\"sequence\""
            << ",\"blocks\":" << InstructionSequenceAsJSON{data->sequence()}
            << ",\"register_allocation\":{"
            << RegisterAllocationDataAsJSON{*(data->register_allocation_data()),
                                            *(data->sequence())}
            << "}},\n";
  }
  if (info->trace_turbo_graph()) {
    UnparkedScopeIfNeeded scope(data->broker());
    AllowHandleDereference allow_deref;
    CodeTracer::StreamScope tracing_scope(data->GetCodeTracer());
    tracing_scope.stream() << "----- Instruction sequence " << phase_name
                           << " -----\n"
                           << *data->sequence();
  }
}

}  // namespace

void PipelineImpl::AllocateRegisters(const RegisterConfiguration* config,
                                     CallDescriptor* call_descriptor,
                                     bool run_verifier) {
  TFPipelineData* data = this->data_;
  // Don't track usage for this zone in compiler stats.
  std::unique_ptr<Zone> verifier_zone;
  RegisterAllocatorVerifier* verifier = nullptr;
  if (run_verifier) {
    verifier_zone.reset(
        new Zone(data->allocator(), kRegisterAllocatorVerifierZoneName));
    verifier = verifier_zone->New<RegisterAllocatorVerifier>(
        verifier_zone.get(), config, data->sequence(), data->frame());
  }

#ifdef DEBUG
  data_->sequence()->ValidateEdgeSplitForm();
  data_->sequence()->ValidateDeferredBlockEntryPaths();
  data_->sequence()->ValidateDeferredBlockExitPaths();
#endif

  data->InitializeRegisterAllocationData(config, call_descriptor);

  Run<MeetRegisterConstraintsPhase>();
  Run<ResolvePhisPhase>();
  Run<BuildLiveRangesPhase>();
  Run<BuildBundlesPhase>();

  TraceSequence(info(), data, "before register allocation");
  if (verifier != nullptr) {
    CHECK(!data->register_allocation_data()->ExistsUseWithoutDefinition());
    CHECK(data->register_allocation_data()
              ->RangesDefinedInDeferredStayInDeferred());
  }

  if (info()->trace_turbo_json() && !data->MayHaveUnverifiableGraph()) {
    TurboCfgFile tcf(isolate());
    tcf << AsC1VRegisterAllocationData("PreAllocation",
                                       data->register_allocation_data());
  }

  Run<AllocateGeneralRegistersPhase<LinearScanAllocator>>();

  if (data->sequence()->HasFPVirtualRegisters()) {
    Run<AllocateFPRegistersPhase<LinearScanAllocator>>();
  }

  if (data->sequence()->HasSimd128VirtualRegisters() &&
      (kFPAliasing == AliasingKind::kIndependent)) {
    Run<AllocateSimd128RegistersPhase<LinearScanAllocator>>();
  }

  Run<DecideSpillingModePhase>();
  Run<AssignSpillSlotsPhase>();
  Run<CommitAssignmentPhase>();

  // TODO(chromium:725559): remove this check once
  // we understand the cause of the bug. We keep just the
  // check at the end of the allocation.
  if (verifier != nullptr) {
    verifier->VerifyAssignment("Immediately after CommitAssignmentPhase.");
  }

  Run<ConnectRangesPhase>();

  Run<ResolveControlFlowPhase>();

  Run<PopulateReferenceMapsPhase>();

  if (v8_flags.turbo_move_optimization) {
    Run<OptimizeMovesPhase>();
  }

  TraceSequence(info(), data, "after register allocation");

  if (verifier != nullptr) {
    verifier->VerifyAssignment("End of regalloc pipeline.");
    verifier->VerifyGapMoves();
  }

  if (info()->trace_turbo_json() && !data->MayHaveUnverifiableGraph()) {
    TurboCfgFile tcf(isolate());
    tcf << AsC1VRegisterAllocationData("CodeGen",
                                       data->register_allocation_data());
  }

  data->DeleteRegisterAllocationZone();
}

OptimizedCompilationInfo* PipelineImpl::info() const { return data_->info(); }

Isolate* PipelineImpl::isolate() const { return data_->isolate(); }

CodeGenerator* PipelineImpl::code_generator() const {
  return data_->code_generator();
}

ObserveNodeManager* PipelineImpl::observe_node_manager() const {
  return data_->observe_node_manager();
}

std::ostream& operator<<(std::ostream& out, const InstructionRangesAsJSON& s) {
  const int max = static_cast<int>(s.sequence->LastInstructionIndex());

  out << ", \"nodeIdToInstructionRange\": {";
  bool need_comma = false;
  for (size_t i = 0; i < s.instr_origins->size(); ++i) {
    std::pair<int, int> offset = (*s.instr_origins)[i];
    if (offset.first == -1) continue;
    const int first = max - offset.first + 1;
    const int second = max - offset.second + 1;
    if (need_comma) out << ", ";
    out << "\"" << i << "\": [" << first << ", " << second << "]";
    need_comma = true;
  }
  out << "}";
  out << ", \"blockIdToInstructionRange\": {";
  need_comma = false;
  for (auto block : s.sequence->instruction_blocks()) {
    if (need_comma) out << ", ";
    out << "\"" << block->rpo_number() << "\": [" << block->code_start() << ", "
        << block->code_end() << "]";
    need_comma = true;
  }
  out << "}";
  return out;
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```