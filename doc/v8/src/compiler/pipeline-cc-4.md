Response:
My thinking process to answer the request about the provided C++ code snippet goes like this:

1. **Understand the Goal:** The request asks for a summary of the functionality of the provided C++ code, specifically within the context of the V8 JavaScript engine's `pipeline.cc` file. It also asks about potential Torque origins, JavaScript relationships, logical deductions, common programming errors, and a final summary.

2. **Initial Code Scan (High-Level):** I first quickly scanned the code to identify key areas and patterns. I noticed:
    * Heavy use of V8-specific classes like `OptimizedCompilationInfo`, `wasm::CompilationEnv`, `MachineGraph`, `CallDescriptor`, etc. This immediately tells me it's deeply embedded within V8's compilation process.
    * The presence of both `GenerateCodeForWasmFunction` and `GenerateWasmCodeFromTurboshaftGraph` strongly suggests it deals with WebAssembly compilation.
    * The existence of `GenerateCodeForTesting` indicates internal testing utilities.
    * The `PipelineImpl` class and its `Run` method point to a pipeline-based architecture.
    * Several conditional blocks based on flags (e.g., `v8_flags.turboshaft_wasm`, `v8_flags.wasm_opt`) suggest different compilation paths and optimization levels.
    * References to "Turbofan" and "Turboshaft" indicate the two major V8 compilers.
    * Phases like "WasmInliningPhase", "WasmLoopPeelingPhase", "WasmOptimizationPhase", "InstructionSelectionPhase", etc., clearly outline the steps involved in compilation.
    * The code manipulates low-level constructs like instruction sequences and register allocation.

3. **Address Specific Questions:** I then addressed each part of the request systematically:

    * **Functionality Listing:** Based on the code scan, I started listing the core functionalities. The two main WebAssembly code generation functions are the most prominent. Testing and internal utility functions are also important. The pipeline structure is crucial to mention.

    * **Torque Source (.tq):** I checked the file extension. Since it's `.cc`, it's C++ and not a Torque source file.

    * **JavaScript Relationship:** I looked for connections to JavaScript features. While this code is about *compiling* WebAssembly, and WebAssembly can be called from JavaScript, there isn't a direct, explicit manipulation of JavaScript code within *this* specific snippet. The connection is more about *enabling* the execution of WebAssembly, which is often generated from other languages but integrates with JavaScript. My example illustrates how JavaScript *uses* the compiled WebAssembly, even if it's not directly generated here.

    * **Code Logic Inference (Input/Output):**  This is tricky without the full context of how this code is called. I focused on the `SerializeInliningPositions` function as it has clear input (a vector of tuples) and output (a `base::OwnedVector<uint8_t>`). I explained how the data is packed into a byte array. For the larger compilation functions, it's difficult to provide specific input/output without knowing the exact input WebAssembly bytecode, flags, etc. I described the general input (Wasm function, compilation settings) and output (compiled machine code).

    * **Common Programming Errors:** I thought about potential issues in a compilation pipeline. Incorrect handling of compiler flags, leading to unexpected behavior or bugs, is a common problem. I provided a simple JavaScript example where incorrect flags might lead to suboptimal or broken WebAssembly execution.

    * **Overall Functionality (Part 5 of 6):** I synthesized the previous points to provide a concise summary of the code's role in the larger compilation process, focusing on WebAssembly and the interplay between Turbofan and Turboshaft. The "part 5 of 6" suggests it's near the end of a compilation sequence, likely handling the final stages of code generation.

4. **Refine and Organize:** I reviewed my answers to ensure clarity, accuracy, and proper organization. I used headings and bullet points to make the information easier to read. I made sure to explain V8-specific terminology where needed (e.g., Turbofan, Turboshaft).

5. **Self-Correction/Double-Checking:** I mentally re-read the code and my answers to ensure they align. For instance, I confirmed that the code is indeed about *compiling* WebAssembly, not about directly executing JavaScript. I double-checked that my JavaScript example correctly illustrates the *usage* of the compiled WebAssembly. I also made sure to acknowledge the limitations of inferring exact input/output for the larger functions without the full context.

By following these steps, I could systematically analyze the code snippet and generate a comprehensive and informative answer to the user's request.
好的，让我们来分析一下 `v8/src/compiler/pipeline.cc` 的这个代码片段。

**功能列举:**

这段代码的主要功能是 **为 WebAssembly 函数生成机器码**。它涉及了 V8 引擎中两个主要的编译器框架：TurboFan 和 Turboshaft。具体来说，它包含了以下关键功能：

1. **WebAssembly 函数的编译入口:**  `GenerateCodeForWasmFunction` 和 `GenerateWasmCodeFromTurboshaftGraph` 是为 WebAssembly 函数生成机器码的入口点。它们接收编译信息、Wasm 模块环境、中间表示图（`MachineGraph`）以及其他必要的编译数据。

2. **TurboFan 编译流程 (旧)**: `GenerateCodeForWasmFunction`  是针对旧的 TurboFan 编译器的路径。它会执行一系列的优化阶段，包括：
    * **SIMD 重矢量化 (可选):** `Revectorize` 阶段用于优化 SIMD 指令。
    * **各种优化阶段:** 包括内联 (`WasmInliningPhase`), 循环剥离 (`WasmLoopPeelingPhase`), 循环展开 (`WasmLoopUnrollingPhase`), GC 优化 (`WasmGCOptimizationPhase`), 类型化 (`WasmTypingPhase`), GC 低版本化 (`WasmGCLoweringPhase`), 通用优化 (`WasmOptimizationPhase`, `WasmBaseOptimizationPhase`), 内存优化 (`MemoryOptimizationPhase`), 以及机器操作优化 (`MachineOperatorOptimizationPhase`) 等。
    * **指令选择:** `SelectInstructions` 负责将中间表示转换为目标机器的指令。
    * **代码组装:** `AssembleCode` 将选择的指令组装成最终的机器码。
    * **结果封装:** 将生成的机器码、帧信息、源位置信息等封装到 `wasm::WasmCompilationResult` 中。

3. **Turboshaft 编译流程 (新)**: `GenerateWasmCodeFromTurboshaftGraph` 是针对新的 Turboshaft 编译器的路径。它也执行一系列的优化阶段，但使用的是 Turboshaft 框架下的阶段，例如：
    * **图构建:**  `wasm::BuildTSGraph` 使用 Turboshaft 构建图。
    * **SIMD 重矢量化 (可选)**: 与 TurboFan 类似。
    * **各种优化阶段:** 包括循环剥离 (`LoopPeelingPhase`), 循环展开 (`LoopUnrollingPhase`), GC 优化 (`WasmGCOptimizePhase`), 低版本化 (`WasmLoweringPhase`), 通用优化 (`WasmOptimizePhase`), 以及死代码消除 (`WasmDeadCodeEliminationPhase`) 等。
    * **指令选择:**  可以选择使用 Turboshaft 的指令选择器或 TurboFan 的指令选择器，由 `v8_flags` 控制。
    * **代码生成:** `GenerateCodeFromTurboshaftGraph` 函数内部会调用 Turboshaft 或 TurboFan 的代码生成流程。
    * **结果封装:**  将生成的机器码等信息封装到 `wasm::WasmCompilationResult` 中。

4. **通用工具函数:** `SerializeInliningPositions` 函数用于将内联位置信息序列化为字节数组。

5. **测试用的代码生成:** `GenerateCodeForTesting` 和 `GenerateTurboshaftCodeForTesting`  是为了测试编译流程而提供的函数，可以用于生成特定配置下的代码。

6. **寄存器分配:** `AllocateRegistersForTesting` 用于测试寄存器分配功能。

7. **调度图计算:** `ComputeScheduledGraph` 用于计算指令的执行顺序。

**如果 `v8/src/compiler/pipeline.cc` 以 `.tq` 结尾:**

如果 `v8/src/compiler/pipeline.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**。Torque 是一种 V8 自研的类型化的领域特定语言，用于编写 V8 内部的运行时代码（例如内置函数、运行时函数等）。 Torque 代码会被编译成 C++ 代码。

**与 JavaScript 的关系 (及 JavaScript 示例):**

这段 C++ 代码虽然不直接操作 JavaScript 代码，但它 **密切关系到 JavaScript 中 WebAssembly 的执行**。  当 JavaScript 代码中加载并调用 WebAssembly 模块时，V8 引擎会使用这里的代码来将 WebAssembly 的字节码编译成可以在当前 CPU 上运行的机器码。

**JavaScript 示例:**

```javascript
// 创建一个 WebAssembly 实例
WebAssembly.instantiateStreaming(fetch('my_wasm_module.wasm'))
  .then(result => {
    // 获取导出的函数
    const exportedFunction = result.instance.exports.myFunction;

    // 从 JavaScript 调用 WebAssembly 函数
    const resultFromWasm = exportedFunction(10, 20);
    console.log(resultFromWasm);
  });
```

在这个例子中，当 `WebAssembly.instantiateStreaming` 加载并编译 `my_wasm_module.wasm` 时，V8 内部的编译流程（很可能涉及到 `v8/src/compiler/pipeline.cc` 中的代码）会将 Wasm 模块中的函数（例如 `myFunction`）编译成机器码，这样 JavaScript 才能调用它。

**代码逻辑推理 (假设输入与输出):**

让我们以 `SerializeInliningPositions` 函数为例进行逻辑推理：

**假设输入:**

`positions` 是一个 `ZoneVector<std::tuple<int, bool, int>>`，包含以下数据：

```
[
  { func_index: 0, was_tail_call: true, caller_pos: 100 },
  { func_index: 1, was_tail_call: false, caller_pos: 250 },
  { func_index: 0, was_tail_call: true, caller_pos: 400 }
]
```

**输出:**

`result` 是一个 `base::OwnedVector<uint8_t>`，它将 `positions` 中的数据按照 `func_index`, `was_tail_call`, `caller_pos` 的顺序，以二进制形式紧密排列。假设 `int` 是 4 字节，`bool` 是 1 字节，那么每个条目占用 4 + 1 + 4 = 9 字节。

`result` 的内容（以字节表示）将会是：

```
[
  0x00, 0x00, 0x00, 0x00,  // func_index: 0
  0x01,                // was_tail_call: true
  0x64, 0x00, 0x00, 0x00,  // caller_pos: 100

  0x01, 0x00, 0x00, 0x00,  // func_index: 1
  0x00,                // was_tail_call: false
  0xfa, 0x00, 0x00, 0x00,  // caller_pos: 250

  0x00, 0x00, 0x00, 0x00,  // func_index: 0
  0x01,                // was_tail_call: true
  0x90, 0x01, 0x00, 0x00   // caller_pos: 400
]
```

**用户常见的编程错误 (涉及 WebAssembly):**

虽然这段 C++ 代码是 V8 内部的，用户一般不会直接修改它，但了解其功能可以帮助理解与 WebAssembly 相关的常见编程错误：

1. **WebAssembly 模块加载/实例化失败:** 如果 WebAssembly 模块的字节码无效或加载过程中出现错误，V8 的编译流程可能会失败，导致 JavaScript 代码中的 `WebAssembly.instantiateStreaming` Promise rejected。

   ```javascript
   WebAssembly.instantiateStreaming(fetch('invalid_module.wasm'))
     .catch(error => {
       console.error("WebAssembly 模块加载失败:", error);
     });
   ```

2. **WebAssembly 函数签名不匹配:** 当 JavaScript 调用 WebAssembly 函数时，如果传递的参数类型或数量与 WebAssembly 函数的导出签名不匹配，V8 可能会抛出错误。

   **WebAssembly (假设):**
   ```wat
   (module
     (func (export "add") (param i32 i32) (result i32)
       local.get 0
       local.get 1
       i32.add))
   ```

   **JavaScript (错误):**
   ```javascript
   const instance = (await WebAssembly.instantiateStreaming(fetch('module.wasm'))).instance.exports;
   instance.add("hello", 10); // 错误：参数类型不匹配
   ```

3. **WebAssembly 内存访问越界:** 如果 WebAssembly 代码尝试访问超出其分配内存范围的地址，会导致运行时错误。

**归纳一下它的功能 (第 5 部分，共 6 部分):**

考虑到这是第 5 部分，并且前面的部分很可能处理了 WebAssembly 模块的解析、验证、以及中间表示的生成，那么这段代码的功能可以归纳为：

**将 WebAssembly 函数的中间表示（例如 MachineGraph）转换为目标架构的机器码，并进行各种优化以提高性能。这是 WebAssembly 编译流程中非常核心和靠后的一个阶段，负责生成最终可执行的代码。**  在整个编译流程中，这一步紧随着中间表示的构建和优化，并为最终的代码生成和执行做准备。  第 6 部分很可能涉及到将生成的机器码集成到 V8 引擎中，并进行最后的清理和收尾工作。

希望这个分析对您有所帮助！

### 提示词
```
这是目录为v8/src/compiler/pipeline.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/pipeline.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
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
  int instruction_blocks = code->InstructionBlockCou
```