Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/deoptimizer/deoptimizer.cc`. The request also includes several constraints:

1. **List Functionality:**  Describe what the code does.
2. **Torque Check:** Determine if the file would be a Torque file based on its name (it isn't).
3. **JavaScript Relation:** If related to JavaScript functionality, provide a JavaScript example.
4. **Logic Inference:** If there's code logic, provide assumed input and output.
5. **Common Errors:**  If it relates to user programming errors, give an example.
6. **Part of a Series:** Acknowledge that this is part 2 of 4.
7. **Summarize Functionality:** Condense the overall purpose of the snippet.

Let's break down the code snippet:

* **Tracing Functions:**  `TraceDeopt`, `TraceEvictFromOptimizedCodeCache`, `TraceFoundActivation`, `TraceDeoptAll`. These seem to be for logging and debugging deoptimization events.
* **Wasm Deoptimization (Conditional Compilation):** There's a block of code related to WebAssembly deoptimization using Liftoff. This involves recompiling with Liftoff and creating `FrameDescription` objects. This is complex and deals with the intricacies of how WebAssembly execution is handled within V8 during deoptimization.
* **`DoComputeWasmLiftoffFrame`:**  This function specifically handles the creation of a `FrameDescription` for a WebAssembly frame during deoptimization. It interacts with `wasm::NativeModule`, `wasm::WasmCode`, and `wasm::LiftoffFrameDescriptionForDeopt`. It involves setting up stack slots, registers, and frame pointers.
* **`DoComputeOutputFramesWasmImpl`:** This function seems to orchestrate the creation of output frames during WebAssembly deoptimization. It retrieves deoptimization information and iterates through translated frames.
* **`GetWasmStackSlotsCounts`:** A utility function to determine the number of parameter and return stack slots for a WebAssembly function.
* **JavaScript Deoptimization (Conditional Compilation):** There's a section related to JavaScript deoptimization, including checking if Maglev-optimized code is being deoptimized early.
* **`DoComputeOutputFrames`:** This is the main function for computing output frames during deoptimization, handling both JavaScript and potentially WebAssembly (though the `wasm_deopt` check suggests the WebAssembly path is separate). It interacts with `DeoptimizationData`, `TranslatedFrame`, and different types of frames (unoptimized, inlined, stubs, builtins).

**Plan:**

1. **Functionality:** Describe the main purpose as preparing for deoptimization by creating new stack frames. Highlight the WebAssembly-specific and general JavaScript parts.
2. **Torque:** Clearly state it's not Torque.
3. **JavaScript Relation:** Provide a simple JavaScript example that could lead to deoptimization (e.g., changing an object's shape).
4. **Logic Inference:** Focus on the `DoComputeWasmLiftoffFrame` function. Assume a WASM function call and explain how it sets up the new frame with potentially different register and stack layouts. Provide a simplified hypothetical example of register and stack mapping.
5. **Common Errors:**  Focus on type changes in JavaScript leading to deoptimization.
6. **Part of Series:** Acknowledge.
7. **Summary:**  Concise summary of the deoptimization preparation process.
这是v8源代码文件 `v8/src/deoptimizer/deoptimizer.cc` 的一部分，它主要负责在V8 JavaScript引擎中进行**反优化 (Deoptimization)** 过程中的一些关键操作。以下是这段代码的功能归纳：

**功能列举:**

1. **跟踪反优化事件:**  提供了一系列用于跟踪和记录反优化事件的函数 (`TraceDeopt`, `TraceEvictFromOptimizedCodeCache`, `TraceFoundActivation`, `TraceDeoptAll`)。这些函数在 verbose 模式下会输出详细的反优化信息，例如反优化的原因、涉及的函数等，用于调试和性能分析。

2. **处理 WebAssembly 反优化:**  包含用于处理 WebAssembly 代码反优化的逻辑。这部分代码会在需要将优化的 WebAssembly 代码切换回未优化的 Liftoff 代码时被调用。
    * **重新编译 Liftoff 代码:**  `CompileWithLiftoffAndGetDeoptInfo` 函数负责在反优化时重新编译 WebAssembly 函数的 Liftoff 版本，并获取反优化所需的信息。
    * **计算 Liftoff 栈帧:** `DoComputeWasmLiftoffFrame` 函数负责计算反优化后 Liftoff 代码的栈帧布局，包括参数、局部变量、寄存器状态等。它会根据 Liftoff 的 frame description 来设置新的栈帧。
    * **构建 WebAssembly 输出帧:** `DoComputeOutputFramesWasmImpl` 函数是 WebAssembly 反优化的核心，它会根据反优化信息，迭代地创建反优化后的栈帧 (`FrameDescription`)。

3. **计算 JavaScript 反优化输出帧:**  `DoComputeOutputFrames` 函数是计算 JavaScript 代码反优化后输出帧的核心函数。它会根据之前收集的输入信息（例如优化的代码、反优化数据等），计算出反优化后需要在栈上构建的新的栈帧。这包括确定新的程序计数器 (PC)、栈指针 (SP)、帧指针 (FP)、参数等。

4. **辅助函数:** `GetWasmStackSlotsCounts` 函数用于计算 WebAssembly 函数的参数和返回值所需的栈槽数量。

5. **判断提前反优化:** 提供了 `DeoptimizedMaglevvedCodeEarly` 函数，用于判断是否需要提前反优化 Maglev 优化的代码。

**关于文件类型:**

`v8/src/deoptimizer/deoptimizer.cc` 以 `.cc` 结尾，表明它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件。如果它是 Torque 源代码，文件名应该以 `.tq` 结尾。

**与 JavaScript 功能的关系及示例:**

反优化是 V8 引擎为了保证 JavaScript 代码的正确执行而采取的一种回退机制。当优化的代码（例如 TurboFan 或 Maglev 生成的代码）在运行时遇到某些无法处理的情况，或者假设条件不再成立时，V8 会将执行回退到未优化的代码 (通常是 Interpreter 或 Liftoff 生成的代码)。

**JavaScript 示例 (可能触发反优化的情况):**

```javascript
function add(a, b) {
  return a + b;
}

// 第一次调用，V8 可能会优化 add 函数，假设 a 和 b 都是数字
add(1, 2);

// 后续调用，如果传入非数字类型，可能触发反优化
add("hello", "world");
```

在这个例子中，V8 可能会在第一次调用 `add(1, 2)` 时，假设 `a` 和 `b` 始终是数字类型，并生成针对数字加法的优化代码。然而，当后续调用 `add("hello", "world")` 时，类型假设被打破，V8 就需要进行反优化，将执行回退到可以处理字符串拼接的未优化代码。

**代码逻辑推理及假设输入输出 (针对 `DoComputeWasmLiftoffFrame`):**

**假设输入:**

* `frame`: 一个 `TranslatedFrame` 对象，描述了需要反优化的 WebAssembly 栈帧的信息，例如函数索引、字节码偏移量等。
* `native_module`:  指向 WebAssembly 本地模块的指针。
* `wasm_trusted_instance`:  WebAssembly 实例数据。
* `frame_index`: 当前处理的栈帧索引。
* `shadow_stack`: 用于 CET (Control-flow Enforcement Technology) 的影子栈。

**处理过程 (简化):**

1. **重新编译 Liftoff:** 使用 `CompileWithLiftoffAndGetDeoptInfo` 获取 Liftoff 代码和反优化信息。
2. **计算栈帧大小:** 根据 Liftoff 的描述和参数数量计算新栈帧的大小。
3. **创建 `FrameDescription`:**  分配内存创建一个新的 `FrameDescription` 对象。
4. **设置栈顶 (Top):**  根据当前栈帧索引计算新栈帧的栈顶地址。
5. **设置程序计数器 (PC):**  从 Liftoff 的反优化信息中获取 PC 偏移量，并计算出新的 PC 值。
6. **设置帧指针 (FP):** 计算并设置新栈帧的帧指针。
7. **复制参数:** 将参数从旧栈帧复制到新栈帧的对应位置。
8. **设置寄存器值:**  根据 Liftoff 的寄存器状态信息，将寄存器的值设置到新的 `FrameDescription` 中。
9. **存储元数据:**  存储 WebAssembly 实例数据、帧类型、反馈向量等信息。

**假设输出:**

* `output_frame`: 一个指向新创建的 `FrameDescription` 对象的指针，该对象描述了反优化后 Liftoff 代码的栈帧布局，包含了正确的 PC、SP、FP、寄存器值以及其他必要的元数据。

**用户常见编程错误举例 (与反优化相关):**

用户在编写 JavaScript 代码时，容易犯一些导致类型不稳定，从而频繁触发反优化的错误：

```javascript
function process(input) {
  if (typeof input === 'number') {
    return input * 2;
  } else if (typeof input === 'string') {
    return input.toUpperCase();
  }
  return null;
}

console.log(process(5));     // V8 可能优化此路径
console.log(process("abc")); // 可能会触发反优化，因为 input 的类型发生了变化
console.log(process({}));    // 继续触发反优化
```

在这个例子中，`process` 函数接受不同类型的输入。虽然这是合法的 JavaScript，但会导致 V8 难以进行有效的优化，因为每次调用时 `input` 的类型都可能不同，从而导致频繁的反优化和重新优化，降低性能。

**功能归纳 (针对提供的代码片段):**

这段代码片段是 V8 引擎反优化机制的一部分，主要负责在发生反优化时，**为 JavaScript 和 WebAssembly 代码创建新的、未优化的栈帧**。它包含了跟踪反优化事件、处理 WebAssembly 特定的反优化流程（包括重新编译 Liftoff 代码和构建 Liftoff 栈帧），以及计算 JavaScript 代码反优化后的栈帧布局等功能。 其核心目标是确保程序能够从优化后的代码安全地回退到未优化版本继续执行。

Prompt: 
```
这是目录为v8/src/deoptimizer/deoptimizer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/deoptimizer/deoptimizer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
int(deopt_data->GetSharedFunctionInfo(), scope.file());
    PrintF(") (opt id %d) for deoptimization, reason: %s]\n",
           deopt_data->OptimizationId().value(), reason);
  }
  if (!v8_flags.log_deopt) return;
  no_gc.Release();
  {
    HandleScope handle_scope(isolate);
    PROFILE(isolate,
            CodeDependencyChangeEvent(
                handle(code, isolate),
                handle(deopt_data->GetSharedFunctionInfo(), isolate), reason));
  }
}

// static
void Deoptimizer::TraceEvictFromOptimizedCodeCache(
    Isolate* isolate, Tagged<SharedFunctionInfo> sfi, const char* reason) {
  if (!v8_flags.trace_deopt_verbose) return;

  DisallowGarbageCollection no_gc;
  CodeTracer::Scope scope(isolate->GetCodeTracer());
  PrintF(scope.file(),
         "[evicting optimized code marked for deoptimization (%s) for ",
         reason);
  ShortPrint(sfi, scope.file());
  PrintF(scope.file(), "]\n");
}

#ifdef DEBUG
// static
void Deoptimizer::TraceFoundActivation(Isolate* isolate,
                                       Tagged<JSFunction> function) {
  if (!v8_flags.trace_deopt_verbose) return;
  CodeTracer::Scope scope(isolate->GetCodeTracer());
  PrintF(scope.file(), "[deoptimizer found activation of function: ");
  function->PrintName(scope.file());
  PrintF(scope.file(), " / %" V8PRIxPTR "]\n", function.ptr());
}
#endif  // DEBUG

// static
void Deoptimizer::TraceDeoptAll(Isolate* isolate) {
  if (!v8_flags.trace_deopt_verbose) return;
  CodeTracer::Scope scope(isolate->GetCodeTracer());
  PrintF(scope.file(), "[deoptimize all code in all contexts]\n");
}

#if V8_ENABLE_WEBASSEMBLY
namespace {
std::pair<wasm::WasmCode*,
          std::unique_ptr<wasm::LiftoffFrameDescriptionForDeopt>>
CompileWithLiftoffAndGetDeoptInfo(wasm::NativeModule* native_module,
                                  int function_index,
                                  BytecodeOffset deopt_point, bool is_topmost) {
  wasm::WasmCompilationUnit unit(function_index, wasm::ExecutionTier::kLiftoff,
                                 wasm::ForDebugging::kNotForDebugging);
  wasm::WasmDetectedFeatures detected;
  wasm::CompilationEnv env = wasm::CompilationEnv::ForModule(native_module);
  env.deopt_info_bytecode_offset = deopt_point.ToInt();
  env.deopt_location_kind = is_topmost
                                ? wasm::LocationKindForDeopt::kEagerDeopt
                                : wasm::LocationKindForDeopt::kInlinedCall;
  std::shared_ptr<wasm::WireBytesStorage> wire_bytes =
      native_module->compilation_state()->GetWireBytesStorage();
  wasm::WasmCompilationResult result =
      unit.ExecuteCompilation(&env, &*wire_bytes, nullptr, &detected);

  // Replace the optimized code with the unoptimized code in the
  // WasmCodeManager as a deopt was reached.
  std::unique_ptr<wasm::WasmCode> compiled_code =
      native_module->AddCompiledCode(result);
  wasm::WasmCodeRefScope code_ref_scope;
  // TODO(mliedtke): This might unoptimize functions because they were inlined
  // into a function that now needs to deopt them while the optimized function
  // might have taken different inlining decisions.
  // TODO(mliedtke): The code cache should also be invalidated.
  wasm::WasmCode* wasm_code = native_module->compilation_state()->PublishCode(
      base::VectorOf(&compiled_code, 1))[0];
  return {wasm_code, std::move(result.liftoff_frame_descriptions)};
}
}  // anonymous namespace

FrameDescription* Deoptimizer::DoComputeWasmLiftoffFrame(
    TranslatedFrame& frame, wasm::NativeModule* native_module,
    Tagged<WasmTrustedInstanceData> wasm_trusted_instance, int frame_index,
    std::stack<intptr_t>& shadow_stack) {
  // Given inlined frames where function a calls b, b is considered the topmost
  // because b is on top of the call stack! This is aligned with the names used
  // by the JS deopt.
  const bool is_bottommost = frame_index == 0;
  const bool is_topmost = output_count_ - 1 == frame_index;
  // Recompile the liftoff (unoptimized) wasm code for the input frame.
  // TODO(mliedtke): This recompiles every single function even if it never got
  // optimized and exists as a liftoff variant in the WasmCodeManager as we also
  // need to compute the deopt information. Can we avoid some of the extra work
  // here?
  auto [wasm_code, liftoff_description] = CompileWithLiftoffAndGetDeoptInfo(
      native_module, frame.wasm_function_index(), frame.bytecode_offset(),
      is_topmost);

  DCHECK(liftoff_description);

  int parameter_stack_slots, return_stack_slots;
  const wasm::FunctionSig* sig =
      native_module->module()->functions[frame.wasm_function_index()].sig;
  GetWasmStackSlotsCounts(sig, &parameter_stack_slots, &return_stack_slots);

  // Allocate and populate the FrameDescription describing the output frame.
  const uint32_t output_frame_size = liftoff_description->total_frame_size;
  const uint32_t total_output_frame_size =
      output_frame_size + parameter_stack_slots * kSystemPointerSize +
      CommonFrameConstants::kFixedFrameSizeAboveFp;

  if (verbose_tracing_enabled()) {
    std::ostringstream outstream;
    outstream << "  Liftoff stack & register state for function index "
              << frame.wasm_function_index() << ", frame size "
              << output_frame_size << ", total frame size "
              << total_output_frame_size << '\n';
    size_t index = 0;
    for (const wasm::LiftoffVarState& state : liftoff_description->var_state) {
      outstream << "     " << index++ << ": " << state << '\n';
    }
    FILE* file = trace_scope()->file();
    PrintF(file, "%s", outstream.str().c_str());
  }

  FrameDescription* output_frame = FrameDescription::Create(
      total_output_frame_size, parameter_stack_slots, isolate());

  // Copy the parameter stack slots.
  static_assert(CommonFrameConstants::kFixedFrameSizeAboveFp ==
                2 * kSystemPointerSize);
  uint32_t output_offset = total_output_frame_size;
  // Zero out the incoming parameter slots. This will make sure that tagged
  // values are safely ignored by the gc.
  // Note that zero is clearly not the correct value. Still, liftoff copies
  // all parameters into "its own" stack slots at the beginning and always
  // uses these slots to restore parameters from the stack.
  for (int i = 0; i < parameter_stack_slots; ++i) {
    output_offset -= kSystemPointerSize;
    output_frame->SetFrameSlot(output_offset, 0);
  }

  // Calculate top and update previous caller's pc.
  Address top = is_bottommost ? caller_frame_top_ - total_output_frame_size
                              : output_[frame_index - 1]->GetTop() -
                                    total_output_frame_size;
  output_frame->SetTop(top);
  Address pc = wasm_code->instruction_start() + liftoff_description->pc_offset;
  // Sign the PC. Note that for the non-topmost frames the stack pointer at
  // which the PC is stored as the "caller pc" / return address depends on the
  // amount of parameter stack slots of the callee. To simplify the code, we
  // just sign it as if there weren't any parameter stack slots.
  // When building up the next frame we can check and "move" the caller PC by
  // signing it again with the correct stack pointer.
  Address signed_pc = PointerAuthentication::SignAndCheckPC(
      isolate(), pc, output_frame->GetTop());
  output_frame->SetPc(signed_pc);
#ifdef V8_ENABLE_CET_SHADOW_STACK
  if (v8_flags.cet_compatible) {
    if (is_topmost) {
      shadow_stack.push(pc);
    } else {
      shadow_stack.push(wasm_code->instruction_start() +
                        liftoff_description->adapt_shadow_stack_pc_offset);
    }
  }
#endif  // V8_ENABLE_CET_SHADOW_STACK

  // Sign the previous frame's PC.
  if (is_bottommost) {
    Address old_context =
        caller_frame_top_ - input_->parameter_count() * kSystemPointerSize;
    Address new_context =
        caller_frame_top_ - parameter_stack_slots * kSystemPointerSize;
    caller_pc_ = PointerAuthentication::MoveSignedPC(isolate(), caller_pc_,
                                                     new_context, old_context);
  } else if (parameter_stack_slots != 0) {
    // The previous frame's PC is stored at a different stack slot, so we need
    // to re-sign the PC for the new context (stack pointer).
    FrameDescription* previous_frame = output_[frame_index - 1];
    Address pc = previous_frame->GetPc();
    Address old_context = previous_frame->GetTop();
    Address new_context =
        old_context - parameter_stack_slots * kSystemPointerSize;
    Address signed_pc = PointerAuthentication::MoveSignedPC(
        isolate(), pc, new_context, old_context);
    previous_frame->SetPc(signed_pc);
  }

  // Store the caller PC.
  output_offset -= kSystemPointerSize;
  output_frame->SetFrameSlot(
      output_offset,
      is_bottommost ? caller_pc_ : output_[frame_index - 1]->GetPc());
  // Store the caller frame pointer.
  output_offset -= kSystemPointerSize;
  output_frame->SetFrameSlot(
      output_offset,
      is_bottommost ? caller_fp_ : output_[frame_index - 1]->GetFp());

  CHECK_EQ(output_frame_size, output_offset);
  int base_offset = output_frame_size;

  // Set trusted instance data on output frame.
  output_frame->SetFrameSlot(
      base_offset - WasmLiftoffFrameConstants::kInstanceDataOffset,
      wasm_trusted_instance.ptr());
  if (liftoff_description->trusted_instance != no_reg) {
    output_frame->SetRegister(liftoff_description->trusted_instance.code(),
                              wasm_trusted_instance.ptr());
  }

  DCHECK_GE(translated_state_.frames().size(), 1);
  auto liftoff_iter = liftoff_description->var_state.begin();
  if constexpr (Is64()) {
    // On 32 bit platforms int64s are represented as 2 values on Turbofan.
    // Liftoff on the other hand treats them as 1 value (a register pair).
    CHECK_EQ(liftoff_description->var_state.size(), frame.GetValueCount());
  }

  bool int64_lowering_is_low = true;

  for (const TranslatedValue& value : frame) {
    bool skip_increase_liftoff_iter = false;
    switch (liftoff_iter->loc()) {
      case wasm::LiftoffVarState::kIntConst:
        if (!Is64() && liftoff_iter->kind() == wasm::ValueKind::kI64) {
          if (int64_lowering_is_low) skip_increase_liftoff_iter = true;
          int64_lowering_is_low = !int64_lowering_is_low;
        }
        break;  // Nothing to be done for constants in liftoff frame.
      case wasm::LiftoffVarState::kRegister:
        if (liftoff_iter->is_gp_reg()) {
          intptr_t reg_value = kZapValue;
          switch (value.kind()) {
            case TranslatedValue::Kind::kInt32:
              // Ensure that the upper half is zeroed out.
              reg_value = static_cast<uint32_t>(value.int32_value());
              break;
            case TranslatedValue::Kind::kTagged:
              reg_value = value.raw_literal().ptr();
              break;
            case TranslatedValue::Kind::kInt64:
              reg_value = value.int64_value();
              break;
            default:
              UNIMPLEMENTED();
          }
          output_frame->SetRegister(liftoff_iter->reg().gp().code(), reg_value);
        } else if (liftoff_iter->is_fp_reg()) {
          switch (value.kind()) {
            case TranslatedValue::Kind::kDouble:
              output_frame->SetDoubleRegister(liftoff_iter->reg().fp().code(),
                                              value.double_value());
              break;
            case TranslatedValue::Kind::kFloat:
              // Liftoff doesn't have a concept of floating point registers.
              // This is an important distinction as e.g. on arm s1 and d1 are
              // two completely distinct registers.
              static_assert(std::is_same_v<decltype(liftoff_iter->reg().fp()),
                                           DoubleRegister>);
              output_frame->SetDoubleRegister(
                  liftoff_iter->reg().fp().code(),
                  Float64::FromBits(value.float_value().get_bits()));
              break;
            case TranslatedValue::Kind::kSimd128:
              output_frame->SetSimd128Register(liftoff_iter->reg().fp().code(),
                                               value.simd_value());
              break;
            default:
              UNIMPLEMENTED();
          }
        } else if (!Is64() && liftoff_iter->is_gp_reg_pair()) {
          intptr_t reg_value = kZapValue;
          switch (value.kind()) {
            case TranslatedValue::Kind::kInt32:
              // Ensure that the upper half is zeroed out.
              reg_value = static_cast<uint32_t>(value.int32_value());
              break;
            case TranslatedValue::Kind::kTagged:
              reg_value = value.raw_literal().ptr();
              break;
            default:
              UNREACHABLE();
          }
          int8_t reg = int64_lowering_is_low
                           ? liftoff_iter->reg().low_gp().code()
                           : liftoff_iter->reg().high_gp().code();
          output_frame->SetRegister(reg, reg_value);
          if (int64_lowering_is_low) skip_increase_liftoff_iter = true;
          int64_lowering_is_low = !int64_lowering_is_low;
        } else if (!Is64() && liftoff_iter->is_fp_reg_pair()) {
          CHECK_EQ(value.kind(), TranslatedValue::Kind::kSimd128);
          Simd128 simd_value = value.simd_value();
          Address val_ptr = reinterpret_cast<Address>(&simd_value);
          output_frame->SetDoubleRegister(
              liftoff_iter->reg().low_fp().code(),
              Float64::FromBits(base::ReadUnalignedValue<uint64_t>(val_ptr)));
          output_frame->SetDoubleRegister(
              liftoff_iter->reg().high_fp().code(),
              Float64::FromBits(base::ReadUnalignedValue<uint64_t>(
                  val_ptr + sizeof(double))));
        } else {
          UNREACHABLE();
        }
        break;
      case wasm::LiftoffVarState::kStack:
#ifdef V8_TARGET_BIG_ENDIAN
        static constexpr int kLiftoffStackBias = 4;
#else
        static constexpr int kLiftoffStackBias = 0;
#endif
        switch (liftoff_iter->kind()) {
          case wasm::ValueKind::kI32:
            CHECK(value.kind() == TranslatedValue::Kind::kInt32 ||
                  value.kind() == TranslatedValue::Kind::kUint32);
            output_frame->SetLiftoffFrameSlot32(
                base_offset - liftoff_iter->offset() + kLiftoffStackBias,
                value.int32_value_);
            break;
          case wasm::ValueKind::kF32:
            CHECK_EQ(value.kind(), TranslatedValue::Kind::kFloat);
            output_frame->SetLiftoffFrameSlot32(
                base_offset - liftoff_iter->offset() + kLiftoffStackBias,
                value.float_value().get_bits());
            break;
          case wasm::ValueKind::kI64:
            if constexpr (Is64()) {
              CHECK(value.kind() == TranslatedValue::Kind::kInt64 ||
                    value.kind() == TranslatedValue::Kind::kUint64);
              output_frame->SetLiftoffFrameSlot64(
                  base_offset - liftoff_iter->offset(), value.int64_value_);
            } else {
              CHECK(value.kind() == TranslatedValue::Kind::kInt32 ||
                    value.kind() == TranslatedValue::Kind::kUint32);
              // TODO(bigendian): Either the offsets or the default for
              // int64_lowering_is_low might have to be swapped.
              if (int64_lowering_is_low) {
                skip_increase_liftoff_iter = true;
                output_frame->SetLiftoffFrameSlot32(
                    base_offset - liftoff_iter->offset(), value.int32_value_);
              } else {
                output_frame->SetLiftoffFrameSlot32(
                    base_offset - liftoff_iter->offset() + sizeof(int32_t),
                    value.int32_value_);
              }
              int64_lowering_is_low = !int64_lowering_is_low;
            }
            break;
          case wasm::ValueKind::kS128: {
            int64x2 values = value.simd_value().to_i64x2();
            const int offset = base_offset - liftoff_iter->offset();
            output_frame->SetLiftoffFrameSlot64(offset, values.val[0]);
            output_frame->SetLiftoffFrameSlot64(offset + sizeof(int64_t),
                                                values.val[1]);
            break;
          }
          case wasm::ValueKind::kF64:
            CHECK_EQ(value.kind(), TranslatedValue::Kind::kDouble);
            output_frame->SetLiftoffFrameSlot64(
                base_offset - liftoff_iter->offset(),
                value.double_value().get_bits());
            break;
          case wasm::ValueKind::kRef:
          case wasm::ValueKind::kRefNull:
            CHECK_EQ(value.kind(), TranslatedValue::Kind::kTagged);
            output_frame->SetLiftoffFrameSlotPointer(
                base_offset - liftoff_iter->offset(), value.raw_literal_.ptr());
            break;
          default:
            UNIMPLEMENTED();
        }
        break;
    }
    DCHECK_IMPLIES(skip_increase_liftoff_iter, !Is64());
    if (!skip_increase_liftoff_iter) {
      ++liftoff_iter;
    }
  }

  // Store frame kind.
  uint32_t frame_type_offset =
      base_offset + WasmLiftoffFrameConstants::kFrameTypeOffset;
  output_frame->SetFrameSlot(frame_type_offset,
                             StackFrame::TypeToMarker(StackFrame::WASM));
  // Store feedback vector in stack slot.
  Tagged<FixedArray> module_feedback =
      wasm_trusted_instance->feedback_vectors();
  uint32_t feedback_offset =
      base_offset - WasmLiftoffFrameConstants::kFeedbackVectorOffset;
  uint32_t fct_feedback_index = wasm::declared_function_index(
      native_module->module(), frame.wasm_function_index());
  CHECK_LT(fct_feedback_index, module_feedback->length());
  Tagged<Object> feedback_vector = module_feedback->get(fct_feedback_index);
  if (IsSmi(feedback_vector)) {
    if (verbose_tracing_enabled()) {
      PrintF(trace_scope()->file(),
             "Deopt with uninitialized feedback vector for function %s [%d]\n",
             wasm_code->DebugName().c_str(), frame.wasm_function_index());
    }
    // Not having a feedback vector can happen with multiple instantiations of
    // the same module as the type feedback is separate per instance but the
    // code is shared (even cross-isolate).
    // Note that we cannot allocate the feedback vector here. Instead, store
    // the function index, so that the feedback vector can be populated by the
    // deopt finish builtin called from Liftoff.
    output_frame->SetFrameSlot(feedback_offset,
                               Smi::FromInt(fct_feedback_index).ptr());
  } else {
    output_frame->SetFrameSlot(feedback_offset, feedback_vector.ptr());
  }

  // Instead of a builtin continuation for wasm the deopt builtin will
  // call a c function to destroy the Deoptimizer object and then directly
  // return to the liftoff code.
  output_frame->SetContinuation(0);

  const intptr_t fp_value = top + output_frame_size;
  output_frame->SetFp(fp_value);
  Register fp_reg = JavaScriptFrame::fp_register();
  output_frame->SetRegister(fp_reg.code(), fp_value);
  output_frame->SetRegister(kRootRegister.code(), isolate()->isolate_root());
#ifdef V8_COMPRESS_POINTERS
  output_frame->SetRegister(kPtrComprCageBaseRegister.code(),
                            isolate()->cage_base());
#endif

  return output_frame;
}

// Build up the output frames for a wasm deopt. This creates the
// FrameDescription objects representing the output frames to be "materialized"
// on the stack.
void Deoptimizer::DoComputeOutputFramesWasmImpl() {
  CHECK(v8_flags.wasm_deopt);
  base::ElapsedTimer timer;
  // Lookup the deopt info for the input frame.
  wasm::WasmCode* code = compiled_optimized_wasm_code_;
  DCHECK_NOT_NULL(code);
  DCHECK_EQ(code->kind(), wasm::WasmCode::kWasmFunction);
  wasm::WasmDeoptView deopt_view(code->deopt_data());
  wasm::WasmDeoptEntry deopt_entry =
      deopt_view.GetDeoptEntry(deopt_exit_index_);

  if (tracing_enabled()) {
    timer.Start();
    FILE* file = trace_scope()->file();
    PrintF(file,
           "[bailout (kind: %s, reason: %s, type: Wasm): begin. deoptimizing "
           "%s, function index %d, bytecode offset %d, deopt exit %d, FP to SP "
           "delta %d, "
           "pc " V8PRIxPTR_FMT "]\n",
           MessageFor(deopt_kind_),
           DeoptimizeReasonToString(DeoptimizeReason::kWrongCallTarget),
           code->DebugName().c_str(), code->index(),
           deopt_entry.bytecode_offset.ToInt(), deopt_entry.translation_index,
           fp_to_sp_delta_, PointerAuthentication::StripPAC(from_));
  }

  base::Vector<const uint8_t> off_heap_translations =
      deopt_view.GetTranslationsArray();

  DeoptTranslationIterator state_iterator(off_heap_translations,
                                          deopt_entry.translation_index);
  wasm::NativeModule* native_module = code->native_module();
  int parameter_count = static_cast<int>(
      native_module->module()->functions[code->index()].sig->parameter_count());
  DeoptimizationLiteralProvider literals(
      deopt_view.BuildDeoptimizationLiteralArray());

  Register fp_reg = JavaScriptFrame::fp_register();
  stack_fp_ = input_->GetRegister(fp_reg.code());
  Address fp_address = input_->GetFramePointerAddress();
  caller_fp_ = Memory<intptr_t>(fp_address);
  caller_pc_ =
      Memory<intptr_t>(fp_address + CommonFrameConstants::kCallerPCOffset);
  caller_frame_top_ = stack_fp_ + CommonFrameConstants::kFixedFrameSizeAboveFp +
                      input_->parameter_count() * kSystemPointerSize;

  FILE* trace_file =
      verbose_tracing_enabled() ? trace_scope()->file() : nullptr;
  translated_state_.Init(isolate_, input_->GetFramePointerAddress(), stack_fp_,
                         &state_iterator, {}, literals,
                         input_->GetRegisterValues(), trace_file,
                         parameter_count, parameter_count);

  const size_t output_frames = translated_state_.frames().size();
  CHECK_GT(output_frames, 0);
  output_count_ = static_cast<int>(output_frames);
  output_ = new FrameDescription* [output_frames] {};

  // The top output function *should* be the same as the optimized function
  // with the deopt. However, this is not the case in case of inlined return
  // calls. The optimized function still needs to be invalidated.
  if (translated_state_.frames()[0].wasm_function_index() !=
      compiled_optimized_wasm_code_->index()) {
    CompileWithLiftoffAndGetDeoptInfo(native_module,
                                      compiled_optimized_wasm_code_->index(),
                                      deopt_entry.bytecode_offset, false);
  }

  // Read the trusted instance data from the input frame.
  Tagged<WasmTrustedInstanceData> wasm_trusted_instance =
      Cast<WasmTrustedInstanceData>((Tagged<Object>(input_->GetFrameSlot(
          input_->GetFrameSize() -
          (2 + input_->parameter_count()) * kSystemPointerSize -
          WasmLiftoffFrameConstants::kInstanceDataOffset))));

  std::stack<intptr_t> shadow_stack;
  for (int i = 0; i < output_count_; ++i) {
    TranslatedFrame& frame = translated_state_.frames()[i];
    output_[i] = DoComputeWasmLiftoffFrame(
        frame, native_module, wasm_trusted_instance, i, shadow_stack);
  }

#ifdef V8_ENABLE_CET_SHADOW_STACK
  if (v8_flags.cet_compatible) {
    CHECK_EQ(shadow_stack_count_, 0);
    shadow_stack_ = new intptr_t[shadow_stack.size()];
    while (!shadow_stack.empty()) {
      shadow_stack_[shadow_stack_count_++] = shadow_stack.top();
      shadow_stack.pop();
    }
    CHECK_EQ(shadow_stack_count_, output_count_);
  }
#endif  // V8_ENABLE_CET_SHADOW_STACK

  {
    // Mark the cached feedback result produced by the
    // TransitiveTypeFeedbackProcessor as outdated.
    // This is required to prevent deopt loops as new feedback is ignored
    // otherwise.
    wasm::TypeFeedbackStorage& feedback =
        native_module->module()->type_feedback;
    base::SharedMutexGuard<base::kExclusive> mutex_guard(&feedback.mutex);
    for (const TranslatedFrame& frame : translated_state_) {
      int index = frame.wasm_function_index();
      auto iter = feedback.feedback_for_function.find(index);
      if (iter != feedback.feedback_for_function.end()) {
        iter->second.needs_reprocessing_after_deopt = true;
      }
    }
    // Reset tierup priority. This is important as the tierup trigger will only
    // be taken into account if the tierup_priority is a power of two (to
    // prevent a hot function being enqueued too many times into the compilation
    // queue.)
    feedback.feedback_for_function[code->index()].tierup_priority = 0;
    // Add sample for how many times this function was deopted.
    isolate()->counters()->wasm_deopts_per_function()->AddSample(
        ++feedback.deopt_count_for_function[code->index()]);
  }

  // Reset tiering budget of the function that triggered the deopt.
  int declared_func_index =
      wasm::declared_function_index(native_module->module(), code->index());
  wasm_trusted_instance->tiering_budget_array()[declared_func_index].store(
      v8_flags.wasm_tiering_budget, std::memory_order_relaxed);

  isolate()->counters()->wasm_deopts_executed()->AddSample(
      wasm::GetWasmEngine()->IncrementDeoptsExecutedCount());

  if (verbose_tracing_enabled()) {
    TraceDeoptEnd(timer.Elapsed().InMillisecondsF());
  }
}

void Deoptimizer::GetWasmStackSlotsCounts(const wasm::FunctionSig* sig,
                                          int* parameter_stack_slots,
                                          int* return_stack_slots) {
  class DummyResultCollector {
   public:
    void AddParamAt(size_t index, LinkageLocation location) {}
    void AddReturnAt(size_t index, LinkageLocation location) {}
  } result_collector;

  // On 32 bits we need to perform the int64 lowering for the signature.
#if V8_TARGET_ARCH_32_BIT
  if (!alloc_) {
    DCHECK(!zone_);
    alloc_.emplace();
    zone_.emplace(&*alloc_, "deoptimizer i32sig lowering");
  }
  sig = GetI32Sig(&*zone_, sig);
#endif
  int untagged_slots, untagged_return_slots;  // Unused.
  wasm::IterateSignatureImpl(sig, false, result_collector, &untagged_slots,
                             parameter_stack_slots, &untagged_return_slots,
                             return_stack_slots);
}
#endif  // V8_ENABLE_WEBASSEMBLY

namespace {

bool DeoptimizedMaglevvedCodeEarly(Isolate* isolate,
                                   Tagged<JSFunction> function,
                                   Tagged<Code> code) {
  if (!code->is_maglevved()) return false;
  if (function->GetRequestedOptimizationIfAny(isolate) ==
      CodeKind::TURBOFAN_JS) {
    // We request turbofan after consuming the invocation_count_for_turbofan
    // budget which is greater than
    // invocation_count_for_maglev_with_delay.
    return false;
  }
  int current_invocation_budget =
      function->raw_feedback_cell()->interrupt_budget() /
      function->shared()->GetBytecodeArray(isolate)->length();
  return current_invocation_budget >=
         v8_flags.invocation_count_for_turbofan -
             v8_flags.invocation_count_for_maglev_with_delay;
}

}  // namespace

// We rely on this function not causing a GC.  It is called from generated code
// without having a real stack frame in place.
void Deoptimizer::DoComputeOutputFrames() {
  // When we call this function, the return address of the previous frame has
  // been removed from the stack by the DeoptimizationEntry builtin, so the
  // stack is not iterable by the StackFrameIteratorForProfiler.
#if V8_TARGET_ARCH_STORES_RETURN_ADDRESS_ON_STACK
  DCHECK_EQ(0, isolate()->isolate_data()->stack_is_iterable());
#endif
  base::ElapsedTimer timer;

#if V8_ENABLE_WEBASSEMBLY
  if (v8_flags.wasm_deopt && function_.is_null()) {
    trap_handler::ClearThreadInWasm();
    DoComputeOutputFramesWasmImpl();
    trap_handler::SetThreadInWasm();
    return;
  }
#endif

  // Determine basic deoptimization information.  The optimized frame is
  // described by the input data.
  Tagged<DeoptimizationData> input_data =
      Cast<DeoptimizationData>(compiled_code_->deoptimization_data());

  {
    // Read caller's PC, caller's FP and caller's constant pool values
    // from input frame. Compute caller's frame top address.

    Register fp_reg = JavaScriptFrame::fp_register();
    stack_fp_ = input_->GetRegister(fp_reg.code());

    caller_frame_top_ = stack_fp_ + ComputeInputFrameAboveFpFixedSize();

    Address fp_address = input_->GetFramePointerAddress();
    caller_fp_ = Memory<intptr_t>(fp_address);
    caller_pc_ =
        Memory<intptr_t>(fp_address + CommonFrameConstants::kCallerPCOffset);
    actual_argument_count_ = static_cast<int>(
        Memory<intptr_t>(fp_address + StandardFrameConstants::kArgCOffset));

    if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
      caller_constant_pool_ = Memory<intptr_t>(
          fp_address + CommonFrameConstants::kConstantPoolOffset);
    }
  }

  StackGuard* const stack_guard = isolate()->stack_guard();
  CHECK_GT(static_cast<uintptr_t>(caller_frame_top_),
           stack_guard->real_jslimit());

  BytecodeOffset bytecode_offset =
      input_data->GetBytecodeOffsetOrBuiltinContinuationId(deopt_exit_index_);
  auto translations = input_data->FrameTranslation();
  unsigned translation_index =
      input_data->TranslationIndex(deopt_exit_index_).value();

  if (tracing_enabled()) {
    timer.Start();
    TraceDeoptBegin(input_data->OptimizationId().value(), bytecode_offset);
  }

  FILE* trace_file =
      verbose_tracing_enabled() ? trace_scope()->file() : nullptr;
  DeoptimizationFrameTranslation::Iterator state_iterator(translations,
                                                          translation_index);
  DeoptimizationLiteralProvider literals(input_data->LiteralArray());
  translated_state_.Init(isolate_, input_->GetFramePointerAddress(), stack_fp_,
                         &state_iterator, input_data->ProtectedLiteralArray(),
                         literals, input_->GetRegisterValues(), trace_file,
                         compiled_code_->parameter_count_without_receiver(),
                         actual_argument_count_ - kJSArgcReceiverSlots);

  bytecode_offset_in_outermost_frame_ =
      translated_state_.frames()[0].bytecode_offset();

  // Do the input frame to output frame(s) translation.
  size_t count = translated_state_.frames().size();
  if (is_restart_frame()) {
    // If the debugger requested to restart a particular frame, only materialize
    // up to that frame.
    count = restart_frame_index_ + 1;
  } else if (deoptimizing_throw_) {
    // If we are supposed to go to the catch handler, find the catching frame
    // for the catch and make sure we only deoptimize up to that frame.
    size_t catch_handler_frame_index = count;
    for (size_t i = count; i-- > 0;) {
      catch_handler_pc_offset_ = LookupCatchHandler(
          isolate(), &(translated_state_.frames()[i]), &catch_handler_data_);
      if (catch_handler_pc_offset_ >= 0) {
        catch_handler_frame_index = i;
        break;
      }
    }
    CHECK_LT(catch_handler_frame_index, count);
    count = catch_handler_frame_index + 1;
  }

  DCHECK_NULL(output_);
  output_ = new FrameDescription* [count] {};
  output_count_ = static_cast<int>(count);

  // Translate each output frame.
  int frame_index = 0;
  size_t total_output_frame_size = 0;
  for (size_t i = 0; i < count; ++i, ++frame_index) {
    TranslatedFrame* translated_frame = &(translated_state_.frames()[i]);
    const bool handle_exception = deoptimizing_throw_ && i == count - 1;
    switch (translated_frame->kind()) {
      case TranslatedFrame::kUnoptimizedFunction:
        DoComputeUnoptimizedFrame(translated_frame, frame_index,
                                  handle_exception);
        break;
      case TranslatedFrame::kInlinedExtraArguments:
        DoComputeInlinedExtraArguments(translated_frame, frame_index);
        break;
      case TranslatedFrame::kConstructCreateStub:
        DoComputeConstructCreateStubFrame(translated_frame, frame_index);
        break;
      case TranslatedFrame::kConstructInvokeStub:
        DoComputeConstructInvokeStubFrame(translated_frame, frame_index);
        break;
      case TranslatedFrame::kBuiltinContinuation:
#if V8_ENABLE_WEBASSEMBLY
      case TranslatedFrame::kJSToWasmBuiltinContinuation:
#endif  // V8_ENABLE_WEBASSEMBLY
        DoComputeBuiltinContinuation(translated_frame, frame_index,
                                     BuiltinContinuationMode::STUB);
        break;
      case TranslatedFrame::kJavaScriptBuiltinContinuation:
        DoComputeBuiltinContinuation(translated_frame, frame_index,
                                     BuiltinContinuationMode::JAVASCRIPT);
        brea
"""


```