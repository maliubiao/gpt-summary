Response: The user wants a summary of the functionality of the C++ source code file `v8/src/deoptimizer/deoptimizer.cc`, specifically the second part of the file. The summary should also explain the relationship to Javascript functionality with an example if applicable.

**High-level plan:**

1. Read through the provided code snippet, focusing on the methods and logic.
2. Identify the main purpose and functionalities implemented in this section.
3. Determine if and how these functionalities relate to Javascript behavior.
4. If a relationship exists, create a simple Javascript example to illustrate it.

**Detailed plan:**

1. **Analyze `DoComputeUnoptimizedFrame`:** This function seems responsible for setting up the stack frame when deoptimizing to unoptimized (interpreter or baseline) code. It involves calculating frame size, setting up registers (PC, FP, context), and translating values from the optimized frame. This is crucial for transitioning execution from optimized to unoptimized code.

2. **Analyze `DoComputeInlinedExtraArguments`:** This function deals with how extra arguments of inlined functions are handled during deoptimization. It creates a special frame to hold these arguments. This is important for maintaining correct argument passing semantics after deoptimization.

3. **Analyze `DoComputeConstructCreateStubFrame` and `DoComputeConstructInvokeStubFrame`:** These functions handle deoptimization when a constructor call is involved. They set up frames for the `ConstructStub` which is used to manage object creation. This relates to the `new` keyword in Javascript.

4. **Analyze the `BuiltinContinuation` related functions (`DoComputeBuiltinContinuation`, `TrampolineForBuiltinContinuation`):** These functions deal with deoptimizing to a point where the next action is to call a built-in function. They construct a special frame that prepares the necessary arguments for the built-in. This is related to how Javascript calls internal V8 functions.

5. **Analyze `MaterializeHeapObjects`:** This function seems responsible for ensuring that objects that were only represented as stack values in optimized code are properly allocated on the heap during deoptimization. This is crucial for correctness since unoptimized code expects objects to be on the heap.

6. **Analyze the remaining helper functions (`QueueValueForMaterialization`, `QueueFeedbackVectorForMaterialization`, `ComputeInputFrameAboveFpFixedSize`, `ComputeInputFrameSize`, `ComputeIncomingArgumentSize`, `GetDeoptCallPCFromReturnPC`, `GetDeoptInfo`):** These are utility functions for calculating frame sizes, managing materialization queues, and retrieving information about the deoptimization point.

7. **Identify Javascript connections:**  The key connections are:
    *   Deoptimizing to interpreter/baseline relates directly to how Javascript code is executed initially or after optimization failures.
    *   Handling inlined arguments is necessary for correct behavior of Javascript functions that call other functions, especially with more arguments than parameters.
    *   Construct stubs are essential for the `new` operator in Javascript.
    *   Built-in continuations relate to how Javascript interacts with internal V8 functions for operations like array manipulation, object creation, etc.
    *   Materialization is vital for maintaining the integrity of Javascript object references during deoptimization.

8. **Construct Javascript example:** Focus on a scenario where deoptimization is likely to occur, such as calling a function that was initially optimized but encounters a condition that forces it back to unoptimized code (e.g., type mismatch).

9. **Summarize:** Combine the findings into a concise summary of the file's functionality, emphasizing its role in the deoptimization process and its connection to Javascript execution.
这是 `v8/src/deoptimizer/deoptimizer.cc` 源代码文件的第二部分，它延续了第一部分的工作，主要负责在 V8 引擎中将执行从优化后的代码（例如 TurboFan 或 Maglev 生成的代码）回退到未优化的代码（解释器或 Baseline 代码）的过程，这个过程被称为**反优化 (Deoptimization)**。

**主要功能归纳:**

*   **计算和设置反优化后的栈帧:** 这部分代码包含了多个 `DoCompute...Frame` 函数，它们分别负责计算和设置不同类型的反优化后的栈帧。这些栈帧模拟了未优化代码执行时的状态，包括：
    *   **`DoComputeUnoptimizedFrame`:**  计算和设置反优化到解释器或 Baseline 代码的栈帧。它会根据原始帧的信息，在新的栈上分配空间，并填充参数、局部变量、上下文、函数指针、字节码偏移等信息。
    *   **`DoComputeInlinedExtraArguments`:**  处理内联函数调用时的额外参数。当反优化发生时，需要将这些额外参数放入一个特殊的栈帧中。
    *   **`DoComputeConstructCreateStubFrame` 和 `DoComputeConstructInvokeStubFrame`:**  处理构造函数调用相关的反优化。它们设置用于执行构造函数 stub 的栈帧。
    *   **`DoComputeBuiltinContinuation`:** 处理反优化到内置函数的情况。它会创建一个特殊的栈帧，其中包含调用内置函数所需的参数和上下文。

*   **处理 WebAssembly 相关的反优化:**  代码中包含 `#if V8_ENABLE_WEBASSEMBLY` 宏，表明它也处理了从 WebAssembly 代码反优化到 JavaScript 的情况。`TranslatedValueForWasmReturnKind` 函数用于获取 WebAssembly 函数的返回值，以便在反优化后正确传递。

*   **栈帧布局和数据写入:**  `FrameWriter` 类被用于方便地将数据写入到新分配的栈帧中。代码中大量使用了 `frame_writer.Push...` 方法来填充栈帧的各个部分。

*   **延迟物化 (Lazy Materialization):** `MaterializeHeapObjects` 函数负责将那些在优化代码中可能只存在于寄存器或栈上的对象“物化”到堆上。这是因为未优化的代码通常期望对象存在于堆上。

*   **管理物化队列:** `QueueValueForMaterialization` 和 `QueueFeedbackVectorForMaterialization` 函数用于将需要在反优化后物化的对象添加到队列中。

*   **计算帧大小:**  `ComputeInputFrameAboveFpFixedSize` 和 `ComputeInputFrameSize` 等函数用于计算优化代码的原始栈帧大小，以便在反优化时正确分配空间。

*   **获取反优化信息:** `GetDeoptInfo` 函数用于从优化后的代码中提取关于反优化原因、位置等关键信息。

**与 JavaScript 功能的关系及示例:**

反优化是 V8 引擎确保 JavaScript 代码正确执行的关键机制。当优化后的代码遇到无法处理的情况（例如，类型假设失败、代码 patching 等）时，引擎会触发反优化，将执行回退到未优化的版本，保证代码的正确性，尽管性能会有所下降。

**JavaScript 示例:**

```javascript
function add(a, b) {
  return a + b;
}

// 第一次调用，V8 可能会对 add 函数进行优化
add(1, 2);

// 第二次调用，如果传入了非数字类型，可能会触发反优化
add("hello", "world");

// 后续调用可能继续在未优化模式下执行，或者再次尝试优化
add(3, 4);
```

**解释:**

1. 当 `add(1, 2)` 首次被调用时，V8 的优化器（例如 TurboFan）可能会根据参数的类型（都是数字）生成高度优化的机器码。
2. 当 `add("hello", "world")` 被调用时，优化后的代码可能无法处理字符串类型的参数，因为之前的优化基于数字类型的假设。这会导致 V8 触发反优化。
3. 反优化过程会使用 `deoptimizer.cc` 中的代码来构建未优化版本的栈帧，并将执行回退到解释器或 Baseline 编译器生成的代码。
4. 后续的 `add(3, 4)` 调用可能会在未优化的模式下执行，或者 V8 可能会在稍后再次尝试优化 `add` 函数，但这次会考虑到更广泛的类型可能性。

**在这个例子中，`deoptimizer.cc` 的作用就是确保当优化后的 `add` 函数无法处理字符串参数时，能够安全地将执行回退到可以处理这种情况的未优化版本，从而保证 JavaScript 代码的正确执行。** `DoComputeUnoptimizedFrame` 会被用来设置解释器或 Baseline 代码的栈帧，以便 `add("hello", "world")` 能够在未优化的环境下执行。

总之，`v8/src/deoptimizer/deoptimizer.cc` 的第二部分继续详细描述了反优化的具体实现，包括如何构建各种类型的反优化栈帧，处理 WebAssembly 相关的场景，以及如何确保反优化后程序的正确状态。它是 V8 引擎中保证 JavaScript 代码可靠执行的重要组成部分。

Prompt: 
```
这是目录为v8/src/deoptimizer/deoptimizer.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
k;
      case TranslatedFrame::kJavaScriptBuiltinContinuationWithCatch:
        DoComputeBuiltinContinuation(
            translated_frame, frame_index,
            handle_exception
                ? BuiltinContinuationMode::JAVASCRIPT_HANDLE_EXCEPTION
                : BuiltinContinuationMode::JAVASCRIPT_WITH_CATCH);
        break;
#if V8_ENABLE_WEBASSEMBLY
      case TranslatedFrame::kWasmInlinedIntoJS:
        FATAL("inlined wasm frames may not appear in JS deopts");
      case TranslatedFrame::kLiftoffFunction:
        FATAL("wasm liftoff frames may not appear in JS deopts");
#endif
      case TranslatedFrame::kInvalid:
        FATAL("invalid frame");
    }
    total_output_frame_size += output_[frame_index]->GetFrameSize();
  }

  FrameDescription* topmost = output_[count - 1];
  topmost->GetRegisterValues()->SetRegister(kRootRegister.code(),
                                            isolate()->isolate_root());
#ifdef V8_COMPRESS_POINTERS
  topmost->GetRegisterValues()->SetRegister(kPtrComprCageBaseRegister.code(),
                                            isolate()->cage_base());
#endif

#ifdef V8_ENABLE_CET_SHADOW_STACK
  if (v8_flags.cet_compatible) {
    CHECK_EQ(shadow_stack_count_, 0);
    shadow_stack_ = new intptr_t[count + 1];

    // We should jump to the continuation through AdaptShadowStack to avoid
    // security exception.
    // Clear the continuation so that DeoptimizationEntry does not push the
    // address onto the stack, and push it to the shadow stack instead.
    if (output_[count - 1]->GetContinuation()) {
      shadow_stack_[shadow_stack_count_++] =
          output_[count - 1]->GetContinuation();
      output_[count - 1]->SetContinuation(0);
    }

    // Add topmost frame's pc to the shadow stack.
    shadow_stack_[shadow_stack_count_++] =
        output_[count - 1]->GetPc() -
        Deoptimizer::kAdaptShadowStackOffsetToSubtract;

    // Add return addresses to the shadow stack, except for the bottommost.
    // The bottommost frame's return address already exists in the shadow stack.
    for (int i = static_cast<int>(count) - 1; i > 0; i--) {
      if (!output_[i]->HasCallerPc()) continue;
      shadow_stack_[shadow_stack_count_++] =
          output_[i]->GetCallerPc() -
          Deoptimizer::kAdaptShadowStackOffsetToSubtract;
    }
  }
#endif  // V8_ENABLE_CET_SHADOW_STACK

  // Don't reset the tiering state for OSR code since we might reuse OSR code
  // after deopt, and we still want to tier up to non-OSR code even if OSR code
  // deoptimized.
  bool osr_early_exit = Deoptimizer::GetDeoptInfo().deopt_reason ==
                        DeoptimizeReason::kOSREarlyExit;
  // TODO(saelo): We have to use full pointer comparisons here while not all
  // Code objects have been migrated into trusted space.
  static_assert(!kAllCodeObjectsLiveInTrustedSpace);
  if (IsJSFunction(function_) &&
      (compiled_code_->osr_offset().IsNone()
           ? function_->code(isolate()).SafeEquals(compiled_code_)
           : (!osr_early_exit &&
              DeoptExitIsInsideOsrLoop(isolate(), function_,
                                       bytecode_offset_in_outermost_frame_,
                                       compiled_code_->osr_offset())))) {
    if (v8_flags.profile_guided_optimization &&
        function_->shared()->cached_tiering_decision() !=
            CachedTieringDecision::kDelayMaglev) {
      if (DeoptimizedMaglevvedCodeEarly(isolate(), function_, compiled_code_)) {
        function_->shared()->set_cached_tiering_decision(
            CachedTieringDecision::kDelayMaglev);
      } else {
        function_->shared()->set_cached_tiering_decision(
            CachedTieringDecision::kNormal);
      }
    }
    function_->ResetTieringRequests(isolate_);
    // This allows us to quickly re-spawn a new compilation request even if
    // there is already one running. In particular it helps to squeeze in a
    // maglev compilation when there is a long running turbofan one that was
    // started right before the deopt.
    function_->SetTieringInProgress(false);
    function_->SetInterruptBudget(isolate_, CodeKind::INTERPRETED_FUNCTION);
    function_->feedback_vector()->set_was_once_deoptimized();
  }

  // Print some helpful diagnostic information.
  if (verbose_tracing_enabled()) {
    TraceDeoptEnd(timer.Elapsed().InMillisecondsF());
  }

  // The following invariant is fairly tricky to guarantee, since the size of
  // an optimized frame and its deoptimized counterparts usually differs. We
  // thus need to consider the case in which deoptimized frames are larger than
  // the optimized frame in stack checks in optimized code. We do this by
  // applying an offset to stack checks (see kArchStackPointerGreaterThan in the
  // code generator).
  // Note that we explicitly allow deopts to exceed the limit by a certain
  // number of slack bytes.
  CHECK_GT(
      static_cast<uintptr_t>(caller_frame_top_) - total_output_frame_size,
      stack_guard->real_jslimit() - kStackLimitSlackForDeoptimizationInBytes);
}

// static
bool Deoptimizer::DeoptExitIsInsideOsrLoop(Isolate* isolate,
                                           Tagged<JSFunction> function,
                                           BytecodeOffset deopt_exit_offset,
                                           BytecodeOffset osr_offset) {
  DisallowGarbageCollection no_gc;
  HandleScope scope(isolate);
  DCHECK(!deopt_exit_offset.IsNone());
  DCHECK(!osr_offset.IsNone());

  Handle<BytecodeArray> bytecode_array(
      function->shared()->GetBytecodeArray(isolate), isolate);
  DCHECK(interpreter::BytecodeArrayIterator::IsValidOffset(
      bytecode_array, deopt_exit_offset.ToInt()));

  interpreter::BytecodeArrayIterator it(bytecode_array, osr_offset.ToInt());
  DCHECK_EQ(it.current_bytecode(), interpreter::Bytecode::kJumpLoop);

  for (; !it.done(); it.Advance()) {
    const int current_offset = it.current_offset();
    // If we've reached the deopt exit, it's contained in the current loop
    // (this is covered by IsInRange below, but this check lets us avoid
    // useless iteration).
    if (current_offset == deopt_exit_offset.ToInt()) return true;
    // We're only interested in loop ranges.
    if (it.current_bytecode() != interpreter::Bytecode::kJumpLoop) continue;
    // Is the deopt exit contained in the current loop?
    if (base::IsInRange(deopt_exit_offset.ToInt(), it.GetJumpTargetOffset(),
                        current_offset)) {
      return true;
    }
    // We've reached nesting level 0, i.e. the current JumpLoop concludes a
    // top-level loop.
    const int loop_nesting_level = it.GetImmediateOperand(1);
    if (loop_nesting_level == 0) return false;
  }

  UNREACHABLE();
}
namespace {

// Get the dispatch builtin for unoptimized frames.
Builtin DispatchBuiltinFor(bool deopt_to_baseline, bool advance_bc,
                           bool is_restart_frame) {
  if (is_restart_frame) return Builtin::kRestartFrameTrampoline;

  if (deopt_to_baseline) {
    return advance_bc ? Builtin::kBaselineOrInterpreterEnterAtNextBytecode
                      : Builtin::kBaselineOrInterpreterEnterAtBytecode;
  } else {
    return advance_bc ? Builtin::kInterpreterEnterAtNextBytecode
                      : Builtin::kInterpreterEnterAtBytecode;
  }
}

}  // namespace

void Deoptimizer::DoComputeUnoptimizedFrame(TranslatedFrame* translated_frame,
                                            int frame_index,
                                            bool goto_catch_handler) {
  Tagged<BytecodeArray> bytecode_array = translated_frame->raw_bytecode_array();
  TranslatedFrame::iterator value_iterator = translated_frame->begin();
  const bool is_bottommost = (0 == frame_index);
  const bool is_topmost = (output_count_ - 1 == frame_index);

  const int real_bytecode_offset = translated_frame->bytecode_offset().ToInt();
  const int bytecode_offset =
      goto_catch_handler ? catch_handler_pc_offset_ : real_bytecode_offset;

  const int parameters_count = bytecode_array->parameter_count();

  // If this is the bottom most frame or the previous frame was the inlined
  // extra arguments frame, then we already have extra arguments in the stack
  // (including any extra padding). Therefore we should not try to add any
  // padding.
  bool should_pad_arguments =
      !is_bottommost && (translated_state_.frames()[frame_index - 1]).kind() !=
                            TranslatedFrame::kInlinedExtraArguments;

  const int locals_count = translated_frame->height();
  UnoptimizedFrameInfo frame_info = UnoptimizedFrameInfo::Precise(
      parameters_count, locals_count, is_topmost, should_pad_arguments);
  const uint32_t output_frame_size = frame_info.frame_size_in_bytes();

  TranslatedFrame::iterator function_iterator = value_iterator++;

  std::optional<Tagged<DebugInfo>> debug_info =
      translated_frame->raw_shared_info()->TryGetDebugInfo(isolate());
  if (debug_info.has_value() && debug_info.value()->HasBreakInfo()) {
    // TODO(leszeks): Validate this bytecode.
    bytecode_array = debug_info.value()->DebugBytecodeArray(isolate());
  }

  // Allocate and store the output frame description.
  FrameDescription* output_frame =
      FrameDescription::Create(output_frame_size, parameters_count, isolate());
  FrameWriter frame_writer(this, output_frame, verbose_trace_scope());

  CHECK(frame_index >= 0 && frame_index < output_count_);
  CHECK_NULL(output_[frame_index]);
  output_[frame_index] = output_frame;

  // Compute this frame's PC and state.
  // For interpreted frames, the PC will be a special builtin that
  // continues the bytecode dispatch. Note that non-topmost and lazy-style
  // bailout handlers also advance the bytecode offset before dispatch, hence
  // simulating what normal handlers do upon completion of the operation.
  // For baseline frames, the PC will be a builtin to convert the interpreter
  // frame to a baseline frame before continuing execution of baseline code.
  // We can't directly continue into baseline code, because of CFI.
  Builtins* builtins = isolate_->builtins();
  const bool advance_bc =
      (!is_topmost || (deopt_kind_ == DeoptimizeKind::kLazy)) &&
      !goto_catch_handler;
  const bool deopt_to_baseline = v8_flags.deopt_to_baseline;
  const bool restart_frame = goto_catch_handler && is_restart_frame();
  Tagged<Code> dispatch_builtin = builtins->code(
      DispatchBuiltinFor(deopt_to_baseline, advance_bc, restart_frame));

  if (verbose_tracing_enabled()) {
    PrintF(trace_scope()->file(), "  translating %s frame ",
           deopt_to_baseline ? "baseline" : "interpreted");
    std::unique_ptr<char[]> name =
        translated_frame->raw_shared_info()->DebugNameCStr();
    PrintF(trace_scope()->file(), "%s", name.get());
    PrintF(trace_scope()->file(), " => bytecode_offset=%d, ",
           real_bytecode_offset);
    PrintF(trace_scope()->file(), "variable_frame_size=%d, frame_size=%d%s\n",
           frame_info.frame_size_in_bytes_without_fixed(), output_frame_size,
           goto_catch_handler ? " (throw)" : "");
  }

  // The top address of the frame is computed from the previous frame's top and
  // this frame's size.
  const intptr_t top_address =
      is_bottommost ? caller_frame_top_ - output_frame_size
                    : output_[frame_index - 1]->GetTop() - output_frame_size;
  output_frame->SetTop(top_address);

  // Compute the incoming parameter translation.
  ReadOnlyRoots roots(isolate());
  if (should_pad_arguments) {
    for (int i = 0; i < ArgumentPaddingSlots(parameters_count); ++i) {
      frame_writer.PushRawObject(roots.the_hole_value(), "padding\n");
    }
  }

  if (verbose_tracing_enabled() && is_bottommost &&
      actual_argument_count_ > parameters_count) {
    PrintF(trace_scope_->file(),
           "    -- %d extra argument(s) already in the stack --\n",
           actual_argument_count_ - parameters_count);
  }
  frame_writer.PushStackJSArguments(value_iterator, parameters_count);

  DCHECK_EQ(output_frame->GetLastArgumentSlotOffset(should_pad_arguments),
            frame_writer.top_offset());
  if (verbose_tracing_enabled()) {
    PrintF(trace_scope()->file(), "    -------------------------\n");
  }

  // There are no translation commands for the caller's pc and fp, the
  // context, the function and the bytecode offset.  Synthesize
  // their values and set them up
  // explicitly.
  //
  // The caller's pc for the bottommost output frame is the same as in the
  // input frame. For all subsequent output frames, it can be read from the
  // previous one. This frame's pc can be computed from the non-optimized
  // function code and bytecode offset of the bailout.
  if (is_bottommost) {
    frame_writer.PushBottommostCallerPc(caller_pc_);
  } else {
    frame_writer.PushApprovedCallerPc(output_[frame_index - 1]->GetPc());
  }

  // The caller's frame pointer for the bottommost output frame is the same
  // as in the input frame.  For all subsequent output frames, it can be
  // read from the previous one.  Also compute and set this frame's frame
  // pointer.
  const intptr_t caller_fp =
      is_bottommost ? caller_fp_ : output_[frame_index - 1]->GetFp();
  frame_writer.PushCallerFp(caller_fp);

  const intptr_t fp_value = top_address + frame_writer.top_offset();
  output_frame->SetFp(fp_value);
  if (is_topmost) {
    Register fp_reg = UnoptimizedJSFrame::fp_register();
    output_frame->SetRegister(fp_reg.code(), fp_value);
  }

  if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
    // For the bottommost output frame the constant pool pointer can be gotten
    // from the input frame. For subsequent output frames, it can be read from
    // the previous frame.
    const intptr_t caller_cp =
        is_bottommost ? caller_constant_pool_
                      : output_[frame_index - 1]->GetConstantPool();
    frame_writer.PushCallerConstantPool(caller_cp);
  }

  // For the bottommost output frame the context can be gotten from the input
  // frame. For all subsequent output frames it can be gotten from the function
  // so long as we don't inline functions that need local contexts.

  // When deoptimizing into a catch block, we need to take the context
  // from a register that was specified in the handler table.
  TranslatedFrame::iterator context_pos = value_iterator++;
  if (goto_catch_handler) {
    // Skip to the translated value of the register specified
    // in the handler table.
    for (int i = 0; i < catch_handler_data_ + 1; ++i) {
      context_pos++;
    }
  }
  // Read the context from the translations.
  frame_writer.PushTranslatedValue(context_pos, "context");

  // The function was mentioned explicitly in the BEGIN_FRAME.
  frame_writer.PushTranslatedValue(function_iterator, "function");

  // Actual argument count.
  int argc;
  if (is_bottommost) {
    argc = actual_argument_count_;
  } else {
    TranslatedFrame::Kind previous_frame_kind =
        (translated_state_.frames()[frame_index - 1]).kind();
    argc = previous_frame_kind == TranslatedFrame::kInlinedExtraArguments
               ? output_[frame_index - 1]->parameter_count()
               : parameters_count;
  }
  frame_writer.PushRawValue(argc, "actual argument count\n");

  // Set the bytecode array pointer.
  frame_writer.PushRawObject(bytecode_array, "bytecode array\n");

  // The bytecode offset was mentioned explicitly in the BEGIN_FRAME.
  const int raw_bytecode_offset =
      BytecodeArray::kHeaderSize - kHeapObjectTag + bytecode_offset;
  Tagged<Smi> smi_bytecode_offset = Smi::FromInt(raw_bytecode_offset);
  frame_writer.PushRawObject(smi_bytecode_offset, "bytecode offset\n");

  // We need to materialize the closure before getting the feedback vector.
  frame_writer.PushFeedbackVectorForMaterialization(function_iterator);

  if (verbose_tracing_enabled()) {
    PrintF(trace_scope()->file(), "    -------------------------\n");
  }

  // Translate the rest of the interpreter registers in the frame.
  // The return_value_offset is counted from the top. Here, we compute the
  // register index (counted from the start).
  const int return_value_first_reg =
      locals_count - translated_frame->return_value_offset();
  const int return_value_count = translated_frame->return_value_count();
  for (int i = 0; i < locals_count; ++i, ++value_iterator) {
    // Ensure we write the return value if we have one and we are returning
    // normally to a lazy deopt point.
    if (is_topmost && !goto_catch_handler &&
        deopt_kind_ == DeoptimizeKind::kLazy && i >= return_value_first_reg &&
        i < return_value_first_reg + return_value_count) {
      const int return_index = i - return_value_first_reg;
      if (return_index == 0) {
        frame_writer.PushRawValue(input_->GetRegister(kReturnRegister0.code()),
                                  "return value 0\n");
        // We do not handle the situation when one return value should go into
        // the accumulator and another one into an ordinary register. Since
        // the interpreter should never create such situation, just assert
        // this does not happen.
        CHECK_LE(return_value_first_reg + return_value_count, locals_count);
      } else {
        CHECK_EQ(return_index, 1);
        frame_writer.PushRawValue(input_->GetRegister(kReturnRegister1.code()),
                                  "return value 1\n");
      }
    } else {
      // This is not return value, just write the value from the translations.
      frame_writer.PushTranslatedValue(value_iterator, "stack parameter");
    }
  }

  uint32_t register_slots_written = static_cast<uint32_t>(locals_count);
  DCHECK_LE(register_slots_written, frame_info.register_stack_slot_count());
  // Some architectures must pad the stack frame with extra stack slots
  // to ensure the stack frame is aligned. Do this now.
  while (register_slots_written < frame_info.register_stack_slot_count()) {
    register_slots_written++;
    frame_writer.PushRawObject(roots.the_hole_value(), "padding\n");
  }

  // Translate the accumulator register (depending on frame position).
  if (is_topmost) {
    for (int i = 0; i < ArgumentPaddingSlots(1); ++i) {
      frame_writer.PushRawObject(roots.the_hole_value(), "padding\n");
    }
    // For topmost frame, put the accumulator on the stack. The
    // {NotifyDeoptimized} builtin pops it off the topmost frame (possibly
    // after materialization).
    if (goto_catch_handler) {
      // If we are lazy deopting to a catch handler, we set the accumulator to
      // the exception (which lives in the result register).
      intptr_t accumulator_value =
          input_->GetRegister(kInterpreterAccumulatorRegister.code());
      frame_writer.PushRawObject(Tagged<Object>(accumulator_value),
                                 "accumulator\n");
    } else {
      // If we are lazily deoptimizing make sure we store the deopt
      // return value into the appropriate slot.
      if (deopt_kind_ == DeoptimizeKind::kLazy &&
          translated_frame->return_value_offset() == 0 &&
          translated_frame->return_value_count() > 0) {
        CHECK_EQ(translated_frame->return_value_count(), 1);
        frame_writer.PushRawValue(input_->GetRegister(kReturnRegister0.code()),
                                  "return value 0\n");
      } else {
        frame_writer.PushTranslatedValue(value_iterator, "accumulator");
      }
    }
    ++value_iterator;  // Move over the accumulator.
  } else {
    // For non-topmost frames, skip the accumulator translation. For those
    // frames, the return value from the callee will become the accumulator.
    ++value_iterator;
  }
  CHECK_EQ(translated_frame->end(), value_iterator);
  CHECK_EQ(0u, frame_writer.top_offset());

  const intptr_t pc =
      static_cast<intptr_t>(dispatch_builtin->instruction_start()) +
      isolate()->heap()->deopt_pc_offset_after_adapt_shadow_stack().value();
  if (is_topmost) {
    // Only the pc of the topmost frame needs to be signed since it is
    // authenticated at the end of the DeoptimizationEntry builtin.
    const intptr_t top_most_pc = PointerAuthentication::SignAndCheckPC(
        isolate(), pc, frame_writer.frame()->GetTop());
    output_frame->SetPc(top_most_pc);
  } else {
    output_frame->SetPc(pc);
  }

  // Update constant pool.
  if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
    intptr_t constant_pool_value =
        static_cast<intptr_t>(dispatch_builtin->constant_pool());
    output_frame->SetConstantPool(constant_pool_value);
    if (is_topmost) {
      Register constant_pool_reg =
          UnoptimizedJSFrame::constant_pool_pointer_register();
      output_frame->SetRegister(constant_pool_reg.code(), constant_pool_value);
    }
  }

  // Clear the context register. The context might be a de-materialized object
  // and will be materialized by {Runtime_NotifyDeoptimized}. For additional
  // safety we use Tagged<Smi>(0) instead of the potential {arguments_marker}
  // here.
  if (is_topmost) {
    intptr_t context_value = static_cast<intptr_t>(Smi::zero().ptr());
    Register context_reg = JavaScriptFrame::context_register();
    output_frame->SetRegister(context_reg.code(), context_value);
    // Set the continuation for the topmost frame.
    Tagged<Code> continuation = builtins->code(Builtin::kNotifyDeoptimized);
    output_frame->SetContinuation(
        static_cast<intptr_t>(continuation->instruction_start()));
  }
}

void Deoptimizer::DoComputeInlinedExtraArguments(
    TranslatedFrame* translated_frame, int frame_index) {
  // Inlined arguments frame can not be the topmost, nor the bottom most frame.
  CHECK(frame_index < output_count_ - 1);
  CHECK_GT(frame_index, 0);
  CHECK_NULL(output_[frame_index]);

  // During deoptimization we need push the extra arguments of inlined functions
  // (arguments with index greater than the formal parameter count).
  // For more info, see the design document:
  // https://docs.google.com/document/d/150wGaUREaZI6YWqOQFD5l2mWQXaPbbZjcAIJLOFrzMs

  TranslatedFrame::iterator value_iterator = translated_frame->begin();
  const int argument_count_without_receiver = translated_frame->height() - 1;
  const int formal_parameter_count =
      translated_frame->raw_shared_info()
          ->internal_formal_parameter_count_without_receiver();
  const int extra_argument_count =
      argument_count_without_receiver - formal_parameter_count;
  // The number of pushed arguments is the maximum of the actual argument count
  // and the formal parameter count + the receiver.
  const int padding = ArgumentPaddingSlots(
      std::max(argument_count_without_receiver, formal_parameter_count) + 1);
  const int output_frame_size =
      (std::max(0, extra_argument_count) + padding) * kSystemPointerSize;
  if (verbose_tracing_enabled()) {
    PrintF(trace_scope_->file(),
           "  translating inlined arguments frame => variable_size=%d\n",
           output_frame_size);
  }

  // Allocate and store the output frame description.
  FrameDescription* output_frame = FrameDescription::Create(
      output_frame_size, JSParameterCount(argument_count_without_receiver),
      isolate());
  // The top address of the frame is computed from the previous frame's top and
  // this frame's size.
  const intptr_t top_address =
      output_[frame_index - 1]->GetTop() - output_frame_size;
  output_frame->SetTop(top_address);
  // This is not a real frame, we take PC and FP values from the parent frame.
  output_frame->SetPc(output_[frame_index - 1]->GetPc());
  output_frame->SetFp(output_[frame_index - 1]->GetFp());
  output_[frame_index] = output_frame;

  FrameWriter frame_writer(this, output_frame, verbose_trace_scope());

  ReadOnlyRoots roots(isolate());
  for (int i = 0; i < padding; ++i) {
    frame_writer.PushRawObject(roots.the_hole_value(), "padding\n");
  }

  if (extra_argument_count > 0) {
    // The receiver and arguments with index below the formal parameter
    // count are in the fake adaptor frame, because they are used to create the
    // arguments object. We should however not push them, since the interpreter
    // frame will do that.
    value_iterator++;  // Skip function.
    value_iterator++;  // Skip receiver.
    for (int i = 0; i < formal_parameter_count; i++) value_iterator++;
    frame_writer.PushStackJSArguments(value_iterator, extra_argument_count);
  }
}

void Deoptimizer::DoComputeConstructCreateStubFrame(
    TranslatedFrame* translated_frame, int frame_index) {
  TranslatedFrame::iterator value_iterator = translated_frame->begin();
  const bool is_topmost = (output_count_ - 1 == frame_index);
  // The construct frame could become topmost only if we inlined a constructor
  // call which does a tail call (otherwise the tail callee's frame would be
  // the topmost one). So it could only be the DeoptimizeKind::kLazy case.
  CHECK(!is_topmost || deopt_kind_ == DeoptimizeKind::kLazy);
  DCHECK_EQ(translated_frame->kind(), TranslatedFrame::kConstructCreateStub);

  const int parameters_count = translated_frame->height();
  ConstructStubFrameInfo frame_info =
      ConstructStubFrameInfo::Precise(parameters_count, is_topmost);
  const uint32_t output_frame_size = frame_info.frame_size_in_bytes();

  TranslatedFrame::iterator function_iterator = value_iterator++;
  if (verbose_tracing_enabled()) {
    PrintF(trace_scope()->file(),
           "  translating construct create stub => variable_frame_size=%d, "
           "frame_size=%d\n",
           frame_info.frame_size_in_bytes_without_fixed(), output_frame_size);
  }

  // Allocate and store the output frame description.
  FrameDescription* output_frame =
      FrameDescription::Create(output_frame_size, parameters_count, isolate());
  FrameWriter frame_writer(this, output_frame, verbose_trace_scope());
  DCHECK(frame_index > 0 && frame_index < output_count_);
  DCHECK_NULL(output_[frame_index]);
  output_[frame_index] = output_frame;

  // The top address of the frame is computed from the previous frame's top and
  // this frame's size.
  const intptr_t top_address =
      output_[frame_index - 1]->GetTop() - output_frame_size;
  output_frame->SetTop(top_address);

  ReadOnlyRoots roots(isolate());
  for (int i = 0; i < ArgumentPaddingSlots(parameters_count); ++i) {
    frame_writer.PushRawObject(roots.the_hole_value(), "padding\n");
  }

  // The allocated receiver of a construct stub frame is passed as the
  // receiver parameter through the translation. It might be encoding
  // a captured object, so we need save it for later.
  TranslatedFrame::iterator receiver_iterator = value_iterator;

  // Compute the incoming parameter translation.
  frame_writer.PushStackJSArguments(value_iterator, parameters_count);

  DCHECK_EQ(output_frame->GetLastArgumentSlotOffset(),
            frame_writer.top_offset());

  // Read caller's PC from the previous frame.
  const intptr_t caller_pc = output_[frame_index - 1]->GetPc();
  frame_writer.PushApprovedCallerPc(caller_pc);

  // Read caller's FP from the previous frame, and set this frame's FP.
  const intptr_t caller_fp = output_[frame_index - 1]->GetFp();
  frame_writer.PushCallerFp(caller_fp);

  const intptr_t fp_value = top_address + frame_writer.top_offset();
  output_frame->SetFp(fp_value);
  if (is_topmost) {
    Register fp_reg = JavaScriptFrame::fp_register();
    output_frame->SetRegister(fp_reg.code(), fp_value);
  }

  if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
    // Read the caller's constant pool from the previous frame.
    const intptr_t caller_cp = output_[frame_index - 1]->GetConstantPool();
    frame_writer.PushCallerConstantPool(caller_cp);
  }

  // A marker value is used to mark the frame.
  intptr_t marker = StackFrame::TypeToMarker(StackFrame::CONSTRUCT);
  frame_writer.PushRawValue(marker, "context (construct stub sentinel)\n");

  frame_writer.PushTranslatedValue(value_iterator++, "context");

  // Number of incoming arguments.
  const uint32_t argc = parameters_count;
  frame_writer.PushRawValue(argc, "argc\n");

  // The constructor function was mentioned explicitly in the
  // CONSTRUCT_STUB_FRAME.
  frame_writer.PushTranslatedValue(function_iterator, "constructor function\n");

  // The deopt info contains the implicit receiver or the new target at the
  // position of the receiver. Copy it to the top of stack, with the hole value
  // as padding to maintain alignment.
  frame_writer.PushRawObject(roots.the_hole_value(), "padding\n");
  frame_writer.PushTranslatedValue(receiver_iterator, "new target\n");

  if (is_topmost) {
    for (int i = 0; i < ArgumentPaddingSlots(1); ++i) {
      frame_writer.PushRawObject(roots.the_hole_value(), "padding\n");
    }
    // Ensure the result is restored back when we return to the stub.
    Register result_reg = kReturnRegister0;
    intptr_t result = input_->GetRegister(result_reg.code());
    frame_writer.PushRawValue(result, "subcall result\n");
  }

  CHECK_EQ(translated_frame->end(), value_iterator);
  CHECK_EQ(0u, frame_writer.top_offset());

  // Compute this frame's PC.
  Tagged<Code> construct_stub =
      isolate_->builtins()->code(Builtin::kJSConstructStubGeneric);
  Address start = construct_stub->instruction_start();
  const int pc_offset =
      isolate_->heap()->construct_stub_create_deopt_pc_offset().value();
  intptr_t pc_value = static_cast<intptr_t>(start + pc_offset);
  if (is_topmost) {
    // Only the pc of the topmost frame needs to be signed since it is
    // authenticated at the end of the DeoptimizationEntry builtin.
    output_frame->SetPc(PointerAuthentication::SignAndCheckPC(
        isolate(), pc_value, frame_writer.frame()->GetTop()));
  } else {
    output_frame->SetPc(pc_value);
  }

  // Update constant pool.
  if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
    intptr_t constant_pool_value =
        static_cast<intptr_t>(construct_stub->constant_pool());
    output_frame->SetConstantPool(constant_pool_value);
    if (is_topmost) {
      Register constant_pool_reg =
          JavaScriptFrame::constant_pool_pointer_register();
      output_frame->SetRegister(constant_pool_reg.code(), constant_pool_value);
    }
  }

  // Clear the context register. The context might be a de-materialized object
  // and will be materialized by {Runtime_NotifyDeoptimized}. For additional
  // safety we use Tagged<Smi>(0) instead of the potential {arguments_marker}
  // here.
  if (is_topmost) {
    intptr_t context_value = static_cast<intptr_t>(Smi::zero().ptr());
    Register context_reg = JavaScriptFrame::context_register();
    output_frame->SetRegister(context_reg.code(), context_value);

    // Set the continuation for the topmost frame.
    DCHECK_EQ(DeoptimizeKind::kLazy, deopt_kind_);
    Tagged<Code> continuation =
        isolate_->builtins()->code(Builtin::kNotifyDeoptimized);
    output_frame->SetContinuation(
        static_cast<intptr_t>(continuation->instruction_start()));
  }
}

void Deoptimizer::DoComputeConstructInvokeStubFrame(
    TranslatedFrame* translated_frame, int frame_index) {
  TranslatedFrame::iterator value_iterator = translated_frame->begin();
  const bool is_topmost = (output_count_ - 1 == frame_index);
  // The construct frame could become topmost only if we inlined a constructor
  // call which does a tail call (otherwise the tail callee's frame would be
  // the topmost one). So it could only be the DeoptimizeKind::kLazy case.
  CHECK(!is_topmost || deopt_kind_ == DeoptimizeKind::kLazy);
  DCHECK_EQ(translated_frame->kind(), TranslatedFrame::kConstructInvokeStub);
  DCHECK_EQ(translated_frame->height(), 0);

  FastConstructStubFrameInfo frame_info =
      FastConstructStubFrameInfo::Precise(is_topmost);
  const uint32_t output_frame_size = frame_info.frame_size_in_bytes();
  if (verbose_tracing_enabled()) {
    PrintF(trace_scope()->file(),
           "  translating construct invoke stub => variable_frame_size=%d, "
           "frame_size=%d\n",
           frame_info.frame_size_in_bytes_without_fixed(), output_frame_size);
  }

  // Allocate and store the output frame description.
  FrameDescription* output_frame =
      FrameDescription::Create(output_frame_size, 0, isolate());
  FrameWriter frame_writer(this, output_frame, verbose_trace_scope());
  DCHECK(frame_index > 0 && frame_index < output_count_);
  DCHECK_NULL(output_[frame_index]);
  output_[frame_index] = output_frame;

  // The top address of the frame is computed from the previous frame's top and
  // this frame's size.
  const intptr_t top_address =
      output_[frame_index - 1]->GetTop() - output_frame_size;
  output_frame->SetTop(top_address);

  // The allocated receiver of a construct stub frame is passed as the
  // receiver parameter through the translation. It might be encoding
  // a captured object, so we need save it for later.
  TranslatedFrame::iterator receiver_iterator = value_iterator;
  value_iterator++;

  // Read caller's PC from the previous frame.
  const intptr_t caller_pc = output_[frame_index - 1]->GetPc();
  frame_writer.PushApprovedCallerPc(caller_pc);

  // Read caller's FP from the previous frame, and set this frame's FP.
  const intptr_t caller_fp = output_[frame_index - 1]->GetFp();
  frame_writer.PushCallerFp(caller_fp);

  const intptr_t fp_value = top_address + frame_writer.top_offset();
  output_frame->SetFp(fp_value);
  if (is_topmost) {
    Register fp_reg = JavaScriptFrame::fp_register();
    output_frame->SetRegister(fp_reg.code(), fp_value);
  }

  if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
    // Read the caller's constant pool from the previous frame.
    const intptr_t caller_cp = output_[frame_index - 1]->GetConstantPool();
    frame_writer.PushCallerConstantPool(caller_cp);
  }
  intptr_t marker = StackFrame::TypeToMarker(StackFrame::FAST_CONSTRUCT);
  frame_writer.PushRawValue(marker, "fast construct stub sentinel\n");
  frame_writer.PushTranslatedValue(value_iterator++, "context");
  frame_writer.PushTranslatedValue(receiver_iterator, "implicit receiver");

  // The FastConstructFrame needs to be aligned in some architectures.
  ReadOnlyRoots roots(isolate());
  for (int i = 0; i < ArgumentPaddingSlots(1); ++i) {
    frame_writer.PushRawObject(roots.the_hole_value(), "padding\n");
  }

  if (is_topmost) {
    for (int i = 0; i < ArgumentPaddingSlots(1); ++i) {
      frame_writer.PushRawObject(roots.the_hole_value(), "padding\n");
    }
    // Ensure the result is restored back when we return to the stub.
    Register result_reg = kReturnRegister0;
    intptr_t result = input_->GetRegister(result_reg.code());
    frame_writer.PushRawValue(result, "subcall result\n");
  }

  CHECK_EQ(translated_frame->end(), value_iterator);
  CHECK_EQ(0u, frame_writer.top_offset());

  // Compute this frame's PC.
  Tagged<Code> construct_stub = isolate_->builtins()->code(
      Builtin::kInterpreterPushArgsThenFastConstructFunction);
  Address start = construct_stub->instruction_start();
  const int pc_offset =
      isolate_->heap()->construct_stub_invoke_deopt_pc_offset().value();
  intptr_t pc_value = static_cast<intptr_t>(start + pc_offset);
  if (is_topmost) {
    // Only the pc of the topmost frame needs to be signed since it is
    // authenticated at the end of the DeoptimizationEntry builtin.
    output_frame->SetPc(PointerAuthentication::SignAndCheckPC(
        isolate(), pc_value, frame_writer.frame()->GetTop()));
  } else {
    output_frame->SetPc(pc_value);
  }

  // Update constant pool.
  if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
    intptr_t constant_pool_value =
        static_cast<intptr_t>(construct_stub->constant_pool());
    output_frame->SetConstantPool(constant_pool_value);
    if (is_topmost) {
      Register constant_pool_reg =
          JavaScriptFrame::constant_pool_pointer_register();
      output_frame->SetRegister(constant_pool_reg.code(), constant_pool_value);
    }
  }

  // Clear the context register. The context might be a de-materialized object
  // and will be materialized by {Runtime_NotifyDeoptimized}. For additional
  // safety we use Tagged<Smi>(0) instead of the potential {arguments_marker}
  // here.
  if (is_topmost) {
    intptr_t context_value = static_cast<intptr_t>(Smi::zero().ptr());
    Register context_reg = JavaScriptFrame::context_register();
    output_frame->SetRegister(context_reg.code(), context_value);

    // Set the continuation for the topmost frame.
    DCHECK_EQ(DeoptimizeKind::kLazy, deopt_kind_);
    Tagged<Code> continuation =
        isolate_->builtins()->code(Builtin::kNotifyDeoptimized);
    output_frame->SetContinuation(
        static_cast<intptr_t>(continuation->instruction_start()));
  }
}

namespace {

bool BuiltinContinuationModeIsJavaScript(BuiltinContinuationMode mode) {
  switch (mode) {
    case BuiltinContinuationMode::STUB:
      return false;
    case BuiltinContinuationMode::JAVASCRIPT:
    case BuiltinContinuationMode::JAVASCRIPT_WITH_CATCH:
    case BuiltinContinuationMode::JAVASCRIPT_HANDLE_EXCEPTION:
      return true;
  }
  UNREACHABLE();
}

StackFrame::Type BuiltinContinuationModeToFrameType(
    BuiltinContinuationMode mode) {
  switch (mode) {
    case BuiltinContinuationMode::STUB:
      return StackFrame::BUILTIN_CONTINUATION;
    case BuiltinContinuationMode::JAVASCRIPT:
      return StackFrame::JAVASCRIPT_BUILTIN_CONTINUATION;
    case BuiltinContinuationMode::JAVASCRIPT_WITH_CATCH:
      return StackFrame::JAVASCRIPT_BUILTIN_CONTINUATION_WITH_CATCH;
    case BuiltinContinuationMode::JAVASCRIPT_HANDLE_EXCEPTION:
      return StackFrame::JAVASCRIPT_BUILTIN_CONTINUATION_WITH_CATCH;
  }
  UNREACHABLE();
}

}  // namespace

Builtin Deoptimizer::TrampolineForBuiltinContinuation(
    BuiltinContinuationMode mode, bool must_handle_result) {
  switch (mode) {
    case BuiltinContinuationMode::STUB:
      return must_handle_result ? Builtin::kContinueToCodeStubBuiltinWithResult
                                : Builtin::kContinueToCodeStubBuiltin;
    case BuiltinContinuationMode::JAVASCRIPT:
    case BuiltinContinuationMode::JAVASCRIPT_WITH_CATCH:
    case BuiltinContinuationMode::JAVASCRIPT_HANDLE_EXCEPTION:
      return must_handle_result
                 ? Builtin::kContinueToJavaScriptBuiltinWithResult
                 : Builtin::kContinueToJavaScriptBuiltin;
  }
  UNREACHABLE();
}

#if V8_ENABLE_WEBASSEMBLY
TranslatedValue Deoptimizer::TranslatedValueForWasmReturnKind(
    std::optional<wasm::ValueKind> wasm_call_return_kind) {
  if (wasm_call_return_kind) {
    switch (wasm_call_return_kind.value()) {
      case wasm::kI32:
        return TranslatedValue::NewInt32(
            &translated_state_,
            static_cast<int32_t>(input_->GetRegister(kReturnRegister0.code())));
      case wasm::kI64:
        return TranslatedValue::NewInt64ToBigInt(
            &translated_state_,
            static_cast<int64_t>(input_->GetRegister(kReturnRegister0.code())));
      case wasm::kF32:
        return TranslatedValue::NewFloat(
            &translated_state_,
            Float32(*reinterpret_cast<float*>(
                input_->GetDoubleRegister(wasm::kFpReturnRegisters[0].code())
                    .get_bits_address())));
      case wasm::kF64:
        return TranslatedValue::NewDouble(
            &translated_state_,
            input_->GetDoubleRegister(wasm::kFpReturnRegisters[0].code()));
      default:
        UNREACHABLE();
    }
  }
  return TranslatedValue::NewTagged(&translated_state_,
                                    ReadOnlyRoots(isolate()).undefined_value());
}
#endif  // V8_ENABLE_WEBASSEMBLY

// BuiltinContinuationFrames capture the machine state that is expected as input
// to a builtin, including both input register values and stack parameters. When
// the frame is reactivated (i.e. the frame below it returns), a
// ContinueToBuiltin stub restores the register state from the frame and tail
// calls to the actual target builtin, making it appear that the stub had been
// directly called by the frame above it. The input values to populate the frame
// are taken from the deopt's FrameState.
//
// Frame translation happens in two modes, EAGER and LAZY. In EAGER mode, all of
// the parameters to the Builtin are explicitly specified in the TurboFan
// FrameState node. In LAZY mode, there is always one fewer parameters specified
// in the FrameState than expected by the Builtin. In that case, construction of
// BuiltinContinuationFrame adds the final missing parameter during
// deoptimization, and that parameter is always on the stack and contains the
// value returned from the callee of the call site triggering the LAZY deopt
// (e.g. rax on x64). This requires that continuation Builtins for LAZY deopts
// must have at least one stack parameter.
//
//                TO
//    |          ....           |
//    +-------------------------+
//    | arg padding (arch dept) |<- at most 1*kSystemPointerSize
//    +-------------------------+
//    |     builtin param 0     |<- FrameState input value n becomes
//    +-------------------------+
//    |           ...           |
//    +-------------------------+
//    |     builtin param m     |<- FrameState input value n+m-1, or in
//    +-----needs-alignment-----+   the LAZY case, return LAZY result value
//    | ContinueToBuiltin entry |
//    +-------------------------+
// |  |    saved frame (FP)     |
// |  +=====needs=alignment=====+<- fpreg
// |  |constant pool (if ool_cp)|
// v  +-------------------------+
//    |BUILTIN_CONTINUATION mark|
//    +-------------------------+
//    |  JSFunction (or zero)   |<- only if JavaScript builtin
//    +-------------------------+
//    |  frame height above FP  |
//    +-------------------------+
//    |         context         |<- this non-standard context slot contains
//    +-------------------------+   the context, even for non-JS builtins.
//    |      builtin index      |
//    +-------------------------+
//    | builtin input GPR reg0  |<- populated from deopt FrameState using
//    +-------------------------+   the builtin's CallInterfaceDescriptor
//    |          ...            |   to map a FrameState's 0..n-1 inputs to
//    +-------------------------+   the builtin's n input register params.
//    | builtin input GPR regn  |
//    +-------------------------+
//    | reg padding (arch dept) |
//    +-----needs--alignment----+
//    | res padding (arch dept) |<- only if {is_topmost}; result is pop'd by
//    +-------------------------+<- kNotifyDeopt ASM stub and moved to acc
//    |      result  value      |<- reg, as ContinueToBuiltin stub expects.
//    +-----needs-alignment-----+<- spreg
//
void Deoptimizer::DoComputeBuiltinContinuation(
    TranslatedFrame* translated_frame, int frame_index,
    BuiltinContinuationMode mode) {
  TranslatedFrame::iterator result_iterator = translated_frame->end();

  bool is_js_to_wasm_builtin_continuation = false;
#if V8_ENABLE_WEBASSEMBLY
  is_js_to_wasm_builtin_continuation =
      translated_frame->kind() == TranslatedFrame::kJSToWasmBuiltinContinuation;
  if (is_js_to_wasm_builtin_continuation) {
    // For JSToWasmBuiltinContinuations, add a TranslatedValue with the result
    // of the Wasm call, extracted from the input FrameDescription.
    // This TranslatedValue will be written in the output frame in place of the
    // hole and we'll use ContinueToCodeStubBuiltin in place of
    // ContinueToCodeStubBuiltinWithResult.
    TranslatedValue result = TranslatedValueForWasmReturnKind(
        translated_frame->wasm_call_return_kind());
    translated_frame->Add(result);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  TranslatedFrame::iterator value_iterator = translated_frame->begin();

  const BytecodeOffset bytecode_offset = translated_frame->bytecode_offset();
  Builtin builtin = Builtins::GetBuiltinFromBytecodeOffset(bytecode_offset);
  CallInterfaceDescriptor continuation_descriptor =
      Builtins::CallInterfaceDescriptorFor(builtin);

  const RegisterConfiguration* config = RegisterConfiguration::Default();

  const bool is_bottommost = (0 == frame_index);
  const bool is_topmost = (output_count_ - 1 == frame_index);

  const int parameters_count = translated_frame->height();
  BuiltinContinuationFrameInfo frame_info =
      BuiltinContinuationFrameInfo::Precise(parameters_count,
                                            continuation_descriptor, config,
                                            is_topmost, deopt_kind_, mode);

  const unsigned output_frame_size = frame_info.frame_size_in_bytes();
  const unsigned output_frame_size_above_fp =
      frame_info.frame_size_in_bytes_above_fp();

  // Validate types of parameters. They must all be tagged except for argc and
  // the dispatch handle for JS builtins.
  bool has_argc = false;
  const int register_parameter_count =
      continuation_descriptor.GetRegisterParameterCount();
  for (int i = 0; i < register_parameter_count; ++i) {
    MachineType type = continuation_descriptor.GetParameterType(i);
    int code = continuation_descriptor.GetRegisterParameter(i).code();
    // Only tagged and int32 arguments are supported, and int32 only for the
    // arguments count and dispatch handle on JavaScript builtins.
    if (type == MachineType::Int32()) {
      CHECK(code == kJavaScriptCallArgCountRegister.code() ||
            code == kJavaScriptCallDispatchHandleRegister.code());
      has_argc = true;
    } else {
      // Any other argument must be a tagged value.
      CHECK(IsAnyTagged(type.representation()));
    }
  }
  CHECK_EQ(BuiltinContinuationModeIsJavaScript(mode), has_argc);

  if (verbose_tracing_enabled()) {
    PrintF(trace_scope()->file(),
           "  translating BuiltinContinuation to %s,"
           " => register_param_count=%d,"
           " stack_param_count=%d, frame_size=%d\n",
           Builtins::name(builtin), register_parameter_count,
           frame_info.stack_parameter_count(), output_frame_size);
  }

  FrameDescription* output_frame = FrameDescription::Create(
      output_frame_size, frame_info.stack_parameter_count(), isolate());
  output_[frame_index] = output_frame;
  FrameWriter frame_writer(this, output_frame, verbose_trace_scope());

  // The top address of the frame is computed from the previous frame's top and
  // this frame's size.
  const intptr_t top_address =
      is_bottommost ? caller_frame_top_ - output_frame_size
                    : output_[frame_index - 1]->GetTop() - output_frame_size;
  output_frame->SetTop(top_address);

  // Get the possible JSFunction for the case that this is a
  // JavaScriptBuiltinContinuationFrame, which needs the JSFunction pointer
  // like a normal JavaScriptFrame.
  const intptr_t maybe_function = value_iterator->GetRawValue().ptr();
  ++value_iterator;

  ReadOnlyRoots roots(isolate());
  const int padding = ArgumentPaddingSlots(frame_info.stack_parameter_count());
  for (int i = 0; i < padding; ++i) {
    frame_writer.PushRawObject(roots.the_hole_value(), "padding\n");
  }

  if (mode == BuiltinContinuationMode::STUB) {
    DCHECK_EQ(continuation_descriptor.GetStackArgumentOrder(),
              StackArgumentOrder::kDefault);
    for (uint32_t i = 0; i < frame_info.translated_stack_parameter_count();
         ++i, ++value_iterator) {
      frame_writer.PushTranslatedValue(value_iterator, "stack parameter");
    }
    if (frame_info.frame_has_result_stack_slot()) {
      if (is_js_to_wasm_builtin_continuation) {
        frame_writer.PushTranslatedValue(result_iterator,
                                         "return result on lazy deopt\n");
      } else {
        DCHECK_EQ(result_iterator, translated_frame->end());
        frame_writer.PushRawObject(
            roots.the_hole_value(),
            "placeholder for return result on lazy deopt\n");
      }
    }
  } else {
    // JavaScript builtin.
    if (frame_info.frame_has_result_stack_slot()) {
      frame_writer.PushRawObject(
          roots.the_hole_value(),
          "placeholder for return result on lazy deopt\n");
    }
    switch (mode) {
      case BuiltinContinuationMode::STUB:
        UNREACHABLE();
      case BuiltinContinuationMode::JAVASCRIPT:
        break;
      case BuiltinContinuationMode::JAVASCRIPT_WITH_CATCH: {
        frame_writer.PushRawObject(roots.the_hole_value(),
                                   "placeholder for exception on lazy deopt\n");
      } break;
      case BuiltinContinuationMode::JAVASCRIPT_HANDLE_EXCEPTION: {
        intptr_t accumulator_value =
            input_->GetRegister(kInterpreterAccumulatorRegister.code());
        frame_writer.PushRawObject(Tagged<Object>(accumulator_value),
                                   "exception (from accumulator)\n");
      } break;
    }
    frame_writer.PushStackJSArguments(
        value_iterator, frame_info.translated_stack_parameter_count());
  }

  DCHECK_EQ(output_frame->GetLastArgumentSlotOffset(),
            frame_writer.top_offset());

  std::vector<TranslatedFrame::iterator> register_values;
  int total_registers = config->num_general_registers();
  register_values.resize(total_registers, {value_iterator});

  for (int i = 0; i < register_parameter_count; ++i, ++value_iterator) {
    int code = continuation_descriptor.GetRegisterParameter(i).code();
    register_values[code] = value_iterator;
  }

  // The context register is always implicit in the CallInterfaceDescriptor but
  // its register must be explicitly set when continuing to the builtin. Make
  // sure that it's harvested from the translation and copied into the register
  // set (it was automatically added at the end of the FrameState by the
  // instruction selector).
  Tagged<Object> context = value_iterator->GetRawValue();
  const intptr_t value = context.ptr();
  TranslatedFrame::iterator context_register_value = value_iterator++;
  register_values[kContextRegister.code()] = context_register_value;
  output_frame->SetRegister(kContextRegister.code(), value);

  // Set caller's PC (JSFunction continuation).
  if (is_bottommost) {
    frame_writer.PushBottommostCallerPc(caller_pc_);
  } else {
    frame_writer.PushApprovedCallerPc(output_[frame_index - 1]->GetPc());
  }

  // Read caller's FP from the previous frame, and set this frame's FP.
  const intptr_t caller_fp =
      is_bottommost ? caller_fp_ : output_[frame_index - 1]->GetFp();
  frame_writer.PushCallerFp(caller_fp);

  const intptr_t fp_value = top_address + frame_writer.top_offset();
  output_frame->SetFp(fp_value);

  DCHECK_EQ(output_frame_size_above_fp, frame_writer.top_offset());

  if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
    // Read the caller's constant pool from the previous frame.
    const intptr_t caller_cp =
        is_bottommost ? caller_constant_pool_
                      : output_[frame_index - 1]->GetConstantPool();
    frame_writer.PushCallerConstantPool(caller_cp);
  }

  // A marker value is used in place of the context.
  const intptr_t marker =
      StackFrame::TypeToMarker(BuiltinContinuationModeToFrameType(mode));
  frame_writer.PushRawValue(marker,
                            "context (builtin continuation sentinel)\n");

  if (BuiltinContinuationModeIsJavaScript(mode)) {
    frame_writer.PushRawValue(maybe_function, "JSFunction\n");
  } else {
    frame_writer.PushRawValue(0, "unused\n");
  }

  // The delta from the SP to the FP; used to reconstruct SP in
  // Isolate::UnwindAndFindHandler.
  frame_writer.PushRawObject(Smi::FromInt(output_frame_size_above_fp),
                             "frame height at deoptimization\n");

  // The context even if this is a stub continuation frame. We can't use the
  // usual context slot, because we must store the frame marker there.
  frame_writer.PushTranslatedValue(context_register_value,
                                   "builtin JavaScript context\n");

  // The builtin to continue to.
  frame_writer.PushRawObject(Smi::FromInt(static_cast<int>(builtin)),
                             "builtin index\n");

  const int allocatable_register_count =
      config->num_allocatable_general_registers();
  for (int i = 0; i < allocatable_register_count; ++i) {
    int code = config->GetAllocatableGeneralCode(i);
    base::ScopedVector<char> str(128);
    if (verbose_tracing_enabled()) {
      if (BuiltinContinuationModeIsJavaScript(mode) &&
          code == kJavaScriptCallArgCountRegister.code()) {
        SNPrintF(
            str,
            "tagged argument count %s (will be untagged by continuation)\n",
            RegisterName(Register::from_code(code)));
      } else {
        SNPrintF(str, "builtin register argument %s\n",
                 RegisterName(Register::from_code(code)));
      }
    }
    frame_writer.PushTranslatedValue(
        register_values[code], verbose_tracing_enabled() ? str.begin() : "");
  }

  // Some architectures must pad the stack frame with extra stack slots
  // to ensure the stack frame is aligned.
  const int padding_slot_count =
      BuiltinContinuationFrameConstants::PaddingSlotCount(
          allocatable_register_count);
  for (int i = 0; i < padding_slot_count; ++i) {
    frame_writer.PushRawObject(roots.the_hole_value(), "padding\n");
  }

  if (is_topmost) {
    for (int i = 0; i < ArgumentPaddingSlots(1); ++i) {
      frame_writer.PushRawObject(roots.the_hole_value(), "padding\n");
    }

    // Ensure the result is restored back when we return to the stub.
    if (frame_info.frame_has_result_stack_slot()) {
      Register result_reg = kReturnRegister0;
      frame_writer.PushRawValue(input_->GetRegister(result_reg.code()),
                                "callback result\n");
    } else {
      frame_writer.PushRawObject(roots.undefined_value(), "callback result\n");
    }
  }

  CHECK_EQ(result_iterator, value_iterator);
  CHECK_EQ(0u, frame_writer.top_offset());

  // Clear the context register. The context might be a de-materialized object
  // and will be materialized by {Runtime_NotifyDeoptimized}. For additional
  // safety we use Tagged<Smi>(0) instead of the potential {arguments_marker}
  // here.
  if (is_topmost) {
    intptr_t context_value = static_cast<intptr_t>(Smi::zero().ptr());
    Register context_reg = JavaScriptFrame::context_register();
    output_frame->SetRegister(context_reg.code(), context_value);
  }

  // Ensure the frame pointer register points to the callee's frame. The builtin
  // will build its own frame once we continue to it.
  Register fp_reg = JavaScriptFrame::fp_register();
  output_frame->SetRegister(fp_reg.code(), fp_value);
  // For JSToWasmBuiltinContinuations use ContinueToCodeStubBuiltin, and not
  // ContinueToCodeStubBuiltinWithResult because we don't want to overwrite the
  // return value that we have already set.
  Tagged<Code> continue_to_builtin =
      isolate()->builtins()->code(TrampolineForBuiltinContinuation(
          mode, frame_info.frame_has_result_stack_slot() &&
                    !is_js_to_wasm_builtin_continuation));
  intptr_t pc =
      static_cast<intptr_t>(continue_to_builtin->instruction_start()) +
      isolate()->heap()->deopt_pc_offset_after_adapt_shadow_stack().value();
  if (is_topmost) {
    // Only the pc of the topmost frame needs to be signed since it is
    // authenticated at the end of the DeoptimizationEntry builtin.
    const intptr_t top_most_pc = PointerAuthentication::SignAndCheckPC(
        isolate(), pc, frame_writer.frame()->GetTop());
    output_frame->SetPc(top_most_pc);
  } else {
    output_frame->SetPc(pc);
  }

  Tagged<Code> continuation =
      isolate()->builtins()->code(Builtin::kNotifyDeoptimized);
  output_frame->SetContinuation(
      static_cast<intptr_t>(continuation->instruction_start()));
}

void Deoptimizer::MaterializeHeapObjects() {
  translated_state_.Prepare(static_cast<Address>(stack_fp_));
  if (v8_flags.deopt_every_n_times > 0) {
    // Doing a GC here will find problems with the deoptimized frames.
    isolate_->heap()->CollectAllGarbage(GCFlag::kNoFlags,
                                        GarbageCollectionReason::kTesting);
  }

  for (auto& materialization : values_to_materialize_) {
    DirectHandle<Object> value = materialization.value_->GetValue();

    if (verbose_tracing_enabled()) {
      PrintF(trace_scope()->file(),
             "Materialization [" V8PRIxPTR_FMT "] <- " V8PRIxPTR_FMT " ;  ",
             static_cast<intptr_t>(materialization.output_slot_address_),
             (*value).ptr());
      ShortPrint(*value, trace_scope()->file());
      PrintF(trace_scope()->file(), "\n");
    }

    *(reinterpret_cast<Address*>(materialization.output_slot_address_)) =
        (*value).ptr();
  }

  for (auto& fbv_materialization : feedback_vector_to_materialize_) {
    DirectHandle<Object> closure = fbv_materialization.value_->GetValue();
    DCHECK(IsJSFunction(*closure));
    Tagged<Object> feedback_vector =
        Cast<JSFunction>(*closure)->raw_feedback_cell()->value();
    CHECK(IsFeedbackVector(feedback_vector));
    *(reinterpret_cast<Address*>(fbv_materialization.output_slot_address_)) =
        feedback_vector.ptr();
  }

  translated_state_.VerifyMaterializedObjects();

  bool feedback_updated = translated_state_.DoUpdateFeedback();
  if (verbose_tracing_enabled() && feedback_updated) {
    FILE* file = trace_scope()->file();
    Deoptimizer::DeoptInfo info = Deoptimizer::GetDeoptInfo();
    PrintF(file, "Feedback updated from deoptimization at ");
    OFStream outstr(file);
    info.position.Print(outstr, compiled_code_);
    PrintF(file, ", %s\n", DeoptimizeReasonToString(info.deopt_reason));
  }

  isolate_->materialized_object_store()->Remove(
      static_cast<Address>(stack_fp_));
}

void Deoptimizer::QueueValueForMaterialization(
    Address output_address, Tagged<Object> obj,
    const TranslatedFrame::iterator& iterator) {
  if (obj == ReadOnlyRoots(isolate_).arguments_marker()) {
    values_to_materialize_.push_back({output_address, iterator});
  }
}

void Deoptimizer::QueueFeedbackVectorForMaterialization(
    Address output_address, const TranslatedFrame::iterator& iterator) {
  feedback_vector_to_materialize_.push_back({output_address, iterator});
}

unsigned Deoptimizer::ComputeInputFrameAboveFpFixedSize() const {
  unsigned fixed_size = CommonFrameConstants::kFixedFrameSizeAboveFp;
  IF_WASM(DCHECK_IMPLIES, function_.is_null(), v8_flags.wasm_deopt);
  DCHECK_IMPLIES(function_.is_null(), compiled_code_->parameter_count() == 0);
  fixed_size += ComputeIncomingArgumentSize(compiled_code_);
  return fixed_size;
}

namespace {

// Get the actual deopt call PC from the return address of the deopt, which
// points to immediately after the deopt call).
//
// See also the Deoptimizer constructor.
Address GetDeoptCallPCFromReturnPC(Address return_pc, Tagged<Code> code) {
  DCHECK_GT(Deoptimizer::kEagerDeoptExitSize, 0);
  DCHECK_GT(Deoptimizer::kLazyDeoptExitSize, 0);
  Tagged<DeoptimizationData> deopt_data =
      Cast<DeoptimizationData>(code->deoptimization_data());
  Address deopt_start =
      code->instruction_start() + deopt_data->DeoptExitStart().value();
  int eager_deopt_count = deopt_data->EagerDeoptCount().value();
  Address lazy_deopt_start =
      deopt_start + eager_deopt_count * Deoptimizer::kEagerDeoptExitSize;
  // The deoptimization exits are sorted so that lazy deopt exits appear
  // after eager deopts.
  static_assert(static_cast<int>(DeoptimizeKind::kLazy) ==
                    static_cast<int>(kLastDeoptimizeKind),
                "lazy deopts are expected to be emitted last");
  if (return_pc <= lazy_deopt_start) {
    return return_pc - Deoptimizer::kEagerDeoptExitSize;
  } else {
    return return_pc - Deoptimizer::kLazyDeoptExitSize;
  }
}

}  // namespace

unsigned Deoptimizer::ComputeInputFrameSize() const {
  // The fp-to-sp delta already takes the context, constant pool pointer and the
  // function into account so we have to avoid double counting them.
  unsigned fixed_size_above_fp = ComputeInputFrameAboveFpFixedSize();
  unsigned result = fixed_size_above_fp + fp_to_sp_delta_;
  DCHECK(CodeKindCanDeoptimize(compiled_code_->kind()));
  unsigned stack_slots = compiled_code_->stack_slots();
  if (compiled_code_->is_maglevved() && !deoptimizing_throw_) {
    // Maglev code can deopt in deferred code which has spilled registers across
    // the call. These will be included in the fp_to_sp_delta, but the expected
    // frame size won't include them, so we need to check for less-equal rather
    // than equal. For deoptimizing throws, these will have already been trimmed
    // off.
    CHECK_LE(fixed_size_above_fp + (stack_slots * kSystemPointerSize) -
                 CommonFrameConstants::kFixedFrameSizeAboveFp,
             result);
    // With slow asserts we can check this exactly, by looking up the safepoint.
    if (v8_flags.enable_slow_asserts) {
      Address deopt_call_pc = GetDeoptCallPCFromReturnPC(from_, compiled_code_);
      MaglevSafepointTable table(isolate_, deopt_call_pc, compiled_code_);
      MaglevSafepointEntry safepoint = table.FindEntry(deopt_call_pc);
      unsigned extra_spills = safepoint.num_extra_spill_slots();
      CHECK_EQ(fixed_size_above_fp + (stack_slots * kSystemPointerSize) -
                   CommonFrameConstants::kFixedFrameSizeAboveFp +
                   extra_spills * kSystemPointerSize,
               result);
    }
  } else {
    unsigned outgoing_size = 0;
    CHECK_EQ(fixed_size_above_fp + (stack_slots * kSystemPointerSize) -
                 CommonFrameConstants::kFixedFrameSizeAboveFp + outgoing_size,
             result);
  }
  return result;
}

// static
unsigned Deoptimizer::ComputeIncomingArgumentSize(Tagged<Code> code) {
  int parameter_slots = code->parameter_count();
  return parameter_slots * kSystemPointerSize;
}

Deoptimizer::DeoptInfo Deoptimizer::GetDeoptInfo(Tagged<Code> code,
                                                 Address pc) {
  CHECK(code->instruction_start() <= pc && pc <= code->instruction_end());
  SourcePosition last_position = SourcePosition::Unknown();
  DeoptimizeReason last_reason = DeoptimizeReason::kUnknown;
  uint32_t last_node_id = 0;
  int last_deopt_id = kNoDeoptimizationId;
  int mask = RelocInfo::ModeMask(RelocInfo::DEOPT_REASON) |
             RelocInfo::ModeMask(RelocInfo::DEOPT_ID) |
             RelocInfo::ModeMask(RelocInfo::DEOPT_SCRIPT_OFFSET) |
             RelocInfo::ModeMask(RelocInfo::DEOPT_INLINING_ID) |
             RelocInfo::ModeMask(RelocInfo::DEOPT_NODE_ID);
  for (RelocIterator it(code, mask); !it.done(); it.next()) {
    RelocInfo* info = it.rinfo();
    if (info->pc() >= pc) break;
    if (info->rmode() == RelocInfo::DEOPT_SCRIPT_OFFSET) {
      int script_offset = static_cast<int>(info->data());
      it.next();
      DCHECK(it.rinfo()->rmode() == RelocInfo::DEOPT_INLINING_ID);
      int inlining_id = static_cast<int>(it.rinfo()->data());
      last_position = SourcePosition(script_offset, inlining_id);
    } else if (info->rmode() == RelocInfo::DEOPT_ID) {
      last_deopt_id = static_cast<int>(info->data());
    } else if (info->rmode() == RelocInfo::DEOPT_REASON) {
      last_reason = static_cast<DeoptimizeReason>(info->data());
    } else if (info->rmode() == RelocInfo::DEOPT_NODE_ID) {
      last_node_id = static_cast<uint32_t>(info->data());
    }
  }
  return DeoptInfo(last_position, last_reason, last_node_id, last_deopt_id);
}

}  // namespace internal
}  // namespace v8

"""


```