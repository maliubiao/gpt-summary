Response:
My thinking process to summarize the provided C++ code snippet goes like this:

1. **Identify the Core Functionality:** The code is within a `MacroAssembler` class, specifically for the x64 architecture. This immediately tells me it's about generating machine code instructions. The various methods within the snippet likely correspond to specific x64 instructions or common code patterns.

2. **Break Down into Logical Groups:** I start reading through the code and mentally group related functionalities. I notice patterns and comments that suggest these groups:

    * **Write Barriers:** The code around `RecordWriteField` and `CallRecordWriteStub` clearly deals with managing writes to the heap and ensuring proper garbage collection behavior. The `ReadOnlyCheck` and `SmiCheck` options provide further clues.
    * **Conditional Checks and Aborts:** The `Check`, `SbxCheck`, and `Abort` methods are about asserting conditions and handling errors.
    * **Stack Management:**  `CheckStackAlignment` and `AlignStackPointer` relate to maintaining proper stack structure.
    * **Runtime Calls:** `CallRuntime` and `TailCallRuntime` deal with invoking functions implemented in C++.
    * **Optimized Code Handling:** The section involving `TailCallOptimizedCodeSlot`, `ReplaceClosureCodeWithOptimizedCode`, and the feedback vector checks are related to optimizing JavaScript function calls.
    * **Register Saving/Restoring:**  `PushCallerSaved` and `PopCallerSaved` are standard procedures for managing registers across function calls.
    * **Floating-Point Operations:** A significant portion of the code deals with various floating-point conversions (`Cvtss2sd`, `Cvtsd2ss`, `Cvttss2si`, etc.) and comparisons. The AVX/SSE conditional compilation hints at the use of SIMD instructions.
    * **Smi Handling:** `GetSmiConstant` and the mention of Smi checks point to optimizations for small integers.
    * **Bitwise Operations (AVX2):** The functions `S256Not` and `S256Select` utilize AVX2 instructions for operating on 256-bit vectors.
    * **Integer Conversions from Float:** The `ConvertFloatToUint64` and `ConvertFloatToUint32` templates with the `Cvttsd2uiq` and related functions show the complex logic required for these conversions on x64.

3. **Summarize Each Group Concisely:**  For each identified group, I formulate a brief description of its purpose. I use action verbs and focus on the "what" rather than the "how" of the implementation details. For example, instead of saying "it pushes registers onto the stack," I say "manages saving and restoring of registers."

4. **Address Specific Instructions:** The prompt asks about JavaScript relevance and potential errors. I look for clues within each group:

    * **Write Barriers:**  Directly related to JavaScript object manipulation and GC.
    * **Optimized Code:** Crucial for JavaScript performance.
    * **Runtime Calls:** The bridge between compiled JavaScript and V8's runtime.
    * **Floating-Point Conversions:** Important for Number type operations in JavaScript. Potential errors: precision loss, overflow, NaN handling.
    * **Smi Handling:** Optimization for common JavaScript integer values.

5. **Consider the "Torque" Question:** The prompt explicitly mentions `.tq` files. I confirm that this file is `.cc` and therefore *not* Torque.

6. **Construct the Final Summary:** I combine the summaries of each group into a coherent overview. I start with the most general purpose ("low-level code generation") and then delve into the more specific functionalities.

7. **Review and Refine:** I read through the summary to ensure accuracy, clarity, and conciseness. I double-check that I've addressed all aspects of the prompt. I make sure the language is appropriate for a technical audience but still understandable.

Essentially, my approach is to dissect the code into its functional components, understand the purpose of each component within the context of a macro assembler, and then synthesize this information into a concise and informative summary, paying attention to the specific questions asked in the prompt. The comments in the code itself are very helpful in this process.
这是对 `v8/src/codegen/x64/macro-assembler-x64.cc` 源代码片段的功能归纳，延续了之前的部分。

**功能归纳 (第 2 部分):**

这段代码主要集中在以下几个方面的功能：

1. **写入屏障 (Write Barrier) 的实现:** 这部分代码负责在修改堆中对象指针时，确保垃圾回收器 (Garbage Collector, GC) 能够正确追踪对象的引用关系。它会检查是否需要执行写入屏障，例如写入的是小整数 (Smi)、只读对象或年轻代对象时可以跳过。对于需要写入屏障的情况，会根据 slot 的类型 (直接指针或间接指针) 调用相应的写入屏障例程 (`CallRecordWriteStub` 或 `CallIndirectPointerBarrier`)。

2. **断言和错误处理:**  `Check` 和 `SbxCheck` 方法用于在代码中插入断言，当条件不满足时，会触发 `Abort` 方法，导致程序终止并报告错误原因。

3. **栈对齐管理:** `CheckStackAlignment` 和 `AlignStackPointer` 确保栈指针在函数调用前后保持正确的对齐，这对于某些 CPU 指令和性能优化至关重要。

4. **调用运行时函数 (Runtime Calls):** `CallRuntime` 和 `TailCallRuntime` 用于调用 V8 的 C++ 运行时函数。`CallRuntime` 用于普通调用，而 `TailCallRuntime` 用于尾调用优化，可以减少栈帧的创建。

5. **尾调用优化到已编译代码:**  `GenerateTailCallToReturnedCode` 用于生成尾调用到已经编译的代码的指令序列。这在 JavaScript 函数调用优化中非常重要。

6. **替换闭包中的代码:** `ReplaceClosureCodeWithOptimizedCode` 用于将闭包对象中指向解释执行代码的指针替换为指向优化后代码的指针。

7. **基于反馈向量优化代码调用 (非 Leap Tiering):** 在未启用 Leap Tiering 的情况下，`CheckFeedbackVectorFlagsNeedsProcessing`、`CheckFeedbackVectorFlagsAndJumpIfNeedsProcessing` 和 `OptimizeCodeOrTailCallOptimizedCodeSlot` 这组函数用于检查反馈向量中的标志，判断是否需要进行代码优化或尾调用到已优化的代码。

8. **保存和恢复调用者保存的寄存器:** `PushCallerSaved` 和 `PopCallerSaved` 用于在函数调用前后保存和恢复调用者负责保存的寄存器，以避免寄存器被覆盖。

9. **浮点数操作:**  代码中包含了大量的浮点数操作指令，例如 `Movq` (移动), `Cvtss2sd` (单精度转双精度), `Cvtsd2ss` (双精度转单精度), `Cvttss2si` (截断单精度转有符号整数), `Cvttsd2si` (截断双精度转有符号整数) 等。这些指令用于执行 JavaScript 中的数值运算。

10. **SIMD 指令 (AVX/AVX2/SSE4.1/F16C):** 代码中使用了如 `vmovq`, `vpextrq`, `vpcmpeqd`, `vpxor`, `vpandn`, `vpand`, `vpor`, `vcvtps2ph` 等 AVX/AVX2 和 SSE4.1/F16C 指令，用于并行处理数据，提高浮点数和整数运算的性能。

11. **浮点数转换为无符号整数:**  `Cvttsd2uiq`, `Cvttsd2ui`, `Cvttss2uiq`, `Cvttss2ui` 这组函数实现了将浮点数截断转换为无符号 64 位或 32 位整数的功能，并处理了超出范围的情况。

12. **浮点数比较:** `Cmpeqss` 和 `Cmpeqsd` 用于比较单精度和双精度浮点数是否相等。

13. **Smi (小整数) 常量获取:** `GetSmiConstant` 用于获取 Smi 类型的常量值到寄存器中。

14. **整数比较:** `Cmp(Register dst, int32_t src)` 提供了一种方便的整数比较方式，对于比较 0 做了特殊优化。

15. **256 位向量操作 (AVX2):** `I64x4Mul`, `S256Not`, `S256Select` 等函数利用 AVX2 指令对 256 位向量进行乘法、位非和选择操作。

**关于问题中的点:**

* **.tq 结尾:** 代码片段来自 `.cc` 文件，因此不是 Torque 源代码。
* **与 JavaScript 功能的关系:** 这段代码与 JavaScript 的执行密切相关。
    * **写入屏障:**  支持 JavaScript 对象的垃圾回收。
    * **运行时调用:**  JavaScript 代码经常需要调用 V8 提供的内置函数。
    * **尾调用优化:**  提升 JavaScript 函数调用的性能。
    * **替换闭包代码:**  实现 JavaScript 函数的优化执行。
    * **浮点数操作:**  支持 JavaScript 中的 `Number` 类型和相关的数学运算。
    * **SIMD 指令:**  用于加速 JavaScript 中的密集数值计算。
* **JavaScript 示例:**

```javascript
function example(obj) {
  obj.field = 10; // 可能会触发写入屏障
  return Math.sqrt(obj.field); // 可能使用浮点数操作
}

function factorial(n) {
  if (n <= 1) {
    return 1;
  }
  return n * factorial(n - 1); // 尾调用可能被优化
}
```

* **代码逻辑推理 (假设输入与输出):**

假设输入：`object` 寄存器指向一个堆中的对象，`slot_address` 寄存器指向对象中一个字段的地址，`value` 寄存器包含要写入的值 (一个指向另一个堆对象的指针)。

输出：
    * 如果需要写入屏障，则调用相应的写入屏障例程，确保 GC 能追踪到 `object` 指向的对象的修改。
    * 如果不需要写入屏障 (例如 `value` 是 Smi)，则直接将 `value` 写入到 `slot_address` 指向的内存。

* **用户常见的编程错误:**

    * **内存泄漏 (Memory Leaks):**  虽然写入屏障帮助 GC 追踪引用，但如果 JavaScript 代码中存在逻辑错误导致对象无法被回收，仍然会发生内存泄漏。
    * **类型错误 (Type Errors):**  例如，尝试将一个非对象的值赋值给一个期望对象引用的字段，可能会触发写入屏障相关的错误或导致程序崩溃。
    * **浮点数精度问题:**  JavaScript 中的 `Number` 类型是双精度浮点数，在进行大量或复杂的浮点数运算时，可能会遇到精度丢失的问题。

**总结:**

这段 `macro-assembler-x64.cc` 的代码片段是 V8 引擎中用于生成 x64 架构机器码的关键部分，负责处理底层的内存操作、错误处理、函数调用优化以及数值运算。它直接支撑着 JavaScript 代码的执行效率和内存管理。

Prompt: 
```
这是目录为v8/src/codegen/x64/macro-assembler-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/x64/macro-assembler-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能

"""
 // Use object register as scratch
      Register scratch = object;
      Push(slot_address);  // Use slot address register to load the value into
      Register value_in_slot = slot_address;
      LoadIndirectPointerField(value_in_slot, Operand(slot_address, 0),
                               slot.indirect_pointer_tag(), scratch);
      cmp_tagged(value, value_in_slot);
      // These pops don't affect the flag registers, so we can do them before
      // the conditional jump below.
      Pop(slot_address);
      Pop(object);
    } else {
      cmp_tagged(value, Operand(slot_address, 0));
    }
    j(equal, &ok, Label::kNear);
    int3();
    bind(&ok);
  }

  // First, check if a write barrier is even needed. The tests below
  // catch stores of smis and read-only objects, as well as stores into the
  // young generation.
  Label done;

#if V8_STATIC_ROOTS_BOOL
  if (ro_check == ReadOnlyCheck::kInline) {
    // Quick check for Read-only and small Smi values.
    static_assert(StaticReadOnlyRoot::kLastAllocatedRoot < kRegularPageSize);
    JumpIfUnsignedLessThan(value, kRegularPageSize, &done);
  }
#endif  // V8_STATIC_ROOTS_BOOL

  if (smi_check == SmiCheck::kInline) {
    // Skip barrier if writing a smi.
    JumpIfSmi(value, &done);
  }

  if (slot.contains_indirect_pointer()) {
    // The indirect pointer write barrier is only enabled during marking.
    JumpIfNotMarking(&done);
  } else {
#if V8_ENABLE_STICKY_MARK_BITS_BOOL
    DCHECK(!AreAliased(kScratchRegister, object, slot_address, value));
    Label stub_call;

    JumpIfMarking(&stub_call);

    // Save the slot_address in the xmm scratch register.
    movq(kScratchDoubleReg, slot_address);
    Register scratch0 = slot_address;
    CheckMarkBit(object, kScratchRegister, scratch0, carry, &done);
    CheckPageFlag(value, kScratchRegister, MemoryChunk::kIsInReadOnlyHeapMask,
                  not_zero, &done, Label::kFar);
    CheckMarkBit(value, kScratchRegister, scratch0, carry, &done);
    movq(slot_address, kScratchDoubleReg);
    bind(&stub_call);
#else   // !V8_ENABLE_STICKY_MARK_BITS_BOOL
    CheckPageFlag(value,
                  value,  // Used as scratch.
                  MemoryChunk::kPointersToHereAreInterestingMask, zero, &done,
                  Label::kNear);

    CheckPageFlag(object,
                  value,  // Used as scratch.
                  MemoryChunk::kPointersFromHereAreInterestingMask, zero, &done,
                  Label::kNear);
#endif  // !V8_ENABLE_STICKY_MARK_BITS_BOOL
  }

  if (slot.contains_direct_pointer()) {
    CallRecordWriteStub(object, slot_address, fp_mode,
                        StubCallMode::kCallBuiltinPointer);
  } else {
    DCHECK(slot.contains_indirect_pointer());
    CallIndirectPointerBarrier(object, slot_address, fp_mode,
                               slot.indirect_pointer_tag());
  }

  bind(&done);

  // Clobber clobbered registers when running with the debug-code flag
  // turned on to provoke errors.
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT_STRING(this, "Zap scratch registers");
    Move(slot_address, kZapValue, RelocInfo::NO_INFO);
    Move(value, kZapValue, RelocInfo::NO_INFO);
  }
}

void MacroAssembler::Check(Condition cc, AbortReason reason) {
  Label L;
  j(cc, &L, Label::kNear);
  Abort(reason);
  // Control will not return here.
  bind(&L);
}

void MacroAssembler::SbxCheck(Condition cc, AbortReason reason) {
  Check(cc, reason);
}

void MacroAssembler::CheckStackAlignment() {
  int frame_alignment = base::OS::ActivationFrameAlignment();
  int frame_alignment_mask = frame_alignment - 1;
  if (frame_alignment > kSystemPointerSize) {
    ASM_CODE_COMMENT(this);
    DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
    Label alignment_as_expected;
    testq(rsp, Immediate(frame_alignment_mask));
    j(zero, &alignment_as_expected, Label::kNear);
    // Abort if stack is not aligned.
    int3();
    bind(&alignment_as_expected);
  }
}

void MacroAssembler::AlignStackPointer() {
  const int kFrameAlignment = base::OS::ActivationFrameAlignment();
  if (kFrameAlignment > 0) {
    DCHECK(base::bits::IsPowerOfTwo(kFrameAlignment));
    DCHECK(is_int8(kFrameAlignment));
    andq(rsp, Immediate(-kFrameAlignment));
  }
}

void MacroAssembler::Abort(AbortReason reason) {
  ASM_CODE_COMMENT(this);
  if (v8_flags.code_comments) {
    const char* msg = GetAbortReason(reason);
    RecordComment("Abort message: ");
    RecordComment(msg);
  }

  // Avoid emitting call to builtin if requested.
  if (trap_on_abort()) {
    int3();
    return;
  }

  if (should_abort_hard()) {
    // We don't care if we constructed a frame. Just pretend we did.
    FrameScope assume_frame(this, StackFrame::NO_FRAME_TYPE);
    Move(kCArgRegs[0], static_cast<int>(reason));
    PrepareCallCFunction(1);
    LoadAddress(rax, ExternalReference::abort_with_reason());
    call(rax);
    return;
  }

  Move(rdx, Smi::FromInt(static_cast<int>(reason)));

  {
    // We don't actually want to generate a pile of code for this, so just
    // claim there is a stack frame, without generating one.
    FrameScope scope(this, StackFrame::NO_FRAME_TYPE);
    if (root_array_available()) {
      // Generate an indirect call via builtins entry table here in order to
      // ensure that the interpreter_entry_return_pc_offset is the same for
      // InterpreterEntryTrampoline and InterpreterEntryTrampolineForProfiling
      // when v8_flags.debug_code is enabled.
      Call(EntryFromBuiltinAsOperand(Builtin::kAbort));
    } else {
      CallBuiltin(Builtin::kAbort);
    }
  }

  // Control will not return here.
  int3();
}

void MacroAssembler::CallRuntime(const Runtime::Function* f,
                                 int num_arguments) {
  ASM_CODE_COMMENT(this);
  // If the expected number of arguments of the runtime function is
  // constant, we check that the actual number of arguments match the
  // expectation.
  CHECK(f->nargs < 0 || f->nargs == num_arguments);

  // TODO(1236192): Most runtime routines don't need the number of
  // arguments passed in because it is constant. At some point we
  // should remove this need and make the runtime routine entry code
  // smarter.
  Move(rax, num_arguments);
  LoadAddress(rbx, ExternalReference::Create(f));

  bool switch_to_central = options().is_wasm;
  CallBuiltin(Builtins::RuntimeCEntry(f->result_size, switch_to_central));
}

void MacroAssembler::TailCallRuntime(Runtime::FunctionId fid) {
  // ----------- S t a t e -------------
  //  -- rsp[0]                 : return address
  //  -- rsp[8]                 : argument num_arguments - 1
  //  ...
  //  -- rsp[8 * num_arguments] : argument 0 (receiver)
  //
  //  For runtime functions with variable arguments:
  //  -- rax                    : number of  arguments
  // -----------------------------------
  ASM_CODE_COMMENT(this);
  const Runtime::Function* function = Runtime::FunctionForId(fid);
  DCHECK_EQ(1, function->result_size);
  if (function->nargs >= 0) {
    Move(rax, function->nargs);
  }
  JumpToExternalReference(ExternalReference::Create(fid));
}

void MacroAssembler::JumpToExternalReference(const ExternalReference& ext,
                                             bool builtin_exit_frame) {
  ASM_CODE_COMMENT(this);
  // Set the entry point and jump to the C entry runtime stub.
  LoadAddress(rbx, ext);
  TailCallBuiltin(Builtins::CEntry(1, ArgvMode::kStack, builtin_exit_frame));
}

namespace {

#ifndef V8_ENABLE_LEAPTIERING
// Only used when leaptiering is disabled.
void TailCallOptimizedCodeSlot(MacroAssembler* masm,
                               Register optimized_code_entry, Register closure,
                               Register scratch1, Register scratch2,
                               JumpMode jump_mode) {
  // ----------- S t a t e -------------
  //  rax : actual argument count
  //  rdx : new target (preserved for callee if needed, and caller)
  //  rsi : current context, used for the runtime call
  //  rdi : target function (preserved for callee if needed, and caller)
  // -----------------------------------
  ASM_CODE_COMMENT(masm);
  DCHECK_EQ(closure, kJSFunctionRegister);
  DCHECK(!AreAliased(rax, rdx, closure, rsi, optimized_code_entry, scratch1,
                     scratch2));

  Label heal_optimized_code_slot;

  // If the optimized code is cleared, go to runtime to update the optimization
  // marker field.
  __ LoadWeakValue(optimized_code_entry, &heal_optimized_code_slot);

  // The entry references a CodeWrapper object. Unwrap it now.
  __ LoadCodePointerField(
      optimized_code_entry,
      FieldOperand(optimized_code_entry, CodeWrapper::kCodeOffset), scratch1);

  // Check if the optimized code is marked for deopt. If it is, call the
  // runtime to clear it.
  __ AssertCode(optimized_code_entry);
  __ TestCodeIsMarkedForDeoptimization(optimized_code_entry);
  __ j(not_zero, &heal_optimized_code_slot);

  // Optimized code is good, get it into the closure and link the closure into
  // the optimized functions list, then tail call the optimized code.
  __ ReplaceClosureCodeWithOptimizedCode(optimized_code_entry, closure,
                                         scratch1, scratch2);
  static_assert(kJavaScriptCallCodeStartRegister == rcx, "ABI mismatch");
  __ Move(rcx, optimized_code_entry);
  __ JumpCodeObject(rcx, kJSEntrypointTag, jump_mode);

  // Optimized code slot contains deoptimized code or code is cleared and
  // optimized code marker isn't updated. Evict the code, update the marker
  // and re-enter the closure's code.
  __ bind(&heal_optimized_code_slot);
  __ GenerateTailCallToReturnedCode(Runtime::kHealOptimizedCodeSlot, jump_mode);
}
#endif  // V8_ENABLE_LEAPTIERING

}  // namespace

#ifdef V8_ENABLE_DEBUG_CODE
void MacroAssembler::AssertFeedbackCell(Register object, Register scratch) {
  if (v8_flags.debug_code) {
    IsObjectType(object, FEEDBACK_CELL_TYPE, scratch);
    Assert(equal, AbortReason::kExpectedFeedbackCell);
  }
}
void MacroAssembler::AssertFeedbackVector(Register object, Register scratch) {
  if (v8_flags.debug_code) {
    IsObjectType(object, FEEDBACK_VECTOR_TYPE, scratch);
    Assert(equal, AbortReason::kExpectedFeedbackVector);
  }
}
#endif  // V8_ENABLE_DEBUG_CODE

void MacroAssembler::GenerateTailCallToReturnedCode(
    Runtime::FunctionId function_id, JumpMode jump_mode) {
  // ----------- S t a t e -------------
  //  -- rax : actual argument count (preserved for callee)
  //  -- rdx : new target (preserved for callee)
  //  -- rdi : target function (preserved for callee)
  //  -- r15 : dispatch handle (preserved for callee)
  // -----------------------------------
  ASM_CODE_COMMENT(this);
  {
    FrameScope scope(this, StackFrame::INTERNAL);
    // Push a copy of the target function, the new target, the actual argument
    // count, and the dispatch handle.
    Push(kJavaScriptCallTargetRegister);
    Push(kJavaScriptCallNewTargetRegister);
    SmiTag(kJavaScriptCallArgCountRegister);
    Push(kJavaScriptCallArgCountRegister);
#ifdef V8_ENABLE_LEAPTIERING
    // No need to SmiTag since dispatch handles always look like Smis.
    static_assert(kJSDispatchHandleShift > 0);
    Push(kJavaScriptCallDispatchHandleRegister);
#endif
    // Function is also the parameter to the runtime call.
    Push(kJavaScriptCallTargetRegister);

    CallRuntime(function_id, 1);
    movq(rcx, rax);

    // Restore target function, new target, actual argument count, and dispatch
    // handle.
#ifdef V8_ENABLE_LEAPTIERING
    Pop(kJavaScriptCallDispatchHandleRegister);
#endif
    Pop(kJavaScriptCallArgCountRegister);
    SmiUntagUnsigned(kJavaScriptCallArgCountRegister);
    Pop(kJavaScriptCallNewTargetRegister);
    Pop(kJavaScriptCallTargetRegister);
  }
  static_assert(kJavaScriptCallCodeStartRegister == rcx, "ABI mismatch");
  JumpCodeObject(rcx, kJSEntrypointTag, jump_mode);
}

void MacroAssembler::ReplaceClosureCodeWithOptimizedCode(
    Register optimized_code, Register closure, Register scratch1,
    Register slot_address) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(optimized_code, closure, scratch1, slot_address));
  DCHECK_EQ(closure, kJSFunctionRegister);

#ifdef V8_ENABLE_LEAPTIERING
  UNREACHABLE();
#else
  // Store the optimized code in the closure.
  AssertCode(optimized_code);
  StoreCodePointerField(FieldOperand(closure, JSFunction::kCodeOffset),
                        optimized_code);

  // Write barrier clobbers scratch1 below.
  Register value = scratch1;
  movq(value, optimized_code);

  RecordWriteField(closure, JSFunction::kCodeOffset, value, slot_address,
                   SaveFPRegsMode::kIgnore, SmiCheck::kOmit,
                   ReadOnlyCheck::kOmit, SlotDescriptor::ForCodePointerSlot());
#endif  // V8_ENABLE_LEAPTIERING
}

#ifndef V8_ENABLE_LEAPTIERING

// Read off the flags in the feedback vector and check if there
// is optimized code or a tiering state that needs to be processed.
Condition MacroAssembler::CheckFeedbackVectorFlagsNeedsProcessing(
    Register feedback_vector, CodeKind current_code_kind) {
  ASM_CODE_COMMENT(this);
  DCHECK(CodeKindCanTierUp(current_code_kind));
  uint32_t flag_mask =
      FeedbackVector::FlagMaskForNeedsProcessingCheckFrom(current_code_kind);
  testw(FieldOperand(feedback_vector, FeedbackVector::kFlagsOffset),
        Immediate(flag_mask));
  return not_zero;
}

void MacroAssembler::CheckFeedbackVectorFlagsAndJumpIfNeedsProcessing(
    Register feedback_vector, CodeKind current_code_kind,
    Label* flags_need_processing) {
  ASM_CODE_COMMENT(this);
  j(CheckFeedbackVectorFlagsNeedsProcessing(feedback_vector, current_code_kind),
    flags_need_processing);
}

void MacroAssembler::OptimizeCodeOrTailCallOptimizedCodeSlot(
    Register feedback_vector, Register closure, JumpMode jump_mode) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(feedback_vector, closure));

  Label maybe_has_optimized_code, maybe_needs_logging;
  // Check if optimized code is available.
  testw(FieldOperand(feedback_vector, FeedbackVector::kFlagsOffset),
        Immediate(FeedbackVector::kFlagsTieringStateIsAnyRequested));
  j(zero, &maybe_needs_logging);

  GenerateTailCallToReturnedCode(Runtime::kCompileOptimized, jump_mode);

  bind(&maybe_needs_logging);
  testw(FieldOperand(feedback_vector, FeedbackVector::kFlagsOffset),
        Immediate(FeedbackVector::LogNextExecutionBit::kMask));
  j(zero, &maybe_has_optimized_code);
  GenerateTailCallToReturnedCode(Runtime::kFunctionLogNextExecution, jump_mode);

  bind(&maybe_has_optimized_code);
  Register optimized_code_entry = kJavaScriptCallCodeStartRegister;
  LoadTaggedField(
      optimized_code_entry,
      FieldOperand(feedback_vector, FeedbackVector::kMaybeOptimizedCodeOffset));
  TailCallOptimizedCodeSlot(this, optimized_code_entry, closure, r9,
                            WriteBarrierDescriptor::SlotAddressRegister(),
                            jump_mode);
}

#endif  // !V8_ENABLE_LEAPTIERING

int MacroAssembler::RequiredStackSizeForCallerSaved(SaveFPRegsMode fp_mode,
                                                    Register exclusion) const {
  int bytes = 0;
  RegList saved_regs = kCallerSaved - exclusion;
  bytes += kSystemPointerSize * saved_regs.Count();

  // R12 to r15 are callee save on all platforms.
  if (fp_mode == SaveFPRegsMode::kSave) {
    bytes += kStackSavedSavedFPSize * kAllocatableDoubleRegisters.Count();
  }

  return bytes;
}

int MacroAssembler::PushCallerSaved(SaveFPRegsMode fp_mode,
                                    Register exclusion) {
  ASM_CODE_COMMENT(this);
  int bytes = 0;
  bytes += PushAll(kCallerSaved - exclusion);
  if (fp_mode == SaveFPRegsMode::kSave) {
    bytes += PushAll(kAllocatableDoubleRegisters);
  }

  return bytes;
}

int MacroAssembler::PopCallerSaved(SaveFPRegsMode fp_mode, Register exclusion) {
  ASM_CODE_COMMENT(this);
  int bytes = 0;
  if (fp_mode == SaveFPRegsMode::kSave) {
    bytes += PopAll(kAllocatableDoubleRegisters);
  }
  bytes += PopAll(kCallerSaved - exclusion);

  return bytes;
}

int MacroAssembler::PushAll(RegList registers) {
  int bytes = 0;
  for (Register reg : registers) {
    pushq(reg);
    bytes += kSystemPointerSize;
  }
  return bytes;
}

int MacroAssembler::PopAll(RegList registers) {
  int bytes = 0;
  for (Register reg : base::Reversed(registers)) {
    popq(reg);
    bytes += kSystemPointerSize;
  }
  return bytes;
}

int MacroAssembler::PushAll(DoubleRegList registers, int stack_slot_size) {
  if (registers.is_empty()) return 0;
  const int delta = stack_slot_size * registers.Count();
  AllocateStackSpace(delta);
  int slot = 0;
  for (XMMRegister reg : registers) {
    if (stack_slot_size == kDoubleSize) {
      Movsd(Operand(rsp, slot), reg);
    } else {
      DCHECK_EQ(stack_slot_size, 2 * kDoubleSize);
      Movdqu(Operand(rsp, slot), reg);
    }
    slot += stack_slot_size;
  }
  DCHECK_EQ(slot, delta);
  return delta;
}

int MacroAssembler::PopAll(DoubleRegList registers, int stack_slot_size) {
  if (registers.is_empty()) return 0;
  int slot = 0;
  for (XMMRegister reg : registers) {
    if (stack_slot_size == kDoubleSize) {
      Movsd(reg, Operand(rsp, slot));
    } else {
      DCHECK_EQ(stack_slot_size, 2 * kDoubleSize);
      Movdqu(reg, Operand(rsp, slot));
    }
    slot += stack_slot_size;
  }
  DCHECK_EQ(slot, stack_slot_size * registers.Count());
  addq(rsp, Immediate(slot));
  return slot;
}

void MacroAssembler::Movq(XMMRegister dst, Register src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    vmovq(dst, src);
  } else {
    movq(dst, src);
  }
}

void MacroAssembler::Movq(Register dst, XMMRegister src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    vmovq(dst, src);
  } else {
    movq(dst, src);
  }
}

void MacroAssembler::Pextrq(Register dst, XMMRegister src, int8_t imm8) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    vpextrq(dst, src, imm8);
  } else {
    CpuFeatureScope sse_scope(this, SSE4_1);
    pextrq(dst, src, imm8);
  }
}

void MacroAssembler::Cvtss2sd(XMMRegister dst, XMMRegister src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvtss2sd(dst, src, src);
  } else {
    cvtss2sd(dst, src);
  }
}

void MacroAssembler::Cvtss2sd(XMMRegister dst, Operand src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvtss2sd(dst, dst, src);
  } else {
    cvtss2sd(dst, src);
  }
}

void MacroAssembler::Cvtsd2ss(XMMRegister dst, XMMRegister src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvtsd2ss(dst, src, src);
  } else {
    cvtsd2ss(dst, src);
  }
}

void MacroAssembler::Cvtsd2ss(XMMRegister dst, Operand src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvtsd2ss(dst, dst, src);
  } else {
    cvtsd2ss(dst, src);
  }
}

void MacroAssembler::Cvtlsi2sd(XMMRegister dst, Register src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvtlsi2sd(dst, kScratchDoubleReg, src);
  } else {
    xorpd(dst, dst);
    cvtlsi2sd(dst, src);
  }
}

void MacroAssembler::Cvtlsi2sd(XMMRegister dst, Operand src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvtlsi2sd(dst, kScratchDoubleReg, src);
  } else {
    xorpd(dst, dst);
    cvtlsi2sd(dst, src);
  }
}

void MacroAssembler::Cvtlsi2ss(XMMRegister dst, Register src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvtlsi2ss(dst, kScratchDoubleReg, src);
  } else {
    xorps(dst, dst);
    cvtlsi2ss(dst, src);
  }
}

void MacroAssembler::Cvtlsi2ss(XMMRegister dst, Operand src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvtlsi2ss(dst, kScratchDoubleReg, src);
  } else {
    xorps(dst, dst);
    cvtlsi2ss(dst, src);
  }
}

void MacroAssembler::Cvtqsi2ss(XMMRegister dst, Register src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvtqsi2ss(dst, kScratchDoubleReg, src);
  } else {
    xorps(dst, dst);
    cvtqsi2ss(dst, src);
  }
}

void MacroAssembler::Cvtqsi2ss(XMMRegister dst, Operand src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvtqsi2ss(dst, kScratchDoubleReg, src);
  } else {
    xorps(dst, dst);
    cvtqsi2ss(dst, src);
  }
}

void MacroAssembler::Cvtqsi2sd(XMMRegister dst, Register src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvtqsi2sd(dst, kScratchDoubleReg, src);
  } else {
    xorpd(dst, dst);
    cvtqsi2sd(dst, src);
  }
}

void MacroAssembler::Cvtqsi2sd(XMMRegister dst, Operand src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvtqsi2sd(dst, kScratchDoubleReg, src);
  } else {
    xorpd(dst, dst);
    cvtqsi2sd(dst, src);
  }
}

void MacroAssembler::Cvtlui2ss(XMMRegister dst, Register src) {
  // Zero-extend the 32 bit value to 64 bit.
  movl(kScratchRegister, src);
  Cvtqsi2ss(dst, kScratchRegister);
}

void MacroAssembler::Cvtlui2ss(XMMRegister dst, Operand src) {
  // Zero-extend the 32 bit value to 64 bit.
  movl(kScratchRegister, src);
  Cvtqsi2ss(dst, kScratchRegister);
}

void MacroAssembler::Cvtlui2sd(XMMRegister dst, Register src) {
  // Zero-extend the 32 bit value to 64 bit.
  movl(kScratchRegister, src);
  Cvtqsi2sd(dst, kScratchRegister);
}

void MacroAssembler::Cvtlui2sd(XMMRegister dst, Operand src) {
  // Zero-extend the 32 bit value to 64 bit.
  movl(kScratchRegister, src);
  Cvtqsi2sd(dst, kScratchRegister);
}

void MacroAssembler::Cvtqui2ss(XMMRegister dst, Register src) {
  Label done;
  Cvtqsi2ss(dst, src);
  testq(src, src);
  j(positive, &done, Label::kNear);

  // Compute {src/2 | (src&1)} (retain the LSB to avoid rounding errors).
  if (src != kScratchRegister) movq(kScratchRegister, src);
  shrq(kScratchRegister, Immediate(1));
  // The LSB is shifted into CF. If it is set, set the LSB in {tmp}.
  Label msb_not_set;
  j(not_carry, &msb_not_set, Label::kNear);
  orq(kScratchRegister, Immediate(1));
  bind(&msb_not_set);
  Cvtqsi2ss(dst, kScratchRegister);
  Addss(dst, dst);
  bind(&done);
}

void MacroAssembler::Cvtqui2ss(XMMRegister dst, Operand src) {
  movq(kScratchRegister, src);
  Cvtqui2ss(dst, kScratchRegister);
}

void MacroAssembler::Cvtqui2sd(XMMRegister dst, Register src) {
  Label done;
  Cvtqsi2sd(dst, src);
  testq(src, src);
  j(positive, &done, Label::kNear);

  // Compute {src/2 | (src&1)} (retain the LSB to avoid rounding errors).
  if (src != kScratchRegister) movq(kScratchRegister, src);
  shrq(kScratchRegister, Immediate(1));
  // The LSB is shifted into CF. If it is set, set the LSB in {tmp}.
  Label msb_not_set;
  j(not_carry, &msb_not_set, Label::kNear);
  orq(kScratchRegister, Immediate(1));
  bind(&msb_not_set);
  Cvtqsi2sd(dst, kScratchRegister);
  Addsd(dst, dst);
  bind(&done);
}

void MacroAssembler::Cvtqui2sd(XMMRegister dst, Operand src) {
  movq(kScratchRegister, src);
  Cvtqui2sd(dst, kScratchRegister);
}

void MacroAssembler::Cvttss2si(Register dst, XMMRegister src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvttss2si(dst, src);
  } else {
    cvttss2si(dst, src);
  }
}

void MacroAssembler::Cvttss2si(Register dst, Operand src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvttss2si(dst, src);
  } else {
    cvttss2si(dst, src);
  }
}

void MacroAssembler::Cvttsd2si(Register dst, XMMRegister src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvttsd2si(dst, src);
  } else {
    cvttsd2si(dst, src);
  }
}

void MacroAssembler::Cvttsd2si(Register dst, Operand src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvttsd2si(dst, src);
  } else {
    cvttsd2si(dst, src);
  }
}

void MacroAssembler::Cvttss2siq(Register dst, XMMRegister src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvttss2siq(dst, src);
  } else {
    cvttss2siq(dst, src);
  }
}

void MacroAssembler::Cvttss2siq(Register dst, Operand src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvttss2siq(dst, src);
  } else {
    cvttss2siq(dst, src);
  }
}

void MacroAssembler::Cvttsd2siq(Register dst, XMMRegister src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvttsd2siq(dst, src);
  } else {
    cvttsd2siq(dst, src);
  }
}

void MacroAssembler::Cvttsd2siq(Register dst, Operand src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vcvttsd2siq(dst, src);
  } else {
    cvttsd2siq(dst, src);
  }
}

void MacroAssembler::Cvtpd2ph(XMMRegister dst, XMMRegister src, Register tmp) {
  ASM_CODE_COMMENT(this);
  CpuFeatureScope f16c_scope(this, F16C);
  CpuFeatureScope avx_scope(this, AVX);
  Register tmp2 = kScratchRegister;
  DCHECK_NE(tmp, tmp2);
  DCHECK_NE(dst, src);

  // Conversion algo from
  // https://github.com/tc39/proposal-float16array/issues/12#issuecomment-2256642971
  Label f32tof16;
  // Convert Float64 -> Float32.
  Cvtsd2ss(dst, src);
  vmovd(tmp, dst);
  // Mask off sign bit.
  andl(tmp, Immediate(kFP32WithoutSignMask));
  // Underflow to zero.
  cmpl(tmp, Immediate(kFP32MinFP16ZeroRepresentable));
  j(below, &f32tof16);
  // Overflow to infinity.
  cmpl(tmp, Immediate(kFP32MaxFP16Representable));
  j(above_equal, &f32tof16);
  // Detection of subnormal numbers.
  cmpl(tmp, Immediate(kFP32SubnormalThresholdOfFP16));
  setcc(above_equal, tmp2);
  movzxbl(tmp2, tmp2);
  // Compute 0x1000 for normal and 0x0000 for denormal numbers.
  shll(tmp2, Immediate(12));
  // Look at the last thirteen bits of the mantissa which will be shifted out
  // when converting from float32 to float16. (The round and sticky bits.)
  // Normal numbers: If the round bit is set and sticky bits are zero, then
  // adjust the float32 mantissa.
  // Denormal numbers: If all bits are zero, then adjust the mantissa.
  andl(tmp, Immediate(0x1fff));
  // Check round and sticky bits.
  cmpl(tmp, tmp2);
  j(not_equal, &f32tof16);

  // Adjust mantissa by -1/0/+1.
  Move(kScratchDoubleReg, static_cast<uint32_t>(1));
  psignd(kScratchDoubleReg, src);
  paddd(dst, kScratchDoubleReg);

  bind(&f32tof16);
  // Convert Float32 -> Float16.
  vcvtps2ph(dst, dst, 4);
}

namespace {
template <typename OperandOrXMMRegister, bool is_double>
void ConvertFloatToUint64(MacroAssembler* masm, Register dst,
                          OperandOrXMMRegister src, Label* fail) {
  Label success;
  // There does not exist a native float-to-uint instruction, so we have to use
  // a float-to-int, and postprocess the result.
  if (is_double) {
    masm->Cvttsd2siq(dst, src);
  } else {
    masm->Cvttss2siq(dst, src);
  }
  // If the result of the conversion is positive, we are already done.
  masm->testq(dst, dst);
  masm->j(positive, &success);
  // The result of the first conversion was negative, which means that the
  // input value was not within the positive int64 range. We subtract 2^63
  // and convert it again to see if it is within the uint64 range.
  if (is_double) {
    masm->Move(kScratchDoubleReg, -9223372036854775808.0);
    masm->Addsd(kScratchDoubleReg, src);
    masm->Cvttsd2siq(dst, kScratchDoubleReg);
  } else {
    masm->Move(kScratchDoubleReg, -9223372036854775808.0f);
    masm->Addss(kScratchDoubleReg, src);
    masm->Cvttss2siq(dst, kScratchDoubleReg);
  }
  masm->testq(dst, dst);
  // The only possible negative value here is 0x8000000000000000, which is
  // used on x64 to indicate an integer overflow.
  masm->j(negative, fail ? fail : &success);
  // The input value is within uint64 range and the second conversion worked
  // successfully, but we still have to undo the subtraction we did
  // earlier.
  masm->Move(kScratchRegister, 0x8000000000000000);
  masm->orq(dst, kScratchRegister);
  masm->bind(&success);
}

template <typename OperandOrXMMRegister, bool is_double>
void ConvertFloatToUint32(MacroAssembler* masm, Register dst,
                          OperandOrXMMRegister src, Label* fail) {
  Label success;
  // There does not exist a native float-to-uint instruction, so we have to use
  // a float-to-int, and postprocess the result.
  if (is_double) {
    masm->Cvttsd2si(dst, src);
  } else {
    masm->Cvttss2si(dst, src);
  }
  // If the result of the conversion is positive, we are already done.
  masm->testl(dst, dst);
  masm->j(positive, &success);
  // The result of the first conversion was negative, which means that the
  // input value was not within the positive int32 range. We subtract 2^31
  // and convert it again to see if it is within the uint32 range.
  if (is_double) {
    masm->Move(kScratchDoubleReg, -2147483648.0);
    masm->Addsd(kScratchDoubleReg, src);
    masm->Cvttsd2si(dst, kScratchDoubleReg);
  } else {
    masm->Move(kScratchDoubleReg, -2147483648.0f);
    masm->Addss(kScratchDoubleReg, src);
    masm->Cvttss2si(dst, kScratchDoubleReg);
  }
  masm->testl(dst, dst);
  // The only possible negative value here is 0x80000000, which is
  // used on x64 to indicate an integer overflow.
  masm->j(negative, fail ? fail : &success);
  // The input value is within uint32 range and the second conversion worked
  // successfully, but we still have to undo the subtraction we did
  // earlier.
  masm->Move(kScratchRegister, 0x80000000);
  masm->orl(dst, kScratchRegister);
  masm->bind(&success);
}
}  // namespace

void MacroAssembler::Cvttsd2uiq(Register dst, Operand src, Label* fail) {
  ConvertFloatToUint64<Operand, true>(this, dst, src, fail);
}

void MacroAssembler::Cvttsd2uiq(Register dst, XMMRegister src, Label* fail) {
  ConvertFloatToUint64<XMMRegister, true>(this, dst, src, fail);
}

void MacroAssembler::Cvttsd2ui(Register dst, Operand src, Label* fail) {
  ConvertFloatToUint32<Operand, true>(this, dst, src, fail);
}

void MacroAssembler::Cvttsd2ui(Register dst, XMMRegister src, Label* fail) {
  ConvertFloatToUint32<XMMRegister, true>(this, dst, src, fail);
}

void MacroAssembler::Cvttss2uiq(Register dst, Operand src, Label* fail) {
  ConvertFloatToUint64<Operand, false>(this, dst, src, fail);
}

void MacroAssembler::Cvttss2uiq(Register dst, XMMRegister src, Label* fail) {
  ConvertFloatToUint64<XMMRegister, false>(this, dst, src, fail);
}

void MacroAssembler::Cvttss2ui(Register dst, Operand src, Label* fail) {
  ConvertFloatToUint32<Operand, false>(this, dst, src, fail);
}

void MacroAssembler::Cvttss2ui(Register dst, XMMRegister src, Label* fail) {
  ConvertFloatToUint32<XMMRegister, false>(this, dst, src, fail);
}

void MacroAssembler::Cmpeqss(XMMRegister dst, XMMRegister src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    vcmpeqss(dst, src);
  } else {
    cmpeqss(dst, src);
  }
}

void MacroAssembler::Cmpeqsd(XMMRegister dst, XMMRegister src) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope avx_scope(this, AVX);
    vcmpeqsd(dst, src);
  } else {
    cmpeqsd(dst, src);
  }
}

void MacroAssembler::S256Not(YMMRegister dst, YMMRegister src,
                             YMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  CpuFeatureScope avx2_scope(this, AVX2);
  if (dst == src) {
    vpcmpeqd(scratch, scratch, scratch);
    vpxor(dst, dst, scratch);
  } else {
    vpcmpeqd(dst, dst, dst);
    vpxor(dst, dst, src);
  }
}

void MacroAssembler::S256Select(YMMRegister dst, YMMRegister mask,
                                YMMRegister src1, YMMRegister src2,
                                YMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  CpuFeatureScope avx2_scope(this, AVX2);
  // v256.select = v256.or(v256.and(v1, c), v256.andnot(v2, c)).
  // pandn(x, y) = !x & y, so we have to flip the mask and input.
  vpandn(scratch, mask, src2);
  vpand(dst, src1, mask);
  vpor(dst, dst, scratch);
}

// ----------------------------------------------------------------------------
// Smi tagging, untagging and tag detection.

Register MacroAssembler::GetSmiConstant(Tagged<Smi> source) {
  Move(kScratchRegister, source);
  return kScratchRegister;
}

void MacroAssembler::Cmp(Register dst, int32_t src) {
  if (src == 0) {
    testl(dst, dst);
  } else {
    cmpl(dst, Immediate(src));
  }
}

void MacroAssembler::I64x4Mul(YMMRegister dst, YMMRegister lhs, YMMRegister rhs,
                              YMMRegister tmp1, YMMRegister tmp2) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(dst, tmp1, tmp2));
  DCHECK(!AreAliased(lhs, tmp1, tmp2));
  DCHECK(!AreAliased(rhs, tmp1, tmp2));
  DCHECK(CpuFeatures::IsSupported(AVX2));
  CpuFeatureScope avx_scope(this, AVX2);
  // 1. Multiply high dword of each qword of left with right.
  vpsrlq(t
"""


```