Response: The user wants to understand the functionality of the provided C++ code snippet, which is part of the `macro-assembler-arm64.cc` file in the V8 JavaScript engine. This is the second of three parts.

The code snippet seems to implement low-level assembly instructions and utility functions for the ARM64 architecture, specifically tailored for the V8 engine. It deals with memory access, function calls, object manipulation, and other architecture-specific operations necessary for JavaScript execution.

Since this is part 2, I should focus on the functionality present in this specific segment and avoid repeating details from part 1 (which I haven't seen, but I can infer general macro assembler functionalities).

Key functionalities observed in this part:
- Handling of tagged pointers and their decompression.
- Support for calling C functions and runtime functions.
- Stack frame management (prologue, epilogue, entering/leaving frames).
- Object type checking and manipulation.
- Support for weak references.
- Atomic operations on memory.
- Loading constants and roots from memory.
- Implementing conditional jumps and calls.
- Optimizations for different scenarios (e.g., static roots, compressed pointers).

To illustrate the connection with JavaScript, I can provide examples of how these low-level operations are used in the context of JavaScript execution.
这个C++代码片段（`v8/src/codegen/arm64/macro-assembler-arm64.cc` 的一部分）主要负责提供**操作带标记指针的原子操作和非原子操作，以及解压缩带标记指针的功能**。它还包含了一些**与对象类型判断相关的辅助函数**。

考虑到这是第二部分，我们可以推断第一部分可能包含了基础的寄存器操作、内存加载/存储等更基础的功能。这一部分则专注于处理V8中非常重要的**带标记指针**。

**带标记指针** 是V8用来表示JavaScript值的核心机制。为了区分值是对象指针还是小的整数（Smi），V8会在指针的低位设置标记。  `DecompressTagged` 等函数的作用就是去除这些标记，得到真正的内存地址。

以下是用JavaScript来说明这些功能可能在V8中如何使用的例子：

假设V8正在执行以下JavaScript代码：

```javascript
let a = { x: 10 };
let b = a.x;
```

当V8执行 `let a = { x: 10 };` 时：

1. V8会在堆上分配一个新的对象 `{ x: 10 }` 的内存。
2. `a` 变量会指向这个对象的**带标记的指针**。这个指针的低位可能被设置为表示这是一个堆对象。

当V8执行 `let b = a.x;` 时：

1. V8需要访问对象 `a` 的 `x` 属性。
2. 为了做到这一点，V8首先需要**解压缩** `a` 的带标记指针，以获得对象在内存中的真实地址。 `DecompressTagged` 系列的函数就用于完成这个任务。  在 `macro-assembler-arm64.cc` 中，你可以看到 `LoadTaggedField` 函数内部会调用 `DecompressTagged`，因为它需要加载对象字段的值，这些字段值也是带标记的。

3. 一旦获得了对象的真实地址，V8就可以计算出 `x` 属性在对象内存布局中的偏移量。
4. 然后，V8会加载该偏移量处的值。  由于 `x` 的值是整数 `10`，它可能被表示为一个 **Smi**（Small Integer，一种特殊的带标记的整数）。

   如果在后续的操作中需要将 `b` 用作一个普通的整数进行计算，V8可能需要 **去除 Smi 的标记**。虽然这个代码片段中没有直接展示去除 Smi 标记的操作，但在 V8 的其他部分会完成这个操作（例如，通过位运算）。

**原子操作** 在多线程 JavaScript 环境中至关重要。  当多个线程同时访问和修改共享的 JavaScript 对象时，需要确保操作的原子性，避免数据竞争。  `AtomicStoreTaggedField` 和 `AtomicDecompressTagged` 等函数就提供了这种能力，确保对带标记指针的读写操作是不可中断的。

例如，考虑一个使用了 `SharedArrayBuffer` 的多线程 JavaScript 应用：

```javascript
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
const view = new Int32Array(sab);

// 线程 1
Atomics.add(view, 0, 5);

// 线程 2
console.log(Atomics.load(view, 0));
```

在上面的例子中，`Atomics.add` 和 `Atomics.load` 在底层就可能使用类似 `AtomicStoreTaggedField` 和 `AtomicDecompressTagged` 的原子操作，来安全地修改和读取 `SharedArrayBuffer` 中的数据，即使在多个线程并发执行的情况下。虽然 `SharedArrayBuffer` 中存储的是原始数据类型，但 V8 内部的某些操作，尤其是涉及到对象头和属性的修改，仍然可能需要原子操作来保证一致性。

总而言之，这个代码片段是 V8 引擎实现其核心值表示和并发控制的关键部分，为高效且线程安全的 JavaScript 执行提供了底层的构建块。

### 提示词
```
这是目录为v8/src/codegen/arm64/macro-assembler-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```
cting 0.0 preserves all inputs except for signalling NaNs, which
  // become quiet NaNs. We use fsub rather than fadd because fsub preserves -0.0
  // inputs: -0.0 + 0.0 = 0.0, but -0.0 - 0.0 = -0.0.
  Fsub(dst, src, fp_zero);
}

void MacroAssembler::LoadTaggedRoot(Register destination, RootIndex index) {
  ASM_CODE_COMMENT(this);
  if (CanBeImmediate(index)) {
    Mov(destination,
        Immediate(ReadOnlyRootPtr(index), RelocInfo::Mode::NO_INFO));
    return;
  }
  LoadRoot(destination, index);
}

void MacroAssembler::LoadRoot(Register destination, RootIndex index) {
  ASM_CODE_COMMENT(this);
  if (V8_STATIC_ROOTS_BOOL && RootsTable::IsReadOnly(index) &&
      IsImmAddSub(ReadOnlyRootPtr(index))) {
    DecompressTagged(destination, ReadOnlyRootPtr(index));
    return;
  }
  // Many roots have addresses that are too large to fit into addition immediate
  // operands. Evidence suggests that the extra instruction for decompression
  // costs us more than the load.
  Ldr(destination,
      MemOperand(kRootRegister, RootRegisterOffsetForRootIndex(index)));
}

void MacroAssembler::PushRoot(RootIndex index) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register tmp = temps.AcquireX();
  LoadRoot(tmp, index);
  Push(tmp);
}

void MacroAssembler::Move(Register dst, Tagged<Smi> src) { Mov(dst, src); }
void MacroAssembler::Move(Register dst, MemOperand src) { Ldr(dst, src); }
void MacroAssembler::Move(Register dst, Register src) {
  if (dst == src) return;
  Mov(dst, src);
}

void MacroAssembler::MovePair(Register dst0, Register src0, Register dst1,
                              Register src1) {
  DCHECK_NE(dst0, dst1);
  if (dst0 != src1) {
    Mov(dst0, src0);
    Mov(dst1, src1);
  } else if (dst1 != src0) {
    // Swap the order of the moves to resolve the overlap.
    Mov(dst1, src1);
    Mov(dst0, src0);
  } else {
    // Worse case scenario, this is a swap.
    Swap(dst0, src0);
  }
}

void MacroAssembler::Swap(Register lhs, Register rhs) {
  DCHECK(lhs.IsSameSizeAndType(rhs));
  DCHECK_NE(lhs, rhs);
  UseScratchRegisterScope temps(this);
  Register temp = temps.AcquireX();
  Mov(temp, rhs);
  Mov(rhs, lhs);
  Mov(lhs, temp);
}

void MacroAssembler::Swap(VRegister lhs, VRegister rhs) {
  DCHECK(lhs.IsSameSizeAndType(rhs));
  DCHECK_NE(lhs, rhs);
  UseScratchRegisterScope temps(this);
  VRegister temp = VRegister::no_reg();
  if (lhs.IsS()) {
    temp = temps.AcquireS();
  } else if (lhs.IsD()) {
    temp = temps.AcquireD();
  } else {
    DCHECK(lhs.IsQ());
    temp = temps.AcquireQ();
  }
  Mov(temp, rhs);
  Mov(rhs, lhs);
  Mov(lhs, temp);
}

void MacroAssembler::CallRuntime(const Runtime::Function* f,
                                 int num_arguments) {
  ASM_CODE_COMMENT(this);
  // All arguments must be on the stack before this function is called.
  // x0 holds the return value after the call.

  // Check that the number of arguments matches what the function expects.
  // If f->nargs is -1, the function can accept a variable number of arguments.
  CHECK(f->nargs < 0 || f->nargs == num_arguments);

  // Place the necessary arguments.
  Mov(x0, num_arguments);
  Mov(x1, ExternalReference::Create(f));

  bool switch_to_central = options().is_wasm;
  CallBuiltin(Builtins::RuntimeCEntry(f->result_size, switch_to_central));
}

void MacroAssembler::JumpToExternalReference(const ExternalReference& builtin,
                                             bool builtin_exit_frame) {
  ASM_CODE_COMMENT(this);
  Mov(x1, builtin);
  TailCallBuiltin(Builtins::CEntry(1, ArgvMode::kStack, builtin_exit_frame));
}

void MacroAssembler::TailCallRuntime(Runtime::FunctionId fid) {
  ASM_CODE_COMMENT(this);
  const Runtime::Function* function = Runtime::FunctionForId(fid);
  DCHECK_EQ(1, function->result_size);
  if (function->nargs >= 0) {
    // TODO(1236192): Most runtime routines don't need the number of
    // arguments passed in because it is constant. At some point we
    // should remove this need and make the runtime routine entry code
    // smarter.
    Mov(x0, function->nargs);
  }
  JumpToExternalReference(ExternalReference::Create(fid));
}

int MacroAssembler::ActivationFrameAlignment() {
#if V8_HOST_ARCH_ARM64
  // Running on the real platform. Use the alignment as mandated by the local
  // environment.
  // Note: This will break if we ever start generating snapshots on one ARM
  // platform for another ARM platform with a different alignment.
  return base::OS::ActivationFrameAlignment();
#else   // V8_HOST_ARCH_ARM64
  // If we are using the simulator then we should always align to the expected
  // alignment. As the simulator is used to generate snapshots we do not know
  // if the target platform will need alignment, so this is controlled from a
  // flag.
  return v8_flags.sim_stack_alignment;
#endif  // V8_HOST_ARCH_ARM64
}

int MacroAssembler::CallCFunction(ExternalReference function,
                                  int num_of_reg_args,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  return CallCFunction(function, num_of_reg_args, 0, set_isolate_data_slots,
                       return_location);
}

int MacroAssembler::CallCFunction(ExternalReference function,
                                  int num_of_reg_args, int num_of_double_args,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  // Note: The "CallCFunction" code comment will be generated by the other
  // CallCFunction method called below.
  UseScratchRegisterScope temps(this);
  Register temp = temps.AcquireX();
  Mov(temp, function);
  return CallCFunction(temp, num_of_reg_args, num_of_double_args,
                       set_isolate_data_slots, return_location);
}

int MacroAssembler::CallCFunction(Register function, int num_of_reg_args,
                                  int num_of_double_args,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  ASM_CODE_COMMENT(this);
  DCHECK_LE(num_of_reg_args + num_of_double_args, kMaxCParameters);
  DCHECK(has_frame());

  Label get_pc;
  UseScratchRegisterScope temps(this);
  // We're doing a C call, which means non-parameter caller-saved registers
  // (x8-x17) will be clobbered and so are available to use as scratches.
  // In the worst-case scenario, we'll need 2 scratch registers. We pick 3
  // registers minus the `function` register, in case `function` aliases with
  // any of the registers.
  temps.Include(CPURegList(64, {x8, x9, x10, function}));
  temps.Exclude(function);

  if (set_isolate_data_slots == SetIsolateDataSlots::kYes) {
    // Save the frame pointer and PC so that the stack layout remains iterable,
    // even without an ExitFrame which normally exists between JS and C frames.
    UseScratchRegisterScope temps(this);
    Register pc_scratch = temps.AcquireX();

    Adr(pc_scratch, &get_pc);

    CHECK(root_array_available());
    static_assert(IsolateData::GetOffset(IsolateFieldId::kFastCCallCallerPC) ==
                  IsolateData::GetOffset(IsolateFieldId::kFastCCallCallerFP) +
                      8);
    Stp(fp, pc_scratch,
        ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP));
  }

  // Call directly. The function called cannot cause a GC, or allow preemption,
  // so the return address in the link register stays correct.
  Call(function);
  int call_pc_offset = pc_offset();
  bind(&get_pc);
  if (return_location) bind(return_location);

  if (set_isolate_data_slots == SetIsolateDataSlots::kYes) {
    // We don't unset the PC; the FP is the source of truth.
    Str(xzr, ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP));
  }

  if (num_of_reg_args > kRegisterPassedArguments) {
    // Drop the register passed arguments.
    int claim_slots = RoundUp(num_of_reg_args - kRegisterPassedArguments, 2);
    Drop(claim_slots);
  }

  if (num_of_double_args > kFPRegisterPassedArguments) {
    // Drop the register passed arguments.
    int claim_slots =
        RoundUp(num_of_double_args - kFPRegisterPassedArguments, 2);
    Drop(claim_slots);
  }

  return call_pc_offset;
}

void MacroAssembler::LoadFromConstantsTable(Register destination,
                                            int constant_index) {
  ASM_CODE_COMMENT(this);
  DCHECK(RootsTable::IsImmortalImmovable(RootIndex::kBuiltinsConstantsTable));
  LoadRoot(destination, RootIndex::kBuiltinsConstantsTable);
  LoadTaggedField(destination,
                  FieldMemOperand(destination, FixedArray::OffsetOfElementAt(
                                                   constant_index)));
}

void MacroAssembler::LoadRootRelative(Register destination, int32_t offset) {
  Ldr(destination, MemOperand(kRootRegister, offset));
}

void MacroAssembler::StoreRootRelative(int32_t offset, Register value) {
  Str(value, MemOperand(kRootRegister, offset));
}

void MacroAssembler::LoadRootRegisterOffset(Register destination,
                                            intptr_t offset) {
  if (offset == 0) {
    Mov(destination, kRootRegister);
  } else {
    Add(destination, kRootRegister, offset);
  }
}

MemOperand MacroAssembler::ExternalReferenceAsOperand(
    ExternalReference reference, Register scratch) {
  if (root_array_available()) {
    if (reference.IsIsolateFieldId()) {
      return MemOperand(kRootRegister, reference.offset_from_root_register());
    }
    if (options().enable_root_relative_access) {
      intptr_t offset =
          RootRegisterOffsetForExternalReference(isolate(), reference);
      if (is_int32(offset)) {
        return MemOperand(kRootRegister, static_cast<int32_t>(offset));
      }
    }
    if (options().isolate_independent_code) {
      if (IsAddressableThroughRootRegister(isolate(), reference)) {
        // Some external references can be efficiently loaded as an offset from
        // kRootRegister.
        intptr_t offset =
            RootRegisterOffsetForExternalReference(isolate(), reference);
        CHECK(is_int32(offset));
        return MemOperand(kRootRegister, static_cast<int32_t>(offset));
      } else {
        // Otherwise, do a memory load from the external reference table.
        Ldr(scratch,
            MemOperand(kRootRegister,
                       RootRegisterOffsetForExternalReferenceTableEntry(
                           isolate(), reference)));
        return MemOperand(scratch, 0);
      }
    }
  }
  Mov(scratch, reference);
  return MemOperand(scratch, 0);
}

void MacroAssembler::Jump(Register target, Condition cond) {
  if (cond == nv) return;
  Label done;
  if (cond != al) B(NegateCondition(cond), &done);
  Br(target);
  Bind(&done);
}

void MacroAssembler::JumpHelper(int64_t offset, RelocInfo::Mode rmode,
                                Condition cond) {
  if (cond == nv) return;
  Label done;
  if (cond != al) B(NegateCondition(cond), &done);
  if (CanUseNearCallOrJump(rmode)) {
    DCHECK(IsNearCallOffset(offset));
    near_jump(static_cast<int>(offset), rmode);
  } else {
    UseScratchRegisterScope temps(this);
    Register temp = temps.AcquireX();
    uint64_t imm = reinterpret_cast<uint64_t>(pc_) + offset * kInstrSize;
    Mov(temp, Immediate(imm, rmode));
    Br(temp);
  }
  Bind(&done);
}

// The calculated offset is either:
// * the 'target' input unmodified if this is a Wasm call, or
// * the offset of the target from the current PC, in instructions, for any
//   other type of call.
// static
int64_t MacroAssembler::CalculateTargetOffset(Address target,
                                              RelocInfo::Mode rmode,
                                              uint8_t* pc) {
  int64_t offset = static_cast<int64_t>(target);
  if (rmode == RelocInfo::WASM_CALL || rmode == RelocInfo::WASM_STUB_CALL) {
    // The target of WebAssembly calls is still an index instead of an actual
    // address at this point, and needs to be encoded as-is.
    return offset;
  }
  offset -= reinterpret_cast<int64_t>(pc);
  DCHECK_EQ(offset % kInstrSize, 0);
  offset = offset / static_cast<int>(kInstrSize);
  return offset;
}

void MacroAssembler::Jump(Address target, RelocInfo::Mode rmode,
                          Condition cond) {
  int64_t offset = CalculateTargetOffset(target, rmode, pc_);
  JumpHelper(offset, rmode, cond);
}

void MacroAssembler::Jump(Handle<Code> code, RelocInfo::Mode rmode,
                          Condition cond) {
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  DCHECK_IMPLIES(options().isolate_independent_code,
                 Builtins::IsIsolateIndependentBuiltin(*code));

  Builtin builtin = Builtin::kNoBuiltinId;
  if (isolate()->builtins()->IsBuiltinHandle(code, &builtin)) {
    TailCallBuiltin(builtin, cond);
    return;
  }
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  if (CanUseNearCallOrJump(rmode)) {
    EmbeddedObjectIndex index = AddEmbeddedObject(code);
    DCHECK(is_int32(index));
    JumpHelper(static_cast<int64_t>(index), rmode, cond);
  } else {
    Jump(code.address(), rmode, cond);
  }
}

void MacroAssembler::Jump(const ExternalReference& reference) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();
  Mov(scratch, reference);
  Jump(scratch);
}

void MacroAssembler::Call(Register target) {
  BlockPoolsScope scope(this);
  Blr(target);
}

void MacroAssembler::Call(Address target, RelocInfo::Mode rmode) {
  BlockPoolsScope scope(this);
  if (CanUseNearCallOrJump(rmode)) {
    int64_t offset = CalculateTargetOffset(target, rmode, pc_);
    DCHECK(IsNearCallOffset(offset));
    near_call(static_cast<int>(offset), rmode);
  } else {
    IndirectCall(target, rmode);
  }
}

void MacroAssembler::Call(Handle<Code> code, RelocInfo::Mode rmode) {
  DCHECK_IMPLIES(options().isolate_independent_code,
                 Builtins::IsIsolateIndependentBuiltin(*code));
  BlockPoolsScope scope(this);

  Builtin builtin = Builtin::kNoBuiltinId;
  if (isolate()->builtins()->IsBuiltinHandle(code, &builtin)) {
    CallBuiltin(builtin);
    return;
  }

  DCHECK(RelocInfo::IsCodeTarget(rmode));

  if (CanUseNearCallOrJump(rmode)) {
    EmbeddedObjectIndex index = AddEmbeddedObject(code);
    DCHECK(is_int32(index));
    near_call(static_cast<int32_t>(index), rmode);
  } else {
    IndirectCall(code.address(), rmode);
  }
}

void MacroAssembler::Call(ExternalReference target) {
  UseScratchRegisterScope temps(this);
  Register temp = temps.AcquireX();
  Mov(temp, target);
  Call(temp);
}

void MacroAssembler::LoadEntryFromBuiltinIndex(Register builtin_index,
                                               Register target) {
  ASM_CODE_COMMENT(this);
  // The builtin_index register contains the builtin index as a Smi.
  if (SmiValuesAre32Bits()) {
    Asr(target, builtin_index, kSmiShift - kSystemPointerSizeLog2);
    Add(target, target, IsolateData::builtin_entry_table_offset());
    Ldr(target, MemOperand(kRootRegister, target));
  } else {
    DCHECK(SmiValuesAre31Bits());
    if (COMPRESS_POINTERS_BOOL) {
      Add(target, kRootRegister,
          Operand(builtin_index.W(), SXTW, kSystemPointerSizeLog2 - kSmiShift));
    } else {
      Add(target, kRootRegister,
          Operand(builtin_index, LSL, kSystemPointerSizeLog2 - kSmiShift));
    }
    Ldr(target, MemOperand(target, IsolateData::builtin_entry_table_offset()));
  }
}

void MacroAssembler::LoadEntryFromBuiltin(Builtin builtin,
                                          Register destination) {
  Ldr(destination, EntryFromBuiltinAsOperand(builtin));
}

MemOperand MacroAssembler::EntryFromBuiltinAsOperand(Builtin builtin) {
  ASM_CODE_COMMENT(this);
  DCHECK(root_array_available());
  return MemOperand(kRootRegister,
                    IsolateData::BuiltinEntrySlotOffset(builtin));
}

void MacroAssembler::CallBuiltinByIndex(Register builtin_index,
                                        Register target) {
  ASM_CODE_COMMENT(this);
  LoadEntryFromBuiltinIndex(builtin_index, target);
  Call(target);
}

void MacroAssembler::CallBuiltin(Builtin builtin) {
  ASM_CODE_COMMENT_STRING(this, CommentForOffHeapTrampoline("call", builtin));
  switch (options().builtin_call_jump_mode) {
    case BuiltinCallJumpMode::kAbsolute: {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.AcquireX();
      Ldr(scratch, Operand(BuiltinEntry(builtin), RelocInfo::OFF_HEAP_TARGET));
      Call(scratch);
      break;
    }
    case BuiltinCallJumpMode::kPCRelative:
      near_call(static_cast<int>(builtin), RelocInfo::NEAR_BUILTIN_ENTRY);
      break;
    case BuiltinCallJumpMode::kIndirect: {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.AcquireX();
      LoadEntryFromBuiltin(builtin, scratch);
      Call(scratch);
      break;
    }
    case BuiltinCallJumpMode::kForMksnapshot: {
      if (options().use_pc_relative_calls_and_jumps_for_mksnapshot) {
        Handle<Code> code = isolate()->builtins()->code_handle(builtin);
        EmbeddedObjectIndex index = AddEmbeddedObject(code);
        DCHECK(is_int32(index));
        near_call(static_cast<int32_t>(index), RelocInfo::CODE_TARGET);
      } else {
        UseScratchRegisterScope temps(this);
        Register scratch = temps.AcquireX();
        LoadEntryFromBuiltin(builtin, scratch);
        Call(scratch);
      }
      break;
    }
  }
}

// TODO(ishell): remove cond parameter from here to simplify things.
void MacroAssembler::TailCallBuiltin(Builtin builtin, Condition cond) {
  ASM_CODE_COMMENT_STRING(this,
                          CommentForOffHeapTrampoline("tail call", builtin));

  // The control flow integrity (CFI) feature allows us to "sign" code entry
  // points as a target for calls, jumps or both. Arm64 has special
  // instructions for this purpose, so-called "landing pads" (see
  // MacroAssembler::CallTarget(), MacroAssembler::JumpTarget() and
  // MacroAssembler::JumpOrCallTarget()). Currently, we generate "Call"
  // landing pads for CPP builtins. In order to allow tail calling to those
  // builtins we have to use a workaround.
  // x17 is used to allow using "Call" (i.e. `bti c`) rather than "Jump"
  // (i.e. `bti j`) landing pads for the tail-called code.
  Register temp = x17;

  switch (options().builtin_call_jump_mode) {
    case BuiltinCallJumpMode::kAbsolute: {
      Ldr(temp, Operand(BuiltinEntry(builtin), RelocInfo::OFF_HEAP_TARGET));
      Jump(temp, cond);
      break;
    }
    case BuiltinCallJumpMode::kPCRelative: {
      if (cond != nv) {
        Label done;
        if (cond != al) B(NegateCondition(cond), &done);
        near_jump(static_cast<int>(builtin), RelocInfo::NEAR_BUILTIN_ENTRY);
        Bind(&done);
      }
      break;
    }
    case BuiltinCallJumpMode::kIndirect: {
      LoadEntryFromBuiltin(builtin, temp);
      Jump(temp, cond);
      break;
    }
    case BuiltinCallJumpMode::kForMksnapshot: {
      if (options().use_pc_relative_calls_and_jumps_for_mksnapshot) {
        Handle<Code> code = isolate()->builtins()->code_handle(builtin);
        EmbeddedObjectIndex index = AddEmbeddedObject(code);
        DCHECK(is_int32(index));
        JumpHelper(static_cast<int64_t>(index), RelocInfo::CODE_TARGET, cond);
      } else {
        LoadEntryFromBuiltin(builtin, temp);
        Jump(temp, cond);
      }
      break;
    }
  }
}

void MacroAssembler::LoadCodeInstructionStart(Register destination,
                                              Register code_object,
                                              CodeEntrypointTag tag) {
  ASM_CODE_COMMENT(this);
#ifdef V8_ENABLE_SANDBOX
  LoadCodeEntrypointViaCodePointer(
      destination,
      FieldMemOperand(code_object, Code::kSelfIndirectPointerOffset), tag);
#else
  Ldr(destination, FieldMemOperand(code_object, Code::kInstructionStartOffset));
#endif
}

void MacroAssembler::CallCodeObject(Register code_object,
                                    CodeEntrypointTag tag) {
  ASM_CODE_COMMENT(this);
  LoadCodeInstructionStart(code_object, code_object, tag);
  Call(code_object);
}

void MacroAssembler::JumpCodeObject(Register code_object, CodeEntrypointTag tag,
                                    JumpMode jump_mode) {
  // TODO(saelo): can we avoid using this for JavaScript functions
  // (kJSEntrypointTag) and instead use a variant that ensures that the caller
  // and callee agree on the signature (i.e. parameter count)?
  ASM_CODE_COMMENT(this);
  DCHECK_EQ(JumpMode::kJump, jump_mode);
  LoadCodeInstructionStart(code_object, code_object, tag);
  // We jump through x17 here because for Branch Identification (BTI) we use
  // "Call" (`bti c`) rather than "Jump" (`bti j`) landing pads for tail-called
  // code. See TailCallBuiltin for more information.
  if (code_object != x17) {
    Mov(x17, code_object);
  }
  Jump(x17);
}

void MacroAssembler::CallJSFunction(Register function_object,
                                    uint16_t argument_count) {
  Register code = kJavaScriptCallCodeStartRegister;
#if V8_ENABLE_LEAPTIERING
  Register dispatch_handle = kJavaScriptCallDispatchHandleRegister;
  Register parameter_count = x20;
  Register scratch = x21;

  Ldr(dispatch_handle.W(),
      FieldMemOperand(function_object, JSFunction::kDispatchHandleOffset));
  LoadEntrypointAndParameterCountFromJSDispatchTable(code, parameter_count,
                                                     dispatch_handle, scratch);
  // Force a safe crash if the parameter count doesn't match.
  Cmp(parameter_count, Immediate(argument_count));
  SbxCheck(le, AbortReason::kJSSignatureMismatch);
  Call(code);
#elif V8_ENABLE_SANDBOX
  // When the sandbox is enabled, we can directly fetch the entrypoint pointer
  // from the code pointer table instead of going through the Code object. In
  // this way, we avoid one memory load on this code path.
  LoadCodeEntrypointViaCodePointer(
      code, FieldMemOperand(function_object, JSFunction::kCodeOffset),
      kJSEntrypointTag);
  Call(code);
#else
  LoadTaggedField(code,
                  FieldMemOperand(function_object, JSFunction::kCodeOffset));
  CallCodeObject(code, kJSEntrypointTag);
#endif
}

void MacroAssembler::JumpJSFunction(Register function_object,
                                    JumpMode jump_mode) {
  Register code = kJavaScriptCallCodeStartRegister;
#if V8_ENABLE_LEAPTIERING
  Register dispatch_handle = kJavaScriptCallDispatchHandleRegister;
  Register scratch = x20;
  Ldr(dispatch_handle.W(),
      FieldMemOperand(function_object, JSFunction::kDispatchHandleOffset));
  LoadEntrypointFromJSDispatchTable(code, dispatch_handle, scratch);
  DCHECK_EQ(jump_mode, JumpMode::kJump);
  // We jump through x17 here because for Branch Identification (BTI) we use
  // "Call" (`bti c`) rather than "Jump" (`bti j`) landing pads for tail-called
  // code. See TailCallBuiltin for more information.
  DCHECK_NE(code, x17);
  Mov(x17, code);
  Jump(x17);
  // This implementation is not currently used because callers usually need
  // to load both entry point and parameter count and then do something with
  // the latter before the actual call.
  // TODO(ishell): remove the above code once it's clear it's not needed.
  UNREACHABLE();
#elif V8_ENABLE_SANDBOX
  // When the sandbox is enabled, we can directly fetch the entrypoint pointer
  // from the code pointer table instead of going through the Code object. In
  // this way, we avoid one memory load on this code path.
  LoadCodeEntrypointViaCodePointer(
      code, FieldMemOperand(function_object, JSFunction::kCodeOffset),
      kJSEntrypointTag);
  DCHECK_EQ(jump_mode, JumpMode::kJump);
  // We jump through x17 here because for Branch Identification (BTI) we use
  // "Call" (`bti c`) rather than "Jump" (`bti j`) landing pads for tail-called
  // code. See TailCallBuiltin for more information.
  DCHECK_NE(code, x17);
  Mov(x17, code);
  Jump(x17);
#else
  LoadTaggedField(code,
                  FieldMemOperand(function_object, JSFunction::kCodeOffset));
  JumpCodeObject(code, kJSEntrypointTag, jump_mode);
#endif
}

void MacroAssembler::ResolveWasmCodePointer(Register target) {
#ifdef V8_ENABLE_WASM_CODE_POINTER_TABLE
  ExternalReference global_jump_table =
      ExternalReference::wasm_code_pointer_table();
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();
  Mov(scratch, global_jump_table);
  static_assert(sizeof(wasm::WasmCodePointerTableEntry) == kSystemPointerSize);
  lsl(target.W(), target.W(), kSystemPointerSizeLog2);
  Ldr(target, MemOperand(scratch, target));
#endif
}

void MacroAssembler::CallWasmCodePointer(Register target,
                                         CallJumpMode call_jump_mode) {
  ResolveWasmCodePointer(target);
  if (call_jump_mode == CallJumpMode::kTailCall) {
    Jump(target);
  } else {
    Call(target);
  }
}

void MacroAssembler::LoadWasmCodePointer(Register dst, MemOperand src) {
  if constexpr (V8_ENABLE_WASM_CODE_POINTER_TABLE_BOOL) {
    static_assert(!V8_ENABLE_WASM_CODE_POINTER_TABLE_BOOL ||
                  sizeof(WasmCodePointer) == 4);
    Ldr(dst.W(), src);
  } else {
    static_assert(V8_ENABLE_WASM_CODE_POINTER_TABLE_BOOL ||
                  sizeof(WasmCodePointer) == 8);
    Ldr(dst, src);
  }
}

void MacroAssembler::StoreReturnAddressAndCall(Register target) {
  ASM_CODE_COMMENT(this);
  // This generates the final instruction sequence for calls to C functions
  // once an exit frame has been constructed.
  //
  // Note that this assumes the caller code (i.e. the InstructionStream object
  // currently being generated) is immovable or that the callee function cannot
  // trigger GC, since the callee function will return to it.

  UseScratchRegisterScope temps(this);
  temps.Exclude(x16, x17);
  DCHECK(!AreAliased(x16, x17, target));

  Label return_location;
  Adr(x17, &return_location);
#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
  Add(x16, sp, kSystemPointerSize);
  Pacib1716();
#endif
  Str(x17, MemOperand(sp));

  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT_STRING(this, "Verify fp[kSPOffset]-8");
    // Verify that the slot below fp[kSPOffset]-8 points to the signed return
    // location.
    Ldr(x16, MemOperand(fp, ExitFrameConstants::kSPOffset));
    Ldr(x16, MemOperand(x16, -static_cast<int64_t>(kXRegSize)));
    Cmp(x16, x17);
    Check(eq, AbortReason::kReturnAddressNotFoundInFrame);
  }

  Blr(target);
  Bind(&return_location);
}

void MacroAssembler::IndirectCall(Address target, RelocInfo::Mode rmode) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register temp = temps.AcquireX();
  Mov(temp, Immediate(target, rmode));
  Blr(temp);
}

bool MacroAssembler::IsNearCallOffset(int64_t offset) {
  return is_int26(offset);
}

// Check if the code object is marked for deoptimization. If it is, then it
// jumps to the CompileLazyDeoptimizedCode builtin. In order to do this we need
// to:
//    1. read from memory the word that contains that bit, which can be found in
//       the flags in the referenced {Code} object;
//    2. test kMarkedForDeoptimizationBit in those flags; and
//    3. if it is not zero then it jumps to the builtin.
void MacroAssembler::BailoutIfDeoptimized() {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();
  int offset = InstructionStream::kCodeOffset - InstructionStream::kHeaderSize;
  LoadProtectedPointerField(
      scratch, MemOperand(kJavaScriptCallCodeStartRegister, offset));
  Ldr(scratch.W(), FieldMemOperand(scratch, Code::kFlagsOffset));
  Label not_deoptimized;
  Tbz(scratch.W(), Code::kMarkedForDeoptimizationBit, &not_deoptimized);
  TailCallBuiltin(Builtin::kCompileLazyDeoptimizedCode);
  Bind(&not_deoptimized);
}

void MacroAssembler::CallForDeoptimization(
    Builtin target, int deopt_id, Label* exit, DeoptimizeKind kind, Label* ret,
    Label* jump_deoptimization_entry_label) {
  ASM_CODE_COMMENT(this);
  BlockPoolsScope scope(this);
  bl(jump_deoptimization_entry_label);
  DCHECK_EQ(SizeOfCodeGeneratedSince(exit),
            (kind == DeoptimizeKind::kLazy) ? Deoptimizer::kLazyDeoptExitSize
                                            : Deoptimizer::kEagerDeoptExitSize);
}

void MacroAssembler::LoadStackLimit(Register destination, StackLimitKind kind) {
  ASM_CODE_COMMENT(this);
  DCHECK(root_array_available());
  intptr_t offset = kind == StackLimitKind::kRealStackLimit
                        ? IsolateData::real_jslimit_offset()
                        : IsolateData::jslimit_offset();

  Ldr(destination, MemOperand(kRootRegister, offset));
}

void MacroAssembler::StackOverflowCheck(Register num_args,
                                        Label* stack_overflow) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();

  // Check the stack for overflow.
  // We are not trying to catch interruptions (e.g. debug break and
  // preemption) here, so the "real stack limit" is checked.

  LoadStackLimit(scratch, StackLimitKind::kRealStackLimit);
  // Make scratch the space we have left. The stack might already be overflowed
  // here which will cause scratch to become negative.
  Sub(scratch, sp, scratch);
  // Check if the arguments will overflow the stack.
  Cmp(scratch, Operand(num_args, LSL, kSystemPointerSizeLog2));
  B(le, stack_overflow);
}

void MacroAssembler::InvokePrologue(Register formal_parameter_count,
                                    Register actual_argument_count,
                                    InvokeType type) {
  ASM_CODE_COMMENT(this);
  //  x0: actual arguments count.
  //  x1: function (passed through to callee).
  //  x2: expected arguments count.
  //  x3: new target
  Label regular_invoke;
  DCHECK_EQ(actual_argument_count, x0);
  DCHECK_EQ(formal_parameter_count, x2);

  // If overapplication or if the actual argument count is equal to the
  // formal parameter count, no need to push extra undefined values.
  Register extra_argument_count = x2;
  Subs(extra_argument_count, formal_parameter_count, actual_argument_count);
  B(le, &regular_invoke);

  // The stack pointer in arm64 needs to be 16-byte aligned. We might need to
  // (1) add an extra padding or (2) remove (re-use) the extra padding already
  // in the stack. Let {slots_to_copy} be the number of slots (arguments) to
  // move up in the stack and let {slots_to_claim} be the number of extra stack
  // slots to claim.
  Label even_extra_count, skip_move;
  Register slots_to_copy = x5;
  Register slots_to_claim = x6;

  Mov(slots_to_copy, actual_argument_count);
  Mov(slots_to_claim, extra_argument_count);
  Tbz(extra_argument_count, 0, &even_extra_count);

  // Calculate {slots_to_claim} when {extra_argument_count} is odd.
  // If {actual_argument_count} is even, we need one extra padding slot
  // {slots_to_claim = extra_argument_count + 1}.
  // If {actual_argument_count} is odd, we know that the
  // original arguments will have a padding slot that we can reuse
  // {slots_to_claim = extra_argument_count - 1}.
  {
    Register scratch = x11;
    Add(slots_to_claim, extra_argument_count, 1);
    And(scratch, actual_argument_count, 1);
    Sub(slots_to_claim, slots_to_claim, Operand(scratch, LSL, 1));
  }

  Bind(&even_extra_count);
  Cbz(slots_to_claim, &skip_move);

  Label stack_overflow;
  StackOverflowCheck(slots_to_claim, &stack_overflow);
  Claim(slots_to_claim);

  // Move the arguments already in the stack including the receiver.
  {
    Register src = x7;
    Register dst = x8;
    SlotAddress(src, slots_to_claim);
    SlotAddress(dst, 0);
    CopyDoubleWords(dst, src, slots_to_copy);
  }

  Bind(&skip_move);
  Register pointer_next_value = x6;

  // Copy extra arguments as undefined values.
  {
    Label loop;
    Register undefined_value = x7;
    Register count = x8;
    LoadRoot(undefined_value, RootIndex::kUndefinedValue);
    SlotAddress(pointer_next_value, actual_argument_count);
    Mov(count, extra_argument_count);
    Bind(&loop);
    Str(undefined_value,
        MemOperand(pointer_next_value, kSystemPointerSize, PostIndex));
    Subs(count, count, 1);
    Cbnz(count, &loop);
  }

  // Set padding if needed.
  {
    Label skip;
    Register total_args_slots = x5;
    Add(total_args_slots, actual_argument_count, extra_argument_count);
    Tbz(total_args_slots, 0, &skip);
    Str(padreg, MemOperand(pointer_next_value));
    Bind(&skip);
  }
  B(&regular_invoke);

  bind(&stack_overflow);
  {
    FrameScope frame(
        this, has_frame() ? StackFrame::NO_FRAME_TYPE : StackFrame::INTERNAL);
    CallRuntime(Runtime::kThrowStackOverflow);
    Unreachable();
  }

  Bind(&regular_invoke);
}

void MacroAssembler::CallDebugOnFunctionCall(
    Register fun, Register new_target,
    Register expected_parameter_count_or_dispatch_handle,
    Register actual_parameter_count) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(x5, fun, new_target,
                     expected_parameter_count_or_dispatch_handle,
                     actual_parameter_count));
  // Load receiver to pass it later to DebugOnFunctionCall hook.
  Peek(x5, ReceiverOperand());
  FrameScope frame(
      this, has_frame() ? StackFrame::NO_FRAME_TYPE : StackFrame::INTERNAL);

  if (!new_target.is_valid()) new_target = padreg;

  // Save values on stack.
  SmiTag(expected_parameter_count_or_dispatch_handle);
  SmiTag(actual_parameter_count);
  Push(expected_parameter_count_or_dispatch_handle, actual_parameter_count,
       new_target, fun);
  Push(fun, x5);
  CallRuntime(Runtime::kDebugOnFunctionCall);

  // Restore values from stack.
  Pop(fun, new_target, actual_parameter_count,
      expected_parameter_count_or_dispatch_handle);
  SmiUntag(actual_parameter_count);
  SmiUntag(expected_parameter_count_or_dispatch_handle);
}

#ifdef V8_ENABLE_LEAPTIERING
void MacroAssembler::InvokeFunction(
    Register function, Register actual_parameter_count, InvokeType type,
    ArgumentAdaptionMode argument_adaption_mode) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK(type == InvokeType::kJump || has_frame());

  // Contract with called JS functions requires that function is passed in x1.
  // (See FullCodeGenerator::Generate().)
  DCHECK_EQ(function, x1);

  // Set up the context.
  LoadTaggedField(cp, FieldMemOperand(function, JSFunction::kContextOffset));

  InvokeFunctionCode(function, no_reg, actual_parameter_count, type,
                     argument_adaption_mode);
}

void MacroAssembler::InvokeFunctionWithNewTarget(
    Register function, Register new_target, Register actual_parameter_count,
    InvokeType type) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK(type == InvokeType::kJump || has_frame());

  // Contract with called JS functions requires that function is passed in x1.
  // (See FullCodeGenerator::Generate().)
  DCHECK_EQ(function, x1);

  LoadTaggedField(cp, FieldMemOperand(function, JSFunction::kContextOffset));

  InvokeFunctionCode(function, new_target, actual_parameter_count, type);
}

void MacroAssembler::InvokeFunctionCode(
    Register function, Register new_target, Register actual_parameter_count,
    InvokeType type, ArgumentAdaptionMode argument_adaption_mode) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());
  DCHECK_EQ(function, x1);
  DCHECK_IMPLIES(new_target.is_valid(), new_target == x3);

  Register dispatch_handle = kJavaScriptCallDispatchHandleRegister;
  Ldr(dispatch_handle.W(),
      FieldMemOperand(function, JSFunction::kDispatchHandleOffset));

  // On function call, call into the debugger if necessary.
  Label debug_hook, continue_after_hook;
  {
    Mov(x5, ExternalReference::debug_hook_on_function_call_address(isolate()));
    Ldrsb(x5, MemOperand(x5));
    Cbnz(x5, &debug_hook);
  }
  bind(&continue_after_hook);

  // Clear the new.target register if not given.
  if (!new_target.is_valid()) {
    LoadRoot(x3, RootIndex::kUndefinedValue);
  }

  Register scratch = x20;
  if (argument_adaption_mode == ArgumentAdaptionMode::kAdapt) {
    Register expected_parameter_count = x2;
    LoadParameterCountFromJSDispatchTable(expected_parameter_count,
                                          dispatch_handle, scratch);
    InvokePrologue(expected_parameter_count, actual_parameter_count, type);
  }

  // We call indirectly through the code field in the function to
  // allow recompilation to take effect without changing any of the
  // call sites.
  LoadEntrypointFromJSDispatchTable(kJavaScriptCallCodeStartRegister,
                                    dispatch_handle, scratch);
  switch (type) {
    case InvokeType::kCall:
      Call(kJavaScriptCallCodeStartRegister);
      break;
    case InvokeType::kJump:
      // We jump through x17 here because for Branch Identification (BTI) we use
      // "Call" (`bti c`) rather than "Jump" (`bti j`) landing pads for
      // tail-called code. See TailCallBuiltin for more information.
      Mov(x17, kJavaScriptCallCodeStartRegister);
      Jump(x17);
      break;
  }
  Label done;
  B(&done);

  // Deferred debug hook.
  bind(&debug_hook);
  CallDebugOnFunctionCall(function, new_target, dispatch_handle,
                          actual_parameter_count);
  B(&continue_after_hook);

  bind(&done);
}
#else
void MacroAssembler::InvokeFunctionCode(Register function, Register new_target,
                                        Register expected_parameter_count,
                                        Register actual_parameter_count,
                                        InvokeType type) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());
  DCHECK_EQ(function, x1);
  DCHECK_IMPLIES(new_target.is_valid(), new_target == x3);

  // On function call, call into the debugger if necessary.
  Label debug_hook, continue_after_hook;
  {
    Mov(x5, ExternalReference::debug_hook_on_function_call_address(isolate()));
    Ldrsb(x5, MemOperand(x5));
    Cbnz(x5, &debug_hook);
  }
  bind(&continue_after_hook);

  // Clear the new.target register if not given.
  if (!new_target.is_valid()) {
    LoadRoot(x3, RootIndex::kUndefinedValue);
  }

  InvokePrologue(expected_parameter_count, actual_parameter_count, type);

  // The called function expects the call kind in x5.
  // We call indirectly through the code field in the function to
  // allow recompilation to take effect without changing any of the
  // call sites.
  constexpr int unused_argument_count = 0;
  switch (type) {
    case InvokeType::kCall:
      CallJSFunction(function, unused_argument_count);
      break;
    case InvokeType::kJump:
      JumpJSFunction(function);
      break;
  }
  Label done;
  B(&done);

  // Deferred debug hook.
  bind(&debug_hook);
  CallDebugOnFunctionCall(function, new_target, expected_parameter_count,
                          actual_parameter_count);
  B(&continue_after_hook);

  bind(&done);
}

void MacroAssembler::InvokeFunctionWithNewTarget(
    Register function, Register new_target, Register actual_parameter_count,
    InvokeType type) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK(type == InvokeType::kJump || has_frame());

  // Contract with called JS functions requires that function is passed in x1.
  // (See FullCodeGenerator::Generate().)
  DCHECK_EQ(function, x1);

  Register expected_parameter_count = x2;

  LoadTaggedField(cp, FieldMemOperand(function, JSFunction::kContextOffset));
  // The number of arguments is stored as an int32_t, and -1 is a marker
  // (kDontAdaptArgumentsSentinel), so we need sign
  // extension to correctly handle it.
  LoadTaggedField(
      expected_parameter_count,
      FieldMemOperand(function, JSFunction::kSharedFunctionInfoOffset));
  Ldrh(expected_parameter_count,
       FieldMemOperand(expected_parameter_count,
                       SharedFunctionInfo::kFormalParameterCountOffset));

  InvokeFunctionCode(function, new_target, expected_parameter_count,
                     actual_parameter_count, type);
}

void MacroAssembler::InvokeFunction(Register function,
                                    Register expected_parameter_count,
                                    Register actual_parameter_count,
                                    InvokeType type) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK(type == InvokeType::kJump || has_frame());

  // Contract with called JS functions requires that function is passed in x1.
  // (See FullCodeGenerator::Generate().)
  DCHECK_EQ(function, x1);

  // Set up the context.
  LoadTaggedField(cp, FieldMemOperand(function, JSFunction::kContextOffset));

  InvokeFunctionCode(function, no_reg, expected_parameter_count,
                     actual_parameter_count, type);
}
#endif  // V8_ENABLE_LEAPTIERING

void MacroAssembler::JumpIfCodeIsMarkedForDeoptimization(
    Register code, Register scratch, Label* if_marked_for_deoptimization) {
  Ldr(scratch.W(), FieldMemOperand(code, Code::kFlagsOffset));
  Tbnz(scratch.W(), Code::kMarkedForDeoptimizationBit,
       if_marked_for_deoptimization);
}

void MacroAssembler::JumpIfCodeIsTurbofanned(Register code, Register scratch,
                                             Label* if_turbofanned) {
  Ldr(scratch.W(), FieldMemOperand(code, Code::kFlagsOffset));
  Tbnz(scratch.W(), Code::kIsTurbofannedBit, if_turbofanned);
}

Operand MacroAssembler::ClearedValue() const {
  return Operand(static_cast<int32_t>(i::ClearedValue(isolate()).ptr()));
}

Operand MacroAssembler::ReceiverOperand() { return Operand(0); }

void MacroAssembler::TryConvertDoubleToInt64(Register result,
                                             DoubleRegister double_input,
                                             Label* done) {
  ASM_CODE_COMMENT(this);
  // Try to convert with an FPU convert instruction. It's trivial to compute
  // the modulo operation on an integer register so we convert to a 64-bit
  // integer.
  //
  // Fcvtzs will saturate to INT64_MIN (0x800...00) or INT64_MAX (0x7FF...FF)
  // when the double is out of range. NaNs and infinities will be converted to 0
  // (as ECMA-262 requires).
  Fcvtzs(result.X(), double_input);

  // The values INT64_MIN (0x800...00) or INT64_MAX (0x7FF...FF) are not
  // representable using a double, so if the result is one of those then we know
  // that saturation occurred, and we need to manually handle the conversion.
  //
  // It is easy to detect INT64_MIN and INT64_MAX because adding or subtracting
  // 1 will cause signed overflow.
  Cmp(result.X(), 1);
  Ccmp(result.X(), -1, VFlag, vc);

  B(vc, done);
}

void MacroAssembler::TruncateDoubleToI(Isolate* isolate, Zone* zone,
                                       Register result,
                                       DoubleRegister double_input,
                                       StubCallMode stub_mode,
                                       LinkRegisterStatus lr_status) {
  ASM_CODE_COMMENT(this);
  if (CpuFeatures::IsSupported(JSCVT)) {
    Fjcvtzs(result.W(), double_input);
    return;
  }

  Label done;

  // Try to convert the double to an int64. If successful, the bottom 32 bits
  // contain our truncated int32 result.
  TryConvertDoubleToInt64(result, double_input, &done);

  // If we fell through then inline version didn't succeed - call stub instead.
  if (lr_status == kLRHasNotBeenSaved) {
    Push<MacroAssembler::kSignLR>(lr, double_input);
  } else {
    Push<MacroAssembler::kDontStoreLR>(xzr, double_input);
  }

  // DoubleToI preserves any registers it needs to clobber.
#if V8_ENABLE_WEBASSEMBLY
  if (stub_mode == StubCallMode::kCallWasmRuntimeStub) {
    Call(static_cast<Address>(Builtin::kDoubleToI), RelocInfo::WASM_STUB_CALL);
#else
  // For balance.
  if (false) {
#endif  // V8_ENABLE_WEBASSEMBLY
  } else {
    CallBuiltin(Builtin::kDoubleToI);
  }
  Ldr(result, MemOperand(sp, 0));

  DCHECK_EQ(xzr.SizeInBytes(), double_input.SizeInBytes());

  if (lr_status == kLRHasNotBeenSaved) {
    // Pop into xzr here to drop the double input on the stack:
    Pop<MacroAssembler::kAuthLR>(xzr, lr);
  } else {
    Drop(2);
  }

  Bind(&done);
  // Keep our invariant that the upper 32 bits are zero.
  Uxtw(result.W(), result.W());
}

void MacroAssembler::Prologue() {
  ASM_CODE_COMMENT(this);
  Push<MacroAssembler::kSignLR>(lr, fp);
  mov(fp, sp);
  static_assert(kExtraSlotClaimedByPrologue == 1);
  Push(cp, kJSFunctionRegister, kJavaScriptCallArgCountRegister, padreg);
}

void MacroAssembler::EnterFrame(StackFrame::Type type) {
  UseScratchRegisterScope temps(this);

  if (StackFrame::IsJavaScript(type)) {
    // Just push a minimal "machine frame", saving the frame pointer and return
    // address, without any markers.
    Push<MacroAssembler::kSignLR>(lr, fp);
    Mov(fp, sp);
    // sp[1] : lr
    // sp[0] : fp
  } else {
      Register type_reg = temps.AcquireX();
      Mov(type_reg, StackFrame::TypeToMarker(type));
      Register fourth_reg = padreg;
      if (type == StackFrame::CONSTRUCT || type == StackFrame::FAST_CONSTRUCT) {
        fourth_reg = cp;
      }
#if V8_ENABLE_WEBASSEMBLY
      if (type == StackFrame::WASM || type == StackFrame::WASM_LIFTOFF_SETUP ||
          type == StackFrame::WASM_EXIT) {
        fourth_reg = kWasmImplicitArgRegister;
      }
#endif  // V8_ENABLE_WEBASSEMBLY
      Push<MacroAssembler::kSignLR>(lr, fp, type_reg, fourth_reg);
      static constexpr int kSPToFPDelta  = 2 * kSystemPointerSize;
      Add(fp, sp, kSPToFPDelta);
      // sp[3] : lr
      // sp[2] : fp
      // sp[1] : type
      // sp[0] : cp | wasm instance | for alignment
  }
}

void MacroAssembler::LeaveFrame(StackFrame::Type type) {
  ASM_CODE_COMMENT(this);
  // Drop the execution stack down to the frame pointer and restore
  // the caller frame pointer and return address.
  Mov(sp, fp);
  Pop<MacroAssembler::kAuthLR>(fp, lr);
}

void MacroAssembler::EnterExitFrame(const Register& scratch, int extra_space,
                                    StackFrame::Type frame_type) {
  ASM_CODE_COMMENT(this);
  DCHECK(frame_type == StackFrame::EXIT ||
         frame_type == StackFrame::BUILTIN_EXIT ||
         frame_type == StackFrame::API_ACCESSOR_EXIT ||
         frame_type == StackFrame::API_CALLBACK_EXIT);

  // Set up the new stack frame.
  Push<MacroAssembler::kSignLR>(lr, fp);
  Mov(fp, sp);
  Mov(scratch, StackFrame::TypeToMarker(frame_type));
  Push(scratch, xzr);
  //          fp[8]: CallerPC (lr)
  //    fp -> fp[0]: CallerFP (old fp)
  //          fp[-8]: STUB marker
  //    sp -> fp[-16]: Space reserved for SPOffset.
  static_assert((2 * kSystemPointerSize) ==
                ExitFrameConstants::kCallerSPOffset);
  static_assert((1 * kSystemPointerSize) ==
                ExitFrameConstants::kCallerPCOffset);
  static_assert((0 * kSystemPointerSize) ==
                ExitFrameConstants::kCallerFPOffset);
  static_assert((-2 * kSystemPointerSize) == ExitFrameConstants::kSPOffset);

  // Save the frame pointer and context pointer in the top frame.
  Mov(scratch,
      ExternalReference::Create(IsolateAddressId::kCEntryFPAddress, isolate()));
  Str(fp, MemOperand(scratch));
  Mov(scratch,
      ExternalReference::Create(IsolateAddressId::kContextAddress, isolate()));
  Str(cp, MemOperand(scratch));

  static_assert((-2 * kSystemPointerSize) ==
                ExitFrameConstants::kLastExitFrameField);

  // Round the number of space we need to claim to a multiple of two.
  int slots_to_claim = RoundUp(extra_space + 1, 2);

  // Reserve space for the return address and for user requested memory.
  // We do this before aligning to make sure that we end up correctly
  // aligned with the minimum of wasted space.
  Claim(slots_to_claim, kXRegSize);
  //         fp[8]: CallerPC (lr)
  //   fp -> fp[0]: CallerFP (old fp)
  //         fp[-8]: STUB marker
  //         fp[-16]: Space reserved for SPOffset.
  //         sp[8]: Extra space reserved for caller (if extra_space != 0).
  //   sp -> sp[0]: Space reserved for the return address.

  // ExitFrame::GetStateForFramePointer expects to find the return address at
  // the memory address immediately below the pointer stored in SPOffset.
  // It is not safe to derive much else from SPOffset, because the size of the
  // padding can vary.
  Add(scratch, sp, kXRegSize);
  Str(scratch, MemOperand(fp, ExitFrameConstants::kSPOffset));
}

// Leave the current exit frame.
void MacroAssembler::LeaveExitFrame(const Register& scratch,
                                    const Register& scratch2) {
  ASM_CODE_COMMENT(this);

  // Restore the context pointer from the top frame.
  Mov(scratch,
      ExternalReference::Create(IsolateAddressId::kContextAddress, isolate()));
  Ldr(cp, MemOperand(scratch));

  if (v8_flags.debug_code) {
    // Also emit debug code to clear the cp in the top frame.
    Mov(scratch2, Operand(Context::kInvalidContext));
    Mov(scratch, ExternalReference::Create(IsolateAddressId::kContextAddress,
                                           isolate()));
    Str(scratch2, MemOperand(scratch));
  }
  // Clear the frame pointer from the top frame.
  Mov(scratch,
      ExternalReference::Create(IsolateAddressId::kCEntryFPAddress, isolate()));
  Str(xzr, MemOperand(scratch));

  // Pop the exit frame.
  //         fp[8]: CallerPC (lr)
  //   fp -> fp[0]: CallerFP (old fp)
  //         fp[...]: The rest of the frame.
  Mov(sp, fp);
  Pop<MacroAssembler::kAuthLR>(fp, lr);
}

void MacroAssembler::LoadGlobalProxy(Register dst) {
  ASM_CODE_COMMENT(this);
  LoadNativeContextSlot(dst, Context::GLOBAL_PROXY_INDEX);
}

void MacroAssembler::LoadWeakValue(Register out, Register in,
                                   Label* target_if_cleared) {
  ASM_CODE_COMMENT(this);
  CompareAndBranch(in.W(), Operand(kClearedWeakHeapObjectLower32), eq,
                   target_if_cleared);

  and_(out, in, Operand(~kWeakHeapObjectMask));
}

void MacroAssembler::EmitIncrementCounter(StatsCounter* counter, int value,
                                          Register scratch1,
                                          Register scratch2) {
  ASM_CODE_COMMENT(this);
  DCHECK_NE(value, 0);
  if (v8_flags.native_code_counters && counter->Enabled()) {
    // This operation has to be exactly 32-bit wide in case the external
    // reference table redirects the counter to a uint32_t dummy_stats_counter_
    // field.
    Mov(scratch2, ExternalReference::Create(counter));
    Ldr(scratch1.W(), MemOperand(scratch2));
    Add(scratch1.W(), scratch1.W(), value);
    Str(scratch1.W(), MemOperand(scratch2));
  }
}

void MacroAssembler::JumpIfObjectType(Register object, Register map,
                                      Register type_reg, InstanceType type,
                                      Label* if_cond_pass, Condition cond) {
  ASM_CODE_COMMENT(this);
  CompareObjectType(object, map, type_reg, type);
  B(cond, if_cond_pass);
}

void MacroAssembler::JumpIfJSAnyIsNotPrimitive(Register heap_object,
                                               Register scratch, Label* target,
                                               Label::Distance distance,
                                               Condition cc) {
  CHECK(cc == Condition::kUnsignedLessThan ||
        cc == Condition::kUnsignedGreaterThanEqual);
  if (V8_STATIC_ROOTS_BOOL) {
#ifdef DEBUG
    Label ok;
    LoadMap(scratch, heap_object);
    CompareInstanceTypeRange(scratch, scratch, FIRST_JS_RECEIVER_TYPE,
                             LAST_JS_RECEIVER_TYPE);
    B(Condition::kUnsignedLessThanEqual, &ok);
    LoadMap(scratch, heap_object);
    CompareInstanceTypeRange(scratch, scratch, FIRST_PRIMITIVE_HEAP_OBJECT_TYPE,
                             LAST_PRIMITIVE_HEAP_OBJECT_TYPE);
    B(Condition::kUnsignedLessThanEqual, &ok);
    Abort(AbortReason::kInvalidReceiver);
    bind(&ok);
#endif  // DEBUG

    // All primitive object's maps are allocated at the start of the read only
    // heap. Thus JS_RECEIVER's must have maps with larger (compressed)
    // addresses.
    LoadCompressedMap(scratch, heap_object);
    CmpTagged(scratch, Immediate(InstanceTypeChecker::kNonJsReceiverMapLimit));
  } else {
    static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
    CompareObjectType(heap_object, scratch, scratch, FIRST_JS_RECEIVER_TYPE);
  }
  B(cc, target);
}

#if V8_STATIC_ROOTS_BOOL
void MacroAssembler::CompareInstanceTypeWithUniqueCompressedMap(
    Register map, Register scratch, InstanceType type) {
  std::optional<RootIndex> expected =
      InstanceTypeChecker::UniqueMapOfInstanceType(type);
  CHECK(expected);
  Tagged_t expected_ptr = ReadOnlyRootPtr(*expected);
  DCHECK_NE(map, scratch);
  UseScratchRegisterScope temps(this);
  CHECK(IsImmAddSub(expected_ptr) || scratch != Register::no_reg() ||
        temps.CanAcquire());
  if (!IsImmAddSub(expected_ptr)) {
    if (scratch == Register::no_reg()) {
      scratch = temps.AcquireX();
      DCHECK_NE(map, scratch);
    }
    Operand imm_operand =
        MoveImmediateForShiftedOp(scratch, expected_ptr, kAnyShift);
    CmpTagged(map, imm_operand);
  } else {
    CmpTagged(map, Immediate(expected_ptr));
  }
}

void MacroAssembler::IsObjectTypeFast(Register object,
                                      Register compressed_map_scratch,
                                      InstanceType type) {
  ASM_CODE_COMMENT(this);
  CHECK(InstanceTypeChecker::UniqueMapOfInstanceType(type));
  LoadCompressedMap(compressed_map_scratch, object);
  CompareInstanceTypeWithUniqueCompressedMap(compressed_map_scratch,
                                             Register::no_reg(), type);
}
#endif  // V8_STATIC_ROOTS_BOOL

// Sets equality condition flags.
void MacroAssembler::IsObjectType(Register object, Register scratch1,
                                  Register scratch2, InstanceType type) {
  ASM_CODE_COMMENT(this);

#if V8_STATIC_ROOTS_BOOL
  if (InstanceTypeChecker::UniqueMapOfInstanceType(type)) {
    LoadCompressedMap(scratch1, object);
    CompareInstanceTypeWithUniqueCompressedMap(
        scratch1, scratch1 != scratch2 ? scratch2 : Register::no_reg(), type);
    return;
  }
#endif  // V8_STATIC_ROOTS_BOOL

  CompareObjectType(object, scratch1, scratch2, type);
}

// Sets equality condition flags.
void MacroAssembler::IsObjectTypeInRange(Register heap_object, Register scratch,
                                         InstanceType lower_limit,
                                         InstanceType higher_limit) {
  DCHECK_LT(lower_limit, higher_limit);
#if V8_STATIC_ROOTS_BOOL
  if (auto range = InstanceTypeChecker::UniqueMapRangeOfInstanceTypeRange(
          lower_limit, higher_limit)) {
    LoadCompressedMap(scratch.W(), heap_object);
    CompareRange(scratch.W(), scratch.W(), range->first, range->second);
    return;
  }
#endif  // V8_STATIC_ROOTS_BOOL
  LoadMap(scratch, heap_object);
  CompareInstanceTypeRange(scratch, scratch, lower_limit, higher_limit);
}

// Sets condition flags based on comparison, and returns type in type_reg.
void MacroAssembler::CompareObjectType(Register object, Register map,
                                       Register type_reg, InstanceType type) {
  ASM_CODE_COMMENT(this);
  LoadMap(map, object);
  CompareInstanceType(map, type_reg, type);
}

void MacroAssembler::CompareRange(Register value, Register scratch,
                                  unsigned lower_limit, unsigned higher_limit) {
  ASM_CODE_COMMENT(this);
  DCHECK_LT(lower_limit, higher_limit);
  if (lower_limit != 0) {
    Sub(scratch.W(), value.W(), Operand(lower_limit));
    Cmp(scratch.W(), Operand(higher_limit - lower_limit));
  } else {
    Cmp(value.W(), Immediate(higher_limit));
  }
}

void MacroAssembler::JumpIfIsInRange(Register value, Register scratch,
                                     unsigned lower_limit,
                                     unsigned higher_limit,
                                     Label* on_in_range) {
  CompareRange(value, scratch, lower_limit, higher_limit);
  B(ls, on_in_range);
}

void MacroAssembler::LoadCompressedMap(Register dst, Register object) {
  ASM_CODE_COMMENT(this);
  Ldr(dst.W(), FieldMemOperand(object, HeapObject::kMapOffset));
}

void MacroAssembler::LoadMap(Register dst, Register object) {
  ASM_CODE_COMMENT(this);
  LoadTaggedField(dst, FieldMemOperand(object, HeapObject::kMapOffset));
}

void MacroAssembler::LoadFeedbackVector(Register dst, Register closure,
                                        Register scratch, Label* fbv_undef) {
  Label done;

  // Load the feedback vector from the closure.
  LoadTaggedField(dst,
                  FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
  LoadTaggedField(dst, FieldMemOperand(dst, FeedbackCell::kValueOffset));

  // Check if feedback vector is valid.
  LoadTaggedField(scratch, FieldMemOperand(dst, HeapObject::kMapOffset));
  Ldrh(scratch, FieldMemOperand(scratch, Map::kInstanceTypeOffset));
  Cmp(scratch, FEEDBACK_VECTOR_TYPE);
  B(eq, &done);

  // Not valid, load undefined.
  LoadRoot(dst, RootIndex::kUndefinedValue);
  B(fbv_undef);

  Bind(&done);
}

// Sets condition flags based on comparison, and returns type in type_reg.
void MacroAssembler::CompareInstanceType(Register map, Register type_reg,
                                         InstanceType type) {
  ASM_CODE_COMMENT(this);
  Ldrh(type_reg, FieldMemOperand(map, Map::kInstanceTypeOffset));
  Cmp(type_reg, type);
}

// Sets condition flags based on comparison, and returns type in type_reg.
void MacroAssembler::CompareInstanceTypeRange(Register map, Register type_reg,
                                              InstanceType lower_limit,
                                              InstanceType higher_limit) {
  ASM_CODE_COMMENT(this);
  DCHECK_LT(lower_limit, higher_limit);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();
  Ldrh(type_reg, FieldMemOperand(map, Map::kInstanceTypeOffset));
  CompareRange(type_reg, scratch, lower_limit, higher_limit);
}

void MacroAssembler::LoadElementsKindFromMap(Register result, Register map) {
  ASM_CODE_COMMENT(this);
  // Load the map's "bit field 2".
  Ldrb(result, FieldMemOperand(map, Map::kBitField2Offset));
  // Retrieve elements_kind from bit field 2.
  DecodeField<Map::Bits2::ElementsKindBits>(result);
}

void MacroAssembler::CompareTaggedRoot(const Register& obj, RootIndex index) {
  ASM_CODE_COMMENT(this);
  AssertSmiOrHeapObjectInMainCompressionCage(obj);
  UseScratchRegisterScope temps(this);
  if (V8_STATIC_ROOTS_BOOL && RootsTable::IsReadOnly(index)) {
    CmpTagged(obj, Immediate(ReadOnlyRootPtr(index)));
    return;
  }
  // Some smi roots contain system pointer size values like stack limits.
  DCHECK(base::IsInRange(index, RootIndex::kFirstStrongOrReadOnlyRoot,
                         RootIndex::kLastStrongOrReadOnlyRoot));
  Register temp = temps.AcquireX();
  DCHECK(!AreAliased(obj, temp));
  LoadRoot(temp, index);
  CmpTagged(obj, temp);
}

void MacroAssembler::CompareRoot(const Register& obj, RootIndex index,
                                 ComparisonMode mode) {
  ASM_CODE_COMMENT(this);
  if (mode == ComparisonMode::kFullPointer ||
      !base::IsInRange(index, RootIndex::kFirstStrongOrReadOnlyRoot,
                       RootIndex::kLastStrongOrReadOnlyRoot)) {
    // Some smi roots contain system pointer size values like stack limits.
    UseScratchRegisterScope temps(this);
    Register temp = temps.AcquireX();
    DCHECK(!AreAliased(obj, temp));
    LoadRoot(temp, index);
    Cmp(obj, temp);
    return;
  }
  CompareTaggedRoot(obj, index);
}

void MacroAssembler::JumpIfRoot(const Register& obj, RootIndex index,
                                Label* if_equal) {
  CompareRoot(obj, index);
  B(eq, if_equal);
}

void MacroAssembler::JumpIfNotRoot(const Register& obj, RootIndex index,
                                   Label* if_not_equal) {
  CompareRoot(obj, index);
  B(ne, if_not_equal);
}

void MacroAssembler::JumpIfIsInRange(const Register& value,
                                     unsigned lower_limit,
                                     unsigned higher_limit,
                                     Label* on_in_range) {
  ASM_CODE_COMMENT(this);
  if (lower_limit != 0) {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.AcquireW();
    Sub(scratch, value, Operand(lower_limit));
    CompareAndBranch(scratch, Operand(higher_limit - lower_limit), ls,
                     on_in_range);
  } else {
    CompareAndBranch(value, Operand(higher_limit - lower_limit), ls,
                     on_in_range);
  }
}

void MacroAssembler::LoadTaggedField(const Register& destination,
                                     const MemOperand& field_operand) {
  if (COMPRESS_POINTERS_BOOL) {
    DecompressTagged(destination, field_operand);
  } else {
    Ldr(destination, field_operand);
  }
}

void MacroAssembler::LoadTaggedFieldWithoutDecompressing(
    const Register& destination, const MemOperand& field_operand) {
  if (COMPRESS_POINTERS_BOOL) {
    Ldr(destination.W(), field_operand);
  } else {
    Ldr(destination, field_operand);
  }
}

void MacroAssembler::LoadTaggedSignedField(const Register& destination,
                                           const MemOperand& field_operand) {
  if (COMPRESS_POINTERS_BOOL) {
    DecompressTaggedSigned(destination, field_operand);
  } else {
    Ldr(destination, field_operand);
  }
}

void MacroAssembler::SmiUntagField(Register dst, const MemOperand& src) {
  SmiUntag(dst, src);
}

void MacroAssembler::StoreTwoTaggedFields(const Register& value,
                                          const MemOperand& dst_field_operand) {
  if (COMPRESS_POINTERS_BOOL) {
    Stp(value.W(), value.W(), dst_field_operand);
  } else {
    Stp(value, value, dst_field_operand);
  }
}

void MacroAssembler::StoreTaggedField(const Register& value,
                                      const MemOperand& dst_field_operand) {
  if (COMPRESS_POINTERS_BOOL) {
    Str(value.W(), dst_field_operand);
  } else {
    Str(value, dst_field_operand);
  }
}

void MacroAssembler::AtomicStoreTaggedField(const Register& value,
                                            const Register& dst_base,
                                            const Register& dst_index,
                                            const Register& temp) {
  Add(temp, dst_base, dst_index);
  if (COMPRESS_POINTERS_BOOL) {
    Stlr(value.W(), temp);
  } else {
    Stlr(value, temp);
  }
}

void MacroAssembler::DecompressTaggedSigned(const Register& destination,
                                            const MemOperand& field_operand) {
  ASM_CODE_COMMENT(this);
  Ldr(destination.W(), field_operand);
  if (v8_flags.debug_code) {
    // Corrupt the top 32 bits. Made up of 16 fixed bits and 16 pc offset bits.
    Add(destination, destination,
        ((kDebugZapValue << 16) | (pc_offset() & 0xffff)) << 32);
  }
}

void MacroAssembler::DecompressTagged(const Register& destination,
                                      const MemOperand& field_operand) {
  ASM_CODE_COMMENT(this);
  Ldr(destination.W(), field_operand);
  Add(destination, kPtrComprCageBaseRegister, destination);
}

void MacroAssembler::DecompressTagged(const Register& destination,
                                      const Register& source) {
  ASM_CODE_COMMENT(this);
  Add(destination, kPtrComprCageBaseRegister, Operand(source, UXTW));
}

void MacroAssembler::DecompressTagged(const Register& destination,
                                      Tagged_t immediate) {
  ASM_CODE_COMMENT(this);
  if (IsImmAddSub(immediate)) {
    Add(destination, kPtrComprCageBaseRegister,
        Immediate(immediate, RelocInfo::Mode::NO_INFO));
  } else {
    // Immediate is larger than 12 bit and therefore can't be encoded directly.
    // Use destination as a temporary to not acquire a scratch register.
    DCHECK_NE(destination, sp);
    Operand imm_operand =
        MoveImmediateForShiftedOp(destination, immediate, kAnyShift);
    Add(destination, kPtrComprCageBaseRegister, imm_operand);
  }
}

void MacroAssembler::DecompressProtected(const Register& destination,
                                         const MemOperand& field_operand) {
#if V8_ENABLE_SANDBOX
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();
  Ldr(destination.W(), field_operand);
  Ldr(scratch,
      MemOperand(kRootRegister, IsolateData::trusted_cage_base_offset()));
  Orr(destination, destination, scratch);
#else
  UNREACHABLE();
#endif  // V8_ENABLE_SANDBOX
}

void MacroAssembler::AtomicDecompressTaggedSigned(const Register& destination,
                                                  const Register& base,
                                                  const Register& index,
                                                  const Register& temp) {
  ASM_CODE_COMMENT(this);
  Add(temp, base, index);
  Ldar(destination.W(), temp);
  if (v8_flags.debug_code) {
    // Corrupt the top 32 bits. Made up of 16 fixed bits and 16 pc offset bits.
    Add(destination, destination,
        ((kDebugZapValue << 16) | (pc_offset() & 0xffff)) << 32);
  }
}

void MacroAssembler::AtomicDecompressTagged(const Register& destination,
                                            const Register& base,
                                            const Register& index,
                                            const Register& temp) {
  ASM_CODE_COMMENT(this);
  Add(temp, base, index);
  Ldar(destination.W(), temp);
  Add
```