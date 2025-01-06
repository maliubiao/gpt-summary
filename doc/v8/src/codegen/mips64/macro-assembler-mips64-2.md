Response: The user wants a summary of the functionality of the provided C++ code snippet. This is part 3 of 4, suggesting that the previous parts have already covered some functionality. The file appears to be `macro-assembler-mips64.cc`, indicating it's about generating MIPS64 assembly code.

I need to analyze the code in this specific snippet, focusing on the functions and their operations. If any of these operations are directly related to JavaScript concepts, I need to provide a JavaScript example.

The code snippet includes functions for:
- Jumping to different locations in code (with conditions and delay slots).
- Calling functions (C++ and JavaScript).
- Tail calls.
- Handling builtin functions.
- Stack manipulation (push, pop, drop arguments).
- Exception handling.
- Floating-point operations.
- Invoking JavaScript functions.
- Runtime calls.
- Debugging utilities.
- Assertions.
- Weak value loading.
- Counter manipulation.
- Stack frame management.
- Smi tagging/untagging.
- Code object manipulation.

Based on these observations, I can formulate the functionality summary. The connection to JavaScript will primarily be in the functions related to invoking and calling JavaScript functions and handling builtins.
这个C++代码片段（`v8/src/codegen/mips64/macro-assembler-mips64.cc`的第3部分）主要负责**生成MIPS64架构的汇编指令，用于实现V8 JavaScript引擎的各种功能**。

具体来说，这部分代码提供了以下关键功能：

1. **控制流操作**:
   - 提供了各种跳转指令 (`Jump`, `BranchLong`, `BranchAndLinkLong`)，允许在满足特定条件时跳转到代码的不同位置。
   - 实现了函数调用 (`Call`) 和尾调用 (`TailCallBuiltin`) 的汇编指令生成。
   - 支持条件跳转，可以根据寄存器中的值或比较结果进行跳转。
   - 包含用于处理分支延迟槽的机制。

2. **函数调用支持**:
   - 封装了调用C++函数和JavaScript函数的指令序列。
   - 提供了调用内置函数 (`CallBuiltin`, `TailCallBuiltin`) 的方法，这些内置函数是V8引擎预先定义的一些核心功能。
   - 包含了用于调用运行时函数 (`CallRuntime`) 的机制，这些运行时函数是由C++实现的，用于处理一些较为复杂或底层的操作。

3. **栈操作**:
   - 提供了压栈 (`push`)、弹栈 (`pop`) 以及调整栈指针 (`DropArguments`) 的指令。
   - 包含用于管理函数调用时参数传递和返回值的栈操作。

4. **异常处理**:
   - 提供了压入和弹出栈处理帧 (`PushStackHandler`, `PopStackHandler`) 的机制，用于处理JavaScript执行过程中出现的异常。

5. **浮点数操作**:
   - 提供了规范化NaN (`FPUCanonicalizeNaN`) 以及在寄存器之间移动浮点数 (`MovFromFloatResult`, `MovToFloatParameter` 等) 的指令。
   - 实现了浮点数的最大值 (`Float32Max`, `Float64Max`) 和最小值 (`Float32Min`, `Float64Min`) 计算，并考虑了NaN的情况。

6. **JavaScript调用相关的辅助功能**:
   - 提供了加载栈限制 (`LoadStackLimit`) 进行栈溢出检查的功能 (`StackOverflowCheck`).
   - 包含了调用JavaScript函数的序言 (`InvokePrologue`)，用于处理参数数量不匹配的情况。
   - 提供了调用不同类型的JavaScript函数 (`InvokeFunctionCode`, `InvokeFunctionWithNewTarget`, `InvokeFunction`) 的指令序列。

7. **内置函数处理**:
   - 提供了根据内置函数索引加载入口点 (`LoadEntryFromBuiltinIndex`) 和直接根据内置函数加载入口点 (`LoadEntryFromBuiltin`) 的方法。

8. **调试和断言**:
   - 提供了插入断点 (`Trap`, `DebugBreak`) 和检查条件是否满足 (`Check`, `Abort`) 的指令，用于调试和错误处理。
   - 包含了一些用于在调试模式下进行类型断言的宏 (`AssertJSAny`, `AssertNotSmi`, `AssertSmi` 等)。

**与JavaScript功能的关联和示例：**

这部分代码是V8引擎将JavaScript代码转换为机器码的关键部分。许多功能都直接服务于JavaScript的执行。

**示例 1：调用JavaScript函数**

假设有以下 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

add(5, 10);
```

当 V8 引擎执行 `add(5, 10)` 时，`InvokeFunction` 或 `InvokeFunctionCode` 相关的汇编代码会被生成。这些代码会执行以下操作（简化描述）：

1. **获取函数对象 (`add`)**: 从上下文中加载 `add` 函数对象。
2. **设置上下文**:  将 `add` 函数的上下文加载到 `cp` 寄存器。
3. **准备参数**: 将参数 `5` 和 `10` 放入栈中。
4. **调用函数代码**: 调用 `add` 函数对应的机器码。这涉及到跳转到 `add` 函数代码的入口点。

生成的汇编代码中可能包含类似于以下的代码片段（简化）：

```assembly
  // ... (其他操作)
  Ld cp, FieldMemOperand(a1, JSFunction::kContextOffset); // 加载 add 函数的上下文到 cp
  // ... (准备参数，将 5 和 10 压栈)
  CallJSFunction(a1); // 调用 add 函数
  // ... (处理返回值)
```

**示例 2：调用内置函数**

JavaScript 中的某些操作会直接调用 V8 引擎的内置函数。例如，`Array.prototype.push()` 方法就是一个内置函数。

```javascript
const arr = [];
arr.push(1);
```

当执行 `arr.push(1)` 时，`CallBuiltin` 相关的汇编代码会被生成。

生成的汇编代码可能包含类似于以下的代码片段（简化）：

```assembly
  // ... (其他操作)
  CallBuiltin(Builtin::kArrayPush); // 调用 Array.prototype.push 内置函数
  // ... (处理返回值)
```

在这个例子中，`Builtin::kArrayPush` 代表了 `Array.prototype.push` 在 V8 引擎内部的标识符。`CallBuiltin` 会加载这个内置函数的入口地址并跳转到那里执行。

总之，这部分 `macro-assembler-mips64.cc` 代码是 V8 引擎将高级的 JavaScript 代码转化为底层机器码的关键组件，它提供了构建各种控制流、函数调用和基本操作所需的汇编指令生成能力，是理解 V8 引擎执行原理的重要部分。

Prompt: 
```
这是目录为v8/src/codegen/mips64/macro-assembler-mips64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共4部分，请归纳一下它的功能

"""
                 RootRegisterOffsetForExternalReferenceTableEntry(
                                   isolate(), reference)));
        return MemOperand(scratch, 0);
      }
    }
  }
  DCHECK(scratch.is_valid());
  li(scratch, reference);
  return MemOperand(scratch, 0);
}

void MacroAssembler::Jump(Register target, Condition cond, Register rs,
                          const Operand& rt, BranchDelaySlot bd) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  if (kArchVariant == kMips64r6 && bd == PROTECT) {
    if (cond == cc_always) {
      jic(target, 0);
    } else {
      BRANCH_ARGS_CHECK(cond, rs, rt);
      Branch(2, NegateCondition(cond), rs, rt);
      jic(target, 0);
    }
  } else {
    if (cond == cc_always) {
      jr(target);
    } else {
      BRANCH_ARGS_CHECK(cond, rs, rt);
      Branch(2, NegateCondition(cond), rs, rt);
      jr(target);
    }
    // Emit a nop in the branch delay slot if required.
    if (bd == PROTECT) nop();
  }
}

void MacroAssembler::Jump(intptr_t target, RelocInfo::Mode rmode,
                          Condition cond, Register rs, const Operand& rt,
                          BranchDelaySlot bd) {
  Label skip;
  if (cond != cc_always) {
    Branch(USE_DELAY_SLOT, &skip, NegateCondition(cond), rs, rt);
  }
  // The first instruction of 'li' may be placed in the delay slot.
  // This is not an issue, t9 is expected to be clobbered anyway.
  {
    BlockTrampolinePoolScope block_trampoline_pool(this);
    li(t9, Operand(target, rmode));
    Jump(t9, al, zero_reg, Operand(zero_reg), bd);
    bind(&skip);
  }
}

void MacroAssembler::Jump(Address target, RelocInfo::Mode rmode, Condition cond,
                          Register rs, const Operand& rt, BranchDelaySlot bd) {
  DCHECK(!RelocInfo::IsCodeTarget(rmode));
  Jump(static_cast<intptr_t>(target), rmode, cond, rs, rt, bd);
}

void MacroAssembler::Jump(Handle<Code> code, RelocInfo::Mode rmode,
                          Condition cond, Register rs, const Operand& rt,
                          BranchDelaySlot bd) {
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Label skip;
  if (cond != cc_always) {
    BranchShort(&skip, NegateCondition(cond), rs, rt);
  }

  Builtin builtin = Builtin::kNoBuiltinId;
  if (isolate()->builtins()->IsBuiltinHandle(code, &builtin)) {
    TailCallBuiltin(builtin);
    bind(&skip);
    return;
  }

  Jump(static_cast<intptr_t>(code.address()), rmode, cc_always, rs, rt, bd);
  bind(&skip);
}

void MacroAssembler::Jump(const ExternalReference& reference) {
  li(t9, reference);
  Jump(t9);
}

// Note: To call gcc-compiled C code on mips, you must call through t9.
void MacroAssembler::Call(Register target, Condition cond, Register rs,
                          const Operand& rt, BranchDelaySlot bd) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  if (kArchVariant == kMips64r6 && bd == PROTECT) {
    if (cond == cc_always) {
      jialc(target, 0);
    } else {
      BRANCH_ARGS_CHECK(cond, rs, rt);
      Branch(2, NegateCondition(cond), rs, rt);
      jialc(target, 0);
    }
  } else {
    if (cond == cc_always) {
      jalr(target);
    } else {
      BRANCH_ARGS_CHECK(cond, rs, rt);
      Branch(2, NegateCondition(cond), rs, rt);
      jalr(target);
    }
    // Emit a nop in the branch delay slot if required.
    if (bd == PROTECT) nop();
  }
  set_pc_for_safepoint();
}

void MacroAssembler::JumpIfIsInRange(Register value, unsigned lower_limit,
                                     unsigned higher_limit,
                                     Label* on_in_range) {
  ASM_CODE_COMMENT(this);
  if (lower_limit != 0) {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Dsubu(scratch, value, Operand(lower_limit));
    Branch(on_in_range, ls, scratch, Operand(higher_limit - lower_limit));
  } else {
    Branch(on_in_range, ls, value, Operand(higher_limit - lower_limit));
  }
}

void MacroAssembler::Call(Address target, RelocInfo::Mode rmode, Condition cond,
                          Register rs, const Operand& rt, BranchDelaySlot bd) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  li(t9, Operand(static_cast<int64_t>(target), rmode), ADDRESS_LOAD);
  Call(t9, cond, rs, rt, bd);
}

void MacroAssembler::Call(Handle<Code> code, RelocInfo::Mode rmode,
                          Condition cond, Register rs, const Operand& rt,
                          BranchDelaySlot bd) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Builtin builtin = Builtin::kNoBuiltinId;
  if (isolate()->builtins()->IsBuiltinHandle(code, &builtin)) {
    CallBuiltin(builtin);
    return;
  }
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  Call(code.address(), rmode, cond, rs, rt, bd);
}

void MacroAssembler::LoadEntryFromBuiltinIndex(Register builtin_index,
                                               Register target) {
  ASM_CODE_COMMENT(this);
  static_assert(kSystemPointerSize == 8);
  static_assert(kSmiTagSize == 1);
  static_assert(kSmiTag == 0);

  // The builtin_index register contains the builtin index as a Smi.
  SmiUntag(target, builtin_index);
  Dlsa(target, kRootRegister, target, kSystemPointerSizeLog2);
  Ld(target, MemOperand(target, IsolateData::builtin_entry_table_offset()));
}
void MacroAssembler::LoadEntryFromBuiltin(Builtin builtin,
                                          Register destination) {
  Ld(destination, EntryFromBuiltinAsOperand(builtin));
}
MemOperand MacroAssembler::EntryFromBuiltinAsOperand(Builtin builtin) {
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
  Register temp = t9;
  switch (options().builtin_call_jump_mode) {
    case BuiltinCallJumpMode::kAbsolute: {
      li(temp, Operand(BuiltinEntry(builtin), RelocInfo::OFF_HEAP_TARGET));
      Call(temp);
      break;
    }
    case BuiltinCallJumpMode::kIndirect: {
      LoadEntryFromBuiltin(builtin, temp);
      Call(temp);
      break;
    }
    case BuiltinCallJumpMode::kForMksnapshot: {
      Handle<Code> code = isolate()->builtins()->code_handle(builtin);
      IndirectLoadConstant(temp, code);
      CallCodeObject(temp, kJSEntrypointTag);
      break;
    }
    case BuiltinCallJumpMode::kPCRelative:
      // Short builtin calls is unsupported in mips64.
      UNREACHABLE();
  }
}

void MacroAssembler::TailCallBuiltin(Builtin builtin, Condition cond,
                                     Register type, Operand range) {
  if (cond != cc_always) {
    Label done;
    Branch(&done, NegateCondition(cond), type, range);
    TailCallBuiltin(builtin);
    bind(&done);
  } else {
    TailCallBuiltin(builtin);
  }
}

void MacroAssembler::TailCallBuiltin(Builtin builtin) {
  ASM_CODE_COMMENT_STRING(this,
                          CommentForOffHeapTrampoline("tail call", builtin));
  Register temp = t9;

  switch (options().builtin_call_jump_mode) {
    case BuiltinCallJumpMode::kAbsolute: {
      li(temp, Operand(BuiltinEntry(builtin), RelocInfo::OFF_HEAP_TARGET));
      Jump(temp);
      break;
    }
    case BuiltinCallJumpMode::kIndirect: {
      LoadEntryFromBuiltin(builtin, temp);
      Jump(temp);
      break;
    }
    case BuiltinCallJumpMode::kForMksnapshot: {
      Handle<Code> code = isolate()->builtins()->code_handle(builtin);
      IndirectLoadConstant(temp, code);
      JumpCodeObject(temp, kJSEntrypointTag);
      break;
    }
    case BuiltinCallJumpMode::kPCRelative:
      UNREACHABLE();
  }
}

void MacroAssembler::PatchAndJump(Address target) {
  if (kArchVariant != kMips64r6) {
    ASM_CODE_COMMENT(this);
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    mov(scratch, ra);
    bal(1);                                  // jump to ld
    nop();                                   // in the delay slot
    ld(t9, MemOperand(ra, kInstrSize * 3));  // ra == pc_
    jr(t9);
    mov(ra, scratch);  // in delay slot
    DCHECK_EQ(reinterpret_cast<uint64_t>(pc_) % 8, 0);
    *reinterpret_cast<uint64_t*>(pc_) = target;  // pc_ should be align.
    pc_ += sizeof(uint64_t);
  } else {
    // TODO(mips r6): Implement.
    UNIMPLEMENTED();
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

  // Compute the return address in lr to return to after the jump below. The pc
  // is already at '+ 8' from the current instruction; but return is after three
  // instructions, so add another 4 to pc to get the return address.

  Assembler::BlockTrampolinePoolScope block_trampoline_pool(this);
  static constexpr int kNumInstructionsToJump = 4;
  Label find_ra;
  // Adjust the value in ra to point to the correct return location, 2nd
  // instruction past the real call into C code (the jalr(t9)), and push it.
  // This is the return address of the exit frame.
  if (kArchVariant >= kMips64r6) {
    addiupc(ra, kNumInstructionsToJump + 1);
  } else {
    // This no-op-and-link sequence saves PC + 8 in ra register on pre-r6 MIPS
    nal();  // nal has branch delay slot.
    Daddu(ra, ra, kNumInstructionsToJump * kInstrSize);
  }
  bind(&find_ra);

  // This spot was reserved in EnterExitFrame.
  Sd(ra, MemOperand(sp));
  // Stack space reservation moved to the branch delay slot below.
  // Stack is still aligned.

  // Call the C routine.
  mov(t9, target);  // Function pointer to t9 to conform to ABI for PIC.
  jalr(t9);
  // Set up sp in the delay slot.
  daddiu(sp, sp, -kCArgsSlotsSize);
  // Make sure the stored 'ra' points to this position.
  DCHECK_EQ(kNumInstructionsToJump, InstructionsGeneratedSince(&find_ra));
}

void MacroAssembler::Ret(Condition cond, Register rs, const Operand& rt,
                         BranchDelaySlot bd) {
  Jump(ra, cond, rs, rt, bd);
}

void MacroAssembler::BranchLong(Label* L, BranchDelaySlot bdslot) {
  if (kArchVariant == kMips64r6 && bdslot == PROTECT &&
      (!L->is_bound() || is_near_r6(L))) {
    BranchShortHelperR6(0, L);
  } else {
    // Generate position independent long branch.
    BlockTrampolinePoolScope block_trampoline_pool(this);
    int64_t imm64 = branch_long_offset(L);
    DCHECK(is_int32(imm64));
    int32_t imm32 = static_cast<int32_t>(imm64);
    or_(t8, ra, zero_reg);
    nal();                                        // Read PC into ra register.
    lui(t9, (imm32 & kHiMaskOf32) >> kLuiShift);  // Branch delay slot.
    ori(t9, t9, (imm32 & kImm16Mask));
    daddu(t9, ra, t9);
    if (bdslot == USE_DELAY_SLOT) {
      or_(ra, t8, zero_reg);
    }
    jr(t9);
    // Emit a or_ in the branch delay slot if it's protected.
    if (bdslot == PROTECT) or_(ra, t8, zero_reg);
  }
}

void MacroAssembler::BranchLong(int32_t offset, BranchDelaySlot bdslot) {
  if (kArchVariant == kMips64r6 && bdslot == PROTECT && (is_int26(offset))) {
    BranchShortHelperR6(offset, nullptr);
  } else {
    BlockTrampolinePoolScope block_trampoline_pool(this);
    or_(t8, ra, zero_reg);
    nal();                                         // Read PC into ra register.
    lui(t9, (offset & kHiMaskOf32) >> kLuiShift);  // Branch delay slot.
    ori(t9, t9, (offset & kImm16Mask));
    daddu(t9, ra, t9);
    if (bdslot == USE_DELAY_SLOT) {
      or_(ra, t8, zero_reg);
    }
    jr(t9);
    // Emit a or_ in the branch delay slot if it's protected.
    if (bdslot == PROTECT) or_(ra, t8, zero_reg);
  }
}

void MacroAssembler::BranchAndLinkLong(Label* L, BranchDelaySlot bdslot) {
  if (kArchVariant == kMips64r6 && bdslot == PROTECT &&
      (!L->is_bound() || is_near_r6(L))) {
    BranchAndLinkShortHelperR6(0, L);
  } else {
    // Generate position independent long branch and link.
    BlockTrampolinePoolScope block_trampoline_pool(this);
    int64_t imm64 = branch_long_offset(L);
    DCHECK(is_int32(imm64));
    int32_t imm32 = static_cast<int32_t>(imm64);
    lui(t8, (imm32 & kHiMaskOf32) >> kLuiShift);
    nal();                              // Read PC into ra register.
    ori(t8, t8, (imm32 & kImm16Mask));  // Branch delay slot.
    daddu(t8, ra, t8);
    jalr(t8);
    // Emit a nop in the branch delay slot if required.
    if (bdslot == PROTECT) nop();
  }
}

void MacroAssembler::DropArguments(Register count) {
  Dlsa(sp, sp, count, kPointerSizeLog2);
}

void MacroAssembler::DropArgumentsAndPushNewReceiver(Register argc,
                                                     Register receiver) {
  DCHECK(!AreAliased(argc, receiver));
  DropArguments(argc);
  push(receiver);
}

void MacroAssembler::DropAndRet(int drop) {
  int32_t drop_size = drop * kSystemPointerSize;
  DCHECK(is_int31(drop_size));

  if (is_int16(drop_size)) {
    Ret(USE_DELAY_SLOT);
    daddiu(sp, sp, drop_size);
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    li(scratch, drop_size);
    Ret(USE_DELAY_SLOT);
    daddu(sp, sp, scratch);
  }
}

void MacroAssembler::DropAndRet(int drop, Condition cond, Register r1,
                                const Operand& r2) {
  // Both Drop and Ret need to be conditional.
  Label skip;
  if (cond != cc_always) {
    Branch(&skip, NegateCondition(cond), r1, r2);
  }

  Drop(drop);
  Ret();

  if (cond != cc_always) {
    bind(&skip);
  }
}

void MacroAssembler::Drop(int count, Condition cond, Register reg,
                          const Operand& op) {
  if (count <= 0) {
    return;
  }

  Label skip;

  if (cond != al) {
    Branch(&skip, NegateCondition(cond), reg, op);
  }

  Daddu(sp, sp, Operand(count * kPointerSize));

  if (cond != al) {
    bind(&skip);
  }
}

void MacroAssembler::Swap(Register reg1, Register reg2, Register scratch) {
  if (scratch == no_reg) {
    Xor(reg1, reg1, Operand(reg2));
    Xor(reg2, reg2, Operand(reg1));
    Xor(reg1, reg1, Operand(reg2));
  } else {
    mov(scratch, reg1);
    mov(reg1, reg2);
    mov(reg2, scratch);
  }
}

void MacroAssembler::Call(Label* target) { BranchAndLink(target); }

void MacroAssembler::LoadAddress(Register dst, Label* target) {
  uint64_t address = jump_address(target);
  li(dst, address);
}

void MacroAssembler::LoadAddressPCRelative(Register dst, Label* target) {
  ASM_CODE_COMMENT(this);
  nal();
  // daddiu could handle 16-bit pc offset.
  int32_t offset = branch_offset_helper(target, OffsetSize::kOffset16);
  DCHECK(is_int16(offset));
  mov(t8, ra);
  daddiu(dst, ra, offset);
  mov(ra, t8);
}

void MacroAssembler::Push(Tagged<Smi> smi) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  li(scratch, Operand(smi));
  push(scratch);
}

void MacroAssembler::Push(Handle<HeapObject> handle) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  li(scratch, Operand(handle));
  push(scratch);
}

void MacroAssembler::PushArray(Register array, Register size, Register scratch,
                               Register scratch2, PushArrayOrder order) {
  DCHECK(!AreAliased(array, size, scratch, scratch2));
  Label loop, entry;
  if (order == PushArrayOrder::kReverse) {
    mov(scratch, zero_reg);
    jmp(&entry);
    bind(&loop);
    Dlsa(scratch2, array, scratch, kPointerSizeLog2);
    Ld(scratch2, MemOperand(scratch2));
    push(scratch2);
    Daddu(scratch, scratch, Operand(1));
    bind(&entry);
    Branch(&loop, less, scratch, Operand(size));
  } else {
    mov(scratch, size);
    jmp(&entry);
    bind(&loop);
    Dlsa(scratch2, array, scratch, kPointerSizeLog2);
    Ld(scratch2, MemOperand(scratch2));
    push(scratch2);
    bind(&entry);
    Daddu(scratch, scratch, Operand(-1));
    Branch(&loop, greater_equal, scratch, Operand(zero_reg));
  }
}

// ---------------------------------------------------------------------------
// Exception handling.

void MacroAssembler::PushStackHandler() {
  // Adjust this code if not the case.
  static_assert(StackHandlerConstants::kSize == 2 * kPointerSize);
  static_assert(StackHandlerConstants::kNextOffset == 0 * kPointerSize);

  Push(Smi::zero());  // Padding.

  // Link the current handler as the next handler.
  li(t2,
     ExternalReference::Create(IsolateAddressId::kHandlerAddress, isolate()));
  Ld(t1, MemOperand(t2));
  push(t1);

  // Set this new handler as the current one.
  Sd(sp, MemOperand(t2));
}

void MacroAssembler::PopStackHandler() {
  static_assert(StackHandlerConstants::kNextOffset == 0);
  pop(a1);
  Daddu(sp, sp,
        Operand(
            static_cast<int64_t>(StackHandlerConstants::kSize - kPointerSize)));
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  li(scratch,
     ExternalReference::Create(IsolateAddressId::kHandlerAddress, isolate()));
  Sd(a1, MemOperand(scratch));
}

void MacroAssembler::FPUCanonicalizeNaN(const DoubleRegister dst,
                                        const DoubleRegister src) {
  sub_d(dst, src, kDoubleRegZero);
}

void MacroAssembler::MovFromFloatResult(const DoubleRegister dst) {
  if (IsMipsSoftFloatABI) {
    if (kArchEndian == kLittle) {
      Move(dst, v0, v1);
    } else {
      Move(dst, v1, v0);
    }
  } else {
    Move(dst, f0);  // Reg f0 is o32 ABI FP return value.
  }
}

void MacroAssembler::MovFromFloatParameter(const DoubleRegister dst) {
  if (IsMipsSoftFloatABI) {
    if (kArchEndian == kLittle) {
      Move(dst, a0, a1);
    } else {
      Move(dst, a1, a0);
    }
  } else {
    Move(dst, f12);  // Reg f12 is n64 ABI FP first argument value.
  }
}

void MacroAssembler::MovToFloatParameter(DoubleRegister src) {
  if (!IsMipsSoftFloatABI) {
    Move(f12, src);
  } else {
    if (kArchEndian == kLittle) {
      Move(a0, a1, src);
    } else {
      Move(a1, a0, src);
    }
  }
}

void MacroAssembler::MovToFloatResult(DoubleRegister src) {
  if (!IsMipsSoftFloatABI) {
    Move(f0, src);
  } else {
    if (kArchEndian == kLittle) {
      Move(v0, v1, src);
    } else {
      Move(v1, v0, src);
    }
  }
}

void MacroAssembler::MovToFloatParameters(DoubleRegister src1,
                                          DoubleRegister src2) {
  if (!IsMipsSoftFloatABI) {
    const DoubleRegister fparg2 = f13;
    if (src2 == f12) {
      DCHECK(src1 != fparg2);
      Move(fparg2, src2);
      Move(f12, src1);
    } else {
      Move(f12, src1);
      Move(fparg2, src2);
    }
  } else {
    if (kArchEndian == kLittle) {
      Move(a0, a1, src1);
      Move(a2, a3, src2);
    } else {
      Move(a1, a0, src1);
      Move(a3, a2, src2);
    }
  }
}

// -----------------------------------------------------------------------------
// JavaScript invokes.

void MacroAssembler::LoadStackLimit(Register destination, StackLimitKind kind) {
  ASM_CODE_COMMENT(this);
  DCHECK(root_array_available());
  intptr_t offset = kind == StackLimitKind::kRealStackLimit
                        ? IsolateData::real_jslimit_offset()
                        : IsolateData::jslimit_offset();

  Ld(destination, MemOperand(kRootRegister, static_cast<int32_t>(offset)));
}

void MacroAssembler::StackOverflowCheck(Register num_args, Register scratch1,
                                        Register scratch2,
                                        Label* stack_overflow) {
  ASM_CODE_COMMENT(this);
  // Check the stack for overflow. We are not trying to catch
  // interruptions (e.g. debug break and preemption) here, so the "real stack
  // limit" is checked.

  LoadStackLimit(scratch1, StackLimitKind::kRealStackLimit);
  // Make scratch1 the space we have left. The stack might already be overflowed
  // here which will cause scratch1 to become negative.
  dsubu(scratch1, sp, scratch1);
  // Check if the arguments will overflow the stack.
  dsll(scratch2, num_args, kPointerSizeLog2);
  // Signed comparison.
  Branch(stack_overflow, le, scratch1, Operand(scratch2));
}

#ifdef V8_ENABLE_LEAPTIERING
void MacroAssembler::LoadCodeEntrypointFromJSDispatchTable(
    Register destination, MemOperand field_operand) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  DCHECK(!AreAliased(destination, scratch));
  DCHECK_EQ(JSDispatchEntry::kEntrypointOffset, 0);

  li(scratch, ExternalReference::js_dispatch_table_address());
  Lwu(destination, field_operand);
  dsrl(destination, destination, kJSDispatchHandleShift);
  dsll(destination, destination, kJSDispatchTableEntrySizeLog2);
  Ld(destination, MemOperand(scratch, destination));
}
#endif

void MacroAssembler::TestCodeIsMarkedForDeoptimizationAndJump(
    Register code_data_container, Register scratch, Condition cond,
    Label* target) {
  Lwu(scratch, FieldMemOperand(code_data_container, Code::kFlagsOffset));
  And(scratch, scratch, Operand(1 << Code::kMarkedForDeoptimizationBit));
  Branch(target, cond, scratch, Operand(zero_reg));
}

Operand MacroAssembler::ClearedValue() const {
  return Operand(static_cast<int32_t>(i::ClearedValue(isolate()).ptr()));
}

void MacroAssembler::InvokePrologue(Register expected_parameter_count,
                                    Register actual_parameter_count,
                                    Label* done, InvokeType type) {
  ASM_CODE_COMMENT(this);
  Label regular_invoke;

  //  a0: actual arguments count
  //  a1: function (passed through to callee)
  //  a2: expected arguments count

  DCHECK_EQ(actual_parameter_count, a0);
  DCHECK_EQ(expected_parameter_count, a2);

  // If overapplication or if the actual argument count is equal to the
  // formal parameter count, no need to push extra undefined values.
  Dsubu(expected_parameter_count, expected_parameter_count,
        actual_parameter_count);
  Branch(&regular_invoke, le, expected_parameter_count, Operand(zero_reg));

  Label stack_overflow;
  StackOverflowCheck(expected_parameter_count, t0, t1, &stack_overflow);
  // Underapplication. Move the arguments already in the stack, including the
  // receiver and the return address.
  {
    Label copy;
    Register src = a6, dest = a7;
    mov(src, sp);
    dsll(t0, expected_parameter_count, kSystemPointerSizeLog2);
    Dsubu(sp, sp, Operand(t0));
    // Update stack pointer.
    mov(dest, sp);
    mov(t0, actual_parameter_count);
    bind(&copy);
    Ld(t1, MemOperand(src, 0));
    Sd(t1, MemOperand(dest, 0));
    Dsubu(t0, t0, Operand(1));
    Daddu(src, src, Operand(kSystemPointerSize));
    Daddu(dest, dest, Operand(kSystemPointerSize));
    Branch(&copy, gt, t0, Operand(zero_reg));
  }

  // Fill remaining expected arguments with undefined values.
  LoadRoot(t0, RootIndex::kUndefinedValue);
  {
    Label loop;
    bind(&loop);
    Sd(t0, MemOperand(a7, 0));
    Dsubu(expected_parameter_count, expected_parameter_count, Operand(1));
    Daddu(a7, a7, Operand(kSystemPointerSize));
    Branch(&loop, gt, expected_parameter_count, Operand(zero_reg));
  }
  b(&regular_invoke);
  nop();

  bind(&stack_overflow);
  {
    FrameScope frame(
        this, has_frame() ? StackFrame::NO_FRAME_TYPE : StackFrame::INTERNAL);
    CallRuntime(Runtime::kThrowStackOverflow);
    break_(0xCC);
  }

  bind(&regular_invoke);
}

void MacroAssembler::CheckDebugHook(Register fun, Register new_target,
                                    Register expected_parameter_count,
                                    Register actual_parameter_count) {
  Label skip_hook;

  li(t0, ExternalReference::debug_hook_on_function_call_address(isolate()));
  Lb(t0, MemOperand(t0));
  Branch(&skip_hook, eq, t0, Operand(zero_reg));

  {
    // Load receiver to pass it later to DebugOnFunctionCall hook.
    LoadReceiver(t0);

    FrameScope frame(
        this, has_frame() ? StackFrame::NO_FRAME_TYPE : StackFrame::INTERNAL);
    SmiTag(expected_parameter_count);
    Push(expected_parameter_count);

    SmiTag(actual_parameter_count);
    Push(actual_parameter_count);

    if (new_target.is_valid()) {
      Push(new_target);
    }
    Push(fun);
    Push(fun);
    Push(t0);
    CallRuntime(Runtime::kDebugOnFunctionCall);
    Pop(fun);
    if (new_target.is_valid()) {
      Pop(new_target);
    }

    Pop(actual_parameter_count);
    SmiUntag(actual_parameter_count);

    Pop(expected_parameter_count);
    SmiUntag(expected_parameter_count);
  }
  bind(&skip_hook);
}

void MacroAssembler::InvokeFunctionCode(Register function, Register new_target,
                                        Register expected_parameter_count,
                                        Register actual_parameter_count,
                                        InvokeType type) {
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());
  DCHECK_EQ(function, a1);
  DCHECK_IMPLIES(new_target.is_valid(), new_target == a3);

  // On function call, call into the debugger if necessary.
  CheckDebugHook(function, new_target, expected_parameter_count,
                 actual_parameter_count);

  // Clear the new.target register if not given.
  if (!new_target.is_valid()) {
    LoadRoot(a3, RootIndex::kUndefinedValue);
  }

  Label done;
  InvokePrologue(expected_parameter_count, actual_parameter_count, &done, type);
  // We call indirectly through the code field in the function to
  // allow recompilation to take effect without changing any of the
  // call sites.
  switch (type) {
    case InvokeType::kCall:
      CallJSFunction(function);
      break;
    case InvokeType::kJump:
      JumpJSFunction(function);
      break;
  }

  // Continue here if InvokePrologue does handle the invocation due to
  // mismatched parameter counts.
  bind(&done);
}

void MacroAssembler::InvokeFunctionWithNewTarget(
    Register function, Register new_target, Register actual_parameter_count,
    InvokeType type) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());

  // Contract with called JS functions requires that function is passed in a1.
  DCHECK_EQ(function, a1);
  Register expected_parameter_count = a2;
  Register temp_reg = t0;
  Ld(temp_reg, FieldMemOperand(a1, JSFunction::kSharedFunctionInfoOffset));
  Ld(cp, FieldMemOperand(a1, JSFunction::kContextOffset));
  // The argument count is stored as uint16_t
  Lhu(expected_parameter_count,
      FieldMemOperand(temp_reg,
                      SharedFunctionInfo::kFormalParameterCountOffset));

  InvokeFunctionCode(a1, new_target, expected_parameter_count,
                     actual_parameter_count, type);
}

void MacroAssembler::InvokeFunction(Register function,
                                    Register expected_parameter_count,
                                    Register actual_parameter_count,
                                    InvokeType type) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());

  // Contract with called JS functions requires that function is passed in a1.
  DCHECK_EQ(function, a1);

  // Get the function and setup the context.
  Ld(cp, FieldMemOperand(a1, JSFunction::kContextOffset));

  InvokeFunctionCode(a1, no_reg, expected_parameter_count,
                     actual_parameter_count, type);
}

// ---------------------------------------------------------------------------
// Support functions.

void MacroAssembler::GetObjectType(Register object, Register map,
                                   Register type_reg) {
  LoadMap(map, object);
  Lhu(type_reg, FieldMemOperand(map, Map::kInstanceTypeOffset));
}

void MacroAssembler::GetInstanceTypeRange(Register map, Register type_reg,
                                          InstanceType lower_limit,
                                          Register range) {
  Lhu(type_reg, FieldMemOperand(map, Map::kInstanceTypeOffset));
  Dsubu(range, type_reg, Operand(lower_limit));
}

// -----------------------------------------------------------------------------
// Runtime calls.

void MacroAssembler::DaddOverflow(Register dst, Register left,
                                  const Operand& right, Register overflow) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register right_reg = no_reg;
  Register scratch = t8;
  if (!right.is_reg()) {
    li(at, Operand(right));
    right_reg = at;
  } else {
    right_reg = right.rm();
  }

  DCHECK(left != scratch && right_reg != scratch && dst != scratch &&
         overflow != scratch);
  DCHECK(overflow != left && overflow != right_reg);

  if (dst == left || dst == right_reg) {
    daddu(scratch, left, right_reg);
    xor_(overflow, scratch, left);
    xor_(at, scratch, right_reg);
    and_(overflow, overflow, at);
    mov(dst, scratch);
  } else {
    daddu(dst, left, right_reg);
    xor_(overflow, dst, left);
    xor_(at, dst, right_reg);
    and_(overflow, overflow, at);
  }
}

void MacroAssembler::DsubOverflow(Register dst, Register left,
                                  const Operand& right, Register overflow) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register right_reg = no_reg;
  Register scratch = t8;
  if (!right.is_reg()) {
    li(at, Operand(right));
    right_reg = at;
  } else {
    right_reg = right.rm();
  }

  DCHECK(left != scratch && right_reg != scratch && dst != scratch &&
         overflow != scratch);
  DCHECK(overflow != left && overflow != right_reg);

  if (dst == left || dst == right_reg) {
    dsubu(scratch, left, right_reg);
    xor_(overflow, left, scratch);
    xor_(at, left, right_reg);
    and_(overflow, overflow, at);
    mov(dst, scratch);
  } else {
    dsubu(dst, left, right_reg);
    xor_(overflow, left, dst);
    xor_(at, left, right_reg);
    and_(overflow, overflow, at);
  }
}

void MacroAssembler::MulOverflow(Register dst, Register left,
                                 const Operand& right, Register overflow) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register right_reg = no_reg;
  Register scratch = t8;
  if (!right.is_reg()) {
    li(at, Operand(right));
    right_reg = at;
  } else {
    right_reg = right.rm();
  }

  DCHECK(left != scratch && right_reg != scratch && dst != scratch &&
         overflow != scratch);
  DCHECK(overflow != left && overflow != right_reg);

  if (dst == left || dst == right_reg) {
    Mul(scratch, left, right_reg);
    Mulh(overflow, left, right_reg);
    mov(dst, scratch);
  } else {
    Mul(dst, left, right_reg);
    Mulh(overflow, left, right_reg);
  }

  dsra32(scratch, dst, 0);
  xor_(overflow, overflow, scratch);
}

void MacroAssembler::DMulOverflow(Register dst, Register left,
                                  const Operand& right, Register overflow) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register right_reg = no_reg;
  Register scratch = t8;
  if (!right.is_reg()) {
    li(at, Operand(right));
    right_reg = at;
  } else {
    right_reg = right.rm();
  }

  DCHECK(left != scratch && right_reg != scratch && dst != scratch &&
         overflow != scratch);
  DCHECK(overflow != left && overflow != right_reg);

  if (dst == left || dst == right_reg) {
    Dmul(scratch, left, right_reg);
    Dmulh(overflow, left, right_reg);
    mov(dst, scratch);
  } else {
    Dmul(dst, left, right_reg);
    Dmulh(overflow, left, right_reg);
  }

  dsra32(scratch, dst, 31);
  xor_(overflow, overflow, scratch);
}

void MacroAssembler::CallRuntime(const Runtime::Function* f,
                                 int num_arguments) {
  ASM_CODE_COMMENT(this);
  // All parameters are on the stack. v0 has the return value after call.

  // If the expected number of arguments of the runtime function is
  // constant, we check that the actual number of arguments match the
  // expectation.
  CHECK(f->nargs < 0 || f->nargs == num_arguments);

  // TODO(1236192): Most runtime routines don't need the number of
  // arguments passed in because it is constant. At some point we
  // should remove this need and make the runtime routine entry code
  // smarter.
  PrepareCEntryArgs(num_arguments);
  PrepareCEntryFunction(ExternalReference::Create(f));
  CallBuiltin(Builtins::RuntimeCEntry(f->result_size));
}

void MacroAssembler::TailCallRuntime(Runtime::FunctionId fid) {
  ASM_CODE_COMMENT(this);
  const Runtime::Function* function = Runtime::FunctionForId(fid);
  DCHECK_EQ(1, function->result_size);
  if (function->nargs >= 0) {
    PrepareCEntryArgs(function->nargs);
  }
  JumpToExternalReference(ExternalReference::Create(fid));
}

void MacroAssembler::JumpToExternalReference(const ExternalReference& builtin,
                                             bool builtin_exit_frame) {
  PrepareCEntryFunction(builtin);
  TailCallBuiltin(Builtins::CEntry(1, ArgvMode::kStack, builtin_exit_frame));
}

void MacroAssembler::LoadWeakValue(Register out, Register in,
                                   Label* target_if_cleared) {
  Branch(target_if_cleared, eq, in, Operand(kClearedWeakHeapObjectLower32));

  And(out, in, Operand(~kWeakHeapObjectMask));
}

void MacroAssembler::EmitIncrementCounter(StatsCounter* counter, int value,
                                          Register scratch1,
                                          Register scratch2) {
  DCHECK_GT(value, 0);
  if (v8_flags.native_code_counters && counter->Enabled()) {
    ASM_CODE_COMMENT(this);
    // This operation has to be exactly 32-bit wide in case the external
    // reference table redirects the counter to a uint32_t dummy_stats_counter_
    // field.
    li(scratch2, ExternalReference::Create(counter));
    Lw(scratch1, MemOperand(scratch2));
    Addu(scratch1, scratch1, Operand(value));
    Sw(scratch1, MemOperand(scratch2));
  }
}

void MacroAssembler::EmitDecrementCounter(StatsCounter* counter, int value,
                                          Register scratch1,
                                          Register scratch2) {
  DCHECK_GT(value, 0);
  if (v8_flags.native_code_counters && counter->Enabled()) {
    ASM_CODE_COMMENT(this);
    // This operation has to be exactly 32-bit wide in case the external
    // reference table redirects the counter to a uint32_t dummy_stats_counter_
    // field.
    li(scratch2, ExternalReference::Create(counter));
    Lw(scratch1, MemOperand(scratch2));
    Subu(scratch1, scratch1, Operand(value));
    Sw(scratch1, MemOperand(scratch2));
  }
}

// -----------------------------------------------------------------------------
// Debugging.

void MacroAssembler::Trap() { stop(); }
void MacroAssembler::DebugBreak() { stop(); }

void MacroAssembler::Check(Condition cc, AbortReason reason, Register rs,
                           Operand rt) {
  Label L;
  Branch(&L, cc, rs, rt);
  Abort(reason);
  // Will not return here.
  bind(&L);
}

void MacroAssembler::Abort(AbortReason reason) {
  Label abort_start;
  bind(&abort_start);
  if (v8_flags.code_comments) {
    const char* msg = GetAbortReason(reason);
    RecordComment("Abort message: ");
    RecordComment(msg);
  }

  // Avoid emitting call to builtin if requested.
  if (trap_on_abort()) {
    stop();
    return;
  }

  if (should_abort_hard()) {
    // We don't care if we constructed a frame. Just pretend we did.
    FrameScope assume_frame(this, StackFrame::NO_FRAME_TYPE);
    PrepareCallCFunction(1, a0);
    li(a0, Operand(static_cast<int>(reason)));
    li(a1, ExternalReference::abort_with_reason());
    // Use Call directly to avoid any unneeded overhead. The function won't
    // return anyway.
    Call(a1);
    return;
  }

  Move(a0, Smi::FromInt(static_cast<int>(reason)));

  {
    // We don't actually want to generate a pile of code for this, so just
    // claim there is a stack frame, without generating one.
    FrameScope scope(this, StackFrame::NO_FRAME_TYPE);
    if (root_array_available()) {
      // Generate an indirect call via builtins entry table here in order to
      // ensure that the interpreter_entry_return_pc_offset is the same for
      // InterpreterEntryTrampoline and InterpreterEntryTrampolineForProfiling
      // when v8_flags.debug_code is enabled.
      LoadEntryFromBuiltin(Builtin::kAbort, t9);
      Call(t9);
    } else {
      CallBuiltin(Builtin::kAbort);
    }
  }
  // Will not return here.
  if (is_trampoline_pool_blocked()) {
    // If the calling code cares about the exact number of
    // instructions generated, we insert padding here to keep the size
    // of the Abort macro constant.
    // Currently in debug mode with debug_code enabled the number of
    // generated instructions is 10, so we use this as a maximum value.
    static const int kExpectedAbortInstructions = 10;
    int abort_instructions = InstructionsGeneratedSince(&abort_start);
    DCHECK_LE(abort_instructions, kExpectedAbortInstructions);
    while (abort_instructions++ < kExpectedAbortInstructions) {
      nop();
    }
  }
}

void MacroAssembler::LoadMap(Register destination, Register object) {
  Ld(destination, FieldMemOperand(object, HeapObject::kMapOffset));
}

void MacroAssembler::LoadFeedbackVector(Register dst, Register closure,
                                        Register scratch, Label* fbv_undef) {
  Label done;
  // Load the feedback vector from the closure.
  Ld(dst, FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
  Ld(dst, FieldMemOperand(dst, FeedbackCell::kValueOffset));

  // Check if feedback vector is valid.
  Ld(scratch, FieldMemOperand(dst, HeapObject::kMapOffset));
  Lhu(scratch, FieldMemOperand(scratch, Map::kInstanceTypeOffset));
  Branch(&done, eq, scratch, Operand(FEEDBACK_VECTOR_TYPE));

  // Not valid, load undefined.
  LoadRoot(dst, RootIndex::kUndefinedValue);
  Branch(fbv_undef);

  bind(&done);
}

void MacroAssembler::LoadNativeContextSlot(Register dst, int index) {
  LoadMap(dst, cp);
  Ld(dst,
     FieldMemOperand(dst, Map::kConstructorOrBackPointerOrNativeContextOffset));
  Ld(dst, MemOperand(dst, Context::SlotOffset(index)));
}

void MacroAssembler::StubPrologue(StackFrame::Type type) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  li(scratch, Operand(StackFrame::TypeToMarker(type)));
  PushCommonFrame(scratch);
}

void MacroAssembler::Prologue() { PushStandardFrame(a1); }

void MacroAssembler::EnterFrame(StackFrame::Type type) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Push(ra, fp);
  Move(fp, sp);
  if (!StackFrame::IsJavaScript(type)) {
    li(kScratchReg, Operand(StackFrame::TypeToMarker(type)));
    Push(kScratchReg);
  }
#if V8_ENABLE_WEBASSEMBLY
  if (type == StackFrame::WASM || type == StackFrame::WASM_LIFTOFF_SETUP) {
    Push(kWasmImplicitArgRegister);
  }
#endif  // V8_ENABLE_WEBASSEMBLY
}

void MacroAssembler::LeaveFrame(StackFrame::Type type) {
  ASM_CODE_COMMENT(this);
  daddiu(sp, fp, 2 * kPointerSize);
  Ld(ra, MemOperand(fp, 1 * kPointerSize));
  Ld(fp, MemOperand(fp, 0 * kPointerSize));
}

void MacroAssembler::EnterExitFrame(Register scratch, int stack_space,
                                    StackFrame::Type frame_type) {
  ASM_CODE_COMMENT(this);
  DCHECK(frame_type == StackFrame::EXIT ||
         frame_type == StackFrame::BUILTIN_EXIT ||
         frame_type == StackFrame::API_ACCESSOR_EXIT ||
         frame_type == StackFrame::API_CALLBACK_EXIT);

  using ER = ExternalReference;

  // Set up the frame structure on the stack.
  static_assert(2 * kPointerSize == ExitFrameConstants::kCallerSPDisplacement);
  static_assert(1 * kPointerSize == ExitFrameConstants::kCallerPCOffset);
  static_assert(0 * kPointerSize == ExitFrameConstants::kCallerFPOffset);

  // This is how the stack will look:
  // fp + 2 (==kCallerSPDisplacement) - old stack's end
  // [fp + 1 (==kCallerPCOffset)] - saved old ra
  // [fp + 0 (==kCallerFPOffset)] - saved old fp
  // [fp - 1 frame_type Smi
  // [fp - 2 (==kSPOffset)] - sp of the called function
  // fp - (2 + stack_space + alignment) == sp == [fp - kSPOffset] - top of the
  //   new stack (will contain saved ra)

  // Save registers and reserve room for saved entry sp.
  daddiu(sp, sp, -2 * kPointerSize - ExitFrameConstants::kFixedFrameSizeFromFp);
  Sd(ra, MemOperand(sp, 3 * kPointerSize));
  Sd(fp, MemOperand(sp, 2 * kPointerSize));
  li(scratch, Operand(StackFrame::TypeToMarker(frame_type)));
  Sd(scratch, MemOperand(sp, 1 * kPointerSize));

  // Set up new frame pointer.
  daddiu(fp, sp, ExitFrameConstants::kFixedFrameSizeFromFp);

  if (v8_flags.debug_code) {
    Sd(zero_reg, MemOperand(fp, ExitFrameConstants::kSPOffset));
  }

  // Save the frame pointer and the context in top.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, isolate());
  Sd(fp, ExternalReferenceAsOperand(c_entry_fp_address, no_reg));

  ER context_address = ER::Create(IsolateAddressId::kContextAddress, isolate());
  Sd(cp, ExternalReferenceAsOperand(context_address, no_reg));

  const int frame_alignment = MacroAssembler::ActivationFrameAlignment();

  // Reserve place for the return address, stack space and align the frame
  // preparing for calling the runtime function.
  DCHECK_GE(stack_space, 0);
  Dsubu(sp, sp, Operand((stack_space + 1) * kPointerSize));
  if (frame_alignment > 0) {
    DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
    And(sp, sp, Operand(-frame_alignment));  // Align stack.
  }

  // Set the exit frame sp value to point just before the return address
  // location.
  daddiu(scratch, sp, kPointerSize);
  Sd(scratch, MemOperand(fp, ExitFrameConstants::kSPOffset));
}

void MacroAssembler::LeaveExitFrame(Register scratch) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);

  using ER = ExternalReference;

  // Restore current context from top and clear it in debug mode.
  ER context_address = ER::Create(IsolateAddressId::kContextAddress, isolate());
  Ld(cp, ExternalReferenceAsOperand(context_address, no_reg));

  if (v8_flags.debug_code) {
    li(scratch, Operand(Context::kInvalidContext));
    Sd(scratch, ExternalReferenceAsOperand(context_address, no_reg));
  }

  // Clear the top frame.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, isolate());
  Sd(zero_reg, ExternalReferenceAsOperand(c_entry_fp_address, no_reg));

  // Pop the arguments, restore registers, and return.
  mov(sp, fp);  // Respect ABI stack constraint.
  Ld(fp, MemOperand(sp, ExitFrameConstants::kCallerFPOffset));
  Ld(ra, MemOperand(sp, ExitFrameConstants::kCallerPCOffset));

  daddiu(sp, sp, 2 * kPointerSize);
}

int MacroAssembler::ActivationFrameAlignment() {
#if V8_HOST_ARCH_MIPS || V8_HOST_ARCH_MIPS64
  // Running on the real platform. Use the alignment as mandated by the local
  // environment.
  // Note: This will break if we ever start generating snapshots on one Mips
  // platform for another Mips platform with a different alignment.
  return base::OS::ActivationFrameAlignment();
#else   // V8_HOST_ARCH_MIPS
  // If we are using the simulator then we should always align to the expected
  // alignment. As the simulator is used to generate snapshots we do not know
  // if the target platform will need alignment, so this is controlled from a
  // flag.
  return v8_flags.sim_stack_alignment;
#endif  // V8_HOST_ARCH_MIPS
}

void MacroAssembler::SmiUntag(Register dst, const MemOperand& src) {
  if (SmiValuesAre32Bits()) {
    Lw(dst, MemOperand(src.rm(), SmiWordOffset(src.offset())));
  } else {
    DCHECK(SmiValuesAre31Bits());
    Lw(dst, src);
    SmiUntag(dst);
  }
}

void MacroAssembler::JumpIfSmi(Register value, Label* smi_label,
                               BranchDelaySlot bd) {
  DCHECK_EQ(0, kSmiTag);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  andi(scratch, value, kSmiTagMask);
  Branch(bd, smi_label, eq, scratch, Operand(zero_reg));
}

void MacroAssembler::JumpIfNotSmi(Register value, Label* not_smi_label,
                                  BranchDelaySlot bd) {
  DCHECK_EQ(0, kSmiTag);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  andi(scratch, value, kSmiTagMask);
  Branch(bd, not_smi_label, ne, scratch, Operand(zero_reg));
}

#ifdef V8_ENABLE_DEBUG_CODE

void MacroAssembler::Assert(Condition cc, AbortReason reason, Register rs,
                            Operand rt) {
  if (v8_flags.debug_code) Check(cc, reason, rs, rt);
}

void MacroAssembler::AssertJSAny(Register object, Register map_tmp,
                                 Register tmp, AbortReason abort_reason) {
  if (!v8_flags.debug_code) return;

  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(object, map_tmp, tmp));
  Label ok;

  JumpIfSmi(object, &ok);

  GetObjectType(object, map_tmp, tmp);

  Branch(&ok, kUnsignedLessThanEqual, tmp, Operand(LAST_NAME_TYPE));

  Branch(&ok, kUnsignedGreaterThanEqual, tmp, Operand(FIRST_JS_RECEIVER_TYPE));

  Branch(&ok, kEqual, map_tmp, RootIndex::kHeapNumberMap);

  Branch(&ok, kEqual, map_tmp, RootIndex::kBigIntMap);

  Branch(&ok, kEqual, object, RootIndex::kUndefinedValue);

  Branch(&ok, kEqual, object, RootIndex::kTrueValue);

  Branch(&ok, kEqual, object, RootIndex::kFalseValue);

  Branch(&ok, kEqual, object, RootIndex::kNullValue);

  Abort(abort_reason);
  bind(&ok);
}

void MacroAssembler::AssertNotSmi(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    static_assert(kSmiTag == 0);
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    andi(scratch, object, kSmiTagMask);
    Check(ne, AbortReason::kOperandIsASmi, scratch, Operand(zero_reg));
  }
}

void MacroAssembler::AssertSmi(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    static_assert(kSmiTag == 0);
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    andi(scratch, object, kSmiTagMask);
    Check(eq, AbortReason::kOperandIsASmi, scratch, Operand(zero_reg));
  }
}

void MacroAssembler::AssertStackIsAligned() {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    const int frame_alignment = ActivationFrameAlignment();
    const int frame_alignment_mask = frame_alignment - 1;

    if (frame_alignment > kPointerSize) {
      Label alignment_as_expected;
      DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
      {
        UseScratchRegisterScope temps(this);
        Register scratch = temps.Acquire();
        andi(scratch, sp, frame_alignment_mask);
        Branch(&alignment_as_expected, eq, scratch, Operand(zero_reg));
      }
      // Don't use Check here, as it will call Runtime_Abort re-entering here.
      stop();
      bind(&alignment_as_expected);
    }
  }
}

void MacroAssembler::AssertConstructor(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    static_assert(kSmiTag == 0);
    SmiTst(object, t8);
    Check(ne, AbortReason::kOperandIsASmiAndNotAConstructor, t8,
          Operand(zero_reg));

    LoadMap(t8, object);
    Lbu(t8, FieldMemOperand(t8, Map::kBitFieldOffset));
    And(t8, t8, Operand(Map::Bits1::IsConstructorBit::kMask));
    Check(ne, AbortReason::kOperandIsNotAConstructor, t8, Operand(zero_reg));
  }
}

void MacroAssembler::AssertFunction(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    static_assert(kSmiTag == 0);
    SmiTst(object, t8);
    Check(ne, AbortReason::kOperandIsASmiAndNotAFunction, t8,
          Operand(zero_reg));
    push(object);
    LoadMap(object, object);
    GetInstanceTypeRange(object, object, FIRST_JS_FUNCTION_TYPE, t8);
    Check(ls, AbortReason::kOperandIsNotAFunction, t8,
          Operand(LAST_JS_FUNCTION_TYPE - FIRST_JS_FUNCTION_TYPE));
    pop(object);
  }
}

void MacroAssembler::AssertCallableFunction(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    static_assert(kSmiTag == 0);
    SmiTst(object, t8);
    Check(ne, AbortReason::kOperandIsASmiAndNotAFunction, t8,
          Operand(zero_reg));
    push(object);
    LoadMap(object, object);
    GetInstanceTypeRange(object, object, FIRST_CALLABLE_JS_FUNCTION_TYPE, t8);
    Check(ls, AbortReason::kOperandIsNotACallableFunction, t8,
          Operand(LAST_CALLABLE_JS_FUNCTION_TYPE -
                  FIRST_CALLABLE_JS_FUNCTION_TYPE));
    pop(object);
  }
}

void MacroAssembler::AssertBoundFunction(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    static_assert(kSmiTag == 0);
    SmiTst(object, t8);
    Check(ne, AbortReason::kOperandIsASmiAndNotABoundFunction, t8,
          Operand(zero_reg));
    GetObjectType(object, t8, t8);
    Check(eq, AbortReason::kOperandIsNotABoundFunction, t8,
          Operand(JS_BOUND_FUNCTION_TYPE));
  }
}

void MacroAssembler::AssertGeneratorObject(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  static_assert(kSmiTag == 0);
  SmiTst(object, t8);
  Check(ne, AbortReason::kOperandIsASmiAndNotAGeneratorObject, t8,
        Operand(zero_reg));
  GetObjectType(object, t8, t8);
  Dsubu(t8, t8, Operand(FIRST_JS_GENERATOR_OBJECT_TYPE));
  Check(
      ls, AbortReason::kOperandIsNotAGeneratorObject, t8,
      Operand(LAST_JS_GENERATOR_OBJECT_TYPE - FIRST_JS_GENERATOR_OBJECT_TYPE));
}

void MacroAssembler::AssertUndefinedOrAllocationSite(Register object,
                                                     Register scratch) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    Label done_checking;
    AssertNotSmi(object);
    LoadRoot(scratch, RootIndex::kUndefinedValue);
    Branch(&done_checking, eq, object, Operand(scratch));
    GetObjectType(object, scratch, scratch);
    Assert(eq, AbortReason::kExpectedUndefinedOrCell, scratch,
           Operand(ALLOCATION_SITE_TYPE));
    bind(&done_checking);
  }
}

#endif  // V8_ENABLE_DEBUG_CODE

void MacroAssembler::Float32Max(FPURegister dst, FPURegister src1,
                                FPURegister src2, Label* out_of_line) {
  ASM_CODE_COMMENT(this);
  if (src1 == src2) {
    Move_s(dst, src1);
    return;
  }

  // Check if one of operands is NaN.
  CompareIsNanF32(src1, src2);
  BranchTrueF(out_of_line);

  if (kArchVariant >= kMips64r6) {
    max_s(dst, src1, src2);
  } else {
    Label return_left, return_right, done;

    CompareF32(OLT, src1, src2);
    BranchTrueShortF(&return_right);
    CompareF32(OLT, src2, src1);
    BranchTrueShortF(&return_left);

    // Operands are equal, but check for +/-0.
    {
      BlockTrampolinePoolScope block_trampoline_pool(this);
      mfc1(t8, src1);
      dsll32(t8, t8, 0);
      Branch(&return_left, eq, t8, Operand(zero_reg));
      Branch(&return_right);
    }

    bind(&return_right);
    if (src2 != dst) {
      Move_s(dst, src2);
    }
    Branch(&done);

    bind(&return_left);
    if (src1 != dst) {
      Move_s(dst, src1);
    }

    bind(&done);
  }
}

void MacroAssembler::Float32MaxOutOfLine(FPURegister dst, FPURegister src1,
                                         FPURegister src2) {
  add_s(dst, src1, src2);
}

void MacroAssembler::Float32Min(FPURegister dst, FPURegister src1,
                                FPURegister src2, Label* out_of_line) {
  ASM_CODE_COMMENT(this);
  if (src1 == src2) {
    Move_s(dst, src1);
    return;
  }

  // Check if one of operands is NaN.
  CompareIsNanF32(src1, src2);
  BranchTrueF(out_of_line);

  if (kArchVariant >= kMips64r6) {
    min_s(dst, src1, src2);
  } else {
    Label return_left, return_right, done;

    CompareF32(OLT, src1, src2);
    BranchTrueShortF(&return_left);
    CompareF32(OLT, src2, src1);
    BranchTrueShortF(&return_right);

    // Left equals right => check for -0.
    {
      BlockTrampolinePoolScope block_trampoline_pool(this);
      mfc1(t8, src1);
      dsll32(t8, t8, 0);
      Branch(&return_right, eq, t8, Operand(zero_reg));
      Branch(&return_left);
    }

    bind(&return_right);
    if (src2 != dst) {
      Move_s(dst, src2);
    }
    Branch(&done);

    bind(&return_left);
    if (src1 != dst) {
      Move_s(dst, src1);
    }

    bind(&done);
  }
}

void MacroAssembler::Float32MinOutOfLine(FPURegister dst, FPURegister src1,
                                         FPURegister src2) {
  add_s(dst, src1, src2);
}

void MacroAssembler::Float64Max(FPURegister dst, FPURegister src1,
                                FPURegister src2, Label* out_of_line) {
  ASM_CODE_COMMENT(this);
  if (src1 == src2) {
    Move_d(dst, src1);
    return;
  }

  // Check if one of operands is NaN.
  CompareIsNanF64(src1, src2);
  BranchTrueF(out_of_line);

  if (kArchVariant >= kMips64r6) {
    max_d(dst, src1, src2);
  } else {
    Label return_left, return_right, done;

    CompareF64(OLT, src1, src2);
    BranchTrueShortF(&return_right);
    CompareF64(OLT, src2, src1);
    BranchTrueShortF(&return_left);

    // Left equals right => check for -0.
    {
      BlockTrampolinePoolScope block_trampoline_pool(this);
      dmfc1(t8, src1);
      Branch(&return_left, eq, t8, Operand(zero_reg));
      Branch(&return_right);
    }

    bind(&return_right);
    if (src2 != dst) {
      Move_d(dst, src2);
    }
    Branch(&done);

    bind(&return_left);
    if (src1 != dst) {
      Move_d(dst, src1);
    }

    bind(&done);
  }
}

void MacroAssembler::Float64MaxOutOfLine(FPURegister dst, FPURegister src1,
                                         FPURegister src2) {
  add_d(dst, src1, src2);
}

void MacroAssembler::Float64Min(FPURegister dst, FPURegister src1,
                                FPURegister src2, Label* out_of_line) {
  ASM_CODE_COMMENT(this);
  if (src1 == src2) {
    Move_d(dst, src1);
    return;
  }

  // Check if one of operands is NaN.
  CompareIsNanF64(src1, src2);
  BranchTrueF(out_of_line);

  if (kArchVariant >= kMips64r6) {
    min_d(dst, src1, src2);
  } else {
    Label return_left, return_right, done;

    CompareF64(OLT, src1, src2);
    BranchTrueShortF(&return_left);
    CompareF64(OLT, src2, src1);
    BranchTrueShortF(&return_right);

    // Left equals right => check for -0.
    {
      BlockTrampolinePoolScope block_trampoline_pool(this);
      dmfc1(t8, src1);
      Branch(&return_right, eq, t8, Operand(zero_reg));
      Branch(&return_left);
    }

    bind(&return_right);
    if (src2 != dst) {
      Move_d(dst, src2);
    }
    Branch(&done);

    bind(&return_left);
    if (src1 != dst) {
      Move_d(dst, src1);
    }

    bind(&done);
  }
}

void MacroAssembler::Float64MinOutOfLine(FPURegister dst, FPURegister src1,
                                         FPURegister src2) {
  add_d(dst, src1, src2);
}

int MacroAssembler::CalculateStackPassedWords(int num_reg_arguments,
                                              int num_double_arguments) {
  int stack_passed_words = 0;
  int num_args = num_reg_arguments + num_double_arguments;

  // Up to eight arguments are passed in FPURegisters and GPRegisters.
  if (num_args > kRegisterPassedArguments) {
    stack_passed_words = num_args - kRegisterPassedArguments;
  }
  stack_passed_words += kCArgSlotCount;
  return stack_passed_words;
}

void MacroAssembler::PrepareCallCFunction(int num_reg_arguments,
                                          int num_double_arguments,
                                          Register scratch) {
  ASM_CODE_COMMENT(this);
  int frame_alignment = ActivationFrameAlignment();

  // n64: Up to eight simple arguments in a0..a3, a4..a7, No argument slots.
  // O32: Up to four simple arguments are passed in registers a0..a3.
  // Those four arguments must have reserved argument slots on the stack for
  // mips, even though those argument slots are not normally used.
  // Both ABIs: Remaining arguments are pushed on the stack, above (higher
  // address than) the (O32) argument slots. (arg slot calculation handled by
  // CalculateStackPassedWords()).
  int stack_passed_arguments =
      CalculateStackPassedWords(num_reg_arguments, num_double_arguments);
  if (frame_alignment > kPointerSize) {
    // Make stack end at alignment and make room for num_arguments - 4 words
    // and the original value of sp.
    mov(scratch, sp);
    Dsubu(sp, sp, Operand((stack_passed_arguments + 1) * kPointerSize));
    DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
    And(sp, sp, Operand(-frame_alignment));
    Sd(scratch, MemOperand(sp, stack_passed_arguments * kPointerSize));
  } else {
    Dsubu(sp, sp, Operand(stack_passed_arguments * kPointerSize));
  }
}

void MacroAssembler::PrepareCallCFunction(int num_reg_arguments,
                                          Register scratch) {
  PrepareCallCFunction(num_reg_arguments, 0, scratch);
}

int MacroAssembler::CallCFunction(ExternalReference function,
                                  int num_reg_arguments,
                                  int num_double_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  li(t9, function);
  return CallCFunctionHelper(t9, num_reg_arguments, num_double_arguments,
                             set_isolate_data_slots, return_location);
}

int MacroAssembler::CallCFunction(Register function, int num_reg_arguments,
                                  int num_double_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  ASM_CODE_COMMENT(this);
  return CallCFunctionHelper(function, num_reg_arguments, num_double_arguments,
                             set_isolate_data_slots, return_location);
}

int MacroAssembler::CallCFunction(ExternalReference function, int num_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  return CallCFunction(function, num_arguments, 0, set_isolate_data_slots,
                       return_location);
}

int MacroAssembler::CallCFunction(Register function, int num_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  return CallCFunction(function, num_arguments, 0, set_isolate_data_slots,
                       return_location);
}

int MacroAssembler::CallCFunctionHelper(
    Register function, int num_reg_arguments, int num_double_arguments,
    SetIsolateDataSlots set_isolate_data_slots, Label* return_location) {
  DCHECK_LE(num_reg_arguments + num_double_arguments, kMaxCParameters);
  DCHECK(has_frame());

  Label get_pc;

  // Make sure that the stack is aligned before calling a C function unless
  // running in the simulator. The simulator has its own alignment check which
  // provides more information.
  // The argument stots are presumed to have been set up by
  // PrepareCallCFunction. The C function must be called via t9, for mips ABI.

#if V8_HOST_ARCH_MIPS || V8_HOST_ARCH_MIPS64
  if (v8_flags.debug_code) {
    int frame_alignment = base::OS::ActivationFrameAlignment();
    int frame_alignment_mask = frame_alignment - 1;
    if (frame_alignment > kPointerSize) {
      DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
      Label alignment_as_expected;
      {
        UseScratchRegisterScope temps(this);
        Register scratch = temps.Acquire();
        And(scratch, sp, Operand(frame_alignment_mask));
        Branch(&alignment_as_expected, eq, scratch, Operand(zero_reg));
      }
      // Don't use Check here, as it will call Runtime_Abort possibly
      // re-entering here.
      stop();
      bind(&alignment_as_expected);
    }
  }
#endif  // V8_HOST_ARCH_MIPS

  // Just call directly. The function called cannot cause a GC, or
  // allow preemption, so the return address in the link register
  // stays correct.
  {
    BlockTrampolinePoolScope block_trampoline_pool(this);
    if (set_isolate_data_slots == SetIsolateDataSlots::kYes) {
      if (function != t9) {
        mov(t9, function);
        function = t9;
      }

      // Save the frame pointer and PC so that the stack layout remains
      // iterable, even without an ExitFrame which normally exists between JS
      // and C frames. 't' registers are caller-saved so this is safe as a
      // scratch register.
      Register pc_scratch = t1;
      DCHECK(!AreAliased(pc_scratch, function));
      CHECK(root_array_available());

      LoadAddressPCRelative(pc_scratch, &get_pc);

      Sd(pc_scratch,
         ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerPC));
      Sd(fp, ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP));
    }

    Call(function);
    int call_pc_offset = pc_offset();
    bind(&get_pc);

    if (return_location) bind(return_location);

    if (set_isolate_data_slots == SetIsolateDataSlots::kYes) {
      // We don't unset the PC; the FP is the source of truth.
      Sd(zero_reg,
         ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP));
    }

    int stack_passed_arguments =
        CalculateStackPassedWords(num_reg_arguments, num_double_arguments);

    if (base::OS::ActivationFrameAlignment() > kPointerSize) {
      Ld(sp, MemOperand(sp, stack_passed_arguments * kPointerSize));
    } else {
      Daddu(sp, sp, Operand(stack_passed_arguments * kPointerSize));
    }

    set_pc_for_safepoint();

    return call_pc_offset;
  }
}

#undef BRANCH_ARGS_CHECK

void MacroAssembler::CheckPageFlag(Register object, Register scratch, int mask,
                                   Condition cc, Label* condition_met) {
  ASM_CODE_COMMENT(this);
  And(scratch, object, Operand(~MemoryChunk::GetAlignmentMaskForAssembler()));
  Ld(scratch, MemOperand(scratch, MemoryChunk::FlagsOffset()));
  And(scratch, scratch, Operand(mask));
  Branch(condition_met, cc, scratch, Operand(zero_reg));
}

Register GetRegisterThatIsNotOneOf(Register reg1, Register reg2, Register reg3,
                                   Register reg4, Register reg5,
                                   Register reg6) {
  RegList regs = {reg1, reg2, reg3, reg4, reg5, reg6};

  const RegisterConfiguration* config = RegisterConfiguration::Default();
  for (int i = 0; i < config->num_allocatable_general_registers(); ++i) {
    int code = config->GetAllocatableGeneralCode(i);
    Register candidate = Register::from_code(code);
    if (regs.has(candidate)) continue;
    return candidate;
  }
  UNREACHABLE();
}

void MacroAssembler::ComputeCodeStartAddress(Register dst) {
  // This push on ra and the pop below together ensure that we restore the
  // register ra, which is needed while computing the code start address.
  push(ra);

  // The nal instruction puts the address of the current instruction into
  // the return address (ra) register, which we can use later on.
  if (kArchVariant == kMips64r6) {
    addiupc(ra, 1);
  } else {
    nal();
    nop();
  }
  int pc = pc_offset();
  li(dst, Operand(pc));
  Dsubu(dst, ra, dst);

  pop(ra);  // Restore ra
}

void MacroAssembler::CallForDeoptimization(Builtin target, int, Label* exit,
                                           DeoptimizeKind kind, Label* ret,
                                           Label*) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Ld(t9,
     MemOperand(kRootRegister, IsolateData::BuiltinEntrySlotOffset(target)));
  Call(t9);
  DCHECK_EQ(SizeOfCodeGeneratedSince(exit),
            (kind == DeoptimizeKind::kLazy) ? Deoptimizer::kLazyDeoptExitSize
                                            : Deoptimizer::kEagerDeoptExitSize);
}

void MacroAssembler::LoadCodeInstructionStart(
    Register destination, Register code_data_container_object,
    CodeEntrypointTag tag) {
  ASM_CODE_COMMENT(this);
  Ld(destination, FieldMemOperand(code_data_container_object,
                                  Code::kInstructionStartOffset));
}

void MacroAssembler::CallCodeObject(Register code_data_container_object,
                                    CodeEntrypointTag tag) {
  ASM_CODE_COMMENT(this);
  LoadCodeInstructionStart(code_data_container_object,
                           code_data_container_object, tag);
  Call(code_data_container_object);
}

void MacroAssembler::JumpCodeObject(Register code_data_container_object,
                                    CodeEntrypointTag tag, JumpMode jump_mode) {
  ASM_CODE_COMMENT(this);
  DCHECK_EQ(JumpMode::kJump, jump_mode);
  LoadCodeInstructionStart(code_data_container_object,
                           code_data_container_object, tag);
  Jump(code_data_container_object);
}

void MacroAssembler::CallJSFunction(Register function_object) {
  Register code = kJavaScriptCallCodeStartRegister;
#ifdef V8_ENABLE_LEAPTIERING
  LoadCodeEntrypointFromJSDispatchTable(
      code,
      FieldMemOperand(function_object, JSFunction::kDispatchHandleOffset));
  Call(code);
#else
  Ld(code, FieldMemOperand(func
"""


```