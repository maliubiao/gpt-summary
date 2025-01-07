Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/codegen/ppc/macro-assembler-ppc.cc`.
I need to analyze the code and list its functionalities.
The user has provided context about `.tq` files and JavaScript relevance, which I should consider.
The request specifies that this is part 2 of 7, so a concise summary is appropriate.

Based on the code, the main functionalities seem to be:

1. **Pointer Handling:** Resolving tagged pointers and handles (trusted and code pointers).
2. **Write Barriers:** Implementing write barriers for garbage collection, including ephemeron key barriers and indirect pointer barriers.
3. **Stack Frame Management:** Functions for pushing and restoring different types of stack frames (common, standard, exit).
4. **Floating-Point Conversions:** Functions for converting between integer and floating-point types.
5. **Constant Pool Management:** Loading the constant pool pointer.
6. **Stub and Prologue/Epilogue Generation:** Functions for generating stub prologues and general prologues/epilogues.
7. **Argument Handling:** Dropping and manipulating arguments on the stack.
8. **Function Invocation:** Implementing function call and jump logic, including stack overflow checks and debug hooks.
9. **Stack Handler Management:** Functions for pushing and popping stack handlers for exception handling.
10. **Object Type Checking:** Functions for checking the type of objects.
这个C++代码片段是V8 JavaScript引擎在PPC架构上的`MacroAssembler`类的实现的一部分，主要负责以下功能：

1. **处理Tagged Pointer和Handle:**
   - `ResolvePointer`:  根据指针的标签类型，解析指针指向的实际地址。这包括处理`kCodeIndirectPointerTag`和`kTrustedPointerHandleTag`两种类型的handle。
   - `ResolveTrustedPointerHandle`:  解析受信任指针handle，从受信任指针表中加载实际地址，并设置HeapObjectTag。
   - `ResolveCodePointerHandle`: 解析代码指针handle，从代码指针表中加载代码对象的地址，并设置HeapObjectTag。
   - `LoadCodeEntrypointViaCodePointer`:  通过代码指针加载代码入口点。

2. **实现写屏障 (Write Barriers):**
   - `CallEphemeronKeyBarrier`:  调用内置的ephemeron key写屏障函数。用于在弱哈希表中插入键值对时，确保键对象不会被过早回收。
   - `CallIndirectPointerBarrier`: 调用内置的间接指针写屏障函数。用于更新指向代码对象的指针时，通知垃圾回收器。
   - `CallRecordWriteStubSaveRegisters`: 调用记录写桩 (Record Write Stub)，并在调用前后保存和恢复寄存器。
   - `CallRecordWriteStub`: 调用记录写桩的实际函数。
   - `RecordWrite`:  实现写屏障的逻辑。它会检查是否需要写屏障（例如，写入Smi或写入新生代对象），如果需要，则调用相应的写屏障函数。

3. **管理栈帧 (Stack Frames):**
   - `MaybeSaveRegisters` 和 `MaybeRestoreRegisters`:  根据寄存器列表，选择性地保存和恢复寄存器。
   - `PushCommonFrame`:  压入通用的栈帧结构，包含返回地址和帧指针。
   - `PushStandardFrame`: 压入标准的栈帧结构，包含返回地址、帧指针、常量池指针和参数个数。
   - `RestoreFrameStateForTailCall`:  在尾调用优化时，恢复栈帧状态。
   - `EnterFrame`:  创建新的栈帧。
   - `LeaveFrame`:  销毁栈帧。
   - `EnterExitFrame`:  在从C++代码进入V8环境时，创建特殊的退出帧。
   - `LeaveExitFrame`:  在从V8环境返回C++代码时，销毁退出帧。

4. **浮点数转换:**
   - `CanonicalizeNaN`: 将潜在的sNaN转换为qNaN。
   - `ConvertIntToDouble`, `ConvertUnsignedIntToDouble`, `ConvertIntToFloat`, `ConvertUnsignedIntToFloat`:  将整数转换为浮点数。
   - `ConvertInt64ToDouble`, `ConvertUnsignedInt64ToFloat`, `ConvertUnsignedInt64ToDouble`, `ConvertInt64ToFloat`: 将64位整数转换为浮点数。
   - `ConvertDoubleToInt64`, `ConvertDoubleToUnsignedInt64`: 将浮点数转换为64位整数。

5. **常量池管理:**
   - `LoadConstantPoolPointerRegisterFromCodeTargetAddress`: 从代码目标地址加载常量池指针。
   - `LoadPC`: 获取当前程序计数器 (PC) 的值。
   - `ComputeCodeStartAddress`: 计算代码的起始地址。
   - `LoadConstantPoolPointerRegister`:  加载常量池指针到指定的寄存器。

6. **Stub和Prologue/Epilogue生成:**
   - `StubPrologue`:  生成桩函数的序言。
   - `Prologue`:  生成普通函数的序言。
   - `DropArguments`: 从栈上移除指定数量的参数。
   - `DropArgumentsAndPushNewReceiver`:  移除参数并压入新的接收者对象。

7. **函数调用 (Function Invocation):**
   - `InvokePrologue`:  函数调用的序言，处理参数数量不匹配的情况。
   - `CheckDebugHook`:  在函数调用前检查是否需要触发调试钩子。
   - `InvokeFunctionCode`:  调用JS函数的实际代码，包括直接调用和跳转调用。
   - `InvokeFunctionWithNewTarget`:  调用带有 `new.target` 的函数。
   - `InvokeFunction`:  调用普通的JS函数。

8. **栈处理器 (Stack Handler) 管理:**
   - `PushStackHandler`:  压入一个新的栈处理器，用于异常处理。
   - `PopStackHandler`:  弹出当前的栈处理器。

9. **对象类型检查 (Object Type Checking):**
   - `CompareInstanceTypeWithUniqueCompressedMap`:  比较对象的压缩Map和指定的实例类型。
   - `IsObjectTypeFast`:  快速检查对象是否为指定的实例类型。

**JavaScript 功能关联示例:**

与 JavaScript 功能相关的部分主要是函数调用和对象操作。

```javascript
function myFunction(a, b) {
  return a + b;
}

myFunction(1, 2); // 这会涉及到 InvokeFunction 相关的代码

new myFunction(1, 2); // 这会涉及到 InvokeFunctionWithNewTarget 相关的代码

const obj = {};
obj.prop = 10; // 这会涉及到 RecordWrite 相关的代码
```

**代码逻辑推理示例:**

**假设输入:**
- `destination` 寄存器：需要存储解析后地址的目标寄存器。
- `handle` 寄存器：包含需要解析的handle。
- `tag`：handle的标签类型，例如 `kCodeIndirectPointerTag`。
- `scratch` 寄存器：一个临时寄存器。

**输出:**
- `destination` 寄存器将包含 `handle` 指向的实际内存地址。

**例如，如果 `tag` 是 `kCodeIndirectPointerTag`，`ResolvePointer` 函数会执行 `ResolveCodePointerHandle`，它会：**
1. 将代码指针表的地址加载到 `table` 寄存器。
2. 将 `handle` 右移 `kCodePointerHandleShift` 位，去除标签。
3. 将结果左移 `kCodePointerTableEntrySizeLog2` 位，计算在表中的偏移量。
4. 将偏移量加到表地址，得到表项的地址。
5. 从表项中加载代码对象的地址到 `destination` 寄存器。
6. 将 `destination` 寄存器的最低位设置为 `kHeapObjectTag`。

**用户常见的编程错误示例:**

在与写屏障相关的代码中，一个常见的错误是**忘记在修改对象属性后触发写屏障**。 例如，直接修改了老生代对象的属性，而没有调用 `RecordWrite`，可能导致垃圾回收器无法正确追踪对象引用，从而引发内存泄漏或悬挂指针。

```javascript
const oldGenObject = { data: null };
const youngGenObject = { value: 123 };

// 错误：直接赋值，没有通知垃圾回收器
oldGenObject.data = youngGenObject;

// 正确的做法（V8 内部会处理，但理解概念很重要）
// 在 V8 内部，当 JavaScript 代码执行类似赋值操作时，
// 引擎的底层代码会调用 RecordWrite 等机制来处理写屏障。
```

**归纳其功能:**

总而言之，这个代码片段是 `MacroAssembler` 类中用于在 PPC 架构上生成机器码的关键部分，它提供了处理指针、实现垃圾回收机制（写屏障）、管理函数调用栈帧、进行类型转换以及辅助生成函数序言和调用逻辑等底层操作的功能。 这些功能是 V8 引擎将 JavaScript 代码高效地编译和执行为机器码的基础。
Prompt: 
```
这是目录为v8/src/codegen/ppc/macro-assembler-ppc.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/ppc/macro-assembler-ppc.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共7部分，请归纳一下它的功能

"""
r));
    AndU64(scratch, handle, scratch, SetRC);
    beq(&is_trusted_pointer_handle, cr0);
    ResolveCodePointerHandle(destination, handle, scratch);
    b(&done);
    bind(&is_trusted_pointer_handle);
    ResolveTrustedPointerHandle(destination, handle, kUnknownIndirectPointerTag,
                                scratch);
    bind(&done);
  } else if (tag == kCodeIndirectPointerTag) {
    ResolveCodePointerHandle(destination, handle, scratch);
  } else {
    ResolveTrustedPointerHandle(destination, handle, tag, scratch);
  }
}

void MacroAssembler::ResolveTrustedPointerHandle(Register destination,
                                                 Register handle,
                                                 IndirectPointerTag tag,
                                                 Register scratch) {
  DCHECK_NE(tag, kCodeIndirectPointerTag);
  DCHECK(!AreAliased(handle, destination));

  CHECK(root_array_available_);
  Register table = destination;
  Move(table, ExternalReference::trusted_pointer_table_base_address(isolate()));
  ShiftRightU64(handle, handle, Operand(kTrustedPointerHandleShift));
  ShiftLeftU64(handle, handle, Operand(kTrustedPointerTableEntrySizeLog2));
  LoadU64(destination, MemOperand(table, handle), scratch);
  // The LSB is used as marking bit by the trusted pointer table, so here we
  // have to set it using a bitwise OR as it may or may not be set.
  mov(handle, Operand(kHeapObjectTag));
  OrU64(destination, destination, handle);
}

void MacroAssembler::ResolveCodePointerHandle(Register destination,
                                              Register handle,
                                              Register scratch) {
  DCHECK(!AreAliased(handle, destination));

  Register table = destination;
  Move(table, ExternalReference::code_pointer_table_address());
  ShiftRightU64(handle, handle, Operand(kCodePointerHandleShift));
  ShiftLeftU64(handle, handle, Operand(kCodePointerTableEntrySizeLog2));
  AddS64(handle, table, handle);
  LoadU64(destination,
          MemOperand(handle, kCodePointerTableEntryCodeObjectOffset), scratch);
  // The LSB is used as marking bit by the code pointer table, so here we have
  // to set it using a bitwise OR as it may or may not be set.
  mov(handle, Operand(kHeapObjectTag));
  OrU64(destination, destination, handle);
}

void MacroAssembler::LoadCodeEntrypointViaCodePointer(Register destination,
                                                      MemOperand field_operand,
                                                      Register scratch) {
  ASM_CODE_COMMENT(this);

  // Due to register pressure, table is also used as a scratch register
  DCHECK(destination != r0);
  Register table = scratch;
  LoadU32(destination, field_operand, scratch);
  Move(table, ExternalReference::code_pointer_table_address());
  // TODO(tpearson): can the offset computation be done more efficiently?
  ShiftRightU64(destination, destination, Operand(kCodePointerHandleShift));
  ShiftLeftU64(destination, destination,
               Operand(kCodePointerTableEntrySizeLog2));
  LoadU64(destination, MemOperand(destination, table));
}
#endif  // V8_ENABLE_SANDBOX

void MacroAssembler::MaybeSaveRegisters(RegList registers) {
  if (registers.is_empty()) return;
  MultiPush(registers);
}

void MacroAssembler::MaybeRestoreRegisters(RegList registers) {
  if (registers.is_empty()) return;
  MultiPop(registers);
}

void MacroAssembler::CallEphemeronKeyBarrier(Register object,
                                             Register slot_address,
                                             SaveFPRegsMode fp_mode) {
  DCHECK(!AreAliased(object, slot_address));
  RegList registers =
      WriteBarrierDescriptor::ComputeSavedRegisters(object, slot_address);
  MaybeSaveRegisters(registers);

  Register object_parameter = WriteBarrierDescriptor::ObjectRegister();
  Register slot_address_parameter =
      WriteBarrierDescriptor::SlotAddressRegister();

  // TODO(tpearson): The following is equivalent to
  // MovePair(slot_address_parameter, slot_address, object_parameter, object);
  // Implement with MoveObjectAndSlot()
  push(object);
  push(slot_address);
  pop(slot_address_parameter);
  pop(object_parameter);

  CallBuiltin(Builtins::EphemeronKeyBarrier(fp_mode));
  MaybeRestoreRegisters(registers);
}

void MacroAssembler::CallIndirectPointerBarrier(Register object,
                                                Register slot_address,
                                                SaveFPRegsMode fp_mode,
                                                IndirectPointerTag tag) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(object, slot_address));
  RegList registers =
      IndirectPointerWriteBarrierDescriptor::ComputeSavedRegisters(
          object, slot_address);
  MaybeSaveRegisters(registers);

  Register object_parameter =
      IndirectPointerWriteBarrierDescriptor::ObjectRegister();
  Register slot_address_parameter =
      IndirectPointerWriteBarrierDescriptor::SlotAddressRegister();
  Register tag_parameter =
      IndirectPointerWriteBarrierDescriptor::IndirectPointerTagRegister();
  DCHECK(!AreAliased(object_parameter, slot_address_parameter, tag_parameter));

  // TODO(tpearson): The following is equivalent to
  // MovePair(slot_address_parameter, slot_address, object_parameter, object);
  // Implement with MoveObjectAndSlot()
  push(object);
  push(slot_address);
  pop(slot_address_parameter);
  pop(object_parameter);

  mov(tag_parameter, Operand(tag));

  CallBuiltin(Builtins::IndirectPointerBarrier(fp_mode));
  MaybeRestoreRegisters(registers);
}

void MacroAssembler::CallRecordWriteStubSaveRegisters(Register object,
                                                      Register slot_address,
                                                      SaveFPRegsMode fp_mode,
                                                      StubCallMode mode) {
  DCHECK(!AreAliased(object, slot_address));
  RegList registers =
      WriteBarrierDescriptor::ComputeSavedRegisters(object, slot_address);
  MaybeSaveRegisters(registers);

  Register object_parameter = WriteBarrierDescriptor::ObjectRegister();
  Register slot_address_parameter =
      WriteBarrierDescriptor::SlotAddressRegister();

  push(object);
  push(slot_address);
  pop(slot_address_parameter);
  pop(object_parameter);

  CallRecordWriteStub(object_parameter, slot_address_parameter, fp_mode, mode);

  MaybeRestoreRegisters(registers);
}

void MacroAssembler::CallRecordWriteStub(Register object, Register slot_address,
                                         SaveFPRegsMode fp_mode,
                                         StubCallMode mode) {
  // Use CallRecordWriteStubSaveRegisters if the object and slot registers
  // need to be caller saved.
  DCHECK_EQ(WriteBarrierDescriptor::ObjectRegister(), object);
  DCHECK_EQ(WriteBarrierDescriptor::SlotAddressRegister(), slot_address);
#if V8_ENABLE_WEBASSEMBLY
  if (mode == StubCallMode::kCallWasmRuntimeStub) {
    // Use {near_call} for direct Wasm call within a module.
    auto wasm_target =
        static_cast<Address>(wasm::WasmCode::GetRecordWriteBuiltin(fp_mode));
    Call(wasm_target, RelocInfo::WASM_STUB_CALL);
#else
  if (false) {
#endif
  } else {
    CallBuiltin(Builtins::RecordWrite(fp_mode), al);
  }
}

// Will clobber 4 registers: object, address, scratch, ip.  The
// register 'object' contains a heap object pointer.  The heap object
// tag is shifted away.
void MacroAssembler::RecordWrite(Register object, Register slot_address,
                                 Register value, LinkRegisterStatus lr_status,
                                 SaveFPRegsMode fp_mode, SmiCheck smi_check,
                                 SlotDescriptor slot) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(object, value, slot_address));
  if (v8_flags.debug_code) {
    Register value_check = r0;
    // TODO(tpearson): Figure out why ScratchRegisterScope returns a
    // register that is aliased with one of our other in-use registers
    // For now, use r11 (kScratchReg in the code generator)
    Register scratch = r11;
    ASM_CODE_COMMENT_STRING(this, "Verify slot_address");
    DCHECK(!AreAliased(object, value, value_check, scratch));
    if (slot.contains_indirect_pointer()) {
      LoadIndirectPointerField(value_check, MemOperand(slot_address),
                               slot.indirect_pointer_tag(), scratch);
    } else {
      DCHECK(slot.contains_direct_pointer());
      LoadTaggedField(value_check, MemOperand(slot_address));
    }
    CmpS64(value_check, value);
    Check(eq, AbortReason::kWrongAddressOrValuePassedToRecordWrite);
  }

  if (v8_flags.disable_write_barriers) {
    return;
  }

  // First, check if a write barrier is even needed. The tests below
  // catch stores of smis and stores into the young generation.
  Label done;

  if (smi_check == SmiCheck::kInline) {
    JumpIfSmi(value, &done);
  }

  CheckPageFlag(value,
                value,  // Used as scratch.
                MemoryChunk::kPointersToHereAreInterestingMask, eq, &done);
  CheckPageFlag(object,
                value,  // Used as scratch.
                MemoryChunk::kPointersFromHereAreInterestingMask, eq, &done);

  // Record the actual write.
  if (lr_status == kLRHasNotBeenSaved) {
    mflr(r0);
    push(r0);
  }
  if (slot.contains_direct_pointer()) {
    CallRecordWriteStubSaveRegisters(object, slot_address, fp_mode,
                                     StubCallMode::kCallBuiltinPointer);
  } else {
    DCHECK(slot.contains_indirect_pointer());
    CallIndirectPointerBarrier(object, slot_address, fp_mode,
                               slot.indirect_pointer_tag());
  }
  if (lr_status == kLRHasNotBeenSaved) {
    pop(r0);
    mtlr(r0);
  }

  if (v8_flags.debug_code) mov(slot_address, Operand(kZapValue));

  bind(&done);

  // Clobber clobbered registers when running with the debug-code flag
  // turned on to provoke errors.
  if (v8_flags.debug_code) {
    mov(slot_address, Operand(base::bit_cast<intptr_t>(kZapValue + 12)));
    mov(value, Operand(base::bit_cast<intptr_t>(kZapValue + 16)));
  }
}

void MacroAssembler::PushCommonFrame(Register marker_reg) {
  int fp_delta = 0;
  mflr(r0);
  if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
    if (marker_reg.is_valid()) {
      Push(r0, fp, kConstantPoolRegister, marker_reg);
      fp_delta = 2;
    } else {
      Push(r0, fp, kConstantPoolRegister);
      fp_delta = 1;
    }
  } else {
    if (marker_reg.is_valid()) {
      Push(r0, fp, marker_reg);
      fp_delta = 1;
    } else {
      Push(r0, fp);
      fp_delta = 0;
    }
  }
  addi(fp, sp, Operand(fp_delta * kSystemPointerSize));
}

void MacroAssembler::PushStandardFrame(Register function_reg) {
  int fp_delta = 0;
  mflr(r0);
  if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
    if (function_reg.is_valid()) {
      Push(r0, fp, kConstantPoolRegister, cp, function_reg);
      fp_delta = 3;
    } else {
      Push(r0, fp, kConstantPoolRegister, cp);
      fp_delta = 2;
    }
  } else {
    if (function_reg.is_valid()) {
      Push(r0, fp, cp, function_reg);
      fp_delta = 2;
    } else {
      Push(r0, fp, cp);
      fp_delta = 1;
    }
  }
  addi(fp, sp, Operand(fp_delta * kSystemPointerSize));
  Push(kJavaScriptCallArgCountRegister);
}

void MacroAssembler::RestoreFrameStateForTailCall() {
  if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
    LoadU64(kConstantPoolRegister,
            MemOperand(fp, StandardFrameConstants::kConstantPoolOffset));
    set_constant_pool_available(false);
  }
  LoadU64(r0, MemOperand(fp, StandardFrameConstants::kCallerPCOffset));
  LoadU64(fp, MemOperand(fp, StandardFrameConstants::kCallerFPOffset));
  mtlr(r0);
}

void MacroAssembler::CanonicalizeNaN(const DoubleRegister dst,
                                     const DoubleRegister src) {
  // Turn potential sNaN into qNaN.
  fsub(dst, src, kDoubleRegZero);
}

void MacroAssembler::ConvertIntToDouble(Register src, DoubleRegister dst) {
  MovIntToDouble(dst, src, r0);
  fcfid(dst, dst);
}

void MacroAssembler::ConvertUnsignedIntToDouble(Register src,
                                                DoubleRegister dst) {
  MovUnsignedIntToDouble(dst, src, r0);
  fcfid(dst, dst);
}

void MacroAssembler::ConvertIntToFloat(Register src, DoubleRegister dst) {
  MovIntToDouble(dst, src, r0);
  fcfids(dst, dst);
}

void MacroAssembler::ConvertUnsignedIntToFloat(Register src,
                                               DoubleRegister dst) {
  MovUnsignedIntToDouble(dst, src, r0);
  fcfids(dst, dst);
}

void MacroAssembler::ConvertInt64ToDouble(Register src,
                                          DoubleRegister double_dst) {
  MovInt64ToDouble(double_dst, src);
  fcfid(double_dst, double_dst);
}

void MacroAssembler::ConvertUnsignedInt64ToFloat(Register src,
                                                 DoubleRegister double_dst) {
  MovInt64ToDouble(double_dst, src);
  fcfidus(double_dst, double_dst);
}

void MacroAssembler::ConvertUnsignedInt64ToDouble(Register src,
                                                  DoubleRegister double_dst) {
  MovInt64ToDouble(double_dst, src);
  fcfidu(double_dst, double_dst);
}

void MacroAssembler::ConvertInt64ToFloat(Register src,
                                         DoubleRegister double_dst) {
  MovInt64ToDouble(double_dst, src);
  fcfids(double_dst, double_dst);
}

void MacroAssembler::ConvertDoubleToInt64(const DoubleRegister double_input,
                                          const Register dst,
                                          const DoubleRegister double_dst,
                                          FPRoundingMode rounding_mode) {
  if (rounding_mode == kRoundToZero) {
    fctidz(double_dst, double_input);
  } else {
    SetRoundingMode(rounding_mode);
    fctid(double_dst, double_input);
    ResetRoundingMode();
  }

  MovDoubleToInt64(
      dst, double_dst);
}

void MacroAssembler::ConvertDoubleToUnsignedInt64(
    const DoubleRegister double_input, const Register dst,
    const DoubleRegister double_dst, FPRoundingMode rounding_mode) {
  if (rounding_mode == kRoundToZero) {
    fctiduz(double_dst, double_input);
  } else {
    SetRoundingMode(rounding_mode);
    fctidu(double_dst, double_input);
    ResetRoundingMode();
  }

  MovDoubleToInt64(dst, double_dst);
}

void MacroAssembler::LoadConstantPoolPointerRegisterFromCodeTargetAddress(
    Register code_target_address, Register scratch1, Register scratch2) {
  // Builtins do not use the constant pool (see is_constant_pool_available).
  static_assert(InstructionStream::kOnHeapBodyIsContiguous);

#ifdef V8_ENABLE_SANDBOX
  LoadCodeEntrypointViaCodePointer(
      scratch2,
      FieldMemOperand(code_target_address, Code::kSelfIndirectPointerOffset),
      scratch1);
#else
  LoadU64(scratch2,
          FieldMemOperand(code_target_address, Code::kInstructionStartOffset),
          scratch1);
#endif
  LoadU32(scratch1,
          FieldMemOperand(code_target_address, Code::kInstructionSizeOffset),
          scratch1);
  add(scratch2, scratch1, scratch2);
  LoadU32(kConstantPoolRegister,
          FieldMemOperand(code_target_address, Code::kConstantPoolOffsetOffset),
          scratch1);
  add(kConstantPoolRegister, scratch2, kConstantPoolRegister);
}

void MacroAssembler::LoadPC(Register dst) {
  b(4, SetLK);
  mflr(dst);
}

void MacroAssembler::ComputeCodeStartAddress(Register dst) {
  mflr(r0);
  LoadPC(dst);
  subi(dst, dst, Operand(pc_offset() - kInstrSize));
  mtlr(r0);
}

void MacroAssembler::LoadConstantPoolPointerRegister() {
  //
  // Builtins do not use the constant pool (see is_constant_pool_available).
  static_assert(InstructionStream::kOnHeapBodyIsContiguous);

  LoadPC(kConstantPoolRegister);
  int32_t delta = -pc_offset() + 4;
  add_label_offset(kConstantPoolRegister, kConstantPoolRegister,
                   ConstantPoolPosition(), delta);
}

void MacroAssembler::StubPrologue(StackFrame::Type type) {
  {
    ConstantPoolUnavailableScope constant_pool_unavailable(this);
    mov(r11, Operand(StackFrame::TypeToMarker(type)));
    PushCommonFrame(r11);
  }
  if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
    LoadConstantPoolPointerRegister();
    set_constant_pool_available(true);
  }
}

void MacroAssembler::Prologue() {
  PushStandardFrame(r4);
  if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
    // base contains prologue address
    LoadConstantPoolPointerRegister();
    set_constant_pool_available(true);
  }
}

void MacroAssembler::DropArguments(Register count) {
  ShiftLeftU64(ip, count, Operand(kSystemPointerSizeLog2));
  add(sp, sp, ip);
}

void MacroAssembler::DropArgumentsAndPushNewReceiver(Register argc,
                                                     Register receiver) {
  DCHECK(!AreAliased(argc, receiver));
  DropArguments(argc);
  push(receiver);
}

void MacroAssembler::EnterFrame(StackFrame::Type type,
                                bool load_constant_pool_pointer_reg) {
  if (V8_EMBEDDED_CONSTANT_POOL_BOOL && load_constant_pool_pointer_reg) {
    // Push type explicitly so we can leverage the constant pool.
    // This path cannot rely on ip containing code entry.
    PushCommonFrame();
    LoadConstantPoolPointerRegister();
    if (!StackFrame::IsJavaScript(type)) {
      mov(ip, Operand(StackFrame::TypeToMarker(type)));
      push(ip);
    }
  } else {
    Register scratch = no_reg;
    if (!StackFrame::IsJavaScript(type)) {
      scratch = ip;
      mov(scratch, Operand(StackFrame::TypeToMarker(type)));
    }
    PushCommonFrame(scratch);
  }
#if V8_ENABLE_WEBASSEMBLY
  if (type == StackFrame::WASM) Push(kWasmImplicitArgRegister);
#endif  // V8_ENABLE_WEBASSEMBLY
}

int MacroAssembler::LeaveFrame(StackFrame::Type type, int stack_adjustment) {
  ConstantPoolUnavailableScope constant_pool_unavailable(this);
  // r3: preserved
  // r4: preserved
  // r5: preserved

  // Drop the execution stack down to the frame pointer and restore
  // the caller's state.
  int frame_ends;
  LoadU64(r0, MemOperand(fp, StandardFrameConstants::kCallerPCOffset));
  LoadU64(ip, MemOperand(fp, StandardFrameConstants::kCallerFPOffset));
  if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
    LoadU64(kConstantPoolRegister,
            MemOperand(fp, StandardFrameConstants::kConstantPoolOffset));
  }
  mtlr(r0);
  frame_ends = pc_offset();
  AddS64(sp, fp,
         Operand(StandardFrameConstants::kCallerSPOffset + stack_adjustment),
         r0);
  mr(fp, ip);
  return frame_ends;
}

// ExitFrame layout (probably wrongish.. needs updating)
//
//  SP -> previousSP
//        LK reserved
//        sp_on_exit (for debug?)
// oldSP->prev SP
//        LK
//        <parameters on stack>

// Prior to calling EnterExitFrame, we've got a bunch of parameters
// on the stack that we need to wrap a real frame around.. so first
// we reserve a slot for LK and push the previous SP which is captured
// in the fp register (r31)
// Then - we buy a new frame

void MacroAssembler::EnterExitFrame(Register scratch, int stack_space,
                                    StackFrame::Type frame_type) {
  DCHECK(frame_type == StackFrame::EXIT ||
         frame_type == StackFrame::BUILTIN_EXIT ||
         frame_type == StackFrame::API_ACCESSOR_EXIT ||
         frame_type == StackFrame::API_CALLBACK_EXIT);

  using ER = ExternalReference;

  // Set up the frame structure on the stack.
  DCHECK_EQ(2 * kSystemPointerSize, ExitFrameConstants::kCallerSPDisplacement);
  DCHECK_EQ(1 * kSystemPointerSize, ExitFrameConstants::kCallerPCOffset);
  DCHECK_EQ(0 * kSystemPointerSize, ExitFrameConstants::kCallerFPOffset);

  // This is an opportunity to build a frame to wrap
  // all of the pushes that have happened inside of V8
  // since we were called from C code

  mov(ip, Operand(StackFrame::TypeToMarker(frame_type)));
  PushCommonFrame(ip);
  // Reserve room for saved entry sp.
  subi(sp, fp, Operand(ExitFrameConstants::kFixedFrameSizeFromFp));

  if (v8_flags.debug_code) {
    li(r8, Operand::Zero());
    StoreU64(r8, MemOperand(fp, ExitFrameConstants::kSPOffset));
  }
  if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
    StoreU64(kConstantPoolRegister,
             MemOperand(fp, ExitFrameConstants::kConstantPoolOffset));
  }

  // Save the frame pointer and the context in top.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, isolate());
  StoreU64(fp, ExternalReferenceAsOperand(c_entry_fp_address, no_reg));

  ER context_address = ER::Create(IsolateAddressId::kContextAddress, isolate());
  StoreU64(cp, ExternalReferenceAsOperand(context_address, no_reg));

  AddS64(sp, sp, Operand(-(stack_space + 1) * kSystemPointerSize));

  // Allocate and align the frame preparing for calling the runtime
  // function.
  const int frame_alignment = ActivationFrameAlignment();
  if (frame_alignment > kSystemPointerSize) {
    DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
    ClearRightImm(sp, sp,
                  Operand(base::bits::WhichPowerOfTwo(frame_alignment)));
  }
  li(r0, Operand::Zero());
  StoreU64WithUpdate(
      r0, MemOperand(sp, -kNumRequiredStackFrameSlots * kSystemPointerSize));

  // Set the exit frame sp value to point just before the return address
  // location.
  AddS64(r8, sp, Operand((kStackFrameExtraParamSlot + 1) * kSystemPointerSize),
         r0);
  StoreU64(r8, MemOperand(fp, ExitFrameConstants::kSPOffset));
}

int MacroAssembler::ActivationFrameAlignment() {
#if !defined(USE_SIMULATOR)
  // Running on the real platform. Use the alignment as mandated by the local
  // environment.
  // Note: This will break if we ever start generating snapshots on one PPC
  // platform for another PPC platform with a different alignment.
  return base::OS::ActivationFrameAlignment();
#else  // Simulated
  // If we are using the simulator then we should always align to the expected
  // alignment. As the simulator is used to generate snapshots we do not know
  // if the target platform will need alignment, so this is controlled from a
  // flag.
  return v8_flags.sim_stack_alignment;
#endif
}

void MacroAssembler::LeaveExitFrame(Register scratch) {
  ConstantPoolUnavailableScope constant_pool_unavailable(this);

  using ER = ExternalReference;

  // Restore current context from top and clear it in debug mode.
  ER context_address = ER::Create(IsolateAddressId::kContextAddress, isolate());
  LoadU64(cp, ExternalReferenceAsOperand(context_address, no_reg));

#ifdef DEBUG
  mov(scratch, Operand(Context::kInvalidContext));
  StoreU64(scratch, ExternalReferenceAsOperand(context_address, no_reg));
#endif

  // Clear the top frame.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, isolate());
  mov(scratch, Operand::Zero());
  StoreU64(scratch, ExternalReferenceAsOperand(c_entry_fp_address, no_reg));

  // Tear down the exit frame, pop the arguments, and return.
  LeaveFrame(StackFrame::EXIT);
}

void MacroAssembler::MovFromFloatResult(const DoubleRegister dst) {
  Move(dst, d1);
}

void MacroAssembler::MovFromFloatParameter(const DoubleRegister dst) {
  Move(dst, d1);
}

void MacroAssembler::LoadStackLimit(Register destination, StackLimitKind kind,
                                    Register scratch) {
  DCHECK(root_array_available());
  intptr_t offset = kind == StackLimitKind::kRealStackLimit
                        ? IsolateData::real_jslimit_offset()
                        : IsolateData::jslimit_offset();
  CHECK(is_int32(offset));
  LoadU64(destination, MemOperand(kRootRegister, offset), scratch);
}

void MacroAssembler::StackOverflowCheck(Register num_args, Register scratch,
                                        Label* stack_overflow) {
  // Check the stack for overflow. We are not trying to catch
  // interruptions (e.g. debug break and preemption) here, so the "real stack
  // limit" is checked.
  LoadStackLimit(scratch, StackLimitKind::kRealStackLimit, r0);
  // Make scratch the space we have left. The stack might already be overflowed
  // here which will cause scratch to become negative.
  sub(scratch, sp, scratch);
  // Check if the arguments will overflow the stack.
  ShiftLeftU64(r0, num_args, Operand(kSystemPointerSizeLog2));
  CmpS64(scratch, r0);
  ble(stack_overflow);  // Signed comparison.
}

void MacroAssembler::InvokePrologue(Register expected_parameter_count,
                                    Register actual_parameter_count,
                                    Label* done, InvokeType type) {
  Label regular_invoke;

  //  r3: actual arguments count
  //  r4: function (passed through to callee)
  //  r5: expected arguments count

  DCHECK_EQ(actual_parameter_count, r3);
  DCHECK_EQ(expected_parameter_count, r5);

  // If overapplication or if the actual argument count is equal to the
  // formal parameter count, no need to push extra undefined values.
  sub(expected_parameter_count, expected_parameter_count,
      actual_parameter_count, LeaveOE, SetRC);
  ble(&regular_invoke, cr0);

  Label stack_overflow;
  Register scratch = r7;
  StackOverflowCheck(expected_parameter_count, scratch, &stack_overflow);

  // Underapplication. Move the arguments already in the stack, including the
  // receiver and the return address.
  {
    Label copy, skip;
    Register src = r9, dest = r8;
    addi(src, sp, Operand(-kSystemPointerSize));
    ShiftLeftU64(r0, expected_parameter_count, Operand(kSystemPointerSizeLog2));
    sub(sp, sp, r0);
    // Update stack pointer.
    addi(dest, sp, Operand(-kSystemPointerSize));
    mr(r0, actual_parameter_count);
    cmpi(r0, Operand::Zero());
    ble(&skip);
    mtctr(r0);

    bind(&copy);
    LoadU64WithUpdate(r0, MemOperand(src, kSystemPointerSize));
    StoreU64WithUpdate(r0, MemOperand(dest, kSystemPointerSize));
    bdnz(&copy);
    bind(&skip);
  }

  // Fill remaining expected arguments with undefined values.
  LoadRoot(scratch, RootIndex::kUndefinedValue);
  {
    mtctr(expected_parameter_count);

    Label loop;
    bind(&loop);
    StoreU64WithUpdate(scratch, MemOperand(r8, kSystemPointerSize));
    bdnz(&loop);
  }
  b(&regular_invoke);

  bind(&stack_overflow);
  {
    FrameScope frame(
        this, has_frame() ? StackFrame::NO_FRAME_TYPE : StackFrame::INTERNAL);
    CallRuntime(Runtime::kThrowStackOverflow);
    bkpt(0);
  }

  bind(&regular_invoke);
}

void MacroAssembler::CheckDebugHook(Register fun, Register new_target,
                                    Register expected_parameter_count,
                                    Register actual_parameter_count) {
  Label skip_hook;

  ExternalReference debug_hook_active =
      ExternalReference::debug_hook_on_function_call_address(isolate());
  Move(r7, debug_hook_active);
  LoadU8(r7, MemOperand(r7), r0);
  extsb(r7, r7);
  CmpSmiLiteral(r7, Smi::zero(), r0);
  beq(&skip_hook);

  {
    // Load receiver to pass it later to DebugOnFunctionCall hook.
    LoadReceiver(r7);
    FrameScope frame(
        this, has_frame() ? StackFrame::NO_FRAME_TYPE : StackFrame::INTERNAL);

    SmiTag(expected_parameter_count);
    Push(expected_parameter_count);

    SmiTag(actual_parameter_count);
    Push(actual_parameter_count);

    if (new_target.is_valid()) {
      Push(new_target);
    }
    Push(fun, fun, r7);
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
  DCHECK_EQ(function, r4);
  DCHECK_IMPLIES(new_target.is_valid(), new_target == r6);

  // On function call, call into the debugger if necessary.
  CheckDebugHook(function, new_target, expected_parameter_count,
                 actual_parameter_count);

  // Clear the new.target register if not given.
  if (!new_target.is_valid()) {
    LoadRoot(r6, RootIndex::kUndefinedValue);
  }

  Label done;
  InvokePrologue(expected_parameter_count, actual_parameter_count, &done, type);
  // We call indirectly through the code field in the function to
  // allow recompilation to take effect without changing any of the
  // call sites.
  constexpr int unused_argument_count = 0;
  switch (type) {
    case InvokeType::kCall:
      CallJSFunction(function, unused_argument_count, r0);
      break;
    case InvokeType::kJump:
      JumpJSFunction(function, r0);
      break;
  }

    // Continue here if InvokePrologue does handle the invocation due to
    // mismatched parameter counts.
    bind(&done);
}

void MacroAssembler::InvokeFunctionWithNewTarget(
    Register fun, Register new_target, Register actual_parameter_count,
    InvokeType type) {
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());

  // Contract with called JS functions requires that function is passed in r4.
  DCHECK_EQ(fun, r4);

  Register expected_reg = r5;
  Register temp_reg = r7;

  LoadTaggedField(
      temp_reg, FieldMemOperand(r4, JSFunction::kSharedFunctionInfoOffset), r0);
  LoadTaggedField(cp, FieldMemOperand(r4, JSFunction::kContextOffset), r0);
  LoadU16(expected_reg,
          FieldMemOperand(temp_reg,
                          SharedFunctionInfo::kFormalParameterCountOffset));

  InvokeFunctionCode(fun, new_target, expected_reg, actual_parameter_count,
                     type);
}

void MacroAssembler::InvokeFunction(Register function,
                                    Register expected_parameter_count,
                                    Register actual_parameter_count,
                                    InvokeType type) {
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());

  // Contract with called JS functions requires that function is passed in r4.
  DCHECK_EQ(function, r4);

  // Get the function and setup the context.
  LoadTaggedField(cp, FieldMemOperand(r4, JSFunction::kContextOffset), r0);

  InvokeFunctionCode(r4, no_reg, expected_parameter_count,
                     actual_parameter_count, type);
}

void MacroAssembler::PushStackHandler() {
  // Adjust this code if not the case.
  static_assert(StackHandlerConstants::kSize == 2 * kSystemPointerSize);
  static_assert(StackHandlerConstants::kNextOffset == 0 * kSystemPointerSize);

  Push(Smi::zero());  // Padding.

  // Link the current handler as the next handler.
  // Preserve r4-r8.
  Move(r3,
       ExternalReference::Create(IsolateAddressId::kHandlerAddress, isolate()));
  LoadU64(r0, MemOperand(r3));
  push(r0);

  // Set this new handler as the current one.
  StoreU64(sp, MemOperand(r3));
}

void MacroAssembler::PopStackHandler() {
  static_assert(StackHandlerConstants::kSize == 2 * kSystemPointerSize);
  static_assert(StackHandlerConstants::kNextOffset == 0);

  pop(r4);
  Move(ip,
       ExternalReference::Create(IsolateAddressId::kHandlerAddress, isolate()));
  StoreU64(r4, MemOperand(ip));

  Drop(1);  // Drop padding.
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
  CHECK(scratch != Register::no_reg() || temps.CanAcquire());
  if (scratch == Register::no_reg()) {
    // TODO(tpearson): Figure out why ScratchRegisterScope returns a
    // register that is aliased with one of our other in-use registers
    // For now, use r11 (kScratchReg in the code generator)
    scratch = r11;
    DCHECK_NE(map, scratch);
  }
  mov(scratch, Operand(expected_ptr));
  CompareTagged(map, scratch);
}

void MacroAssembler::IsObjectTypeFast(Register object,
                                      Register compressed_map_scratch,
                                      InstanceType type, Register scratch) {
  ASM_CODE_COMMENT(this);
  CHECK(InstanceTypeChecker::UniqueMapOfInstanceType(type));
  LoadCompressedMap(compressed_map_scratch, object, scratch);
  CompareInstanceTypeWithUniqueCompressedMap(compressed_map_scratch,
                                             Register::no_reg(), type);
}
#endif  // V8_STATIC_ROOTS_BOOL

// Sets equality condition flags.
void MacroAssembler::IsObjectType(Register object, Register scratch1,
                                  Register scratch2,
"""


```