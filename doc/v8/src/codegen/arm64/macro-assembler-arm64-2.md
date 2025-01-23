Response: The user wants a summary of the provided C++ code, which is a part of the `MacroAssembler` for the ARM64 architecture in V8. I need to focus on the functionality implemented in this specific snippet (part 3 of 3). If the code has any relation to JavaScript concepts, I should illustrate with JavaScript examples.

The code seems to implement various low-level operations, particularly related to memory management, garbage collection, and interaction with the V8 runtime. Key areas appear to be:

1. **Write Barriers:**  Functions like `RecordWriteField` and `RecordWrite` are crucial for maintaining the integrity of the garbage-collected heap.
2. **Sandboxed Pointers:**  Functions for loading, storing, and decoding sandboxed pointers, which are used when the sandbox feature is enabled.
3. **Indirect Pointers:** Handling of indirect pointers, likely used for code objects and other special data in the sandbox.
4. **External Pointers:** Loading external pointers, possibly pointing to data outside the V8 heap.
5. **Trusted Pointers:** Operations involving trusted pointers.
6. **Leaptiering:**  Functions related to loading entry points and parameter counts from a dispatch table, likely for optimization purposes.
7. **Protected Pointers:**  Loading pointers that might be compressed or protected in some way.
8. **Saving/Restoring Registers:** Utility functions for saving and restoring sets of registers, crucial for calling conventions and maintaining state.
9. **Calling Builtins and Runtime Functions:** Functions for calling pre-compiled code within V8.
10. **Error Handling:**  The `Check`, `SbxCheck`, `Trap`, `DebugBreak`, and `Abort` functions handle error conditions.
11. **Loading Native Context Slots:**  A function to access specific slots in the native context.
12. **Optimized OSR (On-Stack Replacement) Code Loading:** A function to attempt loading optimized code during OSR.
13. **Printf Implementation:**  A `Printf` function for debugging output.
14. **Frame Management:**  Functions like `RestoreFPAndLR` for stack frame manipulation.
15. **WebAssembly Support:** Functions related to WebAssembly, such as storing return addresses in exit frames.
16. **Bit Manipulation Helpers:**  Functions like `PopcntHelper` and bitmask operations, likely used for SIMD operations.
17. **Calling API Functions:** A function `CallApiFunctionAndReturn` to handle calls to external C++ API functions.

Regarding JavaScript relevance, the write barrier is a fundamental concept behind JavaScript's garbage collection. The interaction with builtins and runtime functions directly relates to the implementation of JavaScript language features. The OSR functionality directly impacts the performance of JavaScript code.

I will structure the summary by grouping related functions and providing a high-level explanation of their purpose. For the JavaScript examples, I'll focus on how the write barrier concept is manifested in JavaScript's memory management.
这个C++源代码文件（`macro-assembler-arm64.cc` 的第 3 部分）是 V8 JavaScript 引擎中用于 ARM64 架构的宏汇编器实现的一部分。它包含了实现各种底层操作的函数，这些操作是构建 JavaScript 虚拟机和执行 JavaScript 代码所必需的。

**主要功能归纳:**

1. **内存屏障 (Write Barriers):**  定义了用于在堆内存中写入对象时维护垃圾回收器一致性的机制。这包括 `RecordWriteField`, `RecordWrite`, `CallEphemeronKeyBarrier`, `CallIndirectPointerBarrier`, 和相关的 `CallRecordWriteStub` 函数。这些函数确保当一个对象指向另一个可能需要被垃圾回收的对象时，垃圾回收器能够正确地跟踪这些引用。

2. **指针处理 (Pointer Handling):**  提供了处理不同类型指针的函数，包括：
    * **沙箱指针 (Sandboxed Pointers):**  `DecodeSandboxedPointer`, `LoadSandboxedPointerField`, `StoreSandboxedPointerField` 用于在启用了沙箱安全特性的情况下操作指针。
    * **外部指针 (External Pointers):** `LoadExternalPointerField` 用于加载指向 V8 堆外部内存的指针。
    * **可信指针 (Trusted Pointers):** `LoadTrustedPointerField`, `StoreTrustedPointerField`, `LoadIndirectPointerField`, `StoreIndirectPointerField`, `ResolveIndirectPointerHandle`, `ResolveTrustedPointerHandle`, `ResolveCodePointerHandle`, `LoadCodeEntrypointViaCodePointer` 用于处理指向代码对象或其他关键内部结构的指针。
    * **保护指针 (Protected Pointers):** `LoadProtectedPointerField` 用于加载可能被压缩或以其他方式保护的指针。

3. **代码优化和执行 (Code Optimization and Execution):**
    * **Leaptiering 支持:**  `LoadEntrypointFromJSDispatchTable`, `LoadParameterCountFromJSDispatchTable`, `LoadEntrypointAndParameterCountFromJSDispatchTable` 这些函数用于从 JavaScript 调用分发表中加载入口点和参数计数，这与 V8 的分层编译优化 (Leaptiering) 相关。
    * **OSR (On-Stack Replacement):** `TryLoadOptimizedOsrCode` 用于尝试加载优化的代码，用于在函数执行过程中进行优化切换。

4. **寄存器管理 (Register Management):** `MaybeSaveRegisters` 和 `MaybeRestoreRegisters` 用于保存和恢复一组寄存器，这在调用其他函数或执行特定操作时非常重要。

5. **调用约定 (Calling Conventions):** 涉及调用内置函数、运行时函数和 C++ API 函数的机制，例如 `CallBuiltin`, `CallRecordWriteStub`, `CallApiFunctionAndReturn`。

6. **错误处理 (Error Handling):** 提供了用于检查条件并在失败时触发中止或断点的函数，例如 `Check`, `SbxCheck`, `Trap`, `DebugBreak`, `Abort`。

7. **调试支持 (Debugging Support):** `Printf` 函数允许在生成的代码中插入格式化输出，方便调试。

8. **栈帧管理 (Stack Frame Management):** `RestoreFPAndLR` 用于恢复帧指针 (FP) 和链接寄存器 (LR)，这对于函数返回至关重要。

9. **WebAssembly 支持 (WebAssembly Support):**  `StoreReturnAddressInWasmExitFrame` 用于在 WebAssembly 出口帧中存储返回地址。

10. **位操作辅助函数 (Bit Manipulation Helpers):** 提供了一些辅助函数，如 `PopcntHelper` 用于计算 population count (设置的位的数量)，以及 `I8x16BitMask`, `I16x8BitMask`, `I32x4BitMask`, `I64x2BitMask`, `I64x2AllTrue` 用于 SIMD (Single Instruction, Multiple Data) 相关的位掩码操作。

11. **本地上下文槽位加载 (Native Context Slot Loading):** `LoadNativeContextSlot` 用于加载本地上下文中的特定槽位。

**与 JavaScript 功能的关系 (及 JavaScript 例子):**

这个文件中的代码虽然是 C++，但它直接支持和实现了 JavaScript 的核心功能。以下是一些例子：

* **垃圾回收 (Garbage Collection):** `RecordWriteField` 和 `RecordWrite` 函数是实现增量标记垃圾回收的关键部分。当 JavaScript 代码执行 `obj.property = anotherObj;` 时，如果 `anotherObj` 可能需要被垃圾回收，那么 V8 会插入一个写屏障。

   ```javascript
   let obj1 = { data: 1 };
   let obj2 = { ref: obj1 }; // 当执行这行代码时，可能会触发写屏障
   ```

* **内置函数 (Built-in Functions):** `CallBuiltin` 用于调用 V8 引擎预先编译好的内置函数，例如 `Array.prototype.push` 或 `console.log` 的底层实现。

   ```javascript
   const arr = [1, 2, 3];
   arr.push(4); // 这会调用 V8 的内置 Array.prototype.push 函数
   console.log("Hello"); // 这会调用 V8 的内置 console.log 函数
   ```

* **代码优化 (Code Optimization):**  `TryLoadOptimizedOsrCode` 与 V8 的即时编译 (JIT) 技术有关。当 JavaScript 函数变得“热”时，V8 会尝试编译和替换为优化的机器码。OSR 允许在函数执行过程中进行这种替换。

   ```javascript
   function add(a, b) {
     return a + b;
   }

   for (let i = 0; i < 10000; i++) {
     add(i, i + 1); // 循环多次后，add 函数可能被优化，并可能发生 OSR
   }
   ```

* **错误处理 (Error Handling):** 当 JavaScript 代码抛出异常时，或者当 V8 内部检测到错误时，可能会调用 `Abort` 函数来停止执行。

   ```javascript
   function riskyOperation() {
     throw new Error("Something went wrong!");
   }

   try {
     riskyOperation();
   } catch (e) {
     // 捕获错误，否则 V8 可能会调用类似 Abort 的机制
   }
   ```

总而言之，`macro-assembler-arm64.cc` 的这一部分是 V8 引擎的核心组成部分，它提供了在 ARM64 架构上高效执行 JavaScript 代码所需的底层指令和机制。它抽象了底层的硬件细节，并为 V8 的其他组件（如编译器、解释器和垃圾回收器）提供了构建块。

### 提示词
```
这是目录为v8/src/codegen/arm64/macro-assembler-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```
(destination, kPtrComprCageBaseRegister, destination);
}

void MacroAssembler::CheckPageFlag(const Register& object, int mask,
                                   Condition cc, Label* condition_met) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();
  And(scratch, object, ~MemoryChunk::GetAlignmentMaskForAssembler());
  Ldr(scratch, MemOperand(scratch, MemoryChunk::FlagsOffset()));
  if (cc == ne) {
    TestAndBranchIfAnySet(scratch, mask, condition_met);
  } else {
    DCHECK_EQ(cc, eq);
    TestAndBranchIfAllClear(scratch, mask, condition_met);
  }
}

void MacroAssembler::JumpIfMarking(Label* is_marking,
                                   Label::Distance condition_met_distance) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();
  Ldrb(scratch,
       MemOperand(kRootRegister, IsolateData::is_marking_flag_offset()));
  Cbnz(scratch, is_marking);
}

void MacroAssembler::JumpIfNotMarking(Label* not_marking,
                                      Label::Distance condition_met_distance) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();
  Ldrb(scratch,
       MemOperand(kRootRegister, IsolateData::is_marking_flag_offset()));
  Cbz(scratch, not_marking);
}

void MacroAssembler::RecordWriteField(
    Register object, int offset, Register value, LinkRegisterStatus lr_status,
    SaveFPRegsMode save_fp, SmiCheck smi_check, ReadOnlyCheck ro_check,
    SlotDescriptor slot) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(object, value));
  // First, check if a write barrier is even needed. The tests below
  // catch stores of Smis and read-only objects.
  Label done;

#if V8_STATIC_ROOTS_BOOL
  if (ro_check == ReadOnlyCheck::kInline) {
    // Quick check for Read-only and small Smi values.
    static_assert(StaticReadOnlyRoot::kLastAllocatedRoot < kRegularPageSize);
    JumpIfUnsignedLessThan(value, kRegularPageSize, &done);
  }
#endif  // V8_STATIC_ROOTS_BOOL

  // Skip the barrier if writing a smi.
  if (smi_check == SmiCheck::kInline) {
    JumpIfSmi(value, &done);
  }

  // Although the object register is tagged, the offset is relative to the start
  // of the object, so offset must be a multiple of kTaggedSize.
  DCHECK(IsAligned(offset, kTaggedSize));

  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT_STRING(this, "Verify slot_address");
    Label ok;
    UseScratchRegisterScope temps(this);
    Register scratch = temps.AcquireX();
    DCHECK(!AreAliased(object, value, scratch));
    Add(scratch, object, offset - kHeapObjectTag);
    Tst(scratch, kTaggedSize - 1);
    B(eq, &ok);
    Abort(AbortReason::kUnalignedCellInWriteBarrier);
    Bind(&ok);
  }

  RecordWrite(object, Operand(offset - kHeapObjectTag), value, lr_status,
              save_fp, SmiCheck::kOmit, ReadOnlyCheck::kOmit, slot);

  Bind(&done);
}

void MacroAssembler::DecodeSandboxedPointer(Register value) {
  ASM_CODE_COMMENT(this);
#ifdef V8_ENABLE_SANDBOX
  Add(value, kPtrComprCageBaseRegister,
      Operand(value, LSR, kSandboxedPointerShift));
#else
  UNREACHABLE();
#endif
}

void MacroAssembler::LoadSandboxedPointerField(Register destination,
                                               MemOperand field_operand) {
#ifdef V8_ENABLE_SANDBOX
  ASM_CODE_COMMENT(this);
  Ldr(destination, field_operand);
  DecodeSandboxedPointer(destination);
#else
  UNREACHABLE();
#endif
}

void MacroAssembler::StoreSandboxedPointerField(Register value,
                                                MemOperand dst_field_operand) {
#ifdef V8_ENABLE_SANDBOX
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();
  Sub(scratch, value, kPtrComprCageBaseRegister);
  Mov(scratch, Operand(scratch, LSL, kSandboxedPointerShift));
  Str(scratch, dst_field_operand);
#else
  UNREACHABLE();
#endif
}

void MacroAssembler::LoadExternalPointerField(Register destination,
                                              MemOperand field_operand,
                                              ExternalPointerTag tag,
                                              Register isolate_root) {
  DCHECK(!AreAliased(destination, isolate_root));
  ASM_CODE_COMMENT(this);
#ifdef V8_ENABLE_SANDBOX
  DCHECK_NE(tag, kExternalPointerNullTag);
  DCHECK(!IsSharedExternalPointerType(tag));
  UseScratchRegisterScope temps(this);
  Register external_table = temps.AcquireX();
  if (isolate_root == no_reg) {
    DCHECK(root_array_available_);
    isolate_root = kRootRegister;
  }
  Ldr(external_table,
      MemOperand(isolate_root,
                 IsolateData::external_pointer_table_offset() +
                     Internals::kExternalPointerTableBasePointerOffset));
  Ldr(destination.W(), field_operand);
  Mov(destination, Operand(destination, LSR, kExternalPointerIndexShift));
  Ldr(destination, MemOperand(external_table, destination, LSL,
                              kExternalPointerTableEntrySizeLog2));
  // We need another scratch register for the 64-bit tag constant. Instead of
  // forcing the `And` to allocate a new temp register (which we may not have),
  // reuse the temp register that we used for the external pointer table base.
  Register tag_reg = external_table;
  Mov(tag_reg, Immediate(~tag));
  And(destination, destination, tag_reg);
#else
  Ldr(destination, field_operand);
#endif  // V8_ENABLE_SANDBOX
}

void MacroAssembler::LoadTrustedPointerField(Register destination,
                                             MemOperand field_operand,
                                             IndirectPointerTag tag) {
#ifdef V8_ENABLE_SANDBOX
  LoadIndirectPointerField(destination, field_operand, tag);
#else
  LoadTaggedField(destination, field_operand);
#endif
}

void MacroAssembler::StoreTrustedPointerField(Register value,
                                              MemOperand dst_field_operand) {
#ifdef V8_ENABLE_SANDBOX
  StoreIndirectPointerField(value, dst_field_operand);
#else
  StoreTaggedField(value, dst_field_operand);
#endif
}

void MacroAssembler::LoadIndirectPointerField(Register destination,
                                              MemOperand field_operand,
                                              IndirectPointerTag tag) {
#ifdef V8_ENABLE_SANDBOX
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);

  Register handle = temps.AcquireX();
  Ldr(handle.W(), field_operand);
  ResolveIndirectPointerHandle(destination, handle, tag);
#else
  UNREACHABLE();
#endif  // V8_ENABLE_SANDBOX
}

void MacroAssembler::StoreIndirectPointerField(Register value,
                                               MemOperand dst_field_operand) {
#ifdef V8_ENABLE_SANDBOX
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();
  Ldr(scratch.W(),
      FieldMemOperand(value, ExposedTrustedObject::kSelfIndirectPointerOffset));
  Str(scratch.W(), dst_field_operand);
#else
  UNREACHABLE();
#endif  // V8_ENABLE_SANDBOX
}

#ifdef V8_ENABLE_SANDBOX
void MacroAssembler::ResolveIndirectPointerHandle(Register destination,
                                                  Register handle,
                                                  IndirectPointerTag tag) {
  // The tag implies which pointer table to use.
  if (tag == kUnknownIndirectPointerTag) {
    // In this case we have to rely on the handle marking to determine which
    // pointer table to use.
    Label is_trusted_pointer_handle, done;
    constexpr int kCodePointerHandleMarkerBit = 0;
    static_assert((1 << kCodePointerHandleMarkerBit) ==
                  kCodePointerHandleMarker);
    Tbz(handle, kCodePointerHandleMarkerBit, &is_trusted_pointer_handle);
    ResolveCodePointerHandle(destination, handle);
    B(&done);
    Bind(&is_trusted_pointer_handle);
    ResolveTrustedPointerHandle(destination, handle,
                                kUnknownIndirectPointerTag);
    Bind(&done);
  } else if (tag == kCodeIndirectPointerTag) {
    ResolveCodePointerHandle(destination, handle);
  } else {
    ResolveTrustedPointerHandle(destination, handle, tag);
  }
}

void MacroAssembler::ResolveTrustedPointerHandle(Register destination,
                                                 Register handle,
                                                 IndirectPointerTag tag) {
  DCHECK_NE(tag, kCodeIndirectPointerTag);
  DCHECK(!AreAliased(handle, destination));

  Register table = destination;
  DCHECK(root_array_available_);
  Ldr(table,
      MemOperand{kRootRegister, IsolateData::trusted_pointer_table_offset()});
  Mov(handle, Operand(handle, LSR, kTrustedPointerHandleShift));
  Ldr(destination,
      MemOperand(table, handle, LSL, kTrustedPointerTableEntrySizeLog2));
  // Untag the pointer and remove the marking bit in one operation.
  Register tag_reg = handle;
  Mov(tag_reg, Immediate(~(tag | kTrustedPointerTableMarkBit)));
  And(destination, destination, tag_reg);
}

void MacroAssembler::ResolveCodePointerHandle(Register destination,
                                              Register handle) {
  DCHECK(!AreAliased(handle, destination));

  Register table = destination;
  Mov(table, ExternalReference::code_pointer_table_address());
  Mov(handle, Operand(handle, LSR, kCodePointerHandleShift));
  Add(destination, table, Operand(handle, LSL, kCodePointerTableEntrySizeLog2));
  Ldr(destination,
      MemOperand(destination,
                 Immediate(kCodePointerTableEntryCodeObjectOffset)));
  // The LSB is used as marking bit by the code pointer table, so here we have
  // to set it using a bitwise OR as it may or may not be set.
  Orr(destination, destination, Immediate(kHeapObjectTag));
}

void MacroAssembler::LoadCodeEntrypointViaCodePointer(Register destination,
                                                      MemOperand field_operand,
                                                      CodeEntrypointTag tag) {
  DCHECK_NE(tag, kInvalidEntrypointTag);
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();
  Mov(scratch, ExternalReference::code_pointer_table_address());
  Ldr(destination.W(), field_operand);
  // TODO(saelo): can the offset computation be done more efficiently?
  Mov(destination, Operand(destination, LSR, kCodePointerHandleShift));
  Mov(destination, Operand(destination, LSL, kCodePointerTableEntrySizeLog2));
  Ldr(destination, MemOperand(scratch, destination));
  if (tag != 0) {
    Mov(scratch, Immediate(tag));
    Eor(destination, destination, scratch);
  }
}
#endif  // V8_ENABLE_SANDBOX

#ifdef V8_ENABLE_LEAPTIERING
void MacroAssembler::LoadEntrypointFromJSDispatchTable(Register destination,
                                                       Register dispatch_handle,
                                                       Register scratch) {
  DCHECK(!AreAliased(destination, dispatch_handle, scratch));
  ASM_CODE_COMMENT(this);

  Register index = destination;
  Mov(scratch, ExternalReference::js_dispatch_table_address());
  Mov(index, Operand(dispatch_handle, LSR, kJSDispatchHandleShift));
  Add(scratch, scratch, Operand(index, LSL, kJSDispatchTableEntrySizeLog2));
  Ldr(destination, MemOperand(scratch, JSDispatchEntry::kEntrypointOffset));
}

void MacroAssembler::LoadParameterCountFromJSDispatchTable(
    Register destination, Register dispatch_handle, Register scratch) {
  DCHECK(!AreAliased(destination, dispatch_handle, scratch));
  ASM_CODE_COMMENT(this);

  Register index = destination;
  Mov(scratch, ExternalReference::js_dispatch_table_address());
  Mov(index, Operand(dispatch_handle, LSR, kJSDispatchHandleShift));
  Add(scratch, scratch, Operand(index, LSL, kJSDispatchTableEntrySizeLog2));
  static_assert(JSDispatchEntry::kParameterCountMask == 0xffff);
  Ldrh(destination, MemOperand(scratch, JSDispatchEntry::kCodeObjectOffset));
}

void MacroAssembler::LoadEntrypointAndParameterCountFromJSDispatchTable(
    Register entrypoint, Register parameter_count, Register dispatch_handle,
    Register scratch) {
  DCHECK(!AreAliased(entrypoint, parameter_count, dispatch_handle, scratch));
  ASM_CODE_COMMENT(this);

  Register index = parameter_count;
  Mov(scratch, ExternalReference::js_dispatch_table_address());
  Mov(index, Operand(dispatch_handle, LSR, kJSDispatchHandleShift));
  Add(scratch, scratch, Operand(index, LSL, kJSDispatchTableEntrySizeLog2));
  Ldr(entrypoint, MemOperand(scratch, JSDispatchEntry::kEntrypointOffset));
  static_assert(JSDispatchEntry::kParameterCountMask == 0xffff);
  Ldrh(parameter_count,
       MemOperand(scratch, JSDispatchEntry::kCodeObjectOffset));
}
#endif

void MacroAssembler::LoadProtectedPointerField(Register destination,
                                               MemOperand field_operand) {
  DCHECK(root_array_available());
#ifdef V8_ENABLE_SANDBOX
  DecompressProtected(destination, field_operand);
#else
  LoadTaggedField(destination, field_operand);
#endif
}

void MacroAssembler::MaybeSaveRegisters(RegList registers) {
  if (registers.is_empty()) return;
  ASM_CODE_COMMENT(this);
  CPURegList regs(kXRegSizeInBits, registers);
  // If we were saving LR, we might need to sign it.
  DCHECK(!regs.IncludesAliasOf(lr));
  regs.Align();
  PushCPURegList(regs);
}

void MacroAssembler::MaybeRestoreRegisters(RegList registers) {
  if (registers.is_empty()) return;
  ASM_CODE_COMMENT(this);
  CPURegList regs(kXRegSizeInBits, registers);
  // If we were saving LR, we might need to sign it.
  DCHECK(!regs.IncludesAliasOf(lr));
  regs.Align();
  PopCPURegList(regs);
}

void MacroAssembler::CallEphemeronKeyBarrier(Register object, Operand offset,
                                             SaveFPRegsMode fp_mode) {
  ASM_CODE_COMMENT(this);
  RegList registers = WriteBarrierDescriptor::ComputeSavedRegisters(object);
  MaybeSaveRegisters(registers);

  MoveObjectAndSlot(WriteBarrierDescriptor::ObjectRegister(),
                    WriteBarrierDescriptor::SlotAddressRegister(), object,
                    offset);

  CallBuiltin(Builtins::EphemeronKeyBarrier(fp_mode));
  MaybeRestoreRegisters(registers);
}

void MacroAssembler::CallIndirectPointerBarrier(Register object, Operand offset,
                                                SaveFPRegsMode fp_mode,
                                                IndirectPointerTag tag) {
  ASM_CODE_COMMENT(this);
  RegList registers =
      IndirectPointerWriteBarrierDescriptor::ComputeSavedRegisters(object);
  MaybeSaveRegisters(registers);

  MoveObjectAndSlot(
      IndirectPointerWriteBarrierDescriptor::ObjectRegister(),
      IndirectPointerWriteBarrierDescriptor::SlotAddressRegister(), object,
      offset);
  Mov(IndirectPointerWriteBarrierDescriptor::IndirectPointerTagRegister(),
      Operand(tag));

  CallBuiltin(Builtins::IndirectPointerBarrier(fp_mode));
  MaybeRestoreRegisters(registers);
}

void MacroAssembler::CallRecordWriteStubSaveRegisters(Register object,
                                                      Operand offset,
                                                      SaveFPRegsMode fp_mode,
                                                      StubCallMode mode) {
  ASM_CODE_COMMENT(this);
  RegList registers = WriteBarrierDescriptor::ComputeSavedRegisters(object);
  MaybeSaveRegisters(registers);

  Register object_parameter = WriteBarrierDescriptor::ObjectRegister();
  Register slot_address_parameter =
      WriteBarrierDescriptor::SlotAddressRegister();
  MoveObjectAndSlot(object_parameter, slot_address_parameter, object, offset);

  CallRecordWriteStub(object_parameter, slot_address_parameter, fp_mode, mode);

  MaybeRestoreRegisters(registers);
}

void MacroAssembler::CallRecordWriteStub(Register object, Register slot_address,
                                         SaveFPRegsMode fp_mode,
                                         StubCallMode mode) {
  ASM_CODE_COMMENT(this);
  DCHECK_EQ(WriteBarrierDescriptor::ObjectRegister(), object);
  DCHECK_EQ(WriteBarrierDescriptor::SlotAddressRegister(), slot_address);
#if V8_ENABLE_WEBASSEMBLY
  if (mode == StubCallMode::kCallWasmRuntimeStub) {
    auto wasm_target =
        static_cast<Address>(wasm::WasmCode::GetRecordWriteBuiltin(fp_mode));
    Call(wasm_target, RelocInfo::WASM_STUB_CALL);
#else
  if (false) {
#endif
  } else {
    CallBuiltin(Builtins::RecordWrite(fp_mode));
  }
}

void MacroAssembler::MoveObjectAndSlot(Register dst_object, Register dst_slot,
                                       Register object, Operand offset) {
  ASM_CODE_COMMENT(this);
  DCHECK_NE(dst_object, dst_slot);
  // If `offset` is a register, it cannot overlap with `object`.
  DCHECK_IMPLIES(!offset.IsImmediate(), offset.reg() != object);

  // If the slot register does not overlap with the object register, we can
  // overwrite it.
  if (dst_slot != object) {
    Add(dst_slot, object, offset);
    Mov(dst_object, object);
    return;
  }

  DCHECK_EQ(dst_slot, object);

  // If the destination object register does not overlap with the offset
  // register, we can overwrite it.
  if (offset.IsImmediate() || (offset.reg() != dst_object)) {
    Mov(dst_object, dst_slot);
    Add(dst_slot, dst_slot, offset);
    return;
  }

  DCHECK_EQ(dst_object, offset.reg());

  // We only have `dst_slot` and `dst_object` left as distinct registers so we
  // have to swap them. We write this as a add+sub sequence to avoid using a
  // scratch register.
  Add(dst_slot, dst_slot, dst_object);
  Sub(dst_object, dst_slot, dst_object);
}

// If lr_status is kLRHasBeenSaved, lr will be clobbered.
//
// The register 'object' contains a heap object pointer. The heap object tag is
// shifted away.
void MacroAssembler::RecordWrite(Register object, Operand offset,
                                 Register value, LinkRegisterStatus lr_status,
                                 SaveFPRegsMode fp_mode, SmiCheck smi_check,
                                 ReadOnlyCheck ro_check, SlotDescriptor slot) {
  ASM_CODE_COMMENT(this);
  ASM_LOCATION_IN_ASSEMBLER("MacroAssembler::RecordWrite");
  DCHECK(!AreAliased(object, value));

  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT_STRING(this, "Verify slot_address");
    UseScratchRegisterScope temps(this);
    Register temp = temps.AcquireX();
    DCHECK(!AreAliased(object, value, temp));
    Add(temp, object, offset);
    if (slot.contains_indirect_pointer()) {
      LoadIndirectPointerField(temp, MemOperand(temp),
                               slot.indirect_pointer_tag());
    } else {
      DCHECK(slot.contains_direct_pointer());
      LoadTaggedField(temp, MemOperand(temp));
    }
    Cmp(temp, value);
    Check(eq, AbortReason::kWrongAddressOrValuePassedToRecordWrite);
  }

  if (v8_flags.disable_write_barriers) {
    return;
  }

  // First, check if a write barrier is even needed. The tests below
  // catch stores of smisand read-only objects, as well as stores into the
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
    DCHECK_EQ(0, kSmiTag);
    JumpIfSmi(value, &done);
  }

  if (slot.contains_indirect_pointer()) {
    // The indirect pointer write barrier is only enabled during marking.
    JumpIfNotMarking(&done);
  } else {
    CheckPageFlag(value, MemoryChunk::kPointersToHereAreInterestingMask, eq,
                  &done);

    CheckPageFlag(object, MemoryChunk::kPointersFromHereAreInterestingMask, eq,
                  &done);
  }

  // Record the actual write.
  if (lr_status == kLRHasNotBeenSaved) {
    Push<MacroAssembler::kSignLR>(padreg, lr);
  }
  Register slot_address = WriteBarrierDescriptor::SlotAddressRegister();
  DCHECK(!AreAliased(object, slot_address, value));
  if (slot.contains_direct_pointer()) {
    // TODO(cbruni): Turn offset into int.
    DCHECK(offset.IsImmediate());
    Add(slot_address, object, offset);
    CallRecordWriteStub(object, slot_address, fp_mode,
                        StubCallMode::kCallBuiltinPointer);
  } else {
    DCHECK(slot.contains_indirect_pointer());
    CallIndirectPointerBarrier(object, offset, fp_mode,
                               slot.indirect_pointer_tag());
  }
  if (lr_status == kLRHasNotBeenSaved) {
    Pop<MacroAssembler::kAuthLR>(lr, padreg);
  }
  if (v8_flags.debug_code) Mov(slot_address, Operand(kZapValue));

  Bind(&done);
}

void MacroAssembler::Check(Condition cond, AbortReason reason) {
  Label ok;
  B(cond, &ok);
  Abort(reason);
  // Will not return here.
  Bind(&ok);
}

void MacroAssembler::SbxCheck(Condition cc, AbortReason reason) {
  Check(cc, reason);
}

void MacroAssembler::Trap() { Brk(0); }
void MacroAssembler::DebugBreak() { Debug("DebugBreak", 0, BREAK); }

void MacroAssembler::Abort(AbortReason reason) {
  ASM_CODE_COMMENT(this);
  if (v8_flags.code_comments) {
    RecordComment("Abort message: ");
    RecordComment(GetAbortReason(reason));
  }

  // Avoid emitting call to builtin if requested.
  if (trap_on_abort()) {
    Brk(0);
    return;
  }

  // We need some scratch registers for the MacroAssembler, so make sure we have
  // some. This is safe here because Abort never returns.
  uint64_t old_tmp_list = TmpList()->bits();
  TmpList()->Combine(MacroAssembler::DefaultTmpList());

  if (should_abort_hard()) {
    // We don't care if we constructed a frame. Just pretend we did.
    FrameScope assume_frame(this, StackFrame::NO_FRAME_TYPE);
    Mov(w0, static_cast<int>(reason));
    Call(ExternalReference::abort_with_reason());
    return;
  }

  // Avoid infinite recursion; Push contains some assertions that use Abort.
  HardAbortScope hard_aborts(this);

  Mov(x1, Smi::FromInt(static_cast<int>(reason)));

  {
    // We don't actually want to generate a pile of code for this, so just
    // claim there is a stack frame, without generating one.
    FrameScope scope(this, StackFrame::NO_FRAME_TYPE);
    if (root_array_available()) {
      // Generate an indirect call via builtins entry table here in order to
      // ensure that the interpreter_entry_return_pc_offset is the same for
      // InterpreterEntryTrampoline and InterpreterEntryTrampolineForProfiling
      // when v8_flags.debug_code is enabled.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.AcquireX();
      LoadEntryFromBuiltin(Builtin::kAbort, scratch);
      Call(scratch);
    } else {
      CallBuiltin(Builtin::kAbort);
    }
  }

  TmpList()->set_bits(old_tmp_list);
}

void MacroAssembler::LoadNativeContextSlot(Register dst, int index) {
  LoadMap(dst, cp);
  LoadTaggedField(
      dst, FieldMemOperand(
               dst, Map::kConstructorOrBackPointerOrNativeContextOffset));
  LoadTaggedField(dst, MemOperand(dst, Context::SlotOffset(index)));
}

void MacroAssembler::TryLoadOptimizedOsrCode(Register scratch_and_result,
                                             CodeKind min_opt_level,
                                             Register feedback_vector,
                                             FeedbackSlot slot,
                                             Label* on_result,
                                             Label::Distance) {
  Label fallthrough, clear_slot;
  LoadTaggedField(
      scratch_and_result,
      FieldMemOperand(feedback_vector,
                      FeedbackVector::OffsetOfElementAt(slot.ToInt())));
  LoadWeakValue(scratch_and_result, scratch_and_result, &fallthrough);

  // Is it marked_for_deoptimization? If yes, clear the slot.
  {
    UseScratchRegisterScope temps(this);

    // The entry references a CodeWrapper object. Unwrap it now.
    LoadCodePointerField(
        scratch_and_result,
        FieldMemOperand(scratch_and_result, CodeWrapper::kCodeOffset));

    Register temp = temps.AcquireX();
    JumpIfCodeIsMarkedForDeoptimization(scratch_and_result, temp, &clear_slot);
    if (min_opt_level == CodeKind::TURBOFAN_JS) {
      JumpIfCodeIsTurbofanned(scratch_and_result, temp, on_result);
      B(&fallthrough);
    } else {
      B(on_result);
    }
  }

  bind(&clear_slot);
  Mov(scratch_and_result, ClearedValue());
  StoreTaggedField(
      scratch_and_result,
      FieldMemOperand(feedback_vector,
                      FeedbackVector::OffsetOfElementAt(slot.ToInt())));

  bind(&fallthrough);
  Mov(scratch_and_result, 0);
}

// This is the main Printf implementation. All other Printf variants call
// PrintfNoPreserve after setting up one or more PreserveRegisterScopes.
void MacroAssembler::PrintfNoPreserve(const char* format,
                                      const CPURegister& arg0,
                                      const CPURegister& arg1,
                                      const CPURegister& arg2,
                                      const CPURegister& arg3) {
  ASM_CODE_COMMENT(this);
  // We cannot handle a caller-saved stack pointer. It doesn't make much sense
  // in most cases anyway, so this restriction shouldn't be too serious.
  DCHECK(!kCallerSaved.IncludesAliasOf(sp));

  // The provided arguments, and their proper procedure-call standard registers.
  CPURegister args[kPrintfMaxArgCount] = {arg0, arg1, arg2, arg3};
  CPURegister pcs[kPrintfMaxArgCount] = {NoReg, NoReg, NoReg, NoReg};

  int arg_count = kPrintfMaxArgCount;

  // The PCS varargs registers for printf. Note that x0 is used for the printf
  // format string.
  static const CPURegList kPCSVarargs =
      CPURegList(CPURegister::kRegister, kXRegSizeInBits, 1, arg_count);
  static const CPURegList kPCSVarargsFP =
      CPURegList(CPURegister::kVRegister, kDRegSizeInBits, 0, arg_count - 1);

  // We can use caller-saved registers as scratch values, except for the
  // arguments and the PCS registers where they might need to go.
  CPURegList tmp_list = kCallerSaved;
  tmp_list.Remove(x0);  // Used to pass the format string.
  tmp_list.Remove(kPCSVarargs);
  tmp_list.Remove(arg0, arg1, arg2, arg3);

  CPURegList fp_tmp_list = kCallerSavedV;
  fp_tmp_list.Remove(kPCSVarargsFP);
  fp_tmp_list.Remove(arg0, arg1, arg2, arg3);

  // Override the MacroAssembler's scratch register list. The lists will be
  // reset automatically at the end of the UseScratchRegisterScope.
  UseScratchRegisterScope temps(this);
  TmpList()->set_bits(tmp_list.bits());
  FPTmpList()->set_bits(fp_tmp_list.bits());

  // Copies of the printf vararg registers that we can pop from.
  CPURegList pcs_varargs = kPCSVarargs;
#ifndef V8_OS_WIN
  CPURegList pcs_varargs_fp = kPCSVarargsFP;
#endif

  // Place the arguments. There are lots of clever tricks and optimizations we
  // could use here, but Printf is a debug tool so instead we just try to keep
  // it simple: Move each input that isn't already in the right place to a
  // scratch register, then move everything back.
  for (unsigned i = 0; i < kPrintfMaxArgCount; i++) {
    // Work out the proper PCS register for this argument.
    if (args[i].IsRegister()) {
      pcs[i] = pcs_varargs.PopLowestIndex().X();
      // We might only need a W register here. We need to know the size of the
      // argument so we can properly encode it for the simulator call.
      if (args[i].Is32Bits()) pcs[i] = pcs[i].W();
    } else if (args[i].IsVRegister()) {
      // In C, floats are always cast to doubles for varargs calls.
#ifdef V8_OS_WIN
      // In case of variadic functions SIMD and Floating-point registers
      // aren't used. The general x0-x7 should be used instead.
      // https://docs.microsoft.com/en-us/cpp/build/arm64-windows-abi-conventions
      pcs[i] = pcs_varargs.PopLowestIndex().X();
#else
      pcs[i] = pcs_varargs_fp.PopLowestIndex().D();
#endif
    } else {
      DCHECK(args[i].IsNone());
      arg_count = i;
      break;
    }

    // If the argument is already in the right place, leave it where it is.
    if (args[i].Aliases(pcs[i])) continue;

    // Otherwise, if the argument is in a PCS argument register, allocate an
    // appropriate scratch register and then move it out of the way.
    if (kPCSVarargs.IncludesAliasOf(args[i]) ||
        kPCSVarargsFP.IncludesAliasOf(args[i])) {
      if (args[i].IsRegister()) {
        Register old_arg = args[i].Reg();
        Register new_arg = temps.AcquireSameSizeAs(old_arg);
        Mov(new_arg, old_arg);
        args[i] = new_arg;
      } else {
        VRegister old_arg = args[i].VReg();
        VRegister new_arg = temps.AcquireSameSizeAs(old_arg);
        Fmov(new_arg, old_arg);
        args[i] = new_arg;
      }
    }
  }

  // Do a second pass to move values into their final positions and perform any
  // conversions that may be required.
  for (int i = 0; i < arg_count; i++) {
#ifdef V8_OS_WIN
    if (args[i].IsVRegister()) {
      if (pcs[i].SizeInBytes() != args[i].SizeInBytes()) {
        // If the argument is half- or single-precision
        // converts to double-precision before that is
        // moved into the one of X scratch register.
        VRegister temp0 = temps.AcquireD();
        Fcvt(temp0.VReg(), args[i].VReg());
        Fmov(pcs[i].Reg(), temp0);
      } else {
        Fmov(pcs[i].Reg(), args[i].VReg());
      }
    } else {
      Mov(pcs[i].Reg(), args[i].Reg(), kDiscardForSameWReg);
    }
#else
    DCHECK(pcs[i].type() == args[i].type());
    if (pcs[i].IsRegister()) {
      Mov(pcs[i].Reg(), args[i].Reg(), kDiscardForSameWReg);
    } else {
      DCHECK(pcs[i].IsVRegister());
      if (pcs[i].SizeInBytes() == args[i].SizeInBytes()) {
        Fmov(pcs[i].VReg(), args[i].VReg());
      } else {
        Fcvt(pcs[i].VReg(), args[i].VReg());
      }
    }
#endif
  }

  // Load the format string into x0, as per the procedure-call standard.
  //
  // To make the code as portable as possible, the format string is encoded
  // directly in the instruction stream. It might be cleaner to encode it in a
  // literal pool, but since Printf is usually used for debugging, it is
  // beneficial for it to be minimally dependent on other features.
  Label format_address;
  Adr(x0, &format_address);

  // Emit the format string directly in the instruction stream.
  {
    BlockPoolsScope scope(this);
    Label after_data;
    B(&after_data);
    Bind(&format_address);
    EmitStringData(format);
    Unreachable();
    Bind(&after_data);
  }

  CallPrintf(arg_count, pcs);
}

void MacroAssembler::CallPrintf(int arg_count, const CPURegister* args) {
  ASM_CODE_COMMENT(this);
  // A call to printf needs special handling for the simulator, since the system
  // printf function will use a different instruction set and the procedure-call
  // standard will not be compatible.
  if (options().enable_simulator_code) {
    InstructionAccurateScope scope(this, kPrintfLength / kInstrSize);
    hlt(kImmExceptionIsPrintf);
    dc32(arg_count);  // kPrintfArgCountOffset

    // Determine the argument pattern.
    uint32_t arg_pattern_list = 0;
    for (int i = 0; i < arg_count; i++) {
      uint32_t arg_pattern;
      if (args[i].IsRegister()) {
        arg_pattern = args[i].Is32Bits() ? kPrintfArgW : kPrintfArgX;
      } else {
        DCHECK(args[i].Is64Bits());
        arg_pattern = kPrintfArgD;
      }
      DCHECK(arg_pattern < (1 << kPrintfArgPatternBits));
      arg_pattern_list |= (arg_pattern << (kPrintfArgPatternBits * i));
    }
    dc32(arg_pattern_list);  // kPrintfArgPatternListOffset
    return;
  }

  Call(ExternalReference::printf_function());
}

void MacroAssembler::Printf(const char* format, CPURegister arg0,
                            CPURegister arg1, CPURegister arg2,
                            CPURegister arg3) {
  ASM_CODE_COMMENT(this);
  // Printf is expected to preserve all registers, so make sure that none are
  // available as scratch registers until we've preserved them.
  uint64_t old_tmp_list = TmpList()->bits();
  uint64_t old_fp_tmp_list = FPTmpList()->bits();
  TmpList()->set_bits(0);
  FPTmpList()->set_bits(0);

  CPURegList saved_registers = kCallerSaved;
  saved_registers.Align();

  // Preserve all caller-saved registers as well as NZCV.
  // PushCPURegList asserts that the size of each list is a multiple of 16
  // bytes.
  PushCPURegList(saved_registers);
  PushCPURegList(kCallerSavedV);

  // We can use caller-saved registers as scratch values (except for argN).
  CPURegList tmp_list = saved_registers;
  CPURegList fp_tmp_list = kCallerSavedV;
  tmp_list.Remove(arg0, arg1, arg2, arg3);
  fp_tmp_list.Remove(arg0, arg1, arg2, arg3);
  TmpList()->set_bits(tmp_list.bits());
  FPTmpList()->set_bits(fp_tmp_list.bits());

  {
    UseScratchRegisterScope temps(this);
    // If any of the arguments are the current stack pointer, allocate a new
    // register for them, and adjust the value to compensate for pushing the
    // caller-saved registers.
    bool arg0_sp = arg0.is_valid() && sp.Aliases(arg0);
    bool arg1_sp = arg1.is_valid() && sp.Aliases(arg1);
    bool arg2_sp = arg2.is_valid() && sp.Aliases(arg2);
    bool arg3_sp = arg3.is_valid() && sp.Aliases(arg3);
    if (arg0_sp || arg1_sp || arg2_sp || arg3_sp) {
      // Allocate a register to hold the original stack pointer value, to pass
      // to PrintfNoPreserve as an argument.
      Register arg_sp = temps.AcquireX();
      Add(arg_sp, sp,
          saved_registers.TotalSizeInBytes() +
              kCallerSavedV.TotalSizeInBytes());
      if (arg0_sp) arg0 = Register::Create(arg_sp.code(), arg0.SizeInBits());
      if (arg1_sp) arg1 = Register::Create(arg_sp.code(), arg1.SizeInBits());
      if (arg2_sp) arg2 = Register::Create(arg_sp.code(), arg2.SizeInBits());
      if (arg3_sp) arg3 = Register::Create(arg_sp.code(), arg3.SizeInBits());
    }

    // Preserve NZCV.
    {
      UseScratchRegisterScope temps(this);
      Register tmp = temps.AcquireX();
      Mrs(tmp, NZCV);
      Push(tmp, xzr);
    }

    PrintfNoPreserve(format, arg0, arg1, arg2, arg3);

    // Restore NZCV.
    {
      UseScratchRegisterScope temps(this);
      Register tmp = temps.AcquireX();
      Pop(xzr, tmp);
      Msr(NZCV, tmp);
    }
  }

  PopCPURegList(kCallerSavedV);
  PopCPURegList(saved_registers);

  TmpList()->set_bits(old_tmp_list);
  FPTmpList()->set_bits(old_fp_tmp_list);
}

void MacroAssembler::ComputeCodeStartAddress(const Register& rd) {
  // We can use adr to load a pc relative location.
  adr(rd, -pc_offset());
}

void MacroAssembler::RestoreFPAndLR() {
  static_assert(StandardFrameConstants::kCallerFPOffset + kSystemPointerSize ==
                    StandardFrameConstants::kCallerPCOffset,
                "Offsets must be consecutive for ldp!");
#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
  // Make sure we can use x16 and x17.
  UseScratchRegisterScope temps(this);
  temps.Exclude(x16, x17);
  // We can load the return address directly into x17.
  Add(x16, fp, StandardFrameConstants::kCallerSPOffset);
  Ldp(fp, x17, MemOperand(fp, StandardFrameConstants::kCallerFPOffset));
  Autib1716();
  Mov(lr, x17);
#else
  Ldp(fp, lr, MemOperand(fp, StandardFrameConstants::kCallerFPOffset));
#endif
}

#if V8_ENABLE_WEBASSEMBLY
void MacroAssembler::StoreReturnAddressInWasmExitFrame(Label* return_location) {
  UseScratchRegisterScope temps(this);
  temps.Exclude(x16, x17);
  Adr(x17, return_location);
#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
  Add(x16, fp, WasmExitFrameConstants::kCallingPCOffset + kSystemPointerSize);
  Pacib1716();
#endif
  Str(x17, MemOperand(fp, WasmExitFrameConstants::kCallingPCOffset));
}
#endif  // V8_ENABLE_WEBASSEMBLY

void MacroAssembler::PopcntHelper(Register dst, Register src) {
  UseScratchRegisterScope temps(this);
  VRegister scratch = temps.AcquireV(kFormat8B);
  VRegister tmp = src.Is32Bits() ? scratch.S() : scratch.D();
  Fmov(tmp, src);
  Cnt(scratch, scratch);
  Addv(scratch.B(), scratch);
  Fmov(dst, tmp);
}

void MacroAssembler::I8x16BitMask(Register dst, VRegister src, VRegister temp) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  VRegister tmp = temps.AcquireQ();
  VRegister mask = temps.AcquireQ();

  if (CpuFeatures::IsSupported(PMULL1Q) && temp.is_valid()) {
    CpuFeatureScope scope(this, PMULL1Q);

    Movi(mask.V2D(), 0x0102'0408'1020'4080);
    // Normalize the input - at most 1 bit per vector element should be set.
    Ushr(tmp.V16B(), src.V16B(), 7);
    // Collect the input bits into a byte of the output - once for each
    // half of the input.
    Pmull2(temp.V1Q(), mask.V2D(), tmp.V2D());
    Pmull(tmp.V1Q(), mask.V1D(), tmp.V1D());
    // Combine the bits from both input halves.
    Trn2(tmp.V8B(), tmp.V8B(), temp.V8B());
    Mov(dst.W(), tmp.V8H(), 3);
  } else {
    // Set i-th bit of each lane i. When AND with tmp, the lanes that
    // are signed will have i-th bit set, unsigned will be 0.
    Sshr(tmp.V16B(), src.V16B(), 7);
    Movi(mask.V2D(), 0x8040'2010'0804'0201);
    And(tmp.V16B(), mask.V16B(), tmp.V16B());
    Ext(mask.V16B(), tmp.V16B(), tmp.V16B(), 8);
    Zip1(tmp.V16B(), tmp.V16B(), mask.V16B());
    Addv(tmp.H(), tmp.V8H());
    Mov(dst.W(), tmp.V8H(), 0);
  }
}

void MacroAssembler::I16x8BitMask(Register dst, VRegister src) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  VRegister tmp = temps.AcquireQ();
  VRegister mask = temps.AcquireQ();

  if (CpuFeatures::IsSupported(PMULL1Q)) {
    CpuFeatureScope scope(this, PMULL1Q);

    // Normalize the input - at most 1 bit per vector element should be set.
    Ushr(tmp.V8H(), src.V8H(), 15);
    Movi(mask.V1D(), 0x0102'0408'1020'4080);
    // Trim some of the redundant 0 bits, so that we can operate on
    // only 64 bits.
    Xtn(tmp.V8B(), tmp.V8H());
    // Collect the input bits into a byte of the output.
    Pmull(tmp.V1Q(), tmp.V1D(), mask.V1D());
    Mov(dst.W(), tmp.V16B(), 7);
  } else {
    Sshr(tmp.V8H(), src.V8H(), 15);
    // Set i-th bit of each lane i. When AND with tmp, the lanes that
    // are signed will have i-th bit set, unsigned will be 0.
    Movi(mask.V2D(), 0x0080'0040'0020'0010, 0x0008'0004'0002'0001);
    And(tmp.V16B(), mask.V16B(), tmp.V16B());
    Addv(tmp.H(), tmp.V8H());
    Mov(dst.W(), tmp.V8H(), 0);
  }
}

void MacroAssembler::I32x4BitMask(Register dst, VRegister src) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register tmp = temps.AcquireX();
  Mov(dst.X(), src.D(), 1);
  Fmov(tmp.X(), src.D());
  And(dst.X(), dst.X(), 0x80000000'80000000);
  And(tmp.X(), tmp.X(), 0x80000000'80000000);
  Orr(dst.X(), dst.X(), Operand(dst.X(), LSL, 31));
  Orr(tmp.X(), tmp.X(), Operand(tmp.X(), LSL, 31));
  Lsr(dst.X(), dst.X(), 60);
  Bfxil(dst.X(), tmp.X(), 62, 2);
}

void MacroAssembler::I64x2BitMask(Register dst, VRegister src) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope scope(this);
  Register tmp = scope.AcquireX();
  Mov(dst.X(), src.D(), 1);
  Fmov(tmp.X(), src.D());
  Lsr(dst.X(), dst.X(), 62);
  Bfxil(dst.X(), tmp.X(), 63, 1);
}

void MacroAssembler::I64x2AllTrue(Register dst, VRegister src) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope scope(this);
  VRegister tmp = scope.AcquireV(kFormat2D);
  Cmeq(tmp.V2D(), src.V2D(), 0);
  Addp(tmp.D(), tmp);
  Fcmp(tmp.D(), tmp.D());
  Cset(dst, eq);
}

// Calls an API function. Allocates HandleScope, extracts returned value
// from handle and propagates exceptions. Clobbers C argument registers
// and C caller-saved registers. Restores context. On return removes
//   (*argc_operand + slots_to_drop_on_return) * kSystemPointerSize
// (GCed, includes the call JS arguments space and the additional space
// allocated for the fast call).
void CallApiFunctionAndReturn(MacroAssembler* masm, bool with_profiling,
                              Register function_address,
                              ExternalReference thunk_ref, Register thunk_arg,
                              int slots_to_drop_on_return,
                              MemOperand* argc_operand,
                              MemOperand return_value_operand) {
  ASM_CODE_COMMENT(masm);
  ASM_LOCATION("CallApiFunctionAndReturn");

  using ER = ExternalReference;

  Isolate* isolate = masm->isolate();
  MemOperand next_mem_op = __ ExternalReferenceAsOperand(
      ER::handle_scope_next_address(isolate), no_reg);
  MemOperand limit_mem_op = __ ExternalReferenceAsOperand(
      ER::handle_scope_limit_address(isolate), no_reg);
  MemOperand level_mem_op = __ ExternalReferenceAsOperand(
      ER::handle_scope_level_address(isolate), no_reg);

  Register return_value = x0;
  Register scratch = x4;
  Register scratch2 = x5;

  // Allocate HandleScope in callee-saved registers.
  // We will need to restore the HandleScope after the call to the API function,
  // by allocating it in callee-saved registers it'll be preserved by C code.
  Register prev_next_address_reg = x19;
  Register prev_limit_reg = x20;
  Register prev_level_reg = w21;

  // C arguments (kCArgRegs[0/1]) are expected to be initialized outside, so
  // this function must not corrupt them (return_value overlaps with
  // kCArgRegs[0] but that's ok because we start using it only after the C
  // call).
  DCHECK(!AreAliased(kCArgRegs[0], kCArgRegs[1],  // C args
                     scratch, scratch2, prev_next_address_reg, prev_limit_reg));
  // function_address and thunk_arg might overlap but this function must not
  // corrupted them until the call is made (i.e. overlap with return_value is
  // fine).
  DCHECK(!AreAliased(function_address,  // incoming parameters
                     scratch, scratch2, prev_next_address_reg, prev_limit_reg));
  DCHECK(!AreAliased(thunk_arg,  // incoming parameters
                     scratch, scratch2, prev_next_address_reg, prev_limit_reg));

  // Explicitly include x16/x17 to let StoreReturnAddressAndCall() use them.
  UseScratchRegisterScope fix_temps(masm);
  fix_temps.Include(x16, x17);

  {
    ASM_CODE_COMMENT_STRING(masm,
                            "Allocate HandleScope in callee-save registers.");
    __ Ldr(prev_next_address_reg, next_mem_op);
    __ Ldr(prev_limit_reg, limit_mem_op);
    __ Ldr(prev_level_reg, level_mem_op);
    __ Add(scratch.W(), prev_level_reg, 1);
    __ Str(scratch.W(), level_mem_op);
  }

  Label profiler_or_side_effects_check_enabled, done_api_call;
  if (with_profiling) {
    __ RecordComment("Check if profiler or side effects check is enabled");
    __ Ldrb(scratch.W(),
            __ ExternalReferenceAsOperand(IsolateFieldId::kExecutionMode));
    __ Cbnz(scratch.W(), &profiler_or_side_effects_check_enabled);
#ifdef V8_RUNTIME_CALL_STATS
    __ RecordComment("Check if RCS is enabled");
    __ Mov(scratch, ER::address_of_runtime_stats_flag());
    __ Ldrsw(scratch.W(), MemOperand(scratch));
    __ Cbnz(scratch.W(), &profiler_or_side_effects_check_enabled);
#endif  // V8_RUNTIME_CALL_STATS
  }

  __ RecordComment("Call the api function directly.");
  __ StoreReturnAddressAndCall(function_address);
  __ Bind(&done_api_call);

  Label propagate_exception;
  Label delete_allocated_handles;
  Label leave_exit_frame;

  __ RecordComment("Load the value from ReturnValue");
  __ Ldr(return_value, return_value_operand);

  {
    ASM_CODE_COMMENT_STRING(
        masm,
        "No more valid handles (the result handle was the last one)."
        "Restore previous handle scope.");
    __ Str(prev_next_address_reg, next_mem_op);
    if (v8_flags.debug_code) {
      __ Ldr(scratch.W(), level_mem_op);
      __ Sub(scratch.W(), scratch.W(), 1);
      __ Cmp(scratch.W(), prev_level_reg);
      __ Check(eq, AbortReason::kUnexpectedLevelAfterReturnFromApiCall);
    }
    __ Str(prev_level_reg, level_mem_op);

    __ Ldr(scratch, limit_mem_op);
    __ Cmp(prev_limit_reg, scratch);
    __ B(ne, &delete_allocated_handles);
  }

  __ RecordComment("Leave the API exit frame.");
  __ Bind(&leave_exit_frame);

  Register argc_reg = prev_limit_reg;
  if (argc_operand != nullptr) {
    // Load the number of stack slots to drop before LeaveExitFrame modifies sp.
    __ Ldr(argc_reg, *argc_operand);
  }

  __ LeaveExitFrame(scratch, scratch2);

  {
    ASM_CODE_COMMENT_STRING(masm,
                            "Check if the function scheduled an exception.");
    __ Mov(scratch, ER::exception_address(isolate));
    __ Ldr(scratch, MemOperand(scratch));
    __ JumpIfNotRoot(scratch, RootIndex::kTheHoleValue, &propagate_exception);
  }

  __ AssertJSAny(return_value, scratch, scratch2,
                 AbortReason::kAPICallReturnedInvalidObject);

  if (argc_operand == nullptr) {
    DCHECK_NE(slots_to_drop_on_return, 0);
    __ DropSlots(slots_to_drop_on_return);
  } else {
    // {argc_operand} was loaded into {argc_reg} above.
    __ DropArguments(argc_reg, slots_to_drop_on_return);
  }
  __ Ret();

  if (with_profiling) {
    ASM_CODE_COMMENT_STRING(masm, "Call the api function via thunk wrapper.");
    __ Bind(&profiler_or_side_effects_check_enabled);
    // Additional parameter is the address of the actual callback function.
    if (thunk_arg.is_valid()) {
      MemOperand thunk_arg_mem_op = __ ExternalReferenceAsOperand(
          IsolateFieldId::kApiCallbackThunkArgument);
      __ Str(thunk_arg, thunk_arg_mem_op);
    }
    __ Mov(scratch, thunk_ref);
    __ StoreReturnAddressAndCall(scratch);
    __ B(&done_api_call);
  }

  __ RecordComment("An exception was thrown. Propagate it.");
  __ Bind(&propagate_exception);
  __ TailCallRuntime(Runtime::kPropagateException);

  {
    ASM_CODE_COMMENT_STRING(
        masm, "HandleScope limit has changed. Delete allocated extensions.");
    __ Bind(&delete_allocated_handles);
    __ Str(prev_limit_reg, limit_mem_op);
    // Save the return value in a callee-save register.
    Register saved_result = prev_limit_reg;
    __ Mov(saved_result, x0);
    __ Mov(kCArgRegs[0], ER::isolate_address());
    __ CallCFunction(ER::delete_handle_scope_extensions(), 1);
    __ Mov(kCArgRegs[0], saved_result);
    __ B(&leave_exit_frame);
  }
}

}  // namespace internal
}  // namespace v8

#undef __

#endif  // V8_TARGET_ARCH_ARM64
```