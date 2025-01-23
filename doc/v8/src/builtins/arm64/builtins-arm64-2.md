Response: The user wants a summary of the provided C++ code snippet, which is part of a larger file related to ARM64 architecture within the V8 JavaScript engine. The code seems to deal with low-level operations related to stack management, function calls, and interactions between JavaScript and WebAssembly.

Here's a breakdown of the code's functionalities:

1. **Stack Switching:** The code defines functions and utilities for switching between different stacks. This is crucial for implementing features like WebAssembly's asynchronous operations (suspending and resuming).
2. **Continuation Management:** Concepts like "continuations" are used to represent the execution state that can be saved and restored. The code manipulates these continuation objects.
3. **Suspender Management:** Similar to continuations, "suspenders" are used in the context of asynchronous operations.
4. **Register Allocation:** A basic register allocator is implemented to manage the usage of CPU registers.
5. **Wasm-to-JS and JS-to-Wasm Wrappers:** The code includes functions for generating assembly code that bridges the gap between WebAssembly and JavaScript function calls.
6. **Trap Handling:** Logic for handling WebAssembly traps (runtime errors) is present.
7. **Exception Handling:** There's code related to handling exceptions thrown during WebAssembly execution.
8. **C++ Interoperability:**  The code interacts with C++ functions, indicating the low-level nature of the operations.

To illustrate the relationship with JavaScript, I need to create a JavaScript example that would trigger some of these underlying mechanisms. A good candidate is using WebAssembly's asynchronous capabilities, which involve stack switching and continuation management.
这是 `v8/src/builtins/arm64/builtins-arm64.cc` 文件的第三部分，主要专注于实现 WebAssembly 和 JavaScript 之间的互操作，以及 WebAssembly 内部的栈管理和异常处理机制。

**功能归纳:**

1. **`Generate_WasmSuspend(MacroAssembler* masm)`:** 生成 WebAssembly `suspend` 操作的汇编代码。当 WebAssembly 代码执行到 `suspend` 指令时，这个代码负责保存当前 WebAssembly 栈的状态（通过 `FillJumpBuffer` 和 `SwitchStackState`），更新全局的 continuation 和 suspender 根，然后切换到父 continuation 的栈上执行。这允许 WebAssembly 代码暂停执行，并将控制权返回给 JavaScript。

2. **`Generate_WasmResumeHelper(MacroAssembler* masm, wasm::OnResume on_resume)`:**  生成 WebAssembly `resume` 和 `reject` 操作的通用辅助函数。它负责从 closure 中加载 suspender 信息，保存当前状态，更新 continuation 和 suspender 的父级信息并更新全局根，然后加载目标 continuation 的状态并切换栈。根据 `on_resume` 的值，它可以选择正常恢复执行（`kContinue`）或抛出异常（`kThrow`）。

3. **`Generate_WasmResume(MacroAssembler* masm)` 和 `Generate_WasmReject(MacroAssembler* masm)`:** 分别调用 `Generate_WasmResumeHelper` 生成 WebAssembly `resume` 和 `reject` 操作的汇编代码。

4. **`Generate_WasmOnStackReplace(MacroAssembler* masm)`:**  这个函数在 ARM64 架构上直接生成一个 trap 指令。这可能意味着栈上替换 (OSR) 的功能在 ARM64 上有不同的实现方式或者暂时不需要。

5. **`JSToWasmWrapperHelper(MacroAssembler* masm, wasm::Promise mode)`:** 生成从 JavaScript 调用 WebAssembly 函数的包装器（wrapper）的通用辅助函数。这个函数负责设置 WebAssembly 函数调用的栈帧，处理参数传递，调用 WebAssembly 代码，并处理返回值。它还处理了栈切换的情况 (当 `mode` 是 `kPromise` 或 `kStressSwitch` 时)，负责切换到为 WebAssembly 分配的栈上执行。

6. **`Generate_JSToWasmWrapperAsm(MacroAssembler* masm)`:** 调用 `JSToWasmWrapperHelper` 生成从 JavaScript 同步调用 WebAssembly 函数的包装器汇编代码。

7. **`Generate_WasmReturnPromiseOnSuspendAsm(MacroAssembler* masm)`:** 调用 `JSToWasmWrapperHelper` 生成当 WebAssembly 函数挂起时返回 Promise 的包装器汇编代码。

8. **`Generate_JSToWasmStressSwitchStacksAsm(MacroAssembler* masm)`:** 调用 `JSToWasmWrapperHelper` 生成用于压力测试栈切换的包装器汇编代码。

9. **`SwitchToTheCentralStackIfNeeded(MacroAssembler* masm, ...)` 和 `SwitchFromTheCentralStackIfNeeded(MacroAssembler* masm)`:** 这两个函数用于在必要时切换到中央栈和从中央栈切换回来。这通常用于处理 C++ 代码的调用，以确保在 GC 期间栈的正确管理。

**与 JavaScript 的关系及示例:**

这些代码与 JavaScript 的关系在于实现了 WebAssembly 和 JavaScript 之间的互操作性，特别是涉及到异步操作时。

**JavaScript 示例 (涉及 `suspend` 和 `resume`):**

假设我们有以下 WebAssembly 模块，其中包含一个 `suspend` 操作：

```wat
(module
  (import "env" "suspend" (func $suspend))
  (func (export "run")
    call $suspend
  )
)
```

对应的 JavaScript 代码可能会是这样：

```javascript
async function runWasm() {
  const importObject = {
    env: {
      async suspend() {
        console.log("WebAssembly suspending...");
        // 这里会触发 Generate_WasmSuspend 中的代码
        await new Promise(resolve => setTimeout(resolve, 1000));
        console.log("WebAssembly resumed!");
        // 当 Promise resolve 时，会触发 Generate_WasmResume 或 Generate_WasmReject 中的代码
      }
    }
  };

  const response = await fetch('your_wasm_module.wasm');
  const bytes = await response.arrayBuffer();
  const module = await WebAssembly.instantiate(bytes, importObject);
  module.instance.exports.run();
}

runWasm();
```

**解释:**

*   当 WebAssembly 模块中的 `run` 函数调用导入的 `suspend` 函数时，会触发 `Generate_WasmSuspend` 中生成的汇编代码。这段汇编代码会保存 WebAssembly 的执行状态，然后切换到 JavaScript 的栈上。
*   JavaScript 的 `suspend` 函数中创建了一个 Promise，并通过 `setTimeout` 模拟了一个异步操作。
*   当 `setTimeout` 的回调被执行，Promise 被 resolve 时，V8 引擎会找到之前挂起的 WebAssembly 执行状态，并使用 `Generate_WasmResume` 中生成的汇编代码将其恢复到之前的状态继续执行。

**JavaScript 示例 (涉及 JS 调用 WASM):**

```javascript
// 假设已经加载了 WebAssembly 模块 instance
const result = instance.exports.someWasmFunction(10, 20);
console.log(result);
```

当 JavaScript 调用 `instance.exports.someWasmFunction` 时，会触发 `Generate_JSToWasmWrapperAsm` (或其 Promise 版本) 中生成的汇编代码。这个包装器会负责将 JavaScript 的参数转换为 WebAssembly 可以理解的格式，设置好 WebAssembly 的执行环境，并最终调用 WebAssembly 函数。WebAssembly 函数执行完毕后，包装器还会负责将 WebAssembly 的返回值转换回 JavaScript 的格式。

总而言之，这部分 C++ 代码是 V8 引擎中实现 WebAssembly 和 JavaScript 深度集成的重要组成部分，它处理了跨语言的函数调用、异步操作以及底层的栈管理和异常处理。

### 提示词
```
这是目录为v8/src/builtins/arm64/builtins-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```
cate that the stack that we
// are switching from has returned, and in this case return its memory to the
// stack pool.
void SwitchStacks(MacroAssembler* masm, Register finished_continuation,
                  const CPURegister& keep1 = NoReg,
                  const CPURegister& keep2 = padreg,
                  const CPURegister& keep3 = NoReg) {
  using ER = ExternalReference;
  __ Push(keep1, keep2);
  if (keep3 != NoReg) {
    __ Push(keep3, padreg);
  }
  if (finished_continuation != no_reg) {
    FrameScope scope(masm, StackFrame::MANUAL);
    __ Mov(kCArgRegs[0], ExternalReference::isolate_address(masm->isolate()));
    __ Mov(kCArgRegs[1], finished_continuation);
    __ CallCFunction(ER::wasm_return_switch(), 2);
  } else {
    FrameScope scope(masm, StackFrame::MANUAL);
    __ Mov(kCArgRegs[0], ER::isolate_address());
    __ CallCFunction(ER::wasm_sync_stack_limit(), 1);
  }
  if (keep3 != NoReg) {
    __ Pop(padreg, keep3);
  }
  __ Pop(keep2, keep1);
}

void ReloadParentContinuation(MacroAssembler* masm, Register return_reg,
                              Register return_value, Register context,
                              Register tmp1, Register tmp2, Register tmp3) {
  Register active_continuation = tmp1;
  __ LoadRoot(active_continuation, RootIndex::kActiveContinuation);

  // Set a null pointer in the jump buffer's SP slot to indicate to the stack
  // frame iterator that this stack is empty.
  Register jmpbuf = tmp2;
  __ LoadExternalPointerField(
      jmpbuf,
      FieldMemOperand(active_continuation,
                      WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag);
  __ Str(xzr, MemOperand(jmpbuf, wasm::kJmpBufSpOffset));
  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.AcquireX();
    SwitchStackState(masm, jmpbuf, scratch, wasm::JumpBuffer::Active,
                     wasm::JumpBuffer::Retired);
  }
  Register parent = tmp2;
  __ LoadTaggedField(parent,
                     FieldMemOperand(active_continuation,
                                     WasmContinuationObject::kParentOffset));

  // Update active continuation root.
  int32_t active_continuation_offset =
      MacroAssembler::RootRegisterOffsetForRootIndex(
          RootIndex::kActiveContinuation);
  __ Str(parent, MemOperand(kRootRegister, active_continuation_offset));
  jmpbuf = parent;
  __ LoadExternalPointerField(
      jmpbuf, FieldMemOperand(parent, WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag);

  // Switch stack!
  LoadJumpBuffer(masm, jmpbuf, false, tmp3, wasm::JumpBuffer::Inactive);

  SwitchStacks(masm, active_continuation, return_reg, return_value, context);
}

void RestoreParentSuspender(MacroAssembler* masm, Register tmp1,
                            Register tmp2) {
  Register suspender = tmp1;
  __ LoadRoot(suspender, RootIndex::kActiveSuspender);
  MemOperand state_loc =
    FieldMemOperand(suspender, WasmSuspenderObject::kStateOffset);
  __ Move(tmp2, Smi::FromInt(WasmSuspenderObject::kInactive));
  __ StoreTaggedField(tmp2, state_loc);
  __ LoadTaggedField(
      suspender,
      FieldMemOperand(suspender, WasmSuspenderObject::kParentOffset));
  __ CompareRoot(suspender, RootIndex::kUndefinedValue);
  Label undefined;
  __ B(&undefined, eq);
  if (v8_flags.debug_code) {
    // Check that the parent suspender is active.
    Label parent_inactive;
    Register state = tmp2;
    __ SmiUntag(state, state_loc);
    __ cmp(state, WasmSuspenderObject::kActive);
    __ B(&parent_inactive, eq);
    __ Trap();
    __ bind(&parent_inactive);
  }
  __ Move(tmp2, Smi::FromInt(WasmSuspenderObject::kActive));
  __ StoreTaggedField(tmp2, state_loc);
  __ bind(&undefined);
  int32_t active_suspender_offset =
      MacroAssembler::RootRegisterOffsetForRootIndex(
          RootIndex::kActiveSuspender);
  __ Str(suspender, MemOperand(kRootRegister, active_suspender_offset));
}

void ResetStackSwitchFrameStackSlots(MacroAssembler* masm) {
  __ Str(xzr, MemOperand(fp, StackSwitchFrameConstants::kResultArrayOffset));
  __ Str(xzr, MemOperand(fp, StackSwitchFrameConstants::kImplicitArgOffset));
}

// TODO(irezvov): Consolidate with arm RegisterAllocator.
class RegisterAllocator {
 public:
  class Scoped {
   public:
    Scoped(RegisterAllocator* allocator, Register* reg):
      allocator_(allocator), reg_(reg) {}
    ~Scoped() { allocator_->Free(reg_); }
   private:
    RegisterAllocator* allocator_;
    Register* reg_;
  };

  explicit RegisterAllocator(const CPURegList& registers)
      : initial_(registers),
        available_(registers) {}
  void Ask(Register* reg) {
    DCHECK_EQ(*reg, no_reg);
    DCHECK(!available_.IsEmpty());
    *reg = available_.PopLowestIndex().X();
    allocated_registers_.push_back(reg);
  }

  void Pinned(const Register& requested, Register* reg) {
    DCHECK(available_.IncludesAliasOf(requested));
    *reg = requested;
    Reserve(requested);
    allocated_registers_.push_back(reg);
  }

  void Free(Register* reg) {
    DCHECK_NE(*reg, no_reg);
    available_.Combine(*reg);
    *reg = no_reg;
    allocated_registers_.erase(
      find(allocated_registers_.begin(), allocated_registers_.end(), reg));
  }

  void Reserve(const Register& reg) {
    if (reg == NoReg) {
      return;
    }
    DCHECK(available_.IncludesAliasOf(reg));
    available_.Remove(reg);
  }

  void Reserve(const Register& reg1,
               const Register& reg2,
               const Register& reg3 = NoReg,
               const Register& reg4 = NoReg,
               const Register& reg5 = NoReg,
               const Register& reg6 = NoReg) {
    Reserve(reg1);
    Reserve(reg2);
    Reserve(reg3);
    Reserve(reg4);
    Reserve(reg5);
    Reserve(reg6);
  }

  bool IsUsed(const Register& reg) {
    return initial_.IncludesAliasOf(reg)
      && !available_.IncludesAliasOf(reg);
  }

  void ResetExcept(const Register& reg1 = NoReg,
                   const Register& reg2 = NoReg,
                   const Register& reg3 = NoReg,
                   const Register& reg4 = NoReg,
                   const Register& reg5 = NoReg,
                   const Register& reg6 = NoReg) {
    available_ = initial_;
    if (reg1 != NoReg) {
      available_.Remove(reg1, reg2, reg3, reg4);
    }
    if (reg5 != NoReg) {
      available_.Remove(reg5, reg6);
    }
    auto it = allocated_registers_.begin();
    while (it != allocated_registers_.end()) {
      if (available_.IncludesAliasOf(**it)) {
        **it = no_reg;
        it = allocated_registers_.erase(it);
      } else {
        it++;
      }
    }
  }

  static RegisterAllocator WithAllocatableGeneralRegisters() {
    CPURegList list(kXRegSizeInBits, RegList());
    const RegisterConfiguration* config(RegisterConfiguration::Default());
    list.set_bits(config->allocatable_general_codes_mask());
    return RegisterAllocator(list);
  }

 private:
  std::vector<Register*> allocated_registers_;
  const CPURegList initial_;
  CPURegList available_;
};

#define DEFINE_REG(Name) \
  Register Name = no_reg; \
  regs.Ask(&Name);

#define DEFINE_REG_W(Name) \
  DEFINE_REG(Name); \
  Name = Name.W();

#define ASSIGN_REG(Name) \
  regs.Ask(&Name);

#define ASSIGN_REG_W(Name) \
  ASSIGN_REG(Name); \
  Name = Name.W();

#define DEFINE_PINNED(Name, Reg) \
  Register Name = no_reg; \
  regs.Pinned(Reg, &Name);

#define ASSIGN_PINNED(Name, Reg) regs.Pinned(Reg, &Name);

#define DEFINE_SCOPED(Name) \
  DEFINE_REG(Name) \
  RegisterAllocator::Scoped scope_##Name(&regs, &Name);

#define FREE_REG(Name) regs.Free(&Name);

// Loads the context field of the WasmTrustedInstanceData or WasmImportData
// depending on the data's type, and places the result in the input register.
void GetContextFromImplicitArg(MacroAssembler* masm, Register data,
                               Register scratch) {
  __ LoadTaggedField(scratch, FieldMemOperand(data, HeapObject::kMapOffset));
  __ CompareInstanceType(scratch, scratch, WASM_TRUSTED_INSTANCE_DATA_TYPE);
  Label instance;
  Label end;
  __ B(eq, &instance);
  __ LoadTaggedField(
      data, FieldMemOperand(data, WasmImportData::kNativeContextOffset));
  __ jmp(&end);
  __ bind(&instance);
  __ LoadTaggedField(
      data,
      FieldMemOperand(data, WasmTrustedInstanceData::kNativeContextOffset));
  __ bind(&end);
}

}  // namespace

void Builtins::Generate_WasmToJsWrapperAsm(MacroAssembler* masm) {
  // Push registers in reverse order so that they are on the stack like
  // in an array, with the first item being at the lowest address.
  __ Push(wasm::kFpParamRegisters[7], wasm::kFpParamRegisters[6],
          wasm::kFpParamRegisters[5], wasm::kFpParamRegisters[4]);
  __ Push(wasm::kFpParamRegisters[3], wasm::kFpParamRegisters[2],
          wasm::kFpParamRegisters[1], wasm::kFpParamRegisters[0]);

  __ Push(wasm::kGpParamRegisters[6], wasm::kGpParamRegisters[5],
          wasm::kGpParamRegisters[4], wasm::kGpParamRegisters[3]);
  __ Push(wasm::kGpParamRegisters[2], wasm::kGpParamRegisters[1]);
  // Reserve a slot for the signature, and one for stack alignment.
  __ Push(xzr, xzr);
  __ TailCallBuiltin(Builtin::kWasmToJsWrapperCSA);
}

void Builtins::Generate_WasmTrapHandlerLandingPad(MacroAssembler* masm) {
  __ Add(lr, kWasmTrapHandlerFaultAddressRegister,
         WasmFrameConstants::kProtectedInstructionReturnAddressOffset);
  __ TailCallBuiltin(Builtin::kWasmTrapHandlerThrowTrap);
}

void Builtins::Generate_WasmSuspend(MacroAssembler* masm) {
  auto regs = RegisterAllocator::WithAllocatableGeneralRegisters();
  // Set up the stackframe.
  __ EnterFrame(StackFrame::STACK_SWITCH);

  DEFINE_PINNED(suspender, x0);
  DEFINE_PINNED(context, kContextRegister);

  __ Sub(sp, sp,
         Immediate(StackSwitchFrameConstants::kNumSpillSlots *
                   kSystemPointerSize));
  // Set a sentinel value for the spill slots visited by the GC.
  ResetStackSwitchFrameStackSlots(masm);

  // -------------------------------------------
  // Save current state in active jump buffer.
  // -------------------------------------------
  Label resume;
  DEFINE_REG(continuation);
  __ LoadRoot(continuation, RootIndex::kActiveContinuation);
  DEFINE_REG(jmpbuf);
  DEFINE_REG(scratch);
  __ LoadExternalPointerField(
      jmpbuf,
      FieldMemOperand(continuation, WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag);
  FillJumpBuffer(masm, jmpbuf, &resume, scratch);
  SwitchStackState(masm, jmpbuf, scratch, wasm::JumpBuffer::Active,
                   wasm::JumpBuffer::Suspended);
  __ Move(scratch, Smi::FromInt(WasmSuspenderObject::kSuspended));
  __ StoreTaggedField(
      scratch,
      FieldMemOperand(suspender, WasmSuspenderObject::kStateOffset));
  regs.ResetExcept(suspender, continuation);

  DEFINE_REG(suspender_continuation);
  __ LoadTaggedField(
      suspender_continuation,
      FieldMemOperand(suspender, WasmSuspenderObject::kContinuationOffset));
  if (v8_flags.debug_code) {
    // -------------------------------------------
    // Check that the suspender's continuation is the active continuation.
    // -------------------------------------------
    // TODO(thibaudm): Once we add core stack-switching instructions, this
    // check will not hold anymore: it's possible that the active continuation
    // changed (due to an internal switch), so we have to update the suspender.
    __ cmp(suspender_continuation, continuation);
    Label ok;
    __ B(&ok, eq);
    __ Trap();
    __ bind(&ok);
  }
  FREE_REG(continuation);
  // -------------------------------------------
  // Update roots.
  // -------------------------------------------
  DEFINE_REG(caller);
  __ LoadTaggedField(caller,
                     FieldMemOperand(suspender_continuation,
                                     WasmContinuationObject::kParentOffset));
  int32_t active_continuation_offset =
      MacroAssembler::RootRegisterOffsetForRootIndex(
          RootIndex::kActiveContinuation);
  __ Str(caller, MemOperand(kRootRegister, active_continuation_offset));
  DEFINE_REG(parent);
  __ LoadTaggedField(
      parent, FieldMemOperand(suspender, WasmSuspenderObject::kParentOffset));
  int32_t active_suspender_offset =
      MacroAssembler::RootRegisterOffsetForRootIndex(
          RootIndex::kActiveSuspender);
  __ Str(parent, MemOperand(kRootRegister, active_suspender_offset));
  regs.ResetExcept(suspender, caller);

  // -------------------------------------------
  // Load jump buffer.
  // -------------------------------------------
  SwitchStacks(masm, no_reg, caller, suspender);
  ASSIGN_REG(jmpbuf);
  __ LoadExternalPointerField(
      jmpbuf, FieldMemOperand(caller, WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag);
  __ LoadTaggedField(
      kReturnRegister0,
      FieldMemOperand(suspender, WasmSuspenderObject::kPromiseOffset));
  MemOperand GCScanSlotPlace =
      MemOperand(fp, StackSwitchFrameConstants::kGCScanSlotCountOffset);
  __ Str(xzr, GCScanSlotPlace);
  ASSIGN_REG(scratch)
  LoadJumpBuffer(masm, jmpbuf, true, scratch, wasm::JumpBuffer::Inactive);
  __ Trap();
  __ Bind(&resume, BranchTargetIdentifier::kBtiJump);
  __ LeaveFrame(StackFrame::STACK_SWITCH);
  __ Ret(lr);
}

namespace {
// Resume the suspender stored in the closure. We generate two variants of this
// builtin: the onFulfilled variant resumes execution at the saved PC and
// forwards the value, the onRejected variant throws the value.

void Generate_WasmResumeHelper(MacroAssembler* masm, wasm::OnResume on_resume) {
  auto regs = RegisterAllocator::WithAllocatableGeneralRegisters();
  __ EnterFrame(StackFrame::STACK_SWITCH);

  DEFINE_PINNED(closure, kJSFunctionRegister);  // x1

  __ Sub(sp, sp,
         Immediate(StackSwitchFrameConstants::kNumSpillSlots *
                   kSystemPointerSize));
  // Set a sentinel value for the spill slots visited by the GC.
  ResetStackSwitchFrameStackSlots(masm);

  regs.ResetExcept(closure);

  // -------------------------------------------
  // Load suspender from closure.
  // -------------------------------------------
  DEFINE_REG(sfi);
  __ LoadTaggedField(
      sfi,
      MemOperand(
          closure,
          wasm::ObjectAccess::SharedFunctionInfoOffsetInTaggedJSFunction()));
  FREE_REG(closure);
  // Suspender should be ObjectRegister register to be used in
  // RecordWriteField calls later.
  DEFINE_PINNED(suspender, WriteBarrierDescriptor::ObjectRegister());
  DEFINE_REG(resume_data);
  __ LoadTaggedField(
      resume_data,
      FieldMemOperand(sfi, SharedFunctionInfo::kUntrustedFunctionDataOffset));
  // The write barrier uses a fixed register for the host object (rdi). The next
  // barrier is on the suspender, so load it in rdi directly.
  __ LoadTaggedField(
      suspender,
      FieldMemOperand(resume_data, WasmResumeData::kSuspenderOffset));
  // Check the suspender state.
  Label suspender_is_suspended;
  DEFINE_REG(state);
  __ SmiUntag(state,
              FieldMemOperand(suspender, WasmSuspenderObject::kStateOffset));
  __ cmp(state, WasmSuspenderObject::kSuspended);
  __ B(&suspender_is_suspended, eq);
  __ Trap();

  regs.ResetExcept(suspender);

  __ bind(&suspender_is_suspended);
  // -------------------------------------------
  // Save current state.
  // -------------------------------------------
  Label suspend;
  DEFINE_REG(active_continuation);
  __ LoadRoot(active_continuation, RootIndex::kActiveContinuation);
  DEFINE_REG(current_jmpbuf);
  DEFINE_REG(scratch);
  __ LoadExternalPointerField(
      current_jmpbuf,
      FieldMemOperand(active_continuation,
                      WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag);
  FillJumpBuffer(masm, current_jmpbuf, &suspend, scratch);
  SwitchStackState(masm, current_jmpbuf, scratch, wasm::JumpBuffer::Active,
                   wasm::JumpBuffer::Inactive);
  FREE_REG(current_jmpbuf);

  // -------------------------------------------
  // Set the suspender and continuation parents and update the roots
  // -------------------------------------------
  DEFINE_REG(active_suspender);
  __ LoadRoot(active_suspender, RootIndex::kActiveSuspender);
  __ StoreTaggedField(
      active_suspender,
      FieldMemOperand(suspender, WasmSuspenderObject::kParentOffset));
  __ RecordWriteField(suspender, WasmSuspenderObject::kParentOffset,
                      active_suspender, kLRHasBeenSaved,
                      SaveFPRegsMode::kIgnore);
  __ Move(scratch, Smi::FromInt(WasmSuspenderObject::kActive));
  __ StoreTaggedField(
      scratch,
      FieldMemOperand(suspender, WasmSuspenderObject::kStateOffset));
  int32_t active_suspender_offset =
      MacroAssembler::RootRegisterOffsetForRootIndex(
          RootIndex::kActiveSuspender);
  __ Str(suspender, MemOperand(kRootRegister, active_suspender_offset));

  // Next line we are going to load a field from suspender, but we have to use
  // the same register for target_continuation to use it in RecordWriteField.
  // So, free suspender here to use pinned reg, but load from it next line.
  FREE_REG(suspender);
  DEFINE_PINNED(target_continuation, WriteBarrierDescriptor::ObjectRegister());
  suspender = target_continuation;
  __ LoadTaggedField(
      target_continuation,
      FieldMemOperand(suspender, WasmSuspenderObject::kContinuationOffset));
  suspender = no_reg;

  __ StoreTaggedField(
      active_continuation,
      FieldMemOperand(target_continuation,
                      WasmContinuationObject::kParentOffset));
  __ RecordWriteField(
      target_continuation, WasmContinuationObject::kParentOffset,
      active_continuation, kLRHasBeenSaved, SaveFPRegsMode::kIgnore);
  FREE_REG(active_continuation);
  int32_t active_continuation_offset =
      MacroAssembler::RootRegisterOffsetForRootIndex(
          RootIndex::kActiveContinuation);
  __ Str(target_continuation,
         MemOperand(kRootRegister, active_continuation_offset));

  SwitchStacks(masm, no_reg, target_continuation);

  regs.ResetExcept(target_continuation);

  // -------------------------------------------
  // Load state from target jmpbuf (longjmp).
  // -------------------------------------------
  regs.Reserve(kReturnRegister0);
  DEFINE_REG(target_jmpbuf);
  ASSIGN_REG(scratch);
  __ LoadExternalPointerField(
      target_jmpbuf,
      FieldMemOperand(target_continuation,
                      WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag);
  // Move resolved value to return register.
  __ Ldr(kReturnRegister0, MemOperand(fp, 3 * kSystemPointerSize));
  MemOperand GCScanSlotPlace =
      MemOperand(fp, StackSwitchFrameConstants::kGCScanSlotCountOffset);
  __ Str(xzr, GCScanSlotPlace);
  if (on_resume == wasm::OnResume::kThrow) {
    // Switch to the continuation's stack without restoring the PC.
    LoadJumpBuffer(masm, target_jmpbuf, false, scratch,
                   wasm::JumpBuffer::Suspended);
    // Pop this frame now. The unwinder expects that the first STACK_SWITCH
    // frame is the outermost one.
    __ LeaveFrame(StackFrame::STACK_SWITCH);
    // Forward the onRejected value to kThrow.
    __ Push(xzr, kReturnRegister0);
    __ CallRuntime(Runtime::kThrow);
  } else {
    // Resume the continuation normally.
    LoadJumpBuffer(masm, target_jmpbuf, true, scratch,
                   wasm::JumpBuffer::Suspended);
  }
  __ Trap();
  __ Bind(&suspend, BranchTargetIdentifier::kBtiJump);
  __ LeaveFrame(StackFrame::STACK_SWITCH);
  // Pop receiver + parameter.
  __ DropArguments(2);
  __ Ret(lr);
}
}  // namespace

void Builtins::Generate_WasmResume(MacroAssembler* masm) {
  Generate_WasmResumeHelper(masm, wasm::OnResume::kContinue);
}

void Builtins::Generate_WasmReject(MacroAssembler* masm) {
  Generate_WasmResumeHelper(masm, wasm::OnResume::kThrow);
}

void Builtins::Generate_WasmOnStackReplace(MacroAssembler* masm) {
  // Only needed on x64.
  __ Trap();
}
namespace {
void SwitchToAllocatedStack(MacroAssembler* masm, RegisterAllocator& regs,
                            Register wasm_instance, Register wrapper_buffer,
                            Register& original_fp, Register& new_wrapper_buffer,
                            Label* suspend) {
  ResetStackSwitchFrameStackSlots(masm);
  DEFINE_SCOPED(scratch)
  DEFINE_REG(target_continuation)
  __ LoadRoot(target_continuation, RootIndex::kActiveContinuation);
  DEFINE_REG(parent_continuation)
  __ LoadTaggedField(parent_continuation,
                     FieldMemOperand(target_continuation,
                                     WasmContinuationObject::kParentOffset));
  SaveState(masm, parent_continuation, scratch, suspend);
  SwitchStacks(masm, no_reg, wasm_instance, wrapper_buffer);
  FREE_REG(parent_continuation);
  // Save the old stack's fp in x9, and use it to access the parameters in
  // the parent frame.
  regs.Pinned(x9, &original_fp);
  __ Mov(original_fp, fp);
  __ LoadRoot(target_continuation, RootIndex::kActiveContinuation);
  LoadTargetJumpBuffer(masm, target_continuation, scratch,
                       wasm::JumpBuffer::Suspended);
  FREE_REG(target_continuation);
  // Push the loaded fp. We know it is null, because there is no frame yet,
  // so we could also push 0 directly. In any case we need to push it,
  // because this marks the base of the stack segment for
  // the stack frame iterator.
  __ EnterFrame(StackFrame::STACK_SWITCH);
  int stack_space =
      RoundUp(StackSwitchFrameConstants::kNumSpillSlots * kSystemPointerSize +
                  JSToWasmWrapperFrameConstants::kWrapperBufferSize,
              16);
  __ Sub(sp, sp, Immediate(stack_space));
  ASSIGN_REG(new_wrapper_buffer)
  __ Mov(new_wrapper_buffer, sp);
  // Copy data needed for return handling from old wrapper buffer to new one.
  // kWrapperBufferRefReturnCount will be copied too, because 8 bytes are copied
  // at the same time.
  static_assert(JSToWasmWrapperFrameConstants::kWrapperBufferRefReturnCount ==
                JSToWasmWrapperFrameConstants::kWrapperBufferReturnCount + 4);
  __ Ldr(scratch,
         MemOperand(wrapper_buffer,
                    JSToWasmWrapperFrameConstants::kWrapperBufferReturnCount));
  __ Str(scratch,
         MemOperand(new_wrapper_buffer,
                    JSToWasmWrapperFrameConstants::kWrapperBufferReturnCount));
  __ Ldr(
      scratch,
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferSigRepresentationArray));
  __ Str(
      scratch,
      MemOperand(
          new_wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferSigRepresentationArray));
}

void SwitchBackAndReturnPromise(MacroAssembler* masm, RegisterAllocator& regs,
                                wasm::Promise mode, Label* return_promise) {
  regs.ResetExcept();
  // The return value of the wasm function becomes the parameter of the
  // FulfillPromise builtin, and the promise is the return value of this
  // wrapper.
  static const Builtin_FulfillPromise_InterfaceDescriptor desc;
  DEFINE_PINNED(promise, desc.GetRegisterParameter(0));
  DEFINE_PINNED(return_value, desc.GetRegisterParameter(1));
  DEFINE_SCOPED(tmp);
  DEFINE_SCOPED(tmp2);
  DEFINE_SCOPED(tmp3);
  if (mode == wasm::kPromise) {
    __ Move(return_value, kReturnRegister0);
    __ LoadRoot(promise, RootIndex::kActiveSuspender);
    __ LoadTaggedField(
        promise, FieldMemOperand(promise, WasmSuspenderObject::kPromiseOffset));
  }
  __ Ldr(kContextRegister,
         MemOperand(fp, StackSwitchFrameConstants::kImplicitArgOffset));
  GetContextFromImplicitArg(masm, kContextRegister, tmp);

  ReloadParentContinuation(masm, promise, return_value, kContextRegister, tmp,
                           tmp2, tmp3);
  RestoreParentSuspender(masm, tmp, tmp2);

  if (mode == wasm::kPromise) {
    __ Mov(tmp, 1);
    __ Str(tmp,
           MemOperand(fp, StackSwitchFrameConstants::kGCScanSlotCountOffset));
    __ Push(padreg, promise);
    __ CallBuiltin(Builtin::kFulfillPromise);
    __ Pop(promise, padreg);
  }
  FREE_REG(promise);
  FREE_REG(return_value);
  __ bind(return_promise);
}

void GenerateExceptionHandlingLandingPad(MacroAssembler* masm,
                                         RegisterAllocator& regs,
                                         Label* return_promise) {
  regs.ResetExcept();
  static const Builtin_RejectPromise_InterfaceDescriptor desc;
  DEFINE_PINNED(promise, desc.GetRegisterParameter(0));
  DEFINE_PINNED(reason, desc.GetRegisterParameter(1));
  DEFINE_PINNED(debug_event, desc.GetRegisterParameter(2));
  int catch_handler = __ pc_offset();
  __ JumpTarget();

  DEFINE_SCOPED(thread_in_wasm_flag_addr);
  thread_in_wasm_flag_addr = x2;
  // Unset thread_in_wasm_flag.
  __ Ldr(
      thread_in_wasm_flag_addr,
      MemOperand(kRootRegister, Isolate::thread_in_wasm_flag_address_offset()));
  __ Str(wzr, MemOperand(thread_in_wasm_flag_addr, 0));

  // The exception becomes the parameter of the RejectPromise builtin, and the
  // promise is the return value of this wrapper.
  __ Move(reason, kReturnRegister0);
  __ LoadRoot(promise, RootIndex::kActiveSuspender);
  __ LoadTaggedField(
      promise, FieldMemOperand(promise, WasmSuspenderObject::kPromiseOffset));

  __ Ldr(kContextRegister,
         MemOperand(fp, StackSwitchFrameConstants::kImplicitArgOffset));

  DEFINE_SCOPED(tmp);
  DEFINE_SCOPED(tmp2);
  DEFINE_SCOPED(tmp3);
  GetContextFromImplicitArg(masm, kContextRegister, tmp);
  ReloadParentContinuation(masm, promise, reason, kContextRegister, tmp, tmp2,
                           tmp3);
  RestoreParentSuspender(masm, tmp, tmp2);

  __ Mov(tmp, 1);
  __ Str(tmp,
         MemOperand(fp, StackSwitchFrameConstants::kGCScanSlotCountOffset));
  __ Push(padreg, promise);
  __ LoadRoot(debug_event, RootIndex::kTrueValue);
  __ CallBuiltin(Builtin::kRejectPromise);
  __ Pop(promise, padreg);

  // Run the rest of the wrapper normally (deconstruct the frame, ...).
  __ jmp(return_promise);

  masm->isolate()->builtins()->SetJSPIPromptHandlerOffset(catch_handler);
}

void JSToWasmWrapperHelper(MacroAssembler* masm, wasm::Promise mode) {
  bool stack_switch = mode == wasm::kPromise || mode == wasm::kStressSwitch;
  auto regs = RegisterAllocator::WithAllocatableGeneralRegisters();

  __ EnterFrame(stack_switch ? StackFrame::STACK_SWITCH
                             : StackFrame::JS_TO_WASM);

  __ Sub(sp, sp,
         Immediate(StackSwitchFrameConstants::kNumSpillSlots *
                   kSystemPointerSize));

  // Load the implicit argument (instance data or import data) from the frame.
  DEFINE_PINNED(implicit_arg, kWasmImplicitArgRegister);
  __ Ldr(implicit_arg,
         MemOperand(fp, JSToWasmWrapperFrameConstants::kImplicitArgOffset));

  DEFINE_PINNED(wrapper_buffer,
                WasmJSToWasmWrapperDescriptor::WrapperBufferRegister());

  Label suspend;
  Register original_fp = no_reg;
  Register new_wrapper_buffer = no_reg;
  if (stack_switch) {
    SwitchToAllocatedStack(masm, regs, implicit_arg, wrapper_buffer,
                           original_fp, new_wrapper_buffer, &suspend);
  } else {
    original_fp = fp;
    new_wrapper_buffer = wrapper_buffer;
  }

  regs.ResetExcept(original_fp, wrapper_buffer, implicit_arg,
                   new_wrapper_buffer);

  {
    __ Str(new_wrapper_buffer,
           MemOperand(fp, JSToWasmWrapperFrameConstants::kWrapperBufferOffset));
    if (stack_switch) {
      __ Str(implicit_arg,
             MemOperand(fp, StackSwitchFrameConstants::kImplicitArgOffset));
      DEFINE_SCOPED(scratch)
      __ Ldr(
          scratch,
          MemOperand(original_fp,
                     JSToWasmWrapperFrameConstants::kResultArrayParamOffset));
      __ Str(scratch,
             MemOperand(fp, StackSwitchFrameConstants::kResultArrayOffset));
    }
  }
  {
    DEFINE_SCOPED(result_size);
    __ Ldr(result_size,
           MemOperand(wrapper_buffer, JSToWasmWrapperFrameConstants::
                                          kWrapperBufferStackReturnBufferSize));
    // The `result_size` is the number of slots needed on the stack to store the
    // return values of the wasm function. If `result_size` is an odd number, we
    // have to add `1` to preserve stack pointer alignment.
    __ Add(result_size, result_size, 1);
    __ Bic(result_size, result_size, 1);
    __ Sub(sp, sp, Operand(result_size, LSL, kSystemPointerSizeLog2));
  }
  {
    DEFINE_SCOPED(scratch);
    __ Mov(scratch, sp);
    __ Str(scratch, MemOperand(new_wrapper_buffer,
                               JSToWasmWrapperFrameConstants::
                                   kWrapperBufferStackReturnBufferStart));
  }
  if (stack_switch) {
    FREE_REG(new_wrapper_buffer)
  }
  FREE_REG(implicit_arg)
  for (auto reg : wasm::kGpParamRegisters) {
    regs.Reserve(reg);
  }

  // The first GP parameter holds the trusted instance data or the import data.
  // This is handled specially.
  int stack_params_offset =
      (arraysize(wasm::kGpParamRegisters) - 1) * kSystemPointerSize +
      arraysize(wasm::kFpParamRegisters) * kDoubleSize;

  {
    DEFINE_SCOPED(params_start);
    __ Ldr(params_start,
           MemOperand(wrapper_buffer,
                      JSToWasmWrapperFrameConstants::kWrapperBufferParamStart));
    {
      // Push stack parameters on the stack.
      DEFINE_SCOPED(params_end);
      __ Ldr(params_end,
             MemOperand(wrapper_buffer,
                        JSToWasmWrapperFrameConstants::kWrapperBufferParamEnd));
      DEFINE_SCOPED(last_stack_param);

      __ Add(last_stack_param, params_start, Immediate(stack_params_offset));
      Label loop_start;
      {
        DEFINE_SCOPED(scratch);
        // Check if there is an even number of parameters, so no alignment
        // needed.
        __ Sub(scratch, params_end, last_stack_param);
        __ TestAndBranchIfAllClear(scratch, 0x8, &loop_start);

        // Push the first parameter with alignment.
        __ Ldr(scratch, MemOperand(params_end, -kSystemPointerSize, PreIndex));
        __ Push(xzr, scratch);
      }
      __ bind(&loop_start);

      Label finish_stack_params;
      __ Cmp(last_stack_param, params_end);
      __ B(ge, &finish_stack_params);

      // Push parameter
      {
        DEFINE_SCOPED(scratch1);
        DEFINE_SCOPED(scratch2);
        __ Ldp(scratch2, scratch1,
               MemOperand(params_end, -2 * kSystemPointerSize, PreIndex));
        __ Push(scratch1, scratch2);
      }
      __ jmp(&loop_start);

      __ bind(&finish_stack_params);
    }

    size_t next_offset = 0;
    for (size_t i = 1; i < arraysize(wasm::kGpParamRegisters); i += 2) {
      // Check that {params_start} does not overlap with any of the parameter
      // registers, so that we don't overwrite it by accident with the loads
      // below.
      DCHECK_NE(params_start, wasm::kGpParamRegisters[i]);
      DCHECK_NE(params_start, wasm::kGpParamRegisters[i + 1]);
      __ Ldp(wasm::kGpParamRegisters[i], wasm::kGpParamRegisters[i + 1],
             MemOperand(params_start, next_offset));
      next_offset += 2 * kSystemPointerSize;
    }

    for (size_t i = 0; i < arraysize(wasm::kFpParamRegisters); i += 2) {
      __ Ldp(wasm::kFpParamRegisters[i], wasm::kFpParamRegisters[i + 1],
             MemOperand(params_start, next_offset));
      next_offset += 2 * kDoubleSize;
    }
    DCHECK_EQ(next_offset, stack_params_offset);
  }

  {
    DEFINE_SCOPED(thread_in_wasm_flag_addr);
    __ Ldr(thread_in_wasm_flag_addr,
           MemOperand(kRootRegister,
                      Isolate::thread_in_wasm_flag_address_offset()));
    DEFINE_SCOPED(scratch);
    __ Mov(scratch, 1);
    __ Str(scratch.W(), MemOperand(thread_in_wasm_flag_addr, 0));
  }
  __ Str(xzr,
         MemOperand(fp, StackSwitchFrameConstants::kGCScanSlotCountOffset));
  {
    DEFINE_SCOPED(call_target);
    __ LoadWasmCodePointer(
        call_target,
        MemOperand(wrapper_buffer,
                   JSToWasmWrapperFrameConstants::kWrapperBufferCallTarget));
    __ CallWasmCodePointer(call_target);
  }
  regs.ResetExcept();
  // The wrapper_buffer has to be in x2 as the correct parameter register.
  regs.Reserve(kReturnRegister0, kReturnRegister1);
  ASSIGN_PINNED(wrapper_buffer, x2);
  {
    DEFINE_SCOPED(thread_in_wasm_flag_addr);
    __ Ldr(thread_in_wasm_flag_addr,
           MemOperand(kRootRegister,
                      Isolate::thread_in_wasm_flag_address_offset()));
    __ Str(wzr, MemOperand(thread_in_wasm_flag_addr, 0));
  }

  __ Ldr(wrapper_buffer,
         MemOperand(fp, JSToWasmWrapperFrameConstants::kWrapperBufferOffset));

  __ Str(wasm::kFpReturnRegisters[0],
         MemOperand(
             wrapper_buffer,
             JSToWasmWrapperFrameConstants::kWrapperBufferFPReturnRegister1));
  __ Str(wasm::kFpReturnRegisters[1],
         MemOperand(
             wrapper_buffer,
             JSToWasmWrapperFrameConstants::kWrapperBufferFPReturnRegister2));
  __ Str(wasm::kGpReturnRegisters[0],
         MemOperand(
             wrapper_buffer,
             JSToWasmWrapperFrameConstants::kWrapperBufferGPReturnRegister1));
  __ Str(wasm::kGpReturnRegisters[1],
         MemOperand(
             wrapper_buffer,
             JSToWasmWrapperFrameConstants::kWrapperBufferGPReturnRegister2));
  // Call the return value builtin with
  // x0: wasm instance.
  // x1: the result JSArray for multi-return.
  // x2: pointer to the byte buffer which contains all parameters.
  if (stack_switch) {
    __ Ldr(x1, MemOperand(fp, StackSwitchFrameConstants::kResultArrayOffset));
    __ Ldr(x0, MemOperand(fp, StackSwitchFrameConstants::kImplicitArgOffset));
  } else {
    __ Ldr(x1, MemOperand(
                   fp, JSToWasmWrapperFrameConstants::kResultArrayParamOffset));
    __ Ldr(x0,
           MemOperand(fp, JSToWasmWrapperFrameConstants::kImplicitArgOffset));
  }
  Register scratch = x3;
  GetContextFromImplicitArg(masm, x0, scratch);
  __ CallBuiltin(Builtin::kJSToWasmHandleReturns);

  Label return_promise;
  if (stack_switch) {
    SwitchBackAndReturnPromise(masm, regs, mode, &return_promise);
  }
  __ Bind(&suspend, BranchTargetIdentifier::kBtiJump);

  __ LeaveFrame(stack_switch ? StackFrame::STACK_SWITCH
                             : StackFrame::JS_TO_WASM);
  // Despite returning to the different location for regular and stack switching
  // versions, incoming argument count matches both cases:
  // instance and result array without suspend or
  // or promise resolve/reject params for callback.
  constexpr int64_t stack_arguments_in = 2;
  __ DropArguments(stack_arguments_in);
  __ Ret();

  // Catch handler for the stack-switching wrapper: reject the promise with the
  // thrown exception.
  if (mode == wasm::kPromise) {
    GenerateExceptionHandlingLandingPad(masm, regs, &return_promise);
  }
}
}  // namespace

void Builtins::Generate_JSToWasmWrapperAsm(MacroAssembler* masm) {
  JSToWasmWrapperHelper(masm, wasm::kNoPromise);
}

void Builtins::Generate_WasmReturnPromiseOnSuspendAsm(MacroAssembler* masm) {
  JSToWasmWrapperHelper(masm, wasm::kPromise);
}

void Builtins::Generate_JSToWasmStressSwitchStacksAsm(MacroAssembler* masm) {
  JSToWasmWrapperHelper(masm, wasm::kStressSwitch);
}

namespace {
void SwitchSimulatorStackLimit(MacroAssembler* masm) {
  if (masm->options().enable_simulator_code) {
    UseScratchRegisterScope temps(masm);
    temps.Exclude(x16);
    __ LoadStackLimit(x16, StackLimitKind::kRealStackLimit);
    __ hlt(kImmExceptionIsSwitchStackLimit);
  }
}

static constexpr Register kOldSPRegister = x23;
static constexpr Register kSwitchFlagRegister = x24;

void SwitchToTheCentralStackIfNeeded(MacroAssembler* masm, Register argc_input,
                                     Register target_input,
                                     Register argv_input) {
  using ER = ExternalReference;

  __ Mov(kSwitchFlagRegister, 0);
  __ Mov(kOldSPRegister, sp);

  // Using x2-x4 as temporary registers, because they will be rewritten
  // before exiting to native code anyway.

  ER on_central_stack_flag_loc = ER::Create(
      IsolateAddressId::kIsOnCentralStackFlagAddress, masm->isolate());
  const Register& on_central_stack_flag = x2;
  __ Mov(on_central_stack_flag, on_central_stack_flag_loc);
  __ Ldrb(on_central_stack_flag, MemOperand(on_central_stack_flag));

  Label do_not_need_to_switch;
  __ Cbnz(on_central_stack_flag, &do_not_need_to_switch);
  // Switch to central stack.

  static constexpr Register central_stack_sp = x4;
  DCHECK(!AreAliased(central_stack_sp, argc_input, argv_input, target_input));
  {
    __ Push(argc_input, target_input, argv_input, padreg);
    __ Mov(kCArgRegs[0], ER::isolate_address());
    __ Mov(kCArgRegs[1], kOldSPRegister);
    __ CallCFunction(ER::wasm_switch_to_the_central_stack(), 2,
                     SetIsolateDataSlots::kNo);
    __ Mov(central_stack_sp, kReturnRegister0);
    __ Pop(padreg, argv_input, target_input, argc_input);
  }
  {
    // Update the sp saved in the frame.
    // It will be used to calculate the callee pc during GC.
    // The pc is going to be on the new stack segment, so rewrite it here.
    UseScratchRegisterScope temps{masm};
    Register new_sp_after_call = temps.AcquireX();
    __ Sub(new_sp_after_call, central_stack_sp, kSystemPointerSize);
    __ Str(new_sp_after_call, MemOperand(fp, ExitFrameConstants::kSPOffset));
  }

  SwitchSimulatorStackLimit(masm);

  static constexpr int kReturnAddressSlotOffset = 1 * kSystemPointerSize;
  static constexpr int kPadding = 1 * kSystemPointerSize;
  __ Sub(sp, central_stack_sp, kReturnAddressSlotOffset + kPadding);
  __ Mov(kSwitchFlagRegister, 1);

  __ bind(&do_not_need_to_switch);
}

void SwitchFromTheCentralStackIfNeeded(MacroAssembler* masm) {
  using ER = ExternalReference;

  Label no_stack_change;
  __ Cbz(kSwitchFlagRegister, &no_stack_change);

  {
    __ Push(kReturnRegister0, kReturnRegister1);
    __ Mov(kCArgRegs[0], ER::isolate_address());
    __ CallCFunction(ER::wasm_switch_from_the_central_stack(), 1,
                     SetIsolateDataSlots::kNo);
    __ Pop(kReturnRegister1, kReturnRegister0);
  }

  SwitchSimulatorStackLimit(masm);

  __ Mov(sp, kOldSPRegister);

  __ bind(&no_stack_change);
}

}  // namespace

#endif  // V8_ENABLE_WEBASSEMBLY

void Builtins::Generate_CEntry(MacroAssembler* masm, int result_size,
                               ArgvMode argv_mode, bool builtin_exit_frame,
                               bool switch_to_central_stack) {
  ASM_LOCATION("CEntry::Generate entry");

  using ER = ExternalReference;

  // Register parameters:
  //    x0: argc (including receiver, untagged)
  //    x1: target
  // If argv_mode == ArgvMode::kRegister:
  //    x11: argv (pointer to first argument)
  //
  // The stack on entry holds the arguments and the receiver, with the receiver
  // at the highest address:
  //
  //    sp[argc-1]: receiver
  //    sp[argc-2]: arg[argc-2]
  //    ...           ...
  //    sp[1]:      arg[1]
  //    sp[0]:      arg[0]
  //
  // The arguments are in reverse order, so that arg[argc-2] is actually the
  // first argument to the target function and arg[0] is the last.
  static constexpr Register argc_input = x0;
  static constexpr Register target_input = x1;
  // Initialized below if ArgvMode::kStack.
  static constexpr Register argv_input = x11;

  if (argv_mode == ArgvMode::kStack) {
    // Derive argv from the stack pointer so that it points to the first
    // argument.
    __ SlotAddress(argv_input, argc_input);
    __ Sub(argv_input, argv_input, kReceiverOnStackSize);
  }

  // If ArgvMode::kStack, argc is reused below and must be retained across the
  // call in a callee-saved register.
  static constexpr Register argc = x22;

  // Enter the exit frame.
  const int kNoExtraSpace = 0;
  FrameScope scope(masm, StackFrame::MANUAL);
  __ EnterExitFrame(
      x10, kNoExtraSpace,
      builtin_exit_frame ? StackFrame::BUILTIN_EXIT : StackFrame::EXIT);

  if (argv_mode == ArgvMode::kStack) {
    __ Mov(argc, argc_input);
  }

#if V8_ENABLE_WEBASSEMBLY
  if (switch_to_central_stack) {
    SwitchToTheCentralStackIfNeeded(masm, argc_input, target_input, argv_input);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  // x21 : argv
  // x22 : argc
  // x23 : call target
  //
  // The stack (on entry) holds the arguments and the receiver, with the
  // receiver at the highest address:
  //
  //         argv[8]:     receiver
  // argv -> argv[0]:     arg[argc-2]
  //         ...          ...
  //         argv[...]:   arg[1]
  //         argv[...]:   arg[0]
  //
  // Immediately below (after) this is the exit frame, as constructed by
  // EnterExitFrame:
  //         fp[8]:    CallerPC (lr)
  //   fp -> fp[0]:    CallerFP (old fp)
  //         fp[-8]:   Space reserved for SPOffset.
  //         fp[-16]:  CodeObject()
  //         sp[...]:  Saved doubles, if saved_doubles is true.
  //         sp[16]:   Alignment padding, if necessary.
  //         sp[8]:   Preserved x22 (used for argc).
  //   sp -> sp[0]:    Space reserved for the return address.

  // TODO(jgruber): Swap these registers in the calling convention instead.
  static_assert(target_input == x1);
  static_assert(argv_input == x11);
  __ Swap(target_input, argv_input);
  static constexpr Register target = x11;
  static constexpr Register argv = x1;
  static_assert(!AreAliased(argc_input, argc, target, argv));

  // Prepare AAPCS64 arguments to pass to the builtin.
  static_assert(argc_input == x0);  // Already in the right spot.
  static_assert(argv == x1);        // Already in the right spot.
  __ Mov(x2, ER::isolate_address());

  __ StoreReturnAddressAndCall(target);

  // Result returned in x0 or x1:x0 - do not destroy these registers!

  //  x0    result0      The return code from the call.
  //  x1    result1      For calls which return ObjectPair.
  //  x22   argc         .. only if ArgvMode::kStack.
  const Register& result = x0;

#if V8_ENABLE_WEBASSEMBLY
  if (switch_to_central_stack) {
    SwitchFromTheCentralStackIfNeeded(masm);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  // Check result for exception sentinel.
  Label exception_returned;
  // The returned value may be a trusted object, living outside of the main
  // pointer compression cage, so we need to use full pointer comparison here.
  __ CompareRoot(result, RootIndex::kException, ComparisonMode::kFullPointer);
  __ B(eq, &exception_returned);

  // The call succeeded, so unwind the stack and return.
  if (argv_mode == ArgvMode::kStack) {
    __ Mov(x11, argc);  // x11 used as scratch, just til DropArguments below.
    __ LeaveExitFrame(x10, x9);
    __ DropArguments(x11);
  } else {
    __ LeaveExitFrame(x10, x9);
  }

  __ AssertFPCRState();
  __ Ret();

  // Handling of exception.
  __ Bind(&exception_returned);

  // Ask the runtime for help to determine the handler. This will set x0 to
  // contain the current exception, don't clobber it.
  {
    FrameScope scope(masm, StackFrame::MANUAL);
    __ Mov(x0, 0);  // argc.
    __ Mov(x1, 0);  // argv.
    __ Mov(x2, ER::isolate_address());
    __ CallCFunction(ER::Create(Runtime::kUnwindAndFindExceptionHandler), 3,
                     SetIsolateDataSlots::kNo);
  }

  // Retrieve the handler context, SP and FP.
  __ Mov(cp, ER::Create(IsolateAddressId::kPendingHandlerContextAddress,
                        masm->isolate()));
  __ Ldr(cp, MemOperand(cp));
  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.AcquireX();
    __ Mov(scratch, ER::Create(IsolateAddressId::kPendingHandlerSPAddress,
                               masm->isolate()));
    __ Ldr(scratch, MemOperand(scratch));
    __ Mov(sp, scratch);
  }
  __ Mov(fp, ER::Create(IsolateAddressId::kPendingHandlerFPAddress,
                        masm->isolate()));
  __ Ldr(fp, MemOperand(fp));

  // If the handler is a JS frame, restore the context to the frame. Note that
  // the context will be set to (cp == 0) for non-JS frames.
  Label not_js_frame;
  __ Cbz(cp, &not_js_frame);
  __ Str(cp, MemOperand(fp, StandardFrameConstants::kContextOffset));
  __ Bind(&not_js_frame);

  {
    // Clear c_entry_fp, like we do in `LeaveExitFrame`.
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.AcquireX();
    __ Mov(scratch,
           ER::Create(IsolateAddressId::kCEntryFPAddress, masm->isolate()));
    __ Str(xzr, MemOperand(scratch));
  }

  // Compute the handler entry address and jump to it. We use x17 here for the
  // jump target, as this jump can occasionally end up at the start of
  // InterpreterEnterAtBytecode, which when CFI is enabled starts with
  // a "BTI c".
  UseScratchRegisterScope temps(masm);
  temps.Exclude(x17);
  __ Mov(x17, ER::Create(IsolateAddressId::kPendingHandlerEntrypointAddress,
                         masm->isolate()));
  __ Ldr(x17, MemOperand(x17));
  __ Br(x17);
}

#if V8_ENABLE_WEBASSEMBLY
void Builtins::Generate_WasmHandleStackOverflow(MacroAssembler* masm) {
  using ER = ExternalReference;
  Register frame_base = WasmHandleStackOverflowDescriptor::FrameBaseRegister();
  Register gap = WasmHandleStackOverflowDescriptor::GapRegister();
  {
    DCHECK_NE(kCArgRegs[1], frame_base);
    DCHECK_NE(kCArgRegs[3], frame_base);
    __ Mov(kCArgRegs[3], gap);
    __ Mov(kCArgRegs[1], sp);
    __ Sub(kCArgRegs[2], frame_base, kCArgRegs[1]);
    __ Mov(kCArgRegs[4], fp);
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ Push(kCArgRegs[3], padreg);
    __ Mov(kCArgRegs[0], ER::isolate_address());
    __ CallCFunction(ER::wasm_grow_stack(), 5);
    __ Pop(padreg, gap);
    DCHECK_NE(kReturnRegister0, gap);
  }
  Label call_runtime;
  // wasm_grow_stack returns zero if it cannot grow a stack.
  __ Cbz(kReturnRegister0, &call_runtime);
  {
    UseScratchRegisterScope temps(masm);
    Register new_fp = temps.AcquireX();
    // Calculate old FP - SP offset to adjust FP accordingly to new SP.
    __ Mov(new_fp, sp);
    __ Sub(new_fp, fp, new_fp);
    __ Add(new_fp, kReturnRegister0, new_fp);
    __ Mov(fp, new_fp);
  }
  SwitchSimulatorStackLimit(masm);
  __ Mov(sp, kReturnRegister0);
  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.AcquireX();
    __ Mov(scratch, StackFrame::TypeToMarker(StackFrame::WASM_SEGMENT_START));
    __ Str(scratch, MemOperand(fp, TypedFrameConstants::kFrameTypeOffset));
  }
  __ Ret();

  __ bind(&call_runtime);
  // If wasm_grow_stack returns zero interruption or stack overflow
  // should be handled by runtime call.
  {
    __ Ldr(kWasmImplicitArgRegister,
           MemOperand(fp, WasmFrameConstants::kWasmInstanceDataOffset));
    __ LoadTaggedField(
        cp, FieldMemOperand(kWasmImplicitArgRegister,
                            WasmTrustedInstanceData::kNativeContextOffset));
    FrameScope scope(masm, StackFrame::MANUAL);
    __ EnterFrame(StackFrame::INTERNAL);
    __ SmiTag(gap);
    __ PushArgument(gap);
    __ CallRuntime(Runtime::kWasmStackGuard);
    __ LeaveFrame(StackFrame::INTERNAL);
    __ Ret();
  }
}
#endif  // V8_ENABLE_WEBASSEMBLY

void Builtins::Generate_DoubleToI(MacroAssembler* masm) {
  Label done;
  Register result = x7;

  DCHECK(result.Is64Bits());

  HardAbortScope hard_abort(masm);  // Avoid calls to Abort.
  UseScratchRegisterScope temps(masm);
  Register scratch1 = temps.AcquireX();
  Register scratch2 = temps.AcquireX();
  DoubleRegister double_scratch = temps.AcquireD();

  // Account for saved regs.
  const int kArgumentOffset = 2 * kSystemPointerSize;

  __ Push(result, scratch1);  // scratch1 is also pushed to preserve alignment.
  __ Peek(double_scratch, kArgumentOffset);

  // Try to convert with a FPU convert instruction.  This handles all
  // non-saturating cases.
  __ TryConvertDoubleToInt64(result, double_scratch, &done);
  __ Fmov(result, double_scratch);

  // If we reach here we need to manually convert the input to an int32.

  // Extract the exponent.
  Register exponent = scratch1;
  __ Ubfx(exponent, result, HeapNumber::kMantissaBits,
          HeapNumber::kExponentBits);

  // It the exponent is >= 84 (kMantissaBits + 32), the result is always 0 since
  // the mantissa gets shifted completely out of the int32_t result.
  __ Cmp(exponent, HeapNumber::kExponentBias + HeapNumber::kMantissaBits + 32);
  __ CzeroX(result, ge);
  __ B(ge, &done);

  // The Fcvtzs sequence handles all cases except where the conversion causes
  // signed overflow in the int64_t target. Since we've already handled
  // exponents >= 84, we can guarantee that 63 <= exponent < 84.

  if (v8_flags.debug_code) {
    __ Cmp(exponent, HeapNumber::kExponentBias + 63);
    // Exponents less than this should have been handled by the Fcvt case.
    __ Check(ge, AbortReason::kUnexpectedValue);
  }

  // Isolate the mantissa bits, and set the implicit '1'.
  Register mantissa = scratch2;
  __ Ubfx(mantissa, result, 0, HeapNumber::kMantissaBits);
  __ Orr(mantissa, mantissa, 1ULL << HeapNumber::kMantissaBits);

  // Negate the mantissa if necessary.
  __ Tst(result, kXSignMask);
  __ Cneg(mantissa, mantissa, ne);

  // Shift the mantissa bits in the correct place. We know that we have to shift
  // it left here, because exponent >= 63 >= kMantissaBits.
  __ Sub(exponent, exponent,
         HeapNumber::kExponentBias + HeapNumber::kMantissaBits);
  __ Lsl(result, mantissa, exponent);

  __ Bind(&done);
  __ Poke(result, kArgumentOffset);
  __ Pop(scratch1, result);
  __ Ret();
}

void Builtins::Generate_CallApiCallbackImpl(MacroAssembler* masm,
                                            CallApiCallbackMode mode) {
  // ----------- S t a t e -------------
  // CallApiCallbackMode::kOptimizedNoProfiling/kOptimized modes:
  //  -- x1                  : api function address
  // Both modes:
  //  -- x2                  : arguments count (not including the receiver)
  //  -- x3                  : FunctionTemplateInfo
  //  -- x0                  : holder
  //  -- cp                  : context
  //  -- sp[0]               : receiver
  //  -- sp[8]               : first argument
  //  -- ...
  //  -- sp[(argc) * 8]      : last argument
  // -----------------------------------

  Register function_callback_info_arg = kCArgRegs[0];

  Register api_function_address = no_reg;
  Register argc = no_reg;
  Register func_templ = no_reg;
  Register holder = no_reg;
  Register topmost_script_having_context = no_reg;
  Register scratch = x4;

  switch (mode) {
    case CallApiCallbackMode::kGeneric:
      argc = CallApiCallbackGenericDescriptor::ActualArgumentsCountRegister();
      topmost_script_having_context = CallApiCallbackGenericDescriptor::
          TopmostScriptHavingContextRegister();
      func_templ =
          CallApiCallbackGenericDescriptor::FunctionTemplateInfoRegister();
      holder = CallApiCallbackGenericDescriptor::HolderRegister();
      break;

    case CallApiCallbackMode::kOptimizedNoProfiling:
    case CallApiCallbackMode::kOptimized:
      // Caller context is always equal to current context because we don't
      // inline Api calls cross-context.
      topmost_script_having_context = kContextRegister;
      api_function_address =
          CallApiCallbackOptimizedDescriptor::ApiFunctionAddressRegister();
      argc = CallApiCallbackOptimizedDescriptor::ActualArgumentsCountRegister();
      func_templ =
          CallApiCallbackOptimizedDescriptor::FunctionTemplateInfoRegister();
      holder = CallApiCallbackOptimizedDescriptor::HolderRegister();
      break;
  }
  DCHECK(!AreAliased(api_function_address, topmost_script_having_context, argc,
                     holder, func_templ, scratch));

  using FCA = FunctionCallbackArguments;
  using ER = ExternalReference;
  using FC = ApiCallbackExitFrameConstants;

  static_assert(FCA::kArgsLength == 6);
  static_assert(FCA::kNewTargetIndex == 5);
  static_assert(FCA::kTargetIndex == 4);
  static_assert(FCA::kReturnValueIndex == 3);
  static_assert(FCA::kContextIndex == 2);
  static_assert(FCA::kIsolateIndex == 1);
  static_assert(FCA::kHolderIndex == 0);

  // Set up FunctionCallbackInfo's implicit_args on the stack as follows:
  // Target state:
  //   sp[0 * kSystemPointerSize]: kHolder   <= FCA::implicit_args_
  //   sp[1 * kSystemPointerSize]: kIsolate
  //   sp[2 * kSystemPointerSize]: kContext
  //   sp[3 * kSystemPointerSize]: undefined (kReturnValue)
  //   sp[4 * kSystemPointerSize]: kData
  //   sp[5 * kSystemPointerSize]: undefined (kNewTarget)
  // Existing state:
  //   sp[6 * kSystemPointerSize]:            <= FCA:::values_

  __ StoreRootRelative(IsolateData::topmost_script_having_context_offset(),
                       topmost_script_having_context);

  if (mode == CallApiCallbackMode::kGeneric) {
    api_function_address = ReassignRegister(topmost_script_having_context);
  }

  // Reserve space on the stack.
  static constexpr int kStackSize = FCA::kArgsLength;
  static_assert(kStackSize % 2 == 0);
  __ Claim(kStackSize, kSystemPointerSize);

  // kHolder.
  __ Str(holder, MemOperand(sp, FCA::kHolderIndex * kSystemPointerSize));

  // kIsolate.
  __ Mov(scratch, ER::isolate_address());
  __ Str(scratch, MemOperand(sp, FCA::kIsolateIndex * kSystemPointerSize));

  // kContext.
  __ Str(cp, MemOperand(sp, FCA::kContextIndex * kSystemPointerSize));

  // kReturnValue.
  __ LoadRoot(scratch, RootIndex::kUndefinedValue);
  __ Str(scratch, MemOperand(sp, FCA::kReturnValueIndex * kSystemPointerSize));

  // kTarget.
  __ Str(func_templ, MemOperand(sp, FCA::kTargetIndex * kSystemPointerSize));

  // kNewTarget.
  __ Str(scratch, MemOperand(sp, FCA::kNewTargetIndex * kSystemPointerSize));

  FrameScope frame_scope(masm, StackFrame::MANUAL);
  if (mode == CallApiCallbackMode::kGeneric) {
    __ LoadExternalPointerField(
        api_function_address,
        FieldMemOperand(func_templ,
                        FunctionTemplateInfo::kMaybeRedirectedCallbackOffset),
        kFunctionTemplateInfoCallbackTag);
  }

  __ EnterExitFrame(scratch, FC::getExtraSlotsCountFrom<ExitFrameConstants>(),
                    StackFrame::API_CALLBACK_EXIT);

  // This is a workaround for performance regression observed on Apple Silicon
  // (https://crbug.com/347741609): reading argc value after the call via
  //   MemOperand argc_operand = MemOperand(fp, FC::kFCIArgcOffset);
  // is noticeably slower than using sp-based access:
  MemOperand argc_operand = ExitFrameStackSlotOperand(FCA::kLengthOffset);
  if (v8_flags.debug_code) {
    // Ensure sp-based calculation of FC::length_'s address matches the
    // fp-based one.
    Label ok;
    // +kSystemPointerSize is for the slot at [sp] which is reserved in all
    // ExitFrames for storing the return PC.
    __ Add(scratch, sp,
           FCA::kLengthOffset + kSystemPointerSize - FC::kFCIArgcOffset);
    __ cmp(scratch, fp);
    __ B(eq, &ok);
    __ DebugBreak();
    __ Bind(&ok);
  }
  {
    ASM_CODE_COMMENT_STRING(masm, "Initialize v8::FunctionCallbackInfo");
    // FunctionCallbackInfo::length_.
    // TODO(ishell): pass JSParameterCount(argc) to simplify things on the
    // caller end.
    __ Str(argc, argc_operand);

    // FunctionCallbackInfo::implicit_args_.
    __ Add(scratch, fp, Operand(FC::kImplicitArgsArrayOffset));
    __ Str(scratch, MemOperand(fp, FC::kFCIImplicitArgsOffset));

    // FunctionCallbackInfo::values_ (points at JS arguments on the stack).
    __ Add(scratch, fp, Operand(FC::kFirstArgumentOffset));
    __ Str(scratch, MemOperand(fp, FC::kFCIValuesOffset));
  }

  __ RecordComment("v8::FunctionCallback's argument.");
  // function_callback_info_arg = v8::FunctionCallbackInfo&
  __ Add(function_callback_info_arg, fp,
         Operand(FC::kFunctionCallbackInfoOffset));

  DCHECK(!AreAliased(api_function_address, function_callback_info_arg));

  ExternalReference thunk_ref = ER::invoke_function_callback(mode);
  Register no_thunk_arg = no_reg;

  MemOperand return_value_operand = MemOperand(fp, FC::kReturnValueOffset);
  static constexpr int kSlotsToDropOnReturn =
      FC::kFunctionCallbackInfoArgsLength + kJSArgcReceiverSlots;

  const bool with_profiling =
      mode != CallApiCallbackMode::kOptimizedNoProfiling;
  CallApiFunctionAndReturn(masm, with_profiling, api_function_address,
                           thunk_ref, no_thunk_arg, kSlotsToDropOnReturn,
                           &argc_operand, return_value_operand);
}

void Builtins::Generate_CallApiGetter(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- cp                  : context
  //  -- x1                  : receiver
  //  -- x3                  : accessor info
  //  -- x0                  : holder
  // -----------------------------------

  Register name_arg = kCArgRegs[0];
  Register property_callback_info_arg = kCArgRegs[1];

  Register api_function_address = x2;
  Register receiver = ApiGetterDescriptor::ReceiverRegister();
  Register holder = ApiGetterDescriptor::HolderRegister();
  Register callback = ApiGetterDescriptor::CallbackRegister();
  Register scratch = x4;
  Register undef = x5;
  Register scratch2 = x6;

  DCHECK(!AreAliased(receiver, holder, callback, scratch, undef, scratch2));

  // Build v8::PropertyCallbackInfo::args_ array on the stack and push property
  // name below the exit frame to make GC aware of them.
  using PCA = PropertyCallbackArguments;
  using ER = ExternalReference;
  using FC = ApiAccessorExitFrameConstants;

  static_assert(PCA::kPropertyKeyIndex == 0);
  static_assert(PCA::kShouldThrowOnErrorIndex == 1);
  static_assert(PCA::kHolderIndex == 2);
  static_assert(PCA::kIsolateIndex == 3);
  static_assert(PCA::kHolderV2Index == 4);
  static_assert(PCA::kReturnValueIndex == 5);
  static_assert(PCA::kDataIndex == 6);
  static_assert(PCA::kThisIndex == 7);
  static_assert(PCA::kArgsLength == 8);

  // Set up v8::PropertyCallbackInfo's (PCI) args_ on the stack as follows:
  // Target state:
  //   sp[0 * kSystemPointerSize]: name                      <= PCI::args_
  //   sp[1 * kSystemPointerSize]: kShouldThrowOnErrorIndex
  //   sp[2 * kSystemPointerSize]: kHolderIndex
  //   sp[3 * kSystemPointerSize]: kIsolateIndex
  //   sp[4 * kSystemPointerSize]: kHolderV2Index
  //   sp[5 * kSystemPointerSize]: kReturnValueIndex
  //   sp[6 * kSystemPointerSize]: kDataIndex
  //   sp[7 * kSystemPointerSize]: kThisIndex / receiver

  __ LoadTaggedField(scratch,
                     FieldMemOperand(callback, AccessorInfo::kDataOffset));
  __ LoadRoot(undef, RootIndex::kUndefinedValue);
  __ Mov(scratch2, ER::isolate_address());
  Register holderV2 = xzr;
  __ Push(receiver, scratch,  // kThisIndex, kDataIndex
          undef, holderV2,    // kReturnValueIndex, kHolderV2Index
          scratch2, holder);  // kIsolateIndex, kHolderIndex

  // |name_arg| clashes with |holder|, so we need to push holder first.
  __ LoadTaggedField(name_arg,
                     FieldMemOperand(callback, AccessorInfo::kNameOffset));
  static_assert(kDontThrow == 0);
  Register should_throw_on_error = xzr;  // should_throw_on_error -> kDontThrow
  __ Push(should_throw_on_error, name_arg);

  __ RecordComment("Load api_function_address");
  __ LoadExternalPointerField(
      api_function_address,
      FieldMemOperand(callback, AccessorInfo::kMaybeRedirectedGetterOffset),
      kAccessorInfoGetterTag);

  FrameScope frame_scope(masm, StackFrame::MANUAL);
  __ EnterExitFrame(scratch, FC::getExtraSlotsCountFrom<ExitFrameConstants>(),
                    StackFrame::API_ACCESSOR_EXIT);

  __ RecordComment("Create v8::PropertyCallbackInfo object on the stack.");
  // property_callback_info_arg = v8::PropertyCallbackInfo&
  __ Add(property_callback_info_arg, fp, Operand(FC::kArgsArrayOffset));

  DCHECK(!AreAliased(api_function_address, property_callback_info_arg, name_arg,
                     callback, scratch, scratch2));

#ifdef V8_ENABLE_DIRECT_HANDLE
  // name_arg = Local<Name>(name), name value was pushed to GC-ed stack space.
  // |name_arg| is already initialized above.
#else
  // name_arg = Local<Name>(&name), which is &args_array[kPropertyKeyIndex].
  static_assert(PCA::kPropertyKeyIndex == 0);
  __ mov(name_arg, property_callback_info_arg);
#endif

  ExternalReference thunk_ref = ER::invoke_accessor_getter_callback();
  // Pass AccessorInfo to thunk wrapper in case profiler or side-effect
  // checking is enabled.
  Register thunk_arg = callback;

  MemOperand return_value_operand = MemOperand(fp, FC::kReturnValueOffset);
  static constexpr int kSlotsToDropOnReturn =
      FC::kPropertyCallbackInfoArgsLength;
  MemOperand* const kUseStackSpaceConstant = nullptr;

  const bool with_profiling = true;
  CallApiFunctionAndReturn(masm, with_profiling, api_function_address,
                           thunk_ref, thunk_arg, kSlotsToDropOnReturn,
                           kUseStackSpaceConstant, return_value_operand);
}

void Builtins::Generate_DirectCEntry(MacroAssembler* masm) {
  // The sole purpose of DirectCEntry is for movable callers (e.g. any general
  // purpose InstructionStream object) to be able to call into C functions that
  // may trigger GC and thus move the caller.
  //
  // DirectCEntry places the return address on the stack (updated by the GC),
  // making the call GC safe. The irregexp backend relies on this.

  __ Poke<MacroAssembler::kSignLR>(lr, 0);  // Store the return address.
  __ Blr(x10);                              // Call the C++ function.
  __ Peek<MacroAssembler::kAuthLR>(lr, 0);  // Return to calling code.
  __ AssertFPCRState();
  __ Ret();
}

namespace {

template <typename RegisterT>
void CopyRegListToFrame(MacroAssembler* masm, const Register& dst,
                        int dst_offset, const CPURegList& reg_list,
                        const RegisterT& temp0, const RegisterT& temp1,
                        int src_offset = 0) {
  ASM_CODE_COMMENT(masm);
  DCHECK_EQ(reg_list.Count() % 2, 0);
  UseScratchRegisterScope temps(masm);
  CPURegList copy_to_input = reg_list;
  int reg_size = reg_list.RegisterSizeInBytes();
  DCHECK_EQ(temp0.SizeInBytes(), reg_size);
  DCHECK_EQ(temp1.SizeInBytes(), reg_size);

  // Compute some temporary addresses to avoid having the macro assembler set
  // up a temp with an offset for accesses out of the range of the addressing
  // mode.
  Register src = temps.AcquireX();
  masm->Add(src, sp, src_offset);
  masm->Add(dst, dst, dst_offset);

  // Write reg_list into the frame pointed to by dst.
  for (int i = 0; i < reg_list.Count(); i += 2) {
    masm->Ldp(temp0, temp1, MemOperand(src, i * reg_size));

    CPURegister reg0 = copy_to_input.PopLowestIndex();
    CPURegister reg1 = copy_to_input.PopLowestIndex();
    int offset0 = reg0.code() * reg_size;
    int offset1 = reg1.code() * reg_size;

    // Pair up adjacent stores, otherwise write them separately.
    if (offset1 == offset0 + reg_size) {
      masm->Stp(temp0, temp1, MemOperand(dst, offset0));
    } else {
      masm->Str(temp0, MemOperand(dst, offset0));
      masm->Str(temp1, MemOperand(dst, offset1));
    }
  }
  masm->Sub(dst, dst, dst_offset);
}

void RestoreRegList(MacroAssembler* masm, const CPURegList& reg_list,
                    const Register& src_base, int src_offset) {
  ASM_CODE_COMMENT(masm);
  DCHECK_EQ(reg_list.Count() % 2, 0);
  UseScratchRegisterScope temps(masm);
  CPURegList restore_list = reg_list;
  int reg_size = restore_list.RegisterSizeInBytes();

  // Compute a temporary addresses to avoid having the macro assembler set
  // up a temp with an offset for accesses out of the range of the addressing
  // mode.
  Register src = temps.AcquireX();
  masm->Add(src, src_base, src_offset);

  // No need to restore padreg.
  restore_list.Remove(padreg);

  // Restore every register in restore_list from src.
  while (!restore_list.IsEmpty()) {
    CPURegister reg0 = restore_list.PopLowestIndex();
    CPURegister reg1 = restore_list.PopLowestIndex();
    int offset0 = reg0.code() * reg_size;

    if (reg1 == NoCPUReg) {
      masm->Ldr(reg0, MemOperand(src, offset0));
      break;
    }

    int offset1 = reg1.code() * reg_size;

    // Pair up adjacent loads, otherwise read them separately.
    if (offset1 == offset0 + reg_size) {
      masm->Ldp(reg0, reg1, MemOperand(src, offset0));
    } else {
      masm->Ldr(reg0, MemOperand(src, offset0));
      masm->Ldr(reg1, MemOperand(src, offset1));
    }
  }
}

void Generate_DeoptimizationEntry(MacroAssembler* masm,
                                  DeoptimizeKind deopt_kind) {
  Isolate* isolate = masm->isolate();

  // TODO(all): This code needs to be revisited. We probably only need to save
  // caller-saved registers here. Callee-saved registers can be stored directly
  // in the input frame.

  // Save all allocatable simd128 / double registers.
  CPURegList saved_simd128_registers(
      kQRegSizeInBits,
      DoubleRegList::FromBits(
          RegisterConfiguration::Default()->allocatable_simd128_codes_mask()));
  DCHECK_EQ(saved_simd128_registers.Count() % 2, 0);
  __ PushCPURegList(saved_simd128_registers);

  // We save all the registers except sp, lr, platform register (x18) and the
  // masm scratches.
  CPURegList saved_registers(CPURegister::kRegister, kXRegSizeInBits, 0, 28);
  saved_registers.Remove(ip0);
  saved_registers.Remove(ip1);
  saved_registers.Remove(x18);
  saved_registers.Combine(fp);
  saved_registers.Align();
  DCHECK_EQ(saved_registers.Count() % 2, 0);
  __ PushCPURegList(saved_registers);

  __ Mov(x3, Operand(ExternalReference::Create(
                 IsolateAddressId::kCEntryFPAddress, isolate)));
  __ Str(fp, MemOperand(x3));

  const int kSavedRegistersAreaSize =
      (saved_registers.Count() * kXRegSize) +
      (saved_simd128_registers.Count() * kQRegSize);

  // Floating point registers are s
```