Response:
The user wants a summary of the provided C++ code snippet from `v8/src/builtins/arm64/builtins-arm64.cc`.

Here's a breakdown of the thinking process to generate the response:

1. **Identify the Core Functionality:** The code consists of several functions (or "Builtins" in V8 terminology) related to WebAssembly (Wasm) and its interaction with JavaScript. Keywords like "Wasm," "Js," "Wrapper," "Suspend," "Resume," "Stack," and "Continuation" are strong indicators.

2. **Categorize the Functions:** Group the functions by their apparent purpose. For example:
    * **Stack Manipulation:**  `SwitchStacks`, `ReloadParentContinuation`, `RestoreParentSuspender`, `ResetStackSwitchFrameStackSlots`
    * **Wasm Callbacks:** `Generate_WasmToJsWrapperAsm`, `Generate_WasmTrapHandlerLandingPad`
    * **Wasm Suspension/Resumption:** `Generate_WasmSuspend`, `Generate_WasmResume`, `Generate_WasmReject`, `Generate_WasmOnStackReplace`
    * **JSToWasm Interaction:** `SwitchToAllocatedStack`, `SwitchBackAndReturnPromise`, `GenerateExceptionHandlingLandingPad`, `JSToWasmWrapperHelper`

3. **Analyze Individual Functions:** For each function, try to understand its role:
    * `SwitchStacks`:  Handles switching between different execution stacks, likely for Wasm continuations.
    * `ReloadParentContinuation`: Restores the continuation of the calling function.
    * `RestoreParentSuspender`: Restores the state of the suspender object.
    * `ResetStackSwitchFrameStackSlots`: Clears specific slots on the stack.
    * `Generate_WasmToJsWrapperAsm`: Creates a wrapper to call JavaScript from Wasm.
    * `Generate_WasmTrapHandlerLandingPad`:  Handles Wasm trap exceptions.
    * `Generate_WasmSuspend`: Implements the Wasm suspend operation.
    * `Generate_WasmResume`/`Generate_WasmReject`: Implement resuming a suspended Wasm function, either successfully or with a rejection.
    * `Generate_WasmOnStackReplace`:  Indicates it's related to on-stack replacement (optimization), but the implementation is a trap (likely not implemented or relevant on this architecture).
    * `SwitchToAllocatedStack`:  Manages switching to a new stack when calling Wasm from JS.
    * `SwitchBackAndReturnPromise`: Handles returning a promise from Wasm to JS.
    * `GenerateExceptionHandlingLandingPad`:  Handles exceptions thrown from Wasm when called from JS.
    * `JSToWasmWrapperHelper`:  Sets up the call from JavaScript to Wasm.

4. **Identify JavaScript Connections:**  Look for functions that explicitly mention "Js" or handle interactions between JavaScript and Wasm. `Generate_WasmToJsWrapperAsm`, `Generate_WasmSuspend`, `Generate_WasmResume`, `Generate_WasmReject`, and the `JSToWasmWrapperHelper` family are key here. Consider how these functions would be used from a JavaScript perspective.

5. **Look for Code Logic/Reasoning:**  Pay attention to conditional statements, loops, and variable assignments. The `RegisterAllocator` class is a good example of internal logic. Try to infer the purpose of these structures.

6. **Consider Common Programming Errors:** Think about potential issues that could arise when working with stack switching, asynchronous operations, and calling between languages.

7. **Address the ".tq" Question:** The prompt explicitly asks about `.tq` files. Explain that `.tq` indicates Torque, V8's type-checked assembly language, and that the provided file is C++, not Torque.

8. **Structure the Response:** Organize the findings into clear sections based on the prompt's requirements:
    * Overall Functionality
    * JavaScript Relationship (with examples)
    * Code Logic/Reasoning (with hypothetical input/output)
    * Common Programming Errors
    * Summary (as requested in the final instruction)

9. **Refine and Elaborate:**  Expand on the initial observations with more details. For instance, when explaining `Generate_WasmSuspend`, mention the saving of the current state and the updating of roots. For JavaScript examples, provide concrete snippets.

10. **Self-Correction/Review:** Reread the generated response and compare it to the code. Are there any inconsistencies or inaccuracies?  Is the language clear and concise?  For example, initially, I might focus too much on individual instructions. The correction would be to focus on the *higher-level purpose* of the functions. Also ensure all parts of the prompt are answered. For instance, the initial draft might forget the ".tq" question.

By following these steps, the detailed and informative response can be constructed. The process involves understanding the context (V8, WebAssembly), analyzing the code structure and individual functions, identifying connections to JavaScript, inferring logic, and structuring the information effectively.
这是一个V8源代码文件，位于`v8/src/builtins/arm64`目录下，专门针对ARM64架构。从文件名 `builtins-arm64.cc` 可以判断，它包含了一系列内置函数的实现。

**功能归纳:**

这个文件的主要功能是为 V8 虚拟机在 ARM64 架构上实现与 WebAssembly (Wasm) 相关的内置函数。这些内置函数负责处理 Wasm 代码和 JavaScript 代码之间的交互，包括：

* **Wasm 到 JavaScript 的调用:**  创建和管理从 Wasm 代码调用 JavaScript 函数的机制。
* **JavaScript 到 Wasm 的调用:**  创建和管理从 JavaScript 代码调用 Wasm 函数的机制。
* **Wasm 陷阱处理:**  处理 Wasm 代码执行过程中发生的错误（陷阱）。
* **Wasm 挂起和恢复 (Suspend/Resume):**  实现 Wasm 代码的挂起和恢复机制，这通常与异步操作或 Promises 相关。
* **栈切换 (Stack Switching):**  管理在 JavaScript 和 Wasm 之间切换执行栈的过程，这是实现 Wasm 挂起/恢复以及某些类型的优化的关键。

**详细功能列表:**

1. **`SwitchStacks`**:  负责在不同的执行栈之间进行切换。这通常用于 Wasm 的协程或者异步操作。
2. **`ReloadParentContinuation`**:  在栈切换后，重新加载父级 continuation 的信息。Continuation 可以理解为当前执行状态的快照。
3. **`RestoreParentSuspender`**:  在栈切换后，恢复父级 suspender 的状态。Suspender 对象用于管理 Wasm 的挂起状态。
4. **`ResetStackSwitchFrameStackSlots`**:  重置栈切换帧中用于 GC 扫描的槽位。
5. **`RegisterAllocator`**:  一个简单的寄存器分配器，用于在生成汇编代码时管理寄存器的使用。
6. **`GetContextFromImplicitArg`**:  从隐式参数中获取上下文信息，隐式参数可能是 `WasmTrustedInstanceData` 或 `WasmImportData`。
7. **`Builtins::Generate_WasmToJsWrapperAsm`**:  生成将 Wasm 代码调用桥接到 JavaScript 的汇编代码。
8. **`Builtins::Generate_WasmTrapHandlerLandingPad`**:  生成 Wasm 陷阱处理的入口代码。
9. **`Builtins::Generate_WasmSuspend`**:  生成实现 Wasm 代码挂起操作的汇编代码。
10. **`Builtins::Generate_WasmResume`**:  生成实现 Wasm 代码恢复执行的汇编代码 (成功恢复)。
11. **`Builtins::Generate_WasmReject`**:  生成实现 Wasm 代码恢复执行的汇编代码 (以拒绝状态恢复，通常用于 Promise 的 reject)。
12. **`Builtins::Generate_WasmOnStackReplace`**:  生成与 Wasm 代码的栈上替换 (OSR) 相关的代码，但在 ARM64 上目前是一个 `Trap()`，表示尚未实现或不需要。
13. **`SwitchToAllocatedStack`**:  当从 JavaScript 调用 Wasm 时，切换到为 Wasm 分配的栈。
14. **`SwitchBackAndReturnPromise`**:  在 Wasm 函数执行完毕后，切换回 JavaScript 栈并返回一个 Promise。
15. **`GenerateExceptionHandlingLandingPad`**:  生成处理从 Wasm 抛出的异常的入口代码。
16. **`JSToWasmWrapperHelper`**:  生成辅助函数，用于设置从 JavaScript 调用 Wasm 的过程。
17. **`Builtins::Generate_JSToWasmWrapper`**:  生成从 JavaScript 调用 Wasm 函数的包装器代码。

**关于 `.tq` 结尾:**

如果 `v8/src/builtins/arm64/builtins-arm64.cc` 以 `.tq` 结尾，那它将是一个 **V8 Torque 源代码文件**。Torque 是 V8 用于定义内置函数的类型化汇编语言。  **然而，这个文件是以 `.cc` 结尾，所以它是 C++ 源代码，直接编写汇编指令。**

**与 JavaScript 功能的关系及示例:**

这些内置函数是 V8 执行 WebAssembly 代码的关键部分，它们使得 JavaScript 可以与 Wasm 模块进行交互。

**示例 (JavaScript 调用 Wasm):**

假设有一个 Wasm 模块导出一个名为 `add` 的函数，它接受两个整数并返回它们的和。

```javascript
// 假设 wasmModule 是已加载的 WebAssembly.Module 实例
WebAssembly.instantiate(wasmModule).then(instance => {
  const wasmAdd = instance.exports.add;
  const result = wasmAdd(5, 10);
  console.log(result); // 输出 15
});
```

在这个例子中，当 JavaScript 调用 `wasmAdd(5, 10)` 时，V8 内部会使用 `Builtins::Generate_JSToWasmWrapper` 生成的包装器代码，该包装器会调用 `JSToWasmWrapperHelper` 来设置调用栈，并将参数传递给 Wasm 函数。

**示例 (Wasm 调用 JavaScript 并挂起/恢复):**

假设 Wasm 代码需要执行一个异步 JavaScript 操作（例如使用 `fetch`）。Wasm 代码可以调用一个特殊的 "suspend" 函数，该函数由 V8 提供。

```javascript
// JavaScript 端定义一个可以被 Wasm 调用的异步函数
globalThis.asyncOperation = async function(input) {
  console.log("JavaScript async operation started with:", input);
  await new Promise(resolve => setTimeout(resolve, 1000));
  console.log("JavaScript async operation finished");
  return input * 2;
};

// Wasm 代码 (伪代码)
// 导入 suspend 函数和 asyncOperation 函数
import "v8" "suspend" : fn();
import "env" "asyncOperation" : fn(i32) -> i32;

export function doAsync(value: i32): i32 {
  // 调用 JavaScript 的异步函数
  let result = asyncOperation(value);
  // 挂起 Wasm 执行，等待异步操作完成
  suspend();
  // 恢复后，返回结果
  return result;
}
```

在这个场景中，当 Wasm 代码调用 `suspend()` 时，`Builtins::Generate_WasmSuspend` 会被执行，它会保存 Wasm 当前的执行状态，并将控制权交还给 JavaScript。当 JavaScript 的异步操作完成时，它可以通过 V8 提供的机制来 "resume"  Wasm 的执行，这会涉及到 `Builtins::Generate_WasmResume`。

**代码逻辑推理及假设输入/输出:**

以 `SwitchStacks` 函数为例：

**假设输入:**

* `masm`: 一个 `MacroAssembler` 对象，用于生成汇编代码。
* `finished_continuation`: 一个寄存器，可能包含已完成的 continuation 对象。如果为 `no_reg`，则表示没有完成的 continuation。
* `keep1`, `keep2`, `keep3`: 可选的寄存器，其值需要在栈切换过程中保留。

**代码逻辑:**

1. 将 `keep1` 和 `keep2` 的值压入栈。
2. 如果 `keep3` 不是 `NoReg`，则将其值压入栈。
3. 如果 `finished_continuation` 不是 `no_reg`，则：
   * 设置 C 函数调用的参数：isolate 地址和 `finished_continuation`。
   * 调用 C++ 函数 `wasm_return_switch()`，该函数负责处理已完成的 continuation。
4. 否则 (如果 `finished_continuation` 是 `no_reg`)：
   * 设置 C 函数调用的参数：isolate 地址。
   * 调用 C++ 函数 `wasm_sync_stack_limit()`，这可能与同步栈限制有关。
5. 如果之前压入了 `keep3`，则从栈中弹出它的值。
6. 从栈中弹出 `keep2` 和 `keep1` 的值。

**可能的输出/影响:**

* 执行栈被切换到另一个 continuation。
* 如果提供了 `finished_continuation`，与之关联的内存可能会被返回到栈池。
* 栈指针 (sp) 的值会发生变化。

**用户常见的编程错误:**

与这些内置函数相关的编程错误通常发生在编写 Wasm 代码或 JavaScript 代码与 Wasm 交互时：

1. **不匹配的函数签名:**  在 JavaScript 中调用 Wasm 函数时，传递的参数类型或数量与 Wasm 函数的期望不符。例如，Wasm 期望一个整数，但 JavaScript 传递了一个字符串。
   ```javascript
   // 假设 wasmAdd 期望两个 i32 参数
   const result = wasmAdd("5", 10); // 错误：传递了字符串
   ```
2. **Wasm 内存访问越界:**  在 Wasm 代码中尝试访问超出其线性内存范围的地址。虽然这通常会被 Wasm 虚拟机捕获，但理解内存模型对于避免此类错误至关重要。
3. **异步操作处理不当:**  在使用 Wasm 的挂起/恢复功能时，JavaScript 端没有正确地处理 Promise 的 resolve 或 reject，导致 Wasm 无法正确恢复执行。
4. **在不安全的时间调用 Wasm 函数:**  例如，在垃圾回收期间调用 Wasm 函数可能会导致崩溃，因为 Wasm 内存可能正在被移动。V8 会尝试避免这种情况，但用户也需要注意。
5. **在 Wasm 模块加载完成前调用其导出函数:**  尝试在 `WebAssembly.instantiate` 的 Promise resolve 之前调用 Wasm 导出函数会导致错误。

**总结:**

`v8/src/builtins/arm64/builtins-arm64.cc` 是 V8 虚拟机在 ARM64 架构上支持 WebAssembly 的核心组成部分。它定义了用于处理 JavaScript 和 Wasm 之间交互、异常处理、以及 Wasm 挂起/恢复等关键操作的底层实现。理解这些内置函数的功能有助于深入了解 V8 如何执行 WebAssembly 代码。

### 提示词
```
这是目录为v8/src/builtins/arm64/builtins-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/arm64/builtins-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
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
             JSTo
```