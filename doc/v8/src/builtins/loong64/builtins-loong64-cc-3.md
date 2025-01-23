Response:
My thought process for analyzing the provided assembly code snippet and fulfilling the request goes like this:

1. **Understand the Goal:** The request asks for the functionality of the given C++ code (which generates assembly for the LoongArch64 architecture), its relationship to JavaScript, examples, potential errors, and a summary. The key is to interpret the assembly instructions and connect them to higher-level concepts.

2. **Initial Scan and Keyword Identification:** I quickly scanned the code looking for familiar keywords and patterns. Words like `Construct`, `BoundFunction`, `TailCallBuiltin`, `Wasm`, `FrameScope`, `Runtime`, `Stack`, `Push`, `Pop`, `Load`, `Store`, `Jump`, and labels like `call_generic_stub` and `non_constructor` immediately stand out. These give clues about the code's purpose. The presence of `Wasm` strongly suggests WebAssembly related functionality.

3. **Group by Function:** The code is divided into distinct functions like `Generate_ConstructFunction`, `Generate_ConstructBoundFunction`, `Generate_Construct`, `Generate_WasmLiftoffFrameSetup`, etc. This suggests that each function handles a specific aspect of V8's execution. I decided to analyze each function individually and then combine the insights.

4. **Analyze Individual Functions - High-Level Interpretation:**

   * **`Generate_ConstructFunction`:**  This seems to handle the creation of new JavaScript objects using the `new` keyword. It checks if the target is a "builtin" constructor or a generic one.

   * **`Generate_ConstructBoundFunction`:** This likely deals with the `bind()` method in JavaScript, creating functions with pre-set `this` values and arguments. The code manipulates the stack to accommodate the bound arguments.

   * **`Generate_Construct`:** This is the central `new` operator logic. It checks if the target is a constructor, dispatches to different handlers based on the type (regular function, bound function, proxy), and handles cases where the target is not a constructor.

   * **`Generate_WasmLiftoffFrameSetup`:** The "Wasm" prefix is a strong indicator. This function appears to be setting up the stack frame when entering a WebAssembly function. It saves registers and manages the feedback vector (used for optimization).

   * **`Generate_WasmCompileLazy`:** This function handles the lazy compilation of WebAssembly functions. It calls the runtime to perform the compilation.

   * **`Generate_WasmDebugBreak`:**  This looks like a breakpoint mechanism for WebAssembly debugging, calling into the runtime.

   * **Helper Functions (`SwitchStackState`, `SwitchStackPointer`, etc.):** The helper functions and the `Generate_WasmSuspend` function clearly relate to WebAssembly's support for asynchronous operations or continuations. They deal with saving and restoring execution state, switching stacks, and interacting with the runtime. The register allocation logic reinforces this idea.

   * **`Generate_WasmToJsWrapperAsm`:** This likely handles the transition from WebAssembly code to JavaScript code, marshaling arguments.

   * **`Generate_WasmTrapHandlerLandingPad`:** This function handles runtime errors (traps) within WebAssembly, re-entering the V8 runtime to throw an exception.

   * **`Generate_WasmSuspend`:** This function explicitly implements the suspension of a WebAssembly execution, saving its state.

   * **`Generate_WasmResumeHelper`:**  This function is responsible for resuming a previously suspended WebAssembly execution. The `onFulfilled` and `onRejected` variants handle successful and unsuccessful resumption, respectively, similar to Promises.

5. **Connect to JavaScript Concepts:** After understanding the assembly's purpose, I linked it back to familiar JavaScript features:

   * `new` operator -> `Generate_Construct`, `Generate_ConstructFunction`
   * `bind()` -> `Generate_ConstructBoundFunction`
   * WebAssembly execution, compilation, debugging -> `Generate_WasmLiftoffFrameSetup`, `Generate_WasmCompileLazy`, `Generate_WasmDebugBreak`
   * Asynchronous operations (like `async`/`await` or WebAssembly proposals for continuations) -> `Generate_WasmSuspend`, `Generate_WasmResumeHelper`, the helper functions.
   * Error handling in WebAssembly -> `Generate_WasmTrapHandlerLandingPad`

6. **Provide JavaScript Examples:**  I created simple JavaScript examples to illustrate the functionality of the `new` operator, `bind()`, and the basic concept of WebAssembly execution. For the more complex WebAssembly features like `suspend` and `resume`, I acknowledged that direct JavaScript equivalents might not be immediately obvious and relate them to concepts like `async`/`await` or Promises.

7. **Identify Potential Errors:** Based on my understanding of the code, I pinpointed common programming errors: trying to use `new` on a non-constructor, stack overflows (especially relevant for bound functions with many bound arguments), and issues related to WebAssembly integration.

8. **Code Logic Reasoning (Hypothetical Inputs and Outputs):** For the `Generate_ConstructBoundFunction`, I devised a simple scenario with a bound function and showed how the arguments would be manipulated on the stack. This demonstrates the assembly's role in argument handling.

9. **Address the ".tq" Question:**  I explained that a `.tq` extension signifies Torque, V8's internal type system and code generation language, which generates C++ code like the example provided.

10. **Summarize the Functionality:**  Finally, I synthesized the information gathered from each function's analysis into a concise summary, highlighting the core functionalities: object creation, bound functions, WebAssembly support (including compilation, debugging, and asynchronous operations), and error handling.

11. **Review and Refine:** I reviewed my analysis to ensure clarity, accuracy, and completeness, checking if I addressed all aspects of the original request. I also made sure the examples were simple and easy to understand. For instance, I initially might have overcomplicated the WebAssembly examples, but I simplified them to focus on the core concept. I also ensured the language was precise and avoided jargon where possible.
这是提供的v8源代码文件 `v8/src/builtins/loong64/builtins-loong64.cc` 的第 4 部分，总共 6 部分。基于提供的代码片段，我们可以归纳其功能如下：

**核心功能：实现 JavaScript 构造函数和 WebAssembly 相关 built-in 函数的 LoongArch64 架构特定实现。**

更具体地说，这段代码实现了以下功能：

1. **`Generate_ConstructFunction(MacroAssembler* masm)`:**  处理使用 `new` 关键字调用 JavaScript 函数作为构造函数的情况。它区分了内置构造函数和普通的 JavaScript 构造函数，并跳转到相应的 stub 执行。

2. **`Generate_ConstructBoundFunction(MacroAssembler* masm)`:** 处理使用 `new` 关键字调用 `bind()` 方法创建的绑定函数的情况。它将绑定函数的参数压入栈中，并调用目标函数。

3. **`Generate_Construct(MacroAssembler* masm)`:** 这是 `new` 操作符的核心实现。它检查目标是否可构造，并根据目标类型（普通函数、绑定函数、Proxy）分发到不同的 built-in 函数。如果目标不可构造，则调用 `ConstructedNonConstructable` 抛出错误。

4. **WebAssembly 相关 Built-ins (带 `#if V8_ENABLE_WEBASSEMBLY` 条件编译):** 这部分代码包含了多个用于支持 WebAssembly 的 built-in 函数：
    * **`Generate_WasmLiftoffFrameSetup(MacroAssembler* masm)`:**  在 Liftoff 编译模式下设置 WebAssembly 函数的栈帧，包括分配和管理反馈向量。
    * **`Generate_WasmCompileLazy(MacroAssembler* masm)`:**  实现 WebAssembly 函数的延迟编译。当首次调用未编译的 WebAssembly 函数时，会调用此 built-in 函数来触发编译。
    * **`Generate_WasmDebugBreak(MacroAssembler* masm)`:**  处理 WebAssembly 代码中的 `debugger` 语句或断点，暂停执行并调用运行时进行调试。
    * **`Generate_WasmToJsWrapperAsm(MacroAssembler* masm)`:**  实现从 WebAssembly 代码到 JavaScript 代码的调用包装器，负责参数的传递和转换。
    * **`Generate_WasmTrapHandlerLandingPad(MacroAssembler* masm)`:**  当 WebAssembly 代码发生运行时错误（例如，内存越界访问）时，作为陷阱处理程序的入口点。它会调整返回地址并跳转到 `kWasmTrapHandlerThrowTrap`。
    * **`Generate_WasmSuspend(MacroAssembler* masm)`:** 实现 WebAssembly 的 `suspend` 操作，用于挂起当前的 WebAssembly 执行状态。
    * **`Generate_WasmResumeHelper(MacroAssembler* masm, wasm::OnResume on_resume)`:**  辅助函数，用于实现 WebAssembly 的 `resume` 操作，根据 `on_resume` 参数决定是正常恢复执行还是抛出异常。

**如果 `v8/src/builtins/loong64/builtins-loong64.cc` 以 `.tq` 结尾：**

如果文件以 `.tq` 结尾，那么它确实是 **v8 Torque 源代码**。Torque 是 V8 用来定义 built-in 函数的领域特定语言。Torque 代码会被编译成 C++ 代码，类似于这里提供的 `.cc` 文件。

**与 JavaScript 功能的关系及示例：**

这段代码直接关联到 JavaScript 中创建对象和调用函数的核心机制，以及 WebAssembly 的集成。

**示例 1: `new` 操作符**

```javascript
function MyClass(value) {
  this.value = value;
}

const instance = new MyClass(10);
console.log(instance.value); // 输出 10
```

当执行 `new MyClass(10)` 时，V8 会调用类似 `Generate_Construct` 和 `Generate_ConstructFunction` 中的逻辑来创建 `MyClass` 的实例。

**示例 2: `bind()` 方法**

```javascript
function greet(name) {
  console.log(`Hello, ${name}! My context is: ${this}`);
}

const boundGreet = greet.bind({greeting: "Hi"});
boundGreet("Alice"); // 输出 "Hello, Alice! My context is: [object Object]"
```

执行 `greet.bind({greeting: "Hi"})` 时，`Generate_ConstructBoundFunction` 中的逻辑会被调用来创建一个新的绑定函数 `boundGreet`，其中 `this` 被绑定到 `{greeting: "Hi"}`。

**示例 3: WebAssembly (需要 WebAssembly 代码)**

假设有一个简单的 WebAssembly 模块导出了一个函数 `add`:

```wat
(module
  (func (export "add") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.add))
```

在 JavaScript 中加载和调用该 WebAssembly 模块的 `add` 函数时，V8 会使用像 `Generate_WasmCompileLazy` 来编译 WebAssembly 代码，并使用 `Generate_WasmToJsWrapperAsm` 来处理 JavaScript 到 WebAssembly 的调用。

```javascript
async function load
### 提示词
```
这是目录为v8/src/builtins/loong64/builtins-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/loong64/builtins-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
unction(a1);

  // Calling convention for function specific ConstructStubs require
  // a2 to contain either an AllocationSite or undefined.
  __ LoadRoot(a2, RootIndex::kUndefinedValue);

  Label call_generic_stub;

  // Jump to JSBuiltinsConstructStub or JSConstructStubGeneric.
  __ LoadTaggedField(
      a4, FieldMemOperand(a1, JSFunction::kSharedFunctionInfoOffset));
  __ Ld_wu(a4, FieldMemOperand(a4, SharedFunctionInfo::kFlagsOffset));
  __ And(a4, a4, Operand(SharedFunctionInfo::ConstructAsBuiltinBit::kMask));
  __ Branch(&call_generic_stub, eq, a4, Operand(zero_reg));

  __ TailCallBuiltin(Builtin::kJSBuiltinsConstructStub);

  __ bind(&call_generic_stub);
  __ TailCallBuiltin(Builtin::kJSConstructStubGeneric);
}

// static
void Builtins::Generate_ConstructBoundFunction(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- a0 : the number of arguments
  //  -- a1 : the function to call (checked to be a JSBoundFunction)
  //  -- a3 : the new target (checked to be a constructor)
  // -----------------------------------
  __ AssertConstructor(a1);
  __ AssertBoundFunction(a1);

  // Load [[BoundArguments]] into a2 and length of that into a4.
  __ LoadTaggedField(
      a2, FieldMemOperand(a1, JSBoundFunction::kBoundArgumentsOffset));
  __ SmiUntagField(a4, FieldMemOperand(a2, offsetof(FixedArray, length_)));

  // ----------- S t a t e -------------
  //  -- a0 : the number of arguments
  //  -- a1 : the function to call (checked to be a JSBoundFunction)
  //  -- a2 : the [[BoundArguments]] (implemented as FixedArray)
  //  -- a3 : the new target (checked to be a constructor)
  //  -- a4 : the number of [[BoundArguments]]
  // -----------------------------------

  // Reserve stack space for the [[BoundArguments]].
  {
    Label done;
    __ slli_d(a5, a4, kSystemPointerSizeLog2);
    __ Sub_d(t0, sp, Operand(a5));
    // Check the stack for overflow. We are not trying to catch interruptions
    // (i.e. debug break and preemption) here, so check the "real stack limit".
    __ LoadStackLimit(kScratchReg,
                      MacroAssembler::StackLimitKind::kRealStackLimit);
    __ Branch(&done, hs, t0, Operand(kScratchReg));
    {
      FrameScope scope(masm, StackFrame::MANUAL);
      __ EnterFrame(StackFrame::INTERNAL);
      __ CallRuntime(Runtime::kThrowStackOverflow);
    }
    __ bind(&done);
  }

  // Pop receiver.
  __ Pop(t0);

  // Push [[BoundArguments]].
  {
    Label loop, done_loop;
    __ SmiUntagField(a4, FieldMemOperand(a2, offsetof(FixedArray, length_)));
    __ Add_d(a0, a0, Operand(a4));
    __ Add_d(a2, a2,
             Operand(OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag));
    __ bind(&loop);
    __ Sub_d(a4, a4, Operand(1));
    __ Branch(&done_loop, lt, a4, Operand(zero_reg));
    __ Alsl_d(a5, a4, a2, kTaggedSizeLog2, t7);
    __ LoadTaggedField(kScratchReg, MemOperand(a5, 0));
    __ Push(kScratchReg);
    __ Branch(&loop);
    __ bind(&done_loop);
  }

  // Push receiver.
  __ Push(t0);

  // Patch new.target to [[BoundTargetFunction]] if new.target equals target.
  {
    Label skip_load;
    __ CompareTaggedAndBranch(&skip_load, ne, a1, Operand(a3));
    __ LoadTaggedField(
        a3, FieldMemOperand(a1, JSBoundFunction::kBoundTargetFunctionOffset));
    __ bind(&skip_load);
  }

  // Construct the [[BoundTargetFunction]] via the Construct builtin.
  __ LoadTaggedField(
      a1, FieldMemOperand(a1, JSBoundFunction::kBoundTargetFunctionOffset));
  __ TailCallBuiltin(Builtin::kConstruct);
}

// static
void Builtins::Generate_Construct(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- a0 : the number of arguments
  //  -- a1 : the constructor to call (can be any Object)
  //  -- a3 : the new target (either the same as the constructor or
  //          the JSFunction on which new was invoked initially)
  // -----------------------------------

  Register target = a1;
  Register map = t1;
  Register instance_type = t2;
  Register scratch = t8;
  DCHECK(!AreAliased(a0, target, map, instance_type, scratch));

  // Check if target is a Smi.
  Label non_constructor, non_proxy;
  __ JumpIfSmi(target, &non_constructor);

  // Check if target has a [[Construct]] internal method.
  __ LoadTaggedField(map, FieldMemOperand(target, HeapObject::kMapOffset));
  {
    Register flags = t3;
    __ Ld_bu(flags, FieldMemOperand(map, Map::kBitFieldOffset));
    __ And(flags, flags, Operand(Map::Bits1::IsConstructorBit::kMask));
    __ Branch(&non_constructor, eq, flags, Operand(zero_reg));
  }

  // Dispatch based on instance type.
  __ GetInstanceTypeRange(map, instance_type, FIRST_JS_FUNCTION_TYPE, scratch);
  __ TailCallBuiltin(Builtin::kConstructFunction, ls, scratch,
                     Operand(LAST_JS_FUNCTION_TYPE - FIRST_JS_FUNCTION_TYPE));

  // Only dispatch to bound functions after checking whether they are
  // constructors.
  __ TailCallBuiltin(Builtin::kConstructBoundFunction, eq, instance_type,
                     Operand(JS_BOUND_FUNCTION_TYPE));

  // Only dispatch to proxies after checking whether they are constructors.
  __ Branch(&non_proxy, ne, instance_type, Operand(JS_PROXY_TYPE));
  __ TailCallBuiltin(Builtin::kConstructProxy);

  // Called Construct on an exotic Object with a [[Construct]] internal method.
  __ bind(&non_proxy);
  {
    // Overwrite the original receiver with the (original) target.
    __ StoreReceiver(target);
    // Let the "call_as_constructor_delegate" take care of the rest.
    __ LoadNativeContextSlot(target,
                             Context::CALL_AS_CONSTRUCTOR_DELEGATE_INDEX);
    __ TailCallBuiltin(Builtins::CallFunction());
  }

  // Called Construct on an Object that doesn't have a [[Construct]] internal
  // method.
  __ bind(&non_constructor);
  __ TailCallBuiltin(Builtin::kConstructedNonConstructable);
}

#if V8_ENABLE_WEBASSEMBLY
// Compute register lists for parameters to be saved. We save all parameter
// registers (see wasm-linkage.h). They might be overwritten in the runtime
// call below. We don't have any callee-saved registers in wasm, so no need to
// store anything else.
constexpr RegList kSavedGpRegs = ([]() constexpr {
  RegList saved_gp_regs;
  for (Register gp_param_reg : wasm::kGpParamRegisters) {
    saved_gp_regs.set(gp_param_reg);
  }

  // The instance data has already been stored in the fixed part of the frame.
  saved_gp_regs.clear(kWasmImplicitArgRegister);
  // All set registers were unique.
  CHECK_EQ(saved_gp_regs.Count(), arraysize(wasm::kGpParamRegisters) - 1);
  CHECK_EQ(WasmLiftoffSetupFrameConstants::kNumberOfSavedGpParamRegs,
           saved_gp_regs.Count());
  return saved_gp_regs;
})();

constexpr DoubleRegList kSavedFpRegs = ([]() constexpr {
  DoubleRegList saved_fp_regs;
  for (DoubleRegister fp_param_reg : wasm::kFpParamRegisters) {
    saved_fp_regs.set(fp_param_reg);
  }

  CHECK_EQ(saved_fp_regs.Count(), arraysize(wasm::kFpParamRegisters));
  CHECK_EQ(WasmLiftoffSetupFrameConstants::kNumberOfSavedFpParamRegs,
           saved_fp_regs.Count());
  return saved_fp_regs;
})();

// When entering this builtin, we have just created a Wasm stack frame:
//
// [ Wasm instance data ]  <-- sp
// [ WASM frame marker  ]
// [     saved fp       ]  <-- fp
//
// Add the feedback vector to the stack.
//
// [  feedback vector   ]  <-- sp
// [ Wasm instance data ]
// [ WASM frame marker  ]
// [     saved fp       ]  <-- fp
void Builtins::Generate_WasmLiftoffFrameSetup(MacroAssembler* masm) {
  Register func_index = wasm::kLiftoffFrameSetupFunctionReg;
  Register vector = t1;
  Register scratch = t2;
  Label allocate_vector, done;

  __ LoadTaggedField(
      vector, FieldMemOperand(kWasmImplicitArgRegister,
                              WasmTrustedInstanceData::kFeedbackVectorsOffset));
  __ Alsl_d(vector, func_index, vector, kTaggedSizeLog2);
  __ LoadTaggedField(vector,
                     FieldMemOperand(vector, OFFSET_OF_DATA_START(FixedArray)));
  __ JumpIfSmi(vector, &allocate_vector);
  __ bind(&done);
  __ Push(vector);
  __ Ret();

  __ bind(&allocate_vector);
  // Feedback vector doesn't exist yet. Call the runtime to allocate it.
  // We temporarily change the frame type for this, because we need special
  // handling by the stack walker in case of GC.
  __ li(scratch, StackFrame::TypeToMarker(StackFrame::WASM_LIFTOFF_SETUP));
  __ St_d(scratch, MemOperand(fp, TypedFrameConstants::kFrameTypeOffset));

  // Save registers.
  __ MultiPush(kSavedGpRegs);
  __ MultiPushFPU(kSavedFpRegs);
  __ Push(ra);

  // Arguments to the runtime function: instance data, func_index, and an
  // additional stack slot for the NativeModule.
  __ SmiTag(func_index);
  __ Push(kWasmImplicitArgRegister, func_index, zero_reg);
  __ Move(cp, Smi::zero());
  __ CallRuntime(Runtime::kWasmAllocateFeedbackVector, 3);
  __ mov(vector, kReturnRegister0);

  // Restore registers and frame type.
  __ Pop(ra);
  __ MultiPopFPU(kSavedFpRegs);
  __ MultiPop(kSavedGpRegs);
  __ Ld_d(kWasmImplicitArgRegister,
          MemOperand(fp, WasmFrameConstants::kWasmInstanceDataOffset));
  __ li(scratch, StackFrame::TypeToMarker(StackFrame::WASM));
  __ St_d(scratch, MemOperand(fp, TypedFrameConstants::kFrameTypeOffset));
  __ Branch(&done);
}

void Builtins::Generate_WasmCompileLazy(MacroAssembler* masm) {
  // The function index was put in t0 by the jump table trampoline.
  // Convert to Smi for the runtime call
  __ SmiTag(kWasmCompileLazyFuncIndexRegister);

  {
    HardAbortScope hard_abort(masm);  // Avoid calls to Abort.
    FrameScope scope(masm, StackFrame::INTERNAL);

    // Save registers that we need to keep alive across the runtime call.
    __ Push(kWasmImplicitArgRegister);
    __ MultiPush(kSavedGpRegs);
    __ MultiPushFPU(kSavedFpRegs);

    // kFixedFrameSizeFromFp is hard coded to include space for Simd
    // registers, so we still need to allocate extra (unused) space on the stack
    // as if they were saved.
    __ Sub_d(sp, sp, kSavedFpRegs.Count() * kDoubleSize);

    __ Push(kWasmImplicitArgRegister, kWasmCompileLazyFuncIndexRegister);

    // Initialize the JavaScript context with 0. CEntry will use it to
    // set the current context on the isolate.
    __ Move(kContextRegister, Smi::zero());
    __ CallRuntime(Runtime::kWasmCompileLazy, 2);

    // Untag the returned Smi into into t7, for later use.
    static_assert(!kSavedGpRegs.has(t7));
    __ SmiUntag(t7, a0);

    __ Add_d(sp, sp, kSavedFpRegs.Count() * kDoubleSize);
    // Restore registers.
    __ MultiPopFPU(kSavedFpRegs);
    __ MultiPop(kSavedGpRegs);
    __ Pop(kWasmImplicitArgRegister);
  }

  // The runtime function returned the jump table slot offset as a Smi (now in
  // t7). Use that to compute the jump target.
  static_assert(!kSavedGpRegs.has(t8));
  __ Ld_d(t8, FieldMemOperand(kWasmImplicitArgRegister,
                              WasmTrustedInstanceData::kJumpTableStartOffset));
  __ Add_d(t7, t8, Operand(t7));

  // Finally, jump to the jump table slot for the function.
  __ Jump(t7);
}

void Builtins::Generate_WasmDebugBreak(MacroAssembler* masm) {
  HardAbortScope hard_abort(masm);  // Avoid calls to Abort.
  {
    FrameScope scope(masm, StackFrame::WASM_DEBUG_BREAK);

    // Save all parameter registers. They might hold live values, we restore
    // them after the runtime call.
    __ MultiPush(WasmDebugBreakFrameConstants::kPushedGpRegs);
    __ MultiPushFPU(WasmDebugBreakFrameConstants::kPushedFpRegs);

    // Initialize the JavaScript context with 0. CEntry will use it to
    // set the current context on the isolate.
    __ Move(cp, Smi::zero());
    __ CallRuntime(Runtime::kWasmDebugBreak, 0);

    // Restore registers.
    __ MultiPopFPU(WasmDebugBreakFrameConstants::kPushedFpRegs);
    __ MultiPop(WasmDebugBreakFrameConstants::kPushedGpRegs);
  }
  __ Ret();
}

namespace {
// Check that the stack was in the old state (if generated code assertions are
// enabled), and switch to the new state.
void SwitchStackState(MacroAssembler* masm, Register jmpbuf, Register tmp,
                      wasm::JumpBuffer::StackState old_state,
                      wasm::JumpBuffer::StackState new_state) {
#if V8_ENABLE_SANDBOX
  __ Ld_w(tmp, MemOperand(jmpbuf, wasm::kJmpBufStateOffset));
  Label ok;
  __ JumpIfEqual(tmp, old_state, &ok);
  __ Trap();
  __ bind(&ok);
#endif
  __ li(tmp, Operand(new_state));
  __ St_w(tmp, MemOperand(jmpbuf, wasm::kJmpBufStateOffset));
}

// Switch the stack pointer.
void SwitchStackPointer(MacroAssembler* masm, Register jmpbuf) {
  __ Ld_d(sp, MemOperand(jmpbuf, wasm::kJmpBufSpOffset));
}

void FillJumpBuffer(MacroAssembler* masm, Register jmpbuf, Label* target,
                    Register tmp) {
  __ mov(tmp, sp);
  __ St_d(tmp, MemOperand(jmpbuf, wasm::kJmpBufSpOffset));
  __ St_d(fp, MemOperand(jmpbuf, wasm::kJmpBufFpOffset));
  __ LoadStackLimit(tmp, __ StackLimitKind::kRealStackLimit);
  __ St_d(tmp, MemOperand(jmpbuf, wasm::kJmpBufStackLimitOffset));

  __ LoadLabelRelative(tmp, target);
  // Stash the address in the jump buffer.
  __ St_d(tmp, MemOperand(jmpbuf, wasm::kJmpBufPcOffset));
}

void LoadJumpBuffer(MacroAssembler* masm, Register jmpbuf, bool load_pc,
                    Register tmp, wasm::JumpBuffer::StackState expected_state) {
  SwitchStackPointer(masm, jmpbuf);
  __ Ld_d(fp, MemOperand(jmpbuf, wasm::kJmpBufFpOffset));
  SwitchStackState(masm, jmpbuf, tmp, expected_state, wasm::JumpBuffer::Active);
  if (load_pc) {
    __ Ld_d(tmp, MemOperand(jmpbuf, wasm::kJmpBufPcOffset));
    __ Jump(tmp);
  }
  // The stack limit in StackGuard is set separately under the ExecutionAccess
  // lock.
}

void SaveState(MacroAssembler* masm, Register active_continuation, Register tmp,
               Label* suspend) {
  Register jmpbuf = tmp;
  __ LoadExternalPointerField(
      jmpbuf,
      FieldMemOperand(active_continuation,
                      WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag);

  UseScratchRegisterScope temps(masm);
  FillJumpBuffer(masm, jmpbuf, suspend, temps.Acquire());
}

void LoadTargetJumpBuffer(MacroAssembler* masm, Register target_continuation,
                          Register tmp,
                          wasm::JumpBuffer::StackState expected_state) {
  Register target_jmpbuf = target_continuation;
  __ LoadExternalPointerField(
      target_jmpbuf,
      FieldMemOperand(target_continuation,
                      WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag);

  __ St_d(zero_reg,
          MemOperand(fp, StackSwitchFrameConstants::kGCScanSlotCountOffset));
  // Switch stack!
  LoadJumpBuffer(masm, target_jmpbuf, false, tmp, expected_state);
}

// Updates the stack limit to match the new active stack.
// Pass the {finished_continuation} argument to indicate that the stack that we
// are switching from has returned, and in this case return its memory to the
// stack pool.
void SwitchStacks(MacroAssembler* masm, Register finished_continuation,
                  const Register& keep1, const Register& keep2 = no_reg,
                  const Register& keep3 = no_reg) {
  using ER = ExternalReference;

  __ Push(keep1);
  if (keep2 != no_reg) {
    __ Push(keep2);
  }
  if (keep3 != no_reg) {
    __ Push(keep3);
  }

  if (finished_continuation != no_reg) {
    __ PrepareCallCFunction(2, a0);
    FrameScope scope(masm, StackFrame::MANUAL);
    __ li(kCArgRegs[0], ExternalReference::isolate_address(masm->isolate()));
    __ mov(kCArgRegs[1], finished_continuation);
    __ CallCFunction(ER::wasm_return_switch(), 2);
  } else {
    __ PrepareCallCFunction(1, a0);
    FrameScope scope(masm, StackFrame::MANUAL);
    __ li(kCArgRegs[0], ER::isolate_address(masm->isolate()));
    __ CallCFunction(ER::wasm_sync_stack_limit(), 1);
  }

  if (keep3 != no_reg) {
    __ Pop(keep3);
  }
  if (keep2 != no_reg) {
    __ Pop(keep2);
  }
  __ Pop(keep1);
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
  __ St_d(zero_reg, MemOperand(jmpbuf, wasm::kJmpBufSpOffset));
  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
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
  __ St_d(parent, MemOperand(kRootRegister, active_continuation_offset));
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
  __ li(tmp2, Operand(Smi::FromInt(WasmSuspenderObject::kInactive)));
  __ StoreTaggedField(tmp2, state_loc);
  __ LoadTaggedField(
      suspender,
      FieldMemOperand(suspender, WasmSuspenderObject::kParentOffset));

  Label undefined;
  __ JumpIfRoot(suspender, RootIndex::kUndefinedValue, &undefined);

  if (v8_flags.debug_code) {
    // Check that the parent suspender is active.
    Label parent_inactive;
    Register state = tmp2;
    __ SmiUntag(state, state_loc);
    __ JumpIfEqual(state, WasmSuspenderObject::kActive, &parent_inactive);
    __ Trap();
    __ bind(&parent_inactive);
  }
  __ li(tmp2, Operand(Smi::FromInt(WasmSuspenderObject::kActive)));
  __ StoreTaggedField(tmp2, state_loc);
  __ bind(&undefined);
  int32_t active_suspender_offset =
      MacroAssembler::RootRegisterOffsetForRootIndex(
          RootIndex::kActiveSuspender);
  __ St_d(suspender, MemOperand(kRootRegister, active_suspender_offset));
}

void ResetStackSwitchFrameStackSlots(MacroAssembler* masm) {
  __ St_d(zero_reg,
          MemOperand(fp, StackSwitchFrameConstants::kResultArrayOffset));
  __ St_d(zero_reg,
          MemOperand(fp, StackSwitchFrameConstants::kImplicitArgOffset));
}

// TODO(irezvov): Consolidate with arm64 RegisterAllocator.
class RegisterAllocator {
 public:
  class Scoped {
   public:
    Scoped(RegisterAllocator* allocator, Register* reg)
        : allocator_(allocator), reg_(reg) {}
    ~Scoped() { allocator_->Free(reg_); }

   private:
    RegisterAllocator* allocator_;
    Register* reg_;
  };

  explicit RegisterAllocator(const RegList& registers)
      : initial_(registers), available_(registers) {}
  void Ask(Register* reg) {
    DCHECK_EQ(*reg, no_reg);
    DCHECK(!available_.is_empty());
    *reg = available_.PopFirst();
    allocated_registers_.push_back(reg);
  }

  bool registerIsAvailable(const Register& reg) { return available_.has(reg); }

  void Pinned(const Register& requested, Register* reg) {
    if (!registerIsAvailable(requested)) {
      printf("%s register is ocupied!", RegisterName(requested));
    }
    DCHECK(registerIsAvailable(requested));
    *reg = requested;
    Reserve(requested);
    allocated_registers_.push_back(reg);
  }

  void Free(Register* reg) {
    DCHECK_NE(*reg, no_reg);
    available_.set(*reg);
    *reg = no_reg;
    allocated_registers_.erase(
        find(allocated_registers_.begin(), allocated_registers_.end(), reg));
  }

  void Reserve(const Register& reg) {
    if (reg == no_reg) {
      return;
    }
    DCHECK(registerIsAvailable(reg));
    available_.clear(reg);
  }

  void Reserve(const Register& reg1, const Register& reg2,
               const Register& reg3 = no_reg, const Register& reg4 = no_reg,
               const Register& reg5 = no_reg, const Register& reg6 = no_reg) {
    Reserve(reg1);
    Reserve(reg2);
    Reserve(reg3);
    Reserve(reg4);
    Reserve(reg5);
    Reserve(reg6);
  }

  bool IsUsed(const Register& reg) {
    return initial_.has(reg) && !registerIsAvailable(reg);
  }

  void ResetExcept(const Register& reg1 = no_reg, const Register& reg2 = no_reg,
                   const Register& reg3 = no_reg, const Register& reg4 = no_reg,
                   const Register& reg5 = no_reg,
                   const Register& reg6 = no_reg) {
    available_ = initial_;
    available_.clear(reg1);
    available_.clear(reg2);
    available_.clear(reg3);
    available_.clear(reg4);
    available_.clear(reg5);
    available_.clear(reg6);

    auto it = allocated_registers_.begin();
    while (it != allocated_registers_.end()) {
      if (registerIsAvailable(**it)) {
        **it = no_reg;
        allocated_registers_.erase(it);
      } else {
        it++;
      }
    }
  }

  static RegisterAllocator WithAllocatableGeneralRegisters() {
    RegList list;
    const RegisterConfiguration* config(RegisterConfiguration::Default());

    for (int i = 0; i < config->num_allocatable_general_registers(); ++i) {
      int code = config->GetAllocatableGeneralCode(i);
      Register candidate = Register::from_code(code);
      list.set(candidate);
    }
    return RegisterAllocator(list);
  }

 private:
  std::vector<Register*> allocated_registers_;
  const RegList initial_;
  RegList available_;
};

#define DEFINE_REG(Name)  \
  Register Name = no_reg; \
  regs.Ask(&Name);

#define DEFINE_REG_W(Name) \
  DEFINE_REG(Name);        \
  Name = Name.W();

#define ASSIGN_REG(Name) regs.Ask(&Name);

#define ASSIGN_REG_W(Name) \
  ASSIGN_REG(Name);        \
  Name = Name.W();

#define DEFINE_PINNED(Name, Reg) \
  Register Name = no_reg;        \
  regs.Pinned(Reg, &Name);

#define ASSIGN_PINNED(Name, Reg) regs.Pinned(Reg, &Name);

#define DEFINE_SCOPED(Name) \
  DEFINE_REG(Name)          \
  RegisterAllocator::Scoped scope_##Name(&regs, &Name);

#define FREE_REG(Name) regs.Free(&Name);

// Loads the context field of the WasmTrustedInstanceData or WasmImportData
// depending on the data's type, and places the result in the input register.
void GetContextFromImplicitArg(MacroAssembler* masm, Register data,
                               Register scratch) {
  Label instance;
  Label end;
  __ LoadTaggedField(scratch, FieldMemOperand(data, HeapObject::kMapOffset));
  __ Ld_hu(scratch, FieldMemOperand(scratch, Map::kInstanceTypeOffset));
  __ Branch(&instance, eq, scratch, Operand(WASM_TRUSTED_INSTANCE_DATA_TYPE));

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
  constexpr int cnt_fp = arraysize(wasm::kFpParamRegisters);
  constexpr int cnt_gp = arraysize(wasm::kGpParamRegisters) - 1;
  int required_stack_space = cnt_fp * kDoubleSize + cnt_gp * kSystemPointerSize;
  __ Sub_d(sp, sp, Operand(required_stack_space));
  for (int i = cnt_fp - 1; i >= 0; i--) {
    __ Fst_d(wasm::kFpParamRegisters[i],
             MemOperand(sp, i * kDoubleSize + cnt_gp * kSystemPointerSize));
  }

  // Without wasm::kGpParamRegisters[0] here.
  for (int i = cnt_gp; i >= 1; i--) {
    __ St_d(wasm::kGpParamRegisters[i],
            MemOperand(sp, (i - 1) * kSystemPointerSize));
  }
  // Reserve a slot for the signature.
  __ Push(zero_reg);
  __ TailCallBuiltin(Builtin::kWasmToJsWrapperCSA);
}

void Builtins::Generate_WasmTrapHandlerLandingPad(MacroAssembler* masm) {
  // This builtin gets called from the WebAssembly trap handler when an
  // out-of-bounds memory access happened or when a null reference gets
  // dereferenced. This builtin then fakes a call from the instruction that
  // triggered the signal to the runtime. This is done by setting a return
  // address and then jumping to a builtin which will call further to the
  // runtime.
  // As the return address we use the fault address + 1. Using the fault address
  // itself would cause problems with safepoints and source positions.
  //
  // The problem with safepoints is that a safepoint has to be registered at the
  // return address, and that at most one safepoint should be registered at a
  // location. However, there could already be a safepoint registered at the
  // fault address if the fault address is the return address of a call.
  //
  // The problem with source positions is that the stack trace code looks for
  // the source position of a call before the return address. The source
  // position of the faulty memory access, however, is recorded at the fault
  // address. Therefore the stack trace code would not find the source position
  // if we used the fault address as the return address.
  __ Add_d(ra, kWasmTrapHandlerFaultAddressRegister, 1);
  __ TailCallBuiltin(Builtin::kWasmTrapHandlerThrowTrap);
}

void Builtins::Generate_WasmSuspend(MacroAssembler* masm) {
  auto regs = RegisterAllocator::WithAllocatableGeneralRegisters();
  // Set up the stackframe.
  __ EnterFrame(StackFrame::STACK_SWITCH);

  DEFINE_PINNED(suspender, a0);
  DEFINE_PINNED(context, kContextRegister);

  __ Sub_d(
      sp, sp,
      Operand(StackSwitchFrameConstants::kNumSpillSlots * kSystemPointerSize));
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
  __ li(scratch, Operand(Smi::FromInt(WasmSuspenderObject::kSuspended)));
  __ StoreTaggedField(
      scratch, FieldMemOperand(suspender, WasmSuspenderObject::kStateOffset));
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
    Label ok;
    __ Branch(&ok, eq, suspender_continuation, Operand(continuation));
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
  __ St_d(caller, MemOperand(kRootRegister, active_continuation_offset));
  DEFINE_REG(parent);
  __ LoadTaggedField(
      parent, FieldMemOperand(suspender, WasmSuspenderObject::kParentOffset));
  int32_t active_suspender_offset =
      MacroAssembler::RootRegisterOffsetForRootIndex(
          RootIndex::kActiveSuspender);
  __ St_d(parent, MemOperand(kRootRegister, active_suspender_offset));
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
  __ St_d(zero_reg, GCScanSlotPlace);
  ASSIGN_REG(scratch)
  LoadJumpBuffer(masm, jmpbuf, true, scratch, wasm::JumpBuffer::Inactive);
  __ Trap();
  __ bind(&resume);
  __ LeaveFrame(StackFrame::STACK_SWITCH);
  __ Ret();
}

namespace {
// Resume the suspender stored in the closure. We generate two variants of this
// builtin: the onFulfilled variant resumes execution at the saved PC and
// forwards the value, the onRejected variant throws the value.

void Generate_WasmResumeHelper(MacroAssembler* masm, wasm::OnResume on_resume) {
  auto regs = RegisterAllocator::WithAllocatableGeneralRegisters();
  __ EnterFrame(StackFrame::STACK_SWITCH);

  DEFINE_PINNED(closure, kJSFunctionRegister);  // a1

  __ Sub_d(
      sp, sp,
      Operand(StackSwitchFrameConstants::kNumSpillSlots * kSystemPointerSize));
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
  __ LoadTaggedField(
      suspender,
      FieldMemOperand(resume_data, WasmResumeData::kSuspenderOffset));
  // Check the suspender state.
  Label suspender_is_suspended;
  DEFINE_REG(state);
  __ SmiUntag(state,
              FieldMemOperand(suspender, WasmSuspenderObject::kStateOffset));
  __ JumpIfEqual(state, WasmSuspenderObject::kSuspended,
                 &suspender_is_suspended);
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
                      active_suspender, kRAHasBeenSaved,
                      SaveFPRegsMode::kIgnore);
  __ li(scratch, Operand(Smi::FromInt(WasmSuspenderObject::kActive)));
  __
```