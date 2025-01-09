Response:
The user wants a summary of the functionality of the provided C++ code snippet. The code is part of the V8 JavaScript engine and is located in the `v8/src/builtins/arm/builtins-arm.cc` file.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Language:** The code is C++ for the V8 engine. The user explicitly asks if it were Torque code, but since it isn't `.tq`, that part of the question is irrelevant for this snippet.

2. **Core Functionality Identification:**  Scan the code for the primary functions defined. The names `Generate_Construct`, `Generate_WasmLiftoffFrameSetup`, `Generate_WasmCompileLazy`, `Generate_WasmDebugBreak`, `Generate_WasmToJsWrapperAsm`, `Generate_WasmTrapHandlerLandingPad`, `Generate_WasmSuspend`, `Generate_WasmResume`, `Generate_WasmReject`, and `Generate_WasmOnStackReplace` immediately stand out. The prefix `Generate_` suggests these functions are responsible for generating assembly code for specific built-in functionalities.

3. **Categorize Functionality:** Group the identified functions into logical categories based on their names and operations:
    * **Constructor Handling:** `Generate_Construct`, `Generate_ConstructBoundFunction` (although not explicitly a standalone function, it's called within `Generate_Construct`).
    * **WebAssembly (Wasm) Specific:**  `Generate_WasmLiftoffFrameSetup`, `Generate_WasmCompileLazy`, `Generate_WasmDebugBreak`, `Generate_WasmToJsWrapperAsm`, `Generate_WasmTrapHandlerLandingPad`, `Generate_WasmSuspend`, `Generate_WasmResume`, `Generate_WasmReject`, `Generate_WasmOnStackReplace`. The `wasm::` namespace usage reinforces this.
    * **Helper Functions:** The anonymous namespace contains utility functions related to WebAssembly continuations and stack manipulation.

4. **Describe Each Category:** Summarize the purpose of each category:
    * **Constructor Handling:** Deals with the `new` operator, checking if an object is a constructor, and handling different constructor types (JSFunctions, Bound Functions, Proxies).
    * **WebAssembly:**  Focuses on various aspects of WebAssembly execution, including setting up frames, lazy compilation, debugging, interactions between Wasm and JavaScript, handling traps (errors), and support for asynchronous operations (suspending and resuming execution).

5. **JavaScript Relevance:** Determine if the code relates to JavaScript features. `Generate_Construct` directly implements the semantics of the `new` operator in JavaScript. The Wasm-related functions enable the execution of WebAssembly code within a JavaScript environment, which is a crucial JavaScript capability.

6. **JavaScript Examples:** For `Generate_Construct`, provide a basic JavaScript example demonstrating the `new` operator and different constructor types.

7. **Code Logic Inference (Hypothetical Input/Output):** Focus on `Generate_Construct` as it has a clear control flow.
    * **Input:** A JavaScript function object (constructor) and arguments.
    * **Output:** A new object instance.
    * **Edge Cases:**  Demonstrate what happens when a non-constructor is used with `new`.

8. **Common Programming Errors:**  Connect the code to potential user errors. Using `new` on a non-constructor is a common mistake that `Generate_Construct` handles.

9. **Torque Check:** Reiterate that the file is C++, not Torque, as per the user's conditional question.

10. **Part Number and Overall Functionality:** Acknowledge the "part 4 of 6" and provide a high-level summary of the entire file's purpose, connecting the individual functionalities.

11. **Structure and Refine:** Organize the information logically with clear headings and bullet points for readability. Ensure the language is clear and concise.

**(Self-Correction/Refinement during the process):**

* Initially, I might have just listed all the `Generate_` functions without grouping. However, recognizing the `Wasm` prefix allows for better categorization.
* The user asked about `.tq`, so even though the answer is "no", it's important to explicitly address that part of the question.
*  For the code logic inference, I initially considered multiple Wasm functions, but `Generate_Construct` provides a more straightforward example of control flow within the given snippet.
* The common error example should directly relate to the code being analyzed, making the `new` on a non-constructor scenario ideal.
这是 `v8/src/builtins/arm/builtins-arm.cc` 源代码的第 4 部分（共 6 部分）。这个文件包含了 ARM 架构下 V8 引擎内置函数的汇编代码实现。以下是其功能的归纳和详细说明：

**核心功能归纳：**

这个代码片段主要负责以下功能：

1. **构造函数调用 (`Construct`):**  实现了 JavaScript 中 `new` 运算符的核心逻辑，包括检查目标是否为构造函数，并根据不同的构造函数类型（普通函数、绑定函数、代理对象）调用相应的构建流程。
2. **WebAssembly (Wasm) 支持:** 包含了一系列用于支持 WebAssembly 代码执行的关键内置函数，涵盖了从框架设置、懒加载编译、调试断点到与 JavaScript 交互以及实现异步操作（挂起和恢复）。

**详细功能列举：**

* **`Generate_ConstructBoundFunction(MacroAssembler* masm)`:**  处理 `new` 运算符调用绑定函数的情况。它会提取绑定函数的元信息（目标函数和绑定参数）并调用目标函数的构造函数。
* **`Generate_Construct(MacroAssembler* masm)`:**  实现通用的构造函数调用逻辑。
    * 检查目标是否为 Smi (立即数)，如果不是，则继续判断是否为构造函数。
    * 检查目标对象是否具有 `[[Construct]]` 内部方法，即是否为构造函数。
    * 根据对象的类型（JSFunction, JSBoundFunction, JSProxy）分发到不同的构建流程：
        * `Builtin::kConstructFunction`: 构建普通的 JavaScript 函数实例。
        * `Builtin::kConstructBoundFunction`: 构建绑定函数实例。
        * `Builtin::kConstructProxy`: 构建代理对象实例。
    * 如果目标对象有 `[[Construct]]` 方法但不是上述类型，则调用 `call_as_constructor_delegate` 来处理。
    * 如果目标对象没有 `[[Construct]]` 方法，则抛出异常 (`Builtin::kConstructedNonConstructable`)。
* **WebAssembly 相关函数 (以 `Generate_Wasm` 开头):**
    * **`Generate_WasmLiftoffFrameSetup(MacroAssembler* masm)`:** 为 WebAssembly Liftoff 编译的函数设置栈帧，包括保存反馈向量和实例数据。
    * **`Generate_WasmCompileLazy(MacroAssembler* masm)`:**  实现 WebAssembly 函数的懒加载编译。当首次调用某个 WebAssembly 函数时，会调用此内置函数来触发编译。
    * **`Generate_WasmDebugBreak(MacroAssembler* masm)`:**  处理 WebAssembly 代码中的调试断点。
    * **`Generate_WasmToJsWrapperAsm(MacroAssembler* masm)`:**  生成从 WebAssembly 调用到 JavaScript 的包装器函数的汇编代码。用于将 WebAssembly 函数的调用转换为符合 JavaScript 调用约定的形式。
    * **`Generate_WasmTrapHandlerLandingPad(MacroAssembler* masm)`:**  WebAssembly 陷阱处理程序的入口点。当 WebAssembly 代码发生运行时错误（例如除零）时，会跳转到这里。
    * **`Generate_WasmSuspend(MacroAssembler* masm)`:**  实现 WebAssembly 的挂起操作，用于支持异步操作。它会保存当前执行状态并切换到另一个栈。
    * **`Generate_WasmResume(MacroAssembler* masm)`:**  实现 WebAssembly 的恢复操作，与 `Generate_WasmSuspend` 配对使用，用于恢复之前挂起的执行。
    * **`Generate_WasmReject(MacroAssembler* masm)`:**  类似于 `Generate_WasmResume`，但在恢复时会抛出一个错误。
    * **`Generate_WasmOnStackReplace(MacroAssembler* masm)`:**  通常用于在调试或优化过程中替换栈上的代码，在这个 ARM 版本中似乎还没有实现（`__ Trap()`）。
* **匿名命名空间中的辅助函数:** 这些函数主要用于支持 WebAssembly 的挂起和恢复功能，例如：
    * `SwitchStackState`, `SwitchStackPointer`, `FillJumpBuffer`, `LoadJumpBuffer`: 用于管理和切换 WebAssembly 的栈状态和栈指针。
    * `SaveState`, `LoadTargetJumpBuffer`, `SwitchStacks`: 用于保存和加载 WebAssembly 执行上下文，以及进行栈切换。
    * `ReloadParentContinuation`, `RestoreParentSuspender`: 用于在 WebAssembly 挂起和恢复过程中更新 continuation 和 suspender 的状态。
    * `ResetStackSwitchFrameStackSlots`: 用于重置栈切换帧的槽位。
    * `RegisterAllocator`: 一个简单的寄存器分配器，用于在生成汇编代码时管理寄存器的使用。
    * `GetContextFromImplicitArg`: 从 Wasm 实例或导入数据中获取上下文信息。

**如果 `v8/src/builtins/arm/builtins-arm.cc` 以 `.tq` 结尾：**

如果文件以 `.tq` 结尾，那么它将是一个 **Torque** 源代码文件。Torque 是 V8 用来定义内置函数的一种领域特定语言，它允许以更高级、更类型安全的方式描述内置函数的行为，然后由 Torque 编译器生成 C++ 代码（以及可能的汇编代码）。 当前情况下，该文件是 `.cc` 文件，所以它是直接编写的 C++ 代码，其中内嵌了汇编指令。

**与 JavaScript 功能的关系及示例：**

这些内置函数直接支撑着 JavaScript 的核心功能和 WebAssembly 的执行。

* **`Generate_Construct` 对应 JavaScript 的 `new` 运算符：**

```javascript
function MyClass(value) {
  this.value = value;
}

const instance = new MyClass(10);
console.log(instance.value); // 输出 10
```

在这个例子中，`new MyClass(10)` 的操作最终会调用到 V8 引擎中 `Generate_Construct` 及其相关的内置函数。

* **WebAssembly 相关函数对应 JavaScript 中对 WebAssembly 模块的使用：**

```javascript
async function loadAndRunWasm() {
  const response = await fetch('my_wasm_module.wasm');
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer);
  const instance = await WebAssembly.instantiate(module);
  const result = instance.exports.myFunction(1, 2);
  console.log(result);
}

loadAndRunWasm();
```

当 JavaScript 代码加载、编译和实例化 WebAssembly 模块并调用其导出的函数时，会涉及到 `Generate_WasmLiftoffFrameSetup`, `Generate_WasmCompileLazy`, `Generate_WasmToJsWrapperAsm` 等内置函数。

* **`Generate_WasmSuspend` 和 `Generate_WasmResume` 对应 JavaScript 中使用 `async/await` 与 WebAssembly 的异步交互 (如果 Wasm 模块支持 Continuations proposal):**

虽然当前的 WebAssembly 标准对直接的挂起和恢复支持有限，但如果使用了 Continuations proposal，并且 WebAssembly 模块实现了相应的挂起逻辑，那么 JavaScript 的 `async/await` 可以与 WebAssembly 的挂起和恢复机制进行交互。

**代码逻辑推理（假设输入与输出）：**

以 `Generate_Construct` 为例：

**假设输入：**

* `r0`: 参数数量，例如 1
* `r1`:  指向 `MyClass` 函数对象的指针 (一个 JSFunction)。
* `r3`:  指向 `MyClass` 函数对象的指针 (作为 new.target)。

**预期输出：**

* 在堆上分配一个新的 `MyClass` 实例对象。
* 调用 `MyClass` 函数，并将新创建的对象作为 `this` 绑定。
* 返回新创建的实例对象的指针。

**代码逻辑推理：**

1. 代码首先检查 `r1` 是否为 Smi。
2. 然后检查 `r1` 指向的对象是否具有构造函数的特征（通过检查其 Map 的标志位）。
3. 由于 `r1` 指向的是一个 JSFunction，代码会跳转到 `Builtin::kConstructFunction` 内置函数，该函数负责创建和初始化 JSFunction 的实例。

**涉及用户常见的编程错误及示例：**

* **尝试使用 `new` 运算符调用非构造函数：**

```javascript
const notAConstructor = {};
try {
  const instance = new notAConstructor(); // TypeError: notAConstructor is not a constructor
} catch (e) {
  console.error(e);
}
```

在这种情况下，`Generate_Construct` 中的检查会发现 `notAConstructor` 没有 `[[Construct]]` 方法，最终会调用 `Builtin::kConstructedNonConstructable` 抛出 `TypeError`。

* **在 WebAssembly 中不正确地处理异步操作或陷阱：**

如果 WebAssembly 代码可能抛出异常（陷阱），但 JavaScript 没有正确处理，或者 WebAssembly 的异步操作（如果使用 Continuations）没有与 JavaScript 的 `Promise` 或 `async/await` 正确集成，就可能导致程序崩溃或行为异常。 `Generate_WasmTrapHandlerLandingPad` 和 `Generate_WasmSuspend`/`Generate_WasmResume` 就是为了处理这些情况。

**总结：**

这个代码片段是 V8 引擎在 ARM 架构上实现 JavaScript 构造函数调用和 WebAssembly 支持的关键组成部分。它包含了处理对象创建、类型检查、方法分发以及与 WebAssembly 运行时交互的底层汇编代码逻辑。这些内置函数对于保证 JavaScript 语言的正确性和 WebAssembly 代码的高效执行至关重要。

Prompt: 
```
这是目录为v8/src/builtins/arm/builtins-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/arm/builtins-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能

"""
tor)
  // -----------------------------------
  __ AssertConstructor(r1);
  __ AssertBoundFunction(r1);

  // Push the [[BoundArguments]] onto the stack.
  Generate_PushBoundArguments(masm);

  // Patch new.target to [[BoundTargetFunction]] if new.target equals target.
  __ cmp(r1, r3);
  __ ldr(r3, FieldMemOperand(r1, JSBoundFunction::kBoundTargetFunctionOffset),
         eq);

  // Construct the [[BoundTargetFunction]] via the Construct builtin.
  __ ldr(r1, FieldMemOperand(r1, JSBoundFunction::kBoundTargetFunctionOffset));
  __ TailCallBuiltin(Builtin::kConstruct);
}

// static
void Builtins::Generate_Construct(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r0 : the number of arguments
  //  -- r1 : the constructor to call (can be any Object)
  //  -- r3 : the new target (either the same as the constructor or
  //          the JSFunction on which new was invoked initially)
  // -----------------------------------
  Register target = r1;
  Register map = r4;
  Register instance_type = r5;
  Register scratch = r6;
  DCHECK(!AreAliased(r0, target, map, instance_type, scratch));

  // Check if target is a Smi.
  Label non_constructor, non_proxy;
  __ JumpIfSmi(target, &non_constructor);

  // Check if target has a [[Construct]] internal method.
  __ ldr(map, FieldMemOperand(target, HeapObject::kMapOffset));
  {
    Register flags = r2;
    DCHECK(!AreAliased(r0, target, map, instance_type, flags));
    __ ldrb(flags, FieldMemOperand(map, Map::kBitFieldOffset));
    __ tst(flags, Operand(Map::Bits1::IsConstructorBit::kMask));
    __ b(eq, &non_constructor);
  }

  // Dispatch based on instance type.
  __ CompareInstanceTypeRange(map, instance_type, scratch,
                              FIRST_JS_FUNCTION_TYPE, LAST_JS_FUNCTION_TYPE);
  __ TailCallBuiltin(Builtin::kConstructFunction, ls);

  // Only dispatch to bound functions after checking whether they are
  // constructors.
  __ cmp(instance_type, Operand(JS_BOUND_FUNCTION_TYPE));
  __ TailCallBuiltin(Builtin::kConstructBoundFunction, eq);

  // Only dispatch to proxies after checking whether they are constructors.
  __ cmp(instance_type, Operand(JS_PROXY_TYPE));
  __ b(ne, &non_proxy);
  __ TailCallBuiltin(Builtin::kConstructProxy);

  // Called Construct on an exotic Object with a [[Construct]] internal method.
  __ bind(&non_proxy);
  {
    // Overwrite the original receiver with the (original) target.
    __ str(target, __ ReceiverOperand());
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

struct SaveWasmParamsScope {
  explicit SaveWasmParamsScope(MacroAssembler* masm)
      : lowest_fp_reg(std::begin(wasm::kFpParamRegisters)[0]),
        highest_fp_reg(std::end(wasm::kFpParamRegisters)[-1]),
        masm(masm) {
    for (Register gp_param_reg : wasm::kGpParamRegisters) {
      gp_regs.set(gp_param_reg);
    }
    gp_regs.set(lr);
    for (DwVfpRegister fp_param_reg : wasm::kFpParamRegisters) {
      CHECK(fp_param_reg.code() >= lowest_fp_reg.code() &&
            fp_param_reg.code() <= highest_fp_reg.code());
    }

    CHECK_EQ(gp_regs.Count(), arraysize(wasm::kGpParamRegisters) + 1);
    CHECK_EQ(highest_fp_reg.code() - lowest_fp_reg.code() + 1,
             arraysize(wasm::kFpParamRegisters));
    CHECK_EQ(gp_regs.Count(),
             WasmLiftoffSetupFrameConstants::kNumberOfSavedGpParamRegs +
                 1 /* instance */ + 1 /* lr */);
    CHECK_EQ(highest_fp_reg.code() - lowest_fp_reg.code() + 1,
             WasmLiftoffSetupFrameConstants::kNumberOfSavedFpParamRegs);

    __ stm(db_w, sp, gp_regs);
    __ vstm(db_w, sp, lowest_fp_reg, highest_fp_reg);
  }
  ~SaveWasmParamsScope() {
    __ vldm(ia_w, sp, lowest_fp_reg, highest_fp_reg);
    __ ldm(ia_w, sp, gp_regs);
  }

  RegList gp_regs;
  DwVfpRegister lowest_fp_reg;
  DwVfpRegister highest_fp_reg;
  MacroAssembler* masm;
};

// This builtin creates the following stack frame:
//
// [  feedback vector   ]  <-- sp  // Added by this builtin.
// [ Wasm instance data ]          // Added by this builtin.
// [ WASM frame marker  ]          // Already there on entry.
// [     saved fp       ]  <-- fp  // Already there on entry.
void Builtins::Generate_WasmLiftoffFrameSetup(MacroAssembler* masm) {
  Register func_index = wasm::kLiftoffFrameSetupFunctionReg;
  Register vector = r5;
  Register scratch = r7;
  Label allocate_vector, done;

  __ ldr(vector,
         FieldMemOperand(kWasmImplicitArgRegister,
                         WasmTrustedInstanceData::kFeedbackVectorsOffset));
  __ add(vector, vector, Operand(func_index, LSL, kTaggedSizeLog2));
  __ ldr(vector, FieldMemOperand(vector, OFFSET_OF_DATA_START(FixedArray)));
  __ JumpIfSmi(vector, &allocate_vector);
  __ bind(&done);
  __ push(kWasmImplicitArgRegister);
  __ push(vector);
  __ Ret();

  __ bind(&allocate_vector);

  // Feedback vector doesn't exist yet. Call the runtime to allocate it.
  // We temporarily change the frame type for this, because we need special
  // handling by the stack walker in case of GC.
  __ mov(scratch,
         Operand(StackFrame::TypeToMarker(StackFrame::WASM_LIFTOFF_SETUP)));
  __ str(scratch, MemOperand(sp));
  {
    SaveWasmParamsScope save_params(masm);
    // Arguments to the runtime function: instance data, func_index.
    __ push(kWasmImplicitArgRegister);
    __ SmiTag(func_index);
    __ push(func_index);
    // Allocate a stack slot where the runtime function can spill a pointer
    // to the {NativeModule}.
    __ push(r8);
    __ Move(cp, Smi::zero());
    __ CallRuntime(Runtime::kWasmAllocateFeedbackVector, 3);
    __ mov(vector, kReturnRegister0);
    // Saved parameters are restored at the end of this block.
  }
  __ mov(scratch, Operand(StackFrame::TypeToMarker(StackFrame::WASM)));
  __ str(scratch, MemOperand(sp));
  __ b(&done);
}

void Builtins::Generate_WasmCompileLazy(MacroAssembler* masm) {
  // The function index was put in a register by the jump table trampoline.
  // Convert to Smi for the runtime call.
  __ SmiTag(kWasmCompileLazyFuncIndexRegister);
  {
    HardAbortScope hard_abort(masm);  // Avoid calls to Abort.
    FrameAndConstantPoolScope scope(masm, StackFrame::INTERNAL);

    {
      SaveWasmParamsScope save_params(masm);

      // Push the instance data as an explicit argument to the runtime function.
      __ push(kWasmImplicitArgRegister);
      // Push the function index as second argument.
      __ push(kWasmCompileLazyFuncIndexRegister);
      // Initialize the JavaScript context with 0. CEntry will use it to
      // set the current context on the isolate.
      __ Move(cp, Smi::zero());
      __ CallRuntime(Runtime::kWasmCompileLazy, 2);
      // The runtime function returns the jump table slot offset as a Smi. Use
      // that to compute the jump target in r8.
      __ mov(r8, Operand::SmiUntag(kReturnRegister0));

      // Saved parameters are restored at the end of this block.
    }

    // After the instance data register has been restored, we can add the jump
    // table start to the jump table offset already stored in r8.
    __ ldr(r9, FieldMemOperand(kWasmImplicitArgRegister,
                               WasmTrustedInstanceData::kJumpTableStartOffset));
    __ add(r8, r8, r9);
  }

  // Finally, jump to the jump table slot for the function.
  __ Jump(r8);
}

void Builtins::Generate_WasmDebugBreak(MacroAssembler* masm) {
  HardAbortScope hard_abort(masm);  // Avoid calls to Abort.
  {
    FrameAndConstantPoolScope scope(masm, StackFrame::WASM_DEBUG_BREAK);

    static_assert(DwVfpRegister::kNumRegisters == 32);
    constexpr DwVfpRegister last =
        WasmDebugBreakFrameConstants::kPushedFpRegs.last();
    constexpr DwVfpRegister first =
        WasmDebugBreakFrameConstants::kPushedFpRegs.first();
    static_assert(
        WasmDebugBreakFrameConstants::kPushedFpRegs.Count() ==
            last.code() - first.code() + 1,
        "All registers in the range from first to last have to be set");

    // Save all parameter registers. They might hold live values, we restore
    // them after the runtime call.
    constexpr DwVfpRegister lowest_fp_reg = first;
    constexpr DwVfpRegister highest_fp_reg = last;

    // Store gp parameter registers.
    __ stm(db_w, sp, WasmDebugBreakFrameConstants::kPushedGpRegs);
    // Store fp parameter registers.
    __ vstm(db_w, sp, lowest_fp_reg, highest_fp_reg);

    // Initialize the JavaScript context with 0. CEntry will use it to
    // set the current context on the isolate.
    __ Move(cp, Smi::zero());
    __ CallRuntime(Runtime::kWasmDebugBreak, 0);

    // Restore registers.
    __ vldm(ia_w, sp, lowest_fp_reg, highest_fp_reg);
    __ ldm(ia_w, sp, WasmDebugBreakFrameConstants::kPushedGpRegs);
  }
  __ Ret();
}

namespace {
// Check that the stack was in the old state (if generated code assertions are
// enabled), and switch to the new state.
void SwitchStackState(MacroAssembler* masm, Register jmpbuf, Register tmp,
                      wasm::JumpBuffer::StackState old_state,
                      wasm::JumpBuffer::StackState new_state) {
  __ ldr(tmp, MemOperand(jmpbuf, wasm::kJmpBufStateOffset));
  Label ok;
  __ JumpIfEqual(tmp, old_state, &ok);
  __ Trap();
  __ bind(&ok);
  __ mov(tmp, Operand(new_state));
  __ str(tmp, MemOperand(jmpbuf, wasm::kJmpBufStateOffset));
}

// Switch the stack pointer.
void SwitchStackPointer(MacroAssembler* masm, Register jmpbuf) {
  __ ldr(sp, MemOperand(jmpbuf, wasm::kJmpBufSpOffset));
}

void FillJumpBuffer(MacroAssembler* masm, Register jmpbuf, Label* target,
                    Register tmp) {
  __ mov(tmp, sp);
  __ str(tmp, MemOperand(jmpbuf, wasm::kJmpBufSpOffset));
  __ str(fp, MemOperand(jmpbuf, wasm::kJmpBufFpOffset));
  __ LoadStackLimit(tmp, StackLimitKind::kRealStackLimit);
  __ str(tmp, MemOperand(jmpbuf, wasm::kJmpBufStackLimitOffset));

  __ GetLabelAddress(tmp, target);
  // Stash the address in the jump buffer.
  __ str(tmp, MemOperand(jmpbuf, wasm::kJmpBufPcOffset));
}

void LoadJumpBuffer(MacroAssembler* masm, Register jmpbuf, bool load_pc,
                    Register tmp, wasm::JumpBuffer::StackState expected_state) {
  SwitchStackPointer(masm, jmpbuf);
  __ ldr(fp, MemOperand(jmpbuf, wasm::kJmpBufFpOffset));
  SwitchStackState(masm, jmpbuf, tmp, expected_state, wasm::JumpBuffer::Active);
  if (load_pc) {
    __ ldr(tmp, MemOperand(jmpbuf, wasm::kJmpBufPcOffset));
    __ bx(tmp);
  }
  // The stack limit in StackGuard is set separately under the ExecutionAccess
  // lock.
}

void SaveState(MacroAssembler* masm, Register active_continuation, Register tmp,
               Label* suspend) {
  Register jmpbuf = tmp;
  __ ldr(jmpbuf, FieldMemOperand(active_continuation,
                                 WasmContinuationObject::kJmpbufOffset));

  UseScratchRegisterScope temps(masm);
  FillJumpBuffer(masm, jmpbuf, suspend, temps.Acquire());
}

void LoadTargetJumpBuffer(MacroAssembler* masm, Register target_continuation,
                          Register tmp,
                          wasm::JumpBuffer::StackState expected_state) {
  Register target_jmpbuf = target_continuation;
  __ ldr(target_jmpbuf, FieldMemOperand(target_continuation,
                                        WasmContinuationObject::kJmpbufOffset));

  __ Zero(MemOperand(fp, StackSwitchFrameConstants::kGCScanSlotCountOffset));
  // Switch stack!
  LoadJumpBuffer(masm, target_jmpbuf, false, tmp, expected_state);
}

// Updates the stack limit to match the new active stack.
// Pass the {finished_continuation} argument to indicate that the stack that we
// are switching from returned, and in this case return its memory to the stack
// pool.
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
    __ PrepareCallCFunction(2);
    FrameScope scope(masm, StackFrame::MANUAL);
    __ Move(kCArgRegs[0], ExternalReference::isolate_address(masm->isolate()));
    __ Move(kCArgRegs[1], finished_continuation);
    __ CallCFunction(ER::wasm_return_switch(), 2);
  } else {
    __ PrepareCallCFunction(1);
    FrameScope scope(masm, StackFrame::MANUAL);
    __ Move(kCArgRegs[0], ER::isolate_address());
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
  __ ldr(jmpbuf, FieldMemOperand(active_continuation,
                                 WasmContinuationObject::kJmpbufOffset));
  __ Zero(MemOperand(jmpbuf, wasm::kJmpBufSpOffset));
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
  __ str(parent, MemOperand(kRootRegister, active_continuation_offset));
  jmpbuf = parent;
  __ ldr(jmpbuf,
         FieldMemOperand(parent, WasmContinuationObject::kJmpbufOffset));

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

  Label undefined;
  __ JumpIfRoot(suspender, RootIndex::kUndefinedValue, &undefined);

  if (v8_flags.debug_code) {
    // Check that the parent suspender is active.
    Label parent_inactive;
    Register state = tmp2;
    __ Move(state, state_loc);
    __ SmiUntag(state);
    __ JumpIfEqual(state, WasmSuspenderObject::kActive, &parent_inactive);
    __ Trap();
    __ bind(&parent_inactive);
  }
  __ Move(tmp2, Smi::FromInt(WasmSuspenderObject::kActive));
  __ StoreTaggedField(tmp2, state_loc);
  __ bind(&undefined);
  int32_t active_suspender_offset =
      MacroAssembler::RootRegisterOffsetForRootIndex(
          RootIndex::kActiveSuspender);
  __ str(suspender, MemOperand(kRootRegister, active_suspender_offset));
}

void ResetStackSwitchFrameStackSlots(MacroAssembler* masm) {
  __ Zero(MemOperand(fp, StackSwitchFrameConstants::kResultArrayOffset),
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
        it = allocated_registers_.erase(it);
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
  __ LoadTaggedField(scratch, FieldMemOperand(data, HeapObject::kMapOffset));
  __ CompareInstanceType(scratch, scratch, WASM_TRUSTED_INSTANCE_DATA_TYPE);
  Label instance;
  Label end;
  __ b(eq, &instance);
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
  for (int i = static_cast<int>(arraysize(wasm::kFpParamRegisters)) - 1; i >= 0;
       --i) {
    __ vpush(wasm::kFpParamRegisters[i]);
  }

  // r6 is pushed for alignment, so that the pushed register parameters and
  // stack parameters look the same as the layout produced by the js-to-wasm
  // wrapper for out-going parameters. Having the same layout allows to share
  // code in Torque, especially the `LocationAllocator`. r6 has been picked
  // arbitrarily.
  __ Push(r6, wasm::kGpParamRegisters[3], wasm::kGpParamRegisters[2],
          wasm::kGpParamRegisters[1]);
  // Reserve a slot for the signature.
  __ Push(r0);
  __ TailCallBuiltin(Builtin::kWasmToJsWrapperCSA);
}

void Builtins::Generate_WasmTrapHandlerLandingPad(MacroAssembler* masm) {
  __ Trap();
}

void Builtins::Generate_WasmSuspend(MacroAssembler* masm) {
  auto regs = RegisterAllocator::WithAllocatableGeneralRegisters();
  // Set up the stackframe.
  __ EnterFrame(StackFrame::STACK_SWITCH);

  DEFINE_PINNED(suspender, r0);
  DEFINE_PINNED(context, kContextRegister);

  __ sub(
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
  __ ldr(jmpbuf,
         FieldMemOperand(continuation, WasmContinuationObject::kJmpbufOffset));
  FillJumpBuffer(masm, jmpbuf, &resume, scratch);
  SwitchStackState(masm, jmpbuf, scratch, wasm::JumpBuffer::Active,
                   wasm::JumpBuffer::Suspended);
  __ Move(scratch, Smi::FromInt(WasmSuspenderObject::kSuspended));
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
    __ cmp(suspender_continuation, continuation);
    Label ok;
    __ b(&ok, eq);
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
  __ str(caller, MemOperand(kRootRegister, active_continuation_offset));
  DEFINE_REG(parent);
  __ LoadTaggedField(
      parent, FieldMemOperand(suspender, WasmSuspenderObject::kParentOffset));
  int32_t active_suspender_offset =
      MacroAssembler::RootRegisterOffsetForRootIndex(
          RootIndex::kActiveSuspender);
  __ str(parent, MemOperand(kRootRegister, active_suspender_offset));
  regs.ResetExcept(suspender, caller);

  // -------------------------------------------
  // Load jump buffer.
  // -------------------------------------------
  SwitchStacks(masm, no_reg, caller, suspender);
  ASSIGN_REG(jmpbuf);
  __ ldr(jmpbuf,
         FieldMemOperand(caller, WasmContinuationObject::kJmpbufOffset));
  __ LoadTaggedField(
      kReturnRegister0,
      FieldMemOperand(suspender, WasmSuspenderObject::kPromiseOffset));
  MemOperand GCScanSlotPlace =
      MemOperand(fp, StackSwitchFrameConstants::kGCScanSlotCountOffset);
  __ Zero(GCScanSlotPlace);
  ASSIGN_REG(scratch)
  LoadJumpBuffer(masm, jmpbuf, true, scratch, wasm::JumpBuffer::Inactive);
  if (v8_flags.debug_code) {
    __ Trap();
  }
  __ bind(&resume);
  __ LeaveFrame(StackFrame::STACK_SWITCH);
  __ Jump(lr);
}

namespace {
// Resume the suspender stored in the closure. We generate two variants of this
// builtin: the onFulfilled variant resumes execution at the saved PC and
// forwards the value, the onRejected variant throws the value.

void Generate_WasmResumeHelper(MacroAssembler* masm, wasm::OnResume on_resume) {
  auto regs = RegisterAllocator::WithAllocatableGeneralRegisters();
  __ EnterFrame(StackFrame::STACK_SWITCH);

  DEFINE_PINNED(closure, kJSFunctionRegister);  // r1

  __ sub(
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
  __ ldr(state, FieldMemOperand(suspender, WasmSuspenderObject::kStateOffset));
  __ SmiUntag(state);
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
  __ ldr(current_jmpbuf,
         FieldMemOperand(active_continuation,
                         WasmContinuationObject::kJmpbufOffset));
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
      scratch, FieldMemOperand(suspender, WasmSuspenderObject::kStateOffset));
  int32_t active_suspender_offset =
      MacroAssembler::RootRegisterOffsetForRootIndex(
          RootIndex::kActiveSuspender);
  __ str(suspender, MemOperand(kRootRegister, active_suspender_offset));

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

  __ StoreTaggedField(active_continuation,
                      FieldMemOperand(target_continuation,
                                      WasmContinuationObject::kParentOffset));
  __ RecordWriteField(
      target_continuation, WasmContinuationObject::kParentOffset,
      active_continuation, kLRHasBeenSaved, SaveFPRegsMode::kIgnore);
  FREE_REG(active_continuation);
  int32_t active_continuation_offset =
      MacroAssembler::RootRegisterOffsetForRootIndex(
          RootIndex::kActiveContinuation);
  __ str(target_continuation,
         MemOperand(kRootRegister, active_continuation_offset));

  SwitchStacks(masm, no_reg, target_continuation);

  regs.ResetExcept(target_continuation);

  // -------------------------------------------
  // Load state from target jmpbuf (longjmp).
  // -------------------------------------------
  regs.Reserve(kReturnRegister0);
  DEFINE_REG(target_jmpbuf);
  ASSIGN_REG(scratch);
  __ ldr(target_jmpbuf, FieldMemOperand(target_continuation,
                                        WasmContinuationObject::kJmpbufOffset));
  // Move resolved value to return register.
  __ ldr(kReturnRegister0, MemOperand(fp, 3 * kSystemPointerSize));
  MemOperand GCScanSlotPlace =
      MemOperand(fp, StackSwitchFrameConstants::kGCScanSlotCountOffset);
  __ Zero(GCScanSlotPlace);
  if (on_resume == wasm::OnResume::kThrow) {
    // Switch to the continuation's stack without restoring the PC.
    LoadJumpBuffer(masm, target_jmpbuf, false, scratch,
                   wasm::JumpBuffer::Suspended);
    // Pop this frame now. The unwinder expects that the first STACK_SWITCH
    // frame is the outermost one.
    __ LeaveFrame(StackFrame::STACK_SWITCH);
    // Forward the onRejected value to kThrow.
    __ Push(kReturnRegister0);
    __ CallRuntime(Runtime::kThrow);
  } else {
    // Resume the continuation normally.
    LoadJumpBuffer(masm, target_jmpbuf, true, scratch,
                   wasm::JumpBuffer::Suspended);
  }
  if (v8_flags.debug_code) {
    __ Trap();
  }
  __ bind(&suspend);
  __ LeaveFrame(StackFrame::STACK_SWITCH);
  // Pop receiver + parameter.
  __ add(sp, sp, Operand(2 * kSystemPointerSize));
  __ Jump(lr);
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
  regs.Pinned(r9, &original_fp);
  __ Move(original_fp, fp);
  __ LoadRoot(target_continuation, RootIndex::kActiveContinuation);
  LoadTargetJumpBuffer(masm, target_continuation, scratch,
                       wasm::JumpBuffer::Suspended);
  FREE_REG(target_continuation);

  // Push the loaded fp. We know it is null, because there is no frame yet,
  // so we could also push 0 directly. In any case we need to push it,
  // because this marks the bas
"""


```