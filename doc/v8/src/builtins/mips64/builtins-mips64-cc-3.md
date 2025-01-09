Response:
The user wants a summary of the provided MIPS64 assembly code, which is a part of the V8 JavaScript engine.

Here's a breakdown of the thought process to generate the response:

1. **Identify the File and its Role:** The file is `v8/src/builtins/mips64/builtins-mips64.cc`. The path suggests it contains architecture-specific (MIPS64) implementations of built-in functions for V8. The `.cc` extension indicates it's C++ code containing assembly instructions.

2. **Scan for Key Function Names and Patterns:**  Look for function declarations starting with `void Builtins::Generate_`. These are the individual built-in functions being implemented. Note common patterns like `TailCallBuiltin`, `CallRuntime`, `Trap`, and specific instructions related to stack manipulation and register usage.

3. **Categorize the Functions:** Group the listed functions by their apparent purpose. Based on the names and internal operations, potential categories emerge:
    * **Function Calls/Construction:** `Call`, `Construct`, `BoundFunctionCall`, `ConstructBoundFunction`.
    * **WebAssembly (Wasm):**  Functions with `Wasm` in their name, like `WasmLiftoffFrameSetup`, `WasmCompileLazy`, `WasmDebugBreak`, `WasmToJsWrapperAsm`, etc.
    * **C++ Integration:** `CEntry`, `DirectCEntry`.
    * **Type Conversion:** `DoubleToI`.
    * **API Calls:** `CallApiCallbackImpl`, `CallApiGetter`.

4. **Summarize Each Category's Functionality:**
    * **Function Calls/Construction:** These functions handle how JavaScript functions are called (normal calls and with `new`) and how bound functions (created with `bind`) are invoked. They manage the stack, arguments, and potentially involve checks for constructor validity.
    * **WebAssembly:** This section deals with the interaction between JavaScript and WebAssembly. It includes setting up Wasm frames, lazy compilation of Wasm code, handling debug breaks, and wrapping calls between Wasm and JavaScript. The presence of `Trap` suggests unimplemented features or intentional halting.
    * **C++ Integration:** `CEntry` is the crucial bridge for calling C++ functions from JavaScript. It handles argument passing, stack frame setup, and exception handling. `DirectCEntry` is a specialized entry point for GC-safe calls.
    * **Type Conversion:** `DoubleToI` focuses on converting JavaScript's double-precision floating-point numbers to integers, handling potential overflow and NaN cases.
    * **API Calls:**  These functions manage calls to V8's C++ API from JavaScript. They set up the necessary structures (`FunctionCallbackInfo`, `PropertyCallbackInfo`) and call the provided API function.

5. **Address Specific User Prompts:**
    * **`.tq` extension:** The code explicitly checks for this and correctly states it would indicate a Torque source file.
    * **Relationship to JavaScript (with example):** Choose a conceptually simple and commonly used built-in, like `Function.prototype.bind`, and explain its connection to the `BoundFunctionCall` logic. Provide a basic JavaScript example demonstrating `bind`.
    * **Code Logic Reasoning (with example):** Select a function with relatively clear logic, like `DoubleToI`. Create hypothetical input (a double value) and trace the likely output based on the code's conversion logic. Highlight edge cases like very large numbers or NaN.
    * **Common Programming Errors (with example):** Connect to a function like `Construct` and illustrate a common error like calling a non-constructor with `new`.
    * **Overall Functionality (the main request):**  Synthesize the category summaries into a concise overview of the file's purpose within V8.

6. **Structure the Output:** Organize the information clearly with headings and bullet points for readability. Start with the basic file information and then delve into the functionalities. Present the JavaScript examples and code logic reasoning in a clear, understandable format.

7. **Refine and Review:** Check for accuracy, clarity, and completeness. Ensure the language is appropriate for someone understanding basic programming concepts but possibly unfamiliar with V8 internals. Make sure all parts of the user's prompt are addressed. For instance, explicitly state if a feature is not implemented (`Trap`).
好的，让我们来分析一下 `v8/src/builtins/mips64/builtins-mips64.cc` 这个文件的功能。

**文件功能概览**

`v8/src/builtins/mips64/builtins-mips64.cc` 文件是 V8 JavaScript 引擎中专门为 **MIPS64 架构** 实现 **内置函数 (Built-ins)** 的 C++ 源代码文件。 内置函数是 V8 引擎预先定义好的一些函数，它们用高效的机器码实现，用于执行 JavaScript 中一些核心的操作，例如函数调用、对象构造、类型转换、与 WebAssembly 的交互以及调用 C++ API 等。 由于不同 CPU 架构的指令集不同，因此需要为每个支持的架构提供特定的内置函数实现。

**详细功能列举**

这个文件包含了多个 `Builtins::Generate_` 开头的静态方法，每个方法负责生成特定内置函数的 MIPS64 汇编代码。以下是一些关键功能的归纳：

1. **函数调用和构造 (Function Calls and Construction):**
   - `Generate_Call`:  实现 JavaScript 函数调用的逻辑。它负责设置调用栈帧，传递参数，并跳转到目标函数。
   - `Generate_Construct`: 实现使用 `new` 关键字调用构造函数的逻辑。它会检查目标是否为构造函数，并分配新的对象实例。
   - `Generate_BoundFunctionCall`:  实现使用 `Function.prototype.bind()` 创建的绑定函数的调用逻辑。
   - `Generate_ConstructBoundFunction`: 实现使用 `new` 关键字调用绑定函数的逻辑。

2. **WebAssembly 支持 (WebAssembly Support - 如果 `V8_ENABLE_WEBASSEMBLY` 宏定义启用):**
   - `Generate_WasmLiftoffFrameSetup`:  为 WebAssembly 函数调用设置快速的 Liftoff 栈帧。
   - `Generate_WasmCompileLazy`:  实现 WebAssembly 模块的延迟编译。
   - `Generate_WasmDebugBreak`:  处理 WebAssembly 代码中的断点。
   - `Generate_WasmToJsWrapperAsm`:  生成从 WebAssembly 调用 JavaScript 的包装器代码。
   - `Generate_WasmTrapHandlerLandingPad`:  处理 WebAssembly 代码中的 trap 异常。
   - `Generate_WasmSuspend`, `Generate_WasmResume`, `Generate_WasmReject`:  可能与 WebAssembly 的异步操作或异常处理相关 (代码中目前是 `__ Trap()`，表示未实现或故意抛出异常)。
   - `Generate_WasmOnStackReplace`:  支持 WebAssembly 的栈上替换 (OSR)，用于优化正在运行的 WebAssembly 代码。
   - `Generate_JSToWasmWrapperAsm`: 生成从 JavaScript 调用 WebAssembly 的包装器代码。
   - `Generate_WasmHandleStackOverflow`: 处理 WebAssembly 代码中的栈溢出。

3. **C++ 调用 (Calling C++):**
   - `Generate_CEntry`:  实现从 JavaScript 代码调用 C++ 函数的入口点。它负责设置 C++ 调用的栈帧，传递参数，并处理返回值和异常。
   - `Generate_DirectCEntry`:  一种更直接的调用 C++ 函数的方式，可能用于特定的性能敏感场景。

4. **类型转换 (Type Conversion):**
   - `Generate_DoubleToI`:  实现将 JavaScript 的双精度浮点数转换为整数的逻辑，需要处理溢出和 NaN (Not a Number) 的情况。

5. **API 调用 (API Calls):**
   - `Generate_CallApiCallbackImpl`:  实现调用由 C++ API 设置的 JavaScript 回调函数的逻辑。
   - `Generate_CallApiGetter`: 实现调用由 C++ API 设置的属性 getter 函数的逻辑。

**关于 `.tq` 结尾**

如果 `v8/src/builtins/mips64/builtins-mips64.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。 Torque 是 V8 开发的一种领域特定语言，用于更安全、更易于维护的方式生成内置函数的汇编代码。 当前的文件是 `.cc` 结尾，意味着它是直接用 C++ 和汇编宏编写的。

**与 JavaScript 功能的关系及示例**

这个文件中的每一个内置函数都直接对应着 JavaScript 中的某些操作或语法结构。

**示例 1：`Generate_Call` (函数调用)**

当你在 JavaScript 中调用一个函数时，例如：

```javascript
function myFunction(a, b) {
  return a + b;
}

myFunction(1, 2);
```

V8 引擎最终会执行 `Generate_Call` 中生成的 MIPS64 汇编代码来完成这次函数调用。  `Generate_Call` 会负责将参数 `1` 和 `2` 放置到正确的位置，然后跳转到 `myFunction` 的编译后的代码地址。

**示例 2：`Generate_Construct` (对象构造)**

当你使用 `new` 关键字创建一个对象时：

```javascript
function MyClass(value) {
  this.value = value;
}

const myObject = new MyClass(5);
```

V8 会执行 `Generate_Construct` 中生成的汇编代码。 它会检查 `MyClass` 是否是构造函数，然后分配一个新的对象，并将 `this` 指向新对象，最后调用 `MyClass` 的代码。

**示例 3：`Generate_DoubleToI` (类型转换)**

当你尝试将一个浮点数转换为整数时：

```javascript
const floatValue = 3.14;
const intValue = parseInt(floatValue); // 或者使用 Math.trunc, Math.floor, Math.ceil 等
```

V8 可能会使用 `Generate_DoubleToI` 中生成的代码来完成这个转换。这段代码需要处理浮点数的内部表示，并将其转换为整数，同时考虑溢出等情况。

**代码逻辑推理及假设输入输出**

以 `Generate_DoubleToI` 为例进行简单的逻辑推理：

**假设输入：**  一个双精度浮点数 `3.7`  （在 MIPS64 的寄存器或栈上的表示）。

**执行过程：**

1. 代码会首先尝试使用快速的浮点数截断指令 (`Trunc_w_d`) 将其转换为有符号整数。
2. 检查浮点状态寄存器 (FCSR) 是否有溢出或 NaN 的标志。
3. 如果没有异常，截断后的整数值 (3) 将会被存储在结果寄存器中。
4. 如果有溢出或 NaN，代码会执行更复杂的“手动截断”逻辑：
   - 解析浮点数的符号、指数和尾数。
   - 根据指数值进行移位操作，提取整数部分。
   - 处理符号。

**假设输出：**  整数值 `3` (存储在指定的寄存器中)。

**涉及用户常见的编程错误及示例**

1. **在非构造函数上使用 `new` 关键字:**

   ```javascript
   function normalFunction() {
     return 10;
   }

   const obj = new normalFunction(); // 这是一个错误用法
   ```

   当执行 `new normalFunction()` 时，`Generate_Construct` 中的代码会检测到 `normalFunction` 不是一个构造函数（没有内部 `[[Construct]]` 方法），并会抛出一个 `TypeError` 异常。

2. **尝试将超出整数范围的浮点数转换为整数:**

   ```javascript
   const largeFloat = 9007199254740992; // 大于 JavaScript 的安全整数
   const intValue = parseInt(largeFloat);
   ```

   `Generate_DoubleToI` 中的代码在处理这类情况时，可能会返回一个不精确的结果，或者根据具体实现返回最大/最小整数值。  早期的快速转换可能会检测到溢出，而手动转换逻辑也会处理超出 32 位整数范围的情况。

**归纳总结 (第 4 部分)**

到目前为止，我们可以归纳出 `v8/src/builtins/mips64/builtins-mips64.cc` 文件的主要功能是：

* **为 MIPS64 架构提供了 V8 JavaScript 引擎内置函数的底层实现。** 这些实现使用高效的 MIPS64 汇编指令来执行关键的 JavaScript 操作。
* **涵盖了 JavaScript 中核心的语言特性，如函数调用、对象构造、类型转换。**
* **包含了对 WebAssembly 的支持 (如果启用)，允许 JavaScript 代码与 WebAssembly 模块进行交互。**
* **提供了从 JavaScript 代码调用 C++ 函数的桥梁。**
* **通过底层的汇编代码实现，确保了 V8 引擎在 MIPS64 架构上的性能。**

这个文件是 V8 引擎在 MIPS64 架构上运行的基础，它将高级的 JavaScript 语义转化为底层的机器指令，使得 JavaScript 代码能够在该架构上高效执行。

Prompt: 
```
这是目录为v8/src/builtins/mips64/builtins-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/mips64/builtins-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能

"""
allRuntime(Runtime::kThrowStackOverflow);
    }
    __ bind(&done);
  }

  // Pop receiver.
  __ Pop(t0);

  // Push [[BoundArguments]].
  {
    Label loop, done_loop;
    __ SmiUntag(a4, FieldMemOperand(a2, offsetof(FixedArray, length_)));
    __ Daddu(a0, a0, Operand(a4));
    __ Daddu(a2, a2,
             Operand(OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag));
    __ bind(&loop);
    __ Dsubu(a4, a4, Operand(1));
    __ Branch(&done_loop, lt, a4, Operand(zero_reg));
    __ Dlsa(a5, a2, a4, kSystemPointerSizeLog2);
    __ Ld(kScratchReg, MemOperand(a5));
    __ Push(kScratchReg);
    __ Branch(&loop);
    __ bind(&done_loop);
  }

  // Push receiver.
  __ Push(t0);

  // Patch new.target to [[BoundTargetFunction]] if new.target equals target.
  {
    Label skip_load;
    __ Branch(&skip_load, ne, a1, Operand(a3));
    __ Ld(a3, FieldMemOperand(a1, JSBoundFunction::kBoundTargetFunctionOffset));
    __ bind(&skip_load);
  }

  // Construct the [[BoundTargetFunction]] via the Construct builtin.
  __ Ld(a1, FieldMemOperand(a1, JSBoundFunction::kBoundTargetFunctionOffset));
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
  __ ld(map, FieldMemOperand(target, HeapObject::kMapOffset));
  {
    Register flags = t3;
    __ Lbu(flags, FieldMemOperand(map, Map::kBitFieldOffset));
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

  __ Ld(vector,
        FieldMemOperand(kWasmImplicitArgRegister,
                        WasmTrustedInstanceData::kFeedbackVectorsOffset));
  __ Dlsa(vector, vector, func_index, kTaggedSizeLog2);
  __ Ld(vector, FieldMemOperand(vector, OFFSET_OF_DATA_START(FixedArray)));
  __ JumpIfSmi(vector, &allocate_vector);
  __ bind(&done);
  __ Push(vector);
  __ Ret();

  __ bind(&allocate_vector);
  // Feedback vector doesn't exist yet. Call the runtime to allocate it.
  // We temporarily change the frame type for this, because we need special
  // handling by the stack walker in case of GC.
  __ li(scratch, StackFrame::TypeToMarker(StackFrame::WASM_LIFTOFF_SETUP));
  __ Sd(scratch, MemOperand(fp, TypedFrameConstants::kFrameTypeOffset));

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
  __ Ld(kWasmImplicitArgRegister,
        MemOperand(fp, WasmFrameConstants::kWasmInstanceDataOffset));
  __ li(scratch, StackFrame::TypeToMarker(StackFrame::WASM));
  __ Sd(scratch, MemOperand(fp, TypedFrameConstants::kFrameTypeOffset));
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
    // Check if machine has simd enabled, if so push vector registers. If not
    // then only push double registers.
    Label push_doubles, simd_pushed;
    __ li(a1, ExternalReference::supports_wasm_simd_128_address());
    // If > 0 then simd is available.
    __ Lbu(a1, MemOperand(a1));
    __ Branch(&push_doubles, le, a1, Operand(zero_reg));
    // Save vector registers.
    {
      CpuFeatureScope msa_scope(
          masm, MIPS_SIMD, CpuFeatureScope::CheckPolicy::kDontCheckSupported);
      __ MultiPushMSA(kSavedFpRegs);
    }
    __ Branch(&simd_pushed);
    __ bind(&push_doubles);
    __ MultiPushFPU(kSavedFpRegs);
    // kFixedFrameSizeFromFp is hard coded to include space for Simd
    // registers, so we still need to allocate extra (unused) space on the stack
    // as if they were saved.
    __ Dsubu(sp, sp, kSavedFpRegs.Count() * kDoubleSize);
    __ bind(&simd_pushed);

    __ Push(kWasmImplicitArgRegister, kWasmCompileLazyFuncIndexRegister);

    // Initialize the JavaScript context with 0. CEntry will use it to
    // set the current context on the isolate.
    __ Move(kContextRegister, Smi::zero());
    __ CallRuntime(Runtime::kWasmCompileLazy, 2);

    // Restore registers.
    Label pop_doubles, simd_popped;
    __ li(a1, ExternalReference::supports_wasm_simd_128_address());
    // If > 0 then simd is available.
    __ Lbu(a1, MemOperand(a1));
    __ Branch(&pop_doubles, le, a1, Operand(zero_reg));
    // Pop vector registers.
    {
      CpuFeatureScope msa_scope(
          masm, MIPS_SIMD, CpuFeatureScope::CheckPolicy::kDontCheckSupported);
      __ MultiPopMSA(kSavedFpRegs);
    }
    __ Branch(&simd_popped);
    __ bind(&pop_doubles);
    __ Daddu(sp, sp, kSavedFpRegs.Count() * kDoubleSize);
    __ MultiPopFPU(kSavedFpRegs);
    __ bind(&simd_popped);
    __ MultiPop(kSavedGpRegs);
    __ Pop(kWasmImplicitArgRegister);
  }

  // Untag the returned Smi, for later use.
  static_assert(!kSavedGpRegs.has(v0));
  __ SmiUntag(v0);

  // The runtime function returned the jump table slot offset as a Smi (now in
  // t8). Use that to compute the jump target.
  static_assert(!kSavedGpRegs.has(t8));
  __ Ld(t8, FieldMemOperand(kWasmImplicitArgRegister,
                            WasmTrustedInstanceData::kJumpTableStartOffset));
  __ Daddu(t8, v0, t8);

  // Finally, jump to the jump table slot for the function.
  __ Jump(t8);
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

void Builtins::Generate_WasmReturnPromiseOnSuspendAsm(MacroAssembler* masm) {
  __ Trap();
}

void Builtins::Generate_JSToWasmStressSwitchStacksAsm(MacroAssembler* masm) {
  __ Trap();
}

void Builtins::Generate_WasmToJsWrapperAsm(MacroAssembler* masm) {
  // Push registers in reverse order so that they are on the stack like
  // in an array, with the first item being at the lowest address.
  constexpr int cnt_fp = arraysize(wasm::kFpParamRegisters);
  constexpr int cnt_gp = arraysize(wasm::kGpParamRegisters) - 1;
  int required_stack_space = cnt_fp * kDoubleSize + cnt_gp * kSystemPointerSize;
  __ Dsubu(sp, sp, Operand(required_stack_space));
  for (int i = cnt_fp - 1; i >= 0; i--) {
    __ Sdc1(wasm::kFpParamRegisters[i],
            MemOperand(sp, i * kDoubleSize + cnt_gp * kSystemPointerSize));
  }

  // Without wasm::kGpParamRegisters[0] here.
  for (int i = cnt_gp; i >= 1; i--) {
    __ Sd(wasm::kGpParamRegisters[i],
          MemOperand(sp, (i - 1) * kSystemPointerSize));
  }
  // Reserve a slot for the signature.
  __ Push(zero_reg);
  __ TailCallBuiltin(Builtin::kWasmToJsWrapperCSA);
}

void Builtins::Generate_WasmTrapHandlerLandingPad(MacroAssembler* masm) {
  __ Trap();
}

void Builtins::Generate_WasmSuspend(MacroAssembler* masm) {
  // TODO(v8:12191): Implement for this platform.
  __ Trap();
}

void Builtins::Generate_WasmResume(MacroAssembler* masm) {
  // TODO(v8:12191): Implement for this platform.
  __ Trap();
}

void Builtins::Generate_WasmReject(MacroAssembler* masm) {
  // TODO(v8:12191): Implement for this platform.
  __ Trap();
}

void Builtins::Generate_WasmOnStackReplace(MacroAssembler* masm) {
  // Only needed on x64.
  __ Trap();
}

void Builtins::Generate_JSToWasmWrapperAsm(MacroAssembler* masm) { __ Trap(); }

#endif  // V8_ENABLE_WEBASSEMBLY

void Builtins::Generate_CEntry(MacroAssembler* masm, int result_size,
                               ArgvMode argv_mode, bool builtin_exit_frame,
                               bool switch_to_central_stack) {
  // Called from JavaScript; parameters are on stack as if calling JS function
  // a0: number of arguments including receiver
  // a1: pointer to builtin function
  // fp: frame pointer    (restored after C call)
  // sp: stack pointer    (restored as callee's sp after C call)
  // cp: current context  (C callee-saved)
  //
  // If argv_mode == ArgvMode::kRegister:
  // a2: pointer to the first argument

  using ER = ExternalReference;

  // Move input arguments to more convenient registers.
  static constexpr Register argc_input = a0;
  static constexpr Register target_fun = s1;  // C callee-saved
  static constexpr Register argv = a1;
  static constexpr Register scratch = a3;
  static constexpr Register argc_sav = s0;  // C callee-saved

  __ mov(target_fun, argv);

  if (argv_mode == ArgvMode::kRegister) {
    // Move argv into the correct register.
    __ mov(argv, a2);
  } else {
    // Compute the argv pointer in a callee-saved register.
    __ Dlsa(argv, sp, argc_input, kSystemPointerSizeLog2);
    __ Dsubu(argv, argv, kSystemPointerSize);
  }

  // Enter the exit frame that transitions from JavaScript to C++.
  FrameScope scope(masm, StackFrame::MANUAL);
  __ EnterExitFrame(
      scratch, 0,
      builtin_exit_frame ? StackFrame::BUILTIN_EXIT : StackFrame::EXIT);

  // Store a copy of argc in callee-saved registers for later.
  __ mov(argc_sav, argc_input);

  // a0: number of arguments  including receiver
  // s0: number of arguments  including receiver (C callee-saved)
  // a1: pointer to first argument
  // s1: pointer to builtin function (C callee-saved)

  // We are calling compiled C/C++ code. a0 and a1 hold our two arguments. We
  // also need to reserve the 4 argument slots on the stack.

  __ AssertStackIsAligned();

  // Call C built-in.
  // a0 = argc, a1 = argv, a2 = isolate, s1 = target_fun
  DCHECK_EQ(kCArgRegs[0], argc_input);
  DCHECK_EQ(kCArgRegs[1], argv);
  __ li(kCArgRegs[2], ER::isolate_address());

  __ StoreReturnAddressAndCall(target_fun);

  // Result returned in v0 or v1:v0 - do not destroy these registers!

  // Check result for exception sentinel.
  Label exception_returned;
  __ LoadRoot(a4, RootIndex::kException);
  __ Branch(&exception_returned, eq, a4, Operand(v0));

  // Check that there is no exception, otherwise we
  // should have returned the exception sentinel.
  if (v8_flags.debug_code) {
    Label okay;
    ER exception_address =
        ER::Create(IsolateAddressId::kExceptionAddress, masm->isolate());
    __ Ld(scratch, __ ExternalReferenceAsOperand(exception_address, no_reg));
    __ LoadRoot(a4, RootIndex::kTheHoleValue);
    // Cannot use check here as it attempts to generate call into runtime.
    __ Branch(&okay, eq, a4, Operand(scratch));
    __ stop();
    __ bind(&okay);
  }

  // Exit C frame and return.
  // v0:v1: result
  // sp: stack pointer
  // fp: frame pointer
  // s0: still holds argc (C caller-saved).
  __ LeaveExitFrame(scratch);
  if (argv_mode == ArgvMode::kStack) {
    DCHECK(!AreAliased(scratch, argc_sav));
    __ Dlsa(sp, sp, argc_sav, kPointerSizeLog2);
  }

  __ Ret();

  // Handling of exception.
  __ bind(&exception_returned);

  ER pending_handler_context_address = ER::Create(
      IsolateAddressId::kPendingHandlerContextAddress, masm->isolate());
  ER pending_handler_entrypoint_address = ER::Create(
      IsolateAddressId::kPendingHandlerEntrypointAddress, masm->isolate());
  ER pending_handler_fp_address =
      ER::Create(IsolateAddressId::kPendingHandlerFPAddress, masm->isolate());
  ER pending_handler_sp_address =
      ER::Create(IsolateAddressId::kPendingHandlerSPAddress, masm->isolate());

  // Ask the runtime for help to determine the handler. This will set v0 to
  // contain the current exception, don't clobber it.
  {
    FrameScope scope(masm, StackFrame::MANUAL);
    __ PrepareCallCFunction(3, 0, a0);
    __ mov(kCArgRegs[0], zero_reg);
    __ mov(kCArgRegs[1], zero_reg);
    __ li(kCArgRegs[2], ER::isolate_address());
    __ CallCFunction(ER::Create(Runtime::kUnwindAndFindExceptionHandler), 3,
                     SetIsolateDataSlots::kNo);
  }

  // Retrieve the handler context, SP and FP.
  __ li(cp, pending_handler_context_address);
  __ Ld(cp, MemOperand(cp));
  __ li(sp, pending_handler_sp_address);
  __ Ld(sp, MemOperand(sp));
  __ li(fp, pending_handler_fp_address);
  __ Ld(fp, MemOperand(fp));

  // If the handler is a JS frame, restore the context to the frame. Note that
  // the context will be set to (cp == 0) for non-JS frames.
  Label zero;
  __ Branch(&zero, eq, cp, Operand(zero_reg));
  __ Sd(cp, MemOperand(fp, StandardFrameConstants::kContextOffset));
  __ bind(&zero);

  // Clear c_entry_fp, like we do in `LeaveExitFrame`.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, masm->isolate());
  __ Sd(zero_reg, __ ExternalReferenceAsOperand(c_entry_fp_address, no_reg));

  // Compute the handler entry address and jump to it.
  __ Ld(t9, __ ExternalReferenceAsOperand(pending_handler_entrypoint_address,
                                          no_reg));
  __ Jump(t9);
}

#if V8_ENABLE_WEBASSEMBLY
void Builtins::Generate_WasmHandleStackOverflow(MacroAssembler* masm) {
  __ Trap();
}
#endif  // V8_ENABLE_WEBASSEMBLY

void Builtins::Generate_DoubleToI(MacroAssembler* masm) {
  Label done;
  Register result_reg = t0;

  Register scratch = GetRegisterThatIsNotOneOf(result_reg);
  Register scratch2 = GetRegisterThatIsNotOneOf(result_reg, scratch);
  Register scratch3 = GetRegisterThatIsNotOneOf(result_reg, scratch, scratch2);
  DoubleRegister double_scratch = kScratchDoubleReg;

  // Account for saved regs.
  const int kArgumentOffset = 4 * kSystemPointerSize;

  __ Push(result_reg);
  __ Push(scratch, scratch2, scratch3);

  // Load double input.
  __ Ldc1(double_scratch, MemOperand(sp, kArgumentOffset));

  // Try a conversion to a signed integer.
  __ Trunc_w_d(double_scratch, double_scratch);
  // Move the converted value into the result register.
  __ mfc1(scratch3, double_scratch);

  // Retrieve the FCSR.
  __ cfc1(scratch, FCSR);

  // Check for overflow and NaNs.
  __ And(scratch, scratch,
         kFCSROverflowCauseMask | kFCSRUnderflowCauseMask |
             kFCSRInvalidOpCauseMask);
  // If we had no exceptions then set result_reg and we are done.
  Label error;
  __ Branch(&error, ne, scratch, Operand(zero_reg));
  __ Move(result_reg, scratch3);
  __ Branch(&done);
  __ bind(&error);

  // Load the double value and perform a manual truncation.
  Register input_high = scratch2;
  Register input_low = scratch3;

  __ Lw(input_low, MemOperand(sp, kArgumentOffset + Register::kMantissaOffset));
  __ Lw(input_high,
        MemOperand(sp, kArgumentOffset + Register::kExponentOffset));

  Label normal_exponent;
  // Extract the biased exponent in result.
  __ Ext(result_reg, input_high, HeapNumber::kExponentShift,
         HeapNumber::kExponentBits);

  // Check for Infinity and NaNs, which should return 0.
  __ Subu(scratch, result_reg, HeapNumber::kExponentMask);
  __ Movz(result_reg, zero_reg, scratch);
  __ Branch(&done, eq, scratch, Operand(zero_reg));

  // Express exponent as delta to (number of mantissa bits + 31).
  __ Subu(result_reg, result_reg,
          Operand(HeapNumber::kExponentBias + HeapNumber::kMantissaBits + 31));

  // If the delta is strictly positive, all bits would be shifted away,
  // which means that we can return 0.
  __ Branch(&normal_exponent, le, result_reg, Operand(zero_reg));
  __ mov(result_reg, zero_reg);
  __ Branch(&done);

  __ bind(&normal_exponent);
  const int kShiftBase = HeapNumber::kNonMantissaBitsInTopWord - 1;
  // Calculate shift.
  __ Addu(scratch, result_reg, Operand(kShiftBase + HeapNumber::kMantissaBits));

  // Save the sign.
  Register sign = result_reg;
  result_reg = no_reg;
  __ And(sign, input_high, Operand(HeapNumber::kSignMask));

  // On ARM shifts > 31 bits are valid and will result in zero. On MIPS we need
  // to check for this specific case.
  Label high_shift_needed, high_shift_done;
  __ Branch(&high_shift_needed, lt, scratch, Operand(32));
  __ mov(input_high, zero_reg);
  __ Branch(&high_shift_done);
  __ bind(&high_shift_needed);

  // Set the implicit 1 before the mantissa part in input_high.
  __ Or(input_high, input_high,
        Operand(1 << HeapNumber::kMantissaBitsInTopWord));
  // Shift the mantissa bits to the correct position.
  // We don't need to clear non-mantissa bits as they will be shifted away.
  // If they weren't, it would mean that the answer is in the 32bit range.
  __ sllv(input_high, input_high, scratch);

  __ bind(&high_shift_done);

  // Replace the shifted bits with bits from the lower mantissa word.
  Label pos_shift, shift_done;
  __ li(kScratchReg, 32);
  __ subu(scratch, kScratchReg, scratch);
  __ Branch(&pos_shift, ge, scratch, Operand(zero_reg));

  // Negate scratch.
  __ Subu(scratch, zero_reg, scratch);
  __ sllv(input_low, input_low, scratch);
  __ Branch(&shift_done);

  __ bind(&pos_shift);
  __ srlv(input_low, input_low, scratch);

  __ bind(&shift_done);
  __ Or(input_high, input_high, Operand(input_low));
  // Restore sign if necessary.
  __ mov(scratch, sign);
  result_reg = sign;
  sign = no_reg;
  __ Subu(result_reg, zero_reg, input_high);
  __ Movz(result_reg, input_high, scratch);

  __ bind(&done);

  __ Sd(result_reg, MemOperand(sp, kArgumentOffset));
  __ Pop(scratch, scratch2, scratch3);
  __ Pop(result_reg);
  __ Ret();
}

void Builtins::Generate_CallApiCallbackImpl(MacroAssembler* masm,
                                            CallApiCallbackMode mode) {
  // ----------- S t a t e -------------
  // CallApiCallbackMode::kOptimizedNoProfiling/kOptimized modes:
  //  -- a1                  : api function address
  //  Both modes:
  //  -- a2                  : arguments count (not including the receiver)
  //  -- a3                  : FunctionTemplateInfo
  //  -- a0                  : holder
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
  Register scratch = t0;

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
  //
  // Target state:
  //   sp[0 * kSystemPointerSize]: kHolder   <= FCA::implicit_args_
  //   sp[1 * kSystemPointerSize]: kIsolate
  //   sp[2 * kSystemPointerSize]: kContext
  //   sp[3 * kSystemPointerSize]: undefined (kReturnValue)
  //   sp[4 * kSystemPointerSize]: kData
  //   sp[5 * kSystemPointerSize]: undefined (kNewTarget)
  // Existing state:
  //   sp[6 * kSystemPointerSize]:           <= FCA:::values_

  __ StoreRootRelative(IsolateData::topmost_script_having_context_offset(),
                       topmost_script_having_context);
  if (mode == CallApiCallbackMode::kGeneric) {
    api_function_address = ReassignRegister(topmost_script_having_context);
  }

  // Reserve space on the stack.
  __ Dsubu(sp, sp, Operand(FCA::kArgsLength * kSystemPointerSize));

  // kHolder.
  __ Sd(holder, MemOperand(sp, FCA::kHolderIndex * kSystemPointerSize));

  // kIsolate.
  __ li(scratch, ER::isolate_address());
  __ Sd(scratch, MemOperand(sp, FCA::kIsolateIndex * kSystemPointerSize));

  // kContext.
  __ Sd(cp, MemOperand(sp, FCA::kContextIndex * kSystemPointerSize));

  // kReturnValue.
  __ LoadRoot(scratch, RootIndex::kUndefinedValue);
  __ Sd(scratch, MemOperand(sp, FCA::kReturnValueIndex * kSystemPointerSize));

  // kTarget.
  __ Sd(func_templ, MemOperand(sp, FCA::kTargetIndex * kSystemPointerSize));

  // kNewTarget.
  __ Sd(scratch, MemOperand(sp, FCA::kNewTargetIndex * kSystemPointerSize));

  FrameScope frame_scope(masm, StackFrame::MANUAL);
  if (mode == CallApiCallbackMode::kGeneric) {
    __ Ld(
        api_function_address,
        FieldMemOperand(func_templ,
                        FunctionTemplateInfo::kMaybeRedirectedCallbackOffset));
  }

  __ EnterExitFrame(scratch, FC::getExtraSlotsCountFrom<ExitFrameConstants>(),
                    StackFrame::API_CALLBACK_EXIT);

  MemOperand argc_operand = MemOperand(fp, FC::kFCIArgcOffset);
  {
    ASM_CODE_COMMENT_STRING(masm, "Initialize FunctionCallbackInfo");
    // FunctionCallbackInfo::length_.
    // TODO(ishell): pass JSParameterCount(argc) to simplify things on the
    // caller end.
    __ Sd(argc, argc_operand);

    // FunctionCallbackInfo::implicit_args_.
    __ Daddu(scratch, fp, Operand(FC::kImplicitArgsArrayOffset));
    __ Sd(scratch, MemOperand(fp, FC::kFCIImplicitArgsOffset));

    // FunctionCallbackInfo::values_ (points at JS arguments on the stack).
    __ Daddu(scratch, fp, Operand(FC::kFirstArgumentOffset));
    __ Sd(scratch, MemOperand(fp, FC::kFCIValuesOffset));
  }

  __ RecordComment("v8::FunctionCallback's argument.");
  // function_callback_info_arg = v8::FunctionCallbackInfo&
  __ Daddu(function_callback_info_arg, fp,
           Operand(FC::kFunctionCallbackInfoOffset));

  DCHECK(
      !AreAliased(api_function_address, scratch, function_callback_info_arg));

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
  //  -- a1                  : receiver
  //  -- a3                  : accessor info
  //  -- a0                  : holder
  // -----------------------------------

  Register name_arg = kCArgRegs[0];
  Register property_callback_info_arg = kCArgRegs[1];

  Register api_function_address = a2;
  Register receiver = ApiGetterDescriptor::ReceiverRegister();
  Register holder = ApiGetterDescriptor::HolderRegister();
  Register callback = ApiGetterDescriptor::CallbackRegister();
  Register scratch = a4;
  Register undef = a5;
  Register scratch2 = a6;

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

  // Set up PropertyCallbackInfo's (PCI) args_ on the stack as follows:
  // Target state:
  //   sp[0 * kSystemPointerSize]: name                       <= PCI:args_
  //   sp[1 * kSystemPointerSize]: kShouldThrowOnErrorIndex
  //   sp[2 * kSystemPointerSize]: kHolderIndex
  //   sp[3 * kSystemPointerSize]: kIsolateIndex
  //   sp[4 * kSystemPointerSize]: kHolderV2Index
  //   sp[5 * kSystemPointerSize]: kReturnValueIndex
  //   sp[6 * kSystemPointerSize]: kDataIndex
  //   sp[7 * kSystemPointerSize]: kThisIndex / receiver

  __ Ld(scratch, FieldMemOperand(callback, AccessorInfo::kDataOffset));
  __ LoadRoot(undef, RootIndex::kUndefinedValue);
  __ li(scratch2, ER::isolate_address());
  Register holderV2 = zero_reg;
  __ Push(receiver, scratch,  // kThisIndex, kDataIndex
          undef, holderV2);   // kReturnValueIndex, kHolderV2Index
  __ Push(scratch2, holder);  // kIsolateIndex, kHolderIndex

  // |name_arg| clashes with |holder|, so we need to push holder first.
  __ Ld(name_arg, FieldMemOperand(callback, AccessorInfo::kNameOffset));

  static_assert(kDontThrow == 0);
  Register should_throw_on_error =
      zero_reg;  // should_throw_on_error -> kDontThrow
  __ Push(should_throw_on_error, name_arg);

  __ RecordComment("Load api_function_address");
  __ Ld(api_function_address,
        FieldMemOperand(callback, AccessorInfo::kMaybeRedirectedGetterOffset));

  FrameScope frame_scope(masm, StackFrame::MANUAL);
  __ EnterExitFrame(scratch, FC::getExtraSlotsCountFrom<ExitFrameConstants>(),
                    StackFrame::API_ACCESSOR_EXIT);

  __ RecordComment("Create v8::PropertyCallbackInfo object on the stack.");
  // property_callback_info_arg = v8::PropertyCallbackInfo&
  __ Daddu(property_callback_info_arg, fp, Operand(FC::kArgsArrayOffset));

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

  ER thunk_ref = ER::invoke_accessor_getter_callback();
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

  // Make place for arguments to fit C c
"""


```