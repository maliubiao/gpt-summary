Response:
The user wants a summary of the functionality of the provided C++ code snippet.
The code is part of V8's ARM64 built-in functions.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the File:** The filename `builtins-arm64.cc` suggests it contains architecture-specific implementations of built-in functions for ARM64.

2. **Scan for Key Function Names:** Look for function names starting with `Builtins::Generate_`. These are the entry points for generating the assembly code for specific built-in functionalities.

3. **Categorize Functionality:** Group the identified functions based on their names and the surrounding code. Common themes emerge:
    * Varargs handling (`CallOrConstructVarargs`, `CallOrConstructForwardVarargs`)
    * Function calls (`CallFunction`, `CallBoundFunctionImpl`, `Call`)
    * Object construction (`ConstructFunction`, `ConstructBoundFunction`, `Construct`)
    * WebAssembly specific functions (`WasmLiftoffFrameSetup`, `WasmCompileLazy`, `WasmDebugBreak`)
    * Stack switching/continuation related functions (the last part of the snippet).

4. **Analyze Individual Function Logic (briefly):**  For each group, try to understand the core purpose. Keywords and code patterns help:
    * **Varargs:**  "copy", "push", "stack", "len" suggest handling variable arguments.
    * **Function Calls:** "InvokeFunctionCode", "TailCallBuiltin", "ConvertReceiverMode" point to function invocation with receiver handling.
    * **Construction:** "Construct", "new.target", "AllocationSite" are related to object creation.
    * **Wasm:**  "Wasm", "instance data", "jump table", "feedback vector" are WebAssembly related.
    * **Continuations:** "jmpbuf", "stack limit", "switch stack", "continuation" indicate stack manipulation for control flow.

5. **Address Specific Instructions:**
    * **`.tq` extension:** The code itself is `.cc`, so it's not Torque source.
    * **JavaScript relationship:** Several functions directly relate to core JavaScript operations like calling functions and constructing objects. Examples can be provided.
    * **Code logic/inference:** The `Generate_PrepareForCopyingVarargs` function has clear logic. Consider a simple input scenario.
    * **Common programming errors:** The `Call` and `Construct` functions check for callable/constructable targets, suggesting potential errors when those conditions are not met.
    * **Part of a larger series:** Note that this is part 4/7, implying the file covers a subset of all built-in functions.

6. **Formulate the Summary:** Combine the categorized functionalities into a concise summary, addressing the user's specific questions.

7. **Refine and Organize:** Structure the summary logically, using headings and bullet points for clarity. Ensure the language is accessible and avoids overly technical jargon where possible.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the file just handles function calls.
* **Correction:**  Scanning reveals constructor handling and WebAssembly specific code.
* **Initial thought:** Focus on low-level assembly details.
* **Correction:** Emphasize the *purpose* of the generated assembly code within the V8 context.
* **Initial thought:** Provide detailed assembly code analysis.
* **Correction:**  Offer high-level explanations and JavaScript examples instead, as requested. Keep the assembly details brief.

By following these steps, we arrive at the comprehensive summary provided previously.
这是v8源代码文件 `v8/src/builtins/arm64/builtins-arm64.cc` 的一部分，它定义了在 ARM64 架构上执行的 JavaScript 内置函数的汇编代码生成逻辑。

**主要功能归纳:**

这段代码主要负责生成以下 JavaScript 核心功能的 ARM64 汇编代码：

* **处理变长参数 (Varargs) 的函数调用和构造:**  例如 `Call` 或 `new` 操作时，如果参数数量不固定，就需要特殊的处理。
* **函数调用 (Call):**  实现 JavaScript 函数的调用，包括处理 `this` 绑定、参数传递、以及对不同类型可调用对象的处理 (如普通函数、绑定函数、代理对象等)。
* **对象构造 (Construct):**  实现 JavaScript 对象的创建，包括处理 `new` 操作符，调用构造函数，以及处理不同类型的构造器 (如普通构造函数、绑定构造函数、代理对象等)。
* **WebAssembly (Wasm) 相关的支持:**  包含 Wasm 帧的设置、延迟编译、调试断点等功能的汇编代码生成。
* **协程 (Continuations) 的支持:**  实现协程的挂起和恢复，涉及到栈的切换和状态管理。

**详细功能列表:**

* **`Generate_PrepareForCopyingVarargs`:**  为复制变长参数到栈上做准备，包括计算需要复制的槽位数量，并在必要时初始化对齐槽位。
* **`Generate_CallOrConstructVarargs`:**  生成调用或构造函数时处理变长参数的汇编代码。它从一个数组中取出参数并压入栈中。
* **`Generate_CallOrConstructForwardVarargs`:**  生成转发变长参数的调用或构造函数的汇编代码，用于处理剩余参数 (rest parameters)。
* **`Generate_CallFunction`:**  生成调用普通 JavaScript 函数的汇编代码，包括处理 `this` 的转换（根据函数是否为严格模式或原生函数）。
* **`Generate_CallBoundFunctionImpl`:**  生成调用绑定函数的汇编代码，包括将绑定参数压入栈中。
* **`Generate_Call`:**  生成通用的函数调用汇编代码，根据目标对象的类型 (JSFunction, BoundFunction, Proxy 等) 分发到不同的处理逻辑。
* **`Generate_ConstructFunction`:**  生成调用普通 JavaScript 构造函数的汇编代码。
* **`Generate_ConstructBoundFunction`:**  生成调用绑定构造函数的汇编代码。
* **`Generate_Construct`:**  生成通用的对象构造汇编代码，根据目标对象的类型分发到不同的构造逻辑。
* **`Generate_WasmLiftoffFrameSetup`:**  生成 WebAssembly Liftoff 执行的帧设置代码，用于分配反馈向量。
* **`Generate_WasmCompileLazy`:**  生成 WebAssembly 延迟编译的汇编代码。
* **`Generate_WasmDebugBreak`:**  生成 WebAssembly 调试断点的汇编代码。
* **`SwitchStackState`, `SwitchStackPointerAndSimulatorStackLimit`, `FillJumpBuffer`, `LoadJumpBuffer`, `SaveState`, `LoadTargetJumpBuffer`:** 这些函数是为 WebAssembly 协程支持生成汇编代码的辅助函数，用于管理栈的切换和状态。

**关于源代码类型:**

代码以 `.cc` 结尾，因此它是 **C++ 源代码**，而不是 Torque 源代码。如果以 `.tq` 结尾，那才是 Torque 源代码。 Torque 是一种 V8 自研的类型化汇编语言，用于生成高效的内置函数代码。

**与 JavaScript 的关系和示例:**

这段 C++ 代码最终生成的是 ARM64 汇编指令，这些指令实现了 JavaScript 的核心功能。以下是一些与代码功能相关的 JavaScript 示例：

* **`Generate_CallOrConstructVarargs` / `Generate_CallOrConstructForwardVarargs`:**
  ```javascript
  function myFunction(...args) {
    console.log(args);
  }
  myFunction(1, 2, 3); // 使用剩余参数
  myFunction.apply(null, [4, 5, 6]); // 使用 apply 调用
  ```

* **`Generate_CallFunction` / `Generate_Call`:**
  ```javascript
  function greet(name) {
    console.log(`Hello, ${name}!`);
  }
  greet("World"); // 普通函数调用

  const obj = { message: "Hi" };
  function sayMessage() {
    console.log(this.message);
  }
  sayMessage.call(obj); // 使用 call 改变 this 上下文
  ```

* **`Generate_ConstructFunction` / `Generate_Construct`:**
  ```javascript
  class MyClass {
    constructor(value) {
      this.value = value;
    }
  }
  const instance = new MyClass(10); // 使用 new 操作符创建对象
  ```

* **`Generate_CallBoundFunctionImpl`:**
  ```javascript
  function add(a, b) {
    return a + b;
  }
  const add5 = add.bind(null, 5); // 创建绑定函数
  console.log(add5(3)); // 调用绑定函数
  ```

**代码逻辑推理和假设输入输出 (以 `Generate_PrepareForCopyingVarargs` 为例):**

**假设输入:**

* `argc` (寄存器 x0):  当前栈上的参数数量 (包括接收者)。假设值为 1 (只有接收者)。
* `len` (寄存器 x4):  需要从参数列表中复制到栈上的元素数量。假设值为 3。

**代码逻辑:**

1. **`__ SlotAddress(src, slots_to_claim);`**: 计算需要在栈上为即将复制的参数预留的空间，`slots_to_claim` 等于 `len` (3)。`src` 将指向栈上预留空间的起始地址。
2. **`__ SlotAddress(dst, 0);`**: `dst` 指向当前栈顶，也就是接收者的位置。
3. **`__ CopyDoubleWords(dst, src, slots_to_copy);`**: 由于 `argc` 为 1，`slots_to_copy` 为 0，所以这部分代码不会执行。
4. **`__ Bind(&init);`**: 跳转到 `init` 标签。
5. **`__ Tbz(len, 0, &exit);`**: 检查 `len` 的最低位是否为 0。由于 `len` 为 3 (奇数)，条件不成立。
6. **`__ Str(xzr, MemOperand(sp, len, LSL, kSystemPointerSizeLog2));`**:  在栈顶偏移 `len * kSystemPointerSize` 的位置写入零寄存器 (`xzr`) 的值。这是为了进行栈对齐。

**假设输出 (执行 `Generate_PrepareForCopyingVarargs` 之后):**

* 栈顶预留了 3 个槽位用于存放即将复制的参数。
* 栈顶偏移 3 个指针大小的位置被写入了 0 (用于对齐)。

**用户常见的编程错误:**

* **调用不可调用对象:**  例如尝试调用一个普通对象或 `undefined`。`Generate_Call` 会检查目标对象是否可调用，并在不可调用时抛出错误。
  ```javascript
  const obj = {};
  obj(); // TypeError: obj is not a function
  ```
* **`new` 操作符用于非构造函数:**  例如尝试 `new` 一个普通函数或箭头函数（在某些情况下）。`Generate_Construct` 会检查目标对象是否可构造。
  ```javascript
  function normalFunction() {
    return 1;
  }
  new normalFunction(); // TypeError: normalFunction is not a constructor
  ```
* **栈溢出:**  传递过多的参数可能导致栈溢出。代码中可以看到对栈溢出的检查 (`__ StackOverflowCheck`)。
  ```javascript
  function recursiveFunction() {
    recursiveFunction();
  }
  try {
    recursiveFunction(); // RangeError: Maximum call stack size exceeded
  } catch (e) {
    console.error(e);
  }
  ```

**功能归纳 (针对第 4 部分):**

这段代码是 `v8/src/builtins/arm64/builtins-arm64.cc` 文件的 **一部分**，它专注于生成 **ARM64 架构下 JavaScript 函数调用和对象构造相关的内置函数的汇编代码**。 具体来说，这部分代码涵盖了处理变长参数、普通函数和绑定函数的调用与构造，以及初步的 WebAssembly 框架设置和延迟编译支持。  此外，还开始涉及到 WebAssembly 协程的栈管理机制。

Prompt: 
```
这是目录为v8/src/builtins/arm64/builtins-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/arm64/builtins-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共7部分，请归纳一下它的功能

"""
2;
    __ SlotAddress(src, slots_to_claim);
    __ SlotAddress(dst, 0);
    __ CopyDoubleWords(dst, src, slots_to_copy);
    __ jmp(&exit);
  }
  // Initialize the alignment slot with a meaningful value. This is only
  // necessary if slots_to_copy is 0, because otherwise the alignment slot
  // already contains a valid value. In case slots_to_copy is even, then the
  // alignment slot contains the last parameter passed over the stack. In case
  // slots_to_copy is odd, then the alignment slot is that alignment slot when
  // CallVarArgs (or similar) was called, and already got initialized for that
  // call.
  {
    __ Bind(&init);
    // This code here is only reached when the number of stack parameters is 0.
    // In that case we have to initialize the alignment slot if there is one.
    __ Tbz(len, 0, &exit);
    __ Str(xzr, MemOperand(sp, len, LSL, kSystemPointerSizeLog2));
  }
  __ Bind(&exit);
}

}  // namespace

// static
// TODO(v8:11615): Observe Code::kMaxArguments in CallOrConstructVarargs
void Builtins::Generate_CallOrConstructVarargs(MacroAssembler* masm,
                                               Builtin target_builtin) {
  // ----------- S t a t e -------------
  //  -- x1 : target
  //  -- x0 : number of parameters on the stack
  //  -- x2 : arguments list (a FixedArray)
  //  -- x4 : len (number of elements to push from args)
  //  -- x3 : new.target (for [[Construct]])
  // -----------------------------------
  if (v8_flags.debug_code) {
    // Allow x2 to be a FixedArray, or a FixedDoubleArray if x4 == 0.
    Label ok, fail;
    __ AssertNotSmi(x2, AbortReason::kOperandIsNotAFixedArray);
    __ LoadTaggedField(x10, FieldMemOperand(x2, HeapObject::kMapOffset));
    __ Ldrh(x13, FieldMemOperand(x10, Map::kInstanceTypeOffset));
    __ Cmp(x13, FIXED_ARRAY_TYPE);
    __ B(eq, &ok);
    __ Cmp(x13, FIXED_DOUBLE_ARRAY_TYPE);
    __ B(ne, &fail);
    __ Cmp(x4, 0);
    __ B(eq, &ok);
    // Fall through.
    __ bind(&fail);
    __ Abort(AbortReason::kOperandIsNotAFixedArray);

    __ bind(&ok);
  }

  Register arguments_list = x2;
  Register argc = x0;
  Register len = x4;

  Label stack_overflow;
  __ StackOverflowCheck(len, &stack_overflow);

  // Skip argument setup if we don't need to push any varargs.
  Label done;
  __ Cbz(len, &done);

  Generate_PrepareForCopyingVarargs(masm, argc, len);

  // Push varargs.
  {
    Label loop;
    Register src = x10;
    Register undefined_value = x12;
    Register scratch = x13;
    __ Add(src, arguments_list,
           OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag);
#if !V8_STATIC_ROOTS_BOOL
    // We do not use the CompareRoot macro without static roots as it would do a
    // LoadRoot behind the scenes and we want to avoid that in a loop.
    Register the_hole_value = x11;
    __ LoadTaggedRoot(the_hole_value, RootIndex::kTheHoleValue);
#endif  // !V8_STATIC_ROOTS_BOOL
    __ LoadRoot(undefined_value, RootIndex::kUndefinedValue);
    // TODO(all): Consider using Ldp and Stp.
    Register dst = x16;
    __ SlotAddress(dst, argc);
    __ Add(argc, argc, len);  // Update new argc.
    __ Bind(&loop);
    __ Sub(len, len, 1);
    __ LoadTaggedField(scratch, MemOperand(src, kTaggedSize, PostIndex));
#if V8_STATIC_ROOTS_BOOL
    __ CompareRoot(scratch, RootIndex::kTheHoleValue);
#else
    __ CmpTagged(scratch, the_hole_value);
#endif
    __ Csel(scratch, scratch, undefined_value, ne);
    __ Str(scratch, MemOperand(dst, kSystemPointerSize, PostIndex));
    __ Cbnz(len, &loop);
  }
  __ Bind(&done);
  // Tail-call to the actual Call or Construct builtin.
  __ TailCallBuiltin(target_builtin);

  __ bind(&stack_overflow);
  __ TailCallRuntime(Runtime::kThrowStackOverflow);
}

// static
void Builtins::Generate_CallOrConstructForwardVarargs(MacroAssembler* masm,
                                                      CallOrConstructMode mode,
                                                      Builtin target_builtin) {
  // ----------- S t a t e -------------
  //  -- x0 : the number of arguments
  //  -- x3 : the new.target (for [[Construct]] calls)
  //  -- x1 : the target to call (can be any Object)
  //  -- x2 : start index (to support rest parameters)
  // -----------------------------------

  Register argc = x0;
  Register start_index = x2;

  // Check if new.target has a [[Construct]] internal method.
  if (mode == CallOrConstructMode::kConstruct) {
    Label new_target_constructor, new_target_not_constructor;
    __ JumpIfSmi(x3, &new_target_not_constructor);
    __ LoadTaggedField(x5, FieldMemOperand(x3, HeapObject::kMapOffset));
    __ Ldrb(x5, FieldMemOperand(x5, Map::kBitFieldOffset));
    __ TestAndBranchIfAnySet(x5, Map::Bits1::IsConstructorBit::kMask,
                             &new_target_constructor);
    __ Bind(&new_target_not_constructor);
    {
      FrameScope scope(masm, StackFrame::MANUAL);
      __ EnterFrame(StackFrame::INTERNAL);
      __ PushArgument(x3);
      __ CallRuntime(Runtime::kThrowNotConstructor);
      __ Unreachable();
    }
    __ Bind(&new_target_constructor);
  }

  Register len = x6;
  Label stack_done, stack_overflow;
  __ Ldr(len, MemOperand(fp, StandardFrameConstants::kArgCOffset));
  __ Subs(len, len, kJSArgcReceiverSlots);
  __ Subs(len, len, start_index);
  __ B(le, &stack_done);
  // Check for stack overflow.
  __ StackOverflowCheck(len, &stack_overflow);

  Generate_PrepareForCopyingVarargs(masm, argc, len);

  // Push varargs.
  {
    Register args_fp = x5;
    Register dst = x13;
    // Point to the fist argument to copy from (skipping receiver).
    __ Add(args_fp, fp,
           CommonFrameConstants::kFixedFrameSizeAboveFp + kSystemPointerSize);
    __ lsl(start_index, start_index, kSystemPointerSizeLog2);
    __ Add(args_fp, args_fp, start_index);
    // Point to the position to copy to.
    __ SlotAddress(dst, argc);
    // Update total number of arguments.
    __ Add(argc, argc, len);
    __ CopyDoubleWords(dst, args_fp, len);
  }

  __ Bind(&stack_done);
  // Tail-call to the actual Call or Construct builtin.
  __ TailCallBuiltin(target_builtin);

  __ Bind(&stack_overflow);
  __ TailCallRuntime(Runtime::kThrowStackOverflow);
}

// static
void Builtins::Generate_CallFunction(MacroAssembler* masm,
                                     ConvertReceiverMode mode) {
  ASM_LOCATION("Builtins::Generate_CallFunction");
  // ----------- S t a t e -------------
  //  -- x0 : the number of arguments
  //  -- x1 : the function to call (checked to be a JSFunction)
  // -----------------------------------
  __ AssertCallableFunction(x1);

  __ LoadTaggedField(
      x2, FieldMemOperand(x1, JSFunction::kSharedFunctionInfoOffset));

  // Enter the context of the function; ToObject has to run in the function
  // context, and we also need to take the global proxy from the function
  // context in case of conversion.
  __ LoadTaggedField(cp, FieldMemOperand(x1, JSFunction::kContextOffset));
  // We need to convert the receiver for non-native sloppy mode functions.
  Label done_convert;
  __ Ldr(w3, FieldMemOperand(x2, SharedFunctionInfo::kFlagsOffset));
  __ TestAndBranchIfAnySet(w3,
                           SharedFunctionInfo::IsNativeBit::kMask |
                               SharedFunctionInfo::IsStrictBit::kMask,
                           &done_convert);
  {
    // ----------- S t a t e -------------
    //  -- x0 : the number of arguments
    //  -- x1 : the function to call (checked to be a JSFunction)
    //  -- x2 : the shared function info.
    //  -- cp : the function context.
    // -----------------------------------

    if (mode == ConvertReceiverMode::kNullOrUndefined) {
      // Patch receiver to global proxy.
      __ LoadGlobalProxy(x3);
    } else {
      Label convert_to_object, convert_receiver;
      __ Peek(x3, __ ReceiverOperand());
      __ JumpIfSmi(x3, &convert_to_object);
      __ JumpIfJSAnyIsNotPrimitive(x3, x4, &done_convert);
      if (mode != ConvertReceiverMode::kNotNullOrUndefined) {
        Label convert_global_proxy;
        __ JumpIfRoot(x3, RootIndex::kUndefinedValue, &convert_global_proxy);
        __ JumpIfNotRoot(x3, RootIndex::kNullValue, &convert_to_object);
        __ Bind(&convert_global_proxy);
        {
          // Patch receiver to global proxy.
          __ LoadGlobalProxy(x3);
        }
        __ B(&convert_receiver);
      }
      __ Bind(&convert_to_object);
      {
        // Convert receiver using ToObject.
        // TODO(bmeurer): Inline the allocation here to avoid building the frame
        // in the fast case? (fall back to AllocateInNewSpace?)
        FrameScope scope(masm, StackFrame::INTERNAL);
        __ SmiTag(x0);
        __ Push(padreg, x0, x1, cp);
        __ Mov(x0, x3);
        __ CallBuiltin(Builtin::kToObject);
        __ Mov(x3, x0);
        __ Pop(cp, x1, x0, padreg);
        __ SmiUntag(x0);
      }
      __ LoadTaggedField(
          x2, FieldMemOperand(x1, JSFunction::kSharedFunctionInfoOffset));
      __ Bind(&convert_receiver);
    }
    __ Poke(x3, __ ReceiverOperand());
  }
  __ Bind(&done_convert);

  // ----------- S t a t e -------------
  //  -- x0 : the number of arguments
  //  -- x1 : the function to call (checked to be a JSFunction)
  //  -- x2 : the shared function info.
  //  -- cp : the function context.
  // -----------------------------------

#ifdef V8_ENABLE_LEAPTIERING
  __ InvokeFunctionCode(x1, no_reg, x0, InvokeType::kJump);
#else
  __ Ldrh(x2,
          FieldMemOperand(x2, SharedFunctionInfo::kFormalParameterCountOffset));
  __ InvokeFunctionCode(x1, no_reg, x2, x0, InvokeType::kJump);
#endif  // V8_ENABLE_LEAPTIERING
}

namespace {

void Generate_PushBoundArguments(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- x0 : the number of arguments
  //  -- x1 : target (checked to be a JSBoundFunction)
  //  -- x3 : new.target (only in case of [[Construct]])
  // -----------------------------------

  Register bound_argc = x4;
  Register bound_argv = x2;

  // Load [[BoundArguments]] into x2 and length of that into x4.
  Label no_bound_arguments;
  __ LoadTaggedField(
      bound_argv, FieldMemOperand(x1, JSBoundFunction::kBoundArgumentsOffset));
  __ SmiUntagField(bound_argc,
                   FieldMemOperand(bound_argv, offsetof(FixedArray, length_)));
  __ Cbz(bound_argc, &no_bound_arguments);
  {
    // ----------- S t a t e -------------
    //  -- x0 : the number of arguments
    //  -- x1 : target (checked to be a JSBoundFunction)
    //  -- x2 : the [[BoundArguments]] (implemented as FixedArray)
    //  -- x3 : new.target (only in case of [[Construct]])
    //  -- x4 : the number of [[BoundArguments]]
    // -----------------------------------

    Register argc = x0;

    // Check for stack overflow.
    {
      // Check the stack for overflow. We are not trying to catch interruptions
      // (i.e. debug break and preemption) here, so check the "real stack
      // limit".
      Label done;
      __ LoadStackLimit(x10, StackLimitKind::kRealStackLimit);
      // Make x10 the space we have left. The stack might already be overflowed
      // here which will cause x10 to become negative.
      __ Sub(x10, sp, x10);
      // Check if the arguments will overflow the stack.
      __ Cmp(x10, Operand(bound_argc, LSL, kSystemPointerSizeLog2));
      __ B(gt, &done);
      __ TailCallRuntime(Runtime::kThrowStackOverflow);
      __ Bind(&done);
    }

    Label copy_bound_args;
    Register total_argc = x15;
    Register slots_to_claim = x12;
    Register scratch = x10;
    Register receiver = x14;

    __ Sub(argc, argc, kJSArgcReceiverSlots);
    __ Add(total_argc, argc, bound_argc);
    __ Peek(receiver, 0);

    // Round up slots_to_claim to an even number if it is odd.
    __ Add(slots_to_claim, bound_argc, 1);
    __ Bic(slots_to_claim, slots_to_claim, 1);
    __ Claim(slots_to_claim, kSystemPointerSize);

    __ Tbz(bound_argc, 0, &copy_bound_args);
    {
      Label argc_even;
      __ Tbz(argc, 0, &argc_even);
      // Arguments count is odd (with the receiver it's even), so there's no
      // alignment padding above the arguments and we have to "add" it. We
      // claimed bound_argc + 1, since it is odd and it was rounded up. +1 here
      // is for stack alignment padding.
      // 1. Shift args one slot down.
      {
        Register copy_from = x11;
        Register copy_to = x12;
        __ SlotAddress(copy_to, slots_to_claim);
        __ Add(copy_from, copy_to, kSystemPointerSize);
        __ CopyDoubleWords(copy_to, copy_from, argc);
      }
      // 2. Write a padding in the last slot.
      __ Add(scratch, total_argc, 1);
      __ Str(padreg, MemOperand(sp, scratch, LSL, kSystemPointerSizeLog2));
      __ B(&copy_bound_args);

      __ Bind(&argc_even);
      // Arguments count is even (with the receiver it's odd), so there's an
      // alignment padding above the arguments and we can reuse it. We need to
      // claim bound_argc - 1, but we claimed bound_argc + 1, since it is odd
      // and it was rounded up.
      // 1. Drop 2.
      __ Drop(2);
      // 2. Shift args one slot up.
      {
        Register copy_from = x11;
        Register copy_to = x12;
        __ SlotAddress(copy_to, total_argc);
        __ Sub(copy_from, copy_to, kSystemPointerSize);
        __ CopyDoubleWords(copy_to, copy_from, argc,
                           MacroAssembler::kSrcLessThanDst);
      }
    }

    // If bound_argc is even, there is no alignment massage to do, and we have
    // already claimed the correct number of slots (bound_argc).
    __ Bind(&copy_bound_args);

    // Copy the receiver back.
    __ Poke(receiver, 0);
    // Copy [[BoundArguments]] to the stack (below the receiver).
    {
      Label loop;
      Register counter = bound_argc;
      Register copy_to = x12;
      __ Add(bound_argv, bound_argv,
             OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag);
      __ SlotAddress(copy_to, 1);
      __ Bind(&loop);
      __ Sub(counter, counter, 1);
      __ LoadTaggedField(scratch,
                         MemOperand(bound_argv, kTaggedSize, PostIndex));
      __ Str(scratch, MemOperand(copy_to, kSystemPointerSize, PostIndex));
      __ Cbnz(counter, &loop);
    }
    // Update argc.
    __ Add(argc, total_argc, kJSArgcReceiverSlots);
  }
  __ Bind(&no_bound_arguments);
}

}  // namespace

// static
void Builtins::Generate_CallBoundFunctionImpl(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- x0 : the number of arguments
  //  -- x1 : the function to call (checked to be a JSBoundFunction)
  // -----------------------------------
  __ AssertBoundFunction(x1);

  // Patch the receiver to [[BoundThis]].
  __ LoadTaggedField(x10,
                     FieldMemOperand(x1, JSBoundFunction::kBoundThisOffset));
  __ Poke(x10, __ ReceiverOperand());

  // Push the [[BoundArguments]] onto the stack.
  Generate_PushBoundArguments(masm);

  // Call the [[BoundTargetFunction]] via the Call builtin.
  __ LoadTaggedField(
      x1, FieldMemOperand(x1, JSBoundFunction::kBoundTargetFunctionOffset));
  __ TailCallBuiltin(Builtins::Call());
}

// static
void Builtins::Generate_Call(MacroAssembler* masm, ConvertReceiverMode mode) {
  // ----------- S t a t e -------------
  //  -- x0 : the number of arguments
  //  -- x1 : the target to call (can be any Object).
  // -----------------------------------
  Register target = x1;
  Register map = x4;
  Register instance_type = x5;
  DCHECK(!AreAliased(x0, target, map, instance_type));

  Label non_callable, class_constructor;
  __ JumpIfSmi(target, &non_callable);
  __ LoadMap(map, target);
  __ CompareInstanceTypeRange(map, instance_type,
                              FIRST_CALLABLE_JS_FUNCTION_TYPE,
                              LAST_CALLABLE_JS_FUNCTION_TYPE);
  __ TailCallBuiltin(Builtins::CallFunction(mode), ls);
  __ Cmp(instance_type, JS_BOUND_FUNCTION_TYPE);
  __ TailCallBuiltin(Builtin::kCallBoundFunction, eq);

  // Check if target has a [[Call]] internal method.
  {
    Register flags = x4;
    __ Ldrb(flags, FieldMemOperand(map, Map::kBitFieldOffset));
    map = no_reg;
    __ TestAndBranchIfAllClear(flags, Map::Bits1::IsCallableBit::kMask,
                               &non_callable);
  }

  // Check if target is a proxy and call CallProxy external builtin
  __ Cmp(instance_type, JS_PROXY_TYPE);
  __ TailCallBuiltin(Builtin::kCallProxy, eq);

  // Check if target is a wrapped function and call CallWrappedFunction external
  // builtin
  __ Cmp(instance_type, JS_WRAPPED_FUNCTION_TYPE);
  __ TailCallBuiltin(Builtin::kCallWrappedFunction, eq);

  // ES6 section 9.2.1 [[Call]] ( thisArgument, argumentsList)
  // Check that the function is not a "classConstructor".
  __ Cmp(instance_type, JS_CLASS_CONSTRUCTOR_TYPE);
  __ B(eq, &class_constructor);

  // 2. Call to something else, which might have a [[Call]] internal method (if
  // not we raise an exception).
  // Overwrite the original receiver with the (original) target.
  __ Poke(target, __ ReceiverOperand());

  // Let the "call_as_function_delegate" take care of the rest.
  __ LoadNativeContextSlot(target, Context::CALL_AS_FUNCTION_DELEGATE_INDEX);
  __ TailCallBuiltin(
      Builtins::CallFunction(ConvertReceiverMode::kNotNullOrUndefined));

  // 3. Call to something that is not callable.
  __ bind(&non_callable);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ PushArgument(target);
    __ CallRuntime(Runtime::kThrowCalledNonCallable);
    __ Unreachable();
  }

  // 4. The function is a "classConstructor", need to raise an exception.
  __ bind(&class_constructor);
  {
    FrameScope frame(masm, StackFrame::INTERNAL);
    __ PushArgument(target);
    __ CallRuntime(Runtime::kThrowConstructorNonCallableError);
    __ Unreachable();
  }
}

// static
void Builtins::Generate_ConstructFunction(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- x0 : the number of arguments
  //  -- x1 : the constructor to call (checked to be a JSFunction)
  //  -- x3 : the new target (checked to be a constructor)
  // -----------------------------------
  __ AssertConstructor(x1);
  __ AssertFunction(x1);

  // Calling convention for function specific ConstructStubs require
  // x2 to contain either an AllocationSite or undefined.
  __ LoadRoot(x2, RootIndex::kUndefinedValue);

  Label call_generic_stub;

  // Jump to JSBuiltinsConstructStub or JSConstructStubGeneric.
  __ LoadTaggedField(
      x4, FieldMemOperand(x1, JSFunction::kSharedFunctionInfoOffset));
  __ Ldr(w4, FieldMemOperand(x4, SharedFunctionInfo::kFlagsOffset));
  __ TestAndBranchIfAllClear(
      w4, SharedFunctionInfo::ConstructAsBuiltinBit::kMask, &call_generic_stub);

  __ TailCallBuiltin(Builtin::kJSBuiltinsConstructStub);

  __ bind(&call_generic_stub);
  __ TailCallBuiltin(Builtin::kJSConstructStubGeneric);
}

// static
void Builtins::Generate_ConstructBoundFunction(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- x0 : the number of arguments
  //  -- x1 : the function to call (checked to be a JSBoundFunction)
  //  -- x3 : the new target (checked to be a constructor)
  // -----------------------------------
  __ AssertConstructor(x1);
  __ AssertBoundFunction(x1);

  // Push the [[BoundArguments]] onto the stack.
  Generate_PushBoundArguments(masm);

  // Patch new.target to [[BoundTargetFunction]] if new.target equals target.
  {
    Label done;
    __ CmpTagged(x1, x3);
    __ B(ne, &done);
    __ LoadTaggedField(
        x3, FieldMemOperand(x1, JSBoundFunction::kBoundTargetFunctionOffset));
    __ Bind(&done);
  }

  // Construct the [[BoundTargetFunction]] via the Construct builtin.
  __ LoadTaggedField(
      x1, FieldMemOperand(x1, JSBoundFunction::kBoundTargetFunctionOffset));
  __ TailCallBuiltin(Builtin::kConstruct);
}

// static
void Builtins::Generate_Construct(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- x0 : the number of arguments
  //  -- x1 : the constructor to call (can be any Object)
  //  -- x3 : the new target (either the same as the constructor or
  //          the JSFunction on which new was invoked initially)
  // -----------------------------------
  Register target = x1;
  Register map = x4;
  Register instance_type = x5;
  DCHECK(!AreAliased(x0, target, map, instance_type));

  // Check if target is a Smi.
  Label non_constructor, non_proxy;
  __ JumpIfSmi(target, &non_constructor);

  // Check if target has a [[Construct]] internal method.
  __ LoadTaggedField(map, FieldMemOperand(target, HeapObject::kMapOffset));
  {
    Register flags = x2;
    DCHECK(!AreAliased(x0, target, map, instance_type, flags));
    __ Ldrb(flags, FieldMemOperand(map, Map::kBitFieldOffset));
    __ TestAndBranchIfAllClear(flags, Map::Bits1::IsConstructorBit::kMask,
                               &non_constructor);
  }

  // Dispatch based on instance type.
  __ CompareInstanceTypeRange(map, instance_type, FIRST_JS_FUNCTION_TYPE,
                              LAST_JS_FUNCTION_TYPE);
  __ TailCallBuiltin(Builtin::kConstructFunction, ls);

  // Only dispatch to bound functions after checking whether they are
  // constructors.
  __ Cmp(instance_type, JS_BOUND_FUNCTION_TYPE);
  __ TailCallBuiltin(Builtin::kConstructBoundFunction, eq);

  // Only dispatch to proxies after checking whether they are constructors.
  __ Cmp(instance_type, JS_PROXY_TYPE);
  __ B(ne, &non_proxy);
  __ TailCallBuiltin(Builtin::kConstructProxy);

  // Called Construct on an exotic Object with a [[Construct]] internal method.
  __ bind(&non_proxy);
  {
    // Overwrite the original receiver with the (original) target.
    __ Poke(target, __ ReceiverOperand());

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
// registers (see wasm-linkage.h). They might be overwritten in runtime
// calls. We don't have any callee-saved registers in wasm, so no need to
// store anything else.
constexpr RegList kSavedGpRegs = ([]() constexpr {
  RegList saved_gp_regs;
  for (Register gp_param_reg : wasm::kGpParamRegisters) {
    saved_gp_regs.set(gp_param_reg);
  }
  // The instance data has already been stored in the fixed part of the frame.
  saved_gp_regs.clear(kWasmImplicitArgRegister);
  // All set registers were unique. The instance is skipped.
  CHECK_EQ(saved_gp_regs.Count(), arraysize(wasm::kGpParamRegisters) - 1);
  // We push a multiple of 16 bytes.
  CHECK_EQ(0, saved_gp_regs.Count() % 2);
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
// Due to stack alignment restrictions, this builtin adds the feedback vector
// plus a filler to the stack. The stack pointer will be
// moved an appropriate distance by {PatchPrepareStackFrame}.
//
// [     (unused)       ]  <-- sp
// [  feedback vector   ]
// [ Wasm instance data ]
// [ WASM frame marker  ]
// [     saved fp       ]  <-- fp
void Builtins::Generate_WasmLiftoffFrameSetup(MacroAssembler* masm) {
  Register func_index = wasm::kLiftoffFrameSetupFunctionReg;
  Register vector = x9;
  Register scratch = x10;
  Label allocate_vector, done;

  __ LoadTaggedField(
      vector, FieldMemOperand(kWasmImplicitArgRegister,
                              WasmTrustedInstanceData::kFeedbackVectorsOffset));
  __ Add(vector, vector, Operand(func_index, LSL, kTaggedSizeLog2));
  __ LoadTaggedField(vector,
                     FieldMemOperand(vector, OFFSET_OF_DATA_START(FixedArray)));
  __ JumpIfSmi(vector, &allocate_vector);
  __ bind(&done);
  __ Push(vector, xzr);
  __ Ret();

  __ bind(&allocate_vector);
  // Feedback vector doesn't exist yet. Call the runtime to allocate it.
  // We temporarily change the frame type for this, because we need special
  // handling by the stack walker in case of GC.
  __ Mov(scratch, StackFrame::TypeToMarker(StackFrame::WASM_LIFTOFF_SETUP));
  __ Str(scratch, MemOperand(fp, TypedFrameConstants::kFrameTypeOffset));
  // Save registers.
  __ PushXRegList(kSavedGpRegs);
  __ PushQRegList(kSavedFpRegs);
  __ Push<MacroAssembler::kSignLR>(lr, xzr);  // xzr is for alignment.

  // Arguments to the runtime function: instance data, func_index, and an
  // additional stack slot for the NativeModule. The first pushed register
  // is for alignment. {x0} and {x1} are picked arbitrarily.
  __ SmiTag(func_index);
  __ Push(x0, kWasmImplicitArgRegister, func_index, x1);
  __ Mov(cp, Smi::zero());
  __ CallRuntime(Runtime::kWasmAllocateFeedbackVector, 3);
  __ Mov(vector, kReturnRegister0);

  // Restore registers and frame type.
  __ Pop<MacroAssembler::kAuthLR>(xzr, lr);
  __ PopQRegList(kSavedFpRegs);
  __ PopXRegList(kSavedGpRegs);
  // Restore the instance data from the frame.
  __ Ldr(kWasmImplicitArgRegister,
         MemOperand(fp, WasmFrameConstants::kWasmInstanceDataOffset));
  __ Mov(scratch, StackFrame::TypeToMarker(StackFrame::WASM));
  __ Str(scratch, MemOperand(fp, TypedFrameConstants::kFrameTypeOffset));
  __ B(&done);
}

void Builtins::Generate_WasmCompileLazy(MacroAssembler* masm) {
  // The function index was put in w8 by the jump table trampoline.
  // Sign extend and convert to Smi for the runtime call.
  __ sxtw(kWasmCompileLazyFuncIndexRegister,
          kWasmCompileLazyFuncIndexRegister.W());
  __ SmiTag(kWasmCompileLazyFuncIndexRegister);

  UseScratchRegisterScope temps(masm);
  temps.Exclude(x17);
  {
    HardAbortScope hard_abort(masm);  // Avoid calls to Abort.
    FrameScope scope(masm, StackFrame::INTERNAL);
    // Manually save the instance data (which kSavedGpRegs skips because its
    // other use puts it into the fixed frame anyway). The stack slot is valid
    // because the {FrameScope} (via {EnterFrame}) always reserves it (for stack
    // alignment reasons). The instance is needed because once this builtin is
    // done, we'll call a regular Wasm function.
    __ Str(kWasmImplicitArgRegister,
           MemOperand(fp, WasmFrameConstants::kWasmInstanceDataOffset));

    // Save registers that we need to keep alive across the runtime call.
    __ PushXRegList(kSavedGpRegs);
    __ PushQRegList(kSavedFpRegs);

    __ Push(kWasmImplicitArgRegister, kWasmCompileLazyFuncIndexRegister);
    // Initialize the JavaScript context with 0. CEntry will use it to
    // set the current context on the isolate.
    __ Mov(cp, Smi::zero());
    __ CallRuntime(Runtime::kWasmCompileLazy, 2);

    // Untag the returned Smi into into x17 (ip1), for later use.
    static_assert(!kSavedGpRegs.has(x17));
    __ SmiUntag(x17, kReturnRegister0);

    // Restore registers.
    __ PopQRegList(kSavedFpRegs);
    __ PopXRegList(kSavedGpRegs);
    // Restore the instance data from the frame.
    __ Ldr(kWasmImplicitArgRegister,
           MemOperand(fp, WasmFrameConstants::kWasmInstanceDataOffset));
  }

  // The runtime function returned the jump table slot offset as a Smi (now in
  // x17). Use that to compute the jump target. Use x17 (ip1) for the branch
  // target, to be compliant with CFI.
  constexpr Register temp = x8;
  static_assert(!kSavedGpRegs.has(temp));
  __ ldr(temp, FieldMemOperand(kWasmImplicitArgRegister,
                               WasmTrustedInstanceData::kJumpTableStartOffset));
  __ add(x17, temp, Operand(x17));
  // Finally, jump to the jump table slot for the function.
  __ Jump(x17);
}

void Builtins::Generate_WasmDebugBreak(MacroAssembler* masm) {
  HardAbortScope hard_abort(masm);  // Avoid calls to Abort.
  {
    FrameScope scope(masm, StackFrame::WASM_DEBUG_BREAK);

    // Save all parameter registers. They might hold live values, we restore
    // them after the runtime call.
    __ PushXRegList(WasmDebugBreakFrameConstants::kPushedGpRegs);
    __ PushQRegList(WasmDebugBreakFrameConstants::kPushedFpRegs);

    // Initialize the JavaScript context with 0. CEntry will use it to
    // set the current context on the isolate.
    __ Move(cp, Smi::zero());
    __ CallRuntime(Runtime::kWasmDebugBreak, 0);

    // Restore registers.
    __ PopQRegList(WasmDebugBreakFrameConstants::kPushedFpRegs);
    __ PopXRegList(WasmDebugBreakFrameConstants::kPushedGpRegs);
  }
  __ Ret();
}

namespace {
// Check that the stack was in the old state (if generated code assertions are
// enabled), and switch to the new state.
void SwitchStackState(MacroAssembler* masm, Register jmpbuf,
                      Register tmp,
                      wasm::JumpBuffer::StackState old_state,
                      wasm::JumpBuffer::StackState new_state) {
#if V8_ENABLE_SANDBOX
  __ Ldr(tmp.W(), MemOperand(jmpbuf, wasm::kJmpBufStateOffset));
  __ Cmp(tmp.W(), old_state);
  Label ok;
  __ B(&ok, eq);
  __ Trap();
  __ bind(&ok);
#endif
  __ Mov(tmp.W(), new_state);
  __ Str(tmp.W(), MemOperand(jmpbuf, wasm::kJmpBufStateOffset));
}

// Switch the stack pointer. Also switch the simulator's stack limit when
// running on the simulator. This needs to be done as close as possible to
// changing the stack pointer, as a mismatch between the stack pointer and the
// simulator's stack limit can cause stack access check failures.
void SwitchStackPointerAndSimulatorStackLimit(MacroAssembler* masm,
                                              Register jmpbuf, Register tmp) {
  if (masm->options().enable_simulator_code) {
    UseScratchRegisterScope temps(masm);
    temps.Exclude(x16);
    __ Ldr(tmp, MemOperand(jmpbuf, wasm::kJmpBufSpOffset));
    __ Ldr(x16, MemOperand(jmpbuf, wasm::kJmpBufStackLimitOffset));
    __ Mov(sp, tmp);
    __ hlt(kImmExceptionIsSwitchStackLimit);
  } else {
    __ Ldr(tmp, MemOperand(jmpbuf, wasm::kJmpBufSpOffset));
    __ Mov(sp, tmp);
  }
}

void FillJumpBuffer(MacroAssembler* masm, Register jmpbuf, Label* pc,
                    Register tmp) {
  __ Mov(tmp, sp);
  __ Str(tmp, MemOperand(jmpbuf, wasm::kJmpBufSpOffset));
  __ Str(fp, MemOperand(jmpbuf, wasm::kJmpBufFpOffset));
  __ LoadStackLimit(tmp, StackLimitKind::kRealStackLimit);
  __ Str(tmp, MemOperand(jmpbuf, wasm::kJmpBufStackLimitOffset));
  __ Adr(tmp, pc);
  __ Str(tmp, MemOperand(jmpbuf, wasm::kJmpBufPcOffset));
}

void LoadJumpBuffer(MacroAssembler* masm, Register jmpbuf, bool load_pc,
                    Register tmp, wasm::JumpBuffer::StackState expected_state) {
  SwitchStackPointerAndSimulatorStackLimit(masm, jmpbuf, tmp);
  __ Ldr(fp, MemOperand(jmpbuf, wasm::kJmpBufFpOffset));
  SwitchStackState(masm, jmpbuf, tmp, expected_state, wasm::JumpBuffer::Active);
  if (load_pc) {
    __ Ldr(tmp, MemOperand(jmpbuf, wasm::kJmpBufPcOffset));
    __ Br(tmp);
  }
  // The stack limit in StackGuard is set separately under the ExecutionAccess
  // lock.
}

void SaveState(MacroAssembler* masm, Register active_continuation,
               Register tmp, Label* suspend) {
  Register jmpbuf = tmp;
  __ LoadExternalPointerField(
      jmpbuf,
      FieldMemOperand(active_continuation,
                      WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag);
  UseScratchRegisterScope temps(masm);
  Register scratch = temps.AcquireX();
  FillJumpBuffer(masm, jmpbuf, suspend, scratch);
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
  __ Str(xzr,
         MemOperand(fp, StackSwitchFrameConstants::kGCScanSlotCountOffset));
  // Switch stack!
  LoadJumpBuffer(masm, target_jmpbuf, false, tmp, expected_state);
}

// Updates the stack limit to match the new active stack.
// Pass the {finished_continuation} argument to indi
"""


```