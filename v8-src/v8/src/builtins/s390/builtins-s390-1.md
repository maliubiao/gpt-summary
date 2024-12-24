Response: The user wants a summary of the functionality of the C++ code in the provided snippet. This is the second part of a three-part file. The code seems to define various built-in functions for the s390 architecture within the V8 JavaScript engine. These built-ins are low-level implementations of core JavaScript functionalities.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The file is named `builtins-s390.cc` and is part of the `v8/src/builtins/s390` directory. This strongly suggests it contains architecture-specific implementations of built-in functions for the s390 architecture.

2. **Scan for function definitions:** Look for lines starting with `void Builtins::Generate_`. These are the definitions of the built-in functions.

3. **Group related built-ins:** Notice patterns in the function names and their functionalities. For example, functions starting with `Construct`, `Call`, `Interpreter`, `Wasm`, and `CEntry` seem to form logical groups.

4. **Summarize each group:**
    * **Construct/Call related:**  Functions like `Generate_Construct`, `Generate_Call`, `Generate_ConstructFunction`, `Generate_CallFunction`, and their variations (e.g., `ForwardAllArgs`, `Varargs`, `BoundFunction`) are clearly related to object construction and function calls in JavaScript.
    * **Interpreter related:** Functions with `Interpreter` in their name (`Generate_InterpreterPushArgsThenFastConstructFunction`, `Generate_InterpreterEnterBytecode`, etc.) likely deal with executing JavaScript code within the interpreter.
    * **Deoptimization related:** `Generate_ContinueToCodeStubBuiltin`, `Generate_ContinueToJavaScriptBuiltin`, `Generate_NotifyDeoptimized` are related to transitioning back from optimized code to the interpreter.
    * **Function prototype methods:** `Generate_FunctionPrototypeApply`, `Generate_FunctionPrototypeCall` implement the core `apply` and `call` methods on functions.
    * **Reflect API:** `Generate_ReflectApply`, `Generate_ReflectConstruct` handle the `Reflect.apply` and `Reflect.construct` functionalities.
    * **Varargs handling:** `Generate_CallOrConstructVarargs`, `Generate_CallOrConstructForwardVarargs` deal with functions that accept a variable number of arguments.
    * **Bound functions:** `Generate_CallBoundFunctionImpl`, `Generate_ConstructBoundFunction` handle calls and constructions of bound functions.
    * **Maglev (optimization):** `Generate_MaglevFunctionEntryStackCheck` seems to be related to stack checking during Maglev execution.
    * **WebAssembly (Wasm):**  A significant number of functions with `Wasm` in their names (`Generate_WasmLiftoffFrameSetup`, `Generate_WasmCompileLazy`, `Generate_WasmToJsWrapperAsm`, etc.) are responsible for handling WebAssembly integration within V8, including compilation, execution, and interoperability with JavaScript.
    * **C Entry:** `Generate_CEntry` handles the transition from JavaScript to C++ when calling native built-in functions.

5. **Identify relationships with JavaScript:** For each group, consider the corresponding JavaScript functionality. Provide concise JavaScript examples to illustrate the C++ code's purpose.

6. **Note the "Part 2" indication:**  Explicitly mention that this is part 2 and acknowledge that the previous part likely contained related built-in function implementations. This provides context and hints at the larger scope of the file.

7. **Review and refine:** Check the summary for clarity, accuracy, and completeness. Ensure the JavaScript examples are simple and illustrative. For example, initially, I might have listed individual Wasm built-ins, but grouping them under "WebAssembly integration" provides a better high-level overview. Similarly, combining the various `Construct` and `Call` related functions makes the summary more concise.
这个C++源代码文件（是 `v8/src/builtins/s390/builtins-s390.cc` 的第二部分）定义了更多针对 s390 架构的 V8 JavaScript 引擎的内置函数（built-ins）的实现。 这些内置函数是 V8 虚拟机执行 JavaScript 代码时调用的底层操作。

从代码片段来看，这部分主要关注以下功能：

**1. 构造函数调用相关的内置函数：**

*   **`Generate_ConstructForwardAllArgsImpl`:**  实现了将当前或父帧的所有参数转发给构造函数的逻辑。这通常用于 `super()` 调用或需要将所有接收到的参数传递给另一个构造函数的情况。
*   **`Generate_InterpreterPushArgsThenFastConstructFunction`:**  针对解释器模式下的快速构造函数调用。它负责设置栈帧，推送参数，并根据函数类型（普通函数或内置函数）调用相应的构造逻辑。它还处理隐式接收者的创建。

**2. 解释器入口和执行相关的内置函数：**

*   **`Generate_InterpreterEnterBytecode`:**  负责进入解释器执行字节码。它设置返回地址，初始化分发表，加载字节码数组和偏移量，并跳转到目标字节码。
*   **`Generate_InterpreterEnterAtNextBytecode` 和 `Generate_InterpreterEnterAtBytecode`:**  用于在解释器中跳转到下一个或指定的字节码指令执行。

**3. 代码桩 (Code Stub) 继续执行相关的内置函数：**

*   **`Generate_ContinueToCodeStubBuiltin` 和 `Generate_ContinueToCodeStubBuiltinWithResult`:**  用于从优化代码（代码桩）返回到解释器或其他代码，可以选择是否携带返回值。
*   **`Generate_ContinueToJavaScriptBuiltin` 和 `Generate_ContinueToJavaScriptBuiltinWithResult`:** 类似于上面的函数，但专门用于从 JavaScript 内置函数返回。
*   **`Generate_NotifyDeoptimized`:**  在代码反优化（deoptimization）时被调用，通知运行时。

**4. `Function.prototype.apply` 和 `Function.prototype.call` 的实现：**

*   **`Generate_FunctionPrototypeApply`:**  实现了 `Function.prototype.apply()` 方法，允许以指定的 `this` 值和参数数组调用函数。
*   **`Generate_FunctionPrototypeCall`:**  实现了 `Function.prototype.call()` 方法，允许以指定的 `this` 值和一系列参数调用函数。

**5. `Reflect` API 的实现：**

*   **`Generate_ReflectApply`:**  实现了 `Reflect.apply()` 方法。
*   **`Generate_ReflectConstruct`:**  实现了 `Reflect.construct()` 方法。

**6. 变长参数函数调用和构造相关的内置函数：**

*   **`Generate_CallOrConstructVarargs`:**  用于处理使用剩余参数 (`...args`) 或 `arguments` 对象进行函数调用或构造的情况。它将参数从数组或类数组对象推送到栈上。
*   **`Generate_CallOrConstructForwardVarargs`:**  用于将调用者的变长参数直接转发给被调用的函数或构造函数。

**7. 普通函数调用的内置函数：**

*   **`Generate_CallFunction`:**  实现了普通函数调用的逻辑，包括处理 `this` 值的转换（根据函数是否为严格模式或原生函数）。

**8. 绑定函数调用相关的内置函数：**

*   **`Generate_CallBoundFunctionImpl`:**  实现了调用绑定函数的逻辑，包括设置 `this` 值和推送绑定参数。

**9. `call` 操作的内置函数：**

*   **`Generate_Call`:**  实现了 JavaScript 中的 `call` 操作符或方法调用。它会检查被调用对象的可调用性，并根据对象类型（普通函数、绑定函数、代理等）分发到相应的内置函数。

**10. `construct` 操作的内置函数：**

*   **`Generate_ConstructFunction`:** 专门用于构造 JSFunction 对象。
*   **`Generate_ConstructBoundFunction`:** 专门用于构造绑定函数对象。
*   **`Generate_Construct`:**  实现了 JavaScript 中的 `new` 操作符或构造函数调用。它会检查被调用对象是否为构造函数，并根据对象类型分发到相应的内置函数。

**11. Maglev 优化相关的内置函数:**

*   **`Generate_MaglevFunctionEntryStackCheck`:**  在 Maglev 优化代码的入口进行栈溢出检查。

**12. WebAssembly 相关的内置函数：**

*   这部分包含大量以 `Generate_Wasm` 开头的函数，负责 WebAssembly 代码的执行和与 JavaScript 的互操作，包括：
    *   **`Generate_WasmLiftoffFrameSetup`:** 设置 Liftoff 解释器的栈帧。
    *   **`Generate_WasmCompileLazy`:** 延迟编译 WebAssembly 函数。
    *   **`Generate_WasmDebugBreak`:** 处理 WebAssembly 中的断点。
    *   **`Generate_WasmToJsWrapperAsm`:**  实现 WebAssembly 调用 JavaScript 的包装器。
    *   **`Generate_WasmTrapHandlerLandingPad`:**  WebAssembly 陷阱处理程序的着陆点。
    *   **`Generate_WasmSuspend` 和 `Generate_WasmResume`:**  用于 WebAssembly 的挂起和恢复（可能与异步操作相关）。
    *   **`Generate_WasmReject`:**  处理 WebAssembly 的拒绝（可能与 Promise 相关）。
    *   **`Generate_WasmOnStackReplace`:**  支持 WebAssembly 的栈上替换（OSR）。
    *   **`Generate_JSToWasmWrapperAsm`:**  实现 JavaScript 调用 WebAssembly 的包装器。
    *   **`Generate_WasmHandleStackOverflow`:** 处理 WebAssembly 的栈溢出。

**13. C++ 调用入口的内置函数：**

*   **`Generate_CEntry`:**  实现了从 JavaScript 代码调用 C++ 函数的入口点。它负责设置 C++ 调用的栈帧，传递参数，调用 C++ 函数，处理返回值和异常。

**与 JavaScript 的关系和示例：**

这些内置函数直接对应于 JavaScript 语言的核心特性和 API。以下是一些 JavaScript 示例以及它们可能触发的此文件中定义的内置函数：

*   **构造函数调用：**
    ```javascript
    function MyClass(a, b) {
      this.a = a;
      this.b = b;
    }
    const instance = new MyClass(1, 2);
    ```
    这会触发 `Generate_Construct`，进而可能根据 `MyClass` 的类型触发 `Generate_ConstructFunction` 或 `Generate_ConstructBoundFunction`。

*   **函数调用：**
    ```javascript
    function myFunction(x) {
      console.log(x);
    }
    myFunction(5);
    ```
    这会触发 `Generate_Call`，进而可能触发 `Generate_CallFunction` 或 `Generate_CallBoundFunctionImpl`。

*   **`Function.prototype.apply` 和 `call`：**
    ```javascript
    function greet(greeting) {
      console.log(greeting + ' ' + this.name);
    }
    const person = { name: 'Alice' };
    greet.apply(person, ['Hello']); // 触发 Generate_FunctionPrototypeApply
    greet.call(person, 'Hi');      // 触发 Generate_FunctionPrototypeCall
    ```

*   **`Reflect` API：**
    ```javascript
    function sum(a, b) {
      return a + b;
    }
    const result = Reflect.apply(sum, null, [3, 4]); // 触发 Generate_ReflectApply

    function Point(x, y) {
      this.x = x;
      this.y = y;
    }
    const point = Reflect.construct(Point, [10, 20]); // 触发 Generate_ReflectConstruct
    ```

*   **剩余参数和 `arguments` 对象：**
    ```javascript
    function logArgs(...args) {
      console.log(args);
    }
    logArgs(1, 2, 3); // 可能触发 Generate_CallOrConstructVarargs

    function sumArguments() {
      let total = 0;
      for (let i = 0; i < arguments.length; i++) {
        total += arguments[i];
      }
      return total;
    }
    sumArguments(5, 10); // 可能触发 Generate_CallOrConstructVarargs
    ```

*   **绑定函数：**
    ```javascript
    function multiply(a, b) {
      return a * b;
    }
    const double = multiply.bind(null, 2);
    double(5); // 触发 Generate_CallBoundFunctionImpl

    class MyComponent {
      constructor(name) {
        this.name = name;
        this.handleClick = this.handleClick.bind(this);
      }
      handleClick() {
        console.log('Clicked by ' + this.name);
      }
    }
    ```
    `bind` 操作本身会有内置函数处理，而调用绑定后的 `handleClick` 会触发 `Generate_CallBoundFunctionImpl`.

*   **WebAssembly 调用：**
    ```javascript
    const wasmInstance = // ... 加载和实例化 WebAssembly 模块
    wasmInstance.exports.myWasmFunction(10, 20); // 触发 Generate_JSToWasmWrapperAsm
    ```
    以及 WebAssembly 调用 JavaScript 函数会触发 `Generate_WasmToJsWrapperAsm`.

总而言之，这个代码片段是 V8 JavaScript 引擎在 s390 架构上实现各种核心 JavaScript 功能的蓝图，它将 JavaScript 语言的概念和操作转化为底层的机器指令。 它是 V8 引擎高性能执行 JavaScript 代码的关键组成部分。

Prompt: 
```
这是目录为v8/src/builtins/s390/builtins-s390.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
nalSpread) {
    // Pass the spread in the register r2.
    // r4 already points to the penultimate argument, the spread
    // lies in the next interpreter register.
    __ lay(r6, MemOperand(r6, -kSystemPointerSize));
    __ LoadU64(r4, MemOperand(r6));
  } else {
    __ AssertUndefinedOrAllocationSite(r4, r7);
  }

  if (mode == InterpreterPushArgsMode::kArrayFunction) {
    __ AssertFunction(r3);

    // Tail call to the array construct stub (still in the caller
    // context at this point).
    __ TailCallBuiltin(Builtin::kArrayConstructorImpl);
  } else if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Call the constructor with r2, r3, and r5 unmodified.
    __ TailCallBuiltin(Builtin::kConstructWithSpread);
  } else {
    DCHECK_EQ(InterpreterPushArgsMode::kOther, mode);
    // Call the constructor with r2, r3, and r5 unmodified.
    __ TailCallBuiltin(Builtin::kConstruct);
  }

  __ bind(&stack_overflow);
  {
    __ TailCallRuntime(Runtime::kThrowStackOverflow);
    // Unreachable Code.
    __ bkpt(0);
  }
}

// static
void Builtins::Generate_ConstructForwardAllArgsImpl(
    MacroAssembler* masm, ForwardWhichFrame which_frame) {
  // ----------- S t a t e -------------
  // -- r5 : new target
  // -- r3 : constructor to call
  // -----------------------------------
  Label stack_overflow;

  // Load the frame pointer into r6.
  switch (which_frame) {
    case ForwardWhichFrame::kCurrentFrame:
      __ mov(r6, fp);
      break;
    case ForwardWhichFrame::kParentFrame:
      __ LoadU64(r6, MemOperand(fp, StandardFrameConstants::kCallerFPOffset));
      break;
  }

  // Load the argument count into r2.
  __ LoadU64(r2, MemOperand(r6, StandardFrameConstants::kArgCOffset));
  __ StackOverflowCheck(r2, ip, &stack_overflow);

  // Point r6 to the base of the argument list to forward, excluding the
  // receiver.
  __ AddS64(r6, r6,
            Operand((StandardFrameConstants::kFixedSlotCountAboveFp + 1) *
                    kSystemPointerSize));

  // Copy arguments on the stack. r5 is a scratch register.
  Register argc_without_receiver = ip;
  __ SubS64(argc_without_receiver, r2, Operand(kJSArgcReceiverSlots));
  __ PushArray(r6, argc_without_receiver, r1, r7);

  // Push a slot for the receiver.
  __ mov(r0, Operand::Zero());
  __ push(r0);

  // Call the constructor with r2, r5, and r3 unmodifdied.
  __ TailCallBuiltin(Builtin::kConstruct);

  __ bind(&stack_overflow);
  {
    __ TailCallRuntime(Runtime::kThrowStackOverflow);
    // Unreachable Code.
    __ bkpt(0);
  }
}

namespace {

void NewImplicitReceiver(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  // -- r2 : argument count
  // -- r3 : constructor to call (checked to be a JSFunction)
  // -- r5 : new target
  //
  //  Stack:
  //  -- Implicit Receiver
  //  -- [arguments without receiver]
  //  -- Implicit Receiver
  //  -- Context
  //  -- FastConstructMarker
  //  -- FramePointer
  // -----------------------------------
  Register implicit_receiver = r6;

  // Save live registers.
  __ SmiTag(r2);
  __ Push(r2, r3, r5);
  __ CallBuiltin(Builtin::kFastNewObject);
  // Save result.
  __ Move(implicit_receiver, r2);
  // Restore live registers.
  __ Pop(r2, r3, r5);
  __ SmiUntag(r2);

  // Patch implicit receiver (in arguments)
  __ StoreU64(implicit_receiver, MemOperand(sp, 0 * kSystemPointerSize));
  // Patch second implicit (in construct frame)
  __ StoreU64(
      implicit_receiver,
      MemOperand(fp, FastConstructFrameConstants::kImplicitReceiverOffset));

  // Restore context.
  __ LoadU64(cp, MemOperand(fp, FastConstructFrameConstants::kContextOffset));
}

}  // namespace

// static
void Builtins::Generate_InterpreterPushArgsThenFastConstructFunction(
    MacroAssembler* masm) {
  // ----------- S t a t e -------------
  // -- r2 : argument count
  // -- r3 : constructor to call (checked to be a JSFunction)
  // -- r5 : new target
  // -- r6 : address of the first argument
  // -- cp/r13 : context pointer
  // -----------------------------------
  __ AssertFunction(r3);

  // Check if target has a [[Construct]] internal method.
  Label non_constructor;
  __ LoadMap(r4, r3);
  __ LoadU8(r4, FieldMemOperand(r4, Map::kBitFieldOffset));
  __ TestBit(r4, Map::Bits1::IsConstructorBit::kShift);
  __ beq(&non_constructor);

  // Add a stack check before pushing arguments.
  Label stack_overflow;
  __ StackOverflowCheck(r2, r4, &stack_overflow);

  // Enter a construct frame.
  FrameScope scope(masm, StackFrame::MANUAL);
  __ EnterFrame(StackFrame::FAST_CONSTRUCT);
  // Implicit receiver stored in the construct frame.
  __ LoadRoot(r4, RootIndex::kTheHoleValue);
  __ Push(cp, r4);

  // Push arguments + implicit receiver.
  Register argc_without_receiver = r8;
  __ SubS64(argc_without_receiver, r2, Operand(kJSArgcReceiverSlots));
  // Push the arguments. r6 and r7 will be modified.
  GenerateInterpreterPushArgs(masm, argc_without_receiver, r6, r7);
  // Implicit receiver as part of the arguments (patched later if needed).
  __ push(r4);

  // Check if it is a builtin call.
  Label builtin_call;
  __ LoadTaggedField(
      r4, FieldMemOperand(r3, JSFunction::kSharedFunctionInfoOffset));
  __ LoadU32(r4, FieldMemOperand(r4, SharedFunctionInfo::kFlagsOffset));
  __ AndP(r0, r4, Operand(SharedFunctionInfo::ConstructAsBuiltinBit::kMask));
  __ bne(&builtin_call);

  // Check if we need to create an implicit receiver.
  Label not_create_implicit_receiver;
  __ DecodeField<SharedFunctionInfo::FunctionKindBits>(r4);
  __ JumpIfIsInRange(
      r4, r4, static_cast<uint32_t>(FunctionKind::kDefaultDerivedConstructor),
      static_cast<uint32_t>(FunctionKind::kDerivedConstructor),
      &not_create_implicit_receiver);
  NewImplicitReceiver(masm);
  __ bind(&not_create_implicit_receiver);

  // Call the function.
  __ InvokeFunctionWithNewTarget(r3, r5, r2, InvokeType::kCall);

  // ----------- S t a t e -------------
  //  -- r0     constructor result
  //
  //  Stack:
  //  -- Implicit Receiver
  //  -- Context
  //  -- FastConstructMarker
  //  -- FramePointer
  // -----------------------------------

  // Store offset of return address for deoptimizer.
  masm->isolate()->heap()->SetConstructStubInvokeDeoptPCOffset(
      masm->pc_offset());

  // If the result is an object (in the ECMA sense), we should get rid
  // of the receiver and use the result; see ECMA-262 section 13.2.2-7
  // on page 74.
  Label use_receiver, do_throw, leave_and_return, check_receiver;

  // If the result is undefined, we jump out to using the implicit receiver.
  __ JumpIfNotRoot(r2, RootIndex::kUndefinedValue, &check_receiver);

  // Otherwise we do a smi check and fall through to check if the return value
  // is a valid receiver.

  // Throw away the result of the constructor invocation and use the
  // on-stack receiver as the result.
  __ bind(&use_receiver);
  __ LoadU64(
      r2, MemOperand(fp, FastConstructFrameConstants::kImplicitReceiverOffset));
  __ JumpIfRoot(r2, RootIndex::kTheHoleValue, &do_throw);

  __ bind(&leave_and_return);
  // Leave construct frame.
  __ LeaveFrame(StackFrame::CONSTRUCT);
  __ Ret();

  __ bind(&check_receiver);
  // If the result is a smi, it is *not* an object in the ECMA sense.
  __ JumpIfSmi(r2, &use_receiver);

  // If the type of the result (stored in its map) is less than
  // FIRST_JS_RECEIVER_TYPE, it is not an object in the ECMA sense.
  static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
  __ CompareObjectType(r2, r6, r7, FIRST_JS_RECEIVER_TYPE);
  __ bge(&leave_and_return);
  __ b(&use_receiver);

  __ bind(&builtin_call);
  // TODO(victorgomes): Check the possibility to turn this into a tailcall.
  __ InvokeFunctionWithNewTarget(r3, r5, r2, InvokeType::kCall);
  __ LeaveFrame(StackFrame::FAST_CONSTRUCT);
  __ Ret();

  __ bind(&do_throw);
  // Restore the context from the frame.
  __ LoadU64(cp, MemOperand(fp, FastConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowConstructorReturnedNonObject);
  __ bkpt(0);

  __ bind(&stack_overflow);
  // Restore the context from the frame.
  __ TailCallRuntime(Runtime::kThrowStackOverflow);
  // Unreachable code.
  __ bkpt(0);

  // Called Construct on an Object that doesn't have a [[Construct]] internal
  // method.
  __ bind(&non_constructor);
  __ TailCallBuiltin(Builtin::kConstructedNonConstructable);
}

static void Generate_InterpreterEnterBytecode(MacroAssembler* masm) {
  // Set the return address to the correct point in the interpreter entry
  // trampoline.
  Label builtin_trampoline, trampoline_loaded;
  Tagged<Smi> interpreter_entry_return_pc_offset(
      masm->isolate()->heap()->interpreter_entry_return_pc_offset());
  DCHECK_NE(interpreter_entry_return_pc_offset, Smi::zero());

  // If the SFI function_data is an InterpreterData, the function will have a
  // custom copy of the interpreter entry trampoline for profiling. If so,
  // get the custom trampoline, otherwise grab the entry address of the global
  // trampoline.
  __ LoadU64(r4, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ LoadTaggedField(
      r4, FieldMemOperand(r4, JSFunction::kSharedFunctionInfoOffset));
  __ LoadTaggedField(
      r4, FieldMemOperand(r4, SharedFunctionInfo::kTrustedFunctionDataOffset));
  __ CompareObjectType(r4, kInterpreterDispatchTableRegister,
                       kInterpreterDispatchTableRegister,
                       INTERPRETER_DATA_TYPE);
  __ bne(&builtin_trampoline);

  __ LoadTaggedField(
      r4, FieldMemOperand(r4, InterpreterData::kInterpreterTrampolineOffset));
  __ LoadCodeInstructionStart(r4, r4);
  __ b(&trampoline_loaded);

  __ bind(&builtin_trampoline);
  __ Move(r4, ExternalReference::
                  address_of_interpreter_entry_trampoline_instruction_start(
                      masm->isolate()));
  __ LoadU64(r4, MemOperand(r4));

  __ bind(&trampoline_loaded);
  __ AddS64(r14, r4, Operand(interpreter_entry_return_pc_offset.value()));

  // Initialize the dispatch table register.
  __ Move(
      kInterpreterDispatchTableRegister,
      ExternalReference::interpreter_dispatch_table_address(masm->isolate()));

  // Get the bytecode array pointer from the frame.
  __ LoadU64(kInterpreterBytecodeArrayRegister,
             MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));

  if (v8_flags.debug_code) {
    // Check function data field is actually a BytecodeArray object.
    __ TestIfSmi(kInterpreterBytecodeArrayRegister);
    __ Assert(
        ne, AbortReason::kFunctionDataShouldBeBytecodeArrayOnInterpreterEntry);
    __ CompareObjectType(kInterpreterBytecodeArrayRegister, r3, no_reg,
                         BYTECODE_ARRAY_TYPE);
    __ Assert(
        eq, AbortReason::kFunctionDataShouldBeBytecodeArrayOnInterpreterEntry);
  }

  // Get the target bytecode offset from the frame.
  __ LoadU64(kInterpreterBytecodeOffsetRegister,
             MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ SmiUntag(kInterpreterBytecodeOffsetRegister);

  if (v8_flags.debug_code) {
    Label okay;
    __ CmpS64(kInterpreterBytecodeOffsetRegister,
              Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));
    __ bge(&okay);
    __ bkpt(0);
    __ bind(&okay);
  }

  // Dispatch to the target bytecode.
  UseScratchRegisterScope temps(masm);
  Register scratch = temps.Acquire();
  __ LoadU8(scratch, MemOperand(kInterpreterBytecodeArrayRegister,
                                kInterpreterBytecodeOffsetRegister));
  __ ShiftLeftU64(scratch, scratch, Operand(kSystemPointerSizeLog2));
  __ LoadU64(kJavaScriptCallCodeStartRegister,
             MemOperand(kInterpreterDispatchTableRegister, scratch));
  __ Jump(kJavaScriptCallCodeStartRegister);
}

void Builtins::Generate_InterpreterEnterAtNextBytecode(MacroAssembler* masm) {
  // Get bytecode array and bytecode offset from the stack frame.
  __ LoadU64(kInterpreterBytecodeArrayRegister,
             MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ LoadU64(kInterpreterBytecodeOffsetRegister,
             MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ SmiUntag(kInterpreterBytecodeOffsetRegister);

  Label enter_bytecode, function_entry_bytecode;
  __ CmpS64(kInterpreterBytecodeOffsetRegister,
            Operand(BytecodeArray::kHeaderSize - kHeapObjectTag +
                    kFunctionEntryBytecodeOffset));
  __ beq(&function_entry_bytecode);

  // Load the current bytecode.
  __ LoadU8(r3, MemOperand(kInterpreterBytecodeArrayRegister,
                           kInterpreterBytecodeOffsetRegister));

  // Advance to the next bytecode.
  Label if_return;
  AdvanceBytecodeOffsetOrReturn(masm, kInterpreterBytecodeArrayRegister,
                                kInterpreterBytecodeOffsetRegister, r3, r4, r5,
                                &if_return);

  __ bind(&enter_bytecode);
  // Convert new bytecode offset to a Smi and save in the stackframe.
  __ SmiTag(r4, kInterpreterBytecodeOffsetRegister);
  __ StoreU64(r4,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));

  Generate_InterpreterEnterBytecode(masm);

  __ bind(&function_entry_bytecode);
  // If the code deoptimizes during the implicit function entry stack interrupt
  // check, it will have a bailout ID of kFunctionEntryBytecodeOffset, which is
  // not a valid bytecode offset. Detect this case and advance to the first
  // actual bytecode.
  __ mov(kInterpreterBytecodeOffsetRegister,
         Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));
  __ b(&enter_bytecode);

  // We should never take the if_return path.
  __ bind(&if_return);
  __ Abort(AbortReason::kInvalidBytecodeAdvance);
}

void Builtins::Generate_InterpreterEnterAtBytecode(MacroAssembler* masm) {
  Generate_InterpreterEnterBytecode(masm);
}

namespace {
void Generate_ContinueToBuiltinHelper(MacroAssembler* masm,
                                      bool javascript_builtin,
                                      bool with_result) {
  const RegisterConfiguration* config(RegisterConfiguration::Default());
  int allocatable_register_count = config->num_allocatable_general_registers();
  Register scratch = ip;
  if (with_result) {
    if (javascript_builtin) {
      __ mov(scratch, r2);
    } else {
      // Overwrite the hole inserted by the deoptimizer with the return value
      // from the LAZY deopt point.
      __ StoreU64(
          r2, MemOperand(
                  sp, config->num_allocatable_general_registers() *
                              kSystemPointerSize +
                          BuiltinContinuationFrameConstants::kFixedFrameSize));
    }
  }
  for (int i = allocatable_register_count - 1; i >= 0; --i) {
    int code = config->GetAllocatableGeneralCode(i);
    __ Pop(Register::from_code(code));
    if (javascript_builtin && code == kJavaScriptCallArgCountRegister.code()) {
      __ SmiUntag(Register::from_code(code));
    }
  }
  if (javascript_builtin && with_result) {
    // Overwrite the hole inserted by the deoptimizer with the return value from
    // the LAZY deopt point. r0 contains the arguments count, the return value
    // from LAZY is always the last argument.
    constexpr int return_value_offset =
        BuiltinContinuationFrameConstants::kFixedSlotCount -
        kJSArgcReceiverSlots;
    __ AddS64(r2, r2, Operand(return_value_offset));
    __ ShiftLeftU64(r1, r2, Operand(kSystemPointerSizeLog2));
    __ StoreU64(scratch, MemOperand(sp, r1));
    // Recover arguments count.
    __ SubS64(r2, r2, Operand(return_value_offset));
  }
  __ LoadU64(
      fp,
      MemOperand(sp, BuiltinContinuationFrameConstants::kFixedFrameSizeFromFp));
  // Load builtin index (stored as a Smi) and use it to get the builtin start
  // address from the builtins table.
  UseScratchRegisterScope temps(masm);
  Register builtin = temps.Acquire();
  __ Pop(builtin);
  __ AddS64(sp, sp,
            Operand(BuiltinContinuationFrameConstants::kFixedFrameSizeFromFp));
  __ Pop(r0);
  __ mov(r14, r0);
  __ LoadEntryFromBuiltinIndex(builtin, builtin);
  __ Jump(builtin);
}
}  // namespace

void Builtins::Generate_ContinueToCodeStubBuiltin(MacroAssembler* masm) {
  Generate_ContinueToBuiltinHelper(masm, false, false);
}

void Builtins::Generate_ContinueToCodeStubBuiltinWithResult(
    MacroAssembler* masm) {
  Generate_ContinueToBuiltinHelper(masm, false, true);
}

void Builtins::Generate_ContinueToJavaScriptBuiltin(MacroAssembler* masm) {
  Generate_ContinueToBuiltinHelper(masm, true, false);
}

void Builtins::Generate_ContinueToJavaScriptBuiltinWithResult(
    MacroAssembler* masm) {
  Generate_ContinueToBuiltinHelper(masm, true, true);
}

void Builtins::Generate_NotifyDeoptimized(MacroAssembler* masm) {
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kNotifyDeoptimized);
  }

  DCHECK_EQ(kInterpreterAccumulatorRegister.code(), r2.code());
  __ pop(r2);
  __ Ret();
}

// static
void Builtins::Generate_FunctionPrototypeApply(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r2    : argc
  //  -- sp[0] : receiver
  //  -- sp[4] : thisArg
  //  -- sp[8] : argArray
  // -----------------------------------

  // 1. Load receiver into r3, argArray into r4 (if present), remove all
  // arguments from the stack (including the receiver), and push thisArg (if
  // present) instead.
  {
    __ LoadRoot(r7, RootIndex::kUndefinedValue);
    __ mov(r4, r7);
    Label done;

    __ LoadU64(r3, MemOperand(sp));  // receiver
    __ CmpS64(r2, Operand(JSParameterCount(1)));
    __ blt(&done);
    __ LoadU64(r7, MemOperand(sp, kSystemPointerSize));  // thisArg
    __ CmpS64(r2, Operand(JSParameterCount(2)));
    __ blt(&done);
    __ LoadU64(r4, MemOperand(sp, 2 * kSystemPointerSize));  // argArray

    __ bind(&done);
    __ DropArgumentsAndPushNewReceiver(r2, r7);
  }

  // ----------- S t a t e -------------
  //  -- r4    : argArray
  //  -- r3    : receiver
  //  -- sp[0] : thisArg
  // -----------------------------------

  // 2. We don't need to check explicitly for callable receiver here,
  // since that's the first thing the Call/CallWithArrayLike builtins
  // will do.

  // 3. Tail call with no arguments if argArray is null or undefined.
  Label no_arguments;
  __ JumpIfRoot(r4, RootIndex::kNullValue, &no_arguments);
  __ JumpIfRoot(r4, RootIndex::kUndefinedValue, &no_arguments);

  // 4a. Apply the receiver to the given argArray.
  __ TailCallBuiltin(Builtin::kCallWithArrayLike);

  // 4b. The argArray is either null or undefined, so we tail call without any
  // arguments to the receiver.
  __ bind(&no_arguments);
  {
    __ mov(r2, Operand(JSParameterCount(0)));
    __ TailCallBuiltin(Builtins::Call());
  }
}

// static
void Builtins::Generate_FunctionPrototypeCall(MacroAssembler* masm) {
  // 1. Get the callable to call (passed as receiver) from the stack.
  __ Pop(r3);

  // 2. Make sure we have at least one argument.
  // r2: actual number of arguments
  {
    Label done;
    __ CmpS64(r2, Operand(JSParameterCount(0)));
    __ b(ne, &done);
    __ PushRoot(RootIndex::kUndefinedValue);
    __ AddS64(r2, r2, Operand(1));
    __ bind(&done);
  }

  // 3. Adjust the actual number of arguments.
  __ SubS64(r2, r2, Operand(1));

  // 4. Call the callable.
  __ TailCallBuiltin(Builtins::Call());
}

void Builtins::Generate_ReflectApply(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r2     : argc
  //  -- sp[0]  : receiver
  //  -- sp[4]  : target         (if argc >= 1)
  //  -- sp[8]  : thisArgument   (if argc >= 2)
  //  -- sp[12] : argumentsList  (if argc == 3)
  // -----------------------------------

  // 1. Load target into r3 (if present), argumentsList into r4 (if present),
  // remove all arguments from the stack (including the receiver), and push
  // thisArgument (if present) instead.
  {
    __ LoadRoot(r3, RootIndex::kUndefinedValue);
    __ mov(r7, r3);
    __ mov(r4, r3);

    Label done;

    __ CmpS64(r2, Operand(JSParameterCount(1)));
    __ blt(&done);
    __ LoadU64(r3, MemOperand(sp, kSystemPointerSize));  // thisArg
    __ CmpS64(r2, Operand(JSParameterCount(2)));
    __ blt(&done);
    __ LoadU64(r7, MemOperand(sp, 2 * kSystemPointerSize));  // argArray
    __ CmpS64(r2, Operand(JSParameterCount(3)));
    __ blt(&done);
    __ LoadU64(r4, MemOperand(sp, 3 * kSystemPointerSize));  // argArray

    __ bind(&done);
    __ DropArgumentsAndPushNewReceiver(r2, r7);
  }

  // ----------- S t a t e -------------
  //  -- r4    : argumentsList
  //  -- r3    : target
  //  -- sp[0] : thisArgument
  // -----------------------------------

  // 2. We don't need to check explicitly for callable target here,
  // since that's the first thing the Call/CallWithArrayLike builtins
  // will do.

  // 3 Apply the target to the given argumentsList.
  __ TailCallBuiltin(Builtin::kCallWithArrayLike);
}

void Builtins::Generate_ReflectConstruct(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r2     : argc
  //  -- sp[0]  : receiver
  //  -- sp[4]  : target
  //  -- sp[8]  : argumentsList
  //  -- sp[12] : new.target (optional)
  // -----------------------------------

  // 1. Load target into r3 (if present), argumentsList into r4 (if present),
  // new.target into r5 (if present, otherwise use target), remove all
  // arguments from the stack (including the receiver), and push thisArgument
  // (if present) instead.
  {
    __ LoadRoot(r3, RootIndex::kUndefinedValue);
    __ mov(r4, r3);

    Label done;

    __ mov(r6, r3);
    __ CmpS64(r2, Operand(JSParameterCount(1)));
    __ blt(&done);
    __ LoadU64(r3, MemOperand(sp, kSystemPointerSize));  // thisArg
    __ mov(r5, r3);
    __ CmpS64(r2, Operand(JSParameterCount(2)));
    __ blt(&done);
    __ LoadU64(r4, MemOperand(sp, 2 * kSystemPointerSize));  // argArray
    __ CmpS64(r2, Operand(JSParameterCount(3)));
    __ blt(&done);
    __ LoadU64(r5, MemOperand(sp, 3 * kSystemPointerSize));  // argArray
    __ bind(&done);
    __ DropArgumentsAndPushNewReceiver(r2, r6);
  }

  // ----------- S t a t e -------------
  //  -- r4    : argumentsList
  //  -- r5    : new.target
  //  -- r3    : target
  //  -- sp[0] : receiver (undefined)
  // -----------------------------------

  // 2. We don't need to check explicitly for constructor target here,
  // since that's the first thing the Construct/ConstructWithArrayLike
  // builtins will do.

  // 3. We don't need to check explicitly for constructor new.target here,
  // since that's the second thing the Construct/ConstructWithArrayLike
  // builtins will do.

  // 4. Construct the target with the given new.target and argumentsList.
  __ TailCallBuiltin(Builtin::kConstructWithArrayLike);
}

namespace {

// Allocate new stack space for |count| arguments and shift all existing
// arguments already on the stack. |pointer_to_new_space_out| points to the
// first free slot on the stack to copy additional arguments to and
// |argc_in_out| is updated to include |count|.
void Generate_AllocateSpaceAndShiftExistingArguments(
    MacroAssembler* masm, Register count, Register argc_in_out,
    Register pointer_to_new_space_out, Register scratch1, Register scratch2) {
  DCHECK(!AreAliased(count, argc_in_out, pointer_to_new_space_out, scratch1,
                     scratch2));
  Register old_sp = scratch1;
  Register new_space = scratch2;
  __ mov(old_sp, sp);
  __ ShiftLeftU64(new_space, count, Operand(kSystemPointerSizeLog2));
  __ AllocateStackSpace(new_space);

  Register end = scratch2;
  Register value = r1;
  Register dest = pointer_to_new_space_out;
  __ mov(dest, sp);
  __ ShiftLeftU64(r0, argc_in_out, Operand(kSystemPointerSizeLog2));
  __ AddS64(end, old_sp, r0);
  Label loop, done;
  __ bind(&loop);
  __ CmpS64(old_sp, end);
  __ bge(&done);
  __ LoadU64(value, MemOperand(old_sp));
  __ lay(old_sp, MemOperand(old_sp, kSystemPointerSize));
  __ StoreU64(value, MemOperand(dest));
  __ lay(dest, MemOperand(dest, kSystemPointerSize));
  __ b(&loop);
  __ bind(&done);

  // Update total number of arguments.
  __ AddS64(argc_in_out, argc_in_out, count);
}

}  // namespace

// static
// TODO(v8:11615): Observe Code::kMaxArguments in CallOrConstructVarargs
void Builtins::Generate_CallOrConstructVarargs(MacroAssembler* masm,
                                               Builtin target_builtin) {
  // ----------- S t a t e -------------
  //  -- r3 : target
  //  -- r2 : number of parameters on the stack
  //  -- r4 : arguments list (a FixedArray)
  //  -- r6 : len (number of elements to push from args)
  //  -- r5 : new.target (for [[Construct]])
  // -----------------------------------

  Register scratch = ip;

  if (v8_flags.debug_code) {
    // Allow r4 to be a FixedArray, or a FixedDoubleArray if r6 == 0.
    Label ok, fail;
    __ AssertNotSmi(r4);
    __ LoadTaggedField(scratch, FieldMemOperand(r4, HeapObject::kMapOffset));
    __ LoadS16(scratch, FieldMemOperand(scratch, Map::kInstanceTypeOffset));
    __ CmpS64(scratch, Operand(FIXED_ARRAY_TYPE));
    __ beq(&ok);
    __ CmpS64(scratch, Operand(FIXED_DOUBLE_ARRAY_TYPE));
    __ bne(&fail);
    __ CmpS64(r6, Operand::Zero());
    __ beq(&ok);
    // Fall through.
    __ bind(&fail);
    __ Abort(AbortReason::kOperandIsNotAFixedArray);

    __ bind(&ok);
  }

  // Check for stack overflow.
  Label stack_overflow;
  __ StackOverflowCheck(r6, scratch, &stack_overflow);

  // Move the arguments already in the stack,
  // including the receiver and the return address.
  // r6: Number of arguments to make room for.
  // r2: Number of arguments already on the stack.
  // r7: Points to first free slot on the stack after arguments were shifted.
  Generate_AllocateSpaceAndShiftExistingArguments(masm, r6, r2, r7, ip, r8);

  // Push arguments onto the stack (thisArgument is already on the stack).
  {
    Label loop, no_args, skip;
    __ CmpS64(r6, Operand::Zero());
    __ beq(&no_args);
    __ AddS64(r4, r4,
              Operand(OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag -
                      kTaggedSize));
    __ mov(r1, r6);
    __ bind(&loop);
    __ LoadTaggedField(scratch, MemOperand(r4, kTaggedSize), r0);
    __ la(r4, MemOperand(r4, kTaggedSize));
    __ CompareRoot(scratch, RootIndex::kTheHoleValue);
    __ bne(&skip, Label::kNear);
    __ LoadRoot(scratch, RootIndex::kUndefinedValue);
    __ bind(&skip);
    __ StoreU64(scratch, MemOperand(r7));
    __ lay(r7, MemOperand(r7, kSystemPointerSize));
    __ BranchOnCount(r1, &loop);
    __ bind(&no_args);
  }

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
  //  -- r2 : the number of arguments
  //  -- r5 : the new.target (for [[Construct]] calls)
  //  -- r3 : the target to call (can be any Object)
  //  -- r4 : start index (to support rest parameters)
  // -----------------------------------

  Register scratch = r8;

  if (mode == CallOrConstructMode::kConstruct) {
    Label new_target_constructor, new_target_not_constructor;
    __ JumpIfSmi(r5, &new_target_not_constructor);
    __ LoadTaggedField(scratch, FieldMemOperand(r5, HeapObject::kMapOffset));
    __ LoadU8(scratch, FieldMemOperand(scratch, Map::kBitFieldOffset));
    __ tmll(scratch, Operand(Map::Bits1::IsConstructorBit::kShift));
    __ bne(&new_target_constructor);
    __ bind(&new_target_not_constructor);
    {
      FrameScope scope(masm, StackFrame::MANUAL);
      __ EnterFrame(StackFrame::INTERNAL);
      __ Push(r5);
      __ CallRuntime(Runtime::kThrowNotConstructor);
      __ Trap();  // Unreachable.
    }
    __ bind(&new_target_constructor);
  }

  Label stack_done, stack_overflow;
  __ LoadU64(r7, MemOperand(fp, StandardFrameConstants::kArgCOffset));
  __ SubS64(r7, r7, Operand(kJSArgcReceiverSlots));
  __ SubS64(r7, r7, r4);
  __ ble(&stack_done);
  {
    // ----------- S t a t e -------------
    //  -- r2 : the number of arguments already in the stack
    //  -- r3 : the target to call (can be any Object)
    //  -- r4 : start index (to support rest parameters)
    //  -- r5 : the new.target (for [[Construct]] calls)
    //  -- r6 : point to the caller stack frame
    //  -- r7 : number of arguments to copy, i.e. arguments count - start index
    // -----------------------------------

    // Check for stack overflow.
    __ StackOverflowCheck(r7, scratch, &stack_overflow);

    // Forward the arguments from the caller frame.
    __ mov(r5, r5);
    // Point to the first argument to copy (skipping the receiver).
    __ AddS64(r6, fp,
              Operand(CommonFrameConstants::kFixedFrameSizeAboveFp +
                      kSystemPointerSize));
    __ ShiftLeftU64(scratch, r4, Operand(kSystemPointerSizeLog2));
    __ AddS64(r6, r6, scratch);

    // Move the arguments already in the stack,
    // including the receiver and the return address.
    // r7: Number of arguments to make room for.0
    // r2: Number of arguments already on the stack.
    // r4: Points to first free slot on the stack after arguments were shifted.
    Generate_AllocateSpaceAndShiftExistingArguments(masm, r7, r2, r4, scratch,
                                                    ip);

    // Copy arguments from the caller frame.
    // TODO(victorgomes): Consider using forward order as potentially more cache
    // friendly.
    {
      Label loop;
      __ bind(&loop);
      {
        __ SubS64(r7, r7, Operand(1));
        __ ShiftLeftU64(r1, r7, Operand(kSystemPointerSizeLog2));
        __ LoadU64(scratch, MemOperand(r6, r1));
        __ StoreU64(scratch, MemOperand(r4, r1));
        __ CmpS64(r7, Operand::Zero());
        __ bne(&loop);
      }
    }
  }
  __ bind(&stack_done);
  // Tail-call to the actual Call or Construct builtin.
  __ TailCallBuiltin(target_builtin);

  __ bind(&stack_overflow);
  __ TailCallRuntime(Runtime::kThrowStackOverflow);
}

// static
void Builtins::Generate_CallFunction(MacroAssembler* masm,
                                     ConvertReceiverMode mode) {
  // ----------- S t a t e -------------
  //  -- r2 : the number of arguments
  //  -- r3 : the function to call (checked to be a JSFunction)
  // -----------------------------------
  __ AssertCallableFunction(r3);

  __ LoadTaggedField(
      r4, FieldMemOperand(r3, JSFunction::kSharedFunctionInfoOffset));

  // Enter the context of the function; ToObject has to run in the function
  // context, and we also need to take the global proxy from the function
  // context in case of conversion.
  __ LoadTaggedField(cp, FieldMemOperand(r3, JSFunction::kContextOffset));
  // We need to convert the receiver for non-native sloppy mode functions.
  Label done_convert;
  __ LoadU32(r5, FieldMemOperand(r4, SharedFunctionInfo::kFlagsOffset));
  __ AndP(r0, r5,
          Operand(SharedFunctionInfo::IsStrictBit::kMask |
                  SharedFunctionInfo::IsNativeBit::kMask));
  __ bne(&done_convert);
  {
    // ----------- S t a t e -------------
    //  -- r2 : the number of arguments
    //  -- r3 : the function to call (checked to be a JSFunction)
    //  -- r4 : the shared function info.
    //  -- cp : the function context.
    // -----------------------------------

    if (mode == ConvertReceiverMode::kNullOrUndefined) {
      // Patch receiver to global proxy.
      __ LoadGlobalProxy(r5);
    } else {
      Label convert_to_object, convert_receiver;
      __ LoadReceiver(r5);
      __ JumpIfSmi(r5, &convert_to_object);
      static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
      __ CompareObjectType(r5, r6, r6, FIRST_JS_RECEIVER_TYPE);
      __ bge(&done_convert);
      if (mode != ConvertReceiverMode::kNotNullOrUndefined) {
        Label convert_global_proxy;
        __ JumpIfRoot(r5, RootIndex::kUndefinedValue, &convert_global_proxy);
        __ JumpIfNotRoot(r5, RootIndex::kNullValue, &convert_to_object);
        __ bind(&convert_global_proxy);
        {
          // Patch receiver to global proxy.
          __ LoadGlobalProxy(r5);
        }
        __ b(&convert_receiver);
      }
      __ bind(&convert_to_object);
      {
        // Convert receiver using ToObject.
        // TODO(bmeurer): Inline the allocation here to avoid building the frame
        // in the fast case? (fall back to AllocateInNewSpace?)
        FrameAndConstantPoolScope scope(masm, StackFrame::INTERNAL);
        __ SmiTag(r2);
        __ Push(r2, r3);
        __ mov(r2, r5);
        __ Push(cp);
        __ CallBuiltin(Builtin::kToObject);
        __ Pop(cp);
        __ mov(r5, r2);
        __ Pop(r2, r3);
        __ SmiUntag(r2);
      }
      __ LoadTaggedField(
          r4, FieldMemOperand(r3, JSFunction::kSharedFunctionInfoOffset));
      __ bind(&convert_receiver);
    }
    __ StoreReceiver(r5);
  }
  __ bind(&done_convert);

  // ----------- S t a t e -------------
  //  -- r2 : the number of arguments
  //  -- r3 : the function to call (checked to be a JSFunction)
  //  -- r4 : the shared function info.
  //  -- cp : the function context.
  // -----------------------------------

  __ LoadU16(
      r4, FieldMemOperand(r4, SharedFunctionInfo::kFormalParameterCountOffset));
  __ InvokeFunctionCode(r3, no_reg, r4, r2, InvokeType::kJump);
}

namespace {

void Generate_PushBoundArguments(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r2 : the number of arguments
  //  -- r3 : target (checked to be a JSBoundFunction)
  //  -- r5 : new.target (only in case of [[Construct]])
  // -----------------------------------

  // Load [[BoundArguments]] into r4 and length of that into r6.
  Label no_bound_arguments;
  __ LoadTaggedField(
      r4, FieldMemOperand(r3, JSBoundFunction::kBoundArgumentsOffset));
  __ SmiUntagField(r6, FieldMemOperand(r4, offsetof(FixedArray, length_)));
  __ LoadAndTestP(r6, r6);
  __ beq(&no_bound_arguments);
  {
    // ----------- S t a t e -------------
    //  -- r2 : the number of arguments
    //  -- r3 : target (checked to be a JSBoundFunction)
    //  -- r4 : the [[BoundArguments]] (implemented as FixedArray)
    //  -- r5 : new.target (only in case of [[Construct]])
    //  -- r6 : the number of [[BoundArguments]]
    // -----------------------------------

    Register scratch = r8;
    // Reserve stack space for the [[BoundArguments]].
    {
      Label done;
      __ ShiftLeftU64(scratch, r6, Operand(kSystemPointerSizeLog2));
      __ SubS64(r1, sp, scratch);
      // Check the stack for overflow. We are not trying to catch interruptions
      // (i.e. debug break and preemption) here, so check the "real stack
      // limit".
      __ CmpU64(r1, __ StackLimitAsMemOperand(StackLimitKind::kRealStackLimit));
      __ bgt(&done);  // Signed comparison.
      // Restore the stack pointer.
      {
        FrameScope scope(masm, StackFrame::MANUAL);
        __ EnterFrame(StackFrame::INTERNAL);
        __ CallRuntime(Runtime::kThrowStackOverflow);
      }
      __ bind(&done);
    }

    // Pop receiver.
    __ Pop(r7);

    // Push [[BoundArguments]].
    {
      Label loop, done;
      __ AddS64(r2, r2, r6);  // Adjust effective number of arguments.
      __ AddS64(r4, r4,
                Operand(OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag));

      __ bind(&loop);
      __ SubS64(r1, r6, Operand(1));
      __ ShiftLeftU64(r1, r1, Operand(kTaggedSizeLog2));
      __ LoadTaggedField(scratch, MemOperand(r4, r1), r0);
      __ Push(scratch);
      __ SubS64(r6, r6, Operand(1));
      __ bgt(&loop);
      __ bind(&done);
    }

    // Push receiver.
    __ Push(r7);
  }
  __ bind(&no_bound_arguments);
}

}  // namespace

// static
void Builtins::Generate_CallBoundFunctionImpl(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r2 : the number of arguments
  //  -- r3 : the function to call (checked to be a JSBoundFunction)
  // -----------------------------------
  __ AssertBoundFunction(r3);

  // Patch the receiver to [[BoundThis]].
  __ LoadTaggedField(r5,
                     FieldMemOperand(r3, JSBoundFunction::kBoundThisOffset));
  __ StoreReceiver(r5);

  // Push the [[BoundArguments]] onto the stack.
  Generate_PushBoundArguments(masm);

  // Call the [[BoundTargetFunction]] via the Call builtin.
  __ LoadTaggedField(
      r3, FieldMemOperand(r3, JSBoundFunction::kBoundTargetFunctionOffset));
  __ TailCallBuiltin(Builtins::Call());
}

// static
void Builtins::Generate_Call(MacroAssembler* masm, ConvertReceiverMode mode) {
  // ----------- S t a t e -------------
  //  -- r2 : the number of arguments
  //  -- r3 : the target to call (can be any Object).
  // -----------------------------------
  Register target = r3;
  Register map = r6;
  Register instance_type = r7;
  Register scratch = r8;
  DCHECK(!AreAliased(r2, target, map, instance_type));

  Label non_callable, class_constructor;
  __ JumpIfSmi(target, &non_callable);
  __ LoadMap(map, target);
  __ CompareInstanceTypeRange(map, instance_type, scratch,
                              FIRST_CALLABLE_JS_FUNCTION_TYPE,
                              LAST_CALLABLE_JS_FUNCTION_TYPE);
  __ TailCallBuiltin(Builtins::CallFunction(mode), le);
  __ CmpS64(instance_type, Operand(JS_BOUND_FUNCTION_TYPE));
  __ TailCallBuiltin(Builtin::kCallBoundFunction, eq);

  // Check if target has a [[Call]] internal method.
  {
    Register flags = r6;
    __ LoadU8(flags, FieldMemOperand(map, Map::kBitFieldOffset));
    map = no_reg;
    __ TestBit(flags, Map::Bits1::IsCallableBit::kShift);
    __ beq(&non_callable);
  }

  // Check if target is a proxy and call CallProxy external builtin
  __ CmpS64(instance_type, Operand(JS_PROXY_TYPE));
  __ TailCallBuiltin(Builtin::kCallProxy, eq);

  // Check if target is a wrapped function and call CallWrappedFunction external
  // builtin
  __ CmpS64(instance_type, Operand(JS_WRAPPED_FUNCTION_TYPE));
  __ TailCallBuiltin(Builtin::kCallWrappedFunction, eq);

  // ES6 section 9.2.1 [[Call]] ( thisArgument, argumentsList)
  // Check that the function is not a "classConstructor".
  __ CmpS64(instance_type, Operand(JS_CLASS_CONSTRUCTOR_TYPE));
  __ beq(&class_constructor);

  // 2. Call to something else, which might have a [[Call]] internal method (if
  // not we raise an exception).
  // Overwrite the original receiver the (original) target.
  __ StoreReceiver(target);
  // Let the "call_as_function_delegate" take care of the rest.
  __ LoadNativeContextSlot(target, Context::CALL_AS_FUNCTION_DELEGATE_INDEX);
  __ TailCallBuiltin(
      Builtins::CallFunction(ConvertReceiverMode::kNotNullOrUndefined));

  // 3. Call to something that is not callable.
  __ bind(&non_callable);
  {
    FrameAndConstantPoolScope scope(masm, StackFrame::INTERNAL);
    __ Push(target);
    __ CallRuntime(Runtime::kThrowCalledNonCallable);
    __ Trap();  // Unreachable.
  }

  // 4. The function is a "classConstructor", need to raise an exception.
  __ bind(&class_constructor);
  {
    FrameAndConstantPoolScope scope(masm, StackFrame::INTERNAL);
    __ Push(target);
    __ CallRuntime(Runtime::kThrowConstructorNonCallableError);
    __ Trap();  // Unreachable.
  }
}

// static
void Builtins::Generate_ConstructFunction(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r2 : the number of arguments
  //  -- r3 : the constructor to call (checked to be a JSFunction)
  //  -- r5 : the new target (checked to be a constructor)
  // -----------------------------------
  __ AssertConstructor(r3, r1);
  __ AssertFunction(r3);

  // Calling convention for function specific ConstructStubs require
  // r4 to contain either an AllocationSite or undefined.
  __ LoadRoot(r4, RootIndex::kUndefinedValue);

  Label call_generic_stub;

  // Jump to JSBuiltinsConstructStub or JSConstructStubGeneric.
  __ LoadTaggedField(
      r6, FieldMemOperand(r3, JSFunction::kSharedFunctionInfoOffset));
  __ LoadU32(r6, FieldMemOperand(r6, SharedFunctionInfo::kFlagsOffset));
  __ AndP(r6, Operand(SharedFunctionInfo::ConstructAsBuiltinBit::kMask));
  __ beq(&call_generic_stub);

  __ TailCallBuiltin(Builtin::kJSBuiltinsConstructStub);

  __ bind(&call_generic_stub);
  __ TailCallBuiltin(Builtin::kJSConstructStubGeneric);
}

// static
void Builtins::Generate_ConstructBoundFunction(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r2 : the number of arguments
  //  -- r3 : the function to call (checked to be a JSBoundFunction)
  //  -- r5 : the new target (checked to be a constructor)
  // -----------------------------------
  __ AssertConstructor(r3, r1);
  __ AssertBoundFunction(r3);

  // Push the [[BoundArguments]] onto the stack.
  Generate_PushBoundArguments(masm);

  // Patch new.target to [[BoundTargetFunction]] if new.target equals target.
  Label skip;
  __ CompareTagged(r3, r5);
  __ bne(&skip);
  __ LoadTaggedField(
      r5, FieldMemOperand(r3, JSBoundFunction::kBoundTargetFunctionOffset));
  __ bind(&skip);

  // Construct the [[BoundTargetFunction]] via the Construct builtin.
  __ LoadTaggedField(
      r3, FieldMemOperand(r3, JSBoundFunction::kBoundTargetFunctionOffset));
  __ TailCallBuiltin(Builtin::kConstruct);
}

// static
void Builtins::Generate_Construct(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r2 : the number of arguments
  //  -- r3 : the constructor to call (can be any Object)
  //  -- r5 : the new target (either the same as the constructor or
  //          the JSFunction on which new was invoked initially)
  // -----------------------------------
  Register target = r3;
  Register map = r6;
  Register instance_type = r7;
  Register scratch = r8;
  DCHECK(!AreAliased(r2, target, map, instance_type, scratch));

  // Check if target is a Smi.
  Label non_constructor, non_proxy;
  __ JumpIfSmi(target, &non_constructor);

  // Check if target has a [[Construct]] internal method.
  __ LoadTaggedField(map, FieldMemOperand(target, HeapObject::kMapOffset));
  {
    Register flags = r4;
    DCHECK(!AreAliased(r2, target, map, instance_type, flags));
    __ LoadU8(flags, FieldMemOperand(map, Map::kBitFieldOffset));
    __ TestBit(flags, Map::Bits1::IsConstructorBit::kShift);
    __ beq(&non_constructor);
  }

  // Dispatch based on instance type.
  __ CompareInstanceTypeRange(map, instance_type, scratch,
                              FIRST_JS_FUNCTION_TYPE, LAST_JS_FUNCTION_TYPE);
  __ TailCallBuiltin(Builtin::kConstructFunction, le);

  // Only dispatch to bound functions after checking whether they are
  // constructors.
  __ CmpS64(instance_type, Operand(JS_BOUND_FUNCTION_TYPE));
  __ TailCallBuiltin(Builtin::kConstructBoundFunction, eq);

  // Only dispatch to proxies after checking whether they are constructors.
  __ CmpS64(instance_type, Operand(JS_PROXY_TYPE));
  __ bne(&non_proxy);
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

#ifdef V8_ENABLE_MAGLEV

void Builtins::Generate_MaglevFunctionEntryStackCheck(MacroAssembler* masm,
                                                      bool save_new_target) {
  // Input (r0): Stack size (Smi).
  // This builtin can be invoked just after Maglev's prologue.
  // All registers are available, except (possibly) new.target.
  ASM_CODE_COMMENT(masm);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ AssertSmi(r2);
    if (save_new_target) {
      __ Push(kJavaScriptCallNewTargetRegister);
    }
    __ Push(r2);
    __ CallRuntime(Runtime::kStackGuardWithGap, 1);
    if (save_new_target) {
      __ Pop(kJavaScriptCallNewTargetRegister);
    }
  }
  __ Ret();
}

#endif  // V8_ENABLE_MAGLEV

#if V8_ENABLE_WEBASSEMBLY

struct SaveWasmParamsScope {
  explicit SaveWasmParamsScope(MacroAssembler* masm) : masm(masm) {
    for (Register gp_param_reg : wasm::kGpParamRegisters) {
      gp_regs.set(gp_param_reg);
    }
    for (DoubleRegister fp_param_reg : wasm::kFpParamRegisters) {
      fp_regs.set(fp_param_reg);
    }

    CHECK_EQ(gp_regs.Count(), arraysize(wasm::kGpParamRegisters));
    CHECK_EQ(fp_regs.Count(), arraysize(wasm::kFpParamRegisters));
    CHECK_EQ(WasmLiftoffSetupFrameConstants::kNumberOfSavedGpParamRegs + 1,
             gp_regs.Count());
    CHECK_EQ(WasmLiftoffSetupFrameConstants::kNumberOfSavedFpParamRegs,
             fp_regs.Count());

    __ MultiPush(gp_regs);
    __ MultiPushF64OrV128(fp_regs, r1);
  }
  ~SaveWasmParamsScope() {
    __ MultiPopF64OrV128(fp_regs, r1);
    __ MultiPop(gp_regs);
  }

  RegList gp_regs;
  DoubleRegList fp_regs;
  MacroAssembler* masm;
};

void Builtins::Generate_WasmLiftoffFrameSetup(MacroAssembler* masm) {
  Register func_index = wasm::kLiftoffFrameSetupFunctionReg;
  Register vector = ip;
  Register scratch = r0;
  Label allocate_vector, done;

  __ LoadTaggedField(
      vector, FieldMemOperand(kWasmImplicitArgRegister,
                              WasmTrustedInstanceData::kFeedbackVectorsOffset));
  __ ShiftLeftU64(scratch, func_index, Operand(kTaggedSizeLog2));
  __ AddS64(vector, vector, scratch);
  __ LoadTaggedField(vector,
                     FieldMemOperand(vector, OFFSET_OF_DATA_START(FixedArray)));
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
  __ StoreU64(scratch, MemOperand(sp));

  // Save current return address as it will get clobbered during CallRuntime.
  __ push(r14);
  {
    SaveWasmParamsScope save_params(masm);
    // Arguments to the runtime function: instance data, func_index.
    __ push(kWasmImplicitArgRegister);
    __ SmiTag(func_index);
    __ push(func_index);
    // Allocate a stack slot where the runtime function can spill a pointer
    // to the {NativeModule}.
    __ push(r10);
    __ LoadSmiLiteral(cp, Smi::zero());
    __ CallRuntime(Runtime::kWasmAllocateFeedbackVector, 3);
    __ mov(vector, kReturnRegister0);
    // Saved parameters are restored at the end of this block.
  }
  __ pop(r14);

  __ mov(scratch, Operand(StackFrame::TypeToMarker(StackFrame::WASM)));
  __ StoreU64(scratch, MemOperand(sp));
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
      __ LoadSmiLiteral(cp, Smi::zero());
      __ CallRuntime(Runtime::kWasmCompileLazy, 2);
      // The runtime function returns the jump table slot offset as a Smi. Use
      // that to compute the jump target in ip.
      __ SmiUntag(kReturnRegister0);
      __ mov(ip, kReturnRegister0);

      // Saved parameters are restored at the end of this block.
    }

    // After the instance data register has been restored, we can add the jump
    // table start to the jump table offset already stored in r8.
    __ LoadU64(r0,
               FieldMemOperand(kWasmImplicitArgRegister,
                               WasmTrustedInstanceData::kJumpTableStartOffset));
    __ AddS64(ip, ip, r0);
  }

  // Finally, jump to the jump table slot for the function.
  __ Jump(ip);
}

void Builtins::Generate_WasmDebugBreak(MacroAssembler* masm) {
  HardAbortScope hard_abort(masm);  // Avoid calls to Abort.
  {
    FrameAndConstantPoolScope scope(masm, StackFrame::WASM_DEBUG_BREAK);

    // Save all parameter registers. They might hold live values, we restore
    // them after the runtime call.
    __ MultiPush(WasmDebugBreakFrameConstants::kPushedGpRegs);
    __ MultiPushF64OrV128(WasmDebugBreakFrameConstants::kPushedFpRegs, ip);

    // Initialize the JavaScript context with 0. CEntry will use it to
    // set the current context on the isolate.
    __ LoadSmiLiteral(cp, Smi::zero());
    __ CallRuntime(Runtime::kWasmDebugBreak, 0);

    // Restore registers.
    __ MultiPopF64OrV128(WasmDebugBreakFrameConstants::kPushedFpRegs, ip);
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

// Loads the context field of the WasmTrustedInstanceData or WasmImportData
// depending on the data's type, and places the result in the input register.
void GetContextFromImplicitArg(MacroAssembler* masm, Register data,
                               Register scratch) {
  __ LoadTaggedField(scratch, FieldMemOperand(data, HeapObject::kMapOffset));
  __ CompareInstanceType(scratch, scratch, WASM_TRUSTED_INSTANCE_DATA_TYPE);
  Label instance;
  Label end;
  __ beq(&instance);
  __ LoadTaggedField(
      data, FieldMemOperand(data, WasmImportData::kNativeContextOffset));
  __ jmp(&end);
  __ bind(&instance);
  __ LoadTaggedField(
      data,
      FieldMemOperand(data, WasmTrustedInstanceData::kNativeContextOffset));
  __ bind(&end);
}

void Builtins::Generate_WasmToJsWrapperAsm(MacroAssembler* masm) {
  // Push registers in reverse order so that they are on the stack like
  // in an array, with the first item being at the lowest address.
  DoubleRegList fp_regs;
  for (DoubleRegister fp_param_reg : wasm::kFpParamRegisters) {
    fp_regs.set(fp_param_reg);
  }
  __ MultiPushDoubles(fp_regs);

  // Push the GP registers in reverse order so that they are on the stack like
  // in an array, with the first item being at the lowest address.
  RegList gp_regs;
  for (size_t i = arraysize(wasm::kGpParamRegisters) - 1; i > 0; --i) {
    gp_regs.set(wasm::kGpParamRegisters[i]);
  }
  __ MultiPush(gp_regs);
  // Reserve a slot for the signature.
  __ Push(r2);
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

void ResetStackSwitchFrameStackSlots(MacroAssembler* masm) {
  Register zero = r2;
  __ Move(zero, Smi::zero());
  __ StoreU64(zero,
              MemOperand(fp, StackSwitchFrameConstants::kResultArrayOffset));
  __ StoreU64(zero,
              MemOperand(fp, StackSwitchFrameConstants::kImplicitArgOffset));
}

void Builtins::Generate_JSToWasmWrapperAsm(MacroAssembler* masm) {
  __ EnterFrame(StackFrame::JS_TO_WASM);

  constexpr int kNumSpillSlots = StackSwitchFrameConstants::kNumSpillSlots;
  __ AllocateStackSpace(kNumSpillSlots * kSystemPointerSize);
  ResetStackSwitchFrameStackSlots(masm);

  Register wrapper_buffer =
      WasmJSToWasmWrapperDescriptor::WrapperBufferRegister();
  // Push the wrapper_buffer stack, it's needed later for the results.
  __ StoreU64(
      wrapper_buffer,
      MemOperand(fp, JSToWasmWrapperFrameConstants::kWrapperBufferOffset));

  Register result_size = r2;
  __ LoadU64(
      result_size,
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferStackReturnBufferSize),
      r0);
  __ ShiftLeftU64(r0, result_size, Operand(kSystemPointerSizeLog2));
  __ SubS64(sp, sp, r0);

  __ StoreU64(
      sp,
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferStackReturnBufferStart));
  // Push stack parameters on the stack.
  Register params_end = r1;
  __ LoadU64(params_end,
             MemOperand(wrapper_buffer,
                        JSToWasmWrapperFrameConstants::kWrapperBufferParamEnd));

  Register params_start = ip;
  __ LoadU64(
      params_start,
      MemOperand(wrapper_buffer,
                 JSToWasmWrapperFrameConstants::kWrapperBufferParamStart));
  // The first GP parameter holds the trusted instance data or the import data.
  // This is handled specially.
  int stack_params_offset =
      (arraysize(wasm::kGpParamRegisters) - 1) * kSystemPointerSize +
      arraysize(wasm::kFpParamRegisters) * kDoubleSize;
  Register last_stack_param = r2;
  __ AddS64(last_stack_param, params_start, Operand(stack_params_offset));

  Label loop_start;
  __ bind(&loop_start);

  Label finish_stack_params;
  __ CmpS64(last_stack_param, params_end);
  __ bge(&finish_stack_params);

  // Push parameter
  {
    // TODO(miladfarca): Use a different register for scratch.
    __ AddS64(params_end, params_end, Operand(-kSystemPointerSize));
    __ LoadU64(r0, MemOperand(params_end));
    __ push(r0);
  }

  __ jmp(&loop_start);

  __ bind(&finish_stack_params);

  size_t next_offset = 0;
  for (size_t i = 1; i < arraysize(wasm::kGpParamRegisters); ++i) {
    // Check that {params_start} does not overlap with any of the parameter
    // registers, so that we don't overwrite it by accident with the loads
    // below.
    DCHECK_NE(params_start, wasm::kGpParamRegisters[i]);
    __ LoadU64(wasm::kGpParamRegisters[i],
               MemOperand(params_start, next_offset));
    next_offset += kSystemPointerSize;
  }

  for (size_t i = 0; i < arraysize(wasm::kFpParamRegisters); ++i) {
    __ LoadF64(wasm::kFpParamRegisters[i],
               MemOperand(params_start, next_offset));
    next_offset += kDoubleSize;
  }
  DCHECK_EQ(next_offset, stack_params_offset);

  // Load the implicit argument into r5.
  __ LoadU64(kWasmImplicitArgRegister,
             MemOperand(fp, JSToWasmWrapperFrameConstants::kImplicitArgOffset));

  {
    Register thread_in_wasm_flag_addr = r3;
    __ LoadU64(thread_in_wasm_flag_addr,
               MemOperand(kRootRegister,
                          Isolate::thread_in_wasm_flag_address_offset()));
    __ mov(r0, Operand(1));
    __ StoreU32(r0, MemOperand(thread_in_wasm_flag_addr, 0));
  }

  Register function_entry = r3;
  __ LoadU64(
      function_entry,
      MemOperand(wrapper_buffer,
                 JSToWasmWrapperFrameConstants::kWrapperBufferCallTarget));
  __ Call(function_entry);

  {
    Register thread_in_wasm_flag_addr = r6;
    __ LoadU64(thread_in_wasm_flag_addr,
               MemOperand(kRootRegister,
                          Isolate::thread_in_wasm_flag_address_offset()));
    __ mov(r0, Operand(0));
    __ StoreU32(r0, MemOperand(thread_in_wasm_flag_addr, 0));
  }

  // `wrapper_buffer` is a parameter for `JSToWasmHandleReturns`, it therefore
  // has to be in r4.
  wrapper_buffer = r4;
  __ LoadU64(
      wrapper_buffer,
      MemOperand(fp, JSToWasmWrapperFrameConstants::kWrapperBufferOffset));

  __ StoreF64(
      wasm::kFpReturnRegisters[0],
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferFPReturnRegister1));
  __ StoreF64(
      wasm::kFpReturnRegisters[1],
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferFPReturnRegister2));
  __ StoreU64(
      wasm::kGpReturnRegisters[0],
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferGPReturnRegister1));
  __ StoreU64(
      wasm::kGpReturnRegisters[1],
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferGPReturnRegister2));

  // r2: wasm instance.
  // r3: the result JSArray for multi-return.
  // r4: pointer to the byte buffer which contains all parameters.
  __ LoadU64(
      r3,
      MemOperand(fp, JSToWasmWrapperFrameConstants::kResultArrayParamOffset));
  __ LoadU64(r2,
             MemOperand(fp, JSToWasmWrapperFrameConstants::kImplicitArgOffset));
  Register scratch = r5;
  GetContextFromImplicitArg(masm, r2, scratch);

  __ CallBuiltin(Builtin::kJSToWasmHandleReturns);

  __ LeaveFrame(StackFrame::JS_TO_WASM);
  __ AddS64(sp, sp, Operand(2 * kSystemPointerSize));
  __ b(r14);
}

#endif  // V8_ENABLE_WEBASSEMBLY

void Builtins::Generate_CEntry(MacroAssembler* masm, int result_size,
                               ArgvMode argv_mode, bool builtin_exit_frame,
                               bool switch_to_central_stack) {
  // Called from JavaScript; parameters are on stack as if calling JS function.
  // r2: number of arguments including receiver
  // r3: pointer to builtin function
  // fp: frame pointer  (restored after C call)
  // sp: stack pointer  (restored as callee's sp after C call)
  // cp: current context  (C callee-saved)
  //
  // If argv_mode == ArgvMode::kRegister:
  // r4: pointer to the first argument

  using ER = ExternalReference;

  // Move input arguments to more convenient registers.
  static constexpr Register argc_input = r2;
  static constexpr Register target_fun = r7;  // C callee-saved
  static constexpr Register argv = r3;
  static constexpr Register scratch = ip;
#if V8_OS_ZOS
  static constexpr Register argc_sav = r9;  // C callee-saved
#else
  static constexpr Register argc_sav = r6;  // C callee-saved
#endif

  __ mov(target_fun, argv);

  if (argv_mode == ArgvMode::kRegister) {
    // Move argv into the correct register.
    __ mov(argv, r4);
  } else {
    // Compute the argv pointer.
    __ ShiftLeftU64(argv, argc_input, Operand(kSystemPointerSizeLog2));
    __ lay(argv, MemOperand(argv, sp, -kSystemPointerSize));
  }

  // Enter the exit frame that transitions from JavaScript to C++.
  FrameScope scope(masm, StackFrame::MANUAL);

  int arg_stack_space = 0;

  // Pass buffer for return value on stack if necessary
  bool needs_return_buffer =
      result_size == 2 && !ABI_RETURNS_OBJECTPAIR_IN_REGS;
  if (needs_return_buffer) {
    arg_stack_space += result_size;
  }

  // 64-bit linux pass Argument object by reference not value
  arg_stack_space += 2;

  __ EnterExitFrame(
      scratch, arg_stack_space,
      builtin_exit_frame ? StackFrame::BUILTIN_EXIT : StackFrame::EXIT);

  // Store a copy of argc, argv in callee-saved registers for later.
  __ mov(argc_sav, argc_input);
  __ mov(r8, argv);
  // r2: number of arguments including receiver
  // r6: number of arguments including receiver (C callee-saved)
  // r3, r8: pointer to the first argument
  // r7: pointer to builtin function  (C callee-saved)

  // Result returned in registers or stack, depending on result size and ABI.

  Register isolate_reg = r4;
  if (needs_return_buffer) {
    // The return value is 16-byte non-scalar value.
    // Use frame storage reserved by calling function to pass return
    // buffer as implicit first argument in R2.  Shfit original parameters
    // by one register each.
    __ mov(r4, r3);
    __ mov(r3, r2);
    __ la(r2,
          MemOperand(sp, (kStackFrameExtraParamSlot + 1) * kSystemPointerSize));
    isolate_reg = r5;
    // Clang doesn't preserve r2 (result buffer)
    // write to r8 (preserved) before entry
    __ mov(r8, r2);
  }
  // Call C built-in.
  __ Move(isolate_reg, ER::isolate_address());

#if V8_OS_ZOS
  // Shuffle input arguments to match XPLINK ABI
  __ mov(r1, r2);
  __ mov(r2, r3);
  __ mov(r3, r4);
  // Save stack arguments to XPLINK extra param slot
  const int stack_args = 3;
  const int stack_space = kXPLINKStackFrameExtraParamSlot + stack_args;
  __ lay(r4, MemOperand(sp, -((stack_space * kSystemPointerSize) +
                              kStackPointerBias)));
  __ StoreMultipleP(
      r5, target_fun,
      MemOperand(r4, kStackPointerBias +
                         kXPLINKStackFrameExtraParamSlot * kSystemPointerSize));
  // Load environment from slot 0 of fn desc.
  __ LoadU64(r5, MemOperand(target_fun));
  // Load function pointer from slot 1 of fn desc.
  __ LoadU64(r8, MemOperand(target_fun, kSystemPointerSize));
  __ StoreReturnAddressAndCall(r8);

  // r9 and r13 are used to store argc and argv on z/OS instead
  // of r6 and r8 since r6 is not callee saved.
  __ mov(r6, r9);
  __ mov(r8, r13);

  // Shuffler arguments based on result_size to match XPLINK ABI
  if (result_size == 1) {
    __ mov(r2, r3);
  } else if (result_size == 2) {
    __ mov(r3, r2);
    __ mov(r2, r1);
  } else {
    __ mov(r4, r3);
    __ mov(r3, r2);
    __ mov(r2, r1);
  }
#else
  __ StoreReturnAddressAndCall(target_fun);

  // If return value is on the stack, pop it to registers.
  if (needs_return_buffer) {
    __ mov(r2, r8);
    __ LoadU64(r3, MemOperand(r2, kSystemPointerSize));
    __ LoadU64(r2, MemOperand(r2));
  }
#endif

  // Check result for exception sentinel.
  Label exception_returned;
  __ CompareRoot(r2, RootIndex::kException);
  __ beq(&exception_returned, Label::kNear);

  // Check that there is no exception, otherwise we
  // should have returned the exception sentinel.
  if (v8_flags.debug_code) {
    Label okay;
    ER exception_address =
        ER::Create(IsolateAddressId::kExceptionAddress, masm->isolate());
    __ LoadU64(scratch,
               __ ExternalReferenceAsOperand(exception_address, no_reg));
    __ CompareRoot(scratch, RootIndex::kTheHoleValue);
    // Cannot use check here as it attempts to generate call into runtime.
    __ beq(&okay, Label::kNear);
    __ stop();
    __ bind(&okay);
  }

  // Exit C frame and return.
  // r2:r3: result
  // sp: stack pointer
  // fp: frame pointer
  // r6: still holds argc (C caller-saved).
  __ LeaveExitFrame(scratch);
  if (argv_mode == ArgvMode::kStack) {
    DCHECK(!AreAliased(scratch, argc_sav));
    __ ShiftLeftU64(scratch, argc_sav, Operand(kSystemPointerSizeLog2));
    __ AddS64(sp, sp, scratch);
  }

  __ b(r14);

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

  // Ask the runtime for help to determine the handler. This will set r3 to
  // contain the current exception, don't clobber it.
  {
    FrameScope scope(masm, StackFrame::MANUAL);
    __ PrepareCallCFunction(3, 0, r2);
    __ mov(kCArgRegs[0], Operand::Zero());
    __ mov(kCArgRegs[1], Operand::Zero());
    __ Move(kCArgRegs[2], ER::isolate_address());
    __ CallCFunction(ER::Create(Runtime::kUnwindAndFindExceptionHandler), 3,
                     SetIsolateDataSlots::kNo);
  }

  // Retrieve the handler context, SP and FP.
  __ Move(cp, pending_handler_context_address);
  __ LoadU64(cp, MemOperand(cp));
  __ Move(sp, pending_handler_sp_address);
  __ LoadU64(sp, MemOperand(sp));
  __ Move(fp, pending_handler_fp_address);
  __ LoadU64(fp, MemOperand(fp));

  // If the handler is a JS frame, restore the context to the frame. Note that
  // the context will be set to (cp == 0) for non-JS frames.
  Label skip;
  __ CmpS64(cp, Operand::Zero());
  __ beq(&skip, Label::kNear);
  __ StoreU64(cp, MemOperand(fp, StandardFrameConstants::kContextOffset));
  __ bind(&skip);

  // Clear c_entry_fp, like we do in `LeaveExitFrame`.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, masm->isolate());
  __ mov(scratch, Operand::Zero());
  __ StoreU64(scratch,
              __ ExternalReferenceAsOperand(c_entry_fp_address, no_reg));

  // Compute the handler entry address and jump to it.
  __ LoadU64(scratch, __ ExternalReferenceAsOperand(
                          pending_handler_entrypoint_address, no_reg));
  __ Jump(scratch);
}

#if V8_ENABLE_WEBASSEMBLY
void Builtins::Generate_WasmHandleStackOverflow(MacroAssembler* masm) {
  __ Trap();
}
#endif  // V8_ENABLE_WEBASSEMBLY

void Builtins::Generate_DoubleToI(MacroAssembler* masm) {
  Label out_of_range, only_low, negate, done, fastpath_done;
  Register result_reg = r2;

  HardAbortSco
"""


```