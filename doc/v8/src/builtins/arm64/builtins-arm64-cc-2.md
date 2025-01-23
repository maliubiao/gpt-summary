Response:
Let's break down the thought process for analyzing this V8 builtins code.

**1. Initial Understanding and Context:**

* **File Path:** `v8/src/builtins/arm64/builtins-arm64.cc`. This immediately tells us:
    * It's part of the V8 JavaScript engine.
    * It's specific to the ARM64 architecture.
    * It deals with "builtins," which are core functions implemented in native code for performance.
* **Input:** We are given a code snippet from this file.
* **Goal:**  List the functionalities implemented in the provided snippet. Also, address specific questions about Torque, JavaScript relationship, logic, and common errors.

**2. High-Level Code Scan and Function Identification:**

The first step is to quickly scan the code and identify the function definitions. Keywords like `void Builtins::Generate_...` are key indicators. I see functions like:

* `Generate_InterpreterPushArgs`
* `Generate_InterpreterPushArgsThenConstructImpl`
* `Generate_ConstructForwardAllArgsImpl`
* `Generate_InterpreterPushArgsThenFastConstructFunction`
* `Generate_InterpreterEnterBytecode`
* `Generate_InterpreterEnterAtNextBytecode`
* `Generate_InterpreterEnterAtBytecode`
* `Generate_ContinueToBuiltinHelper`
* `Generate_ContinueToCodeStubBuiltin`
* `Generate_ContinueToCodeStubBuiltinWithResult`
* `Generate_ContinueToJavaScriptBuiltin`
* `Generate_ContinueToJavaScriptBuiltinWithResult`
* `Generate_NotifyDeoptimized`
* `Generate_OSREntry` (within a namespace)
* `Generate_InterpreterOnStackReplacement`
* `Generate_BaselineOnStackReplacement`
* `Generate_MaglevFunctionEntryStackCheck`
* `Generate_FunctionPrototypeApply`
* `Generate_FunctionPrototypeCall`
* `Generate_ReflectApply`
* `Generate_ReflectConstruct`
* `Generate_PrepareForCopyingVarargs` (within a namespace)

**3. Functional Grouping and Keyword Analysis:**

Now, let's group these functions based on their names and the code inside:

* **Argument Handling:**  `InterpreterPushArgs`, `ConstructForwardAllArgs`, `PrepareForCopyingVarargs`. These clearly deal with manipulating function arguments on the stack. Keywords like `Push`, `Poke`, `CopyDoubleWords`, `Claim` reinforce this.
* **Construction:** `InterpreterPushArgsThenConstructImpl`, `InterpreterPushArgsThenFastConstructFunction`, `ReflectConstruct`. These functions are involved in object construction. Keywords like `Construct`, `new target`, `implicit receiver` are important.
* **Interpreter Entry/Exit:** `InterpreterEnterBytecode`, `InterpreterEnterAtNextBytecode`, `InterpreterEnterAtBytecode`. These are directly related to entering and managing the V8 interpreter. Keywords: `bytecode`, `dispatch table`, `offset`.
* **Continuation and Deoptimization:** `ContinueToBuiltinHelper`, `ContinueToCodeStubBuiltin`, `ContinueToJavaScriptBuiltin`, `NotifyDeoptimized`. These deal with resuming execution after a builtin call or handling deoptimization.
* **Optimization and Tiering:** `OSREntry`, `InterpreterOnStackReplacement`, `BaselineOnStackReplacement`, `MaglevFunctionEntryStackCheck`. These are related to optimizing code execution, including On-Stack Replacement (OSR) and Maglev.
* **JavaScript Builtin Implementations:** `FunctionPrototypeApply`, `FunctionPrototypeCall`, `ReflectApply`, `ReflectConstruct`. These implement standard JavaScript functions as builtins.

**4. Answering Specific Questions:**

* **Torque:** The prompt explicitly states how to identify Torque files (`.tq`). Since this file ends in `.cc`, it's not a Torque file.
* **JavaScript Relationship:** Many of the functions have a direct relationship to JavaScript features. `FunctionPrototype.apply`, `FunctionPrototype.call`, and `Reflect.apply`/`Reflect.construct` are prime examples. The interpreter entry points are essential for running JavaScript code. Construction mechanisms are core to JavaScript object creation.
* **JavaScript Examples:** For the JavaScript-related functions, I'd create simple examples to illustrate their usage. For example:
    ```javascript
    function myFunction(a, b) { console.log(this, a, b); }
    myFunction.apply({ value: 1 }, [2, 3]); // Demonstrates Function.prototype.apply
    myFunction.call({ value: 4 }, 5, 6);  // Demonstrates Function.prototype.call
    ```
* **Logic and Assumptions:** For functions like `InterpreterPushArgs`, I'd consider the inputs (argument count, first argument address, etc.) and what the code does with them (pushing onto the stack). I'd make assumptions about the stack layout. For instance, the code assumes a standard frame structure.
* **Common Errors:** For functions related to argument handling or construction, I'd think about common JavaScript errors:
    * Incorrect number of arguments in `apply` or `call`.
    * Passing a non-array-like object to `apply`.
    * Calling `new` on a non-constructor.
* **Code Logic Inference (Example - `InterpreterPushArgs`):**
    * **Assumption:** The arguments are laid out contiguously in memory starting at `first_arg_index`.
    * **Input:** `num_args` = 2, `first_arg_index` points to the first argument's memory location.
    * **Output:** The two arguments are pushed onto the V8 stack.

**5. Structuring the Output:**

Finally, organize the findings in a clear and structured way:

* **Overall Function:** Start with a concise summary of the file's purpose.
* **Detailed Functionality List:**  Categorize the functions as done in step 3, providing brief descriptions for each.
* **Specific Questions:** Address the Torque, JavaScript relationship, logic, and error questions with examples.
* **Part Summary:** Since this is part 3 of 7, reiterate the focus of this section.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe I should go deep into the assembly instructions.
* **Correction:**  For this level of analysis, focusing on the function names and the high-level operations (pushing, calling, loading) is sufficient. Detailed assembly analysis isn't strictly necessary to understand the *functionality*.
* **Initial Thought:** Try to trace the execution flow exactly.
* **Correction:** While understanding the flow is important,  the goal isn't a full step-by-step execution trace but rather identifying the *purpose* of each function.

By following these steps, breaking down the problem, and continuously refining the analysis, I can arrive at a comprehensive and accurate description of the V8 builtins code.
好的，让我们来分析一下这段 `v8/src/builtins/arm64/builtins-arm64.cc` 代码的功能。

**总体功能归纳**

这段代码是 V8 JavaScript 引擎中 ARM64 架构特定的内置函数（builtins）的实现。它包含了一系列用汇编语言编写的函数，这些函数是为了优化 JavaScript 的执行而设计的。这些内置函数通常处理一些底层的操作，例如函数调用、对象构造、解释器执行以及优化相关的操作（如 OSR - On-Stack Replacement）。

**详细功能列表**

1. **`Generate_InterpreterPushArgs`**:  该函数负责将参数从解释器的栈帧推送到机器码栈帧，以便调用其他函数。它支持不同的模式，例如处理 `...spread` 语法。

2. **`Generate_InterpreterPushArgsThenConstructImpl`**:  在解释器环境下，该函数先推送参数，然后调用构造函数。它处理了标准构造调用以及使用 `...spread` 语法的构造调用。

3. **`Generate_ConstructForwardAllArgsImpl`**:  该函数用于转发当前或父级栈帧中的所有参数给构造函数。这在例如使用 `new.target` 和 `super()` 时会用到。它还包含了栈溢出检查。

4. **`Generate_InterpreterPushArgsThenFastConstructFunction`**:  这是一个优化后的构造函数调用路径，用于解释器环境。它会检查目标是否是构造函数，并尝试执行快速的对象分配和初始化。

5. **`Generate_InterpreterEnterBytecode`**:  该函数负责进入字节码解释器。它会设置解释器需要的寄存器，例如 dispatch table 和 bytecode array 的地址，然后跳转到目标字节码执行。

6. **`Generate_InterpreterEnterAtNextBytecode`**:  在解释器中执行完一个字节码后，该函数用于跳转到下一个字节码指令。

7. **`Generate_InterpreterEnterAtBytecode`**:  直接进入解释器执行字节码。

8. **`Generate_ContinueToBuiltinHelper`**:  这是一个辅助函数，用于在从例如 deoptimization 或其他状态恢复执行时，跳转回内置函数。它负责恢复寄存器状态和跳转到内置函数的入口点。

9. **`Generate_ContinueToCodeStubBuiltin`**:  从代码桩（CodeStub）恢复执行到内置函数。

10. **`Generate_ContinueToCodeStubBuiltinWithResult`**:  从代码桩恢复执行到内置函数，并传递一个结果值。

11. **`Generate_ContinueToJavaScriptBuiltin`**:  从 JavaScript 内置函数恢复执行。

12. **`Generate_ContinueToJavaScriptBuiltinWithResult`**:  从 JavaScript 内置函数恢复执行，并传递一个结果值。

13. **`Generate_NotifyDeoptimized`**:  当代码被 deoptimize 时，该函数会调用运行时函数 `kNotifyDeoptimized` 来进行通知。

14. **`Generate_OSREntry` (namespace 内的函数)**:  该函数用于处理 On-Stack Replacement (OSR) 的入口。OSR 是一种优化技术，允许在函数执行过程中从解释执行或较低级别的优化代码切换到更高级别的优化代码。

15. **`Generate_InterpreterOnStackReplacement`**:  特定于解释器的 OSR 入口点的生成。

16. **`Generate_BaselineOnStackReplacement`**:  特定于 Baseline 编译器的 OSR 入口点的生成。

17. **`Generate_MaglevFunctionEntryStackCheck`**:  在 Maglev 编译器优化的函数入口处进行栈大小检查。

18. **`Generate_FunctionPrototypeApply`**:  实现了 `Function.prototype.apply()` 方法的内置版本。

19. **`Generate_FunctionPrototypeCall`**:  实现了 `Function.prototype.call()` 方法的内置版本。

20. **`Generate_ReflectApply`**:  实现了 `Reflect.apply()` 方法的内置版本。

21. **`Generate_ReflectConstruct`**:  实现了 `Reflect.construct()` 方法的内置版本。

22. **`Generate_PrepareForCopyingVarargs` (namespace 内的函数)**:  为复制可变参数（varargs）准备栈空间。

**关于 `.tq` 后缀**

正如你所说，如果 `v8/src/builtins/arm64/builtins-arm64.cc` 文件以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。Torque 是一种 V8 内部使用的领域特定语言，用于更安全、更易维护的方式来定义内置函数。当前的 `.cc` 后缀表明它是用 C++ 和汇编混合编写的。

**与 JavaScript 的关系及示例**

这些内置函数直接支持 JavaScript 的核心功能。以下是一些与 JavaScript 功能相关的示例：

* **`Function.prototype.apply()` 和 `Function.prototype.call()`**:

   ```javascript
   function greet(greeting) {
     console.log(greeting + ', ' + this.name);
   }

   const person = { name: 'Alice' };

   greet.apply(person, ['Hello']); // 相当于 Generate_FunctionPrototypeApply
   greet.call(person, 'Hi');      // 相当于 Generate_FunctionPrototypeCall
   ```

* **`Reflect.apply()`**:

   ```javascript
   function sum(a, b) {
     return a + b;
   }

   const result = Reflect.apply(sum, null, [5, 3]); // 相当于 Generate_ReflectApply
   console.log(result); // 输出 8
   ```

* **`Reflect.construct()`**:

   ```javascript
   class Point {
     constructor(x, y) {
       this.x = x;
       this.y = y;
     }
   }

   const point = Reflect.construct(Point, [10, 20]); // 相当于 Generate_ReflectConstruct
   console.log(point.x, point.y); // 输出 10, 20
   ```

* **对象构造 (`new` 关键字)**:

   ```javascript
   function MyObject(value) {
     this.value = value;
   }

   const obj = new MyObject(42); // 可能会触发类似 Generate_InterpreterPushArgsThenConstructImpl 的内置函数
   console.log(obj.value);
   ```

* **函数调用 (普通函数调用)**:

   ```javascript
   function add(a, b) {
     return a + b;
   }

   const result = add(2, 3); // 可能会触发类似 Generate_InterpreterPushArgs 的内置函数
   console.log(result);
   ```

**代码逻辑推理和假设输入/输出**

以 `Generate_InterpreterPushArgs` 为例：

**假设输入：**

* `x0` (argument count): 2
* `x4` (address of the first argument): 指向内存中第一个参数的地址
* 栈上存储着两个参数的值（例如，数字 5 和字符串 "hello"）

**输出：**

* 在机器码栈上，这两个参数的值（5 和 "hello"）会被压入栈。
* `spread_arg_out` 寄存器可能会被更新，如果使用了 spread 语法。

**用户常见的编程错误**

* **`Function.prototype.apply()` 或 `Function.prototype.call()` 的参数错误**:

   ```javascript
   function myFunction(a, b) {
     console.log(a, b);
   }

   myFunction.apply(null, 1, 2); // 错误：apply 的第二个参数应该是数组
   myFunction.call(null, [1, 2]); // 错误：call 的后续参数应该直接是参数值
   ```

* **`Reflect.apply()` 的参数错误**:

   ```javascript
   function multiply(a, b) {
     return a * b;
   }

   Reflect.apply(multiply, null, 5); // 错误：第三个参数应该是参数数组
   ```

* **`Reflect.construct()` 的参数错误**:

   ```javascript
   class MyClass {
     constructor(name) {
       this.name = name;
     }
   }

   Reflect.construct(MyClass, 'John'); // 错误：第二个参数应该是参数数组
   ```

**总结（针对第 3 部分）**

这段代码（作为第 3 部分）主要关注于**函数调用的参数准备、对象构造的初步处理，以及解释器执行的入口和控制流**。它包含了将参数推送到栈、调用构造函数、进入和跳转字节码解释器等核心功能。此外，它也开始涉及一些优化相关的机制，例如 OSR 的入口准备。这部分代码是 V8 执行 JavaScript 代码的关键基础设施，连接了解释器和更底层的机器码执行。

希望这个分析对您有所帮助！

### 提示词
```
这是目录为v8/src/builtins/arm64/builtins-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/arm64/builtins-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
rg_index, spread_arg_out,
                              receiver_mode, mode);

  // Call the target.
  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    __ TailCallBuiltin(Builtin::kCallWithSpread);
  } else {
    __ TailCallBuiltin(Builtins::Call(receiver_mode));
  }
}

// static
void Builtins::Generate_InterpreterPushArgsThenConstructImpl(
    MacroAssembler* masm, InterpreterPushArgsMode mode) {
  // ----------- S t a t e -------------
  // -- x0 : argument count
  // -- x3 : new target
  // -- x1 : constructor to call
  // -- x2 : allocation site feedback if available, undefined otherwise
  // -- x4 : address of the first argument
  // -----------------------------------
  __ AssertUndefinedOrAllocationSite(x2);

  // Push the arguments. num_args may be updated according to mode.
  // spread_arg_out will be updated to contain the last spread argument, when
  // mode == InterpreterPushArgsMode::kWithFinalSpread.
  Register num_args = x0;
  Register first_arg_index = x4;
  Register spread_arg_out =
      (mode == InterpreterPushArgsMode::kWithFinalSpread) ? x2 : no_reg;
  GenerateInterpreterPushArgs(masm, num_args, first_arg_index, spread_arg_out,
                              ConvertReceiverMode::kNullOrUndefined, mode);

  if (mode == InterpreterPushArgsMode::kArrayFunction) {
    __ AssertFunction(x1);

    // Tail call to the array construct stub (still in the caller
    // context at this point).
    __ TailCallBuiltin(Builtin::kArrayConstructorImpl);
  } else if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Call the constructor with x0, x1, and x3 unmodified.
    __ TailCallBuiltin(Builtin::kConstructWithSpread);
  } else {
    DCHECK_EQ(InterpreterPushArgsMode::kOther, mode);
    // Call the constructor with x0, x1, and x3 unmodified.
    __ TailCallBuiltin(Builtin::kConstruct);
  }
}

// static
void Builtins::Generate_ConstructForwardAllArgsImpl(
    MacroAssembler* masm, ForwardWhichFrame which_frame) {
  // ----------- S t a t e -------------
  // -- x3 : new target
  // -- x1 : constructor to call
  // -----------------------------------
  Label stack_overflow;

  // Load the frame pointer into x4.
  switch (which_frame) {
    case ForwardWhichFrame::kCurrentFrame:
      __ Move(x4, fp);
      break;
    case ForwardWhichFrame::kParentFrame:
      __ Ldr(x4, MemOperand(fp, StandardFrameConstants::kCallerFPOffset));
      break;
  }

  // Load the argument count into x0.
  __ Ldr(x0, MemOperand(x4, StandardFrameConstants::kArgCOffset));

  // Point x4 to the base of the argument list to forward, excluding the
  // receiver.
  __ Add(x4, x4,
         Operand((StandardFrameConstants::kFixedSlotCountAboveFp + 1) *
                 kSystemPointerSize));

  Register stack_addr = x11;
  Register slots_to_claim = x12;
  Register argc_without_receiver = x13;

  // Round up to even number of slots.
  __ Add(slots_to_claim, x0, 1);
  __ Bic(slots_to_claim, slots_to_claim, 1);

  __ StackOverflowCheck(slots_to_claim, &stack_overflow);

  // Adjust the stack pointer.
  __ Claim(slots_to_claim);
  {
    // Store padding, which may be overwritten.
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.AcquireX();
    __ Sub(scratch, slots_to_claim, 1);
    __ Poke(padreg, Operand(scratch, LSL, kSystemPointerSizeLog2));
  }

  // Copy the arguments.
  __ Sub(argc_without_receiver, x0, kJSArgcReceiverSlots);
  __ SlotAddress(stack_addr, 1);
  __ CopyDoubleWords(stack_addr, x4, argc_without_receiver);

  // Push a slot for the receiver to be constructed.
  __ Mov(x14, Operand(0));
  __ Poke(x14, 0);

  // Call the constructor with x0, x1, and x3 unmodified.
  __ TailCallBuiltin(Builtin::kConstruct);

  __ Bind(&stack_overflow);
  {
    __ TailCallRuntime(Runtime::kThrowStackOverflow);
    __ Unreachable();
  }
}

namespace {

void NewImplicitReceiver(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  // -- x0 : the number of arguments
  // -- x1 : constructor to call (checked to be a JSFunction)
  // -- x3 : new target
  //
  //  Stack:
  //  -- Implicit Receiver
  //  -- [arguments without receiver]
  //  -- Implicit Receiver
  //  -- Context
  //  -- FastConstructMarker
  //  -- FramePointer
  // -----------------------------------
  Register implicit_receiver = x4;

  // Save live registers.
  __ SmiTag(x0);
  __ Push(x0, x1, x3, padreg);
  __ CallBuiltin(Builtin::kFastNewObject);
  // Save result.
  __ Mov(implicit_receiver, x0);
  // Restore live registers.
  __ Pop(padreg, x3, x1, x0);
  __ SmiUntag(x0);

  // Patch implicit receiver (in arguments)
  __ Poke(implicit_receiver, 0 * kSystemPointerSize);
  // Patch second implicit (in construct frame)
  __ Str(implicit_receiver,
         MemOperand(fp, FastConstructFrameConstants::kImplicitReceiverOffset));

  // Restore context.
  __ Ldr(cp, MemOperand(fp, FastConstructFrameConstants::kContextOffset));
}

}  // namespace

// static
void Builtins::Generate_InterpreterPushArgsThenFastConstructFunction(
    MacroAssembler* masm) {
  // ----------- S t a t e -------------
  // -- x0 : argument count
  // -- x1 : constructor to call (checked to be a JSFunction)
  // -- x3 : new target
  // -- x4 : address of the first argument
  // -- cp : context pointer
  // -----------------------------------
  __ AssertFunction(x1);

  // Check if target has a [[Construct]] internal method.
  Label non_constructor;
  __ LoadMap(x2, x1);
  __ Ldrb(x2, FieldMemOperand(x2, Map::kBitFieldOffset));
  __ TestAndBranchIfAllClear(x2, Map::Bits1::IsConstructorBit::kMask,
                             &non_constructor);

  // Enter a construct frame.
  FrameScope scope(masm, StackFrame::MANUAL);
  __ EnterFrame(StackFrame::FAST_CONSTRUCT);

  if (v8_flags.debug_code) {
    // Check that FrameScope pushed the context on to the stack already.
    __ Peek(x2, 0);
    __ Cmp(x2, cp);
    __ Check(eq, AbortReason::kUnexpectedValue);
  }

  // Implicit receiver stored in the construct frame.
  __ LoadRoot(x2, RootIndex::kTheHoleValue);
  __ Push(x2, padreg);

  // Push arguments + implicit receiver.
  GenerateInterpreterPushArgs(masm, x0, x4, Register::no_reg(),
                              ConvertReceiverMode::kNullOrUndefined,
                              InterpreterPushArgsMode::kOther);
  __ Poke(x2, 0 * kSystemPointerSize);

  // Check if it is a builtin call.
  Label builtin_call;
  __ LoadTaggedField(
      x2, FieldMemOperand(x1, JSFunction::kSharedFunctionInfoOffset));
  __ Ldr(w2, FieldMemOperand(x2, SharedFunctionInfo::kFlagsOffset));
  __ TestAndBranchIfAnySet(w2, SharedFunctionInfo::ConstructAsBuiltinBit::kMask,
                           &builtin_call);

  // Check if we need to create an implicit receiver.
  Label not_create_implicit_receiver;
  __ DecodeField<SharedFunctionInfo::FunctionKindBits>(w2);
  __ JumpIfIsInRange(
      w2, static_cast<uint32_t>(FunctionKind::kDefaultDerivedConstructor),
      static_cast<uint32_t>(FunctionKind::kDerivedConstructor),
      &not_create_implicit_receiver);
  NewImplicitReceiver(masm);
  __ bind(&not_create_implicit_receiver);

  // Call the function.
  __ InvokeFunctionWithNewTarget(x1, x3, x0, InvokeType::kCall);

  // ----------- S t a t e -------------
  //  -- x0     constructor result
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
  __ CompareRoot(x0, RootIndex::kUndefinedValue);
  __ B(ne, &check_receiver);

  // Throw away the result of the constructor invocation and use the
  // on-stack receiver as the result.
  __ Bind(&use_receiver);
  __ Ldr(x0,
         MemOperand(fp, FastConstructFrameConstants::kImplicitReceiverOffset));
  __ CompareRoot(x0, RootIndex::kTheHoleValue);
  __ B(eq, &do_throw);

  __ Bind(&leave_and_return);
  // Leave construct frame.
  __ LeaveFrame(StackFrame::FAST_CONSTRUCT);
  __ Ret();

  // Otherwise we do a smi check and fall through to check if the return value
  // is a valid receiver.
  __ bind(&check_receiver);

  // If the result is a smi, it is *not* an object in the ECMA sense.
  __ JumpIfSmi(x0, &use_receiver);

  // Check if the type of the result is not an object in the ECMA sense.
  __ JumpIfJSAnyIsNotPrimitive(x0, x4, &leave_and_return);
  __ B(&use_receiver);

  __ bind(&builtin_call);
  // TODO(victorgomes): Check the possibility to turn this into a tailcall.
  __ InvokeFunctionWithNewTarget(x1, x3, x0, InvokeType::kCall);
  __ LeaveFrame(StackFrame::FAST_CONSTRUCT);
  __ Ret();

  __ Bind(&do_throw);
  // Restore the context from the frame.
  __ Ldr(cp, MemOperand(fp, FastConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowConstructorReturnedNonObject);
  __ Unreachable();

  // Called Construct on an Object that doesn't have a [[Construct]] internal
  // method.
  __ bind(&non_constructor);
  __ TailCallBuiltin(Builtin::kConstructedNonConstructable);
}

static void Generate_InterpreterEnterBytecode(MacroAssembler* masm) {
  // Initialize the dispatch table register.
  __ Mov(
      kInterpreterDispatchTableRegister,
      ExternalReference::interpreter_dispatch_table_address(masm->isolate()));

  // Get the bytecode array pointer from the frame.
  __ Ldr(kInterpreterBytecodeArrayRegister,
         MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));

  if (v8_flags.debug_code) {
    // Check function data field is actually a BytecodeArray object.
    __ AssertNotSmi(
        kInterpreterBytecodeArrayRegister,
        AbortReason::kFunctionDataShouldBeBytecodeArrayOnInterpreterEntry);
    __ IsObjectType(kInterpreterBytecodeArrayRegister, x1, x1,
                    BYTECODE_ARRAY_TYPE);
    __ Assert(
        eq, AbortReason::kFunctionDataShouldBeBytecodeArrayOnInterpreterEntry);
  }

  // Get the target bytecode offset from the frame.
  __ SmiUntag(kInterpreterBytecodeOffsetRegister,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));

  if (v8_flags.debug_code) {
    Label okay;
    __ cmp(kInterpreterBytecodeOffsetRegister,
           Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));
    __ B(ge, &okay);
    __ Unreachable();
    __ bind(&okay);
  }

  // Dispatch to the target bytecode.
  __ Ldrb(x23, MemOperand(kInterpreterBytecodeArrayRegister,
                          kInterpreterBytecodeOffsetRegister));
  __ Mov(x1, Operand(x23, LSL, kSystemPointerSizeLog2));
  __ Ldr(kJavaScriptCallCodeStartRegister,
         MemOperand(kInterpreterDispatchTableRegister, x1));

  {
    UseScratchRegisterScope temps(masm);
    temps.Exclude(x17);
    __ Mov(x17, kJavaScriptCallCodeStartRegister);
    __ Call(x17);
  }

  // We return here after having executed the function in the interpreter.
  // Now jump to the correct point in the interpreter entry trampoline.
  Label builtin_trampoline, trampoline_loaded;
  Tagged<Smi> interpreter_entry_return_pc_offset(
      masm->isolate()->heap()->interpreter_entry_return_pc_offset());
  DCHECK_NE(interpreter_entry_return_pc_offset, Smi::zero());

  // If the SFI function_data is an InterpreterData, the function will have a
  // custom copy of the interpreter entry trampoline for profiling. If so,
  // get the custom trampoline, otherwise grab the entry address of the global
  // trampoline.
  __ Ldr(x1, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ LoadTaggedField(
      x1, FieldMemOperand(x1, JSFunction::kSharedFunctionInfoOffset));
  __ LoadTrustedPointerField(
      x1, FieldMemOperand(x1, SharedFunctionInfo::kTrustedFunctionDataOffset),
      kUnknownIndirectPointerTag);
  __ IsObjectType(x1, kInterpreterDispatchTableRegister,
                  kInterpreterDispatchTableRegister, INTERPRETER_DATA_TYPE);
  __ B(ne, &builtin_trampoline);

  __ LoadProtectedPointerField(
      x1, FieldMemOperand(x1, InterpreterData::kInterpreterTrampolineOffset));
  __ LoadCodeInstructionStart(x1, x1, kJSEntrypointTag);
  __ B(&trampoline_loaded);

  __ Bind(&builtin_trampoline);
  __ Mov(x1, ExternalReference::
                 address_of_interpreter_entry_trampoline_instruction_start(
                     masm->isolate()));
  __ Ldr(x1, MemOperand(x1));

  __ Bind(&trampoline_loaded);

  {
    UseScratchRegisterScope temps(masm);
    temps.Exclude(x17);
    __ Add(x17, x1, Operand(interpreter_entry_return_pc_offset.value()));
    __ Br(x17);
  }
}

void Builtins::Generate_InterpreterEnterAtNextBytecode(MacroAssembler* masm) {
  // Get bytecode array and bytecode offset from the stack frame.
  __ ldr(kInterpreterBytecodeArrayRegister,
         MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ SmiUntag(kInterpreterBytecodeOffsetRegister,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));

  Label enter_bytecode, function_entry_bytecode;
  __ cmp(kInterpreterBytecodeOffsetRegister,
         Operand(BytecodeArray::kHeaderSize - kHeapObjectTag +
                 kFunctionEntryBytecodeOffset));
  __ B(eq, &function_entry_bytecode);

  // Load the current bytecode.
  __ Ldrb(x1, MemOperand(kInterpreterBytecodeArrayRegister,
                         kInterpreterBytecodeOffsetRegister));

  // Advance to the next bytecode.
  Label if_return;
  AdvanceBytecodeOffsetOrReturn(masm, kInterpreterBytecodeArrayRegister,
                                kInterpreterBytecodeOffsetRegister, x1, x2, x3,
                                &if_return);

  __ bind(&enter_bytecode);
  // Convert new bytecode offset to a Smi and save in the stackframe.
  __ SmiTag(x2, kInterpreterBytecodeOffsetRegister);
  __ Str(x2, MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));

  Generate_InterpreterEnterBytecode(masm);

  __ bind(&function_entry_bytecode);
  // If the code deoptimizes during the implicit function entry stack interrupt
  // check, it will have a bailout ID of kFunctionEntryBytecodeOffset, which is
  // not a valid bytecode offset. Detect this case and advance to the first
  // actual bytecode.
  __ Mov(kInterpreterBytecodeOffsetRegister,
         Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));
  __ B(&enter_bytecode);

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
  int frame_size = BuiltinContinuationFrameConstants::kFixedFrameSizeFromFp +
                   (allocatable_register_count +
                    BuiltinContinuationFrameConstants::PaddingSlotCount(
                        allocatable_register_count)) *
                       kSystemPointerSize;

  UseScratchRegisterScope temps(masm);
  Register scratch = temps.AcquireX();  // Temp register is not allocatable.

  // Set up frame pointer.
  __ Add(fp, sp, frame_size);

  if (with_result) {
    if (javascript_builtin) {
      __ mov(scratch, x0);
    } else {
      // Overwrite the hole inserted by the deoptimizer with the return value
      // from the LAZY deopt point.
      __ Str(x0, MemOperand(
                     fp, BuiltinContinuationFrameConstants::kCallerSPOffset));
    }
  }

  // Restore registers in pairs.
  int offset = -BuiltinContinuationFrameConstants::kFixedFrameSizeFromFp -
               allocatable_register_count * kSystemPointerSize;
  for (int i = allocatable_register_count - 1; i > 0; i -= 2) {
    int code1 = config->GetAllocatableGeneralCode(i);
    int code2 = config->GetAllocatableGeneralCode(i - 1);
    Register reg1 = Register::from_code(code1);
    Register reg2 = Register::from_code(code2);
    __ Ldp(reg1, reg2, MemOperand(fp, offset));
    offset += 2 * kSystemPointerSize;
  }

  // Restore first register separately, if number of registers is odd.
  if (allocatable_register_count % 2 != 0) {
    int code = config->GetAllocatableGeneralCode(0);
    __ Ldr(Register::from_code(code), MemOperand(fp, offset));
  }

  if (javascript_builtin) __ SmiUntag(kJavaScriptCallArgCountRegister);

  if (javascript_builtin && with_result) {
    // Overwrite the hole inserted by the deoptimizer with the return value from
    // the LAZY deopt point. x0 contains the arguments count, the return value
    // from LAZY is always the last argument.
    constexpr int return_offset =
        BuiltinContinuationFrameConstants::kCallerSPOffset /
            kSystemPointerSize -
        kJSArgcReceiverSlots;
    __ add(x0, x0, return_offset);
    __ Str(scratch, MemOperand(fp, x0, LSL, kSystemPointerSizeLog2));
    // Recover argument count.
    __ sub(x0, x0, return_offset);
  }

  // Load builtin index (stored as a Smi) and use it to get the builtin start
  // address from the builtins table.
  Register builtin = scratch;
  __ Ldr(
      builtin,
      MemOperand(fp, BuiltinContinuationFrameConstants::kBuiltinIndexOffset));

  // Restore fp, lr.
  __ Mov(sp, fp);
  __ Pop<MacroAssembler::kAuthLR>(fp, lr);

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

  // Pop TOS register and padding.
  DCHECK_EQ(kInterpreterAccumulatorRegister.code(), x0.code());
  __ Pop(x0, padreg);
  __ Ret();
}

namespace {

void Generate_OSREntry(MacroAssembler* masm, Register entry_address,
                       Operand offset = Operand(0)) {
  // Pop the return address to this function's caller from the return stack
  // buffer, since we'll never return to it.
  Label jump;
  __ Adr(lr, &jump);
  __ Ret();

  __ Bind(&jump);

  UseScratchRegisterScope temps(masm);
  temps.Exclude(x17);
  if (offset.IsZero()) {
    __ Mov(x17, entry_address);
  } else {
    __ Add(x17, entry_address, offset);
  }
  __ Br(x17);
}

enum class OsrSourceTier {
  kInterpreter,
  kBaseline,
};

void OnStackReplacement(MacroAssembler* masm, OsrSourceTier source,
                        Register maybe_target_code) {
  Label jump_to_optimized_code;
  {
    // If maybe_target_code is not null, no need to call into runtime. A
    // precondition here is: if maybe_target_code is an InstructionStream
    // object, it must NOT be marked_for_deoptimization (callers must ensure
    // this).
    __ CompareTaggedAndBranch(x0, Smi::zero(), ne, &jump_to_optimized_code);
  }

  ASM_CODE_COMMENT(masm);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kCompileOptimizedOSR);
  }

  // If the code object is null, just return to the caller.
  __ CompareTaggedAndBranch(x0, Smi::zero(), ne, &jump_to_optimized_code);
  __ Ret();

  __ Bind(&jump_to_optimized_code);
  DCHECK_EQ(maybe_target_code, x0);  // Already in the right spot.

  // OSR entry tracing.
  {
    Label next;
    __ Mov(x1, ExternalReference::address_of_log_or_trace_osr());
    __ Ldrsb(x1, MemOperand(x1));
    __ Tst(x1, 0xFF);  // Mask to the LSB.
    __ B(eq, &next);

    {
      FrameScope scope(masm, StackFrame::INTERNAL);
      __ Push(x0, padreg);  // Preserve the code object.
      __ CallRuntime(Runtime::kLogOrTraceOptimizedOSREntry, 0);
      __ Pop(padreg, x0);
    }

    __ Bind(&next);
  }

  if (source == OsrSourceTier::kInterpreter) {
    // Drop the handler frame that is be sitting on top of the actual
    // JavaScript frame. This is the case then OSR is triggered from bytecode.
    __ LeaveFrame(StackFrame::STUB);
  }

  // Load deoptimization data from the code object.
  // <deopt_data> = <code>[#deoptimization_data_offset]
  __ LoadProtectedPointerField(
      x1,
      FieldMemOperand(x0, Code::kDeoptimizationDataOrInterpreterDataOffset));

  // Load the OSR entrypoint offset from the deoptimization data.
  // <osr_offset> = <deopt_data>[#header_size + #osr_pc_offset]
  __ SmiUntagField(
      x1, FieldMemOperand(x1, TrustedFixedArray::OffsetOfElementAt(
                                  DeoptimizationData::kOsrPcOffsetIndex)));

  __ LoadCodeInstructionStart(x0, x0, kJSEntrypointTag);

  // Compute the target address = code_entry + osr_offset
  // <entry_addr> = <code_entry> + <osr_offset>
  Generate_OSREntry(masm, x0, x1);
}

}  // namespace

void Builtins::Generate_InterpreterOnStackReplacement(MacroAssembler* masm) {
  using D = OnStackReplacementDescriptor;
  static_assert(D::kParameterCount == 1);
  OnStackReplacement(masm, OsrSourceTier::kInterpreter,
                     D::MaybeTargetCodeRegister());
}

void Builtins::Generate_BaselineOnStackReplacement(MacroAssembler* masm) {
  using D = OnStackReplacementDescriptor;
  static_assert(D::kParameterCount == 1);

  __ ldr(kContextRegister,
         MemOperand(fp, BaselineFrameConstants::kContextOffset));
  OnStackReplacement(masm, OsrSourceTier::kBaseline,
                     D::MaybeTargetCodeRegister());
}

#ifdef V8_ENABLE_MAGLEV

// static
void Builtins::Generate_MaglevFunctionEntryStackCheck(MacroAssembler* masm,
                                                      bool save_new_target) {
  // Input (x0): Stack size (Smi).
  // This builtin can be invoked just after Maglev's prologue.
  // All registers are available, except (possibly) new.target.
  ASM_CODE_COMMENT(masm);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ AssertSmi(x0);
    if (save_new_target) {
      if (PointerCompressionIsEnabled()) {
        __ AssertSmiOrHeapObjectInMainCompressionCage(
            kJavaScriptCallNewTargetRegister);
      }
      __ Push(kJavaScriptCallNewTargetRegister, padreg);
    }
    __ PushArgument(x0);
    __ CallRuntime(Runtime::kStackGuardWithGap, 1);
    if (save_new_target) {
      __ Pop(padreg, kJavaScriptCallNewTargetRegister);
    }
  }
  __ Ret();
}

#endif  // V8_ENABLE_MAGLEV

// static
void Builtins::Generate_FunctionPrototypeApply(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- x0       : argc
  //  -- sp[0]    : receiver
  //  -- sp[8]    : thisArg  (if argc >= 1)
  //  -- sp[16]   : argArray (if argc == 2)
  // -----------------------------------

  ASM_LOCATION("Builtins::Generate_FunctionPrototypeApply");

  Register argc = x0;
  Register receiver = x1;
  Register arg_array = x2;
  Register this_arg = x3;
  Register undefined_value = x4;
  Register null_value = x5;

  __ LoadRoot(undefined_value, RootIndex::kUndefinedValue);
  __ LoadRoot(null_value, RootIndex::kNullValue);

  // 1. Load receiver into x1, argArray into x2 (if present), remove all
  // arguments from the stack (including the receiver), and push thisArg (if
  // present) instead.
  {
    Label done;
    __ Mov(this_arg, undefined_value);
    __ Mov(arg_array, undefined_value);
    __ Peek(receiver, 0);
    __ Cmp(argc, Immediate(JSParameterCount(1)));
    __ B(lt, &done);
    __ Peek(this_arg, kSystemPointerSize);
    __ B(eq, &done);
    __ Peek(arg_array, 2 * kSystemPointerSize);
    __ bind(&done);
  }
  __ DropArguments(argc);
  __ PushArgument(this_arg);

  // ----------- S t a t e -------------
  //  -- x2      : argArray
  //  -- x1      : receiver
  //  -- sp[0]   : thisArg
  // -----------------------------------

  // 2. We don't need to check explicitly for callable receiver here,
  // since that's the first thing the Call/CallWithArrayLike builtins
  // will do.

  // 3. Tail call with no arguments if argArray is null or undefined.
  Label no_arguments;
  __ CmpTagged(arg_array, null_value);
  __ CcmpTagged(arg_array, undefined_value, ZFlag, ne);
  __ B(eq, &no_arguments);

  // 4a. Apply the receiver to the given argArray.
  __ TailCallBuiltin(Builtin::kCallWithArrayLike);

  // 4b. The argArray is either null or undefined, so we tail call without any
  // arguments to the receiver.
  __ Bind(&no_arguments);
  {
    __ Mov(x0, JSParameterCount(0));
    DCHECK_EQ(receiver, x1);
    __ TailCallBuiltin(Builtins::Call());
  }
}

// static
void Builtins::Generate_FunctionPrototypeCall(MacroAssembler* masm) {
  Register argc = x0;
  Register function = x1;

  ASM_LOCATION("Builtins::Generate_FunctionPrototypeCall");

  // 1. Get the callable to call (passed as receiver) from the stack.
  __ Peek(function, __ ReceiverOperand());

  // 2. Handle case with no arguments.
  {
    Label non_zero;
    Register scratch = x10;
    __ Cmp(argc, JSParameterCount(0));
    __ B(gt, &non_zero);
    __ LoadRoot(scratch, RootIndex::kUndefinedValue);
    // Overwrite receiver with undefined, which will be the new receiver.
    // We do not need to overwrite the padding slot above it with anything.
    __ Poke(scratch, 0);
    // Call function. The argument count is already zero.
    __ TailCallBuiltin(Builtins::Call());
    __ Bind(&non_zero);
  }

  Label arguments_ready;
  // 3. Shift arguments. It depends if the arguments is even or odd.
  // That is if padding exists or not.
  {
    Label even;
    Register copy_from = x10;
    Register copy_to = x11;
    Register count = x12;
    UseScratchRegisterScope temps(masm);
    Register argc_without_receiver = temps.AcquireX();
    __ Sub(argc_without_receiver, argc, kJSArgcReceiverSlots);

    // CopyDoubleWords changes the count argument.
    __ Mov(count, argc_without_receiver);
    __ Tbz(argc_without_receiver, 0, &even);

    // Shift arguments one slot down on the stack (overwriting the original
    // receiver).
    __ SlotAddress(copy_from, 1);
    __ Sub(copy_to, copy_from, kSystemPointerSize);
    __ CopyDoubleWords(copy_to, copy_from, count);
    // Overwrite the duplicated remaining last argument.
    __ Poke(padreg, Operand(argc_without_receiver, LSL, kXRegSizeLog2));
    __ B(&arguments_ready);

    // Copy arguments one slot higher in memory, overwriting the original
    // receiver and padding.
    __ Bind(&even);
    __ SlotAddress(copy_from, count);
    __ Add(copy_to, copy_from, kSystemPointerSize);
    __ CopyDoubleWords(copy_to, copy_from, count,
                       MacroAssembler::kSrcLessThanDst);
    __ Drop(2);
  }

  // 5. Adjust argument count to make the original first argument the new
  //    receiver and call the callable.
  __ Bind(&arguments_ready);
  __ Sub(argc, argc, 1);
  __ TailCallBuiltin(Builtins::Call());
}

void Builtins::Generate_ReflectApply(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- x0     : argc
  //  -- sp[0]  : receiver
  //  -- sp[8]  : target         (if argc >= 1)
  //  -- sp[16] : thisArgument   (if argc >= 2)
  //  -- sp[24] : argumentsList  (if argc == 3)
  // -----------------------------------

  ASM_LOCATION("Builtins::Generate_ReflectApply");

  Register argc = x0;
  Register arguments_list = x2;
  Register target = x1;
  Register this_argument = x4;
  Register undefined_value = x3;

  __ LoadRoot(undefined_value, RootIndex::kUndefinedValue);

  // 1. Load target into x1 (if present), argumentsList into x2 (if present),
  // remove all arguments from the stack (including the receiver), and push
  // thisArgument (if present) instead.
  {
    Label done;
    __ Mov(target, undefined_value);
    __ Mov(this_argument, undefined_value);
    __ Mov(arguments_list, undefined_value);
    __ Cmp(argc, Immediate(JSParameterCount(1)));
    __ B(lt, &done);
    __ Peek(target, kSystemPointerSize);
    __ B(eq, &done);
    __ Peek(this_argument, 2 * kSystemPointerSize);
    __ Cmp(argc, Immediate(JSParameterCount(3)));
    __ B(lt, &done);
    __ Peek(arguments_list, 3 * kSystemPointerSize);
    __ bind(&done);
  }
  __ DropArguments(argc);
  __ PushArgument(this_argument);

  // ----------- S t a t e -------------
  //  -- x2      : argumentsList
  //  -- x1      : target
  //  -- sp[0]   : thisArgument
  // -----------------------------------

  // 2. We don't need to check explicitly for callable target here,
  // since that's the first thing the Call/CallWithArrayLike builtins
  // will do.

  // 3. Apply the target to the given argumentsList.
  __ TailCallBuiltin(Builtin::kCallWithArrayLike);
}

void Builtins::Generate_ReflectConstruct(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- x0       : argc
  //  -- sp[0]   : receiver
  //  -- sp[8]   : target
  //  -- sp[16]  : argumentsList
  //  -- sp[24]  : new.target (optional)
  // -----------------------------------

  ASM_LOCATION("Builtins::Generate_ReflectConstruct");

  Register argc = x0;
  Register arguments_list = x2;
  Register target = x1;
  Register new_target = x3;
  Register undefined_value = x4;

  __ LoadRoot(undefined_value, RootIndex::kUndefinedValue);

  // 1. Load target into x1 (if present), argumentsList into x2 (if present),
  // new.target into x3 (if present, otherwise use target), remove all
  // arguments from the stack (including the receiver), and push thisArgument
  // (if present) instead.
  {
    Label done;
    __ Mov(target, undefined_value);
    __ Mov(arguments_list, undefined_value);
    __ Mov(new_target, undefined_value);
    __ Cmp(argc, Immediate(JSParameterCount(1)));
    __ B(lt, &done);
    __ Peek(target, kSystemPointerSize);
    __ B(eq, &done);
    __ Peek(arguments_list, 2 * kSystemPointerSize);
    __ Mov(new_target, target);  // new.target defaults to target
    __ Cmp(argc, Immediate(JSParameterCount(3)));
    __ B(lt, &done);
    __ Peek(new_target, 3 * kSystemPointerSize);
    __ bind(&done);
  }

  __ DropArguments(argc);

  // Push receiver (undefined).
  __ PushArgument(undefined_value);

  // ----------- S t a t e -------------
  //  -- x2      : argumentsList
  //  -- x1      : target
  //  -- x3      : new.target
  //  -- sp[0]   : receiver (undefined)
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

// Prepares the stack for copying the varargs. First we claim the necessary
// slots, taking care of potential padding. Then we copy the existing arguments
// one slot up or one slot down, as needed.
void Generate_PrepareForCopyingVarargs(MacroAssembler* masm, Register argc,
                                       Register len) {
  Label exit, even, init;
  Register slots_to_copy = x10;
  Register slots_to_claim = x12;

  __ Mov(slots_to_copy, argc);
  __ Mov(slots_to_claim, len);
  __ Tbz(slots_to_claim, 0, &even);

  // Claim space we need. If argc (without receiver) is even, slots_to_claim =
  // len + 1, as we need one extra padding slot. If argc (without receiver) is
  // odd, we know that the original arguments will have a padding slot we can
  // reuse (since len is odd), so slots_to_claim = len - 1.
  {
    Register scratch = x11;
    __ Add(slots_to_claim, len, 1);
    __ And(scratch, argc, 1);
    __ Sub(slots_to_claim, slots_to_claim, Operand(scratch, LSL, 1));
  }

  __ Bind(&even);
  __ Cbz(slots_to_claim, &exit);
  __ Claim(slots_to_claim);
  // An alignment slot may have been allocated above. If the number of stack
  // parameters is 0, the we have to initialize the alignment slot.
  __ Cbz(slots_to_copy, &init);

  // Move the arguments already in the stack including the receiver.
  {
    Register src = x11;
    Register dst = x1
```