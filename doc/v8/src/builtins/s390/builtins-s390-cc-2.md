Response:
My thinking process to analyze the provided C++ code and generate the summary involves these steps:

1. **Identify the Core Functionality:**  The file name `builtins-s390.cc` immediately suggests that this code defines built-in functions for the s390 architecture within the V8 JavaScript engine. The "builtins" part is key – these are fundamental functions directly implemented in native code for performance.

2. **Recognize Key Patterns and Code Structures:** I scan the code for recurring patterns and structures that indicate specific functionalities. I see:
    * `Builtins::Generate_...`: This clearly signals the generation of code for specific built-in functions.
    * `MacroAssembler* masm`: This is a V8 class responsible for generating machine code.
    * Register usage (r2, r3, r4, r5, etc.):  Indicates low-level manipulation of CPU registers.
    * Stack manipulation (`push`, `pop`, `AllocateStackSpace`):  Shows how arguments and temporary values are managed during function calls.
    * Calls to other builtins (`TailCallBuiltin`) and runtime functions (`TailCallRuntime`, `CallRuntime`):  Highlights interdependencies and delegation of tasks.
    * Checks for stack overflow (`StackOverflowCheck`).
    * Frame setup (`EnterFrame`, `LeaveFrame`): Indicates the creation and destruction of stack frames for function calls.
    * Conditional jumps and labels (`beq`, `bne`, `bind`): Demonstrates control flow within the generated code.
    * Code related to constructors and function calls (`Construct`, `Call`, `Apply`).
    * Code related to the interpreter (`InterpreterPushArgs`, `Generate_InterpreterEnterBytecode`).
    * Code related to deoptimization (`ContinueToCodeStubBuiltin`, `NotifyDeoptimized`).

3. **Group Related Functionalities:** Based on the identified patterns, I start grouping related blocks of code:
    * **Constructor-related builtins:** `Construct`, `ConstructWithSpread`, `ConstructForwardAllArgsImpl`, `InterpreterPushArgsThenFastConstructFunction`.
    * **Call-related builtins:** `CallFunction`, `FunctionPrototypeApply`, `FunctionPrototypeCall`, `ReflectApply`, `CallOrConstructVarargs`, `CallOrConstructForwardVarargs`.
    * **Interpreter entry/exit builtins:** `Generate_InterpreterEnterBytecode`, `Generate_InterpreterEnterAtNextBytecode`, `Generate_InterpreterEnterAtBytecode`.
    * **Deoptimization builtins:** `ContinueToCodeStubBuiltin`, `ContinueToJavaScriptBuiltin`, `NotifyDeoptimized`.

4. **Infer Function Purpose from Code:** For each identified function block, I try to infer its purpose by looking at the operations it performs:
    * **`Construct` family:** These functions handle the `new` operator in JavaScript, creating new objects and calling constructors. They manage arguments, handle spread syntax, and deal with potential stack overflows.
    * **`Call` family:** These functions implement the calling of JavaScript functions, including `apply` and `call`. They handle argument passing, receiver binding, and potential argument transformations.
    * **Interpreter builtins:** These functions deal with entering the interpreter to execute bytecode.
    * **Deoptimization builtins:** These handle the transition back from optimized code to the interpreter.

5. **Connect to JavaScript Concepts:**  I relate the identified functionalities to corresponding JavaScript concepts. For example:
    * `Construct` -> `new` operator, constructor functions.
    * `Call` -> function invocation, `call` and `apply` methods.
    * `InterpreterEnterBytecode` -> the execution of JavaScript code after compilation (or directly in the interpreter).
    * Deoptimization -> the fallback mechanism when optimized code becomes invalid.

6. **Consider the ".tq" Extension:** The prompt specifically mentions the `.tq` extension, indicating Torque. I check if the provided code *actually* uses Torque syntax. In this case, it doesn't. It's pure assembly. So, I note that the premise about Torque is incorrect for *this specific code snippet*.

7. **Address User Programming Errors:**  Based on the functionality, I consider common programming errors related to these areas:
    * Incorrect number of arguments in function calls.
    * Using `apply` or `call` with incorrect `this` binding or argument lists.
    * Stack overflow errors, especially in recursive functions or when passing large argument lists.
    * Trying to call a non-constructor with `new`.

8. **Create Examples (if applicable):** Since the prompt asks for JavaScript examples, I craft simple, illustrative code snippets that demonstrate the JavaScript equivalents of the built-in functionalities.

9. **Synthesize a Summary:**  Finally, I combine all the gathered information into a concise summary, highlighting the key functionalities of the code, its relationship to JavaScript, and potential programming pitfalls. I structure the summary logically, addressing each part of the prompt. Because it's part 3 of 5, I specifically frame the summary as a partial overview.

**Self-Correction/Refinement During the Process:**

* **Initial misinterpretations:**  I might initially assume a deeper level of complexity in some functions, but then realize through closer inspection that the core logic is relatively straightforward (e.g., simple argument manipulation).
* **Focusing on relevant details:** I might initially get bogged down in low-level assembly details, but then refocus on the higher-level purpose of each function.
* **Ensuring accuracy:** I double-check my understanding of V8 concepts and JavaScript semantics to avoid making incorrect connections. For example, I confirm the role of the `new.target` meta-property in constructors.
* **Clarity and conciseness:** I refine my language to be clear, concise, and avoid jargon where possible, while still accurately reflecting the technical details.

By following these steps, I can effectively analyze the provided V8 builtins code and generate a comprehensive and informative summary.这是对 `v8/src/builtins/s390/builtins-s390.cc` 文件代码片段的功能归纳：

**核心功能：为 s390 架构生成 V8 JavaScript 引擎的内置函数 (Builtins) 的机器码。**

这个代码片段定义了多个内置函数的代码生成逻辑，这些函数涵盖了 JavaScript 中常见的操作，例如：

* **构造函数调用 (Construction):**  处理 `new` 关键字，创建新的对象实例。
* **普通函数调用 (Call):**  处理函数的一般调用方式。
* **`apply` 和 `call` 方法:**  允许以不同的方式调用函数并指定 `this` 上下文和参数。
* **`Reflect` API 的方法:** 例如 `Reflect.apply` 和 `Reflect.construct`。
* **可变参数处理 (Varargs):**  处理参数数量不定的函数调用。
* **解释器入口 (Interpreter Entry):**  负责在需要时进入 V8 的字节码解释器。
* **去优化处理 (Deoptimization):**  处理从优化后的代码返回到解释器的情况。

**具体功能分解：**

1. **构造函数调用 (Construction):**
   - `Generate_Construct`: 生成调用普通构造函数的代码。
   - `Generate_ConstructWithSpread`:  生成处理带有展开运算符 (`...`) 的构造函数调用的代码。
   - `Generate_ConstructForwardAllArgsImpl`: 生成转发所有参数给构造函数的代码，用于 `super()` 调用等场景。
   - `Generate_InterpreterPushArgsThenFastConstructFunction`:  生成在解释器中准备好参数后快速调用构造函数的代码。
   - 这些函数会处理参数的传递、新对象的创建、以及可能的栈溢出检查。

2. **普通函数调用 (Call):**
   - `Generate_CallFunction`: 生成调用普通 JavaScript 函数的代码，并处理 `this` 值的转换（对于非严格模式的函数）。

3. **`apply` 和 `call` 方法:**
   - `Generate_FunctionPrototypeApply`:  生成 `Function.prototype.apply` 方法的代码，允许指定 `this` 值和一个数组或类数组对象作为参数。
   - `Generate_FunctionPrototypeCall`: 生成 `Function.prototype.call` 方法的代码，允许指定 `this` 值并逐个传递参数。

4. **`Reflect` API 的方法:**
   - `Generate_ReflectApply`: 生成 `Reflect.apply` 方法的代码，类似于 `Function.prototype.apply`，但参数顺序不同。
   - `Generate_ReflectConstruct`: 生成 `Reflect.construct` 方法的代码，允许像使用 `new` 关键字一样调用构造函数，但可以自定义 `new.target`。

5. **可变参数处理 (Varargs):**
   - `Generate_CallOrConstructVarargs`:  生成处理可变参数的函数调用或构造函数调用的代码，参数来自一个 `FixedArray`。
   - `Generate_CallOrConstructForwardVarargs`: 生成转发可变参数的函数调用或构造函数调用的代码，参数来自调用者的栈帧。

6. **解释器入口 (Interpreter Entry):**
   - `Generate_InterpreterEnterBytecode`: 生成进入字节码解释器的代码，设置必要的寄存器和状态。
   - `Generate_InterpreterEnterAtNextBytecode`: 生成进入下一个字节码指令的代码。
   - `Generate_InterpreterEnterAtBytecode`:  是 `Generate_InterpreterEnterBytecode` 的别名。
   - 这些函数负责将控制权转移到解释器，执行 JavaScript 字节码。

7. **去优化处理 (Deoptimization):**
   - `Generate_ContinueToCodeStubBuiltin`: 生成在去优化后继续执行 CodeStub 内置函数的代码。
   - `Generate_ContinueToCodeStubBuiltinWithResult`:  类似，但处理带有返回结果的情况。
   - `Generate_ContinueToJavaScriptBuiltin`: 生成在去优化后继续执行 JavaScript 内置函数的代码。
   - `Generate_ContinueToJavaScriptBuiltinWithResult`: 类似，但处理带有返回结果的情况。
   - `Generate_NotifyDeoptimized`: 生成通知运行时系统发生了去优化的代码。
   - 这些函数处理从优化后的机器码返回到解释执行的过程，恢复必要的上下文。

**与 JavaScript 的关系和示例:**

这些内置函数是 V8 引擎执行 JavaScript 代码的基础。 它们直接对应于 JavaScript 的语法和内置对象的方法。

**构造函数调用示例:**

```javascript
function MyClass(a, b) {
  this.a = a;
  this.b = b;
}

const instance = new MyClass(1, 2); // Generate_Construct 或 Generate_InterpreterPushArgsThenFastConstructFunction 会参与执行
```

**普通函数调用示例:**

```javascript
function add(x, y) {
  return x + y;
}

const sum = add(5, 3); // Generate_CallFunction 会参与执行
```

**`apply` 和 `call` 示例:**

```javascript
function greet(greeting) {
  console.log(greeting + ', ' + this.name);
}

const person = { name: 'Alice' };

greet.apply(person, ['Hello']); // Generate_FunctionPrototypeApply 会参与执行
greet.call(person, 'Hi');     // Generate_FunctionPrototypeCall 会参与执行
```

**`Reflect` API 示例:**

```javascript
function MyConstructor(arg1, arg2) {
  this.prop1 = arg1;
  this.prop2 = arg2;
}

const obj = Reflect.construct(MyConstructor, [10, 20]); // Generate_ReflectConstruct 会参与执行

const myObject = { value: 42 };
function getValue() {
  return this.value;
}
const value = Reflect.apply(getValue, myObject, []); // Generate_ReflectApply 会参与执行
```

**代码逻辑推理和假设输入输出 (以 `Generate_Construct` 为例):**

**假设输入：**

* `r3`:  指向要调用的构造函数 (一个 `JSFunction` 对象)。
* `r2`:  参数的个数。
* 栈上存储着传递给构造函数的参数（包括接收者）。
* `r5`:  `new.target` 的值。

**代码逻辑推理 (简化版):**

1. **栈溢出检查:** 检查是否有足够的栈空间来执行构造函数。
2. **分配对象:**  调用内置函数或运行时函数来分配新的对象实例。
3. **调用构造函数:**  使用 `TailCallBuiltin` 跳转到实际执行构造函数代码的内置函数 (`Builtin::kConstruct` 或 `Builtin::kConstructWithSpread`)。

**假设输出：**

* 如果构造成功，寄存器 `r0` 将包含新创建的对象实例。
* 如果发生栈溢出，将会跳转到 `stack_overflow` 标签，并调用 `Runtime::kThrowStackOverflow` 抛出错误。

**用户常见的编程错误:**

* **调用非构造函数：** 尝试使用 `new` 关键字调用一个不是构造函数的对象会导致错误。V8 会检查被调用的对象是否具有 `[[Construct]]` 内部方法。
  ```javascript
  const notAConstructor = {};
  // TypeError: notAConstructor is not a constructor
  // new notAConstructor();
  ```
* **栈溢出：**  递归调用深度过大或者传递过多的参数可能导致栈溢出。
  ```javascript
  function recursiveFunction() {
    recursiveFunction();
  }
  // RangeError: Maximum call stack size exceeded
  // recursiveFunction();

  function manyArgs(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z, ...) {
    // ...
  }
  // 传递大量的参数也可能导致栈溢出
  // manyArgs(1, 2, 3, ...);
  ```
* **`apply` 或 `call` 使用错误：**  传递给 `apply` 的参数不是数组或类数组对象，或者 `this` 上下文传递错误。
  ```javascript
  function myFunc() {
    console.log(this.value);
  }
  const obj = { value: 10 };
  // TypeError: CreateListFromArrayLike called on non-object
  // myFunc.apply(obj, 1); // 应该传递数组

  myFunc.call(null); // this 指向全局对象 (非严格模式) 或 undefined (严格模式)
  ```

**归纳其功能 (作为第 3 部分):**

作为 V8 代码生成流程的一部分，`v8/src/builtins/s390/builtins-s390.cc` 的这个代码片段专注于为 s390 架构的 CPU 生成处理 **函数调用和对象构造** 相关的 JavaScript 操作的机器码。它实现了诸如普通函数调用、构造函数调用、`apply` 和 `call` 方法、以及 `Reflect` API 的相关功能。此外，它还负责在需要时进入 JavaScript 解释器以及处理去优化的情况。  这个文件是 V8 引擎执行 JavaScript 代码的关键组成部分，它直接将高级的 JavaScript 概念转换为底层的机器指令。

### 提示词
```
这是目录为v8/src/builtins/s390/builtins-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/s390/builtins-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
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
        __ CallBuiltin
```