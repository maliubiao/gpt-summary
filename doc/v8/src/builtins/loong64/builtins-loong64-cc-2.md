Response:
My thinking process to analyze the provided V8 assembly code snippet went through these stages:

1. **Identify the Core Functionality:**  I immediately scanned the function names and comments. Keywords like "InterpreterEnter," "ContinueToBuiltin," "OSREntry," "FunctionPrototype," "Reflect," "CallOrConstruct," and "CallFunction" stood out. These strongly suggested the code deals with different entry points into the V8 engine (interpreter, compiled code), function calls (both regular and with `apply`/`call`), and object construction.

2. **Group Related Functions:** I noticed patterns in the naming. Functions starting with "Generate_Interpreter" were clearly related to the interpreter. "Generate_ContinueTo" was about transitioning to different types of built-in functions. "Generate_FunctionPrototype" and "Generate_Reflect" indicated implementations of JavaScript's `Function.prototype.apply`, `Function.prototype.call`, `Reflect.apply`, and `Reflect.construct`. The "Generate_CallOrConstruct" and "Generate_Call" functions seemed to be the core logic for calling JavaScript functions and constructors.

3. **Analyze Individual Function Groups:**

    * **Interpreter Entry Points:** I saw `Generate_InterpreterEnterBytecode`, `Generate_InterpreterEnterAtNextBytecode`, and `Generate_InterpreterEnterAtBytecode`. The comments within these functions clearly indicated they manage the execution of bytecode within the V8 interpreter, advancing the bytecode offset and dispatching to the appropriate handler.

    * **Continuing to Builtins:** The `Generate_ContinueToBuiltinHelper` function, along with its specialized versions (`Generate_ContinueToCodeStubBuiltin`, `Generate_ContinueToJavaScriptBuiltin`, etc.), dealt with transitioning from deoptimized code back to optimized built-in functions. The code manipulates the stack to restore registers and jump to the correct entry point in the builtins table.

    * **On-Stack Replacement (OSR):** `Generate_InterpreterOnStackReplacement` and `Generate_BaselineOnStackReplacement` were about optimizing code during runtime. The `OnStackReplacement` helper function manages the process of switching from interpreter or baseline code to optimized code, handling potential runtime compilation.

    * **`Function.prototype.apply` and `call`:** These implementations were about manipulating arguments and the `this` value before calling the target function. The code handles cases with and without arguments.

    * **`Reflect.apply` and `construct`:** Similar to the `Function.prototype` methods, these implementations focus on setting up the arguments and target for the actual call or construction.

    * **`CallOrConstructVarargs` and `CallOrConstructForwardVarargs`:** These functions were crucial for handling calls with a variable number of arguments, potentially coming from an array-like object or directly from the stack. They involve allocating stack space and moving arguments.

    * **`CallFunction`:** This function handles the core logic of calling a JavaScript function, including checking for callability, handling different receiver types (including `null` and `undefined`), and dispatching to the actual function code.

    * **`CallBoundFunctionImpl`:** This function specifically deals with calling bound functions, where the `this` value and some arguments are pre-determined.

    * **`Call`:** This was a high-level entry point for calling any JavaScript object. It checks the object's type and dispatches to the appropriate handler (e.g., `CallFunction`, `CallBoundFunction`, `CallProxy`).

    * **`ConstructFunction`:** This handles the construction of objects using the `new` operator.

4. **Identify JavaScript Relevance:**  Almost all the functions directly relate to JavaScript features. The names themselves map to JavaScript concepts (`Function.prototype.apply`, `Reflect.construct`, function calls, etc.). The code manipulates JavaScript values (receivers, arguments) and handles specific JavaScript semantics (like the difference between calling a regular function and a constructor).

5. **Look for Potential Errors:** I paid attention to error handling, particularly in functions like `Generate_Call`. The code explicitly throws exceptions (`kThrowCalledNonCallable`, `kThrowConstructorNonCallableError`) when encountering invalid call targets. The stack overflow checks in `CallOrConstructVarargs` and `CallOrConstructForwardVarargs` also point to a common programming error.

6. **Infer Input/Output and Logic:** For functions like the interpreter entry points, the input is implicitly the current state of the interpreter (bytecode array, offset, stack frame), and the output is the advancement of the interpreter's execution. For the call-related functions, the input is the target function/constructor, arguments, and the receiver, and the output is the result of the function call or the newly constructed object.

7. **Formulate Examples:**  Based on the identified functionality, I constructed JavaScript examples demonstrating the behavior of the related functions (e.g., using `apply` and `call`, `Reflect.apply` and `Reflect.construct`, and the error cases).

8. **Synthesize the Summary:** Finally, I summarized the findings, highlighting the key areas covered by the code: interpreter management, handling calls and constructions, dealing with variable arguments, and implementing built-in JavaScript functionalities. I also noted the relevance to JavaScript and common errors.

Essentially, I used a combination of code reading, pattern recognition, understanding of V8 architecture, and knowledge of JavaScript semantics to analyze the provided code snippet. The comments within the code were invaluable for understanding the purpose of each function.
这是提供的v8源代码文件 `v8/src/builtins/loong64/builtins-loong64.cc` 的第三部分，共六部分。根据之前两部分的分析，我们可以推断这部分代码继续定义了 LoongArch64 架构特定的内置函数 (builtins) 的实现。

**功能归纳 (基于提供的代码片段):**

这部分代码主要负责实现以下功能：

1. **解释器入口和控制流：**
   - `Generate_InterpreterEnterBytecode`:  进入解释器执行字节码。
   - `Generate_InterpreterEnterAtNextBytecode`: 在执行完当前字节码后，前进到下一个字节码并进入解释器。它模拟了字节码处理程序的完成行为。
   - `Generate_InterpreterEnterAtBytecode`: 直接进入解释器执行字节码。

2. **从去优化 (Deoptimization) 返回到内置函数：**
   - `Generate_ContinueToCodeStubBuiltin`: 从代码桩 (CodeStub) 返回 (通常是去优化后的返回)。
   - `Generate_ContinueToCodeStubBuiltinWithResult`:  从代码桩返回，并带有返回值。
   - `Generate_ContinueToJavaScriptBuiltin`: 从 JavaScript 内置函数返回。
   - `Generate_ContinueToJavaScriptBuiltinWithResult`: 从 JavaScript 内置函数返回，并带有返回值。
   - `Generate_NotifyDeoptimized`: 通知运行时发生了去优化。

3. **栈上替换 (On-Stack Replacement, OSR)：**
   - `Generate_InterpreterOnStackReplacement`:  从解释器切换到优化后的代码。
   - `Generate_BaselineOnStackReplacement`: 从基线编译器 (Baseline Compiler) 切换到优化后的代码。
   - 内部辅助函数 `OnStackReplacement`:  执行 OSR 的核心逻辑，包括调用运行时进行编译、跳转到优化后的代码等。

4. **实现 `Function.prototype.apply` 和 `Function.prototype.call`：**
   - `Generate_FunctionPrototypeApply`:  实现了 `Function.prototype.apply` 的功能，允许以指定的 `this` 值和数组或类数组对象作为参数调用函数。
   - `Generate_FunctionPrototypeCall`: 实现了 `Function.prototype.call` 的功能，允许以指定的 `this` 值和一系列参数调用函数.

5. **实现 `Reflect.apply` 和 `Reflect.construct`：**
   - `Generate_ReflectApply`: 实现了 `Reflect.apply` 的功能，类似于 `Function.prototype.apply`，但更加规范化。
   - `Generate_ReflectConstruct`: 实现了 `Reflect.construct` 的功能，用于调用构造函数创建对象。

6. **处理可变参数的函数调用和构造：**
   - `Generate_CallOrConstructVarargs`:  处理调用或构造函数时，参数来自于一个数组或类数组对象的情况。
   - `Generate_CallOrConstructForwardVarargs`: 处理调用或构造函数时，需要从当前调用栈帧中转发参数的情况，常用于 rest 参数。

7. **实现普通的函数调用：**
   - `Generate_CallFunction`:  实现普通函数调用的核心逻辑，包括处理 `this` 值、上下文切换等。
   - `Generate_CallBoundFunctionImpl`: 实现绑定函数的调用。
   - `Generate_Call`:  作为函数调用的入口点，根据目标对象的类型分发到不同的处理逻辑 (例如，普通函数、绑定函数、代理对象)。

8. **实现构造函数调用：**
   - `Generate_ConstructFunction`:  实现使用 `new` 关键字调用构造函数的功能。

**与 JavaScript 功能的关系及示例:**

这部分代码几乎完全与 JavaScript 的功能息息相关。以下是部分功能的 JavaScript 示例：

* **`Function.prototype.apply`:**
  ```javascript
  function greet(greeting) {
    console.log(greeting + ', ' + this.name);
  }

  const person = { name: 'Alice' };
  greet.apply(person, ['Hello']); // 输出: Hello, Alice
  ```

* **`Function.prototype.call`:**
  ```javascript
  function add(a, b) {
    return this.value + a + b;
  }

  const obj = { value: 10 };
  const result = add.call(obj, 5, 3); // result 为 18
  ```

* **`Reflect.apply`:**
  ```javascript
  function subtract(a, b) {
    return a - b;
  }

  const result = Reflect.apply(subtract, null, [10, 3]); // result 为 7
  ```

* **`Reflect.construct`:**
  ```javascript
  class MyClass {
    constructor(value) {
      this.value = value;
    }
  }

  const instance = Reflect.construct(MyClass, [42]);
  console.log(instance.value); // 输出: 42
  ```

* **可变参数调用 (对应 `...` 扩展运算符):**
  ```javascript
  function sum(...numbers) {
    return numbers.reduce((acc, curr) => acc + curr, 0);
  }

  const nums = [1, 2, 3, 4];
  const total = sum(...nums); // total 为 10
  ```

* **普通函数调用:**
  ```javascript
  function sayHello(name) {
    console.log('Hello, ' + name);
  }

  sayHello('Bob');
  ```

* **构造函数调用:**
  ```javascript
  function Person(name) {
    this.name = name;
  }

  const person = new Person('Charlie');
  console.log(person.name); // 输出: Charlie
  ```

**代码逻辑推理和假设输入/输出:**

以 `Generate_InterpreterEnterAtNextBytecode` 为例：

**假设输入:**
- 当前解释器帧指针 (`fp`) 指向一个有效的解释器帧。
- 该帧中存储了当前的字节码数组和偏移量。

**输出:**
- 解释器帧中的字节码偏移量会前进到下一个字节码的位置。
- 程序控制流跳转到下一个字节码的处理逻辑。

**代码逻辑:**
1. 从当前帧中加载字节码数组和偏移量。
2. 将偏移量从 Smi (V8 中表示小整数的方式) 转换为普通整数。
3. 检查是否到达函数入口的特殊偏移量，如果是，则处理函数入口的情况。
4. 计算下一个字节码的地址。
5. 加载下一个字节码的值。
6. 调用 `AdvanceBytecodeOffsetOrReturn` 函数来更新偏移量，并处理可能的返回情况。
7. 将新的偏移量转换为 Smi 并存储回帧中。
8. 跳转到 `Generate_InterpreterEnterBytecode` 执行下一个字节码。

**用户常见的编程错误:**

* **`Function.prototype.apply` 或 `call` 的 `this` 指向错误:**  初学者可能不理解 `apply` 和 `call` 如何显式地设置 `this` 值，导致在方法中访问错误的上下文。

  ```javascript
  const myObject = {
    value: 10,
    getValue: function() {
      console.log(this.value);
    }
  };

  const standaloneFunction = myObject.getValue;
  standaloneFunction(); // 输出 undefined (this 通常指向全局对象)
  standaloneFunction.call(myObject); // 输出 10 (this 被显式设置为 myObject)
  ```

* **使用 `Reflect.construct` 调用非构造函数:**  `Reflect.construct` 期望第一个参数是一个构造函数。如果传入的不是构造函数，会抛出 `TypeError`。

  ```javascript
  function notAConstructor() {
    return 42;
  }

  try {
    Reflect.construct(notAConstructor, []); // 抛出 TypeError
  } catch (e) {
    console.error(e);
  }
  ```

* **在使用可变参数时，不理解扩展运算符 (`...`) 的作用:** 可能会错误地将整个数组作为单个参数传递，而不是展开数组元素。

  ```javascript
  function multiply(a, b, c) {
    return a * b * c;
  }

  const numbers = [2, 3, 4];
  const result1 = multiply(numbers); // result1 为 NaN (尝试将数组与数字相乘)
  const result2 = multiply(...numbers); // result2 为 24 (数组元素被展开)
  ```

**总结第三部分的功能:**

总的来说，这部分 `builtins-loong64.cc` 代码实现了 V8 引擎在 LoongArch64 架构上处理 JavaScript 代码执行、函数调用和对象构造的关键底层机制。它涵盖了解释器的入口和控制，去优化后的返回处理，栈上替换优化，以及核心的 JavaScript 函数调用和构造相关的内置函数的实现，包括 `apply`、`call`、`Reflect` API 和可变参数的处理。 这些都是 V8 引擎执行 JavaScript 代码的基础构建块。

Prompt: 
```
这是目录为v8/src/builtins/loong64/builtins-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/loong64/builtins-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能

"""
  __ Alsl_d(a1, a7, kInterpreterDispatchTableRegister, kSystemPointerSizeLog2,
            t7);
  __ Ld_d(kJavaScriptCallCodeStartRegister, MemOperand(a1, 0));
  __ Jump(kJavaScriptCallCodeStartRegister);
}

void Builtins::Generate_InterpreterEnterAtNextBytecode(MacroAssembler* masm) {
  // Advance the current bytecode offset stored within the given interpreter
  // stack frame. This simulates what all bytecode handlers do upon completion
  // of the underlying operation.
  __ Ld_d(kInterpreterBytecodeArrayRegister,
          MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ Ld_d(kInterpreterBytecodeOffsetRegister,
          MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ SmiUntag(kInterpreterBytecodeOffsetRegister);

  Label enter_bytecode, function_entry_bytecode;
  __ Branch(&function_entry_bytecode, eq, kInterpreterBytecodeOffsetRegister,
            Operand(BytecodeArray::kHeaderSize - kHeapObjectTag +
                    kFunctionEntryBytecodeOffset));

  // Load the current bytecode.
  __ Add_d(a1, kInterpreterBytecodeArrayRegister,
           kInterpreterBytecodeOffsetRegister);
  __ Ld_bu(a1, MemOperand(a1, 0));

  // Advance to the next bytecode.
  Label if_return;
  AdvanceBytecodeOffsetOrReturn(masm, kInterpreterBytecodeArrayRegister,
                                kInterpreterBytecodeOffsetRegister, a1, a2, a3,
                                a4, &if_return);

  __ bind(&enter_bytecode);
  // Convert new bytecode offset to a Smi and save in the stackframe.
  __ SmiTag(a2, kInterpreterBytecodeOffsetRegister);
  __ St_d(a2, MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));

  Generate_InterpreterEnterBytecode(masm);

  __ bind(&function_entry_bytecode);
  // If the code deoptimizes during the implicit function entry stack interrupt
  // check, it will have a bailout ID of kFunctionEntryBytecodeOffset, which is
  // not a valid bytecode offset. Detect this case and advance to the first
  // actual bytecode.
  __ li(kInterpreterBytecodeOffsetRegister,
        Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));
  __ Branch(&enter_bytecode);

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
  UseScratchRegisterScope temps(masm);
  Register scratch = temps.Acquire();
  if (with_result) {
    if (javascript_builtin) {
      __ mov(scratch, a0);
    } else {
      // Overwrite the hole inserted by the deoptimizer with the return value
      // from the LAZY deopt point.
      __ St_d(a0,
              MemOperand(
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

  if (with_result && javascript_builtin) {
    // Overwrite the hole inserted by the deoptimizer with the return value from
    // the LAZY deopt point. t0 contains the arguments count, the return value
    // from LAZY is always the last argument.
    constexpr int return_value_offset =
        BuiltinContinuationFrameConstants::kFixedSlotCount -
        kJSArgcReceiverSlots;
    __ Add_d(a0, a0, Operand(return_value_offset));
    __ Alsl_d(t0, a0, sp, kSystemPointerSizeLog2, t7);
    __ St_d(scratch, MemOperand(t0, 0));
    // Recover arguments count.
    __ Sub_d(a0, a0, Operand(return_value_offset));
  }

  __ Ld_d(
      fp,
      MemOperand(sp, BuiltinContinuationFrameConstants::kFixedFrameSizeFromFp));
  // Load builtin index (stored as a Smi) and use it to get the builtin start
  // address from the builtins table.
  __ Pop(t0);
  __ Add_d(sp, sp,
           Operand(BuiltinContinuationFrameConstants::kFixedFrameSizeFromFp));
  __ Pop(ra);
  __ LoadEntryFromBuiltinIndex(t0, t0);
  __ Jump(t0);
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

  DCHECK_EQ(kInterpreterAccumulatorRegister.code(), a0.code());
  __ Ld_d(a0, MemOperand(sp, 0 * kSystemPointerSize));
  __ Add_d(sp, sp, Operand(1 * kSystemPointerSize));  // Remove state.
  __ Ret();
}

namespace {

void Generate_OSREntry(MacroAssembler* masm, Register entry_address,
                       Operand offset = Operand(zero_reg)) {
  __ Add_d(ra, entry_address, offset);
  // And "return" to the OSR entry point of the function.
  __ Ret();
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
    __ CompareTaggedAndBranch(&jump_to_optimized_code, ne, maybe_target_code,
                              Operand(Smi::zero()));
  }

  ASM_CODE_COMMENT(masm);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kCompileOptimizedOSR);
  }

  // If the code object is null, just return to the caller.
  __ CompareTaggedAndBranch(&jump_to_optimized_code, ne, maybe_target_code,
                            Operand(Smi::zero()));
  __ Ret();

  __ bind(&jump_to_optimized_code);
  DCHECK_EQ(maybe_target_code, a0);  // Already in the right spot.

  // OSR entry tracing.
  {
    Label next;
    __ li(a1, ExternalReference::address_of_log_or_trace_osr());
    __ Ld_bu(a1, MemOperand(a1, 0));
    __ Branch(&next, eq, a1, Operand(zero_reg));

    {
      FrameScope scope(masm, StackFrame::INTERNAL);
      __ Push(a0);  // Preserve the code object.
      __ CallRuntime(Runtime::kLogOrTraceOptimizedOSREntry, 0);
      __ Pop(a0);
    }

    __ bind(&next);
  }

  if (source == OsrSourceTier::kInterpreter) {
    // Drop the handler frame that is be sitting on top of the actual
    // JavaScript frame. This is the case then OSR is triggered from bytecode.
    __ LeaveFrame(StackFrame::STUB);
  }

  // Load deoptimization data from the code object.
  // <deopt_data> = <code>[#deoptimization_data_offset]
  __ LoadProtectedPointerField(
      a1, MemOperand(maybe_target_code,
                     Code::kDeoptimizationDataOrInterpreterDataOffset -
                         kHeapObjectTag));

  // Load the OSR entrypoint offset from the deoptimization data.
  // <osr_offset> = <deopt_data>[#header_size + #osr_pc_offset]
  __ SmiUntagField(a1,
                   MemOperand(a1, TrustedFixedArray::OffsetOfElementAt(
                                      DeoptimizationData::kOsrPcOffsetIndex) -
                                      kHeapObjectTag));

  __ LoadCodeInstructionStart(maybe_target_code, maybe_target_code,
                              kJSEntrypointTag);

  // Compute the target address = code_entry + osr_offset
  // <entry_addr> = <code_entry> + <osr_offset>
  Generate_OSREntry(masm, maybe_target_code, Operand(a1));
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

  __ Ld_d(kContextRegister,
          MemOperand(fp, BaselineFrameConstants::kContextOffset));
  OnStackReplacement(masm, OsrSourceTier::kBaseline,
                     D::MaybeTargetCodeRegister());
}

// static
void Builtins::Generate_FunctionPrototypeApply(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- a0    : argc
  //  -- sp[0] : receiver
  //  -- sp[4] : thisArg
  //  -- sp[8] : argArray
  // -----------------------------------

  Register argc = a0;
  Register arg_array = a2;
  Register receiver = a1;
  Register this_arg = a5;
  Register undefined_value = a3;
  Register scratch = a4;

  __ LoadRoot(undefined_value, RootIndex::kUndefinedValue);

  // 1. Load receiver into a1, argArray into a2 (if present), remove all
  // arguments from the stack (including the receiver), and push thisArg (if
  // present) instead.
  {
    __ Sub_d(scratch, argc, JSParameterCount(0));
    __ Ld_d(this_arg, MemOperand(sp, kSystemPointerSize));
    __ Ld_d(arg_array, MemOperand(sp, 2 * kSystemPointerSize));
    __ Movz(arg_array, undefined_value, scratch);  // if argc == 0
    __ Movz(this_arg, undefined_value, scratch);   // if argc == 0
    __ Sub_d(scratch, scratch, Operand(1));
    __ Movz(arg_array, undefined_value, scratch);  // if argc == 1
    __ Ld_d(receiver, MemOperand(sp, 0));
    __ DropArgumentsAndPushNewReceiver(argc, this_arg);
  }

  // ----------- S t a t e -------------
  //  -- a2    : argArray
  //  -- a1    : receiver
  //  -- a3    : undefined root value
  //  -- sp[0] : thisArg
  // -----------------------------------

  // 2. We don't need to check explicitly for callable receiver here,
  // since that's the first thing the Call/CallWithArrayLike builtins
  // will do.

  // 3. Tail call with no arguments if argArray is null or undefined.
  Label no_arguments;
  __ LoadRoot(scratch, RootIndex::kNullValue);
  __ CompareTaggedAndBranch(&no_arguments, eq, arg_array, Operand(scratch));
  __ CompareTaggedAndBranch(&no_arguments, eq, arg_array,
                            Operand(undefined_value));

  // 4a. Apply the receiver to the given argArray.
  __ TailCallBuiltin(Builtin::kCallWithArrayLike);

  // 4b. The argArray is either null or undefined, so we tail call without any
  // arguments to the receiver.
  __ bind(&no_arguments);
  {
    __ li(a0, JSParameterCount(0));
    DCHECK(receiver == a1);
    __ TailCallBuiltin(Builtins::Call());
  }
}

// static
void Builtins::Generate_FunctionPrototypeCall(MacroAssembler* masm) {
  // 1. Get the callable to call (passed as receiver) from the stack.
  { __ Pop(a1); }

  // 2. Make sure we have at least one argument.
  // a0: actual number of arguments
  {
    Label done;
    __ Branch(&done, ne, a0, Operand(JSParameterCount(0)));
    __ PushRoot(RootIndex::kUndefinedValue);
    __ Add_d(a0, a0, Operand(1));
    __ bind(&done);
  }

  // 3. Adjust the actual number of arguments.
  __ addi_d(a0, a0, -1);

  // 4. Call the callable.
  __ TailCallBuiltin(Builtins::Call());
}

void Builtins::Generate_ReflectApply(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- a0     : argc
  //  -- sp[0]  : receiver
  //  -- sp[8]  : target         (if argc >= 1)
  //  -- sp[16] : thisArgument   (if argc >= 2)
  //  -- sp[24] : argumentsList  (if argc == 3)
  // -----------------------------------

  Register argc = a0;
  Register arguments_list = a2;
  Register target = a1;
  Register this_argument = a5;
  Register undefined_value = a3;
  Register scratch = a4;

  __ LoadRoot(undefined_value, RootIndex::kUndefinedValue);

  // 1. Load target into a1 (if present), argumentsList into a2 (if present),
  // remove all arguments from the stack (including the receiver), and push
  // thisArgument (if present) instead.
  {
    // Claim (3 - argc) dummy arguments form the stack, to put the stack in a
    // consistent state for a simple pop operation.

    __ Sub_d(scratch, argc, Operand(JSParameterCount(0)));
    __ Ld_d(target, MemOperand(sp, kSystemPointerSize));
    __ Ld_d(this_argument, MemOperand(sp, 2 * kSystemPointerSize));
    __ Ld_d(arguments_list, MemOperand(sp, 3 * kSystemPointerSize));
    __ Movz(arguments_list, undefined_value, scratch);  // if argc == 0
    __ Movz(this_argument, undefined_value, scratch);   // if argc == 0
    __ Movz(target, undefined_value, scratch);          // if argc == 0
    __ Sub_d(scratch, scratch, Operand(1));
    __ Movz(arguments_list, undefined_value, scratch);  // if argc == 1
    __ Movz(this_argument, undefined_value, scratch);   // if argc == 1
    __ Sub_d(scratch, scratch, Operand(1));
    __ Movz(arguments_list, undefined_value, scratch);  // if argc == 2

    __ DropArgumentsAndPushNewReceiver(argc, this_argument);
  }

  // ----------- S t a t e -------------
  //  -- a2    : argumentsList
  //  -- a1    : target
  //  -- a3    : undefined root value
  //  -- sp[0] : thisArgument
  // -----------------------------------

  // 2. We don't need to check explicitly for callable target here,
  // since that's the first thing the Call/CallWithArrayLike builtins
  // will do.

  // 3. Apply the target to the given argumentsList.
  __ TailCallBuiltin(Builtin::kCallWithArrayLike);
}

void Builtins::Generate_ReflectConstruct(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- a0     : argc
  //  -- sp[0]   : receiver
  //  -- sp[8]   : target
  //  -- sp[16]  : argumentsList
  //  -- sp[24]  : new.target (optional)
  // -----------------------------------

  Register argc = a0;
  Register arguments_list = a2;
  Register target = a1;
  Register new_target = a3;
  Register undefined_value = a4;
  Register scratch = a5;

  __ LoadRoot(undefined_value, RootIndex::kUndefinedValue);

  // 1. Load target into a1 (if present), argumentsList into a2 (if present),
  // new.target into a3 (if present, otherwise use target), remove all
  // arguments from the stack (including the receiver), and push thisArgument
  // (if present) instead.
  {
    // Claim (3 - argc) dummy arguments form the stack, to put the stack in a
    // consistent state for a simple pop operation.

    __ Sub_d(scratch, argc, Operand(JSParameterCount(0)));
    __ Ld_d(target, MemOperand(sp, kSystemPointerSize));
    __ Ld_d(arguments_list, MemOperand(sp, 2 * kSystemPointerSize));
    __ Ld_d(new_target, MemOperand(sp, 3 * kSystemPointerSize));
    __ Movz(arguments_list, undefined_value, scratch);  // if argc == 0
    __ Movz(new_target, undefined_value, scratch);      // if argc == 0
    __ Movz(target, undefined_value, scratch);          // if argc == 0
    __ Sub_d(scratch, scratch, Operand(1));
    __ Movz(arguments_list, undefined_value, scratch);  // if argc == 1
    __ Movz(new_target, target, scratch);               // if argc == 1
    __ Sub_d(scratch, scratch, Operand(1));
    __ Movz(new_target, target, scratch);  // if argc == 2

    __ DropArgumentsAndPushNewReceiver(argc, undefined_value);
  }

  // ----------- S t a t e -------------
  //  -- a2    : argumentsList
  //  -- a1    : target
  //  -- a3    : new.target
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
    Register pointer_to_new_space_out, Register scratch1, Register scratch2,
    Register scratch3) {
  DCHECK(!AreAliased(count, argc_in_out, pointer_to_new_space_out, scratch1,
                     scratch2));
  Register old_sp = scratch1;
  Register new_space = scratch2;
  __ mov(old_sp, sp);
  __ slli_d(new_space, count, kSystemPointerSizeLog2);
  __ Sub_d(sp, sp, Operand(new_space));

  Register end = scratch2;
  Register value = scratch3;
  Register dest = pointer_to_new_space_out;
  __ mov(dest, sp);
  __ Alsl_d(end, argc_in_out, old_sp, kSystemPointerSizeLog2);
  Label loop, done;
  __ Branch(&done, ge, old_sp, Operand(end));
  __ bind(&loop);
  __ Ld_d(value, MemOperand(old_sp, 0));
  __ St_d(value, MemOperand(dest, 0));
  __ Add_d(old_sp, old_sp, Operand(kSystemPointerSize));
  __ Add_d(dest, dest, Operand(kSystemPointerSize));
  __ Branch(&loop, lt, old_sp, Operand(end));
  __ bind(&done);

  // Update total number of arguments.
  __ Add_d(argc_in_out, argc_in_out, count);
}

}  // namespace

// static
void Builtins::Generate_CallOrConstructVarargs(MacroAssembler* masm,
                                               Builtin target_builtin) {
  // ----------- S t a t e -------------
  //  -- a1 : target
  //  -- a0 : number of parameters on the stack
  //  -- a2 : arguments list (a FixedArray)
  //  -- a4 : len (number of elements to push from args)
  //  -- a3 : new.target (for [[Construct]])
  // -----------------------------------
  if (v8_flags.debug_code) {
    // Allow a2 to be a FixedArray, or a FixedDoubleArray if a4 == 0.
    Label ok, fail;
    __ AssertNotSmi(a2);
    __ GetObjectType(a2, t8, t8);
    __ Branch(&ok, eq, t8, Operand(FIXED_ARRAY_TYPE));
    __ Branch(&fail, ne, t8, Operand(FIXED_DOUBLE_ARRAY_TYPE));
    __ Branch(&ok, eq, a4, Operand(zero_reg));
    // Fall through.
    __ bind(&fail);
    __ Abort(AbortReason::kOperandIsNotAFixedArray);

    __ bind(&ok);
  }

  Register args = a2;
  Register len = a4;

  // Check for stack overflow.
  Label stack_overflow;
  __ StackOverflowCheck(len, kScratchReg, a5, &stack_overflow);

  // Move the arguments already in the stack,
  // including the receiver and the return address.
  // a4: Number of arguments to make room for.
  // a0: Number of arguments already on the stack.
  // a7: Points to first free slot on the stack after arguments were shifted.
  Generate_AllocateSpaceAndShiftExistingArguments(masm, a4, a0, a7, a6, t0, t1);

  // Push arguments onto the stack (thisArgument is already on the stack).
  {
    Label done, push, loop;
    Register src = a6;
    Register scratch = len;

    __ addi_d(src, args, OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag);
    __ Branch(&done, eq, len, Operand(zero_reg));
    __ slli_d(scratch, len, kSystemPointerSizeLog2);
    __ Sub_d(scratch, sp, Operand(scratch));
#if !V8_STATIC_ROOTS_BOOL
    // We do not use the Branch(reg, RootIndex) macro without static roots,
    // as it would do a LoadRoot behind the scenes and we want to avoid that
    // in a loop.
    __ LoadTaggedRoot(t1, RootIndex::kTheHoleValue);
#endif  // !V8_STATIC_ROOTS_BOOL
    __ bind(&loop);
    __ LoadTaggedField(a5, MemOperand(src, 0));
    __ addi_d(src, src, kTaggedSize);
#if V8_STATIC_ROOTS_BOOL
    __ Branch(&push, ne, a5, RootIndex::kTheHoleValue);
#else
    __ slli_w(t0, a5, 0);
    __ Branch(&push, ne, t0, Operand(t1));
#endif
    __ LoadRoot(a5, RootIndex::kUndefinedValue);
    __ bind(&push);
    __ St_d(a5, MemOperand(a7, 0));
    __ Add_d(a7, a7, Operand(kSystemPointerSize));
    __ Add_d(scratch, scratch, Operand(kSystemPointerSize));
    __ Branch(&loop, ne, scratch, Operand(sp));
    __ bind(&done);
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
  //  -- a0 : the number of arguments
  //  -- a3 : the new.target (for [[Construct]] calls)
  //  -- a1 : the target to call (can be any Object)
  //  -- a2 : start index (to support rest parameters)
  // -----------------------------------

  // Check if new.target has a [[Construct]] internal method.
  if (mode == CallOrConstructMode::kConstruct) {
    Label new_target_constructor, new_target_not_constructor;
    __ JumpIfSmi(a3, &new_target_not_constructor);
    __ LoadTaggedField(t1, FieldMemOperand(a3, HeapObject::kMapOffset));
    __ Ld_bu(t1, FieldMemOperand(t1, Map::kBitFieldOffset));
    __ And(t1, t1, Operand(Map::Bits1::IsConstructorBit::kMask));
    __ Branch(&new_target_constructor, ne, t1, Operand(zero_reg));
    __ bind(&new_target_not_constructor);
    {
      FrameScope scope(masm, StackFrame::MANUAL);
      __ EnterFrame(StackFrame::INTERNAL);
      __ Push(a3);
      __ CallRuntime(Runtime::kThrowNotConstructor);
    }
    __ bind(&new_target_constructor);
  }

  Label stack_done, stack_overflow;
  __ Ld_d(a7, MemOperand(fp, StandardFrameConstants::kArgCOffset));
  __ Sub_d(a7, a7, Operand(kJSArgcReceiverSlots));
  __ Sub_d(a7, a7, a2);
  __ Branch(&stack_done, le, a7, Operand(zero_reg));
  {
    // Check for stack overflow.
    __ StackOverflowCheck(a7, a4, a5, &stack_overflow);

    // Forward the arguments from the caller frame.

    // Point to the first argument to copy (skipping the receiver).
    __ Add_d(a6, fp,
             Operand(CommonFrameConstants::kFixedFrameSizeAboveFp +
                     kSystemPointerSize));
    __ Alsl_d(a6, a2, a6, kSystemPointerSizeLog2, t7);

    // Move the arguments already in the stack,
    // including the receiver and the return address.
    // a7: Number of arguments to make room for.
    // a0: Number of arguments already on the stack.
    // a2: Points to first free slot on the stack after arguments were shifted.
    Generate_AllocateSpaceAndShiftExistingArguments(masm, a7, a0, a2, t0, t1,
                                                    t2);

    // Copy arguments from the caller frame.
    // TODO(victorgomes): Consider using forward order as potentially more cache
    // friendly.
    {
      Label loop;
      __ bind(&loop);
      {
        __ Sub_w(a7, a7, Operand(1));
        __ Alsl_d(t0, a7, a6, kSystemPointerSizeLog2, t7);
        __ Ld_d(kScratchReg, MemOperand(t0, 0));
        __ Alsl_d(t0, a7, a2, kSystemPointerSizeLog2, t7);
        __ St_d(kScratchReg, MemOperand(t0, 0));
        __ Branch(&loop, ne, a7, Operand(zero_reg));
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
  //  -- a0 : the number of arguments
  //  -- a1 : the function to call (checked to be a JSFunction)
  // -----------------------------------
  __ AssertFunction(a1);

  __ LoadTaggedField(
      a2, FieldMemOperand(a1, JSFunction::kSharedFunctionInfoOffset));

  // Enter the context of the function; ToObject has to run in the function
  // context, and we also need to take the global proxy from the function
  // context in case of conversion.
  __ LoadTaggedField(cp, FieldMemOperand(a1, JSFunction::kContextOffset));
  // We need to convert the receiver for non-native sloppy mode functions.
  Label done_convert;
  __ Ld_wu(a3, FieldMemOperand(a2, SharedFunctionInfo::kFlagsOffset));
  __ And(kScratchReg, a3,
         Operand(SharedFunctionInfo::IsNativeBit::kMask |
                 SharedFunctionInfo::IsStrictBit::kMask));
  __ Branch(&done_convert, ne, kScratchReg, Operand(zero_reg));
  {
    // ----------- S t a t e -------------
    //  -- a0 : the number of arguments
    //  -- a1 : the function to call (checked to be a JSFunction)
    //  -- a2 : the shared function info.
    //  -- cp : the function context.
    // -----------------------------------

    if (mode == ConvertReceiverMode::kNullOrUndefined) {
      // Patch receiver to global proxy.
      __ LoadGlobalProxy(a3);
    } else {
      Label convert_to_object, convert_receiver;
      __ LoadReceiver(a3);
      __ JumpIfSmi(a3, &convert_to_object);
      __ JumpIfJSAnyIsNotPrimitive(a3, a4, &done_convert);
      if (mode != ConvertReceiverMode::kNotNullOrUndefined) {
        Label convert_global_proxy;
        __ JumpIfRoot(a3, RootIndex::kUndefinedValue, &convert_global_proxy);
        __ JumpIfNotRoot(a3, RootIndex::kNullValue, &convert_to_object);
        __ bind(&convert_global_proxy);
        {
          // Patch receiver to global proxy.
          __ LoadGlobalProxy(a3);
        }
        __ Branch(&convert_receiver);
      }
      __ bind(&convert_to_object);
      {
        // Convert receiver using ToObject.
        // TODO(bmeurer): Inline the allocation here to avoid building the frame
        // in the fast case? (fall back to AllocateInNewSpace?)
        FrameScope scope(masm, StackFrame::INTERNAL);
        __ SmiTag(a0);
        __ Push(a0, a1);
        __ mov(a0, a3);
        __ Push(cp);
        __ CallBuiltin(Builtin::kToObject);
        __ Pop(cp);
        __ mov(a3, a0);
        __ Pop(a0, a1);
        __ SmiUntag(a0);
      }
      __ LoadTaggedField(
          a2, FieldMemOperand(a1, JSFunction::kSharedFunctionInfoOffset));
      __ bind(&convert_receiver);
    }
    __ StoreReceiver(a3);
  }
  __ bind(&done_convert);

  // ----------- S t a t e -------------
  //  -- a0 : the number of arguments
  //  -- a1 : the function to call (checked to be a JSFunction)
  //  -- a2 : the shared function info.
  //  -- cp : the function context.
  // -----------------------------------

#ifdef V8_ENABLE_LEAPTIERING
  __ InvokeFunctionCode(a1, no_reg, a0, InvokeType::kJump);
#else
  __ Ld_hu(
      a2, FieldMemOperand(a2, SharedFunctionInfo::kFormalParameterCountOffset));
  __ InvokeFunctionCode(a1, no_reg, a2, a0, InvokeType::kJump);
#endif  // V8_ENABLE_LEAPTIERING
}

// static
void Builtins::Generate_CallBoundFunctionImpl(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- a0 : the number of arguments
  //  -- a1 : the function to call (checked to be a JSBoundFunction)
  // -----------------------------------
  __ AssertBoundFunction(a1);

  // Patch the receiver to [[BoundThis]].
  {
    __ LoadTaggedField(t0,
                       FieldMemOperand(a1, JSBoundFunction::kBoundThisOffset));
    __ StoreReceiver(t0);
  }

  // Load [[BoundArguments]] into a2 and length of that into a4.
  __ LoadTaggedField(
      a2, FieldMemOperand(a1, JSBoundFunction::kBoundArgumentsOffset));
  __ SmiUntagField(a4, FieldMemOperand(a2, offsetof(FixedArray, length_)));

  // ----------- S t a t e -------------
  //  -- a0 : the number of arguments
  //  -- a1 : the function to call (checked to be a JSBoundFunction)
  //  -- a2 : the [[BoundArguments]] (implemented as FixedArray)
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

  // Call the [[BoundTargetFunction]] via the Call builtin.
  __ LoadTaggedField(
      a1, FieldMemOperand(a1, JSBoundFunction::kBoundTargetFunctionOffset));
  __ TailCallBuiltin(Builtins::Call());
}

// static
void Builtins::Generate_Call(MacroAssembler* masm, ConvertReceiverMode mode) {
  // ----------- S t a t e -------------
  //  -- a0 : the number of arguments
  //  -- a1 : the target to call (can be any Object).
  // -----------------------------------

  Register target = a1;
  Register map = t1;
  Register instance_type = t2;
  Register scratch = t8;
  DCHECK(!AreAliased(a0, target, map, instance_type, scratch));

  Label non_callable, class_constructor;
  __ JumpIfSmi(target, &non_callable);
  __ LoadMap(map, target);
  __ GetInstanceTypeRange(map, instance_type, FIRST_CALLABLE_JS_FUNCTION_TYPE,
                          scratch);
  __ TailCallBuiltin(Builtins::CallFunction(mode), ls, scratch,
                     Operand(LAST_CALLABLE_JS_FUNCTION_TYPE -
                             FIRST_CALLABLE_JS_FUNCTION_TYPE));
  __ TailCallBuiltin(Builtin::kCallBoundFunction, eq, instance_type,
                     Operand(JS_BOUND_FUNCTION_TYPE));

  // Check if target has a [[Call]] internal method.
  {
    Register flags = t1;
    __ Ld_bu(flags, FieldMemOperand(map, Map::kBitFieldOffset));
    map = no_reg;
    __ And(flags, flags, Operand(Map::Bits1::IsCallableBit::kMask));
    __ Branch(&non_callable, eq, flags, Operand(zero_reg));
  }

  __ TailCallBuiltin(Builtin::kCallProxy, eq, instance_type,
                     Operand(JS_PROXY_TYPE));

  // Check if target is a wrapped function and call CallWrappedFunction external
  // builtin
  __ TailCallBuiltin(Builtin::kCallWrappedFunction, eq, instance_type,
                     Operand(JS_WRAPPED_FUNCTION_TYPE));

  // ES6 section 9.2.1 [[Call]] ( thisArgument, argumentsList)
  // Check that the function is not a "classConstructor".
  __ Branch(&class_constructor, eq, instance_type,
            Operand(JS_CLASS_CONSTRUCTOR_TYPE));

  // 2. Call to something else, which might have a [[Call]] internal method (if
  // not we raise an exception).
  // Overwrite the original receiver with the (original) target.
  __ StoreReceiver(target);
  // Let the "call_as_function_delegate" take care of the rest.
  __ LoadNativeContextSlot(target, Context::CALL_AS_FUNCTION_DELEGATE_INDEX);
  __ TailCallBuiltin(
      Builtins::CallFunction(ConvertReceiverMode::kNotNullOrUndefined));

  // 3. Call to something that is not callable.
  __ bind(&non_callable);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ Push(target);
    __ CallRuntime(Runtime::kThrowCalledNonCallable);
  }

  // 4. The function is a "classConstructor", need to raise an exception.
  __ bind(&class_constructor);
  {
    FrameScope frame(masm, StackFrame::INTERNAL);
    __ Push(target);
    __ CallRuntime(Runtime::kThrowConstructorNonCallableError);
  }
}

void Builtins::Generate_ConstructFunction(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- a0 : the number of arguments
  //  -- a1 : the constructor to call (checked to be a JSFunction)
  //  -- a3 : the new target (checked to be a constructor)
  // -----------------------------------
  __ AssertConstructor(a1);
  __ AssertF
"""


```