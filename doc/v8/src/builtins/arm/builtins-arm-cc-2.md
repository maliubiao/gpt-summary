Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the V8 JavaScript engine.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Language and Context:** The code is C++ and resides in `v8/src/builtins/arm/builtins-arm.cc`. The path suggests it's related to built-in functions for the ARM architecture within V8.

2. **High-Level Overview:** The code defines various built-in functions that are essential for executing JavaScript code. These built-ins handle core functionalities like interpreting bytecode, calling functions, constructing objects, and handling optimization and deoptimization.

3. **Function-by-Function Analysis:** Go through each function defined in the snippet and understand its purpose. Look for keywords and patterns that reveal their function:
    * **Interpreter-related:** Functions starting with `Generate_Interpreter...` clearly deal with the interpreter. They handle entering and resuming execution of bytecode.
    * **`ContinueTo...`:** These functions seem to be involved in resuming execution after some operation, potentially related to deoptimization. The `javascript_builtin` flag hints at different handling for JavaScript built-ins.
    * **`NotifyDeoptimized`:** This function is for informing the runtime about deoptimization.
    * **`...OnStackReplacement`:** These functions are crucial for the optimization process, facilitating the transition from less optimized to more optimized code during runtime.
    * **`...FunctionPrototype...` and `Reflect...`:** These are implementations of standard JavaScript methods.
    * **`...Varargs` and `...ForwardVarargs`:** These built-ins handle function calls with a variable number of arguments.
    * **`Call...` and `Construct...`:**  These are fundamental built-ins for function invocation and object creation.
    * **`...BoundFunction...`:** These deal with the specifics of calling and constructing bound functions.

4. **Identify Key Themes:**  Group related functions together to identify major areas of functionality:
    * **Interpreter Execution:**  `Generate_InterpreterDispatch`, `Generate_InterpreterEnter...`
    * **Deoptimization and Optimization:** `Generate_ContinueTo...`, `Generate_NotifyDeoptimized`, `Generate_...OnStackReplacement`
    * **Standard JavaScript Functions:** `Generate_FunctionPrototypeApply`, `Generate_FunctionPrototypeCall`, `Generate_ReflectApply`, `Generate_ReflectConstruct`
    * **Variable Arguments:** `Generate_CallOrConstructVarargs`, `Generate_CallOrConstructForwardVarargs`
    * **Function Calls:** `Generate_CallFunction`, `Generate_Call`
    * **Object Construction:** `Generate_ConstructFunction`, `Generate_ConstructBoundFunction`
    * **Bound Functions:** `Generate_CallBoundFunctionImpl`

5. **Address Specific Questions:**
    * **`.tq` extension:**  The code is `.cc`, so it's standard C++. The comment clarifies what a `.tq` extension would signify.
    * **Relationship to JavaScript:** Many functions directly implement JavaScript features (e.g., `Function.prototype.apply`). Provide JavaScript examples demonstrating these features.
    * **Code Logic and Reasoning:** For the interpreter-related functions, outline the steps involved (loading bytecode, advancing the offset, dispatching). Provide hypothetical input and output for the bytecode offset.
    * **Common Programming Errors:** Relate the function implementations to common JavaScript errors like calling non-callable objects or trying to call class constructors without `new`.

6. **Summarize the Functionality:** Condense the identified themes into a concise summary.

7. **Structure the Answer:** Organize the information logically, addressing each aspect of the user's request. Use clear headings and bullet points.

8. **Review and Refine:**  Check for accuracy, clarity, and completeness. Ensure the JavaScript examples are correct and illustrate the intended points. Make sure the summary accurately reflects the code's purpose. For instance, ensure the connection between the C++ built-ins and their corresponding JavaScript functionality is clearly stated. Initially, I might have just listed the functions, but the prompt asks for *functionality*, which requires explaining *what* they do in the context of JavaScript. The prompt also specifically asks about common programming errors, so adding examples for those is important.

By following these steps, a comprehensive and accurate answer can be generated that meets all the requirements of the user's request.
这是 V8 JavaScript 引擎在 ARM 架构下的内置函数实现代码的第三部分。它主要负责实现 V8 引擎中各种核心的 JavaScript 功能，特别是与函数调用、对象构造、以及解释器和优化相关的操作。

**功能归纳:**

这部分代码主要涵盖了以下功能：

1. **解释器入口和调度:**
   - `Generate_InterpreterDispatch`:  负责将控制权转移到解释器去执行字节码。
   - `Generate_InterpreterEnterAtNextBytecode`:  在解释器中执行下一个字节码，并处理一些边界情况，例如函数入口。
   - `Generate_InterpreterEnterAtBytecode`:  直接进入解释器执行字节码。

2. **从 Builtin 返回:**
   - `Generate_ContinueToCodeStubBuiltin`:  用于从一个 CodeStub 内置函数返回。
   - `Generate_ContinueToCodeStubBuiltinWithResult`:  与上一个类似，但带有返回值。
   - `Generate_ContinueToJavaScriptBuiltin`:  用于从一个 JavaScript 内置函数返回。
   - `Generate_ContinueToJavaScriptBuiltinWithResult`:  与上一个类似，但带有返回值。
   - 这些函数通常在 deoptimization 后，需要恢复执行流程时被调用。

3. **处理 Deoptimization:**
   - `Generate_NotifyDeoptimized`:  通知运行时发生了 deoptimization。

4. **栈上替换 (OSR - On-Stack Replacement):**
   - `Generate_InterpreterOnStackReplacement`:  处理从解释器到优化代码的栈上替换。
   - `Generate_BaselineOnStackReplacement`:  处理从 Baseline 代码到优化代码的栈上替换。
   - 这些功能允许在程序运行时将正在执行的解释器或 Baseline 代码替换为更优化的代码。

5. **Maglev 函数入口栈检查:**
   - `Generate_MaglevFunctionEntryStackCheck`:  在 Maglev 优化编译的函数入口处进行栈溢出检查。

6. **实现 `Function.prototype.apply` 和 `Function.prototype.call`:**
   - `Generate_FunctionPrototypeApply`:  实现了 `Function.prototype.apply` 的功能。
   - `Generate_FunctionPrototypeCall`:  实现了 `Function.prototype.call` 的功能。

7. **实现 `Reflect.apply` 和 `Reflect.construct`:**
   - `Generate_ReflectApply`:  实现了 `Reflect.apply` 的功能。
   - `Generate_ReflectConstruct`: 实现了 `Reflect.construct` 的功能。

8. **处理可变参数函数调用 (`...Varargs`):**
   - `Generate_CallOrConstructVarargs`:  用于实现 `Function.prototype.apply` 和 `Reflect.apply` 等，将数组或类数组的参数展开并调用函数或构造函数。
   - `Generate_CallOrConstructForwardVarargs`:  用于实现 rest 参数等，将调用者的部分参数传递给被调用函数或构造函数。

9. **实现 `CallFunction`:**
   - `Generate_CallFunction`:  实现函数调用的核心逻辑，包括 receiver 的转换（根据调用模式）。

10. **处理 Bound Function 的调用和构造:**
    - `Generate_PushBoundArguments`:  将 bound function 的绑定参数压入栈中。
    - `Generate_CallBoundFunctionImpl`:  实现 bound function 的调用逻辑。
    - `Generate_ConstructBoundFunction`: 实现 bound function 的构造逻辑。

11. **实现 `Call` 和 `Construct`:**
    - `Generate_Call`:  实现了 JavaScript 中普通函数调用的核心逻辑，包括检查可调用性。
    - `Generate_ConstructFunction`: 实现了 JavaScript 中构造函数调用的核心逻辑。

**如果 `v8/src/builtins/arm/builtins-arm.cc` 以 `.tq` 结尾:**

那么它将是一个 **V8 Torque 源代码**。Torque 是 V8 使用的一种领域特定语言，用于更安全和更易于维护地定义内置函数。 Torque 代码会被编译成 C++ 代码。

**与 JavaScript 功能的关系及 JavaScript 示例:**

以下是一些与代码功能相关的 JavaScript 示例：

* **`Function.prototype.apply` 和 `Function.prototype.call`:**

   ```javascript
   function greet(greeting) {
     console.log(greeting + ', ' + this.name);
   }

   const person = { name: 'Alice' };

   greet.call(person, 'Hello');   // 输出: Hello, Alice
   greet.apply(person, ['Hi']);    // 输出: Hi, Alice
   ```

* **`Reflect.apply` 和 `Reflect.construct`:**

   ```javascript
   function sum(a, b) {
     return a + b;
   }

   const resultApply = Reflect.apply(sum, null, [5, 3]);
   console.log(resultApply); // 输出: 8

   class Point {
     constructor(x, y) {
       this.x = x;
       this.y = y;
     }
   }

   const point = Reflect.construct(Point, [10, 20]);
   console.log(point.x, point.y); // 输出: 10 20
   ```

* **可变参数和 Rest 参数:**

   ```javascript
   function addAll() {
     let sum = 0;
     for (let i = 0; i < arguments.length; i++) {
       sum += arguments[i];
     }
     return sum;
   }

   console.log(addAll(1, 2, 3, 4)); // 输出: 10

   function multiply(factor, ...numbers) {
     return numbers.map(num => num * factor);
   }

   console.log(multiply(5, 1, 2, 3)); // 输出: [5, 10, 15]
   ```

* **Bound Function:**

   ```javascript
   function multiplyBy(factor, number) {
     return factor * number;
   }

   const double = multiplyBy.bind(null, 2);
   console.log(double(5)); // 输出: 10
   ```

* **`Call` 和 `Construct` (直接调用和使用 `new` 关键字):**

   ```javascript
   function myFunction() {
     console.log("Function called!");
   }

   myFunction(); // 直接调用

   class MyClass {}
   const instance = new MyClass(); // 使用 new 构造对象
   ```

**代码逻辑推理 (假设输入与输出):**

以 `Generate_InterpreterEnterAtNextBytecode` 为例：

**假设输入:**

* 当前的解释器栈帧 (fp) 指向一个有效的栈帧。
* 栈帧中存储了 `kBytecodeArrayFromFp` 和 `kBytecodeOffsetFromFp`。
* `kBytecodeOffsetFromFp` 指向字节码数组中的某个偏移量。

**输出:**

* `kInterpreterBytecodeOffsetRegister` 更新为下一个要执行的字节码的偏移量（以 Smi 格式存储）。
* 如果当前字节码是 `kFunctionEntryBytecodeOffset`，则跳转到函数入口的特殊处理逻辑。
* 最终调用 `Generate_InterpreterEnterBytecode` 来执行下一个字节码。

**用户常见的编程错误:**

* **调用不可调用的对象:**

   ```javascript
   const obj = {};
   obj(); // TypeError: obj is not a function
   ```
   `Generate_Call` 中的检查会捕获这类错误并抛出异常。

* **尝试调用类构造函数但不使用 `new` 关键字:**

   ```javascript
   class MyClass {}
   MyClass(); // TypeError: Class constructor MyClass cannot be invoked without 'new'
   ```
   `Generate_Call` 中会检查 `JS_CLASS_CONSTRUCTOR_TYPE` 并抛出相应的错误。

* **`Function.prototype.apply` 或 `Reflect.apply` 的参数错误:**

   ```javascript
   function test(a, b) { console.log(a, b); }
   test.apply(null, 1); // TypeError: CreateListFromArrayLike called on non-object
   Reflect.apply(test, null, 1); // TypeError: CreateListFromArrayLike called on non-object
   ```
   虽然 C++ 代码本身不直接处理 JavaScript 级别的类型错误，但它为 `CallWithArrayLike` 等内置函数提供了基础，这些内置函数会进行参数校验。

**总结:**

`v8/src/builtins/arm/builtins-arm.cc` 的这部分代码是 V8 引擎在 ARM 架构下实现核心 JavaScript 语义的关键组成部分。它涵盖了解释器调度、优化过程中的栈替换、以及各种重要的内置函数（如 `Function.prototype.call/apply` 和 `Reflect` API）。这些内置函数直接支撑着 JavaScript 代码的执行，并处理了一些常见的运行时错误。理解这部分代码有助于深入了解 V8 引擎的工作原理和 JavaScript 的底层实现。

Prompt: 
```
这是目录为v8/src/builtins/arm/builtins-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/arm/builtins-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能

"""
nd(kInterpreterDispatchTableRegister, scratch, LSL,
                    kPointerSizeLog2));
  __ Jump(kJavaScriptCallCodeStartRegister);
}

void Builtins::Generate_InterpreterEnterAtNextBytecode(MacroAssembler* masm) {
  // Get bytecode array and bytecode offset from the stack frame.
  __ ldr(kInterpreterBytecodeArrayRegister,
         MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ ldr(kInterpreterBytecodeOffsetRegister,
         MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ SmiUntag(kInterpreterBytecodeOffsetRegister);

  Label enter_bytecode, function_entry_bytecode;
  __ cmp(kInterpreterBytecodeOffsetRegister,
         Operand(BytecodeArray::kHeaderSize - kHeapObjectTag +
                 kFunctionEntryBytecodeOffset));
  __ b(eq, &function_entry_bytecode);

  // Load the current bytecode.
  __ ldrb(r1, MemOperand(kInterpreterBytecodeArrayRegister,
                         kInterpreterBytecodeOffsetRegister));

  // Advance to the next bytecode.
  Label if_return;
  AdvanceBytecodeOffsetOrReturn(masm, kInterpreterBytecodeArrayRegister,
                                kInterpreterBytecodeOffsetRegister, r1, r2, r3,
                                &if_return);

  __ bind(&enter_bytecode);
  // Convert new bytecode offset to a Smi and save in the stackframe.
  __ SmiTag(r2, kInterpreterBytecodeOffsetRegister);
  __ str(r2, MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));

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
  UseScratchRegisterScope temps(masm);
  Register scratch = temps.Acquire();  // Temp register is not allocatable.
  if (with_result) {
    if (javascript_builtin) {
      __ mov(scratch, r0);
    } else {
      // Overwrite the hole inserted by the deoptimizer with the return value
      // from the LAZY deopt point.
      __ str(
          r0,
          MemOperand(
              sp, config->num_allocatable_general_registers() * kPointerSize +
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
    __ add(r0, r0, Operand(return_value_offset));
    __ str(scratch, MemOperand(sp, r0, LSL, kPointerSizeLog2));
    // Recover arguments count.
    __ sub(r0, r0, Operand(return_value_offset));
  }
  __ ldr(fp, MemOperand(
                 sp, BuiltinContinuationFrameConstants::kFixedFrameSizeFromFp));
  // Load builtin index (stored as a Smi) and use it to get the builtin start
  // address from the builtins table.
  Register builtin = scratch;
  __ Pop(builtin);
  __ add(sp, sp,
         Operand(BuiltinContinuationFrameConstants::kFixedFrameSizeFromFp));
  __ Pop(lr);
  __ LoadEntryFromBuiltinIndex(builtin, builtin);
  __ bx(builtin);
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
    FrameAndConstantPoolScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kNotifyDeoptimized);
  }

  DCHECK_EQ(kInterpreterAccumulatorRegister.code(), r0.code());
  __ pop(r0);
  __ Ret();
}

namespace {

void Generate_OSREntry(MacroAssembler* masm, Register entry_address,
                       Operand offset = Operand::Zero()) {
  // Compute the target address = entry_address + offset
  if (offset.IsImmediate() && offset.immediate() == 0) {
    __ mov(lr, entry_address);
  } else {
    __ add(lr, entry_address, offset);
  }

  // "return" to the OSR entry point of the function.
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
    __ cmp(maybe_target_code, Operand(Smi::zero()));
    __ b(ne, &jump_to_optimized_code);
  }

  ASM_CODE_COMMENT(masm);
  {
    FrameAndConstantPoolScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kCompileOptimizedOSR);
  }

  // If the code object is null, just return to the caller.
  __ cmp(r0, Operand(Smi::zero()));
  __ b(ne, &jump_to_optimized_code);
  __ Ret();

  __ bind(&jump_to_optimized_code);
  DCHECK_EQ(maybe_target_code, r0);  // Already in the right spot.

  // OSR entry tracing.
  {
    Label next;
    __ Move(r1, ExternalReference::address_of_log_or_trace_osr());
    __ ldrsb(r1, MemOperand(r1));
    __ tst(r1, Operand(0xFF));  // Mask to the LSB.
    __ b(eq, &next);

    {
      FrameAndConstantPoolScope scope(masm, StackFrame::INTERNAL);
      __ Push(r0);  // Preserve the code object.
      __ CallRuntime(Runtime::kLogOrTraceOptimizedOSREntry, 0);
      __ Pop(r0);
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
  __ ldr(r1,
         FieldMemOperand(r0, Code::kDeoptimizationDataOrInterpreterDataOffset));

  __ LoadCodeInstructionStart(r0, r0);

  {
    ConstantPoolUnavailableScope constant_pool_unavailable(masm);

    // Load the OSR entrypoint offset from the deoptimization data.
    // <osr_offset> = <deopt_data>[#header_size + #osr_pc_offset]
    __ ldr(r1, FieldMemOperand(r1, FixedArray::OffsetOfElementAt(
                                       DeoptimizationData::kOsrPcOffsetIndex)));

    Generate_OSREntry(masm, r0, Operand::SmiUntag(r1));
  }
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

void Builtins::Generate_MaglevFunctionEntryStackCheck(MacroAssembler* masm,
                                                      bool save_new_target) {
  // Input (r0): Stack size (Smi).
  // This builtin can be invoked just after Maglev's prologue.
  // All registers are available, except (possibly) new.target.
  ASM_CODE_COMMENT(masm);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ AssertSmi(r0);
    if (save_new_target) {
      __ Push(kJavaScriptCallNewTargetRegister);
    }
    __ Push(r0);
    __ CallRuntime(Runtime::kStackGuardWithGap, 1);
    if (save_new_target) {
      __ Pop(kJavaScriptCallNewTargetRegister);
    }
  }
  __ Ret();
}

#endif  // V8_ENABLE_MAGLEV

// static
void Builtins::Generate_FunctionPrototypeApply(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r0    : argc
  //  -- sp[0] : receiver
  //  -- sp[4] : thisArg
  //  -- sp[8] : argArray
  // -----------------------------------

  // 1. Load receiver into r1, argArray into r2 (if present), remove all
  // arguments from the stack (including the receiver), and push thisArg (if
  // present) instead.
  {
    __ LoadRoot(r5, RootIndex::kUndefinedValue);
    __ mov(r2, r5);
    __ ldr(r1, MemOperand(sp, 0));  // receiver
    __ cmp(r0, Operand(JSParameterCount(1)));
    __ ldr(r5, MemOperand(sp, kSystemPointerSize), ge);  // thisArg
    __ cmp(r0, Operand(JSParameterCount(2)), ge);
    __ ldr(r2, MemOperand(sp, 2 * kSystemPointerSize), ge);  // argArray
    __ DropArgumentsAndPushNewReceiver(r0, r5);
  }

  // ----------- S t a t e -------------
  //  -- r2    : argArray
  //  -- r1    : receiver
  //  -- sp[0] : thisArg
  // -----------------------------------

  // 2. We don't need to check explicitly for callable receiver here,
  // since that's the first thing the Call/CallWithArrayLike builtins
  // will do.

  // 3. Tail call with no arguments if argArray is null or undefined.
  Label no_arguments;
  __ JumpIfRoot(r2, RootIndex::kNullValue, &no_arguments);
  __ JumpIfRoot(r2, RootIndex::kUndefinedValue, &no_arguments);

  // 4a. Apply the receiver to the given argArray.
  __ TailCallBuiltin(Builtin::kCallWithArrayLike);

  // 4b. The argArray is either null or undefined, so we tail call without any
  // arguments to the receiver.
  __ bind(&no_arguments);
  {
    __ mov(r0, Operand(JSParameterCount(0)));
    __ TailCallBuiltin(Builtins::Call());
  }
}

// static
void Builtins::Generate_FunctionPrototypeCall(MacroAssembler* masm) {
  // 1. Get the callable to call (passed as receiver) from the stack.
  __ Pop(r1);

  // 2. Make sure we have at least one argument.
  // r0: actual number of arguments
  {
    Label done;
    __ cmp(r0, Operand(JSParameterCount(0)));
    __ b(ne, &done);
    __ PushRoot(RootIndex::kUndefinedValue);
    __ add(r0, r0, Operand(1));
    __ bind(&done);
  }

  // 3. Adjust the actual number of arguments.
  __ sub(r0, r0, Operand(1));

  // 4. Call the callable.
  __ TailCallBuiltin(Builtins::Call());
}

void Builtins::Generate_ReflectApply(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r0     : argc
  //  -- sp[0]  : receiver
  //  -- sp[4]  : target         (if argc >= 1)
  //  -- sp[8]  : thisArgument   (if argc >= 2)
  //  -- sp[12] : argumentsList  (if argc == 3)
  // -----------------------------------

  // 1. Load target into r1 (if present), argumentsList into r2 (if present),
  // remove all arguments from the stack (including the receiver), and push
  // thisArgument (if present) instead.
  {
    __ LoadRoot(r1, RootIndex::kUndefinedValue);
    __ mov(r5, r1);
    __ mov(r2, r1);
    __ cmp(r0, Operand(JSParameterCount(1)));
    __ ldr(r1, MemOperand(sp, kSystemPointerSize), ge);  // target
    __ cmp(r0, Operand(JSParameterCount(2)), ge);
    __ ldr(r5, MemOperand(sp, 2 * kSystemPointerSize), ge);  // thisArgument
    __ cmp(r0, Operand(JSParameterCount(3)), ge);
    __ ldr(r2, MemOperand(sp, 3 * kSystemPointerSize), ge);  // argumentsList
    __ DropArgumentsAndPushNewReceiver(r0, r5);
  }

  // ----------- S t a t e -------------
  //  -- r2    : argumentsList
  //  -- r1    : target
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
  //  -- r0     : argc
  //  -- sp[0]  : receiver
  //  -- sp[4]  : target
  //  -- sp[8]  : argumentsList
  //  -- sp[12] : new.target (optional)
  // -----------------------------------

  // 1. Load target into r1 (if present), argumentsList into r2 (if present),
  // new.target into r3 (if present, otherwise use target), remove all
  // arguments from the stack (including the receiver), and push thisArgument
  // (if present) instead.
  {
    __ LoadRoot(r1, RootIndex::kUndefinedValue);
    __ mov(r2, r1);
    __ mov(r4, r1);
    __ cmp(r0, Operand(JSParameterCount(1)));
    __ ldr(r1, MemOperand(sp, kSystemPointerSize), ge);  // target
    __ mov(r3, r1);  // new.target defaults to target
    __ cmp(r0, Operand(JSParameterCount(2)), ge);
    __ ldr(r2, MemOperand(sp, 2 * kSystemPointerSize), ge);  // argumentsList
    __ cmp(r0, Operand(JSParameterCount(3)), ge);
    __ ldr(r3, MemOperand(sp, 3 * kSystemPointerSize), ge);  // new.target
    __ DropArgumentsAndPushNewReceiver(r0, r4);
  }

  // ----------- S t a t e -------------
  //  -- r2    : argumentsList
  //  -- r3    : new.target
  //  -- r1    : target
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
  UseScratchRegisterScope temps(masm);
  Register old_sp = scratch1;
  Register new_space = scratch2;
  __ mov(old_sp, sp);
  __ lsl(new_space, count, Operand(kSystemPointerSizeLog2));
  __ AllocateStackSpace(new_space);

  Register end = scratch2;
  Register value = temps.Acquire();
  Register dest = pointer_to_new_space_out;
  __ mov(dest, sp);
  __ add(end, old_sp, Operand(argc_in_out, LSL, kSystemPointerSizeLog2));
  Label loop, done;
  __ bind(&loop);
  __ cmp(old_sp, end);
  __ b(ge, &done);
  __ ldr(value, MemOperand(old_sp, kSystemPointerSize, PostIndex));
  __ str(value, MemOperand(dest, kSystemPointerSize, PostIndex));
  __ b(&loop);
  __ bind(&done);

  // Update total number of arguments.
  __ add(argc_in_out, argc_in_out, count);
}

}  // namespace

// static
// TODO(v8:11615): Observe Code::kMaxArguments in
// CallOrConstructVarargs
void Builtins::Generate_CallOrConstructVarargs(MacroAssembler* masm,
                                               Builtin target_builtin) {
  // ----------- S t a t e -------------
  //  -- r1 : target
  //  -- r0 : number of parameters on the stack
  //  -- r2 : arguments list (a FixedArray)
  //  -- r4 : len (number of elements to push from args)
  //  -- r3 : new.target (for [[Construct]])
  // -----------------------------------
  Register scratch = r8;

  if (v8_flags.debug_code) {
    // Allow r2 to be a FixedArray, or a FixedDoubleArray if r4 == 0.
    Label ok, fail;
    __ AssertNotSmi(r2);
    __ ldr(scratch, FieldMemOperand(r2, HeapObject::kMapOffset));
    __ ldrh(r6, FieldMemOperand(scratch, Map::kInstanceTypeOffset));
    __ cmp(r6, Operand(FIXED_ARRAY_TYPE));
    __ b(eq, &ok);
    __ cmp(r6, Operand(FIXED_DOUBLE_ARRAY_TYPE));
    __ b(ne, &fail);
    __ cmp(r4, Operand(0));
    __ b(eq, &ok);
    // Fall through.
    __ bind(&fail);
    __ Abort(AbortReason::kOperandIsNotAFixedArray);

    __ bind(&ok);
  }

  Label stack_overflow;
  __ StackOverflowCheck(r4, scratch, &stack_overflow);

  // Move the arguments already in the stack,
  // including the receiver and the return address.
  // r4: Number of arguments to make room for.
  // r0: Number of arguments already on the stack.
  // r9: Points to first free slot on the stack after arguments were shifted.
  Generate_AllocateSpaceAndShiftExistingArguments(masm, r4, r0, r9, r5, r6);

  // Copy arguments onto the stack (thisArgument is already on the stack).
  {
    __ mov(r6, Operand(0));
    __ LoadRoot(r5, RootIndex::kTheHoleValue);
    Label done, loop;
    __ bind(&loop);
    __ cmp(r6, r4);
    __ b(eq, &done);
    __ add(scratch, r2, Operand(r6, LSL, kTaggedSizeLog2));
    __ ldr(scratch, FieldMemOperand(scratch, OFFSET_OF_DATA_START(FixedArray)));
    __ cmp(scratch, r5);
    // Turn the hole into undefined as we go.
    __ LoadRoot(scratch, RootIndex::kUndefinedValue, eq);
    __ str(scratch, MemOperand(r9, kSystemPointerSize, PostIndex));
    __ add(r6, r6, Operand(1));
    __ b(&loop);
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
  //  -- r0 : the number of arguments
  //  -- r3 : the new.target (for [[Construct]] calls)
  //  -- r1 : the target to call (can be any Object)
  //  -- r2 : start index (to support rest parameters)
  // -----------------------------------

  Register scratch = r6;

  // Check if new.target has a [[Construct]] internal method.
  if (mode == CallOrConstructMode::kConstruct) {
    Label new_target_constructor, new_target_not_constructor;
    __ JumpIfSmi(r3, &new_target_not_constructor);
    __ ldr(scratch, FieldMemOperand(r3, HeapObject::kMapOffset));
    __ ldrb(scratch, FieldMemOperand(scratch, Map::kBitFieldOffset));
    __ tst(scratch, Operand(Map::Bits1::IsConstructorBit::kMask));
    __ b(ne, &new_target_constructor);
    __ bind(&new_target_not_constructor);
    {
      FrameScope scope(masm, StackFrame::MANUAL);
      __ EnterFrame(StackFrame::INTERNAL);
      __ Push(r3);
      __ CallRuntime(Runtime::kThrowNotConstructor);
    }
    __ bind(&new_target_constructor);
  }

  Label stack_done, stack_overflow;
  __ ldr(r5, MemOperand(fp, StandardFrameConstants::kArgCOffset));
  __ sub(r5, r5, Operand(kJSArgcReceiverSlots));
  __ sub(r5, r5, r2, SetCC);
  __ b(le, &stack_done);
  {
    // ----------- S t a t e -------------
    //  -- r0 : the number of arguments already in the stack
    //  -- r1 : the target to call (can be any Object)
    //  -- r2 : start index (to support rest parameters)
    //  -- r3 : the new.target (for [[Construct]] calls)
    //  -- fp : point to the caller stack frame
    //  -- r5 : number of arguments to copy, i.e. arguments count - start index
    // -----------------------------------

    // Check for stack overflow.
    __ StackOverflowCheck(r5, scratch, &stack_overflow);

    // Forward the arguments from the caller frame.
    // Point to the first argument to copy (skipping the receiver).
    __ add(r4, fp,
           Operand(CommonFrameConstants::kFixedFrameSizeAboveFp +
                   kSystemPointerSize));
    __ add(r4, r4, Operand(r2, LSL, kSystemPointerSizeLog2));

    // Move the arguments already in the stack,
    // including the receiver and the return address.
    // r5: Number of arguments to make room for.
    // r0: Number of arguments already on the stack.
    // r2: Points to first free slot on the stack after arguments were shifted.
    Generate_AllocateSpaceAndShiftExistingArguments(masm, r5, r0, r2, scratch,
                                                    r8);

    // Copy arguments from the caller frame.
    // TODO(victorgomes): Consider using forward order as potentially more cache
    // friendly.
    {
      Label loop;
      __ bind(&loop);
      {
        __ sub(r5, r5, Operand(1), SetCC);
        __ ldr(scratch, MemOperand(r4, r5, LSL, kSystemPointerSizeLog2));
        __ str(scratch, MemOperand(r2, r5, LSL, kSystemPointerSizeLog2));
        __ b(ne, &loop);
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
  //  -- r0 : the number of arguments
  //  -- r1 : the function to call (checked to be a JSFunction)
  // -----------------------------------
  __ AssertCallableFunction(r1);

  __ ldr(r2, FieldMemOperand(r1, JSFunction::kSharedFunctionInfoOffset));

  // Enter the context of the function; ToObject has to run in the function
  // context, and we also need to take the global proxy from the function
  // context in case of conversion.
  __ ldr(cp, FieldMemOperand(r1, JSFunction::kContextOffset));
  // We need to convert the receiver for non-native sloppy mode functions.
  Label done_convert;
  __ ldr(r3, FieldMemOperand(r2, SharedFunctionInfo::kFlagsOffset));
  __ tst(r3, Operand(SharedFunctionInfo::IsNativeBit::kMask |
                     SharedFunctionInfo::IsStrictBit::kMask));
  __ b(ne, &done_convert);
  {
    // ----------- S t a t e -------------
    //  -- r0 : the number of arguments
    //  -- r1 : the function to call (checked to be a JSFunction)
    //  -- r2 : the shared function info.
    //  -- cp : the function context.
    // -----------------------------------

    if (mode == ConvertReceiverMode::kNullOrUndefined) {
      // Patch receiver to global proxy.
      __ LoadGlobalProxy(r3);
    } else {
      Label convert_to_object, convert_receiver;
      __ ldr(r3, __ ReceiverOperand());
      __ JumpIfSmi(r3, &convert_to_object);
      static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
      __ CompareObjectType(r3, r4, r4, FIRST_JS_RECEIVER_TYPE);
      __ b(hs, &done_convert);
      if (mode != ConvertReceiverMode::kNotNullOrUndefined) {
        Label convert_global_proxy;
        __ JumpIfRoot(r3, RootIndex::kUndefinedValue, &convert_global_proxy);
        __ JumpIfNotRoot(r3, RootIndex::kNullValue, &convert_to_object);
        __ bind(&convert_global_proxy);
        {
          // Patch receiver to global proxy.
          __ LoadGlobalProxy(r3);
        }
        __ b(&convert_receiver);
      }
      __ bind(&convert_to_object);
      {
        // Convert receiver using ToObject.
        // TODO(bmeurer): Inline the allocation here to avoid building the frame
        // in the fast case? (fall back to AllocateInNewSpace?)
        FrameAndConstantPoolScope scope(masm, StackFrame::INTERNAL);
        __ SmiTag(r0);
        __ Push(r0, r1);
        __ mov(r0, r3);
        __ Push(cp);
        __ CallBuiltin(Builtin::kToObject);
        __ Pop(cp);
        __ mov(r3, r0);
        __ Pop(r0, r1);
        __ SmiUntag(r0);
      }
      __ ldr(r2, FieldMemOperand(r1, JSFunction::kSharedFunctionInfoOffset));
      __ bind(&convert_receiver);
    }
    __ str(r3, __ ReceiverOperand());
  }
  __ bind(&done_convert);

  // ----------- S t a t e -------------
  //  -- r0 : the number of arguments
  //  -- r1 : the function to call (checked to be a JSFunction)
  //  -- r2 : the shared function info.
  //  -- cp : the function context.
  // -----------------------------------

  __ ldrh(r2,
          FieldMemOperand(r2, SharedFunctionInfo::kFormalParameterCountOffset));
  __ InvokeFunctionCode(r1, no_reg, r2, r0, InvokeType::kJump);
}

namespace {

void Generate_PushBoundArguments(MacroAssembler* masm) {
  ASM_CODE_COMMENT(masm);
  // ----------- S t a t e -------------
  //  -- r0 : the number of arguments
  //  -- r1 : target (checked to be a JSBoundFunction)
  //  -- r3 : new.target (only in case of [[Construct]])
  // -----------------------------------

  // Load [[BoundArguments]] into r2 and length of that into r4.
  Label no_bound_arguments;
  __ ldr(r2, FieldMemOperand(r1, JSBoundFunction::kBoundArgumentsOffset));
  __ ldr(r4, FieldMemOperand(r2, offsetof(FixedArray, length_)));
  __ SmiUntag(r4);
  __ cmp(r4, Operand(0));
  __ b(eq, &no_bound_arguments);
  {
    // ----------- S t a t e -------------
    //  -- r0 : the number of arguments
    //  -- r1 : target (checked to be a JSBoundFunction)
    //  -- r2 : the [[BoundArguments]] (implemented as FixedArray)
    //  -- r3 : new.target (only in case of [[Construct]])
    //  -- r4 : the number of [[BoundArguments]]
    // -----------------------------------

    Register scratch = r6;

    {
      // Check the stack for overflow. We are not trying to catch interruptions
      // (i.e. debug break and preemption) here, so check the "real stack
      // limit".
      Label done;
      __ mov(scratch, Operand(r4, LSL, kSystemPointerSizeLog2));
      {
        UseScratchRegisterScope temps(masm);
        Register remaining_stack_size = temps.Acquire();
        DCHECK(!AreAliased(r0, r1, r2, r3, r4, scratch, remaining_stack_size));

        // Compute the space we have left. The stack might already be overflowed
        // here which will cause remaining_stack_size to become negative.
        __ LoadStackLimit(remaining_stack_size,
                          StackLimitKind::kRealStackLimit);
        __ sub(remaining_stack_size, sp, remaining_stack_size);

        // Check if the arguments will overflow the stack.
        __ cmp(remaining_stack_size, scratch);
      }
      __ b(gt, &done);
      {
        FrameScope scope(masm, StackFrame::MANUAL);
        __ EnterFrame(StackFrame::INTERNAL);
        __ CallRuntime(Runtime::kThrowStackOverflow);
      }
      __ bind(&done);
    }

    // Pop receiver.
    __ Pop(r5);

    // Push [[BoundArguments]].
    {
      Label loop;
      __ add(r0, r0, r4);  // Adjust effective number of arguments.
      __ add(r2, r2,
             Operand(OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag));
      __ bind(&loop);
      __ sub(r4, r4, Operand(1), SetCC);
      __ ldr(scratch, MemOperand(r2, r4, LSL, kTaggedSizeLog2));
      __ Push(scratch);
      __ b(gt, &loop);
    }

    // Push receiver.
    __ Push(r5);
  }
  __ bind(&no_bound_arguments);
}

}  // namespace

// static
void Builtins::Generate_CallBoundFunctionImpl(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r0 : the number of arguments
  //  -- r1 : the function to call (checked to be a JSBoundFunction)
  // -----------------------------------
  __ AssertBoundFunction(r1);

  // Patch the receiver to [[BoundThis]].
  __ ldr(r3, FieldMemOperand(r1, JSBoundFunction::kBoundThisOffset));
  __ str(r3, __ ReceiverOperand());

  // Push the [[BoundArguments]] onto the stack.
  Generate_PushBoundArguments(masm);

  // Call the [[BoundTargetFunction]] via the Call builtin.
  __ ldr(r1, FieldMemOperand(r1, JSBoundFunction::kBoundTargetFunctionOffset));
  __ TailCallBuiltin(Builtins::Call());
}

// static
void Builtins::Generate_Call(MacroAssembler* masm, ConvertReceiverMode mode) {
  // ----------- S t a t e -------------
  //  -- r0 : the number of arguments
  //  -- r1 : the target to call (can be any Object).
  // -----------------------------------
  Register target = r1;
  Register map = r4;
  Register instance_type = r5;
  Register scratch = r6;
  DCHECK(!AreAliased(r0, target, map, instance_type));

  Label non_callable, class_constructor;
  __ JumpIfSmi(target, &non_callable);
  __ LoadMap(map, target);
  __ CompareInstanceTypeRange(map, instance_type, scratch,
                              FIRST_CALLABLE_JS_FUNCTION_TYPE,
                              LAST_CALLABLE_JS_FUNCTION_TYPE);
  __ TailCallBuiltin(Builtins::CallFunction(mode), ls);
  __ cmp(instance_type, Operand(JS_BOUND_FUNCTION_TYPE));
  __ TailCallBuiltin(Builtin::kCallBoundFunction, eq);

  // Check if target has a [[Call]] internal method.
  {
    Register flags = r4;
    __ ldrb(flags, FieldMemOperand(map, Map::kBitFieldOffset));
    map = no_reg;
    __ tst(flags, Operand(Map::Bits1::IsCallableBit::kMask));
    __ b(eq, &non_callable);
  }

  // Check if target is a proxy and call CallProxy external builtin
  __ cmp(instance_type, Operand(JS_PROXY_TYPE));
  __ TailCallBuiltin(Builtin::kCallProxy, eq);

  // Check if target is a wrapped function and call CallWrappedFunction external
  // builtin
  __ cmp(instance_type, Operand(JS_WRAPPED_FUNCTION_TYPE));
  __ TailCallBuiltin(Builtin::kCallWrappedFunction, eq);

  // ES6 section 9.2.1 [[Call]] ( thisArgument, argumentsList)
  // Check that the function is not a "classConstructor".
  __ cmp(instance_type, Operand(JS_CLASS_CONSTRUCTOR_TYPE));
  __ b(eq, &class_constructor);

  // 2. Call to something else, which might have a [[Call]] internal method (if
  // not we raise an exception).
  // Overwrite the original receiver the (original) target.
  __ str(target, __ ReceiverOperand());
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
  //  -- r0 : the number of arguments
  //  -- r1 : the constructor to call (checked to be a JSFunction)
  //  -- r3 : the new target (checked to be a constructor)
  // -----------------------------------
  __ AssertConstructor(r1);
  __ AssertFunction(r1);

  // Calling convention for function specific ConstructStubs require
  // r2 to contain either an AllocationSite or undefined.
  __ LoadRoot(r2, RootIndex::kUndefinedValue);

  Label call_generic_stub;

  // Jump to JSBuiltinsConstructStub or JSConstructStubGeneric.
  __ ldr(r4, FieldMemOperand(r1, JSFunction::kSharedFunctionInfoOffset));
  __ ldr(r4, FieldMemOperand(r4, SharedFunctionInfo::kFlagsOffset));
  __ tst(r4, Operand(SharedFunctionInfo::ConstructAsBuiltinBit::kMask));
  __ b(eq, &call_generic_stub);

  __ TailCallBuiltin(Builtin::kJSBuiltinsConstructStub);

  __ bind(&call_generic_stub);
  __ TailCallBuiltin(Builtin::kJSConstructStubGeneric);
}

// static
void Builtins::Generate_ConstructBoundFunction(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r0 : the number of arguments
  //  -- r1 : the function to call (checked to be a JSBoundFunction)
  //  -- r3 : the new target (checked to be a construc
"""


```