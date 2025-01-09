Response:
The user wants a summary of the functionality of the provided C++ code snippet. The code is part of V8's MIPS64 architecture-specific built-in functions.

Here's a breakdown of the code and how to address the user's requirements:

1. **Identify the main functions and their purpose:**  Scan the code for function definitions within the `Builtins` namespace. The function names often indicate their purpose (e.g., `Generate_InterpreterEnterBytecode`, `Generate_ContinueToCodeStubBuiltin`, `Generate_OSREntry`, `Generate_FunctionPrototypeApply`, etc.).

2. **Classify by functionality:** Group related functions. For example, functions related to interpreter entry, continuing to builtins, on-stack replacement, `Function.prototype` methods, `Reflect` API methods, and variable arguments.

3. **Explain the role of each group:** Summarize what each group of functions does within the V8 runtime.

4. **Address the `.tq` question:**  The prompt states the file ends in `.cc`, so it's a C++ source file, not Torque.

5. **Javascript relationship:** Identify functions that directly correspond to Javascript features. Provide Javascript examples demonstrating these features.

6. **Code logic and examples:** For functions with clear logic (like `Generate_AllocateSpaceAndShiftExistingArguments`), provide a simplified explanation and example input/output.

7. **Common programming errors:**  Point out any functions that deal with handling potential user errors (like calling a non-callable object).

8. **Synthesize the summary:**  Combine the individual function descriptions into a concise overview of the file's purpose.

**Mental Walkthrough of the Code:**

- **Interpreter entry:** `Generate_InterpreterEnterBytecode`, `Generate_InterpreterEnterAtBytecode`: These are responsible for setting up the interpreter when entering bytecode execution.
- **Continuing to builtins:** `Generate_ContinueToCodeStubBuiltin`, `Generate_ContinueToJavaScriptBuiltin`: These handle transitions from deoptimized code back to optimized built-in functions.
- **On-stack replacement (OSR):** `Generate_InterpreterOnStackReplacement`, `Generate_BaselineOnStackReplacement`: These functions manage the process of optimizing a running function by replacing its interpreter or baseline code with optimized code.
- **`Function.prototype` methods:** `Generate_FunctionPrototypeApply`, `Generate_FunctionPrototypeCall`: These implement the core functionality of `Function.prototype.apply` and `Function.prototype.call`.
- **`Reflect` API:** `Generate_ReflectApply`, `Generate_ReflectConstruct`: These implement the `Reflect.apply` and `Reflect.construct` methods.
- **Variable arguments:** `Generate_CallOrConstructVarargs`, `Generate_CallOrConstructForwardVarargs`: These handle calling functions with a variable number of arguments, often used with the spread syntax or `arguments` object.
- **Calling functions:** `Generate_CallFunction`, `Generate_CallBoundFunctionImpl`, `Generate_Call`: These functions implement the core function call logic, including handling different types of callables (JS functions, bound functions, proxies).
- **Constructing objects:** `Generate_ConstructFunction`, `Generate_ConstructBoundFunction`: These functions handle object construction using the `new` keyword.
- **Helper function:** `Generate_AllocateSpaceAndShiftExistingArguments`: A utility function to manage stack arguments.

By following this process, I can generate a comprehensive and accurate summary that addresses all aspects of the user's request.
这是目录为 `v8/src/builtins/mips64/builtins-mips64.cc` 的一个 V8 源代码文件的部分内容。它定义了 MIPS64 架构特定的内置函数（builtins）的生成逻辑。

**功能归纳:**

这段代码主要负责生成以下类型的 MIPS64 汇编代码，这些代码是 V8 虚拟机在执行 JavaScript 代码时调用的底层函数：

1. **解释器入口和继续执行:**
   - **`Generate_InterpreterEnterBytecode` 和 `Generate_InterpreterEnterAtBytecode`:**  负责进入字节码解释器执行 JavaScript 代码。它会设置解释器状态，如字节码偏移量。
   - **`Generate_ContinueToCodeStubBuiltin`，`Generate_ContinueToCodeStubBuiltinWithResult`，`Generate_ContinueToJavaScriptBuiltin`，`Generate_ContinueToJavaScriptBuiltinWithResult`:**  用于从非优化的代码（例如，被反优化后的代码）跳转回优化的内置函数或 JavaScript 函数。它们负责恢复寄存器状态和跳转到正确的入口点。

2. **反优化通知:**
   - **`Generate_NotifyDeoptimized`:**  当代码发生反优化时被调用，通知运行时系统。

3. **栈上替换 (OSR - On-Stack Replacement):**
   - **`Generate_InterpreterOnStackReplacement` 和 `Generate_BaselineOnStackReplacement`:**  实现栈上替换的逻辑，允许正在解释执行或基线编译的代码在运行时被更优化的代码替换。

4. **`Function.prototype` 方法:**
   - **`Generate_FunctionPrototypeApply`:**  实现了 `Function.prototype.apply()` 方法。
   - **`Generate_FunctionPrototypeCall`:**  实现了 `Function.prototype.call()` 方法。

5. **`Reflect` API:**
   - **`Generate_ReflectApply`:**  实现了 `Reflect.apply()` 方法。
   - **`Generate_ReflectConstruct`:** 实现了 `Reflect.construct()` 方法。

6. **变长参数调用:**
   - **`Generate_CallOrConstructVarargs`:**  处理使用类似数组的对象作为参数来调用或构造函数的场景（例如，使用扩展运算符 `...`）。
   - **`Generate_CallOrConstructForwardVarargs`:**  处理从调用者的栈帧中转发变长参数的情况。

7. **函数调用:**
   - **`Generate_CallFunction`:**  实现标准的函数调用，包括处理 `this` 绑定和可能的类型转换。
   - **`Generate_CallBoundFunctionImpl`:**  处理绑定函数的调用。
   - **`Generate_Call`:**  实现通用的调用逻辑，根据目标对象的类型分发到不同的调用机制。

8. **对象构造:**
   - **`Generate_ConstructFunction`:**  实现使用 `new` 关键字构造对象的逻辑。
   - **`Generate_ConstructBoundFunction`:**  实现使用 `new` 关键字构造绑定对象的逻辑。

9. **辅助函数:**
   - **`Generate_AllocateSpaceAndShiftExistingArguments`:**  一个辅助函数，用于在栈上分配空间并移动已有的参数。

**关于 `.tq` 结尾:**

正如代码所示，`v8/src/builtins/mips64/builtins-mips64.cc` 以 `.cc` 结尾，**因此它是一个 C++ 源代码文件，而不是 Torque 源代码文件**。Torque 源代码文件通常以 `.tq` 结尾。

**与 JavaScript 功能的关系及 JavaScript 示例:**

这段 C++ 代码直接对应于 JavaScript 的一些核心功能。以下是一些例子：

1. **`Function.prototype.apply()` 和 `Function.prototype.call()`:**

   ```javascript
   function greet(greeting) {
     console.log(greeting + ', ' + this.name);
   }

   const person = { name: 'Alice' };

   // 使用 apply
   greet.apply(person, ['Hello']); // 输出: Hello, Alice

   // 使用 call
   greet.call(person, 'Hi');      // 输出: Hi, Alice
   ```
   `Generate_FunctionPrototypeApply` 和 `Generate_FunctionPrototypeCall` 负责实现 `apply` 和 `call` 在 V8 内部的具体执行逻辑。

2. **`Reflect.apply()` 和 `Reflect.construct()`:**

   ```javascript
   function sum(a, b) {
     return a + b;
   }

   const args = [5, 10];
   const resultApply = Reflect.apply(sum, null, args);
   console.log(resultApply); // 输出: 15

   class Point {
     constructor(x, y) {
       this.x = x;
       this.y = y;
     }
   }

   const pointArgs = [1, 2];
   const newPoint = Reflect.construct(Point, pointArgs);
   console.log(newPoint.x, newPoint.y); // 输出: 1 2
   ```
   `Generate_ReflectApply` 和 `Generate_ReflectConstruct` 负责实现 `Reflect.apply` 和 `Reflect.construct` 的底层操作。

3. **变长参数 (扩展运算符):**

   ```javascript
   function logAll(a, b, c) {
     console.log(a, b, c);
   }

   const numbers = [1, 2, 3];
   logAll(...numbers); // 输出: 1 2 3
   ```
   `Generate_CallOrConstructVarargs` 负责处理这种使用扩展运算符 `...` 传递参数的场景。

4. **函数调用和构造:**

   ```javascript
   function myFunction(arg1, arg2) {
     console.log(arg1, arg2, this);
   }

   myFunction(10, 20); // 普通函数调用
   new myFunction(30, 40); // 构造函数调用
   ```
   `Generate_CallFunction`, `Generate_Call`, `Generate_ConstructFunction` 等函数负责实现这些基本的函数调用和对象构造机制。

**代码逻辑推理（假设输入与输出）:**

考虑 `Generate_AllocateSpaceAndShiftExistingArguments` 函数。

**假设输入:**

- `masm`:  指向 `MacroAssembler` 对象的指针，用于生成汇编代码。
- `count`: 寄存器，假设其值为 `2` (表示需要为 2 个新参数分配空间)。
- `argc_in_out`: 寄存器，假设其值为 `3` (表示栈上已经有 3 个参数)。
- `pointer_to_new_space_out`: 寄存器，用于输出新空间的起始地址。
- `scratch1`, `scratch2`, `scratch3`:  用作临时寄存器。
- 栈的状态（简化表示）： `[arg3, arg2, arg1, receiver, return_address]` (栈顶在左侧)

**输出 (预期效果):**

1. 在栈上分配足够的空间来容纳 `count` 个新参数。
2. 将原有的 `argc_in_out` 个参数移动到新分配的空间中。
3. `pointer_to_new_space_out` 寄存器将指向新空间的起始地址。
4. `argc_in_out` 寄存器的值更新为 `3 + 2 = 5`。
5. 栈的状态变为： `[新空间2, 新空间1, arg3, arg2, arg1, receiver, return_address]`

**用户常见的编程错误:**

1. **调用不可调用的对象:**  例如，尝试调用一个普通对象而不是一个函数。
   ```javascript
   const obj = { a: 1 };
   obj(); // TypeError: obj is not a function
   ```
   `Generate_Call` 中的逻辑会检查目标对象是否可调用，如果不可调用，则会调用 `Runtime::kThrowCalledNonCallable` 抛出错误。

2. **将类作为普通函数调用:**  尝试直接调用一个类构造器。
   ```javascript
   class MyClass {}
   MyClass(); // TypeError: Class constructor MyClass cannot be invoked without 'new'
   ```
   `Generate_Call` 中对 `JS_CLASS_CONSTRUCTOR_TYPE` 的检查会处理这种情况，并抛出相应的错误。

3. **在 `apply` 或 `call` 中传递错误的参数:** 例如，传递的 `this` 值不是对象，或者 `apply` 的第二个参数不是数组或类数组对象。虽然 C++ 代码主要处理底层的执行，但这些错误会在 JavaScript 层面被捕获，并可能触发到某些内置函数的调用。

**总结:**

`v8/src/builtins/mips64/builtins-mips64.cc` 的这一部分定义了 MIPS64 架构下 V8 虚拟机执行各种关键 JavaScript 操作的底层汇编代码生成逻辑。它涵盖了解释器入口、代码优化、函数调用、对象构造以及 `Function.prototype` 和 `Reflect` API 的实现。这些内置函数是 V8 引擎高效执行 JavaScript 代码的基础。

Prompt: 
```
这是目录为v8/src/builtins/mips64/builtins-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/mips64/builtins-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能

"""
  __ bind(&enter_bytecode);
  // Convert new bytecode offset to a Smi and save in the stackframe.
  __ SmiTag(a2, kInterpreterBytecodeOffsetRegister);
  __ Sd(a2, MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));

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
      __ mov(scratch, v0);
    } else {
      // Overwrite the hole inserted by the deoptimizer with the return value
      // from the LAZY deopt point.
      __ Sd(v0,
            MemOperand(sp,
                       config->num_allocatable_general_registers() *
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
    __ Daddu(a0, a0, Operand(return_value_offset));
    __ Dlsa(t0, sp, a0, kSystemPointerSizeLog2);
    __ Sd(scratch, MemOperand(t0));
    // Recover arguments count.
    __ Dsubu(a0, a0, Operand(return_value_offset));
  }

  __ Ld(fp, MemOperand(
                sp, BuiltinContinuationFrameConstants::kFixedFrameSizeFromFp));
  // Load builtin index (stored as a Smi) and use it to get the builtin start
  // address from the builtins table.
  __ Pop(t0);
  __ Daddu(sp, sp,
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

  DCHECK_EQ(kInterpreterAccumulatorRegister.code(), v0.code());
  __ Ld(v0, MemOperand(sp, 0 * kSystemPointerSize));
  __ Ret(USE_DELAY_SLOT);
  // Safe to fill delay slot Addu will emit one instruction.
  __ Daddu(sp, sp, Operand(1 * kSystemPointerSize));  // Remove state.
}

namespace {

void Generate_OSREntry(MacroAssembler* masm, Register entry_address,
                       Operand offset = Operand(zero_reg)) {
  __ Daddu(ra, entry_address, offset);
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
    __ Branch(&jump_to_optimized_code, ne, maybe_target_code,
              Operand(Smi::zero()));
  }

  ASM_CODE_COMMENT(masm);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kCompileOptimizedOSR);
  }

  // If the code object is null, just return to the caller.
  __ Ret(eq, maybe_target_code, Operand(Smi::zero()));
  __ bind(&jump_to_optimized_code);
  DCHECK_EQ(maybe_target_code, v0);  // Already in the right spot.

  // OSR entry tracing.
  {
    Label next;
    __ li(a1, ExternalReference::address_of_log_or_trace_osr());
    __ Lbu(a1, MemOperand(a1));
    __ Branch(&next, eq, a1, Operand(zero_reg));

    {
      FrameScope scope(masm, StackFrame::INTERNAL);
      __ Push(v0);  // Preserve the code object.
      __ CallRuntime(Runtime::kLogOrTraceOptimizedOSREntry, 0);
      __ Pop(v0);
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
  __ Ld(a1, MemOperand(maybe_target_code,
                       Code::kDeoptimizationDataOrInterpreterDataOffset -
                           kHeapObjectTag));

  // Load the OSR entrypoint offset from the deoptimization data.
  // <osr_offset> = <deopt_data>[#header_size + #osr_pc_offset]
  __ SmiUntag(a1, MemOperand(a1, FixedArray::OffsetOfElementAt(
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

  __ Ld(kContextRegister,
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
    __ Dsubu(scratch, argc, JSParameterCount(0));
    __ Ld(this_arg, MemOperand(sp, kSystemPointerSize));
    __ Ld(arg_array, MemOperand(sp, 2 * kSystemPointerSize));
    __ Movz(arg_array, undefined_value, scratch);  // if argc == 0
    __ Movz(this_arg, undefined_value, scratch);   // if argc == 0
    __ Dsubu(scratch, scratch, Operand(1));
    __ Movz(arg_array, undefined_value, scratch);  // if argc == 1
    __ Ld(receiver, MemOperand(sp));
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
  __ JumpIfRoot(arg_array, RootIndex::kNullValue, &no_arguments);
  __ Branch(&no_arguments, eq, arg_array, Operand(undefined_value));

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
  {
    __ Pop(a1);
  }

  // 2. Make sure we have at least one argument.
  // a0: actual number of arguments
  {
    Label done;
    __ Branch(&done, ne, a0, Operand(JSParameterCount(0)));
    __ PushRoot(RootIndex::kUndefinedValue);
    __ Daddu(a0, a0, Operand(1));
    __ bind(&done);
  }

  // 3. Adjust the actual number of arguments.
  __ daddiu(a0, a0, -1);

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

    __ Dsubu(scratch, argc, Operand(JSParameterCount(0)));
    __ Ld(target, MemOperand(sp, kSystemPointerSize));
    __ Ld(this_argument, MemOperand(sp, 2 * kSystemPointerSize));
    __ Ld(arguments_list, MemOperand(sp, 3 * kSystemPointerSize));
    __ Movz(arguments_list, undefined_value, scratch);  // if argc == 0
    __ Movz(this_argument, undefined_value, scratch);   // if argc == 0
    __ Movz(target, undefined_value, scratch);          // if argc == 0
    __ Dsubu(scratch, scratch, Operand(1));
    __ Movz(arguments_list, undefined_value, scratch);  // if argc == 1
    __ Movz(this_argument, undefined_value, scratch);   // if argc == 1
    __ Dsubu(scratch, scratch, Operand(1));
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

    __ Dsubu(scratch, argc, Operand(JSParameterCount(0)));
    __ Ld(target, MemOperand(sp, kSystemPointerSize));
    __ Ld(arguments_list, MemOperand(sp, 2 * kSystemPointerSize));
    __ Ld(new_target, MemOperand(sp, 3 * kSystemPointerSize));
    __ Movz(arguments_list, undefined_value, scratch);  // if argc == 0
    __ Movz(new_target, undefined_value, scratch);      // if argc == 0
    __ Movz(target, undefined_value, scratch);          // if argc == 0
    __ Dsubu(scratch, scratch, Operand(1));
    __ Movz(arguments_list, undefined_value, scratch);  // if argc == 1
    __ Movz(new_target, target, scratch);               // if argc == 1
    __ Dsubu(scratch, scratch, Operand(1));
    __ Movz(new_target, target, scratch);               // if argc == 2

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
  __ dsll(new_space, count, kSystemPointerSizeLog2);
  __ Dsubu(sp, sp, Operand(new_space));

  Register end = scratch2;
  Register value = scratch3;
  Register dest = pointer_to_new_space_out;
  __ mov(dest, sp);
  __ Dlsa(end, old_sp, argc_in_out, kSystemPointerSizeLog2);
  Label loop, done;
  __ Branch(&done, ge, old_sp, Operand(end));
  __ bind(&loop);
  __ Ld(value, MemOperand(old_sp, 0));
  __ Sd(value, MemOperand(dest, 0));
  __ Daddu(old_sp, old_sp, Operand(kSystemPointerSize));
  __ Daddu(dest, dest, Operand(kSystemPointerSize));
  __ Branch(&loop, lt, old_sp, Operand(end));
  __ bind(&done);

  // Update total number of arguments.
  __ Daddu(argc_in_out, argc_in_out, count);
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

    __ daddiu(src, args, OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag);
    __ Branch(&done, eq, len, Operand(zero_reg), i::USE_DELAY_SLOT);
    __ dsll(scratch, len, kSystemPointerSizeLog2);
    __ Dsubu(scratch, sp, Operand(scratch));
    __ LoadRoot(t1, RootIndex::kTheHoleValue);
    __ bind(&loop);
    __ Ld(a5, MemOperand(src));
    __ daddiu(src, src, kSystemPointerSize);
    __ Branch(&push, ne, a5, Operand(t1));
    __ LoadRoot(a5, RootIndex::kUndefinedValue);
    __ bind(&push);
    __ Sd(a5, MemOperand(a7, 0));
    __ Daddu(a7, a7, Operand(kSystemPointerSize));
    __ Daddu(scratch, scratch, Operand(kSystemPointerSize));
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
    __ ld(t1, FieldMemOperand(a3, HeapObject::kMapOffset));
    __ lbu(t1, FieldMemOperand(t1, Map::kBitFieldOffset));
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
  __ Ld(a7, MemOperand(fp, StandardFrameConstants::kArgCOffset));
  __ Dsubu(a7, a7, Operand(kJSArgcReceiverSlots));
  __ Dsubu(a7, a7, a2);
  __ Branch(&stack_done, le, a7, Operand(zero_reg));
  {
    // Check for stack overflow.
    __ StackOverflowCheck(a7, a4, a5, &stack_overflow);

    // Forward the arguments from the caller frame.

    // Point to the first argument to copy (skipping the receiver).
    __ Daddu(a6, fp,
             Operand(CommonFrameConstants::kFixedFrameSizeAboveFp +
                     kSystemPointerSize));
    __ Dlsa(a6, a6, a2, kSystemPointerSizeLog2);

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
        __ Subu(a7, a7, Operand(1));
        __ Dlsa(t0, a6, a7, kSystemPointerSizeLog2);
        __ Ld(kScratchReg, MemOperand(t0));
        __ Dlsa(t0, a2, a7, kSystemPointerSizeLog2);
        __ Sd(kScratchReg, MemOperand(t0));
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
  __ AssertCallableFunction(a1);

  __ Ld(a2, FieldMemOperand(a1, JSFunction::kSharedFunctionInfoOffset));

  // Enter the context of the function; ToObject has to run in the function
  // context, and we also need to take the global proxy from the function
  // context in case of conversion.
  __ Ld(cp, FieldMemOperand(a1, JSFunction::kContextOffset));
  // We need to convert the receiver for non-native sloppy mode functions.
  Label done_convert;
  __ Lwu(a3, FieldMemOperand(a2, SharedFunctionInfo::kFlagsOffset));
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
      static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
      __ GetObjectType(a3, a4, a4);
      __ Branch(&done_convert, hs, a4, Operand(FIRST_JS_RECEIVER_TYPE));
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
        __ mov(a3, v0);
        __ Pop(a0, a1);
        __ SmiUntag(a0);
      }
      __ Ld(a2, FieldMemOperand(a1, JSFunction::kSharedFunctionInfoOffset));
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

  __ Lhu(a2,
         FieldMemOperand(a2, SharedFunctionInfo::kFormalParameterCountOffset));
  __ InvokeFunctionCode(a1, no_reg, a2, a0, InvokeType::kJump);
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
    __ Ld(t0, FieldMemOperand(a1, JSBoundFunction::kBoundThisOffset));
    __ StoreReceiver(t0);
  }

  // Load [[BoundArguments]] into a2 and length of that into a4.
  __ Ld(a2, FieldMemOperand(a1, JSBoundFunction::kBoundArgumentsOffset));
  __ SmiUntag(a4, FieldMemOperand(a2, offsetof(FixedArray, length_)));

  // ----------- S t a t e -------------
  //  -- a0 : the number of arguments
  //  -- a1 : the function to call (checked to be a JSBoundFunction)
  //  -- a2 : the [[BoundArguments]] (implemented as FixedArray)
  //  -- a4 : the number of [[BoundArguments]]
  // -----------------------------------

  // Reserve stack space for the [[BoundArguments]].
  {
    Label done;
    __ dsll(a5, a4, kSystemPointerSizeLog2);
    __ Dsubu(t0, sp, Operand(a5));
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

  // Call the [[BoundTargetFunction]] via the Call builtin.
  __ Ld(a1, FieldMemOperand(a1, JSBoundFunction::kBoundTargetFunctionOffset));
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
    __ Lbu(flags, FieldMemOperand(map, Map::kBitFieldOffset));
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
  __ AssertFunction(a1);

  // Calling convention for function specific ConstructStubs require
  // a2 to contain either an AllocationSite or undefined.
  __ LoadRoot(a2, RootIndex::kUndefinedValue);

  Label call_generic_stub;

  // Jump to JSBuiltinsConstructStub or JSConstructStubGeneric.
  __ Ld(a4, FieldMemOperand(a1, JSFunction::kSharedFunctionInfoOffset));
  __ lwu(a4, FieldMemOperand(a4, SharedFunctionInfo::kFlagsOffset));
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
  __ Ld(a2, FieldMemOperand(a1, JSBoundFunction::kBoundArgumentsOffset));
  __ SmiUntag(a4, FieldMemOperand(a2, offsetof(FixedArray, length_)));

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
    __ dsll(a5, a4, kSystemPointerSizeLog2);
    __ Dsubu(t0, sp, Operand(a5));
    // Check the stack for overflow. We are not trying to catch interruptions
    // (i.e. debug break and preemption) here, so check the "real stack limit".
    __ LoadStackLimit(kScratchReg,
                      MacroAssembler::StackLimitKind::kRealStackLimit);
    __ Branch(&done, hs, t0, Operand(kScratchReg));
    {
      FrameScope scope(masm, StackFrame::MANUAL);
      __ EnterFrame(StackFrame::INTERNAL);
      __ C
"""


```