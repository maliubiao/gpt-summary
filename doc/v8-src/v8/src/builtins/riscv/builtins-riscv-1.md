Response: The user is asking for a summary of the C++ source code file `v8/src/builtins/riscv/builtins-riscv.cc`.
This is the second part of a three-part series. Therefore, I should focus on the functionality within this specific chunk of code and avoid repeating information from the other parts if possible.

The code seems to define several built-in functions for the RISC-V architecture in V8. These built-ins are often low-level implementations of JavaScript features or internal VM operations.

I will go through the code section by section and summarize the functionality:

- **Interpreter Entry Points:**  Functions to enter the interpreter at different points (next bytecode, specific bytecode).
- **Continuation Builtins:** Functions to resume execution after a deoptimization.
- **Deoptimization Notification:** A function to notify the runtime about a deoptimization.
- **On-Stack Replacement (OSR):** Functions related to transitioning execution from interpreted or baseline code to optimized code during runtime.
- **Maglev Stack Check:** A function for stack size checking during Maglev execution.
- **`Function.prototype.apply` and `Function.prototype.call`:** Implementations of these core JavaScript functions.
- **`Reflect.apply` and `Reflect.construct`:** Implementations of these ES6 Reflection API methods.
- **Varargs Handling:** Functions for calling or constructing functions with a variable number of arguments (using either an array-like object or forwarding arguments from the caller frame).
- **`CallFunction`:** A central function for calling JavaScript functions, handling receiver conversion.
- **Bound Function Handling:** Functions for calling and constructing bound functions.
- **`Call` and `Construct`:** High-level built-ins for calling and constructing objects, dispatching to appropriate lower-level built-ins.
- **WebAssembly Support:** Built-ins related to WebAssembly, including frame setup, lazy compilation, debug breaks, and trap handling.
- **CEntry:**  The crucial built-in for calling C++ functions from JavaScript. This involves setting up the necessary frames and handling potential exceptions.
- **Double to Integer Conversion:** A built-in for converting double-precision floating-point numbers to integers.
- **Wasm to JS Wrapper:** A built-in to handle calls from WebAssembly to JavaScript.
- **Wasm Trap Handling:**  A built-in called when a WebAssembly trap occurs.
- **Stack Switching (Experimental):** Functions related to switching between different stacks, potentially for WebAssembly.

For the JavaScript examples, I will focus on the built-ins that directly correspond to JavaScript features, like `apply`, `call`, `Reflect.apply`, and `Reflect.construct`.
这个C++源代码文件（`v8/src/builtins/riscv/builtins-riscv.cc`）的第2部分主要实现了以下功能：

**核心功能：解释器和优化的入口、函数调用和构造、以及WebAssembly的相关支持。**

具体来说，它包含了以下方面的实现：

1. **解释器入口点 (Interpreter Entry Points):**
   - `Generate_InterpreterEnterBytecode`:  用于在指定的字节码偏移量处进入解释器执行。
   - `Generate_InterpreterEnterAtNextBytecode`: 模拟字节码处理器的行为，前进到下一个字节码并进入解释器。
   - `Generate_InterpreterEnterAtBytecode`:  与 `Generate_InterpreterEnterBytecode` 功能相同。

2. **代码桩（Code Stub）的继续执行 (Continuation Builtins):**
   - `Generate_ContinueToCodeStubBuiltin`: 用于在执行完代码桩后继续执行，不带返回值。
   - `Generate_ContinueToCodeStubBuiltinWithResult`: 用于在执行完代码桩后继续执行，带返回值。
   - `Generate_ContinueToJavaScriptBuiltin`: 用于在执行完JavaScript内置函数后继续执行，不带返回值。
   - `Generate_ContinueToJavaScriptBuiltinWithResult`: 用于在执行完JavaScript内置函数后继续执行，带返回值。
   这些函数主要用于处理从优化的代码返回到非优化代码的情况，例如在 deoptimization 之后。

3. **通知 Deoptimization (Notify Deoptimized):**
   - `Generate_NotifyDeoptimized`:  当代码发生 deoptimization 时，通知运行时系统。

4. **栈上替换 (On-Stack Replacement - OSR):**
   - `Generate_InterpreterOnStackReplacement`:  从解释器代码切换到优化后的代码。
   - `Generate_BaselineOnStackReplacement`: 从 Baseline 代码切换到优化后的代码。
   这些功能允许在程序运行过程中，将正在执行的解释器或 Baseline 代码替换为优化后的机器码，从而提高性能。

5. **Maglev 函数入口栈检查 (Maglev Function Entry Stack Check):**
   - `Generate_MaglevFunctionEntryStackCheck`:  在 Maglev 优化代码入口处进行栈大小检查。

6. **`Function.prototype.apply` 和 `Function.prototype.call` 的实现:**
   - `Generate_FunctionPrototypeApply`:  实现了 JavaScript 中 `Function.prototype.apply` 方法的行为。
   - `Generate_FunctionPrototypeCall`: 实现了 JavaScript 中 `Function.prototype.call` 方法的行为。

7. **`Reflect.apply` 和 `Reflect.construct` 的实现:**
   - `Generate_ReflectApply`: 实现了 JavaScript 中 `Reflect.apply` 方法的行为。
   - `Generate_ReflectConstruct`: 实现了 JavaScript 中 `Reflect.construct` 方法的行为。

8. **调用或构造变长参数函数 (Call or Construct Varargs):**
   - `Generate_CallOrConstructVarargs`:  用于调用或构造函数，其参数来自一个数组。
   - `Generate_CallOrConstructForwardVarargs`: 用于调用或构造函数，将调用者的参数转发给被调用者，支持 rest 参数。

9. **调用函数 (Call Function):**
   - `Generate_CallFunction`:  实现了调用 JavaScript 函数的核心逻辑，包括处理 receiver 和上下文。

10. **绑定函数 (Bound Function) 的处理:**
    - `Generate_CallBoundFunctionImpl`:  实现了调用绑定函数的逻辑。
    - `Generate_PushBoundArguments`: 将绑定函数的绑定参数压入栈中。

11. **`Call` 和 `Construct` 的实现:**
    - `Generate_Call`: 实现了 JavaScript 中函数调用的核心逻辑，处理不同类型的可调用对象。
    - `Generate_ConstructFunction`:  实现了构造 JavaScript 函数的逻辑。
    - `Generate_ConstructBoundFunction`: 实现了构造绑定函数的逻辑。
    - `Generate_Construct`: 实现了 JavaScript 中对象构造的核心逻辑，处理不同类型的构造器。

12. **WebAssembly (Wasm) 的相关支持:**
    - `Generate_WasmLiftoffFrameSetup`:  为 WebAssembly Liftoff 编译器设置栈帧。
    - `Generate_WasmCompileLazy`:  实现 WebAssembly 代码的延迟编译。
    - `Generate_WasmDebugBreak`:  用于 WebAssembly 的调试断点。
    - `Generate_WasmToJsWrapperAsm`:  用于从 WebAssembly 调用 JavaScript 的包装器。
    - `Generate_WasmTrapHandlerLandingPad`:  WebAssembly 陷阱处理程序的入口点。
    - `Generate_WasmHandleStackOverflow`:  处理 WebAssembly 的栈溢出。

13. **C++ 调用入口 (CEntry):**
    - `Generate_CEntry`:  用于从 JavaScript 代码调用 C++ 函数，是 JavaScript 和 C++ 之间互操作的关键部分，负责设置调用栈帧、传递参数和处理返回值以及异常。

14. **双精度浮点数转整数 (Double To Integer):**
    - `Generate_DoubleToI`:  实现了将双精度浮点数转换为整数的功能。

15. **栈切换 (Stack Switching - Experimental):**
    - `SwitchToTheCentralStackIfNeeded`:  根据需要切换到中心栈 (central stack)。
    - `SwitchFromTheCentralStackIfNeeded`:  根据需要从中心栈切换回来。

**与 JavaScript 功能的关系和示例:**

这个文件中的许多函数直接对应或支持 JavaScript 的核心功能。以下是一些 JavaScript 示例：

**1. `Function.prototype.apply` 和 `Function.prototype.call`:**

```javascript
function greet(prefix, punctuation) {
  console.log(prefix + " " + this.name + punctuation);
}

const person = { name: "Alice" };

// 使用 call
greet.call(person, "Hello", "!"); // 输出: Hello Alice!

// 使用 apply
greet.apply(person, ["Hi", "?"]);   // 输出: Hi Alice?
```
`Generate_FunctionPrototypeCall` 和 `Generate_FunctionPrototypeApply` 就实现了上述 `call` 和 `apply` 的底层机制。

**2. `Reflect.apply` 和 `Reflect.construct`:**

```javascript
function sum(a, b) {
  return a + b;
}

const args = [5, 3];

// 使用 Reflect.apply
const resultApply = Reflect.apply(sum, null, args);
console.log(resultApply); // 输出: 8

class Point {
  constructor(x, y) {
    this.x = x;
    this.y = y;
  }
}

const pointArgs = [10, 20];

// 使用 Reflect.construct
const pointInstance = Reflect.construct(Point, pointArgs);
console.log(pointInstance.x, pointInstance.y); // 输出: 10 20
```
`Generate_ReflectApply` 和 `Generate_ReflectConstruct`  实现了 `Reflect.apply` 和 `Reflect.construct` 的底层行为。

**3. 函数调用和构造:**

```javascript
function myFunction(arg1, arg2) {
  console.log("Function called with:", arg1, arg2);
}

myFunction(1, 2); // 普通函数调用

function MyClass(value) {
  this.value = value;
}

const instance = new MyClass(42); // 使用 new 关键字构造对象
console.log(instance.value);
```
`Generate_CallFunction`, `Generate_Call`, `Generate_ConstructFunction`, 和 `Generate_Construct` 等函数共同实现了 JavaScript 中函数调用和对象构造的各种场景。

**总结:**

这个文件的核心在于为 RISC-V 架构提供了 V8 引擎中关键的内置函数实现，这些内置函数是支撑 JavaScript 语言执行和虚拟机内部运作的基础。它涵盖了解释器和优化代码的入口、函数调用和构造的各种形式，以及对 WebAssembly 的重要支持。

Prompt: 
```
这是目录为v8/src/builtins/riscv/builtins-riscv.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
ter_dispatch_table_address(masm->isolate()));

  // Get the bytecode array pointer from the frame.
  __ LoadWord(kInterpreterBytecodeArrayRegister,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));

  if (v8_flags.debug_code) {
    // Check function data field is actually a BytecodeArray object.
    __ SmiTst(kInterpreterBytecodeArrayRegister, kScratchReg);
    __ Assert(ne,
              AbortReason::kFunctionDataShouldBeBytecodeArrayOnInterpreterEntry,
              kScratchReg, Operand(zero_reg));
    __ GetObjectType(kInterpreterBytecodeArrayRegister, a1, a1);
    __ Assert(eq,
              AbortReason::kFunctionDataShouldBeBytecodeArrayOnInterpreterEntry,
              a1, Operand(BYTECODE_ARRAY_TYPE));
  }

  // Get the target bytecode offset from the frame.
  __ SmiUntag(kInterpreterBytecodeOffsetRegister,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));

  if (v8_flags.debug_code) {
    Label okay;
    __ Branch(&okay, ge, kInterpreterBytecodeOffsetRegister,
              Operand(BytecodeArray::kHeaderSize - kHeapObjectTag),
              Label::Distance::kNear);
    // Unreachable code.
    __ break_(0xCC);
    __ bind(&okay);
  }

  // Dispatch to the target bytecode.
  __ AddWord(a1, kInterpreterBytecodeArrayRegister,
             kInterpreterBytecodeOffsetRegister);
  __ Lbu(a7, MemOperand(a1));
  __ CalcScaledAddress(a1, kInterpreterDispatchTableRegister, a7,
                       kSystemPointerSizeLog2);
  __ LoadWord(kJavaScriptCallCodeStartRegister, MemOperand(a1));
  __ Jump(kJavaScriptCallCodeStartRegister);
}

void Builtins::Generate_InterpreterEnterAtNextBytecode(MacroAssembler* masm) {
  // Advance the current bytecode offset stored within the given interpreter
  // stack frame. This simulates what all bytecode handlers do upon completion
  // of the underlying operation.
  __ LoadWord(kInterpreterBytecodeArrayRegister,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ LoadWord(kInterpreterBytecodeOffsetRegister,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ SmiUntag(kInterpreterBytecodeOffsetRegister);

  Label enter_bytecode, function_entry_bytecode;
  __ Branch(&function_entry_bytecode, eq, kInterpreterBytecodeOffsetRegister,
            Operand(BytecodeArray::kHeaderSize - kHeapObjectTag +
                    kFunctionEntryBytecodeOffset));

  // Load the current bytecode.
  __ AddWord(a1, kInterpreterBytecodeArrayRegister,
             kInterpreterBytecodeOffsetRegister);
  __ Lbu(a1, MemOperand(a1));

  // Advance to the next bytecode.
  Label if_return;
  AdvanceBytecodeOffsetOrReturn(masm, kInterpreterBytecodeArrayRegister,
                                kInterpreterBytecodeOffsetRegister, a1, a2, a3,
                                a4, &if_return);

  __ bind(&enter_bytecode);
  // Convert new bytecode offset to a Smi and save in the stackframe.
  __ SmiTag(a2, kInterpreterBytecodeOffsetRegister);
  __ StoreWord(
      a2, MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));

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
  UseScratchRegisterScope temp(masm);
  Register scratch = temp.Acquire();
  if (with_result) {
    if (javascript_builtin) {
      __ Move(scratch, a0);
    } else {
      // Overwrite the hole inserted by the deoptimizer with the return value
      // from the LAZY deopt point.
      __ StoreWord(
          a0, MemOperand(
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
    __ AddWord(a0, a0, Operand(return_value_offset));
    __ CalcScaledAddress(t0, sp, a0, kSystemPointerSizeLog2);
    __ StoreWord(scratch, MemOperand(t0));
    // Recover arguments count.
    __ SubWord(a0, a0, Operand(return_value_offset));
  }

  __ LoadWord(
      fp,
      MemOperand(sp, BuiltinContinuationFrameConstants::kFixedFrameSizeFromFp));
  // Load builtin index (stored as a Smi) and use it to get the builtin start
  // address from the builtins table.
  __ Pop(t6);
  __ AddWord(sp, sp,
             Operand(BuiltinContinuationFrameConstants::kFixedFrameSizeFromFp));
  __ Pop(ra);
  __ LoadEntryFromBuiltinIndex(t6, t6);
  __ Jump(t6);
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
  __ LoadWord(a0, MemOperand(sp, 0 * kSystemPointerSize));
  __ AddWord(sp, sp, Operand(1 * kSystemPointerSize));  // Remove state.
  __ Ret();
}

namespace {

void Generate_OSREntry(MacroAssembler* masm, Register entry_address,
                       Operand offset = Operand(0)) {
  __ AddWord(ra, entry_address, offset);
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
  // If the code object is null, just return to the caller.
  __ CompareTaggedAndBranch(&jump_to_optimized_code, ne, maybe_target_code,
                            Operand(Smi::zero()));
  __ Ret();
  DCHECK_EQ(maybe_target_code, a0);  // Already in the right spot.

  __ bind(&jump_to_optimized_code);

  // OSR entry tracing.
  {
    Label next;
    __ li(a1, ExternalReference::address_of_log_or_trace_osr());
    __ Lbu(a1, MemOperand(a1));
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
      a1, FieldMemOperand(maybe_target_code,
                          Code::kDeoptimizationDataOrInterpreterDataOffset));

  // Load the OSR entrypoint offset from the deoptimization data.
  // <osr_offset> = <deopt_data>[#header_size + #osr_pc_offset]
  __ SmiUntagField(
      a1, FieldMemOperand(a1, TrustedFixedArray::OffsetOfElementAt(
                                  DeoptimizationData::kOsrPcOffsetIndex)));

  __ LoadCodeInstructionStart(a0, a0, kJSEntrypointTag);

  // Compute the target address = code_entry + osr_offset
  // <entry_addr> = <code_entry> + <osr_offset>
  Generate_OSREntry(masm, a0, Operand(a1));
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

  __ LoadWord(kContextRegister,
              MemOperand(fp, BaselineFrameConstants::kContextOffset));
  OnStackReplacement(masm, OsrSourceTier::kBaseline,
                     D::MaybeTargetCodeRegister());
}

#ifdef V8_ENABLE_MAGLEV

void Builtins::Generate_MaglevFunctionEntryStackCheck(MacroAssembler* masm,
                                                      bool save_new_target) {
  // Input (a0): Stack size (Smi).
  // This builtin can be invoked just after Maglev's prologue.
  // All registers are available, except (possibly) new.target.
  Register stack_size = kCArgRegs[0];
  ASM_CODE_COMMENT(masm);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ AssertSmi(stack_size);
    if (save_new_target) {
      if (PointerCompressionIsEnabled()) {
        __ AssertSmiOrHeapObjectInMainCompressionCage(
            kJavaScriptCallNewTargetRegister);
      }
      __ Push(kJavaScriptCallNewTargetRegister);
    }
    __ Push(stack_size);
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
    // Claim (2 - argc) dummy arguments form the stack, to put the stack in a
    // consistent state for a simple pop operation.
    __ LoadWord(this_arg, MemOperand(sp, kSystemPointerSize));
    __ LoadWord(arg_array, MemOperand(sp, 2 * kSystemPointerSize));
    __ SubWord(scratch, argc, JSParameterCount(0));
    if (CpuFeatures::IsSupported(ZICOND)) {
      __ MoveIfZero(arg_array, undefined_value, scratch);  // if argc == 0
      __ MoveIfZero(this_arg, undefined_value, scratch);   // if argc == 0
      __ SubWord(scratch, scratch, Operand(1));
      __ MoveIfZero(arg_array, undefined_value, scratch);  // if argc == 1
    } else {
      Label done0, done1;
      __ Branch(&done0, ne, scratch, Operand(zero_reg), Label::Distance::kNear);
      __ Move(arg_array, undefined_value);  // if argc == 0
      __ Move(this_arg, undefined_value);   // if argc == 0
      __ bind(&done0);                      // else (i.e., argc > 0)

      __ Branch(&done1, ne, scratch, Operand(1), Label::Distance::kNear);
      __ Move(arg_array, undefined_value);  // if argc == 1
      __ bind(&done1);                      // else (i.e., argc > 1)
    }
    __ LoadWord(receiver, MemOperand(sp));
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
    __ Branch(&done, ne, a0, Operand(JSParameterCount(0)),
              Label::Distance::kNear);
    __ PushRoot(RootIndex::kUndefinedValue);
    __ AddWord(a0, a0, Operand(1));
    __ bind(&done);
  }

  // 3. Adjust the actual number of arguments.
  __ AddWord(a0, a0, -1);

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

  __ LoadRoot(undefined_value, RootIndex::kUndefinedValue);

  // 1. Load target into a1 (if present), argumentsList into a2 (if present),
  // remove all arguments from the stack (including the receiver), and push
  // thisArgument (if present) instead.
  {
    // Claim (3 - argc) dummy arguments form the stack, to put the stack in a
    // consistent state for a simple pop operation.

    __ LoadWord(target, MemOperand(sp, kSystemPointerSize));
    __ LoadWord(this_argument, MemOperand(sp, 2 * kSystemPointerSize));
    __ LoadWord(arguments_list, MemOperand(sp, 3 * kSystemPointerSize));

    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    __ SubWord(scratch, argc, Operand(JSParameterCount(0)));
    if (CpuFeatures::IsSupported(ZICOND)) {
      __ MoveIfZero(arguments_list, undefined_value, scratch);  // if argc == 0
      __ MoveIfZero(this_argument, undefined_value, scratch);   // if argc == 0
      __ MoveIfZero(target, undefined_value, scratch);          // if argc == 0
      __ SubWord(scratch, scratch, Operand(1));
      __ MoveIfZero(arguments_list, undefined_value, scratch);  // if argc == 1
      __ MoveIfZero(this_argument, undefined_value, scratch);   // if argc == 1
      __ SubWord(scratch, scratch, Operand(1));
      __ MoveIfZero(arguments_list, undefined_value, scratch);  // if argc == 2
    } else {
      Label done0, done1, done2;
      __ Branch(&done0, ne, scratch, Operand(zero_reg), Label::Distance::kNear);
      __ Move(arguments_list, undefined_value);  // if argc == 0
      __ Move(this_argument, undefined_value);   // if argc == 0
      __ Move(target, undefined_value);          // if argc == 0
      __ bind(&done0);                           // argc != 0

      __ Branch(&done1, ne, scratch, Operand(1), Label::Distance::kNear);
      __ Move(arguments_list, undefined_value);  // if argc == 1
      __ Move(this_argument, undefined_value);   // if argc == 1
      __ bind(&done1);                           // argc > 1

      __ Branch(&done2, ne, scratch, Operand(2), Label::Distance::kNear);
      __ Move(arguments_list, undefined_value);  // if argc == 2
      __ bind(&done2);                           // argc > 2
    }

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

  __ LoadRoot(undefined_value, RootIndex::kUndefinedValue);

  // 1. Load target into a1 (if present), argumentsList into a2 (if present),
  // new.target into a3 (if present, otherwise use target), remove all
  // arguments from the stack (including the receiver), and push thisArgument
  // (if present) instead.
  {
    // Claim (3 - argc) dummy arguments form the stack, to put the stack in a
    // consistent state for a simple pop operation.
    __ LoadWord(target, MemOperand(sp, kSystemPointerSize));
    __ LoadWord(arguments_list, MemOperand(sp, 2 * kSystemPointerSize));
    __ LoadWord(new_target, MemOperand(sp, 3 * kSystemPointerSize));

    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    __ SubWord(scratch, argc, Operand(JSParameterCount(0)));
    if (CpuFeatures::IsSupported(ZICOND)) {
      __ MoveIfZero(arguments_list, undefined_value, scratch);  // if argc == 0
      __ MoveIfZero(new_target, undefined_value, scratch);      // if argc == 0
      __ MoveIfZero(target, undefined_value, scratch);          // if argc == 0
      __ SubWord(scratch, scratch, Operand(1));
      __ MoveIfZero(arguments_list, undefined_value, scratch);  // if argc == 1
      __ MoveIfZero(new_target, target, scratch);               // if argc == 1
      __ SubWord(scratch, scratch, Operand(1));
      __ MoveIfZero(new_target, target, scratch);  // if argc == 2
    } else {
      Label done0, done1, done2;
      __ Branch(&done0, ne, scratch, Operand(zero_reg), Label::Distance::kNear);
      __ Move(arguments_list, undefined_value);  // if argc == 0
      __ Move(new_target, undefined_value);      // if argc == 0
      __ Move(target, undefined_value);          // if argc == 0
      __ bind(&done0);

      __ Branch(&done1, ne, scratch, Operand(1), Label::Distance::kNear);
      __ Move(arguments_list, undefined_value);  // if argc == 1
      __ Move(new_target, target);               // if argc == 1
      __ bind(&done1);

      __ Branch(&done2, ne, scratch, Operand(2), Label::Distance::kNear);
      __ Move(new_target, target);  // if argc == 2
      __ bind(&done2);
    }

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
    Register pointer_to_new_space_out) {
  UseScratchRegisterScope temps(masm);
  Register scratch1 = temps.Acquire();
  Register scratch2 = temps.Acquire();
  Register scratch3 = temps.Acquire();
  DCHECK(!AreAliased(count, argc_in_out, pointer_to_new_space_out, scratch1,
                     scratch2));
  Register old_sp = scratch1;
  Register new_space = scratch2;
  __ mv(old_sp, sp);
  __ slli(new_space, count, kSystemPointerSizeLog2);
  __ SubWord(sp, sp, Operand(new_space));

  Register end = scratch2;
  Register value = scratch3;
  Register dest = pointer_to_new_space_out;
  __ mv(dest, sp);
  __ CalcScaledAddress(end, old_sp, argc_in_out, kSystemPointerSizeLog2);
  Label loop, done;
  __ Branch(&done, ge, old_sp, Operand(end));
  __ bind(&loop);
  __ LoadWord(value, MemOperand(old_sp, 0));
  __ StoreWord(value, MemOperand(dest, 0));
  __ AddWord(old_sp, old_sp, Operand(kSystemPointerSize));
  __ AddWord(dest, dest, Operand(kSystemPointerSize));
  __ Branch(&loop, lt, old_sp, Operand(end));
  __ bind(&done);

  // Update total number of arguments.
  __ AddWord(argc_in_out, argc_in_out, count);
}

}  // namespace

// static
void Builtins::Generate_CallOrConstructVarargs(MacroAssembler* masm,
                                               Builtin target_builtin) {
  UseScratchRegisterScope temps(masm);
  temps.Include(t1, t0);
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
    __ GetObjectType(a2, kScratchReg, kScratchReg);
    __ Branch(&ok, eq, kScratchReg, Operand(FIXED_ARRAY_TYPE),
              Label::Distance::kNear);
    __ Branch(&fail, ne, kScratchReg, Operand(FIXED_DOUBLE_ARRAY_TYPE),
              Label::Distance::kNear);
    __ Branch(&ok, eq, a4, Operand(zero_reg), Label::Distance::kNear);
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
  Generate_AllocateSpaceAndShiftExistingArguments(masm, a4, a0, a7);

  // Push arguments onto the stack (thisArgument is already on the stack).
  {
    Label done, push, loop;
    Register src = a6;
    Register scratch = len;
    UseScratchRegisterScope temps(masm);
    __ AddWord(src, args, OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag);
    __ Branch(&done, eq, len, Operand(zero_reg), Label::Distance::kNear);
    __ SllWord(scratch, len, kTaggedSizeLog2);
    __ SubWord(scratch, sp, Operand(scratch));
#if !V8_STATIC_ROOTS_BOOL
    // We do not use the Branch(reg, RootIndex) macro without static roots,
    // as it would do a LoadRoot behind the scenes and we want to avoid that
    // in a loop.
    Register hole_value = temps.Acquire();
    __ LoadTaggedRoot(hole_value, RootIndex::kTheHoleValue);
#endif  // !V8_STATIC_ROOTS_BOOL
    __ bind(&loop);
    __ LoadTaggedField(a5, MemOperand(src));
    __ AddWord(src, src, kTaggedSize);
#if V8_STATIC_ROOTS_BOOL
    __ CompareRootAndBranch(a5, RootIndex::kTheHoleValue, ne, &push);
#else
    __ CompareTaggedAndBranch(&push, ne, a5, Operand(hole_value));
#endif
    __ LoadRoot(a5, RootIndex::kUndefinedValue);
    __ bind(&push);
    __ StoreWord(a5, MemOperand(a7, 0));
    __ AddWord(a7, a7, Operand(kSystemPointerSize));
    __ AddWord(scratch, scratch, Operand(kTaggedSize));
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
  UseScratchRegisterScope temps(masm);
  temps.Include(t0, t1);
  temps.Include(t2);
  // Check if new.target has a [[Construct]] internal method.
  if (mode == CallOrConstructMode::kConstruct) {
    Label new_target_constructor, new_target_not_constructor;
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    __ JumpIfSmi(a3, &new_target_not_constructor);
    __ LoadTaggedField(scratch, FieldMemOperand(a3, HeapObject::kMapOffset));
    __ Lbu(scratch, FieldMemOperand(scratch, Map::kBitFieldOffset));
    __ And(scratch, scratch, Operand(Map::Bits1::IsConstructorBit::kMask));
    __ Branch(&new_target_constructor, ne, scratch, Operand(zero_reg),
              Label::Distance::kNear);
    __ bind(&new_target_not_constructor);
    {
      FrameScope scope(masm, StackFrame::MANUAL);
      __ EnterFrame(StackFrame::INTERNAL);
      __ Push(a3);
      __ CallRuntime(Runtime::kThrowNotConstructor);
    }
    __ bind(&new_target_constructor);
  }

  __ Move(a6, fp);
  __ LoadWord(a7, MemOperand(fp, StandardFrameConstants::kArgCOffset));

  Label stack_done, stack_overflow;
  __ SubWord(a7, a7, Operand(kJSArgcReceiverSlots));
  __ SubWord(a7, a7, a2);
  __ Branch(&stack_done, le, a7, Operand(zero_reg));
  {
    // Check for stack overflow.
    __ StackOverflowCheck(a7, a4, a5, &stack_overflow);

    // Forward the arguments from the caller frame.

    // Point to the first argument to copy (skipping the receiver).
    __ AddWord(a6, a6,
               Operand(CommonFrameConstants::kFixedFrameSizeAboveFp +
                       kSystemPointerSize));
    __ CalcScaledAddress(a6, a6, a2, kSystemPointerSizeLog2);

    // Move the arguments already in the stack,
    // including the receiver and the return address.
    // a7: Number of arguments to make room for.
    // a0: Number of arguments already on the stack.
    // a2: Points to first free slot on the stack after arguments were shifted.
    Generate_AllocateSpaceAndShiftExistingArguments(masm, a7, a0, a2);

    // Copy arguments from the caller frame.
    // TODO(victorgomes): Consider using forward order as potentially more cache
    // friendly.
    {
      Label loop;
      __ bind(&loop);
      {
        UseScratchRegisterScope temps(masm);
        Register scratch = temps.Acquire(), addr = temps.Acquire();
        __ Sub32(a7, a7, Operand(1));
        __ CalcScaledAddress(addr, a6, a7, kSystemPointerSizeLog2);
        __ LoadWord(scratch, MemOperand(addr));
        __ CalcScaledAddress(addr, a2, a7, kSystemPointerSizeLog2);
        __ StoreWord(scratch, MemOperand(addr));
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
  __ Load32U(a3, FieldMemOperand(a2, SharedFunctionInfo::kFlagsOffset));
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
        __ Move(a0, a3);
        __ Push(cp);
        __ CallBuiltin(Builtin::kToObject);
        __ Pop(cp);
        __ Move(a3, a0);
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

  __ Lhu(a2,
         FieldMemOperand(a2, SharedFunctionInfo::kFormalParameterCountOffset));
  __ InvokeFunctionCode(a1, no_reg, a2, a0, InvokeType::kJump);
}

namespace {

void Generate_PushBoundArguments(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- a0 : the number of arguments
  //  -- a1 : target (checked to be a JSBoundFunction)
  //  -- a3 : new.target (only in case of [[Construct]])
  // -----------------------------------
  UseScratchRegisterScope temps(masm);
  temps.Include(t0, t1);
  Register bound_argc = a4;
  Register bound_argv = a2;
  // Load [[BoundArguments]] into a2 and length of that into a4.
  Label no_bound_arguments;
  __ LoadTaggedField(
      bound_argv, FieldMemOperand(a1, JSBoundFunction::kBoundArgumentsOffset));
  __ SmiUntagField(bound_argc,
                   FieldMemOperand(bound_argv, offsetof(FixedArray, length_)));
  __ Branch(&no_bound_arguments, eq, bound_argc, Operand(zero_reg));
  {
    // ----------- S t a t e -------------
    //  -- a0 : the number of arguments
    //  -- a1 : target (checked to be a JSBoundFunction)
    //  -- a2 : the [[BoundArguments]] (implemented as FixedArray)
    //  -- a3 : new.target (only in case of [[Construct]])
    //  -- a4: the number of [[BoundArguments]]
    // -----------------------------------
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    Label done;
    // Reserve stack space for the [[BoundArguments]].
    {
      // Check the stack for overflow. We are not trying to catch interruptions
      // (i.e. debug break and preemption) here, so check the "real stack
      // limit".
      __ StackOverflowCheck(a4, temps.Acquire(), temps.Acquire(), nullptr,
                            &done);
      {
        FrameScope scope(masm, StackFrame::MANUAL);
        __ EnterFrame(StackFrame::INTERNAL);
        __ CallRuntime(Runtime::kThrowStackOverflow);
      }
      __ bind(&done);
    }

    // Pop receiver.
    __ Pop(scratch);

    // Push [[BoundArguments]].
    {
      Label loop, done_loop;
      __ SmiUntag(a4, FieldMemOperand(a2, offsetof(FixedArray, length_)));
      __ AddWord(a0, a0, Operand(a4));
      __ AddWord(a2, a2,
                 Operand(OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag));
      __ bind(&loop);
      __ SubWord(a4, a4, Operand(1));
      __ Branch(&done_loop, lt, a4, Operand(zero_reg), Label::Distance::kNear);
      __ CalcScaledAddress(a5, a2, a4, kTaggedSizeLog2);
      __ LoadTaggedField(kScratchReg, MemOperand(a5));
      __ Push(kScratchReg);
      __ Branch(&loop);
      __ bind(&done_loop);
    }

    // Push receiver.
    __ Push(scratch);
  }
  __ bind(&no_bound_arguments);
}

}  // namespace

// static
void Builtins::Generate_CallBoundFunctionImpl(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- a0 : the number of arguments
  //  -- a1 : the function to call (checked to be a JSBoundFunction)
  // -----------------------------------
  __ AssertBoundFunction(a1);

  // Patch the receiver to [[BoundThis]].
  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    __ LoadTaggedField(scratch,
                       FieldMemOperand(a1, JSBoundFunction::kBoundThisOffset));
    __ StoreReceiver(scratch);
  }

  // Push the [[BoundArguments]] onto the stack.
  Generate_PushBoundArguments(masm);

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
  Register scratch = t6;
  DCHECK(!AreAliased(a0, target, map, instance_type, scratch));

  Label non_callable, class_constructor;
  __ JumpIfSmi(target, &non_callable);
  __ LoadMap(map, target);
  __ GetInstanceTypeRange(map, instance_type, FIRST_CALLABLE_JS_FUNCTION_TYPE,
                          scratch);
  __ TailCallBuiltin(Builtins::CallFunction(mode), ule, scratch,
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
  __ LoadTaggedField(
      a4, FieldMemOperand(a1, JSFunction::kSharedFunctionInfoOffset));
  __ Load32U(a4, FieldMemOperand(a4, SharedFunctionInfo::kFlagsOffset));
  __ And(a4, a4, Operand(SharedFunctionInfo::ConstructAsBuiltinBit::kMask));
  __ Branch(&call_generic_stub, eq, a4, Operand(zero_reg),
            Label::Distance::kNear);

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
  __ AssertBoundFunction(a1);

  // Push the [[BoundArguments]] onto the stack.
  Generate_PushBoundArguments(masm);

  // Patch new.target to [[BoundTargetFunction]] if new.target equals target.
  Label skip;
  __ CompareTaggedAndBranch(&skip, ne, a1, Operand(a3));
  __ LoadTaggedField(
      a3, FieldMemOperand(a1, JSBoundFunction::kBoundTargetFunctionOffset));
  __ bind(&skip);

  // Construct the [[BoundTargetFunction]] via the Construct builtin.
  __ LoadTaggedField(
      a1, FieldMemOperand(a1, JSBoundFunction::kBoundTargetFunctionOffset));
  __ TailCallBuiltin(Builtin::kConstruct);
}

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
  Register scratch = t6;
  DCHECK(!AreAliased(a0, target, map, instance_type, scratch));

  // Check if target is a Smi.
  Label non_constructor, non_proxy;
  __ JumpIfSmi(target, &non_constructor);

  // Check if target has a [[Construct]] internal method.
  __ LoadTaggedField(map, FieldMemOperand(target, HeapObject::kMapOffset));
  {
    Register flags = t3;
    __ Lbu(flags, FieldMemOperand(map, Map::kBitFieldOffset));
    __ And(flags, flags, Operand(Map::Bits1::IsConstructorBit::kMask));
    __ Branch(&non_constructor, eq, flags, Operand(zero_reg));
  }

  // Dispatch based on instance type.
  __ GetInstanceTypeRange(map, instance_type, FIRST_JS_FUNCTION_TYPE, scratch);
  __ TailCallBuiltin(Builtin::kConstructFunction, Uless_equal, scratch,
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
  static_assert(WasmLiftoffSetupFrameConstants::kNumberOfSavedGpParamRegs ==
                    arraysize(wasm::kGpParamRegisters) - 1,
                "frame size mismatch");
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
  static_assert(WasmLiftoffSetupFrameConstants::kNumberOfSavedFpParamRegs ==
                    arraysize(wasm::kFpParamRegisters),
                "frame size mismatch");
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
  __ CalcScaledAddress(vector, vector, func_index, kTaggedSizeLog2);
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
  __ StoreWord(scratch, MemOperand(fp, TypedFrameConstants::kFrameTypeOffset));

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
  __ mv(vector, kReturnRegister0);

  // Restore registers and frame type.
  __ Pop(ra);
  __ MultiPopFPU(kSavedFpRegs);
  __ MultiPop(kSavedGpRegs);
  __ LoadWord(kWasmImplicitArgRegister,
              MemOperand(fp, WasmFrameConstants::kWasmInstanceDataOffset));
  __ li(scratch, StackFrame::TypeToMarker(StackFrame::WASM));
  __ StoreWord(scratch, MemOperand(fp, TypedFrameConstants::kFrameTypeOffset));
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

    __ Push(kWasmImplicitArgRegister, kWasmCompileLazyFuncIndexRegister);
    // Initialize the JavaScript context with 0. CEntry will use it to
    // set the current context on the isolate.
    __ Move(kContextRegister, Smi::zero());
    __ CallRuntime(Runtime::kWasmCompileLazy, 2);

    __ SmiUntag(s1, a0);  // move return value to s1 since a0 will be restored
                          // to the value before the call
    CHECK(!kSavedGpRegs.has(s1));

    // Restore registers.
    __ MultiPopFPU(kSavedFpRegs);
    __ MultiPop(kSavedGpRegs);
    __ Pop(kWasmImplicitArgRegister);
  }

  // The runtime function returned the jump table slot offset as a Smi (now in
  // x17). Use that to compute the jump target.
  __ LoadWord(kScratchReg,
              FieldMemOperand(kWasmImplicitArgRegister,
                              WasmTrustedInstanceData::kJumpTableStartOffset));
  __ AddWord(s1, s1, Operand(kScratchReg));
  // Finally, jump to the entrypoint.
  __ Jump(s1);
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

#endif  // V8_ENABLE_WEBASSEMBLY

namespace {
void SwitchSimulatorStackLimit(MacroAssembler* masm) {
#ifdef V8_TARGET_ARCH_RISCV64
  if (masm->options().enable_simulator_code) {
    UseScratchRegisterScope temps(masm);
    temps.Exclude(kSimulatorBreakArgument);
    __ RecordComment("-- Set simulator stack limit --");
    __ LoadStackLimit(kSimulatorBreakArgument, StackLimitKind::kRealStackLimit);
    __ break_(kExceptionIsSwitchStackLimit, false);
  }
#endif
}

static constexpr Register kOldSPRegister = s9;
static constexpr Register kSwitchFlagRegister = s10;

void SwitchToTheCentralStackIfNeeded(MacroAssembler* masm, Register argc_input,
                                     Register target_input,
                                     Register argv_input) {
  using ER = ExternalReference;

  __ li(kSwitchFlagRegister, 0);
  __ mv(kOldSPRegister, sp);

  // Using x2-x4 as temporary registers, because they will be rewritten
  // before exiting to native code anyway.

  ER on_central_stack_flag_loc = ER::Create(
      IsolateAddressId::kIsOnCentralStackFlagAddress, masm->isolate());
  const Register& on_central_stack_flag = a2;
  __ li(on_central_stack_flag, on_central_stack_flag_loc);
  __ Lb(on_central_stack_flag, MemOperand(on_central_stack_flag));

  Label do_not_need_to_switch;
  __ Branch(&do_not_need_to_switch, ne, on_central_stack_flag,
            Operand(zero_reg));
  // Switch to central stack.

  static constexpr Register central_stack_sp = a4;
  DCHECK(!AreAliased(central_stack_sp, argc_input, argv_input, target_input));
  {
    __ Push(argc_input, target_input, argv_input);
    __ PrepareCallCFunction(2, argc_input);
    __ li(kCArgRegs[0], ER::isolate_address(masm->isolate()));
    __ mv(kCArgRegs[1], kOldSPRegister);
    __ CallCFunction(ER::wasm_switch_to_the_central_stack(), 2,
                     SetIsolateDataSlots::kNo);
    __ mv(central_stack_sp, kReturnRegister0);
    __ Pop(argc_input, target_input, argv_input);
  }

  SwitchSimulatorStackLimit(masm);

  static constexpr int kReturnAddressSlotOffset = 1 * kSystemPointerSize;
  static constexpr int kPadding = 1 * kSystemPointerSize;
  __ SubWord(sp, central_stack_sp, kReturnAddressSlotOffset + kPadding);
  __ li(kSwitchFlagRegister, 1);

  // Update the sp saved in the frame.
  // It will be used to calculate the callee pc during GC.
  // The pc is going to be on the new stack segment, so rewrite it here.
  __ AddWord(central_stack_sp, sp, kSystemPointerSize);
  __ StoreWord(central_stack_sp, MemOperand(fp, ExitFrameConstants::kSPOffset));

  __ bind(&do_not_need_to_switch);
}

void SwitchFromTheCentralStackIfNeeded(MacroAssembler* masm) {
  using ER = ExternalReference;

  Label no_stack_change;
  __ Branch(&no_stack_change, eq, kSwitchFlagRegister, Operand(zero_reg));

  {
    __ Push(kReturnRegister0, kReturnRegister1);
    __ li(kCArgRegs[0], ER::isolate_address(masm->isolate()));
    DCHECK_NE(kReturnRegister1, kCArgRegs[0]);
    __ PrepareCallCFunction(1, kReturnRegister1);
    __ CallCFunction(ER::wasm_switch_from_the_central_stack(), 1,
                     SetIsolateDataSlots::kNo);
    __ Pop(kReturnRegister0, kReturnRegister1);
  }

  __ mv(sp, kOldSPRegister);

  __ bind(&no_stack_change);
}
}  // namespace

void Builtins::Generate_CEntry(MacroAssembler* masm, int result_size,
                               ArgvMode argv_mode, bool builtin_exit_frame,
                               bool switch_to_central_stack) {
  // Called from JavaScript; parameters are on stack as if calling JS function
  // a0: number of arguments including receiver
  // a1: pointer to c++ function
  // fp: frame pointer    (restored after C call)
  // sp: stack pointer    (restored as callee's sp after C call)
  // cp: current context  (C callee-saved)
  // If argv_mode == ArgvMode::kRegister:
  // a2: pointer to the first argument
  using ER = ExternalReference;

  static constexpr Register argc_input = a0;
  static constexpr Register target_input = a1;
  // Initialized below if ArgvMode::kStack.
  static constexpr Register argv_input = s1;
  static constexpr Register argc_sav = s3;
  static constexpr Register scratch = a3;
  if (argv_mode == ArgvMode::kRegister) {
    // Move argv into the correct register.
    __ Move(s1, a2);
  } else {
    // Compute the argv pointer in a callee-saved register.
    __ CalcScaledAddress(s1, sp, a0, kSystemPointerSizeLog2);
    __ SubWord(s1, s1, kSystemPointerSize);
  }

  // Enter the exit frame that transitions from JavaScript to C++.
  FrameScope scope(masm, StackFrame::MANUAL);
  __ EnterExitFrame(
      scratch, 0,
      builtin_exit_frame ? StackFrame::BUILTIN_EXIT : StackFrame::EXIT);

  // s3: number of arguments  including receiver (C callee-saved)
  // s1: pointer to first argument (C callee-saved)
  // s2: pointer to builtin function (C callee-saved)

  // Prepare arguments for C routine.
  // a0 = argc
  __ Move(argc_sav, argc_input);
  __ Move(s2, target_input);

  // We are calling compiled C/C++ code. a0 and a1 hold our two arguments. We
  // also need to reserve the 4 argument slots on the stack.

  __ AssertStackIsAligned();

#if V8_ENABLE_WEBASSEMBLY
  if (switch_to_central_stack) {
    SwitchToTheCentralStackIfNeeded(masm, argc_input, target_input, argv_input);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  // a0 = argc, a1 = argv, a2 = isolate
  __ li(a2, ER::isolate_address(masm->isolate()));
  __ Move(a1, s1);

  __ StoreReturnAddressAndCall(s2);

  // Result returned in a0 or a1:a0 - do not destroy these registers!
#if V8_ENABLE_WEBASSEMBLY
  if (switch_to_central_stack) {
    SwitchFromTheCentralStackIfNeeded(masm);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  // Check result for exception sentinel.
  Label exception_returned;
  // The returned value may be a trusted object, living outside of the main
  // pointer compression cage, so we need to use full pointer comparison here.
  __ CompareRootAndBranch(a0, RootIndex::kException, eq, &exception_returned,
                          ComparisonMode::kFullPointer);

  // Exit C frame and return.
  // a0:a1: result
  // sp: stack pointer
  // fp: frame pointer
  // s3: still holds argc (C caller-saved).
  __ LeaveExitFrame(scratch);
  if (argv_mode == ArgvMode::kStack) {
    DCHECK(!AreAliased(scratch, argc_sav));
    __ DropArguments(argc_sav);
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

  // Ask the runtime for help to determine the handler. This will set a0 to
  // contain the current exception, don't clobber it.
  ER find_handler = ER::Create(Runtime::kUnwindAndFindExceptionHandler);
  {
    FrameScope scope(masm, StackFrame::MANUAL);
    __ PrepareCallCFunction(3, 0, a0);
    __ Move(a0, zero_reg);
    __ Move(a1, zero_reg);
    __ li(a2, ER::isolate_address());
    __ CallCFunction(find_handler, 3, SetIsolateDataSlots::kNo);
  }

  // Retrieve the handler context, SP and FP.
  __ li(cp, pending_handler_context_address);
  __ LoadWord(cp, MemOperand(cp));
  __ li(sp, pending_handler_sp_address);
  __ LoadWord(sp, MemOperand(sp));
  __ li(fp, pending_handler_fp_address);
  __ LoadWord(fp, MemOperand(fp));

  // If the handler is a JS frame, restore the context to the frame. Note that
  // the context will be set to (cp == 0) for non-JS frames.
  Label zero;
  __ Branch(&zero, eq, cp, Operand(zero_reg), Label::Distance::kNear);
  __ StoreWord(cp, MemOperand(fp, StandardFrameConstants::kContextOffset));
  __ bind(&zero);

  // Clear c_entry_fp, like we do in `LeaveExitFrame`.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, masm->isolate());
  __ StoreWord(zero_reg,
               __ ExternalReferenceAsOperand(c_entry_fp_address, no_reg));

  // Compute the handler entry address and jump to it.
  __ LoadWord(scratch, __ ExternalReferenceAsOperand(
                           pending_handler_entrypoint_address, no_reg));
  __ Jump(scratch);
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
  __ LoadDouble(double_scratch, MemOperand(sp, kArgumentOffset));

  // Try a conversion to a signed integer, if exception occurs, scratch is
  // set to 0
  __ Trunc_w_d(scratch3, double_scratch, scratch);

  // If we had no exceptions then set result_reg and we are done.
  Label error;
  __ Branch(&error, eq, scratch, Operand(zero_reg), Label::Distance::kNear);
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
  __ ExtractBits(result_reg, input_high, HeapNumber::kExponentShift,
                 HeapNumber::kExponentBits);

  // Check for Infinity and NaNs, which should return 0.
  __ Sub32(scratch, result_reg, HeapNumber::kExponentMask);
  __ LoadZeroIfConditionZero(
      result_reg,
      scratch);  // result_reg = scratch == 0 ? 0 : result_reg
  __ Branch(&done, eq, scratch, Operand(zero_reg));

  // Express exponent as delta to (number of mantissa bits + 31).
  __ Sub32(result_reg, result_reg,
           Operand(HeapNumber::kExponentBias + HeapNumber::kMantissaBits + 31));

  // If the delta is strictly positive, all bits would be shifted away,
  // which means that we can return 0.
  __ Branch(&normal_exponent, le, result_reg, Operand(zero_reg),
            Label::Distance::kNear);
  __ Move(result_reg, zero_reg);
  __ Branch(&done);

  __ bind(&normal_exponent);
  const int kShiftBase = HeapNumber::kNonMantissaBitsInTopWord - 1;
  // Calculate shift.
  __ Add32(scratch, result_reg,
           Operand(kShiftBase + HeapNumber::kMantissaBits));

  // Save the sign.
  Register sign = result_reg;
  result_reg = no_reg;
  __ And(sign, input_high, Operand(HeapNumber::kSignMask));

  // We must specially handle shifts greater than 31.
  Label high_shift_needed, high_shift_done;
  __ Branch(&high_shift_needed, lt, scratch, Operand(32),
            Label::Distance::kNear);
  __ Move(input_high, zero_reg);
  __ BranchShort(&high_shift_done);
  __ bind(&high_shift_needed);

  // Set the implicit 1 before the mantissa part in input_high.
  __ Or(input_high, input_high,
        Operand(1 << HeapNumber::kMantissaBitsInTopWord));
  // Shift the mantissa bits to the correct position.
  // We don't need to clear non-mantissa bits as they will be shifted away.
  // If they weren't, it would mean that the answer is in the 32bit range.
  __ Sll32(input_high, input_high, scratch);

  __ bind(&high_shift_done);

  // Replace the shifted bits with bits from the lower mantissa word.
  Label pos_shift, shift_done, sign_negative;
  __ li(kScratchReg, 32);
  __ Sub32(scratch, kScratchReg, scratch);
  __ Branch(&pos_shift, ge, scratch, Operand(zero_reg), Label::Distance::kNear);

  // Negate scratch.
  __ Sub32(scratch, zero_reg, scratch);
  __ Sll32(input_low, input_low, scratch);
  __ BranchShort(&shift_done);

  __ bind(&pos_shift);
  __ Srl32(input_low, input_low, scratch);

  __ bind(&shift_done);
  __ Or(input_high, input_high, Operand(input_low));
  // Restore sign if necessary.
  __ Move(scratch, sign);
  result_reg = sign;
  sign = no_reg;
  __ Sub32(result_reg, zero_reg, input_high);
  __ Branch(&sign_negative, ne, scratch, Operand(zero_reg),
            Label::Distance::kNear);
  __ Move(result_reg, input_high);
  __ bind(&sign_negative);

  __ bind(&done);

  __ StoreWord(result_reg, MemOperand(sp, kArgumentOffset));
  __ Pop(scratch, scratch2, scratch3);
  __ Pop(result_reg);
  __ Ret();
}

void Builtins::Generate_WasmToJsWrapperAsm(MacroAssembler* masm) {
  int required_stack_space = arraysize(wasm::kFpParamRegisters) * kDoubleSize;
  __ SubWord(sp, sp, Operand(required_stack_space));
  for (int i = 0; i < static_cast<int>(arraysize(wasm::kFpParamRegisters));
       ++i) {
    __ StoreDouble(wasm::kFpParamRegisters[i], MemOperand(sp, i * kDoubleSize));
  }

  constexpr int num_gp = arraysize(wasm::kGpParamRegisters) - 1;
  required_stack_space = num_gp * kSystemPointerSize;
  __ SubWord(sp, sp, Operand(required_stack_space));
  for (int i = 1; i < static_cast<int>(arraysize(wasm::kGpParamRegisters));
       ++i) {
    __ StoreWord(wasm::kGpParamRegisters[i],
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
  __ AddWord(ra, kWasmTrapHandlerFaultAddressRegister, 1);
  __ TailCallBuiltin(Builtin::kWasmTrapHandlerThrowTrap);
}

namespace {
// Check that the stack was in the old state (if generated code assertions are
// enabled), and switch to the new state.
void SwitchStackState(MacroAssembler* masm, Register jmpbuf, Register tmp,
                      wasm::JumpBuffer::StackState old_state,
                      wasm::JumpBuffer::StackState new_state) {
  ASM_CODE_COMMENT(masm);
#if V8_ENABLE_SANDBOX
  __ Lw(tmp, MemOperand(jmpbuf, wasm::kJmpBufStateOffset));
  Label ok;
  // is branch32?
  __ Branch(&ok, eq, tmp, Operand(old_state));
  __ Trap();
  __ bind(&ok);
#endif
  __ li(tmp, new_state);
  __ Sw(tmp, MemOperand(jmpbuf, wasm::kJmpBufStateOffset));
}

// Switch the stack pointer. Also switch the simulator's stack limit when
// running on the simulator. This needs to be done as close as possible to
// changing the stack pointer, as a mismatch between the stack pointer and the
// simulator's stack limit can cause stack access check failures.
void SwitchStackPointerAndSimulatorStackLimit(MacroAssembler* masm,
                                              Re
"""


```