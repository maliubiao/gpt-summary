Response: The user wants me to summarize the functionality of the provided C++ code snippet from `v8/src/builtins/arm/builtins-arm.cc`. This is part 2 of a 3-part request.

The code mainly deals with the implementation of various built-in functions and operations specific to the ARM architecture within the V8 JavaScript engine. These built-ins are often low-level and directly interact with the underlying interpreter and compiled code.

Here's a breakdown of the functionality:

1. **Interpreter Entry Points:**  Functions to enter the JavaScript interpreter at specific bytecode offsets.
2. **Continuation Handling:** Functions to resume execution after a deoptimization or other interruption, both for regular code stubs and JavaScript built-ins.
3. **Deoptimization Notification:** A function to notify the runtime when deoptimization occurs.
4. **On-Stack Replacement (OSR):** Functions to transition execution from the interpreter or baseline compiler to optimized code.
5. **Stack Checking:**  A function to perform stack overflow checks.
6. **`Function.prototype.apply` and `Function.prototype.call`:** Implementations of these core JavaScript functions.
7. **`Reflect.apply` and `Reflect.construct`:** Implementations of these reflection API methods.
8. **Variable Argument Handling:** Functions (`CallOrConstructVarargs`, `CallOrConstructForwardVarargs`) to manage calling functions with a variable number of arguments, either directly or by forwarding arguments from a caller frame.
9. **Function Calling:**  `CallFunction` handles calling JavaScript functions, including receiver conversion for non-strict mode functions.
10. **Bound Function Handling:** Functions (`Generate_PushBoundArguments`, `Generate_CallBoundFunctionImpl`) to manage calls to bound functions, including pushing bound arguments onto the stack and adjusting the receiver.
11. **Generic Call Builtin:** `Call` handles calling various JavaScript objects, including functions, bound functions, proxies, and objects with a `[[Call]]` internal method.
12. **Function Construction:** `ConstructFunction` handles constructing JavaScript functions.
13. **Bound Function Construction:** `ConstructBoundFunction` handles constructing bound functions.
14. **Generic Construct Builtin:** `Construct` handles constructing various JavaScript objects, including functions, bound functions, and proxies.
15. **WebAssembly Support:** A significant portion of the code deals with WebAssembly integration, including:
    - Frame setup for Liftoff compiler.
    - Lazy compilation of WebAssembly functions.
    - Handling debug breaks in WebAssembly code.
    - Implementing `wasm-suspend` and `wasm-resume` for asynchronous operations.
    - Handling stack switching for WebAssembly.

I will now formulate a concise summary and provide JavaScript examples where applicable.
这是 `v8/src/builtins/arm/builtins-arm.cc` 文件的一部分，主要负责实现以下与 JavaScript 执行密切相关的功能，特别是在 ARM 架构上：

**核心功能归纳：**

* **解释器入口 (Interpreter Entry Points):**  定义了进入 JavaScript 解释器的不同入口点，例如 `Generate_InterpreterEnterBytecode` 和 `Generate_InterpreterEnterAtNextBytecode`，用于在执行字节码时跳转到解释器。
* **代码桩（Code Stub）和内置函数的继续执行 (Continuation Handling):**  提供了在执行代码桩或内置函数后，如何返回到 JavaScript 代码或继续执行的机制，例如 `Generate_ContinueToCodeStubBuiltin` 和 `Generate_ContinueToJavaScriptBuiltin`。这些机制处理了在优化的代码中发生去优化（deoptimization）后如何返回到解释器继续执行。
* **去优化通知 (Deoptimization Notification):**  `Generate_NotifyDeoptimized` 函数用于在发生去优化时通知运行时系统。
* **栈上替换 (On-Stack Replacement - OSR):**  `Generate_InterpreterOnStackReplacement` 和 `Generate_BaselineOnStackReplacement`  实现了从解释器或基线编译器切换到优化后的代码的机制。
* **函数原型方法的实现 (`Function.prototype.apply`, `Function.prototype.call`):** 提供了 `apply` 和 `call` 这两个重要的函数原型方法的底层实现，用于动态调用函数并指定 `this` 值和参数。
* **反射 API 的实现 (`Reflect.apply`, `Reflect.construct`):** 实现了 `Reflect.apply` 和 `Reflect.construct` 这两个反射 API 的底层机制。
* **变长参数处理 (`CallOrConstructVarargs`, `CallOrConstructForwardVarargs`):** 实现了在调用或构造函数时处理可变数量参数的逻辑。
* **函数调用和构造 (`Generate_CallFunction`, `Generate_ConstructFunction`, `Generate_Call`, `Generate_Construct`):**  提供了调用普通函数、构造函数以及处理绑定函数调用的底层实现。这部分代码负责检查目标是否可调用或可构造，并根据目标类型执行相应的操作。
* **WebAssembly 支持 (Wasm Support):**  包含了一系列与 WebAssembly 集成相关的功能，例如 WebAssembly 函数的懒编译 (`Generate_WasmCompileLazy`)、调试断点处理 (`Generate_WasmDebugBreak`) 以及对 `wasm-suspend` 和 `wasm-resume` 的支持，用于实现 WebAssembly 的异步操作。

**与 JavaScript 功能的关系及 JavaScript 示例：**

这些 C++ 代码直接支撑着 JavaScript 的运行时行为。它们是 V8 引擎执行 JavaScript 代码的基础。

**1. `Function.prototype.apply` 和 `Function.prototype.call`:**

```javascript
function greet(greeting) {
  console.log(greeting + ', ' + this.name);
}

const person = { name: 'Alice' };

// 使用 call
greet.call(person, 'Hello'); // C++ 代码中 Generate_FunctionPrototypeCall 的实现会被调用

// 使用 apply
greet.apply(person, ['Hi']);   // C++ 代码中 Generate_FunctionPrototypeApply 的实现会被调用
```

**2. `Reflect.apply` 和 `Reflect.construct`:**

```javascript
function sum(a, b) {
  return a + b;
}

const args = [5, 10];
const result = Reflect.apply(sum, null, args); // C++ 代码中 Generate_ReflectApply 的实现会被调用
console.log(result); // 输出 15

class Point {
  constructor(x, y) {
    this.x = x;
    this.y = y;
  }
}

const pointArgs = [1, 2];
const newPoint = Reflect.construct(Point, pointArgs); // C++ 代码中 Generate_ReflectConstruct 的实现会被调用
console.log(newPoint.x, newPoint.y); // 输出 1 2
```

**3. 变长参数：**

```javascript
function logArguments() {
  console.log(arguments.length);
  for (let i = 0; i < arguments.length; i++) {
    console.log(arguments[i]);
  }
}

logArguments(1, 'hello', true); // C++ 代码中 CallOrConstructVarargs 或 CallOrConstructForwardVarargs 的实现会被调用
```

**4. 函数调用和构造：**

```javascript
function myFunction() {
  console.log('Function called');
}

myFunction(); // C++ 代码中 Generate_Call 或 Generate_CallFunction 的实现会被调用

function MyConstructor(value) {
  this.value = value;
}

const instance = new MyConstructor(42); // C++ 代码中 Generate_Construct 或 Generate_ConstructFunction 的实现会被调用
console.log(instance.value);
```

**5. WebAssembly 的 `wasm-suspend` 和 `wasm-resume` (需要 WebAssembly 代码):**

虽然直接的 JavaScript 示例不容易展示，但这些 C++ 代码支持 WebAssembly 的异步操作。当 WebAssembly 模块调用 `wasm-suspend` 时，`Generate_WasmSuspend` 中的逻辑会被执行，将当前状态保存起来。当 Promise resolve 或 reject 时，JavaScript 代码可能会调用 `wasm-resume` 或 `wasm-reject`，对应 C++ 代码中的 `Generate_WasmResume` 或 `Generate_WasmReject`，用于恢复 WebAssembly 的执行。

总而言之，这部分 C++ 代码是 V8 引擎在 ARM 架构上执行 JavaScript 代码的关键组成部分，它提供了许多核心的运行时支持。

Prompt: 
```
这是目录为v8/src/builtins/arm/builtins-arm.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能

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
  //  -- r3 : the new target (checked to be a constructor)
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