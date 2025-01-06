Response: The user wants me to summarize the functionality of a C++ source code file.
This is part 2 of 4. I have already seen part 1.
The code seems to be related to built-in functions for the ARM64 architecture in the V8 JavaScript engine.
It defines various built-in functions related to function calls, construction, interpreter interactions, and WebAssembly.

I need to go through the provided code snippets and understand what each function does.
Then, I should provide a summary of the overall functionality of this part of the file.
If any functionality is directly related to JavaScript, I should provide a JavaScript example to illustrate it.

Let's analyze each function:

- `Generate_InterpreterPushArgs`: This function seems to handle pushing arguments onto the stack when calling a JavaScript function in the interpreter.
- `Generate_InterpreterPushArgsThenConstructImpl`:  This builds upon `Generate_InterpreterPushArgs` and handles the specifics of calling a constructor in the interpreter.
- `Generate_ConstructForwardAllArgsImpl`: This function is about forwarding all arguments from a current or parent frame to a constructor call.
- `NewImplicitReceiver`:  This helper function creates an implicit receiver object during constructor calls.
- `Generate_InterpreterPushArgsThenFastConstructFunction`: This function optimizes constructor calls in the interpreter by creating a "fast construct" frame.
- `Generate_InterpreterEnterBytecode`: This function is responsible for entering the interpreter at a specific bytecode offset.
- `Generate_InterpreterEnterAtNextBytecode` and `Generate_InterpreterEnterAtBytecode`: These are variations of entering the interpreter.
- `Generate_ContinueToBuiltinHelper`: This helper manages the transition back to a built-in function after deoptimization.
- `Generate_ContinueToCodeStubBuiltin`, `Generate_ContinueToCodeStubBuiltinWithResult`, `Generate_ContinueToJavaScriptBuiltin`, `Generate_ContinueToJavaScriptBuiltinWithResult`: These are specific implementations of continuing to built-in functions.
- `Generate_NotifyDeoptimized`: This function is called when code is deoptimized.
- `Generate_OSREntry`: This helper is for On-Stack Replacement (OSR).
- `OnStackReplacement`: This function handles the logic for replacing running code with optimized code during OSR.
- `Generate_InterpreterOnStackReplacement` and `Generate_BaselineOnStackReplacement`: These are specific implementations of OSR from the interpreter and baseline compiler.
- `Generate_MaglevFunctionEntryStackCheck`: This function checks the stack size upon entering a Maglev-compiled function.
- `Generate_FunctionPrototypeApply`: This implements the `Function.prototype.apply` method.
- `Generate_FunctionPrototypeCall`: This implements the `Function.prototype.call` method.
- `Generate_ReflectApply`: This implements the `Reflect.apply` method.
- `Generate_ReflectConstruct`: This implements the `Reflect.construct` method.
- `Generate_PrepareForCopyingVarargs`: This helper prepares the stack for variable arguments.
- `Generate_CallOrConstructVarargs`: This handles calling or constructing functions with variable arguments.
- `Generate_CallOrConstructForwardVarargs`: This handles calling or constructing functions by forwarding variable arguments.
- `Generate_CallFunction`: This implements the core function call logic.
- `Generate_PushBoundArguments`: This helper pushes bound arguments onto the stack for bound functions.
- `Generate_CallBoundFunctionImpl`: This implements calling a bound function.
- `Generate_Call`: This is a general call dispatcher that handles different callable types.
- `Generate_ConstructFunction`: This handles constructing a regular JavaScript function.
- `Generate_ConstructBoundFunction`: This handles constructing a bound function.
- `Generate_Construct`: This is a general construct dispatcher.
- `Generate_WasmLiftoffFrameSetup`, `Generate_WasmCompileLazy`, `Generate_WasmDebugBreak`: These functions are related to WebAssembly.
- Helper functions related to WebAssembly continuations.

Overall, this part of the file focuses heavily on the mechanics of calling and constructing JavaScript functions at a low level, including handling arguments, receivers, and new targets. It also includes support for interpreter execution, deoptimization, on-stack replacement, and specific built-in methods like `apply` and `call`. The inclusion of WebAssembly related functions suggests this part also deals with the integration of WebAssembly calls.
这个C++源代码文件（`builtins-arm64.cc` 的第2部分）主要负责生成ARM64架构下V8 JavaScript引擎的内置函数（built-ins）的代码。 这部分代码涵盖了多种与函数调用和对象构造相关的内置函数的实现，尤其关注解释器（Interpreter）的集成、优化（如On-Stack Replacement），以及对特定 built-in 方法（如 `apply` 和 `call`）的实现。

**主要功能归纳:**

1. **解释器集成:**
   - 提供将参数推送到解释器调用栈的机制 (`Generate_InterpreterPushArgs`, `Generate_InterpreterPushArgsThenConstructImpl`, `Generate_InterpreterPushArgsThenFastConstructFunction`).
   - 实现进入和在解释器中执行字节码的逻辑 (`Generate_InterpreterEnterBytecode`, `Generate_InterpreterEnterAtNextBytecode`, `Generate_InterpreterEnterAtBytecode`).

2. **函数调用机制:**
   - 实现不同类型的函数调用，包括普通函数 (`Generate_CallFunction`)、绑定函数 (`Generate_CallBoundFunctionImpl`)。
   - 提供通用的 `Call` built-in，用于分发到不同的调用实现，并处理非可调用对象的调用。

3. **对象构造机制:**
   - 实现不同类型的对象构造，包括普通函数作为构造函数 (`Generate_ConstructFunction`)、绑定函数作为构造函数 (`Generate_ConstructBoundFunction`)。
   - 提供通用的 `Construct` built-in，用于分发到不同的构造实现，并处理非构造函数的构造调用。
   - 支持 `new.target` 的处理。

4. **内置方法实现:**
   - 实现 `Function.prototype.apply` (`Generate_FunctionPrototypeApply`) 和 `Function.prototype.call` (`Generate_FunctionPrototypeCall`)。
   - 实现 `Reflect.apply` (`Generate_ReflectApply`) 和 `Reflect.construct` (`Generate_ReflectConstruct`)。

5. **可变参数处理:**
   - 提供处理可变参数的机制，用于函数调用和构造 (`Generate_CallOrConstructVarargs`, `Generate_CallOrConstructForwardVarargs`, `Generate_PrepareForCopyingVarargs`).

6. **优化和去优化:**
   - 实现 On-Stack Replacement (OSR) 的进入逻辑，允许将正在执行的解释器或基线代码替换为优化后的代码 (`Generate_InterpreterOnStackReplacement`, `Generate_BaselineOnStackReplacement`, `Generate_OSREntry`, `OnStackReplacement`).
   - 提供去优化通知机制 (`Generate_NotifyDeoptimized`)。
   - 包含 Maglev 编译器的入口栈检查 (`Generate_MaglevFunctionEntryStackCheck`).

7. **WebAssembly 支持:**
   - 包含用于设置 WebAssembly Liftoff 框架、延迟编译 WebAssembly 代码和处理 WebAssembly 断点的内置函数 (`Generate_WasmLiftoffFrameSetup`, `Generate_WasmCompileLazy`, `Generate_WasmDebugBreak`)。
   - 包含 WebAssembly 协程（continuations）相关的辅助函数。

**与 JavaScript 功能的关系及示例:**

这部分代码直接对应于 JavaScript 中函数调用和对象构造的核心语义。例如：

**1. `Function.prototype.apply` 和 `Function.prototype.call`:**

```javascript
function greet(greeting) {
  console.log(greeting + ', ' + this.name);
}

const person = { name: 'Alice' };

// 使用 apply
greet.apply(person, ['Hello']); // 对应 Builtins::Generate_FunctionPrototypeApply

// 使用 call
greet.call(person, 'Hi');    // 对应 Builtins::Generate_FunctionPrototypeCall
```

**2. `Reflect.apply` 和 `Reflect.construct`:**

```javascript
function sum(a, b) {
  return a + b;
}

const args = [5, 10];
const resultApply = Reflect.apply(sum, null, args); // 对应 Builtins::Generate_ReflectApply
console.log(resultApply); // 输出 15

class Point {
  constructor(x, y) {
    this.x = x;
    this.y = y;
  }
}

const argsConstruct = [1, 2];
const point = Reflect.construct(Point, argsConstruct); // 对应 Builtins::Generate_ReflectConstruct
console.log(point.x, point.y); // 输出 1 2
```

**3. 构造函数调用:**

```javascript
function MyClass(value) {
  this.value = value;
}

const instance = new MyClass(42); // 对应 Builtins::Generate_Construct 等相关函数
console.log(instance.value); // 输出 42
```

**4. 可变参数函数调用:**

```javascript
function logArgs() {
  console.log(arguments.length, Array.from(arguments));
}

logArgs(1, 2, 3); // 对应 Builtins::Generate_CallOrConstructVarargs 等相关函数
```

**总结:**

`builtins-arm64.cc` 的这一部分是 V8 引擎中实现 JavaScript 函数调用和对象构造等核心功能的基石。它定义了在 ARM64 架构上执行这些操作的具体步骤，并且与 JavaScript 语言的语义紧密相关。通过这些底层的 built-in 函数，V8 能够高效地执行 JavaScript 代码。 同时，也包含了与解释器和 WebAssembly 集成的重要功能。

Prompt: 
```
这是目录为v8/src/builtins/arm64/builtins-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
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
    Register dst = x12;
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