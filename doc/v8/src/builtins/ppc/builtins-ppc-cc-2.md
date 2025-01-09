Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/builtins/ppc/builtins-ppc.cc`.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the file:** The filename `v8/src/builtins/ppc/builtins-ppc.cc` indicates this file contains architecture-specific (PPC in this case) implementations of built-in functions for the V8 JavaScript engine. The `.cc` extension confirms it's C++ source code.

2. **Scan for function definitions:** The code consists primarily of function definitions within the `v8::internal::Builtins` namespace. Each function name (e.g., `Generate_InterpreterPushArgsThenFastConstructFunction`, `Generate_InterpreterEnterBytecode`, `Generate_FunctionPrototypeApply`) strongly suggests the purpose of the code block.

3. **Categorize the functionalities:**  Group the functions based on their apparent purpose. Common themes emerge:
    * **Object Construction:**  Functions with "Construct" in their name (e.g., `Generate_InterpreterPushArgsThenFastConstructFunction`, `Generate_ReflectConstruct`).
    * **Function Calls:** Functions related to calling functions (e.g., `Generate_FunctionPrototypeApply`, `Generate_FunctionPrototypeCall`, `Generate_ReflectApply`, `Generate_CallFunction`).
    * **Interpreter Interaction:** Functions with "Interpreter" in their name (e.g., `Generate_InterpreterEnterBytecode`, `Generate_InterpreterEnterAtNextBytecode`). These seem to handle the transition into the V8 interpreter.
    * **Deoptimization and Optimization:** Functions like `Generate_ContinueToCodeStubBuiltin`, `Generate_NotifyDeoptimized`, and the "OnStackReplacement" functions.
    * **Variable Argument Handling:** Functions with "Varargs" in their name (e.g., `Generate_CallOrConstructVarargs`, `Generate_CallOrConstructForwardVarargs`).

4. **Analyze individual function logic (briefly):** While a full detailed analysis isn't needed for a summary, skim the code within each function to understand the core actions:
    * **Stack Manipulation:**  Look for `Push`, `Pop`, `AllocateStackSpace`, and frame-related operations (`EnterFrame`, `LeaveFrame`).
    * **Register Usage:** Note the registers used and their roles (e.g., `r3` for argument count, `r4` for the target function).
    * **Builtin Calls:** Identify calls to other built-in functions (e.g., `TailCallBuiltin(Builtin::kConstruct)`).
    * **Runtime Calls:** Identify calls to runtime functions (e.g., `CallRuntime(Runtime::kThrowStackOverflow)`).
    * **Conditional Logic:** Observe `if` statements and branching instructions (labels and `beq`, `bne`).

5. **Address specific instructions from the prompt:**
    * **`.tq` extension:** The prompt mentions that a `.tq` extension would indicate a Torque source file. Confirm that this file is `.cc` and therefore C++ code.
    * **Relationship to JavaScript:**  Since these are built-in functions, they directly implement core JavaScript functionalities like function calls, object creation, and handling arguments. Provide JavaScript examples to illustrate these connections (e.g., `new` for constructors, `.apply()` and `.call()` for function invocation).
    * **Code logic inference:** The example of `Generate_InterpreterPushArgsThenFastConstructFunction` and the stack layout demonstrates code logic. Provide a simplified input/output scenario.
    * **Common programming errors:**  Think about the kinds of errors these built-ins help prevent or handle. Stack overflow is a clear example.
    * **Part 3 of 5:** Acknowledge this context.

6. **Synthesize the summary:**  Combine the categorized functionalities and insights from the code analysis into a concise summary. Use clear and descriptive language. Address all points raised in the initial prompt.

7. **Refine and organize:** Review the summary for clarity, accuracy, and organization. Ensure it flows logically and is easy to understand. Use bullet points or numbered lists to improve readability. Specifically address the "归纳一下它的功能" (summarize its functionality) part of the prompt.

By following these steps, we can generate a comprehensive and informative summary of the provided V8 built-ins code.这是一个V8 JavaScript引擎的源代码文件，专门针对PowerPC (PPC) 架构。它定义了在PPC架构上执行JavaScript内置函数的核心逻辑。以下是其功能的详细归纳：

**主要功能归纳：**

* **实现 JavaScript 内置函数的核心逻辑 (PPC 架构特定):**  这个文件包含了许多关键 JavaScript 内置函数的低级实现，这些函数是 JavaScript 语言的基础组成部分，例如对象创建、函数调用、`apply`、`call`、`construct` 等。由于是 `.cc` 文件，这些实现是用 C++ 和汇编语言（通过 `MacroAssembler`）编写的，直接操作机器指令，以实现高性能。
* **处理函数调用和构造:**  文件中定义了多种处理函数调用和对象构造的内置函数，包括：
    * **Fast Construct:** 优化后的对象构造路径，尝试避免不必要的开销。
    * **Interpreter Integration:**  处理从解释器调用内置函数的情况，以及在解释器中执行代码前的准备工作。
    * **Varargs Handling:** 处理参数数量可变的函数调用 (`apply` 等)。
* **管理执行栈帧:**  代码中大量涉及到栈帧的操作，例如创建、进入、离开栈帧，以及在栈帧中存储和加载参数、上下文等信息。这对于正确的函数调用和控制流至关重要。
* **处理优化和反优化 (Deoptimization):**  包含了与代码优化和反优化相关的逻辑。例如，`Generate_ContinueToCodeStubBuiltin` 等函数用于在代码被反优化后继续执行。
* **提供与解释器交互的入口:**  `Generate_InterpreterEnterBytecode` 等函数负责将控制权转移到字节码解释器，开始执行 JavaScript 代码。
* **实现 `Function.prototype.apply` 和 `Function.prototype.call`:**  这些是重要的内置函数，允许以不同的方式调用函数并指定 `this` 上下文。
* **实现 `Reflect` API 的方法:**  例如 `Reflect.apply` 和 `Reflect.construct`，提供了对函数调用和对象构造的底层控制。
* **处理 On-Stack Replacement (OSR):**  `Generate_InterpreterOnStackReplacement` 和 `Generate_BaselineOnStackReplacement` 用于在程序运行过程中，将正在执行的解释器代码或基线代码替换为更优化的代码。

**关于文件类型和与 JavaScript 的关系：**

* **`.tq` 结尾：**  你提到如果文件以 `.tq` 结尾，则为 Torque 源代码。由于 `v8/src/builtins/ppc/builtins-ppc.cc` 以 `.cc` 结尾， **它是一个 C++ 源代码文件**。 Torque 是一种 V8 内部使用的领域特定语言，用于定义内置函数的行为，它可以生成 C++ 代码。
* **与 JavaScript 的关系：** 这个文件中的代码 **直接实现了 JavaScript 的核心功能**。  JavaScript 代码最终会调用这些内置函数来执行各种操作。

**JavaScript 示例：**

以下是一些 JavaScript 代码示例，它们的功能与 `builtins-ppc.cc` 中的代码密切相关：

```javascript
// 对象构造
class MyClass {}
const myObject = new MyClass(); //  对应 builtins-ppc.cc 中的构造相关逻辑

// 函数调用
function myFunction(a, b) {
  return a + b;
}
myFunction(1, 2); // 对应 builtins-ppc.cc 中的函数调用逻辑

// Function.prototype.apply
const obj = { value: 10 };
function applyFunction(a, b) {
  return this.value + a + b;
}
applyFunction.apply(obj, [1, 2]); // 对应 Builtins::Generate_FunctionPrototypeApply

// Function.prototype.call
function callFunction(a, b) {
  return this.value + a + b;
}
callFunction.call(obj, 3, 4); // 对应 Builtins::Generate_FunctionPrototypeCall

// Reflect.apply
Reflect.apply(applyFunction, obj, [5, 6]); // 对应 Builtins::Generate_ReflectApply

// Reflect.construct
Reflect.construct(MyClass, []); // 对应 Builtins::Generate_ReflectConstruct
```

**代码逻辑推理示例：**

假设输入以下 JavaScript 代码并尝试执行：

```javascript
function greet(name) {
  console.log("Hello, " + name + "!");
}

greet("World");
```

**假设输入:**  调用 `greet` 函数，参数为字符串 "World"。

**相关 `builtins-ppc.cc` 代码片段 (简化)：**  可能会涉及到 `Generate_CallFunction` 或类似的函数调用处理逻辑。

**代码逻辑推理 (基于 `Generate_CallFunction` 的部分逻辑):**

1. V8 引擎识别到函数调用 `greet("World")`。
2. `Generate_CallFunction` (或类似的函数) 被调用。
3. **假设栈的状态:**  栈上会包含参数数量 (1)，以及对 `greet` 函数的引用。
4. 代码会加载 `greet` 函数的 `SharedFunctionInfo` 以获取函数的信息。
5. 代码会加载 `greet` 函数的上下文。
6. 代码可能会执行接收者转换（如果 `greet` 不是严格模式函数）。在这个例子中，`greet` 是普通函数，接收者会是全局对象（或 `undefined` 在严格模式下，但这里假设非严格模式）。
7. 最终，代码会跳转到 `greet` 函数的代码入口点，开始执行 `greet` 函数的逻辑。

**输出 (JavaScript 执行结果):**  控制台会打印 "Hello, World!".

**用户常见的编程错误示例：**

* **调用非函数对象：**

```javascript
const notAFunction = {};
notAFunction(); // TypeError: notAFunction is not a function
```

   `builtins-ppc.cc` 中与函数调用相关的代码会进行类型检查，如果发现被调用的不是函数，则会抛出 `TypeError`。

* **`apply` 或 `call` 的参数错误：**

```javascript
function myFunction(a, b) {
  console.log(a, b);
}
myFunction.apply(null, 1); // TypeError: CreateListFromArrayLike called on non-object
```

   `Generate_FunctionPrototypeApply` 等函数会检查 `apply` 的第二个参数是否是可迭代对象（类似数组）。如果不是，则会抛出 `TypeError`。

* **构造非构造函数：**

```javascript
function notAConstructor() {
  return {};
}
new notAConstructor(); // TypeError: notAConstructor is not a constructor
```

   `Generate_InterpreterPushArgsThenFastConstructFunction` 等构造函数相关的代码会检查被 `new` 调用的对象是否具有 `[[Construct]]` 内部方法。如果没有，则会抛出 `TypeError`。

**总结：**

`v8/src/builtins/ppc/builtins-ppc.cc` 是 V8 引擎中至关重要的一个文件，它包含了在 PPC 架构上高效执行 JavaScript 内置函数的底层实现。它处理了函数调用、对象构造、参数传递、栈帧管理以及与解释器和优化器的交互。理解这个文件中的代码有助于深入了解 V8 引擎的内部工作原理。

Prompt: 
```
这是目录为v8/src/builtins/ppc/builtins-ppc.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/ppc/builtins-ppc.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能

"""
 StandardFrameConstants::kCallerFPOffset),
                 r0);
      break;
  }

  // Load the argument count into r3.
  __ LoadU64(r3, MemOperand(r7, StandardFrameConstants::kArgCOffset), r0);
  __ StackOverflowCheck(r3, ip, &stack_overflow);

  // Point r7 to the base of the argument list to forward, excluding the
  // receiver.
  __ addi(r7, r7,
          Operand((StandardFrameConstants::kFixedSlotCountAboveFp + 1) *
                  kSystemPointerSize));

  // Copy arguments on the stack. r8 is a scratch register.
  Register argc_without_receiver = ip;
  __ subi(argc_without_receiver, r3, Operand(kJSArgcReceiverSlots));
  __ PushArray(r7, argc_without_receiver, r8, r0);

  // Push a slot for the receiver to be constructed.
  __ li(r0, Operand::Zero());
  __ push(r0);

  // Call the constructor with r3, r4, and r6 unmodified.
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
  // -- r3 : argument count
  // -- r4 : constructor to call (checked to be a JSFunction)
  // -- r6 : new target
  //
  //  Stack:
  //  -- Implicit Receiver
  //  -- [arguments without receiver]
  //  -- Implicit Receiver
  //  -- Context
  //  -- FastConstructMarker
  //  -- FramePointer
  // -----------------------------------
  Register implicit_receiver = r7;

  // Save live registers.
  __ SmiTag(r3);
  __ Push(r3, r4, r6);
  __ CallBuiltin(Builtin::kFastNewObject);
  // Save result.
  __ Move(implicit_receiver, r3);
  // Restore live registers.
  __ Pop(r3, r4, r6);
  __ SmiUntag(r3);

  // Patch implicit receiver (in arguments)
  __ StoreU64(implicit_receiver, MemOperand(sp, 0 * kSystemPointerSize), r0);
  // Patch second implicit (in construct frame)
  __ StoreU64(
      implicit_receiver,
      MemOperand(fp, FastConstructFrameConstants::kImplicitReceiverOffset), r0);

  // Restore context.
  __ LoadU64(cp, MemOperand(fp, FastConstructFrameConstants::kContextOffset),
             r0);
}

}  // namespace

// static
void Builtins::Generate_InterpreterPushArgsThenFastConstructFunction(
    MacroAssembler* masm) {
  // ----------- S t a t e -------------
  // -- r3 : argument count
  // -- r4 : constructor to call (checked to be a JSFunction)
  // -- r6 : new target
  // -- r7 : address of the first argument
  // -- cp/r30 : context pointer
  // -----------------------------------
  __ AssertFunction(r4);

  // Check if target has a [[Construct]] internal method.
  Label non_constructor;
  __ LoadMap(r5, r4);
  __ lbz(r5, FieldMemOperand(r5, Map::kBitFieldOffset));
  __ TestBit(r5, Map::Bits1::IsConstructorBit::kShift, r0);
  __ beq(&non_constructor, cr0);

  // Add a stack check before pushing arguments.
  Label stack_overflow;
  __ StackOverflowCheck(r3, r5, &stack_overflow);

  // Enter a construct frame.
  FrameScope scope(masm, StackFrame::MANUAL);
  __ EnterFrame(StackFrame::FAST_CONSTRUCT);
  // Implicit receiver stored in the construct frame.
  __ LoadRoot(r5, RootIndex::kTheHoleValue);
  __ Push(cp, r5);

  // Push arguments + implicit receiver.
  Register argc_without_receiver = r9;
  __ SubS64(argc_without_receiver, r3, Operand(kJSArgcReceiverSlots));
  // Push the arguments. r7 and r8 will be modified.
  GenerateInterpreterPushArgs(masm, argc_without_receiver, r7, r8);
  // Implicit receiver as part of the arguments (patched later if needed).
  __ push(r5);

  // Check if it is a builtin call.
  Label builtin_call;
  __ LoadTaggedField(
      r5, FieldMemOperand(r4, JSFunction::kSharedFunctionInfoOffset), r0);
  __ lwz(r5, FieldMemOperand(r5, SharedFunctionInfo::kFlagsOffset));
  __ mov(ip, Operand(SharedFunctionInfo::ConstructAsBuiltinBit::kMask));
  __ and_(r0, r5, ip, SetRC);
  __ bne(&builtin_call, cr0);

  // Check if we need to create an implicit receiver.
  Label not_create_implicit_receiver;
  __ DecodeField<SharedFunctionInfo::FunctionKindBits>(r5);
  __ JumpIfIsInRange(
      r5, r0, static_cast<uint32_t>(FunctionKind::kDefaultDerivedConstructor),
      static_cast<uint32_t>(FunctionKind::kDerivedConstructor),
      &not_create_implicit_receiver);
  NewImplicitReceiver(masm);
  __ bind(&not_create_implicit_receiver);

  // Call the function.
  __ InvokeFunctionWithNewTarget(r4, r6, r3, InvokeType::kCall);

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
  __ JumpIfNotRoot(r3, RootIndex::kUndefinedValue, &check_receiver);

  // Otherwise we do a smi check and fall through to check if the return value
  // is a valid receiver.

  // Throw away the result of the constructor invocation and use the
  // on-stack receiver as the result.
  __ bind(&use_receiver);
  __ LoadU64(
      r3, MemOperand(fp, FastConstructFrameConstants::kImplicitReceiverOffset),
      r0);
  __ JumpIfRoot(r3, RootIndex::kTheHoleValue, &do_throw);

  __ bind(&leave_and_return);
  // Leave construct frame.
  __ LeaveFrame(StackFrame::CONSTRUCT);
  __ blr();

  __ bind(&check_receiver);
  // If the result is a smi, it is *not* an object in the ECMA sense.
  __ JumpIfSmi(r3, &use_receiver);

  // If the type of the result (stored in its map) is less than
  // FIRST_JS_RECEIVER_TYPE, it is not an object in the ECMA sense.
  static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
  __ CompareObjectType(r3, r7, r8, FIRST_JS_RECEIVER_TYPE);
  __ bge(&leave_and_return);
  __ b(&use_receiver);

  __ bind(&builtin_call);
  // TODO(victorgomes): Check the possibility to turn this into a tailcall.
  __ InvokeFunctionWithNewTarget(r4, r6, r3, InvokeType::kCall);
  __ LeaveFrame(StackFrame::FAST_CONSTRUCT);
  __ blr();

  __ bind(&do_throw);
  // Restore the context from the frame.
  __ LoadU64(cp, MemOperand(fp, FastConstructFrameConstants::kContextOffset),
             r0);
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
  __ LoadU64(r5, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ LoadTaggedField(
      r5, FieldMemOperand(r5, JSFunction::kSharedFunctionInfoOffset), r0);
  __ LoadTrustedPointerField(
      r5, FieldMemOperand(r5, SharedFunctionInfo::kTrustedFunctionDataOffset),
      kUnknownIndirectPointerTag, r0);
  __ IsObjectType(r5, kInterpreterDispatchTableRegister,
                  kInterpreterDispatchTableRegister, INTERPRETER_DATA_TYPE);
  __ bne(&builtin_trampoline);

  __ LoadCodePointerField(
      r5, FieldMemOperand(r5, InterpreterData::kInterpreterTrampolineOffset),
      r6);
  __ LoadCodeInstructionStart(r5, r5);
  __ b(&trampoline_loaded);

  __ bind(&builtin_trampoline);
  __ Move(r5, ExternalReference::
                  address_of_interpreter_entry_trampoline_instruction_start(
                      masm->isolate()));
  __ LoadU64(r5, MemOperand(r5));

  __ bind(&trampoline_loaded);
  __ addi(r0, r5, Operand(interpreter_entry_return_pc_offset.value()));
  __ mtlr(r0);

  // Initialize the dispatch table register.
  __ Move(
      kInterpreterDispatchTableRegister,
      ExternalReference::interpreter_dispatch_table_address(masm->isolate()));

  // Get the bytecode array pointer from the frame.
  __ LoadU64(kInterpreterBytecodeArrayRegister,
             MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));

  if (v8_flags.debug_code) {
    // Check function data field is actually a BytecodeArray object.
    __ TestIfSmi(kInterpreterBytecodeArrayRegister, r0);
    __ Assert(ne,
              AbortReason::kFunctionDataShouldBeBytecodeArrayOnInterpreterEntry,
              cr0);
    __ IsObjectType(kInterpreterBytecodeArrayRegister, r4, r0,
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
    __ cmpi(kInterpreterBytecodeOffsetRegister,
            Operand(BytecodeArray::kHeaderSize - kHeapObjectTag +
                    kFunctionEntryBytecodeOffset));
    __ bge(&okay);
    __ bkpt(0);
    __ bind(&okay);
  }

  // Dispatch to the target bytecode.
  UseScratchRegisterScope temps(masm);
  Register scratch = temps.Acquire();
  __ lbzx(ip, MemOperand(kInterpreterBytecodeArrayRegister,
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
  __ cmpi(kInterpreterBytecodeOffsetRegister,
          Operand(BytecodeArray::kHeaderSize - kHeapObjectTag +
                  kFunctionEntryBytecodeOffset));
  __ beq(&function_entry_bytecode);

  // Load the current bytecode.
  __ lbzx(r4, MemOperand(kInterpreterBytecodeArrayRegister,
                         kInterpreterBytecodeOffsetRegister));

  // Advance to the next bytecode.
  Label if_return;
  AdvanceBytecodeOffsetOrReturn(masm, kInterpreterBytecodeArrayRegister,
                                kInterpreterBytecodeOffsetRegister, r4, r5, r6,
                                &if_return);

  __ bind(&enter_bytecode);
  // Convert new bytecode offset to a Smi and save in the stackframe.
  __ SmiTag(r5, kInterpreterBytecodeOffsetRegister);
  __ StoreU64(r5,
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
      __ mr(scratch, r3);
    } else {
      // Overwrite the hole inserted by the deoptimizer with the return value
      // from the LAZY deopt point.
      __ StoreU64(
          r3, MemOperand(
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
    __ addi(r3, r3, Operand(return_value_offset));
    __ ShiftLeftU64(r0, r3, Operand(kSystemPointerSizeLog2));
    __ StoreU64(scratch, MemOperand(sp, r0));
    // Recover arguments count.
    __ subi(r3, r3, Operand(return_value_offset));
  }
  __ LoadU64(
      fp,
      MemOperand(sp, BuiltinContinuationFrameConstants::kFixedFrameSizeFromFp));
  // Load builtin index (stored as a Smi) and use it to get the builtin start
  // address from the builtins table.
  UseScratchRegisterScope temps(masm);
  Register builtin = temps.Acquire();
  __ Pop(builtin);
  __ addi(sp, sp,
          Operand(BuiltinContinuationFrameConstants::kFixedFrameSizeFromFp));
  __ Pop(r0);
  __ mtlr(r0);
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
    FrameAndConstantPoolScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kNotifyDeoptimized);
  }

  DCHECK_EQ(kInterpreterAccumulatorRegister.code(), r3.code());
  __ LoadU64(r3, MemOperand(sp, 0 * kSystemPointerSize));
  __ addi(sp, sp, Operand(1 * kSystemPointerSize));
  __ Ret();
}

void Builtins::Generate_InterpreterOnStackReplacement(MacroAssembler* masm) {
  using D = OnStackReplacementDescriptor;
  static_assert(D::kParameterCount == 1);
  OnStackReplacement(masm, OsrSourceTier::kInterpreter,
                     D::MaybeTargetCodeRegister());
}

void Builtins::Generate_BaselineOnStackReplacement(MacroAssembler* masm) {
  using D = OnStackReplacementDescriptor;
  static_assert(D::kParameterCount == 1);

  __ LoadU64(kContextRegister,
             MemOperand(fp, BaselineFrameConstants::kContextOffset), r0);
  OnStackReplacement(masm, OsrSourceTier::kBaseline,
                     D::MaybeTargetCodeRegister());
}

// static
void Builtins::Generate_FunctionPrototypeApply(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r3    : argc
  //  -- sp[0] : receiver
  //  -- sp[4] : thisArg
  //  -- sp[8] : argArray
  // -----------------------------------

  // 1. Load receiver into r4, argArray into r5 (if present), remove all
  // arguments from the stack (including the receiver), and push thisArg (if
  // present) instead.
  {
    __ LoadRoot(r8, RootIndex::kUndefinedValue);
    __ mr(r5, r8);

    Label done;
    __ LoadU64(r4, MemOperand(sp));  // receiver
    __ CmpS64(r3, Operand(JSParameterCount(1)), r0);
    __ blt(&done);
    __ LoadU64(r8, MemOperand(sp, kSystemPointerSize));  // thisArg
    __ CmpS64(r3, Operand(JSParameterCount(2)), r0);
    __ blt(&done);
    __ LoadU64(r5, MemOperand(sp, 2 * kSystemPointerSize));  // argArray

    __ bind(&done);
    __ DropArgumentsAndPushNewReceiver(r3, r8);
  }

  // ----------- S t a t e -------------
  //  -- r5    : argArray
  //  -- r4    : receiver
  //  -- sp[0] : thisArg
  // -----------------------------------

  // 2. We don't need to check explicitly for callable receiver here,
  // since that's the first thing the Call/CallWithArrayLike builtins
  // will do.

  // 3. Tail call with no arguments if argArray is null or undefined.
  Label no_arguments;
  __ JumpIfRoot(r5, RootIndex::kNullValue, &no_arguments);
  __ JumpIfRoot(r5, RootIndex::kUndefinedValue, &no_arguments);

  // 4a. Apply the receiver to the given argArray.
  __ TailCallBuiltin(Builtin::kCallWithArrayLike);

  // 4b. The argArray is either null or undefined, so we tail call without any
  // arguments to the receiver.
  __ bind(&no_arguments);
  {
    __ mov(r3, Operand(JSParameterCount(0)));
    __ TailCallBuiltin(Builtins::Call());
  }
}

// static
void Builtins::Generate_FunctionPrototypeCall(MacroAssembler* masm) {
  // 1. Get the callable to call (passed as receiver) from the stack.
  __ Pop(r4);

  // 2. Make sure we have at least one argument.
  // r3: actual number of arguments
  {
    Label done;
    __ CmpS64(r3, Operand(JSParameterCount(0)), r0);
    __ bne(&done);
    __ PushRoot(RootIndex::kUndefinedValue);
    __ addi(r3, r3, Operand(1));
    __ bind(&done);
  }

  // 3. Adjust the actual number of arguments.
  __ subi(r3, r3, Operand(1));

  // 4. Call the callable.
  __ TailCallBuiltin(Builtins::Call());
}

void Builtins::Generate_ReflectApply(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r3     : argc
  //  -- sp[0]  : receiver
  //  -- sp[4]  : target         (if argc >= 1)
  //  -- sp[8]  : thisArgument   (if argc >= 2)
  //  -- sp[12] : argumentsList  (if argc == 3)
  // -----------------------------------

  // 1. Load target into r4 (if present), argumentsList into r5 (if present),
  // remove all arguments from the stack (including the receiver), and push
  // thisArgument (if present) instead.
  {
    __ LoadRoot(r4, RootIndex::kUndefinedValue);
    __ mr(r8, r4);
    __ mr(r5, r4);

    Label done;
    __ CmpS64(r3, Operand(JSParameterCount(1)), r0);
    __ blt(&done);
    __ LoadU64(r4, MemOperand(sp, kSystemPointerSize));  // thisArg
    __ CmpS64(r3, Operand(JSParameterCount(2)), r0);
    __ blt(&done);
    __ LoadU64(r8, MemOperand(sp, 2 * kSystemPointerSize));  // argArray
    __ CmpS64(r3, Operand(JSParameterCount(3)), r0);
    __ blt(&done);
    __ LoadU64(r5, MemOperand(sp, 3 * kSystemPointerSize));  // argArray

    __ bind(&done);
    __ DropArgumentsAndPushNewReceiver(r3, r8);
  }

  // ----------- S t a t e -------------
  //  -- r5    : argumentsList
  //  -- r4    : target
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
  //  -- r3     : argc
  //  -- sp[0]  : receiver
  //  -- sp[4]  : target
  //  -- sp[8]  : argumentsList
  //  -- sp[12] : new.target (optional)
  // -----------------------------------

  // 1. Load target into r4 (if present), argumentsList into r5 (if present),
  // new.target into r6 (if present, otherwise use target), remove all
  // arguments from the stack (including the receiver), and push thisArgument
  // (if present) instead.
  {
    __ LoadRoot(r4, RootIndex::kUndefinedValue);
    __ mr(r5, r4);

    Label done;
    __ mr(r7, r4);
    __ CmpS64(r3, Operand(JSParameterCount(1)), r0);
    __ blt(&done);
    __ LoadU64(r4, MemOperand(sp, kSystemPointerSize));  // thisArg
    __ mr(r6, r4);
    __ CmpS64(r3, Operand(JSParameterCount(2)), r0);
    __ blt(&done);
    __ LoadU64(r5, MemOperand(sp, 2 * kSystemPointerSize));  // argArray
    __ CmpS64(r3, Operand(JSParameterCount(3)), r0);
    __ blt(&done);
    __ LoadU64(r6, MemOperand(sp, 3 * kSystemPointerSize));  // argArray
    __ bind(&done);
    __ DropArgumentsAndPushNewReceiver(r3, r7);
  }

  // ----------- S t a t e -------------
  //  -- r5    : argumentsList
  //  -- r6    : new.target
  //  -- r4    : target
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
  __ addi(old_sp, sp, Operand(-kSystemPointerSize));
  __ ShiftLeftU64(new_space, count, Operand(kSystemPointerSizeLog2));
  __ AllocateStackSpace(new_space);

  Register dest = pointer_to_new_space_out;
  __ addi(dest, sp, Operand(-kSystemPointerSize));
  Label loop, skip;
  __ mr(r0, argc_in_out);
  __ cmpi(r0, Operand::Zero());
  __ ble(&skip);
  __ mtctr(r0);
  __ bind(&loop);
  __ LoadU64WithUpdate(r0, MemOperand(old_sp, kSystemPointerSize));
  __ StoreU64WithUpdate(r0, MemOperand(dest, kSystemPointerSize));
  __ bdnz(&loop);

  __ bind(&skip);
  // Update total number of arguments, restore dest.
  __ add(argc_in_out, argc_in_out, count);
  __ addi(dest, dest, Operand(kSystemPointerSize));
}

}  // namespace

// static
// TODO(v8:11615): Observe Code::kMaxArguments in CallOrConstructVarargs
void Builtins::Generate_CallOrConstructVarargs(MacroAssembler* masm,
                                               Builtin target_builtin) {
  // ----------- S t a t e -------------
  //  -- r4 : target
  //  -- r3 : number of parameters on the stack
  //  -- r5 : arguments list (a FixedArray)
  //  -- r7 : len (number of elements to push from args)
  //  -- r6 : new.target (for [[Construct]])
  // -----------------------------------

  Register scratch = ip;

  if (v8_flags.debug_code) {
    // Allow r5 to be a FixedArray, or a FixedDoubleArray if r7 == 0.
    Label ok, fail;
    __ AssertNotSmi(r5);
    __ LoadTaggedField(scratch, FieldMemOperand(r5, HeapObject::kMapOffset),
                       r0);
    __ LoadU16(scratch, FieldMemOperand(scratch, Map::kInstanceTypeOffset));
    __ cmpi(scratch, Operand(FIXED_ARRAY_TYPE));
    __ beq(&ok);
    __ cmpi(scratch, Operand(FIXED_DOUBLE_ARRAY_TYPE));
    __ bne(&fail);
    __ cmpi(r7, Operand::Zero());
    __ beq(&ok);
    // Fall through.
    __ bind(&fail);
    __ Abort(AbortReason::kOperandIsNotAFixedArray);

    __ bind(&ok);
  }

  // Check for stack overflow.
  Label stack_overflow;
  __ StackOverflowCheck(r7, scratch, &stack_overflow);

  // Move the arguments already in the stack,
  // including the receiver and the return address.
  // r7: Number of arguments to make room for.
  // r3: Number of arguments already on the stack.
  // r8: Points to first free slot on the stack after arguments were shifted.
  Generate_AllocateSpaceAndShiftExistingArguments(masm, r7, r3, r8, ip, r9);

  // Push arguments onto the stack (thisArgument is already on the stack).
  {
    Label loop, no_args, skip;
    __ cmpi(r7, Operand::Zero());
    __ beq(&no_args);
    __ addi(r5, r5,
            Operand(OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag -
                    kTaggedSize));
    __ mtctr(r7);
    __ bind(&loop);
    __ LoadTaggedField(scratch, MemOperand(r5, kTaggedSize), r0);
    __ addi(r5, r5, Operand(kTaggedSize));
    __ CompareRoot(scratch, RootIndex::kTheHoleValue);
    __ bne(&skip);
    __ LoadRoot(scratch, RootIndex::kUndefinedValue);
    __ bind(&skip);
    __ StoreU64(scratch, MemOperand(r8));
    __ addi(r8, r8, Operand(kSystemPointerSize));
    __ bdnz(&loop);
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
  //  -- r3 : the number of arguments
  //  -- r6 : the new.target (for [[Construct]] calls)
  //  -- r4 : the target to call (can be any Object)
  //  -- r5 : start index (to support rest parameters)
  // -----------------------------------

  Register scratch = r9;

  if (mode == CallOrConstructMode::kConstruct) {
    Label new_target_constructor, new_target_not_constructor;
    __ JumpIfSmi(r6, &new_target_not_constructor);
    __ LoadTaggedField(scratch, FieldMemOperand(r6, HeapObject::kMapOffset),
                       r0);
    __ lbz(scratch, FieldMemOperand(scratch, Map::kBitFieldOffset));
    __ TestBit(scratch, Map::Bits1::IsConstructorBit::kShift, r0);
    __ bne(&new_target_constructor, cr0);
    __ bind(&new_target_not_constructor);
    {
      FrameScope scope(masm, StackFrame::MANUAL);
      __ EnterFrame(StackFrame::INTERNAL);
      __ Push(r6);
      __ CallRuntime(Runtime::kThrowNotConstructor);
      __ Trap();  // Unreachable.
    }
    __ bind(&new_target_constructor);
  }

  Label stack_done, stack_overflow;
  __ LoadU64(r8, MemOperand(fp, StandardFrameConstants::kArgCOffset));
  __ subi(r8, r8, Operand(kJSArgcReceiverSlots));
  __ sub(r8, r8, r5, LeaveOE, SetRC);
  __ ble(&stack_done, cr0);
  {
    // ----------- S t a t e -------------
    //  -- r3 : the number of arguments already in the stack
    //  -- r4 : the target to call (can be any Object)
    //  -- r5 : start index (to support rest parameters)
    //  -- r6 : the new.target (for [[Construct]] calls)
    //  -- fp : point to the caller stack frame
    //  -- r8 : number of arguments to copy, i.e. arguments count - start index
    // -----------------------------------

    // Check for stack overflow.
    __ StackOverflowCheck(r8, scratch, &stack_overflow);

    // Forward the arguments from the caller frame.
    // Point to the first argument to copy (skipping the receiver).
    __ addi(r7, fp,
            Operand(CommonFrameConstants::kFixedFrameSizeAboveFp +
                    kSystemPointerSize));
    __ ShiftLeftU64(scratch, r5, Operand(kSystemPointerSizeLog2));
    __ add(r7, r7, scratch);

    // Move the arguments already in the stack,
    // including the receiver and the return address.
    // r8: Number of arguments to make room for.
    // r3: Number of arguments already on the stack.
    // r5: Points to first free slot on the stack after arguments were shifted.
    Generate_AllocateSpaceAndShiftExistingArguments(masm, r8, r3, r5, scratch,
                                                    ip);

    // Copy arguments from the caller frame.
    // TODO(victorgomes): Consider using forward order as potentially more cache
    // friendly.
    {
      Label loop;
      __ bind(&loop);
      {
        __ subi(r8, r8, Operand(1));
        __ ShiftLeftU64(scratch, r8, Operand(kSystemPointerSizeLog2));
        __ LoadU64(r0, MemOperand(r7, scratch));
        __ StoreU64(r0, MemOperand(r5, scratch));
        __ cmpi(r8, Operand::Zero());
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
  //  -- r3 : the number of arguments
  //  -- r4 : the function to call (checked to be a JSFunction)
  // -----------------------------------
  __ AssertCallableFunction(r4);

  __ LoadTaggedField(
      r5, FieldMemOperand(r4, JSFunction::kSharedFunctionInfoOffset), r0);

  // Enter the context of the function; ToObject has to run in the function
  // context, and we also need to take the global proxy from the function
  // context in case of conversion.
  __ LoadTaggedField(cp, FieldMemOperand(r4, JSFunction::kContextOffset), r0);
  // We need to convert the receiver for non-native sloppy mode functions.
  Label done_convert;
  __ lwz(r6, FieldMemOperand(r5, SharedFunctionInfo::kFlagsOffset));
  __ andi(r0, r6,
          Operand(SharedFunctionInfo::IsStrictBit::kMask |
                  SharedFunctionInfo::IsNativeBit::kMask));
  __ bne(&done_convert, cr0);
  {
    // ----------- S t a t e -------------
    //  -- r3 : the number of arguments
    //  -- r4 : the function to call (checked to be a JSFunction)
    //  -- r5 : the shared function info.
    //  -- cp : the function context.
    // -----------------------------------

    if (mode == ConvertReceiverMode::kNullOrUndefined) {
      // Patch receiver to global proxy.
      __ LoadGlobalProxy(r6);
    } else {
      Label convert_to_object, convert_receiver;
      __ LoadReceiver(r6);
      __ JumpIfSmi(r6, &convert_to_object);
      static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
      __ CompareObjectType(r6, r7, r7, FIRST_JS_RECEIVER_TYPE);
      __ bge(&done_convert);
      if (mode != ConvertReceiverMode::kNotNullOrUndefined) {
        Label convert_global_proxy;
        __ JumpIfRoot(r6, RootIndex::kUndefinedValue, &convert_global_proxy);
        __ JumpIfNotRoot(r6, RootIndex::kNullValue, &convert_to_object);
        __ bind(&convert_global_proxy);
        {
          // Patch receiver to global proxy.
          __ LoadGlobalProxy(r6);
        }
        __ b(&convert_receiver);
      }
      __ bind(&convert_to_object);
      {
        // Convert receiver using ToObject.
        // TODO(bmeurer): Inline the allocation here to avoid building the frame
        // in the fast case? (fall back to AllocateInNewSpace?)
        FrameAndConstantPoolScope scope(masm, StackFrame::INTERNAL);
        __ SmiTag(r3);
        __ Push(r3, r4);
        __ mr(r3, r6);
        __ Push(cp);
        __ CallBuiltin(Builtin::kToObject);
        __ Pop(cp);
        __ mr(r6, r3);
        __ Pop(r3, r4);
        __ SmiUntag(r3);
      }
      __ LoadTaggedField(
          r5, FieldMemOperand(r4, JSFunction::kSharedFunctionInfoOffset), r0);
      __ bind(&convert_receiver);
    }
    __ StoreReceiver(r6);
  }
  __ bind(&done_convert);

  // ----------- S t a t e -------------
  //  -- r3 : the number of arguments
  //  -- r4 : the function to call (checked to be a JSFunction)
  //  -- r5 : the shared function info.
  //  -- cp : the function context.
  // -----------------------------------

  __ LoadU16(
      r5, F
"""


```