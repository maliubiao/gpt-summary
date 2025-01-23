Response: The user has provided a C++ source code file and asked to summarize its functionality. This is the second part of a three-part series. The previous context is unknown, but the code itself provides clues.

The code seems to define built-in functions for the V8 JavaScript engine on the PowerPC architecture. It includes implementations for:

* **Constructor calls**: `Generate_FastConstruct`, `Generate_InterpreterPushArgsThenFastConstructFunction`
* **Interpreter entry**: `Generate_InterpreterEnterBytecode`, `Generate_InterpreterEnterAtNextBytecode`, `Generate_InterpreterEnterAtBytecode`
* **Deoptimization continuation**: `Generate_ContinueToCodeStubBuiltin`, `Generate_ContinueToCodeStubBuiltinWithResult`, `Generate_ContinueToJavaScriptBuiltin`, `Generate_ContinueToJavaScriptBuiltinWithResult`, `Generate_NotifyDeoptimized`
* **On-stack replacement**: `Generate_InterpreterOnStackReplacement`, `Generate_BaselineOnStackReplacement`
* **Function prototype methods**: `Generate_FunctionPrototypeApply`, `Generate_FunctionPrototypeCall`
* **Reflect API methods**: `Generate_ReflectApply`, `Generate_ReflectConstruct`
* **Variable arguments handling**: `Generate_CallOrConstructVarargs`, `Generate_CallOrConstructForwardVarargs`
* **Function calls**: `Generate_CallFunction`, `Generate_CallBoundFunctionImpl`, `Generate_Call`, `Generate_ConstructFunction`, `Generate_ConstructBoundFunction`, `Generate_Construct`
* **WebAssembly (if enabled)**: Several functions related to WASM lifecycle, debugging, and interop.
* **C++ entry points**: `Generate_CEntry`
* **Double to integer conversion**: `Generate_DoubleToI`

Considering this is part 2 of 3, the file likely contains a substantial portion of the built-in functions for the PowerPC architecture. The functions deal with how JavaScript constructs are executed at a low level, including handling arguments, stack frames, and calling conventions.

To illustrate the connection with JavaScript, I will provide examples for a few key functionalities.
这是v8 JavaScript引擎在PowerPC架构下内置函数的C++源代码文件的一部分。它主要负责实现JavaScript中**函数调用**和**构造函数调用**相关的底层操作，以及与**解释器**和**代码优化**相关的支持功能。

具体来说，这部分代码涵盖了以下功能：

**1. 快速构造函数调用 (`Generate_FastConstruct`)：**

这个函数处理使用 `new` 关键字调用构造函数的快速路径。它假设一些前提条件已经满足，从而可以避免一些额外的检查。

**JavaScript 示例：**

```javascript
class MyClass {
  constructor(value) {
    this.value = value;
  }
}

const instance = new MyClass(10); // 这里可能会触发快速构造函数调用
```

**2. 解释器状态下的快速构造函数调用 (`Generate_InterpreterPushArgsThenFastConstructFunction`)：**

当JavaScript代码在解释器中执行时，这个函数处理构造函数的调用。它会设置必要的栈帧，并将参数推入栈中，然后调用底层的构造函数实现。

**JavaScript 示例：**

```javascript
function MyFunction(value) {
  this.value = value;
}

const instance = new MyFunction(20); // 在解释器中执行时会用到这个函数
```

**3. 进入解释器 (`Generate_InterpreterEnterBytecode`, `Generate_InterpreterEnterAtNextBytecode`, `Generate_InterpreterEnterAtBytecode`)：**

这些函数负责进入JavaScript字节码的解释器。它们会设置必要的寄存器和栈帧，指向要执行的字节码指令。

**JavaScript 示例：**

当JavaScript代码首次执行，或者从优化后的代码回退到解释器时，会涉及到这些函数的调用。

```javascript
function add(a, b) {
  return a + b;
}

add(5, 3); // 首次执行可能进入解释器
```

**4. 从代码桩继续执行 (`Generate_ContinueToCodeStubBuiltin`, `Generate_ContinueToCodeStubBuiltinWithResult`, `Generate_ContinueToJavaScriptBuiltin`, `Generate_ContinueToJavaScriptBuiltinWithResult`)：**

当从优化后的代码（代码桩）调用内置函数或JavaScript函数后，需要回到原来的执行流程时，这些函数会被调用。它们负责恢复寄存器状态并跳转到正确的地址。

**JavaScript 示例：**

```javascript
function myFunction() {
  console.log("Hello"); // console.log 是一个内置函数
  return 42;
}

myFunction(); // 执行过程中会调用内置函数，然后通过这些函数继续执行
```

**5. 通知已取消优化 (`Generate_NotifyDeoptimized`)：**

当一段优化后的代码需要回退到解释器执行时，这个函数会被调用。

**JavaScript 示例：**

某些运行时条件可能会导致V8放弃对代码的优化，这时会调用此函数。

```javascript
function potentiallyDeoptimizedFunction(x) {
  if (Math.random() > 0.9) {
    // 某些操作可能触发反优化
    debugger;
  }
  return x * 2;
}
```

**6. 栈上替换 (`Generate_InterpreterOnStackReplacement`, `Generate_BaselineOnStackReplacement`)：**

这些函数用于在代码执行过程中进行优化或反优化，它们可以将解释器栈帧替换为优化后的代码栈帧，反之亦然。

**JavaScript 示例：**

当一段代码执行频率较高，V8会尝试对其进行优化。栈上替换就是实现这种动态优化的机制。

```javascript
function hotFunction(n) {
  let sum = 0;
  for (let i = 0; i < n; i++) {
    sum += i;
  }
  return sum;
}

for (let i = 0; i < 10000; i++) {
  hotFunction(i); // 多次调用后可能触发栈上替换进行优化
}
```

**7. `Function.prototype.apply` 和 `Function.prototype.call` 的实现 (`Generate_FunctionPrototypeApply`, `Generate_FunctionPrototypeCall`)：**

这两个函数实现了JavaScript中 `apply` 和 `call` 方法的底层逻辑，用于改变函数调用时的 `this` 值和传递参数。

**JavaScript 示例：**

```javascript
function greet(greeting) {
  console.log(greeting + ", " + this.name);
}

const person = { name: "Alice" };
greet.apply(person, ["Hello"]); // 调用 Generate_FunctionPrototypeApply
greet.call(person, "Hi");      // 调用 Generate_FunctionPrototypeCall
```

**8. `Reflect.apply` 和 `Reflect.construct` 的实现 (`Generate_ReflectApply`, `Generate_ReflectConstruct`)：**

这些函数实现了 ES6 中 `Reflect` 对象的 `apply` 和 `construct` 方法的底层逻辑，提供了更底层的函数调用和构造函数调用的方式。

**JavaScript 示例：**

```javascript
function sum(a, b) {
  return a + b;
}

const args = [5, 10];
const result = Reflect.apply(sum, null, args); // 调用 Generate_ReflectApply

class Point {
  constructor(x, y) {
    this.x = x;
    this.y = y;
  }
}

const pointArgs = [1, 2];
const point = Reflect.construct(Point, pointArgs); // 调用 Generate_ReflectConstruct
```

**9. 处理可变参数的函数调用和构造函数调用 (`Generate_CallOrConstructVarargs`, `Generate_CallOrConstructForwardVarargs`)：**

这些函数处理带有剩余参数或通过数组展开传递参数的函数调用和构造函数调用。

**JavaScript 示例：**

```javascript
function logAll(first, ...rest) { // 剩余参数
  console.log(first, ...rest);
}
logAll(1, 2, 3); // 调用 Generate_CallOrConstructVarargs 或 Generate_CallOrConstructForwardVarargs

function multiply(a, b, c) {
  return a * b * c;
}
const numbers = [2, 3, 4];
multiply(...numbers); // 调用 Generate_CallOrConstructVarargs 或 Generate_CallOrConstructForwardVarargs
```

**10. 调用函数 (`Generate_CallFunction`)：**

这个函数处理普通的函数调用，它会检查被调用对象的类型，并根据需要转换 `this` 值。

**JavaScript 示例：**

```javascript
function sayHello() {
  console.log("Hello!");
}
sayHello(); // 调用 Generate_CallFunction
```

**11. 调用绑定函数 (`Generate_CallBoundFunctionImpl`)：**

这个函数处理通过 `bind` 方法创建的绑定函数的调用。

**JavaScript 示例：**

```javascript
function originalFunction(arg) {
  console.log(this.value, arg);
}
const boundFunction = originalFunction.bind({ value: 100 }, "boundArg");
boundFunction("callArg"); // 调用 Generate_CallBoundFunctionImpl
```

**12. 通用的调用处理 (`Generate_Call`)：**

这个函数是函数调用的入口点，它会根据被调用对象的类型分发到不同的处理函数，例如 `Generate_CallFunction` 或 `Generate_CallBoundFunctionImpl`。

**JavaScript 示例：**

所有的函数调用最终都会经过这个函数。

**13. 构造函数调用 (`Generate_ConstructFunction`, `Generate_ConstructBoundFunction`, `Generate_Construct`)：**

这些函数处理使用 `new` 关键字调用构造函数的过程，包括分配对象、设置原型链和调用构造函数体。

**JavaScript 示例：**

```javascript
class Car {
  constructor(model) {
    this.model = model;
  }
}
const myCar = new Car("Sedan"); // 调用 Generate_Construct 等相关函数
```

**14. WebAssembly 相关功能 (`Generate_WasmLiftoffFrameSetup`, `Generate_WasmCompileLazy`, 等)：**

如果启用了 WebAssembly，这些函数负责处理 WebAssembly 模块的加载、编译、执行和与其他 JavaScript 代码的交互。

**JavaScript 示例：**

```javascript
// 假设已经加载了一个 WebAssembly 模块
WebAssembly.instantiateStreaming(fetch('module.wasm'))
  .then(result => {
    result.instance.exports.exported_function(); // 可能涉及到 WASM 相关函数的调用
  });
```

**15. C++ 入口点 (`Generate_CEntry`)：**

这个函数定义了从 JavaScript 代码调用 C++ 内置函数的入口点。它负责设置栈帧、传递参数和处理返回值。

**JavaScript 示例：**

当 JavaScript 调用 V8 引擎内部用 C++ 实现的内置函数时，会进入这个函数。例如 `console.log` 的底层实现就可能涉及到 `Generate_CEntry`。

**16. 双精度浮点数转整数 (`Generate_DoubleToI`)：**

这个函数负责将 JavaScript 中的双精度浮点数转换为整数。

**JavaScript 示例：**

```javascript
const floatValue = 3.14;
const intValue = Math.floor(floatValue); // Math.floor 的底层实现可能调用此函数
```

总而言之，这段代码是 V8 引擎在 PowerPC 架构上实现 JavaScript 核心功能的关键部分，它连接了 JavaScript 代码的高层语义和底层机器指令的执行。它展示了 JavaScript 引擎在执行函数和构造函数时所涉及的复杂步骤和优化策略。

### 提示词
```
这是目录为v8/src/builtins/ppc/builtins-ppc.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```
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
      r5, FieldMemOperand(r5, SharedFunctionInfo::kFormalParameterCountOffset));
  __ InvokeFunctionCode(r4, no_reg, r5, r3, InvokeType::kJump);
}

namespace {

void Generate_PushBoundArguments(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r3 : the number of arguments
  //  -- r4 : target (checked to be a JSBoundFunction)
  //  -- r6 : new.target (only in case of [[Construct]])
  // -----------------------------------

  // Load [[BoundArguments]] into r5 and length of that into r7.
  Label no_bound_arguments;
  __ LoadTaggedField(
      r5, FieldMemOperand(r4, JSBoundFunction::kBoundArgumentsOffset), r0);
  __ SmiUntag(r7, FieldMemOperand(r5, offsetof(FixedArray, length_)), SetRC,
              r0);
  __ beq(&no_bound_arguments, cr0);
  {
    // ----------- S t a t e -------------
    //  -- r3 : the number of arguments
    //  -- r4 : target (checked to be a JSBoundFunction)
    //  -- r5 : the [[BoundArguments]] (implemented as FixedArray)
    //  -- r6 : new.target (only in case of [[Construct]])
    //  -- r7 : the number of [[BoundArguments]]
    // -----------------------------------

    Register scratch = r9;
    // Reserve stack space for the [[BoundArguments]].
    {
      Label done;
      __ ShiftLeftU64(r10, r7, Operand(kSystemPointerSizeLog2));
      __ sub(r0, sp, r10);
      // Check the stack for overflow. We are not trying to catch interruptions
      // (i.e. debug break and preemption) here, so check the "real stack
      // limit".
      {
        __ LoadStackLimit(scratch, StackLimitKind::kRealStackLimit, ip);
        __ CmpU64(r0, scratch);
      }
      __ bgt(&done);  // Signed comparison.
      {
        FrameScope scope(masm, StackFrame::MANUAL);
        __ EnterFrame(StackFrame::INTERNAL);
        __ CallRuntime(Runtime::kThrowStackOverflow);
      }
      __ bind(&done);
    }

    // Pop receiver.
    __ Pop(r8);

    // Push [[BoundArguments]].
    {
      Label loop, done;
      __ add(r3, r3, r7);  // Adjust effective number of arguments.
      __ addi(r5, r5,
              Operand(OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag));
      __ mtctr(r7);

      __ bind(&loop);
      __ subi(r7, r7, Operand(1));
      __ ShiftLeftU64(scratch, r7, Operand(kTaggedSizeLog2));
      __ add(scratch, scratch, r5);
      __ LoadTaggedField(scratch, MemOperand(scratch), r0);
      __ Push(scratch);
      __ bdnz(&loop);
      __ bind(&done);
    }

    // Push receiver.
    __ Push(r8);
  }
  __ bind(&no_bound_arguments);
}

}  // namespace

// static
void Builtins::Generate_CallBoundFunctionImpl(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r3 : the number of arguments
  //  -- r4 : the function to call (checked to be a JSBoundFunction)
  // -----------------------------------
  __ AssertBoundFunction(r4);

  // Patch the receiver to [[BoundThis]].
  __ LoadTaggedField(r6, FieldMemOperand(r4, JSBoundFunction::kBoundThisOffset),
                     r0);
  __ StoreReceiver(r6);

  // Push the [[BoundArguments]] onto the stack.
  Generate_PushBoundArguments(masm);

  // Call the [[BoundTargetFunction]] via the Call builtin.
  __ LoadTaggedField(
      r4, FieldMemOperand(r4, JSBoundFunction::kBoundTargetFunctionOffset), r0);
  __ TailCallBuiltin(Builtins::Call());
}

// static
void Builtins::Generate_Call(MacroAssembler* masm, ConvertReceiverMode mode) {
  // ----------- S t a t e -------------
  //  -- r3 : the number of arguments
  //  -- r4 : the target to call (can be any Object).
  // -----------------------------------
  Register target = r4;
  Register map = r7;
  Register instance_type = r8;
  Register scratch = r9;
  DCHECK(!AreAliased(r3, target, map, instance_type));

  Label non_callable, class_constructor;
  __ JumpIfSmi(target, &non_callable);
  __ LoadMap(map, target);
  __ CompareInstanceTypeRange(map, instance_type, scratch,
                              FIRST_CALLABLE_JS_FUNCTION_TYPE,
                              LAST_CALLABLE_JS_FUNCTION_TYPE);
  __ TailCallBuiltin(Builtins::CallFunction(mode), le);
  __ cmpi(instance_type, Operand(JS_BOUND_FUNCTION_TYPE));
  __ TailCallBuiltin(Builtin::kCallBoundFunction, eq);

  // Check if target has a [[Call]] internal method.
  {
    Register flags = r7;
    __ lbz(flags, FieldMemOperand(map, Map::kBitFieldOffset));
    map = no_reg;
    __ TestBit(flags, Map::Bits1::IsCallableBit::kShift, r0);
    __ beq(&non_callable, cr0);
  }

  // Check if target is a proxy and call CallProxy external builtin
  __ cmpi(instance_type, Operand(JS_PROXY_TYPE));
  __ TailCallBuiltin(Builtin::kCallProxy, eq);

  // Check if target is a wrapped function and call CallWrappedFunction external
  // builtin
  __ cmpi(instance_type, Operand(JS_WRAPPED_FUNCTION_TYPE));
  __ TailCallBuiltin(Builtin::kCallWrappedFunction, eq);

  // ES6 section 9.2.1 [[Call]] ( thisArgument, argumentsList)
  // Check that the function is not a "classConstructor".
  __ cmpi(instance_type, Operand(JS_CLASS_CONSTRUCTOR_TYPE));
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
  //  -- r3 : the number of arguments
  //  -- r4 : the constructor to call (checked to be a JSFunction)
  //  -- r6 : the new target (checked to be a constructor)
  // -----------------------------------
  __ AssertConstructor(r4);
  __ AssertFunction(r4);

  // Calling convention for function specific ConstructStubs require
  // r5 to contain either an AllocationSite or undefined.
  __ LoadRoot(r5, RootIndex::kUndefinedValue);

  Label call_generic_stub;

  // Jump to JSBuiltinsConstructStub or JSConstructStubGeneric.
  __ LoadTaggedField(
      r7, FieldMemOperand(r4, JSFunction::kSharedFunctionInfoOffset), r0);
  __ lwz(r7, FieldMemOperand(r7, SharedFunctionInfo::kFlagsOffset));
  __ mov(ip, Operand(SharedFunctionInfo::ConstructAsBuiltinBit::kMask));
  __ and_(r7, r7, ip, SetRC);
  __ beq(&call_generic_stub, cr0);

  __ TailCallBuiltin(Builtin::kJSBuiltinsConstructStub);

  __ bind(&call_generic_stub);
  __ TailCallBuiltin(Builtin::kJSConstructStubGeneric);
}

// static
void Builtins::Generate_ConstructBoundFunction(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r3 : the number of arguments
  //  -- r4 : the function to call (checked to be a JSBoundFunction)
  //  -- r6 : the new target (checked to be a constructor)
  // -----------------------------------
  __ AssertConstructor(r4);
  __ AssertBoundFunction(r4);

  // Push the [[BoundArguments]] onto the stack.
  Generate_PushBoundArguments(masm);

  // Patch new.target to [[BoundTargetFunction]] if new.target equals target.
  Label skip;
  __ CompareTagged(r4, r6);
  __ bne(&skip);
  __ LoadTaggedField(
      r6, FieldMemOperand(r4, JSBoundFunction::kBoundTargetFunctionOffset), r0);
  __ bind(&skip);

  // Construct the [[BoundTargetFunction]] via the Construct builtin.
  __ LoadTaggedField(
      r4, FieldMemOperand(r4, JSBoundFunction::kBoundTargetFunctionOffset), r0);
  __ TailCallBuiltin(Builtin::kConstruct);
}

// static
void Builtins::Generate_Construct(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- r3 : the number of arguments
  //  -- r4 : the constructor to call (can be any Object)
  //  -- r6 : the new target (either the same as the constructor or
  //          the JSFunction on which new was invoked initially)
  // -----------------------------------
  Register target = r4;
  Register map = r7;
  Register instance_type = r8;
  Register scratch = r9;
  DCHECK(!AreAliased(r3, target, map, instance_type, scratch));

  // Check if target is a Smi.
  Label non_constructor, non_proxy;
  __ JumpIfSmi(target, &non_constructor);

  // Check if target has a [[Construct]] internal method.
  __ LoadTaggedField(map, FieldMemOperand(target, HeapObject::kMapOffset), r0);
  {
    Register flags = r5;
    DCHECK(!AreAliased(r3, target, map, instance_type, flags));
    __ lbz(flags, FieldMemOperand(map, Map::kBitFieldOffset));
    __ TestBit(flags, Map::Bits1::IsConstructorBit::kShift, r0);
    __ beq(&non_constructor, cr0);
  }

  // Dispatch based on instance type.
  __ CompareInstanceTypeRange(map, instance_type, scratch,
                              FIRST_JS_FUNCTION_TYPE, LAST_JS_FUNCTION_TYPE);
  __ TailCallBuiltin(Builtin::kConstructFunction, le);

  // Only dispatch to bound functions after checking whether they are
  // constructors.
  __ cmpi(instance_type, Operand(JS_BOUND_FUNCTION_TYPE));
  __ TailCallBuiltin(Builtin::kConstructBoundFunction, eq);

  // Only dispatch to proxies after checking whether they are constructors.
  __ cmpi(instance_type, Operand(JS_PROXY_TYPE));
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
    CHECK_EQ(simd_regs.Count(), arraysize(wasm::kFpParamRegisters));
    CHECK_EQ(WasmLiftoffSetupFrameConstants::kNumberOfSavedGpParamRegs + 1,
             gp_regs.Count());
    CHECK_EQ(WasmLiftoffSetupFrameConstants::kNumberOfSavedFpParamRegs,
             fp_regs.Count());
    CHECK_EQ(WasmLiftoffSetupFrameConstants::kNumberOfSavedFpParamRegs,
             simd_regs.Count());

    __ MultiPush(gp_regs);
    __ MultiPushF64AndV128(fp_regs, simd_regs, ip, r0);
  }
  ~SaveWasmParamsScope() {
    __ MultiPopF64AndV128(fp_regs, simd_regs, ip, r0);
    __ MultiPop(gp_regs);
  }

  RegList gp_regs;
  DoubleRegList fp_regs;
  // List must match register numbers under kFpParamRegisters.
  Simd128RegList simd_regs = {v1, v2, v3, v4, v5, v6, v7, v8};
  MacroAssembler* masm;
};

void Builtins::Generate_WasmLiftoffFrameSetup(MacroAssembler* masm) {
  Register func_index = wasm::kLiftoffFrameSetupFunctionReg;
  Register vector = r11;
  Register scratch = ip;
  Label allocate_vector, done;

  __ LoadTaggedField(
      vector,
      FieldMemOperand(kWasmImplicitArgRegister,
                      WasmTrustedInstanceData::kFeedbackVectorsOffset),
      scratch);
  __ ShiftLeftU64(scratch, func_index, Operand(kTaggedSizeLog2));
  __ AddS64(vector, vector, scratch);
  __ LoadTaggedField(vector,
                     FieldMemOperand(vector, OFFSET_OF_DATA_START(FixedArray)),
                     scratch);
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
  __ mflr(scratch);
  __ push(scratch);
  {
    SaveWasmParamsScope save_params(masm);  // Will use r0 and ip as scratch.
    // Arguments to the runtime function: instance data, func_index.
    __ push(kWasmImplicitArgRegister);
    __ SmiTag(func_index);
    __ push(func_index);
    // Allocate a stack slot where the runtime function can spill a pointer
    // to the {NativeModule}.
    __ push(r11);
    __ LoadSmiLiteral(cp, Smi::zero());
    __ CallRuntime(Runtime::kWasmAllocateFeedbackVector, 3);
    __ mr(vector, kReturnRegister0);
    // Saved parameters are restored at the end of this block.
  }
  __ pop(scratch);
  __ mtlr(scratch);

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
      SaveWasmParamsScope save_params(masm);  // Will use r0 and ip as scratch.

      // Push the instance data as an explicit argument to the runtime function.
      __ push(kWasmImplicitArgRegister);
      // Push the function index as second argument.
      __ push(kWasmCompileLazyFuncIndexRegister);
      // Initialize the JavaScript context with 0. CEntry will use it to
      // set the current context on the isolate.
      __ LoadSmiLiteral(cp, Smi::zero());
      __ CallRuntime(Runtime::kWasmCompileLazy, 2);
      // The runtime function returns the jump table slot offset as a Smi. Use
      // that to compute the jump target in r11.
      __ SmiUntag(kReturnRegister0);
      __ mr(r11, kReturnRegister0);

      // Saved parameters are restored at the end of this block.
    }

    // After the instance data register has been restored, we can add the jump
    // table start to the jump table offset already stored in r11.
    __ LoadU64(ip,
               FieldMemOperand(kWasmImplicitArgRegister,
                               WasmTrustedInstanceData::kJumpTableStartOffset),
               r0);
    __ AddS64(r11, r11, ip);
  }

  // Finally, jump to the jump table slot for the function.
  __ Jump(r11);
}

void Builtins::Generate_WasmDebugBreak(MacroAssembler* masm) {
  HardAbortScope hard_abort(masm);  // Avoid calls to Abort.
  {
    FrameAndConstantPoolScope scope(masm, StackFrame::WASM_DEBUG_BREAK);

    // Save all parameter registers. They might hold live values, we restore
    // them after the runtime call.
    __ MultiPush(WasmDebugBreakFrameConstants::kPushedGpRegs);
    __ MultiPushF64AndV128(WasmDebugBreakFrameConstants::kPushedFpRegs,
                           WasmDebugBreakFrameConstants::kPushedSimd128Regs, ip,
                           r0);

    // Initialize the JavaScript context with 0. CEntry will use it to
    // set the current context on the isolate.
    __ LoadSmiLiteral(cp, Smi::zero());
    __ CallRuntime(Runtime::kWasmDebugBreak, 0);

    // Restore registers.
    __ MultiPopF64AndV128(WasmDebugBreakFrameConstants::kPushedFpRegs,
                          WasmDebugBreakFrameConstants::kPushedSimd128Regs, ip,
                          r0);
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
  __ LoadTaggedField(scratch, FieldMemOperand(data, HeapObject::kMapOffset),
                     r0);
  __ CompareInstanceType(scratch, scratch, WASM_TRUSTED_INSTANCE_DATA_TYPE);
  Label instance;
  Label end;
  __ beq(&instance);
  __ LoadTaggedField(
      data, FieldMemOperand(data, WasmImportData::kNativeContextOffset), r0);
  __ jmp(&end);
  __ bind(&instance);
  __ LoadTaggedField(
      data,
      FieldMemOperand(data, WasmTrustedInstanceData::kNativeContextOffset), r0);
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
  __ Push(r3);
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
  Register zero = r3;
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

  Register result_size = r3;
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
  Register params_end = r4;
  __ LoadU64(params_end,
             MemOperand(wrapper_buffer,
                        JSToWasmWrapperFrameConstants::kWrapperBufferParamEnd),
             r0);

  Register params_start = ip;
  __ LoadU64(
      params_start,
      MemOperand(wrapper_buffer,
                 JSToWasmWrapperFrameConstants::kWrapperBufferParamStart),
      r0);

  // The first GP parameter holds the trusted instance data or the import data.
  // This is handled specially.
  int stack_params_offset =
      (arraysize(wasm::kGpParamRegisters) - 1) * kSystemPointerSize +
      arraysize(wasm::kFpParamRegisters) * kDoubleSize;
  Register last_stack_param = r3;
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
    __ LoadU64(r0, MemOperand(params_end), r0);
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
               MemOperand(params_start, next_offset), r0);
    next_offset += kSystemPointerSize;
  }

  for (size_t i = 0; i < arraysize(wasm::kFpParamRegisters); ++i) {
    __ LoadF64(wasm::kFpParamRegisters[i],
               MemOperand(params_start, next_offset), r0);
    next_offset += kDoubleSize;
  }
  DCHECK_EQ(next_offset, stack_params_offset);

  // Load the instance data (implicit arg) into r6.
  __ LoadU64(kWasmImplicitArgRegister,
             MemOperand(fp, JSToWasmWrapperFrameConstants::kImplicitArgOffset),
             r0);

  {
    Register thread_in_wasm_flag_addr = r4;
    __ LoadU64(thread_in_wasm_flag_addr,
               MemOperand(kRootRegister,
                          Isolate::thread_in_wasm_flag_address_offset()),
               r0);
    __ mov(r0, Operand(1));
    __ StoreU32(r0, MemOperand(thread_in_wasm_flag_addr, 0), no_reg);
  }

  Register function_entry = r4;
  __ LoadU64(
      function_entry,
      MemOperand(wrapper_buffer,
                 JSToWasmWrapperFrameConstants::kWrapperBufferCallTarget),
      r0);
  __ Call(function_entry);
  {
    Register thread_in_wasm_flag_addr = r7;
    __ LoadU64(thread_in_wasm_flag_addr,
               MemOperand(kRootRegister,
                          Isolate::thread_in_wasm_flag_address_offset()),
               r0);
    __ mov(r0, Operand(0));
    __ StoreU32(r0, MemOperand(thread_in_wasm_flag_addr, 0), no_reg);
  }

  // `wrapper_buffer` is a parameter for `JSToWasmHandleReturns`, it therefore
  // has to be in r5.
  wrapper_buffer = r5;
  __ LoadU64(
      wrapper_buffer,
      MemOperand(fp, JSToWasmWrapperFrameConstants::kWrapperBufferOffset), r0);

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

  // r3: wasm instance.
  // r4: the result JSArray for multi-return.
  // r5: pointer to the byte buffer which contains all parameters.
  __ LoadU64(
      r4,
      MemOperand(fp, JSToWasmWrapperFrameConstants::kResultArrayParamOffset),
      r0);
  __ LoadU64(r3,
             MemOperand(fp, JSToWasmWrapperFrameConstants::kImplicitArgOffset),
             r0);
  Register scratch = r6;
  GetContextFromImplicitArg(masm, r3, scratch);

  __ CallBuiltin(Builtin::kJSToWasmHandleReturns);

  __ LeaveFrame(StackFrame::JS_TO_WASM);
  __ AddS64(sp, sp, Operand(2 * kSystemPointerSize));
  __ blr();
}

#endif  // V8_ENABLE_WEBASSEMBLY

void Builtins::Generate_CEntry(MacroAssembler* masm, int result_size,
                               ArgvMode argv_mode, bool builtin_exit_frame,
                               bool switch_to_central_stack) {
  // Called from JavaScript; parameters are on stack as if calling JS function.
  // r3: number of arguments including receiver
  // r4: pointer to builtin function
  // fp: frame pointer  (restored after C call)
  // sp: stack pointer  (restored as callee's sp after C call)
  // cp: current context  (C callee-saved)
  //
  // If argv_mode == ArgvMode::kRegister:
  // r5: pointer to the first argument

  using ER = ExternalReference;

  // Move input arguments to more convenient registers.
  static constexpr Register argc_input = r3;
  static constexpr Register target_fun = r15;  // C callee-saved
  static constexpr Register argv = r4;
  static constexpr Register scratch = ip;
  static constexpr Register argc_sav = r14;  // C callee-saved

  __ mr(target_fun, argv);

  if (argv_mode == ArgvMode::kRegister) {
    // Move argv into the correct register.
    __ mr(argv, r5);
  } else {
    // Compute the argv pointer.
    __ ShiftLeftU64(argv, argc_input, Operand(kSystemPointerSizeLog2));
    __ add(argv, argv, sp);
    __ subi(argv, argv, Operand(kSystemPointerSize));
  }

  // Enter the exit frame that transitions from JavaScript to C++.
  FrameScope scope(masm, StackFrame::MANUAL);

  int arg_stack_space = 0;

  // Pass buffer for return value on stack if necessary
  bool needs_return_buffer =
      (result_size == 2 && !ABI_RETURNS_OBJECT_PAIRS_IN_REGS);
  if (needs_return_buffer) {
    arg_stack_space += result_size;
  }

  __ EnterExitFrame(
      scratch, arg_stack_space,
      builtin_exit_frame ? StackFrame::BUILTIN_EXIT : StackFrame::EXIT);

  // Store a copy of argc in callee-saved registers for later.
  __ mr(argc_sav, argc_input);

  // r3: number of arguments including receiver
  // r14: number of arguments including receiver (C callee-saved)
  // r4: pointer to the first argument
  // r15: pointer to builtin function  (C callee-saved)

  // Result returned in registers or stack, depending on result size and ABI.

  Register isolate_reg = r5;
  if (needs_return_buffer) {
    // The return value is a non-scalar value.
    // Use frame storage reserved by calling function to pass return
    // buffer as implicit first argument.
    __ mr(r5, r4);
    __ mr(r4, r3);
    __ addi(r3, sp,
            Operand((kStackFrameExtraParamSlot + 1) * kSystemPointerSize));
    isolate_reg = r6;
  }

  // Call C built-in.
  __ Move(isolate_reg, ER::isolate_address());
  __ StoreReturnAddressAndCall(target_fun);

  // If return value is on the stack, pop it to registers.
  if (needs_return_buffer) {
    __ LoadU64(r4, MemOperand(r3, kSystemPointerSize));
    __ LoadU64(r3, MemOperand(r3));
  }

  // Check result for exception sentinel.
  Label exception_returned;
  __ CompareRoot(r3, RootIndex::kException);
  __ beq(&exception_returned);

  // Check that there is no exception, otherwise we
  // should have returned the exception sentinel.
  if (v8_flags.debug_code) {
    Label okay;
    ER exception_address =
        ER::Create(IsolateAddressId::kExceptionAddress, masm->isolate());
    __ LoadU64(scratch,
               __ ExternalReferenceAsOperand(exception_address, no_reg));
    __ LoadRoot(r0, RootIndex::kTheHoleValue);
    __ CompareTagged(r0, scratch);
    // Cannot use check here as it attempts to generate call into runtime.
    __ beq(&okay);
    __ stop();
    __ bind(&okay);
  }

  // Exit C frame and return.
  // r3:r4: result
  // sp: stack pointer
  // fp: frame pointer
  // r14: still holds argc (C caller-saved).
  __ LeaveExitFrame(scratch);
  if (argv_mode == ArgvMode::kStack) {
    DCHECK(!AreAliased(scratch, argc_sav));
    __ ShiftLeftU64(scratch, argc_sav, Operand(kSystemPointerSizeLog2));
    __ AddS64(sp, sp, scratch);
  }

  __ blr();

  // Handling of exception.
  __ bind(&exception_returned);

  ER pending_handler_context_address = ER::Create(
      IsolateAddressId::kPendingHandlerContextAddress, masm->isolate());
  ER pending_handler_entrypoint_address = ER::Create(
      IsolateAddressId::kPendingHandlerEntrypointAddress, masm->isolate());
  ER pending_handler_constant_pool_address = ER::Create(
      IsolateAddressId::kPendingHandlerConstantPoolAddress, masm->isolate());
  ER pending_handler_fp_address =
      ER::Create(IsolateAddressId::kPendingHandlerFPAddress, masm->isolate());
  ER pending_handler_sp_address =
      ER::Create(IsolateAddressId::kPendingHandlerSPAddress, masm->isolate());

  // Ask the runtime for help to determine the handler. This will set r3 to
  // contain the current exception, don't clobber it.
  {
    FrameScope scope(masm, StackFrame::MANUAL);
    __ PrepareCallCFunction(3, 0, r3);
    __ li(kCArgRegs[0], Operand::Zero());
    __ li(kCArgRegs[1], Operand::Zero());
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
  __ cmpi(cp, Operand::Zero());
  __ beq(&skip);
  __ StoreU64(cp, MemOperand(fp, StandardFrameConstants::kContextOffset));
  __ bind(&skip);

  // Clear c_entry_fp, like we do in `LeaveExitFrame`.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, masm->isolate());
  __ mov(scratch, Operand::Zero());
  __ StoreU64(scratch,
              __ ExternalReferenceAsOperand(c_entry_fp_address, no_reg));

  // Compute the handler entry address and jump to it.
  ConstantPoolUnavailableScope constant_pool_unavailable(masm);
  __ LoadU64(
      scratch,
      __ ExternalReferenceAsOperand(pending_handler_entrypoint_address, no_reg),
      r0);
  if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
    __ Move(kConstantPoolRegister, pending_handler_constant_pool_address);
    __ LoadU64(kConstantPoolRegister, MemOperand(kConstantPoolRegister));
  }
  __ Jump(scratch);
}

#if V8_ENABLE_WEBASSEMBLY
void Builtins::Generate_WasmHandleStackOverflow(MacroAssembler* masm) {
  __ Trap();
}
#endif  // V8_ENABLE_WEBASSEMBLY

void Builtins::Generate_DoubleToI(MacroAssembler* masm) {
  Label out_of_range, only_low, negate, done, fastpath_done;
  Register result_reg = r3;

  HardAbortScope hard_abort(masm);  // Avoid calls to Abort.

  // Immediate values for this stub fit in instructions, so it's safe to use ip.
  Register scratch = GetRegisterThatIsNotOneOf(result_reg);
  Register scratch_low = GetRegisterThatIsNotOneOf(result_reg, scratch);
  Register scratch_high =
      GetRegisterThatIsNotOneOf(result_reg, scratch, scratch_low);
  DoubleRegister double_scratch = kScratchDoubleReg;

  __ Push(result_reg, scratch);
  // Account for saved regs.
  int argument_offset = 2 * kSystemPointerSize;

  // Load double input.
  __ lfd(double_scratch, MemOperand(sp, argument_offset));

  // Do fast-path convert from double to int.
  __ ConvertDoubleToInt64(double_scratch,
                          result_reg, d0);

// Test for overflow
  __ TestIfInt32(result_reg, r0);
  __ beq(&fastpath_done);

  __ Push(scratch_high, scratch_low);
  // Account for saved regs.
  argument_offset += 2 * kSystemPointerSize;

  __ lwz(scratch_high,
         MemOperand(sp, argument_offset + Register::kExponentOffset));
  __ lwz(scratch_low,
         MemOperand(sp, argument_offset + Register::kMantissaOffset));

  __ ExtractBitMask(scratch, scratch_high, HeapNumber::kExponentMask);
  // Load scratch with exponent - 1. This is faster than loading
  // with exponent because Bias + 1 = 1024 which is a *PPC* immediate value.
  static_assert(HeapNumber::kExponentBias + 1 == 1024);
  __ subi(scratch, scratch, Operand(HeapNumber::kExponentBias + 1));
  // If exponent is greater than or equal to 84, the 32 less significant
  // bits are 0s (2^84 = 1, 52 significant
```