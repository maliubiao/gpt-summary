Response:
The user wants a summary of the functionality of the provided C++ code snippet.

Here's a plan to break down the task:

1. **Identify the file's purpose:** Based on the directory `v8/src/builtins/riscv/`, the file likely contains built-in functions specifically for the RISC-V architecture. The `builtins-riscv.cc` naming convention reinforces this.

2. **Analyze includes:** The included header files hint at the functionalities within. Look for keywords like "builtins", "codegen", "debug", "deoptimizer", "execution", "logging", "heap", "objects", "runtime", and "wasm".

3. **Examine defined functions and macros:** Pay attention to functions like `Generate_Adaptor`, `Generate_PushArguments`, `Generate_JSBuiltinsConstructStubHelper`, `Generate_JSConstructStubGeneric`, `Generate_ResumeGeneratorTrampoline`, `Generate_JSEntry`, and related trampoline functions. The presence of `ASM_CODE_COMMENT` suggests assembly code generation.

4. **Infer functionality from the code:** Analyze the assembly code generated within each function. Look for patterns like stack manipulation, function calls (especially to `CallBuiltin` and `CallRuntime`), object creation, and checks (like stack overflow checks).

5. **Address specific questions:**
    * **`.tq` extension:** The code is `.cc`, so it's not a Torque file.
    * **JavaScript relation:**  The code implements low-level functionalities that underpin JavaScript execution, such as function calls, object construction, and generator handling. Provide JavaScript examples that would trigger these underlying mechanisms.
    * **Code logic inference:**  For functions with clear logic (like `Generate_PushArguments`), infer the input and output.
    * **Common programming errors:** Think about errors related to function calls, incorrect arguments, or stack overflow, and connect them to the code's checks.

6. **Summarize the overall functionality:** Based on the analysis, provide a concise summary of what the code does.

**Constraint Checklist & Confidence Score:**

* Provide a list of functions: Yes.
* Explain functionality: Yes.
* Check for `.tq` extension: Yes.
* Explain JavaScript relation: Yes.
* Provide JavaScript examples: Yes.
* Code logic inference: Yes.
* Assume input/output: Yes.
* Common programming errors: Yes.
* Example of errors: Yes.
* Part 1 of 6: Yes.
* Summarize functionality: Yes.

Confidence Score: 5/5

**Mental Sandbox Simulation:**

I can imagine going through the code section by section. For example, `Generate_Adaptor` seems to be a simple function that sets up a call to another builtin. `Generate_PushArguments` clearly pushes arguments onto the stack. The `Generate_JSConstructStubGeneric` function looks complex and handles object construction, including handling derived class constructors and stack overflow checks. The generator trampoline function manages the state of generator objects. The `JSEntry` family of functions handles the entry and exit points for JavaScript calls. The inclusion of WASM related headers suggests the code might also be involved in WebAssembly integration.

Strategizing complete. I will now generate the response following these steps.
好的，让我们来分析一下 `v8/src/builtins/riscv/builtins-riscv.cc` 这个文件的功能。

**文件功能归纳:**

`v8/src/builtins/riscv/builtins-riscv.cc` 文件是 V8 JavaScript 引擎中针对 RISC-V 架构的内置函数实现。它包含了用汇编语言编写的关键代码片段，用于高效地执行 JavaScript 的底层操作。

**具体功能列举:**

1. **`Generate_Adaptor`**:  生成一个适配器函数。这个适配器函数会将一个 C++ 函数地址作为参数传递，并最终调用 `Builtins::AdaptorWithBuiltinExitFrame`。这通常用于连接 JavaScript 代码和底层的 C++ 代码实现。

2. **`Generate_PushArguments`**: 生成用于将参数压入堆栈的代码。它从一个数组中读取参数，并根据 `ArgumentsElementType` 决定是否需要解引用（对于 `kHandle` 类型）。

3. **`Generate_JSBuiltinsConstructStubHelper`**: 生成用于辅助执行内置构造函数的桩代码。它会设置构造函数调用的栈帧，并将参数压入堆栈，然后调用构造函数。

4. **`Generate_JSConstructStubGeneric`**: 生成用于 ES5 构造函数和 ES6 类构造函数的通用构造桩代码。它处理对象实例化、调用构造函数以及处理构造函数的返回值。

5. **`Builtins::Generate_JSConstructStub`**:  调用 `Generate_JSBuiltinsConstructStubHelper`，是内置构造桩的入口点。

6. **`GetSharedFunctionInfoBytecodeOrBaseline`**:  获取 `SharedFunctionInfo` 关联的字节码数组或基线代码。这用于确定函数应该如何被执行（解释执行或基线编译执行）。

7. **`Builtins::Generate_ResumeGeneratorTrampoline`**: 生成用于恢复生成器对象的入口代码。它负责将输入值存储到生成器对象中，加载生成器的上下文和函数，并将参数压入堆栈，然后跳转到生成器函数的执行入口。

8. **`Builtins::Generate_ConstructedNonConstructable`**: 生成当尝试构造一个不可构造的对象时抛出错误的代码。

9. **`Generate_CheckStackOverflow`**: 生成用于检查堆栈溢出的代码。

10. **`Generate_JSEntryVariant`**: 生成 JavaScript 进入 V8 引擎的入口变体。它会设置入口栈帧，处理异常，并调用 JavaScript 代码。

11. **`Builtins::Generate_JSEntry`**:  生成标准的 JavaScript 进入 V8 引擎的入口点。

12. **`Builtins::Generate_JSConstructEntry`**: 生成用于构造函数调用的 JavaScript 进入 V8 引擎的入口点。

13. **`Builtins::Generate_JSRunMicrotasksEntry`**: 生成用于运行微任务的入口点。

14. **`Generate_JSEntryTrampolineHelper`**: 生成 `JSEntry` 和 `JSConstructEntry` 的辅助入口跳转代码，负责设置上下文、压入参数并调用相应的内置函数。

15. **`Builtins::Generate_JSEntryTrampoline`**: 生成标准的 JavaScript 进入跳转代码。

16. **`Builtins::Generate_JSConstructEntryTrampoline`**: 生成用于构造函数调用的 JavaScript 进入跳转代码。

17. **`Builtins::Generate_RunMicrotasksTrampoline`**: 生成运行微任务的跳转代码。

18. **`LeaveInterpreterFrame`**: 生成用于离开解释器栈帧的代码。

19. **`AdvanceBytecodeOffsetOrReturn`**: 生成用于推进字节码偏移量或返回的代码，模拟字节码处理器的行为。

**关于文件类型和 JavaScript 关系:**

*   **文件类型:** `v8/src/builtins/riscv/builtins-riscv.cc` 以 `.cc` 结尾，所以它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件（Torque 文件以 `.tq` 结尾）。

*   **JavaScript 关系:** 这个文件中的代码直接关系到 JavaScript 的执行。它实现了 JavaScript 引擎的底层机制，例如：
    *   **函数调用:**  `Generate_Adaptor` 和 `Generate_JSEntry` 系列函数负责 JavaScript 函数的调用和入口。
    *   **对象构造:** `Generate_JSConstructStubGeneric` 负责 JavaScript 对象的构造过程。
    *   **生成器:** `Builtins::Generate_ResumeGeneratorTrampoline` 处理 JavaScript 生成器的恢复执行。
    *   **错误处理:** `Builtins::Generate_ConstructedNonConstructable` 在尝试构造不可构造的对象时抛出错误。
    *   **堆栈管理:** `Generate_PushArguments` 和 `Generate_CheckStackOverflow` 涉及 JavaScript 执行时的堆栈操作。

**JavaScript 示例:**

以下 JavaScript 例子可能会触发 `v8/src/builtins/riscv/builtins-riscv.cc` 中的部分代码：

```javascript
// 触发 Generate_JSConstructStubGeneric (对象构造)
function MyClass(arg) {
  this.value = arg;
}
const instance = new MyClass(10);

// 触发 Builtins::Generate_ResumeGeneratorTrampoline (生成器)
function* myGenerator() {
  yield 1;
  yield 2;
}
const generator = myGenerator();
generator.next();
generator.next();

// 触发 Builtins::Generate_ConstructedNonConstructable (构造不可构造的对象)
const symbol = Symbol();
try {
  new symbol(); // TypeError: Symbol is not a constructor
} catch (e) {
  console.error(e);
}

// 触发函数调用相关的 builtins (例如 Generate_JSEntry)
function normalFunction(a, b) {
  return a + b;
}
normalFunction(5, 3);
```

**代码逻辑推理 (以 `Generate_PushArguments` 为例):**

**假设输入:**

*   `array`: 寄存器指向一个包含参数的数组的起始地址。
*   `argc`: 寄存器包含参数的个数（包括接收者）。
*   `scratch`, `scratch2`:  可用作临时寄存器。
*   `element_type`:  `ArgumentsElementType::kRaw` 或 `ArgumentsElementType::kHandle`。

**输出:**

*   将 `argc - 1` 个参数（排除接收者）从 `array` 指向的位置压入堆栈。
*   如果 `element_type` 是 `kHandle`，则在压入堆栈之前会先解引用数组中的每个元素。

**逻辑:**

1. 计算需要压入的参数个数： `argc - kJSArgcReceiverSlots` (通常 `kJSArgcReceiverSlots` 为 1，表示接收者)。
2. 循环遍历参数数组，从后往前压入堆栈。
3. 如果 `element_type` 是 `kHandle`，则先从数组中加载参数的地址，然后再加载该地址指向的值，最后压入堆栈。否则，直接加载数组中的值并压入堆栈。

**用户常见的编程错误示例:**

*   **堆栈溢出:**  如果 JavaScript 代码传递了非常多的参数给一个函数，可能会导致堆栈溢出。`Generate_CheckStackOverflow` 尝试在底层检测并处理这种情况，防止程序崩溃。

    ```javascript
    function recursiveFunction(n) {
      if (n <= 0) {
        return;
      }
      recursiveFunction(n - 1, new Array(10000).fill(0)); // 传递大量参数或局部变量
    }
    try {
      recursiveFunction(1000); // 可能导致堆栈溢出
    } catch (e) {
      console.error(e); // 可能会捕获到 RangeError: Maximum call stack size exceeded
    }
    ```

*   **尝试构造不可构造的对象:**  用户可能会尝试使用 `new` 关键字调用像 `Symbol` 或 `Math` 这样的内置对象，这些对象不是构造函数。`Builtins::Generate_ConstructedNonConstructable` 就是处理这种情况并抛出 `TypeError` 的。

    ```javascript
    try {
      new Math(); // TypeError: Math is not a constructor
    } catch (e) {
      console.error(e);
    }
    ```

总结一下，`v8/src/builtins/riscv/builtins-riscv.cc` 是 V8 引擎中至关重要的底层代码，它使用汇编语言为 RISC-V 架构实现了核心的 JavaScript 执行机制，包括函数调用、对象构造、生成器处理、堆栈管理和错误处理等。它直接支撑着 JavaScript 代码的运行。

Prompt: 
```
这是目录为v8/src/builtins/riscv/builtins-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/riscv/builtins-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/api/api-arguments.h"
#include "src/builtins/builtins-descriptors.h"
#include "src/builtins/builtins-inl.h"
#include "src/codegen/code-factory.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/debug/debug.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/frame-constants.h"
#include "src/execution/frames.h"
#include "src/logging/counters.h"
// For interpreter_entry_return_pc_offset. TODO(jkummerow): Drop.
#include "src/codegen/macro-assembler-inl.h"
#include "src/codegen/register-configuration.h"
#include "src/heap/heap-inl.h"
#include "src/objects/cell.h"
#include "src/objects/foreign.h"
#include "src/objects/heap-number.h"
#include "src/objects/js-generator.h"
#include "src/objects/objects-inl.h"
#include "src/objects/smi.h"
#include "src/runtime/runtime.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/baseline/liftoff-assembler-defs.h"
#include "src/wasm/object-access.h"
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-objects.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {

#define __ ACCESS_MASM(masm)

void Builtins::Generate_Adaptor(MacroAssembler* masm,
                                int formal_parameter_count, Address address) {
  ASM_CODE_COMMENT(masm);
  __ li(kJavaScriptCallExtraArg1Register, ExternalReference::Create(address));
  __ TailCallBuiltin(
      Builtins::AdaptorWithBuiltinExitFrame(formal_parameter_count));
}

namespace {

enum class ArgumentsElementType {
  kRaw,    // Push arguments as they are.
  kHandle  // Dereference arguments before pushing.
};

void Generate_PushArguments(MacroAssembler* masm, Register array, Register argc,
                            Register scratch, Register scratch2,
                            ArgumentsElementType element_type) {
  ASM_CODE_COMMENT(masm);
  DCHECK(!AreAliased(array, argc, scratch));
  Label loop, entry;
  __ SubWord(scratch, argc, Operand(kJSArgcReceiverSlots));
  __ Branch(&entry);
  __ bind(&loop);
  __ CalcScaledAddress(scratch2, array, scratch, kSystemPointerSizeLog2);
  __ LoadWord(scratch2, MemOperand(scratch2));
  if (element_type == ArgumentsElementType::kHandle) {
    __ LoadWord(scratch2, MemOperand(scratch2));
  }
  __ push(scratch2);
  __ bind(&entry);
  __ AddWord(scratch, scratch, Operand(-1));
  __ Branch(&loop, greater_equal, scratch, Operand(zero_reg));
}

void Generate_JSBuiltinsConstructStubHelper(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- a0     : number of arguments
  //  -- a1     : constructor function
  //  -- a3     : new target
  //  -- cp     : context
  //  -- ra     : return address
  //  -- sp[...]: constructor arguments
  // -----------------------------------

  // Enter a construct frame.
  {
    FrameScope scope(masm, StackFrame::CONSTRUCT);

    // Preserve the incoming parameters on the stack.
    __ Push(cp, a0);

    // Set up pointer to first argument (skip receiver).
    __ AddWord(
        t2, fp,
        Operand(StandardFrameConstants::kCallerSPOffset + kSystemPointerSize));
    // t2: Pointer to start of arguments.
    // a0: Number of arguments.
    {
      UseScratchRegisterScope temps(masm);
      temps.Include(t0);
      Generate_PushArguments(masm, t2, a0, temps.Acquire(), temps.Acquire(),
                             ArgumentsElementType::kRaw);
    }
    // The receiver for the builtin/api call.
    __ PushRoot(RootIndex::kTheHoleValue);

    // Call the function.
    // a0: number of arguments (untagged)
    // a1: constructor function
    // a3: new target
    __ InvokeFunctionWithNewTarget(a1, a3, a0, InvokeType::kCall);

    // Restore context from the frame.
    __ LoadWord(cp, MemOperand(fp, ConstructFrameConstants::kContextOffset));
    // Restore arguments count from the frame.
    __ LoadWord(kScratchReg,
                MemOperand(fp, ConstructFrameConstants::kLengthOffset));
    // Leave construct frame.
  }

  // Remove caller arguments from the stack and return.
  __ DropArguments(kScratchReg);
  __ Ret();
}

}  // namespace

// The construct stub for ES5 constructor functions and ES6 class constructors.
void Builtins::Generate_JSConstructStubGeneric(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  --      a0: number of arguments (untagged)
  //  --      a1: constructor function
  //  --      a3: new target
  //  --      cp: context
  //  --      ra: return address
  //  -- sp[...]: constructor arguments
  // -----------------------------------
  UseScratchRegisterScope temps(masm);
  temps.Include(t0, t1);
  // Enter a construct frame.
  FrameScope scope(masm, StackFrame::MANUAL);
  Label post_instantiation_deopt_entry, not_create_implicit_receiver;
  __ EnterFrame(StackFrame::CONSTRUCT);

  // Preserve the incoming parameters on the stack.
  __ Push(cp, a0, a1);
  __ PushRoot(RootIndex::kUndefinedValue);
  __ Push(a3);

  // ----------- S t a t e -------------
  //  --        sp[0*kSystemPointerSize]: new target
  //  --        sp[1*kSystemPointerSize]: padding
  //  -- a1 and sp[2*kSystemPointerSize]: constructor function
  //  --        sp[3*kSystemPointerSize]: number of arguments
  //  --        sp[4*kSystemPointerSize]: context
  // -----------------------------------
  {
    UseScratchRegisterScope temps(masm);
    Register func_info = temps.Acquire();
    __ LoadTaggedField(
        func_info, FieldMemOperand(a1, JSFunction::kSharedFunctionInfoOffset));
    __ Load32U(func_info,
               FieldMemOperand(func_info, SharedFunctionInfo::kFlagsOffset));
    __ DecodeField<SharedFunctionInfo::FunctionKindBits>(func_info);
    __ JumpIfIsInRange(
        func_info,
        static_cast<uint32_t>(FunctionKind::kDefaultDerivedConstructor),
        static_cast<uint32_t>(FunctionKind::kDerivedConstructor),
        &not_create_implicit_receiver);
    // If not derived class constructor: Allocate the new receiver object.
    __ CallBuiltin(Builtin::kFastNewObject);
    __ BranchShort(&post_instantiation_deopt_entry);

    // Else: use TheHoleValue as receiver for constructor call
    __ bind(&not_create_implicit_receiver);
    __ LoadRoot(a0, RootIndex::kTheHoleValue);
  }
  // ----------- S t a t e -------------
  //  --                          a0: receiver
  //  -- Slot 4 / sp[0*kSystemPointerSize]: new target
  //  -- Slot 3 / sp[1*kSystemPointerSize]: padding
  //  -- Slot 2 / sp[2*kSystemPointerSize]: constructor function
  //  -- Slot 1 / sp[3*kSystemPointerSize]: number of arguments
  //  -- Slot 0 / sp[4*kSystemPointerSize]: context
  // -----------------------------------
  // Deoptimizer enters here.
  masm->isolate()->heap()->SetConstructStubCreateDeoptPCOffset(
      masm->pc_offset());
  __ bind(&post_instantiation_deopt_entry);

  // Restore new target.
  __ Pop(a3);

  // Push the allocated receiver to the stack.
  __ Push(a0);

  // We need two copies because we may have to return the original one
  // and the calling conventions dictate that the called function pops the
  // receiver. The second copy is pushed after the arguments, we saved in a6
  // since a0 will store the return value of callRuntime.
  __ Move(a6, a0);

  // Set up pointer to first argument (skip receiver)..
  __ AddWord(
      t2, fp,
      Operand(StandardFrameConstants::kCallerSPOffset + kSystemPointerSize));

  // ----------- S t a t e -------------
  //  --                 a3: new target
  //  -- sp[0*kSystemPointerSize]: implicit receiver
  //  -- sp[1*kSystemPointerSize]: implicit receiver
  //  -- sp[2*kSystemPointerSize]: padding
  //  -- sp[3*kSystemPointerSize]: constructor function
  //  -- sp[4*kSystemPointerSize]: number of arguments
  //  -- sp[5*kSystemPointerSize]: context
  // -----------------------------------

  // Restore constructor function and argument count.
  __ LoadWord(a1, MemOperand(fp, ConstructFrameConstants::kConstructorOffset));
  __ LoadWord(a0, MemOperand(fp, ConstructFrameConstants::kLengthOffset));

  Label stack_overflow;
  {
    UseScratchRegisterScope temps(masm);
    __ StackOverflowCheck(a0, temps.Acquire(), temps.Acquire(),
                          &stack_overflow);
  }
  // TODO(victorgomes): When the arguments adaptor is completely removed, we
  // should get the formal parameter count and copy the arguments in its
  // correct position (including any undefined), instead of delaying this to
  // InvokeFunction.

  // Copy arguments and receiver to the expression stack.
  // t2: Pointer to start of argument.
  // a0: Number of arguments.
  {
    UseScratchRegisterScope temps(masm);
    Generate_PushArguments(masm, t2, a0, temps.Acquire(), temps.Acquire(),
                           ArgumentsElementType::kRaw);
  }
  // We need two copies because we may have to return the original one
  // and the calling conventions dictate that the called function pops the
  // receiver. The second copy is pushed after the arguments,
  __ Push(a6);

  // Call the function.
  __ InvokeFunctionWithNewTarget(a1, a3, a0, InvokeType::kCall);

  // If the result is an object (in the ECMA sense), we should get rid
  // of the receiver and use the result; see ECMA-262 section 13.2.2-7
  // on page 74.
  Label use_receiver, do_throw, leave_and_return, check_receiver;

  // If the result is undefined, we jump out to using the implicit receiver.
  __ JumpIfNotRoot(a0, RootIndex::kUndefinedValue, &check_receiver);

  // Otherwise we do a smi check and fall through to check if the return value
  // is a valid receiver.

  // Throw away the result of the constructor invocation and use the
  // on-stack receiver as the result.
  __ bind(&use_receiver);
  __ LoadWord(a0, MemOperand(sp, 0 * kSystemPointerSize));
  __ JumpIfRoot(a0, RootIndex::kTheHoleValue, &do_throw);

  __ bind(&leave_and_return);
  // Restore  arguments count from the frame.
  __ LoadWord(a1, MemOperand(fp, ConstructFrameConstants::kLengthOffset));
  // Leave construct frame.
  __ LeaveFrame(StackFrame::CONSTRUCT);

  // Remove caller arguments from the stack and return.
  __ DropArguments(a1);
  __ Ret();

  __ bind(&check_receiver);
  __ JumpIfSmi(a0, &use_receiver);

  // If the type of the result (stored in its map) is less than
  // FIRST_JS_RECEIVER_TYPE, it is not an object in the ECMA sense.
  {
    UseScratchRegisterScope temps(masm);
    Register map = temps.Acquire(), type = temps.Acquire();
    __ GetObjectType(a0, map, type);

    static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
    __ Branch(&leave_and_return, greater_equal, type,
              Operand(FIRST_JS_RECEIVER_TYPE));
    __ Branch(&use_receiver);
  }
  __ bind(&do_throw);
  // Restore the context from the frame.
  __ LoadWord(cp, MemOperand(fp, ConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowConstructorReturnedNonObject);
  __ break_(0xCC);

  __ bind(&stack_overflow);
  // Restore the context from the frame.
  __ LoadWord(cp, MemOperand(fp, ConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowStackOverflow);
  __ break_(0xCC);
}

void Builtins::Generate_JSBuiltinsConstructStub(MacroAssembler* masm) {
  Generate_JSBuiltinsConstructStubHelper(masm);
}

static void AssertCodeIsBaseline(MacroAssembler* masm, Register code,
                                 Register scratch) {
  DCHECK(!AreAliased(code, scratch));
  // Verify that the code kind is baseline code via the CodeKind.
  __ LoadWord(scratch, FieldMemOperand(code, Code::kFlagsOffset));
  __ DecodeField<Code::KindField>(scratch);
  __ Assert(eq, AbortReason::kExpectedBaselineData, scratch,
            Operand(static_cast<int64_t>(CodeKind::BASELINE)));
}

// TODO(v8:11429): Add a path for "not_compiled" and unify the two uses under
// the more general dispatch.
static void GetSharedFunctionInfoBytecodeOrBaseline(
    MacroAssembler* masm, Register sfi, Register bytecode, Register scratch1,
    Label* is_baseline, Label* is_unavailable) {
  DCHECK(!AreAliased(bytecode, scratch1));
  ASM_CODE_COMMENT(masm);
  Label done;

  Register data = bytecode;
  __ LoadTrustedPointerField(
      data,
      FieldMemOperand(sfi, SharedFunctionInfo::kTrustedFunctionDataOffset),
      kUnknownIndirectPointerTag);

  __ GetObjectType(data, scratch1, scratch1);
#ifndef V8_JITLESS
  if (v8_flags.debug_code) {
    Label not_baseline;
    __ Branch(&not_baseline, ne, scratch1, Operand(CODE_TYPE));
    AssertCodeIsBaseline(masm, data, scratch1);
    __ Branch(is_baseline);
    __ bind(&not_baseline);
  } else {
    __ Branch(is_baseline, eq, scratch1, Operand(CODE_TYPE));
  }
#endif  // !V8_JITLESS
  __ Branch(&done, eq, scratch1, Operand(BYTECODE_ARRAY_TYPE));
  __ Branch(is_unavailable, ne, scratch1, Operand(INTERPRETER_DATA_TYPE));
  __ LoadProtectedPointerField(
      bytecode, FieldMemOperand(data, InterpreterData::kBytecodeArrayOffset));
  __ bind(&done);
}

// static
void Builtins::Generate_ResumeGeneratorTrampoline(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- a0 : the value to pass to the generator
  //  -- a1 : the JSGeneratorObject to resume
  //  -- ra : return address
  // -----------------------------------
  // Store input value into generator object.
  __ StoreTaggedField(
      a0, FieldMemOperand(a1, JSGeneratorObject::kInputOrDebugPosOffset));
  __ RecordWriteField(a1, JSGeneratorObject::kInputOrDebugPosOffset, a0,
                      kRAHasNotBeenSaved, SaveFPRegsMode::kIgnore);
  // Check that a1 is still valid, RecordWrite might have clobbered it.
  __ AssertGeneratorObject(a1);

  // Load suspended function and context.
  __ LoadTaggedField(a4,
                     FieldMemOperand(a1, JSGeneratorObject::kFunctionOffset));
  __ LoadTaggedField(cp, FieldMemOperand(a4, JSFunction::kContextOffset));

  // Flood function if we are stepping.
  Label prepare_step_in_if_stepping, prepare_step_in_suspended_generator;
  Label stepping_prepared;
  ExternalReference debug_hook =
      ExternalReference::debug_hook_on_function_call_address(masm->isolate());
  __ li(a5, debug_hook);
  __ Lb(a5, MemOperand(a5));
  __ Branch(&prepare_step_in_if_stepping, ne, a5, Operand(zero_reg));

  // Flood function if we need to continue stepping in the suspended generator.
  ExternalReference debug_suspended_generator =
      ExternalReference::debug_suspended_generator_address(masm->isolate());
  __ li(a5, debug_suspended_generator);
  __ LoadWord(a5, MemOperand(a5));
  __ Branch(&prepare_step_in_suspended_generator, eq, a1, Operand(a5));
  __ bind(&stepping_prepared);

  // Check the stack for overflow. We are not trying to catch interruptions
  // (i.e. debug break and preemption) here, so check the "real stack limit".
  Label stack_overflow;
  __ LoadStackLimit(kScratchReg, StackLimitKind::kRealStackLimit);
  __ Branch(&stack_overflow, Uless, sp, Operand(kScratchReg));

  // ----------- S t a t e -------------
  //  -- a1    : the JSGeneratorObject to resume
  //  -- a4    : generator function
  //  -- cp    : generator context
  //  -- ra    : return address
  // -----------------------------------

  // Push holes for arguments to generator function. Since the parser forced
  // context allocation for any variables in generators, the actual argument
  // values have already been copied into the context and these dummy values
  // will never be used.
  __ LoadTaggedField(
      a3, FieldMemOperand(a4, JSFunction::kSharedFunctionInfoOffset));
  __ Lhu(a3,
         FieldMemOperand(a3, SharedFunctionInfo::kFormalParameterCountOffset));
  __ SubWord(a3, a3, Operand(kJSArgcReceiverSlots));
  __ LoadTaggedField(
      t1,
      FieldMemOperand(a1, JSGeneratorObject::kParametersAndRegistersOffset));
  {
    Label done_loop, loop;
    __ bind(&loop);
    __ SubWord(a3, a3, Operand(1));
    __ Branch(&done_loop, lt, a3, Operand(zero_reg), Label::Distance::kNear);
    __ CalcScaledAddress(kScratchReg, t1, a3, kTaggedSizeLog2);
    __ LoadTaggedField(
        kScratchReg,
        FieldMemOperand(kScratchReg, OFFSET_OF_DATA_START(FixedArray)));
    __ Push(kScratchReg);
    __ Branch(&loop);
    __ bind(&done_loop);
    // Push receiver.
    __ LoadTaggedField(kScratchReg,
                       FieldMemOperand(a1, JSGeneratorObject::kReceiverOffset));
    __ Push(kScratchReg);
  }

  // Underlying function needs to have bytecode available.
  if (v8_flags.debug_code) {
    Label ok, is_baseline, is_unavailable;
    Register sfi = a3;
    Register bytecode = a3;
    __ LoadTaggedField(
        sfi, FieldMemOperand(a4, JSFunction::kSharedFunctionInfoOffset));
    GetSharedFunctionInfoBytecodeOrBaseline(masm, sfi, bytecode, t5,
                                            &is_baseline, &is_unavailable);
    __ Branch(&ok);
    __ bind(&is_unavailable);
    __ Abort(AbortReason::kMissingBytecodeArray);
    __ bind(&is_baseline);
    __ GetObjectType(bytecode, t5, t5);
    __ Assert(eq, AbortReason::kMissingBytecodeArray, t5, Operand(CODE_TYPE));
    __ bind(&ok);
  }

  // Resume (Ignition/TurboFan) generator object.
  {
    __ LoadTaggedField(
        a0, FieldMemOperand(a4, JSFunction::kSharedFunctionInfoOffset));
    __ Lhu(a0, FieldMemOperand(
                   a0, SharedFunctionInfo::kFormalParameterCountOffset));
    // We abuse new.target both to indicate that this is a resume call and to
    // pass in the generator object.  In ordinary calls, new.target is always
    // undefined because generator functions are non-constructable.
    __ Move(a3, a1);
    __ Move(a1, a4);
    __ JumpJSFunction(a1);
  }

  __ bind(&prepare_step_in_if_stepping);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ Push(a1, a4);
    // Push hole as receiver since we do not use it for stepping.
    __ PushRoot(RootIndex::kTheHoleValue);
    __ CallRuntime(Runtime::kDebugOnFunctionCall);
    __ Pop(a1);
  }
  __ LoadTaggedField(a4,
                     FieldMemOperand(a1, JSGeneratorObject::kFunctionOffset));
  __ Branch(&stepping_prepared);

  __ bind(&prepare_step_in_suspended_generator);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ Push(a1);
    __ CallRuntime(Runtime::kDebugPrepareStepInSuspendedGenerator);
    __ Pop(a1);
  }
  __ LoadTaggedField(a4,
                     FieldMemOperand(a1, JSGeneratorObject::kFunctionOffset));
  __ Branch(&stepping_prepared);

  __ bind(&stack_overflow);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kThrowStackOverflow);
    __ break_(0xCC);  // This should be unreachable.
  }
}

void Builtins::Generate_ConstructedNonConstructable(MacroAssembler* masm) {
  FrameScope scope(masm, StackFrame::INTERNAL);
  __ Push(a1);
  __ CallRuntime(Runtime::kThrowConstructedNonConstructable);
}

// Clobbers scratch1 and scratch2; preserves all other registers.
static void Generate_CheckStackOverflow(MacroAssembler* masm, Register argc,
                                        Register scratch1, Register scratch2) {
  // Check the stack for overflow. We are not trying to catch
  // interruptions (e.g. debug break and preemption) here, so the "real stack
  // limit" is checked.
  Label okay;
  __ LoadStackLimit(scratch1, StackLimitKind::kRealStackLimit);
  // Make a2 the space we have left. The stack might already be overflowed
  // here which will cause r2 to become negative.
  __ SubWord(scratch1, sp, scratch1);
  // Check if the arguments will overflow the stack.
  __ SllWord(scratch2, argc, kSystemPointerSizeLog2);
  __ Branch(&okay, gt, scratch1, Operand(scratch2),
            Label::Distance::kNear);  // Signed comparison.

  // Out of stack space.
  __ CallRuntime(Runtime::kThrowStackOverflow);

  __ bind(&okay);
}

namespace {

// Called with the native C calling convention. The corresponding function
// signature is either:
//
//   using JSEntryFunction = GeneratedCode<Address(
//       Address root_register_value, Address new_target, Address target,
//       Address receiver, intptr_t argc, Address** args)>;
// or
//   using JSEntryFunction = GeneratedCode<Address(
//       Address root_register_value, MicrotaskQueue* microtask_queue)>;
void Generate_JSEntryVariant(MacroAssembler* masm, StackFrame::Type type,
                             Builtin entry_trampoline) {
  Label invoke, handler_entry, exit;

  {
    NoRootArrayScope no_root_array(masm);

    // TODO(plind): unify the ABI description here.
    // Registers:
    //  either
    //   a0: root register value
    //   a1: entry address
    //   a2: function
    //   a3: receiver
    //   a4: argc
    //   a5: argv
    //  or
    //   a0: root register value
    //   a1: microtask_queue

    // Save callee saved registers on the stack.
    __ MultiPush(kCalleeSaved | ra);

    // Save callee-saved FPU registers.
    __ MultiPushFPU(kCalleeSavedFPU);
    // Set up the reserved register for 0.0.
    __ LoadFPRImmediate(kDoubleRegZero, 0.0);
    __ LoadFPRImmediate(kSingleRegZero, 0.0f);

    // Initialize the root register.
    // C calling convention. The first argument is passed in a0.
    __ Move(kRootRegister, a0);

#ifdef V8_COMPRESS_POINTERS
    // Initialize the pointer cage base register.
    __ LoadRootRelative(kPtrComprCageBaseRegister,
                        IsolateData::cage_base_offset());
#endif
  }

  // a1: entry address
  // a2: function
  // a3: receiver
  // a4: argc
  // a5: argv

  // We build an EntryFrame.
  __ li(s1, Operand(-1));  // Push a bad frame pointer to fail if it is used.
  __ li(s2, Operand(StackFrame::TypeToMarker(type)));
  __ li(s3, Operand(StackFrame::TypeToMarker(type)));
  ExternalReference c_entry_fp = ExternalReference::Create(
      IsolateAddressId::kCEntryFPAddress, masm->isolate());
  __ li(s5, c_entry_fp);
  __ LoadWord(s4, MemOperand(s5));
  __ Push(s1, s2, s3, s4);
  // Clear c_entry_fp, now we've pushed its previous value to the stack.
  // If the c_entry_fp is not already zero and we don't clear it, the
  // StackFrameIteratorForProfiler will assume we are executing C++ and miss the
  // JS frames on top.
  __ StoreWord(zero_reg, MemOperand(s5));

  __ LoadIsolateField(s1, IsolateFieldId::kFastCCallCallerFP);
  __ LoadWord(s2, MemOperand(s1, 0));
  __ StoreWord(zero_reg, MemOperand(s1, 0));

  __ LoadIsolateField(s1, IsolateFieldId::kFastCCallCallerPC);
  __ LoadWord(s3, MemOperand(s1, 0));
  __ StoreWord(zero_reg, MemOperand(s1, 0));
  __ Push(s2, s3);
  // Set up frame pointer for the frame to be pushed.
  __ AddWord(fp, sp, -EntryFrameConstants::kNextFastCallFramePCOffset);
  // Registers:
  //  either
  //   a1: entry address
  //   a2: function
  //   a3: receiver
  //   a4: argc
  //   a5: argv
  //  or
  //   a1: microtask_queue
  //
  // Stack:
  // fast api call pc
  // fast api call fp
  // caller fp          |
  // function slot      | entry frame
  // context slot       |
  // bad fp (0xFF...F)  |
  // callee saved registers + ra

  // If this is the outermost JS call, set js_entry_sp value.
  Label non_outermost_js;
  ExternalReference js_entry_sp = ExternalReference::Create(
      IsolateAddressId::kJSEntrySPAddress, masm->isolate());
  __ li(s1, js_entry_sp);
  __ LoadWord(s2, MemOperand(s1));
  __ Branch(&non_outermost_js, ne, s2, Operand(zero_reg),
            Label::Distance::kNear);
  __ StoreWord(fp, MemOperand(s1));
  __ li(s3, Operand(StackFrame::OUTERMOST_JSENTRY_FRAME));
  Label cont;
  __ Branch(&cont);
  __ bind(&non_outermost_js);
  __ li(s3, Operand(StackFrame::INNER_JSENTRY_FRAME));
  __ bind(&cont);
  __ push(s3);

  // Jump to a faked try block that does the invoke, with a faked catch
  // block that sets the exception.
  __ BranchShort(&invoke);
  __ bind(&handler_entry);

  // Store the current pc as the handler offset. It's used later to create the
  // handler table.
  masm->isolate()->builtins()->SetJSEntryHandlerOffset(handler_entry.pos());

  // Caught exception: Store result (exception) in the exception
  // field in the JSEnv and return a failure sentinel.  Coming in here the
  // fp will be invalid because the PushStackHandler below sets it to 0 to
  // signal the existence of the JSEntry frame.
  __ li(s1, ExternalReference::Create(IsolateAddressId::kExceptionAddress,
                                      masm->isolate()));
  __ StoreWord(a0,
               MemOperand(s1));  // We come back from 'invoke'. result is in a0.
  __ LoadRoot(a0, RootIndex::kException);
  __ BranchShort(&exit);

  // Invoke: Link this frame into the handler chain.
  __ bind(&invoke);
  __ PushStackHandler();
  // If an exception not caught by another handler occurs, this handler
  // returns control to the code after the bal(&invoke) above, which
  // restores all kCalleeSaved registers (including cp and fp) to their
  // saved values before returning a failure to C.
  //
  // Registers:
  //  either
  //   a0: root register value
  //   a1: entry address
  //   a2: function
  //   a3: receiver
  //   a4: argc
  //   a5: argv
  //  or
  //   a0: root register value
  //   a1: microtask_queue
  //
  // Stack:
  // fast api call pc.
  // fast api call fp.
  // JS entry frame marker
  // caller fp          |
  // function slot      | entry frame
  // context slot       |
  // bad fp (0xFF...F)  |
  // handler frame
  // entry frame
  // callee saved registers + ra
  // [ O32: 4 args slots]
  // args
  //
  // Invoke the function by calling through JS entry trampoline builtin and
  // pop the faked function when we return.
  __ CallBuiltin(entry_trampoline);

  // Unlink this frame from the handler chain.
  __ PopStackHandler();

  __ bind(&exit);  // a0 holds result
  // Check if the current stack frame is marked as the outermost JS frame.

  Label non_outermost_js_2;
  __ pop(a5);
  __ Branch(&non_outermost_js_2, ne, a5,
            Operand(StackFrame::OUTERMOST_JSENTRY_FRAME),
            Label::Distance::kNear);
  __ li(a5, js_entry_sp);
  __ StoreWord(zero_reg, MemOperand(a5));
  __ bind(&non_outermost_js_2);

  __ Pop(s2, s3);
  __ LoadIsolateField(s1, IsolateFieldId::kFastCCallCallerFP);
  __ StoreWord(s2, MemOperand(s1, 0));
  __ LoadIsolateField(s1, IsolateFieldId::kFastCCallCallerPC);
  __ StoreWord(s3, MemOperand(s1, 0));
  // Restore the top frame descriptors from the stack.
  __ pop(a5);
  __ li(a4, ExternalReference::Create(IsolateAddressId::kCEntryFPAddress,
                                      masm->isolate()));
  __ StoreWord(a5, MemOperand(a4));

  // Reset the stack to the callee saved registers.
  __ AddWord(sp, sp, -EntryFrameConstants::kNextExitFrameFPOffset);

  // Restore callee-saved fpu registers.
  __ MultiPopFPU(kCalleeSavedFPU);

  // Restore callee saved registers from the stack.
  __ MultiPop(kCalleeSaved | ra);
  // Return.
  __ Jump(ra);
}

}  // namespace

void Builtins::Generate_JSEntry(MacroAssembler* masm) {
  Generate_JSEntryVariant(masm, StackFrame::ENTRY, Builtin::kJSEntryTrampoline);
}

void Builtins::Generate_JSConstructEntry(MacroAssembler* masm) {
  Generate_JSEntryVariant(masm, StackFrame::CONSTRUCT_ENTRY,
                          Builtin::kJSConstructEntryTrampoline);
}

void Builtins::Generate_JSRunMicrotasksEntry(MacroAssembler* masm) {
  Generate_JSEntryVariant(masm, StackFrame::ENTRY,
                          Builtin::kRunMicrotasksTrampoline);
}

static void Generate_JSEntryTrampolineHelper(MacroAssembler* masm,
                                             bool is_construct) {
  // ----------- S t a t e -------------
  //  -- a1: new.target
  //  -- a2: function
  //  -- a3: receiver_pointer
  //  -- a4: argc
  //  -- a5: argv
  // -----------------------------------

  // Enter an internal frame.
  {
    FrameScope scope(masm, StackFrame::INTERNAL);

    // Setup the context (we need to use the caller context from the isolate).
    ExternalReference context_address = ExternalReference::Create(
        IsolateAddressId::kContextAddress, masm->isolate());
    __ li(cp, context_address);
    __ LoadWord(cp, MemOperand(cp));

    // Push the function onto the stack.
    __ Push(a2);

    // Check if we have enough stack space to push all arguments.
    __ mv(a6, a4);
    Generate_CheckStackOverflow(masm, a6, a0, s2);

    // Copy arguments to the stack.
    // a4: argc
    // a5: argv, i.e. points to first arg
    {
      UseScratchRegisterScope temps(masm);
      Generate_PushArguments(masm, a5, a4, temps.Acquire(), temps.Acquire(),
                             ArgumentsElementType::kHandle);
    }
    // Push the receive.
    __ Push(a3);

    // a0: argc
    // a1: function
    // a3: new.target
    __ Move(a3, a1);
    __ Move(a1, a2);
    __ Move(a0, a4);

    // Initialize all JavaScript callee-saved registers, since they will be seen
    // by the garbage collector as part of handlers.
    __ LoadRoot(a4, RootIndex::kUndefinedValue);
    __ Move(a5, a4);
    __ Move(s1, a4);
    __ Move(s2, a4);
    __ Move(s3, a4);
    __ Move(s4, a4);
    __ Move(s5, a4);
    __ Move(s8, a4);
    __ Move(s9, a4);
    __ Move(s10, a4);
#ifndef V8_COMPRESS_POINTERS
    __ Move(s11, a4);
#endif
    // s6 holds the root address. Do not clobber.
    // s7 is cp. Do not init.
    // s11 is pointer cage base register (kPointerCageBaseRegister).

    // Invoke the code.
    Builtin builtin = is_construct ? Builtin::kConstruct : Builtins::Call();
    __ CallBuiltin(builtin);

    // Leave internal frame.
  }
  __ Jump(ra);
}

void Builtins::Generate_JSEntryTrampoline(MacroAssembler* masm) {
  Generate_JSEntryTrampolineHelper(masm, false);
}

void Builtins::Generate_JSConstructEntryTrampoline(MacroAssembler* masm) {
  Generate_JSEntryTrampolineHelper(masm, true);
}

void Builtins::Generate_RunMicrotasksTrampoline(MacroAssembler* masm) {
  // a1: microtask_queue
  __ Move(RunMicrotasksDescriptor::MicrotaskQueueRegister(), a1);
  __ TailCallBuiltin(Builtin::kRunMicrotasks);
}

static void LeaveInterpreterFrame(MacroAssembler* masm, Register scratch1,
                                  Register scratch2) {
  ASM_CODE_COMMENT(masm);
  Register params_size = scratch1;

  // Get the size of the formal parameters + receiver (in bytes).
  __ LoadWord(params_size,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ Lhu(params_size,
         FieldMemOperand(params_size, BytecodeArray::kParameterSizeOffset));

  Register actual_params_size = scratch2;
  Label L1;
  // Compute the size of the actual parameters + receiver (in bytes).
  __ LoadWord(actual_params_size,
              MemOperand(fp, StandardFrameConstants::kArgCOffset));
  // If actual is bigger than formal, then we should use it to free up the stack
  // arguments.
  __ Branch(&L1, le, actual_params_size, Operand(params_size),
            Label::Distance::kNear);
  __ Move(params_size, actual_params_size);
  __ bind(&L1);

  // Leave the frame (also dropping the register file).
  __ LeaveFrame(StackFrame::INTERPRETED);

  // Drop receiver + arguments.
  __ DropArguments(params_size);
}

// Advance the current bytecode offset. This simulates what all bytecode
// handlers do upon completion of the underlying operation. Will bail out to a
// label if the bytecode (without prefix) is a return bytecode. Will not advance
// the bytecode offset if the current bytecode is a JumpLoop, instead just
// re-executing the JumpLoop to jump to the correct bytecode.
static void AdvanceBytecodeOffsetOrReturn(MacroAssembler* masm,
                                          Register bytecode_array,
                                          Register bytecode_offset,
                                          Register bytecode, Register scratch1,
                                          Register scratch2, Register scratch3,
                                          Label* if_return) {
  ASM_CODE_COMMENT(masm);
  Register bytecode_size_table = scratch1;

  // The bytecode offset value will be increased by one in wide and extra wide
  // cases. In the case of having a wide or extra wide JumpLoop bytecode, we
  // will restore the original bytecode. In order to simplify the code, we have
  // a backup of it.
  Register original_bytecode_offset = scratch3;
  DCHECK(!AreAliased(bytecode_array, bytecode_offset, bytecode,
                     bytecode_size_table, original_bytecode_offset));
  __ Move(original_bytecode_offset, bytecode_offset);
  __ li(bytecode_size_table, ExternalReference::bytecode_size_table_address());

  // Check if the bytecode is a Wide or ExtraWide prefix bytecode.
  Label process_bytecode, extra_wide;
  static_assert(0 == static_cast<int>(interpreter::Bytecode::kWide));
  static_assert(1 == static_cast<int>(interpreter::Bytecode::kExtraWide));
  static_assert(2 == static_cast<int>(interpreter::Bytecode::kDebugBreakWide));
  static_assert(3 ==
               
"""


```