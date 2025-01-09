Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/builtins/riscv/builtins-riscv.cc`. The response should also consider if this file could be a Torque file (based on its name), if it relates to JavaScript (with examples), any code logic inferences (with examples), common programming errors it might help avoid, and finally a general summary of its function.

Here's a breakdown of the thought process:

1. **Identify the File's Purpose:** The code clearly deals with built-in functions for the RISC-V architecture within the V8 JavaScript engine. This suggests it's low-level code handling fundamental operations.

2. **Check for Torque:** The prompt explicitly asks about `.tq` extension. The given file name is `builtins-riscv.cc`. Therefore, it's *not* a Torque file.

3. **Analyze Core Functionalities:**  Read through the functions and identify their primary actions. Keywords like `InterpreterEnter`, `ContinueToBuiltin`, `OnStackReplacement`, `FunctionPrototypeApply/Call`, `ReflectApply/Construct`, and `CallOrConstructVarargs/ForwardVarargs` are strong indicators of the functionalities being implemented.

4. **Relate to JavaScript:** Connect these C++ built-ins to their JavaScript counterparts. For example:
    * `InterpreterEnter` is related to how JavaScript code execution starts in the interpreter.
    * `FunctionPrototype.apply` and `FunctionPrototype.call` have direct JavaScript equivalents.
    * `Reflect.apply` and `Reflect.construct` also have corresponding JavaScript APIs.
    * `OnStackReplacement` relates to optimizing code execution at runtime, a core concept in JavaScript engines.

5. **Provide JavaScript Examples:**  For the JavaScript-related functionalities, provide concise code examples demonstrating their usage. This helps illustrate the connection between the low-level C++ and the high-level JavaScript.

6. **Infer Code Logic and Provide Examples:**  Look for patterns or specific logic within the C++ code that can be demonstrated with examples.
    * The `InterpreterEnter` functions handle the transition into and between bytecode execution. A simple JavaScript function demonstrates the interpreter in action.
    * The `CallOrConstructVarargs` functions deal with variable arguments. Show how `apply` and the spread operator work in JavaScript to relate to this.
    * The `OnStackReplacement` logic is more complex but its purpose is runtime optimization. A long-running loop can illustrate the concept, though the exact mechanism is hidden.

7. **Identify Potential Programming Errors:** Think about common mistakes developers might make when using the JavaScript features implemented by these built-ins.
    * Incorrect usage of `apply` or `call` (wrong `this` binding, incorrect arguments).
    * Issues with `Reflect.apply` and `Reflect.construct` (non-callable target, non-constructor target).
    * Stack overflow errors when dealing with large numbers of arguments.

8. **Formulate Assumptions for Input/Output:**  For functions with clear logic (like those manipulating arguments), create simple hypothetical inputs and expected outputs to illustrate the transformations happening within the C++ code. Focus on the effects on registers and stack.

9. **Summarize Functionality:**  Condense the analysis into a concise summary that captures the main purpose of the file. Emphasize that it contains the RISC-V specific implementations of essential built-in functions used by the V8 engine to execute JavaScript code.

10. **Structure the Response:** Organize the information logically, addressing each point from the prompt. Use clear headings and formatting to improve readability.

**(Self-Correction/Refinement during the process):**

* **Initial thought:** Focus heavily on the assembly instructions.
* **Correction:** Shift focus to the *purpose* of the functions rather than just the low-level details. The user needs to understand what these built-ins *do* in relation to JavaScript.
* **Initial thought:**  Only provide very technical explanations.
* **Correction:** Include accessible JavaScript examples to bridge the gap between the C++ code and the user's understanding of JavaScript.
* **Initial thought:**  Treat each function completely independently.
* **Correction:** Look for overarching themes and group related functionalities (e.g., the different `Call` and `Construct` built-ins).

By following this process, the response effectively addresses all aspects of the user's request, providing a comprehensive overview of the `builtins-riscv.cc` file's role within the V8 engine.
好的，让我们来分析一下 `v8/src/builtins/riscv/builtins-riscv.cc` 这个文件的功能。

**功能列举：**

从代码片段来看，这个文件定义了一系列 RISC-V 架构特定的 V8 内建函数（builtins）。这些内建函数是 V8 引擎执行 JavaScript 代码时调用的底层实现。 它们涵盖了以下主要功能：

1. **解释器入口和执行：**
   - `Generate_InterpreterEnterBytecode`:  负责进入 V8 的字节码解释器。它从栈帧中加载必要的信息（字节码数组、偏移量），然后跳转到目标字节码执行。
   - `Generate_InterpreterEnterAtNextBytecode`: 模拟字节码处理完成后的行为，更新字节码偏移量，并跳转到下一个字节码。
   - `Generate_InterpreterEnterAtBytecode`: 实际上是调用 `Generate_InterpreterEnterBytecode`，提供一个入口点。

2. **内建函数调用和返回：**
   - `Generate_ContinueToCodeStubBuiltin` 和 `Generate_ContinueToCodeStubBuiltinWithResult`:  用于从代码桩（CodeStub）中恢复执行。代码桩是 V8 用于优化代码执行的一种机制。`WithResult` 版本表示代码桩执行后有返回值需要处理。
   - `Generate_ContinueToJavaScriptBuiltin` 和 `Generate_ContinueToJavaScriptBuiltinWithResult`:  用于从 JavaScript 内建函数中恢复执行，与上面的代码桩类似。

3. **去优化通知：**
   - `Generate_NotifyDeoptimized`:  当代码从优化后的版本回退到解释器执行时被调用，通知运行时系统。

4. **栈上替换 (OSR)：**
   - `Generate_InterpreterOnStackReplacement` 和 `Generate_BaselineOnStackReplacement`:  处理从解释器或 Baseline 编译器生成的代码到优化后的代码的转换。这是 V8 优化执行流程的关键部分。

5. **Maglev 相关 (如果启用)：**
   - `Generate_MaglevFunctionEntryStackCheck`:  在 Maglev 编译器生成的代码入口处进行栈大小检查。Maglev 是 V8 的一个中间层编译器。

6. **`Function.prototype.apply` 的实现：**
   - `Builtins::Generate_FunctionPrototypeApply`:  实现了 JavaScript 中 `Function.prototype.apply` 方法的功能，允许以指定的 `this` 值和参数数组调用函数。

7. **`Function.prototype.call` 的实现：**
   - `Builtins::Generate_FunctionPrototypeCall`:  实现了 JavaScript 中 `Function.prototype.call` 方法的功能，允许以指定的 `this` 值和逐个列出的参数调用函数。

8. **`Reflect.apply` 的实现：**
   - `Builtins::Generate_ReflectApply`:  实现了 JavaScript 中 `Reflect.apply` 方法的功能，与 `Function.prototype.apply` 类似，但更加规范。

9. **`Reflect.construct` 的实现：**
   - `Builtins::Generate_ReflectConstruct`: 实现了 JavaScript 中 `Reflect.construct` 方法的功能，允许使用指定的构造函数和参数列表创建对象。

10. **变长参数的调用和构造：**
    - `Builtins::Generate_CallOrConstructVarargs`:  处理带有可变数量参数的函数调用或对象构造。参数来自于一个 `FixedArray`。
    - `Builtins::Generate_CallOrConstructForwardVarargs`:  处理从调用者的栈帧中转发可变数量的参数。

11. **普通函数调用：**
    - `Builtins::Generate_CallFunction`:  实现了标准的 JavaScript 函数调用，包括处理 `this` 值的转换（根据是否为严格模式和是否为原生函数）。

**关于 `.tq` 结尾：**

根据您的描述，如果 `v8/src/builtins/riscv/builtins-riscv.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。Torque 是 V8 用于定义内建函数的一种高级类型化的语言，它可以编译成 C++ 代码。但当前的文件名是 `.cc`，所以它是一个 **C++ 源代码文件**。

**与 JavaScript 的关系及示例：**

这个文件中的代码直接实现了 JavaScript 的一些核心功能。以下是一些与 JavaScript 相关的示例：

**1. `Function.prototype.apply`:**

```javascript
function greet(greeting) {
  console.log(greeting + ', ' + this.name);
}

const person = { name: 'Alice' };
greet.apply(person, ['Hello']); // 输出: Hello, Alice
```

`Builtins::Generate_FunctionPrototypeApply` 中的代码负责处理 `greet.apply(person, ['Hello'])` 这样的调用。它会设置 `this` 为 `person`，并将 `['Hello']` 作为参数传递给 `greet` 函数。

**2. `Function.prototype.call`:**

```javascript
function subtract(a, b) {
  return this.value - a - b;
}

const calculator = { value: 100 };
let result = subtract.call(calculator, 10, 5); // result 为 85
console.log(result);
```

`Builtins::Generate_FunctionPrototypeCall` 中的代码处理 `subtract.call(calculator, 10, 5)` 这样的调用。它设置 `this` 为 `calculator`，并将 `10` 和 `5` 作为参数传递给 `subtract` 函数。

**3. `Reflect.apply`:**

```javascript
function multiply(a, b) {
  return a * b;
}

let result = Reflect.apply(multiply, null, [5, 2]); // result 为 10
console.log(result);
```

`Builtins::Generate_ReflectApply` 负责实现 `Reflect.apply(multiply, null, [5, 2])` 这样的调用。

**4. `Reflect.construct`:**

```javascript
class Point {
  constructor(x, y) {
    this.x = x;
    this.y = y;
  }
}

let point = Reflect.construct(Point, [10, 20]);
console.log(point.x, point.y); // 输出: 10 20
```

`Builtins::Generate_ReflectConstruct` 实现了 `Reflect.construct(Point, [10, 20])`，它创建了一个 `Point` 类的实例。

**代码逻辑推理（假设输入与输出）：**

**示例：`Generate_InterpreterEnterBytecode`**

**假设输入：**

- 栈帧指针 (`fp`) 指向一个有效的解释器栈帧。
- 该栈帧中存储了：
    - `InterpreterFrameConstants::kBytecodeArrayFromFp` 指向一个 `BytecodeArray` 对象。
    - `InterpreterFrameConstants::kBytecodeOffsetFromFp` 存储了一个 `Smi` 类型的字节码偏移量，例如 `Smi(10)`.
- `kInterpreterDispatchTableRegister` 寄存器中存储了字节码分发表的地址。

**代码逻辑：**

1. 加载 `BytecodeArray` 到 `kInterpreterBytecodeArrayRegister`。
2. 加载字节码偏移量（Smi 类型）到 `kInterpreterBytecodeOffsetRegister`。
3. 将偏移量解标签（`SmiUntag`）。
4. 计算目标字节码的地址：`BytecodeArray地址 + 偏移量`。
5. 从目标地址加载字节码值到 `a7`。
6. 使用字节码值在分发表中查找目标代码的地址。
7. 跳转到目标代码地址 (`kJavaScriptCallCodeStartRegister`)。

**假设输出（中间状态）：**

- `kInterpreterBytecodeArrayRegister` 包含 `BytecodeArray` 对象的地址。
- `kInterpreterBytecodeOffsetRegister` 包含整数 `10`。
- `a1` 包含目标字节码的地址。
- `a7` 包含位于偏移量 `10` 的字节码值。
- `kJavaScriptCallCodeStartRegister` 包含与该字节码对应的处理函数的入口地址。

**涉及用户常见的编程错误（JavaScript 层面）：**

虽然这个 C++ 文件本身不直接涉及用户编写的 JavaScript 代码错误，但它所实现的功能与一些常见的 JavaScript 错误场景有关：

1. **`apply` 或 `call` 的 `this` 指向错误：**  如果用户不正确地使用 `apply` 或 `call`，可能会导致函数中的 `this` 指向意外的对象或 `undefined` (在非严格模式下全局对象)。

   ```javascript
   const myObject = {
     value: 10,
     getValue: function() {
       console.log(this.value);
     }
   };

   const unboundGetValue = myObject.getValue;
   unboundGetValue(); // 在浏览器中可能输出 undefined 或 window 对象的属性

   unboundGetValue.call(myObject); // 正确用法，输出 10
   ```

2. **传递给 `apply` 或 `call` 的参数错误：** `apply` 期望一个数组作为参数，而 `call` 期望参数逐个列出。混用会导致错误。

   ```javascript
   function sum(a, b) {
     return a + b;
   }

   sum.apply(null, 1, 2); // 错误：apply 的第二个参数应该是一个数组
   sum.call(null, [1, 2]); // 错误：call 的参数应该逐个列出
   sum.apply(null, [1, 2]); // 正确
   sum.call(null, 1, 2);   // 正确
   ```

3. **`Reflect.construct` 的目标不是构造函数：** `Reflect.construct` 的第一个参数必须是一个构造函数。

   ```javascript
   function notAConstructor() { return 10; }
   Reflect.construct(notAConstructor, []); // TypeError: notAConstructor is not a constructor
   ```

4. **调用或构造变长参数时传递了错误类型的参数：** `CallOrConstructVarargs` 期望参数来自 `FixedArray`。如果用户尝试以其他方式传递变长参数，可能会导致 V8 内部错误或类型检查失败。在 JavaScript 层面，这通常体现在使用 `apply` 或 spread 运算符时传递了非类数组对象。

**功能归纳（第 3 部分）：**

这个 `builtins-riscv.cc` 文件的第 3 部分主要实现了以下功能：

- **解释器控制流：** 定义了进入和执行 V8 字节码解释器的关键入口点和执行逻辑。
- **内建函数调用框架：** 提供了从不同执行阶段（代码桩、JavaScript 内建函数）恢复执行的机制。
- **去优化处理：** 包含了代码去优化时的通知机制。
- **栈上替换 (OSR)：**  实现了从解释器或 Baseline 代码向优化代码转换的关键步骤。
- **部分 JavaScript 反射和函数调用的底层实现：** 涵盖了 `Function.prototype.apply`、`Function.prototype.call`、`Reflect.apply`、`Reflect.construct` 等重要 JavaScript 特性的 RISC-V 架构特定实现。
- **变长参数处理：**  实现了处理函数调用和构造时变长参数的逻辑。
- **标准函数调用：**  提供了普通 JavaScript 函数调用的底层支持，包括 `this` 值的处理。

总而言之，这个代码片段是 V8 引擎在 RISC-V 架构上执行 JavaScript 代码的核心组成部分，它负责底层的执行控制和关键的内置函数实现。

Prompt: 
```
这是目录为v8/src/builtins/riscv/builtins-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/riscv/builtins-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能

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
  __ InvokeFunctionCode(
"""


```