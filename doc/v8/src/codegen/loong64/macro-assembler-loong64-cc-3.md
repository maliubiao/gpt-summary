Response:
My thinking process to answer the request about the `macro-assembler-loong64.cc` code snippet went through these stages:

1. **Understanding the Core Request:** The primary goal is to explain the functionality of the provided C++ code within the context of the V8 JavaScript engine. The request specifically asks for a summary of its features, potential connections to JavaScript, code logic explanations, common programming errors it might help prevent, and a final concise summary. The "Part 4 of 6" suggests this is a piece of a larger explanation.

2. **Initial Code Scan and Keyword Identification:** I quickly scanned the code looking for recognizable patterns and keywords related to assembly language manipulation, function calls, memory operations, and V8-specific concepts. Keywords like `Ld_d`, `St_d`, `Call`, `Jump`, `Push`, `Pop`, `Builtin`, `Runtime`, `StackFrame`, `Map`, `Handle`, `Isolate`, etc., immediately stood out. The `loong64` in the file path clearly indicates the target architecture.

3. **Categorizing Functionality:** Based on the initial scan, I mentally grouped the functions and code blocks into logical categories. This helps in structuring the explanation. The key categories I identified were:

    * **Builtin Calls:** Functions dealing with calling predefined V8 functions (builtins). This is a core function.
    * **Tail Calls:**  Optimized calls that don't require returning to the caller.
    * **Stack Manipulation:**  Functions for pushing, popping, and managing the stack (arguments, return addresses, stack frames).
    * **Function Invocation:**  The logic for calling JavaScript functions, including handling argument counts and debugging hooks.
    * **Exception Handling:** Mechanisms for pushing and popping stack handlers.
    * **Runtime Calls:** Interfacing with V8's runtime system for lower-level operations.
    * **Object Manipulation:**  Loading object properties like maps.
    * **Debugging and Error Handling:**  Functions like `Trap`, `DebugBreak`, `Check`, and `Abort`.
    * **Code Generation Primitives:**  Basic assembly instructions like `mov`, `add`, `sub`, `xor`, etc. (Though these are used within the higher-level macros).

4. **Analyzing Specific Code Blocks:**  I examined individual functions more closely to understand their specific purposes. For example:

    * `CallBuiltin` and `TailCallBuiltin`:  I noticed the different `BuiltinCallJumpMode` options, indicating different ways V8 can call built-in functions (direct, indirect, PC-relative, etc.).
    * `StoreReturnAddressAndCall`:  This clearly relates to calling C functions from V8 and managing the return address.
    * `InvokeFunctionCode`, `InvokeFunction`, `InvokeFunctionWithNewTarget`:  These are central to how V8 executes JavaScript function calls, including handling `new.target` and argument adaptation.
    * The `AddOverflow_d`, `SubOverflow_d`, `MulOverflow_w`, `MulOverflow_d` family:  These are clearly related to arithmetic operations with overflow detection, which is important for correct numerical behavior in JavaScript.
    * `PushStackHandler` and `PopStackHandler`:  These are fundamental for V8's exception handling mechanism.

5. **Identifying Connections to JavaScript:** I considered how the C++ code relates to JavaScript execution. The most obvious connections are:

    * **Builtin Functions:** The `CallBuiltin` and `TailCallBuiltin` functions directly call V8's internal functions, many of which implement core JavaScript functionalities.
    * **Function Calls:** The `InvokeFunction...` family is directly responsible for executing JavaScript functions.
    * **Stack Management:** The stack manipulation functions are crucial for managing the call stack during JavaScript execution.
    * **Exception Handling:** The stack handler functions are used when JavaScript code throws and catches exceptions.
    * **Object Model:** The `LoadMap` function is used to access the type information of JavaScript objects.
    * **Runtime Functions:**  Calling into the V8 runtime allows executing operations that are not directly expressible in the assembly code itself (e.g., throwing errors, allocating memory).

6. **Crafting JavaScript Examples:** For the JavaScript connection, I thought of simple examples that would illustrate the functionality of the C++ code. Calling built-in methods (`Array.push`), function calls, and try-catch blocks were natural fits.

7. **Developing Code Logic Examples:**  For code logic, I chose scenarios involving calling built-in functions and overflowing the stack, as these are directly related to the code snippets provided. I specified simple inputs and the expected outputs or consequences.

8. **Considering Common Programming Errors:** I thought about what kinds of errors the `macro-assembler` might help V8 handle or that developers might make in JavaScript that relate to the code's functionality. Stack overflows and incorrect argument counts were the most prominent.

9. **Synthesizing the Summary:**  Finally, I condensed the information into a concise summary, highlighting the key role of the `macro-assembler-loong64.cc` file in generating low-level assembly code for the LoongArch64 architecture, specifically for handling function calls, stack management, and interactions with V8's runtime and built-in functions.

10. **Review and Refinement:** I reread my explanation to ensure clarity, accuracy, and completeness, given the provided code snippet and the specific questions asked in the request. I made sure to address all parts of the prompt. For instance, explicitly stating that the snippet isn't Torque code (because it doesn't end in `.tq`) is important.

This iterative process of scanning, categorizing, analyzing, connecting, and synthesizing allowed me to build a comprehensive explanation of the functionality of the provided `macro-assembler-loong64.cc` code snippet.
这是v8源代码文件 `v8/src/codegen/loong64/macro-assembler-loong64.cc` 的第四部分，它定义了 `MacroAssembler` 类在 LoongArch64 架构上的特定功能。`MacroAssembler` 是一个核心组件，用于生成底层的机器码指令，这些指令构成了 V8 引擎执行 JavaScript 代码的基础。

**功能归纳 (基于提供的代码片段):**

这部分代码主要集中在以下几个核心功能：

1. **调用 Builtin 函数 (Builtin Calls):**  提供了多种方式来调用 V8 的内置 (Builtin) 函数。这些 Builtin 函数是用 C++ 或汇编实现的高效的底层操作，例如对象创建、类型转换等。  支持不同的调用模式，例如绝对地址调用、PC 相对调用和间接调用，以及针对快照 (mksnapshot) 构建的优化。

2. **尾调用 Builtin 函数 (Tail Calls):**  实现了尾调用优化，当一个函数的最后操作是调用另一个函数时，可以直接跳转到被调函数，而无需在当前栈帧中返回，节省了栈空间和调用开销。

3. **存储返回地址并调用 (Store Return Address and Call):**  用于调用 C 函数。它负责设置正确的返回地址，以便 C 函数执行完毕后能够返回到 V8 代码。这通常用于与 V8 引擎交互的外部 C++ 代码。

4. **栈操作 (Stack Operations):**  提供了操作栈的指令，例如 `DropArguments` 用于丢弃栈上的参数，`Push` 用于将数据压入栈，`Pop` 用于从栈中弹出数据。

5. **条件跳转和返回 (Conditional Jumps and Returns):**  实现了基于条件的跳转和返回指令，允许控制代码的执行流程。

6. **交换寄存器值 (Swap Registers):**  提供了一个高效的方式来交换两个寄存器中的值。

7. **处理异常 (Exception Handling):** 提供了 `PushStackHandler` 和 `PopStackHandler` 函数，用于管理异常处理栈帧。

8. **浮点 NaN 规范化 (FPU NaN Canonicalization):** 提供了一个函数来规范化浮点数的 NaN 值。

9. **加载栈限制 (Load Stack Limit):**  用于加载当前的栈限制，以便在函数调用时进行栈溢出检查。

10. **栈溢出检查 (Stack Overflow Check):**  在函数调用前检查是否有足够的栈空间，防止栈溢出。

11. **测试代码是否标记为反优化 (Test Code Is Marked For Deoptimization):** 检查代码是否因为某些原因被标记为需要反优化。

12. **调用序言 (Invoke Prologue):**  在调用 JavaScript 函数之前进行参数适配，处理实参和形参不匹配的情况。

13. **调用调试钩子 (Call Debug On Function Call):**  在函数调用时，如果启用了调试功能，则会调用相应的调试钩子。

14. **调用 JavaScript 函数 (Invoke Function):**  提供了多种方式来调用 JavaScript 函数，包括处理 `new.target` 和参数适配。

15. **获取对象类型 (GetObjectType):**  用于获取对象的类型信息。

16. **获取实例类型范围 (GetInstanceTypeRange):** 用于获取实例类型的范围。

17. **运行时调用 (Runtime Calls):**  提供了调用 V8 运行时函数的机制，这些运行时函数执行一些较为复杂的操作。

18. **尾调用运行时函数 (Tail Call Runtime):**  对运行时函数进行尾调用优化。

19. **跳转到外部引用 (Jump To External Reference):**  跳转到外部代码，例如 C++ 函数。

20. **加载弱引用值 (Load Weak Value):**  用于加载弱引用的值，如果弱引用已被清除，则跳转到指定标签。

21. **发射计数器增减 (Emit Increment/Decrement Counter):** 用于更新性能计数器。

22. **调试和断言 (Debugging and Assertions):**  提供了 `Trap`, `DebugBreak`, `Check`, `SbxCheck`, 和 `Abort` 等函数，用于调试和错误处理。

23. **加载 Map (Load Map):**  用于加载对象的 Map，Map 包含了对象的类型和布局信息。

24. **加载反馈向量 (Load Feedback Vector):** 用于加载用于内联缓存的反馈向量。

25. **加载原生上下文槽 (Load Native Context Slot):** 用于加载原生上下文中的槽位。

26. **桩序言 (Stub Prologue):**  用于创建桩函数的栈帧。

27. **函数序言 (Prologue):**  用于创建标准函数的栈帧。

28. **进入和离开栈帧 (EnterFrame and LeaveFrame):**  用于创建和销毁栈帧，栈帧用于管理函数调用时的局部变量和状态。

**关于 .tq 后缀和 JavaScript 功能：**

* 该文件 `macro-assembler-loong64.cc` 的后缀是 `.cc`，而不是 `.tq`。因此，它不是 V8 Torque 源代码。 Torque 是一种用于生成高效机器码的高级类型化的中间语言。
* 该文件与 JavaScript 的功能有非常直接的关系。 `MacroAssembler` 生成的机器码指令直接执行 JavaScript 代码。例如：
    * **调用 Builtin 函数** 是 JavaScript 引擎执行许多内置操作的基础，例如 `Array.push()` 等。
    * **调用 JavaScript 函数**  直接负责执行用户编写的 JavaScript 函数。
    * **栈操作** 用于管理 JavaScript 函数调用时的参数和局部变量。
    * **异常处理** 使得 JavaScript 中的 `try...catch` 语句能够正常工作。

**JavaScript 举例说明:**

```javascript
function add(a, b) {
  return a + b;
}

function main() {
  let result = add(5, 3); // 调用 JavaScript 函数
  console.log(result);    // 可能涉及到调用 Builtin 函数进行输出
  try {
    throw new Error("Something went wrong");
  } catch (e) {
    console.error(e.message); // 异常处理
  }
}

main();
```

在这个简单的 JavaScript 例子中：

* 调用 `add(5, 3)` 会涉及到 `MacroAssembler` 生成的指令来设置栈帧、传递参数、跳转到 `add` 函数的代码、执行加法运算并返回。
* `console.log()` 和 `console.error()` 可能会调用 V8 的 Builtin 函数来进行实际的输出操作。
* `try...catch` 语句的实现依赖于 `MacroAssembler` 提供的异常处理机制 (`PushStackHandler`, `PopStackHandler`)。

**代码逻辑推理和假设输入输出:**

以 `CallBuiltin` 函数为例，假设输入 `builtin` 是 `Builtins::kArrayPush`，`destination` 是寄存器 `t0`。

**假设输入:**

* `builtin`: `Builtins::kArrayPush` (表示数组的 `push` 方法的内置函数)
* `destination`: 寄存器 `t0`

**代码逻辑推理 (基于 `BuiltinCallJumpMode::kIndirect`):**

1. `LoadEntryFromBuiltin(builtin, destination);` 会被调用。
2. `EntryFromBuiltinAsOperand(builtin)` 会计算出 `Builtins::kArrayPush` 在 Builtin 入口表中的偏移量。
3. `MemOperand(kRootRegister, IsolateData::BuiltinEntrySlotOffset(builtin))`  会创建一个内存操作数，指向 Builtin 入口表中 `Builtins::kArrayPush` 的地址。
4. `Ld_d(destination, ...)` 指令会将该地址加载到 `destination` 寄存器 `t0` 中。

**输出:**

* 寄存器 `t0` 将会包含 `Builtins::kArrayPush` 函数在内存中的入口地址。

**用户常见的编程错误:**

* **栈溢出 (Stack Overflow):**  递归调用过深的函数或者在栈上分配过多的局部变量可能导致栈溢出。`StackOverflowCheck` 函数旨在在实际发生溢出前检测到这种情况。

   ```javascript
   function recursiveFunction() {
     recursiveFunction(); // 永远不会停止递归
   }
   recursiveFunction(); // 可能导致栈溢出
   ```

* **调用参数不匹配:** 在 JavaScript 中，函数调用时参数的数量可能与定义时不匹配。`InvokePrologue` 负责处理这种情况，例如当提供的参数少于预期时，会用 `undefined` 填充。

   ```javascript
   function greet(name, greeting) {
     console.log(greeting + ", " + name + "!");
   }

   greet("Alice"); // 缺少 greeting 参数，greeting 在函数内部会是 undefined
   ```

* **类型错误:** 尽管 JavaScript 是动态类型语言，但在某些底层操作中，类型仍然很重要。例如，对非数值类型进行算术运算可能导致意外的结果或错误。V8 的 Builtin 函数通常会对类型进行检查。

**总结:**

这部分 `v8/src/codegen/loong64/macro-assembler-loong64.cc` 代码是 V8 引擎在 LoongArch64 架构上生成机器码的关键组成部分。它提供了用于调用 Builtin 函数、操作栈、处理异常、调用 JavaScript 函数以及进行调试和错误处理的基础指令。这些功能直接支撑着 JavaScript 代码的执行，并帮助 V8 引擎处理一些常见的编程错误。

### 提示词
```
这是目录为v8/src/codegen/loong64/macro-assembler-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/loong64/macro-assembler-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
d(target, IsolateData::builtin_entry_table_offset()));
}

void MacroAssembler::LoadEntryFromBuiltin(Builtin builtin,
                                          Register destination) {
  Ld_d(destination, EntryFromBuiltinAsOperand(builtin));
}
MemOperand MacroAssembler::EntryFromBuiltinAsOperand(Builtin builtin) {
  DCHECK(root_array_available());
  return MemOperand(kRootRegister,
                    IsolateData::BuiltinEntrySlotOffset(builtin));
}

void MacroAssembler::CallBuiltinByIndex(Register builtin_index,
                                        Register target) {
  ASM_CODE_COMMENT(this);
  LoadEntryFromBuiltinIndex(builtin_index, target);
  Call(target);
}

void MacroAssembler::CallBuiltin(Builtin builtin) {
  ASM_CODE_COMMENT_STRING(this, CommentForOffHeapTrampoline("call", builtin));
  UseScratchRegisterScope temps(this);
  Register temp = temps.Acquire();
  switch (options().builtin_call_jump_mode) {
    case BuiltinCallJumpMode::kAbsolute: {
      li(temp, Operand(BuiltinEntry(builtin), RelocInfo::OFF_HEAP_TARGET));
      Call(temp);
      break;
    }
    case BuiltinCallJumpMode::kPCRelative: {
      RecordRelocInfo(RelocInfo::NEAR_BUILTIN_ENTRY);
      bl(static_cast<int>(builtin));
      set_pc_for_safepoint();
      break;
    }
    case BuiltinCallJumpMode::kIndirect: {
      LoadEntryFromBuiltin(builtin, temp);
      Call(temp);
      break;
    }
    case BuiltinCallJumpMode::kForMksnapshot: {
      if (options().use_pc_relative_calls_and_jumps_for_mksnapshot) {
        Handle<Code> code = isolate()->builtins()->code_handle(builtin);
        int32_t code_target_index = AddCodeTarget(code);
        RecordRelocInfo(RelocInfo::RELATIVE_CODE_TARGET);
        bl(code_target_index);
        set_pc_for_safepoint();
      } else {
        LoadEntryFromBuiltin(builtin, temp);
        Call(temp);
      }
      break;
    }
  }
}

void MacroAssembler::TailCallBuiltin(Builtin builtin, Condition cond,
                                     Register type, Operand range) {
  if (cond != cc_always) {
    Label done;
    Branch(&done, NegateCondition(cond), type, range);
    TailCallBuiltin(builtin);
    bind(&done);
  } else {
    TailCallBuiltin(builtin);
  }
}

void MacroAssembler::TailCallBuiltin(Builtin builtin) {
  ASM_CODE_COMMENT_STRING(this,
                          CommentForOffHeapTrampoline("tail call", builtin));
  UseScratchRegisterScope temps(this);
  Register temp = temps.Acquire();

  switch (options().builtin_call_jump_mode) {
    case BuiltinCallJumpMode::kAbsolute: {
      li(temp, Operand(BuiltinEntry(builtin), RelocInfo::OFF_HEAP_TARGET));
      Jump(temp);
      break;
    }
    case BuiltinCallJumpMode::kIndirect: {
      LoadEntryFromBuiltin(builtin, temp);
      Jump(temp);
      break;
    }
    case BuiltinCallJumpMode::kPCRelative: {
      RecordRelocInfo(RelocInfo::NEAR_BUILTIN_ENTRY);
      b(static_cast<int>(builtin));
      set_pc_for_safepoint();
      break;
    }
    case BuiltinCallJumpMode::kForMksnapshot: {
      if (options().use_pc_relative_calls_and_jumps_for_mksnapshot) {
        Handle<Code> code = isolate()->builtins()->code_handle(builtin);
        int32_t code_target_index = AddCodeTarget(code);
        RecordRelocInfo(RelocInfo::RELATIVE_CODE_TARGET);
        b(code_target_index);
      } else {
        LoadEntryFromBuiltin(builtin, temp);
        Jump(temp);
      }
      break;
    }
  }
}

void MacroAssembler::StoreReturnAddressAndCall(Register target) {
  ASM_CODE_COMMENT(this);
  // This generates the final instruction sequence for calls to C functions
  // once an exit frame has been constructed.
  //
  // Note that this assumes the caller code (i.e. the InstructionStream object
  // currently being generated) is immovable or that the callee function cannot
  // trigger GC, since the callee function will return to it.

  Assembler::BlockTrampolinePoolScope block_trampoline_pool(this);
  static constexpr int kNumInstructionsToJump = 2;
  Label find_ra;
  // Adjust the value in ra to point to the correct return location, 2nd
  // instruction past the real call into C code (the jirl)), and push it.
  // This is the return address of the exit frame.
  pcaddi(ra, kNumInstructionsToJump + 1);
  bind(&find_ra);

  // This spot was reserved in EnterExitFrame.
  St_d(ra, MemOperand(sp, 0));
  // Stack is still aligned.

  // TODO(LOONG_dev): can be jirl target? a0 -- a7?
  jirl(zero_reg, target, 0);
  // Make sure the stored 'ra' points to this position.
  DCHECK_EQ(kNumInstructionsToJump, InstructionsGeneratedSince(&find_ra));
}

void MacroAssembler::DropArguments(Register count) {
  Alsl_d(sp, count, sp, kSystemPointerSizeLog2);
}

void MacroAssembler::DropArgumentsAndPushNewReceiver(Register argc,
                                                     Register receiver) {
  DCHECK(!AreAliased(argc, receiver));
  DropArguments(argc);
  Push(receiver);
}

void MacroAssembler::Ret(Condition cond, Register rj, const Operand& rk) {
  Jump(ra, cond, rj, rk);
}

void MacroAssembler::Drop(int count, Condition cond, Register reg,
                          const Operand& op) {
  if (count <= 0) {
    return;
  }

  Label skip;

  if (cond != al) {
    Branch(&skip, NegateCondition(cond), reg, op);
  }

  Add_d(sp, sp, Operand(count * kSystemPointerSize));

  if (cond != al) {
    bind(&skip);
  }
}

void MacroAssembler::Swap(Register reg1, Register reg2, Register scratch) {
  if (scratch == no_reg) {
    Xor(reg1, reg1, Operand(reg2));
    Xor(reg2, reg2, Operand(reg1));
    Xor(reg1, reg1, Operand(reg2));
  } else {
    mov(scratch, reg1);
    mov(reg1, reg2);
    mov(reg2, scratch);
  }
}

void MacroAssembler::Call(Label* target) { Branch(target, true); }

void MacroAssembler::Push(Tagged<Smi> smi) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  li(scratch, Operand(smi));
  Push(scratch);
}

void MacroAssembler::Push(Handle<HeapObject> handle) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  li(scratch, Operand(handle));
  Push(scratch);
}

void MacroAssembler::PushArray(Register array, Register size, Register scratch,
                               Register scratch2, PushArrayOrder order) {
  DCHECK(!AreAliased(array, size, scratch, scratch2));
  Label loop, entry;
  if (order == PushArrayOrder::kReverse) {
    mov(scratch, zero_reg);
    jmp(&entry);
    bind(&loop);
    Alsl_d(scratch2, scratch, array, kSystemPointerSizeLog2, t7);
    Ld_d(scratch2, MemOperand(scratch2, 0));
    Push(scratch2);
    Add_d(scratch, scratch, Operand(1));
    bind(&entry);
    Branch(&loop, less, scratch, Operand(size));
  } else {
    mov(scratch, size);
    jmp(&entry);
    bind(&loop);
    Alsl_d(scratch2, scratch, array, kSystemPointerSizeLog2, t7);
    Ld_d(scratch2, MemOperand(scratch2, 0));
    Push(scratch2);
    bind(&entry);
    Add_d(scratch, scratch, Operand(-1));
    Branch(&loop, greater_equal, scratch, Operand(zero_reg));
  }
}

// ---------------------------------------------------------------------------
// Exception handling.

void MacroAssembler::PushStackHandler() {
  // Adjust this code if not the case.
  static_assert(StackHandlerConstants::kSize == 2 * kSystemPointerSize);
  static_assert(StackHandlerConstants::kNextOffset == 0 * kSystemPointerSize);

  Push(Smi::zero());  // Padding.

  // Link the current handler as the next handler.
  li(t2,
     ExternalReference::Create(IsolateAddressId::kHandlerAddress, isolate()));
  Ld_d(t1, MemOperand(t2, 0));
  Push(t1);

  // Set this new handler as the current one.
  St_d(sp, MemOperand(t2, 0));
}

void MacroAssembler::PopStackHandler() {
  static_assert(StackHandlerConstants::kNextOffset == 0);
  Pop(a1);
  Add_d(sp, sp,
        Operand(static_cast<int64_t>(StackHandlerConstants::kSize -
                                     kSystemPointerSize)));
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  li(scratch,
     ExternalReference::Create(IsolateAddressId::kHandlerAddress, isolate()));
  St_d(a1, MemOperand(scratch, 0));
}

void MacroAssembler::FPUCanonicalizeNaN(const DoubleRegister dst,
                                        const DoubleRegister src) {
  fsub_d(dst, src, kDoubleRegZero);
}

// -----------------------------------------------------------------------------
// JavaScript invokes.

void MacroAssembler::LoadStackLimit(Register destination, StackLimitKind kind) {
  ASM_CODE_COMMENT(this);
  DCHECK(root_array_available());
  intptr_t offset = kind == StackLimitKind::kRealStackLimit
                        ? IsolateData::real_jslimit_offset()
                        : IsolateData::jslimit_offset();

  Ld_d(destination, MemOperand(kRootRegister, static_cast<int32_t>(offset)));
}

void MacroAssembler::StackOverflowCheck(Register num_args, Register scratch1,
                                        Register scratch2,
                                        Label* stack_overflow) {
  ASM_CODE_COMMENT(this);
  // Check the stack for overflow. We are not trying to catch
  // interruptions (e.g. debug break and preemption) here, so the "real stack
  // limit" is checked.

  LoadStackLimit(scratch1, StackLimitKind::kRealStackLimit);
  // Make scratch1 the space we have left. The stack might already be overflowed
  // here which will cause scratch1 to become negative.
  sub_d(scratch1, sp, scratch1);
  // Check if the arguments will overflow the stack.
  slli_d(scratch2, num_args, kSystemPointerSizeLog2);
  // Signed comparison.
  Branch(stack_overflow, le, scratch1, Operand(scratch2));
}

void MacroAssembler::TestCodeIsMarkedForDeoptimizationAndJump(
    Register code_data_container, Register scratch, Condition cond,
    Label* target) {
  Ld_wu(scratch, FieldMemOperand(code_data_container, Code::kFlagsOffset));
  And(scratch, scratch, Operand(1 << Code::kMarkedForDeoptimizationBit));
  Branch(target, cond, scratch, Operand(zero_reg));
}

Operand MacroAssembler::ClearedValue() const {
  return Operand(static_cast<int32_t>(i::ClearedValue(isolate()).ptr()));
}

void MacroAssembler::InvokePrologue(Register expected_parameter_count,
                                    Register actual_parameter_count,
                                    InvokeType type) {
  ASM_CODE_COMMENT(this);
  Label regular_invoke;

  //  a0: actual arguments count
  //  a1: function (passed through to callee)
  //  a2: expected arguments count

  DCHECK_EQ(actual_parameter_count, a0);
  DCHECK_EQ(expected_parameter_count, a2);

  // If overapplication or if the actual argument count is equal to the
  // formal parameter count, no need to push extra undefined values.
  sub_d(expected_parameter_count, expected_parameter_count,
        actual_parameter_count);
  Branch(&regular_invoke, le, expected_parameter_count, Operand(zero_reg));

  Label stack_overflow;
  StackOverflowCheck(expected_parameter_count, t0, t1, &stack_overflow);
  // Underapplication. Move the arguments already in the stack, including the
  // receiver and the return address.
  {
    Label copy;
    Register src = a6, dest = a7;
    mov(src, sp);
    slli_d(t0, expected_parameter_count, kSystemPointerSizeLog2);
    Sub_d(sp, sp, Operand(t0));
    // Update stack pointer.
    mov(dest, sp);
    mov(t0, actual_parameter_count);
    bind(&copy);
    Ld_d(t1, MemOperand(src, 0));
    St_d(t1, MemOperand(dest, 0));
    Sub_d(t0, t0, Operand(1));
    Add_d(src, src, Operand(kSystemPointerSize));
    Add_d(dest, dest, Operand(kSystemPointerSize));
    Branch(&copy, gt, t0, Operand(zero_reg));
  }

  // Fill remaining expected arguments with undefined values.
  LoadRoot(t0, RootIndex::kUndefinedValue);
  {
    Label loop;
    bind(&loop);
    St_d(t0, MemOperand(a7, 0));
    Sub_d(expected_parameter_count, expected_parameter_count, Operand(1));
    Add_d(a7, a7, Operand(kSystemPointerSize));
    Branch(&loop, gt, expected_parameter_count, Operand(zero_reg));
  }
  b(&regular_invoke);

  bind(&stack_overflow);
  {
    FrameScope frame(
        this, has_frame() ? StackFrame::NO_FRAME_TYPE : StackFrame::INTERNAL);
    CallRuntime(Runtime::kThrowStackOverflow);
    break_(0xCC);
  }

  bind(&regular_invoke);
}

void MacroAssembler::CallDebugOnFunctionCall(
    Register fun, Register new_target,
    Register expected_parameter_count_or_dispatch_handle,
    Register actual_parameter_count) {
  DCHECK(!AreAliased(t0, fun, new_target,
                     expected_parameter_count_or_dispatch_handle,
                     actual_parameter_count));
  // Load receiver to pass it later to DebugOnFunctionCall hook.
  LoadReceiver(t0);
  FrameScope frame(
      this, has_frame() ? StackFrame::NO_FRAME_TYPE : StackFrame::INTERNAL);

  SmiTag(expected_parameter_count_or_dispatch_handle);
  SmiTag(actual_parameter_count);
  Push(expected_parameter_count_or_dispatch_handle, actual_parameter_count);

  if (new_target.is_valid()) {
    Push(new_target);
  }
  Push(fun, fun, t0);
  CallRuntime(Runtime::kDebugOnFunctionCall);
  Pop(fun);
  if (new_target.is_valid()) {
    Pop(new_target);
  }

  Pop(expected_parameter_count_or_dispatch_handle, actual_parameter_count);
  SmiUntag(actual_parameter_count);
  SmiUntag(expected_parameter_count_or_dispatch_handle);
}

#ifdef V8_ENABLE_LEAPTIERING
void MacroAssembler::InvokeFunction(
    Register function, Register actual_parameter_count, InvokeType type,
    ArgumentAdaptionMode argument_adaption_mode) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK(type == InvokeType::kJump || has_frame());

  // Contract with called JS functions requires that function is passed in a1.
  // (See FullCodeGenerator::Generate().)
  DCHECK_EQ(function, a1);

  // Set up the context.
  LoadTaggedField(cp, FieldMemOperand(function, JSFunction::kContextOffset));

  InvokeFunctionCode(function, no_reg, actual_parameter_count, type,
                     argument_adaption_mode);
}

void MacroAssembler::InvokeFunctionWithNewTarget(
    Register function, Register new_target, Register actual_parameter_count,
    InvokeType type) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK(type == InvokeType::kJump || has_frame());

  // Contract with called JS functions requires that function is passed in a1.
  // (See FullCodeGenerator::Generate().)
  DCHECK_EQ(function, a1);

  LoadTaggedField(cp, FieldMemOperand(function, JSFunction::kContextOffset));

  InvokeFunctionCode(function, new_target, actual_parameter_count, type);
}

void MacroAssembler::InvokeFunctionCode(
    Register function, Register new_target, Register actual_parameter_count,
    InvokeType type, ArgumentAdaptionMode argument_adaption_mode) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());
  DCHECK_EQ(function, a1);
  DCHECK_IMPLIES(new_target.is_valid(), new_target == a3);

  Register dispatch_handle = kJavaScriptCallDispatchHandleRegister;
  Ld_w(dispatch_handle,
       FieldMemOperand(function, JSFunction::kDispatchHandleOffset));

  // On function call, call into the debugger if necessary.
  Label debug_hook, continue_after_hook;
  {
    li(t0, ExternalReference::debug_hook_on_function_call_address(isolate()));
    Ld_b(t0, MemOperand(t0, 0));
    BranchShort(&debug_hook, ne, t0, Operand(zero_reg));
  }
  bind(&continue_after_hook);

  // Clear the new.target register if not given.
  if (!new_target.is_valid()) {
    LoadRoot(a3, RootIndex::kUndefinedValue);
  }

  Register scratch = s1;
  if (argument_adaption_mode == ArgumentAdaptionMode::kAdapt) {
    Register expected_parameter_count = a2;
    LoadParameterCountFromJSDispatchTable(expected_parameter_count,
                                          dispatch_handle, scratch);
    InvokePrologue(expected_parameter_count, actual_parameter_count, type);
  }

  // We call indirectly through the code field in the function to
  // allow recompilation to take effect without changing any of the
  // call sites.
  LoadEntrypointFromJSDispatchTable(kJavaScriptCallCodeStartRegister,
                                    dispatch_handle, scratch);
  switch (type) {
    case InvokeType::kCall:
      Call(kJavaScriptCallCodeStartRegister);
      break;
    case InvokeType::kJump:
      Jump(kJavaScriptCallCodeStartRegister);
      break;
  }
  Label done;
  Branch(&done);

  // Deferred debug hook.
  bind(&debug_hook);
  CallDebugOnFunctionCall(function, new_target, dispatch_handle,
                          actual_parameter_count);
  Branch(&continue_after_hook);

  bind(&done);
}
#else
void MacroAssembler::InvokeFunctionCode(Register function, Register new_target,
                                        Register expected_parameter_count,
                                        Register actual_parameter_count,
                                        InvokeType type) {
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());
  DCHECK_EQ(function, a1);
  DCHECK_IMPLIES(new_target.is_valid(), new_target == a3);

  // On function call, call into the debugger if necessary.
  Label debug_hook, continue_after_hook;
  {
    li(t0, ExternalReference::debug_hook_on_function_call_address(isolate()));
    Ld_b(t0, MemOperand(t0, 0));
    BranchShort(&debug_hook, ne, t0, Operand(zero_reg));
  }
  bind(&continue_after_hook);

  // Clear the new.target register if not given.
  if (!new_target.is_valid()) {
    LoadRoot(a3, RootIndex::kUndefinedValue);
  }

  InvokePrologue(expected_parameter_count, actual_parameter_count, type);

  // We call indirectly through the code field in the function to
  // allow recompilation to take effect without changing any of the
  // call sites.
  constexpr int unused_argument_count = 0;
  switch (type) {
    case InvokeType::kCall:
      CallJSFunction(function, unused_argument_count);
      break;
    case InvokeType::kJump:
      JumpJSFunction(function);
      break;
  }

  Label done;
  Branch(&done);

  // Deferred debug hook.
  bind(&debug_hook);
  CallDebugOnFunctionCall(function, new_target, expected_parameter_count,
                          actual_parameter_count);
  Branch(&continue_after_hook);

  // Continue here if InvokePrologue does handle the invocation due to
  // mismatched parameter counts.
  bind(&done);
}

void MacroAssembler::InvokeFunctionWithNewTarget(
    Register function, Register new_target, Register actual_parameter_count,
    InvokeType type) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());

  // Contract with called JS functions requires that function is passed in a1.
  DCHECK_EQ(function, a1);
  Register expected_parameter_count = a2;
  Register temp_reg = t0;
  LoadTaggedField(temp_reg,
                  FieldMemOperand(a1, JSFunction::kSharedFunctionInfoOffset));
  LoadTaggedField(cp, FieldMemOperand(a1, JSFunction::kContextOffset));
  // The argument count is stored as uint16_t
  Ld_hu(expected_parameter_count,
        FieldMemOperand(temp_reg,
                        SharedFunctionInfo::kFormalParameterCountOffset));

  InvokeFunctionCode(a1, new_target, expected_parameter_count,
                     actual_parameter_count, type);
}

void MacroAssembler::InvokeFunction(Register function,
                                    Register expected_parameter_count,
                                    Register actual_parameter_count,
                                    InvokeType type) {
  ASM_CODE_COMMENT(this);
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());

  // Contract with called JS functions requires that function is passed in a1.
  DCHECK_EQ(function, a1);

  // Get the function and setup the context.
  LoadTaggedField(cp, FieldMemOperand(a1, JSFunction::kContextOffset));

  InvokeFunctionCode(a1, no_reg, expected_parameter_count,
                     actual_parameter_count, type);
}
#endif  // V8_ENABLE_LEAPTIERING

// ---------------------------------------------------------------------------
// Support functions.

void MacroAssembler::GetObjectType(Register object, Register map,
                                   Register type_reg) {
  LoadMap(map, object);
  Ld_hu(type_reg, FieldMemOperand(map, Map::kInstanceTypeOffset));
}

void MacroAssembler::GetInstanceTypeRange(Register map, Register type_reg,
                                          InstanceType lower_limit,
                                          Register range) {
  Ld_hu(type_reg, FieldMemOperand(map, Map::kInstanceTypeOffset));
  if (lower_limit != 0 || type_reg != range) {
    Sub_d(range, type_reg, Operand(lower_limit));
  }
}

// -----------------------------------------------------------------------------
// Runtime calls.

void MacroAssembler::AddOverflow_d(Register dst, Register left,
                                   const Operand& right, Register overflow) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Register scratch2 = temps.Acquire();
  Register right_reg = no_reg;
  if (!right.is_reg()) {
    li(scratch, Operand(right));
    right_reg = scratch;
  } else {
    right_reg = right.rm();
  }

  DCHECK(left != scratch2 && right_reg != scratch2 && dst != scratch2 &&
         overflow != scratch2);
  DCHECK(overflow != left && overflow != right_reg);

  if (dst == left || dst == right_reg) {
    add_d(scratch2, left, right_reg);
    xor_(overflow, scratch2, left);
    xor_(scratch, scratch2, right_reg);
    and_(overflow, overflow, scratch);
    mov(dst, scratch2);
  } else {
    add_d(dst, left, right_reg);
    xor_(overflow, dst, left);
    xor_(scratch, dst, right_reg);
    and_(overflow, overflow, scratch);
  }
}

void MacroAssembler::SubOverflow_d(Register dst, Register left,
                                   const Operand& right, Register overflow) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Register scratch2 = temps.Acquire();
  Register right_reg = no_reg;
  if (!right.is_reg()) {
    li(scratch, Operand(right));
    right_reg = scratch;
  } else {
    right_reg = right.rm();
  }

  DCHECK(left != scratch2 && right_reg != scratch2 && dst != scratch2 &&
         overflow != scratch2);
  DCHECK(overflow != left && overflow != right_reg);

  if (dst == left || dst == right_reg) {
    Sub_d(scratch2, left, right_reg);
    xor_(overflow, left, scratch2);
    xor_(scratch, left, right_reg);
    and_(overflow, overflow, scratch);
    mov(dst, scratch2);
  } else {
    sub_d(dst, left, right_reg);
    xor_(overflow, left, dst);
    xor_(scratch, left, right_reg);
    and_(overflow, overflow, scratch);
  }
}

void MacroAssembler::MulOverflow_w(Register dst, Register left,
                                   const Operand& right, Register overflow) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Register scratch2 = temps.Acquire();
  Register right_reg = no_reg;
  if (!right.is_reg()) {
    li(scratch, Operand(right));
    right_reg = scratch;
  } else {
    right_reg = right.rm();
  }

  DCHECK(left != scratch2 && right_reg != scratch2 && dst != scratch2 &&
         overflow != scratch2);
  DCHECK(overflow != left && overflow != right_reg);

  if (dst == left || dst == right_reg) {
    Mul_w(scratch2, left, right_reg);
    Mulh_w(overflow, left, right_reg);
    mov(dst, scratch2);
  } else {
    Mul_w(dst, left, right_reg);
    Mulh_w(overflow, left, right_reg);
  }

  srai_d(scratch2, dst, 32);
  xor_(overflow, overflow, scratch2);
}

void MacroAssembler::MulOverflow_d(Register dst, Register left,
                                   const Operand& right, Register overflow) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Register scratch2 = temps.Acquire();
  Register right_reg = no_reg;
  if (!right.is_reg()) {
    li(scratch, Operand(right));
    right_reg = scratch;
  } else {
    right_reg = right.rm();
  }

  DCHECK(left != scratch2 && right_reg != scratch2 && dst != scratch2 &&
         overflow != scratch2);
  DCHECK(overflow != left && overflow != right_reg);

  if (dst == left || dst == right_reg) {
    Mul_d(scratch2, left, right_reg);
    Mulh_d(overflow, left, right_reg);
    mov(dst, scratch2);
  } else {
    Mul_d(dst, left, right_reg);
    Mulh_d(overflow, left, right_reg);
  }

  srai_d(scratch2, dst, 63);
  xor_(overflow, overflow, scratch2);
}

void MacroAssembler::CallRuntime(const Runtime::Function* f,
                                 int num_arguments) {
  ASM_CODE_COMMENT(this);
  // All parameters are on the stack. v0 has the return value after call.

  // If the expected number of arguments of the runtime function is
  // constant, we check that the actual number of arguments match the
  // expectation.
  CHECK(f->nargs < 0 || f->nargs == num_arguments);

  // TODO(1236192): Most runtime routines don't need the number of
  // arguments passed in because it is constant. At some point we
  // should remove this need and make the runtime routine entry code
  // smarter.
  PrepareCEntryArgs(num_arguments);
  PrepareCEntryFunction(ExternalReference::Create(f));
  CallBuiltin(Builtins::RuntimeCEntry(f->result_size));
}

void MacroAssembler::TailCallRuntime(Runtime::FunctionId fid) {
  ASM_CODE_COMMENT(this);
  const Runtime::Function* function = Runtime::FunctionForId(fid);
  DCHECK_EQ(1, function->result_size);
  if (function->nargs >= 0) {
    PrepareCEntryArgs(function->nargs);
  }
  JumpToExternalReference(ExternalReference::Create(fid));
}

void MacroAssembler::JumpToExternalReference(const ExternalReference& builtin,
                                             bool builtin_exit_frame) {
  PrepareCEntryFunction(builtin);
  TailCallBuiltin(Builtins::CEntry(1, ArgvMode::kStack, builtin_exit_frame));
}

void MacroAssembler::LoadWeakValue(Register out, Register in,
                                   Label* target_if_cleared) {
  CompareTaggedAndBranch(target_if_cleared, eq, in,
                         Operand(kClearedWeakHeapObjectLower32));
  And(out, in, Operand(~kWeakHeapObjectMask));
}

void MacroAssembler::EmitIncrementCounter(StatsCounter* counter, int value,
                                          Register scratch1,
                                          Register scratch2) {
  DCHECK_GT(value, 0);
  if (v8_flags.native_code_counters && counter->Enabled()) {
    ASM_CODE_COMMENT(this);
    // This operation has to be exactly 32-bit wide in case the external
    // reference table redirects the counter to a uint32_t dummy_stats_counter_
    // field.
    li(scratch2, ExternalReference::Create(counter));
    Ld_w(scratch1, MemOperand(scratch2, 0));
    Add_w(scratch1, scratch1, Operand(value));
    St_w(scratch1, MemOperand(scratch2, 0));
  }
}

void MacroAssembler::EmitDecrementCounter(StatsCounter* counter, int value,
                                          Register scratch1,
                                          Register scratch2) {
  DCHECK_GT(value, 0);
  if (v8_flags.native_code_counters && counter->Enabled()) {
    ASM_CODE_COMMENT(this);
    // This operation has to be exactly 32-bit wide in case the external
    // reference table redirects the counter to a uint32_t dummy_stats_counter_
    // field.
    li(scratch2, ExternalReference::Create(counter));
    Ld_w(scratch1, MemOperand(scratch2, 0));
    Sub_w(scratch1, scratch1, Operand(value));
    St_w(scratch1, MemOperand(scratch2, 0));
  }
}

// -----------------------------------------------------------------------------
// Debugging.

void MacroAssembler::Trap() { stop(); }
void MacroAssembler::DebugBreak() { stop(); }

void MacroAssembler::Check(Condition cc, AbortReason reason, Register rj,
                           Operand rk) {
  Label L;
  Branch(&L, cc, rj, rk);
  Abort(reason);
  // Will not return here.
  bind(&L);
}

void MacroAssembler::SbxCheck(Condition cc, AbortReason reason, Register rj,
                              Operand rk) {
  Check(cc, reason, rj, rk);
}

void MacroAssembler::Abort(AbortReason reason) {
  Label abort_start;
  bind(&abort_start);
  if (v8_flags.code_comments) {
    const char* msg = GetAbortReason(reason);
    RecordComment("Abort message: ");
    RecordComment(msg);
  }

  // Avoid emitting call to builtin if requested.
  if (trap_on_abort()) {
    stop();
    return;
  }

  if (should_abort_hard()) {
    // We don't care if we constructed a frame. Just pretend we did.
    FrameScope assume_frame(this, StackFrame::NO_FRAME_TYPE);
    PrepareCallCFunction(1, a0);
    li(a0, Operand(static_cast<int>(reason)));
    li(a1, ExternalReference::abort_with_reason());
    // Use Call directly to avoid any unneeded overhead. The function won't
    // return anyway.
    Call(a1);
    return;
  }

  Move(a0, Smi::FromInt(static_cast<int>(reason)));

  {
    // We don't actually want to generate a pile of code for this, so just
    // claim there is a stack frame, without generating one.
    FrameScope scope(this, StackFrame::NO_FRAME_TYPE);
    if (root_array_available()) {
      // Generate an indirect call via builtins entry table here in order to
      // ensure that the interpreter_entry_return_pc_offset is the same for
      // InterpreterEntryTrampoline and InterpreterEntryTrampolineForProfiling
      // when v8_flags.debug_code is enabled.
      LoadEntryFromBuiltin(Builtin::kAbort, t7);
      Call(t7);
    } else {
      CallBuiltin(Builtin::kAbort);
    }
  }

  // Will not return here.
  if (is_trampoline_pool_blocked()) {
    // If the calling code cares about the exact number of
    // instructions generated, we insert padding here to keep the size
    // of the Abort macro constant.
    // Currently in debug mode with debug_code enabled the number of
    // generated instructions is 10, so we use this as a maximum value.
    static const int kExpectedAbortInstructions = 10;
    int abort_instructions = InstructionsGeneratedSince(&abort_start);
    DCHECK_LE(abort_instructions, kExpectedAbortInstructions);
    while (abort_instructions++ < kExpectedAbortInstructions) {
      nop();
    }
  }
}

void MacroAssembler::LoadMap(Register destination, Register object) {
  LoadTaggedField(destination, FieldMemOperand(object, HeapObject::kMapOffset));
}

void MacroAssembler::LoadCompressedMap(Register dst, Register object) {
  ASM_CODE_COMMENT(this);
  Ld_w(dst, FieldMemOperand(object, HeapObject::kMapOffset));
}

void MacroAssembler::LoadFeedbackVector(Register dst, Register closure,
                                        Register scratch, Label* fbv_undef) {
  Label done;
  // Load the feedback vector from the closure.
  LoadTaggedField(dst,
                  FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
  LoadTaggedField(dst, FieldMemOperand(dst, FeedbackCell::kValueOffset));

  // Check if feedback vector is valid.
  LoadTaggedField(scratch, FieldMemOperand(dst, HeapObject::kMapOffset));
  Ld_hu(scratch, FieldMemOperand(scratch, Map::kInstanceTypeOffset));
  Branch(&done, eq, scratch, Operand(FEEDBACK_VECTOR_TYPE));

  // Not valid, load undefined.
  LoadRoot(dst, RootIndex::kUndefinedValue);
  Branch(fbv_undef);

  bind(&done);
}

void MacroAssembler::LoadNativeContextSlot(Register dst, int index) {
  LoadMap(dst, cp);
  LoadTaggedField(
      dst, FieldMemOperand(
               dst, Map::kConstructorOrBackPointerOrNativeContextOffset));
  LoadTaggedField(dst, MemOperand(dst, Context::SlotOffset(index)));
}

void MacroAssembler::StubPrologue(StackFrame::Type type) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  li(scratch, Operand(StackFrame::TypeToMarker(type)));
  PushCommonFrame(scratch);
}

void MacroAssembler::Prologue() { PushStandardFrame(a1); }

void MacroAssembler::EnterFrame(StackFrame::Type type) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Push(ra, fp);
  Move(fp, sp);
  if (!StackFrame::IsJavaScript(type)) {
    li(kScratchReg, Operand(StackFrame::TypeToMarker(type)));
    Push(kScratchReg);
  }
#if V8_ENABLE_WEBASSEMBLY
  if (type == StackFrame::WASM || type == StackFrame::WASM_LIFTOFF_SETUP) {
    Push(kWasmImplicitArgRegister);
  }
#endif  // V8_ENABLE_WEBASSEMBLY
}

void MacroAssembler::LeaveFrame(StackFrame::Type type) {
  ASM_CODE_COMMENT(this);
  addi_d(sp, fp, 2 * kSystemPointerSize);
  Ld_d(ra, MemOperand(fp, 1 * kSystemPoin
```