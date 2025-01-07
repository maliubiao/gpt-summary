Response:
The user wants a summary of the functionality of the provided C++ code snippet from V8. I need to analyze the code and identify its main purposes.

Here's a breakdown of the code's functionalities:

1. **Stack Frame Management:** Functions like `EnterFrame`, `LeaveFrame`, `EnterExitFrame`, and `LeaveExitFrame` manage the stack when entering and exiting different types of function calls (JavaScript and C++). This involves saving and restoring registers (like the frame pointer `fp`, stack pointer `sp`, and return address `ra`), and setting up the stack layout.
2. **Smi Handling:** Functions like `SmiUntag`, `JumpIfSmi`, and `JumpIfNotSmi` deal with Smis (small integers), a special tagged representation used in V8 for efficiency. These functions check if a value is a Smi and convert between tagged and untagged representations.
3. **Object Type Checking:**  Functions like `JumpIfObjectType` and `JumpIfJSAnyIsNotPrimitive` help determine the type of JavaScript objects. They compare the object's `InstanceType` against specific values.
4. **Assertions (Debug Code):** The code includes many `Assert` functions that are active in debug builds. These functions perform runtime checks to ensure the program's assumptions are correct, helping to catch bugs early.
5. **Floating-Point Operations:** `Float32Max`, `Float32Min`, `Float64Max`, and `Float64Min` implement the maximum and minimum operations for single and double-precision floating-point numbers, handling NaN cases.
6. **Calling C Functions:** `PrepareCallCFunction` and `CallCFunction` handle calling native C++ functions from V8-generated code, managing argument passing and stack alignment.
7. **Code Object Handling:** Functions like `ComputeCodeStartAddress`, `CallCodeObject`, and `JumpCodeObject` work with `Code` objects, which represent compiled JavaScript code. They load the start address of the executable code and perform calls or jumps.
8. **JavaScript Function Calls:** `CallJSFunction` and `JumpJSFunction` are specifically for calling JavaScript functions, potentially utilizing optimized code or dispatch tables.
9. **Tail Calls:** The `GenerateTailCallToReturnedCode` function helps implement tail call optimization, a performance technique.
10. **Feedback Vector and Closure Management:**  Functions like `ReplaceClosureCodeWithOptimizedCode` are involved in optimization, potentially replacing a function's original code with optimized versions and managing feedback vectors.
11. **Page Flag Checking:** `CheckPageFlag` likely checks flags associated with memory pages, which can be related to garbage collection or memory management.

Considering the user's prompt, I need to:

*   List the functionalities.
*   Confirm it's not Torque code (it's C++).
*   Provide JavaScript examples where applicable (relating to function calls, object types, Smis).
*   Give a simple code logic推理 example.
*   Illustrate a common programming error.
*   Summarize the overall function of this part.
这是一个V8源代码文件，路径为 `v8/src/codegen/loong64/macro-assembler-loong64.cc`。它不是以 `.tq` 结尾，所以不是V8 Torque源代码。

以下是 `v8/src/codegen/loong64/macro-assembler-loong64.cc` 代码片段的功能归纳：

**核心功能：LoongArch64架构的宏汇编器**

这个代码片段是V8 JavaScript引擎中，用于LoongArch64 (龙芯64) 架构的**宏汇编器 (MacroAssembler)** 的实现。宏汇编器是V8代码生成器的重要组成部分，它提供了一组高级接口，用于生成底层的机器码指令。  相比直接编写汇编指令，使用宏汇编器可以提高代码的可读性和可维护性。

**具体功能点：**

1. **栈帧管理 (Stack Frame Management):**
    *   `EnterFrame()` 和 `LeaveFrame()`: 用于在函数调用时设置和清理标准栈帧。
    *   `EnterExitFrame()`:  用于进入从 JavaScript 代码调用 C++ 代码的出口帧 (Exit Frame)。它保存必要的寄存器，设置新的帧指针，并为运行时调用准备栈空间。
    *   `LeaveExitFrame()`: 用于离开出口帧，恢复上下文和寄存器。

2. **Smi (Small Integer) 处理:**
    *   `SmiUntag()`: 将 Smi 类型的值转换为其原始的整数值。
    *   `JumpIfSmi()`: 如果寄存器中的值是 Smi，则跳转到指定标签。
    *   `JumpIfNotSmi()`: 如果寄存器中的值不是 Smi，则跳转到指定标签。

3. **对象类型检查 (Object Type Checking):**
    *   `JumpIfObjectType()`:  检查对象的类型是否与给定的 `instance_type` 匹配，并根据条件跳转。
    *   `JumpIfJSAnyIsNotPrimitive()`: 检查一个值是否是非原始类型的 JavaScript 对象。

4. **断言 (Assertions - 仅在 Debug 模式下):**
    *   提供了大量的 `Assert...()` 函数，用于在开发和调试阶段检查代码的假设是否成立。例如，`AssertNotSmi()`, `AssertSmi()`, `AssertStackIsAligned()`, `AssertConstructor()`, `AssertFunction()` 等。这些断言有助于尽早发现潜在的错误。

5. **浮点数操作 (Floating-Point Operations):**
    *   `Float32Max()`, `Float32Min()`, `Float64Max()`, `Float64Min()`:  实现了浮点数的最大值和最小值操作，并考虑了 NaN (非数字) 的情况。

6. **调用 C 函数 (Calling C Functions):**
    *   `PrepareCallCFunction()`:  为调用 C 函数准备栈空间和参数。
    *   `CallCFunction()`: 生成调用 C 函数的代码，并处理参数传递和栈对齐。

7. **代码对象处理 (Code Object Handling):**
    *   `ComputeCodeStartAddress()`: 计算代码的起始地址。
    *   `CallCodeObject()`: 调用一个 `Code` 对象（表示编译后的 JavaScript 代码）。
    *   `JumpCodeObject()`: 跳转到一个 `Code` 对象。
    *   `LoadCodeInstructionStart()`: 加载 `Code` 对象的指令起始地址。

8. **调用 JavaScript 函数 (Calling JavaScript Functions):**
    *   `CallJSFunction()`: 生成调用 JavaScript 函数的代码。根据配置，可能会使用 LeapTiering 优化或直接从 `Code` 对象加载入口点。
    *   `JumpJSFunction()`: 跳转到 JavaScript 函数。

9. **尾调用优化 (Tail Call Optimization):**
    *   `GenerateTailCallToReturnedCode()`:  实现尾调用优化，避免不必要的栈帧创建。

10. **反馈单元和闭包管理 (Feedback Cell and Closure Management):**
    *   `ReplaceClosureCodeWithOptimizedCode()`:  在优化过程中，将闭包中的代码替换为优化后的代码。

11. **页标志检查 (Page Flag Checking):**
    *   `CheckPageFlag()`: 检查内存页的特定标志位，可能用于垃圾回收或其他内存管理相关的操作。

**与 JavaScript 功能的关系 (JavaScript Examples):**

*   **栈帧管理:** 当 JavaScript 函数被调用时，V8 内部会创建栈帧来存储局部变量和函数调用的上下文。`EnterFrame` 和 `LeaveFrame` 等函数就参与了这个过程。

    ```javascript
    function foo(a, b) {
      let sum = a + b;
      return sum;
    }

    foo(1, 2); // 调用 foo 函数时会创建栈帧
    ```

*   **Smi 处理:** JavaScript 中的小整数会被表示为 Smis 以提高性能。

    ```javascript
    let smallNumber = 10; // 10 可能在 V8 内部以 Smi 的形式表示

    if (smallNumber < 100) { // V8 需要判断 smallNumber 是否是 Smi
      // ...
    }
    ```

*   **对象类型检查:**  JavaScript 中变量的类型是动态的，V8 需要在运行时检查对象的类型。

    ```javascript
    function processObject(obj) {
      if (typeof obj === 'string') {
        console.log("It's a string");
      } else if (typeof obj === 'number') {
        console.log("It's a number");
      } else if (obj instanceof Array) {
        console.log("It's an array");
      }
    }

    processObject("hello");
    processObject(123);
    processObject([1, 2, 3]);
    ```
    V8 内部会使用类似 `JumpIfObjectType` 的机制来快速判断对象的类型。

*   **调用 C 函数:**  当 JavaScript 代码调用内置的 C++ 函数（例如 `Math.sqrt()`）或通过 Native Node.js Addons 调用 C++ 代码时，`CallCFunction` 就发挥作用。

    ```javascript
    Math.sqrt(9); // 调用内置的 C++ sqrt 函数

    // (假设有一个 Native Node.js Addon)
    const addon = require('./my-addon');
    addon.myFunction(); // 调用 Addon 中定义的 C++ 函数
    ```

*   **调用 JavaScript 函数:** 当一个 JavaScript 函数被调用时，`CallJSFunction` 负责生成相应的机器码来执行该函数。

    ```javascript
    function bar() {
      console.log("Inside bar");
    }

    function baz() {
      bar(); // 调用 JavaScript 函数 bar
    }

    baz();
    ```

**代码逻辑推理示例 (假设输入与输出):**

假设 `EnterExitFrame` 函数被调用，`scratch` 寄存器为 `t0`，`stack_space` 为 16 (字节)，`frame_type` 为 `StackFrame::EXIT`。

**输入:**

*   `scratch`: `t0`
*   `stack_space`: 16
*   `frame_type`: `StackFrame::EXIT`

**执行的逻辑 (部分):**

1. 计算需要分配的栈空间: `2 * kSystemPointerSize + ExitFrameConstants::kFixedFrameSizeFromFp` 加上 `stack_space` 和对齐。
2. 调整栈指针 `sp`，为保存寄存器和出口帧信息预留空间。
3. 将返回地址 `ra` 和帧指针 `fp` 保存到栈上。
4. 将表示 `StackFrame::EXIT` 类型的标记值加载到 `t0` 寄存器。
5. 将 `t0` 寄存器的值存储到栈上，作为帧类型标记。
6. 设置新的帧指针 `fp`。
7. 将当前的帧指针 `fp` 和上下文 `cp` 保存到特定的内存位置。
8. 再次调整栈指针 `sp`，为运行时函数调用预留空间并进行对齐。
9. 将出口帧的 `sp` 值存储到当前帧。

**输出 (栈状态的改变 - 抽象表示):**

栈顶 (`sp` 指向的位置) 会向下移动，并且栈上会存储以下信息 (从高地址到低地址):

*   旧的栈顶 (在某些情况下)
*   旧的返回地址 (`ra`)
*   旧的帧指针 (`fp`)
*   帧类型标记 (`StackFrame::EXIT`)
*   出口帧的 `sp` 值
*   为运行时调用预留的空间 (大小取决于 `stack_space`)

**用户常见的编程错误举例:**

*   **栈溢出 (Stack Overflow):** 如果在 JavaScript 代码中发生无限递归调用，可能会导致栈空间耗尽，最终触发错误。V8 的栈帧管理机制会在一定程度上防止这种情况，但过深的递归仍然会导致问题。

    ```javascript
    function recursiveFunction() {
      recursiveFunction(); // 无限递归
    }

    recursiveFunction(); // 可能导致栈溢出
    ```

*   **类型错误 (Type Errors):**  在 JavaScript 中，错误地假设变量的类型可能导致运行时错误。V8 的对象类型检查机制会在运行时进行类型判断，如果类型不符合预期，可能会抛出异常。

    ```javascript
    function processNumber(num) {
      return num.toUpperCase(); // 假设 num 是字符串，但如果传入数字会出错
    }

    processNumber(10); // TypeError: num.toUpperCase is not a function
    ```

**本部分功能归纳 (第 5 部分):**

作为宏汇编器实现的一部分，这段代码主要负责处理函数调用和返回过程中的底层细节，包括栈帧的建立和清理，以及与 C++ 代码交互时的上下文切换。它还提供了用于类型检查、Smi 处理和浮点数操作的基础指令，并包含用于调试的断言机制。 这部分代码是 V8 代码生成器的核心组件，确保了在 LoongArch64 架构上高效地执行 JavaScript 代码。

Prompt: 
```
这是目录为v8/src/codegen/loong64/macro-assembler-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/loong64/macro-assembler-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能

"""
terSize));
  Ld_d(fp, MemOperand(fp, 0 * kSystemPointerSize));
}

void MacroAssembler::EnterExitFrame(Register scratch, int stack_space,
                                    StackFrame::Type frame_type) {
  ASM_CODE_COMMENT(this);
  DCHECK(frame_type == StackFrame::EXIT ||
         frame_type == StackFrame::BUILTIN_EXIT ||
         frame_type == StackFrame::API_ACCESSOR_EXIT ||
         frame_type == StackFrame::API_CALLBACK_EXIT);

  using ER = ExternalReference;

  // Set up the frame structure on the stack.
  static_assert(2 * kSystemPointerSize ==
                ExitFrameConstants::kCallerSPDisplacement);
  static_assert(1 * kSystemPointerSize == ExitFrameConstants::kCallerPCOffset);
  static_assert(0 * kSystemPointerSize == ExitFrameConstants::kCallerFPOffset);

  // This is how the stack will look:
  // fp + 2 (==kCallerSPDisplacement) - old stack's end
  // [fp + 1 (==kCallerPCOffset)] - saved old ra
  // [fp + 0 (==kCallerFPOffset)] - saved old fp
  // [fp - 1 frame_type Smi
  // [fp - 2 (==kSPOffset)] - sp of the called function
  // fp - (2 + stack_space + alignment) == sp == [fp - kSPOffset] - top of the
  //   new stack (will contain saved ra)

  // Save registers and reserve room for saved entry sp.
  addi_d(sp, sp,
         -2 * kSystemPointerSize - ExitFrameConstants::kFixedFrameSizeFromFp);
  St_d(ra, MemOperand(sp, 3 * kSystemPointerSize));
  St_d(fp, MemOperand(sp, 2 * kSystemPointerSize));
  li(scratch, Operand(StackFrame::TypeToMarker(frame_type)));
  St_d(scratch, MemOperand(sp, 1 * kSystemPointerSize));

  // Set up new frame pointer.
  addi_d(fp, sp, ExitFrameConstants::kFixedFrameSizeFromFp);

  if (v8_flags.debug_code) {
    St_d(zero_reg, MemOperand(fp, ExitFrameConstants::kSPOffset));
  }

  // Save the frame pointer and the context in top.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, isolate());
  St_d(fp, ExternalReferenceAsOperand(c_entry_fp_address, no_reg));

  ER context_address = ER::Create(IsolateAddressId::kContextAddress, isolate());
  St_d(cp, ExternalReferenceAsOperand(context_address, no_reg));

  const int frame_alignment = MacroAssembler::ActivationFrameAlignment();

  // Reserve place for the return address, stack space and align the frame
  // preparing for calling the runtime function.
  DCHECK_GE(stack_space, 0);
  Sub_d(sp, sp, Operand((stack_space + 1) * kSystemPointerSize));
  if (frame_alignment > 0) {
    DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
    And(sp, sp, Operand(-frame_alignment));  // Align stack.
  }

  // Set the exit frame sp value to point just before the return address
  // location.
  addi_d(scratch, sp, kSystemPointerSize);
  St_d(scratch, MemOperand(fp, ExitFrameConstants::kSPOffset));
}

void MacroAssembler::LeaveExitFrame(Register scratch) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);

  using ER = ExternalReference;

  // Restore current context from top and clear it in debug mode.
  ER context_address = ER::Create(IsolateAddressId::kContextAddress, isolate());
  Ld_d(cp, ExternalReferenceAsOperand(context_address, no_reg));

  if (v8_flags.debug_code) {
    li(scratch, Operand(Context::kInvalidContext));
    St_d(scratch, ExternalReferenceAsOperand(context_address, no_reg));
  }

  // Clear the top frame.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, isolate());
  St_d(zero_reg, ExternalReferenceAsOperand(c_entry_fp_address, no_reg));

  // Pop the arguments, restore registers, and return.
  mov(sp, fp);  // Respect ABI stack constraint.
  Ld_d(fp, MemOperand(sp, ExitFrameConstants::kCallerFPOffset));
  Ld_d(ra, MemOperand(sp, ExitFrameConstants::kCallerPCOffset));
  addi_d(sp, sp, 2 * kSystemPointerSize);
}

int MacroAssembler::ActivationFrameAlignment() {
#if V8_HOST_ARCH_LOONG64
  // Running on the real platform. Use the alignment as mandated by the local
  // environment.
  // Note: This will break if we ever start generating snapshots on one LOONG64
  // platform for another LOONG64 platform with a different alignment.
  return base::OS::ActivationFrameAlignment();
#else   // V8_HOST_ARCH_LOONG64
  // If we are using the simulator then we should always align to the expected
  // alignment. As the simulator is used to generate snapshots we do not know
  // if the target platform will need alignment, so this is controlled from a
  // flag.
  return v8_flags.sim_stack_alignment;
#endif  // V8_HOST_ARCH_LOONG64
}

void MacroAssembler::SmiUntag(Register dst, const MemOperand& src) {
  if (SmiValuesAre32Bits()) {
    Ld_w(dst, MemOperand(src.base(), SmiWordOffset(src.offset())));
  } else {
    DCHECK(SmiValuesAre31Bits());
    if (COMPRESS_POINTERS_BOOL) {
      Ld_w(dst, src);
    } else {
      Ld_d(dst, src);
    }
    SmiUntag(dst);
  }
}

void MacroAssembler::JumpIfSmi(Register value, Label* smi_label) {
  DCHECK_EQ(0, kSmiTag);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  andi(scratch, value, kSmiTagMask);
  Branch(smi_label, eq, scratch, Operand(zero_reg));
}

void MacroAssembler::JumpIfNotSmi(Register value, Label* not_smi_label) {
  DCHECK_EQ(0, kSmiTag);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  andi(scratch, value, kSmiTagMask);
  Branch(not_smi_label, ne, scratch, Operand(zero_reg));
}

void MacroAssembler::JumpIfObjectType(Label* target, Condition cc,
                                      Register object,
                                      InstanceType instance_type,
                                      Register scratch) {
  DCHECK(cc == eq || cc == ne);
  UseScratchRegisterScope temps(this);
  if (scratch == no_reg) {
    scratch = temps.Acquire();
  }
  if (V8_STATIC_ROOTS_BOOL) {
    if (std::optional<RootIndex> expected =
            InstanceTypeChecker::UniqueMapOfInstanceType(instance_type)) {
      Tagged_t ptr = ReadOnlyRootPtr(*expected);
      LoadCompressedMap(scratch, object);
      Branch(target, cc, scratch, Operand(ptr));
      return;
    }
  }
  GetObjectType(object, scratch, scratch);
  Branch(target, cc, scratch, Operand(instance_type));
}

void MacroAssembler::JumpIfJSAnyIsNotPrimitive(Register heap_object,
                                               Register scratch, Label* target,
                                               Label::Distance distance,
                                               Condition cc) {
  CHECK(cc == Condition::kUnsignedLessThan ||
        cc == Condition::kUnsignedGreaterThanEqual);
  if (V8_STATIC_ROOTS_BOOL) {
#ifdef DEBUG
    Label ok;
    LoadMap(scratch, heap_object);
    GetInstanceTypeRange(scratch, scratch, FIRST_JS_RECEIVER_TYPE, scratch);
    Branch(&ok, Condition::kUnsignedLessThanEqual, scratch,
           Operand(LAST_JS_RECEIVER_TYPE - FIRST_JS_RECEIVER_TYPE));

    LoadMap(scratch, heap_object);
    GetInstanceTypeRange(scratch, scratch, FIRST_PRIMITIVE_HEAP_OBJECT_TYPE,
                         scratch);
    Branch(&ok, Condition::kUnsignedLessThanEqual, scratch,
           Operand(LAST_PRIMITIVE_HEAP_OBJECT_TYPE -
                   FIRST_PRIMITIVE_HEAP_OBJECT_TYPE));

    Abort(AbortReason::kInvalidReceiver);
    bind(&ok);
#endif  // DEBUG

    // All primitive object's maps are allocated at the start of the read only
    // heap. Thus JS_RECEIVER's must have maps with larger (compressed)
    // addresses.
    LoadCompressedMap(scratch, heap_object);
    Branch(target, cc, scratch,
           Operand(InstanceTypeChecker::kNonJsReceiverMapLimit));
  } else {
    static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
    GetObjectType(heap_object, scratch, scratch);
    Branch(target, cc, scratch, Operand(FIRST_JS_RECEIVER_TYPE));
  }
}

#ifdef V8_ENABLE_DEBUG_CODE

void MacroAssembler::Assert(Condition cc, AbortReason reason, Register rs,
                            Operand rk) {
  if (v8_flags.debug_code) Check(cc, reason, rs, rk);
}

void MacroAssembler::AssertJSAny(Register object, Register map_tmp,
                                 Register tmp, AbortReason abort_reason) {
  if (!v8_flags.debug_code) return;

  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(object, map_tmp, tmp));
  Label ok;

  JumpIfSmi(object, &ok);

  GetObjectType(object, map_tmp, tmp);

  Branch(&ok, kUnsignedLessThanEqual, tmp, Operand(LAST_NAME_TYPE));

  Branch(&ok, kUnsignedGreaterThanEqual, tmp, Operand(FIRST_JS_RECEIVER_TYPE));

  Branch(&ok, kEqual, map_tmp, RootIndex::kHeapNumberMap);

  Branch(&ok, kEqual, map_tmp, RootIndex::kBigIntMap);

  Branch(&ok, kEqual, object, RootIndex::kUndefinedValue);

  Branch(&ok, kEqual, object, RootIndex::kTrueValue);

  Branch(&ok, kEqual, object, RootIndex::kFalseValue);

  Branch(&ok, kEqual, object, RootIndex::kNullValue);

  Abort(abort_reason);
  bind(&ok);
}

void MacroAssembler::AssertNotSmi(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    static_assert(kSmiTag == 0);
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    andi(scratch, object, kSmiTagMask);
    Check(ne, AbortReason::kOperandIsASmi, scratch, Operand(zero_reg));
  }
}

void MacroAssembler::AssertSmi(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    static_assert(kSmiTag == 0);
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    andi(scratch, object, kSmiTagMask);
    Check(eq, AbortReason::kOperandIsASmi, scratch, Operand(zero_reg));
  }
}

void MacroAssembler::AssertStackIsAligned() {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    const int frame_alignment = ActivationFrameAlignment();
    const int frame_alignment_mask = frame_alignment - 1;

    if (frame_alignment > kSystemPointerSize) {
      Label alignment_as_expected;
      DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
      {
        UseScratchRegisterScope temps(this);
        Register scratch = temps.Acquire();
        andi(scratch, sp, frame_alignment_mask);
        Branch(&alignment_as_expected, eq, scratch, Operand(zero_reg));
      }
      // Don't use Check here, as it will call Runtime_Abort re-entering here.
      stop();
      bind(&alignment_as_expected);
    }
  }
}

void MacroAssembler::AssertConstructor(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    static_assert(kSmiTag == 0);
    SmiTst(object, t8);
    Check(ne, AbortReason::kOperandIsASmiAndNotAConstructor, t8,
          Operand(zero_reg));

    LoadMap(t8, object);
    Ld_bu(t8, FieldMemOperand(t8, Map::kBitFieldOffset));
    And(t8, t8, Operand(Map::Bits1::IsConstructorBit::kMask));
    Check(ne, AbortReason::kOperandIsNotAConstructor, t8, Operand(zero_reg));
  }
}

void MacroAssembler::AssertFunction(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    static_assert(kSmiTag == 0);
    SmiTst(object, t8);
    Check(ne, AbortReason::kOperandIsASmiAndNotAFunction, t8,
          Operand(zero_reg));
    Push(object);
    LoadMap(object, object);
    GetInstanceTypeRange(object, object, FIRST_JS_FUNCTION_TYPE, t8);
    Check(ls, AbortReason::kOperandIsNotAFunction, t8,
          Operand(LAST_JS_FUNCTION_TYPE - FIRST_JS_FUNCTION_TYPE));
    Pop(object);
  }
}

void MacroAssembler::AssertCallableFunction(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    static_assert(kSmiTag == 0);
    SmiTst(object, t8);
    Check(ne, AbortReason::kOperandIsASmiAndNotAFunction, t8,
          Operand(zero_reg));
    Push(object);
    LoadMap(object, object);
    GetInstanceTypeRange(object, object, FIRST_CALLABLE_JS_FUNCTION_TYPE, t8);
    Check(ls, AbortReason::kOperandIsNotACallableFunction, t8,
          Operand(LAST_CALLABLE_JS_FUNCTION_TYPE -
                  FIRST_CALLABLE_JS_FUNCTION_TYPE));
    Pop(object);
  }
}

void MacroAssembler::AssertBoundFunction(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    static_assert(kSmiTag == 0);
    SmiTst(object, t8);
    Check(ne, AbortReason::kOperandIsASmiAndNotABoundFunction, t8,
          Operand(zero_reg));
    GetObjectType(object, t8, t8);
    Check(eq, AbortReason::kOperandIsNotABoundFunction, t8,
          Operand(JS_BOUND_FUNCTION_TYPE));
  }
}

void MacroAssembler::AssertGeneratorObject(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  static_assert(kSmiTag == 0);
  SmiTst(object, t8);
  Check(ne, AbortReason::kOperandIsASmiAndNotAGeneratorObject, t8,
        Operand(zero_reg));
  GetObjectType(object, t8, t8);
  Sub_d(t8, t8, Operand(FIRST_JS_GENERATOR_OBJECT_TYPE));
  Check(
      ls, AbortReason::kOperandIsNotAGeneratorObject, t8,
      Operand(LAST_JS_GENERATOR_OBJECT_TYPE - FIRST_JS_GENERATOR_OBJECT_TYPE));
}

void MacroAssembler::AssertUnreachable(AbortReason reason) {
  if (v8_flags.debug_code) Abort(reason);
}

void MacroAssembler::AssertUndefinedOrAllocationSite(Register object,
                                                     Register scratch) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    Label done_checking;
    AssertNotSmi(object);
    LoadRoot(scratch, RootIndex::kUndefinedValue);
    Branch(&done_checking, eq, object, Operand(scratch));
    GetObjectType(object, scratch, scratch);
    Assert(eq, AbortReason::kExpectedUndefinedOrCell, scratch,
           Operand(ALLOCATION_SITE_TYPE));
    bind(&done_checking);
  }
}

#endif  // V8_ENABLE_DEBUG_CODE

void MacroAssembler::Float32Max(FPURegister dst, FPURegister src1,
                                FPURegister src2, Label* out_of_line) {
  ASM_CODE_COMMENT(this);
  if (src1 == src2) {
    Move_s(dst, src1);
    return;
  }

  // Check if one of operands is NaN.
  CompareIsNanF32(src1, src2);
  BranchTrueF(out_of_line);

  fmax_s(dst, src1, src2);
}

void MacroAssembler::Float32MaxOutOfLine(FPURegister dst, FPURegister src1,
                                         FPURegister src2) {
  fadd_s(dst, src1, src2);
}

void MacroAssembler::Float32Min(FPURegister dst, FPURegister src1,
                                FPURegister src2, Label* out_of_line) {
  ASM_CODE_COMMENT(this);
  if (src1 == src2) {
    Move_s(dst, src1);
    return;
  }

  // Check if one of operands is NaN.
  CompareIsNanF32(src1, src2);
  BranchTrueF(out_of_line);

  fmin_s(dst, src1, src2);
}

void MacroAssembler::Float32MinOutOfLine(FPURegister dst, FPURegister src1,
                                         FPURegister src2) {
  fadd_s(dst, src1, src2);
}

void MacroAssembler::Float64Max(FPURegister dst, FPURegister src1,
                                FPURegister src2, Label* out_of_line) {
  ASM_CODE_COMMENT(this);
  if (src1 == src2) {
    Move_d(dst, src1);
    return;
  }

  // Check if one of operands is NaN.
  CompareIsNanF64(src1, src2);
  BranchTrueF(out_of_line);

  fmax_d(dst, src1, src2);
}

void MacroAssembler::Float64MaxOutOfLine(FPURegister dst, FPURegister src1,
                                         FPURegister src2) {
  fadd_d(dst, src1, src2);
}

void MacroAssembler::Float64Min(FPURegister dst, FPURegister src1,
                                FPURegister src2, Label* out_of_line) {
  ASM_CODE_COMMENT(this);
  if (src1 == src2) {
    Move_d(dst, src1);
    return;
  }

  // Check if one of operands is NaN.
  CompareIsNanF64(src1, src2);
  BranchTrueF(out_of_line);

  fmin_d(dst, src1, src2);
}

void MacroAssembler::Float64MinOutOfLine(FPURegister dst, FPURegister src1,
                                         FPURegister src2) {
  fadd_d(dst, src1, src2);
}

int MacroAssembler::CalculateStackPassedWords(int num_reg_arguments,
                                              int num_double_arguments) {
  int stack_passed_words = 0;

  // Up to eight simple arguments are passed in registers a0..a7.
  if (num_reg_arguments > kRegisterPassedArguments) {
    stack_passed_words += num_reg_arguments - kRegisterPassedArguments;
  }
  if (num_double_arguments > kFPRegisterPassedArguments) {
    int num_count = num_double_arguments - kFPRegisterPassedArguments;
    if (num_reg_arguments >= kRegisterPassedArguments) {
      stack_passed_words += num_count;
    } else if (num_count > kRegisterPassedArguments - num_reg_arguments) {
      stack_passed_words +=
          num_count - (kRegisterPassedArguments - num_reg_arguments);
    }
  }
  return stack_passed_words;
}

void MacroAssembler::PrepareCallCFunction(int num_reg_arguments,
                                          int num_double_arguments,
                                          Register scratch) {
  ASM_CODE_COMMENT(this);
  int frame_alignment = ActivationFrameAlignment();

  // Up to eight simple arguments in a0..a3, a4..a7, No argument slots.
  // Remaining arguments are pushed on the stack.
  int stack_passed_arguments =
      CalculateStackPassedWords(num_reg_arguments, num_double_arguments);
  if (frame_alignment > kSystemPointerSize) {
    // Make stack end at alignment and make room for num_arguments - 4 words
    // and the original value of sp.
    mov(scratch, sp);
    Sub_d(sp, sp, Operand((stack_passed_arguments + 1) * kSystemPointerSize));
    DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
    bstrins_d(sp, zero_reg, std::log2(frame_alignment) - 1, 0);
    St_d(scratch, MemOperand(sp, stack_passed_arguments * kSystemPointerSize));
  } else {
    Sub_d(sp, sp, Operand(stack_passed_arguments * kSystemPointerSize));
  }
}

void MacroAssembler::PrepareCallCFunction(int num_reg_arguments,
                                          Register scratch) {
  PrepareCallCFunction(num_reg_arguments, 0, scratch);
}

int MacroAssembler::CallCFunction(ExternalReference function,
                                  int num_reg_arguments,
                                  int num_double_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  li(t7, function);
  return CallCFunctionHelper(t7, num_reg_arguments, num_double_arguments,
                             set_isolate_data_slots, return_location);
}

int MacroAssembler::CallCFunction(Register function, int num_reg_arguments,
                                  int num_double_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  ASM_CODE_COMMENT(this);
  return CallCFunctionHelper(function, num_reg_arguments, num_double_arguments,
                             set_isolate_data_slots, return_location);
}

int MacroAssembler::CallCFunction(ExternalReference function, int num_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  return CallCFunction(function, num_arguments, 0, set_isolate_data_slots,
                       return_location);
}

int MacroAssembler::CallCFunction(Register function, int num_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  return CallCFunction(function, num_arguments, 0, set_isolate_data_slots,
                       return_location);
}

int MacroAssembler::CallCFunctionHelper(
    Register function, int num_reg_arguments, int num_double_arguments,
    SetIsolateDataSlots set_isolate_data_slots, Label* return_location) {
  DCHECK_LE(num_reg_arguments + num_double_arguments, kMaxCParameters);
  DCHECK(has_frame());

  Label get_pc;

  // Make sure that the stack is aligned before calling a C function unless
  // running in the simulator. The simulator has its own alignment check which
  // provides more information.

#if V8_HOST_ARCH_LOONG64
  if (v8_flags.debug_code) {
    int frame_alignment = base::OS::ActivationFrameAlignment();
    int frame_alignment_mask = frame_alignment - 1;
    if (frame_alignment > kSystemPointerSize) {
      DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
      Label alignment_as_expected;
      {
        Register scratch = t8;
        And(scratch, sp, Operand(frame_alignment_mask));
        Branch(&alignment_as_expected, eq, scratch, Operand(zero_reg));
      }
      // Don't use Check here, as it will call Runtime_Abort possibly
      // re-entering here.
      stop();
      bind(&alignment_as_expected);
    }
  }
#endif  // V8_HOST_ARCH_LOONG64

  // Just call directly. The function called cannot cause a GC, or
  // allow preemption, so the return address in the link register
  // stays correct.
  {
    BlockTrampolinePoolScope block_trampoline_pool(this);
    if (set_isolate_data_slots == SetIsolateDataSlots::kYes) {
      if (function != t7) {
        mov(t7, function);
        function = t7;
      }

      // Save the frame pointer and PC so that the stack layout remains
      // iterable, even without an ExitFrame which normally exists between JS
      // and C frames. 't' registers are caller-saved so this is safe as a
      // scratch register.
      Register pc_scratch = t1;
      DCHECK(!AreAliased(pc_scratch, function));
      CHECK(root_array_available());

      LoadLabelRelative(pc_scratch, &get_pc);

      St_d(pc_scratch,
           ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerPC));
      St_d(fp, ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP));
    }

    Call(function);
    int call_pc_offset = pc_offset();
    bind(&get_pc);
    if (return_location) bind(return_location);

    if (set_isolate_data_slots == SetIsolateDataSlots::kYes) {
      // We don't unset the PC; the FP is the source of truth.
      St_d(zero_reg,
           ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP));
    }

    int stack_passed_arguments =
        CalculateStackPassedWords(num_reg_arguments, num_double_arguments);

    if (base::OS::ActivationFrameAlignment() > kSystemPointerSize) {
      Ld_d(sp, MemOperand(sp, stack_passed_arguments * kSystemPointerSize));
    } else {
      Add_d(sp, sp, Operand(stack_passed_arguments * kSystemPointerSize));
    }

    set_pc_for_safepoint();

    return call_pc_offset;
  }
}

#undef BRANCH_ARGS_CHECK

void MacroAssembler::CheckPageFlag(Register object, int mask, Condition cc,
                                   Label* condition_met) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  temps.Include(t8);
  Register scratch = temps.Acquire();
  And(scratch, object, Operand(~MemoryChunk::GetAlignmentMaskForAssembler()));
  Ld_d(scratch, MemOperand(scratch, MemoryChunk::FlagsOffset()));
  And(scratch, scratch, Operand(mask));
  Branch(condition_met, cc, scratch, Operand(zero_reg));
}

Register GetRegisterThatIsNotOneOf(Register reg1, Register reg2, Register reg3,
                                   Register reg4, Register reg5,
                                   Register reg6) {
  RegList regs = {reg1, reg2, reg3, reg4, reg5, reg6};

  const RegisterConfiguration* config = RegisterConfiguration::Default();
  for (int i = 0; i < config->num_allocatable_general_registers(); ++i) {
    int code = config->GetAllocatableGeneralCode(i);
    Register candidate = Register::from_code(code);
    if (regs.has(candidate)) continue;
    return candidate;
  }
  UNREACHABLE();
}

void MacroAssembler::ComputeCodeStartAddress(Register dst) {
  // TODO(LOONG_dev): range check, add Pcadd macro function?
  pcaddi(dst, -pc_offset() >> 2);
}

void MacroAssembler::CallForDeoptimization(Builtin target, int, Label* exit,
                                           DeoptimizeKind kind, Label* ret,
                                           Label*) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Ld_d(t7,
       MemOperand(kRootRegister, IsolateData::BuiltinEntrySlotOffset(target)));
  Call(t7);
  DCHECK_EQ(SizeOfCodeGeneratedSince(exit),
            (kind == DeoptimizeKind::kLazy) ? Deoptimizer::kLazyDeoptExitSize
                                            : Deoptimizer::kEagerDeoptExitSize);
}

void MacroAssembler::LoadCodeInstructionStart(Register destination,
                                              Register code_object,
                                              CodeEntrypointTag tag) {
  ASM_CODE_COMMENT(this);
#ifdef V8_ENABLE_SANDBOX
  LoadCodeEntrypointViaCodePointer(
      destination,
      FieldMemOperand(code_object, Code::kSelfIndirectPointerOffset), tag);
#else
  Ld_d(destination,
       FieldMemOperand(code_object, Code::kInstructionStartOffset));
#endif
}

void MacroAssembler::CallCodeObject(Register code_object,
                                    CodeEntrypointTag tag) {
  ASM_CODE_COMMENT(this);
  LoadCodeInstructionStart(code_object, code_object, tag);
  Call(code_object);
}

void MacroAssembler::JumpCodeObject(Register code_object, CodeEntrypointTag tag,
                                    JumpMode jump_mode) {
  // TODO(saelo): can we avoid using this for JavaScript functions
  // (kJSEntrypointTag) and instead use a variant that ensures that the caller
  // and callee agree on the signature (i.e. parameter count)?
  ASM_CODE_COMMENT(this);
  DCHECK_EQ(JumpMode::kJump, jump_mode);
  LoadCodeInstructionStart(code_object, code_object, tag);
  Jump(code_object);
}

void MacroAssembler::CallJSFunction(Register function_object,
                                    uint16_t argument_count) {
  Register code = kJavaScriptCallCodeStartRegister;
#ifdef V8_ENABLE_LEAPTIERING
  Register dispatch_handle = kJavaScriptCallDispatchHandleRegister;
  Register parameter_count = s1;
  Register scratch = s2;

  Ld_w(dispatch_handle,
       FieldMemOperand(function_object, JSFunction::kDispatchHandleOffset));
  LoadEntrypointAndParameterCountFromJSDispatchTable(code, parameter_count,
                                                     dispatch_handle, scratch);

  // Force a safe crash if the parameter count doesn't match.
  SbxCheck(le, AbortReason::kJSSignatureMismatch, parameter_count,
           Operand(argument_count));
  Call(code);
#elif V8_ENABLE_SANDBOX
  // When the sandbox is enabled, we can directly fetch the entrypoint pointer
  // from the code pointer table instead of going through the Code object. In
  // this way, we avoid one memory load on this code path.
  LoadCodeEntrypointViaCodePointer(
      code, FieldMemOperand(function_object, JSFunction::kCodeOffset),
      kJSEntrypointTag);
  Call(code);
#else
  LoadTaggedField(code,
                  FieldMemOperand(function_object, JSFunction::kCodeOffset));
  CallCodeObject(code, kJSEntrypointTag);
#endif
}

void MacroAssembler::JumpJSFunction(Register function_object,
                                    JumpMode jump_mode) {
  Register code = kJavaScriptCallCodeStartRegister;
#ifdef V8_ENABLE_LEAPTIERING
  Register dispatch_handle = kJavaScriptCallDispatchHandleRegister;
  Register scratch = s1;
  Ld_w(dispatch_handle,
       FieldMemOperand(function_object, JSFunction::kDispatchHandleOffset));
  LoadEntrypointFromJSDispatchTable(code, dispatch_handle, scratch);
  DCHECK_EQ(jump_mode, JumpMode::kJump);
  Jump(code);
#elif V8_ENABLE_SANDBOX
  // When the sandbox is enabled, we can directly fetch the entrypoint pointer
  // from the code pointer table instead of going through the Code object. In
  // this way, we avoid one memory load on this code path.
  LoadCodeEntrypointViaCodePointer(
      code, FieldMemOperand(function_object, JSFunction::kCodeOffset),
      kJSEntrypointTag);
  DCHECK_EQ(jump_mode, JumpMode::kJump);
  Jump(code);
#else
  LoadTaggedField(code,
                  FieldMemOperand(function_object, JSFunction::kCodeOffset));
  JumpCodeObject(code, kJSEntrypointTag, jump_mode);
#endif
}

namespace {

#ifndef V8_ENABLE_LEAPTIERING
// Only used when leaptiering is disabled.
void TailCallOptimizedCodeSlot(MacroAssembler* masm,
                               Register optimized_code_entry) {
  // ----------- S t a t e -------------
  //  -- a0 : actual argument count
  //  -- a3 : new target (preserved for callee if needed, and caller)
  //  -- a1 : target function (preserved for callee if needed, and caller)
  // -----------------------------------
  DCHECK(!AreAliased(optimized_code_entry, a1, a3));

  Label heal_optimized_code_slot;

  // If the optimized code is cleared, go to runtime to update the optimization
  // marker field.
  __ LoadWeakValue(optimized_code_entry, optimized_code_entry,
                   &heal_optimized_code_slot);

  // The entry references a CodeWrapper object. Unwrap it now.
  __ LoadCodePointerField(
      optimized_code_entry,
      FieldMemOperand(optimized_code_entry, CodeWrapper::kCodeOffset));

  // Check if the optimized code is marked for deopt. If it is, call the
  // runtime to clear it.
  __ TestCodeIsMarkedForDeoptimizationAndJump(optimized_code_entry, a6, ne,
                                              &heal_optimized_code_slot);

  // Optimized code is good, get it into the closure and link the closure into
  // the optimized functions list, then tail call the optimized code.
  // The feedback vector is no longer used, so re-use it as a scratch
  // register.
  __ ReplaceClosureCodeWithOptimizedCode(optimized_code_entry, a1);

  static_assert(kJavaScriptCallCodeStartRegister == a2, "ABI mismatch");
  __ LoadCodeInstructionStart(a2, optimized_code_entry, kJSEntrypointTag);
  __ Jump(a2);

  // Optimized code slot contains deoptimized code or code is cleared and
  // optimized code marker isn't updated. Evict the code, update the marker
  // and re-enter the closure's code.
  __ bind(&heal_optimized_code_slot);
  __ GenerateTailCallToReturnedCode(Runtime::kHealOptimizedCodeSlot);
}
#endif  // V8_ENABLE_LEAPTIERING

}  // namespace

#ifdef V8_ENABLE_DEBUG_CODE
void MacroAssembler::AssertFeedbackCell(Register object, Register scratch) {
  if (v8_flags.debug_code) {
    GetObjectType(object, scratch, scratch);
    Assert(eq, AbortReason::kExpectedFeedbackCell, scratch,
           Operand(FEEDBACK_CELL_TYPE));
  }
}
void MacroAssembler::AssertFeedbackVector(Register object, Register scratch) {
  if (v8_flags.debug_code) {
    GetObjectType(object, scratch, scratch);
    Assert(eq, AbortReason::kExpectedFeedbackVector, scratch,
           Operand(FEEDBACK_VECTOR_TYPE));
  }
}
#endif  // V8_ENABLE_DEBUG_CODE

void MacroAssembler::ReplaceClosureCodeWithOptimizedCode(
    Register optimized_code, Register closure) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(optimized_code, closure));

#ifdef V8_ENABLE_LEAPTIERING
  UNREACHABLE();
#else
  // Store code entry in the closure.
  StoreCodePointerField(optimized_code,
                        FieldMemOperand(closure, JSFunction::kCodeOffset));
  RecordWriteField(closure, JSFunction::kCodeOffset, optimized_code,
                   kRAHasNotBeenSaved, SaveFPRegsMode::kIgnore, SmiCheck::kOmit,
                   SlotDescriptor::ForCodePointerSlot());
#endif  // V8_ENABLE_LEAPTIERING
}

void MacroAssembler::GenerateTailCallToReturnedCode(
    Runtime::FunctionId function_id) {
  ASM_CODE_COMMENT(this);
  // ----------- S t a t e -------------
  //  -- a0 : actual argument count (preserved for callee)
  //  -- a1 : target function (preserved for callee)
  //  -- a3 : new target (preserved for callee)
  //  -- a4 : dispatch handle (preserved for callee)
  // -----------------------------------
  {
    FrameScope scope(this, StackFrame::INTERNAL);
    // Push a copy of the target function, the new target, the actual
    // argument count, and the dispatch handle.
    // Push function as parameter to the runtime call.
    SmiTag(kJavaScriptCallArgCountRegister);
    Push(kJavaScriptCallTargetRegister, kJavaScriptCallNewTargetRegister,
         kJavaScriptCallArgCountRegister);
#ifdef V8_ENABLE_LEAPTIERING
    // No need to SmiTag since dispatch handles always look like Smis.
    static_assert(kJSDispatchHandleShift > 0);
    Push(kJavaScriptCallDispatchHandleRegister);
#endif
    // Function is also the parameter to the runtime call.
    Push(kJavaScriptCallTargetRegister);

    CallRuntime(function_id, 1);
    LoadCodeInstructionStart(a2, a0, kJSEntrypointTag);

    // Restore target function, new target, actual argument count and dispatch
    // handle.
#ifdef V8_ENABLE_LEAPTIERING
    Pop(kJavaScriptCallDispatchHandleRegister);
#endif
    Pop(kJavaScriptCallTargetRegister, kJavaScriptCallNewTargetRegister,
        kJavaScriptCallArgCountRegister);
    SmiUntag(kJavaScriptCallArgCountRegister);
  }

  static_assert(kJavaSc
"""


```