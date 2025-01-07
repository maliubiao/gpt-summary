Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/codegen/arm64/macro-assembler-arm64.cc`. I need to analyze the code and list its capabilities.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the File's Purpose:** The file name `macro-assembler-arm64.cc` strongly suggests this code is responsible for generating ARM64 assembly instructions. "MacroAssembler" implies it provides a higher-level interface for emitting these instructions.

2. **Scan for Key Functionalities:** I will read through the code, looking for function names and code patterns that indicate specific actions. Keywords like `Load`, `Store`, `Move`, `Call`, `Jump`, `Push`, `Pop`, `Add`, `Sub`, `Cmp`, etc., are important.

3. **Categorize Functionalities:** As I identify functionalities, I'll group them logically. For example, operations related to loading data from different sources (roots, constants, memory) belong together. Similarly, call and jump instructions form a group.

4. **Address Specific Instructions:**
    * **`.tq` Check:**  The code explicitly asks about the `.tq` extension. I see the file ends with `.cc`, so it's not a Torque file.
    * **JavaScript Relationship:** I need to identify parts of the code that interact with JavaScript concepts like `JSFunction`, `Runtime`, and stack management. The `CallJSFunction`, `JumpJSFunction`, `CallRuntime`, and stack manipulation functions are relevant here. I'll provide a simple JavaScript example to illustrate the interaction.
    * **Code Logic Inference:**  I'll look for functions that perform some computation or manipulation based on inputs. The `MovePair` and `Swap` functions are good candidates. I'll devise simple input/output examples for them.
    * **Common Programming Errors:**  I'll think about typical mistakes developers make when working with assembly or low-level code, and see if any parts of this code relate to those. Stack overflows are a common issue, and the `StackOverflowCheck` function is directly related.
    * **Part Number:** The prompt mentions this is part 3 of 6. I'll acknowledge this context in the summary.

5. **Synthesize the Summary:**  I'll combine the categorized functionalities and the answers to the specific instructions into a concise summary.

**Pre-computation/Pre-analysis (Internal thought process while reading the code):**

* **Root Handling:**  Notice the functions `LoadTaggedRoot`, `LoadRoot`, `PushRoot`. These are clearly about accessing the V8 roots table. The code also considers different optimization strategies based on whether roots are static and the size of the root address.
* **Data Movement:**  The `Move`, `MovePair`, and `Swap` functions are straightforward data manipulation operations.
* **Function Calls:**  There are numerous functions related to calling other code: `CallRuntime`, `JumpToExternalReference`, `TailCallRuntime`, `CallCFunction`, `CallBuiltin`, `TailCallBuiltin`, `CallCodeObject`, `JumpCodeObject`, `CallJSFunction`, `JumpJSFunction`, `CallWasmCodePointer`. These vary based on the type of target (runtime function, C function, built-in, JavaScript function, WebAssembly).
* **Stack Management:** Functions like `Push`, `Pop`, `Claim`, `Drop`, `StackOverflowCheck`, and `InvokePrologue` directly manage the stack.
* **Deoptimization:**  `BailoutIfDeoptimized` and `CallForDeoptimization` are related to V8's deoptimization mechanism.
* **Constants Table:** `LoadFromConstantsTable` shows how constants are accessed.
* **External References:**  `ExternalReferenceAsOperand` deals with accessing data through external references.
* **Conditional Execution:** `Jump` with a condition argument enables conditional branching.
* **WebAssembly:** `ResolveWasmCodePointer`, `CallWasmCodePointer`, and `LoadWasmCodePointer` indicate support for WebAssembly.

By following these steps and carefully reading the code, I can create a comprehensive and accurate summary of the `macro-assembler-arm64.cc` file's functionality.
这是 `v8/src/codegen/arm64/macro-assembler-arm64.cc` 源代码的第三部分，主要功能是提供用于生成 ARM64 汇编代码的高级宏指令。它封装了底层的汇编指令，使得 V8 引擎的开发者可以使用更易于理解和维护的方式来生成机器码。

以下是该部分代码的具体功能归纳：

**1. 浮点数操作助手:**

*   `FzeroingAbs(VRegister dst, VRegister src)`:  计算浮点数的绝对值，并将负零转换为正零。

**2. 加载根对象:**

*   `LoadTaggedRoot(Register destination, RootIndex index)`: 加载一个带标签的根对象到寄存器。根据根对象的索引判断是否可以使用立即数加载。
*   `LoadRoot(Register destination, RootIndex index)`:  加载一个根对象到寄存器。针对静态根和地址大小进行了优化。
*   `PushRoot(RootIndex index)`: 将一个根对象压入栈。

**3. 数据移动操作:**

*   `Move(Register dst, Tagged<Smi> src)`: 将一个小的整数 (Smi) 移动到寄存器。
*   `Move(Register dst, MemOperand src)`: 将内存中的数据移动到寄存器。
*   `Move(Register dst, Register src)`: 将一个寄存器中的值移动到另一个寄存器。
*   `MovePair(Register dst0, Register src0, Register dst1, Register src1)`: 同时移动两个寄存器对，并处理可能的寄存器重叠情况。
*   `Swap(Register lhs, Register rhs)`: 交换两个通用寄存器的值。
*   `Swap(VRegister lhs, VRegister rhs)`: 交换两个 SIMD 寄存器的值。

**4. 运行时函数调用:**

*   `CallRuntime(const Runtime::Function* f, int num_arguments)`: 调用 V8 运行时函数。负责设置参数（参数个数，函数引用）并调用运行时入口。
*   `JumpToExternalReference(const ExternalReference& builtin, bool builtin_exit_frame)`:  跳转到外部引用（通常是 C++ 实现的内置函数）。
*   `TailCallRuntime(Runtime::FunctionId fid)`: 尾调用 V8 运行时函数。

**5. C 函数调用:**

*   `ActivationFrameAlignment()`: 获取当前平台的激活帧对齐要求。
*   `CallCFunction(ExternalReference function, int num_of_reg_args, SetIsolateDataSlots set_isolate_data_slots, Label* return_location)`: 调用 C 函数，处理寄存器参数，并可以选择设置 Isolate 数据槽。
*   `CallCFunction(ExternalReference function, int num_of_reg_args, int num_of_double_args, SetIsolateDataSlots set_isolate_data_slots, Label* return_location)`: 调用 C 函数，处理寄存器参数和浮点寄存器参数。
*   `CallCFunction(Register function, int num_of_reg_args, int num_of_double_args, SetIsolateDataSlots set_isolate_data_slots, Label* return_location)`: 调用 C 函数，函数地址由寄存器提供。

**6. 常量表操作:**

*   `LoadFromConstantsTable(Register destination, int constant_index)`: 从常量表中加载一个常量到寄存器。

**7. 根寄存器相关操作:**

*   `LoadRootRelative(Register destination, int32_t offset)`: 从根寄存器偏移处加载数据。
*   `StoreRootRelative(int32_t offset, Register value)`: 将数据存储到根寄存器偏移处。
*   `LoadRootRegisterOffset(Register destination, intptr_t offset)`: 将根寄存器加上偏移量加载到目标寄存器。

**8. 外部引用操作:**

*   `ExternalReferenceAsOperand(ExternalReference reference, Register scratch)`: 将外部引用转换为内存操作数，根据是否可以使用根寄存器相对寻址进行优化。

**9. 跳转指令:**

*   `Jump(Register target, Condition cond)`:  跳转到寄存器指定的地址，可以带条件。
*   `JumpHelper(int64_t offset, RelocInfo::Mode rmode, Condition cond)`:  根据偏移量跳转，处理不同类型的重定位信息。
*   `CalculateTargetOffset(Address target, RelocInfo::Mode rmode, uint8_t* pc)`: 计算跳转目标地址相对于当前 PC 的偏移量。
*   `Jump(Address target, RelocInfo::Mode rmode, Condition cond)`: 跳转到指定的内存地址。
*   `Jump(Handle<Code> code, RelocInfo::Mode rmode, Condition cond)`: 跳转到 Code 对象的入口，支持内置函数的尾调用优化。
*   `Jump(const ExternalReference& reference)`: 跳转到外部引用指向的地址。

**10. 调用指令:**

*   `Call(Register target)`: 调用寄存器指定的地址处的函数。
*   `Call(Address target, RelocInfo::Mode rmode)`: 调用指定内存地址处的函数。
*   `Call(Handle<Code> code, RelocInfo::Mode rmode)`: 调用 Code 对象的入口，支持内置函数的直接调用优化。
*   `Call(ExternalReference target)`: 调用外部引用指向的地址处的函数。

**11. 内置函数调用:**

*   `LoadEntryFromBuiltinIndex(Register builtin_index, Register target)`: 根据内置函数索引加载其入口地址。
*   `LoadEntryFromBuiltin(Builtin builtin, Register destination)`: 加载指定内置函数的入口地址。
*   `EntryFromBuiltinAsOperand(Builtin builtin)`:  获取内置函数入口地址的内存操作数。
*   `CallBuiltinByIndex(Register builtin_index, Register target)`:  通过内置函数索引调用内置函数。
*   `CallBuiltin(Builtin builtin)`:  调用指定的内置函数，根据不同的编译选项选择不同的调用方式（绝对地址、PC 相对地址、间接调用）。
*   `TailCallBuiltin(Builtin builtin, Condition cond)`: 尾调用指定的内置函数。

**12. 代码对象调用和跳转:**

*   `LoadCodeInstructionStart(Register destination, Register code_object, CodeEntrypointTag tag)`: 加载 Code 对象的指定入口点（例如，指令开始地址）。
*   `CallCodeObject(Register code_object, CodeEntrypointTag tag)`: 调用 Code 对象的指定入口点。
*   `JumpCodeObject(Register code_object, CodeEntrypointTag tag, JumpMode jump_mode)`: 跳转到 Code 对象的指定入口点。

**13. JavaScript 函数调用和跳转:**

*   `CallJSFunction(Register function_object, uint16_t argument_count)`: 调用 JavaScript 函数，处理函数对象和参数数量。
*   `JumpJSFunction(Register function_object, JumpMode jump_mode)`: 跳转到 JavaScript 函数。

**14. WebAssembly 代码指针处理:**

*   `ResolveWasmCodePointer(Register target)`: 解析 WebAssembly 代码指针。
*   `CallWasmCodePointer(Register target, CallJumpMode call_jump_mode)`: 调用 WebAssembly 代码指针指向的代码。
*   `LoadWasmCodePointer(Register dst, MemOperand src)`: 加载 WebAssembly 代码指针。

**15. 返回地址处理和调用:**

*   `StoreReturnAddressAndCall(Register target)`: 存储返回地址并调用目标地址处的函数，用于 C 函数调用。
*   `IndirectCall(Address target, RelocInfo::Mode rmode)`: 通过寄存器间接调用目标地址处的函数。

**16. 代码去优化:**

*   `BailoutIfDeoptimized()`:  检查代码对象是否被标记为需要去优化，如果是则跳转到去优化代码。
*   `CallForDeoptimization(Builtin target, int deopt_id, Label* exit, DeoptimizeKind kind, Label* ret, Label* jump_deoptimization_entry_label)`:  生成去优化的调用代码。

**17. 栈溢出检查:**

*   `LoadStackLimit(Register destination, StackLimitKind kind)`: 加载栈限制。
*   `StackOverflowCheck(Register num_args, Label* stack_overflow)`: 检查是否会发生栈溢出。

**18. 调用序言:**

*   `InvokePrologue(Register formal_parameter_count, Register actual_argument_count, InvokeType type)`: 生成函数调用的序言代码，处理参数数量不匹配的情况。

**关于提问中的特定点：**

*   **`.tq` 结尾:**  代码片段的开头说明这是 `v8/src/codegen/arm64/macro-assembler-arm64.cc` 文件，以 `.cc` 结尾，因此它是一个 C++ 源代码文件，而不是 Torque 源代码文件。

*   **与 JavaScript 功能的关系:**  这个文件是代码生成器的一部分，直接负责将 JavaScript 代码编译成 ARM64 机器码。  它包含了调用 JavaScript 函数 (`CallJSFunction`)、调用运行时函数 (这些函数处理 JavaScript 的一些底层操作) 以及进行栈管理等与 JavaScript 执行密切相关的功能。

    **JavaScript 示例:**

    ```javascript
    function add(a, b) {
      return a + b;
    }

    add(5, 10);
    ```

    当 V8 编译 `add(5, 10)` 这行代码时，`macro-assembler-arm64.cc` 中的 `CallJSFunction` 等函数会被用来生成调用 `add` 函数的 ARM64 指令。 `InvokePrologue` 会处理参数传递，运行时函数可能会处理加法运算，最终结果会被返回。

*   **代码逻辑推理 (以 `MovePair` 为例):**

    **假设输入:**
    *   `dst0` = x0, `src0` = x1, `dst1` = x2, `src1` = x3 (所有寄存器都不相同)

    **输出 (生成的汇编指令):**
    ```assembly
    mov x0, x1
    mov x2, x3
    ```

    **假设输入:**
    *   `dst0` = x0, `src0` = x1, `dst1` = x1, `src1` = x2 ( `dst1` 与 `src0` 相同)

    **输出 (生成的汇编指令):**
    ```assembly
    mov x1, x2
    mov x0, x1
    ```
    这里会调整指令顺序以避免覆盖 `src0` 的值。

*   **用户常见的编程错误 (与 `StackOverflowCheck` 相关):**

    一个常见的编程错误是**无限递归**，这会导致栈空间被耗尽。

    **JavaScript 示例:**

    ```javascript
    function recursiveFunction() {
      recursiveFunction();
    }

    recursiveFunction(); // 这将导致栈溢出
    ```

    当执行 `recursiveFunction()` 时，每次调用都会在栈上分配新的空间。 由于没有终止条件，栈会不断增长，直到超出栈的限制。 `StackOverflowCheck` 宏指令会在函数调用前检查栈空间是否足够，如果不足则跳转到错误处理代码。

**总结该部分的功能:**

这部分 `macro-assembler-arm64.cc` 代码是 V8 引擎在 ARM64 架构上生成机器码的核心组件之一。它提供了一组高级宏指令，用于执行以下关键操作：

*   **数据操作:**  加载、存储、移动和交换数据。
*   **函数调用:**  调用运行时函数、C 函数、内置函数和 JavaScript 函数。
*   **控制流:**  实现跳转和条件跳转。
*   **栈管理:**  分配和释放栈空间，并进行栈溢出检查。
*   **代码优化和去优化:**  支持内置函数的快速调用和代码去优化机制。

总而言之，这部分代码抽象了底层的 ARM64 指令细节，为 V8 引擎的开发者提供了一个更方便、更高级的接口来生成高效的机器码，从而驱动 JavaScript 代码的执行。它是连接 JavaScript 代码和底层硬件的关键桥梁。

Prompt: 
```
这是目录为v8/src/codegen/arm64/macro-assembler-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/arm64/macro-assembler-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能

"""
cting 0.0 preserves all inputs except for signalling NaNs, which
  // become quiet NaNs. We use fsub rather than fadd because fsub preserves -0.0
  // inputs: -0.0 + 0.0 = 0.0, but -0.0 - 0.0 = -0.0.
  Fsub(dst, src, fp_zero);
}

void MacroAssembler::LoadTaggedRoot(Register destination, RootIndex index) {
  ASM_CODE_COMMENT(this);
  if (CanBeImmediate(index)) {
    Mov(destination,
        Immediate(ReadOnlyRootPtr(index), RelocInfo::Mode::NO_INFO));
    return;
  }
  LoadRoot(destination, index);
}

void MacroAssembler::LoadRoot(Register destination, RootIndex index) {
  ASM_CODE_COMMENT(this);
  if (V8_STATIC_ROOTS_BOOL && RootsTable::IsReadOnly(index) &&
      IsImmAddSub(ReadOnlyRootPtr(index))) {
    DecompressTagged(destination, ReadOnlyRootPtr(index));
    return;
  }
  // Many roots have addresses that are too large to fit into addition immediate
  // operands. Evidence suggests that the extra instruction for decompression
  // costs us more than the load.
  Ldr(destination,
      MemOperand(kRootRegister, RootRegisterOffsetForRootIndex(index)));
}

void MacroAssembler::PushRoot(RootIndex index) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register tmp = temps.AcquireX();
  LoadRoot(tmp, index);
  Push(tmp);
}

void MacroAssembler::Move(Register dst, Tagged<Smi> src) { Mov(dst, src); }
void MacroAssembler::Move(Register dst, MemOperand src) { Ldr(dst, src); }
void MacroAssembler::Move(Register dst, Register src) {
  if (dst == src) return;
  Mov(dst, src);
}

void MacroAssembler::MovePair(Register dst0, Register src0, Register dst1,
                              Register src1) {
  DCHECK_NE(dst0, dst1);
  if (dst0 != src1) {
    Mov(dst0, src0);
    Mov(dst1, src1);
  } else if (dst1 != src0) {
    // Swap the order of the moves to resolve the overlap.
    Mov(dst1, src1);
    Mov(dst0, src0);
  } else {
    // Worse case scenario, this is a swap.
    Swap(dst0, src0);
  }
}

void MacroAssembler::Swap(Register lhs, Register rhs) {
  DCHECK(lhs.IsSameSizeAndType(rhs));
  DCHECK_NE(lhs, rhs);
  UseScratchRegisterScope temps(this);
  Register temp = temps.AcquireX();
  Mov(temp, rhs);
  Mov(rhs, lhs);
  Mov(lhs, temp);
}

void MacroAssembler::Swap(VRegister lhs, VRegister rhs) {
  DCHECK(lhs.IsSameSizeAndType(rhs));
  DCHECK_NE(lhs, rhs);
  UseScratchRegisterScope temps(this);
  VRegister temp = VRegister::no_reg();
  if (lhs.IsS()) {
    temp = temps.AcquireS();
  } else if (lhs.IsD()) {
    temp = temps.AcquireD();
  } else {
    DCHECK(lhs.IsQ());
    temp = temps.AcquireQ();
  }
  Mov(temp, rhs);
  Mov(rhs, lhs);
  Mov(lhs, temp);
}

void MacroAssembler::CallRuntime(const Runtime::Function* f,
                                 int num_arguments) {
  ASM_CODE_COMMENT(this);
  // All arguments must be on the stack before this function is called.
  // x0 holds the return value after the call.

  // Check that the number of arguments matches what the function expects.
  // If f->nargs is -1, the function can accept a variable number of arguments.
  CHECK(f->nargs < 0 || f->nargs == num_arguments);

  // Place the necessary arguments.
  Mov(x0, num_arguments);
  Mov(x1, ExternalReference::Create(f));

  bool switch_to_central = options().is_wasm;
  CallBuiltin(Builtins::RuntimeCEntry(f->result_size, switch_to_central));
}

void MacroAssembler::JumpToExternalReference(const ExternalReference& builtin,
                                             bool builtin_exit_frame) {
  ASM_CODE_COMMENT(this);
  Mov(x1, builtin);
  TailCallBuiltin(Builtins::CEntry(1, ArgvMode::kStack, builtin_exit_frame));
}

void MacroAssembler::TailCallRuntime(Runtime::FunctionId fid) {
  ASM_CODE_COMMENT(this);
  const Runtime::Function* function = Runtime::FunctionForId(fid);
  DCHECK_EQ(1, function->result_size);
  if (function->nargs >= 0) {
    // TODO(1236192): Most runtime routines don't need the number of
    // arguments passed in because it is constant. At some point we
    // should remove this need and make the runtime routine entry code
    // smarter.
    Mov(x0, function->nargs);
  }
  JumpToExternalReference(ExternalReference::Create(fid));
}

int MacroAssembler::ActivationFrameAlignment() {
#if V8_HOST_ARCH_ARM64
  // Running on the real platform. Use the alignment as mandated by the local
  // environment.
  // Note: This will break if we ever start generating snapshots on one ARM
  // platform for another ARM platform with a different alignment.
  return base::OS::ActivationFrameAlignment();
#else   // V8_HOST_ARCH_ARM64
  // If we are using the simulator then we should always align to the expected
  // alignment. As the simulator is used to generate snapshots we do not know
  // if the target platform will need alignment, so this is controlled from a
  // flag.
  return v8_flags.sim_stack_alignment;
#endif  // V8_HOST_ARCH_ARM64
}

int MacroAssembler::CallCFunction(ExternalReference function,
                                  int num_of_reg_args,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  return CallCFunction(function, num_of_reg_args, 0, set_isolate_data_slots,
                       return_location);
}

int MacroAssembler::CallCFunction(ExternalReference function,
                                  int num_of_reg_args, int num_of_double_args,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  // Note: The "CallCFunction" code comment will be generated by the other
  // CallCFunction method called below.
  UseScratchRegisterScope temps(this);
  Register temp = temps.AcquireX();
  Mov(temp, function);
  return CallCFunction(temp, num_of_reg_args, num_of_double_args,
                       set_isolate_data_slots, return_location);
}

int MacroAssembler::CallCFunction(Register function, int num_of_reg_args,
                                  int num_of_double_args,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  ASM_CODE_COMMENT(this);
  DCHECK_LE(num_of_reg_args + num_of_double_args, kMaxCParameters);
  DCHECK(has_frame());

  Label get_pc;
  UseScratchRegisterScope temps(this);
  // We're doing a C call, which means non-parameter caller-saved registers
  // (x8-x17) will be clobbered and so are available to use as scratches.
  // In the worst-case scenario, we'll need 2 scratch registers. We pick 3
  // registers minus the `function` register, in case `function` aliases with
  // any of the registers.
  temps.Include(CPURegList(64, {x8, x9, x10, function}));
  temps.Exclude(function);

  if (set_isolate_data_slots == SetIsolateDataSlots::kYes) {
    // Save the frame pointer and PC so that the stack layout remains iterable,
    // even without an ExitFrame which normally exists between JS and C frames.
    UseScratchRegisterScope temps(this);
    Register pc_scratch = temps.AcquireX();

    Adr(pc_scratch, &get_pc);

    CHECK(root_array_available());
    static_assert(IsolateData::GetOffset(IsolateFieldId::kFastCCallCallerPC) ==
                  IsolateData::GetOffset(IsolateFieldId::kFastCCallCallerFP) +
                      8);
    Stp(fp, pc_scratch,
        ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP));
  }

  // Call directly. The function called cannot cause a GC, or allow preemption,
  // so the return address in the link register stays correct.
  Call(function);
  int call_pc_offset = pc_offset();
  bind(&get_pc);
  if (return_location) bind(return_location);

  if (set_isolate_data_slots == SetIsolateDataSlots::kYes) {
    // We don't unset the PC; the FP is the source of truth.
    Str(xzr, ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP));
  }

  if (num_of_reg_args > kRegisterPassedArguments) {
    // Drop the register passed arguments.
    int claim_slots = RoundUp(num_of_reg_args - kRegisterPassedArguments, 2);
    Drop(claim_slots);
  }

  if (num_of_double_args > kFPRegisterPassedArguments) {
    // Drop the register passed arguments.
    int claim_slots =
        RoundUp(num_of_double_args - kFPRegisterPassedArguments, 2);
    Drop(claim_slots);
  }

  return call_pc_offset;
}

void MacroAssembler::LoadFromConstantsTable(Register destination,
                                            int constant_index) {
  ASM_CODE_COMMENT(this);
  DCHECK(RootsTable::IsImmortalImmovable(RootIndex::kBuiltinsConstantsTable));
  LoadRoot(destination, RootIndex::kBuiltinsConstantsTable);
  LoadTaggedField(destination,
                  FieldMemOperand(destination, FixedArray::OffsetOfElementAt(
                                                   constant_index)));
}

void MacroAssembler::LoadRootRelative(Register destination, int32_t offset) {
  Ldr(destination, MemOperand(kRootRegister, offset));
}

void MacroAssembler::StoreRootRelative(int32_t offset, Register value) {
  Str(value, MemOperand(kRootRegister, offset));
}

void MacroAssembler::LoadRootRegisterOffset(Register destination,
                                            intptr_t offset) {
  if (offset == 0) {
    Mov(destination, kRootRegister);
  } else {
    Add(destination, kRootRegister, offset);
  }
}

MemOperand MacroAssembler::ExternalReferenceAsOperand(
    ExternalReference reference, Register scratch) {
  if (root_array_available()) {
    if (reference.IsIsolateFieldId()) {
      return MemOperand(kRootRegister, reference.offset_from_root_register());
    }
    if (options().enable_root_relative_access) {
      intptr_t offset =
          RootRegisterOffsetForExternalReference(isolate(), reference);
      if (is_int32(offset)) {
        return MemOperand(kRootRegister, static_cast<int32_t>(offset));
      }
    }
    if (options().isolate_independent_code) {
      if (IsAddressableThroughRootRegister(isolate(), reference)) {
        // Some external references can be efficiently loaded as an offset from
        // kRootRegister.
        intptr_t offset =
            RootRegisterOffsetForExternalReference(isolate(), reference);
        CHECK(is_int32(offset));
        return MemOperand(kRootRegister, static_cast<int32_t>(offset));
      } else {
        // Otherwise, do a memory load from the external reference table.
        Ldr(scratch,
            MemOperand(kRootRegister,
                       RootRegisterOffsetForExternalReferenceTableEntry(
                           isolate(), reference)));
        return MemOperand(scratch, 0);
      }
    }
  }
  Mov(scratch, reference);
  return MemOperand(scratch, 0);
}

void MacroAssembler::Jump(Register target, Condition cond) {
  if (cond == nv) return;
  Label done;
  if (cond != al) B(NegateCondition(cond), &done);
  Br(target);
  Bind(&done);
}

void MacroAssembler::JumpHelper(int64_t offset, RelocInfo::Mode rmode,
                                Condition cond) {
  if (cond == nv) return;
  Label done;
  if (cond != al) B(NegateCondition(cond), &done);
  if (CanUseNearCallOrJump(rmode)) {
    DCHECK(IsNearCallOffset(offset));
    near_jump(static_cast<int>(offset), rmode);
  } else {
    UseScratchRegisterScope temps(this);
    Register temp = temps.AcquireX();
    uint64_t imm = reinterpret_cast<uint64_t>(pc_) + offset * kInstrSize;
    Mov(temp, Immediate(imm, rmode));
    Br(temp);
  }
  Bind(&done);
}

// The calculated offset is either:
// * the 'target' input unmodified if this is a Wasm call, or
// * the offset of the target from the current PC, in instructions, for any
//   other type of call.
// static
int64_t MacroAssembler::CalculateTargetOffset(Address target,
                                              RelocInfo::Mode rmode,
                                              uint8_t* pc) {
  int64_t offset = static_cast<int64_t>(target);
  if (rmode == RelocInfo::WASM_CALL || rmode == RelocInfo::WASM_STUB_CALL) {
    // The target of WebAssembly calls is still an index instead of an actual
    // address at this point, and needs to be encoded as-is.
    return offset;
  }
  offset -= reinterpret_cast<int64_t>(pc);
  DCHECK_EQ(offset % kInstrSize, 0);
  offset = offset / static_cast<int>(kInstrSize);
  return offset;
}

void MacroAssembler::Jump(Address target, RelocInfo::Mode rmode,
                          Condition cond) {
  int64_t offset = CalculateTargetOffset(target, rmode, pc_);
  JumpHelper(offset, rmode, cond);
}

void MacroAssembler::Jump(Handle<Code> code, RelocInfo::Mode rmode,
                          Condition cond) {
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  DCHECK_IMPLIES(options().isolate_independent_code,
                 Builtins::IsIsolateIndependentBuiltin(*code));

  Builtin builtin = Builtin::kNoBuiltinId;
  if (isolate()->builtins()->IsBuiltinHandle(code, &builtin)) {
    TailCallBuiltin(builtin, cond);
    return;
  }
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  if (CanUseNearCallOrJump(rmode)) {
    EmbeddedObjectIndex index = AddEmbeddedObject(code);
    DCHECK(is_int32(index));
    JumpHelper(static_cast<int64_t>(index), rmode, cond);
  } else {
    Jump(code.address(), rmode, cond);
  }
}

void MacroAssembler::Jump(const ExternalReference& reference) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();
  Mov(scratch, reference);
  Jump(scratch);
}

void MacroAssembler::Call(Register target) {
  BlockPoolsScope scope(this);
  Blr(target);
}

void MacroAssembler::Call(Address target, RelocInfo::Mode rmode) {
  BlockPoolsScope scope(this);
  if (CanUseNearCallOrJump(rmode)) {
    int64_t offset = CalculateTargetOffset(target, rmode, pc_);
    DCHECK(IsNearCallOffset(offset));
    near_call(static_cast<int>(offset), rmode);
  } else {
    IndirectCall(target, rmode);
  }
}

void MacroAssembler::Call(Handle<Code> code, RelocInfo::Mode rmode) {
  DCHECK_IMPLIES(options().isolate_independent_code,
                 Builtins::IsIsolateIndependentBuiltin(*code));
  BlockPoolsScope scope(this);

  Builtin builtin = Builtin::kNoBuiltinId;
  if (isolate()->builtins()->IsBuiltinHandle(code, &builtin)) {
    CallBuiltin(builtin);
    return;
  }

  DCHECK(RelocInfo::IsCodeTarget(rmode));

  if (CanUseNearCallOrJump(rmode)) {
    EmbeddedObjectIndex index = AddEmbeddedObject(code);
    DCHECK(is_int32(index));
    near_call(static_cast<int32_t>(index), rmode);
  } else {
    IndirectCall(code.address(), rmode);
  }
}

void MacroAssembler::Call(ExternalReference target) {
  UseScratchRegisterScope temps(this);
  Register temp = temps.AcquireX();
  Mov(temp, target);
  Call(temp);
}

void MacroAssembler::LoadEntryFromBuiltinIndex(Register builtin_index,
                                               Register target) {
  ASM_CODE_COMMENT(this);
  // The builtin_index register contains the builtin index as a Smi.
  if (SmiValuesAre32Bits()) {
    Asr(target, builtin_index, kSmiShift - kSystemPointerSizeLog2);
    Add(target, target, IsolateData::builtin_entry_table_offset());
    Ldr(target, MemOperand(kRootRegister, target));
  } else {
    DCHECK(SmiValuesAre31Bits());
    if (COMPRESS_POINTERS_BOOL) {
      Add(target, kRootRegister,
          Operand(builtin_index.W(), SXTW, kSystemPointerSizeLog2 - kSmiShift));
    } else {
      Add(target, kRootRegister,
          Operand(builtin_index, LSL, kSystemPointerSizeLog2 - kSmiShift));
    }
    Ldr(target, MemOperand(target, IsolateData::builtin_entry_table_offset()));
  }
}

void MacroAssembler::LoadEntryFromBuiltin(Builtin builtin,
                                          Register destination) {
  Ldr(destination, EntryFromBuiltinAsOperand(builtin));
}

MemOperand MacroAssembler::EntryFromBuiltinAsOperand(Builtin builtin) {
  ASM_CODE_COMMENT(this);
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
  switch (options().builtin_call_jump_mode) {
    case BuiltinCallJumpMode::kAbsolute: {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.AcquireX();
      Ldr(scratch, Operand(BuiltinEntry(builtin), RelocInfo::OFF_HEAP_TARGET));
      Call(scratch);
      break;
    }
    case BuiltinCallJumpMode::kPCRelative:
      near_call(static_cast<int>(builtin), RelocInfo::NEAR_BUILTIN_ENTRY);
      break;
    case BuiltinCallJumpMode::kIndirect: {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.AcquireX();
      LoadEntryFromBuiltin(builtin, scratch);
      Call(scratch);
      break;
    }
    case BuiltinCallJumpMode::kForMksnapshot: {
      if (options().use_pc_relative_calls_and_jumps_for_mksnapshot) {
        Handle<Code> code = isolate()->builtins()->code_handle(builtin);
        EmbeddedObjectIndex index = AddEmbeddedObject(code);
        DCHECK(is_int32(index));
        near_call(static_cast<int32_t>(index), RelocInfo::CODE_TARGET);
      } else {
        UseScratchRegisterScope temps(this);
        Register scratch = temps.AcquireX();
        LoadEntryFromBuiltin(builtin, scratch);
        Call(scratch);
      }
      break;
    }
  }
}

// TODO(ishell): remove cond parameter from here to simplify things.
void MacroAssembler::TailCallBuiltin(Builtin builtin, Condition cond) {
  ASM_CODE_COMMENT_STRING(this,
                          CommentForOffHeapTrampoline("tail call", builtin));

  // The control flow integrity (CFI) feature allows us to "sign" code entry
  // points as a target for calls, jumps or both. Arm64 has special
  // instructions for this purpose, so-called "landing pads" (see
  // MacroAssembler::CallTarget(), MacroAssembler::JumpTarget() and
  // MacroAssembler::JumpOrCallTarget()). Currently, we generate "Call"
  // landing pads for CPP builtins. In order to allow tail calling to those
  // builtins we have to use a workaround.
  // x17 is used to allow using "Call" (i.e. `bti c`) rather than "Jump"
  // (i.e. `bti j`) landing pads for the tail-called code.
  Register temp = x17;

  switch (options().builtin_call_jump_mode) {
    case BuiltinCallJumpMode::kAbsolute: {
      Ldr(temp, Operand(BuiltinEntry(builtin), RelocInfo::OFF_HEAP_TARGET));
      Jump(temp, cond);
      break;
    }
    case BuiltinCallJumpMode::kPCRelative: {
      if (cond != nv) {
        Label done;
        if (cond != al) B(NegateCondition(cond), &done);
        near_jump(static_cast<int>(builtin), RelocInfo::NEAR_BUILTIN_ENTRY);
        Bind(&done);
      }
      break;
    }
    case BuiltinCallJumpMode::kIndirect: {
      LoadEntryFromBuiltin(builtin, temp);
      Jump(temp, cond);
      break;
    }
    case BuiltinCallJumpMode::kForMksnapshot: {
      if (options().use_pc_relative_calls_and_jumps_for_mksnapshot) {
        Handle<Code> code = isolate()->builtins()->code_handle(builtin);
        EmbeddedObjectIndex index = AddEmbeddedObject(code);
        DCHECK(is_int32(index));
        JumpHelper(static_cast<int64_t>(index), RelocInfo::CODE_TARGET, cond);
      } else {
        LoadEntryFromBuiltin(builtin, temp);
        Jump(temp, cond);
      }
      break;
    }
  }
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
  Ldr(destination, FieldMemOperand(code_object, Code::kInstructionStartOffset));
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
  // We jump through x17 here because for Branch Identification (BTI) we use
  // "Call" (`bti c`) rather than "Jump" (`bti j`) landing pads for tail-called
  // code. See TailCallBuiltin for more information.
  if (code_object != x17) {
    Mov(x17, code_object);
  }
  Jump(x17);
}

void MacroAssembler::CallJSFunction(Register function_object,
                                    uint16_t argument_count) {
  Register code = kJavaScriptCallCodeStartRegister;
#if V8_ENABLE_LEAPTIERING
  Register dispatch_handle = kJavaScriptCallDispatchHandleRegister;
  Register parameter_count = x20;
  Register scratch = x21;

  Ldr(dispatch_handle.W(),
      FieldMemOperand(function_object, JSFunction::kDispatchHandleOffset));
  LoadEntrypointAndParameterCountFromJSDispatchTable(code, parameter_count,
                                                     dispatch_handle, scratch);
  // Force a safe crash if the parameter count doesn't match.
  Cmp(parameter_count, Immediate(argument_count));
  SbxCheck(le, AbortReason::kJSSignatureMismatch);
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
#if V8_ENABLE_LEAPTIERING
  Register dispatch_handle = kJavaScriptCallDispatchHandleRegister;
  Register scratch = x20;
  Ldr(dispatch_handle.W(),
      FieldMemOperand(function_object, JSFunction::kDispatchHandleOffset));
  LoadEntrypointFromJSDispatchTable(code, dispatch_handle, scratch);
  DCHECK_EQ(jump_mode, JumpMode::kJump);
  // We jump through x17 here because for Branch Identification (BTI) we use
  // "Call" (`bti c`) rather than "Jump" (`bti j`) landing pads for tail-called
  // code. See TailCallBuiltin for more information.
  DCHECK_NE(code, x17);
  Mov(x17, code);
  Jump(x17);
  // This implementation is not currently used because callers usually need
  // to load both entry point and parameter count and then do something with
  // the latter before the actual call.
  // TODO(ishell): remove the above code once it's clear it's not needed.
  UNREACHABLE();
#elif V8_ENABLE_SANDBOX
  // When the sandbox is enabled, we can directly fetch the entrypoint pointer
  // from the code pointer table instead of going through the Code object. In
  // this way, we avoid one memory load on this code path.
  LoadCodeEntrypointViaCodePointer(
      code, FieldMemOperand(function_object, JSFunction::kCodeOffset),
      kJSEntrypointTag);
  DCHECK_EQ(jump_mode, JumpMode::kJump);
  // We jump through x17 here because for Branch Identification (BTI) we use
  // "Call" (`bti c`) rather than "Jump" (`bti j`) landing pads for tail-called
  // code. See TailCallBuiltin for more information.
  DCHECK_NE(code, x17);
  Mov(x17, code);
  Jump(x17);
#else
  LoadTaggedField(code,
                  FieldMemOperand(function_object, JSFunction::kCodeOffset));
  JumpCodeObject(code, kJSEntrypointTag, jump_mode);
#endif
}

void MacroAssembler::ResolveWasmCodePointer(Register target) {
#ifdef V8_ENABLE_WASM_CODE_POINTER_TABLE
  ExternalReference global_jump_table =
      ExternalReference::wasm_code_pointer_table();
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();
  Mov(scratch, global_jump_table);
  static_assert(sizeof(wasm::WasmCodePointerTableEntry) == kSystemPointerSize);
  lsl(target.W(), target.W(), kSystemPointerSizeLog2);
  Ldr(target, MemOperand(scratch, target));
#endif
}

void MacroAssembler::CallWasmCodePointer(Register target,
                                         CallJumpMode call_jump_mode) {
  ResolveWasmCodePointer(target);
  if (call_jump_mode == CallJumpMode::kTailCall) {
    Jump(target);
  } else {
    Call(target);
  }
}

void MacroAssembler::LoadWasmCodePointer(Register dst, MemOperand src) {
  if constexpr (V8_ENABLE_WASM_CODE_POINTER_TABLE_BOOL) {
    static_assert(!V8_ENABLE_WASM_CODE_POINTER_TABLE_BOOL ||
                  sizeof(WasmCodePointer) == 4);
    Ldr(dst.W(), src);
  } else {
    static_assert(V8_ENABLE_WASM_CODE_POINTER_TABLE_BOOL ||
                  sizeof(WasmCodePointer) == 8);
    Ldr(dst, src);
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

  UseScratchRegisterScope temps(this);
  temps.Exclude(x16, x17);
  DCHECK(!AreAliased(x16, x17, target));

  Label return_location;
  Adr(x17, &return_location);
#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
  Add(x16, sp, kSystemPointerSize);
  Pacib1716();
#endif
  Str(x17, MemOperand(sp));

  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT_STRING(this, "Verify fp[kSPOffset]-8");
    // Verify that the slot below fp[kSPOffset]-8 points to the signed return
    // location.
    Ldr(x16, MemOperand(fp, ExitFrameConstants::kSPOffset));
    Ldr(x16, MemOperand(x16, -static_cast<int64_t>(kXRegSize)));
    Cmp(x16, x17);
    Check(eq, AbortReason::kReturnAddressNotFoundInFrame);
  }

  Blr(target);
  Bind(&return_location);
}

void MacroAssembler::IndirectCall(Address target, RelocInfo::Mode rmode) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register temp = temps.AcquireX();
  Mov(temp, Immediate(target, rmode));
  Blr(temp);
}

bool MacroAssembler::IsNearCallOffset(int64_t offset) {
  return is_int26(offset);
}

// Check if the code object is marked for deoptimization. If it is, then it
// jumps to the CompileLazyDeoptimizedCode builtin. In order to do this we need
// to:
//    1. read from memory the word that contains that bit, which can be found in
//       the flags in the referenced {Code} object;
//    2. test kMarkedForDeoptimizationBit in those flags; and
//    3. if it is not zero then it jumps to the builtin.
void MacroAssembler::BailoutIfDeoptimized() {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();
  int offset = InstructionStream::kCodeOffset - InstructionStream::kHeaderSize;
  LoadProtectedPointerField(
      scratch, MemOperand(kJavaScriptCallCodeStartRegister, offset));
  Ldr(scratch.W(), FieldMemOperand(scratch, Code::kFlagsOffset));
  Label not_deoptimized;
  Tbz(scratch.W(), Code::kMarkedForDeoptimizationBit, &not_deoptimized);
  TailCallBuiltin(Builtin::kCompileLazyDeoptimizedCode);
  Bind(&not_deoptimized);
}

void MacroAssembler::CallForDeoptimization(
    Builtin target, int deopt_id, Label* exit, DeoptimizeKind kind, Label* ret,
    Label* jump_deoptimization_entry_label) {
  ASM_CODE_COMMENT(this);
  BlockPoolsScope scope(this);
  bl(jump_deoptimization_entry_label);
  DCHECK_EQ(SizeOfCodeGeneratedSince(exit),
            (kind == DeoptimizeKind::kLazy) ? Deoptimizer::kLazyDeoptExitSize
                                            : Deoptimizer::kEagerDeoptExitSize);
}

void MacroAssembler::LoadStackLimit(Register destination, StackLimitKind kind) {
  ASM_CODE_COMMENT(this);
  DCHECK(root_array_available());
  intptr_t offset = kind == StackLimitKind::kRealStackLimit
                        ? IsolateData::real_jslimit_offset()
                        : IsolateData::jslimit_offset();

  Ldr(destination, MemOperand(kRootRegister, offset));
}

void MacroAssembler::StackOverflowCheck(Register num_args,
                                        Label* stack_overflow) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();

  // Check the stack for overflow.
  // We are not trying to catch interruptions (e.g. debug break and
  // preemption) here, so the "real stack limit" is checked.

  LoadStackLimit(scratch, StackLimitKind::kRealStackLimit);
  // Make scratch the space we have left. The stack might already be overflowed
  // here which will cause scratch to become negative.
  Sub(scratch, sp, scratch);
  // Check if the arguments will overflow the stack.
  Cmp(scratch, Operand(num_args, LSL, kSystemPointerSizeLog2));
  B(le, stack_overflow);
}

void MacroAssembler::InvokePrologue(Register formal_parameter_count,
                                    Register actual_argument_count,
                                    InvokeType type) {
  ASM_CODE_COMMENT(this);
  //  x0: actual arguments count.
  //  x1: function (passed through to callee).
  //  x2: expected arguments count.
  //  x3: new target
  Label regular_invoke;
  DCHECK_EQ(actual_argument_count, x0);
  DCHECK_EQ(formal_parameter_count, x2);

  // If overapplication or if the actual argument count is equal to the
  // formal parameter count, no need to push extra undefined values.
  Register extra_argument_count = x2;
  Subs(extra_argument_count, formal_parameter_count, actual_argument_count);
  B(le, &regular_invoke);

  // The stack pointer in arm64 needs to be 16-byte aligned. We might need to
  // (1) add an extra padding or (2) remove (re-use) the extra padding already
  // in the stack. Let {slots_to_copy} be the number of slots (arguments) to
  // move up in the stack and let {slots_to_claim} be the number of extra stack
  // slots to claim.
  Label even_extra_count, skip_move;
  Register slots_to_copy = x5;
  Register slots_to_claim = x6;

  Mov(slots_to_copy, actual_argument_count);
  Mov(slots_to_claim, extra_argument_count);
  Tbz(extra_argument_count, 0, &even_extra_count);

  // Calculate {slots_to_claim} when {extra_argument_count} is odd.
  // If {actual_argument_count} is even, we need one extra padding slot
  // {slots_to_claim = extra_argument_count + 1}.
  // If {actual_argument_count} is odd, we know that the
  // original arguments will have a padding slot that we can reuse
  // {slots_to_claim = extra_argument_count - 1}.
  {
    Register scratch = x11;
    Add(slots_to_claim, extra_argument_count, 1);
    And(scratch, actual_argument_count, 1);
    Sub(slots_to_claim, slots_to_claim, Operand(scratch, LSL, 1));
  }

  Bind(&even_extra_count);
  Cbz(slots_to_claim, &skip_move);

  Label stack_overflow;
  StackOverflowCheck(slots_to_claim, &stack_overflow);
  Claim(slots_to_claim);

  // Move the arguments already in the stack including the receiver.
  {
    Register src = x7;
    Register dst = x8;
    SlotAddress(src, slots_to_claim);
    SlotAddress(dst, 0);
    CopyDoubleWords(dst, src, slots_to_copy);
  }

  Bind(&skip_move);
  Register pointer_next_value = x6;

  // Copy extra arguments as undefined values.
  {
    Label loop;
    Register undefined_value = x7;
    Register count = x8;
    LoadRoot(undefined_value, RootIndex::kUndefinedValue);
    SlotAddress(pointer_next_value, actual_argument_count);
    Mov(count, extra_argument_count);
    Bind(&loop);
    Str(undefined_value,
        MemOperand(pointer_next_value, kSystemPointerSize, PostIndex));
    Subs(count, count, 1);
    Cbnz(count, &loop);
  }

  // Set padding if needed.
  {
    Label skip;
    Register total_args_slots = x5;
    Add(total_args_slots, actual_argument_count, extra_argument_count);
    Tbz(total_args_slots, 0, &skip);
    Str(padreg, MemOperand(pointer_next_value));
    Bind(&skip);
  }
  B(&regular_invoke);

  bind(&stack_overflow);
  {
    FrameScope frame(
        this, has_frame() ? StackFrame::NO_FRAME_TYPE : StackFrame::INTERNAL);
    CallRuntime(Runtime::kThrowStackOverflow);
    Unreachable();
  }

  Bind(&regular_invoke);
}

void MacroAssembler::CallDebugOnFunctionCall(
    Register fun, Register new_target,
    Register expected_parameter_count_or_dispatch_handle,
    Register
"""


```