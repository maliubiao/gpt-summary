Response:
Let's break down the thought process for analyzing this C++ header file and answering the prompt.

**1. Understanding the Goal:**

The primary goal is to understand the *functionality* of the `macro-assembler-riscv.h` file within the V8 JavaScript engine. The prompt also has specific sub-goals related to Torque, JavaScript relevance, logic examples, common errors, and a final summary.

**2. Initial Scan and Keyword Recognition:**

I would first scan the file for prominent keywords and structural elements:

* **`#ifndef`, `#define`, `#endif`:** This confirms it's a header file and uses include guards.
* **`namespace v8`, `namespace internal`:**  Indicates it's part of the V8 engine's internal implementation.
* **`class MacroAssembler`:** This is the core of the file. It's a class named `MacroAssembler`. The name itself is a strong clue – it likely helps in generating machine code (assembly) for the RISC-V architecture.
* **Function names (e.g., `CompareObjectTypeAndJump`, `PushStackHandler`, `CallRuntime`, `LoadWeakValue`, `IncrementCounter`, `SmiScale`, `JumpIfNotSmi`, `AssertConstructor`):** These provide the most direct insights into the file's capabilities. They suggest operations related to:
    * Object type checking.
    * Exception handling.
    * Function calls (runtime and built-in).
    * Weak references.
    * Performance counters.
    * Stack manipulation.
    * Smi (Small Integer) handling.
    * Assertions (for debugging).
    * Dispatch tables.
    * Floating-point operations.
* **Data types (e.g., `Register`, `Label*`, `Condition`, `InstanceType`, `Runtime::FunctionId`, `StatsCounter*`, `MemOperand`, `DoubleRegister`, `FPURegister`):** These reveal the underlying concepts and data structures the assembler works with. They indicate interactions with registers, memory, and V8-specific types.
* **Preprocessor directives (e.g., `#if V8_TARGET_ARCH_RISCV64`, `#ifdef V8_ENABLE_LEAPTIERING`):**  These show conditional compilation based on the target architecture and build flags.
* **Comments:**  The comments are crucial! They often explain the purpose of functions and provide context.

**3. Categorizing Functionality:**

Based on the scanned keywords and function names, I'd start grouping the functionalities:

* **Object Handling:** `CompareObjectTypeAndJump`, `IsObjectType`, `GetObjectType`, `GetInstanceTypeRange`
* **Control Flow/Branching:**  Various `JumpIf...`, `Branch...` functions.
* **Function Calls:** `CallRuntime`, `TailCallRuntime`, `JumpToExternalReference`, `GenerateTailCallToReturnedCode`, `InvokePrologue`, `CallApiFunctionAndReturn`
* **Exception Handling:** `PushStackHandler`, `PopStackHandler`
* **Stack Manipulation:** `PushCommonFrame`, `DropArguments`, `LoadStackLimit`, `StackOverflowCheck`
* **Small Integer (Smi) Operations:** `SmiScale`, `SmiTst`, `JumpIfNotSmi`
* **Debugging/Assertions:**  All the `Assert...` functions.
* **Performance/Stats:** `IncrementCounter`, `DecrementCounter`
* **Weak References:** `LoadWeakValue`
* **Dispatch Tables:** `LoadEntrypointFromJSDispatchTable`, etc.
* **Floating Point:** `TryInlineTruncateDoubleToI`, `RoundHelper`
* **Code Optimization/Tiering:** `AssertFeedbackCell`, `AssertFeedbackVector`, `ReplaceClosureCodeWithOptimizedCode`, `LoadFeedbackVectorFlags...`, `OptimizeCodeOrTailCallOptimizedCodeSlot`

**4. Addressing Specific Prompt Questions:**

* **Torque:** The prompt explicitly mentions checking for the `.tq` extension. Since this file ends in `.h`, it's not a Torque file.
* **JavaScript Relationship:**  This requires connecting the low-level assembler to higher-level JavaScript concepts. The key here is understanding that the `MacroAssembler` is *how* V8 executes JavaScript. The functions listed directly implement the core operations needed to run JavaScript code. Examples like object creation, function calls, type checking, and handling runtime errors all have direct mappings. I would then construct simple JavaScript examples that would trigger these underlying assembler functions.
* **Logic Examples:**  Choose a relatively simple function like `CompareObjectTypeAndJump`. Invent hypothetical register values and an `InstanceType` to illustrate the conditional jump. Describe the expected flag settings and register contents.
* **Common Errors:** Think about mistakes developers might make when interacting with low-level code or even when the *engine* itself might encounter errors that these functions handle. Examples include incorrect type assumptions, stack overflows, and calling non-functions.
* **Summary:**  Synthesize the categorized functionalities into a concise overview of the `MacroAssembler`'s role in code generation and execution for RISC-V in V8.

**5. Refinement and Organization:**

Finally, I'd organize the findings into a clear and structured answer, addressing each part of the prompt. I'd use bullet points, code examples, and explanations to make the information easy to understand. I would review the answer for clarity, accuracy, and completeness.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe focus heavily on individual instructions.
* **Correction:** Realize the prompt asks for *functionality*, so focusing on the higher-level purpose of the functions is more important than detailing every assembly instruction they might generate.
* **Initial thought:** Provide very complex JavaScript examples.
* **Correction:** Use simpler, more illustrative JavaScript snippets that directly relate to the core assembler functions.
* **Initial thought:**  Overlook the connection between the assembler and JavaScript execution.
* **Correction:** Explicitly state that the `MacroAssembler` is the mechanism for executing JavaScript on the RISC-V architecture.

By following this thought process, breaking down the problem, and systematically analyzing the code, I can arrive at a comprehensive and accurate answer to the prompt.
这是对 V8 引擎中 `v8/src/codegen/riscv/macro-assembler-riscv.h` 文件功能的总结。

**功能归纳:**

`v8/src/codegen/riscv/macro-assembler-riscv.h` 文件定义了 `MacroAssembler` 类，它是 V8 引擎在 RISC-V 架构上生成机器码的核心工具。 它的主要功能可以归纳为：

1. **指令流生成辅助:**  `MacroAssembler` 提供了一系列方法，用于方便地生成 RISC-V 汇编指令序列。它封装了底层的汇编指令，使得 V8 的代码生成器可以更容易、更高效地生成目标代码。

2. **支持功能:**  它包含了许多用于实现 V8 运行时行为的辅助函数，例如：
    * **对象类型比较:**  `CompareObjectTypeAndJump`, `IsObjectType` 用于检查堆对象的类型。
    * **异常处理:** `PushStackHandler`, `PopStackHandler` 用于管理异常处理栈帧。
    * **代码分层优化 (Tiering):** `AssertFeedbackCell`, `AssertFeedbackVector`, `ReplaceClosureCodeWithOptimizedCode`, `GenerateTailCallToReturnedCode`,  `LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing`, `OptimizeCodeOrTailCallOptimizedCodeSlot` 等函数支持代码的优化和分层执行。
    * **获取对象类型:** `GetObjectType`, `GetInstanceTypeRange` 用于获取对象的类型信息。
    * **运行时调用:** `CallRuntime`, `TailCallRuntime` 用于调用 V8 的运行时函数。
    * **弱引用:** `LoadWeakValue` 用于加载弱引用，并在引用被清除时跳转。
    * **性能计数器:** `IncrementCounter`, `DecrementCounter` 用于更新性能统计信息。
    * **栈限制工具:** `LoadStackLimit`, `StackOverflowCheck` 用于管理和检查栈溢出。
    * **Smi (小整数) 处理:** `SmiScale`, `SmiTst` 用于处理 Smi 类型的值。
    * **参数处理:** `DropArguments`, `DropArgumentsAndPushNewReceiver` 用于操作函数调用的参数。
    * **代码去优化检查:** `JumpIfCodeIsMarkedForDeoptimization` 用于检查代码是否被标记为需要去优化。
    * **断言:**  各种 `Assert...` 函数用于在调试模式下进行条件检查。
    * **位域解码:** `DecodeField` 用于提取位域信息。
    * **Dispatch Table (Leaptiering 支持):**  `LoadEntrypointFromJSDispatchTable` 等函数用于支持 Leaptiering 优化技术。
    * **受保护指针字段加载:** `LoadProtectedPointerField` 用于加载受保护的指针。
    * **浮点数截断:** `TryInlineTruncateDoubleToI` 用于将浮点数截断为整数。
    * **switch 语句生成:** `GenerateSwitchTable` 用于生成 switch 语句的跳转表。
    * **API 函数调用:** `CallApiFunctionAndReturn` 用于调用 C++ API 函数并处理返回值和异常。

**关于 .tq 扩展名:**

正如你所说，如果 `v8/src/codegen/riscv/macro-assembler-riscv.h` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。Torque 是一种 V8 特有的领域特定语言，用于生成高效的 C++ 代码，通常用于实现 V8 的内置函数和运行时部分。由于该文件以 `.h` 结尾，它是一个 C++ 头文件。

**与 JavaScript 功能的关系及示例:**

`MacroAssembler` 的功能直接关系到 JavaScript 的执行。当 V8 编译 JavaScript 代码时，它会使用 `MacroAssembler` 将高级的 JavaScript 操作转换为底层的 RISC-V 机器指令。

例如，JavaScript 中的一个简单的加法操作：

```javascript
function add(a, b) {
  return a + b;
}
```

在 V8 编译执行 `add` 函数时，`MacroAssembler` 会生成类似以下的 RISC-V 指令（简化表示）：

1. **加载参数:** 将 `a` 和 `b` 的值从寄存器或内存加载到 RISC-V 的寄存器中。
2. **执行加法:** 使用 RISC-V 的加法指令将两个寄存器的值相加。
3. **返回结果:** 将结果存储到指定的寄存器中，以便返回。

`MacroAssembler` 中提供的一些函数直接对应着 JavaScript 的运行时行为：

* **对象类型检查 (`CompareObjectTypeAndJump`, `IsObjectType`):**  当 JavaScript 代码中需要判断一个对象的类型时（例如使用 `typeof` 或进行原型链查找），`MacroAssembler` 中的这些函数会被用来生成相应的机器码。

   ```javascript
   function isNumber(x) {
     return typeof x === 'number';
   }
   ```
   V8 会使用 `CompareObjectTypeAndJump` 或类似的指令来检查 `x` 的类型是否为 Number。

* **函数调用 (`CallRuntime`):** 当 JavaScript 代码调用一些内置函数或需要执行一些运行时操作时，`MacroAssembler` 会使用 `CallRuntime` 来调用相应的 C++ 运行时函数。

   ```javascript
   Math.sqrt(9);
   ```
   对 `Math.sqrt` 的调用会通过 `MacroAssembler` 生成调用 V8 内部 `MathSqrt` 函数的指令。

* **异常处理 (`PushStackHandler`, `PopStackHandler`):** 当 JavaScript 代码中使用 `try...catch` 语句时，`MacroAssembler` 会使用这些函数来设置和清理异常处理的栈帧。

   ```javascript
   try {
     // 可能抛出异常的代码
     throw new Error("Something went wrong");
   } catch (e) {
     console.error(e);
   }
   ```
   `PushStackHandler` 会在 `try` 块开始时被调用，而 `PopStackHandler` 会在 `try` 块结束或 `catch` 块开始时被调用。

**代码逻辑推理示例:**

假设我们有以下 `CompareObjectTypeAndJump` 的调用：

```c++
CompareObjectTypeAndJump(a0, a1, a2, MAP_SPACE, kEqual, &target_label, Label::kNear);
```

**假设输入:**

* `a0` 寄存器包含一个堆对象的地址。
* `a1` 寄存器包含该对象的 `map` 属性的地址。
* `a2` 寄存器将用于存储对象的类型信息。
* `MAP_SPACE` 是一个表示 `MAP_SPACE_TYPE` 的枚举值。
* `kEqual` 是一个表示相等条件的枚举值。
* `target_label` 是一个代码标签。

**输出:**

1. **类型信息加载:**  `a2` 寄存器将被设置为 `a0` 指向的对象的类型信息。
2. **条件比较:** 将 `a2` 中的对象类型与 `MAP_SPACE_TYPE` 进行比较。
3. **条件跳转:** 如果对象类型等于 `MAP_SPACE_TYPE`，则程序会跳转到 `target_label` 标签处执行。否则，程序会继续执行下一条指令。
4. **标志位设置:**  RISC-V 的条件标志位会被设置，以反映比较的结果（例如，零标志位会被设置，如果类型相等）。

**用户常见的编程错误示例:**

虽然用户通常不会直接编写 RISC-V 汇编代码，但在理解 V8 的工作原理时，可以想象一些与这些功能相关的潜在错误：

* **类型假设错误:**  在优化代码时，如果 V8 错误地假设了某个对象的类型，那么在执行到类型检查相关的代码时，可能会导致意外的行为或崩溃。例如，如果 V8 假设一个变量总是数字，并在没有进行类型检查的情况下进行算术运算，那么当该变量实际上是字符串时，就会出错。

* **栈溢出:**  如果 JavaScript 代码导致过多的函数调用（例如，无限递归），最终会导致栈溢出。`StackOverflowCheck` 函数旨在在发生这种情况之前检测到，但如果配置不当或存在漏洞，仍然可能发生栈溢出错误。

* **未处理的异常:**  如果 JavaScript 代码中抛出的异常没有被 `try...catch` 捕获，那么 V8 的异常处理机制会介入。如果 `PushStackHandler` 和 `PopStackHandler` 的使用不当，可能会导致异常处理过程出错，例如，无法正确找到合适的 `catch` 块。

**总结:**

`v8/src/codegen/riscv/macro-assembler-riscv.h` 是 V8 引擎中至关重要的组成部分，它为 RISC-V 架构上的代码生成提供了基础框架和工具。它封装了底层的汇编指令，并提供了各种高级功能，用于实现 JavaScript 的语义、优化代码性能以及处理运行时事件。理解 `MacroAssembler` 的功能有助于深入理解 V8 引擎的工作原理和 JavaScript 的执行过程。

### 提示词
```
这是目录为v8/src/codegen/riscv/macro-assembler-riscv.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/riscv/macro-assembler-riscv.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```c
tructionStream generation helpers ----

  // ---------------------------------------------------------------------------
  // Support functions.

  // Compare object type for heap object.  heap_object contains a non-Smi
  // whose object type should be compared with the given type.  This both
  // sets the flags and leaves the object type in the type_reg register.
  // It leaves the map in the map register (unless the type_reg and map register
  // are the same register).  It leaves the heap object in the heap_object
  // register unless the heap_object register is the same register as one of the
  // other registers.
  void CompareObjectTypeAndJump(Register heap_object, Register map,
                                Register type_reg, InstanceType type,
                                Condition cond, Label* target,
                                Label::Distance distance);
  // Variant of the above, which only guarantees to set the correct eq/ne flag.
  // Neither map, nor type_reg might be set to any particular value.
  void IsObjectType(Register heap_object, Register scratch1, Register scratch2,
                    InstanceType type);

  // Exception handling.

  // Push a new stack handler and link into stack handler chain.
  void PushStackHandler();

  // Unlink the stack handler on top of the stack from the stack handler chain.
  // Must preserve the result register.
  void PopStackHandler();

  // Tiering support.
  void AssertFeedbackCell(Register object,
                          Register scratch) NOOP_UNLESS_DEBUG_CODE;
  void AssertFeedbackVector(Register object,
                            Register scratch) NOOP_UNLESS_DEBUG_CODE;
  void ReplaceClosureCodeWithOptimizedCode(Register optimized_code,
                                           Register closure);
  void GenerateTailCallToReturnedCode(Runtime::FunctionId function_id);

  Condition LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing(
      Register flags, Register feedback_vector, Register result,
      CodeKind current_code_kind);
  void LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
      Register flags, Register feedback_vector, CodeKind current_code_kind,
      Label* flags_need_processing);
  void OptimizeCodeOrTailCallOptimizedCodeSlot(Register flags,
                                               Register feedback_vector);

  // -------------------------------------------------------------------------
  // Support functions.

  void GetObjectType(Register function, Register map, Register type_reg);

  void GetInstanceTypeRange(Register map, Register type_reg,
                            InstanceType lower_limit, Register range);

  // -------------------------------------------------------------------------
  // Runtime calls.

  // Call a runtime routine.
  void CallRuntime(const Runtime::Function* f, int num_arguments);

  // Convenience function: Same as above, but takes the fid instead.
  void CallRuntime(Runtime::FunctionId fid) {
    const Runtime::Function* function = Runtime::FunctionForId(fid);
    CallRuntime(function, function->nargs);
  }

  // Convenience function: Same as above, but takes the fid instead.
  void CallRuntime(Runtime::FunctionId fid, int num_arguments) {
    CallRuntime(Runtime::FunctionForId(fid), num_arguments);
  }

  // Convenience function: tail call a runtime routine (jump).
  void TailCallRuntime(Runtime::FunctionId fid);

  // Jump to the builtin routine.
  void JumpToExternalReference(const ExternalReference& builtin,
                               bool builtin_exit_frame = false);
  // ---------------------------------------------------------------------------
  // In-place weak references.
  void LoadWeakValue(Register out, Register in, Label* target_if_cleared);

  // -------------------------------------------------------------------------
  // StatsCounter support.

  void IncrementCounter(StatsCounter* counter, int value, Register scratch1,
                        Register scratch2) {
    if (!v8_flags.native_code_counters) return;
    EmitIncrementCounter(counter, value, scratch1, scratch2);
  }
  void EmitIncrementCounter(StatsCounter* counter, int value, Register scratch1,
                            Register scratch2);
  void DecrementCounter(StatsCounter* counter, int value, Register scratch1,
                        Register scratch2) {
    if (!v8_flags.native_code_counters) return;
    EmitDecrementCounter(counter, value, scratch1, scratch2);
  }
  void EmitDecrementCounter(StatsCounter* counter, int value, Register scratch1,
                            Register scratch2);

  // -------------------------------------------------------------------------
  // Stack limit utilities
  void LoadStackLimit(Register destination, StackLimitKind kind);
  void StackOverflowCheck(Register num_args, Register scratch1,
                          Register scratch2, Label* stack_overflow,
                          Label* done = nullptr);

  // Left-shifted from int32 equivalent of Smi.
  void SmiScale(Register dst, Register src, int scale) {
#if V8_TARGET_ARCH_RISCV64
    if (SmiValuesAre32Bits()) {
      // The int portion is upper 32-bits of 64-bit word.
      srai(dst, src, (kSmiShift - scale) & 0x3F);
    } else {
      DCHECK(SmiValuesAre31Bits());
      DCHECK_GE(scale, kSmiTagSize);
      slliw(dst, src, scale - kSmiTagSize);
    }
#elif V8_TARGET_ARCH_RISCV32
    DCHECK(SmiValuesAre31Bits());
    DCHECK_GE(scale, kSmiTagSize);
    slli(dst, src, scale - kSmiTagSize);
#endif
  }

  // Test if the register contains a smi.
  inline void SmiTst(Register value, Register scratch) {
    And(scratch, value, Operand(kSmiTagMask));
  }

  enum ArgumentsCountMode { kCountIncludesReceiver, kCountExcludesReceiver };
  enum ArgumentsCountType { kCountIsInteger, kCountIsSmi };
  void DropArguments(Register count);
  void DropArgumentsAndPushNewReceiver(Register argc, Register receiver);

  void JumpIfCodeIsMarkedForDeoptimization(Register code, Register scratch,
                                           Label* if_marked_for_deoptimization);
  Operand ClearedValue() const;

  // Jump if the register contains a non-smi.
  void JumpIfNotSmi(Register value, Label* not_smi_label,
                    Label::Distance dist = Label::kFar);
  // Abort execution if argument is not a Constructor, enabled via --debug-code.
  void AssertConstructor(Register object);

  // Abort execution if argument is not a JSFunction, enabled via --debug-code.
  void AssertFunction(Register object);

  // Abort execution if argument is not a callable JSFunction, enabled via
  // --debug-code.
  void AssertCallableFunction(Register object);

  // Abort execution if argument is not a JSBoundFunction,
  // enabled via --debug-code.
  void AssertBoundFunction(Register object);

  // Abort execution if argument is not a JSGeneratorObject (or subclass),
  // enabled via --debug-code.
  void AssertGeneratorObject(Register object);

  // Calls Abort(msg) if the condition cond is not satisfied.
  // Use --debug_code to enable.
  void Assert(Condition cond, AbortReason reason) NOOP_UNLESS_DEBUG_CODE;

  // Like Assert(), but without condition.
  // Use --debug_code to enable.
  void AssertUnreachable(AbortReason reason) NOOP_UNLESS_DEBUG_CODE;

  // Abort execution if argument is not undefined or an AllocationSite, enabled
  // via --debug-code.
  void AssertUndefinedOrAllocationSite(Register object, Register scratch);

  template <typename Field>
  void DecodeField(Register dst, Register src) {
    ExtractBits(dst, src, Field::kShift, Field::kSize);
  }

  template <typename Field>
  void DecodeField(Register reg) {
    DecodeField<Field>(reg, reg);
  }

#ifdef V8_ENABLE_LEAPTIERING
  // Load the entrypoint pointer of a JSDispatchTable entry.
  void LoadEntrypointFromJSDispatchTable(Register destination,
                                         Register dispatch_handle,
                                         Register scratch);
  void LoadParameterCountFromJSDispatchTable(Register destination,
                                             Register dispatch_handle,
                                             Register scratch);
  void LoadEntrypointAndParameterCountFromJSDispatchTable(
      Register entrypoint, Register parameter_count, Register dispatch_handle,
      Register scratch);
#endif  // V8_ENABLE_LEAPTIERING
  // Load a protected pointer field.
  void LoadProtectedPointerField(Register destination,
                                 MemOperand field_operand);
  // Performs a truncating conversion of a floating point number as used by
  // the JS bitwise operations. See ECMA-262 9.5: ToInt32. Goes to 'done' if it
  // succeeds, otherwise falls through if result is saturated. On return
  // 'result' either holds answer, or is clobbered on fall through.
  void TryInlineTruncateDoubleToI(Register result, DoubleRegister input,
                                  Label* done);

 protected:
  inline Register GetRtAsRegisterHelper(const Operand& rt, Register scratch);
  inline int32_t GetOffset(int32_t offset, Label* L, OffsetSize bits);

 private:
  bool has_double_zero_reg_set_ = false;
  bool has_single_zero_reg_set_ = false;

  int CallCFunctionHelper(
      Register function, int num_reg_arguments, int num_double_arguments,
      SetIsolateDataSlots set_isolate_data_slots = SetIsolateDataSlots::kYes,
      Label* return_location = nullptr);

  // TODO(RISCV) Reorder parameters so out parameters come last.
  bool CalculateOffset(Label* L, int32_t* offset, OffsetSize bits);
  bool CalculateOffset(Label* L, int32_t* offset, OffsetSize bits,
                       Register* scratch, const Operand& rt);

  void BranchShortHelper(int32_t offset, Label* L);
  bool BranchShortHelper(int32_t offset, Label* L, Condition cond, Register rs,
                         const Operand& rt);
  bool BranchShortCheck(int32_t offset, Label* L, Condition cond, Register rs,
                        const Operand& rt);

  void BranchAndLinkShortHelper(int32_t offset, Label* L);
  void BranchAndLinkShort(int32_t offset);
  void BranchAndLinkShort(Label* L);
  bool BranchAndLinkShortHelper(int32_t offset, Label* L, Condition cond,
                                Register rs, const Operand& rt);
  bool BranchAndLinkShortCheck(int32_t offset, Label* L, Condition cond,
                               Register rs, const Operand& rt);
  void BranchAndLinkLong(Label* L);
#if V8_TARGET_ARCH_RISCV64
  template <typename F_TYPE>
  void RoundHelper(FPURegister dst, FPURegister src, FPURegister fpu_scratch,
                   FPURoundingMode mode);
#elif V8_TARGET_ARCH_RISCV32
  void RoundDouble(FPURegister dst, FPURegister src, FPURegister fpu_scratch,
                   FPURoundingMode mode);

  void RoundFloat(FPURegister dst, FPURegister src, FPURegister fpu_scratch,
                  FPURoundingMode mode);
#endif
  template <typename F>
  void RoundHelper(VRegister dst, VRegister src, Register scratch,
                   VRegister v_scratch, FPURoundingMode frm,
                   bool keep_nan_same = true);

  template <typename TruncFunc>
  void RoundFloatingPointToInteger(Register rd, FPURegister fs, Register result,
                                   TruncFunc trunc);

  // Push a fixed frame, consisting of ra, fp.
  void PushCommonFrame(Register marker_reg = no_reg);

  // Helper functions for generating invokes.
  void InvokePrologue(Register expected_parameter_count,
                      Register actual_parameter_count, Label* done,
                      InvokeType type);

  // Compute memory operands for safepoint stack slots.
  static int SafepointRegisterStackIndex(int reg_code);

  // Needs access to SafepointRegisterStackIndex for compiled frame
  // traversal.
  friend class CommonFrame;

  DISALLOW_IMPLICIT_CONSTRUCTORS(MacroAssembler);
};

template <typename Func>
void MacroAssembler::GenerateSwitchTable(Register index, size_t case_count,
                                         Func GetLabelFunction) {
  // Ensure that dd-ed labels following this instruction use 8 bytes aligned
  // addresses.
  BlockTrampolinePoolFor(static_cast<int>(case_count) * 2 +
                         kSwitchTablePrologueSize);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Register scratch2 = temps.Acquire();

  Align(8);
  // Load the address from the jump table at index and jump to it
  auipc(scratch, 0);  // Load the current PC into scratch
  slli(scratch2, index,
       kSystemPointerSizeLog2);  // scratch2 = offset of indexth entry
  add(scratch2, scratch2,
      scratch);  // scratch2 = (saved PC) + (offset of indexth entry)
  LoadWord(scratch2,
           MemOperand(scratch2,
                      6 * kInstrSize));  // Add the size of these 6 instructions
                                         // to the offset, then load
  jr(scratch2);  // Jump to the address loaded from the table
  nop();         // For 16-byte alignment
  for (size_t index = 0; index < case_count; ++index) {
    dd(GetLabelFunction(index));
  }
}

struct MoveCycleState {
  // List of scratch registers reserved for pending moves in a move cycle, and
  // which should therefore not be used as a temporary location by
  // {MoveToTempLocation}.
  RegList scratch_regs;
  // Available scratch registers during the move cycle resolution scope.
  std::optional<UseScratchRegisterScope> temps;
  // Scratch register picked by {MoveToTempLocation}.
  std::optional<Register> scratch_reg;
};

inline MemOperand ExitFrameStackSlotOperand(int offset) {
  static constexpr int kSPOffset = 1 * kSystemPointerSize;
  return MemOperand(sp, kSPOffset + offset);
}

inline MemOperand ExitFrameCallerStackSlotOperand(int index) {
  return MemOperand(fp, (ExitFrameConstants::kFixedSlotCountAboveFp + index) *
                            kSystemPointerSize);
}

// Calls an API function. Allocates HandleScope, extracts returned value
// from handle and propagates exceptions. Clobbers C argument registers
// and C caller-saved registers. Restores context. On return removes
//   (*argc_operand + slots_to_drop_on_return) * kSystemPointerSize
// (GCed, includes the call JS arguments space and the additional space
// allocated for the fast call).
void CallApiFunctionAndReturn(MacroAssembler* masm, bool with_profiling,
                              Register function_address,
                              ExternalReference thunk_ref, Register thunk_arg,
                              int slots_to_drop_on_return,
                              MemOperand* argc_operand,
                              MemOperand return_value_operand);

#define ACCESS_MASM(masm) masm->

}  // namespace internal
}  // namespace v8

#endif  // V8_CODEGEN_RISCV_MACRO_ASSEMBLER_RISCV_H_
```