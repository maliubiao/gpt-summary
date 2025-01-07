Response:
The user is asking for a summary of the functionality provided by the C++ header file `v8/src/codegen/arm/macro-assembler-arm.h`.

The file seems to define a class `MacroAssembler` which provides an interface for generating ARM assembly instructions.

I need to go through the methods in the provided code snippet and categorize them based on their functionality.

Based on the method names and comments, the functionalities seem to include:
- Loading values (global proxy, native context slot)
- Invoking JavaScript functions
- Handling exceptions (pushing and popping stack handlers)
- Comparing object types and roots
- Checking ranges
- Accessing stack operands
- Supporting tiering (optimization)
- Calling runtime functions
- Handling weak references
- Managing stats counters
- Stack limit checks
- Smi (small integer) utilities
- Assertions for debugging
- Decoding fields
- Code marking for deoptimization
- Helper functions for invoking, comparing floating-point numbers, and handling floating-point min/max.

The prompt also mentions checking if the filename ends with `.tq` (it doesn't) and relating it to JavaScript functionality (which it does, as it's part of the V8 JavaScript engine). I need to provide JavaScript examples where relevant.

For code logic inference, I can take some methods and illustrate their potential inputs and outputs.

For common programming errors, I can think about scenarios where incorrect usage of these assembler methods could lead to issues.
这是 `v8/src/codegen/arm/macro-assembler-arm.h` 文件定义的部分 `MacroAssembler` 类的功能。 `MacroAssembler` 类是 V8 JavaScript 引擎中用于生成 ARM 汇编指令的核心组件。它提供了一系列高级接口，封装了底层的汇编指令，使得 V8 能够动态地生成执行 JavaScript 代码的机器码。

以下是列举的功能：

**1. 加载值 (Loading Values):**

*   `LoadGlobalProxy(Register dst)`: 将全局代理对象加载到目标寄存器 `dst` 中。全局代理对象用于处理全局作用域中的属性访问。
*   `LoadNativeContextSlot(Register dst, int index)`:  从原生上下文（native context）加载指定索引的槽位值到目标寄存器 `dst` 中。原生上下文包含了内置对象和函数。

**2. JavaScript 调用 (JavaScript Invokes):**

*   `InvokeFunctionCode(Register function, Register new_target, Register expected_parameter_count, Register actual_parameter_count, InvokeType type)`:  调用 JavaScript 函数代码。`function` 寄存器包含要调用的函数对象，`new_target` 用于 `new` 操作符，`expected_parameter_count` 和 `actual_parameter_count` 分别表示期望和实际的参数数量，`InvokeType` 指定调用类型（例如，普通调用或构造函数调用）。
*   `CallDebugOnFunctionCall(Register fun, Register new_target, Register expected_parameter_count, Register actual_parameter_count)`:  在函数调用时调用调试器。
*   `InvokeFunctionWithNewTarget(Register function, Register new_target, Register actual_parameter_count, InvokeType type)`:  使用指定的 `new_target` 调用 JavaScript 函数。
*   `InvokeFunction(Register function, Register expected_parameter_count, Register actual_parameter_count, InvokeType type)`: 调用 JavaScript 函数。

**3. 异常处理 (Exception Handling):**

*   `PushStackHandler()`:  压入一个新的栈处理器，并将其链接到栈处理器链中。用于捕获和处理异常。
*   `PopStackHandler()`:  从栈处理器链中移除栈顶的栈处理器。

**4. 支持函数 (Support Functions):**

*   `CompareObjectType(Register heap_object, Register map, Register type_reg, InstanceType type)`:  比较堆对象的类型。`heap_object` 包含要检查的对象，`type` 是要比较的类型。该方法会设置 CPU 的标志位，并将对象类型存储在 `type_reg` 寄存器中，除非 `type_reg` 与 `map` 寄存器相同。
*   `CompareObjectTypeRange(...)`: 比较堆对象的类型是否在给定的范围内。
*   `CompareInstanceType(...)`: 比较 Map 对象的实例类型。
*   `CompareInstanceTypeRange(...)`: 比较 Map 对象的实例类型是否在给定的范围内。
*   `CompareRoot(Register obj, RootIndex index)`:  将寄存器中的对象与根列表中的值进行比较。根列表包含了 V8 引擎的一些重要对象。
*   `CompareTaggedRoot(Register with, RootIndex index)`:  类似于 `CompareRoot`，但假设比较的值是已标记的（tagged）。
*   `PushRoot(RootIndex index)`: 将根列表中的值压入栈中。
*   `JumpIfRoot(...)`: 如果寄存器中的对象与根列表中的值相等，则跳转到指定标签。
*   `JumpIfNotRoot(...)`: 如果寄存器中的对象与根列表中的值不相等，则跳转到指定标签。
*   `CompareRange(...)`:  检查一个值是否在给定的范围内。
*   `JumpIfIsInRange(...)`: 如果一个值在给定的范围内，则跳转到指定标签。
*   `ReceiverOperand()`:  返回接收者（`this`）操作数在栈上的位置。

**5. 分层编译支持 (Tiering Support):**

*   `AssertFeedbackCell(...)`, `AssertFeedbackVector(...)`:  断言检查反馈单元和反馈向量，用于优化代码。
*   `ReplaceClosureCodeWithOptimizedCode(...)`:  用优化后的代码替换闭包的代码。
*   `GenerateTailCallToReturnedCode(...)`:  生成尾调用到返回的代码。
*   `LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing(...)`: 加载反馈向量的标志并检查是否需要处理（例如，进行优化）。
*   `LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(...)`: 加载反馈向量的标志，如果需要处理则跳转到指定标签。
*   `OptimizeCodeOrTailCallOptimizedCodeSlot(...)`: 优化代码或尾调用到优化后的代码槽位。

**6. 运行时调用 (Runtime Calls):**

*   `CallRuntime(const Runtime::Function* f, int num_arguments)`:  调用 V8 的运行时函数。运行时函数是用 C++ 实现的，用于执行一些底层的操作。
*   `CallRuntime(Runtime::FunctionId fid)`:  调用指定 ID 的运行时函数。
*   `CallRuntime(Runtime::FunctionId fid, int num_arguments)`: 调用指定 ID 的运行时函数，并指定参数数量。
*   `TailCallRuntime(Runtime::FunctionId fid)`:  尾调用运行时函数。
*   `JumpToExternalReference(...)`: 跳转到外部引用，通常是内置的 C++ 函数。

**7. 原位弱引用 (In-place Weak References):**

*   `LoadWeakValue(Register out, Register in, Label* target_if_cleared)`:  加载弱引用的值。如果弱引用已被清除，则跳转到指定的标签。

**8. 统计计数器支持 (StatsCounter Support):**

*   `IncrementCounter(...)`, `EmitIncrementCounter(...)`:  增加统计计数器的值。
*   `DecrementCounter(...)`, `EmitDecrementCounter(...)`:  减少统计计数器的值。

**9. 栈限制工具 (Stack Limit Utilities):**

*   `LoadStackLimit(Register destination, StackLimitKind kind)`:  加载指定类型的栈限制到寄存器中。
*   `StackOverflowCheck(Register num_args, Register scratch, Label* stack_overflow)`:  检查是否发生栈溢出。

**10. Smi 工具 (Smi Utilities):**

*   `SmiTag(Register reg, SBit s = LeaveCC)`: 将一个整数标记为 Smi (Small Integer)。V8 使用一种称为标记指针的技术来区分对象指针和小的整数。
*   `SmiTag(Register dst, Register src, SBit s = LeaveCC)`: 将一个寄存器的值标记为 Smi 并存储到另一个寄存器。
*   `SmiTst(Register value)`: 测试寄存器中的值是否为 Smi。
*   `JumpIfNotSmi(Register value, Label* not_smi_label)`: 如果寄存器中的值不是 Smi，则跳转到指定标签。
*   `AssertNotSmi(...)`, `AssertSmi(...)`:  断言检查一个值是否为 Smi。这些通常在调试模式下使用。

**11. 断言 (Assertions):**

*   `AssertConstructor(...)`, `AssertFunction(...)`, `AssertCallableFunction(...)`, `AssertBoundFunction(...)`, `AssertGeneratorObject(...)`, `AssertUndefinedOrAllocationSite(...)`, `AssertJSAny(...)`:  在调试模式下，断言检查对象的类型。如果断言失败，程序会中止。

**12. 解码字段 (Decode Field):**

*   `DecodeField<Field>(...)`: 从一个值中解码指定字段。这通常用于从对象的内部表示中提取信息。

**13. 代码标记 (Code Marking):**

*   `TestCodeIsMarkedForDeoptimization(...)`:  检查代码是否被标记为需要反优化。

**14. 其他辅助函数:**

*   `ClearedValue() const`: 返回一个表示已清除的值的操作数。
*   `InvokePrologue(...)`:  生成函数调用的序言代码。
*   `VFPCompareAndLoadFlags(...)`:  比较浮点数并加载标志位到寄存器。
*   `Jump(...)`:  生成跳转指令。
*   `FloatMaxHelper(...)`, `FloatMinHelper(...)`, `FloatMaxOutOfLineHelper(...)`, `FloatMinOutOfLineHelper(...)`:  辅助实现浮点数的最大值和最小值操作。
*   `CalculateStackPassedWords(...)`: 计算通过栈传递的字数。

**关于 `.tq` 文件：**

`v8/src/codegen/arm/macro-assembler-arm.h` 文件不是以 `.tq` 结尾，因此它不是一个 V8 Torque 源代码文件。Torque 是一种 V8 使用的领域特定语言，用于生成高效的运行时代码。`.tq` 文件会被编译成 C++ 代码。

**与 JavaScript 功能的关系及示例：**

`MacroAssembler` 提供的功能直接服务于 JavaScript 代码的执行。当 V8 编译 JavaScript 代码时，它会使用 `MacroAssembler` 生成相应的机器码。

例如：

*   **`LoadGlobalProxy`**: 当 JavaScript 代码访问全局变量时，V8 需要获取全局代理对象来查找该变量。
    ```javascript
    // JavaScript 代码
    console.log("Hello");
    ```
    在底层，`LoadGlobalProxy` 可能会被用来加载 `console` 对象所在的全局代理。

*   **`InvokeFunction`**:  当 JavaScript 调用一个函数时，`InvokeFunction` 系列的方法会被用来生成实际的调用指令。
    ```javascript
    // JavaScript 代码
    function add(a, b) {
      return a + b;
    }
    add(1, 2);
    ```
    当调用 `add(1, 2)` 时，`InvokeFunction` 负责设置参数并跳转到 `add` 函数的代码。

*   **`CompareObjectType`**: 当 V8 需要判断一个对象的类型时，例如在类型检查或 instanceof 操作中，会使用 `CompareObjectType`。
    ```javascript
    // JavaScript 代码
    const arr = [];
    if (typeof arr === 'object') {
      console.log("arr is an object");
    }
    ```
    在执行 `typeof arr === 'object'` 时，`CompareObjectType` 可能会被用来检查 `arr` 的类型信息。

*   **`CallRuntime`**:  一些 JavaScript 内置的功能会委托给 V8 的运行时函数来实现。
    ```javascript
    // JavaScript 代码
    parseInt("10");
    ```
    `parseInt` 函数的实现可能会调用一个 V8 内部的运行时函数，这时会用到 `CallRuntime`。

**代码逻辑推理示例：**

假设我们有以下调用：

```c++
UseScratchRegisterScope temps(this);
Register scratch = temps.Acquire();
Label not_smi;
masm->JumpIfNotSmi(input_register, &not_smi);
// ... 处理 Smi 的逻辑 ...
masm->bind(&not_smi);
// ... 处理非 Smi 的逻辑 ...
```

**假设输入：**

*   `input_register` 寄存器中存储的值为 `0x80000001`（一个非 Smi 值，假设 Smi 的最低位为 0）。

**输出：**

1. `JumpIfNotSmi(input_register, &not_smi)` 将会检查 `input_register` 的最低位。由于最低位是 1，它不是一个 Smi。
2. 条件码将会被设置，使得跳转到 `not_smi` 标签的条件成立。
3. 程序执行流程将会跳转到 `masm->bind(&not_smi)` 处，开始执行处理非 Smi 的逻辑。

**用户常见的编程错误示例：**

*   **不正确的参数数量传递给 `InvokeFunction` 或 `CallRuntime`**: 如果传递的 `actual_parameter_count` 与实际传递的参数数量不符，可能导致栈上的数据错乱，引发崩溃或未定义的行为。
*   **错误地使用寄存器**:  `MacroAssembler` 的方法通常会指定哪些寄存器是输入，哪些是输出，以及哪些可能会被修改。如果用户错误地假设寄存器的状态，可能会导致计算错误。例如，在一个操作后错误地使用了本应被修改的寄存器。
*   **忘记 `PushStackHandler` 和 `PopStackHandler` 配对使用**: 如果在可能抛出异常的代码段前忘记压入栈处理器，异常可能会导致程序崩溃。如果在异常处理完成后忘记弹出栈处理器，可能会导致栈处理器链混乱。
*   **在需要 Smi 的地方使用了非 Smi 值，或者反之**: V8 内部对 Smi 和对象有不同的处理方式。如果代码逻辑期望一个 Smi，但实际传入的是一个对象指针，或者反过来，会导致类型错误或崩溃。

**总结 (第 2 部分功能归纳):**

这部分 `v8/src/codegen/arm/macro-assembler-arm.h` 定义的 `MacroAssembler` 类的功能主要集中在：

*   **更细粒度的 JavaScript 调用控制**: 提供了区分普通调用和构造函数调用，以及处理 `new.target` 的方法。
*   **底层的类型检查和比较**: 允许直接比较对象的类型信息和根对象，为实现 JavaScript 的类型系统提供基础。
*   **运行时交互**: 提供了调用 V8 运行时函数和处理外部引用的能力，用于执行内置功能和与 C++ 代码交互。
*   **性能优化支持**:  包含了对分层编译的支持，例如反馈向量的处理和代码优化。
*   **底层的内存和栈管理**:  提供了栈处理器管理、栈限制检查和 Smi 类型操作的功能。
*   **调试和断言机制**:  内置了断言检查，用于在开发和调试阶段验证代码的正确性。
*   **统计和监控**:  支持统计计数器，用于性能分析和监控。

总的来说，这部分的功能更加底层和细致，涵盖了 JavaScript 执行过程中的关键环节，例如函数调用、类型检查、异常处理和性能优化，是 V8 引擎高效执行 JavaScript 代码的核心组成部分。

Prompt: 
```
这是目录为v8/src/codegen/arm/macro-assembler-arm.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/arm/macro-assembler-arm.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
xt.
  void LoadGlobalProxy(Register dst);

  void LoadNativeContextSlot(Register dst, int index);

  // ---------------------------------------------------------------------------
  // JavaScript invokes

  // Invoke the JavaScript function code by either calling or jumping.
  void InvokeFunctionCode(Register function, Register new_target,
                          Register expected_parameter_count,
                          Register actual_parameter_count, InvokeType type);

  // On function call, call into the debugger.
  void CallDebugOnFunctionCall(Register fun, Register new_target,
                               Register expected_parameter_count,
                               Register actual_parameter_count);

  // Invoke the JavaScript function in the given register. Changes the
  // current context to the context in the function before invoking.
  void InvokeFunctionWithNewTarget(Register function, Register new_target,
                                   Register actual_parameter_count,
                                   InvokeType type);

  void InvokeFunction(Register function, Register expected_parameter_count,
                      Register actual_parameter_count, InvokeType type);

  // Exception handling

  // Push a new stack handler and link into stack handler chain.
  void PushStackHandler();

  // Unlink the stack handler on top of the stack from the stack handler chain.
  // Must preserve the result register.
  void PopStackHandler();

  // ---------------------------------------------------------------------------
  // Support functions.

  // Compare object type for heap object.  heap_object contains a non-Smi
  // whose object type should be compared with the given type.  This both
  // sets the flags and leaves the object type in the type_reg register.
  // It leaves the map in the map register (unless the type_reg and map register
  // are the same register).  It leaves the heap object in the heap_object
  // register unless the heap_object register is the same register as one of the
  // other registers.
  // Type_reg can be no_reg. In that case a scratch register is used.
  void CompareObjectType(Register heap_object, Register map, Register type_reg,
                         InstanceType type);
  // Variant of the above, which compares against a type range rather than a
  // single type (lower_limit and higher_limit are inclusive).
  //
  // Always use unsigned comparisons: ls for a positive result.
  void CompareObjectTypeRange(Register heap_object, Register map,
                              Register type_reg, Register scratch,
                              InstanceType lower_limit,
                              InstanceType higher_limit);

  // Compare instance type in a map.  map contains a valid map object whose
  // object type should be compared with the given type.  This both
  // sets the flags and leaves the object type in the type_reg register.
  void CompareInstanceType(Register map, Register type_reg, InstanceType type);

  // Compare instance type ranges for a map (lower_limit and higher_limit
  // inclusive).
  //
  // Always use unsigned comparisons: ls for a positive result.
  void CompareInstanceTypeRange(Register map, Register type_reg,
                                Register scratch, InstanceType lower_limit,
                                InstanceType higher_limit);

  // Compare the object in a register to a value from the root list.
  // Acquires a scratch register.
  void CompareRoot(Register obj, RootIndex index);
  void CompareTaggedRoot(Register with, RootIndex index);
  void PushRoot(RootIndex index) {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    LoadRoot(scratch, index);
    Push(scratch);
  }

  // Compare the object in a register to a value and jump if they are equal.
  void JumpIfRoot(Register with, RootIndex index, Label* if_equal) {
    CompareRoot(with, index);
    b(eq, if_equal);
  }

  // Compare the object in a register to a value and jump if they are not equal.
  void JumpIfNotRoot(Register with, RootIndex index, Label* if_not_equal) {
    CompareRoot(with, index);
    b(ne, if_not_equal);
  }

  // Checks if value is in range [lower_limit, higher_limit] using a single
  // comparison. Flags C=0 or Z=1 indicate the value is in the range (condition
  // ls).
  void CompareRange(Register value, Register scratch, unsigned lower_limit,
                    unsigned higher_limit);
  void JumpIfIsInRange(Register value, Register scratch, unsigned lower_limit,
                       unsigned higher_limit, Label* on_in_range);

  // It assumes that the arguments are located below the stack pointer.
  MemOperand ReceiverOperand() { return MemOperand(sp, 0); }

  // Tiering support.
  void AssertFeedbackCell(Register object,
                          Register scratch) NOOP_UNLESS_DEBUG_CODE;
  void AssertFeedbackVector(Register object,
                            Register scratch) NOOP_UNLESS_DEBUG_CODE;
  void ReplaceClosureCodeWithOptimizedCode(Register optimized_code,
                                           Register closure);
  void GenerateTailCallToReturnedCode(Runtime::FunctionId function_id);
  Condition LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing(
      Register flags, Register feedback_vector, CodeKind current_code_kind);
  void LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
      Register flags, Register feedback_vector, CodeKind current_code_kind,
      Label* flags_need_processing);
  void OptimizeCodeOrTailCallOptimizedCodeSlot(Register flags,
                                               Register feedback_vector);

  // ---------------------------------------------------------------------------
  // Runtime calls

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

  // Jump to a runtime routine.
  void JumpToExternalReference(const ExternalReference& builtin,
                               bool builtin_exit_frame = false);

  // ---------------------------------------------------------------------------
  // In-place weak references.
  void LoadWeakValue(Register out, Register in, Label* target_if_cleared);

  // ---------------------------------------------------------------------------
  // StatsCounter support

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

  // ---------------------------------------------------------------------------
  // Stack limit utilities
  void LoadStackLimit(Register destination, StackLimitKind kind);
  void StackOverflowCheck(Register num_args, Register scratch,
                          Label* stack_overflow);

  // ---------------------------------------------------------------------------
  // Smi utilities

  void SmiTag(Register reg, SBit s = LeaveCC);
  void SmiTag(Register dst, Register src, SBit s = LeaveCC);

  // Test if the register contains a smi (Z == 0 (eq) if true).
  void SmiTst(Register value);
  // Jump if either of the registers contain a non-smi.
  void JumpIfNotSmi(Register value, Label* not_smi_label);

  // Abort execution if argument is a smi, enabled via --debug-code.
  void AssertNotSmi(Register object,
                    AbortReason reason = AbortReason::kOperandIsASmi)
      NOOP_UNLESS_DEBUG_CODE;
  void AssertSmi(Register object,
                 AbortReason reason = AbortReason::kOperandIsNotASmi)
      NOOP_UNLESS_DEBUG_CODE;

  // Abort execution if argument is not a Constructor, enabled via --debug-code.
  void AssertConstructor(Register object) NOOP_UNLESS_DEBUG_CODE;

  // Abort execution if argument is not a JSFunction, enabled via --debug-code.
  void AssertFunction(Register object) NOOP_UNLESS_DEBUG_CODE;

  // Abort execution if argument is not a callable JSFunction, enabled via
  // --debug-code.
  void AssertCallableFunction(Register object) NOOP_UNLESS_DEBUG_CODE;

  // Abort execution if argument is not a JSBoundFunction,
  // enabled via --debug-code.
  void AssertBoundFunction(Register object) NOOP_UNLESS_DEBUG_CODE;

  // Abort execution if argument is not a JSGeneratorObject (or subclass),
  // enabled via --debug-code.
  void AssertGeneratorObject(Register object) NOOP_UNLESS_DEBUG_CODE;

  // Abort execution if argument is not undefined or an AllocationSite, enabled
  // via --debug-code.
  void AssertUndefinedOrAllocationSite(Register object,
                                       Register scratch) NOOP_UNLESS_DEBUG_CODE;

  void AssertJSAny(Register object, Register map_tmp, Register tmp,
                   AbortReason abort_reason) NOOP_UNLESS_DEBUG_CODE;

  template <typename Field>
  void DecodeField(Register dst, Register src) {
    Ubfx(dst, src, Field::kShift, Field::kSize);
  }

  template <typename Field>
  void DecodeField(Register reg) {
    DecodeField<Field>(reg, reg);
  }

  void TestCodeIsMarkedForDeoptimization(Register code, Register scratch);
  Operand ClearedValue() const;

 private:
  // Helper functions for generating invokes.
  void InvokePrologue(Register expected_parameter_count,
                      Register actual_parameter_count, Label* done,
                      InvokeType type);

  // Compare single values and then load the fpscr flags to a register.
  void VFPCompareAndLoadFlags(const SwVfpRegister src1,
                              const SwVfpRegister src2,
                              const Register fpscr_flags,
                              const Condition cond = al);
  void VFPCompareAndLoadFlags(const SwVfpRegister src1, const float src2,
                              const Register fpscr_flags,
                              const Condition cond = al);

  // Compare double values and then load the fpscr flags to a register.
  void VFPCompareAndLoadFlags(const DwVfpRegister src1,
                              const DwVfpRegister src2,
                              const Register fpscr_flags,
                              const Condition cond = al);
  void VFPCompareAndLoadFlags(const DwVfpRegister src1, const double src2,
                              const Register fpscr_flags,
                              const Condition cond = al);

  void Jump(intptr_t target, RelocInfo::Mode rmode, Condition cond = al);

  // Implementation helpers for FloatMin and FloatMax.
  template <typename T>
  void FloatMaxHelper(T result, T left, T right, Label* out_of_line);
  template <typename T>
  void FloatMinHelper(T result, T left, T right, Label* out_of_line);
  template <typename T>
  void FloatMaxOutOfLineHelper(T result, T left, T right);
  template <typename T>
  void FloatMinOutOfLineHelper(T result, T left, T right);

  int CalculateStackPassedWords(int num_reg_arguments,
                                int num_double_arguments);

  DISALLOW_IMPLICIT_CONSTRUCTORS(MacroAssembler);
};

struct MoveCycleState {
  // List of scratch registers reserved for pending moves in a move cycle, and
  // which should therefore not be used as a temporary location by
  // {MoveToTempLocation}. The GP scratch register is implicitly reserved.
  VfpRegList scratch_v_reglist = 0;
  // Available scratch registers during the move cycle resolution scope.
  std::optional<UseScratchRegisterScope> temps;
  // InstructionStream of the scratch register picked by {MoveToTempLocation}.
  int scratch_reg_code = -1;
};

// Provides access to exit frame parameters (GC-ed).
inline MemOperand ExitFrameStackSlotOperand(int offset) {
  // The slot at [sp] is reserved in all ExitFrames for storing the return
  // address before doing the actual call, it's necessary for frame iteration
  // (see StoreReturnAddressAndCall for details).
  static constexpr int kSPOffset = 1 * kPointerSize;
  return MemOperand(sp, kSPOffset + offset);
}

// Provides access to exit frame stack space (not GC-ed).
inline MemOperand ExitFrameCallerStackSlotOperand(int index) {
  return MemOperand(
      fp, (BuiltinExitFrameConstants::kFixedSlotCountAboveFp + index) *
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

#endif  // V8_CODEGEN_ARM_MACRO_ASSEMBLER_ARM_H_

"""


```