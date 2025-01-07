Response:
Let's break down the request and the provided C++ header file to formulate the response.

**1. Understanding the Core Request:**

The request asks for a functional summary of `v8/src/codegen/s390/macro-assembler-s390.h`. Key aspects to address are:

* **Functionality Listing:**  Enumerate the primary actions this header file enables.
* **Torque Check:** Determine if it's a Torque file (it's not, based on the `.h` extension).
* **JavaScript Relationship:** If there's a link to JavaScript functionality, illustrate with JavaScript examples.
* **Code Logic Inference:**  Provide examples of how the provided functions might work, including hypothetical inputs and outputs.
* **Common Programming Errors:** Highlight potential pitfalls or mistakes a programmer might make when using these functionalities.
* **Overall Summary:**  Synthesize the key purpose and role of this header file.
* **Part of a Series:** Acknowledge that this is the final part of a three-part series.

**2. Analyzing the Header File (`macro-assembler-s390.h`):**

The header file defines the `MacroAssembler` class, specifically for the s390 architecture within V8. The core purpose of a `MacroAssembler` is to provide a higher-level interface for generating machine code. It encapsulates individual assembly instructions into more convenient, named methods.

Here's a breakdown of the functionalities provided by the methods within the `MacroAssembler` class:

* **Memory Access:** `Load`, `Store`, `LoadTaggedField`, `StoreTaggedField`, etc. - These deal with reading and writing data to memory locations. The "Tagged" variants are crucial for V8's object representation.
* **Smi Handling:** `SmiUntagField`,  `JumpIfNotSmi` -  Operations specific to "Small Integers" (Smis), V8's optimized representation for small integers.
* **Data Compression/Decompression:** `CompressTagged`, `DecompressTagged` -  Related to pointer compression, an optimization technique in V8.
* **Bit Manipulation:** `CountLeadingZerosU32`, `CountTrailingZerosU64`, `ExtractBitRange` - Low-level bitwise operations.
* **Function Calls:** `CallRuntime`, `TailCallRuntime`, `InvokeFunctionCode`, `CallApiFunctionAndReturn` -  Mechanisms for calling different types of functions (runtime, JavaScript, API).
* **Object Type Checking:** `IsObjectType`, `CompareObjectType`, `CompareInstanceType` -  Essential for V8's dynamic typing and object model.
* **Root Handling:** `CompareRoot`, `JumpIfRoot` -  Operations related to V8's "root list," which holds pointers to important global objects.
* **Comparisons:** `Cmp`, `CompareTagged`, `CompareRange` -  Comparison operations for different data types.
* **Weak References:** `LoadWeakValue` -  Support for weak references, used for garbage collection.
* **Performance Counters:** `IncrementCounter`, `DecrementCounter` -  Mechanisms for tracking performance metrics.
* **Stack Management:** `LoadStackLimit`, `StackOverflowCheck`, `PushStackHandler`, `PopStackHandler`, `EnterExitFrame`, `LeaveExitFrame` - Operations related to the call stack and exception handling.
* **Context Management:** `LoadGlobalProxy`, `LoadNativeContextSlot` -  Accessing the current JavaScript execution context.
* **Optimization Support:** `TryLoadOptimizedOsrCode`, `ReplaceClosureCodeWithOptimizedCode`, `LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing`, `OptimizeCodeOrTailCallOptimizedCodeSlot` - Features related to V8's optimization pipeline.
* **Assertions (Debug Mode):** `AssertConstructor`, `AssertFunction`, etc. - Checks that are enabled in debug builds to catch errors.
* **Field Decoding:** `DecodeField` -  Extracting specific fields from objects.
* **Garbage Collection Support:** `IncrementalMarkingRecordWriteHelper`, `RecordWriteField`, `RecordWrite`, `TestCodeIsMarkedForDeoptimization` -  Crucial for V8's garbage collection process, ensuring memory safety.

**3. Answering the Specific Points:**

* **Functionality Listing:**  Based on the method names, I can create a bulleted list of functionalities.
* **Torque Check:** Explicitly state that the `.h` extension indicates it's a C++ header, not a Torque file.
* **JavaScript Relationship:**  Focus on methods like `CallRuntime`, `InvokeFunction`, object property access (using `LoadTaggedField`), and the concept of contexts. Provide simple JavaScript examples that would trigger these underlying mechanisms.
* **Code Logic Inference:** Choose a few representative methods (e.g., `LoadTaggedField`, `CompareObjectType`) and provide simple hypothetical scenarios with input register values and expected output register values or flag settings.
* **Common Programming Errors:** Think about things like incorrect register usage, assuming Smi values when they might not be, or forgetting to handle weak references correctly.
* **Overall Summary:**  Concise statement about the `MacroAssembler`'s role in generating machine code for the s390 architecture.
* **Part of a Series:** Acknowledge the context.

**4. Structuring the Output:**

Organize the response into logical sections corresponding to the request's points. Use clear headings and formatting (like bullet points and code blocks) for readability.

**Self-Correction/Refinement During Thinking:**

* **Initial Thought:**  Simply list all the methods.
* **Refinement:** Group the methods by functionality (memory access, function calls, etc.) to provide a more organized overview.
* **Initial Thought:**  Provide very complex JavaScript examples.
* **Refinement:** Keep the JavaScript examples simple and directly related to the underlying `MacroAssembler` functions. Avoid overcomplicating them.
* **Initial Thought:**  Describe the code logic in very technical detail.
* **Refinement:** Focus on the *effect* of the code logic with simple inputs and outputs, avoiding overly detailed assembly language explanations.
* **Initial Thought:** List a huge number of potential programming errors.
* **Refinement:** Select a few of the *most common* and illustrative errors related to the functionalities.

By following this thinking process, I can systematically analyze the header file and generate a comprehensive and accurate response that addresses all aspects of the request.
```javascript
/*
  假设我们有一个简单的 JavaScript 函数，它访问一个对象的属性：
*/
function getProperty(obj) {
  return obj.value;
}

/*
  在 V8 的底层，当执行 `obj.value` 时，`MacroAssembler` 中的一些方法可能会被使用：

  1. LoadTaggedField: 用于加载对象的属性值。`value` 属性在 V8 内部会被表示为一个“字段”。
  2. CompareObjectType: 用于检查 `obj` 是否是预期的对象类型。
  3. JumpIfNotSmi:  如果属性值是一个小的整数 (Smi)，则执行特定的处理。

  例如，`LoadTaggedField` 可能被用来从 `obj` 的内存布局中读取 `value` 属性的值。
  如果 V8 需要确保 `obj` 是一个普通的 JavaScript 对象，`CompareObjectType` 可能会被调用。
*/

// 假设在 V8 的内部表示中，一个对象的属性存储在特定的偏移量。
// 并且假设 'value' 属性存储在偏移量 8 的位置 (这只是一个假设的例子)。

// 在 MacroAssembler-s390.h 中，可能会有类似这样的代码被生成：

// 假设 'obj' 存储在寄存器 r3，要将 'obj.value' 加载到寄存器 r4。
// const int kValueOffset = 8; // 假设的偏移量

// LoadTaggedField(r4, MemOperand(r3, kValueOffset));

/*
  Common Programming Errors (与这些功能相关):

  1. 假设对象布局: 程序员（通常是 V8 的开发者）如果错误地假设了对象的内存布局，
     比如属性的偏移量不正确，那么 `LoadTaggedField` 会加载到错误的数据。

     // 错误的偏移量
     // LoadTaggedField(r4, MemOperand(r3, 16)); // 这将加载错误的字段

  2. 类型假设错误: 在使用 `CompareObjectType` 之前，如果程序员没有正确地理解
     对象的类型，可能会导致错误的比较和后续的执行流程。

     // 假设我们期望的是一个 JSObject 类型
     // 但实际上传递了一个 Smi (小的整数)
     // CompareObjectType(object_register, map_register, type_register, JS_OBJECT_TYPE);
     // 这将导致比较失败

  3. Smi 假设错误: 如果代码假设一个值总是 Smi，但实际中它可能是一个指向堆对象的指针，
      那么 `JumpIfNotSmi` 分支可能会导致意外的行为。

      function add(a, b) {
        return a + b;
      }

      // 如果 a 和 b 都是小的整数，V8 可能会使用优化的 Smi 操作。
      // 但如果 a 或 b 是一个大的整数或对象，则不会是 Smi。

      // 错误地假设 'a' 总是 Smi
      // JumpIfNotSmi(a_register, not_smi_label);
      // ... // 假设这里只处理 Smi 的情况
      // not_smi_label:
      // ... // 处理非 Smi 的情况

*/

```

## `v8/src/codegen/s390/macro-assembler-s390.h` 功能归纳 (第 3 部分)

这是 `v8/src/codegen/s390/macro-assembler-s390.h` 文件的第三部分，继续定义了 `MacroAssembler` 类的方法，用于在 s390 架构上生成机器码。 本部分的功能主要集中在以下几个方面：

**1. 内存操作和字段访问的扩展:**

*   提供了更多加载和存储不同类型字段的方法，例如 `LoadTaggedSignedField` (加载带符号的标记字段), `LoadTaggedFieldWithoutDecompressing` (加载标记字段但不解压)。
*   包含了处理 Smi (小整数) 的特定方法，如 `SmiUntagField` (去除 Smi 标签)。
*   提供了压缩和解压缩标记值的方法，用于优化内存使用和性能，如 `StoreTaggedField`, `DecompressTagged`, `CompressTagged`.

**2. 位操作:**

*   包含了计算前导零和尾随零的指令，例如 `CountLeadingZerosU32`, `CountTrailingZerosU64`，这在某些算法中非常有用。

**3. 运行时函数调用:**

*   提供了调用 V8 运行时函数的便捷方法，例如 `CallRuntime` 和 `TailCallRuntime`，用于执行一些底层的操作。

**4. 对象类型检查和比较:**

*   提供了多种方法来检查和比较对象的类型，例如 `IsObjectType`, `CompareObjectType`, `CompareInstanceType`, `CompareObjectTypeRange`, `CompareInstanceTypeRange`。这些方法对于实现 JavaScript 的动态类型特性至关重要。
*   提供了与 Root 对象（V8 中一些重要的全局对象）进行比较的方法，例如 `CompareRoot`, `CompareTaggedRoot`, `JumpIfRoot`, `JumpIfNotRoot`.

**5. 弱引用支持:**

*   提供了加载弱引用的值的方法 `LoadWeakValue`，用于在对象可能被垃圾回收时进行处理。

**6. 性能计数器支持:**

*   提供了递增和递减性能计数器的方法，例如 `IncrementCounter`, `DecrementCounter`，用于性能分析和监控。

**7. 栈限制工具:**

*   提供了加载栈限制的方法 `LoadStackLimit` 和进行栈溢出检查的方法 `StackOverflowCheck`。

**8. JavaScript 函数调用相关:**

*   提供了调用 JavaScript 函数的方法，例如 `InvokeFunctionCode`, `InvokeFunctionWithNewTarget`, `InvokeFunction`。
*   包含了调试钩子 `CheckDebugHook`，用于在函数调用时进行调试。

**9. 异常处理:**

*   提供了推入和弹出栈处理帧的方法 `PushStackHandler`, `PopStackHandler`。
*   提供了进入和离开退出帧的方法 `EnterExitFrame`, `LeaveExitFrame`，用于从 JavaScript 代码调用 C++ 代码。

**10. 上下文操作:**

*   提供了加载全局代理和原生上下文槽的方法 `LoadGlobalProxy`, `LoadNativeContextSlot`。

**11. 代码优化相关:**

*   提供了尝试加载优化代码的方法 `TryLoadOptimizedOsrCode`，以及替换闭包代码为优化代码的方法 `ReplaceClosureCodeWithOptimizedCode`。
*   包含了一些与反馈向量 (Feedback Vector) 相关的操作，用于驱动代码优化。

**12. Smi 工具:**

*   提供了快速检查是否为 Smi 的方法 `JumpIfNotSmi`。
*   提供了一些断言方法（在 debug 模式下生效），用于检查变量的类型，例如 `AssertConstructor`, `AssertFunction`, `AssertCallableFunction` 等。

**13. 字段解码:**

*   提供了从寄存器中解码特定字段的方法 `DecodeField`，利用模板实现对不同字段类型的处理。

**14. 代码分层编译 (Tiering) 支持:**

*   提供了一些用于支持代码分层编译的方法，例如断言反馈单元和反馈向量，以及生成尾调用返回代码的方法。

**15. 垃圾回收支持:**

*   提供了与垃圾回收相关的辅助方法，例如 `IncrementalMarkingRecordWriteHelper`, `RecordWriteField`, `RecordWrite`, `TestCodeIsMarkedForDeoptimization`，用于通知垃圾回收器内存的修改。

**总结:**

这部分 `MacroAssembler` 的功能进一步扩展了其在 s390 架构上生成高效机器码的能力。它提供了处理各种 V8 内部数据结构（如 Tagged 值、Smi、对象）的方法，支持 JavaScript 函数的调用和优化，并与垃圾回收机制紧密结合。这些方法是 V8 引擎将 JavaScript 代码转换为可执行机器码的关键组成部分。该文件不是 Torque 代码，因为它以 `.h` 结尾，是 C++ 头文件。

Prompt: 
```
这是目录为v8/src/codegen/s390/macro-assembler-s390.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/s390/macro-assembler-s390.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
mOperand& field_operand,
                       const Register& scratch = no_reg);
  void LoadTaggedSignedField(Register destination, MemOperand field_operand);
  void LoadTaggedFieldWithoutDecompressing(const Register& destination,
                                           const MemOperand& field_operand,
                                           const Register& scratch = no_reg);

  // Loads a field containing smi value and untags it.
  void SmiUntagField(Register dst, const MemOperand& src);

  // Compresses and stores tagged value to given on-heap location.
  void StoreTaggedField(const Register& value,
                        const MemOperand& dst_field_operand,
                        const Register& scratch = no_reg);

  void DecompressTaggedSigned(Register destination, MemOperand field_operand);
  void DecompressTaggedSigned(Register destination, Register src);
  void DecompressTagged(Register destination, MemOperand field_operand);
  void DecompressTagged(Register destination, Register source);
  void DecompressTagged(const Register& destination, Tagged_t immediate);

  // CountLeadingZeros will corrupt the scratch register pair (eg. r0:r1)
  void CountLeadingZerosU32(Register dst, Register src,
                            Register scratch_pair = r0);
  void CountLeadingZerosU64(Register dst, Register src,
                            Register scratch_pair = r0);
  void CountTrailingZerosU32(Register dst, Register src,
                             Register scratch_pair = r0);
  void CountTrailingZerosU64(Register dst, Register src,
                             Register scratch_pair = r0);

  void LoadStackLimit(Register destination, StackLimitKind kind);

  // It assumes that the arguments are located below the stack pointer.
  void LoadReceiver(Register dest) { LoadU64(dest, MemOperand(sp, 0)); }
  void StoreReceiver(Register rec) { StoreU64(rec, MemOperand(sp, 0)); }

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

  // ---------------------------------------------------------------------------
  // Support functions.

  void IsObjectType(Register object, Register scratch1, Register scratch2,
                    InstanceType type);

  // Compare object type for heap object.  heap_object contains a non-Smi
  // whose object type should be compared with the given type.  This both
  // sets the flags and leaves the object type in the type_reg register.
  // It leaves the map in the map register (unless the type_reg and map register
  // are the same register).  It leaves the heap object in the heap_object
  // register unless the heap_object register is the same register as one of the
  // other registers.
  // Type_reg can be no_reg. In that case ip is used.
  template <bool use_unsigned_cmp = false>
  void CompareObjectType(Register heap_object, Register map, Register type_reg,
                         InstanceType type) {
    const Register temp = type_reg == no_reg ? r0 : type_reg;

    LoadMap(map, heap_object);
    CompareInstanceType<use_unsigned_cmp>(map, temp, type);
  }
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
  template <bool use_unsigned_cmp = false>
  void CompareInstanceType(Register map, Register type_reg, InstanceType type) {
    static_assert(Map::kInstanceTypeOffset < 4096);
    static_assert(LAST_TYPE <= 0xFFFF);
    if (use_unsigned_cmp) {
      LoadU16(type_reg, FieldMemOperand(map, Map::kInstanceTypeOffset));
      CmpU64(type_reg, Operand(type));
    } else {
      LoadS16(type_reg, FieldMemOperand(map, Map::kInstanceTypeOffset));
      CmpS64(type_reg, Operand(type));
    }
  }

  // Compare instance type ranges for a map (lower_limit and higher_limit
  // inclusive).
  //
  // Always use unsigned comparisons: ls for a positive result.
  void CompareInstanceTypeRange(Register map, Register type_reg,
                                Register scratch, InstanceType lower_limit,
                                InstanceType higher_limit);

  // Compare the object in a register to a value from the root list.
  // Uses the ip register as scratch.
  void CompareRoot(Register obj, RootIndex index);
  void CompareTaggedRoot(Register obj, RootIndex index);
  void PushRoot(RootIndex index) {
    LoadRoot(r0, index);
    Push(r0);
  }

  template <class T>
  void CompareTagged(Register src1, T src2) {
    if (COMPRESS_POINTERS_BOOL) {
      CmpS32(src1, src2);
    } else {
      CmpS64(src1, src2);
    }
  }

  void Cmp(Register dst, int32_t src) { CmpS32(dst, Operand(src)); }

  void CmpTagged(const Register& src1, const Register& src2) {
    CompareTagged(src1, src2);
  }

  // Jump to a runtime routine.
  void JumpToExternalReference(const ExternalReference& builtin,
                               bool builtin_exit_frame = false);

  // Compare the object in a register to a value and jump if they are equal.
  void JumpIfRoot(Register with, RootIndex index, Label* if_equal) {
    CompareRoot(with, index);
    beq(if_equal);
  }

  // Compare the object in a register to a value and jump if they are not equal.
  void JumpIfNotRoot(Register with, RootIndex index, Label* if_not_equal) {
    CompareRoot(with, index);
    bne(if_not_equal);
  }

  // Checks if value is in range [lower_limit, higher_limit] using a single
  // comparison.
  void CompareRange(Register value, Register scratch, unsigned lower_limit,
                    unsigned higher_limit);
  void JumpIfIsInRange(Register value, Register scratch, unsigned lower_limit,
                       unsigned higher_limit, Label* on_in_range);

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

  MemOperand StackLimitAsMemOperand(StackLimitKind kind);
  void StackOverflowCheck(Register num_args, Register scratch,
                          Label* stack_overflow);

  // ---------------------------------------------------------------------------
  // JavaScript invokes

  // Set up call kind marking in ecx. The method takes ecx as an
  // explicit first parameter to make the code more readable at the
  // call sites.
  // void SetCallKind(Register dst, CallKind kind);

  // Removes current frame and its arguments from the stack preserving
  // the arguments and a return address pushed to the stack for the next call.
  // Both |callee_args_count| and |caller_args_count| do not include
  // receiver. |callee_args_count| is not modified. |caller_args_count|
  // is trashed.

  // Invoke the JavaScript function code by either calling or jumping.
  void InvokeFunctionCode(Register function, Register new_target,
                          Register expected_parameter_count,
                          Register actual_parameter_count, InvokeType type);

  // On function call, call into the debugger if necessary.
  void CheckDebugHook(Register fun, Register new_target,
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

  // Enter exit frame.
  // stack_space - extra stack space, used for parameters before call to C.
  void EnterExitFrame(Register scratch, int stack_space,
                      StackFrame::Type frame_type);

  // Leave the current exit frame.
  void LeaveExitFrame(Register scratch);

  // Load the global proxy from the current context.
  void LoadGlobalProxy(Register dst) {
    LoadNativeContextSlot(dst, Context::GLOBAL_PROXY_INDEX);
  }

  void LoadNativeContextSlot(Register dst, int index);

  // Falls through and sets scratch_and_result to 0 on failure, jumps to
  // on_result on success.
  void TryLoadOptimizedOsrCode(Register scratch_and_result,
                               CodeKind min_opt_level, Register feedback_vector,
                               FeedbackSlot slot, Label* on_result,
                               Label::Distance distance);
  // ---------------------------------------------------------------------------
  // Smi utilities

  // Jump if either of the registers contain a non-smi.
  inline void JumpIfNotSmi(Register value, Label* not_smi_label) {
    TestIfSmi(value);
    bne(not_smi_label /*, cr0*/);
  }

#if !defined(V8_COMPRESS_POINTERS) && !defined(V8_31BIT_SMIS_ON_64BIT_ARCH)
  // Ensure it is permissible to read/write int value directly from
  // upper half of the smi.
  static_assert(kSmiTag == 0);
  static_assert(kSmiTagSize + kSmiShiftSize == 32);
#endif
#if V8_TARGET_LITTLE_ENDIAN
#define SmiWordOffset(offset) (offset + kSystemPointerSize / 2)
#else
#define SmiWordOffset(offset) offset
#endif

  // Abort execution if argument is not a Constructor, enabled via --debug-code.
  void AssertConstructor(Register object,
                         Register scratch) NOOP_UNLESS_DEBUG_CODE;

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
    int shift = Field::kShift;
    int mask = Field::kMask >> Field::kShift;
    if (base::bits::IsPowerOfTwo(mask + 1)) {
      ExtractBitRange(dst, src, Field::kShift + Field::kSize - 1,
                      Field::kShift);
    } else if (shift != 0) {
      ShiftLeftU64(dst, src, Operand(shift));
      AndP(dst, Operand(mask));
    } else {
      AndP(dst, src, Operand(mask));
    }
  }

  template <typename Field>
  void DecodeField(Register reg) {
    DecodeField<Field>(reg, reg);
  }

  // Tiering support.
  void AssertFeedbackCell(Register object,
                          Register scratch) NOOP_UNLESS_DEBUG_CODE;
  void AssertFeedbackVector(Register object,
                            Register scratch) NOOP_UNLESS_DEBUG_CODE;
  void AssertFeedbackVector(Register object) NOOP_UNLESS_DEBUG_CODE;
  void ReplaceClosureCodeWithOptimizedCode(Register optimized_code,
                                           Register closure, Register scratch1,
                                           Register slot_address);
  void GenerateTailCallToReturnedCode(Runtime::FunctionId function_id);
  Condition LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing(
      Register flags, Register feedback_vector, CodeKind current_code_kind);
  void LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
      Register flags, Register feedback_vector, CodeKind current_code_kind,
      Label* flags_need_processing);
  void OptimizeCodeOrTailCallOptimizedCodeSlot(Register flags,
                                               Register feedback_vector);

  // ---------------------------------------------------------------------------
  // GC Support

  void IncrementalMarkingRecordWriteHelper(Register object, Register value,
                                           Register address);

  void CallJSEntry(Register target);
  static int CallSizeNotPredictableCodeSize(Address target,
                                            RelocInfo::Mode rmode,
                                            Condition cond = al);
  // Notify the garbage collector that we wrote a pointer into an object.
  // |object| is the object being stored into, |value| is the object being
  // stored.  value and scratch registers are clobbered by the operation.
  // The offset is the offset from the start of the object, not the offset from
  // the tagged HeapObject pointer.  For use with FieldMemOperand(reg, off).
  void RecordWriteField(Register object, int offset, Register value,
                        Register slot_address, LinkRegisterStatus lr_status,
                        SaveFPRegsMode save_fp,
                        SmiCheck smi_check = SmiCheck::kInline);

  // For a given |object| notify the garbage collector that the slot |address|
  // has been written.  |value| is the object being stored. The value and
  // address registers are clobbered by the operation.
  void RecordWrite(Register object, Register slot_address, Register value,
                   LinkRegisterStatus lr_status, SaveFPRegsMode save_fp,
                   SmiCheck smi_check = SmiCheck::kInline);

  void TestCodeIsMarkedForDeoptimization(Register code, Register scratch);
  Operand ClearedValue() const;

 private:
  static const int kSmiShift = kSmiTagSize + kSmiShiftSize;

  void Jump(intptr_t target, RelocInfo::Mode rmode, Condition cond = al);
  int CalculateStackPassedWords(int num_reg_arguments,
                                int num_double_arguments);

  // Helper functions for generating invokes.
  void InvokePrologue(Register expected_parameter_count,
                      Register actual_parameter_count, Label* done,
                      InvokeType type);

  DISALLOW_IMPLICIT_CONSTRUCTORS(MacroAssembler);
};

struct MoveCycleState {
  // Whether a move in the cycle needs a double scratch register.
  bool pending_double_scratch_register_use = false;
};

// Provides access to exit frame parameters (GC-ed).
inline MemOperand ExitFrameStackSlotOperand(int offset) {
  // The slot at [sp] is reserved in all ExitFrames for storing the return
  // address before doing the actual call, it's necessary for frame iteration
  // (see StoreReturnAddressAndCall for details).
  static constexpr int kSPOffset = 1 * kSystemPointerSize;
  return MemOperand(sp, (kStackFrameExtraParamSlot * kSystemPointerSize) +
                            offset + kSPOffset);
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

#endif  // V8_CODEGEN_S390_MACRO_ASSEMBLER_S390_H_

"""


```