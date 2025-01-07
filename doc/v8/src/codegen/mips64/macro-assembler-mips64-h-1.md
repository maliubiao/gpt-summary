Response:
The user wants a summary of the functionality of the provided C++ header file for the MIPS64 architecture in V8.

Here's a breakdown of how to address the prompt:

1. **Identify the file's purpose:** The filename `macro-assembler-mips64.h` strongly suggests this file defines a class (`MacroAssembler`) used to generate machine code for MIPS64.

2. **Analyze the class members (methods):**  Go through the methods and group them by functionality. Common categories in an assembler class would be:
    * Basic instruction emission (e.g., `li`, `Branch`, `Ld`, `Sd`).
    * Floating-point operations (e.g., `FPUCanonicalizeNaN`, `Cvt_d_uw`, `Trunc_uw_d`).
    * MSA (MIPS SIMD Architecture) operations (e.g., `LoadLane`, `StoreLane`).
    * Control flow (e.g., `JumpIfSmi`, `JumpIfEqual`, `PushStandardFrame`).
    * Function calls (e.g., `InvokeFunctionCode`, `CallRuntime`).
    * Stack manipulation (e.g., `Push`, `Pop`).
    * Memory operations (e.g., `LoadRoot`, `RecordWriteField`).
    * Debugging and assertions.
    * Tiering support (related to optimization).
    * Helper functions.

3. **Address specific prompt points:**
    * **`.tq` extension:** Confirm that `.h` is not `.tq` and therefore not Torque code.
    * **Relation to Javascript:** Explain that this is low-level code generation for the V8 engine, which *executes* Javascript. Give a conceptual example of how a Javascript operation might be translated into these assembler instructions.
    * **Code logic推理:**  For simple methods, provide an example of input and output registers.
    * **Common programming errors:** Think about how mistakes in using the `MacroAssembler` could lead to issues, like incorrect register usage or stack imbalances.
    * **歸納功能 (Summarize functionality):**  Provide a concise overview of the `MacroAssembler`'s role in V8.

4. **Structure the response:** Organize the information logically, using headings and bullet points for clarity.

**Self-Correction/Refinement during thought process:**

* **Initial thought:**  List every single function. **Correction:** Group functions by category for better readability and understanding.
* **Initial thought:** Focus only on the MIPS64 specifics. **Correction:** Emphasize the *purpose* within V8 – generating machine code for Javascript execution.
* **Initial thought:** Provide very technical examples. **Correction:** Keep Javascript examples simple and high-level to illustrate the connection without getting bogged down in implementation details.
* **Initial thought:**  Not explicitly address all the decomposed instructions. **Correction:** Ensure each decomposed instruction in the prompt is touched upon in the explanation.
好的，我们来归纳一下 `v8/src/codegen/mips64/macro-assembler-mips64.h` 这个头文件的功能，基于你提供的第二部分内容和之前的第一部分。

**核心功能总结:**

`v8/src/codegen/mips64/macro-assembler-mips64.h` 定义了一个 `MacroAssembler` 类，它是 V8 JavaScript 引擎中用于生成 MIPS64 架构机器码的核心工具。它提供了一系列方法，用于抽象地表示和生成 MIPS64 的汇编指令，并封装了与 V8 运行时环境交互的必要操作。

**更细致的功能点:**

* **浮点运算宏:** 提供了处理浮点数（单精度和双精度）的宏指令，包括类型转换（如无符号整型到浮点数，浮点数到无符号整型）、取整操作（截断、四舍五入、向下取整、向上取整）以及 NaN 值的规范化。
* **MSA (MIPS SIMD Architecture) 支持:** 包含用于 MIPS SIMD 扩展的指令，如加载和存储指定通道的数据 (`LoadLane`, `StoreLane`)，扩展乘法 (`ExtMulLow`, `ExtMulHigh`)，广播加载 (`LoadSplat`)，成对加法 (`ExtAddPairwise`) 以及 MSA 寄存器的舍入操作 (`MSARoundW`, `MSARoundD`)。
* **条件跳转:** 提供基于寄存器值和立即数的条件跳转指令，例如当寄存器包含一个 SMI (Small Integer) 时跳转 (`JumpIfSmi`)，或当寄存器值等于或小于一个立即数时跳转 (`JumpIfEqual`, `JumpIfLessThan`)。
* **栈帧操作:** 提供了管理函数调用栈帧的指令，例如推送标准栈帧 (`PushStandardFrame`)。
* **地址计算:** 包含计算缩放地址的指令 (`Lsa`, `Dlsa`) 和计算代码起始地址的指令 (`ComputeCodeStartAddress`)。
* **控制流完整性:**  虽然 MIPS64 架构本身可能不支持，但定义了相关的占位符方法 (`CodeEntry`, `ExceptionHandler`, `BindExceptionHandler`)，这可能是为了保持接口的一致性。
* **接收者处理:**  提供了加载和存储函数调用接收者（`this` 指针）的指令 (`LoadReceiver`, `StoreReceiver`)。
* **Leap Tiering 支持:**  提供了从 JSDispatchTable 加载代码入口点指针的指令 (`LoadCodeEntrypointFromJSDispatchTable`)，这与 V8 的分层编译优化有关。
* **寄存器操作:**  提供了交换两个寄存器值的指令 (`Swap`)。
* **代码去优化检查:**  包含检查代码是否被标记为需要去优化并跳转的指令 (`TestCodeIsMarkedForDeoptimizationAndJump`)。
* **根对象比较:**  提供了与预定义的根对象进行比较并跳转的指令 (`JumpIfRoot`, `JumpIfNotRoot`)。
* **范围检查:**  提供了检查一个值是否在给定范围内的指令 (`JumpIfIsInRange`)。
* **垃圾回收支持:**  提供了通知垃圾回收器指针写入操作的指令 (`RecordWriteField`, `RecordWrite`)，这是 V8 内存管理的关键部分。
* **预取指令:** 提供了数据预取指令 (`Pref`)。
* **伪指令:**  定义了一些方便的指令组合，例如加载和存储字对 (`LoadWordPair`, `StoreWordPair`) 以及更多浮点数转换和算术运算的变体。
* **退出帧操作:** 提供了进入和离开退出帧的指令 (`EnterExitFrame`, `LeaveExitFrame`)，用于从 JavaScript 代码调用 C++ 代码。
* **栈对齐断言:**  包含用于调试模式下检查栈是否对齐的断言 (`AssertStackIsAligned`)。
* **全局对象加载:**  提供了加载全局代理对象和全局函数初始 Map 的指令 (`LoadGlobalProxy`, `LoadGlobalFunctionInitialMap`)。
* **JavaScript 调用:** 提供了调用 JavaScript 函数的指令 (`InvokeFunctionCode`, `InvokeFunctionWithNewTarget`, `InvokeFunction`)，以及相关的调试钩子检查 (`CheckDebugHook`)。
* **异常处理:** 提供了压入和弹出栈处理器的指令 (`PushStackHandler`, `PopStackHandler`)。
* **类型检查:**  提供了获取对象类型和实例类型范围的指令 (`GetObjectType`, `GetInstanceTypeRange`)。
* **运行时调用:** 提供了调用 V8 运行时函数的指令 (`CallRuntime`, `TailCallRuntime`)，以及跳转到外部引用（如内置函数）的指令 (`JumpToExternalReference`)。
* **弱引用支持:**  提供了加载弱引用的值的指令，如果弱引用已被清除，则跳转到指定标签 (`LoadWeakValue`)。
* **性能计数器支持:**  提供了递增和递减性能计数器的指令 (`IncrementCounter`, `DecrementCounter`)。
* **栈限制工具:**  提供了加载栈限制和执行栈溢出检查的指令 (`LoadStackLimit`, `StackOverflowCheck`)。
* **SMI 工具:**  提供了测试寄存器是否包含 SMI 和如果不是 SMI 则跳转的指令 (`SmiTst`, `JumpIfNotSmi`)。
* **断言宏:** 提供了一系列断言宏，用于在调试模式下检查特定条件（如参数是否为构造函数、函数等）。
* **Tiering 支持:**  提供了与 V8 分层编译优化相关的断言和操作，例如检查反馈单元和反馈向量，以及用优化后的代码替换闭包的代码 (`AssertFeedbackCell`, `AssertFeedbackVector`, `ReplaceClosureCodeWithOptimizedCode`)。
* **助手函数:**  定义了一些用于辅助指令生成和计算的内联和私有助手函数。
* **Switch Table 生成:** 提供了一个用于生成 switch 语句跳转表的模板函数 (`GenerateSwitchTable`)。
* **Exit Frame 参数访问:** 定义了用于访问退出帧参数的便捷方法 (`ExitFrameStackSlotOperand`, `ExitFrameCallerStackSlotOperand`).
* **API 函数调用:**  提供调用 C++ API 函数并处理返回值的函数 (`CallApiFunctionAndReturn`).

**关于 .tq 结尾:**

正如你所说，如果 `v8/src/codegen/mips64/macro-assembler-mips64.h` 以 `.tq` 结尾，那么它将是 V8 Torque 源代码。但根据你提供的文件名，它以 `.h` 结尾，所以它是一个标准的 C++ 头文件，用于定义 `MacroAssembler` 类。 Torque 是一种用于生成高效 V8 内置函数的领域特定语言，它可以生成类似这里定义的汇编代码。

**与 JavaScript 的关系:**

`macro-assembler-mips64.h` 中的功能直接服务于 V8 引擎执行 JavaScript 代码的过程。当 V8 需要执行一段 JavaScript 代码时，它会将 JavaScript 代码编译成 MIPS64 架构的机器码，而 `MacroAssembler` 类就是用于生成这些机器码的工具。

**JavaScript 例子:**

例如，考虑以下简单的 JavaScript 加法运算：

```javascript
function add(a, b) {
  return a + b;
}
```

当 V8 编译这个 `add` 函数时，`MacroAssembler` 可能会生成类似的 MIPS64 指令来执行加法操作（简化示例）：

```assembly
// 假设参数 a 和 b 已经加载到寄存器 r2 和 r3
addu  r4, r2, r3  // 将 r2 和 r3 的值相加，结果存储到 r4
move  v0, r4      // 将结果移动到返回值寄存器 v0
jr    ra          // 返回
```

`MacroAssembler` 类中类似 `Addu()` 和 `Move()` 的方法会被用来生成这些底层的汇编指令。

**代码逻辑推理示例:**

假设我们调用 `Push(r5)`，其内部实现会生成将寄存器 `r5` 的值压入栈的 MIPS64 指令，例如：

```assembly
sd  r5, 0(sp)   // 将 r5 的值存储到栈指针 sp 指向的地址
addi sp, sp, -8 // 栈指针向下移动 8 字节 (假设是 64 位架构)
```

**假设输入与输出:**

* **输入:** 调用 `Push(r5)`，其中寄存器 `r5` 的值为 `0x1234567890abcdef`，栈指针 `sp` 的值为 `0x7ffffff000`.
* **输出:** 执行 `Push(r5)` 后，内存地址 `0x7ffffeff8` (之前的 `sp - 8`) 存储了值 `0x1234567890abcdef`，栈指针 `sp` 的值变为 `0x7ffffefff8`.

**用户常见的编程错误:**

在直接使用 `MacroAssembler` 时（通常 V8 开发者才会这样做），常见的错误包括：

* **寄存器分配错误:** 错误地使用了已经被占用的寄存器，导致数据被覆盖。
* **栈不平衡:**  `Push` 和 `Pop` 的数量不匹配，导致栈指针错误。
* **条件跳转目标错误:**  条件跳转指令跳转到了错误的代码位置。
* **内存访问错误:**  使用了错误的内存地址或偏移量进行加载和存储操作。
* **不理解指令的副作用:**  某些指令可能会修改意想不到的寄存器或标志位。

例如，如果开发者忘记在 `Push` 之后进行相应的 `Pop` 操作，就会导致栈指针错乱，最终可能导致程序崩溃或行为异常。

总而言之，`v8/src/codegen/mips64/macro-assembler-mips64.h` 是 V8 引擎中至关重要的组成部分，它提供了一种结构化的方式来生成高效的 MIPS64 机器码，从而使得 V8 能够在该架构上执行 JavaScript 代码。

Prompt: 
```
这是目录为v8/src/codegen/mips64/macro-assembler-mips64.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/mips64/macro-assembler-mips64.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
ize the value else, do nothing.
  void FPUCanonicalizeNaN(const DoubleRegister dst, const DoubleRegister src);

  // ---------------------------------------------------------------------------
  // FPU macros. These do not handle special cases like NaN or +- inf.

  // Convert unsigned word to double.
  void Cvt_d_uw(FPURegister fd, FPURegister fs);
  void Cvt_d_uw(FPURegister fd, Register rs);

  // Convert unsigned long to double.
  void Cvt_d_ul(FPURegister fd, FPURegister fs);
  void Cvt_d_ul(FPURegister fd, Register rs);

  // Convert unsigned word to float.
  void Cvt_s_uw(FPURegister fd, FPURegister fs);
  void Cvt_s_uw(FPURegister fd, Register rs);

  // Convert unsigned long to float.
  void Cvt_s_ul(FPURegister fd, FPURegister fs);
  void Cvt_s_ul(FPURegister fd, Register rs);

  // Convert double to unsigned word.
  void Trunc_uw_d(FPURegister fd, FPURegister fs, FPURegister scratch);
  void Trunc_uw_d(Register rd, FPURegister fs, FPURegister scratch);

  // Convert double to unsigned long.
  void Trunc_ul_d(FPURegister fd, FPURegister fs, FPURegister scratch,
                  Register result = no_reg);
  void Trunc_ul_d(Register rd, FPURegister fs, FPURegister scratch,
                  Register result = no_reg);

  // Convert single to unsigned long.
  void Trunc_ul_s(FPURegister fd, FPURegister fs, FPURegister scratch,
                  Register result = no_reg);
  void Trunc_ul_s(Register rd, FPURegister fs, FPURegister scratch,
                  Register result = no_reg);

  // Round double functions
  void Trunc_d_d(FPURegister fd, FPURegister fs);
  void Round_d_d(FPURegister fd, FPURegister fs);
  void Floor_d_d(FPURegister fd, FPURegister fs);
  void Ceil_d_d(FPURegister fd, FPURegister fs);

  // Round float functions
  void Trunc_s_s(FPURegister fd, FPURegister fs);
  void Round_s_s(FPURegister fd, FPURegister fs);
  void Floor_s_s(FPURegister fd, FPURegister fs);
  void Ceil_s_s(FPURegister fd, FPURegister fs);

  void LoadLane(MSASize sz, MSARegister dst, uint8_t laneidx, MemOperand src);
  void StoreLane(MSASize sz, MSARegister src, uint8_t laneidx, MemOperand dst);
  void ExtMulLow(MSADataType type, MSARegister dst, MSARegister src1,
                 MSARegister src2);
  void ExtMulHigh(MSADataType type, MSARegister dst, MSARegister src1,
                  MSARegister src2);
  void LoadSplat(MSASize sz, MSARegister dst, MemOperand src);
  void ExtAddPairwise(MSADataType type, MSARegister dst, MSARegister src);
  void MSARoundW(MSARegister dst, MSARegister src, FPURoundingMode mode);
  void MSARoundD(MSARegister dst, MSARegister src, FPURoundingMode mode);

  // Jump the register contains a smi.
  void JumpIfSmi(Register value, Label* smi_label,
                 BranchDelaySlot bd = PROTECT);

  void JumpIfEqual(Register a, int32_t b, Label* dest) {
    li(kScratchReg, Operand(b));
    Branch(dest, eq, a, Operand(kScratchReg));
  }

  void JumpIfLessThan(Register a, int32_t b, Label* dest) {
    li(kScratchReg, Operand(b));
    Branch(dest, lt, a, Operand(kScratchReg));
  }

  // Push a standard frame, consisting of ra, fp, context and JS function.
  void PushStandardFrame(Register function_reg);

  // Get the actual activation frame alignment for target environment.
  static int ActivationFrameAlignment();

  // Load Scaled Address instructions. Parameter sa (shift argument) must be
  // between [1, 31] (inclusive). On pre-r6 architectures the scratch register
  // may be clobbered.
  void Lsa(Register rd, Register rs, Register rt, uint8_t sa,
           Register scratch = at);
  void Dlsa(Register rd, Register rs, Register rt, uint8_t sa,
            Register scratch = at);

  // Compute the start of the generated instruction stream from the current PC.
  // This is an alternative to embedding the {CodeObject} handle as a reference.
  void ComputeCodeStartAddress(Register dst);

  // Control-flow integrity:

  // Define a function entrypoint. This doesn't emit any code for this
  // architecture, as control-flow integrity is not supported for it.
  void CodeEntry() {}
  // Define an exception handler.
  void ExceptionHandler() {}
  // Define an exception handler and bind a label.
  void BindExceptionHandler(Label* label) { bind(label); }

  // It assumes that the arguments are located below the stack pointer.
  void LoadReceiver(Register dest) { Ld(dest, MemOperand(sp, 0)); }
  void StoreReceiver(Register rec) { Sd(rec, MemOperand(sp, 0)); }

#ifdef V8_ENABLE_LEAPTIERING
  // Load the entrypoint pointer of a JSDispatchTable entry.
  void LoadCodeEntrypointFromJSDispatchTable(Register destination,
                                             MemOperand field_operand);
#endif  // V8_ENABLE_LEAPTIERING

  bool IsNear(Label* L, Condition cond, int rs_reg);

  // Swap two registers.  If the scratch register is omitted then a slightly
  // less efficient form using xor instead of mov is emitted.
  void Swap(Register reg1, Register reg2, Register scratch = no_reg);

  void TestCodeIsMarkedForDeoptimizationAndJump(Register code_data_container,
                                                Register scratch,
                                                Condition cond, Label* target);
  Operand ClearedValue() const;

  void PushRoot(RootIndex index) {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    LoadRoot(scratch, index);
    Push(scratch);
  }

  // Compare the object in a register to a value and jump if they are equal.
  void JumpIfRoot(Register with, RootIndex index, Label* if_equal) {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    LoadRoot(scratch, index);
    Branch(if_equal, eq, with, Operand(scratch));
  }

  // Compare the object in a register to a value and jump if they are not equal.
  void JumpIfNotRoot(Register with, RootIndex index, Label* if_not_equal) {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    LoadRoot(scratch, index);
    Branch(if_not_equal, ne, with, Operand(scratch));
  }

  // Checks if value is in range [lower_limit, higher_limit] using a single
  // comparison.
  void JumpIfIsInRange(Register value, unsigned lower_limit,
                       unsigned higher_limit, Label* on_in_range);

  // ---------------------------------------------------------------------------
  // GC Support

  // Notify the garbage collector that we wrote a pointer into an object.
  // |object| is the object being stored into, |value| is the object being
  // stored.  value and scratch registers are clobbered by the operation.
  // The offset is the offset from the start of the object, not the offset from
  // the tagged HeapObject pointer.  For use with FieldOperand(reg, off).
  void RecordWriteField(Register object, int offset, Register value,
                        Register scratch, RAStatus ra_status,
                        SaveFPRegsMode save_fp,
                        SmiCheck smi_check = SmiCheck::kInline);

  // For a given |object| notify the garbage collector that the slot |address|
  // has been written.  |value| is the object being stored. The value and
  // address registers are clobbered by the operation.
  void RecordWrite(Register object, Register address, Register value,
                   RAStatus ra_status, SaveFPRegsMode save_fp,
                   SmiCheck smi_check = SmiCheck::kInline);

  void Pref(int32_t hint, const MemOperand& rs);

  // ---------------------------------------------------------------------------
  // Pseudo-instructions.

  void LoadWordPair(Register rd, const MemOperand& rs, Register scratch = at);
  void StoreWordPair(Register rd, const MemOperand& rs, Register scratch = at);

  // Convert double to unsigned long.
  void Trunc_l_ud(FPURegister fd, FPURegister fs, FPURegister scratch);

  void Trunc_l_d(FPURegister fd, FPURegister fs);
  void Round_l_d(FPURegister fd, FPURegister fs);
  void Floor_l_d(FPURegister fd, FPURegister fs);
  void Ceil_l_d(FPURegister fd, FPURegister fs);

  void Trunc_w_d(FPURegister fd, FPURegister fs);
  void Round_w_d(FPURegister fd, FPURegister fs);
  void Floor_w_d(FPURegister fd, FPURegister fs);
  void Ceil_w_d(FPURegister fd, FPURegister fs);

  void Madd_s(FPURegister fd, FPURegister fr, FPURegister fs, FPURegister ft,
              FPURegister scratch);
  void Madd_d(FPURegister fd, FPURegister fr, FPURegister fs, FPURegister ft,
              FPURegister scratch);
  void Msub_s(FPURegister fd, FPURegister fr, FPURegister fs, FPURegister ft,
              FPURegister scratch);
  void Msub_d(FPURegister fd, FPURegister fr, FPURegister fs, FPURegister ft,
              FPURegister scratch);

  // Enter exit frame.
  // stack_space - extra stack space.
  void EnterExitFrame(Register scratch, int stack_space,
                      StackFrame::Type frame_type);

  // Leave the current exit frame.
  void LeaveExitFrame(Register scratch);

  // Make sure the stack is aligned. Only emits code in debug mode.
  void AssertStackIsAligned() NOOP_UNLESS_DEBUG_CODE;

  // Load the global proxy from the current context.
  void LoadGlobalProxy(Register dst) {
    LoadNativeContextSlot(dst, Context::GLOBAL_PROXY_INDEX);
  }

  void LoadNativeContextSlot(Register dst, int index);

  // Load the initial map from the global function. The registers
  // function and map can be the same, function is then overwritten.
  void LoadGlobalFunctionInitialMap(Register function, Register map,
                                    Register scratch);

  // -------------------------------------------------------------------------
  // JavaScript invokes.

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

  // Exception handling.

  // Push a new stack handler and link into stack handler chain.
  void PushStackHandler();

  // Unlink the stack handler on top of the stack from the stack handler chain.
  // Must preserve the result register.
  void PopStackHandler();

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

  enum StackLimitKind { kInterruptStackLimit, kRealStackLimit };
  void LoadStackLimit(Register destination, StackLimitKind kind);
  void StackOverflowCheck(Register num_args, Register scratch1,
                          Register scratch2, Label* stack_overflow);

  // ---------------------------------------------------------------------------
  // Smi utilities.

  // Test if the register contains a smi.
  inline void SmiTst(Register value, Register scratch) {
    And(scratch, value, Operand(kSmiTagMask));
  }

  // Jump if the register contains a non-smi.
  void JumpIfNotSmi(Register value, Label* not_smi_label,
                    BranchDelaySlot bd = PROTECT);

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

  // ---------------------------------------------------------------------------
  // Tiering support.
  void AssertFeedbackCell(Register object,
                          Register scratch) NOOP_UNLESS_DEBUG_CODE;
  void AssertFeedbackVector(Register object,
                            Register scratch) NOOP_UNLESS_DEBUG_CODE;
  void ReplaceClosureCodeWithOptimizedCode(Register optimized_code,
                                           Register closure, Register scratch1,
                                           Register scratch2);
  void GenerateTailCallToReturnedCode(Runtime::FunctionId function_id);
  void LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
      Register flags, Register feedback_vector, CodeKind current_code_kind,
      Label* flags_need_processing);
  void OptimizeCodeOrTailCallOptimizedCodeSlot(Register flags,
                                               Register feedback_vector);

  template <typename Field>
  void DecodeField(Register dst, Register src) {
    Ext(dst, src, Field::kShift, Field::kSize);
  }

  template <typename Field>
  void DecodeField(Register reg) {
    DecodeField<Field>(reg, reg);
  }

 protected:
  inline Register GetRtAsRegisterHelper(const Operand& rt, Register scratch);
  inline int32_t GetOffset(int32_t offset, Label* L, OffsetSize bits);

 private:
  bool has_double_zero_reg_set_ = false;

  // Helper functions for generating invokes.
  void InvokePrologue(Register expected_parameter_count,
                      Register actual_parameter_count, Label* done,
                      InvokeType type);

  // Performs a truncating conversion of a floating point number as used by
  // the JS bitwise operations. See ECMA-262 9.5: ToInt32. Goes to 'done' if it
  // succeeds, otherwise falls through if result is saturated. On return
  // 'result' either holds answer, or is clobbered on fall through.
  void TryInlineTruncateDoubleToI(Register result, DoubleRegister input,
                                  Label* done);

  void CompareF(SecondaryField sizeField, FPUCondition cc, FPURegister cmp1,
                FPURegister cmp2);

  void CompareIsNanF(SecondaryField sizeField, FPURegister cmp1,
                     FPURegister cmp2);

  void BranchShortMSA(MSABranchDF df, Label* target, MSABranchCondition cond,
                      MSARegister wt, BranchDelaySlot bd = PROTECT);

  int CallCFunctionHelper(
      Register function, int num_reg_arguments, int num_double_arguments,
      SetIsolateDataSlots set_isolate_data_slots = SetIsolateDataSlots::kYes,
      Label* return_location = nullptr);

  // TODO(mips) Reorder parameters so out parameters come last.
  bool CalculateOffset(Label* L, int32_t* offset, OffsetSize bits);
  bool CalculateOffset(Label* L, int32_t* offset, OffsetSize bits,
                       Register* scratch, const Operand& rt);

  void BranchShortHelperR6(int32_t offset, Label* L);
  void BranchShortHelper(int16_t offset, Label* L, BranchDelaySlot bdslot);
  bool BranchShortHelperR6(int32_t offset, Label* L, Condition cond,
                           Register rs, const Operand& rt);
  bool BranchShortHelper(int16_t offset, Label* L, Condition cond, Register rs,
                         const Operand& rt, BranchDelaySlot bdslot);
  bool BranchShortCheck(int32_t offset, Label* L, Condition cond, Register rs,
                        const Operand& rt, BranchDelaySlot bdslot);

  void BranchAndLinkShortHelperR6(int32_t offset, Label* L);
  void BranchAndLinkShortHelper(int16_t offset, Label* L,
                                BranchDelaySlot bdslot);
  void BranchAndLinkShort(int32_t offset, BranchDelaySlot bdslot = PROTECT);
  void BranchAndLinkShort(Label* L, BranchDelaySlot bdslot = PROTECT);
  bool BranchAndLinkShortHelperR6(int32_t offset, Label* L, Condition cond,
                                  Register rs, const Operand& rt);
  bool BranchAndLinkShortHelper(int16_t offset, Label* L, Condition cond,
                                Register rs, const Operand& rt,
                                BranchDelaySlot bdslot);
  bool BranchAndLinkShortCheck(int32_t offset, Label* L, Condition cond,
                               Register rs, const Operand& rt,
                               BranchDelaySlot bdslot);
  void BranchLong(Label* L, BranchDelaySlot bdslot);
  void BranchAndLinkLong(Label* L, BranchDelaySlot bdslot);

  template <typename RoundFunc>
  void RoundDouble(FPURegister dst, FPURegister src, FPURoundingMode mode,
                   RoundFunc round);

  template <typename RoundFunc>
  void RoundFloat(FPURegister dst, FPURegister src, FPURoundingMode mode,
                  RoundFunc round);

  // Push a fixed frame, consisting of ra, fp.
  void PushCommonFrame(Register marker_reg = no_reg);

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
  if (kArchVariant >= kMips64r6) {
    // Opposite of Align(8) as we have odd number of instructions in this case.
    if ((pc_offset() & 7) == 0) {
      nop();
    }
    addiupc(scratch, 5);
    Dlsa(scratch, scratch, index, kPointerSizeLog2);
    Ld(scratch, MemOperand(scratch));
  } else {
    Label here;
    Align(8);
    push(ra);
    bal(&here);
    dsll(scratch, index, kPointerSizeLog2);  // Branch delay slot.
    bind(&here);
    daddu(scratch, scratch, ra);
    pop(ra);
    Ld(scratch, MemOperand(scratch, 6 * v8::internal::kInstrSize));
  }
  jr(scratch);
  nop();  // Branch delay slot nop.
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

// Provides access to exit frame parameters (GC-ed).
inline MemOperand ExitFrameStackSlotOperand(int offset) {
  // The slot at [sp] is reserved in all ExitFrames for storing the return
  // address before doing the actual call, it's necessary for frame iteration
  // (see StoreReturnAddressAndCall for details).
  static constexpr int kSPOffset = 1 * kSystemPointerSize;
  return MemOperand(sp, kSPOffset + offset);
}

// Provides access to exit frame parameters (GC-ed).
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

}  // namespace internal
}  // namespace v8

#define ACCESS_MASM(masm) masm->

#endif  // V8_CODEGEN_MIPS64_MACRO_ASSEMBLER_MIPS64_H_

"""


```