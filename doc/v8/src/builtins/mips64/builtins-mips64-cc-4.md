Response:
My thinking process to analyze the provided MIPS64 assembly code and fulfill the request goes like this:

1. **Understand the Goal:** The primary goal is to analyze the functionality of the provided V8 builtins code for the MIPS64 architecture. The request asks for a description of its functions, examples (if related to JavaScript), logic inference, common programming errors, and a final summary.

2. **High-Level Overview:** I first scanned the code for keywords like "Generate_", "Deoptimization", "Baseline", "Interpreter", and "CallCFunction". This gave me a general idea that the code is related to handling function calls, deoptimization (going back from optimized to less optimized code), and transitions between interpreted and compiled (baseline) JavaScript execution. The architecture-specific nature is evident from the "mips64" in the file path and the use of MIPS64 assembly instructions.

3. **Break Down into Sections (by Function):**  I then mentally divided the code based on the `void Builtins::Generate_...` functions. Each of these functions likely represents a specific entry point or code generation routine within the V8 engine.

4. **Analyze Individual Functions:** I went through each `Generate_` function, paying attention to:
    * **Function Name:**  The name itself provides clues (e.g., `Generate_CEntry`, `Generate_DeoptimizationEntry_Eager`).
    * **Assembly Instructions:**  I examined the assembly instructions, recognizing common patterns:
        * Stack manipulation (`daddiu sp, sp, ...`, `Sd`, `Ld`, `push`, `pop`).
        * Function calls (`Call`, `TailCallBuiltin`, `CallCFunction`).
        * Register usage (e.g., `t9`, `ra`, `sp`, `fp`, `a0`, `a1`, etc.).
        * Conditional branches (`Branch`, `beq`, `bne`).
        * Memory access (`MemOperand`, `FieldMemOperand`).
        * Constants and external references (`ExternalReference`).
    * **Comments:** The comments provide valuable insights into the purpose of the code.
    * **Logic Flow:** I tried to trace the logical steps within each function. For instance, in `Generate_CEntry`, I saw the saving of the return address, the call to the C++ function, and the restoration of the return address. In `Generate_DeoptimizationEntry`, I noted the saving of registers, the allocation of a deoptimizer object, and the copying of frame data. The `Generate_BaselineOrInterpreterEntry` function clearly deals with transitioning between baseline and interpreter code.

5. **Identify Key Concepts:** As I analyzed, I identified core V8 concepts being handled:
    * **Call Stack Management:** The code heavily manipulates the stack frame, saving and restoring registers, and managing return addresses.
    * **Deoptimization:** The `Generate_DeoptimizationEntry` functions are explicitly about handling the process of moving from optimized code back to a less optimized state.
    * **Baseline Compilation:** The `Generate_BaselineOrInterpreterEntry` functions are about entering baseline-compiled code or falling back to the interpreter.
    * **Interpreter:**  The code mentions entering the interpreter and handling bytecode offsets.
    * **Function Calls (C++ and JavaScript):**  The code interacts with both C++ functions within V8 and JavaScript functions.
    * **Frame Descriptors:** The deoptimization code uses `FrameDescription` to store and manipulate frame information.

6. **Relate to JavaScript (If Applicable):** I looked for connections between the assembly code and JavaScript concepts. The transitions between baseline and interpreter are directly related to how V8 optimizes JavaScript execution. Deoptimization is a crucial mechanism for handling situations where optimizations are no longer valid.

7. **Construct Examples (If Applicable):**  For the baseline/interpreter transitions, I could imagine a simple JavaScript function that might initially run in the interpreter and later be optimized to baseline code. Deoptimization could be triggered by changes in the function's behavior or the types of arguments it receives.

8. **Infer Logic and Provide Examples:** I tried to infer the purpose of specific code blocks. For instance, the code in `Generate_CEntry` related to `kCArgsSlotsSize` is about making space for arguments for C++ calls. The deoptimization code copying registers is for preserving the state of the program.

9. **Consider Common Programming Errors:**  I thought about potential errors that could lead to deoptimization or issues related to the concepts in the code, such as type inconsistencies, reliance on specific optimization assumptions, or stack corruption.

10. **Synthesize a Summary:** Finally, I combined my observations into a concise summary of the file's overall functionality. I emphasized the core responsibilities of the code: handling C++ calls from JavaScript, managing deoptimization, and facilitating transitions between interpreted and baseline-compiled JavaScript.

11. **Address Specific Instructions:** I made sure to address each part of the original prompt, specifically mentioning that the file is not a Torque file (because it doesn't end in `.tq`).

By following these steps, I could systematically analyze the assembly code and generate a comprehensive response that addresses the different aspects of the request. The key is to break down the complex code into manageable parts, understand the underlying concepts, and connect them back to the broader workings of the V8 JavaScript engine.好的，让我们来分析一下 `v8/src/builtins/mips64/builtins-mips64.cc` 这个文件的功能。

**核心功能归纳：**

这个文件包含了 V8 JavaScript 引擎在 MIPS64 架构下实现内置函数和运行时支持的汇编代码。它定义了当 JavaScript 代码调用某些特定的内置函数或者 V8 内部需要执行特定操作时，MIPS64 架构的 CPU 应该如何执行。

**具体功能分解：**

1. **C++ 函数入口 (`Generate_CEntry`)：**
   - **功能：**  定义了从 JavaScript 代码调用 C++ 函数的入口点。
   - **机制：**  它负责设置调用约定，在栈上分配空间用于传递参数，保存返回地址，调用 C++ 函数，并在 C++ 函数返回后恢复状态。
   - **与 JavaScript 的关系：**  当 JavaScript 代码调用一个由 C++ 实现的内置函数（例如 `Array.push`, `console.log` 等）时，V8 会跳转到 `Generate_CEntry` 生成的代码。
   - **JavaScript 示例：**
     ```javascript
     const arr = [1, 2, 3];
     arr.push(4); // 这里会调用 C++ 实现的 Array.push
     console.log("Hello"); // 这里会调用 C++ 实现的 console.log
     ```
   - **代码逻辑推理：**
     - **假设输入：**  `t9` 寄存器包含要调用的 C++ 函数的地址。
     - **输出：** 执行完 C++ 函数后，程序跳转回调用 `Generate_CEntry` 的 JavaScript 代码。
   - **用户常见编程错误：**  通常用户不会直接与这个层面的代码交互，但如果 C++ 内置函数实现有错误，可能会导致 JavaScript 代码的行为异常。

2. **去优化入口 (`Generate_DeoptimizationEntry_Eager`, `Generate_DeoptimizationEntry_Lazy`)：**
   - **功能：**  定义了当优化的代码（例如 TurboFan 生成的代码）需要回退到未优化的代码（例如解释器或基线编译器生成的代码）时的入口点。
   - **机制：** 它负责保存当前寄存器的状态，创建 `Deoptimizer` 对象，复制必要的帧信息，调用 C++ 代码来计算输出帧，然后恢复寄存器状态并跳转到未优化的代码。
   - **与 JavaScript 的关系：** 当 V8 发现优化的代码不再有效（例如，类型假设错误）时，会触发去优化。
   - **JavaScript 示例：**
     ```javascript
     function add(a, b) {
       return a + b;
     }

     // 假设 V8 优化了 add 函数，并假设 a 和 b 总是数字
     add(1, 2);
     add(3, 4);
     add("hello", "world"); // 这里可能会触发去优化，因为参数类型不再是数字
     ```
   - **代码逻辑推理：**
     - **假设输入：** 当前执行的是优化后的代码，需要回退。
     - **输出：** 程序状态恢复到去优化发生前的状态，并跳转到解释器或基线编译器生成的代码继续执行。
   - **用户常见编程错误：**
     - **类型不稳定：** 在同一个函数中，参数或变量的类型频繁变化，会导致 V8 的类型假设失效，从而触发去优化，降低性能。

3. **基线或解释器入口 (`Generate_BaselineOrInterpreterEnterAtBytecode`, `Generate_BaselineOrInterpreterEnterAtNextBytecode`)：**
   - **功能：** 定义了进入基线编译器生成的代码或解释器执行字节码的入口点。
   - **机制：** 它负责从帧中获取函数信息，检查是否存在基线代码，如果存在则计算基线代码的 PC 地址并跳转执行，否则跳转到解释器入口。
   - **与 JavaScript 的关系：**  当 JavaScript 函数首次被调用或者从去优化状态恢复时，会进入这里。基线编译器是 V8 中一个轻量级的编译器，用于在解释器和全功能优化编译器 (TurboFan) 之间提供一个性能折衷方案。
   - **JavaScript 示例：**
     ```javascript
     function foo() {
       // ... 一些代码 ...
     }

     foo(); // 第一次调用，可能进入解释器
     foo(); // 第二次调用，可能会进入基线代码
     ```
   - **代码逻辑推理：**
     - **假设输入：**  当前需要执行一个 JavaScript 函数。
     - **输出：** 程序跳转到该函数的基线代码的起始地址，或者跳转到解释器开始执行该函数的字节码。
   - **用户常见编程错误：** 用户通常不会直接与此交互，但理解 V8 的编译和执行流程有助于理解性能瓶颈。

4. **解释器栈替换到基线代码 (`Generate_InterpreterOnStackReplacement_ToBaseline`)：**
   - **功能：**  定义了在解释器执行过程中，如果满足一定条件（例如函数被频繁调用），将解释器栈帧替换为基线代码栈帧并继续执行的入口点。这是一种 On-Stack Replacement (OSR) 技术。
   - **机制：**  类似于基线入口，但发生在函数执行过程中，允许 V8 在不重新调用函数的情况下进行优化。
   - **与 JavaScript 的关系：**  当一个函数在解释器中执行一段时间后，V8 可能会决定使用基线编译器来优化它，这时就会用到 OSR。
   - **JavaScript 示例：**
     ```javascript
     function longRunningFunction() {
       let sum = 0;
       for (let i = 0; i < 10000; i++) {
         sum += i;
       }
       return sum;
     }

     longRunningFunction(); // 在执行过程中可能会发生 OSR
     ```

5. **重启帧跳转 (`Generate_RestartFrameTrampoline`)：**
   - **功能：**  定义了当需要丢弃当前帧并重新启动执行时的跳转目标。
   - **机制：**  它负责查找当前帧对应的函数，离开当前帧，然后通过调用该函数来重启执行。
   - **与 JavaScript 的关系：**  这通常与异常处理或调试等场景相关。
   - **JavaScript 示例：**  这通常是 V8 内部机制，用户代码很难直接触发。

**关于 `.tq` 结尾：**

您提到如果文件以 `.tq` 结尾，那么它是 V8 Torque 源代码。`v8/src/builtins/mips64/builtins-mips64.cc` 的确是以 `.cc` 结尾，所以**它不是 Torque 源代码**。 Torque 是一种 V8 内部使用的类型安全的 DSL (领域特定语言)，用于生成高效的内置函数代码。

**总结 `v8/src/builtins/mips64/builtins-mips64.cc` 的功能：**

总而言之，`v8/src/builtins/mips64/builtins-mips64.cc` 文件是 V8 引擎在 MIPS64 架构上的一个关键组成部分，它提供了连接 JavaScript 和底层 C++ 代码的桥梁，并负责处理代码的优化和去优化过程，以及在解释器和基线编译器之间进行切换。它定义了在 MIPS64 架构上执行 V8 内部操作和内置函数的底层指令序列。理解这个文件中的代码有助于深入理解 V8 的执行模型和性能优化策略。

### 提示词
```
这是目录为v8/src/builtins/mips64/builtins-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/mips64/builtins-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
alling convention. Callers use
  // EnterExitFrame/LeaveExitFrame so they handle stack restoring and we don't
  // have to do that here. Any caller must drop kCArgsSlotsSize stack space
  // after the call.
  __ daddiu(sp, sp, -kCArgsSlotsSize);

  __ Sd(ra, MemOperand(sp, kCArgsSlotsSize));  // Store the return address.
  __ Call(t9);                                 // Call the C++ function.
  __ Ld(t9, MemOperand(sp, kCArgsSlotsSize));  // Return to calling code.

  if (v8_flags.debug_code && v8_flags.enable_slow_asserts) {
    // In case of an error the return address may point to a memory area
    // filled with kZapValue by the GC. Dereference the address and check for
    // this.
    __ Uld(a4, MemOperand(t9));
    __ Assert(ne, AbortReason::kReceivedInvalidReturnAddress, a4,
              Operand(reinterpret_cast<uint64_t>(kZapValue)));
  }

  __ Jump(t9);
}

namespace {

// This code tries to be close to ia32 code so that any changes can be
// easily ported.
void Generate_DeoptimizationEntry(MacroAssembler* masm,
                                  DeoptimizeKind deopt_kind) {
  Isolate* isolate = masm->isolate();

  // Unlike on ARM we don't save all the registers, just the useful ones.
  // For the rest, there are gaps on the stack, so the offsets remain the same.
  const int kNumberOfRegisters = Register::kNumRegisters;

  RegList restored_regs = kJSCallerSaved | kCalleeSaved;
  RegList saved_regs = restored_regs | sp | ra;

  const int kMSARegsSize = kSimd128Size * MSARegister::kNumRegisters;

  // Save all allocatable simd128 / double registers before messing with them.
  __ Dsubu(sp, sp, Operand(kMSARegsSize));
  const RegisterConfiguration* config = RegisterConfiguration::Default();
  {
    // Check if machine has simd support, if so save vector registers.
    // If not then save double registers.
    Label no_simd, done;
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();

    __ li(scratch, ExternalReference::supports_wasm_simd_128_address());
    // If > 0 then simd is available.
    __ Lbu(scratch, MemOperand(scratch));
    __ Branch(&no_simd, le, scratch, Operand(zero_reg));

    CpuFeatureScope msa_scope(
        masm, MIPS_SIMD, CpuFeatureScope::CheckPolicy::kDontCheckSupported);
    for (int i = 0; i < config->num_allocatable_simd128_registers(); ++i) {
      int code = config->GetAllocatableSimd128Code(i);
      int offset = code * kSimd128Size;
      const MSARegister fpu_reg = MSARegister::from_code(code);
      __ st_d(fpu_reg, MemOperand(sp, offset));
    }
    __ Branch(&done);

    __ bind(&no_simd);
    for (int i = 0; i < config->num_allocatable_simd128_registers(); ++i) {
      int code = config->GetAllocatableSimd128Code(i);
      int offset = code * kSimd128Size;
      const DoubleRegister fpu_reg = DoubleRegister::from_code(code);
      __ Sdc1(fpu_reg, MemOperand(sp, offset));
    }

    __ bind(&done);
  }

  // Push saved_regs (needed to populate FrameDescription::registers_).
  // Leave gaps for other registers.
  __ Dsubu(sp, sp, kNumberOfRegisters * kSystemPointerSize);
  for (int16_t i = kNumberOfRegisters - 1; i >= 0; i--) {
    if ((saved_regs.bits() & (1 << i)) != 0) {
      __ Sd(ToRegister(i), MemOperand(sp, kSystemPointerSize * i));
    }
  }

  __ li(a2,
        ExternalReference::Create(IsolateAddressId::kCEntryFPAddress, isolate));
  __ Sd(fp, MemOperand(a2));

  const int kSavedRegistersAreaSize =
      (kNumberOfRegisters * kSystemPointerSize) + kMSARegsSize;

  // Get the address of the location in the code object (a2) (return
  // address for lazy deoptimization) and compute the fp-to-sp delta in
  // register a3.
  __ mov(a2, ra);
  __ Daddu(a3, sp, Operand(kSavedRegistersAreaSize));

  __ Dsubu(a3, fp, a3);

  // Allocate a new deoptimizer object.
  __ PrepareCallCFunction(5, a4);
  // Pass six arguments, according to n64 ABI.
  __ mov(a0, zero_reg);
  Label context_check;
  __ Ld(a1, MemOperand(fp, CommonFrameConstants::kContextOrFrameTypeOffset));
  __ JumpIfSmi(a1, &context_check);
  __ Ld(a0, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ bind(&context_check);
  __ li(a1, Operand(static_cast<int>(deopt_kind)));
  // a2: code address or 0 already loaded.
  // a3: already has fp-to-sp delta.
  __ li(a4, ExternalReference::isolate_address());

  // Call Deoptimizer::New().
  {
    AllowExternalCallThatCantCauseGC scope(masm);
    __ CallCFunction(ExternalReference::new_deoptimizer_function(), 5);
  }

  // Preserve "deoptimizer" object in register v0 and get the input
  // frame descriptor pointer to a1 (deoptimizer->input_);
  // Move deopt-obj to a0 for call to Deoptimizer::ComputeOutputFrames() below.
  __ mov(a0, v0);
  __ Ld(a1, MemOperand(v0, Deoptimizer::input_offset()));

  // Copy core registers into FrameDescription::registers_[kNumRegisters].
  DCHECK_EQ(Register::kNumRegisters, kNumberOfRegisters);
  for (int i = 0; i < kNumberOfRegisters; i++) {
    int offset =
        (i * kSystemPointerSize) + FrameDescription::registers_offset();
    if ((saved_regs.bits() & (1 << i)) != 0) {
      __ Ld(a2, MemOperand(sp, i * kSystemPointerSize));
      __ Sd(a2, MemOperand(a1, offset));
    } else if (v8_flags.debug_code) {
      __ li(a2, kDebugZapValue);
      __ Sd(a2, MemOperand(a1, offset));
    }
  }

  // Copy simd128 / double registers to the input frame.
  int simd128_regs_offset = FrameDescription::simd128_registers_offset();
  {
    // Check if machine has simd support, if so copy vector registers.
    // If not then copy double registers.
    Label no_simd, done;
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();

    __ li(scratch, ExternalReference::supports_wasm_simd_128_address());
    // If > 0 then simd is available.
    __ Lbu(scratch, MemOperand(scratch));
    __ Branch(&no_simd, le, scratch, Operand(zero_reg));

    CpuFeatureScope msa_scope(
        masm, MIPS_SIMD, CpuFeatureScope::CheckPolicy::kDontCheckSupported);
    for (int i = 0; i < config->num_allocatable_simd128_registers(); ++i) {
      int code = config->GetAllocatableSimd128Code(i);
      int dst_offset = code * kSimd128Size + simd128_regs_offset;
      int src_offset =
          code * kSimd128Size + kNumberOfRegisters * kSystemPointerSize;
      __ ld_d(w0, MemOperand(sp, src_offset));
      __ st_d(w0, MemOperand(a1, dst_offset));
    }
    __ Branch(&done);

    __ bind(&no_simd);
    for (int i = 0; i < config->num_allocatable_simd128_registers(); ++i) {
      int code = config->GetAllocatableSimd128Code(i);
      int dst_offset = code * kSimd128Size + simd128_regs_offset;
      int src_offset =
          code * kSimd128Size + kNumberOfRegisters * kSystemPointerSize;
      __ Ldc1(f0, MemOperand(sp, src_offset));
      __ Sdc1(f0, MemOperand(a1, dst_offset));
    }

    __ bind(&done);
  }

  // Remove the saved registers from the stack.
  __ Daddu(sp, sp, Operand(kSavedRegistersAreaSize));

  // Compute a pointer to the unwinding limit in register a2; that is
  // the first stack slot not part of the input frame.
  __ Ld(a2, MemOperand(a1, FrameDescription::frame_size_offset()));
  __ Daddu(a2, a2, sp);

  // Unwind the stack down to - but not including - the unwinding
  // limit and copy the contents of the activation frame to the input
  // frame description.
  __ Daddu(a3, a1, Operand(FrameDescription::frame_content_offset()));
  Label pop_loop;
  Label pop_loop_header;
  __ BranchShort(&pop_loop_header);
  __ bind(&pop_loop);
  __ pop(a4);
  __ Sd(a4, MemOperand(a3, 0));
  __ daddiu(a3, a3, sizeof(uint64_t));
  __ bind(&pop_loop_header);
  __ BranchShort(&pop_loop, ne, a2, Operand(sp));
  // Compute the output frame in the deoptimizer.
  __ push(a0);  // Preserve deoptimizer object across call.
  // a0: deoptimizer object; a1: scratch.
  __ PrepareCallCFunction(1, a1);
  // Call Deoptimizer::ComputeOutputFrames().
  {
    AllowExternalCallThatCantCauseGC scope(masm);
    __ CallCFunction(ExternalReference::compute_output_frames_function(), 1);
  }
  __ pop(a0);  // Restore deoptimizer object (class Deoptimizer).

  __ Ld(sp, MemOperand(a0, Deoptimizer::caller_frame_top_offset()));

  // Replace the current (input) frame with the output frames.
  Label outer_push_loop, inner_push_loop, outer_loop_header, inner_loop_header;
  // Outer loop state: a4 = current "FrameDescription** output_",
  // a1 = one past the last FrameDescription**.
  __ Lw(a1, MemOperand(a0, Deoptimizer::output_count_offset()));
  __ Ld(a4, MemOperand(a0, Deoptimizer::output_offset()));  // a4 is output_.
  __ Dlsa(a1, a4, a1, kSystemPointerSizeLog2);
  __ BranchShort(&outer_loop_header);

  __ bind(&outer_push_loop);
  Register current_frame = a2;
  Register frame_size = a3;
  __ Ld(current_frame, MemOperand(a4, 0));
  __ Ld(frame_size,
        MemOperand(current_frame, FrameDescription::frame_size_offset()));
  __ BranchShort(&inner_loop_header);

  __ bind(&inner_push_loop);
  __ Dsubu(frame_size, frame_size, Operand(sizeof(uint64_t)));
  __ Daddu(a6, current_frame, Operand(frame_size));
  __ Ld(a7, MemOperand(a6, FrameDescription::frame_content_offset()));
  __ push(a7);

  __ bind(&inner_loop_header);
  __ BranchShort(&inner_push_loop, ne, frame_size, Operand(zero_reg));

  __ Daddu(a4, a4, Operand(kSystemPointerSize));

  __ bind(&outer_loop_header);
  __ BranchShort(&outer_push_loop, lt, a4, Operand(a1));

  {
    // Check if machine has simd support, if so restore vector registers.
    // If not then restore double registers.
    Label no_simd, done;
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();

    __ li(scratch, ExternalReference::supports_wasm_simd_128_address());
    // If > 0 then simd is available.
    __ Lbu(scratch, MemOperand(scratch));
    __ Branch(&no_simd, le, scratch, Operand(zero_reg));

    CpuFeatureScope msa_scope(
        masm, MIPS_SIMD, CpuFeatureScope::CheckPolicy::kDontCheckSupported);
    for (int i = 0; i < config->num_allocatable_simd128_registers(); ++i) {
      int code = config->GetAllocatableSimd128Code(i);
      int src_offset = code * kSimd128Size + simd128_regs_offset;
      const MSARegister fpu_reg = MSARegister::from_code(code);
      __ ld_d(fpu_reg, MemOperand(current_frame, src_offset));
    }
    __ Branch(&done);

    __ bind(&no_simd);
    for (int i = 0; i < config->num_allocatable_simd128_registers(); ++i) {
      int code = config->GetAllocatableSimd128Code(i);
      int src_offset = code * kSimd128Size + simd128_regs_offset;
      const DoubleRegister fpu_reg = DoubleRegister::from_code(code);
      __ Ldc1(fpu_reg, MemOperand(current_frame, src_offset));
    }

    __ bind(&done);
  }

  // Push pc and continuation from the last output frame.
  __ Ld(a6, MemOperand(current_frame, FrameDescription::pc_offset()));
  __ push(a6);
  __ Ld(a6, MemOperand(current_frame, FrameDescription::continuation_offset()));
  __ push(a6);

  // Technically restoring 'at' should work unless zero_reg is also restored
  // but it's safer to check for this.
  DCHECK(!(restored_regs.has(at)));
  // Restore the registers from the last output frame.
  __ mov(at, current_frame);
  for (int i = kNumberOfRegisters - 1; i >= 0; i--) {
    int offset =
        (i * kSystemPointerSize) + FrameDescription::registers_offset();
    if ((restored_regs.bits() & (1 << i)) != 0) {
      __ Ld(ToRegister(i), MemOperand(at, offset));
    }
  }

  // If the continuation is non-zero (JavaScript), branch to the continuation.
  // For Wasm just return to the pc from the last output frame in the lr
  // register.
  Label end;
  __ pop(at);  // Get continuation, leave pc on stack.
  __ pop(ra);
  __ Branch(&end, eq, at, Operand(zero_reg));
  __ Jump(at);

  __ bind(&end);
  __ Jump(ra);
}

}  // namespace

void Builtins::Generate_DeoptimizationEntry_Eager(MacroAssembler* masm) {
  Generate_DeoptimizationEntry(masm, DeoptimizeKind::kEager);
}

void Builtins::Generate_DeoptimizationEntry_Lazy(MacroAssembler* masm) {
  Generate_DeoptimizationEntry(masm, DeoptimizeKind::kLazy);
}

namespace {

// Restarts execution either at the current or next (in execution order)
// bytecode. If there is baseline code on the shared function info, converts an
// interpreter frame into a baseline frame and continues execution in baseline
// code. Otherwise execution continues with bytecode.
void Generate_BaselineOrInterpreterEntry(MacroAssembler* masm,
                                         bool next_bytecode,
                                         bool is_osr = false) {
  Label start;
  __ bind(&start);

  // Get function from the frame.
  Register closure = a1;
  __ Ld(closure, MemOperand(fp, StandardFrameConstants::kFunctionOffset));

  // Get the InstructionStream object from the shared function info.
  Register code_obj = s1;
  __ Ld(code_obj,
        FieldMemOperand(closure, JSFunction::kSharedFunctionInfoOffset));

  if (is_osr) {
    ResetSharedFunctionInfoAge(masm, code_obj);
  }

  __ Ld(code_obj,
        FieldMemOperand(code_obj,
                        SharedFunctionInfo::kTrustedFunctionDataOffset));

  // Check if we have baseline code. For OSR entry it is safe to assume we
  // always have baseline code.
  if (!is_osr) {
    Label start_with_baseline;
    __ GetObjectType(code_obj, t2, t2);
    __ Branch(&start_with_baseline, eq, t2, Operand(CODE_TYPE));

    // Start with bytecode as there is no baseline code.
    Builtin builtin = next_bytecode ? Builtin::kInterpreterEnterAtNextBytecode
                                    : Builtin::kInterpreterEnterAtBytecode;
    __ TailCallBuiltin(builtin);

    // Start with baseline code.
    __ bind(&start_with_baseline);
  } else if (v8_flags.debug_code) {
    __ GetObjectType(code_obj, t2, t2);
    __ Assert(eq, AbortReason::kExpectedBaselineData, t2, Operand(CODE_TYPE));
  }

  if (v8_flags.debug_code) {
    AssertCodeIsBaseline(masm, code_obj, t2);
  }

  // Load the feedback cell and vector.
  Register feedback_cell = a2;
  Register feedback_vector = t8;
  __ Ld(feedback_cell,
        FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
  __ Ld(feedback_vector,
        FieldMemOperand(feedback_cell, FeedbackCell::kValueOffset));

  Label install_baseline_code;
  // Check if feedback vector is valid. If not, call prepare for baseline to
  // allocate it.
  __ GetObjectType(feedback_vector, t2, t2);
  __ Branch(&install_baseline_code, ne, t2, Operand(FEEDBACK_VECTOR_TYPE));

  // Save BytecodeOffset from the stack frame.
  __ SmiUntag(kInterpreterBytecodeOffsetRegister,
              MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  // Replace BytecodeOffset with feedback cell.
  static_assert(InterpreterFrameConstants::kBytecodeOffsetFromFp ==
                BaselineFrameConstants::kFeedbackCellFromFp);
  __ Sd(feedback_cell,
        MemOperand(fp, BaselineFrameConstants::kFeedbackCellFromFp));
  feedback_cell = no_reg;
  // Update feedback vector cache.
  static_assert(InterpreterFrameConstants::kFeedbackVectorFromFp ==
                BaselineFrameConstants::kFeedbackVectorFromFp);
  __ Sd(feedback_vector,
        MemOperand(fp, InterpreterFrameConstants::kFeedbackVectorFromFp));
  feedback_vector = no_reg;

  // Compute baseline pc for bytecode offset.
  ExternalReference get_baseline_pc_extref;
  if (next_bytecode || is_osr) {
    get_baseline_pc_extref =
        ExternalReference::baseline_pc_for_next_executed_bytecode();
  } else {
    get_baseline_pc_extref =
        ExternalReference::baseline_pc_for_bytecode_offset();
  }

  Register get_baseline_pc = a3;
  __ li(get_baseline_pc, get_baseline_pc_extref);

  // If the code deoptimizes during the implicit function entry stack interrupt
  // check, it will have a bailout ID of kFunctionEntryBytecodeOffset, which is
  // not a valid bytecode offset.
  // TODO(pthier): Investigate if it is feasible to handle this special case
  // in TurboFan instead of here.
  Label valid_bytecode_offset, function_entry_bytecode;
  if (!is_osr) {
    __ Branch(&function_entry_bytecode, eq, kInterpreterBytecodeOffsetRegister,
              Operand(BytecodeArray::kHeaderSize - kHeapObjectTag +
                      kFunctionEntryBytecodeOffset));
  }

  __ Dsubu(kInterpreterBytecodeOffsetRegister,
           kInterpreterBytecodeOffsetRegister,
           (BytecodeArray::kHeaderSize - kHeapObjectTag));

  __ bind(&valid_bytecode_offset);
  // Get bytecode array from the stack frame.
  __ Ld(kInterpreterBytecodeArrayRegister,
        MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  // Save the accumulator register, since it's clobbered by the below call.
  __ Push(kInterpreterAccumulatorRegister);
  {
    __ Move(kCArgRegs[0], code_obj);
    __ Move(kCArgRegs[1], kInterpreterBytecodeOffsetRegister);
    __ Move(kCArgRegs[2], kInterpreterBytecodeArrayRegister);
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ PrepareCallCFunction(3, 0, a4);
    __ CallCFunction(get_baseline_pc, 3, 0);
  }
  __ LoadCodeInstructionStart(code_obj, code_obj, kJSEntrypointTag);
  __ Daddu(code_obj, code_obj, kReturnRegister0);
  __ Pop(kInterpreterAccumulatorRegister);

  if (is_osr) {
    // TODO(liuyu): Remove Ld as arm64 after register reallocation.
    __ Ld(kInterpreterBytecodeArrayRegister,
          MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
    Generate_OSREntry(masm, code_obj);
  } else {
    __ Jump(code_obj);
  }
  __ Trap();  // Unreachable.

  if (!is_osr) {
    __ bind(&function_entry_bytecode);
    // If the bytecode offset is kFunctionEntryOffset, get the start address of
    // the first bytecode.
    __ mov(kInterpreterBytecodeOffsetRegister, zero_reg);
    if (next_bytecode) {
      __ li(get_baseline_pc,
            ExternalReference::baseline_pc_for_bytecode_offset());
    }
    __ Branch(&valid_bytecode_offset);
  }

  __ bind(&install_baseline_code);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ Push(kInterpreterAccumulatorRegister);
    __ Push(closure);
    __ CallRuntime(Runtime::kInstallBaselineCode, 1);
    __ Pop(kInterpreterAccumulatorRegister);
  }
  // Retry from the start after installing baseline code.
  __ Branch(&start);
}

}  // namespace

void Builtins::Generate_BaselineOrInterpreterEnterAtBytecode(
    MacroAssembler* masm) {
  Generate_BaselineOrInterpreterEntry(masm, false);
}

void Builtins::Generate_BaselineOrInterpreterEnterAtNextBytecode(
    MacroAssembler* masm) {
  Generate_BaselineOrInterpreterEntry(masm, true);
}

void Builtins::Generate_InterpreterOnStackReplacement_ToBaseline(
    MacroAssembler* masm) {
  Generate_BaselineOrInterpreterEntry(masm, false, true);
}

void Builtins::Generate_RestartFrameTrampoline(MacroAssembler* masm) {
  // Frame is being dropped:
  // - Look up current function on the frame.
  // - Leave the frame.
  // - Restart the frame by calling the function.

  __ Ld(a1, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ Ld(a0, MemOperand(fp, StandardFrameConstants::kArgCOffset));

  // Pop return address and frame.
  __ LeaveFrame(StackFrame::INTERPRETED);

  __ li(a2, Operand(kDontAdaptArgumentsSentinel));

  __ InvokeFunction(a1, a2, a0, InvokeType::kJump);
}

#undef __

}  // namespace internal
}  // namespace v8

#endif  // V8_TARGET_ARCH_MIPS64
```