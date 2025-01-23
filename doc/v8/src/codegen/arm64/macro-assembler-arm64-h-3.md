Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Understanding the Core Request:** The primary goal is to understand the functionality of `macro-assembler-arm64.h` within the V8 JavaScript engine, specifically concerning its role in code generation for the ARM64 architecture.

2. **Initial Scan for Keywords and Structure:**  I'd start by skimming the file, looking for recurring keywords and structural elements:
    * `class MacroAssembler`: This immediately tells me the core functionality is encapsulated in this class.
    * Method names like `Load`, `Store`, `Push`, `Pop`, `Call`, `Jump`, `Compare`: These suggest low-level operations related to CPU instructions.
    * Data types like `Register`, `VRegister`, `MemOperand`, `Label`:  These hint at representing CPU registers, memory locations, and code labels.
    * Sections like "Debugging," "Protected," "Private": This indicates different levels of access and purpose for different parts of the class.
    * `#ifdef DEBUG`:  Suggests debugging-related features and conditional compilation.
    * Nested classes like `InstructionAccurateScope`, `UseScratchRegisterScope`:  These look like helper classes to manage specific tasks.

3. **Analyzing the `MacroAssembler` Class - High-Level Functionality:**
    * **Code Generation:** The name "MacroAssembler" implies it's responsible for generating machine code. The numerous methods with names resembling ARM64 instructions confirm this.
    * **Abstraction over Assembly:** The "macro" aspect suggests it provides a higher-level abstraction than raw assembly, simplifying common sequences of instructions.
    * **Architecture Specificity:** The "arm64" in the filename clearly indicates its target architecture.

4. **Examining Key Method Categories and Their Functionality:**  I'd group related methods to understand their broader purpose:
    * **Data Movement:** `Load`, `Store`, `Push`, `Pop`, `Move`. These are fundamental for moving data between registers and memory.
    * **Arithmetic and Logic:**  `Add`, `Sub`, `Mul`, `And`, `Or`, `Cmp`. Basic operations on data.
    * **Control Flow:** `Jump`, `Branch`, `Call`, `Ret`. Mechanisms for controlling the execution order.
    * **Comparisons:**  Methods like `CompareMacro`, `ConditionalCompareMacro`. Setting up conditions for branching.
    * **Floating-Point Operations:**  Methods involving `VRegister` suggest support for SIMD (Single Instruction, Multiple Data) and floating-point operations.
    * **Debugging and Runtime Support:**  `LoadNativeContextSlot`, `TryLoadOptimizedOsrCode`, `CallPrintf`. These indicate interaction with the V8 runtime and debugging features.
    * **Immediate Values:** Methods like `Movi16bitHelper`, `Movi32bitHelper`, `Movi64bitHelper` for loading immediate values into registers.

5. **Analyzing Helper Classes:**
    * **`InstructionAccurateScope`:** The name and comments suggest this is for ensuring a precise mapping between C++ code and generated instructions, useful for debugging or when precise instruction counts are needed.
    * **`UseScratchRegisterScope`:**  The comments clearly state its purpose: managing temporary registers ("scratch registers") automatically. This is a common pattern in code generators to avoid manual register allocation.

6. **Considering the `.tq` Extension and JavaScript Connection:**
    * The prompt explicitly mentions `.tq` indicating Torque. I'd note this down as a possibility, even if the content doesn't immediately scream "Torque."
    * The connection to JavaScript is through the fact that this code generator is *for* the V8 engine, which *executes* JavaScript. The generated ARM64 code directly implements JavaScript functionality.

7. **Looking for Code Logic and Examples:**
    * The methods themselves represent code logic, but they are *generating* code, not executing it directly in the C++ file.
    * For JavaScript examples, I need to think about what kind of low-level operations are required to implement JavaScript features. Simple arithmetic, object property access, function calls are good starting points.

8. **Identifying Common Programming Errors:** I'd think about common mistakes in low-level programming that this `MacroAssembler` might help prevent or where its use could lead to errors:
    * Incorrect register usage.
    * Off-by-one errors in memory access.
    * Incorrectly setting up function call arguments.
    * Branching to the wrong location.

9. **Addressing the "Part 4 of 4" and Summarization Request:** This signals the need for a concise summary of the overall purpose and role of the header file.

10. **Refinement and Structuring the Answer:** Finally, I'd organize the gathered information into a logical structure, using headings and bullet points for clarity. I'd aim for a comprehensive yet concise explanation, addressing all aspects of the prompt.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  "Is this just a wrapper around ARM assembly?"  -> **Correction:** It's more than just a direct mapping. The "macro" aspect indicates higher-level constructs and helper functions to manage things like labels and register allocation.
* **Considering Torque:**  While the `.h` extension contradicts the `.tq` statement, it's important to acknowledge the prompt's information and consider the possibility of generated code or related files.
* **JavaScript examples:** Initially, I might focus on very low-level details, but then realize it's more effective to demonstrate the *purpose* through relatable JavaScript concepts.
* **Error examples:** I'd aim for examples relevant to the functionality exposed in the header, not just generic programming errors.

By following this systematic process, combining keyword analysis, understanding the domain (V8 code generation), and considering the specific points raised in the prompt, I can arrive at a detailed and accurate explanation of the `macro-assembler-arm64.h` file.
这是对 `v8/src/codegen/arm64/macro-assembler-arm64.h` 文件剩余部分的功能进行总结和解释。

**核心功能归纳：**

`v8/src/codegen/arm64/macro-assembler-arm64.h` 文件定义了 `MacroAssembler` 类，它是 V8 JavaScript 引擎中用于在 ARM64 架构上生成机器码的关键组件。它提供了一组高级的 C++ 接口，允许开发者以更抽象的方式生成 ARM64 指令，而无需手动编写原始汇编代码。

**具体功能点：**

1. **只读检查 (ReadOnlyCheck):**
   - `o_check = ReadOnlyCheck::kInline;` 和 `SlotDescriptor slot = SlotDescriptor::ForDirectPointerSlot());`  定义了在某些操作中执行内联只读检查的方式和槽位描述符。这通常用于确保某些内存区域在特定操作中不会被意外修改，例如访问常量或不可变对象。

2. **调试功能 (Debugging):**
   - `void LoadNativeContextSlot(Register dst, int index);`:  允许加载原生上下文的槽位到指定的寄存器。这对于调试 V8 内部状态非常有用。
   - `void TryLoadOptimizedOsrCode(...)`: 尝试加载优化的 On-Stack Replacement (OSR) 代码。OSR 是一种优化技术，允许在函数执行过程中切换到更优化的代码版本。这个方法负责在运行时检查并加载合适的优化代码。

3. **底层的 Push 和 Pop 辅助函数 (Push and Pop Helpers):**
   - `void PushHelper(...)` 和 `void PopHelper(...)`:  提供了实际执行压栈和出栈操作的底层实现。它们接受寄存器列表和数据大小作为参数，并生成相应的机器码。这些辅助函数被 `PushCPURegList` 和 `PopCPURegList` 等高层方法使用。

4. **条件比较宏 (Conditional Compare Macro):**
   - `void ConditionalCompareMacro(...)`: 生成执行条件比较的指令。它可以比较寄存器和一个操作数，并根据比较结果设置状态标志。

5. **带进位的加减法宏 (Add/Sub With Carry Macro):**
   - `void AddSubWithCarryMacro(...)`: 生成带进位的加法或减法指令。这对于处理大于寄存器大小的数值运算非常重要。

6. **调用 Printf (Call Printf):**
   - `void CallPrintf(...)`: 允许在生成的代码中调用 `printf` 函数。在原生构建中，它会生成一个简单的函数调用；在模拟器中，会使用伪指令。调用者需要准备好参数和堆栈。

7. **控制宏指令的使用 (Control Macro Instructions):**
   - `#if DEBUG bool allow_macro_instructions_ = true; #endif`:  在调试模式下，允许控制是否可以使用生成可变数量指令的宏指令。这有助于在需要精确控制生成代码大小时进行调试。

8. **临时寄存器列表 (Temporary Register Lists):**
   - `CPURegList tmp_list_ = DefaultTmpList();` 和 `CPURegList fptmp_list_ = DefaultFPTmpList();`:  维护用于宏汇编器临时使用的通用寄存器和浮点寄存器列表。

9. **处理超出范围的分支 (Handling Out-of-Range Branches):**
   - `template <ImmBranchType branch_type> bool NeedExtraInstructionsOrRegisterBranch(Label* label)`:  负责检测分支目标是否超出当前指令的寻址范围。如果超出范围，它会记录必要的信息以便稍后生成跳转桩 (veneer)。

10. **加载立即数辅助函数 (Load Immediate Helpers):**
    - `void Movi16bitHelper(...)`, `void Movi32bitHelper(...)`, `void Movi64bitHelper(...)`: 帮助将 16 位、32 位和 64 位立即数加载到向量寄存器中。

11. **加载和存储宏 (Load and Store Macros):**
    - `void LoadStoreMacro(...)` 和 `void LoadStoreMacroComplex(...)`:  生成加载和存储数据的指令。`LoadStoreMacroComplex` 可能处理更复杂的寻址模式。
    - `void LoadStorePairMacro(...)`: 生成加载和存储一对寄存器的指令。

12. **计算目标偏移量 (Calculate Target Offset):**
    - `static int64_t CalculateTargetOffset(...)`:  计算跳转目标地址相对于当前程序计数器 (PC) 的偏移量，并考虑重定位信息。

13. **跳转辅助函数 (Jump Helper):**
    - `void JumpHelper(...)`:  生成跳转指令，允许指定偏移量、重定位模式和条件。

14. **`InstructionAccurateScope` 类:**
    - 提供了一个作用域，用于确保生成代码的方法和指令之间存在一对一的映射。在这个作用域内，宏汇编器不能被调用，也不会发射文字池。这对于需要精确控制生成指令数量的场景很有用，例如在测试或需要进行精确代码大小分析时。

15. **`UseScratchRegisterScope` 类:**
    - 提供了一个方便的作用域，用于安全地管理临时寄存器（scratch registers）。它从宏汇编器的临时寄存器列表中分配寄存器，并在作用域结束时自动释放，避免了手动管理临时寄存器的复杂性。

16. **`MoveCycleState` 结构体:**
    - 用于在指令移动周期中管理状态，包括保留的临时寄存器和可用的临时寄存器。这通常用于优化代码生成过程中的寄存器分配。

17. **访问 Exit Frame 参数 (Accessing Exit Frame Parameters):**
    - `inline MemOperand ExitFrameStackSlotOperand(int offset);` 和 `inline MemOperand ExitFrameCallerStackSlotOperand(int index);`:  提供了访问退出帧（Exit Frame）中堆栈槽位的便捷方法。退出帧用于管理从 JavaScript 代码调用原生 C++ 代码时的上下文。

18. **调用 API 函数并返回 (Calling API Function and Returning):**
    - `void CallApiFunctionAndReturn(...)`:  生成调用 V8 API 函数的代码。它负责分配 `HandleScope`，提取返回值，处理异常，并清理堆栈。

**关于 `.tq` 结尾：**

如果 `v8/src/codegen/arm64/macro-assembler-arm64.h` 以 `.tq` 结尾，那么它确实是一个 V8 Torque 源代码文件。Torque 是一种用于定义 V8 内部函数（例如内置函数和运行时函数）的领域特定语言。然而，根据您提供的文件名，它是 `.h` 文件，表明这是一个 C++ 头文件。 Torque 文件通常会生成 C++ 代码，这些生成的代码可能会与 `MacroAssembler` 类一起使用。

**与 JavaScript 的关系及示例：**

`MacroAssembler` 生成的 ARM64 机器码直接执行 JavaScript 代码。例如，考虑一个简单的 JavaScript 加法操作：

```javascript
function add(a, b) {
  return a + b;
}
```

当 V8 编译这个函数时，`MacroAssembler` 可能会生成如下类似的 ARM64 指令序列（简化示例）：

```assembly
// 假设 'a' 在寄存器 x0, 'b' 在寄存器 x1
ldr w2, [sp, #offset_a]  // 从栈中加载 'a' 到 w2
ldr w3, [sp, #offset_b]  // 从栈中加载 'b' 到 w3
add w0, w2, w3           // 将 w2 和 w3 相加，结果放入 w0
str w0, [sp, #offset_result] // 将结果存储回栈中
```

在 `macro-assembler-arm64.h` 中，会提供类似 `LoadMemOperand`、`Add`、`StoreMemOperand` 等方法来生成这些指令。例如，`Add` 方法可能如下所示：

```c++
void MacroAssembler::Add(Register rd, Register rn, const Operand& operand) {
  Emit(ADD_rr(rd, rn, operand));
}
```

**代码逻辑推理 (假设输入与输出)：**

假设我们有一个 `MacroAssembler` 实例 `masm` 并且我们想生成将寄存器 `x1` 和 `x2` 的内容相加并将结果存储到 `x0` 的指令。

```c++
MacroAssembler masm;
Register dst = x0;
Register src1 = x1;
Register src2 = x2;

masm.Add(dst, src1, src2);
```

**假设输入：**  `masm` 是一个 `MacroAssembler` 对象，`dst` 是寄存器 `x0`，`src1` 是寄存器 `x1`，`src2` 是寄存器 `x2`。

**输出（生成的机器码）：**  类似于 `add x0, x1, x2` 的 ARM64 指令会被添加到 `masm` 的代码缓冲区中。

**用户常见的编程错误：**

使用 `MacroAssembler` 时，常见的编程错误包括：

1. **错误的寄存器分配：**  手动分配寄存器时，可能会错误地使用了已被占用的寄存器，导致数据被覆盖。`UseScratchRegisterScope` 可以帮助避免这类错误。
2. **不正确的内存访问：**  计算内存地址时出现错误，导致访问了错误的内存位置，可能引发崩溃或数据损坏。
3. **忘记处理分支标签：**  在生成包含分支的指令时，需要正确绑定标签，否则会导致跳转到错误的位置。
4. **不匹配的 Push 和 Pop 操作：**  压栈和出栈操作数量不匹配会导致栈指针错误，最终可能导致程序崩溃。
5. **调用约定错误：**  在调用函数时，没有按照 ARM64 的调用约定设置参数和堆栈，可能导致函数调用失败或产生未定义行为。

**总结：**

`v8/src/codegen/arm64/macro-assembler-arm64.h` 是 V8 引擎在 ARM64 架构上进行代码生成的核心组件。它提供了一组丰富的接口，用于生成各种 ARM64 指令，并抽象了底层的汇编细节。它包含了用于调试、优化、处理分支、内存访问以及与运行时环境交互的功能。 `InstructionAccurateScope` 和 `UseScratchRegisterScope` 等辅助类提高了代码生成过程的可靠性和效率。 开发者使用此类可以构建高效且正确的 JavaScript 执行代码。

### 提示词
```
这是目录为v8/src/codegen/arm64/macro-assembler-arm64.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/arm64/macro-assembler-arm64.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```c
o_check = ReadOnlyCheck::kInline,
      SlotDescriptor slot = SlotDescriptor::ForDirectPointerSlot());

  // ---------------------------------------------------------------------------
  // Debugging.

  void LoadNativeContextSlot(Register dst, int index);

  // Falls through and sets scratch_and_result to 0 on failure, jumps to
  // on_result on success.
  void TryLoadOptimizedOsrCode(Register scratch_and_result,
                               CodeKind min_opt_level, Register feedback_vector,
                               FeedbackSlot slot, Label* on_result,
                               Label::Distance distance);

 protected:
  // The actual Push and Pop implementations. These don't generate any code
  // other than that required for the push or pop. This allows
  // (Push|Pop)CPURegList to bundle together run-time assertions for a large
  // block of registers.
  //
  // Note that size is per register, and is specified in bytes.
  void PushHelper(int count, int size, const CPURegister& src0,
                  const CPURegister& src1, const CPURegister& src2,
                  const CPURegister& src3);
  void PopHelper(int count, int size, const CPURegister& dst0,
                 const CPURegister& dst1, const CPURegister& dst2,
                 const CPURegister& dst3);

  void ConditionalCompareMacro(const Register& rn, const Operand& operand,
                               StatusFlags nzcv, Condition cond,
                               ConditionalCompareOp op);

  void AddSubWithCarryMacro(const Register& rd, const Register& rn,
                            const Operand& operand, FlagsUpdate S,
                            AddSubWithCarryOp op);

  // Call Printf. On a native build, a simple call will be generated, but if the
  // simulator is being used then a suitable pseudo-instruction is used. The
  // arguments and stack must be prepared by the caller as for a normal AAPCS64
  // call to 'printf'.
  //
  // The 'args' argument should point to an array of variable arguments in their
  // proper PCS registers (and in calling order). The argument registers can
  // have mixed types. The format string (x0) should not be included.
  void CallPrintf(int arg_count = 0, const CPURegister* args = nullptr);

 private:
#if DEBUG
  // Tell whether any of the macro instruction can be used. When false the
  // MacroAssembler will assert if a method which can emit a variable number
  // of instructions is called.
  bool allow_macro_instructions_ = true;
#endif

  // Scratch registers available for use by the MacroAssembler.
  CPURegList tmp_list_ = DefaultTmpList();
  CPURegList fptmp_list_ = DefaultFPTmpList();

  // Helps resolve branching to labels potentially out of range.
  // If the label is not bound, it registers the information necessary to later
  // be able to emit a veneer for this branch if necessary.
  // If the label is bound, it returns true if the label (or the previous link
  // in the label chain) is out of range. In that case the caller is responsible
  // for generating appropriate code.
  // Otherwise it returns false.
  // This function also checks wether veneers need to be emitted.
  template <ImmBranchType branch_type>
  bool NeedExtraInstructionsOrRegisterBranch(Label* label) {
    static_assert((branch_type == CondBranchType) ||
                  (branch_type == CompareBranchType) ||
                  (branch_type == TestBranchType));

    bool need_longer_range = false;
    // There are two situations in which we care about the offset being out of
    // range:
    //  - The label is bound but too far away.
    //  - The label is not bound but linked, and the previous branch
    //    instruction in the chain is too far away.
    if (label->is_bound() || label->is_linked()) {
      need_longer_range = !Instruction::IsValidImmPCOffset(
          branch_type, label->pos() - pc_offset());
    }
    if (!need_longer_range && !label->is_bound()) {
      int max_reachable_pc =
          pc_offset() + Instruction::ImmBranchRange(branch_type);

      // Use the LSB of the max_reachable_pc (always four-byte aligned) to
      // encode the branch type. We need only distinguish between TB[N]Z and
      // CB[N]Z/conditional branch, as the ranges for the latter are the same.
      int branch_type_tag = (branch_type == TestBranchType) ? 1 : 0;

      unresolved_branches_.insert(
          std::pair<int, Label*>(max_reachable_pc + branch_type_tag, label));
      // Also maintain the next pool check.
      next_veneer_pool_check_ =
          std::min(next_veneer_pool_check_,
                   max_reachable_pc - kVeneerDistanceCheckMargin);
    }
    return need_longer_range;
  }

  void Movi16bitHelper(const VRegister& vd, uint64_t imm);
  void Movi32bitHelper(const VRegister& vd, uint64_t imm);
  void Movi64bitHelper(const VRegister& vd, uint64_t imm);

  void LoadStoreMacro(const CPURegister& rt, const MemOperand& addr,
                      LoadStoreOp op);
  void LoadStoreMacroComplex(const CPURegister& rt, const MemOperand& addr,
                             LoadStoreOp op);

  void LoadStorePairMacro(const CPURegister& rt, const CPURegister& rt2,
                          const MemOperand& addr, LoadStorePairOp op);

  static int64_t CalculateTargetOffset(Address target, RelocInfo::Mode rmode,
                                       uint8_t* pc);

  void JumpHelper(int64_t offset, RelocInfo::Mode rmode, Condition cond = al);

  friend class wasm::JumpTableAssembler;

  DISALLOW_IMPLICIT_CONSTRUCTORS(MacroAssembler);
};

// Use this scope when you need a one-to-one mapping between methods and
// instructions. This scope prevents the MacroAssembler from being called and
// literal pools from being emitted. It also asserts the number of instructions
// emitted is what you specified when creating the scope.
class V8_NODISCARD InstructionAccurateScope {
 public:
  explicit InstructionAccurateScope(MacroAssembler* masm, size_t count = 0)
      : masm_(masm),
        block_pool_(masm, count * kInstrSize)
#ifdef DEBUG
        ,
        size_(count * kInstrSize)
#endif
  {
    masm_->CheckVeneerPool(false, true, count * kInstrSize);
    masm_->StartBlockVeneerPool();
#ifdef DEBUG
    if (count != 0) {
      masm_->bind(&start_);
    }
    previous_allow_macro_instructions_ = masm_->allow_macro_instructions();
    masm_->set_allow_macro_instructions(false);
#endif
  }

  ~InstructionAccurateScope() {
    masm_->EndBlockVeneerPool();
#ifdef DEBUG
    if (start_.is_bound()) {
      DCHECK(masm_->SizeOfCodeGeneratedSince(&start_) == size_);
    }
    masm_->set_allow_macro_instructions(previous_allow_macro_instructions_);
#endif
  }

 private:
  MacroAssembler* masm_;
  MacroAssembler::BlockConstPoolScope block_pool_;
#ifdef DEBUG
  size_t size_;
  Label start_;
  bool previous_allow_macro_instructions_;
#endif
};

// This scope utility allows scratch registers to be managed safely. The
// MacroAssembler's TmpList() (and FPTmpList()) is used as a pool of scratch
// registers. These registers can be allocated on demand, and will be returned
// at the end of the scope.
//
// When the scope ends, the MacroAssembler's lists will be restored to their
// original state, even if the lists were modified by some other means. Note
// that this scope can be nested but the destructors need to run in the opposite
// order as the constructors. We do not have assertions for this.
class V8_NODISCARD UseScratchRegisterScope {
 public:
  explicit UseScratchRegisterScope(MacroAssembler* masm)
      : available_(masm->TmpList()),
        availablefp_(masm->FPTmpList()),
        old_available_(available_->bits()),
        old_availablefp_(availablefp_->bits()) {
    DCHECK_EQ(available_->type(), CPURegister::kRegister);
    DCHECK_EQ(availablefp_->type(), CPURegister::kVRegister);
  }

  V8_EXPORT_PRIVATE ~UseScratchRegisterScope() {
    available_->set_bits(old_available_);
    availablefp_->set_bits(old_availablefp_);
  }

  // Take a register from the appropriate temps list. It will be returned
  // automatically when the scope ends.
  Register AcquireW() { return AcquireNextAvailable(available_).W(); }
  Register AcquireX() { return AcquireNextAvailable(available_).X(); }
  VRegister AcquireS() { return AcquireNextAvailable(availablefp_).S(); }
  VRegister AcquireD() { return AcquireNextAvailable(availablefp_).D(); }
  VRegister AcquireQ() { return AcquireNextAvailable(availablefp_).Q(); }
  VRegister AcquireV(VectorFormat format) {
    return VRegister::Create(AcquireNextAvailable(availablefp_).code(), format);
  }

  bool CanAcquire() const { return !available_->IsEmpty(); }
  bool CanAcquireFP() const { return !availablefp_->IsEmpty(); }

  Register AcquireSameSizeAs(const Register& reg) {
    int code = AcquireNextAvailable(available_).code();
    return Register::Create(code, reg.SizeInBits());
  }

  V8_EXPORT_PRIVATE VRegister AcquireSameSizeAs(const VRegister& reg) {
    int code = AcquireNextAvailable(availablefp_).code();
    return VRegister::Create(code, reg.SizeInBits());
  }

  void Include(const CPURegList& list) { available_->Combine(list); }
  void IncludeFP(const CPURegList& list) { availablefp_->Combine(list); }
  void Exclude(const CPURegList& list) {
#if DEBUG
    CPURegList copy(list);
    while (!copy.IsEmpty()) {
      const CPURegister& reg = copy.PopHighestIndex();
      DCHECK(available_->IncludesAliasOf(reg));
    }
#endif
    available_->Remove(list);
  }
  void ExcludeFP(const CPURegList& list) {
#if DEBUG
    CPURegList copy(list);
    while (!copy.IsEmpty()) {
      const CPURegister& reg = copy.PopHighestIndex();
      DCHECK(availablefp_->IncludesAliasOf(reg));
    }
#endif
    availablefp_->Remove(list);
  }
  void Include(const Register& reg1, const Register& reg2 = NoReg) {
    CPURegList list(reg1, reg2);
    Include(list);
  }
  void Exclude(const Register& reg1, const Register& reg2 = NoReg) {
    CPURegList list(reg1, reg2);
    Exclude(list);
  }
  void ExcludeFP(const VRegister& reg) { ExcludeFP(CPURegList(reg)); }

  CPURegList* Available() { return available_; }
  void SetAvailable(const CPURegList& list) { *available_ = list; }

  CPURegList* AvailableFP() { return availablefp_; }
  void SetAvailableFP(const CPURegList& list) { *availablefp_ = list; }

 private:
  V8_EXPORT_PRIVATE static CPURegister AcquireNextAvailable(
      CPURegList* available) {
    CHECK(!available->IsEmpty());
    CPURegister result = available->PopLowestIndex();
    DCHECK(!AreAliased(result, xzr, sp));
    return result;
  }

  // Available scratch registers.
  CPURegList* available_;    // kRegister
  CPURegList* availablefp_;  // kVRegister

  // The state of the available lists at the start of this scope.
  uint64_t old_available_;    // kRegister
  uint64_t old_availablefp_;  // kVRegister
};

struct MoveCycleState {
  // List of scratch registers reserved for pending moves in a move cycle, and
  // which should therefore not be used as a temporary location by
  // {MoveToTempLocation}.
  RegList scratch_regs;
  DoubleRegList scratch_fp_regs;
  // Available scratch registers during the move cycle resolution scope.
  std::optional<UseScratchRegisterScope> temps;
  // Scratch register picked by {MoveToTempLocation}.
  std::optional<CPURegister> scratch_reg;
};

// Provides access to exit frame parameters (GC-ed).
inline MemOperand ExitFrameStackSlotOperand(int offset);

// Provides access to exit frame parameters (GC-ed).
inline MemOperand ExitFrameCallerStackSlotOperand(int index);

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

#endif  // V8_CODEGEN_ARM64_MACRO_ASSEMBLER_ARM64_H_
```