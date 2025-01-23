Response:
My thinking process to answer the request went through these stages:

1. **Understanding the Core Request:** The primary goal is to summarize the functionality of the provided C++ header file (`macro-assembler-arm64.h`) for the V8 JavaScript engine. The prompt also includes specific constraints about checking for Torque files, relating to JavaScript, providing examples, and identifying common errors.

2. **Initial Scan and Keyword Identification:** I first scanned the provided code snippet for recurring keywords and patterns. This helps to quickly grasp the major areas of functionality. Keywords like `Register`, `Label`, `MemOperand`, `VRegister`, `Sandbox`, `Wasm`, `Push`, `Pop`, `Call`, `Jump`, `Load`, `Store`, `Compare`, `Assert`, `RecordWrite`, and function names like `RestoreFPAndLR`, `PopcntHelper`, `DecodeSandboxedPointer`, `InvokeFunction`, `CompareObjectType`, `EnterExitFrame`, `LoadWeakValue`, `IncrementCounter`, `StackOverflowCheck` stood out. These are strong indicators of the header's purpose.

3. **Categorization and Grouping:**  Based on the keywords and function names, I started mentally grouping related functionalities. For example, functions with `Push` and `Pop` clearly deal with stack manipulation. Functions with `LoadSandboxedPointer`, `DecodeSandboxedPointer` are related to sandboxing. Functions with `CallRuntime`, `InvokeFunction` are about function calls. This categorization is crucial for a coherent summary.

4. **Inferring High-Level Functionality:**  From the categories, I started to infer the overall purpose of the header. The presence of register manipulation, memory operations, conditional jumps, and function calls strongly suggests that this header is responsible for generating machine code instructions for the ARM64 architecture. The "MacroAssembler" part of the filename reinforces this.

5. **Addressing Specific Constraints:**  I then went through the prompt's specific constraints:

    * **Torque Check:** The prompt states how to identify a Torque file (`.tq` extension). I noted that this file doesn't end in `.tq`, so it's not a Torque file.
    * **Relationship to JavaScript:** The file is part of V8, a JavaScript engine. The functions clearly operate on JavaScript concepts like functions, objects, and execution. I looked for concrete examples. Functions like `InvokeFunction`, `CallRuntime`, and assertions about object types (`AssertMap`, `AssertFunction`) directly relate to JavaScript execution.
    * **JavaScript Examples:**  I formulated simple JavaScript examples that could potentially lead to the execution of the functions described in the header. Focusing on function calls, object property access, and control flow made sense.
    * **Code Logic/Reasoning:** I looked for functions that involved conditional logic or data transformation. The sandbox-related functions (encoding/decoding pointers) and the feedback vector functions seemed like good candidates for illustrating input/output. I created hypothetical scenarios.
    * **Common Programming Errors:**  I thought about typical errors related to the functionalities exposed by the header. Stack overflows (related to stack manipulation functions), incorrect function calls (related to the invoke functions), and memory access violations (potentially related to sandbox functions) came to mind.
    * **Summarization:** This was the final step. I synthesized the information gathered in the previous steps into a concise summary, focusing on the key responsibilities of the `MacroAssembler`.

6. **Refinement and Structuring:** I organized the information logically, using headings and bullet points to improve readability. I ensured the JavaScript examples were clear and directly related to the C++ functions. I double-checked that all the prompt's constraints were addressed.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Perhaps focus heavily on individual instruction mnemonics. **Correction:** Realized the prompt asks for *functionality*, so a higher-level summary is more appropriate. The mnemonics are implementation details.
* **Initial thought:**  Provide very complex JavaScript examples. **Correction:** Simplified the examples to clearly demonstrate the connection to the C++ functions without getting bogged down in intricate JavaScript code.
* **Initial thought:**  Treat each function in isolation. **Correction:** Recognized the importance of grouping related functions to show broader areas of responsibility (e.g., all the sandbox functions together).
* **Initial thought:**  Omit details about the ARM64 architecture. **Correction:** Included a brief mention that this header is specific to ARM64, as it's in the file path.

By following this iterative process of scanning, categorizing, inferring, and refining, I aimed to produce a comprehensive and accurate summary that addressed all aspects of the prompt.
这是提供的 `v8/src/codegen/arm64/macro-assembler-arm64.h` 文件的第三部分，延续了之前定义的功能。 让我们归纳一下这部分代码的功能：

**核心功能： 辅助代码生成，特别是针对ARM64架构的优化和特殊场景处理。**

这部分代码继续扩展了 `MacroAssembler` 类，提供了用于生成 ARM64 汇编指令的更高级别的抽象和辅助方法。其重点在于处理 V8 引擎的特定需求，例如 WebAssembly 支持、安全沙箱机制、代码优化分层 (Leaptiering)、以及与垃圾回收、调用约定和运行时环境的交互。

**功能细分：**

1. **栈帧管理和寄存器保存/恢复:**
   - `RestoreFPAndLR()`: 恢复帧指针 (FP) 和链接寄存器 (LR)，用于函数返回时的状态恢复。
   - `StoreReturnAddressInWasmExitFrame()`:  在 WebAssembly 的退出帧中存储返回地址。

2. **WebAssembly 辅助函数:**
   - 提供了一些用于 WebAssembly 代码生成的辅助函数，这些函数没有直接对应的原生 ARM64 指令，需要在 `MacroAssembler` 中进行特殊处理，例如：
     - `PopcntHelper()`: 计算 population count (设置位的数量)。
     - `I8x16BitMask()`, `I16x8BitMask()`, `I32x4BitMask()`, `I64x2BitMask()`, `I64x2AllTrue()`:  用于 SIMD 指令，生成位掩码。

3. **V8 沙箱支持 (安全机制):**
   - 这部分定义了处理沙箱指针的函数，用于增强安全性，防止代码访问沙箱外的内存。
   - `DecodeSandboxedPointer()`, `LoadSandboxedPointerField()`, `StoreSandboxedPointerField()`:  处理沙箱指针的编码和解码。
   - `LoadExternalPointerField()`:  加载指向沙箱外部的指针，并进行必要的解码。
   - `LoadTrustedPointerField()`, `StoreTrustedPointerField()`:  加载和存储受信任的指针，这些指针在沙箱启用时使用间接指针表。
   - `LoadCodePointerField()`, `StoreCodePointerField()`:  专门处理代码指针，用于在沙箱环境中引用代码对象。
   - `LoadIndirectPointerField()`, `StoreIndirectPointerField()`: 处理间接指针。
   - `#ifdef V8_ENABLE_SANDBOX` 块中的函数 (例如 `ResolveIndirectPointerHandle`, `ResolveCodePointerHandle`, `LoadCodeEntrypointViaCodePointer`) 是仅在启用沙箱时才使用的功能。

4. **代码优化分层 (Leaptiering) 支持:**
   - `#ifdef V8_ENABLE_LEAPTIERING` 块中的函数 (例如 `LoadEntrypointFromJSDispatchTable`, `LoadParameterCountFromJSDispatchTable`, `LoadEntrypointAndParameterCountFromJSDispatchTable`) 用于在分层编译过程中，从 JS 分发表中加载入口点和参数计数。

5. **受保护指针字段:**
   - `LoadProtectedPointerField()`:  加载受保护的指针字段。

6. **ARM64 指令宏:**
   - 提供了一些 ARM64 指令的宏定义，方便使用，例如：
     - `Bics`, `Adcs`, `Sbc`, `Sbcs`, `Ngc`, `Ngcs`:  逻辑和算术运算指令。
     - `STLX_MACRO_LIST`:  一系列原子加载/存储指令。
     - `Bfxil`, `Cinc`, `Cinv`, `CzeroX`, `Csinv`, `Csneg`, `Extr`:  位域操作和条件选择指令。
     - `Fcvtl2`, `Fcvtn2`, `Fcvtxn`, `Fcvtxn2`:  浮点数转换指令。
     - `Fmadd`, `Fmaxnm`, `Fminnm`, `Fmsub`, `Fnmadd`, `Fnmsub`:  浮点数乘加/减指令。
     - `Hint`, `Hlt`:  系统提示和停止指令。
     - `Ldnp`, `Movk`, `Nop`, `Mvni`, `Smaddl`, `Smsubl`, `Stnp`, `Umaddl`, `Umsubl`:  各种数据加载/移动和算术指令。
     - `Ld1`, `Ld2`, `Ld3`, `Ld4`, `St2`, `St3`, `St4`, `Tbx`:  SIMD 加载/存储指令。
     - `PushSizeRegList`, `PopSizeRegList`, `PushXRegList`, `PopXRegList`, `PushWRegList`, `PopWRegList`, `PushQRegList`, `PopQRegList`, `PushDRegList`, `PopDRegList`, `PushSRegList`, `PopSRegList`:  批量压栈/出栈寄存器。
     - `PushAll`, `PopAll`:  压栈/出栈所有指定寄存器。
     - `PushMultipleTimes()`:  将指定寄存器压栈多次。
     - `PeekPair()`:  查看栈上的两个值。

7. **调用约定和上下文管理:**
   - `PushCalleeSavedRegisters()`:  保存被调用者保存的寄存器。
   - `PopCalleeSavedRegisters()`:  恢复被调用者保存的寄存器。

8. **代码优化辅助:**
   - `AssertFeedbackCell()`, `AssertFeedbackVector()`:  断言反馈单元和反馈向量的状态，用于调试和优化。
   - `ReplaceClosureCodeWithOptimizedCode()`:  用优化后的代码替换闭包的代码。
   - `GenerateTailCallToReturnedCode()`:  生成尾调用到返回的代码。
   - `#ifndef V8_ENABLE_LEAPTIERING` 块中的函数 (例如 `LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing`, `OptimizeCodeOrTailCallOptimizedCodeSlot`) 用于在未启用 Leaptiering 的情况下处理反馈向量。

**与 JavaScript 的关系 (举例):**

当 JavaScript 代码执行时，V8 的编译器 (例如 TurboFan 或 Crankshaft) 会将 JavaScript 代码转换为机器码。 `MacroAssembler` 就是在这个过程中被用来生成 ARM64 汇编指令的关键组件。

例如，考虑以下 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

add(5, 10);
```

当 `add(5, 10)` 被调用时，V8 可能会生成类似以下的 ARM64 汇编代码片段（简化示例）：

```assembly
// ... 前期准备工作 ...

// 将参数加载到寄存器 (假设 W0 和 W1)
mov w0, #5
mov w1, #10

// 调用 add 函数的代码
bl <address_of_add_function>

// ... 后续处理 ...
```

`MacroAssembler` 提供的函数，例如 `Mov()` (虽然在这个代码片段中是汇编指令，但在 `MacroAssembler` 中会有对应的 C++ 方法) 和 `Call()` (或其底层实现)，会被用来生成这些指令。  `PushCalleeSavedRegisters()` 和 `PopCalleeSavedRegisters()` 会在函数调用的前后被用来保存和恢复寄存器，以遵守调用约定。  如果涉及到对象操作，例如访问对象的属性，那么沙箱相关的函数可能会被调用来确保内存访问的安全性。

**代码逻辑推理 (假设输入与输出):**

假设我们调用 `PopcntHelper(w0, w1)`，其中 `w1` 寄存器包含值 `0b10110100` (二进制)。

* **输入:** `dst` (w0), `src` (w1, 值为 `0b10110100`)
* **操作:** `PopcntHelper` 函数内部会生成相应的 ARM64 指令来计算 `w1` 中设置的位的数量。
* **输出:** `w0` 寄存器将包含值 `4` (因为 `w1` 中有 4 个 '1' 位)。

**用户常见的编程错误 (如果与 JavaScript 功能相关):**

虽然这个头文件是 V8 内部的，普通 JavaScript 开发者不会直接接触，但理解其背后的概念有助于理解 V8 的工作原理。  与这部分功能相关的常见编程错误可能包括：

* **栈溢出:**  如果 JavaScript 代码导致过多的函数调用或递归，可能会超过栈的限制。`StackOverflowCheck()` 这样的函数会在底层帮助 V8 检测这种情况。
* **类型错误:**  如果 JavaScript 代码尝试对不兼容的类型进行操作，例如将一个非数字的值传递给 `add` 函数，V8 在运行时会进行类型检查，这可能涉及到 `CompareObjectType()` 或 `JumpIfObjectType()` 这样的函数来检查对象的类型。
* **安全漏洞:**  虽然 V8 自身会处理沙箱机制，但理解沙箱的概念有助于理解为什么某些操作在特定的上下文中是不允许的。

**归纳一下它的功能:**

这部分 `macro-assembler-arm64.h` 的核心功能是 **提供了一组用于生成高效、安全且与 V8 运行时环境集成的 ARM64 汇编指令的构建块。** 它涵盖了栈帧管理、WebAssembly 支持、沙箱安全机制、代码优化分层、底层的 ARM64 指令抽象以及与垃圾回收和调用约定的集成。  这些功能对于 V8 引擎将 JavaScript 代码编译为高性能的机器码至关重要。

### 提示词
```
这是目录为v8/src/codegen/arm64/macro-assembler-arm64.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/arm64/macro-assembler-arm64.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```c
onst Register& temp);

  // Restore FP and LR from the values stored in the current frame. This will
  // authenticate the LR when pointer authentication is enabled.
  void RestoreFPAndLR();

#if V8_ENABLE_WEBASSEMBLY
  void StoreReturnAddressInWasmExitFrame(Label* return_location);
#endif  // V8_ENABLE_WEBASSEMBLY

  // Wasm helpers. These instructions don't have direct lowering
  // to native instructions. These helpers allow us to define the optimal code
  // sequence, and be used in both TurboFan and Liftoff.
  void PopcntHelper(Register dst, Register src);
  void I8x16BitMask(Register dst, VRegister src, VRegister temp = NoVReg);
  void I16x8BitMask(Register dst, VRegister src);
  void I32x4BitMask(Register dst, VRegister src);
  void I64x2BitMask(Register dst, VRegister src);
  void I64x2AllTrue(Register dst, VRegister src);

  // ---------------------------------------------------------------------------
  // V8 Sandbox support

  // Transform a SandboxedPointer from/to its encoded form, which is used when
  // the pointer is stored on the heap and ensures that the pointer will always
  // point into the sandbox.
  void DecodeSandboxedPointer(Register value);
  void LoadSandboxedPointerField(Register destination,
                                 MemOperand field_operand);
  void StoreSandboxedPointerField(Register value, MemOperand dst_field_operand);

  // Loads a field containing an off-heap ("external") pointer and does
  // necessary decoding if the sandbox is enabled.
  void LoadExternalPointerField(Register destination, MemOperand field_operand,
                                ExternalPointerTag tag,
                                Register isolate_root = Register::no_reg());

  // Load a trusted pointer field.
  // When the sandbox is enabled, these are indirect pointers using the trusted
  // pointer table. Otherwise they are regular tagged fields.
  void LoadTrustedPointerField(Register destination, MemOperand field_operand,
                               IndirectPointerTag tag);
  // Store a trusted pointer field.
  void StoreTrustedPointerField(Register value, MemOperand dst_field_operand);

  // Load a code pointer field.
  // These are special versions of trusted pointers that, when the sandbox is
  // enabled, reference code objects through the code pointer table.
  void LoadCodePointerField(Register destination, MemOperand field_operand) {
    LoadTrustedPointerField(destination, field_operand,
                            kCodeIndirectPointerTag);
  }
  // Store a code pointer field.
  void StoreCodePointerField(Register value, MemOperand dst_field_operand) {
    StoreTrustedPointerField(value, dst_field_operand);
  }

  // Load an indirect pointer field.
  // Only available when the sandbox is enabled, but always visible to avoid
  // having to place the #ifdefs into the caller.
  void LoadIndirectPointerField(Register destination, MemOperand field_operand,
                                IndirectPointerTag tag);

  // Store an indirect pointer field.
  // Only available when the sandbox is enabled, but always visible to avoid
  // having to place the #ifdefs into the caller.
  void StoreIndirectPointerField(Register value, MemOperand dst_field_operand);

#ifdef V8_ENABLE_SANDBOX
  // Retrieve the heap object referenced by the given indirect pointer handle,
  // which can either be a trusted pointer handle or a code pointer handle.
  void ResolveIndirectPointerHandle(Register destination, Register handle,
                                    IndirectPointerTag tag);

  // Retrieve the heap object referenced by the given trusted pointer handle.
  void ResolveTrustedPointerHandle(Register destination, Register handle,
                                   IndirectPointerTag tag);

  // Retrieve the Code object referenced by the given code pointer handle.
  void ResolveCodePointerHandle(Register destination, Register handle);

  // Load the pointer to a Code's entrypoint via a code pointer.
  // Only available when the sandbox is enabled as it requires the code pointer
  // table.
  void LoadCodeEntrypointViaCodePointer(Register destination,
                                        MemOperand field_operand,
                                        CodeEntrypointTag tag);
#endif

#ifdef V8_ENABLE_LEAPTIERING
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

  // Instruction set functions ------------------------------------------------
  // Logical macros.
  inline void Bics(const Register& rd, const Register& rn,
                   const Operand& operand);

  inline void Adcs(const Register& rd, const Register& rn,
                   const Operand& operand);
  inline void Sbc(const Register& rd, const Register& rn,
                  const Operand& operand);
  inline void Sbcs(const Register& rd, const Register& rn,
                   const Operand& operand);
  inline void Ngc(const Register& rd, const Operand& operand);
  inline void Ngcs(const Register& rd, const Operand& operand);

#define DECLARE_FUNCTION(FN, OP) \
  inline void FN(const Register& rs, const Register& rt, const Register& rn);
  STLX_MACRO_LIST(DECLARE_FUNCTION)
#undef DECLARE_FUNCTION

  // Branch type inversion relies on these relations.
  static_assert((reg_zero == (reg_not_zero ^ 1)) &&
                (reg_bit_clear == (reg_bit_set ^ 1)) &&
                (always == (never ^ 1)));

  inline void Bfxil(const Register& rd, const Register& rn, unsigned lsb,
                    unsigned width);
  inline void Cinc(const Register& rd, const Register& rn, Condition cond);
  inline void Cinv(const Register& rd, const Register& rn, Condition cond);
  inline void CzeroX(const Register& rd, Condition cond);
  inline void Csinv(const Register& rd, const Register& rn, const Register& rm,
                    Condition cond);
  inline void Csneg(const Register& rd, const Register& rn, const Register& rm,
                    Condition cond);
  inline void Extr(const Register& rd, const Register& rn, const Register& rm,
                   unsigned lsb);
  void Fcvtl2(const VRegister& vd, const VRegister& vn) {
    DCHECK(allow_macro_instructions());
    fcvtl2(vd, vn);
  }
  void Fcvtn2(const VRegister& vd, const VRegister& vn) {
    DCHECK(allow_macro_instructions());
    fcvtn2(vd, vn);
  }
  void Fcvtxn(const VRegister& vd, const VRegister& vn) {
    DCHECK(allow_macro_instructions());
    fcvtxn(vd, vn);
  }
  void Fcvtxn2(const VRegister& vd, const VRegister& vn) {
    DCHECK(allow_macro_instructions());
    fcvtxn2(vd, vn);
  }
  inline void Fmadd(const VRegister& fd, const VRegister& fn,
                    const VRegister& fm, const VRegister& fa);
  inline void Fmaxnm(const VRegister& fd, const VRegister& fn,
                     const VRegister& fm);
  inline void Fminnm(const VRegister& fd, const VRegister& fn,
                     const VRegister& fm);
  inline void Fmsub(const VRegister& fd, const VRegister& fn,
                    const VRegister& fm, const VRegister& fa);
  inline void Fnmadd(const VRegister& fd, const VRegister& fn,
                     const VRegister& fm, const VRegister& fa);
  inline void Fnmsub(const VRegister& fd, const VRegister& fn,
                     const VRegister& fm, const VRegister& fa);
  inline void Hint(SystemHint code);
  inline void Hlt(int code);
  inline void Ldnp(const CPURegister& rt, const CPURegister& rt2,
                   const MemOperand& src);
  inline void Movk(const Register& rd, uint64_t imm, int shift = -1);
  inline void Nop() { nop(); }
  void Mvni(const VRegister& vd, const int imm8, Shift shift = LSL,
            const int shift_amount = 0) {
    DCHECK(allow_macro_instructions());
    mvni(vd, imm8, shift, shift_amount);
  }
  inline void Smaddl(const Register& rd, const Register& rn, const Register& rm,
                     const Register& ra);
  inline void Smsubl(const Register& rd, const Register& rn, const Register& rm,
                     const Register& ra);
  inline void Stnp(const CPURegister& rt, const CPURegister& rt2,
                   const MemOperand& dst);
  inline void Umaddl(const Register& rd, const Register& rn, const Register& rm,
                     const Register& ra);
  inline void Umsubl(const Register& rd, const Register& rn, const Register& rm,
                     const Register& ra);

  void Ld1(const VRegister& vt, const MemOperand& src) {
    DCHECK(allow_macro_instructions());
    ld1(vt, src);
  }
  void Ld1(const VRegister& vt, const VRegister& vt2, const MemOperand& src) {
    DCHECK(allow_macro_instructions());
    ld1(vt, vt2, src);
  }
  void Ld1(const VRegister& vt, const VRegister& vt2, const VRegister& vt3,
           const MemOperand& src) {
    DCHECK(allow_macro_instructions());
    ld1(vt, vt2, vt3, src);
  }
  void Ld1(const VRegister& vt, const VRegister& vt2, const VRegister& vt3,
           const VRegister& vt4, const MemOperand& src) {
    DCHECK(allow_macro_instructions());
    ld1(vt, vt2, vt3, vt4, src);
  }
  void Ld1(const VRegister& vt, int lane, const MemOperand& src) {
    DCHECK(allow_macro_instructions());
    ld1(vt, lane, src);
  }
  void Ld1r(const VRegister& vt, const MemOperand& src) {
    DCHECK(allow_macro_instructions());
    ld1r(vt, src);
  }
  void Ld2(const VRegister& vt, const VRegister& vt2, const MemOperand& src) {
    DCHECK(allow_macro_instructions());
    ld2(vt, vt2, src);
  }
  void Ld2(const VRegister& vt, const VRegister& vt2, int lane,
           const MemOperand& src) {
    DCHECK(allow_macro_instructions());
    ld2(vt, vt2, lane, src);
  }
  void Ld2r(const VRegister& vt, const VRegister& vt2, const MemOperand& src) {
    DCHECK(allow_macro_instructions());
    ld2r(vt, vt2, src);
  }
  void Ld3(const VRegister& vt, const VRegister& vt2, const VRegister& vt3,
           const MemOperand& src) {
    DCHECK(allow_macro_instructions());
    ld3(vt, vt2, vt3, src);
  }
  void Ld3(const VRegister& vt, const VRegister& vt2, const VRegister& vt3,
           int lane, const MemOperand& src) {
    DCHECK(allow_macro_instructions());
    ld3(vt, vt2, vt3, lane, src);
  }
  void Ld3r(const VRegister& vt, const VRegister& vt2, const VRegister& vt3,
            const MemOperand& src) {
    DCHECK(allow_macro_instructions());
    ld3r(vt, vt2, vt3, src);
  }
  void Ld4(const VRegister& vt, const VRegister& vt2, const VRegister& vt3,
           const VRegister& vt4, const MemOperand& src) {
    DCHECK(allow_macro_instructions());
    ld4(vt, vt2, vt3, vt4, src);
  }
  void Ld4(const VRegister& vt, const VRegister& vt2, const VRegister& vt3,
           const VRegister& vt4, int lane, const MemOperand& src) {
    DCHECK(allow_macro_instructions());
    ld4(vt, vt2, vt3, vt4, lane, src);
  }
  void Ld4r(const VRegister& vt, const VRegister& vt2, const VRegister& vt3,
            const VRegister& vt4, const MemOperand& src) {
    DCHECK(allow_macro_instructions());
    ld4r(vt, vt2, vt3, vt4, src);
  }
  void St2(const VRegister& vt, const VRegister& vt2, const MemOperand& dst) {
    DCHECK(allow_macro_instructions());
    st2(vt, vt2, dst);
  }
  void St3(const VRegister& vt, const VRegister& vt2, const VRegister& vt3,
           const MemOperand& dst) {
    DCHECK(allow_macro_instructions());
    st3(vt, vt2, vt3, dst);
  }
  void St4(const VRegister& vt, const VRegister& vt2, const VRegister& vt3,
           const VRegister& vt4, const MemOperand& dst) {
    DCHECK(allow_macro_instructions());
    st4(vt, vt2, vt3, vt4, dst);
  }
  void St2(const VRegister& vt, const VRegister& vt2, int lane,
           const MemOperand& dst) {
    DCHECK(allow_macro_instructions());
    st2(vt, vt2, lane, dst);
  }
  void St3(const VRegister& vt, const VRegister& vt2, const VRegister& vt3,
           int lane, const MemOperand& dst) {
    DCHECK(allow_macro_instructions());
    st3(vt, vt2, vt3, lane, dst);
  }
  void St4(const VRegister& vt, const VRegister& vt2, const VRegister& vt3,
           const VRegister& vt4, int lane, const MemOperand& dst) {
    DCHECK(allow_macro_instructions());
    st4(vt, vt2, vt3, vt4, lane, dst);
  }
  void Tbx(const VRegister& vd, const VRegister& vn, const VRegister& vm) {
    DCHECK(allow_macro_instructions());
    tbx(vd, vn, vm);
  }
  void Tbx(const VRegister& vd, const VRegister& vn, const VRegister& vn2,
           const VRegister& vm) {
    DCHECK(allow_macro_instructions());
    tbx(vd, vn, vn2, vm);
  }
  void Tbx(const VRegister& vd, const VRegister& vn, const VRegister& vn2,
           const VRegister& vn3, const VRegister& vm) {
    DCHECK(allow_macro_instructions());
    tbx(vd, vn, vn2, vn3, vm);
  }
  void Tbx(const VRegister& vd, const VRegister& vn, const VRegister& vn2,
           const VRegister& vn3, const VRegister& vn4, const VRegister& vm) {
    DCHECK(allow_macro_instructions());
    tbx(vd, vn, vn2, vn3, vn4, vm);
  }

  inline void PushSizeRegList(RegList registers, unsigned reg_size) {
    PushCPURegList(CPURegList(reg_size, registers));
  }
  inline void PushSizeRegList(DoubleRegList registers, unsigned reg_size) {
    PushCPURegList(CPURegList(reg_size, registers));
  }
  inline void PopSizeRegList(RegList registers, unsigned reg_size) {
    PopCPURegList(CPURegList(reg_size, registers));
  }
  inline void PopSizeRegList(DoubleRegList registers, unsigned reg_size) {
    PopCPURegList(CPURegList(reg_size, registers));
  }
  inline void PushXRegList(RegList regs) {
    PushSizeRegList(regs, kXRegSizeInBits);
  }
  inline void PopXRegList(RegList regs) {
    PopSizeRegList(regs, kXRegSizeInBits);
  }
  inline void PushWRegList(RegList regs) {
    PushSizeRegList(regs, kWRegSizeInBits);
  }
  inline void PopWRegList(RegList regs) {
    PopSizeRegList(regs, kWRegSizeInBits);
  }
  inline void PushQRegList(DoubleRegList regs) {
    PushSizeRegList(regs, kQRegSizeInBits);
  }
  inline void PopQRegList(DoubleRegList regs) {
    PopSizeRegList(regs, kQRegSizeInBits);
  }
  inline void PushDRegList(DoubleRegList regs) {
    PushSizeRegList(regs, kDRegSizeInBits);
  }
  inline void PopDRegList(DoubleRegList regs) {
    PopSizeRegList(regs, kDRegSizeInBits);
  }
  inline void PushSRegList(DoubleRegList regs) {
    PushSizeRegList(regs, kSRegSizeInBits);
  }
  inline void PopSRegList(DoubleRegList regs) {
    PopSizeRegList(regs, kSRegSizeInBits);
  }

  // These PushAll/PopAll respect the order of the registers in the stack from
  // low index to high.
  void PushAll(RegList registers);
  void PopAll(RegList registers);

  inline void PushAll(DoubleRegList registers,
                      int stack_slot_size = kDoubleSize) {
    if (registers.Count() % 2 != 0) {
      DCHECK(!registers.has(fp_zero));
      registers.set(fp_zero);
    }
    PushDRegList(registers);
  }
  inline void PopAll(DoubleRegList registers,
                     int stack_slot_size = kDoubleSize) {
    if (registers.Count() % 2 != 0) {
      DCHECK(!registers.has(fp_zero));
      registers.set(fp_zero);
    }
    PopDRegList(registers);
  }

  // Push the specified register 'count' times.
  void PushMultipleTimes(CPURegister src, Register count);

  // Peek at two values on the stack, and put them in 'dst1' and 'dst2'. The
  // values peeked will be adjacent, with the value in 'dst2' being from a
  // higher address than 'dst1'. The offset is in bytes. The stack pointer must
  // be aligned to 16 bytes.
  void PeekPair(const CPURegister& dst1, const CPURegister& dst2, int offset);

  // Preserve the callee-saved registers (as defined by AAPCS64).
  //
  // Higher-numbered registers are pushed before lower-numbered registers, and
  // thus get higher addresses.
  // Floating-point registers are pushed before general-purpose registers, and
  // thus get higher addresses.
  //
  // When control flow integrity measures are enabled, this method signs the
  // link register before pushing it.
  //
  // Note that registers are not checked for invalid values. Use this method
  // only if you know that the GC won't try to examine the values on the stack.
  void PushCalleeSavedRegisters();

  // Restore the callee-saved registers (as defined by AAPCS64).
  //
  // Higher-numbered registers are popped after lower-numbered registers, and
  // thus come from higher addresses.
  // Floating-point registers are popped after general-purpose registers, and
  // thus come from higher addresses.
  //
  // When control flow integrity measures are enabled, this method
  // authenticates the link register after popping it.
  void PopCalleeSavedRegisters();

  // Tiering support.
  void AssertFeedbackCell(Register object,
                          Register scratch) NOOP_UNLESS_DEBUG_CODE;
  inline void AssertFeedbackVector(Register object);
  void AssertFeedbackVector(Register object,
                            Register scratch) NOOP_UNLESS_DEBUG_CODE;
  void ReplaceClosureCodeWithOptimizedCode(Register optimized_code,
                                           Register closure);
  void GenerateTailCallToReturnedCode(Runtime::FunctionId function_id);
#ifndef V8_ENABLE_LEAPTIERING
  Condition LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing(
      Register flags, Register feedback_vector, CodeKind current_code_kind);
  void LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
      Register flags, Register feedback_vector, CodeKind current_code_kind,
      Label* flags_need_processing);
  void OptimizeCodeOrTailCallOptimizedCodeSlot(Register flags,
                                               Register feedback_vector);
#endif  // !V8_ENABLE_LEAPTIERING

  // Helpers ------------------------------------------------------------------

  template <typename Field>
  void DecodeField(Register dst, Register src) {
    static const int shift = Field::kShift;
    static const int setbits = CountSetBits(Field::kMask, 32);
    Ubfx(dst, src, shift, setbits);
  }

  template <typename Field>
  void DecodeField(Register reg) {
    DecodeField<Field>(reg, reg);
  }

  void JumpIfCodeIsMarkedForDeoptimization(Register code, Register scratch,
                                           Label* if_marked_for_deoptimization);
  void JumpIfCodeIsTurbofanned(Register code, Register scratch,
                               Label* if_marked_for_deoptimization);
  Operand ClearedValue() const;

  Operand ReceiverOperand();

  // ---- SMI and Number Utilities ----

  inline void JumpIfNotSmi(Register value, Label* not_smi_label);

  // Abort execution if argument is not a Map, enabled via
  // --debug-code.
  void AssertMap(Register object) NOOP_UNLESS_DEBUG_CODE;

  // Abort execution if argument is not a Code, enabled via
  // --debug-code.
  void AssertCode(Register object) NOOP_UNLESS_DEBUG_CODE;

  // Abort execution if argument is not a Constructor, enabled via
  // --debug-code.
  void AssertConstructor(Register object) NOOP_UNLESS_DEBUG_CODE;

  // Abort execution if argument is not a JSFunction, enabled via
  // --debug-code.
  void AssertFunction(Register object) NOOP_UNLESS_DEBUG_CODE;

  // Abort execution if argument is not a callable JSFunction, enabled via
  // --debug-code.
  void AssertCallableFunction(Register object) NOOP_UNLESS_DEBUG_CODE;

  // Abort execution if argument is not a JSGeneratorObject (or subclass),
  // enabled via --debug-code.
  void AssertGeneratorObject(Register object) NOOP_UNLESS_DEBUG_CODE;

  // Abort execution if argument is not a JSBoundFunction,
  // enabled via --debug-code.
  void AssertBoundFunction(Register object) NOOP_UNLESS_DEBUG_CODE;

  // Abort execution if argument is not undefined or an AllocationSite,
  // enabled via --debug-code.
  void AssertUndefinedOrAllocationSite(Register object) NOOP_UNLESS_DEBUG_CODE;

  // Abort execution if argument is not smi nor in the pointer compresssion
  // cage, enabled via --debug-code.
  void AssertSmiOrHeapObjectInMainCompressionCage(Register object)
      NOOP_UNLESS_DEBUG_CODE;

  // ---- Calling / Jumping helpers ----

  void CallRuntime(const Runtime::Function* f, int num_arguments);

  // Convenience function: Same as above, but takes the fid instead.
  void CallRuntime(Runtime::FunctionId fid, int num_arguments) {
    CallRuntime(Runtime::FunctionForId(fid), num_arguments);
  }

  // Convenience function: Same as above, but takes the fid instead.
  void CallRuntime(Runtime::FunctionId fid) {
    const Runtime::Function* function = Runtime::FunctionForId(fid);
    CallRuntime(function, function->nargs);
  }

  void TailCallRuntime(Runtime::FunctionId fid);

  // Jump to a runtime routine.
  void JumpToExternalReference(const ExternalReference& builtin,
                               bool builtin_exit_frame = false);

  // Registers used through the invocation chain are hard-coded.
  // We force passing the parameters to ensure the contracts are correctly
  // honoured by the caller.
  // 'function' must be x1.
  // 'actual' must use an immediate or x0.
  // 'expected' must use an immediate or x2.
  // 'call_kind' must be x5.
  void InvokePrologue(Register expected_parameter_count,
                      Register actual_parameter_count, InvokeType type);

  // On function call, call into the debugger.
  void CallDebugOnFunctionCall(
      Register fun, Register new_target,
      Register expected_parameter_count_or_dispatch_handle,
      Register actual_parameter_count);

  // The way we invoke JSFunctions differs depending on whether leaptiering is
  // enabled. As such, these functions exist in two variants. In the future,
  // leaptiering will be used on all platforms. At that point, the
  // non-leaptiering variants will disappear.

#ifdef V8_ENABLE_LEAPTIERING
  // Invoke the JavaScript function in the given register. Changes the
  // current context to the context in the function before invoking.
  void InvokeFunction(Register function, Register actual_parameter_count,
                      InvokeType type,
                      ArgumentAdaptionMode argument_adaption_mode =
                          ArgumentAdaptionMode::kAdapt);
  // Invoke the JavaScript function in the given register.
  // Changes the current context to the context in the function before invoking.
  void InvokeFunctionWithNewTarget(Register function, Register new_target,
                                   Register actual_parameter_count,
                                   InvokeType type);
  // Invoke the JavaScript function code by either calling or jumping.
  void InvokeFunctionCode(Register function, Register new_target,
                          Register actual_parameter_count, InvokeType type,
                          ArgumentAdaptionMode argument_adaption_mode =
                              ArgumentAdaptionMode::kAdapt);
#else
  void InvokeFunctionCode(Register function, Register new_target,
                          Register expected_parameter_count,
                          Register actual_parameter_count, InvokeType type);
  // Invoke the JavaScript function in the given register.
  // Changes the current context to the context in the function before invoking.
  void InvokeFunctionWithNewTarget(Register function, Register new_target,
                                   Register actual_parameter_count,
                                   InvokeType type);
  void InvokeFunction(Register function, Register expected_parameter_count,
                      Register actual_parameter_count, InvokeType type);
#endif

  // ---- InstructionStream generation helpers ----

  // ---------------------------------------------------------------------------
  // Support functions.

  // Compare object type for heap object.  heap_object contains a non-Smi
  // whose object type should be compared with the given type.  This both
  // sets the flags and leaves the object type in the type_reg register.
  // It leaves the map in the map register (unless the type_reg and map register
  // are the same register).  It leaves the heap object in the heap_object
  // register unless the heap_object register is the same register as one of the
  // other registers.
  void CompareObjectType(Register heap_object, Register map, Register type_reg,
                         InstanceType type);
  // Variant of the above, which only guarantees to set the correct eq/ne flag.
  // Neither map, nor type_reg might be set to any particular value.
  void IsObjectType(Register heap_object, Register scratch1, Register scratch2,
                    InstanceType type);
  // Variant of the above, which compares against a type range rather than a
  // single type (lower_limit and higher_limit are inclusive).
  //
  // Always use unsigned comparisons: ls for a positive result.
  void IsObjectTypeInRange(Register heap_object, Register scratch,
                           InstanceType lower_limit, InstanceType higher_limit);
#if V8_STATIC_ROOTS_BOOL
  // Fast variant which is guaranteed to not actually load the instance type
  // from the map.
  void IsObjectTypeFast(Register heap_object, Register compressed_map_scratch,
                        InstanceType type);
  void CompareInstanceTypeWithUniqueCompressedMap(Register map,
                                                  Register scratch,
                                                  InstanceType type);
#endif  // V8_STATIC_ROOTS_BOOL

  // Compare object type for heap object, and branch if equal (or not.)
  // heap_object contains a non-Smi whose object type should be compared with
  // the given type.  This both sets the flags and leaves the object type in
  // the type_reg register. It leaves the map in the map register (unless the
  // type_reg and map register are the same register).  It leaves the heap
  // object in the heap_object register unless the heap_object register is the
  // same register as one of the other registers.
  void JumpIfObjectType(Register object, Register map, Register type_reg,
                        InstanceType type, Label* if_cond_pass,
                        Condition cond = eq);

  // Fast check if the object is a js receiver type. Assumes only primitive
  // objects or js receivers are passed.
  void JumpIfJSAnyIsNotPrimitive(
      Register heap_object, Register scratch, Label* target,
      Label::Distance distance = Label::kFar,
      Condition condition = Condition::kUnsignedGreaterThanEqual);
  void JumpIfJSAnyIsPrimitive(Register heap_object, Register scratch,
                              Label* target,
                              Label::Distance distance = Label::kFar) {
    return JumpIfJSAnyIsNotPrimitive(heap_object, scratch, target, distance,
                                     Condition::kUnsignedLessThan);
  }

  // Compare instance type in a map.  map contains a valid map object whose
  // object type should be compared with the given type.  This both
  // sets the flags and leaves the object type in the type_reg register.
  void CompareInstanceType(Register map, Register type_reg, InstanceType type);

  // Compare instance type ranges for a map (lower_limit and higher_limit
  // inclusive).
  //
  // Always use unsigned comparisons: ls for a positive result.
  void CompareInstanceTypeRange(Register map, Register type_reg,
                                InstanceType lower_limit,
                                InstanceType higher_limit);

  // Load the elements kind field from a map, and return it in the result
  // register.
  void LoadElementsKindFromMap(Register result, Register map);

  // Compare the object in a register to a value from the root list.
  void CompareRoot(const Register& obj, RootIndex index,
                   ComparisonMode mode = ComparisonMode::kDefault);
  void CompareTaggedRoot(const Register& with, RootIndex index);

  // Compare the object in a register to a value and jump if they are equal.
  void JumpIfRoot(const Register& obj, RootIndex index, Label* if_equal);

  // Compare the object in a register to a value and jump if they are not equal.
  void JumpIfNotRoot(const Register& obj, RootIndex index, Label* if_not_equal);

  // Checks if value is in range [lower_limit, higher_limit] using a single
  // comparison.
  void JumpIfIsInRange(const Register& value, unsigned lower_limit,
                       unsigned higher_limit, Label* on_in_range);

  // ---------------------------------------------------------------------------
  // Frames.

  // Enter exit frame. Exit frames are used when calling C code from generated
  // (JavaScript) code.
  //
  // The only registers modified by this function are the provided scratch
  // register, the frame pointer and the stack pointer.
  //
  // The 'extra_space' argument can be used to allocate some space in the exit
  // frame that will be ignored by the GC. This space will be reserved in the
  // bottom of the frame immediately above the return address slot.
  //
  // Set up a stack frame and registers as follows:
  //         fp[8]: CallerPC (lr)
  //   fp -> fp[0]: CallerFP (old fp)
  //         fp[-8]: SPOffset (new sp)
  //         fp[-16]: CodeObject()
  //         fp[-16 - fp-size]: Saved doubles, if saved_doubles is true.
  //         sp[8]: Memory reserved for the caller if extra_space != 0.
  //                 Alignment padding, if necessary.
  //   sp -> sp[0]: Space reserved for the return address.
  //
  // This function also stores the new frame information in the top frame, so
  // that the new frame becomes the current frame.
  void EnterExitFrame(const Register& scratch, int extra_space,
                      StackFrame::Type frame_type);

  // Leave the current exit frame, after a C function has returned to generated
  // (JavaScript) code.
  //
  // This effectively unwinds the operation of EnterExitFrame:
  //  * The frame information is removed from the top frame.
  //  * The exit frame is dropped.
  void LeaveExitFrame(const Register& scratch, const Register& scratch2);

  // Load the global proxy from the current context.
  void LoadGlobalProxy(Register dst);

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
    EmitIncrementCounter(counter, -value, scratch1, scratch2);
  }

  // ---------------------------------------------------------------------------
  // Stack limit utilities
  void LoadStackLimit(Register destination, StackLimitKind kind);
  void StackOverflowCheck(Register num_args, Label* stack_overflow);

  // ---------------------------------------------------------------------------
  // Garbage collector support (GC).

  // Notify the garbage collector that we wrote a pointer into an object.
  // |object| is the object being stored into, |value| is the object being
  // stored.
  // The offset is the offset from the start of the object, not the offset from
  // the tagged HeapObject pointer.  For use with FieldMemOperand(reg, off).
  void RecordWriteField(
      Register object, int offset, Register value, LinkRegisterStatus lr_status,
      SaveFPRegsMode save_fp, SmiCheck smi_check = SmiCheck::kInline,
      ReadOnlyCheck ro_check = ReadOnlyCheck::kInline,
      SlotDescriptor slot = SlotDescriptor::ForDirectPointerSlot());

  // For a given |object| notify the garbage collector that the slot at |offset|
  // has been written. |value| is the object being stored.
  void RecordWrite(
      Register object, Operand offset, Register value,
      LinkRegisterStatus lr_status, SaveFPRegsMode save_fp,
      SmiCheck smi_check = SmiCheck::kInline,
      ReadOnlyCheck r
```