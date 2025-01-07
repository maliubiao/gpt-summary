Response:
My thinking process to arrive at the summary of the provided C++ header file went through these steps:

1. **Initial Scan and Keyword Spotting:** I quickly scanned the code, looking for recurring patterns and keywords. The prevalence of `void`, register names (like `Register`, `XMMRegister`, `YMMRegister`), instruction mnemonics (like `mov`, `add`, `jmp`, `call`, `test`, etc.), and macros like `SHIFT_INSTRUCTION_LIST`, `SSE_INSTRUCTION_LIST`, etc., immediately stood out. This hinted at the file's purpose: defining functions that represent x64 assembly instructions.

2. **Identifying Core Functionality:** The consistent structure of many functions taking registers, operands, and immediate values as arguments, and their naming convention closely resembling x64 assembly instructions, strongly suggested that this file is responsible for *generating x64 machine code*. The `Assembler` class name in the header file (from the file path, although not explicitly in the provided snippet) further reinforces this.

3. **Categorizing Instruction Types:** I noticed groups of instructions related to specific operations:
    * **Arithmetic:** `add`, `sub`, `imul`, `idiv`, `inc`, `dec`, `neg`.
    * **Logical/Bitwise:** `and`, `or`, `xor`, `not`, `test`, `shl`, `shr`, `rol`, `ror`, `bsr`, `bsf`.
    * **Data Movement:** `mov`, `lea`, `push`, `pop`.
    * **Control Flow:** `jmp`, `call`, `ret`, `j` (conditional jumps), `bind` (for labels).
    * **Floating-Point:** Instructions starting with `f` (like `fld`, `fstp`, `fadd`, `fmul`).
    * **SSE/AVX:** Instructions involving `XMMRegister` and `YMMRegister`, like `movaps`, `movss`, `paddd`, `vaddps`. The macros like `SSE_INSTRUCTION_LIST` clearly indicate a systematic way of defining these instructions.

4. **Recognizing Macro Usage:** The presence of macros like `SHIFT_INSTRUCTION_LIST`, `SSE_UNOP_INSTRUCTION_LIST`, `SSE_BINOP_INSTRUCTION_LIST`, etc., indicated a code generation pattern. These macros likely expand to define multiple similar instruction variants with different operand types and sizes. This is a common technique in assemblers to avoid repetitive code.

5. **Inferring Helper Functions:** Functions like `shift`, `immediate_arithmetic_op_8`, `AlignForJCCErratum`, and `vinstr` appeared to be internal helper functions used to implement the core instruction generation logic. They encapsulate common tasks or handle specific encoding details.

6. **Identifying Architecture-Specific Features:** The presence of instructions related to SSE, AVX, and mitigations for the "JCC erratum" pointed to the x64-specific nature of this code. These are instruction set extensions and hardware quirks specific to the x86-64 architecture.

7. **Considering the Context:** Knowing that this is part of V8's code generation pipeline, I understood that this `Assembler` class is used to translate V8's internal representation of code into actual machine instructions that the processor can execute.

8. **Formulating the Summary:** Based on the above observations, I formulated the summary by highlighting the core function: generating x64 machine code. I then listed the key categories of instructions supported and mentioned the use of macros and helper functions. I also included the architecture-specific nature and the context within V8's code generation.

9. **Addressing Specific Questions (as part of the original prompt):**

    * **`.tq` extension:** I correctly identified that this header file is a C++ header (`.h`) and not a Torque file (`.tq`).
    * **Relationship to JavaScript:** I recognized that while this C++ code doesn't directly contain JavaScript, it's crucial for *executing* JavaScript. V8 compiles JavaScript code into machine code using components like this assembler. My JavaScript example illustrated a simple operation that would likely involve some of the assembly instructions defined in the header.
    * **Code Logic and Examples:**  I provided examples for shift instructions, demonstrating how different operand types are handled. The input/output examples showed how a shift operation affects the register's value.
    * **Common Programming Errors:** I provided an example of an out-of-bounds shift, a typical error when working with bitwise operations.

Essentially, I performed a top-down analysis, starting with the overall purpose and then diving into the details of the instructions and helper functions, while keeping the context of V8's code generation in mind. The combination of keyword recognition, pattern identification, and contextual understanding allowed me to accurately summarize the functionality of the provided code snippet.
这是提供的 v8/src/codegen/x64/assembler-x64.h 文件的一部分内容。基于这段代码，我们可以归纳一下它的功能：

**功能归纳：**

这段代码定义了 `Assembler` 类中用于生成 x64 汇编代码的指令方法。它提供了多种指令的接口，涵盖了以下几个方面：

1. **移位指令 (Shift Instructions):**
   - 定义了各种移位操作的指令，例如逻辑左移、逻辑右移、算术左移、算术右移。
   - 提供了操作不同大小的数据（32位和64位）以及不同操作数类型（寄存器和内存操作数）的指令变体。
   - 包括使用立即数作为移位量和使用 `cl` 寄存器作为移位量的版本。
   - 包含双精度移位指令 `shld` 和 `shrd`。

2. **存储指令 (Store Instruction):**
   - 提供了将 `rax` 寄存器的值存储到指定内存地址的指令 `store_rax`。

3. **减法指令 (Subtraction Instruction):**
   - 提供了从寄存器中减去立即数的 8 位减法指令 `subb`。
   - 提供了用于调整栈指针 `sp` 的 `sub_sp_32` 指令。

4. **测试指令 (Test Instructions):**
   - 定义了多种 `test` 指令，用于执行按位与操作并设置标志位，但不修改操作数。
   - 提供了操作寄存器和立即数、内存操作数和立即数、内存操作数和寄存器等不同组合的指令。
   - 包含了用于缓解 Intel JCC erratum 性能问题的对齐版本 (`aligned_testb`, `aligned_testw`)。

5. **位操作指令 (Bit Operations):**
   - 提供了各种位操作指令，例如位交换 (`bswapl`, `bswapq`)，位测试 (`btq`)，位设置 (`btsq`)，位清除 (`btrq`)，前导零/一扫描 (`bsrq`, `bsrl`, `bsfq`, `bsfl`)。

6. **杂项指令 (Miscellaneous Instructions):**
   - 提供了其他常用的汇编指令，例如清除进位标志 (`clc`)，清除方向标志 (`cld`)，执行 CPUID 指令 (`cpuid`)，暂停执行 (`hlt`)，触发断点 (`int3`)，空操作 (`nop`)，返回 (`ret`)，未定义指令 (`ud2`)，根据条件码设置字节 (`setcc`)，以及用于控制流保护的 `endbr64`。

7. **SIMD 指令 (SSE/AVX Instructions):**
   - 提供了部分 SSE 和 AVX 指令，用于并行处理数据。
   - 包括 `pblendw` (字混合)，`palignr` (对齐和提取)，以及 `vpermq` (YMM 寄存器置换)。

8. **标签和跳转操作 (Label & Jump Operations):**
   - 提供了用于定义和绑定标签 (`bind`) 的功能。
   - 提供了近调用 (`call`) 和近跳转 (`jmp`) 指令，可以跳转到标签或指定的偏移地址。
   - 包括条件跳转指令 (`j`) 和用于缓解 JCC erratum 的对齐版本 (`aligned_jmp`, `aligned_j`)。

9. **浮点操作指令 (Floating-Point Operations):**
   - 提供了一系列传统的 x87 浮点指令，例如加载 (`fld`)，存储 (`fstp`)，加法 (`fadd`)，减法 (`fsub`)，乘法 (`fmul`)，除法 (`fdiv`)，比较 (`fucomp`) 等。

10. **SSE/AVX 浮点和整数操作指令:**
    - 提供了大量的 SSE 和 AVX 指令，用于操作 XMM 和 YMM 寄存器中的浮点数和整数。
    - 包括数据移动 (`movaps`, `movss`, `movd`, `movq`)，类型转换 (`cvttss2si`, `cvtlsi2ss`)，算术运算 (`haddps`)，比较 (`cmpeqsd`)，位操作 (`pmovmskb`)，以及其他各种 SIMD 操作。
    - 通过宏定义 (`DECLARE_SSE_INSTRUCTION`, `DECLARE_SSE2_INSTRUCTION` 等) 大量生成 SSE/AVX 指令的接口。

**关于代码的推断：**

* **假设输入与输出 (对于移位指令):**
    * **假设输入:**
        * `dst` 寄存器存储值 `0x12345678` (32位) 或 `0x123456789ABCDEF0` (64位)。
        * `imm8` 立即数为 `0x04` (表示移位 4 位)。
    * **输出 (以 `shll` 为例):**
        * `dst` 寄存器中的值变为 `0x23456780` (32位) 或 `0x23456789ABCDEF00` (64位)。

* **用户常见的编程错误 (与移位指令相关):**
    * **移位量过大:**  如果 `imm8` 的值大于操作数的大小（例如，对 32 位寄存器移位 32 位或更多），结果将是未定义的，通常由硬件决定，可能不会得到预期的零或符号位扩展。
    * **例如 (JavaScript 模拟):**
      ```javascript
      let num32 = 0x12345678;
      let shiftAmount = 32; // 错误：移位量等于数据大小
      let result32 = num32 << shiftAmount;
      console.log(result32); // 预期可能为 0，但实际行为取决于硬件

      let num64 = 0x123456789ABCDEF0n;
      shiftAmount = 64; // 错误：移位量等于数据大小
      let result64 = num64 << shiftAmount;
      console.log(result64); // 预期可能为 0n，但实际行为取决于硬件
      ```

**关于文件类型：**

您提供的代码片段是 C++ 头文件代码，以 `.h` 结尾。您提到如果以 `.tq` 结尾，则是 v8 Torque 源代码。 这段代码是 C++， 用于定义汇编器的接口。

**与 JavaScript 的关系：**

这个头文件定义的 `Assembler` 类是 V8 引擎中用于将 JavaScript 代码编译成机器码的关键组件。当 V8 执行 JavaScript 代码时，它会将 JavaScript 代码转换成一种中间表示，然后使用像 `assembler-x64.h` 中定义的指令来生成目标机器的汇编代码，最终由 CPU 执行。

**JavaScript 示例:**

一个简单的 JavaScript 加法运算，在 V8 的底层编译过程中，可能会涉及到这里定义的一些汇编指令，例如 `mov` 将数据加载到寄存器，`add` 执行加法操作，然后再用 `mov` 将结果存储回内存或寄存器。

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
console.log(result); // 输出 15
```

在 V8 的编译过程中，`a` 和 `b` 的值可能会被加载到寄存器中，然后使用类似于 `addl` 或 `addq` (取决于数据类型) 的指令进行加法运算。

**总结第 2 部分的功能：**

总而言之，这段代码是 `v8/src/codegen/x64/assembler-x64.h` 文件的一部分，它详细定义了 `Assembler` 类能够生成的各种 x64 汇编指令的 C++ 接口。 这些指令涵盖了数据操作、算术运算、逻辑运算、控制流、浮点运算以及 SIMD 操作，是 V8 引擎将 JavaScript 代码编译成可执行机器码的核心组成部分。 尤其需要注意的是，这里包含了大量的 SSE 和 AVX 指令的定义，这对于 JavaScript 中处理数值计算和多媒体等高性能场景至关重要。

Prompt: 
```
这是目录为v8/src/codegen/x64/assembler-x64.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/x64/assembler-x64.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
de)                     \
  void instruction##l(Register dst, Immediate imm8) {                       \
    shift(dst, imm8, subcode, kInt32Size);                                  \
  }                                                                         \
                                                                            \
  void instruction##q(Register dst, Immediate imm8) {                       \
    shift(dst, imm8, subcode, kInt64Size);                                  \
  }                                                                         \
                                                                            \
  void instruction##l(Operand dst, Immediate imm8) {                        \
    shift(dst, imm8, subcode, kInt32Size);                                  \
  }                                                                         \
                                                                            \
  void instruction##q(Operand dst, Immediate imm8) {                        \
    shift(dst, imm8, subcode, kInt64Size);                                  \
  }                                                                         \
                                                                            \
  void instruction##l_cl(Register dst) { shift(dst, subcode, kInt32Size); } \
                                                                            \
  void instruction##q_cl(Register dst) { shift(dst, subcode, kInt64Size); } \
                                                                            \
  void instruction##l_cl(Operand dst) { shift(dst, subcode, kInt32Size); }  \
                                                                            \
  void instruction##q_cl(Operand dst) { shift(dst, subcode, kInt64Size); }
  SHIFT_INSTRUCTION_LIST(DECLARE_SHIFT_INSTRUCTION)
#undef DECLARE_SHIFT_INSTRUCTION

  // Shifts dst:src left by cl bits, affecting only dst.
  void shld(Register dst, Register src);

  // Shifts src:dst right by cl bits, affecting only dst.
  void shrd(Register dst, Register src);

  void store_rax(Address dst, RelocInfo::Mode mode);
  void store_rax(ExternalReference ref);

  void subb(Register dst, Immediate src) {
    immediate_arithmetic_op_8(0x5, dst, src);
  }

  void sub_sp_32(uint32_t imm);

  void testb(Register dst, Register src);
  // Used for JCC erratum performance mitigation.
  void aligned_testb(Register dst, Register src) {
    DCHECK(CpuFeatures::IsSupported(INTEL_JCC_ERRATUM_MITIGATION));
    // /* test */ 3 + /* jcc */ 6
    const int kMaxMacroFusionLength = 9;
    AlignForJCCErratum(kMaxMacroFusionLength);
    testb(dst, src);
  }

  void testb(Register reg, Immediate mask);
  // Used for JCC erratum performance mitigation.
  void aligned_testb(Register reg, Immediate mask) {
    DCHECK(CpuFeatures::IsSupported(INTEL_JCC_ERRATUM_MITIGATION));
    // /* test */ 4 + /* jcc */ 6
    const int kMaxMacroFusionLength = 10;
    AlignForJCCErratum(kMaxMacroFusionLength);
    testb(reg, mask);
  }

  void testb(Operand op, Immediate mask);
  // Used for JCC erratum performance mitigation.
  void aligned_testb(Operand op, Immediate mask) {
    DCHECK(CpuFeatures::IsSupported(INTEL_JCC_ERRATUM_MITIGATION));
    // test can not be fused when comparing MEM-IMM, so we would not align this
    // instruction.
    testb(op, mask);
  }

  void testb(Operand op, Register reg);
  // Used for JCC erratum performance mitigation.
  void aligned_testb(Operand op, Register reg) {
    DCHECK(CpuFeatures::IsSupported(INTEL_JCC_ERRATUM_MITIGATION));
    // /* test */ 8 + /* jcc */ 6
    const int kMaxMacroFusionLength = 14;
    AlignForJCCErratum(kMaxMacroFusionLength);
    testb(op, reg);
  }

  void testw(Register dst, Register src);
  // Used for JCC erratum performance mitigation.
  void aligned_testw(Register dst, Register src) {
    DCHECK(CpuFeatures::IsSupported(INTEL_JCC_ERRATUM_MITIGATION));
    // /* test */ 4 + /* jcc */ 6
    const int kMaxMacroFusionLength = 10;
    AlignForJCCErratum(kMaxMacroFusionLength);
    testw(dst, src);
  }

  void testw(Register reg, Immediate mask);
  // Used for JCC erratum performance mitigation.
  void aligned_testw(Register reg, Immediate mask) {
    DCHECK(CpuFeatures::IsSupported(INTEL_JCC_ERRATUM_MITIGATION));
    // /* test */ 6 + /* jcc */ 6
    const int kMaxMacroFusionLength = 12;
    AlignForJCCErratum(kMaxMacroFusionLength);
    testw(reg, mask);
  }

  void testw(Operand op, Immediate mask);
  // Used for JCC erratum performance mitigation.
  void aligned_testw(Operand op, Immediate mask) {
    DCHECK(CpuFeatures::IsSupported(INTEL_JCC_ERRATUM_MITIGATION));
    // test can not be fused when comparing MEM-IMM, so we would not align this
    // instruction.
    testw(op, mask);
  }

  void testw(Operand op, Register reg);
  // Used for JCC erratum performance mitigation.
  void aligned_testw(Operand op, Register reg) {
    DCHECK(CpuFeatures::IsSupported(INTEL_JCC_ERRATUM_MITIGATION));
    // /* test */ 9 + /* jcc */ 6
    const int kMaxMacroFusionLength = 15;
    AlignForJCCErratum(kMaxMacroFusionLength);
    testw(op, reg);
  }

  // Bit operations.
  void bswapl(Register dst);
  void bswapq(Register dst);
  void btq(Operand dst, Register src);
  void btsq(Operand dst, Register src);
  void btsq(Register dst, Immediate imm8);
  void btrq(Register dst, Immediate imm8);
  void bsrq(Register dst, Register src);
  void bsrq(Register dst, Operand src);
  void bsrl(Register dst, Register src);
  void bsrl(Register dst, Operand src);
  void bsfq(Register dst, Register src);
  void bsfq(Register dst, Operand src);
  void bsfl(Register dst, Register src);
  void bsfl(Register dst, Operand src);

  // Miscellaneous
  void clc();
  void cld();
  void cpuid();
  void hlt();
  void int3();
  void nop();
  void ret(int imm16);
  void ud2();
  void setcc(Condition cc, Register reg);
  void endbr64();

  void pblendw(XMMRegister dst, Operand src, uint8_t mask);
  void pblendw(XMMRegister dst, XMMRegister src, uint8_t mask);
  void palignr(XMMRegister dst, Operand src, uint8_t mask);
  void palignr(XMMRegister dst, XMMRegister src, uint8_t mask);

  void vpermq(YMMRegister dst, Operand src, uint8_t imm8) {
    vinstr(0x0, dst, ymm0, src, k66, k0F3A, kW1, AVX2);
    emit(imm8);
  }
  void vpermq(YMMRegister dst, YMMRegister src, uint8_t imm8) {
    vinstr(0x0, dst, ymm0, src, k66, k0F3A, kW1, AVX2);
    emit(imm8);
  }

  // Label operations & relative jumps (PPUM Appendix D)
  //
  // Takes a branch opcode (cc) and a label (L) and generates
  // either a backward branch or a forward branch and links it
  // to the label fixup chain. Usage:
  //
  // Label L;    // unbound label
  // j(cc, &L);  // forward branch to unbound label
  // bind(&L);   // bind label to the current pc
  // j(cc, &L);  // backward branch to bound label
  // bind(&L);   // illegal: a label may be bound only once
  //
  // Note: The same Label can be used for forward and backward branches
  // but it may be bound only once.

  void bind(Label* L);  // binds an unbound label L to the current code position

  // Calls
  // Call near relative 32-bit displacement, relative to next instruction.
  void call(Label* L);

  // Explicitly emit a near call / near jump. The displacement is relative to
  // the next instructions (which starts at
  // {pc_offset() + kIntraSegmentJmpInstrSize}).
  static constexpr int kIntraSegmentJmpInstrSize = 5;
  void near_call(intptr_t disp, RelocInfo::Mode rmode);
  void near_call(Builtin buitin, RelocInfo::Mode rmode);
  void near_jmp(intptr_t disp, RelocInfo::Mode rmode);
  void near_j(Condition cc, intptr_t disp, RelocInfo::Mode rmode);

  void call(Handle<Code> target,
            RelocInfo::Mode rmode = RelocInfo::CODE_TARGET);

  // Call near absolute indirect, address in register
  void call(Register adr);

  // Jumps
  // Jump short or near relative.
  // Use a 32-bit signed displacement.
  // Unconditional jump to L
  void jmp(Label* L, Label::Distance distance = Label::kFar);
  // Used for JCC erratum performance mitigation.
  void aligned_jmp(Label* L, Label::Distance distance = Label::kFar) {
    DCHECK(CpuFeatures::IsSupported(INTEL_JCC_ERRATUM_MITIGATION));
    const int kInstLength = distance == Label::kFar ? 6 : 2;
    AlignForJCCErratum(kInstLength);
    jmp(L, distance);
  }
  void jmp(Handle<Code> target, RelocInfo::Mode rmode);

  // Jump near absolute indirect (r64)
  // With notrack, add an optional prefix to disable CET IBT enforcement for
  // this jump.
  void jmp(Register adr, bool notrack = false);
  void jmp(Operand src, bool notrack = false);

  // Unconditional jump relative to the current address. Low-level routine,
  // use with caution!
  void jmp_rel(int offset);

  // Conditional jumps
  void j(Condition cc, Label* L, Label::Distance distance = Label::kFar);
  // Used for JCC erratum performance mitigation.
  void aligned_j(Condition cc, Label* L,
                 Label::Distance distance = Label::kFar) {
    DCHECK(CpuFeatures::IsSupported(INTEL_JCC_ERRATUM_MITIGATION));
    const int kInstLength = distance == Label::kFar ? 6 : 2;
    AlignForJCCErratum(kInstLength);
    j(cc, L, distance);
  }
  void j(Condition cc, Address entry, RelocInfo::Mode rmode);
  void j(Condition cc, Handle<Code> target, RelocInfo::Mode rmode);

  // Floating-point operations
  void fld(int i);

  void fld1();
  void fldz();
  void fldpi();
  void fldln2();

  void fld_s(Operand adr);
  void fld_d(Operand adr);

  void fstp_s(Operand adr);
  void fstp_d(Operand adr);
  void fstp(int index);

  void fild_s(Operand adr);
  void fild_d(Operand adr);

  void fist_s(Operand adr);

  void fistp_s(Operand adr);
  void fistp_d(Operand adr);

  void fisttp_s(Operand adr);
  void fisttp_d(Operand adr);

  void fabs();
  void fchs();

  void fadd(int i);
  void fsub(int i);
  void fmul(int i);
  void fdiv(int i);

  void fisub_s(Operand adr);

  void faddp(int i = 1);
  void fsubp(int i = 1);
  void fsubrp(int i = 1);
  void fmulp(int i = 1);
  void fdivp(int i = 1);
  void fprem();
  void fprem1();

  void fxch(int i = 1);
  void fincstp();
  void ffree(int i = 0);

  void ftst();
  void fucomp(int i);
  void fucompp();
  void fucomi(int i);
  void fucomip();

  void fcompp();
  void fnstsw_ax();
  void fwait();
  void fnclex();

  void fsin();
  void fcos();
  void fptan();
  void fyl2x();
  void f2xm1();
  void fscale();
  void fninit();

  void frndint();

  void sahf();

  void ucomiss(XMMRegister dst, XMMRegister src);
  void ucomiss(XMMRegister dst, Operand src);
  void movaps(XMMRegister dst, XMMRegister src);
  void movaps(XMMRegister dst, Operand src);

  // Don't use this unless it's important to keep the
  // top half of the destination register unchanged.
  // Use movaps when moving float values and movd for integer
  // values in xmm registers.
  void movss(XMMRegister dst, XMMRegister src);

  void movss(XMMRegister dst, Operand src);
  void movss(Operand dst, XMMRegister src);

  void movlps(XMMRegister dst, Operand src);
  void movlps(Operand dst, XMMRegister src);

  void movhps(XMMRegister dst, Operand src);
  void movhps(Operand dst, XMMRegister src);

  void shufps(XMMRegister dst, XMMRegister src, uint8_t imm8);

  void cvttss2si(Register dst, Operand src);
  void cvttss2si(Register dst, XMMRegister src);
  void cvtlsi2ss(XMMRegister dst, Operand src);
  void cvtlsi2ss(XMMRegister dst, Register src);

  void movmskps(Register dst, XMMRegister src);

  void vinstr(uint8_t op, XMMRegister dst, XMMRegister src1, XMMRegister src2,
              SIMDPrefix pp, LeadingOpcode m, VexW w, CpuFeature feature = AVX);
  void vinstr(uint8_t op, XMMRegister dst, XMMRegister src1, Operand src2,
              SIMDPrefix pp, LeadingOpcode m, VexW w, CpuFeature feature = AVX);

  template <typename Reg1, typename Reg2, typename Op>
  void vinstr(uint8_t op, Reg1 dst, Reg2 src1, Op src2, SIMDPrefix pp,
              LeadingOpcode m, VexW w, CpuFeature feature = AVX2);

  // SSE instructions
  void sse_instr(XMMRegister dst, XMMRegister src, uint8_t escape,
                 uint8_t opcode);
  void sse_instr(XMMRegister dst, Operand src, uint8_t escape, uint8_t opcode);
#define DECLARE_SSE_INSTRUCTION(instruction, escape, opcode) \
  void instruction(XMMRegister dst, XMMRegister src) {       \
    sse_instr(dst, src, 0x##escape, 0x##opcode);             \
  }                                                          \
  void instruction(XMMRegister dst, Operand src) {           \
    sse_instr(dst, src, 0x##escape, 0x##opcode);             \
  }

  SSE_UNOP_INSTRUCTION_LIST(DECLARE_SSE_INSTRUCTION)
  SSE_BINOP_INSTRUCTION_LIST(DECLARE_SSE_INSTRUCTION)
#undef DECLARE_SSE_INSTRUCTION

  // SSE instructions with prefix and SSE2 instructions
  void sse2_instr(XMMRegister dst, XMMRegister src, uint8_t prefix,
                  uint8_t escape, uint8_t opcode);
  void sse2_instr(XMMRegister dst, Operand src, uint8_t prefix, uint8_t escape,
                  uint8_t opcode);
#define DECLARE_SSE2_INSTRUCTION(instruction, prefix, escape, opcode) \
  void instruction(XMMRegister dst, XMMRegister src) {                \
    sse2_instr(dst, src, 0x##prefix, 0x##escape, 0x##opcode);         \
  }                                                                   \
  void instruction(XMMRegister dst, Operand src) {                    \
    sse2_instr(dst, src, 0x##prefix, 0x##escape, 0x##opcode);         \
  }

  // These SSE instructions have the same encoding as the SSE2 instructions.
  SSE_INSTRUCTION_LIST_SS(DECLARE_SSE2_INSTRUCTION)
  SSE2_INSTRUCTION_LIST(DECLARE_SSE2_INSTRUCTION)
  SSE2_INSTRUCTION_LIST_SD(DECLARE_SSE2_INSTRUCTION)
  SSE2_UNOP_INSTRUCTION_LIST(DECLARE_SSE2_INSTRUCTION)
#undef DECLARE_SSE2_INSTRUCTION

  void sse2_instr(XMMRegister reg, uint8_t imm8, uint8_t prefix, uint8_t escape,
                  uint8_t opcode, int extension) {
    XMMRegister ext_reg = XMMRegister::from_code(extension);
    sse2_instr(ext_reg, reg, prefix, escape, opcode);
    emit(imm8);
  }

#define DECLARE_SSE2_SHIFT_IMM(instruction, prefix, escape, opcode, extension) \
  void instruction(XMMRegister reg, uint8_t imm8) {                            \
    sse2_instr(reg, imm8, 0x##prefix, 0x##escape, 0x##opcode, 0x##extension);  \
  }
  SSE2_INSTRUCTION_LIST_SHIFT_IMM(DECLARE_SSE2_SHIFT_IMM)
#undef DECLARE_SSE2_SHIFT_IMM

#define DECLARE_SSE2_AVX_INSTRUCTION(instruction, prefix, escape, opcode)    \
  void v##instruction(XMMRegister dst, XMMRegister src1, XMMRegister src2) { \
    vinstr(0x##opcode, dst, src1, src2, k##prefix, k##escape, kW0);          \
  }                                                                          \
  void v##instruction(XMMRegister dst, XMMRegister src1, Operand src2) {     \
    vinstr(0x##opcode, dst, src1, src2, k##prefix, k##escape, kW0);          \
  }

#define DECLARE_SSE2_PD_AVX_INSTRUCTION(instruction, prefix, escape, opcode) \
  DECLARE_SSE2_AVX_INSTRUCTION(instruction, prefix, escape, opcode)          \
  void v##instruction(YMMRegister dst, YMMRegister src1, YMMRegister src2) { \
    vinstr(0x##opcode, dst, src1, src2, k##prefix, k##escape, kW0, AVX);     \
  }                                                                          \
  void v##instruction(YMMRegister dst, YMMRegister src1, Operand src2) {     \
    vinstr(0x##opcode, dst, src1, src2, k##prefix, k##escape, kW0, AVX);     \
  }

  SSE2_INSTRUCTION_LIST_PD(DECLARE_SSE2_PD_AVX_INSTRUCTION)
#undef DECLARE_SSE2_PD_AVX_INSTRUCTION

#define DECLARE_SSE2_PI_AVX_INSTRUCTION(instruction, prefix, escape, opcode) \
  DECLARE_SSE2_AVX_INSTRUCTION(instruction, prefix, escape, opcode)          \
  void v##instruction(YMMRegister dst, YMMRegister src1, YMMRegister src2) { \
    vinstr(0x##opcode, dst, src1, src2, k##prefix, k##escape, kW0, AVX2);    \
  }                                                                          \
  void v##instruction(YMMRegister dst, YMMRegister src1, Operand src2) {     \
    vinstr(0x##opcode, dst, src1, src2, k##prefix, k##escape, kW0, AVX2);    \
  }

  SSE2_INSTRUCTION_LIST_PI(DECLARE_SSE2_PI_AVX_INSTRUCTION)
#undef DECLARE_SSE2_PI_AVX_INSTRUCTION

#define DECLARE_SSE2_SHIFT_AVX_INSTRUCTION(instruction, prefix, escape,      \
                                           opcode)                           \
  DECLARE_SSE2_AVX_INSTRUCTION(instruction, prefix, escape, opcode)          \
  void v##instruction(YMMRegister dst, YMMRegister src1, XMMRegister src2) { \
    vinstr(0x##opcode, dst, src1, src2, k##prefix, k##escape, kW0, AVX2);    \
  }                                                                          \
  void v##instruction(YMMRegister dst, YMMRegister src1, Operand src2) {     \
    vinstr(0x##opcode, dst, src1, src2, k##prefix, k##escape, kW0, AVX2);    \
  }

  SSE2_INSTRUCTION_LIST_SHIFT(DECLARE_SSE2_SHIFT_AVX_INSTRUCTION)
#undef DECLARE_SSE2_SHIFT_AVX_INSTRUCTION
#undef DECLARE_SSE2_AVX_INSTRUCTION

#define DECLARE_SSE2_UNOP_AVX_INSTRUCTION(instruction, prefix, escape, opcode) \
  void v##instruction(XMMRegister dst, XMMRegister src) {                      \
    vpd(0x##opcode, dst, xmm0, src);                                           \
  }                                                                            \
  void v##instruction(XMMRegister dst, Operand src) {                          \
    vpd(0x##opcode, dst, xmm0, src);                                           \
  }

  SSE2_UNOP_INSTRUCTION_LIST(DECLARE_SSE2_UNOP_AVX_INSTRUCTION)
#undef DECLARE_SSE2_UNOP_AVX_INSTRUCTION

#define DECLARE_SSE2_UNOP_AVX_YMM_INSTRUCTION(                 \
    instruction, opcode, DSTRegister, SRCRegister, MemOperand) \
  void v##instruction(DSTRegister dst, SRCRegister src) {      \
    vpd(0x##opcode, dst, ymm0, src);                           \
  }                                                            \
  void v##instruction(DSTRegister dst, MemOperand src) {       \
    vpd(0x##opcode, dst, ymm0, src);                           \
  }
  DECLARE_SSE2_UNOP_AVX_YMM_INSTRUCTION(sqrtpd, 51, YMMRegister, YMMRegister,
                                        Operand)
  DECLARE_SSE2_UNOP_AVX_YMM_INSTRUCTION(cvtpd2ps, 5A, XMMRegister, YMMRegister,
                                        Operand256)
  DECLARE_SSE2_UNOP_AVX_YMM_INSTRUCTION(cvtps2dq, 5B, YMMRegister, YMMRegister,
                                        Operand)
  DECLARE_SSE2_UNOP_AVX_YMM_INSTRUCTION(cvttpd2dq, E6, XMMRegister, YMMRegister,
                                        Operand256)
#undef DECLARE_SSE2_UNOP_AVX_YMM_INSTRUCTION

  // SSE3
  void lddqu(XMMRegister dst, Operand src);
  void movddup(XMMRegister dst, Operand src);
  void movddup(XMMRegister dst, XMMRegister src);
  void movshdup(XMMRegister dst, XMMRegister src);

  // SSSE3
  void ssse3_instr(XMMRegister dst, XMMRegister src, uint8_t prefix,
                   uint8_t escape1, uint8_t escape2, uint8_t opcode);
  void ssse3_instr(XMMRegister dst, Operand src, uint8_t prefix,
                   uint8_t escape1, uint8_t escape2, uint8_t opcode);

#define DECLARE_SSSE3_INSTRUCTION(instruction, prefix, escape1, escape2,     \
                                  opcode)                                    \
  void instruction(XMMRegister dst, XMMRegister src) {                       \
    ssse3_instr(dst, src, 0x##prefix, 0x##escape1, 0x##escape2, 0x##opcode); \
  }                                                                          \
  void instruction(XMMRegister dst, Operand src) {                           \
    ssse3_instr(dst, src, 0x##prefix, 0x##escape1, 0x##escape2, 0x##opcode); \
  }

  SSSE3_INSTRUCTION_LIST(DECLARE_SSSE3_INSTRUCTION)
  SSSE3_UNOP_INSTRUCTION_LIST(DECLARE_SSSE3_INSTRUCTION)
#undef DECLARE_SSSE3_INSTRUCTION

  // SSE4
  void sse4_instr(Register dst, XMMRegister src, uint8_t prefix,
                  uint8_t escape1, uint8_t escape2, uint8_t opcode,
                  int8_t imm8);
  void sse4_instr(Operand dst, XMMRegister src, uint8_t prefix, uint8_t escape1,
                  uint8_t escape2, uint8_t opcode, int8_t imm8);
  void sse4_instr(XMMRegister dst, Register src, uint8_t prefix,
                  uint8_t escape1, uint8_t escape2, uint8_t opcode,
                  int8_t imm8);
  void sse4_instr(XMMRegister dst, XMMRegister src, uint8_t prefix,
                  uint8_t escape1, uint8_t escape2, uint8_t opcode);
  void sse4_instr(XMMRegister dst, Operand src, uint8_t prefix, uint8_t escape1,
                  uint8_t escape2, uint8_t opcode);
#define DECLARE_SSE4_INSTRUCTION(instruction, prefix, escape1, escape2,     \
                                 opcode)                                    \
  void instruction(XMMRegister dst, XMMRegister src) {                      \
    sse4_instr(dst, src, 0x##prefix, 0x##escape1, 0x##escape2, 0x##opcode); \
  }                                                                         \
  void instruction(XMMRegister dst, Operand src) {                          \
    sse4_instr(dst, src, 0x##prefix, 0x##escape1, 0x##escape2, 0x##opcode); \
  }

  SSE4_INSTRUCTION_LIST(DECLARE_SSE4_INSTRUCTION)
  SSE4_UNOP_INSTRUCTION_LIST(DECLARE_SSE4_INSTRUCTION)
  DECLARE_SSE4_INSTRUCTION(pblendvb, 66, 0F, 38, 10)
  DECLARE_SSE4_INSTRUCTION(blendvps, 66, 0F, 38, 14)
  DECLARE_SSE4_INSTRUCTION(blendvpd, 66, 0F, 38, 15)
#undef DECLARE_SSE4_INSTRUCTION

#define DECLARE_SSE4_EXTRACT_INSTRUCTION(instruction, prefix, escape1,     \
                                         escape2, opcode)                  \
  void instruction(Register dst, XMMRegister src, uint8_t imm8) {          \
    sse4_instr(dst, src, 0x##prefix, 0x##escape1, 0x##escape2, 0x##opcode, \
               imm8);                                                      \
  }                                                                        \
  void instruction(Operand dst, XMMRegister src, uint8_t imm8) {           \
    sse4_instr(dst, src, 0x##prefix, 0x##escape1, 0x##escape2, 0x##opcode, \
               imm8);                                                      \
  }

  SSE4_EXTRACT_INSTRUCTION_LIST(DECLARE_SSE4_EXTRACT_INSTRUCTION)
#undef DECLARE_SSE4_EXTRACT_INSTRUCTION

  // SSE4.2
  void sse4_2_instr(XMMRegister dst, XMMRegister src, uint8_t prefix,
                    uint8_t escape1, uint8_t escape2, uint8_t opcode);
  void sse4_2_instr(XMMRegister dst, Operand src, uint8_t prefix,
                    uint8_t escape1, uint8_t escape2, uint8_t opcode);
#define DECLARE_SSE4_2_INSTRUCTION(instruction, prefix, escape1, escape2,     \
                                   opcode)                                    \
  void instruction(XMMRegister dst, XMMRegister src) {                        \
    sse4_2_instr(dst, src, 0x##prefix, 0x##escape1, 0x##escape2, 0x##opcode); \
  }                                                                           \
  void instruction(XMMRegister dst, Operand src) {                            \
    sse4_2_instr(dst, src, 0x##prefix, 0x##escape1, 0x##escape2, 0x##opcode); \
  }

  SSE4_2_INSTRUCTION_LIST(DECLARE_SSE4_2_INSTRUCTION)
#undef DECLARE_SSE4_2_INSTRUCTION

#define DECLARE_SSE34_AVX_INSTRUCTION(instruction, prefix, escape1, escape2,  \
                                      opcode)                                 \
  void v##instruction(XMMRegister dst, XMMRegister src1, XMMRegister src2) {  \
    vinstr(0x##opcode, dst, src1, src2, k##prefix, k##escape1##escape2, kW0); \
  }                                                                           \
  void v##instruction(XMMRegister dst, XMMRegister src1, Operand src2) {      \
    vinstr(0x##opcode, dst, src1, src2, k##prefix, k##escape1##escape2, kW0); \
  }                                                                           \
  void v##instruction(YMMRegister dst, YMMRegister src1, YMMRegister src2) {  \
    vinstr(0x##opcode, dst, src1, src2, k##prefix, k##escape1##escape2, kW0,  \
           AVX2);                                                             \
  }                                                                           \
  void v##instruction(YMMRegister dst, YMMRegister src1, Operand src2) {      \
    vinstr(0x##opcode, dst, src1, src2, k##prefix, k##escape1##escape2, kW0,  \
           AVX2);                                                             \
  }

  SSSE3_INSTRUCTION_LIST(DECLARE_SSE34_AVX_INSTRUCTION)
  SSE4_INSTRUCTION_LIST(DECLARE_SSE34_AVX_INSTRUCTION)
  SSE4_2_INSTRUCTION_LIST(DECLARE_SSE34_AVX_INSTRUCTION)
#undef DECLARE_SSE34_AVX_INSTRUCTION

#define DECLARE_SSSE3_UNOP_AVX_INSTRUCTION(instruction, prefix, escape1,     \
                                           escape2, opcode)                  \
  void v##instruction(XMMRegister dst, XMMRegister src) {                    \
    vinstr(0x##opcode, dst, xmm0, src, k##prefix, k##escape1##escape2, kW0); \
  }                                                                          \
  void v##instruction(XMMRegister dst, Operand src) {                        \
    vinstr(0x##opcode, dst, xmm0, src, k##prefix, k##escape1##escape2, kW0); \
  }                                                                          \
  void v##instruction(YMMRegister dst, YMMRegister src) {                    \
    vinstr(0x##opcode, dst, ymm0, src, k##prefix, k##escape1##escape2, kW0); \
  }                                                                          \
  void v##instruction(YMMRegister dst, Operand src) {                        \
    vinstr(0x##opcode, dst, ymm0, src, k##prefix, k##escape1##escape2, kW0); \
  }

  SSSE3_UNOP_INSTRUCTION_LIST(DECLARE_SSSE3_UNOP_AVX_INSTRUCTION)
#undef DECLARE_SSSE3_UNOP_AVX_INSTRUCTION

  void vpblendvb(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                 XMMRegister mask) {
    vinstr(0x4C, dst, src1, src2, k66, k0F3A, kW0);
    // The mask operand is encoded in bits[7:4] of the immediate byte.
    emit(mask.code() << 4);
  }
  void vpblendvb(YMMRegister dst, YMMRegister src1, YMMRegister src2,
                 YMMRegister mask) {
    vinstr(0x4C, dst, src1, src2, k66, k0F3A, kW0, AVX2);
    // The mask operand is encoded in bits[7:4] of the immediate byte.
    emit(mask.code() << 4);
  }

  void vblendvps(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                 XMMRegister mask) {
    vinstr(0x4A, dst, src1, src2, k66, k0F3A, kW0);
    // The mask operand is encoded in bits[7:4] of the immediate byte.
    emit(mask.code() << 4);
  }
  void vblendvps(YMMRegister dst, YMMRegister src1, YMMRegister src2,
                 YMMRegister mask) {
    vinstr(0x4A, dst, src1, src2, k66, k0F3A, kW0, AVX);
    // The mask operand is encoded in bits[7:4] of the immediate byte.
    emit(mask.code() << 4);
  }

  void vblendvpd(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                 XMMRegister mask) {
    vinstr(0x4B, dst, src1, src2, k66, k0F3A, kW0);
    // The mask operand is encoded in bits[7:4] of the immediate byte.
    emit(mask.code() << 4);
  }
  void vblendvpd(YMMRegister dst, YMMRegister src1, YMMRegister src2,
                 YMMRegister mask) {
    vinstr(0x4B, dst, src1, src2, k66, k0F3A, kW0, AVX);
    // The mask operand is encoded in bits[7:4] of the immediate byte.
    emit(mask.code() << 4);
  }

#define DECLARE_SSE4_PMOV_AVX_INSTRUCTION(instruction, prefix, escape1,      \
                                          escape2, opcode)                   \
  void v##instruction(XMMRegister dst, XMMRegister src) {                    \
    vinstr(0x##opcode, dst, xmm0, src, k##prefix, k##escape1##escape2, kW0); \
  }                                                                          \
  void v##instruction(XMMRegister dst, Operand src) {                        \
    vinstr(0x##opcode, dst, xmm0, src, k##prefix, k##escape1##escape2, kW0); \
  }
  SSE4_UNOP_INSTRUCTION_LIST(DECLARE_SSE4_PMOV_AVX_INSTRUCTION)
#undef DECLARE_SSE4_PMOV_AVX_INSTRUCTION

#define DECLARE_SSE4_PMOV_AVX2_INSTRUCTION(instruction, prefix, escape1,     \
                                           escape2, opcode)                  \
  void v##instruction(YMMRegister dst, XMMRegister src) {                    \
    vinstr(0x##opcode, dst, xmm0, src, k##prefix, k##escape1##escape2, kW0); \
  }                                                                          \
  void v##instruction(YMMRegister dst, Operand src) {                        \
    vinstr(0x##opcode, dst, xmm0, src, k##prefix, k##escape1##escape2, kW0); \
  }
  SSE4_UNOP_INSTRUCTION_LIST_PMOV(DECLARE_SSE4_PMOV_AVX2_INSTRUCTION)
#undef DECLARE_SSE4_PMOV_AVX2_INSTRUCTION

  void vptest(YMMRegister dst, YMMRegister src) {
    vinstr(0x17, dst, ymm0, src, k66, k0F38, kW0, AVX);
  }
  void vptest(YMMRegister dst, Operand src) {
    vinstr(0x17, dst, ymm0, src, k66, k0F38, kW0, AVX);
  }

#define DECLARE_AVX_INSTRUCTION(instruction, prefix, escape1, escape2, opcode) \
  void v##instruction(Register dst, XMMRegister src, uint8_t imm8) {           \
    XMMRegister idst = XMMRegister::from_code(dst.code());                     \
    vinstr(0x##opcode, src, xmm0, idst, k##prefix, k##escape1##escape2, kW0);  \
    emit(imm8);                                                                \
  }                                                                            \
  void v##instruction(Operand dst, XMMRegister src, uint8_t imm8) {            \
    vinstr(0x##opcode, src, xmm0, dst, k##prefix, k##escape1##escape2, kW0);   \
    emit(imm8);                                                                \
  }

  SSE4_EXTRACT_INSTRUCTION_LIST(DECLARE_AVX_INSTRUCTION)
#undef DECLARE_AVX_INSTRUCTION

  void movd(XMMRegister dst, Register src);
  void movd(XMMRegister dst, Operand src);
  void movd(Register dst, XMMRegister src);
  void movq(XMMRegister dst, Register src);
  void movq(XMMRegister dst, Operand src);
  void movq(Register dst, XMMRegister src);
  void movq(XMMRegister dst, XMMRegister src);

  // Don't use this unless it's important to keep the
  // top half of the destination register unchanged.
  // Use movapd when moving double values and movq for integer
  // values in xmm registers.
  void movsd(XMMRegister dst, XMMRegister src);

  void movsd(Operand dst, XMMRegister src);
  void movsd(XMMRegister dst, Operand src);

  void movdqa(Operand dst, XMMRegister src);
  void movdqa(XMMRegister dst, Operand src);
  void movdqa(XMMRegister dst, XMMRegister src);

  void movdqu(Operand dst, XMMRegister src);
  void movdqu(XMMRegister dst, Operand src);
  void movdqu(XMMRegister dst, XMMRegister src);

  void movapd(XMMRegister dst, XMMRegister src);
  void movupd(XMMRegister dst, Operand src);
  void movupd(Operand dst, XMMRegister src);

  void cvtdq2pd(XMMRegister dst, XMMRegister src);

  void cvttsd2si(Register dst, Operand src);
  void cvttsd2si(Register dst, XMMRegister src);
  void cvttss2siq(Register dst, XMMRegister src);
  void cvttss2siq(Register dst, Operand src);
  void cvttsd2siq(Register dst, XMMRegister src);
  void cvttsd2siq(Register dst, Operand src);
  void cvttps2dq(XMMRegister dst, Operand src);
  void cvttps2dq(XMMRegister dst, XMMRegister src);

  void cvtlsi2sd(XMMRegister dst, Operand src);
  void cvtlsi2sd(XMMRegister dst, Register src);

  void cvtqsi2ss(XMMRegister dst, Operand src);
  void cvtqsi2ss(XMMRegister dst, Register src);

  void cvtqsi2sd(XMMRegister dst, Operand src);
  void cvtqsi2sd(XMMRegister dst, Register src);

  void cvtsd2si(Register dst, XMMRegister src);
  void cvtsd2siq(Register dst, XMMRegister src);

  void haddps(XMMRegister dst, XMMRegister src);
  void haddps(XMMRegister dst, Operand src);

  void cmpeqsd(XMMRegister dst, XMMRegister src);
  void cmpeqss(XMMRegister dst, XMMRegister src);
  void cmpltsd(XMMRegister dst, XMMRegister src);

  void movmskpd(Register dst, XMMRegister src);

  void pmovmskb(Register dst, XMMRegister src);

  void pinsrw(XMMRegister dst, Register src, uint8_t imm8);
  void pinsrw(XMMRegister dst, Operand src, uint8_t imm8);

  // SSE 4.1 instruction
  void insertps(XMMRegister dst, XMMRegister src, uint8_t imm8);
  void insertps(XMMRegister dst, Operand src, uint8_t imm8);
  void pextrq(Register dst, XMMRegister src, int8_t imm8);
  void pinsrb(XMMRegister dst, Register src, uint8_t imm8);
  void pinsrb(XMMRegister dst, Operand src, uint8_t imm8);
  void pinsrd(XMMRegister dst, Register src, uint8_t imm8);
  void pinsrd(XMMRegister dst, Operand src, uint8_t imm8);
  void pinsrq(XMMRegister dst, Register src, uint8_t imm8);
  void pinsrq(XMMRegister dst, Operand src, uint8_t imm8);

  void roundss(XMMRegister dst, XMMRegister src, RoundingMode mode);
  void roundss(XMMRegister dst, Operand src, RoundingMode mode);
  void roundsd(XMMRegister dst, XMMRegister src, Rou
"""


```