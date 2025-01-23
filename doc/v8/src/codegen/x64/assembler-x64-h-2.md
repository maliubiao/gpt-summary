Response:
The user wants a summary of the functionality of the provided C++ header file for the x64 architecture in V8.

Here's a breakdown of the thought process:

1. **Identify the core purpose:** The filename `assembler-x64.h` strongly suggests this file is about assembling x64 instructions. The namespace `v8::internal::compiler` confirms it's part of V8's code generation.

2. **Scan for instruction patterns:** Look for repeated patterns like `void instruction(...)`. Notice the prevalence of `XMMRegister`, `YMMRegister`, `Operand`, and `Register`, which are key data types for x64 assembly. This reinforces the idea that the file defines methods to emit specific x64 instructions.

3. **Categorize instructions:**  Group the instructions based on their prefixes (SSE, AVX, AVX2, BMI), data types (ps, pd, ss, sd), and general functionality (move, compare, arithmetic, bit manipulation).

4. **Check for Torque relevance:** The prompt explicitly asks about `.tq` files. This file ends in `.h`, so it's a C++ header file, not a Torque file.

5. **Look for JavaScript connections:**  Since V8 executes JavaScript, think about how these low-level instructions relate to JavaScript operations. Floating-point arithmetic, array manipulation, and bitwise operations in JavaScript likely utilize these instructions under the hood.

6. **Find potential for common programming errors:** Think about how these instructions could be misused. Incorrect data types, misaligned memory access, and wrong instruction choices for a given task come to mind.

7. **Consider code logic and examples:** For specific instruction groups, devise simple examples to illustrate their behavior, keeping in mind the register and operand types.

8. **Address each part of the prompt:**  Ensure all the explicit requests from the user are covered: list functionalities, check for Torque, JavaScript examples, code logic, common errors, and a summary.

9. **Structure the response:** Organize the information logically, starting with the main purpose, then detailing the functionalities, addressing the specific questions, and concluding with a summary. Use clear headings and bullet points for readability.

10. **Refine and review:** Read through the response to ensure clarity, accuracy, and completeness. For instance, initially, I might have just said "handles SSE instructions," but it's more informative to list some examples like `movups`, `cmpps`, etc. Similarly, when providing JavaScript examples, it's better to show concrete code than just abstract concepts.

By following these steps, the comprehensive and well-organized answer can be generated.
这是 `v8/src/codegen/x64/assembler-x64.h` 文件的第 3 部分，它定义了 `Assembler` 类在 x64 架构下用于生成机器码的各种指令方法，主要集中在 **SIMD (Single Instruction, Multiple Data)** 指令集，特别是 **SSE (Streaming SIMD Extensions)** 和 **AVX (Advanced Vector Extensions)** 及其扩展。

**功能归纳（第 3 部分）：**

这一部分主要提供了以下功能：

1. **浮点数和整数的 SIMD 操作：** 提供了大量的 SSE 和 AVX 指令，用于对打包的单精度和双精度浮点数以及整数进行并行运算。这包括：
    * **数据移动：** 在 XMM 和 YMM 寄存器之间以及寄存器和内存之间移动数据 (`movups`, `movapd`, `vmovddup`, `vmovdqa`, `vmovdqu` 等)。
    * **数据混洗和重排：** 允许重新排列寄存器中的数据元素 (`pshufd`, `pshuflw`, `pshufhw`, `vshufps`, `vinsertps`, `vpextrq` 等)。
    * **类型转换：** 在不同的数据类型之间进行转换，例如整数和浮点数之间的转换 (`vcvtdq2pd`, `vcvttps2dq`, `vcvtlsi2sd`, `vcvttss2si` 等)。
    * **算术运算：** 执行加法、减法、乘法、除法等运算（通过 `FMA` 相关的宏和具体的指令如 `vhaddps` 等）。
    * **比较运算：** 比较 SIMD 寄存器中的值 (`cmpps`, `cmppd`, `vcmpeqps`, `vcmpltpd` 等)。
    * **舍入操作：** 对浮点数进行舍入到不同的精度和模式 (`roundss`, `roundsd`, `roundps`, `roundpd`, `vroundss`, `vroundsd`, `vroundps`, `vroundpd`)。

2. **AVX 特有的操作：**  定义了 AVX 指令，允许使用更宽的 YMM 寄存器 (256 位) 进行操作，从而提高并行处理能力。

3. **FMA (Fused Multiply-Add) 指令：**  通过宏定义提供了 FMA 指令的支持，可以将乘法和加法运算合并为一个指令，提高性能和精度。

4. **AVX2 和其他扩展指令：**  包含了 AVX2 (`vpblendw`, `vpalignr`)、F16C (`vcvtph2ps`, `vcvtps2ph`) 和 AVX-VNNI (`vpdpbusd`, `vpdpbssd`) 等指令集的支持，用于更高级的向量化操作。

5. **BMI (Bit Manipulation Instructions) 指令：**  提供了一组用于位操作的指令，例如位提取、位设置、计数等 (`andnq`, `bextrq`, `blsiq`, `tzcntq`, `lzcntq`, `popcntq`, `bzhiq`, `mulxq`, `pdepq`, `pextq`, `sarxq`, `shlxq`, `shrxq`, `rorxq`)。

6. **内存屏障和暂停指令：** 提供了 `mfence` (内存写屏障), `lfence` (内存读屏障) 和 `pause` 指令，用于控制内存访问顺序和优化多线程性能。

7. **代码大小跟踪：** 提供了 `SizeOfCodeGeneratedSince` 方法，用于计算自指定标签以来生成的代码大小，这在代码生成和优化过程中很有用。

**如果 `v8/src/codegen/x64/assembler-x64.h` 以 `.tq` 结尾，那它是个 v8 torque 源代码：**

当前提供的文件是以 `.h` 结尾，这是一个 C++ 头文件，而不是 Torque 源代码文件。 Torque 文件用于定义 V8 的内置函数和类型，并且会生成 C++ 代码。

**如果它与 javascript 的功能有关系，请用 javascript 举例说明：**

很多 JavaScript 的操作最终会通过这些底层的汇编指令来实现，特别是涉及到数值计算、数组操作以及一些内置函数。

**JavaScript 示例：**

```javascript
// 假设 JavaScript 引擎使用 SSE/AVX 指令优化数组操作

const arr1 = [1.0, 2.0, 3.0, 4.0];
const arr2 = [5.0, 6.0, 7.0, 8.0];
const result = [];

for (let i = 0; i < arr1.length; i++) {
  result.push(arr1[i] + arr2[i]);
}

console.log(result); // 输出 [6, 8, 10, 12]

// 在底层，V8 可能会使用类似 vmovaps, vaddps 指令来并行处理数组元素的加法。
```

在这个例子中，虽然 JavaScript 代码是顺序的，但 V8 的 JavaScript 引擎在编译和执行时，可能会将数组的加法操作转换为 SIMD 指令，例如 `vmovaps` 将 `arr1` 和 `arr2` 的一部分加载到 YMM 寄存器，然后使用 `vaddps` 指令并行执行加法，最后将结果存回内存。

**如果有代码逻辑推理，请给出假设输入与输出：**

考虑 `vaddps` 指令：

**假设输入：**

* `dst` (XMMRegister 或 YMMRegister):  `xmm0`
* `src1` (XMMRegister 或 YMMRegister): `xmm1`， 假设其值为 `[1.0, 2.0, 3.0, 4.0]` (单精度浮点数)
* `src2` (XMMRegister 或 Operand): `xmm2`， 假设其值为 `[5.0, 6.0, 7.0, 8.0]` (单精度浮点数)

**代码逻辑：** `vaddps xmm0, xmm1, xmm2`

**输出：**

* `xmm0` 的值将会是 `[1.0 + 5.0, 2.0 + 6.0, 3.0 + 7.0, 4.0 + 8.0]`，即 `[6.0, 8.0, 10.0, 12.0]`。

**如果涉及用户常见的编程错误，请举例说明：**

用户在使用 JavaScript 时，通常不会直接接触到这些汇编指令。但是，理解这些指令可以帮助理解一些性能问题。

**常见编程错误（概念层面）：**

1. **不必要的循环和标量操作：**  如果用户编写了大量的循环来处理数组元素，而没有意识到 JavaScript 引擎可以利用 SIMD 指令进行优化，就可能导致性能下降。例如，手动循环相加数组元素，而不是使用 `map` 或其他可以被优化的方法。

   ```javascript
   // 低效的标量操作
   const arr1 = [1, 2, 3, 4];
   const arr2 = [5, 6, 7, 8];
   const result = [];
   for (let i = 0; i < arr1.length; i++) {
       result.push(arr1[i] + arr2[i]);
   }

   // V8 可能会尝试优化，但如果逻辑复杂，优化可能不充分。
   ```

2. **数据类型不匹配：** 虽然 JavaScript 是动态类型的，但在底层，SIMD 指令对数据类型有严格的要求。如果 JavaScript 代码中频繁进行类型转换，可能会影响 SIMD 指令的效率。

3. **内存对齐问题：**  虽然在 JavaScript 中不直接控制内存分配，但在 C++ 代码中生成这些指令时，如果内存访问没有对齐，某些 SIMD 指令可能会导致性能下降或错误。这通常是 V8 开发者需要考虑的问题。

**总结一下它的功能（第 3 部分）：**

`v8/src/codegen/x64/assembler-x64.h` 的第 3 部分主要定义了 `Assembler` 类在 x64 架构下生成 **SIMD 指令** 的方法，包括 SSE、AVX、AVX2、FMA 和 BMI 等指令集。这些指令允许 V8 高效地执行向量化操作，例如对浮点数和整数数组进行并行计算、数据重排和位操作，从而提升 JavaScript 代码的执行性能。 此外，它还包含了一些控制流和内存操作相关的指令，以及用于代码大小跟踪的辅助方法。 这部分是 V8 代码生成器中实现高性能数值计算和数据处理的关键组成部分。

### 提示词
```
这是目录为v8/src/codegen/x64/assembler-x64.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/x64/assembler-x64.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```c
ndingMode mode);
  void roundsd(XMMRegister dst, Operand src, RoundingMode mode);
  void roundps(XMMRegister dst, XMMRegister src, RoundingMode mode);
  void roundpd(XMMRegister dst, XMMRegister src, RoundingMode mode);

  void cmpps(XMMRegister dst, XMMRegister src, int8_t cmp);
  void cmpps(XMMRegister dst, Operand src, int8_t cmp);
  void cmppd(XMMRegister dst, XMMRegister src, int8_t cmp);
  void cmppd(XMMRegister dst, Operand src, int8_t cmp);

#define SSE_CMP_P(instr, imm8)                                                \
  void instr##ps(XMMRegister dst, XMMRegister src) { cmpps(dst, src, imm8); } \
  void instr##ps(XMMRegister dst, Operand src) { cmpps(dst, src, imm8); }     \
  void instr##pd(XMMRegister dst, XMMRegister src) { cmppd(dst, src, imm8); } \
  void instr##pd(XMMRegister dst, Operand src) { cmppd(dst, src, imm8); }

  SSE_CMP_P(cmpeq, 0x0)
  SSE_CMP_P(cmplt, 0x1)
  SSE_CMP_P(cmple, 0x2)
  SSE_CMP_P(cmpunord, 0x3)
  SSE_CMP_P(cmpneq, 0x4)
  SSE_CMP_P(cmpnlt, 0x5)
  SSE_CMP_P(cmpnle, 0x6)

#undef SSE_CMP_P

  void movups(XMMRegister dst, XMMRegister src);
  void movups(XMMRegister dst, Operand src);
  void movups(Operand dst, XMMRegister src);
  void psrldq(XMMRegister dst, uint8_t shift);
  void pshufd(XMMRegister dst, XMMRegister src, uint8_t shuffle);
  void pshufd(XMMRegister dst, Operand src, uint8_t shuffle);
  void pshufhw(XMMRegister dst, XMMRegister src, uint8_t shuffle);
  void pshufhw(XMMRegister dst, Operand src, uint8_t shuffle);
  void pshuflw(XMMRegister dst, XMMRegister src, uint8_t shuffle);
  void pshuflw(XMMRegister dst, Operand src, uint8_t shuffle);

  void movhlps(XMMRegister dst, XMMRegister src) {
    sse_instr(dst, src, 0x0F, 0x12);
  }
  void movlhps(XMMRegister dst, XMMRegister src) {
    sse_instr(dst, src, 0x0F, 0x16);
  }

  // AVX instruction
  void vmovddup(XMMRegister dst, XMMRegister src);
  void vmovddup(XMMRegister dst, Operand src);
  void vmovddup(YMMRegister dst, YMMRegister src);
  void vmovddup(YMMRegister dst, Operand src);
  void vmovshdup(XMMRegister dst, XMMRegister src);
  void vmovshdup(YMMRegister dst, YMMRegister src);
  void vbroadcastss(XMMRegister dst, Operand src);
  void vbroadcastss(XMMRegister dst, XMMRegister src);
  void vbroadcastss(YMMRegister dst, Operand src);
  void vbroadcastss(YMMRegister dst, XMMRegister src);
  void vbroadcastsd(YMMRegister dst, XMMRegister src);
  void vbroadcastsd(YMMRegister dst, Operand src);

  void vinserti128(YMMRegister dst, YMMRegister src1, XMMRegister src2,
                   uint8_t lane);
  void vperm2f128(YMMRegister dst, YMMRegister src1, YMMRegister src2,
                  uint8_t lane);
  void vextractf128(XMMRegister dst, YMMRegister src, uint8_t lane);

  template <typename Reg1, typename Reg2, typename Op>
  void fma_instr(uint8_t op, Reg1 dst, Reg2 src1, Op src2, VectorLength l,
                 SIMDPrefix pp, LeadingOpcode m, VexW w);

#define FMA(instr, prefix, escape1, escape2, extension, opcode)     \
  void instr(XMMRegister dst, XMMRegister src1, XMMRegister src2) { \
    fma_instr(0x##opcode, dst, src1, src2, kL128, k##prefix,        \
              k##escape1##escape2, k##extension);                   \
  }                                                                 \
  void instr(XMMRegister dst, XMMRegister src1, Operand src2) {     \
    fma_instr(0x##opcode, dst, src1, src2, kL128, k##prefix,        \
              k##escape1##escape2, k##extension);                   \
  }
  FMA_INSTRUCTION_LIST(FMA)
#undef FMA

#define DECLARE_FMA_YMM_INSTRUCTION(instr, prefix, escape1, escape2, \
                                    extension, opcode)               \
  void instr(YMMRegister dst, YMMRegister src1, YMMRegister src2) {  \
    fma_instr(0x##opcode, dst, src1, src2, kL256, k##prefix,         \
              k##escape1##escape2, k##extension);                    \
  }                                                                  \
  void instr(YMMRegister dst, YMMRegister src1, Operand src2) {      \
    fma_instr(0x##opcode, dst, src1, src2, kL256, k##prefix,         \
              k##escape1##escape2, k##extension);                    \
  }
  FMA_PS_INSTRUCTION_LIST(DECLARE_FMA_YMM_INSTRUCTION)
  FMA_PD_INSTRUCTION_LIST(DECLARE_FMA_YMM_INSTRUCTION)
#undef DECLARE_FMA_YMM_INSTRUCTION

  void vmovd(XMMRegister dst, Register src);
  void vmovd(XMMRegister dst, Operand src);
  void vmovd(Register dst, XMMRegister src);
  void vmovq(XMMRegister dst, Register src);
  void vmovq(XMMRegister dst, Operand src);
  void vmovq(Register dst, XMMRegister src);

  void vmovsd(XMMRegister dst, XMMRegister src1, XMMRegister src2) {
    vsd(0x10, dst, src1, src2);
  }
  void vmovsd(XMMRegister dst, Operand src) { vsd(0x10, dst, xmm0, src); }
  void vmovsd(Operand dst, XMMRegister src) { vsd(0x11, src, xmm0, dst); }
  void vmovdqa(XMMRegister dst, Operand src);
  void vmovdqa(XMMRegister dst, XMMRegister src);
  void vmovdqa(YMMRegister dst, Operand src);
  void vmovdqa(YMMRegister dst, YMMRegister src);
  void vmovdqu(XMMRegister dst, Operand src);
  void vmovdqu(Operand dst, XMMRegister src);
  void vmovdqu(XMMRegister dst, XMMRegister src);
  void vmovdqu(YMMRegister dst, Operand src);
  void vmovdqu(Operand dst, YMMRegister src);
  void vmovdqu(YMMRegister dst, YMMRegister src);

  void vmovlps(XMMRegister dst, XMMRegister src1, Operand src2);
  void vmovlps(Operand dst, XMMRegister src);

  void vmovhps(XMMRegister dst, XMMRegister src1, Operand src2);
  void vmovhps(Operand dst, XMMRegister src);

#define AVX_SSE_UNOP(instr, escape, opcode)          \
  void v##instr(XMMRegister dst, XMMRegister src2) { \
    vps(0x##opcode, dst, xmm0, src2);                \
  }                                                  \
  void v##instr(XMMRegister dst, Operand src2) {     \
    vps(0x##opcode, dst, xmm0, src2);                \
  }                                                  \
  void v##instr(YMMRegister dst, YMMRegister src2) { \
    vps(0x##opcode, dst, ymm0, src2);                \
  }                                                  \
  void v##instr(YMMRegister dst, Operand src2) {     \
    vps(0x##opcode, dst, ymm0, src2);                \
  }
  SSE_UNOP_INSTRUCTION_LIST(AVX_SSE_UNOP)
#undef AVX_SSE_UNOP

#define AVX_SSE_BINOP(instr, escape, opcode)                           \
  void v##instr(XMMRegister dst, XMMRegister src1, XMMRegister src2) { \
    vps(0x##opcode, dst, src1, src2);                                  \
  }                                                                    \
  void v##instr(XMMRegister dst, XMMRegister src1, Operand src2) {     \
    vps(0x##opcode, dst, src1, src2);                                  \
  }                                                                    \
  void v##instr(YMMRegister dst, YMMRegister src1, YMMRegister src2) { \
    vps(0x##opcode, dst, src1, src2);                                  \
  }                                                                    \
  void v##instr(YMMRegister dst, YMMRegister src1, Operand src2) {     \
    vps(0x##opcode, dst, src1, src2);                                  \
  }
  SSE_BINOP_INSTRUCTION_LIST(AVX_SSE_BINOP)
#undef AVX_SSE_BINOP

#define AVX_3(instr, opcode, impl, SIMDRegister)                       \
  void instr(SIMDRegister dst, SIMDRegister src1, SIMDRegister src2) { \
    impl(opcode, dst, src1, src2);                                     \
  }                                                                    \
  void instr(SIMDRegister dst, SIMDRegister src1, Operand src2) {      \
    impl(opcode, dst, src1, src2);                                     \
  }

  AVX_3(vhaddps, 0x7c, vsd, XMMRegister)
  AVX_3(vhaddps, 0x7c, vsd, YMMRegister)

#define AVX_SCALAR(instr, prefix, escape, opcode)                      \
  void v##instr(XMMRegister dst, XMMRegister src1, XMMRegister src2) { \
    vinstr(0x##opcode, dst, src1, src2, k##prefix, k##escape, kWIG);   \
  }                                                                    \
  void v##instr(XMMRegister dst, XMMRegister src1, Operand src2) {     \
    vinstr(0x##opcode, dst, src1, src2, k##prefix, k##escape, kWIG);   \
  }
  SSE_INSTRUCTION_LIST_SS(AVX_SCALAR)
  SSE2_INSTRUCTION_LIST_SD(AVX_SCALAR)
#undef AVX_SCALAR

#undef AVX_3

#define AVX_SSE2_SHIFT_IMM(instr, prefix, escape, opcode, extension)   \
  void v##instr(XMMRegister dst, XMMRegister src, uint8_t imm8) {      \
    XMMRegister ext_reg = XMMRegister::from_code(extension);           \
    vinstr(0x##opcode, ext_reg, dst, src, k##prefix, k##escape, kWIG); \
    emit(imm8);                                                        \
  }                                                                    \
                                                                       \
  void v##instr(YMMRegister dst, YMMRegister src, uint8_t imm8) {      \
    YMMRegister ext_reg = YMMRegister::from_code(extension);           \
    vinstr(0x##opcode, ext_reg, dst, src, k##prefix, k##escape, kWIG); \
    emit(imm8);                                                        \
  }
  SSE2_INSTRUCTION_LIST_SHIFT_IMM(AVX_SSE2_SHIFT_IMM)
#undef AVX_SSE2_SHIFT_IMM

  void vmovlhps(XMMRegister dst, XMMRegister src1, XMMRegister src2) {
    vinstr(0x16, dst, src1, src2, kNoPrefix, k0F, kWIG);
  }
  void vmovhlps(XMMRegister dst, XMMRegister src1, XMMRegister src2) {
    vinstr(0x12, dst, src1, src2, kNoPrefix, k0F, kWIG);
  }
  void vcvtdq2pd(XMMRegister dst, XMMRegister src) {
    vinstr(0xe6, dst, xmm0, src, kF3, k0F, kWIG);
  }
  void vcvtdq2pd(YMMRegister dst, XMMRegister src) {
    vinstr(0xe6, dst, xmm0, src, kF3, k0F, kWIG, AVX);
  }
  void vcvtdq2pd(YMMRegister dst, Operand src) {
    vinstr(0xe6, dst, xmm0, src, kF3, k0F, kWIG, AVX);
  }
  void vcvttps2dq(XMMRegister dst, XMMRegister src) {
    vinstr(0x5b, dst, xmm0, src, kF3, k0F, kWIG);
  }
  void vcvttps2dq(YMMRegister dst, YMMRegister src) {
    vinstr(0x5b, dst, ymm0, src, kF3, k0F, kWIG, AVX);
  }
  void vcvttps2dq(YMMRegister dst, Operand src) {
    vinstr(0x5b, dst, ymm0, src, kF3, k0F, kWIG, AVX);
  }
  void vcvtlsi2sd(XMMRegister dst, XMMRegister src1, Register src2) {
    XMMRegister isrc2 = XMMRegister::from_code(src2.code());
    vinstr(0x2a, dst, src1, isrc2, kF2, k0F, kW0);
  }
  void vcvtlsi2sd(XMMRegister dst, XMMRegister src1, Operand src2) {
    vinstr(0x2a, dst, src1, src2, kF2, k0F, kW0);
  }
  void vcvtlsi2ss(XMMRegister dst, XMMRegister src1, Register src2) {
    XMMRegister isrc2 = XMMRegister::from_code(src2.code());
    vinstr(0x2a, dst, src1, isrc2, kF3, k0F, kW0);
  }
  void vcvtlsi2ss(XMMRegister dst, XMMRegister src1, Operand src2) {
    vinstr(0x2a, dst, src1, src2, kF3, k0F, kW0);
  }
  void vcvtqsi2ss(XMMRegister dst, XMMRegister src1, Register src2) {
    XMMRegister isrc2 = XMMRegister::from_code(src2.code());
    vinstr(0x2a, dst, src1, isrc2, kF3, k0F, kW1);
  }
  void vcvtqsi2ss(XMMRegister dst, XMMRegister src1, Operand src2) {
    vinstr(0x2a, dst, src1, src2, kF3, k0F, kW1);
  }
  void vcvtqsi2sd(XMMRegister dst, XMMRegister src1, Register src2) {
    XMMRegister isrc2 = XMMRegister::from_code(src2.code());
    vinstr(0x2a, dst, src1, isrc2, kF2, k0F, kW1);
  }
  void vcvtqsi2sd(XMMRegister dst, XMMRegister src1, Operand src2) {
    vinstr(0x2a, dst, src1, src2, kF2, k0F, kW1);
  }
  void vcvttss2si(Register dst, XMMRegister src) {
    XMMRegister idst = XMMRegister::from_code(dst.code());
    vinstr(0x2c, idst, xmm0, src, kF3, k0F, kW0);
  }
  void vcvttss2si(Register dst, Operand src) {
    XMMRegister idst = XMMRegister::from_code(dst.code());
    vinstr(0x2c, idst, xmm0, src, kF3, k0F, kW0);
  }
  void vcvttsd2si(Register dst, XMMRegister src) {
    XMMRegister idst = XMMRegister::from_code(dst.code());
    vinstr(0x2c, idst, xmm0, src, kF2, k0F, kW0);
  }
  void vcvttsd2si(Register dst, Operand src) {
    XMMRegister idst = XMMRegister::from_code(dst.code());
    vinstr(0x2c, idst, xmm0, src, kF2, k0F, kW0);
  }
  void vcvttss2siq(Register dst, XMMRegister src) {
    XMMRegister idst = XMMRegister::from_code(dst.code());
    vinstr(0x2c, idst, xmm0, src, kF3, k0F, kW1);
  }
  void vcvttss2siq(Register dst, Operand src) {
    XMMRegister idst = XMMRegister::from_code(dst.code());
    vinstr(0x2c, idst, xmm0, src, kF3, k0F, kW1);
  }
  void vcvttsd2siq(Register dst, XMMRegister src) {
    XMMRegister idst = XMMRegister::from_code(dst.code());
    vinstr(0x2c, idst, xmm0, src, kF2, k0F, kW1);
  }
  void vcvttsd2siq(Register dst, Operand src) {
    XMMRegister idst = XMMRegister::from_code(dst.code());
    vinstr(0x2c, idst, xmm0, src, kF2, k0F, kW1);
  }
  void vcvtsd2si(Register dst, XMMRegister src) {
    XMMRegister idst = XMMRegister::from_code(dst.code());
    vinstr(0x2d, idst, xmm0, src, kF2, k0F, kW0);
  }
  void vroundss(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                RoundingMode mode) {
    vinstr(0x0a, dst, src1, src2, k66, k0F3A, kWIG);
    emit(static_cast<uint8_t>(mode) | 0x8);  // Mask precision exception.
  }
  void vroundss(XMMRegister dst, XMMRegister src1, Operand src2,
                RoundingMode mode) {
    vinstr(0x0a, dst, src1, src2, k66, k0F3A, kWIG);
    emit(static_cast<uint8_t>(mode) | 0x8);  // Mask precision exception.
  }
  void vroundsd(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                RoundingMode mode) {
    vinstr(0x0b, dst, src1, src2, k66, k0F3A, kWIG);
    emit(static_cast<uint8_t>(mode) | 0x8);  // Mask precision exception.
  }
  void vroundsd(XMMRegister dst, XMMRegister src1, Operand src2,
                RoundingMode mode) {
    vinstr(0x0b, dst, src1, src2, k66, k0F3A, kWIG);
    emit(static_cast<uint8_t>(mode) | 0x8);  // Mask precision exception.
  }
  void vroundps(XMMRegister dst, XMMRegister src, RoundingMode mode) {
    vinstr(0x08, dst, xmm0, src, k66, k0F3A, kWIG);
    emit(static_cast<uint8_t>(mode) | 0x8);  // Mask precision exception.
  }
  void vroundps(YMMRegister dst, YMMRegister src, RoundingMode mode) {
    vinstr(0x08, dst, ymm0, src, k66, k0F3A, kWIG, AVX);
    emit(static_cast<uint8_t>(mode) | 0x8);  // Mask precision exception.
  }
  void vroundpd(XMMRegister dst, XMMRegister src, RoundingMode mode) {
    vinstr(0x09, dst, xmm0, src, k66, k0F3A, kWIG);
    emit(static_cast<uint8_t>(mode) | 0x8);  // Mask precision exception.
  }
  void vroundpd(YMMRegister dst, YMMRegister src, RoundingMode mode) {
    vinstr(0x09, dst, ymm0, src, k66, k0F3A, kWIG, AVX);
    emit(static_cast<uint8_t>(mode) | 0x8);  // Mask precision exception.
  }

  template <typename Reg, typename Op>
  void vsd(uint8_t op, Reg dst, Reg src1, Op src2) {
    vinstr(op, dst, src1, src2, kF2, k0F, kWIG, AVX);
  }

  void vmovss(XMMRegister dst, XMMRegister src1, XMMRegister src2) {
    vss(0x10, dst, src1, src2);
  }
  void vmovss(XMMRegister dst, Operand src) { vss(0x10, dst, xmm0, src); }
  void vmovss(Operand dst, XMMRegister src) { vss(0x11, src, xmm0, dst); }
  void vucomiss(XMMRegister dst, XMMRegister src);
  void vucomiss(XMMRegister dst, Operand src);
  void vss(uint8_t op, XMMRegister dst, XMMRegister src1, XMMRegister src2);
  void vss(uint8_t op, XMMRegister dst, XMMRegister src1, Operand src2);

  void vshufps(XMMRegister dst, XMMRegister src1, XMMRegister src2,
               uint8_t imm8) {
    vps(0xC6, dst, src1, src2, imm8);
  }
  void vshufps(YMMRegister dst, YMMRegister src1, YMMRegister src2,
               uint8_t imm8) {
    vps(0xC6, dst, src1, src2, imm8);
  }

  void vmovaps(XMMRegister dst, XMMRegister src) { vps(0x28, dst, xmm0, src); }
  void vmovaps(YMMRegister dst, YMMRegister src) { vps(0x28, dst, ymm0, src); }
  void vmovaps(XMMRegister dst, Operand src) { vps(0x28, dst, xmm0, src); }
  void vmovaps(YMMRegister dst, Operand src) { vps(0x28, dst, ymm0, src); }
  void vmovups(XMMRegister dst, XMMRegister src) { vps(0x10, dst, xmm0, src); }
  void vmovups(YMMRegister dst, YMMRegister src) { vps(0x10, dst, ymm0, src); }
  void vmovups(XMMRegister dst, Operand src) { vps(0x10, dst, xmm0, src); }
  void vmovups(YMMRegister dst, Operand src) { vps(0x10, dst, ymm0, src); }
  void vmovups(Operand dst, XMMRegister src) { vps(0x11, src, xmm0, dst); }
  void vmovups(Operand dst, YMMRegister src) { vps(0x11, src, ymm0, dst); }
  void vmovapd(XMMRegister dst, XMMRegister src) { vpd(0x28, dst, xmm0, src); }
  void vmovapd(YMMRegister dst, YMMRegister src) { vpd(0x28, dst, ymm0, src); }
  void vmovupd(XMMRegister dst, Operand src) { vpd(0x10, dst, xmm0, src); }
  void vmovupd(YMMRegister dst, Operand src) { vpd(0x10, dst, ymm0, src); }
  void vmovupd(Operand dst, XMMRegister src) { vpd(0x11, src, xmm0, dst); }
  void vmovupd(Operand dst, YMMRegister src) { vpd(0x11, src, ymm0, dst); }
  void vmovmskps(Register dst, XMMRegister src) {
    XMMRegister idst = XMMRegister::from_code(dst.code());
    vps(0x50, idst, xmm0, src);
  }
  void vmovmskpd(Register dst, XMMRegister src) {
    XMMRegister idst = XMMRegister::from_code(dst.code());
    vpd(0x50, idst, xmm0, src);
  }
  void vpmovmskb(Register dst, XMMRegister src);
  void vcmpeqss(XMMRegister dst, XMMRegister src) {
    vss(0xC2, dst, dst, src);
    emit(0x00);  // EQ == 0
  }
  void vcmpeqsd(XMMRegister dst, XMMRegister src) {
    vsd(0xC2, dst, dst, src);
    emit(0x00);  // EQ == 0
  }
  void vcmpps(XMMRegister dst, XMMRegister src1, XMMRegister src2, int8_t cmp) {
    vps(0xC2, dst, src1, src2);
    emit(cmp);
  }
  void vcmpps(YMMRegister dst, YMMRegister src1, YMMRegister src2, int8_t cmp) {
    vps(0xC2, dst, src1, src2);
    emit(cmp);
  }
  void vcmpps(XMMRegister dst, XMMRegister src1, Operand src2, int8_t cmp) {
    vps(0xC2, dst, src1, src2);
    emit(cmp);
  }
  void vcmpps(YMMRegister dst, YMMRegister src1, Operand src2, int8_t cmp) {
    vps(0xC2, dst, src1, src2);
    emit(cmp);
  }
  void vcmppd(XMMRegister dst, XMMRegister src1, XMMRegister src2, int8_t cmp) {
    vpd(0xC2, dst, src1, src2);
    emit(cmp);
  }
  void vcmppd(YMMRegister dst, YMMRegister src1, YMMRegister src2, int8_t cmp) {
    vpd(0xC2, dst, src1, src2);
    emit(cmp);
  }
  void vcmppd(XMMRegister dst, XMMRegister src1, Operand src2, int8_t cmp) {
    vpd(0xC2, dst, src1, src2);
    emit(cmp);
  }
  void vcmppd(YMMRegister dst, YMMRegister src1, Operand src2, int8_t cmp) {
    vpd(0xC2, dst, src1, src2);
    emit(cmp);
  }
#define AVX_CMP_P(instr, imm8, SIMDRegister)                               \
  void instr##ps(SIMDRegister dst, SIMDRegister src1, SIMDRegister src2) { \
    vcmpps(dst, src1, src2, imm8);                                         \
  }                                                                        \
  void instr##ps(SIMDRegister dst, SIMDRegister src1, Operand src2) {      \
    vcmpps(dst, src1, src2, imm8);                                         \
  }                                                                        \
  void instr##pd(SIMDRegister dst, SIMDRegister src1, SIMDRegister src2) { \
    vcmppd(dst, src1, src2, imm8);                                         \
  }                                                                        \
  void instr##pd(SIMDRegister dst, SIMDRegister src1, Operand src2) {      \
    vcmppd(dst, src1, src2, imm8);                                         \
  }

  AVX_CMP_P(vcmpeq, 0x0, XMMRegister)
  AVX_CMP_P(vcmpeq, 0x0, YMMRegister)
  AVX_CMP_P(vcmplt, 0x1, XMMRegister)
  AVX_CMP_P(vcmplt, 0x1, YMMRegister)
  AVX_CMP_P(vcmple, 0x2, XMMRegister)
  AVX_CMP_P(vcmple, 0x2, YMMRegister)
  AVX_CMP_P(vcmpunord, 0x3, XMMRegister)
  AVX_CMP_P(vcmpunord, 0x3, YMMRegister)
  AVX_CMP_P(vcmpneq, 0x4, XMMRegister)
  AVX_CMP_P(vcmpneq, 0x4, YMMRegister)
  AVX_CMP_P(vcmpnlt, 0x5, XMMRegister)
  AVX_CMP_P(vcmpnlt, 0x5, YMMRegister)
  AVX_CMP_P(vcmpnle, 0x6, XMMRegister)
  AVX_CMP_P(vcmpnle, 0x6, YMMRegister)
  AVX_CMP_P(vcmpge, 0xd, XMMRegister)
  AVX_CMP_P(vcmpge, 0xd, YMMRegister)

#undef AVX_CMP_P

  void vlddqu(XMMRegister dst, Operand src) {
    vinstr(0xF0, dst, xmm0, src, kF2, k0F, kWIG);
  }
  void vinsertps(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                 uint8_t imm8) {
    vinstr(0x21, dst, src1, src2, k66, k0F3A, kWIG);
    emit(imm8);
  }
  void vinsertps(XMMRegister dst, XMMRegister src1, Operand src2,
                 uint8_t imm8) {
    vinstr(0x21, dst, src1, src2, k66, k0F3A, kWIG);
    emit(imm8);
  }
  void vpextrq(Register dst, XMMRegister src, int8_t imm8) {
    XMMRegister idst = XMMRegister::from_code(dst.code());
    vinstr(0x16, src, xmm0, idst, k66, k0F3A, kW1);
    emit(imm8);
  }
  void vpinsrb(XMMRegister dst, XMMRegister src1, Register src2, uint8_t imm8) {
    XMMRegister isrc = XMMRegister::from_code(src2.code());
    vinstr(0x20, dst, src1, isrc, k66, k0F3A, kW0);
    emit(imm8);
  }
  void vpinsrb(XMMRegister dst, XMMRegister src1, Operand src2, uint8_t imm8) {
    vinstr(0x20, dst, src1, src2, k66, k0F3A, kW0);
    emit(imm8);
  }
  void vpinsrw(XMMRegister dst, XMMRegister src1, Register src2, uint8_t imm8) {
    XMMRegister isrc = XMMRegister::from_code(src2.code());
    vinstr(0xc4, dst, src1, isrc, k66, k0F, kW0);
    emit(imm8);
  }
  void vpinsrw(XMMRegister dst, XMMRegister src1, Operand src2, uint8_t imm8) {
    vinstr(0xc4, dst, src1, src2, k66, k0F, kW0);
    emit(imm8);
  }
  void vpinsrd(XMMRegister dst, XMMRegister src1, Register src2, uint8_t imm8) {
    XMMRegister isrc = XMMRegister::from_code(src2.code());
    vinstr(0x22, dst, src1, isrc, k66, k0F3A, kW0);
    emit(imm8);
  }
  void vpinsrd(XMMRegister dst, XMMRegister src1, Operand src2, uint8_t imm8) {
    vinstr(0x22, dst, src1, src2, k66, k0F3A, kW0);
    emit(imm8);
  }
  void vpinsrq(XMMRegister dst, XMMRegister src1, Register src2, uint8_t imm8) {
    XMMRegister isrc = XMMRegister::from_code(src2.code());
    vinstr(0x22, dst, src1, isrc, k66, k0F3A, kW1);
    emit(imm8);
  }
  void vpinsrq(XMMRegister dst, XMMRegister src1, Operand src2, uint8_t imm8) {
    vinstr(0x22, dst, src1, src2, k66, k0F3A, kW1);
    emit(imm8);
  }

  void vpshufd(XMMRegister dst, XMMRegister src, uint8_t imm8) {
    vinstr(0x70, dst, xmm0, src, k66, k0F, kWIG);
    emit(imm8);
  }
  void vpshufd(YMMRegister dst, YMMRegister src, uint8_t imm8) {
    vinstr(0x70, dst, ymm0, src, k66, k0F, kWIG);
    emit(imm8);
  }
  void vpshufd(XMMRegister dst, Operand src, uint8_t imm8) {
    vinstr(0x70, dst, xmm0, src, k66, k0F, kWIG);
    emit(imm8);
  }
  void vpshufd(YMMRegister dst, Operand src, uint8_t imm8) {
    vinstr(0x70, dst, ymm0, src, k66, k0F, kWIG);
    emit(imm8);
  }
  void vpshuflw(XMMRegister dst, XMMRegister src, uint8_t imm8) {
    vinstr(0x70, dst, xmm0, src, kF2, k0F, kWIG);
    emit(imm8);
  }
  void vpshuflw(YMMRegister dst, YMMRegister src, uint8_t imm8) {
    vinstr(0x70, dst, ymm0, src, kF2, k0F, kWIG);
    emit(imm8);
  }
  void vpshuflw(XMMRegister dst, Operand src, uint8_t imm8) {
    vinstr(0x70, dst, xmm0, src, kF2, k0F, kWIG);
    emit(imm8);
  }
  void vpshuflw(YMMRegister dst, Operand src, uint8_t imm8) {
    vinstr(0x70, dst, ymm0, src, kF2, k0F, kWIG);
    emit(imm8);
  }
  void vpshufhw(XMMRegister dst, XMMRegister src, uint8_t imm8) {
    vinstr(0x70, dst, xmm0, src, kF3, k0F, kWIG);
    emit(imm8);
  }
  void vpshufhw(YMMRegister dst, YMMRegister src, uint8_t imm8) {
    vinstr(0x70, dst, ymm0, src, kF3, k0F, kWIG);
    emit(imm8);
  }
  void vpshufhw(XMMRegister dst, Operand src, uint8_t imm8) {
    vinstr(0x70, dst, xmm0, src, kF3, k0F, kWIG);
    emit(imm8);
  }
  void vpshufhw(YMMRegister dst, Operand src, uint8_t imm8) {
    vinstr(0x70, dst, ymm0, src, kF3, k0F, kWIG);
    emit(imm8);
  }

  void vpblendw(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                uint8_t mask) {
    vinstr(0x0E, dst, src1, src2, k66, k0F3A, kWIG);
    emit(mask);
  }
  void vpblendw(YMMRegister dst, YMMRegister src1, YMMRegister src2,
                uint8_t mask) {
    vinstr(0x0E, dst, src1, src2, k66, k0F3A, kWIG);
    emit(mask);
  }
  void vpblendw(XMMRegister dst, XMMRegister src1, Operand src2, uint8_t mask) {
    vinstr(0x0E, dst, src1, src2, k66, k0F3A, kWIG);
    emit(mask);
  }
  void vpblendw(YMMRegister dst, YMMRegister src1, Operand src2, uint8_t mask) {
    vinstr(0x0E, dst, src1, src2, k66, k0F3A, kWIG);
    emit(mask);
  }

  void vpalignr(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                uint8_t imm8) {
    vinstr(0x0F, dst, src1, src2, k66, k0F3A, kWIG);
    emit(imm8);
  }
  void vpalignr(YMMRegister dst, YMMRegister src1, YMMRegister src2,
                uint8_t imm8) {
    vinstr(0x0F, dst, src1, src2, k66, k0F3A, kWIG);
    emit(imm8);
  }
  void vpalignr(XMMRegister dst, XMMRegister src1, Operand src2, uint8_t imm8) {
    vinstr(0x0F, dst, src1, src2, k66, k0F3A, kWIG);
    emit(imm8);
  }
  void vpalignr(YMMRegister dst, YMMRegister src1, Operand src2, uint8_t imm8) {
    vinstr(0x0F, dst, src1, src2, k66, k0F3A, kWIG);
    emit(imm8);
  }

  void vps(uint8_t op, XMMRegister dst, XMMRegister src1, XMMRegister src2);
  void vps(uint8_t op, YMMRegister dst, YMMRegister src1, YMMRegister src2);
  void vps(uint8_t op, XMMRegister dst, XMMRegister src1, Operand src2);
  void vps(uint8_t op, YMMRegister dst, YMMRegister src1, Operand src2);
  void vps(uint8_t op, XMMRegister dst, XMMRegister src1, XMMRegister src2,
           uint8_t imm8);
  void vps(uint8_t op, YMMRegister dst, YMMRegister src1, YMMRegister src2,
           uint8_t imm8);
  void vpd(uint8_t op, XMMRegister dst, XMMRegister src1, XMMRegister src2);
  void vpd(uint8_t op, YMMRegister dst, YMMRegister src1, YMMRegister src2);
  void vpd(uint8_t op, XMMRegister dst, YMMRegister src1, YMMRegister src2);
  void vpd(uint8_t op, XMMRegister dst, XMMRegister src1, Operand src2);
  void vpd(uint8_t op, YMMRegister dst, YMMRegister src1, Operand src2);
  void vpd(uint8_t op, XMMRegister dst, YMMRegister src1, Operand src2);

  // AVX2 instructions
#define AVX2_INSTRUCTION(instr, prefix, escape1, escape2, opcode)           \
  template <typename Reg, typename Op>                                      \
  void instr(Reg dst, Op src) {                                             \
    vinstr(0x##opcode, dst, xmm0, src, k##prefix, k##escape1##escape2, kW0, \
           AVX2);                                                           \
  }
  AVX2_BROADCAST_LIST(AVX2_INSTRUCTION)
#undef AVX2_INSTRUCTION

  // F16C Instructions.
  void vcvtph2ps(XMMRegister dst, XMMRegister src);
  void vcvtph2ps(YMMRegister dst, XMMRegister src);
  void vcvtps2ph(XMMRegister dst, XMMRegister src, uint8_t imm8);
  void vcvtps2ph(XMMRegister dst, YMMRegister src, uint8_t imm8);

  // AVX-VNNI instruction
  void vpdpbusd(XMMRegister dst, XMMRegister src1, XMMRegister src2) {
    vinstr(0x50, dst, src1, src2, k66, k0F38, kW0, AVX_VNNI);
  }
  void vpdpbusd(YMMRegister dst, YMMRegister src1, YMMRegister src2) {
    vinstr(0x50, dst, src1, src2, k66, k0F38, kW0, AVX_VNNI);
  }

  // AVX-VNNI-INT8 instruction
  void vpdpbssd(XMMRegister dst, XMMRegister src1, XMMRegister src2) {
    vinstr(0x50, dst, src1, src2, kF2, k0F38, kW0, AVX_VNNI_INT8);
  }
  void vpdpbssd(YMMRegister dst, YMMRegister src1, YMMRegister src2) {
    vinstr(0x50, dst, src1, src2, kF2, k0F38, kW0, AVX_VNNI_INT8);
  }

  // BMI instruction
  void andnq(Register dst, Register src1, Register src2) {
    bmi1q(0xf2, dst, src1, src2);
  }
  void andnq(Register dst, Register src1, Operand src2) {
    bmi1q(0xf2, dst, src1, src2);
  }
  void andnl(Register dst, Register src1, Register src2) {
    bmi1l(0xf2, dst, src1, src2);
  }
  void andnl(Register dst, Register src1, Operand src2) {
    bmi1l(0xf2, dst, src1, src2);
  }
  void bextrq(Register dst, Register src1, Register src2) {
    bmi1q(0xf7, dst, src2, src1);
  }
  void bextrq(Register dst, Operand src1, Register src2) {
    bmi1q(0xf7, dst, src2, src1);
  }
  void bextrl(Register dst, Register src1, Register src2) {
    bmi1l(0xf7, dst, src2, src1);
  }
  void bextrl(Register dst, Operand src1, Register src2) {
    bmi1l(0xf7, dst, src2, src1);
  }
  void blsiq(Register dst, Register src) { bmi1q(0xf3, rbx, dst, src); }
  void blsiq(Register dst, Operand src) { bmi1q(0xf3, rbx, dst, src); }
  void blsil(Register dst, Register src) { bmi1l(0xf3, rbx, dst, src); }
  void blsil(Register dst, Operand src) { bmi1l(0xf3, rbx, dst, src); }
  void blsmskq(Register dst, Register src) { bmi1q(0xf3, rdx, dst, src); }
  void blsmskq(Register dst, Operand src) { bmi1q(0xf3, rdx, dst, src); }
  void blsmskl(Register dst, Register src) { bmi1l(0xf3, rdx, dst, src); }
  void blsmskl(Register dst, Operand src) { bmi1l(0xf3, rdx, dst, src); }
  void blsrq(Register dst, Register src) { bmi1q(0xf3, rcx, dst, src); }
  void blsrq(Register dst, Operand src) { bmi1q(0xf3, rcx, dst, src); }
  void blsrl(Register dst, Register src) { bmi1l(0xf3, rcx, dst, src); }
  void blsrl(Register dst, Operand src) { bmi1l(0xf3, rcx, dst, src); }
  void tzcntq(Register dst, Register src);
  void tzcntq(Register dst, Operand src);
  void tzcntl(Register dst, Register src);
  void tzcntl(Register dst, Operand src);

  void lzcntq(Register dst, Register src);
  void lzcntq(Register dst, Operand src);
  void lzcntl(Register dst, Register src);
  void lzcntl(Register dst, Operand src);

  void popcntq(Register dst, Register src);
  void popcntq(Register dst, Operand src);
  void popcntl(Register dst, Register src);
  void popcntl(Register dst, Operand src);

  void bzhiq(Register dst, Register src1, Register src2) {
    bmi2q(kNoPrefix, 0xf5, dst, src2, src1);
  }
  void bzhiq(Register dst, Operand src1, Register src2) {
    bmi2q(kNoPrefix, 0xf5, dst, src2, src1);
  }
  void bzhil(Register dst, Register src1, Register src2) {
    bmi2l(kNoPrefix, 0xf5, dst, src2, src1);
  }
  void bzhil(Register dst, Operand src1, Register src2) {
    bmi2l(kNoPrefix, 0xf5, dst, src2, src1);
  }
  void mulxq(Register dst1, Register dst2, Register src) {
    bmi2q(kF2, 0xf6, dst1, dst2, src);
  }
  void mulxq(Register dst1, Register dst2, Operand src) {
    bmi2q(kF2, 0xf6, dst1, dst2, src);
  }
  void mulxl(Register dst1, Register dst2, Register src) {
    bmi2l(kF2, 0xf6, dst1, dst2, src);
  }
  void mulxl(Register dst1, Register dst2, Operand src) {
    bmi2l(kF2, 0xf6, dst1, dst2, src);
  }
  void pdepq(Register dst, Register src1, Register src2) {
    bmi2q(kF2, 0xf5, dst, src1, src2);
  }
  void pdepq(Register dst, Register src1, Operand src2) {
    bmi2q(kF2, 0xf5, dst, src1, src2);
  }
  void pdepl(Register dst, Register src1, Register src2) {
    bmi2l(kF2, 0xf5, dst, src1, src2);
  }
  void pdepl(Register dst, Register src1, Operand src2) {
    bmi2l(kF2, 0xf5, dst, src1, src2);
  }
  void pextq(Register dst, Register src1, Register src2) {
    bmi2q(kF3, 0xf5, dst, src1, src2);
  }
  void pextq(Register dst, Register src1, Operand src2) {
    bmi2q(kF3, 0xf5, dst, src1, src2);
  }
  void pextl(Register dst, Register src1, Register src2) {
    bmi2l(kF3, 0xf5, dst, src1, src2);
  }
  void pextl(Register dst, Register src1, Operand src2) {
    bmi2l(kF3, 0xf5, dst, src1, src2);
  }
  void sarxq(Register dst, Register src1, Register src2) {
    bmi2q(kF3, 0xf7, dst, src2, src1);
  }
  void sarxq(Register dst, Operand src1, Register src2) {
    bmi2q(kF3, 0xf7, dst, src2, src1);
  }
  void sarxl(Register dst, Register src1, Register src2) {
    bmi2l(kF3, 0xf7, dst, src2, src1);
  }
  void sarxl(Register dst, Operand src1, Register src2) {
    bmi2l(kF3, 0xf7, dst, src2, src1);
  }
  void shlxq(Register dst, Register src1, Register src2) {
    bmi2q(k66, 0xf7, dst, src2, src1);
  }
  void shlxq(Register dst, Operand src1, Register src2) {
    bmi2q(k66, 0xf7, dst, src2, src1);
  }
  void shlxl(Register dst, Register src1, Register src2) {
    bmi2l(k66, 0xf7, dst, src2, src1);
  }
  void shlxl(Register dst, Operand src1, Register src2) {
    bmi2l(k66, 0xf7, dst, src2, src1);
  }
  void shrxq(Register dst, Register src1, Register src2) {
    bmi2q(kF2, 0xf7, dst, src2, src1);
  }
  void shrxq(Register dst, Operand src1, Register src2) {
    bmi2q(kF2, 0xf7, dst, src2, src1);
  }
  void shrxl(Register dst, Register src1, Register src2) {
    bmi2l(kF2, 0xf7, dst, src2, src1);
  }
  void shrxl(Register dst, Operand src1, Register src2) {
    bmi2l(kF2, 0xf7, dst, src2, src1);
  }
  void rorxq(Register dst, Register src, uint8_t imm8);
  void rorxq(Register dst, Operand src, uint8_t imm8);
  void rorxl(Register dst, Register src, uint8_t imm8);
  void rorxl(Register dst, Operand src, uint8_t imm8);

  void mfence();
  void lfence();
  void pause();

  // Check the code size generated from label to here.
  int SizeOfCodeGeneratedSince(Label* label) {
    return pc_offset() - label->pos();
  }

  // Record a deoptimization reason that can be used by a log o
```