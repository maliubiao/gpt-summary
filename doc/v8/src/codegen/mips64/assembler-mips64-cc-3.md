Response:
The user wants a summary of the provided C++ code snippet. The code is part of the V8 JavaScript engine and specifically targets the MIPS64 architecture.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The filename `assembler-mips64.cc` and the code itself strongly suggest it's responsible for generating MIPS64 machine code.

2. **Analyze the function names:** Look for patterns and common prefixes. Functions like `add_s`, `sub_d`, `cvt_w_s` clearly indicate operations on floating-point numbers with single-precision (s) and double-precision (d) formats. Similarly, `ld_w`, `st_b` suggest load and store operations. The "MSA" prefixed functions indicate instructions related to the MIPS SIMD Architecture (MSA).

3. **Understand the `GenInstrRegister` function:** This seems like a helper function to generate MIPS instructions, taking opcodes and register operands as input.

4. **Categorize the functionalities:** Group the functions based on the type of operation they perform (e.g., arithmetic, conversions, comparisons, loads/stores, branches). Pay attention to different instruction sets like FPU and MSA.

5. **Address specific questions from the prompt:**
    * `.tq` extension: This part is explicitly answered - the code doesn't have a `.tq` extension.
    * Relation to JavaScript:  Consider how these low-level instructions are used in the context of a JavaScript engine (number processing, array manipulation, etc.).
    * JavaScript examples:  Create simple JavaScript code snippets that would likely involve the kinds of operations defined in the C++ code.
    * Code logic and assumptions: Focus on the conditional logic related to different MIPS architecture versions (e.g., `kArchVariant == kMips64r6`). Infer the input and output of functions based on their names and parameters.
    * Common programming errors: Think about how misuse of these low-level instructions or misunderstandings about data types could lead to errors.
    *归纳功能 (Summarize function): Provide a high-level overview of the code's role within V8.

6. **Structure the answer:** Organize the findings logically, addressing each part of the user's prompt.

**Self-Correction/Refinement during thought process:**

* Initially, I might focus too much on individual instruction details. It's important to step back and see the bigger picture of the file's purpose.
* The prompt specifically asks about the file *as a whole*. While individual function explanations are necessary, the summary should encompass the overall functionality.
* When providing JavaScript examples, make them as directly related as possible to the C++ function names. Avoid overly complex or abstract examples.
* The prompt mentions "第4部分，共5部分". This suggests there are other related files. While summarizing this file, keep in mind it's a component within a larger system. The歸納功能 should reflect this.
这是一个V8源代码文件，位于 `v8/src/codegen/mips64/` 目录下，名为 `assembler-mips64.cc`。根据提供的代码片段，可以归纳出以下功能：

**主要功能：MIPS64 汇编代码生成**

这个文件定义了 `Assembler` 类的一部分，专门用于生成 MIPS64 架构的机器码指令。它提供了一系列方法，每个方法对应一条或一组 MIPS64 汇编指令。这些指令主要涵盖以下几个方面：

1. **浮点运算指令 (FPU Instructions):**
   - **基本运算:**  加 (`add_s`, `add_d`)、减 (`sub_s`, `sub_d`)、乘 (`mul_s`, `mul_d`)、除 (`div_s`, `div_d`)、绝对值 (`abs_s`, `abs_d`)、取反 (`neg_s`, `neg_d`)、平方根 (`sqrt_s`, `sqrt_d`)、倒数平方根 (`rsqrt_s`, `rsqrt_d`)、倒数 (`recip_s`, `recip_d`)。
   - **数据移动:**  浮点寄存器之间的数据移动 (`mov_s`, `mov_d`)。
   - **类型转换:**  浮点数与整数之间的转换 (`cvt_w_s`, `cvt_w_d`, `cvt_l_s`, `cvt_l_d`, `cvt_s_w`, `cvt_s_l`, `cvt_s_d`, `cvt_d_w`, `cvt_d_l`, `cvt_d_s`)，以及各种舍入模式的转换 (`trunc_w_s`, `round_w_s`, `floor_w_s`, `ceil_w_s`, `trunc_l_s` 等)。
   - **比较指令:**  浮点数之间的比较 (`c_s`, `c_d`, `cmp_s`, `cmp_d`)，以及与零的比较 (`bc1eqz`, `bc1nez`)。
   - **其他:**  例如，`class_s`, `class_d` 用于获取浮点数的类型信息，`mina`, `maxa` 用于取最小值和最大值。

2. **MSA (MIPS SIMD Architecture) 指令:**
   - **加载/存储:**  从内存加载数据到 MSA 寄存器 (`ld_b`, `ld_h`, `ld_w`, `ld_d`)，以及将 MSA 寄存器中的数据存储到内存 (`st_b`, `st_h`, `st_w`, `st_d`)。
   - **立即数加载:**  将立即数加载到 MSA 寄存器 (`ldi_b`, `ldi_h`, `ldi_w`, `ldi_d`)。
   - **向量运算:**  各种向量算术运算 (`addvi`, `subvi`, `mulv`, `div_s`, `div_u` 等)、逻辑运算 (`and_v`, `or_v`, `xor_v` 等)、比较运算 (`ceqi`, `clti_s`, `clei_s`, `ceq`, `clt_s`, `cle_s` 等)。
   - **位操作:**  对 MSA 寄存器中的位进行操作 (`slli`, `srai`, `srli`, `bclri`, `bseti` 等)。
   - **数据重排:**  例如 `sld`, `splat`, `pckev`, `pckod`, `ilvl`, `ilvr` 等指令用于向量元素的选择、复制和重组。
   - **浮点 MSA 运算:**  MSA 版本的浮点运算指令 (`fadd_w`, `fsub_w`, `fmul_w`, `fdiv_w` 等)。
   - **控制寄存器操作:**  用于读写 MSA 控制寄存器 (`ctcmsa`, `cfcmsa`)。
   - **分支指令:**  基于 MSA 寄存器的状态进行分支 (`bz_v`, `bnz_v` 等)。

3. **内部引用重定位:**
   - `RelocateInternalReference` 函数用于在代码生成后，对内部引用进行重定位，例如跳转目标地址的更新。

4. **缓冲区管理:**
   - `GrowBuffer` 函数用于在需要更多空间时，动态扩展汇编器内部的缓冲区。

5. **数据发射:**
   - `db`, `dd`, `dq` 等函数用于将字节、双字、四字等数据直接写入到汇编器的缓冲区中。

6. **标签处理:**
   - 使用 `Label` 类来标记代码位置，并支持在代码中跳转到这些标签。

7. **代码块和安全点管理:**
   - 涉及到 `BlockTrampolinePoolScope` 和 `BlockTrampolinePoolFor` 等机制，用于管理跳转指令的范围和确保在需要时插入跳转表（trampoline pool）。

**关于 .tq 结尾：**

如果 `v8/src/codegen/mips64/assembler-mips64.cc` 以 `.tq` 结尾，那么它会是一个 **Torque** 源代码文件。Torque 是 V8 用来生成高效的内置函数和运行时代码的领域特定语言。当前的 `.cc` 结尾表示这是一个标准的 C++ 源代码文件。

**与 JavaScript 的关系：**

`assembler-mips64.cc` 中定义的汇编指令生成方法是 V8 JavaScript 引擎在 MIPS64 架构上执行 JavaScript 代码的关键组成部分。当 V8 编译 JavaScript 代码时，它会将高级的 JavaScript 代码转换为底层的 MIPS64 汇编指令，然后由 CPU 执行。

**JavaScript 例子：**

以下是一些 JavaScript 例子，它们背后的执行可能涉及到 `assembler-mips64.cc` 中定义的指令：

```javascript
// 浮点运算
let a = 1.5;
let b = 2.5;
let sum = a + b;  // 可能用到 add_s 或 add_d
let product = a * b; // 可能用到 mul_s 或 mul_d
let sqrt_a = Math.sqrt(a); // 可能用到 sqrt_s 或 sqrt_d

// 类型转换
let int_val = parseInt(a); // 可能用到 trunc_w_s 或 floor_w_s 等
let float_val = parseFloat(int_val); // 可能用到 cvt_s_w 或 cvt_d_w

// 数组和向量操作（可能涉及 MSA 指令）
let arr1 = [1, 2, 3, 4];
let arr2 = [5, 6, 7, 8];
// 某些 JavaScript 引擎可能会使用 SIMD 指令来加速数组运算
// 例如，将两个数组的元素相加
// 在底层可能用到 MSA 的 addv 指令

// 条件判断
if (a > b) {
  console.log("a is greater than b"); // 可能用到 c_s 或 c_d 进行比较
}
```

**代码逻辑推理 (假设输入与输出):**

假设我们调用 `assembler->add_d(f2, f4, f6)`，其中 `f2`, `f4`, `f6` 是代表 MIPS64 浮点寄存器的枚举值。

* **假设输入:**
    * `fd` (目标寄存器): `f2`
    * `fs` (源寄存器 1): `f4`
    * `ft` (源寄存器 2): `f6`

* **代码逻辑:**  `add_d` 函数会调用 `GenInstrRegister(COP1, D, ft, fs, fd, ADD_D)`。 `GenInstrRegister` 函数会将这些参数编码成一个 MIPS64 的机器码指令，该指令执行的操作是将寄存器 `f4` 和 `f6` 中的双精度浮点数相加，结果存储到寄存器 `f2` 中。

* **可能的输出 (生成的机器码):**  具体生成的机器码会是一个 32 位的整数，其各个位域分别代表操作码、寄存器编号等信息。例如，可能类似于 `0b010001_01100_01000_00010_00000_000010` (这只是一个示例，实际编码会根据 MIPS64 指令格式而定)。

**用户常见的编程错误：**

在与汇编代码生成相关的编程中，常见的错误包括：

1. **寄存器类型不匹配：** 错误地将整数寄存器用于浮点运算，或者反之。例如，在应该使用 `FPURegister` 的地方使用了 `Register`。
2. **指令操作数错误：**  为指令提供了错误数量或类型的操作数。例如，某些 MSA 指令要求特定的数据格式，如果提供的数据格式不正确，会导致错误。
3. **内存访问错误：**  使用错误的地址或偏移量进行内存加载或存储，导致访问无效内存。例如，在计算 `MemOperand` 时出现错误。
4. **条件码使用错误：**  在分支指令中使用了错误的条件码，导致程序流程错误。
5. **忽视延迟槽：**  在早期的 MIPS 架构中，某些跳转指令后有一个延迟槽，需要放置一条不会影响跳转结果的指令。现代 MIPS 架构（如 MIPS64r6）已经取消了延迟槽，但在生成代码时需要注意目标架构的特性。
6. **未对齐的内存访问：**  某些架构对内存访问的对齐有要求。如果尝试访问未对齐的内存地址，可能会导致崩溃或性能下降。

**归纳其功能 (作为第 4 部分):**

作为一系列汇编器代码生成文件中的一部分，`v8/src/codegen/mips64/assembler-mips64.cc` 的主要功能是 **提供用于生成 MIPS64 架构上浮点运算和 MSA (SIMD) 指令的接口**。它是 V8 引擎在 MIPS64 平台上将高级代码转换为可执行机器码的关键组件，专注于处理浮点数和向量数据的运算和操作。它的存在使得 V8 能够高效地执行涉及到大量数值计算和数据并行处理的 JavaScript 代码。

Prompt: 
```
这是目录为v8/src/codegen/mips64/assembler-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/mips64/assembler-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能

"""
ister ft) {
  GenInstrRegister(COP1, D, ft, fs, fd, DIV_D);
}

void Assembler::abs_s(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, S, f0, fs, fd, ABS_D);
}

void Assembler::abs_d(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, D, f0, fs, fd, ABS_D);
}

void Assembler::mov_d(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, D, f0, fs, fd, MOV_D);
}

void Assembler::mov_s(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, S, f0, fs, fd, MOV_S);
}

void Assembler::neg_s(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, S, f0, fs, fd, NEG_D);
}

void Assembler::neg_d(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, D, f0, fs, fd, NEG_D);
}

void Assembler::sqrt_s(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, S, f0, fs, fd, SQRT_D);
}

void Assembler::sqrt_d(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, D, f0, fs, fd, SQRT_D);
}

void Assembler::rsqrt_s(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, S, f0, fs, fd, RSQRT_S);
}

void Assembler::rsqrt_d(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, D, f0, fs, fd, RSQRT_D);
}

void Assembler::recip_d(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, D, f0, fs, fd, RECIP_D);
}

void Assembler::recip_s(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, S, f0, fs, fd, RECIP_S);
}

// Conversions.
void Assembler::cvt_w_s(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, S, f0, fs, fd, CVT_W_S);
}

void Assembler::cvt_w_d(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, D, f0, fs, fd, CVT_W_D);
}

void Assembler::trunc_w_s(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, S, f0, fs, fd, TRUNC_W_S);
}

void Assembler::trunc_w_d(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, D, f0, fs, fd, TRUNC_W_D);
}

void Assembler::round_w_s(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, S, f0, fs, fd, ROUND_W_S);
}

void Assembler::round_w_d(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, D, f0, fs, fd, ROUND_W_D);
}

void Assembler::floor_w_s(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, S, f0, fs, fd, FLOOR_W_S);
}

void Assembler::floor_w_d(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, D, f0, fs, fd, FLOOR_W_D);
}

void Assembler::ceil_w_s(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, S, f0, fs, fd, CEIL_W_S);
}

void Assembler::ceil_w_d(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, D, f0, fs, fd, CEIL_W_D);
}

void Assembler::rint_s(FPURegister fd, FPURegister fs) { rint(S, fd, fs); }

void Assembler::rint_d(FPURegister fd, FPURegister fs) { rint(D, fd, fs); }

void Assembler::rint(SecondaryField fmt, FPURegister fd, FPURegister fs) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(COP1, fmt, f0, fs, fd, RINT);
}

void Assembler::cvt_l_s(FPURegister fd, FPURegister fs) {
  DCHECK(kArchVariant == kMips64r2 || kArchVariant == kMips64r6);
  GenInstrRegister(COP1, S, f0, fs, fd, CVT_L_S);
}

void Assembler::cvt_l_d(FPURegister fd, FPURegister fs) {
  DCHECK(kArchVariant == kMips64r2 || kArchVariant == kMips64r6);
  GenInstrRegister(COP1, D, f0, fs, fd, CVT_L_D);
}

void Assembler::trunc_l_s(FPURegister fd, FPURegister fs) {
  DCHECK(kArchVariant == kMips64r2 || kArchVariant == kMips64r6);
  GenInstrRegister(COP1, S, f0, fs, fd, TRUNC_L_S);
}

void Assembler::trunc_l_d(FPURegister fd, FPURegister fs) {
  DCHECK(kArchVariant == kMips64r2 || kArchVariant == kMips64r6);
  GenInstrRegister(COP1, D, f0, fs, fd, TRUNC_L_D);
}

void Assembler::round_l_s(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, S, f0, fs, fd, ROUND_L_S);
}

void Assembler::round_l_d(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, D, f0, fs, fd, ROUND_L_D);
}

void Assembler::floor_l_s(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, S, f0, fs, fd, FLOOR_L_S);
}

void Assembler::floor_l_d(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, D, f0, fs, fd, FLOOR_L_D);
}

void Assembler::ceil_l_s(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, S, f0, fs, fd, CEIL_L_S);
}

void Assembler::ceil_l_d(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, D, f0, fs, fd, CEIL_L_D);
}

void Assembler::class_s(FPURegister fd, FPURegister fs) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(COP1, S, f0, fs, fd, CLASS_S);
}

void Assembler::class_d(FPURegister fd, FPURegister fs) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  GenInstrRegister(COP1, D, f0, fs, fd, CLASS_D);
}

void Assembler::mina(SecondaryField fmt, FPURegister fd, FPURegister fs,
                     FPURegister ft) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK((fmt == D) || (fmt == S));
  GenInstrRegister(COP1, fmt, ft, fs, fd, MINA);
}

void Assembler::maxa(SecondaryField fmt, FPURegister fd, FPURegister fs,
                     FPURegister ft) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK((fmt == D) || (fmt == S));
  GenInstrRegister(COP1, fmt, ft, fs, fd, MAXA);
}

void Assembler::cvt_s_w(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, W, f0, fs, fd, CVT_S_W);
}

void Assembler::cvt_s_l(FPURegister fd, FPURegister fs) {
  DCHECK(kArchVariant == kMips64r2 || kArchVariant == kMips64r6);
  GenInstrRegister(COP1, L, f0, fs, fd, CVT_S_L);
}

void Assembler::cvt_s_d(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, D, f0, fs, fd, CVT_S_D);
}

void Assembler::cvt_d_w(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, W, f0, fs, fd, CVT_D_W);
}

void Assembler::cvt_d_l(FPURegister fd, FPURegister fs) {
  DCHECK(kArchVariant == kMips64r2 || kArchVariant == kMips64r6);
  GenInstrRegister(COP1, L, f0, fs, fd, CVT_D_L);
}

void Assembler::cvt_d_s(FPURegister fd, FPURegister fs) {
  GenInstrRegister(COP1, S, f0, fs, fd, CVT_D_S);
}

// Conditions for >= MIPSr6.
void Assembler::cmp(FPUCondition cond, SecondaryField fmt, FPURegister fd,
                    FPURegister fs, FPURegister ft) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  DCHECK_EQ(fmt & ~(31 << kRsShift), 0);
  Instr instr = COP1 | fmt | ft.code() << kFtShift | fs.code() << kFsShift |
                fd.code() << kFdShift | (0 << 5) | cond;
  emit(instr);
}

void Assembler::cmp_s(FPUCondition cond, FPURegister fd, FPURegister fs,
                      FPURegister ft) {
  cmp(cond, W, fd, fs, ft);
}

void Assembler::cmp_d(FPUCondition cond, FPURegister fd, FPURegister fs,
                      FPURegister ft) {
  cmp(cond, L, fd, fs, ft);
}

void Assembler::bc1eqz(int16_t offset, FPURegister ft) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Instr instr = COP1 | BC1EQZ | ft.code() << kFtShift | (offset & kImm16Mask);
  emit(instr);
  BlockTrampolinePoolFor(1);  // For associated delay slot.
}

void Assembler::bc1nez(int16_t offset, FPURegister ft) {
  DCHECK_EQ(kArchVariant, kMips64r6);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Instr instr = COP1 | BC1NEZ | ft.code() << kFtShift | (offset & kImm16Mask);
  emit(instr);
  BlockTrampolinePoolFor(1);  // For associated delay slot.
}

// Conditions for < MIPSr6.
void Assembler::c(FPUCondition cond, SecondaryField fmt, FPURegister fs,
                  FPURegister ft, uint16_t cc) {
  DCHECK_NE(kArchVariant, kMips64r6);
  DCHECK(is_uint3(cc));
  DCHECK(fmt == S || fmt == D);
  DCHECK_EQ(fmt & ~(31 << kRsShift), 0);
  Instr instr = COP1 | fmt | ft.code() << kFtShift | fs.code() << kFsShift |
                cc << 8 | 3 << 4 | cond;
  emit(instr);
}

void Assembler::c_s(FPUCondition cond, FPURegister fs, FPURegister ft,
                    uint16_t cc) {
  c(cond, S, fs, ft, cc);
}

void Assembler::c_d(FPUCondition cond, FPURegister fs, FPURegister ft,
                    uint16_t cc) {
  c(cond, D, fs, ft, cc);
}

void Assembler::fcmp(FPURegister src1, const double src2, FPUCondition cond) {
  DCHECK_EQ(src2, 0.0);
  mtc1(zero_reg, f14);
  cvt_d_w(f14, f14);
  c(cond, D, src1, f14, 0);
}

void Assembler::bc1f(int16_t offset, uint16_t cc) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  DCHECK(is_uint3(cc));
  Instr instr = COP1 | BC1 | cc << 18 | 0 << 16 | (offset & kImm16Mask);
  emit(instr);
  BlockTrampolinePoolFor(1);  // For associated delay slot.
}

void Assembler::bc1t(int16_t offset, uint16_t cc) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  DCHECK(is_uint3(cc));
  Instr instr = COP1 | BC1 | cc << 18 | 1 << 16 | (offset & kImm16Mask);
  emit(instr);
  BlockTrampolinePoolFor(1);  // For associated delay slot.
}

// ---------- MSA instructions ------------
#define MSA_BRANCH_LIST(V) \
  V(bz_v, BZ_V)            \
  V(bz_b, BZ_B)            \
  V(bz_h, BZ_H)            \
  V(bz_w, BZ_W)            \
  V(bz_d, BZ_D)            \
  V(bnz_v, BNZ_V)          \
  V(bnz_b, BNZ_B)          \
  V(bnz_h, BNZ_H)          \
  V(bnz_w, BNZ_W)          \
  V(bnz_d, BNZ_D)

#define MSA_BRANCH(name, opcode)                         \
  void Assembler::name(MSARegister wt, int16_t offset) { \
    GenInstrMsaBranch(opcode, wt, offset);               \
  }

MSA_BRANCH_LIST(MSA_BRANCH)
#undef MSA_BRANCH
#undef MSA_BRANCH_LIST

#define MSA_LD_ST_LIST(V) \
  V(ld_b, LD_B, 1)        \
  V(ld_h, LD_H, 2)        \
  V(ld_w, LD_W, 4)        \
  V(ld_d, LD_D, 8)        \
  V(st_b, ST_B, 1)        \
  V(st_h, ST_H, 2)        \
  V(st_w, ST_W, 4)        \
  V(st_d, ST_D, 8)

#define MSA_LD_ST(name, opcode, b)                                   \
  void Assembler::name(MSARegister wd, const MemOperand& rs) {       \
    MemOperand source = rs;                                          \
    AdjustBaseAndOffset(&source);                                    \
    if (is_int10(source.offset())) {                                 \
      DCHECK_EQ(source.offset() % b, 0);                             \
      GenInstrMsaMI10(opcode, source.offset() / b, source.rm(), wd); \
    } else {                                                         \
      UseScratchRegisterScope temps(this);                           \
      Register scratch = temps.Acquire();                            \
      DCHECK_NE(rs.rm(), scratch);                                   \
      daddiu(scratch, source.rm(), source.offset());                 \
      GenInstrMsaMI10(opcode, 0, scratch, wd);                       \
    }                                                                \
  }

MSA_LD_ST_LIST(MSA_LD_ST)
#undef MSA_LD_ST
#undef MSA_LD_ST_LIST

#define MSA_I10_LIST(V) \
  V(ldi_b, I5_DF_b)     \
  V(ldi_h, I5_DF_h)     \
  V(ldi_w, I5_DF_w)     \
  V(ldi_d, I5_DF_d)

#define MSA_I10(name, format)                           \
  void Assembler::name(MSARegister wd, int32_t imm10) { \
    GenInstrMsaI10(LDI, format, imm10, wd);             \
  }
MSA_I10_LIST(MSA_I10)
#undef MSA_I10
#undef MSA_I10_LIST

#define MSA_I5_LIST(V) \
  V(addvi, ADDVI)      \
  V(subvi, SUBVI)      \
  V(maxi_s, MAXI_S)    \
  V(maxi_u, MAXI_U)    \
  V(mini_s, MINI_S)    \
  V(mini_u, MINI_U)    \
  V(ceqi, CEQI)        \
  V(clti_s, CLTI_S)    \
  V(clti_u, CLTI_U)    \
  V(clei_s, CLEI_S)    \
  V(clei_u, CLEI_U)

#define MSA_I5_FORMAT(name, opcode, format)                       \
  void Assembler::name##_##format(MSARegister wd, MSARegister ws, \
                                  uint32_t imm5) {                \
    GenInstrMsaI5(opcode, I5_DF_##format, imm5, ws, wd);          \
  }

#define MSA_I5(name, opcode)     \
  MSA_I5_FORMAT(name, opcode, b) \
  MSA_I5_FORMAT(name, opcode, h) \
  MSA_I5_FORMAT(name, opcode, w) \
  MSA_I5_FORMAT(name, opcode, d)

MSA_I5_LIST(MSA_I5)
#undef MSA_I5
#undef MSA_I5_FORMAT
#undef MSA_I5_LIST

#define MSA_I8_LIST(V) \
  V(andi_b, ANDI_B)    \
  V(ori_b, ORI_B)      \
  V(nori_b, NORI_B)    \
  V(xori_b, XORI_B)    \
  V(bmnzi_b, BMNZI_B)  \
  V(bmzi_b, BMZI_B)    \
  V(bseli_b, BSELI_B)  \
  V(shf_b, SHF_B)      \
  V(shf_h, SHF_H)      \
  V(shf_w, SHF_W)

#define MSA_I8(name, opcode)                                            \
  void Assembler::name(MSARegister wd, MSARegister ws, uint32_t imm8) { \
    GenInstrMsaI8(opcode, imm8, ws, wd);                                \
  }

MSA_I8_LIST(MSA_I8)
#undef MSA_I8
#undef MSA_I8_LIST

#define MSA_VEC_LIST(V) \
  V(and_v, AND_V)       \
  V(or_v, OR_V)         \
  V(nor_v, NOR_V)       \
  V(xor_v, XOR_V)       \
  V(bmnz_v, BMNZ_V)     \
  V(bmz_v, BMZ_V)       \
  V(bsel_v, BSEL_V)

#define MSA_VEC(name, opcode)                                            \
  void Assembler::name(MSARegister wd, MSARegister ws, MSARegister wt) { \
    GenInstrMsaVec(opcode, wt, ws, wd);                                  \
  }

MSA_VEC_LIST(MSA_VEC)
#undef MSA_VEC
#undef MSA_VEC_LIST

#define MSA_2R_LIST(V) \
  V(pcnt, PCNT)        \
  V(nloc, NLOC)        \
  V(nlzc, NLZC)

#define MSA_2R_FORMAT(name, opcode, format)                         \
  void Assembler::name##_##format(MSARegister wd, MSARegister ws) { \
    GenInstrMsa2R(opcode, MSA_2R_DF_##format, ws, wd);              \
  }

#define MSA_2R(name, opcode)     \
  MSA_2R_FORMAT(name, opcode, b) \
  MSA_2R_FORMAT(name, opcode, h) \
  MSA_2R_FORMAT(name, opcode, w) \
  MSA_2R_FORMAT(name, opcode, d)

MSA_2R_LIST(MSA_2R)
#undef MSA_2R
#undef MSA_2R_FORMAT
#undef MSA_2R_LIST

#define MSA_FILL(format)                                              \
  void Assembler::fill_##format(MSARegister wd, Register rs) {        \
    DCHECK(IsEnabled(MIPS_SIMD));                                     \
    DCHECK(rs.is_valid() && wd.is_valid());                           \
    Instr instr = MSA | MSA_2R_FORMAT | FILL | MSA_2R_DF_##format |   \
                  (rs.code() << kWsShift) | (wd.code() << kWdShift) | \
                  MSA_VEC_2R_2RF_MINOR;                               \
    emit(instr);                                                      \
  }

MSA_FILL(b)
MSA_FILL(h)
MSA_FILL(w)
MSA_FILL(d)
#undef MSA_FILL

#define MSA_2RF_LIST(V) \
  V(fclass, FCLASS)     \
  V(ftrunc_s, FTRUNC_S) \
  V(ftrunc_u, FTRUNC_U) \
  V(fsqrt, FSQRT)       \
  V(frsqrt, FRSQRT)     \
  V(frcp, FRCP)         \
  V(frint, FRINT)       \
  V(flog2, FLOG2)       \
  V(fexupl, FEXUPL)     \
  V(fexupr, FEXUPR)     \
  V(ffql, FFQL)         \
  V(ffqr, FFQR)         \
  V(ftint_s, FTINT_S)   \
  V(ftint_u, FTINT_U)   \
  V(ffint_s, FFINT_S)   \
  V(ffint_u, FFINT_U)

#define MSA_2RF_FORMAT(name, opcode, format)                        \
  void Assembler::name##_##format(MSARegister wd, MSARegister ws) { \
    GenInstrMsa2RF(opcode, MSA_2RF_DF_##format, ws, wd);            \
  }

#define MSA_2RF(name, opcode)     \
  MSA_2RF_FORMAT(name, opcode, w) \
  MSA_2RF_FORMAT(name, opcode, d)

MSA_2RF_LIST(MSA_2RF)
#undef MSA_2RF
#undef MSA_2RF_FORMAT
#undef MSA_2RF_LIST

#define MSA_3R_LIST(V)  \
  V(sll, SLL_MSA)       \
  V(sra, SRA_MSA)       \
  V(srl, SRL_MSA)       \
  V(bclr, BCLR)         \
  V(bset, BSET)         \
  V(bneg, BNEG)         \
  V(binsl, BINSL)       \
  V(binsr, BINSR)       \
  V(addv, ADDV)         \
  V(subv, SUBV)         \
  V(max_s, MAX_S)       \
  V(max_u, MAX_U)       \
  V(min_s, MIN_S)       \
  V(min_u, MIN_U)       \
  V(max_a, MAX_A)       \
  V(min_a, MIN_A)       \
  V(ceq, CEQ)           \
  V(clt_s, CLT_S)       \
  V(clt_u, CLT_U)       \
  V(cle_s, CLE_S)       \
  V(cle_u, CLE_U)       \
  V(add_a, ADD_A)       \
  V(adds_a, ADDS_A)     \
  V(adds_s, ADDS_S)     \
  V(adds_u, ADDS_U)     \
  V(ave_s, AVE_S)       \
  V(ave_u, AVE_U)       \
  V(aver_s, AVER_S)     \
  V(aver_u, AVER_U)     \
  V(subs_s, SUBS_S)     \
  V(subs_u, SUBS_U)     \
  V(subsus_u, SUBSUS_U) \
  V(subsuu_s, SUBSUU_S) \
  V(asub_s, ASUB_S)     \
  V(asub_u, ASUB_U)     \
  V(mulv, MULV)         \
  V(maddv, MADDV)       \
  V(msubv, MSUBV)       \
  V(div_s, DIV_S_MSA)   \
  V(div_u, DIV_U)       \
  V(mod_s, MOD_S)       \
  V(mod_u, MOD_U)       \
  V(dotp_s, DOTP_S)     \
  V(dotp_u, DOTP_U)     \
  V(dpadd_s, DPADD_S)   \
  V(dpadd_u, DPADD_U)   \
  V(dpsub_s, DPSUB_S)   \
  V(dpsub_u, DPSUB_U)   \
  V(pckev, PCKEV)       \
  V(pckod, PCKOD)       \
  V(ilvl, ILVL)         \
  V(ilvr, ILVR)         \
  V(ilvev, ILVEV)       \
  V(ilvod, ILVOD)       \
  V(vshf, VSHF)         \
  V(srar, SRAR)         \
  V(srlr, SRLR)         \
  V(hadd_s, HADD_S)     \
  V(hadd_u, HADD_U)     \
  V(hsub_s, HSUB_S)     \
  V(hsub_u, HSUB_U)

#define MSA_3R_FORMAT(name, opcode, format)                             \
  void Assembler::name##_##format(MSARegister wd, MSARegister ws,       \
                                  MSARegister wt) {                     \
    GenInstrMsa3R<MSARegister>(opcode, MSA_3R_DF_##format, wt, ws, wd); \
  }

#define MSA_3R_FORMAT_SLD_SPLAT(name, opcode, format)                \
  void Assembler::name##_##format(MSARegister wd, MSARegister ws,    \
                                  Register rt) {                     \
    GenInstrMsa3R<Register>(opcode, MSA_3R_DF_##format, rt, ws, wd); \
  }

#define MSA_3R(name, opcode)     \
  MSA_3R_FORMAT(name, opcode, b) \
  MSA_3R_FORMAT(name, opcode, h) \
  MSA_3R_FORMAT(name, opcode, w) \
  MSA_3R_FORMAT(name, opcode, d)

#define MSA_3R_SLD_SPLAT(name, opcode)     \
  MSA_3R_FORMAT_SLD_SPLAT(name, opcode, b) \
  MSA_3R_FORMAT_SLD_SPLAT(name, opcode, h) \
  MSA_3R_FORMAT_SLD_SPLAT(name, opcode, w) \
  MSA_3R_FORMAT_SLD_SPLAT(name, opcode, d)

MSA_3R_LIST(MSA_3R)
MSA_3R_SLD_SPLAT(sld, SLD)
MSA_3R_SLD_SPLAT(splat, SPLAT)

#undef MSA_3R
#undef MSA_3R_FORMAT
#undef MSA_3R_FORMAT_SLD_SPLAT
#undef MSA_3R_SLD_SPLAT
#undef MSA_3R_LIST

#define MSA_3RF_LIST1(V) \
  V(fcaf, FCAF)          \
  V(fcun, FCUN)          \
  V(fceq, FCEQ)          \
  V(fcueq, FCUEQ)        \
  V(fclt, FCLT)          \
  V(fcult, FCULT)        \
  V(fcle, FCLE)          \
  V(fcule, FCULE)        \
  V(fsaf, FSAF)          \
  V(fsun, FSUN)          \
  V(fseq, FSEQ)          \
  V(fsueq, FSUEQ)        \
  V(fslt, FSLT)          \
  V(fsult, FSULT)        \
  V(fsle, FSLE)          \
  V(fsule, FSULE)        \
  V(fadd, FADD)          \
  V(fsub, FSUB)          \
  V(fmul, FMUL)          \
  V(fdiv, FDIV)          \
  V(fmadd, FMADD)        \
  V(fmsub, FMSUB)        \
  V(fexp2, FEXP2)        \
  V(fmin, FMIN)          \
  V(fmin_a, FMIN_A)      \
  V(fmax, FMAX)          \
  V(fmax_a, FMAX_A)      \
  V(fcor, FCOR)          \
  V(fcune, FCUNE)        \
  V(fcne, FCNE)          \
  V(fsor, FSOR)          \
  V(fsune, FSUNE)        \
  V(fsne, FSNE)

#define MSA_3RF_LIST2(V) \
  V(fexdo, FEXDO)        \
  V(ftq, FTQ)            \
  V(mul_q, MUL_Q)        \
  V(madd_q, MADD_Q)      \
  V(msub_q, MSUB_Q)      \
  V(mulr_q, MULR_Q)      \
  V(maddr_q, MADDR_Q)    \
  V(msubr_q, MSUBR_Q)

#define MSA_3RF_FORMAT(name, opcode, df, df_c)                \
  void Assembler::name##_##df(MSARegister wd, MSARegister ws, \
                              MSARegister wt) {               \
    GenInstrMsa3RF(opcode, df_c, wt, ws, wd);                 \
  }

#define MSA_3RF_1(name, opcode)      \
  MSA_3RF_FORMAT(name, opcode, w, 0) \
  MSA_3RF_FORMAT(name, opcode, d, 1)

#define MSA_3RF_2(name, opcode)      \
  MSA_3RF_FORMAT(name, opcode, h, 0) \
  MSA_3RF_FORMAT(name, opcode, w, 1)

MSA_3RF_LIST1(MSA_3RF_1)
MSA_3RF_LIST2(MSA_3RF_2)
#undef MSA_3RF_1
#undef MSA_3RF_2
#undef MSA_3RF_FORMAT
#undef MSA_3RF_LIST1
#undef MSA_3RF_LIST2

void Assembler::sldi_b(MSARegister wd, MSARegister ws, uint32_t n) {
  GenInstrMsaElm<MSARegister, MSARegister>(SLDI, ELM_DF_B, n, ws, wd);
}

void Assembler::sldi_h(MSARegister wd, MSARegister ws, uint32_t n) {
  GenInstrMsaElm<MSARegister, MSARegister>(SLDI, ELM_DF_H, n, ws, wd);
}

void Assembler::sldi_w(MSARegister wd, MSARegister ws, uint32_t n) {
  GenInstrMsaElm<MSARegister, MSARegister>(SLDI, ELM_DF_W, n, ws, wd);
}

void Assembler::sldi_d(MSARegister wd, MSARegister ws, uint32_t n) {
  GenInstrMsaElm<MSARegister, MSARegister>(SLDI, ELM_DF_D, n, ws, wd);
}

void Assembler::splati_b(MSARegister wd, MSARegister ws, uint32_t n) {
  GenInstrMsaElm<MSARegister, MSARegister>(SPLATI, ELM_DF_B, n, ws, wd);
}

void Assembler::splati_h(MSARegister wd, MSARegister ws, uint32_t n) {
  GenInstrMsaElm<MSARegister, MSARegister>(SPLATI, ELM_DF_H, n, ws, wd);
}

void Assembler::splati_w(MSARegister wd, MSARegister ws, uint32_t n) {
  GenInstrMsaElm<MSARegister, MSARegister>(SPLATI, ELM_DF_W, n, ws, wd);
}

void Assembler::splati_d(MSARegister wd, MSARegister ws, uint32_t n) {
  GenInstrMsaElm<MSARegister, MSARegister>(SPLATI, ELM_DF_D, n, ws, wd);
}

void Assembler::copy_s_b(Register rd, MSARegister ws, uint32_t n) {
  GenInstrMsaElm<Register, MSARegister>(COPY_S, ELM_DF_B, n, ws, rd);
}

void Assembler::copy_s_h(Register rd, MSARegister ws, uint32_t n) {
  GenInstrMsaElm<Register, MSARegister>(COPY_S, ELM_DF_H, n, ws, rd);
}

void Assembler::copy_s_w(Register rd, MSARegister ws, uint32_t n) {
  GenInstrMsaElm<Register, MSARegister>(COPY_S, ELM_DF_W, n, ws, rd);
}

void Assembler::copy_s_d(Register rd, MSARegister ws, uint32_t n) {
  GenInstrMsaElm<Register, MSARegister>(COPY_S, ELM_DF_D, n, ws, rd);
}

void Assembler::copy_u_b(Register rd, MSARegister ws, uint32_t n) {
  GenInstrMsaElm<Register, MSARegister>(COPY_U, ELM_DF_B, n, ws, rd);
}

void Assembler::copy_u_h(Register rd, MSARegister ws, uint32_t n) {
  GenInstrMsaElm<Register, MSARegister>(COPY_U, ELM_DF_H, n, ws, rd);
}

void Assembler::copy_u_w(Register rd, MSARegister ws, uint32_t n) {
  GenInstrMsaElm<Register, MSARegister>(COPY_U, ELM_DF_W, n, ws, rd);
}

void Assembler::insert_b(MSARegister wd, uint32_t n, Register rs) {
  GenInstrMsaElm<MSARegister, Register>(INSERT, ELM_DF_B, n, rs, wd);
}

void Assembler::insert_h(MSARegister wd, uint32_t n, Register rs) {
  GenInstrMsaElm<MSARegister, Register>(INSERT, ELM_DF_H, n, rs, wd);
}

void Assembler::insert_w(MSARegister wd, uint32_t n, Register rs) {
  GenInstrMsaElm<MSARegister, Register>(INSERT, ELM_DF_W, n, rs, wd);
}

void Assembler::insert_d(MSARegister wd, uint32_t n, Register rs) {
  GenInstrMsaElm<MSARegister, Register>(INSERT, ELM_DF_D, n, rs, wd);
}

void Assembler::insve_b(MSARegister wd, uint32_t n, MSARegister ws) {
  GenInstrMsaElm<MSARegister, MSARegister>(INSVE, ELM_DF_B, n, ws, wd);
}

void Assembler::insve_h(MSARegister wd, uint32_t n, MSARegister ws) {
  GenInstrMsaElm<MSARegister, MSARegister>(INSVE, ELM_DF_H, n, ws, wd);
}

void Assembler::insve_w(MSARegister wd, uint32_t n, MSARegister ws) {
  GenInstrMsaElm<MSARegister, MSARegister>(INSVE, ELM_DF_W, n, ws, wd);
}

void Assembler::insve_d(MSARegister wd, uint32_t n, MSARegister ws) {
  GenInstrMsaElm<MSARegister, MSARegister>(INSVE, ELM_DF_D, n, ws, wd);
}

void Assembler::move_v(MSARegister wd, MSARegister ws) {
  DCHECK(IsEnabled(MIPS_SIMD));
  DCHECK(ws.is_valid() && wd.is_valid());
  Instr instr = MSA | MOVE_V | (ws.code() << kWsShift) |
                (wd.code() << kWdShift) | MSA_ELM_MINOR;
  emit(instr);
}

void Assembler::ctcmsa(MSAControlRegister cd, Register rs) {
  DCHECK(IsEnabled(MIPS_SIMD));
  DCHECK(cd.is_valid() && rs.is_valid());
  Instr instr = MSA | CTCMSA | (rs.code() << kWsShift) |
                (cd.code() << kWdShift) | MSA_ELM_MINOR;
  emit(instr);
}

void Assembler::cfcmsa(Register rd, MSAControlRegister cs) {
  DCHECK(IsEnabled(MIPS_SIMD));
  DCHECK(rd.is_valid() && cs.is_valid());
  Instr instr = MSA | CFCMSA | (cs.code() << kWsShift) |
                (rd.code() << kWdShift) | MSA_ELM_MINOR;
  emit(instr);
}

#define MSA_BIT_LIST(V) \
  V(slli, SLLI)         \
  V(srai, SRAI)         \
  V(srli, SRLI)         \
  V(bclri, BCLRI)       \
  V(bseti, BSETI)       \
  V(bnegi, BNEGI)       \
  V(binsli, BINSLI)     \
  V(binsri, BINSRI)     \
  V(sat_s, SAT_S)       \
  V(sat_u, SAT_U)       \
  V(srari, SRARI)       \
  V(srlri, SRLRI)

#define MSA_BIT_FORMAT(name, opcode, format)                      \
  void Assembler::name##_##format(MSARegister wd, MSARegister ws, \
                                  uint32_t m) {                   \
    GenInstrMsaBit(opcode, BIT_DF_##format, m, ws, wd);           \
  }

#define MSA_BIT(name, opcode)     \
  MSA_BIT_FORMAT(name, opcode, b) \
  MSA_BIT_FORMAT(name, opcode, h) \
  MSA_BIT_FORMAT(name, opcode, w) \
  MSA_BIT_FORMAT(name, opcode, d)

MSA_BIT_LIST(MSA_BIT)
#undef MSA_BIT
#undef MSA_BIT_FORMAT
#undef MSA_BIT_LIST

int Assembler::RelocateInternalReference(
    RelocInfo::Mode rmode, Address pc, intptr_t pc_delta,
    WritableJitAllocation* jit_allocation) {
  if (RelocInfo::IsInternalReference(rmode)) {
    intptr_t internal_ref = ReadUnalignedValue<intptr_t>(pc);
    if (internal_ref == kEndOfJumpChain) {
      return 0;  // Number of instructions patched.
    }
    internal_ref += pc_delta;  // Relocate entry.
    if (jit_allocation) {
      jit_allocation->WriteUnalignedValue<intptr_t>(pc, internal_ref);
    } else {
      WriteUnalignedValue<intptr_t>(pc, internal_ref);
    }
    return 2;  // Number of instructions patched.
  }
  Instr instr = instr_at(pc);
  DCHECK(RelocInfo::IsInternalReferenceEncoded(rmode));
  if (IsLui(instr)) {
    Instr instr_lui = instr_at(pc + 0 * kInstrSize);
    Instr instr_ori = instr_at(pc + 1 * kInstrSize);
    Instr instr_ori2 = instr_at(pc + 3 * kInstrSize);
    DCHECK(IsOri(instr_ori));
    DCHECK(IsOri(instr_ori2));
    // TODO(plind): symbolic names for the shifts.
    int64_t imm = (instr_lui & static_cast<int64_t>(kImm16Mask)) << 48;
    imm |= (instr_ori & static_cast<int64_t>(kImm16Mask)) << 32;
    imm |= (instr_ori2 & static_cast<int64_t>(kImm16Mask)) << 16;
    // Sign extend address.
    imm >>= 16;

    if (imm == kEndOfJumpChain) {
      return 0;  // Number of instructions patched.
    }
    imm += pc_delta;
    DCHECK_EQ(imm & 3, 0);

    instr_lui &= ~kImm16Mask;
    instr_ori &= ~kImm16Mask;
    instr_ori2 &= ~kImm16Mask;

    instr_at_put(pc + 0 * kInstrSize, instr_lui | ((imm >> 32) & kImm16Mask),
                 jit_allocation);
    instr_at_put(pc + 1 * kInstrSize, instr_ori | (imm >> 16 & kImm16Mask),
                 jit_allocation);
    instr_at_put(pc + 3 * kInstrSize, instr_ori2 | (imm & kImm16Mask),
                 jit_allocation);
    return 4;  // Number of instructions patched.
  } else if (IsJ(instr) || IsJal(instr)) {
    // Regular j/jal relocation.
    uint32_t imm28 = (instr & static_cast<int32_t>(kImm26Mask)) << 2;
    imm28 += pc_delta;
    imm28 &= kImm28Mask;
    instr &= ~kImm26Mask;
    DCHECK_EQ(imm28 & 3, 0);
    uint32_t imm26 = static_cast<uint32_t>(imm28 >> 2);
    instr_at_put(pc, instr | (imm26 & kImm26Mask), jit_allocation);
    return 1;  // Number of instructions patched.
  } else {
    DCHECK(((instr & kJumpRawMask) == kJRawMark) ||
           ((instr & kJumpRawMask) == kJalRawMark));
    // Unbox raw offset and emit j/jal.
    int32_t imm28 = (instr & static_cast<int32_t>(kImm26Mask)) << 2;
    // Sign extend 28-bit offset to 32-bit.
    imm28 = (imm28 << 4) >> 4;
    uint64_t target =
        static_cast<int64_t>(imm28) + reinterpret_cast<uint64_t>(pc);
    target &= kImm28Mask;
    DCHECK_EQ(imm28 & 3, 0);
    uint32_t imm26 = static_cast<uint32_t>(target >> 2);
    // Check markings whether to emit j or jal.
    uint32_t unbox = (instr & kJRawMark) ? J : JAL;
    instr_at_put(pc, unbox | (imm26 & kImm26Mask), jit_allocation);
    return 1;  // Number of instructions patched.
  }
}

void Assembler::GrowBuffer() {
  // Compute new buffer size.
  int old_size = buffer_->size();
  int new_size = std::min(2 * old_size, old_size + 1 * MB);

  // Some internal data structures overflow for very large buffers,
  // they must ensure that kMaximalBufferSize is not too large.
  if (new_size > kMaximalBufferSize) {
    V8::FatalProcessOutOfMemory(nullptr, "Assembler::GrowBuffer");
  }

  // Set up new buffer.
  std::unique_ptr<AssemblerBuffer> new_buffer = buffer_->Grow(new_size);
  DCHECK_EQ(new_size, new_buffer->size());
  uint8_t* new_start = new_buffer->start();

  // Copy the data.
  intptr_t pc_delta = new_start - buffer_start_;
  intptr_t rc_delta = (new_start + new_size) - (buffer_start_ + old_size);
  size_t reloc_size = (buffer_start_ + old_size) - reloc_info_writer.pos();
  MemMove(new_start, buffer_start_, pc_offset());
  MemMove(reloc_info_writer.pos() + rc_delta, reloc_info_writer.pos(),
          reloc_size);

  // Switch buffers.
  buffer_ = std::move(new_buffer);
  buffer_start_ = new_start;
  pc_ += pc_delta;
  pc_for_safepoint_ += pc_delta;
  reloc_info_writer.Reposition(reloc_info_writer.pos() + rc_delta,
                               reloc_info_writer.last_pc() + pc_delta);

  // Relocate runtime entries.
  base::Vector<uint8_t> instructions{buffer_start_,
                                     static_cast<size_t>(pc_offset())};
  base::Vector<const uint8_t> reloc_info{reloc_info_writer.pos(), reloc_size};
  for (RelocIterator it(instructions, reloc_info, 0); !it.done(); it.next()) {
    RelocInfo::Mode rmode = it.rinfo()->rmode();
    if (rmode == RelocInfo::INTERNAL_REFERENCE) {
      RelocateInternalReference(rmode, it.rinfo()->pc(), pc_delta);
    }
  }

  DCHECK(!overflow());
}

void Assembler::db(uint8_t data) {
  CheckForEmitInForbiddenSlot();
  *reinterpret_cast<uint8_t*>(pc_) = data;
  pc_ += sizeof(uint8_t);
}

void Assembler::dd(uint32_t data) {
  CheckForEmitInForbiddenSlot();
  *reinterpret_cast<uint32_t*>(pc_) = data;
  pc_ += sizeof(uint32_t);
}

void Assembler::dq(uint64_t data) {
  CheckForEmitInForbiddenSlot();
  *reinterpret_cast<uint64_t*>(pc_) = data;
  pc_ += sizeof(uint64_t);
}

void Assembler::dd(Label* label) {
  uint64_t data;
  CheckForEmitInForbiddenSlot();
  if (label->is_bound()) {
    data = reinterpret_cast<uint64_t>(buffer_start_ + label->pos());
  } else {
    data = jump_address(label);
    unbound_labels_count_++;
    internal_reference_positions_.insert(label->pos());
  }
  RecordRelocInfo(RelocInfo::INTERNAL_REFERENCE);
  EmitHelper(data);
}

void Assembler::RecordRelocInfo(RelocInfo::Mode rmode, intptr_t data) {
  if (!ShouldRecordRelocInfo(rmode)) return;
  // We do not try to reuse pool constants.
  RelocInfo rinfo(reinterpret_cast<Address>(pc_), rmode, data);
  DCHECK_GE(buffer_space(), kMaxRelocSize);  // Too late to grow buffer here.
  reloc_info_writer.Write(&rinfo);
}

void Assembler::BlockTrampolinePoolFor(int instructions) {
  CheckTrampolinePoolQuick(instructions);
  BlockTrampolinePoolBefore(pc_offset() + instructions * kInstrSize);
}

void Assembler::CheckTrampolinePool() {
  // Some small sequences of instructions must not be broken up by the
  // insertion of a trampoline pool; such sequences are protected by setting
  // either trampoline_pool_blocked_nesting_ or no_trampoline_pool_before_,
  // which are both checked here. Also, recursive calls to CheckTrampolinePool
  // are blocked by trampoline_pool_blocked_nesting_.
  if ((trampoline_pool_blocked_nesting_ > 0) ||
      (pc_offset() < no_trampoline_pool_before_)) {
    // Emission is currently blocked; make sure we try again as soon as
    // possible.
    if (trampoline_pool_blocked_nesting_ > 0) {
      next_buffer_check_ = pc_offset() + kInstrSize;
    } else {
      next_buffer_check_ = no_trampoline_pool_before_;
    }
    return;
  }

  DCHECK(!trampoline_emitted_);
  DCHECK_GE(unbound_labels_count_, 0);
  if (unbound_labels_count_ > 0) {
    // First we emit jump (2 instructions), then we emit trampoline pool.
    {
      BlockTrampolinePoolScope block_trampoline_pool(this);
      Label after_pool;
      if (kArchVariant == kMips64r6) {
        bc(&after_pool);
      } else {
        b(&after_pool);
      }
      nop();

      int pool_start = pc_offset();
      for (int i = 0; i < unbound_labels_count_; i++) {
        {
          if (kArchVariant == kMips64r6) {
            bc(&after_pool);
            nop();
          } else {
            or_(t8, ra, zero_reg);
            nal();       // Read PC into ra register.
            lui(t9, 0);  // Branch delay slot.
            ori(t9, t9, 0);
            daddu(t9, ra, t9);
            or_(ra, t8, zero_reg);
            // Instruction jr will take or_ from the next trampoline.
            // in its branch delay slot. This is the expected behavior
            // in order to decrease size of trampoline pool.
            jr(t9);
          }
        }
      }
      nop();
      // If unbound_labels_count_ is big enough, label after_pool will
      // need a trampoline too, so we must create the trampoline before
      // the bind operation to make sure function 'bind' can get this
      // information.
      trampoline_ = Trampoline(pool_start, unbound_labels_count_);
      bind(&after_pool);

      trampoline_emitted_ = true;
      // As we are only going to emit trampoline once, we need to prevent any
      // further emission.
      next_buffer_check_ = kMaxInt;
    }
  } else {
    // Number of branches t
"""


```