Response:
Let's break down the thought process for analyzing this header file.

1. **Identify the Core Purpose:** The filename `assembler-mips64.h` immediately suggests this file is related to assembly code generation for the MIPS64 architecture within the V8 JavaScript engine. The "assembler" part is key – it's about generating low-level machine instructions.

2. **Recognize the Header File Nature:** Header files in C++ primarily declare interfaces. This means we'll be looking at function prototypes, not full implementations (though inline functions are an exception). The lack of extensive code blocks reinforces this.

3. **Categorize the Functionalities:**  Scanning the function names reveals several distinct groups of operations. Look for patterns and prefixes.

    * **`cvt_` functions:** These clearly relate to data type conversions, specifically for floating-point numbers. The suffixes (`_w`, `_l`, `_s`, `_d`) likely indicate the source and destination types (word, long, single, double).

    * **`cmp_` and `c_` functions:** These involve comparisons. The `FPUCondition` argument further confirms they deal with floating-point comparisons. The different suffixes and the presence of `MIPSr6` hints at different instruction sets or versions.

    * **`bc1` functions:**  These are conditional branch instructions for the floating-point unit (BC1 stands for Branch on Condition 1). `eqz` and `nez` mean "equal to zero" and "not equal to zero" respectively. `f` and `t` likely mean "false" and "true" based on a condition code.

    * **`fcmp`:** Another floating-point comparison, this time against a double-precision constant.

    * **`bz_v`, `bnz_v` (and similar with `_b`, `_h`, `_w`, `_d`):**  These are conditional branch instructions related to MSA registers. `bz` is "branch if zero," and `bnz` is "branch if not zero." The suffixes likely denote data sizes within the MSA register.

    * **`ld_` and `st_`:** These are load and store instructions for MSA registers, with suffixes indicating the data size being loaded/stored.

    * **`ldi_`:**  Load immediate value into an MSA register.

    * **A large block of functions starting with `addvi_`, `subvi_`, `maxi_`, `mini_`, `ceqi_`, `clti_`, `clei_`, `andi_`, `ori_`, etc., followed by `_b`, `_h`, `_w`, `_d`:** This suggests a comprehensive set of arithmetic, logical, and comparison operations between MSA registers and immediate values. The suffixes again denote data sizes.

    * **Another large block of functions like `and_v`, `or_v`, `nor_v`, `xor_v`, `bmnz_v`, `bmz_v`, `bsel_v`:**  These appear to be bitwise logical operations between MSA registers.

    * **Functions like `fill_`, `pcnt_`, `nloc_`, `nlzc_`:** These seem to be utility operations on MSA registers (fill with a value, count set bits, locate the first set bit, count leading zeros).

    * **Functions starting with `fclass_`, `ftrunc_`, `fsqrt_`, `frsqrt_`, etc.:**  These are mathematical operations on floating-point data within MSA registers.

    * **Functions like `sll_`, `sra_`, `srl_`, `bclr_`, `bset_`, `bneg_`, `binsl_`, `binsr_`:** These are bit manipulation operations (shift left logical, shift right arithmetic, shift right logical, bit clear, bit set, bit negate, bit insert left, bit insert right).

    * **More arithmetic operations like `addv_`, `subv_`, `max_`, `min_`, `ave_`, `aver_`, `subs_`, `subsus_`, `subsuu_`, `asub_`, `mulv_`, `maddv_`, `msubv_`, `div_`, `mod_`, `dotp_`, `dpadd_`, `dpsub_`:** These operate between two MSA registers. The suffixes (`_b`, `_h`, `_w`, `_d`) and prefixes (`s_`, `u_`, `a_`) indicate signed/unsigned and accumulation variations.

    * **Functions like `sld_`, `splat_`, `pckev_`, `pckod_`, `ilvl_`, `ilvr_`, `ilvev_`, `ilvod_`, `vshf_`, `srar_`, `srlr_`, `hadd_`, `hsub_`:**  These seem to be data manipulation and arrangement operations within and between MSA registers (shift left by scalar, splat a value, pack even/odd elements, interleave low/high, vector shift, horizontal add/subtract).

    * **Functions starting with `fcaf_`, `fcun_`, `fceq_`, `fcueq_`, `fclt_`, `fcult_`, `fcle_`, `fcule_`, `fsaf_`, `fsun_`, `fseq_`, `fsueq_`, `fslt_`, `fsult_`, `fsle_`, `fsule_`, `fadd_`, `fsub_`, `fmul_`, `fdiv_`, `fmadd_`, `fmsub_`, `fexp2_`, `fexdo_`, `ftq_`, `fmin_`, `fmax_`, `fcor_`, `fcune_`, `fcne_`, `fsor_`, `fsune_`, `fsne_`:**  These are floating-point comparisons and arithmetic operations specifically for MSA registers.

    * **Functions with `mul_q_`, `madd_q_`, `msub_q_`, `mulr_q_`, `maddr_q_`, `msubr_q_`:** These likely relate to multiplication and accumulation with results stored in a "quad" size (larger than double).

    * **Functions like `sldi_`, `splati_`, `copy_s_`, `copy_u_`, `insert_`, `insve_`:** These involve moving and inserting data between general-purpose registers and MSA registers, or within MSA registers, potentially with immediate offsets.

4. **Infer the Overall Purpose:**  Based on the identified categories, it becomes clear that this header file provides a C++ interface for generating a wide range of MIPS64 assembly instructions, particularly focusing on:

    * **General-purpose integer operations.**
    * **Floating-point operations (both traditional FPU and MSA).**
    * **Advanced SIMD (Single Instruction, Multiple Data) operations using the MSA extension.**
    * **Conditional branching.**
    * **Data loading and storing.**
    * **Bit manipulation.**

5. **Consider the Context:**  Knowing this is within V8, these instructions are used by the JavaScript engine's compiler (likely Crankshaft or Turbofan) to translate JavaScript code into efficient machine code for MIPS64-based systems.

6. **Address Specific Questions:**  Now, tackle the specific points raised in the prompt:

    * **`.tq` extension:**  Confirm that `.tq` files are indeed related to Torque.
    * **Relationship to JavaScript:**  Explain how these low-level instructions are the foundation for executing JavaScript code. Provide a simple JavaScript example and how it might translate into assembly.
    * **Code Logic/Assumptions:**  Illustrate with a simple example, showing inputs (registers, operands) and the expected output (effect on registers, memory).
    * **Common Programming Errors:** Think about mistakes developers might make *when using this assembler interface* (incorrect register usage, wrong immediate values, etc.).

7. **Synthesize the Summary:** Combine the key functionalities into a concise summary, highlighting the role of the `assembler-mips64.h` file in V8's code generation process for the MIPS64 architecture. Emphasize the breadth of supported instructions, especially the MSA extensions for SIMD operations.

By following this structured approach, we can effectively analyze and understand the purpose and functionality of the provided C++ header file.
好的，这是对 `v8/src/codegen/mips64/assembler-mips64.h` 文件中第二部分代码的功能归纳：

**功能归纳：**

这部分代码主要定义了 `Assembler` 类中用于生成 MIPS64 架构汇编指令的方法，专注于**浮点运算 (FPU)** 和 **MSA (MIPS SIMD Architecture)** 指令集的操作。

**具体功能点：**

1. **浮点数类型转换指令 (`cvt_`)：**
   - 提供了将浮点寄存器中的数据从一种浮点类型转换为另一种浮点类型的指令，例如从单精度 (`_s`) 到双精度 (`_d`)，从整数 (`_w`, `_l`) 到浮点数等。

2. **浮点数比较和分支指令 (`cmp_`, `c_`, `bc1eqz`, `bc1nez`, `bc1f`, `bc1t`, `fcmp`)：**
   - 提供了多种浮点数比较指令，用于比较两个浮点寄存器中的值，并根据比较结果设置条件标志。
   - 提供了基于浮点条件标志进行分支跳转的指令，例如：
     - `bc1eqz`:  如果浮点寄存器中的值为零则跳转。
     - `bc1nez`: 如果浮点寄存器中的值不为零则跳转。
     - `bc1f`:  如果浮点条件为假则跳转。
     - `bc1t`:  如果浮点条件为真则跳转。
   - `fcmp`: 提供了一种直接比较浮点寄存器与双精度常数的功能。
   - 区分了 MIPSr6 和非 MIPSr6 架构的比较和分支指令。

3. **MSA 寄存器条件分支指令 (`bz_v`, `bnz_v` 等)：**
   - 提供了基于 MSA 寄存器值是否为零进行分支跳转的指令。
   - 针对不同的数据类型（字节 `_b`、半字 `_h`、字 `_w`、双字 `_d`、向量 `_v`) 提供了相应的指令。

4. **MSA 寄存器加载和存储指令 (`ld_`, `st_`)：**
   - 提供了从内存加载数据到 MSA 寄存器以及将 MSA 寄存器中的数据存储到内存的指令。
   - 针对不同的数据类型提供了相应的指令。

5. **MSA 寄存器加载立即数指令 (`ldi_`)：**
   - 提供了将立即数加载到 MSA 寄存器的指令。
   - 针对不同的数据类型提供了相应的指令。

6. **MSA 寄存器与立即数之间的算术、比较和逻辑运算指令 (`addvi_`, `subvi_`, `maxi_`, `mini_`, `ceqi_`, `clti_`, `clei_`, `andi_`, `ori_`, `nori_`, `xori_`, `bmnzi_`, `bmzi_`, `bseli_`, `shf_`)：**
   - 提供了一系列 MSA 寄存器与立即数进行操作的指令，包括加法、减法、取最大值、取最小值、相等比较、小于比较、小于等于比较、按位与、按位或、按位或非、按位异或、以及一些位操作和选择指令。
   - 针对不同的数据类型提供了相应的指令。

7. **MSA 寄存器之间的逻辑运算指令 (`and_v`, `or_v`, `nor_v`, `xor_v`, `bmnz_v`, `bmz_v`, `bsel_v`)：**
   - 提供了 MSA 寄存器之间进行按位与、按位或、按位或非、按位异或以及一些位操作和选择指令。

8. **MSA 寄存器填充指令 (`fill_`)：**
   - 提供了将通用寄存器中的值填充到整个 MSA 寄存器的指令。
   - 针对不同的数据类型提供了相应的指令。

9. **MSA 寄存器位计数和查找指令 (`pcnt_`, `nloc_`, `nlzc_`)：**
   - 提供了对 MSA 寄存器中的位进行计数（例如，统计设置的位数）和查找（例如，查找第一个设置位或前导零）的指令。
   - 针对不同的数据类型提供了相应的指令。

10. **MSA 浮点数分类和转换指令 (`fclass_`, `ftrunc_`)：**
    - 提供了对 MSA 寄存器中的浮点数进行分类的指令。
    - 提供了将 MSA 浮点数截断为整数的指令。

11. **MSA 浮点数数学运算指令 (`fsqrt_`, `frsqrt_`, `frcp_`, `frint_`, `flog2_`, `fexupl_`, `fexupr_`, `ffql_`, `ffqr_`, `ftint_`, `ffint_`)：**
    - 提供了一系列 MSA 浮点数的数学运算指令，例如平方根、倒数平方根、倒数、取整、以 2 为底的对数、指数运算等。

12. **MSA 寄存器移位和位操作指令 (`sll_`, `sra_`, `srl_`, `bclr_`, `bset_`, `bneg_`, `binsl_`, `binsr_`)：**
    - 提供了一系列 MSA 寄存器的移位（逻辑左移、算术右移、逻辑右移）和位操作（位清除、位设置、位取反、位插入）指令。
    - 针对不同的数据类型提供了相应的指令。

13. **MSA 寄存器算术运算指令 (`addv_`, `subv_`, `max_`, `min_`, `ave_`, `aver_`, `subs_`, `subsus_`, `subsuu_`, `asub_`, `mulv_`, `maddv_`, `msubv_`, `div_`, `mod_`, `dotp_`, `dpadd_`, `dpsub_`)：**
    - 提供了 MSA 寄存器之间进行加法、减法、取最大值、取最小值、平均值、饱和减法、绝对值减法、乘法、乘加、乘减、除法、取模、点积等运算的指令。
    - 针对不同的数据类型以及有符号/无符号提供了相应的指令。

14. **MSA 数据重排和打包指令 (`sld_`, `splat_`, `pckev_`, `pckod_`, `ilvl_`, `ilvr_`, `ilvev_`, `ilvod_`, `vshf_`, `srar_`, `srlr_`, `hadd_`, `hsub_`)：**
    - 提供了在 MSA 寄存器内部以及 MSA 寄存器之间进行数据移动、复制、打包、交错、移位、水平加法/减法等操作的指令。
    - 针对不同的数据类型提供了相应的指令。

15. **MSA 浮点数比较指令 (`fcaf_`, `fcun_`, `fceq_`, `fcueq_`, `fclt_`, `fcult_`, `fcle_`, `fcule_`, `fsaf_`, `fsun_`, `fseq_`, `fsueq_`, `fslt_`, `fsult_`, `fsle_`, `fsule_`)：**
    - 提供了 MSA 寄存器中浮点数的各种比较指令，包括 NaN 的处理。

16. **MSA 浮点数算术运算指令 (`fadd_`, `fsub_`, `fmul_`, `fdiv_`, `fmadd_`, `fmsub_`, `fexp2_`, `fexdo_`, `ftq_`, `fmin_`, `fmax_`, `fcor_`, `fcune_`, `fcne_`, `fsor_`, `fsune_`, `fsne_`)：**
    - 提供了 MSA 寄存器中浮点数的加法、减法、乘法、除法、乘加、乘减、指数运算、最小值、最大值等运算指令。

17. **MSA 寄存器乘法和累加指令 (`mul_q_`, `madd_q_`, `msub_q_`, `mulr_q_`, `maddr_q_`, `msubr_q_`)：**
    - 提供了将 MSA 寄存器中的元素相乘并将结果累加到另一个 MSA 寄存器的指令，可能涉及更高精度的中间结果。

18. **MSA 数据移动和插入指令 (`sldi_`, `splati_`, `copy_s_`, `copy_u_`, `insert_`, `insve_`)：**
    - 提供了在 MSA 寄存器内部以及 MSA 寄存器与通用寄存器之间进行数据移动、复制和插入的指令，可以指定偏移量。

**总结:**

这部分代码为 V8 在 MIPS64 架构上生成高效代码提供了丰富的指令支持，尤其是在处理浮点数和利用 MSA SIMD 指令集进行并行计算方面。这些指令是 V8 执行 JavaScript 代码中涉及数值计算、数据处理等操作的关键组成部分。

### 提示词
```
这是目录为v8/src/codegen/mips64/assembler-mips64.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/mips64/assembler-mips64.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```c
cvt_d_w(FPURegister fd, FPURegister fs);
  void cvt_d_l(FPURegister fd, FPURegister fs);
  void cvt_d_s(FPURegister fd, FPURegister fs);

  // Conditions and branches for MIPSr6.
  void cmp(FPUCondition cond, SecondaryField fmt, FPURegister fd,
           FPURegister ft, FPURegister fs);
  void cmp_s(FPUCondition cond, FPURegister fd, FPURegister fs, FPURegister ft);
  void cmp_d(FPUCondition cond, FPURegister fd, FPURegister fs, FPURegister ft);

  void bc1eqz(int16_t offset, FPURegister ft);
  inline void bc1eqz(Label* L, FPURegister ft) {
    bc1eqz(shifted_branch_offset(L), ft);
  }
  void bc1nez(int16_t offset, FPURegister ft);
  inline void bc1nez(Label* L, FPURegister ft) {
    bc1nez(shifted_branch_offset(L), ft);
  }

  // Conditions and branches for non MIPSr6.
  void c(FPUCondition cond, SecondaryField fmt, FPURegister ft, FPURegister fs,
         uint16_t cc = 0);
  void c_s(FPUCondition cond, FPURegister ft, FPURegister fs, uint16_t cc = 0);
  void c_d(FPUCondition cond, FPURegister ft, FPURegister fs, uint16_t cc = 0);

  void bc1f(int16_t offset, uint16_t cc = 0);
  inline void bc1f(Label* L, uint16_t cc = 0) {
    bc1f(shifted_branch_offset(L), cc);
  }
  void bc1t(int16_t offset, uint16_t cc = 0);
  inline void bc1t(Label* L, uint16_t cc = 0) {
    bc1t(shifted_branch_offset(L), cc);
  }
  void fcmp(FPURegister src1, const double src2, FPUCondition cond);

  // MSA instructions
  void bz_v(MSARegister wt, int16_t offset);
  inline void bz_v(MSARegister wt, Label* L) {
    bz_v(wt, shifted_branch_offset(L));
  }
  void bz_b(MSARegister wt, int16_t offset);
  inline void bz_b(MSARegister wt, Label* L) {
    bz_b(wt, shifted_branch_offset(L));
  }
  void bz_h(MSARegister wt, int16_t offset);
  inline void bz_h(MSARegister wt, Label* L) {
    bz_h(wt, shifted_branch_offset(L));
  }
  void bz_w(MSARegister wt, int16_t offset);
  inline void bz_w(MSARegister wt, Label* L) {
    bz_w(wt, shifted_branch_offset(L));
  }
  void bz_d(MSARegister wt, int16_t offset);
  inline void bz_d(MSARegister wt, Label* L) {
    bz_d(wt, shifted_branch_offset(L));
  }
  void bnz_v(MSARegister wt, int16_t offset);
  inline void bnz_v(MSARegister wt, Label* L) {
    bnz_v(wt, shifted_branch_offset(L));
  }
  void bnz_b(MSARegister wt, int16_t offset);
  inline void bnz_b(MSARegister wt, Label* L) {
    bnz_b(wt, shifted_branch_offset(L));
  }
  void bnz_h(MSARegister wt, int16_t offset);
  inline void bnz_h(MSARegister wt, Label* L) {
    bnz_h(wt, shifted_branch_offset(L));
  }
  void bnz_w(MSARegister wt, int16_t offset);
  inline void bnz_w(MSARegister wt, Label* L) {
    bnz_w(wt, shifted_branch_offset(L));
  }
  void bnz_d(MSARegister wt, int16_t offset);
  inline void bnz_d(MSARegister wt, Label* L) {
    bnz_d(wt, shifted_branch_offset(L));
  }

  void ld_b(MSARegister wd, const MemOperand& rs);
  void ld_h(MSARegister wd, const MemOperand& rs);
  void ld_w(MSARegister wd, const MemOperand& rs);
  void ld_d(MSARegister wd, const MemOperand& rs);
  void st_b(MSARegister wd, const MemOperand& rs);
  void st_h(MSARegister wd, const MemOperand& rs);
  void st_w(MSARegister wd, const MemOperand& rs);
  void st_d(MSARegister wd, const MemOperand& rs);

  void ldi_b(MSARegister wd, int32_t imm10);
  void ldi_h(MSARegister wd, int32_t imm10);
  void ldi_w(MSARegister wd, int32_t imm10);
  void ldi_d(MSARegister wd, int32_t imm10);

  void addvi_b(MSARegister wd, MSARegister ws, uint32_t imm5);
  void addvi_h(MSARegister wd, MSARegister ws, uint32_t imm5);
  void addvi_w(MSARegister wd, MSARegister ws, uint32_t imm5);
  void addvi_d(MSARegister wd, MSARegister ws, uint32_t imm5);
  void subvi_b(MSARegister wd, MSARegister ws, uint32_t imm5);
  void subvi_h(MSARegister wd, MSARegister ws, uint32_t imm5);
  void subvi_w(MSARegister wd, MSARegister ws, uint32_t imm5);
  void subvi_d(MSARegister wd, MSARegister ws, uint32_t imm5);
  void maxi_s_b(MSARegister wd, MSARegister ws, uint32_t imm5);
  void maxi_s_h(MSARegister wd, MSARegister ws, uint32_t imm5);
  void maxi_s_w(MSARegister wd, MSARegister ws, uint32_t imm5);
  void maxi_s_d(MSARegister wd, MSARegister ws, uint32_t imm5);
  void maxi_u_b(MSARegister wd, MSARegister ws, uint32_t imm5);
  void maxi_u_h(MSARegister wd, MSARegister ws, uint32_t imm5);
  void maxi_u_w(MSARegister wd, MSARegister ws, uint32_t imm5);
  void maxi_u_d(MSARegister wd, MSARegister ws, uint32_t imm5);
  void mini_s_b(MSARegister wd, MSARegister ws, uint32_t imm5);
  void mini_s_h(MSARegister wd, MSARegister ws, uint32_t imm5);
  void mini_s_w(MSARegister wd, MSARegister ws, uint32_t imm5);
  void mini_s_d(MSARegister wd, MSARegister ws, uint32_t imm5);
  void mini_u_b(MSARegister wd, MSARegister ws, uint32_t imm5);
  void mini_u_h(MSARegister wd, MSARegister ws, uint32_t imm5);
  void mini_u_w(MSARegister wd, MSARegister ws, uint32_t imm5);
  void mini_u_d(MSARegister wd, MSARegister ws, uint32_t imm5);
  void ceqi_b(MSARegister wd, MSARegister ws, uint32_t imm5);
  void ceqi_h(MSARegister wd, MSARegister ws, uint32_t imm5);
  void ceqi_w(MSARegister wd, MSARegister ws, uint32_t imm5);
  void ceqi_d(MSARegister wd, MSARegister ws, uint32_t imm5);
  void clti_s_b(MSARegister wd, MSARegister ws, uint32_t imm5);
  void clti_s_h(MSARegister wd, MSARegister ws, uint32_t imm5);
  void clti_s_w(MSARegister wd, MSARegister ws, uint32_t imm5);
  void clti_s_d(MSARegister wd, MSARegister ws, uint32_t imm5);
  void clti_u_b(MSARegister wd, MSARegister ws, uint32_t imm5);
  void clti_u_h(MSARegister wd, MSARegister ws, uint32_t imm5);
  void clti_u_w(MSARegister wd, MSARegister ws, uint32_t imm5);
  void clti_u_d(MSARegister wd, MSARegister ws, uint32_t imm5);
  void clei_s_b(MSARegister wd, MSARegister ws, uint32_t imm5);
  void clei_s_h(MSARegister wd, MSARegister ws, uint32_t imm5);
  void clei_s_w(MSARegister wd, MSARegister ws, uint32_t imm5);
  void clei_s_d(MSARegister wd, MSARegister ws, uint32_t imm5);
  void clei_u_b(MSARegister wd, MSARegister ws, uint32_t imm5);
  void clei_u_h(MSARegister wd, MSARegister ws, uint32_t imm5);
  void clei_u_w(MSARegister wd, MSARegister ws, uint32_t imm5);
  void clei_u_d(MSARegister wd, MSARegister ws, uint32_t imm5);

  void andi_b(MSARegister wd, MSARegister ws, uint32_t imm8);
  void ori_b(MSARegister wd, MSARegister ws, uint32_t imm8);
  void nori_b(MSARegister wd, MSARegister ws, uint32_t imm8);
  void xori_b(MSARegister wd, MSARegister ws, uint32_t imm8);
  void bmnzi_b(MSARegister wd, MSARegister ws, uint32_t imm8);
  void bmzi_b(MSARegister wd, MSARegister ws, uint32_t imm8);
  void bseli_b(MSARegister wd, MSARegister ws, uint32_t imm8);
  void shf_b(MSARegister wd, MSARegister ws, uint32_t imm8);
  void shf_h(MSARegister wd, MSARegister ws, uint32_t imm8);
  void shf_w(MSARegister wd, MSARegister ws, uint32_t imm8);

  void and_v(MSARegister wd, MSARegister ws, MSARegister wt);
  void or_v(MSARegister wd, MSARegister ws, MSARegister wt);
  void nor_v(MSARegister wd, MSARegister ws, MSARegister wt);
  void xor_v(MSARegister wd, MSARegister ws, MSARegister wt);
  void bmnz_v(MSARegister wd, MSARegister ws, MSARegister wt);
  void bmz_v(MSARegister wd, MSARegister ws, MSARegister wt);
  void bsel_v(MSARegister wd, MSARegister ws, MSARegister wt);

  void fill_b(MSARegister wd, Register rs);
  void fill_h(MSARegister wd, Register rs);
  void fill_w(MSARegister wd, Register rs);
  void fill_d(MSARegister wd, Register rs);
  void pcnt_b(MSARegister wd, MSARegister ws);
  void pcnt_h(MSARegister wd, MSARegister ws);
  void pcnt_w(MSARegister wd, MSARegister ws);
  void pcnt_d(MSARegister wd, MSARegister ws);
  void nloc_b(MSARegister wd, MSARegister ws);
  void nloc_h(MSARegister wd, MSARegister ws);
  void nloc_w(MSARegister wd, MSARegister ws);
  void nloc_d(MSARegister wd, MSARegister ws);
  void nlzc_b(MSARegister wd, MSARegister ws);
  void nlzc_h(MSARegister wd, MSARegister ws);
  void nlzc_w(MSARegister wd, MSARegister ws);
  void nlzc_d(MSARegister wd, MSARegister ws);

  void fclass_w(MSARegister wd, MSARegister ws);
  void fclass_d(MSARegister wd, MSARegister ws);
  void ftrunc_s_w(MSARegister wd, MSARegister ws);
  void ftrunc_s_d(MSARegister wd, MSARegister ws);
  void ftrunc_u_w(MSARegister wd, MSARegister ws);
  void ftrunc_u_d(MSARegister wd, MSARegister ws);
  void fsqrt_w(MSARegister wd, MSARegister ws);
  void fsqrt_d(MSARegister wd, MSARegister ws);
  void frsqrt_w(MSARegister wd, MSARegister ws);
  void frsqrt_d(MSARegister wd, MSARegister ws);
  void frcp_w(MSARegister wd, MSARegister ws);
  void frcp_d(MSARegister wd, MSARegister ws);
  void frint_w(MSARegister wd, MSARegister ws);
  void frint_d(MSARegister wd, MSARegister ws);
  void flog2_w(MSARegister wd, MSARegister ws);
  void flog2_d(MSARegister wd, MSARegister ws);
  void fexupl_w(MSARegister wd, MSARegister ws);
  void fexupl_d(MSARegister wd, MSARegister ws);
  void fexupr_w(MSARegister wd, MSARegister ws);
  void fexupr_d(MSARegister wd, MSARegister ws);
  void ffql_w(MSARegister wd, MSARegister ws);
  void ffql_d(MSARegister wd, MSARegister ws);
  void ffqr_w(MSARegister wd, MSARegister ws);
  void ffqr_d(MSARegister wd, MSARegister ws);
  void ftint_s_w(MSARegister wd, MSARegister ws);
  void ftint_s_d(MSARegister wd, MSARegister ws);
  void ftint_u_w(MSARegister wd, MSARegister ws);
  void ftint_u_d(MSARegister wd, MSARegister ws);
  void ffint_s_w(MSARegister wd, MSARegister ws);
  void ffint_s_d(MSARegister wd, MSARegister ws);
  void ffint_u_w(MSARegister wd, MSARegister ws);
  void ffint_u_d(MSARegister wd, MSARegister ws);

  void sll_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void sll_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void sll_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void sll_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void sra_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void sra_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void sra_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void sra_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void srl_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void srl_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void srl_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void srl_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void bclr_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void bclr_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void bclr_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void bclr_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void bset_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void bset_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void bset_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void bset_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void bneg_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void bneg_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void bneg_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void bneg_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void binsl_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void binsl_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void binsl_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void binsl_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void binsr_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void binsr_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void binsr_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void binsr_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void addv_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void addv_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void addv_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void addv_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void subv_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void subv_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void subv_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void subv_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void max_s_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void max_s_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void max_s_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void max_s_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void max_u_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void max_u_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void max_u_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void max_u_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void min_s_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void min_s_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void min_s_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void min_s_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void min_u_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void min_u_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void min_u_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void min_u_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void max_a_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void max_a_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void max_a_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void max_a_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void min_a_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void min_a_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void min_a_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void min_a_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void ceq_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void ceq_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void ceq_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void ceq_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void clt_s_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void clt_s_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void clt_s_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void clt_s_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void clt_u_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void clt_u_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void clt_u_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void clt_u_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void cle_s_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void cle_s_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void cle_s_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void cle_s_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void cle_u_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void cle_u_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void cle_u_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void cle_u_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void add_a_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void add_a_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void add_a_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void add_a_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void adds_a_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void adds_a_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void adds_a_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void adds_a_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void adds_s_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void adds_s_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void adds_s_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void adds_s_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void adds_u_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void adds_u_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void adds_u_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void adds_u_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void ave_s_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void ave_s_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void ave_s_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void ave_s_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void ave_u_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void ave_u_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void ave_u_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void ave_u_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void aver_s_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void aver_s_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void aver_s_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void aver_s_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void aver_u_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void aver_u_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void aver_u_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void aver_u_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void subs_s_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void subs_s_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void subs_s_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void subs_s_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void subs_u_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void subs_u_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void subs_u_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void subs_u_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void subsus_u_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void subsus_u_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void subsus_u_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void subsus_u_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void subsus_s_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void subsus_s_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void subsus_s_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void subsus_s_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void subsuu_u_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void subsuu_u_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void subsuu_u_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void subsuu_u_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void subsuu_s_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void subsuu_s_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void subsuu_s_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void subsuu_s_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void asub_s_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void asub_s_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void asub_s_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void asub_s_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void asub_u_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void asub_u_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void asub_u_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void asub_u_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void mulv_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void mulv_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void mulv_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void mulv_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void maddv_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void maddv_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void maddv_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void maddv_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void msubv_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void msubv_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void msubv_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void msubv_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void div_s_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void div_s_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void div_s_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void div_s_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void div_u_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void div_u_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void div_u_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void div_u_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void mod_s_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void mod_s_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void mod_s_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void mod_s_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void mod_u_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void mod_u_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void mod_u_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void mod_u_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void dotp_s_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void dotp_s_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void dotp_s_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void dotp_s_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void dotp_u_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void dotp_u_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void dotp_u_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void dotp_u_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void dpadd_s_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void dpadd_s_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void dpadd_s_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void dpadd_s_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void dpadd_u_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void dpadd_u_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void dpadd_u_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void dpadd_u_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void dpsub_s_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void dpsub_s_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void dpsub_s_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void dpsub_s_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void dpsub_u_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void dpsub_u_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void dpsub_u_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void dpsub_u_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void sld_b(MSARegister wd, MSARegister ws, Register rt);
  void sld_h(MSARegister wd, MSARegister ws, Register rt);
  void sld_w(MSARegister wd, MSARegister ws, Register rt);
  void sld_d(MSARegister wd, MSARegister ws, Register rt);
  void splat_b(MSARegister wd, MSARegister ws, Register rt);
  void splat_h(MSARegister wd, MSARegister ws, Register rt);
  void splat_w(MSARegister wd, MSARegister ws, Register rt);
  void splat_d(MSARegister wd, MSARegister ws, Register rt);
  void pckev_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void pckev_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void pckev_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void pckev_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void pckod_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void pckod_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void pckod_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void pckod_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void ilvl_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void ilvl_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void ilvl_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void ilvl_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void ilvr_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void ilvr_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void ilvr_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void ilvr_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void ilvev_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void ilvev_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void ilvev_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void ilvev_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void ilvod_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void ilvod_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void ilvod_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void ilvod_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void vshf_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void vshf_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void vshf_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void vshf_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void srar_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void srar_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void srar_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void srar_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void srlr_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void srlr_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void srlr_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void srlr_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void hadd_s_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void hadd_s_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void hadd_s_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void hadd_s_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void hadd_u_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void hadd_u_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void hadd_u_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void hadd_u_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void hsub_s_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void hsub_s_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void hsub_s_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void hsub_s_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void hsub_u_b(MSARegister wd, MSARegister ws, MSARegister wt);
  void hsub_u_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void hsub_u_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void hsub_u_d(MSARegister wd, MSARegister ws, MSARegister wt);

  void fcaf_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fcaf_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void fcun_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fcun_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void fceq_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fceq_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void fcueq_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fcueq_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void fclt_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fclt_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void fcult_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fcult_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void fcle_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fcle_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void fcule_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fcule_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void fsaf_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fsaf_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void fsun_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fsun_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void fseq_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fseq_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void fsueq_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fsueq_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void fslt_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fslt_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void fsult_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fsult_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void fsle_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fsle_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void fsule_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fsule_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void fadd_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fadd_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void fsub_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fsub_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void fmul_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fmul_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void fdiv_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fdiv_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void fmadd_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fmadd_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void fmsub_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fmsub_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void fexp2_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fexp2_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void fexdo_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void fexdo_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void ftq_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void ftq_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fmin_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fmin_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void fmin_a_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fmin_a_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void fmax_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fmax_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void fmax_a_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fmax_a_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void fcor_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fcor_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void fcune_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fcune_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void fcne_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fcne_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void mul_q_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void mul_q_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void madd_q_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void madd_q_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void msub_q_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void msub_q_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fsor_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fsor_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void fsune_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fsune_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void fsne_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void fsne_d(MSARegister wd, MSARegister ws, MSARegister wt);
  void mulr_q_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void mulr_q_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void maddr_q_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void maddr_q_w(MSARegister wd, MSARegister ws, MSARegister wt);
  void msubr_q_h(MSARegister wd, MSARegister ws, MSARegister wt);
  void msubr_q_w(MSARegister wd, MSARegister ws, MSARegister wt);

  void sldi_b(MSARegister wd, MSARegister ws, uint32_t n);
  void sldi_h(MSARegister wd, MSARegister ws, uint32_t n);
  void sldi_w(MSARegister wd, MSARegister ws, uint32_t n);
  void sldi_d(MSARegister wd, MSARegister ws, uint32_t n);
  void splati_b(MSARegister wd, MSARegister ws, uint32_t n);
  void splati_h(MSARegister wd, MSARegister ws, uint32_t n);
  void splati_w(MSARegister wd, MSARegister ws, uint32_t n);
  void splati_d(MSARegister wd, MSARegister ws, uint32_t n);
  void copy_s_b(Register rd, MSARegister ws, uint32_t n);
  void copy_s_h(Register rd, MSARegister ws, uint32_t n);
  void copy_s_w(Register rd, MSARegister ws, uint32_t n);
  void copy_s_d(Register rd, MSARegister ws, uint32_t n);
  void copy_u_b(Register rd, MSARegister ws, uint32_t n);
  void copy_u_h(Register rd, MSARegister ws, uint32_t n);
  void copy_u_w(Register rd, MSARegister ws, uint32_t n);
  void insert_b(MSARegister wd, uint32_t n, Register rs);
  void insert_h(MSARegister wd, uint32_t n, Register rs);
  void insert_w(MSARegister wd, uint32_t n, Register rs);
  void insert_d(MSARegister wd, uint32_t n, Register rs);
  void insve_b(MSARegister wd, uint32_t n, MSARegister ws);
  void insve_h(MSARegister wd, uint32_t n, MSARegister ws);
  void insve_w(MSARegister wd, uint32_t n, MSARegister ws);
  void insve_d(MSARegiste
```