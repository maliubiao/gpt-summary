Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/codegen/loong64/assembler-loong64.cc`. They are also asking for specific checks related to file extensions, JavaScript relevance, code logic, and common programming errors. Finally, they want a summary of the functions described in the snippet.

Here's a breakdown of the thought process to address each part of the request:

1. **Overall Functionality:** The code defines methods within the `Assembler` class that correspond to LoongArch64 assembly instructions. Each method takes registers and immediate values as arguments and generates the corresponding machine code. The naming convention is clear (e.g., `add_w` for add word, `ld_d` for load double). The presence of `GenImm` and `GenRegister` suggests helper functions for encoding instructions based on their format.

2. **File Extension Check:** This is straightforward. The code explicitly checks if the filename ends with `.tq`. If it does, it's a Torque file.

3. **JavaScript Relevance:**  Assembler code directly translates to machine code. JavaScript engines like V8 use assemblers to generate optimized machine code for executing JavaScript. This connection needs to be illustrated with a JavaScript example that would necessitate the use of these low-level instructions. A simple arithmetic operation in JavaScript could be a good example, as it would eventually be translated into machine code additions or multiplications.

4. **Code Logic Inference:** Some methods involve simple logic, like `alsl_wu` and `alsl_d`, which seem to perform an arithmetic left shift with an immediate value. The `DCHECK` statements provide constraints on the input values. For example, `DCHECK(is_uint2(sa2 - 1))` implies `sa2` should be between 1 and 4 inclusive for `alsl_d`. I need to formulate an example with specific register inputs and `sa2` values to demonstrate the expected outcome.

5. **Common Programming Errors:**  Since the code deals with low-level assembly, common errors would involve incorrect register usage, invalid immediate values (violating the `DCHECK` constraints), or trying to perform operations on incompatible data types (though this is less explicitly enforced in this snippet but is a general concept in assembly).

6. **Summarization:** I need to synthesize the information gathered in the previous steps into a concise summary of the code's purpose. The core function is providing an interface to generate LoongArch64 instructions.

**Pre-computation/Pre-analysis (Mental Walkthrough):**

* **Instruction Types:** I'll categorize the instructions into arithmetic, logical, memory access, shifts, bit manipulation, and floating-point operations. This helps in understanding the breadth of functionality.
* **Register and Immediate Arguments:** Note the conventions for register names (rd, rj, rk, fd, fj, fk) and the types of immediate values (si, ui, sa).
* **`GenImm` and `GenRegister`:** Assume these functions handle the actual encoding of instructions based on the opcode and operands. The details of these functions are not provided, but their names are indicative of their purpose.
* **`DCHECK`:**  These are assertions used for debugging, indicating expected constraints on input parameters.

**Drafting the Response:**  Based on the above analysis, I can now construct the response, ensuring each point of the user's request is addressed with specific examples and explanations. I'll pay attention to the language used, making it clear and concise. The examples should be simple and illustrative.

**Self-Correction/Refinement:**

* **JavaScript Example:** Ensure the JavaScript example is directly related to the types of operations available in the assembly code (e.g., arithmetic, bitwise operations).
* **Code Logic Example:**  Clearly state the assumptions for register values and the expected outcome after the instruction executes.
* **Common Error Example:** Focus on errors that are likely when writing assembly code directly or when the compiler/JIT might generate incorrect code due to misconfiguration or bugs.
* **Summary:**  The summary should be a high-level overview, avoiding excessive technical details about individual instructions.

By following this process, I can provide a comprehensive and accurate answer to the user's request.
这是对 `v8/src/codegen/loong64/assembler-loong64.cc` 文件代码片段的功能归纳：

**功能归纳:**

这段代码定义了 `v8::internal::loong64::Assembler` 类中用于生成 LoongArch 64 位架构机器码的各种指令的方法。它提供了对 LoongArch 指令集的操作封装，允许 V8 引擎在 LoongArch 平台上动态生成可执行代码。

具体来说，这段代码片段涵盖了以下功能：

* **算术和逻辑运算指令:** 提供了加法 (`add_w`, `add_d`, `addi_w`, `addi_d`)、减法 (`sub_w`, `sub_d`, `subi_w`, `subi_d`)、乘法 (`mul_w`, `mul_d`, `mulh_w`, `mulh_wu`, `mulh_d`, `mulh_du`, `mulw_d_w`, `mulw_d_wu`)、除法 (`div_w`, `mod_w`, `div_wu`, `mod_wu`, `div_d`, `mod_d`, `div_du`, `mod_du`)、以及按位与 (`and_`, `andi`)、或 (`or_`, `ori`)、异或 (`xor_`, `xori`)、非 (`nor`)、与非 (`andn`)、或非 (`orn`) 等操作。
* **位移操作指令:**  提供了逻辑左移 (`sll_w`, `sll_d`, `slli_w`, `slli_d`)、逻辑右移 (`srl_w`, `srl_d`, `srli_w`, `srli_d`)、算术右移 (`sra_w`, `sra_d`, `srai_w`, `srai_d`)、循环右移 (`rotr_w`, `rotr_d`, `rotri_w`, `rotri_d`) 以及算术逻辑左移 (`alsl_wu`, `alsl_d`) 等操作。
* **比较指令:** 提供了小于比较 (`slt`)、小于等于比较 (`sltu`) 以及带立即数的比较 (`slti`, `sltui`)。
* **加载指令:**  提供了加载 12 位立即数到寄存器的指令 (`lu12i_w`, `lu32i_d`, `lu52i_d`)，以及与 PC 相关的地址加载指令 (`pcaddi`, `pcaddu12i`, `pcaddu18i`, `pcalau12i`)。
* **位操作指令:**  提供了位段提取 (`ext_w_b`, `ext_w_h`)、前导零计数 (`clz_w`, `clz_d`)、尾部零计数 (`ctz_w`, `ctz_d`)、前导一计数 (`clo_w`, `clo_d`)、尾部一计数 (`cto_w`, `cto_d`)、字节选择 (`bytepick_w`, `bytepick_d`)、字节反转 (`revb_2h`, `revb_4h`, `revb_2w`, `revb_d`)、半字反转 (`revh_2w`, `revh_d`)、位反转 (`bitrev_4b`, `bitrev_8b`, `bitrev_w`, `bitrev_d`)、位段插入 (`bstrins_w`, `bstrins_d`) 和位段提取 (`bstrpick_w`, `bstrpick_d`) 以及掩码操作 (`maskeqz`, `masknez`)。
* **内存访问指令:** 提供了加载 (`ld_b`, `ld_h`, `ld_w`, `ld_d`, `ld_bu`, `ld_hu`, `ld_wu`, `ldx_b`, `ldx_h`, `ldx_w`, `ldx_d`, `ldx_bu`, `ldx_hu`, `ldx_wu`, `ldptr_w`, `ldptr_d`, `ll_w`, `ll_d`) 和存储 (`st_b`, `st_h`, `st_w`, `st_d`, `stx_b`, `stx_h`, `stx_w`, `stx_d`, `stptr_w`, `stptr_d`, `sc_w`, `sc_d`) 指令。
* **原子内存操作指令:** 提供了原子交换 (`amswap_w`, `amswap_d`, `amswap_db_w`, `amswap_db_d`)、原子加 (`amadd_w`, `amadd_d`, `amadd_db_w`, `amadd_db_d`)、原子与 (`amand_w`, `amand_d`, `amand_db_w`, `amand_db_d`)、原子或 (`amor_w`, `amor_d`, `amor_db_w`, `amor_db_d`)、原子异或 (`amxor_w`, `amxor_d`, `amxor_db_w`, `amxor_db_d`)、原子最大值 (`ammax_w`, `ammax_d`, `ammax_wu`, `ammax_du`, `ammax_db_w`, `ammax_db_d`, `ammax_db_wu`, `ammax_db_du`) 和原子最小值 (`ammin_w`, `ammin_d`, `ammin_wu`, `ammin_du`, `ammin_db_w`, `ammin_db_d`, `ammin_db_wu`, `ammin_db_du`) 指令。
* **缓存控制指令:** 提供了数据缓存操作 (`dbar`) 和指令缓存操作 (`ibar`)。
* **断点指令:** 提供了 `break_` 和 `stop` 指令用于设置断点。
* **浮点运算指令:** 提供了浮点数的加法 (`fadd_s`, `fadd_d`)、减法 (`fsub_s`, `fsub_d`)、乘法 (`fmul_s`, `fmul_d`)、除法 (`fdiv_s`, `fdiv_d`)、融合乘加 (`fmadd_s`, `fmadd_d`)、融合乘减 (`fmsub_s`, `fmsub_d`)、负融合乘加 (`fnmadd_s`, `fnmadd_d`)、负融合乘减 (`fnmsub_s`, `fnmsub_d`)、最大值 (`fmax_s`, `fmax_d`, `fmaxa_s`, `fmaxa_d`)、最小值 (`fmin_s`, `fmin_d`, `fmina_s`, `fmina_d`)、绝对值 (`fabs_s`, `fabs_d`)、取反 (`fneg_s`, `fneg_d`)、平方根 (`fsqrt_s`, `fsqrt_d`)、倒数 (`frecip_s`, `frecip_d`)、倒数平方根 (`frsqrt_s`, `frsqrt_d`)、缩放 (`fscaleb_s`, `fscaleb_d`)、以 2 为底的对数 (`flogb_s`, `flogb_d`)、符号复制 (`fcopysign_s`, `fcopysign_d`)、类型判断 (`fclass_s`, `fclass_d`)、比较 (`fcmp_cond_s`, `fcmp_cond_d`)、类型转换 (`fcvt_s_d`, `fcvt_d_s`)、浮点数转整数 (`ffint_s_w`, `ffint_s_l`, `ffint_d_w`, `ffint_d_l`)、整数转浮点数 (`ftint_w_s`, `ftint_w_d`, `ftint_l_s`, `ftint_l_d` 和各种舍入模式的版本)、四舍五入到最近的整数 (`frint_s`, `frint_d`)、移动 (`fmov_s`, `fmov_d`)、选择 (`fsel`)、通用寄存器和浮点寄存器之间的数据移动 (`movgr2fr_w`, `movgr2fr_d`, `movgr2frh_w`, `movfr2gr_s`, `movfr2gr_d`, `movfrh2gr_s`)、通用寄存器和浮点控制状态寄存器之间的数据移动 (`movgr2fcsr`, `movfcsr2gr`)、浮点寄存器和条件标志寄存器之间的数据移动 (`movfr2cf`, `movcf2fr`)、通用寄存器和条件标志寄存器之间的数据移动 (`movgr2cf`, `movcf2gr`) 以及浮点数的加载和存储 (`fld_s`, `fld_d`, `fst_s`, `fst_d`, `fldx_s`, `fldx_d`, `fstx_s`, `fstx_d`) 指令。
* **其他辅助方法:** 提供了调整内存操作数的方法 (`AdjustBaseAndOffset`)、重定位相对引用的方法 (`RelocateRelativeReference`)、以及动态增长内部缓冲区的方法 (`GrowBuffer`)。

**关于代码片段的补充说明:**

* **文件类型:** 提供的代码片段是 C++ 源代码 (`.cc`)，用于实现汇编器功能。因此，如果 `v8/src/codegen/loong64/assembler-loong64.cc` 以 `.tq` 结尾，那将是错误的，因为它应该是一个 C++ 文件。Torque (一种 V8 使用的领域特定语言) 的源代码文件通常以 `.tq` 结尾。
* **与 JavaScript 的关系:**  `assembler-loong64.cc` 的核心功能是为 LoongArch64 架构生成机器码。当 V8 引擎需要执行 JavaScript 代码时，它会将 JavaScript 代码编译成机器码，而 `Assembler` 类就是用来生成这些机器码的。

**JavaScript 示例 (与功能相关):**

例如，JavaScript 中的一个简单的加法操作：

```javascript
function add(a, b) {
  return a + b;
}

add(5, 3);
```

当 V8 引擎执行这段代码时，`v8/src/codegen/loong64/assembler-loong64.cc` 中的 `add_w` 或 `add_d` 方法（取决于变量的类型）会被调用，生成类似以下的 LoongArch64 汇编指令 (这是一个简化的例子，实际情况会更复杂)：

```assembly
  // 假设 a 在寄存器 r10，b 在寄存器 r11，结果存入 r12
  add.w  r12, r10, r11
  // 或者
  add.d  r12, r10, r11
```

**代码逻辑推理示例:**

假设我们调用 `Assembler::add_w(r10, r11, r12)`，其中 `r11` 的值为 5，`r12` 的值为 3。

* **假设输入:**
    * `rd` (目标寄存器) = `r10`
    * `rj` (源寄存器 1) = `r11`, 值为 5
    * `rk` (源寄存器 2) = `r12`, 值为 3
* **输出:**
    * 执行 `add.w r10, r11, r12` 后，寄存器 `r10` 的值将变为 5 + 3 = 8。

**用户常见的编程错误示例:**

在使用汇编器或者理解其生成的代码时，常见的编程错误包括：

* **寄存器使用错误:** 错误地使用了某些特定用途的寄存器，或者在没有保存和恢复的情况下修改了调用者期望保留的寄存器。例如，在函数调用前后没有正确保存和恢复栈指针寄存器。
* **立即数越界:**  某些指令的立即数有取值范围限制。如果传递的立即数超出了这个范围，汇编器可能会报错，或者生成错误的指令。例如，`addi_w` 的立即数通常是 12 位的有符号数。
* **内存地址计算错误:**  在进行内存访问时，如果计算出的内存地址无效（例如，越界访问），会导致程序崩溃。例如，在使用 `ld_w` 指令时，提供的偏移量加上基址寄存器的值超出了有效的内存范围。
* **数据类型不匹配:** 尝试将不兼容的数据类型进行运算。例如，对浮点数使用整数运算指令，或者反之。虽然汇编器本身可能不会强制类型检查，但执行结果会出错。

**总结:**

这段代码是 V8 引擎在 LoongArch64 平台上生成机器码的关键组成部分，它提供了丰富的指令支持，涵盖了算术、逻辑、位操作、内存访问、浮点运算等多个方面，使得 V8 能够高效地执行 JavaScript 代码。

Prompt: 
```
这是目录为v8/src/codegen/loong64/assembler-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/loong64/assembler-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
rd, Register rj, Register rk, int32_t sa2) {
  DCHECK(is_uint2(sa2 - 1));
  GenImm(ALSL_WU, sa2 + 3, rk, rj, rd);
}

void Assembler::alsl_d(Register rd, Register rj, Register rk, int32_t sa2) {
  DCHECK(is_uint2(sa2 - 1));
  GenImm(ALSL_D, sa2 - 1, rk, rj, rd);
}

void Assembler::lu12i_w(Register rd, int32_t si20) {
  GenImm(LU12I_W, si20, rd);
}

void Assembler::lu32i_d(Register rd, int32_t si20) {
  GenImm(LU32I_D, si20, rd);
}

void Assembler::lu52i_d(Register rd, Register rj, int32_t si12) {
  GenImm(LU52I_D, si12, rj, rd, 12);
}

void Assembler::slt(Register rd, Register rj, Register rk) {
  GenRegister(SLT, rk, rj, rd);
}

void Assembler::sltu(Register rd, Register rj, Register rk) {
  GenRegister(SLTU, rk, rj, rd);
}

void Assembler::slti(Register rd, Register rj, int32_t si12) {
  GenImm(SLTI, si12, rj, rd, 12);
}

void Assembler::sltui(Register rd, Register rj, int32_t si12) {
  GenImm(SLTUI, si12, rj, rd, 12);
}

void Assembler::pcaddi(Register rd, int32_t si20) { GenImm(PCADDI, si20, rd); }

void Assembler::pcaddu12i(Register rd, int32_t si20) {
  GenImm(PCADDU12I, si20, rd);
}

void Assembler::pcaddu18i(Register rd, int32_t si20) {
  GenImm(PCADDU18I, si20, rd);
}

void Assembler::pcalau12i(Register rd, int32_t si20) {
  GenImm(PCALAU12I, si20, rd);
}

void Assembler::and_(Register rd, Register rj, Register rk) {
  GenRegister(AND, rk, rj, rd);
}

void Assembler::or_(Register rd, Register rj, Register rk) {
  GenRegister(OR, rk, rj, rd);
}

void Assembler::xor_(Register rd, Register rj, Register rk) {
  GenRegister(XOR, rk, rj, rd);
}

void Assembler::nor(Register rd, Register rj, Register rk) {
  GenRegister(NOR, rk, rj, rd);
}

void Assembler::andn(Register rd, Register rj, Register rk) {
  GenRegister(ANDN, rk, rj, rd);
}

void Assembler::orn(Register rd, Register rj, Register rk) {
  GenRegister(ORN, rk, rj, rd);
}

void Assembler::andi(Register rd, Register rj, int32_t ui12) {
  GenImm(ANDI, ui12, rj, rd, 12);
}

void Assembler::ori(Register rd, Register rj, int32_t ui12) {
  GenImm(ORI, ui12, rj, rd, 12);
}

void Assembler::xori(Register rd, Register rj, int32_t ui12) {
  GenImm(XORI, ui12, rj, rd, 12);
}

void Assembler::mul_w(Register rd, Register rj, Register rk) {
  GenRegister(MUL_W, rk, rj, rd);
}

void Assembler::mulh_w(Register rd, Register rj, Register rk) {
  GenRegister(MULH_W, rk, rj, rd);
}

void Assembler::mulh_wu(Register rd, Register rj, Register rk) {
  GenRegister(MULH_WU, rk, rj, rd);
}

void Assembler::mul_d(Register rd, Register rj, Register rk) {
  GenRegister(MUL_D, rk, rj, rd);
}

void Assembler::mulh_d(Register rd, Register rj, Register rk) {
  GenRegister(MULH_D, rk, rj, rd);
}

void Assembler::mulh_du(Register rd, Register rj, Register rk) {
  GenRegister(MULH_DU, rk, rj, rd);
}

void Assembler::mulw_d_w(Register rd, Register rj, Register rk) {
  GenRegister(MULW_D_W, rk, rj, rd);
}

void Assembler::mulw_d_wu(Register rd, Register rj, Register rk) {
  GenRegister(MULW_D_WU, rk, rj, rd);
}

void Assembler::div_w(Register rd, Register rj, Register rk) {
  GenRegister(DIV_W, rk, rj, rd);
}

void Assembler::mod_w(Register rd, Register rj, Register rk) {
  GenRegister(MOD_W, rk, rj, rd);
}

void Assembler::div_wu(Register rd, Register rj, Register rk) {
  GenRegister(DIV_WU, rk, rj, rd);
}

void Assembler::mod_wu(Register rd, Register rj, Register rk) {
  GenRegister(MOD_WU, rk, rj, rd);
}

void Assembler::div_d(Register rd, Register rj, Register rk) {
  GenRegister(DIV_D, rk, rj, rd);
}

void Assembler::mod_d(Register rd, Register rj, Register rk) {
  GenRegister(MOD_D, rk, rj, rd);
}

void Assembler::div_du(Register rd, Register rj, Register rk) {
  GenRegister(DIV_DU, rk, rj, rd);
}

void Assembler::mod_du(Register rd, Register rj, Register rk) {
  GenRegister(MOD_DU, rk, rj, rd);
}

// Shifts.
void Assembler::sll_w(Register rd, Register rj, Register rk) {
  GenRegister(SLL_W, rk, rj, rd);
}

void Assembler::srl_w(Register rd, Register rj, Register rk) {
  GenRegister(SRL_W, rk, rj, rd);
}

void Assembler::sra_w(Register rd, Register rj, Register rk) {
  GenRegister(SRA_W, rk, rj, rd);
}

void Assembler::rotr_w(Register rd, Register rj, Register rk) {
  GenRegister(ROTR_W, rk, rj, rd);
}

void Assembler::slli_w(Register rd, Register rj, int32_t ui5) {
  DCHECK(is_uint5(ui5));
  GenImm(SLLI_W, ui5 + 0x20, rj, rd, 6);
}

void Assembler::srli_w(Register rd, Register rj, int32_t ui5) {
  DCHECK(is_uint5(ui5));
  GenImm(SRLI_W, ui5 + 0x20, rj, rd, 6);
}

void Assembler::srai_w(Register rd, Register rj, int32_t ui5) {
  DCHECK(is_uint5(ui5));
  GenImm(SRAI_W, ui5 + 0x20, rj, rd, 6);
}

void Assembler::rotri_w(Register rd, Register rj, int32_t ui5) {
  DCHECK(is_uint5(ui5));
  GenImm(ROTRI_W, ui5 + 0x20, rj, rd, 6);
}

void Assembler::sll_d(Register rd, Register rj, Register rk) {
  GenRegister(SLL_D, rk, rj, rd);
}

void Assembler::srl_d(Register rd, Register rj, Register rk) {
  GenRegister(SRL_D, rk, rj, rd);
}

void Assembler::sra_d(Register rd, Register rj, Register rk) {
  GenRegister(SRA_D, rk, rj, rd);
}

void Assembler::rotr_d(Register rd, Register rj, Register rk) {
  GenRegister(ROTR_D, rk, rj, rd);
}

void Assembler::slli_d(Register rd, Register rj, int32_t ui6) {
  GenImm(SLLI_D, ui6, rj, rd, 6);
}

void Assembler::srli_d(Register rd, Register rj, int32_t ui6) {
  GenImm(SRLI_D, ui6, rj, rd, 6);
}

void Assembler::srai_d(Register rd, Register rj, int32_t ui6) {
  GenImm(SRAI_D, ui6, rj, rd, 6);
}

void Assembler::rotri_d(Register rd, Register rj, int32_t ui6) {
  GenImm(ROTRI_D, ui6, rj, rd, 6);
}

// Bit twiddling.
void Assembler::ext_w_b(Register rd, Register rj) {
  GenRegister(EXT_W_B, rj, rd);
}

void Assembler::ext_w_h(Register rd, Register rj) {
  GenRegister(EXT_W_H, rj, rd);
}

void Assembler::clo_w(Register rd, Register rj) { GenRegister(CLO_W, rj, rd); }

void Assembler::clz_w(Register rd, Register rj) { GenRegister(CLZ_W, rj, rd); }

void Assembler::cto_w(Register rd, Register rj) { GenRegister(CTO_W, rj, rd); }

void Assembler::ctz_w(Register rd, Register rj) { GenRegister(CTZ_W, rj, rd); }

void Assembler::clo_d(Register rd, Register rj) { GenRegister(CLO_D, rj, rd); }

void Assembler::clz_d(Register rd, Register rj) { GenRegister(CLZ_D, rj, rd); }

void Assembler::cto_d(Register rd, Register rj) { GenRegister(CTO_D, rj, rd); }

void Assembler::ctz_d(Register rd, Register rj) { GenRegister(CTZ_D, rj, rd); }

void Assembler::bytepick_w(Register rd, Register rj, Register rk, int32_t sa2) {
  DCHECK(is_uint2(sa2));
  GenImm(BYTEPICK_W, sa2, rk, rj, rd);
}

void Assembler::bytepick_d(Register rd, Register rj, Register rk, int32_t sa3) {
  GenImm(BYTEPICK_D, sa3, rk, rj, rd);
}

void Assembler::revb_2h(Register rd, Register rj) {
  GenRegister(REVB_2H, rj, rd);
}

void Assembler::revb_4h(Register rd, Register rj) {
  GenRegister(REVB_4H, rj, rd);
}

void Assembler::revb_2w(Register rd, Register rj) {
  GenRegister(REVB_2W, rj, rd);
}

void Assembler::revb_d(Register rd, Register rj) {
  GenRegister(REVB_D, rj, rd);
}

void Assembler::revh_2w(Register rd, Register rj) {
  GenRegister(REVH_2W, rj, rd);
}

void Assembler::revh_d(Register rd, Register rj) {
  GenRegister(REVH_D, rj, rd);
}

void Assembler::bitrev_4b(Register rd, Register rj) {
  GenRegister(BITREV_4B, rj, rd);
}

void Assembler::bitrev_8b(Register rd, Register rj) {
  GenRegister(BITREV_8B, rj, rd);
}

void Assembler::bitrev_w(Register rd, Register rj) {
  GenRegister(BITREV_W, rj, rd);
}

void Assembler::bitrev_d(Register rd, Register rj) {
  GenRegister(BITREV_D, rj, rd);
}

void Assembler::bstrins_w(Register rd, Register rj, int32_t msbw,
                          int32_t lsbw) {
  DCHECK(is_uint5(msbw) && is_uint5(lsbw));
  GenImm(BSTR_W, msbw + 0x20, lsbw, rj, rd);
}

void Assembler::bstrins_d(Register rd, Register rj, int32_t msbd,
                          int32_t lsbd) {
  GenImm(BSTRINS_D, msbd, lsbd, rj, rd);
}

void Assembler::bstrpick_w(Register rd, Register rj, int32_t msbw,
                           int32_t lsbw) {
  DCHECK(is_uint5(msbw) && is_uint5(lsbw));
  GenImm(BSTR_W, msbw + 0x20, lsbw + 0x20, rj, rd);
}

void Assembler::bstrpick_d(Register rd, Register rj, int32_t msbd,
                           int32_t lsbd) {
  GenImm(BSTRPICK_D, msbd, lsbd, rj, rd);
}

void Assembler::maskeqz(Register rd, Register rj, Register rk) {
  GenRegister(MASKEQZ, rk, rj, rd);
}

void Assembler::masknez(Register rd, Register rj, Register rk) {
  GenRegister(MASKNEZ, rk, rj, rd);
}

// Memory-instructions
void Assembler::ld_b(Register rd, Register rj, int32_t si12) {
  GenImm(LD_B, si12, rj, rd, 12);
}

void Assembler::ld_h(Register rd, Register rj, int32_t si12) {
  GenImm(LD_H, si12, rj, rd, 12);
}

void Assembler::ld_w(Register rd, Register rj, int32_t si12) {
  GenImm(LD_W, si12, rj, rd, 12);
}

void Assembler::ld_d(Register rd, Register rj, int32_t si12) {
  GenImm(LD_D, si12, rj, rd, 12);
}

void Assembler::ld_bu(Register rd, Register rj, int32_t si12) {
  GenImm(LD_BU, si12, rj, rd, 12);
}

void Assembler::ld_hu(Register rd, Register rj, int32_t si12) {
  GenImm(LD_HU, si12, rj, rd, 12);
}

void Assembler::ld_wu(Register rd, Register rj, int32_t si12) {
  GenImm(LD_WU, si12, rj, rd, 12);
}

void Assembler::st_b(Register rd, Register rj, int32_t si12) {
  GenImm(ST_B, si12, rj, rd, 12);
}

void Assembler::st_h(Register rd, Register rj, int32_t si12) {
  GenImm(ST_H, si12, rj, rd, 12);
}

void Assembler::st_w(Register rd, Register rj, int32_t si12) {
  GenImm(ST_W, si12, rj, rd, 12);
}

void Assembler::st_d(Register rd, Register rj, int32_t si12) {
  GenImm(ST_D, si12, rj, rd, 12);
}

void Assembler::ldx_b(Register rd, Register rj, Register rk) {
  GenRegister(LDX_B, rk, rj, rd);
}

void Assembler::ldx_h(Register rd, Register rj, Register rk) {
  GenRegister(LDX_H, rk, rj, rd);
}

void Assembler::ldx_w(Register rd, Register rj, Register rk) {
  GenRegister(LDX_W, rk, rj, rd);
}

void Assembler::ldx_d(Register rd, Register rj, Register rk) {
  GenRegister(LDX_D, rk, rj, rd);
}

void Assembler::ldx_bu(Register rd, Register rj, Register rk) {
  GenRegister(LDX_BU, rk, rj, rd);
}

void Assembler::ldx_hu(Register rd, Register rj, Register rk) {
  GenRegister(LDX_HU, rk, rj, rd);
}

void Assembler::ldx_wu(Register rd, Register rj, Register rk) {
  GenRegister(LDX_WU, rk, rj, rd);
}

void Assembler::stx_b(Register rd, Register rj, Register rk) {
  GenRegister(STX_B, rk, rj, rd);
}

void Assembler::stx_h(Register rd, Register rj, Register rk) {
  GenRegister(STX_H, rk, rj, rd);
}

void Assembler::stx_w(Register rd, Register rj, Register rk) {
  GenRegister(STX_W, rk, rj, rd);
}

void Assembler::stx_d(Register rd, Register rj, Register rk) {
  GenRegister(STX_D, rk, rj, rd);
}

void Assembler::ldptr_w(Register rd, Register rj, int32_t si14) {
  DCHECK(is_int16(si14) && ((si14 & 0x3) == 0));
  GenImm(LDPTR_W, si14 >> 2, rj, rd, 14);
}

void Assembler::ldptr_d(Register rd, Register rj, int32_t si14) {
  DCHECK(is_int16(si14) && ((si14 & 0x3) == 0));
  GenImm(LDPTR_D, si14 >> 2, rj, rd, 14);
}

void Assembler::stptr_w(Register rd, Register rj, int32_t si14) {
  DCHECK(is_int16(si14) && ((si14 & 0x3) == 0));
  GenImm(STPTR_W, si14 >> 2, rj, rd, 14);
}

void Assembler::stptr_d(Register rd, Register rj, int32_t si14) {
  DCHECK(is_int16(si14) && ((si14 & 0x3) == 0));
  GenImm(STPTR_D, si14 >> 2, rj, rd, 14);
}

void Assembler::amswap_w(Register rd, Register rk, Register rj) {
  GenRegister(AMSWAP_W, rk, rj, rd);
}

void Assembler::amswap_d(Register rd, Register rk, Register rj) {
  GenRegister(AMSWAP_D, rk, rj, rd);
}

void Assembler::amadd_w(Register rd, Register rk, Register rj) {
  GenRegister(AMADD_W, rk, rj, rd);
}

void Assembler::amadd_d(Register rd, Register rk, Register rj) {
  GenRegister(AMADD_D, rk, rj, rd);
}

void Assembler::amand_w(Register rd, Register rk, Register rj) {
  GenRegister(AMAND_W, rk, rj, rd);
}

void Assembler::amand_d(Register rd, Register rk, Register rj) {
  GenRegister(AMAND_D, rk, rj, rd);
}

void Assembler::amor_w(Register rd, Register rk, Register rj) {
  GenRegister(AMOR_W, rk, rj, rd);
}

void Assembler::amor_d(Register rd, Register rk, Register rj) {
  GenRegister(AMOR_D, rk, rj, rd);
}

void Assembler::amxor_w(Register rd, Register rk, Register rj) {
  GenRegister(AMXOR_W, rk, rj, rd);
}

void Assembler::amxor_d(Register rd, Register rk, Register rj) {
  GenRegister(AMXOR_D, rk, rj, rd);
}

void Assembler::ammax_w(Register rd, Register rk, Register rj) {
  GenRegister(AMMAX_W, rk, rj, rd);
}

void Assembler::ammax_d(Register rd, Register rk, Register rj) {
  GenRegister(AMMAX_D, rk, rj, rd);
}

void Assembler::ammin_w(Register rd, Register rk, Register rj) {
  GenRegister(AMMIN_W, rk, rj, rd);
}

void Assembler::ammin_d(Register rd, Register rk, Register rj) {
  GenRegister(AMMIN_D, rk, rj, rd);
}

void Assembler::ammax_wu(Register rd, Register rk, Register rj) {
  GenRegister(AMMAX_WU, rk, rj, rd);
}

void Assembler::ammax_du(Register rd, Register rk, Register rj) {
  GenRegister(AMMAX_DU, rk, rj, rd);
}

void Assembler::ammin_wu(Register rd, Register rk, Register rj) {
  GenRegister(AMMIN_WU, rk, rj, rd);
}

void Assembler::ammin_du(Register rd, Register rk, Register rj) {
  GenRegister(AMMIN_DU, rk, rj, rd);
}

void Assembler::amswap_db_w(Register rd, Register rk, Register rj) {
  GenRegister(AMSWAP_DB_W, rk, rj, rd);
}

void Assembler::amswap_db_d(Register rd, Register rk, Register rj) {
  GenRegister(AMSWAP_DB_D, rk, rj, rd);
}

void Assembler::amadd_db_w(Register rd, Register rk, Register rj) {
  GenRegister(AMADD_DB_W, rk, rj, rd);
}

void Assembler::amadd_db_d(Register rd, Register rk, Register rj) {
  GenRegister(AMADD_DB_D, rk, rj, rd);
}

void Assembler::amand_db_w(Register rd, Register rk, Register rj) {
  GenRegister(AMAND_DB_W, rk, rj, rd);
}

void Assembler::amand_db_d(Register rd, Register rk, Register rj) {
  GenRegister(AMAND_DB_D, rk, rj, rd);
}

void Assembler::amor_db_w(Register rd, Register rk, Register rj) {
  GenRegister(AMOR_DB_W, rk, rj, rd);
}

void Assembler::amor_db_d(Register rd, Register rk, Register rj) {
  GenRegister(AMOR_DB_D, rk, rj, rd);
}

void Assembler::amxor_db_w(Register rd, Register rk, Register rj) {
  GenRegister(AMXOR_DB_W, rk, rj, rd);
}

void Assembler::amxor_db_d(Register rd, Register rk, Register rj) {
  GenRegister(AMXOR_DB_D, rk, rj, rd);
}

void Assembler::ammax_db_w(Register rd, Register rk, Register rj) {
  GenRegister(AMMAX_DB_W, rk, rj, rd);
}

void Assembler::ammax_db_d(Register rd, Register rk, Register rj) {
  GenRegister(AMMAX_DB_D, rk, rj, rd);
}

void Assembler::ammin_db_w(Register rd, Register rk, Register rj) {
  GenRegister(AMMIN_DB_W, rk, rj, rd);
}

void Assembler::ammin_db_d(Register rd, Register rk, Register rj) {
  GenRegister(AMMIN_DB_D, rk, rj, rd);
}

void Assembler::ammax_db_wu(Register rd, Register rk, Register rj) {
  GenRegister(AMMAX_DB_WU, rk, rj, rd);
}

void Assembler::ammax_db_du(Register rd, Register rk, Register rj) {
  GenRegister(AMMAX_DB_DU, rk, rj, rd);
}

void Assembler::ammin_db_wu(Register rd, Register rk, Register rj) {
  GenRegister(AMMIN_DB_WU, rk, rj, rd);
}

void Assembler::ammin_db_du(Register rd, Register rk, Register rj) {
  GenRegister(AMMIN_DB_DU, rk, rj, rd);
}

void Assembler::ll_w(Register rd, Register rj, int32_t si14) {
  DCHECK(is_int16(si14) && ((si14 & 0x3) == 0));
  GenImm(LL_W, si14 >> 2, rj, rd, 14);
}

void Assembler::ll_d(Register rd, Register rj, int32_t si14) {
  DCHECK(is_int16(si14) && ((si14 & 0x3) == 0));
  GenImm(LL_D, si14 >> 2, rj, rd, 14);
}

void Assembler::sc_w(Register rd, Register rj, int32_t si14) {
  DCHECK(is_int16(si14) && ((si14 & 0x3) == 0));
  GenImm(SC_W, si14 >> 2, rj, rd, 14);
}

void Assembler::sc_d(Register rd, Register rj, int32_t si14) {
  DCHECK(is_int16(si14) && ((si14 & 0x3) == 0));
  GenImm(SC_D, si14 >> 2, rj, rd, 14);
}

void Assembler::dbar(int32_t hint) { GenImm(DBAR, hint); }

void Assembler::ibar(int32_t hint) { GenImm(IBAR, hint); }

// Break instruction.
void Assembler::break_(uint32_t code, bool break_as_stop) {
  DCHECK(
      (break_as_stop && code <= kMaxStopCode && code > kMaxWatchpointCode) ||
      (!break_as_stop && (code > kMaxStopCode || code <= kMaxWatchpointCode)));
  GenImm(BREAK, code);
}

void Assembler::stop(uint32_t code) {
  DCHECK_GT(code, kMaxWatchpointCode);
  DCHECK_LE(code, kMaxStopCode);
#if defined(V8_HOST_ARCH_LOONG64)
  break_(0x4321);
#else  // V8_HOST_ARCH_LOONG64
  break_(code, true);
#endif
}

void Assembler::fadd_s(FPURegister fd, FPURegister fj, FPURegister fk) {
  GenRegister(FADD_S, fk, fj, fd);
}

void Assembler::fadd_d(FPURegister fd, FPURegister fj, FPURegister fk) {
  GenRegister(FADD_D, fk, fj, fd);
}

void Assembler::fsub_s(FPURegister fd, FPURegister fj, FPURegister fk) {
  GenRegister(FSUB_S, fk, fj, fd);
}

void Assembler::fsub_d(FPURegister fd, FPURegister fj, FPURegister fk) {
  GenRegister(FSUB_D, fk, fj, fd);
}

void Assembler::fmul_s(FPURegister fd, FPURegister fj, FPURegister fk) {
  GenRegister(FMUL_S, fk, fj, fd);
}

void Assembler::fmul_d(FPURegister fd, FPURegister fj, FPURegister fk) {
  GenRegister(FMUL_D, fk, fj, fd);
}

void Assembler::fdiv_s(FPURegister fd, FPURegister fj, FPURegister fk) {
  GenRegister(FDIV_S, fk, fj, fd);
}

void Assembler::fdiv_d(FPURegister fd, FPURegister fj, FPURegister fk) {
  GenRegister(FDIV_D, fk, fj, fd);
}

void Assembler::fmadd_s(FPURegister fd, FPURegister fj, FPURegister fk,
                        FPURegister fa) {
  GenRegister(FMADD_S, fa, fk, fj, fd);
}

void Assembler::fmadd_d(FPURegister fd, FPURegister fj, FPURegister fk,
                        FPURegister fa) {
  GenRegister(FMADD_D, fa, fk, fj, fd);
}

void Assembler::fmsub_s(FPURegister fd, FPURegister fj, FPURegister fk,
                        FPURegister fa) {
  GenRegister(FMSUB_S, fa, fk, fj, fd);
}

void Assembler::fmsub_d(FPURegister fd, FPURegister fj, FPURegister fk,
                        FPURegister fa) {
  GenRegister(FMSUB_D, fa, fk, fj, fd);
}

void Assembler::fnmadd_s(FPURegister fd, FPURegister fj, FPURegister fk,
                         FPURegister fa) {
  GenRegister(FNMADD_S, fa, fk, fj, fd);
}

void Assembler::fnmadd_d(FPURegister fd, FPURegister fj, FPURegister fk,
                         FPURegister fa) {
  GenRegister(FNMADD_D, fa, fk, fj, fd);
}

void Assembler::fnmsub_s(FPURegister fd, FPURegister fj, FPURegister fk,
                         FPURegister fa) {
  GenRegister(FNMSUB_S, fa, fk, fj, fd);
}

void Assembler::fnmsub_d(FPURegister fd, FPURegister fj, FPURegister fk,
                         FPURegister fa) {
  GenRegister(FNMSUB_D, fa, fk, fj, fd);
}

void Assembler::fmax_s(FPURegister fd, FPURegister fj, FPURegister fk) {
  GenRegister(FMAX_S, fk, fj, fd);
}

void Assembler::fmax_d(FPURegister fd, FPURegister fj, FPURegister fk) {
  GenRegister(FMAX_D, fk, fj, fd);
}

void Assembler::fmin_s(FPURegister fd, FPURegister fj, FPURegister fk) {
  GenRegister(FMIN_S, fk, fj, fd);
}

void Assembler::fmin_d(FPURegister fd, FPURegister fj, FPURegister fk) {
  GenRegister(FMIN_D, fk, fj, fd);
}

void Assembler::fmaxa_s(FPURegister fd, FPURegister fj, FPURegister fk) {
  GenRegister(FMAXA_S, fk, fj, fd);
}

void Assembler::fmaxa_d(FPURegister fd, FPURegister fj, FPURegister fk) {
  GenRegister(FMAXA_D, fk, fj, fd);
}

void Assembler::fmina_s(FPURegister fd, FPURegister fj, FPURegister fk) {
  GenRegister(FMINA_S, fk, fj, fd);
}

void Assembler::fmina_d(FPURegister fd, FPURegister fj, FPURegister fk) {
  GenRegister(FMINA_D, fk, fj, fd);
}

void Assembler::fabs_s(FPURegister fd, FPURegister fj) {
  GenRegister(FABS_S, fj, fd);
}

void Assembler::fabs_d(FPURegister fd, FPURegister fj) {
  GenRegister(FABS_D, fj, fd);
}

void Assembler::fneg_s(FPURegister fd, FPURegister fj) {
  GenRegister(FNEG_S, fj, fd);
}

void Assembler::fneg_d(FPURegister fd, FPURegister fj) {
  GenRegister(FNEG_D, fj, fd);
}

void Assembler::fsqrt_s(FPURegister fd, FPURegister fj) {
  GenRegister(FSQRT_S, fj, fd);
}

void Assembler::fsqrt_d(FPURegister fd, FPURegister fj) {
  GenRegister(FSQRT_D, fj, fd);
}

void Assembler::frecip_s(FPURegister fd, FPURegister fj) {
  GenRegister(FRECIP_S, fj, fd);
}

void Assembler::frecip_d(FPURegister fd, FPURegister fj) {
  GenRegister(FRECIP_D, fj, fd);
}

void Assembler::frsqrt_s(FPURegister fd, FPURegister fj) {
  GenRegister(FRSQRT_S, fj, fd);
}

void Assembler::frsqrt_d(FPURegister fd, FPURegister fj) {
  GenRegister(FRSQRT_D, fj, fd);
}

void Assembler::fscaleb_s(FPURegister fd, FPURegister fj, FPURegister fk) {
  GenRegister(FSCALEB_S, fk, fj, fd);
}

void Assembler::fscaleb_d(FPURegister fd, FPURegister fj, FPURegister fk) {
  GenRegister(FSCALEB_D, fk, fj, fd);
}

void Assembler::flogb_s(FPURegister fd, FPURegister fj) {
  GenRegister(FLOGB_S, fj, fd);
}

void Assembler::flogb_d(FPURegister fd, FPURegister fj) {
  GenRegister(FLOGB_D, fj, fd);
}

void Assembler::fcopysign_s(FPURegister fd, FPURegister fj, FPURegister fk) {
  GenRegister(FCOPYSIGN_S, fk, fj, fd);
}

void Assembler::fcopysign_d(FPURegister fd, FPURegister fj, FPURegister fk) {
  GenRegister(FCOPYSIGN_D, fk, fj, fd);
}

void Assembler::fclass_s(FPURegister fd, FPURegister fj) {
  GenRegister(FCLASS_S, fj, fd);
}

void Assembler::fclass_d(FPURegister fd, FPURegister fj) {
  GenRegister(FCLASS_D, fj, fd);
}

void Assembler::fcmp_cond_s(FPUCondition cc, FPURegister fj, FPURegister fk,
                            CFRegister cd) {
  GenCmp(FCMP_COND_S, cc, fk, fj, cd);
}

void Assembler::fcmp_cond_d(FPUCondition cc, FPURegister fj, FPURegister fk,
                            CFRegister cd) {
  GenCmp(FCMP_COND_D, cc, fk, fj, cd);
}

void Assembler::fcvt_s_d(FPURegister fd, FPURegister fj) {
  GenRegister(FCVT_S_D, fj, fd);
}

void Assembler::fcvt_d_s(FPURegister fd, FPURegister fj) {
  GenRegister(FCVT_D_S, fj, fd);
}

void Assembler::ffint_s_w(FPURegister fd, FPURegister fj) {
  GenRegister(FFINT_S_W, fj, fd);
}

void Assembler::ffint_s_l(FPURegister fd, FPURegister fj) {
  GenRegister(FFINT_S_L, fj, fd);
}

void Assembler::ffint_d_w(FPURegister fd, FPURegister fj) {
  GenRegister(FFINT_D_W, fj, fd);
}

void Assembler::ffint_d_l(FPURegister fd, FPURegister fj) {
  GenRegister(FFINT_D_L, fj, fd);
}

void Assembler::ftint_w_s(FPURegister fd, FPURegister fj) {
  GenRegister(FTINT_W_S, fj, fd);
}

void Assembler::ftint_w_d(FPURegister fd, FPURegister fj) {
  GenRegister(FTINT_W_D, fj, fd);
}

void Assembler::ftint_l_s(FPURegister fd, FPURegister fj) {
  GenRegister(FTINT_L_S, fj, fd);
}

void Assembler::ftint_l_d(FPURegister fd, FPURegister fj) {
  GenRegister(FTINT_L_D, fj, fd);
}

void Assembler::ftintrm_w_s(FPURegister fd, FPURegister fj) {
  GenRegister(FTINTRM_W_S, fj, fd);
}

void Assembler::ftintrm_w_d(FPURegister fd, FPURegister fj) {
  GenRegister(FTINTRM_W_D, fj, fd);
}

void Assembler::ftintrm_l_s(FPURegister fd, FPURegister fj) {
  GenRegister(FTINTRM_L_S, fj, fd);
}

void Assembler::ftintrm_l_d(FPURegister fd, FPURegister fj) {
  GenRegister(FTINTRM_L_D, fj, fd);
}

void Assembler::ftintrp_w_s(FPURegister fd, FPURegister fj) {
  GenRegister(FTINTRP_W_S, fj, fd);
}

void Assembler::ftintrp_w_d(FPURegister fd, FPURegister fj) {
  GenRegister(FTINTRP_W_D, fj, fd);
}

void Assembler::ftintrp_l_s(FPURegister fd, FPURegister fj) {
  GenRegister(FTINTRP_L_S, fj, fd);
}

void Assembler::ftintrp_l_d(FPURegister fd, FPURegister fj) {
  GenRegister(FTINTRP_L_D, fj, fd);
}

void Assembler::ftintrz_w_s(FPURegister fd, FPURegister fj) {
  GenRegister(FTINTRZ_W_S, fj, fd);
}

void Assembler::ftintrz_w_d(FPURegister fd, FPURegister fj) {
  GenRegister(FTINTRZ_W_D, fj, fd);
}

void Assembler::ftintrz_l_s(FPURegister fd, FPURegister fj) {
  GenRegister(FTINTRZ_L_S, fj, fd);
}

void Assembler::ftintrz_l_d(FPURegister fd, FPURegister fj) {
  GenRegister(FTINTRZ_L_D, fj, fd);
}

void Assembler::ftintrne_w_s(FPURegister fd, FPURegister fj) {
  GenRegister(FTINTRNE_W_S, fj, fd);
}

void Assembler::ftintrne_w_d(FPURegister fd, FPURegister fj) {
  GenRegister(FTINTRNE_W_D, fj, fd);
}

void Assembler::ftintrne_l_s(FPURegister fd, FPURegister fj) {
  GenRegister(FTINTRNE_L_S, fj, fd);
}

void Assembler::ftintrne_l_d(FPURegister fd, FPURegister fj) {
  GenRegister(FTINTRNE_L_D, fj, fd);
}

void Assembler::frint_s(FPURegister fd, FPURegister fj) {
  GenRegister(FRINT_S, fj, fd);
}

void Assembler::frint_d(FPURegister fd, FPURegister fj) {
  GenRegister(FRINT_D, fj, fd);
}

void Assembler::fmov_s(FPURegister fd, FPURegister fj) {
  GenRegister(FMOV_S, fj, fd);
}

void Assembler::fmov_d(FPURegister fd, FPURegister fj) {
  GenRegister(FMOV_D, fj, fd);
}

void Assembler::fsel(CFRegister ca, FPURegister fd, FPURegister fj,
                     FPURegister fk) {
  GenSel(FSEL, ca, fk, fj, fd);
}

void Assembler::movgr2fr_w(FPURegister fd, Register rj) {
  GenRegister(MOVGR2FR_W, rj, fd);
}

void Assembler::movgr2fr_d(FPURegister fd, Register rj) {
  GenRegister(MOVGR2FR_D, rj, fd);
}

void Assembler::movgr2frh_w(FPURegister fd, Register rj) {
  GenRegister(MOVGR2FRH_W, rj, fd);
}

void Assembler::movfr2gr_s(Register rd, FPURegister fj) {
  GenRegister(MOVFR2GR_S, fj, rd);
}

void Assembler::movfr2gr_d(Register rd, FPURegister fj) {
  GenRegister(MOVFR2GR_D, fj, rd);
}

void Assembler::movfrh2gr_s(Register rd, FPURegister fj) {
  GenRegister(MOVFRH2GR_S, fj, rd);
}

void Assembler::movgr2fcsr(Register rj, FPUControlRegister fcsr) {
  GenRegister(MOVGR2FCSR, rj, fcsr);
}

void Assembler::movfcsr2gr(Register rd, FPUControlRegister fcsr) {
  GenRegister(MOVFCSR2GR, fcsr, rd);
}

void Assembler::movfr2cf(CFRegister cd, FPURegister fj) {
  GenRegister(MOVFR2CF, fj, cd);
}

void Assembler::movcf2fr(FPURegister fd, CFRegister cj) {
  GenRegister(MOVCF2FR, cj, fd);
}

void Assembler::movgr2cf(CFRegister cd, Register rj) {
  GenRegister(MOVGR2CF, rj, cd);
}

void Assembler::movcf2gr(Register rd, CFRegister cj) {
  GenRegister(MOVCF2GR, cj, rd);
}

void Assembler::fld_s(FPURegister fd, Register rj, int32_t si12) {
  GenImm(FLD_S, si12, rj, fd);
}

void Assembler::fld_d(FPURegister fd, Register rj, int32_t si12) {
  GenImm(FLD_D, si12, rj, fd);
}

void Assembler::fst_s(FPURegister fd, Register rj, int32_t si12) {
  GenImm(FST_S, si12, rj, fd);
}

void Assembler::fst_d(FPURegister fd, Register rj, int32_t si12) {
  GenImm(FST_D, si12, rj, fd);
}

void Assembler::fldx_s(FPURegister fd, Register rj, Register rk) {
  GenRegister(FLDX_S, rk, rj, fd);
}

void Assembler::fldx_d(FPURegister fd, Register rj, Register rk) {
  GenRegister(FLDX_D, rk, rj, fd);
}

void Assembler::fstx_s(FPURegister fd, Register rj, Register rk) {
  GenRegister(FSTX_S, rk, rj, fd);
}

void Assembler::fstx_d(FPURegister fd, Register rj, Register rk) {
  GenRegister(FSTX_D, rk, rj, fd);
}

void Assembler::AdjustBaseAndOffset(MemOperand* src) {
  // is_int12 must be passed a signed value, hence the static cast below.
  if ((!src->hasIndexReg() && is_int12(src->offset())) || src->hasIndexReg()) {
    return;
  }
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  if (is_uint12(static_cast<int32_t>(src->offset()))) {
    ori(scratch, zero_reg, src->offset() & kImm12Mask);
  } else {
    lu12i_w(scratch, src->offset() >> 12 & 0xfffff);
    if (src->offset() & kImm12Mask) {
      ori(scratch, scratch, src->offset() & kImm12Mask);
    }
  }
  src->index_ = scratch;
  src->offset_ = 0;
}

void Assembler::RelocateRelativeReference(
    RelocInfo::Mode rmode, Address pc, intptr_t pc_delta,
    WritableJitAllocation* jit_allocation) {
  DCHECK(RelocInfo::IsRelativeCodeTarget(rmode) ||
         RelocInfo::IsNearBuiltinEntry(rmode));
  Instr instr = instr_at(pc);
  int32_t offset = instr & kImm26Mask;
  offset = (((offset & 0x3ff) << 22 >> 6) | ((offset >> 10) & kImm16Mask)) << 2;
  offset -= pc_delta;
  offset >>= 2;
  offset = ((offset & kImm16Mask) << kRkShift) | ((offset & kImm26Mask) >> 16);
  Instr new_instr = (instr & ~kImm26Mask) | offset;
  instr_at_put(pc, new_instr, jit_allocation);
  return;
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

  // None of our relocation types are pc relative pointing outside the code
  // buffer nor pc absolute pointing inside the code buffer, so there is no need
  // to relocate any emitted relocation entries.

  // Relocate internal references.
  for (auto pos : internal_reference_positions_) {
    Address address = reinterpret_cast<intptr_t>(buffer_start_) + pos;
    intptr_t internal_ref = ReadUnalignedValue<intptr_t>(address);
    if (internal_ref != kEndOfJumpChain) {
      internal_ref += pc_delta;
      WriteUnalignedValue<intptr_t>(address, internal_ref);
    }
  }
}

void Assembler::db(uint8_t data) {
  if (!is_buffer_growth_blocked()) {
    CheckBuffer();
  }
  *reinterpret_cast<uint8_t*>(pc_) = data;
  pc_ += sizeof(uint8_t);
}

void Assembler::dd(uint32_t data) {
  if (!is_buffer_growth_blocked()) {
    CheckBuffer();
  }
  *reinterpret_cast<uint32_t*>(pc_) = data;
  pc_ += sizeof(uint32_t);
}

void Assembler::dq(uint64_t data) {
  if (!is_buffer_growth_blocked()) {
    CheckBuffer();
  }
  *reinterpret_cast<uint64_t*>(pc_) = data;
  pc_ += sizeof(uint64_t);
}

void Assembler::dd(Label* label) {
  if (!is_buffer_growth_blocked()) {
    CheckBuffer();
  }
  uint64_t data;
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
      b(&after_pool);
      nop();  // TODO(LOONG_dev): remove this

      int pool_start = pc_offset();
      for (int i = 0; i < unbound_labels_count_; i++) {
        {
          b(&after_pool);
          nop();  // TODO(LOONG_dev): remove this
        }
      }
      nop();
      trampoline_ = Trampoline(pool_start, unbound_labels_count_);
      bind(&after_pool);

      trampoline_emitted_ = true;
      // As we are only going to emit trampoline once, we need to prevent any
      // further emission.
      next_buffer_ch
"""


```