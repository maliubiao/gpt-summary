Response:
My thought process to arrive at the summary of the provided code snippet goes like this:

1. **Understand the Context:** The initial prompt identifies the file as `v8/test/unittests/assembler/disasm-mips64-unittest.cc`. This immediately tells me it's a C++ file within the V8 project, specifically for *unit testing* the *disassembler* for the *MIPS64* architecture. The `.cc` extension confirms it's C++.

2. **Scan for Key Terms and Patterns:** I look for recurring keywords, function names, and structural elements. I see:
    * `TEST_F`: This is a Google Test macro, indicating that the code contains several individual test cases.
    * `DisasmMips64Test`: This is the name of the test fixture, further confirming the purpose of the tests.
    * `COMPARE`, `COMPARE_PC_REL_COMPACT`, `COMPARE_MSA_BRANCH`: These functions seem central to the testing logic. They likely take an instruction and its expected disassembled string representation as input.
    * MIPS64 instruction mnemonics: `add.d`, `lw`, `bne`, `movz.s`, `class.s`, `bovc`, `bc1eqz`, `cvt.d.s`, `ll`, `sc`, `bnz.b`, `ld_b`, `addvi_b`, `ldi_b`, `andi_b`, `and_v`, `fill_b`, `fclass_w`, etc. The sheer variety indicates it's testing a broad range of instructions.
    * Register names: `f3`, `f4`, `t0`, `a0`, `v0`, `w0`, etc.
    * Immediate values (integers).
    * `kArchVariant == kMips64rX`: This suggests the tests might be conditional based on the specific MIPS64 revision.
    * `CpuFeatures::IsSupported(MIPS_SIMD)`:  Indicates tests for SIMD instructions are conditionally executed based on CPU support.
    * `SET_UP()`, `VERIFY_RUN()`: These likely handle test setup and teardown/verification.
    * Memory operands: `MemOperand(v1, -1)`.

3. **Infer the Core Functionality:** Based on the recurring `COMPARE` functions and the presence of MIPS64 instructions, I can deduce the primary function: **to verify that the MIPS64 disassembler correctly translates machine code (binary instructions) into human-readable assembly language mnemonics.**

4. **Identify Specific Testing Areas:**  The different `TEST_F` blocks (like `Type1`, `Type2`, `Type3`, `C_FMT_DISASM`, `MSA_BRANCH`, etc.) suggest the tests are categorized by instruction type or format. This indicates a systematic approach to testing the disassembler.

5. **Address the Specific Questions from the Prompt:**

    * **Functionality:** The core function is identified in step 3. The conditional execution based on architecture variant and CPU features is also important.
    * **.tq Extension:** The code is C++, not Torque, so this condition is false.
    * **Relationship to JavaScript:** While the disassembler is used internally by V8 (which executes JavaScript), the *test code itself* doesn't directly manipulate JavaScript values or execute JavaScript code. It focuses on the low-level assembly representation.
    * **Code Logic Inference (Input/Output):** The `COMPARE` macros provide clear input (the assembler instruction) and expected output (the disassembled string). For example, `COMPARE(add_d(f1, f2, f3), "46231000       add.d   f1, f2, f3")` shows that the input `add_d(f1, f2, f3)` should produce the output string `"46231000       add.d   f1, f2, f3"`.
    * **Common Programming Errors:** This snippet primarily tests the *disassembler*. It doesn't directly demonstrate common *user* programming errors in JavaScript or C++. However, if the disassembler were buggy, it could lead to incorrect analysis of compiled code, which *could* indirectly make debugging user errors harder.
    * **Summarize Functionality (Part 2):** This requires synthesizing the information gathered so far. I focus on the specific instructions tested in this part of the snippet.

6. **Structure the Summary:** I organize the summary to address the prompt's requirements clearly and concisely. I use bullet points for easy readability.

7. **Refine and Clarify:**  I review the summary for accuracy and completeness, ensuring I haven't made any incorrect assumptions or missed crucial details. For instance, I explicitly mention that the tests are for the *MIPS64* disassembler and that the `.cc` extension indicates C++.

By following these steps, I can effectively analyze the provided code snippet and generate a comprehensive and accurate summary of its functionality.
这是提供的 v8 源代码文件 `v8/test/unittests/assembler/disasm-mips64-unittest.cc` 的第二部分，它延续了第一部分的测试逻辑，主要功能仍然是 **测试 MIPS64 指令反汇编器的正确性**。

以下是对这部分代码功能的归纳：

* **继续测试浮点运算指令的反汇编:**  这部分代码延续了上一部分的模式，通过 `COMPARE` 宏，对比了汇编器生成的二进制指令与预期反汇编结果是否一致。它覆盖了更多的浮点运算指令，包括：
    * **选择指令:** `seleqz.d`, `selnez.d`, `seleqz.s`, `selnez.s`, `sel.s`, `sel.d`。
    * **最小值/最大值指令:** `min.d`, `max.d`, `min.s`, `max.s`, `mina.d`, `mina.s`, `maxa.d`, `maxa.s`。
    * **取整指令:** `rint.d`, `rint.s`。
    * **截断/舍入指令:** `trunc_w_d`, `trunc_w_s`, `round_w_s`, `round_w_d`, `round_l_s`, `round_l_d`, `floor_w_s`, `floor_w_d`, `floor_l_s`, `floor_l_d`, `ceil_w_s`, `ceil_w_d`, `ceil_l_s`, `ceil_l_d`。
    * **算术指令:** `sub_s`, `sub_d`, `sqrt_s`, `sqrt_d`, `neg_s`, `neg_d`, `mul_s`, `mul_d`, `rsqrt_s`, `rsqrt_d`, `recip_s`, `recip_d`。
    * **移动指令:** `mov_s`, `mov_d`。
    * **特定于 MIPS64r2 的指令:**  `trunc_l_d`, `trunc_l_s`, `movz_s`, `movz_d`, `movt_s`, `movt_d`, `movf_s`, `movf_d`, `movn_s`, `movn_d`。

* **测试 MIPS64r6 特有的浮点类型分类指令:**  `TEST_F(DisasmMips64Test, Type2)` 代码块专门针对 MIPS64 Release 6 (r6) 架构，测试了 `class.s` 和 `class.d` 指令的反汇编。

* **测试 MIPS64r6 特有的压缩分支指令:** `TEST_F(DisasmMips64Test, Type3)` 代码块主要测试了 MIPS64r6 引入的 16 位偏移的压缩分支指令的反汇编，包括：
    * **带溢出/无溢出比较分支:** `bovc`, `bnvc`。
    * **比较等于零/不等于零分支 (compact):** `beqzc`, `bnezc`。
    * **无条件分支 (compact):** `bc`, `balc`。
    * **带符号/无符号大于等于/小于比较分支 (compact):** `bgeuc`, `bgezalc`, `blezalc`, `bltuc`, `bltzalc`, `bgtzalc`。
    * **其他条件分支 (compact):** `bgezc`, `bgec`, `blezc`, `bltzc`, `bltc`, `bgtzc`。
    * **浮点条件分支 (compact):** `bc1eqz`, `bc1nez`。
    * **比较等于/不等于分支 (compact):** `beqc`, `bnec`。

* **继续测试标准分支指令的反汇编:**  `TEST_F(DisasmMips64Test, Type3)` 也包含对标准 32 位偏移分支指令的测试，例如 `bne`, `beq`, `bltz`, `bgez`, `blez`, `bgtz`。

* **测试 MIPS64r2 特有的浮点条件比较指令:** `TEST_F(DisasmMips64Test, C_FMT_DISASM)` 代码块专门针对 MIPS64r2，测试了 `c.f.s`, `c.f.d`, `c.un.s`, `c.un.d`, `c.eq.s`, `c.eq.d`, `c.ueq.s`, `c.ueq.d`, `c.olt.s`,
Prompt: 
```
这是目录为v8/test/unittests/assembler/disasm-mips64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/assembler/disasm-mips64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
    f3, f4, f5");
    COMPARE(selnez(D, f3, f4, f5), "462520d7       selnez.d    f3, f4, f5");
    COMPARE(seleqz(S, f3, f4, f5), "460520d4       seleqz.s    f3, f4, f5");
    COMPARE(selnez(S, f3, f4, f5), "460520d7       selnez.s    f3, f4, f5");

    COMPARE(min_d(f3, f4, f5), "462520dc       min.d    f3, f4, f5");
    COMPARE(max_d(f3, f4, f5), "462520de       max.d    f3, f4, f5");

    COMPARE(sel(S, f3, f4, f5), "460520d0       sel.s      f3, f4, f5");
    COMPARE(sel(D, f3, f4, f5), "462520d0       sel.d      f3, f4, f5");

    COMPARE(rint_d(f8, f6), "4620321a       rint.d    f8, f6");

    COMPARE(min_s(f3, f4, f5), "460520dc       min.s    f3, f4, f5");
    COMPARE(max_s(f3, f4, f5), "460520de       max.s    f3, f4, f5");

    COMPARE(rint(S, f8, f6), "4600321a       rint.s    f8, f6");

    COMPARE(mina_d(f3, f4, f5), "462520dd       mina.d   f3, f4, f5");
    COMPARE(mina_s(f3, f4, f5), "460520dd       mina.s   f3, f4, f5");

    COMPARE(maxa_d(f3, f4, f5), "462520df       maxa.d   f3, f4, f5");
    COMPARE(maxa_s(f3, f4, f5), "460520df       maxa.s   f3, f4, f5");
  }
  COMPARE(trunc_w_d(f8, f6), "4620320d       trunc.w.d f8, f6");
  COMPARE(trunc_w_s(f8, f6), "4600320d       trunc.w.s f8, f6");

  COMPARE(round_w_s(f8, f6), "4600320c       round.w.s f8, f6");
  COMPARE(round_w_d(f8, f6), "4620320c       round.w.d f8, f6");

  COMPARE(round_l_s(f8, f6), "46003208       round.l.s f8, f6");
  COMPARE(round_l_d(f8, f6), "46203208       round.l.d f8, f6");

  COMPARE(floor_w_s(f8, f6), "4600320f       floor.w.s f8, f6");
  COMPARE(floor_w_d(f8, f6), "4620320f       floor.w.d f8, f6");

  COMPARE(floor_l_s(f8, f6), "4600320b       floor.l.s f8, f6");
  COMPARE(floor_l_d(f8, f6), "4620320b       floor.l.d f8, f6");

  COMPARE(ceil_w_s(f8, f6), "4600320e       ceil.w.s f8, f6");
  COMPARE(ceil_w_d(f8, f6), "4620320e       ceil.w.d f8, f6");

  COMPARE(ceil_l_s(f8, f6), "4600320a       ceil.l.s f8, f6");
  COMPARE(ceil_l_d(f8, f6), "4620320a       ceil.l.d f8, f6");

  COMPARE(sub_s(f10, f8, f6), "46064281       sub.s   f10, f8, f6");
  COMPARE(sub_d(f10, f8, f6), "46264281       sub.d   f10, f8, f6");

  COMPARE(sqrt_s(f8, f6), "46003204       sqrt.s  f8, f6");
  COMPARE(sqrt_d(f8, f6), "46203204       sqrt.d  f8, f6");

  COMPARE(neg_s(f8, f6), "46003207       neg.s   f8, f6");
  COMPARE(neg_d(f8, f6), "46203207       neg.d   f8, f6");

  COMPARE(mul_s(f8, f6, f4), "46043202       mul.s   f8, f6, f4");
  COMPARE(mul_d(f8, f6, f4), "46243202       mul.d   f8, f6, f4");

  COMPARE(rsqrt_s(f8, f6), "46003216       rsqrt.s  f8, f6");
  COMPARE(rsqrt_d(f8, f6), "46203216       rsqrt.d  f8, f6");

  COMPARE(recip_s(f8, f6), "46003215       recip.s  f8, f6");
  COMPARE(recip_d(f8, f6), "46203215       recip.d  f8, f6");

  COMPARE(mov_s(f6, f4), "46002186       mov.s   f6, f4");
  COMPARE(mov_d(f6, f4), "46202186       mov.d   f6, f4");
  if (kArchVariant == kMips64r2) {
    COMPARE(trunc_l_d(f8, f6), "46203209       trunc.l.d f8, f6");
    COMPARE(trunc_l_s(f8, f6), "46003209       trunc.l.s f8, f6");

    COMPARE(movz_s(f6, f4, t0), "460c2192       movz.s    f6, f4, t0");
    COMPARE(movz_d(f6, f4, t0), "462c2192       movz.d    f6, f4, t0");

    COMPARE(movt_s(f6, f4, 4), "46112191       movt.s    f6, f4, cc(1)");
    COMPARE(movt_d(f6, f4, 4), "46312191       movt.d    f6, f4, cc(1)");

    COMPARE(movf_s(f6, f4, 4), "46102191       movf.s    f6, f4, cc(1)");
    COMPARE(movf_d(f6, f4, 4), "46302191       movf.d    f6, f4, cc(1)");

    COMPARE(movn_s(f6, f4, t0), "460c2193       movn.s    f6, f4, t0");
    COMPARE(movn_d(f6, f4, t0), "462c2193       movn.d    f6, f4, t0");
  }
  VERIFY_RUN();
}

TEST_F(DisasmMips64Test, Type2) {
  if (kArchVariant == kMips64r6) {
    SET_UP();

    COMPARE(class_s(f3, f4), "460020db       class.s f3, f4");
    COMPARE(class_d(f2, f3), "4620189b       class.d f2, f3");

    VERIFY_RUN();
  }
}

TEST_F(DisasmMips64Test, Type3) {
  SET_UP();

  if (kArchVariant == kMips64r6) {
    COMPARE_PC_REL_COMPACT(bovc(a0, a0, static_cast<int16_t>(0)),
                           "20840000       bovc  a0, a0, 0", 0);
    COMPARE_PC_REL_COMPACT(bovc(a1, a0, static_cast<int16_t>(0)),
                           "20a40000       bovc  a1, a0, 0", 0);
    COMPARE_PC_REL_COMPACT(bovc(a1, a0, 32767),
                           "20a47fff       bovc  a1, a0, 32767", 32767);
    COMPARE_PC_REL_COMPACT(bovc(a1, a0, -32768),
                           "20a48000       bovc  a1, a0, -32768", -32768);

    COMPARE_PC_REL_COMPACT(bnvc(a0, a0, static_cast<int16_t>(0)),
                           "60840000       bnvc  a0, a0, 0", 0);
    COMPARE_PC_REL_COMPACT(bnvc(a1, a0, static_cast<int16_t>(0)),
                           "60a40000       bnvc  a1, a0, 0", 0);
    COMPARE_PC_REL_COMPACT(bnvc(a1, a0, 32767),
                           "60a47fff       bnvc  a1, a0, 32767", 32767);
    COMPARE_PC_REL_COMPACT(bnvc(a1, a0, -32768),
                           "60a48000       bnvc  a1, a0, -32768", -32768);

    COMPARE_PC_REL_COMPACT(beqzc(a0, 0), "d8800000       beqzc   a0, 0", 0);
    COMPARE_PC_REL_COMPACT(beqzc(a0, 1048575),  // 0x0FFFFF ==  1048575.
                           "d88fffff       beqzc   a0, 1048575", 1048575);
    COMPARE_PC_REL_COMPACT(beqzc(a0, -1048576),  // 0x100000 == -1048576.
                           "d8900000       beqzc   a0, -1048576", -1048576);

    COMPARE_PC_REL_COMPACT(bnezc(a0, 0), "f8800000       bnezc   a0, 0", 0);
    COMPARE_PC_REL_COMPACT(bnezc(a0, 1048575),  // int21 maximal value.
                           "f88fffff       bnezc   a0, 1048575", 1048575);
    COMPARE_PC_REL_COMPACT(bnezc(a0, -1048576),  // int21 minimal value.
                           "f8900000       bnezc   a0, -1048576", -1048576);

    COMPARE_PC_REL_COMPACT(bc(-33554432), "ca000000       bc      -33554432",
                           -33554432);
    COMPARE_PC_REL_COMPACT(bc(-1), "cbffffff       bc      -1", -1);
    COMPARE_PC_REL_COMPACT(bc(0), "c8000000       bc      0", 0);
    COMPARE_PC_REL_COMPACT(bc(1), "c8000001       bc      1", 1);
    COMPARE_PC_REL_COMPACT(bc(33554431), "c9ffffff       bc      33554431",
                           33554431);

    COMPARE_PC_REL_COMPACT(balc(-33554432), "ea000000       balc    -33554432",
                           -33554432);
    COMPARE_PC_REL_COMPACT(balc(-1), "ebffffff       balc    -1", -1);
    COMPARE_PC_REL_COMPACT(balc(0), "e8000000       balc    0", 0);
    COMPARE_PC_REL_COMPACT(balc(1), "e8000001       balc    1", 1);
    COMPARE_PC_REL_COMPACT(balc(33554431), "e9ffffff       balc    33554431",
                           33554431);

    COMPARE_PC_REL_COMPACT(bgeuc(a0, a1, -32768),
                           "18858000       bgeuc   a0, a1, -32768", -32768);
    COMPARE_PC_REL_COMPACT(bgeuc(a0, a1, -1),
                           "1885ffff       bgeuc   a0, a1, -1", -1);
    COMPARE_PC_REL_COMPACT(bgeuc(a0, a1, 1), "18850001       bgeuc   a0, a1, 1",
                           1);
    COMPARE_PC_REL_COMPACT(bgeuc(a0, a1, 32767),
                           "18857fff       bgeuc   a0, a1, 32767", 32767);

    COMPARE_PC_REL_COMPACT(bgezalc(a0, -32768),
                           "18848000       bgezalc a0, -32768", -32768);
    COMPARE_PC_REL_COMPACT(bgezalc(a0, -1), "1884ffff       bgezalc a0, -1",
                           -1);
    COMPARE_PC_REL_COMPACT(bgezalc(a0, 1), "18840001       bgezalc a0, 1", 1);
    COMPARE_PC_REL_COMPACT(bgezalc(a0, 32767),
                           "18847fff       bgezalc a0, 32767", 32767);

    COMPARE_PC_REL_COMPACT(blezalc(a0, -32768),
                           "18048000       blezalc a0, -32768", -32768);
    COMPARE_PC_REL_COMPACT(blezalc(a0, -1), "1804ffff       blezalc a0, -1",
                           -1);
    COMPARE_PC_REL_COMPACT(blezalc(a0, 1), "18040001       blezalc a0, 1", 1);
    COMPARE_PC_REL_COMPACT(blezalc(a0, 32767),
                           "18047fff       blezalc a0, 32767", 32767);

    COMPARE_PC_REL_COMPACT(bltuc(a0, a1, -32768),
                           "1c858000       bltuc   a0, a1, -32768", -32768);
    COMPARE_PC_REL_COMPACT(bltuc(a0, a1, -1),
                           "1c85ffff       bltuc   a0, a1, -1", -1);
    COMPARE_PC_REL_COMPACT(bltuc(a0, a1, 1), "1c850001       bltuc   a0, a1, 1",
                           1);
    COMPARE_PC_REL_COMPACT(bltuc(a0, a1, 32767),
                           "1c857fff       bltuc   a0, a1, 32767", 32767);

    COMPARE_PC_REL_COMPACT(bltzalc(a0, -32768),
                           "1c848000       bltzalc a0, -32768", -32768);
    COMPARE_PC_REL_COMPACT(bltzalc(a0, -1), "1c84ffff       bltzalc a0, -1",
                           -1);
    COMPARE_PC_REL_COMPACT(bltzalc(a0, 1), "1c840001       bltzalc a0, 1", 1);
    COMPARE_PC_REL_COMPACT(bltzalc(a0, 32767),
                           "1c847fff       bltzalc a0, 32767", 32767);

    COMPARE_PC_REL_COMPACT(bgtzalc(a0, -32768),
                           "1c048000       bgtzalc a0, -32768", -32768);
    COMPARE_PC_REL_COMPACT(bgtzalc(a0, -1), "1c04ffff       bgtzalc a0, -1",
                           -1);
    COMPARE_PC_REL_COMPACT(bgtzalc(a0, 1), "1c040001       bgtzalc a0, 1", 1);
    COMPARE_PC_REL_COMPACT(bgtzalc(a0, 32767),
                           "1c047fff       bgtzalc a0, 32767", 32767);

    COMPARE_PC_REL_COMPACT(bgezc(a0, -32768),
                           "58848000       bgezc    a0, -32768", -32768);
    COMPARE_PC_REL_COMPACT(bgezc(a0, -1), "5884ffff       bgezc    a0, -1", -1);
    COMPARE_PC_REL_COMPACT(bgezc(a0, 1), "58840001       bgezc    a0, 1", 1);
    COMPARE_PC_REL_COMPACT(bgezc(a0, 32767),
                           "58847fff       bgezc    a0, 32767", 32767);

    COMPARE_PC_REL_COMPACT(bgec(a0, a1, -32768),
                           "58858000       bgec     a0, a1, -32768", -32768);
    COMPARE_PC_REL_COMPACT(bgec(a0, a1, -1),
                           "5885ffff       bgec     a0, a1, -1", -1);
    COMPARE_PC_REL_COMPACT(bgec(a0, a1, 1), "58850001       bgec     a0, a1, 1",
                           1);
    COMPARE_PC_REL_COMPACT(bgec(a0, a1, 32767),
                           "58857fff       bgec     a0, a1, 32767", 32767);

    COMPARE_PC_REL_COMPACT(blezc(a0, -32768),
                           "58048000       blezc    a0, -32768", -32768);
    COMPARE_PC_REL_COMPACT(blezc(a0, -1), "5804ffff       blezc    a0, -1", -1);
    COMPARE_PC_REL_COMPACT(blezc(a0, 1), "58040001       blezc    a0, 1", 1);
    COMPARE_PC_REL_COMPACT(blezc(a0, 32767),
                           "58047fff       blezc    a0, 32767", 32767);

    COMPARE_PC_REL_COMPACT(bltzc(a0, -32768),
                           "5c848000       bltzc    a0, -32768", -32768);
    COMPARE_PC_REL_COMPACT(bltzc(a0, -1), "5c84ffff       bltzc    a0, -1", -1);
    COMPARE_PC_REL_COMPACT(bltzc(a0, 1), "5c840001       bltzc    a0, 1", 1);
    COMPARE_PC_REL_COMPACT(bltzc(a0, 32767),
                           "5c847fff       bltzc    a0, 32767", 32767);

    COMPARE_PC_REL_COMPACT(bltc(a0, a1, -32768),
                           "5c858000       bltc    a0, a1, -32768", -32768);
    COMPARE_PC_REL_COMPACT(bltc(a0, a1, -1),
                           "5c85ffff       bltc    a0, a1, -1", -1);
    COMPARE_PC_REL_COMPACT(bltc(a0, a1, 1), "5c850001       bltc    a0, a1, 1",
                           1);
    COMPARE_PC_REL_COMPACT(bltc(a0, a1, 32767),
                           "5c857fff       bltc    a0, a1, 32767", 32767);

    COMPARE_PC_REL_COMPACT(bgtzc(a0, -32768),
                           "5c048000       bgtzc    a0, -32768", -32768);
    COMPARE_PC_REL_COMPACT(bgtzc(a0, -1), "5c04ffff       bgtzc    a0, -1", -1);
    COMPARE_PC_REL_COMPACT(bgtzc(a0, 1), "5c040001       bgtzc    a0, 1", 1);
    COMPARE_PC_REL_COMPACT(bgtzc(a0, 32767),
                           "5c047fff       bgtzc    a0, 32767", 32767);

    COMPARE_PC_REL_COMPACT(bc1eqz(-32768, f1),
                           "45218000       bc1eqz    f1, -32768", -32768);
    COMPARE_PC_REL_COMPACT(bc1eqz(-1, f1), "4521ffff       bc1eqz    f1, -1",
                           -1);
    COMPARE_PC_REL_COMPACT(bc1eqz(1, f1), "45210001       bc1eqz    f1, 1", 1);
    COMPARE_PC_REL_COMPACT(bc1eqz(32767, f1),
                           "45217fff       bc1eqz    f1, 32767", 32767);

    COMPARE_PC_REL_COMPACT(bc1nez(-32768, f1),
                           "45a18000       bc1nez    f1, -32768", -32768);
    COMPARE_PC_REL_COMPACT(bc1nez(-1, f1), "45a1ffff       bc1nez    f1, -1",
                           -1);
    COMPARE_PC_REL_COMPACT(bc1nez(1, f1), "45a10001       bc1nez    f1, 1", 1);
    COMPARE_PC_REL_COMPACT(bc1nez(32767, f1),
                           "45a17fff       bc1nez    f1, 32767", 32767);

    COMPARE_PC_REL_COMPACT(bovc(a1, a0, -1), "20a4ffff       bovc  a1, a0, -1",
                           -1);
    COMPARE_PC_REL_COMPACT(bovc(a0, a0, 1), "20840001       bovc  a0, a0, 1",
                           1);

    COMPARE_PC_REL_COMPACT(beqc(a0, a1, -32768),
                           "20858000       beqc    a0, a1, -32768", -32768);
    COMPARE_PC_REL_COMPACT(beqc(a0, a1, -1),
                           "2085ffff       beqc    a0, a1, -1", -1);
    COMPARE_PC_REL_COMPACT(beqc(a0, a1, 1), "20850001       beqc    a0, a1, 1",
                           1);
    COMPARE_PC_REL_COMPACT(beqc(a0, a1, 32767),
                           "20857fff       beqc    a0, a1, 32767", 32767);

    COMPARE_PC_REL_COMPACT(bnec(a0, a1, -32768),
                           "60858000       bnec  a0, a1, -32768", -32768);
    COMPARE_PC_REL_COMPACT(bnec(a0, a1, -1), "6085ffff       bnec  a0, a1, -1",
                           -1);
    COMPARE_PC_REL_COMPACT(bnec(a0, a1, 1), "60850001       bnec  a0, a1, 1",
                           1);
    COMPARE_PC_REL_COMPACT(bnec(a0, a1, 32767),
                           "60857fff       bnec  a0, a1, 32767", 32767);
  }

  COMPARE_PC_REL_COMPACT(bne(a0, a1, -32768),
                         "14858000       bne     a0, a1, -32768", -32768);
  COMPARE_PC_REL_COMPACT(bne(a0, a1, -1), "1485ffff       bne     a0, a1, -1",
                         -1);
  COMPARE_PC_REL_COMPACT(bne(a0, a1, 1), "14850001       bne     a0, a1, 1", 1);
  COMPARE_PC_REL_COMPACT(bne(a0, a1, 32767),
                         "14857fff       bne     a0, a1, 32767", 32767);

  COMPARE_PC_REL_COMPACT(beq(a0, a1, -32768),
                         "10858000       beq     a0, a1, -32768", -32768);
  COMPARE_PC_REL_COMPACT(beq(a0, a1, -1), "1085ffff       beq     a0, a1, -1",
                         -1);
  COMPARE_PC_REL_COMPACT(beq(a0, a1, 1), "10850001       beq     a0, a1, 1", 1);
  COMPARE_PC_REL_COMPACT(beq(a0, a1, 32767),
                         "10857fff       beq     a0, a1, 32767", 32767);

  COMPARE_PC_REL_COMPACT(bltz(a0, -32768), "04808000       bltz    a0, -32768",
                         -32768);
  COMPARE_PC_REL_COMPACT(bltz(a0, -1), "0480ffff       bltz    a0, -1", -1);
  COMPARE_PC_REL_COMPACT(bltz(a0, 1), "04800001       bltz    a0, 1", 1);
  COMPARE_PC_REL_COMPACT(bltz(a0, 32767), "04807fff       bltz    a0, 32767",
                         32767);

  COMPARE_PC_REL_COMPACT(bgez(a0, -32768), "04818000       bgez    a0, -32768",
                         -32768);
  COMPARE_PC_REL_COMPACT(bgez(a0, -1), "0481ffff       bgez    a0, -1", -1);
  COMPARE_PC_REL_COMPACT(bgez(a0, 1), "04810001       bgez    a0, 1", 1);
  COMPARE_PC_REL_COMPACT(bgez(a0, 32767), "04817fff       bgez    a0, 32767",
                         32767);

  COMPARE_PC_REL_COMPACT(blez(a0, -32768), "18808000       blez    a0, -32768",
                         -32768);
  COMPARE_PC_REL_COMPACT(blez(a0, -1), "1880ffff       blez    a0, -1", -1);
  COMPARE_PC_REL_COMPACT(blez(a0, 1), "18800001       blez    a0, 1", 1);
  COMPARE_PC_REL_COMPACT(blez(a0, 32767), "18807fff       blez    a0, 32767",
                         32767);

  COMPARE_PC_REL_COMPACT(bgtz(a0, -32768), "1c808000       bgtz    a0, -32768",
                         -32768);
  COMPARE_PC_REL_COMPACT(bgtz(a0, -1), "1c80ffff       bgtz    a0, -1", -1);
  COMPARE_PC_REL_COMPACT(bgtz(a0, 1), "1c800001       bgtz    a0, 1", 1);
  COMPARE_PC_REL_COMPACT(bgtz(a0, 32767), "1c807fff       bgtz    a0, 32767",
                         32767);

  VERIFY_RUN();
}

TEST_F(DisasmMips64Test, C_FMT_DISASM) {
  if (kArchVariant == kMips64r2) {
    SET_UP();

    COMPARE(c_s(F, f8, f10, 0), "460a4030       c.f.s   f8, f10, cc(0)");
    COMPARE(c_d(F, f8, f10, 0), "462a4030       c.f.d   f8, f10, cc(0)");

    COMPARE(c_s(UN, f8, f10, 2), "460a4231       c.un.s  f8, f10, cc(2)");
    COMPARE(c_d(UN, f8, f10, 2), "462a4231       c.un.d  f8, f10, cc(2)");

    COMPARE(c_s(EQ, f8, f10, 4), "460a4432       c.eq.s  f8, f10, cc(4)");
    COMPARE(c_d(EQ, f8, f10, 4), "462a4432       c.eq.d  f8, f10, cc(4)");

    COMPARE(c_s(UEQ, f8, f10, 6), "460a4633       c.ueq.s f8, f10, cc(6)");
    COMPARE(c_d(UEQ, f8, f10, 6), "462a4633       c.ueq.d f8, f10, cc(6)");

    COMPARE(c_s(OLT, f8, f10, 0), "460a4034       c.olt.s f8, f10, cc(0)");
    COMPARE(c_d(OLT, f8, f10, 0), "462a4034       c.olt.d f8, f10, cc(0)");

    COMPARE(c_s(ULT, f8, f10, 2), "460a4235       c.ult.s f8, f10, cc(2)");
    COMPARE(c_d(ULT, f8, f10, 2), "462a4235       c.ult.d f8, f10, cc(2)");

    COMPARE(c_s(OLE, f8, f10, 4), "460a4436       c.ole.s f8, f10, cc(4)");
    COMPARE(c_d(OLE, f8, f10, 4), "462a4436       c.ole.d f8, f10, cc(4)");

    COMPARE(c_s(ULE, f8, f10, 6), "460a4637       c.ule.s f8, f10, cc(6)");
    COMPARE(c_d(ULE, f8, f10, 6), "462a4637       c.ule.d f8, f10, cc(6)");

    VERIFY_RUN();
  }
}

TEST_F(DisasmMips64Test, COND_FMT_DISASM) {
  if (kArchVariant == kMips64r6) {
    SET_UP();

    COMPARE(cmp_s(F, f6, f8, f10), "468a4180       cmp.af.s    f6, f8, f10");
    COMPARE(cmp_d(F, f6, f8, f10), "46aa4180       cmp.af.d  f6,  f8, f10");

    COMPARE(cmp_s(UN, f6, f8, f10), "468a4181       cmp.un.s    f6, f8, f10");
    COMPARE(cmp_d(UN, f6, f8, f10), "46aa4181       cmp.un.d  f6,  f8, f10");

    COMPARE(cmp_s(EQ, f6, f8, f10), "468a4182       cmp.eq.s    f6, f8, f10");
    COMPARE(cmp_d(EQ, f6, f8, f10), "46aa4182       cmp.eq.d  f6,  f8, f10");

    COMPARE(cmp_s(UEQ, f6, f8, f10), "468a4183       cmp.ueq.s   f6, f8, f10");
    COMPARE(cmp_d(UEQ, f6, f8, f10), "46aa4183       cmp.ueq.d  f6,  f8, f10");

    COMPARE(cmp_s(LT, f6, f8, f10), "468a4184       cmp.lt.s    f6, f8, f10");
    COMPARE(cmp_d(LT, f6, f8, f10), "46aa4184       cmp.lt.d  f6,  f8, f10");

    COMPARE(cmp_s(ULT, f6, f8, f10), "468a4185       cmp.ult.s   f6, f8, f10");
    COMPARE(cmp_d(ULT, f6, f8, f10), "46aa4185       cmp.ult.d  f6,  f8, f10");

    COMPARE(cmp_s(LE, f6, f8, f10), "468a4186       cmp.le.s    f6, f8, f10");
    COMPARE(cmp_d(LE, f6, f8, f10), "46aa4186       cmp.le.d  f6,  f8, f10");

    COMPARE(cmp_s(ULE, f6, f8, f10), "468a4187       cmp.ule.s   f6, f8, f10");
    COMPARE(cmp_d(ULE, f6, f8, f10), "46aa4187       cmp.ule.d  f6,  f8, f10");

    COMPARE(cmp_s(ORD, f6, f8, f10), "468a4191       cmp.or.s    f6, f8, f10");
    COMPARE(cmp_d(ORD, f6, f8, f10), "46aa4191       cmp.or.d  f6,  f8, f10");

    COMPARE(cmp_s(UNE, f6, f8, f10), "468a4192       cmp.une.s   f6, f8, f10");
    COMPARE(cmp_d(UNE, f6, f8, f10), "46aa4192       cmp.une.d  f6,  f8, f10");

    COMPARE(cmp_s(NE, f6, f8, f10), "468a4193       cmp.ne.s    f6, f8, f10");
    COMPARE(cmp_d(NE, f6, f8, f10), "46aa4193       cmp.ne.d  f6,  f8, f10");

    VERIFY_RUN();
  }
}

TEST_F(DisasmMips64Test, CVT_DISSASM) {
  SET_UP();
  COMPARE(cvt_d_s(f22, f24), "4600c5a1       cvt.d.s f22, f24");
  COMPARE(cvt_d_w(f22, f24), "4680c5a1       cvt.d.w f22, f24");
  if (kArchVariant == kMips64r6 || kArchVariant == kMips64r2) {
    COMPARE(cvt_d_l(f22, f24), "46a0c5a1       cvt.d.l f22, f24");
  }

  if (kArchVariant == kMips64r6 || kArchVariant == kMips64r2) {
    COMPARE(cvt_l_s(f22, f24), "4600c5a5       cvt.l.s f22, f24");
    COMPARE(cvt_l_d(f22, f24), "4620c5a5       cvt.l.d f22, f24");
  }

  COMPARE(cvt_s_d(f22, f24), "4620c5a0       cvt.s.d f22, f24");
  COMPARE(cvt_s_w(f22, f24), "4680c5a0       cvt.s.w f22, f24");
  if (kArchVariant == kMips64r6 || kArchVariant == kMips64r2) {
    COMPARE(cvt_s_l(f22, f24), "46a0c5a0       cvt.s.l f22, f24");
  }

  COMPARE(cvt_s_d(f22, f24), "4620c5a0       cvt.s.d f22, f24");
  COMPARE(cvt_s_w(f22, f24), "4680c5a0       cvt.s.w f22, f24");

  VERIFY_RUN();
}

TEST_F(DisasmMips64Test, ctc1_cfc1_disasm) {
  SET_UP();
  COMPARE(abs_d(f10, f31), "4620fa85       abs.d   f10, f31");
  COMPARE(ceil_w_s(f8, f31), "4600fa0e       ceil.w.s f8, f31");
  COMPARE(ctc1(a0, FCSR), "44c4f800       ctc1    a0, FCSR");
  COMPARE(cfc1(a0, FCSR), "4444f800       cfc1    a0, FCSR");
  VERIFY_RUN();
}

TEST_F(DisasmMips64Test, madd_msub_maddf_msubf) {
  SET_UP();
  if (kArchVariant == kMips64r6) {
    COMPARE(maddf_s(f4, f8, f10), "460a4118       maddf.s  f4, f8, f10");
    COMPARE(maddf_d(f4, f8, f10), "462a4118       maddf.d  f4, f8, f10");
    COMPARE(msubf_s(f4, f8, f10), "460a4119       msubf.s  f4, f8, f10");
    COMPARE(msubf_d(f4, f8, f10), "462a4119       msubf.d  f4, f8, f10");
  }
  VERIFY_RUN();
}

TEST_F(DisasmMips64Test, atomic_load_store) {
  SET_UP();
  if (kArchVariant == kMips64r6) {
    COMPARE(ll(v0, MemOperand(v1, -1)), "7c62ffb6       ll     v0, -1(v1)");
    COMPARE(sc(v0, MemOperand(v1, 1)), "7c6200a6       sc     v0, 1(v1)");
    COMPARE(lld(v0, MemOperand(v1, -1)), "7c62ffb7       lld     v0, -1(v1)");
    COMPARE(scd(v0, MemOperand(v1, 1)), "7c6200a7       scd     v0, 1(v1)");
  } else {
    COMPARE(ll(v0, MemOperand(v1, -1)), "c062ffff       ll     v0, -1(v1)");
    COMPARE(sc(v0, MemOperand(v1, 1)), "e0620001       sc     v0, 1(v1)");
    COMPARE(lld(v0, MemOperand(v1, -1)), "d062ffff       lld     v0, -1(v1)");
    COMPARE(scd(v0, MemOperand(v1, 1)), "f0620001       scd     v0, 1(v1)");
  }
  VERIFY_RUN();
}

TEST_F(DisasmMips64Test, MSA_BRANCH) {
  SET_UP();
  if ((kArchVariant == kMips64r6) && CpuFeatures::IsSupported(MIPS_SIMD)) {
    CpuFeatureScope fscope(&assm, MIPS_SIMD);

    COMPARE_MSA_BRANCH(bnz_b(w0, 1), "47800001       bnz.b  w0, 1", 1);
    COMPARE_MSA_BRANCH(bnz_h(w1, -1), "47a1ffff       bnz.h  w1, -1", -1);
    COMPARE_MSA_BRANCH(bnz_w(w2, 32767), "47c27fff       bnz.w  w2, 32767",
                       32767);
    COMPARE_MSA_BRANCH(bnz_d(w3, -32768), "47e38000       bnz.d  w3, -32768",
                       -32768);
    COMPARE_MSA_BRANCH(bnz_v(w0, static_cast<int16_t>(0)),
                       "45e00000       bnz.v  w0, 0", 0);
    COMPARE_MSA_BRANCH(bz_b(w0, 1), "47000001       bz.b  w0, 1", 1);
    COMPARE_MSA_BRANCH(bz_h(w1, -1), "4721ffff       bz.h  w1, -1", -1);
    COMPARE_MSA_BRANCH(bz_w(w2, 32767), "47427fff       bz.w  w2, 32767",
                       32767);
    COMPARE_MSA_BRANCH(bz_d(w3, -32768), "47638000       bz.d  w3, -32768",
                       -32768);
    COMPARE_MSA_BRANCH(bz_v(w0, static_cast<int16_t>(0)),
                       "45600000       bz.v  w0, 0", 0);
  }
  VERIFY_RUN();
}

TEST_F(DisasmMips64Test, MSA_MI10) {
  SET_UP();
  if ((kArchVariant == kMips64r6) && CpuFeatures::IsSupported(MIPS_SIMD)) {
    CpuFeatureScope fscope(&assm, MIPS_SIMD);

    COMPARE(ld_b(w0, MemOperand(at, -512)),
            "7a000820       ld.b  w0, -512(at)");
    COMPARE(ld_b(w1, MemOperand(v0, 0)), "78001060       ld.b  w1, 0(v0)");
    COMPARE(ld_b(w2, MemOperand(v1, 511)), "79ff18a0       ld.b  w2, 511(v1)");
    COMPARE(ld_h(w4, MemOperand(a1, -512)),
            "7a002921       ld.h  w4, -512(a1)");
    COMPARE(ld_h(w5, MemOperand(a2, 64)), "78403161       ld.h  w5, 64(a2)");
    COMPARE(ld_h(w6, MemOperand(a3, 511)), "79ff39a1       ld.h  w6, 511(a3)");
    COMPARE(ld_w(w10, MemOperand(a7, -512)),
            "7a005aa2       ld.w  w10, -512(a7)");
    COMPARE(ld_w(w11, MemOperand(t0, 511)),
            "79ff62e2       ld.w  w11, 511(t0)");
    COMPARE(ld_w(w12, MemOperand(t1, -128)),
            "7b806b22       ld.w  w12, -128(t1)");
    COMPARE(ld_d(w17, MemOperand(s2, -512)),
            "7a009463       ld.d  w17, -512(s2)");
    COMPARE(ld_d(w18, MemOperand(s3, 128)),
            "78809ca3       ld.d  w18, 128(s3)");
    COMPARE(ld_d(w19, MemOperand(s4, 511)),
            "79ffa4e3       ld.d  w19, 511(s4)");
    COMPARE(st_b(w0, MemOperand(at, -512)),
            "7a000824       st.b  w0, -512(at)");
    COMPARE(st_b(w1, MemOperand(v0, 0)), "78001064       st.b  w1, 0(v0)");
    COMPARE(st_b(w2, MemOperand(v1, 511)), "79ff18a4       st.b  w2, 511(v1)");
    COMPARE(st_h(w4, MemOperand(a1, -512)),
            "7a002925       st.h  w4, -512(a1)");
    COMPARE(st_h(w5, MemOperand(a2, 64)), "78403165       st.h  w5, 64(a2)");
    COMPARE(st_h(w6, MemOperand(a3, 511)), "79ff39a5       st.h  w6, 511(a3)");
    COMPARE(st_w(w10, MemOperand(a7, -512)),
            "7a005aa6       st.w  w10, -512(a7)");
    COMPARE(st_w(w11, MemOperand(t0, 511)),
            "79ff62e6       st.w  w11, 511(t0)");
    COMPARE(st_w(w12, MemOperand(t1, -128)),
            "7b806b26       st.w  w12, -128(t1)");
    COMPARE(st_d(w17, MemOperand(s2, -512)),
            "7a009467       st.d  w17, -512(s2)");
    COMPARE(st_d(w18, MemOperand(s3, 128)),
            "78809ca7       st.d  w18, 128(s3)");
    COMPARE(st_d(w19, MemOperand(s4, 511)),
            "79ffa4e7       st.d  w19, 511(s4)");
  }
  VERIFY_RUN();
}

TEST_F(DisasmMips64Test, MSA_I5) {
  SET_UP();
  if ((kArchVariant == kMips64r6) && CpuFeatures::IsSupported(MIPS_SIMD)) {
    CpuFeatureScope fscope(&assm, MIPS_SIMD);

    COMPARE(addvi_b(w3, w31, 30), "781ef8c6       addvi.b  w3, w31, 30");
    COMPARE(addvi_h(w24, w13, 26), "783a6e06       addvi.h  w24, w13, 26");
    COMPARE(addvi_w(w26, w20, 26), "785aa686       addvi.w  w26, w20, 26");
    COMPARE(addvi_d(w16, w1, 21), "78750c06       addvi.d  w16, w1, 21");
    COMPARE(ceqi_b(w24, w21, -8), "7818ae07       ceqi.b  w24, w21, -8");
    COMPARE(ceqi_h(w31, w15, 2), "78227fc7       ceqi.h  w31, w15, 2");
    COMPARE(ceqi_w(w12, w1, -1), "785f0b07       ceqi.w  w12, w1, -1");
    COMPARE(ceqi_d(w24, w22, 7), "7867b607       ceqi.d  w24, w22, 7");
    COMPARE(clei_s_b(w12, w16, 1), "7a018307       clei_s.b  w12, w16, 1");
    COMPARE(clei_s_h(w2, w10, -9), "7a375087       clei_s.h  w2, w10, -9");
    COMPARE(clei_s_w(w4, w11, -10), "7a565907       clei_s.w  w4, w11, -10");
    COMPARE(clei_s_d(w0, w29, -10), "7a76e807       clei_s.d  w0, w29, -10");
    COMPARE(clei_u_b(w21, w17, 3), "7a838d47       clei_u.b  w21, w17, 3");
    COMPARE(clei_u_h(w29, w7, 17), "7ab13f47       clei_u.h  w29, w7, 17");
    COMPARE(clei_u_w(w1, w1, 2), "7ac20847       clei_u.w  w1, w1, 2");
    COMPARE(clei_u_d(w27, w27, 29), "7afddec7       clei_u.d  w27, w27, 29");
    COMPARE(clti_s_b(w19, w13, -7), "79196cc7       clti_s.b  w19, w13, -7");
    COMPARE(clti_s_h(w15, w10, -12), "793453c7       clti_s.h  w15, w10, -12");
    COMPARE(clti_s_w(w12, w12, 11), "794b6307       clti_s.w  w12, w12, 11");
    COMPARE(clti_s_d(w29, w20, -15), "7971a747       clti_s.d  w29, w20, -15");
    COMPARE(clti_u_b(w14, w9, 29), "799d4b87       clti_u.b  w14, w9, 29");
    COMPARE(clti_u_h(w24, w25, 25), "79b9ce07       clti_u.h  w24, w25, 25");
    COMPARE(clti_u_w(w1, w1, 22), "79d60847       clti_u.w  w1, w1, 22");
    COMPARE(clti_u_d(w21, w25, 1), "79e1cd47       clti_u.d  w21, w25, 1");
    COMPARE(maxi_s_b(w22, w21, 1), "7901ad86       maxi_s.b  w22, w21, 1");
    COMPARE(maxi_s_h(w29, w5, -8), "79382f46       maxi_s.h  w29, w5, -8");
    COMPARE(maxi_s_w(w1, w10, -12), "79545046       maxi_s.w  w1, w10, -12");
    COMPARE(maxi_s_d(w13, w29, -16), "7970eb46       maxi_s.d  w13, w29, -16");
    COMPARE(maxi_u_b(w20, w0, 12), "798c0506       maxi_u.b  w20, w0, 12");
    COMPARE(maxi_u_h(w1, w14, 3), "79a37046       maxi_u.h  w1, w14, 3");
    COMPARE(maxi_u_w(w27, w22, 11), "79cbb6c6       maxi_u.w  w27, w22, 11");
    COMPARE(maxi_u_d(w26, w6, 4), "79e43686       maxi_u.d  w26, w6, 4");
    COMPARE(mini_s_b(w4, w1, 1), "7a010906       mini_s.b  w4, w1, 1");
    COMPARE(mini_s_h(w27, w27, -9), "7a37dec6       mini_s.h  w27, w27, -9");
    COMPARE(mini_s_w(w28, w11, 9), "7a495f06       mini_s.w  w28, w11, 9");
    COMPARE(mini_s_d(w11, w10, 10), "7a6a52c6       mini_s.d  w11, w10, 10");
    COMPARE(mini_u_b(w18, w23, 27), "7a9bbc86       mini_u.b  w18, w23, 27");
    COMPARE(mini_u_h(w7, w26, 18), "7ab2d1c6       mini_u.h  w7, w26, 18");
    COMPARE(mini_u_w(w11, w12, 26), "7ada62c6       mini_u.w  w11, w12, 26");
    COMPARE(mini_u_d(w11, w15, 2), "7ae27ac6       mini_u.d  w11, w15, 2");
    COMPARE(subvi_b(w24, w20, 19), "7893a606       subvi.b  w24, w20, 19");
    COMPARE(subvi_h(w11, w19, 4), "78a49ac6       subvi.h  w11, w19, 4");
    COMPARE(subvi_w(w12, w10, 11), "78cb5306       subvi.w  w12, w10, 11");
    COMPARE(subvi_d(w19, w16, 7), "78e784c6       subvi.d  w19, w16, 7");
  }
  VERIFY_RUN();
}

TEST_F(DisasmMips64Test, MSA_I10) {
  SET_UP();
  if ((kArchVariant == kMips64r6) && CpuFeatures::IsSupported(MIPS_SIMD)) {
    CpuFeatureScope fscope(&assm, MIPS_SIMD);

    COMPARE(ldi_b(w8, 198), "7b063207       ldi.b  w8, 198");
    COMPARE(ldi_h(w20, 313), "7b29cd07       ldi.h  w20, 313");
    COMPARE(ldi_w(w24, 492), "7b4f6607       ldi.w  w24, 492");
    COMPARE(ldi_d(w27, -180), "7b7a66c7       ldi.d  w27, -180");
  }
  VERIFY_RUN();
}

TEST_F(DisasmMips64Test, MSA_I8) {
  SET_UP();
  if ((kArchVariant == kMips64r6) && CpuFeatures::IsSupported(MIPS_SIMD)) {
    CpuFeatureScope fscope(&assm, MIPS_SIMD);

    COMPARE(andi_b(w2, w29, 48), "7830e880       andi.b  w2, w29, 48");
    COMPARE(bmnzi_b(w6, w22, 126), "787eb181       bmnzi.b  w6, w22, 126");
    COMPARE(bmzi_b(w27, w1, 88), "79580ec1       bmzi.b  w27, w1, 88");
    COMPARE(bseli_b(w29, w3, 189), "7abd1f41       bseli.b  w29, w3, 189");
    COMPARE(nori_b(w1, w17, 56), "7a388840       nori.b  w1, w17, 56");
    COMPARE(ori_b(w26, w20, 135), "7987a680       ori.b  w26, w20, 135");
    COMPARE(shf_b(w19, w30, 105), "7869f4c2       shf.b  w19, w30, 105");
    COMPARE(shf_h(w17, w8, 76), "794c4442       shf.h  w17, w8, 76");
    COMPARE(shf_w(w14, w3, 93), "7a5d1b82       shf.w  w14, w3, 93");
    COMPARE(xori_b(w16, w10, 20), "7b145400       xori.b  w16, w10, 20");
  }
  VERIFY_RUN();
}

TEST_F(DisasmMips64Test, MSA_VEC) {
  SET_UP();
  if ((kArchVariant == kMips64r6) && CpuFeatures::IsSupported(MIPS_SIMD)) {
    CpuFeatureScope fscope(&assm, MIPS_SIMD);

    COMPARE(and_v(w25, w20, w27), "781ba65e       and.v  w25, w20, w27");
    COMPARE(bmnz_v(w17, w6, w7), "7887345e       bmnz.v  w17, w6, w7");
    COMPARE(bmz_v(w3, w17, w9), "78a988de       bmz.v  w3, w17, w9");
    COMPARE(bsel_v(w8, w0, w14), "78ce021e       bsel.v  w8, w0, w14");
    COMPARE(nor_v(w7, w31, w0), "7840f9de       nor.v  w7, w31, w0");
    COMPARE(or_v(w24, w26, w30), "783ed61e       or.v  w24, w26, w30");
    COMPARE(xor_v(w7, w27, w15), "786fd9de       xor.v  w7, w27, w15");
  }
  VERIFY_RUN();
}

TEST_F(DisasmMips64Test, MSA_2R) {
  SET_UP();
  if ((kArchVariant == kMips64r6) && CpuFeatures::IsSupported(MIPS_SIMD)) {
    CpuFeatureScope fscope(&assm, MIPS_SIMD);

    COMPARE(fill_b(w30, a5), "7b004f9e       fill.b  w30, a5");
    COMPARE(fill_h(w31, s7), "7b01bfde       fill.h  w31, s7");
    COMPARE(fill_w(w16, t8), "7b02c41e       fill.w  w16, t8");
    COMPARE(fill_d(w27, a5), "7b034ede       fill.d  w27, a5");
    COMPARE(nloc_b(w21, w0), "7b08055e       nloc.b  w21, w0");
    COMPARE(nloc_h(w18, w31), "7b09fc9e       nloc.h  w18, w31");
    COMPARE(nloc_w(w2, w23), "7b0ab89e       nloc.w  w2, w23");
    COMPARE(nloc_d(w4, w10), "7b0b511e       nloc.d  w4, w10");
    COMPARE(nlzc_b(w31, w2), "7b0c17de       nlzc.b  w31, w2");
    COMPARE(nlzc_h(w27, w22), "7b0db6de       nlzc.h  w27, w22");
    COMPARE(nlzc_w(w10, w29), "7b0eea9e       nlzc.w  w10, w29");
    COMPARE(nlzc_d(w25, w9), "7b0f4e5e       nlzc.d  w25, w9");
    COMPARE(pcnt_b(w20, w18), "7b04951e       pcnt.b  w20, w18");
    COMPARE(pcnt_h(w0, w8), "7b05401e       pcnt.h  w0, w8");
    COMPARE(pcnt_w(w23, w9), "7b064dde       pcnt.w  w23, w9");
    COMPARE(pcnt_d(w21, w24), "7b07c55e       pcnt.d  w21, w24");
  }
  VERIFY_RUN();
}

TEST_F(DisasmMips64Test, MSA_2RF) {
  SET_UP();
  if ((kArchVariant == kMips64r6) && CpuFeatures::IsSupported(MIPS_SIMD)) {
    CpuFeatureScope fscope(&assm, MIPS_SIMD);

    COMPARE(fclass_w(w26, w12), "7b20669e       fclass.w  w26, w12");
    COMPARE(fclass_d(w24, w17), "7b218e1e       fclass.d  w24, w17");
    COMPARE(fexupl_w(w8, w0), "7b30021e       fexupl.w  w8, w0");
    COMPARE(fexupl_d(w17, w29), "7b31ec5e       fexupl.d  w17, w29");
    COMPARE(fexupr_w(w13, w4), "7b32235e       fexupr.w  w13, w4");
    COMPARE(fexupr_d(w5, w2), "7b33115e       
"""


```