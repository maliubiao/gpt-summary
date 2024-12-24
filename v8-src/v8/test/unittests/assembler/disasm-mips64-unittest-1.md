Response: Let's break down the thought process for summarizing this C++ code.

1. **Understand the Goal:** The request asks for a summary of a C++ file's functionality, particularly in relation to JavaScript, and notes it's the *second part* of a larger file. This "second part" clue is important – it suggests the *first part* likely handles the setup and infrastructure for the tests.

2. **Initial Scan and Keywords:** Quickly read through the code, looking for repeated patterns, keywords, and class names. I see:
    * `TEST_F`: This strongly indicates a testing framework (likely Google Test, given the V8 context).
    * `DisasmMips64Test`:  This is the name of the test fixture. "Disasm" suggests disassembler, and "Mips64" indicates the target architecture.
    * `COMPARE`: This macro is used extensively. It's comparing something, and the arguments seem to be assembly instructions (strings).
    * Instruction mnemonics like `fexupr.d`, `ffint_s_w`, `add_a.b`, `fadd_w`, `copy_s.b`, `bclri_b`, etc. These look like MIPS64 assembly instructions.
    * `CpuFeatures::IsSupported(MIPS_SIMD)` and `CpuFeatureScope`: This points to conditional execution of tests based on CPU features, specifically SIMD (Single Instruction, Multiple Data) for MIPS.
    * `VERIFY_RUN()`:  Another macro related to the test framework.
    * `kArchVariant == kMips64r6`: More conditional logic based on the MIPS architecture revision.
    * Register names like `w5`, `w2`, `t0`, `at`, `sp`.

3. **Formulate a Hypothesis:** Based on the keywords and patterns, a likely hypothesis is:  "This C++ file contains unit tests for a MIPS64 disassembler. It verifies that the disassembler correctly converts MIPS64 machine code (represented as hexadecimal strings) back into their corresponding assembly language mnemonics."

4. **Examine the `COMPARE` Macro:** The core of the testing seems to be the `COMPARE` macro. The first argument looks like a function call (or macro) that would generate the *actual* machine code for a MIPS64 instruction. The second argument is a string representing the *expected* disassembled output. Therefore, the `COMPARE` macro likely:
    * Assembles the MIPS64 instruction given in the first argument.
    * Disassembles the resulting machine code.
    * Compares the disassembled output with the expected string in the second argument.

5. **Identify the Test Categories:** Notice the different `TEST_F` blocks with descriptive names like `FP_Formats`, `MSA_3R`, `MSA_3RF`, `MSA_ELM`, `MSA_BIT`. These likely represent different categories of MIPS64 instructions being tested. "FP" probably means floating-point, and "MSA" likely refers to MIPS SIMD Architecture (or similar).

6. **Address the JavaScript Relationship:** The request specifically asks about the relationship to JavaScript. Consider the role of a disassembler in the V8 JavaScript engine:
    * V8 compiles JavaScript to machine code for the target architecture (in this case, MIPS64).
    * For debugging, profiling, or introspection, it might be necessary to disassemble the generated machine code to understand what's happening at a lower level.
    * This unit test is *not directly executing JavaScript code*. Instead, it's testing a *tool* (the disassembler) that would be used *by* V8 developers to work with the generated MIPS64 code.

7. **Construct the Summary (Initial Draft):**  Based on the above, a first draft of the summary could be: "This C++ file contains unit tests for the MIPS64 disassembler used in the V8 JavaScript engine. It tests the disassembler's ability to correctly convert MIPS64 machine code into assembly language. The `COMPARE` macro is used to verify the output for various MIPS64 instructions. The tests cover different instruction categories like floating-point and MSA instructions. This is the second part of the test file."

8. **Refine and Add Detail:** Review the draft and add more specific information:
    * Mention the conditional execution based on architecture variant and CPU features.
    * Explain the structure of the `COMPARE` macro more clearly.
    * Emphasize that the tests use pre-defined machine code and expected disassembly strings.
    * Strengthen the JavaScript link by explaining *why* a disassembler is relevant to a JavaScript engine like V8.
    * Explicitly state that the tests don't execute JavaScript directly.

9. **Generate the JavaScript Example (If Applicable):** Since the tests don't directly involve JavaScript execution, a relevant JavaScript example would demonstrate a scenario where disassembling MIPS64 code might be useful in the context of V8. This could involve:
    * Mentioning V8's compilation pipeline.
    * Describing the potential need to inspect generated machine code for performance analysis or debugging.
    *  A simplified (and conceptual) example of how one might hypothetically obtain and then *want* to disassemble generated code (even if the actual API for this isn't directly exposed in a simple way).

10. **Final Review:** Read the complete summary to ensure accuracy, clarity, and completeness. Check for any jargon that needs explanation.

This iterative process of scanning, hypothesizing, examining, categorizing, and refining helps in understanding the code's purpose and its relationship to the broader project (V8). The "second part" clue is a reminder that context from the first part might be needed for a full understanding, but we can still summarize the functionality of this specific file.
这个C++源代码文件 `disasm-mips64-unittest.cc` 的第二部分，延续了第一部分的功能，**主要用于测试 V8 JavaScript 引擎中 MIPS64 架构的反汇编器 (`Disassembler`) 的正确性。**

具体来说，这一部分继续定义了更多的单元测试用例，每个测试用例都针对特定的 MIPS64 指令或指令组合，验证反汇编器能否将对应的机器码正确地转换回人类可读的汇编代码。

**功能归纳：**

* **扩展了对 MIPS64 指令集的覆盖:**  在第一部分的基础上，这部分增加了对更多 MIPS64 指令的测试，包括但不限于：
    * **浮点指令 (FP):** 如 `fexupr.d`, `ffint_s.w`, `frcp.w`, `fsqrt.d` 等，涵盖了各种浮点运算、类型转换和数学函数。
    * **MSA (MIPS SIMD Architecture) 指令:**  如 `add_a.b`, `adds_s.h`, `ave_u.w`, `bclr.d`, `binsl.b`, `ceq.h`, `div_s.w`, `dotp_s.h`, `hadd_u.d`, `ilvev.w`, `max_a.b`, `min_s.d`, `mod_u.w`, `mulv.h`, `pckev.d`, `sld.w`, `sll.d`, `splat.h`, `sra.w`, `srar.b`, `srl.h`, `srlr.d`, `subs_u.w`, `subv.d`, `vshf.h` 等，涉及到 SIMD 向量运算的各种操作，包括算术、位操作、比较、数据重排等。
    * **MSA 浮点指令:** 如 `fadd_w`, `fcaf_d`, `fceq_w`, `fcle_d`, `fclt_w`, `fcne_d`, `fcor_w`, `fcueq_d`, `fcule_w`, `fcult_d`, `fcun_w`, `fcune_d`, `fdiv_w`, `fexdo_h`, `fexp2_d`, `fmadd_w`, `fmax_d`, `fmax_a_w`, `fmin_a_d`, `fmsub_w`, `fmul_d`, `fsaf_w`, `fseq_d`, `fsle_w`, `fslt_d`, `fsne_w`, `fsor_d`, `fsub_w`, `fsueq_d`, `fsule_w`, `fsult_d`, `fsun_w`, `fsune_d`, `ftq_h`, `madd_q_h`, `maddr_q_w`, `msub_q_h`, `msubr_q_w`, `mul_q_h`, `mulr_q_w` 等，涵盖了 MSA 架构下的浮点运算和乘加/乘减等复杂操作。
    * **MSA 元素操作指令:** 如 `copy_s.b`, `copy_u.h`, `sldi.w`, `splati.d`, `move_v`, `insert_h`, `insve_w`, `cfcmsa`, `ctcmsa` 等，用于在 MSA 向量寄存器中移动、复制和插入元素，以及访问 MSA 控制寄存器。
    * **MSA 位操作指令:** 如 `bclri_h`, `binsli.w`, `binsri.d`, `bnegi.b`, `bseti.w`, `sat_s.h`, `sat_u.d`, `slli.h`, `srai.w`, `srari.d`, `srli.h`, `srlri.w` 等，提供了对 MSA 向量中各个位进行操作的功能。

* **使用了 Google Test 框架:**  与第一部分一样，仍然使用 Google Test 框架来组织和运行测试用例。`TEST_F(DisasmMips64Test, ...)` 定义了属于 `DisasmMips64Test` 测试夹具的各个测试函数。

* **依赖于 `COMPARE` 宏:**  核心的验证逻辑仍然是通过 `COMPARE` 宏实现的。这个宏很可能接收一个表示 MIPS64 指令的操作（例如，通过汇编器组装得到机器码），以及一个预期的反汇编结果字符串。宏内部会执行反汇编操作，并将结果与预期字符串进行比较，如果匹配则测试通过，否则测试失败。

* **条件编译:**  部分测试用例使用了条件编译，例如 `if ((kArchVariant == kMips64r6) && CpuFeatures::IsSupported(MIPS_SIMD)) {...}`，这意味着这些测试只会在特定的 MIPS64 架构变体（例如 MIPS64 Release 6）并且 CPU 支持 MSA 特性时才会执行。

**与 JavaScript 的关系：**

这个文件直接测试的是 V8 引擎中用于处理 MIPS64 架构的底层组件——反汇编器。反汇编器的作用是将机器码转换回汇编代码，这在以下场景中对 JavaScript 引擎非常重要：

* **调试和故障排除:** 当 JavaScript 代码在 MIPS64 平台上运行时出现问题，开发者可能需要查看 V8 生成的机器码，以理解程序的实际执行流程。反汇编器可以将这些机器码转换为可读的汇编代码，帮助开发者定位问题。
* **性能分析:**  通过反汇编生成的机器码，可以分析 V8 的代码生成质量，识别潜在的性能瓶颈，并指导优化。
* **理解 V8 的内部机制:**  对于研究 V8 引擎内部工作原理的开发者来说，反汇编器是一个重要的工具，可以帮助他们理解 JavaScript 代码是如何被编译和执行的。

**JavaScript 举例说明 (间接关系):**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它测试的组件是 JavaScript 引擎运行的基础。 考虑以下概念性的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
console.log(result);
```

当这段 JavaScript 代码在 V8 引擎中执行时，V8 会将其编译成 MIPS64 机器码。  如果开发者想要查看 `add` 函数对应的 MIPS64 汇编代码，V8 内部就会使用类似于这里测试的反汇编器来完成这个转换。

例如，`TEST_F(DisasmMips64Test, FP_Formats)` 中测试的 `fadd.d` 指令，可能对应于 JavaScript 中浮点数加法操作编译后的部分机器码。

**总结来说，这个 C++ 文件是 V8 引擎质量保证体系的一部分，它通过详尽的单元测试，确保 MIPS64 反汇编器能够准确地将机器码翻译回汇编代码，这对于 V8 在 MIPS64 平台上的正确运行、调试和性能分析至关重要。**

Prompt: 
```
这是目录为v8/test/unittests/assembler/disasm-mips64-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
fexupr.d  w5, w2");
    COMPARE(ffint_s_w(w20, w29), "7b3ced1e       ffint_s.w  w20, w29");
    COMPARE(ffint_s_d(w12, w15), "7b3d7b1e       ffint_s.d  w12, w15");
    COMPARE(ffint_u_w(w7, w27), "7b3ed9de       ffint_u.w  w7, w27");
    COMPARE(ffint_u_d(w19, w16), "7b3f84de       ffint_u.d  w19, w16");
    COMPARE(ffql_w(w31, w13), "7b346fde       ffql.w  w31, w13");
    COMPARE(ffql_d(w12, w13), "7b356b1e       ffql.d  w12, w13");
    COMPARE(ffqr_w(w27, w30), "7b36f6de       ffqr.w  w27, w30");
    COMPARE(ffqr_d(w30, w15), "7b377f9e       ffqr.d  w30, w15");
    COMPARE(flog2_w(w25, w31), "7b2efe5e       flog2.w  w25, w31");
    COMPARE(flog2_d(w18, w10), "7b2f549e       flog2.d  w18, w10");
    COMPARE(frint_w(w7, w15), "7b2c79de       frint.w  w7, w15");
    COMPARE(frint_d(w21, w22), "7b2db55e       frint.d  w21, w22");
    COMPARE(frcp_w(w19, w0), "7b2a04de       frcp.w  w19, w0");
    COMPARE(frcp_d(w4, w14), "7b2b711e       frcp.d  w4, w14");
    COMPARE(frsqrt_w(w12, w17), "7b288b1e       frsqrt.w  w12, w17");
    COMPARE(frsqrt_d(w23, w11), "7b295dde       frsqrt.d  w23, w11");
    COMPARE(fsqrt_w(w0, w11), "7b26581e       fsqrt.w  w0, w11");
    COMPARE(fsqrt_d(w15, w12), "7b2763de       fsqrt.d  w15, w12");
    COMPARE(ftint_s_w(w30, w5), "7b382f9e       ftint_s.w  w30, w5");
    COMPARE(ftint_s_d(w5, w23), "7b39b95e       ftint_s.d  w5, w23");
    COMPARE(ftint_u_w(w20, w14), "7b3a751e       ftint_u.w  w20, w14");
    COMPARE(ftint_u_d(w23, w21), "7b3badde       ftint_u.d  w23, w21");
    COMPARE(ftrunc_s_w(w29, w17), "7b228f5e       ftrunc_s.w  w29, w17");
    COMPARE(ftrunc_s_d(w12, w27), "7b23db1e       ftrunc_s.d  w12, w27");
    COMPARE(ftrunc_u_w(w17, w15), "7b247c5e       ftrunc_u.w  w17, w15");
    COMPARE(ftrunc_u_d(w5, w27), "7b25d95e       ftrunc_u.d  w5, w27");
  }
  VERIFY_RUN();
}

TEST_F(DisasmMips64Test, MSA_3R) {
  SET_UP();
  if ((kArchVariant == kMips64r6) && CpuFeatures::IsSupported(MIPS_SIMD)) {
    CpuFeatureScope fscope(&assm, MIPS_SIMD);

    COMPARE(add_a_b(w26, w9, w4), "78044e90       add_a.b  w26, w9, w4");
    COMPARE(add_a_h(w23, w27, w31), "783fddd0       add_a.h  w23, w27, w31");
    COMPARE(add_a_w(w11, w6, w22), "785632d0       add_a.w  w11, w6, w22");
    COMPARE(add_a_d(w6, w10, w0), "78605190       add_a.d  w6, w10, w0");
    COMPARE(adds_a_b(w19, w24, w19), "7893c4d0       adds_a.b  w19, w24, w19");
    COMPARE(adds_a_h(w25, w6, w4), "78a43650       adds_a.h  w25, w6, w4");
    COMPARE(adds_a_w(w25, w17, w27), "78db8e50       adds_a.w  w25, w17, w27");
    COMPARE(adds_a_d(w15, w18, w26), "78fa93d0       adds_a.d  w15, w18, w26");
    COMPARE(adds_s_b(w29, w11, w19), "79135f50       adds_s.b  w29, w11, w19");
    COMPARE(adds_s_h(w5, w23, w26), "793ab950       adds_s.h  w5, w23, w26");
    COMPARE(adds_s_w(w16, w14, w13), "794d7410       adds_s.w  w16, w14, w13");
    COMPARE(adds_s_d(w2, w14, w28), "797c7090       adds_s.d  w2, w14, w28");
    COMPARE(adds_u_b(w3, w17, w14), "798e88d0       adds_u.b  w3, w17, w14");
    COMPARE(adds_u_h(w10, w30, w4), "79a4f290       adds_u.h  w10, w30, w4");
    COMPARE(adds_u_w(w15, w18, w20), "79d493d0       adds_u.w  w15, w18, w20");
    COMPARE(adds_u_d(w30, w10, w9), "79e95790       adds_u.d  w30, w10, w9");
    COMPARE(addv_b(w24, w20, w21), "7815a60e       addv.b  w24, w20, w21");
    COMPARE(addv_h(w4, w13, w27), "783b690e       addv.h  w4, w13, w27");
    COMPARE(addv_w(w19, w11, w14), "784e5cce       addv.w  w19, w11, w14");
    COMPARE(addv_d(w2, w21, w31), "787fa88e       addv.d  w2, w21, w31");
    COMPARE(asub_s_b(w23, w16, w3), "7a0385d1       asub_s.b  w23, w16, w3");
    COMPARE(asub_s_h(w22, w17, w25), "7a398d91       asub_s.h  w22, w17, w25");
    COMPARE(asub_s_w(w24, w1, w9), "7a490e11       asub_s.w  w24, w1, w9");
    COMPARE(asub_s_d(w13, w12, w12), "7a6c6351       asub_s.d  w13, w12, w12");
    COMPARE(asub_u_b(w10, w29, w11), "7a8bea91       asub_u.b  w10, w29, w11");
    COMPARE(asub_u_h(w18, w9, w15), "7aaf4c91       asub_u.h  w18, w9, w15");
    COMPARE(asub_u_w(w10, w19, w31), "7adf9a91       asub_u.w  w10, w19, w31");
    COMPARE(asub_u_d(w17, w10, w0), "7ae05451       asub_u.d  w17, w10, w0");
    COMPARE(ave_s_b(w2, w5, w1), "7a012890       ave_s.b  w2, w5, w1");
    COMPARE(ave_s_h(w16, w19, w9), "7a299c10       ave_s.h  w16, w19, w9");
    COMPARE(ave_s_w(w17, w31, w5), "7a45fc50       ave_s.w  w17, w31, w5");
    COMPARE(ave_s_d(w27, w25, w10), "7a6aced0       ave_s.d  w27, w25, w10");
    COMPARE(ave_u_b(w16, w19, w9), "7a899c10       ave_u.b  w16, w19, w9");
    COMPARE(ave_u_h(w28, w28, w11), "7aabe710       ave_u.h  w28, w28, w11");
    COMPARE(ave_u_w(w11, w12, w11), "7acb62d0       ave_u.w  w11, w12, w11");
    COMPARE(ave_u_d(w30, w19, w28), "7afc9f90       ave_u.d  w30, w19, w28");
    COMPARE(aver_s_b(w26, w16, w2), "7b028690       aver_s.b  w26, w16, w2");
    COMPARE(aver_s_h(w31, w27, w27), "7b3bdfd0       aver_s.h  w31, w27, w27");
    COMPARE(aver_s_w(w28, w18, w25), "7b599710       aver_s.w  w28, w18, w25");
    COMPARE(aver_s_d(w29, w21, w27), "7b7baf50       aver_s.d  w29, w21, w27");
    COMPARE(aver_u_b(w29, w26, w3), "7b83d750       aver_u.b  w29, w26, w3");
    COMPARE(aver_u_h(w18, w18, w9), "7ba99490       aver_u.h  w18, w18, w9");
    COMPARE(aver_u_w(w17, w25, w29), "7bddcc50       aver_u.w  w17, w25, w29");
    COMPARE(aver_u_d(w22, w22, w19), "7bf3b590       aver_u.d  w22, w22, w19");
    COMPARE(bclr_b(w2, w15, w29), "799d788d       bclr.b  w2, w15, w29");
    COMPARE(bclr_h(w16, w21, w28), "79bcac0d       bclr.h  w16, w21, w28");
    COMPARE(bclr_w(w19, w2, w9), "79c914cd       bclr.w  w19, w2, w9");
    COMPARE(bclr_d(w27, w31, w4), "79e4fecd       bclr.d  w27, w31, w4");
    COMPARE(binsl_b(w5, w16, w24), "7b18814d       binsl.b  w5, w16, w24");
    COMPARE(binsl_h(w30, w5, w10), "7b2a2f8d       binsl.h  w30, w5, w10");
    COMPARE(binsl_w(w14, w15, w13), "7b4d7b8d       binsl.w  w14, w15, w13");
    COMPARE(binsl_d(w23, w20, w12), "7b6ca5cd       binsl.d  w23, w20, w12");
    COMPARE(binsr_b(w22, w11, w2), "7b825d8d       binsr.b  w22, w11, w2");
    COMPARE(binsr_h(w0, w26, w6), "7ba6d00d       binsr.h  w0, w26, w6");
    COMPARE(binsr_w(w26, w3, w28), "7bdc1e8d       binsr.w  w26, w3, w28");
    COMPARE(binsr_d(w0, w0, w21), "7bf5000d       binsr.d  w0, w0, w21");
    COMPARE(bneg_b(w0, w11, w24), "7a98580d       bneg.b  w0, w11, w24");
    COMPARE(bneg_h(w28, w16, w4), "7aa4870d       bneg.h  w28, w16, w4");
    COMPARE(bneg_w(w3, w26, w19), "7ad3d0cd       bneg.w  w3, w26, w19");
    COMPARE(bneg_d(w13, w29, w15), "7aefeb4d       bneg.d  w13, w29, w15");
    COMPARE(bset_b(w31, w5, w31), "7a1f2fcd       bset.b  w31, w5, w31");
    COMPARE(bset_h(w14, w12, w6), "7a26638d       bset.h  w14, w12, w6");
    COMPARE(bset_w(w31, w9, w12), "7a4c4fcd       bset.w  w31, w9, w12");
    COMPARE(bset_d(w5, w22, w5), "7a65b14d       bset.d  w5, w22, w5");
    COMPARE(ceq_b(w31, w31, w18), "7812ffcf       ceq.b  w31, w31, w18");
    COMPARE(ceq_h(w10, w27, w9), "7829da8f       ceq.h  w10, w27, w9");
    COMPARE(ceq_w(w9, w5, w14), "784e2a4f       ceq.w  w9, w5, w14");
    COMPARE(ceq_d(w5, w17, w0), "7860894f       ceq.d  w5, w17, w0");
    COMPARE(cle_s_b(w23, w4, w9), "7a0925cf       cle_s.b  w23, w4, w9");
    COMPARE(cle_s_h(w22, w27, w19), "7a33dd8f       cle_s.h  w22, w27, w19");
    COMPARE(cle_s_w(w30, w26, w10), "7a4ad78f       cle_s.w  w30, w26, w10");
    COMPARE(cle_s_d(w18, w5, w10), "7a6a2c8f       cle_s.d  w18, w5, w10");
    COMPARE(cle_u_b(w1, w25, w0), "7a80c84f       cle_u.b  w1, w25, w0");
    COMPARE(cle_u_h(w7, w0, w29), "7abd01cf       cle_u.h  w7, w0, w29");
    COMPARE(cle_u_w(w25, w18, w1), "7ac1964f       cle_u.w  w25, w18, w1");
    COMPARE(cle_u_d(w6, w0, w30), "7afe018f       cle_u.d  w6, w0, w30");
    COMPARE(clt_s_b(w25, w2, w21), "7915164f       clt_s.b  w25, w2, w21");
    COMPARE(clt_s_h(w2, w19, w9), "7929988f       clt_s.h  w2, w19, w9");
    COMPARE(clt_s_w(w23, w8, w16), "795045cf       clt_s.w  w23, w8, w16");
    COMPARE(clt_s_d(w7, w30, w12), "796cf1cf       clt_s.d  w7, w30, w12");
    COMPARE(clt_u_b(w2, w31, w13), "798df88f       clt_u.b  w2, w31, w13");
    COMPARE(clt_u_h(w16, w31, w23), "79b7fc0f       clt_u.h  w16, w31, w23");
    COMPARE(clt_u_w(w3, w24, w9), "79c9c0cf       clt_u.w  w3, w24, w9");
    COMPARE(clt_u_d(w7, w0, w1), "79e101cf       clt_u.d  w7, w0, w1");
    COMPARE(div_s_b(w29, w3, w18), "7a121f52       div_s.b  w29, w3, w18");
    COMPARE(div_s_h(w17, w16, w13), "7a2d8452       div_s.h  w17, w16, w13");
    COMPARE(div_s_w(w4, w25, w30), "7a5ec912       div_s.w  w4, w25, w30");
    COMPARE(div_s_d(w31, w9, w20), "7a744fd2       div_s.d  w31, w9, w20");
    COMPARE(div_u_b(w6, w29, w10), "7a8ae992       div_u.b  w6, w29, w10");
    COMPARE(div_u_h(w24, w21, w14), "7aaeae12       div_u.h  w24, w21, w14");
    COMPARE(div_u_w(w29, w14, w25), "7ad97752       div_u.w  w29, w14, w25");
    COMPARE(div_u_d(w31, w1, w21), "7af50fd2       div_u.d  w31, w1, w21");
    COMPARE(dotp_s_h(w23, w22, w25), "7839b5d3       dotp_s.h  w23, w22, w25");
    COMPARE(dotp_s_w(w20, w14, w5), "78457513       dotp_s.w  w20, w14, w5");
    COMPARE(dotp_s_d(w17, w2, w22), "78761453       dotp_s.d  w17, w2, w22");
    COMPARE(dotp_u_h(w13, w2, w6), "78a61353       dotp_u.h  w13, w2, w6");
    COMPARE(dotp_u_w(w15, w22, w21), "78d5b3d3       dotp_u.w  w15, w22, w21");
    COMPARE(dotp_u_d(w4, w16, w26), "78fa8113       dotp_u.d  w4, w16, w26");
    COMPARE(dpadd_s_h(w1, w28, w22), "7936e053       dpadd_s.h  w1, w28, w22");
    COMPARE(dpadd_s_w(w10, w1, w12), "794c0a93       dpadd_s.w  w10, w1, w12");
    COMPARE(dpadd_s_d(w3, w21, w27), "797ba8d3       dpadd_s.d  w3, w21, w27");
    COMPARE(dpadd_u_h(w17, w5, w20), "79b42c53       dpadd_u.h  w17, w5, w20");
    COMPARE(dpadd_u_w(w24, w8, w16), "79d04613       dpadd_u.w  w24, w8, w16");
    COMPARE(dpadd_u_d(w15, w29, w16),
            "79f0ebd3       dpadd_u.d  w15, w29, w16");
    COMPARE(dpsub_s_h(w4, w11, w12), "7a2c5913       dpsub_s.h  w4, w11, w12");
    COMPARE(dpsub_s_w(w4, w7, w6), "7a463913       dpsub_s.w  w4, w7, w6");
    COMPARE(dpsub_s_d(w31, w12, w28),
            "7a7c67d3       dpsub_s.d  w31, w12, w28");
    COMPARE(dpsub_u_h(w4, w25, w17), "7ab1c913       dpsub_u.h  w4, w25, w17");
    COMPARE(dpsub_u_w(w19, w25, w16),
            "7ad0ccd3       dpsub_u.w  w19, w25, w16");
    COMPARE(dpsub_u_d(w7, w10, w26), "7afa51d3       dpsub_u.d  w7, w10, w26");
    COMPARE(hadd_s_h(w28, w24, w2), "7a22c715       hadd_s.h  w28, w24, w2");
    COMPARE(hadd_s_w(w24, w17, w11), "7a4b8e15       hadd_s.w  w24, w17, w11");
    COMPARE(hadd_s_d(w17, w15, w20), "7a747c55       hadd_s.d  w17, w15, w20");
    COMPARE(hadd_u_h(w12, w29, w17), "7ab1eb15       hadd_u.h  w12, w29, w17");
    COMPARE(hadd_u_w(w9, w5, w6), "7ac62a55       hadd_u.w  w9, w5, w6");
    COMPARE(hadd_u_d(w1, w20, w6), "7ae6a055       hadd_u.d  w1, w20, w6");
    COMPARE(hsub_s_h(w16, w14, w29), "7b3d7415       hsub_s.h  w16, w14, w29");
    COMPARE(hsub_s_w(w9, w13, w11), "7b4b6a55       hsub_s.w  w9, w13, w11");
    COMPARE(hsub_s_d(w30, w18, w14), "7b6e9795       hsub_s.d  w30, w18, w14");
    COMPARE(hsub_u_h(w7, w12, w14), "7bae61d5       hsub_u.h  w7, w12, w14");
    COMPARE(hsub_u_w(w21, w5, w5), "7bc52d55       hsub_u.w  w21, w5, w5");
    COMPARE(hsub_u_d(w11, w12, w31), "7bff62d5       hsub_u.d  w11, w12, w31");
    COMPARE(ilvev_b(w18, w16, w30), "7b1e8494       ilvev.b  w18, w16, w30");
    COMPARE(ilvev_h(w14, w0, w13), "7b2d0394       ilvev.h  w14, w0, w13");
    COMPARE(ilvev_w(w12, w25, w22), "7b56cb14       ilvev.w  w12, w25, w22");
    COMPARE(ilvev_d(w30, w27, w3), "7b63df94       ilvev.d  w30, w27, w3");
    COMPARE(ilvl_b(w29, w3, w21), "7a151f54       ilvl.b  w29, w3, w21");
    COMPARE(ilvl_h(w27, w10, w17), "7a3156d4       ilvl.h  w27, w10, w17");
    COMPARE(ilvl_w(w6, w1, w0), "7a400994       ilvl.w  w6, w1, w0");
    COMPARE(ilvl_d(w3, w16, w24), "7a7880d4       ilvl.d  w3, w16, w24");
    COMPARE(ilvod_b(w11, w5, w20), "7b942ad4       ilvod.b  w11, w5, w20");
    COMPARE(ilvod_h(w18, w13, w31), "7bbf6c94       ilvod.h  w18, w13, w31");
    COMPARE(ilvod_w(w29, w16, w24), "7bd88754       ilvod.w  w29, w16, w24");
    COMPARE(ilvod_d(w22, w12, w29), "7bfd6594       ilvod.d  w22, w12, w29");
    COMPARE(ilvr_b(w4, w30, w6), "7a86f114       ilvr.b  w4, w30, w6");
    COMPARE(ilvr_h(w28, w19, w29), "7abd9f14       ilvr.h  w28, w19, w29");
    COMPARE(ilvr_w(w18, w20, w21), "7ad5a494       ilvr.w  w18, w20, w21");
    COMPARE(ilvr_d(w23, w30, w12), "7aecf5d4       ilvr.d  w23, w30, w12");
    COMPARE(maddv_b(w17, w31, w29), "789dfc52       maddv.b  w17, w31, w29");
    COMPARE(maddv_h(w7, w24, w9), "78a9c1d2       maddv.h  w7, w24, w9");
    COMPARE(maddv_w(w22, w22, w20), "78d4b592       maddv.w  w22, w22, w20");
    COMPARE(maddv_d(w30, w26, w20), "78f4d792       maddv.d  w30, w26, w20");
    COMPARE(max_a_b(w23, w11, w23), "7b175dce       max_a.b  w23, w11, w23");
    COMPARE(max_a_h(w20, w5, w30), "7b3e2d0e       max_a.h  w20, w5, w30");
    COMPARE(max_a_w(w7, w18, w30), "7b5e91ce       max_a.w  w7, w18, w30");
    COMPARE(max_a_d(w8, w8, w31), "7b7f420e       max_a.d  w8, w8, w31");
    COMPARE(max_s_b(w10, w1, w19), "79130a8e       max_s.b  w10, w1, w19");
    COMPARE(max_s_h(w15, w29, w17), "7931ebce       max_s.h  w15, w29, w17");
    COMPARE(max_s_w(w15, w29, w14), "794eebce       max_s.w  w15, w29, w14");
    COMPARE(max_s_d(w25, w24, w3), "7963c64e       max_s.d  w25, w24, w3");
    COMPARE(max_u_b(w12, w24, w5), "7985c30e       max_u.b  w12, w24, w5");
    COMPARE(max_u_h(w5, w6, w7), "79a7314e       max_u.h  w5, w6, w7");
    COMPARE(max_u_w(w16, w4, w7), "79c7240e       max_u.w  w16, w4, w7");
    COMPARE(max_u_d(w26, w12, w24), "79f8668e       max_u.d  w26, w12, w24");
    COMPARE(min_a_b(w4, w26, w1), "7b81d10e       min_a.b  w4, w26, w1");
    COMPARE(min_a_h(w12, w13, w31), "7bbf6b0e       min_a.h  w12, w13, w31");
    COMPARE(min_a_w(w28, w20, w0), "7bc0a70e       min_a.w  w28, w20, w0");
    COMPARE(min_a_d(w12, w20, w19), "7bf3a30e       min_a.d  w12, w20, w19");
    COMPARE(min_s_b(w19, w3, w14), "7a0e1cce       min_s.b  w19, w3, w14");
    COMPARE(min_s_h(w27, w21, w8), "7a28aece       min_s.h  w27, w21, w8");
    COMPARE(min_s_w(w0, w14, w30), "7a5e700e       min_s.w  w0, w14, w30");
    COMPARE(min_s_d(w6, w8, w21), "7a75418e       min_s.d  w6, w8, w21");
    COMPARE(min_u_b(w22, w26, w8), "7a88d58e       min_u.b  w22, w26, w8");
    COMPARE(min_u_h(w7, w27, w12), "7aacd9ce       min_u.h  w7, w27, w12");
    COMPARE(min_u_w(w8, w20, w14), "7acea20e       min_u.w  w8, w20, w14");
    COMPARE(min_u_d(w26, w14, w15), "7aef768e       min_u.d  w26, w14, w15");
    COMPARE(mod_s_b(w18, w1, w26), "7b1a0c92       mod_s.b  w18, w1, w26");
    COMPARE(mod_s_h(w31, w30, w28), "7b3cf7d2       mod_s.h  w31, w30, w28");
    COMPARE(mod_s_w(w2, w6, w13), "7b4d3092       mod_s.w  w2, w6, w13");
    COMPARE(mod_s_d(w21, w27, w22), "7b76dd52       mod_s.d  w21, w27, w22");
    COMPARE(mod_u_b(w16, w7, w13), "7b8d3c12       mod_u.b  w16, w7, w13");
    COMPARE(mod_u_h(w24, w8, w7), "7ba74612       mod_u.h  w24, w8, w7");
    COMPARE(mod_u_w(w30, w2, w17), "7bd11792       mod_u.w  w30, w2, w17");
    COMPARE(mod_u_d(w31, w2, w25), "7bf917d2       mod_u.d  w31, w2, w25");
    COMPARE(msubv_b(w14, w5, w12), "790c2b92       msubv.b  w14, w5, w12");
    COMPARE(msubv_h(w6, w7, w30), "793e3992       msubv.h  w6, w7, w30");
    COMPARE(msubv_w(w13, w2, w21), "79551352       msubv.w  w13, w2, w21");
    COMPARE(msubv_d(w16, w14, w27), "797b7412       msubv.d  w16, w14, w27");
    COMPARE(mulv_b(w20, w3, w13), "780d1d12       mulv.b  w20, w3, w13");
    COMPARE(mulv_h(w27, w26, w14), "782ed6d2       mulv.h  w27, w26, w14");
    COMPARE(mulv_w(w10, w29, w3), "7843ea92       mulv.w  w10, w29, w3");
    COMPARE(mulv_d(w7, w19, w29), "787d99d2       mulv.d  w7, w19, w29");
    COMPARE(pckev_b(w5, w27, w7), "7907d954       pckev.b  w5, w27, w7");
    COMPARE(pckev_h(w1, w4, w27), "793b2054       pckev.h  w1, w4, w27");
    COMPARE(pckev_w(w30, w20, w0), "7940a794       pckev.w  w30, w20, w0");
    COMPARE(pckev_d(w6, w1, w15), "796f0994       pckev.d  w6, w1, w15");
    COMPARE(pckod_b(w18, w28, w30), "799ee494       pckod.b  w18, w28, w30");
    COMPARE(pckod_h(w26, w5, w8), "79a82e94       pckod.h  w26, w5, w8");
    COMPARE(pckod_w(w9, w4, w2), "79c22254       pckod.w  w9, w4, w2");
    COMPARE(pckod_d(w30, w22, w20), "79f4b794       pckod.d  w30, w22, w20");
    COMPARE(sld_b(w5, w23, t0), "780cb954       sld.b  w5, w23[t0]");
    COMPARE(sld_h(w1, w23, v1), "7823b854       sld.h  w1, w23[v1]");
    COMPARE(sld_w(w20, w8, a5), "78494514       sld.w  w20, w8[a5]");
    COMPARE(sld_d(w7, w23, fp), "787eb9d4       sld.d  w7, w23[fp]");
    COMPARE(sll_b(w3, w0, w17), "781100cd       sll.b  w3, w0, w17");
    COMPARE(sll_h(w17, w27, w3), "7823dc4d       sll.h  w17, w27, w3");
    COMPARE(sll_w(w16, w7, w6), "78463c0d       sll.w  w16, w7, w6");
    COMPARE(sll_d(w9, w0, w26), "787a024d       sll.d  w9, w0, w26");
    COMPARE(splat_b(w28, w1, at), "78810f14       splat.b  w28, w1[at]");
    COMPARE(splat_h(w2, w11, a7), "78ab5894       splat.h  w2, w11[a7]");
    COMPARE(splat_w(w22, w0, a7), "78cb0594       splat.w  w22, w0[a7]");
    COMPARE(splat_d(w0, w0, v0), "78e20014       splat.d  w0, w0[v0]");
    COMPARE(sra_b(w28, w4, w17), "7891270d       sra.b  w28, w4, w17");
    COMPARE(sra_h(w13, w9, w3), "78a34b4d       sra.h  w13, w9, w3");
    COMPARE(sra_w(w27, w21, w19), "78d3aecd       sra.w  w27, w21, w19");
    COMPARE(sra_d(w30, w8, w23), "78f7478d       sra.d  w30, w8, w23");
    COMPARE(srar_b(w19, w18, w18), "789294d5       srar.b  w19, w18, w18");
    COMPARE(srar_h(w7, w23, w8), "78a8b9d5       srar.h  w7, w23, w8");
    COMPARE(srar_w(w1, w12, w2), "78c26055       srar.w  w1, w12, w2");
    COMPARE(srar_d(w21, w7, w14), "78ee3d55       srar.d  w21, w7, w14");
    COMPARE(srl_b(w12, w3, w19), "79131b0d       srl.b  w12, w3, w19");
    COMPARE(srl_h(w23, w31, w20), "7934fdcd       srl.h  w23, w31, w20");
    COMPARE(srl_w(w18, w27, w11), "794bdc8d       srl.w  w18, w27, w11");
    COMPARE(srl_d(w3, w12, w26), "797a60cd       srl.d  w3, w12, w26");
    COMPARE(srlr_b(w15, w21, w11), "790babd5       srlr.b  w15, w21, w11");
    COMPARE(srlr_h(w21, w13, w19), "79336d55       srlr.h  w21, w13, w19");
    COMPARE(srlr_w(w6, w30, w3), "7943f195       srlr.w  w6, w30, w3");
    COMPARE(srlr_d(w1, w2, w14), "796e1055       srlr.d  w1, w2, w14");
    COMPARE(subs_s_b(w25, w15, w1), "78017e51       subs_s.b  w25, w15, w1");
    COMPARE(subs_s_h(w28, w25, w22), "7836cf11       subs_s.h  w28, w25, w22");
    COMPARE(subs_s_w(w10, w12, w21), "78556291       subs_s.w  w10, w12, w21");
    COMPARE(subs_s_d(w4, w20, w18), "7872a111       subs_s.d  w4, w20, w18");
    COMPARE(subs_u_b(w21, w6, w25), "78993551       subs_u.b  w21, w6, w25");
    COMPARE(subs_u_h(w3, w10, w7), "78a750d1       subs_u.h  w3, w10, w7");
    COMPARE(subs_u_w(w9, w15, w10), "78ca7a51       subs_u.w  w9, w15, w10");
    COMPARE(subs_u_d(w7, w19, w10), "78ea99d1       subs_u.d  w7, w19, w10");
    COMPARE(subsus_u_b(w6, w7, w12), "790c3991       subsus_u.b  w6, w7, w12");
    COMPARE(subsus_u_h(w6, w29, w19),
            "7933e991       subsus_u.h  w6, w29, w19");
    COMPARE(subsus_u_w(w7, w15, w7), "794779d1       subsus_u.w  w7, w15, w7");
    COMPARE(subsus_u_d(w9, w3, w15), "796f1a51       subsus_u.d  w9, w3, w15");
    COMPARE(subsuu_s_b(w22, w3, w31),
            "799f1d91       subsuu_s.b  w22, w3, w31");
    COMPARE(subsuu_s_h(w19, w23, w22),
            "79b6bcd1       subsuu_s.h  w19, w23, w22");
    COMPARE(subsuu_s_w(w9, w10, w13),
            "79cd5251       subsuu_s.w  w9, w10, w13");
    COMPARE(subsuu_s_d(w5, w6, w0), "79e03151       subsuu_s.d  w5, w6, w0");
    COMPARE(subv_b(w6, w13, w19), "7893698e       subv.b  w6, w13, w19");
    COMPARE(subv_h(w4, w25, w12), "78acc90e       subv.h  w4, w25, w12");
    COMPARE(subv_w(w27, w27, w11), "78cbdece       subv.w  w27, w27, w11");
    COMPARE(subv_d(w9, w24, w10), "78eac24e       subv.d  w9, w24, w10");
    COMPARE(vshf_b(w3, w16, w5), "780580d5       vshf.b  w3, w16, w5");
    COMPARE(vshf_h(w20, w19, w8), "78289d15       vshf.h  w20, w19, w8");
    COMPARE(vshf_w(w16, w30, w25), "7859f415       vshf.w  w16, w30, w25");
    COMPARE(vshf_d(w19, w11, w15), "786f5cd5       vshf.d  w19, w11, w15");
  }
  VERIFY_RUN();
}

TEST_F(DisasmMips64Test, MSA_3RF) {
  SET_UP();
  if ((kArchVariant == kMips64r6) && CpuFeatures::IsSupported(MIPS_SIMD)) {
    CpuFeatureScope fscope(&assm, MIPS_SIMD);

    COMPARE(fadd_w(w28, w19, w28), "781c9f1b       fadd.w  w28, w19, w28");
    COMPARE(fadd_d(w13, w2, w29), "783d135b       fadd.d  w13, w2, w29");
    COMPARE(fcaf_w(w14, w11, w25), "78195b9a       fcaf.w  w14, w11, w25");
    COMPARE(fcaf_d(w1, w1, w19), "7833085a       fcaf.d  w1, w1, w19");
    COMPARE(fceq_w(w1, w23, w16), "7890b85a       fceq.w  w1, w23, w16");
    COMPARE(fceq_d(w0, w8, w16), "78b0401a       fceq.d  w0, w8, w16");
    COMPARE(fcle_w(w16, w9, w24), "79984c1a       fcle.w  w16, w9, w24");
    COMPARE(fcle_d(w27, w14, w1), "79a176da       fcle.d  w27, w14, w1");
    COMPARE(fclt_w(w28, w8, w8), "7908471a       fclt.w  w28, w8, w8");
    COMPARE(fclt_d(w30, w25, w11), "792bcf9a       fclt.d  w30, w25, w11");
    COMPARE(fcne_w(w2, w18, w23), "78d7909c       fcne.w  w2, w18, w23");
    COMPARE(fcne_d(w14, w20, w15), "78efa39c       fcne.d  w14, w20, w15");
    COMPARE(fcor_w(w10, w18, w25), "7859929c       fcor.w  w10, w18, w25");
    COMPARE(fcor_d(w17, w25, w11), "786bcc5c       fcor.d  w17, w25, w11");
    COMPARE(fcueq_w(w14, w2, w21), "78d5139a       fcueq.w  w14, w2, w21");
    COMPARE(fcueq_d(w29, w3, w7), "78e71f5a       fcueq.d  w29, w3, w7");
    COMPARE(fcule_w(w17, w5, w3), "79c32c5a       fcule.w  w17, w5, w3");
    COMPARE(fcule_d(w31, w1, w30), "79fe0fda       fcule.d  w31, w1, w30");
    COMPARE(fcult_w(w6, w25, w9), "7949c99a       fcult.w  w6, w25, w9");
    COMPARE(fcult_d(w27, w8, w17), "797146da       fcult.d  w27, w8, w17");
    COMPARE(fcun_w(w4, w20, w8), "7848a11a       fcun.w  w4, w20, w8");
    COMPARE(fcun_d(w29, w11, w3), "78635f5a       fcun.d  w29, w11, w3");
    COMPARE(fcune_w(w13, w18, w19), "7893935c       fcune.w  w13, w18, w19");
    COMPARE(fcune_d(w16, w26, w21), "78b5d41c       fcune.d  w16, w26, w21");
    COMPARE(fdiv_w(w13, w24, w2), "78c2c35b       fdiv.w  w13, w24, w2");
    COMPARE(fdiv_d(w19, w4, w25), "78f924db       fdiv.d  w19, w4, w25");
    COMPARE(fexdo_h(w8, w0, w16), "7a10021b       fexdo.h  w8, w0, w16");
    COMPARE(fexdo_w(w0, w13, w27), "7a3b681b       fexdo.w  w0, w13, w27");
    COMPARE(fexp2_w(w17, w0, w3), "79c3045b       fexp2.w  w17, w0, w3");
    COMPARE(fexp2_d(w22, w0, w10), "79ea059b       fexp2.d  w22, w0, w10");
    COMPARE(fmadd_w(w29, w6, w23), "7917375b       fmadd.w  w29, w6, w23");
    COMPARE(fmadd_d(w11, w28, w21), "7935e2db       fmadd.d  w11, w28, w21");
    COMPARE(fmax_w(w0, w23, w13), "7b8db81b       fmax.w  w0, w23, w13");
    COMPARE(fmax_d(w26, w18, w8), "7ba8969b       fmax.d  w26, w18, w8");
    COMPARE(fmax_a_w(w10, w16, w10), "7bca829b       fmax_a.w  w10, w16, w10");
    COMPARE(fmax_a_d(w30, w9, w22), "7bf64f9b       fmax_a.d  w30, w9, w22");
    COMPARE(fmin_w(w24, w1, w30), "7b1e0e1b       fmin.w  w24, w1, w30");
    COMPARE(fmin_d(w27, w27, w10), "7b2adedb       fmin.d  w27, w27, w10");
    COMPARE(fmin_a_w(w10, w29, w20), "7b54ea9b       fmin_a.w  w10, w29, w20");
    COMPARE(fmin_a_d(w13, w30, w24), "7b78f35b       fmin_a.d  w13, w30, w24");
    COMPARE(fmsub_w(w17, w25, w0), "7940cc5b       fmsub.w  w17, w25, w0");
    COMPARE(fmsub_d(w8, w18, w16), "7970921b       fmsub.d  w8, w18, w16");
    COMPARE(fmul_w(w3, w15, w15), "788f78db       fmul.w  w3, w15, w15");
    COMPARE(fmul_d(w9, w30, w10), "78aaf25b       fmul.d  w9, w30, w10");
    COMPARE(fsaf_w(w25, w5, w10), "7a0a2e5a       fsaf.w  w25, w5, w10");
    COMPARE(fsaf_d(w25, w3, w29), "7a3d1e5a       fsaf.d  w25, w3, w29");
    COMPARE(fseq_w(w11, w17, w13), "7a8d8ada       fseq.w  w11, w17, w13");
    COMPARE(fseq_d(w29, w0, w31), "7abf075a       fseq.d  w29, w0, w31");
    COMPARE(fsle_w(w30, w31, w31), "7b9fff9a       fsle.w  w30, w31, w31");
    COMPARE(fsle_d(w18, w23, w24), "7bb8bc9a       fsle.d  w18, w23, w24");
    COMPARE(fslt_w(w12, w5, w6), "7b062b1a       fslt.w  w12, w5, w6");
    COMPARE(fslt_d(w16, w26, w21), "7b35d41a       fslt.d  w16, w26, w21");
    COMPARE(fsne_w(w30, w1, w12), "7acc0f9c       fsne.w  w30, w1, w12");
    COMPARE(fsne_d(w14, w13, w23), "7af76b9c       fsne.d  w14, w13, w23");
    COMPARE(fsor_w(w27, w13, w27), "7a5b6edc       fsor.w  w27, w13, w27");
    COMPARE(fsor_d(w12, w24, w11), "7a6bc31c       fsor.d  w12, w24, w11");
    COMPARE(fsub_w(w31, w26, w1), "7841d7db       fsub.w  w31, w26, w1");
    COMPARE(fsub_d(w19, w17, w27), "787b8cdb       fsub.d  w19, w17, w27");
    COMPARE(fsueq_w(w16, w24, w25), "7ad9c41a       fsueq.w  w16, w24, w25");
    COMPARE(fsueq_d(w18, w14, w14), "7aee749a       fsueq.d  w18, w14, w14");
    COMPARE(fsule_w(w23, w30, w13), "7bcdf5da       fsule.w  w23, w30, w13");
    COMPARE(fsule_d(w2, w11, w26), "7bfa589a       fsule.d  w2, w11, w26");
    COMPARE(fsult_w(w11, w26, w22), "7b56d2da       fsult.w  w11, w26, w22");
    COMPARE(fsult_d(w6, w23, w30), "7b7eb99a       fsult.d  w6, w23, w30");
    COMPARE(fsun_w(w3, w18, w28), "7a5c90da       fsun.w  w3, w18, w28");
    COMPARE(fsun_d(w18, w11, w19), "7a735c9a       fsun.d  w18, w11, w19");
    COMPARE(fsune_w(w16, w31, w2), "7a82fc1c       fsune.w  w16, w31, w2");
    COMPARE(fsune_d(w3, w26, w17), "7ab1d0dc       fsune.d  w3, w26, w17");
    COMPARE(ftq_h(w16, w4, w24), "7a98241b       ftq.h  w16, w4, w24");
    COMPARE(ftq_w(w5, w5, w25), "7ab9295b       ftq.w  w5, w5, w25");
    COMPARE(madd_q_h(w16, w20, w10), "794aa41c       madd_q.h  w16, w20, w10");
    COMPARE(madd_q_w(w28, w2, w9), "7969171c       madd_q.w  w28, w2, w9");
    COMPARE(maddr_q_h(w8, w18, w9), "7b49921c       maddr_q.h  w8, w18, w9");
    COMPARE(maddr_q_w(w29, w12, w16),
            "7b70675c       maddr_q.w  w29, w12, w16");
    COMPARE(msub_q_h(w24, w26, w10), "798ad61c       msub_q.h  w24, w26, w10");
    COMPARE(msub_q_w(w13, w30, w28), "79bcf35c       msub_q.w  w13, w30, w28");
    COMPARE(msubr_q_h(w12, w21, w11),
            "7b8bab1c       msubr_q.h  w12, w21, w11");
    COMPARE(msubr_q_w(w1, w14, w20), "7bb4705c       msubr_q.w  w1, w14, w20");
    COMPARE(mul_q_h(w6, w16, w30), "791e819c       mul_q.h  w6, w16, w30");
    COMPARE(mul_q_w(w16, w1, w4), "79240c1c       mul_q.w  w16, w1, w4");
    COMPARE(mulr_q_h(w6, w20, w19), "7b13a19c       mulr_q.h  w6, w20, w19");
    COMPARE(mulr_q_w(w27, w1, w20), "7b340edc       mulr_q.w  w27, w1, w20");
  }
  VERIFY_RUN();
}

TEST_F(DisasmMips64Test, MSA_ELM) {
  SET_UP();
  if ((kArchVariant == kMips64r6) && CpuFeatures::IsSupported(MIPS_SIMD)) {
    CpuFeatureScope fscope(&assm, MIPS_SIMD);

    COMPARE(copy_s_b(t1, w8, 2), "78824359       copy_s.b  t1, w8[2]");
    COMPARE(copy_s_h(at, w25, 0), "78a0c859       copy_s.h  at, w25[0]");
    COMPARE(copy_s_w(s6, w5, 1), "78b12d99       copy_s.w  s6, w5[1]");
    COMPARE(copy_s_d(s3, w31, 0), "78b8fcd9       copy_s.d  s3, w31[0]");
    COMPARE(copy_u_b(s6, w20, 4), "78c4a599       copy_u.b  s6, w20[4]");
    COMPARE(copy_u_h(s4, w4, 0), "78e02519       copy_u.h  s4, w4[0]");
    COMPARE(copy_u_w(t1, w0, 1), "78f10359       copy_u.w  t1, w0[1]");
    COMPARE(sldi_b(w0, w29, 4), "7804e819       sldi.b  w0, w29[4]");
    COMPARE(sldi_h(w8, w17, 0), "78208a19       sldi.h  w8, w17[0]");
    COMPARE(sldi_w(w20, w27, 2), "7832dd19       sldi.w  w20, w27[2]");
    COMPARE(sldi_d(w4, w12, 0), "78386119       sldi.d  w4, w12[0]");
    COMPARE(splati_b(w25, w3, 2), "78421e59       splati.b  w25, w3[2]");
    COMPARE(splati_h(w24, w28, 1), "7861e619       splati.h  w24, w28[1]");
    COMPARE(splati_w(w13, w18, 0), "78709359       splati.w  w13, w18[0]");
    COMPARE(splati_d(w28, w1, 0), "78780f19       splati.d  w28, w1[0]");
    COMPARE(move_v(w23, w24), "78bec5d9       move.v  w23, w24");
    COMPARE(insert_b(w23, 3, sp), "7903edd9       insert.b  w23[3], sp");
    COMPARE(insert_h(w20, 2, a1), "79222d19       insert.h  w20[2], a1");
    COMPARE(insert_w(w8, 2, s0), "79328219       insert.w  w8[2], s0");
    COMPARE(insert_d(w1, 1, sp), "7939e859       insert.d  w1[1], sp");
    COMPARE(insve_b(w25, 3, w9), "79434e59       insve.b  w25[3], w9[0]");
    COMPARE(insve_h(w24, 2, w2), "79621619       insve.h  w24[2], w2[0]");
    COMPARE(insve_w(w0, 2, w13), "79726819       insve.w  w0[2], w13[0]");
    COMPARE(insve_d(w3, 0, w18), "797890d9       insve.d  w3[0], w18[0]");
    COMPARE(cfcmsa(at, MSAIR), "787e0059       cfcmsa  at, MSAIR");
    COMPARE(cfcmsa(v0, MSACSR), "787e0899       cfcmsa  v0, MSACSR");
    COMPARE(ctcmsa(MSAIR, at), "783e0819       ctcmsa  MSAIR, at");
    COMPARE(ctcmsa(MSACSR, v0), "783e1059       ctcmsa  MSACSR, v0");
  }
  VERIFY_RUN();
}

TEST_F(DisasmMips64Test, MSA_BIT) {
  SET_UP();
  if ((kArchVariant == kMips64r6) && CpuFeatures::IsSupported(MIPS_SIMD)) {
    CpuFeatureScope fscope(&assm, MIPS_SIMD);

    COMPARE(bclri_b(w21, w30, 2), "79f2f549       bclri.b  w21, w30, 2");
    COMPARE(bclri_h(w24, w21, 0), "79e0ae09       bclri.h  w24, w21, 0");
    COMPARE(bclri_w(w23, w30, 3), "79c3f5c9       bclri.w  w23, w30, 3");
    COMPARE(bclri_d(w9, w11, 0), "79805a49       bclri.d  w9, w11, 0");
    COMPARE(binsli_b(w25, w12, 1), "7b716649       binsli.b  w25, w12, 1");
    COMPARE(binsli_h(w21, w22, 0), "7b60b549       binsli.h  w21, w22, 0");
    COMPARE(binsli_w(w22, w4, 0), "7b402589       binsli.w  w22, w4, 0");
    COMPARE(binsli_d(w6, w2, 6), "7b061189       binsli.d  w6, w2, 6");
    COMPARE(binsri_b(w15, w19, 0), "7bf09bc9       binsri.b  w15, w19, 0");
    COMPARE(binsri_h(w8, w30, 1), "7be1f209       binsri.h  w8, w30, 1");
    COMPARE(binsri_w(w2, w19, 5), "7bc59889       binsri.w  w2, w19, 5");
    COMPARE(binsri_d(w18, w20, 1), "7b81a489       binsri.d  w18, w20, 1");
    COMPARE(bnegi_b(w24, w19, 0), "7af09e09       bnegi.b  w24, w19, 0");
    COMPARE(bnegi_h(w28, w11, 3), "7ae35f09       bnegi.h  w28, w11, 3");
    COMPARE(bnegi_w(w1, w27, 5), "7ac5d849       bnegi.w  w1, w27, 5");
    COMPARE(bnegi_d(w4, w21, 1), "7a81a909       bnegi.d  w4, w21, 1");
    COMPARE(bseti_b(w18, w8, 0), "7a704489       bseti.b  w18, w8, 0");
    COMPARE(bseti_h(w24, w14, 2), "7a627609       bseti.h  w24, w14, 2");
    COMPARE(bseti_w(w9, w18, 4), "7a449249       bseti.w  w9, w18, 4");
    COMPARE(bseti_d(w7, w15, 1), "7a0179c9       bseti.d  w7, w15, 1");
    COMPARE(sat_s_b(w31, w31, 2), "7872ffca       sat_s.b  w31, w31, 2");
    COMPARE(sat_s_h(w19, w19, 0), "78609cca       sat_s.h  w19, w19, 0");
    COMPARE(sat_s_w(w19, w29, 0), "7840ecca       sat_s.w  w19, w29, 0");
    COMPARE(sat_s_d(w11, w22, 0), "7800b2ca       sat_s.d  w11, w22, 0");
    COMPARE(sat_u_b(w1, w13, 3), "78f3684a       sat_u.b  w1, w13, 3");
    COMPARE(sat_u_h(w30, w24, 4), "78e4c78a       sat_u.h  w30, w24, 4");
    COMPARE(sat_u_w(w31, w13, 0), "78c06fca       sat_u.w  w31, w13, 0");
    COMPARE(sat_u_d(w29, w16, 5), "7885874a       sat_u.d  w29, w16, 5");
    COMPARE(slli_b(w23, w10, 1), "787155c9       slli.b  w23, w10, 1");
    COMPARE(slli_h(w9, w18, 1), "78619249       slli.h  w9, w18, 1");
    COMPARE(slli_w(w11, w29, 4), "7844eac9       slli.w  w11, w29, 4");
    COMPARE(slli_d(w25, w20, 1), "7801a649       slli.d  w25, w20, 1");
    COMPARE(srai_b(w24, w29, 1), "78f1ee09       srai.b  w24, w29, 1");
    COMPARE(srai_h(w1, w6, 0), "78e03049       srai.h  w1, w6, 0");
    COMPARE(srai_w(w7, w26, 1), "78c1d1c9       srai.w  w7, w26, 1");
    COMPARE(srai_d(w20, w25, 3), "7883cd09       srai.d  w20, w25, 3");
    COMPARE(srari_b(w5, w25, 0), "7970c94a       srari.b  w5, w25, 0");
    COMPARE(srari_h(w7, w6, 4), "796431ca       srari.h  w7, w6, 4");
    COMPARE(srari_w(w17, w11, 5), "79455c4a       srari.w  w17, w11, 5");
    COMPARE(srari_d(w21, w25, 5), "7905cd4a       srari.d  w21, w25, 5");
    COMPARE(srli_b(w2, w0, 2), "79720089       srli.b  w2, w0, 2");
    COMPARE(srli_h(w31, w31, 2), "7962ffc9       srli.h  w31, w31, 2");
    COMPARE(srli_w(w5, w9, 4), "79444949       srli.w  w5, w9, 4");
    COMPARE(srli_d(w27, w26, 5), "7905d6c9       srli.d  w27, w26, 5");
    COMPARE(srlri_b(w18, w3, 0), "79f01c8a       srlri.b  w18, w3, 0");
    COMPARE(srlri_h(w1, w2, 3), "79e3104a       srlri.h  w1, w2, 3");
    COMPARE(srlri_w(w11, w22, 2), "79c2b2ca       srlri.w  w11, w22, 2");
    COMPARE(srlri_d(w24, w10, 6), "7986560a       srlri.d  w24, w10, 6");
  }
  VERIFY_RUN();
}

}  // namespace internal
}  // namespace v8

"""


```