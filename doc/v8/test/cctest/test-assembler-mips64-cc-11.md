Response:
Let's break down the thought process for answering the request about the `v8/test/cctest/test-assembler-mips64.cc` file based on the provided code snippet.

**1. Initial Analysis & Goal Identification:**

The core request is to understand the *functionality* of this C++ file. The file path itself gives a strong hint: it's a test file (`test`) within the V8 project (`v8`), specifically testing the assembler (`assembler`) for the MIPS64 architecture (`mips64`). The `.cc` extension confirms it's C++ source code.

**2. Examining the Code Snippet for Key Clues:**

The provided snippet is a large block of preprocessor macros and test case definitions. The most prominent feature is the large `TEST_CASE` macro with its extensive list of `V(...)` invocations.

* **`TEST_CASE(RUN_TEST)` and `TEST_CASE2(RUN_TEST2)`:** These clearly indicate that the file is setting up and running tests.

* **The `V(...)` macro:** This is the central point. It appears to be defining different test cases. Let's look at the structure of these `V` calls. A typical example is `V(sll_b, SLL_DF, uint8_t, kMSALanesByte, UINT8_MAX)`. Breaking this down:
    * `sll_b`:  Likely the name of the instruction being tested (shift left logical, byte).
    * `SLL_DF`:  Looks like a macro representing the instruction's encoding or some internal identifier within the assembler.
    * `uint8_t`: The data type being operated on.
    * `kMSALanesByte`:  Probably the number of lanes (parallel operations) for this data type in the MSA (MIPS SIMD Architecture) registers.
    * `UINT8_MAX`:  A maximum value, possibly used for testing boundary conditions.

* **The list of instructions:** The sheer number and naming of these instructions (e.g., `bclr_b`, `bset_h`, `addv_w`, `max_s_d`, `ceq_b`, `fadd_w`, `fsub_d`) strongly suggest that the file is testing the implementation of **MIPS MSA instructions** within the V8 assembler. The prefixes like 'b' for bitwise, 'addv' for vector addition with overflow, 'f' for floating-point confirm this.

* **`RUN_TEST` and `RUN_TEST2` macros:** These macros appear to encapsulate the logic for executing a single test case. They take the instruction, a `verify` function (likely to check the results), the data type, number of lanes, and a mask as arguments. They seem to use a `MacroAssembler` to generate machine code for the instruction and then run it.

* **`run_msa_3r` and `run_msa_3rf` functions:**  These seem to be helper functions for executing tests involving three register operands. The 'f' likely indicates floating-point versions. They handle setting up the assembler, loading data into registers, executing the instruction, and comparing the result against an expected value.

* **`TestCaseMsa3RF`, `ExpectedResult_MSA3RF`, `TestCaseMsa3RF_F`, etc.:** These structs define the input and expected output data structures for the test cases, further confirming the testing nature of the file.

* **Floating-point specific tests (`MSA_floating_point_quiet_compare`, `MSA_floating_point_arithmetic`, `MSA_fmin_fmin_a_fmax_fmax_a`):** These clearly indicate testing of floating-point MSA instructions.

**3. Formulating the Functionality Description:**

Based on the analysis, the core functionality is:

* **Testing the MIPS64 Assembler:** The file contains tests specifically for the MIPS64 architecture's assembler within the V8 JavaScript engine.
* **Focus on MSA Instructions:** The tests heavily emphasize the MIPS SIMD Architecture (MSA) instructions, covering a wide range of operations (arithmetic, bitwise, comparisons, floating-point).
* **Unit Testing:**  The structure suggests unit tests, where individual instructions or small sequences are tested in isolation.
* **Verification:** The `verify` functions within the `RUN_TEST` macros are used to validate the correctness of the generated code and the instruction's behavior.

**4. Addressing the Specific Questions:**

* **`.tq` extension:** The file ends in `.cc`, so it's a C++ file, not a Torque file.
* **Relationship to JavaScript:** The connection is indirect. The assembler is used by the V8 JavaScript engine to generate native machine code from JavaScript. The tested instructions are the building blocks for optimizing JavaScript execution on MIPS64. An example would be vectorizing array operations in JavaScript.
* **JavaScript Example:** Illustrate how MSA instructions could be used to optimize a common JavaScript task like adding two arrays.
* **Code Logic Reasoning:** Choose a simple instruction (like `addv_b`) and provide a concrete example with input and expected output, demonstrating overflow behavior.
* **Common Programming Errors:**  Consider errors related to data types, overflow, and incorrect usage of SIMD instructions.
* **归纳总结 (Summarization):** Combine the key functionalities identified earlier into a concise summary, emphasizing its role in testing the MIPS64 assembler and its MSA instruction support within V8. Mention the test-driven development aspect.

**5. Structuring the Answer:**

Organize the information logically, addressing each point in the request clearly and concisely. Use headings and bullet points for better readability. Provide clear explanations for technical terms like "assembler" and "MSA."

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe the file tests a wider range of MIPS64 instructions.
* **Correction:**  The strong focus on the `V(...)` macro and the names of the instructions heavily leans towards MSA instruction testing specifically.
* **Initial thought:** The JavaScript connection might be very direct through inline assembly.
* **Correction:** While V8 has mechanisms for embedding assembly, this file is primarily testing the assembler *itself*, which is a lower-level component. The connection to JavaScript is through the code the assembler generates *later*.

By following this systematic approach, analyzing the code snippets for key patterns and information, and addressing each aspect of the request, a comprehensive and accurate answer can be generated.
```cpp
 uint64_t, kMSALanesDword, UINT64_MAX)          \
  V(bclr_b, BCRL_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(bclr_h, BCRL_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(bclr_w, BCRL_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(bclr_d, BCRL_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(bset_b, BSET_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(bset_h, BSET_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(bset_w, BSET_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(bset_d, BSET_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(bneg_b, BNEG_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(bneg_h, BNEG_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(bneg_w, BNEG_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(bneg_d, BNEG_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(binsl_b, BINSL_DF, uint8_t, kMSALanesByte, UINT8_MAX)         \
  V(binsl_h, BINSL_DF, uint16_t, kMSALanesHalf, UINT16_MAX)       \
  V(binsl_w, BINSL_DF, uint32_t, kMSALanesWord, UINT32_MAX)       \
  V(binsl_d, BINSL_DF, uint64_t, kMSALanesDword, UINT64_MAX)      \
  V(binsr_b, BINSR_DF, uint8_t, kMSALanesByte, UINT8_MAX)         \
  V(binsr_h, BINSR_DF, uint16_t, kMSALanesHalf, UINT16_MAX)       \
  V(binsr_w, BINSR_DF, uint32_t, kMSALanesWord, UINT32_MAX)       \
  V(binsr_d, BINSR_DF, uint64_t, kMSALanesDword, UINT64_MAX)      \
  V(addv_b, ADDV_DF, int8_t, kMSALanesByte, UINT8_MAX)            \
  V(addv_h, ADDV_DF, int16_t, kMSALanesHalf, UINT16_MAX)          \
  V(addv_w, ADDV_DF, int32_t, kMSALanesWord, UINT32_MAX)          \
  V(addv_d, ADDV_DF, int64_t, kMSALanesDword, UINT64_MAX)         \
  V(subv_b, SUBV_DF, int8_t, kMSALanesByte, UINT8_MAX)            \
  V(subv_h, SUBV_DF, int16_t, kMSALanesHalf, UINT16_MAX)          \
  V(subv_w, SUBV_DF, int32_t, kMSALanesWord, UINT32_MAX)          \
  V(subv_d, SUBV_DF, int64_t, kMSALanesDword, UINT64_MAX)         \
  V(max_s_b, MAX_DF, int8_t, kMSALanesByte, UINT8_MAX)            \
  V(max_s_h, MAX_DF, int16_t, kMSALanesHalf, UINT16_MAX)          \
  V(max_s_w, MAX_DF, int32_t, kMSALanesWord, UINT32_MAX)          \
  V(max_s_d, MAX_DF, int64_t, kMSALanesDword, UINT64_MAX)         \
  V(max_u_b, MAX_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(max_u_h, MAX_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(max_u_w, MAX_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(max_u_d, MAX_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(min_s_b, MIN_DF, int8_t, kMSALanesByte, UINT8_MAX)            \
  V(min_s_h, MIN_DF, int16_t, kMSALanesHalf, UINT16_MAX)          \
  V(min_s_w, MIN_DF, int32_t, kMSALanesWord, UINT32_MAX)          \
  V(min_s_d, MIN_DF, int64_t, kMSALanesDword, UINT64_MAX)         \
  V(min_u_b, MIN_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(min_u_h, MIN_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(min_u_w, MIN_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(min_u_d, MIN_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(max_a_b, MAXA_DF, int8_t, kMSALanesByte, UINT8_MAX)           \
  V(max_a_h, MAXA_DF, int16_t, kMSALanesHalf, UINT16_MAX)         \
  V(max_a_w, MAXA_DF, int32_t, kMSALanesWord, UINT32_MAX)         \
  V(max_a_d, MAXA_DF, int64_t, kMSALanesDword, UINT64_MAX)        \
  V(min_a_b, MINA_DF, int8_t, kMSALanesByte, UINT8_MAX)           \
  V(min_a_h, MINA_DF, int16_t, kMSALanesHalf, UINT16_MAX)         \
  V(min_a_w, MINA_DF, int32_t, kMSALanesWord, UINT32_MAX)         \
  V(min_a_d, MINA_DF, int64_t, kMSALanesDword, UINT64_MAX)        \
  V(ceq_b, CEQ_DF, uint8_t, kMSALanesByte, UINT8_MAX)             \
  V(ceq_h, CEQ_DF, uint16_t, kMSALanesHalf, UINT16_MAX)           \
  V(ceq_w, CEQ_DF, uint32_t, kMSALanesWord, UINT32_MAX)           \
  V(ceq_d, CEQ_DF, uint64_t, kMSALanesDword, UINT64_MAX)          \
  V(clt_s_b, CLT_DF, int8_t, kMSALanesByte, UINT8_MAX)            \
  V(clt_s_h, CLT_DF, int16_t, kMSALanesHalf, UINT16_MAX)          \
  V(clt_s_w, CLT_DF, int32_t, kMSALanesWord, UINT32_MAX)          \
  V(clt_s_d, CLT_DF, int64_t, kMSALanesDword, UINT64_MAX)         \
  V(clt_u_b, CLT_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(clt_u_h, CLT_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(clt_u_w, CLT_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(clt_u_d, CLT_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(cle_s_b, CLE_DF, int8_t, kMSALanesByte, UINT8_MAX)            \
  V(cle_s_h, CLE_DF, int16_t, kMSALanesHalf, UINT16_MAX)          \
  V(cle_s_w, CLE_DF, int32_t, kMSALanesWord, UINT32_MAX)          \
  V(cle_s_d, CLE_DF, int64_t, kMSALanesDword, UINT64_MAX)         \
  V(cle_u_b, CLE_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(cle_u_h, CLE_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(cle_u_w, CLE_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(cle_u_d, CLE_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(add_a_b, ADD_A_DF, int8_t, kMSALanesByte, UINT8_MAX)          \
  V(add_a_h, ADD_A_DF, int16_t, kMSALanesHalf, UINT16_MAX)        \
  V(add_a_w, ADD_A_DF, int32_t, kMSALanesWord, UINT32_MAX)        \
  V(add_a_d, ADD_A_DF, int64_t, kMSALanesDword, UINT64_MAX)       \
  V(adds_a_b, ADDS_A_DF, int8_t, kMSALanesByte, UINT8_MAX)        \
  V(adds_a_h, ADDS_A_DF, int16_t, kMSALanesHalf, UINT16_MAX)      \
  V(adds_a_w, ADDS_A_DF, int32_t, kMSALanesWord, UINT32_MAX)      \
  V(adds_a_d, ADDS_A_DF, int64_t, kMSALanesDword, UINT64_MAX)     \
  V(adds_s_b, ADDS_DF, int8_t, kMSALanesByte, UINT8_MAX)          \
  V(adds_s_h, ADDS_DF, int16_t, kMSALanesHalf, UINT16_MAX)        \
  V(adds_s_w, ADDS_DF, int32_t, kMSALanesWord, UINT32_MAX)        \
  V(adds_s_d, ADDS_DF, int64_t, kMSALanesDword, UINT64_MAX)       \
  V(adds_u_b, ADDS_DF, uint8_t, kMSALanesByte, UINT8_MAX)         \
  V(adds_u_h, ADDS_DF, uint16_t, kMSALanesHalf, UINT16_MAX)       \
  V(adds_u_w, ADDS_DF, uint32_t, kMSALanesWord, UINT32_MAX)       \
  V(adds_u_d, ADDS_DF, uint64_t, kMSALanesDword, UINT64_MAX)      \
  V(ave_s_b, AVE_DF, int8_t, kMSALanesByte, UINT8_MAX)            \
  V(ave_s_h, AVE_DF, int16_t, kMSALanesHalf, UINT16_MAX)          \
  V(ave_s_w, AVE_DF, int32_t, kMSALanesWord, UINT32_MAX)          \
  V(ave_s_d, AVE_DF, int64_t, kMSALanesDword, UINT64_MAX)         \
  V(ave_u_b, AVE_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(ave_u_h, AVE_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(ave_u_w, AVE_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(ave_u_d, AVE_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(aver_s_b, AVER_DF, int8_t, kMSALanesByte, UINT8_MAX)          \
  V(aver_s_h, AVER_DF, int16_t, kMSALanesHalf, UINT16_MAX)        \
  V(aver_s_w, AVER_DF, int32_t, kMSALanesWord, UINT32_MAX)        \
  V(aver_s_d, AVER_DF, int64_t, kMSALanesDword, UINT64_MAX)       \
  V(aver_u_b, AVER_DF, uint8_t, kMSALanesByte, UINT8_MAX)         \
  V(aver_u_h, AVER_DF, uint16_t, kMSALanesHalf, UINT16_MAX)       \
  V(aver_u_w, AVER_DF, uint32_t, kMSALanesWord, UINT32_MAX)       \
  V(aver_u_d, AVER_DF, uint64_t, kMSALanesDword, UINT64_MAX)      \
  V(subs_s_b, SUBS_DF, int8_t, kMSALanesByte, UINT8_MAX)          \
  V(subs_s_h, SUBS_DF, int16_t, kMSALanesHalf, UINT16_MAX)        \
  V(subs_s_w, SUBS_DF, int32_t, kMSALanesWord, UINT32_MAX)        \
  V(subs_s_d, SUBS_DF, int64_t, kMSALanesDword, UINT64_MAX)       \
  V(subs_u_b, SUBS_DF, uint8_t, kMSALanesByte, UINT8_MAX)         \
  V(subs_u_h, SUBS_DF, uint16_t, kMSALanesHalf, UINT16_MAX)       \
  V(subs_u_w, SUBS_DF, uint32_t, kMSALanesWord, UINT32_MAX)       \
  V(subs_u_d, SUBS_DF, uint64_t, kMSALanesDword, UINT64_MAX)      \
  V(subsus_u_b, SUBSUS_U_DF, int8_t, kMSALanesByte, UINT8_MAX)    \
  V(subsus_u_h, SUBSUS_U_DF, int16_t, kMSALanesHalf, UINT16_MAX)  \
  V(subsus_u_w, SUBSUS_U_DF, int32_t, kMSALanesWord, UINT32_MAX)  \
  V(subsus_u_d, SUBSUS_U_DF, int64_t, kMSALanesDword, UINT64_MAX) \
  V(subsuu_s_b, SUBSUU_S_DF, int8_t, kMSALanesByte, UINT8_MAX)    \
  V(subsuu_s_h, SUBSUU_S_DF, int16_t, kMSALanesHalf, UINT16_MAX)  \
  V(subsuu_s_w, SUBSUU_S_DF, int32_t, kMSALanesWord, UINT32_MAX)  \
  V(subsuu_s_d, SUBSUU_S_DF, int64_t, kMSALanesDword, UINT64_MAX) \
  V(asub_s_b, ASUB_S_DF, int8_t, kMSALanesByte, UINT8_MAX)        \
  V(asub_s_h, ASUB_S_DF, int16_t, kMSALanesHalf, UINT16_MAX)      \
  V(asub_s_w, ASUB_S_DF, int32_t, kMSALanesWord, UINT32_MAX)      \
  V(asub_s_d, ASUB_S_DF, int64_t, kMSALanesDword, UINT64_MAX)     \
  V(asub_u_b, ASUB_U_DF, uint8_t, kMSALanesByte, UINT8_MAX)       \
  V(asub_u_h, ASUB_U_DF, uint16_t, kMSALanesHalf, UINT16_MAX)     \
  V(asub_u_w, ASUB_U_DF, uint32_t, kMSALanesWord, UINT32_MAX)     \
  V(asub_u_d, ASUB_U_DF, uint64_t, kMSALanesDword, UINT64_MAX)    \
  V(mulv_b, MULV_DF, int8_t, kMSALanesByte, UINT8_MAX)            \
  V(mulv_h, MULV_DF, int16_t, kMSALanesHalf, UINT16_MAX)          \
  V(mulv_w, MULV_DF, int32_t, kMSALanesWord, UINT32_MAX)          \
  V(mulv_d, MULV_DF, int64_t, kMSALanesDword, UINT64_MAX)         \
  V(maddv_b, MADDV_DF, int8_t, kMSALanesByte, UINT8_MAX)          \
  V(maddv_h, MADDV_DF, int16_t, kMSALanesHalf, UINT16_MAX)        \
  V(maddv_w, MADDV_DF, int32_t, kMSALanesWord, UINT32_MAX)        \
  V(maddv_d, MADDV_DF, int64_t, kMSALanesDword, UINT64_MAX)       \
  V(msubv_b, MSUBV_DF, int8_t, kMSALanesByte, UINT8_MAX)          \
  V(msubv_h, MSUBV_DF, int16_t, kMSALanesHalf, UINT16_MAX)        \
  V(msubv_w, MSUBV_DF, int32_t, kMSALanesWord, UINT32_MAX)        \
  V(msubv_d, MSUBV_DF, int64_t, kMSALanesDword, UINT64_MAX)       \
  V(div_s_b, DIV_DF, int8_t, kMSALanesByte, UINT8_MAX)            \
  V(div_s_h, DIV_DF, int16_t, kMSALanesHalf, UINT16_MAX)          \
  V(div_s_w, DIV_DF, int32_t, kMSALanesWord, UINT32_MAX)          \
  V(div_s_d, DIV_DF, int64_t, kMSALanesDword, UINT64_MAX)         \
  V(div_u_b, DIV_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(div_u_h, DIV_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(div_u_w, DIV_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(div_u_d, DIV_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(mod_s_b, MOD_DF, int8_t, kMSALanesByte, UINT8_MAX)            \
  V(mod_s_h, MOD_DF, int16_t, kMSALanesHalf, UINT16_MAX)          \
  V(mod_s_w, MOD_DF, int32_t, kMSALanesWord, UINT32_MAX)          \
  V(mod_s_d, MOD_DF, int64_t, kMSALanesDword, UINT64_MAX)         \
  V(mod_u_b, MOD_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(mod_u_h, MOD_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(mod_u_w, MOD_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(mod_u_d, MOD_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(srlr_b, SRAR_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(srlr_h, SRAR_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(srlr_w, SRAR_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(srlr_d, SRAR_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(pckev_b, PCKEV_DF, uint8_t, kMSALanesByte, UINT8_MAX)         \
  V(pckev_h, PCKEV_DF, uint16_t, kMSALanesHalf, UINT16_MAX)       \
  V(pckev_w, PCKEV_DF, uint32_t, kMSALanesWord, UINT32_MAX)       \
  V(pckev_d, PCKEV_DF, uint64_t, kMSALanesDword, UINT64_MAX)      \
  V(pckod_b, PCKOD_DF, uint8_t, kMSALanesByte, UINT8_MAX)         \
  V(pckod_h, PCKOD_DF, uint16_t, kMSALanesHalf, UINT16_MAX)       \
  V(pckod_w, PCKOD_DF, uint32_t, kMSALanesWord, UINT32_MAX)       \
  V(pckod_d, PCKOD_DF, uint64_t, kMSALanesDword, UINT64_MAX)      \
  V(ilvl_b, ILVL_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(ilvl_h, ILVL_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(ilvl_w, ILVL_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(ilvl_d, ILVL_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(ilvr_b, ILVR_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(ilvr_h, ILVR_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(ilvr_w, ILVR_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(ilvr_d, ILVR_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(ilvev_b, ILVEV_DF, uint8_t, kMSALanesByte, UINT8_MAX)         \
  V(ilvev_h, ILVEV_DF, uint16_t, kMSALanesHalf, UINT16_MAX)       \
  V(ilvev_w, ILVEV_DF, uint32_t, kMSALanesWord, UINT32_MAX)       \
  V(ilvev_d, ILVEV_DF, uint64_t, kMSALanesDword, UINT64_MAX)      \
  V(ilvod_b, ILVOD_DF, uint8_t, kMSALanesByte, UINT8_MAX)         \
  V(ilvod_h, ILVOD_DF, uint16_t, kMSALanesHalf, UINT16_MAX)       \
  V(ilvod_w, ILVOD_DF, uint32_t, kMSALanesWord, UINT32_MAX)       \
  V(ilvod_d, ILVOD_DF, uint64_t, kMSALanesDword, UINT64_MAX)      \
  V(vshf_b, VSHF_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(vshf_h, VSHF_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(vshf_w, VSHF_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(vshf_d, VSHF_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(hadd_s_h, HADD_DF, int16_t, int8_t, kMSALanesHalf)            \
  V(hadd_s_w, HADD_DF, int32_t, int16_t, kMSALanesWord)           \
  V(hadd_s_d, HADD_DF, int64_t, int32_t, kMSALanesDword)          \
  V(hadd_u_h, HADD_DF, uint16_t, uint8_t, kMSALanesHalf)          \
  V(hadd_u_w, HADD_DF, uint32_t, uint16_t, kMSALanesWord)         \
  V(hadd_u_d, HADD_DF, uint64_t, uint32_t, kMSALanesDword)        \
  V(hsub_s_h, HSUB_DF, int16
### 提示词
```
这是目录为v8/test/cctest/test-assembler-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第12部分，共13部分，请归纳一下它的功能
```

### 源代码
```cpp
uint64_t, kMSALanesDword, UINT64_MAX)          \
  V(bclr_b, BCRL_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(bclr_h, BCRL_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(bclr_w, BCRL_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(bclr_d, BCRL_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(bset_b, BSET_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(bset_h, BSET_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(bset_w, BSET_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(bset_d, BSET_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(bneg_b, BNEG_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(bneg_h, BNEG_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(bneg_w, BNEG_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(bneg_d, BNEG_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(binsl_b, BINSL_DF, uint8_t, kMSALanesByte, UINT8_MAX)         \
  V(binsl_h, BINSL_DF, uint16_t, kMSALanesHalf, UINT16_MAX)       \
  V(binsl_w, BINSL_DF, uint32_t, kMSALanesWord, UINT32_MAX)       \
  V(binsl_d, BINSL_DF, uint64_t, kMSALanesDword, UINT64_MAX)      \
  V(binsr_b, BINSR_DF, uint8_t, kMSALanesByte, UINT8_MAX)         \
  V(binsr_h, BINSR_DF, uint16_t, kMSALanesHalf, UINT16_MAX)       \
  V(binsr_w, BINSR_DF, uint32_t, kMSALanesWord, UINT32_MAX)       \
  V(binsr_d, BINSR_DF, uint64_t, kMSALanesDword, UINT64_MAX)      \
  V(addv_b, ADDV_DF, int8_t, kMSALanesByte, UINT8_MAX)            \
  V(addv_h, ADDV_DF, int16_t, kMSALanesHalf, UINT16_MAX)          \
  V(addv_w, ADDV_DF, int32_t, kMSALanesWord, UINT32_MAX)          \
  V(addv_d, ADDV_DF, int64_t, kMSALanesDword, UINT64_MAX)         \
  V(subv_b, SUBV_DF, int8_t, kMSALanesByte, UINT8_MAX)            \
  V(subv_h, SUBV_DF, int16_t, kMSALanesHalf, UINT16_MAX)          \
  V(subv_w, SUBV_DF, int32_t, kMSALanesWord, UINT32_MAX)          \
  V(subv_d, SUBV_DF, int64_t, kMSALanesDword, UINT64_MAX)         \
  V(max_s_b, MAX_DF, int8_t, kMSALanesByte, UINT8_MAX)            \
  V(max_s_h, MAX_DF, int16_t, kMSALanesHalf, UINT16_MAX)          \
  V(max_s_w, MAX_DF, int32_t, kMSALanesWord, UINT32_MAX)          \
  V(max_s_d, MAX_DF, int64_t, kMSALanesDword, UINT64_MAX)         \
  V(max_u_b, MAX_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(max_u_h, MAX_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(max_u_w, MAX_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(max_u_d, MAX_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(min_s_b, MIN_DF, int8_t, kMSALanesByte, UINT8_MAX)            \
  V(min_s_h, MIN_DF, int16_t, kMSALanesHalf, UINT16_MAX)          \
  V(min_s_w, MIN_DF, int32_t, kMSALanesWord, UINT32_MAX)          \
  V(min_s_d, MIN_DF, int64_t, kMSALanesDword, UINT64_MAX)         \
  V(min_u_b, MIN_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(min_u_h, MIN_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(min_u_w, MIN_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(min_u_d, MIN_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(max_a_b, MAXA_DF, int8_t, kMSALanesByte, UINT8_MAX)           \
  V(max_a_h, MAXA_DF, int16_t, kMSALanesHalf, UINT16_MAX)         \
  V(max_a_w, MAXA_DF, int32_t, kMSALanesWord, UINT32_MAX)         \
  V(max_a_d, MAXA_DF, int64_t, kMSALanesDword, UINT64_MAX)        \
  V(min_a_b, MINA_DF, int8_t, kMSALanesByte, UINT8_MAX)           \
  V(min_a_h, MINA_DF, int16_t, kMSALanesHalf, UINT16_MAX)         \
  V(min_a_w, MINA_DF, int32_t, kMSALanesWord, UINT32_MAX)         \
  V(min_a_d, MINA_DF, int64_t, kMSALanesDword, UINT64_MAX)        \
  V(ceq_b, CEQ_DF, uint8_t, kMSALanesByte, UINT8_MAX)             \
  V(ceq_h, CEQ_DF, uint16_t, kMSALanesHalf, UINT16_MAX)           \
  V(ceq_w, CEQ_DF, uint32_t, kMSALanesWord, UINT32_MAX)           \
  V(ceq_d, CEQ_DF, uint64_t, kMSALanesDword, UINT64_MAX)          \
  V(clt_s_b, CLT_DF, int8_t, kMSALanesByte, UINT8_MAX)            \
  V(clt_s_h, CLT_DF, int16_t, kMSALanesHalf, UINT16_MAX)          \
  V(clt_s_w, CLT_DF, int32_t, kMSALanesWord, UINT32_MAX)          \
  V(clt_s_d, CLT_DF, int64_t, kMSALanesDword, UINT64_MAX)         \
  V(clt_u_b, CLT_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(clt_u_h, CLT_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(clt_u_w, CLT_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(clt_u_d, CLT_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(cle_s_b, CLE_DF, int8_t, kMSALanesByte, UINT8_MAX)            \
  V(cle_s_h, CLE_DF, int16_t, kMSALanesHalf, UINT16_MAX)          \
  V(cle_s_w, CLE_DF, int32_t, kMSALanesWord, UINT32_MAX)          \
  V(cle_s_d, CLE_DF, int64_t, kMSALanesDword, UINT64_MAX)         \
  V(cle_u_b, CLE_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(cle_u_h, CLE_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(cle_u_w, CLE_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(cle_u_d, CLE_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(add_a_b, ADD_A_DF, int8_t, kMSALanesByte, UINT8_MAX)          \
  V(add_a_h, ADD_A_DF, int16_t, kMSALanesHalf, UINT16_MAX)        \
  V(add_a_w, ADD_A_DF, int32_t, kMSALanesWord, UINT32_MAX)        \
  V(add_a_d, ADD_A_DF, int64_t, kMSALanesDword, UINT64_MAX)       \
  V(adds_a_b, ADDS_A_DF, int8_t, kMSALanesByte, UINT8_MAX)        \
  V(adds_a_h, ADDS_A_DF, int16_t, kMSALanesHalf, UINT16_MAX)      \
  V(adds_a_w, ADDS_A_DF, int32_t, kMSALanesWord, UINT32_MAX)      \
  V(adds_a_d, ADDS_A_DF, int64_t, kMSALanesDword, UINT64_MAX)     \
  V(adds_s_b, ADDS_DF, int8_t, kMSALanesByte, UINT8_MAX)          \
  V(adds_s_h, ADDS_DF, int16_t, kMSALanesHalf, UINT16_MAX)        \
  V(adds_s_w, ADDS_DF, int32_t, kMSALanesWord, UINT32_MAX)        \
  V(adds_s_d, ADDS_DF, int64_t, kMSALanesDword, UINT64_MAX)       \
  V(adds_u_b, ADDS_DF, uint8_t, kMSALanesByte, UINT8_MAX)         \
  V(adds_u_h, ADDS_DF, uint16_t, kMSALanesHalf, UINT16_MAX)       \
  V(adds_u_w, ADDS_DF, uint32_t, kMSALanesWord, UINT32_MAX)       \
  V(adds_u_d, ADDS_DF, uint64_t, kMSALanesDword, UINT64_MAX)      \
  V(ave_s_b, AVE_DF, int8_t, kMSALanesByte, UINT8_MAX)            \
  V(ave_s_h, AVE_DF, int16_t, kMSALanesHalf, UINT16_MAX)          \
  V(ave_s_w, AVE_DF, int32_t, kMSALanesWord, UINT32_MAX)          \
  V(ave_s_d, AVE_DF, int64_t, kMSALanesDword, UINT64_MAX)         \
  V(ave_u_b, AVE_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(ave_u_h, AVE_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(ave_u_w, AVE_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(ave_u_d, AVE_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(aver_s_b, AVER_DF, int8_t, kMSALanesByte, UINT8_MAX)          \
  V(aver_s_h, AVER_DF, int16_t, kMSALanesHalf, UINT16_MAX)        \
  V(aver_s_w, AVER_DF, int32_t, kMSALanesWord, UINT32_MAX)        \
  V(aver_s_d, AVER_DF, int64_t, kMSALanesDword, UINT64_MAX)       \
  V(aver_u_b, AVER_DF, uint8_t, kMSALanesByte, UINT8_MAX)         \
  V(aver_u_h, AVER_DF, uint16_t, kMSALanesHalf, UINT16_MAX)       \
  V(aver_u_w, AVER_DF, uint32_t, kMSALanesWord, UINT32_MAX)       \
  V(aver_u_d, AVER_DF, uint64_t, kMSALanesDword, UINT64_MAX)      \
  V(subs_s_b, SUBS_DF, int8_t, kMSALanesByte, UINT8_MAX)          \
  V(subs_s_h, SUBS_DF, int16_t, kMSALanesHalf, UINT16_MAX)        \
  V(subs_s_w, SUBS_DF, int32_t, kMSALanesWord, UINT32_MAX)        \
  V(subs_s_d, SUBS_DF, int64_t, kMSALanesDword, UINT64_MAX)       \
  V(subs_u_b, SUBS_DF, uint8_t, kMSALanesByte, UINT8_MAX)         \
  V(subs_u_h, SUBS_DF, uint16_t, kMSALanesHalf, UINT16_MAX)       \
  V(subs_u_w, SUBS_DF, uint32_t, kMSALanesWord, UINT32_MAX)       \
  V(subs_u_d, SUBS_DF, uint64_t, kMSALanesDword, UINT64_MAX)      \
  V(subsus_u_b, SUBSUS_U_DF, int8_t, kMSALanesByte, UINT8_MAX)    \
  V(subsus_u_h, SUBSUS_U_DF, int16_t, kMSALanesHalf, UINT16_MAX)  \
  V(subsus_u_w, SUBSUS_U_DF, int32_t, kMSALanesWord, UINT32_MAX)  \
  V(subsus_u_d, SUBSUS_U_DF, int64_t, kMSALanesDword, UINT64_MAX) \
  V(subsuu_s_b, SUBSUU_S_DF, int8_t, kMSALanesByte, UINT8_MAX)    \
  V(subsuu_s_h, SUBSUU_S_DF, int16_t, kMSALanesHalf, UINT16_MAX)  \
  V(subsuu_s_w, SUBSUU_S_DF, int32_t, kMSALanesWord, UINT32_MAX)  \
  V(subsuu_s_d, SUBSUU_S_DF, int64_t, kMSALanesDword, UINT64_MAX) \
  V(asub_s_b, ASUB_S_DF, int8_t, kMSALanesByte, UINT8_MAX)        \
  V(asub_s_h, ASUB_S_DF, int16_t, kMSALanesHalf, UINT16_MAX)      \
  V(asub_s_w, ASUB_S_DF, int32_t, kMSALanesWord, UINT32_MAX)      \
  V(asub_s_d, ASUB_S_DF, int64_t, kMSALanesDword, UINT64_MAX)     \
  V(asub_u_b, ASUB_U_DF, uint8_t, kMSALanesByte, UINT8_MAX)       \
  V(asub_u_h, ASUB_U_DF, uint16_t, kMSALanesHalf, UINT16_MAX)     \
  V(asub_u_w, ASUB_U_DF, uint32_t, kMSALanesWord, UINT32_MAX)     \
  V(asub_u_d, ASUB_U_DF, uint64_t, kMSALanesDword, UINT64_MAX)    \
  V(mulv_b, MULV_DF, int8_t, kMSALanesByte, UINT8_MAX)            \
  V(mulv_h, MULV_DF, int16_t, kMSALanesHalf, UINT16_MAX)          \
  V(mulv_w, MULV_DF, int32_t, kMSALanesWord, UINT32_MAX)          \
  V(mulv_d, MULV_DF, int64_t, kMSALanesDword, UINT64_MAX)         \
  V(maddv_b, MADDV_DF, int8_t, kMSALanesByte, UINT8_MAX)          \
  V(maddv_h, MADDV_DF, int16_t, kMSALanesHalf, UINT16_MAX)        \
  V(maddv_w, MADDV_DF, int32_t, kMSALanesWord, UINT32_MAX)        \
  V(maddv_d, MADDV_DF, int64_t, kMSALanesDword, UINT64_MAX)       \
  V(msubv_b, MSUBV_DF, int8_t, kMSALanesByte, UINT8_MAX)          \
  V(msubv_h, MSUBV_DF, int16_t, kMSALanesHalf, UINT16_MAX)        \
  V(msubv_w, MSUBV_DF, int32_t, kMSALanesWord, UINT32_MAX)        \
  V(msubv_d, MSUBV_DF, int64_t, kMSALanesDword, UINT64_MAX)       \
  V(div_s_b, DIV_DF, int8_t, kMSALanesByte, UINT8_MAX)            \
  V(div_s_h, DIV_DF, int16_t, kMSALanesHalf, UINT16_MAX)          \
  V(div_s_w, DIV_DF, int32_t, kMSALanesWord, UINT32_MAX)          \
  V(div_s_d, DIV_DF, int64_t, kMSALanesDword, UINT64_MAX)         \
  V(div_u_b, DIV_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(div_u_h, DIV_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(div_u_w, DIV_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(div_u_d, DIV_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(mod_s_b, MOD_DF, int8_t, kMSALanesByte, UINT8_MAX)            \
  V(mod_s_h, MOD_DF, int16_t, kMSALanesHalf, UINT16_MAX)          \
  V(mod_s_w, MOD_DF, int32_t, kMSALanesWord, UINT32_MAX)          \
  V(mod_s_d, MOD_DF, int64_t, kMSALanesDword, UINT64_MAX)         \
  V(mod_u_b, MOD_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(mod_u_h, MOD_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(mod_u_w, MOD_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(mod_u_d, MOD_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(srlr_b, SRAR_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(srlr_h, SRAR_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(srlr_w, SRAR_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(srlr_d, SRAR_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(pckev_b, PCKEV_DF, uint8_t, kMSALanesByte, UINT8_MAX)         \
  V(pckev_h, PCKEV_DF, uint16_t, kMSALanesHalf, UINT16_MAX)       \
  V(pckev_w, PCKEV_DF, uint32_t, kMSALanesWord, UINT32_MAX)       \
  V(pckev_d, PCKEV_DF, uint64_t, kMSALanesDword, UINT64_MAX)      \
  V(pckod_b, PCKOD_DF, uint8_t, kMSALanesByte, UINT8_MAX)         \
  V(pckod_h, PCKOD_DF, uint16_t, kMSALanesHalf, UINT16_MAX)       \
  V(pckod_w, PCKOD_DF, uint32_t, kMSALanesWord, UINT32_MAX)       \
  V(pckod_d, PCKOD_DF, uint64_t, kMSALanesDword, UINT64_MAX)      \
  V(ilvl_b, ILVL_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(ilvl_h, ILVL_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(ilvl_w, ILVL_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(ilvl_d, ILVL_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(ilvr_b, ILVR_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(ilvr_h, ILVR_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(ilvr_w, ILVR_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(ilvr_d, ILVR_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(ilvev_b, ILVEV_DF, uint8_t, kMSALanesByte, UINT8_MAX)         \
  V(ilvev_h, ILVEV_DF, uint16_t, kMSALanesHalf, UINT16_MAX)       \
  V(ilvev_w, ILVEV_DF, uint32_t, kMSALanesWord, UINT32_MAX)       \
  V(ilvev_d, ILVEV_DF, uint64_t, kMSALanesDword, UINT64_MAX)      \
  V(ilvod_b, ILVOD_DF, uint8_t, kMSALanesByte, UINT8_MAX)         \
  V(ilvod_h, ILVOD_DF, uint16_t, kMSALanesHalf, UINT16_MAX)       \
  V(ilvod_w, ILVOD_DF, uint32_t, kMSALanesWord, UINT32_MAX)       \
  V(ilvod_d, ILVOD_DF, uint64_t, kMSALanesDword, UINT64_MAX)      \
  V(vshf_b, VSHF_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(vshf_h, VSHF_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(vshf_w, VSHF_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(vshf_d, VSHF_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(hadd_s_h, HADD_DF, int16_t, int8_t, kMSALanesHalf)            \
  V(hadd_s_w, HADD_DF, int32_t, int16_t, kMSALanesWord)           \
  V(hadd_s_d, HADD_DF, int64_t, int32_t, kMSALanesDword)          \
  V(hadd_u_h, HADD_DF, uint16_t, uint8_t, kMSALanesHalf)          \
  V(hadd_u_w, HADD_DF, uint32_t, uint16_t, kMSALanesWord)         \
  V(hadd_u_d, HADD_DF, uint64_t, uint32_t, kMSALanesDword)        \
  V(hsub_s_h, HSUB_DF, int16_t, int8_t, kMSALanesHalf)            \
  V(hsub_s_w, HSUB_DF, int32_t, int16_t, kMSALanesWord)           \
  V(hsub_s_d, HSUB_DF, int64_t, int32_t, kMSALanesDword)          \
  V(hsub_u_h, HSUB_DF, uint16_t, uint8_t, kMSALanesHalf)          \
  V(hsub_u_w, HSUB_DF, uint32_t, uint16_t, kMSALanesWord)         \
  V(hsub_u_d, HSUB_DF, uint64_t, uint32_t, kMSALanesDword)

#define RUN_TEST(instr, verify, type, lanes, mask)                       \
  run_msa_3r(&tc[i], [](MacroAssembler& assm) { __ instr(w2, w1, w0); }, \
             [](uint64_t* ws, uint64_t* wt, uint64_t* wd) {              \
               verify(type, lanes, mask);                                \
             });

  for (size_t i = 0; i < arraysize(tc); ++i) {
    TEST_CASE(RUN_TEST)
  }

#define RUN_TEST2(instr, verify, type, lanes, mask)                      \
  for (unsigned i = 0; i < arraysize(tc); i++) {                         \
    for (unsigned j = 0; j < 3; j++) {                                   \
      for (unsigned k = 0; k < lanes; k++) {                             \
        type* element = reinterpret_cast<type*>(&tc[i]);                 \
        element[k + j * lanes] &= std::numeric_limits<type>::max();      \
      }                                                                  \
    }                                                                    \
  }                                                                      \
  run_msa_3r(&tc[i], [](MacroAssembler& assm) { __ instr(w2, w1, w0); }, \
             [](uint64_t* ws, uint64_t* wt, uint64_t* wd) {              \
               verify(type, lanes, mask);                                \
             });

#define TEST_CASE2(V)                                    \
  V(sra_b, SRA_DF, int8_t, kMSALanesByte, UINT8_MAX)     \
  V(sra_h, SRA_DF, int16_t, kMSALanesHalf, UINT16_MAX)   \
  V(sra_w, SRA_DF, int32_t, kMSALanesWord, UINT32_MAX)   \
  V(sra_d, SRA_DF, int64_t, kMSALanesDword, UINT64_MAX)  \
  V(srar_b, SRAR_DF, int8_t, kMSALanesByte, UINT8_MAX)   \
  V(srar_h, SRAR_DF, int16_t, kMSALanesHalf, UINT16_MAX) \
  V(srar_w, SRAR_DF, int32_t, kMSALanesWord, UINT32_MAX) \
  V(srar_d, SRAR_DF, int64_t, kMSALanesDword, UINT64_MAX)

  for (size_t i = 0; i < arraysize(tc); ++i) {
    TEST_CASE2(RUN_TEST2)
  }

#undef TEST_CASE
#undef TEST_CASE2
#undef RUN_TEST
#undef RUN_TEST2
#undef SLL_DF
#undef SRL_DF
#undef SRA_DF
#undef BCRL_DF
#undef BSET_DF
#undef BNEG_DF
#undef BINSL_DF
#undef BINSR_DF
#undef ADDV_DF
#undef SUBV_DF
#undef MAX_DF
#undef MIN_DF
#undef MAXA_DF
#undef MINA_DF
#undef CEQ_DF
#undef CLT_DF
#undef CLE_DF
#undef ADD_A_DF
#undef ADDS_A_DF
#undef ADDS_DF
#undef AVE_DF
#undef AVER_DF
#undef SUBS_DF
#undef SUBSUS_U_DF
#undef SUBSUU_S_DF
#undef ASUB_S_DF
#undef ASUB_U_DF
#undef MULV_DF
#undef MADDV_DF
#undef MSUBV_DF
#undef DIV_DF
#undef MOD_DF
#undef SRAR_DF
#undef PCKEV_DF
#undef PCKOD_DF
#undef ILVL_DF
#undef ILVR_DF
#undef ILVEV_DF
#undef ILVOD_DF
#undef VSHF_DF
#undef HADD_DF
#undef HSUB_DF
}

struct TestCaseMsa3RF {
  uint64_t ws_lo;
  uint64_t ws_hi;
  uint64_t wt_lo;
  uint64_t wt_hi;
  uint64_t wd_lo;
  uint64_t wd_hi;
};

struct ExpectedResult_MSA3RF {
  uint64_t exp_res_lo;
  uint64_t exp_res_hi;
};

template <typename Func>
void run_msa_3rf(const struct TestCaseMsa3RF* input,
                 const struct ExpectedResult_MSA3RF* output,
                 Func Generate2RInstructionFunc) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  CpuFeatureScope fscope(&assm, MIPS_SIMD);
  msa_reg_t res;

  load_elements_of_vector(
      &assm, reinterpret_cast<const uint64_t*>(&input->ws_lo), w0, t0, t1);
  load_elements_of_vector(
      &assm, reinterpret_cast<const uint64_t*>(&input->wt_lo), w1, t0, t1);
  load_elements_of_vector(
      &assm, reinterpret_cast<const uint64_t*>(&input->wd_lo), w2, t0, t1);
  Generate2RInstructionFunc(assm);
  store_elements_of_vector(&assm, w2, a0);

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);

  f.Call(&res, 0, 0, 0, 0);

  CHECK_EQ(output->exp_res_lo, res.d[0]);
  CHECK_EQ(output->exp_res_hi, res.d[1]);
}

struct TestCaseMsa3RF_F {
  float ws_1, ws_2, ws_3, ws_4;
  float wt_1, wt_2, wt_3, wt_4;
  float wd_1, wd_2, wd_3, wd_4;
};
struct ExpRes_32I {
  int32_t exp_res_1;
  int32_t exp_res_2;
  int32_t exp_res_3;
  int32_t exp_res_4;
};

struct TestCaseMsa3RF_D {
  double ws_lo, ws_hi;
  double wt_lo, wt_hi;
  double wd_lo, wd_hi;
};
struct ExpRes_64I {
  int64_t exp_res_lo;
  int64_t exp_res_hi;
};

TEST(MSA_floating_point_quiet_compare) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  const float qnan_f = std::numeric_limits<float>::quiet_NaN();
  const double qnan_d = std::numeric_limits<double>::quiet_NaN();
  const float inf_f = std::numeric_limits<float>::infinity();
  const double inf_d = std::numeric_limits<double>::infinity();
  const int32_t ones = -1;

  const struct TestCaseMsa3RF_F tc_w[]{
      {qnan_f, -qnan_f, inf_f, 2.14e9f,  // ws
       qnan_f, 0.f, qnan_f, -2.14e9f,    // wt
       0, 0, 0, 0},                      // wd
      {inf_f, -inf_f, -3.4e38f, 1.5e-45f, -inf_f, -inf_f, -inf_f, inf_f, 0, 0,
       0, 0},
      {0.f, 19.871e24f, -1.5e-45f, -1.5e-45f, -19.871e24f, 19.871e24f, 1.5e-45f,
       -1.5e-45f, 0, 0, 0, 0}};

  const struct TestCaseMsa3RF_D tc_d[]{
      // ws_lo, ws_hi, wt_lo, wt_hi, wd_lo, wd_hi
      {qnan_d, -qnan_d, qnan_f, 0., 0, 0},
      {inf_d, 9.22e18, qnan_d, -9.22e18, 0, 0},
      {inf_d, inf_d, -inf_d, inf_d, 0, 0},
      {-2.3e-308, 5e-324, -inf_d, inf_d, 0, 0},
      {0., 24.1e87, -1.6e308, 24.1e87, 0, 0},
      {-5e-324, -5e-324, 5e-324, -5e-324, 0, 0}};

  const struct ExpectedResult_MSA3RF exp_res_fcaf = {0, 0};
  const struct ExpRes_32I exp_res_fcun_w[] = {
      {ones, ones, ones, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}};
  const struct ExpRes_64I exp_res_fcun_d[] = {{ones, ones}, {ones, 0}, {0, 0},
                                              {0, 0},       {0, 0},    {0, 0}};
  const struct ExpRes_32I exp_res_fceq_w[] = {
      {0, 0, 0, 0}, {0, ones, 0, 0}, {0, ones, 0, ones}};
  const struct ExpRes_64I exp_res_fceq_d[] = {{0, 0}, {0, 0},    {0, ones},
                                              {0, 0}, {0, ones}, {0, ones}};
  const struct ExpRes_32I exp_res_fcueq_w[] = {
      {ones, ones, ones, 0}, {0, ones, 0, 0}, {0, ones, 0, ones}};
  const struct ExpRes_64I exp_res_fcueq_d[] = {
      {ones, ones}, {ones, 0}, {0, ones}, {0, 0}, {0, ones}, {0, ones}};
  const struct ExpRes_32I exp_res_fclt_w[] = {
      {0, 0, 0, 0}, {0, 0, 0, ones}, {0, 0, ones, 0}};
  const struct ExpRes_64I exp_res_fclt_d[] = {{0, 0},    {0, 0}, {0, 0},
                                              {0, ones}, {0, 0}, {ones, 0}};
  const struct ExpRes_32I exp_res_fcult_w[] = {
      {ones, ones, ones, 0}, {0, 0, 0, ones}, {0, 0, ones, 0}};
  const struct ExpRes_64I exp_res_fcult_d[] = {
      {ones, ones}, {ones, 0}, {0, 0}, {0, ones}, {0, 0}, {ones, 0}};
  const struct ExpRes_32I exp_res_fcle_w[] = {
      {0, 0, 0, 0}, {0, ones, 0, ones}, {0, ones, ones, ones}};
  const struct ExpRes_64I exp_res_fcle_d[] = {
      {0, 0}, {0, 0}, {0, ones}, {0, ones}, {0, ones}, {ones, ones}};
  const struct ExpRes_32I exp_res_fcule_w[] = {
      {ones, ones, ones, 0}, {0, ones, 0, ones}, {0, ones, ones, ones}};
  const struct ExpRes_64I exp_res_fcule_d[] = {
      {ones, ones}, {ones, 0}, {0, ones}, {0, ones}, {0, ones}, {ones, ones}};
  const struct ExpRes_32I exp_res_fcor_w[] = {
      {0, 0, 0, ones}, {ones, ones, ones, ones}, {ones, ones, ones, ones}};
  const struct ExpRes_64I exp_res_fcor_d[] = {{0, 0},       {0, ones},
                                              {ones, ones}, {ones, ones},
                                              {ones, ones}, {ones, ones}};
  const struct ExpRes_32I exp_res_fcune_w[] = {
      {ones, ones, ones, ones}, {ones, 0, ones, ones}, {ones, 0, ones, 0}};
  const struct ExpRes_64I exp_res_fcune_d[] = {{ones, ones}, {ones, ones},
                                               {ones, 0},    {ones, ones},
                                               {ones, 0},    {ones, 0}};
  const struct ExpRes_32I exp_res_fcne_w[] = {
      {0, 0, 0, ones}, {ones, 0, ones, ones}, {ones, 0, ones, 0}};
  const struct ExpRes_64I exp_res_fcne_d[] = {
      {0, 0}, {0, ones}, {ones, 0}, {ones, ones}, {ones, 0}, {ones, 0}};

#define TEST_FP_QUIET_COMPARE_W(instruction, src, exp_res)                    \
  run_msa_3rf(reinterpret_cast<const struct TestCaseMsa3RF*>(src),            \
              reinterpret_cast<const struct ExpectedResult_MSA3RF*>(exp_res), \
              [](MacroAssembler& assm) { __ instruction(w2, w0, w1); });

#define TEST_FP_QUIET_COMPARE_D(instruction, src, exp_res)                    \
  run_msa_3rf(reinterpret_cast<const struct TestCaseMsa3RF*>(src),            \
              reinterpret_cast<const struct ExpectedResult_MSA3RF*>(exp_res), \
              [](MacroAssembler& assm) { __ instruction(w2, w0, w1); });

  for (uint64_t i = 0; i < arraysize(tc_w); i++) {
    TEST_FP_QUIET_COMPARE_W(fcaf_w, &tc_w[i], &exp_res_fcaf)
    TEST_FP_QUIET_COMPARE_W(fcun_w, &tc_w[i], &exp_res_fcun_w[i])
    TEST_FP_QUIET_COMPARE_W(fceq_w, &tc_w[i], &exp_res_fceq_w[i])
    TEST_FP_QUIET_COMPARE_W(fcueq_w, &tc_w[i], &exp_res_fcueq_w[i])
    TEST_FP_QUIET_COMPARE_W(fclt_w, &tc_w[i], &exp_res_fclt_w[i])
    TEST_FP_QUIET_COMPARE_W(fcult_w, &tc_w[i], &exp_res_fcult_w[i])
    TEST_FP_QUIET_COMPARE_W(fcle_w, &tc_w[i], &exp_res_fcle_w[i])
    TEST_FP_QUIET_COMPARE_W(fcule_w, &tc_w[i], &exp_res_fcule_w[i])
    TEST_FP_QUIET_COMPARE_W(fcor_w, &tc_w[i], &exp_res_fcor_w[i])
    TEST_FP_QUIET_COMPARE_W(fcune_w, &tc_w[i], &exp_res_fcune_w[i])
    TEST_FP_QUIET_COMPARE_W(fcne_w, &tc_w[i], &exp_res_fcne_w[i])
  }
  for (uint64_t i = 0; i < arraysize(tc_d); i++) {
    TEST_FP_QUIET_COMPARE_D(fcaf_d, &tc_d[i], &exp_res_fcaf)
    TEST_FP_QUIET_COMPARE_D(fcun_d, &tc_d[i], &exp_res_fcun_d[i])
    TEST_FP_QUIET_COMPARE_D(fceq_d, &tc_d[i], &exp_res_fceq_d[i])
    TEST_FP_QUIET_COMPARE_D(fcueq_d, &tc_d[i], &exp_res_fcueq_d[i])
    TEST_FP_QUIET_COMPARE_D(fclt_d, &tc_d[i], &exp_res_fclt_d[i])
    TEST_FP_QUIET_COMPARE_D(fcult_d, &tc_d[i], &exp_res_fcult_d[i])
    TEST_FP_QUIET_COMPARE_D(fcle_d, &tc_d[i], &exp_res_fcle_d[i])
    TEST_FP_QUIET_COMPARE_D(fcule_d, &tc_d[i], &exp_res_fcule_d[i])
    TEST_FP_QUIET_COMPARE_D(fcor_d, &tc_d[i], &exp_res_fcor_d[i])
    TEST_FP_QUIET_COMPARE_D(fcune_d, &tc_d[i], &exp_res_fcune_d[i])
    TEST_FP_QUIET_COMPARE_D(fcne_d, &tc_d[i], &exp_res_fcne_d[i])
  }
#undef TEST_FP_QUIET_COMPARE_W
#undef TEST_FP_QUIET_COMPARE_D
}

template <typename T>
inline const T* fadd_function(const T* src1, const T* src2, const T* src3,
                              T* dst) {
  for (uint64_t i = 0; i < kMSALanesByte / sizeof(T); i++) {
    dst[i] = src1[i] + src2[i];
  }
  return dst;
}
template <typename T>
inline const T* fsub_function(const T* src1, const T* src2, const T* src3,
                              T* dst) {
  for (uint64_t i = 0; i < kMSALanesByte / sizeof(T); i++) {
    dst[i] = src1[i] - src2[i];
  }
  return dst;
}
template <typename T>
inline const T* fmul_function(const T* src1, const T* src2, const T* src3,
                              T* dst) {
  for (uint64_t i = 0; i < kMSALanesByte / sizeof(T); i++) {
    dst[i] = src1[i] * src2[i];
  }
  return dst;
}
template <typename T>
inline const T* fdiv_function(const T* src1, const T* src2, const T* src3,
                              T* dst) {
  for (uint64_t i = 0; i < kMSALanesByte / sizeof(T); i++) {
    dst[i] = src1[i] / src2[i];
  }
  return dst;
}
template <typename T>
inline const T* fmadd_function(const T* src1, const T* src2, const T* src3,
                               T* dst) {
  for (uint64_t i = 0; i < kMSALanesByte / sizeof(T); i++) {
    dst[i] = std::fma(src1[i], src2[i], src3[i]);
  }
  return dst;
}
template <typename T>
inline const T* fmsub_function(const T* src1, const T* src2, const T* src3,
                               T* dst) {
  for (uint64_t i = 0; i < kMSALanesByte / sizeof(T); i++) {
    dst[i] = std::fma(src1[i], -src2[i], src3[i]);
  }
  return dst;
}

TEST(MSA_floating_point_arithmetic) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  const float inf_f = std::numeric_limits<float>::infinity();
  const double inf_d = std::numeric_limits<double>::infinity();

  const struct TestCaseMsa3RF_F tc_w[] = {
      {0.3, -2.14e13f, inf_f, 0.f,                     // ws
       -inf_f, std::sqrt(8.e-26f), -23.e34, -2.14e9f,  // wt
       -1e30f, 4.6e12f, 0, 2.14e9f},                   // wd
      {3.4e38f, -1.2e-38f, 1e19f, -1e19f, 3.4e38f, 1.2e-38f, -1e19f, -1e-19f,
       3.4e38f, 1.2e-38f * 3, 3.4e38f, -4e19f},
      {-3e-31f, 3e10f, 1e25f, 123.f, 1e-14f, 1e-34f, 4e25f, 321.f, 3e-17f,
       2e-24f, 2.f, -123456.f}};

  const struct TestCaseMsa3RF_D tc_d[] = {
      // ws_lo, ws_hi, wt_lo, wt_hi, wd_lo, wd_hi
      {0.3, -2.14e103, -inf_d, std::sqrt(8.e-206), -1e30, 4.6e102},
      {inf_d, 0., -23.e304, -2.104e9, 0, 2.104e9},
      {3.4e307, -1.2e-307, 3.4e307, 1.2e-307, 3.4e307, 1.2e-307 * 3},
      {1e154, -1e154, -1e154, -1e-154, 2.9e38, -4e19},
      {-3e-301, 3e100, 1e-104, 1e-304, 3e-107, 2e-204},
      {1e205, 123., 4e205, 321., 2., -123456.}};

  struct ExpectedResult_MSA3RF dst_container;

#define FP_ARITHMETIC_DF_W(instr, function, src1, src2, src3)           \
  run_msa_3rf(                                                          \
      reinterpret_cast<const struct TestCaseMsa3RF*>(src1),             \
      reinterpret_cast<const struct ExpectedResult_MSA3RF*>(function(   \
          src1, src2, src3, reinterpret_cast<float*>(&dst_container))), \
      [](MacroAssembler& assm) { __ instr(w2, w0, w1); });

#define FP_ARITHMETIC_DF_D(instr, function, src1, src2, src3)            \
  run_msa_3rf(                                                           \
      reinterpret_cast<const struct TestCaseMsa3RF*>(src1),              \
      reinterpret_cast<const struct ExpectedResult_MSA3RF*>(function(    \
          src1, src2, src3, reinterpret_cast<double*>(&dst_container))), \
      [](MacroAssembler& assm) { __ instr(w2, w0, w1); });

  for (uint64_t i = 0; i < arraysize(tc_w); i++) {
    FP_ARITHMETIC_DF_W(fadd_w, fadd_function, &tc_w[i].ws_1, &tc_w[i].wt_1,
                       &tc_w[i].wd_1)
    FP_ARITHMETIC_DF_W(fsub_w, fsub_function, &tc_w[i].ws_1, &tc_w[i].wt_1,
                       &tc_w[i].wd_1)
    FP_ARITHMETIC_DF_W(fmul_w, fmul_function, &tc_w[i].ws_1, &tc_w[i].wt_1,
                       &tc_w[i].wd_1)
    FP_ARITHMETIC_DF_W(fdiv_w, fdiv_function, &tc_w[i].ws_1, &tc_w[i].wt_1,
                       &tc_w[i].wd_1)
    FP_ARITHMETIC_DF_W(fmadd_w, fmadd_function, &tc_w[i].ws_1, &tc_w[i].wt_1,
                       &tc_w[i].wd_1)
    FP_ARITHMETIC_DF_W(fmsub_w, fmsub_function, &tc_w[i].ws_1, &tc_w[i].wt_1,
                       &tc_w[i].wd_1)
  }
  for (uint64_t i = 0; i < arraysize(tc_d); i++) {
    FP_ARITHMETIC_DF_D(fadd_d, fadd_function, &tc_d[i].ws_lo, &tc_d[i].wt_lo,
                       &tc_d[i].wd_lo)
    FP_ARITHMETIC_DF_D(fsub_d, fsub_function, &tc_d[i].ws_lo, &tc_d[i].wt_lo,
                       &tc_d[i].wd_lo)
    FP_ARITHMETIC_DF_D(fmul_d, fmul_function, &tc_d[i].ws_lo, &tc_d[i].wt_lo,
                       &tc_d[i].wd_lo)
    FP_ARITHMETIC_DF_D(fdiv_d, fdiv_function, &tc_d[i].ws_lo, &tc_d[i].wt_lo,
                       &tc_d[i].wd_lo)
    FP_ARITHMETIC_DF_D(fmadd_d, fmadd_function, &tc_d[i].ws_lo, &tc_d[i].wt_lo,
                       &tc_d[i].wd_lo)
    FP_ARITHMETIC_DF_D(fmsub_d, fmsub_function, &tc_d[i].ws_lo, &tc_d[i].wt_lo,
                       &tc_d[i].wd_lo)
  }
#undef FP_ARITHMETIC_DF_W
#undef FP_ARITHMETIC_DF_D
}

struct ExpRes_F {
  float exp_res_1;
  float exp_res_2;
  float exp_res_3;
  float exp_res_4;
};

struct ExpRes_D {
  double exp_res_1;
  double exp_res_2;
};

TEST(MSA_fmin_fmin_a_fmax_fmax_a) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  const float inf_f = std::numeric_limits<float>::infinity();
  const double inf_d = std::numeric_limits<double>::infinity();

  const struct TestCaseMsa3RF_F tc_w[] = {
      {0.3f, -2.14e13f, inf_f, -0.f,                    // ws
       -inf_f, -std::sqrt(8.e26f), -23.e34f, -2.14e9f,  // wt
       0, 0, 0, 0},                                     // wd
      {3.4e38f, 1.2e-41f, 1e19f, 1e19f,                 // ws
       3.4e38f, -1.1e-41f, -1e-42f, -1e29f,             // wt
       0, 0, 0, 0}};                                    // wd

  const struct TestCaseMsa3RF_D tc_d[] = {
      // ws_lo, ws_hi, wt_lo, wt_hi, wd_lo, wd_hi
      {0.3, -2.14e103, -inf_d, -std::sqrt(8e206), 0, 0},
      {inf_d, -0., -23e304, -2.14e90, 0, 0},
      {3.4e307, 1.2e-320, 3.4e307, -1.1e-320, 0, 0},
      {1e154, 1e154, -1e-321, -1e174, 0, 0}};

  const struct ExpRes_F exp_res_fmax_w[] = {{0.3f, -2.14e13f, inf_f, -0.f},
                                            {3.4e38f, 1.2e-41f, 1e19f, 1e19f}};
  const struct ExpRes_F exp_res_fmax_a_w[] = {
      {-inf_f, -std::sqrt(8e26f), inf_f, -2.14e9f},
      {3.4e38f, 1.2e-41f, 1e19f, -1e29f}};
  const struct ExpRes_F exp_res_fmin_w[] = {
      {-inf_f, -std::sqrt(8.e26f), -23e34f, -2.14e9f},
      {3.4e38f, -1.1e-41f, -1e-42f, -1e29f}};
  const struct ExpRes_F exp_res_fmin_a_w[] = {
      {0.3, -2.14e13f, -23.e34f, -0.f}, {3.4e38f, -1.1e-41f, -1e-42f, 1e19f}};

  const struct ExpRes_D exp_res_fmax_d[] = {
      {0.3, -2.14e103}, {inf_d, -0.}, {3.4e307, 1.2e-320}, {1e154, 1e154}};
  const struct ExpRes_D exp_res_fmax_a_d[] = {{-inf_d, -std::sqrt(8e206)},
                                              {inf_d, -2.14e90},
                                              {3.4e307, 1.2e-320},
                                              {1e154, -1e174}};
  const struct ExpRes_D exp_res_fmin_d[] = {{-inf_d, -std::sqrt(8e206)},
                                            {-23e304, -2.14e90},
                                            {3.4e307, -1.1e-320},
                                            {-1e-321, -1e174}};
  const struct ExpRes_D exp_res_fmin_a_d[] = {
      {0.3, -2.14e103}, {-23e304, -0.}, {3.4e307, -1.1e-320}, {-1e-321, 1e154}};

#define TEST_FP_MIN_MAX_W(instruction, src, exp_res)                          \
  run_msa_3rf(reinterpret_cast<const struct TestCaseMsa3RF*>(src),            \
              reinterpret_cast<const struct ExpectedResult_MSA3RF*>(exp_res), \
              [](MacroAssembler& assm) { __ instruction(w2, w0, w1); });

#define TEST_FP_MIN_MAX_D(instruction, src, exp_res)                          \
  run_msa_3rf(reinterpret_cast<const struct TestCaseMsa3RF*>(src),            \
              reinterpret_cast<const struct ExpectedResult_MSA3RF*>(exp_res), \
              [](MacroAssembler& assm) { __ instruction(w2, w0, w1); });

  for (uint64_t i = 0; i < arraysize(tc_w); i++) {
    TEST_FP_MIN_MAX_W(fmax_w, &tc_w[i], &exp_res_fmax_w[i])
    TEST_FP_MIN_MAX_W(fmax_a_w, &tc_w[i], &exp_res_fmax_a_w[i])
    TEST_FP_MIN_MAX_W(fmin_w, &tc_w[
```