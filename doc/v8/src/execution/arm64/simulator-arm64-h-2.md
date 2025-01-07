Response:
The user wants a summary of the provided C++ code snippet from V8.

Here's a breakdown of the thinking process:

1. **Identify the core purpose:** The code snippet defines a class named `Simulator` and includes methods related to logic and floating-point operations. The presence of `LogicVRegister` and `VectorFormat` strongly suggests vector/SIMD operations, likely NEON on ARM64.

2. **Recognize the context:** The file path `v8/src/execution/arm64/simulator-arm64.h` indicates this is part of the V8 JavaScript engine, specifically for simulating ARM64 architecture during development or testing.

3. **Categorize the functionalities:**  Group the provided methods into logical categories. The most prominent categories are:
    * **Logical Operations:** `and_`, `orr`, `eor`, etc. operating on `LogicVRegister`.
    * **Vector Manipulation:** `ext`, `ins_element`, `dup_element`, `trn`, `zip`, `uzp`.
    * **Arithmetic Operations:** `add`, `sub`, but the snippet focuses on vector versions like `addlp`, `saddlp`.
    * **Shift/Rotate Operations:** `shl`, `sshr`, `rbit`, `rev`.
    * **Floating-Point Operations:**  Methods starting with `f` like `fadd`, `fsub`, `fmul`, `fcmp`, and helper functions for FP conversions and rounding.

4. **Address specific instructions:**

    * **`.tq` extension:**  The code snippet is `.h`, a C++ header file, so it's not Torque.
    * **Relationship to JavaScript:**  Vector operations are used to optimize numerical computations in JavaScript. Floating-point operations are fundamental to JavaScript number handling.
    * **Code logic reasoning:**  Focus on explaining the *types* of operations rather than detailed step-by-step logic. For example, "addition of vector registers" instead of simulating each element-wise addition.
    * **User programming errors:** Think about how these low-level operations relate to common JavaScript mistakes, like assuming exact floating-point arithmetic.

5. **Formulate the summary:** Combine the categorized functionalities and the answers to specific instructions into a concise summary.

6. **Refine the language:**  Use clear and accurate terminology. Explain concepts like "SIMD" and "vector registers" in a way that's understandable even without deep hardware knowledge.

7. **Structure the answer:** Follow the user's request by listing functionalities, addressing the `.tq` question, explaining the JavaScript relationship, providing a simple code logic example, discussing user errors, and finally summarizing.

**(Self-Correction during the process):**

* **Initial thought:**  Focus heavily on individual instructions.
* **Correction:** Realized the request is for a functional overview, so grouping instructions by category is more effective.
* **Initial thought:** Provide very detailed explanations of each instruction.
* **Correction:**  Keep the explanations high-level, as the user didn't ask for a detailed manual of each function.
* **Initial thought:**  Provide complex JavaScript examples.
* **Correction:**  Keep the JavaScript example simple and illustrative of the *concept* rather than directly mirroring the C++ code.
```cpp
    const LogicVRegister& src2, int index);
  LogicVRegister sub(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister and_(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister orr(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister orn(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister eor(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister bic(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister bic(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src, uint64_t imm);
  LogicVRegister bif(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister bit(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister bsl(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister cls(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src);
  LogicVRegister clz(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src);
  LogicVRegister cnt(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src);
  LogicVRegister not_(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src);
  LogicVRegister rbit(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src);
  LogicVRegister rev(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src, int revSize);
  LogicVRegister rev16(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister rev32(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister rev64(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister addlp(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src, bool is_signed,
                       bool do_accumulate);
  LogicVRegister saddlp(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src);
  LogicVRegister uaddlp(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src);
  LogicVRegister sadalp(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src);
  LogicVRegister uadalp(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src);
  LogicVRegister ext(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src1, const LogicVRegister& src2,
                     int index);
  LogicVRegister ins_element(VectorFormat vform, LogicVRegister dst,
                             int dst_index, const LogicVRegister& src,
                             int src_index);
  LogicVRegister ins_immediate(VectorFormat vform, LogicVRegister dst,
                               int dst_index, uint64_t imm);
  LogicVRegister dup_element(VectorFormat vform, LogicVRegister dst,
                             const LogicVRegister& src, int src_index);
  LogicVRegister dup_immediate(VectorFormat vform, LogicVRegister dst,
                               uint64_t imm);
  LogicVRegister movi(VectorFormat vform, LogicVRegister dst, uint64_t imm);
  LogicVRegister mvni(VectorFormat vform, LogicVRegister dst, uint64_t imm);
  LogicVRegister orr(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src, uint64_t imm);
  LogicVRegister sshl(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister ushl(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister SMinMax(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src1, const LogicVRegister& src2,
                         bool max);
  LogicVRegister smax(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister smin(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister SMinMaxP(VectorFormat vform, LogicVRegister dst,
                          const LogicVRegister& src1,
                          const LogicVRegister& src2, bool max);
  LogicVRegister smaxp(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister sminp(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister addp(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src);
  LogicVRegister addv(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src);
  LogicVRegister uaddlv(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src);
  LogicVRegister saddlv(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src);
  LogicVRegister SMinMaxV(VectorFormat vform, LogicVRegister dst,
                          const LogicVRegister& src, bool max);
  LogicVRegister smaxv(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister sminv(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister uxtl(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src);
  LogicVRegister uxtl2(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister sxtl(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src);
  LogicVRegister sxtl2(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister Table(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& ind, bool zero_out_of_bounds,
                       const LogicVRegister* tab1,
                       const LogicVRegister* tab2 = nullptr,
                       const LogicVRegister* tab3 = nullptr,
                       const LogicVRegister* tab4 = nullptr);
  LogicVRegister tbl(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& tab, const LogicVRegister& ind);
  LogicVRegister tbl(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& tab, const LogicVRegister& tab2,
                     const LogicVRegister& ind);
  LogicVRegister tbl(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& tab, const LogicVRegister& tab2,
                     const LogicVRegister& tab3, const LogicVRegister& ind);
  LogicVRegister tbl(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& tab, const LogicVRegister& tab2,
                     const LogicVRegister& tab3, const LogicVRegister& tab4,
                     const LogicVRegister& ind);
  LogicVRegister tbx(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& tab, const LogicVRegister& ind);
  LogicVRegister tbx(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& tab, const LogicVRegister& tab2,
                     const LogicVRegister& ind);
  LogicVRegister tbx(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& tab, const LogicVRegister& tab2,
                     const LogicVRegister& tab3, const LogicVRegister& ind);
  LogicVRegister tbx(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& tab, const LogicVRegister& tab2,
                     const LogicVRegister& tab3, const LogicVRegister& tab4,
                     const LogicVRegister& ind);
  LogicVRegister uaddl(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister uaddl2(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister uaddw(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister uaddw2(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister saddl(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister saddl2(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister saddw(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister saddw2(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister usubl(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister usubl2(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister usubw(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister usubw2(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister ssubl(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister ssubl2(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister ssubw(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister ssubw2(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister UMinMax(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src1, const LogicVRegister& src2,
                         bool max);
  LogicVRegister umax(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister umin(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister UMinMaxP(VectorFormat vform, LogicVRegister dst,
                          const LogicVRegister& src1,
                          const LogicVRegister& src2, bool max);
  LogicVRegister umaxp(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister uminp(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister UMinMaxV(VectorFormat vform, LogicVRegister dst,
                          const LogicVRegister& src, bool max);
  LogicVRegister umaxv(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister uminv(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister trn1(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister trn2(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister zip1(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister zip2(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister uzp1(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister uzp2(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister shl(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src, int shift);
  LogicVRegister scvtf(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src, int fbits,
                       FPRounding rounding_mode);
  LogicVRegister ucvtf(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src, int fbits,
                       FPRounding rounding_mode);
  LogicVRegister sshll(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src, int shift);
  LogicVRegister sshll2(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src, int shift);
  LogicVRegister shll(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src);
  LogicVRegister shll2(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister ushll(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src, int shift);
  LogicVRegister ushll2(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src, int shift);
  LogicVRegister sli(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src, int shift);
  LogicVRegister sri(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src, int shift);
  LogicVRegister sshr(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src, int shift);
  LogicVRegister ushr(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src, int shift);
  LogicVRegister ssra(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src, int shift);
  LogicVRegister usra(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src, int shift);
  LogicVRegister srsra(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src, int shift);
  LogicVRegister ursra(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src, int shift);
  LogicVRegister suqadd(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src);
  LogicVRegister usqadd(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src);
  LogicVRegister sqshl(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src, int shift);
  LogicVRegister uqshl(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src, int shift);
  LogicVRegister sqshlu(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src, int shift);
  LogicVRegister abs(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src);
  LogicVRegister neg(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src);
  LogicVRegister ExtractNarrow(VectorFormat vform, LogicVRegister dst,
                               bool dstIsSigned, const LogicVRegister& src,
                               bool srcIsSigned);
  LogicVRegister xtn(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src);
  LogicVRegister sqxtn(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister uqxtn(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister sqxtun(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src);
  LogicVRegister AbsDiff(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src1, const LogicVRegister& src2,
                         bool issigned);
  LogicVRegister saba(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister uaba(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister shrn(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src, int shift);
  LogicVRegister shrn2(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src, int shift);
  LogicVRegister rshrn(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src, int shift);
  LogicVRegister rshrn2(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src, int shift);
  LogicVRegister uqshrn(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src, int shift);
  LogicVRegister uqshrn2(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src, int shift);
  LogicVRegister uqrshrn(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src, int shift);
  LogicVRegister uqrshrn2(VectorFormat vform, LogicVRegister dst,
                          const LogicVRegister& src, int shift);
  LogicVRegister sqshrn(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src, int shift);
  LogicVRegister sqshrn2(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src, int shift);
  LogicVRegister sqrshrn(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src, int shift);
  LogicVRegister sqrshrn2(VectorFormat vform, LogicVRegister dst,
                          const LogicVRegister& src, int shift);
  LogicVRegister sqshrun(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src, int shift);
  LogicVRegister sqshrun2(VectorFormat vform, LogicVRegister dst,
                          const LogicVRegister& src, int shift);
  LogicVRegister sqrshrun(VectorFormat vform, LogicVRegister dst,
                          const LogicVRegister& src, int shift);
  LogicVRegister sqrshrun2(VectorFormat vform, LogicVRegister dst,
                           const LogicVRegister& src, int shift);
  LogicVRegister sqrdmulh(VectorFormat vform, LogicVRegister dst,
                          const LogicVRegister& src1,
                          const LogicVRegister& src2, bool round = true);
  LogicVRegister dot(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src1, const LogicVRegister& src2,
                     bool is_src1_signed, bool is_src2_signed);
  LogicVRegister sdot(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister sqdmulh(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src1,
                         const LogicVRegister& src2);
#define NEON_3VREG_LOGIC_LIST(V) \
  V(addhn)                       \
  V(addhn2)                      \
  V(raddhn)                      \
  V(raddhn2)                     \
  V(subhn)                       \
  V(subhn2)                      \
  V(rsubhn)                      \
  V(rsubhn2)                     \
  V(pmull)                       \
  V(pmull2)                      \
  V(sabal)                       \
  V(sabal2)                      \
  V(uabal)                       \
  V(uabal2)                      \
  V(sabdl)                       \
  V(sabdl2)                      \
  V(uabdl)                       \
  V(uabdl2)                      \
  V(smull)                       \
  V(smull2)                      \
  V(umull)                       \
  V(umull2)                      \
  V(smlal)                       \
  V(smlal2)                      \
  V(umlal)                       \
  V(umlal2)                      \
  V(smlsl)                       \
  V(smlsl2)                      \
  V(umlsl)                       \
  V(umlsl2)                      \
  V(sqdmlal)                     \
  V(sqdmlal2)                    \
  V(sqdmlsl)                     \
  V(sqdmlsl2)                    \
  V(sqdmull)                     \
  V(sqdmull2)

#define DEFINE_LOGIC_FUNC(FXN)                               \
  LogicVRegister FXN(VectorFormat vform, LogicVRegister dst, \
                     const LogicVRegister& src1, const LogicVRegister& src2);
  NEON_3VREG_LOGIC_LIST(DEFINE_LOGIC_FUNC)
#undef DEFINE_LOGIC_FUNC

#define NEON_FP3SAME_LIST(V) \
  V(fadd, FPAdd, false)      \
  V(fsub, FPSub, true)       \
  V(fmul, FPMul, true)       \
  V(fmulx, FPMulx, true)     \
  V(fdiv, FPDiv, true)       \
  V(fmax, FPMax, false)      \
  V(fmin, FPMin, false)      \
  V(fmaxnm, FPMaxNM, false)  \
  V(fminnm, FPMinNM, false)

#define DECLARE_NEON_FP_VECTOR_OP(FN, OP, PROCNAN)                           \
  template <typename T>                                                      \
  LogicVRegister FN(VectorFormat vform, LogicVRegister dst,                  \
                    const LogicVRegister& src1, const LogicVRegister& src2); \
  LogicVRegister FN(VectorFormat vform, LogicVRegister dst,                  \
                    const LogicVRegister& src1, const LogicVRegister& src2);
  NEON_FP3SAME_LIST(DECLARE_NEON_FP_VECTOR_OP)
#undef DECLARE_NEON_FP_VECTOR_OP

#define NEON_FPPAIRWISE_LIST(V) \
  V(faddp, fadd, FPAdd)         \
  V(fmaxp, fmax, FPMax)         \
  V(fmaxnmp, fmaxnm, FPMaxNM)   \
  V(fminp, fmin, FPMin)         \
  V(fminnmp, fminnm, FPMinNM)

#define DECLARE_NEON_FP_PAIR_OP(FNP, FN, OP)                                  \
  LogicVRegister FNP(VectorFormat vform, LogicVRegister dst,                  \
                     const LogicVRegister& src1, const LogicVRegister& src2); \
  LogicVRegister FNP(VectorFormat vform, LogicVRegister dst,                  \
                     const LogicVRegister& src);
  NEON_FPPAIRWISE_LIST(DECLARE_NEON_FP_PAIR_OP)
#undef DECLARE_NEON_FP_PAIR_OP

  template <typename T>
  LogicVRegister frecps(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister frecps(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src1, const LogicVRegister& src2);
  template <typename T>
  LogicVRegister frsqrts(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src1,
                         const LogicVRegister& src2);
  LogicVRegister frsqrts(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src1,
                         const LogicVRegister& src2);
  template <typename T>
  LogicVRegister fmla(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister fmla(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  template <typename T>
  LogicVRegister fmls(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister fmls(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister fnmul(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2);

  template <typename T>
  LogicVRegister fcmp(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2,
                      Condition cond);
  LogicVRegister fcmp(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2,
                      Condition cond);
  LogicVRegister fabscmp(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src1, const LogicVRegister& src2,
                         Condition cond);
  LogicVRegister fcmp_zero(VectorFormat vform, LogicVRegister dst,
                           const LogicVRegister& src, Condition cond);

  template <typename T>
  LogicVRegister fneg(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src);
  LogicVRegister fneg(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src);
  template <typename T>
  LogicVRegister frecpx(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src);
  LogicVRegister frecpx(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src);
  template <typename T>
  LogicVRegister fabs_(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister fabs_(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister fabd(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister frint(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src, FPRounding rounding_mode,
                       bool inexact_exception = false);
  LogicVRegister fcvts(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src, FPRounding rounding_mode,
                       int fbits = 0);
  LogicVRegister fcvtu(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src, FPRounding rounding_mode,
                       int fbits = 0);
  LogicVRegister fcvtl(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister fcvtl2(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src);
  LogicVRegister fcvtn(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister fcvtn2(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src);
  LogicVRegister fcvtxn(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src);
  LogicVRegister fcvtxn2(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src);
  LogicVRegister fsqrt(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister frsqrte(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src);
  LogicVRegister frecpe(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src, FPRounding rounding);
  LogicVRegister ursqrte(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src);
  LogicVRegister urecpe(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src);

  using FPMinMaxOp = float (Simulator::*)(float a, float b);

  LogicVRegister FMinMaxV(VectorFormat vform, LogicVRegister dst,
                          const LogicVRegister& src, FPMinMaxOp Op);

  LogicVRegister fminv(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister fmaxv(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister fminnmv(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src);
  LogicVRegister fmaxnmv(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src);

  template <typename T>
  T FPRecipSqrtEstimate(T op);
  template <typename T>
  T FPRecipEstimate(T op, FPRounding rounding);
  template <typename T, typename R>
  R FPToFixed(T op, int fbits, bool is_signed, FPRounding rounding);

  void FPCompare(double val0, double val1);
  double FPRoundInt(double value, FPRounding round_mode);
  double FPToDouble(float value);
  float FPToFloat(double value, FPRounding round_mode);
  float FPToFloat(float16 value);
  float16 FPToFloat16(float value, FPRounding round_mode);
  float16 FPToFloat16(double value, FPRounding round_mode);
  double recip_sqrt_estimate(double a);
  double recip_estimate(double a);
  double FPRecipSqrtEstimate(double a);
  double FPRecipEstimate(double a);
  double FixedToDouble(int64_t src, int
Prompt: 
```
这是目录为v8/src/execution/arm64/simulator-arm64.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/arm64/simulator-arm64.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能

"""
    const LogicVRegister& src2, int index);
  LogicVRegister sub(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister and_(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister orr(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister orn(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister eor(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister bic(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister bic(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src, uint64_t imm);
  LogicVRegister bif(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister bit(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister bsl(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister cls(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src);
  LogicVRegister clz(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src);
  LogicVRegister cnt(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src);
  LogicVRegister not_(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src);
  LogicVRegister rbit(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src);
  LogicVRegister rev(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src, int revSize);
  LogicVRegister rev16(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister rev32(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister rev64(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister addlp(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src, bool is_signed,
                       bool do_accumulate);
  LogicVRegister saddlp(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src);
  LogicVRegister uaddlp(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src);
  LogicVRegister sadalp(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src);
  LogicVRegister uadalp(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src);
  LogicVRegister ext(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src1, const LogicVRegister& src2,
                     int index);
  LogicVRegister ins_element(VectorFormat vform, LogicVRegister dst,
                             int dst_index, const LogicVRegister& src,
                             int src_index);
  LogicVRegister ins_immediate(VectorFormat vform, LogicVRegister dst,
                               int dst_index, uint64_t imm);
  LogicVRegister dup_element(VectorFormat vform, LogicVRegister dst,
                             const LogicVRegister& src, int src_index);
  LogicVRegister dup_immediate(VectorFormat vform, LogicVRegister dst,
                               uint64_t imm);
  LogicVRegister movi(VectorFormat vform, LogicVRegister dst, uint64_t imm);
  LogicVRegister mvni(VectorFormat vform, LogicVRegister dst, uint64_t imm);
  LogicVRegister orr(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src, uint64_t imm);
  LogicVRegister sshl(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister ushl(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister SMinMax(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src1, const LogicVRegister& src2,
                         bool max);
  LogicVRegister smax(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister smin(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister SMinMaxP(VectorFormat vform, LogicVRegister dst,
                          const LogicVRegister& src1,
                          const LogicVRegister& src2, bool max);
  LogicVRegister smaxp(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister sminp(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister addp(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src);
  LogicVRegister addv(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src);
  LogicVRegister uaddlv(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src);
  LogicVRegister saddlv(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src);
  LogicVRegister SMinMaxV(VectorFormat vform, LogicVRegister dst,
                          const LogicVRegister& src, bool max);
  LogicVRegister smaxv(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister sminv(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister uxtl(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src);
  LogicVRegister uxtl2(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister sxtl(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src);
  LogicVRegister sxtl2(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister Table(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& ind, bool zero_out_of_bounds,
                       const LogicVRegister* tab1,
                       const LogicVRegister* tab2 = nullptr,
                       const LogicVRegister* tab3 = nullptr,
                       const LogicVRegister* tab4 = nullptr);
  LogicVRegister tbl(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& tab, const LogicVRegister& ind);
  LogicVRegister tbl(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& tab, const LogicVRegister& tab2,
                     const LogicVRegister& ind);
  LogicVRegister tbl(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& tab, const LogicVRegister& tab2,
                     const LogicVRegister& tab3, const LogicVRegister& ind);
  LogicVRegister tbl(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& tab, const LogicVRegister& tab2,
                     const LogicVRegister& tab3, const LogicVRegister& tab4,
                     const LogicVRegister& ind);
  LogicVRegister tbx(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& tab, const LogicVRegister& ind);
  LogicVRegister tbx(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& tab, const LogicVRegister& tab2,
                     const LogicVRegister& ind);
  LogicVRegister tbx(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& tab, const LogicVRegister& tab2,
                     const LogicVRegister& tab3, const LogicVRegister& ind);
  LogicVRegister tbx(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& tab, const LogicVRegister& tab2,
                     const LogicVRegister& tab3, const LogicVRegister& tab4,
                     const LogicVRegister& ind);
  LogicVRegister uaddl(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister uaddl2(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister uaddw(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister uaddw2(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister saddl(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister saddl2(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister saddw(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister saddw2(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister usubl(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister usubl2(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister usubw(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister usubw2(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister ssubl(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister ssubl2(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister ssubw(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister ssubw2(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister UMinMax(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src1, const LogicVRegister& src2,
                         bool max);
  LogicVRegister umax(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister umin(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister UMinMaxP(VectorFormat vform, LogicVRegister dst,
                          const LogicVRegister& src1,
                          const LogicVRegister& src2, bool max);
  LogicVRegister umaxp(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister uminp(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister UMinMaxV(VectorFormat vform, LogicVRegister dst,
                          const LogicVRegister& src, bool max);
  LogicVRegister umaxv(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister uminv(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister trn1(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister trn2(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister zip1(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister zip2(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister uzp1(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister uzp2(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister shl(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src, int shift);
  LogicVRegister scvtf(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src, int fbits,
                       FPRounding rounding_mode);
  LogicVRegister ucvtf(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src, int fbits,
                       FPRounding rounding_mode);
  LogicVRegister sshll(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src, int shift);
  LogicVRegister sshll2(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src, int shift);
  LogicVRegister shll(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src);
  LogicVRegister shll2(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister ushll(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src, int shift);
  LogicVRegister ushll2(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src, int shift);
  LogicVRegister sli(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src, int shift);
  LogicVRegister sri(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src, int shift);
  LogicVRegister sshr(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src, int shift);
  LogicVRegister ushr(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src, int shift);
  LogicVRegister ssra(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src, int shift);
  LogicVRegister usra(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src, int shift);
  LogicVRegister srsra(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src, int shift);
  LogicVRegister ursra(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src, int shift);
  LogicVRegister suqadd(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src);
  LogicVRegister usqadd(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src);
  LogicVRegister sqshl(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src, int shift);
  LogicVRegister uqshl(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src, int shift);
  LogicVRegister sqshlu(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src, int shift);
  LogicVRegister abs(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src);
  LogicVRegister neg(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src);
  LogicVRegister ExtractNarrow(VectorFormat vform, LogicVRegister dst,
                               bool dstIsSigned, const LogicVRegister& src,
                               bool srcIsSigned);
  LogicVRegister xtn(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src);
  LogicVRegister sqxtn(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister uqxtn(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister sqxtun(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src);
  LogicVRegister AbsDiff(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src1, const LogicVRegister& src2,
                         bool issigned);
  LogicVRegister saba(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister uaba(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister shrn(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src, int shift);
  LogicVRegister shrn2(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src, int shift);
  LogicVRegister rshrn(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src, int shift);
  LogicVRegister rshrn2(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src, int shift);
  LogicVRegister uqshrn(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src, int shift);
  LogicVRegister uqshrn2(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src, int shift);
  LogicVRegister uqrshrn(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src, int shift);
  LogicVRegister uqrshrn2(VectorFormat vform, LogicVRegister dst,
                          const LogicVRegister& src, int shift);
  LogicVRegister sqshrn(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src, int shift);
  LogicVRegister sqshrn2(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src, int shift);
  LogicVRegister sqrshrn(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src, int shift);
  LogicVRegister sqrshrn2(VectorFormat vform, LogicVRegister dst,
                          const LogicVRegister& src, int shift);
  LogicVRegister sqshrun(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src, int shift);
  LogicVRegister sqshrun2(VectorFormat vform, LogicVRegister dst,
                          const LogicVRegister& src, int shift);
  LogicVRegister sqrshrun(VectorFormat vform, LogicVRegister dst,
                          const LogicVRegister& src, int shift);
  LogicVRegister sqrshrun2(VectorFormat vform, LogicVRegister dst,
                           const LogicVRegister& src, int shift);
  LogicVRegister sqrdmulh(VectorFormat vform, LogicVRegister dst,
                          const LogicVRegister& src1,
                          const LogicVRegister& src2, bool round = true);
  LogicVRegister dot(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src1, const LogicVRegister& src2,
                     bool is_src1_signed, bool is_src2_signed);
  LogicVRegister sdot(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister sqdmulh(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src1,
                         const LogicVRegister& src2);
#define NEON_3VREG_LOGIC_LIST(V) \
  V(addhn)                       \
  V(addhn2)                      \
  V(raddhn)                      \
  V(raddhn2)                     \
  V(subhn)                       \
  V(subhn2)                      \
  V(rsubhn)                      \
  V(rsubhn2)                     \
  V(pmull)                       \
  V(pmull2)                      \
  V(sabal)                       \
  V(sabal2)                      \
  V(uabal)                       \
  V(uabal2)                      \
  V(sabdl)                       \
  V(sabdl2)                      \
  V(uabdl)                       \
  V(uabdl2)                      \
  V(smull)                       \
  V(smull2)                      \
  V(umull)                       \
  V(umull2)                      \
  V(smlal)                       \
  V(smlal2)                      \
  V(umlal)                       \
  V(umlal2)                      \
  V(smlsl)                       \
  V(smlsl2)                      \
  V(umlsl)                       \
  V(umlsl2)                      \
  V(sqdmlal)                     \
  V(sqdmlal2)                    \
  V(sqdmlsl)                     \
  V(sqdmlsl2)                    \
  V(sqdmull)                     \
  V(sqdmull2)

#define DEFINE_LOGIC_FUNC(FXN)                               \
  LogicVRegister FXN(VectorFormat vform, LogicVRegister dst, \
                     const LogicVRegister& src1, const LogicVRegister& src2);
  NEON_3VREG_LOGIC_LIST(DEFINE_LOGIC_FUNC)
#undef DEFINE_LOGIC_FUNC

#define NEON_FP3SAME_LIST(V) \
  V(fadd, FPAdd, false)      \
  V(fsub, FPSub, true)       \
  V(fmul, FPMul, true)       \
  V(fmulx, FPMulx, true)     \
  V(fdiv, FPDiv, true)       \
  V(fmax, FPMax, false)      \
  V(fmin, FPMin, false)      \
  V(fmaxnm, FPMaxNM, false)  \
  V(fminnm, FPMinNM, false)

#define DECLARE_NEON_FP_VECTOR_OP(FN, OP, PROCNAN)                           \
  template <typename T>                                                      \
  LogicVRegister FN(VectorFormat vform, LogicVRegister dst,                  \
                    const LogicVRegister& src1, const LogicVRegister& src2); \
  LogicVRegister FN(VectorFormat vform, LogicVRegister dst,                  \
                    const LogicVRegister& src1, const LogicVRegister& src2);
  NEON_FP3SAME_LIST(DECLARE_NEON_FP_VECTOR_OP)
#undef DECLARE_NEON_FP_VECTOR_OP

#define NEON_FPPAIRWISE_LIST(V) \
  V(faddp, fadd, FPAdd)         \
  V(fmaxp, fmax, FPMax)         \
  V(fmaxnmp, fmaxnm, FPMaxNM)   \
  V(fminp, fmin, FPMin)         \
  V(fminnmp, fminnm, FPMinNM)

#define DECLARE_NEON_FP_PAIR_OP(FNP, FN, OP)                                  \
  LogicVRegister FNP(VectorFormat vform, LogicVRegister dst,                  \
                     const LogicVRegister& src1, const LogicVRegister& src2); \
  LogicVRegister FNP(VectorFormat vform, LogicVRegister dst,                  \
                     const LogicVRegister& src);
  NEON_FPPAIRWISE_LIST(DECLARE_NEON_FP_PAIR_OP)
#undef DECLARE_NEON_FP_PAIR_OP

  template <typename T>
  LogicVRegister frecps(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister frecps(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src1, const LogicVRegister& src2);
  template <typename T>
  LogicVRegister frsqrts(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src1,
                         const LogicVRegister& src2);
  LogicVRegister frsqrts(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src1,
                         const LogicVRegister& src2);
  template <typename T>
  LogicVRegister fmla(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister fmla(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  template <typename T>
  LogicVRegister fmls(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister fmls(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister fnmul(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2);

  template <typename T>
  LogicVRegister fcmp(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2,
                      Condition cond);
  LogicVRegister fcmp(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2,
                      Condition cond);
  LogicVRegister fabscmp(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src1, const LogicVRegister& src2,
                         Condition cond);
  LogicVRegister fcmp_zero(VectorFormat vform, LogicVRegister dst,
                           const LogicVRegister& src, Condition cond);

  template <typename T>
  LogicVRegister fneg(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src);
  LogicVRegister fneg(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src);
  template <typename T>
  LogicVRegister frecpx(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src);
  LogicVRegister frecpx(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src);
  template <typename T>
  LogicVRegister fabs_(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister fabs_(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister fabd(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister frint(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src, FPRounding rounding_mode,
                       bool inexact_exception = false);
  LogicVRegister fcvts(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src, FPRounding rounding_mode,
                       int fbits = 0);
  LogicVRegister fcvtu(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src, FPRounding rounding_mode,
                       int fbits = 0);
  LogicVRegister fcvtl(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister fcvtl2(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src);
  LogicVRegister fcvtn(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister fcvtn2(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src);
  LogicVRegister fcvtxn(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src);
  LogicVRegister fcvtxn2(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src);
  LogicVRegister fsqrt(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister frsqrte(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src);
  LogicVRegister frecpe(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src, FPRounding rounding);
  LogicVRegister ursqrte(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src);
  LogicVRegister urecpe(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src);

  using FPMinMaxOp = float (Simulator::*)(float a, float b);

  LogicVRegister FMinMaxV(VectorFormat vform, LogicVRegister dst,
                          const LogicVRegister& src, FPMinMaxOp Op);

  LogicVRegister fminv(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister fmaxv(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src);
  LogicVRegister fminnmv(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src);
  LogicVRegister fmaxnmv(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src);

  template <typename T>
  T FPRecipSqrtEstimate(T op);
  template <typename T>
  T FPRecipEstimate(T op, FPRounding rounding);
  template <typename T, typename R>
  R FPToFixed(T op, int fbits, bool is_signed, FPRounding rounding);

  void FPCompare(double val0, double val1);
  double FPRoundInt(double value, FPRounding round_mode);
  double FPToDouble(float value);
  float FPToFloat(double value, FPRounding round_mode);
  float FPToFloat(float16 value);
  float16 FPToFloat16(float value, FPRounding round_mode);
  float16 FPToFloat16(double value, FPRounding round_mode);
  double recip_sqrt_estimate(double a);
  double recip_estimate(double a);
  double FPRecipSqrtEstimate(double a);
  double FPRecipEstimate(double a);
  double FixedToDouble(int64_t src, int fbits, FPRounding round_mode);
  double UFixedToDouble(uint64_t src, int fbits, FPRounding round_mode);
  float FixedToFloat(int64_t src, int fbits, FPRounding round_mode);
  float UFixedToFloat(uint64_t src, int fbits, FPRounding round_mode);
  float16 FixedToFloat16(int64_t src, int fbits, FPRounding round_mode);
  float16 UFixedToFloat16(uint64_t src, int fbits, FPRounding round_mode);
  int16_t FPToInt16(double value, FPRounding rmode);
  int32_t FPToInt32(double value, FPRounding rmode);
  int64_t FPToInt64(double value, FPRounding rmode);
  uint16_t FPToUInt16(double value, FPRounding rmode);
  uint32_t FPToUInt32(double value, FPRounding rmode);
  uint64_t FPToUInt64(double value, FPRounding rmode);
  int32_t FPToFixedJS(double value);

  template <typename T>
  T FPAdd(T op1, T op2);

  template <typename T>
  T FPDiv(T op1, T op2);

  template <typename T>
  T FPMax(T a, T b);

  template <typename T>
  T FPMaxNM(T a, T b);

  template <typename T>
  T FPMin(T a, T b);

  template <typename T>
  T FPMinNM(T a, T b);

  template <typename T>
  T FPMul(T op1, T op2);

  template <typename T>
  T FPMulx(T op1, T op2);

  template <typename T>
  T FPMulAdd(T a, T op1, T op2);

  template <typename T>
  T FPSqrt(T op);

  template <typename T>
  T FPSub(T op1, T op2);

  template <typename T>
  T FPRecipStepFused(T op1, T op2);

  template <typename T>
  T FPRSqrtStepFused(T op1, T op2);

  // This doesn't do anything at the moment. We'll need it if we want support
  // for cumulative exception bits or floating-point exceptions.
  void FPProcessException() {}

  // Standard NaN processing.
  bool FPProcessNaNs(Instruction* instr);

  void CheckStackAlignment();

  inline void CheckPCSComplianceAndRun();

#ifdef DEBUG
  // Corruption values should have their least significant byte cleared to
  // allow the code of the register being corrupted to be inserted.
  static const uint64_t kCallerSavedRegisterCorruptionValue =
      0xca11edc0de000000UL;
  // This value is a NaN in both 32-bit and 64-bit FP.
  static const uint64_t kCallerSavedVRegisterCorruptionValue =
      0x7ff000007f801000UL;
  // This value is a mix of 32/64-bits NaN and "verbose" immediate.
  static const uint64_t kDefaultCPURegisterCorruptionValue =
      0x7ffbad007f8bad00UL;

  void CorruptRegisters(CPURegList* list,
                        uint64_t value = kDefaultCPURegisterCorruptionValue);
  void CorruptAllCallerSavedCPURegisters();
#endif

  // Pseudo Printf instruction
  void DoPrintf(Instruction* instr);

  // Pseudo instruction for switching stack limit
  void DoSwitchStackLimit(Instruction* instr);

  // Processor state ---------------------------------------

  // Output stream.
  FILE* stream_;
  PrintDisassembler* print_disasm_;
  void PRINTF_FORMAT(2, 3) TraceSim(const char* format, ...);

  // General purpose registers. Register 31 is the stack pointer.
  SimRegister registers_[kNumberOfRegisters];

  // Floating point registers
  SimVRegister vregisters_[kNumberOfVRegisters];

  // Processor state
  // bits[31, 27]: Condition flags N, Z, C, and V.
  //               (Negative, Zero, Carry, Overflow)
  SimSystemRegister nzcv_;

  // Floating-Point Control Register
  SimSystemRegister fpcr_;

  // Only a subset of FPCR features are supported by the simulator. This helper
  // checks that the FPCR settings are supported.
  //
  // This is checked when floating-point instructions are executed, not when
  // FPCR is set. This allows generated
"""


```