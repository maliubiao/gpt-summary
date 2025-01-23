Response:
The user is asking for a summary of the functionalities provided by the C++ header file `v8/src/codegen/arm64/macro-assembler-arm64.h`.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the file type:** The file ends with `.h`, which indicates it's a C++ header file. The prompt explicitly states it's *not* a `.tq` (Torque) file.

2. **Recognize the core purpose:** The name "macro-assembler" strongly suggests its purpose is to provide a higher-level interface for generating ARM64 assembly code. It's built on top of a lower-level "assembler".

3. **Scan the header file for key features:** Look for:
    * Includes: These reveal dependencies and related functionalities. `assembler-arm64.h` is the base assembler.
    * Macros (`#define`): These often define shorthand notations for assembly instructions or common patterns. The file contains several `*_MACRO_LIST` macros, suggesting it's systematically defining wrappers for various ARM64 instructions.
    * Class definition (`class MacroAssembler`): This is the central class providing the interface.
    * Public methods of `MacroAssembler`: These represent the actions the macro assembler can perform.

4. **Group functionalities based on keywords and patterns:** As I scan the methods, I'll notice recurring patterns:
    * `Mov`: Moving data between registers and memory.
    * `Ldr`, `Str`, `Ldp`, `Stp`: Load and store instructions (single and pairs).
    * Atomic operations (`Ldar`, `Stlr`, `Cas`, `ldadd`, etc.).
    * NEON instructions (prefixed with `f`, `s`, `u`, etc., and often involving `VRegister`).
    * Branching instructions (`B`, `Tbnz`, `Cbz`).
    * Stack manipulation (`EnterFrame`, `LeaveFrame`, `Claim`, `Drop`, `PushArgument`).
    * Logical and arithmetic operations (`Add`, `Sub`, `And`, `Orr`, `Eor`, `Cmp`).
    * Assertions and debugging aids (`Assert`, `Check`, `DebugBreak`, `Printf`).
    * Control-flow integrity features (`CodeEntry`, `ExceptionHandler`, `JumpTarget`, `CallTarget`).

5. **Formulate initial functional categories:** Based on the grouped functionalities, I can create initial categories like:
    * Data movement
    * Arithmetic and logical operations
    * Memory access
    * Control flow
    * Stack management
    * Floating-point/NEON operations
    * Atomic operations
    * Debugging and assertions
    * Control-flow integrity

6. **Refine and elaborate on the categories:** Go back through the code and add more detail to each category. For example, within "Data movement," specify that it handles registers, immediates, external references, and tagged Smis. For "Memory access," highlight different load/store sizes and atomic variants.

7. **Address specific prompt questions:**
    * **Torque:** Explicitly state it's not a Torque file.
    * **JavaScript relation:** Explain that it's used by V8 to generate machine code for JavaScript execution. Provide a simple JavaScript example and show how the macro assembler would be involved (conceptually, as the C++ code doesn't directly map to the JS example).
    * **Code logic推理 (Reasoning):**  Choose a simple example like `Add` and illustrate how it takes input registers and produces an output register. Mention the flags update aspect.
    * **User programming errors:**  Consider common assembly-level errors, such as incorrect register usage, stack corruption (though this is somewhat mitigated by the macro assembler's higher level), and issues with conditional branches.

8. **Summarize the overall function:**  Provide a concise summary stating the header file's role in providing an abstraction for generating ARM64 code within the V8 engine.

9. **Organize the answer:**  Present the information clearly, using headings and bullet points for readability. Start with the general purpose and then delve into specific functionalities. Address each part of the prompt systematically.

10. **Review and refine:** Read through the generated answer to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas where more explanation might be needed. For instance, initially, I might just say "memory access," but refining it to "loading and storing data from memory" with examples like `Ldr` and `Str` is more informative. Also, adding details about the different load/store sizes (byte, half-word, word, double-word) improves accuracy. Similarly, clarifying the role of the `*_MACRO_LIST` definitions is beneficial.
```cpp
// Copyright 2013 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INCLUDED_FROM_MACRO_ASSEMBLER_H
#error This header must be included via macro-assembler.h
#endif

#ifndef V8_CODEGEN_ARM64_MACRO_ASSEMBLER_ARM64_H_
#define V8_CODEGEN_ARM64_MACRO_ASSEMBLER_ARM64_H_

#include <optional>

#include "src/base/bits.h"
#include "src/codegen/arm64/assembler-arm64.h"
#include "src/codegen/bailout-reason.h"
#include "src/common/globals.h"
#include "src/objects/tagged-index.h"

// Simulator specific helpers.
#if USE_SIMULATOR
#if DEBUG
#define ASM_LOCATION(message) __ Debug("LOCATION: " message, __LINE__, NO_PARAM)
#define ASM_LOCATION_IN_ASSEMBLER(message) \
  Debug("LOCATION: " message, __LINE__, NO_PARAM)
#else
#define ASM_LOCATION(message)
#define ASM_LOCATION_IN_ASSEMBLER(message)
#endif
#else
#define ASM_LOCATION(message)
#define ASM_LOCATION_IN_ASSEMBLER(message)
#endif

namespace v8 {
namespace internal {

namespace wasm {
class JumpTableAssembler;
}

#define LS_MACRO_LIST(V)                                     \
  V(Ldrb, Register&, rt, LDRB_w)                             \
  V(Strb, Register&, rt, STRB_w)                             \
  V(Ldrsb, Register&, rt, rt.Is64Bits() ? LDRSB_x : LDRSB_w) \
  V(Ldrh, Register&, rt, LDRH_w)                             \
  V(Strh, Register&, rt, STRH_w)                             \
  V(Ldrsh, Register&, rt, rt.Is64Bits() ? LDRSH_x : LDRSH_w) \
  V(Ldr, CPURegister&, rt, LoadOpFor(rt))                    \
  V(Str, CPURegister&, rt, StoreOpFor(rt))                   \
  V(Ldrsw, Register&, rt, LDRSW_x)

#define LSPAIR_MACRO_LIST(V)                             \
  V(Ldp, CPURegister&, rt, rt2, LoadPairOpFor(rt, rt2))  \
  V(Stp, CPURegister&, rt, rt2, StorePairOpFor(rt, rt2)) \
  V(Ldpsw, CPURegister&, rt, rt2, LDPSW_x)

#define LDA_STL_MACRO_LIST(V) \
  V(Ldarb, ldarb)             \
  V(Ldarh, ldarh)             \
  V(Ldar, ldar)               \
  V(Ldaxrb, ldaxrb)           \
  V(Ldaxrh, ldaxrh)           \
  V(Ldaxr, ldaxr)             \
  V(Stlrb, stlrb)             \
  V(Stlrh, stlrh)             \
  V(Stlr, stlr)

#define STLX_MACRO_LIST(V) \
  V(Stlxrb, stlxrb)        \
  V(Stlxrh, stlxrh)        \
  V(Stlxr, stlxr)

#define CAS_SINGLE_MACRO_LIST(V) \
  V(Cas, cas)                    \
  V(Casa, casa)                  \
  V(Casl, casl)                  \
  V(Casal, casal)                \
  V(Casb, casb)                  \
  V(Casab, casab)                \
  V(Caslb, caslb)                \
  V(Casalb, casalb)              \
  V(Cash, cash)                  \
  V(Casah, casah)                \
  V(Caslh, caslh)                \
  V(Casalh, casalh)

#define CAS_PAIR_MACRO_LIST(V) \
  V(Casp, casp)                \
  V(Caspa, caspa)              \
  V(Caspl, caspl)              \
  V(Caspal, caspal)

// These macros generate all the variations of the atomic memory operations,
// e.g. ldadd, ldadda, ldaddb, staddl, etc.

#define ATOMIC_MEMORY_SIMPLE_MACRO_LIST(V, DEF, MASM_PRE, ASM_PRE) \
  V(DEF, MASM_PRE##add, ASM_PRE##add)                              \
  V(DEF, MASM_PRE##clr, ASM_PRE##clr)                              \
  V(DEF, MASM_PRE##eor, ASM_PRE##eor)                              \
  V(DEF, MASM_PRE##set, ASM_PRE##set)                              \
  V(DEF, MASM_PRE##smax, ASM_PRE##smax)                            \
  V(DEF, MASM_PRE##smin, ASM_PRE##smin)                            \
  V(DEF, MASM_PRE##umax, ASM_PRE##umax)                            \
  V(DEF, MASM_PRE##umin, ASM_PRE##umin)

#define ATOMIC_MEMORY_STORE_MACRO_MODES(V, MASM, ASM) \
  V(MASM, ASM)                                        \
  V(MASM##l, ASM##l)                                  \
  V(MASM##b, ASM##b)                                  \
  V(MASM##lb, ASM##lb)                                \
  V(MASM##h, ASM##h)                                  \
  V(MASM##lh, ASM##lh)

#define ATOMIC_MEMORY_LOAD_MACRO_MODES(V, MASM, ASM) \
  ATOMIC_MEMORY_STORE_MACRO_MODES(V, MASM, ASM)      \
  V(MASM##a, ASM##a)                                 \
  V(MASM##al, ASM##al)                               \
  V(MASM##ab, ASM##ab)                               \
  V(MASM##alb, ASM##alb)                             \
  V(MASM##ah, ASM##ah)                               \
  V(MASM##alh, ASM##alh)

// ----------------------------------------------------------------------------
// Static helper functions

// Generate a MemOperand for loading a field from an object.
inline MemOperand FieldMemOperand(Register object, int offset);

// ----------------------------------------------------------------------------
// MacroAssembler

enum BranchType {
  // Copies of architectural conditions.
  // The associated conditions can be used in place of those, the code will
  // take care of reinterpreting them with the correct type.
  integer_eq = eq,
  integer_ne = ne,
  integer_hs = hs,
  integer_lo = lo,
  integer_mi = mi,
  integer_pl = pl,
  integer_vs = vs,
  integer_vc = vc,
  integer_hi = hi,
  integer_ls = ls,
  integer_ge = ge,
  integer_lt = lt,
  integer_gt = gt,
  integer_le = le,
  integer_al = al,
  integer_nv = nv,

  // These two are *different* from the architectural codes al and nv.
  // 'always' is used to generate unconditional branches.
  // 'never' is used to not generate a branch (generally as the inverse
  // branch type of 'always).
  always,
  never,
  // cbz and cbnz
  reg_zero,
  reg_not_zero,
  // tbz and tbnz
  reg_bit_clear,
  reg_bit_set,

  // Aliases.
  kBranchTypeFirstCondition = eq,
  kBranchTypeLastCondition = nv,
  kBranchTypeFirstUsingReg = reg_zero,
  kBranchTypeFirstUsingBit = reg_bit_clear
};

inline BranchType InvertBranchType(BranchType type) {
  if (kBranchTypeFirstCondition <= type && type <= kBranchTypeLastCondition) {
    return static_cast<BranchType>(
        NegateCondition(static_cast<Condition>(type)));
  } else {
    return static_cast<BranchType>(type ^ 1);
  }
}

enum LinkRegisterStatus { kLRHasNotBeenSaved, kLRHasBeenSaved };
enum DiscardMoveMode { kDontDiscardForSameWReg, kDiscardForSameWReg };

// The macro assembler supports moving automatically pre-shifted immediates for
// arithmetic and logical instructions, and then applying a post shift in the
// instruction to undo the modification, in order to reduce the code emitted for
// an operation. For example:
//
//  Add(x0, x0, 0x1f7de) => movz x16, 0xfbef; add x0, x0, x16, lsl #1.
//
// This optimisation can be only partially applied when the stack pointer is an
// operand or destination, so this enumeration is used to control the shift.
enum PreShiftImmMode {
  kNoShift,          // Don't pre-shift.
  kLimitShiftForSP,  // Limit pre-shift for add/sub extend use.
  kAnyShift          // Allow any pre-shift.
};

// TODO(victorgomes): Move definition to macro-assembler.h, once all other
// platforms are updated.
enum class StackLimitKind { kInterruptStackLimit, kRealStackLimit };

class V8_EXPORT_PRIVATE MacroAssembler : public MacroAssemblerBase {
 public:
  using MacroAssemblerBase::MacroAssemblerBase;

#if DEBUG
  void set_allow_macro_instructions(bool value) {
    allow_macro_instructions_ = value;
  }
  bool allow_macro_instructions() const { return allow_macro_instructions_; }
#endif

  // We should not use near calls or jumps for calls to external references,
  // since the code spaces are not guaranteed to be close to each other.
  bool CanUseNearCallOrJump(RelocInfo::Mode rmode) {
    return rmode != RelocInfo::EXTERNAL_REFERENCE;
  }

  static bool IsNearCallOffset(int64_t offset);

  // Activation support.
  void EnterFrame(StackFrame::Type type);
  void EnterFrame(StackFrame::Type type, bool load_constant_pool_pointer_reg) {
    // Out-of-line constant pool not implemented on arm64.
    UNREACHABLE();
  }
  void LeaveFrame(StackFrame::Type type);

  inline void InitializeRootRegister();

  void Mov(const Register& rd, const Operand& operand,
           DiscardMoveMode discard_mode = kDontDiscardForSameWReg);
  void Mov(const Register& rd, uint64_t imm);
  void Mov(const Register& rd, ExternalReference reference);
  void LoadIsolateField(const Register& rd, IsolateFieldId id);
  void Mov(const VRegister& vd, int vd_index, const VRegister& vn,
           int vn_index) {
    DCHECK(allow_macro_instructions());
    mov(vd, vd_index, vn, vn_index);
  }
  void Mov(const Register& rd, Tagged<Smi> smi);
  void Mov(const VRegister& vd, const VRegister& vn, int index) {
    DCHECK(allow_macro_instructions());
    mov(vd, vn, index);
  }
  void Mov(const VRegister& vd, int vd_index, const Register& rn) {
    DCHECK(allow_macro_instructions());
    mov(vd, vd_index, rn);
  }
  void Mov(const Register& rd, const VRegister& vn, int vn_index) {
    DCHECK(allow_macro_instructions());
    mov(rd, vn, vn_index);
  }

  // These are required for compatibility with architecture independent code.
  // Remove if not needed.
  void Move(Register dst, Tagged<Smi> src);
  void Move(Register dst, MemOperand src);
  void Move(Register dst, Register src);

  // Move src0 to dst0 and src1 to dst1, handling possible overlaps.
  void MovePair(Register dst0, Register src0, Register dst1, Register src1);

  // Register swap. Note that the register operands should be distinct.
  void Swap(Register lhs, Register rhs);
  void Swap(VRegister lhs, VRegister rhs);

// NEON by element instructions.
#define NEON_BYELEMENT_MACRO_LIST(V) \
  V(fmla, Fmla)                      \
  V(fmls, Fmls)                      \
  V(fmul, Fmul)                      \
  V(fmulx, Fmulx)                    \
  V(mul, Mul)                        \
  V(mla, Mla)                        \
  V(mls, Mls)                        \
  V(sqdmulh, Sqdmulh)                \
  V(sqrdmulh, Sqrdmulh)              \
  V(sqdmull, Sqdmull)                \
  V(sqdmull2, Sqdmull2)              \
  V(sqdmlal, Sqdmlal)                \
  V(sqdmlal2, Sqdmlal2)              \
  V(sqdmlsl, Sqdmlsl)                \
  V(sqdmlsl2, Sqdmlsl2)              \
  V(smull, Smull)                    \
  V(smull2, Smull2)                  \
  V(smlal, Smlal)                    \
  V(smlal2, Smlal2)                  \
  V(smlsl, Smlsl)                    \
  V(smlsl2, Smlsl2)                  \
  V(umull, Umull)                    \
  V(umull2, Umull2)                  \
  V(umlal, Umlal)                    \
  V(umlal2, Umlal2)                  \
  V(umlsl, Umlsl)                    \
  V(umlsl2, Umlsl2)

#define DEFINE_MACRO_ASM_FUNC(ASM, MASM)                                   \
  void MASM(const VRegister& vd, const VRegister& vn, const VRegister& vm, \
            int vm_index) {                                                \
    DCHECK(allow_macro_instructions());                                    \
    ASM(vd, vn, vm, vm_index);                                             \
  }
  NEON_BYELEMENT_MACRO_LIST(DEFINE_MACRO_ASM_FUNC)
#undef DEFINE_MACRO_ASM_FUNC

// NEON 2 vector register instructions.
#define NEON_2VREG_MACRO_LIST(V) \
  V(abs, Abs)                    \
  V(addp, Addp)                  \
  V(addv, Addv)                  \
  V(cls, Cls)                    \
  V(clz, Clz)                    \
  V(cnt, Cnt)                    \
  V(faddp, Faddp)                \
  V(fcvtas, Fcvtas)              \
  V(fcvtau, Fcvtau)              \
  V(fcvtl, Fcvtl)                \
  V(fcvtms, Fcvtms)              \
  V(fcvtmu, Fcvtmu)              \
  V(fcvtn, Fcvtn)                \
  V(fcvtns, Fcvtns)              \
  V(fcvtnu, Fcvtnu)              \
  V(fcvtps, Fcvtps)              \
  V(fcvtpu, Fcvtpu)              \
  V(fmaxnmp, Fmaxnmp)            \
  V(fmaxnmv, Fmaxnmv)            \
  V(fmaxp, Fmaxp)                \
  V(fmaxv, Fmaxv)                \
  V(fminnmp, Fminnmp)            \
  V(fminnmv, Fminnmv)            \
  V(fminp, Fminp)                \
  V(fminv, Fminv)                \
  V(fneg, Fneg)                  \
  V(frecpe, Frecpe)              \
  V(frecpx, Freecpx)              \
  V(frinta, Frinta)              \
  V(frinti, Frinti)              \
  V(frintm, Frintm)              \
  V(frintn, Frintn)              \
  V(frintp, Frintp)              \
  V(frintx, Frintx)              \
  V(frintz, Frintz)              \
  V(frsqrte, Frsqrte)            \
  V(fsqrt, Fsqrt)                \
  V(mov, Mov)                    \
  V(mvn, Mvn)                    \
  V(neg, Neg)                    \
  V(not_, Not)                   \
  V(rbit, Rbit)                  \
  V(rev16, Rev16)                \
  V(rev32, Rev32)                \
  V(rev64, Rev64)                \
  V(sadalp, Sadalp)              \
  V(saddlp, Saddlp)              \
  V(saddlv, Saddlv)              \
  V(smaxv, Smaxv)                \
  V(sminv, Sminv)                \
  V(sqabs, Sqabs)                \
  V(sqneg, Sqneg)                \
  V(sqxtn2, Sqxtn2)              \
  V(sqxtn, Sqxtn)                \
  V(sqxtun2, Sqxtun2)            \
  V(sqxtun, Sqxtun)              \
  V(suqadd, Suqadd)              \
  V(sxtl2, Sxtl2)                \
  V(sxtl, Sxtl)                  \
  V(uadalp, Uadalp)              \
  V(uaddlp, Uaddlp)              \
  V(uaddlv, Uaddlv)              \
  V(umaxv, Umaxv)                \
  V(uminv, Uminv)                \
  V(uqxtn2, Uqxtn2)              \
  V(uqxtn, Uqxtn)                \
  V(urecpe, Urecpe)              \
  V(ursqrte, Ursqrte)            \
  V(usqadd, Usqadd)              \
  V(uxtl2, Uxtl2)                \
  V(uxtl, Uxtl)                  \
  V(xtn2, Xtn2)                  \
  V(xtn, Xtn)

#define DEFINE_MACRO_ASM_FUNC(ASM, MASM)                \
  void MASM(const VRegister& vd, const VRegister& vn) { \
    DCHECK(allow_macro_instructions());                 \
    ASM(vd, vn);                                        \
  }
  NEON_2VREG_MACRO_LIST(DEFINE_MACRO_ASM_FUNC)
#undef DEFINE_MACRO_ASM_FUNC
#undef NEON_2VREG_MACRO_LIST

// NEON 2 vector register with immediate instructions.
#define NEON_2VREG_FPIMM_MACRO_LIST(V) \
  V(fcmeq, Fcmeq)                      \
  V(fcmge, Fcmge)                      \
  V(fcmgt, Fcmgt)                      \
  V(fcmle, Fcmle)                      \
  V(fcmlt, Fcmlt)

#define DEFINE_MACRO_ASM_FUNC(ASM, MASM)                            \
  void MASM(const VRegister& vd, const VRegister& vn, double imm) { \
    DCHECK(allow_macro_instructions());                             \
    ASM(vd, vn, imm);                                               \
  }
  NEON_2VREG_FPIMM_MACRO_LIST(DEFINE_MACRO_ASM_FUNC)
#undef DEFINE_MACRO_ASM_FUNC

// NEON 3 vector register instructions.
#define NEON_3VREG_MACRO_LIST(V) \
  V(add, Add)                    \
  V(addhn2, Addhn2)              \
  V(addhn, Addhn)                \
  V(addp, Addp)                  \
  V(and_, And)                   \
  V(bic, Bic)                    \
  V(bif, Bif)                    \
  V(bit, Bit)                    \
  V(bsl, Bsl)                    \
  V(cmeq, Cmeq)                  \
  V(cmge, Cmge)                  \
  V(cmgt, Cmgt)                  \
  V(cmhi, Cmhi)                  \
  V(cmhs, Cmhs)                  \
  V(cmtst, Cmtst)                \
  V(eor, Eor)                    \
  V(fabd, Fabd)                  \
  V(facge, Facge)                \
  V(facgt, Facgt)                \
  V(faddp, Faddp)                \
  V(fcmeq, Fcmeq)                \
  V(fcmge, Fcmge)                \
  V(fcmgt, Fcmgt)                \
  V(fmaxnmp, Fmaxnmp)            \
  V(fmaxp, Fmaxp)                \
  V(fminnmp, Fminnmp)            \
  V(fminp, Fminp)                \
  V(fmla, Fmla)                  \
  V(fmls, Fmls)                  \
  V(fmulx, Fmulx)                \
  V(fnmul, Fnmul)                \
  V(frecps, Frecps)              \
  V(frsqrts, Frsqrts)            \
  V(mla, Mla)                    \
  V(mls, Mls)                    \
  V(mul, Mul)                    \
  V(orn, Orn)                    \
  V(orr, Orr)                    \
  V(pmull2, Pmull2)              \
  V(pmull, Pmull)                \
  V(pmul, Pmul)                  \
  V(raddhn2, Raddhn2)            \
  V(raddhn, Raddhn)              \
  V(rsubhn2, Rsubhn2)            \
  V(rsubhn, Rsubhn)              \
  V(sabal2, Sabal2)              \
  V(sabal, Sabal)                \
  V(saba, Saba)                  \
  V(sabdl2, Sabdl2)              \
  V(sabdl, Sabdl)                \
  V(sabd, Sabd)                  \
  V(saddl2, Saddl2)              \
  V(saddl, Saddl)                \
  V(saddw2, Saddw2)              \
  V(saddw, Saddw)                \
  V(sdot, Sdot)                  \
  V(shadd, Shadd)                \
  V(shsub, Shsub)                \
  V(smaxp, Smaxp)                \
  V(smax, Smax)                  \
  V(sminp, Sminp)                \
  V(smin, Smin)                  \
  V(smlal2, Smlal2)              \
  V(smlal, Smlal)                \
  V(smlsl2, Smlsl2)              \
  V(smlsl, Smlsl)                \
  V(smull2, Smull2)              \
  V(smull, Smull)                \
  V(sqadd, Sqadd)                \
  V(sqdmlal2, Sqdmlal2)          \
  V(sqdmlal, Sqdmlal)            \
  V(sqdmlsl2, Sqdmlsl2)          \
  V(sqdmlsl, Sqdmlsl)            \
  V(sqdmulh, Sqdmulh)            \
  V(sqdmull2, Sqdmull2)          \
  V(sqdmull, Sqdmull)            \
  V(sqrdmulh, Sqrdmulh)          \
  V(sqrshl, Sqrshl)              \
  V(sqshl, Sqshl)                \
  V(sqsub, Sqsub)                \
  V(srhadd, Srhadd)              \
  V(srshl, Srshl)                \
  V(sshl, Sshl)                  \
  V(ssubl2, Ssubl2)              \
  V(ssubl, Ssubl)                \
  V(ssubw2, Ssubw2)              \
  V(ssubw, Ssubw)                \
  V(subhn2, Subhn2)              \
  V(subhn, Subhn)                \
  V(sub, Sub)                    \
  V(trn1, Trn1)                  \
  V(trn2, Trn2)                  \
  V(uabal2, Uabal2)              \
  V(uabal, Uabal)                \
  V(uaba, Uaba)                  \
  V(uabdl2, Uabdl2)              \
  V(uabdl, Uabdl)                \
  V(uabd, Uabd)                  \
  V(uaddl2, Uaddl2)              \
  V(uaddl, Uaddl)                \
  V(uaddw2, Uaddw2)              \
  V(uaddw, Uaddw)                \
  V(uhadd, Uhadd)                \
  V(uhsub, Uhsub)                \
  V(umaxp, Umaxp)                \
  V(umax, Umax)                  \
  V(uminp, Uminp)                \
  V(umin, Umin)                  \
  V(umlal2, Umlal2)              \
  V(umlal, Umlal)                \
  V(umlsl2, Umlsl2)              \
  V(umlsl, Umlsl)                \
  V(umull2, Umull2)              \
  V(umull, Umull)                \
  V(uqadd, Uqadd)                \
  V(uqrshl, Uqrshl)              \
  V(uqshl, Uqshl)                \
  V(uqsub, Uqsub)                \
  V(urhadd, Urhadd)              \
  V(urshl, Urshl)                \
  V(ushl, Ushl)                  \
  V(usubl2, Usubl2)              \
  V(usubl, Usubl)                \
  V(usubw2, Usubw2)              \
  V(usubw, Usubw)                \
  V(uzp1, Uzp1)                  \
  V(uzp2, Uzp2)                  \
  V(zip1, Zip1)                  \
  V(zip2, Zip2)

#define DEFINE_MACRO_ASM_FUNC(ASM, MASM)                                     \
  void MASM(const VRegister& vd, const VRegister& vn, const VRegister& vm) { \
    DCHECK(allow_macro_instructions());                                      \
    ASM(vd, vn, vm);                                                         \
  }
  NEON_3VREG_MACRO_LIST(DEFINE_MACRO_ASM_FUNC)
#undef DEFINE_MACRO_ASM_FUNC

  void Bic(const VRegister& vd, const int imm8, const int left_shift = 0) {
    DCHECK(allow_macro_instructions());
    bic(vd, imm8, left_shift);
  }

  // This is required for compatibility in architecture independent code.
  inline void jmp(Label* L);

  void B(Label* label, BranchType type, Register reg = NoReg, int bit = -1);
  inline void B(Label* label);
  inline void B(Condition cond, Label* label);
  void B(Label* label, Condition cond);

  void Tbnz(const Register& rt, unsigned bit_pos, Label* label);
  void Tbz(const Register& rt, unsigned bit_pos, Label* label);

  void Cbnz(const Register& rt, Label* label);
  void Cbz(const Register& rt, Label* label);

  void Pacibsp() {
    DCHECK(allow_macro_instructions_);
    pacibsp();
  }
  void Autibsp() {
    DCHECK(allow_macro_instructions_);
    autibsp();
  }

  // The 1716 pac and aut instructions encourage people to use x16 and x17
  // directly, perhaps without realising that this is forbidden. For example:
  //
  //     UseScratchRegisterScope temps(&masm);
  //     Register temp = temps.AcquireX();  // temp will be x16
  //     __ Mov(x17, ptr);
  //     __ Mov(x16, modifier);  // Will override temp!
  //     __
### 提示词
```
这是目录为v8/src/codegen/arm64/macro-assembler-arm64.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/arm64/macro-assembler-arm64.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2013 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INCLUDED_FROM_MACRO_ASSEMBLER_H
#error This header must be included via macro-assembler.h
#endif

#ifndef V8_CODEGEN_ARM64_MACRO_ASSEMBLER_ARM64_H_
#define V8_CODEGEN_ARM64_MACRO_ASSEMBLER_ARM64_H_

#include <optional>

#include "src/base/bits.h"
#include "src/codegen/arm64/assembler-arm64.h"
#include "src/codegen/bailout-reason.h"
#include "src/common/globals.h"
#include "src/objects/tagged-index.h"

// Simulator specific helpers.
#if USE_SIMULATOR
#if DEBUG
#define ASM_LOCATION(message) __ Debug("LOCATION: " message, __LINE__, NO_PARAM)
#define ASM_LOCATION_IN_ASSEMBLER(message) \
  Debug("LOCATION: " message, __LINE__, NO_PARAM)
#else
#define ASM_LOCATION(message)
#define ASM_LOCATION_IN_ASSEMBLER(message)
#endif
#else
#define ASM_LOCATION(message)
#define ASM_LOCATION_IN_ASSEMBLER(message)
#endif

namespace v8 {
namespace internal {

namespace wasm {
class JumpTableAssembler;
}

#define LS_MACRO_LIST(V)                                     \
  V(Ldrb, Register&, rt, LDRB_w)                             \
  V(Strb, Register&, rt, STRB_w)                             \
  V(Ldrsb, Register&, rt, rt.Is64Bits() ? LDRSB_x : LDRSB_w) \
  V(Ldrh, Register&, rt, LDRH_w)                             \
  V(Strh, Register&, rt, STRH_w)                             \
  V(Ldrsh, Register&, rt, rt.Is64Bits() ? LDRSH_x : LDRSH_w) \
  V(Ldr, CPURegister&, rt, LoadOpFor(rt))                    \
  V(Str, CPURegister&, rt, StoreOpFor(rt))                   \
  V(Ldrsw, Register&, rt, LDRSW_x)

#define LSPAIR_MACRO_LIST(V)                             \
  V(Ldp, CPURegister&, rt, rt2, LoadPairOpFor(rt, rt2))  \
  V(Stp, CPURegister&, rt, rt2, StorePairOpFor(rt, rt2)) \
  V(Ldpsw, CPURegister&, rt, rt2, LDPSW_x)

#define LDA_STL_MACRO_LIST(V) \
  V(Ldarb, ldarb)             \
  V(Ldarh, ldarh)             \
  V(Ldar, ldar)               \
  V(Ldaxrb, ldaxrb)           \
  V(Ldaxrh, ldaxrh)           \
  V(Ldaxr, ldaxr)             \
  V(Stlrb, stlrb)             \
  V(Stlrh, stlrh)             \
  V(Stlr, stlr)

#define STLX_MACRO_LIST(V) \
  V(Stlxrb, stlxrb)        \
  V(Stlxrh, stlxrh)        \
  V(Stlxr, stlxr)

#define CAS_SINGLE_MACRO_LIST(V) \
  V(Cas, cas)                    \
  V(Casa, casa)                  \
  V(Casl, casl)                  \
  V(Casal, casal)                \
  V(Casb, casb)                  \
  V(Casab, casab)                \
  V(Caslb, caslb)                \
  V(Casalb, casalb)              \
  V(Cash, cash)                  \
  V(Casah, casah)                \
  V(Caslh, caslh)                \
  V(Casalh, casalh)

#define CAS_PAIR_MACRO_LIST(V) \
  V(Casp, casp)                \
  V(Caspa, caspa)              \
  V(Caspl, caspl)              \
  V(Caspal, caspal)

// These macros generate all the variations of the atomic memory operations,
// e.g. ldadd, ldadda, ldaddb, staddl, etc.

#define ATOMIC_MEMORY_SIMPLE_MACRO_LIST(V, DEF, MASM_PRE, ASM_PRE) \
  V(DEF, MASM_PRE##add, ASM_PRE##add)                              \
  V(DEF, MASM_PRE##clr, ASM_PRE##clr)                              \
  V(DEF, MASM_PRE##eor, ASM_PRE##eor)                              \
  V(DEF, MASM_PRE##set, ASM_PRE##set)                              \
  V(DEF, MASM_PRE##smax, ASM_PRE##smax)                            \
  V(DEF, MASM_PRE##smin, ASM_PRE##smin)                            \
  V(DEF, MASM_PRE##umax, ASM_PRE##umax)                            \
  V(DEF, MASM_PRE##umin, ASM_PRE##umin)

#define ATOMIC_MEMORY_STORE_MACRO_MODES(V, MASM, ASM) \
  V(MASM, ASM)                                        \
  V(MASM##l, ASM##l)                                  \
  V(MASM##b, ASM##b)                                  \
  V(MASM##lb, ASM##lb)                                \
  V(MASM##h, ASM##h)                                  \
  V(MASM##lh, ASM##lh)

#define ATOMIC_MEMORY_LOAD_MACRO_MODES(V, MASM, ASM) \
  ATOMIC_MEMORY_STORE_MACRO_MODES(V, MASM, ASM)      \
  V(MASM##a, ASM##a)                                 \
  V(MASM##al, ASM##al)                               \
  V(MASM##ab, ASM##ab)                               \
  V(MASM##alb, ASM##alb)                             \
  V(MASM##ah, ASM##ah)                               \
  V(MASM##alh, ASM##alh)

// ----------------------------------------------------------------------------
// Static helper functions

// Generate a MemOperand for loading a field from an object.
inline MemOperand FieldMemOperand(Register object, int offset);

// ----------------------------------------------------------------------------
// MacroAssembler

enum BranchType {
  // Copies of architectural conditions.
  // The associated conditions can be used in place of those, the code will
  // take care of reinterpreting them with the correct type.
  integer_eq = eq,
  integer_ne = ne,
  integer_hs = hs,
  integer_lo = lo,
  integer_mi = mi,
  integer_pl = pl,
  integer_vs = vs,
  integer_vc = vc,
  integer_hi = hi,
  integer_ls = ls,
  integer_ge = ge,
  integer_lt = lt,
  integer_gt = gt,
  integer_le = le,
  integer_al = al,
  integer_nv = nv,

  // These two are *different* from the architectural codes al and nv.
  // 'always' is used to generate unconditional branches.
  // 'never' is used to not generate a branch (generally as the inverse
  // branch type of 'always).
  always,
  never,
  // cbz and cbnz
  reg_zero,
  reg_not_zero,
  // tbz and tbnz
  reg_bit_clear,
  reg_bit_set,

  // Aliases.
  kBranchTypeFirstCondition = eq,
  kBranchTypeLastCondition = nv,
  kBranchTypeFirstUsingReg = reg_zero,
  kBranchTypeFirstUsingBit = reg_bit_clear
};

inline BranchType InvertBranchType(BranchType type) {
  if (kBranchTypeFirstCondition <= type && type <= kBranchTypeLastCondition) {
    return static_cast<BranchType>(
        NegateCondition(static_cast<Condition>(type)));
  } else {
    return static_cast<BranchType>(type ^ 1);
  }
}

enum LinkRegisterStatus { kLRHasNotBeenSaved, kLRHasBeenSaved };
enum DiscardMoveMode { kDontDiscardForSameWReg, kDiscardForSameWReg };

// The macro assembler supports moving automatically pre-shifted immediates for
// arithmetic and logical instructions, and then applying a post shift in the
// instruction to undo the modification, in order to reduce the code emitted for
// an operation. For example:
//
//  Add(x0, x0, 0x1f7de) => movz x16, 0xfbef; add x0, x0, x16, lsl #1.
//
// This optimisation can be only partially applied when the stack pointer is an
// operand or destination, so this enumeration is used to control the shift.
enum PreShiftImmMode {
  kNoShift,          // Don't pre-shift.
  kLimitShiftForSP,  // Limit pre-shift for add/sub extend use.
  kAnyShift          // Allow any pre-shift.
};

// TODO(victorgomes): Move definition to macro-assembler.h, once all other
// platforms are updated.
enum class StackLimitKind { kInterruptStackLimit, kRealStackLimit };

class V8_EXPORT_PRIVATE MacroAssembler : public MacroAssemblerBase {
 public:
  using MacroAssemblerBase::MacroAssemblerBase;

#if DEBUG
  void set_allow_macro_instructions(bool value) {
    allow_macro_instructions_ = value;
  }
  bool allow_macro_instructions() const { return allow_macro_instructions_; }
#endif

  // We should not use near calls or jumps for calls to external references,
  // since the code spaces are not guaranteed to be close to each other.
  bool CanUseNearCallOrJump(RelocInfo::Mode rmode) {
    return rmode != RelocInfo::EXTERNAL_REFERENCE;
  }

  static bool IsNearCallOffset(int64_t offset);

  // Activation support.
  void EnterFrame(StackFrame::Type type);
  void EnterFrame(StackFrame::Type type, bool load_constant_pool_pointer_reg) {
    // Out-of-line constant pool not implemented on arm64.
    UNREACHABLE();
  }
  void LeaveFrame(StackFrame::Type type);

  inline void InitializeRootRegister();

  void Mov(const Register& rd, const Operand& operand,
           DiscardMoveMode discard_mode = kDontDiscardForSameWReg);
  void Mov(const Register& rd, uint64_t imm);
  void Mov(const Register& rd, ExternalReference reference);
  void LoadIsolateField(const Register& rd, IsolateFieldId id);
  void Mov(const VRegister& vd, int vd_index, const VRegister& vn,
           int vn_index) {
    DCHECK(allow_macro_instructions());
    mov(vd, vd_index, vn, vn_index);
  }
  void Mov(const Register& rd, Tagged<Smi> smi);
  void Mov(const VRegister& vd, const VRegister& vn, int index) {
    DCHECK(allow_macro_instructions());
    mov(vd, vn, index);
  }
  void Mov(const VRegister& vd, int vd_index, const Register& rn) {
    DCHECK(allow_macro_instructions());
    mov(vd, vd_index, rn);
  }
  void Mov(const Register& rd, const VRegister& vn, int vn_index) {
    DCHECK(allow_macro_instructions());
    mov(rd, vn, vn_index);
  }

  // These are required for compatibility with architecture independent code.
  // Remove if not needed.
  void Move(Register dst, Tagged<Smi> src);
  void Move(Register dst, MemOperand src);
  void Move(Register dst, Register src);

  // Move src0 to dst0 and src1 to dst1, handling possible overlaps.
  void MovePair(Register dst0, Register src0, Register dst1, Register src1);

  // Register swap. Note that the register operands should be distinct.
  void Swap(Register lhs, Register rhs);
  void Swap(VRegister lhs, VRegister rhs);

// NEON by element instructions.
#define NEON_BYELEMENT_MACRO_LIST(V) \
  V(fmla, Fmla)                      \
  V(fmls, Fmls)                      \
  V(fmul, Fmul)                      \
  V(fmulx, Fmulx)                    \
  V(mul, Mul)                        \
  V(mla, Mla)                        \
  V(mls, Mls)                        \
  V(sqdmulh, Sqdmulh)                \
  V(sqrdmulh, Sqrdmulh)              \
  V(sqdmull, Sqdmull)                \
  V(sqdmull2, Sqdmull2)              \
  V(sqdmlal, Sqdmlal)                \
  V(sqdmlal2, Sqdmlal2)              \
  V(sqdmlsl, Sqdmlsl)                \
  V(sqdmlsl2, Sqdmlsl2)              \
  V(smull, Smull)                    \
  V(smull2, Smull2)                  \
  V(smlal, Smlal)                    \
  V(smlal2, Smlal2)                  \
  V(smlsl, Smlsl)                    \
  V(smlsl2, Smlsl2)                  \
  V(umull, Umull)                    \
  V(umull2, Umull2)                  \
  V(umlal, Umlal)                    \
  V(umlal2, Umlal2)                  \
  V(umlsl, Umlsl)                    \
  V(umlsl2, Umlsl2)

#define DEFINE_MACRO_ASM_FUNC(ASM, MASM)                                   \
  void MASM(const VRegister& vd, const VRegister& vn, const VRegister& vm, \
            int vm_index) {                                                \
    DCHECK(allow_macro_instructions());                                    \
    ASM(vd, vn, vm, vm_index);                                             \
  }
  NEON_BYELEMENT_MACRO_LIST(DEFINE_MACRO_ASM_FUNC)
#undef DEFINE_MACRO_ASM_FUNC

// NEON 2 vector register instructions.
#define NEON_2VREG_MACRO_LIST(V) \
  V(abs, Abs)                    \
  V(addp, Addp)                  \
  V(addv, Addv)                  \
  V(cls, Cls)                    \
  V(clz, Clz)                    \
  V(cnt, Cnt)                    \
  V(faddp, Faddp)                \
  V(fcvtas, Fcvtas)              \
  V(fcvtau, Fcvtau)              \
  V(fcvtl, Fcvtl)                \
  V(fcvtms, Fcvtms)              \
  V(fcvtmu, Fcvtmu)              \
  V(fcvtn, Fcvtn)                \
  V(fcvtns, Fcvtns)              \
  V(fcvtnu, Fcvtnu)              \
  V(fcvtps, Fcvtps)              \
  V(fcvtpu, Fcvtpu)              \
  V(fmaxnmp, Fmaxnmp)            \
  V(fmaxnmv, Fmaxnmv)            \
  V(fmaxp, Fmaxp)                \
  V(fmaxv, Fmaxv)                \
  V(fminnmp, Fminnmp)            \
  V(fminnmv, Fminnmv)            \
  V(fminp, Fminp)                \
  V(fminv, Fminv)                \
  V(fneg, Fneg)                  \
  V(frecpe, Frecpe)              \
  V(frecpx, Frecpx)              \
  V(frinta, Frinta)              \
  V(frinti, Frinti)              \
  V(frintm, Frintm)              \
  V(frintn, Frintn)              \
  V(frintp, Frintp)              \
  V(frintx, Frintx)              \
  V(frintz, Frintz)              \
  V(frsqrte, Frsqrte)            \
  V(fsqrt, Fsqrt)                \
  V(mov, Mov)                    \
  V(mvn, Mvn)                    \
  V(neg, Neg)                    \
  V(not_, Not)                   \
  V(rbit, Rbit)                  \
  V(rev16, Rev16)                \
  V(rev32, Rev32)                \
  V(rev64, Rev64)                \
  V(sadalp, Sadalp)              \
  V(saddlp, Saddlp)              \
  V(saddlv, Saddlv)              \
  V(smaxv, Smaxv)                \
  V(sminv, Sminv)                \
  V(sqabs, Sqabs)                \
  V(sqneg, Sqneg)                \
  V(sqxtn2, Sqxtn2)              \
  V(sqxtn, Sqxtn)                \
  V(sqxtun2, Sqxtun2)            \
  V(sqxtun, Sqxtun)              \
  V(suqadd, Suqadd)              \
  V(sxtl2, Sxtl2)                \
  V(sxtl, Sxtl)                  \
  V(uadalp, Uadalp)              \
  V(uaddlp, Uaddlp)              \
  V(uaddlv, Uaddlv)              \
  V(umaxv, Umaxv)                \
  V(uminv, Uminv)                \
  V(uqxtn2, Uqxtn2)              \
  V(uqxtn, Uqxtn)                \
  V(urecpe, Urecpe)              \
  V(ursqrte, Ursqrte)            \
  V(usqadd, Usqadd)              \
  V(uxtl2, Uxtl2)                \
  V(uxtl, Uxtl)                  \
  V(xtn2, Xtn2)                  \
  V(xtn, Xtn)

#define DEFINE_MACRO_ASM_FUNC(ASM, MASM)                \
  void MASM(const VRegister& vd, const VRegister& vn) { \
    DCHECK(allow_macro_instructions());                 \
    ASM(vd, vn);                                        \
  }
  NEON_2VREG_MACRO_LIST(DEFINE_MACRO_ASM_FUNC)
#undef DEFINE_MACRO_ASM_FUNC
#undef NEON_2VREG_MACRO_LIST

// NEON 2 vector register with immediate instructions.
#define NEON_2VREG_FPIMM_MACRO_LIST(V) \
  V(fcmeq, Fcmeq)                      \
  V(fcmge, Fcmge)                      \
  V(fcmgt, Fcmgt)                      \
  V(fcmle, Fcmle)                      \
  V(fcmlt, Fcmlt)

#define DEFINE_MACRO_ASM_FUNC(ASM, MASM)                            \
  void MASM(const VRegister& vd, const VRegister& vn, double imm) { \
    DCHECK(allow_macro_instructions());                             \
    ASM(vd, vn, imm);                                               \
  }
  NEON_2VREG_FPIMM_MACRO_LIST(DEFINE_MACRO_ASM_FUNC)
#undef DEFINE_MACRO_ASM_FUNC

// NEON 3 vector register instructions.
#define NEON_3VREG_MACRO_LIST(V) \
  V(add, Add)                    \
  V(addhn2, Addhn2)              \
  V(addhn, Addhn)                \
  V(addp, Addp)                  \
  V(and_, And)                   \
  V(bic, Bic)                    \
  V(bif, Bif)                    \
  V(bit, Bit)                    \
  V(bsl, Bsl)                    \
  V(cmeq, Cmeq)                  \
  V(cmge, Cmge)                  \
  V(cmgt, Cmgt)                  \
  V(cmhi, Cmhi)                  \
  V(cmhs, Cmhs)                  \
  V(cmtst, Cmtst)                \
  V(eor, Eor)                    \
  V(fabd, Fabd)                  \
  V(facge, Facge)                \
  V(facgt, Facgt)                \
  V(faddp, Faddp)                \
  V(fcmeq, Fcmeq)                \
  V(fcmge, Fcmge)                \
  V(fcmgt, Fcmgt)                \
  V(fmaxnmp, Fmaxnmp)            \
  V(fmaxp, Fmaxp)                \
  V(fminnmp, Fminnmp)            \
  V(fminp, Fminp)                \
  V(fmla, Fmla)                  \
  V(fmls, Fmls)                  \
  V(fmulx, Fmulx)                \
  V(fnmul, Fnmul)                \
  V(frecps, Frecps)              \
  V(frsqrts, Frsqrts)            \
  V(mla, Mla)                    \
  V(mls, Mls)                    \
  V(mul, Mul)                    \
  V(orn, Orn)                    \
  V(orr, Orr)                    \
  V(pmull2, Pmull2)              \
  V(pmull, Pmull)                \
  V(pmul, Pmul)                  \
  V(raddhn2, Raddhn2)            \
  V(raddhn, Raddhn)              \
  V(rsubhn2, Rsubhn2)            \
  V(rsubhn, Rsubhn)              \
  V(sabal2, Sabal2)              \
  V(sabal, Sabal)                \
  V(saba, Saba)                  \
  V(sabdl2, Sabdl2)              \
  V(sabdl, Sabdl)                \
  V(sabd, Sabd)                  \
  V(saddl2, Saddl2)              \
  V(saddl, Saddl)                \
  V(saddw2, Saddw2)              \
  V(saddw, Saddw)                \
  V(sdot, Sdot)                  \
  V(shadd, Shadd)                \
  V(shsub, Shsub)                \
  V(smaxp, Smaxp)                \
  V(smax, Smax)                  \
  V(sminp, Sminp)                \
  V(smin, Smin)                  \
  V(smlal2, Smlal2)              \
  V(smlal, Smlal)                \
  V(smlsl2, Smlsl2)              \
  V(smlsl, Smlsl)                \
  V(smull2, Smull2)              \
  V(smull, Smull)                \
  V(sqadd, Sqadd)                \
  V(sqdmlal2, Sqdmlal2)          \
  V(sqdmlal, Sqdmlal)            \
  V(sqdmlsl2, Sqdmlsl2)          \
  V(sqdmlsl, Sqdmlsl)            \
  V(sqdmulh, Sqdmulh)            \
  V(sqdmull2, Sqdmull2)          \
  V(sqdmull, Sqdmull)            \
  V(sqrdmulh, Sqrdmulh)          \
  V(sqrshl, Sqrshl)              \
  V(sqshl, Sqshl)                \
  V(sqsub, Sqsub)                \
  V(srhadd, Srhadd)              \
  V(srshl, Srshl)                \
  V(sshl, Sshl)                  \
  V(ssubl2, Ssubl2)              \
  V(ssubl, Ssubl)                \
  V(ssubw2, Ssubw2)              \
  V(ssubw, Ssubw)                \
  V(subhn2, Subhn2)              \
  V(subhn, Subhn)                \
  V(sub, Sub)                    \
  V(trn1, Trn1)                  \
  V(trn2, Trn2)                  \
  V(uabal2, Uabal2)              \
  V(uabal, Uabal)                \
  V(uaba, Uaba)                  \
  V(uabdl2, Uabdl2)              \
  V(uabdl, Uabdl)                \
  V(uabd, Uabd)                  \
  V(uaddl2, Uaddl2)              \
  V(uaddl, Uaddl)                \
  V(uaddw2, Uaddw2)              \
  V(uaddw, Uaddw)                \
  V(uhadd, Uhadd)                \
  V(uhsub, Uhsub)                \
  V(umaxp, Umaxp)                \
  V(umax, Umax)                  \
  V(uminp, Uminp)                \
  V(umin, Umin)                  \
  V(umlal2, Umlal2)              \
  V(umlal, Umlal)                \
  V(umlsl2, Umlsl2)              \
  V(umlsl, Umlsl)                \
  V(umull2, Umull2)              \
  V(umull, Umull)                \
  V(uqadd, Uqadd)                \
  V(uqrshl, Uqrshl)              \
  V(uqshl, Uqshl)                \
  V(uqsub, Uqsub)                \
  V(urhadd, Urhadd)              \
  V(urshl, Urshl)                \
  V(ushl, Ushl)                  \
  V(usubl2, Usubl2)              \
  V(usubl, Usubl)                \
  V(usubw2, Usubw2)              \
  V(usubw, Usubw)                \
  V(uzp1, Uzp1)                  \
  V(uzp2, Uzp2)                  \
  V(zip1, Zip1)                  \
  V(zip2, Zip2)

#define DEFINE_MACRO_ASM_FUNC(ASM, MASM)                                     \
  void MASM(const VRegister& vd, const VRegister& vn, const VRegister& vm) { \
    DCHECK(allow_macro_instructions());                                      \
    ASM(vd, vn, vm);                                                         \
  }
  NEON_3VREG_MACRO_LIST(DEFINE_MACRO_ASM_FUNC)
#undef DEFINE_MACRO_ASM_FUNC

  void Bic(const VRegister& vd, const int imm8, const int left_shift = 0) {
    DCHECK(allow_macro_instructions());
    bic(vd, imm8, left_shift);
  }

  // This is required for compatibility in architecture independent code.
  inline void jmp(Label* L);

  void B(Label* label, BranchType type, Register reg = NoReg, int bit = -1);
  inline void B(Label* label);
  inline void B(Condition cond, Label* label);
  void B(Label* label, Condition cond);

  void Tbnz(const Register& rt, unsigned bit_pos, Label* label);
  void Tbz(const Register& rt, unsigned bit_pos, Label* label);

  void Cbnz(const Register& rt, Label* label);
  void Cbz(const Register& rt, Label* label);

  void Pacibsp() {
    DCHECK(allow_macro_instructions_);
    pacibsp();
  }
  void Autibsp() {
    DCHECK(allow_macro_instructions_);
    autibsp();
  }

  // The 1716 pac and aut instructions encourage people to use x16 and x17
  // directly, perhaps without realising that this is forbidden. For example:
  //
  //     UseScratchRegisterScope temps(&masm);
  //     Register temp = temps.AcquireX();  // temp will be x16
  //     __ Mov(x17, ptr);
  //     __ Mov(x16, modifier);  // Will override temp!
  //     __ Pacib1716();
  //
  // To work around this issue, you must exclude x16 and x17 from the scratch
  // register list. You may need to replace them with other registers:
  //
  //     UseScratchRegisterScope temps(&masm);
  //     temps.Exclude(x16, x17);
  //     temps.Include(x10, x11);
  //     __ Mov(x17, ptr);
  //     __ Mov(x16, modifier);
  //     __ Pacib1716();
  void Pacib1716() {
    DCHECK(allow_macro_instructions_);
    DCHECK(!TmpList()->IncludesAliasOf(x16));
    DCHECK(!TmpList()->IncludesAliasOf(x17));
    pacib1716();
  }
  void Autib1716() {
    DCHECK(allow_macro_instructions_);
    DCHECK(!TmpList()->IncludesAliasOf(x16));
    DCHECK(!TmpList()->IncludesAliasOf(x17));
    autib1716();
  }

  inline void Dmb(BarrierDomain domain, BarrierType type);
  inline void Dsb(BarrierDomain domain, BarrierType type);
  inline void Isb();
  inline void Csdb();

  inline void SmiUntag(Register dst, Register src);
  inline void SmiUntag(Register dst, const MemOperand& src);
  inline void SmiUntag(Register smi);

  inline void SmiTag(Register dst, Register src);
  inline void SmiTag(Register smi);

  inline void SmiToInt32(Register smi);
  inline void SmiToInt32(Register dst, Register smi);

  // Calls Abort(msg) if the condition cond is not satisfied.
  // Use --debug_code to enable.
  void Assert(Condition cond, AbortReason reason) NOOP_UNLESS_DEBUG_CODE;

  // Like Assert(), but without condition.
  // Use --debug_code to enable.
  void AssertUnreachable(AbortReason reason) NOOP_UNLESS_DEBUG_CODE;

  void AssertSmi(Register object,
                 AbortReason reason = AbortReason::kOperandIsNotASmi)
      NOOP_UNLESS_DEBUG_CODE;

  // Abort execution if argument is a smi, enabled via --debug-code.
  void AssertNotSmi(Register object,
                    AbortReason reason = AbortReason::kOperandIsASmi)
      NOOP_UNLESS_DEBUG_CODE;

  // Abort execution if a 64 bit register containing a 32 bit payload does
  // not have zeros in the top 32 bits, enabled via --debug-code.
  void AssertZeroExtended(Register int32_register) NOOP_UNLESS_DEBUG_CODE;

  void AssertJSAny(Register object, Register map_tmp, Register tmp,
                   AbortReason abort_reason) NOOP_UNLESS_DEBUG_CODE;

  // Like Assert(), but always enabled.
  void Check(Condition cond, AbortReason reason);

  // Same as Check() but expresses that the check is needed for the sandbox.
  void SbxCheck(Condition cc, AbortReason reason);

  // Functions performing a check on a known or potential smi. Returns
  // a condition that is satisfied if the check is successful.
  Condition CheckSmi(Register src);

  inline void Debug(const char* message, uint32_t code, Instr params = BREAK);

  void Trap();
  void DebugBreak();

  // Print a message to stderr and abort execution.
  void Abort(AbortReason reason);

  // Like printf, but print at run-time from generated code.
  //
  // The caller must ensure that arguments for floating-point placeholders
  // (such as %e, %f or %g) are VRegisters, and that arguments for integer
  // placeholders are Registers.
  //
  // Format placeholders that refer to more than one argument, or to a specific
  // argument, are not supported. This includes formats like "%1$d" or "%.*d".
  //
  // This function automatically preserves caller-saved registers so that
  // calling code can use Printf at any point without having to worry about
  // corruption. The preservation mechanism generates a lot of code. If this is
  // a problem, preserve the important registers manually and then call
  // PrintfNoPreserve. Callee-saved registers are not used by Printf, and are
  // implicitly preserved.
  void Printf(const char* format, CPURegister arg0 = NoCPUReg,
              CPURegister arg1 = NoCPUReg, CPURegister arg2 = NoCPUReg,
              CPURegister arg3 = NoCPUReg);

  // Like Printf, but don't preserve any caller-saved registers, not even 'lr'.
  //
  // The return code from the system printf call will be returned in x0.
  void PrintfNoPreserve(const char* format, const CPURegister& arg0 = NoCPUReg,
                        const CPURegister& arg1 = NoCPUReg,
                        const CPURegister& arg2 = NoCPUReg,
                        const CPURegister& arg3 = NoCPUReg);

  // Remaining instructions are simple pass-through calls to the assembler.
  inline void Asr(const Register& rd, const Register& rn, unsigned shift);
  inline void Asr(const Register& rd, const Register& rn, const Register& rm);

  // Try to move an immediate into the destination register in a single
  // instruction. Returns true for success, and updates the contents of dst.
  // Returns false, otherwise.
  bool TryOneInstrMoveImmediate(const Register& dst, int64_t imm);

  inline void Bind(Label* label,
                   BranchTargetIdentifier id = BranchTargetIdentifier::kNone);

  // Control-flow integrity:

  // Define a function entrypoint.
  inline void CodeEntry();
  // Define an exception handler.
  inline void ExceptionHandler();
  // Define an exception handler and bind a label.
  inline void BindExceptionHandler(Label* label);

  // Control-flow integrity:

  // Define a jump (BR) target.
  inline void JumpTarget();
  // Define a jump (BR) target and bind a label.
  inline void BindJumpTarget(Label* label);
  // Define a call (BLR) target. The target also allows tail calls (via BR)
  // when the target is x16 or x17.
  inline void CallTarget();
  // Define a jump/call target and bind a label.
  inline void BindCallTarget(Label* label);
  // Define a jump/call target.
  inline void JumpOrCallTarget();
  // Define a jump/call target and bind a label.
  inline void BindJumpOrCallTarget(Label* label);

  static unsigned CountSetHalfWords(uint64_t imm, unsigned reg_size);

  CPURegList* TmpList() { return &tmp_list_; }
  CPURegList* FPTmpList() { return &fptmp_list_; }

  static CPURegList DefaultTmpList();
  static CPURegList DefaultFPTmpList();

  // Move macros.
  inline void Mvn(const Register& rd, uint64_t imm);
  void Mvn(const Register& rd, const Operand& operand);
  static bool IsImmMovn(uint64_t imm, unsigned reg_size);
  static bool IsImmMovz(uint64_t imm, unsigned reg_size);

  void LogicalMacro(const Register& rd, const Register& rn,
                    const Operand& operand, LogicalOp op);
  void AddSubMacro(const Register& rd, const Register& rn,
                   const Operand& operand, FlagsUpdate S, AddSubOp op);
  inline void Orr(const Register& rd, const Register& rn,
                  const Operand& operand);
  void Orr(const VRegister& vd, const int imm8, const int left_shift = 0) {
    DCHECK(allow_macro_instructions());
    orr(vd, imm8, left_shift);
  }
  inline void Orn(const Register& rd, const Register& rn,
                  const Operand& operand);
  inline void Eor(const Register& rd, const Register& rn,
                  const Operand& operand);
  inline void Eon(const Register& rd, const Register& rn,
                  const Operand& operand);
  inline void And(const Register& rd, const Register& rn,
                  const Operand& operand);
  inline void Ands(const Register& rd, const Register& rn,
                   const Operand& operand);
  inline void Tst(const Register& rn, const Operand& operand);
  inline void Bic(const Register& rd, const Register& rn,
                  const Operand& operand);
  inline void Blr(const Register& xn);
  inline void Cmp(const Register& rn, const Operand& operand);
  inline void CmpTagged(const Register& rn, const Operand& operand);
  inline void Subs(const Register& rd, const Register& rn,
                   const Operand& operand);
  void Csel(const Register& rd, const Register& rn, const Operand& operand,
            Condition cond);
  inline void Fcsel(const VRegister& fd, const VRegister& fn,
                    const VRegister& fm, Condition cond);

  // Checks if value is in range [lower_limit, higher_limit] using a single
  // comparison. Condition `ls` indicates the value is in the range.
  void CompareRange(Register value, Register scratch, unsigned lower_limit,
                    unsigned higher_limit);
  void JumpIfIsInRange(Register value, Register scratch, unsigned lower_limit,
                       unsigned higher_limit, Label* on_in_range);

  // Emits a runtime assert that the stack pointer is aligned.
  void AssertSpAligned() NOOP_UNLESS_DEBUG_CODE;

  // Copy slot_count stack slots from the stack offset specified by src to
  // the stack offset specified by dst. The offsets and count are expressed in
  // slot-sized units. Offset dst must be less than src, or the gap between
  // them must be greater than or equal to slot_count, otherwise the result is
  // unpredictable. The function may corrupt its register arguments. The
  // registers must not alias each other.
  void CopySlots(int dst, Register src, Register slot_count);
  void CopySlots(Register dst, Register src, Register slot_count);

  // Copy count double words from the address in register src to the address
  // in register dst. There are three modes for this function:
  // 1) Address dst must be less than src, or the gap between them must be
  //    greater than or equal to count double words, otherwise the result is
  //    unpredictable. This is the default mode.
  // 2) Address src must be less than dst, or the gap between them must be
  //    greater than or equal to count double words, otherwise the result is
  //    undpredictable. In this mode, src and dst specify the last (highest)
  //    address of the regions to copy from and to.
  // 3) The same as mode 1, but the words are copied in the reversed order.
  // The case where src == dst is not supported.
  // The function may corrupt its register arguments. The registers must not
  // alias each other.
  enum CopyDoubleWordsMode {
    kDstLessThanSrc,
    kSrcLessThanDst,
    kDstLessThanSrcAndReverse
  };
  void CopyDoubleWords(Register dst, Register src, Register count,
                       CopyDoubleWordsMode mode = kDstLessThanSrc);

  // Calculate the address of a double word-sized slot at slot_offset from the
  // stack pointer, and write it to dst. Positive slot_offsets are at addresses
  // greater than sp, with slot zero at sp.
  void SlotAddress(Register dst, int slot_offset);
  void SlotAddress(Register dst, Register slot_offset);

  // Load a literal from the inline constant pool.
  inline void Ldr(const CPURegister& rt, const Operand& imm);

  // Claim or drop stack space.
  //
  // On Windows, Claim will write a value every 4k, as is required by the stack
  // expansion mechanism.
  //
  // The stack pointer must be aligned to 16 bytes and the size claimed or
  // dropped must be a multiple of 16 bytes.
  //
  // Note that unit_size must be specified in bytes. For variants which take a
  // Register count, the unit size must be a power of two.
  inline void Claim(int64_t count, uint64_t unit_size = kXRegSize);
  inline void Claim(const Register& count, uint64_t unit_size = kXRegSize,
                    bool assume_sp_aligned = true);
  inline void Drop(int64_t count, uint64_t unit_size = kXRegSize);
  inline void Drop(const Register& count, uint64_t unit_size = kXRegSize);

  // Drop 'count' + 'extra_slots' arguments from the stack, rounded up to
  // a multiple of two, without actually accessing memory.
  // We assume the size of the arguments is the pointer size.
  inline void DropArguments(const Register& count, int extra_slots = 0);
  inline void DropArguments(int64_t count);

  // Drop 'count' slots from stack, rounded up to a multiple of two, without
  // actually accessing memory.
  inline void DropSlots(int64_t count);

  // Push a single argument, with padding, to the stack.
  inline void PushArgument(const Register& arg);

  // Add and sub macros.
  inline void Add(const Register& rd, const Register& rn,
                  const Operand& operand);
  inline void Adds(const Register& rd, const Register& rn,
                   const Operand& operand);
  inline void Sub(con
```