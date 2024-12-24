Response: 
Prompt: 
```
这是目录为v8/test/unittests/assembler/disasm-arm64-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""

  COMPARE(ldp(s29, s30, MemOperand(fp, -256, PreIndex)),
          "ldp s29, s30, [fp, #-256]!");
  COMPARE(ldp(s31, s0, MemOperand(x1, 252, PostIndex)),
          "ldp s31, s0, [x1], #252");
  COMPARE(ldp(s2, s3, MemOperand(x4, -256, PostIndex)),
          "ldp s2, s3, [x4], #-256");
  COMPARE(ldp(d17, d18, MemOperand(x19)), "ldp d17, d18, [x19]");
  COMPARE(ldp(d20, d21, MemOperand(x22, 504)), "ldp d20, d21, [x22, #504]");
  COMPARE(ldp(d23, d24, MemOperand(x25, -512)), "ldp d23, d24, [x25, #-512]");
  COMPARE(ldp(d26, d27, MemOperand(x28, 504, PreIndex)),
          "ldp d26, d27, [x28, #504]!");
  COMPARE(ldp(d29, d30, MemOperand(fp, -512, PreIndex)),
          "ldp d29, d30, [fp, #-512]!");
  COMPARE(ldp(d31, d0, MemOperand(x1, 504, PostIndex)),
          "ldp d31, d0, [x1], #504");
  COMPARE(ldp(d2, d3, MemOperand(x4, -512, PostIndex)),
          "ldp d2, d3, [x4], #-512");

  COMPARE(stp(w0, w1, MemOperand(x2)), "stp w0, w1, [x2]");
  COMPARE(stp(x3, x4, MemOperand(x5)), "stp x3, x4, [x5]");
  COMPARE(stp(w6, w7, MemOperand(x8, 4)), "stp w6, w7, [x8, #4]");
  COMPARE(stp(x9, x10, MemOperand(x11, 8)), "stp x9, x10, [x11, #8]");
  COMPARE(stp(w12, w13, MemOperand(x14, 252)), "stp w12, w13, [x14, #252]");
  COMPARE(stp(x15, x16, MemOperand(x17, 504)), "stp x15, x16, [x17, #504]");
  COMPARE(stp(w18, w19, MemOperand(x20, -256)), "stp w18, w19, [x20, #-256]");
  COMPARE(stp(x21, x22, MemOperand(x23, -512)), "stp x21, x22, [x23, #-512]");
  COMPARE(stp(w24, w25, MemOperand(x26, 252, PreIndex)),
          "stp w24, w25, [x26, #252]!");
  COMPARE(stp(cp, x28, MemOperand(fp, 504, PreIndex)),
          "stp cp, x28, [fp, #504]!");
  COMPARE(stp(w30, w0, MemOperand(x1, -256, PreIndex)),
          "stp w30, w0, [x1, #-256]!");
  COMPARE(stp(x2, x3, MemOperand(x4, -512, PreIndex)),
          "stp x2, x3, [x4, #-512]!");
  COMPARE(stp(w5, w6, MemOperand(x7, 252, PostIndex)),
          "stp w5, w6, [x7], #252");
  COMPARE(stp(x8, x9, MemOperand(x10, 504, PostIndex)),
          "stp x8, x9, [x10], #504");
  COMPARE(stp(w11, w12, MemOperand(x13, -256, PostIndex)),
          "stp w11, w12, [x13], #-256");
  COMPARE(stp(x14, x15, MemOperand(x16, -512, PostIndex)),
          "stp x14, x15, [x16], #-512");

  COMPARE(stp(s17, s18, MemOperand(x19)), "stp s17, s18, [x19]");
  COMPARE(stp(s20, s21, MemOperand(x22, 252)), "stp s20, s21, [x22, #252]");
  COMPARE(stp(s23, s24, MemOperand(x25, -256)), "stp s23, s24, [x25, #-256]");
  COMPARE(stp(s26, s27, MemOperand(x28, 252, PreIndex)),
          "stp s26, s27, [x28, #252]!");
  COMPARE(stp(s29, s30, MemOperand(fp, -256, PreIndex)),
          "stp s29, s30, [fp, #-256]!");
  COMPARE(stp(s31, s0, MemOperand(x1, 252, PostIndex)),
          "stp s31, s0, [x1], #252");
  COMPARE(stp(s2, s3, MemOperand(x4, -256, PostIndex)),
          "stp s2, s3, [x4], #-256");
  COMPARE(stp(d17, d18, MemOperand(x19)), "stp d17, d18, [x19]");
  COMPARE(stp(d20, d21, MemOperand(x22, 504)), "stp d20, d21, [x22, #504]");
  COMPARE(stp(d23, d24, MemOperand(x25, -512)), "stp d23, d24, [x25, #-512]");
  COMPARE(stp(d26, d27, MemOperand(x28, 504, PreIndex)),
          "stp d26, d27, [x28, #504]!");
  COMPARE(stp(d29, d30, MemOperand(fp, -512, PreIndex)),
          "stp d29, d30, [fp, #-512]!");
  COMPARE(stp(d31, d0, MemOperand(x1, 504, PostIndex)),
          "stp d31, d0, [x1], #504");
  COMPARE(stp(d2, d3, MemOperand(x4, -512, PostIndex)),
          "stp d2, d3, [x4], #-512");

  COMPARE(stp(q5, q6, MemOperand(x7)), "stp q5, q6, [x7]");
  COMPARE(stp(q8, q9, MemOperand(x10, 1008)), "stp q8, q9, [x10, #1008]");
  COMPARE(stp(q11, q12, MemOperand(x13, -1024)), "stp q11, q12, [x13, #-1024]");
  COMPARE(stp(q14, q15, MemOperand(x16, 1008, PreIndex)),
          "stp q14, q15, [x16, #1008]!");
  COMPARE(stp(q17, q18, MemOperand(x19, -1024, PreIndex)),
          "stp q17, q18, [x19, #-1024]!");
  COMPARE(stp(q20, q21, MemOperand(x22, 1008, PostIndex)),
          "stp q20, q21, [x22], #1008");
  COMPARE(stp(q23, q24, MemOperand(x25, -1024, PostIndex)),
          "stp q23, q24, [x25], #-1024");

  COMPARE(ldp(w16, w17, MemOperand(x28, 4, PostIndex)),
          "ldp w16, w17, [x28], #4");
  COMPARE(stp(x18, x19, MemOperand(x28, -8, PreIndex)),
          "stp x18, x19, [x28, #-8]!");
  COMPARE(ldp(s30, s31, MemOperand(x28, 12, PostIndex)),
          "ldp s30, s31, [x28], #12");
  COMPARE(stp(d30, d31, MemOperand(x28, -16)), "stp d30, d31, [x28, #-16]");
  COMPARE(ldp(q30, q31, MemOperand(x28, 32, PostIndex)),
          "ldp q30, q31, [x28], #32");

  COMPARE(ldpsw(x0, x1, MemOperand(x2)), "ldpsw x0, x1, [x2]");
  COMPARE(ldpsw(x3, x4, MemOperand(x5, 16)), "ldpsw x3, x4, [x5, #16]");
  COMPARE(ldpsw(x6, x7, MemOperand(x8, -32, PreIndex)),
          "ldpsw x6, x7, [x8, #-32]!");
  COMPARE(ldpsw(x9, x10, MemOperand(x11, 128, PostIndex)),
          "ldpsw x9, x10, [x11], #128");

  CLEANUP();
}

TEST_F(DisasmArm64Test, load_store_acquire_release) {
  SET_UP_MASM();

  COMPARE(ldar(w0, x1), "ldar w0, [x1]");
  COMPARE(ldarb(w2, x3), "ldarb w2, [x3]");
  COMPARE(ldarh(w4, x5), "ldarh w4, [x5]");
  COMPARE(ldaxr(w6, x7), "ldaxr w6, [x7]");
  COMPARE(ldaxrb(w8, x9), "ldaxrb w8, [x9]");
  COMPARE(ldaxrh(w10, x11), "ldaxrh w10, [x11]");
  COMPARE(stlr(w12, x13), "stlr w12, [x13]");
  COMPARE(stlrb(w14, x15), "stlrb w14, [x15]");
  COMPARE(stlrh(w16, x17), "stlrh w16, [x17]");
  COMPARE(stlxr(w18, w19, x20), "stlxr w18, w19, [x20]");
  COMPARE(stlxrb(w21, w22, x23), "stlxrb w21, w22, [x23]");
  COMPARE(stlxrh(w24, w25, x26), "stlxrh w24, w25, [x26]");

  COMPARE(ldarb(wzr, sp), "ldarb wzr, [sp]");
  COMPARE(ldarh(wzr, sp), "ldarh wzr, [sp]");
  COMPARE(ldar(wzr, sp), "ldar wzr, [sp]");
  COMPARE(stlrb(wzr, sp), "stlrb wzr, [sp]");
  COMPARE(stlrh(wzr, sp), "stlrh wzr, [sp]");
  COMPARE(stlr(wzr, sp), "stlr wzr, [sp]");
  COMPARE(ldaxrb(wzr, sp), "ldaxrb wzr, [sp]");
  COMPARE(ldaxrh(wzr, sp), "ldaxrh wzr, [sp]");
  COMPARE(ldaxr(wzr, sp), "ldaxr wzr, [sp]");
  COMPARE(stlxrb(w0, wzr, sp), "stlxrb w0, wzr, [sp]");
  COMPARE(stlxrh(wzr, w1, sp), "stlxrh wzr, w1, [sp]");
  COMPARE(stlxr(w2, wzr, sp), "stlxr w2, wzr, [sp]");

  CpuFeatureScope feature_scope(assm, LSE,
                                CpuFeatureScope::kDontCheckSupported);

  COMPARE(cas(w30, w0, MemOperand(x1)), "cas w30, w0, [x1]");
  COMPARE(cas(w2, w3, MemOperand(sp)), "cas w2, w3, [sp]");
  COMPARE(cas(x4, x5, MemOperand(x6)), "cas x4, x5, [x6]");
  COMPARE(cas(x7, x8, MemOperand(sp)), "cas x7, x8, [sp]");
  COMPARE(casa(w9, w10, MemOperand(x11)), "casa w9, w10, [x11]");
  COMPARE(casa(w12, w13, MemOperand(sp)), "casa w12, w13, [sp]");
  COMPARE(casa(x14, x15, MemOperand(x16)), "casa x14, x15, [x16]");
  COMPARE(casa(x17, x18, MemOperand(sp)), "casa x17, x18, [sp]");
  COMPARE(casl(w19, w20, MemOperand(x21)), "casl w19, w20, [x21]");
  COMPARE(casl(w22, w23, MemOperand(sp)), "casl w22, w23, [sp]");
  COMPARE(casl(x24, x25, MemOperand(x26)), "casl x24, x25, [x26]");
  COMPARE(casl(x27, x28, MemOperand(sp)), "casl cp, x28, [sp]");
  COMPARE(casal(w29, w30, MemOperand(x0)), "casal w29, w30, [x0]");
  COMPARE(casal(w1, w2, MemOperand(sp)), "casal w1, w2, [sp]");
  COMPARE(casal(x3, x4, MemOperand(x5)), "casal x3, x4, [x5]");
  COMPARE(casal(x6, x7, MemOperand(sp)), "casal x6, x7, [sp]");
  COMPARE(casb(w8, w9, MemOperand(x10)), "casb w8, w9, [x10]");
  COMPARE(casb(w11, w12, MemOperand(sp)), "casb w11, w12, [sp]");
  COMPARE(casab(w13, w14, MemOperand(x15)), "casab w13, w14, [x15]");
  COMPARE(casab(w16, w17, MemOperand(sp)), "casab w16, w17, [sp]");
  COMPARE(caslb(w18, w19, MemOperand(x20)), "caslb w18, w19, [x20]");
  COMPARE(caslb(w21, w22, MemOperand(sp)), "caslb w21, w22, [sp]");
  COMPARE(casalb(w23, w24, MemOperand(x25)), "casalb w23, w24, [x25]");
  COMPARE(casalb(w26, w27, MemOperand(sp)), "casalb w26, w27, [sp]");
  COMPARE(cash(w28, w29, MemOperand(x30)), "cash w28, w29, [lr]");
  COMPARE(cash(w0, w1, MemOperand(sp)), "cash w0, w1, [sp]");
  COMPARE(casah(w2, w3, MemOperand(x4)), "casah w2, w3, [x4]");
  COMPARE(casah(w5, w6, MemOperand(sp)), "casah w5, w6, [sp]");
  COMPARE(caslh(w7, w8, MemOperand(x9)), "caslh w7, w8, [x9]");
  COMPARE(caslh(w10, w11, MemOperand(sp)), "caslh w10, w11, [sp]");
  COMPARE(casalh(w12, w13, MemOperand(x14)), "casalh w12, w13, [x14]");
  COMPARE(casalh(w15, w16, MemOperand(sp)), "casalh w15, w16, [sp]");
  COMPARE(casp(w18, w19, w20, w21, MemOperand(x22)),
          "casp w18, w19, w20, w21, [x22]");
  COMPARE(casp(w24, w25, w26, w27, MemOperand(sp)),
          "casp w24, w25, w26, w27, [sp]");
  COMPARE(casp(x28, x29, x0, x1, MemOperand(x2)), "casp x28, fp, x0, x1, [x2]");
  COMPARE(casp(x4, x5, x6, x7, MemOperand(sp)), "casp x4, x5, x6, x7, [sp]");
  COMPARE(caspa(w8, w9, w10, w11, MemOperand(x12)),
          "caspa w8, w9, w10, w11, [x12]");
  COMPARE(caspa(w14, w15, w16, w17, MemOperand(sp)),
          "caspa w14, w15, w16, w17, [sp]");
  COMPARE(caspa(x18, x19, x20, x21, MemOperand(x22)),
          "caspa x18, x19, x20, x21, [x22]");
  COMPARE(caspa(x24, x25, x26, x27, MemOperand(sp)),
          "caspa x24, x25, x26, cp, [sp]");
  COMPARE(caspl(w28, w29, w0, w1, MemOperand(x2)),
          "caspl w28, w29, w0, w1, [x2]");
  COMPARE(caspl(w4, w5, w6, w7, MemOperand(sp)), "caspl w4, w5, w6, w7, [sp]");
  COMPARE(caspl(x8, x9, x10, x11, MemOperand(x12)),
          "caspl x8, x9, x10, x11, [x12]");
  COMPARE(caspl(x14, x15, x16, x17, MemOperand(sp)),
          "caspl x14, x15, x16, x17, [sp]");
  COMPARE(caspal(w18, w19, w20, w21, MemOperand(x22)),
          "caspal w18, w19, w20, w21, [x22]");
  COMPARE(caspal(w24, w25, w26, w27, MemOperand(sp)),
          "caspal w24, w25, w26, w27, [sp]");
  COMPARE(caspal(x28, x29, x0, x1, MemOperand(x2)),
          "caspal x28, fp, x0, x1, [x2]");
  COMPARE(caspal(x4, x5, x6, x7, MemOperand(sp)),
          "caspal x4, x5, x6, x7, [sp]");

  CLEANUP();
}

#define ATOMIC_MEMORY_DISASM_LIST(V, DEF) \
  V(DEF, add, "add")                      \
  V(DEF, clr, "clr")                      \
  V(DEF, eor, "eor")                      \
  V(DEF, set, "set")                      \
  V(DEF, smax, "smax")                    \
  V(DEF, smin, "smin")                    \
  V(DEF, umax, "umax")                    \
  V(DEF, umin, "umin")

#define ATOMIC_MEMORY_DISASM_STORE_X_MODES(V, NAME, STR) \
  V(NAME, STR)                                           \
  V(NAME##l, STR "l")

#define ATOMIC_MEMORY_DISASM_STORE_W_MODES(V, NAME, STR) \
  ATOMIC_MEMORY_DISASM_STORE_X_MODES(V, NAME, STR)       \
  V(NAME##b, STR "b")                                    \
  V(NAME##lb, STR "lb")                                  \
  V(NAME##h, STR "h")                                    \
  V(NAME##lh, STR "lh")

#define ATOMIC_MEMORY_DISASM_LOAD_X_MODES(V, NAME, STR) \
  ATOMIC_MEMORY_DISASM_STORE_X_MODES(V, NAME, STR)      \
  V(NAME##a, STR "a")                                   \
  V(NAME##al, STR "al")

#define ATOMIC_MEMORY_DISASM_LOAD_W_MODES(V, NAME, STR) \
  ATOMIC_MEMORY_DISASM_LOAD_X_MODES(V, NAME, STR)       \
  V(NAME##ab, STR "ab")                                 \
  V(NAME##alb, STR "alb")                               \
  V(NAME##ah, STR "ah")                                 \
  V(NAME##alh, STR "alh")

TEST_F(DisasmArm64Test, atomic_memory) {
  SET_UP_MASM();

  CpuFeatureScope feature_scope(assm, LSE,
                                CpuFeatureScope::kDontCheckSupported);

  // These macros generate tests for all the variations of the atomic memory
  // operations, e.g. ldadd, ldadda, ldaddb, staddl, etc.

#define AM_LOAD_X_TESTS(N, MN)                                     \
  COMPARE(ld##N(x0, x1, MemOperand(x2)), "ld" MN " x0, x1, [x2]"); \
  COMPARE(ld##N(x3, x4, MemOperand(sp)), "ld" MN " x3, x4, [sp]");
#define AM_LOAD_W_TESTS(N, MN)                                     \
  COMPARE(ld##N(w0, w1, MemOperand(x2)), "ld" MN " w0, w1, [x2]"); \
  COMPARE(ld##N(w3, w4, MemOperand(sp)), "ld" MN " w3, w4, [sp]");
#define AM_STORE_X_TESTS(N, MN)                            \
  COMPARE(st##N(x0, MemOperand(x1)), "st" MN " x0, [x1]"); \
  COMPARE(st##N(x2, MemOperand(sp)), "st" MN " x2, [sp]");
#define AM_STORE_W_TESTS(N, MN)                            \
  COMPARE(st##N(w0, MemOperand(x1)), "st" MN " w0, [x1]"); \
  COMPARE(st##N(w2, MemOperand(sp)), "st" MN " w2, [sp]");

  ATOMIC_MEMORY_DISASM_LIST(ATOMIC_MEMORY_DISASM_LOAD_X_MODES, AM_LOAD_X_TESTS)
  ATOMIC_MEMORY_DISASM_LIST(ATOMIC_MEMORY_DISASM_LOAD_W_MODES, AM_LOAD_W_TESTS)
  ATOMIC_MEMORY_DISASM_LIST(ATOMIC_MEMORY_DISASM_STORE_X_MODES,
                            AM_STORE_X_TESTS)
  ATOMIC_MEMORY_DISASM_LIST(ATOMIC_MEMORY_DISASM_STORE_W_MODES,
                            AM_STORE_W_TESTS)

#define AM_SWP_X_TESTS(N, MN)                             \
  COMPARE(N(x0, x1, MemOperand(x2)), MN " x0, x1, [x2]"); \
  COMPARE(N(x3, x4, MemOperand(sp)), MN " x3, x4, [sp]");
#define AM_SWP_W_TESTS(N, MN)                             \
  COMPARE(N(w0, w1, MemOperand(x2)), MN " w0, w1, [x2]"); \
  COMPARE(N(w3, w4, MemOperand(sp)), MN " w3, w4, [sp]");

  ATOMIC_MEMORY_DISASM_LOAD_X_MODES(AM_SWP_X_TESTS, swp, "swp")
  ATOMIC_MEMORY_DISASM_LOAD_W_MODES(AM_SWP_W_TESTS, swp, "swp")

#undef AM_LOAD_X_TESTS
#undef AM_LOAD_W_TESTS
#undef AM_STORE_X_TESTS
#undef AM_STORE_W_TESTS
#undef AM_SWP_X_TESTS
#undef AM_SWP_W_TESTS

  CLEANUP();
}

TEST_F(DisasmArm64Test, load_literal) {
  SET_UP_ASM();

  COMPARE_PREFIX(ldr_pcrel(x10, 0), "ldr x10, pc+0");
  COMPARE_PREFIX(ldr_pcrel(x10, 1), "ldr x10, pc+4");
  COMPARE_PREFIX(ldr_pcrel(d11, 0), "ldr d11, pc+0");
  COMPARE_PREFIX(ldr_pcrel(d11, 1), "ldr d11, pc+4");

  int max_offset = (kMaxLoadLiteralRange >> kLoadLiteralScaleLog2) - 1;
  COMPARE_PREFIX(ldr_pcrel(x0, max_offset), "ldr x0, pc+1048572");
  COMPARE_PREFIX(ldr_pcrel(d0, max_offset), "ldr d0, pc+1048572");

  CLEANUP();
}

TEST_F(DisasmArm64Test, cond_select) {
  SET_UP_ASM();

  COMPARE(csel(w0, w1, w2, eq), "csel w0, w1, w2, eq");
  COMPARE(csel(x3, x4, x5, ne), "csel x3, x4, x5, ne");
  COMPARE(csinc(w6, w7, w8, hs), "csinc w6, w7, w8, hs");
  COMPARE(csinc(x9, x10, x11, lo), "csinc x9, x10, x11, lo");
  COMPARE(csinv(w12, w13, w14, mi), "csinv w12, w13, w14, mi");
  COMPARE(csinv(x15, x16, x17, pl), "csinv x15, x16, x17, pl");
  COMPARE(csneg(w18, w19, w20, vs), "csneg w18, w19, w20, vs");
  COMPARE(csneg(x21, x22, x23, vc), "csneg x21, x22, x23, vc");
  COMPARE(cset(w24, hi), "cset w24, hi");
  COMPARE(cset(x25, ls), "cset x25, ls");
  COMPARE(csetm(w26, ge), "csetm w26, ge");
  COMPARE(csetm(cp, lt), "csetm cp, lt");
  COMPARE(cinc(w28, w29, gt), "cinc w28, w29, gt");
  COMPARE(cinc(lr, x0, le), "cinc lr, x0, le");
  COMPARE(cinv(w1, w2, eq), "cinv w1, w2, eq");
  COMPARE(cinv(x3, x4, ne), "cinv x3, x4, ne");
  COMPARE(cneg(w5, w6, hs), "cneg w5, w6, hs");
  COMPARE(cneg(x7, x8, lo), "cneg x7, x8, lo");

  COMPARE(csel(x0, x1, x2, al), "csel x0, x1, x2, al");
  COMPARE(csel(x1, x2, x3, nv), "csel x1, x2, x3, nv");
  COMPARE(csinc(x2, x3, x4, al), "csinc x2, x3, x4, al");
  COMPARE(csinc(x3, x4, x5, nv), "csinc x3, x4, x5, nv");
  COMPARE(csinv(x4, x5, x6, al), "csinv x4, x5, x6, al");
  COMPARE(csinv(x5, x6, x7, nv), "csinv x5, x6, x7, nv");
  COMPARE(csneg(x6, x7, x8, al), "csneg x6, x7, x8, al");
  COMPARE(csneg(x7, x8, x9, nv), "csneg x7, x8, x9, nv");

  CLEANUP();
}

TEST_F(DisasmArm64Test, cond_select_macro) {
  SET_UP_MASM();

  COMPARE(Csel(w0, w1, -1, eq), "csinv w0, w1, wzr, eq");
  COMPARE(Csel(w2, w3, 0, ne), "csel w2, w3, wzr, ne");
  COMPARE(Csel(w4, w5, 1, hs), "csinc w4, w5, wzr, hs");
  COMPARE(Csel(x6, x7, -1, lo), "csinv x6, x7, xzr, lo");
  COMPARE(Csel(x8, x9, 0, mi), "csel x8, x9, xzr, mi");
  COMPARE(Csel(x10, x11, 1, pl), "csinc x10, x11, xzr, pl");

  CLEANUP();
}

TEST_F(DisasmArm64Test, cond_cmp) {
  SET_UP_ASM();

  COMPARE(ccmn(w0, w1, NZCVFlag, eq), "ccmn w0, w1, #NZCV, eq");
  COMPARE(ccmn(x2, x3, NZCFlag, ne), "ccmn x2, x3, #NZCv, ne");
  COMPARE(ccmp(w4, w5, NZVFlag, hs), "ccmp w4, w5, #NZcV, hs");
  COMPARE(ccmp(x6, x7, NZFlag, lo), "ccmp x6, x7, #NZcv, lo");
  COMPARE(ccmn(w8, 31, NFlag, mi), "ccmn w8, #31, #Nzcv, mi");
  COMPARE(ccmn(x9, 30, NCFlag, pl), "ccmn x9, #30, #NzCv, pl");
  COMPARE(ccmp(w10, 29, NVFlag, vs), "ccmp w10, #29, #NzcV, vs");
  COMPARE(ccmp(x11, 28, NFlag, vc), "ccmp x11, #28, #Nzcv, vc");
  COMPARE(ccmn(w12, w13, NoFlag, al), "ccmn w12, w13, #nzcv, al");
  COMPARE(ccmp(x14, 27, ZVFlag, nv), "ccmp x14, #27, #nZcV, nv");

  CLEANUP();
}

TEST_F(DisasmArm64Test, cond_cmp_macro) {
  SET_UP_MASM();

  COMPARE(Ccmp(w0, -1, VFlag, hi), "ccmn w0, #1, #nzcV, hi");
  COMPARE(Ccmp(x1, -31, CFlag, ge), "ccmn x1, #31, #nzCv, ge");
  COMPARE(Ccmn(w2, -1, CVFlag, gt), "ccmp w2, #1, #nzCV, gt");
  COMPARE(Ccmn(x3, -31, ZCVFlag, ls), "ccmp x3, #31, #nZCV, ls");

  CLEANUP();
}

TEST_F(DisasmArm64Test, fmov_imm) {
  SET_UP_ASM();

  COMPARE(fmov(s0, 1.0f), "fmov s0, #0x70 (1.0000)");
  COMPARE(fmov(s31, -13.0f), "fmov s31, #0xaa (-13.0000)");
  COMPARE(fmov(d1, 1.0), "fmov d1, #0x70 (1.0000)");
  COMPARE(fmov(d29, -13.0), "fmov d29, #0xaa (-13.0000)");

  CLEANUP();
}

TEST_F(DisasmArm64Test, fmov_reg) {
  SET_UP_ASM();

  COMPARE(fmov(w3, s13), "fmov w3, s13");
  COMPARE(fmov(x6, d26), "fmov x6, d26");
  COMPARE(fmov(s11, w30), "fmov s11, w30");
  COMPARE(fmov(d31, x2), "fmov d31, x2");
  COMPARE(fmov(s12, s13), "fmov s12, s13");
  COMPARE(fmov(d22, d23), "fmov d22, d23");
  COMPARE(fmov(v0.D(), 1, x13), "fmov v0.D[1], x13");
  COMPARE(fmov(x13, v0.D(), 1), "fmov x13, v0.D[1]");

  CLEANUP();
}

TEST_F(DisasmArm64Test, fp_dp1) {
  SET_UP_ASM();

  COMPARE(fabs(s0, s1), "fabs s0, s1");
  COMPARE(fabs(s31, s30), "fabs s31, s30");
  COMPARE(fabs(d2, d3), "fabs d2, d3");
  COMPARE(fabs(d31, d30), "fabs d31, d30");
  COMPARE(fneg(s4, s5), "fneg s4, s5");
  COMPARE(fneg(s31, s30), "fneg s31, s30");
  COMPARE(fneg(d6, d7), "fneg d6, d7");
  COMPARE(fneg(d31, d30), "fneg d31, d30");
  COMPARE(fsqrt(s8, s9), "fsqrt s8, s9");
  COMPARE(fsqrt(s31, s30), "fsqrt s31, s30");
  COMPARE(fsqrt(d10, d11), "fsqrt d10, d11");
  COMPARE(fsqrt(d31, d30), "fsqrt d31, d30");
  COMPARE(frinta(s10, s11), "frinta s10, s11");
  COMPARE(frinta(s31, s30), "frinta s31, s30");
  COMPARE(frinta(d12, d13), "frinta d12, d13");
  COMPARE(frinta(d31, d30), "frinta d31, d30");
  COMPARE(frinti(s10, s11), "frinti s10, s11");
  COMPARE(frinti(s31, s30), "frinti s31, s30");
  COMPARE(frinti(d12, d13), "frinti d12, d13");
  COMPARE(frinti(d31, d30), "frinti d31, d30");
  COMPARE(frintm(s10, s11), "frintm s10, s11");
  COMPARE(frintm(s31, s30), "frintm s31, s30");
  COMPARE(frintm(d12, d13), "frintm d12, d13");
  COMPARE(frintm(d31, d30), "frintm d31, d30");
  COMPARE(frintn(s10, s11), "frintn s10, s11");
  COMPARE(frintn(s31, s30), "frintn s31, s30");
  COMPARE(frintn(d12, d13), "frintn d12, d13");
  COMPARE(frintn(d31, d30), "frintn d31, d30");
  COMPARE(frintx(s10, s11), "frintx s10, s11");
  COMPARE(frintx(s31, s30), "frintx s31, s30");
  COMPARE(frintx(d12, d13), "frintx d12, d13");
  COMPARE(frintx(d31, d30), "frintx d31, d30");
  COMPARE(frintp(s10, s11), "frintp s10, s11");
  COMPARE(frintp(s31, s30), "frintp s31, s30");
  COMPARE(frintp(d12, d13), "frintp d12, d13");
  COMPARE(frintp(d31, d30), "frintp d31, d30");
  COMPARE(frintz(s10, s11), "frintz s10, s11");
  COMPARE(frintz(s31, s30), "frintz s31, s30");
  COMPARE(frintz(d12, d13), "frintz d12, d13");
  COMPARE(frintz(d31, d30), "frintz d31, d30");
  COMPARE(fcvt(d14, s15), "fcvt d14, s15");
  COMPARE(fcvt(d31, s31), "fcvt d31, s31");
  COMPARE(fcvt(s0, d1), "fcvt s0, d1");
  COMPARE(fcvt(s2, h3), "fcvt s2, h3");
  COMPARE(fcvt(d4, h5), "fcvt d4, h5");
  COMPARE(fcvt(h6, s7), "fcvt h6, s7");
  COMPARE(fcvt(h8, d9), "fcvt h8, d9");

  CLEANUP();
}

TEST_F(DisasmArm64Test, fp_dp2) {
  SET_UP_ASM();

  COMPARE(fadd(s0, s1, s2), "fadd s0, s1, s2");
  COMPARE(fadd(d3, d4, d5), "fadd d3, d4, d5");
  COMPARE(fsub(s31, s30, s29), "fsub s31, s30, s29");
  COMPARE(fsub(d31, d30, d29), "fsub d31, d30, d29");
  COMPARE(fmul(s7, s8, s9), "fmul s7, s8, s9");
  COMPARE(fmul(d10, d11, d12), "fmul d10, d11, d12");
  COMPARE(fnmul(s7, s8, s9), "fnmul s7, s8, s9");
  COMPARE(fnmul(d10, d11, d12), "fnmul d10, d11, d12");
  COMPARE(fdiv(s13, s14, s15), "fdiv s13, s14, s15");
  COMPARE(fdiv(d16, d17, d18), "fdiv d16, d17, d18");
  COMPARE(fmax(s19, s20, s21), "fmax s19, s20, s21");
  COMPARE(fmax(d22, d23, d24), "fmax d22, d23, d24");
  COMPARE(fmin(s25, s26, s27), "fmin s25, s26, s27");
  COMPARE(fmin(d28, d29, d30), "fmin d28, d29, d30");
  COMPARE(fmaxnm(s31, s0, s1), "fmaxnm s31, s0, s1");
  COMPARE(fmaxnm(d2, d3, d4), "fmaxnm d2, d3, d4");
  COMPARE(fminnm(s5, s6, s7), "fminnm s5, s6, s7");
  COMPARE(fminnm(d8, d9, d10), "fminnm d8, d9, d10");

  CLEANUP();
}

TEST_F(DisasmArm64Test, fp_dp3) {
  SET_UP_ASM();

  COMPARE(fmadd(s7, s8, s9, s10), "fmadd s7, s8, s9, s10");
  COMPARE(fmadd(d10, d11, d12, d10), "fmadd d10, d11, d12, d10");
  COMPARE(fmsub(s7, s8, s9, s10), "fmsub s7, s8, s9, s10");
  COMPARE(fmsub(d10, d11, d12, d10), "fmsub d10, d11, d12, d10");

  COMPARE(fnmadd(s7, s8, s9, s10), "fnmadd s7, s8, s9, s10");
  COMPARE(fnmadd(d10, d11, d12, d10), "fnmadd d10, d11, d12, d10");
  COMPARE(fnmsub(s7, s8, s9, s10), "fnmsub s7, s8, s9, s10");
  COMPARE(fnmsub(d10, d11, d12, d10), "fnmsub d10, d11, d12, d10");

  CLEANUP();
}

TEST_F(DisasmArm64Test, fp_compare) {
  SET_UP_ASM();

  COMPARE(fcmp(s0, s1), "fcmp s0, s1");
  COMPARE(fcmp(s31, s30), "fcmp s31, s30");
  COMPARE(fcmp(d0, d1), "fcmp d0, d1");
  COMPARE(fcmp(d31, d30), "fcmp d31, d30");
  COMPARE(fcmp(s12, 0), "fcmp s12, #0.0");
  COMPARE(fcmp(d12, 0), "fcmp d12, #0.0");

  CLEANUP();
}

TEST_F(DisasmArm64Test, fp_cond_compare) {
  SET_UP_ASM();

  COMPARE(fccmp(s0, s1, NoFlag, eq), "fccmp s0, s1, #nzcv, eq");
  COMPARE(fccmp(s2, s3, ZVFlag, ne), "fccmp s2, s3, #nZcV, ne");
  COMPARE(fccmp(s30, s16, NCFlag, pl), "fccmp s30, s16, #NzCv, pl");
  COMPARE(fccmp(s31, s31, NZCVFlag, le), "fccmp s31, s31, #NZCV, le");
  COMPARE(fccmp(d4, d5, VFlag, gt), "fccmp d4, d5, #nzcV, gt");
  COMPARE(fccmp(d6, d7, NFlag, vs), "fccmp d6, d7, #Nzcv, vs");
  COMPARE(fccmp(d30, d0, NZFlag, vc), "fccmp d30, d0, #NZcv, vc");
  COMPARE(fccmp(d31, d31, ZFlag, hs), "fccmp d31, d31, #nZcv, hs");
  COMPARE(fccmp(s14, s15, CVFlag, al), "fccmp s14, s15, #nzCV, al");
  COMPARE(fccmp(d16, d17, CFlag, nv), "fccmp d16, d17, #nzCv, nv");

  CLEANUP();
}

TEST_F(DisasmArm64Test, fp_select) {
  SET_UP_ASM();

  COMPARE(fcsel(s0, s1, s2, eq), "fcsel s0, s1, s2, eq")
  COMPARE(fcsel(s31, s31, s30, ne), "fcsel s31, s31, s30, ne");
  COMPARE(fcsel(d0, d1, d2, mi), "fcsel d0, d1, d2, mi");
  COMPARE(fcsel(d31, d30, d31, pl), "fcsel d31, d30, d31, pl");
  COMPARE(fcsel(s14, s15, s16, al), "fcsel s14, s15, s16, al");
  COMPARE(fcsel(d17, d18, d19, nv), "fcsel d17, d18, d19, nv");

  CLEANUP();
}

TEST_F(DisasmArm64Test, fcvt_scvtf_ucvtf) {
  SET_UP_ASM();

  COMPARE(fcvtas(w0, s1), "fcvtas w0, s1");
  COMPARE(fcvtas(x2, s3), "fcvtas x2, s3");
  COMPARE(fcvtas(w4, d5), "fcvtas w4, d5");
  COMPARE(fcvtas(x6, d7), "fcvtas x6, d7");
  COMPARE(fcvtau(w8, s9), "fcvtau w8, s9");
  COMPARE(fcvtau(x10, s11), "fcvtau x10, s11");
  COMPARE(fcvtau(w12, d13), "fcvtau w12, d13");
  COMPARE(fcvtau(x14, d15), "fcvtau x14, d15");
  COMPARE(fcvtns(w0, s1), "fcvtns w0, s1");
  COMPARE(fcvtns(x2, s3), "fcvtns x2, s3");
  COMPARE(fcvtns(w4, d5), "fcvtns w4, d5");
  COMPARE(fcvtns(x6, d7), "fcvtns x6, d7");
  COMPARE(fcvtnu(w8, s9), "fcvtnu w8, s9");
  COMPARE(fcvtnu(x10, s11), "fcvtnu x10, s11");
  COMPARE(fcvtnu(w12, d13), "fcvtnu w12, d13");
  COMPARE(fcvtnu(x14, d15), "fcvtnu x14, d15");
  COMPARE(fcvtzu(x16, d17), "fcvtzu x16, d17");
  COMPARE(fcvtzu(w18, d19), "fcvtzu w18, d19");
  COMPARE(fcvtzs(x20, d21), "fcvtzs x20, d21");
  COMPARE(fcvtzs(w22, d23), "fcvtzs w22, d23");
  COMPARE(fcvtzu(x16, s17), "fcvtzu x16, s17");
  COMPARE(fcvtzu(w18, s19), "fcvtzu w18, s19");
  COMPARE(fcvtzs(x20, s21), "fcvtzs x20, s21");
  COMPARE(fcvtzs(w22, s23), "fcvtzs w22, s23");
  COMPARE(fcvtzs(w2, d1, 1), "fcvtzs w2, d1, #1");
  COMPARE(fcvtzs(w2, s1, 1), "fcvtzs w2, s1, #1");
  COMPARE(fcvtzs(x4, d3, 15), "fcvtzs x4, d3, #15");
  COMPARE(fcvtzs(x4, s3, 15), "fcvtzs x4, s3, #15");
  COMPARE(fcvtzs(w6, d5, 32), "fcvtzs w6, d5, #32");
  COMPARE(fcvtzs(w6, s5, 32), "fcvtzs w6, s5, #32");
  COMPARE(fjcvtzs(w0, d1), "fjcvtzs w0, d1");
  COMPARE(fcvtzu(w2, d1, 1), "fcvtzu w2, d1, #1");
  COMPARE(fcvtzu(w2, s1, 1), "fcvtzu w2, s1, #1");
  COMPARE(fcvtzu(x4, d3, 15), "fcvtzu x4, d3, #15");
  COMPARE(fcvtzu(x4, s3, 15), "fcvtzu x4, s3, #15");
  COMPARE(fcvtzu(w6, d5, 32), "fcvtzu w6, d5, #32");
  COMPARE(fcvtzu(w6, s5, 32), "fcvtzu w6, s5, #32");
  COMPARE(fcvtpu(x24, d25), "fcvtpu x24, d25");
  COMPARE(fcvtpu(w26, d27), "fcvtpu w26, d27");
  COMPARE(fcvtps(x28, d29), "fcvtps x28, d29");
  COMPARE(fcvtps(w30, d31), "fcvtps w30, d31");
  COMPARE(fcvtpu(x0, s1), "fcvtpu x0, s1");
  COMPARE(fcvtpu(w2, s3), "fcvtpu w2, s3");
  COMPARE(fcvtps(x4, s5), "fcvtps x4, s5");
  COMPARE(fcvtps(w6, s7), "fcvtps w6, s7");
  COMPARE(scvtf(d24, w25), "scvtf d24, w25");
  COMPARE(scvtf(s24, w25), "scvtf s24, w25");
  COMPARE(scvtf(d26, x0), "scvtf d26, x0");
  COMPARE(scvtf(s26, x0), "scvtf s26, x0");
  COMPARE(ucvtf(d28, w29), "ucvtf d28, w29");
  COMPARE(ucvtf(s28, w29), "ucvtf s28, w29");
  COMPARE(ucvtf(d0, x1), "ucvtf d0, x1");
  COMPARE(ucvtf(s0, x1), "ucvtf s0, x1");
  COMPARE(ucvtf(d0, x1, 0), "ucvtf d0, x1");
  COMPARE(ucvtf(s0, x1, 0), "ucvtf s0, x1");
  COMPARE(scvtf(d1, x2, 1), "scvtf d1, x2, #1");
  COMPARE(scvtf(s1, x2, 1), "scvtf s1, x2, #1");
  COMPARE(scvtf(d3, x4, 15), "scvtf d3, x4, #15");
  COMPARE(scvtf(s3, x4, 15), "scvtf s3, x4, #15");
  COMPARE(scvtf(d5, x6, 32), "scvtf d5, x6, #32");
  COMPARE(scvtf(s5, x6, 32), "scvtf s5, x6, #32");
  COMPARE(ucvtf(d7, x8, 2), "ucvtf d7, x8, #2");
  COMPARE(ucvtf(s7, x8, 2), "ucvtf s7, x8, #2");
  COMPARE(ucvtf(d9, x10, 16), "ucvtf d9, x10, #16");
  COMPARE(ucvtf(s9, x10, 16), "ucvtf s9, x10, #16");
  COMPARE(ucvtf(d11, x12, 33), "ucvtf d11, x12, #33");
  COMPARE(ucvtf(s11, x12, 33), "ucvtf s11, x12, #33");
  COMPARE(fcvtms(w0, s1), "fcvtms w0, s1");
  COMPARE(fcvtms(x2, s3), "fcvtms x2, s3");
  COMPARE(fcvtms(w4, d5), "fcvtms w4, d5");
  COMPARE(fcvtms(x6, d7), "fcvtms x6, d7");
  COMPARE(fcvtmu(w8, s9), "fcvtmu w8, s9");
  COMPARE(fcvtmu(x10, s11), "fcvtmu x10, s11");
  COMPARE(fcvtmu(w12, d13), "fcvtmu w12, d13");
  COMPARE(fcvtmu(x14, d15), "fcvtmu x14, d15");

  CLEANUP();
}

TEST_F(DisasmArm64Test, system_mrs) {
  SET_UP_ASM();

  COMPARE(mrs(x0, NZCV), "mrs x0, nzcv");
  COMPARE(mrs(lr, NZCV), "mrs lr, nzcv");
  COMPARE(mrs(x15, FPCR), "mrs x15, fpcr");

  CLEANUP();
}

TEST_F(DisasmArm64Test, system_msr) {
  SET_UP_ASM();

  COMPARE(msr(NZCV, x0), "msr nzcv, x0");
  COMPARE(msr(NZCV, x30), "msr nzcv, lr");
  COMPARE(msr(FPCR, x15), "msr fpcr, x15");

  CLEANUP();
}

TEST_F(DisasmArm64Test, system_nop) {
  {
    SET_UP_ASM();
    COMPARE(nop(), "nop");
    CLEANUP();
  }
  {
    SET_UP_MASM();
    COMPARE(Nop(), "nop");
    CLEANUP();
  }
}

TEST_F(DisasmArm64Test, bti) {
  {
    SET_UP_ASM();

    COMPARE(bti(BranchTargetIdentifier::kBti), "bti");
    COMPARE(bti(BranchTargetIdentifier::kBtiCall), "bti c");
    COMPARE(bti(BranchTargetIdentifier::kBtiJump), "bti j");
    COMPARE(bti(BranchTargetIdentifier::kBtiJumpCall), "bti jc");
    COMPARE(hint(BTI), "bti");
    COMPARE(hint(BTI_c), "bti c");
    COMPARE(hint(BTI_j), "bti j");
    COMPARE(hint(BTI_jc), "bti jc");

    CLEANUP();
  }

  {
    SET_UP_MASM();

    Label dummy1, dummy2, dummy3, dummy4;
    COMPARE(Bind(&dummy1, BranchTargetIdentifier::kBti), "bti");
    COMPARE(Bind(&dummy2, BranchTargetIdentifier::kBtiCall), "bti c");
    COMPARE(Bind(&dummy3, BranchTargetIdentifier::kBtiJump), "bti j");
    COMPARE(Bind(&dummy4, BranchTargetIdentifier::kBtiJumpCall), "bti jc");

    CLEANUP();
  }
}

TEST_F(DisasmArm64Test, system_pauth) {
  SET_UP_ASM();

  COMPARE(pacib1716(), "pacib1716");
  COMPARE(pacibsp(), "pacibsp");
  COMPARE(autib1716(), "autib1716");
  COMPARE(autibsp(), "autibsp");

  CLEANUP();
}

TEST_F(DisasmArm64Test, debug) {
  for (int i = 0; i < 2; i++) {
    // Loop runs with and without the simulator code enabled.
    HandleScope scope(isolate());
    uint8_t* buf = static_cast<uint8_t*>(malloc(INSTR_SIZE));
    uint32_t encoding = 0;
    AssemblerOptions options{};
#ifdef USE_SIMULATOR
    options.enable_simulator_code = (i == 1);
#else
    CHECK(!options.enable_simulator_code);
#endif
    Assembler* assm = new Assembler(i_isolate()->allocator(), options,
                                    ExternalAssemblerBuffer(buf, INSTR_SIZE));
    Decoder<DispatchingDecoderVisitor>* decoder =
        new Decoder<DispatchingDecoderVisitor>();
    DisassemblingDecoder* disasm = new DisassemblingDecoder();
    decoder->AppendVisitor(disasm);

    CHECK_EQ(kImmExceptionIsDebug, 0xdeb0);

    // All debug codes should produce the same instruction, and the debug code
    // can be any uint32_t.
    const char* expected_instruction =
        options.enable_simulator_code ? "hlt #0xdeb0" : "brk #0x0";

    COMPARE(debug("message", 0, BREAK), expected_instruction);
    COMPARE(debug("message", 1, BREAK), expected_instruction);
    COMPARE(debug("message", 0xffff, BREAK), expected_instruction);
    COMPARE(debug("message", 0x10000, BREAK), expected_instruction);
    COMPARE(debug("message", 0x7fffffff, BREAK), expected_instruction);
    COMPARE(debug("message", 0x80000000u, BREAK), expected_instruction);
    COMPARE(debug("message", 0xffffffffu, BREAK), expected_instruction);

    CLEANUP();
  }
}

TEST_F(DisasmArm64Test, hlt) {
  SET_UP_ASM();

  COMPARE(hlt(0), "hlt #0x0");
  COMPARE(hlt(1), "hlt #0x1");
  COMPARE(hlt(65535), "hlt #0xffff");

  CLEANUP();
}

TEST_F(DisasmArm64Test, brk) {
  SET_UP_ASM();

  COMPARE(brk(0), "brk #0x0");
  COMPARE(brk(1), "brk #0x1");
  COMPARE(brk(65535), "brk #0xffff");

  CLEANUP();
}

TEST_F(DisasmArm64Test, add_sub_negative) {
  SET_UP_MASM();

  COMPARE(Add(x10, x0, -42), "sub x10, x0, #0x2a (42)");
  COMPARE(Add(x11, x1, -687), "sub x11, x1, #0x2af (687)");
  COMPARE(Add(x12, x2, -0x88), "sub x12, x2, #0x88 (136)");

  COMPARE(Sub(x13, x0, -600), "add x13, x0, #0x258 (600)");
  COMPARE(Sub(x14, x1, -313), "add x14, x1, #0x139 (313)");
  COMPARE(Sub(x15, x2, -0x555), "add x15, x2, #0x555 (1365)");

  COMPARE(Add(w19, w3, -0x344), "sub w19, w3, #0x344 (836)");
  COMPARE(Add(w20, w4, -2000), "sub w20, w4, #0x7d0 (2000)");

  COMPARE(Sub(w21, w3, -0xbc), "add w21, w3, #0xbc (188)");
  COMPARE(Sub(w22, w4, -2000), "add w22, w4, #0x7d0 (2000)");

  COMPARE(Cmp(w0, -1), "cmn w0, #0x1 (1)");
  COMPARE(Cmp(x1, -1), "cmn x1, #0x1 (1)");
  COMPARE(Cmp(w2, -4095), "cmn w2, #0xfff (4095)");
  COMPARE(Cmp(x3, -4095), "cmn x3, #0xfff (4095)");

  COMPARE(Cmn(w0, -1), "cmp w0, #0x1 (1)");
  COMPARE(Cmn(x1, -1), "cmp x1, #0x1 (1)");
  COMPARE(Cmn(w2, -4095), "cmp w2, #0xfff (4095)");
  COMPARE(Cmn(x3, -4095), "cmp x3, #0xfff (4095)");

  CLEANUP();
}

TEST_F(DisasmArm64Test, logical_immediate_move) {
  SET_UP_MASM();

  COMPARE(And(w0, w1, 0), "movz w0, #0x0");
  COMPARE(And(x0, x1, 0), "movz x0, #0x0");
  COMPARE(Orr(w2, w3, 0), "mov w2, w3");
  COMPARE(Orr(x2, x3, 0), "mov x2, x3");
  COMPARE(Eor(w4, w5, 0), "mov w4, w5");
  COMPARE(Eor(x4, x5, 0), "mov x4, x5");
  COMPARE(Bic(w6, w7, 0), "mov w6, w7");
  COMPARE(Bic(x6, x7, 0), "mov x6, x7");
  COMPARE(Orn(w8, w9, 0), "movn w8, #0x0");
  COMPARE(Orn(x8, x9, 0), "movn x8, #0x0");
  COMPARE(Eon(w10, w11, 0), "mvn w10, w11");
  COMPARE(Eon(x10, x11, 0), "mvn x10, x11");

  COMPARE(And(w12, w13, 0xffffffff), "mov w12, w13");
  COMPARE(And(x12, x13, 0xffffffff), "and x12, x13, #0xffffffff");
  COMPARE(And(x12, x13, 0xffffffffffffffff), "mov x12, x13");
  COMPARE(Orr(w14, w15, 0xffffffff), "movn w14, #0x0");
  COMPARE(Orr(x14, x15, 0xffffffff), "orr x14, x15, #0xffffffff");
  COMPARE(Orr(x14, x15, 0xffffffffffffffff), "movn x14, #0x0");
  COMPARE(Eor(w16, w17, 0xffffffff), "mvn w16, w17");
  COMPARE(Eor(x16, x17, 0xffffffff), "eor x16, x17, #0xffffffff");
  COMPARE(Eor(x16, x17, 0xffffffffffffffff), "mvn x16, x17");
  COMPARE(Bic(w18, w19, 0xffffffff), "movz w18, #0x0");
  COMPARE(Bic(x18, x19, 0xffffffff), "and x18, x19, #0xffffffff00000000");
  COMPARE(Bic(x18, x19, 0xffffffffffffffff), "movz x18, #0x0");
  COMPARE(Orn(w20, w21, 0xffffffff), "mov w20, w21");
  COMPARE(Orn(x20, x21, 0xffffffff), "orr x20, x21, #0xffffffff00000000");
  COMPARE(Orn(x20, x21, 0xffffffffffffffff), "mov x20, x21");
  COMPARE(Eon(w22, w23, 0xffffffff), "mov w22, w23");
  COMPARE(Eon(x22, x23, 0xffffffff), "eor x22, x23, #0xffffffff00000000");
  COMPARE(Eon(x22, x23, 0xffffffffffffffff), "mov x22, x23");

  CLEANUP();
}

TEST_F(DisasmArm64Test, barriers) {
  SET_UP_MASM();

  // DMB
  COMPARE(Dmb(FullSystem, BarrierAll), "dmb sy");
  COMPARE(Dmb(FullSystem, BarrierReads), "dmb ld");
  COMPARE(Dmb(FullSystem, BarrierWrites), "dmb st");

  COMPARE(Dmb(InnerShareable, BarrierAll), "dmb ish");
  COMPARE(Dmb(InnerShareable, BarrierReads), "dmb ishld");
  COMPARE(Dmb(InnerShareable, BarrierWrites), "dmb ishst");

  COMPARE(Dmb(NonShareable, BarrierAll), "dmb nsh");
  COMPARE(Dmb(NonShareable, BarrierReads), "dmb nshld");
  COMPARE(Dmb(NonShareable, BarrierWrites), "dmb nshst");

  COMPARE(Dmb(OuterShareable, BarrierAll), "dmb osh");
  COMPARE(Dmb(OuterShareable, BarrierReads), "dmb oshld");
  COMPARE(Dmb(OuterShareable, BarrierWrites), "dmb oshst");

  COMPARE(Dmb(FullSystem, BarrierOther), "dmb sy (0b1100)");
  COMPARE(Dmb(InnerShareable, BarrierOther), "dmb sy (0b1000)");
  COMPARE(Dmb(NonShareable, BarrierOther), "dmb sy (0b0100)");
  COMPARE(Dmb(OuterShareable, BarrierOther), "dmb sy (0b0000)");

  // DSB
  COMPARE(Dsb(FullSystem, BarrierAll), "dsb sy");
  COMPARE(Dsb(FullSystem, BarrierReads), "dsb ld");
  COMPARE(Dsb(FullSystem, BarrierWrites), "dsb st");

  COMPARE(Dsb(InnerShareable, BarrierAll), "dsb ish");
  COMPARE(Dsb(InnerShareable, BarrierReads), "dsb ishld");
  COMPARE(Dsb(InnerShareable, BarrierWrites), "dsb ishst");

  COMPARE(Dsb(NonShareable, BarrierAll), "dsb nsh");
  COMPARE(Dsb(NonShareable, BarrierReads), "dsb nshld");
  COMPARE(Dsb(NonShareable, BarrierWrites), "dsb nshst");

  COMPARE(Dsb(OuterShareable, BarrierAll), "dsb osh");
  COMPARE(Dsb(OuterShareable, BarrierReads), "dsb oshld");
  COMPARE(Dsb(OuterShareable, BarrierWrites), "dsb oshst");

  COMPARE(Dsb(FullSystem, BarrierOther), "dsb sy (0b1100)");
  COMPARE(Dsb(InnerShareable, BarrierOther), "dsb sy (0b1000)");
  COMPARE(Dsb(NonShareable, BarrierOther), "dsb sy (0b0100)");
  COMPARE(Dsb(OuterShareable, BarrierOther), "dsb sy (0b0000)");

  // ISB
  COMPARE(Isb(), "isb");

  // CSDB
  COMPARE(Csdb(), "csdb");

  CLEANUP();
}

#define VLIST2(v) \
  v, VRegister::Create((v.code() + 1) % 32, v.SizeInBits(), v.LaneCount())
#define VLIST3(v) \
  VLIST2(v)       \
  , VRegister::Create((v.code() + 2) % 32, v.SizeInBits(), v.LaneCount())
#define VLIST4(v) \
  VLIST3(v)       \
  , VRegister::Create((v.code() + 3) % 32, v.SizeInBits(), v.LaneCount())

#define NEON_FORMAT_LIST(V) \
  V(V8B(), "8b")            \
  V(V16B(), "16b")          \
  V(V4H(), "4h")            \
  V(V8H(), "8h")            \
  V(V2S(), "2s")            \
  V(V4S(), "4s")            \
  V(V2D(), "2d")

#define NEON_FORMAT_LIST_LP(V)  \
  V(V4H(), "4h", V8B(), "8b")   \
  V(V2S(), "2s", V4H(), "4h")   \
  V(V1D(), "1d", V2S(), "2s")   \
  V(V8H(), "8h", V16B(), "16b") \
  V(V4S(), "4s", V8H(), "8h")   \
  V(V2D(), "2d", V4S(), "4s")

#define NEON_FORMAT_LIST_LW(V) \
  V(V8H(), "8h", V8B(), "8b")  \
  V(V4S(), "4s", V4H(), "4h")  \
  V(V2D(), "2d", V2S(), "2s")

#define NEON_FORMAT_LIST_LW2(V) \
  V(V8H(), "8h", V16B(), "16b") \
  V(V4S(), "4s", V8H(), "8h")   \
  V(V2D(), "2d", V4S(), "4s")

#define NEON_FORMAT_LIST_BHS(V) \
  V(V8B(), "8b")                \
  V(V16B(), "16b")              \
  V(V4H(), "4h")                \
  V(V8H(), "8h")                \
  V(V2S(), "2s")                \
  V(V4S(), "4s")

#define NEON_FORMAT_LIST_HS(V) \
  V(V4H(), "4h")               \
  V(V8H(), "8h")               \
  V(V2S(), "2s")               \
  V(V4S(), "4s")

#define NEON_FORMAT_LIST_FP(V) \
  V(V4H(), "4h")               \
  V(V8H(), "8h")               \
  V(V2S(), "2s")               \
  V(V4S(), "4s")               \
  V(V2D(), "2d")

TEST_F(DisasmArm64Test, neon_load_store_vector) {
  SET_UP_MASM();

#define DISASM_INST(M, S)                                         \
  COMPARE(Ld1(v0.M, MemOperand(x15)), "ld1 {v0." S "}, [x15]");   \
  COMPARE(Ld1(v1.M, v2.M, MemOperand(x16)),                       \
          "ld1 {v1." S ", v2." S "}, [x16]");                     \
  COMPARE(Ld1(v3.M, v4.M, v5.M, MemOperand(x17)),                 \
          "ld1 {v3." S ", v4." S ", v5." S "}, [x17]");           \
  COMPARE(Ld1(v6.M, v7.M, v8_.M, v9.M, MemOperand(x18)),          \
          "ld1 {v6." S ", v7." S ", v8_." S ", v9." S "}, [x18]") \
  COMPARE(Ld1(v30.M, v31.M, v0.M, v1.M, MemOperand(sp)),          \
          "ld1 {v30." S ", v31." S ", v0." S ", v1." S "}, [sp]") \
  COMPARE(Ld2(v1.M, v2.M, MemOperand(x16)),                       \
          "ld2 {v1." S ", v2." S "}, [x16]");                     \
  COMPARE(Ld3(v3.M, v4.M, v5.M, MemOperand(x17)),                 \
          "ld3 {v3." S ", v4." S ", v5." S "}, [x17]");           \
  COMPARE(Ld4(v6.M, v7.M, v8_.M, v9.M, MemOperand(x18)),          \
          "ld4 {v6." S ", v7." S ", v8." S ", v9." S "}, [x18]")  \
  COMPARE(Ld4(v30.M, v31.M, v0.M, v1.M, MemOperand(sp)),          \
          "ld4 {v30." S ", v31." S ", v0." S ", v1." S "}, [sp]") \
  NEON_FORMAT_LIST(DISASM_INST);
#undef DISASM_INST

#define DISASM_INST(M, S)                                                \
  COMPARE(Ld1(v0.M, MemOperand(x15, x20, PostIndex)),                    \
          "ld1 {v0." S "}, [x15], x20");                                 \
  COMPARE(Ld1(v1.M, v2.M, MemOperand(x16, x21, PostIndex)),              \
          "ld1 {v1." S ", v2." S "}, [x16], x21");                       \
  COMPARE(Ld1(v3.M, v4.M, v5.M, MemOperand(x17, x22, PostIndex)),        \
          "ld1 {v3." S ", v4." S ", v5." S "}, [x17], x22");             \
  COMPARE(Ld1(v6.M, v7.M, v8_.M, v9.M, MemOperand(x18, x23, PostIndex)), \
          "ld1 {v6." S ", v7." S ", v8." S ", v9." S "}, [x18], x23")    \
  COMPARE(Ld1(v30.M, v31.M, v0.M, v1.M, MemOperand(sp, x24, PostIndex)), \
          "ld1 {v30." S ", v31." S ", v0." S ", v1." S "}, [sp], x24")   \
  COMPARE(Ld2(v1.M, v2.M, MemOperand(x16, x21, PostIndex)),              \
          "ld2 {v1." S ", v2." S "}, [x16], x21");                       \
  COMPARE(Ld3(v3.M, v4.M, v5.M, MemOperand(x17, x22, PostIndex)),        \
          "ld3 {v3." S ", v4." S ", v5." S "}, [x17], x22");             \
  COMPARE(Ld4(v6.M, v7.M, v8_.M, v9.M, MemOperand(x18, x23, PostIndex)), \
          "ld4 {v6." S ", v7." S ", v8_." S ", v9." S "}, [x18], x23")   \
  COMPARE(Ld4(v30.M, v31.M, v0.M, v1.M, MemOperand(sp, x24, PostIndex)), \
          "ld4 {v30." S ", v31." S ", v0." S ", v1." S "}, [sp], x24")   \
  NEON_FORMAT_LIST(DISASM_INST);
#undef DISASM_INST

  COMPARE(Ld1(v0.V8B(), MemOperand(x15, 8, PostIndex)),
          "ld1 {v0.8b}, [x15], #8");
  COMPARE(Ld1(v1.V16B(), MemOperand(x16, 16, PostIndex)),
          "ld1 {v1.16b}, [x16], #16");
  COMPARE(Ld1(v2.V4H(), v3.V4H(), MemOperand(x17, 16, PostIndex)),
          "ld1 {v2.4h, v3.4h}, [x17], #16");
  COMPARE(Ld1(v4.V8H(), v5.V8H(), MemOperand(x18, 32, PostIndex)),
          "ld1 {v4.8h, v5.8h}, [x18], #32");
  COMPARE(Ld1(v16.V2S(), v17.V2S(), v18.V2S(), MemOperand(x19, 24, PostIndex)),
          "ld1 {v16.2s, v17.2s, v18.2s}, [x19], #24");
  COMPARE(Ld1(v16.V4S(), v17.V4S(), v18.V4S(), MemOperand(x19, 48, PostIndex)),
          "ld1 {v16.4s, v17.4s, v18.4s}, [x19], #48");
  COMPARE(Ld1(v19.V2S(), v20.V2S(), v21.V2S(), v22.V2S(),
              MemOperand(x20, 32, PostIndex)),
          "ld1 {v19.2s, v20.2s, v21.2s, v22.2s}, [x20], #32");
  COMPARE(Ld1(v23.V2D(), v24.V2D(), v25.V2D(), v26.V2D(),
              MemOperand(x21, 64, PostIndex)),
          "ld1 {v23.2d, v24.2d, v25.2d, v26.2d}, [x21], #64");

  COMPARE(Ld2(v2.V4H(), v3.V4H(), MemOperand(x17, 16, PostIndex)),
          "ld2 {v2.4h, v3.4h}, [x17], #16");
  COMPARE(Ld2(v4.V8H(), v5.V8H(), MemOperand(x18, 32, PostIndex)),
          "ld2 {v4.8h, v5.8h}, [x18], #32");
  COMPARE(Ld3(v16.V2S(), v17.V2S(), v18.V2S(), MemOperand(x19, 24, PostIndex)),
          "ld3 {v16.2s, v17.2s, v18.2s}, [x19], #24");
  COMPARE(Ld3(v16.V4S(), v17.V4S(), v18.V4S(), MemOperand(x19, 48, PostIndex)),
          "ld3 {v16.4s, v17.4s, v18.4s}, [x19], #48");
  COMPARE(Ld4(v19.V2S(), v20.V2S(), v21.V2S(), v22.V2S(),
              MemOperand(x20, 32, PostIndex)),
          "ld4 {v19.2s, v20.2s, v21.2s, v22.2s}, [x20], #32");
  COMPARE(Ld4(v23.V2D(), v24.V2D(), v25.V2D(), v26.V2D(),
              MemOperand(x21, 64, PostIndex)),
          "ld4 {v23.2d, v24.2d, v25.2d, v26.2d}, [x21], #64");

  COMPARE(Ld1(v0.V1D(), MemOperand(x16)), "ld1 {v0.1d}, [x16]");
  COMPARE(Ld1(v1.V1D(), v2.V1D(), MemOperand(x17, 16, PostIndex)),
          "ld1 {v1.1d, v2.1d}, [x17], #16");
  COMPARE(Ld1(v3.V1D(), v4.V1D(), v5.V1D(), MemOperand(x18, x19, PostIndex)),
          "ld1 {v3.1d, v4.1d, v5.1d}, [x18], x19");
  COMPARE(Ld1(v30.V1D(), v31.V1D(), v0.V1D(), v1.V1D(),
              MemOperand(x20, 32, PostIndex)),
          "ld1 {v30.1d, v31.1d, v0.1d, v1.1d}, [x20], #32");
  COMPARE(Ld1(d30, d31, d0, d1, MemOperand(x21, x22, PostIndex)),
          "ld1 {v30.1d, v31.1d, v0.1d, v1.1d}, [x21], x22");

#define DISASM_INST(M, S)                                            \
  COMPARE(St1(v20.M, MemOperand(x15)), "st1 {v20." S "}, [x15]");    \
  COMPARE(St1(v21.M, v22.M, MemOperand(x16)),                        \
          "st1 {v21." S ", v22." S "}, [x16]");                      \
  COMPARE(St1(v23.M, v24.M, v25.M, MemOperand(x17)),                 \
          "st1 {v23." S ", v24." S ", v25." S "}, [x17]");           \
  COMPARE(St1(v26.M, v27.M, v28.M, v29.M, MemOperand(x18)),          \
          "st1 {v26." S ", v27." S ", v28." S ", v29." S "}, [x18]") \
  COMPARE(St1(v30.M, v31.M, v0.M, v1.M, MemOperand(sp)),             \
          "st1 {v30." S ", v31." S ", v0." S ", v1." S "}, [sp]")    \
  COMPARE(St2(VLIST2(v21.M), MemOperand(x16)),                       \
          "st2 {v21." S ", v22." S "}, [x16]");                      \
  COMPARE(St3(v23.M, v24.M, v25.M, MemOperand(x17)),                 \
          "st3 {v23." S ", v24." S ", v25." S "}, [x17]");           \
  COMPARE(St4(v30.M, v31.M, v0.M, v1.M, MemOperand(sp)),             \
          "st4 {v30." S ", v31." S ", v0." S ", v1." S "}, [sp]")
  NEON_FORMAT_LIST(DISASM_INST);
#undef DISASM_INST

#define DISASM_INST(M, S)                                                \
  COMPARE(St1(v0.M, MemOperand(x15, x20, PostIndex)),                    \
          "st1 {v0." S "}, [x15], x20");                                 \
  COMPARE(St1(v1.M, v2.M, MemOperand(x16, x21, PostIndex)),              \
          "st1 {v1." S ", v2." S "}, [x16], x21");                       \
  COMPARE(St1(v3.M, v4.M, v5.M, MemOperand(x17, x22, PostIndex)),        \
          "st1 {v3." S ", v4." S ", v5." S "}, [x17], x22");             \
  COMPARE(St1(v6.M, v7.M, v8_.M, v9.M, MemOperand(x18, x23, PostIndex)), \
          "st1 {v6." S ", v7." S ", v8." S ", v9." S "}, [x18], x23")    \
  COMPARE(St1(v30.M, v31.M, v0.M, v1.M, MemOperand(sp, x24, PostIndex)), \
          "st1 {v30." S ", v31." S ", v0." S ", v1." S "}, [sp], x24")   \
  COMPARE(St2(v1.M, v2.M, MemOperand(x16, x21, PostIndex)),              \
          "st2 {v1." S ", v2." S "}, [x16], x21");                       \
  COMPARE(St3(v3.M, v4.M, v5.M, MemOperand(x17, x22, PostIndex)),        \
          "st3 {v3." S ", v4." S ", v5." S "}, [x17], x22");             \
  COMPARE(St4(v6.M, v7.M, v8_.M, v9.M, MemOperand(x18, x23, PostIndex)), \
          "st4 {v6." S ", v7." S ", v8." S ", v9." S "}, [x18], x23")    \
  COMPARE(St4(v30.M, v31.M, v0.M, v1.M, MemOperand(sp, x24, PostIndex)), \
          "st4 {v30." S ", v31." S ", v0." S ", v1." S "}, [sp], x24")
  NEON_FORMAT_LIST(DISASM_INST);
#undef DISASM_INST

  COMPARE(St1(v0.V8B(), MemOperand(x15, 8, PostIndex)),
          "st1 {v0.8b}, [x15], #8");
  COMPARE(St1(v1.V16B(), MemOperand(x16, 16, PostIndex)),
          "st1 {v1.16b}, [x16], #16");
  COMPARE(St1(v2.V4H(), v3.V4H(), MemOperand(x17, 16, PostIndex)),
          "st1 {v2.4h, v3.4h}, [x17], #16");
  COMPARE(St1(v4.V8H(), v5.V8H(), MemOperand(x18, 32, PostIndex)),
          "st1 {v4.8h, v5.8h}, [x18], #32");
  COMPARE(St1(v16.V2S(), v17.V2S(), v18.V2S(), MemOperand(x19, 24, PostIndex)),
          "st1 {v16.2s, v17.2s, v18.2s}, [x19], #24");
  COMPARE(St1(v16.V4S(), v17.V4S(), v18.V4S(), MemOperand(x19, 48, PostIndex)),
          "st1 {v16.4s, v17.4s, v18.4s}, [x19], #48");
  COMPARE(St1(v19.V2S(), v20.V2S(), v21.V2S(), v22.V2S(),
              MemOperand(x20, 32, PostIndex)),
          "st1 {v19.2s, v20.2s, v21.2s, v22.2s}, [x20], #32");
  COMPARE(St1(v23.V2D(), v24.V2D(), v25.V2D(), v26.V2D(),
              MemOperand(x21, 64, PostIndex)),
          "st1 {v23.2d, v24.2d, v25.2d, v26.2d}, [x21], #64");
  COMPARE(St2(v1.V16B(), v2.V16B(), MemOperand(x16, 32, PostIndex)),
          "st2 {v1.16b, v2.16b}, [x16], #32");
  COMPARE(St2(v2.V4H(), v3.V4H(), MemOperand(x17, 16, PostIndex)),
          "st2 {v2.4h, v3.4h}, [x17], #16");
  COMPARE(St2(v4.V8H(), v5.V8H(), MemOperand(x18, 32, PostIndex)),
          "st2 {v4.8h, v5.8h}, [x18], #32");
  COMPARE(St3(v16.V2S(), v17.V2S(), v18.V2S(), MemOperand(x19, 24, PostIndex)),
          "st3 {v16.2s, v17.2s, v18.2s}, [x19], #24");
  COMPARE(St3(v16.V4S(), v17.V4S(), v18.V4S(), MemOperand(x19, 48, PostIndex)),
          "st3 {v16.4s, v17.4s, v18.4s}, [x19], #48");
  COMPARE(St4(v19.V2S(), v20.V2S(), v21.V2S(), v22.V2S(),
              MemOperand(x20, 32, PostIndex)),
          "st4 {v19.2s, v20.2s, v21.2s, v22.2s}, [x20], #32");
  COMPARE(St4(v23.V2D(), v24.V2D(), v25.V2D(), v26.V2D(),
              MemOperand(x21, 64, PostIndex)),
          "st4 {v23.2d, v24.2d, v25.2d, v26.2d}, [x21], #64");

  COMPARE(St1(v0.V1D(), MemOperand(x16)), "st1 {v0.1d}, [x16]");
  COMPARE(St1(v1.V1D(), v2.V1D(), MemOperand(x17, 16, PostIndex)),
          "st1 {v1.1d, v2.1d}, [x17], #16");
  COMPARE(St1(v3.V1D(), v4.V1D(), v5.V1D(), MemOperand(x18, x19, PostIndex)),
          "st1 {v3.1d, v4.1d, v5.1d}, [x18], x19");
  COMPARE(St1(v30.V1D(), v31.V1D(), v0.V1D(), v1.V1D(),
              MemOperand(x20, 32, PostIndex)),
          "st1 {v30.1d, v31.1d, v0.1d, v1.1d}, [x20], #32");
  COMPARE(St1(d30, d31, d0, d1, MemOperand(x21, x22, PostIndex)),
          "st1 {v30.1d, v31.1d, v0.1d, v1.1d}, [x21], x22");

  CLEANUP();
}

TEST_F(DisasmArm64Test, neon_load_store_vector_unallocated) {
  SET_UP_MASM();

  const char* expected = "unallocated (NEONLoadStoreMultiStruct)";
  // LD[1-4] (multiple structures) (no offset)
  COMPARE(dci(0x0c401000), expected);  // opcode = 0b0001
  COMPARE(dci(0x0c403000), expected);  // opcode = 0b0011
  COMPARE(dci(0x0c405000), expected);  // opcode = 0b0101
  COMPARE(dci(0x0c409000), expected);  // opcode = 0b1001
  COMPARE(dci(0x0c40b000), expected);  // opcode = 0b1011
  COMPARE(dci(0x0c40c000), expected);  // opcode = 0b1100
  COMPARE(dci(0x0c40d000), expected);  // opcode = 0b1101
  COMPARE(dci(0x0c40e000), expected);  // opcode = 0b1110
  COMPARE(dci(0x0c40f000), expected);  // opcode = 0b1111
  COMPARE(dci(0x0c400c00), expected);  // opcode = 0b0000, size:Q = 0b110
  COMPARE(dci(0x0c404c00), expected);  // opcode = 0b0100, size:Q = 0b110
  COMPARE(dci(0x0c408c00), expected);  // opcode = 0b1000, size:Q = 0b110

  // ST[1-4] (multiple structures) (no offset)
  COMPARE(dci(0x0c001000), expected);  // opcode = 0b0001
  COMPARE(dci(0x0c003000), expected);  // opcode = 0b0011
  COMPARE(dci(0x0c005000), expected);  // opcode = 0b0101
  COMPARE(dci(0x0c009000), expected);  // opcode = 0b1001
  COMPARE(dci(0x0c00b000), expected);  // opcode = 0b1011
  COMPARE(dci(0x0c00c000), expected);  // opcode = 0b1100
  COMPARE(dci(0x0c00d000), expected);  // opcode = 0b1101
  COMPARE(dci(0x0c00e000), expected);  // opcode = 0b1110
  COMPARE(dci(0x0c00f000), expected);  // opcode = 0b1111
  COMPARE(dci(0x0c000c00), expected);  // opcode = 0b0000, size:Q = 0b110
  COMPARE(dci(0x0c004c00), expected);  // opcode = 0b0100, size:Q = 0b110
  COMPARE(dci(0x0c008c00), expected);  // opcode = 0b1000, size:Q = 0b110

  expected = "unallocated (NEONLoadStoreMultiStructPostIndex)";
  // LD[1-4] (multiple structures) (post index)
  COMPARE(dci(0x0cc01000), expected);  // opcode = 0b0001
  COMPARE(dci(0x0cc03000), expected);  // opcode = 0b0011
  COMPARE(dci(0x0cc05000), expected);  // opcode = 0b0101
  COMPARE(dci(0x0cc09000), expected);  // opcode = 0b1001
  COMPARE(dci(0x0cc0b000), expected);  // opcode = 0b1011
  COMPARE(dci(0x0cc0c000), expected);  // opcode = 0b1100
  COMPARE(dci(0x0cc0d000), expected);  // opcode = 0b1101
  COMPARE(dci(0x0cc0e000), expected);  // opcode = 0b1110
  COMPARE(dci(0x0cc0f000), expected);  // opcode = 0b1111
  COMPARE(dci(0x0cc00c00), expected);  // opcode = 0b0000, size:Q = 0b110
  COMPARE(dci(0x0cc04c00), expected);  // opcode = 0b0100, size:Q = 0b110
  COMPARE(dci(0x0cc08c00), expected);  // opcode = 0b1000, size:Q = 0b110

  // ST[1-4] (multiple structures) (post index)
  COMPARE(dci(0x0c801000), expected);  // opcode = 0b0001
  COMPARE(dci(0x0c803000), expected);  // opcode = 0b0011
  COMPARE(dci(0x0c805000), expected);  // opcode = 0b0101
  COMPARE(dci(0x0c809000), expected);  // opcode = 0b1001
  COMPARE(dci(0x0c80b000), expected);  // opcode = 0b1011
  COMPARE(dci(0x0c80c000), expected);  // opcode = 0b1100
  COMPARE(dci(0x0c80d000), expected);  // opcode = 0b1101
  COMPARE(dci(0x0c80e000), expected);  // opcode = 0b1110
  COMPARE(dci(0x0c80f000), expected);  // opcode = 0b1111
  COMPARE(dci(0x0c800c00), expected);  // opcode = 0b0000, size:Q = 0b110
  COMPARE(dci(0x0c804c00), expected);  // opcode = 0b0100, size:Q = 0b110
  COMPARE(dci(0x0c808c00), expected);  // opcode = 0b1000, size:Q = 0b110

  CLEANUP();
}

TEST_F(DisasmArm64Test, neon_load_store_lane) {
  SET_UP_MASM();

  COMPARE(Ld1(v0.V8B(), 0, MemOperand(x15)), "ld1 {v0.b}[0], [x15]");
  COMPARE(Ld1(v1.V16B(), 1, MemOperand(x16)), "ld1 {v1.b}[1], [x16]");
  COMPARE(Ld1(v2.V4H(), 2, MemOperand(x17)), "ld1 {v2.h}[2], [x17]");
  COMPARE(Ld1(v3.V8H(), 3, MemOperand(x18)), "ld1 {v3.h}[3], [x18]");
  COMPARE(Ld1(v4.V2S(), 0, MemOperand(x19)), "ld1 {v4.s}[0], [x19]");
  COMPARE(Ld1(v5.V4S(), 1, MemOperand(x20)), "ld1 {v5.s}[1], [x20]");
  COMPARE(Ld1(v6.V2D(), 0, MemOperand(x21)), "ld1 {v6.d}[0], [x21]");
  COMPARE(Ld1(v7.B(), 7, MemOperand(x22)), "ld1 {v7.b}[7], [x22]");
  COMPARE(Ld1(v8_.B(), 15, MemOperand(x23)), "ld1 {v8.b}[15], [x23]");
  COMPARE(Ld1(v9.H(), 3, MemOperand(x24)), "ld1 {v9.h}[3], [x24]");
  COMPARE(Ld1(v10.H(), 7, MemOperand(x25)), "ld1 {v10.h}[7], [x25]");
  COMPARE(Ld1(v11.S(), 1, MemOperand(x26)), "ld1 {v11.s}[1], [x26]");
  COMPARE(Ld1(v12.S(), 3, MemOperand(x27)), "ld1 {v12.s}[3], [cp]");
  COMPARE(Ld1(v13.D(), 1, MemOperand(sp)), "ld1 {v13.d}[1], [sp]");

  COMPARE(Ld1(v0.V8B(), 0, MemOperand(x15, x0, PostIndex)),
          "ld1 {v0.b}[0], [x15], x0");
  COMPARE(Ld1(v1.V16B(), 1, MemOperand(x16, 1, PostIndex)),
          "ld1 {v1.b}[1], [x16], #1");
  COMPARE(Ld1(v2.V4H(), 2, MemOperand(x17, 2, PostIndex)),
          "ld1 {v2.h}[2], [x17], #2");
  COMPARE(Ld1(v3.V8H(), 3, MemOperand(x18, x1, PostIndex)),
          "ld1 {v3.h}[3], [x18], x1");
  COMPARE(Ld1(v4.V2S(), 0, MemOperand(x19, x2, PostIndex)),
          "ld1 {v4.s}[0], [x19], x2");
  COMPARE(Ld1(v5.V4S(), 1, MemOperand(x20, 4, PostIndex)),
          "ld1 {v5.s}[1], [x20], #4");
  COMPARE(Ld1(v6.V2D(), 0, MemOperand(x21, 8, PostIndex)),
          "ld1 {v6.d}[0], [x21], #8");
  COMPARE(Ld1(v7.B(), 7, MemOperand(x22, 1, PostIndex)),
          "ld1 {v7.b}[7], [x22], #1");
  COMPARE(Ld1(v8_.B(), 15, MemOperand(x23, x3, PostIndex)),
          "ld1 {v8.b}[15], [x23], x3");
  COMPARE(Ld1(v9.H(), 3, MemOperand(x24, x4, PostIndex)),
          "ld1 {v9.h}[3], [x24], x4");
  COMPARE(Ld1(v10.H(), 7, MemOperand(x25, 2, PostIndex)),
          "ld1 {v10.h}[7], [x25], #2");
  COMPARE(Ld1(v11.S(), 1, MemOperand(x26, 4, PostIndex)),
          "ld1 {v11.s}[1], [x26], #4");
  COMPARE(Ld1(v12.S(), 3, MemOperand(x27, x5, PostIndex)),
          "ld1 {v12.s}[3], [cp], x5");
  COMPARE(Ld1(v12.S(), 3, MemOperand(x27, 4, PostIndex)),
          "ld1 {v12.s}[3], [cp], #4");
  COMPARE(Ld1(v13.D(), 1, MemOperand(sp, x6, PostIndex)),
          "ld1 {v13.d}[1], [sp], x6");
  COMPARE(Ld1(v13.D(), 1, MemOperand(sp, 8, PostIndex)),
          "ld1 {v13.d}[1], [sp], #8");

  COMPARE(Ld2(v0.V8B(), v1.V8B(), 0, MemOperand(x15)),
          "ld2 {v0.b, v1.b}[0], [x15]");
  COMPARE(Ld2(v1.V16B(), v2.V16B(), 1, MemOperand(x16)),
          "ld2 {v1.b, v2.b}[1], [x16]");
  COMPARE(Ld2(v2.V4H(), v3.V4H(), 2, MemOperand(x17)),
          "ld2 {v2.h, v3.h}[2], [x17]");
  COMPARE(Ld2(v3.V8H(), v4.V8H(), 3, MemOperand(x18)),
          "ld2 {v3.h, v4.h}[3], [x18]");
  COMPARE(Ld2(v4.V2S(), v5.V2S(), 0, MemOperand(x19)),
          "ld2 {v4.s, v5.s}[0], [x19]");
  COMPARE(Ld2(v5.V4S(), v6.V4S(), 1, MemOperand(x20)),
          "ld2 {v5.s, v6.s}[1], [x20]");
  COMPARE(Ld2(v6.V2D(), v7.V2D(), 0, MemOperand(x21)),
          "ld2 {v6.d, v7.d}[0], [x21]");
  COMPARE(Ld2(v7.B(), v8_.B(), 7, MemOperand(x22)),
          "ld2 {v7.b, v8.b}[7], [x22]");
  COMPARE(Ld2(v8_.B(), v9.B(), 15, MemOperand(x23)),
          "ld2 {v8.b, v9.b}[15], [x23]");
  COMPARE(Ld2(v9.H(), v10.H(), 3, MemOperand(x24)),
          "ld2 {v9.h, v10.h}[3], [x24]");
  COMPARE(Ld2(v10.H(), v11.H(), 7, MemOperand(x25)),
          "ld2 {v10.h, v11.h}[7], [x25]");
  COMPARE(Ld2(v11.S(), v12.S(), 1, MemOperand(x26)),
          "ld2 {v11.s, v12.s}[1], [x26]");
  COMPARE(Ld2(v12.S(), v13.S(), 3, MemOperand(x27)),
          "ld2 {v12.s, v13.s}[3], [cp]");
  COMPARE(Ld2(v13.D(), v14.D(), 1, MemOperand(sp)),
          "ld2 {v13.d, v14.d}[1], [sp]");

  COMPARE(Ld2(v0.V8B(), v1.V8B(), 0, MemOperand(x15, x0, PostIndex)),
          "ld2 {v0.b, v1.b}[0], [x15], x0");
  COMPARE(Ld2(v1.V16B(), v2.V16B(), 1, MemOperand(x16, 2, PostIndex)),
          "ld2 {v1.b, v2.b}[1], [x16], #2");
  COMPARE(Ld2(v2.V4H(), v3.V4H(), 2, MemOperand(x17, 4, PostIndex)),
          "ld2 {v2.h, v3.h}[2], [x17], #4");
  COMPARE(Ld2(v3.V8H(), v4.V8H(), 3, MemOperand(x18, x1, PostIndex)),
          "ld2 {v3.h, v4.h}[3], [x18], x1");
  COMPARE(Ld2(v4.V2S(), v5.V2S(), 0, MemOperand(x19, x2, PostIndex)),
          "ld2 {v4.s, v5.s}[0], [x19], x2");
  COMPARE(Ld2(v5.V4S(), v6.V4S(), 1, MemOperand(x20, 8, PostIndex)),
          "ld2 {v5.s, v6.s}[1], [x20], #8");
  COMPARE(Ld2(v6.V2D(), v7.V2D(), 0, MemOperand(x21, 16, PostIndex)),
          "ld2 {v6.d, v7.d}[0], [x21], #16");
  COMPARE(Ld2(v7.B(), v8_.B(), 7, MemOperand(x22, 2, PostIndex)),
          "ld2 {v7.b, v8.b}[7], [x22], #2");
  COMPARE(Ld2(v8_.B(), v9.B(), 15, MemOperand(x23, x3, PostIndex)),
          "ld2 {v8.b, v9.b}[15], [x23], x3");
  COMPARE(Ld2(v9.H(), v10.H(), 3, MemOperand(x24, x4, PostIndex)),
          "ld2 {v9.h, v10.h}[3], [x24], x4");
  COMPARE(Ld2(v10.H(), v11.H(), 7, MemOperand(x25, 4, PostIndex)),
          "ld2 {v10.h, v11.h}[7], [x25], #4");
  COMPARE(Ld2(v11.S(), v12.S(), 1, MemOperand(x26, 8, PostIndex)),
          "ld2 {v11.s, v12.s}[1], [x26], #8");
  COMPARE(Ld2(v12.S(), v13.S(), 3, MemOperand(x27, x5, PostIndex)),
          "ld2 {v12.s, v13.s}[3], [cp], x5");
  COMPARE(Ld2(v11.S(), v12.S(), 3, MemOperand(x26, 8, PostIndex)),
          "ld2 {v11.s, v12.s}[3], [x26], #8");
  COMPARE(Ld2(v13.D(), v14.D(), 1, MemOperand(sp, x6, PostIndex)),
          "ld2 {v13.d, v14.d}[1], [sp], x6");
  COMPARE(Ld2(v13.D(), v14.D(), 1, MemOperand(sp, 16, PostIndex)),
          "ld2 {v13.d, v14.d}[1], [sp], #16");

  COMPARE(Ld3(v0.V8B(), v1.V8B(), v2.V8B(), 0, MemOperand(x15)),
          "ld3 {v0.b, v1.b, v2.b}[0], [x15]");
  COMPARE(Ld3(v1.V16B(), v2.V16B(), v3.V16B(), 1, MemOperand(x16)),
          "ld3 {v1.b, v2.b, v3.b}[1], [x16]");
  COMPARE(Ld3(v2.V4H(), v3.V4H(), v4.V4H(), 2, MemOperand(x17)),
          "ld3 {v2.h, v3.h, v4.h}[2], [x17]");
  COMPARE(Ld3(v3.V8H(), v4.V8H(), v5.V8H(), 3, MemOperand(x18)),
          "ld3 {v3.h, v4.h, v5.h}[3], [x18]");
  COMPARE(Ld3(v4.V2S(), v5.V2S(), v6.V2S(), 0, MemOperand(x19)),
          "ld3 {v4.s, v5.s, v6.s}[0], [x19]");
  COMPARE(Ld3(v5.V4S(), v6.V4S(), v7.V4S(), 1, MemOperand(x20)),
          "ld3 {v5.s, v6.s, v7.s}[1], [x20]");
  COMPARE(Ld3(v6.V2D(), v7.V2D(), v8_.V2D(), 0, MemOperand(x21)),
          "ld3 {v6.d, v7.d, v8.d}[0], [x21]");
  COMPARE(Ld3(v7.B(), v8_.B(), v9.B(), 7, MemOperand(x22)),
          "ld3 {v7.b, v8.b, v9.b}[7], [x22]");
  COMPARE(Ld3(v8_.B(), v9.B(), v10.B(), 15, MemOperand(x23)),
          "ld3 {v8.b, v9.b, v10.b}[15], [x23]");
  COMPARE(Ld3(v9.H(), v10.H(), v11.H(), 3, MemOperand(x24)),
          "ld3 {v9.h, v10.h, v11.h}[3], [x24]");
  COMPARE(Ld3(v10.H(), v11.H(), v12.H(), 7, MemOperand(x25)),
          "ld3 {v10.h, v11.h, v12.h}[7], [x25]");
  COMPARE(Ld3(v11.S(), v12.S(), v13.S(), 1, MemOperand(x26)),
          "ld3 {v11.s, v12.s, v13.s}[1], [x26]");
  COMPARE(Ld3(v12.S(), v13.S(), v14.S(), 3, MemOperand(x27)),
          "ld3 {v12.s, v13.s, v14.s}[3], [cp]");
  COMPARE(Ld3(v13.D(), v14.D(), v15.D(), 1, MemOperand(sp)),
          "ld3 {v13.d, v14.d, v15.d}[1], [sp]");

  COMPARE(Ld3(v0.V8B(), v1.V8B(), v2.V8B(), 0, MemOperand(x15, x0, PostIndex)),
          "ld3 {v0.b, v1.b, v2.b}[0], [x15], x0");
  COMPARE(
      Ld3(v1.V16B(), v2.V16B(), v3.V16B(), 1, MemOperand(x16, 3, PostIndex)),
      "ld3 {v1.b, v2.b, v3.b}[1], [x16], #3");
  COMPARE(Ld3(v2.V4H(), v3.V4H(), v4.V4H(), 2, MemOperand(x17, 6, PostIndex)),
          "ld3 {v2.h, v3.h, v4.h}[2], [x17], #6");
  COMPARE(Ld3(v3.V8H(), v4.V8H(), v5.V8H(), 3, MemOperand(x18, x1, PostIndex)),
          "ld3 {v3.h, v4.h, v5.h}[3], [x18], x1");
  COMPARE(Ld3(v4.V2S(), v5.V2S(), v6.V2S(), 0, MemOperand(x19, x2, PostIndex)),
          "ld3 {v4.s, v5.s, v6.s}[0], [x19], x2");
  COMPARE(Ld3(v5.V4S(), v6.V4S(), v7.V4S(), 1, MemOperand(x20, 12, PostIndex)),
          "ld3 {v5.s, v6.s, v7.s}[1], [x20], #12");
  COMPARE(Ld3(v6.V2D(), v7.V2D(), v8_.V2D(), 0, MemOperand(x21, 24, PostIndex)),
          "ld3 {v6.d, v7.d, v8.d}[0], [x21], #24");
  COMPARE(Ld3(v7.B(), v8_.B(), v9.B(), 7, MemOperand(x22, 3, PostIndex)),
          "ld3 {v7.b, v8.b, v9.b}[7], [x22], #3");
  COMPARE(Ld3(v8_.B(), v9.B(), v10.B(), 15, MemOperand(x23, x3, PostIndex)),
          "ld3 {v8.b, v9.b, v10.b}[15], [x23], x3");
  COMPARE(Ld3(v9.H(), v10.H(), v11.H(), 3, MemOperand(x24, x4, PostIndex)),
          "ld3 {v9.h, v10.h, v11.h}[3], [x24], x4");
  COMPARE(Ld3(v10.H(), v11.H(), v12.H(), 7, MemOperand(x25, 6, PostIndex)),
          "ld3 {v10.h, v11.h, v12.h}[7], [x25], #6");
  COMPARE(Ld3(v11.S(), v12.S(), v13.S(), 1, MemOperand(x26, 12, PostIndex)),
          "ld3 {v11.s, v12.s, v13.s}[1], [x26], #12");
  COMPARE(Ld3(v12.S(), v13.S(), v14.S(), 3, MemOperand(x27, x5, PostIndex)),
          "ld3 {v12.s, v13.s, v14.s}[3], [cp], x5");
  COMPARE(Ld3(v12.S(), v13.S(), v14.S(), 3, MemOperand(x27, 12, PostIndex)),
          "ld3 {v12.s, v13.s, v14.s}[3], [cp], #12");
  COMPARE(Ld3(v13.D(), v14.D(), v15.D(), 1, MemOperand(sp, x6, PostIndex)),
          "ld3 {v13.d, v14.d, v15.d}[1], [sp], x6");
  COMPARE(Ld3(v13.D(), v14.D(), v15.D(), 1, MemOperand(sp, 24, PostIndex)),
          "ld3 {v13.d, v14.d, v15.d}[1], [sp], #24");

  COMPARE(Ld4(v0.V8B(), v1.V8B(), v2.V8B(), v3.V8B(), 0, MemOperand(x15)),
          "ld4 {v0.b, v1.b, v2.b, v3.b}[0], [x15]");
  COMPARE(Ld4(v1.V16B(), v2.V16B(), v3.V16B(), v4.V16B(), 1, MemOperand(x16)),
          "ld4 {v1.b, v2.b, v3.b, v4.b}[1], [x16]");
  COMPARE(Ld4(v2.V4H(), v3.V4H(), v4.V4H(), v5.V4H(), 2, MemOperand(x17)),
          "ld4 {v2.h, v3.h, v4.h, v5.h}[2], [x17]");
  COMPARE(Ld4(v3.V8H(), v4.V8H(), v5.V8H(), v6.V8H(), 3, MemOperand(x18)),
          "ld4 {v3.h, v4.h, v5.h, v6.h}[3], [x18]");
  COMPARE(Ld4(v4.V2S(), v5.V2S(), v6.V2S(), v7.V2S(), 0, MemOperand(x19)),
          "ld4 {v4.s, v5.s, v6.s, v7.s}[0], [x19]");
  COMPARE(Ld4(v5.V4S(), v6.V4S(), v7.V4S(), v8_.V4S(), 1, MemOperand(x20)),
          "ld4 {v5.s, v6.s, v7.s, v8.s}[1], [x20]");
  COMPARE(Ld4(v6.V2D(), v7.V2D(), v8_.V2D(), v9.V2D(), 0, MemOperand(x21)),
          "ld4 {v6.d, v7.d, v8.d, v9.d}[0], [x21]");
  COMPARE(Ld4(v7.B(), v8_.B(), v9.B(), v10.B(), 7, MemOperand(x22)),
          "ld4 {v7.b, v8.b, v9.b, v10.b}[7], [x22]");
  COMPARE(Ld4(v8_.B(), v9.B(), v10.B(), v11.B(), 15, MemOperand(x23)),
          "ld4 {v8.b, v9.b, v10.b, v11.b}[15], [x23]");
  COMPARE(Ld4(v9.H(), v10.H(), v11.H(), v12.H(), 3, MemOperand(x24)),
          "ld4 {v9.h, v10.h, v11.h, v12.h}[3], [x24]");
  COMPARE(Ld4(v10.H(), v11.H(), v12.H(), v13.H(), 7, MemOperand(x25)),
          "ld4 {v10.h, v11.h, v12.h, v13.h}[7], [x25]");
  COMPARE(Ld4(v11.S(), v12.S(), v13.S(), v14.S(), 1, MemOperand(x26)),
          "ld4 {v11.s, v12.s, v13.s, v14.s}[1], [x26]");
  COMPARE(Ld4(v12.S(), v13.S(), v14.S(), v15.S(), 3, MemOperand(x27)),
          "ld4 {v12.s, v13.s, v14.s, v15.s}[3], [cp]");
  COMPARE(Ld4(v13.D(), v14.D(), v15.D(), v16.D(), 1, MemOperand(sp)),
          "ld4 {v13.d, v14.d, v15.d, v16.d}[1], [sp]");

  COMPARE(Ld4(v0.V8B(), v1.V8B(), v2.V8B(), v3.V8B(), 0,
              MemOperand(x15, x0, PostIndex)),
          "ld4 {v0.b, v1.b, v2.b, v3.b}[0], [x15], x0");
  COMPARE(Ld4(v1.V16B(), v2.V16B(), v3.V16B(), v4.V16B(), 1,
              MemOperand(x16, 4, PostIndex)),
          "ld4 {v1.b, v2.b, v3.b, v4.b}[1], [x16], #4");
  COMPARE(Ld4(v2.V4H(), v3.V4H(), v4.V4H(), v5.V4H(), 2,
              MemOperand(x17, 8, PostIndex)),
          "ld4 {v2.h, v3.h, v4.h, v5.h}[2], [x17], #8");
  COMPARE(Ld4(v3.V8H(), v4.V8H(), v5.V8H(), v6.V8H(), 3,
              MemOperand(x18, x1, PostIndex)),
          "ld4 {v3.h, v4.h, v5.h, v6.h}[3], [x18], x1");
  COMPARE(Ld4(v4.V2S(), v5.V2S(), v6.V2S(), v7.V2S(), 0,
              MemOperand(x19, x2, PostIndex)),
          "ld4 {v4.s, v5.s, v6.s, v7.s}[0], [x19], x2");
  COMPARE(Ld4(v5.V4S(), v6.V4S(), v7.V4S(), v8_.V4S(), 1,
              MemOperand(x20, 16, PostIndex)),
          "ld4 {v5.s, v6.s, v7.s, v8.s}[1], [x20], #16");
  COMPARE(Ld4(v6.V2D(), v7.V2D(), v8_.V2D(), v9.V2D(), 0,
              MemOperand(x21, 32, PostIndex)),
          "ld4 {v6.d, v7.d, v8.d, v9.d}[0], [x21], #32");
  COMPARE(
      Ld4(v7.B(), v8_.B(), v9.B(), v10.B(), 7, MemOperand(x22, 4, PostIndex)),
      "ld4 {v7.b, v8.b, v9.b, v10.b}[7], [x22], #4");
  COMPARE(Ld4(v8_.B(), v9.B(), v10.B(), v11.B(), 15,
              MemOperand(x23, x3, PostIndex)),
          "ld4 {v8.b, v9.b, v10.b, v11.b}[15], [x23], x3");
  COMPARE(
      Ld4(v9.H(), v10.H(), v11.H(), v12.H(), 3, MemOperand(x24, x4, PostIndex)),
      "ld4 {v9.h, v10.h, v11.h, v12.h}[3], [x24], x4");
  COMPARE(
      Ld4(v10.H(), v11.H(), v12.H(), v13.H(), 7, MemOperand(x25, 8, PostIndex)),
      "ld4 {v10.h, v11.h, v12.h, v13.h}[7], [x25], #8");
  COMPARE(Ld4(v11.S(), v12.S(), v13.S(), v14.S(), 1,
              MemOperand(x26, 16, PostIndex)),
          "ld4 {v11.s, v12.s, v13.s, v14.s}[1], [x26], #16");
  COMPARE(Ld4(v12.S(), v13.S(), v14.S(), v15.S(), 3,
              MemOperand(x27, x5, PostIndex)),
          "ld4 {v12.s, v13.s, v14.s, v15.s}[3], [cp], x5");
  COMPARE(Ld4(v11.S(), v12.S(), v13.S(), v14.S(), 3,
              MemOperand(x26, 16, PostIndex)),
          "ld4 {v11.s, v12.s, v13.s, v14.s}[3], [x26], #16");
  COMPARE(
      Ld4(v13.D(), v14.D(), v15.D(), v16.D(), 1, MemOperand(sp, x6, PostIndex)),
      "ld4 {v13.d, v14.d, v15.d, v16.d}[1], [sp], x6");
  COMPARE(
      Ld4(v13.D(), v14.D(), v15.D(), v16.D(), 1, MemOperand(sp, 32, PostIndex)),
      "ld4 {v13.d, v14.d, v15.d, v16.d}[1], [sp], #32");

  COMPARE(St1(v0.V8B(), 0, MemOperand(x15)), "st1 {v0.b}[0], [x15]");
  COMPARE(St1(v1.V16B(), 1, MemOperand(x16)), "st1 {v1.b}[1], [x16]");
  COMPARE(St1(v2.V4H(), 2, MemOperand(x17)), "st1 {v2.h}[2], [x17]");
  COMPARE(St1(v3.V8H(), 3, MemOperand(x18)), "st1 {v3.h}[3], [x18]");
  COMPARE(St1(v4.V2S(), 0, MemOperand(x19)), "st1 {v4.s}[0], [x19]");
  COMPARE(St1(v5.V4S(), 1, MemOperand(x20)), "st1 {v5.s}[1], [x20]");
  COMPARE(St1(v6.V2D(), 0, MemOperand(x21)), "st1 {v6.d}[0], [x21]");
  COMPARE(St1(v7.B(), 7, MemOperand(x22)), "st1 {v7.b}[7], [x22]");
  COMPARE(St1(v8_.B(), 15, MemOperand(x23)), "st1 {v8.b}[15], [x23]");
  COMPARE(St1(v9.H(), 3, MemOperand(x24)), "st1 {v9.h}[3], [x24]");
  COMPARE(St1(v10.H(), 7, MemOperand(x25)), "st1 {v10.h}[7], [x25]");
  COMPARE(St1(v11.S(), 1, MemOperand(x26)), "st1 {v11.s}[1], [x26]");
  COMPARE(St1(v12.S(), 3, MemOperand(x27)), "st1 {v12.s}[3], [cp]");
  COMPARE(St1(v13.D(), 1, MemOperand(sp)), "st1 {v13.d}[1], [sp]");

  COMPARE(St1(v0.V8B(), 0, MemOperand(x15, x0, PostIndex)),
          "st1 {v0.b}[0], [x15], x0");
  COMPARE(St1(v1.V16B(), 1, MemOperand(x16, 1, PostIndex)),
          "st1 {v1.b}[1], [x16], #1");
  COMPARE(St1(v2.V4H(), 2, MemOperand(x17, 2, PostIndex)),
          "st1 {v2.h}[2], [x17], #2");
  COMPARE(St1(v3.V8H(), 3, MemOperand(x18, x1, PostIndex)),
          "st1 {v3.h}[3], [x18], x1");
  COMPARE(St1(v4.V2S(), 0, MemOperand(x19, x2, PostIndex)),
          "st1 {v4.s}[0], [x19], x2");
  COMPARE(St1(v5.V4S(), 1
"""


```