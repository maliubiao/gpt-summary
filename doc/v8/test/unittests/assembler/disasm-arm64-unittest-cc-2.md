Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Initial Understanding of the Request:**

The core request is to analyze a C++ source code file (`disasm-arm64-unittest.cc`) from the V8 JavaScript engine. The request has multiple facets:

* **Functionality:** What does this specific piece of code *do*?
* **File Type:**  Is it a standard C++ file or a Torque file?
* **JavaScript Relation:** Does it relate to JavaScript functionality? If so, provide an example.
* **Code Logic/Reasoning:**  Are there any logical deductions or transformations happening within the code? If so, illustrate with inputs and outputs.
* **Common Programming Errors:** Does it highlight potential pitfalls for programmers?
* **Summary:**  Condense the overall purpose of the code.
* **Context:**  This is part 3 of an 8-part series, implying a larger context.

**2. Examining the Code Structure and Content:**

The code is clearly a C++ unit test file. Key observations:

* **Includes:**  It likely includes V8 headers related to assembly, disassembly, and testing. (Though not explicitly shown, this is a reasonable assumption based on the file path and content).
* **Test Fixture:**  The `TEST_F(DisasmArm64Test, ...)` structure immediately suggests it's using a testing framework (likely Google Test or a similar V8-specific framework). The `DisasmArm64Test` part indicates this test suite is focused on disassembling ARM64 instructions.
* **`COMPARE` Macros:**  These are crucial. They take two arguments: an assembler instruction and a string. The name "COMPARE" strongly suggests it's comparing the *disassembled* output of the generated instruction with the expected string representation.
* **Assembler Instructions:**  The first arguments to `COMPARE` are calls to ARM64 assembly instructions (e.g., `ldp`, `stp`, `ldar`, `stlr`, `csel`, `fmov`, etc.). These are the core of what's being tested.
* **String Literals:** The second arguments are string representations of the expected disassembled output for the corresponding assembly instructions.
* **`SET_UP_ASM()`/`SET_UP_MASM()` and `CLEANUP()`:** These suggest setup and teardown routines, likely initializing an assembler object and cleaning up resources.
* **`CpuFeatureScope`:** This indicates testing of instructions that might depend on specific CPU features.
* **Macros like `ATOMIC_MEMORY_DISASM_LIST`:** These are code generation techniques to systematically test variations of atomic memory instructions.

**3. Inferring Functionality:**

Based on the structure and content, the primary function of this code is to **test the ARM64 disassembler in V8**. It generates various ARM64 instructions using the V8 assembler and then checks if the disassembler produces the correct, human-readable string representation for each instruction.

**4. Addressing Specific Request Points:**

* **`.tq` Extension:** The code has a `.cc` extension, so it's standard C++, not Torque.
* **JavaScript Relation:** Disassembly is a crucial part of the JavaScript execution pipeline. When V8 compiles JavaScript code, it generates machine code. The disassembler is used for debugging, profiling, and understanding the generated code. The example provided in the answer demonstrates how V8 internally might use a disassembler to inspect the generated machine code for a simple JavaScript function.
* **Code Logic/Reasoning:**  The "logic" is the comparison between the generated disassembly and the expected string. The input is the assembler instruction (e.g., `ldp(s29, s30, MemOperand(fp, -256, PreIndex))`), and the expected output is the disassembled string (`"ldp s29, s30, [fp, #-256]!"`).
* **Common Programming Errors:** The tests implicitly highlight correct usage of ARM64 instructions. A common error would be using incorrect operands, addressing modes, or immediate values, which would lead to different or invalid machine code and thus a different disassembly output. The example given focuses on incorrect memory addressing.
* **Summary:**  The summary should concisely state the core function: testing the ARM64 disassembler.
* **Part 3 of 8:**  This implies the entire test suite covers a broader range of assembler and disassembler functionalities. This specific part likely focuses on load/store instructions, atomic operations, and potentially some conditional instructions.

**5. Constructing the Answer:**

Now, assemble the observations and inferences into a structured answer, addressing each point of the request clearly and providing concrete examples where necessary. Use the identified keywords and concepts (disassembler, assembler, ARM64, unit tests, etc.) to provide a precise explanation.

**Self-Correction/Refinement:**

* **Initial thought:** Maybe it's testing the assembler itself.
* **Correction:** The `COMPARE` macro with string literals points more directly to testing the *disassembler's output*. The assembler is used as a *means* to generate the code to be disassembled.
* **Initial thought:**  The JavaScript relation might be complex.
* **Refinement:** Focus on the most direct connection: how V8 uses disassembly for internal purposes like debugging and code inspection. Keep the JavaScript example simple to illustrate the concept.
* **Consider the "Part 3 of 8":**  While not requiring detailed speculation, acknowledge that this is part of a larger test suite and infer the likely broader scope.

By following this structured process, carefully examining the code, and connecting the observations to the request's specific points, we arrive at the comprehensive and accurate answer provided previously.
```cpp
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
  COMPARE
Prompt: 
```
这是目录为v8/test/unittests/assembler/disasm-arm64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/assembler/disasm-arm64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共8部分，请归纳一下它的功能

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
"""


```