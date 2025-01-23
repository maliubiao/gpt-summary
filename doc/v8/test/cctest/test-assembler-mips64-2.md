Response:
The user wants a summary of the functionality of the provided C++ code snippet. The code is a series of unit tests for the MIPS64 assembler in V8.

Here's a breakdown of the request and how to address it:

1. **Identify the file type:** The file ends with `.cc`, so it's a C++ source file, not a Torque file.

2. **Determine the purpose:** The code contains `TEST()` macros, which are part of the Google Test framework. This indicates that the file is a unit test suite. The filename `test-assembler-mips64.cc` strongly suggests it's testing the MIPS64 assembler within V8.

3. **Analyze individual tests:** Each `TEST()` block focuses on testing specific MIPS64 assembly instructions or scenarios. Look for the assembly instructions being used within each test (e.g., `addiu`, `lwpc`, `jic`, etc.).

4. **Relate to JavaScript (if applicable):** Assembler code directly translates to machine code. While not directly equivalent to high-level JavaScript, these instructions are the building blocks for implementing JavaScript features. Think about how these low-level operations might be used in JavaScript execution (e.g., arithmetic, memory access, control flow).

5. **Code logic and examples:** For tests involving specific instructions, the code often sets up input values and checks for expected output. Note these input/output pairs.

6. **Common programming errors:**  Consider what types of errors might arise when working with assembly language (e.g., incorrect offsets, register usage, branching). While the tests themselves don't *demonstrate* user errors, the *purpose* of the tests is to ensure the assembler prevents or handles potential errors in instruction encoding and execution.

7. **Summarize overall functionality:** Combine the findings from the individual tests to describe the file's overall purpose.

**Mental Sandbox:**

* **Initial thought:** This file tests MIPS64 assembly instructions.
* **Specific instructions:**  The tests cover instructions like `addiu`, `lwpc`, `lwupc`, `jic`, `beqzc`, MSA vector instructions (`bz_v`, `bnz_v`, etc.), `jialc`, `addiupc`, `ldpc`, `bc`, `balc`, `dsll`, `bal`, and floating-point instructions (`madd_s`, `msub_s`, `maddf_s`, `msubf_s`). It also tests trampoline functionality for long branches.
* **JavaScript connection:** These instructions are used internally by V8 to execute JavaScript. For example, `addiu` is a basic arithmetic operation, memory access instructions like `lwpc` are needed to load data, and branch instructions control the flow of execution.
* **Code logic example (`r6_lwpc`):** It sets up different offsets and expects specific resulting instruction encodings.
* **User errors:**  A common error when working with assembly is calculating branch offsets incorrectly, leading to unexpected jumps.
* **File type:** Definitely C++, not Torque.

**Final Plan:**

The summary should state that this C++ file contains unit tests for the V8 MIPS64 assembler. It should list the categories of instructions being tested (arithmetic, memory access, branching, MSA, floating-point), and mention the trampoline tests. It should also briefly touch on the connection to JavaScript and provide an example of code logic testing and potential user errors in assembly programming.
```cpp
  uint32_t addiu_new = addiu_start_2 + i;
    __ dd(addiu_new);
  }

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}

TEST(r6_lwpc) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();

    struct TestCaseLwpc {
      int       offset;
      uint64_t  expected_res;
    };

    // clang-format off
    struct TestCaseLwpc tc[] = {
      // offset,   expected_res
      { -262144,   0x250FFFFF         },   // offset 0x40000
      {      -4,   0x250C0003         },
      {      -1,   0x250C0000         },
      {       0,   0xFFFFFFFFEF080000 },
      {       1,   0x03001025         },   // mov(v0, t8)
      {       2,   0x25080000         },
      {       4,   0x25080002         },
      {  262143,   0x250BFFFD         },   // offset 0x3FFFF
    };
    // clang-format on

    size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseLwpc);
    for (size_t i = 0; i < nr_test_cases; ++i) {
      uint64_t res = run_lwpc(tc[i].offset);
      CHECK_EQ(tc[i].expected_res, res);
    }
  }
}

uint64_t run_lwupc(int offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // 256k instructions; 2^8k
  // addiu t3, a4, 0xFFFF;  (0x250FFFFF)
  // ...
  // addiu t0, a4, 0x0000;  (0x250C0000)
  uint32_t addiu_start_1 = 0x25000000;
  for (int32_t i = 0xFFFFF; i >= 0xC0000; --i) {
    uint32_t addiu_new = addiu_start_1 + i;
    __ dd(addiu_new);
  }

  __ lwupc(t8, offset);  // offset 0; 0xEF080000 (t8 register)
  __ mov(v0, t8);

  // 256k instructions; 2^8k
  // addiu a4, a4, 0x0000;  (0x25080000)
  // ...
  // addiu a7, a4, 0xFFFF;  (0x250BFFFF)
  uint32_t addiu_start_2 = 0x25000000;
  for (int32_t i = 0x80000; i <= 0xBFFFF; ++i) {
    uint32_t addiu_new = addiu_start_2 + i;
    __ dd(addiu_new);
  }

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}

TEST(r6_lwupc) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();

    struct TestCaseLwupc {
      int       offset;
      uint64_t  expected_res;
    };

    // clang-format off
    struct TestCaseLwupc tc[] = {
      // offset,    expected_res
      { -262144,    0x250FFFFF },   // offset 0x40000
      {      -4,    0x250C0003 },
      {      -1,    0x250C0000 },
      {       0,    0xEF100000 },
      {       1,    0x03001025 },   // mov(v0, t8)
      {       2,    0x25080000 },
      {       4,    0x25080002 },
      {  262143,    0x250BFFFD },   // offset 0x3FFFF
    };
    // clang-format on

    size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseLwupc);
    for (size_t i = 0; i < nr_test_cases; ++i) {
      uint64_t res = run_lwupc(tc[i].offset);
      CHECK_EQ(tc[i].expected_res, res);
    }
  }
}

uint64_t run_jic(int16_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label stop_execution;
  __ push(ra);
  __ li(v0, 0l);
  __ li(t1, 0x66);

  __ addiu(v0, v0, 0x1);        // <-- offset = -32
  __ addiu(v0, v0, 0x2);
  __ addiu(v0, v0, 0x10);
  __ addiu(v0, v0, 0x20);
  __ beq(v0, t1, &stop_execution);
  __ nop();

  __ nal();  // t0 <- program counter
  __ mov(t0, ra);
  __ jic(t0, offset);

  __ addiu(v0, v0, 0x100);
  __ addiu(v0, v0, 0x200);
  __ addiu(v0, v0, 0x1000);
  __ addiu(v0, v0, 0x2000);   // <--- offset = 16
  __ pop(ra);
  __ jr(ra);
  __ nop();

  __ bind(&stop_execution);
  __ pop(ra);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}

TEST(r6_jic) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();

    struct TestCaseJic {
      // As rt will be used t0 register which will have value of
      // the program counter for the jic instruction.
      int16_t   offset;
      uint32_t  expected_res;
    };

    struct TestCaseJic tc[] = {
      // offset,   expected_result
      {      16,            0x2033 },
      {       4,            0x3333 },
      {     -32,              0x66 },
    };

    size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseJic);
    for (size_t i = 0; i < nr_test_cases; ++i) {
      uint64_t res = run_jic(tc[i].offset);
      CHECK_EQ(tc[i].expected_res, res);
    }
  }
}

uint64_t run_beqzc(int32_t value, int32_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label stop_execution;
  __ li(v0, 0l);
  __ li(t1, 0x66);

  __ addiu(v0, v0, 0x1);        // <-- offset = -8
  __ addiu(v0, v0, 0x2);
  __ addiu(v0, v0, 0x10);
  __ addiu(v0, v0, 0x20);
  __ beq(v0, t1, &stop_execution);
  __ nop();

  __ beqzc(a0, offset);

  __ addiu(v0, v0,    0x1);
  __ addiu(v0, v0,  0x100);
  __ addiu(v0, v0,  0x200);
  __ addiu(v0, v0, 0x1000);
  __ addiu(v0, v0, 0x2000);   // <--- offset = 4
  __ jr(ra);
  __ nop();

  __ bind(&stop_execution);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(value, 0, 0, 0, 0));

  return res;
}

TEST(r6_beqzc) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();

    struct TestCaseBeqzc {
      uint32_t  value;
      int32_t   offset;
      uint32_t  expected_res;
    };

    // clang-format off
    struct TestCaseBeqzc tc[] = {
      //    value,    offset,   expected_res
      {       0x0,        -8,           0x66 },
      {       0x0,         0,         0x3334 },
      {       0x0,         1,         0x3333 },
      {     0xABC,         1,         0x3334 },
      {       0x0,         4,         0x2033 },
    };
    // clang-format on

    size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseBeqzc);
    for (size_t i = 0; i < nr_test_cases; ++i) {
      uint64_t res = run_beqzc(tc[i].value, tc[i].offset);
      CHECK_EQ(tc[i].expected_res, res);
    }
  }
}

void load_elements_of_vector(MacroAssembler* assm_ptr,
                             const uint64_t elements[], MSARegister w,
                             Register t0, Register t1) {
  MacroAssembler& assm = *assm_ptr;
  __ li(t0, static_cast<uint32_t>(elements[0] & 0xFFFFFFFF));
  __ li(t1, static_cast<uint32_t>((elements[0] >> 32) & 0xFFFFFFFF));
  __ insert_w(w, 0, t0);
  __ insert_w(w, 1, t1);
  __ li(t0, static_cast<uint32_t>(elements[1] & 0xFFFFFFFF));
  __ li(t1, static_cast<uint32_t>((elements[1] >> 32) & 0xFFFFFFFF));
  __ insert_w(w, 2, t0);
  __ insert_w(w, 3, t1);
}

inline void store_elements_of_vector(MacroAssembler* assm_ptr, MSARegister w,
                                     Register a) {
  MacroAssembler& assm = *assm_ptr;
  __ st_d(w, MemOperand(a, 0));
}

union msa_reg_t {
  uint8_t b[16];
  uint16_t h[8];
  uint32_t w[4];
  uint64_t d[2];
};

struct TestCaseMsaBranch {
  uint64_t wt_lo;
  uint64_t wt_hi;
};

template <typename Branch>
void run_bz_bnz(TestCaseMsaBranch* input, Branch GenerateBranch,
                bool branched) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  CpuFeatureScope fscope(&assm, MIPS_SIMD);

  struct T {
    uint64_t ws_lo;
    uint64_t ws_hi;
    uint64_t wd_lo;
    uint64_t wd_hi;
  };
  T t = {0x20B9CC4F1A83E0C5, 0xA27E1B5F2F5BB18A, 0x0000000000000000,
         0x0000000000000000};
  msa_reg_t res;
  Label do_not_move_w0_to_w2;

  load_elements_of_vector(&assm, &t.ws_lo, w0, t0, t1);
  load_elements_of_vector(&assm, &t.wd_lo, w2, t0, t1);
  load_elements_of_vector(&assm, &input->wt_lo, w1, t0, t1);
  GenerateBranch(assm, do_not_move_w0_to_w2);
  __ nop();
  __ move_v(w2, w0);

  __ bind(&do_not_move_w0_to_w2);
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
  if (branched) {
    CHECK_EQ(t.wd_lo, res.d[0]);
    CHECK_EQ(t.wd_hi, res.d[1]);
  } else {
    CHECK_EQ(t.ws_lo, res.d[0]);
    CHECK_EQ(t.ws_hi, res.d[1]);
  }
}

TEST(MSA_bz_bnz) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  TestCaseMsaBranch tz_v[] = {
      {0x0, 0x0}, {0xABC, 0x0}, {0x0, 0xABC}, {0xABC, 0xABC}};
  for (unsigned i = 0; i < arraysize(tz_v); ++i) {
    run_bz_bnz(
        &tz_v[i],
        [](MacroAssembler& assm, Label& br_target) { __ bz_v(w1, &br_target); },
        tz_v[i].wt_lo == 0 && tz_v[i].wt_hi == 0);
  }

#define TEST_BZ_DF(input_array, lanes, instruction, int_type)         \
  for (unsigned i = 0; i < arraysize(input_array); ++i) {             \
    int j;                                                            \
    int_type* element = reinterpret_cast<int_type*>(&input_array[i]); \
    for (j = 0; j < lanes; ++j) {                                     \
      if (element[j] == 0) {                                          \
        break;                                                        \
      }                                                               \
    }                                                                 \
    run_bz_bnz(&input_array[i],                                       \
               [](MacroAssembler& assm, Label& br_target) {           \
                 __ instruction(w1, &br_target);                      \
               },                                                     \
               j != lanes);                                           \
  }
  TestCaseMsaBranch tz_b[] = {{0x0, 0x0},
                              {0xBC0000, 0x0},
                              {0x0, 0xAB000000000000CD},
                              {0x123456789ABCDEF0, 0xAAAAAAAAAAAAAAAA}};
  TEST_BZ_DF(tz_b, kMSALanesByte, bz_b, int8_t)

  TestCaseMsaBranch tz_h[] = {{0x0, 0x0},
                              {0xBCDE0000, 0x0},
                              {0x0, 0xABCD00000000ABCD},
                              {0x123456789ABCDEF0, 0xAAAAAAAAAAAAAAAA}};
  TEST_BZ_DF(tz_h, kMSALanesHalf, bz_h, int16_t)

  TestCaseMsaBranch tz_w[] = {{0x0, 0x0},
                              {0xBCDE123400000000, 0x0},
                              {0x0, 0x000000001234ABCD},
                              {0x123456789ABCDEF0, 0xAAAAAAAAAAAAAAAA}};
  TEST_BZ_DF(tz_w, kMSALanesWord, bz_w, int32_t)

  TestCaseMsaBranch tz_d[] = {{0x0, 0x0},
                              {0xBCDE0000, 0x0},
                              {0x0, 0xABCD00000000ABCD},
                              {0x123456789ABCDEF0, 0xAAAAAAAAAAAAAAAA}};
  TEST_BZ_DF(tz_d, kMSALanesDword, bz_d, int64_t)
#undef TEST_BZ_DF

  TestCaseMsaBranch tnz_v[] = {
      {0x0, 0x0}, {0xABC, 0x0}, {0x0, 0xABC}, {0xABC, 0xABC}};
  for (unsigned i = 0; i < arraysize(tnz_v); ++i) {
    run_bz_bnz(&tnz_v[i],
               [](MacroAssembler& assm, Label& br_target) {
                 __ bnz_v(w1, &br_target);
               },
               tnz_v[i].wt_lo != 0 || tnz_v[i].wt_hi != 0);
  }

#define TEST_BNZ_DF(input_array, lanes, instruction, int_type)        \
  for (unsigned i = 0; i < arraysize(input_array); ++i) {             \
    int j;                                                            \
    int_type* element = reinterpret_cast<int_type*>(&input_array[i]); \
    for (j = 0; j < lanes; ++j) {                                     \
      if (element[j] == 0) {                                          \
        break;                                                        \
      }                                                               \
    }                                                                 \
    run_bz_bnz(&input_array[i],                                       \
               [](MacroAssembler& assm, Label& br_target) {           \
                 __ instruction(w1, &br_target);                      \
               },                                                     \
               j == lanes);                                           \
  }
  TestCaseMsaBranch tnz_b[] = {{0x0, 0x0},
                               {0xBC0000, 0x0},
                               {0x0, 0xAB000000000000CD},
                               {0x123456789ABCDEF0, 0xAAAAAAAAAAAAAAAA}};
  TEST_BNZ_DF(tnz_b, 16, bnz_b, int8_t)

  TestCaseMsaBranch tnz_h[] = {{0x0, 0x0},
                               {0xBCDE0000, 0x0},
                               {0x0, 0xABCD00000000ABCD},
                               {0x123456789ABCDEF0, 0xAAAAAAAAAAAAAAAA}};
  TEST_BNZ_DF(tnz_h, 8, bnz_h, int16_t)

  TestCaseMsaBranch tnz_w[] = {{0x0, 0x0},
                               {0xBCDE123400000000, 0x0},
                               {0x0, 0x000000001234ABCD},
                               {0x123456789ABCDEF0, 0xAAAAAAAAAAAAAAAA}};
  TEST_BNZ_DF(tnz_w, 4, bnz_w, int32_t)

  TestCaseMsaBranch tnz_d[] = {{0x0, 0x0},
                               {0xBCDE0000, 0x0},
                               {0x0, 0xABCD00000000ABCD},
                               {0x123456789ABCDEF0, 0xAAAAAAAAAAAAAAAA}};
  TEST_BNZ_DF(tnz_d, 2, bnz_d, int64_t)
#undef TEST_BNZ_DF
}

uint64_t run_jialc(int16_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label main_block;
  __ push(ra);
  __ li(v0, 0l);
  __ beq(v0, v0, &main_block);
  __ nop();

  // Block 1
  __ addiu(v0, v0, 0x1);        // <-- offset = -40
  __ addiu(v0, v0, 0x2);
  __ jr(ra);
  __ nop();

  // Block 2
  __ addiu(v0, v0, 0x10);        // <-- offset = -24
  __ addiu(v0, v0, 0x20);
  __ jr(ra);
  __ nop();

  // Block 3 (Main)
  __ bind(&main_block);
  __ nal();  // t0 <- program counter
  __ mov(t0, ra);
  __ jialc(t0, offset);
  __ addiu(v0, v0, 0x4);
  __ pop(ra);
  __ jr(ra);
  __ nop();

  // Block 4
  __ addiu(v0, v0, 0x100);      // <-- offset = 20
  __ addiu(v0, v0, 0x200);
  __ jr(ra);
  __ nop();

  // Block 5
  __ addiu(v0, v0, 0x1000);     // <--- offset = 36
  __ addiu(v0, v0, 0x2000);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}

TEST(r6_jialc) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();

    struct TestCaseJialc {
      // As rt will be used t0 register which will have value of
      // the program counter for the jialc instruction.
      int16_t   offset;
      uint32_t  expected_res;
    };

    struct TestCaseJialc tc[] = {
      // offset,   expected_res
      {     -40,            0x7 },
      {     -24,           0x34 },
      {      20,          0x304 },
      {      36,         0x3004 }
    };

    size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseJialc);
    for (size_t i = 0; i < nr_test_cases; ++i) {
      uint64_t res = run_jialc(tc[i].offset);
      CHECK_EQ(tc[i].expected_res, res);
    }
  }
}

uint64_t run_addiupc(int32_t imm19) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ addiupc(v0, imm19);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  PC = (uint64_t)code->instruction_start();  // Set the program counter.

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}

TEST(r6_addiupc) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();

    struct TestCaseAddiupc {
      int32_t   imm19;
    };

    struct TestCaseAddiupc tc[] = {
      //  imm19
      { -262144 },   // 0x40000
      {      -1 },   // 0x7FFFF
      {       0 },
      {       1 },   // 0x00001
      {  262143 }    // 0x3FFFF
    };

    size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseAddiupc);
    for (size_t i = 0; i < nr_test_cases; ++i) {
      PC = 0;
      uint64_t res = run_addiupc(tc[i].imm19);
      // Now, the program_counter (PC) is set.
      uint64_t expected_res = PC + (tc[i].imm19 << 2);
      CHECK_EQ(expected_res, res);
    }
  }
}

uint64_t run_ldpc(int offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // 256k instructions; 2 * 2^7k = 2^8k
  // addiu t3, a4, 0xFFFF;  (0x250FFFFF)
  // ...
  // addiu t0, a4, 0x0000;  (0x250C0000)
  uint32_t addiu_start_1 = 0x25000000;
  for (int32_t i = 0xFFFFF; i >= 0xC0000; --i) {
    uint32_t addiu_new = addiu_start_1 + i;
    __ dd(addiu_new);
  }

  __ ldpc(t8, offset);  // offset 0; 0xEF080000 (t8 register)
  __ mov(v0, t8);

  // 256k instructions; 2 * 2^7k = 2^8k
  // addiu a4, a4, 0x0000;  (0x25080000)
  // ...
  // addiu a7, a4, 0xFFFF;  (0x250BFFFF)
  uint32_t
### 提示词
```
这是目录为v8/test/cctest/test-assembler-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共13部分，请归纳一下它的功能
```

### 源代码
```
uint32_t addiu_new = addiu_start_2 + i;
    __ dd(addiu_new);
  }

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}


TEST(r6_lwpc) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();

    struct TestCaseLwpc {
      int       offset;
      uint64_t  expected_res;
    };

    // clang-format off
    struct TestCaseLwpc tc[] = {
      // offset,   expected_res
      { -262144,   0x250FFFFF         },   // offset 0x40000
      {      -4,   0x250C0003         },
      {      -1,   0x250C0000         },
      {       0,   0xFFFFFFFFEF080000 },
      {       1,   0x03001025         },   // mov(v0, t8)
      {       2,   0x25080000         },
      {       4,   0x25080002         },
      {  262143,   0x250BFFFD         },   // offset 0x3FFFF
    };
    // clang-format on

    size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseLwpc);
    for (size_t i = 0; i < nr_test_cases; ++i) {
      uint64_t res = run_lwpc(tc[i].offset);
      CHECK_EQ(tc[i].expected_res, res);
    }
  }
}


uint64_t run_lwupc(int offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // 256k instructions; 2^8k
  // addiu t3, a4, 0xFFFF;  (0x250FFFFF)
  // ...
  // addiu t0, a4, 0x0000;  (0x250C0000)
  uint32_t addiu_start_1 = 0x25000000;
  for (int32_t i = 0xFFFFF; i >= 0xC0000; --i) {
    uint32_t addiu_new = addiu_start_1 + i;
    __ dd(addiu_new);
  }

  __ lwupc(t8, offset);  // offset 0; 0xEF080000 (t8 register)
  __ mov(v0, t8);

  // 256k instructions; 2^8k
  // addiu a4, a4, 0x0000;  (0x25080000)
  // ...
  // addiu a7, a4, 0xFFFF;  (0x250BFFFF)
  uint32_t addiu_start_2 = 0x25000000;
  for (int32_t i = 0x80000; i <= 0xBFFFF; ++i) {
    uint32_t addiu_new = addiu_start_2 + i;
    __ dd(addiu_new);
  }

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}


TEST(r6_lwupc) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();

    struct TestCaseLwupc {
      int       offset;
      uint64_t  expected_res;
    };

    // clang-format off
    struct TestCaseLwupc tc[] = {
      // offset,    expected_res
      { -262144,    0x250FFFFF },   // offset 0x40000
      {      -4,    0x250C0003 },
      {      -1,    0x250C0000 },
      {       0,    0xEF100000 },
      {       1,    0x03001025 },   // mov(v0, t8)
      {       2,    0x25080000 },
      {       4,    0x25080002 },
      {  262143,    0x250BFFFD },   // offset 0x3FFFF
    };
    // clang-format on

    size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseLwupc);
    for (size_t i = 0; i < nr_test_cases; ++i) {
      uint64_t res = run_lwupc(tc[i].offset);
      CHECK_EQ(tc[i].expected_res, res);
    }
  }
}


uint64_t run_jic(int16_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label stop_execution;
  __ push(ra);
  __ li(v0, 0l);
  __ li(t1, 0x66);

  __ addiu(v0, v0, 0x1);        // <-- offset = -32
  __ addiu(v0, v0, 0x2);
  __ addiu(v0, v0, 0x10);
  __ addiu(v0, v0, 0x20);
  __ beq(v0, t1, &stop_execution);
  __ nop();

  __ nal();  // t0 <- program counter
  __ mov(t0, ra);
  __ jic(t0, offset);

  __ addiu(v0, v0, 0x100);
  __ addiu(v0, v0, 0x200);
  __ addiu(v0, v0, 0x1000);
  __ addiu(v0, v0, 0x2000);   // <--- offset = 16
  __ pop(ra);
  __ jr(ra);
  __ nop();

  __ bind(&stop_execution);
  __ pop(ra);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}


TEST(r6_jic) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();

    struct TestCaseJic {
      // As rt will be used t0 register which will have value of
      // the program counter for the jic instruction.
      int16_t   offset;
      uint32_t  expected_res;
    };

    struct TestCaseJic tc[] = {
      // offset,   expected_result
      {      16,            0x2033 },
      {       4,            0x3333 },
      {     -32,              0x66 },
    };

    size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseJic);
    for (size_t i = 0; i < nr_test_cases; ++i) {
      uint64_t res = run_jic(tc[i].offset);
      CHECK_EQ(tc[i].expected_res, res);
    }
  }
}


uint64_t run_beqzc(int32_t value, int32_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label stop_execution;
  __ li(v0, 0l);
  __ li(t1, 0x66);

  __ addiu(v0, v0, 0x1);        // <-- offset = -8
  __ addiu(v0, v0, 0x2);
  __ addiu(v0, v0, 0x10);
  __ addiu(v0, v0, 0x20);
  __ beq(v0, t1, &stop_execution);
  __ nop();

  __ beqzc(a0, offset);

  __ addiu(v0, v0,    0x1);
  __ addiu(v0, v0,  0x100);
  __ addiu(v0, v0,  0x200);
  __ addiu(v0, v0, 0x1000);
  __ addiu(v0, v0, 0x2000);   // <--- offset = 4
  __ jr(ra);
  __ nop();

  __ bind(&stop_execution);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(value, 0, 0, 0, 0));

  return res;
}


TEST(r6_beqzc) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();

    struct TestCaseBeqzc {
      uint32_t  value;
      int32_t   offset;
      uint32_t  expected_res;
    };

    // clang-format off
    struct TestCaseBeqzc tc[] = {
      //    value,    offset,   expected_res
      {       0x0,        -8,           0x66 },
      {       0x0,         0,         0x3334 },
      {       0x0,         1,         0x3333 },
      {     0xABC,         1,         0x3334 },
      {       0x0,         4,         0x2033 },
    };
    // clang-format on

    size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseBeqzc);
    for (size_t i = 0; i < nr_test_cases; ++i) {
      uint64_t res = run_beqzc(tc[i].value, tc[i].offset);
      CHECK_EQ(tc[i].expected_res, res);
    }
  }
}

void load_elements_of_vector(MacroAssembler* assm_ptr,
                             const uint64_t elements[], MSARegister w,
                             Register t0, Register t1) {
  MacroAssembler& assm = *assm_ptr;
  __ li(t0, static_cast<uint32_t>(elements[0] & 0xFFFFFFFF));
  __ li(t1, static_cast<uint32_t>((elements[0] >> 32) & 0xFFFFFFFF));
  __ insert_w(w, 0, t0);
  __ insert_w(w, 1, t1);
  __ li(t0, static_cast<uint32_t>(elements[1] & 0xFFFFFFFF));
  __ li(t1, static_cast<uint32_t>((elements[1] >> 32) & 0xFFFFFFFF));
  __ insert_w(w, 2, t0);
  __ insert_w(w, 3, t1);
}

inline void store_elements_of_vector(MacroAssembler* assm_ptr, MSARegister w,
                                     Register a) {
  MacroAssembler& assm = *assm_ptr;
  __ st_d(w, MemOperand(a, 0));
}

union msa_reg_t {
  uint8_t b[16];
  uint16_t h[8];
  uint32_t w[4];
  uint64_t d[2];
};

struct TestCaseMsaBranch {
  uint64_t wt_lo;
  uint64_t wt_hi;
};

template <typename Branch>
void run_bz_bnz(TestCaseMsaBranch* input, Branch GenerateBranch,
                bool branched) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  CpuFeatureScope fscope(&assm, MIPS_SIMD);

  struct T {
    uint64_t ws_lo;
    uint64_t ws_hi;
    uint64_t wd_lo;
    uint64_t wd_hi;
  };
  T t = {0x20B9CC4F1A83E0C5, 0xA27E1B5F2F5BB18A, 0x0000000000000000,
         0x0000000000000000};
  msa_reg_t res;
  Label do_not_move_w0_to_w2;

  load_elements_of_vector(&assm, &t.ws_lo, w0, t0, t1);
  load_elements_of_vector(&assm, &t.wd_lo, w2, t0, t1);
  load_elements_of_vector(&assm, &input->wt_lo, w1, t0, t1);
  GenerateBranch(assm, do_not_move_w0_to_w2);
  __ nop();
  __ move_v(w2, w0);

  __ bind(&do_not_move_w0_to_w2);
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
  if (branched) {
    CHECK_EQ(t.wd_lo, res.d[0]);
    CHECK_EQ(t.wd_hi, res.d[1]);
  } else {
    CHECK_EQ(t.ws_lo, res.d[0]);
    CHECK_EQ(t.ws_hi, res.d[1]);
  }
}

TEST(MSA_bz_bnz) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  TestCaseMsaBranch tz_v[] = {
      {0x0, 0x0}, {0xABC, 0x0}, {0x0, 0xABC}, {0xABC, 0xABC}};
  for (unsigned i = 0; i < arraysize(tz_v); ++i) {
    run_bz_bnz(
        &tz_v[i],
        [](MacroAssembler& assm, Label& br_target) { __ bz_v(w1, &br_target); },
        tz_v[i].wt_lo == 0 && tz_v[i].wt_hi == 0);
  }

#define TEST_BZ_DF(input_array, lanes, instruction, int_type)         \
  for (unsigned i = 0; i < arraysize(input_array); ++i) {             \
    int j;                                                            \
    int_type* element = reinterpret_cast<int_type*>(&input_array[i]); \
    for (j = 0; j < lanes; ++j) {                                     \
      if (element[j] == 0) {                                          \
        break;                                                        \
      }                                                               \
    }                                                                 \
    run_bz_bnz(&input_array[i],                                       \
               [](MacroAssembler& assm, Label& br_target) {           \
                 __ instruction(w1, &br_target);                      \
               },                                                     \
               j != lanes);                                           \
  }
  TestCaseMsaBranch tz_b[] = {{0x0, 0x0},
                              {0xBC0000, 0x0},
                              {0x0, 0xAB000000000000CD},
                              {0x123456789ABCDEF0, 0xAAAAAAAAAAAAAAAA}};
  TEST_BZ_DF(tz_b, kMSALanesByte, bz_b, int8_t)

  TestCaseMsaBranch tz_h[] = {{0x0, 0x0},
                              {0xBCDE0000, 0x0},
                              {0x0, 0xABCD00000000ABCD},
                              {0x123456789ABCDEF0, 0xAAAAAAAAAAAAAAAA}};
  TEST_BZ_DF(tz_h, kMSALanesHalf, bz_h, int16_t)

  TestCaseMsaBranch tz_w[] = {{0x0, 0x0},
                              {0xBCDE123400000000, 0x0},
                              {0x0, 0x000000001234ABCD},
                              {0x123456789ABCDEF0, 0xAAAAAAAAAAAAAAAA}};
  TEST_BZ_DF(tz_w, kMSALanesWord, bz_w, int32_t)

  TestCaseMsaBranch tz_d[] = {{0x0, 0x0},
                              {0xBCDE0000, 0x0},
                              {0x0, 0xABCD00000000ABCD},
                              {0x123456789ABCDEF0, 0xAAAAAAAAAAAAAAAA}};
  TEST_BZ_DF(tz_d, kMSALanesDword, bz_d, int64_t)
#undef TEST_BZ_DF

  TestCaseMsaBranch tnz_v[] = {
      {0x0, 0x0}, {0xABC, 0x0}, {0x0, 0xABC}, {0xABC, 0xABC}};
  for (unsigned i = 0; i < arraysize(tnz_v); ++i) {
    run_bz_bnz(&tnz_v[i],
               [](MacroAssembler& assm, Label& br_target) {
                 __ bnz_v(w1, &br_target);
               },
               tnz_v[i].wt_lo != 0 || tnz_v[i].wt_hi != 0);
  }

#define TEST_BNZ_DF(input_array, lanes, instruction, int_type)        \
  for (unsigned i = 0; i < arraysize(input_array); ++i) {             \
    int j;                                                            \
    int_type* element = reinterpret_cast<int_type*>(&input_array[i]); \
    for (j = 0; j < lanes; ++j) {                                     \
      if (element[j] == 0) {                                          \
        break;                                                        \
      }                                                               \
    }                                                                 \
    run_bz_bnz(&input_array[i],                                       \
               [](MacroAssembler& assm, Label& br_target) {           \
                 __ instruction(w1, &br_target);                      \
               },                                                     \
               j == lanes);                                           \
  }
  TestCaseMsaBranch tnz_b[] = {{0x0, 0x0},
                               {0xBC0000, 0x0},
                               {0x0, 0xAB000000000000CD},
                               {0x123456789ABCDEF0, 0xAAAAAAAAAAAAAAAA}};
  TEST_BNZ_DF(tnz_b, 16, bnz_b, int8_t)

  TestCaseMsaBranch tnz_h[] = {{0x0, 0x0},
                               {0xBCDE0000, 0x0},
                               {0x0, 0xABCD00000000ABCD},
                               {0x123456789ABCDEF0, 0xAAAAAAAAAAAAAAAA}};
  TEST_BNZ_DF(tnz_h, 8, bnz_h, int16_t)

  TestCaseMsaBranch tnz_w[] = {{0x0, 0x0},
                               {0xBCDE123400000000, 0x0},
                               {0x0, 0x000000001234ABCD},
                               {0x123456789ABCDEF0, 0xAAAAAAAAAAAAAAAA}};
  TEST_BNZ_DF(tnz_w, 4, bnz_w, int32_t)

  TestCaseMsaBranch tnz_d[] = {{0x0, 0x0},
                               {0xBCDE0000, 0x0},
                               {0x0, 0xABCD00000000ABCD},
                               {0x123456789ABCDEF0, 0xAAAAAAAAAAAAAAAA}};
  TEST_BNZ_DF(tnz_d, 2, bnz_d, int64_t)
#undef TEST_BNZ_DF
}

uint64_t run_jialc(int16_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label main_block;
  __ push(ra);
  __ li(v0, 0l);
  __ beq(v0, v0, &main_block);
  __ nop();

  // Block 1
  __ addiu(v0, v0, 0x1);        // <-- offset = -40
  __ addiu(v0, v0, 0x2);
  __ jr(ra);
  __ nop();

  // Block 2
  __ addiu(v0, v0, 0x10);        // <-- offset = -24
  __ addiu(v0, v0, 0x20);
  __ jr(ra);
  __ nop();

  // Block 3 (Main)
  __ bind(&main_block);
  __ nal();  // t0 <- program counter
  __ mov(t0, ra);
  __ jialc(t0, offset);
  __ addiu(v0, v0, 0x4);
  __ pop(ra);
  __ jr(ra);
  __ nop();

  // Block 4
  __ addiu(v0, v0, 0x100);      // <-- offset = 20
  __ addiu(v0, v0, 0x200);
  __ jr(ra);
  __ nop();

  // Block 5
  __ addiu(v0, v0, 0x1000);     // <--- offset = 36
  __ addiu(v0, v0, 0x2000);
  __ jr(ra);
  __ nop();


  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}


TEST(r6_jialc) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();

    struct TestCaseJialc {
      // As rt will be used t0 register which will have value of
      // the program counter for the jialc instruction.
      int16_t   offset;
      uint32_t  expected_res;
    };

    struct TestCaseJialc tc[] = {
      // offset,   expected_res
      {     -40,            0x7 },
      {     -24,           0x34 },
      {      20,          0x304 },
      {      36,         0x3004 }
    };

    size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseJialc);
    for (size_t i = 0; i < nr_test_cases; ++i) {
      uint64_t res = run_jialc(tc[i].offset);
      CHECK_EQ(tc[i].expected_res, res);
    }
  }
}


uint64_t run_addiupc(int32_t imm19) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ addiupc(v0, imm19);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  PC = (uint64_t)code->instruction_start();  // Set the program counter.

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}


TEST(r6_addiupc) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();

    struct TestCaseAddiupc {
      int32_t   imm19;
    };

    struct TestCaseAddiupc tc[] = {
      //  imm19
      { -262144 },   // 0x40000
      {      -1 },   // 0x7FFFF
      {       0 },
      {       1 },   // 0x00001
      {  262143 }    // 0x3FFFF
    };

    size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseAddiupc);
    for (size_t i = 0; i < nr_test_cases; ++i) {
      PC = 0;
      uint64_t res = run_addiupc(tc[i].imm19);
      // Now, the program_counter (PC) is set.
      uint64_t expected_res = PC + (tc[i].imm19 << 2);
      CHECK_EQ(expected_res, res);
    }
  }
}


uint64_t run_ldpc(int offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // 256k instructions; 2 * 2^7k = 2^8k
  // addiu t3, a4, 0xFFFF;  (0x250FFFFF)
  // ...
  // addiu t0, a4, 0x0000;  (0x250C0000)
  uint32_t addiu_start_1 = 0x25000000;
  for (int32_t i = 0xFFFFF; i >= 0xC0000; --i) {
    uint32_t addiu_new = addiu_start_1 + i;
    __ dd(addiu_new);
  }

  __ ldpc(t8, offset);  // offset 0; 0xEF080000 (t8 register)
  __ mov(v0, t8);

  // 256k instructions; 2 * 2^7k = 2^8k
  // addiu a4, a4, 0x0000;  (0x25080000)
  // ...
  // addiu a7, a4, 0xFFFF;  (0x250BFFFF)
  uint32_t addiu_start_2 = 0x25000000;
  for (int32_t i = 0x80000; i <= 0xBFFFF; ++i) {
    uint32_t addiu_new = addiu_start_2 + i;
    __ dd(addiu_new);
  }

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}


TEST(r6_ldpc) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();

    struct TestCaseLdpc {
      int       offset;
      uint64_t  expected_res;
    };

    auto doubleword = [](uint32_t word2, uint32_t word1) {
      if (kArchEndian == kLittle)
        return (static_cast<uint64_t>(word2) << 32) + word1;
      else
        return (static_cast<uint64_t>(word1) << 32) + word2;
    };

    TestCaseLdpc tc[] = {
        // offset,  expected_res
        {-131072, doubleword(0x250FFFFE, 0x250FFFFF)},
        {-4, doubleword(0x250C0006, 0x250C0007)},
        {-1, doubleword(0x250C0000, 0x250C0001)},
        {0, doubleword(0x03001025, 0xEF180000)},
        {1, doubleword(0x25080001, 0x25080000)},
        {4, doubleword(0x25080007, 0x25080006)},
        {131071, doubleword(0x250BFFFD, 0x250BFFFC)},
    };

    size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseLdpc);
    for (size_t i = 0; i < nr_test_cases; ++i) {
      uint64_t res = run_ldpc(tc[i].offset);
      CHECK_EQ(tc[i].expected_res, res);
    }
  }
}


int64_t run_bc(int32_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label continue_1, stop_execution;
  __ push(ra);
  __ li(v0, 0l);
  __ li(t8, 0l);
  __ li(t9, 2);   // Condition for the stopping execution.

  for (int32_t i = -100; i <= -11; ++i) {
    __ addiu(v0, v0, 1);
  }

  __ addiu(t8, t8, 1);              // -10

  __ beq(t8, t9, &stop_execution);  // -9
  __ nop();                         // -8
  __ beq(t8, t8, &continue_1);      // -7
  __ nop();                         // -6

  __ bind(&stop_execution);
  __ pop(ra);                       // -5, -4
  __ jr(ra);                        // -3
  __ nop();                         // -2

  __ bind(&continue_1);
  __ bc(offset);                    // -1

  for (int32_t i = 0; i <= 99; ++i) {
    __ addiu(v0, v0, 1);
  }

  __ pop(ra);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  int64_t res = reinterpret_cast<int64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}


TEST(r6_bc) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();

    struct TestCaseBc {
      int32_t   offset;
      int64_t   expected_res;
    };

    struct TestCaseBc tc[] = {
      //    offset,   expected_result
      {       -100,   (abs(-100) - 10) * 2      },
      {        -11,   (abs(-100) - 10 + 1)      },
      {          0,   (abs(-100) - 10 + 1 + 99) },
      {          1,   (abs(-100) - 10 + 99)     },
      {         99,   (abs(-100) - 10 + 1)      },
    };

    size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseBc);
    for (size_t i = 0; i < nr_test_cases; ++i) {
      int64_t res = run_bc(tc[i].offset);
      CHECK_EQ(tc[i].expected_res, res);
    }
  }
}


int64_t run_balc(int32_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label continue_1;
  __ push(ra);
  __ li(v0, 0l);
  __ li(t8, 0l);
  __ li(t9, 2);   // Condition for stopping execution.

  __ beq(t8, t8, &continue_1);
  __ nop();

  uint32_t instruction_addiu = 0x24420001;  // addiu v0, v0, 1
  for (int32_t i = -117; i <= -57; ++i) {
    __ dd(instruction_addiu);
  }
  __ jr(ra);                        // -56
  __ nop();                         // -55

  for (int32_t i = -54; i <= -4; ++i) {
    __ dd(instruction_addiu);
  }
  __ jr(ra);                        // -3
  __ nop();                         // -2

  __ bind(&continue_1);
  __ balc(offset);                    // -1

  __ pop(ra);                         // 0, 1
  __ jr(ra);                          // 2
  __ nop();                           // 3

  for (int32_t i = 4; i <= 44; ++i) {
    __ dd(instruction_addiu);
  }
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  int64_t res = reinterpret_cast<int64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}


TEST(r6_balc) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();

    struct TestCaseBalc {
      int32_t   offset;
      int64_t   expected_res;
    };

    struct TestCaseBalc tc[] = {
      //  offset,   expected_result
      {     -117,   61  },
      {      -54,   51  },
      {        0,   0   },
      {        4,   41  },
    };

    size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseBalc);
    for (size_t i = 0; i < nr_test_cases; ++i) {
      int64_t res = run_balc(tc[i].offset);
      CHECK_EQ(tc[i].expected_res, res);
    }
  }
}


uint64_t run_dsll(uint64_t rt_value, uint16_t sa_value) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ dsll(v0, a0, sa_value);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F4>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(rt_value, 0, 0, 0, 0));

  return res;
}


TEST(dsll) {
  CcTest::InitializeVM();

  struct TestCaseDsll {
    uint64_t  rt_value;
    uint16_t  sa_value;
    uint64_t  expected_res;
  };

  // clang-format off
  struct TestCaseDsll tc[] = {
    // rt_value,           sa_value, expected_res
    {  0xFFFFFFFFFFFFFFFF,    0,      0xFFFFFFFFFFFFFFFF },
    {  0xFFFFFFFFFFFFFFFF,   16,      0xFFFFFFFFFFFF0000 },
    {  0xFFFFFFFFFFFFFFFF,   31,      0xFFFFFFFF80000000 },
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseDsll);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    CHECK_EQ(tc[i].expected_res,
            run_dsll(tc[i].rt_value, tc[i].sa_value));
  }
}


uint64_t run_bal(int16_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ mov(t0, ra);
  __ bal(offset);       // Equivalent for "BGEZAL zero_reg, offset".
  __ nop();

  __ mov(ra, t0);
  __ jr(ra);
  __ nop();

  __ li(v0, 1);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}


TEST(bal) {
  CcTest::InitializeVM();

  struct TestCaseBal {
    int16_t  offset;
    uint64_t  expected_res;
  };

  // clang-format off
  struct TestCaseBal tc[] = {
    // offset, expected_res
    {       4,            1 },
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseBal);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    CHECK_EQ(tc[i].expected_res, run_bal(tc[i].offset));
  }
}


TEST(Trampoline) {
  // Private member of Assembler class.
  static const int kMaxBranchOffset = (1 << (18 - 1)) - 1;

  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  Label done;
  size_t nr_calls = kMaxBranchOffset / (2 * kInstrSize) + 2;

  for (size_t i = 0; i < nr_calls; ++i) {
    __ BranchShort(&done, eq, a0, Operand(a1));
  }
  __ bind(&done);
  __ Ret(USE_DELAY_SLOT);
  __ mov(v0, zero_reg);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  int64_t res = reinterpret_cast<int64_t>(f.Call(42, 42, 0, 0, 0));
  CHECK_EQ(0, res);
}

TEST(Trampoline_with_massive_unbound_labels) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  const int kNumSlots =
      MacroAssembler::kMaxBranchOffset / MacroAssembler::kTrampolineSlotsSize;
  Label labels[kNumSlots];

  {
    MacroAssembler::BlockTrampolinePoolScope block_trampoline_pool(&assm);
    for (int i = 0; i < kNumSlots; i++) {
      __ Branch(&labels[i]);
    }
  }

  __ bind(&labels[0]);
}

static void DummyFunction(Object result) {}

TEST(Call_with_trampoline) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  int next_buffer_check_ = v8_flags.force_long_branches
                               ? kMaxInt
                               : MacroAssembler::kMaxBranchOffset -
                                     MacroAssembler::kTrampolineSlotsSize * 16;

  Label done;
  __ Branch(&done);
  next_buffer_check_ -= MacroAssembler::kTrampolineSlotsSize;

  int num_nops = (next_buffer_check_ - __ pc_offset()) / kInstrSize - 1;
  for (int i = 0; i < num_nops; i++) {
    __ nop();
  }

  int pc_offset_before = __ pc_offset();
  {
    // There should be a trampoline after this Call
    __ Call(FUNCTION_ADDR(DummyFunction), RelocInfo::EXTERNAL_REFERENCE);
  }
  int pc_offset_after = __ pc_offset();
  int safepoint_pc_offset = __ pc_offset_for_safepoint();

  // Without trampoline, the Call emits no more than 8 instructions, otherwise
  // more than 8 instructions will be generated.
  int num_instrs = 8;
  // pc_offset_after records the offset after trampoline.
  CHECK_GT(pc_offset_after - pc_offset_before, num_instrs * kInstrSize);
  // safepoint_pc_offset records the offset before trampoline.
  CHECK_LE(safepoint_pc_offset - pc_offset_before, num_instrs * kInstrSize);

  __ bind(&done);
}

template <class T>
struct TestCaseMaddMsub {
  T fr, fs, ft, fd_add, fd_sub;
};

template <typename T, typename F>
void helper_madd_msub_maddf_msubf(F func) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  T x = std::sqrt(static_cast<T>(2.0));
  T y = std::sqrt(static_cast<T>(3.0));
  T z = std::sqrt(static_cast<T>(5.0));
  T x2 = 11.11, y2 = 22.22, z2 = 33.33;
  TestCaseMaddMsub<T> test_cases[] = {
      {x, y, z, 0.0, 0.0},
      {x, y, -z, 0.0, 0.0},
      {x, -y, z, 0.0, 0.0},
      {x, -y, -z, 0.0, 0.0},
      {-x, y, z, 0.0, 0.0},
      {-x, y, -z, 0.0, 0.0},
      {-x, -y, z, 0.0, 0.0},
      {-x, -y, -z, 0.0, 0.0},
      {-3.14, 0.2345, -123.000056, 0.0, 0.0},
      {7.3, -23.257, -357.1357, 0.0, 0.0},
      {x2, y2, z2, 0.0, 0.0},
      {x2, y2, -z2, 0.0, 0.0},
      {x2, -y2, z2, 0.0, 0.0},
      {x2, -y2, -z2, 0.0, 0.0},
      {-x2, y2, z2, 0.0, 0.0},
      {-x2, y2, -z2, 0.0, 0.0},
      {-x2, -y2, z2, 0.0, 0.0},
      {-x2, -y2, -z2, 0.0, 0.0},
  };

  if (std::is_same<T, float>::value) {
    __ Lwc1(f4, MemOperand(a0, offsetof(TestCaseMaddMsub<T>, fr)));
    __ Lwc1(f6, MemOperand(a0, offsetof(TestCaseMaddMsub<T>, fs)));
    __ Lwc1(f8, MemOperand(a0, offsetof(TestCaseMaddMsub<T>, ft)));
    __ Lwc1(f16, MemOperand(a0, offsetof(TestCaseMaddMsub<T>, fr)));
  } else if (std::is_same<T, double>::value) {
    __ Ldc1(f4, MemOperand(a0, offsetof(TestCaseMaddMsub<T>, fr)));
    __ Ldc1(f6, MemOperand(a0, offsetof(TestCaseMaddMsub<T>, fs)));
    __ Ldc1(f8, MemOperand(a0, offsetof(TestCaseMaddMsub<T>, ft)));
    __ Ldc1(f16, MemOperand(a0, offsetof(TestCaseMaddMsub<T>, fr)));
  } else {
    UNREACHABLE();
  }

  func(assm);

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);

  const size_t kTableLength = sizeof(test_cases) / sizeof(TestCaseMaddMsub<T>);
  TestCaseMaddMsub<T> tc;
  for (size_t i = 0; i < kTableLength; i++) {
    tc.fr = test_cases[i].fr;
    tc.fs = test_cases[i].fs;
    tc.ft = test_cases[i].ft;

    f.Call(&tc, 0, 0, 0, 0);

    T res_sub;
    T res_add;
    if (kArchVariant != kMips64r6) {
      res_add = tc.fr + (tc.fs * tc.ft);
      res_sub = (tc.fs * tc.ft) - tc.fr;
    } else {
      res_add = std::fma(tc.fs, tc.ft, tc.fr);
      res_sub = std::fma(-tc.fs, tc.ft, tc.fr);
    }

    CHECK_EQ(tc.fd_add, res_add);
    CHECK_EQ(tc.fd_sub, res_sub);
  }
}

TEST(madd_msub_s) {
  if (kArchVariant == kMips64r6) return;
  helper_madd_msub_maddf_msubf<float>([](MacroAssembler& assm) {
    __ Madd_s(f10, f4, f6, f8, f12);
    __ Swc1(f10, MemOperand(a0, offsetof(TestCaseMaddMsub<float>, fd_add)));
    __ Msub_s(f16, f4, f6, f8, f12);
    __ Swc1(f16, MemOperand(a0, offsetof(TestCaseMaddMsub<float>, fd_sub)));
  });
}

TEST(madd_msub_d) {
  if (kArchVariant == kMips64r6) return;
  helper_madd_msub_maddf_msubf<double>([](MacroAssembler& assm) {
    __ Madd_d(f10, f4, f6, f8, f12);
    __ Sdc1(f10, MemOperand(a0, offsetof(TestCaseMaddMsub<double>, fd_add)));
    __ Msub_d(f16, f4, f6, f8, f12);
    __ Sdc1(f16, MemOperand(a0, offsetof(TestCaseMaddMsub<double>, fd_sub)));
  });
}

TEST(maddf_msubf_s) {
  if (kArchVariant != kMips64r6) return;
  helper_madd_msub_maddf_msubf<float>([](MacroAssembler& assm) {
    __ maddf_s(f4, f6, f8);
    __ Swc1(f4, MemOperand(a0, offsetof(TestCaseMaddMsub<float>, fd_add)));
    __ msubf_s(f16, f6, f8);
    __ Swc1(f16, MemOperand(a0, offsetof(TestCaseMaddMsub<float>, fd_sub)));
  });
}

TEST(maddf_msubf_d) {
  if (kArchVariant != kMips64r6) return;
  helper_madd_msub_maddf_msubf<double>([](MacroAssembler& assm) {
    __ maddf_d(f4, f6, f8);
    __ Sdc1(f4, MemOperand(a0, offsetof(TestCaseMaddMsub<double>, fd_add)));
    __ msubf_d(f16, f6, f8);
    __ Sdc1(f16, MemOperand(a0, offsetof(TestCaseMaddMsub<double>, fd_sub)));
  });
}

uint64_t run_Subu(uint64_t imm, int32_t num_instr) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label code_start;
  __ bind(&code_start);
  __ Subu(v0, zero_reg, Operand(imm));
  CHECK_EQ(assm.InstructionsGeneratedSince(&code_start),
```