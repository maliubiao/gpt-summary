Response:
The user wants to understand the functionality of the given C++ code snippet, which is part of the V8 JavaScript engine's test suite for MIPS64 architecture's assembler.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Function:** The file `test-assembler-mips64.cc` and the presence of `TEST()` macros strongly indicate this is a unit test file. It specifically tests the `MacroAssembler` class for MIPS64, which is responsible for generating machine code.

2. **Analyze Individual Tests:**  Go through each `TEST()` block and understand what it's doing. Focus on the macro-instructions being tested (`Subu`, `Dsubu`, `Dins`, `Ins`, `Ext`, and various MSA (MIPS SIMD Architecture) instructions).

3. **Determine the Purpose of Each Test:**
    * **Arithmetic Operations (`Subu`, `Dsubu`):** These tests verify the correct generation of instructions for subtraction with immediate operands, covering different immediate value ranges and instruction sequences.
    * **Bit Manipulation (`Dins`, `Ins`, `Ext`):** These tests check the bitwise insertion and extraction instructions, ensuring they manipulate bits correctly within registers.
    * **MSA Instructions:** The tests starting with `MSA_` exercise the MIPS SIMD Architecture instructions, which operate on vector registers for parallel processing. These include filling registers, copying data, inserting elements, and control register manipulation.

4. **Infer Overall Functionality:** Based on the individual tests, the primary function of this file is to **validate the correctness of the MIPS64 assembler in V8.** It ensures that the `MacroAssembler` generates the expected machine code sequences for various instructions and that these instructions produce the correct results when executed.

5. **Address Specific User Queries:**
    * **`.tq` extension:** The code snippet is `.cc`, not `.tq`, so it's C++, not Torque.
    * **Relationship to JavaScript:** This code directly relates to how V8 executes JavaScript on MIPS64. When JavaScript code needs to perform low-level operations, V8's code generator uses the `MacroAssembler` (and thus the tested instructions) to produce the necessary machine code.
    * **JavaScript Examples:**  Provide simple JavaScript examples that would conceptually trigger the underlying assembly instructions being tested. For instance, bitwise operations, arithmetic, and potentially optimized array manipulations could involve these instructions.
    * **Code Logic and I/O:**  The tests set up specific input values, execute the generated code, and compare the output with expected results. Provide a concrete example with input and output for one of the tests.
    * **Common Programming Errors:** Relate the tested instructions to potential errors programmers might make when working with low-level bit manipulation or arithmetic, such as incorrect bit shifting, sign extension issues, or integer overflow/underflow.
    * **Summary:**  Concise summary of the file's role within V8's testing framework.

6. **Structure the Answer:** Organize the information logically with clear headings and explanations for each point raised in the user's request.

7. **Review and Refine:** Check for clarity, accuracy, and completeness. Ensure the JavaScript examples are relevant and the explanations are easy to understand. Make sure the code logic example clearly shows the input and expected output.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Just list the instructions being tested.
* **Correction:**  Realized the user wants to understand the *purpose* of testing these instructions, which is to validate the assembler.
* **Initial thought:**  Provide very complex JavaScript examples.
* **Correction:** Simplified the JavaScript examples to directly illustrate the *concept* without getting bogged down in V8 internals.
* **Initial thought:** Focus only on the technical details of the assembly instructions.
* **Correction:** Included the connection to potential user programming errors to make the information more broadly relevant.
* **Initial thought:**  Present the tests in the order they appear in the code.
* **Correction:** Grouped the tests by functionality (arithmetic, bit manipulation, MSA) for better clarity.```cpp
 num_instr);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}

TEST(Subu) {
  CcTest::InitializeVM();

  // Test Subu macro-instruction for min_int16 and max_int16 border cases.
  // For subtracting int16 immediate values we use addiu.

  struct TestCaseSubu {
    uint64_t imm;
    uint64_t expected_res;
    int32_t num_instr;
  };

  // We call Subu(v0, zero_reg, imm) to test cases listed below.
  // 0 - imm = expected_res
  // clang-format off
  struct TestCaseSubu tc[] = {
      //              imm, expected_res, num_instr
      {0xFFFFFFFFFFFF8000,       0x8000,         2},  // min_int16
      // The test case above generates ori + addu instruction sequence.
      // We can't have just addiu because -min_int16 > max_int16 so use
      // register. We can load min_int16 to at register with addiu and then
      // subtract at with subu, but now we use ori + addu because -min_int16 can
      // be loaded using ori.
      {0x8000,       0xFFFFFFFFFFFF8000,         1},  // max_int16 + 1
      // Generates addiu
      // max_int16 + 1 is not int16 but -(max_int16 + 1) is, just use addiu.
      {0xFFFFFFFFFFFF7FFF,       0x8001,         2},  // min_int16 - 1
      // Generates ori + addu
      // To load this value to at we need two instructions and another one to
      // subtract, lui + ori + subu. But we can load -value to at using just
      // ori and then add at register with addu.
      {0x8001,       0xFFFFFFFFFFFF7FFF,         2},  // max_int16 + 2
      // Generates ori + subu
      // Not int16 but is uint16, load value to at with ori and subtract with
      // subu.
      {0x00010000,   0xFFFFFFFFFFFF0000,         2},
      // Generates lui + subu
      // Load value using lui to at and subtract with subu.
      {0x00010001,   0xFFFFFFFFFFFEFFFF,         3},
      // Generates lui + ori + subu
      // We have to generate three instructions in this case.
      {0x7FFFFFFF,   0xFFFFFFFF80000001,         3},  // max_int32
      // Generates lui + ori + subu
      {0xFFFFFFFF80000000, 0xFFFFFFFF80000000,   2},  // min_int32
      // The test case above generates lui + subu intruction sequence.
      // The result of 0 - min_int32 eqauls max_int32 + 1, which wraps around to
      // min_int32 again.
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseSubu);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    CHECK_EQ(tc[i].expected_res, run_Subu(tc[i].imm, tc[i].num_instr));
  }
}

uint64_t run_Dsubu(uint64_t imm, int32_t num_instr) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label code_start;
  __ bind(&code_start);
  __ Dsubu(v0, zero_reg, Operand(imm));
  CHECK_EQ(assm.InstructionsGeneratedSince(&code_start), num_instr);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}

TEST(Dsubu) {
  CcTest::InitializeVM();

  // Test Dsubu macro-instruction for min_int16 and max_int16 border cases.
  // For subtracting int16 immediate values we use daddiu.

  struct TestCaseDsubu {
    uint64_t imm;
    uint64_t expected_res;
    int32_t num_instr;
  };

  // We call Dsubu(v0, zero_reg, imm) to test cases listed below.
  // 0 - imm = expected_res
  // clang-format off
  struct TestCaseDsubu tc[] = {
      //        imm, expected_res, num_instr
      {0xFFFFFFFFFFFF8000, 0x8000, 2},  // min_int16
      // The test case above generates daddiu + dsubu instruction sequence.
      // We can't have just daddiu because -min_int16 > max_int16 so use
      // register, but we can load min_int16 to at register with daddiu and then
      // subtract at with dsubu.
      {0x8000, 0xFFFFFFFFFFFF8000, 1},  // max_int16 + 1
      // Generates daddiu
      // max_int16 + 1 is not int16 but -(max_int16 + 1) is, just use daddiu.
      {0xFFFFFFFFFFFF7FFF, 0x8001, 2},  // min_int16 - 1
      // Generates ori + daddu
      // To load this value to at we need two instructions and another one to
      // subtract, lui + ori + dsubu. But we can load -value to at using just
      // ori and then dadd at register with daddu.
      {0x8001, 0xFFFFFFFFFFFF7FFF, 2},  // max_int16 + 2
      // Generates ori + dsubu
      // Not int16 but is uint16, load value to at with ori and subtract with
      // dsubu.
      {0x00010000, 0xFFFFFFFFFFFF0000, 2},
      // Generates lui + dsubu
      // Load value using lui to at and subtract with dsubu.
      {0x00010001, 0xFFFFFFFFFFFEFFFF, 3},
      // Generates lui + ori + dsubu
      // We have to generate three instructions in this case.
      {0x7FFFFFFF, 0xFFFFFFFF80000001, 3},  // max_int32
      // Generates lui + ori + dsubu
      {0xFFFFFFFF80000000, 0x0000000080000000, 2},  // min_int32
      // Generates lui + dsubu
      // The result of 0 - min_int32 eqauls max_int32 + 1, which fits into a 64
      // bit register, Dsubu gives a different result here.
      {0x7FFFFFFFFFFFFFFF, 0x8000000000000001, 3},  // max_int64
      // r2 - Generates daddiu + dsrl + dsubu
      // r6 - Generates daddiu + dati + dsubu
      {0x8000000000000000, 0x8000000000000000, 3},  // min_int64
      // The test case above generates:
      // r2 - daddiu + dsll32 + dsubu instruction sequence,
      // r6 - ori + dati + dsubu.
      // The result of 0 - min_int64 eqauls max_int64 + 1, which wraps around to
      // min_int64 again.
      {0xFFFF0000FFFFFFFF, 0x0000FFFF00000001, 4},
      // The test case above generates:
      // r2 - ori + dsll32 + ori + daddu instruction sequence,
      // r6 - daddiu + dahi + dati + dsubu.
      // For r2 loading imm would take more instructions than loading -imm so we
      // can load -imm and add with daddu.
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseDsubu);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    CHECK_EQ(tc[i].expected_res, run_Dsubu(tc[i].imm, tc[i].num_instr));
  }
}

uint64_t run_Dins(uint64_t imm, uint64_t source, uint16_t pos, uint16_t size) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ li(v0, imm);
  __ li(t0, source);
  __ Dins(v0, t0, pos, size);
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

TEST(Dins) {
  CcTest::InitializeVM();

  // Test Dins macro-instruction.

  struct TestCaseDins {
    uint64_t imm;
    uint64_t source;
    uint16_t pos;
    uint16_t size;
    uint64_t expected_res;
  };

  // We load imm to v0 and source to t0 and then call
  // Dins(v0, t0, pos, size) to test cases listed below.
  // clang-format off
  struct TestCaseDins tc[] = {
      // imm, source, pos, size, expected_res
      {0x5555555555555555, 0x1ABCDEF01, 31, 1, 0x55555555D5555555},
      {0x5555555555555555, 0x1ABCDEF02, 30, 2, 0x5555555595555555},
      {0x201234567, 0x1FABCDEFF, 0, 32, 0x2FABCDEFF},
      {0x201234567, 0x7FABCDEFF, 31, 2, 0x381234567},
      {0x800000000, 0x7FABCDEFF, 0, 33, 0x9FABCDEFF},
      {0x1234, 0xABCDABCDABCDABCD, 0, 64, 0xABCDABCDABCDABCD},
      {0xABCD, 0xABCEABCF, 32, 1, 0x10000ABCD},
      {0xABCD, 0xABCEABCF, 63, 1, 0x800000000000ABCD},
      {0x10000ABCD, 0xABC1ABC2ABC3ABC4, 32, 32, 0xABC3ABC40000ABCD},
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseDins);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    CHECK_EQ(tc[i].expected_res,
             run_Dins(tc[i].imm, tc[i].source, tc[i].pos, tc[i].size));
  }
}

uint64_t run_Ins(uint64_t imm, uint64_t source, uint16_t pos, uint16_t size) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ li(v0, imm);
  __ li(t0, source);
  __ Ins(v0, t0, pos, size);
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

TEST(Ins) {
  CcTest::InitializeVM();

  //       run_Ins(rt_value, rs_value, pos, size),
  //       expected_result
  CHECK_EQ(run_Ins(0x0000000055555555, 0xFFFFFFFFABCDEF01, 31, 1),
           0xFFFFFFFFD5555555);
  CHECK_EQ(run_Ins(0x0000000055555555, 0xFFFFFFFFABCDEF02, 30, 2),
           0xFFFFFFFF95555555);
  CHECK_EQ(run_Ins(0x0000000001234567, 0xFFFFFFFFFABCDEFF, 0, 32),
           0xFFFFFFFFFABCDEFF);

  // Results with positive sign.
  CHECK_EQ(run_Ins(0x0000000055555550, 0xFFFFFFFF80000001, 0, 1),
           0x0000000055555551);
  CHECK_EQ(run_Ins(0x0000000055555555, 0x0000000040000001, 0, 32),
           0x0000000040000001);
  CHECK_EQ(run_Ins(0x0000000055555555, 0x0000000020000001, 1, 31),
           0x0000000040000003);
  CHECK_EQ(run_Ins(0x0000000055555555, 0xFFFFFFFF80700001, 8, 24),
           0x0000000070000155);
  CHECK_EQ(run_Ins(0x0000000055555555, 0xFFFFFFFF80007001, 16, 16),
           0x0000000070015555);
  CHECK_EQ(run_Ins(0x0000000055555555, 0xFFFFFFFF80000071, 24, 8),
           0x0000000071555555);
  CHECK_EQ(run_Ins(0x0000000075555555, 0x0000000040000000, 31, 1),
           0x0000000075555555);

  // Results with negative sign.
  CHECK_EQ(run_Ins(0xFFFFFFFF85555550, 0xFFFFFFFF80000001, 0, 1),
           0xFFFFFFFF85555551);
  CHECK_EQ(run_Ins(0x0000000055555555, 0xFFFFFFFF80000001, 0, 32),
           0xFFFFFFFF80000001);
  CHECK_EQ(run_Ins(0x0000000055555555, 0x0000000040000001, 1, 31),
           0xFFFFFFFF80000003);
  CHECK_EQ(run_Ins(0x0000000055555555, 0xFFFFFFFF80800001, 8, 24),
           0xFFFFFFFF80000155);
  CHECK_EQ(run_Ins(0x0000000055555555, 0xFFFFFFFF80008001, 16, 16),
           0xFFFFFFFF80015555);
  CHECK_EQ(run_Ins(0x0000000055555555, 0xFFFFFFFF80000081, 24, 8),
           0xFFFFFFFF81555555);
  CHECK_EQ(run_Ins(0x0000000075555555, 0x0000000000000001, 31, 1),
           0xFFFFFFFFF5555555);
}

uint64_t run_Ext(uint64_t source, uint16_t pos, uint16_t size) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ li(v0, 0xFFFFFFFFFFFFFFFF);
  __ li(t0, source);
  __ Ext(v0, t0, pos, size);
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

TEST(Ext) {
  CcTest::InitializeVM();

  // Source values with negative sign.
  //       run_Ext(rs_value, pos, size), expected_result
  CHECK_EQ(run_Ext(0xFFFFFFFF80000001, 0, 1), 0x0000000000000001);
  CHECK_EQ(run_Ext(0xFFFFFFFF80000001, 0, 32), 0xFFFFFFFF80000001);
  CHECK_EQ(run_Ext(0xFFFFFFFF80000002, 1, 31), 0x0000000040000001);
  CHECK_EQ(run_Ext(0xFFFFFFFF80000100, 8, 24), 0x0000000000800001);
  CHECK_EQ(run_Ext(0xFFFFFFFF80010000, 16, 16), 0x0000000000008001);
  CHECK_EQ(run_Ext(0xFFFFFFFF81000000, 24, 8), 0x0000000000000081);
  CHECK_EQ(run_Ext(0xFFFFFFFF80000000, 31, 1), 0x0000000000000001);

  // Source values with positive sign.
  CHECK_EQ(run_Ext(0x0000000000000001, 0, 1), 0x0000000000000001);
  CHECK_EQ(run_Ext(0x0000000040000001, 0, 32), 0x0000000040000001);
  CHECK_EQ(run_Ext(0x0000000040000002, 1, 31), 0x0000000020000001);
  CHECK_EQ(run_Ext(0x0000000040000100, 8, 24), 0x0000000000400001);
  CHECK_EQ(run_Ext(0x0000000040010000, 16, 16), 0x0000000000004001);
  CHECK_EQ(run_Ext(0x0000000041000000, 24, 8), 0x0000000000000041);
  CHECK_EQ(run_Ext(0x0000000040000000, 31, 1), 0x0000000000000000);
}

TEST(MSA_fill_copy) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    uint64_t u8;
    uint64_t u16;
    uint64_t u32;
    uint64_t s8;
    uint64_t s16;
    uint64_t s32;
    uint64_t s64;
  };
  T t;

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  {
    CpuFeatureScope fscope(&assm, MIPS_SIMD);

    __ li(t0, 0x9E7689ACA512B683);

    __ fill_b(w0, t0);
    __ fill_h(w2, t0);
    __ fill_w(w4, t0);
    __ fill_d(w6, t0);
    __ copy_u_b(t1, w0, 11);
    __ sd(t1, MemOperand(a0, offsetof(T, u8)));
    __ copy_u_h(t1, w2, 6);
    __ sd(t1, MemOperand(a0, offsetof(T, u16)));
    __ copy_u_w(t1, w4, 3);
    __ sd(t1, MemOperand(a0, offsetof(T, u32)));

    __ copy_s_b(t1, w0, 8);
    __ sd(t1, MemOperand(a0, offsetof(T, s8)));
    __ copy_s_h(t1, w2, 5);
    __ sd(t1, MemOperand(a0, offsetof(T, s16)));
    __ copy_s_w(t1, w4, 1);
    __ sd(t1, MemOperand(a0, offsetof(T, s32)));
    __ copy_s_d(t1, w6, 0);
    __ sd(t1, MemOperand(a0, offsetof(T, s64)));

    __ jr(ra);
    __ nop();
  }

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);

  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(0x83u, t.u8);
  CHECK_EQ(0xB683u, t.u16);
  CHECK_EQ(0xA512B683u, t.u32);
  CHECK_EQ(0xFFFFFFFFFFFFFF83u, t.s8);
  CHECK_EQ(0xFFFFFFFFFFFFB683u, t.s16);
  CHECK_EQ(0xFFFFFFFFA512B683u, t.s32);
  CHECK_EQ(0x9E7689ACA512B683u, t.s64);
}

TEST(MSA_fill_copy_2) {
  // Similar to MSA_fill_copy test, but also check overlaping between MSA and
  // FPU registers with same numbers
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    uint64_t d0;
    uint64_t d1;
  };
  T t[2];

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  {
    CpuFeatureScope fscope(&assm, MIPS_SIMD);

    __ li(t0, 0xAAAAAAAAAAAAAAAA);
    __ li(t1, 0x5555555555555555);

    __ fill_d(w0, t0);
    __ fill_d(w2, t0);

    __ Move(f0, t1);
    __ Move(f2, t1);

#define STORE_MSA_REG(w_reg, base, scratch)          \
  __ copy_s_d(scratch, w_reg, 0);                    \
  __ sd(scratch, MemOperand(base, offsetof(T, d0))); \
  __ copy_s_d(scratch, w_reg, 1);                    \
  __ sd(scratch, MemOperand(base, offsetof(T, d1)));

    STORE_MSA_REG(w0, a0, t2)
    STORE_MSA_REG(w2, a1, t2)
#undef STORE_MSA_REG

    __ jr(ra);
    __ nop();
  }

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F5>::FromCode(isolate, *code);

  f.Call(&t[0], &t[1], 0, 0, 0);

  CHECK_EQ(0x5555555555555555, t[0].d0);
  CHECK_EQ(0xAAAAAAAAAAAAAAAA, t[0].d1);
  CHECK_EQ(0x5555555555555555, t[1].d0);
  CHECK_EQ(0xAAAAAAAAAAAAAAAA, t[1].d1);
}

TEST(MSA_fill_copy_3) {
  // Similar to MSA_fill_copy test, but also check overlaping between MSA and

Prompt: 
```
这是目录为v8/test/cctest/test-assembler-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共13部分，请归纳一下它的功能

"""
 num_instr);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}

TEST(Subu) {
  CcTest::InitializeVM();

  // Test Subu macro-instruction for min_int16 and max_int16 border cases.
  // For subtracting int16 immediate values we use addiu.

  struct TestCaseSubu {
    uint64_t imm;
    uint64_t expected_res;
    int32_t num_instr;
  };

  // We call Subu(v0, zero_reg, imm) to test cases listed below.
  // 0 - imm = expected_res
  // clang-format off
  struct TestCaseSubu tc[] = {
      //              imm, expected_res, num_instr
      {0xFFFFFFFFFFFF8000,       0x8000,         2},  // min_int16
      // The test case above generates ori + addu instruction sequence.
      // We can't have just addiu because -min_int16 > max_int16 so use
      // register. We can load min_int16 to at register with addiu and then
      // subtract at with subu, but now we use ori + addu because -min_int16 can
      // be loaded using ori.
      {0x8000,       0xFFFFFFFFFFFF8000,         1},  // max_int16 + 1
      // Generates addiu
      // max_int16 + 1 is not int16 but -(max_int16 + 1) is, just use addiu.
      {0xFFFFFFFFFFFF7FFF,       0x8001,         2},  // min_int16 - 1
      // Generates ori + addu
      // To load this value to at we need two instructions and another one to
      // subtract, lui + ori + subu. But we can load -value to at using just
      // ori and then add at register with addu.
      {0x8001,       0xFFFFFFFFFFFF7FFF,         2},  // max_int16 + 2
      // Generates ori + subu
      // Not int16 but is uint16, load value to at with ori and subtract with
      // subu.
      {0x00010000,   0xFFFFFFFFFFFF0000,         2},
      // Generates lui + subu
      // Load value using lui to at and subtract with subu.
      {0x00010001,   0xFFFFFFFFFFFEFFFF,         3},
      // Generates lui + ori + subu
      // We have to generate three instructions in this case.
      {0x7FFFFFFF,   0xFFFFFFFF80000001,         3},  // max_int32
      // Generates lui + ori + subu
      {0xFFFFFFFF80000000, 0xFFFFFFFF80000000,   2},  // min_int32
      // The test case above generates lui + subu intruction sequence.
      // The result of 0 - min_int32 eqauls max_int32 + 1, which wraps around to
      // min_int32 again.
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseSubu);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    CHECK_EQ(tc[i].expected_res, run_Subu(tc[i].imm, tc[i].num_instr));
  }
}

uint64_t run_Dsubu(uint64_t imm, int32_t num_instr) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label code_start;
  __ bind(&code_start);
  __ Dsubu(v0, zero_reg, Operand(imm));
  CHECK_EQ(assm.InstructionsGeneratedSince(&code_start), num_instr);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}

TEST(Dsubu) {
  CcTest::InitializeVM();

  // Test Dsubu macro-instruction for min_int16 and max_int16 border cases.
  // For subtracting int16 immediate values we use daddiu.

  struct TestCaseDsubu {
    uint64_t imm;
    uint64_t expected_res;
    int32_t num_instr;
  };

  // We call Dsubu(v0, zero_reg, imm) to test cases listed below.
  // 0 - imm = expected_res
  // clang-format off
  struct TestCaseDsubu tc[] = {
      //        imm, expected_res, num_instr
      {0xFFFFFFFFFFFF8000, 0x8000, 2},  // min_int16
      // The test case above generates daddiu + dsubu instruction sequence.
      // We can't have just daddiu because -min_int16 > max_int16 so use
      // register, but we can load min_int16 to at register with daddiu and then
      // subtract at with dsubu.
      {0x8000, 0xFFFFFFFFFFFF8000, 1},  // max_int16 + 1
      // Generates daddiu
      // max_int16 + 1 is not int16 but -(max_int16 + 1) is, just use daddiu.
      {0xFFFFFFFFFFFF7FFF, 0x8001, 2},  // min_int16 - 1
      // Generates ori + daddu
      // To load this value to at we need two instructions and another one to
      // subtract, lui + ori + dsubu. But we can load -value to at using just
      // ori and then dadd at register with daddu.
      {0x8001, 0xFFFFFFFFFFFF7FFF, 2},  // max_int16 + 2
      // Generates ori + dsubu
      // Not int16 but is uint16, load value to at with ori and subtract with
      // dsubu.
      {0x00010000, 0xFFFFFFFFFFFF0000, 2},
      // Generates lui + dsubu
      // Load value using lui to at and subtract with dsubu.
      {0x00010001, 0xFFFFFFFFFFFEFFFF, 3},
      // Generates lui + ori + dsubu
      // We have to generate three instructions in this case.
      {0x7FFFFFFF, 0xFFFFFFFF80000001, 3},  // max_int32
      // Generates lui + ori + dsubu
      {0xFFFFFFFF80000000, 0x0000000080000000, 2},  // min_int32
      // Generates lui + dsubu
      // The result of 0 - min_int32 eqauls max_int32 + 1, which fits into a 64
      // bit register, Dsubu gives a different result here.
      {0x7FFFFFFFFFFFFFFF, 0x8000000000000001, 3},  // max_int64
      // r2 - Generates daddiu + dsrl + dsubu
      // r6 - Generates daddiu + dati + dsubu
      {0x8000000000000000, 0x8000000000000000, 3},  // min_int64
      // The test case above generates:
      // r2 - daddiu + dsll32 + dsubu instruction sequence,
      // r6 - ori + dati + dsubu.
      // The result of 0 - min_int64 eqauls max_int64 + 1, which wraps around to
      // min_int64 again.
      {0xFFFF0000FFFFFFFF, 0x0000FFFF00000001, 4},
      // The test case above generates:
      // r2 - ori + dsll32 + ori + daddu instruction sequence,
      // r6 - daddiu + dahi + dati + dsubu.
      // For r2 loading imm would take more instructions than loading -imm so we
      // can load -imm and add with daddu.
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseDsubu);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    CHECK_EQ(tc[i].expected_res, run_Dsubu(tc[i].imm, tc[i].num_instr));
  }
}

uint64_t run_Dins(uint64_t imm, uint64_t source, uint16_t pos, uint16_t size) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ li(v0, imm);
  __ li(t0, source);
  __ Dins(v0, t0, pos, size);
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

TEST(Dins) {
  CcTest::InitializeVM();

  // Test Dins macro-instruction.

  struct TestCaseDins {
    uint64_t imm;
    uint64_t source;
    uint16_t pos;
    uint16_t size;
    uint64_t expected_res;
  };

  // We load imm to v0 and source to t0 and then call
  // Dins(v0, t0, pos, size) to test cases listed below.
  // clang-format off
  struct TestCaseDins tc[] = {
      // imm, source, pos, size, expected_res
      {0x5555555555555555, 0x1ABCDEF01, 31, 1, 0x55555555D5555555},
      {0x5555555555555555, 0x1ABCDEF02, 30, 2, 0x5555555595555555},
      {0x201234567, 0x1FABCDEFF, 0, 32, 0x2FABCDEFF},
      {0x201234567, 0x7FABCDEFF, 31, 2, 0x381234567},
      {0x800000000, 0x7FABCDEFF, 0, 33, 0x9FABCDEFF},
      {0x1234, 0xABCDABCDABCDABCD, 0, 64, 0xABCDABCDABCDABCD},
      {0xABCD, 0xABCEABCF, 32, 1, 0x10000ABCD},
      {0xABCD, 0xABCEABCF, 63, 1, 0x800000000000ABCD},
      {0x10000ABCD, 0xABC1ABC2ABC3ABC4, 32, 32, 0xABC3ABC40000ABCD},
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseDins);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    CHECK_EQ(tc[i].expected_res,
             run_Dins(tc[i].imm, tc[i].source, tc[i].pos, tc[i].size));
  }
}

uint64_t run_Ins(uint64_t imm, uint64_t source, uint16_t pos, uint16_t size) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ li(v0, imm);
  __ li(t0, source);
  __ Ins(v0, t0, pos, size);
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

TEST(Ins) {
  CcTest::InitializeVM();

  //       run_Ins(rt_value, rs_value, pos, size),
  //       expected_result
  CHECK_EQ(run_Ins(0x0000000055555555, 0xFFFFFFFFABCDEF01, 31, 1),
           0xFFFFFFFFD5555555);
  CHECK_EQ(run_Ins(0x0000000055555555, 0xFFFFFFFFABCDEF02, 30, 2),
           0xFFFFFFFF95555555);
  CHECK_EQ(run_Ins(0x0000000001234567, 0xFFFFFFFFFABCDEFF, 0, 32),
           0xFFFFFFFFFABCDEFF);

  // Results with positive sign.
  CHECK_EQ(run_Ins(0x0000000055555550, 0xFFFFFFFF80000001, 0, 1),
           0x0000000055555551);
  CHECK_EQ(run_Ins(0x0000000055555555, 0x0000000040000001, 0, 32),
           0x0000000040000001);
  CHECK_EQ(run_Ins(0x0000000055555555, 0x0000000020000001, 1, 31),
           0x0000000040000003);
  CHECK_EQ(run_Ins(0x0000000055555555, 0xFFFFFFFF80700001, 8, 24),
           0x0000000070000155);
  CHECK_EQ(run_Ins(0x0000000055555555, 0xFFFFFFFF80007001, 16, 16),
           0x0000000070015555);
  CHECK_EQ(run_Ins(0x0000000055555555, 0xFFFFFFFF80000071, 24, 8),
           0x0000000071555555);
  CHECK_EQ(run_Ins(0x0000000075555555, 0x0000000040000000, 31, 1),
           0x0000000075555555);

  // Results with negative sign.
  CHECK_EQ(run_Ins(0xFFFFFFFF85555550, 0xFFFFFFFF80000001, 0, 1),
           0xFFFFFFFF85555551);
  CHECK_EQ(run_Ins(0x0000000055555555, 0xFFFFFFFF80000001, 0, 32),
           0xFFFFFFFF80000001);
  CHECK_EQ(run_Ins(0x0000000055555555, 0x0000000040000001, 1, 31),
           0xFFFFFFFF80000003);
  CHECK_EQ(run_Ins(0x0000000055555555, 0xFFFFFFFF80800001, 8, 24),
           0xFFFFFFFF80000155);
  CHECK_EQ(run_Ins(0x0000000055555555, 0xFFFFFFFF80008001, 16, 16),
           0xFFFFFFFF80015555);
  CHECK_EQ(run_Ins(0x0000000055555555, 0xFFFFFFFF80000081, 24, 8),
           0xFFFFFFFF81555555);
  CHECK_EQ(run_Ins(0x0000000075555555, 0x0000000000000001, 31, 1),
           0xFFFFFFFFF5555555);
}

uint64_t run_Ext(uint64_t source, uint16_t pos, uint16_t size) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ li(v0, 0xFFFFFFFFFFFFFFFF);
  __ li(t0, source);
  __ Ext(v0, t0, pos, size);
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

TEST(Ext) {
  CcTest::InitializeVM();

  // Source values with negative sign.
  //       run_Ext(rs_value, pos, size), expected_result
  CHECK_EQ(run_Ext(0xFFFFFFFF80000001, 0, 1), 0x0000000000000001);
  CHECK_EQ(run_Ext(0xFFFFFFFF80000001, 0, 32), 0xFFFFFFFF80000001);
  CHECK_EQ(run_Ext(0xFFFFFFFF80000002, 1, 31), 0x0000000040000001);
  CHECK_EQ(run_Ext(0xFFFFFFFF80000100, 8, 24), 0x0000000000800001);
  CHECK_EQ(run_Ext(0xFFFFFFFF80010000, 16, 16), 0x0000000000008001);
  CHECK_EQ(run_Ext(0xFFFFFFFF81000000, 24, 8), 0x0000000000000081);
  CHECK_EQ(run_Ext(0xFFFFFFFF80000000, 31, 1), 0x0000000000000001);

  // Source values with positive sign.
  CHECK_EQ(run_Ext(0x0000000000000001, 0, 1), 0x0000000000000001);
  CHECK_EQ(run_Ext(0x0000000040000001, 0, 32), 0x0000000040000001);
  CHECK_EQ(run_Ext(0x0000000040000002, 1, 31), 0x0000000020000001);
  CHECK_EQ(run_Ext(0x0000000040000100, 8, 24), 0x0000000000400001);
  CHECK_EQ(run_Ext(0x0000000040010000, 16, 16), 0x0000000000004001);
  CHECK_EQ(run_Ext(0x0000000041000000, 24, 8), 0x0000000000000041);
  CHECK_EQ(run_Ext(0x0000000040000000, 31, 1), 0x0000000000000000);
}

TEST(MSA_fill_copy) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    uint64_t u8;
    uint64_t u16;
    uint64_t u32;
    uint64_t s8;
    uint64_t s16;
    uint64_t s32;
    uint64_t s64;
  };
  T t;

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  {
    CpuFeatureScope fscope(&assm, MIPS_SIMD);

    __ li(t0, 0x9E7689ACA512B683);

    __ fill_b(w0, t0);
    __ fill_h(w2, t0);
    __ fill_w(w4, t0);
    __ fill_d(w6, t0);
    __ copy_u_b(t1, w0, 11);
    __ sd(t1, MemOperand(a0, offsetof(T, u8)));
    __ copy_u_h(t1, w2, 6);
    __ sd(t1, MemOperand(a0, offsetof(T, u16)));
    __ copy_u_w(t1, w4, 3);
    __ sd(t1, MemOperand(a0, offsetof(T, u32)));

    __ copy_s_b(t1, w0, 8);
    __ sd(t1, MemOperand(a0, offsetof(T, s8)));
    __ copy_s_h(t1, w2, 5);
    __ sd(t1, MemOperand(a0, offsetof(T, s16)));
    __ copy_s_w(t1, w4, 1);
    __ sd(t1, MemOperand(a0, offsetof(T, s32)));
    __ copy_s_d(t1, w6, 0);
    __ sd(t1, MemOperand(a0, offsetof(T, s64)));

    __ jr(ra);
    __ nop();
  }

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);

  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(0x83u, t.u8);
  CHECK_EQ(0xB683u, t.u16);
  CHECK_EQ(0xA512B683u, t.u32);
  CHECK_EQ(0xFFFFFFFFFFFFFF83u, t.s8);
  CHECK_EQ(0xFFFFFFFFFFFFB683u, t.s16);
  CHECK_EQ(0xFFFFFFFFA512B683u, t.s32);
  CHECK_EQ(0x9E7689ACA512B683u, t.s64);
}

TEST(MSA_fill_copy_2) {
  // Similar to MSA_fill_copy test, but also check overlaping between MSA and
  // FPU registers with same numbers
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    uint64_t d0;
    uint64_t d1;
  };
  T t[2];

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  {
    CpuFeatureScope fscope(&assm, MIPS_SIMD);

    __ li(t0, 0xAAAAAAAAAAAAAAAA);
    __ li(t1, 0x5555555555555555);

    __ fill_d(w0, t0);
    __ fill_d(w2, t0);

    __ Move(f0, t1);
    __ Move(f2, t1);

#define STORE_MSA_REG(w_reg, base, scratch)          \
  __ copy_s_d(scratch, w_reg, 0);                    \
  __ sd(scratch, MemOperand(base, offsetof(T, d0))); \
  __ copy_s_d(scratch, w_reg, 1);                    \
  __ sd(scratch, MemOperand(base, offsetof(T, d1)));

    STORE_MSA_REG(w0, a0, t2)
    STORE_MSA_REG(w2, a1, t2)
#undef STORE_MSA_REG

    __ jr(ra);
    __ nop();
  }

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F5>::FromCode(isolate, *code);

  f.Call(&t[0], &t[1], 0, 0, 0);

  CHECK_EQ(0x5555555555555555, t[0].d0);
  CHECK_EQ(0xAAAAAAAAAAAAAAAA, t[0].d1);
  CHECK_EQ(0x5555555555555555, t[1].d0);
  CHECK_EQ(0xAAAAAAAAAAAAAAAA, t[1].d1);
}

TEST(MSA_fill_copy_3) {
  // Similar to MSA_fill_copy test, but also check overlaping between MSA and
  // FPU registers with same numbers
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    uint64_t d0;
    uint64_t d1;
  };
  T t[2];

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  {
    CpuFeatureScope fscope(&assm, MIPS_SIMD);

    __ li(t0, 0xAAAAAAAAAAAAAAAA);
    __ li(t1, 0x5555555555555555);

    __ Move(f0, t0);
    __ Move(f2, t0);

    __ fill_d(w0, t1);
    __ fill_d(w2, t1);

    __ Sdc1(f0, MemOperand(a0, offsetof(T, d0)));
    __ Sdc1(f2, MemOperand(a1, offsetof(T, d0)));

    __ jr(ra);
    __ nop();
  }

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F5>::FromCode(isolate, *code);

  f.Call(&t[0], &t[1], 0, 0, 0);

  CHECK_EQ(0x5555555555555555, t[0].d0);
  CHECK_EQ(0x5555555555555555, t[1].d0);
}


template <typename T>
void run_msa_insert(int64_t rs_value, int n, msa_reg_t* w) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  CpuFeatureScope fscope(&assm, MIPS_SIMD);

  __ li(t0, -1);
  __ li(t1, rs_value);
  __ fill_w(w0, t0);

  if (std::is_same<T, int8_t>::value) {
    DCHECK_LT(n, 16);
    __ insert_b(w0, n, t1);
  } else if (std::is_same<T, int16_t>::value) {
    DCHECK_LT(n, 8);
    __ insert_h(w0, n, t1);
  } else if (std::is_same<T, int32_t>::value) {
    DCHECK_LT(n, 4);
    __ insert_w(w0, n, t1);
  } else if (std::is_same<T, int64_t>::value) {
    DCHECK_LT(n, 2);
    __ insert_d(w0, n, t1);
  } else {
    UNREACHABLE();
  }

  store_elements_of_vector(&assm, w0, a0);

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

  f.Call(w, 0, 0, 0, 0);
}

TEST(MSA_insert) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  struct TestCaseInsert {
    uint64_t input;
    int n;
    uint64_t exp_res_lo;
    uint64_t exp_res_hi;
  };

  // clang-format off
  struct TestCaseInsert tc_b[] = {
    // input, n,          exp_res_lo,          exp_res_hi
    {  0xA2, 13, 0xFFFFFFFFFFFFFFFFu, 0xFFFFA2FFFFFFFFFFu},
    {  0x73, 10, 0xFFFFFFFFFFFFFFFFu, 0xFFFFFFFFFF73FFFFu},
    {0x3494,  5, 0xFFFF94FFFFFFFFFFu, 0xFFFFFFFFFFFFFFFFu},
    {0xA6B8,  1, 0xFFFFFFFFFFFFB8FFu, 0xFFFFFFFFFFFFFFFFu}
  };
  // clang-format off

  for (size_t i = 0; i < sizeof(tc_b) / sizeof(TestCaseInsert); ++i) {
    msa_reg_t res;
    run_msa_insert<int8_t>(tc_b[i].input, tc_b[i].n, &res);
    CHECK_EQ(tc_b[i].exp_res_lo, res.d[0]);
    CHECK_EQ(tc_b[i].exp_res_hi, res.d[1]);
  }

  // clang-format off
  struct TestCaseInsert tc_h[] = {
    // input, n,          exp_res_lo,          exp_res_hi
    {0x85A2,  7, 0xFFFFFFFFFFFFFFFFu, 0x85A2FFFFFFFFFFFFu},
    {0xE873,  5, 0xFFFFFFFFFFFFFFFFu, 0xFFFFFFFFE873FFFFu},
    {0x3494,  3, 0x3494FFFFFFFFFFFFu, 0xFFFFFFFFFFFFFFFFu},
    {0xA6B8,  1, 0xFFFFFFFFA6B8FFFFu, 0xFFFFFFFFFFFFFFFFu}
  };
  // clang-format on

  for (size_t i = 0; i < sizeof(tc_h) / sizeof(TestCaseInsert); ++i) {
    msa_reg_t res;
    run_msa_insert<int16_t>(tc_h[i].input, tc_h[i].n, &res);
    CHECK_EQ(tc_h[i].exp_res_lo, res.d[0]);
    CHECK_EQ(tc_h[i].exp_res_hi, res.d[1]);
  }

  // clang-format off
  struct TestCaseInsert tc_w[] = {
    //     input, n,          exp_res_lo,          exp_res_hi
    {0xD2F085A2u, 3, 0xFFFFFFFFFFFFFFFFu, 0xD2F085A2FFFFFFFFu},
    {0x4567E873u, 2, 0xFFFFFFFFFFFFFFFFu, 0xFFFFFFFF4567E873u},
    {0xACDB3494u, 1, 0xACDB3494FFFFFFFFu, 0xFFFFFFFFFFFFFFFFu},
    {0x89ABA6B8u, 0, 0xFFFFFFFF89ABA6B8u, 0xFFFFFFFFFFFFFFFFu}
  };
  // clang-format on

  for (size_t i = 0; i < sizeof(tc_w) / sizeof(TestCaseInsert); ++i) {
    msa_reg_t res;
    run_msa_insert<int32_t>(tc_w[i].input, tc_w[i].n, &res);
    CHECK_EQ(tc_w[i].exp_res_lo, res.d[0]);
    CHECK_EQ(tc_w[i].exp_res_hi, res.d[1]);
  }

  // clang-format off
  struct TestCaseInsert tc_d[] = {
    //            input, n,          exp_res_lo,          exp_res_hi
    {0xF35862E13E38F8B0, 1, 0xFFFFFFFFFFFFFFFFu, 0xF35862E13E38F8B0},
    {0x4F41FFDEF2BFE636, 0,  0x4F41FFDEF2BFE636, 0xFFFFFFFFFFFFFFFFu}
  };
  // clang-format on

  for (size_t i = 0; i < sizeof(tc_d) / sizeof(TestCaseInsert); ++i) {
    msa_reg_t res;
    run_msa_insert<int64_t>(tc_d[i].input, tc_d[i].n, &res);
    CHECK_EQ(tc_d[i].exp_res_lo, res.d[0]);
    CHECK_EQ(tc_d[i].exp_res_hi, res.d[1]);
  }
}

void run_msa_ctc_cfc(uint64_t value) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  CpuFeatureScope fscope(&assm, MIPS_SIMD);

  MSAControlRegister msareg = {kMSACSRRegister};
  __ li(t0, value);
  __ li(t2, 0l);
  __ cfcmsa(t1, msareg);
  __ ctcmsa(msareg, t0);
  __ cfcmsa(t2, msareg);
  __ ctcmsa(msareg, t1);
  __ sd(t2, MemOperand(a0, 0));
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

  uint64_t res;
  f.Call(&res, 0, 0, 0, 0);

  CHECK_EQ(
      base::bit_cast<uint64_t>(static_cast<int64_t>(
          base::bit_cast<int32_t>(static_cast<uint32_t>(value & 0x0167FFFF)))),
      res);
}

TEST(MSA_move_v) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    uint64_t ws_lo;
    uint64_t ws_hi;
    uint64_t wd_lo;
    uint64_t wd_hi;
  };
  T t[] = {{0x20B9CC4F1A83E0C5, 0xA27E1B5F2F5BB18A, 0x1E86678B52F8E1FF,
            0x706E51290AC76FB9},
           {0x4414AED7883FFD18, 0x047D183A06B67016, 0x4EF258CF8D822870,
            0x2686B73484C2E843},
           {0xD38FF9D048884FFC, 0x6DC63A57C0943CA7, 0x8520CA2F3E97C426,
            0xA9913868FB819C59}};

  for (unsigned i = 0; i < arraysize(t); ++i) {
    MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
    CpuFeatureScope fscope(&assm, MIPS_SIMD);

    load_elements_of_vector(&assm, &t[i].ws_lo, w0, t0, t1);
    load_elements_of_vector(&assm, &t[i].wd_lo, w2, t0, t1);
    __ move_v(w2, w0);
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
    f.Call(&t[i].wd_lo, 0, 0, 0, 0);
    CHECK_EQ(t[i].ws_lo, t[i].wd_lo);
    CHECK_EQ(t[i].ws_hi, t[i].wd_hi);
  }
}

template <typename ExpectFunc, typename OperFunc>
void run_msa_sldi(OperFunc GenerateOperation,
                  ExpectFunc GenerateExpectedResult) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    uint64_t ws_lo;
    uint64_t ws_hi;
    uint64_t wd_lo;
    uint64_t wd_hi;
  };
  T t[] = {{0x20B9CC4F1A83E0C5, 0xA27E1B5F2F5BB18A, 0x1E86678B52F8E1FF,
            0x706E51290AC76FB9},
           {0x4414AED7883FFD18, 0x047D183A06B67016, 0x4EF258CF8D822870,
            0x2686B73484C2E843},
           {0xD38FF9D048884FFC, 0x6DC63A57C0943CA7, 0x8520CA2F3E97C426,
            0xA9913868FB819C59}};
  uint64_t res[2];

  for (unsigned i = 0; i < arraysize(t); ++i) {
    MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
    CpuFeatureScope fscope(&assm, MIPS_SIMD);
    load_elements_of_vector(&assm, &t[i].ws_lo, w0, t0, t1);
    load_elements_of_vector(&assm, &t[i].wd_lo, w2, t0, t1);
    GenerateOperation(assm);
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
    f.Call(&res[0], 0, 0, 0, 0);
    GenerateExpectedResult(reinterpret_cast<uint8_t*>(&t[i].ws_lo),
                           reinterpret_cast<uint8_t*>(&t[i].wd_lo));
    CHECK_EQ(res[0], t[i].wd_lo);
    CHECK_EQ(res[1], t[i].wd_hi);
  }
}

TEST(MSA_sldi) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;
  CcTest::InitializeVM();

#define SLDI_DF(s, k)                \
  uint8_t v[32];                     \
  for (unsigned i = 0; i < s; i++) { \
    v[i] = ws[s * k + i];            \
    v[i + s] = wd[s * k + i];        \
  }                                  \
  for (unsigned i = 0; i < s; i++) { \
    wd[s * k + i] = v[i + n];        \
  }

  for (int n = 0; n < 16; ++n) {
    run_msa_sldi([n](MacroAssembler& assm) { __ sldi_b(w2, w0, n); },
                 [n](uint8_t* ws, uint8_t* wd) {
                   SLDI_DF(kMSARegSize / sizeof(int8_t) / kBitsPerByte, 0)
                 });
  }

  for (int n = 0; n < 8; ++n) {
    run_msa_sldi([n](MacroAssembler& assm) { __ sldi_h(w2, w0, n); },
                 [n](uint8_t* ws, uint8_t* wd) {
                   for (int k = 0; k < 2; ++k) {
                     SLDI_DF(kMSARegSize / sizeof(int16_t) / kBitsPerByte, k)
                   }
                 });
  }

  for (int n = 0; n < 4; ++n) {
    run_msa_sldi([n](MacroAssembler& assm) { __ sldi_w(w2, w0, n); },
                 [n](uint8_t* ws, uint8_t* wd) {
                   for (int k = 0; k < 4; ++k) {
                     SLDI_DF(kMSARegSize / sizeof(int32_t) / kBitsPerByte, k)
                   }
                 });
  }

  for (int n = 0; n < 2; ++n) {
    run_msa_sldi([n](MacroAssembler& assm) { __ sldi_d(w2, w0, n); },
                 [n](uint8_t* ws, uint8_t* wd) {
                   for (int k = 0; k < 8; ++k) {
                     SLDI_DF(kMSARegSize / sizeof(int64_t) / kBitsPerByte, k)
                   }
                 });
  }
#undef SLDI_DF
}

TEST(MSA_cfc_ctc) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  const uint64_t mask_without_cause = 0xFFFFFFFFFF9C0FFF;
  const uint64_t mask_always_zero = 0x0167FFFF;
  const uint64_t mask_enables = 0x0000000000000F80;
  uint64_t test_case[] = {0x30C6F6352D5EDE31, 0xEFC9FED507955425,
                          0x64F2A3FF15B7DBE3, 0x6AA069352BF8BC37,
                          0x7EA7AB2AE6AAE923, 0xA10F5D4C24D0F68D,
                          0x6DD14C9441AFA84C, 0xC366373B2D6BF64F,
                          0x6B35FB04925014BD, 0x9E3EA39A4DBA7E61};
  for (unsigned i = 0; i < arraysize(test_case); i++) {
    // Setting enable bits and corresponding cause bits could result in
    // exception raised and this prevents that from happening
    test_case[i] = (~test_case[i] & mask_enables) << 5 |
                   (test_case[i] & mask_without_cause);
    run_msa_ctc_cfc(test_case[i] & mask_always_zero);
  }
}

struct ExpResShf {
  uint8_t i8;
  uint64_t lo;
  uint64_t hi;
};

void run_msa_i8(SecondaryField opcode, uint64_t ws_lo, uint64_t ws_hi,
                uint8_t i8) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  CpuFeatureScope fscope(&assm, MIPS_SIMD);
  msa_reg_t res;
  uint64_t wd_lo = 0xF35862E13E38F8B0;
  uint64_t wd_hi = 0x4F41FFDEF2BFE636;

#define LOAD_W_REG(lo, hi, w_reg) \
  __ li(t0, lo);                  \
  __ li(t1, hi);                  \
  __ insert_d(w_reg, 0, t0);      \
  __ insert_d(w_reg, 1, t1);

  LOAD_W_REG(ws_lo, ws_hi, w0)

  switch (opcode) {
    case ANDI_B:
      __ andi_b(w2, w0, i8);
      break;
    case ORI_B:
      __ ori_b(w2, w0, i8);
      break;
    case NORI_B:
      __ nori_b(w2, w0, i8);
      break;
    case XORI_B:
      __ xori_b(w2, w0, i8);
      break;
    case BMNZI_B:
      LOAD_W_REG(wd_lo, wd_hi, w2);
      __ bmnzi_b(w2, w0, i8);
      break;
    case BMZI_B:
      LOAD_W_REG(wd_lo, wd_hi, w2);
      __ bmzi_b(w2, w0, i8);
      break;
    case BSELI_B:
      LOAD_W_REG(wd_lo, wd_hi, w2);
      __ bseli_b(w2, w0, i8);
      break;
    case SHF_B:
      __ shf_b(w2, w0, i8);
      break;
    case SHF_H:
      __ shf_h(w2, w0, i8);
      break;
    case SHF_W:
      __ shf_w(w2, w0, i8);
      break;
    default:
      UNREACHABLE();
  }

  store_elements_of_vector(&assm, w2, a0);

  __ jr(ra);
  __ nop();

#undef LOAD_W_REG

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);

  f.Call(&res, 0, 0, 0, 0);

  uint64_t mask = i8 * 0x0101010101010101ull;
  switch (opcode) {
    case ANDI_B:
      CHECK_EQ(ws_lo & mask, res.d[0]);
      CHECK_EQ(ws_hi & mask, res.d[1]);
      break;
    case ORI_B:
      CHECK_EQ(ws_lo | mask, res.d[0]);
      CHECK_EQ(ws_hi | mask, res.d[1]);
      break;
    case NORI_B:
      CHECK_EQ(~(ws_lo | mask), res.d[0]);
      CHECK_EQ(~(ws_hi | mask), res.d[1]);
      break;
    case XORI_B:
      CHECK_EQ(ws_lo ^ mask, res.d[0]);
      CHECK_EQ(ws_hi ^ mask, res.d[1]);
      break;
    case BMNZI_B:
      CHECK_EQ((ws_lo & mask) | (wd_lo & ~mask), res.d[0]);
      CHECK_EQ((ws_hi & mask) | (wd_hi & ~mask), res.d[1]);
      break;
    case BMZI_B:
      CHECK_EQ((ws_lo & ~mask) | (wd_lo & mask), res.d[0]);
      CHECK_EQ((ws_hi & ~mask) | (wd_hi & mask), res.d[1]);
      break;
    case BSELI_B:
      CHECK_EQ((ws_lo & ~wd_lo) | (mask & wd_lo), res.d[0]);
      CHECK_EQ((ws_hi & ~wd_hi) | (mask & wd_hi), res.d[1]);
      break;
    case SHF_B: {
      struct ExpResShf exp_b[] = {
          //  i8,             exp_lo,             exp_hi
          {0xFFu, 0x11111111B9B9B9B9, 0xF7F7F7F7C8C8C8C8},
          {0x0u, 0x62626262DFDFDFDF, 0xD6D6D6D6C8C8C8C8},
          {0xE4u, 0xF35862E13E38F8B0, 0x4F41FFDEF2BFE636},
          {0x1Bu, 0x1B756911C3D9A7B9, 0xAE94A5F79C8AEFC8},
          {0xB1u, 0x662B6253E8C4DF12, 0x0D3AD6803F8BC88B},
          {0x4Eu, 0x62E1F358F8B03E38, 0xFFDE4F41E636F2BF},
          {0x27u, 0x1B697511C3A7D9B9, 0xAEA594F79CEF8AC8}};
      for (size_t i = 0; i < sizeof(exp_b) / sizeof(ExpResShf); ++i) {
        if (exp_b[i].i8 == i8) {
          CHECK_EQ(exp_b[i].lo, res.d[0]);
          CHECK_EQ(exp_b[i].hi, res.d[1]);
        }
      }
    } break;
    case SHF_H: {
      struct ExpResShf exp_h[] = {
          //  i8,             exp_lo,             exp_hi
          {0xFFu, 0x1169116911691169, 0xF7A5F7A5F7A5F7A5},
          {0x0u, 0x12DF12DF12DF12DF, 0x8BC88BC88BC88BC8},
          {0xE4u, 0xF35862E13E38F8B0, 0x4F41FFDEF2BFE636},
          {0x1Bu, 0xD9C3B9A7751B1169, 0x8A9CC8EF94AEF7A5},
          {0xB1u, 0x53622B6612DFC4E8, 0x80D63A0D8BC88B3F},
          {0x4Eu, 0x3E38F8B0F35862E1, 0xF2BFE6364F41FFDE},
          {0x27u, 0xD9C3751BB9A71169, 0x8A9C94AEC8EFF7A5}};
      for (size_t i = 0; i < sizeof(exp_h) / sizeof(ExpResShf); ++i) {
        if (exp_h[i].i8 == i8) {
          CHECK_EQ(exp_h[i].lo, res.d[0]);
          CHECK_EQ(exp_h[i].hi, res.d[1]);
        }
      }
    } break;
    case SHF_W: {
      struct ExpResShf exp_w[] = {
          //  i8,             exp_lo,             exp_hi
          {0xFFu, 0xF7A594AEF7A594AE, 0xF7A594AEF7A594AE},
          {0x0u, 0xC4E812DFC4E812DF, 0xC4E812DFC4E812DF},
          {0xE4u, 0xF35862E13E38F8B0, 0x4F41FFDEF2BFE636},
          {0x1Bu, 0xC8EF8A9CF7A594AE, 0xB9A7D9C31169751B},
          {0xB1u, 0xC4E812DF2B665362, 0x8B3F8BC83A0D80D6},
          {0x4Eu, 0x4F41FFDEF2BFE636, 0xF35862E13E38F8B0},
          {0x27u, 0x1169751BF7A594AE, 0xB9A7D9C3C8EF8A9C}};
      for (size_t i = 0; i < sizeof(exp_w) / sizeof(ExpResShf); ++i) {
        if (exp_w[i].i8 == i8) {
          CHECK_EQ(exp_w[i].lo, res.d[0]);
          CHECK_EQ(exp_w[i].hi, res.d[1]);
        }
      }
    } break;
    default:
      UNREACHABLE();
  }
}

struct TestCaseMsaI8 {
  uint64_t input_lo;
  uint64_t input_hi;
  uint8_t i8;
};

TEST(MSA_andi_ori_nori_xori) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  // clang-format off
  struct TestCaseMsaI8 tc[] = {
    //         input_lo,           input_hi,    i8
    {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C, 0xFFu},
    {0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8, 0x0u},
    {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C, 0x3Bu},
    {0x2B665362C4E812DF, 0x3A0D80
"""


```