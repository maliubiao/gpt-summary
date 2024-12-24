Response: 
Prompt: 
```
这是目录为v8/test/cctest/test-assembler-loong64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
off
  struct TestCaseBnez tc[] = {
    // value, offset, expected_res
    {      1,     -6,          0x3 },
    {     -2,     -3,         0x30 },
    {      3,      3,        0x300 },
    {     -4,      6,        0x700 },
    {      0,      6,            0 },
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseBnez);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t res = run_bnez_b(tc[i].value, tc[i].offset);
    CHECK_EQ(tc[i].expected_res, res);
  }
}

uint64_t run_bl(int32_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label main_block;
  __ li(a2, 0l);
  __ Push(ra);  // Push is implemented by two instructions, addi_d and st_d
  __ b(&main_block);

  // Block 1
  __ addi_d(a2, a2, 0x1);
  __ addi_d(a2, a2, 0x2);
  __ jirl(zero_reg, ra, 0);

  // Block 2
  __ addi_d(a2, a2, 0x10);
  __ addi_d(a2, a2, 0x20);
  __ jirl(zero_reg, ra, 0);

  // Block 3 (Main)
  __ bind(&main_block);
  __ bl(offset);
  __ or_(a0, a2, zero_reg);
  __ Pop(ra);  // Pop is implemented by two instructions, ld_d and addi_d.
  __ jirl(zero_reg, ra, 0);

  // Block 4
  __ addi_d(a2, a2, 0x100);
  __ addi_d(a2, a2, 0x200);
  __ jirl(zero_reg, ra, 0);

  // Block 5
  __ addi_d(a2, a2, 0x300);
  __ addi_d(a2, a2, 0x400);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}

TEST(BL) {
  CcTest::InitializeVM();
  struct TestCaseBl {
    int32_t offset;
    uint64_t expected_res;
  };

  // clang-format off
  struct TestCaseBl tc[] = {
    // offset, expected_res
    {     -6,          0x3 },
    {     -3,         0x30 },
    {      5,        0x300 },
    {      8,        0x700 },
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseBl);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t res = run_bl(tc[i].offset);
    CHECK_EQ(tc[i].expected_res, res);
  }
}

TEST(PCADD) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label exit, error;
  __ Push(ra);

  // pcaddi
  __ li(a4, 0x1FFFFC);
  __ li(a5, 0);
  __ li(a6, static_cast<int32_t>(0xFFE00000));

  __ bl(1);
  __ pcaddi(a3, 0x7FFFF);
  __ add_d(a2, ra, a4);
  __ Branch(&error, ne, a2, Operand(a3));

  __ bl(1);
  __ pcaddi(a3, 0);
  __ add_d(a2, ra, a5);
  __ Branch(&error, ne, a2, Operand(a3));

  __ bl(1);
  __ pcaddi(a3, 0x80000);
  __ add_d(a2, ra, a6);
  __ Branch(&error, ne, a2, Operand(a3));

  // pcaddu12i
  __ li(a4, 0x7FFFF000);
  __ li(a5, 0);
  __ li(a6, static_cast<int32_t>(0x80000000));

  __ bl(1);
  __ pcaddu12i(a2, 0x7FFFF);
  __ add_d(a3, ra, a4);
  __ Branch(&error, ne, a2, Operand(a3));
  __ bl(1);
  __ pcaddu12i(a2, 0);
  __ add_d(a3, ra, a5);
  __ Branch(&error, ne, a2, Operand(a3));
  __ bl(1);
  __ pcaddu12i(a2, 0x80000);
  __ add_d(a3, ra, a6);
  __ Branch(&error, ne, a2, Operand(a3));

  // pcaddu18i
  __ li(a4, 0x1FFFFC0000);
  __ li(a5, 0);
  __ li(a6, static_cast<int64_t>(0xFFFFFFE000000000));

  __ bl(1);
  __ pcaddu18i(a2, 0x7FFFF);
  __ add_d(a3, ra, a4);
  __ Branch(&error, ne, a2, Operand(a3));

  __ bl(1);
  __ pcaddu18i(a2, 0);
  __ add_d(a3, ra, a5);
  __ Branch(&error, ne, a2, Operand(a3));

  __ bl(1);
  __ pcaddu18i(a2, 0x80000);
  __ add_d(a3, ra, a6);
  __ Branch(&error, ne, a2, Operand(a3));

  // pcalau12i
  __ li(a4, 0x7FFFF000);
  __ li(a5, 0);
  __ li(a6, static_cast<int32_t>(0x80000000));
  __ li(a7, static_cast<int64_t>(0xFFFFFFFFFFFFF000));

  __ bl(1);
  __ pcalau12i(a3, 0x7FFFF);
  __ add_d(a2, ra, a4);
  __ and_(t0, a2, a7);
  __ and_(t1, a3, a7);
  __ Branch(&error, ne, t0, Operand(t1));

  __ bl(1);
  __ pcalau12i(a3, 0);
  __ add_d(a2, ra, a5);
  __ and_(t0, a2, a7);
  __ and_(t1, a3, a7);
  __ Branch(&error, ne, t0, Operand(t1));

  __ bl(1);
  __ pcalau12i(a2, 0x80000);
  __ add_d(a3, ra, a6);
  __ and_(t0, a2, a7);
  __ and_(t1, a3, a7);
  __ Branch(&error, ne, t0, Operand(t1));

  __ li(a0, 0x31415926);
  __ b(&exit);

  __ bind(&error);
  __ li(a0, 0x666);

  __ bind(&exit);
  __ Pop(ra);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  int64_t res = reinterpret_cast<int64_t>(f.Call(0, 0, 0, 0, 0));

  CHECK_EQ(0x31415926L, res);
}

uint64_t run_jirl(int16_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label main_block;
  __ li(a2, 0l);
  __ Push(ra);
  __ b(&main_block);

  // Block 1
  __ addi_d(a2, a2, 0x1);
  __ addi_d(a2, a2, 0x2);
  __ jirl(zero_reg, ra, 0);

  // Block 2
  __ addi_d(a2, a2, 0x10);
  __ addi_d(a2, a2, 0x20);
  __ jirl(zero_reg, ra, 0);

  // Block 3 (Main)
  __ bind(&main_block);
  __ pcaddi(a3, 1);
  __ jirl(ra, a3, offset);
  __ or_(a0, a2, zero_reg);
  __ Pop(ra);  // Pop is implemented by two instructions, ld_d and addi_d.
  __ jirl(zero_reg, ra, 0);

  // Block 4
  __ addi_d(a2, a2, 0x100);
  __ addi_d(a2, a2, 0x200);
  __ jirl(zero_reg, ra, 0);

  // Block 5
  __ addi_d(a2, a2, 0x300);
  __ addi_d(a2, a2, 0x400);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}

TEST(JIRL) {
  CcTest::InitializeVM();
  struct TestCaseJirl {
    int16_t offset;
    uint64_t expected_res;
  };

  // clang-format off
  struct TestCaseJirl tc[] = {
    // offset, expected_res
    {     -7,          0x3 },
    {     -4,         0x30 },
    {      5,        0x300 },
    {      8,        0x700 },
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseJirl);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t res = run_jirl(tc[i].offset);
    CHECK_EQ(tc[i].expected_res, res);
  }
}

TEST(LA12) {
  // Test floating point calculate instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    double a;
    double b;
    double c;
    double d;
    double e;
    double f;
    double result_fadd_d;
    double result_fsub_d;
    double result_fmul_d;
    double result_fdiv_d;
    double result_fmadd_d;
    double result_fmsub_d;
    double result_fnmadd_d;
    double result_fnmsub_d;
    double result_fsqrt_d;
    double result_frecip_d;
    double result_frsqrt_d;
    double result_fscaleb_d;
    double result_flogb_d;
    double result_fcopysign_d;
    double result_fclass_d;
  };
  T t;

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // Double precision floating point instructions.
  __ Fld_d(f8, MemOperand(a0, offsetof(T, a)));
  __ Fld_d(f9, MemOperand(a0, offsetof(T, b)));

  __ fneg_d(f10, f8);
  __ fadd_d(f11, f9, f10);
  __ Fst_d(f11, MemOperand(a0, offsetof(T, result_fadd_d)));
  __ fabs_d(f11, f11);
  __ fsub_d(f12, f11, f9);
  __ Fst_d(f12, MemOperand(a0, offsetof(T, result_fsub_d)));

  __ Fld_d(f13, MemOperand(a0, offsetof(T, c)));
  __ Fld_d(f14, MemOperand(a0, offsetof(T, d)));
  __ Fld_d(f15, MemOperand(a0, offsetof(T, e)));

  __ fmin_d(f16, f13, f14);
  __ fmul_d(f17, f15, f16);
  __ Fst_d(f17, MemOperand(a0, offsetof(T, result_fmul_d)));
  __ fmax_d(f18, f13, f14);
  __ fdiv_d(f19, f15, f18);
  __ Fst_d(f19, MemOperand(a0, offsetof(T, result_fdiv_d)));

  __ fmina_d(f16, f13, f14);
  __ fmadd_d(f18, f17, f15, f16);
  __ Fst_d(f18, MemOperand(a0, offsetof(T, result_fmadd_d)));
  __ fnmadd_d(f19, f17, f15, f16);
  __ Fst_d(f19, MemOperand(a0, offsetof(T, result_fnmadd_d)));
  __ fmaxa_d(f16, f13, f14);
  __ fmsub_d(f20, f17, f15, f16);
  __ Fst_d(f20, MemOperand(a0, offsetof(T, result_fmsub_d)));
  __ fnmsub_d(f21, f17, f15, f16);
  __ Fst_d(f21, MemOperand(a0, offsetof(T, result_fnmsub_d)));

  __ Fld_d(f8, MemOperand(a0, offsetof(T, f)));
  __ fsqrt_d(f10, f8);
  __ Fst_d(f10, MemOperand(a0, offsetof(T, result_fsqrt_d)));
  //__ frecip_d(f11, f10);
  //__ frsqrt_d(f12, f8);
  //__ Fst_d(f11, MemOperand(a0, offsetof(T, result_frecip_d)));
  //__ Fst_d(f12, MemOperand(a0, offsetof(T, result_frsqrt_d)));

  /*__ fscaleb_d(f16, f13, f15);
  __ flogb_d(f17, f15);
  __ fcopysign_d(f18, f8, f9);
  __ fclass_d(f19, f9);
  __ Fst_d(f16, MemOperand(a0, offsetof(T, result_fscaleb_d)));
  __ Fst_d(f17, MemOperand(a0, offsetof(T, result_flogb_d)));
  __ Fst_d(f18, MemOperand(a0, offsetof(T, result_fcopysign_d)));
  __ Fst_d(f19, MemOperand(a0, offsetof(T, result_fclass_d)));*/

  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  // Double test values.
  t.a = 1.5e14;
  t.b = -2.75e11;
  t.c = 1.5;
  t.d = -2.75;
  t.e = 120.0;
  t.f = 120.44;
  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(static_cast<double>(-1.502750e14), t.result_fadd_d);
  CHECK_EQ(static_cast<double>(1.505500e14), t.result_fsub_d);
  CHECK_EQ(static_cast<double>(-3.300000e02), t.result_fmul_d);
  CHECK_EQ(static_cast<double>(8.000000e01), t.result_fdiv_d);
  CHECK_EQ(static_cast<double>(-3.959850e04), t.result_fmadd_d);
  CHECK_EQ(static_cast<double>(-3.959725e04), t.result_fmsub_d);
  CHECK_EQ(static_cast<double>(3.959850e04), t.result_fnmadd_d);
  CHECK_EQ(static_cast<double>(3.959725e04), t.result_fnmsub_d);
  CHECK_EQ(static_cast<double>(10.97451593465515908537), t.result_fsqrt_d);
  // CHECK_EQ(static_cast<double>( 8.164965e-08), t.result_frecip_d);
  // CHECK_EQ(static_cast<double>( 8.164966e-08), t.result_frsqrt_d);
  // CHECK_EQ(static_cast<double>(), t.result_fscaleb_d);
  // CHECK_EQ(static_cast<double>( 6.906891), t.result_flogb_d);
  // CHECK_EQ(static_cast<double>( 2.75e11), t.result_fcopysign_d);
  // CHECK_EQ(static_cast<double>(), t.result_fclass_d);
}

TEST(LA13) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    float a;
    float b;
    float c;
    float d;
    float e;
    float result_fadd_s;
    float result_fsub_s;
    float result_fmul_s;
    float result_fdiv_s;
    float result_fmadd_s;
    float result_fmsub_s;
    float result_fnmadd_s;
    float result_fnmsub_s;
    float result_fsqrt_s;
    float result_frecip_s;
    float result_frsqrt_s;
    float result_fscaleb_s;
    float result_flogb_s;
    float result_fcopysign_s;
    float result_fclass_s;
  };
  T t;

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // Float precision floating point instructions.
  __ Fld_s(f8, MemOperand(a0, offsetof(T, a)));
  __ Fld_s(f9, MemOperand(a0, offsetof(T, b)));

  __ fneg_s(f10, f8);
  __ fadd_s(f11, f9, f10);
  __ Fst_s(f11, MemOperand(a0, offsetof(T, result_fadd_s)));
  __ fabs_s(f11, f11);
  __ fsub_s(f12, f11, f9);
  __ Fst_s(f12, MemOperand(a0, offsetof(T, result_fsub_s)));

  __ Fld_s(f13, MemOperand(a0, offsetof(T, c)));
  __ Fld_s(f14, MemOperand(a0, offsetof(T, d)));
  __ Fld_s(f15, MemOperand(a0, offsetof(T, e)));

  __ fmin_s(f16, f13, f14);
  __ fmul_s(f17, f15, f16);
  __ Fst_s(f17, MemOperand(a0, offsetof(T, result_fmul_s)));
  __ fmax_s(f18, f13, f14);
  __ fdiv_s(f19, f15, f18);
  __ Fst_s(f19, MemOperand(a0, offsetof(T, result_fdiv_s)));

  __ fmina_s(f16, f13, f14);
  __ fmadd_s(f18, f17, f15, f16);
  __ Fst_s(f18, MemOperand(a0, offsetof(T, result_fmadd_s)));
  __ fnmadd_s(f19, f17, f15, f16);
  __ Fst_s(f19, MemOperand(a0, offsetof(T, result_fnmadd_s)));
  __ fmaxa_s(f16, f13, f14);
  __ fmsub_s(f20, f17, f15, f16);
  __ Fst_s(f20, MemOperand(a0, offsetof(T, result_fmsub_s)));
  __ fnmsub_s(f21, f17, f15, f16);
  __ Fst_s(f21, MemOperand(a0, offsetof(T, result_fnmsub_s)));

  __ fsqrt_s(f10, f8);
  //__ frecip_s(f11, f10);
  //__ frsqrt_s(f12, f8);
  __ Fst_s(f10, MemOperand(a0, offsetof(T, result_fsqrt_s)));
  //__ Fst_s(f11, MemOperand(a0, offsetof(T, result_frecip_s)));
  //__ Fst_s(f12, MemOperand(a0, offsetof(T, result_frsqrt_s)));

  /*__ fscaleb_s(f16, f13, f15);
  __ flogb_s(f17, f15);
  __ fcopysign_s(f18, f8, f9);
  __ fclass_s(f19, f9);
  __ Fst_s(f16, MemOperand(a0, offsetof(T, result_fscaleb_s)));
  __ Fst_s(f17, MemOperand(a0, offsetof(T, result_flogb_s)));
  __ Fst_s(f18, MemOperand(a0, offsetof(T, result_fcopysign_s)));
  __ Fst_s(f19, MemOperand(a0, offsetof(T, result_fclass_s)));*/
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  // Float test values.
  t.a = 1.5e6;
  t.b = -2.75e4;
  t.c = 1.5;
  t.d = -2.75;
  t.e = 120.0;
  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(static_cast<float>(-1.527500e06), t.result_fadd_s);
  CHECK_EQ(static_cast<float>(1.555000e06), t.result_fsub_s);
  CHECK_EQ(static_cast<float>(-3.300000e02), t.result_fmul_s);
  CHECK_EQ(static_cast<float>(8.000000e01), t.result_fdiv_s);
  CHECK_EQ(static_cast<float>(-3.959850e04), t.result_fmadd_s);
  CHECK_EQ(static_cast<float>(-3.959725e04), t.result_fmsub_s);
  CHECK_EQ(static_cast<float>(3.959850e04), t.result_fnmadd_s);
  CHECK_EQ(static_cast<float>(3.959725e04), t.result_fnmsub_s);
  CHECK_EQ(static_cast<float>(1224.744873), t.result_fsqrt_s);
  // CHECK_EQ(static_cast<float>( 8.164966e-04), t.result_frecip_s);
  // CHECK_EQ(static_cast<float>( 8.164966e-04), t.result_frsqrt_s);
  // CHECK_EQ(static_cast<float>(), t.result_fscaleb_s);
  // CHECK_EQ(static_cast<float>( 6.906890), t.result_flogb_s);
  // CHECK_EQ(static_cast<float>( 2.75e4), t.result_fcopysign_s);
  // CHECK_EQ(static_cast<float>(), t.result_fclass_s);
}

TEST(FCMP_COND) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct TestFloat {
    double dTrue;
    double dFalse;
    double dOp1;
    double dOp2;
    double dCaf;
    double dCun;
    double dCeq;
    double dCueq;
    double dClt;
    double dCult;
    double dCle;
    double dCule;
    double dCne;
    double dCor;
    double dCune;
    double dSaf;
    double dSun;
    double dSeq;
    double dSueq;
    double dSlt;
    double dSult;
    double dSle;
    double dSule;
    double dSne;
    double dSor;
    double dSune;
    float fTrue;
    float fFalse;
    float fOp1;
    float fOp2;
    float fCaf;
    float fCun;
    float fCeq;
    float fCueq;
    float fClt;
    float fCult;
    float fCle;
    float fCule;
    float fCne;
    float fCor;
    float fCune;
    float fSaf;
    float fSun;
    float fSeq;
    float fSueq;
    float fSlt;
    float fSult;
    float fSle;
    float fSule;
    float fSne;
    float fSor;
    float fSune;
  };

  TestFloat test;

  __ Fld_d(f8, MemOperand(a0, offsetof(TestFloat, dOp1)));
  __ Fld_d(f9, MemOperand(a0, offsetof(TestFloat, dOp2)));

  __ Fld_s(f10, MemOperand(a0, offsetof(TestFloat, fOp1)));
  __ Fld_s(f11, MemOperand(a0, offsetof(TestFloat, fOp2)));

  __ Fld_d(f12, MemOperand(a0, offsetof(TestFloat, dFalse)));
  __ Fld_d(f13, MemOperand(a0, offsetof(TestFloat, dTrue)));

  __ Fld_s(f14, MemOperand(a0, offsetof(TestFloat, fFalse)));
  __ Fld_s(f15, MemOperand(a0, offsetof(TestFloat, fTrue)));

  __ fcmp_cond_d(CAF, f8, f9, FCC0);
  __ fcmp_cond_s(CAF, f10, f11, FCC1);
  __ fsel(FCC0, f16, f12, f13);
  __ fsel(FCC1, f17, f14, f15);
  __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dCaf)));
  __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fCaf)));

  __ fcmp_cond_d(CUN, f8, f9, FCC0);
  __ fcmp_cond_s(CUN, f10, f11, FCC1);
  __ fsel(FCC0, f16, f12, f13);
  __ fsel(FCC1, f17, f14, f15);
  __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dCun)));
  __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fCun)));

  __ fcmp_cond_d(CEQ, f8, f9, FCC0);
  __ fcmp_cond_s(CEQ, f10, f11, FCC1);
  __ fsel(FCC0, f16, f12, f13);
  __ fsel(FCC1, f17, f14, f15);
  __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dCeq)));
  __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fCeq)));

  __ fcmp_cond_d(CUEQ, f8, f9, FCC0);
  __ fcmp_cond_s(CUEQ, f10, f11, FCC1);
  __ fsel(FCC0, f16, f12, f13);
  __ fsel(FCC1, f17, f14, f15);
  __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dCueq)));
  __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fCueq)));

  __ fcmp_cond_d(CLT, f8, f9, FCC0);
  __ fcmp_cond_s(CLT, f10, f11, FCC1);
  __ fsel(FCC0, f16, f12, f13);
  __ fsel(FCC1, f17, f14, f15);
  __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dClt)));
  __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fClt)));

  __ fcmp_cond_d(CULT, f8, f9, FCC0);
  __ fcmp_cond_s(CULT, f10, f11, FCC1);
  __ fsel(FCC0, f16, f12, f13);
  __ fsel(FCC1, f17, f14, f15);
  __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dCult)));
  __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fCult)));

  __ fcmp_cond_d(CLE, f8, f9, FCC0);
  __ fcmp_cond_s(CLE, f10, f11, FCC1);
  __ fsel(FCC0, f16, f12, f13);
  __ fsel(FCC1, f17, f14, f15);
  __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dCle)));
  __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fCle)));

  __ fcmp_cond_d(CULE, f8, f9, FCC0);
  __ fcmp_cond_s(CULE, f10, f11, FCC1);
  __ fsel(FCC0, f16, f12, f13);
  __ fsel(FCC1, f17, f14, f15);
  __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dCule)));
  __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fCule)));

  __ fcmp_cond_d(CNE, f8, f9, FCC0);
  __ fcmp_cond_s(CNE, f10, f11, FCC1);
  __ fsel(FCC0, f16, f12, f13);
  __ fsel(FCC1, f17, f14, f15);
  __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dCne)));
  __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fCne)));

  __ fcmp_cond_d(COR, f8, f9, FCC0);
  __ fcmp_cond_s(COR, f10, f11, FCC1);
  __ fsel(FCC0, f16, f12, f13);
  __ fsel(FCC1, f17, f14, f15);
  __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dCor)));
  __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fCor)));

  __ fcmp_cond_d(CUNE, f8, f9, FCC0);
  __ fcmp_cond_s(CUNE, f10, f11, FCC1);
  __ fsel(FCC0, f16, f12, f13);
  __ fsel(FCC1, f17, f14, f15);
  __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dCune)));
  __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fCune)));

  /*  __ fcmp_cond_d(SAF, f8, f9, FCC0);
    __ fcmp_cond_s(SAF, f10, f11, FCC1);
    __ fsel(FCC0, f16, f12, f13);
    __ fsel(FCC1, f17, f14, f15);
    __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dSaf)));
    __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fSaf)));

    __ fcmp_cond_d(SUN, f8, f9, FCC0);
    __ fcmp_cond_s(SUN, f10, f11, FCC1);
    __ fsel(FCC0, f16, f12, f13);
    __ fsel(FCC1, f17, f14, f15);
    __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dSun)));
    __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fSun)));

    __ fcmp_cond_d(SEQ, f8, f9, FCC0);
    __ fcmp_cond_s(SEQ, f10, f11, FCC1);
    __ fsel(FCC0, f16, f12, f13);
    __ fsel(FCC1, f17, f14, f15);
    __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dSeq)));
    __ Fst_f(f17, MemOperand(a0, offsetof(TestFloat, fSeq)));

    __ fcmp_cond_d(SUEQ, f8, f9, FCC0);
    __ fcmp_cond_s(SUEQ, f10, f11, FCC1);
    __ fsel(FCC0, f16, f12, f13);
    __ fsel(FCC1, f17, f14, f15);
    __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dSueq)));
    __ Fst_f(f17, MemOperand(a0, offsetof(TestFloat, fSueq)));

    __ fcmp_cond_d(SLT, f8, f9, FCC0);
    __ fcmp_cond_s(SLT, f10, f11, FCC1);
    __ fsel(f16, f12, f13, FCC0);
    __ fsel(f17, f14, f15, FCC1);
    __ Fld_d(f16, MemOperand(a0, offsetof(TestFloat, dSlt)));
    __ Fst_d(f17, MemOperand(a0, offsetof(TestFloat, fSlt)));

    __ fcmp_cond_d(SULT, f8, f9, FCC0);
    __ fcmp_cond_s(SULT, f10, f11, FCC1);
    __ fsel(FCC0, f16, f12, f13);
    __ fsel(FCC1, f17, f14, f15);
    __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dSult)));
    __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fSult)));

    __ fcmp_cond_d(SLE, f8, f9, FCC0);
    __ fcmp_cond_s(SLE, f10, f11, FCC1);
    __ fsel(FCC0, f16, f12, f13);
    __ fsel(FCC1, f17, f14, f15);
    __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dSle)));
    __ Fst_f(f17, MemOperand(a0, offsetof(TestFloat, fSle)));

    __ fcmp_cond_d(SULE, f8, f9, FCC0);
    __ fcmp_cond_s(SULE, f10, f11, FCC1);
    __ fsel(FCC0, f16, f12, f13);
    __ fsel(FCC1, f17, f14, f15);
    __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dSule)));
    __ Fst_f(f17, MemOperand(a0, offsetof(TestFloat, fSule)));

    __ fcmp_cond_d(SNE, f8, f9, FCC0);
    __ fcmp_cond_s(SNE, f10, f11, FCC1);
    __ fsel(FCC0, f16, f12, f13);
    __ fsel(FCC1, f17, f14, f15);
    __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dSne)));
    __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fSne)));

    __ fcmp_cond_d(SOR, f8, f9, FCC0);
    __ fcmp_cond_s(SOR, f10, f11, FCC1);
    __ fsel(FCC0, f16, f12, f13);
    __ fsel(FCC1, f17, f14, f15);
    __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dSor)));
    __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fSor)));

    __ fcmp_cond_d(SUNE, f8, f9, FCC0);
    __ fcmp_cond_s(SUNE, f10, f11, FCC1);
    __ fsel(FCC0, f16, f12, f13);
    __ fsel(FCC1, f17, f14, f15);
    __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dSune)));
    __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fSune)));*/

  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  test.dTrue = 1234.0;
  test.dFalse = 0.0;
  test.fTrue = 12.0;
  test.fFalse = 0.0;

  test.dOp1 = 2.0;
  test.dOp2 = 3.0;
  test.fOp1 = 2.0;
  test.fOp2 = 3.0;
  f.Call(&test, 0, 0, 0, 0);

  CHECK_EQ(test.dCaf, test.dFalse);
  CHECK_EQ(test.fCaf, test.fFalse);
  CHECK_EQ(test.dCun, test.dFalse);
  CHECK_EQ(test.fCun, test.fFalse);
  CHECK_EQ(test.dCeq, test.dFalse);
  CHECK_EQ(test.fCeq, test.fFalse);
  CHECK_EQ(test.dCueq, test.dFalse);
  CHECK_EQ(test.fCueq, test.fFalse);
  CHECK_EQ(test.dClt, test.dTrue);
  CHECK_EQ(test.fClt, test.fTrue);
  CHECK_EQ(test.dCult, test.dTrue);
  CHECK_EQ(test.fCult, test.fTrue);
  CHECK_EQ(test.dCle, test.dTrue);
  CHECK_EQ(test.fCle, test.fTrue);
  CHECK_EQ(test.dCule, test.dTrue);
  CHECK_EQ(test.fCule, test.fTrue);
  CHECK_EQ(test.dCne, test.dTrue);
  CHECK_EQ(test.fCne, test.fTrue);
  CHECK_EQ(test.dCor, test.dTrue);
  CHECK_EQ(test.fCor, test.fTrue);
  CHECK_EQ(test.dCune, test.dTrue);
  CHECK_EQ(test.fCune, test.fTrue);
  /*  CHECK_EQ(test.dSaf, test.dFalse);
    CHECK_EQ(test.fSaf, test.fFalse);
    CHECK_EQ(test.dSun, test.dFalse);
    CHECK_EQ(test.fSun, test.fFalse);
    CHECK_EQ(test.dSeq, test.dFalse);
    CHECK_EQ(test.fSeq, test.fFalse);
    CHECK_EQ(test.dSueq, test.dFalse);
    CHECK_EQ(test.fSueq, test.fFalse);
    CHECK_EQ(test.dClt, test.dTrue);
    CHECK_EQ(test.fClt, test.fTrue);
    CHECK_EQ(test.dCult, test.dTrue);
    CHECK_EQ(test.fCult, test.fTrue);
    CHECK_EQ(test.dSle, test.dTrue);
    CHECK_EQ(test.fSle, test.fTrue);
    CHECK_EQ(test.dSule, test.dTrue);
    CHECK_EQ(test.fSule, test.fTrue);
    CHECK_EQ(test.dSne, test.dTrue);
    CHECK_EQ(test.fSne, test.fTrue);
    CHECK_EQ(test.dSor, test.dTrue);
    CHECK_EQ(test.fSor, test.fTrue);
    CHECK_EQ(test.dSune, test.dTrue);
    CHECK_EQ(test.fSune, test.fTrue);*/

  test.dOp1 = std::numeric_limits<double>::max();
  test.dOp2 = std::numeric_limits<double>::min();
  test.fOp1 = std::numeric_limits<float>::min();
  test.fOp2 = -std::numeric_limits<float>::max();
  f.Call(&test, 0, 0, 0, 0);

  CHECK_EQ(test.dCaf, test.dFalse);
  CHECK_EQ(test.fCaf, test.fFalse);
  CHECK_EQ(test.dCun, test.dFalse);
  CHECK_EQ(test.fCun, test.fFalse);
  CHECK_EQ(test.dCeq, test.dFalse);
  CHECK_EQ(test.fCeq, test.fFalse);
  CHECK_EQ(test.dCueq, test.dFalse);
  CHECK_EQ(test.fCueq, test.fFalse);
  CHECK_EQ(test.dClt, test.dFalse);
  CHECK_EQ(test.fClt, test.fFalse);
  CHECK_EQ(test.dCult, test.dFalse);
  CHECK_EQ(test.fCult, test.fFalse);
  CHECK_EQ(test.dCle, test.dFalse);
  CHECK_EQ(test.fCle, test.fFalse);
  CHECK_EQ(test.dCule, test.dFalse);
  CHECK_EQ(test.fCule, test.fFalse);
  CHECK_EQ(test.dCne, test.dTrue);
  CHECK_EQ(test.fCne, test.fTrue);
  CHECK_EQ(test.dCor, test.dTrue);
  CHECK_EQ(test.fCor, test.fTrue);
  CHECK_EQ(test.dCune, test.dTrue);
  CHECK_EQ(test.fCune, test.fTrue);
  /*  CHECK_EQ(test.dSaf, test.dFalse);
    CHECK_EQ(test.fSaf, test.fFalse);
    CHECK_EQ(test.dSun, test.dFalse);
    CHECK_EQ(test.fSun, test.fFalse);
    CHECK_EQ(test.dSeq, test.dFalse);
    CHECK_EQ(test.fSeq, test.fFalse);
    CHECK_EQ(test.dSueq, test.dFalse);
    CHECK_EQ(test.fSueq, test.fFalse);
    CHECK_EQ(test.dSlt, test.dFalse);
    CHECK_EQ(test.fSlt, test.fFalse);
    CHECK_EQ(test.dSult, test.dFalse);
    CHECK_EQ(test.fSult, test.fFalse);
    CHECK_EQ(test.dSle, test.dFalse);
    CHECK_EQ(test.fSle, test.fFalse);
    CHECK_EQ(test.dSule, test.dFalse);
    CHECK_EQ(test.fSule, test.fFalse);
    CHECK_EQ(test.dSne, test.dTrue);
    CHECK_EQ(test.fSne, test.fTrue);
    CHECK_EQ(test.dSor, test.dTrue);
    CHECK_EQ(test.fSor, test.fTrue);
    CHECK_EQ(test.dSune, test.dTrue);
    CHECK_EQ(test.fSune, test.fTrue);*/

  test.dOp1 = std::numeric_limits<double>::quiet_NaN();
  test.dOp2 = 0.0;
  test.fOp1 = std::numeric_limits<float>::quiet_NaN();
  test.fOp2 = 0.0;
  f.Call(&test, 0, 0, 0, 0);

  CHECK_EQ(test.dCaf, test.dFalse);
  CHECK_EQ(test.fCaf, test.fFalse);
  CHECK_EQ(test.dCun, test.dTrue);
  CHECK_EQ(test.fCun, test.fTrue);
  CHECK_EQ(test.dCeq, test.dFalse);
  CHECK_EQ(test.fCeq, test.fFalse);
  CHECK_EQ(test.dCueq, test.dTrue);
  CHECK_EQ(test.fCueq, test.fTrue);
  CHECK_EQ(test.dClt, test.dFalse);
  CHECK_EQ(test.fClt, test.fFalse);
  CHECK_EQ(test.dCult, test.dTrue);
  CHECK_EQ(test.fCult, test.fTrue);
  CHECK_EQ(test.dCle, test.dFalse);
  CHECK_EQ(test.fCle, test.fFalse);
  CHECK_EQ(test.dCule, test.dTrue);
  CHECK_EQ(test.fCule, test.fTrue);
  CHECK_EQ(test.dCne, test.dFalse);
  CHECK_EQ(test.fCne, test.fFalse);
  CHECK_EQ(test.dCor, test.dFalse);
  CHECK_EQ(test.fCor, test.fFalse);
  CHECK_EQ(test.dCune, test.dTrue);
  CHECK_EQ(test.fCune, test.fTrue);
  /*  CHECK_EQ(test.dSaf, test.dTrue);
    CHECK_EQ(test.fSaf, test.fTrue);
    CHECK_EQ(test.dSun, test.dTrue);
    CHECK_EQ(test.fSun, test.fTrue);
    CHECK_EQ(test.dSeq, test.dFalse);
    CHECK_EQ(test.fSeq, test.fFalse);
    CHECK_EQ(test.dSueq, test.dTrue);
    CHECK_EQ(test.fSueq, test.fTrue);
    CHECK_EQ(test.dSlt, test.dFalse);
    CHECK_EQ(test.fSlt, test.fFalse);
    CHECK_EQ(test.dSult, test.dTrue);
    CHECK_EQ(test.fSult, test.fTrue);
    CHECK_EQ(test.dSle, test.dFalse);
    CHECK_EQ(test.fSle, test.fFalse);
    CHECK_EQ(test.dSule, test.dTrue);
    CHECK_EQ(test.fSule, test.fTrue);
    CHECK_EQ(test.dSne, test.dFalse);
    CHECK_EQ(test.fSne, test.fFalse);
    CHECK_EQ(test.dSor, test.dFalse);
    CHECK_EQ(test.fSor, test.fFalse);
    CHECK_EQ(test.dSune, test.dTrue);
    CHECK_EQ(test.fSune, test.fTrue);*/
}

TEST(FCVT) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct TestFloat {
    float fcvt_d_s_in;
    double fcvt_s_d_in;
    double fcvt_d_s_out;
    float fcvt_s_d_out;
    int fcsr;
  };
  TestFloat test;
  __ xor_(a4, a4, a4);
  __ xor_(a5, a5, a5);
  __ Ld_w(a4, MemOperand(a0, offsetof(TestFloat, fcsr)));
  __ movfcsr2gr(a5);
  __ movgr2fcsr(a4);
  __ Fld_s(f8, MemOperand(a0, offsetof(TestFloat, fcvt_d_s_in)));
  __ Fld_d(f9, MemOperand(a0, offsetof(TestFloat, fcvt_s_d_in)));
  __ fcvt_d_s(f10, f8);
  __ fcvt_s_d(f11, f9);
  __ Fst_d(f10, MemOperand(a0, offsetof(TestFloat, fcvt_d_s_out)));
  __ Fst_s(f11, MemOperand(a0, offsetof(TestFloat, fcvt_s_d_out)));
  __ movgr2fcsr(a5);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  test.fcsr = kRoundToNearest;

  test.fcvt_d_s_in = -0.51;
  test.fcvt_s_d_in = -0.51;
  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.fcvt_d_s_out, static_cast<double>(test.fcvt_d_s_in));
  CHECK_EQ(test.fcvt_s_d_out, static_cast<float>(test.fcvt_s_d_in));

  test.fcvt_d_s_in = 0.49;
  test.fcvt_s_d_in = 0.49;
  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.fcvt_d_s_out, static_cast<double>(test.fcvt_d_s_in));
  CHECK_EQ(test.fcvt_s_d_out, static_cast<float>(test.fcvt_s_d_in));

  test.fcvt_d_s_in = std::numeric_limits<float>::max();
  test.fcvt_s_d_in = std::numeric_limits<double>::max();
  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.fcvt_d_s_out, static_cast<double>(test.fcvt_d_s_in));
  CHECK_EQ(test.fcvt_s_d_out, static_cast<float>(test.fcvt_s_d_in));

  test.fcvt_d_s_in = -std::numeric_limits<float>::max();
  test.fcvt_s_d_in = -std::numeric_limits<double>::max();
  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.fcvt_d_s_out, static_cast<double>(test.fcvt_d_s_in));
  CHECK_EQ(test.fcvt_s_d_out, static_cast<float>(test.fcvt_s_d_in));

  test.fcvt_d_s_in = std::numeric_limits<float>::min();
  test.fcvt_s_d_in = std::numeric_limits<double>::min();
  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.fcvt_d_s_out, static_cast<double>(test.fcvt_d_s_in));
  CHECK_EQ(test.fcvt_s_d_out, static_cast<float>(test.fcvt_s_d_in));
}

TEST(FFINT) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct TestFloat {
    int32_t ffint_s_w_in;
    int64_t ffint_s_l_in;
    int32_t ffint_d_w_in;
    int64_t ffint_d_l_in;
    float ffint_s_w_out;
    float ffint_s_l_out;
    double ffint_d_w_out;
    double ffint_d_l_out;
    int fcsr;
  };
  TestFloat test;
  __ xor_(a4, a4, a4);
  __ xor_(a5, a5, a5);
  __ Ld_w(a4, MemOperand(a0, offsetof(TestFloat, fcsr)));
  __ movfcsr2gr(a5);
  __ movgr2fcsr(a4);
  __ Fld_s(f8, MemOperand(a0, offsetof(TestFloat, ffint_s_w_in)));
  __ Fld_d(f9, MemOperand(a0, offsetof(TestFloat, ffint_s_l_in)));
  __ Fld_s(f10, MemOperand(a0, offsetof(TestFloat, ffint_d_w_in)));
  __ Fld_d(f11, MemOperand(a0, offsetof(TestFloat, ffint_d_l_in)));
  __ ffint_s_w(f12, f8);
  __ ffint_s_l(f13, f9);
  __ ffint_d_w(f14, f10);
  __ ffint_d_l(f15, f11);
  __ Fst_s(f12, MemOperand(a0, offsetof(TestFloat, ffint_s_w_out)));
  __ Fst_s(f13, MemOperand(a0, offsetof(TestFloat, ffint_s_l_out)));
  __ Fst_d(f14, MemOperand(a0, offsetof(TestFloat, ffint_d_w_out)));
  __ Fst_d(f15, MemOperand(a0, offsetof(TestFloat, ffint_d_l_out)));
  __ movgr2fcsr(a5);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  test.fcsr = kRoundToNearest;

  test.ffint_s_w_in = -1;
  test.ffint_s_l_in = -1;
  test.ffint_d_w_in = -1;
  test.ffint_d_l_in = -1;
  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.ffint_s_w_out, static_cast<float>(test.ffint_s_w_in));
  CHECK_EQ(test.ffint_s_l_out, static_cast<float>(test.ffint_s_l_in));
  CHECK_EQ(test.ffint_d_w_out, static_cast<double>(test.ffint_d_w_in));
  CHECK_EQ(test.ffint_d_l_out, static_cast<double>(test.ffint_d_l_in));

  test.ffint_s_w_in = 1;
  test.ffint_s_l_in = 1;
  test.ffint_d_w_in = 1;
  test.ffint_d_l_in = 1;
  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.ffint_s_w_out, static_cast<float>(test.ffint_s_w_in));
  CHECK_EQ(test.ffint_s_l_out, static_cast<float>(test.ffint_s_l_in));
  CHECK_EQ(test.ffint_d_w_out, static_cast<double>(test.ffint_d_w_in));
  CHECK_EQ(test.ffint_d_l_out, static_cast<double>(test.ffint_d_l_in));

  test.ffint_s_w_in = std::numeric_limits<int32_t>::max();
  test.ffint_s_l_in = std::numeric_limits<int64_t>::max();
  test.ffint_d_w_in = std::numeric_limits<int32_t>::max();
  test.ffint_d_l_in = std::numeric_limits<int64_t>::max();
  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.ffint_s_w_out, static_cast<float>(test.ffint_s_w_in));
  CHECK_EQ(test.ffint_s_l_out, static_cast<float>(test.ffint_s_l_in));
  CHECK_EQ(test.ffint_d_w_out, static_cast<double>(test.ffint_d_w_in));
  CHECK_EQ(test.ffint_d_l_out, static_cast<double>(test.ffint_d_l_in));

  test.ffint_s_w_in = std::numeric_limits<int32_t>::min();
  test.ffint_s_l_in = std::numeric_limits<int64_t>::min();
  test.ffint_d_w_in = std::numeric_limits<int32_t>::min();
  test.ffint_d_l_in = std::numeric_limits<int64_t>::min();
  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.ffint_s_w_out, static_cast<float>(test.ffint_s_w_in));
  CHECK_EQ(test.ffint_s_l_out, static_cast<float>(test.ffint_s_l_in));
  CHECK_EQ(test.ffint_d_w_out, static_cast<double>(test.ffint_d_w_in));
  CHECK_EQ(test.ffint_d_l_out, static_cast<double>(test.ffint_d_l_in));
}

TEST(FTINT) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct Test {
    double a;
    float b;
    int32_t c;
    int32_t d;
    int64_t e;
    int64_t f;
    int fcsr;
  };
  Test test;

  const int kTableLength = 9;
  // clang-format off
  double inputs_d[kTableLength] = {
      3.1, 3.6, 3.5, -3.1, -3.6, -3.5,
      2147483648.0,
      std::numeric_limits<double>::quiet_NaN(),
      std::numeric_limits<double>::infinity()
      };
  float inputs_s[kTableLength] = {
      3.1, 3.6, 3.5, -3.1, -3.6, -3.5,
      2147483648.0,
      std::numeric_limits<double>::quiet_NaN(),
      std::numeric_limits<double>::infinity()
      };
  double outputs_RN_W[kTableLength] = {
      3.0, 4.0, 4.0, -3.0, -4.0, -4.0,
      kFPUInvalidResult, 0,
      kFPUInvalidResult};
  double outputs_RN_L[kTableLength] = {
      3.0, 4.0, 4.0, -3.0, -4.0, -4.0,
      2147483648.0, 0,
      static_cast<double>(kFPU64InvalidResult)};
  double outputs_RZ_W[kTableLength] = {
      3.0, 3.0, 3.0, -3.0, -3.0, -3.0,
      kFPUInvalidResult, 0,
      kFPUInvalidResult};
  double outputs_RZ_L[kTableLength] = {
      3.0, 3.0, 3.0, -3.0, -3.0, -3.0,
      2147483648.0, 0,
      static_cast<double>(kFPU64InvalidResult)};
  double outputs_RP_W[kTableLength] = {
      4.0, 4.0, 4.0, -3.0, -3.0, -3.0,
      kFPUInvalidResult, 0,
      kFPUInvalidResult};
  double outputs_RP_L[kTableLength] = {
      4.0, 4.0, 4.0, -3.0, -3.0, -3.0,
      2147483648.0, 0,
      static_cast<double>(kFPU64InvalidResult)};
  double outputs_RM_W[kTableLength] = {
      3.0, 3.0, 3.0, -4.0, -4.0, -4.0,
      kFPUInvalidResult, 0,
      kFPUInvalidResult};
  double outputs_RM_L[kTableLength] = {
      3.0, 3.0, 3.0, -4.0, -4.0, -4.0,
      2147483648.0, 0,
      static_cast<double>(kFPU64InvalidResult)};
  // clang-format on

  int fcsr_inputs[4] = {kRoundToNearest, kRoundToZero, kRoundToPlusInf,
                        kRoundToMinusInf};
  double* outputs[8] = {
      outputs_RN_W, outputs_RN_L, outputs_RZ_W, outputs_RZ_L,
      outputs_RP_W, outputs_RP_L, outputs_RM_W, outputs_RM_L,
  };

  __ Fld_d(f8, MemOperand(a0, offsetof(Test, a)));
  __ Fld_s(f9, MemOperand(a0, offsetof(Test, b)));
  __ xor_(a5, a5, a5);
  __ Ld_w(a5, MemOperand(a0, offsetof(Test, fcsr)));
  __ movfcsr2gr(a4);
  __ movgr2fcsr(a5);
  __ ftint_w_d(f10, f8);
  __ ftint_w_s(f11, f9);
  __ ftint_l_d(f12, f8);
  __ ftint_l_s(f13, f9);
  __ Fst_s(f10, MemOperand(a0, offsetof(Test, c)));
  __ Fst_s(f11, MemOperand(a0, offsetof(Test, d)));
  __ Fst_d(f12, MemOperand(a0, offsetof(Test, e)));
  __ Fst_d(f13, MemOperand(a0, offsetof(Test, f)));
  __ movgr2fcsr(a4);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int j = 0; j < 4; j++) {
    test.fcsr = fcsr_inputs[j];
    for (int i = 0; i < kTableLength; i++) {
      test.a = inputs_d[i];
      test.b = inputs_s[i];
      f.Call(&test, 0, 0, 0, 0);
      CHECK_EQ(test.c, outputs[2 * j][i]);
      CHECK_EQ(test.d, outputs[2 * j][i]);
      CHECK_EQ(test.e, outputs[2 * j + 1][i]);
      CHECK_EQ(test.f, outputs[2 * j + 1][i]);
    }
  }
}

TEST(FTINTRM) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct Test {
    double a;
    float b;
    int32_t c;
    int32_t d;
    int64_t e;
    int64_t f;
  };
  Test test;

  const int kTableLength = 9;

  // clang-format off
  double inputs_d[kTableLength] = {
      3.1, 3.6, 3.5, -3.1, -3.6, -3.5,
      2147483648.0,
      std::numeric_limits<double>::quiet_NaN(),
      std::numeric_limits<double>::infinity()
  };
  float inputs_s[kTableLength] = {
      3.1, 3.6, 3.5, -3.1, -3.6, -3.5,
      2147483648.0,
      std::numeric_limits<double>::quiet_NaN(),
      std::numeric_limits<double>::infinity()
  };
  double outputs_w[kTableLength] = {
      3.0, 3.0, 3.0, -4.0, -4.0, -4.0,
      kFPUInvalidResult, 0,
      kFPUInvalidResult};
  double outputs_l[kTableLength] = {
      3.0, 3.0, 3.0, -4.0, -4.0, -4.0,
      2147483648.0, 0,
      static_cast<double>(kFPU64InvalidResult)};
  // clang-format on

  __ Fld_d(f8, MemOperand(a0, offsetof(Test, a)));
  __ Fld_s(f9, MemOperand(a0, offsetof(Test, b)));
  __ ftintrm_w_d(f10, f8);
  __ ftintrm_w_s(f11, f9);
  __ ftintrm_l_d(f12, f8);
  __ ftintrm_l_s(f13, f9);
  __ Fst_s(f10, MemOperand(a0, offsetof(Test, c)));
  __ Fst_s(f11, MemOperand(a0, offsetof(Test, d)));
  __ Fst_d(f12, MemOperand(a0, offsetof(Test, e)));
  __ Fst_d(f13, MemOperand(a0, offsetof(Test, f)));
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int i = 0; i < kTableLength; i++) {
    test.a = inputs_d[i];
    test.b = inputs_s[i];
    f.Call(&test, 0, 0, 0, 0);
    CHECK_EQ(test.c, outputs_w[i]);
    CHECK_EQ(test.d, outputs_w[i]);
    CHECK_EQ(test.e, outputs_l[i]);
    CHECK_EQ(test.f, outputs_l[i]);
  }
}

TEST(FTINTRP) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct Test {
    double a;
    float b;
    int32_t c;
    int32_t d;
    int64_t e;
    int64_t f;
  };
  Test test;

  const int kTableLength = 9;

  // clang-format off
  double inputs_d[kTableLength] = {
      3.1, 3.6, 3.5, -3.1, -3.6, -3.5,
      2147483648.0,
      std::numeric_limits<double>::quiet_NaN(),
      std::numeric_limits<double>::infinity()
  };
  float inputs_s[kTableLength] = {
      3.1, 3.6, 3.5, -3.1, -3.6, -3.5,
      2147483648.0,
      std::numeric_limits<double>::quiet_NaN(),
      std::numeric_limits<double>::infinity()
  };
  double outputs_w[kTableLength] = {
      4.0, 4.0, 4.0, -3.0, -3.0, -3.0,
      kFPUInvalidResult, 0,
      kFPUInvalidResult};
  double outputs_l[kTableLength] = {
      4.0, 4.0, 4.0, -3.0, -3.0, -3.0,
      2147483648.0, 0,
      static_cast<double>(kFPU64InvalidResult)};
  // clang-format on

  __ Fld_d(f8, MemOperand(a0, offsetof(Test, a)));
  __ Fld_s(f9, MemOperand(a0, offsetof(Test, b)));
  __ ftintrp_w_d(f10, f8);
  __ ftintrp_w_s(f11, f9);
  __ ftintrp_l_d(f12, f8);
  __ ftintrp_l_s(f13, f9);
  __ Fst_s(f10, MemOperand(a0, offsetof(Test, c)));
  __ Fst_s(f11, MemOperand(a0, offsetof(Test, d)));
  __ Fst_d(f12, MemOperand(a0, offsetof(Test, e)));
  __ Fst_d(f13, MemOperand(a0, offsetof(Test, f)));
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int i = 0; i < kTableLength; i++) {
    test.a = inputs_d[i];
    test.b = inputs_s[i];
    f.Call(&test, 0, 0, 0, 0);
    CHECK_EQ(test.c, outputs_w[i]);
    CHECK_EQ(test.d, outputs_w[i]);
    CHECK_EQ(test.e, outputs_l[i]);
    CHECK_EQ(test.f, outputs_l[i]);
  }
}

TEST(FTINTRZ) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct Test {
    double a;
    float b;
    int32_t c;
    int32_t d;
    int64_t e;
    int64_t f;
  };
  Test test;

  const int kTableLength = 9;

  // clang-format off
  double inputs_d[kTableLength] = {
      3.1, 3.6, 3.5, -3.1, -3.6, -3.5,
      2147483648.0,
      std::numeric_limits<double>::quiet_NaN(),
      std::numeric_limits<double>::infinity()
  };
  float inputs_s[kTableLength] = {
      3.1, 3.6, 3.5, -3.1, -3.6, -3.5,
      2147483648.0,
      std::numeric_limits<double>::quiet_NaN(),
      std::numeric_limits<double>::infinity()
  };
  double outputs_w[kTableLength] = {
      3.0, 3.0, 3.0, -3.0, -3.0, -3.0,
      kFPUInvalidResult, 0,
      kFPUInvalidResult};
  double outputs_l[kTableLength] = {
      3.0, 3.0, 3.0, -3.0, -3.0, -3.0,
      2147483648.0, 0,
      static_cast<double>(kFPU64InvalidResult)};
  // clang-format on

  __ Fld_d(f8, MemOperand(a0, offsetof(Test, a)));
  __ Fld_s(f9, MemOperand(a0, offsetof(Test, b)));
  __ ftintrz_w_d(f10, f8);
  __ ftintrz_w_s(f11, f9);
  __ ftintrz_l_d(f12, f8);
  __ ftintrz_l_s(f13, f9);
  __ Fst_s(f10, MemOperand(a0, offsetof(Test, c)));
  __ Fst_s(f11, MemOperand(a0, offsetof(Test, d)));
  __ Fst_d(f12, MemOperand(a0, offsetof(Test, e)));
  __ Fst_d(f13, MemOperand(a0, offsetof(Test, f)));
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int i = 0; i < kTableLength; i++) {
    test.a = inputs_d[i];
    test.b = inputs_s[i];
    f.Call(&test, 0, 0, 0, 0);
    CHECK_EQ(test.c, outputs_w[i]);
    CHECK_EQ(test.d, outputs_w[i]);
    CHECK_EQ(test.e, outputs_l[i]);
    CHECK_EQ(test.f, outputs_l[i]);
  }
}

TEST(FTINTRNE) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct Test {
    double a;
    float b;
    int32_t c;
    int32_t d;
    int64_t e;
    int64_t f;
  };
  Test test;

  const int kTableLength = 9;

  // clang-format off
  double inputs_d[kTableLength] = {
      3.1, 3.6, 3.5, -3.1, -3.6, -3.5,
      2147483648.0,
      std::numeric_limits<double>::quiet_NaN(),
      std::numeric_limits<double>::infinity()
  };
  float inputs_s[kTableLength] = {
      3.1, 3.6, 3.5, -3.1, -3.6, -3.5,
      2147483648.0,
      std::numeric_limits<double>::quiet_NaN(),
      std::numeric_limits<double>::infinity()
  };
  double outputs_w[kTableLength] = {
      3.0, 4.0, 4.0, -3.0, -4.0, -4.0,
      kFPUInvalidResult, 0,
      kFPUInvalidResult};
  double outputs_l[kTableLength] = {
      3.0, 4.0, 4.0, -3.0, -4.0, -4.0,
      2147483648.0, 0,
      static_cast<double>(kFPU64InvalidResult)};
  // clang-format on

  __ Fld_d(f8, MemOperand(a0, offsetof(Test, a)));
  __ Fld_s(f9, MemOperand(a0, offsetof(Test, b)));
  __ ftintrne_w_d(f10, f8);
  __ ftintrne_w_s(f11, f9);
  __ ftintrne_l_d(f12, f8);
  __ ftintrne_l_s(f13, f9);
  __ Fst_s(f10, MemOperand(a0, offsetof(Test, c)));
  __ Fst_s(f11, MemOperand(a0, offsetof(Test, d)));
  __ Fst_d(f12, MemOperand(a0, offsetof(Test, e)));
  __ Fst_d(f13, MemOperand(a0, offsetof(Test, f)));
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int i = 0; i < kTableLength; i++) {
    test.a = inputs_d[i];
    test.b = inputs_s[i];
    f.Call(&test, 0, 0, 0, 0);
    CHECK_EQ(test.c, outputs_w[i]);
    CHECK_EQ(test.d, outputs_w[i]);
    CHECK_EQ(test.e, outputs_l[i]);
    CHECK_EQ(test.f, outputs_l[i]);
  }
}

TEST(FRINT) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct Test {
    double a;
    float b;
    double c;
    float d;
    int fcsr;
  };
  Test test;

  const int kTableLength = 32;

  // clang-format off
  double inputs_d[kTableLength] = {
      18446744073709551617.0, 4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E147,
      1.7976931348623157E+308, 6.27463370218383111104242366943E-307,
      309485009821345068724781056.89,
      2.1, 2.6, 2.5, 3.1, 3.6, 3.5,
      -2.1, -2.6, -2.5, -3.1, -3.6, -3.5,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0,
      std::numeric_limits<double>::max() - 0.1,
      std::numeric_limits<double>::infinity()
      };
  float inputs_s[kTableLength] = {
      18446744073709551617.0, 4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E37,
      1.7976931348623157E+38, 6.27463370218383111104242366943E-37,
      309485009821345068724781056.89,
      2.1, 2.6, 2.5, 3.1, 3.6, 3.5,
      -2.1, -2.6, -2.5, -3.1, -3.6, -3.5,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0,
      std::numeric_limits<float>::lowest() + 0.6,
      std::numeric_limits<float>::infinity()
      };
  float outputs_RN_S[kTableLength] = {
      18446744073709551617.0, 4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E37,
      1.7976931348623157E38, 0,
      309485009821345068724781057.0,
      2.0, 3.0, 2.0, 3.0, 4.0, 4.0,
      -2.0, -3.0, -2.0, -3.0, -4.0, -4.0,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0,
      std::numeric_limits<float>::lowest() + 1,
      std::numeric_limits<float>::infinity()
      };
  double outputs_RN_D[kTableLength] = {
      18446744073709551617.0, 4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E147,
      1.7976931348623157E308, 0,
      309485009821345068724781057.0,
      2.0, 3.0, 2.0, 3.0, 4.0, 4.0,
      -2.0, -3.0, -2.0, -3.0, -4.0, -4.0,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0,
      std::numeric_limits<double>::max(),
      std::numeric_limits<double>::infinity()
  };
  float outputs_RZ_S[kTableLength] = {
      18446744073709551617.0, 4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E37,
      1.7976931348623157E38, 0,
      309485009821345068724781057.0,
      2.0, 2.0, 2.0, 3.0, 3.0, 3.0,
      -2.0, -2.0, -2.0, -3.0, -3.0, -3.0,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0,
      std::numeric_limits<float>::lowest() + 1,
      std::numeric_limits<float>::infinity()
  };
  double outputs_RZ_D[kTableLength] = {
      18446744073709551617.0, 4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E147,
      1.7976931348623157E308, 0,
      309485009821345068724781057.0,
      2.0, 2.0, 2.0, 3.0, 3.0, 3.0,
      -2.0, -2.0, -2.0, -3.0, -3.0, -3.0,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0,
      std::numeric_limits<double>::max() - 1,
      std::numeric_limits<double>::infinity()
  };
  float outputs_RP_S[kTableLength] = {
      18446744073709551617.0, 4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E37,
      1.7976931348623157E38, 1,
      309485009821345068724781057.0,
      3.0, 3.0, 3.0, 4.0, 4.0, 4.0,
      -2.0, -2.0, -2.0, -3.0, -3.0, -3.0,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0,
      std::numeric_limits<float>::lowest() + 1,
      std::numeric_limits<float>::infinity()
  };
  double outputs_RP_D[kTableLength] = {
      18446744073709551617.0, 4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E147,
      1.7976931348623157E308, 1,
      309485009821345068724781057.0,
      3.0, 3.0, 3.0, 4.0, 4.0, 4.0,
      -2.0, -2.0, -2.0, -3.0, -3.0, -3.0,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0,
      std::numeric_limits<double>::max(),
      std::numeric_limits<double>::infinity()
  };
  float outputs_RM_S[kTableLength] = {
      18446744073709551617.0, 4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E37,
      1.7976931348623157E38, 0,
      309485009821345068724781057.0,
      2.0, 2.0, 2.0, 3.0, 3.0, 3.0,
      -3.0, -3.0, -3.0, -4.0, -4.0, -4.0,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0,
      std::numeric_limits<float>::lowest() + 1,
      std::numeric_limits<float>::infinity()
  };
  double outputs_RM_D[kTableLength] = {
      18446744073709551617.0, 4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E147,
      1.7976931348623157E308, 0,
      309485009821345068724781057.0,
      2.0, 2.0, 2.0, 3.0, 3.0, 3.0,
      -3.0, -3.0, -3.0, -4.0, -4.0, -4.0,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0,
      std::numeric_limits<double>::max(),
      std::numeric_limits<double>::infinity()
  };
  // clang-format on

  int fcsr_inputs[4] = {kRoundToNearest, kRoundToZero, kRoundToPlusInf,
                        kRoundToMinusInf};
  double* outputs_d[4] = {outputs_RN_D, outputs_RZ_D, outputs_RP_D,
                          outputs_RM_D};
  float* outputs_s[4] = {outputs_RN_S, outputs_RZ_S, outputs_RP_S,
                         outputs_RM_S};

  __ Fld_d(f8, MemOperand(a0, offsetof(Test, a)));
  __ Fld_s(f9, MemOperand(a0, offsetof(Test, b)));
  __ xor_(a5, a5, a5);
  __ Ld_w(a5, MemOperand(a0, offsetof(Test, fcsr)));
  __ movfcsr2gr(a4);
  __ movgr2fcsr(a5);
  __ frint_d(f10, f8);
  __ frint_s(f11, f9);
  __ Fst_d(f10, MemOperand(a0, offsetof(Test, c)));
  __ Fst_s(f11, MemOperand(a0, offsetof(Test, d)));
  __ movgr2fcsr(a4);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int j = 0; j < 4; j++) {
    test.fcsr = fcsr_inputs[j];
    for (int i = 0; i < kTableLength; i++) {
      test.a = inputs_d[i];
      test.b = inputs_s[i];
      f.Call(&test, 0, 0, 0, 0);
      CHECK_EQ(test.c, outputs_d[j][i]);
      CHECK_EQ(test.d, outputs_s[j][i]);
    }
  }
}

TEST(FMOV) {
  const int kTableLength = 7;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct TestFloat {
    double a;
    float b;
    double c;
    float d;
  };

  TestFloat test;

  // clang-format off
  double inputs_D[kTableLength] = {
    5.3, -5.3, 0.29, -0.29, 0,
  std::numeric_limits<double>::max(),
  -std::numeric_limits<double>::max()
  };
  float inputs_S[kTableLength] = {
    4.8, -4.8, 0.29, -0.29, 0,
  std::numeric_limits<float>::max(),
  -std::numeric_limits<float>::max()
  };

  double outputs_D[kTableLength] = {
    5.3, -5.3, 0.29, -0.29, 0,
  std::numeric_limits<double>::max(),
  -std::numeric_limits<double>::max()
  };

  float outputs_S[kTableLength] = {
    4.8, -4.8, 0.29, -0.29, 0,
  std::numeric_limits<float>::max(),
  -std::numeric_limits<float>::max()
  };
  // clang-format on

  __ Fld_d(f8, MemOperand(a0, offsetof(TestFloat, a)));
  __ Fld_s(f9, MemOperand(a0, offsetof(TestFloat, b)));
  __ fmov_d(f10, f8);
  __ fmov_s(f11, f9);
  __ Fst_d(f10, MemOperand(a0, offsetof(TestFloat, c)));
  __ Fst_s(f11, MemOperand(a0, offsetof(TestFloat, d)));
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int i = 0; i < kTableLength; i++) {
    test.a = inputs_D[i];
    test.b = inputs_S[i];
    f.Call(&test, 0, 0, 0, 0);
    CHECK_EQ(test.c, outputs_D[i]);
    CHECK_EQ(test.d, outputs_S[i]);
  }
}

TEST(LA14) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    double a;
    double b;
    double c;
    double d;
    int64_t high;
    int64_t low;
  };
  T t;

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ Fld_d(f8, MemOperand(a0, offsetof(T, a)));
  __ Fld_d(f9, MemOperand(a0, offsetof(T, b)));

  __ movfr2gr_s(a4, f8);
  __ movfrh2gr_s(a5, f8);
  __ movfr2gr_d(a6, f9);

  __ movgr2fr_w(f9, a4);
  __ movgr2frh_w(f9, a5);
  __ movgr2fr_d(f8, a6);

  __ Fst_d(f8, MemOperand(a0, offsetof(T, a)));
  __ Fst_d(f9, MemOperand(a0, offsetof(T, c)));

  __ Fld_d(f8, MemOperand(a0, offsetof(T, d)));
  __ movfrh2gr_s(a4, f8);
  __ movfr2gr_s(a5, f8);

  __ St_d(a4, MemOperand(a0, offsetof(T, high)));
  __ St_d(a5, MemOperand(a0, offsetof(T, low)));

  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);

  t.a = 1.5e22;
  t.b = 2.75e11;
  t.c = 17.17;
  t.d = -2.75e11;
  f.Call(&t, 0, 0, 0, 0);
  CHECK_EQ(2.75e11, t.a);
  CHECK_EQ(2.75e11, t.b);
  CHECK_EQ(1.5e22, t.c);
  CHECK_EQ(static_cast<int64_t>(0xFFFFFFFFC25001D1L), t.high);
  CHECK_EQ(static_cast<int64_t>(0xFFFFFFFFBF800000L), t.low);

  t.a = -1.5e22;
  t.b = -2.75e11;
  t.c = 17.17;
  t.d = 274999868928.0;
  f.Call(&t, 0, 0, 0, 0);
  CHECK_EQ(-2.75e11, t.a);
  CHECK_EQ(-2.75e11, t.b);
  CHECK_EQ(-1.5e22, t.c);
  CHECK_EQ(static_cast<int64_t>(0x425001D1L), t.high);
  CHECK_EQ(static_cast<int64_t>(0x3F800000L), t.low);
}

uint64_t run_bceqz(int fcc_value, int32_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label main_block, L;
  __ li(a2, 0);
  __ li(t0, fcc_value);
  __ b(&main_block);
  // Block 1
  for (int32_t i = -104; i <= -55; ++i) {
    __ addi_d(a2, a2, 0x1);
  }
  __ b(&L);

  // Block 2
  for (int32_t i = -53; i <= -4; ++i) {
    __ addi_d(a2, a2, 0x10);
  }
  __ b(&L);

  // Block 3 (Main)
  __ bind(&main_block);
  __ movcf2gr(t1, FCC0);
  __ movgr2cf(FCC0, t0);
  __ bceqz(FCC0, offset);
  __ bind(&L);
  __ movgr2cf(FCC0, t1);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  // Block 4
  for (int32_t i = 4; i <= 53; ++i) {
    __ addi_d(a2, a2, 0x100);
  }
  __ b(&L);

  // Block 5
  for (int32_t i = 55; i <= 104; ++i) {
    __ addi_d(a2, a2, 0x300);
  }
  __ b(&L);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}

TEST(BCEQZ) {
  CcTest::InitializeVM();
  struct TestCaseBceqz {
    int fcc;
    int32_t offset;
    uint64_t expected_res;
  };

  // clang-format off
  struct TestCaseBceqz tc[] = {
    // fcc, offset, expected_res
    {    0,    -90,         0x24 },
    {    0,    -27,        0x180 },
    {    0,     47,        0x700 },
    {    0,     70,       0x6900 },
    {    1,    -27,            0 },
    {    1,     47,            0 },
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseBceqz);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t res = run_bceqz(tc[i].fcc, tc[i].offset);
    CHECK_EQ(tc[i].expected_res, res);
  }
}

uint64_t run_bcnez(int fcc_value, int32_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label main_block, L;
  __ li(a2, 0);
  __ li(t0, fcc_value);
  __ b(&main_block);
  // Block 1
  for (int32_t i = -104; i <= -55; ++i) {
    __ addi_d(a2, a2, 0x1);
  }
  __ b(&L);

  // Block 2
  for (int32_t i = -53; i <= -4; ++i) {
    __ addi_d(a2, a2, 0x10);
  }
  __ b(&L);

  // Block 3 (Main)
  __ bind(&main_block);
  __ movcf2gr(t1, FCC0);
  __ movgr2cf(FCC0, t0);
  __ bcnez(FCC0, offset);
  __ bind(&L);
  __ movgr2cf(FCC0, t1);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  // Block 4
  for (int32_t i = 4; i <= 53; ++i) {
    __ addi_d(a2, a2, 0x100);
  }
  __ b(&L);

  // Block 5
  for (int32_t i = 55; i <= 104; ++i) {
    __ addi_d(a2, a2, 0x300);
  }
  __ b(&L);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}

TEST(BCNEZ) {
  CcTest::InitializeVM();
  struct TestCaseBcnez {
    int fcc;
    int32_t offset;
    uint64_t expected_res;
  };

  // clang-format off
  struct TestCaseBcnez tc[] = {
    // fcc, offset, expected_res
    {    1,    -90,         0x24 },
    {    1,    -27,        0x180 },
    {    1,     47,        0x700 },
    {    1,     70,       0x6900 },
    {    0,    -27,            0 },
    {    0,     47,            0 },
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseBcnez);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t res = run_bcnez(tc[i].fcc, tc[i].offset);
    CHECK_EQ(tc[i].expected_res, res);
  }
}

TEST(jump_tables1) {
  // Test jump tables with forward jumps.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  const int kNumCases = 512;
  int values[kNumCases];
  isolate->random_number_generator()->NextBytes(values, sizeof(values));
  Label labels[kNumCases];

  __ addi_d(sp, sp, -8);
  __ St_d(ra, MemOperand(sp, 0));
  __ Align(8);

  Label done;
  {
    __ BlockTrampolinePoolFor(kNumCases * 2 + 6);
    __ pcaddi(ra, 2);
    __ slli_d(t7, a0, 3);
    __ add_d(t7, t7, ra);
    __ Ld_d(t7, MemOperand(t7, 4 * kInstrSize));
    __ jirl(zero_reg, t7, 0);
    __ nop();
    for (int i = 0; i < kNumCases; ++i) {
      __ dd(&labels[i]);
    }
  }

  for (int i = 0; i < kNumCases; ++i) {
    __ bind(&labels[i]);
    __ lu12i_w(a2, (values[i] >> 12) & 0xFFFFF);
    __ ori(a2, a2, values[i] & 0xFFF);
    __ b(&done);
    __ nop();
  }

  __ bind(&done);
  __ Ld_d(ra, MemOperand(sp, 0));
  __ addi_d(sp, sp, 8);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CHECK_EQ(0, assm.UnboundLabelsCount());

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  for (int i = 0; i < kNumCases; ++i) {
    int64_t res = reinterpret_cast<int64_t>(f.Call(i, 0, 0, 0, 0));
    ::printf("f(%d) = %" PRId64 "\n", i, res);
    CHECK_EQ((values[i]), static_cast<int>(res));
  }
}

TEST(jump_tables2) {
  // Test jump tables with backward jumps.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  const int kNumCases = 512;
  int values[kNumCases];
  isolate->random_number_generator()->NextBytes(values, sizeof(values));
  Label labels[kNumCases];

  __ addi_d(sp, sp, -8);
  __ St_d(ra, MemOperand(sp, 0));

  Label done, dispatch;
  __ b(&dispatch);
  __ nop();

  for (int i = 0; i < kNumCases; ++i) {
    __ bind(&labels[i]);
    __ lu12i_w(a2, (values[i] >> 12) & 0xFFFFF);
    __ ori(a2, a2, values[i] & 0xFFF);
    __ b(&done);
    __ nop();
  }

  __ Align(8);
  __ bind(&dispatch);
  {
    __ BlockTrampolinePoolFor(kNumCases * 2 + 6);
    __ pcaddi(ra, 2);
    __ slli_d(t7, a0, 3);
    __ add_d(t7, t7, ra);
    __ Ld_d(t7, MemOperand(t7, 4 * kInstrSize));
    __ jirl(zero_reg, t7, 0);
    __ nop();
    for (int i = 0; i < kNumCases; ++i) {
      __ dd(&labels[i]);
    }
  }

  __ bind(&done);
  __ Ld_d(ra, MemOperand(sp, 0));
  __ addi_d(sp, sp, 8);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  for (int i = 0; i < kNumCases; ++i) {
    int64_t res = reinterpret_cast<int64_t>(f.Call(i, 0, 0, 0, 0));
    ::printf("f(%d) = %" PRId64 "\n", i, res);
    CHECK_EQ(values[i], res);
  }
}

TEST(jump_tables3) {
  // Test jump tables with backward jumps and embedded heap objects.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  const int kNumCases = 512;
  Handle<Object> values[kNumCases];
  for (int i = 0; i < kNumCases; ++i) {
    double value = isolate->random_number_generator()->NextDouble();
    values[i] = isolate->factory()->NewHeapNumber<AllocationType::kOld>(value);
  }
  Label labels[kNumCases];
  Tagged<Object> obj;
  int64_t imm64;

  __ addi_d(sp, sp, -8);
  __ St_d(ra, MemOperand(sp, 0));

  Label done, dispatch;
  __ b(&dispatch);
  __ nop();

  for (int i = 0; i < kNumCases; ++i) {
    __ bind(&labels[i]);
    obj = *values[i];
    imm64 = obj.ptr();
    __ lu12i_w(a2, (imm64 >> 12) & 0xFFFFF);
    __ ori(a2, a2, imm64 & 0xFFF);
    __ lu32i_d(a2, (imm64 >> 32) & 0xFFFFF);
    __ lu52i_d(a2, a2, (imm64 >> 52) & 0xFFF);
    __ b(&done);
  }

  __ Align(8);
  __ bind(&dispatch);
  {
    __ BlockTrampolinePoolFor(kNumCases * 2 + 6);
    __ pcaddi(ra, 2);
    __ slli_d(t7, a0, 3);  // In delay slot.
    __ add_d(t7, t7, ra);
    __ Ld_d(t7, MemOperand(t7, 4 * kInstrSize));
    __ jirl(zero_reg, t7, 0);
    __ nop();
    for (int i = 0; i < kNumCases; ++i) {
      __ dd(&labels[i]);
    }
  }
  __ bind(&done);
  __ Ld_d(ra, MemOperand(sp, 0));
  __ addi_d(sp, sp, 8);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  
"""


```