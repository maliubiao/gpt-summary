Response: 
Prompt: 
```
这是目录为v8/test/cctest/test-assembler-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第5部分，共8部分，请归纳一下它的功能

"""
FP64DefaultNaN, d12);
  CHECK_EQUAL_FP64(kFP64DefaultNaN, d13);
}

TEST(fsub) {
  INIT_V8();
  SETUP();

  START();
  __ Fmov(s14, -0.0f);
  __ Fmov(s15, kFP32PositiveInfinity);
  __ Fmov(s16, kFP32NegativeInfinity);
  __ Fmov(s17, 3.25f);
  __ Fmov(s18, 1.0f);
  __ Fmov(s19, 0.0f);

  __ Fmov(d26, -0.0);
  __ Fmov(d27, kFP64PositiveInfinity);
  __ Fmov(d28, kFP64NegativeInfinity);
  __ Fmov(d29, 0.0);
  __ Fmov(d30, -2.0);
  __ Fmov(d31, 2.25);

  __ Fsub(s0, s17, s18);
  __ Fsub(s1, s18, s19);
  __ Fsub(s2, s14, s18);
  __ Fsub(s3, s18, s15);
  __ Fsub(s4, s18, s16);
  __ Fsub(s5, s15, s15);
  __ Fsub(s6, s16, s16);

  __ Fsub(d7, d30, d31);
  __ Fsub(d8, d29, d31);
  __ Fsub(d9, d26, d31);
  __ Fsub(d10, d31, d27);
  __ Fsub(d11, d31, d28);
  __ Fsub(d12, d27, d27);
  __ Fsub(d13, d28, d28);
  END();

  RUN();

  CHECK_EQUAL_FP32(2.25, s0);
  CHECK_EQUAL_FP32(1.0, s1);
  CHECK_EQUAL_FP32(-1.0, s2);
  CHECK_EQUAL_FP32(kFP32NegativeInfinity, s3);
  CHECK_EQUAL_FP32(kFP32PositiveInfinity, s4);
  CHECK_EQUAL_FP32(kFP32DefaultNaN, s5);
  CHECK_EQUAL_FP32(kFP32DefaultNaN, s6);
  CHECK_EQUAL_FP64(-4.25, d7);
  CHECK_EQUAL_FP64(-2.25, d8);
  CHECK_EQUAL_FP64(-2.25, d9);
  CHECK_EQUAL_FP64(kFP64NegativeInfinity, d10);
  CHECK_EQUAL_FP64(kFP64PositiveInfinity, d11);
  CHECK_EQUAL_FP64(kFP64DefaultNaN, d12);
  CHECK_EQUAL_FP64(kFP64DefaultNaN, d13);
}

TEST(fmul) {
  INIT_V8();
  SETUP();

  START();
  __ Fmov(s14, -0.0f);
  __ Fmov(s15, kFP32PositiveInfinity);
  __ Fmov(s16, kFP32NegativeInfinity);
  __ Fmov(s17, 3.25f);
  __ Fmov(s18, 2.0f);
  __ Fmov(s19, 0.0f);
  __ Fmov(s20, -2.0f);

  __ Fmov(d26, -0.0);
  __ Fmov(d27, kFP64PositiveInfinity);
  __ Fmov(d28, kFP64NegativeInfinity);
  __ Fmov(d29, 0.0);
  __ Fmov(d30, -2.0);
  __ Fmov(d31, 2.25);

  __ Fmul(s0, s17, s18);
  __ Fmul(s1, s18, s19);
  __ Fmul(s2, s14, s14);
  __ Fmul(s3, s15, s20);
  __ Fmul(s4, s16, s20);
  __ Fmul(s5, s15, s19);
  __ Fmul(s6, s19, s16);

  __ Fmul(d7, d30, d31);
  __ Fmul(d8, d29, d31);
  __ Fmul(d9, d26, d26);
  __ Fmul(d10, d27, d30);
  __ Fmul(d11, d28, d30);
  __ Fmul(d12, d27, d29);
  __ Fmul(d13, d29, d28);
  END();

  RUN();

  CHECK_EQUAL_FP32(6.5, s0);
  CHECK_EQUAL_FP32(0.0, s1);
  CHECK_EQUAL_FP32(0.0, s2);
  CHECK_EQUAL_FP32(kFP32NegativeInfinity, s3);
  CHECK_EQUAL_FP32(kFP32PositiveInfinity, s4);
  CHECK_EQUAL_FP32(kFP32DefaultNaN, s5);
  CHECK_EQUAL_FP32(kFP32DefaultNaN, s6);
  CHECK_EQUAL_FP64(-4.5, d7);
  CHECK_EQUAL_FP64(0.0, d8);
  CHECK_EQUAL_FP64(0.0, d9);
  CHECK_EQUAL_FP64(kFP64NegativeInfinity, d10);
  CHECK_EQUAL_FP64(kFP64PositiveInfinity, d11);
  CHECK_EQUAL_FP64(kFP64DefaultNaN, d12);
  CHECK_EQUAL_FP64(kFP64DefaultNaN, d13);
}


static void FmaddFmsubHelper(double n, double m, double a,
                             double fmadd, double fmsub,
                             double fnmadd, double fnmsub) {
  SETUP();
  START();

  __ Fmov(d0, n);
  __ Fmov(d1, m);
  __ Fmov(d2, a);
  __ Fmadd(d28, d0, d1, d2);
  __ Fmsub(d29, d0, d1, d2);
  __ Fnmadd(d30, d0, d1, d2);
  __ Fnmsub(d31, d0, d1, d2);

  END();
  RUN();

  CHECK_EQUAL_FP64(fmadd, d28);
  CHECK_EQUAL_FP64(fmsub, d29);
  CHECK_EQUAL_FP64(fnmadd, d30);
  CHECK_EQUAL_FP64(fnmsub, d31);
}

TEST(fmadd_fmsub_double) {
  INIT_V8();

  // It's hard to check the result of fused operations because the only way to
  // calculate the result is using fma, which is what the simulator uses anyway.
  // TODO(jbramley): Add tests to check behaviour against a hardware trace.

  // Basic operation.
  FmaddFmsubHelper(1.0, 2.0, 3.0, 5.0, 1.0, -5.0, -1.0);
  FmaddFmsubHelper(-1.0, 2.0, 3.0, 1.0, 5.0, -1.0, -5.0);

  // Check the sign of exact zeroes.
  //               n     m     a     fmadd  fmsub  fnmadd fnmsub
  FmaddFmsubHelper(-0.0, +0.0, -0.0, -0.0,  +0.0,  +0.0,  +0.0);
  FmaddFmsubHelper(+0.0, +0.0, -0.0, +0.0,  -0.0,  +0.0,  +0.0);
  FmaddFmsubHelper(+0.0, +0.0, +0.0, +0.0,  +0.0,  -0.0,  +0.0);
  FmaddFmsubHelper(-0.0, +0.0, +0.0, +0.0,  +0.0,  +0.0,  -0.0);
  FmaddFmsubHelper(+0.0, -0.0, -0.0, -0.0,  +0.0,  +0.0,  +0.0);
  FmaddFmsubHelper(-0.0, -0.0, -0.0, +0.0,  -0.0,  +0.0,  +0.0);
  FmaddFmsubHelper(-0.0, -0.0, +0.0, +0.0,  +0.0,  -0.0,  +0.0);
  FmaddFmsubHelper(+0.0, -0.0, +0.0, +0.0,  +0.0,  +0.0,  -0.0);

  // Check NaN generation.
  FmaddFmsubHelper(kFP64PositiveInfinity, 0.0, 42.0,
                   kFP64DefaultNaN, kFP64DefaultNaN,
                   kFP64DefaultNaN, kFP64DefaultNaN);
  FmaddFmsubHelper(0.0, kFP64PositiveInfinity, 42.0,
                   kFP64DefaultNaN, kFP64DefaultNaN,
                   kFP64DefaultNaN, kFP64DefaultNaN);
  FmaddFmsubHelper(kFP64PositiveInfinity, 1.0, kFP64PositiveInfinity,
                   kFP64PositiveInfinity,   //  inf + ( inf * 1) = inf
                   kFP64DefaultNaN,         //  inf + (-inf * 1) = NaN
                   kFP64NegativeInfinity,   // -inf + (-inf * 1) = -inf
                   kFP64DefaultNaN);        // -inf + ( inf * 1) = NaN
  FmaddFmsubHelper(kFP64NegativeInfinity, 1.0, kFP64PositiveInfinity,
                   kFP64DefaultNaN,         //  inf + (-inf * 1) = NaN
                   kFP64PositiveInfinity,   //  inf + ( inf * 1) = inf
                   kFP64DefaultNaN,         // -inf + ( inf * 1) = NaN
                   kFP64NegativeInfinity);  // -inf + (-inf * 1) = -inf
}

static void FmaddFmsubHelper(float n, float m, float a,
                             float fmadd, float fmsub,
                             float fnmadd, float fnmsub) {
  SETUP();
  START();

  __ Fmov(s0, n);
  __ Fmov(s1, m);
  __ Fmov(s2, a);
  __ Fmadd(s28, s0, s1, s2);
  __ Fmsub(s29, s0, s1, s2);
  __ Fnmadd(s30, s0, s1, s2);
  __ Fnmsub(s31, s0, s1, s2);

  END();
  RUN();

  CHECK_EQUAL_FP32(fmadd, s28);
  CHECK_EQUAL_FP32(fmsub, s29);
  CHECK_EQUAL_FP32(fnmadd, s30);
  CHECK_EQUAL_FP32(fnmsub, s31);
}

TEST(fmadd_fmsub_float) {
  INIT_V8();
  // It's hard to check the result of fused operations because the only way to
  // calculate the result is using fma, which is what the simulator uses anyway.
  // TODO(jbramley): Add tests to check behaviour against a hardware trace.

  // Basic operation.
  FmaddFmsubHelper(1.0f, 2.0f, 3.0f, 5.0f, 1.0f, -5.0f, -1.0f);
  FmaddFmsubHelper(-1.0f, 2.0f, 3.0f, 1.0f, 5.0f, -1.0f, -5.0f);

  // Check the sign of exact zeroes.
  //               n      m      a      fmadd  fmsub  fnmadd fnmsub
  FmaddFmsubHelper(-0.0f, +0.0f, -0.0f, -0.0f, +0.0f, +0.0f, +0.0f);
  FmaddFmsubHelper(+0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, +0.0f);
  FmaddFmsubHelper(+0.0f, +0.0f, +0.0f, +0.0f, +0.0f, -0.0f, +0.0f);
  FmaddFmsubHelper(-0.0f, +0.0f, +0.0f, +0.0f, +0.0f, +0.0f, -0.0f);
  FmaddFmsubHelper(+0.0f, -0.0f, -0.0f, -0.0f, +0.0f, +0.0f, +0.0f);
  FmaddFmsubHelper(-0.0f, -0.0f, -0.0f, +0.0f, -0.0f, +0.0f, +0.0f);
  FmaddFmsubHelper(-0.0f, -0.0f, +0.0f, +0.0f, +0.0f, -0.0f, +0.0f);
  FmaddFmsubHelper(+0.0f, -0.0f, +0.0f, +0.0f, +0.0f, +0.0f, -0.0f);

  // Check NaN generation.
  FmaddFmsubHelper(kFP32PositiveInfinity, 0.0f, 42.0f,
                   kFP32DefaultNaN, kFP32DefaultNaN,
                   kFP32DefaultNaN, kFP32DefaultNaN);
  FmaddFmsubHelper(0.0f, kFP32PositiveInfinity, 42.0f,
                   kFP32DefaultNaN, kFP32DefaultNaN,
                   kFP32DefaultNaN, kFP32DefaultNaN);
  FmaddFmsubHelper(kFP32PositiveInfinity, 1.0f, kFP32PositiveInfinity,
                   kFP32PositiveInfinity,   //  inf + ( inf * 1) = inf
                   kFP32DefaultNaN,         //  inf + (-inf * 1) = NaN
                   kFP32NegativeInfinity,   // -inf + (-inf * 1) = -inf
                   kFP32DefaultNaN);        // -inf + ( inf * 1) = NaN
  FmaddFmsubHelper(kFP32NegativeInfinity, 1.0f, kFP32PositiveInfinity,
                   kFP32DefaultNaN,         //  inf + (-inf * 1) = NaN
                   kFP32PositiveInfinity,   //  inf + ( inf * 1) = inf
                   kFP32DefaultNaN,         // -inf + ( inf * 1) = NaN
                   kFP32NegativeInfinity);  // -inf + (-inf * 1) = -inf
}

TEST(fmadd_fmsub_double_nans) {
  INIT_V8();
  // Make sure that NaN propagation works correctly.
  double s1 = base::bit_cast<double>(0x7FF5555511111111);
  double s2 = base::bit_cast<double>(0x7FF5555522222222);
  double sa = base::bit_cast<double>(0x7FF55555AAAAAAAA);
  double q1 = base::bit_cast<double>(0x7FFAAAAA11111111);
  double q2 = base::bit_cast<double>(0x7FFAAAAA22222222);
  double qa = base::bit_cast<double>(0x7FFAAAAAAAAAAAAA);
  CHECK(IsSignallingNaN(s1));
  CHECK(IsSignallingNaN(s2));
  CHECK(IsSignallingNaN(sa));
  CHECK(IsQuietNaN(q1));
  CHECK(IsQuietNaN(q2));
  CHECK(IsQuietNaN(qa));

  // The input NaNs after passing through ProcessNaN.
  double s1_proc = base::bit_cast<double>(0x7FFD555511111111);
  double s2_proc = base::bit_cast<double>(0x7FFD555522222222);
  double sa_proc = base::bit_cast<double>(0x7FFD5555AAAAAAAA);
  double q1_proc = q1;
  double q2_proc = q2;
  double qa_proc = qa;
  CHECK(IsQuietNaN(s1_proc));
  CHECK(IsQuietNaN(s2_proc));
  CHECK(IsQuietNaN(sa_proc));
  CHECK(IsQuietNaN(q1_proc));
  CHECK(IsQuietNaN(q2_proc));
  CHECK(IsQuietNaN(qa_proc));

  // Negated NaNs as it would be done on ARMv8 hardware.
  double s1_proc_neg = base::bit_cast<double>(0xFFFD555511111111);
  double sa_proc_neg = base::bit_cast<double>(0xFFFD5555AAAAAAAA);
  double q1_proc_neg = base::bit_cast<double>(0xFFFAAAAA11111111);
  double qa_proc_neg = base::bit_cast<double>(0xFFFAAAAAAAAAAAAA);
  CHECK(IsQuietNaN(s1_proc_neg));
  CHECK(IsQuietNaN(sa_proc_neg));
  CHECK(IsQuietNaN(q1_proc_neg));
  CHECK(IsQuietNaN(qa_proc_neg));

  // Quiet NaNs are propagated.
  FmaddFmsubHelper(q1, 0, 0, q1_proc, q1_proc_neg, q1_proc_neg, q1_proc);
  FmaddFmsubHelper(0, q2, 0, q2_proc, q2_proc, q2_proc, q2_proc);
  FmaddFmsubHelper(0, 0, qa, qa_proc, qa_proc, qa_proc_neg, qa_proc_neg);
  FmaddFmsubHelper(q1, q2, 0, q1_proc, q1_proc_neg, q1_proc_neg, q1_proc);
  FmaddFmsubHelper(0, q2, qa, qa_proc, qa_proc, qa_proc_neg, qa_proc_neg);
  FmaddFmsubHelper(q1, 0, qa, qa_proc, qa_proc, qa_proc_neg, qa_proc_neg);
  FmaddFmsubHelper(q1, q2, qa, qa_proc, qa_proc, qa_proc_neg, qa_proc_neg);

  // Signalling NaNs are propagated, and made quiet.
  FmaddFmsubHelper(s1, 0, 0, s1_proc, s1_proc_neg, s1_proc_neg, s1_proc);
  FmaddFmsubHelper(0, s2, 0, s2_proc, s2_proc, s2_proc, s2_proc);
  FmaddFmsubHelper(0, 0, sa, sa_proc, sa_proc, sa_proc_neg, sa_proc_neg);
  FmaddFmsubHelper(s1, s2, 0, s1_proc, s1_proc_neg, s1_proc_neg, s1_proc);
  FmaddFmsubHelper(0, s2, sa, sa_proc, sa_proc, sa_proc_neg, sa_proc_neg);
  FmaddFmsubHelper(s1, 0, sa, sa_proc, sa_proc, sa_proc_neg, sa_proc_neg);
  FmaddFmsubHelper(s1, s2, sa, sa_proc, sa_proc, sa_proc_neg, sa_proc_neg);

  // Signalling NaNs take precedence over quiet NaNs.
  FmaddFmsubHelper(s1, q2, qa, s1_proc, s1_proc_neg, s1_proc_neg, s1_proc);
  FmaddFmsubHelper(q1, s2, qa, s2_proc, s2_proc, s2_proc, s2_proc);
  FmaddFmsubHelper(q1, q2, sa, sa_proc, sa_proc, sa_proc_neg, sa_proc_neg);
  FmaddFmsubHelper(s1, s2, qa, s1_proc, s1_proc_neg, s1_proc_neg, s1_proc);
  FmaddFmsubHelper(q1, s2, sa, sa_proc, sa_proc, sa_proc_neg, sa_proc_neg);
  FmaddFmsubHelper(s1, q2, sa, sa_proc, sa_proc, sa_proc_neg, sa_proc_neg);
  FmaddFmsubHelper(s1, s2, sa, sa_proc, sa_proc, sa_proc_neg, sa_proc_neg);

  // A NaN generated by the intermediate op1 * op2 overrides a quiet NaN in a.
  FmaddFmsubHelper(0, kFP64PositiveInfinity, qa,
                   kFP64DefaultNaN, kFP64DefaultNaN,
                   kFP64DefaultNaN, kFP64DefaultNaN);
  FmaddFmsubHelper(kFP64PositiveInfinity, 0, qa,
                   kFP64DefaultNaN, kFP64DefaultNaN,
                   kFP64DefaultNaN, kFP64DefaultNaN);
  FmaddFmsubHelper(0, kFP64NegativeInfinity, qa,
                   kFP64DefaultNaN, kFP64DefaultNaN,
                   kFP64DefaultNaN, kFP64DefaultNaN);
  FmaddFmsubHelper(kFP64NegativeInfinity, 0, qa,
                   kFP64DefaultNaN, kFP64DefaultNaN,
                   kFP64DefaultNaN, kFP64DefaultNaN);
}

TEST(fmadd_fmsub_float_nans) {
  INIT_V8();
  // Make sure that NaN propagation works correctly.
  float s1 = base::bit_cast<float>(0x7F951111);
  float s2 = base::bit_cast<float>(0x7F952222);
  float sa = base::bit_cast<float>(0x7F95AAAA);
  float q1 = base::bit_cast<float>(0x7FEA1111);
  float q2 = base::bit_cast<float>(0x7FEA2222);
  float qa = base::bit_cast<float>(0x7FEAAAAA);
  CHECK(IsSignallingNaN(s1));
  CHECK(IsSignallingNaN(s2));
  CHECK(IsSignallingNaN(sa));
  CHECK(IsQuietNaN(q1));
  CHECK(IsQuietNaN(q2));
  CHECK(IsQuietNaN(qa));

  // The input NaNs after passing through ProcessNaN.
  float s1_proc = base::bit_cast<float>(0x7FD51111);
  float s2_proc = base::bit_cast<float>(0x7FD52222);
  float sa_proc = base::bit_cast<float>(0x7FD5AAAA);
  float q1_proc = q1;
  float q2_proc = q2;
  float qa_proc = qa;
  CHECK(IsQuietNaN(s1_proc));
  CHECK(IsQuietNaN(s2_proc));
  CHECK(IsQuietNaN(sa_proc));
  CHECK(IsQuietNaN(q1_proc));
  CHECK(IsQuietNaN(q2_proc));
  CHECK(IsQuietNaN(qa_proc));

  // Negated NaNs as it would be done on ARMv8 hardware.
  float s1_proc_neg = base::bit_cast<float>(0xFFD51111);
  float sa_proc_neg = base::bit_cast<float>(0xFFD5AAAA);
  float q1_proc_neg = base::bit_cast<float>(0xFFEA1111);
  float qa_proc_neg = base::bit_cast<float>(0xFFEAAAAA);
  CHECK(IsQuietNaN(s1_proc_neg));
  CHECK(IsQuietNaN(sa_proc_neg));
  CHECK(IsQuietNaN(q1_proc_neg));
  CHECK(IsQuietNaN(qa_proc_neg));

  // Quiet NaNs are propagated.
  FmaddFmsubHelper(q1, 0, 0, q1_proc, q1_proc_neg, q1_proc_neg, q1_proc);
  FmaddFmsubHelper(0, q2, 0, q2_proc, q2_proc, q2_proc, q2_proc);
  FmaddFmsubHelper(0, 0, qa, qa_proc, qa_proc, qa_proc_neg, qa_proc_neg);
  FmaddFmsubHelper(q1, q2, 0, q1_proc, q1_proc_neg, q1_proc_neg, q1_proc);
  FmaddFmsubHelper(0, q2, qa, qa_proc, qa_proc, qa_proc_neg, qa_proc_neg);
  FmaddFmsubHelper(q1, 0, qa, qa_proc, qa_proc, qa_proc_neg, qa_proc_neg);
  FmaddFmsubHelper(q1, q2, qa, qa_proc, qa_proc, qa_proc_neg, qa_proc_neg);

  // Signalling NaNs are propagated, and made quiet.
  FmaddFmsubHelper(s1, 0, 0, s1_proc, s1_proc_neg, s1_proc_neg, s1_proc);
  FmaddFmsubHelper(0, s2, 0, s2_proc, s2_proc, s2_proc, s2_proc);
  FmaddFmsubHelper(0, 0, sa, sa_proc, sa_proc, sa_proc_neg, sa_proc_neg);
  FmaddFmsubHelper(s1, s2, 0, s1_proc, s1_proc_neg, s1_proc_neg, s1_proc);
  FmaddFmsubHelper(0, s2, sa, sa_proc, sa_proc, sa_proc_neg, sa_proc_neg);
  FmaddFmsubHelper(s1, 0, sa, sa_proc, sa_proc, sa_proc_neg, sa_proc_neg);
  FmaddFmsubHelper(s1, s2, sa, sa_proc, sa_proc, sa_proc_neg, sa_proc_neg);

  // Signalling NaNs take precedence over quiet NaNs.
  FmaddFmsubHelper(s1, q2, qa, s1_proc, s1_proc_neg, s1_proc_neg, s1_proc);
  FmaddFmsubHelper(q1, s2, qa, s2_proc, s2_proc, s2_proc, s2_proc);
  FmaddFmsubHelper(q1, q2, sa, sa_proc, sa_proc, sa_proc_neg, sa_proc_neg);
  FmaddFmsubHelper(s1, s2, qa, s1_proc, s1_proc_neg, s1_proc_neg, s1_proc);
  FmaddFmsubHelper(q1, s2, sa, sa_proc, sa_proc, sa_proc_neg, sa_proc_neg);
  FmaddFmsubHelper(s1, q2, sa, sa_proc, sa_proc, sa_proc_neg, sa_proc_neg);
  FmaddFmsubHelper(s1, s2, sa, sa_proc, sa_proc, sa_proc_neg, sa_proc_neg);

  // A NaN generated by the intermediate op1 * op2 overrides a quiet NaN in a.
  FmaddFmsubHelper(0, kFP32PositiveInfinity, qa,
                   kFP32DefaultNaN, kFP32DefaultNaN,
                   kFP32DefaultNaN, kFP32DefaultNaN);
  FmaddFmsubHelper(kFP32PositiveInfinity, 0, qa,
                   kFP32DefaultNaN, kFP32DefaultNaN,
                   kFP32DefaultNaN, kFP32DefaultNaN);
  FmaddFmsubHelper(0, kFP32NegativeInfinity, qa,
                   kFP32DefaultNaN, kFP32DefaultNaN,
                   kFP32DefaultNaN, kFP32DefaultNaN);
  FmaddFmsubHelper(kFP32NegativeInfinity, 0, qa,
                   kFP32DefaultNaN, kFP32DefaultNaN,
                   kFP32DefaultNaN, kFP32DefaultNaN);
}

TEST(fdiv) {
  INIT_V8();
  SETUP();

  START();
  __ Fmov(s14, -0.0f);
  __ Fmov(s15, kFP32PositiveInfinity);
  __ Fmov(s16, kFP32NegativeInfinity);
  __ Fmov(s17, 3.25f);
  __ Fmov(s18, 2.0f);
  __ Fmov(s19, 2.0f);
  __ Fmov(s20, -2.0f);

  __ Fmov(d26, -0.0);
  __ Fmov(d27, kFP64PositiveInfinity);
  __ Fmov(d28, kFP64NegativeInfinity);
  __ Fmov(d29, 0.0);
  __ Fmov(d30, -2.0);
  __ Fmov(d31, 2.25);

  __ Fdiv(s0, s17, s18);
  __ Fdiv(s1, s18, s19);
  __ Fdiv(s2, s14, s18);
  __ Fdiv(s3, s18, s15);
  __ Fdiv(s4, s18, s16);
  __ Fdiv(s5, s15, s16);
  __ Fdiv(s6, s14, s14);

  __ Fdiv(d7, d31, d30);
  __ Fdiv(d8, d29, d31);
  __ Fdiv(d9, d26, d31);
  __ Fdiv(d10, d31, d27);
  __ Fdiv(d11, d31, d28);
  __ Fdiv(d12, d28, d27);
  __ Fdiv(d13, d29, d29);
  END();

  RUN();

  CHECK_EQUAL_FP32(1.625f, s0);
  CHECK_EQUAL_FP32(1.0f, s1);
  CHECK_EQUAL_FP32(-0.0f, s2);
  CHECK_EQUAL_FP32(0.0f, s3);
  CHECK_EQUAL_FP32(-0.0f, s4);
  CHECK_EQUAL_FP32(kFP32DefaultNaN, s5);
  CHECK_EQUAL_FP32(kFP32DefaultNaN, s6);
  CHECK_EQUAL_FP64(-1.125, d7);
  CHECK_EQUAL_FP64(0.0, d8);
  CHECK_EQUAL_FP64(-0.0, d9);
  CHECK_EQUAL_FP64(0.0, d10);
  CHECK_EQUAL_FP64(-0.0, d11);
  CHECK_EQUAL_FP64(kFP64DefaultNaN, d12);
  CHECK_EQUAL_FP64(kFP64DefaultNaN, d13);
}


static float MinMaxHelper(float n,
                          float m,
                          bool min,
                          float quiet_nan_substitute = 0.0) {
  uint32_t raw_n = base::bit_cast<uint32_t>(n);
  uint32_t raw_m = base::bit_cast<uint32_t>(m);

  if (std::isnan(n) && ((raw_n & kSQuietNanMask) == 0)) {
    // n is signalling NaN.
    return base::bit_cast<float>(raw_n | static_cast<uint32_t>(kSQuietNanMask));
  } else if (std::isnan(m) && ((raw_m & kSQuietNanMask) == 0)) {
    // m is signalling NaN.
    return base::bit_cast<float>(raw_m | static_cast<uint32_t>(kSQuietNanMask));
  } else if (quiet_nan_substitute == 0.0) {
    if (std::isnan(n)) {
      // n is quiet NaN.
      return n;
    } else if (std::isnan(m)) {
      // m is quiet NaN.
      return m;
    }
  } else {
    // Substitute n or m if one is quiet, but not both.
    if (std::isnan(n) && !std::isnan(m)) {
      // n is quiet NaN: replace with substitute.
      n = quiet_nan_substitute;
    } else if (!std::isnan(n) && std::isnan(m)) {
      // m is quiet NaN: replace with substitute.
      m = quiet_nan_substitute;
    }
  }

  if ((n == 0.0) && (m == 0.0) &&
      (copysign(1.0, n) != copysign(1.0, m))) {
    return min ? -0.0 : 0.0;
  }

  return min ? fminf(n, m) : fmaxf(n, m);
}


static double MinMaxHelper(double n,
                           double m,
                           bool min,
                           double quiet_nan_substitute = 0.0) {
  uint64_t raw_n = base::bit_cast<uint64_t>(n);
  uint64_t raw_m = base::bit_cast<uint64_t>(m);

  if (std::isnan(n) && ((raw_n & kDQuietNanMask) == 0)) {
    // n is signalling NaN.
    return base::bit_cast<double>(raw_n | kDQuietNanMask);
  } else if (std::isnan(m) && ((raw_m & kDQuietNanMask) == 0)) {
    // m is signalling NaN.
    return base::bit_cast<double>(raw_m | kDQuietNanMask);
  } else if (quiet_nan_substitute == 0.0) {
    if (std::isnan(n)) {
      // n is quiet NaN.
      return n;
    } else if (std::isnan(m)) {
      // m is quiet NaN.
      return m;
    }
  } else {
    // Substitute n or m if one is quiet, but not both.
    if (std::isnan(n) && !std::isnan(m)) {
      // n is quiet NaN: replace with substitute.
      n = quiet_nan_substitute;
    } else if (!std::isnan(n) && std::isnan(m)) {
      // m is quiet NaN: replace with substitute.
      m = quiet_nan_substitute;
    }
  }

  if ((n == 0.0) && (m == 0.0) &&
      (copysign(1.0, n) != copysign(1.0, m))) {
    return min ? -0.0 : 0.0;
  }

  return min ? fmin(n, m) : fmax(n, m);
}


static void FminFmaxDoubleHelper(double n, double m, double min, double max,
                                 double minnm, double maxnm) {
  SETUP();

  START();
  __ Fmov(d0, n);
  __ Fmov(d1, m);
  __ Fmin(d28, d0, d1);
  __ Fmax(d29, d0, d1);
  __ Fminnm(d30, d0, d1);
  __ Fmaxnm(d31, d0, d1);
  END();

  RUN();

  CHECK_EQUAL_FP64(min, d28);
  CHECK_EQUAL_FP64(max, d29);
  CHECK_EQUAL_FP64(minnm, d30);
  CHECK_EQUAL_FP64(maxnm, d31);
}

TEST(fmax_fmin_d) {
  INIT_V8();
  // Use non-standard NaNs to check that the payload bits are preserved.
  double snan = base::bit_cast<double>(0x7FF5555512345678);
  double qnan = base::bit_cast<double>(0x7FFAAAAA87654321);

  double snan_processed = base::bit_cast<double>(0x7FFD555512345678);
  double qnan_processed = qnan;

  CHECK(IsSignallingNaN(snan));
  CHECK(IsQuietNaN(qnan));
  CHECK(IsQuietNaN(snan_processed));
  CHECK(IsQuietNaN(qnan_processed));

  // Bootstrap tests.
  FminFmaxDoubleHelper(0, 0, 0, 0, 0, 0);
  FminFmaxDoubleHelper(0, 1, 0, 1, 0, 1);
  FminFmaxDoubleHelper(kFP64PositiveInfinity, kFP64NegativeInfinity,
                       kFP64NegativeInfinity, kFP64PositiveInfinity,
                       kFP64NegativeInfinity, kFP64PositiveInfinity);
  FminFmaxDoubleHelper(snan, 0,
                       snan_processed, snan_processed,
                       snan_processed, snan_processed);
  FminFmaxDoubleHelper(0, snan,
                       snan_processed, snan_processed,
                       snan_processed, snan_processed);
  FminFmaxDoubleHelper(qnan, 0,
                       qnan_processed, qnan_processed,
                       0, 0);
  FminFmaxDoubleHelper(0, qnan,
                       qnan_processed, qnan_processed,
                       0, 0);
  FminFmaxDoubleHelper(qnan, snan,
                       snan_processed, snan_processed,
                       snan_processed, snan_processed);
  FminFmaxDoubleHelper(snan, qnan,
                       snan_processed, snan_processed,
                       snan_processed, snan_processed);

  // Iterate over all combinations of inputs.
  double inputs[] = { DBL_MAX, DBL_MIN, 1.0, 0.0,
                      -DBL_MAX, -DBL_MIN, -1.0, -0.0,
                      kFP64PositiveInfinity, kFP64NegativeInfinity,
                      kFP64QuietNaN, kFP64SignallingNaN };

  const int count = sizeof(inputs) / sizeof(inputs[0]);

  for (int in = 0; in < count; in++) {
    double n = inputs[in];
    for (int im = 0; im < count; im++) {
      double m = inputs[im];
      FminFmaxDoubleHelper(n, m,
                           MinMaxHelper(n, m, true),
                           MinMaxHelper(n, m, false),
                           MinMaxHelper(n, m, true, kFP64PositiveInfinity),
                           MinMaxHelper(n, m, false, kFP64NegativeInfinity));
    }
  }
}

static void FminFmaxFloatHelper(float n, float m, float min, float max,
                                float minnm, float maxnm) {
  SETUP();

  START();
  __ Fmov(s0, n);
  __ Fmov(s1, m);
  __ Fmin(s28, s0, s1);
  __ Fmax(s29, s0, s1);
  __ Fminnm(s30, s0, s1);
  __ Fmaxnm(s31, s0, s1);
  END();

  RUN();

  CHECK_EQUAL_FP32(min, s28);
  CHECK_EQUAL_FP32(max, s29);
  CHECK_EQUAL_FP32(minnm, s30);
  CHECK_EQUAL_FP32(maxnm, s31);
}

TEST(fmax_fmin_s) {
  INIT_V8();
  // Use non-standard NaNs to check that the payload bits are preserved.
  float snan = base::bit_cast<float>(0x7F951234);
  float qnan = base::bit_cast<float>(0x7FEA8765);

  float snan_processed = base::bit_cast<float>(0x7FD51234);
  float qnan_processed = qnan;

  CHECK(IsSignallingNaN(snan));
  CHECK(IsQuietNaN(qnan));
  CHECK(IsQuietNaN(snan_processed));
  CHECK(IsQuietNaN(qnan_processed));

  // Bootstrap tests.
  FminFmaxFloatHelper(0, 0, 0, 0, 0, 0);
  FminFmaxFloatHelper(0, 1, 0, 1, 0, 1);
  FminFmaxFloatHelper(kFP32PositiveInfinity, kFP32NegativeInfinity,
                      kFP32NegativeInfinity, kFP32PositiveInfinity,
                      kFP32NegativeInfinity, kFP32PositiveInfinity);
  FminFmaxFloatHelper(snan, 0,
                      snan_processed, snan_processed,
                      snan_processed, snan_processed);
  FminFmaxFloatHelper(0, snan,
                      snan_processed, snan_processed,
                      snan_processed, snan_processed);
  FminFmaxFloatHelper(qnan, 0,
                      qnan_processed, qnan_processed,
                      0, 0);
  FminFmaxFloatHelper(0, qnan,
                      qnan_processed, qnan_processed,
                      0, 0);
  FminFmaxFloatHelper(qnan, snan,
                      snan_processed, snan_processed,
                      snan_processed, snan_processed);
  FminFmaxFloatHelper(snan, qnan,
                      snan_processed, snan_processed,
                      snan_processed, snan_processed);

  // Iterate over all combinations of inputs.
  float inputs[] = { FLT_MAX, FLT_MIN, 1.0, 0.0,
                     -FLT_MAX, -FLT_MIN, -1.0, -0.0,
                     kFP32PositiveInfinity, kFP32NegativeInfinity,
                     kFP32QuietNaN, kFP32SignallingNaN };

  const int count = sizeof(inputs) / sizeof(inputs[0]);

  for (int in = 0; in < count; in++) {
    float n = inputs[in];
    for (int im = 0; im < count; im++) {
      float m = inputs[im];
      FminFmaxFloatHelper(n, m,
                          MinMaxHelper(n, m, true),
                          MinMaxHelper(n, m, false),
                          MinMaxHelper(n, m, true, kFP32PositiveInfinity),
                          MinMaxHelper(n, m, false, kFP32NegativeInfinity));
    }
  }
}

TEST(fccmp) {
  INIT_V8();
  SETUP();

  START();
  __ Fmov(s16, 0.0);
  __ Fmov(s17, 0.5);
  __ Fmov(d18, -0.5);
  __ Fmov(d19, -1.0);
  __ Mov(x20, 0);

  __ Cmp(x20, 0);
  __ Fccmp(s16, s16, NoFlag, eq);
  __ Mrs(x0, NZCV);

  __ Cmp(x20, 0);
  __ Fccmp(s16, s16, VFlag, ne);
  __ Mrs(x1, NZCV);

  __ Cmp(x20, 0);
  __ Fccmp(s16, s17, CFlag, ge);
  __ Mrs(x2, NZCV);

  __ Cmp(x20, 0);
  __ Fccmp(s16, s17, CVFlag, lt);
  __ Mrs(x3, NZCV);

  __ Cmp(x20, 0);
  __ Fccmp(d18, d18, ZFlag, le);
  __ Mrs(x4, NZCV);

  __ Cmp(x20, 0);
  __ Fccmp(d18, d18, ZVFlag, gt);
  __ Mrs(x5, NZCV);

  __ Cmp(x20, 0);
  __ Fccmp(d18, d19, ZCVFlag, ls);
  __ Mrs(x6, NZCV);

  __ Cmp(x20, 0);
  __ Fccmp(d18, d19, NFlag, hi);
  __ Mrs(x7, NZCV);

  __ fccmp(s16, s16, NFlag, al);
  __ Mrs(x8, NZCV);

  __ fccmp(d18, d18, NFlag, nv);
  __ Mrs(x9, NZCV);

  END();

  RUN();

  CHECK_EQUAL_32(ZCFlag, w0);
  CHECK_EQUAL_32(VFlag, w1);
  CHECK_EQUAL_32(NFlag, w2);
  CHECK_EQUAL_32(CVFlag, w3);
  CHECK_EQUAL_32(ZCFlag, w4);
  CHECK_EQUAL_32(ZVFlag, w5);
  CHECK_EQUAL_32(CFlag, w6);
  CHECK_EQUAL_32(NFlag, w7);
  CHECK_EQUAL_32(ZCFlag, w8);
  CHECK_EQUAL_32(ZCFlag, w9);
}

TEST(fcmp) {
  INIT_V8();
  SETUP();

  START();

  // Some of these tests require a floating-point scratch register assigned to
  // the macro assembler, but most do not.
  {
    // We're going to mess around with the available scratch registers in this
    // test. A UseScratchRegisterScope will make sure that they are restored to
    // the default values once we're finished.
    UseScratchRegisterScope temps(&masm);
    masm.FPTmpList()->set_bits(0);

    __ Fmov(s8, 0.0);
    __ Fmov(s9, 0.5);
    __ Mov(w19, 0x7F800001);  // Single precision NaN.
    __ Fmov(s18, w19);

    __ Fcmp(s8, s8);
    __ Mrs(x0, NZCV);
    __ Fcmp(s8, s9);
    __ Mrs(x1, NZCV);
    __ Fcmp(s9, s8);
    __ Mrs(x2, NZCV);
    __ Fcmp(s8, s18);
    __ Mrs(x3, NZCV);
    __ Fcmp(s18, s18);
    __ Mrs(x4, NZCV);
    __ Fcmp(s8, 0.0);
    __ Mrs(x5, NZCV);
    masm.FPTmpList()->set_bits(DoubleRegList{d0}.bits());
    __ Fcmp(s8, 255.0);
    masm.FPTmpList()->set_bits(0);
    __ Mrs(x6, NZCV);

    __ Fmov(d19, 0.0);
    __ Fmov(d20, 0.5);
    __ Mov(x21, 0x7FF0000000000001UL);  // Double precision NaN.
    __ Fmov(d21, x21);

    __ Fcmp(d19, d19);
    __ Mrs(x10, NZCV);
    __ Fcmp(d19, d20);
    __ Mrs(x11, NZCV);
    __ Fcmp(d20, d19);
    __ Mrs(x12, NZCV);
    __ Fcmp(d19, d21);
    __ Mrs(x13, NZCV);
    __ Fcmp(d21, d21);
    __ Mrs(x14, NZCV);
    __ Fcmp(d19, 0.0);
    __ Mrs(x15, NZCV);
    masm.FPTmpList()->set_bits(DoubleRegList{d0}.bits());
    __ Fcmp(d19, 12.3456);
    masm.FPTmpList()->set_bits(0);
    __ Mrs(x16, NZCV);
  }

  END();

  RUN();

  CHECK_EQUAL_32(ZCFlag, w0);
  CHECK_EQUAL_32(NFlag, w1);
  CHECK_EQUAL_32(CFlag, w2);
  CHECK_EQUAL_32(CVFlag, w3);
  CHECK_EQUAL_32(CVFlag, w4);
  CHECK_EQUAL_32(ZCFlag, w5);
  CHECK_EQUAL_32(NFlag, w6);
  CHECK_EQUAL_32(ZCFlag, w10);
  CHECK_EQUAL_32(NFlag, w11);
  CHECK_EQUAL_32(CFlag, w12);
  CHECK_EQUAL_32(CVFlag, w13);
  CHECK_EQUAL_32(CVFlag, w14);
  CHECK_EQUAL_32(ZCFlag, w15);
  CHECK_EQUAL_32(NFlag, w16);
}

TEST(fcsel) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x16, 0);
  __ Fmov(s16, 1.0);
  __ Fmov(s17, 2.0);
  __ Fmov(d18, 3.0);
  __ Fmov(d19, 4.0);

  __ Cmp(x16, 0);
  __ Fcsel(s0, s16, s17, eq);
  __ Fcsel(s1, s16, s17, ne);
  __ Fcsel(d2, d18, d19, eq);
  __ Fcsel(d3, d18, d19, ne);
  __ fcsel(s4, s16, s17, al);
  __ fcsel(d5, d18, d19, nv);
  END();

  RUN();

  CHECK_EQUAL_FP32(1.0, s0);
  CHECK_EQUAL_FP32(2.0, s1);
  CHECK_EQUAL_FP64(3.0, d2);
  CHECK_EQUAL_FP64(4.0, d3);
  CHECK_EQUAL_FP32(1.0, s4);
  CHECK_EQUAL_FP64(3.0, d5);
}

TEST(fneg) {
  INIT_V8();
  SETUP();

  START();
  __ Fmov(s16, 1.0);
  __ Fmov(s17, 0.0);
  __ Fmov(s18, kFP32PositiveInfinity);
  __ Fmov(d19, 1.0);
  __ Fmov(d20, 0.0);
  __ Fmov(d21, kFP64PositiveInfinity);

  __ Fneg(s0, s16);
  __ Fneg(s1, s0);
  __ Fneg(s2, s17);
  __ Fneg(s3, s2);
  __ Fneg(s4, s18);
  __ Fneg(s5, s4);
  __ Fneg(d6, d19);
  __ Fneg(d7, d6);
  __ Fneg(d8, d20);
  __ Fneg(d9, d8);
  __ Fneg(d10, d21);
  __ Fneg(d11, d10);
  END();

  RUN();

  CHECK_EQUAL_FP32(-1.0, s0);
  CHECK_EQUAL_FP32(1.0, s1);
  CHECK_EQUAL_FP32(-0.0, s2);
  CHECK_EQUAL_FP32(0.0, s3);
  CHECK_EQUAL_FP32(kFP32NegativeInfinity, s4);
  CHECK_EQUAL_FP32(kFP32PositiveInfinity, s5);
  CHECK_EQUAL_FP64(-1.0, d6);
  CHECK_EQUAL_FP64(1.0, d7);
  CHECK_EQUAL_FP64(-0.0, d8);
  CHECK_EQUAL_FP64(0.0, d9);
  CHECK_EQUAL_FP64(kFP64NegativeInfinity, d10);
  CHECK_EQUAL_FP64(kFP64PositiveInfinity, d11);
}

TEST(fabs) {
  INIT_V8();
  SETUP();

  START();
  __ Fmov(s16, -1.0);
  __ Fmov(s17, -0.0);
  __ Fmov(s18, kFP32NegativeInfinity);
  __ Fmov(d19, -1.0);
  __ Fmov(d20, -0.0);
  __ Fmov(d21, kFP64NegativeInfinity);

  __ Fabs(s0, s16);
  __ Fabs(s1, s0);
  __ Fabs(s2, s17);
  __ Fabs(s3, s18);
  __ Fabs(d4, d19);
  __ Fabs(d5, d4);
  __ Fabs(d6, d20);
  __ Fabs(d7, d21);
  END();

  RUN();

  CHECK_EQUAL_FP32(1.0, s0);
  CHECK_EQUAL_FP32(1.0, s1);
  CHECK_EQUAL_FP32(0.0, s2);
  CHECK_EQUAL_FP32(kFP32PositiveInfinity, s3);
  CHECK_EQUAL_FP64(1.0, d4);
  CHECK_EQUAL_FP64(1.0, d5);
  CHECK_EQUAL_FP64(0.0, d6);
  CHECK_EQUAL_FP64(kFP64PositiveInfinity, d7);
}

TEST(fsqrt) {
  INIT_V8();
  SETUP();

  START();
  __ Fmov(s16, 0.0);
  __ Fmov(s17, 1.0);
  __ Fmov(s18, 0.25);
  __ Fmov(s19, 65536.0);
  __ Fmov(s20, -0.0);
  __ Fmov(s21, kFP32PositiveInfinity);
  __ Fmov(s22, -1.0);
  __ Fmov(d23, 0.0);
  __ Fmov(d24, 1.0);
  __ Fmov(d25, 0.25);
  __ Fmov(d26, 4294967296.0);
  __ Fmov(d27, -0.0);
  __ Fmov(d28, kFP64PositiveInfinity);
  __ Fmov(d29, -1.0);

  __ Fsqrt(s0, s16);
  __ Fsqrt(s1, s17);
  __ Fsqrt(s2, s18);
  __ Fsqrt(s3, s19);
  __ Fsqrt(s4, s20);
  __ Fsqrt(s5, s21);
  __ Fsqrt(s6, s22);
  __ Fsqrt(d7, d23);
  __ Fsqrt(d8, d24);
  __ Fsqrt(d9, d25);
  __ Fsqrt(d10, d26);
  __ Fsqrt(d11, d27);
  __ Fsqrt(d12, d28);
  __ Fsqrt(d13, d29);
  END();

  RUN();

  CHECK_EQUAL_FP32(0.0, s0);
  CHECK_EQUAL_FP32(1.0, s1);
  CHECK_EQUAL_FP32(0.5, s2);
  CHECK_EQUAL_FP32(256.0, s3);
  CHECK_EQUAL_FP32(-0.0, s4);
  CHECK_EQUAL_FP32(kFP32PositiveInfinity, s5);
  CHECK_EQUAL_FP32(kFP32DefaultNaN, s6);
  CHECK_EQUAL_FP64(0.0, d7);
  CHECK_EQUAL_FP64(1.0, d8);
  CHECK_EQUAL_FP64(0.5, d9);
  CHECK_EQUAL_FP64(65536.0, d10);
  CHECK_EQUAL_FP64(-0.0, d11);
  CHECK_EQUAL_FP64(kFP32PositiveInfinity, d12);
  CHECK_EQUAL_FP64(kFP64DefaultNaN, d13);
}

TEST(frinta) {
  INIT_V8();
  SETUP();

  START();
  __ Fmov(s16, 1.0);
  __ Fmov(s17, 1.1);
  __ Fmov(s18, 1.5);
  __ Fmov(s19, 1.9);
  __ Fmov(s20, 2.5);
  __ Fmov(s21, -1.5);
  __ Fmov(s22, -2.5);
  __ Fmov(s23, kFP32PositiveInfinity);
  __ Fmov(s24, kFP32NegativeInfinity);
  __ Fmov(s25, 0.0);
  __ Fmov(s26, -0.0);
  __ Fmov(s27, -0.2);

  __ Frinta(s0, s16);
  __ Frinta(s1, s17);
  __ Frinta(s2, s18);
  __ Frinta(s3, s19);
  __ Frinta(s4, s20);
  __ Frinta(s5, s21);
  __ Frinta(s6, s22);
  __ Frinta(s7, s23);
  __ Frinta(s8, s24);
  __ Frinta(s9, s25);
  __ Frinta(s10, s26);
  __ Frinta(s11, s27);

  __ Fmov(d16, 1.0);
  __ Fmov(d17, 1.1);
  __ Fmov(d18, 1.5);
  __ Fmov(d19, 1.9);
  __ Fmov(d20, 2.5);
  __ Fmov(d21, -1.5);
  __ Fmov(d22, -2.5);
  __ Fmov(d23, kFP32PositiveInfinity);
  __ Fmov(d24, kFP32NegativeInfinity);
  __ Fmov(d25, 0.0);
  __ Fmov(d26, -0.0);
  __ Fmov(d27, -0.2);

  __ Frinta(d12, d16);
  __ Frinta(d13, d17);
  __ Frinta(d14, d18);
  __ Frinta(d15, d19);
  __ Frinta(d16, d20);
  __ Frinta(d17, d21);
  __ Frinta(d18, d22);
  __ Frinta(d19, d23);
  __ Frinta(d20, d24);
  __ Frinta(d21, d25);
  __ Frinta(d22, d26);
  __ Frinta(d23, d27);
  END();

  RUN();

  CHECK_EQUAL_FP32(1.0, s0);
  CHECK_EQUAL_FP32(1.0, s1);
  CHECK_EQUAL_FP32(2.0, s2);
  CHECK_EQUAL_FP32(2.0, s3);
  CHECK_EQUAL_FP32(3.0, s4);
  CHECK_EQUAL_FP32(-2.0, s5);
  CHECK_EQUAL_FP32(-3.0, s6);
  CHECK_EQUAL_FP32(kFP32PositiveInfinity, s7);
  CHECK_EQUAL_FP32(kFP32NegativeInfinity, s8);
  CHECK_EQUAL_FP32(0.0, s9);
  CHECK_EQUAL_FP32(-0.0, s10);
  CHECK_EQUAL_FP32(-0.0, s11);
  CHECK_EQUAL_FP64(1.0, d12);
  CHECK_EQUAL_FP64(1.0, d13);
  CHECK_EQUAL_FP64(2.0, d14);
  CHECK_EQUAL_FP64(2.0, d15);
  CHECK_EQUAL_FP64(3.0, d16);
  CHECK_EQUAL_FP64(-2.0, d17);
  CHECK_EQUAL_FP64(-3.0, d18);
  CHECK_EQUAL_FP64(kFP64PositiveInfinity, d19);
  CHECK_EQUAL_FP64(kFP64NegativeInfinity, d20);
  CHECK_EQUAL_FP64(0.0, d21);
  CHECK_EQUAL_FP64(-0.0, d22);
  CHECK_EQUAL_FP64(-0.0, d23);
}

TEST(frintm) {
  INIT_V8();
  SETUP();

  START();
  __ Fmov(s16, 1.0);
  __ Fmov(s17, 1.1);
  __ Fmov(s18, 1.5);
  __ Fmov(s19, 1.9);
  __ Fmov(s20, 2.5);
  __ Fmov(s21, -1.5);
  __ Fmov(s22, -2.5);
  __ Fmov(s23, kFP32PositiveInfinity);
  __ Fmov(s24, kFP32NegativeInfinity);
  __ Fmov(s25, 0.0);
  __ Fmov(s26, -0.0);
  __ Fmov(s27, -0.2);

  __ Frintm(s0, s16);
  __ Frintm(s1, s17);
  __ Frintm(s2, s18);
  __ Frintm(s3, s19);
  __ Frintm(s4, s20);
  __ Frintm(s5, s21);
  __ Frintm(s6, s22);
  __ Frintm(s7, s23);
  __ Frintm(s8, s24);
  __ Frintm(s9, s25);
  __ Frintm(s10, s26);
  __ Frintm(s11, s27);

  __ Fmov(d16, 1.0);
  __ Fmov(d17, 1.1);
  __ Fmov(d18, 1.5);
  __ Fmov(d19, 1.9);
  __ Fmov(d20, 2.5);
  __ Fmov(d21, -1.5);
  __ Fmov(d22, -2.5);
  __ Fmov(d23, kFP32PositiveInfinity);
  __ Fmov(d24, kFP32NegativeInfinity);
  __ Fmov(d25, 0.0);
  __ Fmov(d26, -0.0);
  __ Fmov(d27, -0.2);

  __ Frintm(d12, d16);
  __ Frintm(d13, d17);
  __ Frintm(d14, d18);
  __ Frintm(d15, d19);
  __ Frintm(d16, d20);
  __ Frintm(d17, d21);
  __ Frintm(d18, d22);
  __ Frintm(d19, d23);
  __ Frintm(d20, d24);
  __ Frintm(d21, d25);
  __ Frintm(d22, d26);
  __ Frintm(d23, d27);
  END();

  RUN();

  CHECK_EQUAL_FP32(1.0, s0);
  CHECK_EQUAL_FP32(1.0, s1);
  CHECK_EQUAL_FP32(1.0, s2);
  CHECK_EQUAL_FP32(1.0, s3);
  CHECK_EQUAL_FP32(2.0, s4);
  CHECK_EQUAL_FP32(-2.0, s5);
  CHECK_EQUAL_FP32(-3.0, s6);
  CHECK_EQUAL_FP32(kFP32PositiveInfinity, s7);
  CHECK_EQUAL_FP32(kFP32NegativeInfinity, s8);
  CHECK_EQUAL_FP32(0.0, s9);
  CHECK_EQUAL_FP32(-0.0, s10);
  CHECK_EQUAL_FP32(-1.0, s11);
  CHECK_EQUAL_FP64(1.0, d12);
  CHECK_EQUAL_FP64(1.0, d13);
  CHECK_EQUAL_FP64(1.0, d14);
  CHECK_EQUAL_FP64(1.0, d15);
  CHECK_EQUAL_FP64(2.0, d16);
  CHECK_EQUAL_FP64(-2.0, d17);
  CHECK_EQUAL_FP64(-3.0, d18);
  CHECK_EQUAL_FP64(kFP64PositiveInfinity, d19);
  CHECK_EQUAL_FP64(kFP64NegativeInfinity, d20);
  CHECK_EQUAL_FP64(0.0, d21);
  CHECK_EQUAL_FP64(-0.0, d22);
  CHECK_EQUAL_FP64(-1.0, d23);
}

TEST(frintn) {
  INIT_V8();
  SETUP();

  START();
  __ Fmov(s16, 1.0);
  __ Fmov(s17, 1.1);
  __ Fmov(s18, 1.5);
  __ Fmov(s19, 1.9);
  __ Fmov(s20, 2.5);
  __ Fmov(s21, -1.5);
  __ Fmov(s22, -2.5);
  __ Fmov(s23, kFP32PositiveInfinity);
  __ Fmov(s24, kFP32NegativeInfinity);
  __ Fmov(s25, 0.0);
  __ Fmov(s26, -0.0);
  __ Fmov(s27, -0.2);

  __ Frintn(s0, s16);
  __ Frintn(s1, s17);
  __ Frintn(s2, s18);
  __ Frintn(s3, s19);
  __ Frintn(s4, s20);
  __ Frintn(s5, s21);
  __ Frintn(s6, s22);
  __ Frintn(s7, s23);
  __ Frintn(s8, s24);
  __ Frintn(s9, s25);
  __ Frintn(s10, s26);
  __ Frintn(s11, s27);

  __ Fmov(d16, 1.0);
  __ Fmov(d17, 1.1);
  __ Fmov(d18, 1.5);
  __ Fmov(d19, 1.9);
  __ Fmov(d20, 2.5);
  __ Fmov(d21, -1.5);
  __ Fmov(d22, -2.5);
  __ Fmov(d23, kFP32PositiveInfinity);
  __ Fmov(d24, kFP32NegativeInfinity);
  __ Fmov(d25, 0.0);
  __ Fmov(d26, -0.0);
  __ Fmov(d27, -0.2);

  __ Frintn(d12, d16);
  __ Frintn(d13, d17);
  __ Frintn(d14, d18);
  __ Frintn(d15, d19);
  __ Frintn(d16, d20);
  __ Frintn(d17, d21);
  __ Frintn(d18, d22);
  __ Frintn(d19, d23);
  __ Frintn(d20, d24);
  __ Frintn(d21, d25);
  __ Frintn(d22, d26);
  __ Frintn(d23, d27);
  END();

  RUN();

  CHECK_EQUAL_FP32(1.0, s0);
  CHECK_EQUAL_FP32(1.0, s1);
  CHECK_EQUAL_FP32(2.0, s2);
  CHECK_EQUAL_FP32(2.0, s3);
  CHECK_EQUAL_FP32(2.0, s4);
  CHECK_EQUAL_FP32(-2.0, s5);
  CHECK_EQUAL_FP32(-2.0, s6);
  CHECK_EQUAL_FP32(kFP32PositiveInfinity, s7);
  CHECK_EQUAL_FP32(kFP32NegativeInfinity, s8);
  CHECK_EQUAL_FP32(0.0, s9);
  CHECK_EQUAL_FP32(-0.0, s10);
  CHECK_EQUAL_FP32(-0.0, s11);
  CHECK_EQUAL_FP64(1.0, d12);
  CHECK_EQUAL_FP64(1.0, d13);
  CHECK_EQUAL_FP64(2.0, d14);
  CHECK_EQUAL_FP64(2.0, d15);
  CHECK_EQUAL_FP64(2.0, d16);
  CHECK_EQUAL_FP64(-2.0, d17);
  CHECK_EQUAL_FP64(-2.0, d18);
  CHECK_EQUAL_FP64(kFP64PositiveInfinity, d19);
  CHECK_EQUAL_FP64(kFP64NegativeInfinity, d20);
  CHECK_EQUAL_FP64(0.0, d21);
  CHECK_EQUAL_FP64(-0.0, d22);
  CHECK_EQUAL_FP64(-0.0, d23);
}

TEST(frintp) {
  INIT_V8();
  SETUP();

  START();
  __ Fmov(s16, 1.0);
  __ Fmov(s17, 1.1);
  __ Fmov(s18, 1.5);
  __ Fmov(s19, 1.9);
  __ Fmov(s20, 2.5);
  __ Fmov(s21, -1.5);
  __ Fmov(s22, -2.5);
  __ Fmov(s23, kFP32PositiveInfinity);
  __ Fmov(s24, kFP32NegativeInfinity);
  __ Fmov(s25, 0.0);
  __ Fmov(s26, -0.0);
  __ Fmov(s27, -0.2);

  __ Frintp(s0, s16);
  __ Frintp(s1, s17);
  __ Frintp(s2, s18);
  __ Frintp(s3, s19);
  __ Frintp(s4, s20);
  __ Frintp(s5, s21);
  __ Frintp(s6, s22);
  __ Frintp(s7, s23);
  __ Frintp(s8, s24);
  __ Frintp(s9, s25);
  __ Frintp(s10, s26);
  __ Frintp(s11, s27);

  __ Fmov(d16, -0.5);
  __ Fmov(d17, -0.8);
  __ Fmov(d18, 1.5);
  __ Fmov(d19, 1.9);
  __ Fmov(d20, 2.5);
  __ Fmov(d21, -1.5);
  __ Fmov(d22, -2.5);
  __ Fmov(d23, kFP32PositiveInfinity);
  __ Fmov(d24, kFP32NegativeInfinity);
  __ Fmov(d25, 0.0);
  __ Fmov(d26, -0.0);
  __ Fmov(d27, -0.2);

  __ Frintp(d12, d16);
  __ Frintp(d13, d17);
  __ Frintp(d14, d18);
  __ Frintp(d15, d19);
  __ Frintp(d16, d20);
  __ Frintp(d17, d21);
  __ Frintp(d18, d22);
  __ Frintp(d19, d23);
  __ Frintp(d20, d24);
  __ Frintp(d21, d25);
  __ Frintp(d22, d26);
  __ Frintp(d23, d27);
  END();

  RUN();

  CHECK_EQUAL_FP32(1.0, s0);
  CHECK_EQUAL_FP32(2.0, s1);
  CHECK_EQUAL_FP32(2.0, s2);
  CHECK_EQUAL_FP32(2.0, s3);
  CHECK_EQUAL_FP32(3.0, s4);
  CHECK_EQUAL_FP32(-1.0, s5);
  CHECK_EQUAL_FP32(-2.0, s6);
  CHECK_EQUAL_FP32(kFP32PositiveInfinity, s7);
  CHECK_EQUAL_FP32(kFP32NegativeInfinity, s8);
  CHECK_EQUAL_FP32(0.0, s9);
  CHECK_EQUAL_FP32(-0.0, s10);
  CHECK_EQUAL_FP32(-0.0, s11);
  CHECK_EQUAL_FP64(-0.0, d12);
  CHECK_EQUAL_FP64(-0.0, d13);
  CHECK_EQUAL_FP64(2.0, d14);
  CHECK_EQUAL_FP64(2.0, d15);
  CHECK_EQUAL_FP64(3.0, d16);
  CHECK_EQUAL_FP64(-1.0, d17);
  CHECK_EQUAL_FP64(-2.0, d18);
  CHECK_EQUAL_FP64(kFP64PositiveInfinity, d19);
  CHECK_EQUAL_FP64(kFP64NegativeInfinity, d20);
  CHECK_EQUAL_FP64(0.0, d21);
  CHECK_EQUAL_FP64(-0.0, d22);
  CHECK_EQUAL_FP64(-0.0, d23);
}

TEST(frintz) {
  INIT_V8();
  SETUP();

  START();
  __ Fmov(s16, 1.0);
  __ Fmov(s17, 1.1);
  __ Fmov(s18, 1.5);
  __ Fmov(s19, 1.9);
  __ Fmov(s20, 2.5);
  __ Fmov(s21, -1.5);
  __ Fmov(s22, -2.5);
  __ Fmov(s23, kFP32PositiveInfinity);
  __ Fmov(s24, kFP32NegativeInfinity);
  __ Fmov(s25, 0.0);
  __ Fmov(s26, -0.0);

  __ Frintz(s0, s16);
  __ Frintz(s1, s17);
  __ Frintz(s2, s18);
  __ Frintz(s3, s19);
  __ Frintz(s4, s20);
  __ Frintz(s5, s21);
  __ Frintz(s6, s22);
  __ Frintz(s7, s23);
  __ Frintz(s8, s24);
  __ Frintz(s9, s25);
  __ Frintz(s10, s26);

  __ Fmov(d16, 1.0);
  __ Fmov(d17, 1.1);
  __ Fmov(d18, 1.5);
  __ Fmov(d19, 1.9);
  __ Fmov(d20, 2.5);
  __ Fmov(d21, -1.5);
  __ Fmov(d22, -2.5);
  __ Fmov(d23, kFP32PositiveInfinity);
  __ Fmov(d24, kFP32NegativeInfinity);
  __ Fmov(d25, 0.0);
  __ Fmov(d26, -0.0);

  __ Frintz(d11, d16);
  __ Frintz(d12, d17);
  __ Frintz(d13, d18);
  __ Frintz(d14, d19);
  __ Frintz(d15, d20);
  __ Frintz(d16, d21);
  __ Frintz(d17, d22);
  __ Frintz(d18, d23);
  __ Frintz(d19, d24);
  __ Frintz(d20, d25);
  __ Frintz(d21, d26);
  END();

  RUN();

  CHECK_EQUAL_FP32(1.0, s0);
  CHECK_EQUAL_FP32(1.0, s1);
  CHECK_EQUAL_FP32(1.0, s2);
  CHECK_EQUAL_FP32(1.0, s3);
  CHECK_EQUAL_FP32(2.0, s4);
  CHECK_EQUAL_FP32(-1.0, s5);
  CHECK_EQUAL_FP32(-2.0, s6);
  CHECK_EQUAL_FP32(kFP32PositiveInfinity, s7);
  CHECK_EQUAL_FP32(kFP32NegativeInfinity, s8);
  CHECK_EQUAL_FP32(0.0, s9);
  CHECK_EQUAL_FP32(-0.0, s10);
  CHECK_EQUAL_FP64(1.0, d11);
  CHECK_EQUAL_FP64(1.0, d12);
  CHECK_EQUAL_FP64(1.0, d13);
  CHECK_EQUAL_FP64(1.0, d14);
  CHECK_EQUAL_FP64(2.0, d15);
  CHECK_EQUAL_FP64(-1.0, d16);
  CHECK_EQUAL_FP64(-2.0, d17);
  CHECK_EQUAL_FP64(kFP64PositiveInfinity, d18);
  CHECK_EQUAL_FP64(kFP64NegativeInfinity, d19);
  CHECK_EQUAL_FP64(0.0, d20);
  CHECK_EQUAL_FP64(-0.0, d21);
}

TEST(fcvt_ds) {
  INIT_V8();
  SETUP();

  START();
  __ Fmov(s16, 1.0);
  __ Fmov(s17, 1.1);
  __ Fmov(s18, 1.5);
  __ Fmov(s19, 1.9);
  __ Fmov(s20, 2.5);
  __ Fmov(s21, -1.5);
  __ Fmov(s22, -2.5);
  __ Fmov(s23, kFP32PositiveInfinity);
  __ Fmov(s24, kFP32NegativeInfinity);
  __ Fmov(s25, 0.0);
  __ Fmov(s26, -0.0);
  __ Fmov(s27, FLT_MAX);
  __ Fmov(s28, FLT_MIN);
  __ Fmov(s29, base::bit_cast<float>(0x7FC12345));  // Quiet NaN.
  __ Fmov(s30, base::bit_cast<float>(0x7F812345));  // Signalling NaN.

  __ Fcvt(d0, s16);
  __ Fcvt(d1, s17);
  __ Fcvt(d2, s18);
  __ Fcvt(d3, s19);
  __ Fcvt(d4, s20);
  __ Fcvt(d5, s21);
  __ Fcvt(d6, s22);
  __ Fcvt(d7, s23);
  __ Fcvt(d8, s24);
  __ Fcvt(d9, s25);
  __ Fcvt(d10, s26);
  __ Fcvt(d11, s27);
  __ Fcvt(d12, s28);
  __ Fcvt(d13, s29);
  __ Fcvt(d14, s30);
  END();

  RUN();

  CHECK_EQUAL_FP64(1.0f, d0);
  CHECK_EQUAL_FP64(1.1f, d1);
  CHECK_EQUAL_FP64(1.5f, d2);
  CHECK_EQUAL_FP64(1.9f, d3);
  CHECK_EQUAL_FP64(2.5f, d4);
  CHECK_EQUAL_FP64(-1.5f, d5);
  CHECK_EQUAL_FP64(-2.5f, d6);
  CHECK_EQUAL_FP64(kFP64PositiveInfinity, d7);
  CHECK_EQUAL_FP64(kFP64NegativeInfinity, d8);
  CHECK_EQUAL_FP64(0.0f, d9);
  CHECK_EQUAL_FP64(-0.0f, d10);
  CHECK_EQUAL_FP64(FLT_MAX, d11);
  CHECK_EQUAL_FP64(FLT_MIN, d12);

  // Check that the NaN payload is preserved according to ARM64 conversion
  // rules:
  //  - The sign bit is preserved.
  //  - The top bit of the mantissa is forced to 1 (making it a quiet NaN).
  //  - The remaining mantissa bits are copied until they run out.
  //  - The low-order bits that haven't already been assigned are set to 0.
  CHECK_EQUAL_FP64(base::bit_cast<double>(0x7FF82468A0000000), d13);
  CHECK_EQUAL_FP64(base::bit_cast<double>(0x7FF82468A0000000), d14);
}

TEST(fcvt_sd) {
  INIT_V8();
  // There are a huge number of corner-cases to check, so this test iterates
  // through a list. The list is then negated and checked again (since the sign
  // is irrelevant in ties-to-even rounding), so the list shouldn't include any
  // negative values.
  //
  // Note that this test only checks ties-to-even rounding, because that is all
  // that the simulator supports.
  struct {
    double in;
    float expected;
  } test[] = {
      // Check some simple conversions.
      {0.0, 0.0f},
      {1.0, 1.0f},
      {1.5, 1.5f},
      {2.0, 2.0f},
      {FLT_MAX, FLT_MAX},
      //  - The smallest normalized float.
      {pow(2.0, -126), powf(2, -126)},
      //  - Normal floats that need (ties-to-even) rounding.
      //    For normalized numbers:
      //         bit 29 (0x0000000020000000) is the lowest-order bit which will
      //                                     fit in the float's mantissa.
      {base::bit_cast<double>(0x3FF0000000000000),
       base::bit_cast<float>(0x3F800000)},
      {base::bit_cast<double>(0x3FF0000000000001),
       base::bit_cast<float>(0x3F800000)},
      {base::bit_cast<double>(0x3FF0000010000000),
       base::bit_cast<float>(0x3F800000)},
      {base::bit_cast<double>(0x3FF0000010000001),
       base::bit_cast<float>(0x3F800001)},
      {base::bit_cast<double>(0x3FF0000020000000),
       base::bit_cast<float>(0x3F800001)},
      {base::bit_cast<double>(0x3FF0000020000001),
       base::bit_cast<float>(0x3F800001)},
      {base::bit_cast<double>(0x3FF0000030000000),
       base::bit_cast<float>(0x3F800002)},
      {base::bit_cast<double>(0x3FF0000030000001),
       base::bit_cast<float>(0x3F800002)},
      {base::bit_cast<double>(0x3FF0000040000000),
       base::bit_cast<float>(0x3F800002)},
      {base::bit_cast<double>(0x3FF0000040000001),
       base::bit_cast<float>(0x3F800002)},
      {base::bit_cast<double>(0x3FF0000050000000),
       base::bit_cast<float>(0x3F800002)},
      {base::bit_cast<double>(0x3FF0000050000001),
       base::bit_cast<float>(0x3F800003)},
      {base::bit_cast<double>(0x3FF0000060000000),
       base::bit_cast<float>(0x3F800003)},
      //  - A mantissa that overflows into the exponent during rounding.
      {base::bit_cast<double>(0x3FEFFFFFF0000000),
       base::bit_cast<float>(0x3F800000)},
      //  - The largest double that rounds to a normal float.
      {base::bit_cast<double>(0x47EFFFFFEFFFFFFF),
       base::bit_cast<float>(0x7F7FFFFF)},

      // Doubles that are too big for a float.
      {kFP64PositiveInfinity, kFP32PositiveInfinity},
      {DBL_MAX, kFP32PositiveInfinity},
      //  - The smallest exponent that's too big for a float.
      {pow(2.0, 128), kFP32PositiveInfinity},
      //  - This exponent is in range, but the value rounds to infinity.
      {base::bit_cast<double>(0x47EFFFFFF0000000), kFP32PositiveInfinity},

      // Doubles that are too small for a float.
      //  - The smallest (subnormal) double.
      {DBL_MIN, 0.0},
      //  - The largest double which is too small for a subnormal float.
      {base::bit_cast<double>(0x3690000000000000),
       base::bit_cast<float>(0x00000000)},

      // Normal doubles that become subnormal floats.
      //  - The largest subnormal float.
      {base::bit_cast<double>(0x380FFFFFC0000000),
       base::bit_cast<float>(0x007FFFFF)},
      //  - The smallest subnormal float.
      {base::bit_cast<double>(0x36A0000000000000),
       base::bit_cast<float>(0x00000001)},
      //  - Subnormal floats that need (ties-to-even) rounding.
      //    For these subnormals:
      //         bit 34 (0x0000000400000000) is the lowest-order bit which will
      //                                     fit in the float's mantissa.
      {base::bit_cast<double>(0x37C159E000000000),
       base::bit_cast<float>(0x00045678)},
      {base::bit_cast<double>(0x37C159E000000001),
       base::bit_cast<float>(0x00045678)},
      {base::bit_cast<double>(0x37C159E200000000),
       base::bit_cast<float>(0x00045678)},
      {base::bit_cast<double>(0x37C159E200000001),
       base::bit_cast<float>(0x00045679)},
      {base::bit_cast<double>(0x37C159E400000000),
       base::bit_cast<float>(0x00045679)},
      {base::bit_cast<double>(0x37C159E400000001),
       base::bit_cast<float>(0x00045679)},
      {base::bit_cast<double>(0x37C159E600000000),
       base::bit_cast<float>(0x0004567A)},
      {base::bit_cast<double>(0x37C159E600000001),
       base::bit_cast<float>(0x0004567A)},
      {base::bit_cast<double>(0x37C159E800000000),
       base::bit_cast<float>(0x0004567A)},
      {base::bit_cast<double>(0x37C159E800000001),
       base::bit_cast<float>(0x0004567A)},
      {base::bit_cast<double>(0x37C159EA00000000),
       base::bit_cast<float>(0x0004567A)},
      {base::bit_cast<double>(0x37C159EA00000001),
       base::bit_cast<float>(0x0004567B)},
      {base::bit_cast<double>(0x37C159EC00000000),
       base::bit_cast<float>(0x0004567B)},
      //  - The smallest double which rounds up to become a subnormal float.
      {base::bit_cast<double>(0x3690000000000001),
       base::bit_cast<float>(0x00000001)},

      // Check NaN payload preservation.
      {base::bit_cast<double>(0x7FF82468A0000000),
       base::bit_cast<float>(0x7FC12345)},
      {base::bit_cast<double>(0x7FF82468BFFFFFFF),
       base::bit_cast<float>(0x7FC12345)},
      //  - Signalling NaNs become quiet NaNs.
      {base::bit_cast<double>(0x7FF02468A0000000),
       base::bit_cast<float>(0x7FC12345)},
      {base::bit_cast<double>(0x7FF02468BFFFFFFF),
       base::bit_cast<float>(0x7FC12345)},
      {base::bit_cast<double>(0x7FF000001FFFFFFF),
       base::bit_cast<float>(0x7FC00000)},
  };
  int count = sizeof(test) / sizeof(test[0]);

  for (int i = 0; i < count; i++) {
    double in = test[i].in;
    float expected = test[i].expected;

    // We only expect positive input.
    CHECK_EQ(std::signbit(in), 0);
    CHECK_EQ(std::signbit(expected), 0);

    SETUP();
    START();

    __ Fmov(d10, in);
    __ Fcvt(s20, d10);

    __ Fmov(d11, -in);
    __ Fcvt(s21, d11);

    END();
    RUN();
    CHECK_EQUAL_FP32(expected, s20);
    CHECK_EQUAL_FP32(-expected, s21);
  }
}

TEST(fcvtas) {
  INIT_V8();
  SETUP();

  int64_t scratch = 0;
  uintptr_t scratch_base = reinterpret_cast<uintptr_t>(&scratch);

  START();
  __ Fmov(s0, 1.0);
  __ Fmov(s1, 1.1);
  __ Fmov(s2, 2.5);
  __ Fmov(s3, -2.5);
  __ Fmov(s4, kFP32PositiveInfinity);
  __ Fmov(s5, kFP32NegativeInfinity);
  __ Fmov(s6, 0x7FFFFF80);  // Largest float < INT32_MAX.
  __ Fneg(s7, s6);          // Smallest float > INT32_MIN.
  __ Fmov(d8, 1.0);
  __ Fmov(d9, 1.1);
  __ Fmov(d10, 2.5);
  __ Fmov(d11, -2.5);
  __ Fmov(d12, kFP64PositiveInfinity);
  __ Fmov(d13, kFP64NegativeInfinity);
  __ Fmov(d14, kWMaxInt - 1);
  __ Fmov(d15, kWMinInt + 1);
  __ Fmov(s16, 2.5);
  __ Fmov(s17, 1.1);
  __ Fmov(s19, -2.5);
  __ Fmov(s20, kFP32PositiveInfinity);
  __ Fmov(s21, kFP32NegativeInfinity);
  __ Fmov(s22, 0x7FFFFF8000000000UL);   // Largest float < INT64_MAX.
  __ Fneg(s23, s22);                    // Smallest float > INT64_MIN.
  __ Fmov(d24, 1.1);
  __ Fmov(d25, 2.5);
  __ Fmov(d26, -2.5);
  __ Fmov(d27, kFP64PositiveInfinity);
  __ Fmov(d28, kFP64NegativeInfinity);
  __ Fmov(d29, 0x7FFFFFFFFFFFFC00UL);   // Largest double < INT64_MAX.
  __ Fneg(d30, d29);                    // Smallest double > INT64_MIN.

  __ Fcvtas(w0, s0);
  __ Fcvtas(w1, s1);
  __ Fcvtas(w2, s2);
  __ Fcvtas(w3, s3);
  __ Fcvtas(w4, s4);
  __ Fcvtas(w5, s5);
  __ Fcvtas(w6, s6);
  __ Fcvtas(w7, s7);
  __ Fcvtas(w8, d8);
  __ Fcvtas(w9, d9);
  __ Fcvtas(w10, d10);
  __ Fcvtas(w11, d11);
  __ Fcvtas(w12, d12);
  __ Fcvtas(w13, d13);
  __ Fcvtas(w14, d14);
  __ Fcvtas(w15, d15);
  __ Fcvtas(x17, s17);
  __ Fcvtas(x19, s19);
  __ Fcvtas(x20, s20);
  __ Fcvtas(x21, s21);
  __ Fcvtas(x22, s22);
  __ Fcvtas(x23, s23);
  __ Fcvtas(x24, d24);
  __ Fcvtas(x25, d25);
  __ Fcvtas(x26, d26);
  __ Fcvtas(x27, d27);
  __ Fcvtas(x28, d28);

  // Save results to the scratch memory, for those that don't fit in registers.
  __ Mov(x30, scratch_base);
  __ Fcvtas(x29, s16);
  __ Str(x29, MemOperand(x30));

  __ Fcvtas(x29, d29);
  __ Fcvtas(x30, d30);
  END();

  RUN();

  CHECK_EQUAL_64(1, x0);
  CHECK_EQUAL_64(1, x1);
  CHECK_EQUAL_64(3, x2);
  CHECK_EQUAL_64(0xFFFFFFFD, x3);
  CHECK_EQUAL_64(0x7FFFFFFF, x4);
  CHECK_EQUAL_64(0x80000000, x5);
  CHECK_EQUAL_64(0x7FFFFF80, x6);
  CHECK_EQUAL_64(0x80000080, x7);
  CHECK_EQUAL_64(1, x8);
  CHECK_EQUAL_64(1, x9);
  CHECK_EQUAL_64(3, x10);
  CHECK_EQUAL_64(0xFFFFFFFD, x11);
  CHECK_EQUAL_64(0x7FFFFFFF, x12);
  CHECK_EQUAL_64(0x80000000, x13);
  CHECK_EQUAL_64(0x7FFFFFFE, x14);
  CHECK_EQUAL_64(0x80000001, x15);
  CHECK_EQUAL_64(3, scratch);
  CHECK_EQUAL_64(1, x17);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFDUL, x19);
  CHECK_EQUAL_64(0x7FFFFFFFFFFFFFFFUL, x20);
  CHECK_EQUAL_64(0x8000000000000000UL, x21);
  CHECK_EQUAL_64(0x7FFFFF8000000000UL, x22);
  CHECK_EQUAL_64(0x8000008000000000UL, x23);
  CHECK_EQUAL_64(1, x24);
  CHECK_EQUAL_64(3, x25);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFDUL, x26);
  CHECK_EQUAL_64(0x7FFFFFFFFFFFFFFFUL, x27);
  CHECK_EQUAL_64(0x8000000000000000UL, x28);
  CHECK_EQUAL_64(0x7FFFFFFFFFFFFC00UL, x29);
  CHECK_EQUAL_64(0x8000000000000400UL, x30);
}

TEST(fcvtau) {
  INIT_V8();
  SETUP();

  START();
  __ Fmov(s0, 1.0);
  __ Fmov(s1, 1.1);
  __ Fmov(s2, 2.5);
  __ Fmov(s3, -2.5);
  __ Fmov(s4, kFP32PositiveInfinity);
  __ Fmov(s5, kFP32NegativeInfinity);
  __ Fmov(s6, 0xFFFFFF00);  // Largest float < UINT32_MAX.
  __ Fmov(d8, 1.0);
  __ Fmov(d9, 1.1);
  __ Fmov(d10, 2.5);
  __ Fmov(d11, -2.5);
  __ Fmov(d12, kFP64PositiveInfinity);
  __ Fmov(d13, kFP64NegativeInfinity);
  __ Fmov(d14, 0xFFFFFFFE);
  __ Fmov(s16, 1.0);
  __ Fmov(s17, 1.1);
  __ Fmov(s18, 2.5);
  __ Fmov(s19, -2.5);
  __ Fmov(s20, kFP32PositiveInfinity);
  __ Fmov(s21, kFP32NegativeInfinity);
  __ Fmov(s22, 0xFFFFFF0000000000UL);  // Largest float < UINT64_MAX.
  __ Fmov(d24, 1.1);
  __ Fmov(d25, 2.5);
  __ Fmov(d26, -2.5);
  __ Fmov(d27, kFP64PositiveInfinity);
  __ Fmov(d28, kFP64NegativeInfinity);
  __ Fmov(d29, 0xFFFFFFFFFFFFF800UL);  // Largest double < UINT64_MAX.
  __ Fmov(s30, 0x100000000UL);

  __ Fcvtau(w0, s0);
  __ Fcvtau(w1, s1);
  __ Fcvtau(w2, s2);
  __ Fcvtau(w3, s3);
  __ Fcvtau(w4, s4);
  __ Fcvtau(w5, s5);
  __ Fcvtau(w6, s6);
  __ Fcvtau(w8, d8);
  __ Fcvtau(w9, d9);
  __ Fcvtau(w10, d10);
  __ Fcvtau(w11, d11);
  __ Fcvtau(w12, d12);
  __ Fcvtau(w13, d13);
  __ Fcvtau(w14, d14);
  __ Fcvtau(w15, d15);
  __ Fcvtau(x16, s16);
  __ Fcvtau(x17, s17);
  __ Fcvtau(x7, s18);
  __ Fcvtau(x19, s19);
  __ Fcvtau(x20, s20);
  __ Fcvtau(x21, s21);
  __ Fcvtau(x22, s22);
  __ Fcvtau(x24, d24);
  __ Fcvtau(x25, d25);
  __ Fcvtau(x26, d26);
  __ Fcvtau(x27, d27);
  __ Fcvtau(x28, d28);
  __ Fcvtau(x29, d29);
  __ Fcvtau(w30, s30);
  END();

  RUN();

  CHECK_EQUAL_64(1, x0);
  CHECK_EQUAL_64(1, x1);
  CHECK_EQUAL_64(3, x2);
  CHECK_EQUAL_64(0, x3);
  CHECK_EQUAL_64(0xFFFFFFFF, x4);
  CHECK_EQUAL_64(0, x5);
  CHECK_EQUAL_64(0xFFFFFF00, x6);
  CHECK_EQUAL_64(1, x8);
  CHECK_EQUAL_64(1, x9);
  CHECK_EQUAL_64(3, x10);
  CHECK_EQUAL_64(0, x11);
  CHECK_EQUAL_64(0xFFFFFFFF, x12);
  CHECK_EQUAL_64(0, x13);
  CHECK_EQUAL_64(0xFFFFFFFE, x14);
  CHECK_EQUAL_64(1, x16);
  CHECK_EQUAL_64(1, x17);
  CHECK_EQUAL_64(3, x7);
  CHECK_EQUAL_64(0, x19);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFFUL, x20);
  CHECK_EQUAL_64(0, x21);
  CHECK_EQUAL_64(0xFFFFFF0000000000UL, x22);
  CHECK_EQUAL_64(1, x24);
  CHECK_EQUAL_64(3, x25);
  CHECK_EQUAL_64(0, x26);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFFUL, x27);
  CHECK_EQUAL_64(0, x28);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFF800UL, x29);
  CHECK_EQUAL_64(0xFFFFFFFF, x30);
}

TEST(fcvtms) {
  INIT_V8();
  SETUP();

  int64_t scratch = 0;
  uintptr_t scratch_base = reinterpret_cast<uintptr_t>(&scratch);

  START();
  __ Fmov(s0, 1.0);
  __ Fmov(s1, 1.1);
  __ Fmov(s2, 1.5);
  __ Fmov(s3, -1.5);
  __ Fmov(s4, kFP32PositiveInfinity);
  __ Fmov(s5, kFP32NegativeInfinity);
  __ Fmov(s6, 0x7FFFFF80);  // Largest float < INT32_MAX.
  __ Fneg(s7, s6);          // Smallest float > INT32_MIN.
  __ Fmov(d8, 1.0);
  __ Fmov(d9, 1.1);
  __ Fmov(d10, 1.5);
  __ Fmov(d11, -1.5);
  __ Fmov(d12, kFP64PositiveInfinity);
  __ Fmov(d13, kFP64NegativeInfinity);
  __ Fmov(d14, kWMaxInt - 1);
  __ Fmov(d15, kWMinInt + 1);
  __ Fmov(s16, 1.5);
  __ Fmov(s17, 1.1);
  __ Fmov(s19, -1.5);
  __ Fmov(s20, kFP32PositiveInfinity);
  __ Fmov(s21, kFP32NegativeInfinity);
  __ Fmov(s22, 0x7FFFFF8000000000UL);   // Largest float < INT64_MAX.
  __ Fneg(s23, s22);                    // Smallest float > INT64_MIN.
  __ Fmov(d24, 1.1);
  __ Fmov(d25, 1.5);
  __ Fmov(d26, -1.5);
  __ Fmov(d27, kFP64PositiveInfinity);
  __ Fmov(d28, kFP64NegativeInfinity);
  __ Fmov(d29, 0x7FFFFFFFFFFFFC00UL);   // Largest double < INT64_MAX.
  __ Fneg(d30, d29);                    // Smallest double > INT64_MIN.

  __ Fcvtms(w0, s0);
  __ Fcvtms(w1, s1);
  __ Fcvtms(w2, s2);
  __ Fcvtms(w3, s3);
  __ Fcvtms(w4, s4);
  __ Fcvtms(w5, s5);
  __ Fcvtms(w6, s6);
  __ Fcvtms(w7, s7);
  __ Fcvtms(w8, d8);
  __ Fcvtms(w9, d9);
  __ Fcvtms(w10, d10);
  __ Fcvtms(w11, d11);
  __ Fcvtms(w12, d12);
  __ Fcvtms(w13, d13);
  __ Fcvtms(w14, d14);
  __ Fcvtms(w15, d15);
  __ Fcvtms(x17, s17);
  __ Fcvtms(x19, s19);
  __ Fcvtms(x20, s20);
  __ Fcvtms(x21, s21);
  __ Fcvtms(x22, s22);
  __ Fcvtms(x23, s23);
  __ Fcvtms(x24, d24);
  __ Fcvtms(x25, d25);
  __ Fcvtms(x26, d26);
  __ Fcvtms(x27, d27);
  __ Fcvtms(x28, d28);

  // Save results to the scratch memory, for those that don't fit in registers.
  __ Mov(x30, scratch_base);
  __ Fcvtms(x29, s16);
  __ Str(x29, MemOperand(x30));

  __ Fcvtms(x29, d29);
  __ Fcvtms(x30, d30);
  END();

  RUN();

  CHECK_EQUAL_64(1, x0);
  CHECK_EQUAL_64(1, x1);
  CHECK_EQUAL_64(1, x2);
  CHECK_EQUAL_64(0xFFFFFFFE, x3);
  CHECK_EQUAL_64(0x7FFFFFFF, x4);
  CHECK_EQUAL_64(0x80000000, x5);
  CHECK_EQUAL_64(0x7FFFFF80, x6);
  CHECK_EQUAL_64(0x80000080, x7);
  CHECK_EQUAL_64(1, x8);
  CHECK_EQUAL_64(1, x9);
  CHECK_EQUAL_64(1, x10);
  CHECK_EQUAL_64(0xFFFFFFFE, x11);
  CHECK_EQUAL_64(0x7FFFFFFF, x12);
  CHECK_EQUAL_64(0x80000000, x13);
  CHECK_EQUAL_64(0x7FFFFFFE, x14);
  CHECK_EQUAL_64(0x80000001, x15);
  CHECK_EQUAL_64(1, scratch);
  CHECK_EQUAL_64(1, x17);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFEUL, x19);
  CHECK_EQUAL_64(0x7FFFFFFFFFFFFFFFUL, x20);
  CHECK_EQUAL_64(0x8000000000000000UL, x21);
  CHECK_EQUAL_64(0x7FFFFF8000000000UL, x22);
  CHECK_EQUAL_64(0x8000008000000000UL, x23);
  CHECK_EQUAL_64(1, x24);
  CHECK_EQUAL_64(1, x25);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFEUL, x26);
  CHECK_EQUAL_64(0x7FFFFFFFFFFFFFFFUL, x27);
  CHECK_EQUAL_64(0x8000000000000000UL, x28);
  CHECK_EQUAL_64(0x7FFFFFFFFFFFFC00UL, x29);
  CHECK_EQUAL_64(0x8000000000000400UL, x30);
}

TEST(fcvtmu) {
  INIT_V8();
  SETUP();

  int64_t scratch = 0;
  uintptr_t scratch_base = reinterpret_cast<uintptr_t>(&scratch);

  START();
  __ Fmov(s0, 1.0);
  __ Fmov(s1, 1.1);
  __ Fmov(s2, 1.5);
  __ Fmov(s3, -1.5);
  __ Fmov(s4, kFP32PositiveInfinity);
  __ Fmov(s5, kFP32NegativeInfinity);
  __ Fmov(s6, 0x7FFFFF80);  // Largest float < INT32_MAX.
  __ Fneg(s7, s6);          // Smallest float > INT32_MIN.
  __ Fmov(d8, 1.0);
  __ Fmov(d9, 1.1);
  __ Fmov(d10, 1.5);
  __ Fmov(d11, -1.5);
  __ Fmov(d12, kFP64PositiveInfinity);
  __ Fmov(d13, kFP64NegativeInfinity);
  __ Fmov(d14, kWMaxInt - 1);
  __ Fmov(d15, kWMinInt + 1);
  __ Fmov(s16, 1.5);
  __ Fmov(s17, 1.1);
  __ Fmov(s19, -1.5);
  __ Fmov(s20, kFP32PositiveInfinity);
  __ Fmov(s21, kFP32NegativeInfinity);
  __ Fmov(s22, 0x7FFFFF8000000000UL);   // Largest float < INT64_MAX.
  __ Fneg(s23, s22);                    // Smallest float > INT64_MIN.
  __ Fmov(d24, 1.1);
  __ Fmov(d25, 1.5);
  __ Fmov(d26, -1.5);
  __ Fmov(d27, kFP64PositiveInfinity);
  __ Fmov(d28, kFP64NegativeInfinity);
  __ Fmov(d29, 0x7FFFFFFFFFFFFC00UL);   // Largest double < INT64_MAX.
  __ Fneg(d30, d29);                    // Smallest double > INT64_MIN.

  __ Fcvtmu(w0, s0);
  __ Fcvtmu(w1, s1);
  __ Fcvtmu(w2, s2);
  __ Fcvtmu(w3, s3);
  __ Fcvtmu(w4, s4);
  __ Fcvtmu(w5, s5);
  __ Fcvtmu(w6, s6);
  __ Fcvtmu(w7, s7);
  __ Fcvtmu(w8, d8);
  __ Fcvtmu(w9, d9);
  __ Fcvtmu(w10, d10);
  __ Fcvtmu(w11, d11);
  __ Fcvtmu(w12, d12);
  __ Fcvtmu(w13, d13);
  __ Fcvtmu(w14, d14);
  __ Fcvtmu(w15, d15);
  __ Fcvtmu(x17, s17);
  __ Fcvtmu(x19, s19);
  __ Fcvtmu(x20, s20);
  __ Fcvtmu(x21, s21);
  __ Fcvtmu(x22, s22);
  __ Fcvtmu(x23, s23);
  __ Fcvtmu(x24, d24);
  __ Fcvtmu(x25, d25);
  __ Fcvtmu(x26, d26);
  __ Fcvtmu(x27, d27);
  __ Fcvtmu(x28, d28);

  // Save results to the scratch memory, for those that don't fit in registers.
  __ Mov(x30, scratch_base);
  __ Fcvtmu(x29, s16);
  __ Str(x29, MemOperand(x30));

  __ Fcvtmu(x29, d29);
  __ Fcvtmu(x30, d30);
  END();

  RUN();

  CHECK_EQUAL_64(1, x0);
  CHECK_EQUAL_64(1, x1);
  CHECK_EQUAL_64(1, x2);
  CHECK_EQUAL_64(0, x3);
  CHECK_EQUAL_64(0xFFFFFFFF, x4);
  CHECK_EQUAL_64(0, x5);
  CHECK_EQUAL_64(0x7FFFFF80, x6);
  CHECK_EQUAL_64(0, x7);
  CHECK_EQUAL_64(1, x8);
  CHECK_EQUAL_64(1, x9);
  CHECK_EQUAL_64(1, x10);
  CHECK_EQUAL_64(0, x11);
  CHECK_EQUAL_64(0xFFFFFFFF, x12);
  CHECK_EQUAL_64(0, x13);
  CHECK_EQUAL_64(0x7FFFFFFE, x14);
  CHECK_EQUAL_64(0x0, x15);
  CHECK_EQUAL_64(1, scratch);
  CHECK_EQUAL_64(1, x17);
  CHECK_EQUAL_64(0x0UL, x19);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFFUL, x20);
  CHECK_EQUAL_64(0x0UL, x21);
  CHECK_EQUAL_64(0x7FFFFF8000000000UL, x22);
  CHECK_EQUAL_64(0x0UL, x23);
  CHECK_EQUAL_64(1, x24);
  CHECK_EQUAL_64(1, x25);
  CHECK_EQUAL_64(0x0UL, x26);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFFUL, x27);
  CHECK_EQUAL_64(0x0UL, x28);
  CHECK_EQUAL_64(0x7FFFFFFFFFFFFC00UL, x29);
  CHECK_EQUAL_64(0x0UL, x30);
}

TEST(fcvtn) {
  INIT_V8();
  SETUP();
  START();

  double src[2] = {1.0f, 1.0f};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  __ Mov(x0, src_base);
  __ Ldr(q0, MemOperand(x0, 0));

  __ Fcvtn(q0.V2S(), q0.V2D());

  END();
  RUN();

  // Ensure top half is cleared.
  CHECK_EQUAL_128(0, 0x3f800000'3f800000, q0);
}

TEST(fcvtns) {
  INIT_V8();
  SETUP();

  int64_t scratch = 0;
  uintptr_t scratch_base = reinterpret_cast<uintptr_t>(&scratch);

  START();
  __ Fmov(s0, 1.0);
  __ Fmov(s1, 1.1);
  __ Fmov(s2, 1.5);
  __ Fmov(s3, -1.5);
  __ Fmov(s4, kFP32PositiveInfinity);
  __ Fmov(s5, kFP32NegativeInfinity);
  __ Fmov(s6, 0x7FFFFF80);  // Largest float < INT32_MAX.
  __ Fneg(s7, s6);          // Smallest float > INT32_MIN.
  __ Fmov(d8, 1.0);
  __ Fmov(d9, 1.1);
  __ Fmov(d10, 1.5);
  __ Fmov(d11, -1.5);
  __ Fmov(d12, kFP64PositiveInfinity);
  __ Fmov(d13, kFP64NegativeInfinity);
  __ Fmov(d14, kWMaxInt - 1);
  __ Fmov(d15, kWMinInt + 1);
  __ Fmov(s16, 1.5);
  __ Fmov(s17, 1.1);
  __ Fmov(s19, -1.5);
  __ Fmov(s20, kFP32PositiveInfinity);
  __ Fmov(s21, kFP32NegativeInfinity);
  __ Fmov(s22, 0x7FFFFF8000000000UL);   // Largest float < INT64_MAX.
  __ Fneg(s23, s22);                    // Smallest float > INT64_MIN.
  __ Fmov(d24, 1.1);
  __ Fmov(d25, 1.5);
  __ Fmov(d26, -1.5);
  __ Fmov(d27, kFP64PositiveInfinity);
  __ Fmov(d28, kFP64NegativeInfinity);
  __ Fmov(d29, 0x7FFFFFFFFFFFFC00UL);   // Largest double < INT64_MAX.
  __ Fneg(d30, d29);                    // Smallest double > INT64_MIN.

  __ Fcvtns(w0, s0);
  __ Fcvtns(w1, s1);
  __ Fcvtns(w2, s2);
  __ Fcvtns(w3, s3);
  __ Fcvtns(w4, s4);
  __ Fcvtns(w5, s5);
  __ Fcvtns(w6, s6);
  __ Fcvtns(w7, s7);
  __ Fcvtns(w8, d8);
  __ Fcvtns(w9, d9);
  __ Fcvtns(w10, d10);
  __ Fcvtns(w11, d11);
  __ Fcvtns(w12, d12);
  __ Fcvtns(w13, d13);
  __ Fcvtns(w14, d14);
  __ Fcvtns(w15, d15);
  __ Fcvtns(x17, s17);
  __ Fcvtns(x19, s19);
  __ Fcvtns(x20, s20);
  __ Fcvtns(x21, s21);
  __ Fcvtns(x22, s22);
  __ Fcvtns(x23, s23);
  __ Fcvtns(x24, d24);
  __ Fcvtns(x25, d25);
  __ Fcvtns(x26, d26);
  __ Fcvtns(x27, d27);
//  __ Fcvtns(x28, d28);

  // Save results to the scratch memory, for those that don't fit in registers.
  __ Mov(x30, scratch_base);
  __ Fcvtns(x29, s16);
  __ Str(x29, MemOperand(x30));

  __ Fcvtns(x29, d29);
  __ Fcvtns(x30, d30);
  END();

  RUN();

  CHECK_EQUAL_64(1, x0);
  CHECK_EQUAL_64(1, x1);
  CHECK_EQUAL_64(2, x2);
  CHECK_EQUAL_64(0xFFFFFFFE, x3);
  CHECK_EQUAL_64(0x7FFFFFFF, x4);
  CHECK_EQUAL_64(0x80000000, x5);
  CHECK_EQUAL_64(0x7FFFFF80, x6);
  CHECK_EQUAL_64(0x80000080, x7);
  CHECK_EQUAL_64(1, x8);
  CHECK_EQUAL_64(1, x9);
  CHECK_EQUAL_64(2, x10);
  CHECK_EQUAL_64(0xFFFFFFFE, x11);
  CHECK_EQUAL_64(0x7FFFFFFF, x12);
  CHECK_EQUAL_64(0x80000000, x13);
  CHECK_EQUAL_64(0x7FFFFFFE, x14);
  CHECK_EQUAL_64(0x80000001, x15);
  CHECK_EQUAL_64(2, scratch);
  CHECK_EQUAL_64(1, x17);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFEUL, x19);
  CHECK_EQUAL_64(0x7FFFFFFFFFFFFFFFUL, x20);
  CHECK_EQUAL_64(0x8000000000000000UL, x21);
  CHECK_EQUAL_64(0x7FFFFF8000000000UL, x22);
  CHECK_EQUAL_64(0x8000008000000000UL, x23);
  CHECK_EQUAL_64(1, x24);
  CHECK_EQUAL_64(2, x25);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFEUL, x26);
  CHECK_EQUAL_64(0x7FFFFFFFFFFFFFFFUL, x27);
  //  CHECK_EQUAL_64(0x8000000000000000UL, x28);
  CHECK_EQUAL_64(0x7FFFFFFFFFFFFC00UL, x29);
  CHECK_EQUAL_64(0x8000000000000400UL, x30);
}

TEST(fcvtnu) {
  INIT_V8();
  SETUP();

  START();
  __ Fmov(s0, 1.0);
  __ Fmov(s1, 1.1);
  __ Fmov(s2, 1.5);
  __ Fmov(s3, -1.5);
  __ Fmov(s4, kFP32PositiveInfinity);
  __ Fmov(s5, kFP32NegativeInfinity);
  __ Fmov(s6, 0xFFFFFF00);  // Largest float < UINT32_MAX.
  __ Fmov(s7, 1.5);
  __ Fmov(d8, 1.0);
  __ Fmov(d9, 1.1);
  __ Fmov(d10, 1.5);
  __ Fmov(d11, -1.5);
  __ Fmov(d12, kFP64PositiveInfinity);
  __ Fmov(d13, kFP64NegativeInfinity);
  __ Fmov(d14, 0xFFFFFFFE);
  __ Fmov(s16, 1.0);
  __ Fmov(s17, 1.1);
  __ Fmov(s19, -1.5);
  __ Fmov(s20, kFP32PositiveInfinity);
  __ Fmov(s21, kFP32NegativeInfinity);
  __ Fmov(s22, 0xFFFFFF0000000000UL);  // Largest float < UINT64_MAX.
  __ Fmov(d24, 1.1);
  __ Fmov(d25, 1.5);
  __ Fmov(d26, -1.5);
  __ Fmov(d27, kFP64PositiveInfinity);
  __ Fmov(d28, kFP64NegativeInfinity);
  __ Fmov(d29, 0xFFFFFFFFFFFFF800UL);  // Largest double < UINT64_MAX.
  __ Fmov(s30, 0x100000000UL);

  __ Fcvtnu(w0, s0);
  __ Fcvtnu(w1, s1);
  __ Fcvtnu(w2, s2);
  __ Fcvtnu(w3, s3);
  __ Fcvtnu(w4, s4);
  __ Fcvtnu(w5, s5);
  __ Fcvtnu(w6, s6);
  __ Fcvtnu(x7, s7);
  __ Fcvtnu(w8, d8);
  __ Fcvtnu(w9, d9);
  _
"""


```