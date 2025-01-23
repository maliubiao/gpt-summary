Response:
The user wants a summary of the provided C++ code snippet. The request asks for specific information, structured as follows:

1. **Functionality:** What does the code do?
2. **Torque Source:** Is it a Torque file? (Check file extension)
3. **JavaScript Relation:** If it's related to JavaScript, provide an example.
4. **Logic and I/O:**  If there's logical reasoning, give example inputs and outputs.
5. **Common Errors:**  Illustrate potential user programming mistakes.
6. **Overall Function:** A general summary.

Let's break down the code:

* **Includes:**  It doesn't show any `#include` statements, which is unusual for a C++ file, especially one testing functionality. This suggests it's part of a larger test framework where includes are handled elsewhere.
* **Test Functions:** The code contains several functions named `TEST(...)`. This is a strong indicator that it's using a testing framework (likely Google Test, common in Chromium projects).
* **Assertions:**  The code uses `CHECK_EQ`, `CHECK`, `CHECK!`, `CHECK_EQUAL_64`, etc. These are assertion macros, typical of testing frameworks. They verify expected outcomes.
* **Focus on Registers:** The tests heavily manipulate and check the properties of CPU registers (like `x0`, `w0`, `d0`, `s0`, `v0`, `b0`, `h0`, `q0`) in the ARM64 architecture. It checks size, type (general purpose, vector, floating-point), and relationships between different register sizes.
* **`CPURegList`:** The code tests the `CPURegList` class, which seems to be a utility for managing lists of CPU registers.
* **`Printf` and `PrintfNoPreserve`:**  The code tests formatted printing functionality, with variations for register preservation.
* **Barriers:** It tests memory barrier instructions (`DMB`, `DSB`, `ISB`).
* **CAS Instructions:** It tests Compare-and-Swap atomic instructions (`Cas`, `Casa`, `Casl`, `Casal`).

**Plan:**

1. Identify the primary purpose: Testing the ARM64 assembler in V8.
2. Note that it's C++, not Torque.
3. Highlight that the code tests low-level CPU register manipulation and related assembler instructions.
4. Since it's low-level, direct JavaScript examples are difficult. The connection is that this code *enables* the efficient execution of JavaScript on ARM64.
5. Focus on the types of tests: register property checks, `CPURegList` operations, `Printf` functionality, barrier instructions, and atomic operations.
6. For logic and I/O, use a simple register test as an example, showing the assertion.
7. For common errors, point out incorrect register usage (size mismatches, using a register without knowing its type).
8. Summarize that this section continues testing the ARM64 assembler in V8, focusing on register properties and memory/atomic operations.
```cpp
ormat(kFormat8H));
  CHECK_EQ(128U, RegisterSizeInBitsFromFormat(kFormat4S));
  CHECK_EQ(128U, RegisterSizeInBitsFromFormat(kFormat2D));

  CHECK_EQ(16, LaneCountFromFormat(kFormat16B));
  CHECK_EQ(8, LaneCountFromFormat(kFormat8B));
  CHECK_EQ(8, LaneCountFromFormat(kFormat8H));
  CHECK_EQ(4, LaneCountFromFormat(kFormat4H));
  CHECK_EQ(4, LaneCountFromFormat(kFormat4S));
  CHECK_EQ(2, LaneCountFromFormat(kFormat2S));
  CHECK_EQ(2, LaneCountFromFormat(kFormat2D));
  CHECK_EQ(1, LaneCountFromFormat(kFormat1D));
  CHECK_EQ(1, LaneCountFromFormat(kFormatB));
  CHECK_EQ(1, LaneCountFromFormat(kFormatH));
  CHECK_EQ(1, LaneCountFromFormat(kFormatS));
  CHECK_EQ(1, LaneCountFromFormat(kFormatD));

  CHECK(!IsVectorFormat(kFormatB));
  CHECK(!IsVectorFormat(kFormatH));
  CHECK(!IsVectorFormat(kFormatS));
  CHECK(!IsVectorFormat(kFormatD));
  CHECK(IsVectorFormat(kFormat16B));
  CHECK(IsVectorFormat(kFormat8B));
  CHECK(IsVectorFormat(kFormat8H));
  CHECK(IsVectorFormat(kFormat4H));
  CHECK(IsVectorFormat(kFormat4S));
  CHECK(IsVectorFormat(kFormat2S));
  CHECK(IsVectorFormat(kFormat2D));
  CHECK(IsVectorFormat(kFormat1D));

  CHECK(!d0.Is8B());
  CHECK(!d0.Is16B());
  CHECK(!d0.Is4H());
  CHECK(!d0.Is8H());
  CHECK(!d0.Is2S());
  CHECK(!d0.Is4S());
  CHECK(d0.Is1D());
  CHECK(!d0.Is1S());
  CHECK(!d0.Is1H());
  CHECK(!d0.Is1B());
  CHECK(!d0.IsVector());
  CHECK(d0.IsScalar());
  CHECK(d0.IsFPRegister());

  CHECK(!d0.IsW());
  CHECK(!d0.IsX());
  CHECK(d0.IsV());
  CHECK(!d0.IsB());
  CHECK(!d0.IsH());
  CHECK(!d0.IsS());
  CHECK(d0.IsD());
  CHECK(!d0.IsQ());

  CHECK(!s0.Is8B());
  CHECK(!s0.Is16B());
  CHECK(!s0.Is4H());
  CHECK(!s0.Is8H());
  CHECK(!s0.Is2S());
  CHECK(!s0.Is4S());
  CHECK(!s0.Is1D());
  CHECK(s0.Is1S());
  CHECK(!s0.Is1H());
  CHECK(!s0.Is1B());
  CHECK(!s0.IsVector());
  CHECK(s0.IsScalar());
  CHECK(s0.IsFPRegister());

  CHECK(!s0.IsW());
  CHECK(!s0.IsX());
  CHECK(s0.IsV());
  CHECK(!s0.IsB());
  CHECK(!s0.IsH());
  CHECK(s0.IsS());
  CHECK(!s0.IsD());
  CHECK(!s0.IsQ());

  CHECK(!h0.Is8B());
  CHECK(!h0.Is16B());
  CHECK(!h0.Is4H());
  CHECK(!h0.Is8H());
  CHECK(!h0.Is2S());
  CHECK(!h0.Is4S());
  CHECK(!h0.Is1D());
  CHECK(!h0.Is1S());
  CHECK(h0.Is1H());
  CHECK(!h0.Is1B());
  CHECK(!h0.IsVector());
  CHECK(h0.IsScalar());
  CHECK(!h0.IsFPRegister());

  CHECK(!h0.IsW());
  CHECK(!h0.IsX());
  CHECK(h0.IsV());
  CHECK(!h0.IsB());
  CHECK(h0.IsH());
  CHECK(!h0.IsS());
  CHECK(!h0.IsD());
  CHECK(!h0.IsQ());

  CHECK(!b0.Is8B());
  CHECK(!b0.Is16B());
  CHECK(!b0.Is4H());
  CHECK(!b0.Is8H());
  CHECK(!b0.Is2S());
  CHECK(!b0.Is4S());
  CHECK(!b0.Is1D());
  CHECK(!b0.Is1S());
  CHECK(!b0.Is1H());
  CHECK(b0.Is1B());
  CHECK(!b0.IsVector());
  CHECK(b0.IsScalar());
  CHECK(!b0.IsFPRegister());

  CHECK(!b0.IsW());
  CHECK(!b0.IsX());
  CHECK(b0.IsV());
  CHECK(b0.IsB());
  CHECK(!b0.IsH());
  CHECK(!b0.IsS());
  CHECK(!b0.IsD());
  CHECK(!b0.IsQ());

  CHECK(!q0.Is8B());
  CHECK(!q0.Is16B());
  CHECK(!q0.Is4H());
  CHECK(!q0.Is8H());
  CHECK(!q0.Is2S());
  CHECK(!q0.Is4S());
  CHECK(!q0.Is1D());
  CHECK(!q0.Is2D());
  CHECK(!q0.Is1S());
  CHECK(!q0.Is1H());
  CHECK(!q0.Is1B());
  CHECK(!q0.IsVector());
  CHECK(q0.IsScalar());
  CHECK(!q0.IsFPRegister());

  CHECK(!q0.IsW());
  CHECK(!q0.IsX());
  CHECK(q0.IsV());
  CHECK(!q0.IsB());
  CHECK(!q0.IsH());
  CHECK(!q0.IsS());
  CHECK(!q0.IsD());
  CHECK(q0.IsQ());

  CHECK(w0.IsW());
  CHECK(!w0.IsX());
  CHECK(!w0.IsV());
  CHECK(!w0.IsB());
  CHECK(!w0.IsH());
  CHECK(!w0.IsS());
  CHECK(!w0.IsD());
  CHECK(!w0.IsQ());

  CHECK(!x0.IsW());
  CHECK(x0.IsX());
  CHECK(!x0.IsV());
  CHECK(!x0.IsB());
  CHECK(!x0.IsH());
  CHECK(!x0.IsS());
  CHECK(!x0.IsD());
  CHECK(!x0.IsQ());

  CHECK(v0.V().IsV());
  CHECK(v0.B().IsB());
  CHECK(v0.H().IsH());
  CHECK(v0.D().IsD());
  CHECK(v0.S().IsS());
  CHECK(v0.Q().IsQ());

  VRegister test_8b(VRegister::Create(0, 64, 8));
  CHECK(test_8b.Is8B());
  CHECK(!test_8b.Is16B());
  CHECK(!test_8b.Is4H());
  CHECK(!test_8b.Is8H());
  CHECK(!test_8b.Is2S());
  CHECK(!test_8b.Is4S());
  CHECK(!test_8b.Is1D());
  CHECK(!test_8b.Is2D());
  CHECK(!test_8b.Is1H());
  CHECK(!test_8b.Is1B());
  CHECK(test_8b.IsVector());
  CHECK(!test_8b.IsScalar());
  CHECK(test_8b.IsFPRegister());

  VRegister test_16b(VRegister::Create(0, 128, 16));
  CHECK(!test_16b.Is8B());
  CHECK(test_16b.Is16B());
  CHECK(!test_16b.Is4H());
  CHECK(!test_16b.Is8H());
  CHECK(!test_16b.Is2S());
  CHECK(!test_16b.Is4S());
  CHECK(!test_16b.Is1D());
  CHECK(!test_16b.Is2D());
  CHECK(!test_16b.Is1H());
  CHECK(!test_16b.Is1B());
  CHECK(test_16b.IsVector());
  CHECK(!test_16b.IsScalar());
  CHECK(!test_16b.IsFPRegister());

  VRegister test_4h(VRegister::Create(0, 64, 4));
  CHECK(!test_4h.Is8B());
  CHECK(!test_4h.Is16B());
  CHECK(test_4h.Is4H());
  CHECK(!test_4h.Is8H());
  CHECK(!test_4h.Is2S());
  CHECK(!test_4h.Is4S());
  CHECK(!test_4h.Is1D());
  CHECK(!test_4h.Is2D());
  CHECK(!test_4h.Is1H());
  CHECK(!test_4h.Is1B());
  CHECK(test_4h.IsVector());
  CHECK(!test_4h.IsScalar());
  CHECK(test_4h.IsFPRegister());

  VRegister test_8h(VRegister::Create(0, 128, 8));
  CHECK(!test_8h.Is8B());
  CHECK(!test_8h.Is16B());
  CHECK(!test_8h.Is4H());
  CHECK(test_8h.Is8H());
  CHECK(!test_8h.Is2S());
  CHECK(!test_8h.Is4S());
  CHECK(!test_8h.Is1D());
  CHECK(!test_8h.Is2D());
  CHECK(!test_8h.Is1H());
  CHECK(!test_8h.Is1B());
  CHECK(test_8h.IsVector());
  CHECK(!test_8h.IsScalar());
  CHECK(!test_8h.IsFPRegister());

  VRegister test_2s(VRegister::Create(0, 64, 2));
  CHECK(!test_2s.Is8B());
  CHECK(!test_2s.Is16B());
  CHECK(!test_2s.Is4H());
  CHECK(!test_2s.Is8H());
  CHECK(test_2s.Is2S());
  CHECK(!test_2s.Is4S());
  CHECK(!test_2s.Is1D());
  CHECK(!test_2s.Is2D());
  CHECK(!test_2s.Is1H());
  CHECK(!test_2s.Is1B());
  CHECK(test_2s.IsVector());
  CHECK(!test_2s.IsScalar());
  CHECK(test_2s.IsFPRegister());

  VRegister test_4s(VRegister::Create(0, 128, 4));
  CHECK(!test_4s.Is8B());
  CHECK(!test_4s.Is16B());
  CHECK(!test_4s.Is4H());
  CHECK(!test_4s.Is8H());
  CHECK(!test_4s.Is2S());
  CHECK(test_4s.Is4S());
  CHECK(!test_4s.Is1D());
  CHECK(!test_4s.Is2D());
  CHECK(!test_4s.Is1S());
  CHECK(!test_4s.Is1H());
  CHECK(!test_4s.Is1B());
  CHECK(test_4s.IsVector());
  CHECK(!test_4s.IsScalar());
  CHECK(!test_4s.IsFPRegister());

  VRegister test_1d(VRegister::Create(0, 64, 1));
  CHECK(!test_1d.Is8B());
  CHECK(!test_1d.Is16B());
  CHECK(!test_1d.Is4H());
  CHECK(!test_1d.Is8H());
  CHECK(!test_1d.Is2S());
  CHECK(!test_1d.Is4S());
  CHECK(test_1d.Is1D());
  CHECK(!test_1d.Is2D());
  CHECK(!test_1d.Is1S());
  CHECK(!test_1d.Is1H());
  CHECK(!test_1d.Is1B());
  CHECK(!test_1d.IsVector());
  CHECK(test_1d.IsScalar());
  CHECK(test_1d.IsFPRegister());

  VRegister test_2d(VRegister::Create(0, 128, 2));
  CHECK(!test_2d.Is8B());
  CHECK(!test_2d.Is16B());
  CHECK(!test_2d.Is4H());
  CHECK(!test_2d.Is8H());
  CHECK(!test_2d.Is2S());
  CHECK(!test_2d.Is4S());
  CHECK(!test_2d.Is1D());
  CHECK(test_2d.Is2D());
  CHECK(!test_2d.Is1H());
  CHECK(!test_2d.Is1B());
  CHECK(test_2d.IsVector());
  CHECK(!test_2d.IsScalar());
  CHECK(!test_2d.IsFPRegister());

  VRegister test_1s(VRegister::Create(0, 32, 1));
  CHECK(!test_1s.Is8B());
  CHECK(!test_1s.Is16B());
  CHECK(!test_1s.Is4H());
  CHECK(!test_1s.Is8H());
  CHECK(!test_1s.Is2S());
  CHECK(!test_1s.Is4S());
  CHECK(!test_1s.Is1D());
  CHECK(!test_1s.Is2D());
  CHECK(test_1s.Is1S());
  CHECK(!test_1s.Is1H());
  CHECK(!test_1s.Is1B());
  CHECK(!test_1s.IsVector());
  CHECK(test_1s.IsScalar());
  CHECK(test_1s.IsFPRegister());

  VRegister test_1h(VRegister::Create(0, 16, 1));
  CHECK(!test_1h.Is8B());
  CHECK(!test_1h.Is16B());
  CHECK(!test_1h.Is4H());
  CHECK(!test_1h.Is8H());
  CHECK(!test_1h.Is2S());
  CHECK(!test_1h.Is4S());
  CHECK(!test_1h.Is1D());
  CHECK(!test_1h.Is2D());
  CHECK(!test_1h.Is1S());
  CHECK(test_1h.Is1H());
  CHECK(!test_1h.Is1B());
  CHECK(!test_1h.IsVector());
  CHECK(test_1h.IsScalar());
  CHECK(!test_1h.IsFPRegister());

  VRegister test_1b(VRegister::Create(0, 8, 1));
  CHECK(!test_1b.Is8B());
  CHECK(!test_1b.Is16B());
  CHECK(!test_1b.Is4H());
  CHECK(!test_1b.Is8H());
  CHECK(!test_1b.Is2S());
  CHECK(!test_1b.Is4S());
  CHECK(!test_1b.Is1D());
  CHECK(!test_1b.Is2D());
  CHECK(!test_1b.Is1S());
  CHECK(!test_1b.Is1H());
  CHECK(test_1b.Is1B());
  CHECK(!test_1b.IsVector());
  CHECK(test_1b.IsScalar());
  CHECK(!test_1b.IsFPRegister());

  VRegister test_breg_from_code(VRegister::BRegFromCode(0));
  CHECK_EQ(test_breg_from_code.SizeInBits(), kBRegSizeInBits);

  VRegister test_hreg_from_code(VRegister::HRegFromCode(0));
  CHECK_EQ(test_hreg_from_code.SizeInBits(), kHRegSizeInBits);

  VRegister test_sreg_from_code(VRegister::SRegFromCode(0));
  CHECK_EQ(test_sreg_from_code.SizeInBits(), kSRegSizeInBits);

  VRegister test_dreg_from_code(VRegister::DRegFromCode(0));
  CHECK_EQ(test_dreg_from_code.SizeInBits(), kDRegSizeInBits);

  VRegister test_qreg_from_code(VRegister::QRegFromCode(0));
  CHECK_EQ(test_qreg_from_code.SizeInBits(), kQRegSizeInBits);

  VRegister test_vreg_from_code(VRegister::VRegFromCode(0));
  CHECK_EQ(test_vreg_from_code.SizeInBits(), kVRegSizeInBits);

  VRegister test_v8b(VRegister::VRegFromCode(31).V8B());
  CHECK_EQ(test_v8b.code(), 31);
  CHECK_EQ(test_v8b.SizeInBits(), kDRegSizeInBits);
  CHECK(test_v8b.IsLaneSizeB());
  CHECK(!test_v8b.IsLaneSizeH());
  CHECK(!test_v8b.IsLaneSizeS());
  CHECK(!test_v8b.IsLaneSizeD());
  CHECK_EQ(test_v8b.LaneSizeInBits(), 8U);

  VRegister test_v16b(VRegister::VRegFromCode(31).V16B());
  CHECK_EQ(test_v16b.code(), 31);
  CHECK_EQ(test_v16b.SizeInBits(), kQRegSizeInBits);
  CHECK(test_v16b.IsLaneSizeB());
  CHECK(!test_v16b.IsLaneSizeH());
  CHECK(!test_v16b.IsLaneSizeS());
  CHECK(!test_v16b.IsLaneSizeD());
  CHECK_EQ(test_v16b.LaneSizeInBits(), 8U);

  VRegister test_v4h(VRegister::VRegFromCode(31).V4H());
  CHECK_EQ(test_v4h.code(), 31);
  CHECK_EQ(test_v4h.SizeInBits(), kDRegSizeInBits);
  CHECK(!test_v4h.IsLaneSizeB());
  CHECK(test_v4h.IsLaneSizeH());
  CHECK(!test_v4h.IsLaneSizeS());
  CHECK(!test_v4h.IsLaneSizeD());
  CHECK_EQ(test_v4h.LaneSizeInBits(), 16U);

  VRegister test_v8h(VRegister::VRegFromCode(31).V8H());
  CHECK_EQ(test_v8h.code(), 31);
  CHECK_EQ(test_8h.SizeInBits(), kQRegSizeInBits);
  CHECK(!test_v8h.IsLaneSizeB());
  CHECK(test_v8h.IsLaneSizeH());
  CHECK(!test_v8h.IsLaneSizeS());
  CHECK(!test_v8h.IsLaneSizeD());
  CHECK_EQ(test_v8h.LaneSizeInBits(), 16U);

  VRegister test_v2s(VRegister::VRegFromCode(31).V2S());
  CHECK_EQ(test_v2s.code(), 31);
  CHECK_EQ(test_v2s.SizeInBits(), kDRegSizeInBits);
  CHECK(!test_v2s.IsLaneSizeB());
  CHECK(!test_v2s.IsLaneSizeH());
  CHECK(test_v2s.IsLaneSizeS());
  CHECK(!test_v2s.IsLaneSizeD());
  CHECK_EQ(test_v2s.LaneSizeInBits(), 32U);

  VRegister test_v4s(VRegister::VRegFromCode(31).V4S());
  CHECK_EQ(test_v4s.code(), 31);
  CHECK_EQ(test_v4s.SizeInBits(), kQRegSizeInBits);
  CHECK(!test_v4s.IsLaneSizeB());
  CHECK(!test_v4s.IsLaneSizeH());
  CHECK(test_v4s.IsLaneSizeS());
  CHECK(!test_v4s.IsLaneSizeD());
  CHECK_EQ(test_v4s.LaneSizeInBits(), 32U);

  VRegister test_v1d(VRegister::VRegFromCode(31).V1D());
  CHECK_EQ(test_v1d.code(), 31);
  CHECK_EQ(test_v1d.SizeInBits(), kDRegSizeInBits);
  CHECK(!test_v1d.IsLaneSizeB());
  CHECK(!test_v1d.IsLaneSizeH());
  CHECK(!test_v1d.IsLaneSizeS());
  CHECK(test_v1d.IsLaneSizeD());
  CHECK_EQ(test_v1d.LaneSizeInBits(), 64U);

  VRegister test_v2d(VRegister::VRegFromCode(31).V2D());
  CHECK_EQ(test_v2d.code(), 31);
  CHECK_EQ(test_v2d.SizeInBits(), kQRegSizeInBits);
  CHECK(!test_v2d.IsLaneSizeB());
  CHECK(!test_v2d.IsLaneSizeH());
  CHECK(!test_v2d.IsLaneSizeS());
  CHECK(test_v2d.IsLaneSizeD());
  CHECK_EQ(test_v2d.LaneSizeInBits(), 64U);

  CHECK(test_v1d.IsSameFormat(test_v1d));
  CHECK(test_v2d.IsSameFormat(test_v2d));
  CHECK(!test_v1d.IsSameFormat(test_v2d));
  CHECK(!test_v2s.IsSameFormat(test_v2d));
}

TEST(isvalid) {
  // This test doesn't generate any code, but it verifies some invariants
  // related to IsValid().
  CHECK(!NoReg.is_valid());
  CHECK(!NoVReg.is_valid());
  CHECK(!NoCPUReg.is_valid());

  CHECK(x0.is_valid());
  CHECK(w0.is_valid());
  CHECK(x30.is_valid());
  CHECK(w30.is_valid());
  CHECK(xzr.is_valid());
  CHECK(wzr.is_valid());

  CHECK(sp.is_valid());
  CHECK(wsp.is_valid());

  CHECK(d0.is_valid());
  CHECK(s0.is_valid());
  CHECK(d31.is_valid());
  CHECK(s31.is_valid());

  CHECK(x0.IsRegister());
  CHECK(w0.IsRegister());
  CHECK(xzr.IsRegister());
  CHECK(wzr.IsRegister());
  CHECK(sp.IsRegister());
  CHECK(wsp.IsRegister());
  CHECK(!x0.IsVRegister());
  CHECK(!w0.IsVRegister());
  CHECK(!xzr.IsVRegister());
  CHECK(!wzr.IsVRegister());
  CHECK(!sp.IsVRegister());
  CHECK(!wsp.IsVRegister());

  CHECK(d0.IsVRegister());
  CHECK(s0.IsVRegister());
  CHECK(!d0.IsRegister());
  CHECK(!s0.IsRegister());

  // Test the same as before, but using CPURegister types. This shouldn't make
  // any difference.
  CHECK(static_cast<CPURegister>(x0).is_valid());
  CHECK(static_cast<CPURegister>(w0).is_valid());
  CHECK(static_cast<CPURegister>(x30).is_valid());
  CHECK(static_cast<CPURegister>(w30).is_valid());
  CHECK(static_cast<CPURegister>(xzr).is_valid());
  CHECK(static_cast<CPURegister>(wzr).is_valid());

  CHECK(static_cast<CPURegister>(sp).is_valid());
  CHECK(static_cast<CPURegister>(wsp).is_valid());

  CHECK(static_cast<CPURegister>(d0).is_valid());
  CHECK(static_cast<CPURegister>(s0).is_valid());
  CHECK(static_cast<CPURegister>(d31).is_valid());
  CHECK(static_cast<CPURegister>(s31).is_valid());

  CHECK(static_cast<CPURegister>(x0).IsRegister());
  CHECK(static_cast<CPURegister>(w0).IsRegister());
  CHECK(static_cast<CPURegister>(xzr).IsRegister());
  CHECK(static_cast<CPURegister>(wzr).IsRegister());
  CHECK(static_cast<CPURegister>(sp).IsRegister());
  CHECK(static_cast<CPURegister>(wsp).IsRegister());
  CHECK(!static_cast<CPURegister>(x0).IsVRegister());
  CHECK(!static_cast<CPURegister>(w0).IsVRegister());
  CHECK(!static_cast<CPURegister>(xzr).IsVRegister());
  CHECK(!static_cast<CPURegister>(wzr).IsVRegister());
  CHECK(!static_cast<CPURegister>(sp).IsVRegister());
  CHECK(!static_cast<CPURegister>(wsp).IsVRegister());

  CHECK(static_cast<CPURegister>(d0).IsVRegister());
  CHECK(static_cast<CPURegister>(s0).IsVRegister());
  CHECK(!static_cast<CPURegister>(d0).IsRegister());
  CHECK(!static_cast<CPURegister>(s0).IsRegister());
}

TEST(areconsecutive) {
  // This test generates no code; it just checks that AreConsecutive works.
  CHECK(AreConsecutive(b0, NoVReg));
  CHECK(AreConsecutive(b1, b2));
  CHECK(AreConsecutive(b3, b4, b5));
  CHECK(AreConsecutive(b6, b7, b8, b9));
  CHECK(AreConsecutive(h10, NoVReg));
  CHECK(AreConsecutive(h11, h12));
  CHECK(AreConsecutive(h13, h14, h15));
  CHECK(AreConsecutive(h16, h17, h18, h19));
  CHECK(AreConsecutive(s20, NoVReg));
  CHECK(AreConsecutive(s21, s22));
  CHECK(AreConsecutive(s23, s24, s25));
  CHECK(AreConsecutive(s26, s27, s28, s29));
  CHECK(AreConsecutive(d30, NoVReg));
  CHECK(AreConsecutive(d31, d0));
  CHECK(AreConsecutive(d1, d2, d3));
  CHECK(AreConsecutive(d4, d5, d6, d7));
  CHECK(AreConsecutive(q8, NoVReg));
  CHECK(AreConsecutive(q9, q10));
  CHECK(AreConsecutive(q11, q12, q13));
  CHECK(AreConsecutive(q14, q15, q16, q17));
  CHECK(AreConsecutive(v18, NoVReg));
  CHECK(AreConsecutive(v19, v20));
  CHECK(AreConsecutive(v21, v22, v23));
  CHECK(AreConsecutive(v24, v25, v26, v27));
  CHECK(AreConsecutive(b29, h30));
  CHECK(AreConsecutive(s31, d0, q1));
  CHECK(AreConsecutive(v2, b3, h4, s5));

  CHECK(AreConsecutive(b26, b27, NoVReg, NoVReg));
  CHECK(AreConsecutive(h28, NoVReg, NoVReg, NoVReg));

  CHECK(!AreConsecutive(b0, b2));
  CHECK(!AreConsecutive(h1, h0));
  CHECK(!AreConsecutive(s31, s1));
  CHECK(!AreConsecutive(d12, d12));
  CHECK(!AreConsecutive(q31, q1));

  CHECK(!AreConsecutive(b5, b4, b3));
  CHECK(!AreConsecutive(h15, h16, h15, h14));
  CHECK(!AreConsecutive(s25, s24, s23, s22));
  CHECK(!AreConsecutive(d5, d6, d7, d6));
  CHECK(!AreConsecutive(q15, q16, q17, q6));

  CHECK(!AreConsecutive(b0, b1, b3));
  CHECK(!AreConsecutive(h4, h5, h6, h6));
  CHECK(!AreConsecutive(d15, d16, d18, NoVReg));
  CHECK(!AreConsecutive(s28, s30, NoVReg, NoVReg));
}

TEST(cpureglist_utils_x) {
  // This test doesn't generate any code, but it verifies the behaviour of
  // the CPURegList utility methods.

  // Test a list of X registers.
  CPURegList test(x0, x1, x2, x3);

  CHECK(test.IncludesAliasOf(x0));
  CHECK(test.IncludesAliasOf(x1));
  CHECK(test.IncludesAliasOf(x2));
  CHECK(test.IncludesAliasOf(x3));
  CHECK(test.IncludesAliasOf(w0));
  CHECK(test.IncludesAliasOf(w1));
  CHECK(test.IncludesAliasOf(w2));
  CHECK(test.IncludesAliasOf(w3));

  CHECK(!test.IncludesAliasOf(x4));
  CHECK(!test.IncludesAliasOf(x30));
  CHECK(!test.IncludesAlias
### 提示词
```
这是目录为v8/test/cctest/test-assembler-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第13部分，共15部分，请归纳一下它的功能
```

### 源代码
```cpp
ormat(kFormat8H));
  CHECK_EQ(128U, RegisterSizeInBitsFromFormat(kFormat4S));
  CHECK_EQ(128U, RegisterSizeInBitsFromFormat(kFormat2D));

  CHECK_EQ(16, LaneCountFromFormat(kFormat16B));
  CHECK_EQ(8, LaneCountFromFormat(kFormat8B));
  CHECK_EQ(8, LaneCountFromFormat(kFormat8H));
  CHECK_EQ(4, LaneCountFromFormat(kFormat4H));
  CHECK_EQ(4, LaneCountFromFormat(kFormat4S));
  CHECK_EQ(2, LaneCountFromFormat(kFormat2S));
  CHECK_EQ(2, LaneCountFromFormat(kFormat2D));
  CHECK_EQ(1, LaneCountFromFormat(kFormat1D));
  CHECK_EQ(1, LaneCountFromFormat(kFormatB));
  CHECK_EQ(1, LaneCountFromFormat(kFormatH));
  CHECK_EQ(1, LaneCountFromFormat(kFormatS));
  CHECK_EQ(1, LaneCountFromFormat(kFormatD));

  CHECK(!IsVectorFormat(kFormatB));
  CHECK(!IsVectorFormat(kFormatH));
  CHECK(!IsVectorFormat(kFormatS));
  CHECK(!IsVectorFormat(kFormatD));
  CHECK(IsVectorFormat(kFormat16B));
  CHECK(IsVectorFormat(kFormat8B));
  CHECK(IsVectorFormat(kFormat8H));
  CHECK(IsVectorFormat(kFormat4H));
  CHECK(IsVectorFormat(kFormat4S));
  CHECK(IsVectorFormat(kFormat2S));
  CHECK(IsVectorFormat(kFormat2D));
  CHECK(IsVectorFormat(kFormat1D));

  CHECK(!d0.Is8B());
  CHECK(!d0.Is16B());
  CHECK(!d0.Is4H());
  CHECK(!d0.Is8H());
  CHECK(!d0.Is2S());
  CHECK(!d0.Is4S());
  CHECK(d0.Is1D());
  CHECK(!d0.Is1S());
  CHECK(!d0.Is1H());
  CHECK(!d0.Is1B());
  CHECK(!d0.IsVector());
  CHECK(d0.IsScalar());
  CHECK(d0.IsFPRegister());

  CHECK(!d0.IsW());
  CHECK(!d0.IsX());
  CHECK(d0.IsV());
  CHECK(!d0.IsB());
  CHECK(!d0.IsH());
  CHECK(!d0.IsS());
  CHECK(d0.IsD());
  CHECK(!d0.IsQ());

  CHECK(!s0.Is8B());
  CHECK(!s0.Is16B());
  CHECK(!s0.Is4H());
  CHECK(!s0.Is8H());
  CHECK(!s0.Is2S());
  CHECK(!s0.Is4S());
  CHECK(!s0.Is1D());
  CHECK(s0.Is1S());
  CHECK(!s0.Is1H());
  CHECK(!s0.Is1B());
  CHECK(!s0.IsVector());
  CHECK(s0.IsScalar());
  CHECK(s0.IsFPRegister());

  CHECK(!s0.IsW());
  CHECK(!s0.IsX());
  CHECK(s0.IsV());
  CHECK(!s0.IsB());
  CHECK(!s0.IsH());
  CHECK(s0.IsS());
  CHECK(!s0.IsD());
  CHECK(!s0.IsQ());

  CHECK(!h0.Is8B());
  CHECK(!h0.Is16B());
  CHECK(!h0.Is4H());
  CHECK(!h0.Is8H());
  CHECK(!h0.Is2S());
  CHECK(!h0.Is4S());
  CHECK(!h0.Is1D());
  CHECK(!h0.Is1S());
  CHECK(h0.Is1H());
  CHECK(!h0.Is1B());
  CHECK(!h0.IsVector());
  CHECK(h0.IsScalar());
  CHECK(!h0.IsFPRegister());

  CHECK(!h0.IsW());
  CHECK(!h0.IsX());
  CHECK(h0.IsV());
  CHECK(!h0.IsB());
  CHECK(h0.IsH());
  CHECK(!h0.IsS());
  CHECK(!h0.IsD());
  CHECK(!h0.IsQ());

  CHECK(!b0.Is8B());
  CHECK(!b0.Is16B());
  CHECK(!b0.Is4H());
  CHECK(!b0.Is8H());
  CHECK(!b0.Is2S());
  CHECK(!b0.Is4S());
  CHECK(!b0.Is1D());
  CHECK(!b0.Is1S());
  CHECK(!b0.Is1H());
  CHECK(b0.Is1B());
  CHECK(!b0.IsVector());
  CHECK(b0.IsScalar());
  CHECK(!b0.IsFPRegister());

  CHECK(!b0.IsW());
  CHECK(!b0.IsX());
  CHECK(b0.IsV());
  CHECK(b0.IsB());
  CHECK(!b0.IsH());
  CHECK(!b0.IsS());
  CHECK(!b0.IsD());
  CHECK(!b0.IsQ());

  CHECK(!q0.Is8B());
  CHECK(!q0.Is16B());
  CHECK(!q0.Is4H());
  CHECK(!q0.Is8H());
  CHECK(!q0.Is2S());
  CHECK(!q0.Is4S());
  CHECK(!q0.Is1D());
  CHECK(!q0.Is2D());
  CHECK(!q0.Is1S());
  CHECK(!q0.Is1H());
  CHECK(!q0.Is1B());
  CHECK(!q0.IsVector());
  CHECK(q0.IsScalar());
  CHECK(!q0.IsFPRegister());

  CHECK(!q0.IsW());
  CHECK(!q0.IsX());
  CHECK(q0.IsV());
  CHECK(!q0.IsB());
  CHECK(!q0.IsH());
  CHECK(!q0.IsS());
  CHECK(!q0.IsD());
  CHECK(q0.IsQ());

  CHECK(w0.IsW());
  CHECK(!w0.IsX());
  CHECK(!w0.IsV());
  CHECK(!w0.IsB());
  CHECK(!w0.IsH());
  CHECK(!w0.IsS());
  CHECK(!w0.IsD());
  CHECK(!w0.IsQ());

  CHECK(!x0.IsW());
  CHECK(x0.IsX());
  CHECK(!x0.IsV());
  CHECK(!x0.IsB());
  CHECK(!x0.IsH());
  CHECK(!x0.IsS());
  CHECK(!x0.IsD());
  CHECK(!x0.IsQ());

  CHECK(v0.V().IsV());
  CHECK(v0.B().IsB());
  CHECK(v0.H().IsH());
  CHECK(v0.D().IsD());
  CHECK(v0.S().IsS());
  CHECK(v0.Q().IsQ());

  VRegister test_8b(VRegister::Create(0, 64, 8));
  CHECK(test_8b.Is8B());
  CHECK(!test_8b.Is16B());
  CHECK(!test_8b.Is4H());
  CHECK(!test_8b.Is8H());
  CHECK(!test_8b.Is2S());
  CHECK(!test_8b.Is4S());
  CHECK(!test_8b.Is1D());
  CHECK(!test_8b.Is2D());
  CHECK(!test_8b.Is1H());
  CHECK(!test_8b.Is1B());
  CHECK(test_8b.IsVector());
  CHECK(!test_8b.IsScalar());
  CHECK(test_8b.IsFPRegister());

  VRegister test_16b(VRegister::Create(0, 128, 16));
  CHECK(!test_16b.Is8B());
  CHECK(test_16b.Is16B());
  CHECK(!test_16b.Is4H());
  CHECK(!test_16b.Is8H());
  CHECK(!test_16b.Is2S());
  CHECK(!test_16b.Is4S());
  CHECK(!test_16b.Is1D());
  CHECK(!test_16b.Is2D());
  CHECK(!test_16b.Is1H());
  CHECK(!test_16b.Is1B());
  CHECK(test_16b.IsVector());
  CHECK(!test_16b.IsScalar());
  CHECK(!test_16b.IsFPRegister());

  VRegister test_4h(VRegister::Create(0, 64, 4));
  CHECK(!test_4h.Is8B());
  CHECK(!test_4h.Is16B());
  CHECK(test_4h.Is4H());
  CHECK(!test_4h.Is8H());
  CHECK(!test_4h.Is2S());
  CHECK(!test_4h.Is4S());
  CHECK(!test_4h.Is1D());
  CHECK(!test_4h.Is2D());
  CHECK(!test_4h.Is1H());
  CHECK(!test_4h.Is1B());
  CHECK(test_4h.IsVector());
  CHECK(!test_4h.IsScalar());
  CHECK(test_4h.IsFPRegister());

  VRegister test_8h(VRegister::Create(0, 128, 8));
  CHECK(!test_8h.Is8B());
  CHECK(!test_8h.Is16B());
  CHECK(!test_8h.Is4H());
  CHECK(test_8h.Is8H());
  CHECK(!test_8h.Is2S());
  CHECK(!test_8h.Is4S());
  CHECK(!test_8h.Is1D());
  CHECK(!test_8h.Is2D());
  CHECK(!test_8h.Is1H());
  CHECK(!test_8h.Is1B());
  CHECK(test_8h.IsVector());
  CHECK(!test_8h.IsScalar());
  CHECK(!test_8h.IsFPRegister());

  VRegister test_2s(VRegister::Create(0, 64, 2));
  CHECK(!test_2s.Is8B());
  CHECK(!test_2s.Is16B());
  CHECK(!test_2s.Is4H());
  CHECK(!test_2s.Is8H());
  CHECK(test_2s.Is2S());
  CHECK(!test_2s.Is4S());
  CHECK(!test_2s.Is1D());
  CHECK(!test_2s.Is2D());
  CHECK(!test_2s.Is1H());
  CHECK(!test_2s.Is1B());
  CHECK(test_2s.IsVector());
  CHECK(!test_2s.IsScalar());
  CHECK(test_2s.IsFPRegister());

  VRegister test_4s(VRegister::Create(0, 128, 4));
  CHECK(!test_4s.Is8B());
  CHECK(!test_4s.Is16B());
  CHECK(!test_4s.Is4H());
  CHECK(!test_4s.Is8H());
  CHECK(!test_4s.Is2S());
  CHECK(test_4s.Is4S());
  CHECK(!test_4s.Is1D());
  CHECK(!test_4s.Is2D());
  CHECK(!test_4s.Is1S());
  CHECK(!test_4s.Is1H());
  CHECK(!test_4s.Is1B());
  CHECK(test_4s.IsVector());
  CHECK(!test_4s.IsScalar());
  CHECK(!test_4s.IsFPRegister());

  VRegister test_1d(VRegister::Create(0, 64, 1));
  CHECK(!test_1d.Is8B());
  CHECK(!test_1d.Is16B());
  CHECK(!test_1d.Is4H());
  CHECK(!test_1d.Is8H());
  CHECK(!test_1d.Is2S());
  CHECK(!test_1d.Is4S());
  CHECK(test_1d.Is1D());
  CHECK(!test_1d.Is2D());
  CHECK(!test_1d.Is1S());
  CHECK(!test_1d.Is1H());
  CHECK(!test_1d.Is1B());
  CHECK(!test_1d.IsVector());
  CHECK(test_1d.IsScalar());
  CHECK(test_1d.IsFPRegister());

  VRegister test_2d(VRegister::Create(0, 128, 2));
  CHECK(!test_2d.Is8B());
  CHECK(!test_2d.Is16B());
  CHECK(!test_2d.Is4H());
  CHECK(!test_2d.Is8H());
  CHECK(!test_2d.Is2S());
  CHECK(!test_2d.Is4S());
  CHECK(!test_2d.Is1D());
  CHECK(test_2d.Is2D());
  CHECK(!test_2d.Is1H());
  CHECK(!test_2d.Is1B());
  CHECK(test_2d.IsVector());
  CHECK(!test_2d.IsScalar());
  CHECK(!test_2d.IsFPRegister());

  VRegister test_1s(VRegister::Create(0, 32, 1));
  CHECK(!test_1s.Is8B());
  CHECK(!test_1s.Is16B());
  CHECK(!test_1s.Is4H());
  CHECK(!test_1s.Is8H());
  CHECK(!test_1s.Is2S());
  CHECK(!test_1s.Is4S());
  CHECK(!test_1s.Is1D());
  CHECK(!test_1s.Is2D());
  CHECK(test_1s.Is1S());
  CHECK(!test_1s.Is1H());
  CHECK(!test_1s.Is1B());
  CHECK(!test_1s.IsVector());
  CHECK(test_1s.IsScalar());
  CHECK(test_1s.IsFPRegister());

  VRegister test_1h(VRegister::Create(0, 16, 1));
  CHECK(!test_1h.Is8B());
  CHECK(!test_1h.Is16B());
  CHECK(!test_1h.Is4H());
  CHECK(!test_1h.Is8H());
  CHECK(!test_1h.Is2S());
  CHECK(!test_1h.Is4S());
  CHECK(!test_1h.Is1D());
  CHECK(!test_1h.Is2D());
  CHECK(!test_1h.Is1S());
  CHECK(test_1h.Is1H());
  CHECK(!test_1h.Is1B());
  CHECK(!test_1h.IsVector());
  CHECK(test_1h.IsScalar());
  CHECK(!test_1h.IsFPRegister());

  VRegister test_1b(VRegister::Create(0, 8, 1));
  CHECK(!test_1b.Is8B());
  CHECK(!test_1b.Is16B());
  CHECK(!test_1b.Is4H());
  CHECK(!test_1b.Is8H());
  CHECK(!test_1b.Is2S());
  CHECK(!test_1b.Is4S());
  CHECK(!test_1b.Is1D());
  CHECK(!test_1b.Is2D());
  CHECK(!test_1b.Is1S());
  CHECK(!test_1b.Is1H());
  CHECK(test_1b.Is1B());
  CHECK(!test_1b.IsVector());
  CHECK(test_1b.IsScalar());
  CHECK(!test_1b.IsFPRegister());

  VRegister test_breg_from_code(VRegister::BRegFromCode(0));
  CHECK_EQ(test_breg_from_code.SizeInBits(), kBRegSizeInBits);

  VRegister test_hreg_from_code(VRegister::HRegFromCode(0));
  CHECK_EQ(test_hreg_from_code.SizeInBits(), kHRegSizeInBits);

  VRegister test_sreg_from_code(VRegister::SRegFromCode(0));
  CHECK_EQ(test_sreg_from_code.SizeInBits(), kSRegSizeInBits);

  VRegister test_dreg_from_code(VRegister::DRegFromCode(0));
  CHECK_EQ(test_dreg_from_code.SizeInBits(), kDRegSizeInBits);

  VRegister test_qreg_from_code(VRegister::QRegFromCode(0));
  CHECK_EQ(test_qreg_from_code.SizeInBits(), kQRegSizeInBits);

  VRegister test_vreg_from_code(VRegister::VRegFromCode(0));
  CHECK_EQ(test_vreg_from_code.SizeInBits(), kVRegSizeInBits);

  VRegister test_v8b(VRegister::VRegFromCode(31).V8B());
  CHECK_EQ(test_v8b.code(), 31);
  CHECK_EQ(test_v8b.SizeInBits(), kDRegSizeInBits);
  CHECK(test_v8b.IsLaneSizeB());
  CHECK(!test_v8b.IsLaneSizeH());
  CHECK(!test_v8b.IsLaneSizeS());
  CHECK(!test_v8b.IsLaneSizeD());
  CHECK_EQ(test_v8b.LaneSizeInBits(), 8U);

  VRegister test_v16b(VRegister::VRegFromCode(31).V16B());
  CHECK_EQ(test_v16b.code(), 31);
  CHECK_EQ(test_v16b.SizeInBits(), kQRegSizeInBits);
  CHECK(test_v16b.IsLaneSizeB());
  CHECK(!test_v16b.IsLaneSizeH());
  CHECK(!test_v16b.IsLaneSizeS());
  CHECK(!test_v16b.IsLaneSizeD());
  CHECK_EQ(test_v16b.LaneSizeInBits(), 8U);

  VRegister test_v4h(VRegister::VRegFromCode(31).V4H());
  CHECK_EQ(test_v4h.code(), 31);
  CHECK_EQ(test_v4h.SizeInBits(), kDRegSizeInBits);
  CHECK(!test_v4h.IsLaneSizeB());
  CHECK(test_v4h.IsLaneSizeH());
  CHECK(!test_v4h.IsLaneSizeS());
  CHECK(!test_v4h.IsLaneSizeD());
  CHECK_EQ(test_v4h.LaneSizeInBits(), 16U);

  VRegister test_v8h(VRegister::VRegFromCode(31).V8H());
  CHECK_EQ(test_v8h.code(), 31);
  CHECK_EQ(test_v8h.SizeInBits(), kQRegSizeInBits);
  CHECK(!test_v8h.IsLaneSizeB());
  CHECK(test_v8h.IsLaneSizeH());
  CHECK(!test_v8h.IsLaneSizeS());
  CHECK(!test_v8h.IsLaneSizeD());
  CHECK_EQ(test_v8h.LaneSizeInBits(), 16U);

  VRegister test_v2s(VRegister::VRegFromCode(31).V2S());
  CHECK_EQ(test_v2s.code(), 31);
  CHECK_EQ(test_v2s.SizeInBits(), kDRegSizeInBits);
  CHECK(!test_v2s.IsLaneSizeB());
  CHECK(!test_v2s.IsLaneSizeH());
  CHECK(test_v2s.IsLaneSizeS());
  CHECK(!test_v2s.IsLaneSizeD());
  CHECK_EQ(test_v2s.LaneSizeInBits(), 32U);

  VRegister test_v4s(VRegister::VRegFromCode(31).V4S());
  CHECK_EQ(test_v4s.code(), 31);
  CHECK_EQ(test_v4s.SizeInBits(), kQRegSizeInBits);
  CHECK(!test_v4s.IsLaneSizeB());
  CHECK(!test_v4s.IsLaneSizeH());
  CHECK(test_v4s.IsLaneSizeS());
  CHECK(!test_v4s.IsLaneSizeD());
  CHECK_EQ(test_v4s.LaneSizeInBits(), 32U);

  VRegister test_v1d(VRegister::VRegFromCode(31).V1D());
  CHECK_EQ(test_v1d.code(), 31);
  CHECK_EQ(test_v1d.SizeInBits(), kDRegSizeInBits);
  CHECK(!test_v1d.IsLaneSizeB());
  CHECK(!test_v1d.IsLaneSizeH());
  CHECK(!test_v1d.IsLaneSizeS());
  CHECK(test_v1d.IsLaneSizeD());
  CHECK_EQ(test_v1d.LaneSizeInBits(), 64U);

  VRegister test_v2d(VRegister::VRegFromCode(31).V2D());
  CHECK_EQ(test_v2d.code(), 31);
  CHECK_EQ(test_v2d.SizeInBits(), kQRegSizeInBits);
  CHECK(!test_v2d.IsLaneSizeB());
  CHECK(!test_v2d.IsLaneSizeH());
  CHECK(!test_v2d.IsLaneSizeS());
  CHECK(test_v2d.IsLaneSizeD());
  CHECK_EQ(test_v2d.LaneSizeInBits(), 64U);

  CHECK(test_v1d.IsSameFormat(test_v1d));
  CHECK(test_v2d.IsSameFormat(test_v2d));
  CHECK(!test_v1d.IsSameFormat(test_v2d));
  CHECK(!test_v2s.IsSameFormat(test_v2d));
}

TEST(isvalid) {
  // This test doesn't generate any code, but it verifies some invariants
  // related to IsValid().
  CHECK(!NoReg.is_valid());
  CHECK(!NoVReg.is_valid());
  CHECK(!NoCPUReg.is_valid());

  CHECK(x0.is_valid());
  CHECK(w0.is_valid());
  CHECK(x30.is_valid());
  CHECK(w30.is_valid());
  CHECK(xzr.is_valid());
  CHECK(wzr.is_valid());

  CHECK(sp.is_valid());
  CHECK(wsp.is_valid());

  CHECK(d0.is_valid());
  CHECK(s0.is_valid());
  CHECK(d31.is_valid());
  CHECK(s31.is_valid());

  CHECK(x0.IsRegister());
  CHECK(w0.IsRegister());
  CHECK(xzr.IsRegister());
  CHECK(wzr.IsRegister());
  CHECK(sp.IsRegister());
  CHECK(wsp.IsRegister());
  CHECK(!x0.IsVRegister());
  CHECK(!w0.IsVRegister());
  CHECK(!xzr.IsVRegister());
  CHECK(!wzr.IsVRegister());
  CHECK(!sp.IsVRegister());
  CHECK(!wsp.IsVRegister());

  CHECK(d0.IsVRegister());
  CHECK(s0.IsVRegister());
  CHECK(!d0.IsRegister());
  CHECK(!s0.IsRegister());

  // Test the same as before, but using CPURegister types. This shouldn't make
  // any difference.
  CHECK(static_cast<CPURegister>(x0).is_valid());
  CHECK(static_cast<CPURegister>(w0).is_valid());
  CHECK(static_cast<CPURegister>(x30).is_valid());
  CHECK(static_cast<CPURegister>(w30).is_valid());
  CHECK(static_cast<CPURegister>(xzr).is_valid());
  CHECK(static_cast<CPURegister>(wzr).is_valid());

  CHECK(static_cast<CPURegister>(sp).is_valid());
  CHECK(static_cast<CPURegister>(wsp).is_valid());

  CHECK(static_cast<CPURegister>(d0).is_valid());
  CHECK(static_cast<CPURegister>(s0).is_valid());
  CHECK(static_cast<CPURegister>(d31).is_valid());
  CHECK(static_cast<CPURegister>(s31).is_valid());

  CHECK(static_cast<CPURegister>(x0).IsRegister());
  CHECK(static_cast<CPURegister>(w0).IsRegister());
  CHECK(static_cast<CPURegister>(xzr).IsRegister());
  CHECK(static_cast<CPURegister>(wzr).IsRegister());
  CHECK(static_cast<CPURegister>(sp).IsRegister());
  CHECK(static_cast<CPURegister>(wsp).IsRegister());
  CHECK(!static_cast<CPURegister>(x0).IsVRegister());
  CHECK(!static_cast<CPURegister>(w0).IsVRegister());
  CHECK(!static_cast<CPURegister>(xzr).IsVRegister());
  CHECK(!static_cast<CPURegister>(wzr).IsVRegister());
  CHECK(!static_cast<CPURegister>(sp).IsVRegister());
  CHECK(!static_cast<CPURegister>(wsp).IsVRegister());

  CHECK(static_cast<CPURegister>(d0).IsVRegister());
  CHECK(static_cast<CPURegister>(s0).IsVRegister());
  CHECK(!static_cast<CPURegister>(d0).IsRegister());
  CHECK(!static_cast<CPURegister>(s0).IsRegister());
}

TEST(areconsecutive) {
  // This test generates no code; it just checks that AreConsecutive works.
  CHECK(AreConsecutive(b0, NoVReg));
  CHECK(AreConsecutive(b1, b2));
  CHECK(AreConsecutive(b3, b4, b5));
  CHECK(AreConsecutive(b6, b7, b8, b9));
  CHECK(AreConsecutive(h10, NoVReg));
  CHECK(AreConsecutive(h11, h12));
  CHECK(AreConsecutive(h13, h14, h15));
  CHECK(AreConsecutive(h16, h17, h18, h19));
  CHECK(AreConsecutive(s20, NoVReg));
  CHECK(AreConsecutive(s21, s22));
  CHECK(AreConsecutive(s23, s24, s25));
  CHECK(AreConsecutive(s26, s27, s28, s29));
  CHECK(AreConsecutive(d30, NoVReg));
  CHECK(AreConsecutive(d31, d0));
  CHECK(AreConsecutive(d1, d2, d3));
  CHECK(AreConsecutive(d4, d5, d6, d7));
  CHECK(AreConsecutive(q8, NoVReg));
  CHECK(AreConsecutive(q9, q10));
  CHECK(AreConsecutive(q11, q12, q13));
  CHECK(AreConsecutive(q14, q15, q16, q17));
  CHECK(AreConsecutive(v18, NoVReg));
  CHECK(AreConsecutive(v19, v20));
  CHECK(AreConsecutive(v21, v22, v23));
  CHECK(AreConsecutive(v24, v25, v26, v27));
  CHECK(AreConsecutive(b29, h30));
  CHECK(AreConsecutive(s31, d0, q1));
  CHECK(AreConsecutive(v2, b3, h4, s5));

  CHECK(AreConsecutive(b26, b27, NoVReg, NoVReg));
  CHECK(AreConsecutive(h28, NoVReg, NoVReg, NoVReg));

  CHECK(!AreConsecutive(b0, b2));
  CHECK(!AreConsecutive(h1, h0));
  CHECK(!AreConsecutive(s31, s1));
  CHECK(!AreConsecutive(d12, d12));
  CHECK(!AreConsecutive(q31, q1));

  CHECK(!AreConsecutive(b5, b4, b3));
  CHECK(!AreConsecutive(h15, h16, h15, h14));
  CHECK(!AreConsecutive(s25, s24, s23, s22));
  CHECK(!AreConsecutive(d5, d6, d7, d6));
  CHECK(!AreConsecutive(q15, q16, q17, q6));

  CHECK(!AreConsecutive(b0, b1, b3));
  CHECK(!AreConsecutive(h4, h5, h6, h6));
  CHECK(!AreConsecutive(d15, d16, d18, NoVReg));
  CHECK(!AreConsecutive(s28, s30, NoVReg, NoVReg));
}

TEST(cpureglist_utils_x) {
  // This test doesn't generate any code, but it verifies the behaviour of
  // the CPURegList utility methods.

  // Test a list of X registers.
  CPURegList test(x0, x1, x2, x3);

  CHECK(test.IncludesAliasOf(x0));
  CHECK(test.IncludesAliasOf(x1));
  CHECK(test.IncludesAliasOf(x2));
  CHECK(test.IncludesAliasOf(x3));
  CHECK(test.IncludesAliasOf(w0));
  CHECK(test.IncludesAliasOf(w1));
  CHECK(test.IncludesAliasOf(w2));
  CHECK(test.IncludesAliasOf(w3));

  CHECK(!test.IncludesAliasOf(x4));
  CHECK(!test.IncludesAliasOf(x30));
  CHECK(!test.IncludesAliasOf(xzr));
  CHECK(!test.IncludesAliasOf(sp));
  CHECK(!test.IncludesAliasOf(w4));
  CHECK(!test.IncludesAliasOf(w30));
  CHECK(!test.IncludesAliasOf(wzr));
  CHECK(!test.IncludesAliasOf(wsp));

  CHECK(!test.IncludesAliasOf(d0));
  CHECK(!test.IncludesAliasOf(d1));
  CHECK(!test.IncludesAliasOf(d2));
  CHECK(!test.IncludesAliasOf(d3));
  CHECK(!test.IncludesAliasOf(s0));
  CHECK(!test.IncludesAliasOf(s1));
  CHECK(!test.IncludesAliasOf(s2));
  CHECK(!test.IncludesAliasOf(s3));

  CHECK(!test.IsEmpty());

  CHECK_EQ(test.type(), x0.type());

  CHECK_EQ(test.PopHighestIndex(), x3);
  CHECK_EQ(test.PopLowestIndex(), x0);

  CHECK(test.IncludesAliasOf(x1));
  CHECK(test.IncludesAliasOf(x2));
  CHECK(test.IncludesAliasOf(w1));
  CHECK(test.IncludesAliasOf(w2));
  CHECK(!test.IncludesAliasOf(x0));
  CHECK(!test.IncludesAliasOf(x3));
  CHECK(!test.IncludesAliasOf(w0));
  CHECK(!test.IncludesAliasOf(w3));

  CHECK_EQ(test.PopHighestIndex(), x2);
  CHECK_EQ(test.PopLowestIndex(), x1);

  CHECK(!test.IncludesAliasOf(x1));
  CHECK(!test.IncludesAliasOf(x2));
  CHECK(!test.IncludesAliasOf(w1));
  CHECK(!test.IncludesAliasOf(w2));

  CHECK(test.IsEmpty());
}

TEST(cpureglist_utils_w) {
  // This test doesn't generate any code, but it verifies the behaviour of
  // the CPURegList utility methods.

  // Test a list of W registers.
  CPURegList test(w10, w11, w12, w13);

  CHECK(test.IncludesAliasOf(x10));
  CHECK(test.IncludesAliasOf(x11));
  CHECK(test.IncludesAliasOf(x12));
  CHECK(test.IncludesAliasOf(x13));
  CHECK(test.IncludesAliasOf(w10));
  CHECK(test.IncludesAliasOf(w11));
  CHECK(test.IncludesAliasOf(w12));
  CHECK(test.IncludesAliasOf(w13));

  CHECK(!test.IncludesAliasOf(x0));
  CHECK(!test.IncludesAliasOf(x9));
  CHECK(!test.IncludesAliasOf(x14));
  CHECK(!test.IncludesAliasOf(x30));
  CHECK(!test.IncludesAliasOf(xzr));
  CHECK(!test.IncludesAliasOf(sp));
  CHECK(!test.IncludesAliasOf(w0));
  CHECK(!test.IncludesAliasOf(w9));
  CHECK(!test.IncludesAliasOf(w14));
  CHECK(!test.IncludesAliasOf(w30));
  CHECK(!test.IncludesAliasOf(wzr));
  CHECK(!test.IncludesAliasOf(wsp));

  CHECK(!test.IncludesAliasOf(d10));
  CHECK(!test.IncludesAliasOf(d11));
  CHECK(!test.IncludesAliasOf(d12));
  CHECK(!test.IncludesAliasOf(d13));
  CHECK(!test.IncludesAliasOf(s10));
  CHECK(!test.IncludesAliasOf(s11));
  CHECK(!test.IncludesAliasOf(s12));
  CHECK(!test.IncludesAliasOf(s13));

  CHECK(!test.IsEmpty());

  CHECK_EQ(test.type(), w10.type());

  CHECK_EQ(test.PopHighestIndex(), w13);
  CHECK_EQ(test.PopLowestIndex(), w10);

  CHECK(test.IncludesAliasOf(x11));
  CHECK(test.IncludesAliasOf(x12));
  CHECK(test.IncludesAliasOf(w11));
  CHECK(test.IncludesAliasOf(w12));
  CHECK(!test.IncludesAliasOf(x10));
  CHECK(!test.IncludesAliasOf(x13));
  CHECK(!test.IncludesAliasOf(w10));
  CHECK(!test.IncludesAliasOf(w13));

  CHECK_EQ(test.PopHighestIndex(), w12);
  CHECK_EQ(test.PopLowestIndex(), w11);

  CHECK(!test.IncludesAliasOf(x11));
  CHECK(!test.IncludesAliasOf(x12));
  CHECK(!test.IncludesAliasOf(w11));
  CHECK(!test.IncludesAliasOf(w12));

  CHECK(test.IsEmpty());
}

TEST(cpureglist_utils_d) {
  // This test doesn't generate any code, but it verifies the behaviour of
  // the CPURegList utility methods.

  // Test a list of D registers.
  CPURegList test(d20, d21, d22, d23);

  CHECK(test.IncludesAliasOf(d20));
  CHECK(test.IncludesAliasOf(d21));
  CHECK(test.IncludesAliasOf(d22));
  CHECK(test.IncludesAliasOf(d23));
  CHECK(test.IncludesAliasOf(s20));
  CHECK(test.IncludesAliasOf(s21));
  CHECK(test.IncludesAliasOf(s22));
  CHECK(test.IncludesAliasOf(s23));

  CHECK(!test.IncludesAliasOf(d0));
  CHECK(!test.IncludesAliasOf(d19));
  CHECK(!test.IncludesAliasOf(d24));
  CHECK(!test.IncludesAliasOf(d31));
  CHECK(!test.IncludesAliasOf(s0));
  CHECK(!test.IncludesAliasOf(s19));
  CHECK(!test.IncludesAliasOf(s24));
  CHECK(!test.IncludesAliasOf(s31));

  CHECK(!test.IncludesAliasOf(x20));
  CHECK(!test.IncludesAliasOf(x21));
  CHECK(!test.IncludesAliasOf(x22));
  CHECK(!test.IncludesAliasOf(x23));
  CHECK(!test.IncludesAliasOf(w20));
  CHECK(!test.IncludesAliasOf(w21));
  CHECK(!test.IncludesAliasOf(w22));
  CHECK(!test.IncludesAliasOf(w23));

  CHECK(!test.IncludesAliasOf(xzr));
  CHECK(!test.IncludesAliasOf(wzr));
  CHECK(!test.IncludesAliasOf(sp));
  CHECK(!test.IncludesAliasOf(wsp));

  CHECK(!test.IsEmpty());

  CHECK_EQ(test.type(), d20.type());

  CHECK_EQ(test.PopHighestIndex(), d23);
  CHECK_EQ(test.PopLowestIndex(), d20);

  CHECK(test.IncludesAliasOf(d21));
  CHECK(test.IncludesAliasOf(d22));
  CHECK(test.IncludesAliasOf(s21));
  CHECK(test.IncludesAliasOf(s22));
  CHECK(!test.IncludesAliasOf(d20));
  CHECK(!test.IncludesAliasOf(d23));
  CHECK(!test.IncludesAliasOf(s20));
  CHECK(!test.IncludesAliasOf(s23));

  CHECK_EQ(test.PopHighestIndex(), d22);
  CHECK_EQ(test.PopLowestIndex(), d21);

  CHECK(!test.IncludesAliasOf(d21));
  CHECK(!test.IncludesAliasOf(d22));
  CHECK(!test.IncludesAliasOf(s21));
  CHECK(!test.IncludesAliasOf(s22));

  CHECK(test.IsEmpty());
}

TEST(cpureglist_utils_s) {
  // This test doesn't generate any code, but it verifies the behaviour of
  // the CPURegList utility methods.

  // Test a list of S registers.
  CPURegList test(s20, s21, s22, s23);

  // The type and size mechanisms are already covered, so here we just test
  // that lists of S registers alias individual D registers.

  CHECK(test.IncludesAliasOf(d20));
  CHECK(test.IncludesAliasOf(d21));
  CHECK(test.IncludesAliasOf(d22));
  CHECK(test.IncludesAliasOf(d23));
  CHECK(test.IncludesAliasOf(s20));
  CHECK(test.IncludesAliasOf(s21));
  CHECK(test.IncludesAliasOf(s22));
  CHECK(test.IncludesAliasOf(s23));
}

TEST(cpureglist_utils_empty) {
  // This test doesn't generate any code, but it verifies the behaviour of
  // the CPURegList utility methods.

  // Test an empty list.
  // Empty lists can have type and size properties. Check that we can create
  // them, and that they are empty.
  CPURegList reg32(kWRegSizeInBits, RegList{});
  CPURegList reg64(kXRegSizeInBits, RegList{});
  CPURegList fpreg32(kSRegSizeInBits, DoubleRegList{});
  CPURegList fpreg64(kDRegSizeInBits, DoubleRegList{});

  CHECK(reg32.IsEmpty());
  CHECK(reg64.IsEmpty());
  CHECK(fpreg32.IsEmpty());
  CHECK(fpreg64.IsEmpty());

  CHECK(reg32.PopLowestIndex().IsNone());
  CHECK(reg64.PopLowestIndex().IsNone());
  CHECK(fpreg32.PopLowestIndex().IsNone());
  CHECK(fpreg64.PopLowestIndex().IsNone());

  CHECK(reg32.PopHighestIndex().IsNone());
  CHECK(reg64.PopHighestIndex().IsNone());
  CHECK(fpreg32.PopHighestIndex().IsNone());
  CHECK(fpreg64.PopHighestIndex().IsNone());

  CHECK(reg32.IsEmpty());
  CHECK(reg64.IsEmpty());
  CHECK(fpreg32.IsEmpty());
  CHECK(fpreg64.IsEmpty());
}

TEST(printf) {
  INIT_V8();
  SETUP_SIZE(BUF_SIZE * 2);
  START();

  char const * test_plain_string = "Printf with no arguments.\n";
  char const * test_substring = "'This is a substring.'";
  RegisterDump before;

  // Initialize x29 to the value of the stack pointer. We will use x29 as a
  // temporary stack pointer later, and initializing it in this way allows the
  // RegisterDump check to pass.
  __ Mov(x29, sp);

  // Test simple integer arguments.
  __ Mov(x0, 1234);
  __ Mov(x1, 0x1234);

  // Test simple floating-point arguments.
  __ Fmov(d0, 1.234);

  // Test pointer (string) arguments.
  __ Mov(x2, reinterpret_cast<uintptr_t>(test_substring));

  // Test the maximum number of arguments, and sign extension.
  __ Mov(w3, 0xFFFFFFFF);
  __ Mov(w4, 0xFFFFFFFF);
  __ Mov(x5, 0xFFFFFFFFFFFFFFFF);
  __ Mov(x6, 0xFFFFFFFFFFFFFFFF);
  __ Fmov(s1, 1.234);
  __ Fmov(s2, 2.345);
  __ Fmov(d3, 3.456);
  __ Fmov(d4, 4.567);

  // Test printing callee-saved registers.
  __ Mov(x28, 0x123456789ABCDEF);
  __ Fmov(d10, 42.0);

  // Test with three arguments.
  __ Mov(x10, 3);
  __ Mov(x11, 40);
  __ Mov(x12, 500);

  // A single character.
  __ Mov(w13, 'x');

  // Check that we don't clobber any registers.
  before.Dump(&masm);

  __ Printf(test_plain_string);   // NOLINT(runtime/printf)
  __ Printf("x0: %" PRId64 ", x1: 0x%08" PRIx64 "\n", x0, x1);
  __ Printf("w5: %" PRId32 ", x5: %" PRId64"\n", w5, x5);
  __ Printf("d0: %f\n", d0);
  __ Printf("Test %%s: %s\n", x2);
  __ Printf("w3(uint32): %" PRIu32 "\nw4(int32): %" PRId32 "\n"
            "x5(uint64): %" PRIu64 "\nx6(int64): %" PRId64 "\n",
            w3, w4, x5, x6);
  __ Printf("%%f: %f\n%%g: %g\n%%e: %e\n%%E: %E\n", s1, s2, d3, d4);
  __ Printf("0x%" PRIx32 ", 0x%" PRIx64 "\n", w28, x28);
  __ Printf("%g\n", d10);
  __ Printf("%%%%%s%%%c%%\n", x2, w13);

  // Print the stack pointer.
  __ Printf("StackPointer(sp): 0x%016" PRIx64 ", 0x%08" PRIx32 "\n", sp, wsp);

  // Test with three arguments.
  __ Printf("3=%u, 4=%u, 5=%u\n", x10, x11, x12);

  // Mixed argument types.
  __ Printf("w3: %" PRIu32 ", s1: %f, x5: %" PRIu64 ", d3: %f\n",
            w3, s1, x5, d3);
  __ Printf("s1: %f, d3: %f, w3: %" PRId32 ", x5: %" PRId64 "\n",
            s1, d3, w3, x5);

  END();
  RUN();

  // We cannot easily test the output of the Printf sequences, and because
  // Printf preserves all registers by default, we can't look at the number of
  // bytes that were printed. However, the printf_no_preserve test should check
  // that, and here we just test that we didn't clobber any registers.
  CHECK_EQUAL_REGISTERS(before);
}

TEST(printf_no_preserve) {
  INIT_V8();
  SETUP();
  START();

  char const * test_plain_string = "Printf with no arguments.\n";
  char const * test_substring = "'This is a substring.'";

  __ PrintfNoPreserve(test_plain_string);
  __ Mov(x19, x0);

  // Test simple integer arguments.
  __ Mov(x0, 1234);
  __ Mov(x1, 0x1234);
  __ PrintfNoPreserve("x0: %" PRId64", x1: 0x%08" PRIx64 "\n", x0, x1);
  __ Mov(x20, x0);

  // Test simple floating-point arguments.
  __ Fmov(d0, 1.234);
  __ PrintfNoPreserve("d0: %f\n", d0);
  __ Mov(x21, x0);

  // Test pointer (string) arguments.
  __ Mov(x2, reinterpret_cast<uintptr_t>(test_substring));
  __ PrintfNoPreserve("Test %%s: %s\n", x2);
  __ Mov(x22, x0);

  // Test the maximum number of arguments, and sign extension.
  __ Mov(w3, 0xFFFFFFFF);
  __ Mov(w4, 0xFFFFFFFF);
  __ Mov(x5, 0xFFFFFFFFFFFFFFFF);
  __ Mov(x6, 0xFFFFFFFFFFFFFFFF);
  __ PrintfNoPreserve("w3(uint32): %" PRIu32 "\nw4(int32): %" PRId32 "\n"
                      "x5(uint64): %" PRIu64 "\nx6(int64): %" PRId64 "\n",
                      w3, w4, x5, x6);
  __ Mov(x23, x0);

  __ Fmov(s1, 1.234);
  __ Fmov(s2, 2.345);
  __ Fmov(d3, 3.456);
  __ Fmov(d4, 4.567);
  __ PrintfNoPreserve("%%f: %f\n%%g: %g\n%%e: %e\n%%E: %E\n", s1, s2, d3, d4);
  __ Mov(x24, x0);

  // Test printing callee-saved registers.
  __ Mov(x28, 0x123456789ABCDEF);
  __ PrintfNoPreserve("0x%" PRIx32 ", 0x%" PRIx64 "\n", w28, x28);
  __ Mov(x25, x0);

  __ Fmov(d10, 42.0);
  __ PrintfNoPreserve("%g\n", d10);
  __ Mov(x26, x0);

  // Test with three arguments.
  __ Mov(x3, 3);
  __ Mov(x4, 40);
  __ Mov(x5, 500);
  __ PrintfNoPreserve("3=%u, 4=%u, 5=%u\n", x3, x4, x5);
  __ Mov(x27, x0);

  // Mixed argument types.
  __ Mov(w3, 0xFFFFFFFF);
  __ Fmov(s1, 1.234);
  __ Mov(x5, 0xFFFFFFFFFFFFFFFF);
  __ Fmov(d3, 3.456);
  __ PrintfNoPreserve("w3: %" PRIu32 ", s1: %f, x5: %" PRIu64 ", d3: %f\n",
                      w3, s1, x5, d3);
  __ Mov(x28, x0);

  END();
  RUN();

  // We cannot easily test the exact output of the Printf sequences, but we can
  // use the return code to check that the string length was correct.

  // Printf with no arguments.
  CHECK_EQUAL_64(strlen(test_plain_string), x19);
  // x0: 1234, x1: 0x00001234
  CHECK_EQUAL_64(25, x20);
  // d0: 1.234000
  CHECK_EQUAL_64(13, x21);
  // Test %s: 'This is a substring.'
  CHECK_EQUAL_64(32, x22);
  // w3(uint32): 4294967295
  // w4(int32): -1
  // x5(uint64): 18446744073709551615
  // x6(int64): -1
  CHECK_EQUAL_64(23 + 14 + 33 + 14, x23);
  // %f: 1.234000
  // %g: 2.345
  // %e: 3.456000e+00
  // %E: 4.567000E+00
  CHECK_EQUAL_64(13 + 10 + 17 + 17, x24);
  // 0x89ABCDEF, 0x123456789ABCDEF
  CHECK_EQUAL_64(30, x25);
  // 42
  CHECK_EQUAL_64(3, x26);
  // 3=3, 4=40, 5=500
  CHECK_EQUAL_64(17, x27);
  // w3: 4294967295, s1: 1.234000, x5: 18446744073709551615, d3: 3.456000
  CHECK_EQUAL_64(69, x28);
}

TEST(blr_lr) {
  // A simple test to check that the simulator correcty handle "blr lr".
  INIT_V8();
  SETUP();

  START();
  Label target;
  Label end;

  __ Mov(x0, 0x0);
  __ Adr(lr, &target);

  __ Blr(lr);
  __ Mov(x0, 0xDEADBEEF);
  __ B(&end);

  __ Bind(&target, BranchTargetIdentifier::kBtiCall);
  __ Mov(x0, 0xC001C0DE);

  __ Bind(&end);
  END();

  RUN();

  CHECK_EQUAL_64(0xC001C0DE, x0);
}

TEST(barriers) {
  // Generate all supported barriers, this is just a smoke test
  INIT_V8();
  SETUP();

  START();

  // DMB
  __ Dmb(FullSystem, BarrierAll);
  __ Dmb(FullSystem, BarrierReads);
  __ Dmb(FullSystem, BarrierWrites);
  __ Dmb(FullSystem, BarrierOther);

  __ Dmb(InnerShareable, BarrierAll);
  __ Dmb(InnerShareable, BarrierReads);
  __ Dmb(InnerShareable, BarrierWrites);
  __ Dmb(InnerShareable, BarrierOther);

  __ Dmb(NonShareable, BarrierAll);
  __ Dmb(NonShareable, BarrierReads);
  __ Dmb(NonShareable, BarrierWrites);
  __ Dmb(NonShareable, BarrierOther);

  __ Dmb(OuterShareable, BarrierAll);
  __ Dmb(OuterShareable, BarrierReads);
  __ Dmb(OuterShareable, BarrierWrites);
  __ Dmb(OuterShareable, BarrierOther);

  // DSB
  __ Dsb(FullSystem, BarrierAll);
  __ Dsb(FullSystem, BarrierReads);
  __ Dsb(FullSystem, BarrierWrites);
  __ Dsb(FullSystem, BarrierOther);

  __ Dsb(InnerShareable, BarrierAll);
  __ Dsb(InnerShareable, BarrierReads);
  __ Dsb(InnerShareable, BarrierWrites);
  __ Dsb(InnerShareable, BarrierOther);

  __ Dsb(NonShareable, BarrierAll);
  __ Dsb(NonShareable, BarrierReads);
  __ Dsb(NonShareable, BarrierWrites);
  __ Dsb(NonShareable, BarrierOther);

  __ Dsb(OuterShareable, BarrierAll);
  __ Dsb(OuterShareable, BarrierReads);
  __ Dsb(OuterShareable, BarrierWrites);
  __ Dsb(OuterShareable, BarrierOther);

  // ISB
  __ Isb();

  END();

  RUN();
}

TEST(cas_casa_casl_casal_w) {
  uint64_t data1 = 0x0123456789abcdef;
  uint64_t data2 = 0x0123456789abcdef;
  uint64_t data3 = 0x0123456789abcdef;
  uint64_t data4 = 0x0123456789abcdef;
  uint64_t data5 = 0x0123456789abcdef;
  uint64_t data6 = 0x0123456789abcdef;
  uint64_t data7 = 0x0123456789abcdef;
  uint64_t data8 = 0x0123456789abcdef;

  INIT_V8();
  SETUP();
  SETUP_FEATURE(LSE);

  START();

  __ Mov(x21, reinterpret_cast<uintptr_t>(&data1) + 0);
  __ Mov(x22, reinterpret_cast<uintptr_t>(&data2) + 0);
  __ Mov(x23, reinterpret_cast<uintptr_t>(&data3) + 4);
  __ Mov(x24, reinterpret_cast<uintptr_t>(&data4) + 4);
  __ Mov(x25, reinterpret_cast<uintptr_t>(&data5) + 0);
  __ Mov(x26, reinterpret_cast<uintptr_t>(&data6) + 0);
  __ Mov(x27, reinterpret_cast<uintptr_t>(&data7) + 4);
  __ Mov(x28, reinterpret_cast<uintptr_t>(&data8) + 4);

  __ Mov(x0, 0xffffffff);

  __ Mov(x1, 0xfedcba9876543210);
  __ Mov(x2, 0x0123456789abcdef);
  __ Mov(x3, 0xfedcba9876543210);
  __ Mov(x4, 0x89abcdef01234567);
  __ Mov(x5, 0xfedcba9876543210);
  __ Mov(x6, 0x0123456789abcdef);
  __ Mov(x7, 0xfedcba9876543210);
  __ Mov(x8, 0x89abcdef01234567);

  __ Cas(w1, w0, MemOperand(x21));
  __ Cas(w2, w0, MemOperand(x22));
  __ Casa(w3, w0, MemOperand(x23));
  __ Casa(w4, w0, MemOperand(x24));
  __ Casl(w5, w0, MemOperand(x25));
  __ Casl(w6, w0, MemOperand(x26));
  __ Casal(w7, w0, MemOperand(x27));
  __ Casal(w8, w0, MemOperand(x28));

  END();

  if (CAN_RUN()) {
    RUN();

    CHECK_EQUAL_64(0x89abcdef, x1);
    CHECK_EQUAL_64(0x89abcdef, x2);
    CHECK_EQUAL_64(0x01234567, x3);
    CHECK_EQUAL_64(0x01234567, x4);
    CHECK_EQUAL_64(0x89abcdef, x5);
    CHECK_EQUAL_64(0x89abcdef, x6);
    CHECK_EQUAL_64(0x01234567, x7);
    CHECK_EQUAL_64(0x01234567, x8);

    CHECK_EQUAL_64(0x0123456789abcdef, data1);
    CHECK_EQ
```