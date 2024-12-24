Response: 
Prompt: 
```
这是目录为v8/test/cctest/test-assembler-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共8部分，请归纳一下它的功能

"""
1F1E1D1C1B1A1918, 0x0302151413121110, q21);
  CHECK_EQUAL_128(0x2F2E2D2C2B2A2928, 0x0504252423222120, q22);
  CHECK_EQUAL_128(0x3F3E3D3C3B3A3938, 0x0706353433323130, q23);
  CHECK_EQUAL_128(0x0F0E0D0C03020100, 0x0706050403020100, q24);
  CHECK_EQUAL_128(0x1F1E1D1C07060504, 0x1716151413121110, q25);
  CHECK_EQUAL_128(0x2F2E2D2C0B0A0908, 0x2726252423222120, q26);
  CHECK_EQUAL_128(0x3F3E3D3C0F0E0D0C, 0x3736353433323130, q27);
  CHECK_EQUAL_128(0x0706050403020100, 0x0706050403020100, q28);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x1716151413121110, q29);
  CHECK_EQUAL_128(0x1716151413121110, 0x2726252423222120, q30);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x3736353433323130, q31);
}

TEST(neon_ld4_lane_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[64];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();

  // Test loading whole register by element.
  __ Mov(x17, src_base);
  for (int i = 15; i >= 0; i--) {
    __ Ld4(v0.B(), v1.B(), v2.B(), v3.B(), i, MemOperand(x17, 4, PostIndex));
  }

  __ Mov(x28, src_base);
  for (int i = 7; i >= 0; i--) {
    __ Ld4(v4.H(), v5.H(), v6.H(), v7.H(), i, MemOperand(x28, 8, PostIndex));
  }

  __ Mov(x19, src_base);
  for (int i = 3; i >= 0; i--) {
    __ Ld4(v8_.S(), v9.S(), v10.S(), v11.S(), i,
           MemOperand(x19, 16, PostIndex));
  }

  __ Mov(x20, src_base);
  for (int i = 1; i >= 0; i--) {
    __ Ld4(v12.D(), v13.D(), v14.D(), v15.D(), i,
           MemOperand(x20, 32, PostIndex));
  }

  // Test loading a single element into an initialised register.
  __ Mov(x25, 1);
  __ Mov(x21, src_base);
  __ Mov(x22, src_base);
  __ Mov(x23, src_base);
  __ Mov(x24, src_base);

  __ Mov(x4, x21);
  __ Ldr(q16, MemOperand(x4, 16, PostIndex));
  __ Ldr(q17, MemOperand(x4, 16, PostIndex));
  __ Ldr(q18, MemOperand(x4, 16, PostIndex));
  __ Ldr(q19, MemOperand(x4));
  __ Ld4(v16.B(), v17.B(), v18.B(), v19.B(), 4,
         MemOperand(x21, x25, PostIndex));
  __ Add(x25, x25, 1);

  __ Mov(x5, x22);
  __ Ldr(q20, MemOperand(x5, 16, PostIndex));
  __ Ldr(q21, MemOperand(x5, 16, PostIndex));
  __ Ldr(q22, MemOperand(x5, 16, PostIndex));
  __ Ldr(q23, MemOperand(x5));
  __ Ld4(v20.H(), v21.H(), v22.H(), v23.H(), 3,
         MemOperand(x22, x25, PostIndex));
  __ Add(x25, x25, 1);

  __ Mov(x6, x23);
  __ Ldr(q24, MemOperand(x6, 16, PostIndex));
  __ Ldr(q25, MemOperand(x6, 16, PostIndex));
  __ Ldr(q26, MemOperand(x6, 16, PostIndex));
  __ Ldr(q27, MemOperand(x6));
  __ Ld4(v24.S(), v25.S(), v26.S(), v27.S(), 2,
         MemOperand(x23, x25, PostIndex));
  __ Add(x25, x25, 1);

  __ Mov(x7, x24);
  __ Ldr(q28, MemOperand(x7, 16, PostIndex));
  __ Ldr(q29, MemOperand(x7, 16, PostIndex));
  __ Ldr(q30, MemOperand(x7, 16, PostIndex));
  __ Ldr(q31, MemOperand(x7));
  __ Ld4(v28.D(), v29.D(), v30.D(), v31.D(), 1,
         MemOperand(x24, x25, PostIndex));

  END();

  RUN();

  CHECK_EQUAL_128(0x0004080C1014181C, 0x2024282C3034383C, q0);
  CHECK_EQUAL_128(0x0105090D1115191D, 0x2125292D3135393D, q1);
  CHECK_EQUAL_128(0x02060A0E12161A1E, 0x22262A2E32363A3E, q2);
  CHECK_EQUAL_128(0x03070B0F13171B1F, 0x23272B2F33373B3F, q3);
  CHECK_EQUAL_128(0x0100090811101918, 0x2120292831303938, q4);
  CHECK_EQUAL_128(0x03020B0A13121B1A, 0x23222B2A33323B3A, q5);
  CHECK_EQUAL_128(0x05040D0C15141D1C, 0x25242D2C35343D3C, q6);
  CHECK_EQUAL_128(0x07060F0E17161F1E, 0x27262F2E37363F3E, q7);
  CHECK_EQUAL_128(0x0302010013121110, 0x2322212033323130, q8);
  CHECK_EQUAL_128(0x0706050417161514, 0x2726252437363534, q9);
  CHECK_EQUAL_128(0x0B0A09081B1A1918, 0x2B2A29283B3A3938, q10);
  CHECK_EQUAL_128(0x0F0E0D0C1F1E1D1C, 0x2F2E2D2C3F3E3D3C, q11);
  CHECK_EQUAL_128(0x0706050403020100, 0x2726252423222120, q12);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x2F2E2D2C2B2A2928, q13);
  CHECK_EQUAL_128(0x1716151413121110, 0x3736353433323130, q14);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x3F3E3D3C3B3A3938, q15);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0706050003020100, q16);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x1716150113121110, q17);
  CHECK_EQUAL_128(0x2F2E2D2C2B2A2928, 0x2726250223222120, q18);
  CHECK_EQUAL_128(0x3F3E3D3C3B3A3938, 0x3736350333323130, q19);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0100050403020100, q20);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x0302151413121110, q21);
  CHECK_EQUAL_128(0x2F2E2D2C2B2A2928, 0x0504252423222120, q22);
  CHECK_EQUAL_128(0x3F3E3D3C3B3A3938, 0x0706353433323130, q23);
  CHECK_EQUAL_128(0x0F0E0D0C03020100, 0x0706050403020100, q24);
  CHECK_EQUAL_128(0x1F1E1D1C07060504, 0x1716151413121110, q25);
  CHECK_EQUAL_128(0x2F2E2D2C0B0A0908, 0x2726252423222120, q26);
  CHECK_EQUAL_128(0x3F3E3D3C0F0E0D0C, 0x3736353433323130, q27);
  CHECK_EQUAL_128(0x0706050403020100, 0x0706050403020100, q28);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x1716151413121110, q29);
  CHECK_EQUAL_128(0x1716151413121110, 0x2726252423222120, q30);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x3736353433323130, q31);

  CHECK_EQUAL_64(src_base + 64, x17);
  CHECK_EQUAL_64(src_base + 64, x28);
  CHECK_EQUAL_64(src_base + 64, x19);
  CHECK_EQUAL_64(src_base + 64, x20);
  CHECK_EQUAL_64(src_base + 1, x21);
  CHECK_EQUAL_64(src_base + 2, x22);
  CHECK_EQUAL_64(src_base + 3, x23);
  CHECK_EQUAL_64(src_base + 4, x24);
}

TEST(neon_ld4_alllanes) {
  INIT_V8();
  SETUP();

  uint8_t src[64];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base + 1);
  __ Ld4r(v0.V8B(), v1.V8B(), v2.V8B(), v3.V8B(), MemOperand(x17));
  __ Add(x17, x17, 4);
  __ Ld4r(v4.V16B(), v5.V16B(), v6.V16B(), v7.V16B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld4r(v8_.V4H(), v9.V4H(), v10.V4H(), v11.V4H(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld4r(v12.V8H(), v13.V8H(), v14.V8H(), v15.V8H(), MemOperand(x17));
  __ Add(x17, x17, 8);
  __ Ld4r(v16.V2S(), v17.V2S(), v18.V2S(), v19.V2S(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld4r(v20.V4S(), v21.V4S(), v22.V4S(), v23.V4S(), MemOperand(x17));
  __ Add(x17, x17, 16);
  __ Ld4r(v24.V2D(), v25.V2D(), v26.V2D(), v27.V2D(), MemOperand(x17));

  END();

  RUN();

  CHECK_EQUAL_128(0x0000000000000000, 0x0101010101010101, q0);
  CHECK_EQUAL_128(0x0000000000000000, 0x0202020202020202, q1);
  CHECK_EQUAL_128(0x0000000000000000, 0x0303030303030303, q2);
  CHECK_EQUAL_128(0x0000000000000000, 0x0404040404040404, q3);
  CHECK_EQUAL_128(0x0505050505050505, 0x0505050505050505, q4);
  CHECK_EQUAL_128(0x0606060606060606, 0x0606060606060606, q5);
  CHECK_EQUAL_128(0x0707070707070707, 0x0707070707070707, q6);
  CHECK_EQUAL_128(0x0808080808080808, 0x0808080808080808, q7);
  CHECK_EQUAL_128(0x0000000000000000, 0x0706070607060706, q8);
  CHECK_EQUAL_128(0x0000000000000000, 0x0908090809080908, q9);
  CHECK_EQUAL_128(0x0000000000000000, 0x0B0A0B0A0B0A0B0A, q10);
  CHECK_EQUAL_128(0x0000000000000000, 0x0D0C0D0C0D0C0D0C, q11);
  CHECK_EQUAL_128(0x0807080708070807, 0x0807080708070807, q12);
  CHECK_EQUAL_128(0x0A090A090A090A09, 0x0A090A090A090A09, q13);
  CHECK_EQUAL_128(0x0C0B0C0B0C0B0C0B, 0x0C0B0C0B0C0B0C0B, q14);
  CHECK_EQUAL_128(0x0E0D0E0D0E0D0E0D, 0x0E0D0E0D0E0D0E0D, q15);
  CHECK_EQUAL_128(0x0000000000000000, 0x1211100F1211100F, q16);
  CHECK_EQUAL_128(0x0000000000000000, 0x1615141316151413, q17);
  CHECK_EQUAL_128(0x0000000000000000, 0x1A1918171A191817, q18);
  CHECK_EQUAL_128(0x0000000000000000, 0x1E1D1C1B1E1D1C1B, q19);
  CHECK_EQUAL_128(0x1312111013121110, 0x1312111013121110, q20);
  CHECK_EQUAL_128(0x1716151417161514, 0x1716151417161514, q21);
  CHECK_EQUAL_128(0x1B1A19181B1A1918, 0x1B1A19181B1A1918, q22);
  CHECK_EQUAL_128(0x1F1E1D1C1F1E1D1C, 0x1F1E1D1C1F1E1D1C, q23);
  CHECK_EQUAL_128(0x2726252423222120, 0x2726252423222120, q24);
  CHECK_EQUAL_128(0x2F2E2D2C2B2A2928, 0x2F2E2D2C2B2A2928, q25);
  CHECK_EQUAL_128(0x3736353433323130, 0x3736353433323130, q26);
  CHECK_EQUAL_128(0x3F3E3D3C3B3A3938, 0x3F3E3D3C3B3A3938, q27);
}

TEST(neon_ld4_alllanes_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[64];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base + 1);
  __ Mov(x19, 1);
  __ Ld4r(v0.V8B(), v1.V8B(), v2.V8B(), v3.V8B(),
          MemOperand(x17, 4, PostIndex));
  __ Ld4r(v4.V16B(), v5.V16B(), v6.V16B(), v7.V16B(),
          MemOperand(x17, x19, PostIndex));
  __ Ld4r(v8_.V4H(), v9.V4H(), v10.V4H(), v11.V4H(),
          MemOperand(x17, x19, PostIndex));
  __ Ld4r(v12.V8H(), v13.V8H(), v14.V8H(), v15.V8H(),
          MemOperand(x17, 8, PostIndex));
  __ Ld4r(v16.V2S(), v17.V2S(), v18.V2S(), v19.V2S(),
          MemOperand(x17, x19, PostIndex));
  __ Ld4r(v20.V4S(), v21.V4S(), v22.V4S(), v23.V4S(),
          MemOperand(x17, 16, PostIndex));
  __ Ld4r(v24.V2D(), v25.V2D(), v26.V2D(), v27.V2D(),
          MemOperand(x17, 32, PostIndex));
  END();

  RUN();

  CHECK_EQUAL_128(0x0000000000000000, 0x0101010101010101, q0);
  CHECK_EQUAL_128(0x0000000000000000, 0x0202020202020202, q1);
  CHECK_EQUAL_128(0x0000000000000000, 0x0303030303030303, q2);
  CHECK_EQUAL_128(0x0000000000000000, 0x0404040404040404, q3);
  CHECK_EQUAL_128(0x0505050505050505, 0x0505050505050505, q4);
  CHECK_EQUAL_128(0x0606060606060606, 0x0606060606060606, q5);
  CHECK_EQUAL_128(0x0707070707070707, 0x0707070707070707, q6);
  CHECK_EQUAL_128(0x0808080808080808, 0x0808080808080808, q7);
  CHECK_EQUAL_128(0x0000000000000000, 0x0706070607060706, q8);
  CHECK_EQUAL_128(0x0000000000000000, 0x0908090809080908, q9);
  CHECK_EQUAL_128(0x0000000000000000, 0x0B0A0B0A0B0A0B0A, q10);
  CHECK_EQUAL_128(0x0000000000000000, 0x0D0C0D0C0D0C0D0C, q11);
  CHECK_EQUAL_128(0x0807080708070807, 0x0807080708070807, q12);
  CHECK_EQUAL_128(0x0A090A090A090A09, 0x0A090A090A090A09, q13);
  CHECK_EQUAL_128(0x0C0B0C0B0C0B0C0B, 0x0C0B0C0B0C0B0C0B, q14);
  CHECK_EQUAL_128(0x0E0D0E0D0E0D0E0D, 0x0E0D0E0D0E0D0E0D, q15);
  CHECK_EQUAL_128(0x0000000000000000, 0x1211100F1211100F, q16);
  CHECK_EQUAL_128(0x0000000000000000, 0x1615141316151413, q17);
  CHECK_EQUAL_128(0x0000000000000000, 0x1A1918171A191817, q18);
  CHECK_EQUAL_128(0x0000000000000000, 0x1E1D1C1B1E1D1C1B, q19);
  CHECK_EQUAL_128(0x1312111013121110, 0x1312111013121110, q20);
  CHECK_EQUAL_128(0x1716151417161514, 0x1716151417161514, q21);
  CHECK_EQUAL_128(0x1B1A19181B1A1918, 0x1B1A19181B1A1918, q22);
  CHECK_EQUAL_128(0x1F1E1D1C1F1E1D1C, 0x1F1E1D1C1F1E1D1C, q23);
  CHECK_EQUAL_128(0x2726252423222120, 0x2726252423222120, q24);
  CHECK_EQUAL_128(0x2F2E2D2C2B2A2928, 0x2F2E2D2C2B2A2928, q25);
  CHECK_EQUAL_128(0x3736353433323130, 0x3736353433323130, q26);
  CHECK_EQUAL_128(0x3F3E3D3C3B3A3938, 0x3F3E3D3C3B3A3938, q27);
  CHECK_EQUAL_64(src_base + 64, x17);
}

TEST(neon_st1_lane) {
  INIT_V8();
  SETUP();

  uint8_t src[64];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x19, -16);
  __ Ldr(q0, MemOperand(x17));

  for (int i = 15; i >= 0; i--) {
    __ St1(v0.B(), i, MemOperand(x17));
    __ Add(x17, x17, 1);
  }
  __ Ldr(q1, MemOperand(x17, x19));

  for (int i = 7; i >= 0; i--) {
    __ St1(v0.H(), i, MemOperand(x17));
    __ Add(x17, x17, 2);
  }
  __ Ldr(q2, MemOperand(x17, x19));

  for (int i = 3; i >= 0; i--) {
    __ St1(v0.S(), i, MemOperand(x17));
    __ Add(x17, x17, 4);
  }
  __ Ldr(q3, MemOperand(x17, x19));

  for (int i = 1; i >= 0; i--) {
    __ St1(v0.D(), i, MemOperand(x17));
    __ Add(x17, x17, 8);
  }
  __ Ldr(q4, MemOperand(x17, x19));

  END();

  RUN();

  CHECK_EQUAL_128(0x0001020304050607, 0x08090A0B0C0D0E0F, q1);
  CHECK_EQUAL_128(0x0100030205040706, 0x09080B0A0D0C0F0E, q2);
  CHECK_EQUAL_128(0x0302010007060504, 0x0B0A09080F0E0D0C, q3);
  CHECK_EQUAL_128(0x0706050403020100, 0x0F0E0D0C0B0A0908, q4);
}

TEST(neon_st2_lane) {
  INIT_V8();
  SETUP();

  // Struct size * addressing modes * element sizes * vector size.
  uint8_t dst[2 * 2 * 4 * 16];
  memset(dst, 0, sizeof(dst));
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);

  START();
  __ Mov(x17, dst_base);
  __ Mov(x19, dst_base);
  __ Movi(v0.V2D(), 0x0001020304050607, 0x08090A0B0C0D0E0F);
  __ Movi(v1.V2D(), 0x1011121314151617, 0x18191A1B1C1D1E1F);

  // Test B stores with and without post index.
  for (int i = 15; i >= 0; i--) {
    __ St2(v0.B(), v1.B(), i, MemOperand(x19));
    __ Add(x19, x19, 2);
  }
  for (int i = 15; i >= 0; i--) {
    __ St2(v0.B(), v1.B(), i, MemOperand(x19, 2, PostIndex));
  }
  __ Ldr(q2, MemOperand(x17, 0 * 16));
  __ Ldr(q3, MemOperand(x17, 1 * 16));
  __ Ldr(q4, MemOperand(x17, 2 * 16));
  __ Ldr(q5, MemOperand(x17, 3 * 16));

  // Test H stores with and without post index.
  __ Mov(x0, 4);
  for (int i = 7; i >= 0; i--) {
    __ St2(v0.H(), v1.H(), i, MemOperand(x19));
    __ Add(x19, x19, 4);
  }
  for (int i = 7; i >= 0; i--) {
    __ St2(v0.H(), v1.H(), i, MemOperand(x19, x0, PostIndex));
  }
  __ Ldr(q6, MemOperand(x17, 4 * 16));
  __ Ldr(q7, MemOperand(x17, 5 * 16));
  __ Ldr(q16, MemOperand(x17, 6 * 16));
  __ Ldr(q17, MemOperand(x17, 7 * 16));

  // Test S stores with and without post index.
  for (int i = 3; i >= 0; i--) {
    __ St2(v0.S(), v1.S(), i, MemOperand(x19));
    __ Add(x19, x19, 8);
  }
  for (int i = 3; i >= 0; i--) {
    __ St2(v0.S(), v1.S(), i, MemOperand(x19, 8, PostIndex));
  }
  __ Ldr(q18, MemOperand(x17, 8 * 16));
  __ Ldr(q19, MemOperand(x17, 9 * 16));
  __ Ldr(q20, MemOperand(x17, 10 * 16));
  __ Ldr(q21, MemOperand(x17, 11 * 16));

  // Test D stores with and without post index.
  __ Mov(x0, 16);
  __ St2(v0.D(), v1.D(), 1, MemOperand(x19));
  __ Add(x19, x19, 16);
  __ St2(v0.D(), v1.D(), 0, MemOperand(x19, 16, PostIndex));
  __ St2(v0.D(), v1.D(), 1, MemOperand(x19, x0, PostIndex));
  __ St2(v0.D(), v1.D(), 0, MemOperand(x19, x0, PostIndex));
  __ Ldr(q22, MemOperand(x17, 12 * 16));
  __ Ldr(q23, MemOperand(x17, 13 * 16));
  __ Ldr(q24, MemOperand(x17, 14 * 16));
  __ Ldr(q25, MemOperand(x17, 15 * 16));
  END();

  RUN();

  CHECK_EQUAL_128(0x1707160615051404, 0x1303120211011000, q2);
  CHECK_EQUAL_128(0x1F0F1E0E1D0D1C0C, 0x1B0B1A0A19091808, q3);
  CHECK_EQUAL_128(0x1707160615051404, 0x1303120211011000, q4);
  CHECK_EQUAL_128(0x1F0F1E0E1D0D1C0C, 0x1B0B1A0A19091808, q5);

  CHECK_EQUAL_128(0x1617060714150405, 0x1213020310110001, q6);
  CHECK_EQUAL_128(0x1E1F0E0F1C1D0C0D, 0x1A1B0A0B18190809, q7);
  CHECK_EQUAL_128(0x1617060714150405, 0x1213020310110001, q16);
  CHECK_EQUAL_128(0x1E1F0E0F1C1D0C0D, 0x1A1B0A0B18190809, q17);

  CHECK_EQUAL_128(0x1415161704050607, 0x1011121300010203, q18);
  CHECK_EQUAL_128(0x1C1D1E1F0C0D0E0F, 0x18191A1B08090A0B, q19);
  CHECK_EQUAL_128(0x1415161704050607, 0x1011121300010203, q20);
  CHECK_EQUAL_128(0x1C1D1E1F0C0D0E0F, 0x18191A1B08090A0B, q21);

  CHECK_EQUAL_128(0x1011121314151617, 0x0001020304050607, q22);
  CHECK_EQUAL_128(0x18191A1B1C1D1E1F, 0x08090A0B0C0D0E0F, q23);
  CHECK_EQUAL_128(0x1011121314151617, 0x0001020304050607, q22);
  CHECK_EQUAL_128(0x18191A1B1C1D1E1F, 0x08090A0B0C0D0E0F, q23);
}

TEST(neon_st3_lane) {
  INIT_V8();
  SETUP();

  // Struct size * addressing modes * element sizes * vector size.
  uint8_t dst[3 * 2 * 4 * 16];
  memset(dst, 0, sizeof(dst));
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);

  START();
  __ Mov(x17, dst_base);
  __ Mov(x19, dst_base);
  __ Movi(v0.V2D(), 0x0001020304050607, 0x08090A0B0C0D0E0F);
  __ Movi(v1.V2D(), 0x1011121314151617, 0x18191A1B1C1D1E1F);
  __ Movi(v2.V2D(), 0x2021222324252627, 0x28292A2B2C2D2E2F);

  // Test B stores with and without post index.
  for (int i = 15; i >= 0; i--) {
    __ St3(v0.B(), v1.B(), v2.B(), i, MemOperand(x19));
    __ Add(x19, x19, 3);
  }
  for (int i = 15; i >= 0; i--) {
    __ St3(v0.B(), v1.B(), v2.B(), i, MemOperand(x19, 3, PostIndex));
  }
  __ Ldr(q3, MemOperand(x17, 0 * 16));
  __ Ldr(q4, MemOperand(x17, 1 * 16));
  __ Ldr(q5, MemOperand(x17, 2 * 16));
  __ Ldr(q6, MemOperand(x17, 3 * 16));
  __ Ldr(q7, MemOperand(x17, 4 * 16));
  __ Ldr(q16, MemOperand(x17, 5 * 16));

  // Test H stores with and without post index.
  __ Mov(x0, 6);
  for (int i = 7; i >= 0; i--) {
    __ St3(v0.H(), v1.H(), v2.H(), i, MemOperand(x19));
    __ Add(x19, x19, 6);
  }
  for (int i = 7; i >= 0; i--) {
    __ St3(v0.H(), v1.H(), v2.H(), i, MemOperand(x19, x0, PostIndex));
  }
  __ Ldr(q17, MemOperand(x17, 6 * 16));
  __ Ldr(q18, MemOperand(x17, 7 * 16));
  __ Ldr(q19, MemOperand(x17, 8 * 16));
  __ Ldr(q20, MemOperand(x17, 9 * 16));
  __ Ldr(q21, MemOperand(x17, 10 * 16));
  __ Ldr(q22, MemOperand(x17, 11 * 16));

  // Test S stores with and without post index.
  for (int i = 3; i >= 0; i--) {
    __ St3(v0.S(), v1.S(), v2.S(), i, MemOperand(x19));
    __ Add(x19, x19, 12);
  }
  for (int i = 3; i >= 0; i--) {
    __ St3(v0.S(), v1.S(), v2.S(), i, MemOperand(x19, 12, PostIndex));
  }
  __ Ldr(q23, MemOperand(x17, 12 * 16));
  __ Ldr(q24, MemOperand(x17, 13 * 16));
  __ Ldr(q25, MemOperand(x17, 14 * 16));
  __ Ldr(q26, MemOperand(x17, 15 * 16));
  __ Ldr(q27, MemOperand(x17, 16 * 16));
  __ Ldr(q28, MemOperand(x17, 17 * 16));

  // Test D stores with and without post index.
  __ Mov(x0, 24);
  __ St3(v0.D(), v1.D(), v2.D(), 1, MemOperand(x19));
  __ Add(x19, x19, 24);
  __ St3(v0.D(), v1.D(), v2.D(), 0, MemOperand(x19, 24, PostIndex));
  __ St3(v0.D(), v1.D(), v2.D(), 1, MemOperand(x19, x0, PostIndex));
  __ Ldr(q29, MemOperand(x17, 18 * 16));
  __ Ldr(q30, MemOperand(x17, 19 * 16));
  __ Ldr(q31, MemOperand(x17, 20 * 16));
  END();

  RUN();

  CHECK_EQUAL_128(0x0524140423130322, 0x1202211101201000, q3);
  CHECK_EQUAL_128(0x1A0A291909281808, 0x2717072616062515, q4);
  CHECK_EQUAL_128(0x2F1F0F2E1E0E2D1D, 0x0D2C1C0C2B1B0B2A, q5);
  CHECK_EQUAL_128(0x0524140423130322, 0x1202211101201000, q6);
  CHECK_EQUAL_128(0x1A0A291909281808, 0x2717072616062515, q7);
  CHECK_EQUAL_128(0x2F1F0F2E1E0E2D1D, 0x0D2C1C0C2B1B0B2A, q16);

  CHECK_EQUAL_128(0x1415040522231213, 0x0203202110110001, q17);
  CHECK_EQUAL_128(0x0A0B282918190809, 0x2627161706072425, q18);
  CHECK_EQUAL_128(0x2E2F1E1F0E0F2C2D, 0x1C1D0C0D2A2B1A1B, q19);
  CHECK_EQUAL_128(0x1415040522231213, 0x0203202110110001, q20);
  CHECK_EQUAL_128(0x0A0B282918190809, 0x2627161706072425, q21);
  CHECK_EQUAL_128(0x2E2F1E1F0E0F2C2D, 0x1C1D0C0D2A2B1A1B, q22);

  CHECK_EQUAL_128(0x0405060720212223, 0x1011121300010203, q23);
  CHECK_EQUAL_128(0x18191A1B08090A0B, 0x2425262714151617, q24);
  CHECK_EQUAL_128(0x2C2D2E2F1C1D1E1F, 0x0C0D0E0F28292A2B, q25);
  CHECK_EQUAL_128(0x0405060720212223, 0x1011121300010203, q26);
  CHECK_EQUAL_128(0x18191A1B08090A0B, 0x2425262714151617, q27);
  CHECK_EQUAL_128(0x2C2D2E2F1C1D1E1F, 0x0C0D0E0F28292A2B, q28);
}

TEST(neon_st4_lane) {
  INIT_V8();
  SETUP();

  // Struct size * element sizes * vector size.
  uint8_t dst[4 * 4 * 16];
  memset(dst, 0, sizeof(dst));
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);

  START();
  __ Mov(x17, dst_base);
  __ Mov(x19, dst_base);
  __ Movi(v0.V2D(), 0x0001020304050607, 0x08090A0B0C0D0E0F);
  __ Movi(v1.V2D(), 0x1011121314151617, 0x18191A1B1C1D1E1F);
  __ Movi(v2.V2D(), 0x2021222324252627, 0x28292A2B2C2D2E2F);
  __ Movi(v3.V2D(), 0x2021222324252627, 0x28292A2B2C2D2E2F);

  // Test B stores without post index.
  for (int i = 15; i >= 0; i--) {
    __ St4(v0.B(), v1.B(), v2.B(), v3.B(), i, MemOperand(x19));
    __ Add(x19, x19, 4);
  }
  __ Ldr(q4, MemOperand(x17, 0 * 16));
  __ Ldr(q5, MemOperand(x17, 1 * 16));
  __ Ldr(q6, MemOperand(x17, 2 * 16));
  __ Ldr(q7, MemOperand(x17, 3 * 16));

  // Test H stores with post index.
  __ Mov(x0, 8);
  for (int i = 7; i >= 0; i--) {
    __ St4(v0.H(), v1.H(), v2.H(), v3.H(), i, MemOperand(x19, x0, PostIndex));
  }
  __ Ldr(q16, MemOperand(x17, 4 * 16));
  __ Ldr(q17, MemOperand(x17, 5 * 16));
  __ Ldr(q18, MemOperand(x17, 6 * 16));
  __ Ldr(q19, MemOperand(x17, 7 * 16));

  // Test S stores without post index.
  for (int i = 3; i >= 0; i--) {
    __ St4(v0.S(), v1.S(), v2.S(), v3.S(), i, MemOperand(x19));
    __ Add(x19, x19, 16);
  }
  __ Ldr(q20, MemOperand(x17, 8 * 16));
  __ Ldr(q21, MemOperand(x17, 9 * 16));
  __ Ldr(q22, MemOperand(x17, 10 * 16));
  __ Ldr(q23, MemOperand(x17, 11 * 16));

  // Test D stores with post index.
  __ Mov(x0, 32);
  __ St4(v0.D(), v1.D(), v2.D(), v3.D(), 0, MemOperand(x19, 32, PostIndex));
  __ St4(v0.D(), v1.D(), v2.D(), v3.D(), 1, MemOperand(x19, x0, PostIndex));

  __ Ldr(q24, MemOperand(x17, 12 * 16));
  __ Ldr(q25, MemOperand(x17, 13 * 16));
  __ Ldr(q26, MemOperand(x17, 14 * 16));
  __ Ldr(q27, MemOperand(x17, 15 * 16));
  END();

  RUN();

  CHECK_EQUAL_128(0x2323130322221202, 0x2121110120201000, q4);
  CHECK_EQUAL_128(0x2727170726261606, 0x2525150524241404, q5);
  CHECK_EQUAL_128(0x2B2B1B0B2A2A1A0A, 0x2929190928281808, q6);
  CHECK_EQUAL_128(0x2F2F1F0F2E2E1E0E, 0x2D2D1D0D2C2C1C0C, q7);

  CHECK_EQUAL_128(0x2223222312130203, 0x2021202110110001, q16);
  CHECK_EQUAL_128(0x2627262716170607, 0x2425242514150405, q17);
  CHECK_EQUAL_128(0x2A2B2A2B1A1B0A0B, 0x2829282918190809, q18);
  CHECK_EQUAL_128(0x2E2F2E2F1E1F0E0F, 0x2C2D2C2D1C1D0C0D, q19);

  CHECK_EQUAL_128(0x2021222320212223, 0x1011121300010203, q20);
  CHECK_EQUAL_128(0x2425262724252627, 0x1415161704050607, q21);
  CHECK_EQUAL_128(0x28292A2B28292A2B, 0x18191A1B08090A0B, q22);
  CHECK_EQUAL_128(0x2C2D2E2F2C2D2E2F, 0x1C1D1E1F0C0D0E0F, q23);

  CHECK_EQUAL_128(0x18191A1B1C1D1E1F, 0x08090A0B0C0D0E0F, q24);
  CHECK_EQUAL_128(0x28292A2B2C2D2E2F, 0x28292A2B2C2D2E2F, q25);
  CHECK_EQUAL_128(0x1011121314151617, 0x0001020304050607, q26);
  CHECK_EQUAL_128(0x2021222324252627, 0x2021222324252627, q27);
}

TEST(neon_ld1_lane_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[64];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, src_base);
  __ Mov(x19, src_base);
  __ Mov(x20, src_base);
  __ Mov(x21, src_base);
  __ Mov(x22, src_base);
  __ Mov(x23, src_base);
  __ Mov(x24, src_base);

  // Test loading whole register by element.
  for (int i = 15; i >= 0; i--) {
    __ Ld1(v0.B(), i, MemOperand(x17, 1, PostIndex));
  }

  for (int i = 7; i >= 0; i--) {
    __ Ld1(v1.H(), i, MemOperand(x28, 2, PostIndex));
  }

  for (int i = 3; i >= 0; i--) {
    __ Ld1(v2.S(), i, MemOperand(x19, 4, PostIndex));
  }

  for (int i = 1; i >= 0; i--) {
    __ Ld1(v3.D(), i, MemOperand(x20, 8, PostIndex));
  }

  // Test loading a single element into an initialised register.
  __ Mov(x25, 1);
  __ Ldr(q4, MemOperand(x21));
  __ Ld1(v4.B(), 4, MemOperand(x21, x25, PostIndex));
  __ Add(x25, x25, 1);

  __ Ldr(q5, MemOperand(x22));
  __ Ld1(v5.H(), 3, MemOperand(x22, x25, PostIndex));
  __ Add(x25, x25, 1);

  __ Ldr(q6, MemOperand(x23));
  __ Ld1(v6.S(), 2, MemOperand(x23, x25, PostIndex));
  __ Add(x25, x25, 1);

  __ Ldr(q7, MemOperand(x24));
  __ Ld1(v7.D(), 1, MemOperand(x24, x25, PostIndex));

  END();

  RUN();

  CHECK_EQUAL_128(0x0001020304050607, 0x08090A0B0C0D0E0F, q0);
  CHECK_EQUAL_128(0x0100030205040706, 0x09080B0A0D0C0F0E, q1);
  CHECK_EQUAL_128(0x0302010007060504, 0x0B0A09080F0E0D0C, q2);
  CHECK_EQUAL_128(0x0706050403020100, 0x0F0E0D0C0B0A0908, q3);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0706050003020100, q4);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0100050403020100, q5);
  CHECK_EQUAL_128(0x0F0E0D0C03020100, 0x0706050403020100, q6);
  CHECK_EQUAL_128(0x0706050403020100, 0x0706050403020100, q7);
  CHECK_EQUAL_64(src_base + 16, x17);
  CHECK_EQUAL_64(src_base + 16, x28);
  CHECK_EQUAL_64(src_base + 16, x19);
  CHECK_EQUAL_64(src_base + 16, x20);
  CHECK_EQUAL_64(src_base + 1, x21);
  CHECK_EQUAL_64(src_base + 2, x22);
  CHECK_EQUAL_64(src_base + 3, x23);
  CHECK_EQUAL_64(src_base + 4, x24);
}

TEST(neon_st1_lane_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[64];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x19, -16);
  __ Ldr(q0, MemOperand(x17));

  for (int i = 15; i >= 0; i--) {
    __ St1(v0.B(), i, MemOperand(x17, 1, PostIndex));
  }
  __ Ldr(q1, MemOperand(x17, x19));

  for (int i = 7; i >= 0; i--) {
    __ St1(v0.H(), i, MemOperand(x17, 2, PostIndex));
  }
  __ Ldr(q2, MemOperand(x17, x19));

  for (int i = 3; i >= 0; i--) {
    __ St1(v0.S(), i, MemOperand(x17, 4, PostIndex));
  }
  __ Ldr(q3, MemOperand(x17, x19));

  for (int i = 1; i >= 0; i--) {
    __ St1(v0.D(), i, MemOperand(x17, 8, PostIndex));
  }
  __ Ldr(q4, MemOperand(x17, x19));

  END();

  RUN();

  CHECK_EQUAL_128(0x0001020304050607, 0x08090A0B0C0D0E0F, q1);
  CHECK_EQUAL_128(0x0100030205040706, 0x09080B0A0D0C0F0E, q2);
  CHECK_EQUAL_128(0x0302010007060504, 0x0B0A09080F0E0D0C, q3);
  CHECK_EQUAL_128(0x0706050403020100, 0x0F0E0D0C0B0A0908, q4);
}

TEST(neon_ld1_alllanes) {
  INIT_V8();
  SETUP();

  uint8_t src[64];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base + 1);
  __ Ld1r(v0.V8B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld1r(v1.V16B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld1r(v2.V4H(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld1r(v3.V8H(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld1r(v4.V2S(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld1r(v5.V4S(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld1r(v6.V1D(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld1r(v7.V2D(), MemOperand(x17));
  END();

  RUN();

  CHECK_EQUAL_128(0, 0x0101010101010101, q0);
  CHECK_EQUAL_128(0x0202020202020202, 0x0202020202020202, q1);
  CHECK_EQUAL_128(0, 0x0403040304030403, q2);
  CHECK_EQUAL_128(0x0504050405040504, 0x0504050405040504, q3);
  CHECK_EQUAL_128(0, 0x0807060508070605, q4);
  CHECK_EQUAL_128(0x0908070609080706, 0x0908070609080706, q5);
  CHECK_EQUAL_128(0, 0x0E0D0C0B0A090807, q6);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0F0E0D0C0B0A0908, q7);
}

TEST(neon_ld1_alllanes_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[64];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base + 1);
  __ Mov(x19, 1);
  __ Ld1r(v0.V8B(), MemOperand(x17, 1, PostIndex));
  __ Ld1r(v1.V16B(), MemOperand(x17, x19, PostIndex));
  __ Ld1r(v2.V4H(), MemOperand(x17, x19, PostIndex));
  __ Ld1r(v3.V8H(), MemOperand(x17, 2, PostIndex));
  __ Ld1r(v4.V2S(), MemOperand(x17, x19, PostIndex));
  __ Ld1r(v5.V4S(), MemOperand(x17, 4, PostIndex));
  __ Ld1r(v6.V2D(), MemOperand(x17, 8, PostIndex));
  END();

  RUN();

  CHECK_EQUAL_128(0, 0x0101010101010101, q0);
  CHECK_EQUAL_128(0x0202020202020202, 0x0202020202020202, q1);
  CHECK_EQUAL_128(0, 0x0403040304030403, q2);
  CHECK_EQUAL_128(0x0504050405040504, 0x0504050405040504, q3);
  CHECK_EQUAL_128(0, 0x0908070609080706, q4);
  CHECK_EQUAL_128(0x0A0908070A090807, 0x0A0908070A090807, q5);
  CHECK_EQUAL_128(0x1211100F0E0D0C0B, 0x1211100F0E0D0C0B, q6);
  CHECK_EQUAL_64(src_base + 19, x17);
}

TEST(neon_st1_d) {
  INIT_V8();
  SETUP();

  uint8_t src[14 * kDRegSize];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));
  __ Ldr(q2, MemOperand(x17, 16, PostIndex));
  __ Ldr(q3, MemOperand(x17, 16, PostIndex));
  __ Mov(x17, src_base);

  __ St1(v0.V8B(), MemOperand(x17));
  __ Ldr(d16, MemOperand(x17, 8, PostIndex));

  __ St1(v0.V8B(), v1.V8B(), MemOperand(x17));
  __ Ldr(q17, MemOperand(x17, 16, PostIndex));

  __ St1(v0.V4H(), v1.V4H(), v2.V4H(), MemOperand(x17));
  __ Ldr(d18, MemOperand(x17, 8, PostIndex));
  __ Ldr(d19, MemOperand(x17, 8, PostIndex));
  __ Ldr(d20, MemOperand(x17, 8, PostIndex));

  __ St1(v0.V2S(), v1.V2S(), v2.V2S(), v3.V2S(), MemOperand(x17));
  __ Ldr(q21, MemOperand(x17, 16, PostIndex));
  __ Ldr(q22, MemOperand(x17, 16, PostIndex));

  __ St1(v0.V1D(), v1.V1D(), v2.V1D(), v3.V1D(), MemOperand(x17));
  __ Ldr(q23, MemOperand(x17, 16, PostIndex));
  __ Ldr(q24, MemOperand(x17));
  END();

  RUN();

  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0706050403020100, q0);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x1716151413121110, q1);
  CHECK_EQUAL_128(0x2F2E2D2C2B2A2928, 0x2726252423222120, q2);
  CHECK_EQUAL_128(0x3F3E3D3C3B3A3938, 0x3736353433323130, q3);
  CHECK_EQUAL_128(0, 0x0706050403020100, q16);
  CHECK_EQUAL_128(0x1716151413121110, 0x0706050403020100, q17);
  CHECK_EQUAL_128(0, 0x0706050403020100, q18);
  CHECK_EQUAL_128(0, 0x1716151413121110, q19);
  CHECK_EQUAL_128(0, 0x2726252423222120, q20);
  CHECK_EQUAL_128(0x1716151413121110, 0x0706050403020100, q21);
  CHECK_EQUAL_128(0x3736353433323130, 0x2726252423222120, q22);
  CHECK_EQUAL_128(0x1716151413121110, 0x0706050403020100, q23);
  CHECK_EQUAL_128(0x3736353433323130, 0x2726252423222120, q24);
}

TEST(neon_st1_d_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[64 + 14 * kDRegSize];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, -8);
  __ Mov(x19, -16);
  __ Mov(x20, -24);
  __ Mov(x21, -32);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));
  __ Ldr(q2, MemOperand(x17, 16, PostIndex));
  __ Ldr(q3, MemOperand(x17, 16, PostIndex));
  __ Mov(x17, src_base);

  __ St1(v0.V8B(), MemOperand(x17, 8, PostIndex));
  __ Ldr(d16, MemOperand(x17, x28));

  __ St1(v0.V8B(), v1.V8B(), MemOperand(x17, 16, PostIndex));
  __ Ldr(q17, MemOperand(x17, x19));

  __ St1(v0.V4H(), v1.V4H(), v2.V4H(), MemOperand(x17, 24, PostIndex));
  __ Ldr(d18, MemOperand(x17, x20));
  __ Ldr(d19, MemOperand(x17, x19));
  __ Ldr(d20, MemOperand(x17, x28));

  __ St1(v0.V2S(), v1.V2S(), v2.V2S(), v3.V2S(),
         MemOperand(x17, 32, PostIndex));
  __ Ldr(q21, MemOperand(x17, x21));
  __ Ldr(q22, MemOperand(x17, x19));

  __ St1(v0.V1D(), v1.V1D(), v2.V1D(), v3.V1D(),
         MemOperand(x17, 32, PostIndex));
  __ Ldr(q23, MemOperand(x17, x21));
  __ Ldr(q24, MemOperand(x17, x19));
  END();

  RUN();

  CHECK_EQUAL_128(0, 0x0706050403020100, q16);
  CHECK_EQUAL_128(0x1716151413121110, 0x0706050403020100, q17);
  CHECK_EQUAL_128(0, 0x0706050403020100, q18);
  CHECK_EQUAL_128(0, 0x1716151413121110, q19);
  CHECK_EQUAL_128(0, 0x2726252423222120, q20);
  CHECK_EQUAL_128(0x1716151413121110, 0x0706050403020100, q21);
  CHECK_EQUAL_128(0x3736353433323130, 0x2726252423222120, q22);
  CHECK_EQUAL_128(0x1716151413121110, 0x0706050403020100, q23);
  CHECK_EQUAL_128(0x3736353433323130, 0x2726252423222120, q24);
}

TEST(neon_st1_q) {
  INIT_V8();
  SETUP();

  uint8_t src[64 + 160];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));
  __ Ldr(q2, MemOperand(x17, 16, PostIndex));
  __ Ldr(q3, MemOperand(x17, 16, PostIndex));

  __ St1(v0.V16B(), MemOperand(x17));
  __ Ldr(q16, MemOperand(x17, 16, PostIndex));

  __ St1(v0.V8H(), v1.V8H(), MemOperand(x17));
  __ Ldr(q17, MemOperand(x17, 16, PostIndex));
  __ Ldr(q18, MemOperand(x17, 16, PostIndex));

  __ St1(v0.V4S(), v1.V4S(), v2.V4S(), MemOperand(x17));
  __ Ldr(q19, MemOperand(x17, 16, PostIndex));
  __ Ldr(q20, MemOperand(x17, 16, PostIndex));
  __ Ldr(q21, MemOperand(x17, 16, PostIndex));

  __ St1(v0.V2D(), v1.V2D(), v2.V2D(), v3.V2D(), MemOperand(x17));
  __ Ldr(q22, MemOperand(x17, 16, PostIndex));
  __ Ldr(q23, MemOperand(x17, 16, PostIndex));
  __ Ldr(q24, MemOperand(x17, 16, PostIndex));
  __ Ldr(q25, MemOperand(x17));
  END();

  RUN();

  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0706050403020100, q16);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0706050403020100, q17);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x1716151413121110, q18);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0706050403020100, q19);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x1716151413121110, q20);
  CHECK_EQUAL_128(0x2F2E2D2C2B2A2928, 0x2726252423222120, q21);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0706050403020100, q22);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x1716151413121110, q23);
  CHECK_EQUAL_128(0x2F2E2D2C2B2A2928, 0x2726252423222120, q24);
  CHECK_EQUAL_128(0x3F3E3D3C3B3A3938, 0x3736353433323130, q25);
}

TEST(neon_st1_q_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[64 + 160];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, -16);
  __ Mov(x19, -32);
  __ Mov(x20, -48);
  __ Mov(x21, -64);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));
  __ Ldr(q2, MemOperand(x17, 16, PostIndex));
  __ Ldr(q3, MemOperand(x17, 16, PostIndex));

  __ St1(v0.V16B(), MemOperand(x17, 16, PostIndex));
  __ Ldr(q16, MemOperand(x17, x28));

  __ St1(v0.V8H(), v1.V8H(), MemOperand(x17, 32, PostIndex));
  __ Ldr(q17, MemOperand(x17, x19));
  __ Ldr(q18, MemOperand(x17, x28));

  __ St1(v0.V4S(), v1.V4S(), v2.V4S(), MemOperand(x17, 48, PostIndex));
  __ Ldr(q19, MemOperand(x17, x20));
  __ Ldr(q20, MemOperand(x17, x19));
  __ Ldr(q21, MemOperand(x17, x28));

  __ St1(v0.V2D(), v1.V2D(), v2.V2D(), v3.V2D(),
         MemOperand(x17, 64, PostIndex));
  __ Ldr(q22, MemOperand(x17, x21));
  __ Ldr(q23, MemOperand(x17, x20));
  __ Ldr(q24, MemOperand(x17, x19));
  __ Ldr(q25, MemOperand(x17, x28));

  END();

  RUN();

  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0706050403020100, q16);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0706050403020100, q17);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x1716151413121110, q18);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0706050403020100, q19);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x1716151413121110, q20);
  CHECK_EQUAL_128(0x2F2E2D2C2B2A2928, 0x2726252423222120, q21);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0706050403020100, q22);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x1716151413121110, q23);
  CHECK_EQUAL_128(0x2F2E2D2C2B2A2928, 0x2726252423222120, q24);
  CHECK_EQUAL_128(0x3F3E3D3C3B3A3938, 0x3736353433323130, q25);
}

TEST(neon_st2_d) {
  INIT_V8();
  SETUP();

  uint8_t src[4 * 16];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));

  __ St2(v0.V8B(), v1.V8B(), MemOperand(x19));
  __ Add(x19, x19, 22);
  __ St2(v0.V4H(), v1.V4H(), MemOperand(x19));
  __ Add(x19, x19, 11);
  __ St2(v0.V2S(), v1.V2S(), MemOperand(x19));

  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x19, 16, PostIndex));
  __ Ldr(q1, MemOperand(x19, 16, PostIndex));
  __ Ldr(q2, MemOperand(x19, 16, PostIndex));
  __ Ldr(q3, MemOperand(x19, 16, PostIndex));

  END();

  RUN();

  CHECK_EQUAL_128(0x1707160615051404, 0x1303120211011000, q0);
  CHECK_EQUAL_128(0x0504131203021110, 0x0100151413121110, q1);
  CHECK_EQUAL_128(0x1615140706050413, 0x1211100302010014, q2);
  CHECK_EQUAL_128(0x3F3E3D3C3B3A3938, 0x3736353433323117, q3);
}

TEST(neon_st2_d_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[4 * 16];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x22, 5);
  __ Mov(x17, src_base);
  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));

  __ St2(v0.V8B(), v1.V8B(), MemOperand(x19, x22, PostIndex));
  __ St2(v0.V4H(), v1.V4H(), MemOperand(x19, 16, PostIndex));
  __ St2(v0.V2S(), v1.V2S(), MemOperand(x19));

  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x19, 16, PostIndex));
  __ Ldr(q1, MemOperand(x19, 16, PostIndex));
  __ Ldr(q2, MemOperand(x19, 16, PostIndex));

  END();

  RUN();

  CHECK_EQUAL_128(0x1405041312030211, 0x1001000211011000, q0);
  CHECK_EQUAL_128(0x0605041312111003, 0x0201001716070615, q1);
  CHECK_EQUAL_128(0x2F2E2D2C2B2A2928, 0x2726251716151407, q2);
}

TEST(neon_st2_q) {
  INIT_V8();
  SETUP();

  uint8_t src[5 * 16];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));

  __ St2(v0.V16B(), v1.V16B(), MemOperand(x19));
  __ Add(x19, x19, 8);
  __ St2(v0.V8H(), v1.V8H(), MemOperand(x19));
  __ Add(x19, x19, 22);
  __ St2(v0.V4S(), v1.V4S(), MemOperand(x19));
  __ Add(x19, x19, 2);
  __ St2(v0.V2D(), v1.V2D(), MemOperand(x19));

  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x19, 16, PostIndex));
  __ Ldr(q1, MemOperand(x19, 16, PostIndex));
  __ Ldr(q2, MemOperand(x19, 16, PostIndex));
  __ Ldr(q3, MemOperand(x19, 16, PostIndex));

  END();

  RUN();

  CHECK_EQUAL_128(0x1312030211100100, 0x1303120211011000, q0);
  CHECK_EQUAL_128(0x01000B0A19180908, 0x1716070615140504, q1);
  CHECK_EQUAL_128(0x1716151413121110, 0x0706050403020100, q2);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x0F0E0D0C0B0A0908, q3);
}

TEST(neon_st2_q_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[5 * 16];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x22, 5);
  __ Mov(x17, src_base);
  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));

  __ St2(v0.V16B(), v1.V16B(), MemOperand(x19, x22, PostIndex));
  __ St2(v0.V8H(), v1.V8H(), MemOperand(x19, 32, PostIndex));
  __ St2(v0.V4S(), v1.V4S(), MemOperand(x19, x22, PostIndex));
  __ St2(v0.V2D(), v1.V2D(), MemOperand(x19));

  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x19, 16, PostIndex));
  __ Ldr(q1, MemOperand(x19, 16, PostIndex));
  __ Ldr(q2, MemOperand(x19, 16, PostIndex));
  __ Ldr(q3, MemOperand(x19, 16, PostIndex));
  __ Ldr(q4, MemOperand(x19, 16, PostIndex));

  END();

  RUN();

  CHECK_EQUAL_128(0x1405041312030211, 0x1001000211011000, q0);
  CHECK_EQUAL_128(0x1C0D0C1B1A0B0A19, 0x1809081716070615, q1);
  CHECK_EQUAL_128(0x0504030201001003, 0x0201001F1E0F0E1D, q2);
  CHECK_EQUAL_128(0x0D0C0B0A09081716, 0x1514131211100706, q3);
  CHECK_EQUAL_128(0x4F4E4D4C4B4A1F1E, 0x1D1C1B1A19180F0E, q4);
}

TEST(neon_st3_d) {
  INIT_V8();
  SETUP();

  uint8_t src[3 * 16];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));
  __ Ldr(q2, MemOperand(x17, 16, PostIndex));

  __ St3(v0.V8B(), v1.V8B(), v2.V8B(), MemOperand(x19));
  __ Add(x19, x19, 3);
  __ St3(v0.V4H(), v1.V4H(), v2.V4H(), MemOperand(x19));
  __ Add(x19, x19, 2);
  __ St3(v0.V2S(), v1.V2S(), v2.V2S(), MemOperand(x19));

  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x19, 16, PostIndex));
  __ Ldr(q1, MemOperand(x19, 16, PostIndex));

  END();

  RUN();

  CHECK_EQUAL_128(0x2221201312111003, 0x0201000100201000, q0);
  CHECK_EQUAL_128(0x1F1E1D2726252417, 0x1615140706050423, q1);
}

TEST(neon_st3_d_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[4 * 16];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x22, 5);
  __ Mov(x17, src_base);
  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));
  __ Ldr(q2, MemOperand(x17, 16, PostIndex));

  __ St3(v0.V8B(), v1.V8B(), v2.V8B(), MemOperand(x19, x22, PostIndex));
  __ St3(v0.V4H(), v1.V4H(), v2.V4H(), MemOperand(x19, 24, PostIndex));
  __ St3(v0.V2S(), v1.V2S(), v2.V2S(), MemOperand(x19));

  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x19, 16, PostIndex));
  __ Ldr(q1, MemOperand(x19, 16, PostIndex));
  __ Ldr(q2, MemOperand(x19, 16, PostIndex));
  __ Ldr(q3, MemOperand(x19, 16, PostIndex));

  END();

  RUN();

  CHECK_EQUAL_128(0x2213120302212011, 0x1001001101201000, q0);
  CHECK_EQUAL_128(0x0201002726171607, 0x0625241514050423, q1);
  CHECK_EQUAL_128(0x1615140706050423, 0x2221201312111003, q2);
  CHECK_EQUAL_128(0x3F3E3D3C3B3A3938, 0x3736352726252417, q3);
}

TEST(neon_st3_q) {
  INIT_V8();
  SETUP();

  uint8_t src[6 * 16];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));
  __ Ldr(q2, MemOperand(x17, 16, PostIndex));

  __ St3(v0.V16B(), v1.V16B(), v2.V16B(), MemOperand(x19));
  __ Add(x19, x19, 5);
  __ St3(v0.V8H(), v1.V8H(), v2.V8H(), MemOperand(x19));
  __ Add(x19, x19, 12);
  __ St3(v0.V4S(), v1.V4S(), v2.V4S(), MemOperand(x19));
  __ Add(x19, x19, 22);
  __ St3(v0.V2D(), v1.V2D(), v2.V2D(), MemOperand(x19));

  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x19, 16, PostIndex));
  __ Ldr(q1, MemOperand(x19, 16, PostIndex));
  __ Ldr(q2, MemOperand(x19, 16, PostIndex));
  __ Ldr(q3, MemOperand(x19, 16, PostIndex));
  __ Ldr(q4, MemOperand(x19, 16, PostIndex));
  __ Ldr(q5, MemOperand(x19, 16, PostIndex));

  END();

  RUN();

  CHECK_EQUAL_128(0x2213120302212011, 0x1001001101201000, q0);
  CHECK_EQUAL_128(0x0605042322212013, 0x1211100302010023, q1);
  CHECK_EQUAL_128(0x1007060504030201, 0x0025241716151407, q2);
  CHECK_EQUAL_128(0x0827262524232221, 0x2017161514131211, q3);
  CHECK_EQUAL_128(0x281F1E1D1C1B1A19, 0x180F0E0D0C0B0A09, q4);
  CHECK_EQUAL_128(0x5F5E5D5C5B5A5958, 0x572F2E2D2C2B2A29, q5);
}

TEST(neon_st3_q_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[7 * 16];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x22, 5);
  __ Mov(x17, src_base);
  __ Mov(x28, src_base);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));
  __ Ldr(q2, MemOperand(x17, 16, PostIndex));

  __ St3(v0.V16B(), v1.V16B(), v2.V16B(), MemOperand(x28, x22, PostIndex));
  __ St3(v0.V8H(), v1.V8H(), v2.V8H(), MemOperand(x28, 48, PostIndex));
  __ St3(v0.V4S(), v1.V4S(), v2.V4S(), MemOperand(x28, x22, PostIndex));
  __ St3(v0.V2D(), v1.V2D(), v2.V2D(), MemOperand(x28));

  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x19, 16, PostIndex));
  __ Ldr(q1, MemOperand(x19, 16, PostIndex));
  __ Ldr(q2, MemOperand(x19, 16, PostIndex));
  __ Ldr(q3, MemOperand(x19, 16, PostIndex));
  __ Ldr(q4, MemOperand(x19, 16, PostIndex));
  __ Ldr(q5, MemOperand(x19, 16, PostIndex));
  __ Ldr(q6, MemOperand(x19, 16, PostIndex));

  END();

  RUN();

  CHECK_EQUAL_128(0x2213120302212011, 0x1001001101201000, q0);
  CHECK_EQUAL_128(0x1809082726171607, 0x0625241514050423, q1);
  CHECK_EQUAL_128(0x0E2D2C1D1C0D0C2B, 0x2A1B1A0B0A292819, q2);
  CHECK_EQUAL_128(0x0504030201001003, 0x0201002F2E1F1E0F, q3);
  CHECK_EQUAL_128(0x2524232221201716, 0x1514131211100706, q4);
  CHECK_EQUAL_128(0x1D1C1B1A19180F0E, 0x0D0C0B0A09082726, q5);
  CHECK_EQUAL_128(0x6F6E6D6C6B6A2F2E, 0x2D2C2B2A29281F1E, q6);
}

TEST(neon_st4_d) {
  INIT_V8();
  SETUP();

  uint8_t src[4 * 16];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, src_base);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));
  __ Ldr(q2, MemOperand(x17, 16, PostIndex));
  __ Ldr(q3, MemOperand(x17, 16, PostIndex));

  __ St4(v0.V8B(), v1.V8B(), v2.V8B(), v3.V8B(), MemOperand(x28));
  __ Add(x28, x28, 12);
  __ St4(v0.V4H(), v1.V4H(), v2.V4H(), v3.V4H(), MemOperand(x28));
  __ Add(x28, x28, 15);
  __ St4(v0.V2S(), v1.V2S(), v2.V2S(), v3.V2S(), MemOperand(x28));

  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x19, 16, PostIndex));
  __ Ldr(q1, MemOperand(x19, 16, PostIndex));
  __ Ldr(q2, MemOperand(x19, 16, PostIndex));
  __ Ldr(q3, MemOperand(x19, 16, PostIndex));

  END();

  RUN();

  CHECK_EQUAL_128(0x1110010032221202, 0X3121110130201000, q0);
  CHECK_EQUAL_128(0x1003020100322322, 0X1312030231302120, q1);
  CHECK_EQUAL_128(0x1407060504333231, 0X3023222120131211, q2);
  CHECK_EQUAL_128(0x3F3E3D3C3B373635, 0x3427262524171615, q3);
}

TEST(neon_st4_d_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[5 * 16];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x22, 5);
  __ Mov(x17, src_base);
  __ Mov(x28, src_base);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));
  __ Ldr(q2, MemOperand(x17, 16, PostIndex));
  __ Ldr(q3, MemOperand(x17, 16, PostIndex));

  __ St4(v0.V8B(), v1.V8B(), v2.V8B(), v3.V8B(),
         MemOperand(x28, x22, PostIndex));
  __ St4(v0.V4H(), v1.V4H(), v2.V4H(), v3.V4H(),
         MemOperand(x28, 32, PostIndex));
  __ St4(v0.V2S(), v1.V2S(), v2.V2S(), v3.V2S(), MemOperand(x28));

  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x19, 16, PostIndex));
  __ Ldr(q1, MemOperand(x19, 16, PostIndex));
  __ Ldr(q2, MemOperand(x19, 16, PostIndex));
  __ Ldr(q3, MemOperand(x19, 16, PostIndex));
  __ Ldr(q4, MemOperand(x19, 16, PostIndex));

  END();

  RUN();

  CHECK_EQUAL_128(0x1203023130212011, 0x1001000130201000, q0);
  CHECK_EQUAL_128(0x1607063534252415, 0x1405043332232213, q1);
  CHECK_EQUAL_128(0x2221201312111003, 0x0201003736272617, q2);
  CHECK_EQUAL_128(0x2625241716151407, 0x0605043332313023, q3);
  CHECK_EQUAL_128(0x4F4E4D4C4B4A4948, 0x4746453736353427, q4);
}

TEST(neon_st4_q) {
  INIT_V8();
  SETUP();

  uint8_t src[7 * 16];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, src_base);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));
  __ Ldr(q2, MemOperand(x17, 16, PostIndex));
  __ Ldr(q3, MemOperand(x17, 16, PostIndex));

  __ St4(v0.V16B(), v1.V16B(), v2.V16B(), v3.V16B(), MemOperand(x28));
  __ Add(x28, x28, 5);
  __ St4(v0.V8H(), v1.V8H(), v2.V8H(), v3.V8H(), MemOperand(x28));
  __ Add(x28, x28, 12);
  __ St4(v0.V4S(), v1.V4S(), v2.V4S(), v3.V4S(), MemOperand(x28));
  __ Add(x28, x28, 22);
  __ St4(v0.V2D(), v1.V2D(), v2.V2D(), v3.V2D(), MemOperand(x28));
  __ Add(x28, x28, 10);

  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x19, 16, PostIndex));
  __ Ldr(q1, MemOperand(x19, 16, PostIndex));
  __ Ldr(q2, MemOperand(x19, 16, PostIndex));
  __ Ldr(q3, MemOperand(x19, 16, PostIndex));
  __ Ldr(q4, MemOperand(x19, 16, PostIndex));
  __ Ldr(q5, MemOperand(x19, 16, PostIndex));
  __ Ldr(q6, MemOperand(x19, 16, PostIndex));

  END();

  RUN();

  CHECK_EQUAL_128(0x1203023130212011, 0x1001000130201000, q0);
  CHECK_EQUAL_128(0x3231302322212013, 0x1211100302010013, q1);
  CHECK_EQUAL_128(0x1007060504030201, 0x0015140706050433, q2);
  CHECK_EQUAL_128(0x3027262524232221, 0x2017161514131211, q3);
  CHECK_EQUAL_128(0x180F0E0D0C0B0A09, 0x0837363534333231, q4);
  CHECK_EQUAL_128(0x382F2E2D2C2B2A29, 0x281F1E1D1C1B1A19, q5);
  CHECK_EQUAL_128(0x6F6E6D6C6B6A6968, 0x673F3E3D3C3B3A39, q6);
}

TEST(neon_st4_q_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[9 * 16];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x22, 5);
  __ Mov(x17, src_base);
  __ Mov(x28, src_base);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));
  __ Ldr(q2, MemOperand(x17, 16, PostIndex));
  __ Ldr(q3, MemOperand(x17, 16, PostIndex));

  __ St4(v0.V16B(), v1.V16B(), v2.V16B(), v3.V16B(),
         MemOperand(x28, x22, PostIndex));
  __ St4(v0.V8H(), v1.V8H(), v2.V8H(), v3.V8H(),
         MemOperand(x28, 64, PostIndex));
  __ St4(v0.V4S(), v1.V4S(), v2.V4S(), v3.V4S(),
         MemOperand(x28, x22, PostIndex));
  __ St4(v0.V2D(), v1.V2D(), v2.V2D(), v3.V2D(), MemOperand(x28));

  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x19, 16, PostIndex));
  __ Ldr(q1, MemOperand(x19, 16, PostIndex));
  __ Ldr(q2, MemOperand(x19, 16, PostIndex));
  __ Ldr(q3, MemOperand(x19, 16, PostIndex));
  __ Ldr(q4, MemOperand(x19, 16, PostIndex));
  __ Ldr(q5, MemOperand(x19, 16, PostIndex));
  __ Ldr(q6, MemOperand(x19, 16, PostIndex));
  __ Ldr(q7, MemOperand(x19, 16, PostIndex));
  __ Ldr(q8, MemOperand(x19, 16, PostIndex));

  END();

  RUN();

  CHECK_EQUAL_128(0x1203023130212011, 0x1001000130201000, q0);
  CHECK_EQUAL_128(0x1607063534252415, 0x1405043332232213, q1);
  CHECK_EQUAL_128(0x1A0B0A3938292819, 0x1809083736272617, q2);
  CHECK_EQUAL_128(0x1E0F0E3D3C2D2C1D, 0x1C0D0C3B3A2B2A1B, q3);
  CHECK_EQUAL_128(0x0504030201001003, 0x0201003F3E2F2E1F, q4);
  CHECK_EQUAL_128(0x2524232221201716, 0x1514131211100706, q5);
  CHECK_EQUAL_128(0x0D0C0B0A09083736, 0x3534333231302726, q6);
  CHECK_EQUAL_128(0x2D2C2B2A29281F1E, 0x1D1C1B1A19180F0E, q7);
  CHECK_EQUAL_128(0x8F8E8D8C8B8A3F3E, 0x3D3C3B3A39382F2E, q8);
}

TEST(neon_destructive_minmaxp) {
  INIT_V8();
  SETUP();

  START();
  __ Movi(v0.V2D(), 0, 0x2222222233333333);
  __ Movi(v1.V2D(), 0, 0x0000000011111111);

  __ Sminp(v16.V2S(), v0.V2S(), v1.V2S());
  __ Mov(v17, v0);
  __ Sminp(v17.V2S(), v17.V2S(), v1.V2S());
  __ Mov(v18, v1);
  __ Sminp(v18.V2S(), v0.V2S(), v18.V2S());
  __ Mov(v19, v0);
  __ Sminp(v19.V2S(), v19.V2S(), v19.V2S());

  __ Smaxp(v20.V2S(), v0.V2S(), v1.V2S());
  __ Mov(v21, v0);
  __ Smaxp(v21.V2S(), v21.V2S(), v1.V2S());
  __ Mov(v22, v1);
  __ Smaxp(v22.V2S(), v0.V2S(), v22.V2S());
  __ Mov(v23, v0);
  __ Smaxp(v23.V2S(), v23.V2S(), v23.V2S());

  __ Uminp(v24.V2S(), v0.V2S(), v1.V2S());
  __ Mov(v25, v0);
  __ Uminp(v25.V2S(), v25.V2S(), v1.V2S());
  __ Mov(v26, v1);
  __ Uminp(v26.V2S(), v0.V2S(), v26.V2S());
  __ Mov(v27, v0);
  __ Uminp(v27.V2S(), v27.V2S(), v27.V2S());

  __ Umaxp(v28.V2S(), v0.V2S(), v1.V2S());
  __ Mov(v29, v0);
  __ Umaxp(v29.V2S(), v29.V2S(), v1.V2S());
  __ Mov(v30, v1);
  __ Umaxp(v30.V2S(), v0.V2S(), v30.V2S());
  __ Mov(v31, v0);
  __ Umaxp(v31.V2S(), v31.V2S(), v31.V2S());
  END();

  RUN();

  CHECK_EQUAL_128(0, 0x0000000022222222, q16);
  CHECK_EQUAL_128(0, 0x0000000022222222, q17);
  CHECK_EQUAL_128(0, 0x0000000022222222, q18);
  CHECK_EQUAL_128(0, 0x2222222222222222, q19);

  CHECK_EQUAL_128(0, 0x1111111133333333, q20);
  CHECK_EQUAL_128(0, 0x1111111133333333, q21);
  CHECK_EQUAL_128(0, 0x1111111133333333, q22);
  CHECK_EQUAL_128(0, 0x3333333333333333, q23);

  CHECK_EQUAL_128(0, 0x0000000022222222, q24);
  CHECK_EQUAL_128(0, 0x0000000022222222, q25);
  CHECK_EQUAL_128(0, 0x0000000022222222, q26);
  CHECK_EQUAL_128(0, 0x2222222222222222, q27);

  CHECK_EQUAL_128(0, 0x1111111133333333, q28);
  CHECK_EQUAL_128(0, 0x1111111133333333, q29);
  CHECK_EQUAL_128(0, 0x1111111133333333, q30);
  CHECK_EQUAL_128(0, 0x3333333333333333, q31);
}

TEST(neon_destructive_tbl) {
  INIT_V8();
  SETUP();

  START();
  __ Movi(v0.V2D(), 0x0041424334353627, 0x28291A1B1C0D0E0F);
  __ Movi(v1.V2D(), 0xAFAEADACABAAA9A8, 0xA7A6A5A4A3A2A1A0);
  __ Movi(v2.V2D(), 0xBFBEBDBCBBBAB9B8, 0xB7B6B5B4B3B2B1B0);
  __ Movi(v3.V2D(), 0xCFCECDCCCBCAC9C8, 0xC7C6C5C4C3C2C1C0);
  __ Movi(v4.V2D(), 0xDFDEDDDCDBDAD9D8, 0xD7D6D5D4D3D2D1D0);

  __ Movi(v16.V2D(), 0x5555555555555555, 0x5555555555555555);
  __ Tbl(v16.V16B(), v1.V16B(), v0.V16B());
  __ Mov(v17, v0);
  __ Tbl(v17.V16B(), v1.V16B(), v17.V16B());
  __ Mov(v18, v1);
  __ Tbl(v18.V16B(), v18.V16B(), v0.V16B());
  __ Mov(v19, v0);
  __ Tbl(v19.V16B(), v19.V16B(), v19.V16B());

  __ Movi(v20.V2D(), 0x5555555555555555, 0x5555555555555555);
  __ Tbl(v20.V16B(), v1.V16B(), v2.V16B(), v3.V16B(), v4.V16B(), v0.V16B());
  __ Mov(v21, v0);
  __ Tbl(v21.V16B(), v1.V16B(), v2.V16B(), v3.V16B(), v4.V16B(), v21.V16B());
  __ Mov(v22, v1);
  __ Mov(v23, v2);
  __ Mov(v24, v3);
  __ Mov(v25, v4);
  __ Tbl(v22.V16B(), v22.V16B(), v23.V16B(), v24.V16B(), v25.V16B(), v0.V16B());
  __ Mov(v26, v0);
  __ Mov(v27, v1);
  __ Mov(v28, v2);
  __ Mov(v29, v3);
  __ Tbl(v26.V16B(), v26.V16B(), v27.V16B(), v28.V16B(), v29.V16B(),
         v26.V16B());
  END();

  RUN();

  CHECK_EQUAL_128(0xA000000000000000, 0x0000000000ADAEAF, q16);
  CHECK_EQUAL_128(0xA000000000000000, 0x0000000000ADAEAF, q17);
  CHECK_EQUAL_128(0xA000000000000000, 0x0000000000ADAEAF, q18);
  CHECK_EQUAL_128(0x0F00000000000000, 0x0000000000424100, q19);

  CHECK_EQUAL_128(0xA0000000D4D5D6C7, 0xC8C9BABBBCADAEAF, q20);
  CHECK_EQUAL_128(0xA0000000D4D5D6C7, 0xC8C9BABBBCADAEAF, q21);
  CHECK_EQUAL_128(0xA0000000D4D5D6C7, 0xC8C9BABBBCADAEAF, q22);
  CHECK_EQUAL_128(0x0F000000C4C5C6B7, 0xB8B9AAABAC424100, q26);
}

TEST(neon_destructive_tbx) {
  INIT_V8();
  SETUP();

  START();
  __ Movi(v0.V2D(), 0x0041424334353627, 0x28291A1B1C0D0E0F);
  __ Movi(v1.V2D(), 0xAFAEADACABAAA9A8, 0xA7A6A5A4A3A2A1A0);
  __ Movi(v2.V2D(), 0xBFBEBDBCBBBAB9B8, 0xB7B6B5B4B3B2B1B0);
  __ Movi(v3.V2D(), 0xCFCECDCCCBCAC9C8, 0xC7C6C5C4C3C2C1C0);
  __ Movi(v4.V2D(), 0xDFDEDDDCDBDAD9D8, 0xD7D6D5D4D3D2D1D0);

  __ Movi(v16.V2D(), 0x5555555555555555, 0x5555555555555555);
  __ Tbx(v16.V16B(), v1.V16B(), v0.V16B());
  __ Mov(v17, v0);
  __ Tbx(v17.V16B(), v1.V16B(), v17.V16B());
  __ Mov(v18, v1);
  __ Tbx(v18.V16B(), v18.V16B(), v0.V16B());
  __ Mov(v19, v0);
  __ Tbx(v19.V16B(), v19.V16B(), v19.V16B());

  __ Movi(v20.V2D(), 0x5555555555555555, 0x5555555555555555);
  __ Tbx(v20.V16B(), v1.V16B(), v2.V16B(), v3.V16B(), v4.V16B(), v0.V16B());
  __ Mov(v21, v0);
  __ Tbx(v21.V16B(), v1.V16B(), v2.V16B(), v3.V16B(), v4.V16B(), v21.V16B());
  __ Mov(v22, v1);
  __ Mov(v23, v2);
  __ Mov(v24, v3);
  __ Mov(v25, v4);
  __ Tbx(v22.V16B(), v22.V16B(), v23.V16B(), v24.V16B(), v25.V16B(), v0.V16B());
  __ Mov(v26, v0);
  __ Mov(v27, v1);
  __ Mov(v28, v2);
  __ Mov(v29, v3);
  __ Tbx(v26.V16B(), v26.V16B(), v27.V16B(), v28.V16B(), v29.V16B(),
         v26.V16B());
  END();

  RUN();

  CHECK_EQUAL_128(0xA055555555555555, 0x5555555555ADAEAF, q16);
  CHECK_EQUAL_128(0xA041424334353627, 0x28291A1B1CADAEAF, q17);
  CHECK_EQUAL_128(0xA0AEADACABAAA9A8, 0xA7A6A5A4A3ADAEAF, q18);
  CHECK_EQUAL_128(0x0F41424334353627, 0x28291A1B1C424100, q19);

  CHECK_EQUAL_128(0xA0555555D4D5D6C7, 0xC8C9BABBBCADAEAF, q20);
  CHECK_EQUAL_128(0xA0414243D4D5D6C7, 0xC8C9BABBBCADAEAF, q21);
  CHECK_EQUAL_128(0xA0AEADACD4D5D6C7, 0xC8C9BABBBCADAEAF, q22);
  CHECK_EQUAL_128(0x0F414243C4C5C6B7, 0xB8B9AAABAC424100, q26);
}

TEST(neon_destructive_fcvtl) {
  INIT_V8();
  SETUP();

  START();
  __ Movi(v0.V2D(), 0x400000003F800000, 0xBF800000C0000000);
  __ Fcvtl(v16.V2D(), v0.V2S());
  __ Fcvtl2(v17.V2D(), v0.V4S());
  __ Mov(v18, v0);
  __ Mov(v19, v0);
  __ Fcvtl(v18.V2D(), v18.V2S());
  __ Fcvtl2(v19.V2D(), v19.V4S());

  __ Movi(v1.V2D(), 0x40003C003C004000, 0xC000BC00BC00C000);
  __ Fcvtl(v20.V4S(), v1.V4H());
  __ Fcvtl2(v21.V4S(), v1.V8H());
  __ Mov(v22, v1);
  __ Mov(v23, v1);
  __ Fcvtl(v22.V4S(), v22.V4H());
  __ Fcvtl2(v23.V4S(), v23.V8H());

  END();

  RUN();

  CHECK_EQUAL_128(0xBFF0000000000000, 0xC000000000000000, q16);
  CHECK_EQUAL_128(0x4000000000000000, 0x3FF0000000000000, q17);
  CHECK_EQUAL_128(0xBFF0000000000000, 0xC000000000000000, q18);
  CHECK_EQUAL_128(0x4000000000000000, 0x3FF0000000000000, q19);

  CHECK_EQUAL_128(0xC0000000BF800000, 0xBF800000C0000000, q20);
  CHECK_EQUAL_128(0x400000003F800000, 0x3F80000040000000, q21);
  CHECK_EQUAL_128(0xC0000000BF800000, 0xBF800000C0000000, q22);
  CHECK_EQUAL_128(0x400000003F800000, 0x3F80000040000000, q23);
}

TEST(ldp_stp_float) {
  INIT_V8();
  SETUP();

  float src[2] = {1.0, 2.0};
  float dst[3] = {0.0, 0.0, 0.0};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);

  START();
  __ Mov(x16, src_base);
  __ Mov(x17, dst_base);
  __ Ldp(s31, s0, MemOperand(x16, 2 * sizeof(src[0]), PostIndex));
  __ Stp(s0, s31, MemOperand(x17, sizeof(dst[1]), PreIndex));
  END();

  RUN();

  CHECK_EQUAL_FP32(1.0, s31);
  CHECK_EQUAL_FP32(2.0, s0);
  CHECK_EQUAL_FP32(0.0, dst[0]);
  CHECK_EQUAL_FP32(2.0, dst[1]);
  CHECK_EQUAL_FP32(1.0, dst[2]);
  CHECK_EQUAL_64(src_base + 2 * sizeof(src[0]), x16);
  CHECK_EQUAL_64(dst_base + sizeof(dst[1]), x17);
}

TEST(ldp_stp_double) {
  INIT_V8();
  SETUP();

  double src[2] = {1.0, 2.0};
  double dst[3] = {0.0, 0.0, 0.0};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);

  START();
  __ Mov(x16, src_base);
  __ Mov(x17, dst_base);
  __ Ldp(d31, d0, MemOperand(x16, 2 * sizeof(src[0]), PostIndex));
  __ Stp(d0, d31, MemOperand(x17, sizeof(dst[1]), PreIndex));
  END();

  RUN();

  CHECK_EQUAL_FP64(1.0, d31);
  CHECK_EQUAL_FP64(2.0, d0);
  CHECK_EQUAL_FP64(0.0, dst[0]);
  CHECK_EQUAL_FP64(2.0, dst[1]);
  CHECK_EQUAL_FP64(1.0, dst[2]);
  CHECK_EQUAL_64(src_base + 2 * sizeof(src[0]), x16);
  CHECK_EQUAL_64(dst_base + sizeof(dst[1]), x17);
}

TEST(ldp_stp_quad) {
  SETUP();

  uint64_t src[4] = {0x0123456789ABCDEF, 0xAAAAAAAA55555555, 0xFEDCBA9876543210,
                     0x55555555AAAAAAAA};
  uint64_t dst[6] = {0, 0, 0, 0, 0, 0};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);

  START();
  __ Mov(x16, src_base);
  __ Mov(x17, dst_base);
  __ Ldp(q31, q0, MemOperand(x16, 4 * sizeof(src[0]), PostIndex));
  __ Stp(q0, q31, MemOperand(x17, 2 * sizeof(dst[1]), PreIndex));
  END();

  RUN();

  CHECK_EQUAL_128(0xAAAAAAAA55555555, 0x0123456789ABCDEF, q31);
  CHECK_EQUAL_128(0x55555555AAAAAAAA, 0xFEDCBA9876543210, q0);
  CHECK_EQUAL_64(0, dst[0]);
  CHECK_EQUAL_64(0, dst[1]);
  CHECK_EQUAL_64(0xFEDCBA9876543210, dst[2]);
  CHECK_EQUAL_64(0x55555555AAAAAAAA, dst[3]);
  CHECK_EQUAL_64(0x0123456789ABCDEF, dst[4]);
  CHECK_EQUAL_64(0xAAAAAAAA55555555, dst[5]);
  CHECK_EQUAL_64(src_base + 4 * sizeof(src[0]), x16);
  CHECK_EQUAL_64(dst_base + 2 * sizeof(dst[1]), x17);
}

TEST(ldp_stp_offset) {
  INIT_V8();
  SETUP();

  uint64_t src[3] = {0x0011223344556677UL, 0x8899AABBCCDDEEFFUL,
                     0xFFEEDDCCBBAA9988UL};
  uint64_t dst[7] = {0, 0, 0, 0, 0, 0, 0};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);

  START();
  __ Mov(x16, src_base);
  __ Mov(x17, dst_base);
  __ Mov(x28, src_base + 24);
  __ Mov(x19, dst_base + 56);
  __ Ldp(w0, w1, MemOperand(x16));
  __ Ldp(w2, w3, MemOperand(x16, 4));
  __ Ldp(x4, x5, MemOperand(x16, 8));
  __ Ldp(w6, w7, MemOperand(x28, -12));
  __ Ldp(x8, x9, MemOperand(x28, -16));
  __ Stp(w0, w1, MemOperand(x17));
  __ Stp(w2, w3, MemOperand(x17, 8));
  __ Stp(x4, x5, MemOperand(x17, 16));
  __ Stp(w6, w7, MemOperand(x19, -24));
  __ Stp(x8, x9, MemOperand(x19, -16));
  END();

  RUN();

  CHECK_EQUAL_64(0x44556677, x0);
  CHECK_EQUAL_64(0x00112233, x1);
  CHECK_EQUAL_64(0x0011223344556677UL, dst[0]);
  CHECK_EQUAL_64(0x00112233, x2);
  CHECK_EQUAL_64(0xCCDDEEFF, x3);
  CHECK_EQUAL_64(0xCCDDEEFF00112233UL, dst[1]);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, x4);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, dst[2]);
  CHECK_EQUAL_64(0xFFEEDDCCBBAA9988UL, x5);
  CHECK_EQUAL_64(0xFFEEDDCCBBAA9988UL, dst[3]);
  CHECK_EQUAL_64(0x8899AABB, x6);
  CHECK_EQUAL_64(0xBBAA9988, x7);
  CHECK_EQUAL_64(0xBBAA99888899AABBUL, dst[4]);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, x8);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, dst[5]);
  CHECK_EQUAL_64(0xFFEEDDCCBBAA9988UL, x9);
  CHECK_EQUAL_64(0xFFEEDDCCBBAA9988UL, dst[6]);
  CHECK_EQUAL_64(src_base, x16);
  CHECK_EQUAL_64(dst_base, x17);
  CHECK_EQUAL_64(src_base + 24, x28);
  CHECK_EQUAL_64(dst_base + 56, x19);
}

TEST(ldp_stp_offset_wide) {
  INIT_V8();
  SETUP();

  uint64_t src[3] = {0x0011223344556677, 0x8899AABBCCDDEEFF,
                     0xFFEEDDCCBBAA9988};
  uint64_t dst[7] = {0, 0, 0, 0, 0, 0, 0};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);
  // Move base too far from the array to force multiple instructions
  // to be emitted.
  const int64_t base_offset = 1024;

  START();
  __ Mov(x20, src_base - base_offset);
  __ Mov(x21, dst_base - base_offset);
  __ Mov(x28, src_base + base_offset + 24);
  __ Mov(x19, dst_base + base_offset + 56);
  __ Ldp(w0, w1, MemOperand(x20, base_offset));
  __ Ldp(w2, w3, MemOperand(x20, base_offset + 4));
  __ Ldp(x4, x5, MemOperand(x20, base_offset + 8));
  __ Ldp(w6, w7, MemOperand(x28, -12 - base_offset));
  __ Ldp(x8, x9, MemOperand(x28, -16 - base_offset));
  __ Stp(w0, w1, MemOperand(x21, base_offset));
  __ Stp(w2, w3, MemOperand(x21, base_offset + 8));
  __ Stp(x4, x5, MemOperand(x21, base_offset + 16));
  __ Stp(w6, w7, MemOperand(x19, -24 - base_offset));
  __ Stp(x8, x9, MemOperand(x19, -16 - base_offset));
  END();

  RUN();

  CHECK_EQUAL_64(0x44556677, x0);
  CHECK_EQUAL_64(0x00112233, x1);
  CHECK_EQUAL_64(0x0011223344556677UL, dst[0]);
  CHECK_EQUAL_64(0x00112233, x2);
  CHECK_EQUAL_64(0xCCDDEEFF, x3);
  CHECK_EQUAL_64(0xCCDDEEFF00112233UL, dst[1]);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, x4);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, dst[2]);
  CHECK_EQUAL_64(0xFFEEDDCCBBAA9988UL, x5);
  CHECK_EQUAL_64(0xFFEEDDCCBBAA9988UL, dst[3]);
  CHECK_EQUAL_64(0x8899AABB, x6);
  CHECK_EQUAL_64(0xBBAA9988, x7);
  CHECK_EQUAL_64(0xBBAA99888899AABBUL, dst[4]);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, x8);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, dst[5]);
  CHECK_EQUAL_64(0xFFEEDDCCBBAA9988UL, x9);
  CHECK_EQUAL_64(0xFFEEDDCCBBAA9988UL, dst[6]);
  CHECK_EQUAL_64(src_base - base_offset, x20);
  CHECK_EQUAL_64(dst_base - base_offset, x21);
  CHECK_EQUAL_64(src_base + base_offset + 24, x28);
  CHECK_EQUAL_64(dst_base + base_offset + 56, x19);
}

TEST(ldp_stp_preindex) {
  INIT_V8();
  SETUP();

  uint64_t src[3] = {0x0011223344556677UL, 0x8899AABBCCDDEEFFUL,
                     0xFFEEDDCCBBAA9988UL};
  uint64_t dst[5] = {0, 0, 0, 0, 0};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);

  START();
  __ Mov(x16, src_base);
  __ Mov(x17, dst_base);
  __ Mov(x28, dst_base + 16);
  __ Ldp(w0, w1, MemOperand(x16, 4, PreIndex));
  __ Mov(x19, x16);
  __ Ldp(w2, w3, MemOperand(x16, -4, PreIndex));
  __ Stp(w2, w3, MemOperand(x17, 4, PreIndex));
  __ Mov(x20, x17);
  __ Stp(w0, w1, MemOperand(x17, -4, PreIndex));
  __ Ldp(x4, x5, MemOperand(x16, 8, PreIndex));
  __ Mov(x21, x16);
  __ Ldp(x6, x7, MemOperand(x16, -8, PreIndex));
  __ Stp(x7, x6, MemOperand(x28, 8, PreIndex));
  __ Mov(x22, x28);
  __ Stp(x5, x4, MemOperand(x28, -8, PreIndex));
  END();

  RUN();

  CHECK_EQUAL_64(0x00112233, x0);
  CHECK_EQUAL_64(0xCCDDEEFF, x1);
  CHECK_EQUAL_64(0x44556677, x2);
  CHECK_EQUAL_64(0x00112233, x3);
  CHECK_EQUAL_64(0xCCDDEEFF00112233UL, dst[0]);
  CHECK_EQUAL_64(0x0000000000112233UL, dst[1]);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, x4);
  CHECK_EQUAL_64(0xFFEEDDCCBBAA9988UL, x5);
  CHECK_EQUAL_64(0x0011223344556677UL, x6);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, x7);
  CHECK_EQUAL_64(0xFFEEDDCCBBAA9988UL, dst[2]);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, dst[3]);
  CHECK_EQUAL_64(0x0011223344556677UL, dst[4]);
  CHECK_EQUAL_64(src_base, x16);
  CHECK_EQUAL_64(dst_base, x17);
  CHECK_EQUAL_64(dst_base + 16, x28);
  CHECK_EQUAL_64(src_base + 4, x19);
  CHECK_EQUAL_64(dst_base + 4, x20);
  CHECK_EQUAL_64(src_base + 8, x21);
  CHECK_EQUAL_64(dst_base + 24, x22);
}

TEST(ldp_stp_preindex_wide) {
  INIT_V8();
  SETUP();

  uint64_t src[3] = {0x0011223344556677, 0x8899AABBCCDDEEFF,
                     0xFFEEDDCCBBAA9988};
  uint64_t dst[5] = {0, 0, 0, 0, 0};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);
  // Move base too far from the array to force multiple instructions
  // to be emitted.
  const int64_t base_offset = 1024;

  START();
  __ Mov(x24, src_base - base_offset);
  __ Mov(x25, dst_base + base_offset);
  __ Mov(x28, dst_base + base_offset + 16);
  __ Ldp(w0, w1, MemOperand(x24, base_offset + 4, PreIndex));
  __ Mov(x19, x24);
  __ Mov(x24, src_base - base_offset + 4);
  __ Ldp(w2, w3, MemOperand(x24, base_offset - 4, PreIndex));
  __ Stp(w2, w3, MemOperand(x25, 4 - base_offset, PreIndex));
  __ Mov(x20, x25);
  __ Mov(x25, dst_base + base_offset + 4);
  __ Mov(x24, src_base - base_offset);
  __ Stp(w0, w1, MemOperand(x25, -4 - base_offset, PreIndex));
  __ Ldp(x4, x5, MemOperand(x24, base_offset + 8, PreIndex));
  __ Mov(x21, x24);
  __ Mov(x24, src_base - base_offset + 8);
  __ Ldp(x6, x7, MemOperand(x24, base_offset - 8, PreIndex));
  __ Stp(x7, x6, MemOperand(x28, 8 - base_offset, PreIndex));
  __ Mov(x22, x28);
  __ Mov(x28, dst_base + base_offset + 16 + 8);
  __ Stp(x5, x4, MemOperand(x28, -8 - base_offset, PreIndex));
  END();

  RUN();

  CHECK_EQUAL_64(0x00112233, x0);
  CHECK_EQUAL_64(0xCCDDEEFF, x1);
  CHECK_EQUAL_64(0x44556677, x2);
  CHECK_EQUAL_64(0x00112233, x3);
  CHECK_EQUAL_64(0xCCDDEEFF00112233UL, dst[0]);
  CHECK_EQUAL_64(0x0000000000112233UL, dst[1]);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, x4);
  CHECK_EQUAL_64(0xFFEEDDCCBBAA9988UL, x5);
  CHECK_EQUAL_64(0x0011223344556677UL, x6);
  CHECK_EQUAL_64(0x889
"""


```