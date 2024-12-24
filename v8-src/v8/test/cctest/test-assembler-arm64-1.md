Response: 
Prompt: 
```
这是目录为v8/test/cctest/test-assembler-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共8部分，请归纳一下它的功能

"""
 x0);
}

TEST(ldr_str_offset) {
  INIT_V8();
  SETUP();

  uint64_t src[2] = {0xFEDCBA9876543210UL, 0x0123456789ABCDEFUL};
  uint64_t dst[5] = {0, 0, 0, 0, 0};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);

  START();
  __ Mov(x17, src_base);
  __ Mov(x19, dst_base);
  __ Ldr(w0, MemOperand(x17));
  __ Str(w0, MemOperand(x19));
  __ Ldr(w1, MemOperand(x17, 4));
  __ Str(w1, MemOperand(x19, 12));
  __ Ldr(x2, MemOperand(x17, 8));
  __ Str(x2, MemOperand(x19, 16));
  __ Ldrb(w3, MemOperand(x17, 1));
  __ Strb(w3, MemOperand(x19, 25));
  __ Ldrh(w4, MemOperand(x17, 2));
  __ Strh(w4, MemOperand(x19, 33));
  END();

  RUN();

  CHECK_EQUAL_64(0x76543210, x0);
  CHECK_EQUAL_64(0x76543210, dst[0]);
  CHECK_EQUAL_64(0xFEDCBA98, x1);
  CHECK_EQUAL_64(0xFEDCBA9800000000UL, dst[1]);
  CHECK_EQUAL_64(0x0123456789ABCDEFUL, x2);
  CHECK_EQUAL_64(0x0123456789ABCDEFUL, dst[2]);
  CHECK_EQUAL_64(0x32, x3);
  CHECK_EQUAL_64(0x3200, dst[3]);
  CHECK_EQUAL_64(0x7654, x4);
  CHECK_EQUAL_64(0x765400, dst[4]);
  CHECK_EQUAL_64(src_base, x17);
  CHECK_EQUAL_64(dst_base, x19);
}

TEST(ldr_str_wide) {
  INIT_V8();
  SETUP();

  uint32_t src[8192];
  uint32_t dst[8192];
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);
  memset(src, 0xAA, 8192 * sizeof(src[0]));
  memset(dst, 0xAA, 8192 * sizeof(dst[0]));
  src[0] = 0;
  src[6144] = 6144;
  src[8191] = 8191;

  START();
  __ Mov(x22, src_base);
  __ Mov(x23, dst_base);
  __ Mov(x24, src_base);
  __ Mov(x25, dst_base);
  __ Mov(x26, src_base);
  __ Mov(x27, dst_base);

  __ Ldr(w0, MemOperand(x22, 8191 * sizeof(src[0])));
  __ Str(w0, MemOperand(x23, 8191 * sizeof(dst[0])));
  __ Ldr(w1, MemOperand(x24, 4096 * sizeof(src[0]), PostIndex));
  __ Str(w1, MemOperand(x25, 4096 * sizeof(dst[0]), PostIndex));
  __ Ldr(w2, MemOperand(x26, 6144 * sizeof(src[0]), PreIndex));
  __ Str(w2, MemOperand(x27, 6144 * sizeof(dst[0]), PreIndex));
  END();

  RUN();

  CHECK_EQUAL_32(8191, w0);
  CHECK_EQUAL_32(8191, dst[8191]);
  CHECK_EQUAL_64(src_base, x22);
  CHECK_EQUAL_64(dst_base, x23);
  CHECK_EQUAL_32(0, w1);
  CHECK_EQUAL_32(0, dst[0]);
  CHECK_EQUAL_64(src_base + 4096 * sizeof(src[0]), x24);
  CHECK_EQUAL_64(dst_base + 4096 * sizeof(dst[0]), x25);
  CHECK_EQUAL_32(6144, w2);
  CHECK_EQUAL_32(6144, dst[6144]);
  CHECK_EQUAL_64(src_base + 6144 * sizeof(src[0]), x26);
  CHECK_EQUAL_64(dst_base + 6144 * sizeof(dst[0]), x27);
}

TEST(ldr_str_preindex) {
  INIT_V8();
  SETUP();

  uint64_t src[2] = {0xFEDCBA9876543210UL, 0x0123456789ABCDEFUL};
  uint64_t dst[6] = {0, 0, 0, 0, 0, 0};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, dst_base);
  __ Mov(x19, src_base);
  __ Mov(x20, dst_base);
  __ Mov(x21, src_base + 16);
  __ Mov(x22, dst_base + 40);
  __ Mov(x23, src_base);
  __ Mov(x24, dst_base);
  __ Mov(x25, src_base);
  __ Mov(x26, dst_base);
  __ Ldr(w0, MemOperand(x17, 4, PreIndex));
  __ Str(w0, MemOperand(x28, 12, PreIndex));
  __ Ldr(x1, MemOperand(x19, 8, PreIndex));
  __ Str(x1, MemOperand(x20, 16, PreIndex));
  __ Ldr(w2, MemOperand(x21, -4, PreIndex));
  __ Str(w2, MemOperand(x22, -4, PreIndex));
  __ Ldrb(w3, MemOperand(x23, 1, PreIndex));
  __ Strb(w3, MemOperand(x24, 25, PreIndex));
  __ Ldrh(w4, MemOperand(x25, 3, PreIndex));
  __ Strh(w4, MemOperand(x26, 41, PreIndex));
  END();

  RUN();

  CHECK_EQUAL_64(0xFEDCBA98, x0);
  CHECK_EQUAL_64(0xFEDCBA9800000000UL, dst[1]);
  CHECK_EQUAL_64(0x0123456789ABCDEFUL, x1);
  CHECK_EQUAL_64(0x0123456789ABCDEFUL, dst[2]);
  CHECK_EQUAL_64(0x01234567, x2);
  CHECK_EQUAL_64(0x0123456700000000UL, dst[4]);
  CHECK_EQUAL_64(0x32, x3);
  CHECK_EQUAL_64(0x3200, dst[3]);
  CHECK_EQUAL_64(0x9876, x4);
  CHECK_EQUAL_64(0x987600, dst[5]);
  CHECK_EQUAL_64(src_base + 4, x17);
  CHECK_EQUAL_64(dst_base + 12, x28);
  CHECK_EQUAL_64(src_base + 8, x19);
  CHECK_EQUAL_64(dst_base + 16, x20);
  CHECK_EQUAL_64(src_base + 12, x21);
  CHECK_EQUAL_64(dst_base + 36, x22);
  CHECK_EQUAL_64(src_base + 1, x23);
  CHECK_EQUAL_64(dst_base + 25, x24);
  CHECK_EQUAL_64(src_base + 3, x25);
  CHECK_EQUAL_64(dst_base + 41, x26);
}

TEST(ldr_str_postindex) {
  INIT_V8();
  SETUP();

  uint64_t src[2] = {0xFEDCBA9876543210UL, 0x0123456789ABCDEFUL};
  uint64_t dst[6] = {0, 0, 0, 0, 0, 0};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);

  START();
  __ Mov(x17, src_base + 4);
  __ Mov(x28, dst_base + 12);
  __ Mov(x19, src_base + 8);
  __ Mov(x20, dst_base + 16);
  __ Mov(x21, src_base + 8);
  __ Mov(x22, dst_base + 32);
  __ Mov(x23, src_base + 1);
  __ Mov(x24, dst_base + 25);
  __ Mov(x25, src_base + 3);
  __ Mov(x26, dst_base + 41);
  __ Ldr(w0, MemOperand(x17, 4, PostIndex));
  __ Str(w0, MemOperand(x28, 12, PostIndex));
  __ Ldr(x1, MemOperand(x19, 8, PostIndex));
  __ Str(x1, MemOperand(x20, 16, PostIndex));
  __ Ldr(x2, MemOperand(x21, -8, PostIndex));
  __ Str(x2, MemOperand(x22, -32, PostIndex));
  __ Ldrb(w3, MemOperand(x23, 1, PostIndex));
  __ Strb(w3, MemOperand(x24, 5, PostIndex));
  __ Ldrh(w4, MemOperand(x25, -3, PostIndex));
  __ Strh(w4, MemOperand(x26, -41, PostIndex));
  END();

  RUN();

  CHECK_EQUAL_64(0xFEDCBA98, x0);
  CHECK_EQUAL_64(0xFEDCBA9800000000UL, dst[1]);
  CHECK_EQUAL_64(0x0123456789ABCDEFUL, x1);
  CHECK_EQUAL_64(0x0123456789ABCDEFUL, dst[2]);
  CHECK_EQUAL_64(0x0123456789ABCDEFUL, x2);
  CHECK_EQUAL_64(0x0123456789ABCDEFUL, dst[4]);
  CHECK_EQUAL_64(0x32, x3);
  CHECK_EQUAL_64(0x3200, dst[3]);
  CHECK_EQUAL_64(0x9876, x4);
  CHECK_EQUAL_64(0x987600, dst[5]);
  CHECK_EQUAL_64(src_base + 8, x17);
  CHECK_EQUAL_64(dst_base + 24, x28);
  CHECK_EQUAL_64(src_base + 16, x19);
  CHECK_EQUAL_64(dst_base + 32, x20);
  CHECK_EQUAL_64(src_base, x21);
  CHECK_EQUAL_64(dst_base, x22);
  CHECK_EQUAL_64(src_base + 2, x23);
  CHECK_EQUAL_64(dst_base + 30, x24);
  CHECK_EQUAL_64(src_base, x25);
  CHECK_EQUAL_64(dst_base, x26);
}

TEST(load_signed) {
  INIT_V8();
  SETUP();

  uint32_t src[2] = {0x80008080, 0x7FFF7F7F};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x24, src_base);
  __ Ldrsb(w0, MemOperand(x24));
  __ Ldrsb(w1, MemOperand(x24, 4));
  __ Ldrsh(w2, MemOperand(x24));
  __ Ldrsh(w3, MemOperand(x24, 4));
  __ Ldrsb(x4, MemOperand(x24));
  __ Ldrsb(x5, MemOperand(x24, 4));
  __ Ldrsh(x6, MemOperand(x24));
  __ Ldrsh(x7, MemOperand(x24, 4));
  __ Ldrsw(x8, MemOperand(x24));
  __ Ldrsw(x9, MemOperand(x24, 4));
  END();

  RUN();

  CHECK_EQUAL_64(0xFFFFFF80, x0);
  CHECK_EQUAL_64(0x0000007F, x1);
  CHECK_EQUAL_64(0xFFFF8080, x2);
  CHECK_EQUAL_64(0x00007F7F, x3);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFF80UL, x4);
  CHECK_EQUAL_64(0x000000000000007FUL, x5);
  CHECK_EQUAL_64(0xFFFFFFFFFFFF8080UL, x6);
  CHECK_EQUAL_64(0x0000000000007F7FUL, x7);
  CHECK_EQUAL_64(0xFFFFFFFF80008080UL, x8);
  CHECK_EQUAL_64(0x000000007FFF7F7FUL, x9);
}

TEST(load_store_regoffset) {
  INIT_V8();
  SETUP();

  uint32_t src[3] = {1, 2, 3};
  uint32_t dst[4] = {0, 0, 0, 0};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);

  START();
  __ Mov(x16, src_base);
  __ Mov(x17, dst_base);
  __ Mov(x21, src_base + 3 * sizeof(src[0]));
  __ Mov(x19, dst_base + 3 * sizeof(dst[0]));
  __ Mov(x20, dst_base + 4 * sizeof(dst[0]));
  __ Mov(x24, 0);
  __ Mov(x25, 4);
  __ Mov(x26, -4);
  __ Mov(x27, 0xFFFFFFFC);  // 32-bit -4.
  __ Mov(x28, 0xFFFFFFFE);  // 32-bit -2.
  __ Mov(x29, 0xFFFFFFFF);  // 32-bit -1.

  __ Ldr(w0, MemOperand(x16, x24));
  __ Ldr(x1, MemOperand(x16, x25));
  __ Ldr(w2, MemOperand(x21, x26));
  __ Ldr(w3, MemOperand(x21, x27, SXTW));
  __ Ldr(w4, MemOperand(x21, x28, SXTW, 2));
  __ Str(w0, MemOperand(x17, x24));
  __ Str(x1, MemOperand(x17, x25));
  __ Str(w2, MemOperand(x20, x29, SXTW, 2));
  END();

  RUN();

  CHECK_EQUAL_64(1, x0);
  CHECK_EQUAL_64(0x0000000300000002UL, x1);
  CHECK_EQUAL_64(3, x2);
  CHECK_EQUAL_64(3, x3);
  CHECK_EQUAL_64(2, x4);
  CHECK_EQUAL_32(1, dst[0]);
  CHECK_EQUAL_32(2, dst[1]);
  CHECK_EQUAL_32(3, dst[2]);
  CHECK_EQUAL_32(3, dst[3]);
}

TEST(load_store_float) {
  INIT_V8();
  SETUP();

  float src[3] = {1.0, 2.0, 3.0};
  float dst[3] = {0.0, 0.0, 0.0};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, dst_base);
  __ Mov(x19, src_base);
  __ Mov(x20, dst_base);
  __ Mov(x21, src_base);
  __ Mov(x22, dst_base);
  __ Ldr(s0, MemOperand(x17, sizeof(src[0])));
  __ Str(s0, MemOperand(x28, sizeof(dst[0]), PostIndex));
  __ Ldr(s1, MemOperand(x19, sizeof(src[0]), PostIndex));
  __ Str(s1, MemOperand(x20, 2 * sizeof(dst[0]), PreIndex));
  __ Ldr(s2, MemOperand(x21, 2 * sizeof(src[0]), PreIndex));
  __ Str(s2, MemOperand(x22, sizeof(dst[0])));
  END();

  RUN();

  CHECK_EQUAL_FP32(2.0, s0);
  CHECK_EQUAL_FP32(2.0, dst[0]);
  CHECK_EQUAL_FP32(1.0, s1);
  CHECK_EQUAL_FP32(1.0, dst[2]);
  CHECK_EQUAL_FP32(3.0, s2);
  CHECK_EQUAL_FP32(3.0, dst[1]);
  CHECK_EQUAL_64(src_base, x17);
  CHECK_EQUAL_64(dst_base + sizeof(dst[0]), x28);
  CHECK_EQUAL_64(src_base + sizeof(src[0]), x19);
  CHECK_EQUAL_64(dst_base + 2 * sizeof(dst[0]), x20);
  CHECK_EQUAL_64(src_base + 2 * sizeof(src[0]), x21);
  CHECK_EQUAL_64(dst_base, x22);
}

TEST(load_store_double) {
  INIT_V8();
  SETUP();

  double src[3] = {1.0, 2.0, 3.0};
  double dst[3] = {0.0, 0.0, 0.0};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, dst_base);
  __ Mov(x19, src_base);
  __ Mov(x20, dst_base);
  __ Mov(x21, src_base);
  __ Mov(x22, dst_base);
  __ Ldr(d0, MemOperand(x17, sizeof(src[0])));
  __ Str(d0, MemOperand(x28, sizeof(dst[0]), PostIndex));
  __ Ldr(d1, MemOperand(x19, sizeof(src[0]), PostIndex));
  __ Str(d1, MemOperand(x20, 2 * sizeof(dst[0]), PreIndex));
  __ Ldr(d2, MemOperand(x21, 2 * sizeof(src[0]), PreIndex));
  __ Str(d2, MemOperand(x22, sizeof(dst[0])));
  END();

  RUN();

  CHECK_EQUAL_FP64(2.0, d0);
  CHECK_EQUAL_FP64(2.0, dst[0]);
  CHECK_EQUAL_FP64(1.0, d1);
  CHECK_EQUAL_FP64(1.0, dst[2]);
  CHECK_EQUAL_FP64(3.0, d2);
  CHECK_EQUAL_FP64(3.0, dst[1]);
  CHECK_EQUAL_64(src_base, x17);
  CHECK_EQUAL_64(dst_base + sizeof(dst[0]), x28);
  CHECK_EQUAL_64(src_base + sizeof(src[0]), x19);
  CHECK_EQUAL_64(dst_base + 2 * sizeof(dst[0]), x20);
  CHECK_EQUAL_64(src_base + 2 * sizeof(src[0]), x21);
  CHECK_EQUAL_64(dst_base, x22);
}

TEST(load_store_b) {
  INIT_V8();
  SETUP();

  uint8_t src[3] = {0x12, 0x23, 0x34};
  uint8_t dst[3] = {0, 0, 0};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, dst_base);
  __ Mov(x19, src_base);
  __ Mov(x20, dst_base);
  __ Mov(x21, src_base);
  __ Mov(x22, dst_base);
  __ Ldr(b0, MemOperand(x17, sizeof(src[0])));
  __ Str(b0, MemOperand(x28, sizeof(dst[0]), PostIndex));
  __ Ldr(b1, MemOperand(x19, sizeof(src[0]), PostIndex));
  __ Str(b1, MemOperand(x20, 2 * sizeof(dst[0]), PreIndex));
  __ Ldr(b2, MemOperand(x21, 2 * sizeof(src[0]), PreIndex));
  __ Str(b2, MemOperand(x22, sizeof(dst[0])));
  END();

  RUN();

  CHECK_EQUAL_128(0, 0x23, q0);
  CHECK_EQUAL_64(0x23, dst[0]);
  CHECK_EQUAL_128(0, 0x12, q1);
  CHECK_EQUAL_64(0x12, dst[2]);
  CHECK_EQUAL_128(0, 0x34, q2);
  CHECK_EQUAL_64(0x34, dst[1]);
  CHECK_EQUAL_64(src_base, x17);
  CHECK_EQUAL_64(dst_base + sizeof(dst[0]), x28);
  CHECK_EQUAL_64(src_base + sizeof(src[0]), x19);
  CHECK_EQUAL_64(dst_base + 2 * sizeof(dst[0]), x20);
  CHECK_EQUAL_64(src_base + 2 * sizeof(src[0]), x21);
  CHECK_EQUAL_64(dst_base, x22);
}

TEST(load_store_h) {
  INIT_V8();
  SETUP();

  uint16_t src[3] = {0x1234, 0x2345, 0x3456};
  uint16_t dst[3] = {0, 0, 0};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, dst_base);
  __ Mov(x19, src_base);
  __ Mov(x20, dst_base);
  __ Mov(x21, src_base);
  __ Mov(x22, dst_base);
  __ Ldr(h0, MemOperand(x17, sizeof(src[0])));
  __ Str(h0, MemOperand(x28, sizeof(dst[0]), PostIndex));
  __ Ldr(h1, MemOperand(x19, sizeof(src[0]), PostIndex));
  __ Str(h1, MemOperand(x20, 2 * sizeof(dst[0]), PreIndex));
  __ Ldr(h2, MemOperand(x21, 2 * sizeof(src[0]), PreIndex));
  __ Str(h2, MemOperand(x22, sizeof(dst[0])));
  END();

  RUN();

  CHECK_EQUAL_128(0, 0x2345, q0);
  CHECK_EQUAL_64(0x2345, dst[0]);
  CHECK_EQUAL_128(0, 0x1234, q1);
  CHECK_EQUAL_64(0x1234, dst[2]);
  CHECK_EQUAL_128(0, 0x3456, q2);
  CHECK_EQUAL_64(0x3456, dst[1]);
  CHECK_EQUAL_64(src_base, x17);
  CHECK_EQUAL_64(dst_base + sizeof(dst[0]), x28);
  CHECK_EQUAL_64(src_base + sizeof(src[0]), x19);
  CHECK_EQUAL_64(dst_base + 2 * sizeof(dst[0]), x20);
  CHECK_EQUAL_64(src_base + 2 * sizeof(src[0]), x21);
  CHECK_EQUAL_64(dst_base, x22);
}

TEST(load_store_q) {
  INIT_V8();
  SETUP();

  uint8_t src[48] = {0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x01, 0x23,
                     0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x21, 0x43, 0x65, 0x87,
                     0xA9, 0xCB, 0xED, 0x0F, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,
                     0xDE, 0xF0, 0x24, 0x46, 0x68, 0x8A, 0xAC, 0xCE, 0xE0, 0x02,
                     0x42, 0x64, 0x86, 0xA8, 0xCA, 0xEC, 0x0E, 0x20};

  uint64_t dst[6] = {0, 0, 0, 0, 0, 0};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, dst_base);
  __ Mov(x19, src_base);
  __ Mov(x20, dst_base);
  __ Mov(x21, src_base);
  __ Mov(x22, dst_base);
  __ Ldr(q0, MemOperand(x17, 16));
  __ Str(q0, MemOperand(x28, 16, PostIndex));
  __ Ldr(q1, MemOperand(x19, 16, PostIndex));
  __ Str(q1, MemOperand(x20, 32, PreIndex));
  __ Ldr(q2, MemOperand(x21, 32, PreIndex));
  __ Str(q2, MemOperand(x22, 16));
  END();

  RUN();

  CHECK_EQUAL_128(0xF0DEBC9A78563412, 0x0FEDCBA987654321, q0);
  CHECK_EQUAL_64(0x0FEDCBA987654321, dst[0]);
  CHECK_EQUAL_64(0xF0DEBC9A78563412, dst[1]);
  CHECK_EQUAL_128(0xEFCDAB8967452301, 0xFEDCBA9876543210, q1);
  CHECK_EQUAL_64(0xFEDCBA9876543210, dst[4]);
  CHECK_EQUAL_64(0xEFCDAB8967452301, dst[5]);
  CHECK_EQUAL_128(0x200EECCAA8866442, 0x02E0CEAC8A684624, q2);
  CHECK_EQUAL_64(0x02E0CEAC8A684624, dst[2]);
  CHECK_EQUAL_64(0x200EECCAA8866442, dst[3]);
  CHECK_EQUAL_64(src_base, x17);
  CHECK_EQUAL_64(dst_base + 16, x28);
  CHECK_EQUAL_64(src_base + 16, x19);
  CHECK_EQUAL_64(dst_base + 32, x20);
  CHECK_EQUAL_64(src_base + 32, x21);
  CHECK_EQUAL_64(dst_base, x22);
}

TEST(neon_ld1_d) {
  INIT_V8();
  SETUP();

  uint8_t src[32 + 5];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Ldr(q2, MemOperand(x17));  // Initialise top 64-bits of Q register.
  __ Ld1(v2.V8B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld1(v3.V8B(), v4.V8B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld1(v5.V4H(), v6.V4H(), v7.V4H(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld1(v16.V2S(), v17.V2S(), v18.V2S(), v19.V2S(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld1(v30.V2S(), v31.V2S(), v0.V2S(), v1.V2S(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld1(v20.V1D(), v21.V1D(), v22.V1D(), v23.V1D(), MemOperand(x17));
  END();

  RUN();

  CHECK_EQUAL_128(0, 0x0706050403020100, q2);
  CHECK_EQUAL_128(0, 0x0807060504030201, q3);
  CHECK_EQUAL_128(0, 0x100F0E0D0C0B0A09, q4);
  CHECK_EQUAL_128(0, 0x0908070605040302, q5);
  CHECK_EQUAL_128(0, 0x11100F0E0D0C0B0A, q6);
  CHECK_EQUAL_128(0, 0x1918171615141312, q7);
  CHECK_EQUAL_128(0, 0x0A09080706050403, q16);
  CHECK_EQUAL_128(0, 0x1211100F0E0D0C0B, q17);
  CHECK_EQUAL_128(0, 0x1A19181716151413, q18);
  CHECK_EQUAL_128(0, 0x2221201F1E1D1C1B, q19);
  CHECK_EQUAL_128(0, 0x0B0A090807060504, q30);
  CHECK_EQUAL_128(0, 0x131211100F0E0D0C, q31);
  CHECK_EQUAL_128(0, 0x1B1A191817161514, q0);
  CHECK_EQUAL_128(0, 0x232221201F1E1D1C, q1);
  CHECK_EQUAL_128(0, 0x0C0B0A0908070605, q20);
  CHECK_EQUAL_128(0, 0x14131211100F0E0D, q21);
  CHECK_EQUAL_128(0, 0x1C1B1A1918171615, q22);
  CHECK_EQUAL_128(0, 0x24232221201F1E1D, q23);
}

TEST(neon_ld1_d_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[32 + 5];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, src_base + 1);
  __ Mov(x19, src_base + 2);
  __ Mov(x20, src_base + 3);
  __ Mov(x21, src_base + 4);
  __ Mov(x22, src_base + 5);
  __ Mov(x23, 1);
  __ Ldr(q2, MemOperand(x17));  // Initialise top 64-bits of Q register.
  __ Ld1(v2.V8B(), MemOperand(x17, x23, PostIndex));
  __ Ld1(v3.V8B(), v4.V8B(), MemOperand(x28, 16, PostIndex));
  __ Ld1(v5.V4H(), v6.V4H(), v7.V4H(), MemOperand(x19, 24, PostIndex));
  __ Ld1(v16.V2S(), v17.V2S(), v18.V2S(), v19.V2S(),
         MemOperand(x20, 32, PostIndex));
  __ Ld1(v30.V2S(), v31.V2S(), v0.V2S(), v1.V2S(),
         MemOperand(x21, 32, PostIndex));
  __ Ld1(v20.V1D(), v21.V1D(), v22.V1D(), v23.V1D(),
         MemOperand(x22, 32, PostIndex));
  END();

  RUN();

  CHECK_EQUAL_128(0, 0x0706050403020100, q2);
  CHECK_EQUAL_128(0, 0x0807060504030201, q3);
  CHECK_EQUAL_128(0, 0x100F0E0D0C0B0A09, q4);
  CHECK_EQUAL_128(0, 0x0908070605040302, q5);
  CHECK_EQUAL_128(0, 0x11100F0E0D0C0B0A, q6);
  CHECK_EQUAL_128(0, 0x1918171615141312, q7);
  CHECK_EQUAL_128(0, 0x0A09080706050403, q16);
  CHECK_EQUAL_128(0, 0x1211100F0E0D0C0B, q17);
  CHECK_EQUAL_128(0, 0x1A19181716151413, q18);
  CHECK_EQUAL_128(0, 0x2221201F1E1D1C1B, q19);
  CHECK_EQUAL_128(0, 0x0B0A090807060504, q30);
  CHECK_EQUAL_128(0, 0x131211100F0E0D0C, q31);
  CHECK_EQUAL_128(0, 0x1B1A191817161514, q0);
  CHECK_EQUAL_128(0, 0x232221201F1E1D1C, q1);
  CHECK_EQUAL_128(0, 0x0C0B0A0908070605, q20);
  CHECK_EQUAL_128(0, 0x14131211100F0E0D, q21);
  CHECK_EQUAL_128(0, 0x1C1B1A1918171615, q22);
  CHECK_EQUAL_128(0, 0x24232221201F1E1D, q23);
  CHECK_EQUAL_64(src_base + 1, x17);
  CHECK_EQUAL_64(src_base + 1 + 16, x28);
  CHECK_EQUAL_64(src_base + 2 + 24, x19);
  CHECK_EQUAL_64(src_base + 3 + 32, x20);
  CHECK_EQUAL_64(src_base + 4 + 32, x21);
  CHECK_EQUAL_64(src_base + 5 + 32, x22);
}

TEST(neon_ld1_q) {
  INIT_V8();
  SETUP();

  uint8_t src[64 + 4];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Ld1(v2.V16B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld1(v3.V16B(), v4.V16B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld1(v5.V8H(), v6.V8H(), v7.V8H(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld1(v16.V4S(), v17.V4S(), v18.V4S(), v19.V4S(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld1(v30.V2D(), v31.V2D(), v0.V2D(), v1.V2D(), MemOperand(x17));
  END();

  RUN();

  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0706050403020100, q2);
  CHECK_EQUAL_128(0x100F0E0D0C0B0A09, 0x0807060504030201, q3);
  CHECK_EQUAL_128(0x201F1E1D1C1B1A19, 0x1817161514131211, q4);
  CHECK_EQUAL_128(0x11100F0E0D0C0B0A, 0x0908070605040302, q5);
  CHECK_EQUAL_128(0x21201F1E1D1C1B1A, 0x1918171615141312, q6);
  CHECK_EQUAL_128(0x31302F2E2D2C2B2A, 0x2928272625242322, q7);
  CHECK_EQUAL_128(0x1211100F0E0D0C0B, 0x0A09080706050403, q16);
  CHECK_EQUAL_128(0x2221201F1E1D1C1B, 0x1A19181716151413, q17);
  CHECK_EQUAL_128(0x3231302F2E2D2C2B, 0x2A29282726252423, q18);
  CHECK_EQUAL_128(0x4241403F3E3D3C3B, 0x3A39383736353433, q19);
  CHECK_EQUAL_128(0x131211100F0E0D0C, 0x0B0A090807060504, q30);
  CHECK_EQUAL_128(0x232221201F1E1D1C, 0x1B1A191817161514, q31);
  CHECK_EQUAL_128(0x333231302F2E2D2C, 0x2B2A292827262524, q0);
  CHECK_EQUAL_128(0x434241403F3E3D3C, 0x3B3A393837363534, q1);
}

TEST(neon_ld1_q_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[64 + 4];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, src_base + 1);
  __ Mov(x19, src_base + 2);
  __ Mov(x20, src_base + 3);
  __ Mov(x21, src_base + 4);
  __ Mov(x22, 1);
  __ Ld1(v2.V16B(), MemOperand(x17, x22, PostIndex));
  __ Ld1(v3.V16B(), v4.V16B(), MemOperand(x28, 32, PostIndex));
  __ Ld1(v5.V8H(), v6.V8H(), v7.V8H(), MemOperand(x19, 48, PostIndex));
  __ Ld1(v16.V4S(), v17.V4S(), v18.V4S(), v19.V4S(),
         MemOperand(x20, 64, PostIndex));
  __ Ld1(v30.V2D(), v31.V2D(), v0.V2D(), v1.V2D(),
         MemOperand(x21, 64, PostIndex));
  END();

  RUN();

  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0706050403020100, q2);
  CHECK_EQUAL_128(0x100F0E0D0C0B0A09, 0x0807060504030201, q3);
  CHECK_EQUAL_128(0x201F1E1D1C1B1A19, 0x1817161514131211, q4);
  CHECK_EQUAL_128(0x11100F0E0D0C0B0A, 0x0908070605040302, q5);
  CHECK_EQUAL_128(0x21201F1E1D1C1B1A, 0x1918171615141312, q6);
  CHECK_EQUAL_128(0x31302F2E2D2C2B2A, 0x2928272625242322, q7);
  CHECK_EQUAL_128(0x1211100F0E0D0C0B, 0x0A09080706050403, q16);
  CHECK_EQUAL_128(0x2221201F1E1D1C1B, 0x1A19181716151413, q17);
  CHECK_EQUAL_128(0x3231302F2E2D2C2B, 0x2A29282726252423, q18);
  CHECK_EQUAL_128(0x4241403F3E3D3C3B, 0x3A39383736353433, q19);
  CHECK_EQUAL_128(0x131211100F0E0D0C, 0x0B0A090807060504, q30);
  CHECK_EQUAL_128(0x232221201F1E1D1C, 0x1B1A191817161514, q31);
  CHECK_EQUAL_128(0x333231302F2E2D2C, 0x2B2A292827262524, q0);
  CHECK_EQUAL_128(0x434241403F3E3D3C, 0x3B3A393837363534, q1);
  CHECK_EQUAL_64(src_base + 1, x17);
  CHECK_EQUAL_64(src_base + 1 + 32, x28);
  CHECK_EQUAL_64(src_base + 2 + 48, x19);
  CHECK_EQUAL_64(src_base + 3 + 64, x20);
  CHECK_EQUAL_64(src_base + 4 + 64, x21);
}

TEST(neon_ld1_lane) {
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
    __ Ld1(v0.B(), i, MemOperand(x17));
    __ Add(x17, x17, 1);
  }

  __ Mov(x17, src_base);
  for (int i = 7; i >= 0; i--) {
    __ Ld1(v1.H(), i, MemOperand(x17));
    __ Add(x17, x17, 1);
  }

  __ Mov(x17, src_base);
  for (int i = 3; i >= 0; i--) {
    __ Ld1(v2.S(), i, MemOperand(x17));
    __ Add(x17, x17, 1);
  }

  __ Mov(x17, src_base);
  for (int i = 1; i >= 0; i--) {
    __ Ld1(v3.D(), i, MemOperand(x17));
    __ Add(x17, x17, 1);
  }

  // Test loading a single element into an initialised register.
  __ Mov(x17, src_base);
  __ Ldr(q4, MemOperand(x17));
  __ Ld1(v4.B(), 4, MemOperand(x17));
  __ Ldr(q5, MemOperand(x17));
  __ Ld1(v5.H(), 3, MemOperand(x17));
  __ Ldr(q6, MemOperand(x17));
  __ Ld1(v6.S(), 2, MemOperand(x17));
  __ Ldr(q7, MemOperand(x17));
  __ Ld1(v7.D(), 1, MemOperand(x17));

  END();

  RUN();

  CHECK_EQUAL_128(0x0001020304050607, 0x08090A0B0C0D0E0F, q0);
  CHECK_EQUAL_128(0x0100020103020403, 0x0504060507060807, q1);
  CHECK_EQUAL_128(0x0302010004030201, 0x0504030206050403, q2);
  CHECK_EQUAL_128(0x0706050403020100, 0x0807060504030201, q3);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0706050003020100, q4);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0100050403020100, q5);
  CHECK_EQUAL_128(0x0F0E0D0C03020100, 0x0706050403020100, q6);
  CHECK_EQUAL_128(0x0706050403020100, 0x0706050403020100, q7);
}

TEST(neon_ld2_d) {
  INIT_V8();
  SETUP();

  uint8_t src[64 + 4];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Ld2(v2.V8B(), v3.V8B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld2(v4.V8B(), v5.V8B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld2(v6.V4H(), v7.V4H(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld2(v31.V2S(), v0.V2S(), MemOperand(x17));
  END();

  RUN();

  CHECK_EQUAL_128(0, 0x0E0C0A0806040200, q2);
  CHECK_EQUAL_128(0, 0x0F0D0B0907050301, q3);
  CHECK_EQUAL_128(0, 0x0F0D0B0907050301, q4);
  CHECK_EQUAL_128(0, 0x100E0C0A08060402, q5);
  CHECK_EQUAL_128(0, 0x0F0E0B0A07060302, q6);
  CHECK_EQUAL_128(0, 0x11100D0C09080504, q7);
  CHECK_EQUAL_128(0, 0x0E0D0C0B06050403, q31);
  CHECK_EQUAL_128(0, 0x1211100F0A090807, q0);
}

TEST(neon_ld2_d_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[32 + 4];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, src_base + 1);
  __ Mov(x19, src_base + 2);
  __ Mov(x20, src_base + 3);
  __ Mov(x21, src_base + 4);
  __ Mov(x22, 1);
  __ Ld2(v2.V8B(), v3.V8B(), MemOperand(x17, x22, PostIndex));
  __ Ld2(v4.V8B(), v5.V8B(), MemOperand(x28, 16, PostIndex));
  __ Ld2(v5.V4H(), v6.V4H(), MemOperand(x19, 16, PostIndex));
  __ Ld2(v16.V2S(), v17.V2S(), MemOperand(x20, 16, PostIndex));
  __ Ld2(v31.V2S(), v0.V2S(), MemOperand(x21, 16, PostIndex));
  END();

  RUN();

  CHECK_EQUAL_128(0, 0x0E0C0A0806040200, q2);
  CHECK_EQUAL_128(0, 0x0F0D0B0907050301, q3);
  CHECK_EQUAL_128(0, 0x0F0D0B0907050301, q4);
  CHECK_EQUAL_128(0, 0x0F0E0B0A07060302, q5);
  CHECK_EQUAL_128(0, 0x11100D0C09080504, q6);
  CHECK_EQUAL_128(0, 0x0E0D0C0B06050403, q16);
  CHECK_EQUAL_128(0, 0x1211100F0A090807, q17);
  CHECK_EQUAL_128(0, 0x0F0E0D0C07060504, q31);
  CHECK_EQUAL_128(0, 0x131211100B0A0908, q0);

  CHECK_EQUAL_64(src_base + 1, x17);
  CHECK_EQUAL_64(src_base + 1 + 16, x28);
  CHECK_EQUAL_64(src_base + 2 + 16, x19);
  CHECK_EQUAL_64(src_base + 3 + 16, x20);
  CHECK_EQUAL_64(src_base + 4 + 16, x21);
}

TEST(neon_ld2_q) {
  INIT_V8();
  SETUP();

  uint8_t src[64 + 4];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Ld2(v2.V16B(), v3.V16B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld2(v4.V16B(), v5.V16B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld2(v6.V8H(), v7.V8H(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld2(v16.V4S(), v17.V4S(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld2(v31.V2D(), v0.V2D(), MemOperand(x17));
  END();

  RUN();

  CHECK_EQUAL_128(0x1E1C1A1816141210, 0x0E0C0A0806040200, q2);
  CHECK_EQUAL_128(0x1F1D1B1917151311, 0x0F0D0B0907050301, q3);
  CHECK_EQUAL_128(0x1F1D1B1917151311, 0x0F0D0B0907050301, q4);
  CHECK_EQUAL_128(0x201E1C1A18161412, 0x100E0C0A08060402, q5);
  CHECK_EQUAL_128(0x1F1E1B1A17161312, 0x0F0E0B0A07060302, q6);
  CHECK_EQUAL_128(0x21201D1C19181514, 0x11100D0C09080504, q7);
  CHECK_EQUAL_128(0x1E1D1C1B16151413, 0x0E0D0C0B06050403, q16);
  CHECK_EQUAL_128(0x2221201F1A191817, 0x1211100F0A090807, q17);
  CHECK_EQUAL_128(0x1B1A191817161514, 0x0B0A090807060504, q31);
  CHECK_EQUAL_128(0x232221201F1E1D1C, 0x131211100F0E0D0C, q0);
}

TEST(neon_ld2_q_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[64 + 4];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, src_base + 1);
  __ Mov(x19, src_base + 2);
  __ Mov(x20, src_base + 3);
  __ Mov(x21, src_base + 4);
  __ Mov(x22, 1);
  __ Ld2(v2.V16B(), v3.V16B(), MemOperand(x17, x22, PostIndex));
  __ Ld2(v4.V16B(), v5.V16B(), MemOperand(x28, 32, PostIndex));
  __ Ld2(v6.V8H(), v7.V8H(), MemOperand(x19, 32, PostIndex));
  __ Ld2(v16.V4S(), v17.V4S(), MemOperand(x20, 32, PostIndex));
  __ Ld2(v31.V2D(), v0.V2D(), MemOperand(x21, 32, PostIndex));
  END();

  RUN();

  CHECK_EQUAL_128(0x1E1C1A1816141210, 0x0E0C0A0806040200, q2);
  CHECK_EQUAL_128(0x1F1D1B1917151311, 0x0F0D0B0907050301, q3);
  CHECK_EQUAL_128(0x1F1D1B1917151311, 0x0F0D0B0907050301, q4);
  CHECK_EQUAL_128(0x201E1C1A18161412, 0x100E0C0A08060402, q5);
  CHECK_EQUAL_128(0x1F1E1B1A17161312, 0x0F0E0B0A07060302, q6);
  CHECK_EQUAL_128(0x21201D1C19181514, 0x11100D0C09080504, q7);
  CHECK_EQUAL_128(0x1E1D1C1B16151413, 0x0E0D0C0B06050403, q16);
  CHECK_EQUAL_128(0x2221201F1A191817, 0x1211100F0A090807, q17);
  CHECK_EQUAL_128(0x1B1A191817161514, 0x0B0A090807060504, q31);
  CHECK_EQUAL_128(0x232221201F1E1D1C, 0x131211100F0E0D0C, q0);

  CHECK_EQUAL_64(src_base + 1, x17);
  CHECK_EQUAL_64(src_base + 1 + 32, x28);
  CHECK_EQUAL_64(src_base + 2 + 32, x19);
  CHECK_EQUAL_64(src_base + 3 + 32, x20);
  CHECK_EQUAL_64(src_base + 4 + 32, x21);
}

TEST(neon_ld2_lane) {
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
    __ Ld2(v0.B(), v1.B(), i, MemOperand(x17));
    __ Add(x17, x17, 1);
  }

  __ Mov(x17, src_base);
  for (int i = 7; i >= 0; i--) {
    __ Ld2(v2.H(), v3.H(), i, MemOperand(x17));
    __ Add(x17, x17, 1);
  }

  __ Mov(x17, src_base);
  for (int i = 3; i >= 0; i--) {
    __ Ld2(v4.S(), v5.S(), i, MemOperand(x17));
    __ Add(x17, x17, 1);
  }

  __ Mov(x17, src_base);
  for (int i = 1; i >= 0; i--) {
    __ Ld2(v6.D(), v7.D(), i, MemOperand(x17));
    __ Add(x17, x17, 1);
  }

  // Test loading a single element into an initialised register.
  __ Mov(x17, src_base);
  __ Mov(x4, x17);
  __ Ldr(q8, MemOperand(x4, 16, PostIndex));
  __ Ldr(q9, MemOperand(x4));
  __ Ld2(v8_.B(), v9.B(), 4, MemOperand(x17));
  __ Mov(x5, x17);
  __ Ldr(q10, MemOperand(x5, 16, PostIndex));
  __ Ldr(q11, MemOperand(x5));
  __ Ld2(v10.H(), v11.H(), 3, MemOperand(x17));
  __ Mov(x6, x17);
  __ Ldr(q12, MemOperand(x6, 16, PostIndex));
  __ Ldr(q13, MemOperand(x6));
  __ Ld2(v12.S(), v13.S(), 2, MemOperand(x17));
  __ Mov(x7, x17);
  __ Ldr(q14, MemOperand(x7, 16, PostIndex));
  __ Ldr(q15, MemOperand(x7));
  __ Ld2(v14.D(), v15.D(), 1, MemOperand(x17));

  END();

  RUN();

  CHECK_EQUAL_128(0x0001020304050607, 0x08090A0B0C0D0E0F, q0);
  CHECK_EQUAL_128(0x0102030405060708, 0x090A0B0C0D0E0F10, q1);
  CHECK_EQUAL_128(0x0100020103020403, 0x0504060507060807, q2);
  CHECK_EQUAL_128(0x0302040305040605, 0x0706080709080A09, q3);
  CHECK_EQUAL_128(0x0302010004030201, 0x0504030206050403, q4);
  CHECK_EQUAL_128(0x0706050408070605, 0x090807060A090807, q5);
  CHECK_EQUAL_128(0x0706050403020100, 0x0807060504030201, q6);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x100F0E0D0C0B0A09, q7);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0706050003020100, q8);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x1716150113121110, q9);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0100050403020100, q10);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x0302151413121110, q11);
  CHECK_EQUAL_128(0x0F0E0D0C03020100, 0x0706050403020100, q12);
  CHECK_EQUAL_128(0x1F1E1D1C07060504, 0x1716151413121110, q13);
  CHECK_EQUAL_128(0x0706050403020100, 0x0706050403020100, q14);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x1716151413121110, q15);
}

TEST(neon_ld2_lane_postindex) {
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
    __ Ld2(v0.B(), v1.B(), i, MemOperand(x17, 2, PostIndex));
  }

  for (int i = 7; i >= 0; i--) {
    __ Ld2(v2.H(), v3.H(), i, MemOperand(x28, 4, PostIndex));
  }

  for (int i = 3; i >= 0; i--) {
    __ Ld2(v4.S(), v5.S(), i, MemOperand(x19, 8, PostIndex));
  }

  for (int i = 1; i >= 0; i--) {
    __ Ld2(v6.D(), v7.D(), i, MemOperand(x20, 16, PostIndex));
  }

  // Test loading a single element into an initialised register.
  __ Mov(x25, 1);
  __ Mov(x4, x21);
  __ Ldr(q8, MemOperand(x4, 16, PostIndex));
  __ Ldr(q9, MemOperand(x4));
  __ Ld2(v8_.B(), v9.B(), 4, MemOperand(x21, x25, PostIndex));
  __ Add(x25, x25, 1);

  __ Mov(x5, x22);
  __ Ldr(q10, MemOperand(x5, 16, PostIndex));
  __ Ldr(q11, MemOperand(x5));
  __ Ld2(v10.H(), v11.H(), 3, MemOperand(x22, x25, PostIndex));
  __ Add(x25, x25, 1);

  __ Mov(x6, x23);
  __ Ldr(q12, MemOperand(x6, 16, PostIndex));
  __ Ldr(q13, MemOperand(x6));
  __ Ld2(v12.S(), v13.S(), 2, MemOperand(x23, x25, PostIndex));
  __ Add(x25, x25, 1);

  __ Mov(x7, x24);
  __ Ldr(q14, MemOperand(x7, 16, PostIndex));
  __ Ldr(q15, MemOperand(x7));
  __ Ld2(v14.D(), v15.D(), 1, MemOperand(x24, x25, PostIndex));

  END();

  RUN();

  CHECK_EQUAL_128(0x00020406080A0C0E, 0x10121416181A1C1E, q0);
  CHECK_EQUAL_128(0x01030507090B0D0F, 0x11131517191B1D1F, q1);
  CHECK_EQUAL_128(0x0100050409080D0C, 0x1110151419181D1C, q2);
  CHECK_EQUAL_128(0x030207060B0A0F0E, 0x131217161B1A1F1E, q3);
  CHECK_EQUAL_128(0x030201000B0A0908, 0x131211101B1A1918, q4);
  CHECK_EQUAL_128(0x070605040F0E0D0C, 0x171615141F1E1D1C, q5);
  CHECK_EQUAL_128(0x0706050403020100, 0x1716151413121110, q6);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x1F1E1D1C1B1A1918, q7);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0706050003020100, q8);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x1716150113121110, q9);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0100050403020100, q10);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x0302151413121110, q11);
  CHECK_EQUAL_128(0x0F0E0D0C03020100, 0x0706050403020100, q12);
  CHECK_EQUAL_128(0x1F1E1D1C07060504, 0x1716151413121110, q13);
  CHECK_EQUAL_128(0x0706050403020100, 0x0706050403020100, q14);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x1716151413121110, q15);

  CHECK_EQUAL_64(src_base + 32, x17);
  CHECK_EQUAL_64(src_base + 32, x28);
  CHECK_EQUAL_64(src_base + 32, x19);
  CHECK_EQUAL_64(src_base + 32, x20);
  CHECK_EQUAL_64(src_base + 1, x21);
  CHECK_EQUAL_64(src_base + 2, x22);
  CHECK_EQUAL_64(src_base + 3, x23);
  CHECK_EQUAL_64(src_base + 4, x24);
}

TEST(neon_ld2_alllanes) {
  INIT_V8();
  SETUP();

  uint8_t src[64];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base + 1);
  __ Ld2r(v0.V8B(), v1.V8B(), MemOperand(x17));
  __ Add(x17, x17, 2);
  __ Ld2r(v2.V16B(), v3.V16B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld2r(v4.V4H(), v5.V4H(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld2r(v6.V8H(), v7.V8H(), MemOperand(x17));
  __ Add(x17, x17, 4);
  __ Ld2r(v8_.V2S(), v9.V2S(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld2r(v10.V4S(), v11.V4S(), MemOperand(x17));
  __ Add(x17, x17, 8);
  __ Ld2r(v12.V2D(), v13.V2D(), MemOperand(x17));
  END();

  RUN();

  CHECK_EQUAL_128(0x0000000000000000, 0x0101010101010101, q0);
  CHECK_EQUAL_128(0x0000000000000000, 0x0202020202020202, q1);
  CHECK_EQUAL_128(0x0303030303030303, 0x0303030303030303, q2);
  CHECK_EQUAL_128(0x0404040404040404, 0x0404040404040404, q3);
  CHECK_EQUAL_128(0x0000000000000000, 0x0504050405040504, q4);
  CHECK_EQUAL_128(0x0000000000000000, 0x0706070607060706, q5);
  CHECK_EQUAL_128(0x0605060506050605, 0x0605060506050605, q6);
  CHECK_EQUAL_128(0x0807080708070807, 0x0807080708070807, q7);
  CHECK_EQUAL_128(0x0000000000000000, 0x0C0B0A090C0B0A09, q8);
  CHECK_EQUAL_128(0x0000000000000000, 0x100F0E0D100F0E0D, q9);
  CHECK_EQUAL_128(0x0D0C0B0A0D0C0B0A, 0x0D0C0B0A0D0C0B0A, q10);
  CHECK_EQUAL_128(0x11100F0E11100F0E, 0x11100F0E11100F0E, q11);
  CHECK_EQUAL_128(0x1918171615141312, 0x1918171615141312, q12);
  CHECK_EQUAL_128(0x21201F1E1D1C1B1A, 0x21201F1E1D1C1B1A, q13);
}

TEST(neon_ld2_alllanes_postindex) {
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
  __ Ld2r(v0.V8B(), v1.V8B(), MemOperand(x17, 2, PostIndex));
  __ Ld2r(v2.V16B(), v3.V16B(), MemOperand(x17, x19, PostIndex));
  __ Ld2r(v4.V4H(), v5.V4H(), MemOperand(x17, x19, PostIndex));
  __ Ld2r(v6.V8H(), v7.V8H(), MemOperand(x17, 4, PostIndex));
  __ Ld2r(v8_.V2S(), v9.V2S(), MemOperand(x17, x19, PostIndex));
  __ Ld2r(v10.V4S(), v11.V4S(), MemOperand(x17, 8, PostIndex));
  __ Ld2r(v12.V2D(), v13.V2D(), MemOperand(x17, 16, PostIndex));
  END();

  RUN();

  CHECK_EQUAL_128(0x0000000000000000, 0x0101010101010101, q0);
  CHECK_EQUAL_128(0x0000000000000000, 0x0202020202020202, q1);
  CHECK_EQUAL_128(0x0303030303030303, 0x0303030303030303, q2);
  CHECK_EQUAL_128(0x0404040404040404, 0x0404040404040404, q3);
  CHECK_EQUAL_128(0x0000000000000000, 0x0504050405040504, q4);
  CHECK_EQUAL_128(0x0000000000000000, 0x0706070607060706, q5);
  CHECK_EQUAL_128(0x0605060506050605, 0x0605060506050605, q6);
  CHECK_EQUAL_128(0x0807080708070807, 0x0807080708070807, q7);
  CHECK_EQUAL_128(0x0000000000000000, 0x0C0B0A090C0B0A09, q8);
  CHECK_EQUAL_128(0x0000000000000000, 0x100F0E0D100F0E0D, q9);
  CHECK_EQUAL_128(0x0D0C0B0A0D0C0B0A, 0x0D0C0B0A0D0C0B0A, q10);
  CHECK_EQUAL_128(0x11100F0E11100F0E, 0x11100F0E11100F0E, q11);
  CHECK_EQUAL_128(0x1918171615141312, 0x1918171615141312, q12);
  CHECK_EQUAL_128(0x21201F1E1D1C1B1A, 0x21201F1E1D1C1B1A, q13);
  CHECK_EQUAL_64(src_base + 34, x17);
}

TEST(neon_ld3_d) {
  INIT_V8();
  SETUP();

  uint8_t src[64 + 4];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Ld3(v2.V8B(), v3.V8B(), v4.V8B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld3(v5.V8B(), v6.V8B(), v7.V8B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld3(v8_.V4H(), v9.V4H(), v10.V4H(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld3(v31.V2S(), v0.V2S(), v1.V2S(), MemOperand(x17));
  END();

  RUN();

  CHECK_EQUAL_128(0, 0x15120F0C09060300, q2);
  CHECK_EQUAL_128(0, 0x1613100D0A070401, q3);
  CHECK_EQUAL_128(0, 0x1714110E0B080502, q4);
  CHECK_EQUAL_128(0, 0x1613100D0A070401, q5);
  CHECK_EQUAL_128(0, 0x1714110E0B080502, q6);
  CHECK_EQUAL_128(0, 0x1815120F0C090603, q7);
  CHECK_EQUAL_128(0, 0x15140F0E09080302, q8);
  CHECK_EQUAL_128(0, 0x171611100B0A0504, q9);
  CHECK_EQUAL_128(0, 0x191813120D0C0706, q10);
  CHECK_EQUAL_128(0, 0x1211100F06050403, q31);
  CHECK_EQUAL_128(0, 0x161514130A090807, q0);
  CHECK_EQUAL_128(0, 0x1A1918170E0D0C0B, q1);
}

TEST(neon_ld3_d_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[32 + 4];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, src_base + 1);
  __ Mov(x19, src_base + 2);
  __ Mov(x20, src_base + 3);
  __ Mov(x21, src_base + 4);
  __ Mov(x22, 1);
  __ Ld3(v2.V8B(), v3.V8B(), v4.V8B(), MemOperand(x17, x22, PostIndex));
  __ Ld3(v5.V8B(), v6.V8B(), v7.V8B(), MemOperand(x28, 24, PostIndex));
  __ Ld3(v8_.V4H(), v9.V4H(), v10.V4H(), MemOperand(x19, 24, PostIndex));
  __ Ld3(v11.V2S(), v12.V2S(), v13.V2S(), MemOperand(x20, 24, PostIndex));
  __ Ld3(v31.V2S(), v0.V2S(), v1.V2S(), MemOperand(x21, 24, PostIndex));
  END();

  RUN();

  CHECK_EQUAL_128(0, 0x15120F0C09060300, q2);
  CHECK_EQUAL_128(0, 0x1613100D0A070401, q3);
  CHECK_EQUAL_128(0, 0x1714110E0B080502, q4);
  CHECK_EQUAL_128(0, 0x1613100D0A070401, q5);
  CHECK_EQUAL_128(0, 0x1714110E0B080502, q6);
  CHECK_EQUAL_128(0, 0x1815120F0C090603, q7);
  CHECK_EQUAL_128(0, 0x15140F0E09080302, q8);
  CHECK_EQUAL_128(0, 0x171611100B0A0504, q9);
  CHECK_EQUAL_128(0, 0x191813120D0C0706, q10);
  CHECK_EQUAL_128(0, 0x1211100F06050403, q11);
  CHECK_EQUAL_128(0, 0x161514130A090807, q12);
  CHECK_EQUAL_128(0, 0x1A1918170E0D0C0B, q13);
  CHECK_EQUAL_128(0, 0x1312111007060504, q31);
  CHECK_EQUAL_128(0, 0x171615140B0A0908, q0);
  CHECK_EQUAL_128(0, 0x1B1A19180F0E0D0C, q1);

  CHECK_EQUAL_64(src_base + 1, x17);
  CHECK_EQUAL_64(src_base + 1 + 24, x28);
  CHECK_EQUAL_64(src_base + 2 + 24, x19);
  CHECK_EQUAL_64(src_base + 3 + 24, x20);
  CHECK_EQUAL_64(src_base + 4 + 24, x21);
}

TEST(neon_ld3_q) {
  INIT_V8();
  SETUP();

  uint8_t src[64 + 4];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Ld3(v2.V16B(), v3.V16B(), v4.V16B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld3(v5.V16B(), v6.V16B(), v7.V16B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld3(v8_.V8H(), v9.V8H(), v10.V8H(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld3(v11.V4S(), v12.V4S(), v13.V4S(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld3(v31.V2D(), v0.V2D(), v1.V2D(), MemOperand(x17));
  END();

  RUN();

  CHECK_EQUAL_128(0x2D2A2724211E1B18, 0x15120F0C09060300, q2);
  CHECK_EQUAL_128(0x2E2B2825221F1C19, 0x1613100D0A070401, q3);
  CHECK_EQUAL_128(0x2F2C292623201D1A, 0x1714110E0B080502, q4);
  CHECK_EQUAL_128(0x2E2B2825221F1C19, 0x1613100D0A070401, q5);
  CHECK_EQUAL_128(0x2F2C292623201D1A, 0x1714110E0B080502, q6);
  CHECK_EQUAL_128(0x302D2A2724211E1B, 0x1815120F0C090603, q7);
  CHECK_EQUAL_128(0x2D2C272621201B1A, 0x15140F0E09080302, q8);
  CHECK_EQUAL_128(0x2F2E292823221D1C, 0x171611100B0A0504, q9);
  CHECK_EQUAL_128(0x31302B2A25241F1E, 0x191813120D0C0706, q10);
  CHECK_EQUAL_128(0x2A2928271E1D1C1B, 0x1211100F06050403, q11);
  CHECK_EQUAL_128(0x2E2D2C2B2221201F, 0x161514130A090807, q12);
  CHECK_EQUAL_128(0x3231302F26252423, 0x1A1918170E0D0C0B, q13);
  CHECK_EQUAL_128(0x232221201F1E1D1C, 0x0B0A090807060504, q31);
  CHECK_EQUAL_128(0x2B2A292827262524, 0x131211100F0E0D0C, q0);
  CHECK_EQUAL_128(0x333231302F2E2D2C, 0x1B1A191817161514, q1);
}

TEST(neon_ld3_q_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[64 + 4];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, src_base + 1);
  __ Mov(x19, src_base + 2);
  __ Mov(x20, src_base + 3);
  __ Mov(x21, src_base + 4);
  __ Mov(x22, 1);

  __ Ld3(v2.V16B(), v3.V16B(), v4.V16B(), MemOperand(x17, x22, PostIndex));
  __ Ld3(v5.V16B(), v6.V16B(), v7.V16B(), MemOperand(x28, 48, PostIndex));
  __ Ld3(v8_.V8H(), v9.V8H(), v10.V8H(), MemOperand(x19, 48, PostIndex));
  __ Ld3(v11.V4S(), v12.V4S(), v13.V4S(), MemOperand(x20, 48, PostIndex));
  __ Ld3(v31.V2D(), v0.V2D(), v1.V2D(), MemOperand(x21, 48, PostIndex));
  END();

  RUN();

  CHECK_EQUAL_128(0x2D2A2724211E1B18, 0x15120F0C09060300, q2);
  CHECK_EQUAL_128(0x2E2B2825221F1C19, 0x1613100D0A070401, q3);
  CHECK_EQUAL_128(0x2F2C292623201D1A, 0x1714110E0B080502, q4);
  CHECK_EQUAL_128(0x2E2B2825221F1C19, 0x1613100D0A070401, q5);
  CHECK_EQUAL_128(0x2F2C292623201D1A, 0x1714110E0B080502, q6);
  CHECK_EQUAL_128(0x302D2A2724211E1B, 0x1815120F0C090603, q7);
  CHECK_EQUAL_128(0x2D2C272621201B1A, 0x15140F0E09080302, q8);
  CHECK_EQUAL_128(0x2F2E292823221D1C, 0x171611100B0A0504, q9);
  CHECK_EQUAL_128(0x31302B2A25241F1E, 0x191813120D0C0706, q10);
  CHECK_EQUAL_128(0x2A2928271E1D1C1B, 0x1211100F06050403, q11);
  CHECK_EQUAL_128(0x2E2D2C2B2221201F, 0x161514130A090807, q12);
  CHECK_EQUAL_128(0x3231302F26252423, 0x1A1918170E0D0C0B, q13);
  CHECK_EQUAL_128(0x232221201F1E1D1C, 0x0B0A090807060504, q31);
  CHECK_EQUAL_128(0x2B2A292827262524, 0x131211100F0E0D0C, q0);
  CHECK_EQUAL_128(0x333231302F2E2D2C, 0x1B1A191817161514, q1);

  CHECK_EQUAL_64(src_base + 1, x17);
  CHECK_EQUAL_64(src_base + 1 + 48, x28);
  CHECK_EQUAL_64(src_base + 2 + 48, x19);
  CHECK_EQUAL_64(src_base + 3 + 48, x20);
  CHECK_EQUAL_64(src_base + 4 + 48, x21);
}

TEST(neon_ld3_lane) {
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
    __ Ld3(v0.B(), v1.B(), v2.B(), i, MemOperand(x17));
    __ Add(x17, x17, 1);
  }

  __ Mov(x17, src_base);
  for (int i = 7; i >= 0; i--) {
    __ Ld3(v3.H(), v4.H(), v5.H(), i, MemOperand(x17));
    __ Add(x17, x17, 1);
  }

  __ Mov(x17, src_base);
  for (int i = 3; i >= 0; i--) {
    __ Ld3(v6.S(), v7.S(), v8_.S(), i, MemOperand(x17));
    __ Add(x17, x17, 1);
  }

  __ Mov(x17, src_base);
  for (int i = 1; i >= 0; i--) {
    __ Ld3(v9.D(), v10.D(), v11.D(), i, MemOperand(x17));
    __ Add(x17, x17, 1);
  }

  // Test loading a single element into an initialised register.
  __ Mov(x17, src_base);
  __ Mov(x4, x17);
  __ Ldr(q12, MemOperand(x4, 16, PostIndex));
  __ Ldr(q13, MemOperand(x4, 16, PostIndex));
  __ Ldr(q14, MemOperand(x4));
  __ Ld3(v12.B(), v13.B(), v14.B(), 4, MemOperand(x17));
  __ Mov(x5, x17);
  __ Ldr(q15, MemOperand(x5, 16, PostIndex));
  __ Ldr(q16, MemOperand(x5, 16, PostIndex));
  __ Ldr(q17, MemOperand(x5));
  __ Ld3(v15.H(), v16.H(), v17.H(), 3, MemOperand(x17));
  __ Mov(x6, x17);
  __ Ldr(q18, MemOperand(x6, 16, PostIndex));
  __ Ldr(q19, MemOperand(x6, 16, PostIndex));
  __ Ldr(q20, MemOperand(x6));
  __ Ld3(v18.S(), v19.S(), v20.S(), 2, MemOperand(x17));
  __ Mov(x7, x17);
  __ Ldr(q21, MemOperand(x7, 16, PostIndex));
  __ Ldr(q22, MemOperand(x7, 16, PostIndex));
  __ Ldr(q23, MemOperand(x7));
  __ Ld3(v21.D(), v22.D(), v23.D(), 1, MemOperand(x17));

  END();

  RUN();

  CHECK_EQUAL_128(0x0001020304050607, 0x08090A0B0C0D0E0F, q0);
  CHECK_EQUAL_128(0x0102030405060708, 0x090A0B0C0D0E0F10, q1);
  CHECK_EQUAL_128(0x0203040506070809, 0x0A0B0C0D0E0F1011, q2);
  CHECK_EQUAL_128(0x0100020103020403, 0x0504060507060807, q3);
  CHECK_EQUAL_128(0x0302040305040605, 0x0706080709080A09, q4);
  CHECK_EQUAL_128(0x0504060507060807, 0x09080A090B0A0C0B, q5);
  CHECK_EQUAL_128(0x0302010004030201, 0x0504030206050403, q6);
  CHECK_EQUAL_128(0x0706050408070605, 0x090807060A090807, q7);
  CHECK_EQUAL_128(0x0B0A09080C0B0A09, 0x0D0C0B0A0E0D0C0B, q8);
  CHECK_EQUAL_128(0x0706050403020100, 0x0807060504030201, q9);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x100F0E0D0C0B0A09, q10);
  CHECK_EQUAL_128(0x1716151413121110, 0x1817161514131211, q11);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0706050003020100, q12);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x1716150113121110, q13);
  CHECK_EQUAL_128(0x2F2E2D2C2B2A2928, 0x2726250223222120, q14);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0100050403020100, q15);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x0302151413121110, q16);
  CHECK_EQUAL_128(0x2F2E2D2C2B2A2928, 0x0504252423222120, q17);
}

TEST(neon_ld3_lane_postindex) {
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
  __ Mov(x28, src_base);
  __ Mov(x19, src_base);
  __ Mov(x20, src_base);
  __ Mov(x21, src_base);
  __ Mov(x22, src_base);
  __ Mov(x23, src_base);
  __ Mov(x24, src_base);
  for (int i = 15; i >= 0; i--) {
    __ Ld3(v0.B(), v1.B(), v2.B(), i, MemOperand(x17, 3, PostIndex));
  }

  for (int i = 7; i >= 0; i--) {
    __ Ld3(v3.H(), v4.H(), v5.H(), i, MemOperand(x28, 6, PostIndex));
  }

  for (int i = 3; i >= 0; i--) {
    __ Ld3(v6.S(), v7.S(), v8_.S(), i, MemOperand(x19, 12, PostIndex));
  }

  for (int i = 1; i >= 0; i--) {
    __ Ld3(v9.D(), v10.D(), v11.D(), i, MemOperand(x20, 24, PostIndex));
  }

  // Test loading a single element into an initialised register.
  __ Mov(x25, 1);
  __ Mov(x4, x21);
  __ Ldr(q12, MemOperand(x4, 16, PostIndex));
  __ Ldr(q13, MemOperand(x4, 16, PostIndex));
  __ Ldr(q14, MemOperand(x4));
  __ Ld3(v12.B(), v13.B(), v14.B(), 4, MemOperand(x21, x25, PostIndex));
  __ Add(x25, x25, 1);

  __ Mov(x5, x22);
  __ Ldr(q15, MemOperand(x5, 16, PostIndex));
  __ Ldr(q16, MemOperand(x5, 16, PostIndex));
  __ Ldr(q17, MemOperand(x5));
  __ Ld3(v15.H(), v16.H(), v17.H(), 3, MemOperand(x22, x25, PostIndex));
  __ Add(x25, x25, 1);

  __ Mov(x6, x23);
  __ Ldr(q18, MemOperand(x6, 16, PostIndex));
  __ Ldr(q19, MemOperand(x6, 16, PostIndex));
  __ Ldr(q20, MemOperand(x6));
  __ Ld3(v18.S(), v19.S(), v20.S(), 2, MemOperand(x23, x25, PostIndex));
  __ Add(x25, x25, 1);

  __ Mov(x7, x24);
  __ Ldr(q21, MemOperand(x7, 16, PostIndex));
  __ Ldr(q22, MemOperand(x7, 16, PostIndex));
  __ Ldr(q23, MemOperand(x7));
  __ Ld3(v21.D(), v22.D(), v23.D(), 1, MemOperand(x24, x25, PostIndex));

  END();

  RUN();

  CHECK_EQUAL_128(0x000306090C0F1215, 0x181B1E2124272A2D, q0);
  CHECK_EQUAL_128(0x0104070A0D101316, 0x191C1F2225282B2E, q1);
  CHECK_EQUAL_128(0x0205080B0E111417, 0x1A1D202326292C2F, q2);
  CHECK_EQUAL_128(0x010007060D0C1312, 0x19181F1E25242B2A, q3);
  CHECK_EQUAL_128(0x030209080F0E1514, 0x1B1A212027262D2C, q4);
  CHECK_EQUAL_128(0x05040B0A11101716, 0x1D1C232229282F2E, q5);
  CHECK_EQUAL_128(0x030201000F0E0D0C, 0x1B1A191827262524, q6);
  CHECK_EQUAL_128(0x0706050413121110, 0x1F1E1D1C2B2A2928, q7);
  CHECK_EQUAL_128(0x0B0A090817161514, 0x232221202F2E2D2C, q8);
  CHECK_EQUAL_128(0x0706050403020100, 0x1F1E1D1C1B1A1918, q9);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x2726252423222120, q10);
  CHECK_EQUAL_128(0x1716151413121110, 0x2F2E2D2C2B2A2928, q11);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0706050003020100, q12);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x1716150113121110, q13);
  CHECK_EQUAL_128(0x2F2E2D2C2B2A2928, 0x2726250223222120, q14);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0100050403020100, q15);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x0302151413121110, q16);
  CHECK_EQUAL_128(0x2F2E2D2C2B2A2928, 0x0504252423222120, q17);
  CHECK_EQUAL_128(0x0F0E0D0C03020100, 0x0706050403020100, q18);
  CHECK_EQUAL_128(0x1F1E1D1C07060504, 0x1716151413121110, q19);
  CHECK_EQUAL_128(0x2F2E2D2C0B0A0908, 0x2726252423222120, q20);
  CHECK_EQUAL_128(0x0706050403020100, 0x0706050403020100, q21);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x1716151413121110, q22);
  CHECK_EQUAL_128(0x1716151413121110, 0x2726252423222120, q23);

  CHECK_EQUAL_64(src_base + 48, x17);
  CHECK_EQUAL_64(src_base + 48, x28);
  CHECK_EQUAL_64(src_base + 48, x19);
  CHECK_EQUAL_64(src_base + 48, x20);
  CHECK_EQUAL_64(src_base + 1, x21);
  CHECK_EQUAL_64(src_base + 2, x22);
  CHECK_EQUAL_64(src_base + 3, x23);
  CHECK_EQUAL_64(src_base + 4, x24);
}

TEST(neon_ld3_alllanes) {
  INIT_V8();
  SETUP();

  uint8_t src[64];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base + 1);
  __ Ld3r(v0.V8B(), v1.V8B(), v2.V8B(), MemOperand(x17));
  __ Add(x17, x17, 3);
  __ Ld3r(v3.V16B(), v4.V16B(), v5.V16B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld3r(v6.V4H(), v7.V4H(), v8_.V4H(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld3r(v9.V8H(), v10.V8H(), v11.V8H(), MemOperand(x17));
  __ Add(x17, x17, 6);
  __ Ld3r(v12.V2S(), v13.V2S(), v14.V2S(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld3r(v15.V4S(), v16.V4S(), v17.V4S(), MemOperand(x17));
  __ Add(x17, x17, 12);
  __ Ld3r(v18.V2D(), v19.V2D(), v20.V2D(), MemOperand(x17));
  END();

  RUN();

  CHECK_EQUAL_128(0x0000000000000000, 0x0101010101010101, q0);
  CHECK_EQUAL_128(0x0000000000000000, 0x0202020202020202, q1);
  CHECK_EQUAL_128(0x0000000000000000, 0x0303030303030303, q2);
  CHECK_EQUAL_128(0x0404040404040404, 0x0404040404040404, q3);
  CHECK_EQUAL_128(0x0505050505050505, 0x0505050505050505, q4);
  CHECK_EQUAL_128(0x0606060606060606, 0x0606060606060606, q5);
  CHECK_EQUAL_128(0x0000000000000000, 0x0605060506050605, q6);
  CHECK_EQUAL_128(0x0000000000000000, 0x0807080708070807, q7);
  CHECK_EQUAL_128(0x0000000000000000, 0x0A090A090A090A09, q8);
  CHECK_EQUAL_128(0x0706070607060706, 0x0706070607060706, q9);
  CHECK_EQUAL_128(0x0908090809080908, 0x0908090809080908, q10);
  CHECK_EQUAL_128(0x0B0A0B0A0B0A0B0A, 0x0B0A0B0A0B0A0B0A, q11);
  CHECK_EQUAL_128(0x0000000000000000, 0x0F0E0D0C0F0E0D0C, q12);
  CHECK_EQUAL_128(0x0000000000000000, 0x1312111013121110, q13);
  CHECK_EQUAL_128(0x0000000000000000, 0x1716151417161514, q14);
  CHECK_EQUAL_128(0x100F0E0D100F0E0D, 0x100F0E0D100F0E0D, q15);
  CHECK_EQUAL_128(0x1413121114131211, 0x1413121114131211, q16);
  CHECK_EQUAL_128(0x1817161518171615, 0x1817161518171615, q17);
  CHECK_EQUAL_128(0x201F1E1D1C1B1A19, 0x201F1E1D1C1B1A19, q18);
  CHECK_EQUAL_128(0x2827262524232221, 0x2827262524232221, q19);
  CHECK_EQUAL_128(0x302F2E2D2C2B2A29, 0x302F2E2D2C2B2A29, q20);
}

TEST(neon_ld3_alllanes_postindex) {
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
  __ Ld3r(v0.V8B(), v1.V8B(), v2.V8B(), MemOperand(x17, 3, PostIndex));
  __ Ld3r(v3.V16B(), v4.V16B(), v5.V16B(), MemOperand(x17, x19, PostIndex));
  __ Ld3r(v6.V4H(), v7.V4H(), v8_.V4H(), MemOperand(x17, x19, PostIndex));
  __ Ld3r(v9.V8H(), v10.V8H(), v11.V8H(), MemOperand(x17, 6, PostIndex));
  __ Ld3r(v12.V2S(), v13.V2S(), v14.V2S(), MemOperand(x17, x19, PostIndex));
  __ Ld3r(v15.V4S(), v16.V4S(), v17.V4S(), MemOperand(x17, 12, PostIndex));
  __ Ld3r(v18.V2D(), v19.V2D(), v20.V2D(), MemOperand(x17, 24, PostIndex));
  END();

  RUN();

  CHECK_EQUAL_128(0x0000000000000000, 0x0101010101010101, q0);
  CHECK_EQUAL_128(0x0000000000000000, 0x0202020202020202, q1);
  CHECK_EQUAL_128(0x0000000000000000, 0x0303030303030303, q2);
  CHECK_EQUAL_128(0x0404040404040404, 0x0404040404040404, q3);
  CHECK_EQUAL_128(0x0505050505050505, 0x0505050505050505, q4);
  CHECK_EQUAL_128(0x0606060606060606, 0x0606060606060606, q5);
  CHECK_EQUAL_128(0x0000000000000000, 0x0605060506050605, q6);
  CHECK_EQUAL_128(0x0000000000000000, 0x0807080708070807, q7);
  CHECK_EQUAL_128(0x0000000000000000, 0x0A090A090A090A09, q8);
  CHECK_EQUAL_128(0x0706070607060706, 0x0706070607060706, q9);
  CHECK_EQUAL_128(0x0908090809080908, 0x0908090809080908, q10);
  CHECK_EQUAL_128(0x0B0A0B0A0B0A0B0A, 0x0B0A0B0A0B0A0B0A, q11);
  CHECK_EQUAL_128(0x0000000000000000, 0x0F0E0D0C0F0E0D0C, q12);
  CHECK_EQUAL_128(0x0000000000000000, 0x1312111013121110, q13);
  CHECK_EQUAL_128(0x0000000000000000, 0x1716151417161514, q14);
  CHECK_EQUAL_128(0x100F0E0D100F0E0D, 0x100F0E0D100F0E0D, q15);
  CHECK_EQUAL_128(0x1413121114131211, 0x1413121114131211, q16);
  CHECK_EQUAL_128(0x1817161518171615, 0x1817161518171615, q17);
  CHECK_EQUAL_128(0x201F1E1D1C1B1A19, 0x201F1E1D1C1B1A19, q18);
  CHECK_EQUAL_128(0x2827262524232221, 0x2827262524232221, q19);
  CHECK_EQUAL_128(0x302F2E2D2C2B2A29, 0x302F2E2D2C2B2A29, q20);
}

TEST(neon_ld4_d) {
  INIT_V8();
  SETUP();

  uint8_t src[64 + 4];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Ld4(v2.V8B(), v3.V8B(), v4.V8B(), v5.V8B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld4(v6.V8B(), v7.V8B(), v8_.V8B(), v9.V8B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld4(v10.V4H(), v11.V4H(), v12.V4H(), v13.V4H(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld4(v30.V2S(), v31.V2S(), v0.V2S(), v1.V2S(), MemOperand(x17));
  END();

  RUN();

  CHECK_EQUAL_128(0, 0x1C1814100C080400, q2);
  CHECK_EQUAL_128(0, 0x1D1915110D090501, q3);
  CHECK_EQUAL_128(0, 0x1E1A16120E0A0602, q4);
  CHECK_EQUAL_128(0, 0x1F1B17130F0B0703, q5);
  CHECK_EQUAL_128(0, 0x1D1915110D090501, q6);
  CHECK_EQUAL_128(0, 0x1E1A16120E0A0602, q7);
  CHECK_EQUAL_128(0, 0x1F1B17130F0B0703, q8);
  CHECK_EQUAL_128(0, 0x201C1814100C0804, q9);
  CHECK_EQUAL_128(0, 0x1B1A13120B0A0302, q10);
  CHECK_EQUAL_128(0, 0x1D1C15140D0C0504, q11);
  CHECK_EQUAL_128(0, 0x1F1E17160F0E0706, q12);
  CHECK_EQUAL_128(0, 0x2120191811100908, q13);
  CHECK_EQUAL_128(0, 0x1615141306050403, q30);
  CHECK_EQUAL_128(0, 0x1A1918170A090807, q31);
  CHECK_EQUAL_128(0, 0x1E1D1C1B0E0D0C0B, q0);
  CHECK_EQUAL_128(0, 0x2221201F1211100F, q1);
}

TEST(neon_ld4_d_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[32 + 4];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, src_base + 1);
  __ Mov(x19, src_base + 2);
  __ Mov(x20, src_base + 3);
  __ Mov(x21, src_base + 4);
  __ Mov(x22, 1);
  __ Ld4(v2.V8B(), v3.V8B(), v4.V8B(), v5.V8B(),
         MemOperand(x17, x22, PostIndex));
  __ Ld4(v6.V8B(), v7.V8B(), v8_.V8B(), v9.V8B(),
         MemOperand(x28, 32, PostIndex));
  __ Ld4(v10.V4H(), v11.V4H(), v12.V4H(), v13.V4H(),
         MemOperand(x19, 32, PostIndex));
  __ Ld4(v14.V2S(), v15.V2S(), v16.V2S(), v17.V2S(),
         MemOperand(x20, 32, PostIndex));
  __ Ld4(v30.V2S(), v31.V2S(), v0.V2S(), v1.V2S(),
         MemOperand(x21, 32, PostIndex));
  END();

  RUN();

  CHECK_EQUAL_128(0, 0x1C1814100C080400, q2);
  CHECK_EQUAL_128(0, 0x1D1915110D090501, q3);
  CHECK_EQUAL_128(0, 0x1E1A16120E0A0602, q4);
  CHECK_EQUAL_128(0, 0x1F1B17130F0B0703, q5);
  CHECK_EQUAL_128(0, 0x1D1915110D090501, q6);
  CHECK_EQUAL_128(0, 0x1E1A16120E0A0602, q7);
  CHECK_EQUAL_128(0, 0x1F1B17130F0B0703, q8);
  CHECK_EQUAL_128(0, 0x201C1814100C0804, q9);
  CHECK_EQUAL_128(0, 0x1B1A13120B0A0302, q10);
  CHECK_EQUAL_128(0, 0x1D1C15140D0C0504, q11);
  CHECK_EQUAL_128(0, 0x1F1E17160F0E0706, q12);
  CHECK_EQUAL_128(0, 0x2120191811100908, q13);
  CHECK_EQUAL_128(0, 0x1615141306050403, q14);
  CHECK_EQUAL_128(0, 0x1A1918170A090807, q15);
  CHECK_EQUAL_128(0, 0x1E1D1C1B0E0D0C0B, q16);
  CHECK_EQUAL_128(0, 0x2221201F1211100F, q17);
  CHECK_EQUAL_128(0, 0x1716151407060504, q30);
  CHECK_EQUAL_128(0, 0x1B1A19180B0A0908, q31);
  CHECK_EQUAL_128(0, 0x1F1E1D1C0F0E0D0C, q0);
  CHECK_EQUAL_128(0, 0x2322212013121110, q1);

  CHECK_EQUAL_64(src_base + 1, x17);
  CHECK_EQUAL_64(src_base + 1 + 32, x28);
  CHECK_EQUAL_64(src_base + 2 + 32, x19);
  CHECK_EQUAL_64(src_base + 3 + 32, x20);
  CHECK_EQUAL_64(src_base + 4 + 32, x21);
}

TEST(neon_ld4_q) {
  INIT_V8();
  SETUP();

  uint8_t src[64 + 4];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Ld4(v2.V16B(), v3.V16B(), v4.V16B(), v5.V16B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld4(v6.V16B(), v7.V16B(), v8_.V16B(), v9.V16B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld4(v10.V8H(), v11.V8H(), v12.V8H(), v13.V8H(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld4(v14.V4S(), v15.V4S(), v16.V4S(), v17.V4S(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld4(v18.V2D(), v19.V2D(), v20.V2D(), v21.V2D(), MemOperand(x17));
  END();

  RUN();

  CHECK_EQUAL_128(0x3C3834302C282420, 0x1C1814100C080400, q2);
  CHECK_EQUAL_128(0x3D3935312D292521, 0x1D1915110D090501, q3);
  CHECK_EQUAL_128(0x3E3A36322E2A2622, 0x1E1A16120E0A0602, q4);
  CHECK_EQUAL_128(0x3F3B37332F2B2723, 0x1F1B17130F0B0703, q5);
  CHECK_EQUAL_128(0x3D3935312D292521, 0x1D1915110D090501, q6);
  CHECK_EQUAL_128(0x3E3A36322E2A2622, 0x1E1A16120E0A0602, q7);
  CHECK_EQUAL_128(0x3F3B37332F2B2723, 0x1F1B17130F0B0703, q8);
  CHECK_EQUAL_128(0x403C3834302C2824, 0x201C1814100C0804, q9);
  CHECK_EQUAL_128(0x3B3A33322B2A2322, 0x1B1A13120B0A0302, q10);
  CHECK_EQUAL_128(0x3D3C35342D2C2524, 0x1D1C15140D0C0504, q11);
  CHECK_EQUAL_128(0x3F3E37362F2E2726, 0x1F1E17160F0E0706, q12);
  CHECK_EQUAL_128(0x4140393831302928, 0x2120191811100908, q13);
  CHECK_EQUAL_128(0x3635343326252423, 0x1615141306050403, q14);
  CHECK_EQUAL_128(0x3A3938372A292827, 0x1A1918170A090807, q15);
  CHECK_EQUAL_128(0x3E3D3C3B2E2D2C2B, 0x1E1D1C1B0E0D0C0B, q16);
  CHECK_EQUAL_128(0x4241403F3231302F, 0x2221201F1211100F, q17);
  CHECK_EQUAL_128(0x2B2A292827262524, 0x0B0A090807060504, q18);
  CHECK_EQUAL_128(0x333231302F2E2D2C, 0x131211100F0E0D0C, q19);
  CHECK_EQUAL_128(0x3B3A393837363534, 0x1B1A191817161514, q20);
  CHECK_EQUAL_128(0x434241403F3E3D3C, 0x232221201F1E1D1C, q21);
}

TEST(neon_ld4_q_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[64 + 4];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, src_base + 1);
  __ Mov(x19, src_base + 2);
  __ Mov(x20, src_base + 3);
  __ Mov(x21, src_base + 4);
  __ Mov(x22, 1);

  __ Ld4(v2.V16B(), v3.V16B(), v4.V16B(), v5.V16B(),
         MemOperand(x17, x22, PostIndex));
  __ Ld4(v6.V16B(), v7.V16B(), v8_.V16B(), v9.V16B(),
         MemOperand(x28, 64, PostIndex));
  __ Ld4(v10.V8H(), v11.V8H(), v12.V8H(), v13.V8H(),
         MemOperand(x19, 64, PostIndex));
  __ Ld4(v14.V4S(), v15.V4S(), v16.V4S(), v17.V4S(),
         MemOperand(x20, 64, PostIndex));
  __ Ld4(v30.V2D(), v31.V2D(), v0.V2D(), v1.V2D(),
         MemOperand(x21, 64, PostIndex));
  END();

  RUN();

  CHECK_EQUAL_128(0x3C3834302C282420, 0x1C1814100C080400, q2);
  CHECK_EQUAL_128(0x3D3935312D292521, 0x1D1915110D090501, q3);
  CHECK_EQUAL_128(0x3E3A36322E2A2622, 0x1E1A16120E0A0602, q4);
  CHECK_EQUAL_128(0x3F3B37332F2B2723, 0x1F1B17130F0B0703, q5);
  CHECK_EQUAL_128(0x3D3935312D292521, 0x1D1915110D090501, q6);
  CHECK_EQUAL_128(0x3E3A36322E2A2622, 0x1E1A16120E0A0602, q7);
  CHECK_EQUAL_128(0x3F3B37332F2B2723, 0x1F1B17130F0B0703, q8);
  CHECK_EQUAL_128(0x403C3834302C2824, 0x201C1814100C0804, q9);
  CHECK_EQUAL_128(0x3B3A33322B2A2322, 0x1B1A13120B0A0302, q10);
  CHECK_EQUAL_128(0x3D3C35342D2C2524, 0x1D1C15140D0C0504, q11);
  CHECK_EQUAL_128(0x3F3E37362F2E2726, 0x1F1E17160F0E0706, q12);
  CHECK_EQUAL_128(0x4140393831302928, 0x2120191811100908, q13);
  CHECK_EQUAL_128(0x3635343326252423, 0x1615141306050403, q14);
  CHECK_EQUAL_128(0x3A3938372A292827, 0x1A1918170A090807, q15);
  CHECK_EQUAL_128(0x3E3D3C3B2E2D2C2B, 0x1E1D1C1B0E0D0C0B, q16);
  CHECK_EQUAL_128(0x4241403F3231302F, 0x2221201F1211100F, q17);
  CHECK_EQUAL_128(0x2B2A292827262524, 0x0B0A090807060504, q30);
  CHECK_EQUAL_128(0x333231302F2E2D2C, 0x131211100F0E0D0C, q31);
  CHECK_EQUAL_128(0x3B3A393837363534, 0x1B1A191817161514, q0);
  CHECK_EQUAL_128(0x434241403F3E3D3C, 0x232221201F1E1D1C, q1);

  CHECK_EQUAL_64(src_base + 1, x17);
  CHECK_EQUAL_64(src_base + 1 + 64, x28);
  CHECK_EQUAL_64(src_base + 2 + 64, x19);
  CHECK_EQUAL_64(src_base + 3 + 64, x20);
  CHECK_EQUAL_64(src_base + 4 + 64, x21);
}

TEST(neon_ld4_lane) {
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
    __ Ld4(v0.B(), v1.B(), v2.B(), v3.B(), i, MemOperand(x17));
    __ Add(x17, x17, 1);
  }

  __ Mov(x17, src_base);
  for (int i = 7; i >= 0; i--) {
    __ Ld4(v4.H(), v5.H(), v6.H(), v7.H(), i, MemOperand(x17));
    __ Add(x17, x17, 1);
  }

  __ Mov(x17, src_base);
  for (int i = 3; i >= 0; i--) {
    __ Ld4(v8_.S(), v9.S(), v10.S(), v11.S(), i, MemOperand(x17));
    __ Add(x17, x17, 1);
  }

  __ Mov(x17, src_base);
  for (int i = 1; i >= 0; i--) {
    __ Ld4(v12.D(), v13.D(), v14.D(), v15.D(), i, MemOperand(x17));
    __ Add(x17, x17, 1);
  }

  // Test loading a single element into an initialised register.
  __ Mov(x17, src_base);
  __ Mov(x4, x17);
  __ Ldr(q16, MemOperand(x4, 16, PostIndex));
  __ Ldr(q17, MemOperand(x4, 16, PostIndex));
  __ Ldr(q18, MemOperand(x4, 16, PostIndex));
  __ Ldr(q19, MemOperand(x4));
  __ Ld4(v16.B(), v17.B(), v18.B(), v19.B(), 4, MemOperand(x17));

  __ Mov(x5, x17);
  __ Ldr(q20, MemOperand(x5, 16, PostIndex));
  __ Ldr(q21, MemOperand(x5, 16, PostIndex));
  __ Ldr(q22, MemOperand(x5, 16, PostIndex));
  __ Ldr(q23, MemOperand(x5));
  __ Ld4(v20.H(), v21.H(), v22.H(), v23.H(), 3, MemOperand(x17));

  __ Mov(x6, x17);
  __ Ldr(q24, MemOperand(x6, 16, PostIndex));
  __ Ldr(q25, MemOperand(x6, 16, PostIndex));
  __ Ldr(q26, MemOperand(x6, 16, PostIndex));
  __ Ldr(q27, MemOperand(x6));
  __ Ld4(v24.S(), v25.S(), v26.S(), v27.S(), 2, MemOperand(x17));

  __ Mov(x7, x17);
  __ Ldr(q28, MemOperand(x7, 16, PostIndex));
  __ Ldr(q29, MemOperand(x7, 16, PostIndex));
  __ Ldr(q30, MemOperand(x7, 16, PostIndex));
  __ Ldr(q31, MemOperand(x7));
  __ Ld4(v28.D(), v29.D(), v30.D(), v31.D(), 1, MemOperand(x17));

  END();

  RUN();

  CHECK_EQUAL_128(0x0001020304050607, 0x08090A0B0C0D0E0F, q0);
  CHECK_EQUAL_128(0x0102030405060708, 0x090A0B0C0D0E0F10, q1);
  CHECK_EQUAL_128(0x0203040506070809, 0x0A0B0C0D0E0F1011, q2);
  CHECK_EQUAL_128(0x030405060708090A, 0x0B0C0D0E0F101112, q3);
  CHECK_EQUAL_128(0x0100020103020403, 0x0504060507060807, q4);
  CHECK_EQUAL_128(0x0302040305040605, 0x0706080709080A09, q5);
  CHECK_EQUAL_128(0x0504060507060807, 0x09080A090B0A0C0B, q6);
  CHECK_EQUAL_128(0x0706080709080A09, 0x0B0A0C0B0D0C0E0D, q7);
  CHECK_EQUAL_128(0x0302010004030201, 0x0504030206050403, q8);
  CHECK_EQUAL_128(0x0706050408070605, 0x090807060A090807, q9);
  CHECK_EQUAL_128(0x0B0A09080C0B0A09, 0x0D0C0B0A0E0D0C0B, q10);
  CHECK_EQUAL_128(0x0F0E0D0C100F0E0D, 0x11100F0E1211100F, q11);
  CHECK_EQUAL_128(0x0706050403020100, 0x0807060504030201, q12);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x100F0E0D0C0B0A09, q13);
  CHECK_EQUAL_128(0x1716151413121110, 0x1817161514131211, q14);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x201F1E1D1C1B1A19, q15);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0706050003020100, q16);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x1716150113121110, q17);
  CHECK_EQUAL_128(0x2F2E2D2C2B2A2928, 0x2726250223222120, q18);
  CHECK_EQUAL_128(0x3F3E3D3C3B3A3938, 0x3736350333323130, q19);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0100050403020100, q20);
  CHECK_EQUAL_128(0x
"""


```