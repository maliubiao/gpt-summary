Response: 
Prompt: 
```
这是目录为v8/test/cctest/test-assembler-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共8部分，请归纳一下它的功能

"""
9AABBCCDDEEFFUL, x7);
  CHECK_EQUAL_64(0xFFEEDDCCBBAA9988UL, dst[2]);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, dst[3]);
  CHECK_EQUAL_64(0x0011223344556677UL, dst[4]);
  CHECK_EQUAL_64(src_base, x24);
  CHECK_EQUAL_64(dst_base, x25);
  CHECK_EQUAL_64(dst_base + 16, x28);
  CHECK_EQUAL_64(src_base + 4, x19);
  CHECK_EQUAL_64(dst_base + 4, x20);
  CHECK_EQUAL_64(src_base + 8, x21);
  CHECK_EQUAL_64(dst_base + 24, x22);
}

TEST(ldp_stp_postindex) {
  INIT_V8();
  SETUP();

  uint64_t src[4] = {0x0011223344556677UL, 0x8899AABBCCDDEEFFUL,
                     0xFFEEDDCCBBAA9988UL, 0x7766554433221100UL};
  uint64_t dst[5] = {0, 0, 0, 0, 0};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);

  START();
  __ Mov(x16, src_base);
  __ Mov(x17, dst_base);
  __ Mov(x28, dst_base + 16);
  __ Ldp(w0, w1, MemOperand(x16, 4, PostIndex));
  __ Mov(x19, x16);
  __ Ldp(w2, w3, MemOperand(x16, -4, PostIndex));
  __ Stp(w2, w3, MemOperand(x17, 4, PostIndex));
  __ Mov(x20, x17);
  __ Stp(w0, w1, MemOperand(x17, -4, PostIndex));
  __ Ldp(x4, x5, MemOperand(x16, 8, PostIndex));
  __ Mov(x21, x16);
  __ Ldp(x6, x7, MemOperand(x16, -8, PostIndex));
  __ Stp(x7, x6, MemOperand(x28, 8, PostIndex));
  __ Mov(x22, x28);
  __ Stp(x5, x4, MemOperand(x28, -8, PostIndex));
  END();

  RUN();

  CHECK_EQUAL_64(0x44556677, x0);
  CHECK_EQUAL_64(0x00112233, x1);
  CHECK_EQUAL_64(0x00112233, x2);
  CHECK_EQUAL_64(0xCCDDEEFF, x3);
  CHECK_EQUAL_64(0x4455667700112233UL, dst[0]);
  CHECK_EQUAL_64(0x0000000000112233UL, dst[1]);
  CHECK_EQUAL_64(0x0011223344556677UL, x4);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, x5);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, x6);
  CHECK_EQUAL_64(0xFFEEDDCCBBAA9988UL, x7);
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

TEST(ldp_stp_postindex_wide) {
  INIT_V8();
  SETUP();

  uint64_t src[4] = {0x0011223344556677, 0x8899AABBCCDDEEFF, 0xFFEEDDCCBBAA9988,
                     0x7766554433221100};
  uint64_t dst[5] = {0, 0, 0, 0, 0};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);
  // Move base too far from the array to force multiple instructions
  // to be emitted.
  const int64_t base_offset = 1024;

  START();
  __ Mov(x24, src_base);
  __ Mov(x25, dst_base);
  __ Mov(x28, dst_base + 16);
  __ Ldp(w0, w1, MemOperand(x24, base_offset + 4, PostIndex));
  __ Mov(x19, x24);
  __ Sub(x24, x24, base_offset);
  __ Ldp(w2, w3, MemOperand(x24, base_offset - 4, PostIndex));
  __ Stp(w2, w3, MemOperand(x25, 4 - base_offset, PostIndex));
  __ Mov(x20, x25);
  __ Sub(x24, x24, base_offset);
  __ Add(x25, x25, base_offset);
  __ Stp(w0, w1, MemOperand(x25, -4 - base_offset, PostIndex));
  __ Ldp(x4, x5, MemOperand(x24, base_offset + 8, PostIndex));
  __ Mov(x21, x24);
  __ Sub(x24, x24, base_offset);
  __ Ldp(x6, x7, MemOperand(x24, base_offset - 8, PostIndex));
  __ Stp(x7, x6, MemOperand(x28, 8 - base_offset, PostIndex));
  __ Mov(x22, x28);
  __ Add(x28, x28, base_offset);
  __ Stp(x5, x4, MemOperand(x28, -8 - base_offset, PostIndex));
  END();

  RUN();

  CHECK_EQUAL_64(0x44556677, x0);
  CHECK_EQUAL_64(0x00112233, x1);
  CHECK_EQUAL_64(0x00112233, x2);
  CHECK_EQUAL_64(0xCCDDEEFF, x3);
  CHECK_EQUAL_64(0x4455667700112233UL, dst[0]);
  CHECK_EQUAL_64(0x0000000000112233UL, dst[1]);
  CHECK_EQUAL_64(0x0011223344556677UL, x4);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, x5);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, x6);
  CHECK_EQUAL_64(0xFFEEDDCCBBAA9988UL, x7);
  CHECK_EQUAL_64(0xFFEEDDCCBBAA9988UL, dst[2]);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, dst[3]);
  CHECK_EQUAL_64(0x0011223344556677UL, dst[4]);
  CHECK_EQUAL_64(src_base + base_offset, x24);
  CHECK_EQUAL_64(dst_base - base_offset, x25);
  CHECK_EQUAL_64(dst_base - base_offset + 16, x28);
  CHECK_EQUAL_64(src_base + base_offset + 4, x19);
  CHECK_EQUAL_64(dst_base - base_offset + 4, x20);
  CHECK_EQUAL_64(src_base + base_offset + 8, x21);
  CHECK_EQUAL_64(dst_base - base_offset + 24, x22);
}

TEST(ldp_sign_extend) {
  INIT_V8();
  SETUP();

  uint32_t src[2] = {0x80000000, 0x7FFFFFFF};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x24, src_base);
  __ Ldpsw(x0, x1, MemOperand(x24));
  END();

  RUN();

  CHECK_EQUAL_64(0xFFFFFFFF80000000UL, x0);
  CHECK_EQUAL_64(0x000000007FFFFFFFUL, x1);
}

TEST(ldur_stur) {
  INIT_V8();
  SETUP();

  int64_t src[2] = {0x0123456789ABCDEFUL, 0x0123456789ABCDEFUL};
  int64_t dst[5] = {0, 0, 0, 0, 0};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, dst_base);
  __ Mov(x19, src_base + 16);
  __ Mov(x20, dst_base + 32);
  __ Mov(x21, dst_base + 40);
  __ Ldr(w0, MemOperand(x17, 1));
  __ Str(w0, MemOperand(x28, 2));
  __ Ldr(x1, MemOperand(x17, 3));
  __ Str(x1, MemOperand(x28, 9));
  __ Ldr(w2, MemOperand(x19, -9));
  __ Str(w2, MemOperand(x20, -5));
  __ Ldrb(w3, MemOperand(x19, -1));
  __ Strb(w3, MemOperand(x21, -1));
  END();

  RUN();

  CHECK_EQUAL_64(0x6789ABCD, x0);
  CHECK_EQUAL_64(0x6789ABCD0000L, dst[0]);
  CHECK_EQUAL_64(0xABCDEF0123456789L, x1);
  CHECK_EQUAL_64(0xCDEF012345678900L, dst[1]);
  CHECK_EQUAL_64(0x000000AB, dst[2]);
  CHECK_EQUAL_64(0xABCDEF01, x2);
  CHECK_EQUAL_64(0x00ABCDEF01000000L, dst[3]);
  CHECK_EQUAL_64(0x00000001, x3);
  CHECK_EQUAL_64(0x0100000000000000L, dst[4]);
  CHECK_EQUAL_64(src_base, x17);
  CHECK_EQUAL_64(dst_base, x28);
  CHECK_EQUAL_64(src_base + 16, x19);
  CHECK_EQUAL_64(dst_base + 32, x20);
}

TEST(ldr_pcrel_large_offset) {
  INIT_V8();
  SETUP_SIZE(1 * MB);

  START();

  __ Ldr(x1, isolate->factory()->undefined_value());

  {
    v8::internal::PatchingAssembler::BlockPoolsScope scope(&masm);
    int start = __ pc_offset();
    while (__ pc_offset() - start < 600 * KB) {
      __ Nop();
    }
  }

  __ Ldr(x2, isolate->factory()->undefined_value());

  END();

  RUN();

  CHECK_FULL_HEAP_OBJECT_IN_REGISTER(isolate->factory()->undefined_value(), x1);
  CHECK_FULL_HEAP_OBJECT_IN_REGISTER(isolate->factory()->undefined_value(), x2);
}

TEST(ldr_literal) {
  INIT_V8();
  SETUP();

  START();
  __ Ldr(x2, isolate->factory()->undefined_value());

  END();

  RUN();

  CHECK_FULL_HEAP_OBJECT_IN_REGISTER(isolate->factory()->undefined_value(), x2);
}

#ifdef DEBUG
// These tests rely on functions available in debug mode.
enum LiteralPoolEmitOutcome { EmitExpected, NoEmitExpected };
enum LiteralPoolEmissionAlignment { EmitAtUnaligned, EmitAtAligned };

static void LdrLiteralRangeHelper(
    size_t range, LiteralPoolEmitOutcome outcome,
    LiteralPoolEmissionAlignment unaligned_emission) {
  SETUP_SIZE(static_cast<int>(range + 1024));

  const size_t first_pool_entries = 2;
  const size_t first_pool_size_bytes = first_pool_entries * kInt64Size;

  START();
  // Force a pool dump so the pool starts off empty.
  __ ForceConstantPoolEmissionWithJump();
  CHECK_CONSTANT_POOL_SIZE(0);

  // Emit prepadding to influence alignment of the pool.
  bool currently_aligned = IsAligned(__ pc_offset(), kInt64Size);
  if ((unaligned_emission == EmitAtUnaligned && currently_aligned) ||
      (unaligned_emission == EmitAtAligned && !currently_aligned)) {
    __ Nop();
  }

  int initial_pc_offset = __ pc_offset();
  __ Ldr(x0, isolate->factory()->undefined_value());
  __ Ldr(x1, isolate->factory()->the_hole_value());
  CHECK_CONSTANT_POOL_SIZE(first_pool_size_bytes);

  size_t expected_pool_size = 0;

  auto PoolSizeAt = [&](int pc_offset) {
    // To determine padding, consider the size of the prologue of the pool,
    // and the jump around the pool, which we always need.
    size_t prologue_size = 2 * kInstrSize + kInstrSize;
    size_t pc = pc_offset + prologue_size;
    const size_t padding = IsAligned(pc, kInt64Size) ? 0 : kInt32Size;
    CHECK_EQ(padding == 0, unaligned_emission == EmitAtAligned);
    return prologue_size + first_pool_size_bytes + padding;
  };

  int pc_offset_before_emission = -1;
  bool pool_was_emitted = false;
  while (__ pc_offset() - initial_pc_offset < static_cast<intptr_t>(range)) {
    pc_offset_before_emission = __ pc_offset() + kInstrSize;
    __ Nop();
    if (__ GetConstantPoolEntriesSizeForTesting() == 0) {
      pool_was_emitted = true;
      break;
    }
  }

  if (outcome == EmitExpected) {
    if (!pool_was_emitted) {
      FATAL(
          "Pool was not emitted up to pc_offset %d which corresponds to a "
          "distance to the first constant of %d bytes",
          __ pc_offset(), __ pc_offset() - initial_pc_offset);
    }
    // Check that the size of the emitted constant pool is as expected.
    expected_pool_size = PoolSizeAt(pc_offset_before_emission);
    CHECK_EQ(pc_offset_before_emission + expected_pool_size, __ pc_offset());
  } else {
    CHECK_EQ(outcome, NoEmitExpected);
    if (pool_was_emitted) {
      FATAL("Pool was unexpectedly emitted at pc_offset %d ",
            pc_offset_before_emission);
    }
    CHECK_CONSTANT_POOL_SIZE(first_pool_size_bytes);
    CHECK_EQ(pc_offset_before_emission, __ pc_offset());
  }

  // Force a pool flush to check that a second pool functions correctly.
  __ ForceConstantPoolEmissionWithJump();
  CHECK_CONSTANT_POOL_SIZE(0);

  // These loads should be after the pool (and will require a new one).
  const int second_pool_entries = 2;
  __ Ldr(x4, isolate->factory()->true_value());
  __ Ldr(x5, isolate->factory()->false_value());
  CHECK_CONSTANT_POOL_SIZE(second_pool_entries * kInt64Size);

  END();

  if (outcome == EmitExpected) {
    Address pool_start = code->instruction_start() + pc_offset_before_emission;
    Instruction* branch = reinterpret_cast<Instruction*>(pool_start);
    CHECK(branch->IsImmBranch());
    CHECK_EQ(expected_pool_size, branch->ImmPCOffset());
    Instruction* marker =
        reinterpret_cast<Instruction*>(pool_start + kInstrSize);
    CHECK(marker->IsLdrLiteralX());
    size_t pool_data_start_offset = pc_offset_before_emission + kInstrSize;
    size_t padding =
        IsAligned(pool_data_start_offset, kInt64Size) ? 0 : kInt32Size;
    size_t marker_size = kInstrSize;
    CHECK_EQ((first_pool_size_bytes + marker_size + padding) / kInt32Size,
             marker->ImmLLiteral());
  }

  RUN();

  // Check that the literals loaded correctly.
  CHECK_FULL_HEAP_OBJECT_IN_REGISTER(isolate->factory()->undefined_value(), x0);
  CHECK_FULL_HEAP_OBJECT_IN_REGISTER(isolate->factory()->the_hole_value(), x1);
  CHECK_FULL_HEAP_OBJECT_IN_REGISTER(isolate->factory()->true_value(), x4);
  CHECK_FULL_HEAP_OBJECT_IN_REGISTER(isolate->factory()->false_value(), x5);
}

TEST(ldr_literal_range_max_dist_emission_1) {
  INIT_V8();
  LdrLiteralRangeHelper(
      MacroAssembler::GetApproxMaxDistToConstPoolForTesting() +
          MacroAssembler::GetCheckConstPoolIntervalForTesting(),
      EmitExpected, EmitAtAligned);
}

TEST(ldr_literal_range_max_dist_emission_2) {
  INIT_V8();
  LdrLiteralRangeHelper(
      MacroAssembler::GetApproxMaxDistToConstPoolForTesting() +
          MacroAssembler::GetCheckConstPoolIntervalForTesting(),
      EmitExpected, EmitAtUnaligned);
}

TEST(ldr_literal_range_max_dist_no_emission_1) {
  INIT_V8();
  LdrLiteralRangeHelper(
      MacroAssembler::GetApproxMaxDistToConstPoolForTesting() -
          MacroAssembler::GetCheckConstPoolIntervalForTesting(),
      NoEmitExpected, EmitAtUnaligned);
}

TEST(ldr_literal_range_max_dist_no_emission_2) {
  INIT_V8();
  LdrLiteralRangeHelper(
      MacroAssembler::GetApproxMaxDistToConstPoolForTesting() -
          MacroAssembler::GetCheckConstPoolIntervalForTesting(),
      NoEmitExpected, EmitAtAligned);
}

#endif

TEST(add_sub_imm) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0x0);
  __ Mov(x1, 0x1111);
  __ Mov(x2, 0xFFFFFFFFFFFFFFFFL);
  __ Mov(x3, 0x8000000000000000L);

  __ Add(x10, x0, Operand(0x123));
  __ Add(x11, x1, Operand(0x122000));
  __ Add(x12, x0, Operand(0xABC << 12));
  __ Add(x13, x2, Operand(1));

  __ Add(w14, w0, Operand(0x123));
  __ Add(w15, w1, Operand(0x122000));
  __ Add(w16, w0, Operand(0xABC << 12));
  __ Add(w17, w2, Operand(1));

  __ Sub(x20, x0, Operand(0x1));
  __ Sub(x21, x1, Operand(0x111));
  __ Sub(x22, x1, Operand(0x1 << 12));
  __ Sub(x23, x3, Operand(1));

  __ Sub(w24, w0, Operand(0x1));
  __ Sub(w25, w1, Operand(0x111));
  __ Sub(w26, w1, Operand(0x1 << 12));
  __ Sub(w27, w3, Operand(1));
  END();

  RUN();

  CHECK_EQUAL_64(0x123, x10);
  CHECK_EQUAL_64(0x123111, x11);
  CHECK_EQUAL_64(0xABC000, x12);
  CHECK_EQUAL_64(0x0, x13);

  CHECK_EQUAL_32(0x123, w14);
  CHECK_EQUAL_32(0x123111, w15);
  CHECK_EQUAL_32(0xABC000, w16);
  CHECK_EQUAL_32(0x0, w17);

  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFFL, x20);
  CHECK_EQUAL_64(0x1000, x21);
  CHECK_EQUAL_64(0x111, x22);
  CHECK_EQUAL_64(0x7FFFFFFFFFFFFFFFL, x23);

  CHECK_EQUAL_32(0xFFFFFFFF, w24);
  CHECK_EQUAL_32(0x1000, w25);
  CHECK_EQUAL_32(0x111, w26);
  CHECK_EQUAL_32(0xFFFFFFFF, w27);
}

TEST(add_sub_wide_imm) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0x0);
  __ Mov(x1, 0x1);

  __ Add(x10, x0, Operand(0x1234567890ABCDEFUL));
  __ Add(x11, x1, Operand(0xFFFFFFFF));

  __ Add(w12, w0, Operand(0x12345678));
  __ Add(w13, w1, Operand(0xFFFFFFFF));

  __ Add(w28, w0, Operand(kWMinInt));
  __ Sub(w19, w0, Operand(kWMinInt));

  __ Sub(x20, x0, Operand(0x1234567890ABCDEFUL));
  __ Sub(w21, w0, Operand(0x12345678));
  END();

  RUN();

  CHECK_EQUAL_64(0x1234567890ABCDEFUL, x10);
  CHECK_EQUAL_64(0x100000000UL, x11);

  CHECK_EQUAL_32(0x12345678, w12);
  CHECK_EQUAL_64(0x0, x13);

  CHECK_EQUAL_32(kWMinInt, w28);
  CHECK_EQUAL_32(kWMinInt, w19);

  CHECK_EQUAL_64(-0x1234567890ABCDEFLL, x20);
  CHECK_EQUAL_32(-0x12345678, w21);
}

TEST(add_sub_shifted) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0);
  __ Mov(x1, 0x0123456789ABCDEFL);
  __ Mov(x2, 0xFEDCBA9876543210L);
  __ Mov(x3, 0xFFFFFFFFFFFFFFFFL);

  __ Add(x10, x1, Operand(x2));
  __ Add(x11, x0, Operand(x1, LSL, 8));
  __ Add(x12, x0, Operand(x1, LSR, 8));
  __ Add(x13, x0, Operand(x1, ASR, 8));
  __ Add(x14, x0, Operand(x2, ASR, 8));
  __ Add(w15, w0, Operand(w1, ASR, 8));
  __ Add(w28, w3, Operand(w1, ROR, 8));
  __ Add(x19, x3, Operand(x1, ROR, 8));

  __ Sub(x20, x3, Operand(x2));
  __ Sub(x21, x3, Operand(x1, LSL, 8));
  __ Sub(x22, x3, Operand(x1, LSR, 8));
  __ Sub(x23, x3, Operand(x1, ASR, 8));
  __ Sub(x24, x3, Operand(x2, ASR, 8));
  __ Sub(w25, w3, Operand(w1, ASR, 8));
  __ Sub(w26, w3, Operand(w1, ROR, 8));
  __ Sub(x27, x3, Operand(x1, ROR, 8));
  END();

  RUN();

  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFFL, x10);
  CHECK_EQUAL_64(0x23456789ABCDEF00L, x11);
  CHECK_EQUAL_64(0x000123456789ABCDL, x12);
  CHECK_EQUAL_64(0x000123456789ABCDL, x13);
  CHECK_EQUAL_64(0xFFFEDCBA98765432L, x14);
  CHECK_EQUAL_64(0xFF89ABCD, x15);
  CHECK_EQUAL_64(0xEF89ABCC, x28);
  CHECK_EQUAL_64(0xEF0123456789ABCCL, x19);

  CHECK_EQUAL_64(0x0123456789ABCDEFL, x20);
  CHECK_EQUAL_64(0xDCBA9876543210FFL, x21);
  CHECK_EQUAL_64(0xFFFEDCBA98765432L, x22);
  CHECK_EQUAL_64(0xFFFEDCBA98765432L, x23);
  CHECK_EQUAL_64(0x000123456789ABCDL, x24);
  CHECK_EQUAL_64(0x00765432, x25);
  CHECK_EQUAL_64(0x10765432, x26);
  CHECK_EQUAL_64(0x10FEDCBA98765432L, x27);
}

TEST(add_sub_extended) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0);
  __ Mov(x1, 0x0123456789ABCDEFL);
  __ Mov(x2, 0xFEDCBA9876543210L);
  __ Mov(w3, 0x80);

  __ Add(x10, x0, Operand(x1, UXTB, 0));
  __ Add(x11, x0, Operand(x1, UXTB, 1));
  __ Add(x12, x0, Operand(x1, UXTH, 2));
  __ Add(x13, x0, Operand(x1, UXTW, 4));

  __ Add(x14, x0, Operand(x1, SXTB, 0));
  __ Add(x15, x0, Operand(x1, SXTB, 1));
  __ Add(x16, x0, Operand(x1, SXTH, 2));
  __ Add(x17, x0, Operand(x1, SXTW, 3));
  __ Add(x4, x0, Operand(x2, SXTB, 0));
  __ Add(x19, x0, Operand(x2, SXTB, 1));
  __ Add(x20, x0, Operand(x2, SXTH, 2));
  __ Add(x21, x0, Operand(x2, SXTW, 3));

  __ Add(x22, x1, Operand(x2, SXTB, 1));
  __ Sub(x23, x1, Operand(x2, SXTB, 1));

  __ Add(w24, w1, Operand(w2, UXTB, 2));
  __ Add(w25, w0, Operand(w1, SXTB, 0));
  __ Add(w26, w0, Operand(w1, SXTB, 1));
  __ Add(w27, w2, Operand(w1, SXTW, 3));

  __ Add(w28, w0, Operand(w1, SXTW, 3));
  __ Add(x29, x0, Operand(w1, SXTW, 3));

  __ Sub(x30, x0, Operand(w3, SXTB, 1));
  END();

  RUN();

  CHECK_EQUAL_64(0xEFL, x10);
  CHECK_EQUAL_64(0x1DEL, x11);
  CHECK_EQUAL_64(0x337BCL, x12);
  CHECK_EQUAL_64(0x89ABCDEF0L, x13);

  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFEFL, x14);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFDEL, x15);
  CHECK_EQUAL_64(0xFFFFFFFFFFFF37BCL, x16);
  CHECK_EQUAL_64(0xFFFFFFFC4D5E6F78L, x17);
  CHECK_EQUAL_64(0x10L, x4);
  CHECK_EQUAL_64(0x20L, x19);
  CHECK_EQUAL_64(0xC840L, x20);
  CHECK_EQUAL_64(0x3B2A19080L, x21);

  CHECK_EQUAL_64(0x0123456789ABCE0FL, x22);
  CHECK_EQUAL_64(0x0123456789ABCDCFL, x23);

  CHECK_EQUAL_32(0x89ABCE2F, w24);
  CHECK_EQUAL_32(0xFFFFFFEF, w25);
  CHECK_EQUAL_32(0xFFFFFFDE, w26);
  CHECK_EQUAL_32(0xC3B2A188, w27);

  CHECK_EQUAL_32(0x4D5E6F78, w28);
  CHECK_EQUAL_64(0xFFFFFFFC4D5E6F78L, x29);

  CHECK_EQUAL_64(256, x30);
}

TEST(add_sub_negative) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0);
  __ Mov(x1, 4687);
  __ Mov(x2, 0x1122334455667788);
  __ Mov(w3, 0x11223344);
  __ Mov(w4, 400000);

  __ Add(x10, x0, -42);
  __ Add(x11, x1, -687);
  __ Add(x12, x2, -0x88);

  __ Sub(x13, x0, -600);
  __ Sub(x14, x1, -313);
  __ Sub(x15, x2, -0x555);

  __ Add(w19, w3, -0x344);
  __ Add(w20, w4, -2000);

  __ Sub(w21, w3, -0xBC);
  __ Sub(w22, w4, -2000);
  END();

  RUN();

  CHECK_EQUAL_64(-42, x10);
  CHECK_EQUAL_64(4000, x11);
  CHECK_EQUAL_64(0x1122334455667700, x12);

  CHECK_EQUAL_64(600, x13);
  CHECK_EQUAL_64(5000, x14);
  CHECK_EQUAL_64(0x1122334455667CDD, x15);

  CHECK_EQUAL_32(0x11223000, w19);
  CHECK_EQUAL_32(398000, w20);

  CHECK_EQUAL_32(0x11223400, w21);
  CHECK_EQUAL_32(402000, w22);
}

TEST(add_sub_zero) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0);
  __ Mov(x1, 0);
  __ Mov(x2, 0);

  Label blob1;
  __ Bind(&blob1);
  __ Add(x0, x0, 0);
  __ Sub(x1, x1, 0);
  __ Sub(x2, x2, xzr);
  CHECK_EQ(0u, __ SizeOfCodeGeneratedSince(&blob1));

  Label blob2;
  __ Bind(&blob2);
  __ Add(w3, w3, 0);
  CHECK_NE(0u, __ SizeOfCodeGeneratedSince(&blob2));

  Label blob3;
  __ Bind(&blob3);
  __ Sub(w3, w3, wzr);
  CHECK_NE(0u, __ SizeOfCodeGeneratedSince(&blob3));

  END();

  RUN();

  CHECK_EQUAL_64(0, x0);
  CHECK_EQUAL_64(0, x1);
  CHECK_EQUAL_64(0, x2);
}

TEST(preshift_immediates) {
  INIT_V8();
  SETUP();

  START();
  // Test operations involving immediates that could be generated using a
  // pre-shifted encodable immediate followed by a post-shift applied to
  // the arithmetic or logical operation.

  // Save sp.
  __ Mov(x29, sp);

  // Set the registers to known values.
  __ Mov(x0, 0x1000);
  __ Mov(sp, 0x1000);

  // Arithmetic ops.
  __ Add(x1, x0, 0x1F7DE);
  __ Add(w2, w0, 0xFFFFFF1);
  __ Adds(x3, x0, 0x18001);
  __ Adds(w4, w0, 0xFFFFFF1);
  __ Add(x5, x0, 0x10100);
  __ Sub(w6, w0, 0xFFFFFF1);
  __ Subs(x7, x0, 0x18001);
  __ Subs(w8, w0, 0xFFFFFF1);

  // Logical ops.
  __ And(x9, x0, 0x1F7DE);
  __ Orr(w10, w0, 0xFFFFFF1);
  __ Eor(x11, x0, 0x18001);

  // Ops using the stack pointer.
  __ Add(sp, sp, 0x1F7F0);
  __ Mov(x12, sp);
  __ Mov(sp, 0x1000);

  __ Adds(x13, sp, 0x1F7F0);

  __ Orr(sp, x0, 0x1F7F0);
  __ Mov(x14, sp);
  __ Mov(sp, 0x1000);

  __ Add(sp, sp, 0x10100);
  __ Mov(x15, sp);

  //  Restore sp.
  __ Mov(sp, x29);
  END();

  RUN();

  CHECK_EQUAL_64(0x1000, x0);
  CHECK_EQUAL_64(0x207DE, x1);
  CHECK_EQUAL_64(0x10000FF1, x2);
  CHECK_EQUAL_64(0x19001, x3);
  CHECK_EQUAL_64(0x10000FF1, x4);
  CHECK_EQUAL_64(0x11100, x5);
  CHECK_EQUAL_64(0xF000100F, x6);
  CHECK_EQUAL_64(0xFFFFFFFFFFFE8FFF, x7);
  CHECK_EQUAL_64(0xF000100F, x8);
  CHECK_EQUAL_64(0x1000, x9);
  CHECK_EQUAL_64(0xFFFFFF1, x10);
  CHECK_EQUAL_64(0x207F0, x12);
  CHECK_EQUAL_64(0x207F0, x13);
  CHECK_EQUAL_64(0x1F7F0, x14);
  CHECK_EQUAL_64(0x11100, x15);
}

TEST(claim_drop_zero) {
  INIT_V8();
  SETUP();

  START();

  Label start;
  __ Bind(&start);
  __ Claim(0);
  __ Drop(0);
  __ Claim(xzr, 8);
  __ Drop(xzr, 8);
  __ Claim(xzr, 0);
  __ Drop(xzr, 0);
  __ Claim(x7, 0);
  __ Drop(x7, 0);
  CHECK_EQ(0u, __ SizeOfCodeGeneratedSince(&start));

  END();

  RUN();
}

TEST(neg) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0xF123456789ABCDEFL);

  // Immediate.
  __ Neg(x1, 0x123);
  __ Neg(w2, 0x123);

  // Shifted.
  __ Neg(x3, Operand(x0, LSL, 1));
  __ Neg(w4, Operand(w0, LSL, 2));
  __ Neg(x5, Operand(x0, LSR, 3));
  __ Neg(w6, Operand(w0, LSR, 4));
  __ Neg(x7, Operand(x0, ASR, 5));
  __ Neg(w8, Operand(w0, ASR, 6));

  // Extended.
  __ Neg(w9, Operand(w0, UXTB));
  __ Neg(x10, Operand(x0, SXTB, 1));
  __ Neg(w11, Operand(w0, UXTH, 2));
  __ Neg(x12, Operand(x0, SXTH, 3));
  __ Neg(w13, Operand(w0, UXTW, 4));
  __ Neg(x14, Operand(x0, SXTW, 4));
  END();

  RUN();

  CHECK_EQUAL_64(0xFFFFFFFFFFFFFEDDUL, x1);
  CHECK_EQUAL_64(0xFFFFFEDD, x2);
  CHECK_EQUAL_64(0x1DB97530ECA86422UL, x3);
  CHECK_EQUAL_64(0xD950C844, x4);
  CHECK_EQUAL_64(0xE1DB97530ECA8643UL, x5);
  CHECK_EQUAL_64(0xF7654322, x6);
  CHECK_EQUAL_64(0x0076E5D4C3B2A191UL, x7);
  CHECK_EQUAL_64(0x01D950C9, x8);
  CHECK_EQUAL_64(0xFFFFFF11, x9);
  CHECK_EQUAL_64(0x0000000000000022UL, x10);
  CHECK_EQUAL_64(0xFFFCC844, x11);
  CHECK_EQUAL_64(0x0000000000019088UL, x12);
  CHECK_EQUAL_64(0x65432110, x13);
  CHECK_EQUAL_64(0x0000000765432110UL, x14);
}

template <typename T, typename Op>
static void AdcsSbcsHelper(Op op, T left, T right, int carry, T expected,
                           StatusFlags expected_flags) {
  int reg_size = sizeof(T) * 8;
  auto left_reg = Register::Create(0, reg_size);
  auto right_reg = Register::Create(1, reg_size);
  auto result_reg = Register::Create(2, reg_size);

  SETUP();
  START();

  __ Mov(left_reg, left);
  __ Mov(right_reg, right);
  __ Mov(x10, (carry ? CFlag : NoFlag));

  __ Msr(NZCV, x10);
  (masm.*op)(result_reg, left_reg, right_reg);

  END();
  RUN();

  CHECK_EQUAL_64(left, left_reg.X());
  CHECK_EQUAL_64(right, right_reg.X());
  CHECK_EQUAL_64(expected, result_reg.X());
  CHECK_EQUAL_NZCV(expected_flags);
}

TEST(adcs_sbcs_x) {
  INIT_V8();
  uint64_t inputs[] = {
      0x0000000000000000, 0x0000000000000001, 0x7FFFFFFFFFFFFFFE,
      0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 0x8000000000000001,
      0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF,
  };
  static const size_t input_count = sizeof(inputs) / sizeof(inputs[0]);

  struct Expected {
    uint64_t carry0_result;
    StatusFlags carry0_flags;
    uint64_t carry1_result;
    StatusFlags carry1_flags;
  };

  static const Expected expected_adcs_x[input_count][input_count] = {
      {{0x0000000000000000, ZFlag, 0x0000000000000001, NoFlag},
       {0x0000000000000001, NoFlag, 0x0000000000000002, NoFlag},
       {0x7FFFFFFFFFFFFFFE, NoFlag, 0x7FFFFFFFFFFFFFFF, NoFlag},
       {0x7FFFFFFFFFFFFFFF, NoFlag, 0x8000000000000000, NVFlag},
       {0x8000000000000000, NFlag, 0x8000000000000001, NFlag},
       {0x8000000000000001, NFlag, 0x8000000000000002, NFlag},
       {0xFFFFFFFFFFFFFFFE, NFlag, 0xFFFFFFFFFFFFFFFF, NFlag},
       {0xFFFFFFFFFFFFFFFF, NFlag, 0x0000000000000000, ZCFlag}},
      {{0x0000000000000001, NoFlag, 0x0000000000000002, NoFlag},
       {0x0000000000000002, NoFlag, 0x0000000000000003, NoFlag},
       {0x7FFFFFFFFFFFFFFF, NoFlag, 0x8000000000000000, NVFlag},
       {0x8000000000000000, NVFlag, 0x8000000000000001, NVFlag},
       {0x8000000000000001, NFlag, 0x8000000000000002, NFlag},
       {0x8000000000000002, NFlag, 0x8000000000000003, NFlag},
       {0xFFFFFFFFFFFFFFFF, NFlag, 0x0000000000000000, ZCFlag},
       {0x0000000000000000, ZCFlag, 0x0000000000000001, CFlag}},
      {{0x7FFFFFFFFFFFFFFE, NoFlag, 0x7FFFFFFFFFFFFFFF, NoFlag},
       {0x7FFFFFFFFFFFFFFF, NoFlag, 0x8000000000000000, NVFlag},
       {0xFFFFFFFFFFFFFFFC, NVFlag, 0xFFFFFFFFFFFFFFFD, NVFlag},
       {0xFFFFFFFFFFFFFFFD, NVFlag, 0xFFFFFFFFFFFFFFFE, NVFlag},
       {0xFFFFFFFFFFFFFFFE, NFlag, 0xFFFFFFFFFFFFFFFF, NFlag},
       {0xFFFFFFFFFFFFFFFF, NFlag, 0x0000000000000000, ZCFlag},
       {0x7FFFFFFFFFFFFFFC, CFlag, 0x7FFFFFFFFFFFFFFD, CFlag},
       {0x7FFFFFFFFFFFFFFD, CFlag, 0x7FFFFFFFFFFFFFFE, CFlag}},
      {{0x7FFFFFFFFFFFFFFF, NoFlag, 0x8000000000000000, NVFlag},
       {0x8000000000000000, NVFlag, 0x8000000000000001, NVFlag},
       {0xFFFFFFFFFFFFFFFD, NVFlag, 0xFFFFFFFFFFFFFFFE, NVFlag},
       {0xFFFFFFFFFFFFFFFE, NVFlag, 0xFFFFFFFFFFFFFFFF, NVFlag},
       {0xFFFFFFFFFFFFFFFF, NFlag, 0x0000000000000000, ZCFlag},
       {0x0000000000000000, ZCFlag, 0x0000000000000001, CFlag},
       {0x7FFFFFFFFFFFFFFD, CFlag, 0x7FFFFFFFFFFFFFFE, CFlag},
       {0x7FFFFFFFFFFFFFFE, CFlag, 0x7FFFFFFFFFFFFFFF, CFlag}},
      {{0x8000000000000000, NFlag, 0x8000000000000001, NFlag},
       {0x8000000000000001, NFlag, 0x8000000000000002, NFlag},
       {0xFFFFFFFFFFFFFFFE, NFlag, 0xFFFFFFFFFFFFFFFF, NFlag},
       {0xFFFFFFFFFFFFFFFF, NFlag, 0x0000000000000000, ZCFlag},
       {0x0000000000000000, ZCVFlag, 0x0000000000000001, CVFlag},
       {0x0000000000000001, CVFlag, 0x0000000000000002, CVFlag},
       {0x7FFFFFFFFFFFFFFE, CVFlag, 0x7FFFFFFFFFFFFFFF, CVFlag},
       {0x7FFFFFFFFFFFFFFF, CVFlag, 0x8000000000000000, NCFlag}},
      {{0x8000000000000001, NFlag, 0x8000000000000002, NFlag},
       {0x8000000000000002, NFlag, 0x8000000000000003, NFlag},
       {0xFFFFFFFFFFFFFFFF, NFlag, 0x0000000000000000, ZCFlag},
       {0x0000000000000000, ZCFlag, 0x0000000000000001, CFlag},
       {0x0000000000000001, CVFlag, 0x0000000000000002, CVFlag},
       {0x0000000000000002, CVFlag, 0x0000000000000003, CVFlag},
       {0x7FFFFFFFFFFFFFFF, CVFlag, 0x8000000000000000, NCFlag},
       {0x8000000000000000, NCFlag, 0x8000000000000001, NCFlag}},
      {{0xFFFFFFFFFFFFFFFE, NFlag, 0xFFFFFFFFFFFFFFFF, NFlag},
       {0xFFFFFFFFFFFFFFFF, NFlag, 0x0000000000000000, ZCFlag},
       {0x7FFFFFFFFFFFFFFC, CFlag, 0x7FFFFFFFFFFFFFFD, CFlag},
       {0x7FFFFFFFFFFFFFFD, CFlag, 0x7FFFFFFFFFFFFFFE, CFlag},
       {0x7FFFFFFFFFFFFFFE, CVFlag, 0x7FFFFFFFFFFFFFFF, CVFlag},
       {0x7FFFFFFFFFFFFFFF, CVFlag, 0x8000000000000000, NCFlag},
       {0xFFFFFFFFFFFFFFFC, NCFlag, 0xFFFFFFFFFFFFFFFD, NCFlag},
       {0xFFFFFFFFFFFFFFFD, NCFlag, 0xFFFFFFFFFFFFFFFE, NCFlag}},
      {{0xFFFFFFFFFFFFFFFF, NFlag, 0x0000000000000000, ZCFlag},
       {0x0000000000000000, ZCFlag, 0x0000000000000001, CFlag},
       {0x7FFFFFFFFFFFFFFD, CFlag, 0x7FFFFFFFFFFFFFFE, CFlag},
       {0x7FFFFFFFFFFFFFFE, CFlag, 0x7FFFFFFFFFFFFFFF, CFlag},
       {0x7FFFFFFFFFFFFFFF, CVFlag, 0x8000000000000000, NCFlag},
       {0x8000000000000000, NCFlag, 0x8000000000000001, NCFlag},
       {0xFFFFFFFFFFFFFFFD, NCFlag, 0xFFFFFFFFFFFFFFFE, NCFlag},
       {0xFFFFFFFFFFFFFFFE, NCFlag, 0xFFFFFFFFFFFFFFFF, NCFlag}}};

  static const Expected expected_sbcs_x[input_count][input_count] = {
      {{0xFFFFFFFFFFFFFFFF, NFlag, 0x0000000000000000, ZCFlag},
       {0xFFFFFFFFFFFFFFFE, NFlag, 0xFFFFFFFFFFFFFFFF, NFlag},
       {0x8000000000000001, NFlag, 0x8000000000000002, NFlag},
       {0x8000000000000000, NFlag, 0x8000000000000001, NFlag},
       {0x7FFFFFFFFFFFFFFF, NoFlag, 0x8000000000000000, NVFlag},
       {0x7FFFFFFFFFFFFFFE, NoFlag, 0x7FFFFFFFFFFFFFFF, NoFlag},
       {0x0000000000000001, NoFlag, 0x0000000000000002, NoFlag},
       {0x0000000000000000, ZFlag, 0x0000000000000001, NoFlag}},
      {{0x0000000000000000, ZCFlag, 0x0000000000000001, CFlag},
       {0xFFFFFFFFFFFFFFFF, NFlag, 0x0000000000000000, ZCFlag},
       {0x8000000000000002, NFlag, 0x8000000000000003, NFlag},
       {0x8000000000000001, NFlag, 0x8000000000000002, NFlag},
       {0x8000000000000000, NVFlag, 0x8000000000000001, NVFlag},
       {0x7FFFFFFFFFFFFFFF, NoFlag, 0x8000000000000000, NVFlag},
       {0x0000000000000002, NoFlag, 0x0000000000000003, NoFlag},
       {0x0000000000000001, NoFlag, 0x0000000000000002, NoFlag}},
      {{0x7FFFFFFFFFFFFFFD, CFlag, 0x7FFFFFFFFFFFFFFE, CFlag},
       {0x7FFFFFFFFFFFFFFC, CFlag, 0x7FFFFFFFFFFFFFFD, CFlag},
       {0xFFFFFFFFFFFFFFFF, NFlag, 0x0000000000000000, ZCFlag},
       {0xFFFFFFFFFFFFFFFE, NFlag, 0xFFFFFFFFFFFFFFFF, NFlag},
       {0xFFFFFFFFFFFFFFFD, NVFlag, 0xFFFFFFFFFFFFFFFE, NVFlag},
       {0xFFFFFFFFFFFFFFFC, NVFlag, 0xFFFFFFFFFFFFFFFD, NVFlag},
       {0x7FFFFFFFFFFFFFFF, NoFlag, 0x8000000000000000, NVFlag},
       {0x7FFFFFFFFFFFFFFE, NoFlag, 0x7FFFFFFFFFFFFFFF, NoFlag}},
      {{0x7FFFFFFFFFFFFFFE, CFlag, 0x7FFFFFFFFFFFFFFF, CFlag},
       {0x7FFFFFFFFFFFFFFD, CFlag, 0x7FFFFFFFFFFFFFFE, CFlag},
       {0x0000000000000000, ZCFlag, 0x0000000000000001, CFlag},
       {0xFFFFFFFFFFFFFFFF, NFlag, 0x0000000000000000, ZCFlag},
       {0xFFFFFFFFFFFFFFFE, NVFlag, 0xFFFFFFFFFFFFFFFF, NVFlag},
       {0xFFFFFFFFFFFFFFFD, NVFlag, 0xFFFFFFFFFFFFFFFE, NVFlag},
       {0x8000000000000000, NVFlag, 0x8000000000000001, NVFlag},
       {0x7FFFFFFFFFFFFFFF, NoFlag, 0x8000000000000000, NVFlag}},
      {{0x7FFFFFFFFFFFFFFF, CVFlag, 0x8000000000000000, NCFlag},
       {0x7FFFFFFFFFFFFFFE, CVFlag, 0x7FFFFFFFFFFFFFFF, CVFlag},
       {0x0000000000000001, CVFlag, 0x0000000000000002, CVFlag},
       {0x0000000000000000, ZCVFlag, 0x0000000000000001, CVFlag},
       {0xFFFFFFFFFFFFFFFF, NFlag, 0x0000000000000000, ZCFlag},
       {0xFFFFFFFFFFFFFFFE, NFlag, 0xFFFFFFFFFFFFFFFF, NFlag},
       {0x8000000000000001, NFlag, 0x8000000000000002, NFlag},
       {0x8000000000000000, NFlag, 0x8000000000000001, NFlag}},
      {{0x8000000000000000, NCFlag, 0x8000000000000001, NCFlag},
       {0x7FFFFFFFFFFFFFFF, CVFlag, 0x8000000000000000, NCFlag},
       {0x0000000000000002, CVFlag, 0x0000000000000003, CVFlag},
       {0x0000000000000001, CVFlag, 0x0000000000000002, CVFlag},
       {0x0000000000000000, ZCFlag, 0x0000000000000001, CFlag},
       {0xFFFFFFFFFFFFFFFF, NFlag, 0x0000000000000000, ZCFlag},
       {0x8000000000000002, NFlag, 0x8000000000000003, NFlag},
       {0x8000000000000001, NFlag, 0x8000000000000002, NFlag}},
      {{0xFFFFFFFFFFFFFFFD, NCFlag, 0xFFFFFFFFFFFFFFFE, NCFlag},
       {0xFFFFFFFFFFFFFFFC, NCFlag, 0xFFFFFFFFFFFFFFFD, NCFlag},
       {0x7FFFFFFFFFFFFFFF, CVFlag, 0x8000000000000000, NCFlag},
       {0x7FFFFFFFFFFFFFFE, CVFlag, 0x7FFFFFFFFFFFFFFF, CVFlag},
       {0x7FFFFFFFFFFFFFFD, CFlag, 0x7FFFFFFFFFFFFFFE, CFlag},
       {0x7FFFFFFFFFFFFFFC, CFlag, 0x7FFFFFFFFFFFFFFD, CFlag},
       {0xFFFFFFFFFFFFFFFF, NFlag, 0x0000000000000000, ZCFlag},
       {0xFFFFFFFFFFFFFFFE, NFlag, 0xFFFFFFFFFFFFFFFF, NFlag}},
      {{0xFFFFFFFFFFFFFFFE, NCFlag, 0xFFFFFFFFFFFFFFFF, NCFlag},
       {0xFFFFFFFFFFFFFFFD, NCFlag, 0xFFFFFFFFFFFFFFFE, NCFlag},
       {0x8000000000000000, NCFlag, 0x8000000000000001, NCFlag},
       {0x7FFFFFFFFFFFFFFF, CVFlag, 0x8000000000000000, NCFlag},
       {0x7FFFFFFFFFFFFFFE, CFlag, 0x7FFFFFFFFFFFFFFF, CFlag},
       {0x7FFFFFFFFFFFFFFD, CFlag, 0x7FFFFFFFFFFFFFFE, CFlag},
       {0x0000000000000000, ZCFlag, 0x0000000000000001, CFlag},
       {0xFFFFFFFFFFFFFFFF, NFlag, 0x0000000000000000, ZCFlag}}};

  for (size_t left = 0; left < input_count; left++) {
    for (size_t right = 0; right < input_count; right++) {
      const Expected& expected = expected_adcs_x[left][right];
      AdcsSbcsHelper(&MacroAssembler::Adcs, inputs[left], inputs[right], 0,
                     expected.carry0_result, expected.carry0_flags);
      AdcsSbcsHelper(&MacroAssembler::Adcs, inputs[left], inputs[right], 1,
                     expected.carry1_result, expected.carry1_flags);
    }
  }

  for (size_t left = 0; left < input_count; left++) {
    for (size_t right = 0; right < input_count; right++) {
      const Expected& expected = expected_sbcs_x[left][right];
      AdcsSbcsHelper(&MacroAssembler::Sbcs, inputs[left], inputs[right], 0,
                     expected.carry0_result, expected.carry0_flags);
      AdcsSbcsHelper(&MacroAssembler::Sbcs, inputs[left], inputs[right], 1,
                     expected.carry1_result, expected.carry1_flags);
    }
  }
}

TEST(adcs_sbcs_w) {
  INIT_V8();
  uint32_t inputs[] = {
      0x00000000, 0x00000001, 0x7FFFFFFE, 0x7FFFFFFF,
      0x80000000, 0x80000001, 0xFFFFFFFE, 0xFFFFFFFF,
  };
  static const size_t input_count = sizeof(inputs) / sizeof(inputs[0]);

  struct Expected {
    uint32_t carry0_result;
    StatusFlags carry0_flags;
    uint32_t carry1_result;
    StatusFlags carry1_flags;
  };

  static const Expected expected_adcs_w[input_count][input_count] = {
      {{0x00000000, ZFlag, 0x00000001, NoFlag},
       {0x00000001, NoFlag, 0x00000002, NoFlag},
       {0x7FFFFFFE, NoFlag, 0x7FFFFFFF, NoFlag},
       {0x7FFFFFFF, NoFlag, 0x80000000, NVFlag},
       {0x80000000, NFlag, 0x80000001, NFlag},
       {0x80000001, NFlag, 0x80000002, NFlag},
       {0xFFFFFFFE, NFlag, 0xFFFFFFFF, NFlag},
       {0xFFFFFFFF, NFlag, 0x00000000, ZCFlag}},
      {{0x00000001, NoFlag, 0x00000002, NoFlag},
       {0x00000002, NoFlag, 0x00000003, NoFlag},
       {0x7FFFFFFF, NoFlag, 0x80000000, NVFlag},
       {0x80000000, NVFlag, 0x80000001, NVFlag},
       {0x80000001, NFlag, 0x80000002, NFlag},
       {0x80000002, NFlag, 0x80000003, NFlag},
       {0xFFFFFFFF, NFlag, 0x00000000, ZCFlag},
       {0x00000000, ZCFlag, 0x00000001, CFlag}},
      {{0x7FFFFFFE, NoFlag, 0x7FFFFFFF, NoFlag},
       {0x7FFFFFFF, NoFlag, 0x80000000, NVFlag},
       {0xFFFFFFFC, NVFlag, 0xFFFFFFFD, NVFlag},
       {0xFFFFFFFD, NVFlag, 0xFFFFFFFE, NVFlag},
       {0xFFFFFFFE, NFlag, 0xFFFFFFFF, NFlag},
       {0xFFFFFFFF, NFlag, 0x00000000, ZCFlag},
       {0x7FFFFFFC, CFlag, 0x7FFFFFFD, CFlag},
       {0x7FFFFFFD, CFlag, 0x7FFFFFFE, CFlag}},
      {{0x7FFFFFFF, NoFlag, 0x80000000, NVFlag},
       {0x80000000, NVFlag, 0x80000001, NVFlag},
       {0xFFFFFFFD, NVFlag, 0xFFFFFFFE, NVFlag},
       {0xFFFFFFFE, NVFlag, 0xFFFFFFFF, NVFlag},
       {0xFFFFFFFF, NFlag, 0x00000000, ZCFlag},
       {0x00000000, ZCFlag, 0x00000001, CFlag},
       {0x7FFFFFFD, CFlag, 0x7FFFFFFE, CFlag},
       {0x7FFFFFFE, CFlag, 0x7FFFFFFF, CFlag}},
      {{0x80000000, NFlag, 0x80000001, NFlag},
       {0x80000001, NFlag, 0x80000002, NFlag},
       {0xFFFFFFFE, NFlag, 0xFFFFFFFF, NFlag},
       {0xFFFFFFFF, NFlag, 0x00000000, ZCFlag},
       {0x00000000, ZCVFlag, 0x00000001, CVFlag},
       {0x00000001, CVFlag, 0x00000002, CVFlag},
       {0x7FFFFFFE, CVFlag, 0x7FFFFFFF, CVFlag},
       {0x7FFFFFFF, CVFlag, 0x80000000, NCFlag}},
      {{0x80000001, NFlag, 0x80000002, NFlag},
       {0x80000002, NFlag, 0x80000003, NFlag},
       {0xFFFFFFFF, NFlag, 0x00000000, ZCFlag},
       {0x00000000, ZCFlag, 0x00000001, CFlag},
       {0x00000001, CVFlag, 0x00000002, CVFlag},
       {0x00000002, CVFlag, 0x00000003, CVFlag},
       {0x7FFFFFFF, CVFlag, 0x80000000, NCFlag},
       {0x80000000, NCFlag, 0x80000001, NCFlag}},
      {{0xFFFFFFFE, NFlag, 0xFFFFFFFF, NFlag},
       {0xFFFFFFFF, NFlag, 0x00000000, ZCFlag},
       {0x7FFFFFFC, CFlag, 0x7FFFFFFD, CFlag},
       {0x7FFFFFFD, CFlag, 0x7FFFFFFE, CFlag},
       {0x7FFFFFFE, CVFlag, 0x7FFFFFFF, CVFlag},
       {0x7FFFFFFF, CVFlag, 0x80000000, NCFlag},
       {0xFFFFFFFC, NCFlag, 0xFFFFFFFD, NCFlag},
       {0xFFFFFFFD, NCFlag, 0xFFFFFFFE, NCFlag}},
      {{0xFFFFFFFF, NFlag, 0x00000000, ZCFlag},
       {0x00000000, ZCFlag, 0x00000001, CFlag},
       {0x7FFFFFFD, CFlag, 0x7FFFFFFE, CFlag},
       {0x7FFFFFFE, CFlag, 0x7FFFFFFF, CFlag},
       {0x7FFFFFFF, CVFlag, 0x80000000, NCFlag},
       {0x80000000, NCFlag, 0x80000001, NCFlag},
       {0xFFFFFFFD, NCFlag, 0xFFFFFFFE, NCFlag},
       {0xFFFFFFFE, NCFlag, 0xFFFFFFFF, NCFlag}}};

  static const Expected expected_sbcs_w[input_count][input_count] = {
      {{0xFFFFFFFF, NFlag, 0x00000000, ZCFlag},
       {0xFFFFFFFE, NFlag, 0xFFFFFFFF, NFlag},
       {0x80000001, NFlag, 0x80000002, NFlag},
       {0x80000000, NFlag, 0x80000001, NFlag},
       {0x7FFFFFFF, NoFlag, 0x80000000, NVFlag},
       {0x7FFFFFFE, NoFlag, 0x7FFFFFFF, NoFlag},
       {0x00000001, NoFlag, 0x00000002, NoFlag},
       {0x00000000, ZFlag, 0x00000001, NoFlag}},
      {{0x00000000, ZCFlag, 0x00000001, CFlag},
       {0xFFFFFFFF, NFlag, 0x00000000, ZCFlag},
       {0x80000002, NFlag, 0x80000003, NFlag},
       {0x80000001, NFlag, 0x80000002, NFlag},
       {0x80000000, NVFlag, 0x80000001, NVFlag},
       {0x7FFFFFFF, NoFlag, 0x80000000, NVFlag},
       {0x00000002, NoFlag, 0x00000003, NoFlag},
       {0x00000001, NoFlag, 0x00000002, NoFlag}},
      {{0x7FFFFFFD, CFlag, 0x7FFFFFFE, CFlag},
       {0x7FFFFFFC, CFlag, 0x7FFFFFFD, CFlag},
       {0xFFFFFFFF, NFlag, 0x00000000, ZCFlag},
       {0xFFFFFFFE, NFlag, 0xFFFFFFFF, NFlag},
       {0xFFFFFFFD, NVFlag, 0xFFFFFFFE, NVFlag},
       {0xFFFFFFFC, NVFlag, 0xFFFFFFFD, NVFlag},
       {0x7FFFFFFF, NoFlag, 0x80000000, NVFlag},
       {0x7FFFFFFE, NoFlag, 0x7FFFFFFF, NoFlag}},
      {{0x7FFFFFFE, CFlag, 0x7FFFFFFF, CFlag},
       {0x7FFFFFFD, CFlag, 0x7FFFFFFE, CFlag},
       {0x00000000, ZCFlag, 0x00000001, CFlag},
       {0xFFFFFFFF, NFlag, 0x00000000, ZCFlag},
       {0xFFFFFFFE, NVFlag, 0xFFFFFFFF, NVFlag},
       {0xFFFFFFFD, NVFlag, 0xFFFFFFFE, NVFlag},
       {0x80000000, NVFlag, 0x80000001, NVFlag},
       {0x7FFFFFFF, NoFlag, 0x80000000, NVFlag}},
      {{0x7FFFFFFF, CVFlag, 0x80000000, NCFlag},
       {0x7FFFFFFE, CVFlag, 0x7FFFFFFF, CVFlag},
       {0x00000001, CVFlag, 0x00000002, CVFlag},
       {0x00000000, ZCVFlag, 0x00000001, CVFlag},
       {0xFFFFFFFF, NFlag, 0x00000000, ZCFlag},
       {0xFFFFFFFE, NFlag, 0xFFFFFFFF, NFlag},
       {0x80000001, NFlag, 0x80000002, NFlag},
       {0x80000000, NFlag, 0x80000001, NFlag}},
      {{0x80000000, NCFlag, 0x80000001, NCFlag},
       {0x7FFFFFFF, CVFlag, 0x80000000, NCFlag},
       {0x00000002, CVFlag, 0x00000003, CVFlag},
       {0x00000001, CVFlag, 0x00000002, CVFlag},
       {0x00000000, ZCFlag, 0x00000001, CFlag},
       {0xFFFFFFFF, NFlag, 0x00000000, ZCFlag},
       {0x80000002, NFlag, 0x80000003, NFlag},
       {0x80000001, NFlag, 0x80000002, NFlag}},
      {{0xFFFFFFFD, NCFlag, 0xFFFFFFFE, NCFlag},
       {0xFFFFFFFC, NCFlag, 0xFFFFFFFD, NCFlag},
       {0x7FFFFFFF, CVFlag, 0x80000000, NCFlag},
       {0x7FFFFFFE, CVFlag, 0x7FFFFFFF, CVFlag},
       {0x7FFFFFFD, CFlag, 0x7FFFFFFE, CFlag},
       {0x7FFFFFFC, CFlag, 0x7FFFFFFD, CFlag},
       {0xFFFFFFFF, NFlag, 0x00000000, ZCFlag},
       {0xFFFFFFFE, NFlag, 0xFFFFFFFF, NFlag}},
      {{0xFFFFFFFE, NCFlag, 0xFFFFFFFF, NCFlag},
       {0xFFFFFFFD, NCFlag, 0xFFFFFFFE, NCFlag},
       {0x80000000, NCFlag, 0x80000001, NCFlag},
       {0x7FFFFFFF, CVFlag, 0x80000000, NCFlag},
       {0x7FFFFFFE, CFlag, 0x7FFFFFFF, CFlag},
       {0x7FFFFFFD, CFlag, 0x7FFFFFFE, CFlag},
       {0x00000000, ZCFlag, 0x00000001, CFlag},
       {0xFFFFFFFF, NFlag, 0x00000000, ZCFlag}}};

  for (size_t left = 0; left < input_count; left++) {
    for (size_t right = 0; right < input_count; right++) {
      const Expected& expected = expected_adcs_w[left][right];
      AdcsSbcsHelper(&MacroAssembler::Adcs, inputs[left], inputs[right], 0,
                     expected.carry0_result, expected.carry0_flags);
      AdcsSbcsHelper(&MacroAssembler::Adcs, inputs[left], inputs[right], 1,
                     expected.carry1_result, expected.carry1_flags);
    }
  }

  for (size_t left = 0; left < input_count; left++) {
    for (size_t right = 0; right < input_count; right++) {
      const Expected& expected = expected_sbcs_w[left][right];
      AdcsSbcsHelper(&MacroAssembler::Sbcs, inputs[left], inputs[right], 0,
                     expected.carry0_result, expected.carry0_flags);
      AdcsSbcsHelper(&MacroAssembler::Sbcs, inputs[left], inputs[right], 1,
                     expected.carry1_result, expected.carry1_flags);
    }
  }
}

TEST(adc_sbc_shift) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0);
  __ Mov(x1, 1);
  __ Mov(x2, 0x0123456789ABCDEFL);
  __ Mov(x3, 0xFEDCBA9876543210L);
  __ Mov(x4, 0xFFFFFFFFFFFFFFFFL);

  // Clear the C flag.
  __ Adds(x0, x0, Operand(0));

  __ Adc(x5, x2, Operand(x3));
  __ Adc(x6, x0, Operand(x1, LSL, 60));
  __ Sbc(x7, x4, Operand(x3, LSR, 4));
  __ Adc(x8, x2, Operand(x3, ASR, 4));
  __ Adc(x9, x2, Operand(x3, ROR, 8));

  __ Adc(w10, w2, Operand(w3));
  __ Adc(w11, w0, Operand(w1, LSL, 30));
  __ Sbc(w12, w4, Operand(w3, LSR, 4));
  __ Adc(w13, w2, Operand(w3, ASR, 4));
  __ Adc(w14, w2, Operand(w3, ROR, 8));

  // Set the C flag.
  __ Cmp(w0, Operand(w0));

  __ Adc(x28, x2, Operand(x3));
  __ Adc(x19, x0, Operand(x1, LSL, 60));
  __ Sbc(x20, x4, Operand(x3, LSR, 4));
  __ Adc(x21, x2, Operand(x3, ASR, 4));
  __ Adc(x22, x2, Operand(x3, ROR, 8));

  __ Adc(w23, w2, Operand(w3));
  __ Adc(w24, w0, Operand(w1, LSL, 30));
  __ Sbc(w25, w4, Operand(w3, LSR, 4));
  __ Adc(w26, w2, Operand(w3, ASR, 4));
  __ Adc(w27, w2, Operand(w3, ROR, 8));
  END();

  RUN();

  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFFL, x5);
  CHECK_EQUAL_64(1LL << 60, x6);
  CHECK_EQUAL_64(0xF0123456789ABCDDL, x7);
  CHECK_EQUAL_64(0x0111111111111110L, x8);
  CHECK_EQUAL_64(0x1222222222222221L, x9);

  CHECK_EQUAL_32(0xFFFFFFFF, w10);
  CHECK_EQUAL_32(1 << 30, w11);
  CHECK_EQUAL_32(0xF89ABCDD, w12);
  CHECK_EQUAL_32(0x91111110, w13);
  CHECK_EQUAL_32(0x9A222221, w14);

  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFFLL + 1, x28);
  CHECK_EQUAL_64((1LL << 60) + 1, x19);
  CHECK_EQUAL_64(0xF0123456789ABCDDL + 1, x20);
  CHECK_EQUAL_64(0x0111111111111110L + 1, x21);
  CHECK_EQUAL_64(0x1222222222222221L + 1, x22);

  CHECK_EQUAL_32(0xFFFFFFFFULL + 1, w23);
  CHECK_EQUAL_32((1 << 30) + 1, w24);
  CHECK_EQUAL_32(0xF89ABCDD + 1, w25);
  CHECK_EQUAL_32(0x91111110 + 1, w26);
  CHECK_EQUAL_32(0x9A222221 + 1, w27);
}

TEST(adc_sbc_extend) {
  INIT_V8();
  SETUP();

  START();
  // Clear the C flag.
  __ Adds(x0, x0, Operand(0));

  __ Mov(x0, 0);
  __ Mov(x1, 1);
  __ Mov(x2, 0x0123456789ABCDEFL);

  __ Adc(x10, x1, Operand(w2, UXTB, 1));
  __ Adc(x11, x1, Operand(x2, SXTH, 2));
  __ Sbc(x12, x1, Operand(w2, UXTW, 4));
  __ Adc(x13, x1, Operand(x2, UXTX, 4));

  __ Adc(w14, w1, Operand(w2, UXTB, 1));
  __ Adc(w15, w1, Operand(w2, SXTH, 2));
  __ Adc(w9, w1, Operand(w2, UXTW, 4));

  // Set the C flag.
  __ Cmp(w0, Operand(w0));

  __ Adc(x20, x1, Operand(w2, UXTB, 1));
  __ Adc(x21, x1, Operand(x2, SXTH, 2));
  __ Sbc(x22, x1, Operand(w2, UXTW, 4));
  __ Adc(x23, x1, Operand(x2, UXTX, 4));

  __ Adc(w24, w1, Operand(w2, UXTB, 1));
  __ Adc(w25, w1, Operand(w2, SXTH, 2));
  __ Adc(w26, w1, Operand(w2, UXTW, 4));
  END();

  RUN();

  CHECK_EQUAL_64(0x1DF, x10);
  CHECK_EQUAL_64(0xFFFFFFFFFFFF37BDL, x11);
  CHECK_EQUAL_64(0xFFFFFFF765432110L, x12);
  CHECK_EQUAL_64(0x123456789ABCDEF1L, x13);

  CHECK_EQUAL_32(0x1DF, w14);
  CHECK_EQUAL_32(0xFFFF37BD, w15);
  CHECK_EQUAL_32(0x9ABCDEF1, w9);

  CHECK_EQUAL_64(0x1DF + 1, x20);
  CHECK_EQUAL_64(0xFFFFFFFFFFFF37BDL + 1, x21);
  CHECK_EQUAL_64(0xFFFFFFF765432110L + 1, x22);
  CHECK_EQUAL_64(0x123456789ABCDEF1L + 1, x23);

  CHECK_EQUAL_32(0x1DF + 1, w24);
  CHECK_EQUAL_32(0xFFFF37BD + 1, w25);
  CHECK_EQUAL_32(0x9ABCDEF1 + 1, w26);

  // Check that adc correctly sets the condition flags.
  START();
  __ Mov(x0, 0xFF);
  __ Mov(x1, 0xFFFFFFFFFFFFFFFFL);
  // Clear the C flag.
  __ Adds(x0, x0, Operand(0));
  __ Adcs(x10, x0, Operand(x1, SXTX, 1));
  END();

  RUN();

  CHECK_EQUAL_NZCV(CFlag);

  START();
  __ Mov(x0, 0x7FFFFFFFFFFFFFFFL);
  __ Mov(x1, 1);
  // Clear the C flag.
  __ Adds(x0, x0, Operand(0));
  __ Adcs(x10, x0, Operand(x1, UXTB, 2));
  END();

  RUN();

  CHECK_EQUAL_NZCV(NVFlag);

  START();
  __ Mov(x0, 0x7FFFFFFFFFFFFFFFL);
  // Clear the C flag.
  __ Adds(x0, x0, Operand(0));
  __ Adcs(x10, x0, Operand(1));
  END();

  RUN();

  CHECK_EQUAL_NZCV(NVFlag);
}

TEST(adc_sbc_wide_imm) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0);

  // Clear the C flag.
  __ Adds(x0, x0, Operand(0));

  __ Adc(x7, x0, Operand(0x1234567890ABCDEFUL));
  __ Adc(w8, w0, Operand(0xFFFFFFFF));
  __ Sbc(x9, x0, Operand(0x1234567890ABCDEFUL));
  __ Sbc(w10, w0, Operand(0xFFFFFFFF));
  __ Ngc(x11, Operand(0xFFFFFFFF00000000UL));
  __ Ngc(w12, Operand(0xFFFF0000));

  // Set the C flag.
  __ Cmp(w0, Operand(w0));

  __ Adc(x28, x0, Operand(0x1234567890ABCDEFUL));
  __ Adc(w19, w0, Operand(0xFFFFFFFF));
  __ Sbc(x20, x0, Operand(0x1234567890ABCDEFUL));
  __ Sbc(w21, w0, Operand(0xFFFFFFFF));
  __ Ngc(x22, Operand(0xFFFFFFFF00000000UL));
  __ Ngc(w23, Operand(0xFFFF0000));
  END();

  RUN();

  CHECK_EQUAL_64(0x1234567890ABCDEFUL, x7);
  CHECK_EQUAL_64(0xFFFFFFFF, x8);
  CHECK_EQUAL_64(0xEDCBA9876F543210UL, x9);
  CHECK_EQUAL_64(0, x10);
  CHECK_EQUAL_64(0xFFFFFFFF, x11);
  CHECK_EQUAL_64(0xFFFF, x12);

  CHECK_EQUAL_64(0x1234567890ABCDEFUL + 1, x28);
  CHECK_EQUAL_64(0, x19);
  CHECK_EQUAL_64(0xEDCBA9876F543211UL, x20);
  CHECK_EQUAL_64(1, x21);
  CHECK_EQUAL_64(0x100000000UL, x22);
  CHECK_EQUAL_64(0x10000, x23);
}

TEST(flags) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0);
  __ Mov(x1, 0x1111111111111111L);
  __ Neg(x10, Operand(x0));
  __ Neg(x11, Operand(x1));
  __ Neg(w12, Operand(w1));
  // Clear the C flag.
  __ Adds(x0, x0, Operand(0));
  __ Ngc(x13, Operand(x0));
  // Set the C flag.
  __ Cmp(x0, Operand(x0));
  __ Ngc(w14, Operand(w0));
  END();

  RUN();

  CHECK_EQUAL_64(0, x10);
  CHECK_EQUAL_64(-0x1111111111111111L, x11);
  CHECK_EQUAL_32(-0x11111111, w12);
  CHECK_EQUAL_64(-1L, x13);
  CHECK_EQUAL_32(0, w14);

  START();
  __ Mov(x0, 0);
  __ Cmp(x0, Operand(x0));
  END();

  RUN();

  CHECK_EQUAL_NZCV(ZCFlag);

  START();
  __ Mov(w0, 0);
  __ Cmp(w0, Operand(w0));
  END();

  RUN();

  CHECK_EQUAL_NZCV(ZCFlag);

  START();
  __ Mov(x0, 0);
  __ Mov(x1, 0x1111111111111111L);
  __ Cmp(x0, Operand(x1));
  END();

  RUN();

  CHECK_EQUAL_NZCV(NFlag);

  START();
  __ Mov(w0, 0);
  __ Mov(w1, 0x11111111);
  __ Cmp(w0, Operand(w1));
  END();

  RUN();

  CHECK_EQUAL_NZCV(NFlag);

  START();
  __ Mov(x1, 0x1111111111111111L);
  __ Cmp(x1, Operand(0));
  END();

  RUN();

  CHECK_EQUAL_NZCV(CFlag);

  START();
  __ Mov(w1, 0x11111111);
  __ Cmp(w1, Operand(0));
  END();

  RUN();

  CHECK_EQUAL_NZCV(CFlag);

  START();
  __ Mov(x0, 1);
  __ Mov(x1, 0x7FFFFFFFFFFFFFFFL);
  __ Cmn(x1, Operand(x0));
  END();

  RUN();

  CHECK_EQUAL_NZCV(NVFlag);

  START();
  __ Mov(w0, 1);
  __ Mov(w1, 0x7FFFFFFF);
  __ Cmn(w1, Operand(w0));
  END();

  RUN();

  CHECK_EQUAL_NZCV(NVFlag);

  START();
  __ Mov(x0, 1);
  __ Mov(x1, 0xFFFFFFFFFFFFFFFFL);
  __ Cmn(x1, Operand(x0));
  END();

  RUN();

  CHECK_EQUAL_NZCV(ZCFlag);

  START();
  __ Mov(w0, 1);
  __ Mov(w1, 0xFFFFFFFF);
  __ Cmn(w1, Operand(w0));
  END();

  RUN();

  CHECK_EQUAL_NZCV(ZCFlag);

  START();
  __ Mov(w0, 0);
  __ Mov(w1, 1);
  // Clear the C flag.
  __ Adds(w0, w0, Operand(0));
  __ Ngcs(w0, Operand(w1));
  END();

  RUN();

  CHECK_EQUAL_NZCV(NFlag);

  START();
  __ Mov(w0, 0);
  __ Mov(w1, 0);
  // Set the C flag.
  __ Cmp(w0, Operand(w0));
  __ Ngcs(w0, Operand(w1));
  END();

  RUN();

  CHECK_EQUAL_NZCV(ZCFlag);
}

TEST(cmp_shift) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x28, 0xF0000000);
  __ Mov(x19, 0xF000000010000000UL);
  __ Mov(x20, 0xF0000000F0000000UL);
  __ Mov(x21, 0x7800000078000000UL);
  __ Mov(x22, 0x3C0000003C000000UL);
  __ Mov(x23, 0x8000000780000000UL);
  __ Mov(x24, 0x0000000F00000000UL);
  __ Mov(x25, 0x00000003C0000000UL);
  __ Mov(x26, 0x8000000780000000UL);
  __ Mov(x27, 0xC0000003);

  __ Cmp(w20, Operand(w21, LSL, 1));
  __ Mrs(x0, NZCV);

  __ Cmp(x20, Operand(x22, LSL, 2));
  __ Mrs(x1, NZCV);

  __ Cmp(w19, Operand(w23, LSR, 3));
  __ Mrs(x2, NZCV);

  __ Cmp(x28, Operand(x24, LSR, 4));
  __ Mrs(x3, NZCV);

  __ Cmp(w20, Operand(w25, ASR, 2));
  __ Mrs(x4, NZCV);

  __ Cmp(x20, Operand(x26, ASR, 3));
  __ Mrs(x5, NZCV);

  __ Cmp(w27, Operand(w22, ROR, 28));
  __ Mrs(x6, NZCV);

  __ Cmp(x20, Operand(x21, ROR, 31));
  __ Mrs(x7, NZCV);
  END();

  RUN();

  CHECK_EQUAL_32(ZCFlag, w0);
  CHECK_EQUAL_32(ZCFlag, w1);
  CHECK_EQUAL_32(ZCFlag, w2);
  CHECK_EQUAL_32(ZCFlag, w3);
  CHECK_EQUAL_32(ZCFlag, w4);
  CHECK_EQUAL_32(ZCFlag, w5);
  CHECK_EQUAL_32(ZCFlag, w6);
  CHECK_EQUAL_32(ZCFlag, w7);
}

TEST(cmp_extend) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(w20, 0x2);
  __ Mov(w21, 0x1);
  __ Mov(x22, 0xFFFFFFFFFFFFFFFFUL);
  __ Mov(x23, 0xFF);
  __ Mov(x24, 0xFFFFFFFFFFFFFFFEUL);
  __ Mov(x25, 0xFFFF);
  __ Mov(x26, 0xFFFFFFFF);

  __ Cmp(w20, Operand(w21, LSL, 1));
  __ Mrs(x0, NZCV);

  __ Cmp(x22, Operand(x23, SXTB, 0));
  __ Mrs(x1, NZCV);

  __ Cmp(x24, Operand(x23, SXTB, 1));
  __ Mrs(x2, NZCV);

  __ Cmp(x24, Operand(x23, UXTB, 1));
  __ Mrs(x3, NZCV);

  __ Cmp(w22, Operand(w25, UXTH));
  __ Mrs(x4, NZCV);

  __ Cmp(x22, Operand(x25, SXTH));
  __ Mrs(x5, NZCV);

  __ Cmp(x22, Operand(x26, UXTW));
  __ Mrs(x6, NZCV);

  __ Cmp(x24, Operand(x26, SXTW, 1));
  __ Mrs(x7, NZCV);
  END();

  RUN();

  CHECK_EQUAL_32(ZCFlag, w0);
  CHECK_EQUAL_32(ZCFlag, w1);
  CHECK_EQUAL_32(ZCFlag, w2);
  CHECK_EQUAL_32(NCFlag, w3);
  CHECK_EQUAL_32(NCFlag, w4);
  CHECK_EQUAL_32(ZCFlag, w5);
  CHECK_EQUAL_32(NCFlag, w6);
  CHECK_EQUAL_32(ZCFlag, w7);
}

TEST(ccmp) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(w16, 0);
  __ Mov(w17, 1);
  __ Cmp(w16, w16);
  __ Ccmp(w16, w17, NCFlag, eq);
  __ Mrs(x0, NZCV);

  __ Cmp(w16, w16);
  __ Ccmp(w16, w17, NCFlag, ne);
  __ Mrs(x1, NZCV);

  __ Cmp(x16, x16);
  __ Ccmn(x16, 2, NZCVFlag, eq);
  __ Mrs(x2, NZCV);

  __ Cmp(x16, x16);
  __ Ccmn(x16, 2, NZCVFlag, ne);
  __ Mrs(x3, NZCV);

  __ ccmp(x16, x16, NZCVFlag, al);
  __ Mrs(x4, NZCV);

  __ ccmp(x16, x16, NZCVFlag, nv);
  __ Mrs(x5, NZCV);

  END();

  RUN();

  CHECK_EQUAL_32(NFlag, w0);
  CHECK_EQUAL_32(NCFlag, w1);
  CHECK_EQUAL_32(NoFlag, w2);
  CHECK_EQUAL_32(NZCVFlag, w3);
  CHECK_EQUAL_32(ZCFlag, w4);
  CHECK_EQUAL_32(ZCFlag, w5);
}

TEST(ccmp_wide_imm) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(w20, 0);

  __ Cmp(w20, Operand(w20));
  __ Ccmp(w20, Operand(0x12345678), NZCVFlag, eq);
  __ Mrs(x0, NZCV);

  __ Cmp(w20, Operand(w20));
  __ Ccmp(x20, Operand(0xFFFFFFFFFFFFFFFFUL), NZCVFlag, eq);
  __ Mrs(x1, NZCV);
  END();

  RUN();

  CHECK_EQUAL_32(NFlag, w0);
  CHECK_EQUAL_32(NoFlag, w1);
}

TEST(ccmp_shift_extend) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(w20, 0x2);
  __ Mov(w21, 0x1);
  __ Mov(x22, 0xFFFFFFFFFFFFFFFFUL);
  __ Mov(x23, 0xFF);
  __ Mov(x24, 0xFFFFFFFFFFFFFFFEUL);

  __ Cmp(w20, Operand(w20));
  __ Ccmp(w20, Operand(w21, LSL, 1), NZCVFlag, eq);
  __ Mrs(x0, NZCV);

  __ Cmp(w20, Operand(w20));
  __ Ccmp(x22, Operand(x23, SXTB, 0), NZCVFlag, eq);
  __ Mrs(x1, NZCV);

  __ Cmp(w20, Operand(w20));
  __ Ccmp(x24, Operand(x23, SXTB, 1), NZCVFlag, eq);
  __ Mrs(x2, NZCV);

  __ Cmp(w20, Operand(w20));
  __ Ccmp(x24, Operand(x23, UXTB, 1), NZCVFlag, eq);
  __ Mrs(x3, NZCV);

  __ Cmp(w20, Operand(w20));
  __ Ccmp(x24, Operand(x23, UXTB, 1), NZCVFlag, ne);
  __ Mrs(x4, NZCV);
  END();

  RUN();

  CHECK_EQUAL_32(ZCFlag, w0);
  CHECK_EQUAL_32(ZCFlag, w1);
  CHECK_EQUAL_32(ZCFlag, w2);
  CHECK_EQUAL_32(NCFlag, w3);
  CHECK_EQUAL_32(NZCVFlag, w4);
}

TEST(csel) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x16, 0);
  __ Mov(x24, 0x0000000F0000000FUL);
  __ Mov(x25, 0x0000001F0000001FUL);
  __ Mov(x26, 0);
  __ Mov(x27, 0);

  __ Cmp(w16, 0);
  __ Csel(w0, w24, w25, eq);
  __ Csel(w1, w24, w25, ne);
  __ Csinc(w2, w24, w25, mi);
  __ Csinc(w3, w24, w25, pl);

  __ csel(w13, w24, w25, al);
  __ csel(x14, x24, x25, nv);

  __ Cmp(x16, 1);
  __ Csinv(x4, x24, x25, gt);
  __ Csinv(x5, x24, x25, le);
  __ Csneg(x6, x24, x25, hs);
  __ Csneg(x7, x24, x25, lo);

  __ Cset(w8, ne);
  __ Csetm(w9, ne);
  __ Cinc(x10, x25, ne);
  __ Cinv(x11, x24, ne);
  __ Cneg(x12, x24, ne);

  __ csel(w15, w24, w25, al);
  __ csel(x28, x24, x25, nv);

  __ CzeroX(x24, ne);
  __ CzeroX(x25, eq);

  __ CmovX(x26, x25, ne);
  __ CmovX(x27, x25, eq);
  END();

  RUN();

  CHECK_EQUAL_64(0x0000000F, x0);
  CHECK_EQUAL_64(0x0000001F, x1);
  CHECK_EQUAL_64(0x00000020, x2);
  CHECK_EQUAL_64(0x0000000F, x3);
  CHECK_EQUAL_64(0xFFFFFFE0FFFFFFE0UL, x4);
  CHECK_EQUAL_64(0x0000000F0000000FUL, x5);
  CHECK_EQUAL_64(0xFFFFFFE0FFFFFFE1UL, x6);
  CHECK_EQUAL_64(0x0000000F0000000FUL, x7);
  CHECK_EQUAL_64(0x00000001, x8);
  CHECK_EQUAL_64(0xFFFFFFFF, x9);
  CHECK_EQUAL_64(0x0000001F00000020UL, x10);
  CHECK_EQUAL_64(0xFFFFFFF0FFFFFFF0UL, x11);
  CHECK_EQUAL_64(0xFFFFFFF0FFFFFFF1UL, x12);
  CHECK_EQUAL_64(0x0000000F, x13);
  CHECK_EQUAL_64(0x0000000F0000000FUL, x14);
  CHECK_EQUAL_64(0x0000000F, x15);
  CHECK_EQUAL_64(0x0000000F0000000FUL, x28);
  CHECK_EQUAL_64(0, x24);
  CHECK_EQUAL_64(0x0000001F0000001FUL, x25);
  CHECK_EQUAL_64(0x0000001F0000001FUL, x26);
  CHECK_EQUAL_64(0, x27);
}

TEST(csel_imm) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x28, 0);
  __ Mov(x19, 0x80000000);
  __ Mov(x20, 0x8000000000000000UL);

  __ Cmp(x28, Operand(0));
  __ Csel(w0, w19, -2, ne);
  __ Csel(w1, w19, -1, ne);
  __ Csel(w2, w19, 0, ne);
  __ Csel(w3, w19, 1, ne);
  __ Csel(w4, w19, 2, ne);
  __ Csel(w5, w19, Operand(w19, ASR, 31), ne);
  __ Csel(w6, w19, Operand(w19, ROR, 1), ne);
  __ Csel(w7, w19, 3, eq);

  __ Csel(x8, x20, -2, ne);
  __ Csel(x9, x20, -1, ne);
  __ Csel(x10, x20, 0, ne);
  __ Csel(x11, x20, 1, ne);
  __ Csel(x12, x20, 2, ne);
  __ Csel(x13, x20, Operand(x20, ASR, 63), ne);
  __ Csel(x14, x20, Operand(x20, ROR, 1), ne);
  __ Csel(x15, x20, 3, eq);

  END();

  RUN();

  CHECK_EQUAL_32(-2, w0);
  CHECK_EQUAL_32(-1, w1);
  CHECK_EQUAL_32(0, w2);
  CHECK_EQUAL_32(1, w3);
  CHECK_EQUAL_32(2, w4);
  CHECK_EQUAL_32(-1, w5);
  CHECK_EQUAL_32(0x40000000, w6);
  CHECK_EQUAL_32(0x80000000, w7);

  CHECK_EQUAL_64(-2, x8);
  CHECK_EQUAL_64(-1, x9);
  CHECK_EQUAL_64(0, x10);
  CHECK_EQUAL_64(1, x11);
  CHECK_EQUAL_64(2, x12);
  CHECK_EQUAL_64(-1, x13);
  CHECK_EQUAL_64(0x4000000000000000UL, x14);
  CHECK_EQUAL_64(0x8000000000000000UL, x15);
}

TEST(lslv) {
  INIT_V8();
  SETUP();

  uint64_t value = 0x0123456789ABCDEFUL;
  int shift[] = {1, 3, 5, 9, 17, 33};

  START();
  __ Mov(x0, value);
  __ Mov(w1, shift[0]);
  __ Mov(w2, shift[1]);
  __ Mov(w3, shift[2]);
  __ Mov(w4, shift[3]);
  __ Mov(w5, shift[4]);
  __ Mov(w6, shift[5]);

  __ lslv(x0, x0, xzr);

  __ Lsl(x16, x0, x1);
  __ Lsl(x17, x0, x2);
  __ Lsl(x28, x0, x3);
  __ Lsl(x19, x0, x4);
  __ Lsl(x20, x0, x5);
  __ Lsl(x21, x0, x6);

  __ Lsl(w22, w0, w1);
  __ Lsl(w23, w0, w2);
  __ Lsl(w24, w0, w3);
  __ Lsl(w25, w0, w4);
  __ Lsl(w26, w0, w5);
  __ Lsl(w27, w0, w6);
  END();

  RUN();

  CHECK_EQUAL_64(value, x0);
  CHECK_EQUAL_64(value << (shift[0] & 63), x16);
  CHECK_EQUAL_64(value << (shift[1] & 63), x17);
  CHECK_EQUAL_64(value << (shift[2] & 63), x28);
  CHECK_EQUAL_64(value << (shift[3] & 63), x19);
  CHECK_EQUAL_64(value << (shift[4] & 63), x20);
  CHECK_EQUAL_64(value << (shift[5] & 63), x21);
  CHECK_EQUAL_32(value << (shift[0] & 31), w22);
  CHECK_EQUAL_32(value << (shift[1] & 31), w23);
  CHECK_EQUAL_32(value << (shift[2] & 31), w24);
  CHECK_EQUAL_32(value << (shift[3] & 31), w25);
  CHECK_EQUAL_32(value << (shift[4] & 31), w26);
  CHECK_EQUAL_32(value << (shift[5] & 31), w27);
}

TEST(lsrv) {
  INIT_V8();
  SETUP();

  uint64_t value = 0x0123456789ABCDEFUL;
  int shift[] = {1, 3, 5, 9, 17, 33};

  START();
  __ Mov(x0, value);
  __ Mov(w1, shift[0]);
  __ Mov(w2, shift[1]);
  __ Mov(w3, shift[2]);
  __ Mov(w4, shift[3]);
  __ Mov(w5, shift[4]);
  __ Mov(w6, shift[5]);

  __ lsrv(x0, x0, xzr);

  __ Lsr(x16, x0, x1);
  __ Lsr(x17, x0, x2);
  __ Lsr(x28, x0, x3);
  __ Lsr(x19, x0, x4);
  __ Lsr(x20, x0, x5);
  __ Lsr(x21, x0, x6);

  __ Lsr(w22, w0, w1);
  __ Lsr(w23, w0, w2);
  __ Lsr(w24, w0, w3);
  __ Lsr(w25, w0, w4);
  __ Lsr(w26, w0, w5);
  __ Lsr(w27, w0, w6);
  END();

  RUN();

  CHECK_EQUAL_64(value, x0);
  CHECK_EQUAL_64(value >> (shift[0] & 63), x16);
  CHECK_EQUAL_64(value >> (shift[1] & 63), x17);
  CHECK_EQUAL_64(value >> (shift[2] & 63), x28);
  CHECK_EQUAL_64(value >> (shift[3] & 63), x19);
  CHECK_EQUAL_64(value >> (shift[4] & 63), x20);
  CHECK_EQUAL_64(value >> (shift[5] & 63), x21);

  value &= 0xFFFFFFFFUL;
  CHECK_EQUAL_32(value >> (shift[0] & 31), w22);
  CHECK_EQUAL_32(value >> (shift[1] & 31), w23);
  CHECK_EQUAL_32(value >> (shift[2] & 31), w24);
  CHECK_EQUAL_32(value >> (shift[3] & 31), w25);
  CHECK_EQUAL_32(value >> (shift[4] & 31), w26);
  CHECK_EQUAL_32(value >> (shift[5] & 31), w27);
}

TEST(asrv) {
  INIT_V8();
  SETUP();

  int64_t value = 0xFEDCBA98FEDCBA98UL;
  int shift[] = {1, 3, 5, 9, 17, 33};

  START();
  __ Mov(x0, value);
  __ Mov(w1, shift[0]);
  __ Mov(w2, shift[1]);
  __ Mov(w3, shift[2]);
  __ Mov(w4, shift[3]);
  __ Mov(w5, shift[4]);
  __ Mov(w6, shift[5]);

  __ asrv(x0, x0, xzr);

  __ Asr(x16, x0, x1);
  __ Asr(x17, x0, x2);
  __ Asr(x28, x0, x3);
  __ Asr(x19, x0, x4);
  __ Asr(x20, x0, x5);
  __ Asr(x21, x0, x6);

  __ Asr(w22, w0, w1);
  __ Asr(w23, w0, w2);
  __ Asr(w24, w0, w3);
  __ Asr(w25, w0, w4);
  __ Asr(w26, w0, w5);
  __ Asr(w27, w0, w6);
  END();

  RUN();

  CHECK_EQUAL_64(value, x0);
  CHECK_EQUAL_64(value >> (shift[0] & 63), x16);
  CHECK_EQUAL_64(value >> (shift[1] & 63), x17);
  CHECK_EQUAL_64(value >> (shift[2] & 63), x28);
  CHECK_EQUAL_64(value >> (shift[3] & 63), x19);
  CHECK_EQUAL_64(value >> (shift[4] & 63), x20);
  CHECK_EQUAL_64(value >> (shift[5] & 63), x21);

  int32_t value32 = static_cast<int32_t>(value & 0xFFFFFFFFUL);
  CHECK_EQUAL_32(value32 >> (shift[0] & 31), w22);
  CHECK_EQUAL_32(value32 >> (shift[1] & 31), w23);
  CHECK_EQUAL_32(value32 >> (shift[2] & 31), w24);
  CHECK_EQUAL_32(value32 >> (shift[3] & 31), w25);
  CHECK_EQUAL_32(value32 >> (shift[4] & 31), w26);
  CHECK_EQUAL_32(value32 >> (shift[5] & 31), w27);
}

TEST(rorv) {
  INIT_V8();
  SETUP();

  uint64_t value = 0x0123456789ABCDEFUL;
  int shift[] = {4, 8, 12, 16, 24, 36};

  START();
  __ Mov(x0, value);
  __ Mov(w1, shift[0]);
  __ Mov(w2, shift[1]);
  __ Mov(w3, shift[2]);
  __ Mov(w4, shift[3]);
  __ Mov(w5, shift[4]);
  __ Mov(w6, shift[5]);

  __ rorv(x0, x0, xzr);

  __ Ror(x16, x0, x1);
  __ Ror(x17, x0, x2);
  __ Ror(x28, x0, x3);
  __ Ror(x19, x0, x4);
  __ Ror(x20, x0, x5);
  __ Ror(x21, x0, x6);

  __ Ror(w22, w0, w1);
  __ Ror(w23, w0, w2);
  __ Ror(w24, w0, w3);
  __ Ror(w25, w0, w4);
  __ Ror(w26, w0, w5);
  __ Ror(w27, w0, w6);
  END();

  RUN();

  CHECK_EQUAL_64(value, x0);
  CHECK_EQUAL_64(0xF0123456789ABCDEUL, x16);
  CHECK_EQUAL_64(0xEF0123456789ABCDUL, x17);
  CHECK_EQUAL_64(0xDEF0123456789ABCUL, x28);
  CHECK_EQUAL_64(0xCDEF0123456789ABUL, x19);
  CHECK_EQUAL_64(0xABCDEF0123456789UL, x20);
  CHECK_EQUAL_64(0x789ABCDEF0123456UL, x21);
  CHECK_EQUAL_32(0xF89ABCDE, w22);
  CHECK_EQUAL_32(0xEF89ABCD, w23);
  CHECK_EQUAL_32(0xDEF89ABC, w24);
  CHECK_EQUAL_32(0xCDEF89AB, w25);
  CHECK_EQUAL_32(0xABCDEF89, w26);
  CHECK_EQUAL_32(0xF89ABCDE, w27);
}

TEST(bfm) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x1, 0x0123456789ABCDEFL);

  __ Mov(x10, 0x8888888888888888L);
  __ Mov(x11, 0x8888888888888888L);
  __ Mov(x12, 0x8888888888888888L);
  __ Mov(x13, 0x8888888888888888L);
  __ Mov(w20, 0x88888888);
  __ Mov(w21, 0x88888888);

  __ bfm(x10, x1, 16, 31);
  __ bfm(x11, x1, 32, 15);

  __ bfm(w20, w1, 16, 23);
  __ bfm(w21, w1, 24, 15);

  // Aliases.
  __ Bfi(x12, x1, 16, 8);
  __ Bfxil(x13, x1, 16, 8);
  END();

  RUN();

  CHECK_EQUAL_64(0x88888888888889ABL, x10);
  CHECK_EQUAL_64(0x8888CDEF88888888L, x11);

  CHECK_EQUAL_32(0x888888AB, w20);
  CHECK_EQUAL_32(0x88CDEF88, w21);

  CHECK_EQUAL_64(0x8888888888EF8888L, x12);
  CHECK_EQUAL_64(0x88888888888888ABL, x13);
}

TEST(sbfm) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x1, 0x0123456789ABCDEFL);
  __ Mov(x2, 0xFEDCBA9876543210L);

  __ sbfm(x10, x1, 16, 31);
  __ sbfm(x11, x1, 32, 15);
  __ sbfm(x12, x1, 32, 47);
  __ sbfm(x13, x1, 48, 35);

  __ sbfm(w14, w1, 16, 23);
  __ sbfm(w15, w1, 24, 15);
  __ sbfm(w16, w2, 16, 23);
  __ sbfm(w17, w2, 24, 15);

  // Aliases.
  __ Asr(x3, x1, 32);
  __ Asr(x19, x2, 32);
  __ Sbfiz(x20, x1, 8, 16);
  __ Sbfiz(x21, x2, 8, 16);
  __ Sbfx(x22, x1, 8, 16);
  __ Sbfx(x23, x2, 8, 16);
  __ Sxtb(x24, w1);
  __ Sxtb(x25, x2);
  __ Sxth(x26, w1);
  __ Sxth(x27, x2);
  __ Sxtw(x28, w1);
  __ Sxtw(x29, x2);
  END();

  RUN();

  CHECK_EQUAL_64(0xFFFFFFFFFFFF89ABL, x10);
  CHECK_EQUAL_64(0xFFFFCDEF00000000L, x11);
  CHECK_EQUAL_64(0x4567L, x12);
  CHECK_EQUAL_64(0x789ABCDEF0000L, x13);

  CHECK_EQUAL_32(0xFFFFFFAB, w14);
  CHECK_EQUAL_32(0xFFCDEF00, w15);
  CHECK_EQUAL_32(0x54, w16);
  CHECK_EQUAL_32(0x00321000, w17);

  CHECK_EQUAL_64(0x01234567L, x3);
  CHECK_EQUAL_64(0xFFFFFFFFFEDCBA98L, x19);
  CHECK_EQUAL_64(0xFFFFFFFFFFCDEF00L, x20);
  CHECK_EQUAL_64(0x321000L, x21);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFABCDL, x22);
  CHECK_EQUAL_64(0x5432L, x23);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFEFL, x24);
  CHECK_EQUAL_64(0x10, x25);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFCDEFL, x26);
  CHECK_EQUAL_64(0x3210, x27);
  CHECK_EQUAL_64(0xFFFFFFFF89ABCDEFL, x28);
  CHECK_EQUAL_64(0x76543210, x29);
}

TEST(ubfm) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x1, 0x0123456789ABCDEFL);
  __ Mov(x2, 0xFEDCBA9876543210L);

  __ Mov(x10, 0x8888888888888888L);
  __ Mov(x11, 0x8888888888888888L);

  __ ubfm(x10, x1, 16, 31);
  __ ubfm(x11, x1, 32, 15);
  __ ubfm(x12, x1, 32, 47);
  __ ubfm(x13, x1, 48, 35);

  __ ubfm(w25, w1, 16, 23);
  __ ubfm(w26, w1, 24, 15);
  __ ubfm(w27, w2, 16, 23);
  __ ubfm(w28, w2, 24, 15);

  // Aliases
  __ Lsl(x15, x1, 63);
  __ Lsl(x16, x1, 0);
  __ Lsr(x17, x1, 32);
  __ Ubfiz(x3, x1, 8, 16);
  __ Ubfx(x19, x1, 8, 16);
  __ Uxtb(x20, x1);
  __ Uxth(x21, x1);
  __ Uxtw(x22, x1);
  END();

  RUN();

  CHECK_EQUAL_64(0x00000000000089ABL, x10);
  CHECK_EQUAL_64(0x0000CDEF00000000L, x11);
  CHECK_EQUAL_64(0x4567L, x12);
  CHECK_EQUAL_64(0x789ABCDEF0000L, x13);

  CHECK_EQUAL_32(0x000000AB, w25);
  CHECK_EQUAL_32(0x00CDEF00, w26);
  CHECK_EQUAL_32(0x54, w27);
  CHECK_EQUAL_32(0x00321000, w28);

  CHECK_EQUAL_64(0x8000000000000000L, x15);
  CHECK_EQUAL_64(0x0123456789ABCDEFL, x16);
  CHECK_EQUAL_64(0x01234567L, x17);
  CHECK_EQUAL_64(0xCDEF00L, x3);
  CHECK_EQUAL_64(0xABCDL, x19);
  CHECK_EQUAL_64(0xEFL, x20);
  CHECK_EQUAL_64(0xCDEFL, x21);
  CHECK_EQUAL_64(0x89ABCDEFL, x22);
}

TEST(extr) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x1, 0x0123456789ABCDEFL);
  __ Mov(x2, 0xFEDCBA9876543210L);

  __ Extr(w10, w1, w2, 0);
  __ Extr(x11, x1, x2, 0);
  __ Extr(w12, w1, w2, 1);
  __ Extr(x13, x2, x1, 2);

  __ Ror(w20, w1, 0);
  __ Ror(x21, x1, 0);
  __ Ror(w22, w2, 17);
  __ Ror(w23, w1, 31);
  __ Ror(x24, x2, 1);
  __ Ror(x25, x1, 63);
  END();

  RUN();

  CHECK_EQUAL_64(0x76543210, x10);
  CHECK_EQUAL_64(0xFEDCBA9876543210L, x11);
  CHECK_EQUAL_64(0xBB2A1908, x12);
  CHECK_EQUAL_64(0x0048D159E26AF37BUL, x13);
  CHECK_EQUAL_64(0x89ABCDEF, x20);
  CHECK_EQUAL_64(0x0123456789ABCDEFL, x21);
  CHECK_EQUAL_64(0x19083B2A, x22);
  CHECK_EQUAL_64(0x13579BDF, x23);
  CHECK_EQUAL_64(0x7F6E5D4C3B2A1908UL, x24);
  CHECK_EQUAL_64(0x02468ACF13579BDEUL, x25);
}

TEST(fmov_imm) {
  INIT_V8();
  SETUP();

  START();
  __ Fmov(s11, 1.0);
  __ Fmov(d22, -13.0);
  __ Fmov(s1, 255.0);
  __ Fmov(d2, 12.34567);
  __ Fmov(s3, 0.0);
  __ Fmov(d4, 0.0);
  __ Fmov(s5, kFP32PositiveInfinity);
  __ Fmov(d6, kFP64NegativeInfinity);
  END();

  RUN();

  CHECK_EQUAL_FP32(1.0, s11);
  CHECK_EQUAL_FP64(-13.0, d22);
  CHECK_EQUAL_FP32(255.0, s1);
  CHECK_EQUAL_FP64(12.34567, d2);
  CHECK_EQUAL_FP32(0.0, s3);
  CHECK_EQUAL_FP64(0.0, d4);
  CHECK_EQUAL_FP32(kFP32PositiveInfinity, s5);
  CHECK_EQUAL_FP64(kFP64NegativeInfinity, d6);
}

TEST(fmov_reg) {
  INIT_V8();
  SETUP();

  START();
  __ Fmov(s20, 1.0);
  __ Fmov(w10, s20);
  __ Fmov(s30, w10);
  __ Fmov(s5, s20);
  __ Fmov(d1, -13.0);
  __ Fmov(x1, d1);
  __ Fmov(d2, x1);
  __ Fmov(d4, d1);
  __ Fmov(d6, base::bit_cast<double>(0x0123456789ABCDEFL));
  __ Fmov(s6, s6);
  END();

  RUN();

  CHECK_EQUAL_32(base::bit_cast<uint32_t>(1.0f), w10);
  CHECK_EQUAL_FP32(1.0, s30);
  CHECK_EQUAL_FP32(1.0, s5);
  CHECK_EQUAL_64(base::bit_cast<uint64_t>(-13.0), x1);
  CHECK_EQUAL_FP64(-13.0, d2);
  CHECK_EQUAL_FP64(-13.0, d4);
  CHECK_EQUAL_FP32(base::bit_cast<float>(0x89ABCDEF), s6);
}

TEST(fadd) {
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

  __ Fadd(s0, s17, s18);
  __ Fadd(s1, s18, s19);
  __ Fadd(s2, s14, s18);
  __ Fadd(s3, s15, s18);
  __ Fadd(s4, s16, s18);
  __ Fadd(s5, s15, s16);
  __ Fadd(s6, s16, s15);

  __ Fadd(d7, d30, d31);
  __ Fadd(d8, d29, d31);
  __ Fadd(d9, d26, d31);
  __ Fadd(d10, d27, d31);
  __ Fadd(d11, d28, d31);
  __ Fadd(d12, d27, d28);
  __ Fadd(d13, d28, d27);
  END();

  RUN();

  CHECK_EQUAL_FP32(4.25, s0);
  CHECK_EQUAL_FP32(1.0, s1);
  CHECK_EQUAL_FP32(1.0, s2);
  CHECK_EQUAL_FP32(kFP32PositiveInfinity, s3);
  CHECK_EQUAL_FP32(kFP32NegativeInfinity, s4);
  CHECK_EQUAL_FP32(kFP32DefaultNaN, s5);
  CHECK_EQUAL_FP32(kFP32DefaultNaN, s6);
  CHECK_EQUAL_FP64(0.25, d7);
  CHECK_EQUAL_FP64(2.25, d8);
  CHECK_EQUAL_FP64(2.25, d9);
  CHECK_EQUAL_FP64(kFP64PositiveInfinity, d10);
  CHECK_EQUAL_FP64(kFP64NegativeInfinity, d11);
  CHECK_EQUAL_FP64(k
"""


```