Response: 
Prompt: 
```
这是目录为v8/test/unittests/assembler/disasm-arm64-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共4部分，请归纳一下它的功能

"""
, MemOperand(x20, 4, PostIndex)),
          "st1 {v5.s}[1], [x20], #4");
  COMPARE(St1(v6.V2D(), 0, MemOperand(x21, 8, PostIndex)),
          "st1 {v6.d}[0], [x21], #8");
  COMPARE(St1(v7.B(), 7, MemOperand(x22, 1, PostIndex)),
          "st1 {v7.b}[7], [x22], #1");
  COMPARE(St1(v8_.B(), 15, MemOperand(x23, x3, PostIndex)),
          "st1 {v8.b}[15], [x23], x3");
  COMPARE(St1(v9.H(), 3, MemOperand(x24, x4, PostIndex)),
          "st1 {v9.h}[3], [x24], x4");
  COMPARE(St1(v10.H(), 7, MemOperand(x25, 2, PostIndex)),
          "st1 {v10.h}[7], [x25], #2");
  COMPARE(St1(v11.S(), 1, MemOperand(x26, 4, PostIndex)),
          "st1 {v11.s}[1], [x26], #4");
  COMPARE(St1(v12.S(), 3, MemOperand(x27, x5, PostIndex)),
          "st1 {v12.s}[3], [cp], x5");
  COMPARE(St1(v13.D(), 1, MemOperand(sp, x6, PostIndex)),
          "st1 {v13.d}[1], [sp], x6");
  COMPARE(St2(v0.V8B(), v1.V8B(), 0, MemOperand(x15, x0, PostIndex)),
          "st2 {v0.b, v1.b}[0], [x15], x0");
  COMPARE(St2(v1.V16B(), v2.V16B(), 1, MemOperand(x16, 2, PostIndex)),
          "st2 {v1.b, v2.b}[1], [x16], #2");
  COMPARE(St2(v2.V4H(), v3.V4H(), 2, MemOperand(x17, 4, PostIndex)),
          "st2 {v2.h, v3.h}[2], [x17], #4");
  COMPARE(St2(v3.V8H(), v4.V8H(), 3, MemOperand(x18, x1, PostIndex)),
          "st2 {v3.h, v4.h}[3], [x18], x1");
  COMPARE(St2(v4.V2S(), v5.V2S(), 0, MemOperand(x19, x2, PostIndex)),
          "st2 {v4.s, v5.s}[0], [x19], x2");
  COMPARE(St2(v5.V4S(), v6.V4S(), 1, MemOperand(x20, 8, PostIndex)),
          "st2 {v5.s, v6.s}[1], [x20], #8");
  COMPARE(St2(v6.V2D(), v7.V2D(), 0, MemOperand(x21, 16, PostIndex)),
          "st2 {v6.d, v7.d}[0], [x21], #16");
  COMPARE(St2(v7.B(), v8_.B(), 7, MemOperand(x22, 2, PostIndex)),
          "st2 {v7.b, v8.b}[7], [x22], #2");
  COMPARE(St2(v8_.B(), v9.B(), 15, MemOperand(x23, x3, PostIndex)),
          "st2 {v8.b, v9.b}[15], [x23], x3");
  COMPARE(St2(v9.H(), v10.H(), 3, MemOperand(x24, x4, PostIndex)),
          "st2 {v9.h, v10.h}[3], [x24], x4");
  COMPARE(St2(v10.H(), v11.H(), 7, MemOperand(x25, 4, PostIndex)),
          "st2 {v10.h, v11.h}[7], [x25], #4");
  COMPARE(St2(v11.S(), v12.S(), 1, MemOperand(x26, 8, PostIndex)),
          "st2 {v11.s, v12.s}[1], [x26], #8");
  COMPARE(St2(v12.S(), v13.S(), 3, MemOperand(x27, x5, PostIndex)),
          "st2 {v12.s, v13.s}[3], [cp], x5");
  COMPARE(St2(v13.D(), v14.D(), 1, MemOperand(sp, x6, PostIndex)),
          "st2 {v13.d, v14.d}[1], [sp], x6");
  COMPARE(St3(VLIST3(v0.V8B()), 0, MemOperand(x15, x0, PostIndex)),
          "st3 {v0.b, v1.b, v2.b}[0], [x15], x0");
  COMPARE(St3(VLIST3(v1.V16B()), 1, MemOperand(x16, 3, PostIndex)),
          "st3 {v1.b, v2.b, v3.b}[1], [x16], #3");
  COMPARE(St3(VLIST3(v2.V4H()), 2, MemOperand(x17, 6, PostIndex)),
          "st3 {v2.h, v3.h, v4.h}[2], [x17], #6");
  COMPARE(St3(VLIST3(v3.V8H()), 3, MemOperand(x18, x1, PostIndex)),
          "st3 {v3.h, v4.h, v5.h}[3], [x18], x1");
  COMPARE(St3(VLIST3(v4.V2S()), 0, MemOperand(x19, x2, PostIndex)),
          "st3 {v4.s, v5.s, v6.s}[0], [x19], x2");
  COMPARE(St3(VLIST3(v5.V4S()), 1, MemOperand(x20, 12, PostIndex)),
          "st3 {v5.s, v6.s, v7.s}[1], [x20], #12");
  COMPARE(St3(VLIST3(v6.V2D()), 0, MemOperand(x21, 24, PostIndex)),
          "st3 {v6.d, v7.d, v8.d}[0], [x21], #24");
  COMPARE(St3(VLIST3(v7.B()), 7, MemOperand(x22, 3, PostIndex)),
          "st3 {v7.b, v8.b, v9.b}[7], [x22], #3");
  COMPARE(St3(VLIST3(v8_.B()), 15, MemOperand(x23, x3, PostIndex)),
          "st3 {v8.b, v9.b, v10.b}[15], [x23], x3");
  COMPARE(St3(VLIST3(v9.H()), 3, MemOperand(x24, x4, PostIndex)),
          "st3 {v9.h, v10.h, v11.h}[3], [x24], x4");
  COMPARE(St3(VLIST3(v10.H()), 7, MemOperand(x25, 6, PostIndex)),
          "st3 {v10.h, v11.h, v12.h}[7], [x25], #6");
  COMPARE(St3(VLIST3(v11.S()), 1, MemOperand(x26, 12, PostIndex)),
          "st3 {v11.s, v12.s, v13.s}[1], [x26], #12");
  COMPARE(St3(VLIST3(v12.S()), 3, MemOperand(x27, x5, PostIndex)),
          "st3 {v12.s, v13.s, v14.s}[3], [cp], x5");
  COMPARE(St3(VLIST3(v13.D()), 1, MemOperand(sp, x6, PostIndex)),
          "st3 {v13.d, v14.d, v15.d}[1], [sp], x6");

  COMPARE(St4(VLIST4(v0.V8B()), 0, MemOperand(x15, x0, PostIndex)),
          "st4 {v0.b, v1.b, v2.b, v3.b}[0], [x15], x0");
  COMPARE(St4(VLIST4(v1.V16B()), 1, MemOperand(x16, 4, PostIndex)),
          "st4 {v1.b, v2.b, v3.b, v4.b}[1], [x16], #4");
  COMPARE(St4(VLIST4(v2.V4H()), 2, MemOperand(x17, 8, PostIndex)),
          "st4 {v2.h, v3.h, v4.h, v5.h}[2], [x17], #8");
  COMPARE(St4(VLIST4(v3.V8H()), 3, MemOperand(x18, x1, PostIndex)),
          "st4 {v3.h, v4.h, v5.h, v6.h}[3], [x18], x1");
  COMPARE(St4(VLIST4(v4.V2S()), 0, MemOperand(x19, x2, PostIndex)),
          "st4 {v4.s, v5.s, v6.s, v7.s}[0], [x19], x2");
  COMPARE(St4(VLIST4(v5.V4S()), 1, MemOperand(x20, 16, PostIndex)),
          "st4 {v5.s, v6.s, v7.s, v8.s}[1], [x20], #16");
  COMPARE(St4(VLIST4(v6.V2D()), 0, MemOperand(x21, 32, PostIndex)),
          "st4 {v6.d, v7.d, v8.d, v9.d}[0], [x21], #32");
  COMPARE(St4(VLIST4(v7.B()), 7, MemOperand(x22, 4, PostIndex)),
          "st4 {v7.b, v8.b, v9.b, v10.b}[7], [x22], #4");
  COMPARE(St4(VLIST4(v8_.B()), 15, MemOperand(x23, x3, PostIndex)),
          "st4 {v8.b, v9.b, v10.b, v11.b}[15], [x23], x3");
  COMPARE(St4(VLIST4(v9.H()), 3, MemOperand(x24, x4, PostIndex)),
          "st4 {v9.h, v10.h, v11.h, v12.h}[3], [x24], x4");
  COMPARE(St4(VLIST4(v10.H()), 7, MemOperand(x25, 8, PostIndex)),
          "st4 {v10.h, v11.h, v12.h, v13.h}[7], [x25], #8");
  COMPARE(St4(VLIST4(v11.S()), 1, MemOperand(x26, 16, PostIndex)),
          "st4 {v11.s, v12.s, v13.s, v14.s}[1], [x26], #16");
  COMPARE(St4(VLIST4(v12.S()), 3, MemOperand(x27, x5, PostIndex)),
          "st4 {v12.s, v13.s, v14.s, v15.s}[3], [cp], x5");
  COMPARE(St4(VLIST4(v13.D()), 1, MemOperand(sp, x6, PostIndex)),
          "st4 {v13.d, v14.d, v15.d, v16.d}[1], [sp], x6");

  CLEANUP();
}

TEST_F(DisasmArm64Test, neon_load_store_lane_unallocated) {
  SET_UP_MASM();

  const char* expected = "unallocated (NEONLoadStoreSingleStruct)";
  // LD1 (single structure) (no offset)
  COMPARE(dci(0x0d404400), expected);  // .h, size<0> = 1
  COMPARE(dci(0x0d408800), expected);  // .s, size<1> = 1
  COMPARE(dci(0x0d409400), expected);  // .d, size<0> = 1, S = 1
  // LD2 (single structure) (no offset)
  COMPARE(dci(0x0d604400), expected);  // .h, size<0> = 1
  COMPARE(dci(0x0d608800), expected);  // .s, size<1> = 1
  COMPARE(dci(0x0d609400), expected);  // .d, size<0> = 1, S = 1
  // LD3 (single structure) (no offset)
  COMPARE(dci(0x0d406400), expected);  // .h, size<0> = 1
  COMPARE(dci(0x0d40a800), expected);  // .s, size<1> = 1
  COMPARE(dci(0x0d40b400), expected);  // .d, size<0> = 1, S = 1
  // LD4 (single structure) (no offset)
  COMPARE(dci(0x0d606400), expected);  // .h, size<0> = 1
  COMPARE(dci(0x0d60a800), expected);  // .s, size<1> = 1
  COMPARE(dci(0x0d60b400), expected);  // .d, size<0> = 1, S = 1
  // ST1 (single structure) (no offset)
  COMPARE(dci(0x0d004400), expected);  // .h, size<0> = 1
  COMPARE(dci(0x0d008800), expected);  // .s, size<1> = 1
  COMPARE(dci(0x0d009400), expected);  // .d, size<0> = 1, S = 1
  // ST2 (single structure) (no offset)
  COMPARE(dci(0x0d204400), expected);  // .h, size<0> = 1
  COMPARE(dci(0x0d208800), expected);  // .s, size<1> = 1
  COMPARE(dci(0x0d209400), expected);  // .d, size<0> = 1, S = 1
  // ST3 (single structure) (no offset)
  COMPARE(dci(0x0d006400), expected);  // .h, size<0> = 1
  COMPARE(dci(0x0d00a800), expected);  // .s, size<1> = 1
  COMPARE(dci(0x0d00b400), expected);  // .d, size<0> = 1, S = 1
  // ST4 (single structure) (no offset)
  COMPARE(dci(0x0d206400), expected);  // .h, size<0> = 1
  COMPARE(dci(0x0d20a800), expected);  // .s, size<1> = 1
  COMPARE(dci(0x0d20b400), expected);  // .d, size<0> = 1, S = 1

  expected = "unallocated (NEONLoadStoreSingleStructPostIndex)";
  // LD1 (single structure) (post index)
  COMPARE(dci(0x0dc04400), expected);  // .h, size<0> = 1
  COMPARE(dci(0x0dc08800), expected);  // .s, size<1> = 1
  COMPARE(dci(0x0dc09400), expected);  // .d, size<0> = 1, S = 1
  // LD2 (single structure) (post index)
  COMPARE(dci(0x0de04400), expected);  // .h, size<0> = 1
  COMPARE(dci(0x0de08800), expected);  // .s, size<1> = 1
  COMPARE(dci(0x0de09400), expected);  // .d, size<0> = 1, S = 1
  // LD3 (single structure) (post index)
  COMPARE(dci(0x0dc06400), expected);  // .h, size<0> = 1
  COMPARE(dci(0x0dc0a800), expected);  // .s, size<1> = 1
  COMPARE(dci(0x0dc0b400), expected);  // .d, size<0> = 1, S = 1
  // LD4 (single structure) (post index)
  COMPARE(dci(0x0de06400), expected);  // .h, size<0> = 1
  COMPARE(dci(0x0de0a800), expected);  // .s, size<1> = 1
  COMPARE(dci(0x0de0b400), expected);  // .d, size<0> = 1, S = 1
  // ST1 (single structure) (post index)
  COMPARE(dci(0x0d804400), expected);  // .h, size<0> = 1
  COMPARE(dci(0x0d808800), expected);  // .s, size<1> = 1
  COMPARE(dci(0x0d809400), expected);  // .d, size<0> = 1, S = 1
  // ST2 (single structure) (post index)
  COMPARE(dci(0x0da04400), expected);  // .h, size<0> = 1
  COMPARE(dci(0x0da08800), expected);  // .s, size<1> = 1
  COMPARE(dci(0x0da09400), expected);  // .d, size<0> = 1, S = 1
  // ST3 (single structure) (post index)
  COMPARE(dci(0x0d806400), expected);  // .h, size<0> = 1
  COMPARE(dci(0x0d80a800), expected);  // .s, size<1> = 1
  COMPARE(dci(0x0d80b400), expected);  // .d, size<0> = 1, S = 1
  // ST4 (single structure) (post index)
  COMPARE(dci(0x0da06400), expected);  // .h, size<0> = 1
  COMPARE(dci(0x0da0a800), expected);  // .s, size<1> = 1
  COMPARE(dci(0x0da0b400), expected);  // .d, size<0> = 1, S = 1

  CLEANUP();
}

TEST_F(DisasmArm64Test, neon_load_all_lanes) {
  SET_UP_MASM();

  COMPARE(Ld1r(v14.V8B(), MemOperand(x0)), "ld1r {v14.8b}, [x0]");
  COMPARE(Ld1r(v15.V16B(), MemOperand(x1)), "ld1r {v15.16b}, [x1]");
  COMPARE(Ld1r(v16.V4H(), MemOperand(x2)), "ld1r {v16.4h}, [x2]");
  COMPARE(Ld1r(v17.V8H(), MemOperand(x3)), "ld1r {v17.8h}, [x3]");
  COMPARE(Ld1r(v18.V2S(), MemOperand(x4)), "ld1r {v18.2s}, [x4]");
  COMPARE(Ld1r(v19.V4S(), MemOperand(x5)), "ld1r {v19.4s}, [x5]");
  COMPARE(Ld1r(v20.V2D(), MemOperand(sp)), "ld1r {v20.2d}, [sp]");
  COMPARE(Ld1r(v21.V1D(), MemOperand(x30)), "ld1r {v21.1d}, [lr]");

  COMPARE(Ld1r(v22.V8B(), MemOperand(x6, 1, PostIndex)),
          "ld1r {v22.8b}, [x6], #1");
  COMPARE(Ld1r(v23.V16B(), MemOperand(x7, x16, PostIndex)),
          "ld1r {v23.16b}, [x7], x16");
  COMPARE(Ld1r(v24.V4H(), MemOperand(x8, x17, PostIndex)),
          "ld1r {v24.4h}, [x8], x17");
  COMPARE(Ld1r(v25.V8H(), MemOperand(x9, 2, PostIndex)),
          "ld1r {v25.8h}, [x9], #2");
  COMPARE(Ld1r(v26.V2S(), MemOperand(x10, 4, PostIndex)),
          "ld1r {v26.2s}, [x10], #4");
  COMPARE(Ld1r(v27.V4S(), MemOperand(x11, x18, PostIndex)),
          "ld1r {v27.4s}, [x11], x18");
  COMPARE(Ld1r(v28.V2D(), MemOperand(x12, 8, PostIndex)),
          "ld1r {v28.2d}, [x12], #8");
  COMPARE(Ld1r(v29.V1D(), MemOperand(x13, 8, PostIndex)),
          "ld1r {v29.1d}, [x13], #8");

  COMPARE(Ld2r(v14.V8B(), v15.V8B(), MemOperand(x0)),
          "ld2r {v14.8b, v15.8b}, [x0]");
  COMPARE(Ld2r(v15.V16B(), v16.V16B(), MemOperand(x1)),
          "ld2r {v15.16b, v16.16b}, [x1]");
  COMPARE(Ld2r(v16.V4H(), v17.V4H(), MemOperand(x2)),
          "ld2r {v16.4h, v17.4h}, [x2]");
  COMPARE(Ld2r(v17.V8H(), v18.V8H(), MemOperand(x3)),
          "ld2r {v17.8h, v18.8h}, [x3]");
  COMPARE(Ld2r(v18.V2S(), v19.V2S(), MemOperand(x4)),
          "ld2r {v18.2s, v19.2s}, [x4]");
  COMPARE(Ld2r(v19.V4S(), v20.V4S(), MemOperand(x5)),
          "ld2r {v19.4s, v20.4s}, [x5]");
  COMPARE(Ld2r(v20.V2D(), v21.V2D(), MemOperand(sp)),
          "ld2r {v20.2d, v21.2d}, [sp]");
  COMPARE(Ld2r(v21.V8B(), v22.V8B(), MemOperand(x6, 2, PostIndex)),
          "ld2r {v21.8b, v22.8b}, [x6], #2");
  COMPARE(Ld2r(v22.V16B(), v23.V16B(), MemOperand(x7, x16, PostIndex)),
          "ld2r {v22.16b, v23.16b}, [x7], x16");
  COMPARE(Ld2r(v23.V4H(), v24.V4H(), MemOperand(x8, x17, PostIndex)),
          "ld2r {v23.4h, v24.4h}, [x8], x17");
  COMPARE(Ld2r(v24.V8H(), v25.V8H(), MemOperand(x9, 4, PostIndex)),
          "ld2r {v24.8h, v25.8h}, [x9], #4");
  COMPARE(Ld2r(v25.V2S(), v26.V2S(), MemOperand(x10, 8, PostIndex)),
          "ld2r {v25.2s, v26.2s}, [x10], #8");
  COMPARE(Ld2r(v26.V4S(), v27.V4S(), MemOperand(x11, x18, PostIndex)),
          "ld2r {v26.4s, v27.4s}, [x11], x18");
  COMPARE(Ld2r(v27.V2D(), v28.V2D(), MemOperand(x12, 16, PostIndex)),
          "ld2r {v27.2d, v28.2d}, [x12], #16");

  COMPARE(Ld3r(v14.V8B(), v15.V8B(), v16.V8B(), MemOperand(x0)),
          "ld3r {v14.8b, v15.8b, v16.8b}, [x0]");
  COMPARE(Ld3r(v15.V16B(), v16.V16B(), v17.V16B(), MemOperand(x1)),
          "ld3r {v15.16b, v16.16b, v17.16b}, [x1]");
  COMPARE(Ld3r(v16.V4H(), v17.V4H(), v18.V4H(), MemOperand(x2)),
          "ld3r {v16.4h, v17.4h, v18.4h}, [x2]");
  COMPARE(Ld3r(v17.V8H(), v18.V8H(), v19.V8H(), MemOperand(x3)),
          "ld3r {v17.8h, v18.8h, v19.8h}, [x3]");
  COMPARE(Ld3r(v18.V2S(), v19.V2S(), v20.V2S(), MemOperand(x4)),
          "ld3r {v18.2s, v19.2s, v20.2s}, [x4]");
  COMPARE(Ld3r(v19.V4S(), v20.V4S(), v21.V4S(), MemOperand(x5)),
          "ld3r {v19.4s, v20.4s, v21.4s}, [x5]");
  COMPARE(Ld3r(v20.V2D(), v21.V2D(), v22.V2D(), MemOperand(sp)),
          "ld3r {v20.2d, v21.2d, v22.2d}, [sp]");
  COMPARE(Ld3r(v21.V8B(), v22.V8B(), v23.V8B(), MemOperand(x6, 3, PostIndex)),
          "ld3r {v21.8b, v22.8b, v23.8b}, [x6], #3");
  COMPARE(
      Ld3r(v22.V16B(), v23.V16B(), v24.V16B(), MemOperand(x7, x16, PostIndex)),
      "ld3r {v22.16b, v23.16b, v24.16b}, [x7], x16");
  COMPARE(Ld3r(v23.V4H(), v24.V4H(), v25.V4H(), MemOperand(x8, x17, PostIndex)),
          "ld3r {v23.4h, v24.4h, v25.4h}, [x8], x17");
  COMPARE(Ld3r(v24.V8H(), v25.V8H(), v26.V8H(), MemOperand(x9, 6, PostIndex)),
          "ld3r {v24.8h, v25.8h, v26.8h}, [x9], #6");
  COMPARE(Ld3r(v25.V2S(), v26.V2S(), v27.V2S(), MemOperand(x10, 12, PostIndex)),
          "ld3r {v25.2s, v26.2s, v27.2s}, [x10], #12");
  COMPARE(
      Ld3r(v26.V4S(), v27.V4S(), v28.V4S(), MemOperand(x11, x18, PostIndex)),
      "ld3r {v26.4s, v27.4s, v28.4s}, [x11], x18");
  COMPARE(Ld3r(v27.V2D(), v28.V2D(), v29.V2D(), MemOperand(x12, 24, PostIndex)),
          "ld3r {v27.2d, v28.2d, v29.2d}, [x12], #24");

  COMPARE(Ld4r(v14.V8B(), v15.V8B(), v16.V8B(), v17.V8B(), MemOperand(x0)),
          "ld4r {v14.8b, v15.8b, v16.8b, v17.8b}, [x0]");
  COMPARE(Ld4r(v15.V16B(), v16.V16B(), v17.V16B(), v18.V16B(), MemOperand(x1)),
          "ld4r {v15.16b, v16.16b, v17.16b, v18.16b}, [x1]");
  COMPARE(Ld4r(v16.V4H(), v17.V4H(), v18.V4H(), v19.V4H(), MemOperand(x2)),
          "ld4r {v16.4h, v17.4h, v18.4h, v19.4h}, [x2]");
  COMPARE(Ld4r(v17.V8H(), v18.V8H(), v19.V8H(), v20.V8H(), MemOperand(x3)),
          "ld4r {v17.8h, v18.8h, v19.8h, v20.8h}, [x3]");
  COMPARE(Ld4r(v18.V2S(), v19.V2S(), v20.V2S(), v21.V2S(), MemOperand(x4)),
          "ld4r {v18.2s, v19.2s, v20.2s, v21.2s}, [x4]");
  COMPARE(Ld4r(v19.V4S(), v20.V4S(), v21.V4S(), v22.V4S(), MemOperand(x5)),
          "ld4r {v19.4s, v20.4s, v21.4s, v22.4s}, [x5]");
  COMPARE(Ld4r(v20.V2D(), v21.V2D(), v22.V2D(), v23.V2D(), MemOperand(sp)),
          "ld4r {v20.2d, v21.2d, v22.2d, v23.2d}, [sp]");
  COMPARE(Ld4r(v21.V8B(), v22.V8B(), v23.V8B(), v24.V8B(),
               MemOperand(x6, 4, PostIndex)),
          "ld4r {v21.8b, v22.8b, v23.8b, v24.8b}, [x6], #4");
  COMPARE(Ld4r(v22.V16B(), v23.V16B(), v24.V16B(), v25.V16B(),
               MemOperand(x7, x16, PostIndex)),
          "ld4r {v22.16b, v23.16b, v24.16b, v25.16b}, [x7], x16");
  COMPARE(Ld4r(v23.V4H(), v24.V4H(), v25.V4H(), v26.V4H(),
               MemOperand(x8, x17, PostIndex)),
          "ld4r {v23.4h, v24.4h, v25.4h, v26.4h}, [x8], x17");
  COMPARE(Ld4r(v24.V8H(), v25.V8H(), v26.V8H(), v27.V8H(),
               MemOperand(x9, 8, PostIndex)),
          "ld4r {v24.8h, v25.8h, v26.8h, v27.8h}, [x9], #8");
  COMPARE(Ld4r(v25.V2S(), v26.V2S(), v27.V2S(), v28.V2S(),
               MemOperand(x10, 16, PostIndex)),
          "ld4r {v25.2s, v26.2s, v27.2s, v28.2s}, [x10], #16");
  COMPARE(Ld4r(v26.V4S(), v27.V4S(), v28.V4S(), v29.V4S(),
               MemOperand(x11, x18, PostIndex)),
          "ld4r {v26.4s, v27.4s, v28.4s, v29.4s}, [x11], x18");
  COMPARE(Ld4r(v27.V2D(), v28.V2D(), v29.V2D(), v30.V2D(),
               MemOperand(x12, 32, PostIndex)),
          "ld4r {v27.2d, v28.2d, v29.2d, v30.2d}, [x12], #32");

  CLEANUP();
}

TEST_F(DisasmArm64Test, neon_load_all_lanes_unallocated) {
  SET_UP_MASM();

  const char* expected = "unallocated (NEONLoadStoreSingleStruct)";
  // LD1R (single structure) (no offset)
  COMPARE(dci(0x0d00c000), expected);  // L = 0
  COMPARE(dci(0x0d40d000), expected);  // S = 1
  // LD2R (single structure) (no offset)
  COMPARE(dci(0x0d20c000), expected);  // L = 0
  COMPARE(dci(0x0d60d000), expected);  // S = 1
  // LD3R (single structure) (no offset)
  COMPARE(dci(0x0d00e000), expected);  // L = 0
  COMPARE(dci(0x0d40f000), expected);  // S = 1
  // LD4R (single structure) (no offset)
  COMPARE(dci(0x0d20e000), expected);  // L = 0
  COMPARE(dci(0x0d60f000), expected);  // S = 1

  expected = "unallocated (NEONLoadStoreSingleStructPostIndex)";
  // LD1R (single structure) (post index)
  COMPARE(dci(0x0d80c000), expected);  // L = 0
  COMPARE(dci(0x0dc0d000), expected);  // S = 1
  // LD2R (single structure) (post index)
  COMPARE(dci(0x0da0c000), expected);  // L = 0
  COMPARE(dci(0x0de0d000), expected);  // S = 1
  // LD3R (single structure) (post index)
  COMPARE(dci(0x0d80e000), expected);  // L = 0
  COMPARE(dci(0x0dc0f000), expected);  // S = 1
  // LD4R (single structure) (post index)
  COMPARE(dci(0x0da0e000), expected);  // L = 0
  COMPARE(dci(0x0de0f000), expected);  // S = 1

  CLEANUP();
}

TEST_F(DisasmArm64Test, neon_3same) {
  SET_UP_MASM();

#define DISASM_INST(M, S) \
  COMPARE(Cmeq(v0.M, v1.M, v2.M), "cmeq v0." S ", v1." S ", v2." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Cmge(v0.M, v1.M, v2.M), "cmge v0." S ", v1." S ", v2." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Cmgt(v0.M, v1.M, v2.M), "cmgt v0." S ", v1." S ", v2." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Cmhi(v0.M, v1.M, v2.M), "cmhi v0." S ", v1." S ", v2." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Cmhs(v0.M, v1.M, v2.M), "cmhs v0." S ", v1." S ", v2." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Cmtst(v0.M, v1.M, v2.M), "cmtst v0." S ", v1." S ", v2." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Add(v0.M, v1.M, v2.M), "add v0." S ", v1." S ", v2." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Sub(v3.M, v4.M, v5.M), "sub v3." S ", v4." S ", v5." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Sabd(v3.M, v4.M, v5.M), "sabd v3." S ", v4." S ", v5." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Uabd(v3.M, v4.M, v5.M), "uabd v3." S ", v4." S ", v5." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Saba(v3.M, v4.M, v5.M), "saba v3." S ", v4." S ", v5." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Uaba(v3.M, v4.M, v5.M), "uaba v3." S ", v4." S ", v5." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Smax(v3.M, v4.M, v5.M), "smax v3." S ", v4." S ", v5." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Smin(v3.M, v4.M, v5.M), "smin v3." S ", v4." S ", v5." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Umax(v3.M, v4.M, v5.M), "umax v3." S ", v4." S ", v5." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Umin(v3.M, v4.M, v5.M), "umin v3." S ", v4." S ", v5." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Smaxp(v3.M, v4.M, v5.M), "smaxp v3." S ", v4." S ", v5." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Sminp(v3.M, v4.M, v5.M), "sminp v3." S ", v4." S ", v5." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Umaxp(v3.M, v4.M, v5.M), "umaxp v3." S ", v4." S ", v5." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Uminp(v3.M, v4.M, v5.M), "uminp v3." S ", v4." S ", v5." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Uqadd(v6.M, v7.M, v8_.M), "uqadd v6." S ", v7." S ", v8." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Sqadd(v9.M, v10.M, v11.M), "sqadd v9." S ", v10." S ", v11." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Uqsub(v6.M, v7.M, v8_.M), "uqsub v6." S ", v7." S ", v8." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Sqsub(v9.M, v10.M, v11.M), "sqsub v9." S ", v10." S ", v11." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Sshl(v12.M, v13.M, v14.M), "sshl v12." S ", v13." S ", v14." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Ushl(v15.M, v16.M, v17.M), "ushl v15." S ", v16." S ", v17." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Sqshl(v18.M, v19.M, v20.M), "sqshl v18." S ", v19." S ", v20." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Uqshl(v21.M, v22.M, v23.M), "uqshl v21." S ", v22." S ", v23." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Srshl(v24.M, v25.M, v26.M), "srshl v24." S ", v25." S ", v26." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Urshl(v27.M, v28.M, v29.M), "urshl v27." S ", v28." S ", v29." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Sqrshl(v30.M, v31.M, v0.M), "sqrshl v30." S ", v31." S ", v0." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Uqrshl(v1.M, v2.M, v3.M), "uqrshl v1." S ", v2." S ", v3." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Shadd(v4.M, v5.M, v6.M), "shadd v4." S ", v5." S ", v6." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Uhadd(v7.M, v8_.M, v9.M), "uhadd v7." S ", v8." S ", v9." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Srhadd(v10.M, v11.M, v12.M), "srhadd v10." S ", v11." S ", v12." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Urhadd(v13.M, v14.M, v15.M), "urhadd v13." S ", v14." S ", v15." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Shsub(v16.M, v17.M, v18.M), "shsub v16." S ", v17." S ", v18." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Uhsub(v19.M, v20.M, v21.M), "uhsub v19." S ", v20." S ", v21." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Addp(v19.M, v20.M, v21.M), "addp v19." S ", v20." S ", v21." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Mla(v19.M, v20.M, v21.M), "mla v19." S ", v20." S ", v21." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Mls(v19.M, v20.M, v21.M), "mls v19." S ", v20." S ", v21." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Mul(v19.M, v20.M, v21.M), "mul v19." S ", v20." S ", v21." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Sqdmulh(v1.M, v2.M, v3.M), "sqdmulh v1." S ", v2." S ", v3." S);
  NEON_FORMAT_LIST_HS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Sqrdmulh(v1.M, v2.M, v3.M), "sqrdmulh v1." S ", v2." S ", v3." S);
  NEON_FORMAT_LIST_HS(DISASM_INST)
#undef DISASM_INST

  COMPARE(And(v6.V8B(), v7.V8B(), v8_.V8B()), "and v6.8b, v7.8b, v8.8b");
  COMPARE(And(v6.V16B(), v7.V16B(), v8_.V16B()), "and v6.16b, v7.16b, v8.16b");

  COMPARE(Bic(v6.V8B(), v7.V8B(), v8_.V8B()), "bic v6.8b, v7.8b, v8.8b");
  COMPARE(Bic(v6.V16B(), v7.V16B(), v8_.V16B()), "bic v6.16b, v7.16b, v8.16b");

  COMPARE(Orr(v6.V8B(), v7.V8B(), v8_.V8B()), "orr v6.8b, v7.8b, v8.8b");
  COMPARE(Orr(v6.V16B(), v7.V16B(), v8_.V16B()), "orr v6.16b, v7.16b, v8.16b");

  COMPARE(Orr(v6.V8B(), v7.V8B(), v7.V8B()), "mov v6.8b, v7.8b");
  COMPARE(Orr(v6.V16B(), v7.V16B(), v7.V16B()), "mov v6.16b, v7.16b");

  COMPARE(Mov(v6.V8B(), v8_.V8B()), "mov v6.8b, v8.8b");
  COMPARE(Mov(v6.V16B(), v8_.V16B()), "mov v6.16b, v8.16b");

  COMPARE(Orn(v6.V8B(), v7.V8B(), v8_.V8B()), "orn v6.8b, v7.8b, v8.8b");
  COMPARE(Orn(v6.V16B(), v7.V16B(), v8_.V16B()), "orn v6.16b, v7.16b, v8.16b");

  COMPARE(Eor(v6.V8B(), v7.V8B(), v8_.V8B()), "eor v6.8b, v7.8b, v8.8b");
  COMPARE(Eor(v6.V16B(), v7.V16B(), v8_.V16B()), "eor v6.16b, v7.16b, v8.16b");

  COMPARE(Bif(v6.V8B(), v7.V8B(), v8_.V8B()), "bif v6.8b, v7.8b, v8.8b");
  COMPARE(Bif(v6.V16B(), v7.V16B(), v8_.V16B()), "bif v6.16b, v7.16b, v8.16b");

  COMPARE(Bit(v6.V8B(), v7.V8B(), v8_.V8B()), "bit v6.8b, v7.8b, v8.8b");
  COMPARE(Bit(v6.V16B(), v7.V16B(), v8_.V16B()), "bit v6.16b, v7.16b, v8.16b");

  COMPARE(Bsl(v6.V8B(), v7.V8B(), v8_.V8B()), "bsl v6.8b, v7.8b, v8.8b");
  COMPARE(Bsl(v6.V16B(), v7.V16B(), v8_.V16B()), "bsl v6.16b, v7.16b, v8.16b");

  COMPARE(Pmul(v6.V8B(), v7.V8B(), v8_.V8B()), "pmul v6.8b, v7.8b, v8.8b");
  COMPARE(Pmul(v6.V16B(), v7.V16B(), v8_.V16B()),
          "pmul v6.16b, v7.16b, v8.16b");

  CLEANUP();
}

TEST_F(DisasmArm64Test, neon_fp_3same) {
  SET_UP_MASM();

#define DISASM_INST(M, S) \
  COMPARE(Fadd(v0.M, v1.M, v2.M), "fadd v0." S ", v1." S ", v2." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Fsub(v3.M, v4.M, v5.M), "fsub v3." S ", v4." S ", v5." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Fmul(v6.M, v7.M, v8_.M), "fmul v6." S ", v7." S ", v8." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Fdiv(v9.M, v10.M, v11.M), "fdiv v9." S ", v10." S ", v11." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Fmin(v12.M, v13.M, v14.M), "fmin v12." S ", v13." S ", v14." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Fminnm(v15.M, v16.M, v17.M), "fminnm v15." S ", v16." S ", v17." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Fmax(v18.M, v19.M, v20.M), "fmax v18." S ", v19." S ", v20." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Fmaxnm(v21.M, v22.M, v23.M), "fmaxnm v21." S ", v22." S ", v23." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Frecps(v24.M, v25.M, v26.M), "frecps v24." S ", v25." S ", v26." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S)                                           \
  COMPARE(Frsqrts(v27.M, v28.M, v29.M), "frsqrts v27." S ", v28." S \
                                        ", "                        \
                                        "v29." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Fmulx(v30.M, v31.M, v0.M), "fmulx v30." S ", v31." S ", v0." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Fmla(v1.M, v2.M, v3.M), "fmla v1." S ", v2." S ", v3." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Fmls(v4.M, v5.M, v6.M), "fmls v4." S ", v5." S ", v6." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Fabd(v7.M, v8_.M, v9.M), "fabd v7." S ", v8." S ", v9." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Faddp(v10.M, v11.M, v12.M), "faddp v10." S ", v11." S ", v12." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Fmaxp(v13.M, v14.M, v15.M), "fmaxp v13." S ", v14." S ", v15." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Fminp(v16.M, v17.M, v18.M), "fminp v16." S ", v17." S ", v18." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S)                                           \
  COMPARE(Fmaxnmp(v19.M, v20.M, v21.M), "fmaxnmp v19." S ", v20." S \
                                        ", "                        \
                                        "v21." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S)                                           \
  COMPARE(Fminnmp(v22.M, v23.M, v24.M), "fminnmp v22." S ", v23." S \
                                        ", "                        \
                                        "v24." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Fcmeq(v25.M, v26.M, v27.M), "fcmeq v25." S ", v26." S ", v27." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Fcmge(v25.M, v26.M, v27.M), "fcmge v25." S ", v26." S ", v27." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Fcmgt(v25.M, v26.M, v27.M), "fcmgt v25." S ", v26." S ", v27." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Facge(v25.M, v26.M, v27.M), "facge v25." S ", v26." S ", v27." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Facgt(v25.M, v26.M, v27.M), "facgt v25." S ", v26." S ", v27." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

  CLEANUP();
}

#define NEON_SCALAR_FORMAT_LIST(V) \
  V(B(), "b")                      \
  V(H(), "h")                      \
  V(S(), "s")                      \
  V(D(), "d")

TEST_F(DisasmArm64Test, neon_scalar_3same) {
  SET_UP_MASM();

  // Instructions that only support D-sized scalar operations.
  COMPARE(Add(v0.D(), v1.D(), v2.D()), "add d0, d1, d2");
  COMPARE(Sub(v3.D(), v4.D(), v5.D()), "sub d3, d4, d5");
  COMPARE(Cmeq(v0.D(), v1.D(), v2.D()), "cmeq d0, d1, d2");
  COMPARE(Cmge(v3.D(), v4.D(), v5.D()), "cmge d3, d4, d5");
  COMPARE(Cmgt(v6.D(), v7.D(), v8_.D()), "cmgt d6, d7, d8");
  COMPARE(Cmhi(v0.D(), v1.D(), v2.D()), "cmhi d0, d1, d2");
  COMPARE(Cmhs(v3.D(), v4.D(), v5.D()), "cmhs d3, d4, d5");
  COMPARE(Cmtst(v6.D(), v7.D(), v8_.D()), "cmtst d6, d7, d8");
  COMPARE(Ushl(v6.D(), v7.D(), v8_.D()), "ushl d6, d7, d8");
  COMPARE(Sshl(v6.D(), v7.D(), v8_.D()), "sshl d6, d7, d8");
  COMPARE(Urshl(v9.D(), v10.D(), v11.D()), "urshl d9, d10, d11");
  COMPARE(Srshl(v9.D(), v10.D(), v11.D()), "srshl d9, d10, d11");

  // Instructions that support S and D-sized scalar operations.
  COMPARE(Frecps(v12.S(), v13.S(), v14.S()), "frecps s12, s13, s14");
  COMPARE(Frecps(v15.D(), v16.D(), v17.D()), "frecps d15, d16, d17");
  COMPARE(Frsqrts(v18.S(), v19.S(), v20.S()), "frsqrts s18, s19, s20");
  COMPARE(Frsqrts(v21.D(), v22.D(), v23.D()), "frsqrts d21, d22, d23");
  COMPARE(Fmulx(v12.S(), v13.S(), v14.S()), "fmulx s12, s13, s14");
  COMPARE(Fmulx(v15.D(), v16.D(), v17.D()), "fmulx d15, d16, d17");
  COMPARE(Fcmeq(v12.S(), v13.S(), v14.S()), "fcmeq s12, s13, s14");
  COMPARE(Fcmeq(v15.D(), v16.D(), v17.D()), "fcmeq d15, d16, d17");
  COMPARE(Fcmge(v12.S(), v13.S(), v14.S()), "fcmge s12, s13, s14");
  COMPARE(Fcmge(v15.D(), v16.D(), v17.D()), "fcmge d15, d16, d17");
  COMPARE(Fcmgt(v12.S(), v13.S(), v14.S()), "fcmgt s12, s13, s14");
  COMPARE(Fcmgt(v15.D(), v16.D(), v17.D()), "fcmgt d15, d16, d17");
  COMPARE(Fcmge(v12.S(), v13.S(), v14.S()), "fcmge s12, s13, s14");
  COMPARE(Fcmge(v15.D(), v16.D(), v17.D()), "fcmge d15, d16, d17");
  COMPARE(Facgt(v12.S(), v13.S(), v14.S()), "facgt s12, s13, s14");
  COMPARE(Facgt(v15.D(), v16.D(), v17.D()), "facgt d15, d16, d17");

  // Instructions that support H and S-sized scalar operations.
  COMPARE(Sqdmulh(v12.S(), v13.S(), v14.S()), "sqdmulh s12, s13, s14");
  COMPARE(Sqdmulh(v15.H(), v16.H(), v17.H()), "sqdmulh h15, h16, h17");
  COMPARE(Sqrdmulh(v12.S(), v13.S(), v14.S()), "sqrdmulh s12, s13, s14");
  COMPARE(Sqrdmulh(v15.H(), v16.H(), v17.H()), "sqrdmulh h15, h16, h17");

#define DISASM_INST(M, R) \
  COMPARE(Uqadd(v6.M, v7.M, v8_.M), "uqadd " R "6, " R "7, " R "8");
  NEON_SCALAR_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, R) \
  COMPARE(Uqsub(v9.M, v10.M, v11.M), "uqsub " R "9, " R "10, " R "11");
  NEON_SCALAR_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, R) \
  COMPARE(Sqadd(v12.M, v13.M, v14.M), "sqadd " R "12, " R "13, " R "14");
  NEON_SCALAR_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, R) \
  COMPARE(Sqsub(v15.M, v16.M, v17.M), "sqsub " R "15, " R "16, " R "17");
  NEON_SCALAR_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, R) \
  COMPARE(Uqshl(v18.M, v19.M, v20.M), "uqshl " R "18, " R "19, " R "20");
  NEON_SCALAR_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, R) \
  COMPARE(Sqshl(v21.M, v22.M, v23.M), "sqshl " R "21, " R "22, " R "23");
  NEON_SCALAR_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, R) \
  COMPARE(Uqrshl(v30.M, v31.M, v0.M), "uqrshl " R "30, " R "31, " R "0");
  NEON_SCALAR_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, R) \
  COMPARE(Sqrshl(v1.M, v2.M, v3.M), "sqrshl " R "1, " R "2, " R "3");
  NEON_SCALAR_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

  CLEANUP();
}

TEST_F(DisasmArm64Test, neon_byelement) {
  SET_UP_MASM();

  COMPARE(Mul(v0.V4H(), v1.V4H(), v2.H(), 0), "mul v0.4h, v1.4h, v2.h[0]");
  COMPARE(Mul(v2.V8H(), v3.V8H(), v15.H(), 7), "mul v2.8h, v3.8h, v15.h[7]");
  COMPARE(Mul(v0.V2S(), v1.V2S(), v2.S(), 0), "mul v0.2s, v1.2s, v2.s[0]");
  COMPARE(Mul(v2.V4S(), v3.V4S(), v15.S(), 3), "mul v2.4s, v3.4s, v15.s[3]");

  COMPARE(Mla(v0.V4H(), v1.V4H(), v2.H(), 0), "mla v0.4h, v1.4h, v2.h[0]");
  COMPARE(Mla(v2.V8H(), v3.V8H(), v15.H(), 7), "mla v2.8h, v3.8h, v15.h[7]");
  COMPARE(Mla(v0.V2S(), v1.V2S(), v2.S(), 0), "mla v0.2s, v1.2s, v2.s[0]");
  COMPARE(Mla(v2.V4S(), v3.V4S(), v15.S(), 3), "mla v2.4s, v3.4s, v15.s[3]");

  COMPARE(Mls(v0.V4H(), v1.V4H(), v2.H(), 0), "mls v0.4h, v1.4h, v2.h[0]");
  COMPARE(Mls(v2.V8H(), v3.V8H(), v15.H(), 7), "mls v2.8h, v3.8h, v15.h[7]");
  COMPARE(Mls(v0.V2S(), v1.V2S(), v2.S(), 0), "mls v0.2s, v1.2s, v2.s[0]");
  COMPARE(Mls(v2.V4S(), v3.V4S(), v15.S(), 3), "mls v2.4s, v3.4s, v15.s[3]");

  COMPARE(Sqdmulh(v0.V4H(), v1.V4H(), v2.H(), 0),
          "sqdmulh v0.4h, v1.4h, v2.h[0]");
  COMPARE(Sqdmulh(v2.V8H(), v3.V8H(), v15.H(), 7),
          "sqdmulh v2.8h, v3.8h, v15.h[7]");
  COMPARE(Sqdmulh(v0.V2S(), v1.V2S(), v2.S(), 0),
          "sqdmulh v0.2s, v1.2s, v2.s[0]");
  COMPARE(Sqdmulh(v2.V4S(), v3.V4S(), v15.S(), 3),
          "sqdmulh v2.4s, v3.4s, v15.s[3]");
  COMPARE(Sqdmulh(h0, h1, v2.H(), 0), "sqdmulh h0, h1, v2.h[0]");
  COMPARE(Sqdmulh(s0, s1, v2.S(), 0), "sqdmulh s0, s1, v2.s[0]");

  COMPARE(Sqrdmulh(v0.V4H(), v1.V4H(), v2.H(), 0),
          "sqrdmulh v0.4h, v1.4h, v2.h[0]");
  COMPARE(Sqrdmulh(v2.V8H(), v3.V8H(), v15.H(), 7),
          "sqrdmulh v2.8h, v3.8h, v15.h[7]");
  COMPARE(Sqrdmulh(v0.V2S(), v1.V2S(), v2.S(), 0),
          "sqrdmulh v0.2s, v1.2s, v2.s[0]");
  COMPARE(Sqrdmulh(v2.V4S(), v3.V4S(), v15.S(), 3),
          "sqrdmulh v2.4s, v3.4s, v15.s[3]");
  COMPARE(Sqrdmulh(h0, h1, v2.H(), 0), "sqrdmulh h0, h1, v2.h[0]");
  COMPARE(Sqrdmulh(s0, s1, v2.S(), 0), "sqrdmulh s0, s1, v2.s[0]");

  COMPARE(Smull(v0.V4S(), v1.V4H(), v2.H(), 0), "smull v0.4s, v1.4h, v2.h[0]");
  COMPARE(Smull2(v2.V4S(), v3.V8H(), v4.H(), 7),
          "smull2 v2.4s, v3.8h, v4.h[7]");
  COMPARE(Smull(v0.V2D(), v1.V2S(), v2.S(), 0), "smull v0.2d, v1.2s, v2.s[0]");
  COMPARE(Smull2(v2.V2D(), v3.V4S(), v4.S(), 3),
          "smull2 v2.2d, v3.4s, v4.s[3]");

  COMPARE(Umull(v0.V4S(), v1.V4H(), v2.H(), 0), "umull v0.4s, v1.4h, v2.h[0]");
  COMPARE(Umull2(v2.V4S(), v3.V8H(), v4.H(), 7),
          "umull2 v2.4s, v3.8h, v4.h[7]");
  COMPARE(Umull(v0.V2D(), v1.V2S(), v2.S(), 0), "umull v0.2d, v1.2s, v2.s[0]");
  COMPARE(Umull2(v2.V2D(), v3.V4S(), v4.S(), 3),
          "umull2 v2.2d, v3.4s, v4.s[3]");

  COMPARE(Smlal(v0.V4S(), v1.V4H(), v2.H(), 0), "smlal v0.4s, v1.4h, v2.h[0]");
  COMPARE(Smlal2(v2.V4S(), v3.V8H(), v4.H(), 7),
          "smlal2 v2.4s, v3.8h, v4.h[7]");
  COMPARE(Smlal(v0.V2D(), v1.V2S(), v2.S(), 0), "smlal v0.2d, v1.2s, v2.s[0]");
  COMPARE(Smlal2(v2.V2D(), v3.V4S(), v4.S(), 3),
          "smlal2 v2.2d, v3.4s, v4.s[3]");

  COMPARE(Umlal(v0.V4S(), v1.V4H(), v2.H(), 0), "umlal v0.4s, v1.4h, v2.h[0]");
  COMPARE(Umlal2(v2.V4S(), v3.V8H(), v4.H(), 7),
          "umlal2 v2.4s, v3.8h, v4.h[7]");
  COMPARE(Umlal(v0.V2D(), v1.V2S(), v2.S(), 0), "umlal v0.2d, v1.2s, v2.s[0]");
  COMPARE(Umlal2(v2.V2D(), v3.V4S(), v4.S(), 3),
          "umlal2 v2.2d, v3.4s, v4.s[3]");

  COMPARE(Smlsl(v0.V4S(), v1.V4H(), v2.H(), 0), "smlsl v0.4s, v1.4h, v2.h[0]");
  COMPARE(Smlsl2(v2.V4S(), v3.V8H(), v4.H(), 7),
          "smlsl2 v2.4s, v3.8h, v4.h[7]");
  COMPARE(Smlsl(v0.V2D(), v1.V2S(), v2.S(), 0), "smlsl v0.2d, v1.2s, v2.s[0]");
  COMPARE(Smlsl2(v2.V2D(), v3.V4S(), v4.S(), 3),
          "smlsl2 v2.2d, v3.4s, v4.s[3]");

  COMPARE(Umlsl(v0.V4S(), v1.V4H(), v2.H(), 0), "umlsl v0.4s, v1.4h, v2.h[0]");
  COMPARE(Umlsl2(v2.V4S(), v3.V8H(), v4.H(), 7),
          "umlsl2 v2.4s, v3.8h, v4.h[7]");
  COMPARE(Umlsl(v0.V2D(), v1.V2S(), v2.S(), 0), "umlsl v0.2d, v1.2s, v2.s[0]");
  COMPARE(Umlsl2(v2.V2D(), v3.V4S(), v4.S(), 3),
          "umlsl2 v2.2d, v3.4s, v4.s[3]");

  COMPARE(Sqdmull(v0.V4S(), v1.V4H(), v2.H(), 0),
          "sqdmull v0.4s, v1.4h, v2.h[0]");
  COMPARE(Sqdmull2(v2.V4S(), v3.V8H(), v4.H(), 7),
          "sqdmull2 v2.4s, v3.8h, v4.h[7]");
  COMPARE(Sqdmull(v0.V2D(), v1.V2S(), v2.S(), 0),
          "sqdmull v0.2d, v1.2s, v2.s[0]");
  COMPARE(Sqdmull2(v2.V2D(), v3.V4S(), v4.S(), 3),
          "sqdmull2 v2.2d, v3.4s, v4.s[3]");
  COMPARE(Sqdmull(s0, h1, v2.H(), 0), "sqdmull s0, h1, v2.h[0]");
  COMPARE(Sqdmull(d0, s1, v2.S(), 0), "sqdmull d0, s1, v2.s[0]");

  COMPARE(Sqdmlal(v0.V4S(), v1.V4H(), v2.H(), 0),
          "sqdmlal v0.4s, v1.4h, v2.h[0]");
  COMPARE(Sqdmlal2(v2.V4S(), v3.V8H(), v4.H(), 7),
          "sqdmlal2 v2.4s, v3.8h, v4.h[7]");
  COMPARE(Sqdmlal(v0.V2D(), v1.V2S(), v2.S(), 0),
          "sqdmlal v0.2d, v1.2s, v2.s[0]");
  COMPARE(Sqdmlal2(v2.V2D(), v3.V4S(), v4.S(), 3),
          "sqdmlal2 v2.2d, v3.4s, v4.s[3]");
  COMPARE(Sqdmlal(s0, h1, v2.H(), 0), "sqdmlal s0, h1, v2.h[0]");
  COMPARE(Sqdmlal(d0, s1, v2.S(), 0), "sqdmlal d0, s1, v2.s[0]");

  COMPARE(Sqdmlsl(v0.V4S(), v1.V4H(), v2.H(), 0),
          "sqdmlsl v0.4s, v1.4h, v2.h[0]");
  COMPARE(Sqdmlsl2(v2.V4S(), v3.V8H(), v4.H(), 7),
          "sqdmlsl2 v2.4s, v3.8h, v4.h[7]");
  COMPARE(Sqdmlsl(v0.V2D(), v1.V2S(), v2.S(), 0),
          "sqdmlsl v0.2d, v1.2s, v2.s[0]");
  COMPARE(Sqdmlsl2(v2.V2D(), v3.V4S(), v4.S(), 3),
          "sqdmlsl2 v2.2d, v3.4s, v4.s[3]");
  COMPARE(Sqdmlsl(s0, h1, v2.H(), 0), "sqdmlsl s0, h1, v2.h[0]");
  COMPARE(Sqdmlsl(d0, s1, v2.S(), 0), "sqdmlsl d0, s1, v2.s[0]");

  CLEANUP();
}

TEST_F(DisasmArm64Test, neon_fp_byelement) {
  SET_UP_MASM();

  COMPARE(Fmul(v0.V2S(), v1.V2S(), v2.S(), 0), "fmul v0.2s, v1.2s, v2.s[0]");
  COMPARE(Fmul(v2.V4S(), v3.V4S(), v15.S(), 3), "fmul v2.4s, v3.4s, v15.s[3]");
  COMPARE(Fmul(v0.V2D(), v1.V2D(), v2.D(), 0), "fmul v0.2d, v1.2d, v2.d[0]");
  COMPARE(Fmul(d0, d1, v2.D(), 0), "fmul d0, d1, v2.d[0]");
  COMPARE(Fmul(s0, s1, v2.S(), 0), "fmul s0, s1, v2.s[0]");

  COMPARE(Fmla(v0.V2S(), v1.V2S(), v2.S(), 0), "fmla v0.2s, v1.2s, v2.s[0]");
  COMPARE(Fmla(v2.V4S(), v3.V4S(), v15.S(), 3), "fmla v2.4s, v3.4s, v15.s[3]");
  COMPARE(Fmla(v0.V2D(), v1.V2D(), v2.D(), 0), "fmla v0.2d, v1.2d, v2.d[0]");
  COMPARE(Fmla(d0, d1, v2.D(), 0), "fmla d0, d1, v2.d[0]");
  COMPARE(Fmla(s0, s1, v2.S(), 0), "fmla s0, s1, v2.s[0]");

  COMPARE(Fmls(v0.V2S(), v1.V2S(), v2.S(), 0), "fmls v0.2s, v1.2s, v2.s[0]");
  COMPARE(Fmls(v2.V4S(), v3.V4S(), v15.S(), 3), "fmls v2.4s, v3.4s, v15.s[3]");
  COMPARE(Fmls(v0.V2D(), v1.V2D(), v2.D(), 0), "fmls v0.2d, v1.2d, v2.d[0]");
  COMPARE(Fmls(d0, d1, v2.D(), 0), "fmls d0, d1, v2.d[0]");
  COMPARE(Fmls(s0, s1, v2.S(), 0), "fmls s0, s1, v2.s[0]");

  COMPARE(Fmulx(v0.V2S(), v1.V2S(), v2.S(), 0), "fmulx v0.2s, v1.2s, v2.s[0]");
  COMPARE(Fmulx(v2.V4S(), v3.V4S(), v8_.S(), 3), "fmulx v2.4s, v3.4s, v8.s[3]");
  COMPARE(Fmulx(v0.V2D(), v1.V2D(), v2.D(), 0), "fmulx v0.2d, v1.2d, v2.d[0]");
  COMPARE(Fmulx(d0, d1, v2.D(), 0), "fmulx d0, d1, v2.d[0]");
  COMPARE(Fmulx(s0, s1, v2.S(), 0), "fmulx s0, s1, v2.s[0]");

  CLEANUP();
}

TEST_F(DisasmArm64Test, neon_3different) {
  SET_UP_MASM();

#define DISASM_INST(TA, TAS, TB, TBS)                             \
  COMPARE(Uaddl(v0.TA, v1.TB, v2.TB), "uaddl v0." TAS ", v1." TBS \
                                      ", "                        \
                                      "v2." TBS);
  NEON_FORMAT_LIST_LW(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)  \
  COMPARE(Uaddl2(v0.TA, v1.TB, v2.TB), \
          "uaddl2 v0." TAS ", v1." TBS ", v2." TBS);
  NEON_FORMAT_LIST_LW2(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)                             \
  COMPARE(Uaddw(v0.TA, v1.TA, v2.TB), "uaddw v0." TAS ", v1." TAS \
                                      ", "                        \
                                      "v2." TBS);
  NEON_FORMAT_LIST_LW(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)  \
  COMPARE(Uaddw2(v0.TA, v1.TA, v2.TB), \
          "uaddw2 v0." TAS ", v1." TAS ", v2." TBS);
  NEON_FORMAT_LIST_LW2(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)                             \
  COMPARE(Saddl(v0.TA, v1.TB, v2.TB), "saddl v0." TAS ", v1." TBS \
                                      ", "                        \
                                      "v2." TBS);
  NEON_FORMAT_LIST_LW(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)  \
  COMPARE(Saddl2(v0.TA, v1.TB, v2.TB), \
          "saddl2 v0." TAS ", v1." TBS ", v2." TBS);
  NEON_FORMAT_LIST_LW2(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)                             \
  COMPARE(Saddw(v0.TA, v1.TA, v2.TB), "saddw v0." TAS ", v1." TAS \
                                      ", "                        \
                                      "v2." TBS);
  NEON_FORMAT_LIST_LW(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)  \
  COMPARE(Saddw2(v0.TA, v1.TA, v2.TB), \
          "saddw2 v0." TAS ", v1." TAS ", v2." TBS);
  NEON_FORMAT_LIST_LW2(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)                             \
  COMPARE(Usubl(v0.TA, v1.TB, v2.TB), "usubl v0." TAS ", v1." TBS \
                                      ", "                        \
                                      "v2." TBS);
  NEON_FORMAT_LIST_LW(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)  \
  COMPARE(Usubl2(v0.TA, v1.TB, v2.TB), \
          "usubl2 v0." TAS ", v1." TBS ", v2." TBS);
  NEON_FORMAT_LIST_LW2(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)                             \
  COMPARE(Usubw(v0.TA, v1.TA, v2.TB), "usubw v0." TAS ", v1." TAS \
                                      ", "                        \
                                      "v2." TBS);
  NEON_FORMAT_LIST_LW(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)  \
  COMPARE(Usubw2(v0.TA, v1.TA, v2.TB), \
          "usubw2 v0." TAS ", v1." TAS ", v2." TBS);
  NEON_FORMAT_LIST_LW2(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)                             \
  COMPARE(Ssubl(v0.TA, v1.TB, v2.TB), "ssubl v0." TAS ", v1." TBS \
                                      ", "                        \
                                      "v2." TBS);
  NEON_FORMAT_LIST_LW(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)  \
  COMPARE(Ssubl2(v0.TA, v1.TB, v2.TB), \
          "ssubl2 v0." TAS ", v1." TBS ", v2." TBS);
  NEON_FORMAT_LIST_LW2(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)                             \
  COMPARE(Ssubw(v0.TA, v1.TA, v2.TB), "ssubw v0." TAS ", v1." TAS \
                                      ", "                        \
                                      "v2." TBS);
  NEON_FORMAT_LIST_LW(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)  \
  COMPARE(Ssubw2(v0.TA, v1.TA, v2.TB), \
          "ssubw2 v0." TAS ", v1." TAS ", v2." TBS);
  NEON_FORMAT_LIST_LW2(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)                             \
  COMPARE(Sabal(v0.TA, v1.TB, v2.TB), "sabal v0." TAS ", v1." TBS \
                                      ", "                        \
                                      "v2." TBS);
  NEON_FORMAT_LIST_LW(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)  \
  COMPARE(Sabal2(v0.TA, v1.TB, v2.TB), \
          "sabal2 v0." TAS ", v1." TBS ", v2." TBS);
  NEON_FORMAT_LIST_LW2(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)                             \
  COMPARE(Uabal(v0.TA, v1.TB, v2.TB), "uabal v0." TAS ", v1." TBS \
                                      ", "                        \
                                      "v2." TBS);
  NEON_FORMAT_LIST_LW(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)  \
  COMPARE(Uabal2(v0.TA, v1.TB, v2.TB), \
          "uabal2 v0." TAS ", v1." TBS ", v2." TBS);
  NEON_FORMAT_LIST_LW2(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)                             \
  COMPARE(Sabdl(v0.TA, v1.TB, v2.TB), "sabdl v0." TAS ", v1." TBS \
                                      ", "                        \
                                      "v2." TBS);
  NEON_FORMAT_LIST_LW(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)  \
  COMPARE(Sabdl2(v0.TA, v1.TB, v2.TB), \
          "sabdl2 v0." TAS ", v1." TBS ", v2." TBS);
  NEON_FORMAT_LIST_LW2(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)                             \
  COMPARE(Uabdl(v0.TA, v1.TB, v2.TB), "uabdl v0." TAS ", v1." TBS \
                                      ", "                        \
                                      "v2." TBS);
  NEON_FORMAT_LIST_LW(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)  \
  COMPARE(Uabdl2(v0.TA, v1.TB, v2.TB), \
          "uabdl2 v0." TAS ", v1." TBS ", v2." TBS);
  NEON_FORMAT_LIST_LW2(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)                             \
  COMPARE(Smlal(v0.TA, v1.TB, v2.TB), "smlal v0." TAS ", v1." TBS \
                                      ", "                        \
                                      "v2." TBS);
  NEON_FORMAT_LIST_LW(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)  \
  COMPARE(Smlal2(v0.TA, v1.TB, v2.TB), \
          "smlal2 v0." TAS ", v1." TBS ", v2." TBS);
  NEON_FORMAT_LIST_LW2(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)                             \
  COMPARE(Umlsl(v0.TA, v1.TB, v2.TB), "umlsl v0." TAS ", v1." TBS \
                                      ", "                        \
                                      "v2." TBS);
  NEON_FORMAT_LIST_LW(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)  \
  COMPARE(Umlsl2(v0.TA, v1.TB, v2.TB), \
          "umlsl2 v0." TAS ", v1." TBS ", v2." TBS);
  NEON_FORMAT_LIST_LW2(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)                             \
  COMPARE(Smlsl(v0.TA, v1.TB, v2.TB), "smlsl v0." TAS ", v1." TBS \
                                      ", "                        \
                                      "v2." TBS);
  NEON_FORMAT_LIST_LW(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)  \
  COMPARE(Smlsl2(v0.TA, v1.TB, v2.TB), \
          "smlsl2 v0." TAS ", v1." TBS ", v2." TBS);
  NEON_FORMAT_LIST_LW2(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)                             \
  COMPARE(Umlsl(v0.TA, v1.TB, v2.TB), "umlsl v0." TAS ", v1." TBS \
                                      ", "                        \
                                      "v2." TBS);
  NEON_FORMAT_LIST_LW(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)  \
  COMPARE(Umlsl2(v0.TA, v1.TB, v2.TB), \
          "umlsl2 v0." TAS ", v1." TBS ", v2." TBS);
  NEON_FORMAT_LIST_LW2(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)                             \
  COMPARE(Smull(v0.TA, v1.TB, v2.TB), "smull v0." TAS ", v1." TBS \
                                      ", "                        \
                                      "v2." TBS);
  NEON_FORMAT_LIST_LW(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)  \
  COMPARE(Smull2(v0.TA, v1.TB, v2.TB), \
          "smull2 v0." TAS ", v1." TBS ", v2." TBS);
  NEON_FORMAT_LIST_LW2(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)                             \
  COMPARE(Umull(v0.TA, v1.TB, v2.TB), "umull v0." TAS ", v1." TBS \
                                      ", "                        \
                                      "v2." TBS);
  NEON_FORMAT_LIST_LW(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS)  \
  COMPARE(Umull2(v0.TA, v1.TB, v2.TB), \
          "umull2 v0." TAS ", v1." TBS ", v2." TBS);
  NEON_FORMAT_LIST_LW2(DISASM_INST)
#undef DISASM_INST

  COMPARE(Sqdmull(v0.V4S(), v1.V4H(), v2.V4H()), "sqdmull v0.4s, v1.4h, v2.4h");
  COMPARE(Sqdmull(v1.V2D(), v2.V2S(), v3.V2S()), "sqdmull v1.2d, v2.2s, v3.2s");
  COMPARE(Sqdmull2(v2.V4S(), v3.V8H(), v4.V8H()),
          "sqdmull2 v2.4s, v3.8h, v4.8h");
  COMPARE(Sqdmull2(v3.V2D(), v4.V4S(), v5.V4S()),
          "sqdmull2 v3.2d, v4.4s, v5.4s");
  COMPARE(Sqdmull(s0, h1, h2), "sqdmull s0, h1, h2");
  COMPARE(Sqdmull(d1, s2, s3), "sqdmull d1, s2, s3");

  COMPARE(Sqdmlal(v0.V4S(), v1.V4H(), v2.V4H()), "sqdmlal v0.4s, v1.4h, v2.4h");
  COMPARE(Sqdmlal(v1.V2D(), v2.V2S(), v3.V2S()), "sqdmlal v1.2d, v2.2s, v3.2s");
  COMPARE(Sqdmlal2(v2.V4S(), v3.V8H(), v4.V8H()),
          "sqdmlal2 v2.4s, v3.8h, v4.8h");
  COMPARE(Sqdmlal2(v3.V2D(), v4.V4S(), v5.V4S()),
          "sqdmlal2 v3.2d, v4.4s, v5.4s");
  COMPARE(Sqdmlal(s0, h1, h2), "sqdmlal s0, h1, h2");
  COMPARE(Sqdmlal(d1, s2, s3), "sqdmlal d1, s2, s3");

  COMPARE(Sqdmlsl(v0.V4S(), v1.V4H(), v2.V4H()), "sqdmlsl v0.4s, v1.4h, v2.4h");
  COMPARE(Sqdmlsl(v1.V2D(), v2.V2S(), v3.V2S()), "sqdmlsl v1.2d, v2.2s, v3.2s");
  COMPARE(Sqdmlsl2(v2.V4S(), v3.V8H(), v4.V8H()),
          "sqdmlsl2 v2.4s, v3.8h, v4.8h");
  COMPARE(Sqdmlsl2(v3.V2D(), v4.V4S(), v5.V4S()),
          "sqdmlsl2 v3.2d, v4.4s, v5.4s");
  COMPARE(Sqdmlsl(s0, h1, h2), "sqdmlsl s0, h1, h2");
  COMPARE(Sqdmlsl(d1, s2, s3), "sqdmlsl d1, s2, s3");

  COMPARE(Addhn(v0.V8B(), v1.V8H(), v2.V8H()), "addhn v0.8b, v1.8h, v2.8h");
  COMPARE(Addhn(v1.V4H(), v2.V4S(), v3.V4S()), "addhn v1.4h, v2.4s, v3.4s");
  COMPARE(Addhn(v2.V2S(), v3.V2D(), v4.V2D()), "addhn v2.2s, v3.2d, v4.2d");
  COMPARE(Addhn2(v0.V16B(), v1.V8H(), v5.V8H()), "addhn2 v0.16b, v1.8h, v5.8h");
  COMPARE(Addhn2(v1.V8H(), v2.V4S(), v6.V4S()), "addhn2 v1.8h, v2.4s, v6.4s");
  COMPARE(Addhn2(v2.V4S(), v3.V2D(), v7.V2D()), "addhn2 v2.4s, v3.2d, v7.2d");

  COMPARE(Raddhn(v0.V8B(), v1.V8H(), v2.V8H()), "raddhn v0.8b, v1.8h, v2.8h");
  COMPARE(Raddhn(v1.V4H(), v2.V4S(), v3.V4S()), "raddhn v1.4h, v2.4s, v3.4s");
  COMPARE(Raddhn(v2.V2S(), v3.V2D(), v4.V2D()), "raddhn v2.2s, v3.2d, v4.2d");
  COMPARE(Raddhn2(v0.V16B(), v1.V8H(), v5.V8H()),
          "raddhn2 v0.16b, v1.8h, v5.8h");
  COMPARE(Raddhn2(v1.V8H(), v2.V4S(), v6.V4S()), "raddhn2 v1.8h, v2.4s, v6.4s");
  COMPARE(Raddhn2(v2.V4S(), v3.V2D(), v7.V2D()), "raddhn2 v2.4s, v3.2d, v7.2d");

  COMPARE(Subhn(v1.V4H(), v2.V4S(), v3.V4S()), "subhn v1.4h, v2.4s, v3.4s");
  COMPARE(Subhn(v2.V2S(), v3.V2D(), v4.V2D()), "subhn v2.2s, v3.2d, v4.2d");
  COMPARE(Subhn2(v0.V16B(), v1.V8H(), v5.V8H()), "subhn2 v0.16b, v1.8h, v5.8h");
  COMPARE(Subhn2(v1.V8H(), v2.V4S(), v6.V4S()), "subhn2 v1.8h, v2.4s, v6.4s");
  COMPARE(Subhn2(v2.V4S(), v3.V2D(), v7.V2D()), "subhn2 v2.4s, v3.2d, v7.2d");

  COMPARE(Rsubhn(v0.V8B(), v1.V8H(), v2.V8H()), "rsubhn v0.8b, v1.8h, v2.8h");
  COMPARE(Rsubhn(v1.V4H(), v2.V4S(), v3.V4S()), "rsubhn v1.4h, v2.4s, v3.4s");
  COMPARE(Rsubhn(v2.V2S(), v3.V2D(), v4.V2D()), "rsubhn v2.2s, v3.2d, v4.2d");
  COMPARE(Rsubhn2(v0.V16B(), v1.V8H(), v5.V8H()),
          "rsubhn2 v0.16b, v1.8h, v5.8h");
  COMPARE(Rsubhn2(v1.V8H(), v2.V4S(), v6.V4S()), "rsubhn2 v1.8h, v2.4s, v6.4s");
  COMPARE(Rsubhn2(v2.V4S(), v3.V2D(), v7.V2D()), "rsubhn2 v2.4s, v3.2d, v7.2d");

  COMPARE(Pmull(v0.V8H(), v1.V8B(), v2.V8B()), "pmull v0.8h, v1.8b, v2.8b");
  COMPARE(Pmull2(v2.V8H(), v3.V16B(), v4.V16B()),
          "pmull2 v2.8h, v3.16b, v4.16b");

  {
    CpuFeatureScope feature_scope(assm, PMULL1Q,
                                  CpuFeatureScope::kDontCheckSupported);

    COMPARE(Pmull(v5.V1Q(), v6.V1D(), v7.V1D()), "pmull v5.1q, v6.1d, v7.1d");
    COMPARE(Pmull2(v8.V1Q(), v9.V2D(), v10.V2D()),
            "pmull2 v8.1q, v9.2d, v10.2d");
  }

  {
    CpuFeatureScope feature_scope(assm, DOTPROD,
                                  CpuFeatureScope::kDontCheckSupported);

    COMPARE(Sdot(v11.V2S(), v20.V8B(), v25.V8B()),
            "sdot v11.2s, v20.8b, v25.8b");
    COMPARE(Sdot(v26.V4S(), v5.V16B(), v14.V16B()),
            "sdot v26.4s, v5.16b, v14.16b");
  }

  CLEANUP();
}

TEST_F(DisasmArm64Test, neon_perm) {
  SET_UP_MASM();

#define DISASM_INST(M, S) \
  COMPARE(Trn1(v0.M, v1.M, v2.M), "trn1 v0." S ", v1." S ", v2." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Trn2(v0.M, v1.M, v2.M), "trn2 v0." S ", v1." S ", v2." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Uzp1(v0.M, v1.M, v2.M), "uzp1 v0." S ", v1." S ", v2." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Uzp2(v0.M, v1.M, v2.M), "uzp2 v0." S ", v1." S ", v2." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Zip1(v0.M, v1.M, v2.M), "zip1 v0." S ", v1." S ", v2." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Zip2(v0.M, v1.M, v2.M), "zip2 v0." S ", v1." S ", v2." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

  CLEANUP();
}

TEST_F(DisasmArm64Test, neon_copy) {
  SET_UP_MASM();

  COMPARE(Ins(v1.V16B(), 4, v5.V16B(), 0), "mov v1.b[4], v5.b[0]");
  COMPARE(Ins(v2.V8B(), 5, v6.V8B(), 1), "mov v2.b[5], v6.b[1]");
  COMPARE(Ins(v3.B(), 6, v7.B(), 2), "mov v3.b[6], v7.b[2]");
  COMPARE(Ins(v4.V8H(), 7, v8_.V8H(), 3), "mov v4.h[7], v8.h[3]");
  COMPARE(Ins(v5.V4H(), 3, v9.V4H(), 0), "mov v5.h[3], v9.h[0]");
  COMPARE(Ins(v6.H(), 6, v1.H(), 1), "mov v6.h[6], v1.h[1]");
  COMPARE(Ins(v7.V4S(), 2, v2.V4S(), 2), "mov v7.s[2], v2.s[2]");
  COMPARE(Ins(v8_.V2S(), 1, v3.V2S(), 0), "mov v8.s[1], v3.s[0]");
  COMPARE(Ins(v9.S(), 0, v4.S(), 1), "mov v9.s[0], v4.s[1]");
  COMPARE(Ins(v1.V2D(), 1, v5.V2D(), 0), "mov v1.d[1], v5.d[0]");
  COMPARE(Ins(v2.D(), 0, v6.D(), 1), "mov v2.d[0], v6.d[1]");

  COMPARE(Mov(v3.V16B(), 4, v7.V16B(), 0), "mov v3.b[4], v7.b[0]");
  COMPARE(Mov(v4.V8B(), 5, v8_.V8B(), 1), "mov v4.b[5], v8.b[1]");
  COMPARE(Mov(v5.B(), 6, v9.B(), 2), "mov v5.b[6], v9.b[2]");
  COMPARE(Mov(v6.V8H(), 7, v1.V8H(), 3), "mov v6.h[7], v1.h[3]");
  COMPARE(Mov(v7.V4H(), 0, v2.V4H(), 0), "mov v7.h[0], v2.h[0]");
  COMPARE(Mov(v8_.H(), 1, v3.H(), 1), "mov v8.h[1], v3.h[1]");
  COMPARE(Mov(v9.V4S(), 2, v4.V4S(), 2), "mov v9.s[2], v4.s[2]");
  COMPARE(Mov(v1.V2S(), 3, v5.V2S(), 0), "mov v1.s[3], v5.s[0]");
  COMPARE(Mov(v2.S(), 0, v6.S(), 1), "mov v2.s[0], v6.s[1]");
  COMPARE(Mov(v3.V2D(), 1, v7.V2D(), 0), "mov v3.d[1], v7.d[0]");
  COMPARE(Mov(v4.D(), 0, v8_.D(), 1), "mov v4.d[0], v8.d[1]");

  COMPARE(Ins(v1.V16B(), 4, w0), "mov v1.b[4], w0");
  COMPARE(Ins(v2.V8B(), 5, w1), "mov v2.b[5], w1");
  COMPARE(Ins(v3.B(), 6, w2), "mov v3.b[6], w2");
  COMPARE(Ins(v4.V8H(), 7, w3), "mov v4.h[7], w3");
  COMPARE(Ins(v5.V4H(), 3, w0), "mov v5.h[3], w0");
  COMPARE(Ins(v6.H(), 6, w1), "mov v6.h[6], w1");
  COMPARE(Ins(v7.V4S(), 2, w2), "mov v7.s[2], w2");
  COMPARE(Ins(v8_.V2S(), 1, w0), "mov v8.s[1], w0");
  COMPARE(Ins(v9.S(), 0, w1), "mov v9.s[0], w1");
  COMPARE(Ins(v1.V2D(), 1, x0), "mov v1.d[1], x0");
  COMPARE(Ins(v2.D(), 0, x1), "mov v2.d[0], x1");

  COMPARE(Mov(v1.V16B(), 4, w0), "mov v1.b[4], w0");
  COMPARE(Mov(v2.V8B(), 5, w1), "mov v2.b[5], w1");
  COMPARE(Mov(v3.B(), 6, w2), "mov v3.b[6], w2");
  COMPARE(Mov(v4.V8H(), 7, w3), "mov v4.h[7], w3");
  COMPARE(Mov(v5.V4H(), 3, w0), "mov v5.h[3], w0");
  COMPARE(Mov(v6.H(), 6, w1), "mov v6.h[6], w1");
  COMPARE(Mov(v7.V4S(), 2, w2), "mov v7.s[2], w2");
  COMPARE(Mov(v8_.V2S(), 1, w0), "mov v8.s[1], w0");
  COMPARE(Mov(v9.S(), 0, w1), "mov v9.s[0], w1");
  COMPARE(Mov(v1.V2D(), 1, x0), "mov v1.d[1], x0");
  COMPARE(Mov(v2.D(), 0, x1), "mov v2.d[0], x1");

  COMPARE(Dup(v5.V8B(), v9.V8B(), 6), "dup v5.8b, v9.b[6]");
  COMPARE(Dup(v6.V16B(), v1.V16B(), 5), "dup v6.16b, v1.b[5]");
  COMPARE(Dup(v7.V4H(), v2.V4H(), 4), "dup v7.4h, v2.h[4]");
  COMPARE(Dup(v8_.V8H(), v3.V8H(), 3), "dup v8.8h, v3.h[3]");
  COMPARE(Dup(v9.V2S(), v4.V2S(), 2), "dup v9.2s, v4.s[2]");
  COMPARE(Dup(v1.V4S(), v5.V4S(), 1), "dup v1.4s, v5.s[1]");
  COMPARE(Dup(v2.V2D(), v6.V2D(), 0), "dup v2.2d, v6.d[0]");

  COMPARE(Dup(v5.B(), v9.B(), 6), "mov b5, v9.b[6]");
  COMPARE(Dup(v7.H(), v2.H(), 4), "mov h7, v2.h[4]");
  COMPARE(Dup(v9.S(), v4.S(), 2), "mov s9, v4.s[2]");
  COMPARE(Dup(v2.D(), v6.D(), 0), "mov d2, v6.d[0]");

  COMPARE(Mov(v5.B(), v9.B(), 6), "mov b5, v9.b[6]");
  COMPARE(Mov(v7.H(), v2.H(), 4), "mov h7, v2.h[4]");
  COMPARE(Mov(v9.S(), v4.S(), 2), "mov s9, v4.s[2]");
  COMPARE(Mov(v2.D(), v6.D(), 0), "mov d2, v6.d[0]");

  COMPARE(Mov(v0.B(), v1.V8B(), 7), "mov b0, v1.b[7]");
  COMPARE(Mov(b2, v3.V16B(), 15), "mov b2, v3.b[15]");
  COMPARE(Mov(v4.H(), v5.V4H(), 3), "mov h4, v5.h[3]");
  COMPARE(Mov(h6, v7.V8H(), 7), "mov h6, v7.h[7]");
  COMPARE(Mov(v8_.S(), v9.V2S(), 1), "mov s8, v9.s[1]");
  COMPARE(Mov(s10, v11.V4S(), 3), "mov s10, v11.s[3]");
  COMPARE(Mov(v12.D(), v13.V2D(), 1), "mov d12, v13.d[1]");

  COMPARE(Dup(v5.V8B(), w0), "dup v5.8b, w0");
  COMPARE(Dup(v6.V16B(), w1), "dup v6.16b, w1");
  COMPARE(Dup(v7.V4H(), w2), "dup v7.4h, w2");
  COMPARE(Dup(v8_.V8H(), w3), "dup v8.8h, w3");
  COMPARE(Dup(v9.V2S(), w4), "dup v9.2s, w4");
  COMPARE(Dup(v1.V4S(), w5), "dup v1.4s, w5");
  COMPARE(Dup(v2.V2D(), x6), "dup v2.2d, x6");

  COMPARE(Smov(w0, v1.V16B(), 4), "smov w0, v1.b[4]");
  COMPARE(Smov(w1, v2.V8B(), 5), "smov w1, v2.b[5]");
  COMPARE(Smov(w2, v3.B(), 6), "smov w2, v3.b[6]");
  COMPARE(Smov(w3, v4.V8H(), 7), "smov w3, v4.h[7]");
  COMPARE(Smov(w0, v5.V4H(), 3), "smov w0, v5.h[3]");
  COMPARE(Smov(w1, v6.H(), 6), "smov w1, v6.h[6]");

  COMPARE(Smov(x0, v1.V16B(), 4), "smov x0, v1.b[4]");
  COMPARE(Smov(x1, v2.V8B(), 5), "smov x1, v2.b[5]");
  COMPARE(Smov(x2, v3.B(), 6), "smov x2, v3.b[6]");
  COMPARE(Smov(x3, v4.V8H(), 7), "smov x3, v4.h[7]");
  COMPARE(Smov(x0, v5.V4H(), 3), "smov x0, v5.h[3]");
  COMPARE(Smov(x1, v6.H(), 6), "smov x1, v6.h[6]");
  COMPARE(Smov(x2, v7.V4S(), 2), "smov x2, v7.s[2]");
  COMPARE(Smov(x0, v8_.V2S(), 1), "smov x0, v8.s[1]");
  COMPARE(Smov(x1, v9.S(), 0), "smov x1, v9.s[0]");

  COMPARE(Umov(w0, v1.V16B(), 4), "umov w0, v1.b[4]");
  COMPARE(Umov(w1, v2.V8B(), 5), "umov w1, v2.b[5]");
  COMPARE(Umov(w2, v3.B(), 6), "umov w2, v3.b[6]");
  COMPARE(Umov(w3, v4.V8H(), 7), "umov w3, v4.h[7]");
  COMPARE(Umov(w0, v5.V4H(), 3), "umov w0, v5.h[3]");
  COMPARE(Umov(w1, v6.H(), 6), "umov w1, v6.h[6]");
  COMPARE(Umov(w2, v7.V4S(), 2), "mov w2, v7.s[2]");
  COMPARE(Umov(w0, v8_.V2S(), 1), "mov w0, v8.s[1]");
  COMPARE(Umov(w1, v9.S(), 0), "mov w1, v9.s[0]");
  COMPARE(Umov(x0, v1.V2D(), 1), "mov x0, v1.d[1]");
  COMPARE(Umov(x1, v2.D(), 0), "mov x1, v2.d[0]");

  COMPARE(Mov(w2, v7.V4S(), 2), "mov w2, v7.s[2]");
  COMPARE(Mov(w0, v8_.V2S(), 1), "mov w0, v8.s[1]");
  COMPARE(Mov(w1, v9.S(), 0), "mov w1, v9.s[0]");
  COMPARE(Mov(x0, v1.V2D(), 1), "mov x0, v1.d[1]");
  COMPARE(Mov(x1, v2.D(), 0), "mov x1, v2.d[0]");

  CLEANUP();
}

TEST_F(DisasmArm64Test, neon_extract) {
  SET_UP_MASM();

  COMPARE(Ext(v4.V8B(), v5.V8B(), v6.V8B(), 0), "ext v4.8b, v5.8b, v6.8b, #0");
  COMPARE(Ext(v1.V8B(), v2.V8B(), v3.V8B(), 7), "ext v1.8b, v2.8b, v3.8b, #7");
  COMPARE(Ext(v1.V16B(), v2.V16B(), v3.V16B(), 0),
          "ext v1.16b, v2.16b, v3.16b, #0");
  COMPARE(Ext(v1.V16B(), v2.V16B(), v3.V16B(), 15),
          "ext v1.16b, v2.16b, v3.16b, #15");

  CLEANUP();
}

TEST_F(DisasmArm64Test, neon_table) {
  SET_UP_MASM();

  COMPARE(Tbl(v0.V8B(), v1.V16B(), v2.V8B()), "tbl v0.8b, {v1.16b}, v2.8b");
  COMPARE(Tbl(v3.V8B(), v4.V16B(), v5.V16B(), v6.V8B()),
          "tbl v3.8b, {v4.16b, v5.16b}, v6.8b");
  COMPARE(Tbl(v7.V8B(), v8_.V16B(), v9.V16B(), v10.V16B(), v11.V8B()),
          "tbl v7.8b, {v8.16b, v9.16b, v10.16b}, v11.8b");
  COMPARE(
      Tbl(v12.V8B(), v13.V16B(), v14.V16B(), v15.V16B(), v16.V16B(), v17.V8B()),
      "tbl v12.8b, {v13.16b, v14.16b, v15.16b, v16.16b}, v17.8b");
  COMPARE(Tbl(v18.V16B(), v19.V16B(), v20.V16B()),
          "tbl v18.16b, {v19.16b}, v20.16b");
  COMPARE(Tbl(v21.V16B(), v22.V16B(), v23.V16B(), v24.V16B()),
          "tbl v21.16b, {v22.16b, v23.16b}, v24.16b");
  COMPARE(Tbl(v25.V16B(), v26.V16B(), v27.V16B(), v28.V16B(), v29.V16B()),
          "tbl v25.16b, {v26.16b, v27.16b, v28.16b}, v29.16b");
  COMPARE(
      Tbl(v30.V16B(), v31.V16B(), v0.V16B(), v1.V16B(), v2.V16B(), v3.V16B()),
      "tbl v30.16b, {v31.16b, v0.16b, v1.16b, v2.16b}, v3.16b");

  COMPARE(Tbx(v0.V8B(), v1.V16B(), v2.V8B()), "tbx v0.8b, {v1.16b}, v2.8b");
  COMPARE(Tbx(v3.V8B(), v4.V16B(), v5.V16B(), v6.V8B()),
          "tbx v3.8b, {v4.16b, v5.16b}, v6.8b");
  COMPARE(Tbx(v7.V8B(), v8_.V16B(), v9.V16B(), v10.V16B(), v11.V8B()),
          "tbx v7.8b, {v8.16b, v9.16b, v10.16b}, v11.8b");
  COMPARE(
      Tbx(v12.V8B(), v13.V16B(), v14.V16B(), v15.V16B(), v16.V16B(), v17.V8B()),
      "tbx v12.8b, {v13.16b, v14.16b, v15.16b, v16.16b}, v17.8b");
  COMPARE(Tbx(v18.V16B(), v19.V16B(), v20.V16B()),
          "tbx v18.16b, {v19.16b}, v20.16b");
  COMPARE(Tbx(v21.V16B(), v22.V16B(), v23.V16B(), v24.V16B()),
          "tbx v21.16b, {v22.16b, v23.16b}, v24.16b");
  COMPARE(Tbx(v25.V16B(), v26.V16B(), v27.V16B(), v28.V16B(), v29.V16B()),
          "tbx v25.16b, {v26.16b, v27.16b, v28.16b}, v29.16b");
  COMPARE(
      Tbx(v30.V16B(), v31.V16B(), v0.V16B(), v1.V16B(), v2.V16B(), v3.V16B()),
      "tbx v30.16b, {v31.16b, v0.16b, v1.16b, v2.16b}, v3.16b");

  CLEANUP();
}

TEST_F(DisasmArm64Test, neon_modimm) {
  SET_UP_MASM();

  COMPARE(Orr(v4.V4H(), 0xaa, 0), "orr v4.4h, #0xaa, lsl #0");
  COMPARE(Orr(v1.V8H(), 0xcc, 8), "orr v1.8h, #0xcc, lsl #8");
  COMPARE(Orr(v4.V2S(), 0xaa, 0), "orr v4.2s, #0xaa, lsl #0");
  COMPARE(Orr(v1.V2S(), 0xcc, 8), "orr v1.2s, #0xcc, lsl #8");
  COMPARE(Orr(v4.V4S(), 0xaa, 16), "orr v4.4s, #0xaa, lsl #16");
  COMPARE(Orr(v1.V4S(), 0xcc, 24), "orr v1.4s, #0xcc, lsl #24");

  COMPARE(Bic(v4.V4H(), 0xaa, 0), "bic v4.4h, #0xaa, lsl #0");
  COMPARE(Bic(v1.V8H(), 0xcc, 8), "bic v1.8h, #0xcc, lsl #8");
  COMPARE(Bic(v4.V2S(), 0xaa, 0), "bic v4.2s, #0xaa, lsl #0");
  COMPARE(Bic(v1.V2S(), 0xcc, 8), "bic v1.2s, #0xcc, lsl #8");
  COMPARE(Bic(v4.V4S(), 0xaa, 16), "bic v4.4s, #0xaa, lsl #16");
  COMPARE(Bic(v1.V4S(), 0xcc, 24), "bic v1.4s, #0xcc, lsl #24");

  COMPARE(Mvni(v4.V4H(), 0xaa, LSL, 0), "mvni v4.4h, #0xaa, lsl #0");
  COMPARE(Mvni(v1.V8H(), 0xcc, LSL, 8), "mvni v1.8h, #0xcc, lsl #8");
  COMPARE(Mvni(v4.V2S(), 0xaa, LSL, 0), "mvni v4.2s, #0xaa, lsl #0");
  COMPARE(Mvni(v1.V2S(), 0xcc, LSL, 8), "mvni v1.2s, #0xcc, lsl #8");
  COMPARE(Mvni(v4.V4S(), 0xaa, LSL, 16), "mvni v4.4s, #0xaa, lsl #16");
  COMPARE(Mvni(v1.V4S(), 0xcc, LSL, 24), "mvni v1.4s, #0xcc, lsl #24");

  COMPARE(Mvni(v4.V2S(), 0xaa, MSL, 8), "mvni v4.2s, #0xaa, msl #8");
  COMPARE(Mvni(v1.V2S(), 0xcc, MSL, 16), "mvni v1.2s, #0xcc, msl #16");
  COMPARE(Mvni(v4.V4S(), 0xaa, MSL, 8), "mvni v
"""


```