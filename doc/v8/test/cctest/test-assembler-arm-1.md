Response: The user wants a summary of the provided C++ code snippet. This snippet appears to be a part of a larger test file for the ARM assembler in the V8 JavaScript engine.

The code focuses on testing the functionality of various ARM NEON (SIMD) instructions. It sets up a data structure `T` to hold input and output values. Then, it uses the V8 assembler to generate ARM assembly code that manipulates data using NEON instructions like `vzip`, `vuzp`, `vtrn`, `vrev`, `vtbl`, and `vtbx`.

To illustrate the connection to JavaScript, I need to show how these low-level NEON instructions can be used to optimize operations that are common in JavaScript, especially when dealing with numerical data.

Plan:
1. Summarize the C++ code's functionality: testing ARM NEON instructions for data rearrangement and table lookups.
2. Explain the relationship to JavaScript: NEON instructions can speed up array manipulation and data processing in JavaScript.
3. Provide a JavaScript example that could benefit from the NEON instructions tested in the C++ code.
这是 `v8/test/cctest/test-assembler-arm.cc` 文件的一部分，主要功能是**测试 ARM 汇编器对 NEON (Advanced SIMD) 指令的支持和正确性**。

具体来说，这段代码生成了一段 ARM 汇编代码，这段代码会执行一系列 NEON 指令，例如 `vzip` (向量交错配对), `vuzp` (向量反交错配对), `vtrn` (向量转置), `vrev` (向量反转), `vtbl` (向量表查找), 和 `vtbx` (向量表查找并混合)。  它会加载一些测试数据到 NEON 寄存器中，执行这些指令，然后将结果存储回内存中的特定位置。 之后，测试代码会检查这些内存位置的值，以验证 NEON 指令是否按照预期工作。

**它与 JavaScript 的功能有关系**，因为 V8 JavaScript 引擎在底层使用了汇编语言（包括 ARM 汇编和 NEON 指令）来实现高性能的 JavaScript 执行。  当 JavaScript 代码执行涉及到大量并行数据处理时，V8 可能会利用 NEON 指令来加速这些操作。

**JavaScript 例子：**

假设我们有一个 JavaScript 数组，需要将它的奇数索引和偶数索引的元素进行交错合并。 例如，将 `[a0, a1, a2, a3, a4, a5]` 转换为 `[a0, a2, a4, a1, a3, a5]`。

```javascript
function interleaveArrays(arr) {
  const len = arr.length;
  if (len < 2) {
    return arr;
  }
  const even = [];
  const odd = [];
  for (let i = 0; i < len; i++) {
    if (i % 2 === 0) {
      even.push(arr[i]);
    } else {
      odd.push(arr[i]);
    }
  }
  const result = [];
  const evenLen = even.length;
  const oddLen = odd.length;
  for (let i = 0; i < evenLen || i < oddLen; i++) {
    if (i < evenLen) {
      result.push(even[i]);
    }
    if (i < oddLen) {
      result.push(odd[i]);
    }
  }
  return result;
}

const myArray = [1, 2, 3, 4, 5, 6, 7, 8];
const interleavedArray = interleaveArrays(myArray);
console.log(interleavedArray); // 输出: [1, 3, 5, 7, 2, 4, 6, 8]
```

在 V8 引擎的底层实现中，当遇到类似数组交错操作时，它可能会尝试将这个 JavaScript 操作映射到高效的 NEON 指令 `vzip`。  `vzip` 指令可以在硬件层面并行地完成这种数据的交错合并，比 JavaScript 循环的逐个元素操作要快得多。

**在 C++ 测试代码中看到的 `vzip` 指令，正是用来测试这种底层优化是否正确实现的。**  测试代码创建了模拟的 NEON 寄存器数据，执行 `vzip`，然后验证输出是否符合预期的交错结果。 如果测试通过，就意味着 V8 引擎可以安全地使用 `vzip` 指令来优化相应的 JavaScript 代码，从而提升性能。

总而言之，这段 C++ 代码是 V8 引擎为了确保其底层汇编代码（特别是 NEON 指令）的正确性而进行的单元测试，这直接关系到 V8 执行 JavaScript 代码的效率。

### 提示词
```
这是目录为v8/test/cctest/test-assembler-arm.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```
NeonListOperand(q1), NeonMemOperand(r4));

    // vzip (d-register).
    __ vldr(d2, r0, offsetof(T, lane_test));
    __ vmov(d0, d2);
    __ vmov(d1, d2);
    __ vzip(Neon8, d0, d1);
    __ vstr(d0, r0, offsetof(T, vzipd8a));
    __ vstr(d1, r0, offsetof(T, vzipd8b));
    __ vmov(d0, d2);
    __ vmov(d1, d2);
    __ vzip(Neon16, d0, d1);
    __ vstr(d0, r0, offsetof(T, vzipd16a));
    __ vstr(d1, r0, offsetof(T, vzipd16b));

    // vuzp (q-register).
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, lane_test))));
    __ vld1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ vmov(q1, q0);
    __ vuzp(Neon8, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vuzp8a))));
    __ vst1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vuzp8b))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, lane_test))));
    __ vld1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ vmov(q1, q0);
    __ vuzp(Neon16, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vuzp16a))));
    __ vst1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vuzp16b))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, lane_test))));
    __ vld1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ vmov(q1, q0);
    __ vuzp(Neon32, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vuzp32a))));
    __ vst1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vuzp32b))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vuzp (d-register).
    __ vldr(d2, r0, offsetof(T, lane_test));
    __ vmov(d0, d2);
    __ vmov(d1, d2);
    __ vuzp(Neon8, d0, d1);
    __ vstr(d0, r0, offsetof(T, vuzpd8a));
    __ vstr(d1, r0, offsetof(T, vuzpd8b));
    __ vmov(d0, d2);
    __ vmov(d1, d2);
    __ vuzp(Neon16, d0, d1);
    __ vstr(d0, r0, offsetof(T, vuzpd16a));
    __ vstr(d1, r0, offsetof(T, vuzpd16b));

    // vtrn (q-register).
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, lane_test))));
    __ vld1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ vmov(q1, q0);
    __ vtrn(Neon8, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vtrn8a))));
    __ vst1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vtrn8b))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, lane_test))));
    __ vld1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ vmov(q1, q0);
    __ vtrn(Neon16, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vtrn16a))));
    __ vst1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vtrn16b))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, lane_test))));
    __ vld1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ vmov(q1, q0);
    __ vtrn(Neon32, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vtrn32a))));
    __ vst1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vtrn32b))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vtrn (d-register).
    __ vldr(d2, r0, offsetof(T, lane_test));
    __ vmov(d0, d2);
    __ vmov(d1, d2);
    __ vtrn(Neon8, d0, d1);
    __ vstr(d0, r0, offsetof(T, vtrnd8a));
    __ vstr(d1, r0, offsetof(T, vtrnd8b));
    __ vmov(d0, d2);
    __ vmov(d1, d2);
    __ vtrn(Neon16, d0, d1);
    __ vstr(d0, r0, offsetof(T, vtrnd16a));
    __ vstr(d1, r0, offsetof(T, vtrnd16b));
    __ vmov(d0, d2);
    __ vmov(d1, d2);
    __ vtrn(Neon32, d0, d1);
    __ vstr(d0, r0, offsetof(T, vtrnd32a));
    __ vstr(d1, r0, offsetof(T, vtrnd32b));

    // vrev64/32/16
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, lane_test))));
    __ vld1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ vrev64(Neon32, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vrev64_32))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vrev64(Neon16, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vrev64_16))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vrev64(Neon8, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vrev64_8))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vrev32(Neon16, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vrev32_16))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vrev32(Neon8, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vrev32_8))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vrev16(Neon8, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vrev16_8))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vtb[l/x].
    __ mov(r4, Operand(0x06040200));
    __ mov(r5, Operand(0xFF050301));
    __ vmov(d2, r4, r5);  // d2 = ff05030106040200
    __ vtbl(d0, NeonListOperand(d2, 1), d2);
    __ vstr(d0, r0, offsetof(T, vtbl));
    __ vtbx(d2, NeonListOperand(d2, 1), d2);
    __ vstr(d2, r0, offsetof(T, vtbx));

    // Restore and return.
    __ ldm(ia_w, sp, {r4, r5, pc});

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
    StdoutStream os;
    Print(*code, os);
#endif
    auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
    t.src0 = 0x01020304;
    t.src1 = 0x11121314;
    t.src2 = 0x21222324;
    t.src3 = 0x31323334;
    t.src4 = 0x41424344;
    t.src5 = 0x51525354;
    t.src6 = 0x61626364;
    t.src7 = 0x71727374;
    t.dst0 = 0;
    t.dst1 = 0;
    t.dst2 = 0;
    t.dst3 = 0;
    t.dst4 = 0;
    t.dst5 = 0;
    t.dst6 = 0;
    t.dst7 = 0;
    t.srcA0 = 0x41424344;
    t.srcA1 = 0x81828384;
    t.dstA0 = 0;
    t.dstA1 = 0;
    t.dstA2 = 0;
    t.dstA3 = 0;
    t.lane_test[0] = 0x03020100;
    t.lane_test[1] = 0x07060504;
    t.lane_test[2] = 0x0B0A0908;
    t.lane_test[3] = 0x0F0E0D0C;
    f.Call(&t, 0, 0, 0, 0);

    CHECK_EQ(0x01020304u, t.dst0);
    CHECK_EQ(0x11121314u, t.dst1);
    CHECK_EQ(0x21222324u, t.dst2);
    CHECK_EQ(0x31323334u, t.dst3);
    CHECK_EQ(0x41424344u, t.dst4);
    CHECK_EQ(0x51525354u, t.dst5);
    CHECK_EQ(0x61626364u, t.dst6);
    CHECK_EQ(0x71727374u, t.dst7);
    CHECK_EQ(0x00430044u, t.dstA0);
    CHECK_EQ(0x00410042u, t.dstA1);
    CHECK_EQ(0x00830084u, t.dstA2);
    CHECK_EQ(0x00810082u, t.dstA3);

    CHECK_EQ_32X4(vmovl_s8, 0x00430044u, 0x00410042u, 0xFF83FF84u, 0xFF81FF82u);
    CHECK_EQ_32X4(vmovl_u16, 0xFF84u, 0xFF83u, 0xFF82u, 0xFF81u);
    CHECK_EQ_32X4(vmovl_s32, 0xFF84u, 0x0u, 0xFF83u, 0x0u);
    CHECK_EQ_32X2(vqmovn_u16, 0xFF83FF84u, 0xFF81FF82u);
    CHECK_EQ_32X2(vqmovn_s8, 0x81828384u, 0x81828384u);
    CHECK_EQ_32X2(vqmovn_s32, 0xFF84u, 0xFF83u);

    CHECK_EQ(0xFFFFFFF8FFF8F800u, t.vmov_to_scalar1);
    CHECK_EQ(0xFFF80000F8000000u, t.vmov_to_scalar2);
    CHECK_EQ(0xFFFFFFFFu, t.vmov_from_scalar_s8);
    CHECK_EQ(0xFFu, t.vmov_from_scalar_u8);
    CHECK_EQ(0xFFFFFFFFu, t.vmov_from_scalar_s16);
    CHECK_EQ(0xFFFFu, t.vmov_from_scalar_u16);
    CHECK_EQ(0xFFFFFFFFu, t.vmov_from_scalar_32);

    CHECK_EQ_32X4(vmov, 0x03020100u, 0x07060504u, 0x0B0A0908u, 0x0F0E0D0Cu);
    CHECK_EQ_32X4(vmvn, 0xFCFDFEFFu, 0xF8F9FAFBu, 0xF4F5F6F7u, 0xF0F1F2F3u);

    CHECK_EQ_SPLAT(vdup8, 0x0A0A0A0Au);
    CHECK_EQ_SPLAT(vdup16, 0x000A000Au);
    CHECK_EQ_SPLAT(vdup32, 0x0000000Au);
    CHECK_EQ_SPLAT(vdupf, -1.0);  // bit pattern is 0xBF800000.
    CHECK_EQ_32X2(vdupf_16, 0xBF80BF80u, 0xBF80BF80u);
    CHECK_EQ_SPLAT(vdupf_8, 0xBFBFBFBFu);

    // src: [-1, -1, 1, 1]
    CHECK_EQ_32X4(vcvt_s32_f32, -1, -1, 1, 1);
    CHECK_EQ_32X4(vcvt_u32_f32, 0u, 0u, 1u, 1u);
    // src: [kMinInt, kMaxInt, kMaxUInt32, kMinInt + 1]
    CHECK_EQ_32X4(vcvt_f32_s32, INT32_TO_FLOAT(kMinInt),
                  INT32_TO_FLOAT(kMaxInt), INT32_TO_FLOAT(kMaxUInt32),
                  INT32_TO_FLOAT(kMinInt + 1));
    CHECK_EQ_32X4(vcvt_f32_u32, UINT32_TO_FLOAT(kMinInt),
                  UINT32_TO_FLOAT(kMaxInt), UINT32_TO_FLOAT(kMaxUInt32),
                  UINT32_TO_FLOAT(kMinInt + 1));

    CHECK_EQ_32X4(vclt0_s8, 0x00FFFF00u, 0xFF00FF00u, 0xFF0000FFu, 0x00FF00FFu);
    CHECK_EQ_32X4(vclt0_s16, 0x0000FFFF, 0xFFFFFFFFu, 0xFFFF0000u, 0x00000000u);
    CHECK_EQ_32X4(vclt0_s32, 0x00000000u, 0xFFFFFFFFu, 0xFFFFFFFFu,
                  0x00000000u);

    CHECK_EQ_32X4(vabsf, 1.0, 0.0, 0.0, 1.0);
    CHECK_EQ_32X4(vnegf, 1.0, 0.0, -0.0, -1.0);
    // src: [0x7F7F7F7F, 0x01010101, 0xFFFFFFFF, 0x80808080]
    CHECK_EQ_32X4(vabs_s8, 0x7F7F7F7Fu, 0x01010101u, 0x01010101u, 0x80808080u);
    CHECK_EQ_32X4(vabs_s16, 0x7F7F7F7Fu, 0x01010101u, 0x00010001u, 0x7F807F80u);
    CHECK_EQ_32X4(vabs_s32, 0x7F7F7F7Fu, 0x01010101u, 0x00000001u, 0x7F7F7F80u);
    CHECK_EQ_32X4(vneg_s8, 0x81818181u, 0xFFFFFFFFu, 0x01010101u, 0x80808080u);
    CHECK_EQ_32X4(vneg_s16, 0x80818081u, 0xFEFFFEFFu, 0x00010001u, 0x7F807F80u);
    CHECK_EQ_32X4(vneg_s32, 0x80808081u, 0xFEFEFEFFu, 0x00000001u, 0x7F7F7F80u);

    CHECK_EQ_SPLAT(veor, 0x00FF00FFu);
    CHECK_EQ_SPLAT(vand, 0x00FE00FEu);
    CHECK_EQ_SPLAT(vorr, 0x00FF00FFu);
    CHECK_EQ_SPLAT(vaddf, 2.0);
    CHECK_EQ_32X2(vpaddf, 3.0, 7.0);
    CHECK_EQ_SPLAT(vminf, 1.0);
    CHECK_EQ_SPLAT(vmaxf, 2.0);
    CHECK_EQ_SPLAT(vsubf, -1.0);
    CHECK_EQ_SPLAT(vmulf, 4.0);
    CHECK_ESTIMATE_SPLAT(vrecpe, 0.5f, 0.1f);  // 1 / 2
    CHECK_EQ_SPLAT(vrecps, -1.0f);   // 2 - (2 * 1.5)
    CHECK_ESTIMATE_SPLAT(vrsqrte, 0.5f, 0.1f);  // 1 / sqrt(4)
    CHECK_EQ_SPLAT(vrsqrts, -1.0f);  // (3 - (2 * 2.5)) / 2
    CHECK_EQ_SPLAT(vceqf, 0xFFFFFFFFu);
    // [0] >= [-1, 1, -0, 0]
    CHECK_EQ_32X4(vcgef, 0u, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu);
    CHECK_EQ_32X4(vcgtf, 0u, 0xFFFFFFFFu, 0u, 0u);
    // [0, 3, 0, 3, ...] and [3, 3, 3, 3, ...]
    CHECK_EQ_SPLAT(vmin_s8, 0x00030003u);
    CHECK_EQ_SPLAT(vmax_s8, 0x03030303u);
    // [0x00FF, 0x00FF, ...] and [0xFFFF, 0xFFFF, ...]
    CHECK_EQ_SPLAT(vmin_u16, 0x00FF00FFu);
    CHECK_EQ_SPLAT(vmax_u16, 0xFFFFFFFFu);
    // [0x000000FF, 0x000000FF, ...] and [0xFFFFFFFF, 0xFFFFFFFF, ...]
    CHECK_EQ_SPLAT(vmin_s32, 0xFFFFFFFFu);
    CHECK_EQ_SPLAT(vmax_s32, 0xFFu);
    // [0, 3, 0, 3, ...] and [3, 3, 3, 3, ...]
    CHECK_EQ_32X2(vpadd_i8, 0x03030303u, 0x06060606u);
    CHECK_EQ_32X2(vpadd_i16, 0x0C0C0606u, 0x06060606u);
    CHECK_EQ_32X2(vpadd_i32, 0x12120C0Cu, 0x06060606u);

    CHECK_EQ_32X4(vpadal_s8, 0x30003, 0x30003, 0x30003, 0x30003);
    CHECK_EQ_32X4(vpadal_s16, 0x1000403, 0x1000403, 0x1000403, 0x1000403);
    CHECK_EQ_32X4(vpadal_s32, 0x4040403, 0x1010100, 0x4040403, 0x1010100);

    CHECK_EQ_32X4(vpadal_u8, 0x2030203, 0x2030203, 0x2030203, 0x2030203);
    CHECK_EQ_32X4(vpadal_u16, 0x1020403, 0x1020403, 0x1020403, 0x1020403);
    CHECK_EQ_32X4(vpadal_u32, 0x4040403, 0x1010102, 0x4040403, 0x1010102);

    CHECK_EQ_32X4(vpaddl_s8, 0xFF02FF02, 0xFF02FF02, 0xFF02FF02, 0xFF02FF02);
    CHECK_EQ_32X4(vpaddl_s16, 0xFFFF0302, 0xFFFF0302, 0xFFFF0302, 0xFFFF0302);
    CHECK_EQ_32X4(vpaddl_s32, 0x03030302, 0xFFFFFFFF, 0x03030302, 0xFFFFFFFF);

    CHECK_EQ_32X4(vpaddl_u8, 0x01020102, 0x01020102, 0x01020102, 0x01020102);
    CHECK_EQ_32X4(vpaddl_u16, 0x00010302, 0x00010302, 0x00010302, 0x00010302);
    CHECK_EQ_32X4(vpaddl_u32, 0x03030302, 0x00000001, 0x03030302, 0x00000001);

    CHECK_EQ_32X2(vpmin_s8, 0x00000000u, 0x03030303u);
    CHECK_EQ_32X2(vpmax_s8, 0x03030303u, 0x03030303u);
    // [0, ffff, 0, ffff] and [ffff, ffff]
    CHECK_EQ_32X2(vpmin_u16, 0x00000000u, 0xFFFFFFFFu);
    CHECK_EQ_32X2(vpmax_u16, 0xFFFFFFFFu, 0xFFFFFFFFu);
    // [0x000000FF, 0x00000000u] and [0xFFFFFFFF, 0xFFFFFFFF, ...]
    CHECK_EQ_32X2(vpmin_s32, 0x00u, 0xFFFFFFFFu);
    CHECK_EQ_32X2(vpmax_s32, 0xFFu, 0xFFFFFFFFu);
    CHECK_EQ_SPLAT(vadd8, 0x03030303u);
    CHECK_EQ_SPLAT(vadd16, 0x00030003u);
    CHECK_EQ_SPLAT(vadd32, 0x00000003u);
    CHECK_EQ_SPLAT(vqadd_s8, 0x80808080u);
    CHECK_EQ_SPLAT(vqadd_u16, 0xFFFFFFFFu);
    CHECK_EQ_SPLAT(vqadd_s32, 0x80000000u);
    CHECK_EQ_SPLAT(vqsub_u8, 0x00000000u);
    CHECK_EQ_SPLAT(vqsub_s16, 0x7FFF7FFFu);
    CHECK_EQ_SPLAT(vqsub_u32, 0x00000000u);
    CHECK_EQ_SPLAT(vsub8, 0xFEFEFEFEu);
    CHECK_EQ_SPLAT(vsub16, 0xFFFEFFFEu);
    CHECK_EQ_SPLAT(vsub32, 0xFFFFFFFEu);
    CHECK_EQ_SPLAT(vmul8, 0x04040404u);
    CHECK_EQ_SPLAT(vmul16, 0x00040004u);
    CHECK_EQ_SPLAT(vmul32, 0x00000004u);
    CHECK_EQ_SPLAT(vshl8, 0xAAAAAAAAu);
    CHECK_EQ_SPLAT(vshl16, 0xAA00AA00u);
    CHECK_EQ_SPLAT(vshl32, 0xAAAA0000u);
    CHECK_EQ_SPLAT(vshr_s8, 0xC0C0C0C0u);
    CHECK_EQ_SPLAT(vshr_u16, 0x00400040u);
    CHECK_EQ_SPLAT(vshr_s32, 0xFFFFC040u);
    CHECK_EQ_32X2(vshr_s8_d, 0xC0C0C0C0u, 0xC0C0C0C0u);
    CHECK_EQ_32X2(vshr_u16_d, 0x00400040u, 0x00400040u);
    CHECK_EQ_32X2(vshr_s32_d, 0xFFFFC040u, 0xFFFFC040u);
    CHECK_EQ_32X2(vsli_64, 0x01u, 0xFFFFFFFFu);
    CHECK_EQ_32X2(vsri_64, 0xFFFFFFFFu, 0x01u);
    CHECK_EQ_32X2(vsli_32, 0xFFFF0001u, 0x00010001u);
    CHECK_EQ_32X2(vsri_32, 0x00000000u, 0x0000FFFFu);
    CHECK_EQ_32X2(vsra_64, 0xFFFFFFFEu, 0x2);
    CHECK_EQ_32X2(vsra_32, 0x0, 0xFFFFFFFFu);
    CHECK_EQ_32X2(vsra_16, 0x3FFF4000, 0xFFFFFFFFu);
    CHECK_EQ_SPLAT(vceq, 0x00FF00FFu);
    // [0, 3, 0, 3, ...] >= [3, 3, 3, 3, ...]
    CHECK_EQ_SPLAT(vcge_s8, 0x00FF00FFu);
    CHECK_EQ_SPLAT(vcgt_s8, 0u);
    // [0x00FF, 0x00FF, ...] >= [0xFFFF, 0xFFFF, ...]
    CHECK_EQ_SPLAT(vcge_u16, 0u);
    CHECK_EQ_SPLAT(vcgt_u16, 0u);
    // [0x000000FF, 0x000000FF, ...] >= [0xFFFFFFFF, 0xFFFFFFFF, ...]
    CHECK_EQ_SPLAT(vcge_s32, 0xFFFFFFFFu);
    CHECK_EQ_SPLAT(vcgt_s32, 0xFFFFFFFFu);
    CHECK_EQ_SPLAT(vtst, 0x00FF00FFu);
    CHECK_EQ_SPLAT(vbsl, 0x02010201u);

    CHECK_EQ_32X4(vext, 0x06050403u, 0x0A090807u, 0x0E0D0C0Bu, 0x0201000Fu);

    CHECK_EQ_32X4(vzip8a, 0x01010000u, 0x03030202u, 0x05050404u, 0x07070606u);
    CHECK_EQ_32X4(vzip8b, 0x09090808u, 0x0B0B0A0Au, 0x0D0D0C0Cu, 0x0F0F0E0Eu);
    CHECK_EQ_32X4(vzip16a, 0x01000100u, 0x03020302u, 0x05040504u, 0x07060706u);
    CHECK_EQ_32X4(vzip16b, 0x09080908u, 0x0B0A0B0Au, 0x0D0C0D0Cu, 0x0F0E0F0Eu);
    CHECK_EQ_32X4(vzip32a, 0x03020100u, 0x03020100u, 0x07060504u, 0x07060504u);
    CHECK_EQ_32X4(vzip32b, 0x0B0A0908u, 0x0B0A0908u, 0x0F0E0D0Cu, 0x0F0E0D0Cu);

    CHECK_EQ_32X2(vzipd8a, 0x01010000u, 0x03030202u);
    CHECK_EQ_32X2(vzipd8b, 0x05050404u, 0x07070606u);
    CHECK_EQ_32X2(vzipd16a, 0x01000100u, 0x03020302u);
    CHECK_EQ_32X2(vzipd16b, 0x05040504u, 0x07060706u);

    CHECK_EQ_32X4(vuzp8a, 0x06040200u, 0x0E0C0A08u, 0x06040200u, 0x0E0C0A08u);
    CHECK_EQ_32X4(vuzp8b, 0x07050301u, 0x0F0D0B09u, 0x07050301u, 0x0F0D0B09u);
    CHECK_EQ_32X4(vuzp16a, 0x05040100u, 0x0D0C0908u, 0x05040100u, 0x0D0C0908u);
    CHECK_EQ_32X4(vuzp16b, 0x07060302u, 0x0F0E0B0Au, 0x07060302u, 0x0F0E0B0Au);
    CHECK_EQ_32X4(vuzp32a, 0x03020100u, 0x0B0A0908u, 0x03020100u, 0x0B0A0908u);
    CHECK_EQ_32X4(vuzp32b, 0x07060504u, 0x0F0E0D0Cu, 0x07060504u, 0x0F0E0D0Cu);

    CHECK_EQ_32X2(vuzpd8a, 0x06040200u, 0x06040200u);
    CHECK_EQ_32X2(vuzpd8b, 0x07050301u, 0x07050301u);
    CHECK_EQ_32X2(vuzpd16a, 0x05040100u, 0x05040100u);
    CHECK_EQ_32X2(vuzpd16b, 0x07060302u, 0x07060302u);

    CHECK_EQ_32X4(vtrn8a, 0x02020000u, 0x06060404u, 0x0A0A0808u, 0x0E0E0C0Cu);
    CHECK_EQ_32X4(vtrn8b, 0x03030101u, 0x07070505u, 0x0B0B0909u, 0x0F0F0D0Du);
    CHECK_EQ_32X4(vtrn16a, 0x01000100u, 0x05040504u, 0x09080908u, 0x0D0C0D0Cu);
    CHECK_EQ_32X4(vtrn16b, 0x03020302u, 0x07060706u, 0x0B0A0B0Au, 0x0F0E0F0Eu);
    CHECK_EQ_32X4(vtrn32a, 0x03020100u, 0x03020100u, 0x0B0A0908u, 0x0B0A0908u);
    CHECK_EQ_32X4(vtrn32b, 0x07060504u, 0x07060504u, 0x0F0E0D0Cu, 0x0F0E0D0Cu);

    CHECK_EQ_32X2(vtrnd8a, 0x02020000u, 0x06060404u);
    CHECK_EQ_32X2(vtrnd8b, 0x03030101u, 0x07070505u);
    CHECK_EQ_32X2(vtrnd16a, 0x01000100u, 0x05040504u);
    CHECK_EQ_32X2(vtrnd16b, 0x03020302u, 0x07060706u);
    CHECK_EQ_32X2(vtrnd32a, 0x03020100u, 0x03020100u);
    CHECK_EQ_32X2(vtrnd32b, 0x07060504u, 0x07060504u);

    // src: 0 1 2 3  4 5 6 7  8 9 a b  c d e f (little endian)
    CHECK_EQ_32X4(vrev64_32, 0x07060504u, 0x03020100u, 0x0F0E0D0Cu,
                  0x0B0A0908u);
    CHECK_EQ_32X4(vrev64_16, 0x05040706u, 0x01000302u, 0x0D0C0F0Eu,
                  0x09080B0Au);
    CHECK_EQ_32X4(vrev64_8, 0x04050607u, 0x00010203u, 0x0C0D0E0Fu, 0x08090A0Bu);
    CHECK_EQ_32X4(vrev32_16, 0x01000302u, 0x05040706u, 0x09080B0Au,
                  0x0D0C0F0Eu);
    CHECK_EQ_32X4(vrev32_8, 0x00010203u, 0x04050607u, 0x08090A0Bu, 0x0C0D0E0Fu);
    CHECK_EQ_32X4(vrev16_8, 0x02030001u, 0x06070405u, 0x0A0B0809u, 0x0E0F0C0Du);

    CHECK_EQ(0x05010400u, t.vtbl[0]);
    CHECK_EQ(0x00030602u, t.vtbl[1]);
    CHECK_EQ(0x05010400u, t.vtbx[0]);
    CHECK_EQ(0xFF030602u, t.vtbx[1]);
  }
}

TEST(16) {
  // Test the pkh, uxtb, uxtab and uxtb16 instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    uint32_t src0;
    uint32_t src1;
    uint32_t src2;
    uint32_t dst0;
    uint32_t dst1;
    uint32_t dst2;
    uint32_t dst3;
    uint32_t dst4;
  };
  T t;

  // Create a function that accepts &t, and loads, manipulates, and stores
  // the doubles and floats.
  Assembler assm(AssemblerOptions{});

  __ stm(db_w, sp, {r4, lr});

  __ mov(r4, Operand(r0));
  __ ldr(r0, MemOperand(r4, offsetof(T, src0)));
  __ ldr(r1, MemOperand(r4, offsetof(T, src1)));

  __ pkhbt(r2, r0, Operand(r1, LSL, 8));
  __ str(r2, MemOperand(r4, offsetof(T, dst0)));

  __ pkhtb(r2, r0, Operand(r1, ASR, 8));
  __ str(r2, MemOperand(r4, offsetof(T, dst1)));

  __ uxtb16(r2, r0, 8);
  __ str(r2, MemOperand(r4, offsetof(T, dst2)));

  __ uxtb(r2, r0, 8);
  __ str(r2, MemOperand(r4, offsetof(T, dst3)));

  __ ldr(r0, MemOperand(r4, offsetof(T, src2)));
  __ uxtab(r2, r0, r1, 8);
  __ str(r2, MemOperand(r4, offsetof(T, dst4)));

  __ ldm(ia_w, sp, {r4, pc});

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  StdoutStream os;
  Print(*code, os);
#endif
  auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
  t.src0 = 0x01020304;
  t.src1 = 0x11121314;
  t.src2 = 0x11121300;
  t.dst0 = 0;
  t.dst1 = 0;
  t.dst2 = 0;
  t.dst3 = 0;
  t.dst4 = 0;
  f.Call(&t, 0, 0, 0, 0);
  CHECK_EQ(0x12130304u, t.dst0);
  CHECK_EQ(0x01021213u, t.dst1);
  CHECK_EQ(0x00010003u, t.dst2);
  CHECK_EQ(0x00000003u, t.dst3);
  CHECK_EQ(0x11121313u, t.dst4);
}


TEST(17) {
  // Test generating labels at high addresses.
  // Should not assert.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  // Generate a code segment that will be longer than 2^24 bytes.
  Assembler assm(AssemblerOptions{});
  for (size_t i = 0; i < 1 << 23 ; ++i) {  // 2^23
    __ nop();
  }

  Label target;
  __ b(eq, &target);
  __ bind(&target);
  __ nop();
}

#define TEST_SDIV(expected_, dividend_, divisor_) \
  t.dividend = dividend_;                         \
  t.divisor = divisor_;                           \
  t.result = 0;                                   \
  f.Call(&t, 0, 0, 0, 0);                         \
  CHECK_EQ(expected_, t.result);

TEST(sdiv) {
  // Test the sdiv.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  Assembler assm(AssemblerOptions{});

  struct T {
    int32_t dividend;
    int32_t divisor;
    int32_t result;
  } t;

  if (CpuFeatures::IsSupported(SUDIV)) {
    CpuFeatureScope scope(&assm, SUDIV);

    __ mov(r3, Operand(r0));

    __ ldr(r0, MemOperand(r3, offsetof(T, dividend)));
    __ ldr(r1, MemOperand(r3, offsetof(T, divisor)));

    __ sdiv(r2, r0, r1);
    __ str(r2, MemOperand(r3, offsetof(T, result)));

  __ bx(lr);

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
    StdoutStream os;
    Print(*code, os);
#endif
    auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
    TEST_SDIV(0, kMinInt, 0);
    TEST_SDIV(0, 1024, 0);
    TEST_SDIV(1073741824, kMinInt, -2);
    TEST_SDIV(kMinInt, kMinInt, -1);
    TEST_SDIV(5, 10, 2);
    TEST_SDIV(3, 10, 3);
    TEST_SDIV(-5, 10, -2);
    TEST_SDIV(-3, 10, -3);
    TEST_SDIV(-5, -10, 2);
    TEST_SDIV(-3, -10, 3);
    TEST_SDIV(5, -10, -2);
    TEST_SDIV(3, -10, -3);
  }
}


#undef TEST_SDIV

#define TEST_UDIV(expected_, dividend_, divisor_) \
  t.dividend = dividend_;                         \
  t.divisor = divisor_;                           \
  t.result = 0;                                   \
  f.Call(&t, 0, 0, 0, 0);                         \
  CHECK_EQ(expected_, t.result);

TEST(udiv) {
  // Test the udiv.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  Assembler assm(AssemblerOptions{});

  struct T {
    uint32_t dividend;
    uint32_t divisor;
    uint32_t result;
  } t;

  if (CpuFeatures::IsSupported(SUDIV)) {
    CpuFeatureScope scope(&assm, SUDIV);

    __ mov(r3, Operand(r0));

    __ ldr(r0, MemOperand(r3, offsetof(T, dividend)));
    __ ldr(r1, MemOperand(r3, offsetof(T, divisor)));

    __ sdiv(r2, r0, r1);
    __ str(r2, MemOperand(r3, offsetof(T, result)));

    __ bx(lr);

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
    StdoutStream os;
    Print(*code, os);
#endif
    auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
    TEST_UDIV(0u, 0, 0);
    TEST_UDIV(0u, 1024, 0);
    TEST_UDIV(5u, 10, 2);
    TEST_UDIV(3u, 10, 3);
  }
}


#undef TEST_UDIV


TEST(smmla) {
  CcTest::InitializeVM();
  Isolate* const isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  RandomNumberGenerator* const rng = isolate->random_number_generator();
  Assembler assm(AssemblerOptions{});
  __ smmla(r1, r1, r2, r3);
  __ str(r1, MemOperand(r0));
  __ bx(lr);
  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code, std::cout);
#endif
  auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
  for (size_t i = 0; i < 128; ++i) {
    int32_t r, x = rng->NextInt(), y = rng->NextInt(), z = rng->NextInt();
    f.Call(&r, x, y, z, 0);
    CHECK_EQ(base::bits::SignedMulHighAndAdd32(x, y, z), r);
  }
}


TEST(smmul) {
  CcTest::InitializeVM();
  Isolate* const isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  RandomNumberGenerator* const rng = isolate->random_number_generator();
  Assembler assm(AssemblerOptions{});
  __ smmul(r1, r1, r2);
  __ str(r1, MemOperand(r0));
  __ bx(lr);
  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code, std::cout);
#endif
  auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
  for (size_t i = 0; i < 128; ++i) {
    int32_t r, x = rng->NextInt(), y = rng->NextInt();
    f.Call(&r, x, y, 0, 0);
    CHECK_EQ(base::bits::SignedMulHigh32(x, y), r);
  }
}


TEST(sxtb) {
  CcTest::InitializeVM();
  Isolate* const isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  RandomNumberGenerator* const rng = isolate->random_number_generator();
  Assembler assm(AssemblerOptions{});
  __ sxtb(r1, r1);
  __ str(r1, MemOperand(r0));
  __ bx(lr);
  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code, std::cout);
#endif
  auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
  for (size_t i = 0; i < 128; ++i) {
    int32_t r, x = rng->NextInt();
    f.Call(&r, x, 0, 0, 0);
    CHECK_EQ(static_cast<int32_t>(static_cast<int8_t>(x)), r);
  }
}


TEST(sxtab) {
  CcTest::InitializeVM();
  Isolate* const isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  RandomNumberGenerator* const rng = isolate->random_number_generator();
  Assembler assm(AssemblerOptions{});
  __ sxtab(r1, r2, r1);
  __ str(r1, MemOperand(r0));
  __ bx(lr);
  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code, std::cout);
#endif
  auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
  for (size_t i = 0; i < 128; ++i) {
    int32_t r, x = rng->NextInt(), y = rng->NextInt();
    f.Call(&r, x, y, 0, 0);
    CHECK_EQ(static_cast<int32_t>(static_cast<int8_t>(x)) + y, r);
  }
}


TEST(sxth) {
  CcTest::InitializeVM();
  Isolate* const isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  RandomNumberGenerator* const rng = isolate->random_number_generator();
  Assembler assm(AssemblerOptions{});
  __ sxth(r1, r1);
  __ str(r1, MemOperand(r0));
  __ bx(lr);
  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code, std::cout);
#endif
  auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
  for (size_t i = 0; i < 128; ++i) {
    int32_t r, x = rng->NextInt();
    f.Call(&r, x, 0, 0, 0);
    CHECK_EQ(static_cast<int32_t>(static_cast<int16_t>(x)), r);
  }
}


TEST(sxtah) {
  CcTest::InitializeVM();
  Isolate* const isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  RandomNumberGenerator* const rng = isolate->random_number_generator();
  Assembler assm(AssemblerOptions{});
  __ sxtah(r1, r2, r1);
  __ str(r1, MemOperand(r0));
  __ bx(lr);
  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code, std::cout);
#endif
  auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
  for (size_t i = 0; i < 128; ++i) {
    int32_t r, x = rng->NextInt(), y = rng->NextInt();
    f.Call(&r, x, y, 0, 0);
    CHECK_EQ(static_cast<int32_t>(static_cast<int16_t>(x)) + y, r);
  }
}


TEST(uxtb) {
  CcTest::InitializeVM();
  Isolate* const isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  RandomNumberGenerator* const rng = isolate->random_number_generator();
  Assembler assm(AssemblerOptions{});
  __ uxtb(r1, r1);
  __ str(r1, MemOperand(r0));
  __ bx(lr);
  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code, std::cout);
#endif
  auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
  for (size_t i = 0; i < 128; ++i) {
    int32_t r, x = rng->NextInt();
    f.Call(&r, x, 0, 0, 0);
    CHECK_EQ(static_cast<int32_t>(static_cast<uint8_t>(x)), r);
  }
}


TEST(uxtab) {
  CcTest::InitializeVM();
  Isolate* const isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  RandomNumberGenerator* const rng = isolate->random_number_generator();
  Assembler assm(AssemblerOptions{});
  __ uxtab(r1, r2, r1);
  __ str(r1, MemOperand(r0));
  __ bx(lr);
  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code, std::cout);
#endif
  auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
  for (size_t i = 0; i < 128; ++i) {
    int32_t r, x = rng->NextInt(), y = rng->NextInt();
    f.Call(&r, x, y, 0, 0);
    CHECK_EQ(static_cast<int32_t>(static_cast<uint8_t>(x)) + y, r);
  }
}


TEST(uxth) {
  CcTest::InitializeVM();
  Isolate* const isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  RandomNumberGenerator* const rng = isolate->random_number_generator();
  Assembler assm(AssemblerOptions{});
  __ uxth(r1, r1);
  __ str(r1, MemOperand(r0));
  __ bx(lr);
  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code, std::cout);
#endif
  auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
  for (size_t i = 0; i < 128; ++i) {
    int32_t r, x = rng->NextInt();
    f.Call(&r, x, 0, 0, 0);
    CHECK_EQ(static_cast<int32_t>(static_cast<uint16_t>(x)), r);
  }
}


TEST(uxtah) {
  CcTest::InitializeVM();
  Isolate* const isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  RandomNumberGenerator* const rng = isolate->random_number_generator();
  Assembler assm(AssemblerOptions{});
  __ uxtah(r1, r2, r1);
  __ str(r1, MemOperand(r0));
  __ bx(lr);
  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code, std::cout);
#endif
  auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
  for (size_t i = 0; i < 128; ++i) {
    int32_t r, x = rng->NextInt(), y = rng->NextInt();
    f.Call(&r, x, y, 0, 0);
    CHECK_EQ(static_cast<int32_t>(static_cast<uint16_t>(x)) + y, r);
  }
}

#define TEST_RBIT(expected_, input_) \
  t.input = input_;                  \
  t.result = 0;                      \
  f.Call(&t, 0, 0, 0, 0);            \
  CHECK_EQ(static_cast<uint32_t>(expected_), t.result);

TEST(rbit) {
  CcTest::InitializeVM();
  Isolate* const isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  Assembler assm(AssemblerOptions{});

  if (CpuFeatures::IsSupported(ARMv7)) {
    CpuFeatureScope scope(&assm, ARMv7);

    struct T {
      uint32_t input;
      uint32_t result;
    };
    T t;

    __ ldr(r1, MemOperand(r0, offsetof(T, input)));
    __ rbit(r1, r1);
    __ str(r1, MemOperand(r0, offsetof(T, result)));
    __ bx(lr);

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

#ifdef OBJECT_PRINT
    Print(*code, std::cout);
#endif

    auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
    TEST_RBIT(0xFFFFFFFF, 0xFFFFFFFF);
    TEST_RBIT(0x00000000, 0x00000000);
    TEST_RBIT(0xFFFF0000, 0x0000FFFF);
    TEST_RBIT(0xFF00FF00, 0x00FF00FF);
    TEST_RBIT(0xF0F0F0F0, 0x0F0F0F0F);
    TEST_RBIT(0x1E6A2C48, 0x12345678);
  }
}


TEST(code_relative_offset) {
  // Test extracting the offset of a label from the beginning of the code
  // in a register.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  // Initialize a code object that will contain the code.
  Handle<HeapObject> code_object(ReadOnlyRoots(isolate).self_reference_marker(),
                                 isolate);

  Assembler assm(AssemblerOptions{});

  Label start, target_away, target_faraway;

  __ stm(db_w, sp, {r4, r5, lr});

  // r3 is used as the address zero, the test will crash when we load it.
  __ mov(r3, Operand::Zero());

  // r5 will be a pointer to the start of the code.
  __ mov(r5, Operand(code_object));
  __ mov_label_offset(r4, &start);

  __ mov_label_offset(r1, &target_faraway);
  __ str(r1, MemOperand(sp, kPointerSize, NegPreIndex));

  __ mov_label_offset(r1, &target_away);

  // Jump straight to 'target_away' the first time and use the relative
  // position the second time. This covers the case when extracting the
  // position of a label which is linked.
  __ mov(r2, Operand::Zero());
  __ bind(&start);
  __ cmp(r2, Operand::Zero());
  __ b(eq, &target_away);
  __ add(pc, r5, r1);
  // Emit invalid instructions to push the label between 2^8 and 2^16
  // instructions away. The test will crash if they are reached.
  for (int i = 0; i < (1 << 10); i++) {
    __ ldr(r3, MemOperand(r3));
  }
  __ bind(&target_away);
  // This will be hit twice: r0 = r0 + 5 + 5.
  __ add(r0, r0, Operand(5));

  __ ldr(r1, MemOperand(sp, kPointerSize, PostIndex), ne);
  __ add(pc, r5, r4, LeaveCC, ne);

  __ mov(r2, Operand(1));
  __ b(&start);
  // Emit invalid instructions to push the label between 2^16 and 2^24
  // instructions away. The test will crash if they are reached.
  for (int i = 0; i < (1 << 21); i++) {
    __ ldr(r3, MemOperand(r3));
  }
  __ bind(&target_faraway);
  // r0 = r0 + 5 + 5 + 11
  __ add(r0, r0, Operand(11));

  __ ldm(ia_w, sp, {r4, r5, pc});

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code = Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING)
                          .set_self_reference(code_object)
                          .Build();
  auto f = GeneratedCode<F_iiiii>::FromCode(isolate, *code);
  int res = reinterpret_cast<int>(f.Call(21, 0, 0, 0, 0));
  ::printf("f() = %d\n", res);
  CHECK_EQ(42, res);
}

TEST(msr_mrs) {
  // Test msr and mrs.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});

  // Create a helper function:
  //  void TestMsrMrs(uint32_t nzcv,
  //                  uint32_t * result_conditionals,
  //                  uint32_t * result_mrs);
  __ msr(CPSR_f, Operand(r0));

  // Test that the condition flags have taken effect.
  __ mov(r3, Operand(0));
  __ orr(r3, r3, Operand(1 << 31), LeaveCC, mi);  // N
  __ orr(r3, r3, Operand(1 << 30), LeaveCC, eq);  // Z
  __ orr(r3, r3, Operand(1 << 29), LeaveCC, cs);  // C
  __ orr(r3, r3, Operand(1 << 28), LeaveCC, vs);  // V
  __ str(r3, MemOperand(r1));

  // Also check mrs, ignoring everything other than the flags.
  __ mrs(r3, CPSR);
  __ and_(r3, r3, Operand(kSpecialCondition));
  __ str(r3, MemOperand(r2));

  __ bx(lr);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  StdoutStream os;
  Print(*code, os);
#endif
  auto f = GeneratedCode<F_ippii>::FromCode(isolate, *code);

#define CHECK_MSR_MRS(n, z, c, v)                                  \
  do {                                                             \
    uint32_t nzcv = (n << 31) | (z << 30) | (c << 29) | (v << 28); \
    uint32_t result_conditionals = -1;                             \
    uint32_t result_mrs = -1;                                      \
    f.Call(nzcv, &result_conditionals, &result_mrs, 0, 0);         \
    CHECK_EQ(nzcv, result_conditionals);                           \
    CHECK_EQ(nzcv, result_mrs);                                    \
  } while (0);

  //            N  Z  C  V
  CHECK_MSR_MRS(0, 0, 0, 0);
  CHECK_MSR_MRS(0, 0, 0, 1);
  CHECK_MSR_MRS(0, 0, 1, 0);
  CHECK_MSR_MRS(0, 0, 1, 1);
  CHECK_MSR_MRS(0, 1, 0, 0);
  CHECK_MSR_MRS(0, 1, 0, 1);
  CHECK_MSR_MRS(0, 1, 1, 0);
  CHECK_MSR_MRS(0, 1, 1, 1);
  CHECK_MSR_MRS(1, 0, 0, 0);
  CHECK_MSR_MRS(1, 0, 0, 1);
  CHECK_MSR_MRS(1, 0, 1, 0);
  CHECK_MSR_MRS(1, 0, 1, 1);
  CHECK_MSR_MRS(1, 1, 0, 0);
  CHECK_MSR_MRS(1, 1, 0, 1);
  CHECK_MSR_MRS(1, 1, 1, 0);
  CHECK_MSR_MRS(1, 1, 1, 1);

#undef CHECK_MSR_MRS
}

TEST(ARMv8_float32_vrintX) {
  // Test the vrintX floating point instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    float input;
    float ar;
    float nr;
    float mr;
    float pr;
    float zr;
  };
  T t;

  // Create a function that accepts &t, and loads, manipulates, and stores
  // the floats.
  Assembler assm(AssemblerOptions{});


  if (CpuFeatures::IsSupported(ARMv8)) {
    CpuFeatureScope scope(&assm, ARMv8);

    __ mov(ip, Operand(sp));
    __ stm(db_w, sp, {r4, fp, lr});

    __ mov(r4, Operand(r0));

    // Test vrinta
    __ vldr(s6, r4, offsetof(T, input));
    __ vrinta(s5, s6);
    __ vstr(s5, r4, offsetof(T, ar));

    // Test vrintn
    __ vldr(s6, r4, offsetof(T, input));
    __ vrintn(s5, s6);
    __ vstr(s5, r4, offsetof(T, nr));

    // Test vrintp
    __ vldr(s6, r4, offsetof(T, input));
    __ vrintp(s5, s6);
    __ vstr(s5, r4, offsetof(T, pr));

    // Test vrintm
    __ vldr(s6, r4, offsetof(T, input));
    __ vrintm(s5, s6);
    __ vstr(s5, r4, offsetof(T, mr));

    // Test vrintz
    __ vldr(s6, r4, offsetof(T, input));
    __ vrintz(s5, s6);
    __ vstr(s5, r4, offsetof(T, zr));

    __ ldm(ia_w, sp, {r4, fp, pc});

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
    StdoutStream os;
    Print(*code, os);
#endif
    auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);

#define CHECK_VRINT(input_val, ares, nres, mres, pres, zres) \
  t.input = input_val;                                       \
  f.Call(&t, 0, 0, 0, 0);                                    \
  CHECK_EQ(ares, t.ar);                                      \
  CHECK_EQ(nres, t.nr);                                      \
  CHECK_EQ(mres, t.mr);                                      \
  CHECK_EQ(pres, t.pr);                                      \
  CHECK_EQ(zres, t.zr);

    CHECK_VRINT(-0.5, -1.0, -0.0, -1.0, -0.0, -0.0)
    CHECK_VRINT(-0.6, -1.0, -1.0, -1.0, -0.0, -0.0)
    CHECK_VRINT(-1.1, -1.0, -1.0, -2.0, -1.0, -1.0)
    CHECK_VRINT(0.5, 1.0, 0.0, 0.0, 1.0, 0.0)
    CHECK_VRINT(0.6, 1.0, 1.0, 0.0, 1.0, 0.0)
    CHECK_VRINT(1.1, 1.0, 1.0, 1.0, 2.0, 1.0)
    float inf = std::numeric_limits<float>::infinity();
    CHECK_VRINT(inf, inf, inf, inf, inf, inf)
    CHECK_VRINT(-inf, -inf, -inf, -inf, -inf, -inf)
    CHECK_VRINT(-0.0, -0.0, -0.0, -0.0, -0.0, -0.0)

    // Check NaN propagation.
    float nan = std::numeric_limits<float>::quiet_NaN();
    t.input = nan;
    f.Call(&t, 0, 0, 0, 0);
    CHECK_EQ(base::bit_cast<int32_t>(nan), base::bit_cast<int32_t>(t.ar));
    CHECK_EQ(base::bit_cast<int32_t>(nan), base::bit_cast<int32_t>(t.nr));
    CHECK_EQ(base::bit_cast<int32_t>(nan), base::bit_cast<int32_t>(t.mr));
    CHECK_EQ(base::bit_cast<int32_t>(nan), base::bit_cast<int32_t>(t.pr));
    CHECK_EQ(base::bit_cast<int32_t>(nan), base::bit_cast<int32_t>(t.zr));

#undef CHECK_VRINT
  }
}


TEST(ARMv8_vrintX) {
  // Test the vrintX floating point instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    double input;
    double ar;
    double nr;
    double mr;
    double pr;
    double zr;
  };
  T t;

  // Create a function that accepts &t, and loads, manipulates, and stores
  // the doubles and floats.
  Assembler assm(AssemblerOptions{});


  if (CpuFeatures::IsSupported(ARMv8)) {
    CpuFeatureScope scope(&assm, ARMv8);

    __ mov(ip, Operand(sp));
    __ stm(db_w, sp, {r4, fp, lr});

    __ mov(r4, Operand(r0));

    // Test vrinta
    __ vldr(d6, r4, offsetof(T, input));
    __ vrinta(d5, d6);
    __ vstr(d5, r4, offsetof(T, ar));

    // Test vrintn
    __ vldr(d6, r4, offsetof(T, input));
    __ vrintn(d5, d6);
    __ vstr(d5, r4, offsetof(T, nr));

    // Test vrintp
    __ vldr(d6, r4, offsetof(T, input));
    __ vrintp(d5, d6);
    __ vstr(d5, r4, offsetof(T, pr));

    // Test vrintm
    __ vldr(d6, r4, offsetof(T, input));
    __ vrintm(d5, d6);
    __ vstr(d5, r4, offsetof(T, mr));

    // Test vrintz
    __ vldr(d6, r4, offsetof(T, input));
    __ vrintz(d5, d6);
    __ vstr(d5, r4, offsetof(T, zr));

    __ ldm(ia_w, sp, {r4, fp, pc});

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
    StdoutStream os;
    Print(*code, os);
#endif
    auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);

#define CHECK_VRINT(input_val, ares, nres, mres, pres, zres) \
  t.input = input_val;                                       \
  f.Call(&t, 0, 0, 0, 0);                                    \
  CHECK_EQ(ares, t.ar);                                      \
  CHECK_EQ(nres, t.nr);                                      \
  CHECK_EQ(mres, t.mr);                                      \
  CHECK_EQ(pres, t.pr);                                      \
  CHECK_EQ(zres, t.zr);

    CHECK_VRINT(-0.5, -1.0, -0.0, -1.0, -0.0, -0.0)
    CHECK_VRINT(-0.6, -1.0, -1.0, -1.0, -0.0, -0.0)
    CHECK_VRINT(-1.1, -1.0, -1.0, -2.0, -1.0, -1.0)
    CHECK_VRINT(0.5, 1.0, 0.0, 0.0, 1.0, 0.0)
    CHECK_VRINT(0.6, 1.0, 1.0, 0.0, 1.0, 0.0)
    CHECK_VRINT(1.1, 1.0, 1.0, 1.0, 2.0, 1.0)
    double inf = std::numeric_limits<double>::infinity();
    CHECK_VRINT(inf, inf, inf, inf, inf, inf)
    CHECK_VRINT(-inf, -inf, -inf, -inf, -inf, -inf)
    CHECK_VRINT(-0.0, -0.0, -0.0, -0.0, -0.0, -0.0)

    // Check NaN propagation.
    double nan = std::numeric_limits<double>::quiet_NaN();
    t.input = nan;
    f.Call(&t, 0, 0, 0, 0);
    CHECK_EQ(base::bit_cast<int64_t>(nan), base::bit_cast<int64_t>(t.ar));
    CHECK_EQ(base::bit_cast<int64_t>(nan), base::bit_cast<int64_t>(t.nr));
    CHECK_EQ(base::bit_cast<int64_t>(nan), base::bit_cast<int64_t>(t.mr));
    CHECK_EQ(base::bit_cast<int64_t>(nan), base::bit_cast<int64_t>(t.pr));
    CHECK_EQ(base::bit_cast<int64_t>(nan), base::bit_cast<int64_t>(t.zr));

#undef CHECK_VRINT
  }
}

TEST(ARMv8_vsel) {
  // Test the vsel floating point instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});

  // Used to indicate whether a condition passed or failed.
  static constexpr float kResultPass = 1.0f;
  static constexpr float kResultFail = -kResultPass;

  struct ResultsF32 {
    float vseleq_;
    float vselge_;
    float vselgt_;
    float vselvs_;

    // The following conditions aren't architecturally supported, but the
    // assembler implements them by swapping the inputs.
    float vselne_;
    float vsellt_;
    float vselle_;
    float vselvc_;
  };

  struct ResultsF64 {
    double vseleq_;
    double vselge_;
    double vselgt_;
    double vselvs_;

    // The following conditions aren't architecturally supported, but the
    // assembler implements them by swapping the inputs.
    double vselne_;
    double vsellt_;
    double vselle_;
    double vselvc_;
  };

  if (CpuFeatures::IsSupported(ARMv8)) {
    CpuFeatureScope scope(&assm, ARMv8);

    // Create a helper function:
    //  void TestVsel(uint32_t nzcv,
    //                ResultsF32* results_f32,
    //                ResultsF64* results_f64);
    __ msr(CPSR_f, Operand(r0));

    __ vmov(s1, Float32(kResultPass));
    __ vmov(s2, Float32(kResultFail));

    __ vsel(eq, s0, s1, s2);
    __ vstr(s0, r1, offsetof(ResultsF32, vseleq_));
    __ vsel(ge, s0, s1, s2);
    __ vstr(s0, r1, offsetof(ResultsF32, vselge_));
    __ vsel(gt, s0, s1, s2);
    __ vstr(s0, r1, offsetof(ResultsF32, vselgt_));
    __ vsel(vs, s0, s1, s2);
    __ vstr(s0, r1, offsetof(ResultsF32, vselvs_));

    __ vsel(ne, s0, s1, s2);
    __ vstr(s0, r1, offsetof(ResultsF32, vselne_));
    __ vsel(lt, s0, s1, s2);
    __ vstr(s0, r1, offsetof(ResultsF32, vsellt_));
    __ vsel(le, s0, s1, s2);
    __ vstr(s0, r1, offsetof(ResultsF32, vselle_));
    __ vsel(vc, s0, s1, s2);
    __ vstr(s0, r1, offsetof(ResultsF32, vselvc_));

    __ vmov(d1, base::Double(kResultPass));
    __ vmov(d2, base::Double(kResultFail));

    __ vsel(eq, d0, d1, d2);
    __ vstr(d0, r2, offsetof(ResultsF64, vseleq_));
    __ vsel(ge, d0, d1, d2);
    __ vstr(d0, r2, offsetof(ResultsF64, vselge_));
    __ vsel(gt, d0, d1, d2);
    __ vstr(d0, r2, offsetof(ResultsF64, vselgt_));
    __ vsel(vs, d0, d1, d2);
    __ vstr(d0, r2, offsetof(ResultsF64, vselvs_));

    __ vsel(ne, d0, d1, d2);
    __ vstr(d0, r2, offsetof(ResultsF64, vselne_));
    __ vsel(lt, d0, d1, d2);
    __ vstr(d0, r2, offsetof(ResultsF64, vsellt_));
    __ vsel(le, d0, d1, d2);
    __ vstr(d0, r2, offsetof(ResultsF64, vselle_));
    __ vsel(vc, d0, d1, d2);
    __ vstr(d0, r2, offsetof(ResultsF64, vselvc_));

    __ bx(lr);

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
    StdoutStream os;
    Print(*code, os);
#endif
    auto f = GeneratedCode<F_ippii>::FromCode(isolate, *code);

    static_assert(kResultPass == -kResultFail);
#define CHECK_VSEL(n, z, c, v, vseleq, vselge, vselgt, vselvs)     \
  do {                                                             \
    ResultsF32 results_f32;                                        \
    ResultsF64 results_f64;                                        \
    uint32_t nzcv = (n << 31) | (z << 30) | (c << 29) | (v << 28); \
    f.Call(nzcv, &results_f32, &results_f64, 0, 0);                \
    CHECK_EQ(vseleq, results_f32.vseleq_);                         \
    CHECK_EQ(vselge, results_f32.vselge_);                         \
    CHECK_EQ(vselgt, results_f32.vselgt_);                         \
    CHECK_EQ(vselvs, results_f32.vselvs_);                         \
    CHECK_EQ(-vseleq, results_f32.vselne_);                        \
    CHECK_EQ(-vselge, results_f32.vsellt_);                        \
    CHECK_EQ(-vselgt, results_f32.vselle_);                        \
    CHECK_EQ(-vselvs, results_f32.vselvc_);                        \
    CHECK_EQ(vseleq, results_f64.vseleq_);                         \
    CHECK_EQ(vselge, results_f64.vselge_);                         \
    CHECK_EQ(vselgt, results_f64.vselgt_);                         \
    CHECK_EQ(vselvs, results_f64.vselvs_);                         \
    CHECK_EQ(-vseleq, results_f64.vselne_);                        \
    CHECK_EQ(-vselge, results_f64.vsellt_);                        \
    CHECK_EQ(-vselgt, results_f64.vselle_);                        \
    CHECK_EQ(-vselvs, results_f64.vselvc_);                        \
  } while (0);

    //         N  Z  C  V  vseleq       vselge       vselgt       vselvs
    CHECK_VSEL(0, 0, 0, 0, kResultFail, kResultPass, kResultPass, kResultFail);
    CHECK_VSEL(0, 0, 0, 1, kResultFail, kResultFail, kResultFail, kResultPass);
    CHECK_VSEL(0, 0, 1, 0, kResultFail, kResultPass, kResultPass, kResultFail);
    CHECK_VSEL(0, 0, 1, 1, kResultFail, kResultFail, kResultFail, kResultPass);
    CHECK_VSEL(0, 1, 0, 0, kResultPass, kResultPass, kResultFail, kResultFail);
    CHECK_VSEL(0, 1, 0, 1, kResultPass, kResultFail, kResultFail, kResultPass);
    CHECK_VSEL(0, 1, 1, 0, kResultPass, kResultPass, kResultFail, kResultFail);
    CHECK_VSEL(0, 1, 1, 1, kResultPass, kResultFail, kResultFail, kResultPass);
    CHECK_VSEL(1, 0, 0, 0, kResultFail, kResultFail, kResultFail, kResultFail);
    CHECK_VSEL(1, 0, 0, 1, kResultFail, kResultPass, kResultPass, kResultPass);
    CHECK_VSEL(1, 0, 1, 0, kResultFail, kResultFail, kResultFail, kResultFail);
    CHECK_VSEL(1, 0, 1, 1, kResultFail, kResultPass, kResultPass, kResultPass);
    CHECK_VSEL(1, 1, 0, 0, kResultPass, kResultFail, kResultFail, kResultFail);
    CHECK_VSEL(1, 1, 0, 1, kResultPass, kResultPass, kResultFail, kResultPass);
    CHECK_VSEL(1, 1, 1, 0, kResultPass, kResultFail, kResultFail, kResultFail);
    CHECK_VSEL(1, 1, 1, 1, kResultPass, kResultPass, kResultFail, kResultPass);

#undef CHECK_VSEL
  }
}

TEST(ARMv8_vminmax_f64) {
  // Test the vminnm and vmaxnm floating point instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});

  struct Inputs {
    double left_;
    double right_;
  };

  struct Results {
    double vminnm_;
    double vmaxnm_;
  };

  if (CpuFeatures::IsSupported(ARMv8)) {
    CpuFeatureScope scope(&assm, ARMv8);

    // Create a helper function:
    //  void TestVminmax(const Inputs* inputs,
    //                   Results* results);
    __ vldr(d1, r0, offsetof(Inputs, left_));
    __ vldr(d2, r0, offsetof(Inputs, right_));

    __ vminnm(d0, d1, d2);
    __ vstr(d0, r1, offsetof(Results, vminnm_));
    __ vmaxnm(d0, d1, d2);
    __ vstr(d0, r1, offsetof(Results, vmaxnm_));

    __ bx(lr);

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
    StdoutStream os;
    Print(*code, os);
#endif
    auto f = GeneratedCode<F_ppiii>::FromCode(isolate, *code);

#define CHECK_VMINMAX(left, right, vminnm, vmaxnm)                  \
  do {                                                              \
    Inputs inputs = {left, right};                                  \
    Results results;                                                \
    f.Call(&inputs, &results, 0, 0, 0);                             \
    /* Use a base::bit_cast to correctly identify -0.0 and NaNs. */ \
    CHECK_EQ(base::bit_cast<uint64_t>(vminnm),                      \
             base::bit_cast<uint64_t>(results.vminnm_));            \
    CHECK_EQ(base::bit_cast<uint64_t>(vmaxnm),                      \
             base::bit_cast<uint64_t>(results.vmaxnm_));            \
  } while (0);

    double nan_a = base::bit_cast<double>(UINT64_C(0x7FF8000000000001));
    double nan_b = base::bit_cast<double>(UINT64_C(0x7FF8000000000002));

    CHECK_VMINMAX(1.0, -1.0, -1.0, 1.0);
    CHECK_VMINMAX(-1.0, 1.0, -1.0, 1.0);
    CHECK_VMINMAX(0.0, -1.0, -1.0, 0.0);
    CHECK_VMINMAX(-1.0, 0.0, -1.0, 0.0);
    CHECK_VMINMAX(-0.0, -1.0, -1.0, -0.0);
    CHECK_VMINMAX(-1.0, -0.0, -1.0, -0.0);
    CHECK_VMINMAX(0.0, 1.0, 0.0, 1.0);
    CHECK_VMINMAX(1.0, 0.0, 0.0, 1.0);

    CHECK_VMINMAX(0.0, 0.0, 0.0, 0.0);
    CHECK_VMINMAX(-0.0, -0.0, -0.0, -0.0);
    CHECK_VMINMAX(-0.0, 0.0, -0.0, 0.0);
    CHECK_VMINMAX(0.0, -0.0, -0.0, 0.0);

    CHECK_VMINMAX(0.0, nan_a, 0.0, 0.0);
    CHECK_VMINMAX(nan_a, 0.0, 0.0, 0.0);
    CHECK_VMINMAX(nan_a, nan_b, nan_a, nan_a);
    CHECK_VMINMAX(nan_b, nan_a, nan_b, nan_b);

#undef CHECK_VMINMAX
  }
}

TEST(ARMv8_vminmax_f32) {
  // Test the vminnm and vmaxnm floating point instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});

  struct Inputs {
    float left_;
    float right_;
  };

  struct Results {
    float vminnm_;
    float vmaxnm_;
  };

  if (CpuFeatures::IsSupported(ARMv8)) {
    CpuFeatureScope scope(&assm, ARMv8);

    // Create a helper function:
    //  void TestVminmax(const Inputs* inputs,
    //                   Results* results);
    __ vldr(s1, r0, offsetof(Inputs, left_));
    __ vldr(s2, r0, offsetof(Inputs, right_));

    __ vminnm(s0, s1, s2);
    __ vstr(s0, r1, offsetof(Results, vminnm_));
    __ vmaxnm(s0, s1, s2);
    __ vstr(s0, r1, offsetof(Results, vmaxnm_));

    __ bx(lr);

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
    StdoutStream os;
    Print(*code, os);
#endif
    auto f = GeneratedCode<F_ppiii>::FromCode(isolate, *code);

#define CHECK_VMINMAX(left, right, vminnm, vmaxnm)                  \
  do {                                                              \
    Inputs inputs = {left, right};                                  \
    Results results;                                                \
    f.Call(&inputs, &results, 0, 0, 0);                             \
    /* Use a base::bit_cast to correctly identify -0.0 and NaNs. */ \
    CHECK_EQ(base::bit_cast<uint32_t>(vminnm),                      \
             base::bit_cast<uint32_t>(results.vminnm_));            \
    CHECK_EQ(base::bit_cast<uint32_t>(vmaxnm),                      \
             base::bit_cast<uint32_t>(results.vmaxnm_));            \
  } while (0);

    float nan_a = base::bit_cast<float>(UINT32_C(0x7FC00001));
    float nan_b = base::bit_cast<float>(UINT32_C(0x7FC00002));

    CHECK_VMINMAX(1.0f, -1.0f, -1.0f, 1.0f);
    CHECK_VMINMAX(-1.0f, 1.0f, -1.0f, 1.0f);
    CHECK_VMINMAX(0.0f, -1.0f, -1.0f, 0.0f);
    CHECK_VMINMAX(-1.0f, 0.0f, -1.0f, 0.0f);
    CHECK_VMINMAX(-0.0f, -1.0f, -1.0f, -0.0f);
    CHECK_VMINMAX(-1.0f, -0.0f, -1.0f, -0.0f);
    CHECK_VMINMAX(0.0f, 1.0f, 0.0f, 1.0f);
    CHECK_VMINMAX(1.0f, 0.0f, 0.0f, 1.0f);

    CHECK_VMINMAX(0.0f, 0.0f, 0.0f, 0.0f);
    CHECK_VMINMAX(-0.0f, -0.0f, -0.0f, -0.0f);
    CHECK_VMINMAX(-0.0f, 0.0f, -0.0f, 0.0f);
    CHECK_VMINMAX(0.0f, -0.0f, -0.0f, 0.0f);

    CHECK_VMINMAX(0.0f, nan_a, 0.0f, 0.0f);
    CHECK_VMINMAX(nan_a, 0.0f, 0.0f, 0.0f);
    CHECK_VMINMAX(nan_a, nan_b, nan_a, nan_a);
    CHECK_VMINMAX(nan_b, nan_a, nan_b, nan_b);

#undef CHECK_VMINMAX
  }
}

template <typename T, typename Inputs, typename Results>
static GeneratedCode<F_ppiii> GenerateMacroFloatMinMax(
    MacroAssembler* assm_ptr) {
  MacroAssembler& assm = *assm_ptr;

  T a = T::from_code(0);  // d0/s0
  T b = T::from_code(1);  // d1/s1
  T c = T::from_code(2);  // d2/s2

  // Create a helper function:
  //  void TestFloatMinMax(const Inputs* inputs,
  //                       Results* results);
  Label ool_min_abc, ool_min_aab, ool_min_aba;
  Label ool_max_abc, ool_max_aab, ool_max_aba;

  Label done_min_abc, done_min_aab, done_min_aba;
  Label done_max_abc, done_max_aab, done_max_aba;

  // a = min(b, c);
  __ vldr(b, r0, offsetof(Inputs, left_));
  __ vldr(c, r0, offsetof(Inputs, right_));
  __ FloatMin(a, b, c, &ool_min_abc);
  __ bind(&done_min_abc);
  __ vstr(a, r1, offsetof(Results, min_abc_));

  // a = min(a, b);
  __ vldr(a, r0, offsetof(Inputs, left_));
  __ vldr(b, r0, offsetof(Inputs, right_));
  __ FloatMin(a, a, b, &ool_min_aab);
  __ bind(&done_min_aab);
  __ vstr(a, r1, offsetof(Results, min_aab_));

  // a = min(b, a);
  __ vldr(b, r0, offsetof(Inputs, left_));
  __ vldr(a, r0, offsetof(Inputs, right_));
  __ FloatMin(a, b, a, &ool_min_aba);
  __ bind(&done_min_aba);
  __ vstr(a, r1, offsetof(Results, min_aba_));

  // a = max(b, c);
  __ vldr(b, r0, offsetof(Inputs, left_));
  __ vldr(c, r0, offsetof(Inputs, right_));
  __ FloatMax(a, b, c, &ool_max_abc);
  __ bind(&done_max_abc);
  __ vstr(a, r1, offsetof(Results, max_abc_));

  // a = max(a, b);
  __ vldr(a, r0, offsetof(Inputs, left_));
  __ vldr(b, r0, offsetof(Inputs, right_));
  __ FloatMax(a, a, b, &ool_max_aab);
  __ bind(&done_max_aab);
  __ vstr(a, r1, offsetof(Results, max_aab_));

  // a = max(b, a);
  __ vldr(b, r0, offsetof(Inputs, left_));
  __ vldr(a, r0, offsetof(Inputs, right_));
  __ FloatMax(a, b, a, &ool_max_aba);
  __ bind(&done_max_aba);
  __ vstr(a, r1, offsetof(Results, max_aba_));

  __ bx(lr);

  // Generate out-of-line cases.
  __ bind(&ool_min_abc);
  __ FloatMinOutOfLine(a, b, c);
  __ b(&done_min_abc);

  __ bind(&ool_min_aab);
  __ FloatMinOutOfLine(a, a, b);
  __ b(&done_min_aab);

  __ bind(&ool_min_aba);
  __ FloatMinOutOfLine(a, b, a);
  __ b(&done_min_aba);

  __ bind(&ool_max_abc);
  __ FloatMaxOutOfLine(a, b, c);
  __ b(&done_max_abc);

  __ bind(&ool_max_aab);
  __ FloatMaxOutOfLine(a, a, b);
  __ b(&done_max_aab);

  __ bind(&ool_max_aba);
  __ FloatMaxOutOfLine(a, b, a);
  __ b(&done_max_aba);

  CodeDesc desc;
  assm.GetCode(assm.isolate(), &desc);
  Handle<Code> code =
      Factory::CodeBuilder(assm.isolate(), desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  StdoutStream os;
  Print(*code, os);
#endif
  return GeneratedCode<F_ppiii>::FromCode(assm.isolate(), *code);
}

TEST(macro_float_minmax_f64) {
  // Test the FloatMin and FloatMax macros.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, CodeObjectRequired::kYes);

  struct Inputs {
    double left_;
    double right_;
  };

  struct Results {
    // Check all register aliasing possibilities in order to exercise all
    // code-paths in the macro assembler.
    double min_abc_;
    double min_aab_;
    double min_aba_;
    double max_abc_;
    double max_aab_;
    double max_aba_;
  };

  auto f = GenerateMacroFloatMinMax<DwVfpRegister, Inputs, Results>(&assm);

#define CHECK_MINMAX(left, right, min, max)                         \
  do {                                                              \
    Inputs inputs = {left, right};                                  \
    Results results;                                                \
    f.Call(&inputs, &results, 0, 0, 0);                             \
    /* Use a base::bit_cast to correctly identify -0.0 and NaNs. */ \
    CHECK_EQ(base::bit_cast<uint64_t>(min),                         \
             base::bit_cast<uint64_t>(results.min_abc_));           \
    CHECK_EQ(base::bit_cast<uint64_t>(min),                         \
             base::bit_cast<uint64_t>(results.min_aab_));           \
    CHECK_EQ(base::bit_cast<uint64_t>(min),                         \
             base::bit_cast<uint64_t>(results.min_aba_));           \
    CHECK_EQ(base::bit_cast<uint64_t>(max),                         \
             base::bit_cast<uint64_t>(results.max_abc_));           \
    CHECK_EQ(base::bit_cast<uint64_t>(max),                         \
             base::bit_cast<uint64_t>(results.max_aab_));           \
    CHECK_EQ(base::bit_cast<uint64_t>(max),                         \
             base::bit_cast<uint64_t>(results.max_aba_));           \
  } while (0)

  double nan_a = base::bit_cast<double>(UINT64_C(0x7FF8000000000001));
  double nan_b = base::bit_cast<double>(UINT64_C(0x7FF8000000000002));

  CHECK_MINMAX(1.0, -1.0, -1.0, 1.0);
  CHECK_MINMAX(-1.0, 1.0, -1.0, 1.0);
  CHECK_MINMAX(0.0, -1.0, -1.0, 0.0);
  CHECK_MINMAX(-1.0, 0.0, -1.0, 0.0);
  CHECK_MINMAX(-0.0, -1.0, -1.0, -0.0);
  CHECK_MINMAX(-1.0, -0.0, -1.0, -0.0);
  CHECK_MINMAX(0.0, 1.0, 0.0, 1.0);
  CHECK_MINMAX(1.0, 0.0, 0.0, 1.0);

  CHECK_MINMAX(0.0, 0.0, 0.0, 0.0);
  CHECK_MINMAX(-0.0, -0.0, -0.0, -0.0);
  CHECK_MINMAX(-0.0, 0.0, -0.0, 0.0);
  CHECK_MINMAX(0.0, -0.0, -0.0, 0.0);

  CHECK_MINMAX(0.0, nan_a, nan_a, nan_a);
  CHECK_MINMAX(nan_a, 0.0, nan_a, nan_a);
  CHECK_MINMAX(nan_a, nan_b, nan_a, nan_a);
  CHECK_MINMAX(nan_b, nan_a, nan_b, nan_b);

#undef CHECK_MINMAX
}

TEST(macro_float_minmax_f32) {
  // Test the FloatMin and FloatMax macros.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, CodeObjectRequired::kYes);

  struct Inputs {
    float left_;
    float right_;
  };

  struct Results {
    // Check all register aliasing possibilities in order to exercise all
    // code-paths in the macro assembler.
    float min_abc_;
    float min_aab_;
    float min_aba_;
    float max_abc_;
    float max_aab_;
    float max_aba_;
  };

  auto f = GenerateMacroFloatMinMax<SwVfpRegister, Inputs, Results>(&assm);

#define CHECK_MINMAX(left, right, min, max)                         \
  do {                                                              \
    Inputs inputs = {left, right};                                  \
    Results results;                                                \
    f.Call(&inputs, &results, 0, 0, 0);                             \
    /* Use a base::bit_cast to correctly identify -0.0 and NaNs. */ \
    CHECK_EQ(base::bit_cast<uint32_t>(min),                         \
             base::bit_cast<uint32_t>(results.min_abc_));           \
    CHECK_EQ(base::bit_cast<uint32_t>(min),                         \
             base::bit_cast<uint32_t>(results.min_aab_));           \
    CHECK_EQ(base::bit_cast<uint32_t>(min),                         \
             base::bit_cast<uint32_t>(results.min_aba_));           \
    CHECK_EQ(base::bit_cast<uint32_t>(max),                         \
             base::bit_cast<uint32_t>(results.max_abc_));           \
    CHECK_EQ(base::bit_cast<uint32_t>(max),                         \
             base::bit_cast<uint32_t>(results.max_aab_));           \
    CHECK_EQ(base::bit_cast<uint32_t>(max),                         \
             base::bit_cast<uint32_t>(results.max_aba_));           \
  } while (0)

  float nan_a = base::bit_cast<float>(UINT32_C(0x7FC00001));
  float nan_b = base::bit_cast<float>(UINT32_C(0x7FC00002));

  CHECK_MINMAX(1.0f, -1.0f, -1.0f, 1.0f);
  CHECK_MINMAX(-1.0f, 1.0f, -1.0f, 1.0f);
  CHECK_MINMAX(0.0f, -1.0f, -1.0f, 0.0f);
  CHECK_MINMAX(-1.0f, 0.0f, -1.0f, 0.0f);
  CHECK_MINMAX(-0.0f, -1.0f, -1.0f, -0.0f);
  CHECK_MINMAX(-1.0f, -0.0f, -1.0f, -0.0f);
  CHECK_MINMAX(0.0f, 1.0f, 0.0f, 1.0f);
  CHECK_MINMAX(1.0f, 0.0f, 0.0f, 1.0f);

  CHECK_MINMAX(0.0f, 0.0f, 0.0f, 0.0f);
  CHECK_MINMAX(-0.0f, -0.0f, -0.0f, -0.0f);
  CHECK_MINMAX(-0.0f, 0.0f, -0.0f, 0.0f);
  CHECK_MINMAX(0.0f, -0.0f, -0.0f, 0.0f);

  CHECK_MINMAX(0.0f, nan_a, nan_a, nan_a);
  CHECK_MINMAX(nan_a, 0.0f, nan_a, nan_a);
  CHECK_MINMAX(nan_a, nan_b, nan_a, nan_a);
  CHECK_MINMAX(nan_b, nan_a, nan_b, nan_b);

#undef CHECK_MINMAX
}

TEST(unaligned_loads) {
  // All supported ARM targets allow unaligned accesses.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    uint32_t ldrh;
    uint32_t ldrsh;
    uint32_t ldr;
  };
  T t;

  Assembler assm(AssemblerOptions{});
  __ ldrh(ip, MemOperand(r1, r2));
  __ str(ip, MemOperand(r0, offsetof(T, ldrh)));
  __ ldrsh(ip, MemOperand(r1, r2));
  __ str(ip, MemOperand(r0, offsetof(T, ldrsh)));
  __ ldr(ip, MemOperand(r1, r2));
  __ str(ip, MemOperand(r0, offsetof(T, ldr)));
  __ bx(lr);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  StdoutStream os;
  Print(*code, os);
#endif
  auto f = GeneratedCode<F_ppiii>::FromCode(isolate, *code);

#ifndef V8_TARGET_LITTLE_ENDIAN
#error This test assumes a little-endian layout.
#endif
  uint64_t data = UINT64_C(0x84838281807F7E7D);
  f.Call(&t, &data, 0, 0, 0);
  CHECK_EQ(0x00007E7Du, t.ldrh);
  CHECK_EQ(0x00007E7Du, t.ldrsh);
  CHECK_EQ(0x807F7E7Du, t.ldr);
  f.Call(&t, &data, 1, 0, 0);
  CHECK_EQ(0x00007F7Eu, t.ldrh);
  CHECK_EQ(0x00007F7Eu, t.ldrsh);
  CHECK_EQ(0x81807F7Eu, t.ldr);
  f.Call(&t, &data, 2, 0, 0);
  CHECK_EQ(0x0000807Fu, t.ldrh);
  CHECK_EQ(0xFFFF807Fu, t.ldrsh);
  CHECK_EQ(0x8281807Fu, t.ldr);
  f.Call(&t, &data, 3, 0, 0);
  CHECK_EQ(0x00008180u, t.ldrh);
  CHECK_EQ(0xFFFF8180u, t.ldrsh);
  CHECK_EQ(0x83828180u, t.ldr);
}

TEST(unaligned_stores) {
  // All supported ARM targets allow unaligned accesses.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});
  __ strh(r3, MemOperand(r0, r2));
  __ str(r3, MemOperand(r1, r2));
  __ bx(lr);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  StdoutStream os;
  Print(*code, os);
#endif
  auto f = GeneratedCode<F_ppiii>::FromCode(isolate, *code);

#ifndef V8_TARGET_LITTLE_ENDIAN
#error This test assumes a little-endian layout.
#endif
  {
    uint64_t strh = 0;
    uint64_t str = 0;
    f.Call(&strh, &str, 0, 0xFEDCBA98, 0);
    CHECK_EQ(UINT64_C(0x000000000000BA98), strh);
    CHECK_EQ(UINT64_C(0x00000000FEDCBA98), str);
  }
  {
    uint64_t strh = 0;
    uint64_t str = 0;
    f.Call(&strh, &str, 1, 0xFEDCBA98, 0);
    CHECK_EQ(UINT64_C(0x0000000000BA9800), strh);
    CHECK_EQ(UINT64_C(0x000000FEDCBA9800), str);
  }
  {
    uint64_t strh = 0;
    uint64_t str = 0;
    f.Call(&strh, &str, 2, 0xFEDCBA98, 0);
    CHECK_EQ(UINT64_C(0x00000000BA980000), strh);
    CHECK_EQ(UINT64_C(0x0000FEDCBA980000), str);
  }
  {
    uint64_t strh = 0;
    uint64_t str = 0;
    f.Call(&strh, &str, 3, 0xFEDCBA98, 0);
    CHECK_EQ(UINT64_C(0x000000BA98000000), strh);
    CHECK_EQ(UINT64_C(0x00FEDCBA98000000), str);
  }
}

TEST(vswp) {
  if (!CpuFeatures::IsSupported(NEON)) return;

  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  Assembler assm(AssemblerOptions{});

  struct T {
    uint64_t vswp_d0;
    uint64_t vswp_d1;
    uint64_t vswp_d30;
    uint64_t vswp_d31;
    uint32_t vswp_q4[4];
    uint32_t vswp_q5[4];
  };
  T t;

  __ stm(db_w, sp, {r4, r5, r6, r7, lr});

  uint64_t one = base::bit_cast<uint64_t>(1.0);
  __ mov(r5, Operand(one >> 32));
  __ mov(r4, Operand(one & 0xFFFFFFFF));
  uint64_t minus_one = base::bit_cast<uint64_t>(-1.0);
  __ mov(r7, Operand(minus_one >> 32));
  __ mov(r6, Operand(minus_one & 0xFFFFFFFF));

  __ vmov(d0, r4, r5);  // d0 = 1.0
  __ vmov(d1, r6, r7);  // d1 = -1.0
  __ vswp(d0, d1);
  __ vstr(d0, r0, offsetof(T, vswp_d0));
  __ vstr(d1, r0, offsetof(T, vswp_d1));

  if (CpuFeatures::IsSupported(VFP32DREGS)) {
    __ vmov(d30, r4, r5);  // d30 = 1.0
    __ vmov(d31, r6, r7);  // d31 = -1.0
    __ vswp(d30, d31);
    __ vstr(d30, r0, offsetof(T, vswp_d30));
    __ vstr(d31, r0, offsetof(T, vswp_d31));
  }

  // q-register swap.
  const uint32_t test_1 = 0x01234567;
  const uint32_t test_2 = 0x89ABCDEF;
  __ mov(r4, Operand(test_1));
  __ mov(r5, Operand(test_2));
  __ vdup(Neon32, q4, r4);
  __ vdup(Neon32, q5, r5);
  __ vswp(q4, q5);
  __ add(r6, r0, Operand(static_cast<int32_t>(offsetof(T, vswp_q4))));
  __ vst1(Neon8, NeonListOperand(q4), NeonMemOperand(r6));
  __ add(r6, r0, Operand(static_cast<int32_t>(offsetof(T, vswp_q5))));
  __ vst1(Neon8, NeonLis
```