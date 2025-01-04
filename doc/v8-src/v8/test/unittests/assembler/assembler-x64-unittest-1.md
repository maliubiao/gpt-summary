Response: The user has provided a C++ source code file containing unit tests for the x64 assembler in the V8 JavaScript engine. This is the second part of a two-part file.

My goal is to:
1. **Summarize the functionality of this specific part of the file.** This involves analyzing the test cases defined in the code.
2. **Identify any connections to JavaScript functionality.** Since this is testing the assembler, the connection will be in how these assembler instructions are used to implement JavaScript features.
3. **Provide JavaScript examples** to illustrate the connection, if any.

Let's break down the code section by section:

* **`AssemblerX64Test, AssemblerX64Rorx`**: Tests the `rorxq` and `rorxl` instructions, which perform bitwise rotation to the right. This is a low-level operation.
* **`AssemblerX64Test, AssemblerX64JumpTables1` and `AssemblerX64Test, AssemblerX64JumpTables2`**: Tests jump tables, which are used for efficient branching based on an index. This is a common technique in compilers and interpreters.
* **`AssemblerX64Test, AssemblerX64PslldWithXmm15`**: Tests the `pslld` instruction for shifting bits in an XMM register. XMM registers are used for SIMD (Single Instruction, Multiple Data) operations, often for floating-point or vector processing.
* **`AssemblerX64Test, AssemblerX64vmovups`**: Tests the `vmovups` instruction for moving unaligned packed single-precision floating-point values. This is related to handling floating-point arrays or SIMD operations on floats.
* **`AssemblerX64Test, AssemblerX64Regmove256bit`**: Tests various `vmov` instructions for moving 256-bit data between registers and memory. These instructions are part of the AVX (Advanced Vector Extensions) instruction set, used for high-performance SIMD operations.
* **`AssemblerX64Test, AssemblerX64AVX2Op256bit`**: Tests various AVX2 instructions for 256-bit operations, including shuffling, blending, and broadcasting. AVX2 extends AVX with more integer and bit manipulation instructions.
* **`AssemblerX64Test, AssemblerX64FloatingPoint256bit`**: Tests various AVX floating-point instructions for 256-bit operations, such as arithmetic, rounding, comparisons, and conversions.
* **`AssemblerX64Test, AssemblerX64Integer256bit`**: Tests various AVX integer instructions for 256-bit operations, including packing, comparison, logical operations, and arithmetic.
* **`AssemblerX64Test, AssemblerX64CmpOperations256bit`**: Tests AVX comparison instructions for 256-bit floating-point and integer data.
* **`AssemblerX64Test, AssemblerX64FMA256bit`**: Tests FMA (Fused Multiply-Add) instructions for 256-bit floating-point operations. FMA combines multiplication and addition into a single instruction for improved performance and precision.
* **`AssemblerX64Test, AssemblerX64ShiftImm128bit`**: Tests immediate shift instructions for 128-bit XMM registers.
* **`AssemblerX64Test, AssemblerX64ShiftImm256bit`**: Tests immediate shift instructions for 256-bit YMM registers (AVX).
* **`AssemblerX64Test, AssemblerX64BinOp256bit`**: Tests basic arithmetic operations (add, subtract, multiply, divide) and integer operations for 256-bit registers (AVX and AVX2).
* **`AssemblerX64Test, F16C`**: Tests F16C (Half-Precision Conversion) instructions for converting between single-precision and half-precision floating-point numbers.
* **`AssemblerX64Test, AssemblerX64AVXVNNI`**: Tests AVX-VNNI (Vector Neural Network Instructions) for performing vector dot products, which are crucial for deep learning inference.
* **`AssemblerX64Test, AssemblerX64AVXVNNIINT8`**: Tests AVX-VNNI-INT8 instructions, a variant of VNNI optimized for 8-bit integer data, also for deep learning.
* **`AssemblerX64Test, CpuFeatures_ProbeImpl`**: Tests the logic for detecting CPU feature support. This isn't directly testing an assembler instruction but rather the mechanism V8 uses to determine which instructions are available.

Now, let's consider the JavaScript connection:

* **Bitwise operations**: JavaScript has bitwise operators (`<<`, `>>`, `>>>`, `&`, `|`, `^`, `~`). The `rorxq` test relates to how these operators might be implemented at a lower level.
* **Control flow**: Jump tables are a fundamental way to implement control flow structures in JavaScript like `switch` statements or even optimized `if-else` chains.
* **SIMD.js**: The tests involving XMM and YMM registers directly relate to the SIMD.js API, which allows JavaScript code to perform parallel operations on vectors of numbers.
* **Typed Arrays and Array Buffers**: Operations on XMM and YMM registers are often used when processing data from Typed Arrays (like `Float32Array`, `Int32Array`, etc.), which provide a way to work with raw binary data in JavaScript.
* **Floating-point arithmetic**:  The floating-point tests cover the low-level implementations of JavaScript's number type and its associated arithmetic operations.
* **Deep Learning/Machine Learning**: The AVX-VNNI tests directly relate to the growing use of JavaScript in machine learning, particularly for on-device inference in browsers or Node.js.

Let's create some JavaScript examples.
```cpp
  __ rorxq(r8, rcx, 0x4);
    __ movq(r9, uint64_t{0x8112233445566778});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ rorxq(r8, Operand(rsp, 0), 0x4);
    __ movq(r9, uint64_t{0x8112233445566778});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ rorxl(r8, rcx, 0x4);
    __ movq(r9, uint64_t{0x0000000085566778});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ rorxl(r8, Operand(rsp, 0), 0x4);
    __ movq(r9, uint64_t{0x0000000085566778});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ xorl(rax, rax);
    __ bind(&exit);
    __ popq(rcx);
    __ popq(rbx);
    __ ret(0);
  }

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  StdoutStream os;
  Print(*code, os);
#endif

  auto f = GeneratedCode<F0>::FromCode(isolate, *code);
  CHECK_EQ(0, f.Call());
}

TEST_F(AssemblerX64Test, AssemblerX64JumpTables1) {
  // Test jump tables with forward jumps.

  Isolate* isolate = i_isolate();
  HandleScope scope(isolate);
  MacroAssembler masm(isolate, v8::internal::CodeObjectRequired::kYes);

  const int kNumCases = 512;
  int values[kNumCases];
  isolate->random_number_generator()->NextBytes(values, sizeof(values));
  Label labels[kNumCases];

  Label done, table;
  __ leaq(arg2, Operand(&table));
  __ jmp(Operand(arg2, arg1, times_8, 0));
  __ ud2();
  __ bind(&table);
  for (int i = 0; i < kNumCases; ++i) {
    __ dq(&labels[i]);
  }

  for (int i = 0; i < kNumCases; ++i) {
    __ bind(&labels[i]);
    __ movq(rax, Immediate(values[i]));
    __ jmp(&done);
  }

  __ bind(&done);
  __ ret(0);

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code, std::cout);
#endif

  auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  for (int i = 0; i < kNumCases; ++i) {
    int res = f.Call(i);
    PrintF("f(%d) = %d\n", i, res);
    CHECK_EQ(values[i], res);
  }
}

TEST_F(AssemblerX64Test, AssemblerX64JumpTables2) {
  // Test jump tables with backwards jumps.

  Isolate* isolate = i_isolate();
  HandleScope scope(isolate);
  MacroAssembler masm(isolate, v8::internal::CodeObjectRequired::kYes);

  const int kNumCases = 512;
  int values[kNumCases];
  isolate->random_number_generator()->NextBytes(values, sizeof(values));
  Label labels[kNumCases];

  Label done, table;
  __ leaq(arg2, Operand(&table));
  __ jmp(Operand(arg2, arg1, times_8, 0));
  __ ud2();

  for (int i = 0; i < kNumCases; ++i) {
    __ bind(&labels[i]);
    __ movq(rax, Immediate(values[i]));
    __ jmp(&done);
  }

  __ bind(&done);
  __ ret(0);

  __ bind(&table);
  for (int i = 0; i < kNumCases; ++i) {
    __ dq(&labels[i]);
  }

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code, std::cout);
#endif

  auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  for (int i = 0; i < kNumCases; ++i) {
    int res = f.Call(i);
    PrintF("f(%d) = %d\n", i, res);
    CHECK_EQ(values[i], res);
  }
}

TEST_F(AssemblerX64Test, AssemblerX64PslldWithXmm15) {
  auto buffer = AllocateAssemblerBuffer();
  Assembler masm(AssemblerOptions{}, buffer->CreateView());

  __ movq(xmm15, arg1);
  __ pslld(xmm15, 1);
  __ movq(rax, xmm15);
  __ ret(0);

  CodeDesc desc;
  masm.GetCode(i_isolate(), &desc);
  buffer->MakeExecutable();
  auto f = GeneratedCode<F5>::FromBuffer(i_isolate(), buffer->start());
  uint64_t result = f.Call(uint64_t{0x1122334455667788});
  CHECK_EQ(uint64_t{0x22446688AACCEF10}, result);
}

using F9 = float(float x, float y);
TEST_F(AssemblerX64Test, AssemblerX64vmovups) {
  if (!CpuFeatures::IsSupported(AVX)) return;

  Isolate* isolate = i_isolate();
  HandleScope scope(isolate);
  uint8_t buffer[256];
  MacroAssembler masm(isolate, v8::internal::CodeObjectRequired::kYes,
                      ExternalAssemblerBuffer(buffer, sizeof(buffer)));
  {
    CpuFeatureScope avx_scope(&masm, AVX);
    __ shufps(xmm0, xmm0, 0x0);  // brocast first argument
    __ shufps(xmm1, xmm1, 0x0);  // brocast second argument
    // copy xmm1 to xmm0 through the stack to test the "vmovups reg, mem".
    __ AllocateStackSpace(kSimd128Size);
    __ vmovups(Operand(rsp, 0), xmm1);
    __ vmovups(xmm0, Operand(rsp, 0));
    __ addq(rsp, Immediate(kSimd128Size));

    __ ret(0);
  }

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  StdoutStream os;
  Print(*code, os);
#endif

  auto f = GeneratedCode<F9>::FromCode(isolate, *code);
  CHECK_EQ(-1.5, f.Call(1.5, -1.5));
}

TEST_F(AssemblerX64Test, AssemblerX64Regmove256bit) {
  if (!CpuFeatures::IsSupported(AVX)) return;

  auto buffer = AllocateAssemblerBuffer();
  Isolate* isolate = i_isolate();
  Assembler masm(AssemblerOptions{}, buffer->CreateView());
  CpuFeatureScope fscope(&masm, AVX);

  __ vmovdqa(ymm0, ymm1);
  __ vmovdqa(ymm4, Operand(rbx, rcx, times_4, 10000));
  __ vmovdqu(ymm10, ymm11);
  __ vmovdqu(ymm9, Operand(rbx, rcx, times_4, 10000));
  __ vmovdqu(Operand(rbx, rcx, times_4, 10000), ymm0);
  __ vmovaps(ymm3, ymm1);
  __ vmovups(Operand(rcx, rdx, times_4, 10000), ymm2);
  __ vmovapd(ymm0, ymm5);
  __ vmovupd(ymm6, Operand(r8, r9, times_4, 10000));
  __ vbroadcastss(ymm7, Operand(rbx, rcx, times_4, 10000));
  __ vbroadcastsd(ymm6, Operand(rbx, rcx, times_4, 10000));
  __ vmovddup(ymm3, ymm2);
  __ vmovddup(ymm4, Operand(rbx, rcx, times_4, 10000));
  __ vmovshdup(ymm1, ymm2);

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
#ifdef OBJECT_PRINT
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  StdoutStream os;
  Print(*code, os);
#endif

  uint8_t expected[] = {
      // VMOVDQA
      // vmovdqa ymm0,ymm1
      0xC5, 0xFD, 0x6F, 0xC1,
      // vmovdqa ymm4,YMMWORD PTR [rbx+rcx*4+0x2710]
      0xC5, 0xFD, 0x6F, 0xA4, 0x8B, 0x10, 0x27, 0x00, 0x00,

      // VMOVDQU
      // vmovdqu ymm10,ymm11
      0xC4, 0x41, 0x7E, 0x7F, 0xDA,
      // vmovdqu ymm9,YMMWORD PTR [rbx+rcx*4+0x2710]
      0xC5, 0x7E, 0x6F, 0x8C, 0x8B, 0x10, 0x27, 0x00, 0x00,
      // vmovdqu YMMWORD PTR [rbx+rcx*4+0x2710],ymm0
      0xC5, 0xFE, 0x7F, 0x84, 0x8B, 0x10, 0x27, 0x00, 0x00,

      // vmovaps ymm3, ymm1
      0xC5, 0xFC, 0x28, 0xD9,
      // vmovups YMMWORD PTR [rcx+rdx*4+0x2710], ymm2
      0xC5, 0xFC, 0x11, 0x94, 0x91, 0x10, 0x27, 0x00, 0x00,
      // vmovapd ymm0, ymm5
      0xC5, 0xFD, 0x28, 0xC5,
      // vmovupd ymm6, YMMWORD PTR [r8+r9*4+0x2710]
      0xC4, 0x81, 0x7D, 0x10, 0xB4, 0x88, 0x10, 0x27, 0x00, 0x00,

      // vbroadcastss ymm7, DWORD PTR [rbx+rcx*4+0x2710]
      0xc4, 0xe2, 0x7d, 0x18, 0xbc, 0x8b, 0x10, 0x27, 0x00, 0x00,
      // vbroadcastsd ymm6, QWORD PTR [rbx+rcx*4+0x2710]
      0xc4, 0xe2, 0x7d, 0x19, 0xb4, 0x8b, 0x10, 0x27, 0x00, 0x00,

      // vmovddup ymm3, ymm2
      0xc5, 0xff, 0x12, 0xda,
      // vmovddup ymm4, YMMWORD PTR [rbx+rcx*4+0x2710]
      0xc5, 0xff, 0x12, 0xa4, 0x8b, 0x10, 0x27, 0x00, 0x00,
      // vmovshdup ymm1, ymm2
      0xc5, 0xfe, 0x16, 0xca};

  CHECK_EQ(0, memcmp(expected, desc.buffer, sizeof(expected)));
}

TEST_F(AssemblerX64Test, AssemblerX64AVX2Op256bit) {
  if (!CpuFeatures::IsSupported(AVX2)) return;

  auto buffer = AllocateAssemblerBuffer();
  Isolate* isolate = i_isolate();
  Assembler masm(AssemblerOptions{}, buffer->CreateView());
  CpuFeatureScope fscope(&masm, AVX2);

  __ vpshufd(ymm1, ymm2, 85);
  __ vpshufd(ymm1, Operand(rbx, rcx, times_4, 10000), 85);
  __ vpshuflw(ymm9, ymm10, 85);
  __ vpshuflw(ymm9, Operand(rbx, rcx, times_4, 10000), 85);
  __ vpshufhw(ymm1, ymm2, 85);
  __ vpshufhw(ymm1, Operand(rbx, rcx, times_4, 10000), 85);
  __ vpblendw(ymm2, ymm3, ymm4, 23);
  __ vpblendw(ymm2, ymm3, Operand(rbx, rcx, times_4, 10000), 23);
  __ vpblendvb(ymm1, ymm2, ymm3, ymm4);
  __ vpalignr(ymm10, ymm11, ymm12, 4);
  __ vpalignr(ymm10, ymm11, Operand(rbx, rcx, times_4, 10000), 4);
  __ vbroadcastss(ymm7, xmm0);
  __ vbroadcastsd(ymm6, xmm5);
  __ vpbroadcastb(ymm2, xmm1);
  __ vpbroadcastb(ymm3, Operand(rbx, rcx, times_4, 10000));
  __ vpbroadcastw(ymm15, xmm4);
  __ vpbroadcastw(ymm5, Operand(rbx, rcx, times_4, 10000));
  __ vpmovsxbw(ymm6, xmm5);
  __ vpmovsxwd(ymm1, Operand(rbx, rcx, times_4, 10000));
  __ vpmovsxdq(ymm14, xmm6);
  __ vpmovzxbw(ymm0, Operand(rbx, rcx, times_4, 10000));
  __ vpmovzxbd(ymm14, xmm6);
  __ vpmovzxwd(ymm7, Operand(rbx, rcx, times_4, 10000));
  __ vpmovzxdq(ymm8, xmm6);

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
#ifdef OBJECT_PRINT
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  StdoutStream os;
  Print(*code, os);
#endif

  uint8_t expected[] = {
      // vpshufd ymm1, ymm2, 85
      0xC5, 0xFD, 0x70, 0xCA, 0x55,
      // vpshufd ymm1,YMMWORD PTR [rbx+rcx*4+0x2710], 85
      0xC5, 0xFD, 0x70, 0x8C, 0x8B, 0x10, 0x27, 0x00, 0x00, 0x55,
      // vpshuflw ymm9, ymm10, 85,
      0xC4, 0x41, 0x7F, 0x70, 0xCA, 0x55,
      // vpshuflw ymm9,YMMWORD PTR [rbx+rcx*4+0x2710], 85
      0xC5, 0x7F, 0x70, 0x8C, 0x8B, 0x10, 0x27, 0x00, 0x00, 0x55,
      // vpshufhw ymm1, ymm2, 85
      0xC5, 0xFE, 0x70, 0xCA, 0x55,
      // vpshufhw ymm1,YMMWORD PTR [rbx+rcx*4+0x2710], 85
      0xC5, 0xFE, 0x70, 0x8C, 0x8B, 0x10, 0x27, 0x00, 0x00, 0x55,
      // vpblendw ymm2, ymm3, ymm4, 23
      0xC4, 0xE3, 0x65, 0x0E, 0xD4, 0x17,
      // vpblendw ymm2, ymm3, YMMWORD PTR [rbx+rcx*4+0x2710], 23
      0xC4, 0xE3, 0x65, 0x0E, 0x94, 0x8B, 0x10, 0x27, 0x00, 0x00, 0x17,
      // vpblendvb ymm1, ymm2, ymm3, ymm4
      0xC4, 0xE3, 0x6D, 0x4C, 0xCB, 0x40,
      // vpalignr ymm10, ymm11, ymm12, 4
      0xC4, 0x43, 0x25, 0x0F, 0xD4, 0x04,
      // vpalignr ymm10, ymm11, YMMWORD PTR [rbx+rcx*4+0x2710], 4
      0xC4, 0x63, 0x25, 0x0F, 0x94, 0x8B, 0x10, 0x27, 0x00, 0x00, 0x04,
      // vbroadcastss ymm7, xmm0
      0xc4, 0xe2, 0x7d, 0x18, 0xf8,
      // vbroadcastsd ymm7, xmm0
      0xc4, 0xe2, 0x7d, 0x19, 0xf5,
      // vpbroadcastb ymm2, xmm1
      0xc4, 0xe2, 0x7d, 0x78, 0xd1,
      // vpbroadcastb ymm3, BYTE PTR [rbx+rcx*4+0x2710]
      0xc4, 0xe2, 0x7d, 0x78, 0x9c, 0x8b, 0x10, 0x27, 0x00, 0x00,
      // vpbroadcastw ymm15, xmm4
      0xc4, 0x62, 0x7d, 0x79, 0xfc,
      // vpbroadcastw ymm5, WORD PTR [rbx+rcx*4+0x2710]
      0xc4, 0xe2, 0x7d, 0x79, 0xac, 0x8b, 0x10, 0x27, 0x00, 0x00,
      // vpmovsxbw ymm6, xmm5
      0xc4, 0xe2, 0x7d, 0x20, 0xf5,
      // vpmovsxwd ymm1, XMMWORD PTR [rbx+rcx*4+0x2710]
      0xc4, 0xe2, 0x7d, 0x23, 0x8c, 0x8b, 0x10, 0x27, 0x00, 0x00,
      // vpmovsxdq ymm14, xmm6
      0xc4, 0x62, 0x7d, 0x25, 0xf6,
      // vpmovzxbw ymm0, XMMWORD PTR [rbx+rcx*4+0x2710]
      0xc4, 0xe2, 0x7d, 0x30, 0x84, 0x8b, 0x10, 0x27, 0x00, 0x00,
      // vpmovzxbd ymm14 xmm6
      0xc4, 0x62, 0x7d, 0x31, 0xf6,
      // vpmovzxwd ymm7, XMMWORD PTR [rbx+rcx*4+0x2710]
      0xc4, 0xe2, 0x7d, 0x33, 0xbc, 0x8b, 0x10, 0x27, 0x00, 0x00,
      // vpmovzxdq ymm8, xmm6
      0xc4, 0x62, 0x7d, 0x35, 0xc6};
  CHECK_EQ(0, memcmp(expected, desc.buffer, sizeof(expected)));
}

TEST_F(AssemblerX64Test, AssemblerX64FloatingPoint256bit) {
  if (!CpuFeatures::IsSupported(AVX)) return;

  auto buffer = AllocateAssemblerBuffer();
  Isolate* isolate = i_isolate();
  Assembler masm(AssemblerOptions{}, buffer->CreateView());
  CpuFeatureScope fscope(&masm, AVX);

  __ vandpd(ymm1, ymm3, ymm5);
  __ vminpd(ymm2, ymm3, Operand(r8, r9, times_4, 10000));
  __ vsqrtps(ymm0, ymm1);
  __ vunpcklps(ymm2, ymm3, ymm14);
  __ vsubps(ymm10, ymm11, ymm12);
  __ vroundps(ymm9, ymm2, kRoundUp);
  __ vroundpd(ymm9, ymm2, kRoundToNearest);
  __ vhaddps(ymm1, ymm2, ymm3);
  __ vhaddps(ymm0, ymm1, Operand(rbx, rcx, times_4, 10000));
  __ vblendvps(ymm0, ymm3, ymm5, ymm9);
  __ vblendvpd(ymm7, ymm4, ymm3, ymm1);
  __ vshufps(ymm3, ymm1, ymm2, 0x75);
  __ vsqrtpd(ymm1, ymm2);
  __ vsqrtpd(ymm1, Operand(rbx, rcx, times_4, 10000));
  __ vcvtpd2ps(xmm1, ymm2);
  __ vcvtpd2ps(xmm2, Operand256(rbx, rcx, times_4, 10000));
  __ vcvtps2dq(ymm3, ymm4);
  __ vcvtps2dq(ymm5, Operand(rbx, rcx, times_4, 10000));
  __ vcvttpd2dq(xmm6, ymm8);
  __ vcvttpd2dq(xmm10, Operand256(rbx, rcx, times_4, 10000));
  __ vcvtdq2pd(ymm1, xmm2);
  __ vcvtdq2pd(ymm1, Operand(rbx, rcx, times_4, 10000));
  __ vcvttps2dq(ymm3, ymm2);
  __ vcvttps2dq(ymm3, Operand256(rbx, rcx, times_4, 10000));
  __ vperm2f128(ymm1, ymm2, ymm3, 2);

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
#ifdef OBJECT_PRINT
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  StdoutStream os;
  Print(*code, os);
#endif

  uint8_t expected[] = {// vandpd ymm1, ymm3, ymm5
                        0xC5, 0xE5, 0x54, 0xCD,
                        // vminpd ymm2, ymm3, YMMWORD PTR [r8+r9*4+0x2710]
                        0xC4, 0x81, 0x65, 0x5D, 0x94, 0x88, 0x10, 0x27, 0x00,
                        0x00,
                        // VSQRTPS
                        0xC5, 0xFC, 0x51, 0xC1,
                        // VUNPCKLPS
                        0xC4, 0xC1, 0x64, 0x14, 0xD6,
                        // VSUBPS
                        0xC4, 0x
Prompt: 
```
这是目录为v8/test/unittests/assembler/assembler-x64-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""

    __ rorxq(r8, rcx, 0x4);
    __ movq(r9, uint64_t{0x8112233445566778});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ rorxq(r8, Operand(rsp, 0), 0x4);
    __ movq(r9, uint64_t{0x8112233445566778});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ rorxl(r8, rcx, 0x4);
    __ movq(r9, uint64_t{0x0000000085566778});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ rorxl(r8, Operand(rsp, 0), 0x4);
    __ movq(r9, uint64_t{0x0000000085566778});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ xorl(rax, rax);
    __ bind(&exit);
    __ popq(rcx);
    __ popq(rbx);
    __ ret(0);
  }

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  StdoutStream os;
  Print(*code, os);
#endif

  auto f = GeneratedCode<F0>::FromCode(isolate, *code);
  CHECK_EQ(0, f.Call());
}

TEST_F(AssemblerX64Test, AssemblerX64JumpTables1) {
  // Test jump tables with forward jumps.

  Isolate* isolate = i_isolate();
  HandleScope scope(isolate);
  MacroAssembler masm(isolate, v8::internal::CodeObjectRequired::kYes);

  const int kNumCases = 512;
  int values[kNumCases];
  isolate->random_number_generator()->NextBytes(values, sizeof(values));
  Label labels[kNumCases];

  Label done, table;
  __ leaq(arg2, Operand(&table));
  __ jmp(Operand(arg2, arg1, times_8, 0));
  __ ud2();
  __ bind(&table);
  for (int i = 0; i < kNumCases; ++i) {
    __ dq(&labels[i]);
  }

  for (int i = 0; i < kNumCases; ++i) {
    __ bind(&labels[i]);
    __ movq(rax, Immediate(values[i]));
    __ jmp(&done);
  }

  __ bind(&done);
  __ ret(0);

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code, std::cout);
#endif

  auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  for (int i = 0; i < kNumCases; ++i) {
    int res = f.Call(i);
    PrintF("f(%d) = %d\n", i, res);
    CHECK_EQ(values[i], res);
  }
}

TEST_F(AssemblerX64Test, AssemblerX64JumpTables2) {
  // Test jump tables with backwards jumps.

  Isolate* isolate = i_isolate();
  HandleScope scope(isolate);
  MacroAssembler masm(isolate, v8::internal::CodeObjectRequired::kYes);

  const int kNumCases = 512;
  int values[kNumCases];
  isolate->random_number_generator()->NextBytes(values, sizeof(values));
  Label labels[kNumCases];

  Label done, table;
  __ leaq(arg2, Operand(&table));
  __ jmp(Operand(arg2, arg1, times_8, 0));
  __ ud2();

  for (int i = 0; i < kNumCases; ++i) {
    __ bind(&labels[i]);
    __ movq(rax, Immediate(values[i]));
    __ jmp(&done);
  }

  __ bind(&done);
  __ ret(0);

  __ bind(&table);
  for (int i = 0; i < kNumCases; ++i) {
    __ dq(&labels[i]);
  }

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code, std::cout);
#endif

  auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  for (int i = 0; i < kNumCases; ++i) {
    int res = f.Call(i);
    PrintF("f(%d) = %d\n", i, res);
    CHECK_EQ(values[i], res);
  }
}

TEST_F(AssemblerX64Test, AssemblerX64PslldWithXmm15) {
  auto buffer = AllocateAssemblerBuffer();
  Assembler masm(AssemblerOptions{}, buffer->CreateView());

  __ movq(xmm15, arg1);
  __ pslld(xmm15, 1);
  __ movq(rax, xmm15);
  __ ret(0);

  CodeDesc desc;
  masm.GetCode(i_isolate(), &desc);
  buffer->MakeExecutable();
  auto f = GeneratedCode<F5>::FromBuffer(i_isolate(), buffer->start());
  uint64_t result = f.Call(uint64_t{0x1122334455667788});
  CHECK_EQ(uint64_t{0x22446688AACCEF10}, result);
}

using F9 = float(float x, float y);
TEST_F(AssemblerX64Test, AssemblerX64vmovups) {
  if (!CpuFeatures::IsSupported(AVX)) return;

  Isolate* isolate = i_isolate();
  HandleScope scope(isolate);
  uint8_t buffer[256];
  MacroAssembler masm(isolate, v8::internal::CodeObjectRequired::kYes,
                      ExternalAssemblerBuffer(buffer, sizeof(buffer)));
  {
    CpuFeatureScope avx_scope(&masm, AVX);
    __ shufps(xmm0, xmm0, 0x0);  // brocast first argument
    __ shufps(xmm1, xmm1, 0x0);  // brocast second argument
    // copy xmm1 to xmm0 through the stack to test the "vmovups reg, mem".
    __ AllocateStackSpace(kSimd128Size);
    __ vmovups(Operand(rsp, 0), xmm1);
    __ vmovups(xmm0, Operand(rsp, 0));
    __ addq(rsp, Immediate(kSimd128Size));

    __ ret(0);
  }

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  StdoutStream os;
  Print(*code, os);
#endif

  auto f = GeneratedCode<F9>::FromCode(isolate, *code);
  CHECK_EQ(-1.5, f.Call(1.5, -1.5));
}

TEST_F(AssemblerX64Test, AssemblerX64Regmove256bit) {
  if (!CpuFeatures::IsSupported(AVX)) return;

  auto buffer = AllocateAssemblerBuffer();
  Isolate* isolate = i_isolate();
  Assembler masm(AssemblerOptions{}, buffer->CreateView());
  CpuFeatureScope fscope(&masm, AVX);

  __ vmovdqa(ymm0, ymm1);
  __ vmovdqa(ymm4, Operand(rbx, rcx, times_4, 10000));
  __ vmovdqu(ymm10, ymm11);
  __ vmovdqu(ymm9, Operand(rbx, rcx, times_4, 10000));
  __ vmovdqu(Operand(rbx, rcx, times_4, 10000), ymm0);
  __ vmovaps(ymm3, ymm1);
  __ vmovups(Operand(rcx, rdx, times_4, 10000), ymm2);
  __ vmovapd(ymm0, ymm5);
  __ vmovupd(ymm6, Operand(r8, r9, times_4, 10000));
  __ vbroadcastss(ymm7, Operand(rbx, rcx, times_4, 10000));
  __ vbroadcastsd(ymm6, Operand(rbx, rcx, times_4, 10000));
  __ vmovddup(ymm3, ymm2);
  __ vmovddup(ymm4, Operand(rbx, rcx, times_4, 10000));
  __ vmovshdup(ymm1, ymm2);

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
#ifdef OBJECT_PRINT
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  StdoutStream os;
  Print(*code, os);
#endif

  uint8_t expected[] = {
      // VMOVDQA
      // vmovdqa ymm0,ymm1
      0xC5, 0xFD, 0x6F, 0xC1,
      // vmovdqa ymm4,YMMWORD PTR [rbx+rcx*4+0x2710]
      0xC5, 0xFD, 0x6F, 0xA4, 0x8B, 0x10, 0x27, 0x00, 0x00,

      // VMOVDQU
      // vmovdqu ymm10,ymm11
      0xC4, 0x41, 0x7E, 0x7F, 0xDA,
      // vmovdqu ymm9,YMMWORD PTR [rbx+rcx*4+0x2710]
      0xC5, 0x7E, 0x6F, 0x8C, 0x8B, 0x10, 0x27, 0x00, 0x00,
      // vmovdqu YMMWORD PTR [rbx+rcx*4+0x2710],ymm0
      0xC5, 0xFE, 0x7F, 0x84, 0x8B, 0x10, 0x27, 0x00, 0x00,

      // vmovaps ymm3, ymm1
      0xC5, 0xFC, 0x28, 0xD9,
      // vmovups YMMWORD PTR [rcx+rdx*4+0x2710], ymm2
      0xC5, 0xFC, 0x11, 0x94, 0x91, 0x10, 0x27, 0x00, 0x00,
      // vmovapd ymm0, ymm5
      0xC5, 0xFD, 0x28, 0xC5,
      // vmovupd ymm6, YMMWORD PTR [r8+r9*4+0x2710]
      0xC4, 0x81, 0x7D, 0x10, 0xB4, 0x88, 0x10, 0x27, 0x00, 0x00,

      // vbroadcastss ymm7, DWORD PTR [rbx+rcx*4+0x2710]
      0xc4, 0xe2, 0x7d, 0x18, 0xbc, 0x8b, 0x10, 0x27, 0x00, 0x00,
      // vbroadcastsd ymm6, QWORD PTR [rbx+rcx*4+0x2710]
      0xc4, 0xe2, 0x7d, 0x19, 0xb4, 0x8b, 0x10, 0x27, 0x00, 0x00,

      // vmovddup ymm3, ymm2
      0xc5, 0xff, 0x12, 0xda,
      // vmovddup ymm4, YMMWORD PTR [rbx+rcx*4+0x2710]
      0xc5, 0xff, 0x12, 0xa4, 0x8b, 0x10, 0x27, 0x00, 0x00,
      // vmovshdup ymm1, ymm2
      0xc5, 0xfe, 0x16, 0xca};

  CHECK_EQ(0, memcmp(expected, desc.buffer, sizeof(expected)));
}

TEST_F(AssemblerX64Test, AssemblerX64AVX2Op256bit) {
  if (!CpuFeatures::IsSupported(AVX2)) return;

  auto buffer = AllocateAssemblerBuffer();
  Isolate* isolate = i_isolate();
  Assembler masm(AssemblerOptions{}, buffer->CreateView());
  CpuFeatureScope fscope(&masm, AVX2);

  __ vpshufd(ymm1, ymm2, 85);
  __ vpshufd(ymm1, Operand(rbx, rcx, times_4, 10000), 85);
  __ vpshuflw(ymm9, ymm10, 85);
  __ vpshuflw(ymm9, Operand(rbx, rcx, times_4, 10000), 85);
  __ vpshufhw(ymm1, ymm2, 85);
  __ vpshufhw(ymm1, Operand(rbx, rcx, times_4, 10000), 85);
  __ vpblendw(ymm2, ymm3, ymm4, 23);
  __ vpblendw(ymm2, ymm3, Operand(rbx, rcx, times_4, 10000), 23);
  __ vpblendvb(ymm1, ymm2, ymm3, ymm4);
  __ vpalignr(ymm10, ymm11, ymm12, 4);
  __ vpalignr(ymm10, ymm11, Operand(rbx, rcx, times_4, 10000), 4);
  __ vbroadcastss(ymm7, xmm0);
  __ vbroadcastsd(ymm6, xmm5);
  __ vpbroadcastb(ymm2, xmm1);
  __ vpbroadcastb(ymm3, Operand(rbx, rcx, times_4, 10000));
  __ vpbroadcastw(ymm15, xmm4);
  __ vpbroadcastw(ymm5, Operand(rbx, rcx, times_4, 10000));
  __ vpmovsxbw(ymm6, xmm5);
  __ vpmovsxwd(ymm1, Operand(rbx, rcx, times_4, 10000));
  __ vpmovsxdq(ymm14, xmm6);
  __ vpmovzxbw(ymm0, Operand(rbx, rcx, times_4, 10000));
  __ vpmovzxbd(ymm14, xmm6);
  __ vpmovzxwd(ymm7, Operand(rbx, rcx, times_4, 10000));
  __ vpmovzxdq(ymm8, xmm6);

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
#ifdef OBJECT_PRINT
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  StdoutStream os;
  Print(*code, os);
#endif

  uint8_t expected[] = {
      // vpshufd ymm1, ymm2, 85
      0xC5, 0xFD, 0x70, 0xCA, 0x55,
      // vpshufd ymm1,YMMWORD PTR [rbx+rcx*4+0x2710], 85
      0xC5, 0xFD, 0x70, 0x8C, 0x8B, 0x10, 0x27, 0x00, 0x00, 0x55,
      // vpshuflw ymm9, ymm10, 85,
      0xC4, 0x41, 0x7F, 0x70, 0xCA, 0x55,
      // vpshuflw ymm9,YMMWORD PTR [rbx+rcx*4+0x2710], 85
      0xC5, 0x7F, 0x70, 0x8C, 0x8B, 0x10, 0x27, 0x00, 0x00, 0x55,
      // vpshufhw ymm1, ymm2, 85
      0xC5, 0xFE, 0x70, 0xCA, 0x55,
      // vpshufhw ymm1,YMMWORD PTR [rbx+rcx*4+0x2710], 85
      0xC5, 0xFE, 0x70, 0x8C, 0x8B, 0x10, 0x27, 0x00, 0x00, 0x55,
      // vpblendw ymm2, ymm3, ymm4, 23
      0xC4, 0xE3, 0x65, 0x0E, 0xD4, 0x17,
      // vpblendw ymm2, ymm3, YMMWORD PTR [rbx+rcx*4+0x2710], 23
      0xC4, 0xE3, 0x65, 0x0E, 0x94, 0x8B, 0x10, 0x27, 0x00, 0x00, 0x17,
      // vpblendvb ymm1, ymm2, ymm3, ymm4
      0xC4, 0xE3, 0x6D, 0x4C, 0xCB, 0x40,
      // vpalignr ymm10, ymm11, ymm12, 4
      0xC4, 0x43, 0x25, 0x0F, 0xD4, 0x04,
      // vpalignr ymm10, ymm11, YMMWORD PTR [rbx+rcx*4+0x2710], 4
      0xC4, 0x63, 0x25, 0x0F, 0x94, 0x8B, 0x10, 0x27, 0x00, 0x00, 0x04,
      // vbroadcastss ymm7, xmm0
      0xc4, 0xe2, 0x7d, 0x18, 0xf8,
      // vbroadcastsd ymm7, xmm0
      0xc4, 0xe2, 0x7d, 0x19, 0xf5,
      // vpbroadcastb ymm2, xmm1
      0xc4, 0xe2, 0x7d, 0x78, 0xd1,
      // vpbroadcastb ymm3, BYTE PTR [rbx+rcx*4+0x2710]
      0xc4, 0xe2, 0x7d, 0x78, 0x9c, 0x8b, 0x10, 0x27, 0x00, 0x00,
      // vpbroadcastw ymm15, xmm4
      0xc4, 0x62, 0x7d, 0x79, 0xfc,
      // vpbroadcastw ymm5, WORD PTR [rbx+rcx*4+0x2710]
      0xc4, 0xe2, 0x7d, 0x79, 0xac, 0x8b, 0x10, 0x27, 0x00, 0x00,
      // vpmovsxbw ymm6, xmm5
      0xc4, 0xe2, 0x7d, 0x20, 0xf5,
      // vpmovsxwd ymm1, XMMWORD PTR [rbx+rcx*4+0x2710]
      0xc4, 0xe2, 0x7d, 0x23, 0x8c, 0x8b, 0x10, 0x27, 0x00, 0x00,
      // vpmovsxdq ymm14, xmm6
      0xc4, 0x62, 0x7d, 0x25, 0xf6,
      // vpmovzxbw ymm0, XMMWORD PTR [rbx+rcx*4+0x2710]
      0xc4, 0xe2, 0x7d, 0x30, 0x84, 0x8b, 0x10, 0x27, 0x00, 0x00,
      // vpmovzxbd ymm14 xmm6
      0xc4, 0x62, 0x7d, 0x31, 0xf6,
      // vpmovzxwd ymm7, XMMWORD PTR [rbx+rcx*4+0x2710]
      0xc4, 0xe2, 0x7d, 0x33, 0xbc, 0x8b, 0x10, 0x27, 0x00, 0x00,
      // vpmovzxdq ymm8, xmm6
      0xc4, 0x62, 0x7d, 0x35, 0xc6};
  CHECK_EQ(0, memcmp(expected, desc.buffer, sizeof(expected)));
}

TEST_F(AssemblerX64Test, AssemblerX64FloatingPoint256bit) {
  if (!CpuFeatures::IsSupported(AVX)) return;

  auto buffer = AllocateAssemblerBuffer();
  Isolate* isolate = i_isolate();
  Assembler masm(AssemblerOptions{}, buffer->CreateView());
  CpuFeatureScope fscope(&masm, AVX);

  __ vandpd(ymm1, ymm3, ymm5);
  __ vminpd(ymm2, ymm3, Operand(r8, r9, times_4, 10000));
  __ vsqrtps(ymm0, ymm1);
  __ vunpcklps(ymm2, ymm3, ymm14);
  __ vsubps(ymm10, ymm11, ymm12);
  __ vroundps(ymm9, ymm2, kRoundUp);
  __ vroundpd(ymm9, ymm2, kRoundToNearest);
  __ vhaddps(ymm1, ymm2, ymm3);
  __ vhaddps(ymm0, ymm1, Operand(rbx, rcx, times_4, 10000));
  __ vblendvps(ymm0, ymm3, ymm5, ymm9);
  __ vblendvpd(ymm7, ymm4, ymm3, ymm1);
  __ vshufps(ymm3, ymm1, ymm2, 0x75);
  __ vsqrtpd(ymm1, ymm2);
  __ vsqrtpd(ymm1, Operand(rbx, rcx, times_4, 10000));
  __ vcvtpd2ps(xmm1, ymm2);
  __ vcvtpd2ps(xmm2, Operand256(rbx, rcx, times_4, 10000));
  __ vcvtps2dq(ymm3, ymm4);
  __ vcvtps2dq(ymm5, Operand(rbx, rcx, times_4, 10000));
  __ vcvttpd2dq(xmm6, ymm8);
  __ vcvttpd2dq(xmm10, Operand256(rbx, rcx, times_4, 10000));
  __ vcvtdq2pd(ymm1, xmm2);
  __ vcvtdq2pd(ymm1, Operand(rbx, rcx, times_4, 10000));
  __ vcvttps2dq(ymm3, ymm2);
  __ vcvttps2dq(ymm3, Operand256(rbx, rcx, times_4, 10000));
  __ vperm2f128(ymm1, ymm2, ymm3, 2);

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
#ifdef OBJECT_PRINT
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  StdoutStream os;
  Print(*code, os);
#endif

  uint8_t expected[] = {// vandpd ymm1, ymm3, ymm5
                        0xC5, 0xE5, 0x54, 0xCD,
                        // vminpd ymm2, ymm3, YMMWORD PTR [r8+r9*4+0x2710]
                        0xC4, 0x81, 0x65, 0x5D, 0x94, 0x88, 0x10, 0x27, 0x00,
                        0x00,
                        // VSQRTPS
                        0xC5, 0xFC, 0x51, 0xC1,
                        // VUNPCKLPS
                        0xC4, 0xC1, 0x64, 0x14, 0xD6,
                        // VSUBPS
                        0xC4, 0x41, 0x24, 0x5C, 0xD4,
                        // vroundps ymm9, ymm2, 0xA
                        0xC4, 0x63, 0x7D, 0x08, 0xCA, 0x0A,
                        // vroundpd ymm9, ymm2, 0x8
                        0xC4, 0x63, 0x7D, 0x09, 0xCA, 0x08,
                        // VHADDPS ymm1, ymm2, ymm3
                        0xC5, 0xEF, 0x7C, 0xCB,
                        // VHADDPS ymm0, ymm1, YMMWORD PTR [rbx+rcx*4+0x2710]
                        0xc5, 0xf7, 0x7c, 0x84, 0x8b, 0x10, 0x27, 0x00, 0x00,
                        // vblendvps ymm0, ymm3, ymm5, ymm9
                        0xC4, 0xE3, 0x65, 0x4A, 0xC5, 0x90,
                        // vblendvpd ymm7, ymm4, ymm3, ymm1
                        0xC4, 0xE3, 0x5D, 0x4B, 0xFB, 0x10,
                        // vshufps ymm3, ymm1, ymm2, 0x75
                        0xC5, 0xF4, 0xC6, 0xDA, 0x75,
                        // vsqrtpd ymm1, ymm2
                        0xC5, 0xFD, 0x51, 0xCA,
                        // vsqrtpd ymm1, YMMWORD PTR [rbx+rcx*4+0x2710]
                        0xC5, 0xFD, 0x51, 0x8C, 0x8B, 0x10, 0x27, 0x00, 0x00,
                        // vcvtpd2ps xmm1, ymm2
                        0xC5, 0xFD, 0x5A, 0xCA,
                        // vcvtpd2ps xmm2, YMMWORD PTR [rbx+rcx*4+0x2710]
                        0xC5, 0xFD, 0x5A, 0x94, 0x8B, 0x10, 0x27, 0x00, 0x00,
                        // vcvtps2dq ymm3, ymm4
                        0xC5, 0xFD, 0x5B, 0xDC,
                        // vcvtps2dq ymm5, YMMWORD PTR [rbx+rcx*4+0x2710]
                        0xC5, 0xFD, 0x5B, 0xAC, 0x8B, 0x10, 0x27, 0x00, 0x00,
                        // vcvttpd2dq xmm6, ymm8
                        0xC4, 0xC1, 0x7D, 0xE6, 0xF0,
                        // vcvttpd2dq xmm10, YMMWORD PTR [rbx+rcx*4+0x2710]
                        0xC5, 0x7D, 0xE6, 0x94, 0x8B, 0x10, 0x27, 0x00, 0x00,
                        // vcvtdq2pd ymm1, xmm2
                        0xC5, 0xFE, 0xE6, 0xCA,
                        // vcvtdq2pd ymm1, XMMWORD PTR [rbx+rcx*4+0x2710]
                        0xC5, 0xFE, 0xE6, 0x8C, 0x8B, 0x10, 0x27, 0x00, 0x00,
                        // vcvttps2dq ymm3, ymm2
                        0xC5, 0xFE, 0x5B, 0xDA,
                        // vcvttps2dq ymm3, YMMWORD PTR [rbx+rcx*4+0x2710]
                        0xC5, 0xFE, 0x5B, 0x9C, 0x8B, 0x10, 0x27, 0x00, 0x00,
                        // vperm2f128 ymm1, ymm2, ymm3, 2
                        0xc4, 0xe3, 0x6d, 0x06, 0xcb, 0x02};
  CHECK_EQ(0, memcmp(expected, desc.buffer, sizeof(expected)));
}

TEST_F(AssemblerX64Test, AssemblerX64Integer256bit) {
  if (!CpuFeatures::IsSupported(AVX2)) return;

  auto buffer = AllocateAssemblerBuffer();
  Isolate* isolate = i_isolate();
  Assembler masm(AssemblerOptions{}, buffer->CreateView());
  CpuFeatureScope fscope(&masm, AVX2);

  // SSE2_AVX_INSTRUCTION
  __ vpunpcklbw(ymm9, ymm2, ymm0);
  __ vpacksswb(ymm8, ymm3, ymm1);
  __ vpcmpgtw(ymm2, ymm7, ymm9);
  __ vpand(ymm2, ymm3, ymm4);
  __ vpmaxsw(ymm10, ymm11, Operand(rbx, rcx, times_4, 10000));
  __ vpaddb(ymm1, ymm2, ymm3);
  __ vpsraw(ymm7, ymm1, xmm4);
  __ vpsllq(ymm3, ymm2, xmm1);

  // SSSE3_AVX_INSTRUCTION
  __ vpshufb(ymm1, ymm2, ymm3);
  __ vphaddw(ymm8, ymm9, Operand(rbx, rcx, times_4, 10000));
  __ vpmaddubsw(ymm5, ymm7, ymm9);
  __ vpsignd(ymm7, ymm0, ymm1);
  __ vpmulhrsw(ymm4, ymm3, ymm1);
  __ vpabsb(ymm1, ymm2);
  __ vpabsb(ymm3, Operand(rbx, rcx, times_4, 10000));
  __ vpabsw(ymm6, ymm5);
  __ vpabsd(ymm7, ymm10);

  // SSE4_AVX_INSTRUCTION
  __ vpmuldq(ymm1, ymm5, ymm6);
  __ vpcmpeqq(ymm0, ymm2, ymm3);
  __ vpackusdw(ymm4, ymm2, ymm0);
  __ vpminud(ymm8, ymm9, Operand(rbx, rcx, times_4, 10000));
  __ vpmaxsb(ymm3, ymm4, ymm7);
  __ vpmulld(ymm6, ymm5, ymm3);

  // SSE4_2_AVX_INSTRUCTION
  __ vpcmpgtq(ymm3, ymm2, ymm0);

  __ vpermq(ymm8, Operand(rbx, rcx, times_4, 10000), 0x1E);
  __ vpermq(ymm5, ymm3, 0xD8);

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
#ifdef OBJECT_PRINT
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  StdoutStream os;
  Print(*code, os);
#endif

  uint8_t expected[] = {
      // SSE2_AVX_INSTRUCTION
      // vpunpcklbw ymm9, ymm2, ymm0
      0xC5, 0x6D, 0x60, 0xC8,
      // vpacksswb ymm8, ymm3, ymm1
      0xC5, 0x65, 0x63, 0xC1,
      // vpcmpgtw ymm2, ymm7, ymm9
      0xC4, 0xC1, 0x45, 0x65, 0xD1,
      // vpand ymm2, ymm3, ymm4
      0xC5, 0xE5, 0xDB, 0xD4,
      // vpmaxsw ymm10, ymm11, YMMWORD PTR [rbx+rcx*4+0x2710]
      0xC5, 0x25, 0xEE, 0x94, 0x8B, 0x10, 0x27, 0x00, 0x00,
      // vpaddb ymm1, ymm2, ymm3
      0xC5, 0xED, 0xFC, 0xCB,
      // vpsraw ymm7, ymm1, xmm4
      0xC5, 0xF5, 0xE1, 0xFC,
      // vpsllq ymm3, ymm2, xmm1
      0xC5, 0xED, 0xF3, 0xD9,

      // SSSE3_AVX_INSTRUCTION
      // vpshufb ymm1, ymm2, ymm3
      0xC4, 0xE2, 0x6D, 0x00, 0xCB,
      // vphaddw ymm8, ymm9, YMMWORD PTR [rbx+rcx*4+0x2710]
      0xC4, 0x62, 0x35, 0x01, 0x84, 0x8B, 0x10, 0x27, 0x00, 0x00,
      // vpmaddubsw ymm5, ymm7, ymm9
      0xC4, 0xC2, 0x45, 0x04, 0xE9,
      // vpsignd ymm7, ymm0, ymm1
      0xC4, 0xE2, 0x7D, 0x0A, 0xF9,
      // vpmulhrsw ymm4, ymm3, ymm1
      0xC4, 0xE2, 0x65, 0x0B, 0xE1,
      // vpabsb ymm1, ymm2
      0xC4, 0xE2, 0x7D, 0x1C, 0xCA,
      // vpabsb ymm3, YMMWORD PTR [rbx+rcx+0x2710]
      0xC4, 0xE2, 0x7D, 0x1C, 0x9C, 0x8b, 0x10, 0x27, 0x00, 0x00,
      // vpabsw ymm6, ymm5
      0xC4, 0xE2, 0x7D, 0x1D, 0xF5,
      // vpabsd ymm7, ymm10
      0xC4, 0xC2, 0x7D, 0x1E, 0xFA,

      // SSE4_AVX_INSTRUCTION
      // vpmuldq ymm1, ymm5, ymm6
      0xC4, 0xE2, 0x55, 0x28, 0xCE,
      // vpcmpeqq ymm0, ymm2, ymm3
      0xC4, 0xE2, 0x6D, 0x29, 0xC3,
      // vpackusdw ymm4, ymm2, ymm0
      0xC4, 0xE2, 0x6D, 0x2B, 0xE0,
      // vpminud ymm8, ymm9, YMMWORD PTR [rbx+rcx*4+0x2710]
      0xC4, 0x62, 0x35, 0x3B, 0x84, 0x8B, 0x10, 0x27, 0x0, 0x0,
      // vpmaxsb ymm3, ymm4, ymm7
      0xC4, 0xE2, 0x5D, 0x3C, 0xDF,
      // vpmulld ymm6, ymm5, ymm3
      0xC4, 0xE2, 0x55, 0x40, 0xF3,

      // SSE4_2_AVX_INSTRUCTION
      // vpcmpgtq ymm3, ymm2, ymm0
      0xC4, 0xE2, 0x6D, 0x37, 0xD8,

      // vpermq ymm8, YMMWORD PTR [rbx+rcx*4+0x2710], 0x1e
      0xC4, 0x63, 0xFD, 0x00, 0x84, 0x8B, 0x10, 0x27, 0x00, 0x00, 0x1E,
      // vpermq ymm5, ymm3, 0xD8
      0xC4, 0xE3, 0xFD, 0x00, 0xEB, 0xD8};
  CHECK_EQ(0, memcmp(expected, desc.buffer, sizeof(expected)));
}

TEST_F(AssemblerX64Test, AssemblerX64CmpOperations256bit) {
  if (!CpuFeatures::IsSupported(AVX)) return;

  auto buffer = AllocateAssemblerBuffer();
  Isolate* isolate = i_isolate();
  Assembler masm(AssemblerOptions{}, buffer->CreateView());
  CpuFeatureScope fscope(&masm, AVX);

  __ vcmpeqps(ymm1, ymm2, ymm4);
  __ vcmpltpd(ymm4, ymm7, Operand(rcx, rdx, times_4, 10000));
  __ vcmpleps(ymm9, ymm8, Operand(r8, r11, times_8, 10000));
  __ vcmpunordpd(ymm3, ymm7, ymm8);
  __ vcmpneqps(ymm3, ymm5, ymm9);
  __ vcmpnltpd(ymm10, ymm12, Operand(r12, r11, times_4, 10000));
  __ vcmpnleps(ymm9, ymm11, Operand(r10, r9, times_8, 10000));
  __ vcmpgepd(ymm13, ymm3, ymm12);
  __ vptest(ymm7, ymm1);
  __ vptest(ymm10, Operand(rbx, rcx, times_4, 10000));

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
#ifdef OBJECT_PRINT
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  StdoutStream os;
  Print(*code, os);
#endif

  uint8_t expected[] = {
      // vcmpeqps ymm1, ymm2, ymm4
      0xC5, 0xEC, 0xC2, 0xCC, 0x00,
      // vcmpltpd ymm4, ymm7, YMMWORD PTR [rcx+rdx*4+0x2710]
      0xC5, 0xC5, 0xC2, 0xA4, 0x91, 0x10, 0x27, 0x00, 0x00, 0x01,
      // vcmpleps ymm9, ymm8, YMMWORD PTR [r8+r11*8+0x2710]
      0xC4, 0x01, 0x3C, 0xC2, 0x8C, 0xD8, 0x10, 0x27, 0x00, 0x00, 0x02,
      // vcmpunordpd ymm3, ymm7, ymm8
      0xC4, 0xC1, 0x45, 0xC2, 0xD8, 0x03,
      // vcmpneqps ymm3, ymm5, ymm9
      0xC4, 0xC1, 0x54, 0xC2, 0xD9, 0x04,
      // vcmpnltpd ymm10, ymm12, YMMWORD PTR [r12+r11*4+0x2710]
      0xC4, 0x01, 0x1D, 0xC2, 0x94, 0x9C, 0x10, 0x27, 0x00, 0x00, 0x05,
      // vcmpnleps ymm9, ymm11, YMMWORD PTR [r10+r9*8+0x2710]
      0xC4, 0x01, 0x24, 0xC2, 0x8C, 0xCA, 0x10, 0x27, 0x00, 0x00, 0x06,
      // vcmpgepd ymm13, ymm3, ymm12
      0xC4, 0x41, 0x65, 0xC2, 0xEC, 0x0D,
      // vptest ymm7, ymm1
      0xc4, 0xe2, 0x7d, 0x17, 0xf9,
      // vptest ymm10, YMMWORD PTR [rbx+rcx*4+0x2710]
      0xc4, 0x62, 0x7d, 0x17, 0x94, 0x8b, 0x10, 0x27, 0x00, 0x00};
  CHECK_EQ(0, memcmp(expected, desc.buffer, sizeof(expected)));
}

TEST_F(AssemblerX64Test, AssemblerX64FMA256bit) {
  if (!CpuFeatures::IsSupported(AVX)) return;

  auto buffer = AllocateAssemblerBuffer();
  Isolate* isolate = i_isolate();
  Assembler masm(AssemblerOptions{}, buffer->CreateView());
  CpuFeatureScope fscope(&masm, FMA3);

  __ vfmadd132ps(ymm1, ymm2, ymm4);
  __ vfmadd213ps(ymm3, ymm5, ymm9);
  __ vfmadd231ps(ymm1, ymm3, ymm5);
  __ vfnmadd132ps(ymm1, ymm2, ymm4);
  __ vfnmadd213ps(ymm3, ymm5, ymm9);
  __ vfnmadd231ps(ymm1, ymm3, ymm5);

  __ vfmadd132ps(ymm1, ymm2, Operand(rcx, rdx, times_4, 10000));
  __ vfmadd213ps(ymm3, ymm5, Operand(r8, r11, times_8, 10000));
  __ vfmadd231ps(ymm1, ymm3, Operand(r12, r11, times_4, 10000));
  __ vfnmadd132ps(ymm1, ymm2, Operand(rcx, rdx, times_4, 10000));
  __ vfnmadd213ps(ymm3, ymm5, Operand(r8, r11, times_8, 10000));
  __ vfnmadd231ps(ymm1, ymm3, Operand(r12, r11, times_4, 10000));

  __ vfmadd132pd(ymm1, ymm2, ymm4);
  __ vfmadd213pd(ymm3, ymm5, ymm9);
  __ vfmadd231pd(ymm1, ymm3, ymm5);
  __ vfnmadd132pd(ymm1, ymm2, ymm4);
  __ vfnmadd213pd(ymm3, ymm5, ymm9);
  __ vfnmadd231pd(ymm1, ymm3, ymm5);

  __ vfmadd132pd(ymm1, ymm2, Operand(rcx, rdx, times_4, 10000));
  __ vfmadd213pd(ymm3, ymm5, Operand(r8, r11, times_8, 10000));
  __ vfmadd231pd(ymm1, ymm3, Operand(r12, r11, times_4, 10000));
  __ vfnmadd132pd(ymm1, ymm2, Operand(rcx, rdx, times_4, 10000));
  __ vfnmadd213pd(ymm3, ymm5, Operand(r8, r11, times_8, 10000));
  __ vfnmadd231pd(ymm1, ymm3, Operand(r12, r11, times_4, 10000));

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
#ifdef OBJECT_PRINT
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  StdoutStream os;
  Print(*code, os);
#endif

  uint8_t expected[] = {
      // vfmadd132ps ymm1, ymm2, ymm4
      0xC4, 0xE2, 0x6D, 0x98, 0xCC,
      // vfmadd213ps ymm3, ymm5, ymm9
      0xC4, 0xC2, 0x55, 0xA8, 0xD9,
      // vfmadd231ps ymm1, ymm3, ymm5
      0xC4, 0xE2, 0x65, 0xB8, 0xCD,
      // vfnmadd132ps ymm1, ymm2, ymm4
      0xC4, 0xE2, 0x6D, 0x9C, 0xCC,
      // vfnmadd213ps ymm3, ymm5, ymm9
      0xC4, 0xC2, 0x55, 0xAC, 0xD9,
      // vfnmadd231ps ymm1, ymm3, ymm5
      0xC4, 0xE2, 0x65, 0xBC, 0xCD,
      // vfmadd132ps ymm1, ymm2, YMMWORD PTR [rcx+rdx*4+0x2710]
      0xC4, 0xE2, 0x6D, 0x98, 0x8C, 0x91, 0x10, 0x27, 0x00, 0x00,
      // vfmadd213ps ymm3, ymm5, YMMWORD PTR [r8+r11*8+0x2710]
      0xC4, 0x82, 0x55, 0xA8, 0x9C, 0xD8, 0x10, 0x27, 0x00, 0x00,
      // vfmadd231ps ymm1, ymm3, YMMWORD PTR [r12+r11*4+0x2710]
      0xC4, 0x82, 0x65, 0xB8, 0x8C, 0x9C, 0x10, 0x27, 0x00, 0x00,
      // vfnmadd132ps ymm1, ymm2, YMMWORD PTR [rcx+rdx*4+0x2710]
      0xC4, 0xE2, 0x6D, 0x9C, 0x8C, 0x91, 0x10, 0x27, 0x00, 0x00,
      // vfnmadd213ps ymm3, ymm5, YMMWORD PTR [r8+r11*8+0x2710]
      0xC4, 0x82, 0x55, 0xAC, 0x9C, 0xD8, 0x10, 0x27, 0x00, 0x00,
      // vfnmadd231ps ymm1, ymm3, YMMWORD PTR [r12+r11*4+0x2710]
      0xC4, 0x82, 0x65, 0xBC, 0x8C, 0x9C, 0x10, 0x27, 0x00, 0x00,
      // vfmadd132pd ymm1, ymm2, ymm4
      0xC4, 0xE2, 0xED, 0x98, 0xCC,
      // vfmadd213pd ymm3, ymm5, ymm9
      0xC4, 0xC2, 0xD5, 0xA8, 0xD9,
      // vfmadd231pd ymm1, ymm3, ymm5
      0xC4, 0xE2, 0xE5, 0xB8, 0xCD,
      // vfnmadd132pd ymm1, ymm2, ymm4
      0xC4, 0xE2, 0xED, 0x9C, 0xCC,
      // vfnmadd213pd ymm3, ymm5, ymm9
      0xC4, 0xC2, 0xD5, 0xAC, 0xD9,
      // vfnmadd231pd ymm1, ymm3, ymm5
      0xC4, 0xE2, 0xE5, 0xBC, 0xCD,
      // vfmadd132pd ymm1, ymm2, YMMWORD PTR [rcx+rdx*4+0x2710]
      0xC4, 0xE2, 0xED, 0x98, 0x8C, 0x91, 0x10, 0x27, 0x00, 0x00,
      // vfmadd213pd ymm3, ymm5, YMMWORD PTR [r8+r11*8+0x2710]
      0xC4, 0x82, 0xD5, 0xA8, 0x9C, 0xD8, 0x10, 0x27, 0x00, 0x00,
      // vfmadd231pd ymm1, ymm3, YMMWORD PTR [r12+r11*4+0x2710]
      0xC4, 0x82, 0xE5, 0xB8, 0x8C, 0x9C, 0x10, 0x27, 0x00, 0x00,
      // vfnmadd132pd ymm1, ymm2, YMMWORD PTR [rcx+rdx*4+0x2710]
      0xC4, 0xE2, 0xED, 0x9C, 0x8C, 0x91, 0x10, 0x27, 0x00, 0x00,
      // vfnmadd213pd ymm3, ymm5, YMMWORD PTR [r8+r11*8+0x2710]
      0xC4, 0x82, 0xD5, 0xAC, 0x9C, 0xD8, 0x10, 0x27, 0x00, 0x00,
      // vfnmadd231pd ymm1, ymm3, YMMWORD PTR [r12+r11*4+0x2710]
      0xC4, 0x82, 0xE5, 0xBC, 0x8C, 0x9C, 0x10, 0x27, 0x00, 0x00};
  CHECK_EQ(0, memcmp(expected, desc.buffer, sizeof(expected)));
}

TEST_F(AssemblerX64Test, AssemblerX64ShiftImm128bit) {
  if (!CpuFeatures::IsSupported(AVX)) return;

  auto buffer = AllocateAssemblerBuffer();
  Isolate* isolate = i_isolate();
  Assembler masm(AssemblerOptions{}, buffer->CreateView());
  CpuFeatureScope fscope(&masm, AVX);

  __ vpsrlw(xmm8, xmm2, 4);
  __ vpsrld(xmm11, xmm2, 4);
  __ vpsrlq(xmm1, xmm2, 4);
  __ vpsraw(xmm10, xmm8, 4);
  __ vpsrad(xmm6, xmm7, 4);
  __ vpsllw(xmm1, xmm4, 4);
  __ vpslld(xmm3, xmm2, 4);
  __ vpsllq(xmm6, xmm9, 4);

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
#ifdef OBJECT_PRINT
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  StdoutStream os;
  Print(*code, os);
#endif

  uint8_t expected[] = {// vpsrlw xmm8,xmm2,0x4
                        0XC5, 0xB9, 0x71, 0xD2, 0x04,
                        // vpsrld xmm11,xmm2,0x4
                        0xC5, 0xA1, 0x72, 0xD2, 0x04,
                        // vpsrlq xmm1,xmm2,0x4
                        0xC5, 0xF1, 0x73, 0xD2, 0x04,
                        // vpsraw xmm10,xmm8,0x4
                        0xC4, 0xC1, 0x29, 0x71, 0xE0, 0x04,
                        // vpsrad xmm6,xmm7,0x4
                        0xC5, 0xC9, 0x72, 0xE7, 0x04,
                        // vpsllw xmm1,xmm4,0x4
                        0xC5, 0xF1, 0x71, 0xF4, 0x04,
                        // vpslld xmm3,xmm2,0x4
                        0xC5, 0xE1, 0x72, 0xF2, 0x04,
                        // vpsllq xmm6,xmm9,0x4
                        0xC4, 0xC1, 0x49, 0x73, 0xF1, 0x04};
  CHECK_EQ(0, memcmp(expected, desc.buffer, sizeof(expected)));
}

TEST_F(AssemblerX64Test, AssemblerX64ShiftImm256bit) {
  if (!CpuFeatures::IsSupported(AVX2)) return;

  auto buffer = AllocateAssemblerBuffer();
  Isolate* isolate = i_isolate();
  Assembler masm(AssemblerOptions{}, buffer->CreateView());
  CpuFeatureScope fscope(&masm, AVX2);

  __ vpsrlw(ymm0, ymm2, 4);
  __ vpsrld(ymm11, ymm2, 4);
  __ vpsrlq(ymm1, ymm2, 4);
  __ vpsraw(ymm10, ymm8, 4);
  __ vpsrad(ymm6, ymm7, 4);
  __ vpsllw(ymm1, ymm4, 4);
  __ vpslld(ymm3, ymm2, 4);
  __ vpsllq(ymm6, ymm9, 4);

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
#ifdef OBJECT_PRINT
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  StdoutStream os;
  Print(*code, os);
#endif

  uint8_t expected[] = {// vpsrlw ymm0,ymm2,0x4
                        0XC5, 0xFD, 0x71, 0xD2, 0x04,
                        // vpsrld ymm11,ymm2,0x4
                        0xC5, 0xA5, 0x72, 0xD2, 0x04,
                        // vpsrlq ymm1,ymm2,0x4
                        0xC5, 0xF5, 0x73, 0xD2, 0x04,
                        // vpsraw ymm10,ymm8,0x4
                        0xC4, 0xC1, 0x2D, 0x71, 0xE0, 0x04,
                        // vpsrad ymm6,ymm7,0x4
                        0xC5, 0xCD, 0x72, 0xE7, 0x04,
                        // vpsllw ymm1,ymm4,0x4
                        0xC5, 0xF5, 0x71, 0xF4, 0x04,
                        // vpslld ymm3,ymm2,0x4
                        0xC5, 0xE5, 0x72, 0xF2, 0x04,
                        // vpsllq ymm6,ymm9,0x4
                        0xC4, 0xC1, 0x4D, 0x73, 0xF1, 0x04};
  CHECK_EQ(0, memcmp(expected, desc.buffer, sizeof(expected)));
}

TEST_F(AssemblerX64Test, AssemblerX64BinOp256bit) {
  {
    if (!CpuFeatures::IsSupported(AVX)) return;
    auto buffer = AllocateAssemblerBuffer();
    Isolate* isolate = i_isolate();
    Assembler masm(AssemblerOptions{}, buffer->CreateView());
    CpuFeatureScope fscope(&masm, AVX);

    //  add
    __ vaddps(ymm0, ymm1, ymm2);
    __ vaddpd(ymm3, ymm4, ymm5);

    // sub
    __ vsubps(ymm0, ymm1, ymm2);
    __ vsubpd(ymm3, ymm4, ymm5);

    // mul
    __ vmulps(ymm0, ymm1, ymm2);
    __ vmulpd(ymm3, ymm4, ymm5);

    // div
    __ vdivps(ymm0, ymm1, ymm2);
    __ vdivpd(ymm3, ymm4, ymm5);

    CodeDesc desc;
    masm.GetCode(isolate, &desc);
#ifdef OBJECT_PRINT
    DirectHandle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
    StdoutStream os;
    Print(*code, os);
#endif

    uint8_t expected[] = {// vaddps ymm0,ymm1,ymm2
                          0xc5, 0xf4, 0x58, 0xc2,
                          // vaddpd ymm3,ymm4,ymm5
                          0xc5, 0xdd, 0x58, 0xdd,
                          // vsubps ymm0,ymm1,ymm2
                          0xc5, 0xf4, 0x5c, 0xc2,
                          // vsubpd ymm3,ymm4,ymm5
                          0xc5, 0xdd, 0x5c, 0xdd,
                          // vmulps ymm0,ymm1,ymm2
                          0xc5, 0xf4, 0x59, 0xc2,
                          // vmulpd ymm3,ymm4,ymm5
                          0xc5, 0xdd, 0x59, 0xdd,
                          // vdivps ymm0,ymm1,ymm2
                          0xc5, 0xf4, 0x5e, 0xc2,
                          // vdivpd ymm3,ymm4,ymm5
                          0xc5, 0xdd, 0x5e, 0xdd};
    CHECK_EQ(0, memcmp(expected, desc.buffer, sizeof(expected)));
  }

  {
    if (!CpuFeatures::IsSupported(AVX2)) return;

    auto buffer = AllocateAssemblerBuffer();
    Isolate* isolate = i_isolate();
    Assembler masm(AssemblerOptions{}, buffer->CreateView());
    CpuFeatureScope fscope(&masm, AVX2);

    //  add
    __ vpaddb(ymm6, ymm7, ymm8);
    __ vpaddw(ymm9, ymm10, ymm11);
    __ vpaddd(ymm12, ymm13, ymm14);
    __ vpaddq(ymm15, ymm1, ymm2);

    // sub

    __ vpsubb(ymm6, ymm7, ymm8);
    __ vpsubw(ymm9, ymm10, ymm11);
    __ vpsubd(ymm12, ymm13, ymm14);
    __ vpsubq(ymm15, ymm1, ymm2);

    // mul, exclude I64x4

    __ vpmullw(ymm6, ymm7, ymm8);
    __ vpmulld(ymm15, ymm1, ymm2);

    CodeDesc desc;
    masm.GetCode(isolate, &desc);
#ifdef OBJECT_PRINT
    DirectHandle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
    StdoutStream os;
    Print(*code, os);
#endif

    uint8_t expected[] = {// vpaddb ymm6,ymm7,ymm8
                          0xc4, 0xc1, 0x45, 0xfc, 0xf0,
                          // vpaddw ymm9,ymm10,ymm11
                          0xc4, 0x41, 0x2d, 0xfd, 0xcb,
                          // vpaddd ymm12,ymm13,ymm14
                          0xc4, 0x41, 0x15, 0xfe, 0xe6,
                          // vpaddq ymm15,ymm1,ymm2
                          0xc5, 0x75, 0xd4, 0xfa,
                          // vpsubb ymm6,ymm7,ymm8
                          0xc4, 0xc1, 0x45, 0xf8, 0xf0,
                          // vpsubw ymm9,ymm10,ymm11
                          0xc4, 0x41, 0x2d, 0xf9, 0xcb,
                          // vpsubd ymm12,ymm13,ymm14
                          0xc4, 0x41, 0x15, 0xfa, 0xe6,
                          // vpsubq ymm15,ymm1,ymm2
                          0xc5, 0x75, 0xfb, 0xfa,
                          // vpmullw ymm6,ymm7,ymm8
                          0xc4, 0xc1, 0x45, 0xd5, 0xf0,
                          // vpmulld ymm15,ymm1,ymm2
                          0xc4, 0x62, 0x75, 0x40, 0xfa};
    CHECK_EQ(0, memcmp(expected, desc.buffer, sizeof(expected)));
  }
}

TEST_F(AssemblerX64Test, F16C) {
  if (!CpuFeatures::IsSupported(F16C)) return;

  auto buffer = AllocateAssemblerBuffer();
  Isolate* isolate = i_isolate();
  Assembler masm(AssemblerOptions{}, buffer->CreateView());
  CpuFeatureScope fscope(&masm, F16C);

  __ vcvtph2ps(ymm0, xmm1);
  __ vcvtph2ps(xmm2, xmm3);
  __ vcvtps2ph(xmm4, ymm5, 0);
  __ vcvtps2ph(xmm6, xmm7, 0);

  CodeDesc desc;
  masm.GetCode(isolate, &desc);

  uint8_t expected[] = {// vcvtph2ps ymm0,xmm1,
                        0xc4, 0xe2, 0x7d, 0x13, 0xc1,
                        // vcvtph2ps xymm2,xmm3,
                        0xc4, 0xe2, 0x79, 0x13, 0xd3,
                        // vcvtps2ph xmm4,ymm5,0x0
                        0xc4, 0xe3, 0x7d, 0x1d, 0xec, 0x00,
                        // vcvtps2ph xmm6,xmm7,0x0
                        0xc4, 0xe3, 0x79, 0x1d, 0xfe, 0x00};
  CHECK_EQ(0, memcmp(expected, desc.buffer, sizeof(expected)));
}

TEST_F(AssemblerX64Test, AssemblerX64AVXVNNI) {
  if (!CpuFeatures::IsSupported(AVX_VNNI)) return;

  auto buffer = AllocateAssemblerBuffer();
  Isolate* isolate = i_isolate();
  Assembler masm(AssemblerOptions{}, buffer->CreateView());
  CpuFeatureScope fscope(&masm, AVX_VNNI);

  __ vpdpbusd(xmm1, xmm2, xmm3);
  __ vpdpbusd(ymm8, ymm11, ymm9);

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
#ifdef OBJECT_PRINT
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  StdoutStream os;
  Print(*code, os);
#endif

  uint8_t expected[] = {// vpdpbusd xmm1, xmm2, xmm3
                        0xc4, 0xe2, 0x69, 0x50, 0xcb,
                        // vpdpbusd ymm8, ymm11, ymm9
                        0xc4, 0x42, 0x25, 0x50, 0xc1};
  CHECK_EQ(0, memcmp(expected, desc.buffer, sizeof(expected)));
}

TEST_F(AssemblerX64Test, AssemblerX64AVXVNNIINT8) {
  if (!CpuFeatures::IsSupported(AVX_VNNI_INT8)) return;

  auto buffer = AllocateAssemblerBuffer();
  Isolate* isolate = i_isolate();
  Assembler masm(AssemblerOptions{}, buffer->CreateView());
  CpuFeatureScope fscope(&masm, AVX_VNNI_INT8);

  __ vpdpbssd(xmm12, xmm13, xmm14);
  __ vpdpbssd(ymm12, ymm13, ymm14);

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
#ifdef OBJECT_PRINT
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  StdoutStream os;
  Print(*code, os);
#endif

  uint8_t expected[] = {// vpdpbssd xmm12, xmm13, xmm14
                        0xc4, 0x42, 0x13, 0x50, 0xe6,
                        // vpdpbssd ymm12, ymm13, ymm14
                        0xc4, 0x42, 0x17, 0x50, 0xe6};
  CHECK_EQ(0, memcmp(expected, desc.buffer, sizeof(expected)));
}

TEST_F(AssemblerX64Test, CpuFeatures_ProbeImpl) {
  // Support for a newer extension implies support for the older extensions.
  CHECK_IMPLIES(CpuFeatures::IsSupported(FMA3), CpuFeatures::IsSupported(AVX));
  CHECK_IMPLIES(CpuFeatures::IsSupported(AVX_VNNI_INT8),
                CpuFeatures::IsSupported(AVX));
  CHECK_IMPLIES(CpuFeatures::IsSupported(AVX_VNNI),
                CpuFeatures::IsSupported(AVX));
  CHECK_IMPLIES(CpuFeatures::IsSupported(AVX2), CpuFeatures::IsSupported(AVX));
  CHECK_IMPLIES(CpuFeatures::IsSupported(AVX),
                CpuFeatures::IsSupported(SSE4_2));
  CHECK_IMPLIES(CpuFeatures::IsSupported(SSE4_2),
                CpuFeatures::IsSupported(SSE4_1));
  CHECK_IMPLIES(CpuFeatures::IsSupported(SSE4_1),
                CpuFeatures::IsSupported(SSSE3));
  CHECK_IMPLIES(CpuFeatures::IsSupported(SSSE3),
                CpuFeatures::IsSupported(SSE3));

  // Check the reverse, if an older extension is not supported, a newer
  // extension cannot be supported.
  CHECK_IMPLIES(!CpuFeatures::IsSupported(SSE3),
                !CpuFeatures::IsSupported(SSSE3));
  CHECK_IMPLIES(!CpuFeatures::IsSupported(SSSE3),
                !CpuFeatures::IsSupported(SSE4_1));
  CHECK_IMPLIES(!CpuFeatures::IsSupported(SSE4_1),
                !CpuFeatures::IsSupported(SSE4_2));
  CHECK_IMPLIES(!CpuFeatures::IsSupported(SSE4_2),
                !CpuFeatures::IsSupported(AVX));
  CHECK_IMPLIES(!CpuFeatures::IsSupported(AVX),
                !CpuFeatures::IsSupported(AVX2));
  CHECK_IMPLIES(!CpuFeatures::IsSupported(AVX),
                !CpuFeatures::IsSupported(AVX_VNNI));
  CHECK_IMPLIES(!CpuFeatures::IsSupported(AVX),
                !CpuFeatures::IsSupported(AVX_VNNI_INT8));
  CHECK_IMPLIES(!CpuFeatures::IsSupported(AVX),
                !CpuFeatures::IsSupported(FMA3));
}

#undef __

}  // namespace internal
}  // namespace v8

"""


```