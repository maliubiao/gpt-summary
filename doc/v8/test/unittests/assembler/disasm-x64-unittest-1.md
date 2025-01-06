Response: The user wants me to summarize the functionality of a C++ source code file, specifically the second part of `v8/test/unittests/assembler/disasm-x64-unittest.cc`. I also need to explain the relationship with JavaScript, using a JavaScript example if relevant.

Based on the provided code snippet, which consists of several `TEST_F` blocks and `COMPARE` macros, it appears this part of the file continues to test the **disassembler functionality** for the x64 architecture in the V8 JavaScript engine.

Specifically, it seems to be focusing on testing the disassembly of **Advanced Vector Extensions (AVX, AVX2, AVX_VNNI, F16C) instructions**. The `COMPARE` macro likely takes an assembly instruction's byte representation and the corresponding assembler mnemonic as arguments, verifying that the disassembler correctly decodes the bytes into the expected mnemonic.

Regarding the relationship with JavaScript:  JavaScript engines like V8 compile JavaScript code into machine code for efficient execution. AVX instructions are low-level CPU instructions that can significantly speed up certain types of computations, especially those involving large amounts of numerical data. V8's internal code generators might utilize these AVX instructions when optimizing JavaScript code.

To illustrate the connection, consider a JavaScript array manipulation scenario that could benefit from vectorization:

```javascript
const a = new Float64Array(1024);
const b = new Float64Array(1024);
const c = new Float64Array(1024);

for (let i = 0; i < a.length; i++) {
  c[i] = a[i] + b[i];
}
```

Internally, V8 might translate this loop into machine code that utilizes AVX instructions to perform the additions in parallel across multiple elements of the arrays. The `vaddpd` instruction, seen in the tests, is an example of an AVX instruction for adding packed double-precision floating-point values. The unit tests in this file ensure that V8's disassembler can correctly interpret these generated AVX instructions.
这是 `v8/test/unittests/assembler/disasm-x64-unittest.cc` 文件的第二部分，它延续了第一部分的功能，主要用于 **测试 V8 引擎中 x64 架构的反汇编器 (disassembler) 的正确性**。

具体来说，这部分测试集中于 **验证反汇编器能否正确地将 x64 汇编指令的机器码（字节序列）转换回可读的汇编代码形式**。它涵盖了更广泛的 x64 指令集，特别是以下方面：

* **AVX (Advanced Vector Extensions) 和 AVX2 指令:** 这些指令集允许对向量数据进行并行操作，显著提高了处理性能。测试中包含了如 `vmovdqa`， `vhaddps`， `vbroadcastss`， `vmovddup`， `vshufps`， `vcvtdq2pd`， `vperm2f128` 等 AVX 指令以及 `vpbroadcastb`， `vpabsb`， `vpermq`， `vpmovsxbw` 等 AVX2 指令的测试。
* **AVX-VNNI (Vector Neural Network Instructions) 指令:**  这些是用于加速深度学习推理的指令，例如 `vpdpbusd`。
* **F16C (Half-precision floating-point conversion) 指令:**  用于半精度浮点数和单精度浮点数之间的转换，例如 `vcvtph2ps` 和 `vcvtps2ph`。
* **各种操作数的组合:**  测试了指令与寄存器、立即数和不同寻址模式（例如，基址 + 索引 * 比例 + 偏移）的操作数结合使用时的反汇编结果。
* **条件比较指令 (vcmp):**  测试了各种浮点数比较指令的反汇编，包括不同的比较类型（等于、小于、大于等）。

**与 JavaScript 的关系：**

V8 是 Google Chrome 浏览器和 Node.js 的 JavaScript 引擎。为了提高 JavaScript 代码的执行效率，V8 会将 JavaScript 代码编译成机器码。在 x64 架构上，V8 的代码生成器可能会利用 AVX、AVX2、AVX-VNNI 等指令集来优化某些计算密集型操作，例如：

* **SIMD (Single Instruction, Multiple Data) 操作:**  对于数组或大量数值数据的处理，AVX 指令可以并行处理多个数据，显著加速计算。例如，对两个数组进行逐元素加法或乘法。
* **深度学习推理:**  AVX-VNNI 指令专门用于加速神经网络中的点积运算等。
* **图形和媒体处理:**  这些领域经常需要进行大量的并行计算，AVX 指令可以提供性能提升。

**JavaScript 示例：**

虽然 JavaScript 本身不直接操作 AVX 指令，但 V8 引擎会在幕后使用它们来优化代码。例如，考虑以下 JavaScript 代码：

```javascript
const a = new Float64Array([1.0, 2.0, 3.0, 4.0]);
const b = new Float64Array([5.0, 6.0, 7.0, 8.0]);
const c = new Float64Array(4);

for (let i = 0; i < a.length; i++) {
  c[i] = a[i] + b[i];
}

console.log(c); // 输出: Float64Array [ 6, 8, 10, 12 ]
```

在 V8 引擎中，当这段代码被编译成机器码时，对于循环中的加法操作，V8 可能会生成类似于以下的 x64 AVX 指令（这是一个简化的例子）：

```assembly
vaddpd ymm0, ymm1, ymm2  ; 将 ymm1 和 ymm2 寄存器中的双精度浮点数并行相加，结果存入 ymm0
```

这里的 `vaddpd` 指令可以一次性将多个双精度浮点数相加，从而加速循环的执行。`disasm-x64-unittest.cc` 中的测试，特别是包含 `vaddpd` 的测试，就是用来验证 V8 的反汇编器能否正确识别和显示这条指令。

总而言之，这部分单元测试确保了 V8 引擎能够正确地理解其自身生成的机器码，这对于调试、性能分析和理解 V8 内部工作原理至关重要。 它验证了 V8 在使用高级指令集（如 AVX 及其扩展）时的正确性。

Prompt: 
```
这是目录为v8/test/unittests/assembler/disasm-x64-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
, xmm4, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("c5d8c2e90d           vcmpps xmm5,xmm4,xmm1, (ge)",
          vcmpgeps(xmm5, xmm4, xmm1));
  COMPARE("c5d8c2ac8b102700000d vcmpps xmm5,xmm4,[rbx+rcx*4+0x2710], (ge)",
          vcmpgeps(xmm5, xmm4, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("c5d9c2e901           vcmppd xmm5,xmm4,xmm1, (lt)",
          vcmppd(xmm5, xmm4, xmm1, 1));
  COMPARE("c5d9c2ac8b1027000001 vcmppd xmm5,xmm4,[rbx+rcx*4+0x2710], (lt)",
          vcmppd(xmm5, xmm4, Operand(rbx, rcx, times_4, 10000), 1));
  COMPARE("c5d9c2e900           vcmppd xmm5,xmm4,xmm1, (eq)",
          vcmpeqpd(xmm5, xmm4, xmm1));
  COMPARE("c5d9c2ac8b1027000000 vcmppd xmm5,xmm4,[rbx+rcx*4+0x2710], (eq)",
          vcmpeqpd(xmm5, xmm4, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("c5d9c2e901           vcmppd xmm5,xmm4,xmm1, (lt)",
          vcmpltpd(xmm5, xmm4, xmm1));
  COMPARE("c5d9c2ac8b1027000001 vcmppd xmm5,xmm4,[rbx+rcx*4+0x2710], (lt)",
          vcmpltpd(xmm5, xmm4, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("c5d9c2e902           vcmppd xmm5,xmm4,xmm1, (le)",
          vcmplepd(xmm5, xmm4, xmm1));
  COMPARE("c5d9c2ac8b1027000002 vcmppd xmm5,xmm4,[rbx+rcx*4+0x2710], (le)",
          vcmplepd(xmm5, xmm4, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("c5d9c2e903           vcmppd xmm5,xmm4,xmm1, (unord)",
          vcmpunordpd(xmm5, xmm4, xmm1));
  COMPARE("c5d9c2ac8b1027000003 vcmppd xmm5,xmm4,[rbx+rcx*4+0x2710], (unord)",
          vcmpunordpd(xmm5, xmm4, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("c5d9c2e904           vcmppd xmm5,xmm4,xmm1, (neq)",
          vcmpneqpd(xmm5, xmm4, xmm1));
  COMPARE("c5d9c2ac8b1027000004 vcmppd xmm5,xmm4,[rbx+rcx*4+0x2710], (neq)",
          vcmpneqpd(xmm5, xmm4, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("c5d9c2e905           vcmppd xmm5,xmm4,xmm1, (nlt)",
          vcmpnltpd(xmm5, xmm4, xmm1));
  COMPARE("c5d9c2ac8b1027000005 vcmppd xmm5,xmm4,[rbx+rcx*4+0x2710], (nlt)",
          vcmpnltpd(xmm5, xmm4, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("c5d9c2e906           vcmppd xmm5,xmm4,xmm1, (nle)",
          vcmpnlepd(xmm5, xmm4, xmm1));
  COMPARE("c5d9c2ac8b1027000006 vcmppd xmm5,xmm4,[rbx+rcx*4+0x2710], (nle)",
          vcmpnlepd(xmm5, xmm4, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("c4e36921cb01         vinsertps xmm1,xmm2,xmm3,0x1",
          vinsertps(xmm1, xmm2, xmm3, 1));
  COMPARE("c4e369218c8b1027000001 vinsertps xmm1,xmm2,[rbx+rcx*4+0x2710],0x1",
          vinsertps(xmm1, xmm2, Operand(rbx, rcx, times_4, 10000), 1));
  COMPARE("c5fbf08c8b10270000   vlddqu xmm1,[rbx+rcx*4+0x2710]",
          vlddqu(xmm1, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("c4e36920c80c         vpinsrb xmm1,xmm2,al,0xc",
          vpinsrb(xmm1, xmm2, rax, 12));
  COMPARE("c4e369208c8b102700000c vpinsrb xmm1,xmm2,[rbx+rcx*4+0x2710],0xc",
          vpinsrb(xmm1, xmm2, Operand(rbx, rcx, times_4, 10000), 12));
  COMPARE("c5e9c4c805           vpinsrw xmm1,xmm2,rax,0x5",
          vpinsrw(xmm1, xmm2, rax, 5));
  COMPARE("c5e9c48c8b1027000005 vpinsrw xmm1,xmm2,[rbx+rcx*4+0x2710],0x5",
          vpinsrw(xmm1, xmm2, Operand(rbx, rcx, times_4, 10000), 5));
  COMPARE("c4e36922c802         vpinsrd xmm1,xmm2,rax,0x2",
          vpinsrd(xmm1, xmm2, rax, 2));
  COMPARE("c4e369228c8b1027000002 vpinsrd xmm1,xmm2,[rbx+rcx*4+0x2710],0x2",
          vpinsrd(xmm1, xmm2, Operand(rbx, rcx, times_4, 10000), 2));
  COMPARE("c4e3e922c809         vpinsrq xmm1,xmm2,rax,0x9",
          vpinsrq(xmm1, xmm2, rax, 9));
  COMPARE("c4e3e9228c8b1027000009 vpinsrq xmm1,xmm2,[rbx+rcx*4+0x2710],0x9",
          vpinsrq(xmm1, xmm2, Operand(rbx, rcx, times_4, 10000), 9));
  COMPARE("c5f970ca55           vpshufd xmm1,xmm2,0x55",
          vpshufd(xmm1, xmm2, 85));
  COMPARE("c5f9708c8b1027000055 vpshufd xmm1,[rbx+rcx*4+0x2710],0x55",
          vpshufd(xmm1, Operand(rbx, rcx, times_4, 10000), 85));
  COMPARE("c5fb70ca55           vpshuflw xmm1,xmm2,0x55",
          vpshuflw(xmm1, xmm2, 85));
  COMPARE("c5fb708c8b1027000055 vpshuflw xmm1,[rbx+rcx*4+0x2710],0x55",
          vpshuflw(xmm1, Operand(rbx, rcx, times_4, 10000), 85));
  COMPARE("c5fa70ca55           vpshufhw xmm1,xmm2,0x55",
          vpshufhw(xmm1, xmm2, 85));
  COMPARE("c5fa708c8b1027000055 vpshufhw xmm1,[rbx+rcx*4+0x2710],0x55",
          vpshufhw(xmm1, Operand(rbx, rcx, times_4, 10000), 85));
  COMPARE("c5e8c6db03           vshufps xmm3,xmm2,xmm3,0x3",
          vshufps(xmm3, xmm2, xmm3, 3));
  COMPARE("c4e3690ecb17         vpblendw xmm1,xmm2,xmm3,0x17",
          vpblendw(xmm1, xmm2, xmm3, 23));
  COMPARE("c4e3690e8c8b1027000017 vpblendw xmm1,xmm2,[rbx+rcx*4+0x2710],0x17",
          vpblendw(xmm1, xmm2, Operand(rbx, rcx, times_4, 10000), 23));
  COMPARE("c4e3690fcb04         vpalignr xmm1,xmm2,xmm3,0x4",
          vpalignr(xmm1, xmm2, xmm3, 4));
  COMPARE("c4e3690f8c8b1027000004 vpalignr xmm1,xmm2,[rbx+rcx*4+0x2710],0x4",
          vpalignr(xmm1, xmm2, Operand(rbx, rcx, times_4, 10000), 4));
  COMPARE("c4e3694ccb40         vpblendvb xmm1,xmm2,xmm3,xmm4",
          vpblendvb(xmm1, xmm2, xmm3, xmm4));
  COMPARE("c4e3694acb40         vblendvps xmm1,xmm2,xmm3,xmm4",
          vblendvps(xmm1, xmm2, xmm3, xmm4));
  COMPARE("c4e3694bcb40         vblendvpd xmm1,xmm2,xmm3,xmm4",
          vblendvpd(xmm1, xmm2, xmm3, xmm4));
  COMPARE("c5fb12ca             vmovddup xmm1,xmm2", vmovddup(xmm1, xmm2));
  COMPARE("c5fb128c8b10270000   vmovddup xmm1,[rbx+rcx*4+0x2710]",
          vmovddup(xmm1, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("c5fa16ca             vmovshdup xmm1,xmm2", vmovshdup(xmm1, xmm2));
  COMPARE("c4e279188c8b10270000 vbroadcastss xmm1,[rbx+rcx*4+0x2710]",
          vbroadcastss(xmm1, Operand(rbx, rcx, times_4, 10000)));
}

TEST_F(DisasmX64Test, DisasmX64CheckOutputVNNI) {
  if (!CpuFeatures::IsSupported(AVX_VNNI)) {
    return;
  }

  DisassemblerTester t;
  CpuFeatureScope scope(&t.assm_, AVX_VNNI);
  COMPARE("c4e26950cb           vpdpbusd xmm1,xmm2,xmm3",
          vpdpbusd(xmm1, xmm2, xmm3));
  COMPARE("c4622550c7           vpdpbusd ymm8,ymm11,ymm7",
          vpdpbusd(ymm8, ymm11, ymm7));
}

TEST_F(DisasmX64Test, DisasmX64CheckOutputF16C) {
  if (!CpuFeatures::IsSupported(F16C)) {
    return;
  }

  DisassemblerTester t;
  std::string actual, exp;
  CpuFeatureScope scope(&t.assm_, F16C);

  COMPARE("c4e27d13c1           vcvtph2ps ymm0,xmm1", vcvtph2ps(ymm0, xmm1));
  COMPARE("c4e27913d3           vcvtph2ps xmm2,xmm3", vcvtph2ps(xmm2, xmm3));
  COMPARE("c4e37d1dec00         vcvtps2ph xmm4,ymm5,0x0",
          vcvtps2ph(xmm4, ymm5, 0));
  COMPARE("c4e3791dfe00         vcvtps2ph xmm6,xmm7,0x0",
          vcvtps2ph(xmm6, xmm7, 0));
}

TEST_F(DisasmX64Test, DisasmX64YMMRegister) {
  if (!CpuFeatures::IsSupported(AVX)) return;
  DisassemblerTester t;

  {
    CpuFeatureScope fscope(t.assm(), FMA3);
    COMPARE("c4e26d98cc           vfmadd132ps ymm1,ymm2,ymm4",
            vfmadd132ps(ymm1, ymm2, ymm4));
    COMPARE("c4c255a8d9           vfmadd213ps ymm3,ymm5,ymm9",
            vfmadd213ps(ymm3, ymm5, ymm9));
    COMPARE("c4e265b8cd           vfmadd231ps ymm1,ymm3,ymm5",
            vfmadd231ps(ymm1, ymm3, ymm5));
    COMPARE("c4e26d9ccc           vfnmadd132ps ymm1,ymm2,ymm4",
            vfnmadd132ps(ymm1, ymm2, ymm4));
    COMPARE("c4c255acd9           vfnmadd213ps ymm3,ymm5,ymm9",
            vfnmadd213ps(ymm3, ymm5, ymm9));
    COMPARE("c4e265bccd           vfnmadd231ps ymm1,ymm3,ymm5",
            vfnmadd231ps(ymm1, ymm3, ymm5));
    COMPARE("c4e2ed98cc           vfmadd132pd ymm1,ymm2,ymm4",
            vfmadd132pd(ymm1, ymm2, ymm4));
    COMPARE("c4c2d5a8d9           vfmadd213pd ymm3,ymm5,ymm9",
            vfmadd213pd(ymm3, ymm5, ymm9));
    COMPARE("c4e2e5b8cd           vfmadd231pd ymm1,ymm3,ymm5",
            vfmadd231pd(ymm1, ymm3, ymm5));
    COMPARE("c4e2ed9ccc           vfnmadd132pd ymm1,ymm2,ymm4",
            vfnmadd132pd(ymm1, ymm2, ymm4));
    COMPARE("c4c2d5acd9           vfnmadd213pd ymm3,ymm5,ymm9",
            vfnmadd213pd(ymm3, ymm5, ymm9));
    COMPARE("c4e2e5bccd           vfnmadd231pd ymm1,ymm3,ymm5",
            vfnmadd231pd(ymm1, ymm3, ymm5));
  }

  {
    CpuFeatureScope fscope(t.assm(), AVX);

    // Short immediate instructions
    COMPARE("c5fd6fc1             vmovdqa ymm0,ymm1", vmovdqa(ymm0, ymm1));
    COMPARE("c5f77cc2             vhaddps ymm0,ymm1,ymm2",
            vhaddps(ymm0, ymm1, ymm2));
    COMPARE("c5f77c848b10270000   vhaddps ymm0,ymm1,[rbx+rcx*4+0x2710]",
            vhaddps(ymm0, ymm1, Operand(rbx, rcx, times_4, 10000)));
    COMPARE("c4e27d18bc8b10270000 vbroadcastss ymm7,[rbx+rcx*4+0x2710]",
            vbroadcastss(ymm7, Operand(rbx, rcx, times_4, 10000)));
    COMPARE("c4e27d19b48b10270000 vbroadcastsd ymm6,[rbx+rcx*4+0x2710]",
            vbroadcastsd(ymm6, Operand(rbx, rcx, times_4, 10000)));
    COMPARE("c5ff12da             vmovddup ymm3,ymm2", vmovddup(ymm3, ymm2));
    COMPARE("c5ff12a48b10270000   vmovddup ymm4,[rbx+rcx*4+0x2710]",
            vmovddup(ymm4, Operand(rbx, rcx, times_4, 10000)));
    COMPARE("c5fe16ca             vmovshdup ymm1,ymm2", vmovshdup(ymm1, ymm2));
    COMPARE("c5f4c6da73           vshufps ymm3,ymm1,ymm2,0x73",
            vshufps(ymm3, ymm1, ymm2, 115));
    COMPARE("c5fee6ca             vcvtdq2pd ymm1,xmm2", vcvtdq2pd(ymm1, xmm2));
    COMPARE("c5fee68c8b10270000   vcvtdq2pd ymm1,[rbx+rcx*4+0x2710]",
            vcvtdq2pd(ymm1, Operand(rbx, rcx, times_4, 10000)));
    COMPARE("c5fe5bda             vcvttps2dq ymm3,ymm2",
            vcvttps2dq(ymm3, ymm2));
    COMPARE("c5fe5b9c8b10270000   vcvttps2dq ymm3,[rbx+rcx*4+0x2710]",
            vcvttps2dq(ymm3, Operand256(rbx, rcx, times_4, 10000)));
    COMPARE("c4e36d06cb02         vperm2f128 ymm1,ymm2,ymm3,0x2",
            vperm2f128(ymm1, ymm2, ymm3, 2));

    // vcmp
    COMPARE("c5dcc2e900           vcmpps ymm5,ymm4,ymm1, (eq)",
            vcmpeqps(ymm5, ymm4, ymm1));
    COMPARE("c5ddc2ac8b1027000001 vcmppd ymm5,ymm4,[rbx+rcx*4+0x2710], (lt)",
            vcmpltpd(ymm5, ymm4, Operand(rbx, rcx, times_4, 10000)));
    COMPARE("c5ddc2e902           vcmppd ymm5,ymm4,ymm1, (le)",
            vcmplepd(ymm5, ymm4, ymm1));
    COMPARE("c5dcc2ac8b1027000003 vcmpps ymm5,ymm4,[rbx+rcx*4+0x2710], (unord)",
            vcmpunordps(ymm5, ymm4, Operand(rbx, rcx, times_4, 10000)));
    COMPARE("c5dcc2e904           vcmpps ymm5,ymm4,ymm1, (neq)",
            vcmpneqps(ymm5, ymm4, ymm1));
    COMPARE("c5ddc2ac8b1027000005 vcmppd ymm5,ymm4,[rbx+rcx*4+0x2710], (nlt)",
            vcmpnltpd(ymm5, ymm4, Operand(rbx, rcx, times_4, 10000)));
    COMPARE("c5ddc2ac8b1027000006 vcmppd ymm5,ymm4,[rbx+rcx*4+0x2710], (nle)",
            vcmpnlepd(ymm5, ymm4, Operand(rbx, rcx, times_4, 10000)));
    COMPARE("c5dcc2e90d           vcmpps ymm5,ymm4,ymm1, (ge)",
            vcmpgeps(ymm5, ymm4, ymm1));
    COMPARE("c4e27d17f9           vptest ymm7,ymm1", vptest(ymm7, ymm1));
    COMPARE("c4627d17948b10270000 vptest ymm10,[rbx+rcx*4+0x2710]",
            vptest(ymm10, Operand(rbx, rcx, times_4, 10000)));

    // SSE2_UNOP
    COMPARE("c5fd51ca             vsqrtpd ymm1,ymm2", vsqrtpd(ymm1, ymm2));
    COMPARE("c5fd518c8b10270000   vsqrtpd ymm1,[rbx+rcx*4+0x2710]",
            vsqrtpd(ymm1, Operand(rbx, rcx, times_4, 10000)));
    COMPARE("c5fd5adc             vcvtpd2ps xmm3,ymm4", vcvtpd2ps(xmm3, ymm4));
    COMPARE("c5fd5aa48b10270000   vcvtpd2ps xmm4,[rbx+rcx*4+0x2710]",
            vcvtpd2ps(xmm4, Operand256(rbx, rcx, times_4, 10000)));
    COMPARE("c5fd5bdc             vcvtps2dq ymm3,ymm4", vcvtps2dq(ymm3, ymm4));
    COMPARE("c5fd5bac8b10270000   vcvtps2dq ymm5,[rbx+rcx*4+0x2710]",
            vcvtps2dq(ymm5, Operand(rbx, rcx, times_4, 10000)));
    COMPARE("c4c17de6f8           vcvttpd2dq xmm7,ymm8",
            vcvttpd2dq(xmm7, ymm8));
    COMPARE("c57de68c8b10270000   vcvttpd2dq xmm9,[rbx+rcx*4+0x2710]",
            vcvttpd2dq(xmm9, Operand256(rbx, rcx, times_4, 10000)));
  }

  if (!CpuFeatures::IsSupported(AVX2)) return;
  {
    CpuFeatureScope fscope(t.assm(), AVX2);

    // Short immediate instructions
    COMPARE("c4e27d18d1           vbroadcastss ymm2,xmm1",
            vbroadcastss(ymm2, xmm1));
    COMPARE("c4e27d19f1           vbroadcastsd ymm6,xmm1",
            vbroadcastsd(ymm6, xmm1));
    COMPARE("c4e27d789c8b10270000 vpbroadcastb ymm3,[rbx+rcx*4+0x2710]",
            vpbroadcastb(ymm3, Operand(rbx, rcx, times_4, 10000)));
    COMPARE("c4e27d79d3           vpbroadcastw ymm2,xmm3",
            vpbroadcastw(ymm2, xmm3));
    COMPARE("c4c27d58f8           vpbroadcastd ymm7,xmm8",
            vpbroadcastd(ymm7, xmm8));
    COMPARE("c4627d588c8b10270000 vpbroadcastd ymm9,[rbx+rcx*4+0x2710]",
            vpbroadcastd(ymm9, Operand(rbx, rcx, times_4, 10000)));
    COMPARE("c4e27d1cca           vpabsb ymm1,ymm2", vpabsb(ymm1, ymm2));
    COMPARE("c4e27d1c9c8b10270000 vpabsb ymm3,[rbx+rcx*4+0x2710]",
            vpabsb(ymm3, Operand(rbx, rcx, times_4, 10000)));
    COMPARE("c4e27d1df5           vpabsw ymm6,ymm5", vpabsw(ymm6, ymm5));
    COMPARE("c4c27d1efa           vpabsd ymm7,ymm10", vpabsd(ymm7, ymm10));
    COMPARE("c4e3fd00ebd8         vpermq ymm5,ymm3,0xd8",
            vpermq(ymm5, ymm3, 0xD8));
    COMPARE("c463fd00848b102700001e vpermq ymm8,[rbx+rcx*4+0x2710],0x1e",
            vpermq(ymm8, Operand(rbx, rcx, times_4, 10000), 0x1E));

    // SSE4_UNOP
    COMPARE("c4e27d20f5           vpmovsxbw ymm6,ymm5", vpmovsxbw(ymm6, ymm5));
    COMPARE("c4e27d238c8b10270000 vpmovsxwd ymm1,[rbx+rcx*4+0x2710]",
            vpmovsxwd(ymm1, Operand(rbx, rcx, times_4, 10000)));
    COMPARE("c4627d25f6           vpmovsxdq ymm14,ymm6",
            vpmovsxdq(ymm14, ymm6));
    COMPARE("c4e27d30848b10270000 vpmovzxbw ymm0,[rbx+rcx*4+0x2710]",
            vpmovzxbw(ymm0, Operand(rbx, rcx, times_4, 10000)));
    COMPARE("c4627d31f6           vpmovzxbd ymm14,ymm6",
            vpmovzxbd(ymm14, ymm6));
    COMPARE("c4e27d33bc8b10270000 vpmovzxwd ymm7,[rbx+rcx*4+0x2710]",
            vpmovzxwd(ymm7, Operand(rbx, rcx, times_4, 10000)));
    COMPARE("c4627d35c6           vpmovzxdq ymm8,ymm6", vpmovzxdq(ymm8, ymm6));
  }
}

#undef __

}  // namespace internal
}  // namespace v8

"""


```