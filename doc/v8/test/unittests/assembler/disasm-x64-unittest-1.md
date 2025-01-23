Response:
The user wants a summary of the functionality of the provided C++ code snippet. Here's a breakdown of the thought process to achieve that:

1. **Identify the core purpose:** The filename `disasm-x64-unittest.cc` strongly suggests this code is for *testing the disassembler for the x64 architecture*. The `unittest` part reinforces this.

2. **Examine the structure:** The code is structured using the Google Test framework (`TEST_F`). Each `TEST_F` function represents a specific test case.

3. **Analyze individual test cases:** Look for patterns within the test cases. The `COMPARE` macro is used extensively. This macro likely compares the output of the disassembler for a given instruction (the byte sequence) against an expected output (the assembly mnemonic).

4. **Identify tested features:**  The names of the test functions (e.g., `DisasmX64CheckOutputVNNI`, `DisasmX64CheckOutputF16C`, `DisasmX64YMMRegister`) indicate the specific CPU features or instruction categories being tested. Terms like "VNNI," "F16C," and "YMM register" are key indicators.

5. **Recognize the role of CPU feature detection:** The `if (!CpuFeatures::IsSupported(...))` checks are crucial. This means the tests are conditional based on whether the CPU supports the given feature. This is essential for ensuring the disassembler correctly handles instructions that might not be available on all x64 processors.

6. **Infer the `COMPARE` macro's function:** Given the context, the `COMPARE` macro likely:
    * Takes a byte sequence (string representation of machine code).
    * Feeds this byte sequence to the V8 disassembler.
    * Compares the disassembler's output with the provided assembly instruction string.
    * Asserts that the two outputs are identical.

7. **Connect to JavaScript (if applicable):** The prompt asks about relevance to JavaScript. While this specific code is low-level C++, it's testing a *component* of the V8 JavaScript engine. The disassembler is used for debugging, profiling, and potentially JIT compilation analysis, all of which are relevant to JavaScript performance and behavior. However, there's no direct, easy-to-show JavaScript code equivalent to these assembly instructions. The connection is more about the underlying infrastructure.

8. **Address Torque (if applicable):** The prompt mentions `.tq` files. This file *ends* in `.cc`, so it's C++, not Torque.

9. **Identify potential programming errors:** The tests implicitly demonstrate correct usage of assembly instructions. By showing the *correct* way to encode instructions, they highlight potential errors a programmer might make when trying to generate machine code manually (though this is rare in typical V8 development). A common error might be incorrect operand encoding or using an instruction not supported by the target architecture.

10. **Formulate the summary:** Combine the observations into a concise summary:
    * State the file's purpose: testing the x64 disassembler.
    * Mention the use of the `COMPARE` macro for verifying disassembly.
    * List the tested CPU features and instruction sets (AVX, AVX2, FMA3, F16C, VNNI).
    * Explain the conditional testing based on CPU feature support.
    * Address the JavaScript connection (indirect, via V8 engine components).
    * Address the Torque question (not a Torque file).
    * Briefly touch on potential programming errors (incorrect instruction encoding).

11. **Refine the language:** Ensure the summary is clear, concise, and uses appropriate technical terms. Organize the points logically.
这是第3部分，我们来归纳一下 `v8/test/unittests/assembler/disasm-x64-unittest.cc` 的功能。

**综合前两部分和当前部分，`v8/test/unittests/assembler/disasm-x64-unittest.cc` 的主要功能是：**

**对 V8 引擎的 x64 架构反汇编器进行单元测试。**

具体来说，它通过一系列的测试用例来验证反汇编器是否能正确地将 x64 架构的机器码指令反汇编成可读的汇编代码。

**以下是更详细的归纳：**

* **测试反汇编各种 x64 指令:**  代码包含了大量针对不同 x64 指令的测试用例，涵盖了：
    * **基本指令:**  例如 `mov`, `add`, `sub`, `jmp` 等 (在之前的片段中)。
    * **SIMD 指令 (SSE, AVX, AVX2, FMA, F16C, VNNI):** 例如 `vmovdqa`, `vhaddps`, `vfmadd132ps`, `vcvtph2ps`, `vpdpbusd` 等。这些指令用于处理向量数据，是现代处理器优化的重要组成部分。
    * **不同操作数类型的指令:**  测试了寄存器-寄存器，寄存器-内存，内存-寄存器等不同的操作数组合。
    * **带有立即数的指令:** 测试了指令中包含立即数的情况。
    * **不同编码格式的指令:**  测试了指令的不同编码方式。

* **使用 `COMPARE` 宏进行断言:**  每个测试用例都使用 `COMPARE` 宏来比较：
    * **输入的机器码 (以十六进制字符串表示):**  这是要被反汇编的原始字节码。
    * **期望的反汇编结果 (以汇编语言字符串表示):**  这是预期的反汇编输出。
    如果实际的反汇编结果与期望的结果不符，测试将会失败。

* **条件性测试特定 CPU 特性:**  代码使用了 `CpuFeatures::IsSupported` 来判断当前 CPU 是否支持特定的指令集扩展 (例如 AVX, F16C, VNNI)。如果不支持，相关的测试用例将会被跳过，这确保了测试在不同的硬件平台上都能正常运行。

* **测试 YMM 寄存器:**  专门的测试用例 `DisasmX64Test::DisasmX64YMMRegister`  用于验证反汇编器对 AVX 指令中使用的 256 位 YMM 寄存器的处理是否正确。

**关于您提出的问题：**

* **`.tq` 结尾:**  `v8/test/unittests/assembler/disasm-x64-unittest.cc` 以 `.cc` 结尾，因此它是 C++ 源代码，而不是 V8 Torque 源代码。

* **与 JavaScript 的关系:**  虽然这段代码本身是 C++，但它测试的是 V8 JavaScript 引擎的一个关键组件——x64 反汇编器。反汇编器在 V8 中有以下用途：
    * **调试:** 开发者可以使用反汇编器来检查生成的机器码，以理解代码的执行流程和性能瓶颈。
    * **性能分析:**  反汇编结果可以用于性能分析工具，帮助理解代码在底层是如何执行的。
    * **JIT 编译分析:**  理解即时编译器生成的机器码对于优化 JavaScript 代码至关重要。

    **JavaScript 示例 (间接关系):**

    假设 V8 引擎将以下 JavaScript 代码编译成了某种机器码：

    ```javascript
    function add(a, b) {
      return a + b;
    }
    ```

    开发人员可能会使用 V8 提供的工具（例如 `--print-code` 命令行标志）来查看 `add` 函数编译后的机器码。 V8 的反汇编器就会被用来将这些机器码转换成可读的汇编指令，类似于 `disasm-x64-unittest.cc` 中测试的那些指令。

* **代码逻辑推理:**  测试用例的逻辑是比较直接的：
    * **假设输入 (机器码):** 例如 `"c5d8c2e90d"`
    * **预期输出 (汇编代码):** `"vcmpps xmm5,xmm4,xmm1, (ge)"`
    如果反汇编器将输入的机器码 `"c5d8c2e90d"` 反汇编成其他任何字符串，测试就会失败。

* **用户常见的编程错误:**  虽然这个单元测试不直接涉及用户的 JavaScript 编程错误，但它隐含地验证了 V8 引擎在处理底层机器码时的正确性。 如果反汇编器出现错误，可能会导致调试信息不准确，或者在某些极端情况下，影响到 JIT 编译器的正确性。

**总结来说，`v8/test/unittests/assembler/disasm-x64-unittest.cc` 是 V8 引擎中一个重要的测试文件，它通过大量的测试用例来确保 x64 反汇编器的正确性和可靠性，这对于 V8 的调试、性能分析和 JIT 编译等功能至关重要。**

### 提示词
```
这是目录为v8/test/unittests/assembler/disasm-x64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/assembler/disasm-x64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```
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
```