Response:
The user wants to understand the functionality of the provided C++ code snippet from a V8 unit test file. The file is named `disasm-x64-unittest.cc`, which suggests it's testing the disassembler for the x64 architecture.

Here's a breakdown of the thought process to analyze the code and answer the user's request:

1. **Identify the Core Functionality:** The file name and the presence of `COMPARE` macros strongly suggest this code tests the disassembler. It likely generates assembly instructions and then checks if the disassembler produces the expected string representation.

2. **Analyze the `COMPARE` Macros:** The `COMPARE` and `COMPARE_INSTR` macros are key.
    * `COMPARE(expected_string, assembler_call)`: This macro likely executes the `assembler_call` (which generates machine code), disassembles the generated code, and compares the resulting string with `expected_string`. The hex part is included.
    * `COMPARE_INSTR(expected_instruction_string, assembler_call)`:  This macro seems to do something similar but extracts only the instruction part of the disassembled output, skipping the hex representation. The `kHexOffset` variable confirms this.

3. **Examine the Test Structure:** The code is organized into `TEST_F` functions within the `DisasmX64Test` fixture. This is a standard Google Test pattern for unit tests. Each test function focuses on a specific set of instructions or CPU features.

4. **Identify Tested Instruction Categories:** The test function names (`DisasmX64CheckOutputSSE`, `DisasmX64CheckOutputSSE2`, `DisasmX64CheckOutputAVX`, etc.) clearly indicate that the tests cover different instruction set extensions (SSE, SSE2, AVX, etc.). The code within each test function calls assembler methods corresponding to these instruction sets.

5. **Infer the Testing Methodology:**  The code appears to be testing the *correctness* of the disassembler's output. It provides known machine code sequences (implicitly generated by the `assembler_call`) and verifies that the disassembler produces the expected human-readable assembly string.

6. **Address Specific User Questions:**
    * **File Type:** The filename ends with `.cc`, indicating it's a C++ source file, not a Torque file (`.tq`).
    * **Relationship to JavaScript:**  Disassemblers are crucial for debugging and understanding compiled code. While this specific test is low-level, the correct functioning of the disassembler is indirectly important for JavaScript performance and debugging in V8. When JavaScript code is compiled, the disassembler can be used to inspect the generated machine code.
    * **Code Logic and Examples:** The `COMPARE` macros provide implicit input (the assembler call) and expected output (the string). For example, `COMPARE("4889e0             REX.W movq rax,rsp", movq(rax, rsp));` tests that assembling `movq rax, rsp` and disassembling it results in the string `"4889e0             REX.W movq rax,rsp"`.
    * **Common Programming Errors:** This specific test file doesn't directly illustrate user programming errors. However, the disassembler itself can help developers identify errors in their generated machine code (if they were writing assembly directly, which is rare in typical V8 development). A common error would be incorrect operand encoding or using the wrong instruction.

7. **Summarize the Functionality:** Based on the analysis, the primary function is to unit test the x64 disassembler in V8. It verifies that the disassembler correctly translates machine code (generated by the assembler) back into human-readable assembly instructions for various x64 instruction set extensions.

8. **Structure the Answer:** Organize the findings logically, addressing each point raised in the user's prompt. Provide examples where requested and clarify any ambiguities. Emphasize the testing nature of the code.
这是对V8 JavaScript 引擎的 x64 架构反汇编器的单元测试代码的第二部分。它延续了第一部分的功能，并通过生成汇编指令并与预期的反汇编输出进行比较来测试反汇编器的正确性。

**功能归纳:**

这部分代码的主要功能是继续测试 V8 的 x64 反汇编器，重点测试了以下指令集和功能：

1. **SSE (Streaming SIMD Extensions):**  测试了各种 SSE 指令的反汇编，包括数据转换、算术运算、比较、移动指令等。
2. **SSE2 (Streaming SIMD Extensions 2):** 测试了 SSE2 指令的反汇编，包括数据转换、移动、比较、打包操作等。
3. **SSE3 (Streaming SIMD Extensions 3):** 测试了 SSE3 指令的反汇编，例如水平加法、特殊加载和移动指令。
4. **SSSE3 (Supplemental Streaming SIMD Extensions 3):** 测试了 SSSE3 指令的反汇编，例如字节对齐移动指令和其它 SIMD 操作。
5. **SSE4.1 (Streaming SIMD Extensions 4.1):** 测试了 SSE4.1 指令的反汇编，包括插入/提取、打包混合、比较等。
6. **SSE4.2 (Streaming SIMD Extensions 4.2):**  测试了 SSE4.2 指令的反汇编。
7. **AVX (Advanced Vector Extensions):** 测试了 AVX 指令的反汇编，AVX 是对 SSE 的扩展，支持更宽的向量寄存器 (YMM) 和新的指令编码方式。这部分测试了 AVX 对之前 SSE 和 SSE2 指令的扩展形式（以 `v` 开头的指令）。

**与 JavaScript 的关系:**

反汇编器是将机器码转换回汇编代码的工具。虽然这段代码本身不是直接用 JavaScript 编写的，但它对于 V8 引擎的正确运行至关重要。当 V8 编译 JavaScript 代码时，它会生成机器码。反汇编器可以用于：

* **调试 V8 引擎本身:** 开发人员可以使用反汇编器来检查 V8 生成的机器码是否符合预期，从而帮助定位编译器或代码生成器的错误。
* **性能分析:** 通过查看反汇编代码，可以更深入地了解 JavaScript 代码的执行方式，并识别潜在的性能瓶颈。虽然这通常不是直接由用户完成的，但这是 V8 内部优化过程的一部分。

**如果 `v8/test/unittests/assembler/disasm-x64-unittest.cc` 以 `.tq` 结尾:**

如果该文件以 `.tq` 结尾，那它将是一个 **Torque** 源代码文件。 Torque 是 V8 用于定义其内部运行时函数和内置对象的语言。  这个文件当前以 `.cc` 结尾，所以它是 C++ 代码。

**代码逻辑推理 (假设输入与输出):**

代码使用了 `COMPARE` 和 `COMPARE_INSTR` 宏来执行测试。 这些宏的逻辑是：

1. **输入 (隐式):**  通过 `t.assm_.ASM` 调用汇编器指令生成特定的机器码。例如，`t.assm_.movq(rax, rsp);` 会生成 `movq rax, rsp` 指令的机器码。
2. **执行:** 生成的机器码会被 V8 的反汇编器处理。
3. **输出:** 反汇编器将机器码转换为汇编代码的字符串表示。
4. **比较:** `COMPARE` 宏将反汇编器的输出与预期的字符串进行比较。

**示例 (基于代码中的片段):**

假设我们有以下测试用例：

```c++
COMPARE("4889e0             REX.W movq rax,rsp", movq(rax, rsp));
```

* **假设输入 (机器码):**  `48 89 e0` (这是 `movq rax, rsp` 的十六进制表示)
* **反汇编器处理:** V8 的反汇编器接收到 `48 89 e0` 这个字节序列。
* **预期输出:** 反汇编器应该输出字符串 `"4889e0             REX.W movq rax,rsp"`。
* **比较:** `COMPARE` 宏会检查反汇编器的实际输出是否与预期的字符串 `"4889e0             REX.W movq rax,rsp"` 相等。

**用户常见的编程错误 (与反汇编器本身的功能间接相关):**

虽然这段代码不直接涉及用户编写 JavaScript 代码时的错误，但反汇编器的存在可以帮助理解由于某些编程错误而产生的底层机器码：

* **类型错误导致的意外转换:**  在某些情况下，JavaScript 的类型转换可能会导致 V8 生成特定的指令序列。 通过反汇编，可以观察到这些转换是如何在底层实现的。
* **闭包和作用域问题:**  V8 如何处理闭包和不同的作用域也会反映在生成的机器码中。反汇编可以帮助理解这些机制。
* **性能问题:**  某些 JavaScript 代码模式可能会导致 V8 生成效率较低的机器码。通过反汇编，可以识别这些模式并进行优化。

**总结第 2 部分的功能:**

总而言之，这段代码是 V8 引擎中 x64 架构反汇编器的单元测试的第二部分。它通过生成各种 x64 指令（特别是 SSE、SSE2、SSE3、SSSE3、SSE4.1、SSE4.2 和 AVX 指令集的指令），然后断言反汇编器能够将这些指令正确地转换回其汇编语言表示形式，从而确保反汇编器的正确性和可靠性。这对于 V8 引擎的调试、性能分析和整体稳定性至关重要。

### 提示词
```
这是目录为v8/test/unittests/assembler/disasm-x64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/assembler/disasm-x64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
rax, Operand(rdx, 2)));
  COMPARE("480f4f4203           REX.W cmovgq rax,[rdx+0x3]",
          cmovq(greater, rax, Operand(rdx, 3)));
  COMPARE("4180f803             cmpb r8l,0x3", cmpb(r8, Immediate(0x3)));
  COMPARE("6681fa1008           cmpw rdx,0x810", cmpw(rdx, Immediate(0x810)));
  COMPARE("4180e208             andb r10l,0x8", andb(r10, Immediate(0x8)));
  COMPARE("4181e1ff3f0000       andl r9,0x3fff", andl(r9, Immediate(0x3fff)));
  COMPARE("4183e30f             andl r11,0xf", andl(r11, Immediate(0xf)));
  COMPARE("4883c418             REX.W addq rsp,0x18",
          addq(rsp, Immediate(0x18)));
  COMPARE("4881c1cd000000       REX.W addq rcx,0xcd",
          addq(rcx, Immediate(0xcd)));
}

// This compares just the disassemble instruction (without the hex).
// Requires a |std::string actual| to be in scope.
// Hard coded offset of 21, the hex part is 20 bytes, plus a space. If and when
// the padding changes, this should be adjusted.
constexpr int kHexOffset = 21;
#define COMPARE_INSTR(str, ASM)                                         \
  t.prev_offset = t.pc_offset();                                        \
  t.assm_.ASM;                                                          \
  actual = t.InstructionDecode();                                       \
  actual = std::string(actual, kHexOffset, actual.size() - kHexOffset); \
  CHECK_EQ(str, actual);

TEST_F(DisasmX64Test, DisasmX64CheckOutputSSE) {
  DisassemblerTester t;
  std::string actual;

  COMPARE("f30f2c948b10270000   cvttss2sil rdx,[rbx+rcx*4+0x2710]",
          cvttss2si(rdx, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("f30f2cd1             cvttss2sil rdx,xmm1", cvttss2si(rdx, xmm1));
  COMPARE("f3480f2a8c8b10270000 REX.W cvtsi2ss xmm1,[rbx+rcx*4+0x2710]",
          cvtqsi2ss(xmm1, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("f3480f2aca           REX.W cvtsi2ss xmm1,rdx", cvtqsi2ss(xmm1, rdx));
  COMPARE("f3480f5bc1           REX.W cvttps2dq xmm0,xmm1",
          cvttps2dq(xmm0, xmm1));
  COMPARE("f3480f5b848b10270000 REX.W cvttps2dq xmm0,[rbx+rcx*4+0x2710]",
          cvttps2dq(xmm0, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("0f28c1               movaps xmm0,xmm1", movaps(xmm0, xmm1));
  COMPARE("0f28848b10270000     movaps xmm0,[rbx+rcx*4+0x2710]",
          movaps(xmm0, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("66480f6f44240c       REX.W movdqa xmm0,[rsp+0xc]",
          movdqa(xmm0, Operand(rsp, 12)));
  COMPARE("66480f7f44240c       REX.W movdqa [rsp+0xc],xmm0",
          movdqa(Operand(rsp, 12), xmm0));
  COMPARE("f3480f6f44240c       REX.W movdqu xmm0,[rsp+0xc]",
          movdqu(xmm0, Operand(rsp, 12)));
  COMPARE("f3480f7f44240c       REX.W movdqu [rsp+0xc],xmm0",
          movdqu(Operand(rsp, 12), xmm0));
  COMPARE("f3480f6fc8           REX.W movdqu xmm1,xmm0", movdqu(xmm1, xmm0));
  COMPARE("0f12e9               movhlps xmm5,xmm1", movhlps(xmm5, xmm1));
  COMPARE("440f12848b10270000   movlps xmm8,[rbx+rcx*4+0x2710]",
          movlps(xmm8, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("440f138c8b10270000   movlps [rbx+rcx*4+0x2710],xmm9",
          movlps(Operand(rbx, rcx, times_4, 10000), xmm9));
  COMPARE("0f16e9               movlhps xmm5,xmm1", movlhps(xmm5, xmm1));
  COMPARE("440f16848b10270000   movhps xmm8,[rbx+rcx*4+0x2710]",
          movhps(xmm8, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("440f178c8b10270000   movhps [rbx+rcx*4+0x2710],xmm9",
          movhps(Operand(rbx, rcx, times_4, 10000), xmm9));
  COMPARE("410fc6c100           shufps xmm0,xmm9,0", shufps(xmm0, xmm9, 0x0));
  COMPARE("410fc6faff           shufps xmm7,xmm10,255",
          shufps(xmm7, xmm10, 0xff));
  COMPARE("f30fc2c100           cmpeqss xmm0,xmm1", cmpeqss(xmm0, xmm1));
  COMPARE("f20fc2c100           cmpeqsd xmm0,xmm1", cmpeqsd(xmm0, xmm1));
  COMPARE("0f2ec1               ucomiss xmm0,xmm1", ucomiss(xmm0, xmm1));
  COMPARE("0f2e848b10270000     ucomiss xmm0,[rbx+rcx*4+0x2710]",
          ucomiss(xmm0, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("410f50d1             movmskps rdx,xmm9", movmskps(rdx, xmm9));

  std::string exp;

#define COMPARE_SSE_INSTR(instruction, _, __)    \
  exp = #instruction " xmm1,xmm0";               \
  COMPARE_INSTR(exp, instruction(xmm1, xmm0));   \
  exp = #instruction " xmm1,[rbx+rcx*4+0x2710]"; \
  COMPARE_INSTR(exp, instruction(xmm1, Operand(rbx, rcx, times_4, 10000)));
  SSE_BINOP_INSTRUCTION_LIST(COMPARE_SSE_INSTR)
  SSE_UNOP_INSTRUCTION_LIST(COMPARE_SSE_INSTR)
#undef COMPARE_SSE_INSTR

#define COMPARE_SSE_INSTR(instruction, _, __, ___) \
  exp = #instruction " xmm1,xmm0";                 \
  COMPARE_INSTR(exp, instruction(xmm1, xmm0));     \
  exp = #instruction " xmm1,[rbx+rcx*4+0x2710]";   \
  COMPARE_INSTR(exp, instruction(xmm1, Operand(rbx, rcx, times_4, 10000)));
  SSE_INSTRUCTION_LIST_SS(COMPARE_SSE_INSTR)
#undef COMPARE_SSE_INSTR
}

TEST_F(DisasmX64Test, DisasmX64CheckOutputSSE2) {
  DisassemblerTester t;
  std::string actual, exp;

  COMPARE("f30fe6dc             cvtdq2pd xmm3,xmm4", cvtdq2pd(xmm3, xmm4));
  COMPARE("f20f2c948b10270000   cvttsd2sil rdx,[rbx+rcx*4+0x2710]",
          cvttsd2si(rdx, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("f20f2cd1             cvttsd2sil rdx,xmm1", cvttsd2si(rdx, xmm1));
  COMPARE("f2480f2cd1           REX.W cvttsd2siq rdx,xmm1",
          cvttsd2siq(rdx, xmm1));
  COMPARE("f2480f2c948b10270000 REX.W cvttsd2siq rdx,[rbx+rcx*4+0x2710]",
          cvttsd2siq(rdx, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("f20f2a8c8b10270000   cvtsi2sd xmm1,[rbx+rcx*4+0x2710]",
          cvtlsi2sd(xmm1, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("f20f2aca             cvtsi2sd xmm1,rdx", cvtlsi2sd(xmm1, rdx));
  COMPARE("f2480f2a8c8b10270000 REX.W cvtsi2sd xmm1,[rbx+rcx*4+0x2710]",
          cvtqsi2sd(xmm1, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("f2480f2aca           REX.W cvtsi2sd xmm1,rdx", cvtqsi2sd(xmm1, rdx));
  COMPARE("f3410f5ac9           cvtss2sd xmm1,xmm9", cvtss2sd(xmm1, xmm9));
  COMPARE("f30f5a8c8b10270000   cvtss2sd xmm1,[rbx+rcx*4+0x2710]",
          cvtss2sd(xmm1, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("f2410f2dd1           cvtsd2sil rdx,xmm9", cvtsd2si(rdx, xmm9));
  COMPARE("f2490f2dd1           REX.W cvtsd2siq rdx,xmm9",
          cvtsd2siq(rdx, xmm9););

  COMPARE("f20f108c8b10270000   movsd xmm1,[rbx+rcx*4+0x2710]",
          movsd(xmm1, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("f20f118c8b10270000   movsd [rbx+rcx*4+0x2710],xmm1",
          movsd(Operand(rbx, rcx, times_4, 10000), xmm1));
  COMPARE("660f10848b10270000   movupd xmm0,[rbx+rcx*4+0x2710]",
          movupd(xmm0, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("660f11848b10270000   movupd [rbx+rcx*4+0x2710],xmm0",
          movupd(Operand(rbx, rcx, times_4, 10000), xmm0));
  COMPARE("66480f6f848b10270000 REX.W movdqa xmm0,[rbx+rcx*4+0x2710]",
          movdqa(xmm0, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("66480f7f848b10270000 REX.W movdqa [rbx+rcx*4+0x2710],xmm0",
          movdqa(Operand(rbx, rcx, times_4, 10000), xmm0));
  COMPARE("66480f7fc8           REX.W movdqa xmm0,xmm1", movdqa(xmm0, xmm1));
  COMPARE("660f2ec1             ucomisd xmm0,xmm1", ucomisd(xmm0, xmm1));
  COMPARE("66440f2e849310270000 ucomisd xmm8,[rbx+rdx*4+0x2710]",
          ucomisd(xmm8, Operand(rbx, rdx, times_4, 10000)));
  COMPARE("f2410fc2db01         cmpltsd xmm3,xmm11", cmpltsd(xmm3, xmm11));
  COMPARE("66410f50d1           movmskpd rdx,xmm9", movmskpd(rdx, xmm9));
  COMPARE("66410fd7d1           pmovmskb r9,xmm2", pmovmskb(rdx, xmm9));
  COMPARE("660f76c8             pcmpeqd xmm1,xmm0", pcmpeqd(xmm1, xmm0));
  COMPARE("66410f62cb           punpckldq xmm1,xmm11", punpckldq(xmm1, xmm11));
  COMPARE("660f626a04           punpckldq xmm5,[rdx+0x4]",
          punpckldq(xmm5, Operand(rdx, 4)));
  COMPARE("66450f6ac7           punpckhdq xmm8,xmm15", punpckhdq(xmm8, xmm15));
  COMPARE("f20f70d403           pshuflw xmm2,xmm4,3", pshuflw(xmm2, xmm4, 3));
  COMPARE("f20f70948b10270000ff pshuflw xmm2,[rbx+rcx*4+0x2710],255",
          pshuflw(xmm2, Operand(rbx, rcx, times_4, 10000), 0xff));
  COMPARE("f3410f70c906         pshufhw xmm1,xmm9,6", pshufhw(xmm1, xmm9, 6));
  COMPARE("f30f708c8b10270000ff pshufhw xmm1,[rbx+rcx*4+0x2710],255",
          pshufhw(xmm1, Operand(rbx, rcx, times_4, 10000), 0xff));
  COMPARE("660fc4d101           pinsrw xmm2,rcx,0x1", pinsrw(xmm2, rcx, 1));

#define COMPARE_SSE2_INSTR(instruction, _, __, ___) \
  exp = #instruction " xmm1,xmm0";                  \
  COMPARE_INSTR(exp, instruction(xmm1, xmm0));      \
  exp = #instruction " xmm1,[rbx+rcx*4+0x2710]";    \
  COMPARE_INSTR(exp, instruction(xmm1, Operand(rbx, rcx, times_4, 10000)));
  SSE2_INSTRUCTION_LIST(COMPARE_SSE2_INSTR)
  SSE2_UNOP_INSTRUCTION_LIST(COMPARE_SSE2_INSTR)
  SSE2_INSTRUCTION_LIST_SD(COMPARE_SSE2_INSTR)
#undef COMPARE_SSE2_INSTR

#define COMPARE_SSE2_SHIFT_IMM(instruction, _, __, ___, ____) \
  exp = #instruction " xmm3,35";                              \
  COMPARE_INSTR(exp, instruction(xmm3, 0xA3));
  SSE2_INSTRUCTION_LIST_SHIFT_IMM(COMPARE_SSE2_SHIFT_IMM)
#undef COMPARE_SSE2_SHIFT_IMM
}

TEST_F(DisasmX64Test, DisasmX64CheckOutputSSE3) {
  if (!CpuFeatures::IsSupported(SSE3)) {
    return;
  }

  DisassemblerTester t;
  CpuFeatureScope scope(&t.assm_, SSE3);

  COMPARE("f20f7cc8             haddps xmm1,xmm0", haddps(xmm1, xmm0));
  COMPARE("f20f7c8c8b10270000   haddps xmm1,[rbx+rcx*4+0x2710]",
          haddps(xmm1, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("f20ff04a04           lddqu xmm1,[rdx+0x4]",
          lddqu(xmm1, Operand(rdx, 4)));
  COMPARE("f20f124805           movddup xmm1,[rax+0x5]",
          movddup(xmm1, Operand(rax, 5)));
  COMPARE("f20f12ca             movddup xmm1,xmm2", movddup(xmm1, xmm2));
  COMPARE("f30f16ca             movshdup xmm1,xmm2", movshdup(xmm1, xmm2));
}

TEST_F(DisasmX64Test, DisasmX64CheckOutputSSSE3) {
  if (!CpuFeatures::IsSupported(SSSE3)) {
    return;
  }

  DisassemblerTester t;
  std::string actual, exp;
  CpuFeatureScope scope(&t.assm_, SSSE3);

  COMPARE("660f3a0fe905         palignr xmm5,xmm1,0x5", palignr(xmm5, xmm1, 5));
  COMPARE("660f3a0f6a0405       palignr xmm5,[rdx+0x4],0x5",
          palignr(xmm5, Operand(rdx, 4), 5));

#define COMPARE_SSSE3_INSTR(instruction, _, __, ___, ____) \
  exp = #instruction " xmm5,xmm1";                         \
  COMPARE_INSTR(exp, instruction(xmm5, xmm1));             \
  exp = #instruction " xmm5,[rbx+rcx*4+0x2710]";           \
  COMPARE_INSTR(exp, instruction(xmm5, Operand(rbx, rcx, times_4, 10000)));
  SSSE3_INSTRUCTION_LIST(COMPARE_SSSE3_INSTR)
  SSSE3_UNOP_INSTRUCTION_LIST(COMPARE_SSSE3_INSTR)
#undef COMPARE_SSSE3_INSTR
}

TEST_F(DisasmX64Test, DisasmX64CheckOutputSSE4_1) {
  if (!CpuFeatures::IsSupported(SSE4_1)) {
    return;
  }

  DisassemblerTester t;
  std::string actual, exp;
  CpuFeatureScope scope(&t.assm_, SSE4_1);

  COMPARE("660f3a21e97b         insertps xmm5,xmm1,0x7b",
          insertps(xmm5, xmm1, 123));
  COMPARE("66490f3a16c401       REX.W pextrq r12,xmm0,1", pextrq(r12, xmm0, 1));
  COMPARE("66450f3a20c90f       pinsrb xmm9,r9,15", pinsrb(xmm9, r9, 0xf));
  COMPARE("66440f3a208c8b102700000f pinsrb xmm9,[rbx+rcx*4+0x2710],15",
          pinsrb(xmm9, Operand(rbx, rcx, times_4, 10000), 0xf));
  COMPARE("66450f3a22c900       pinsrd xmm9,r9,0", pinsrd(xmm9, r9, 0));
  COMPARE("660f3a22680401       pinsrd xmm5,[rax+0x4],1",
          pinsrd(xmm5, Operand(rax, 4), 1));
  COMPARE("664d0f3a22c900       REX.W pinsrq xmm9,r9,0", pinsrq(xmm9, r9, 0));
  COMPARE("66480f3a22680401     REX.W pinsrq xmm5,[rax+0x4],1",
          pinsrq(xmm5, Operand(rax, 4), 1));
  COMPARE("660f3a0ee901         pblendw xmm5,xmm1,0x1", pblendw(xmm5, xmm1, 1));
  COMPARE("66440f3a0e480401     pblendw xmm9,[rax+0x4],0x1",
          pblendw(xmm9, Operand(rax, 4), 1));
  COMPARE("0fc2e901             cmpps xmm5, xmm1, lt", cmpps(xmm5, xmm1, 1));
  COMPARE("0fc2ac8b1027000001   cmpps xmm5, [rbx+rcx*4+0x2710], lt",
          cmpps(xmm5, Operand(rbx, rcx, times_4, 10000), 1));
  COMPARE("0fc2e900             cmpps xmm5, xmm1, eq", cmpeqps(xmm5, xmm1));
  COMPARE("0fc2ac8b1027000000   cmpps xmm5, [rbx+rcx*4+0x2710], eq",
          cmpeqps(xmm5, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("0fc2e901             cmpps xmm5, xmm1, lt", cmpltps(xmm5, xmm1));
  COMPARE("0fc2ac8b1027000001   cmpps xmm5, [rbx+rcx*4+0x2710], lt",
          cmpltps(xmm5, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("0fc2e902             cmpps xmm5, xmm1, le", cmpleps(xmm5, xmm1));
  COMPARE("0fc2ac8b1027000002   cmpps xmm5, [rbx+rcx*4+0x2710], le",
          cmpleps(xmm5, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("0fc2e903             cmpps xmm5, xmm1, unord",
          cmpunordps(xmm5, xmm1));
  COMPARE("0fc2ac8b1027000003   cmpps xmm5, [rbx+rcx*4+0x2710], unord",
          cmpunordps(xmm5, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("0fc2e904             cmpps xmm5, xmm1, neq", cmpneqps(xmm5, xmm1));
  COMPARE("0fc2ac8b1027000004   cmpps xmm5, [rbx+rcx*4+0x2710], neq",
          cmpneqps(xmm5, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("0fc2e905             cmpps xmm5, xmm1, nlt", cmpnltps(xmm5, xmm1));
  COMPARE("0fc2ac8b1027000005   cmpps xmm5, [rbx+rcx*4+0x2710], nlt",
          cmpnltps(xmm5, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("0fc2e906             cmpps xmm5, xmm1, nle", cmpnleps(xmm5, xmm1));
  COMPARE("0fc2ac8b1027000006   cmpps xmm5, [rbx+rcx*4+0x2710], nle",
          cmpnleps(xmm5, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("660fc2e901           cmppd xmm5,xmm1, (lt)", cmppd(xmm5, xmm1, 1));
  COMPARE("660fc2ac8b1027000001 cmppd xmm5,[rbx+rcx*4+0x2710], (lt)",
          cmppd(xmm5, Operand(rbx, rcx, times_4, 10000), 1));
  COMPARE("660fc2e900           cmppd xmm5,xmm1, (eq)", cmpeqpd(xmm5, xmm1));
  COMPARE("660fc2ac8b1027000000 cmppd xmm5,[rbx+rcx*4+0x2710], (eq)",
          cmpeqpd(xmm5, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("660fc2e901           cmppd xmm5,xmm1, (lt)", cmpltpd(xmm5, xmm1));
  COMPARE("660fc2ac8b1027000001 cmppd xmm5,[rbx+rcx*4+0x2710], (lt)",
          cmpltpd(xmm5, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("660fc2e902           cmppd xmm5,xmm1, (le)", cmplepd(xmm5, xmm1));
  COMPARE("660fc2ac8b1027000002 cmppd xmm5,[rbx+rcx*4+0x2710], (le)",
          cmplepd(xmm5, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("660fc2e903           cmppd xmm5,xmm1, (unord)",
          cmpunordpd(xmm5, xmm1));
  COMPARE("660fc2ac8b1027000003 cmppd xmm5,[rbx+rcx*4+0x2710], (unord)",
          cmpunordpd(xmm5, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("660fc2e904           cmppd xmm5,xmm1, (neq)", cmpneqpd(xmm5, xmm1));
  COMPARE("660fc2ac8b1027000004 cmppd xmm5,[rbx+rcx*4+0x2710], (neq)",
          cmpneqpd(xmm5, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("660fc2e905           cmppd xmm5,xmm1, (nlt)", cmpnltpd(xmm5, xmm1));
  COMPARE("660fc2ac8b1027000005 cmppd xmm5,[rbx+rcx*4+0x2710], (nlt)",
          cmpnltpd(xmm5, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("660fc2e906           cmppd xmm5,xmm1, (nle)", cmpnlepd(xmm5, xmm1));
  COMPARE("660fc2ac8b1027000006 cmppd xmm5,[rbx+rcx*4+0x2710], (nle)",
          cmpnlepd(xmm5, Operand(rbx, rcx, times_4, 10000)));

  COMPARE("0f10e9               movups xmm5,xmm1", movups(xmm5, xmm1));
  COMPARE("0f106a04             movups xmm5,[rdx+0x4]",
          movups(xmm5, Operand(rdx, 4)));
  COMPARE("0f116a04             movups [rdx+0x4],xmm5",
          movups(Operand(rdx, 4), xmm5));
  COMPARE("660f3840e9           pmulld xmm5,xmm1", pmulld(xmm5, xmm1));
  COMPARE("660f38406a04         pmulld xmm5,[rdx+0x4]",
          pmulld(xmm5, Operand(rdx, 4)));
  COMPARE("660fd5e9             pmullw xmm5,xmm1", pmullw(xmm5, xmm1));
  COMPARE("660fd56a04           pmullw xmm5,[rdx+0x4]",
          pmullw(xmm5, Operand(rdx, 4)));
  COMPARE("660ff4e9             pmuludq xmm5,xmm1", pmuludq(xmm5, xmm1));
  COMPARE("660ff46a04           pmuludq xmm5,[rdx+0x4]",
          pmuludq(xmm5, Operand(rdx, 4)));
  COMPARE("660f73dd7b           psrlq xmm5,123", psrldq(xmm5, 123));
  COMPARE("660f70e903           pshufd xmm5,xmm1,0x3", pshufd(xmm5, xmm1, 3));
  COMPARE("660f5be9             cvtps2dq xmm5,xmm1", cvtps2dq(xmm5, xmm1));
  COMPARE("660f5b6a04           cvtps2dq xmm5,[rdx+0x4]",
          cvtps2dq(xmm5, Operand(rdx, 4)));
  COMPARE("0f5be9               cvtdq2ps xmm5,xmm1", cvtdq2ps(xmm5, xmm1));
  COMPARE("0f5b6a04             cvtdq2ps xmm5,[rdx+0x4]",
          cvtdq2ps(xmm5, Operand(rdx, 4)));
  COMPARE("660f3810e9           pblendvb xmm5,xmm1,<xmm0>",
          pblendvb(xmm5, xmm1));
  COMPARE("660f3814e9           blendvps xmm5,xmm1,<xmm0>",
          blendvps(xmm5, xmm1));
  COMPARE("660f38146a04         blendvps xmm5,[rdx+0x4],<xmm0>",
          blendvps(xmm5, Operand(rdx, 4)));
  COMPARE("660f3815e9           blendvpd xmm5,xmm1,<xmm0>",
          blendvpd(xmm5, xmm1));
  COMPARE("660f38156a04         blendvpd xmm5,[rdx+0x4],<xmm0>",
          blendvpd(xmm5, Operand(rdx, 4)));
  COMPARE("66440f3a08c30a       roundps xmm8,xmm3,0x2",
          roundps(xmm8, xmm3, kRoundUp));
  COMPARE("66440f3a09c308       roundpd xmm8,xmm3,0x0",
          roundpd(xmm8, xmm3, kRoundToNearest));
  COMPARE("66440f3a0ac309       roundss xmm8,xmm3,0x1",
          roundss(xmm8, xmm3, kRoundDown));
  COMPARE("66440f3a0a420b09     roundss xmm8,[rdx+0xb],0x1",
          roundss(xmm8, Operand(rdx, 11), kRoundDown));
  COMPARE("66440f3a0bc309       roundsd xmm8,xmm3,0x1",
          roundsd(xmm8, xmm3, kRoundDown));
  COMPARE("66440f3a0b420b09     roundsd xmm8,[rdx+0xb],0x1",
          roundsd(xmm8, Operand(rdx, 11), kRoundDown));

#define COMPARE_SSE4_1_INSTR(instruction, _, __, ___, ____) \
  exp = #instruction " xmm5,xmm1";                          \
  COMPARE_INSTR(exp, instruction(xmm5, xmm1));              \
  exp = #instruction " xmm5,[rbx+rcx*4+0x2710]";            \
  COMPARE_INSTR(exp, instruction(xmm5, Operand(rbx, rcx, times_4, 10000)));
  SSE4_INSTRUCTION_LIST(COMPARE_SSE4_1_INSTR)
  SSE4_UNOP_INSTRUCTION_LIST(COMPARE_SSE4_1_INSTR)
#undef COMPARE_SSSE3_INSTR

#define COMPARE_SSE4_EXTRACT_INSTR(instruction, _, __, ___, ____) \
  exp = #instruction " rbx,xmm15,3";                              \
  COMPARE_INSTR(exp, instruction(rbx, xmm15, 3));                 \
  exp = #instruction " [rax+0xa],xmm0,1";                         \
  COMPARE_INSTR(exp, instruction(Operand(rax, 10), xmm0, 1));
  SSE4_EXTRACT_INSTRUCTION_LIST(COMPARE_SSE4_EXTRACT_INSTR)
#undef COMPARE_SSE4_EXTRACT_INSTR
}

TEST_F(DisasmX64Test, DisasmX64CheckOutputSSE4_2) {
  if (!CpuFeatures::IsSupported(SSE4_2)) {
    return;
  }

  DisassemblerTester t;
  std::string actual, exp;
  CpuFeatureScope scope(&t.assm_, SSE4_2);

#define COMPARE_SSE4_2_INSTR(instruction, _, __, ___, ____) \
  exp = #instruction " xmm5,xmm1";                          \
  COMPARE_INSTR(exp, instruction(xmm5, xmm1));              \
  exp = #instruction " xmm5,[rbx+rcx*4+0x2710]";            \
  COMPARE_INSTR(exp, instruction(xmm5, Operand(rbx, rcx, times_4, 10000)));
  SSE4_2_INSTRUCTION_LIST(COMPARE_SSE4_2_INSTR)
#undef COMPARE_SSE4_2_INSTR
}

TEST_F(DisasmX64Test, DisasmX64CheckOutputAVX) {
  if (!CpuFeatures::IsSupported(AVX)) {
    return;
  }

  DisassemblerTester t;
  std::string actual, exp;
  CpuFeatureScope scope(&t.assm_, AVX);

#define COMPARE_AVX_INSTR(instruction, _, __)                                  \
  exp = "v" #instruction " xmm9,xmm5";                                         \
  COMPARE_INSTR(exp, v##instruction(xmm9, xmm5));                              \
  exp = "v" #instruction " xmm9,[rbx+rcx*4+0x2710]";                           \
  COMPARE_INSTR(exp, v##instruction(xmm9, Operand(rbx, rcx, times_4, 10000))); \
  exp = "v" #instruction " ymm9,ymm5";                                         \
  COMPARE_INSTR(exp, v##instruction(ymm9, ymm5));                              \
  exp = "v" #instruction " ymm9,[rbx+rcx*4+0x2710]";                           \
  COMPARE_INSTR(exp, v##instruction(ymm9, Operand(rbx, rcx, times_4, 10000)));
  SSE_UNOP_INSTRUCTION_LIST(COMPARE_AVX_INSTR)
#undef COMPARE_AVX_INSTR

#define COMPARE_AVX_INSTR(instruction, _, __)                              \
  exp = "v" #instruction " xmm9,xmm5,xmm2";                                \
  COMPARE_INSTR(exp, v##instruction(xmm9, xmm5, xmm2));                    \
  exp = "v" #instruction " xmm9,xmm5,[rbx+rcx*4+0x2710]";                  \
  COMPARE_INSTR(                                                           \
      exp, v##instruction(xmm9, xmm5, Operand(rbx, rcx, times_4, 10000))); \
  exp = "v" #instruction " ymm9,ymm5,ymm2";                                \
  COMPARE_INSTR(exp, v##instruction(ymm9, ymm5, ymm2));                    \
  exp = "v" #instruction " ymm9,ymm5,[rbx+rcx*4+0x2710]";                  \
  COMPARE_INSTR(                                                           \
      exp, v##instruction(ymm9, ymm5, Operand(rbx, rcx, times_4, 10000)));
  SSE_BINOP_INSTRUCTION_LIST(COMPARE_AVX_INSTR)
#undef COMPARE_AVX_INSTR

#define COMPARE_AVX_INSTR(instruction, _, __, ___)   \
  exp = "v" #instruction " xmm9,xmm2";               \
  COMPARE_INSTR(exp, v##instruction(xmm9, xmm2));    \
  exp = "v" #instruction " xmm9,[rbx+rcx*4+0x2710]"; \
  COMPARE_INSTR(exp, v##instruction(xmm9, Operand(rbx, rcx, times_4, 10000)));
  SSE2_UNOP_INSTRUCTION_LIST(COMPARE_AVX_INSTR)
#undef COMPARE_AVX_INSTR

#define COMPARE_AVX_INSTR(instruction, _, __, ___)        \
  exp = "v" #instruction " xmm9,xmm5,xmm2";               \
  COMPARE_INSTR(exp, v##instruction(xmm9, xmm5, xmm2));   \
  exp = "v" #instruction " xmm9,xmm5,[rbx+rcx*4+0x2710]"; \
  COMPARE_INSTR(                                          \
      exp, v##instruction(xmm9, xmm5, Operand(rbx, rcx, times_4, 10000)));
  SSE_INSTRUCTION_LIST_SS(COMPARE_AVX_INSTR)
  SSE2_INSTRUCTION_LIST(COMPARE_AVX_INSTR)
  SSE2_INSTRUCTION_LIST_SD(COMPARE_AVX_INSTR)
#undef COMPARE_AVX_INSTR

#define COMPARE_AVX_INSTR(instruction, _, __, ___, ____)  \
  exp = "v" #instruction " xmm9,xmm5,xmm2";               \
  COMPARE_INSTR(exp, v##instruction(xmm9, xmm5, xmm2));   \
  exp = "v" #instruction " xmm9,xmm5,[rbx+rcx*4+0x2710]"; \
  COMPARE_INSTR(                                          \
      exp, v##instruction(xmm9, xmm5, Operand(rbx, rcx, times_4, 10000)));
  SSSE3_INSTRUCTION_LIST(COMPARE_AVX_INSTR)
  SSE4_INSTRUCTION_LIST(COMPARE_AVX_INSTR)
  SSE4_2_INSTRUCTION_LIST(COMPARE_AVX_INSTR)
#undef COMPARE_AVX_INSTR

#define COMPARE_AVX_INSTR(instruction, _, __, ___, ____) \
  exp = "v" #instruction " xmm9,xmm2";                   \
  COMPARE_INSTR(exp, v##instruction(xmm9, xmm2));        \
  exp = "v" #instruction " xmm9,[rbx+rcx*4+0x2710]";     \
  COMPARE_INSTR(exp, v##instruction(xmm9, Operand(rbx, rcx, times_4, 10000)));
  SSSE3_UNOP_INSTRUCTION_LIST(COMPARE_AVX_INSTR)
  SSE4_UNOP_INSTRUCTION_LIST(COMPARE_AVX_INSTR)
#undef COMPARE_AVX_INSTR

#define COMPARE_AVX_INSTR(instruction, _, __, ___, ____) \
  exp = "v" #instruction " xmm9,xmm2,21";                \
  COMPARE_INSTR(exp, v##instruction(xmm9, xmm2, 21));
  SSE2_INSTRUCTION_LIST_SHIFT_IMM(COMPARE_AVX_INSTR)
#undef COMPARE_AVX_INSTR

#define COMPARE_AVX_INSTR(instruction, reg)          \
  exp = "v" #instruction " " #reg ",xmm15,0x3";      \
  COMPARE_INSTR(exp, v##instruction(rbx, xmm15, 3)); \
  exp = "v" #instruction " [rax+0xa],xmm15,0x3";     \
  COMPARE_INSTR(exp, v##instruction(Operand(rax, 10), xmm15, 3));
  COMPARE_AVX_INSTR(extractps, rbx)
  COMPARE_AVX_INSTR(pextrb, bl)
  COMPARE_AVX_INSTR(pextrw, rbx)
  COMPARE_INSTR("vpextrq rbx,xmm15,0x3", vpextrq(rbx, xmm15, 3));
#undef COMPARE_AVX_INSTR

  COMPARE("c58a10f2             vmovss xmm6,xmm14,xmm2",
          vmovss(xmm6, xmm14, xmm2));
  COMPARE("c57a108c8b10270000   vmovss xmm9,[rbx+rcx*4+0x2710]",
          vmovss(xmm9, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("c5fa11848b10270000   vmovss [rbx+rcx*4+0x2710],xmm0",
          vmovss(Operand(rbx, rcx, times_4, 10000), xmm0));
  COMPARE("c4417a108ccbf0d8ffff vmovss xmm9,[r11+rcx*8-0x2710]",
          vmovss(xmm9, Operand(r11, rcx, times_8, -10000)));
  COMPARE("c4a17a118c8b10270000 vmovss [rbx+r9*4+0x2710],xmm1",
          vmovss(Operand(rbx, r9, times_4, 10000), xmm1));
  COMPARE("c532c2c900           vcmpss xmm9,xmm9,xmm1, (eq)",
          vcmpeqss(xmm9, xmm1));
  COMPARE("c533c2c900           vcmpsd xmm9,xmm9,xmm1, (eq)",
          vcmpeqsd(xmm9, xmm1));
  COMPARE("c5782ec9             vucomiss xmm9,xmm1", vucomiss(xmm9, xmm1));
  COMPARE("c5782e8453e52a0000   vucomiss xmm8,[rbx+rdx*2+0x2ae5]",
          vucomiss(xmm8, Operand(rbx, rdx, times_2, 10981)));
  COMPARE("c5f96eef             vmovd xmm5,rdi", vmovd(xmm5, rdi));
  COMPARE("c5796e8c8b10270000   vmovd xmm9,[rbx+rcx*4+0x2710]",
          vmovd(xmm9, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("c4c1797ef1           vmovd r9,xmm6", vmovd(r9, xmm6));
  COMPARE("c4e1f96eef           vmovq xmm5,rdi", vmovq(xmm5, rdi));
  COMPARE("c461f96e8c8b10270000 vmovq xmm9,[rbx+rcx*4+0x2710]",
          vmovq(xmm9, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("c4c1f97ef1           vmovq r9,xmm6", vmovq(r9, xmm6));
  COMPARE("c58b10f2             vmovsd xmm6,xmm14,xmm2",
          vmovsd(xmm6, xmm14, xmm2));
  COMPARE("c57b108c8b10270000   vmovsd xmm9,[rbx+rcx*4+0x2710]",
          vmovsd(xmm9, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("c5fb11848b10270000   vmovsd [rbx+rcx*4+0x2710],xmm0",
          vmovsd(Operand(rbx, rcx, times_4, 10000), xmm0));
  COMPARE("c5f96fe5             vmovdqa xmm4,xmm5", vmovdqa(xmm4, xmm5));
  COMPARE("c5f96fa48b10270000   vmovdqa xmm4,[rbx+rcx*4+0x2710]",
          vmovdqa(xmm4, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("c5fd6fe5             vmovdqa ymm4,ymm5", vmovdqa(ymm4, ymm5));
  COMPARE("c5f96fa48b10270000   vmovdqa xmm4,[rbx+rcx*4+0x2710]",
          vmovdqa(xmm4, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("c57a6f8c8b10270000   vmovdqu xmm9,[rbx+rcx*4+0x2710]",
          vmovdqu(xmm9, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("c5fa7f848b10270000   vmovdqu [rbx+rcx*4+0x2710],xmm0",
          vmovdqu(Operand(rbx, rcx, times_4, 10000), xmm0));
  COMPARE("c5fa7fec             vmovdqu xmm4,xmm5", vmovdqu(xmm4, xmm5));
  COMPARE("c57e6f8c8b10270000   vmovdqu ymm9,[rbx+rcx*4+0x2710]",
          vmovdqu(ymm9, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("c5fe7f848b10270000   vmovdqu [rbx+rcx*4+0x2710],ymm0",
          vmovdqu(Operand(rbx, rcx, times_4, 10000), ymm0));
  COMPARE("c5fe7fec             vmovdqu ymm4,ymm5", vmovdqu(ymm4, ymm5));
  COMPARE("c5e012cd             vmovhlps xmm1,xmm3,xmm5",
          vmovhlps(xmm1, xmm3, xmm5));
  COMPARE("c53012848b10270000   vmovlps xmm8,xmm9,[rbx+rcx*4+0x2710]",
          vmovlps(xmm8, xmm9, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("c578138c8b10270000   vmovlps [rbx+rcx*4+0x2710],xmm9",
          vmovlps(Operand(rbx, rcx, times_4, 10000), xmm9));
  COMPARE("c5e016cd             vmovlhps xmm1,xmm3,xmm5",
          vmovlhps(xmm1, xmm3, xmm5));
  COMPARE("c53016848b10270000   vmovhps xmm8,xmm9,[rbx+rcx*4+0x2710]",
          vmovhps(xmm8, xmm9, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("c57817a48b10270000   vmovhps [rbx+rcx*4+0x2710],xmm12",
          vmovhps(Operand(rbx, rcx, times_4, 10000), xmm12));
  COMPARE("c4637908ca0a         vroundps xmm9,xmm2,0xa",
          vroundps(xmm9, xmm2, kRoundUp));
  COMPARE("c4637909ca08         vroundpd xmm9,xmm2,0x8",
          vroundpd(xmm9, xmm2, kRoundToNearest));
  COMPARE("c463710aca09         vroundss xmm9,xmm1,xmm2,0x9",
          vroundss(xmm9, xmm1, xmm2, kRoundDown));
  COMPARE("c463610bc009         vroundsd xmm8,xmm3,xmm0,0x9",
          vroundsd(xmm8, xmm3, xmm0, kRoundDown));
  COMPARE("c5792ec9             vucomisd xmm9,xmm1", vucomisd(xmm9, xmm1));
  COMPARE("c5792e8453e52a0000   vucomisd xmm8,[rbx+rdx*2+0x2ae5]",
          vucomisd(xmm8, Operand(rbx, rdx, times_2, 10981)));
  COMPARE("c4417ae6cb           vcvtdq2pd xmm9,xmm11", vcvtdq2pd(xmm9, xmm11));
  COMPARE("c4c1325ae3           vcvtss2sd xmm4,xmm9,xmm11",
          vcvtss2sd(xmm4, xmm9, xmm11));
  COMPARE("c5b25aa40b10270000   vcvtss2sd xmm4,xmm9,[rbx+rcx*1+0x2710]",
          vcvtss2sd(xmm4, xmm9, Operand(rbx, rcx, times_1, 10000)));
  COMPARE("c4c17a5be3           vcvttps2dq xmm4,xmm11",
          vcvttps2dq(xmm4, xmm11));
  COMPARE("c5b32ae9             vcvtlsi2sd xmm5,xmm9,rcx",
          vcvtlsi2sd(xmm5, xmm9, rcx));
  COMPARE("c421632a8c8b10270000 vcvtlsi2sd xmm9,xmm3,[rbx+r9*4+0x2710]",
          vcvtlsi2sd(xmm9, xmm3, Operand(rbx, r9, times_4, 10000)));
  COMPARE("c4c1b32aeb           vcvtqsi2sd xmm5,xmm9,r11",
          vcvtqsi2sd(xmm5, xmm9, r11));
  COMPARE("c57b2cce             vcvttsd2si r9,xmm6", vcvttsd2si(r9, xmm6));
  COMPARE("c4a17b2c848b10270000 vcvttsd2si rax,[rbx+r9*4+0x2710]",
          vcvttsd2si(rax, Operand(rbx, r9, times_4, 10000)));
  COMPARE("c4c1fb2cf9           vcvttsd2siq rdi,xmm9", vcvttsd2siq(rdi, xmm9));
  COMPARE("c441fb2c849910270000 vcvttsd2siq r8,[r9+rbx*4+0x2710]",
          vcvttsd2siq(r8, Operand(r9, rbx, times_4, 10000)));
  COMPARE("c4c17b2df9           vcvtsd2si rdi,xmm9", vcvtsd2si(rdi, xmm9));
  COMPARE("c4417828d3           vmovaps xmm10,xmm11", vmovaps(xmm10, xmm11));
  COMPARE("c5f828848b10270000   vmovaps xmm0,[rbx+rcx*4+0x2710]",
          vmovaps(xmm0, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("c5f928f8             vmovapd xmm7,xmm0", vmovapd(xmm7, xmm0));
  COMPARE("c5f910848b10270000   vmovupd xmm0,[rbx+rcx*4+0x2710]",
          vmovupd(xmm0, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("c5f911848b10270000   vmovupd [rbx+rcx*4+0x2710],xmm0",
          vmovupd(Operand(rbx, rcx, times_4, 10000), xmm0));
  COMPARE("c57950cc             vmovmskpd r9,xmm4", vmovmskpd(r9, xmm4));
  COMPARE("c44179d7d1           vpmovmskb r10,xmm9", vpmovmskb(r10, xmm9));
  COMPARE("c5f810e9             vmovups xmm5,xmm1", vmovups(xmm5, xmm1));
  COMPARE("c5f8106a04           vmovups xmm5,[rdx+0x4]",
          vmovups(xmm5, Operand(rdx, 4)));
  COMPARE("c5f8116a04           vmovups [rdx+0x4],xmm5",
          vmovups(Operand(rdx, 4), xmm5));
  COMPARE("c4c1737cc1           vhaddps xmm0,xmm1,xmm9",
          vhaddps(xmm0, xmm1, xmm9));
  COMPARE("c5f37c848b10270000   vhaddps xmm0,xmm1,[rbx+rcx*4+0x2710]",
          vhaddps(xmm0, xmm1, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("c5f77cc2             vhaddps ymm0,ymm1,ymm2",
          vhaddps(ymm0, ymm1, ymm2));
  COMPARE("c5f77c848b10270000   vhaddps ymm0,ymm1,[rbx+rcx*4+0x2710]",
          vhaddps(ymm0, ymm1, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("c58176c5             vpcmpeqd xmm0,xmm15,xmm5",
          vpcmpeqd(xmm0, xmm15, xmm5));
  COMPARE("c57976bc8b10270000   vpcmpeqd xmm15,xmm0,[rbx+rcx*4+0x2710]",
          vpcmpeqd(xmm15, xmm0, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("c5d8c2e901           vcmpps xmm5,xmm4,xmm1, (lt)",
          vcmpps(xmm5, xmm4, xmm1, 1));
  COMPARE("c5d8c2ac8b1027000001 vcmpps xmm5,xmm4,[rbx+rcx*4+0x2710], (lt)",
          vcmpps(xmm5, xmm4, Operand(rbx, rcx, times_4, 10000), 1));
  COMPARE("c5d8c2e900           vcmpps xmm5,xmm4,xmm1, (eq)",
          vcmpeqps(xmm5, xmm4, xmm1));
  COMPARE("c5d8c2ac8b1027000000 vcmpps xmm5,xmm4,[rbx+rcx*4+0x2710], (eq)",
          vcmpeqps(xmm5, xmm4, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("c5d8c2e901           vcmpps xmm5,xmm4,xmm1, (lt)",
          vcmpltps(xmm5, xmm4, xmm1));
  COMPARE("c5d8c2ac8b1027000001 vcmpps xmm5,xmm4,[rbx+rcx*4+0x2710], (lt)",
          vcmpltps(xmm5, xmm4, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("c5d8c2e902           vcmpps xmm5,xmm4,xmm1, (le)",
          vcmpleps(xmm5, xmm4, xmm1));
  COMPARE("c5d8c2ac8b1027000002 vcmpps xmm5,xmm4,[rbx+rcx*4+0x2710], (le)",
          vcmpleps(xmm5, xmm4, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("c5d8c2e903           vcmpps xmm5,xmm4,xmm1, (unord)",
          vcmpunordps(xmm5, xmm4, xmm1));
  COMPARE("c5d8c2ac8b1027000003 vcmpps xmm5,xmm4,[rbx+rcx*4+0x2710], (unord)",
          vcmpunordps(xmm5, xmm4, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("c5d8c2e904           vcmpps xmm5,xmm4,xmm1, (neq)",
          vcmpneqps(xmm5, xmm4, xmm1));
  COMPARE("c5d8c2ac8b1027000004 vcmpps xmm5,xmm4,[rbx+rcx*4+0x2710], (neq)",
          vcmpneqps(xmm5, xmm4, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("c5d8c2e905           vcmpps xmm5,xmm4,xmm1, (nlt)",
          vcmpnltps(xmm5, xmm4, xmm1));
  COMPARE("c5d8c2ac8b1027000005 vcmpps xmm5,xmm4,[rbx+rcx*4+0x2710], (nlt)",
          vcmpnltps(xmm5, xmm4, Operand(rbx, rcx, times_4, 10000)));
  COMPARE("c5d8c2e906           vcmpps xmm5,xmm4,xmm1, (nle)",
          vcmpnleps(xmm5, xmm4, xmm1));
  COMPARE("c5d8c2ac8b1027000006 vcmpps xmm5,xmm4,[rbx+rcx*4+0x2710], (nle)",
          vcmpnleps(xmm5
```