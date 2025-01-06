Response:
The user wants me to analyze a C++ source code snippet from V8, specifically `v8/test/unittests/assembler/assembler-x64-unittest.cc`, and describe its functionality.

Here's a breakdown of the thought process to address the user's request:

1. **Identify the Core Purpose:** The filename `assembler-x64-unittest.cc` strongly suggests that this code is a unit test for the x64 assembler within V8. Unit tests verify the correct behavior of individual components, in this case, the assembler's ability to generate specific x64 instructions.

2. **Scan for Key Patterns:**  Look for common patterns in unit test code. This snippet contains:
    * `TEST_F(AssemblerX64Test, ...)`: This is the Google Test framework syntax for defining test cases within a fixture class (`AssemblerX64Test`). Each `TEST_F` block represents an individual test.
    * `Isolate* isolate = i_isolate(); HandleScope scope(isolate);`:  This is standard V8 setup for creating an isolated execution environment for the test.
    * `MacroAssembler masm(...)` or `Assembler masm(...)`: This instantiates the assembler class, which is the core component being tested.
    * `__ instruction(...)`: The double underscore prefix is a convention in V8's assembler to emit x64 assembly instructions. The names following the `__` directly correspond to x64 mnemonics (e.g., `movsd`, `addq`, `mulss`).
    * `CHECK_EQ(...)`:  Another Google Test macro used to assert that two values are equal, verifying the outcome of the generated code.
    * `GeneratedCode<F*>::FromCode(...)`:  This part executes the generated assembly code within the test. `F*` likely represents a function signature (e.g., `int(double, double, double)`).
    * Conditional checks like `if (!CpuFeatures::IsSupported(FMA3)) return;`: This indicates that some tests are specific to certain CPU features.

3. **Analyze Individual Test Cases:** Examine the instructions within each `TEST_F` block to understand what specific functionality is being tested. Focus on the core operations and the expected outcomes.
    * **`AssemblerX64FMA_sd`:**  Tests the FMA (Fused Multiply-Add) instructions for double-precision floating-point numbers (`sd`). It checks the `vfmadd`, `vfmsub`, `vfnmadd`, and `vfnmsub` variants with different operand orderings (132, 213, 231) and with memory operands.
    * **`AssemblerX64FMA_ss`:**  Similar to the above but tests the FMA instructions for single-precision floating-point numbers (`ss`).
    * **`AssemblerX64SSE_ss`:** Tests various SSE (Streaming SIMD Extensions) instructions for single-precision floating-point numbers like `maxss`, `minss`, `subss`, `addss`, `mulss`, and `divss`. It checks the results of these operations.
    * **`AssemblerX64AVX_ss`:** Tests AVX (Advanced Vector Extensions) equivalents of the SSE instructions for single-precision floats, using the `v` prefix (e.g., `vmaxss`, `vminss`). It also tests moving data to/from memory using AVX.
    * **`AssemblerX64AVX_sd`:** Tests various AVX instructions for double-precision floats (`sd`), including arithmetic operations (`vmaxsd`, `vminsd`, `vsubsd`, `vaddsd`, `vmulsd`, `vdivsd`), conversions (`vcvtsd2ss`, `vcvtss2sd`, `vcvttsd2si`, `vcvttsd2siq`, `vcvtlsi2sd`, `vcvtqsi2sd`, `vcvtsd2si`), bitwise operations (`vpcmpeqd`, `vpsllq`, `vpsrlq`, `vandpd`, `vorpd`, `vxorpd`), and other operations like `vsqrtsd`, `vroundsd`, and `vmovmskpd`.
    * **`AssemblerX64BMI1`:** Tests BMI (Bit Manipulation Instructions) set 1, including instructions like `andn`, `bextr`, `blsi`, `blsmsk`, `blsr`, and `tzcnt`.
    * **`AssemblerX64LZCNT`:** Tests the `lzcnt` (Leading Zero Count) instruction.
    * **`AssemblerX64POPCNT`:** Tests the `popcnt` (Population Count) instruction.
    * **`AssemblerX64BMI2`:** Tests BMI set 2 instructions like `bzhi`, `mulx`, `pdep`, `pext`, `sarx`, `shlx`, and `shrx`.

4. **Identify Javascript Relevance (if any):**  While this code directly tests assembly generation, its purpose is to ensure the correctness of low-level operations that *underlie* JavaScript execution. For example, floating-point arithmetic in JavaScript relies on these underlying assembly instructions.

5. **Formulate Javascript Examples (if relevant):**  Create simple JavaScript snippets that would eventually be translated (or use) the assembly instructions being tested. Focus on the equivalent high-level operations.

6. **Infer Code Logic and Provide Examples:** For each test, identify the input values (often passed as arguments to the generated code) and the expected output (verified using `CHECK_EQ`). Provide concrete examples to illustrate the behavior of the tested instructions.

7. **Highlight Potential Programming Errors:** Think about common mistakes developers might make when dealing with the types of operations being tested (e.g., incorrect operand order for FMA, misunderstanding bit manipulation instructions).

8. **Synthesize the Functionality Summary:** Combine the analysis of individual tests into a concise summary of the overall functionality of the code snippet. Emphasize that it's a unit test for the x64 assembler, focusing on various instruction sets and their correct implementation.

9. **Address the ".tq" and Javascript Relationship Questions:** Explicitly answer the questions about the `.tq` extension and the connection to JavaScript based on the analysis.

By following these steps, I can systematically analyze the provided code snippet and generate a comprehensive and accurate description of its functionality, including relevant examples and potential pitfalls.
好的，这是对提供的代码片段的功能归纳：

**功能归纳：**

这段代码是 `v8/test/unittests/assembler/assembler-x64-unittest.cc` 文件的第二部分，主要功能是**测试 V8 的 x64 汇编器生成 FMA (Fused Multiply-Add)、SSE (Streaming SIMD Extensions)、AVX (Advanced Vector Extensions) 以及 BMI (Bit Manipulation Instructions) 等指令集的正确性**。

具体来说，它包含了多个独立的测试用例（以 `TEST_F(AssemblerX64Test, ...)` 开头），每个测试用例针对一组特定的指令或指令变体进行验证：

* **FMA 指令测试 (`AssemblerX64FMA_sd`, `AssemblerX64FMA_ss`):**  测试 `vfmadd` (fused multiply-add)、`vfmsub` (fused multiply-subtract)、`vfnmadd` (fused negative multiply-add) 和 `vfnmsub` (fused negative multiply-subtract) 等指令在双精度 (`sd`) 和单精度 (`ss`) 浮点数上的各种操作数排列方式（例如，132, 213, 231）以及与内存操作数的结合使用。
* **SSE 指令测试 (`AssemblerX64SSE_ss`):** 测试 SSE 指令集中的浮点数运算指令，如 `maxss` (最大值)、`minss` (最小值)、`subss` (减法)、`addss` (加法)、`mulss` (乘法) 和 `divss` (除法)。
* **AVX 指令测试 (`AssemblerX64AVX_ss`, `AssemblerX64AVX_sd`):** 测试 AVX 指令集中的浮点数运算指令，包括单精度 (`ss`) 和双精度 (`sd`) 的加减乘除、最大最小值，以及类型转换指令（例如 `vcvtsd2ss`, `vcvtss2sd`）、位操作指令（例如 `vpcmpeqd`, `vpsllq`, `vpsrlq`, `vandpd`, `vorpd`, `vxorpd`）、平方根 (`vsqrtsd`)、舍入 (`vroundsd`) 和数据移动指令 (`vmovmskpd`) 等。
* **BMI 指令测试 (`AssemblerX64BMI1`, `AssemblerX64BMI2`, `AssemblerX64LZCNT`, `AssemblerX64POPCNT`):** 测试 BMI1 和 BMI2 指令集中的位操作指令，例如 `andn` (与非)、`bextr` (位提取)、`blsi` (最低位设置)、`blsmsk` (最低位设置掩码)、`blsr` (清除最低位设置)、`tzcnt` (尾部零计数)、`lzcnt` (前导零计数)、`popcnt` (人口计数)、`bzhi` (零扩展高位)、`mulx` (无进位乘法)、`pdep` (并行位写入)、`pext` (并行位提取)、`sarx` (算术右移)、`shlx` (逻辑左移) 和 `shrx` (逻辑右移) 等。

每个测试用例都会生成一段汇编代码，然后执行这段代码，并使用 `CHECK_EQ` 宏来断言执行结果是否符合预期。这确保了汇编器能够正确地将高级指令转换为底层的机器码。

**与之前部分的关系：**

可以推断，第一部分可能包含一些基础的汇编器测试，或者设置测试环境和辅助函数。后续的第三部分和第四部分可能会继续测试其他指令集或更复杂的汇编场景。

**总结：**

这段代码片段专注于**验证 x64 汇编器在处理浮点数运算（FMA, SSE, AVX）和位操作（BMI）相关指令时的正确性**，是 V8 代码质量保证的重要组成部分。

Prompt: 
```
这是目录为v8/test/unittests/assembler/assembler-x64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/assembler/assembler-x64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
m8, xmm0);
    __ movsd(Operand(rsp, 0), xmm1);
    __ vfnmsub132sd(xmm8, xmm2, Operand(rsp, 0));
    __ ucomisd(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfnmsub213sd
    __ incq(rax);
    __ movaps(xmm8, xmm1);
    __ movsd(Operand(rsp, 0), xmm2);
    __ vfnmsub213sd(xmm8, xmm0, Operand(rsp, 0));
    __ ucomisd(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfnmsub231sd
    __ incq(rax);
    __ movaps(xmm8, xmm2);
    __ movsd(Operand(rsp, 0), xmm1);
    __ vfnmsub231sd(xmm8, xmm0, Operand(rsp, 0));
    __ ucomisd(xmm8, xmm3);
    __ j(not_equal, &exit);

    __ xorl(rax, rax);
    __ bind(&exit);
    __ addq(rsp, Immediate(kDoubleSize));
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

  auto f = GeneratedCode<F7>::FromCode(isolate, *code);
  CHECK_EQ(
      0, f.Call(0.000092662107262076, -2.460774966188315, -1.0958787393627414));
}

using F8 = int(float x, float y, float z);
TEST_F(AssemblerX64Test, AssemblerX64FMA_ss) {
  if (!CpuFeatures::IsSupported(FMA3)) return;

  Isolate* isolate = i_isolate();
  HandleScope scope(isolate);
  uint8_t buffer[1024];
  MacroAssembler masm(isolate, v8::internal::CodeObjectRequired::kYes,
                      ExternalAssemblerBuffer(buffer, sizeof(buffer)));
  {
    CpuFeatureScope fscope(&masm, FMA3);
    Label exit;
    // arguments in xmm0, xmm1 and xmm2
    // xmm0 * xmm1 + xmm2
    __ movaps(xmm3, xmm0);
    __ mulss(xmm3, xmm1);
    __ addss(xmm3, xmm2);  // Expected result in xmm3

    __ AllocateStackSpace(kDoubleSize);  // For memory operand
    // vfmadd132ss
    __ movl(rax, Immediate(1));  // Test number
    __ movaps(xmm8, xmm0);
    __ vfmadd132ss(xmm8, xmm2, xmm1);
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfmadd213ss
    __ incq(rax);
    __ movaps(xmm8, xmm1);
    __ vfmadd213ss(xmm8, xmm0, xmm2);
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfmadd231ss
    __ incq(rax);
    __ movaps(xmm8, xmm2);
    __ vfmadd231ss(xmm8, xmm0, xmm1);
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);

    // vfmadd132ss
    __ incq(rax);
    __ movaps(xmm8, xmm0);
    __ movss(Operand(rsp, 0), xmm1);
    __ vfmadd132ss(xmm8, xmm2, Operand(rsp, 0));
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfmadd213ss
    __ incq(rax);
    __ movaps(xmm8, xmm1);
    __ movss(Operand(rsp, 0), xmm2);
    __ vfmadd213ss(xmm8, xmm0, Operand(rsp, 0));
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfmadd231ss
    __ incq(rax);
    __ movaps(xmm8, xmm2);
    __ movss(Operand(rsp, 0), xmm1);
    __ vfmadd231ss(xmm8, xmm0, Operand(rsp, 0));
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);

    // xmm0 * xmm1 - xmm2
    __ movaps(xmm3, xmm0);
    __ mulss(xmm3, xmm1);
    __ subss(xmm3, xmm2);  // Expected result in xmm3

    // vfmsub132ss
    __ incq(rax);
    __ movaps(xmm8, xmm0);
    __ vfmsub132ss(xmm8, xmm2, xmm1);
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfmadd213ss
    __ incq(rax);
    __ movaps(xmm8, xmm1);
    __ vfmsub213ss(xmm8, xmm0, xmm2);
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfmsub231ss
    __ incq(rax);
    __ movaps(xmm8, xmm2);
    __ vfmsub231ss(xmm8, xmm0, xmm1);
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);

    // vfmsub132ss
    __ incq(rax);
    __ movaps(xmm8, xmm0);
    __ movss(Operand(rsp, 0), xmm1);
    __ vfmsub132ss(xmm8, xmm2, Operand(rsp, 0));
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfmsub213ss
    __ incq(rax);
    __ movaps(xmm8, xmm1);
    __ movss(Operand(rsp, 0), xmm2);
    __ vfmsub213ss(xmm8, xmm0, Operand(rsp, 0));
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfmsub231ss
    __ incq(rax);
    __ movaps(xmm8, xmm2);
    __ movss(Operand(rsp, 0), xmm1);
    __ vfmsub231ss(xmm8, xmm0, Operand(rsp, 0));
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);

    // - xmm0 * xmm1 + xmm2
    __ movaps(xmm3, xmm0);
    __ mulss(xmm3, xmm1);
    __ Move(xmm4, static_cast<uint32_t>(1) << 31);
    __ xorps(xmm3, xmm4);
    __ addss(xmm3, xmm2);  // Expected result in xmm3

    // vfnmadd132ss
    __ incq(rax);
    __ movaps(xmm8, xmm0);
    __ vfnmadd132ss(xmm8, xmm2, xmm1);
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfmadd213ss
    __ incq(rax);
    __ movaps(xmm8, xmm1);
    __ vfnmadd213ss(xmm8, xmm0, xmm2);
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfnmadd231ss
    __ incq(rax);
    __ movaps(xmm8, xmm2);
    __ vfnmadd231ss(xmm8, xmm0, xmm1);
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);

    // vfnmadd132ss
    __ incq(rax);
    __ movaps(xmm8, xmm0);
    __ movss(Operand(rsp, 0), xmm1);
    __ vfnmadd132ss(xmm8, xmm2, Operand(rsp, 0));
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfnmadd213ss
    __ incq(rax);
    __ movaps(xmm8, xmm1);
    __ movss(Operand(rsp, 0), xmm2);
    __ vfnmadd213ss(xmm8, xmm0, Operand(rsp, 0));
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfnmadd231ss
    __ incq(rax);
    __ movaps(xmm8, xmm2);
    __ movss(Operand(rsp, 0), xmm1);
    __ vfnmadd231ss(xmm8, xmm0, Operand(rsp, 0));
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);

    // - xmm0 * xmm1 - xmm2
    __ movaps(xmm3, xmm0);
    __ mulss(xmm3, xmm1);
    __ Move(xmm4, static_cast<uint32_t>(1) << 31);
    __ xorps(xmm3, xmm4);
    __ subss(xmm3, xmm2);  // Expected result in xmm3

    // vfnmsub132ss
    __ incq(rax);
    __ movaps(xmm8, xmm0);
    __ vfnmsub132ss(xmm8, xmm2, xmm1);
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfmsub213ss
    __ incq(rax);
    __ movaps(xmm8, xmm1);
    __ vfnmsub213ss(xmm8, xmm0, xmm2);
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfnmsub231ss
    __ incq(rax);
    __ movaps(xmm8, xmm2);
    __ vfnmsub231ss(xmm8, xmm0, xmm1);
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);

    // vfnmsub132ss
    __ incq(rax);
    __ movaps(xmm8, xmm0);
    __ movss(Operand(rsp, 0), xmm1);
    __ vfnmsub132ss(xmm8, xmm2, Operand(rsp, 0));
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfnmsub213ss
    __ incq(rax);
    __ movaps(xmm8, xmm1);
    __ movss(Operand(rsp, 0), xmm2);
    __ vfnmsub213ss(xmm8, xmm0, Operand(rsp, 0));
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfnmsub231ss
    __ incq(rax);
    __ movaps(xmm8, xmm2);
    __ movss(Operand(rsp, 0), xmm1);
    __ vfnmsub231ss(xmm8, xmm0, Operand(rsp, 0));
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);

    __ xorl(rax, rax);
    __ bind(&exit);
    __ addq(rsp, Immediate(kDoubleSize));
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

  auto f = GeneratedCode<F8>::FromCode(isolate, *code);
  CHECK_EQ(0, f.Call(9.26621069e-05f, -2.4607749f, -1.09587872f));
}

TEST_F(AssemblerX64Test, AssemblerX64SSE_ss) {
  Isolate* isolate = i_isolate();
  HandleScope scope(isolate);
  uint8_t buffer[1024];
  Assembler masm(AssemblerOptions{},
                 ExternalAssemblerBuffer(buffer, sizeof(buffer)));
  {
    Label exit;
    // arguments in xmm0, xmm1 and xmm2
    __ movl(rax, Immediate(0));

    __ movaps(xmm3, xmm0);
    __ maxss(xmm3, xmm1);
    __ ucomiss(xmm3, xmm1);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(1));

    __ movaps(xmm3, xmm1);
    __ minss(xmm3, xmm2);
    __ ucomiss(xmm3, xmm1);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(2));

    __ movaps(xmm3, xmm2);
    __ subss(xmm3, xmm1);
    __ ucomiss(xmm3, xmm0);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(3));

    __ movaps(xmm3, xmm0);
    __ addss(xmm3, xmm1);
    __ ucomiss(xmm3, xmm2);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(4));

    __ movaps(xmm3, xmm0);
    __ mulss(xmm3, xmm1);
    __ ucomiss(xmm3, xmm1);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(5));

    __ movaps(xmm3, xmm0);
    __ divss(xmm3, xmm1);
    __ mulss(xmm3, xmm2);
    __ mulss(xmm3, xmm1);
    __ ucomiss(xmm3, xmm2);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(6));

    // result in eax
    __ bind(&exit);
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

  auto f = GeneratedCode<F8>::FromCode(isolate, *code);
  int res = f.Call(1.0f, 2.0f, 3.0f);
  PrintF("f(1,2,3) = %d\n", res);
  CHECK_EQ(6, res);
}

TEST_F(AssemblerX64Test, AssemblerX64AVX_ss) {
  if (!CpuFeatures::IsSupported(AVX)) return;

  Isolate* isolate = i_isolate();
  HandleScope scope(isolate);
  uint8_t buffer[1024];
  Assembler masm(AssemblerOptions{},
                 ExternalAssemblerBuffer(buffer, sizeof(buffer)));
  {
    CpuFeatureScope avx_scope(&masm, AVX);
    Label exit;
    // arguments in xmm0, xmm1 and xmm2
    __ subq(rsp, Immediate(kDoubleSize * 2));  // For memory operand

    __ movl(rdx, Immediate(0xC2F64000));  // -123.125
    __ vmovd(xmm4, rdx);
    __ vmovss(Operand(rsp, 0), xmm4);
    __ vmovss(xmm5, Operand(rsp, 0));
    __ vmovaps(xmm6, xmm5);
    __ vmovd(rcx, xmm6);
    __ cmpl(rcx, rdx);
    __ movl(rax, Immediate(9));
    __ j(not_equal, &exit);

    __ movl(rax, Immediate(0));
    __ vmaxss(xmm3, xmm0, xmm1);
    __ vucomiss(xmm3, xmm1);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(1));

    __ vminss(xmm3, xmm1, xmm2);
    __ vucomiss(xmm3, xmm1);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(2));

    __ vsubss(xmm3, xmm2, xmm1);
    __ vucomiss(xmm3, xmm0);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(3));

    __ vaddss(xmm3, xmm0, xmm1);
    __ vucomiss(xmm3, xmm2);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(4));

    __ vmulss(xmm3, xmm0, xmm1);
    __ vucomiss(xmm3, xmm1);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(5));

    __ vdivss(xmm3, xmm0, xmm1);
    __ vmulss(xmm3, xmm3, xmm2);
    __ vmulss(xmm3, xmm3, xmm1);
    __ vucomiss(xmm3, xmm2);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(6));

    // result in eax
    __ bind(&exit);
    __ addq(rsp, Immediate(kDoubleSize * 2));
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

  auto f = GeneratedCode<F8>::FromCode(isolate, *code);
  int res = f.Call(1.0f, 2.0f, 3.0f);
  PrintF("f(1,2,3) = %d\n", res);
  CHECK_EQ(6, res);
}

TEST_F(AssemblerX64Test, AssemblerX64AVX_sd) {
  if (!CpuFeatures::IsSupported(AVX)) return;

  Isolate* isolate = i_isolate();
  HandleScope scope(isolate);
  uint8_t buffer[1024];
  Assembler masm(AssemblerOptions{},
                 ExternalAssemblerBuffer(buffer, sizeof(buffer)));
  {
    CpuFeatureScope avx_scope(&masm, AVX);
    Label exit;
    // arguments in xmm0, xmm1 and xmm2
    __ subq(rsp, Immediate(kDoubleSize * 2));  // For memory operand
    __ movl(rax, Immediate(0));

    __ vmaxsd(xmm4, xmm0, xmm1);
    __ vmovsd(Operand(rsp, kDoubleSize), xmm4);
    __ vmovsd(xmm5, Operand(rsp, kDoubleSize));
    __ vmovsd(xmm6, xmm6, xmm5);
    __ vmovapd(xmm3, xmm6);

    // Test vcvtss2sd & vcvtsd2ss
    __ movl(rax, Immediate(9));
    __ movq(rdx, uint64_t{0x426D1A0000000000});
    __ movq(Operand(rsp, 0), rdx);
    __ vcvtsd2ss(xmm6, xmm6, Operand(rsp, 0));
    __ vcvtss2sd(xmm7, xmm6, xmm6);
    __ vcvtsd2ss(xmm8, xmm7, xmm7);
    __ vmovss(Operand(rsp, 0), xmm8);
    __ vcvtss2sd(xmm9, xmm8, Operand(rsp, 0));
    __ vmovq(rcx, xmm9);
    __ cmpq(rcx, rdx);
    __ j(not_equal, &exit);

    // Test vcvttsd2si
    __ movl(rax, Immediate(10));
    __ movl(rdx, Immediate(123));
    __ vcvtlsi2sd(xmm6, xmm6, rdx);
    __ vcvttsd2si(rcx, xmm6);
    __ cmpl(rcx, rdx);
    __ j(not_equal, &exit);
    __ xorl(rcx, rcx);
    __ vmovsd(Operand(rsp, 0), xmm6);
    __ vcvttsd2si(rcx, Operand(rsp, 0));
    __ cmpl(rcx, rdx);
    __ j(not_equal, &exit);

    // Test vcvttsd2siq
    __ movl(rax, Immediate(11));
    __ movq(rdx, uint64_t{0x426D1A94A2000000});  // 1.0e12
    __ vmovq(xmm6, rdx);
    __ vcvttsd2siq(rcx, xmm6);
    __ movq(rdx, uint64_t{1000000000000});
    __ cmpq(rcx, rdx);
    __ j(not_equal, &exit);
    __ xorq(rcx, rcx);
    __ vmovsd(Operand(rsp, 0), xmm6);
    __ vcvttsd2siq(rcx, Operand(rsp, 0));
    __ cmpq(rcx, rdx);
    __ j(not_equal, &exit);

    // Test vmovmskpd
    __ movl(rax, Immediate(12));
    __ movq(rdx, uint64_t{0x426D1A94A2000000});  // 1.0e12
    __ vmovq(xmm6, rdx);
    __ movq(rdx, uint64_t{0xC26D1A94A2000000});  // -1.0e12
    __ vmovq(xmm7, rdx);
    __ shufps(xmm6, xmm7, 0x44);
    __ vmovmskpd(rdx, xmm6);
    __ cmpl(rdx, Immediate(2));
    __ j(not_equal, &exit);

    // Test vpcmpeqd
    __ movq(rdx, uint64_t{0x0123456789ABCDEF});
    __ movq(rcx, uint64_t{0x0123456788888888});
    __ vmovq(xmm6, rdx);
    __ vmovq(xmm7, rcx);
    __ vpcmpeqd(xmm8, xmm6, xmm7);
    __ vmovq(rdx, xmm8);
    __ movq(rcx, uint64_t{0xFFFFFFFF00000000});
    __ cmpq(rcx, rdx);
    __ movl(rax, Immediate(13));
    __ j(not_equal, &exit);

    // Test vpsllq, vpsrlq
    __ movl(rax, Immediate(13));
    __ movq(rdx, uint64_t{0x0123456789ABCDEF});
    __ vmovq(xmm6, rdx);
    __ vpsrlq(xmm7, xmm6, 4);
    __ vmovq(rdx, xmm7);
    __ movq(rcx, uint64_t{0x00123456789ABCDE});
    __ cmpq(rdx, rcx);
    __ j(not_equal, &exit);
    __ vpsllq(xmm7, xmm6, 12);
    __ vmovq(rdx, xmm7);
    __ movq(rcx, uint64_t{0x3456789ABCDEF000});
    __ cmpq(rdx, rcx);
    __ j(not_equal, &exit);

    // Test vandpd, vorpd, vxorpd
    __ movl(rax, Immediate(14));
    __ movl(rdx, Immediate(0x00FF00FF));
    __ movl(rcx, Immediate(0x0F0F0F0F));
    __ vmovd(xmm4, rdx);
    __ vmovd(xmm5, rcx);
    __ vandpd(xmm6, xmm4, xmm5);
    __ vmovd(rdx, xmm6);
    __ cmpl(rdx, Immediate(0x000F000F));
    __ j(not_equal, &exit);
    __ vorpd(xmm6, xmm4, xmm5);
    __ vmovd(rdx, xmm6);
    __ cmpl(rdx, Immediate(0x0FFF0FFF));
    __ j(not_equal, &exit);
    __ vxorpd(xmm6, xmm4, xmm5);
    __ vmovd(rdx, xmm6);
    __ cmpl(rdx, Immediate(0x0FF00FF0));
    __ j(not_equal, &exit);

    // Test vsqrtsd
    __ movl(rax, Immediate(15));
    __ movq(rdx, uint64_t{0x4004000000000000});  // 2.5
    __ vmovq(xmm4, rdx);
    __ vmulsd(xmm5, xmm4, xmm4);
    __ vmovsd(Operand(rsp, 0), xmm5);
    __ vsqrtsd(xmm6, xmm5, xmm5);
    __ vmovq(rcx, xmm6);
    __ cmpq(rcx, rdx);
    __ j(not_equal, &exit);
    __ vsqrtsd(xmm7, xmm7, Operand(rsp, 0));
    __ vmovq(rcx, xmm7);
    __ cmpq(rcx, rdx);
    __ j(not_equal, &exit);

    // Test vroundsd
    __ movl(rax, Immediate(16));
    __ movq(rdx, uint64_t{0x4002000000000000});  // 2.25
    __ vmovq(xmm4, rdx);
    __ vroundsd(xmm5, xmm4, xmm4, kRoundUp);
    __ movq(rcx, uint64_t{0x4008000000000000});  // 3.0
    __ vmovq(xmm6, rcx);
    __ vucomisd(xmm5, xmm6);
    __ j(not_equal, &exit);

    // Test vcvtlsi2sd
    __ movl(rax, Immediate(17));
    __ movl(rdx, Immediate(6));
    __ movq(rcx, uint64_t{0x4018000000000000});  // 6.0
    __ vmovq(xmm5, rcx);
    __ vcvtlsi2sd(xmm6, xmm6, rdx);
    __ vucomisd(xmm5, xmm6);
    __ j(not_equal, &exit);
    __ movl(Operand(rsp, 0), rdx);
    __ vcvtlsi2sd(xmm7, xmm7, Operand(rsp, 0));
    __ vucomisd(xmm5, xmm6);
    __ j(not_equal, &exit);

    // Test vcvtqsi2sd
    __ movl(rax, Immediate(18));
    __ movq(rdx, uint64_t{0x2000000000000000});  // 2 << 0x3C
    __ movq(rcx, uint64_t{0x43C0000000000000});
    __ vmovq(xmm5, rcx);
    __ vcvtqsi2sd(xmm6, xmm6, rdx);
    __ vucomisd(xmm5, xmm6);
    __ j(not_equal, &exit);

    // Test vcvtsd2si
    __ movl(rax, Immediate(19));
    __ movq(rdx, uint64_t{0x4018000000000000});  // 6.0
    __ vmovq(xmm5, rdx);
    __ vcvtsd2si(rcx, xmm5);
    __ cmpl(rcx, Immediate(6));
    __ j(not_equal, &exit);

    __ movq(rdx, uint64_t{0x3FF0000000000000});  // 1.0
    __ vmovq(xmm7, rdx);
    __ vmulsd(xmm1, xmm1, xmm7);
    __ movq(Operand(rsp, 0), rdx);
    __ vmovq(xmm6, Operand(rsp, 0));
    __ vmulsd(xmm1, xmm1, xmm6);

    __ vucomisd(xmm3, xmm1);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(1));

    __ vminsd(xmm3, xmm1, xmm2);
    __ vucomisd(xmm3, xmm1);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(2));

    __ vsubsd(xmm3, xmm2, xmm1);
    __ vucomisd(xmm3, xmm0);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(3));

    __ vaddsd(xmm3, xmm0, xmm1);
    __ vucomisd(xmm3, xmm2);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(4));

    __ vmulsd(xmm3, xmm0, xmm1);
    __ vucomisd(xmm3, xmm1);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(5));

    __ vdivsd(xmm3, xmm0, xmm1);
    __ vmulsd(xmm3, xmm3, xmm2);
    __ vmulsd(xmm3, xmm3, xmm1);
    __ vucomisd(xmm3, xmm2);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(6));

    // result in eax
    __ bind(&exit);
    __ addq(rsp, Immediate(kDoubleSize * 2));
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

  auto f = GeneratedCode<F7>::FromCode(isolate, *code);
  int res = f.Call(1.0, 2.0, 3.0);
  PrintF("f(1,2,3) = %d\n", res);
  CHECK_EQ(6, res);
}

TEST_F(AssemblerX64Test, AssemblerX64BMI1) {
  if (!CpuFeatures::IsSupported(BMI1)) return;

  Isolate* isolate = i_isolate();
  HandleScope scope(isolate);
  uint8_t buffer[1024];
  MacroAssembler masm(isolate, v8::internal::CodeObjectRequired::kYes,
                      ExternalAssemblerBuffer(buffer, sizeof(buffer)));
  {
    CpuFeatureScope fscope(&masm, BMI1);
    Label exit;

    __ movq(rcx, uint64_t{0x1122334455667788});  // source operand
    __ pushq(rcx);                               // For memory operand

    // andn
    __ movq(rdx, uint64_t{0x1000000020000000});

    __ movl(rax, Immediate(1));  // Test number
    __ andnq(r8, rdx, rcx);
    __ movq(r9, uint64_t{0x0122334455667788});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ andnq(r8, rdx, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x0122334455667788});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ andnl(r8, rdx, rcx);
    __ movq(r9, uint64_t{0x0000000055667788});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ andnl(r8, rdx, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x0000000055667788});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    // bextr
    __ movq(rdx, uint64_t{0x0000000000002808});

    __ incq(rax);
    __ bextrq(r8, rcx, rdx);
    __ movq(r9, uint64_t{0x0000003344556677});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ bextrq(r8, Operand(rsp, 0), rdx);
    __ movq(r9, uint64_t{0x0000003344556677});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ bextrl(r8, rcx, rdx);
    __ movq(r9, uint64_t{0x0000000000556677});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ bextrl(r8, Operand(rsp, 0), rdx);
    __ movq(r9, uint64_t{0x0000000000556677});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    // blsi
    __ incq(rax);
    __ blsiq(r8, rcx);
    __ movq(r9, uint64_t{0x0000000000000008});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ blsiq(r8, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x0000000000000008});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ blsil(r8, rcx);
    __ movq(r9, uint64_t{0x0000000000000008});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ blsil(r8, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x0000000000000008});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    // blsmsk
    __ incq(rax);
    __ blsmskq(r8, rcx);
    __ movq(r9, uint64_t{0x000000000000000F});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ blsmskq(r8, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x000000000000000F});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ blsmskl(r8, rcx);
    __ movq(r9, uint64_t{0x000000000000000F});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ blsmskl(r8, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x000000000000000F});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    // blsr
    __ incq(rax);
    __ blsrq(r8, rcx);
    __ movq(r9, uint64_t{0x1122334455667780});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ blsrq(r8, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x1122334455667780});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ blsrl(r8, rcx);
    __ movq(r9, uint64_t{0x0000000055667780});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ blsrl(r8, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x0000000055667780});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    // tzcnt
    __ incq(rax);
    __ tzcntq(r8, rcx);
    __ movq(r9, uint64_t{0x0000000000000003});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ tzcntq(r8, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x0000000000000003});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ tzcntl(r8, rcx);
    __ movq(r9, uint64_t{0x0000000000000003});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ tzcntl(r8, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x0000000000000003});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ xorl(rax, rax);
    __ bind(&exit);
    __ popq(rcx);
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

TEST_F(AssemblerX64Test, AssemblerX64LZCNT) {
  if (!CpuFeatures::IsSupported(LZCNT)) return;

  Isolate* isolate = i_isolate();
  HandleScope scope(isolate);
  uint8_t buffer[256];
  MacroAssembler masm(isolate, v8::internal::CodeObjectRequired::kYes,
                      ExternalAssemblerBuffer(buffer, sizeof(buffer)));
  {
    CpuFeatureScope fscope(&masm, LZCNT);
    Label exit;

    __ movq(rcx, uint64_t{0x1122334455667788});  // source operand
    __ pushq(rcx);                               // For memory operand

    __ movl(rax, Immediate(1));  // Test number
    __ lzcntq(r8, rcx);
    __ movq(r9, uint64_t{0x0000000000000003});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ lzcntq(r8, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x0000000000000003});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ lzcntl(r8, rcx);
    __ movq(r9, uint64_t{0x0000000000000001});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ lzcntl(r8, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x0000000000000001});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ xorl(rax, rax);
    __ bind(&exit);
    __ popq(rcx);
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

TEST_F(AssemblerX64Test, AssemblerX64POPCNT) {
  if (!CpuFeatures::IsSupported(POPCNT)) return;

  Isolate* isolate = i_isolate();
  HandleScope scope(isolate);
  uint8_t buffer[256];
  MacroAssembler masm(isolate, v8::internal::CodeObjectRequired::kYes,
                      ExternalAssemblerBuffer(buffer, sizeof(buffer)));
  {
    CpuFeatureScope fscope(&masm, POPCNT);
    Label exit;

    __ movq(rcx, uint64_t{0x1111111111111100});  // source operand
    __ pushq(rcx);                               // For memory operand

    __ movl(rax, Immediate(1));  // Test number
    __ popcntq(r8, rcx);
    __ movq(r9, uint64_t{0x000000000000000E});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ popcntq(r8, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x000000000000000E});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ popcntl(r8, rcx);
    __ movq(r9, uint64_t{0x0000000000000006});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ popcntl(r8, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x0000000000000006});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ xorl(rax, rax);
    __ bind(&exit);
    __ popq(rcx);
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

TEST_F(AssemblerX64Test, AssemblerX64BMI2) {
  if (!CpuFeatures::IsSupported(BMI2)) return;

  Isolate* isolate = i_isolate();
  HandleScope scope(isolate);
  uint8_t buffer[2048];
  MacroAssembler masm(isolate, v8::internal::CodeObjectRequired::kYes,
                      ExternalAssemblerBuffer(buffer, sizeof(buffer)));
  {
    CpuFeatureScope fscope(&masm, BMI2);
    Label exit;
    __ pushq(rbx);                               // save rbx
    __ movq(rcx, uint64_t{0x1122334455667788});  // source operand
    __ pushq(rcx);                               // For memory operand

    // bzhi
    __ movq(rdx, uint64_t{0x0000000000000009});

    __ movl(rax, Immediate(1));  // Test number
    __ bzhiq(r8, rcx, rdx);
    __ movq(r9, uint64_t{0x0000000000000188});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ bzhiq(r8, Operand(rsp, 0), rdx);
    __ movq(r9, uint64_t{0x0000000000000188});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ bzhil(r8, rcx, rdx);
    __ movq(r9, uint64_t{0x0000000000000188});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ bzhil(r8, Operand(rsp, 0), rdx);
    __ movq(r9, uint64_t{0x0000000000000188});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    // mulx
    __ movq(rdx, uint64_t{0x0000000000001000});

    __ incq(rax);
    __ mulxq(r8, r9, rcx);
    __ movq(rbx, uint64_t{0x0000000000000112});  // expected result
    __ cmpq(r8, rbx);
    __ j(not_equal, &exit);
    __ movq(rbx, uint64_t{0x2334455667788000});  // expected result
    __ cmpq(r9, rbx);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ mulxq(r8, r9, Operand(rsp, 0));
    __ movq(rbx, uint64_t{0x0000000000000112});  // expected result
    __ cmpq(r8, rbx);
    __ j(not_equal, &exit);
    __ movq(rbx, uint64_t{0x2334455667788000});  // expected result
    __ cmpq(r9, rbx);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ mulxl(r8, r9, rcx);
    __ movq(rbx, uint64_t{0x0000000000000556});  // expected result
    __ cmpq(r8, rbx);
    __ j(not_equal, &exit);
    __ movq(rbx, uint64_t{0x0000000067788000});  // expected result
    __ cmpq(r9, rbx);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ mulxl(r8, r9, Operand(rsp, 0));
    __ movq(rbx, uint64_t{0x0000000000000556});  // expected result
    __ cmpq(r8, rbx);
    __ j(not_equal, &exit);
    __ movq(rbx, uint64_t{0x0000000067788000});  // expected result
    __ cmpq(r9, rbx);
    __ j(not_equal, &exit);

    // pdep
    __ movq(rdx, uint64_t{0xFFFFFFFFFFFFFFF0});

    __ incq(rax);
    __ pdepq(r8, rdx, rcx);
    __ movq(r9, uint64_t{0x1122334455667400});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ pdepq(r8, rdx, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x1122334455667400});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ pdepl(r8, rdx, rcx);
    __ movq(r9, uint64_t{0x0000000055667400});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ pdepl(r8, rdx, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x0000000055667400});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    // pext
    __ movq(rdx, uint64_t{0xFFFFFFFFFFFFFFF0});

    __ incq(rax);
    __ pextq(r8, rdx, rcx);
    __ movq(r9, uint64_t{0x0000000003FFFFFE});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ pextq(r8, rdx, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x0000000003FFFFFE});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ pextl(r8, rdx, rcx);
    __ movq(r9, uint64_t{0x000000000000FFFE});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ pextl(r8, rdx, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x000000000000FFFE});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    // sarx
    __ movq(rdx, uint64_t{0x0000000000000004});

    __ incq(rax);
    __ sarxq(r8, rcx, rdx);
    __ movq(r9, uint64_t{0x0112233445566778});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ sarxq(r8, Operand(rsp, 0), rdx);
    __ movq(r9, uint64_t{0x0112233445566778});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ sarxl(r8, rcx, rdx);
    __ movq(r9, uint64_t{0x0000000005566778});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ sarxl(r8, Operand(rsp, 0), rdx);
    __ movq(r9, uint64_t{0x0000000005566778});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    // shlx
    __ movq(rdx, uint64_t{0x0000000000000004});

    __ incq(rax);
    __ shlxq(r8, rcx, rdx);
    __ movq(r9, uint64_t{0x1223344556677880});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ shlxq(r8, Operand(rsp, 0), rdx);
    __ movq(r9, uint64_t{0x1223344556677880});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ shlxl(r8, rcx, rdx);
    __ movq(r9, uint64_t{0x0000000056677880});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ shlxl(r8, Operand(rsp, 0), rdx);
    __ movq(r9, uint64_t{0x0000000056677880});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    // shrx
    __ movq(rdx, uint64_t{0x0000000000000004});

    __ incq(rax);
    __ shrxq(r8, rcx, rdx);
    __ movq(r9, uint64_t{0x0112233445566778});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ shrxq(r8, Operand(rsp, 0), rdx);
    __ movq(r9, uint64_t{0x0112233445566778});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ shrxl(r8, rcx, rdx);
    __ movq(r9, uint64_t{0x0000000005566778});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ shrxl(r8, Operand(rsp, 0), rdx);
    __ movq(r9, uint64_t{0x0000000005566778});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    // rorx
    __ incq(rax);
"""


```