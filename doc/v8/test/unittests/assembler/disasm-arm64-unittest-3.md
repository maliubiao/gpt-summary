Response:
The user wants a summary of the functionality of a C++ file: `v8/test/unittests/assembler/disasm-arm64-unittest.cc`.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Function:** The filename strongly suggests this is a unit test file specifically for the ARM64 disassembler within the V8 JavaScript engine. The `.cc` extension confirms it's C++ code.

2. **Analyze the Code Snippet:** The provided code uses a pattern of `COMPARE(instruction, "expected disassembly string")`. This clearly indicates the tests are verifying that specific ARM64 instructions, when processed by the V8 disassembler, produce the correct human-readable assembly representation.

3. **Infer Overall Purpose:**  Based on the file path and the code snippet, the primary function of this file is to test the ARM64 disassembler in V8. It checks if the disassembler correctly translates machine code (represented by the `instruction` calls) into assembly language strings.

4. **Address Specific Questions:**

   * **Functionality Listing:**  The core function is testing the ARM64 disassembler. This involves taking machine code and converting it to assembly. The tests cover various ARM64 NEON (Advanced SIMD) instructions.

   * **.tq Extension:** The file has a `.cc` extension, so it's C++ and *not* a Torque file.

   * **Relationship to JavaScript:** While the file itself is C++, it's crucial for the V8 JavaScript engine. V8 compiles JavaScript code into machine code, including ARM64 instructions. The disassembler is used for debugging, inspection, and potentially code optimization analysis of this generated machine code. A simple JavaScript example could be a function that, when compiled by V8 on an ARM64 architecture, would use some of the tested NEON instructions.

   * **Code Logic Reasoning:** The `COMPARE` macro implies an internal comparison within the test framework. We can hypothesize input (an ARM64 instruction) and output (the expected disassembled string).

   * **Common Programming Errors:**  While this test file doesn't directly *demonstrate* user errors, it *prevents* errors in the V8 disassembler. A common user error related to assembly is misinterpreting instructions or their operands. The disassembler aims to provide an accurate representation to avoid such misinterpretations.

   * **Part of a Series:**  Since this is part 7 of 8, it suggests this is one of several files focusing on different aspects of the ARM64 disassembler or related components. Given the content, previous parts likely tested other instruction categories, and the final part might cover edge cases or summary.

5. **Structure the Answer:** Organize the findings into clear sections addressing each of the user's questions. Use examples where requested (JavaScript and hypothetical input/output).

6. **Refine and Polish:** Ensure the language is precise and easy to understand. Avoid overly technical jargon where possible. Emphasize the connection to the V8 engine and its role in executing JavaScript.
好的，让我们来分析一下 `v8/test/unittests/assembler/disasm-arm64-unittest.cc` 这个文件的功能。

**核心功能：测试 ARM64 反汇编器 (Disassembler)**

从文件名 `disasm-arm64-unittest.cc` 可以明显看出，这个文件的主要目的是对 V8 引擎中用于 ARM64 架构的反汇编器进行单元测试。

**具体功能拆解：**

1. **模拟 ARM64 指令并断言其反汇编结果：**  文件中大量使用了 `COMPARE(instruction, "expected disassembly string")` 这样的宏。这表明代码会构建特定的 ARM64 指令（通常是 NEON 指令，因为代码中大量使用了 `v` 开头的寄存器，例如 `v1.V4S()`），然后调用 V8 的反汇编器来处理这些指令。`COMPARE` 宏会断言反汇编器生成的字符串是否与预期的汇编字符串一致。

2. **覆盖多种 ARM64 NEON 指令：**  从代码片段中可以看出，测试覆盖了各种 NEON 指令，包括：
   * **数据移动指令:** `Movi`, `Mvni`, `Fmov`
   * **双操作数杂项指令:** `Shll`, `Shll2`, `Cmeq`, `Cmge`, `Cmgt`, `Cmle`, `Cmlt`, `Fcmeq`, `Fcmge`, `Fcmgt`, `Fcmle`, `Fcmlt`, `Neg`, `Sqneg`, `Abs`, `Sqabs`, `Suqadd`, `Usqadd`, `Xtn`, `Xtn2`, `Sqxtn`, `Sqxtn2`, `Uqxtn`, `Uqxtn2`, `Sqxtun`, `Sqxtun2`, `Cls`, `Clz`, `Cnt`, `Mvn`, `Not`, `Rev64`, `Rev32`, `Rev16`, `Rbit`, `Ursqrte`, `Urecpe`, `Frsqrte`, `Frecpe`, `Fabs`, `Fneg`, `Frintn`, `Frinta`, `Frintp`, `Frintm`, `Frintx`, `Frintz`, `Frinti`, `Fsqrt`, `Fcvtns`, `Fcvtnu`, `Fcvtps`, `Fcvtpu`, `Fcvtms`, `Fcvtmu`, `Fcvtzs`, `Fcvtzu`, `Fcvtas`, `Fcvtau`, `Fcvtl`, `Fcvtl2`, `Fcvtn`, `Fcvtn2`, `Fcvtxn`, `Frecpx`, `Scvtf`, `Ucvtf`, `Saddlp`, `Uaddlp`, `Sadalp`, `Uadalp`
   * **跨通道操作指令:** `Smaxv`, `Sminv`, `Umaxv`, `Uminv`, `Addv`, `Saddlv`, `Uaddlv`, `Fmaxv`, `Fminv`, `Fmaxnmv`, `Fminnmv`
   * **标量配对操作指令:** `Addp`, `Faddp`, `Fmaxp`, `Fmaxnmp`, `Fminp`, `Fminnmp`
   * **带立即数的移位指令:** `Sshr`, `Ushr`, `Srshr`, `Urshr`, `Srsra`, `Ssra`, `Ursra`, `Usra`, `Sli`, `Shl`, `Sqshl`, `Sqshlu`, `Uqshl`, `Sshll`, `Sxtl`

3. **测试未分配的指令编码:**  代码中也包含对 `dci(0x...)` 的测试，这表明它还会测试反汇编器处理未知或未分配指令编码的能力。

**关于其他问题的解答：**

* **如果 `v8/test/unittests/assembler/disasm-arm64-unittest.cc` 以 `.tq` 结尾：** 那么它将是一个 V8 Torque 源代码文件。Torque 是一种 V8 用于定义内置函数和运行时功能的领域特定语言。当前文件以 `.cc` 结尾，因此是 C++ 文件。

* **与 JavaScript 的功能关系：**  虽然这个文件本身是 C++ 代码，但它与 JavaScript 的执行息息相关。V8 引擎负责将 JavaScript 代码编译成机器码，包括 ARM64 指令（特别是运行在 ARM64 架构的设备上时）。这个单元测试确保了 V8 的反汇编器能够正确地“翻译”这些由 V8 生成的机器码，这对于调试、性能分析以及理解 V8 的内部工作原理至关重要。

   **JavaScript 示例：**

   ```javascript
   function add(a, b) {
     return a + b;
   }

   // 当 V8 在 ARM64 架构上编译这个函数时，可能会使用一些 NEON 指令
   // 来加速加法运算，特别是当 a 和 b 是数组或大量数据时。
   ```

   虽然你无法直接看到这个 C++ 测试文件测试的指令对应到哪个具体的 JavaScript 代码，但可以理解为 V8 内部为了优化 JavaScript 的执行，会生成类似的 ARM64 指令，而这个测试文件就是为了保证 V8 能够正确地解析这些指令。

* **代码逻辑推理（假设输入与输出）：**

   **假设输入 (MASM 指令):**  `Movi(v4.V8B(), 0xaa)`  （在 C++ 代码中被调用）

   **预期输出 (反汇编字符串):** `"movi v4.8b, #0xaa"`

   `COMPARE` 宏内部的逻辑会执行 `Movi(v4.V8B(), 0xaa)`，这会生成对应的机器码。然后，V8 的反汇编器会处理这段机器码，并生成一个反汇编字符串。`COMPARE` 宏会比较生成的字符串和预期的字符串 `"movi v4.8b, #0xaa"`，如果两者不一致，测试将会失败。

* **涉及用户常见的编程错误：** 这个测试文件主要关注的是 V8 引擎内部的反汇编器的正确性，而不是用户编写 JavaScript 代码时可能出现的错误。但是，反汇编器的正确性对于开发者理解底层机器码至关重要。如果反汇编器出现错误，开发者在分析 V8 生成的机器码时可能会得到错误的理解，导致调试困难。

   **一个相关的场景是：**  假设 V8 在编译一段复杂的 JavaScript 代码时生成了错误的 NEON 指令。如果反汇编器工作正常，开发者可以通过查看反汇编结果来发现问题，例如看到一条不应该出现的指令或者操作数错误。如果反汇编器本身也有 bug，那么显示的汇编代码可能无法准确反映实际执行的机器码，从而误导开发者。

* **第 7 部分，共 8 部分的功能归纳：**  考虑到这是系列测试的第 7 部分，并且内容集中在各种 NEON 指令的测试上，可以推测：
    * **之前的章节 (1-6) 可能测试了其他类型的 ARM64 指令，例如通用寄存器操作、内存访问、分支跳转等。**
    * **这一部分 (第 7 部分) 专门深入测试了 ARM64 架构中的 NEON (Advanced SIMD) 指令集。** NEON 指令常用于并行处理向量数据，是 V8 优化 JavaScript 性能的重要手段。
    * **最后一部分 (第 8 部分) 可能会涵盖一些更特殊的指令、边界情况测试，或者是一些测试框架的收尾工作。**

**总结：**

`v8/test/unittests/assembler/disasm-arm64-unittest.cc` 是一个关键的单元测试文件，用于验证 V8 引擎中 ARM64 反汇编器的正确性。它通过模拟各种 ARM64 NEON 指令，并断言反汇编器能够生成预期的汇编代码字符串，从而保证了 V8 在 ARM64 架构上反汇编功能的可靠性。 这对于理解 V8 如何将 JavaScript 代码转化为机器码以及进行底层调试和性能分析至关重要。

Prompt: 
```
这是目录为v8/test/unittests/assembler/disasm-arm64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/assembler/disasm-arm64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共8部分，请归纳一下它的功能

"""
4.4s, #0xaa, msl #8");
  COMPARE(Mvni(v1.V4S(), 0xcc, MSL, 16), "mvni v1.4s, #0xcc, msl #16");

  COMPARE(Movi(v4.V8B(), 0xaa), "movi v4.8b, #0xaa");
  COMPARE(Movi(v1.V16B(), 0xcc), "movi v1.16b, #0xcc");

  COMPARE(Movi(v4.V4H(), 0xaa, LSL, 0), "movi v4.4h, #0xaa, lsl #0");
  COMPARE(Movi(v1.V8H(), 0xcc, LSL, 8), "movi v1.8h, #0xcc, lsl #8");

  COMPARE(Movi(v4.V2S(), 0xaa, LSL, 0), "movi v4.2s, #0xaa, lsl #0");
  COMPARE(Movi(v1.V2S(), 0xcc, LSL, 8), "movi v1.2s, #0xcc, lsl #8");
  COMPARE(Movi(v4.V4S(), 0xaa, LSL, 16), "movi v4.4s, #0xaa, lsl #16");
  COMPARE(Movi(v1.V4S(), 0xcc, LSL, 24), "movi v1.4s, #0xcc, lsl #24");

  COMPARE(Movi(v4.V2S(), 0xaa, MSL, 8), "movi v4.2s, #0xaa, msl #8");
  COMPARE(Movi(v1.V2S(), 0xcc, MSL, 16), "movi v1.2s, #0xcc, msl #16");
  COMPARE(Movi(v4.V4S(), 0xaa, MSL, 8), "movi v4.4s, #0xaa, msl #8");
  COMPARE(Movi(v1.V4S(), 0xcc, MSL, 16), "movi v1.4s, #0xcc, msl #16");

  COMPARE(Movi(d2, 0xffff0000ffffff), "movi d2, #0xffff0000ffffff");
  COMPARE(Movi(v1.V2D(), 0xffff0000ffffff), "movi v1.2d, #0xffff0000ffffff");

  COMPARE(Fmov(v0.V2S(), 1.0f), "fmov v0.2s, #0x70 (1.0000)");
  COMPARE(Fmov(v31.V2S(), -13.0f), "fmov v31.2s, #0xaa (-13.0000)");
  COMPARE(Fmov(v0.V4S(), 1.0f), "fmov v0.4s, #0x70 (1.0000)");
  COMPARE(Fmov(v31.V4S(), -13.0f), "fmov v31.4s, #0xaa (-13.0000)");
  COMPARE(Fmov(v1.V2D(), 1.0), "fmov v1.2d, #0x70 (1.0000)");
  COMPARE(Fmov(v29.V2D(), -13.0), "fmov v29.2d, #0xaa (-13.0000)");

  // An unallocated form of fmov.
  COMPARE(dci(0x2f07ffff), "unallocated (NEONModifiedImmediate)");

  CLEANUP();
}

TEST_F(DisasmArm64Test, neon_2regmisc) {
  SET_UP_MASM();

  COMPARE(Shll(v1.V8H(), v8_.V8B(), 8), "shll v1.8h, v8.8b, #8");
  COMPARE(Shll(v3.V4S(), v1.V4H(), 16), "shll v3.4s, v1.4h, #16");
  COMPARE(Shll(v5.V2D(), v3.V2S(), 32), "shll v5.2d, v3.2s, #32");
  COMPARE(Shll2(v2.V8H(), v9.V16B(), 8), "shll2 v2.8h, v9.16b, #8");
  COMPARE(Shll2(v4.V4S(), v2.V8H(), 16), "shll2 v4.4s, v2.8h, #16");
  COMPARE(Shll2(v6.V2D(), v4.V4S(), 32), "shll2 v6.2d, v4.4s, #32");

  // An unallocated form of shll.
  COMPARE(dci(0x2ee13bff), "unallocated (NEON2RegMisc)");
  // An unallocated form of shll2.
  COMPARE(dci(0x6ee13bff), "unallocated (NEON2RegMisc)");

#define DISASM_INST(M, S) \
  COMPARE(Cmeq(v0.M, v1.M, 0), "cmeq v0." S ", v1." S ", #0");
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Cmge(v0.M, v1.M, 0), "cmge v0." S ", v1." S ", #0");
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Cmgt(v0.M, v1.M, 0), "cmgt v0." S ", v1." S ", #0");
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Cmle(v0.M, v1.M, 0), "cmle v0." S ", v1." S ", #0");
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Cmlt(v0.M, v1.M, 0), "cmlt v0." S ", v1." S ", #0");
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

  COMPARE(Cmeq(v0.D(), v1.D(), 0), "cmeq d0, d1, #0");
  COMPARE(Cmge(v3.D(), v4.D(), 0), "cmge d3, d4, #0");
  COMPARE(Cmgt(v6.D(), v7.D(), 0), "cmgt d6, d7, #0");
  COMPARE(Cmle(v0.D(), v1.D(), 0), "cmle d0, d1, #0");
  COMPARE(Cmlt(v3.D(), v4.D(), 0), "cmlt d3, d4, #0");

#define DISASM_INST(M, S) \
  COMPARE(Fcmeq(v0.M, v1.M, 0), "fcmeq v0." S ", v1." S ", #0.0");
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

  COMPARE(Fcmeq(v0.S(), v1.S(), 0), "fcmeq s0, s1, #0.0");
  COMPARE(Fcmeq(v0.D(), v1.D(), 0), "fcmeq d0, d1, #0.0");

#define DISASM_INST(M, S) \
  COMPARE(Fcmge(v0.M, v1.M, 0), "fcmge v0." S ", v1." S ", #0.0");
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

  COMPARE(Fcmge(v0.S(), v1.S(), 0), "fcmge s0, s1, #0.0");
  COMPARE(Fcmge(v0.D(), v1.D(), 0), "fcmge d0, d1, #0.0");

#define DISASM_INST(M, S) \
  COMPARE(Fcmgt(v0.M, v1.M, 0), "fcmgt v0." S ", v1." S ", #0.0");
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

  COMPARE(Fcmgt(v0.S(), v1.S(), 0), "fcmgt s0, s1, #0.0");
  COMPARE(Fcmgt(v0.D(), v1.D(), 0), "fcmgt d0, d1, #0.0");

#define DISASM_INST(M, S) \
  COMPARE(Fcmle(v0.M, v1.M, 0), "fcmle v0." S ", v1." S ", #0.0");
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

  COMPARE(Fcmle(v0.S(), v1.S(), 0), "fcmle s0, s1, #0.0");
  COMPARE(Fcmle(v0.D(), v1.D(), 0), "fcmle d0, d1, #0.0");

#define DISASM_INST(M, S) \
  COMPARE(Fcmlt(v0.M, v1.M, 0), "fcmlt v0." S ", v1." S ", #0.0");
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

  COMPARE(Fcmlt(v0.S(), v1.S(), 0), "fcmlt s0, s1, #0.0");
  COMPARE(Fcmlt(v0.D(), v1.D(), 0), "fcmlt d0, d1, #0.0");

#define DISASM_INST(M, S) COMPARE(Neg(v0.M, v1.M), "neg v0." S ", v1." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

  COMPARE(Neg(v0.D(), v1.D()), "neg d0, d1");

#define DISASM_INST(M, S) COMPARE(Sqneg(v0.M, v1.M), "sqneg v0." S ", v1." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

  COMPARE(Sqneg(b0, b1), "sqneg b0, b1");
  COMPARE(Sqneg(h1, h2), "sqneg h1, h2");
  COMPARE(Sqneg(s2, s3), "sqneg s2, s3");
  COMPARE(Sqneg(d3, d4), "sqneg d3, d4");

#define DISASM_INST(M, S) COMPARE(Abs(v0.M, v1.M), "abs v0." S ", v1." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

  COMPARE(Abs(v0.D(), v1.D()), "abs d0, d1");

#define DISASM_INST(M, S) COMPARE(Sqabs(v0.M, v1.M), "sqabs v0." S ", v1." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

  COMPARE(Sqabs(b0, b1), "sqabs b0, b1");
  COMPARE(Sqabs(h1, h2), "sqabs h1, h2");
  COMPARE(Sqabs(s2, s3), "sqabs s2, s3");
  COMPARE(Sqabs(d3, d4), "sqabs d3, d4");

#define DISASM_INST(M, S) COMPARE(Suqadd(v0.M, v1.M), "suqadd v0." S ", v1." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

  COMPARE(Suqadd(b0, b1), "suqadd b0, b1");
  COMPARE(Suqadd(h1, h2), "suqadd h1, h2");
  COMPARE(Suqadd(s2, s3), "suqadd s2, s3");
  COMPARE(Suqadd(d3, d4), "suqadd d3, d4");

#define DISASM_INST(M, S) COMPARE(Usqadd(v0.M, v1.M), "usqadd v0." S ", v1." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

  COMPARE(Usqadd(b0, b1), "usqadd b0, b1");
  COMPARE(Usqadd(h1, h2), "usqadd h1, h2");
  COMPARE(Usqadd(s2, s3), "usqadd s2, s3");
  COMPARE(Usqadd(d3, d4), "usqadd d3, d4");

  COMPARE(Xtn(v0.V8B(), v1.V8H()), "xtn v0.8b, v1.8h");
  COMPARE(Xtn(v1.V4H(), v2.V4S()), "xtn v1.4h, v2.4s");
  COMPARE(Xtn(v2.V2S(), v3.V2D()), "xtn v2.2s, v3.2d");
  COMPARE(Xtn2(v0.V16B(), v1.V8H()), "xtn2 v0.16b, v1.8h");
  COMPARE(Xtn2(v1.V8H(), v2.V4S()), "xtn2 v1.8h, v2.4s");
  COMPARE(Xtn2(v2.V4S(), v3.V2D()), "xtn2 v2.4s, v3.2d");

  COMPARE(Sqxtn(v0.V8B(), v1.V8H()), "sqxtn v0.8b, v1.8h");
  COMPARE(Sqxtn(v1.V4H(), v2.V4S()), "sqxtn v1.4h, v2.4s");
  COMPARE(Sqxtn(v2.V2S(), v3.V2D()), "sqxtn v2.2s, v3.2d");
  COMPARE(Sqxtn2(v0.V16B(), v1.V8H()), "sqxtn2 v0.16b, v1.8h");
  COMPARE(Sqxtn2(v1.V8H(), v2.V4S()), "sqxtn2 v1.8h, v2.4s");
  COMPARE(Sqxtn2(v2.V4S(), v3.V2D()), "sqxtn2 v2.4s, v3.2d");
  COMPARE(Sqxtn(b19, h0), "sqxtn b19, h0");
  COMPARE(Sqxtn(h20, s0), "sqxtn h20, s0");
  COMPARE(Sqxtn(s21, d0), "sqxtn s21, d0");

  COMPARE(Uqxtn(v0.V8B(), v1.V8H()), "uqxtn v0.8b, v1.8h");
  COMPARE(Uqxtn(v1.V4H(), v2.V4S()), "uqxtn v1.4h, v2.4s");
  COMPARE(Uqxtn(v2.V2S(), v3.V2D()), "uqxtn v2.2s, v3.2d");
  COMPARE(Uqxtn2(v0.V16B(), v1.V8H()), "uqxtn2 v0.16b, v1.8h");
  COMPARE(Uqxtn2(v1.V8H(), v2.V4S()), "uqxtn2 v1.8h, v2.4s");
  COMPARE(Uqxtn2(v2.V4S(), v3.V2D()), "uqxtn2 v2.4s, v3.2d");
  COMPARE(Uqxtn(b19, h0), "uqxtn b19, h0");
  COMPARE(Uqxtn(h20, s0), "uqxtn h20, s0");
  COMPARE(Uqxtn(s21, d0), "uqxtn s21, d0");

  COMPARE(Sqxtun(v0.V8B(), v1.V8H()), "sqxtun v0.8b, v1.8h");
  COMPARE(Sqxtun(v1.V4H(), v2.V4S()), "sqxtun v1.4h, v2.4s");
  COMPARE(Sqxtun(v2.V2S(), v3.V2D()), "sqxtun v2.2s, v3.2d");
  COMPARE(Sqxtun2(v0.V16B(), v1.V8H()), "sqxtun2 v0.16b, v1.8h");
  COMPARE(Sqxtun2(v1.V8H(), v2.V4S()), "sqxtun2 v1.8h, v2.4s");
  COMPARE(Sqxtun2(v2.V4S(), v3.V2D()), "sqxtun2 v2.4s, v3.2d");
  COMPARE(Sqxtun(b19, h0), "sqxtun b19, h0");
  COMPARE(Sqxtun(h20, s0), "sqxtun h20, s0");
  COMPARE(Sqxtun(s21, d0), "sqxtun s21, d0");

  COMPARE(Cls(v1.V8B(), v8_.V8B()), "cls v1.8b, v8.8b");
  COMPARE(Cls(v2.V16B(), v9.V16B()), "cls v2.16b, v9.16b");
  COMPARE(Cls(v3.V4H(), v1.V4H()), "cls v3.4h, v1.4h");
  COMPARE(Cls(v4.V8H(), v2.V8H()), "cls v4.8h, v2.8h");
  COMPARE(Cls(v5.V2S(), v3.V2S()), "cls v5.2s, v3.2s");
  COMPARE(Cls(v6.V4S(), v4.V4S()), "cls v6.4s, v4.4s");

  COMPARE(Clz(v1.V8B(), v8_.V8B()), "clz v1.8b, v8.8b");
  COMPARE(Clz(v2.V16B(), v9.V16B()), "clz v2.16b, v9.16b");
  COMPARE(Clz(v3.V4H(), v1.V4H()), "clz v3.4h, v1.4h");
  COMPARE(Clz(v4.V8H(), v2.V8H()), "clz v4.8h, v2.8h");
  COMPARE(Clz(v5.V2S(), v3.V2S()), "clz v5.2s, v3.2s");
  COMPARE(Clz(v6.V4S(), v4.V4S()), "clz v6.4s, v4.4s");

  COMPARE(Cnt(v1.V8B(), v8_.V8B()), "cnt v1.8b, v8.8b");
  COMPARE(Cnt(v2.V16B(), v9.V16B()), "cnt v2.16b, v9.16b");

  COMPARE(Mvn(v4.V8B(), v5.V8B()), "mvn v4.8b, v5.8b");
  COMPARE(Mvn(v4.V16B(), v5.V16B()), "mvn v4.16b, v5.16b");

  COMPARE(Not(v4.V8B(), v5.V8B()), "mvn v4.8b, v5.8b");
  COMPARE(Not(v4.V16B(), v5.V16B()), "mvn v4.16b, v5.16b");

  COMPARE(Rev64(v1.V8B(), v8_.V8B()), "rev64 v1.8b, v8.8b");
  COMPARE(Rev64(v2.V16B(), v9.V16B()), "rev64 v2.16b, v9.16b");
  COMPARE(Rev64(v3.V4H(), v1.V4H()), "rev64 v3.4h, v1.4h");
  COMPARE(Rev64(v4.V8H(), v2.V8H()), "rev64 v4.8h, v2.8h");
  COMPARE(Rev64(v5.V2S(), v3.V2S()), "rev64 v5.2s, v3.2s");
  COMPARE(Rev64(v6.V4S(), v4.V4S()), "rev64 v6.4s, v4.4s");

  COMPARE(Rev32(v1.V8B(), v8_.V8B()), "rev32 v1.8b, v8.8b");
  COMPARE(Rev32(v2.V16B(), v9.V16B()), "rev32 v2.16b, v9.16b");
  COMPARE(Rev32(v3.V4H(), v1.V4H()), "rev32 v3.4h, v1.4h");
  COMPARE(Rev32(v4.V8H(), v2.V8H()), "rev32 v4.8h, v2.8h");

  COMPARE(Rev16(v1.V8B(), v8_.V8B()), "rev16 v1.8b, v8.8b");
  COMPARE(Rev16(v2.V16B(), v9.V16B()), "rev16 v2.16b, v9.16b");

  COMPARE(Rbit(v1.V8B(), v8_.V8B()), "rbit v1.8b, v8.8b");
  COMPARE(Rbit(v2.V16B(), v9.V16B()), "rbit v2.16b, v9.16b");

  COMPARE(Ursqrte(v2.V2S(), v9.V2S()), "ursqrte v2.2s, v9.2s");
  COMPARE(Ursqrte(v16.V4S(), v23.V4S()), "ursqrte v16.4s, v23.4s");

  COMPARE(Urecpe(v2.V2S(), v9.V2S()), "urecpe v2.2s, v9.2s");
  COMPARE(Urecpe(v16.V4S(), v23.V4S()), "urecpe v16.4s, v23.4s");

  COMPARE(Frsqrte(v2.V2S(), v9.V2S()), "frsqrte v2.2s, v9.2s");
  COMPARE(Frsqrte(v16.V4S(), v23.V4S()), "frsqrte v16.4s, v23.4s");
  COMPARE(Frsqrte(v2.V2D(), v9.V2D()), "frsqrte v2.2d, v9.2d");
  COMPARE(Frsqrte(v0.S(), v1.S()), "frsqrte s0, s1");
  COMPARE(Frsqrte(v0.D(), v1.D()), "frsqrte d0, d1");

  COMPARE(Frecpe(v2.V2S(), v9.V2S()), "frecpe v2.2s, v9.2s");
  COMPARE(Frecpe(v16.V4S(), v23.V4S()), "frecpe v16.4s, v23.4s");
  COMPARE(Frecpe(v2.V2D(), v9.V2D()), "frecpe v2.2d, v9.2d");
  COMPARE(Frecpe(v0.S(), v1.S()), "frecpe s0, s1");
  COMPARE(Frecpe(v0.D(), v1.D()), "frecpe d0, d1");

  COMPARE(Fabs(v2.V2S(), v9.V2S()), "fabs v2.2s, v9.2s");
  COMPARE(Fabs(v16.V4S(), v23.V4S()), "fabs v16.4s, v23.4s");
  COMPARE(Fabs(v31.V2D(), v30.V2D()), "fabs v31.2d, v30.2d");

  COMPARE(Fneg(v2.V2S(), v9.V2S()), "fneg v2.2s, v9.2s");
  COMPARE(Fneg(v16.V4S(), v23.V4S()), "fneg v16.4s, v23.4s");
  COMPARE(Fneg(v31.V2D(), v30.V2D()), "fneg v31.2d, v30.2d");

  COMPARE(Frintn(v2.V2S(), v9.V2S()), "frintn v2.2s, v9.2s");
  COMPARE(Frintn(v16.V4S(), v23.V4S()), "frintn v16.4s, v23.4s");
  COMPARE(Frintn(v31.V2D(), v30.V2D()), "frintn v31.2d, v30.2d");

  COMPARE(Frinta(v2.V2S(), v9.V2S()), "frinta v2.2s, v9.2s");
  COMPARE(Frinta(v16.V4S(), v23.V4S()), "frinta v16.4s, v23.4s");
  COMPARE(Frinta(v31.V2D(), v30.V2D()), "frinta v31.2d, v30.2d");

  COMPARE(Frintp(v2.V2S(), v9.V2S()), "frintp v2.2s, v9.2s");
  COMPARE(Frintp(v16.V4S(), v23.V4S()), "frintp v16.4s, v23.4s");
  COMPARE(Frintp(v31.V2D(), v30.V2D()), "frintp v31.2d, v30.2d");

  COMPARE(Frintm(v2.V2S(), v9.V2S()), "frintm v2.2s, v9.2s");
  COMPARE(Frintm(v16.V4S(), v23.V4S()), "frintm v16.4s, v23.4s");
  COMPARE(Frintm(v31.V2D(), v30.V2D()), "frintm v31.2d, v30.2d");

  COMPARE(Frintx(v2.V2S(), v9.V2S()), "frintx v2.2s, v9.2s");
  COMPARE(Frintx(v16.V4S(), v23.V4S()), "frintx v16.4s, v23.4s");
  COMPARE(Frintx(v31.V2D(), v30.V2D()), "frintx v31.2d, v30.2d");

  COMPARE(Frintz(v2.V2S(), v9.V2S()), "frintz v2.2s, v9.2s");
  COMPARE(Frintz(v16.V4S(), v23.V4S()), "frintz v16.4s, v23.4s");
  COMPARE(Frintz(v31.V2D(), v30.V2D()), "frintz v31.2d, v30.2d");

  COMPARE(Frinti(v2.V2S(), v9.V2S()), "frinti v2.2s, v9.2s");
  COMPARE(Frinti(v16.V4S(), v23.V4S()), "frinti v16.4s, v23.4s");
  COMPARE(Frinti(v31.V2D(), v30.V2D()), "frinti v31.2d, v30.2d");

  COMPARE(Fsqrt(v3.V2S(), v10.V2S()), "fsqrt v3.2s, v10.2s");
  COMPARE(Fsqrt(v22.V4S(), v11.V4S()), "fsqrt v22.4s, v11.4s");
  COMPARE(Fsqrt(v31.V2D(), v0.V2D()), "fsqrt v31.2d, v0.2d");

  COMPARE(Fcvtns(v4.V2S(), v11.V2S()), "fcvtns v4.2s, v11.2s");
  COMPARE(Fcvtns(v23.V4S(), v12.V4S()), "fcvtns v23.4s, v12.4s");
  COMPARE(Fcvtns(v30.V2D(), v1.V2D()), "fcvtns v30.2d, v1.2d");
  COMPARE(Fcvtnu(v4.V2S(), v11.V2S()), "fcvtnu v4.2s, v11.2s");
  COMPARE(Fcvtnu(v23.V4S(), v12.V4S()), "fcvtnu v23.4s, v12.4s");
  COMPARE(Fcvtnu(v30.V2D(), v1.V2D()), "fcvtnu v30.2d, v1.2d");

  COMPARE(Fcvtps(v4.V2S(), v11.V2S()), "fcvtps v4.2s, v11.2s");
  COMPARE(Fcvtps(v23.V4S(), v12.V4S()), "fcvtps v23.4s, v12.4s");
  COMPARE(Fcvtps(v30.V2D(), v1.V2D()), "fcvtps v30.2d, v1.2d");
  COMPARE(Fcvtpu(v4.V2S(), v11.V2S()), "fcvtpu v4.2s, v11.2s");
  COMPARE(Fcvtpu(v23.V4S(), v12.V4S()), "fcvtpu v23.4s, v12.4s");
  COMPARE(Fcvtpu(v30.V2D(), v1.V2D()), "fcvtpu v30.2d, v1.2d");

  COMPARE(Fcvtms(v4.V2S(), v11.V2S()), "fcvtms v4.2s, v11.2s");
  COMPARE(Fcvtms(v23.V4S(), v12.V4S()), "fcvtms v23.4s, v12.4s");
  COMPARE(Fcvtms(v30.V2D(), v1.V2D()), "fcvtms v30.2d, v1.2d");
  COMPARE(Fcvtmu(v4.V2S(), v11.V2S()), "fcvtmu v4.2s, v11.2s");
  COMPARE(Fcvtmu(v23.V4S(), v12.V4S()), "fcvtmu v23.4s, v12.4s");
  COMPARE(Fcvtmu(v30.V2D(), v1.V2D()), "fcvtmu v30.2d, v1.2d");

  COMPARE(Fcvtzs(v4.V2S(), v11.V2S()), "fcvtzs v4.2s, v11.2s");
  COMPARE(Fcvtzs(v23.V4S(), v12.V4S()), "fcvtzs v23.4s, v12.4s");
  COMPARE(Fcvtzs(v30.V2D(), v1.V2D()), "fcvtzs v30.2d, v1.2d");
  COMPARE(Fcvtzu(v4.V2S(), v11.V2S()), "fcvtzu v4.2s, v11.2s");
  COMPARE(Fcvtzu(v23.V4S(), v12.V4S()), "fcvtzu v23.4s, v12.4s");
  COMPARE(Fcvtzu(v30.V2D(), v1.V2D()), "fcvtzu v30.2d, v1.2d");

  COMPARE(Fcvtas(v4.V2S(), v11.V2S()), "fcvtas v4.2s, v11.2s");
  COMPARE(Fcvtas(v23.V4S(), v12.V4S()), "fcvtas v23.4s, v12.4s");
  COMPARE(Fcvtas(v30.V2D(), v1.V2D()), "fcvtas v30.2d, v1.2d");
  COMPARE(Fcvtau(v4.V2S(), v11.V2S()), "fcvtau v4.2s, v11.2s");
  COMPARE(Fcvtau(v23.V4S(), v12.V4S()), "fcvtau v23.4s, v12.4s");
  COMPARE(Fcvtau(v30.V2D(), v1.V2D()), "fcvtau v30.2d, v1.2d");

  COMPARE(Fcvtns(s0, s1), "fcvtns s0, s1");
  COMPARE(Fcvtns(d2, d3), "fcvtns d2, d3");
  COMPARE(Fcvtnu(s4, s5), "fcvtnu s4, s5");
  COMPARE(Fcvtnu(d6, d7), "fcvtnu d6, d7");
  COMPARE(Fcvtps(s8, s9), "fcvtps s8, s9");
  COMPARE(Fcvtps(d10, d11), "fcvtps d10, d11");
  COMPARE(Fcvtpu(s12, s13), "fcvtpu s12, s13");
  COMPARE(Fcvtpu(d14, d15), "fcvtpu d14, d15");
  COMPARE(Fcvtms(s16, s17), "fcvtms s16, s17");
  COMPARE(Fcvtms(d18, d19), "fcvtms d18, d19");
  COMPARE(Fcvtmu(s20, s21), "fcvtmu s20, s21");
  COMPARE(Fcvtmu(d22, d23), "fcvtmu d22, d23");
  COMPARE(Fcvtzs(s24, s25), "fcvtzs s24, s25");
  COMPARE(Fcvtzs(d26, d27), "fcvtzs d26, d27");
  COMPARE(Fcvtzu(s28, s29), "fcvtzu s28, s29");
  COMPARE(Fcvtzu(d30, d31), "fcvtzu d30, d31");
  COMPARE(Fcvtas(s0, s1), "fcvtas s0, s1");
  COMPARE(Fcvtas(d2, d3), "fcvtas d2, d3");
  COMPARE(Fcvtau(s4, s5), "fcvtau s4, s5");
  COMPARE(Fcvtau(d6, d7), "fcvtau d6, d7");

  COMPARE(Fcvtl(v3.V4S(), v5.V4H()), "fcvtl v3.4s, v5.4h");
  COMPARE(Fcvtl(v7.V2D(), v11.V2S()), "fcvtl v7.2d, v11.2s");
  COMPARE(Fcvtl2(v13.V4S(), v17.V8H()), "fcvtl2 v13.4s, v17.8h");
  COMPARE(Fcvtl2(v23.V2D(), v29.V4S()), "fcvtl2 v23.2d, v29.4s");

  COMPARE(Fcvtn(v3.V4H(), v5.V4S()), "fcvtn v3.4h, v5.4s");
  COMPARE(Fcvtn(v7.V2S(), v11.V2D()), "fcvtn v7.2s, v11.2d");
  COMPARE(Fcvtn2(v13.V8H(), v17.V4S()), "fcvtn2 v13.8h, v17.4s");
  COMPARE(Fcvtn2(v23.V4S(), v29.V2D()), "fcvtn2 v23.4s, v29.2d");

  COMPARE(Fcvtxn(v5.V2S(), v7.V2D()), "fcvtxn v5.2s, v7.2d");
  COMPARE(Fcvtxn2(v8_.V4S(), v13.V2D()), "fcvtxn2 v8.4s, v13.2d");
  COMPARE(Fcvtxn(s17, d31), "fcvtxn s17, d31");

  COMPARE(Frecpx(s0, s1), "frecpx s0, s1");
  COMPARE(Frecpx(s31, s30), "frecpx s31, s30");
  COMPARE(Frecpx(d2, d3), "frecpx d2, d3");
  COMPARE(Frecpx(d31, d30), "frecpx d31, d30");

  COMPARE(Scvtf(v5.V2S(), v3.V2S()), "scvtf v5.2s, v3.2s");
  COMPARE(Scvtf(v6.V4S(), v4.V4S()), "scvtf v6.4s, v4.4s");
  COMPARE(Scvtf(v7.V2D(), v5.V2D()), "scvtf v7.2d, v5.2d");
  COMPARE(Scvtf(s8, s6), "scvtf s8, s6");
  COMPARE(Scvtf(d8, d6), "scvtf d8, d6");

  COMPARE(Ucvtf(v5.V2S(), v3.V2S()), "ucvtf v5.2s, v3.2s");
  COMPARE(Ucvtf(v6.V4S(), v4.V4S()), "ucvtf v6.4s, v4.4s");
  COMPARE(Ucvtf(v7.V2D(), v5.V2D()), "ucvtf v7.2d, v5.2d");
  COMPARE(Ucvtf(s8, s6), "ucvtf s8, s6");
  COMPARE(Ucvtf(d8, d6), "ucvtf d8, d6");

#define DISASM_INST(TA, TAS, TB, TBS) \
  COMPARE(Saddlp(v0.TA, v1.TB), "saddlp v0." TAS ", v1." TBS);
  NEON_FORMAT_LIST_LP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS) \
  COMPARE(Uaddlp(v0.TA, v1.TB), "uaddlp v0." TAS ", v1." TBS);
  NEON_FORMAT_LIST_LP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS) \
  COMPARE(Sadalp(v0.TA, v1.TB), "sadalp v0." TAS ", v1." TBS);
  NEON_FORMAT_LIST_LP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(TA, TAS, TB, TBS) \
  COMPARE(Uadalp(v0.TA, v1.TB), "uadalp v0." TAS ", v1." TBS);
  NEON_FORMAT_LIST_LP(DISASM_INST)
#undef DISASM_INST

  CLEANUP();
}

TEST_F(DisasmArm64Test, neon_acrosslanes) {
  SET_UP_MASM();

  COMPARE(Smaxv(b4, v5.V8B()), "smaxv b4, v5.8b");
  COMPARE(Smaxv(b4, v5.V16B()), "smaxv b4, v5.16b");
  COMPARE(Smaxv(h4, v5.V4H()), "smaxv h4, v5.4h");
  COMPARE(Smaxv(h4, v5.V8H()), "smaxv h4, v5.8h");
  COMPARE(Smaxv(s4, v5.V4S()), "smaxv s4, v5.4s");

  COMPARE(Sminv(b4, v5.V8B()), "sminv b4, v5.8b");
  COMPARE(Sminv(b4, v5.V16B()), "sminv b4, v5.16b");
  COMPARE(Sminv(h4, v5.V4H()), "sminv h4, v5.4h");
  COMPARE(Sminv(h4, v5.V8H()), "sminv h4, v5.8h");
  COMPARE(Sminv(s4, v5.V4S()), "sminv s4, v5.4s");

  COMPARE(Umaxv(b4, v5.V8B()), "umaxv b4, v5.8b");
  COMPARE(Umaxv(b4, v5.V16B()), "umaxv b4, v5.16b");
  COMPARE(Umaxv(h4, v5.V4H()), "umaxv h4, v5.4h");
  COMPARE(Umaxv(h4, v5.V8H()), "umaxv h4, v5.8h");
  COMPARE(Umaxv(s4, v5.V4S()), "umaxv s4, v5.4s");

  COMPARE(Uminv(b4, v5.V8B()), "uminv b4, v5.8b");
  COMPARE(Uminv(b4, v5.V16B()), "uminv b4, v5.16b");
  COMPARE(Uminv(h4, v5.V4H()), "uminv h4, v5.4h");
  COMPARE(Uminv(h4, v5.V8H()), "uminv h4, v5.8h");
  COMPARE(Uminv(s4, v5.V4S()), "uminv s4, v5.4s");

  COMPARE(Addv(b4, v5.V8B()), "addv b4, v5.8b");
  COMPARE(Addv(b4, v5.V16B()), "addv b4, v5.16b");
  COMPARE(Addv(h4, v5.V4H()), "addv h4, v5.4h");
  COMPARE(Addv(h4, v5.V8H()), "addv h4, v5.8h");
  COMPARE(Addv(s4, v5.V4S()), "addv s4, v5.4s");

  COMPARE(Saddlv(h4, v5.V8B()), "saddlv h4, v5.8b");
  COMPARE(Saddlv(h4, v5.V16B()), "saddlv h4, v5.16b");
  COMPARE(Saddlv(s4, v5.V4H()), "saddlv s4, v5.4h");
  COMPARE(Saddlv(s4, v5.V8H()), "saddlv s4, v5.8h");
  COMPARE(Saddlv(d4, v5.V4S()), "saddlv d4, v5.4s");

  COMPARE(Uaddlv(h4, v5.V8B()), "uaddlv h4, v5.8b");
  COMPARE(Uaddlv(h4, v5.V16B()), "uaddlv h4, v5.16b");
  COMPARE(Uaddlv(s4, v5.V4H()), "uaddlv s4, v5.4h");
  COMPARE(Uaddlv(s4, v5.V8H()), "uaddlv s4, v5.8h");
  COMPARE(Uaddlv(d4, v5.V4S()), "uaddlv d4, v5.4s");

  COMPARE(Fmaxv(s4, v5.V4S()), "fmaxv s4, v5.4s");
  COMPARE(Fminv(s4, v5.V4S()), "fminv s4, v5.4s");
  COMPARE(Fmaxnmv(s4, v5.V4S()), "fmaxnmv s4, v5.4s");
  COMPARE(Fminnmv(s4, v5.V4S()), "fminnmv s4, v5.4s");

  CLEANUP();
}

TEST_F(DisasmArm64Test, neon_scalar_pairwise) {
  SET_UP_MASM();

  COMPARE(Addp(d0, v1.V2D()), "addp d0, v1.2d");
  COMPARE(Faddp(s0, v1.V2S()), "faddp s0, v1.2s");
  COMPARE(Faddp(d2, v3.V2D()), "faddp d2, v3.2d");
  COMPARE(Fmaxp(s4, v5.V2S()), "fmaxp s4, v5.2s");
  COMPARE(Fmaxp(d6, v7.V2D()), "fmaxp d6, v7.2d");
  COMPARE(Fmaxnmp(s8, v9.V2S()), "fmaxnmp s8, v9.2s");
  COMPARE(Fmaxnmp(d10, v11.V2D()), "fmaxnmp d10, v11.2d");
  COMPARE(Fminp(s12, v13.V2S()), "fminp s12, v13.2s");
  COMPARE(Fminp(d14, v15.V2D()), "fminp d14, v15.2d");
  COMPARE(Fminnmp(s16, v17.V2S()), "fminnmp s16, v17.2s");
  COMPARE(Fminnmp(d18, v19.V2D()), "fminnmp d18, v19.2d");
  CLEANUP();
}

TEST_F(DisasmArm64Test, neon_shift_immediate) {
  SET_UP_MASM();

  COMPARE(Sshr(v0.V8B(), v1.V8B(), 1), "sshr v0.8b, v1.8b, #1");
  COMPARE(Sshr(v2.V8B(), v3.V8B(), 8), "sshr v2.8b, v3.8b, #8");
  COMPARE(Sshr(v4.V16B(), v5.V16B(), 1), "sshr v4.16b, v5.16b, #1");
  COMPARE(Sshr(v6.V16B(), v7.V16B(), 8), "sshr v6.16b, v7.16b, #8");
  COMPARE(Sshr(v8_.V4H(), v9.V4H(), 1), "sshr v8.4h, v9.4h, #1");
  COMPARE(Sshr(v10.V4H(), v11.V4H(), 16), "sshr v10.4h, v11.4h, #16");
  COMPARE(Sshr(v12.V8H(), v13.V8H(), 1), "sshr v12.8h, v13.8h, #1");
  COMPARE(Sshr(v14.V8H(), v15.V8H(), 16), "sshr v14.8h, v15.8h, #16");
  COMPARE(Sshr(v16.V2S(), v17.V2S(), 1), "sshr v16.2s, v17.2s, #1");
  COMPARE(Sshr(v18.V2S(), v19.V2S(), 32), "sshr v18.2s, v19.2s, #32");
  COMPARE(Sshr(v20.V4S(), v21.V4S(), 1), "sshr v20.4s, v21.4s, #1");
  COMPARE(Sshr(v22.V4S(), v23.V4S(), 32), "sshr v22.4s, v23.4s, #32");
  COMPARE(Sshr(v28.V2D(), v29.V2D(), 1), "sshr v28.2d, v29.2d, #1");
  COMPARE(Sshr(v30.V2D(), v31.V2D(), 64), "sshr v30.2d, v31.2d, #64");
  COMPARE(Sshr(d0, d1, 7), "sshr d0, d1, #7");

  COMPARE(Ushr(v0.V8B(), v1.V8B(), 1), "ushr v0.8b, v1.8b, #1");
  COMPARE(Ushr(v2.V8B(), v3.V8B(), 8), "ushr v2.8b, v3.8b, #8");
  COMPARE(Ushr(v4.V16B(), v5.V16B(), 1), "ushr v4.16b, v5.16b, #1");
  COMPARE(Ushr(v6.V16B(), v7.V16B(), 8), "ushr v6.16b, v7.16b, #8");
  COMPARE(Ushr(v8_.V4H(), v9.V4H(), 1), "ushr v8.4h, v9.4h, #1");
  COMPARE(Ushr(v10.V4H(), v11.V4H(), 16), "ushr v10.4h, v11.4h, #16");
  COMPARE(Ushr(v12.V8H(), v13.V8H(), 1), "ushr v12.8h, v13.8h, #1");
  COMPARE(Ushr(v14.V8H(), v15.V8H(), 16), "ushr v14.8h, v15.8h, #16");
  COMPARE(Ushr(v16.V2S(), v17.V2S(), 1), "ushr v16.2s, v17.2s, #1");
  COMPARE(Ushr(v18.V2S(), v19.V2S(), 32), "ushr v18.2s, v19.2s, #32");
  COMPARE(Ushr(v20.V4S(), v21.V4S(), 1), "ushr v20.4s, v21.4s, #1");
  COMPARE(Ushr(v22.V4S(), v23.V4S(), 32), "ushr v22.4s, v23.4s, #32");
  COMPARE(Ushr(v28.V2D(), v29.V2D(), 1), "ushr v28.2d, v29.2d, #1");
  COMPARE(Ushr(v30.V2D(), v31.V2D(), 64), "ushr v30.2d, v31.2d, #64");
  COMPARE(Ushr(d0, d1, 7), "ushr d0, d1, #7");

  COMPARE(Srshr(v0.V8B(), v1.V8B(), 1), "srshr v0.8b, v1.8b, #1");
  COMPARE(Srshr(v2.V8B(), v3.V8B(), 8), "srshr v2.8b, v3.8b, #8");
  COMPARE(Srshr(v4.V16B(), v5.V16B(), 1), "srshr v4.16b, v5.16b, #1");
  COMPARE(Srshr(v6.V16B(), v7.V16B(), 8), "srshr v6.16b, v7.16b, #8");
  COMPARE(Srshr(v8_.V4H(), v9.V4H(), 1), "srshr v8.4h, v9.4h, #1");
  COMPARE(Srshr(v10.V4H(), v11.V4H(), 16), "srshr v10.4h, v11.4h, #16");
  COMPARE(Srshr(v12.V8H(), v13.V8H(), 1), "srshr v12.8h, v13.8h, #1");
  COMPARE(Srshr(v14.V8H(), v15.V8H(), 16), "srshr v14.8h, v15.8h, #16");
  COMPARE(Srshr(v16.V2S(), v17.V2S(), 1), "srshr v16.2s, v17.2s, #1");
  COMPARE(Srshr(v18.V2S(), v19.V2S(), 32), "srshr v18.2s, v19.2s, #32");
  COMPARE(Srshr(v20.V4S(), v21.V4S(), 1), "srshr v20.4s, v21.4s, #1");
  COMPARE(Srshr(v22.V4S(), v23.V4S(), 32), "srshr v22.4s, v23.4s, #32");
  COMPARE(Srshr(v28.V2D(), v29.V2D(), 1), "srshr v28.2d, v29.2d, #1");
  COMPARE(Srshr(v30.V2D(), v31.V2D(), 64), "srshr v30.2d, v31.2d, #64");
  COMPARE(Srshr(d0, d1, 7), "srshr d0, d1, #7");

  COMPARE(Urshr(v0.V8B(), v1.V8B(), 1), "urshr v0.8b, v1.8b, #1");
  COMPARE(Urshr(v2.V8B(), v3.V8B(), 8), "urshr v2.8b, v3.8b, #8");
  COMPARE(Urshr(v4.V16B(), v5.V16B(), 1), "urshr v4.16b, v5.16b, #1");
  COMPARE(Urshr(v6.V16B(), v7.V16B(), 8), "urshr v6.16b, v7.16b, #8");
  COMPARE(Urshr(v8_.V4H(), v9.V4H(), 1), "urshr v8.4h, v9.4h, #1");
  COMPARE(Urshr(v10.V4H(), v11.V4H(), 16), "urshr v10.4h, v11.4h, #16");
  COMPARE(Urshr(v12.V8H(), v13.V8H(), 1), "urshr v12.8h, v13.8h, #1");
  COMPARE(Urshr(v14.V8H(), v15.V8H(), 16), "urshr v14.8h, v15.8h, #16");
  COMPARE(Urshr(v16.V2S(), v17.V2S(), 1), "urshr v16.2s, v17.2s, #1");
  COMPARE(Urshr(v18.V2S(), v19.V2S(), 32), "urshr v18.2s, v19.2s, #32");
  COMPARE(Urshr(v20.V4S(), v21.V4S(), 1), "urshr v20.4s, v21.4s, #1");
  COMPARE(Urshr(v22.V4S(), v23.V4S(), 32), "urshr v22.4s, v23.4s, #32");
  COMPARE(Urshr(v28.V2D(), v29.V2D(), 1), "urshr v28.2d, v29.2d, #1");
  COMPARE(Urshr(v30.V2D(), v31.V2D(), 64), "urshr v30.2d, v31.2d, #64");
  COMPARE(Urshr(d0, d1, 7), "urshr d0, d1, #7");

  COMPARE(Srsra(v0.V8B(), v1.V8B(), 1), "srsra v0.8b, v1.8b, #1");
  COMPARE(Srsra(v2.V8B(), v3.V8B(), 8), "srsra v2.8b, v3.8b, #8");
  COMPARE(Srsra(v4.V16B(), v5.V16B(), 1), "srsra v4.16b, v5.16b, #1");
  COMPARE(Srsra(v6.V16B(), v7.V16B(), 8), "srsra v6.16b, v7.16b, #8");
  COMPARE(Srsra(v8_.V4H(), v9.V4H(), 1), "srsra v8.4h, v9.4h, #1");
  COMPARE(Srsra(v10.V4H(), v11.V4H(), 16), "srsra v10.4h, v11.4h, #16");
  COMPARE(Srsra(v12.V8H(), v13.V8H(), 1), "srsra v12.8h, v13.8h, #1");
  COMPARE(Srsra(v14.V8H(), v15.V8H(), 16), "srsra v14.8h, v15.8h, #16");
  COMPARE(Srsra(v16.V2S(), v17.V2S(), 1), "srsra v16.2s, v17.2s, #1");
  COMPARE(Srsra(v18.V2S(), v19.V2S(), 32), "srsra v18.2s, v19.2s, #32");
  COMPARE(Srsra(v20.V4S(), v21.V4S(), 1), "srsra v20.4s, v21.4s, #1");
  COMPARE(Srsra(v22.V4S(), v23.V4S(), 32), "srsra v22.4s, v23.4s, #32");
  COMPARE(Srsra(v28.V2D(), v29.V2D(), 1), "srsra v28.2d, v29.2d, #1");
  COMPARE(Srsra(v30.V2D(), v31.V2D(), 64), "srsra v30.2d, v31.2d, #64");
  COMPARE(Srsra(d0, d1, 7), "srsra d0, d1, #7");

  COMPARE(Ssra(v0.V8B(), v1.V8B(), 1), "ssra v0.8b, v1.8b, #1");
  COMPARE(Ssra(v2.V8B(), v3.V8B(), 8), "ssra v2.8b, v3.8b, #8");
  COMPARE(Ssra(v4.V16B(), v5.V16B(), 1), "ssra v4.16b, v5.16b, #1");
  COMPARE(Ssra(v6.V16B(), v7.V16B(), 8), "ssra v6.16b, v7.16b, #8");
  COMPARE(Ssra(v8_.V4H(), v9.V4H(), 1), "ssra v8.4h, v9.4h, #1");
  COMPARE(Ssra(v10.V4H(), v11.V4H(), 16), "ssra v10.4h, v11.4h, #16");
  COMPARE(Ssra(v12.V8H(), v13.V8H(), 1), "ssra v12.8h, v13.8h, #1");
  COMPARE(Ssra(v14.V8H(), v15.V8H(), 16), "ssra v14.8h, v15.8h, #16");
  COMPARE(Ssra(v16.V2S(), v17.V2S(), 1), "ssra v16.2s, v17.2s, #1");
  COMPARE(Ssra(v18.V2S(), v19.V2S(), 32), "ssra v18.2s, v19.2s, #32");
  COMPARE(Ssra(v20.V4S(), v21.V4S(), 1), "ssra v20.4s, v21.4s, #1");
  COMPARE(Ssra(v22.V4S(), v23.V4S(), 32), "ssra v22.4s, v23.4s, #32");
  COMPARE(Ssra(v28.V2D(), v29.V2D(), 1), "ssra v28.2d, v29.2d, #1");
  COMPARE(Ssra(v30.V2D(), v31.V2D(), 64), "ssra v30.2d, v31.2d, #64");
  COMPARE(Ssra(d0, d1, 7), "ssra d0, d1, #7");

  COMPARE(Ursra(v0.V8B(), v1.V8B(), 1), "ursra v0.8b, v1.8b, #1");
  COMPARE(Ursra(v2.V8B(), v3.V8B(), 8), "ursra v2.8b, v3.8b, #8");
  COMPARE(Ursra(v4.V16B(), v5.V16B(), 1), "ursra v4.16b, v5.16b, #1");
  COMPARE(Ursra(v6.V16B(), v7.V16B(), 8), "ursra v6.16b, v7.16b, #8");
  COMPARE(Ursra(v8_.V4H(), v9.V4H(), 1), "ursra v8.4h, v9.4h, #1");
  COMPARE(Ursra(v10.V4H(), v11.V4H(), 16), "ursra v10.4h, v11.4h, #16");
  COMPARE(Ursra(v12.V8H(), v13.V8H(), 1), "ursra v12.8h, v13.8h, #1");
  COMPARE(Ursra(v14.V8H(), v15.V8H(), 16), "ursra v14.8h, v15.8h, #16");
  COMPARE(Ursra(v16.V2S(), v17.V2S(), 1), "ursra v16.2s, v17.2s, #1");
  COMPARE(Ursra(v18.V2S(), v19.V2S(), 32), "ursra v18.2s, v19.2s, #32");
  COMPARE(Ursra(v20.V4S(), v21.V4S(), 1), "ursra v20.4s, v21.4s, #1");
  COMPARE(Ursra(v22.V4S(), v23.V4S(), 32), "ursra v22.4s, v23.4s, #32");
  COMPARE(Ursra(v28.V2D(), v29.V2D(), 1), "ursra v28.2d, v29.2d, #1");
  COMPARE(Ursra(v30.V2D(), v31.V2D(), 64), "ursra v30.2d, v31.2d, #64");
  COMPARE(Ursra(d0, d1, 7), "ursra d0, d1, #7");

  COMPARE(Usra(v0.V8B(), v1.V8B(), 1), "usra v0.8b, v1.8b, #1");
  COMPARE(Usra(v2.V8B(), v3.V8B(), 8), "usra v2.8b, v3.8b, #8");
  COMPARE(Usra(v4.V16B(), v5.V16B(), 1), "usra v4.16b, v5.16b, #1");
  COMPARE(Usra(v6.V16B(), v7.V16B(), 8), "usra v6.16b, v7.16b, #8");
  COMPARE(Usra(v8_.V4H(), v9.V4H(), 1), "usra v8.4h, v9.4h, #1");
  COMPARE(Usra(v10.V4H(), v11.V4H(), 16), "usra v10.4h, v11.4h, #16");
  COMPARE(Usra(v12.V8H(), v13.V8H(), 1), "usra v12.8h, v13.8h, #1");
  COMPARE(Usra(v14.V8H(), v15.V8H(), 16), "usra v14.8h, v15.8h, #16");
  COMPARE(Usra(v16.V2S(), v17.V2S(), 1), "usra v16.2s, v17.2s, #1");
  COMPARE(Usra(v18.V2S(), v19.V2S(), 32), "usra v18.2s, v19.2s, #32");
  COMPARE(Usra(v20.V4S(), v21.V4S(), 1), "usra v20.4s, v21.4s, #1");
  COMPARE(Usra(v22.V4S(), v23.V4S(), 32), "usra v22.4s, v23.4s, #32");
  COMPARE(Usra(v28.V2D(), v29.V2D(), 1), "usra v28.2d, v29.2d, #1");
  COMPARE(Usra(v30.V2D(), v31.V2D(), 64), "usra v30.2d, v31.2d, #64");
  COMPARE(Usra(d0, d1, 7), "usra d0, d1, #7");

  COMPARE(Sli(v1.V8B(), v8_.V8B(), 1), "sli v1.8b, v8.8b, #1");
  COMPARE(Sli(v2.V16B(), v9.V16B(), 2), "sli v2.16b, v9.16b, #2");
  COMPARE(Sli(v3.V4H(), v1.V4H(), 3), "sli v3.4h, v1.4h, #3");
  COMPARE(Sli(v4.V8H(), v2.V8H(), 4), "sli v4.8h, v2.8h, #4");
  COMPARE(Sli(v5.V2S(), v3.V2S(), 5), "sli v5.2s, v3.2s, #5");
  COMPARE(Sli(v6.V4S(), v4.V4S(), 6), "sli v6.4s, v4.4s, #6");
  COMPARE(Sli(v7.V2D(), v5.V2D(), 7), "sli v7.2d, v5.2d, #7");
  COMPARE(Sli(d8, d6, 8), "sli d8, d6, #8");

  COMPARE(Shl(v1.V8B(), v8_.V8B(), 1), "shl v1.8b, v8.8b, #1");
  COMPARE(Shl(v2.V16B(), v9.V16B(), 2), "shl v2.16b, v9.16b, #2");
  COMPARE(Shl(v3.V4H(), v1.V4H(), 3), "shl v3.4h, v1.4h, #3");
  COMPARE(Shl(v4.V8H(), v2.V8H(), 4), "shl v4.8h, v2.8h, #4");
  COMPARE(Shl(v5.V2S(), v3.V2S(), 5), "shl v5.2s, v3.2s, #5");
  COMPARE(Shl(v6.V4S(), v4.V4S(), 6), "shl v6.4s, v4.4s, #6");
  COMPARE(Shl(v7.V2D(), v5.V2D(), 7), "shl v7.2d, v5.2d, #7");
  COMPARE(Shl(d8, d6, 8), "shl d8, d6, #8");

  COMPARE(Sqshl(v1.V8B(), v8_.V8B(), 1), "sqshl v1.8b, v8.8b, #1");
  COMPARE(Sqshl(v2.V16B(), v9.V16B(), 2), "sqshl v2.16b, v9.16b, #2");
  COMPARE(Sqshl(v3.V4H(), v1.V4H(), 3), "sqshl v3.4h, v1.4h, #3");
  COMPARE(Sqshl(v4.V8H(), v2.V8H(), 4), "sqshl v4.8h, v2.8h, #4");
  COMPARE(Sqshl(v5.V2S(), v3.V2S(), 5), "sqshl v5.2s, v3.2s, #5");
  COMPARE(Sqshl(v6.V4S(), v4.V4S(), 6), "sqshl v6.4s, v4.4s, #6");
  COMPARE(Sqshl(v7.V2D(), v5.V2D(), 7), "sqshl v7.2d, v5.2d, #7");
  COMPARE(Sqshl(b8, b7, 1), "sqshl b8, b7, #1");
  COMPARE(Sqshl(h9, h8, 2), "sqshl h9, h8, #2");
  COMPARE(Sqshl(s10, s9, 3), "sqshl s10, s9, #3");
  COMPARE(Sqshl(d11, d10, 4), "sqshl d11, d10, #4");

  COMPARE(Sqshlu(v1.V8B(), v8_.V8B(), 1), "sqshlu v1.8b, v8.8b, #1");
  COMPARE(Sqshlu(v2.V16B(), v9.V16B(), 2), "sqshlu v2.16b, v9.16b, #2");
  COMPARE(Sqshlu(v3.V4H(), v1.V4H(), 3), "sqshlu v3.4h, v1.4h, #3");
  COMPARE(Sqshlu(v4.V8H(), v2.V8H(), 4), "sqshlu v4.8h, v2.8h, #4");
  COMPARE(Sqshlu(v5.V2S(), v3.V2S(), 5), "sqshlu v5.2s, v3.2s, #5");
  COMPARE(Sqshlu(v6.V4S(), v4.V4S(), 6), "sqshlu v6.4s, v4.4s, #6");
  COMPARE(Sqshlu(v7.V2D(), v5.V2D(), 7), "sqshlu v7.2d, v5.2d, #7");
  COMPARE(Sqshlu(b8, b7, 1), "sqshlu b8, b7, #1");
  COMPARE(Sqshlu(h9, h8, 2), "sqshlu h9, h8, #2");
  COMPARE(Sqshlu(s10, s9, 3), "sqshlu s10, s9, #3");
  COMPARE(Sqshlu(d11, d10, 4), "sqshlu d11, d10, #4");

  COMPARE(Uqshl(v1.V8B(), v8_.V8B(), 1), "uqshl v1.8b, v8.8b, #1");
  COMPARE(Uqshl(v2.V16B(), v9.V16B(), 2), "uqshl v2.16b, v9.16b, #2");
  COMPARE(Uqshl(v3.V4H(), v1.V4H(), 3), "uqshl v3.4h, v1.4h, #3");
  COMPARE(Uqshl(v4.V8H(), v2.V8H(), 4), "uqshl v4.8h, v2.8h, #4");
  COMPARE(Uqshl(v5.V2S(), v3.V2S(), 5), "uqshl v5.2s, v3.2s, #5");
  COMPARE(Uqshl(v6.V4S(), v4.V4S(), 6), "uqshl v6.4s, v4.4s, #6");
  COMPARE(Uqshl(v7.V2D(), v5.V2D(), 7), "uqshl v7.2d, v5.2d, #7");
  COMPARE(Uqshl(b8, b7, 1), "uqshl b8, b7, #1");
  COMPARE(Uqshl(h9, h8, 2), "uqshl h9, h8, #2");
  COMPARE(Uqshl(s10, s9, 3), "uqshl s10, s9, #3");
  COMPARE(Uqshl(d11, d10, 4), "uqshl d11, d10, #4");

  COMPARE(Sshll(v1.V8H(), v8_.V8B(), 1), "sshll v1.8h, v8.8b, #1");
  COMPARE(Sshll(v3.V4S(), v1.V4H(), 3), "sshll v3.4s, v1.4h, #3");
  COMPARE(Sshll(v5.V2D(), v3.V2S(), 5), "sshll v5.2d, v3.2s, #5");
  COMPARE(Sshll2(v2.V8H(), v9.V16B(), 2), "sshll2 v2.8h, v9.16b, #2");
  COMPARE(Sshll2(v4.V4S(), v2.V8H(), 4), "sshll2 v4.4s, v2.8h, #4");
  COMPARE(Sshll2(v6.V2D(), v4.V4S(), 6), "sshll2 v6.2d, v4.4s, #6");

  COMPARE(Sshll(v1.V8H(), v8_.V8B(), 0), "sxtl v1.8h, v8.8b");
  COMPARE(Sshll(v3.V4S(), v1.V4H(), 0), "sxtl v3.4s, v1.4h");
  COMPARE(Sshll(v5.V2D(), v3.V2S(), 0), "sxtl v5.2d, v3.2s");
  COMPARE(Sshll2(v2.V8H(), v9.V16B(), 0), "sxtl2 v2.8h, v9.16b");
  COMPARE(Sshll2(v4.V4S(), v2.V8H(), 0), "sxtl2 v4.4s, v2.8h");
  COMPARE(Sshll2(v6.V2D(), v4.V4S(), 0), "sxtl2 v6.2d, v4.4s");

  COMPARE(Sxtl(v1.V8H(), v8_.V8B()), "sxtl v1.8h, v8.8b");
  COMPARE(Sxtl(v3.V4S(), v1.V4H()), "sxtl v3.4s, v1.4h");
  COMPARE(Sxtl(v5.V2D(), v3.V2S()), "sxtl v5.2d, v3.2s");
  COMPARE(Sxtl2(v2.V8H(), v9.V16B()), "sxtl2 v2.8h, v9.16b");
  COMPARE(Sxtl2(v4.V4S(),
"""


```