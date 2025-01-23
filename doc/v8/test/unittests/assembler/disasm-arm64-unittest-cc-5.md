Response:
The user wants a summary of the functionality of the provided C++ code snippet.
This code is a unit test file for the ARM64 disassembler in the V8 JavaScript engine.
It tests the disassembler by generating ARM64 instructions using the `Assembler` class and then comparing the disassembled output with expected strings.

Here's a breakdown of the thought process:

1. **Identify the core purpose:** The filename `disasm-arm64-unittest.cc` and the context of `v8/test/unittests/assembler/` strongly suggest this is a unit test for the ARM64 disassembler.

2. **Analyze the code structure:**  The code consists of several `TEST_F` blocks within a `DisasmArm64Test` fixture. Each `TEST_F` focuses on a specific category of ARM64 instructions (e.g., `neon_arith`, `neon_byelement`, `neon_fp_byelement`, etc.).

3. **Examine the `COMPARE` macro:** The `COMPARE` macro is central to the tests. It takes an assembler instruction and an expected disassembled string as arguments. This reveals the core testing methodology: generate an instruction, disassemble it, and verify the output.

4. **Look for patterns within the tests:**
    * **Instruction generation:**  The code uses the V8 `Assembler` class to create ARM64 instructions. Examples include `Add(v0.V8B(), v1.V8B(), v2.V8B())`, `Facgt(v13.S(), v14.S(), v15.S())`, etc.
    * **Disassembly (implicit):** The `COMPARE` macro internally triggers the disassembler for the generated instruction.
    * **String comparison:** The second argument to `COMPARE` is the expected string representation of the disassembled instruction.

5. **Identify the instruction categories being tested:** The `TEST_F` names give a good overview of the categories:
    * `neon_arith`:  NEON arithmetic instructions.
    * `neon_scalar_arith`: NEON scalar arithmetic instructions.
    * `neon_byelement`: NEON instructions operating on specific elements of vectors.
    * `neon_fp_byelement`: NEON floating-point instructions operating on specific elements.
    * `neon_3different`: NEON instructions with three different vector operands.
    * `neon_perm`: NEON permutation instructions.
    * `neon_copy`: NEON instructions for copying and moving data.
    * `neon_extract`: NEON instructions for extracting data.
    * `neon_table`: NEON table lookup instructions.
    * `neon_modimm`: NEON instructions with immediate operands.

6. **Address the specific questions:**
    * **Functionality:** The code tests the ARM64 disassembler by verifying its output for various instructions.
    * **.tq extension:**  The code is C++, so it's not a Torque file.
    * **Relationship to JavaScript:**  While this specific code is for testing, the underlying disassembler is used by the V8 engine, which executes JavaScript. Disassembly is needed for debugging, profiling, and potentially JIT compilation.
    * **JavaScript example (if applicable):** Since the direct connection is the underlying V8 engine, an example would show how these instructions might be used within optimized JavaScript execution. A simple example involving array manipulation could be used to illustrate the potential use of NEON instructions.
    * **Logic and assumptions:** The tests implicitly assume the correctness of the `Assembler` when generating the instructions. The output is compared against hardcoded strings, representing the expected disassembly.
    * **Common programming errors:** This unit test code itself is less prone to common *user* errors. However, incorrect disassembler logic would be the "error" being tested. A user might encounter issues if the disassembler incorrectly represents instructions during debugging.
    * **归纳功能 (Summarize functionality):** Consolidate the findings from the previous steps into a concise summary.

7. **Consider the "Part X of 8" context:** This indicates that the current snippet is part of a larger test suite. The functionality of this specific part is to test a subset of ARM64 NEON instructions.

By following these steps, we can arrive at a comprehensive and accurate description of the code's functionality, addressing all the user's requests.
这是一个V8 JavaScript引擎的单元测试文件，专门用于测试ARM64架构的反汇编器 (`disassembler`) 的功能。 这个文件的主要目的是验证反汇编器是否能将特定的ARM64机器码指令正确地转换回可读的汇编代码。

**功能归纳 (针对提供的第6部分代码):**

这部分代码着重测试了ARM64架构中与 **NEON（Advanced SIMD）** 相关的指令的反汇编功能，特别是以下几类：

* **NEON 标量算术运算 (Scalar Arithmetic):**  测试了诸如 `facgt` (浮点数绝对值比较大于), `sqdmulh` (有符号饱和双字乘高位), `sqrdmulh` (有符号饱和舍入双字乘高位), 以及一系列带饱和运算的加减和移位指令（`uqadd`, `uqsub`, `sqadd`, `sqsub`, `uqshl`, `sqshl`, `uqrshl`, `sqrshl`）。这些指令都是对NEON寄存器中的标量（单个元素）进行操作。

* **NEON 按元素运算 (By Element Operations):** 测试了需要指定第二个源操作数中特定元素的NEON指令，例如 `mul` (乘法), `mla` (乘法累加), `mls` (乘法减法), `sqdmulh` 和 `sqrdmulh` 的向量形式，以及扩展的乘法指令（`smull`, `umull`, `smlal`, `umlal`, `smlsl`, `umlsl`, `sqdmull`, `sqdmlal`, `sqdmlsl`）。这些指令允许向量中的元素与另一个向量的特定元素进行运算。

* **NEON 浮点按元素运算 (Floating-Point By Element Operations):**  测试了浮点数版本的按元素 NEON 指令，例如 `fmul` (浮点乘法), `fmla` (浮点乘法累加), `fmls` (浮点乘法减法) 和 `fmulx` (精确浮点乘法)。

* **NEON 三个不同操作数指令 (Three Different Operands):** 测试了需要三个不同向量寄存器作为操作数的 NEON 指令，包括扩展的加法、减法、绝对差累加指令 (`uaddl`, `uaddw`, `saddl`, `saddw`, `usubl`, `usubw`, `ssubl`, `ssubw`, `sabal`, `uabal`, `sabdl`, `uabdl`)，以及扩展的乘法累加/减指令 (`smlal`, `umlsl`, `smlsl`, `umlsl`, `smull`, `umull`) 和饱和双字乘法指令 (`sqdmull`, `sqdmlal`, `sqdmlsl`)，以及缩小指令 (`addhn`, `raddhn`, `subhn`, `rsubhn`) 和多项式乘法 (`pmull`) 以及点积运算 (`sdot`)。

**关于代码的特性:**

* **`COMPARE` 宏:** 这个宏是测试的核心，它执行以下操作：
    1. 使用提供的 `Assembler` 方法生成一段机器码。
    2. 对生成的机器码进行反汇编。
    3. 将反汇编的结果与提供的字符串进行比较，如果一致则测试通过，否则测试失败。

* **`NEON_SCALAR_FORMAT_LIST` 和 `NEON_FORMAT_LIST_LW` 等宏:**  这些宏用于简化测试代码的编写，它们会展开成一系列针对不同数据类型（例如 Half-word, Single-word）的 `COMPARE` 调用，以覆盖指令的不同变体。

**如果 `v8/test/unittests/assembler/disasm-arm64-unittest.cc` 以 `.tq` 结尾:**

如果文件以 `.tq` 结尾，那么它将是一个 **Torque** 源代码文件。Torque 是 V8 用来定义运行时内置函数和类型系统的领域特定语言。这个文件会包含用 Torque 编写的代码，用于生成 V8 运行时的代码，而不是像现在这样测试反汇编器。

**与 JavaScript 的关系:**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它测试的 **反汇编器** 是 V8 JavaScript 引擎的关键组成部分。反汇编器在以下场景中可能与 JavaScript 功能相关：

* **调试:** 当开发者需要查看 JavaScript 代码在底层是如何被执行的，他们可能会使用调试工具查看 V8 生成的机器码的反汇编结果。
* **性能分析:**  性能分析工具可能会使用反汇编来理解热点代码的机器码实现，以便进行更深入的优化。
* **JIT (Just-In-Time) 编译:**  虽然反汇编器本身不参与 JIT 编译，但理解反汇编的原理有助于理解 JIT 编译器生成的代码。

**JavaScript 示例 (假设某个 NEON 指令与 JavaScript 有直接关联):**

由于 NEON 指令是底层的 SIMD 指令，JavaScript 开发者通常不会直接写这些指令。但是，V8 引擎在执行某些 JavaScript 操作时，可能会在底层使用 NEON 指令进行优化。

例如，假设 JavaScript 中对一个数组进行批量加法操作：

```javascript
const arr1 = [1, 2, 3, 4];
const arr2 = [5, 6, 7, 8];
const result = arr1.map((x, i) => x + arr2[i]);
console.log(result); // 输出 [6, 8, 10, 12]
```

在 V8 引擎的优化下，这个 `map` 操作可能会被编译成使用 NEON 的向量加法指令，例如 `add v0.4s, v1.4s, v2.4s`，其中 `v0`, `v1`, `v2` 是 NEON 寄存器，分别存储结果和两个输入数组的部分数据。  这个测试文件就是用来确保 V8 的反汇编器能够正确地将这样的 NEON 指令反汇编成 `add v0.4s, v1.4s, v2.4s` 这样的字符串。

**代码逻辑推理，假设输入与输出:**

这个测试文件的逻辑主要是验证反汇编的正确性。对于每个 `COMPARE` 宏调用：

* **假设输入 (隐式):**  `Assembler` 方法生成的特定 ARM64 机器码序列。例如，对于 `COMPARE(Facgt(v13.S(), v14.S(), v15.S()), "facgt s13, s14, s15");`， 假设 `Facgt(v13.S(), v14.S(), v15.S())` 内部会生成 `0xXXXXXXXX` 这样的机器码。
* **输出:** 反汇编器将该机器码转换为字符串 `"facgt s13, s14, s15"`。  `COMPARE` 宏会比较实际反汇编输出和这个预期的字符串。

**涉及用户常见的编程错误 (与反汇编器测试本身关联不大):**

这个测试文件本身是为了确保 V8 内部工具的正确性，与用户编写 JavaScript 代码时常犯的错误关系不大。然而，如果反汇编器出现错误，可能会影响开发者调试 JavaScript 代码，例如：

* **误解机器码含义:** 如果反汇编结果不正确，开发者在查看反汇编代码时可能会对程序的实际执行流程产生错误的理解。
* **调试困难:** 不正确的反汇编输出会使调试工具提供的底层信息不可靠，增加调试难度。

**总结第6部分的功能:**

总而言之，`v8/test/unittests/assembler/disasm-arm64-unittest.cc` 的第6部分专注于测试 V8 引擎中 ARM64 反汇编器对于各种 NEON 指令的正确反汇编能力。它通过生成特定的 NEON 指令，然后验证反汇编器是否能将其转换回预期的汇编代码字符串来实现这一目标。这对于确保 V8 引擎的调试、性能分析等工具的可靠性至关重要。

### 提示词
```
这是目录为v8/test/unittests/assembler/disasm-arm64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/assembler/disasm-arm64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
3.S(), v14.S()), "facgt s12, s13, s14");
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
```