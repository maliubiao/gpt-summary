Response:
Let's break down the thought process for analyzing this C++ unit test file.

1. **Understand the Goal:** The primary goal is to figure out what this specific C++ file (`disasm-s390-unittest.cc`) does within the V8 project. The filename hints at "disassembler" and the "s390" architecture. The "unittest" part is a big clue – it's for testing.

2. **High-Level Structure Scan:** Quickly scan the code for key elements:
    * **Copyright Notice:**  Standard boilerplate, confirms it's V8 code.
    * **Includes:**  Look for relevant headers. `macro-assembler.h`, `disasm.h`, `disassembler.h` strongly point to assembly and disassembly functionality. `test-utils.h` and `gtest/gtest.h` confirm it's a unit test.
    * **Namespaces:** `v8::internal` indicates internal V8 functionality.
    * **`using DisasmS390Test = TestWithIsolate;`**: This is a common pattern in V8 unit tests. It's creating a test fixture that sets up an isolated V8 environment for each test.
    * **Functions:** The `DisassembleAndCompare` function looks crucial. It takes a memory address and a string, suggests it disassembles code at that address and compares the result.
    * **Macros (`SET_UP`, `COMPARE`, `VERIFY_RUN`):**  These are defining the test structure. `COMPARE` looks like the core testing action.
    * **`TEST_F` blocks:** These are the individual test cases. The names (`TwoBytes`, `FourBytes`, `SixBytes`) likely refer to the instruction lengths being tested.

3. **Focus on Key Functionality (`DisassembleAndCompare`):**
    * **Input:** `uint8_t* pc` (program counter/memory address), `const char* compare_string` (the expected disassembly).
    * **Process:**
        * Creates `disasm::NameConverter` and `disasm::Disassembler`. These are the core disassembly tools.
        * `disasm.InstructionDecode(disasm_buffer, pc);`  This is the actual disassembly happening.
        * `strcmp(compare_string, disasm_buffer.begin())` compares the disassembled output with the expected string.
        * If they don't match, it prints an error message to `stderr`.
    * **Output:** `true` if disassembly matches, `false` otherwise.

4. **Understand the Macros:**
    * **`SET_UP()`:**  Allocates a buffer to hold assembly code and creates an `Assembler` object that writes to this buffer. This sets up the environment for generating machine code.
    * **`COMPARE(asm_, compare_string)`:**
        * Gets the current offset in the buffer (`assm.pc_offset()`).
        * Calculates the memory address of the next instruction to be assembled.
        * Executes the assembly instruction (`assm.asm_`).
        * Calls `DisassembleAndCompare` to verify the disassembled output.
        * Sets the `failure` flag if the comparison fails.
    * **`VERIFY_RUN()`:** Checks the `failure` flag and calls `FATAL` (which likely stops the test) if any comparison failed.

5. **Analyze the Test Cases (`TEST_F`):**
    * Each test case sets up the environment (`SET_UP()`).
    * They then use multiple `COMPARE` calls, each assembling a specific S390 instruction and checking its disassembled form.
    * The strings passed to `COMPARE` are the expected disassembly output. This is the "ground truth" for the test.
    * Finally, they call `VERIFY_RUN()` to check for overall test failures.

6. **Connect to V8's Purpose:** This code is crucial for V8's ability to:
    * **Generate machine code:** The `Assembler` is used to create the binary instructions.
    * **Debug and inspect code:** The disassembler is essential for understanding the generated machine code, especially during debugging or performance analysis. It helps developers see what the JavaScript code has been translated into at the lowest level.

7. **Address Specific Questions from the Prompt:**

    * **Functionality:** It tests the S390 disassembler by assembling instructions and comparing the disassembled output against expected strings.
    * **`.tq` extension:**  No, the filename ends in `.cc`, so it's C++.
    * **Relationship to JavaScript:**  Indirectly, it's crucial for V8's ability to execute JavaScript. V8 compiles JavaScript to machine code (often including S390 on relevant platforms), and the disassembler is a tool for V8 developers to understand and debug this process.
    * **JavaScript Example:**  Provide a very simple JavaScript example that *could* lead to the generation of some of the tested S390 instructions (even if the exact mapping is complex). Focus on concepts like arithmetic, memory access, and function calls.
    * **Code Logic Reasoning:**  Choose a simple test case (e.g., `ar(r3, r10)`) and trace the execution flow through the macros and `DisassembleAndCompare`. Explain how the input (the instruction encoding) leads to the expected output (the disassembly string).
    * **Common Programming Errors:** Think about errors related to assembly or low-level code, like incorrect instruction encoding, register usage, or memory addressing. Illustrate these with pseudo-assembly examples.

8. **Refine and Organize:** Structure the answer logically, starting with a high-level summary and then going into more detail. Use clear headings and bullet points. Make sure to address all parts of the original prompt.

By following these steps, we can systematically analyze the C++ code and provide a comprehensive answer explaining its purpose and relationship to the V8 JavaScript engine.
`v8/test/unittests/assembler/disasm-s390-unittest.cc` 是 V8 JavaScript 引擎中用于测试 **S390 架构** 反汇编器功能的单元测试文件。

以下是它的主要功能：

1. **测试 S390 指令的反汇编:** 该文件的核心目的是验证 V8 的反汇编器能够正确地将 S390 架构的机器码指令转换回可读的汇编代码形式。

2. **覆盖多种 S390 指令类型:**  通过多个测试用例 (`TEST_F`)，它覆盖了不同长度和类型的 S390 指令，例如：
    * **TwoBytes:**  测试双字节指令。
    * **FourBytes:** 测试四字节指令。
    * **SixBytes:** 测试六字节指令。

3. **生成机器码并进行反汇编比较:**  每个测试用例都会：
    * 使用 `Assembler` 对象生成特定的 S390 机器码指令。
    * 使用 `Disassembler` 对象将生成的机器码反汇编。
    * 将反汇编结果与预期的汇编字符串进行比较。

4. **使用 Google Test 框架:** 该文件使用了 Google Test 框架 (`testing/gtest/include/gtest/gtest.h`) 来组织和运行测试用例，方便进行断言和错误报告。

5. **提供清晰的测试结构:**  通过宏定义 (`SET_UP`, `COMPARE`, `VERIFY_RUN`)，定义了清晰的测试流程，使得添加新的测试用例相对容易。

**关于文件后缀名和 Torque:**

`v8/test/unittests/assembler/disasm-s390-unittest.cc` 的后缀是 `.cc`，这表明它是一个 **C++ 源代码文件**。

如果文件以 `.tq` 结尾，那么它才是 V8 Torque 源代码文件。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。

**与 JavaScript 功能的关系:**

虽然这个文件本身不是 JavaScript 代码，但它直接关系到 V8 执行 JavaScript 的能力。V8 在运行时需要将 JavaScript 代码编译成机器码才能在目标平台上执行，对于 S390 架构，就需要生成相应的 S390 指令。

这个单元测试确保了 V8 的反汇编器能够正确地理解这些生成的 S390 指令。这对于以下方面至关重要：

* **调试和性能分析:**  开发者可以使用反汇编器来查看 V8 生成的机器码，帮助理解代码执行流程和进行性能瓶颈分析。
* **代码生成正确性验证:**  确保编译器或代码生成器生成的机器码是正确的，符合 S390 架构规范。
* **工具开发:**  例如，开发调试器或性能分析工具需要能够正确地反汇编机器码。

**JavaScript 举例说明:**

虽然不能直接用 JavaScript 代码来展示这个 C++ 文件的功能，但可以举例说明一段简单的 JavaScript 代码，V8 在 S390 架构上编译后可能会生成一些被该单元测试覆盖的指令：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
```

当 V8 将这段 JavaScript 代码编译为 S390 机器码时，可能会包含类似 `ar`（加寄存器）、`lr`（加载寄存器）等指令。 `disasm-s390-unittest.cc` 中的测试用例就验证了反汇编器能否正确解析这些指令，例如：

```c++
COMPARE(ar(r3, r10), "1a3a           ar\tr3,r10");
```

这行代码测试了当 `Assembler` 生成 `ar r3, r10` 指令的机器码（`0x1a3a`）时，`Disassembler` 能否正确地将其反汇编为 `"ar\tr3,r10"`。

**代码逻辑推理：假设输入与输出**

让我们以 `COMPARE(ar(r3, r10), "1a3a           ar\tr3,r10");` 这个测试用例为例：

* **假设输入 (由 `Assembler` 生成):**  S390 的 `ar r3, r10` 指令的机器码是 `0x1a3a`。这个机器码会被写入到 `buffer` 中。
* **执行流程:**
    1. `assm.ar(r3, r10)` 会将机器码 `0x1a3a` 写入到 `buffer` 的当前位置。
    2. `DisassembleAndCompare(progcounter, "1a3a           ar\tr3,r10")` 被调用。
    3. `Disassembler::InstructionDecode` 函数会读取 `progcounter` 指向的内存（即 `0x1a3a`），并将其反汇编。
    4. 反汇编器会将 `0x1a3a` 识别为 `ar` 指令，源寄存器是 `r3`，目标寄存器是 `r10`，并生成汇编字符串 `"ar\tr3,r10"`。
    5. `strcmp` 函数比较反汇编结果 `"ar\tr3,r10"` 和预期的字符串 `"1a3a           ar\tr3,r10"`。
* **预期输出:** 如果反汇编正确，`strcmp` 返回 0，`DisassembleAndCompare` 返回 `true`，测试通过。如果反汇编错误，`strcmp` 返回非 0 值，`DisassembleAndCompare` 返回 `false`，`failure` 标志会被设置为 `true`。

**涉及用户常见的编程错误：**

这个单元测试主要针对 V8 内部的反汇编器，用户在使用 JavaScript 时一般不会直接接触到这些底层的机器码操作。然而，理解反汇编的概念可以帮助理解一些与性能相关的编程错误。

例如，一个常见的编程错误是 **在循环中进行大量的内存分配或复杂计算**。 这会导致 V8 生成大量的机器码，如果反汇编器出现错误，可能会导致调试或性能分析工具无法正确理解程序的执行情况。

另一个例子是 **过度使用 `eval()` 或 `Function()` 构造函数**。 这会导致 V8 在运行时动态生成和编译代码，可能会生成一些难以预测的机器码。如果反汇编器无法正确处理这些动态生成的代码，可能会给安全分析带来风险。

虽然用户不会直接编写 S390 汇编代码，但理解 V8 如何将 JavaScript 转换为机器码，以及如何反汇编这些代码，有助于更好地理解 JavaScript 的执行原理和性能特点。这个单元测试正是为了确保 V8 在 S390 架构上的底层代码处理是正确的。

### 提示词
```
这是目录为v8/test/unittests/assembler/disasm-s390-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/assembler/disasm-s390-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//     * Neither the name of Google Inc. nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

#include <stdlib.h>

#include "src/codegen/macro-assembler.h"
#include "src/debug/debug.h"
#include "src/diagnostics/disasm.h"
#include "src/diagnostics/disassembler.h"
#include "src/execution/frames-inl.h"
#include "src/init/v8.h"
#include "test/unittests/test-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {
namespace internal {

using DisasmS390Test = TestWithIsolate;

bool DisassembleAndCompare(uint8_t* pc, const char* compare_string) {
  disasm::NameConverter converter;
  disasm::Disassembler disasm(converter);
  base::EmbeddedVector<char, 128> disasm_buffer;

  disasm.InstructionDecode(disasm_buffer, pc);

  if (strcmp(compare_string, disasm_buffer.begin()) != 0) {
    fprintf(stderr,
            "expected: \n"
            "%s\n"
            "disassembled: \n"
            "%s\n\n",
            compare_string, disasm_buffer.begin());
    return false;
  }
  return true;
}

// Set up V8 to a state where we can at least run the assembler and
// disassembler. Declare the variables and allocate the data structures used
// in the rest of the macros.
#define SET_UP()                                                  \
  HandleScope scope(isolate());                                   \
  uint8_t* buffer = reinterpret_cast<uint8_t*>(malloc(4 * 1024)); \
  Assembler assm(AssemblerOptions{},                              \
                 ExternalAssemblerBuffer(buffer, 4 * 1024));      \
  bool failure = false;

// This macro assembles one instruction using the preallocated assembler and
// disassembles the generated instruction, comparing the output to the expected
// value. If the comparison fails an error message is printed, but the test
// continues to run until the end.
#define COMPARE(asm_, compare_string)                                        \
  {                                                                          \
    int pc_offset = assm.pc_offset();                                        \
    uint8_t* progcounter = &buffer[pc_offset];                               \
    assm.asm_;                                                               \
    if (!DisassembleAndCompare(progcounter, compare_string)) failure = true; \
  }

// Force emission of any pending literals into a pool.
#define EMIT_PENDING_LITERALS() assm.CheckConstPool(true, false)

// Verify that all invocations of the COMPARE macro passed successfully.
// Exit with a failure if at least one of the tests failed.
#define VERIFY_RUN()                            \
  if (failure) {                                \
    FATAL("S390 Disassembler tests failed.\n"); \
  }

TEST_F(DisasmS390Test, TwoBytes) {
  SET_UP();

  COMPARE(ar(r3, r10), "1a3a           ar\tr3,r10");
  COMPARE(sr(r8, ip), "1b8c           sr\tr8,ip");
  COMPARE(mr_z(r0, r6), "1c06           mr\tr0,r6");
  COMPARE(dr(r0, r5), "1d05           dr\tr0,r5");
  COMPARE(or_z(r4, r2), "1642           or\tr4,r2");
  COMPARE(nr(fp, r9), "14b9           nr\tfp,r9");
  COMPARE(xr(r10, ip), "17ac           xr\tr10,ip");
  COMPARE(lr(r2, r13), "182d           lr\tr2,r13");
  COMPARE(cr_z(r9, r3), "1993           cr\tr9,r3");
  COMPARE(clr(sp, r4), "15f4           clr\tsp,r4");
  COMPARE(bcr(eq, r8), "0788           bcr\t0x8,r8");
  COMPARE(ltr(r10, r1), "12a1           ltr\tr10,r1");
  COMPARE(alr(r6, r8), "1e68           alr\tr6,r8");
  COMPARE(slr(r3, ip), "1f3c           slr\tr3,ip");
  COMPARE(lnr(r4, r1), "1141           lnr\tr4,r1");
  COMPARE(lcr(r0, r3), "1303           lcr\tr0,r3");
  COMPARE(basr(r14, r7), "0de7           basr\tr14,r7");
  COMPARE(ldr(d4, d6), "2846           ldr\td4,d6");

  VERIFY_RUN();
}

TEST_F(DisasmS390Test, FourBytes) {
  SET_UP();

  COMPARE(aghi(r5, Operand(1)), "a75b0001       aghi\tr5,1");
  COMPARE(lghi(r6, Operand(8)), "a7690008       lghi\tr6,8");
  COMPARE(mghi(r1, Operand(2)), "a71d0002       mghi\tr1,2");
  COMPARE(cghi(r3, Operand(7)), "a73f0007       cghi\tr3,7");
  COMPARE(iihh(r10, Operand(8)), "a5a00008       iihh\tr10,8");
  COMPARE(iihl(r9, Operand(10)), "a591000a       iihl\tr9,10");
  COMPARE(iilh(r0, Operand(40)), "a5020028       iilh\tr0,40");
  COMPARE(iill(r6, Operand(19)), "a5630013       iill\tr6,19");
  COMPARE(oill(r9, Operand(9)), "a59b0009       oill\tr9,9");
  COMPARE(tmll(r4, Operand(7)), "a7410007       tmll\tr4,7");
  COMPARE(stm(r2, r5, MemOperand(r9, 44)), "9025902c       stm\tr2,r5,44(r9)");
  COMPARE(lm(r8, r0, MemOperand(sp, 88)), "9880f058       lm\tr8,r0,88(sp)");
  COMPARE(nill(r7, Operand(30)), "a577001e       nill\tr7,30");
  COMPARE(nilh(r8, Operand(4)), "a5860004       nilh\tr8,4");
  COMPARE(ah(r9, MemOperand(r5, r4, 4)), "4a954004       ah\tr9,4(r5,r4)");
  COMPARE(sh(r8, MemOperand(r1, r2, 6)), "4b812006       sh\tr8,6(r1,r2)");
  COMPARE(mh(r5, MemOperand(r9, r8, 7)), "4c598007       mh\tr5,7(r9,r8)");

  VERIFY_RUN();
}

TEST_F(DisasmS390Test, SixBytes) {
  SET_UP();

  COMPARE(llihf(ip, Operand(90000)), "c0ce00015f90   llihf\tip,90000");
  COMPARE(agsi(MemOperand(r9, 1000), Operand(70)),
          "eb4693e8007a   agsi\t1000(r9),70");
  COMPARE(clgfi(r7, Operand(80)), "c27e00000050   clgfi\tr7,80");
  COMPARE(cgfi(r8, Operand(10)), "c28c0000000a   cgfi\tr8,10");
  COMPARE(xihf(fp, Operand(8)), "c0b600000008   xihf\tfp,8");
  COMPARE(sllg(r0, r1, r2), "eb012000000d   sllg\tr0,r1,0(r2)");
  COMPARE(sllg(r0, r1, Operand(10)), "eb01000a000d   sllg\tr0,r1,10(r0)");
  COMPARE(srlg(r1, r3, Operand(10)), "eb13000a000c   srlg\tr1,r3,10(r0)");
  COMPARE(srlg(r1, r3, r10), "eb13a000000c   srlg\tr1,r3,0(r10)");
  COMPARE(slag(r1, r3, Operand(2)), "eb130002000b   slag\tr1,r3,2(r0)");
  COMPARE(slag(r1, r3, r2), "eb132000000b   slag\tr1,r3,0(r2)");
  COMPARE(srag(r1, r3, r2), "eb132000000a   srag\tr1,r3,0(r2)");
  COMPARE(srag(r1, r3, Operand(2)), "eb130002000a   srag\tr1,r3,2(r0)");
  COMPARE(risbg(r1, r2, Operand(3), Operand(5), Operand(2)),
          "ec1203050255   risbg\tr1,r2,3,5,2");
  COMPARE(risbgn(r1, r2, Operand(3), Operand(5), Operand(2)),
          "ec1203050259   risbgn\tr1,r2,3,5,2");
  COMPARE(stmg(r3, r4, MemOperand(sp, 10)),
          "eb34f00a0024   stmg\tr3,r4,10(sp)");
  COMPARE(ltg(r1, MemOperand(r4, sp, 10)), "e314f00a0002   ltg\tr1,10(r4,sp)");
  COMPARE(lgh(r8, MemOperand(r1, 8888)), "e38012b80215   lgh\tr8,8888(r1)");
  COMPARE(ag(r4, MemOperand(r9, r4, 2046)),
          "e34947fe0008   ag\tr4,2046(r9,r4)");
  COMPARE(agf(r1, MemOperand(r3, sp, 9)), "e313f0090018   agf\tr1,9(r3,sp)");
  COMPARE(sg(r9, MemOperand(r5, 15)), "e390500f0009   sg\tr9,15(r5)");
  COMPARE(ng(r7, MemOperand(r5, r6, 1000)),
          "e37563e80080   ng\tr7,1000(r5,r6)");
  COMPARE(og(r2, MemOperand(r8, r0, 1000)),
          "e32803e80081   og\tr2,1000(r8,r0)");
  COMPARE(xg(r9, MemOperand(r3, 8888)), "e39032b80282   xg\tr9,8888(r3)");
  COMPARE(ng(r0, MemOperand(r9, r3, 900)), "e30933840080   ng\tr0,900(r9,r3)");
  COMPARE(og(r3, MemOperand(r8, r2, 8888)),
          "e33822b80281   og\tr3,8888(r8,r2)");
  COMPARE(xg(r9, MemOperand(r3, 15)), "e390300f0082   xg\tr9,15(r3)");
  COMPARE(cg(r0, MemOperand(r5, r4, 4)), "e30540040020   cg\tr0,4(r5,r4)");
  COMPARE(lg(r1, MemOperand(r7, r8, 90)), "e317805a0004   lg\tr1,90(r7,r8)");
  COMPARE(lgf(r1, MemOperand(sp, 15)), "e310f00f0014   lgf\tr1,15(sp)");
  COMPARE(llgf(r0, MemOperand(r3, r4, 8)), "e30340080016   llgf\tr0,8(r3,r4)");
  COMPARE(alg(r8, MemOperand(r4, 11)), "e380400b000a   alg\tr8,11(r4)");
  COMPARE(slg(r1, MemOperand(r5, r6, 11)), "e315600b000b   slg\tr1,11(r5,r6)");
  COMPARE(sgf(r0, MemOperand(r4, r5, 8888)),
          "e30452b80219   sgf\tr0,8888(r4,r5)");
  COMPARE(llgh(r4, MemOperand(r1, 8000)), "e3401f400191   llgh\tr4,8000(r1)");
  COMPARE(llgc(r0, MemOperand(r4, r5, 30)),
          "e304501e0090   llgc\tr0,30(r4,r5)");
  COMPARE(lgb(r9, MemOperand(r8, r7, 10)), "e398700a0077   lgb\tr9,10(r8,r7)");
  COMPARE(stg(r0, MemOperand(r9, 10)), "e300900a0024   stg\tr0,10(r9)");
  COMPARE(mvghi(MemOperand(r7, 25), Operand(100)),
          "e54870190064   mvghi\t25(r7),100");
  COMPARE(algfi(r1, Operand(34250)), "c21a000085ca   algfi\tr1,34250");
  COMPARE(slgfi(r1, Operand(87654321)), "c21405397fb1   slgfi\tr1,87654321");
  COMPARE(nihf(r2, Operand(8888)), "c02a000022b8   nihf\tr2,8888");
  COMPARE(oihf(r6, Operand(9000)), "c06c00002328   oihf\tr6,9000");
  COMPARE(msgfi(r6, Operand(90000)), "c26000015f90   msgfi\tr6,90000");
  COMPARE(iihf(r6, Operand(9)), "c06800000009   iihf\tr6,9");
  COMPARE(srlk(r1, r3, r2), "eb13200000de   srlk\tr1,r3,0(r2)");
  COMPARE(srlk(r1, r3, Operand(2)), "eb13000200de   srlk\tr1,r3,2(r0)");
  COMPARE(lmy(r9, r10, MemOperand(r8, 100)),
          "eb9a80640098   lmy\tr9,r10,100(r8)");
  COMPARE(lmg(r7, r8, MemOperand(r9, 100)),
          "eb7890640004   lmg\tr7,r8,100(r9)");
  COMPARE(lay(fp, MemOperand(sp, 8000)), "e3b0ff400171   lay\tfp,8000(sp)");
  COMPARE(cliy(MemOperand(sp, 80), Operand(80)),
          "eb50f0500055   cliy\t80(sp),80");
  COMPARE(tmy(MemOperand(r0, 20), Operand(10)),
          "eb0a00140051   tmy\t20(r0),10");
  COMPARE(clg(r9, MemOperand(r6, r7, 19)), "e39670130021   clg\tr9,19(r6,r7)");
  COMPARE(bctg(r8, MemOperand(sp, 10)), "e380f00a0046   bctg\tr8,10(sp)");
  COMPARE(icy(r2, MemOperand(r3, 2)), "e32030020073   icy\tr2,2(r3)");
  COMPARE(mvc(MemOperand(r9, 9), MemOperand(r3, 15), Operand(10)),
          "d20a9009300f   mvc\t9(10,r9),15(r3)");
  COMPARE(nilf(r0, Operand(8000)), "c00b00001f40   nilf\tr0,8000");
  COMPARE(oilf(r9, Operand(1000)), "c09d000003e8   oilf\tr9,1000");

  VERIFY_RUN();
}

#undef SET_UP
#undef COMPARE
#undef EMIT_PENDING_LITERALS
#undef VERIFY_RUN

}  // namespace internal
}  // namespace v8
```