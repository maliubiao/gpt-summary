Response:
Let's break down the thought process for analyzing this V8 unit test file.

1. **Initial Understanding of the File's Purpose:**

   The filename `disasm-arm64-unittest.cc` immediately suggests that this file contains unit tests related to the ARM64 disassembler within the V8 JavaScript engine. The "unittest" part is a strong indicator that the tests aim to verify the correctness of individual components, specifically the disassembler.

2. **Scanning for Key Components and Definitions:**

   The next step is to quickly scan the code for important elements:

   * **Includes:**  The `#include` directives are crucial. They tell us what other parts of V8 this test relies on. We see:
      * `src/diagnostics/arm64/disasm-arm64.h`:  This is the header file for the ARM64 disassembler itself.
      * `src/codegen/arm64/assembler-arm64.h`: This points to the ARM64 assembler, used to generate the machine code that the disassembler will process.
      * `src/codegen/arm64/decoder-arm64-inl.h`:  This suggests the presence of a decoder, which likely converts raw bytes into an internal representation of the instructions. The `-inl.h` indicates inline functions, implying performance sensitivity.
      * `src/codegen/arm64/utils-arm64.h`:  Utility functions for ARM64.
      * `src/codegen/macro-assembler-inl.h`:  A higher-level assembler that simplifies code generation.
      * `src/execution/frames-inl.h`:  Relates to the execution stack and frame management, possibly used for testing disassembling in realistic scenarios.
      * `src/init/v8.h`:  The core V8 initialization.
      * `test/unittests/test-utils.h`:  Standard V8 testing utilities.
      * `testing/gtest/include/gtest/gtest.h`:  The Google Test framework used for writing the tests.

   * **Namespaces:** The `namespace v8 { namespace internal {` indicates this code is part of V8's internal implementation.

   * **Test Fixture:** `using DisasmArm64Test = TestWithIsolate;` sets up a test fixture, providing a V8 isolate (an isolated instance of the V8 engine) for each test.

   * **Macros:** The `#define` macros are central to how the tests are written:
      * `EXP_SIZE`, `INSTR_SIZE`: Define buffer sizes for expected output and instructions.
      * `SET_UP_MASM`, `SET_UP_ASM`: These macros encapsulate the common setup steps for each test, creating assemblers, decoders, and disassemblers. The "MASM" likely stands for "Macro Assembler."
      * `COMPARE`, `COMPARE_PREFIX`: These are the core assertion macros. They assemble code, disassemble it, and compare the generated disassembly with an expected string. `COMPARE_PREFIX` allows partial matching.
      * `CLEANUP`:  Handles memory cleanup after each test.

   * **`TEST_F` Blocks:** These are the individual unit tests. They follow the Google Test framework's structure. Each `TEST_F` focuses on a specific instruction or a small group of instructions.

3. **Analyzing the Test Structure and Logic:**

   The `COMPARE` macro is the heart of the testing logic. Let's break down its steps:

   1. `assm->Reset();`: Clears the assembler's buffer.
   2. `assm->ASM;`:  Executes the assembler instructions provided within the `ASM` part of the macro call. This generates the machine code.
   3. `assm->GetCode(isolate(), &desc);`:  Finalizes the code generation and gets a `CodeDesc` (code descriptor) which contains information about the generated code.
   4. `decoder->Decode(reinterpret_cast<Instruction*>(buf));`:  The core disassembling step. The generated machine code (in `buf`) is passed to the decoder, which in turn uses the `DisassemblingDecoder` to generate the textual representation.
   5. `encoding = *reinterpret_cast<uint32_t*>(buf);`:  Extracts the raw instruction encoding for debugging purposes.
   6. `if (strcmp(disasm->GetOutput(), EXP) != 0)`:  Compares the disassembled output (`disasm->GetOutput()`) with the expected output (`EXP`).
   7. `printf(...)` and `abort()`: If the comparison fails, prints an error message including the encoding, expected disassembly, and the actual disassembly, and then terminates the program. This is a typical way to signal a test failure in lower-level code.

4. **Identifying the Tested Functionality:**

   By looking at the names of the `TEST_F` blocks and the assembler instructions used within the `COMPARE` macros, we can identify the specific ARM64 instructions being tested. Examples: `bootstrap`, `mov_mvn`, `move_immediate`, `add_immediate`, `sub_immediate`, `add_shifted`, etc. Each test focuses on verifying the disassembler's output for a particular instruction or a variation of an instruction.

5. **Relating to JavaScript (If Applicable):**

   The file name and the internal nature of the code suggest a direct relationship to how V8 compiles and executes JavaScript code on ARM64 architectures. While the test itself doesn't *directly* execute JavaScript, the instructions being tested are the low-level building blocks that V8's compiler (TurboFan, Crankshaft) will generate when optimizing JavaScript code for ARM64. For instance, when performing addition in JavaScript, the compiler might emit ARM64 `add` instructions.

6. **Considering Potential Programming Errors:**

   The tests implicitly guard against errors in the disassembler's logic. If the disassembler incorrectly interprets an instruction's encoding, the `COMPARE` macro will detect the mismatch and fail the test. Common disassembler errors might involve:

   * **Incorrect opcode decoding:**  Mapping the raw bits to the wrong instruction type.
   * **Operand parsing errors:** Misinterpreting register numbers, immediate values, or addressing modes.
   * **Formatting issues:**  Generating the disassembled string with incorrect syntax or spacing.

7. **Addressing Specific Questions from the Prompt:**

   * **`.tq` extension:** The code is `.cc`, so it's C++, not Torque.
   * **JavaScript relationship:**  Explained above.
   * **Code logic reasoning (input/output):** The `COMPARE` macro provides this. The "input" is the sequence of assembler instructions (which translates to machine code), and the "output" is the expected disassembled string.
   * **User programming errors:**  This unit test targets errors *within the V8 engine's disassembler*, not typical user programming errors in JavaScript. However, understanding how instructions are encoded and disassembled is relevant when debugging low-level performance issues or compiler bugs.

8. **Summarization (Instruction 8):**

   The final step is to synthesize the findings into a concise summary, addressing the key aspects of the file's functionality. This involves mentioning its purpose (testing the ARM64 disassembler), the testing methodology (assembling code and comparing disassembly), the scope of testing (various ARM64 instructions), and the language (C++).
这是一个V8 JavaScript引擎的单元测试文件，专门用于测试 **ARM64架构的反汇编器 (disassembler)** 的功能。

**功能归纳:**

1. **测试 ARM64 指令的反汇编:**  该文件包含了大量的测试用例，每个用例都生成一段特定的ARM64机器码指令，然后使用V8的反汇编器将其转换回汇编代码，并与预期的汇编代码字符串进行比较。这确保了反汇编器能够正确地将机器码翻译成可读的汇编指令。

2. **覆盖多种 ARM64 指令:**  从测试用例的名称和内容可以看出，该文件覆盖了多种类型的ARM64指令，包括：
    * **数据处理指令:**  `mov`, `mvn`, `add`, `sub`, `adc`, `sbc`, `mul`, `div`, `neg`, `mneg`, `smull`, `smulh`, `madd`, `msub`, `smaddl`, `smsubl`, `rbit`, `rev16`, `rev32`, `rev`, `clz`, `cls`, `asr`, `lsr`, `lsl`, `sbfiz`, `sbfx`, `bfi`, `bfxil`, `ubfiz`, `ubfx`, `extr` 等。
    * **逻辑指令:** `and`, `orr`, `eor`, `bic`, `orn`, `eon`, `tst`, `ands`, `bics` 等。
    * **立即数操作:** 测试了使用立即数的指令的反汇编。
    * **移位和扩展操作:** 测试了带有移位和扩展操作的指令的反汇编。
    * **栈操作:**  间接测试了一些栈相关的指令，例如 `stp` 和 `ldp`。

3. **使用 Google Test 框架:**  该文件使用了 Google Test 框架来编写和组织测试用例，使得测试结构清晰，易于管理和运行。

4. **宏定义简化测试编写:**  定义了多个宏 (`EXP_SIZE`, `INSTR_SIZE`, `SET_UP_MASM`, `SET_UP_ASM`, `COMPARE`, `COMPARE_PREFIX`, `CLEANUP`) 来简化测试用例的编写，避免了重复的代码。

**关于问题的其他方面:**

* **.tq 结尾:**  `v8/test/unittests/assembler/disasm-arm64-unittest.cc` 的文件扩展名是 `.cc`，这意味着它是一个 **C++源代码文件**，而不是 Torque 源代码文件（Torque 文件通常以 `.tq` 结尾）。

* **与 JavaScript 功能的关系:**  该文件直接测试的是 V8 引擎内部的底层组件——ARM64反汇编器。反汇编器本身不直接执行 JavaScript 代码，但它是 V8 引擎在进行以下操作时的一个重要工具：
    * **调试和性能分析:**  当需要理解 V8 生成的机器码时，反汇编器可以将二进制指令转换成人类可读的汇编代码。这对于调试编译器错误或进行性能分析非常有用。
    * **JIT (Just-In-Time) 编译:**  V8 的 JIT 编译器（如 TurboFan）将 JavaScript 代码编译成机器码，反汇编器可以用来检查生成的机器码是否符合预期。
    * **代码检查和安全性分析:**  在某些情况下，可能需要检查 V8 生成的机器码是否存在安全漏洞或其他问题。

**JavaScript 举例说明 (间接关系):**

虽然 `disasm-arm64-unittest.cc` 不直接包含 JavaScript 代码，但它测试的组件服务于 JavaScript 的执行。 例如，当你在 JavaScript 中执行一个简单的加法操作时，V8 的编译器可能会生成类似 `add` 的 ARM64 指令。这个单元测试就是用来确保 V8 的反汇编器能够正确地解析和显示这些 `add` 指令。

```javascript
// JavaScript 代码示例
function add(a, b) {
  return a + b;
}

add(5, 3);
```

当 V8 执行这段代码时，它可能会将 `a + b` 编译成类似以下的 ARM64 指令（这是一个简化的例子）：

```assembly
// 假设的 ARM64 指令
ldr x0, [sp, #offset_a]  // 将变量 a 加载到寄存器 x0
ldr x1, [sp, #offset_b]  // 将变量 b 加载到寄存器 x1
add x2, x0, x1          // 将 x0 和 x1 的值相加，结果存储在 x2 中
str x2, [sp, #offset_result] // 将结果存储回内存
```

`disasm-arm64-unittest.cc` 中的测试用例就是用来验证 V8 的反汇编器能否正确地将 `add x2, x0, x1` 这样的机器码指令转换回 `add x2, x0, x1` 这样的汇编代码。

**代码逻辑推理 (假设输入与输出):**

假设 `COMPARE(Mov(w0, Operand(0x1234)), "movz w0, #0x1234");` 这个测试用例。

* **假设输入 (机器码):**  `Mov(w0, Operand(0x1234))` 这段代码会生成一条将立即数 `0x1234` 移动到 `w0` 寄存器的 ARM64 机器码指令。这条指令的实际二进制编码取决于 ARM64 的指令格式，例如可能是 `0xb2740000`。

* **处理过程:** V8 的反汇编器会接收到这段二进制编码 `0xb2740000`。它会根据 ARM64 的指令集规范，识别出这是一个 `movz` 指令，目标寄存器是 `w0`，立即数是 `#0x1234`。

* **预期输出 (反汇编代码):**  反汇编器会将这段机器码转换成汇编代码字符串 `"movz w0, #0x1234"`。

`COMPARE` 宏会比较反汇编器生成的实际输出和预期的输出 `"movz w0, #0x1234"`，如果一致，则测试通过。

**涉及用户常见的编程错误 (间接相关):**

这个单元测试主要关注 V8 引擎内部的正确性，而不是直接针对用户的编程错误。但是，如果反汇编器出现错误，可能会影响到开发者理解 V8 生成的代码，从而在调试性能问题时产生误导。

例如，假设反汇编器错误地将一个加法指令 `add x0, x1, x2` 反汇编成减法指令 `sub x0, x1, x2`。当开发者查看反汇编代码进行性能分析时，可能会错误地认为 V8 执行的是减法操作，从而导致错误的优化方向。

**总结第 1 部分的功能:**

`v8/test/unittests/assembler/disasm-arm64-unittest.cc` 的第 1 部分主要包含了对以下 ARM64 指令进行反汇编测试的用例：

* **基本的数据移动指令:** `mov`, `mvn`
* **立即数加载指令:** `movz`, `movk`, `movn`
* **加减法指令 (立即数和寄存器操作):** `add`, `adds`, `cmn`, `sub`, `subs`, `cmp`
* **带移位的加减法指令:** `add`, `cmn`, `sub`, `cmp`, `neg`, `negs`
* **带扩展的加减法指令:** `add`, `adds`, `cmn`, `sub`, `subs`, `cmp`
* **带进位的加减法和求反指令:** `adc`, `adcs`, `sbc`, `sbcs`, `ngc`, `ngcs`
* **乘法和除法指令:** `mul`, `mneg`, `smull`, `smulh`, `madd`, `msub`, `sdiv`, `udiv`
* **带累加的乘法和减法指令 (长字):** `smaddl`, `umaddl`, `smsubl`, `umsubl`
* **单操作数数据处理指令:** `rbit`, `rev16`, `rev32`, `rev`, `clz`, `cls`
* **位域操作指令:** `sxtb`, `sxth`, `sxtw`, `uxtb`, `uxth`, `uxtw`, `asr`, `lsr`, `lsl`, `sbfiz`, `sbfx`, `bfi`, `bfxil`, `ubfiz`, `ubfx`
* **位域提取指令:** `extr`
* **逻辑运算指令 (立即数):** `and`, `tst`, `orr`, `eor`, `ands`, `bic`, `orn`, `eon`, `bics`
* **逻辑运算指令 (移位寄存器):** `and`, `bic`, `orr`, `orn`, `eor`, `eon`

总而言之，第 1 部分涵盖了 ARM64 指令集中相当一部分核心的数据处理和逻辑运算指令的反汇编测试，旨在确保 V8 引擎能够正确地将这些指令的机器码表示转换回可读的汇编代码。

### 提示词
```
这是目录为v8/test/unittests/assembler/disasm-arm64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/assembler/disasm-arm64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2013 the V8 project authors. All rights reserved.
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

#include "src/diagnostics/arm64/disasm-arm64.h"

#include <stdio.h>

#include <cstring>

#include "src/codegen/arm64/assembler-arm64.h"
#include "src/codegen/arm64/decoder-arm64-inl.h"
#include "src/codegen/arm64/utils-arm64.h"
#include "src/codegen/macro-assembler-inl.h"
#include "src/execution/frames-inl.h"
#include "src/init/v8.h"
#include "test/unittests/test-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {
namespace internal {

using DisasmArm64Test = TestWithIsolate;

#define EXP_SIZE (256)
#define INSTR_SIZE (1024)
#define SET_UP_MASM()                                                         \
  HandleScope scope(isolate());                                               \
  uint8_t* buf = static_cast<uint8_t*>(malloc(INSTR_SIZE));                   \
  uint32_t encoding = 0;                                                      \
  MacroAssembler* assm =                                                      \
      new MacroAssembler((isolate()), v8::internal::CodeObjectRequired::kYes, \
                         ExternalAssemblerBuffer(buf, INSTR_SIZE));           \
  Decoder<DispatchingDecoderVisitor>* decoder =                               \
      new Decoder<DispatchingDecoderVisitor>();                               \
  DisassemblingDecoder* disasm = new DisassemblingDecoder();                  \
  decoder->AppendVisitor(disasm)

#define SET_UP_ASM()                                                          \
  HandleScope scope(isolate());                                               \
  uint8_t* buf = static_cast<uint8_t*>(malloc(INSTR_SIZE));                   \
  uint32_t encoding = 0;                                                      \
  Assembler* assm = new Assembler(isolate()->allocator(), AssemblerOptions{}, \
                                  ExternalAssemblerBuffer(buf, INSTR_SIZE));  \
  Decoder<DispatchingDecoderVisitor>* decoder =                               \
      new Decoder<DispatchingDecoderVisitor>();                               \
  DisassemblingDecoder* disasm = new DisassemblingDecoder();                  \
  decoder->AppendVisitor(disasm)

#define COMPARE(ASM, EXP)                                                \
  assm->Reset();                                                         \
  assm->ASM;                                                             \
  {                                                                      \
    CodeDesc desc;                                                       \
    assm->GetCode(isolate(), &desc);                                     \
  }                                                                      \
  decoder->Decode(reinterpret_cast<Instruction*>(buf));                  \
  encoding = *reinterpret_cast<uint32_t*>(buf);                          \
  if (strcmp(disasm->GetOutput(), EXP) != 0) {                           \
    printf("%u : Encoding: %08" PRIx32 "\nExpected: %s\nFound:    %s\n", \
           __LINE__, encoding, EXP, disasm->GetOutput());                \
    abort();                                                             \
  }

#define COMPARE_PREFIX(ASM, EXP)                                         \
  assm->Reset();                                                         \
  assm->ASM;                                                             \
  {                                                                      \
    CodeDesc desc;                                                       \
    assm->GetCode(isolate(), &desc);                                     \
  }                                                                      \
  decoder->Decode(reinterpret_cast<Instruction*>(buf));                  \
  encoding = *reinterpret_cast<uint32_t*>(buf);                          \
  if (strncmp(disasm->GetOutput(), EXP, strlen(EXP)) != 0) {             \
    printf("%u : Encoding: %08" PRIx32 "\nExpected: %s\nFound:    %s\n", \
           __LINE__, encoding, EXP, disasm->GetOutput());                \
    abort();                                                             \
  }

#define CLEANUP() \
  delete disasm;  \
  delete decoder; \
  delete assm;    \
  free(buf)

TEST_F(DisasmArm64Test, bootstrap) {
  SET_UP_ASM();

  // Instructions generated by C compiler, disassembled by objdump, and
  // reformatted to suit our disassembly style.
  COMPARE(dci(0xa9ba7bfd), "stp fp, lr, [sp, #-96]!");
  COMPARE(dci(0x910003fd), "mov fp, sp");
  COMPARE(dci(0x9100e3a0), "add x0, fp, #0x38 (56)");
  COMPARE(dci(0xb900001f), "str wzr, [x0]");
  COMPARE(dci(0x528000e1), "movz w1, #0x7");
  COMPARE(dci(0xb9001c01), "str w1, [x0, #28]");
  COMPARE(dci(0x390043a0), "strb w0, [fp, #16]");
  COMPARE(dci(0x790027a0), "strh w0, [fp, #18]");
  COMPARE(dci(0xb9400400), "ldr w0, [x0, #4]");
  COMPARE(dci(0x0b000021), "add w1, w1, w0");
  COMPARE(dci(0x531b6800), "lsl w0, w0, #5");
  COMPARE(dci(0x521e0400), "eor w0, w0, #0xc");
  COMPARE(dci(0x72af0f00), "movk w0, #0x7878, lsl #16");
  COMPARE(dci(0xd360fc00), "lsr x0, x0, #32");
  COMPARE(dci(0x13037c01), "asr w1, w0, #3");
  COMPARE(dci(0x4b000021), "sub w1, w1, w0");
  COMPARE(dci(0x2a0103e0), "mov w0, w1");
  COMPARE(dci(0x93407c00), "sxtw x0, w0");
  COMPARE(dci(0x2a000020), "orr w0, w1, w0");
  COMPARE(dci(0xa8c67bfd), "ldp fp, lr, [sp], #96");

  CLEANUP();
}

TEST_F(DisasmArm64Test, mov_mvn) {
  SET_UP_MASM();

  COMPARE(Mov(w0, Operand(0x1234)), "movz w0, #0x1234");
  COMPARE(Mov(x1, Operand(0x1234)), "movz x1, #0x1234");
  COMPARE(Mov(w2, Operand(w3)), "mov w2, w3");
  COMPARE(Mov(x4, Operand(x5)), "mov x4, x5");
  COMPARE(Mov(w6, Operand(w7, LSL, 5)), "lsl w6, w7, #5");
  COMPARE(Mov(x8, Operand(x9, ASR, 42)), "asr x8, x9, #42");
  COMPARE(Mov(w10, Operand(w11, UXTB)), "uxtb w10, w11");
  COMPARE(Mov(x12, Operand(x13, UXTB, 1)), "ubfiz x12, x13, #1, #8");
  COMPARE(Mov(w14, Operand(w15, SXTH, 2)), "sbfiz w14, w15, #2, #16");
  COMPARE(Mov(x16, Operand(x20, SXTW, 3)), "sbfiz x16, x20, #3, #32");

  COMPARE(Mov(x0, sp), "mov x0, sp");
  COMPARE(Mov(w0, wsp), "mov w0, wsp");
  COMPARE(Mov(x0, xzr), "mov x0, xzr");
  COMPARE(Mov(w0, wzr), "mov w0, wzr");
  COMPARE(mov(x0, sp), "mov x0, sp");
  COMPARE(mov(w0, wsp), "mov w0, wsp");
  COMPARE(mov(x0, xzr), "mov x0, xzr");
  COMPARE(mov(w0, wzr), "mov w0, wzr");

  COMPARE(Mvn(w0, Operand(0x1)), "movn w0, #0x1");
  COMPARE(Mvn(x1, Operand(0xfff)), "movn x1, #0xfff");
  COMPARE(Mvn(w2, Operand(w3)), "mvn w2, w3");
  COMPARE(Mvn(x4, Operand(x5)), "mvn x4, x5");
  COMPARE(Mvn(w6, Operand(w7, LSL, 12)), "mvn w6, w7, lsl #12");
  COMPARE(Mvn(x8, Operand(x9, ASR, 63)), "mvn x8, x9, asr #63");

  CLEANUP();
}

TEST_F(DisasmArm64Test, move_immediate) {
  SET_UP_ASM();

  COMPARE(movz(w0, 0x1234), "movz w0, #0x1234");
  COMPARE(movz(x1, 0xabcd0000), "movz x1, #0xabcd0000");
  COMPARE(movz(x2, 0x555500000000), "movz x2, #0x555500000000");
  COMPARE(movz(x3, 0xaaaa000000000000), "movz x3, #0xaaaa000000000000");
  COMPARE(movz(x4, 0xabcd, 16), "movz x4, #0xabcd0000");
  COMPARE(movz(x5, 0x5555, 32), "movz x5, #0x555500000000");
  COMPARE(movz(x6, 0xaaaa, 48), "movz x6, #0xaaaa000000000000");

  COMPARE(movk(w7, 0x1234), "movk w7, #0x1234");
  COMPARE(movk(x8, 0xabcd0000), "movk x8, #0xabcd, lsl #16");
  COMPARE(movk(x9, 0x555500000000), "movk x9, #0x5555, lsl #32");
  COMPARE(movk(x10, 0xaaaa000000000000), "movk x10, #0xaaaa, lsl #48");
  COMPARE(movk(w11, 0xabcd, 16), "movk w11, #0xabcd, lsl #16");
  COMPARE(movk(x12, 0x5555, 32), "movk x12, #0x5555, lsl #32");
  COMPARE(movk(x13, 0xaaaa, 48), "movk x13, #0xaaaa, lsl #48");

  COMPARE(movn(w14, 0x1234), "movn w14, #0x1234");
  COMPARE(movn(x15, 0xabcd0000), "movn x15, #0xabcd0000");
  COMPARE(movn(x16, 0x555500000000), "movn x16, #0x555500000000");
  COMPARE(movn(x17, 0xaaaa000000000000), "movn x17, #0xaaaa000000000000");
  COMPARE(movn(w18, 0xabcd, 16), "movn w18, #0xabcd0000");
  COMPARE(movn(x19, 0x5555, 32), "movn x19, #0x555500000000");
  COMPARE(movn(x20, 0xaaaa, 48), "movn x20, #0xaaaa000000000000");

  COMPARE(movk(w21, 0), "movk w21, #0x0");
  COMPARE(movk(x22, 0, 0), "movk x22, #0x0");
  COMPARE(movk(w23, 0, 16), "movk w23, #0x0, lsl #16");
  COMPARE(movk(x24, 0, 32), "movk x24, #0x0, lsl #32");
  COMPARE(movk(x25, 0, 48), "movk x25, #0x0, lsl #48");

  CLEANUP();
}

TEST_F(DisasmArm64Test, move_immediate_2) {
  SET_UP_MASM();

  // Move instructions expected for certain immediates. This is really a macro
  // assembler test, to ensure it generates immediates efficiently.
  COMPARE(Mov(w0, 0), "movz w0, #0x0");
  COMPARE(Mov(w0, 0x0000ffff), "movz w0, #0xffff");
  COMPARE(Mov(w0, 0x00010000), "movz w0, #0x10000");
  COMPARE(Mov(w0, 0xffff0000), "movz w0, #0xffff0000");
  COMPARE(Mov(w0, 0x0001ffff), "movn w0, #0xfffe0000");
  COMPARE(Mov(w0, 0xffff8000), "movn w0, #0x7fff");
  COMPARE(Mov(w0, 0xfffffffe), "movn w0, #0x1");
  COMPARE(Mov(w0, 0xffffffff), "movn w0, #0x0");
  COMPARE(Mov(w0, 0x00ffff00), "mov w0, #0xffff00");
  COMPARE(Mov(w0, 0xfffe7fff), "mov w0, #0xfffe7fff");
  COMPARE(Mov(w0, 0xfffeffff), "movn w0, #0x10000");
  COMPARE(Mov(w0, 0xffff7fff), "movn w0, #0x8000");

  COMPARE(Mov(x0, 0), "movz x0, #0x0");
  COMPARE(Mov(x0, 0x0000ffff), "movz x0, #0xffff");
  COMPARE(Mov(x0, 0x00010000), "movz x0, #0x10000");
  COMPARE(Mov(x0, 0xffff0000), "movz x0, #0xffff0000");
  COMPARE(Mov(x0, 0x0001ffff), "mov x0, #0x1ffff");
  COMPARE(Mov(x0, 0xffff8000), "mov x0, #0xffff8000");
  COMPARE(Mov(x0, 0xfffffffe), "mov x0, #0xfffffffe");
  COMPARE(Mov(x0, 0xffffffff), "mov x0, #0xffffffff");
  COMPARE(Mov(x0, 0x00ffff00), "mov x0, #0xffff00");
  COMPARE(Mov(x0, 0xffff000000000000), "movz x0, #0xffff000000000000");
  COMPARE(Mov(x0, 0x0000ffff00000000), "movz x0, #0xffff00000000");
  COMPARE(Mov(x0, 0x00000000ffff0000), "movz x0, #0xffff0000");
  COMPARE(Mov(x0, 0xffffffffffff0000), "movn x0, #0xffff");
  COMPARE(Mov(x0, 0xffffffff0000ffff), "movn x0, #0xffff0000");
  COMPARE(Mov(x0, 0xffff0000ffffffff), "movn x0, #0xffff00000000");
  COMPARE(Mov(x0, 0x0000ffffffffffff), "movn x0, #0xffff000000000000");
  COMPARE(Mov(x0, 0xfffe7fffffffffff), "mov x0, #0xfffe7fffffffffff");
  COMPARE(Mov(x0, 0xfffeffffffffffff), "movn x0, #0x1000000000000");
  COMPARE(Mov(x0, 0xffff7fffffffffff), "movn x0, #0x800000000000");
  COMPARE(Mov(x0, 0xfffffffe7fffffff), "mov x0, #0xfffffffe7fffffff");
  COMPARE(Mov(x0, 0xfffffffeffffffff), "movn x0, #0x100000000");
  COMPARE(Mov(x0, 0xffffffff7fffffff), "movn x0, #0x80000000");
  COMPARE(Mov(x0, 0xfffffffffffe7fff), "mov x0, #0xfffffffffffe7fff");
  COMPARE(Mov(x0, 0xfffffffffffeffff), "movn x0, #0x10000");
  COMPARE(Mov(x0, 0xffffffffffff7fff), "movn x0, #0x8000");
  COMPARE(Mov(x0, 0xffffffffffffffff), "movn x0, #0x0");

  COMPARE(Movk(w0, 0x1234, 0), "movk w0, #0x1234");
  COMPARE(Movk(x1, 0x2345, 0), "movk x1, #0x2345");
  COMPARE(Movk(w2, 0x3456, 16), "movk w2, #0x3456, lsl #16");
  COMPARE(Movk(x3, 0x4567, 16), "movk x3, #0x4567, lsl #16");
  COMPARE(Movk(x4, 0x5678, 32), "movk x4, #0x5678, lsl #32");
  COMPARE(Movk(x5, 0x6789, 48), "movk x5, #0x6789, lsl #48");

  CLEANUP();
}

TEST_F(DisasmArm64Test, add_immediate) {
  SET_UP_ASM();

  COMPARE(add(w0, w1, Operand(0xff)), "add w0, w1, #0xff (255)");
  COMPARE(add(x2, x3, Operand(0x3ff)), "add x2, x3, #0x3ff (1023)");
  COMPARE(add(w4, w5, Operand(0xfff)), "add w4, w5, #0xfff (4095)");
  COMPARE(add(x6, x7, Operand(0x1000)), "add x6, x7, #0x1000 (4096)");
  COMPARE(add(w8, w9, Operand(0xff000)), "add w8, w9, #0xff000 (1044480)");
  COMPARE(add(x10, x11, Operand(0x3ff000)),
          "add x10, x11, #0x3ff000 (4190208)");
  COMPARE(add(w12, w13, Operand(0xfff000)),
          "add w12, w13, #0xfff000 (16773120)");
  COMPARE(adds(w14, w15, Operand(0xff)), "adds w14, w15, #0xff (255)");
  COMPARE(adds(x16, x17, Operand(0xaa000)), "adds x16, x17, #0xaa000 (696320)");
  COMPARE(cmn(w18, Operand(0xff)), "cmn w18, #0xff (255)");
  COMPARE(cmn(x19, Operand(0xff000)), "cmn x19, #0xff000 (1044480)");
  COMPARE(add(w0, wsp, Operand(0)), "mov w0, wsp");
  COMPARE(add(sp, x0, Operand(0)), "mov sp, x0");

  COMPARE(add(w1, wsp, Operand(8)), "add w1, wsp, #0x8 (8)");
  COMPARE(add(x2, sp, Operand(16)), "add x2, sp, #0x10 (16)");
  COMPARE(add(wsp, wsp, Operand(42)), "add wsp, wsp, #0x2a (42)");
  COMPARE(cmn(sp, Operand(24)), "cmn sp, #0x18 (24)");
  COMPARE(adds(wzr, wsp, Operand(9)), "cmn wsp, #0x9 (9)");

  CLEANUP();
}

TEST_F(DisasmArm64Test, sub_immediate) {
  SET_UP_ASM();

  COMPARE(sub(w0, w1, Operand(0xff)), "sub w0, w1, #0xff (255)");
  COMPARE(sub(x2, x3, Operand(0x3ff)), "sub x2, x3, #0x3ff (1023)");
  COMPARE(sub(w4, w5, Operand(0xfff)), "sub w4, w5, #0xfff (4095)");
  COMPARE(sub(x6, x7, Operand(0x1000)), "sub x6, x7, #0x1000 (4096)");
  COMPARE(sub(w8, w9, Operand(0xff000)), "sub w8, w9, #0xff000 (1044480)");
  COMPARE(sub(x10, x11, Operand(0x3ff000)),
          "sub x10, x11, #0x3ff000 (4190208)");
  COMPARE(sub(w12, w13, Operand(0xfff000)),
          "sub w12, w13, #0xfff000 (16773120)");
  COMPARE(subs(w14, w15, Operand(0xff)), "subs w14, w15, #0xff (255)");
  COMPARE(subs(x16, x17, Operand(0xaa000)), "subs x16, x17, #0xaa000 (696320)");
  COMPARE(cmp(w18, Operand(0xff)), "cmp w18, #0xff (255)");
  COMPARE(cmp(x19, Operand(0xff000)), "cmp x19, #0xff000 (1044480)");

  COMPARE(add(w1, wsp, Operand(8)), "add w1, wsp, #0x8 (8)");
  COMPARE(add(x2, sp, Operand(16)), "add x2, sp, #0x10 (16)");
  COMPARE(add(wsp, wsp, Operand(42)), "add wsp, wsp, #0x2a (42)");
  COMPARE(cmn(sp, Operand(24)), "cmn sp, #0x18 (24)");
  COMPARE(adds(wzr, wsp, Operand(9)), "cmn wsp, #0x9 (9)");

  CLEANUP();
}

TEST_F(DisasmArm64Test, add_shifted) {
  SET_UP_ASM();

  COMPARE(add(w0, w1, Operand(w2)), "add w0, w1, w2");
  COMPARE(add(x3, x4, Operand(x5)), "add x3, x4, x5");
  COMPARE(add(w6, w7, Operand(w8, LSL, 1)), "add w6, w7, w8, lsl #1");
  COMPARE(add(x9, x10, Operand(x11, LSL, 2)), "add x9, x10, x11, lsl #2");
  COMPARE(add(w12, w13, Operand(w14, LSR, 3)), "add w12, w13, w14, lsr #3");
  COMPARE(add(x15, x16, Operand(x17, LSR, 4)), "add x15, x16, x17, lsr #4");
  COMPARE(add(w18, w19, Operand(w20, ASR, 5)), "add w18, w19, w20, asr #5");
  COMPARE(add(x21, x22, Operand(x23, ASR, 6)), "add x21, x22, x23, asr #6");
  COMPARE(cmn(w24, Operand(w25)), "cmn w24, w25");
  COMPARE(cmn(x26, Operand(cp, LSL, 63)), "cmn x26, cp, lsl #63");

  COMPARE(add(x0, sp, Operand(x1)), "add x0, sp, x1");
  COMPARE(add(w2, wsp, Operand(w3)), "add w2, wsp, w3");
  COMPARE(add(x4, sp, Operand(x5, LSL, 1)), "add x4, sp, x5, lsl #1");
  COMPARE(add(x4, xzr, Operand(x5, LSL, 1)), "add x4, xzr, x5, lsl #1");
  COMPARE(add(w6, wsp, Operand(w7, LSL, 3)), "add w6, wsp, w7, lsl #3");
  COMPARE(adds(xzr, sp, Operand(x8, LSL, 4)), "cmn sp, x8, lsl #4");
  COMPARE(adds(xzr, xzr, Operand(x8, LSL, 5)), "cmn xzr, x8, lsl #5");

  CLEANUP();
}

TEST_F(DisasmArm64Test, sub_shifted) {
  SET_UP_ASM();

  COMPARE(sub(w0, w1, Operand(w2)), "sub w0, w1, w2");
  COMPARE(sub(x3, x4, Operand(x5)), "sub x3, x4, x5");
  COMPARE(sub(w6, w7, Operand(w8, LSL, 1)), "sub w6, w7, w8, lsl #1");
  COMPARE(sub(x9, x10, Operand(x11, LSL, 2)), "sub x9, x10, x11, lsl #2");
  COMPARE(sub(w12, w13, Operand(w14, LSR, 3)), "sub w12, w13, w14, lsr #3");
  COMPARE(sub(x15, x16, Operand(x17, LSR, 4)), "sub x15, x16, x17, lsr #4");
  COMPARE(sub(w18, w19, Operand(w20, ASR, 5)), "sub w18, w19, w20, asr #5");
  COMPARE(sub(x21, x22, Operand(x23, ASR, 6)), "sub x21, x22, x23, asr #6");
  COMPARE(cmp(w24, Operand(w25)), "cmp w24, w25");
  COMPARE(cmp(x26, Operand(cp, LSL, 63)), "cmp x26, cp, lsl #63");
  COMPARE(neg(w28, Operand(w29)), "neg w28, w29");
  COMPARE(neg(lr, Operand(x0, LSR, 62)), "neg lr, x0, lsr #62");
  COMPARE(negs(w1, Operand(w2)), "negs w1, w2");
  COMPARE(negs(x3, Operand(x4, ASR, 61)), "negs x3, x4, asr #61");

  COMPARE(sub(x0, sp, Operand(x1)), "sub x0, sp, x1");
  COMPARE(sub(w2, wsp, Operand(w3)), "sub w2, wsp, w3");
  COMPARE(sub(x4, sp, Operand(x5, LSL, 1)), "sub x4, sp, x5, lsl #1");
  COMPARE(sub(x4, xzr, Operand(x5, LSL, 1)), "neg x4, x5, lsl #1");
  COMPARE(sub(w6, wsp, Operand(w7, LSL, 3)), "sub w6, wsp, w7, lsl #3");
  COMPARE(subs(xzr, sp, Operand(x8, LSL, 4)), "cmp sp, x8, lsl #4");
  COMPARE(subs(xzr, xzr, Operand(x8, LSL, 5)), "cmp xzr, x8, lsl #5");

  CLEANUP();
}

TEST_F(DisasmArm64Test, add_extended) {
  SET_UP_ASM();

  COMPARE(add(w0, w1, Operand(w2, UXTB)), "add w0, w1, w2, uxtb");
  COMPARE(adds(x3, x4, Operand(w5, UXTB, 1)), "adds x3, x4, w5, uxtb #1");
  COMPARE(add(w6, w7, Operand(w8, UXTH, 2)), "add w6, w7, w8, uxth #2");
  COMPARE(adds(x9, x10, Operand(x11, UXTW, 3)), "adds x9, x10, w11, uxtw #3");
  COMPARE(add(x12, x13, Operand(x14, UXTX, 4)), "add x12, x13, x14, uxtx #4");
  COMPARE(adds(w15, w16, Operand(w17, SXTB, 4)), "adds w15, w16, w17, sxtb #4");
  COMPARE(add(x18, x19, Operand(x20, SXTB, 3)), "add x18, x19, w20, sxtb #3");
  COMPARE(adds(w21, w22, Operand(w23, SXTH, 2)), "adds w21, w22, w23, sxth #2");
  COMPARE(add(x24, x25, Operand(x26, SXTW, 1)), "add x24, x25, w26, sxtw #1");
  COMPARE(adds(cp, x28, Operand(fp, SXTX)), "adds cp, x28, fp, sxtx");
  COMPARE(cmn(w0, Operand(w1, UXTB, 2)), "cmn w0, w1, uxtb #2");
  COMPARE(cmn(x2, Operand(x3, SXTH, 4)), "cmn x2, w3, sxth #4");

  COMPARE(add(w0, wsp, Operand(w1, UXTB)), "add w0, wsp, w1, uxtb");
  COMPARE(add(x2, sp, Operand(x3, UXTH, 1)), "add x2, sp, w3, uxth #1");
  COMPARE(add(wsp, wsp, Operand(w4, UXTW, 2)), "add wsp, wsp, w4, lsl #2");
  COMPARE(cmn(sp, Operand(xzr, UXTX, 3)), "cmn sp, xzr, lsl #3");
  COMPARE(cmn(sp, Operand(xzr, LSL, 4)), "cmn sp, xzr, lsl #4");

  CLEANUP();
}

TEST_F(DisasmArm64Test, sub_extended) {
  SET_UP_ASM();

  COMPARE(sub(w0, w1, Operand(w2, UXTB)), "sub w0, w1, w2, uxtb");
  COMPARE(subs(x3, x4, Operand(w5, UXTB, 1)), "subs x3, x4, w5, uxtb #1");
  COMPARE(sub(w6, w7, Operand(w8, UXTH, 2)), "sub w6, w7, w8, uxth #2");
  COMPARE(subs(x9, x10, Operand(x11, UXTW, 3)), "subs x9, x10, w11, uxtw #3");
  COMPARE(sub(x12, x13, Operand(x14, UXTX, 4)), "sub x12, x13, x14, uxtx #4");
  COMPARE(subs(w15, w16, Operand(w17, SXTB, 4)), "subs w15, w16, w17, sxtb #4");
  COMPARE(sub(x18, x19, Operand(x20, SXTB, 3)), "sub x18, x19, w20, sxtb #3");
  COMPARE(subs(w21, w22, Operand(w23, SXTH, 2)), "subs w21, w22, w23, sxth #2");
  COMPARE(sub(x24, x25, Operand(x26, SXTW, 1)), "sub x24, x25, w26, sxtw #1");
  COMPARE(subs(cp, x28, Operand(fp, SXTX)), "subs cp, x28, fp, sxtx");
  COMPARE(cmp(w0, Operand(w1, SXTB, 1)), "cmp w0, w1, sxtb #1");
  COMPARE(cmp(x2, Operand(x3, UXTH, 3)), "cmp x2, w3, uxth #3");

  COMPARE(sub(w0, wsp, Operand(w1, UXTB)), "sub w0, wsp, w1, uxtb");
  COMPARE(sub(x2, sp, Operand(x3, UXTH, 1)), "sub x2, sp, w3, uxth #1");
  COMPARE(sub(wsp, wsp, Operand(w4, UXTW, 2)), "sub wsp, wsp, w4, lsl #2");
  COMPARE(cmp(sp, Operand(xzr, UXTX, 3)), "cmp sp, xzr, lsl #3");
  COMPARE(cmp(sp, Operand(xzr, LSL, 4)), "cmp sp, xzr, lsl #4");

  CLEANUP();
}

TEST_F(DisasmArm64Test, adc_subc_ngc) {
  SET_UP_ASM();

  COMPARE(adc(w0, w1, Operand(w2)), "adc w0, w1, w2");
  COMPARE(adc(x3, x4, Operand(x5)), "adc x3, x4, x5");
  COMPARE(adcs(w6, w7, Operand(w8)), "adcs w6, w7, w8");
  COMPARE(adcs(x9, x10, Operand(x11)), "adcs x9, x10, x11");
  COMPARE(sbc(w12, w13, Operand(w14)), "sbc w12, w13, w14");
  COMPARE(sbc(x15, x16, Operand(x17)), "sbc x15, x16, x17");
  COMPARE(sbcs(w18, w19, Operand(w20)), "sbcs w18, w19, w20");
  COMPARE(sbcs(x21, x22, Operand(x23)), "sbcs x21, x22, x23");
  COMPARE(ngc(w24, Operand(w25)), "ngc w24, w25");
  COMPARE(ngc(x26, Operand(cp)), "ngc x26, cp");
  COMPARE(ngcs(w28, Operand(w29)), "ngcs w28, w29");
  COMPARE(ngcs(lr, Operand(x0)), "ngcs lr, x0");

  CLEANUP();
}

TEST_F(DisasmArm64Test, mul_and_div) {
  SET_UP_ASM();

  COMPARE(mul(w0, w1, w2), "mul w0, w1, w2");
  COMPARE(mul(x3, x4, x5), "mul x3, x4, x5");
  COMPARE(mul(w30, w0, w1), "mul w30, w0, w1");
  COMPARE(mul(lr, x0, x1), "mul lr, x0, x1");
  COMPARE(mneg(w0, w1, w2), "mneg w0, w1, w2");
  COMPARE(mneg(x3, x4, x5), "mneg x3, x4, x5");
  COMPARE(mneg(w30, w0, w1), "mneg w30, w0, w1");
  COMPARE(mneg(lr, x0, x1), "mneg lr, x0, x1");
  COMPARE(smull(x0, w0, w1), "smull x0, w0, w1");
  COMPARE(smull(lr, w30, w0), "smull lr, w30, w0");
  COMPARE(smulh(x0, x1, x2), "smulh x0, x1, x2");

  COMPARE(madd(w0, w1, w2, w3), "madd w0, w1, w2, w3");
  COMPARE(madd(x4, x5, x6, x7), "madd x4, x5, x6, x7");
  COMPARE(madd(w8, w9, w10, wzr), "mul w8, w9, w10");
  COMPARE(madd(x11, x12, x13, xzr), "mul x11, x12, x13");
  COMPARE(msub(w14, w15, w16, w17), "msub w14, w15, w16, w17");
  COMPARE(msub(x18, x19, x20, x21), "msub x18, x19, x20, x21");
  COMPARE(msub(w22, w23, w24, wzr), "mneg w22, w23, w24");
  COMPARE(msub(x25, x26, x0, xzr), "mneg x25, x26, x0");

  COMPARE(sdiv(w0, w1, w2), "sdiv w0, w1, w2");
  COMPARE(sdiv(x3, x4, x5), "sdiv x3, x4, x5");
  COMPARE(udiv(w6, w7, w8), "udiv w6, w7, w8");
  COMPARE(udiv(x9, x10, x11), "udiv x9, x10, x11");

  CLEANUP();
}

TEST_F(DisasmArm64Test, maddl_msubl) {
  SET_UP_ASM();

  COMPARE(smaddl(x0, w1, w2, x3), "smaddl x0, w1, w2, x3");
  COMPARE(smaddl(x25, w21, w22, x16), "smaddl x25, w21, w22, x16");
  COMPARE(umaddl(x0, w1, w2, x3), "umaddl x0, w1, w2, x3");
  COMPARE(umaddl(x25, w21, w22, x16), "umaddl x25, w21, w22, x16");

  COMPARE(smsubl(x0, w1, w2, x3), "smsubl x0, w1, w2, x3");
  COMPARE(smsubl(x25, w21, w22, x16), "smsubl x25, w21, w22, x16");
  COMPARE(umsubl(x0, w1, w2, x3), "umsubl x0, w1, w2, x3");
  COMPARE(umsubl(x25, w21, w22, x16), "umsubl x25, w21, w22, x16");

  CLEANUP();
}

TEST_F(DisasmArm64Test, dp_1_source) {
  SET_UP_ASM();

  COMPARE(rbit(w0, w1), "rbit w0, w1");
  COMPARE(rbit(x2, x3), "rbit x2, x3");
  COMPARE(rev16(w4, w5), "rev16 w4, w5");
  COMPARE(rev16(x6, x7), "rev16 x6, x7");
  COMPARE(rev32(x8, x9), "rev32 x8, x9");
  COMPARE(rev(w10, w11), "rev w10, w11");
  COMPARE(rev(x12, x13), "rev x12, x13");
  COMPARE(clz(w14, w15), "clz w14, w15");
  COMPARE(clz(x16, x17), "clz x16, x17");
  COMPARE(cls(w18, w19), "cls w18, w19");
  COMPARE(cls(x20, x21), "cls x20, x21");

  CLEANUP();
}

TEST_F(DisasmArm64Test, bitfield) {
  SET_UP_ASM();

  COMPARE(sxtb(w0, w1), "sxtb w0, w1");
  COMPARE(sxtb(x2, x3), "sxtb x2, w3");
  COMPARE(sxth(w4, w5), "sxth w4, w5");
  COMPARE(sxth(x6, x7), "sxth x6, w7");
  COMPARE(sxtw(x8, x9), "sxtw x8, w9");
  COMPARE(sxtb(x0, w1), "sxtb x0, w1");
  COMPARE(sxth(x2, w3), "sxth x2, w3");
  COMPARE(sxtw(x4, w5), "sxtw x4, w5");

  COMPARE(uxtb(w10, w11), "uxtb w10, w11");
  COMPARE(uxtb(x12, x13), "uxtb x12, w13");
  COMPARE(uxth(w14, w15), "uxth w14, w15");
  COMPARE(uxth(x16, x17), "uxth x16, w17");
  COMPARE(uxtw(x18, x19), "ubfx x18, x19, #0, #32");

  COMPARE(asr(w20, w21, 10), "asr w20, w21, #10");
  COMPARE(asr(x22, x23, 20), "asr x22, x23, #20");
  COMPARE(lsr(w24, w25, 10), "lsr w24, w25, #10");
  COMPARE(lsr(x26, cp, 20), "lsr x26, cp, #20");
  COMPARE(lsl(w28, w29, 10), "lsl w28, w29, #10");
  COMPARE(lsl(lr, x0, 20), "lsl lr, x0, #20");

  COMPARE(sbfiz(w1, w2, 1, 20), "sbfiz w1, w2, #1, #20");
  COMPARE(sbfiz(x3, x4, 2, 19), "sbfiz x3, x4, #2, #19");
  COMPARE(sbfx(w5, w6, 3, 18), "sbfx w5, w6, #3, #18");
  COMPARE(sbfx(x7, x8, 4, 17), "sbfx x7, x8, #4, #17");
  COMPARE(bfi(w9, w10, 5, 16), "bfi w9, w10, #5, #16");
  COMPARE(bfi(x11, x12, 6, 15), "bfi x11, x12, #6, #15");
  COMPARE(bfxil(w13, w14, 7, 14), "bfxil w13, w14, #7, #14");
  COMPARE(bfxil(x15, x16, 8, 13), "bfxil x15, x16, #8, #13");
  COMPARE(ubfiz(w17, w18, 9, 12), "ubfiz w17, w18, #9, #12");
  COMPARE(ubfiz(x19, x20, 10, 11), "ubfiz x19, x20, #10, #11");
  COMPARE(ubfx(w21, w22, 11, 10), "ubfx w21, w22, #11, #10");
  COMPARE(ubfx(x23, x24, 12, 9), "ubfx x23, x24, #12, #9");

  CLEANUP();
}

TEST_F(DisasmArm64Test, extract) {
  SET_UP_ASM();

  COMPARE(extr(w0, w1, w2, 0), "extr w0, w1, w2, #0");
  COMPARE(extr(x3, x4, x5, 1), "extr x3, x4, x5, #1");
  COMPARE(extr(w6, w7, w8, 31), "extr w6, w7, w8, #31");
  COMPARE(extr(x9, x10, x11, 63), "extr x9, x10, x11, #63");
  COMPARE(extr(w12, w13, w13, 10), "ror w12, w13, #10");
  COMPARE(extr(x14, x15, x15, 42), "ror x14, x15, #42");

  CLEANUP();
}

TEST_F(DisasmArm64Test, logical_immediate) {
  SET_UP_ASM();
#define RESULT_SIZE (256)

  char result[RESULT_SIZE];

  // Test immediate encoding - 64-bit destination.
  // 64-bit patterns.
  uint64_t value = 0x7fffffff;
  for (int i = 0; i < 64; i++) {
    snprintf(result, RESULT_SIZE, "and x0, x0, #0x%" PRIx64, value);
    COMPARE(and_(x0, x0, Operand(value)), result);
    value = ((value & 1) << 63) | (value >> 1);  // Rotate right 1 bit.
  }

  // 32-bit patterns.
  value = 0x00003fff00003fffL;
  for (int i = 0; i < 32; i++) {
    snprintf(result, RESULT_SIZE, "and x0, x0, #0x%" PRIx64, value);
    COMPARE(and_(x0, x0, Operand(value)), result);
    value = ((value & 1) << 63) | (value >> 1);  // Rotate right 1 bit.
  }

  // 16-bit patterns.
  value = 0x001f001f001f001fL;
  for (int i = 0; i < 16; i++) {
    snprintf(result, RESULT_SIZE, "and x0, x0, #0x%" PRIx64, value);
    COMPARE(and_(x0, x0, Operand(value)), result);
    value = ((value & 1) << 63) | (value >> 1);  // Rotate right 1 bit.
  }

  // 8-bit patterns.
  value = 0x0e0e0e0e0e0e0e0eL;
  for (int i = 0; i < 8; i++) {
    snprintf(result, RESULT_SIZE, "and x0, x0, #0x%" PRIx64, value);
    COMPARE(and_(x0, x0, Operand(value)), result);
    value = ((value & 1) << 63) | (value >> 1);  // Rotate right 1 bit.
  }

  // 4-bit patterns.
  value = 0x6666666666666666L;
  for (int i = 0; i < 4; i++) {
    snprintf(result, RESULT_SIZE, "and x0, x0, #0x%" PRIx64, value);
    COMPARE(and_(x0, x0, Operand(value)), result);
    value = ((value & 1) << 63) | (value >> 1);  // Rotate right 1 bit.
  }

  // 2-bit patterns.
  COMPARE(and_(x0, x0, Operand(0x5555555555555555L)),
          "and x0, x0, #0x5555555555555555");
  COMPARE(and_(x0, x0, Operand(0xaaaaaaaaaaaaaaaaL)),
          "and x0, x0, #0xaaaaaaaaaaaaaaaa");

  // Test immediate encoding - 32-bit destination.
  COMPARE(and_(w0, w0, Operand(0xff8007ff)),
          "and w0, w0, #0xff8007ff");  // 32-bit pattern.
  COMPARE(and_(w0, w0, Operand(0xf87ff87f)),
          "and w0, w0, #0xf87ff87f");  // 16-bit pattern.
  COMPARE(and_(w0, w0, Operand(0x87878787)),
          "and w0, w0, #0x87878787");  // 8-bit pattern.
  COMPARE(and_(w0, w0, Operand(0x66666666)),
          "and w0, w0, #0x66666666");  // 4-bit pattern.
  COMPARE(and_(w0, w0, Operand(0x55555555)),
          "and w0, w0, #0x55555555");  // 2-bit pattern.

  // Test other instructions.
  COMPARE(tst(w1, Operand(0x11111111)), "tst w1, #0x11111111");
  COMPARE(tst(x2, Operand(0x8888888888888888L)), "tst x2, #0x8888888888888888");
  COMPARE(orr(w7, w8, Operand(0xaaaaaaaa)), "orr w7, w8, #0xaaaaaaaa");
  COMPARE(orr(x9, x10, Operand(0x5555555555555555L)),
          "orr x9, x10, #0x5555555555555555");
  COMPARE(eor(w15, w16, Operand(0x00000001)), "eor w15, w16, #0x1");
  COMPARE(eor(x17, x18, Operand(0x0000000000000003L)), "eor x17, x18, #0x3");
  COMPARE(ands(w23, w24, Operand(0x0000000f)), "ands w23, w24, #0xf");
  COMPARE(ands(x25, x26, Operand(0x800000000000000fL)),
          "ands x25, x26, #0x800000000000000f");

  // Test inverse.
  COMPARE(bic(w3, w4, Operand(0x20202020)), "and w3, w4, #0xdfdfdfdf");
  COMPARE(bic(x5, x6, Operand(0x4040404040404040L)),
          "and x5, x6, #0xbfbfbfbfbfbfbfbf");
  COMPARE(orn(w11, w12, Operand(0x40004000)), "orr w11, w12, #0xbfffbfff");
  COMPARE(orn(x13, x14, Operand(0x8181818181818181L)),
          "orr x13, x14, #0x7e7e7e7e7e7e7e7e");
  COMPARE(eon(w19, w20, Operand(0x80000001)), "eor w19, w20, #0x7ffffffe");
  COMPARE(eon(x21, x22, Operand(0xc000000000000003L)),
          "eor x21, x22, #0x3ffffffffffffffc");
  COMPARE(bics(w27, w28, Operand(0xfffffff7)), "ands w27, w28, #0x8");
  COMPARE(bics(fp, x0, Operand(0xfffffffeffffffffL)),
          "ands fp, x0, #0x100000000");

  // Test stack pointer.
  COMPARE(and_(wsp, wzr, Operand(7)), "and wsp, wzr, #0x7");
  COMPARE(ands(xzr, xzr, Operand(7)), "tst xzr, #0x7");
  COMPARE(orr(sp, xzr, Operand(15)), "orr sp, xzr, #0xf");
  COMPARE(eor(wsp, w0, Operand(31)), "eor wsp, w0, #0x1f");

  // Test move aliases.
  COMPARE(orr(w0, wzr, Operand(0x00000780)), "orr w0, wzr, #0x780");
  COMPARE(orr(w1, wzr, Operand(0x00007800)), "orr w1, wzr, #0x7800");
  COMPARE(orr(w2, wzr, Operand(0x00078000)), "mov w2, #0x78000");
  COMPARE(orr(w3, wzr, Operand(0x00780000)), "orr w3, wzr, #0x780000");
  COMPARE(orr(w4, wzr, Operand(0x07800000)), "orr w4, wzr, #0x7800000");
  COMPARE(orr(x5, xzr, Operand(0xffffffffffffc001UL)),
          "orr x5, xzr, #0xffffffffffffc001");
  COMPARE(orr(x6, xzr, Operand(0xfffffffffffc001fUL)),
          "mov x6, #0xfffffffffffc001f");
  COMPARE(orr(x7, xzr, Operand(0xffffffffffc001ffUL)),
          "mov x7, #0xffffffffffc001ff");
  COMPARE(orr(x8, xzr, Operand(0xfffffffffc001fffUL)),
          "mov x8, #0xfffffffffc001fff");
  COMPARE(orr(x9, xzr, Operand(0xffffffffc001ffffUL)),
          "orr x9, xzr, #0xffffffffc001ffff");

  CLEANUP();
}

TEST_F(DisasmArm64Test, logical_shifted) {
  SET_UP_ASM();

  COMPARE(and_(w0, w1, Operand(w2)), "and w0, w1, w2");
  COMPARE(and_(x3, x4, Operand(x5, LSL, 1)), "and x3, x4, x5, lsl #1");
  COMPARE(and_(w6, w7, Operand(w8, LSR, 2)), "and w6, w7, w8, lsr #2");
  COMPARE(and_(x9, x10, Operand(x11, ASR, 3)), "and x9, x10, x11, asr #3");
  COMPARE(and_(w12, w13, Operand(w14, ROR, 4)), "and w12, w13, w14, ror #4");

  COMPARE(bic(w15, w16, Operand(w17)), "bic w15, w16, w17");
  COMPARE(bic(x18, x19, Operand(x20, LSL, 5)), "bic x18, x19, x20, lsl #5");
  COMPARE(bic(w21, w22, Operand(w23, LSR, 6)), "bic w21, w22, w23, lsr #6");
  COMPARE(bic(x24, x25, Operand(x26, ASR, 7)), "bic x24, x25, x26, asr #7");
  COMPARE(bic(w27, w28, Operand(w29, ROR, 8)), "bic w27, w28, w29, ror #8");

  COMPARE(orr(w0, w1, Operand(w2)), "orr w0, w1, w2");
  COMPARE(orr(x3, x4, Operand(x5, LSL, 9)), "orr x3, x4, x5, lsl #9");
  COMPARE(orr(w6, w7, Operand(w8, LSR, 10)), "orr w6, w7, w8, lsr #10");
  COMPARE(orr(x9, x10, Operand(x11, ASR, 11)), "orr x9, x10, x11, asr #11");
  COMPARE(orr(w12, w13, Operand(w14, ROR, 12)), "orr w12, w13, w14, ror #12");

  COMPARE(orn(w15, w16, Operand(w17)), "orn w15, w16, w17");
  COMPARE(orn(x18, x19, Operand(x20, LSL, 13)), "orn x18, x19, x20, lsl #13");
  COMPARE(orn(w21, w22, Operand(w23, LSR, 14)), "orn w21, w22, w23, lsr #14");
  COMPARE(orn(x24, x25, Operand(x26, ASR, 15)), "orn x24, x25, x26, asr #15");
  COMPARE(orn(w27, w28, Operand(w29, ROR, 16)), "orn w27, w28, w29, ror #16");

  COMPARE(eor(w0, w1, Operand(w2)), "eor w0, w1, w2");
  COMPARE(eor(x3, x4, Operand(x5, LSL, 17)), "eor x3, x4, x5, lsl #17");
  COMPARE(eor(w6, w7, Operand(w8, LSR, 18)), "eor w6, w7, w8, lsr #18");
  COMPARE(eor(x9, x10, Operand(x11, ASR, 19)), "eor x9, x10, x11, asr #19");
  COMPARE(eor(w12, w13, Operand(w14, ROR, 20)), "eor w12, w13, w14, ror #20");

  COMPARE(eon(w15, w16, Operand(w17)), "eon w15, w16, w17");
  COMPARE(eon(x18, x19, Operand(x20, LSL, 21)), "eon x18, x19, x20, lsl #21");
  COMPARE(eon(w21, w22, Operand(w23, LSR, 22)), "eon w21, w22, w23, lsr #22");
  COMPARE(eon(x24, x25, Operand(x26, ASR, 23)), "eon x24, x25, x26, asr
```