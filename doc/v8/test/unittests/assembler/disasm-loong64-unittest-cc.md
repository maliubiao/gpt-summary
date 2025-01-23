Response:
Let's break down the thought process for analyzing this C++ code snippet.

**1. Initial Understanding and Context:**

* **File Path:** `v8/test/unittests/assembler/disasm-loong64-unittest.cc`. The path itself is highly informative.
    * `v8`:  Indicates this is part of the V8 JavaScript engine.
    * `test`: This is a test file.
    * `unittests`: Specifically, a unit test.
    * `assembler`: Deals with assembly code generation.
    * `disasm`:  Suggests disassembly, the reverse process of assembly.
    * `loong64`: Targets the LoongArch 64-bit architecture.
    * `unittest.cc`:  Confirms it's a C++ unit test file.

* **Copyright Header:** Standard V8 copyright and license information. Indicates this is official V8 code.

* **Includes:** These headers provide clues about the code's functionality:
    * `<stdio.h>`, `<stdlib.h>`: Standard C library functions (input/output, memory allocation).
    * `"src/codegen/macro-assembler.h"`:  Crucial. V8's mechanism for generating machine code. Implies the code will *assemble* instructions.
    * `"src/debug/debug.h"`: Likely used for debugging or assertions.
    * `"src/diagnostics/disasm.h"`, `"src/diagnostics/disassembler.h"`: Key for *disassembling* machine code.
    * `"src/execution/frames-inl.h"`:  Potentially related to stack frames, which are important when dealing with function calls and assembly.
    * `"src/init/v8.h"`:  V8 initialization. Necessary for setting up a V8 environment to run the tests.
    * `"test/unittests/test-utils.h"`:  V8-specific test utilities.
    * `"testing/gtest/include/gtest/gtest.h"`: Google Test framework. Confirms this file uses gtest for unit testing.

* **Namespace:** `v8::internal`. Indicates this is internal V8 implementation code, not public API.

**2. High-Level Functionality Identification:**

Based on the file path, includes, and the `DisassembleAndCompare` function, the core purpose becomes clear: **testing the LoongArch 64-bit disassembler in V8.**  It assembles instructions and then checks if the disassembler produces the expected output.

**3. Detailed Analysis of Key Components:**

* **`DisassembleAndCompare(uint8_t* pc, const char* compare_string)`:** This is the heart of the testing logic.
    * Takes a pointer to machine code (`pc`) and an expected disassembly string (`compare_string`).
    * Creates a `disasm::Disassembler` instance.
    * Calls `InstructionDecode` to disassemble the instruction at `pc`.
    * Compares the disassembled output with `compare_string` using `strcmp`.
    * Prints an error message if the comparison fails.

* **Macros (`SET_UP`, `COMPARE`, `VERIFY_RUN`, `COMPARE_PC_REL`):**  These are designed to simplify the test writing process.
    * `SET_UP()`: Initializes a V8 Isolate, allocates memory for code, and creates an `Assembler`. This sets up the environment for generating and disassembling code.
    * `COMPARE(asm_, compare_string)`:  This is the primary test macro.
        * Gets the current program counter offset (`pc_offset`).
        * Points `progcounter` to the current location in the allocated buffer.
        * Executes the assembly instruction provided in `asm_`.
        * Calls `DisassembleAndCompare` to verify the disassembly.
        * Sets a `failure` flag if disassembly fails.
    * `VERIFY_RUN()`:  Checks the `failure` flag and issues a `FATAL` error if any test failed. This ensures that test failures are reported clearly.
    * `COMPARE_PC_REL(...)`:  Similar to `COMPARE`, but it handles cases where the disassembled output includes an address relative to the program counter. It dynamically formats the expected string with the calculated address.

* **Test Fixtures (`DisasmLoong64Test`):** Uses the Google Test framework. Each `TEST_F` represents an individual test case.

* **Individual Test Cases (`TypeOp6`, `TypeOp6PC`, `TypeOp7`, etc.):** Each test case focuses on disassembling a specific type of LoongArch instruction or a group of related instructions. They use the macros to assemble instructions and compare the disassembly.

**4. Answering the Specific Questions:**

* **Functionality:** (As derived above) Tests the LoongArch 64-bit disassembler in V8 by assembling instructions and comparing the disassembled output with expected strings.

* **Torque:** The filename doesn't end with `.tq`, so it's **not** a Torque source file.

* **JavaScript Relation:**  This code is *part* of V8, the engine that *runs* JavaScript. While this specific C++ file doesn't directly execute JavaScript code, it's crucial for V8's ability to understand and execute machine code generated from JavaScript. The assembler and disassembler are fundamental components in the JavaScript execution pipeline (compilation to machine code).

* **JavaScript Example (Illustrative):**  A simple JavaScript function can illustrate the concept:

   ```javascript
   function add(a, b) {
       return a + b;
   }
   ```

   When V8 compiles this function, it generates LoongArch64 machine code (on a LoongArch64 system). This `disasm-loong64-unittest.cc` code would be used to verify that V8 can correctly disassemble the *generated* machine code back into a readable representation.

* **Code Logic/Assumptions:**
    * **Assumption:** The `compare_string` in the `COMPARE` macros represents the *correct* disassembly of the corresponding assembly instruction. This requires either manual verification or comparison against a known-good disassembler.
    * **Input:**  Assembly instructions written using V8's `Assembler` API (e.g., `jirl(ra, t7, 0)`).
    * **Output:** A boolean indicating whether the disassembly matches the expected string. The macros also print error messages to `stderr` on failure.

* **Common Programming Errors (Related to Assembly/Disassembly):**
    * **Incorrect Instruction Encoding:**  Generating the wrong byte sequence for an intended instruction. The disassembler might produce garbage or disassemble it as a different instruction.
    * **Incorrect Operand Encoding:**  Encoding register numbers or immediate values incorrectly within the instruction.
    * **Address Calculation Errors (for PC-relative instructions):**  Calculating branch targets or memory addresses incorrectly. The `COMPARE_PC_REL` macro helps catch these.
    * **Endianness Issues:**  While not explicitly shown in this code, dealing with byte order can be a source of errors when working with raw machine code.
    * **Forgetting Instruction Prefixes/Suffixes:**  Some architectures have prefixes or suffixes for certain instructions. Incorrectly including or omitting them will lead to disassembly errors.

* **Functionality Summary:**  This C++ unit test file for V8 verifies the correctness of the LoongArch 64-bit disassembler by assembling various instructions and comparing the disassembler's output against expected strings. This ensures that V8 can accurately analyze and potentially debug the machine code it generates for the LoongArch64 architecture.

This detailed thought process allows for a comprehensive understanding of the code's purpose and its relationship to the broader V8 project.
好的，让我们来分析一下 `v8/test/unittests/assembler/disasm-loong64-unittest.cc` 这个 V8 源代码文件的功能。

**功能归纳：**

`v8/test/unittests/assembler/disasm-loong64-unittest.cc` 是一个 **C++ 单元测试文件**，用于测试 V8 JavaScript 引擎中 **LoongArch 64 位架构（loong64）的反汇编器 (disassembler)** 的正确性。

**具体功能分解：**

1. **测试反汇编器的指令解码能力:** 该文件包含了大量的测试用例，每个测试用例都针对特定的 LoongArch64 汇编指令。它会：
   - 使用 V8 的 `Assembler` 类生成 LoongArch64 的机器码指令。
   - 使用 V8 的 `Disassembler` 类对生成的机器码进行反汇编，将其转换回可读的汇编指令字符串。
   - 将反汇编的结果与预期的字符串进行比较，以验证反汇编器是否正确地解码了指令。

2. **覆盖多种指令类型:**  从文件名和代码内容来看，测试涵盖了 LoongArch64 架构的多种指令类型，例如：
   - **TypeOp6:**  跳转指令 (`jirl`)
   - **TypeOp6PC:**  基于程序计数器的条件分支指令 (`beqz`, `bnez`, `beq`, `bne`, `blt`, `bge`, `bltu`, `bgeu`, `b`)
   - **TypeOp7:**  立即数加载和 PC 相对地址计算指令 (`lu12i_w`, `lu32i_d`, `pcaddi`, `pcalau12i`, `pcaddu12i`, `pcaddu18i`)
   - **TypeOp8:**  Load-Linked/Store-Conditional 和指针操作指令 (`ll_w`, `sc_w`, `ll_d`, `sc_d`, `ldptr_w`, `stptr_w`, `ldptr_d`, `stptr_d`)
   - **TypeOp10:**  位操作、立即数比较、立即数算术和加载/存储指令 (`bstrins_w`, `bstrins_d`, `bstrpick_w`, `bstrpick_d`, `slti`, `sltui`, `addi_w`, `addi_d`, `lu52i_d`, `andi`, `ori`, `xori`, `ld_b`, `ld_h`, `ld_w`, `ld_d`, `st_b`, `st_h`, `st_w`, `st_d`, `ld_bu`, `ld_hu`, `ld_wu`, `fld_s`, `fld_d`, `fst_d`, `fst_s`)
   - **TypeOp12:**  浮点乘加/减和比较指令 (`fmadd_s`, `fmadd_d`, `fmsub_s`, `fmsub_d`, `fnmadd_s`, `fnmadd_d`, `fnmsub_s`, `fnmsub_d`, `fcmp_cond_s`, `fcmp_cond_d`)
   - **TypeOp14:**  移位和位操作指令 (`alsl_w`, `alsl_wu`, `alsl_d`, `bytepick_w`, `bytepick_d`, `slli_w`, `slli_d`, `srli_w`, `srli_d`, `srai_d`, `srai_w`, `rotri_d`)
   - **TypeOp17:**  算术、逻辑、移位和乘除法指令 (`sltu`, `add_w`, `add_d`, `sub_w`, `sub_d`, `slt`, `maskeqz`, `masknez`, `or_`, `and_`, `nor`, `xor_`, `orn`, `andn`, `sll_w`, `srl_w`, `sra_w`, `sll_d`, `srl_d`, `sra_d`, `rotr_d`, `rotr_w`, `mul_w`, `mulh_w`, `mulh_wu`, `mul_d`, `mulh_d`, `mulh_du`, `mulw_d_w`, `mulw_d_wu`, `div_w`, `mod_w`, `div_wu`, `mod_wu`, `div_d`, `mod_d`, `div_du`, `mod_du`, `fadd_s`, `fadd_d`, `fsub_s`, `fsub_d`, `fmul_s`, `fmul_d`, `fdiv_s`, `fdiv_d`, `fmax_s`, `fmin_s`, `fmax_d`, `fmin_d`, `fmaxa_s`)  (代码片段未完整展示 TypeOp17 的所有指令)

3. **使用 Google Test 框架:**  该文件使用了 Google Test 框架来组织和运行测试用例。`TEST_F(DisasmLoong64Test, ...)` 定义了不同的测试用例。

4. **辅助宏定义:**  文件中定义了一些宏，例如 `SET_UP`, `COMPARE`, `VERIFY_RUN`, `COMPARE_PC_REL`，用于简化测试代码的编写：
   - `SET_UP()`:  初始化测试环境，包括 V8 Isolate 和 `Assembler` 对象。
   - `COMPARE(asm_, compare_string)`:  组装给定的汇编指令，反汇编结果，并与预期字符串比较。
   - `VERIFY_RUN()`:  检查所有 `COMPARE` 宏是否都成功通过，如果失败则报错。
   - `COMPARE_PC_REL(asm_, compare_string, offset)`: 类似 `COMPARE`，但用于处理包含 PC 相对地址的指令，会在比较字符串中动态添加计算出的地址。

**关于其他问题的回答：**

* **`.tq` 结尾:**  `v8/test/unittests/assembler/disasm-loong64-unittest.cc` 以 `.cc` 结尾，表示它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件（Torque 文件以 `.tq` 结尾）。

* **与 JavaScript 的关系:**  这个 C++ 文件是 V8 引擎的一部分，V8 负责执行 JavaScript 代码。反汇编器是 V8 的一个重要组成部分，主要用于：
    - **调试:**  在开发和调试 V8 引擎本身时，反汇编器可以将生成的机器码转换为人类可读的汇编指令，方便开发者理解代码的执行流程和查找错误。
    - **性能分析:**  通过分析反汇编后的代码，可以了解 V8 生成的机器码的效率，并进行优化。
    - **JIT 编译器优化:**  反汇编可以帮助理解 JIT (Just-In-Time) 编译器生成的代码，从而改进编译器的优化策略。

* **JavaScript 示例 (概念性):** 虽然这个 C++ 文件不直接执行 JavaScript，但可以想象当 V8 编译执行以下 JavaScript 代码时，`disasm-loong64-unittest.cc` 中测试的反汇编器可以用来查看 V8 为其生成的 LoongArch64 机器码：

   ```javascript
   function add(a, b) {
       return a + b;
   }

   let result = add(5, 3);
   ```

   V8 内部会将 `add` 函数编译成 LoongArch64 的机器码，例如，可能包含加法指令（`add_d` 或 `add_w`，取决于数据类型）。  `disasm-loong64-unittest.cc` 就是在验证 V8 能否正确地将这些机器码反汇编回类似 `add.d  a4, t0, t1` 这样的汇编指令。

* **代码逻辑推理和假设输入/输出:**

   **假设输入 (针对 `COMPARE` 宏):**
   ```c++
   COMPARE(addi_d(a0, zero_reg, 2047), "02dffc04       addi.d       a0, zero_reg, 2047(0x7ff)");
   ```

   - **汇编指令 (`asm_`):** `addi_d(a0, zero_reg, 2047)` - 这条指令在 LoongArch64 架构中将立即数 2047 加到 `zero_reg` 寄存器（其值为 0），并将结果存储到 `a0` 寄存器。
   - **预期字符串 (`compare_string`):** `"02dffc04       addi.d       a0, zero_reg, 2047(0x7ff)"` - 这是我们期望的反汇编器输出的字符串。 `02dffc04` 是这条指令的机器码，后面的部分是反汇编后的汇编指令，包括操作码、操作数和立即数的十六进制表示。

   **预期输出:**
   - 如果反汇编器能够正确解码指令，`DisassembleAndCompare` 函数将返回 `true`，测试用例通过。
   - 如果反汇编器的输出与预期字符串不符，`DisassembleAndCompare` 函数将返回 `false`，`failure` 标志会被设置为 `true`，并且会打印错误信息到 `stderr`。

* **用户常见的编程错误 (与反汇编测试相关的概念):**

   虽然用户通常不会直接编写或修改像这样的反汇编器测试代码，但理解测试背后的概念可以帮助理解与汇编和机器码相关的常见错误：

   1. **指令编码错误:**  如果 V8 的汇编器在生成机器码时出现错误，例如，对于 `addi_d(a0, zero_reg, 2047)` 错误地生成了不同的机器码，那么反汇编器可能会解码出错误的指令，导致测试失败。

   2. **操作数解析错误:**  反汇编器可能无法正确识别指令的操作数（寄存器、立即数、内存地址等）。例如，可能错误地将 `zero_reg` 解码成其他寄存器。

   3. **立即数和偏移量处理错误:**  对于包含立即数或偏移量的指令，反汇编器可能无法正确解析和显示这些值，例如，可能无法正确显示 2047 或其十六进制表示 `0x7ff`。

   4. **指令格式理解错误:**  不同的指令有不同的格式。反汇编器需要准确理解每种指令的格式才能正确解码。例如，对于 PC 相对分支指令，需要正确计算目标地址。

**总结一下第 1 部分的功能：**

`v8/test/unittests/assembler/disasm-loong64-unittest.cc` 的第 1 部分（以及后续部分）的主要功能是 **系统地测试 V8 JavaScript 引擎中 LoongArch64 架构反汇编器的正确性**。它通过生成各种 LoongArch64 机器码指令，并验证反汇编器能否将它们准确地转换回对应的汇编指令字符串，从而确保 V8 在处理 LoongArch64 架构时能够正确地进行代码分析和调试。

### 提示词
```
这是目录为v8/test/unittests/assembler/disasm-loong64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/assembler/disasm-loong64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2021 the V8 project authors. All rights reserved.
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

#include <stdio.h>
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

using DisasmLoong64Test = TestWithIsolate;

bool DisassembleAndCompare(uint8_t* pc, const char* compare_string) {
  disasm::NameConverter converter;
  disasm::Disassembler disasm(converter);
  base::EmbeddedVector<char, 128> disasm_buffer;

  /*  if (prev_instr_compact_branch) {
      disasm.InstructionDecode(disasm_buffer, pc);
      pc += 4;
    }*/

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

// Verify that all invocations of the COMPARE macro passed successfully.
// Exit with a failure if at least one of the tests failed.
#define VERIFY_RUN()                               \
  if (failure) {                                   \
    FATAL("LOONG64 Disassembler tests failed.\n"); \
  }

#define COMPARE_PC_REL(asm_, compare_string, offset)                           \
  {                                                                            \
    int pc_offset = assm.pc_offset();                                          \
    uint8_t* progcounter = &buffer[pc_offset];                                 \
    char str_with_address[100];                                                \
    printf("%p\n", static_cast<void*>(progcounter));                           \
    snprintf(str_with_address, sizeof(str_with_address), "%s -> %p",           \
             compare_string, static_cast<void*>(progcounter + (offset * 4)));  \
    assm.asm_;                                                                 \
    if (!DisassembleAndCompare(progcounter, str_with_address)) failure = true; \
  }

TEST_F(DisasmLoong64Test, TypeOp6) {
  SET_UP();

  COMPARE(jirl(ra, t7, 0), "4c000261       jirl         ra, t7, 0x0");
  COMPARE(jirl(ra, t7, 32767), "4dfffe61       jirl         ra, t7, 0x1fffc");
  COMPARE(jirl(ra, t7, -32768), "4e000261       jirl         ra, t7, 0x20000");

  VERIFY_RUN();
}

TEST_F(DisasmLoong64Test, TypeOp6PC) {
  SET_UP();

  COMPARE_PC_REL(beqz(t7, 1048575), "43fffe6f       beqz         t7, 0x3ffffc",
                 1048575);
  COMPARE_PC_REL(beqz(t0, -1048576), "40000190       beqz         t0, 0x400000",
                 -1048576);
  COMPARE_PC_REL(beqz(t1, 0), "400001a0       beqz         t1, 0x0", 0);

  COMPARE_PC_REL(bnez(a2, 1048575), "47fffccf       bnez         a2, 0x3ffffc",
                 1048575);
  COMPARE_PC_REL(bnez(s3, -1048576), "44000350       bnez         s3, 0x400000",
                 -1048576);
  COMPARE_PC_REL(bnez(t8, 0), "44000280       bnez         t8, 0x0", 0);

  COMPARE_PC_REL(bceqz(FCC0, 1048575),
                 "4bfffc0f       bceqz        fcc0, 0x3ffffc", 1048575);
  COMPARE_PC_REL(bceqz(FCC0, -1048576),
                 "48000010       bceqz        fcc0, 0x400000", -1048576);
  COMPARE_PC_REL(bceqz(FCC0, 0), "48000000       bceqz        fcc0, 0x0", 0);

  COMPARE_PC_REL(bcnez(FCC0, 1048575),
                 "4bfffd0f       bcnez        fcc0, 0x3ffffc", 1048575);
  COMPARE_PC_REL(bcnez(FCC0, -1048576),
                 "48000110       bcnez        fcc0, 0x400000", -1048576);
  COMPARE_PC_REL(bcnez(FCC0, 0), "48000100       bcnez        fcc0, 0x0", 0);

  COMPARE_PC_REL(b(33554431), "53fffdff       b            0x7fffffc",
                 33554431);
  COMPARE_PC_REL(b(-33554432), "50000200       b            0x8000000",
                 -33554432);
  COMPARE_PC_REL(b(0), "50000000       b            0x0", 0);

  COMPARE_PC_REL(beq(t0, a6, 32767),
                 "59fffd8a       beq          t0, a6, 0x1fffc", 32767);
  COMPARE_PC_REL(beq(t1, a0, -32768),
                 "5a0001a4       beq          t1, a0, 0x20000", -32768);
  COMPARE_PC_REL(beq(a4, t1, 0), "5800010d       beq          a4, t1, 0x0", 0);

  COMPARE_PC_REL(bne(a3, a4, 32767),
                 "5dfffce8       bne          a3, a4, 0x1fffc", 32767);
  COMPARE_PC_REL(bne(a6, a5, -32768),
                 "5e000149       bne          a6, a5, 0x20000", -32768);
  COMPARE_PC_REL(bne(a4, a5, 0), "5c000109       bne          a4, a5, 0x0", 0);

  COMPARE_PC_REL(blt(a4, a6, 32767),
                 "61fffd0a       blt          a4, a6, 0x1fffc", 32767);
  COMPARE_PC_REL(blt(a4, a5, -32768),
                 "62000109       blt          a4, a5, 0x20000", -32768);
  COMPARE_PC_REL(blt(a4, a6, 0), "6000010a       blt          a4, a6, 0x0", 0);

  COMPARE_PC_REL(bge(s7, a5, 32767),
                 "65ffffc9       bge          s7, a5, 0x1fffc", 32767);
  COMPARE_PC_REL(bge(a1, a3, -32768),
                 "660000a7       bge          a1, a3, 0x20000", -32768);
  COMPARE_PC_REL(bge(a5, s3, 0), "6400013a       bge          a5, s3, 0x0", 0);

  COMPARE_PC_REL(bltu(a5, s7, 32767),
                 "69fffd3e       bltu         a5, s7, 0x1fffc", 32767);
  COMPARE_PC_REL(bltu(a4, a5, -32768),
                 "6a000109       bltu         a4, a5, 0x20000", -32768);
  COMPARE_PC_REL(bltu(a4, t6, 0), "68000112       bltu         a4, t6, 0x0", 0);

  COMPARE_PC_REL(bgeu(a7, a6, 32767),
                 "6dfffd6a       bgeu         a7, a6, 0x1fffc", 32767);
  COMPARE_PC_REL(bgeu(a5, a3, -32768),
                 "6e000127       bgeu         a5, a3, 0x20000", -32768);
  COMPARE_PC_REL(bgeu(t2, t1, 0), "6c0001cd       bgeu         t2, t1, 0x0", 0);

  VERIFY_RUN();
}

TEST_F(DisasmLoong64Test, TypeOp7) {
  SET_UP();

  COMPARE(lu12i_w(a4, 524287), "14ffffe8       lu12i.w      a4, 0x7ffff");
  COMPARE(lu12i_w(a5, -524288), "15000009       lu12i.w      a5, 0x80000");
  COMPARE(lu12i_w(a6, 0), "1400000a       lu12i.w      a6, 0x0");

  COMPARE(lu32i_d(a7, 524287), "16ffffeb       lu32i.d      a7, 0x7ffff");
  COMPARE(lu32i_d(t0, -524288), "1700000c       lu32i.d      t0, 0x80000");
  COMPARE(lu32i_d(t1, 0), "1600000d       lu32i.d      t1, 0x0");

  COMPARE(pcaddi(t1, 1), "1800002d       pcaddi       t1, 0x1");
  COMPARE(pcaddi(t2, 524287), "18ffffee       pcaddi       t2, 0x7ffff");
  COMPARE(pcaddi(t3, -524288), "1900000f       pcaddi       t3, 0x80000");
  COMPARE(pcaddi(t4, 0), "18000010       pcaddi       t4, 0x0");

  COMPARE(pcalau12i(t5, 524287), "1afffff1       pcalau12i    t5, 0x7ffff");
  COMPARE(pcalau12i(t6, -524288), "1b000012       pcalau12i    t6, 0x80000");
  COMPARE(pcalau12i(a4, 0), "1a000008       pcalau12i    a4, 0x0");

  COMPARE(pcaddu12i(a5, 524287), "1cffffe9       pcaddu12i    a5, 0x7ffff");
  COMPARE(pcaddu12i(a6, -524288), "1d00000a       pcaddu12i    a6, 0x80000");
  COMPARE(pcaddu12i(a7, 0), "1c00000b       pcaddu12i    a7, 0x0");

  COMPARE(pcaddu18i(t0, 524287), "1effffec       pcaddu18i    t0, 0x7ffff");
  COMPARE(pcaddu18i(t1, -524288), "1f00000d       pcaddu18i    t1, 0x80000");
  COMPARE(pcaddu18i(t2, 0), "1e00000e       pcaddu18i    t2, 0x0");

  VERIFY_RUN();
}

TEST_F(DisasmLoong64Test, TypeOp8) {
  SET_UP();

  COMPARE(ll_w(t2, t3, 32764),
          "207ffdee       ll.w         t2, t3, 32764(0x7ffc)");
  COMPARE(ll_w(t3, t4, -32768),
          "2080020f       ll.w         t3, t4, -32768(0x8000)");
  COMPARE(ll_w(t5, t6, 0), "20000251       ll.w         t5, t6, 0(0x0)");

  COMPARE(sc_w(a6, a7, 32764),
          "217ffd6a       sc.w         a6, a7, 32764(0x7ffc)");
  COMPARE(sc_w(t0, t1, -32768),
          "218001ac       sc.w         t0, t1, -32768(0x8000)");
  COMPARE(sc_w(t2, t3, 0), "210001ee       sc.w         t2, t3, 0(0x0)");

  COMPARE(ll_d(a0, a1, 32764),
          "227ffca4       ll.d         a0, a1, 32764(0x7ffc)");
  COMPARE(ll_d(a2, a3, -32768),
          "228000e6       ll.d         a2, a3, -32768(0x8000)");
  COMPARE(ll_d(a4, a5, 0), "22000128       ll.d         a4, a5, 0(0x0)");

  COMPARE(sc_d(t4, t5, 32764),
          "237ffe30       sc.d         t4, t5, 32764(0x7ffc)");
  COMPARE(sc_d(t6, a0, -32768),
          "23800092       sc.d         t6, a0, -32768(0x8000)");
  COMPARE(sc_d(a1, a2, 0), "230000c5       sc.d         a1, a2, 0(0x0)");

  COMPARE(ldptr_w(a4, a5, 32764),
          "247ffd28       ldptr.w      a4, a5, 32764(0x7ffc)");
  COMPARE(ldptr_w(a6, a7, -32768),
          "2480016a       ldptr.w      a6, a7, -32768(0x8000)");
  COMPARE(ldptr_w(t0, t1, 0), "240001ac       ldptr.w      t0, t1, 0(0x0)");

  COMPARE(stptr_w(a4, a5, 32764),
          "257ffd28       stptr.w      a4, a5, 32764(0x7ffc)");
  COMPARE(stptr_w(a6, a7, -32768),
          "2580016a       stptr.w      a6, a7, -32768(0x8000)");
  COMPARE(stptr_w(t0, t1, 0), "250001ac       stptr.w      t0, t1, 0(0x0)");

  COMPARE(ldptr_d(t2, t3, 32764),
          "267ffdee       ldptr.d      t2, t3, 32764(0x7ffc)");
  COMPARE(ldptr_d(t4, t5, -32768),
          "26800230       ldptr.d      t4, t5, -32768(0x8000)");
  COMPARE(ldptr_d(t6, a4, 0), "26000112       ldptr.d      t6, a4, 0(0x0)");

  COMPARE(stptr_d(a5, a6, 32764),
          "277ffd49       stptr.d      a5, a6, 32764(0x7ffc)");
  COMPARE(stptr_d(a7, t0, -32768),
          "2780018b       stptr.d      a7, t0, -32768(0x8000)");
  COMPARE(stptr_d(t1, t2, 0), "270001cd       stptr.d      t1, t2, 0(0x0)");

  VERIFY_RUN();
}

TEST_F(DisasmLoong64Test, TypeOp10) {
  SET_UP();

  COMPARE(bstrins_w(a4, a5, 31, 16),
          "007f4128       bstrins.w    a4, a5, 31, 16");
  COMPARE(bstrins_w(a6, a7, 5, 0), "0065016a       bstrins.w    a6, a7, 5, 0");

  COMPARE(bstrins_d(a3, zero_reg, 17, 0),
          "00910007       bstrins.d    a3, zero_reg, 17, 0");
  COMPARE(bstrins_d(t1, zero_reg, 17, 0),
          "0091000d       bstrins.d    t1, zero_reg, 17, 0");

  COMPARE(bstrpick_w(t0, t1, 31, 29),
          "007ff5ac       bstrpick.w   t0, t1, 31, 29");
  COMPARE(bstrpick_w(a4, a5, 16, 0),
          "00708128       bstrpick.w   a4, a5, 16, 0");

  COMPARE(bstrpick_d(a5, a5, 31, 0),
          "00df0129       bstrpick.d   a5, a5, 31, 0");
  COMPARE(bstrpick_d(a4, a4, 25, 2),
          "00d90908       bstrpick.d   a4, a4, 25, 2");

  COMPARE(slti(t2, a5, 2047),
          "021ffd2e       slti         t2, a5, 2047(0x7ff)");
  COMPARE(slti(a7, a1, -2048),
          "022000ab       slti         a7, a1, -2048(0x800)");

  COMPARE(sltui(a7, a7, 2047),
          "025ffd6b       sltui        a7, a7, 2047(0x7ff)");
  COMPARE(sltui(t1, t1, -2048),
          "026001ad       sltui        t1, t1, -2048(0x800)");

  COMPARE(addi_w(t0, t2, 2047),
          "029ffdcc       addi.w       t0, t2, 2047(0x7ff)");
  COMPARE(addi_w(a0, a0, -2048),
          "02a00084       addi.w       a0, a0, -2048(0x800)");

  COMPARE(addi_d(a0, zero_reg, 2047),
          "02dffc04       addi.d       a0, zero_reg, 2047(0x7ff)");
  COMPARE(addi_d(t7, t7, -2048),
          "02e00273       addi.d       t7, t7, -2048(0x800)");

  COMPARE(lu52i_d(a0, a0, 2047), "031ffc84       lu52i.d      a0, a0, 0x7ff");
  COMPARE(lu52i_d(a1, a1, -2048), "032000a5       lu52i.d      a1, a1, 0x800");

  COMPARE(andi(s3, a3, 0xfff), "037ffcfa       andi         s3, a3, 0xfff");
  COMPARE(andi(a4, a4, 0), "03400108       andi         a4, a4, 0x0");

  COMPARE(ori(t6, t6, 0xfff), "03bffe52       ori          t6, t6, 0xfff");
  COMPARE(ori(t6, t6, 0), "03800252       ori          t6, t6, 0x0");

  COMPARE(xori(t1, t1, 0xfff), "03fffdad       xori         t1, t1, 0xfff");
  COMPARE(xori(a3, a3, 0x0), "03c000e7       xori         a3, a3, 0x0");

  COMPARE(ld_b(a1, a1, 2047),
          "281ffca5       ld.b         a1, a1, 2047(0x7ff)");
  COMPARE(ld_b(a4, a4, -2048),
          "28200108       ld.b         a4, a4, -2048(0x800)");

  COMPARE(ld_h(a4, a0, 2047),
          "285ffc88       ld.h         a4, a0, 2047(0x7ff)");
  COMPARE(ld_h(a4, a3, -2048),
          "286000e8       ld.h         a4, a3, -2048(0x800)");

  COMPARE(ld_w(a6, a6, 2047),
          "289ffd4a       ld.w         a6, a6, 2047(0x7ff)");
  COMPARE(ld_w(a5, a4, -2048),
          "28a00109       ld.w         a5, a4, -2048(0x800)");

  COMPARE(ld_d(a0, a3, 2047),
          "28dffce4       ld.d         a0, a3, 2047(0x7ff)");
  COMPARE(ld_d(a6, fp, -2048),
          "28e002ca       ld.d         a6, fp, -2048(0x800)");
  COMPARE(ld_d(a0, a6, 0), "28c00144       ld.d         a0, a6, 0(0x0)");

  COMPARE(st_b(a4, a0, 2047),
          "291ffc88       st.b         a4, a0, 2047(0x7ff)");
  COMPARE(st_b(a6, a5, -2048),
          "2920012a       st.b         a6, a5, -2048(0x800)");

  COMPARE(st_h(a4, a0, 2047),
          "295ffc88       st.h         a4, a0, 2047(0x7ff)");
  COMPARE(st_h(t1, t2, -2048),
          "296001cd       st.h         t1, t2, -2048(0x800)");

  COMPARE(st_w(t3, a4, 2047),
          "299ffd0f       st.w         t3, a4, 2047(0x7ff)");
  COMPARE(st_w(a3, t2, -2048),
          "29a001c7       st.w         a3, t2, -2048(0x800)");

  COMPARE(st_d(s3, sp, 2047),
          "29dffc7a       st.d         s3, sp, 2047(0x7ff)");
  COMPARE(st_d(fp, s6, -2048),
          "29e003b6       st.d         fp, s6, -2048(0x800)");

  COMPARE(ld_bu(a6, a0, 2047),
          "2a1ffc8a       ld.bu        a6, a0, 2047(0x7ff)");
  COMPARE(ld_bu(a7, a7, -2048),
          "2a20016b       ld.bu        a7, a7, -2048(0x800)");

  COMPARE(ld_hu(a7, a7, 2047),
          "2a5ffd6b       ld.hu        a7, a7, 2047(0x7ff)");
  COMPARE(ld_hu(a3, a3, -2048),
          "2a6000e7       ld.hu        a3, a3, -2048(0x800)");

  COMPARE(ld_wu(a3, a0, 2047),
          "2a9ffc87       ld.wu        a3, a0, 2047(0x7ff)");
  COMPARE(ld_wu(a3, a5, -2048),
          "2aa00127       ld.wu        a3, a5, -2048(0x800)");

  COMPARE(fld_s(f0, a3, 2047),
          "2b1ffce0       fld.s        f0, a3, 2047(0x7ff)");
  COMPARE(fld_s(f0, a1, -2048),
          "2b2000a0       fld.s        f0, a1, -2048(0x800)");

  COMPARE(fld_d(f0, a0, 2047),
          "2b9ffc80       fld.d        f0, a0, 2047(0x7ff)");
  COMPARE(fld_d(f0, fp, -2048),
          "2ba002c0       fld.d        f0, fp, -2048(0x800)");

  COMPARE(fst_d(f0, fp, 2047),
          "2bdffec0       fst.d        f0, fp, 2047(0x7ff)");
  COMPARE(fst_d(f0, a0, -2048),
          "2be00080       fst.d        f0, a0, -2048(0x800)");

  COMPARE(fst_s(f0, a5, 2047),
          "2b5ffd20       fst.s        f0, a5, 2047(0x7ff)");
  COMPARE(fst_s(f0, a3, -2048),
          "2b6000e0       fst.s        f0, a3, -2048(0x800)");

  VERIFY_RUN();
}

TEST_F(DisasmLoong64Test, TypeOp12) {
  SET_UP();

  COMPARE(fmadd_s(f0, f1, f2, f3),
          "08118820       fmadd.s      f0, f1, f2, f3");
  COMPARE(fmadd_s(f4, f5, f6, f7),
          "081398a4       fmadd.s      f4, f5, f6, f7");

  COMPARE(fmadd_d(f8, f9, f10, f11),
          "0825a928       fmadd.d      f8, f9, f10, f11");
  COMPARE(fmadd_d(f12, f13, f14, f15),
          "0827b9ac       fmadd.d      f12, f13, f14, f15");

  COMPARE(fmsub_s(f0, f1, f2, f3),
          "08518820       fmsub.s      f0, f1, f2, f3");
  COMPARE(fmsub_s(f4, f5, f6, f7),
          "085398a4       fmsub.s      f4, f5, f6, f7");

  COMPARE(fmsub_d(f8, f9, f10, f11),
          "0865a928       fmsub.d      f8, f9, f10, f11");
  COMPARE(fmsub_d(f12, f13, f14, f15),
          "0867b9ac       fmsub.d      f12, f13, f14, f15");

  COMPARE(fnmadd_s(f0, f1, f2, f3),
          "08918820       fnmadd.s     f0, f1, f2, f3");
  COMPARE(fnmadd_s(f4, f5, f6, f7),
          "089398a4       fnmadd.s     f4, f5, f6, f7");

  COMPARE(fnmadd_d(f8, f9, f10, f11),
          "08a5a928       fnmadd.d     f8, f9, f10, f11");
  COMPARE(fnmadd_d(f12, f13, f14, f15),
          "08a7b9ac       fnmadd.d     f12, f13, f14, f15");

  COMPARE(fnmsub_s(f0, f1, f2, f3),
          "08d18820       fnmsub.s     f0, f1, f2, f3");
  COMPARE(fnmsub_s(f4, f5, f6, f7),
          "08d398a4       fnmsub.s     f4, f5, f6, f7");

  COMPARE(fnmsub_d(f8, f9, f10, f11),
          "08e5a928       fnmsub.d     f8, f9, f10, f11");
  COMPARE(fnmsub_d(f12, f13, f14, f15),
          "08e7b9ac       fnmsub.d     f12, f13, f14, f15");

  COMPARE(fcmp_cond_s(CAF, f1, f2, FCC0),
          "0c100820       fcmp.caf.s   fcc0, f1, f2");
  COMPARE(fcmp_cond_s(CUN, f5, f6, FCC0),
          "0c1418a0       fcmp.cun.s   fcc0, f5, f6");
  COMPARE(fcmp_cond_s(CEQ, f9, f10, FCC0),
          "0c122920       fcmp.ceq.s   fcc0, f9, f10");
  COMPARE(fcmp_cond_s(CUEQ, f13, f14, FCC0),
          "0c1639a0       fcmp.cueq.s  fcc0, f13, f14");

  COMPARE(fcmp_cond_s(CLT, f1, f2, FCC0),
          "0c110820       fcmp.clt.s   fcc0, f1, f2");
  COMPARE(fcmp_cond_s(CULT, f5, f6, FCC0),
          "0c1518a0       fcmp.cult.s  fcc0, f5, f6");
  COMPARE(fcmp_cond_s(CLE, f9, f10, FCC0),
          "0c132920       fcmp.cle.s   fcc0, f9, f10");
  COMPARE(fcmp_cond_s(CULE, f13, f14, FCC0),
          "0c1739a0       fcmp.cule.s  fcc0, f13, f14");

  COMPARE(fcmp_cond_s(CNE, f1, f2, FCC0),
          "0c180820       fcmp.cne.s   fcc0, f1, f2");
  COMPARE(fcmp_cond_s(COR, f5, f6, FCC0),
          "0c1a18a0       fcmp.cor.s   fcc0, f5, f6");
  COMPARE(fcmp_cond_s(CUNE, f9, f10, FCC0),
          "0c1c2920       fcmp.cune.s  fcc0, f9, f10");
  COMPARE(fcmp_cond_s(SAF, f13, f14, FCC0),
          "0c10b9a0       fcmp.saf.s   fcc0, f13, f14");

  COMPARE(fcmp_cond_s(SUN, f1, f2, FCC0),
          "0c148820       fcmp.sun.s   fcc0, f1, f2");
  COMPARE(fcmp_cond_s(SEQ, f5, f6, FCC0),
          "0c1298a0       fcmp.seq.s   fcc0, f5, f6");
  COMPARE(fcmp_cond_s(SUEQ, f9, f10, FCC0),
          "0c16a920       fcmp.sueq.s  fcc0, f9, f10");
  //  COMPARE(fcmp_cond_s(SLT, f13, f14, FCC0),
  //          "0c11b9a0       fcmp.slt.s   fcc0, f13, f14");

  COMPARE(fcmp_cond_s(SULT, f1, f2, FCC0),
          "0c158820       fcmp.sult.s  fcc0, f1, f2");
  COMPARE(fcmp_cond_s(SLE, f5, f6, FCC0),
          "0c1398a0       fcmp.sle.s   fcc0, f5, f6");
  COMPARE(fcmp_cond_s(SULE, f9, f10, FCC0),
          "0c17a920       fcmp.sule.s  fcc0, f9, f10");
  COMPARE(fcmp_cond_s(SNE, f13, f14, FCC0),
          "0c18b9a0       fcmp.sne.s   fcc0, f13, f14");
  COMPARE(fcmp_cond_s(SOR, f13, f14, FCC0),
          "0c1ab9a0       fcmp.sor.s   fcc0, f13, f14");
  COMPARE(fcmp_cond_s(SUNE, f1, f2, FCC0),
          "0c1c8820       fcmp.sune.s  fcc0, f1, f2");

  COMPARE(fcmp_cond_d(CAF, f1, f2, FCC0),
          "0c200820       fcmp.caf.d   fcc0, f1, f2");
  COMPARE(fcmp_cond_d(CUN, f5, f6, FCC0),
          "0c2418a0       fcmp.cun.d   fcc0, f5, f6");
  COMPARE(fcmp_cond_d(CEQ, f9, f10, FCC0),
          "0c222920       fcmp.ceq.d   fcc0, f9, f10");
  COMPARE(fcmp_cond_d(CUEQ, f13, f14, FCC0),
          "0c2639a0       fcmp.cueq.d  fcc0, f13, f14");

  COMPARE(fcmp_cond_d(CLT, f1, f2, FCC0),
          "0c210820       fcmp.clt.d   fcc0, f1, f2");
  COMPARE(fcmp_cond_d(CULT, f5, f6, FCC0),
          "0c2518a0       fcmp.cult.d  fcc0, f5, f6");
  COMPARE(fcmp_cond_d(CLE, f9, f10, FCC0),
          "0c232920       fcmp.cle.d   fcc0, f9, f10");
  COMPARE(fcmp_cond_d(CULE, f13, f14, FCC0),
          "0c2739a0       fcmp.cule.d  fcc0, f13, f14");

  COMPARE(fcmp_cond_d(CNE, f1, f2, FCC0),
          "0c280820       fcmp.cne.d   fcc0, f1, f2");
  COMPARE(fcmp_cond_d(COR, f5, f6, FCC0),
          "0c2a18a0       fcmp.cor.d   fcc0, f5, f6");
  COMPARE(fcmp_cond_d(CUNE, f9, f10, FCC0),
          "0c2c2920       fcmp.cune.d  fcc0, f9, f10");
  COMPARE(fcmp_cond_d(SAF, f13, f14, FCC0),
          "0c20b9a0       fcmp.saf.d   fcc0, f13, f14");

  COMPARE(fcmp_cond_d(SUN, f1, f2, FCC0),
          "0c248820       fcmp.sun.d   fcc0, f1, f2");
  COMPARE(fcmp_cond_d(SEQ, f5, f6, FCC0),
          "0c2298a0       fcmp.seq.d   fcc0, f5, f6");
  COMPARE(fcmp_cond_d(SUEQ, f9, f10, FCC0),
          "0c26a920       fcmp.sueq.d  fcc0, f9, f10");
  //  COMPARE(fcmp_cond_d(SLT, f13, f14, FCC0),
  //          "0c21b9a0       fcmp.slt.d   fcc0, f13, f14");

  COMPARE(fcmp_cond_d(SULT, f1, f2, FCC0),
          "0c258820       fcmp.sult.d  fcc0, f1, f2");
  COMPARE(fcmp_cond_d(SLE, f5, f6, FCC0),
          "0c2398a0       fcmp.sle.d   fcc0, f5, f6");
  COMPARE(fcmp_cond_d(SULE, f9, f10, FCC0),
          "0c27a920       fcmp.sule.d  fcc0, f9, f10");
  COMPARE(fcmp_cond_d(SNE, f13, f14, FCC0),
          "0c28b9a0       fcmp.sne.d   fcc0, f13, f14");
  COMPARE(fcmp_cond_d(SOR, f13, f14, FCC0),
          "0c2ab9a0       fcmp.sor.d   fcc0, f13, f14");
  COMPARE(fcmp_cond_d(SUNE, f1, f2, FCC0),
          "0c2c8820       fcmp.sune.d  fcc0, f1, f2");

  VERIFY_RUN();
}

TEST_F(DisasmLoong64Test, TypeOp14) {
  SET_UP();

  COMPARE(alsl_w(a0, a1, a2, 1), "000418a4       alsl.w       a0, a1, a2, 1");
  COMPARE(alsl_w(a3, a4, a5, 3), "00052507       alsl.w       a3, a4, a5, 3");
  COMPARE(alsl_w(a6, a7, t0, 4), "0005b16a       alsl.w       a6, a7, t0, 4");

  COMPARE(alsl_wu(t1, t2, t3, 1), "00063dcd       alsl.wu      t1, t2, t3, 1");
  COMPARE(alsl_wu(t4, t5, t6, 3), "00074a30       alsl.wu      t4, t5, t6, 3");
  COMPARE(alsl_wu(a0, a1, a2, 4), "000798a4       alsl.wu      a0, a1, a2, 4");

  COMPARE(alsl_d(a3, a4, a5, 1), "002c2507       alsl.d       a3, a4, a5, 1");
  COMPARE(alsl_d(a6, a7, t0, 3), "002d316a       alsl.d       a6, a7, t0, 3");
  COMPARE(alsl_d(t1, t2, t3, 4), "002dbdcd       alsl.d       t1, t2, t3, 4");

  COMPARE(bytepick_w(t4, t5, t6, 0),
          "00084a30       bytepick.w   t4, t5, t6, 0");
  COMPARE(bytepick_w(a0, a1, a2, 3),
          "000998a4       bytepick.w   a0, a1, a2, 3");

  COMPARE(bytepick_d(a6, a7, t0, 0),
          "000c316a       bytepick.d   a6, a7, t0, 0");
  COMPARE(bytepick_d(t4, t5, t6, 7),
          "000fca30       bytepick.d   t4, t5, t6, 7");

  COMPARE(slli_w(a3, a3, 31), "0040fce7       slli.w       a3, a3, 31");
  COMPARE(slli_w(a6, a6, 1), "0040854a       slli.w       a6, a6, 1");

  COMPARE(slli_d(t3, t2, 63), "0041fdcf       slli.d       t3, t2, 63");
  COMPARE(slli_d(t4, a6, 1), "00410550       slli.d       t4, a6, 1");

  COMPARE(srli_w(a7, a7, 31), "0044fd6b       srli.w       a7, a7, 31");
  COMPARE(srli_w(a4, a4, 1), "00448508       srli.w       a4, a4, 1");

  COMPARE(srli_d(a4, a3, 63), "0045fce8       srli.d       a4, a3, 63");
  COMPARE(srli_d(a4, a4, 1), "00450508       srli.d       a4, a4, 1");

  COMPARE(srai_d(a0, a0, 63), "0049fc84       srai.d       a0, a0, 63");
  COMPARE(srai_d(a4, a1, 1), "004904a8       srai.d       a4, a1, 1");

  COMPARE(srai_w(s4, a3, 31), "0048fcfb       srai.w       s4, a3, 31");
  COMPARE(srai_w(s4, a5, 1), "0048853b       srai.w       s4, a5, 1");

  COMPARE(rotri_d(t7, t6, 1), "004d0653       rotri.d      t7, t6, 1");

  VERIFY_RUN();
}

TEST_F(DisasmLoong64Test, TypeOp17) {
  SET_UP();

  COMPARE(sltu(t5, t4, a4), "0012a211       sltu         t5, t4, a4");
  COMPARE(sltu(t4, zero_reg, t4),
          "0012c010       sltu         t4, zero_reg, t4");

  COMPARE(add_w(a4, a4, a6), "00102908       add.w        a4, a4, a6");
  COMPARE(add_w(a5, a6, t3), "00103d49       add.w        a5, a6, t3");

  COMPARE(add_d(a4, t0, t1), "0010b588       add.d        a4, t0, t1");
  COMPARE(add_d(a6, a3, t1), "0010b4ea       add.d        a6, a3, t1");

  COMPARE(sub_w(a7, a7, a2), "0011196b       sub.w        a7, a7, a2");
  COMPARE(sub_w(a2, a2, s3), "001168c6       sub.w        a2, a2, s3");

  COMPARE(sub_d(s3, ra, s3), "0011e83a       sub.d        s3, ra, s3");
  COMPARE(sub_d(a0, a1, a2), "001198a4       sub.d        a0, a1, a2");

  COMPARE(slt(a5, a5, a6), "00122929       slt          a5, a5, a6");
  COMPARE(slt(a6, t3, t4), "001241ea       slt          a6, t3, t4");

  COMPARE(maskeqz(a6, a7, t0), "0013316a       maskeqz      a6, a7, t0");
  COMPARE(maskeqz(t1, t2, t3), "00133dcd       maskeqz      t1, t2, t3");

  COMPARE(masknez(a5, a5, a3), "00139d29       masknez      a5, a5, a3");
  COMPARE(masknez(a3, a4, a5), "0013a507       masknez      a3, a4, a5");

  COMPARE(or_(s3, sp, zero_reg),
          "0015007a       or           s3, sp, zero_reg");
  COMPARE(or_(a4, a0, zero_reg),
          "00150088       or           a4, a0, zero_reg");

  COMPARE(and_(sp, sp, t6), "0014c863       and          sp, sp, t6");
  COMPARE(and_(a3, a3, a7), "0014ace7       and          a3, a3, a7");

  COMPARE(nor(a7, a7, a7), "00142d6b       nor          a7, a7, a7");
  COMPARE(nor(t4, t5, t6), "00144a30       nor          t4, t5, t6");

  COMPARE(xor_(a0, a1, a2), "001598a4       xor          a0, a1, a2");
  COMPARE(xor_(a3, a4, a5), "0015a507       xor          a3, a4, a5");

  COMPARE(orn(a6, a7, t0), "0016316a       orn          a6, a7, t0");
  COMPARE(orn(t1, t2, t3), "00163dcd       orn          t1, t2, t3");

  COMPARE(andn(t4, t5, t6), "0016ca30       andn         t4, t5, t6");
  COMPARE(andn(a0, a1, a2), "001698a4       andn         a0, a1, a2");

  COMPARE(sll_w(a3, t0, a7), "00172d87       sll.w        a3, t0, a7");
  COMPARE(sll_w(a3, a4, a3), "00171d07       sll.w        a3, a4, a3");

  COMPARE(srl_w(a3, a4, a3), "00179d07       srl.w        a3, a4, a3");
  COMPARE(srl_w(a3, t1, t4), "0017c1a7       srl.w        a3, t1, t4");

  COMPARE(sra_w(a4, t4, a4), "00182208       sra.w        a4, t4, a4");
  COMPARE(sra_w(a3, t1, a6), "001829a7       sra.w        a3, t1, a6");

  COMPARE(sll_d(a3, a1, a3), "00189ca7       sll.d        a3, a1, a3");
  COMPARE(sll_d(a7, a4, t0), "0018b10b       sll.d        a7, a4, t0");

  COMPARE(srl_d(a7, a7, t0), "0019316b       srl.d        a7, a7, t0");
  COMPARE(srl_d(t0, a6, t0), "0019314c       srl.d        t0, a6, t0");

  COMPARE(sra_d(a3, a4, a5), "0019a507       sra.d        a3, a4, a5");
  COMPARE(sra_d(a6, a7, t0), "0019b16a       sra.d        a6, a7, t0");

  COMPARE(rotr_d(t1, t2, t3), "001bbdcd       rotr.d       t1, t2, t3");
  COMPARE(rotr_d(t4, t5, t6), "001bca30       rotr.d       t4, t5, t6");

  COMPARE(rotr_w(a0, a1, a2), "001b18a4       rotr.w       a0, a1, a2");
  COMPARE(rotr_w(a3, a4, a5), "001b2507       rotr.w       a3, a4, a5");

  COMPARE(mul_w(t8, a5, t7), "001c4d34       mul.w        t8, a5, t7");
  COMPARE(mul_w(t4, t5, t6), "001c4a30       mul.w        t4, t5, t6");

  COMPARE(mulh_w(s3, a3, t7), "001cccfa       mulh.w       s3, a3, t7");
  COMPARE(mulh_w(a0, a1, a2), "001c98a4       mulh.w       a0, a1, a2");

  COMPARE(mulh_wu(a6, a7, t0), "001d316a       mulh.wu      a6, a7, t0");
  COMPARE(mulh_wu(t1, t2, t3), "001d3dcd       mulh.wu      t1, t2, t3");

  COMPARE(mul_d(t2, a5, t1), "001db52e       mul.d        t2, a5, t1");
  COMPARE(mul_d(a4, a4, a5), "001da508       mul.d        a4, a4, a5");

  COMPARE(mulh_d(a3, a4, a5), "001e2507       mulh.d       a3, a4, a5");
  COMPARE(mulh_d(a6, a7, t0), "001e316a       mulh.d       a6, a7, t0");

  COMPARE(mulh_du(t1, t2, t3), "001ebdcd       mulh.du      t1, t2, t3");
  COMPARE(mulh_du(t4, t5, t6), "001eca30       mulh.du      t4, t5, t6");

  COMPARE(mulw_d_w(a0, a1, a2), "001f18a4       mulw.d.w     a0, a1, a2");
  COMPARE(mulw_d_w(a3, a4, a5), "001f2507       mulw.d.w     a3, a4, a5");

  COMPARE(mulw_d_wu(a6, a7, t0), "001fb16a       mulw.d.wu    a6, a7, t0");
  COMPARE(mulw_d_wu(t1, t2, t3), "001fbdcd       mulw.d.wu    t1, t2, t3");

  COMPARE(div_w(a5, a5, a3), "00201d29       div.w        a5, a5, a3");
  COMPARE(div_w(t4, t5, t6), "00204a30       div.w        t4, t5, t6");

  COMPARE(mod_w(a6, t3, a6), "0020a9ea       mod.w        a6, t3, a6");
  COMPARE(mod_w(a3, a4, a3), "00209d07       mod.w        a3, a4, a3");

  COMPARE(div_wu(t1, t2, t3), "00213dcd       div.wu       t1, t2, t3");
  COMPARE(div_wu(t4, t5, t6), "00214a30       div.wu       t4, t5, t6");

  COMPARE(mod_wu(a0, a1, a2), "002198a4       mod.wu       a0, a1, a2");
  COMPARE(mod_wu(a3, a4, a5), "0021a507       mod.wu       a3, a4, a5");

  COMPARE(div_d(t0, t0, a6), "0022298c       div.d        t0, t0, a6");
  COMPARE(div_d(a7, a7, a5), "0022256b       div.d        a7, a7, a5");

  COMPARE(mod_d(a6, a7, t0), "0022b16a       mod.d        a6, a7, t0");
  COMPARE(mod_d(t1, t2, t3), "0022bdcd       mod.d        t1, t2, t3");

  COMPARE(div_du(t4, t5, t6), "00234a30       div.du       t4, t5, t6");
  COMPARE(div_du(a0, a1, a2), "002318a4       div.du       a0, a1, a2");

  COMPARE(mod_du(a3, a4, a5), "0023a507       mod.du       a3, a4, a5");
  COMPARE(mod_du(a6, a7, t0), "0023b16a       mod.du       a6, a7, t0");

  COMPARE(fadd_s(f3, f4, f5), "01009483       fadd.s       f3, f4, f5");
  COMPARE(fadd_s(f6, f7, f8), "0100a0e6       fadd.s       f6, f7, f8");

  COMPARE(fadd_d(f0, f1, f0), "01010020       fadd.d       f0, f1, f0");
  COMPARE(fadd_d(f0, f1, f2), "01010820       fadd.d       f0, f1, f2");

  COMPARE(fsub_s(f9, f10, f11), "0102ad49       fsub.s       f9, f10, f11");
  COMPARE(fsub_s(f12, f13, f14), "0102b9ac       fsub.s       f12, f13, f14");

  COMPARE(fsub_d(f30, f0, f30), "0103781e       fsub.d       f30, f0, f30");
  COMPARE(fsub_d(f0, f0, f1), "01030400       fsub.d       f0, f0, f1");

  COMPARE(fmul_s(f15, f16, f17), "0104c60f       fmul.s       f15, f16, f17");
  COMPARE(fmul_s(f18, f19, f20), "0104d272       fmul.s       f18, f19, f20");

  COMPARE(fmul_d(f0, f0, f1), "01050400       fmul.d       f0, f0, f1");
  COMPARE(fmul_d(f0, f0, f0), "01050000       fmul.d       f0, f0, f0");

  COMPARE(fdiv_s(f0, f1, f2), "01068820       fdiv.s       f0, f1, f2");
  COMPARE(fdiv_s(f3, f4, f5), "01069483       fdiv.s       f3, f4, f5");

  COMPARE(fdiv_d(f0, f0, f1), "01070400       fdiv.d       f0, f0, f1");
  COMPARE(fdiv_d(f0, f1, f0), "01070020       fdiv.d       f0, f1, f0");

  COMPARE(fmax_s(f9, f10, f11), "0108ad49       fmax.s       f9, f10, f11");
  COMPARE(fmin_s(f6, f7, f8), "010aa0e6       fmin.s       f6, f7, f8");

  COMPARE(fmax_d(f0, f1, f0), "01090020       fmax.d       f0, f1, f0");
  COMPARE(fmin_d(f0, f1, f0), "010b0020       fmin.d       f0, f1, f0");

  COMPARE(fmaxa_s(f12, f13, f14), "010cb9ac
```