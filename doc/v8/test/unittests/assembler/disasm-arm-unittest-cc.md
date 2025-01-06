Response:
Let's break down the thought process for analyzing this V8 disassembler unittest code.

1. **Understand the Core Purpose:** The filename `disasm-arm-unittest.cc` immediately suggests this code is about testing the ARM disassembler in V8. "Unittest" further confirms this. The "disasm" part is key: it takes machine code (binary instructions) and converts it into a human-readable assembly language representation.

2. **Identify Key Components:** Scan the `#include` directives. These are the building blocks the code uses:
    * `<cinttypes>`, `<cstdlib>`: Standard C/C++ utilities.
    * `<regex>`: Regular expression support (important for flexible testing).
    * V8 headers (`src/...`): These point to V8's internal components, crucial for the disassembler functionality. Look for keywords like `assembler`, `disassembler`, `codegen`.
    * `"test/unittests/test-utils.h"`, `"testing/gtest/include/gtest/gtest.h"`: Indicate this is a Google Test-based unit test.

3. **Analyze the `DisassembleAndCompare` Function:** This function seems central to the testing process. Examine its steps:
    * Takes a `begin` pointer to the instruction bytes.
    * Takes `use_regex` to decide how to compare.
    * Takes a variable number of `expected_strings`.
    * Creates a `disasm::Disassembler`.
    * Iterates through the bytes, disassembling each instruction.
    * Compares the disassembled output with the `expected_strings`, either using direct string comparison or regular expressions.
    * Prints error messages if discrepancies are found.
    * Returns `true` if all comparisons pass, `false` otherwise.

4. **Examine the Macros (`SET_UP`, `BASE_COMPARE`, `COMPARE`, `COMPARE_REGEX`, `EMIT_PENDING_LITERALS`, `VERIFY_RUN`):** Macros are code shortcuts. Understand their purpose:
    * `SET_UP`:  Initializes the testing environment (creates an `Isolate`, allocates memory for the instruction buffer, creates an `Assembler`). This is boilerplate for each test case.
    * `BASE_COMPARE`: The core comparison macro. It takes an assembler operation (`asm_`) and expected strings. It executes the assembler instruction, then calls `DisassembleAndCompare`.
    * `COMPARE`:  A wrapper around `BASE_COMPARE` for simple string comparison.
    * `COMPARE_REGEX`: A wrapper around `BASE_COMPARE` for regular expression comparison. This is powerful for handling variations in output (e.g., whitespace).
    * `EMIT_PENDING_LITERALS`: Forces the assembler to generate any literals that are waiting. This is important for ensuring the disassembler sees the correct instructions in the right order.
    * `VERIFY_RUN`: Checks the `failure` flag and reports a fatal error if any test failed.

5. **Study the Test Cases (`TEST_F(DisasmArmTest, ...)`):**  These are the individual tests. Observe the patterns:
    * Each test case sets up the environment using `SET_UP()`.
    * Each test case uses `COMPARE` (or `COMPARE_REGEX`) to assemble an instruction and compare the disassembled output.
    * The arguments to `COMPARE` are typically:
        * An assembler instruction call (e.g., `and_(r0, r1, Operand(r2))`).
        * One or more strings representing the expected disassembled output.
    * `VERIFY_RUN()` is called at the end of each test case to check for failures.
    * Some tests have conditional execution based on CPU features (`if (CpuFeatures::IsSupported(ARMv7))`).

6. **Infer Functionality from Test Cases:** By looking at the instructions being tested and the expected output, you can infer what the disassembler needs to handle:
    * Different ARM instruction types (arithmetic, logical, data transfer, control flow).
    * Different operand types (registers, immediate values, shifted registers).
    * Different conditional codes.
    * VFP (Vector Floating Point) instructions.
    * MSR/MRS (Move to/from System Register) instructions.
    * Handling of instruction variants and encodings.
    * The use of regular expressions suggests the disassembler output might have some flexibility (e.g., spacing).

7. **Connect to JavaScript (If Applicable):**  While this specific code is low-level C++, the *purpose* is to support V8's JavaScript execution. The assembler and disassembler are used internally by V8 to:
    * Generate machine code from the JavaScript bytecode.
    * Potentially for debugging and profiling. Being able to disassemble the generated code is crucial for understanding how the JavaScript is being executed at the machine level.

8. **Consider Edge Cases and Common Errors:** The thoroughness of the tests (covering many instructions and variations) indicates an effort to catch potential bugs in the disassembler. Think about common mistakes in disassembler implementation:
    * Incorrectly decoding instruction bits.
    * Misinterpreting operand types.
    * Not handling all instruction variants.
    * Incorrect formatting of the output.

9. **Synthesize and Summarize:**  Combine all the observations to create a concise summary of the code's functionality, like the example provided in the prompt's answer.

Essentially, it's a process of deduction, starting with the high-level purpose and drilling down into the details of the code's structure and the specific tests being performed. Understanding the context (V8, ARM architecture, unit testing) is crucial.
```cpp
// Copyright 2011 the V8 project authors. All rights reserved.
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

#include <cinttypes>
#include <cstdlib>

// The C++ style guide recommends using <re2> instead of <regex>. However, the
// former isn't available in V8.
#include <regex>  // NOLINT(build/c++11)

#include "src/base/numbers/double.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/debug/debug.h"
#include "src/diagnostics/disasm.h"
#include "src/diagnostics/disassembler.h"
#include "src/execution/frames-inl.h"
#include "src/init/v8.h"
#include "src/objects/objects-inl.h"
#include "src/utils/boxed-float.h"
#include "test/unittests/test-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {
namespace internal {

using DisasmArmTest = TestWithIsolate;

enum UseRegex { kRawString, kRegexString };

template <typename... S>
bool DisassembleAndCompare(uint8_t* begin, UseRegex use_regex,
                           S... expected_strings) {
  disasm::NameConverter converter;
  disasm::Disassembler disasm(converter);
  base::EmbeddedVector<char, 128> buffer;

  std::vector<std::string> expected_disassembly = {expected_strings...};
  size_t n_expected = expected_disassembly.size();
  uint8_t* end = begin + (n_expected * kInstrSize);

  std::vector<std::string> disassembly;
  for (uint8_t* pc = begin; pc < end;) {
    pc += disasm.InstructionDecode(buffer, pc);
    disassembly.emplace_back(buffer.begin());
  }

  bool test_passed = true;

  for (size_t i = 0; i < disassembly.size(); i++) {
    if (use_regex == kRawString) {
      if (expected_disassembly[i] != disassembly[i]) {
        fprintf(stderr,
                "expected: \n"
                "%s\n"
                "disassembled: \n"
                "%s\n\n",
                expected_disassembly[i].c_str(), disassembly[i].c_str());
        test_passed = false;
      }
    } else {
      DCHECK_EQ(use_regex, kRegexString);
      if (!std::regex_match(disassembly[i],
                            std::regex(expected_disassembly[i]))) {
        fprintf(stderr,
                "expected (regex): \n"
                "%s\n"
                "disassembled: \n"
                "%s\n\n",
                expected_disassembly[i].c_str(), disassembly[i].c_str());
        test_passed = false;
      }
    }
  }

  // Fail after printing expected disassembly if we expected a different number
  // of instructions.
  if (disassembly.size() != expected_disassembly.size()) {
    return false;
  }

  return test_passed;
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
#define BASE_COMPARE(asm_, use_regex, ...)                             \
  {                                                                    \
    int pc_offset = assm.pc_offset();                                  \
    uint8_t* progcounter = &buffer[pc_offset];                         \
    assm.asm_;                                                         \
    if (!DisassembleAndCompare(progcounter, use_regex, __VA_ARGS__)) { \
      failure = true;                                                  \
    }                                                                  \
  }

#define COMPARE(asm_, ...) BASE_COMPARE(asm_, kRawString, __VA_ARGS__)

#define COMPARE_REGEX(asm_, ...) BASE_COMPARE(asm_, kRegexString, __VA_ARGS__)

// Force emission of any pending literals into a pool.
#define EMIT_PENDING_LITERALS() assm.CheckConstPool(true, false)

// Verify that all invocations of the COMPARE macro passed successfully.
// Exit with a failure if at least one of the tests failed.
#define VERIFY_RUN()                           \
  if (failure) {                               \
    FATAL("ARM Disassembler tests failed.\n"); \
  }

// clang-format off

TEST_F(DisasmArmTest, Type0) {
  SET_UP();

  COMPARE(and_(r0, r1, Operand(r2)),
          "e0010002       and r0, r1, r2");
  COMPARE(and_(r1, r2, Operand(r3), LeaveCC),
          "e0021003       and r1, r2, r3");
  COMPARE(and_(r2, r3, Operand(r4), SetCC),
          "e0132004       ands r2, r3, r4");
  COMPARE(and_(r3, r4, Operand(r5), LeaveCC, eq),
          "00043005       andeq r3, r4, r5");

  COMPARE(eor(r4, r5, Operand(r6, LSL, 0)),
          "e0254006       eor r4, r5, r6");
  COMPARE(eor(r4, r5, Operand(r7, LSL, 1), SetCC),
          "e0354087       eors r4, r5, r7, lsl #1");
  COMPARE(eor(r4, r5, Operand(r8, LSL, 2), LeaveCC, ne),
          "10254108       eorne r4, r5, r8, lsl #2");
  COMPARE(eor(r4, r5, Operand(r9, LSL, 3), SetCC, cs),
          "20354189       eorcss r4, r5, r9, lsl #3");

  COMPARE(sub(r5, r6, Operand(r10, LSL, 31), LeaveCC, hs),
          "20465f8a       subcs r5, r6, r10, lsl #31");
  COMPARE(sub(r5, r6, Operand(r10, LSL, 30), SetCC, cc),
          "30565f0a       subccs r5, r6, r10, lsl #30");
  COMPARE(sub(r5, r6, Operand(r10, LSL, 24), LeaveCC, lo),
          "30465c0a       subcc r5, r6, r10, lsl #24");
  COMPARE(sub(r5, r6, Operand(r10, LSL, 16), SetCC, mi),
          "4056580a       submis r5, r6, r10, lsl #16");

  COMPARE(rsb(r6, r7, Operand(fp)),
          "e067600b       rsb r6, r7, fp");
  COMPARE(rsb(r6, r7, Operand(fp, LSR, 1)),
          "e06760ab       rsb r6, r7, fp, lsr #1");
  COMPARE(rsb(r6, r7, Operand(fp, LSR, 0), SetCC),
          "e077602b       rsbs r6, r7, fp, lsr #32");
  COMPARE(rsb(r6, r7, Operand(fp, LSR, 31), LeaveCC, pl),
          "50676fab       rsbpl r6, r7, fp, lsr #31");

  COMPARE(add(r7, r8, Operand(ip, ASR, 1)),
          "e08870cc       add r7, r8, ip, asr #1");
  COMPARE(add(r7, r8, Operand(ip, ASR, 0)),
          "e088704c       add r7, r8, ip, asr #32");
  COMPARE(add(r7, r8, Operand(ip), SetCC),
          "e098700c       adds r7, r8, ip");
  COMPARE(add(r7, r8, Operand(ip, ASR, 31), SetCC, vs),
          "60987fcc       addvss r7, r8, ip, asr #31");

  COMPARE(adc(r7, fp, Operand(ip, ASR, 5)),
          "e0ab72cc       adc r7, fp, ip, asr #5");
  COMPARE(adc(r4, ip, Operand(ip, ASR, 1), LeaveCC, vc),
          "70ac40cc       adcvc r4, ip, ip, asr #1");
  COMPARE(adc(r5, sp, Operand(ip), SetCC),
          "e0bd500c       adcs r5, sp, ip");
  COMPARE(adc(r8, lr, Operand(ip, ASR, 31), SetCC, vc),
          "70be8fcc       adcvcs r8, lr, ip, asr #31");

  COMPARE(sbc(r7, r1, Operand(ip, ROR, 1), LeaveCC, hi),
          "80c170ec       sbchi r7, r1, ip, ror #1");
  COMPARE(sbc(r7, r9, Operand(ip, ROR, 4)),
          "e0c9726c       sbc r7, r9, ip, ror #4");
  COMPARE(sbc(r7, r10, Operand(ip), SetCC),
          "e0da700c       sbcs r7, r10, ip");
  COMPARE(sbc(r7, ip, Operand(ip, ROR, 31), SetCC, hi),
          "80dc7fec       sbchis r7, ip, ip, ror #31");

  COMPARE(rsc(r7, r8, Operand(ip, LSL, r0)),
          "e0e8701c       rsc r7, r8, ip, lsl r0");
  COMPARE(rsc(r7, r8, Operand(ip, LSL, r1)),
          "e0e8711c       rsc r7, r8, ip, lsl r1");
  COMPARE(rsc(r7, r8, Operand(ip), SetCC),
          "e0f8700c       rscs r7, r8, ip");
  COMPARE(rsc(r7, r8, Operand(ip, LSL, r3), SetCC, ls),
          "90f8731c       rsclss r7, r8, ip, lsl r3");

  COMPARE(tst(r7, Operand(r5, ASR, ip), ge),
          "a1170c55       tstge r7, r5, asr ip");
  COMPARE(tst(r7, Operand(r6, ASR, sp)),
          "e1170d56       tst r7, r6, asr sp");
  COMPARE(tst(r7, Operand(r7), ge),
          "a1170007       tstge r7, r7");
  COMPARE(tst(r7, Operand(r8, ASR, fp), ge),
          "a1170b58       tstge r7, r8, asr fp");

  COMPARE(teq(r7, Operand(r5, ROR, r0), lt),
          "b1370075       teqlt r7, r5, ror r0");
  COMPARE(teq(r7, Operand(r6, ROR, lr)),
          "e1370e76       teq r7, r6, ror lr");
  COMPARE(teq(r7, Operand(r7), lt),
          "b1370007       teqlt r7, r7");
  COMPARE(teq(r7, Operand(r8, ROR, r1)),
          "e1370178       teq r7, r8, ror r1");

  COMPARE(cmp(r7, Operand(r4)),
          "e1570004       cmp r7, r4");
  COMPARE(cmp(r7, Operand(r6, LSL, 1), gt),
          "c1570086       cmpgt r7, r6, lsl #1");
  COMPARE(cmp(r7, Operand(r8, LSR, 3), gt),
          "c15701a8       cmpgt r7, r8, lsr #3");
  COMPARE(cmp(r7, Operand(r8, ASR, 19)),
          "e15709c8       cmp r7, r8, asr #19");

  COMPARE(cmn(r0, Operand(r4)),
          "e1700004       cmn r0, r4");
  COMPARE(cmn(r1, Operand(r6, ROR, 1)),
          "e17100e6       cmn r1, r6, ror #1");
  COMPARE(cmn(r2, Operand(r8)),
          "e1720008       cmn r2, r8");
  COMPARE(cmn(r3, Operand(fp), le),
          "d173000b       cmnle r3, fp");

  COMPARE(orr(r7, r8, Operand(lr), LeaveCC, al),
          "e188700e       orr r7, r8, lr");
  COMPARE(orr(r7, r8, Operand(fp)),
          "e188700b       orr r7, r8, fp");
  COMPARE(orr(r7, r8, Operand(sp), SetCC),
          "e198700d       orrs r7, r8, sp");
  COMPARE(orr(r7, r8, Operand(ip), SetCC, al),
          "e198700c       orrs r7, r8, ip");

  COMPARE(mov(r0, Operand(r1), LeaveCC, eq),
          "01a00001       moveq r0, r1");
  COMPARE(mov(r0, Operand(r2)),
          "e1a00002       mov r0, r2");
  COMPARE(mov(r0, Operand(r3), SetCC),
          "e1b00003       movs r0, r3");
  COMPARE(mov(r0, Operand(r4), SetCC, pl),
          "51b00004       movpls r0, r4");

  COMPARE(bic(r0, lr, Operand(r1), LeaveCC, vs),
          "61ce0001       bicvs r0, lr, r1");
  COMPARE(bic(r0, r9, Operand(r2), LeaveCC, vc),
          "71c90002       bicvc r0, r9, r2");
  COMPARE(bic(r0, r5, Operand(r3), SetCC),
          "e1d50003       bics r0, r5, r3");
  COMPARE(bic(r0, r1, Operand(r4), SetCC, pl),
          "51d10004       bicpls r0, r1, r4");

  COMPARE(mvn(r10, Operand(r1)),
          "e1e0a001       mvn r10, r1");
  COMPARE(mvn(r9, Operand(r2)),
          "e1e09002       mvn r9, r2");
  COMPARE(mvn(r0, Operand(r3), SetCC),
          "e1f00003       mvns r0, r3");
  COMPARE(mvn(r5, Operand(r4), SetCC, cc),
          "31f05004       mvnccs r5, r4");

  // Instructions autotransformed by the assembler.
  // mov -> mvn.
  COMPARE(mov(r3, Operand(-1), LeaveCC, al),
          "e3e03000       mvn r3, #0");
  COMPARE(mov(r4, Operand(-2), SetCC, al),
          "e3f04001       mvns r4, #1");
  COMPARE(mov(r5, Operand(0x0FFFFFF0), SetCC, ne),
          "13f052ff       mvnnes r5, #-268435441");
  COMPARE(mov(r6, Operand(-1), LeaveCC, ne),
          "13e06000       mvnne r6, #0");

  // mvn -> mov.
  COMPARE(mvn(r3, Operand(-1), LeaveCC, al),
          "e3a03000       mov r3, #0");
  COMPARE(mvn(r4, Operand(-2), SetCC, al),
          "e3b04001       movs r4, #1");
  COMPARE(mvn(r5, Operand(0x0FFFFFF0), SetCC, ne),
          "13b052ff       movnes r5, #-268435441");
  COMPARE(mvn(r6, Operand(-1), LeaveCC, ne),
          "13a06000       movne r6, #0");

  // mov -> movw.
  if (CpuFeatures::IsSupported(ARMv7)) {
    COMPARE(mov(r5, Operand(0x01234), LeaveCC, ne),
            "13015234       movwne r5, #4660");
    COMPARE(eor(r5, r4, Operand(0x1234), LeaveCC, ne),
            "13015234       movwne r5, #4660",
            "10245005       eorne r5, r4, r5");
    // Movw can't do setcc, so first move to r5, then the following instruction
    // sets the flags. Mov immediate with setcc is pretty strange anyway.
    COMPARE(mov(r5, Operand(0x01234), SetCC, ne),
            "13015234       movwne r5, #4660",
            "11b05005       movnes r5, r5");
    // Emit a literal pool now, otherwise this could be dumped later, in the
    // middle of a different test.
    EMIT_PENDING_LITERALS();

    // The eor does the setcc so we get a movw here.
    COMPARE(eor(r5, r4, Operand(0x1234), SetCC, ne),
            "13015234       movwne r5, #4660",
            "10345005       eornes r5, r4, r5");

    COMPARE(movt(r5, 0x4321, ne),
            "13445321       movtne r5, #17185");
    COMPARE(movw(r5, 0xABCD, eq),
            "030a5bcd       movweq r5, #43981");
  }

  // Eor doesn't have an eor-negative variant, but we can do an mvn followed by
  // an eor to get the same effect.
  COMPARE(eor(r5, r4, Operand(0xFFFFFF34), SetCC, ne),
          "13e050cb       mvnne r5, #203",
          "10345005       eornes r5, r4, r5");

  // and <-> bic.
  COMPARE(and_(r3, r5, Operand(0xFC03FFFF)),
          "e3c537ff       bic r3, r5, #66846720");
  COMPARE(bic(r3, r5, Operand(0xFC03FFFF)),
          "e20537ff       and r3, r5, #66846720");

  // sub <-> add.
  COMPARE(add(r3, r5, Operand(-1024)),
          "e2453b01       sub r3, r5, #1024");
  COMPARE(sub(r3, r5, Operand(-1024)),
          "e2853b01       add r3, r5, #1024");

  // cmp <-> cmn.
  COMPARE(cmp(r3, Operand(-1024)),
          "e3730b01       cmn r3, #1024");
  COMPARE(cmn(r3, Operand(-1024)),
          "e3530b01       cmp r3, #1024");

  // Miscellaneous instructions encoded as type 0.
  COMPARE(blx(ip),
          "e12fff3c       blx ip");
  COMPARE(bkpt(0),
          "e1200070       bkpt 0");
  COMPARE(bkpt(0xFFFF),
          "e12fff7f       bkpt 65535");
  COMPARE(clz(r6, r7),
          "e16f6f17       clz r6, r7");

  VERIFY_RUN();
}
```

### 功能归纳

`v8/test/unittests/assembler/disasm-arm-unittest.cc` 的主要功能是 **测试 V8 JavaScript 引擎中 ARM 架构的反汇编器 (disassembler) 的正确性**。

具体来说，它通过以下步骤来完成这个功能：

1. **生成 ARM 机器码:** 使用 V8 的汇编器 (assembler) 功能，以编程方式生成各种 ARM 指令的机器码。
2. **反汇编机器码:** 使用 V8 的反汇编器将生成的机器码转换回人类可读的 ARM 汇编指令。
3. **比较反汇编结果:** 将反汇编器生成的汇编指令字符串与预期的正确汇编指令字符串进行比较。
4. **使用正则表达式进行灵活匹配:** 允许使用正则表达式来匹配反汇编结果，这在某些情况下可以更灵活地处理输出格式的细微差异。
5. **组织成单元测试:** 使用 Google Test 框架将这些测试组织成一个个独立的单元测试用例，方便运行和管理。
6. **覆盖多种 ARM 指令:**  测试用例覆盖了各种不同的 ARM 指令类型、操作数、寻址模式和条件码，以确保反汇编器能够正确处理各种情况。
7. **处理汇编器的自动转换:**  测试了汇编器自动将某些指令转换为其他等效指令的情况，并验证反汇编器能够正确地反向转换。
8. **针对特定 CPU 功能进行测试:**  部分测试用例针对 ARMv7 或 VFP (Vector Floating Point) 等特定的 CPU 功能进行测试，确保反汇编器能够处理这些扩展指令集。

**如果 `v8/test/unittests/assembler/disasm-arm-unittest.cc` 以 `.tq` 结尾:**

根据你的描述，如果文件以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。 Torque 是一种 V8 使用的类型化的中间语言，用于生成高效的 JavaScript 运行时代码。在这种情况下，该文件将包含使用 Torque 语言编写的测试，用于验证 ARM 反汇编器的功能。

**它与 JavaScript 的功能的关系:**

这个测试文件直接关系到 V8 引擎执行 JavaScript 代码的正确性。当 V8 引擎需要将 JavaScript 代码编译成机器码在 ARM 架构的处理器上运行时，它会使用汇编器生成机器码。为了调试、性能分析或者其他目的，需要能够将这些机器码反汇编回汇编指令。 这个单元测试确保了 V8 的 ARM 反汇编器能够准确地完成这项工作，从而帮助开发者理解和调试 V8 生成的机器码。

**JavaScript 示例 (概念性):**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它的目的是验证 V8 在处理 JavaScript 时生成的底层机器码的反汇编能力。  以下是一个概念性的 JavaScript 例子，说明了 V8 内部如何使用汇编和反汇编（实际过程更复杂）：

```javascript
function add(a, b) {
  return a + b;
}

// V8 内部会将 add 函数编译成 ARM 机器码
// 假设生成的机器码对应以下汇编指令 (简化示例)
// add r0, r1, r2  // r0 = r1 + r2

// 反汇编器会将上述机器码转换回类似的汇编指令字符串
```

**代码逻辑推理 (假设输入与输出):**

假设汇编器生成了以下表示 ARM `add` 指令的 4 字节机器码：`0xE0010002`

* **输入 (机器码):** `0xE0010002` (十六进制)
* **预期输出 (反汇编):** `"e0010002       add r0, r1, r2"`

`DisassembleAndCompare` 函数会将输入的机器码传递给反汇编器，反汇编器会将其解码并生成汇编指令字符串。然后，该函数会将生成的字符串与预期的字符串进行比较。

**用户常见的编程错误 (与反汇编器测试相关):**

虽然用户通常不直接编写反汇编器，但 V8 的开发者在编写或修改反汇编器时可能会犯以下错误，而这些单元测试旨在捕获这些错误：

1. **指令格式解析错误:**  错误地解析机器码的各个字段，导致指令的操作码、寄存器、立即数等被错误识别。 例如，将 `add`
Prompt: 
```
这是目录为v8/test/unittests/assembler/disasm-arm-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/assembler/disasm-arm-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2011 the V8 project authors. All rights reserved.
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

#include <cinttypes>
#include <cstdlib>

// The C++ style guide recommends using <re2> instead of <regex>. However, the
// former isn't available in V8.
#include <regex>  // NOLINT(build/c++11)

#include "src/base/numbers/double.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/debug/debug.h"
#include "src/diagnostics/disasm.h"
#include "src/diagnostics/disassembler.h"
#include "src/execution/frames-inl.h"
#include "src/init/v8.h"
#include "src/objects/objects-inl.h"
#include "src/utils/boxed-float.h"
#include "test/unittests/test-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {
namespace internal {

using DisasmArmTest = TestWithIsolate;

enum UseRegex { kRawString, kRegexString };

template <typename... S>
bool DisassembleAndCompare(uint8_t* begin, UseRegex use_regex,
                           S... expected_strings) {
  disasm::NameConverter converter;
  disasm::Disassembler disasm(converter);
  base::EmbeddedVector<char, 128> buffer;

  std::vector<std::string> expected_disassembly = {expected_strings...};
  size_t n_expected = expected_disassembly.size();
  uint8_t* end = begin + (n_expected * kInstrSize);

  std::vector<std::string> disassembly;
  for (uint8_t* pc = begin; pc < end;) {
    pc += disasm.InstructionDecode(buffer, pc);
    disassembly.emplace_back(buffer.begin());
  }

  bool test_passed = true;

  for (size_t i = 0; i < disassembly.size(); i++) {
    if (use_regex == kRawString) {
      if (expected_disassembly[i] != disassembly[i]) {
        fprintf(stderr,
                "expected: \n"
                "%s\n"
                "disassembled: \n"
                "%s\n\n",
                expected_disassembly[i].c_str(), disassembly[i].c_str());
        test_passed = false;
      }
    } else {
      DCHECK_EQ(use_regex, kRegexString);
      if (!std::regex_match(disassembly[i],
                            std::regex(expected_disassembly[i]))) {
        fprintf(stderr,
                "expected (regex): \n"
                "%s\n"
                "disassembled: \n"
                "%s\n\n",
                expected_disassembly[i].c_str(), disassembly[i].c_str());
        test_passed = false;
      }
    }
  }

  // Fail after printing expected disassembly if we expected a different number
  // of instructions.
  if (disassembly.size() != expected_disassembly.size()) {
    return false;
  }

  return test_passed;
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
#define BASE_COMPARE(asm_, use_regex, ...)                             \
  {                                                                    \
    int pc_offset = assm.pc_offset();                                  \
    uint8_t* progcounter = &buffer[pc_offset];                         \
    assm.asm_;                                                         \
    if (!DisassembleAndCompare(progcounter, use_regex, __VA_ARGS__)) { \
      failure = true;                                                  \
    }                                                                  \
  }

#define COMPARE(asm_, ...) BASE_COMPARE(asm_, kRawString, __VA_ARGS__)

#define COMPARE_REGEX(asm_, ...) BASE_COMPARE(asm_, kRegexString, __VA_ARGS__)

// Force emission of any pending literals into a pool.
#define EMIT_PENDING_LITERALS() assm.CheckConstPool(true, false)

// Verify that all invocations of the COMPARE macro passed successfully.
// Exit with a failure if at least one of the tests failed.
#define VERIFY_RUN()                           \
  if (failure) {                               \
    FATAL("ARM Disassembler tests failed.\n"); \
  }

// clang-format off


TEST_F(DisasmArmTest, Type0) {
  SET_UP();

  COMPARE(and_(r0, r1, Operand(r2)),
          "e0010002       and r0, r1, r2");
  COMPARE(and_(r1, r2, Operand(r3), LeaveCC),
          "e0021003       and r1, r2, r3");
  COMPARE(and_(r2, r3, Operand(r4), SetCC),
          "e0132004       ands r2, r3, r4");
  COMPARE(and_(r3, r4, Operand(r5), LeaveCC, eq),
          "00043005       andeq r3, r4, r5");

  COMPARE(eor(r4, r5, Operand(r6, LSL, 0)),
          "e0254006       eor r4, r5, r6");
  COMPARE(eor(r4, r5, Operand(r7, LSL, 1), SetCC),
          "e0354087       eors r4, r5, r7, lsl #1");
  COMPARE(eor(r4, r5, Operand(r8, LSL, 2), LeaveCC, ne),
          "10254108       eorne r4, r5, r8, lsl #2");
  COMPARE(eor(r4, r5, Operand(r9, LSL, 3), SetCC, cs),
          "20354189       eorcss r4, r5, r9, lsl #3");

  COMPARE(sub(r5, r6, Operand(r10, LSL, 31), LeaveCC, hs),
          "20465f8a       subcs r5, r6, r10, lsl #31");
  COMPARE(sub(r5, r6, Operand(r10, LSL, 30), SetCC, cc),
          "30565f0a       subccs r5, r6, r10, lsl #30");
  COMPARE(sub(r5, r6, Operand(r10, LSL, 24), LeaveCC, lo),
          "30465c0a       subcc r5, r6, r10, lsl #24");
  COMPARE(sub(r5, r6, Operand(r10, LSL, 16), SetCC, mi),
          "4056580a       submis r5, r6, r10, lsl #16");

  COMPARE(rsb(r6, r7, Operand(fp)),
          "e067600b       rsb r6, r7, fp");
  COMPARE(rsb(r6, r7, Operand(fp, LSR, 1)),
          "e06760ab       rsb r6, r7, fp, lsr #1");
  COMPARE(rsb(r6, r7, Operand(fp, LSR, 0), SetCC),
          "e077602b       rsbs r6, r7, fp, lsr #32");
  COMPARE(rsb(r6, r7, Operand(fp, LSR, 31), LeaveCC, pl),
          "50676fab       rsbpl r6, r7, fp, lsr #31");

  COMPARE(add(r7, r8, Operand(ip, ASR, 1)),
          "e08870cc       add r7, r8, ip, asr #1");
  COMPARE(add(r7, r8, Operand(ip, ASR, 0)),
          "e088704c       add r7, r8, ip, asr #32");
  COMPARE(add(r7, r8, Operand(ip), SetCC),
          "e098700c       adds r7, r8, ip");
  COMPARE(add(r7, r8, Operand(ip, ASR, 31), SetCC, vs),
          "60987fcc       addvss r7, r8, ip, asr #31");

  COMPARE(adc(r7, fp, Operand(ip, ASR, 5)),
          "e0ab72cc       adc r7, fp, ip, asr #5");
  COMPARE(adc(r4, ip, Operand(ip, ASR, 1), LeaveCC, vc),
          "70ac40cc       adcvc r4, ip, ip, asr #1");
  COMPARE(adc(r5, sp, Operand(ip), SetCC),
          "e0bd500c       adcs r5, sp, ip");
  COMPARE(adc(r8, lr, Operand(ip, ASR, 31), SetCC, vc),
          "70be8fcc       adcvcs r8, lr, ip, asr #31");

  COMPARE(sbc(r7, r1, Operand(ip, ROR, 1), LeaveCC, hi),
          "80c170ec       sbchi r7, r1, ip, ror #1");
  COMPARE(sbc(r7, r9, Operand(ip, ROR, 4)),
          "e0c9726c       sbc r7, r9, ip, ror #4");
  COMPARE(sbc(r7, r10, Operand(ip), SetCC),
          "e0da700c       sbcs r7, r10, ip");
  COMPARE(sbc(r7, ip, Operand(ip, ROR, 31), SetCC, hi),
          "80dc7fec       sbchis r7, ip, ip, ror #31");

  COMPARE(rsc(r7, r8, Operand(ip, LSL, r0)),
          "e0e8701c       rsc r7, r8, ip, lsl r0");
  COMPARE(rsc(r7, r8, Operand(ip, LSL, r1)),
          "e0e8711c       rsc r7, r8, ip, lsl r1");
  COMPARE(rsc(r7, r8, Operand(ip), SetCC),
          "e0f8700c       rscs r7, r8, ip");
  COMPARE(rsc(r7, r8, Operand(ip, LSL, r3), SetCC, ls),
          "90f8731c       rsclss r7, r8, ip, lsl r3");

  COMPARE(tst(r7, Operand(r5, ASR, ip), ge),
          "a1170c55       tstge r7, r5, asr ip");
  COMPARE(tst(r7, Operand(r6, ASR, sp)),
          "e1170d56       tst r7, r6, asr sp");
  COMPARE(tst(r7, Operand(r7), ge),
          "a1170007       tstge r7, r7");
  COMPARE(tst(r7, Operand(r8, ASR, fp), ge),
          "a1170b58       tstge r7, r8, asr fp");

  COMPARE(teq(r7, Operand(r5, ROR, r0), lt),
          "b1370075       teqlt r7, r5, ror r0");
  COMPARE(teq(r7, Operand(r6, ROR, lr)),
          "e1370e76       teq r7, r6, ror lr");
  COMPARE(teq(r7, Operand(r7), lt),
          "b1370007       teqlt r7, r7");
  COMPARE(teq(r7, Operand(r8, ROR, r1)),
          "e1370178       teq r7, r8, ror r1");

  COMPARE(cmp(r7, Operand(r4)),
          "e1570004       cmp r7, r4");
  COMPARE(cmp(r7, Operand(r6, LSL, 1), gt),
          "c1570086       cmpgt r7, r6, lsl #1");
  COMPARE(cmp(r7, Operand(r8, LSR, 3), gt),
          "c15701a8       cmpgt r7, r8, lsr #3");
  COMPARE(cmp(r7, Operand(r8, ASR, 19)),
          "e15709c8       cmp r7, r8, asr #19");

  COMPARE(cmn(r0, Operand(r4)),
          "e1700004       cmn r0, r4");
  COMPARE(cmn(r1, Operand(r6, ROR, 1)),
          "e17100e6       cmn r1, r6, ror #1");
  COMPARE(cmn(r2, Operand(r8)),
          "e1720008       cmn r2, r8");
  COMPARE(cmn(r3, Operand(fp), le),
          "d173000b       cmnle r3, fp");

  COMPARE(orr(r7, r8, Operand(lr), LeaveCC, al),
          "e188700e       orr r7, r8, lr");
  COMPARE(orr(r7, r8, Operand(fp)),
          "e188700b       orr r7, r8, fp");
  COMPARE(orr(r7, r8, Operand(sp), SetCC),
          "e198700d       orrs r7, r8, sp");
  COMPARE(orr(r7, r8, Operand(ip), SetCC, al),
          "e198700c       orrs r7, r8, ip");

  COMPARE(mov(r0, Operand(r1), LeaveCC, eq),
          "01a00001       moveq r0, r1");
  COMPARE(mov(r0, Operand(r2)),
          "e1a00002       mov r0, r2");
  COMPARE(mov(r0, Operand(r3), SetCC),
          "e1b00003       movs r0, r3");
  COMPARE(mov(r0, Operand(r4), SetCC, pl),
          "51b00004       movpls r0, r4");

  COMPARE(bic(r0, lr, Operand(r1), LeaveCC, vs),
          "61ce0001       bicvs r0, lr, r1");
  COMPARE(bic(r0, r9, Operand(r2), LeaveCC, vc),
          "71c90002       bicvc r0, r9, r2");
  COMPARE(bic(r0, r5, Operand(r3), SetCC),
          "e1d50003       bics r0, r5, r3");
  COMPARE(bic(r0, r1, Operand(r4), SetCC, pl),
          "51d10004       bicpls r0, r1, r4");

  COMPARE(mvn(r10, Operand(r1)),
          "e1e0a001       mvn r10, r1");
  COMPARE(mvn(r9, Operand(r2)),
          "e1e09002       mvn r9, r2");
  COMPARE(mvn(r0, Operand(r3), SetCC),
          "e1f00003       mvns r0, r3");
  COMPARE(mvn(r5, Operand(r4), SetCC, cc),
          "31f05004       mvnccs r5, r4");

  // Instructions autotransformed by the assembler.
  // mov -> mvn.
  COMPARE(mov(r3, Operand(-1), LeaveCC, al),
          "e3e03000       mvn r3, #0");
  COMPARE(mov(r4, Operand(-2), SetCC, al),
          "e3f04001       mvns r4, #1");
  COMPARE(mov(r5, Operand(0x0FFFFFF0), SetCC, ne),
          "13f052ff       mvnnes r5, #-268435441");
  COMPARE(mov(r6, Operand(-1), LeaveCC, ne),
          "13e06000       mvnne r6, #0");

  // mvn -> mov.
  COMPARE(mvn(r3, Operand(-1), LeaveCC, al),
          "e3a03000       mov r3, #0");
  COMPARE(mvn(r4, Operand(-2), SetCC, al),
          "e3b04001       movs r4, #1");
  COMPARE(mvn(r5, Operand(0x0FFFFFF0), SetCC, ne),
          "13b052ff       movnes r5, #-268435441");
  COMPARE(mvn(r6, Operand(-1), LeaveCC, ne),
          "13a06000       movne r6, #0");

  // mov -> movw.
  if (CpuFeatures::IsSupported(ARMv7)) {
    COMPARE(mov(r5, Operand(0x01234), LeaveCC, ne),
            "13015234       movwne r5, #4660");
    COMPARE(eor(r5, r4, Operand(0x1234), LeaveCC, ne),
            "13015234       movwne r5, #4660",
            "10245005       eorne r5, r4, r5");
    // Movw can't do setcc, so first move to r5, then the following instruction
    // sets the flags. Mov immediate with setcc is pretty strange anyway.
    COMPARE(mov(r5, Operand(0x01234), SetCC, ne),
            "13015234       movwne r5, #4660",
            "11b05005       movnes r5, r5");
    // Emit a literal pool now, otherwise this could be dumped later, in the
    // middle of a different test.
    EMIT_PENDING_LITERALS();

    // The eor does the setcc so we get a movw here.
    COMPARE(eor(r5, r4, Operand(0x1234), SetCC, ne),
            "13015234       movwne r5, #4660",
            "10345005       eornes r5, r4, r5");

    COMPARE(movt(r5, 0x4321, ne),
            "13445321       movtne r5, #17185");
    COMPARE(movw(r5, 0xABCD, eq),
            "030a5bcd       movweq r5, #43981");
  }

  // Eor doesn't have an eor-negative variant, but we can do an mvn followed by
  // an eor to get the same effect.
  COMPARE(eor(r5, r4, Operand(0xFFFFFF34), SetCC, ne),
          "13e050cb       mvnne r5, #203",
          "10345005       eornes r5, r4, r5");

  // and <-> bic.
  COMPARE(and_(r3, r5, Operand(0xFC03FFFF)),
          "e3c537ff       bic r3, r5, #66846720");
  COMPARE(bic(r3, r5, Operand(0xFC03FFFF)),
          "e20537ff       and r3, r5, #66846720");

  // sub <-> add.
  COMPARE(add(r3, r5, Operand(-1024)),
          "e2453b01       sub r3, r5, #1024");
  COMPARE(sub(r3, r5, Operand(-1024)),
          "e2853b01       add r3, r5, #1024");

  // cmp <-> cmn.
  COMPARE(cmp(r3, Operand(-1024)),
          "e3730b01       cmn r3, #1024");
  COMPARE(cmn(r3, Operand(-1024)),
          "e3530b01       cmp r3, #1024");

  // Miscellaneous instructions encoded as type 0.
  COMPARE(blx(ip),
          "e12fff3c       blx ip");
  COMPARE(bkpt(0),
          "e1200070       bkpt 0");
  COMPARE(bkpt(0xFFFF),
          "e12fff7f       bkpt 65535");
  COMPARE(clz(r6, r7),
          "e16f6f17       clz r6, r7");

  VERIFY_RUN();
}


TEST_F(DisasmArmTest, Type1) {
  SET_UP();

  COMPARE(and_(r0, r1, Operand(0x00000000)),
          "e2010000       and r0, r1, #0");
  COMPARE(and_(r1, r2, Operand(0x00000001), LeaveCC),
          "e2021001       and r1, r2, #1");
  COMPARE(and_(r2, r3, Operand(0x00000010), SetCC),
          "e2132010       ands r2, r3, #16");
  COMPARE(and_(r3, r4, Operand(0x00000100), LeaveCC, eq),
          "02043c01       andeq r3, r4, #256");
  COMPARE(and_(r4, r5, Operand(0x00001000), SetCC, ne),
          "12154a01       andnes r4, r5, #4096");

  COMPARE(eor(r4, r5, Operand(0x00001000)),
          "e2254a01       eor r4, r5, #4096");
  COMPARE(eor(r4, r4, Operand(0x00010000), LeaveCC),
          "e2244801       eor r4, r4, #65536");
  COMPARE(eor(r4, r3, Operand(0x00100000), SetCC),
          "e2334601       eors r4, r3, #1048576");
  COMPARE(eor(r4, r2, Operand(0x01000000), LeaveCC, cs),
          "22224401       eorcs r4, r2, #16777216");
  COMPARE(eor(r4, r1, Operand(0x10000000), SetCC, cc),
          "32314201       eorccs r4, r1, #268435456");

  VERIFY_RUN();
}


TEST_F(DisasmArmTest, Type3) {
  SET_UP();

  if (CpuFeatures::IsSupported(ARMv7)) {
    CpuFeatureScope scope(&assm, ARMv7);
    COMPARE(ubfx(r0, r1, 5, 10),
            "e7e902d1       ubfx r0, r1, #5, #10");
    COMPARE(ubfx(r1, r0, 5, 10),
            "e7e912d0       ubfx r1, r0, #5, #10");
    COMPARE(ubfx(r0, r1, 31, 1),
            "e7e00fd1       ubfx r0, r1, #31, #1");
    COMPARE(ubfx(r1, r0, 31, 1),
            "e7e01fd0       ubfx r1, r0, #31, #1");

    COMPARE(sbfx(r0, r1, 5, 10),
            "e7a902d1       sbfx r0, r1, #5, #10");
    COMPARE(sbfx(r1, r0, 5, 10),
            "e7a912d0       sbfx r1, r0, #5, #10");
    COMPARE(sbfx(r0, r1, 31, 1),
            "e7a00fd1       sbfx r0, r1, #31, #1");
    COMPARE(sbfx(r1, r0, 31, 1),
            "e7a01fd0       sbfx r1, r0, #31, #1");

    COMPARE(bfc(r0, 5, 10),
            "e7ce029f       bfc r0, #5, #10");
    COMPARE(bfc(r1, 5, 10),
            "e7ce129f       bfc r1, #5, #10");
    COMPARE(bfc(r0, 31, 1),
            "e7df0f9f       bfc r0, #31, #1");
    COMPARE(bfc(r1, 31, 1),
            "e7df1f9f       bfc r1, #31, #1");

    COMPARE(bfi(r0, r1, 5, 10),
            "e7ce0291       bfi r0, r1, #5, #10");
    COMPARE(bfi(r1, r0, 5, 10),
            "e7ce1290       bfi r1, r0, #5, #10");
    COMPARE(bfi(r0, r1, 31, 1),
            "e7df0f91       bfi r0, r1, #31, #1");
    COMPARE(bfi(r1, r0, 31, 1),
            "e7df1f90       bfi r1, r0, #31, #1");

    COMPARE(pkhbt(r3, r4, Operand(r5, LSL, 17)),
            "e6843895       pkhbt r3, r4, r5, lsl #17");
    COMPARE(pkhtb(r3, r4, Operand(r5, ASR, 17)),
            "e68438d5       pkhtb r3, r4, r5, asr #17");

    COMPARE(sxtb(r1, r7, 0, eq), "06af1077       sxtbeq r1, r7");
    COMPARE(sxtb(r0, r0, 8, ne), "16af0470       sxtbne r0, r0, ror #8");
    COMPARE(sxtb(r9, r10, 16), "e6af987a       sxtb r9, r10, ror #16");
    COMPARE(sxtb(r4, r3, 24), "e6af4c73       sxtb r4, r3, ror #24");

    COMPARE(sxtab(r3, r4, r5), "e6a43075       sxtab r3, r4, r5");

    COMPARE(sxth(r5, r0), "e6bf5070       sxth r5, r0");
    COMPARE(sxth(r5, r9, 8), "e6bf5479       sxth r5, r9, ror #8");
    COMPARE(sxth(r5, r9, 16, hi), "86bf5879       sxthhi r5, r9, ror #16");
    COMPARE(sxth(r8, r9, 24, cc), "36bf8c79       sxthcc r8, r9, ror #24");

    COMPARE(sxtah(r3, r4, r5, 16), "e6b43875       sxtah r3, r4, r5, ror #16");

    COMPARE(uxtb(r9, r10), "e6ef907a       uxtb r9, r10");
    COMPARE(uxtb(r3, r4, 8), "e6ef3474       uxtb r3, r4, ror #8");

    COMPARE(uxtab(r3, r4, r5, 8), "e6e43475       uxtab r3, r4, r5, ror #8");

    COMPARE(uxtb16(r3, r4, 8), "e6cf3474       uxtb16 r3, r4, ror #8");

    COMPARE(uxth(r9, r10), "e6ff907a       uxth r9, r10");
    COMPARE(uxth(r3, r4, 8), "e6ff3474       uxth r3, r4, ror #8");

    COMPARE(uxtah(r3, r4, r5, 24), "e6f43c75       uxtah r3, r4, r5, ror #24");

    COMPARE(rbit(r1, r2), "e6ff1f32       rbit r1, r2");
    COMPARE(rbit(r10, ip), "e6ffaf3c       rbit r10, ip");

    COMPARE(rev(r1, r2), "e6bf1f32       rev r1, r2");
    COMPARE(rev(r10, ip), "e6bfaf3c       rev r10, ip");
  }

  COMPARE(usat(r0, 1, Operand(r1)),
          "e6e10011       usat r0, #1, r1");
  COMPARE(usat(r2, 7, Operand(lr)),
          "e6e7201e       usat r2, #7, lr");
  COMPARE(usat(r3, 31, Operand(r4, LSL, 31)),
          "e6ff3f94       usat r3, #31, r4, lsl #31");
  COMPARE(usat(r8, 0, Operand(r5, ASR, 17)),
          "e6e088d5       usat r8, #0, r5, asr #17");

  COMPARE(smmla(r0, r1, r2, r3), "e7503211       smmla r0, r1, r2, r3");
  COMPARE(smmla(r10, r9, r8, r7), "e75a7819       smmla r10, r9, r8, r7");

  COMPARE(smmul(r0, r1, r2), "e750f211       smmul r0, r1, r2");
  COMPARE(smmul(r8, r9, r10), "e758fa19       smmul r8, r9, r10");

  VERIFY_RUN();
}


TEST_F(DisasmArmTest, msr_mrs_disasm) {
  SET_UP();

  SRegisterFieldMask CPSR_all = CPSR_f | CPSR_s | CPSR_x | CPSR_c;
  SRegisterFieldMask SPSR_all = SPSR_f | SPSR_s | SPSR_x | SPSR_c;

  COMPARE(msr(CPSR_f, Operand(r0)),       "e128f000       msr CPSR_f, r0");
  COMPARE(msr(CPSR_s, Operand(r1)),       "e124f001       msr CPSR_s, r1");
  COMPARE(msr(CPSR_x, Operand(r2)),       "e122f002       msr CPSR_x, r2");
  COMPARE(msr(CPSR_c, Operand(r3)),       "e121f003       msr CPSR_c, r3");
  COMPARE(msr(CPSR_all, Operand(ip)),     "e12ff00c       msr CPSR_fsxc, ip");
  COMPARE(msr(SPSR_f, Operand(r0)),       "e168f000       msr SPSR_f, r0");
  COMPARE(msr(SPSR_s, Operand(r1)),       "e164f001       msr SPSR_s, r1");
  COMPARE(msr(SPSR_x, Operand(r2)),       "e162f002       msr SPSR_x, r2");
  COMPARE(msr(SPSR_c, Operand(r3)),       "e161f003       msr SPSR_c, r3");
  COMPARE(msr(SPSR_all, Operand(ip)),     "e16ff00c       msr SPSR_fsxc, ip");
  COMPARE(msr(CPSR_f, Operand(r0), eq),   "0128f000       msreq CPSR_f, r0");
  COMPARE(msr(CPSR_s, Operand(r1), ne),   "1124f001       msrne CPSR_s, r1");
  COMPARE(msr(CPSR_x, Operand(r2), cs),   "2122f002       msrcs CPSR_x, r2");
  COMPARE(msr(CPSR_c, Operand(r3), cc),   "3121f003       msrcc CPSR_c, r3");
  COMPARE(msr(CPSR_all, Operand(ip), mi), "412ff00c       msrmi CPSR_fsxc, ip");
  COMPARE(msr(SPSR_f, Operand(r0), pl),   "5168f000       msrpl SPSR_f, r0");
  COMPARE(msr(SPSR_s, Operand(r1), vs),   "6164f001       msrvs SPSR_s, r1");
  COMPARE(msr(SPSR_x, Operand(r2), vc),   "7162f002       msrvc SPSR_x, r2");
  COMPARE(msr(SPSR_c, Operand(r3), hi),   "8161f003       msrhi SPSR_c, r3");
  COMPARE(msr(SPSR_all, Operand(ip), ls), "916ff00c       msrls SPSR_fsxc, ip");

  // Other combinations of mask bits.
  COMPARE(msr(CPSR_s | CPSR_x, Operand(r4)),
          "e126f004       msr CPSR_sx, r4");
  COMPARE(msr(SPSR_s | SPSR_x | SPSR_c, Operand(r5)),
          "e167f005       msr SPSR_sxc, r5");
  COMPARE(msr(SPSR_s | SPSR_c, Operand(r6)),
          "e165f006       msr SPSR_sc, r6");
  COMPARE(msr(SPSR_f | SPSR_c, Operand(r7)),
          "e169f007       msr SPSR_fc, r7");
  // MSR with no mask is UNPREDICTABLE, and checked by the assembler, but check
  // that the disassembler does something sensible.
  COMPARE(dd(0xE120F008), "e120f008       msr CPSR_(none), r8");

  COMPARE(mrs(r0, CPSR),     "e10f0000       mrs r0, CPSR");
  COMPARE(mrs(r1, SPSR),     "e14f1000       mrs r1, SPSR");
  COMPARE(mrs(r2, CPSR, ge), "a10f2000       mrsge r2, CPSR");
  COMPARE(mrs(r3, SPSR, lt), "b14f3000       mrslt r3, SPSR");

  VERIFY_RUN();
}


TEST_F(DisasmArmTest, Vfp) {
  SET_UP();

  if (CpuFeatures::IsSupported(VFPv3)) {
    CpuFeatureScope scope(&assm, VFPv3);
    COMPARE(vmov(d0, r2, r3),
            "ec432b10       vmov d0, r2, r3");
    COMPARE(vmov(r2, r3, d0),
            "ec532b10       vmov r2, r3, d0");
    COMPARE(vmov(r4, ip, d1),
            "ec5c4b11       vmov r4, ip, d1");
    COMPARE(vmov(d0, d1),
            "eeb00b41       vmov.f64 d0, d1");
    COMPARE(vmov(d3, d3, eq),
            "0eb03b43       vmoveq.f64 d3, d3");

    COMPARE(vmov(s0, s31),
            "eeb00a6f       vmov.f32 s0, s31");
    COMPARE(vmov(s31, s0),
            "eef0fa40       vmov.f32 s31, s0");
    COMPARE(vmov(r0, s0),
            "ee100a10       vmov r0, s0");
    COMPARE(vmov(r10, s31),
            "ee1faa90       vmov r10, s31");
    COMPARE(vmov(s0, r0),
            "ee000a10       vmov s0, r0");
    COMPARE(vmov(s31, r10),
            "ee0faa90       vmov s31, r10");

    COMPARE(vabs(d0, d1),
            "eeb00bc1       vabs.f64 d0, d1");
    COMPARE(vabs(d3, d4, mi),
            "4eb03bc4       vabsmi.f64 d3, d4");

    COMPARE(vabs(s0, s1),
            "eeb00ae0       vabs.f32 s0, s1");
    COMPARE(vabs(s3, s4, mi),
            "4ef01ac2       vabsmi.f32 s3, s4");

    COMPARE(vneg(d0, d1),
            "eeb10b41       vneg.f64 d0, d1");
    COMPARE(vneg(d3, d4, mi),
            "4eb13b44       vnegmi.f64 d3, d4");

    COMPARE(vneg(s0, s1),
            "eeb10a60       vneg.f32 s0, s1");
    COMPARE(vneg(s3, s4, mi),
            "4ef11a42       vnegmi.f32 s3, s4");

    COMPARE(vadd(d0, d1, d2),
            "ee310b02       vadd.f64 d0, d1, d2");
    COMPARE(vadd(d3, d4, d5, mi),
            "4e343b05       vaddmi.f64 d3, d4, d5");

    COMPARE(vadd(s0, s1, s2),
            "ee300a81       vadd.f32 s0, s1, s2");
    COMPARE(vadd(s3, s4, s5, mi),
            "4e721a22       vaddmi.f32 s3, s4, s5");

    COMPARE(vsub(d0, d1, d2),
            "ee310b42       vsub.f64 d0, d1, d2");
    COMPARE(vsub(d3, d4, d5, ne),
            "1e343b45       vsubne.f64 d3, d4, d5");

    COMPARE(vsub(s0, s1, s2),
            "ee300ac1       vsub.f32 s0, s1, s2");
    COMPARE(vsub(s3, s4, s5, ne),
            "1e721a62       vsubne.f32 s3, s4, s5");

    COMPARE(vmul(d2, d1, d0),
            "ee212b00       vmul.f64 d2, d1, d0");
    COMPARE(vmul(d6, d4, d5, cc),
            "3e246b05       vmulcc.f64 d6, d4, d5");

    COMPARE(vmul(s2, s1, s0),
            "ee201a80       vmul.f32 s2, s1, s0");
    COMPARE(vmul(s6, s4, s5, cc),
            "3e223a22       vmulcc.f32 s6, s4, s5");

    COMPARE(vdiv(d2, d2, d2),
            "ee822b02       vdiv.f64 d2, d2, d2");
    COMPARE(vdiv(d6, d7, d7, hi),
            "8e876b07       vdivhi.f64 d6, d7, d7");

    COMPARE(vdiv(s2, s2, s2),
            "ee811a01       vdiv.f32 s2, s2, s2");
    COMPARE(vdiv(s6, s7, s7, hi),
            "8e833aa3       vdivhi.f32 s6, s7, s7");

    COMPARE(vcmp(d0, d1),
            "eeb40b41       vcmp.f64 d0, d1");
    COMPARE(vcmp(d0, 0.0),
            "eeb50b40       vcmp.f64 d0, #0.0");

    COMPARE(vcmp(s0, s1),
            "eeb40a60       vcmp.f32 s0, s1");
    COMPARE(vcmp(s0, 0.0f),
            "eeb50a40       vcmp.f32 s0, #0.0");

    COMPARE(vsqrt(d0, d0),
            "eeb10bc0       vsqrt.f64 d0, d0");
    COMPARE(vsqrt(d2, d3, ne),
            "1eb12bc3       vsqrtne.f64 d2, d3");

    COMPARE(vsqrt(s0, s0),
            "eeb10ac0       vsqrt.f32 s0, s0");
    COMPARE(vsqrt(s2, s3, ne),
            "1eb11ae1       vsqrtne.f32 s2, s3");

    COMPARE(vmov(d0, base::Double(1.0)),
            "eeb70b00       vmov.f64 d0, #1");
    COMPARE(vmov(d2, base::Double(-13.0)),
            "eeba2b0a       vmov.f64 d2, #-13");

    COMPARE(vmov(s1, Float32(-1.0f)),
            "eeff0a00       vmov.f32 s1, #-1");
    COMPARE(vmov(s3, Float32(13.0f)),
            "eef21a0a       vmov.f32 s3, #13");

    COMPARE(vmov(NeonS32, d0, 0, r0),
            "ee000b10       vmov.32 d0[0], r0");
    COMPARE(vmov(NeonS32, d0, 1, r0),
            "ee200b10       vmov.32 d0[1], r0");

    COMPARE(vmov(NeonS32, r2, d15, 0),
            "ee1f2b10       vmov.32 r2, d15[0]");
    COMPARE(vmov(NeonS32, r3, d14, 1),
            "ee3e3b10       vmov.32 r3, d14[1]");

    COMPARE(vldr(s0, r0, 0),
            "ed900a00       vldr s0, [r0 + 4*0]");
    COMPARE(vldr(s1, r1, 4),
            "edd10a01       vldr s1, [r1 + 4*1]");
    COMPARE(vldr(s15, r4, 16),
            "edd47a04       vldr s15, [r4 + 4*4]");
    COMPARE(vldr(s16, r5, 20),
            "ed958a05       vldr s16, [r5 + 4*5]");
    COMPARE(vldr(s31, r10, 1020),
            "eddafaff       vldr s31, [r10 + 4*255]");
    COMPARE(vldr(s31, ip, 1020),
            "eddcfaff       vldr s31, [ip + 4*255]");

    COMPARE(vstr(s0, r0, 0),
            "ed800a00       vstr s0, [r0 + 4*0]");
    COMPARE(vstr(s1, r1, 4),
            "edc10a01       vstr s1, [r1 + 4*1]");
    COMPARE(vstr(s15, r8, 8),
            "edc87a02       vstr s15, [r8 + 4*2]");
    COMPARE(vstr(s16, r9, 12),
            "ed898a03       vstr s16, [r9 + 4*3]");
    COMPARE(vstr(s31, r10, 1020),
            "edcafaff       vstr s31, [r10 + 4*255]");

    COMPARE(vldr(d0, r0, 0),
            "ed900b00       vldr d0, [r0 + 4*0]");
    COMPARE(vldr(d1, r1, 4),
            "ed911b01       vldr d1, [r1 + 4*1]");
    COMPARE(vldr(d15, r10, 1020),
            "ed9afbff       vldr d15, [r10 + 4*255]");
    COMPARE(vstr(d0, r0, 0),
            "ed800b00       vstr d0, [r0 + 4*0]");
    COMPARE(vstr(d1, r1, 4),
            "ed811b01       vstr d1, [r1 + 4*1]");
    COMPARE(vstr(d15, r10, 1020),
            "ed8afbff       vstr d15, [r10 + 4*255]");

    COMPARE(vmsr(r5),
            "eee15a10       vmsr FPSCR, r5");
    COMPARE(vmsr(r10, pl),
            "5ee1aa10       vmsrpl FPSCR, r10");
    COMPARE(vmsr(pc),
            "eee1fa10       vmsr FPSCR, APSR");
    COMPARE(vmrs(r5),
            "eef15a10       vmrs r5, FPSCR");
    COMPARE(vmrs(r10, ge),
            "aef1aa10       vmrsge r10, FPSCR");
    COMPARE(vmrs(pc),
            "eef1fa10       vmrs APSR, FPSCR");

    COMPARE(vstm(ia, r0, d1, d3),
            "ec801b06       vstmia r0, {d1-d3}");
    COMPARE(vldm(ia, r1, d2, d5),
            "ec912b08       vldmia r1, {d2-d5}");
    COMPARE(vstm(ia, r2, d0, d15),
            "ec820b20       vstmia r2, {d0-d15}");
    COMPARE(vldm(ia, r3, d0, d15),
            "ec930b20       vldmia r3, {d0-d15}");
    COMPARE(vstm(ia, r4, s1, s3),
            "ecc40a03       vstmia r4, {s1-s3}");
    COMPARE(vldm(ia, r5, s2, s5),
            "ec951a04       vldmia r5, {s2-s5}");
    COMPARE(vstm(ia, r6, s0, s31),
            "ec860a20       vstmia r6, {s0-s31}");
    COMPARE(vldm(ia, r7, s0, s31),
            "ec970a20       vldmia r7, {s0-s31}");

    COMPARE(vmla(d2, d1, d0),
            "ee012b00       vmla.f64 d2, d1, d0");
    COMPARE(vmla(d6, d4, d5, cc),
            "3e046b05       vmlacc.f64 d6, d4, d5");

    COMPARE(vmla(s2, s1, s0),
            "ee001a80       vmla.f32 s2, s1, s0");
    COMPARE(vmla(s6, s4, s5, cc),
            "3e023a22       vmlacc.f32 s6, s4, s5");

    COMPARE(vmls(d2, d1, d0),
            "ee012b40       vmls.f64 d2, d1, d0");
    COMPARE(vmls(d6, d4, d5, cc),
            "3e046b45       vmlscc.f64 d6, d4, d5");

    COMPARE(vmls(s2, s1, s0),
            "ee001ac0       vmls.f32 s2, s1, s0");
    COMPARE(vmls(s6, s4, s5, cc),
            "3e023a62       vmlscc.f32 s6, s4, s5");

    COMPARE(vcvt_f32_f64(s31, d15),
            "eef7fbcf       vcvt.f32.f64 s31, d15");
    COMPARE(vcvt_f32_s32(s30, s29),
            "eeb8faee       vcvt.f32.s32 s30, s29");
    COMPARE(vcvt_f64_f32(d14, s28),
            "eeb7eace       vcvt.f64.f32 d14, s28");
    COMPARE(vcvt_f64_s32(d13, s27),
            "eeb8dbed       vcvt.f64.s32 d13, s27");
    COMPARE(vcvt_f64_u32(d12, s26),
            "eeb8cb4d       vcvt.f64.u32 d12, s26");
    COMPARE(vcvt_s32_f32(s25, s24),
            "eefdcacc       vcvt.s32.f32 s25, s24");
    COMPARE(vcvt_s32_f64(s23, d11),
            "eefdbbcb       vcvt.s32.f64 s23, d11");
    COMPARE(vcvt_u32_f32(s22, s21),
            "eebcbaea       vcvt.u32.f32 s22, s21");
    COMPARE(vcvt_u32_f64(s20, d10),
            "eebcabca       vcvt.u32.f64 s20, d10");

    COMPARE(vcvt_f64_s32(d9, 2),
            "eeba9bcf       vcvt.f64.s32 d9, d9, #2");

    if (CpuFeatures::IsSupported(VFP32DREGS)) {
      CpuFeatureScope scope(&assm, VFP32DREGS);
      COMPARE(vmov(d3, d27),
              "eeb03b6b       vmov.f64 d3, d27");
      COMPARE(vmov(d18, d7),
              "eef02b47       vmov.f64 d18, d7");
      COMPARE(vmov(d18, r2, r3),
              "ec432b32       vmov d18, r2, r3");
      COMPARE(vmov(r2, r3, d18),
              "ec532b32       vmov r2, r3, d18");
      COMPARE(vmov(d20, d31),
              "eef04b6f       vmov.f64 d20, d31");

      COMPARE(vabs(d16, d31),
              "eef00bef       vabs.f64 d16, d31");

      COMPARE(vneg(d16, d31),
              "eef10b6f       vneg.f64 d16, d31");

      COMPARE(vadd(d16, d17, d18),
              "ee710ba2       vadd.f64 d16, d17, d18");

      COMPARE(vsub(d16, d17, d18),
              "ee710be2       vsub.f64 d16, d17, d18");

      COMPARE(vmul(d16, d17, d18),
              "ee610ba2       vmul.f64 d16, d17, d18");

      COMPARE(vdiv(d16, d17, d18),
              "eec10ba2       vdiv.f64 d16, d17, d18");

      COMPARE(vcmp(d16, d17),
              "eef40b61       vcmp.f64 d16, d17");
      COMPARE(vcmp(d16, 0.0),
              "eef50b40       vcmp.f64 d16, #0.0");

      COMPARE(vsqrt(d16, d17),
              "eef10be1       vsqrt.f64 d16, d17");

      COMPARE(vmov(d30, base::Double(16.0)),
              "eef3eb00       vmov.f64 d30, #16");

      COMPARE(vmov(NeonS32, d31, 0, r7),
              "ee0f7b90       vmov.32 d31[0], r7");
      COMPARE(vmov(NeonS32, d31, 1, r7),
              "ee2f7b90       vmov.32 d31[1], r7");

      COMPARE(vldr(d25, r0, 0),
              "edd09b00       vldr d25, [r0 + 4*0]");
      COMPARE(vldr(d26, r1, 4),
              "edd1ab01       vldr d26, [r1 + 4*1]");
      COMPARE(vldr(d31, r10, 1020),
              "eddafbff       vldr d31, [r10 + 4*255]");

      COMPARE(vstr(d16, r0, 0),
              "edc00b00 
"""


```