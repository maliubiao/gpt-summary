Response:
The user wants a summary of the functionality of the provided C++ code snippet. The code is a unit test for the MIPS64 disassembler in V8.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the core purpose:** The file name `disasm-mips64-unittest.cc` and the included headers like `disasm.h` and `disassembler.h` clearly indicate this is a test related to disassembling MIPS64 instructions. The `unittest` part signifies it's a unit test.

2. **Examine the setup macros:**
   - `SET_UP()`: This macro initializes the necessary V8 environment for testing the assembler and disassembler. It allocates memory for code and creates an `Assembler` object. This suggests the test will involve generating machine code and then disassembling it.

3. **Analyze the comparison macros:**
   - `COMPARE(asm_, compare_string)`: This is the main workhorse. It takes assembly code (`asm_`) as input, executes it using the `Assembler`, disassembles the resulting bytes, and compares the disassembled output with `compare_string`. The `failure` flag suggests the test will check multiple instructions and report an overall failure.
   - `COMPARE_PC_REL_*`, `COMPARE_MSA_BRANCH`, `COMPARE_PC_JUMP`: These are variations of `COMPARE` that seem to handle instructions with PC-relative addressing or jumps. They calculate the expected target address and include it in the comparison string. This means the tests are verifying the correctness of disassembling these addressing modes.
   - `GET_PC_REGION`: This seems to extract the program counter region, likely for use in calculating jump targets or relative addresses.

4. **Look at the test cases:** The `TEST_F(DisasmMips64Test, Type0)` and `TEST_F(DisasmMips64Test, Type1)` indicate individual test cases. The numerous `COMPARE` calls within these tests show that the code exercises the disassembler with a wide range of MIPS64 instructions. The strings passed to `COMPARE` represent the expected disassembly output.

5. **Consider conditional compilation:** The `if (kArchVariant != kMips64r6)` and `if (kArchVariant == kMips64r6)` blocks indicate that the tests are aware of different MIPS64 architecture variants and have specific test cases for each. This is important for ensuring the disassembler works correctly across different MIPS64 implementations.

6. **Check for Torque/JavaScript relevance:** The prompt asks about Torque and JavaScript. The filename doesn't end with `.tq`, so it's not a Torque file. The code deals with low-level assembly and disassembling, which are foundational to JavaScript execution but not directly related to JavaScript code itself. There are no explicit JavaScript examples within the provided snippet.

7. **Infer code logic and error handling:** The core logic is the assemble-disassemble-compare cycle. The `failure` flag and `VERIFY_RUN()` macro implement a basic error reporting mechanism. If a disassembly doesn't match the expected output, the `failure` flag is set, and at the end, a fatal error is reported if the flag is true. This tests the disassembler's accuracy.

8. **Formulate the summary:** Based on the above analysis, the core function of the code is to test the MIPS64 disassembler in V8. It does this by assembling various MIPS64 instructions and then checking if the disassembler produces the correct human-readable output. The different `COMPARE` macros cater to different instruction types and addressing modes. The conditional compilation indicates testing for different architecture variants.

9. **Address specific prompt points:**
   - `.tq` check: Explicitly state that the file is not a Torque file.
   - JavaScript relevance: Explain the indirect relationship through assembly code.
   - Code logic: Describe the assemble-disassemble-compare process.
   - Error handling: Mention the `failure` flag and `VERIFY_RUN()` macro.

By following these steps, we can arrive at a comprehensive and accurate summary of the provided C++ code snippet.
```cpp
// Copyright 2012 the V8 project authors. All rights reserved.
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

using DisasmMips64Test = TestWithIsolate;

bool prev_instr_compact_branch = false;

bool DisassembleAndCompare(uint8_t* pc, const char* compare_string) {
  disasm::NameConverter converter;
  disasm::Disassembler disasm(converter);
  base::EmbeddedVector<char, 128> disasm_buffer;

  if (prev_instr_compact_branch) {
    disasm.InstructionDecode(disasm_buffer, pc);
    pc += 4;
  }

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
#define VERIFY_RUN()                            \
  if (failure) {                                \
    FATAL("MIPS Disassembler tests failed.\n"); \
  }

#define COMPARE_PC_REL_COMPACT(asm_, compare_string, offset)                   \
  {                                                                            \
    int pc_offset = assm.pc_offset();                                          \
    uint8_t* progcounter = &buffer[pc_offset];                                 \
    char str_with_address[100];                                                \
    prev_instr_compact_branch = assm.IsPrevInstrCompactBranch();               \
    if (prev_instr_compact_branch) {                                           \
      snprintf(str_with_address, sizeof(str_with_address), "%s -> %p",         \
               compare_string,                                                 \
               static_cast<void*>(progcounter + 8 + (offset * 4)));            \
    } else {                                                                   \
      snprintf(str_with_address, sizeof(str_with_address), "%s -> %p",         \
               compare_string,                                                 \
               static_cast<void*>(progcounter + 4 + (offset * 4)));            \
    }                                                                          \
    assm.asm_;                                                                 \
    if (!DisassembleAndCompare(progcounter, str_with_address)) failure = true; \
  }

#define COMPARE_PC_REL(asm_, compare_string, offset)                           \
  {                                                                            \
    int pc_offset = assm.pc_offset();                                          \
    uint8_t* progcounter = &buffer[pc_offset];                                 \
    char str_with_address[100];                                                \
    snprintf(str_with_address, sizeof(str_with_address), "%s -> %p",           \
             compare_string, static_cast<void*>(progcounter + (offset * 4)));  \
    assm.asm_;                                                                 \
    if (!DisassembleAndCompare(progcounter, str_with_address)) failure = true; \
  }

#define COMPARE_MSA_BRANCH(asm_, compare_string, offset)                       \
  {                                                                            \
    int pc_offset = assm.pc_offset();                                          \
    uint8_t* progcounter = &buffer[pc_offset];                                 \
    char str_with_address[100];                                                \
    snprintf(str_with_address, sizeof(str_with_address), "%s -> %p",           \
             compare_string,                                                   \
             static_cast<void*>(progcounter + 4 + (offset * 4)));              \
    assm.asm_;                                                                 \
    if (!DisassembleAndCompare(progcounter, str_with_address)) failure = true; \
  }

#define COMPARE_PC_JUMP(asm_, compare_string, target)                          \
  {                                                                            \
    int pc_offset = assm.pc_offset();                                          \
    uint8_t* progcounter = &buffer[pc_offset];                                 \
    char str_with_address[100];                                                \
    int instr_index = (target >> 2) & kImm26Mask;                              \
    snprintf(                                                                  \
        str_with_address, sizeof(str_with_address), "%s %p -> %p",             \
        compare_string, reinterpret_cast<void*>(target),                       \
        reinterpret_cast<void*>(((uint64_t)(progcounter + 1) & ~0xFFFFFFF) |   \
                                (instr_index << 2)));                          \
    assm.asm_;                                                                 \
    if (!DisassembleAndCompare(progcounter, str_with_address)) failure = true; \
  }

#define GET_PC_REGION(pc_region)                                         \
  {                                                                      \
    int pc_offset = assm.pc_offset();                                    \
    uint8_t* progcounter = &buffer[pc_offset];                           \
    pc_region = reinterpret_cast<int64_t>(progcounter + 4) & ~0xFFFFFFF; \
  }

TEST_F(DisasmMips64Test, Type0) {
  SET_UP();

  COMPARE(addu(a0, a1, a2), "00a62021       addu    a0, a1, a2");
  COMPARE(daddu(a0, a1, a2), "00a6202d       daddu   a0, a1, a2");
  COMPARE(addu(a6, a7, t0), "016c5021       addu    a6, a7, t0");
  COMPARE(daddu(a6, a7, t0), "016c502d       daddu   a6, a7, t0");
  COMPARE(addu(v0, v1, s0), "00701021       addu    v0, v1, s0");
  COMPARE(daddu(v0, v1, s0), "0070102d       daddu   v0, v1, s0");

  COMPARE(subu(a0, a1, a2), "00a62023       subu    a0, a1, a2");
  COMPARE(dsubu(a0, a1, a2), "00a6202f       dsubu   a0, a1, a2");
  COMPARE(subu(a6, a7, t0), "016c5023       subu    a6, a7, t0");
  COMPARE(dsubu(a6, a7, t0), "016c502f       dsubu   a6, a7, t0");
  COMPARE(subu(v0, v1, s0), "00701023       subu    v0, v1, s0");
  COMPARE(dsubu(v0, v1, s0), "0070102f       dsubu   v0, v1, s0");

  if (kArchVariant != kMips64r6) {
    COMPARE(mult(a0, a1), "00850018       mult    a0, a1");
    COMPARE(dmult(a0, a1), "0085001c       dmult   a0, a1");
    COMPARE(mult(a6, a7), "014b0018       mult    a6, a7");
    COMPARE(dmult(a6, a7), "014b001c       dmult   a6, a7");
    COMPARE(mult(v0, v1), "00430018       mult    v0, v1");
    COMPARE(dmult(v0, v1), "0043001c       dmult   v0, v1");

    COMPARE(multu(a0, a1), "00850019       multu   a0, a1");
    COMPARE(dmultu(a0, a1), "0085001d       dmultu  a0, a1");
    COMPARE(multu(a6, a7), "014b0019       multu   a6, a7");
    COMPARE(dmultu(a6, a7), "014b001d       dmultu  a6, a7");
    COMPARE(multu(v0, v1), "00430019       multu   v0, v1");
    COMPARE(dmultu(v0, v1), "0043001d       dmultu  v0, v1");

    COMPARE(div(a0, a1), "0085001a       div     a0, a1");
    COMPARE(div(a6, a7), "014b001a       div     a6, a7");
    COMPARE(div(v0, v1), "0043001a       div     v0, v1");
    COMPARE(ddiv(a0, a1), "0085001e       ddiv    a0, a1");
    COMPARE(ddiv(a6, a7), "014b001e       ddiv    a6, a7");
    COMPARE(ddiv(v0, v1), "0043001e       ddiv    v0, v1");

    COMPARE(divu(a0, a1), "0085001b       divu    a0, a1");
    COMPARE(divu(a6, a7), "014b001b       divu    a6, a7");
    COMPARE(divu(v0, v1), "0043001b       divu    v0, v1");
    COMPARE(ddivu(a0, a1), "0085001f       ddivu   a0, a1");
    COMPARE(ddivu(a6, a7), "014b001f       ddivu   a6, a7");
    COMPARE(ddivu(v0, v1), "0043001f       ddivu   v0, v1");
    COMPARE(mul(a0, a1, a2), "70a62002       mul     a0, a1, a2");
    COMPARE(mul(a6, a7, t0), "716c5002       mul     a6, a7, t0");
    COMPARE(mul(v0, v1, s0), "70701002       mul     v0, v1, s0");
  } else {  // MIPS64r6.
    COMPARE(mul(a0, a1, a2), "00a62098       mul    a0, a1, a2");
    COMPARE(muh(a0, a1, a2), "00a620d8       muh    a0, a1, a2");
    COMPARE(dmul(a0, a1, a2), "00a6209c       dmul   a0, a1, a2");
    COMPARE(dmuh(a0, a1, a2), "00a620dc       dmuh   a0, a1, a2");
    COMPARE(mul(a5, a6, a7), "014b4898       mul    a5, a6, a7");
    COMPARE(muh(a5, a6, a7), "014b48d8       muh    a5, a6, a7");
    COMPARE(dmul(a5, a6, a7), "014b489c       dmul   a5, a6, a7");
    COMPARE(dmuh(a5, a6, a7), "014b48dc       dmuh   a5, a6, a7");
    COMPARE(mul(v0, v1, a0), "00641098       mul    v0, v1, a0");
    COMPARE(muh(v0, v1, a0), "006410d8       muh    v0, v1, a0");
    COMPARE(dmul(v0, v1, a0), "0064109c       dmul   v0, v1, a0");
    COMPARE(dmuh(v0, v1, a0), "006410dc       dmuh   v0, v1, a0");

    COMPARE(mulu(a0, a1, a2), "00a62099       mulu   a0, a1, a2");
    COMPARE(muhu(a0, a1, a2), "00a620d9       muhu   a0, a1, a2");
    COMPARE(dmulu(a0, a1, a2), "00a6209d       dmulu  a0, a1, a2");
    COMPARE(dmuhu(a0, a1, a2), "00a620dd       dmuhu  a0, a1, a2");
    COMPARE(mulu(a5, a6, a7), "014b4899       mulu   a5, a6, a7");
    COMPARE(muhu(a5, a6, a7), "014b48d9       muhu   a5, a6, a7");
    COMPARE(dmulu(a5, a6, a7), "014b489d       dmulu  a5, a6, a7");
    COMPARE(dmuhu(a5, a6, a7), "014b48dd       dmuhu  a5, a6, a7");
    COMPARE(mulu(v0, v1, a0), "00641099       mulu   v0, v1, a0");
    COMPARE(muhu(v0, v1, a0), "006410d9       muhu   v0, v1, a0");
    COMPARE(dmulu(v0, v1, a0), "0064109d       dmulu  v0, v1, a0");
    COMPARE(dmuhu(v0, v1, a0), "006410dd       dmuhu  v0, v1, a0");

    COMPARE(div(a0, a1, a2), "00a6209a       div    a0, a1, a2");
    COMPARE(mod(a0, a1, a2), "00a620da       mod    a0, a1, a2");
    COMPARE(ddiv(a0, a1, a2), "00a6209e       ddiv   a0, a1, a2");
    COMPARE(dmod(a0, a1, a2), "00a620de       dmod   a0, a1, a2");
    COMPARE(div(a5, a6, a7), "014b489a       div    a5, a6, a7");
    COMPARE(mod(a5, a6, a7), "014b48da       mod    a5, a6, a7");
    COMPARE(ddiv(a5, a6, a7), "014b489e       ddiv   a5, a6, a7");
    COMPARE(dmod(a5, a6, a7), "014b48de       dmod   a5, a6, a7");
    COMPARE(div(v0, v1, a0), "0064109a       div    v0, v1, a0");
    COMPARE(mod(v0, v1, a0), "006410da       mod    v0, v1, a0");
    COMPARE(ddiv(v0, v1, a0), "0064109e       ddiv   v0, v1, a0");
    COMPARE(dmod(v0, v1, a0), "006410de       dmod   v0, v1, a0");

    COMPARE(divu(a0, a1, a2), "00a6209b       divu   a0, a1, a2");
    COMPARE(modu(a0, a1, a2), "00a620db       modu   a0, a1, a2");
    COMPARE(ddivu(a0, a1, a2), "00a6209f       ddivu  a0, a1, a2");
    COMPARE(dmodu(a0, a1, a2), "00a620df       dmodu  a0, a1, a2");
    COMPARE(divu(a5, a6, a7), "014b489b       divu   a5, a6, a7");
    COMPARE(modu(a5, a6, a7), "014b48db       modu   a5, a6, a7");
    COMPARE(ddivu(a5, a6, a7), "014b489f       ddivu  a5, a6, a7");
    COMPARE(dmodu(a5, a6, a7), "014b48df       dmodu  a5, a6, a7");
    COMPARE(divu(v0, v1, a0), "0064109b       divu   v0, v1, a0");
    COMPARE(modu(v0, v1, a0), "006410db       modu   v0, v1, a0");
    COMPARE(ddivu(v0, v1, a0), "0064109f       ddivu  v0, v1, a0");
    COMPARE(dmodu(v0, v1, a0), "006410df       dmodu  v0, v1, a0");
  }

  COMPARE(addiu(a0, a1, 0x0), "24a40000       addiu   a0, a1, 0");
  COMPARE(addiu(s0, s1, 32767), "26307fff       addiu   s0, s1, 32767");
  COMPARE(addiu(a6, a7, -32768), "256a8000       addiu   a6, a7, -32768");
  COMPARE(addiu(v0, v1, -1), "2462ffff       addiu   v0, v1, -1");
  COMPARE(daddiu(a0, a1, 0x0), "64a40000       daddiu  a0, a1, 0");
  COMPARE(daddiu(s0, s1, 32767), "66307fff       daddiu  s0, s1, 32767");
  COMPARE(daddiu(a6, a7, -32768), "656a8000       daddiu  a6, a7, -32768");
  COMPARE(daddiu(v0, v1, -1), "6462ffff       daddiu  v0, v1, -1");

  COMPARE(and_(a0, a1, a2), "00a62024       and     a0, a1, a2");
  COMPARE(and_(s0, s1, s2), "02328024       and     s0, s1, s2");
  COMPARE(and_(a6, a7, t0), "016c5024       and     a6, a7, t0");
  COMPARE(and_(v0, v1, a2), "00661024       and     v0, v1, a2");

  COMPARE(or_(a0, a1, a2), "00a62025       or      a0, a1, a2");
  COMPARE(or_(s0, s1, s2), "02328025       or      s0, s1, s2");
  COMPARE(or_(a6, a7, t0), "016c5025       or      a6, a7, t0");
  COMPARE(or_(v0, v1, a2), "00661025       or      v0, v1, a2");

  COMPARE(xor_(a0, a1, a2), "00a62026       xor     a0, a1, a2");
  COMPARE(xor_(s0, s1, s2), "02328026       xor     s0, s1, s2");
  COMPARE(xor_(a6, a7, t0), "016c5026       xor     a6, a7, t0");
  COMPARE(xor_(v0, v1, a2), "00661026       xor     v0, v1, a2");

  COMPARE(nor(a0, a1, a2), "00a62027       nor     a0, a1, a2");
  COMPARE(nor(s0, s1, s2), "02328027       nor     s0, s1, s2");
  COMPARE(nor(a6, a7, t0), "016c5027       nor     a6, a7, t0");
  COMPARE(nor(v0, v1, a2), "00661027       nor     v0, v1, a2");

  COMPARE(andi(a0, a1, 0x1), "30a40001       andi    a0, a1, 0x1");
  COMPARE(andi(v0, v1, 0xffff), "3062ffff       andi    v0, v1, 0xffff");

  COMPARE(ori(a0, a1, 0x1), "34a40001       ori     a0, a1, 0x1");
  COMPARE(ori(v0, v1, 0xffff), "3462ffff       ori     v0, v1, 0xffff");

  COMPARE(xori(a0, a1, 0x1), "38a40001       xori    a0, a1, 0x1");
  COMPARE(xori(v0, v1, 0xffff), "3862ffff       xori    v0, v1, 0xffff");

  COMPARE(lui(a0, 0x1), "3c040001       lui     a0, 0x1");
  COMPARE(lui(v0, 0xffff), "3c02ffff       lui     v0, 0xffff");

  if (kArchVariant == (kMips64r6)) {
    COMPARE(aui(a0, a1, 0x1), "3ca40001       aui     a0, a1, 0x1");
    COMPARE(aui(v0, v1, 0xffff), "3c62ffff       aui     v0, v1, 0xffff");

    COMPARE(daui(a0, a1, 0x1), "74a40001       daui    a0, a1, 0x1");
    COMPARE(daui(v0, v1, 0xffff), "7462ffff       daui    v0, v1, 0xffff");

    COMPARE(dahi(a0, 0x1), "04860001       dahi    a0, 0x1");
    COMPARE(dahi(v0, 0xffff), "0446ffff       dahi    v0, 0xffff");

    COMPARE(dati(a0, 0x1), "049e0001       dati    a0, 0x1");
    COMPARE(dati(v0, 0xffff), "045effff       dati    v0, 0xffff");
  }

  COMPARE(sll(a0, a1, 0), "00052000       sll     a0, a1, 0");
  COMPARE(sll(s0, s1, 8), "00118200       sll     s0, s1, 8");
  COMPARE(sll(a6, a7, 24), "000b5600       sll     a6, a7, 24");
  COMPARE(sll(v0, v1, 31), "000317c0       sll     v0, v1, 31");
  COMPARE(dsll(a0, a1, 0), "00052038       dsll    a0, a1, 0");
  COMPARE(dsll(s0, s1, 8), "00118238       dsll    s0, s1, 8");
  COMPARE(dsll(a6, a7, 24), "000b5638       dsll    a6, a7, 24");
  COMPARE(dsll(v0, v1, 31), "000317f8       dsll    v0, v1, 31");

  COMPARE(sllv(a0, a1, a2), "00c52004       sllv    a0, a1, a2");
  COMPARE(sllv(s0, s1, s2), "02518004       sllv    s0, s1, s2");
  COMPARE(sllv(a6, a7, t0), "018b50
### 提示词
```
这是目录为v8/test/unittests/assembler/disasm-mips64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/assembler/disasm-mips64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 the V8 project authors. All rights reserved.
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

using DisasmMips64Test = TestWithIsolate;

bool prev_instr_compact_branch = false;

bool DisassembleAndCompare(uint8_t* pc, const char* compare_string) {
  disasm::NameConverter converter;
  disasm::Disassembler disasm(converter);
  base::EmbeddedVector<char, 128> disasm_buffer;

  if (prev_instr_compact_branch) {
    disasm.InstructionDecode(disasm_buffer, pc);
    pc += 4;
  }

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
#define VERIFY_RUN()                            \
  if (failure) {                                \
    FATAL("MIPS Disassembler tests failed.\n"); \
  }

#define COMPARE_PC_REL_COMPACT(asm_, compare_string, offset)                   \
  {                                                                            \
    int pc_offset = assm.pc_offset();                                          \
    uint8_t* progcounter = &buffer[pc_offset];                                 \
    char str_with_address[100];                                                \
    prev_instr_compact_branch = assm.IsPrevInstrCompactBranch();               \
    if (prev_instr_compact_branch) {                                           \
      snprintf(str_with_address, sizeof(str_with_address), "%s -> %p",         \
               compare_string,                                                 \
               static_cast<void*>(progcounter + 8 + (offset * 4)));            \
    } else {                                                                   \
      snprintf(str_with_address, sizeof(str_with_address), "%s -> %p",         \
               compare_string,                                                 \
               static_cast<void*>(progcounter + 4 + (offset * 4)));            \
    }                                                                          \
    assm.asm_;                                                                 \
    if (!DisassembleAndCompare(progcounter, str_with_address)) failure = true; \
  }

#define COMPARE_PC_REL(asm_, compare_string, offset)                           \
  {                                                                            \
    int pc_offset = assm.pc_offset();                                          \
    uint8_t* progcounter = &buffer[pc_offset];                                 \
    char str_with_address[100];                                                \
    snprintf(str_with_address, sizeof(str_with_address), "%s -> %p",           \
             compare_string, static_cast<void*>(progcounter + (offset * 4)));  \
    assm.asm_;                                                                 \
    if (!DisassembleAndCompare(progcounter, str_with_address)) failure = true; \
  }

#define COMPARE_MSA_BRANCH(asm_, compare_string, offset)                       \
  {                                                                            \
    int pc_offset = assm.pc_offset();                                          \
    uint8_t* progcounter = &buffer[pc_offset];                                 \
    char str_with_address[100];                                                \
    snprintf(str_with_address, sizeof(str_with_address), "%s -> %p",           \
             compare_string,                                                   \
             static_cast<void*>(progcounter + 4 + (offset * 4)));              \
    assm.asm_;                                                                 \
    if (!DisassembleAndCompare(progcounter, str_with_address)) failure = true; \
  }

#define COMPARE_PC_JUMP(asm_, compare_string, target)                          \
  {                                                                            \
    int pc_offset = assm.pc_offset();                                          \
    uint8_t* progcounter = &buffer[pc_offset];                                 \
    char str_with_address[100];                                                \
    int instr_index = (target >> 2) & kImm26Mask;                              \
    snprintf(                                                                  \
        str_with_address, sizeof(str_with_address), "%s %p -> %p",             \
        compare_string, reinterpret_cast<void*>(target),                       \
        reinterpret_cast<void*>(((uint64_t)(progcounter + 1) & ~0xFFFFFFF) |   \
                                (instr_index << 2)));                          \
    assm.asm_;                                                                 \
    if (!DisassembleAndCompare(progcounter, str_with_address)) failure = true; \
  }

#define GET_PC_REGION(pc_region)                                         \
  {                                                                      \
    int pc_offset = assm.pc_offset();                                    \
    uint8_t* progcounter = &buffer[pc_offset];                           \
    pc_region = reinterpret_cast<int64_t>(progcounter + 4) & ~0xFFFFFFF; \
  }

TEST_F(DisasmMips64Test, Type0) {
  SET_UP();

  COMPARE(addu(a0, a1, a2), "00a62021       addu    a0, a1, a2");
  COMPARE(daddu(a0, a1, a2), "00a6202d       daddu   a0, a1, a2");
  COMPARE(addu(a6, a7, t0), "016c5021       addu    a6, a7, t0");
  COMPARE(daddu(a6, a7, t0), "016c502d       daddu   a6, a7, t0");
  COMPARE(addu(v0, v1, s0), "00701021       addu    v0, v1, s0");
  COMPARE(daddu(v0, v1, s0), "0070102d       daddu   v0, v1, s0");

  COMPARE(subu(a0, a1, a2), "00a62023       subu    a0, a1, a2");
  COMPARE(dsubu(a0, a1, a2), "00a6202f       dsubu   a0, a1, a2");
  COMPARE(subu(a6, a7, t0), "016c5023       subu    a6, a7, t0");
  COMPARE(dsubu(a6, a7, t0), "016c502f       dsubu   a6, a7, t0");
  COMPARE(subu(v0, v1, s0), "00701023       subu    v0, v1, s0");
  COMPARE(dsubu(v0, v1, s0), "0070102f       dsubu   v0, v1, s0");

  if (kArchVariant != kMips64r6) {
    COMPARE(mult(a0, a1), "00850018       mult    a0, a1");
    COMPARE(dmult(a0, a1), "0085001c       dmult   a0, a1");
    COMPARE(mult(a6, a7), "014b0018       mult    a6, a7");
    COMPARE(dmult(a6, a7), "014b001c       dmult   a6, a7");
    COMPARE(mult(v0, v1), "00430018       mult    v0, v1");
    COMPARE(dmult(v0, v1), "0043001c       dmult   v0, v1");

    COMPARE(multu(a0, a1), "00850019       multu   a0, a1");
    COMPARE(dmultu(a0, a1), "0085001d       dmultu  a0, a1");
    COMPARE(multu(a6, a7), "014b0019       multu   a6, a7");
    COMPARE(dmultu(a6, a7), "014b001d       dmultu  a6, a7");
    COMPARE(multu(v0, v1), "00430019       multu   v0, v1");
    COMPARE(dmultu(v0, v1), "0043001d       dmultu  v0, v1");

    COMPARE(div(a0, a1), "0085001a       div     a0, a1");
    COMPARE(div(a6, a7), "014b001a       div     a6, a7");
    COMPARE(div(v0, v1), "0043001a       div     v0, v1");
    COMPARE(ddiv(a0, a1), "0085001e       ddiv    a0, a1");
    COMPARE(ddiv(a6, a7), "014b001e       ddiv    a6, a7");
    COMPARE(ddiv(v0, v1), "0043001e       ddiv    v0, v1");

    COMPARE(divu(a0, a1), "0085001b       divu    a0, a1");
    COMPARE(divu(a6, a7), "014b001b       divu    a6, a7");
    COMPARE(divu(v0, v1), "0043001b       divu    v0, v1");
    COMPARE(ddivu(a0, a1), "0085001f       ddivu   a0, a1");
    COMPARE(ddivu(a6, a7), "014b001f       ddivu   a6, a7");
    COMPARE(ddivu(v0, v1), "0043001f       ddivu   v0, v1");
    COMPARE(mul(a0, a1, a2), "70a62002       mul     a0, a1, a2");
    COMPARE(mul(a6, a7, t0), "716c5002       mul     a6, a7, t0");
    COMPARE(mul(v0, v1, s0), "70701002       mul     v0, v1, s0");
  } else {  // MIPS64r6.
    COMPARE(mul(a0, a1, a2), "00a62098       mul    a0, a1, a2");
    COMPARE(muh(a0, a1, a2), "00a620d8       muh    a0, a1, a2");
    COMPARE(dmul(a0, a1, a2), "00a6209c       dmul   a0, a1, a2");
    COMPARE(dmuh(a0, a1, a2), "00a620dc       dmuh   a0, a1, a2");
    COMPARE(mul(a5, a6, a7), "014b4898       mul    a5, a6, a7");
    COMPARE(muh(a5, a6, a7), "014b48d8       muh    a5, a6, a7");
    COMPARE(dmul(a5, a6, a7), "014b489c       dmul   a5, a6, a7");
    COMPARE(dmuh(a5, a6, a7), "014b48dc       dmuh   a5, a6, a7");
    COMPARE(mul(v0, v1, a0), "00641098       mul    v0, v1, a0");
    COMPARE(muh(v0, v1, a0), "006410d8       muh    v0, v1, a0");
    COMPARE(dmul(v0, v1, a0), "0064109c       dmul   v0, v1, a0");
    COMPARE(dmuh(v0, v1, a0), "006410dc       dmuh   v0, v1, a0");

    COMPARE(mulu(a0, a1, a2), "00a62099       mulu   a0, a1, a2");
    COMPARE(muhu(a0, a1, a2), "00a620d9       muhu   a0, a1, a2");
    COMPARE(dmulu(a0, a1, a2), "00a6209d       dmulu  a0, a1, a2");
    COMPARE(dmuhu(a0, a1, a2), "00a620dd       dmuhu  a0, a1, a2");
    COMPARE(mulu(a5, a6, a7), "014b4899       mulu   a5, a6, a7");
    COMPARE(muhu(a5, a6, a7), "014b48d9       muhu   a5, a6, a7");
    COMPARE(dmulu(a5, a6, a7), "014b489d       dmulu  a5, a6, a7");
    COMPARE(dmuhu(a5, a6, a7), "014b48dd       dmuhu  a5, a6, a7");
    COMPARE(mulu(v0, v1, a0), "00641099       mulu   v0, v1, a0");
    COMPARE(muhu(v0, v1, a0), "006410d9       muhu   v0, v1, a0");
    COMPARE(dmulu(v0, v1, a0), "0064109d       dmulu  v0, v1, a0");
    COMPARE(dmuhu(v0, v1, a0), "006410dd       dmuhu  v0, v1, a0");

    COMPARE(div(a0, a1, a2), "00a6209a       div    a0, a1, a2");
    COMPARE(mod(a0, a1, a2), "00a620da       mod    a0, a1, a2");
    COMPARE(ddiv(a0, a1, a2), "00a6209e       ddiv   a0, a1, a2");
    COMPARE(dmod(a0, a1, a2), "00a620de       dmod   a0, a1, a2");
    COMPARE(div(a5, a6, a7), "014b489a       div    a5, a6, a7");
    COMPARE(mod(a5, a6, a7), "014b48da       mod    a5, a6, a7");
    COMPARE(ddiv(a5, a6, a7), "014b489e       ddiv   a5, a6, a7");
    COMPARE(dmod(a5, a6, a7), "014b48de       dmod   a5, a6, a7");
    COMPARE(div(v0, v1, a0), "0064109a       div    v0, v1, a0");
    COMPARE(mod(v0, v1, a0), "006410da       mod    v0, v1, a0");
    COMPARE(ddiv(v0, v1, a0), "0064109e       ddiv   v0, v1, a0");
    COMPARE(dmod(v0, v1, a0), "006410de       dmod   v0, v1, a0");

    COMPARE(divu(a0, a1, a2), "00a6209b       divu   a0, a1, a2");
    COMPARE(modu(a0, a1, a2), "00a620db       modu   a0, a1, a2");
    COMPARE(ddivu(a0, a1, a2), "00a6209f       ddivu  a0, a1, a2");
    COMPARE(dmodu(a0, a1, a2), "00a620df       dmodu  a0, a1, a2");
    COMPARE(divu(a5, a6, a7), "014b489b       divu   a5, a6, a7");
    COMPARE(modu(a5, a6, a7), "014b48db       modu   a5, a6, a7");
    COMPARE(ddivu(a5, a6, a7), "014b489f       ddivu  a5, a6, a7");
    COMPARE(dmodu(a5, a6, a7), "014b48df       dmodu  a5, a6, a7");
    COMPARE(divu(v0, v1, a0), "0064109b       divu   v0, v1, a0");
    COMPARE(modu(v0, v1, a0), "006410db       modu   v0, v1, a0");
    COMPARE(ddivu(v0, v1, a0), "0064109f       ddivu  v0, v1, a0");
    COMPARE(dmodu(v0, v1, a0), "006410df       dmodu  v0, v1, a0");
  }

  COMPARE(addiu(a0, a1, 0x0), "24a40000       addiu   a0, a1, 0");
  COMPARE(addiu(s0, s1, 32767), "26307fff       addiu   s0, s1, 32767");
  COMPARE(addiu(a6, a7, -32768), "256a8000       addiu   a6, a7, -32768");
  COMPARE(addiu(v0, v1, -1), "2462ffff       addiu   v0, v1, -1");
  COMPARE(daddiu(a0, a1, 0x0), "64a40000       daddiu  a0, a1, 0");
  COMPARE(daddiu(s0, s1, 32767), "66307fff       daddiu  s0, s1, 32767");
  COMPARE(daddiu(a6, a7, -32768), "656a8000       daddiu  a6, a7, -32768");
  COMPARE(daddiu(v0, v1, -1), "6462ffff       daddiu  v0, v1, -1");

  COMPARE(and_(a0, a1, a2), "00a62024       and     a0, a1, a2");
  COMPARE(and_(s0, s1, s2), "02328024       and     s0, s1, s2");
  COMPARE(and_(a6, a7, t0), "016c5024       and     a6, a7, t0");
  COMPARE(and_(v0, v1, a2), "00661024       and     v0, v1, a2");

  COMPARE(or_(a0, a1, a2), "00a62025       or      a0, a1, a2");
  COMPARE(or_(s0, s1, s2), "02328025       or      s0, s1, s2");
  COMPARE(or_(a6, a7, t0), "016c5025       or      a6, a7, t0");
  COMPARE(or_(v0, v1, a2), "00661025       or      v0, v1, a2");

  COMPARE(xor_(a0, a1, a2), "00a62026       xor     a0, a1, a2");
  COMPARE(xor_(s0, s1, s2), "02328026       xor     s0, s1, s2");
  COMPARE(xor_(a6, a7, t0), "016c5026       xor     a6, a7, t0");
  COMPARE(xor_(v0, v1, a2), "00661026       xor     v0, v1, a2");

  COMPARE(nor(a0, a1, a2), "00a62027       nor     a0, a1, a2");
  COMPARE(nor(s0, s1, s2), "02328027       nor     s0, s1, s2");
  COMPARE(nor(a6, a7, t0), "016c5027       nor     a6, a7, t0");
  COMPARE(nor(v0, v1, a2), "00661027       nor     v0, v1, a2");

  COMPARE(andi(a0, a1, 0x1), "30a40001       andi    a0, a1, 0x1");
  COMPARE(andi(v0, v1, 0xffff), "3062ffff       andi    v0, v1, 0xffff");

  COMPARE(ori(a0, a1, 0x1), "34a40001       ori     a0, a1, 0x1");
  COMPARE(ori(v0, v1, 0xffff), "3462ffff       ori     v0, v1, 0xffff");

  COMPARE(xori(a0, a1, 0x1), "38a40001       xori    a0, a1, 0x1");
  COMPARE(xori(v0, v1, 0xffff), "3862ffff       xori    v0, v1, 0xffff");

  COMPARE(lui(a0, 0x1), "3c040001       lui     a0, 0x1");
  COMPARE(lui(v0, 0xffff), "3c02ffff       lui     v0, 0xffff");

  if (kArchVariant == (kMips64r6)) {
    COMPARE(aui(a0, a1, 0x1), "3ca40001       aui     a0, a1, 0x1");
    COMPARE(aui(v0, v1, 0xffff), "3c62ffff       aui     v0, v1, 0xffff");

    COMPARE(daui(a0, a1, 0x1), "74a40001       daui    a0, a1, 0x1");
    COMPARE(daui(v0, v1, 0xffff), "7462ffff       daui    v0, v1, 0xffff");

    COMPARE(dahi(a0, 0x1), "04860001       dahi    a0, 0x1");
    COMPARE(dahi(v0, 0xffff), "0446ffff       dahi    v0, 0xffff");

    COMPARE(dati(a0, 0x1), "049e0001       dati    a0, 0x1");
    COMPARE(dati(v0, 0xffff), "045effff       dati    v0, 0xffff");
  }

  COMPARE(sll(a0, a1, 0), "00052000       sll     a0, a1, 0");
  COMPARE(sll(s0, s1, 8), "00118200       sll     s0, s1, 8");
  COMPARE(sll(a6, a7, 24), "000b5600       sll     a6, a7, 24");
  COMPARE(sll(v0, v1, 31), "000317c0       sll     v0, v1, 31");
  COMPARE(dsll(a0, a1, 0), "00052038       dsll    a0, a1, 0");
  COMPARE(dsll(s0, s1, 8), "00118238       dsll    s0, s1, 8");
  COMPARE(dsll(a6, a7, 24), "000b5638       dsll    a6, a7, 24");
  COMPARE(dsll(v0, v1, 31), "000317f8       dsll    v0, v1, 31");

  COMPARE(sllv(a0, a1, a2), "00c52004       sllv    a0, a1, a2");
  COMPARE(sllv(s0, s1, s2), "02518004       sllv    s0, s1, s2");
  COMPARE(sllv(a6, a7, t0), "018b5004       sllv    a6, a7, t0");
  COMPARE(sllv(v0, v1, fp), "03c31004       sllv    v0, v1, fp");
  COMPARE(dsllv(a0, a1, a2), "00c52014       dsllv   a0, a1, a2");
  COMPARE(dsllv(s0, s1, s2), "02518014       dsllv   s0, s1, s2");
  COMPARE(dsllv(a6, a7, t0), "018b5014       dsllv   a6, a7, t0");
  COMPARE(dsllv(v0, v1, fp), "03c31014       dsllv   v0, v1, fp");

  COMPARE(srl(a0, a1, 0), "00052002       srl     a0, a1, 0");
  COMPARE(srl(s0, s1, 8), "00118202       srl     s0, s1, 8");
  COMPARE(srl(a6, a7, 24), "000b5602       srl     a6, a7, 24");
  COMPARE(srl(v0, v1, 31), "000317c2       srl     v0, v1, 31");
  COMPARE(dsrl(a0, a1, 0), "0005203a       dsrl    a0, a1, 0");
  COMPARE(dsrl(s0, s1, 8), "0011823a       dsrl    s0, s1, 8");
  COMPARE(dsrl(a6, a7, 24), "000b563a       dsrl    a6, a7, 24");
  COMPARE(dsrl(v0, v1, 31), "000317fa       dsrl    v0, v1, 31");

  COMPARE(srlv(a0, a1, a2), "00c52006       srlv    a0, a1, a2");
  COMPARE(srlv(s0, s1, s2), "02518006       srlv    s0, s1, s2");
  COMPARE(srlv(a6, a7, t0), "018b5006       srlv    a6, a7, t0");
  COMPARE(srlv(v0, v1, fp), "03c31006       srlv    v0, v1, fp");
  COMPARE(dsrlv(a0, a1, a2), "00c52016       dsrlv   a0, a1, a2");
  COMPARE(dsrlv(s0, s1, s2), "02518016       dsrlv   s0, s1, s2");
  COMPARE(dsrlv(a6, a7, t0), "018b5016       dsrlv   a6, a7, t0");
  COMPARE(dsrlv(v0, v1, fp), "03c31016       dsrlv   v0, v1, fp");

  COMPARE(sra(a0, a1, 0), "00052003       sra     a0, a1, 0");
  COMPARE(sra(s0, s1, 8), "00118203       sra     s0, s1, 8");
  COMPARE(sra(a6, a7, 24), "000b5603       sra     a6, a7, 24");
  COMPARE(sra(v0, v1, 31), "000317c3       sra     v0, v1, 31");
  COMPARE(dsra(a0, a1, 0), "0005203b       dsra    a0, a1, 0");
  COMPARE(dsra(s0, s1, 8), "0011823b       dsra    s0, s1, 8");
  COMPARE(dsra(a6, a7, 24), "000b563b       dsra    a6, a7, 24");
  COMPARE(dsra(v0, v1, 31), "000317fb       dsra    v0, v1, 31");

  COMPARE(srav(a0, a1, a2), "00c52007       srav    a0, a1, a2");
  COMPARE(srav(s0, s1, s2), "02518007       srav    s0, s1, s2");
  COMPARE(srav(a6, a7, t0), "018b5007       srav    a6, a7, t0");
  COMPARE(srav(v0, v1, fp), "03c31007       srav    v0, v1, fp");
  COMPARE(dsrav(a0, a1, a2), "00c52017       dsrav   a0, a1, a2");
  COMPARE(dsrav(s0, s1, s2), "02518017       dsrav   s0, s1, s2");
  COMPARE(dsrav(a6, a7, t0), "018b5017       dsrav   a6, a7, t0");
  COMPARE(dsrav(v0, v1, fp), "03c31017       dsrav   v0, v1, fp");

  COMPARE(rotr(a0, a1, 0), "00252002       rotr    a0, a1, 0");
  COMPARE(rotr(s0, s1, 8), "00318202       rotr    s0, s1, 8");
  COMPARE(rotr(a6, a7, 24), "002b5602       rotr    a6, a7, 24");
  COMPARE(rotr(v0, v1, 31), "002317c2       rotr    v0, v1, 31");
  COMPARE(drotr(a0, a1, 0), "0025203a       drotr   a0, a1, 0");
  COMPARE(drotr(s0, s1, 8), "0031823a       drotr   s0, s1, 8");
  COMPARE(drotr(a6, a7, 24), "002b563a       drotr   a6, a7, 24");
  COMPARE(drotr(v0, v1, 31), "002317fa       drotr   v0, v1, 31");

  COMPARE(drotr32(a0, a1, 0), "0025203e       drotr32 a0, a1, 0");
  COMPARE(drotr32(s0, s1, 8), "0031823e       drotr32 s0, s1, 8");
  COMPARE(drotr32(a6, a7, 24), "002b563e       drotr32 a6, a7, 24");
  COMPARE(drotr32(v0, v1, 31), "002317fe       drotr32 v0, v1, 31");

  COMPARE(rotrv(a0, a1, a2), "00c52046       rotrv   a0, a1, a2");
  COMPARE(rotrv(s0, s1, s2), "02518046       rotrv   s0, s1, s2");
  COMPARE(rotrv(a6, a7, t0), "018b5046       rotrv   a6, a7, t0");
  COMPARE(rotrv(v0, v1, fp), "03c31046       rotrv   v0, v1, fp");
  COMPARE(drotrv(a0, a1, a2), "00c52056       drotrv  a0, a1, a2");
  COMPARE(drotrv(s0, s1, s2), "02518056       drotrv  s0, s1, s2");
  COMPARE(drotrv(a6, a7, t0), "018b5056       drotrv  a6, a7, t0");
  COMPARE(drotrv(v0, v1, fp), "03c31056       drotrv  v0, v1, fp");

  COMPARE(break_(0), "0000000d       break, code: 0x00000 (0)");
  COMPARE(break_(261120), "00ff000d       break, code: 0x3fc00 (261120)");
  COMPARE(break_(1047552), "03ff000d       break, code: 0xffc00 (1047552)");

  COMPARE(tge(a0, a1, 0), "00850030       tge     a0, a1, code: 0x000");
  COMPARE(tge(s0, s1, 1023), "0211fff0       tge     s0, s1, code: 0x3ff");
  COMPARE(tgeu(a0, a1, 0), "00850031       tgeu    a0, a1, code: 0x000");
  COMPARE(tgeu(s0, s1, 1023), "0211fff1       tgeu    s0, s1, code: 0x3ff");
  COMPARE(tlt(a0, a1, 0), "00850032       tlt     a0, a1, code: 0x000");
  COMPARE(tlt(s0, s1, 1023), "0211fff2       tlt     s0, s1, code: 0x3ff");
  COMPARE(tltu(a0, a1, 0), "00850033       tltu    a0, a1, code: 0x000");
  COMPARE(tltu(s0, s1, 1023), "0211fff3       tltu    s0, s1, code: 0x3ff");
  COMPARE(teq(a0, a1, 0), "00850034       teq     a0, a1, code: 0x000");
  COMPARE(teq(s0, s1, 1023), "0211fff4       teq     s0, s1, code: 0x3ff");
  COMPARE(tne(a0, a1, 0), "00850036       tne     a0, a1, code: 0x000");
  COMPARE(tne(s0, s1, 1023), "0211fff6       tne     s0, s1, code: 0x3ff");

  COMPARE(mfhi(a0), "00002010       mfhi    a0");
  COMPARE(mfhi(s2), "00009010       mfhi    s2");
  COMPARE(mfhi(t0), "00006010       mfhi    t0");
  COMPARE(mfhi(v1), "00001810       mfhi    v1");
  COMPARE(mflo(a0), "00002012       mflo    a0");
  COMPARE(mflo(s2), "00009012       mflo    s2");
  COMPARE(mflo(t0), "00006012       mflo    t0");
  COMPARE(mflo(v1), "00001812       mflo    v1");

  COMPARE(slt(a0, a1, a2), "00a6202a       slt     a0, a1, a2");
  COMPARE(slt(s0, s1, s2), "0232802a       slt     s0, s1, s2");
  COMPARE(slt(a6, a7, t0), "016c502a       slt     a6, a7, t0");
  COMPARE(slt(v0, v1, a2), "0066102a       slt     v0, v1, a2");
  COMPARE(sltu(a0, a1, a2), "00a6202b       sltu    a0, a1, a2");
  COMPARE(sltu(s0, s1, s2), "0232802b       sltu    s0, s1, s2");
  COMPARE(sltu(a6, a7, t0), "016c502b       sltu    a6, a7, t0");
  COMPARE(sltu(v0, v1, a2), "0066102b       sltu    v0, v1, a2");

  COMPARE(slti(a0, a1, 0), "28a40000       slti    a0, a1, 0");
  COMPARE(slti(s0, s1, 32767), "2a307fff       slti    s0, s1, 32767");
  COMPARE(slti(a6, a7, -32768), "296a8000       slti    a6, a7, -32768");
  COMPARE(slti(v0, v1, -1), "2862ffff       slti    v0, v1, -1");
  COMPARE(sltiu(a0, a1, 0), "2ca40000       sltiu   a0, a1, 0");
  COMPARE(sltiu(s0, s1, 32767), "2e307fff       sltiu   s0, s1, 32767");
  COMPARE(sltiu(a6, a7, -32768), "2d6a8000       sltiu   a6, a7, -32768");
  COMPARE(sltiu(v0, v1, -1), "2c62ffff       sltiu   v0, v1, -1");
  COMPARE(movz(a0, a1, a2), "00a6200a       movz    a0, a1, a2");
  COMPARE(movz(s0, s1, s2), "0232800a       movz    s0, s1, s2");
  COMPARE(movz(a6, a7, t0), "016c500a       movz    a6, a7, t0");
  COMPARE(movz(v0, v1, a2), "0066100a       movz    v0, v1, a2");
  COMPARE(movn(a0, a1, a2), "00a6200b       movn    a0, a1, a2");
  COMPARE(movn(s0, s1, s2), "0232800b       movn    s0, s1, s2");
  COMPARE(movn(a6, a7, t0), "016c500b       movn    a6, a7, t0");
  COMPARE(movn(v0, v1, a2), "0066100b       movn    v0, v1, a2");

  COMPARE(movt(a0, a1, 1), "00a52001       movt    a0, a1, 1");
  COMPARE(movt(s0, s1, 2), "02298001       movt    s0, s1, 2");
  COMPARE(movt(a6, a7, 3), "016d5001       movt    a6, a7, 3");
  COMPARE(movt(v0, v1, 7), "007d1001       movt    v0, v1, 7");
  COMPARE(movf(a0, a1, 0), "00a02001       movf    a0, a1, 0");
  COMPARE(movf(s0, s1, 4), "02308001       movf    s0, s1, 4");
  COMPARE(movf(a6, a7, 5), "01745001       movf    a6, a7, 5");
  COMPARE(movf(v0, v1, 6), "00781001       movf    v0, v1, 6");

  if (kArchVariant == kMips64r6) {
    COMPARE(clz(a0, a1), "00a02050       clz     a0, a1");
    COMPARE(clz(s6, s7), "02e0b050       clz     s6, s7");
    COMPARE(clz(v0, v1), "00601050       clz     v0, v1");
  } else {
    COMPARE(clz(a0, a1), "70a42020       clz     a0, a1");
    COMPARE(clz(s6, s7), "72f6b020       clz     s6, s7");
    COMPARE(clz(v0, v1), "70621020       clz     v0, v1");
  }

  COMPARE(seb(a0, a1), "7c052420       seb     a0, a1");
  COMPARE(seb(s6, s7), "7c17b420       seb     s6, s7");
  COMPARE(seb(v0, v1), "7c031420       seb     v0, v1");

  COMPARE(seh(a0, a1), "7c052620       seh     a0, a1");
  COMPARE(seh(s6, s7), "7c17b620       seh     s6, s7");
  COMPARE(seh(v0, v1), "7c031620       seh     v0, v1");

  COMPARE(wsbh(a0, a1), "7c0520a0       wsbh    a0, a1");
  COMPARE(wsbh(s6, s7), "7c17b0a0       wsbh    s6, s7");
  COMPARE(wsbh(v0, v1), "7c0310a0       wsbh    v0, v1");

  COMPARE(dsbh(a0, a1), "7c0520a4       dsbh    a0, a1");
  COMPARE(dsbh(s6, s7), "7c17b0a4       dsbh    s6, s7");
  COMPARE(dsbh(v0, v1), "7c0310a4       dsbh    v0, v1");

  COMPARE(dshd(a0, a1), "7c052164       dshd    a0, a1");
  COMPARE(dshd(s6, s7), "7c17b164       dshd    s6, s7");
  COMPARE(dshd(v0, v1), "7c031164       dshd    v0, v1");

  COMPARE(ext_(a0, a1, 31, 1), "7ca407c0       ext     a0, a1, 31, 1");
  COMPARE(ext_(s6, s7, 30, 2), "7ef60f80       ext     s6, s7, 30, 2");
  COMPARE(ext_(v0, v1, 0, 32), "7c62f800       ext     v0, v1, 0, 32");

  COMPARE(dext_(a0, a1, 31, 1), "7ca407c3       dext    a0, a1, 31, 1");
  COMPARE(dext_(s6, s7, 30, 2), "7ef60f83       dext    s6, s7, 30, 2");
  COMPARE(dext_(v0, v1, 0, 32), "7c62f803       dext    v0, v1, 0, 32");

  COMPARE(dextm_(a0, a1, 31, 33), "7ca407c1       dextm   a0, a1, 31, 33");
  COMPARE(dextm_(s6, s7, 0, 33), "7ef60001       dextm   s6, s7, 0, 33");
  COMPARE(dextm_(v0, v1, 0, 64), "7c62f801       dextm   v0, v1, 0, 64");

  COMPARE(dextu_(a0, a1, 32, 1), "7ca40002       dextu   a0, a1, 32, 1");
  COMPARE(dextu_(s6, s7, 63, 1), "7ef607c2       dextu   s6, s7, 63, 1");
  COMPARE(dextu_(v0, v1, 32, 32), "7c62f802       dextu   v0, v1, 32, 32");

  COMPARE(ins_(a0, a1, 31, 1), "7ca4ffc4       ins     a0, a1, 31, 1");
  COMPARE(ins_(s6, s7, 30, 2), "7ef6ff84       ins     s6, s7, 30, 2");
  COMPARE(ins_(v0, v1, 0, 32), "7c62f804       ins     v0, v1, 0, 32");

  COMPARE(dins_(a0, a1, 31, 1), "7ca4ffc7       dins    a0, a1, 31, 1");
  COMPARE(dins_(s6, s7, 30, 2), "7ef6ff87       dins    s6, s7, 30, 2");
  COMPARE(dins_(v0, v1, 0, 32), "7c62f807       dins    v0, v1, 0, 32");

  COMPARE(dinsm_(a0, a1, 31, 2), "7ca407c5       dinsm   a0, a1, 31, 2");
  COMPARE(dinsm_(s6, s7, 0, 33), "7ef60005       dinsm   s6, s7, 0, 33");
  COMPARE(dinsm_(v0, v1, 0, 64), "7c62f805       dinsm   v0, v1, 0, 64");

  COMPARE(dinsu_(a0, a1, 32, 1), "7ca40006       dinsu   a0, a1, 32, 1");
  COMPARE(dinsu_(s6, s7, 63, 1), "7ef6ffc6       dinsu   s6, s7, 63, 1");
  COMPARE(dinsu_(v0, v1, 32, 32), "7c62f806       dinsu   v0, v1, 32, 32");

  COMPARE(add_s(f4, f6, f8), "46083100       add.s   f4, f6, f8");
  COMPARE(add_d(f12, f14, f16), "46307300       add.d   f12, f14, f16");

  if (kArchVariant == kMips64r6) {
    COMPARE(bitswap(a0, a1), "7c052020       bitswap a0, a1");
    COMPARE(bitswap(t8, s0), "7c10c020       bitswap t8, s0");
    COMPARE(dbitswap(a0, a1), "7c052024       dbitswap a0, a1");
    COMPARE(dbitswap(t8, s0), "7c10c024       dbitswap t8, s0");
  }

  COMPARE(abs_s(f6, f8), "46004185       abs.s   f6, f8");
  COMPARE(abs_d(f10, f12), "46206285       abs.d   f10, f12");

  COMPARE(div_s(f2, f4, f6), "46062083       div.s   f2, f4, f6");
  COMPARE(div_d(f2, f4, f6), "46262083       div.d   f2, f4, f6");

  if (kArchVariant == kMips64r6) {
    COMPARE(align(v0, a0, a1, 0), "7c851220       align  v0, a0, a1, 0");
    COMPARE(align(v0, a0, a1, 1), "7c851260       align  v0, a0, a1, 1");
    COMPARE(align(v0, a0, a1, 2), "7c8512a0       align  v0, a0, a1, 2");
    COMPARE(align(v0, a0, a1, 3), "7c8512e0       align  v0, a0, a1, 3");
  }

  if (kArchVariant == kMips64r6) {
    COMPARE(dalign(v0, a0, a1, 0), "7c851224       dalign  v0, a0, a1, 0");
    COMPARE(dalign(v0, a0, a1, 1), "7c851264       dalign  v0, a0, a1, 1");
    COMPARE(dalign(v0, a0, a1, 2), "7c8512a4       dalign  v0, a0, a1, 2");
    COMPARE(dalign(v0, a0, a1, 3), "7c8512e4       dalign  v0, a0, a1, 3");
    COMPARE(dalign(v0, a0, a1, 4), "7c851324       dalign  v0, a0, a1, 4");
    COMPARE(dalign(v0, a0, a1, 5), "7c851364       dalign  v0, a0, a1, 5");
    COMPARE(dalign(v0, a0, a1, 6), "7c8513a4       dalign  v0, a0, a1, 6");
    COMPARE(dalign(v0, a0, a1, 7), "7c8513e4       dalign  v0, a0, a1, 7");
  }

  if (kArchVariant == kMips64r6) {
    COMPARE(aluipc(v0, 0), "ec5f0000       aluipc  v0, 0");
    COMPARE(aluipc(v0, 1), "ec5f0001       aluipc  v0, 1");
    COMPARE(aluipc(v0, 32767), "ec5f7fff       aluipc  v0, 32767");
    COMPARE(aluipc(v0, -32768), "ec5f8000       aluipc  v0, -32768");
    COMPARE(aluipc(v0, -1), "ec5fffff       aluipc  v0, -1");
  }

  if (kArchVariant == kMips64r6) {
    COMPARE(auipc(t8, 0), "ef1e0000       auipc   t8, 0");
    COMPARE(auipc(t8, 1), "ef1e0001       auipc   t8, 1");
    COMPARE(auipc(t8, 32767), "ef1e7fff       auipc   t8, 32767");
    COMPARE(auipc(t8, -32768), "ef1e8000       auipc   t8, -32768");
    COMPARE(auipc(t8, -1), "ef1effff       auipc   t8, -1");
  }

  if (kArchVariant == kMips64r6) {
    COMPARE(lwpc(a5, 0), "ed280000       lwpc    a5, 0");
    COMPARE(lwpc(a5, 4), "ed280004       lwpc    a5, 4");
    COMPARE(lwpc(a5, -4), "ed2ffffc       lwpc    a5, -4");
  }

  if (kArchVariant == kMips64r6) {
    COMPARE(lwupc(a0, -262144), "ec940000       lwupc   a0, -262144");
    COMPARE(lwupc(a0, -1), "ec97ffff       lwupc   a0, -1");
    COMPARE(lwupc(a0, 0), "ec900000       lwupc   a0, 0");
    COMPARE(lwupc(a0, 1), "ec900001       lwupc   a0, 1");
    COMPARE(lwupc(a0, 262143), "ec93ffff       lwupc   a0, 262143");
  }

  if (kArchVariant == kMips64r6) {
    COMPARE(jic(t0, 16), "d80c0010       jic     t0, 16");
    COMPARE(jic(t0, 4), "d80c0004       jic     t0, 4");
    COMPARE(jic(t0, -32), "d80cffe0       jic     t0, -32");
  }

  if (kArchVariant == kMips64r6) {
    COMPARE(ldpc(v0, 256), "ec580100       ldpc    v0, 256");
    COMPARE(ldpc(a0, -1), "ec9bffff       ldpc    a0, -1");
    COMPARE(ldpc(a1, 0), "ecb80000       ldpc    a1, 0");
  }

  if (kArchVariant == kMips64r6) {
    COMPARE(addiupc(a0, 262143), "ec83ffff       addiupc a0, 262143");
    COMPARE(addiupc(a0, -1), "ec87ffff       addiupc a0, -1");
    COMPARE(addiupc(v0, 0), "ec400000       addiupc v0, 0");
    COMPARE(addiupc(s1, 1), "ee200001       addiupc s1, 1");
    COMPARE(addiupc(a0, -262144), "ec840000       addiupc a0, -262144");
  }

  if (kArchVariant == kMips64r6) {
    COMPARE(jialc(a0, -32768), "f8048000       jialc   a0, -32768");
    COMPARE(jialc(a0, -1), "f804ffff       jialc   a0, -1");
    COMPARE(jialc(v0, 0), "f8020000       jialc   v0, 0");
    COMPARE(jialc(s1, 1), "f8110001       jialc   s1, 1");
    COMPARE(jialc(a0, 32767), "f8047fff       jialc   a0, 32767");
  }

  VERIFY_RUN();
}

TEST_F(DisasmMips64Test, Type1) {
  SET_UP();
  if (kArchVariant == kMips64r6) {
    COMPARE(seleqz(a0, a1, a2), "00a62035       seleqz    a0, a1, a2");
    COMPARE(selnez(a0, a1, a2), "00a62037       selnez    a0, a1, a2");

    COMPARE(seleqz(D, f3, f4, f5), "462520d4       seleqz.d
```