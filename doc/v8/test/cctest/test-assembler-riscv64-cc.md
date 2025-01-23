Response:
Let's break down the thought process for analyzing this C++ code snippet.

1. **Understand the Context:** The first thing to notice is the file path: `v8/test/cctest/test-assembler-riscv64.cc`. This immediately tells us this is a *test file* within the V8 JavaScript engine project. The `riscv64` part indicates it's specifically for testing the RISC-V 64-bit architecture. The `assembler` part suggests it's testing the assembly code generation capabilities of V8 for this architecture.

2. **Initial Code Scan (Top-Down):**
    * **Copyright and License:** Standard boilerplate, indicating open-source nature and usage terms. Not directly functional but important for legal reasons.
    * **Includes:**  These are crucial. They reveal the dependencies and what kind of functionalities are being used. We see things like:
        * `<math.h>`:  Math functions (likely used in floating-point tests).
        * `<iostream>`:  Input/output (might be for debugging, though the testing framework likely handles output).
        * `"src/base/utils/random-number-generator.h"`:  Potentially for generating random test cases.
        * `"src/codegen/assembler-inl.h"`, `"src/codegen/macro-assembler.h"`:  Key V8 headers related to assembly code generation. This confirms the core purpose of the file.
        * `"src/diagnostics/disassembler.h"`:  Suggests the tests might involve disassembling generated code for verification.
        * `"src/execution/simulator.h"`:  Indicates that the generated assembly code is likely executed within a simulator (common for testing target architectures without requiring actual hardware).
        * `"src/heap/factory.h"`, `"src/init/v8.h"`:  V8 core components, implying interaction with the V8 runtime environment.
        * `"src/utils/utils.h"`: General utility functions.
        * `"test/cctest/cctest.h"`, `"test/cctest/test-helper-riscv64.h"`, `"test/common/value-helper.h"`:  Headers related to the V8's testing framework, confirming this is a test file.

3. **Type Definitions:** The `using F1`, `F2`, etc., define function pointer types. These likely represent the signatures of functions that will be generated and executed by the assembler. The naming suggests different argument counts and types.

4. **Macros:** The `#define` directives are essential. They define reusable test structures:
    * `MIN_VAL_IMM12`, `LARGE_INT_EXCEED_32_BIT`, etc.: These define specific test values, revealing the focus on testing edge cases and different data sizes.
    * `__ assm.`:  A shorthand for accessing the `MacroAssembler` object.
    * `UTEST_R2_FORM_WITH_RES`, `UTEST_I_FORM_WITH_RES`, etc.: These are the core test case definition macros. Deconstructing one of them (`UTEST_R2_FORM_WITH_RES`) is key:
        * `TEST(RISCV_UTEST_##instr_name)`: Uses the V8 testing framework's `TEST` macro to define an individual test.
        * `CcTest::InitializeVM()`:  Sets up the V8 environment for the test.
        * `auto fn = [](MacroAssembler& assm) { __ instr_name(a0, a0, a1); };`: Defines a lambda function that takes a `MacroAssembler` object and uses it to emit an assembly instruction (`instr_name`). The `a0`, `a1` likely represent RISC-V registers.
        * `auto res = GenAndRunTest<type, type>(rs1_val, rs2_val, fn);`:  This is a crucial helper function (likely defined in `test-helper-riscv64.h`). It generates assembly code based on `fn`, runs it with input values `rs1_val` and `rs2_val`, and returns the result. The template arguments specify the data types.
        * `CHECK_EQ(expected_res, res);`:  Asserts that the actual result matches the expected result.

5. **Test Case Analysis (Spot Checks):** Looking at the individual `UTEST_*` calls provides concrete examples of what's being tested:
    * `UTEST_LOAD_STORE`: Tests basic load and store instructions for different data sizes (int64_t, int32_t, etc.).
    * `UTEST_I_FORM_WITH_OP(addi, ...)`: Tests the `addi` (add immediate) instruction.
    * `UTEST_R2_FORM_WITH_OP(add, ...)`: Tests the `add` (register-register add) instruction.
    * `UTEST_CSRI`, `UTEST_CSR`: Tests instructions related to Control and Status Registers (CSRs), which are specific to processor architectures.
    * `UTEST_LR_SC`, `UTEST_AMO_WITH_RES`: Tests atomic memory operations.
    * The `_F` suffixes indicate tests for floating-point instructions.

6. **Connecting to JavaScript (if applicable):** Since this is an assembler test, the connection to JavaScript is indirect. The assembler is responsible for generating the low-level code that *implements* JavaScript features. For example, if there's a JavaScript addition operation (`+`), the V8 compiler might generate RISC-V `add` instructions (tested here) to perform that operation at the machine level.

7. **Identifying Potential Programming Errors:** The tests themselves highlight potential errors in the assembler implementation. For instance, incorrect handling of sign extension in load instructions (`lw`, `lh`, `lb`) or incorrect implementation of arithmetic operations.

8. **Inferring Overall Functionality:** Based on the includes, macros, and test cases, the primary function of this file is to **thoroughly test the RISC-V 64-bit assembler within the V8 JavaScript engine.**  It checks the correctness of individual instructions, their behavior with different operands, and their interaction with the processor state (CSRs).

9. **Considering the `.tq` Check:** The prompt asks about `.tq` files. Since this file is `.cc`, it's a standard C++ file, *not* a Torque file. Torque is V8's domain-specific language for implementing built-in functions. If it were a `.tq` file, it would be defining the logic of a built-in JavaScript function at a higher level than assembly.

10. **Structuring the Summary:** Finally, organize the findings into a coherent summary, addressing each point in the prompt (functionality, `.tq` check, JavaScript relation, logic, errors, and the overall purpose).
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

#include <math.h>

#include <iostream>

#include "src/base/utils/random-number-generator.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/diagnostics/disassembler.h"
#include "src/execution/simulator.h"
#include "src/heap/factory.h"
#include "src/init/v8.h"
#include "src/utils/utils.h"
#include "test/cctest/cctest.h"
#include "test/cctest/test-helper-riscv64.h"
#include "test/common/value-helper.h"

namespace v8 {
namespace internal {

// Define these function prototypes to match JSEntryFunction in execution.cc
using F1 = void*(int x, int p1, int p2, int p3, int p4);
using F2 = void*(int x, int y, int p2, int p3, int p4);
using F3 = void*(void* p, int p1, int p2, int p3, int p4);
using F4 = void*(int64_t x, int64_t y, int64_t p2, int64_t p3, int64_t p4);
using F5 = void*(void* p0, void* p1, int p2, int p3, int p4);

#define MIN_VAL_IMM12 -(1 << 11)
#define LARGE_INT_EXCEED_32_BIT 0x01C9'1075'0321'FB01LL
#define LARGE_INT_UNDER_32_BIT 0x1234'5678
#define LARGE_UINT_EXCEED_32_BIT 0xFDCB'1234'A034'5691ULL

#define __ assm.

#define UTEST_R2_FORM_WITH_RES(instr_name, type, rs1_val, rs2_val,     \
                               expected_res)                           \
  TEST(RISCV_UTEST_##instr_name) {                                     \
    CcTest::InitializeVM();                                            \
    auto fn = [](MacroAssembler& assm) { __ instr_name(a0, a0, a1); }; \
    auto res = GenAndRunTest<type, type>(rs1_val, rs2_val, fn);        \
    CHECK_EQ(expected_res, res);                                       \
  }

#define UTEST_R1_FORM_WITH_RES(instr_name, in_type, out_type, rs1_val, \
                               expected_res)                           \
  TEST(RISCV_UTEST_##instr_name) {                                     \
    CcTest::InitializeVM();                                            \
    auto fn = [](MacroAssembler& assm) { __ instr_name(a0, a0); };     \
    auto res = GenAndRunTest<out_type, in_type>(rs1_val, fn);          \
    CHECK_EQ(expected_res, res);                                       \
  }

#define UTEST_R1_FORM_WITH_RES_C(instr_name, in_type, out_type, rs1_val, \
                                 expected_res)                           \
  TEST(RISCV_UTEST_##instr_name) {                                       \
    i::v8_flags.riscv_c_extension = true;                                \
    CcTest::InitializeVM();                                              \
    auto fn = [](MacroAssembler& assm) { __ instr_name(a0, a0); };       \
    auto res = GenAndRunTest<out_type, in_type>(rs1_val, fn);            \
    CHECK_EQ(expected_res, res);                                         \
  }

#define UTEST_I_FORM_WITH_RES(instr_name, type, rs1_val, imm12, expected_res) \
  TEST(RISCV_UTEST_##instr_name) {                                            \
    CcTest::InitializeVM();                                                   \
    CHECK_EQ(is_intn(imm12, 12), true);                                       \
    auto fn = [](MacroAssembler& assm) { __ instr_name(a0, a0, imm12); };     \
    auto res = GenAndRunTest<type, type>(rs1_val, fn);                        \
    CHECK_EQ(expected_res, res);                                              \
  }

#define UTEST_AMO_WITH_RES(instr_name, aq, rl, inout_type, rs1_val, rs2_val,   \
                           expected_res)                                       \
  TEST(RISCV_UTEST_##instr_name) {                                             \
    CcTest::InitializeVM();                                                    \
    auto fn = [](MacroAssembler& assm) { __ instr_name(aq, rl, a1, a0, a2); }; \
    auto res =                                                                 \
        GenAndRunTestForAMO<inout_type, inout_type>(rs1_val, rs2_val, fn);     \
    CHECK_EQ(expected_res, res);                                               \
  }

#define UTEST_LOAD_STORE(ldname, stname, value_type, value) \
  TEST(RISCV_UTEST_##stname##ldname) {                      \
    CcTest::InitializeVM();                                 \
    auto fn = [](MacroAssembler& assm) {                    \
      __ stname(a1, a0, 0);                                 \
      __ ldname(a0, a0, 0);                                 \
    };                                                      \
    GenAndRunTestForLoadStore<value_type>(value, fn);       \
  }

// Since f.Call() is implemented as vararg calls and RISCV calling convention
// passes all vararg arguments and returns (including floats) in GPRs, we have
// to move from GPR to FPR and back in all floating point tests
#define UTEST_LOAD_STORE_F(ldname, stname, value_type, store_value) \
  TEST(RISCV_UTEST_##stname##ldname) {                              \
    DCHECK(std::is_floating_point<value_type>::value);              \
                                                                    \
    CcTest::InitializeVM();                                         \
    auto fn = [](MacroAssembler& assm) {                            \
      __ stname(fa0, a0, 0);                                        \
      __ ldname(fa0, a0, 0);                                        \
    };                                                              \
    GenAndRunTestForLoadStore<value_type>(store_value, fn);         \
  }

#define UTEST_LR_SC(ldname, stname, aq, rl, value_type, value) \
  TEST(RISCV_UTEST_##stname##ldname) {                         \
    CcTest::InitializeVM();                                    \
    auto fn = [](MacroAssembler& assm) {                       \
      __ ldname(aq, rl, a1, a0);                               \
      __ stname(aq, rl, a0, a0, a1);                           \
    };                                                         \
    GenAndRunTestForLRSC<value_type>(value, fn);               \
  }

#define UTEST_R1_FORM_WITH_RES_F(instr_name, type, rs1_fval, expected_fres) \
  TEST(RISCV_UTEST_##instr_name) {                                          \
    DCHECK(std::is_floating_point<type>::value);                            \
    CcTest::InitializeVM();                                                 \
    auto fn = [](MacroAssembler& assm) { __ instr_name(fa0, fa0); };        \
    auto res = GenAndRunTest<type, type>(rs1_fval, fn);                     \
    CHECK_EQ(expected_fres, res);                                           \
  }

#define UTEST_R2_FORM_WITH_RES_F(instr_name, type, rs1_fval, rs2_fval,    \
                                 expected_fres)                           \
  TEST(RISCV_UTEST_##instr_name) {                                        \
    DCHECK(std::is_floating_point<type>::value);                          \
    CcTest::InitializeVM();                                               \
    auto fn = [](MacroAssembler& assm) { __ instr_name(fa0, fa0, fa1); }; \
    auto res = GenAndRunTest<type, type>(rs1_fval, rs2_fval, fn);         \
    CHECK_EQ(expected_fres, res);                                         \
  }

#define UTEST_R3_FORM_WITH_RES_F(instr_name, type, rs1_fval, rs2_fval,         \
                                 rs3_fval, expected_fres)                      \
  TEST(RISCV_UTEST_##instr_name) {                                             \
    DCHECK(std::is_floating_point<type>::value);                               \
    CcTest::InitializeVM();                                                    \
    auto fn = [](MacroAssembler& assm) { __ instr_name(fa0, fa0, fa1, fa2); }; \
    auto res = GenAndRunTest<type, type>(rs1_fval, rs2_fval, rs3_fval, fn);    \
    CHECK_EQ(expected_fres, res);                                              \
  }

#define UTEST_COMPARE_WITH_RES_F(instr_name, input_type, rs1_fval, rs2_fval, \
                                 expected_res)                               \
  TEST(RISCV_UTEST_##instr_name) {                                           \
    CcTest::InitializeVM();                                                  \
    auto fn = [](MacroAssembler& assm) { __ instr_name(a0, fa0, fa1); };     \
    auto res = GenAndRunTest<int32_t, input_type>(rs1_fval, rs2_fval, fn);   \
    CHECK_EQ(expected_res, res);                                             \
  }

#define UTEST_CONV_F_FROM_I(instr_name, input_type, output_type, rs1_val, \
                            expected_fres)                                \
  TEST(RISCV_UTEST_##instr_name) {                                        \
    DCHECK(std::is_integral<input_type>::value&&                          \
               std::is_floating_point<output_type>::value);               \
                                                                          \
    CcTest::InitializeVM();                                               \
    auto fn = [](MacroAssembler& assm) { __ instr_name(fa0, a0); };       \
    auto res = GenAndRunTest<output_type, input_type>(rs1_val, fn);       \
    CHECK_EQ(expected_fres, res);                                         \
  }

#define UTEST_CONV_I_FROM_F(instr_name, input_type, output_type,     \
                            rounding_mode, rs1_fval, expected_res)   \
  TEST(RISCV_UTEST_##instr_name) {                                   \
    DCHECK(std::is_floating_point<input_type>::value&&               \
               std::is_integral<output_type>::value);                \
                                                                     \
    CcTest::InitializeVM();                                          \
    auto fn = [](MacroAssembler& assm) {                             \
      __ instr_name(a0, fa0, rounding_mode);                         \
    };                                                               \
    auto res = GenAndRunTest<output_type, input_type>(rs1_fval, fn); \
    CHECK_EQ(expected_res, res);                                     \
  }                                                                  \
                                                                     \
  TEST(RISCV_UTEST_dyn_##instr_name) {                               \
    DCHECK(std::is_floating_point<input_type>::value&&               \
               std::is_integral<output_type>::value);                \
                                                                     \
    CcTest::InitializeVM();                                          \
    auto fn = [](MacroAssembler& assm) {                             \
      __ csrwi(csr_frm, rounding_mode);                              \
      __ instr_name(a0, fa0, DYN);                                   \
    };                                                               \
    auto res = GenAndRunTest<output_type, input_type>(rs1_fval, fn); \
    CHECK_EQ(expected_res, res);                                     \
  }

#define UTEST_CONV_F_FROM_F(instr_name, input_type, output_type, rs1_val, \
                            expected_fres)                                \
  TEST(RISCV_UTEST_##instr_name) {                                        \
    CcTest::InitializeVM();                                               \
    auto fn = [](MacroAssembler& assm) { __ instr_name(fa0, fa0); };      \
    auto res = GenAndRunTest<output_type, input_type>(rs1_val, fn);       \
    CHECK_EQ(expected_fres, res);                                         \
  }

#define UTEST_CSRI(csr_reg, csr_write_val, csr_set_clear_val)               \
  TEST(RISCV_UTEST_CSRI_##csr_reg) {                                        \
    CHECK_EQ(is_uint5(csr_write_val) && is_uint5(csr_set_clear_val), true); \
                                                                            \
    CcTest::InitializeVM();                                                 \
    int64_t expected_res = 111;                                             \
    Label exit, error;                                                      \
    auto fn = [&exit, &error, expected_res](MacroAssembler& assm) {         \
      /* test csr-write and csr-read */                                     \
      __ csrwi(csr_reg, csr_write_val);                                     \
      __ csrr(a0, csr_reg);                                                 \
      __ RV_li(a1, csr_write_val);                                          \
      __ bne(a0, a1, &error);                                               \
      /* test csr_set */                                                    \
      __ csrsi(csr_reg, csr_set_clear_val);                                 \
      __ csrr(a0, csr_reg);                                                 \
      __ RV_li(a1, (csr_write_val) | (csr_set_clear_val));                  \
      __ bne(a0, a1, &error);                                               \
      /* test csr_clear */                                                  \
      __ csrci(csr_reg, csr_set_clear_val);                                 \
      __ csrr(a0, csr_reg);                                                 \
      __ RV_li(a1, (csr_write_val) & (~(csr_set_clear_val)));               \
      __ bne(a0, a1, &error);                                               \
      /* everyhing runs correctly, return 111 */                            \
      __ RV_li(a0, expected_res);                                           \
      __ j(&exit);                                                          \
                                                                            \
      __ bind(&error);                                                      \
      /* got an error, return 666 */                                        \
      __ RV_li(a0, 666);                                                    \
                                                                            \
      __ bind(&exit);                                                       \
    };                                                                      \
    auto res = GenAndRunTest(fn);                                           \
    CHECK_EQ(expected_res, res);                                            \
  }

#define UTEST_CSR(csr_reg, csr_write_val, csr_set_clear_val)        \
  TEST(RISCV_UTEST_CSR_##csr_reg) {                                 \
    Label exit, error;                                              \
    int64_t expected_res = 111;                                     \
    auto fn = [&exit, &error, expected_res](MacroAssembler& assm) { \
      /* test csr-write and csr-read */                             \
      __ RV_li(t0, csr_write_val);                                  \
      __ csrw(csr_reg, t0);                                         \
      __ csrr(a0, csr_reg);                                         \
      __ RV_li(a1, csr_write_val);                                  \
      __ bne(a0, a1, &error);                                       \
      /* test csr_set */                                            \
      __ RV_li(t0, csr_set_clear_val);                              \
      __ csrs(csr_reg, t0);                                         \
      __ csrr(a0, csr_reg);                                         \
      __ RV_li(a1, (csr_write_val) | (csr_set_clear_val));          \
      __ bne(a0, a1, &error);                                       \
      /* test csr_clear */                                          \
      __ RV_li(t0, csr_set_clear_val);                              \
      __ csrc(csr_reg, t0);                                         \
      __ csrr(a0, csr_reg);                                         \
      __ RV_li(a1, (csr_write_val) & (~(csr_set_clear_val)));       \
      __ bne(a0, a1, &error);                                       \
      /* everyhing runs correctly, return 111 */                    \
      __ RV_li(a0, expected_res);                                   \
      __ j(&exit);                                                  \
                                                                    \
      __ bind(&error);                                              \
      /* got an error, return 666 */                                \
      __ RV_li(a0, 666);                                            \
                                                                    \
      __ bind(&exit);                                               \
    };                                                              \
                                                                    \
    auto res = GenAndRunTest(fn);                                   \
    CHECK_EQ(expected_res, res);                                    \
  }

#define UTEST_R2_FORM_WITH_OP(instr_name, type, rs1_val, rs2_val, tested_op) \
  UTEST_R2_FORM_WITH_RES(instr_name, type, rs1_val, rs2_val,                 \
                         ((rs1_val)tested_op(rs2_val)))

#define UTEST_I_FORM_WITH_OP(instr_name, type, rs1_val, imm12, tested_op) \
  UTEST_I_FORM_WITH_RES(instr_name, type, rs1_val, imm12,                 \
                        ((rs1_val)tested_op(imm12)))

#define UTEST_R2_FORM_WITH_OP_F(instr_name, type, rs1_fval, rs2_fval, \
                                tested_op)                            \
  UTEST_R2_FORM_WITH_RES_F(instr_name, type, rs1_fval, rs2_fval,      \
                           ((rs1_fval)tested_op(rs2_fval)))

#define UTEST_COMPARE_WITH_OP_F(instr_name, input_type, rs1_fval, rs2_fval, \
                                tested_op)                                  \
  UTEST_COMPARE_WITH_RES_F(instr_name, input_type, rs1_fval, rs2_fval,      \
                           ((rs1_fval)tested_op(rs2_fval)))

// -- test load-store --
UTEST_LOAD_STORE(ld, sd, int64_t, 0xFBB10A9C12345678)
// due to sign-extension of lw
// instruction, value-to-stored must have
// its 32th least significant bit be 0
UTEST_LOAD_STORE(lw, sw, int32_t, 0x456AF894)
// set the 32th least significant bit of
// value-to-store to 1 to test
// zero-extension by lwu
UTEST_LOAD_STORE(lwu, sw, uint32_t, 0x856AF894)
// due to sign-extension of lh
// instruction, value-to-stored must have
// its 16th least significant bit be 0
UTEST_LOAD_STORE(lh, sh, int32_t, 0x7894)
// set the 16th least significant bit of
// value-to-store to 1 to test
// zero-extension by lhu
UTEST_LOAD_STORE(lhu, sh, uint32_t, 0xF894)
// due to sign-extension of lb
// instruction, value-to-stored must have
// its 8th least significant bit be 0
UTEST_LOAD_STORE(lb, sb, int32_t, 0x54)
// set the 8th least significant bit of
// value-to-store to 1 to test
// zero-extension by lbu
UTEST_LOAD_STORE(lbu, sb, uint32_t, 0x94)

// -- arithmetic w/ immediate --
UTEST_I_FORM_WITH_OP(addi, int64_t, LARGE_INT_EXCEED_32_BIT, MIN_VAL_IMM12, +)
UTEST_I_FORM_WITH_OP(slti, int64_t, LARGE_INT_EXCEED_32_BIT, MIN_VAL_IMM12, <)
UTEST_I_FORM_WITH_OP(sltiu, uint64_t, LARGE_UINT_EXCEED_32_BIT, 0x4FB, <)
UTEST_I_FORM_WITH_OP(xori, int64_t, LARGE_INT_EXCEED_32_BIT, MIN_VAL_IMM12, ^)
UTEST_I_FORM_WITH_OP(ori, int64_t, LARGE_INT_EXCEED_32_BIT, MIN_VAL_IMM12, |)
UTEST_I_FORM_WITH_OP(andi, int64_t, LARGE_INT_EXCEED_32_BIT, MIN_VAL_IMM12, &)
UTEST_I_FORM_WITH_OP(slli, int64_t, 0x1234'5678ULL, 33, <<)
UTEST_I_FORM_WITH_OP(srli, int64_t, 0x8234'5678'0000'0000ULL, 33, >>)
UTEST_I_FORM_WITH_OP(srai, int64_t, -0x1234'5678'0000'0000LL, 33, >>)

// -- arithmetic --
UTEST_R2_FORM_WITH_OP(add, int64_t, LARGE_INT_EXCEED_32_BIT, MIN_VAL_IMM12, +)
UTEST_R2_FORM_WITH_OP(sub, int64_t, LARGE_INT_EXCEED_32_BIT, MIN_VAL_IMM12, -)
UTEST_R2_FORM_WITH_OP(slt, int64_t, MIN_VAL_IMM12, LARGE_INT_EXCEED_32_BIT, <)
UTEST_R2_FORM_WITH_OP(sltu, uint64_t, 0x4FB, LARGE_UINT_EXCEED_32_BIT, <)
UTEST_R2_FORM_WITH_OP(xor_, int64_t, LARGE_INT_EXCEED_32_BIT, MIN_VAL_IMM12, ^)
UTEST_R2_FORM_WITH_OP(or_, int64_t, LARGE_INT_EXCEED_32_BIT, MIN_VAL_IMM12, |)
UTEST_R2_FORM_WITH_OP(and_, int64_t, LARGE_INT_EXCEED_32_BIT, MIN_VAL_IMM12, &)
UTEST_R2_FORM_WITH_OP(sll, int64_t, 0x12345678ULL, 33, <<)
UTEST_R2_FORM_WITH_OP(srl, int64_t, 0x8234567800000000ULL, 33, >>)
UTEST_R2_FORM_WITH_OP(sra, int64_t, -0x1234'5678'0000'0000LL, 33, >>)

// -- Memory fences --
// void fence(uint8_t pred, uint8_t succ);
// void fence_tso();

// -- Environment call / break --
// void ecall();
// void ebreak();
// void unimp();

// -- CSR --
UTEST_CSRI(csr_frm, DYN, RUP)
UTEST_CSRI(csr_fflags, kInexact | kInvalidOperation, kInvalidOperation)
UTEST_CSRI(csr_fcsr, kDivideByZero | kFPUOverflow, kUnderflow)
UTEST_CSR(csr_frm, DYN, RUP)
UTEST_CSR(csr_fflags, kInexact | kInvalidOperation, kInvalidOperation)
UTEST_CSR(csr_fcsr, kDivideByZero | kFPUOverflow | (RDN << kFcsrFrmShift),
          kUnderflow | (RNE << kFcsrFrmShift))

// -- RV64I --
UTEST_I_FORM_WITH_OP(addiw, int32_t, LARGE_INT_UNDER_32_BIT, MIN_VAL_IMM12, +)
UTEST_I_FORM_WITH_OP(slliw, int32_t, 0x12345678U, 12, <<)
UTEST_I_FORM_WITH_OP(srliw, int32_t, 0x82345678U, 12, >>)
UTEST_I_FORM_WITH_OP(sraiw, int32_t, -123, 12, >>)

UTEST_R2_FORM_WITH_OP(
### 提示词
```
这是目录为v8/test/cctest/test-assembler-riscv64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-riscv64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能
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

#include <math.h>

#include <iostream>

#include "src/base/utils/random-number-generator.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/diagnostics/disassembler.h"
#include "src/execution/simulator.h"
#include "src/heap/factory.h"
#include "src/init/v8.h"
#include "src/utils/utils.h"
#include "test/cctest/cctest.h"
#include "test/cctest/test-helper-riscv64.h"
#include "test/common/value-helper.h"

namespace v8 {
namespace internal {

// Define these function prototypes to match JSEntryFunction in execution.cc
using F1 = void*(int x, int p1, int p2, int p3, int p4);
using F2 = void*(int x, int y, int p2, int p3, int p4);
using F3 = void*(void* p, int p1, int p2, int p3, int p4);
using F4 = void*(int64_t x, int64_t y, int64_t p2, int64_t p3, int64_t p4);
using F5 = void*(void* p0, void* p1, int p2, int p3, int p4);

#define MIN_VAL_IMM12 -(1 << 11)
#define LARGE_INT_EXCEED_32_BIT 0x01C9'1075'0321'FB01LL
#define LARGE_INT_UNDER_32_BIT 0x1234'5678
#define LARGE_UINT_EXCEED_32_BIT 0xFDCB'1234'A034'5691ULL

#define __ assm.

#define UTEST_R2_FORM_WITH_RES(instr_name, type, rs1_val, rs2_val,     \
                               expected_res)                           \
  TEST(RISCV_UTEST_##instr_name) {                                     \
    CcTest::InitializeVM();                                            \
    auto fn = [](MacroAssembler& assm) { __ instr_name(a0, a0, a1); }; \
    auto res = GenAndRunTest<type, type>(rs1_val, rs2_val, fn);        \
    CHECK_EQ(expected_res, res);                                       \
  }

#define UTEST_R1_FORM_WITH_RES(instr_name, in_type, out_type, rs1_val, \
                               expected_res)                           \
  TEST(RISCV_UTEST_##instr_name) {                                     \
    CcTest::InitializeVM();                                            \
    auto fn = [](MacroAssembler& assm) { __ instr_name(a0, a0); };     \
    auto res = GenAndRunTest<out_type, in_type>(rs1_val, fn);          \
    CHECK_EQ(expected_res, res);                                       \
  }

#define UTEST_R1_FORM_WITH_RES_C(instr_name, in_type, out_type, rs1_val, \
                                 expected_res)                           \
  TEST(RISCV_UTEST_##instr_name) {                                       \
    i::v8_flags.riscv_c_extension = true;                                \
    CcTest::InitializeVM();                                              \
    auto fn = [](MacroAssembler& assm) { __ instr_name(a0, a0); };       \
    auto res = GenAndRunTest<out_type, in_type>(rs1_val, fn);            \
    CHECK_EQ(expected_res, res);                                         \
  }

#define UTEST_I_FORM_WITH_RES(instr_name, type, rs1_val, imm12, expected_res) \
  TEST(RISCV_UTEST_##instr_name) {                                            \
    CcTest::InitializeVM();                                                   \
    CHECK_EQ(is_intn(imm12, 12), true);                                       \
    auto fn = [](MacroAssembler& assm) { __ instr_name(a0, a0, imm12); };     \
    auto res = GenAndRunTest<type, type>(rs1_val, fn);                        \
    CHECK_EQ(expected_res, res);                                              \
  }

#define UTEST_AMO_WITH_RES(instr_name, aq, rl, inout_type, rs1_val, rs2_val,   \
                           expected_res)                                       \
  TEST(RISCV_UTEST_##instr_name) {                                             \
    CcTest::InitializeVM();                                                    \
    auto fn = [](MacroAssembler& assm) { __ instr_name(aq, rl, a1, a0, a2); }; \
    auto res =                                                                 \
        GenAndRunTestForAMO<inout_type, inout_type>(rs1_val, rs2_val, fn);     \
    CHECK_EQ(expected_res, res);                                               \
  }

#define UTEST_LOAD_STORE(ldname, stname, value_type, value) \
  TEST(RISCV_UTEST_##stname##ldname) {                      \
    CcTest::InitializeVM();                                 \
    auto fn = [](MacroAssembler& assm) {                    \
      __ stname(a1, a0, 0);                                 \
      __ ldname(a0, a0, 0);                                 \
    };                                                      \
    GenAndRunTestForLoadStore<value_type>(value, fn);       \
  }

// Since f.Call() is implemented as vararg calls and RISCV calling convention
// passes all vararg arguments and returns (including floats) in GPRs, we have
// to move from GPR to FPR and back in all floating point tests
#define UTEST_LOAD_STORE_F(ldname, stname, value_type, store_value) \
  TEST(RISCV_UTEST_##stname##ldname) {                              \
    DCHECK(std::is_floating_point<value_type>::value);              \
                                                                    \
    CcTest::InitializeVM();                                         \
    auto fn = [](MacroAssembler& assm) {                            \
      __ stname(fa0, a0, 0);                                        \
      __ ldname(fa0, a0, 0);                                        \
    };                                                              \
    GenAndRunTestForLoadStore<value_type>(store_value, fn);         \
  }

#define UTEST_LR_SC(ldname, stname, aq, rl, value_type, value) \
  TEST(RISCV_UTEST_##stname##ldname) {                         \
    CcTest::InitializeVM();                                    \
    auto fn = [](MacroAssembler& assm) {                       \
      __ ldname(aq, rl, a1, a0);                               \
      __ stname(aq, rl, a0, a0, a1);                           \
    };                                                         \
    GenAndRunTestForLRSC<value_type>(value, fn);               \
  }

#define UTEST_R1_FORM_WITH_RES_F(instr_name, type, rs1_fval, expected_fres) \
  TEST(RISCV_UTEST_##instr_name) {                                          \
    DCHECK(std::is_floating_point<type>::value);                            \
    CcTest::InitializeVM();                                                 \
    auto fn = [](MacroAssembler& assm) { __ instr_name(fa0, fa0); };        \
    auto res = GenAndRunTest<type, type>(rs1_fval, fn);                     \
    CHECK_EQ(expected_fres, res);                                           \
  }

#define UTEST_R2_FORM_WITH_RES_F(instr_name, type, rs1_fval, rs2_fval,    \
                                 expected_fres)                           \
  TEST(RISCV_UTEST_##instr_name) {                                        \
    DCHECK(std::is_floating_point<type>::value);                          \
    CcTest::InitializeVM();                                               \
    auto fn = [](MacroAssembler& assm) { __ instr_name(fa0, fa0, fa1); }; \
    auto res = GenAndRunTest<type, type>(rs1_fval, rs2_fval, fn);         \
    CHECK_EQ(expected_fres, res);                                         \
  }

#define UTEST_R3_FORM_WITH_RES_F(instr_name, type, rs1_fval, rs2_fval,         \
                                 rs3_fval, expected_fres)                      \
  TEST(RISCV_UTEST_##instr_name) {                                             \
    DCHECK(std::is_floating_point<type>::value);                               \
    CcTest::InitializeVM();                                                    \
    auto fn = [](MacroAssembler& assm) { __ instr_name(fa0, fa0, fa1, fa2); }; \
    auto res = GenAndRunTest<type, type>(rs1_fval, rs2_fval, rs3_fval, fn);    \
    CHECK_EQ(expected_fres, res);                                              \
  }

#define UTEST_COMPARE_WITH_RES_F(instr_name, input_type, rs1_fval, rs2_fval, \
                                 expected_res)                               \
  TEST(RISCV_UTEST_##instr_name) {                                           \
    CcTest::InitializeVM();                                                  \
    auto fn = [](MacroAssembler& assm) { __ instr_name(a0, fa0, fa1); };     \
    auto res = GenAndRunTest<int32_t, input_type>(rs1_fval, rs2_fval, fn);   \
    CHECK_EQ(expected_res, res);                                             \
  }

#define UTEST_CONV_F_FROM_I(instr_name, input_type, output_type, rs1_val, \
                            expected_fres)                                \
  TEST(RISCV_UTEST_##instr_name) {                                        \
    DCHECK(std::is_integral<input_type>::value&&                          \
               std::is_floating_point<output_type>::value);               \
                                                                          \
    CcTest::InitializeVM();                                               \
    auto fn = [](MacroAssembler& assm) { __ instr_name(fa0, a0); };       \
    auto res = GenAndRunTest<output_type, input_type>(rs1_val, fn);       \
    CHECK_EQ(expected_fres, res);                                         \
  }

#define UTEST_CONV_I_FROM_F(instr_name, input_type, output_type,     \
                            rounding_mode, rs1_fval, expected_res)   \
  TEST(RISCV_UTEST_##instr_name) {                                   \
    DCHECK(std::is_floating_point<input_type>::value&&               \
               std::is_integral<output_type>::value);                \
                                                                     \
    CcTest::InitializeVM();                                          \
    auto fn = [](MacroAssembler& assm) {                             \
      __ instr_name(a0, fa0, rounding_mode);                         \
    };                                                               \
    auto res = GenAndRunTest<output_type, input_type>(rs1_fval, fn); \
    CHECK_EQ(expected_res, res);                                     \
  }                                                                  \
                                                                     \
  TEST(RISCV_UTEST_dyn_##instr_name) {                               \
    DCHECK(std::is_floating_point<input_type>::value&&               \
               std::is_integral<output_type>::value);                \
                                                                     \
    CcTest::InitializeVM();                                          \
    auto fn = [](MacroAssembler& assm) {                             \
      __ csrwi(csr_frm, rounding_mode);                              \
      __ instr_name(a0, fa0, DYN);                                   \
    };                                                               \
    auto res = GenAndRunTest<output_type, input_type>(rs1_fval, fn); \
    CHECK_EQ(expected_res, res);                                     \
  }

#define UTEST_CONV_F_FROM_F(instr_name, input_type, output_type, rs1_val, \
                            expected_fres)                                \
  TEST(RISCV_UTEST_##instr_name) {                                        \
    CcTest::InitializeVM();                                               \
    auto fn = [](MacroAssembler& assm) { __ instr_name(fa0, fa0); };      \
    auto res = GenAndRunTest<output_type, input_type>(rs1_val, fn);       \
    CHECK_EQ(expected_fres, res);                                         \
  }

#define UTEST_CSRI(csr_reg, csr_write_val, csr_set_clear_val)               \
  TEST(RISCV_UTEST_CSRI_##csr_reg) {                                        \
    CHECK_EQ(is_uint5(csr_write_val) && is_uint5(csr_set_clear_val), true); \
                                                                            \
    CcTest::InitializeVM();                                                 \
    int64_t expected_res = 111;                                             \
    Label exit, error;                                                      \
    auto fn = [&exit, &error, expected_res](MacroAssembler& assm) {         \
      /* test csr-write and csr-read */                                     \
      __ csrwi(csr_reg, csr_write_val);                                     \
      __ csrr(a0, csr_reg);                                                 \
      __ RV_li(a1, csr_write_val);                                          \
      __ bne(a0, a1, &error);                                               \
      /* test csr_set */                                                    \
      __ csrsi(csr_reg, csr_set_clear_val);                                 \
      __ csrr(a0, csr_reg);                                                 \
      __ RV_li(a1, (csr_write_val) | (csr_set_clear_val));                  \
      __ bne(a0, a1, &error);                                               \
      /* test csr_clear */                                                  \
      __ csrci(csr_reg, csr_set_clear_val);                                 \
      __ csrr(a0, csr_reg);                                                 \
      __ RV_li(a1, (csr_write_val) & (~(csr_set_clear_val)));               \
      __ bne(a0, a1, &error);                                               \
      /* everyhing runs correctly, return 111 */                            \
      __ RV_li(a0, expected_res);                                           \
      __ j(&exit);                                                          \
                                                                            \
      __ bind(&error);                                                      \
      /* got an error, return 666 */                                        \
      __ RV_li(a0, 666);                                                    \
                                                                            \
      __ bind(&exit);                                                       \
    };                                                                      \
    auto res = GenAndRunTest(fn);                                           \
    CHECK_EQ(expected_res, res);                                            \
  }

#define UTEST_CSR(csr_reg, csr_write_val, csr_set_clear_val)        \
  TEST(RISCV_UTEST_CSR_##csr_reg) {                                 \
    Label exit, error;                                              \
    int64_t expected_res = 111;                                     \
    auto fn = [&exit, &error, expected_res](MacroAssembler& assm) { \
      /* test csr-write and csr-read */                             \
      __ RV_li(t0, csr_write_val);                                  \
      __ csrw(csr_reg, t0);                                         \
      __ csrr(a0, csr_reg);                                         \
      __ RV_li(a1, csr_write_val);                                  \
      __ bne(a0, a1, &error);                                       \
      /* test csr_set */                                            \
      __ RV_li(t0, csr_set_clear_val);                              \
      __ csrs(csr_reg, t0);                                         \
      __ csrr(a0, csr_reg);                                         \
      __ RV_li(a1, (csr_write_val) | (csr_set_clear_val));          \
      __ bne(a0, a1, &error);                                       \
      /* test csr_clear */                                          \
      __ RV_li(t0, csr_set_clear_val);                              \
      __ csrc(csr_reg, t0);                                         \
      __ csrr(a0, csr_reg);                                         \
      __ RV_li(a1, (csr_write_val) & (~(csr_set_clear_val)));       \
      __ bne(a0, a1, &error);                                       \
      /* everyhing runs correctly, return 111 */                    \
      __ RV_li(a0, expected_res);                                   \
      __ j(&exit);                                                  \
                                                                    \
      __ bind(&error);                                              \
      /* got an error, return 666 */                                \
      __ RV_li(a0, 666);                                            \
                                                                    \
      __ bind(&exit);                                               \
    };                                                              \
                                                                    \
    auto res = GenAndRunTest(fn);                                   \
    CHECK_EQ(expected_res, res);                                    \
  }

#define UTEST_R2_FORM_WITH_OP(instr_name, type, rs1_val, rs2_val, tested_op) \
  UTEST_R2_FORM_WITH_RES(instr_name, type, rs1_val, rs2_val,                 \
                         ((rs1_val)tested_op(rs2_val)))

#define UTEST_I_FORM_WITH_OP(instr_name, type, rs1_val, imm12, tested_op) \
  UTEST_I_FORM_WITH_RES(instr_name, type, rs1_val, imm12,                 \
                        ((rs1_val)tested_op(imm12)))

#define UTEST_R2_FORM_WITH_OP_F(instr_name, type, rs1_fval, rs2_fval, \
                                tested_op)                            \
  UTEST_R2_FORM_WITH_RES_F(instr_name, type, rs1_fval, rs2_fval,      \
                           ((rs1_fval)tested_op(rs2_fval)))

#define UTEST_COMPARE_WITH_OP_F(instr_name, input_type, rs1_fval, rs2_fval, \
                                tested_op)                                  \
  UTEST_COMPARE_WITH_RES_F(instr_name, input_type, rs1_fval, rs2_fval,      \
                           ((rs1_fval)tested_op(rs2_fval)))

// -- test load-store --
UTEST_LOAD_STORE(ld, sd, int64_t, 0xFBB10A9C12345678)
// due to sign-extension of lw
// instruction, value-to-stored must have
// its 32th least significant bit be 0
UTEST_LOAD_STORE(lw, sw, int32_t, 0x456AF894)
// set the 32th least significant bit of
// value-to-store to 1 to test
// zero-extension by lwu
UTEST_LOAD_STORE(lwu, sw, uint32_t, 0x856AF894)
// due to sign-extension of lh
// instruction, value-to-stored must have
// its 16th least significant bit be 0
UTEST_LOAD_STORE(lh, sh, int32_t, 0x7894)
// set the 16th least significant bit of
// value-to-store to 1 to test
// zero-extension by lhu
UTEST_LOAD_STORE(lhu, sh, uint32_t, 0xF894)
// due to sign-extension of lb
// instruction, value-to-stored must have
// its 8th least significant bit be 0
UTEST_LOAD_STORE(lb, sb, int32_t, 0x54)
// set the 8th least significant bit of
// value-to-store to 1 to test
// zero-extension by lbu
UTEST_LOAD_STORE(lbu, sb, uint32_t, 0x94)

// -- arithmetic w/ immediate --
UTEST_I_FORM_WITH_OP(addi, int64_t, LARGE_INT_EXCEED_32_BIT, MIN_VAL_IMM12, +)
UTEST_I_FORM_WITH_OP(slti, int64_t, LARGE_INT_EXCEED_32_BIT, MIN_VAL_IMM12, <)
UTEST_I_FORM_WITH_OP(sltiu, uint64_t, LARGE_UINT_EXCEED_32_BIT, 0x4FB, <)
UTEST_I_FORM_WITH_OP(xori, int64_t, LARGE_INT_EXCEED_32_BIT, MIN_VAL_IMM12, ^)
UTEST_I_FORM_WITH_OP(ori, int64_t, LARGE_INT_EXCEED_32_BIT, MIN_VAL_IMM12, |)
UTEST_I_FORM_WITH_OP(andi, int64_t, LARGE_INT_EXCEED_32_BIT, MIN_VAL_IMM12, &)
UTEST_I_FORM_WITH_OP(slli, int64_t, 0x1234'5678ULL, 33, <<)
UTEST_I_FORM_WITH_OP(srli, int64_t, 0x8234'5678'0000'0000ULL, 33, >>)
UTEST_I_FORM_WITH_OP(srai, int64_t, -0x1234'5678'0000'0000LL, 33, >>)

// -- arithmetic --
UTEST_R2_FORM_WITH_OP(add, int64_t, LARGE_INT_EXCEED_32_BIT, MIN_VAL_IMM12, +)
UTEST_R2_FORM_WITH_OP(sub, int64_t, LARGE_INT_EXCEED_32_BIT, MIN_VAL_IMM12, -)
UTEST_R2_FORM_WITH_OP(slt, int64_t, MIN_VAL_IMM12, LARGE_INT_EXCEED_32_BIT, <)
UTEST_R2_FORM_WITH_OP(sltu, uint64_t, 0x4FB, LARGE_UINT_EXCEED_32_BIT, <)
UTEST_R2_FORM_WITH_OP(xor_, int64_t, LARGE_INT_EXCEED_32_BIT, MIN_VAL_IMM12, ^)
UTEST_R2_FORM_WITH_OP(or_, int64_t, LARGE_INT_EXCEED_32_BIT, MIN_VAL_IMM12, |)
UTEST_R2_FORM_WITH_OP(and_, int64_t, LARGE_INT_EXCEED_32_BIT, MIN_VAL_IMM12, &)
UTEST_R2_FORM_WITH_OP(sll, int64_t, 0x12345678ULL, 33, <<)
UTEST_R2_FORM_WITH_OP(srl, int64_t, 0x8234567800000000ULL, 33, >>)
UTEST_R2_FORM_WITH_OP(sra, int64_t, -0x1234'5678'0000'0000LL, 33, >>)

// -- Memory fences --
// void fence(uint8_t pred, uint8_t succ);
// void fence_tso();

// -- Environment call / break --
// void ecall();
// void ebreak();
// void unimp();

// -- CSR --
UTEST_CSRI(csr_frm, DYN, RUP)
UTEST_CSRI(csr_fflags, kInexact | kInvalidOperation, kInvalidOperation)
UTEST_CSRI(csr_fcsr, kDivideByZero | kFPUOverflow, kUnderflow)
UTEST_CSR(csr_frm, DYN, RUP)
UTEST_CSR(csr_fflags, kInexact | kInvalidOperation, kInvalidOperation)
UTEST_CSR(csr_fcsr, kDivideByZero | kFPUOverflow | (RDN << kFcsrFrmShift),
          kUnderflow | (RNE << kFcsrFrmShift))

// -- RV64I --
UTEST_I_FORM_WITH_OP(addiw, int32_t, LARGE_INT_UNDER_32_BIT, MIN_VAL_IMM12, +)
UTEST_I_FORM_WITH_OP(slliw, int32_t, 0x12345678U, 12, <<)
UTEST_I_FORM_WITH_OP(srliw, int32_t, 0x82345678U, 12, >>)
UTEST_I_FORM_WITH_OP(sraiw, int32_t, -123, 12, >>)

UTEST_R2_FORM_WITH_OP(addw, int32_t, LARGE_INT_UNDER_32_BIT, MIN_VAL_IMM12, +)
UTEST_R2_FORM_WITH_OP(subw, int32_t, LARGE_INT_UNDER_32_BIT, MIN_VAL_IMM12, -)
UTEST_R2_FORM_WITH_OP(sllw, int32_t, 0x12345678U, 12, <<)
UTEST_R2_FORM_WITH_OP(srlw, int32_t, 0x82345678U, 12, >>)
UTEST_R2_FORM_WITH_OP(sraw, int32_t, -123, 12, >>)

// -- RV32M Standard Extension --
UTEST_R2_FORM_WITH_OP(mul, int64_t, 0x0F945001L, MIN_VAL_IMM12, *)
UTEST_R2_FORM_WITH_RES(mulh, int64_t, 0x1234567800000000LL,
                       -0x1234'5617'0000'0000LL, 0x12345678LL * -0x1234'5617LL)
UTEST_R2_FORM_WITH_RES(mulhu, int64_t, 0x1234'5678'0000'0000ULL,
                       0xF896'7021'0000'0000ULL,
                       0x1234'5678ULL * 0xF896'7021ULL)
UTEST_R2_FORM_WITH_RES(mulhsu, int64_t, -0x1234'56780000'0000LL,
                       0xF234'5678'0000'0000ULL,
                       static_cast<int64_t>(-0x1234'5678LL * 0xF234'5678ULL))
UTEST_R2_FORM_WITH_OP(div, int64_t, LARGE_INT_EXCEED_32_BIT, MIN_VAL_IMM12, /)
UTEST_R2_FORM_WITH_OP(divu, uint64_t, LARGE_UINT_EXCEED_32_BIT, 100, /)
UTEST_R2_FORM_WITH_OP(rem, int64_t, LARGE_INT_EXCEED_32_BIT, MIN_VAL_IMM12, %)
UTEST_R2_FORM_WITH_OP(remu, uint64_t, LARGE_UINT_EXCEED_32_BIT, 100, %)

// -- RV64M Standard Extension (in addition to RV32M) --
UTEST_R2_FORM_WITH_OP(mulw, int32_t, -20, 56, *)
UTEST_R2_FORM_WITH_OP(divw, int32_t, 200, -10, /)
UTEST_R2_FORM_WITH_OP(divuw, uint32_t, 1000, 100, /)
UTEST_R2_FORM_WITH_OP(remw, int32_t, 1234, -91, %)
UTEST_R2_FORM_WITH_OP(remuw, uint32_t, 1234, 43, %)

// -- RV32A Standard Extension --
UTEST_LR_SC(lr_w, sc_w, false, false, int32_t, 0xFBB1A75C)
UTEST_AMO_WITH_RES(amoswap_w, false, false, uint32_t, 0xFBB1A75C, 0xA75C0A9C,
                   (uint32_t)0xA75C0A9C)
UTEST_AMO_WITH_RES(amoadd_w, false, false, uint32_t, 0xFBB1A75C, 0xA75C0A9C,
                   (uint32_t)0xFBB1A75C + (uint32_t)0xA75C0A9C)
UTEST_AMO_WITH_RES(amoxor_w, false, false, uint32_t, 0xFBB1A75C, 0xA75C0A9C,
                   (uint32_t)0xFBB1A75C ^ (uint32_t)0xA75C0A9C)
UTEST_AMO_WITH_RES(amoand_w, false, false, uint32_t, 0xFBB1A75C, 0xA75C0A9C,
                   (uint32_t)0xFBB1A75C & (uint32_t)0xA75C0A9C)
UTEST_AMO_WITH_RES(amoor_w, false, false, uint32_t, 0xFBB1A75C, 0xA75C0A9C,
                   (uint32_t)0xFBB1A75C | (uint32_t)0xA75C0A9C)
UTEST_AMO_WITH_RES(amomin_w, false, false, int32_t, 0xFBB1A75C, 0xA75C0A9C,
                   std::min((int32_t)0xFBB1A75C, (int32_t)0xA75C0A9C))
UTEST_AMO_WITH_RES(amomax_w, false, false, int32_t, 0xFBB1A75C, 0xA75C0A9C,
                   std::max((int32_t)0xFBB1A75C, (int32_t)0xA75C0A9C))
UTEST_AMO_WITH_RES(amominu_w, false, false, uint32_t, 0xFBB1A75C, 0xA75C0A9C,
                   std::min((uint32_t)0xFBB1A75C, (uint32_t)0xA75C0A9C))
UTEST_AMO_WITH_RES(amomaxu_w, false, false, uint32_t, 0xFBB1A75C, 0xA75C0A9C,
                   std::max((uint32_t)0xFBB1A75C, (uint32_t)0xA75C0A9C))

// -- RV64A Standard Extension (in addition to RV32A) --
UTEST_LR_SC(lr_d, sc_d, false, false, int64_t, 0xFBB10A9Cbfb76aa6)
UTEST_AMO_WITH_RES(amoswap_d, false, false, int64_t, 0xFBB10A9Cbfb76aa6,
                   0x284ff922346ad35c, (int64_t)0x284ff922346ad35c)
UTEST_AMO_WITH_RES(amoadd_d, false, false, int64_t, 0xFBB10A9Cbfb76aa6,
                   0x284ff922346ad35c,
                   (int64_t)0xFBB10A9Cbfb76aa6 + (int64_t)0x284ff922346ad35c)
UTEST_AMO_WITH_RES(amoxor_d, false, false, int64_t, 0xFBB10A9Cbfb76aa6,
                   0x284ff922346ad35c,
                   (int64_t)0xFBB10A9Cbfb76aa6 ^ (int64_t)0x284ff922346ad35c)
UTEST_AMO_WITH_RES(amoand_d, false, false, int64_t, 0xFBB10A9Cbfb76aa6,
                   0x284ff922346ad35c,
                   (int64_t)0xFBB10A9Cbfb76aa6 & (int64_t)0x284ff922346ad35c)
UTEST_AMO_WITH_RES(amoor_d, false, false, int64_t, 0xFBB10A9Cbfb76aa6,
                   0x284ff922346ad35c,
                   (int64_t)0xFBB10A9Cbfb76aa6 | (int64_t)0x284ff922346ad35c)
UTEST_AMO_WITH_RES(amomin_d, false, false, int64_t, 0xFBB10A9Cbfb76aa6,
                   0x284ff922346ad35c,
                   std::min((int64_t)0xFBB10A9Cbfb76aa6,
                            (int64_t)0x284ff922346ad35c))
UTEST_AMO_WITH_RES(amomax_d, false, false, int64_t, 0xFBB10A9Cbfb76aa6,
                   0x284ff922346ad35c,
                   std::max((int64_t)0xFBB10A9Cbfb76aa6,
                            (int64_t)0x284ff922346ad35c))
UTEST_AMO_WITH_RES(amominu_d, false, false, uint64_t, 0xFBB10A9Cbfb76aa6,
                   0x284ff922346ad35c,
                   std::min((uint64_t)0xFBB10A9Cbfb76aa6,
                            (uint64_t)0x284ff922346ad35c))
UTEST_AMO_WITH_RES(amomaxu_d, false, false, uint64_t, 0xFBB10A9Cbfb76aa6,
                   0x284ff922346ad35c,
                   std::max((uint64_t)0xFBB10A9Cbfb76aa6,
                            (uint64_t)0x284ff922346ad35c))
// RV64B
UTEST_R2_FORM_WITH_RES(sh1add, int64_t, LARGE_INT_EXCEED_32_BIT,
                       LARGE_UINT_EXCEED_32_BIT,
                       ((LARGE_UINT_EXCEED_32_BIT) +
                        (LARGE_INT_EXCEED_32_BIT << 1)))
UTEST_R2_FORM_WITH_RES(sh2add, int64_t, LARGE_INT_EXCEED_32_BIT,
                       LARGE_UINT_EXCEED_32_BIT,
                       ((LARGE_UINT_EXCEED_32_BIT) +
                        (LARGE_INT_EXCEED_32_BIT << 2)))
UTEST_R2_FORM_WITH_RES(sh3add, int64_t, LARGE_INT_EXCEED_32_BIT,
                       LARGE_UINT_EXCEED_32_BIT,
                       ((LARGE_UINT_EXCEED_32_BIT) +
                        (LARGE_INT_EXCEED_32_BIT << 3)))

UTEST_R2_FORM_WITH_RES(sh1adduw, int64_t, 0x13f42, 1,
                       ((1) + (uint32_t(0x13f42) << 1)))

UTEST_R2_FORM_WITH_RES(sh2adduw, int64_t, 0x13f42, LARGE_UINT_EXCEED_32_BIT,
                       int64_t((LARGE_UINT_EXCEED_32_BIT) +
                               (uint32_t(0x13f42) << 2)))

UTEST_R2_FORM_WITH_RES(sh3adduw, int64_t, LARGE_INT_EXCEED_32_BIT,
                       LARGE_UINT_EXCEED_32_BIT,
                       int64_t((LARGE_UINT_EXCEED_32_BIT) +
                               (uint32_t(LARGE_INT_EXCEED_32_BIT) << 3)))
UTEST_R2_FORM_WITH_RES(adduw, int64_t, LARGE_INT_EXCEED_32_BIT,
                       LARGE_UINT_EXCEED_32_BIT,
                       int64_t((LARGE_UINT_EXCEED_32_BIT) +
                               (uint32_t(LARGE_INT_EXCEED_32_BIT))))

UTEST_I_FORM_WITH_RES(slliuw, int64_t, LARGE_INT_EXCEED_32_BIT, 10,
                      (int64_t(uint32_t(LARGE_INT_EXCEED_32_BIT))) << 10)

UTEST_R2_FORM_WITH_RES(andn, int64_t, LARGE_INT_EXCEED_32_BIT,
                       LARGE_UINT_EXCEED_32_BIT,
                       ((LARGE_INT_EXCEED_32_BIT) &
                        (~LARGE_UINT_EXCEED_32_BIT)))

UTEST_R2_FORM_WITH_RES(orn, int64_t, LARGE_INT_EXCEED_32_BIT,
                       LARGE_UINT_EXCEED_32_BIT,
                       ((LARGE_INT_EXCEED_32_BIT) |
                        (~LARGE_UINT_EXCEED_32_BIT)))

UTEST_R2_FORM_WITH_RES(xnor, int64_t, LARGE_INT_EXCEED_32_BIT,
                       LARGE_UINT_EXCEED_32_BIT,
                       int64_t((~LARGE_INT_EXCEED_32_BIT) ^
                               (~LARGE_UINT_EXCEED_32_BIT)))

UTEST_R1_FORM_WITH_RES(clz, int64_t, int64_t, 0b000011000100000000000, 47)
UTEST_R1_FORM_WITH_RES(ctz, int64_t, int64_t, 0b000011000100000000000, 11)

UTEST_R1_FORM_WITH_RES(clzw, int64_t, int64_t, 0b000011000100000000000, 15)
UTEST_R1_FORM_WITH_RES(ctzw, int64_t, int64_t, 0b000011000100000000000, 11)

UTEST_R1_FORM_WITH_RES(cpop, int64_t, int64_t, 0b000011000100000000000, 3)
UTEST_R1_FORM_WITH_RES(cpopw, int64_t, int64_t, 0b000011000100000000011, 5)

UTEST_R2_FORM_WITH_RES(max, int64_t, -1012, 3456, 3456)
UTEST_R2_FORM_WITH_RES(min, int64_t, -1012, 3456, -1012)
UTEST_R2_FORM_WITH_RES(maxu, uint64_t, -1012, 3456, uint64_t(-1012))
UTEST_R2_FORM_WITH_RES(minu, uint64_t, -1012, 3456, 3456)

UTEST_R1_FORM_WITH_RES(sextb, int64_t, int64_t, 0xB080,
                       int64_t(0xffffffffffffff80))
UTEST_R1_FORM_WITH_RES(sexth, int64_t, int64_t, 0xB080,
                       int64_t(0xffffffffffffb080))
UTEST_R1_FORM_WITH_RES(zexth, int64_t, int64_t, 0xB080, 0xB080)

UTEST_R2_FORM_WITH_RES(rol, uint64_t, 16, 2, 64)
UTEST_R2_FORM_WITH_RES(rolw, uint32_t, 16, 2, 64)
UTEST_R2_FORM_WITH_RES(ror, uint64_t, 16, 2, 4)
UTEST_R2_FORM_WITH_RES(rorw, uint32_t, 16, 2, 4)
UTEST_I_FORM_WITH_RES(rori, int64_t, 16, 2, 4)
UTEST_I_FORM_WITH_RES(roriw, int32_t, 16, 2, 4)
UTEST_R1_FORM_WITH_RES(orcb, int64_t, uint64_t, 0xFF00011010010011,
                       0xFF00FFFFFFFF00FF)
UTEST_R1_FORM_WITH_RES(rev8, uint64_t, uint64_t, 0x1234567890ABCDEF,
                       0xEFCDAB9078563412)

UTEST_R2_FORM_WITH_RES(bclr, int64_t, 0x13f62, 5, 0x13f42)
UTEST_I_FORM_WITH_RES(bclri, int64_t, 0x2013F6213F62, 45, 0x13f6213f62)
UTEST_R2_FORM_WITH_RES(bext, int64_t, 0x13f62, 5, 1)
UTEST_I_FORM_WITH_RES(bexti, int64_t, 0x2013F6213F62, 45, 1)
UTEST_R2_FORM_WITH_RES(binv, int64_t, 0x13f62, 5, 0x13f42)
UTEST_I_FORM_WITH_RES(binvi, int64_t, 0x13f6213f62, 45, 0x2013F6213F62)
UTEST_R2_FORM_WITH_RES(bset, int64_t, 0x13f42, 5, 0x13f62)
UTEST_I_FORM_WITH_RES(bseti, int64_t, 0x13f6213f62, 45, 0x2013F6213F62)

// -- RV32F Standard Extension --
UTEST_LOAD_STORE_F(flw, fsw, float, -2345.678f)
UTEST_R2_FORM_WITH_OP_F(fadd_s, float, -1012.01f, 3456.13f, +)
UTEST_R2_FORM_WITH_OP_F(fsub_s, float, -1012.01f, 3456.13f, -)
UTEST_R2_FORM_WITH_OP_F(fmul_s, float, -10.01f, 56.13f, *)
UTEST_R2_FORM_WITH_OP_F(fdiv_s, float, -10.01f, 34.13f, /)
UTEST_R1_FORM_WITH_RES_F(fsqrt_s, float, 34.13f, sqrtf(34.13f))
UTEST_R2_FORM_WITH_RES_F(fmin_s, float, -1012.0f, 3456.13f, -1012.0f)
UTEST_R2_FORM_WITH_RES_F(fmax_s, float, -1012.0f, 3456.13f, 3456.13f)
UTEST_R3_FORM_WITH_RES_F(fmadd_s, float, 67.56f, -1012.01f, 3456.13f,
                         std::fma(67.56f, -1012.01f, 3456.13f))
UTEST_R3_FORM_WITH_RES_F(fmsub_s, float, 67.56f, -1012.01f, 3456.13f,
                         std::fma(67.56f, -1012.01f, -3456.13f))
UTEST_R3_FORM_WITH_RES_F(fnmsub_s, float, 67.56f, -1012.01f, 3456.13f,
                         -std::fma(67.56f, -1012.01f, -3456.13f))
UTEST_R3_FORM_WITH_RES_F(fnmadd_s, float, 67.56f, -1012.01f, 3456.13f,
                         -std::fma(67.56f, -1012.01f, 3456.13f))
UTEST_COMPARE_WITH_OP_F(feq_s, float, -3456.56, -3456.56, ==)
UTEST_COMPARE
```