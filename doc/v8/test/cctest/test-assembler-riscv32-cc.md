Response:
Let's break down the thought process for analyzing this V8 test file.

**1. Understanding the Goal:**

The primary goal is to figure out what this specific file, `test-assembler-riscv32.cc`, does within the larger V8 project. The request asks for a summary of its functionality.

**2. Initial Observations (Skimming the Code):**

* **Filename and Path:**  `v8/test/cctest/test-assembler-riscv32.cc`  Immediately tells us this is a *test* file (`test`), specifically for the *assembler* (`assembler`), targeting the *RISC-V 32-bit* architecture (`riscv32`), and part of the *component client test* framework (`cctest`).
* **Copyright Notice:** Standard boilerplate, not directly informative about the code's function.
* **Includes:**  A list of header files is present. These are crucial clues. Key includes:
    * `src/codegen/assembler-inl.h`, `src/codegen/macro-assembler.h`: Strong indication that this file deals with low-level code generation and assembly instructions.
    * `src/execution/simulator.h`:  Suggests the tests might involve simulating the execution of the generated code.
    * `test/cctest/cctest.h`, `test/cctest/test-helper-riscv32.h`:  Confirms this is a CCTest and likely uses helper functions specific to RISC-V testing.
* **Namespaces:**  `namespace v8 { namespace internal {`  Indicates this code is part of V8's internal implementation.
* **Type Definitions (using F1, F2, etc.):** These define function pointer types, likely representing the signature of generated assembly functions. The arguments (ints, pointers, int64_t) hint at the kinds of data being manipulated.
* **Macros (UTEST_R2_FORM_WITH_RES, etc.):** A large number of macros. This is a strong indicator of a testing framework. The names suggest different forms of assembly instructions (R-type, I-type, load/store, floating-point). The `WITH_RES` suffix suggests these macros are used to define tests that compare the result of executing an instruction with an expected value.
* **Specific Instruction Names (addi, slti, lw, sw, fadd_s, etc.):**  These are actual RISC-V assembly instruction mnemonics. This confirms the file tests the RISC-V assembler.
* **Test Case Structure (`TEST(RISCV_UTEST_...) { ... }`):**  The `TEST` macro is another clear sign of the CCTest framework being used to define individual test cases.

**3. Deductions and Hypotheses:**

Based on the initial observations, we can form the following hypotheses:

* **Purpose:** This file tests the RISC-V 32-bit assembler in V8. It verifies that the assembler generates correct machine code for various RISC-V instructions.
* **Mechanism:** The tests likely involve:
    1. Using the `MacroAssembler` class to generate RISC-V assembly code snippets.
    2. Executing the generated code using a simulator.
    3. Comparing the actual result of the execution with an expected result.
* **Scope:** The tests cover a wide range of RISC-V instructions, including:
    * Integer arithmetic and logical operations (add, sub, and, or, xor, shifts).
    * Immediate operations (addi, andi, ori, etc.).
    * Load and store instructions (lw, sw, lb, sb, flw, fsw).
    * Atomic memory operations (AMO).
    * Control flow instructions (implied by the use of labels within the test macros).
    * Floating-point instructions (fadd_s, fmul_s, fsqrt_s, conversions).
    * CSR (Control and Status Register) manipulation.
    * Potentially some pseudo-instructions.
* **Testing Methodology:** The macros abstract away the boilerplate of setting up and running tests, allowing for concise test definitions. The `GenAndRunTest` functions (and similar variants) handle the code generation and execution.

**4. Refining the Analysis (Detailed Look at Macros):**

Examining the macros more closely confirms the hypotheses. For instance:

* `UTEST_R2_FORM_WITH_RES`: Clearly defines a test for a two-register instruction, taking input values for two registers (`rs1_val`, `rs2_val`) and comparing the result with `expected_res`. It uses `GenAndRunTest` which takes the input values and the assembly generation lambda.
* `UTEST_LOAD_STORE`: Tests load and store pairs, ensuring data written to memory can be correctly read back.
* `UTEST_CSRI`, `UTEST_CSR`: Tests operations on Control and Status Registers.

**5. Addressing Specific Questions in the Prompt:**

* **Functionality:**  As deduced above, it tests the RISC-V 32-bit assembler.
* **Torque:** The filename does *not* end in `.tq`, so it's not a Torque file.
* **JavaScript Relationship:** This code directly supports the V8 JavaScript engine by ensuring the RISC-V assembler (used in the JIT compiler) works correctly. While the *test code itself* isn't directly used in running JavaScript, the *assembler being tested* is crucial for performance. A JavaScript example would demonstrate code that, when JIT-compiled on a RISC-V 32-bit system, would rely on the correctness of this assembler. For example, a simple arithmetic operation or function call.
* **Code Logic and I/O:** The macros define the test logic. For `UTEST_R2_FORM_WITH_RES(add, int32_t, 5, 3, 8)`, the input is implicitly the values 5 and 3 loaded into registers, and the expected output is 8 (the result of the `add` instruction).
* **Common Programming Errors:**  The tests themselves don't *contain* user programming errors, but they *help prevent* errors in the V8 JIT compiler. A common error the assembler could make (and these tests would catch) is generating incorrect machine code for an instruction, leading to wrong results or crashes in JavaScript execution. Example: Incorrectly encoding the immediate value in an `addi` instruction.

**6. Structuring the Summary:**

Finally, organize the findings into a clear and concise summary, addressing all parts of the prompt. This involves:

* Stating the core function (testing the RISC-V assembler).
* Explaining the testing approach (generating code, simulating, comparing).
* Listing the categories of instructions tested.
* Addressing the Torque question.
* Providing a JavaScript example to illustrate the connection.
* Giving an example of code logic and I/O within a test.
* Giving an example of a common programming error the tests help prevent.

This iterative process of observation, deduction, and refinement allows for a comprehensive understanding of the code's purpose and functionality.
这是 V8 JavaScript 引擎中针对 RISC-V 32 位架构的汇编器测试代码。它使用 V8 的测试框架 (cctest) 来验证 `MacroAssembler` 类生成的 RISC-V 汇编指令是否正确。

以下是它的功能归纳：

1. **测试 RISC-V 32 位汇编指令的正确性:**  该文件包含了大量的测试用例，每个测试用例都针对特定的 RISC-V 汇编指令或指令组合。它会生成一段包含被测指令的汇编代码，然后在模拟器上运行这段代码，并将运行结果与预期结果进行比较。

2. **覆盖多种指令类型:**  测试用例涵盖了 RISC-V 32 位架构中的多种指令类型，包括：
    * **算术运算指令:**  加法 (add, addi)，减法 (sub)，乘法 (mul)，除法 (div, divu)，取余 (rem, remu)。
    * **逻辑运算指令:**  与 (and, andi)，或 (or, ori)，异或 (xor, xori)。
    * **位移指令:**  逻辑左移 (sll, slli)，逻辑右移 (srl, srli)，算术右移 (sra, srai)。
    * **比较指令:**  小于 (slt, slti)，小于等于 (sle)，大于 (sgt)，大于等于 (sge)，等于 (seqz)，不等于 (snez)。
    * **立即数操作指令:**  对寄存器进行立即数操作。
    * **加载和存储指令:**  从内存加载数据 (lw, lh, lb, lwu, lhu, lbu)，将数据存储到内存 (sw, sh, sb)。
    * **原子操作指令 (RV32A 扩展):**  用于多线程环境的原子操作，如交换 (amoswap_w)，加法 (amoadd_w)，异或 (amoxor_w) 等。
    * **浮点运算指令 (RV32F/D 扩展):**  浮点数的加法 (fadd_s)，减法 (fsub_s)，乘法 (fmul_s)，除法 (fdiv_s)，平方根 (fsqrt_s)，比较 (feq_s, flt_s, fle_s)，类型转换 (fcvt_s_w, fcvt_w_s) 等。
    * **控制状态寄存器 (CSR) 操作指令:**  用于读写和修改 CSR 寄存器的值。
    * **伪指令:**  例如 `mv` (移动寄存器)，`not_` (按位取反)，`neg` (取负)。
    * **压缩指令 (RVC 扩展):**  测试 RISC-V 压缩指令集的指令，例如 `c_mv`。

3. **使用宏简化测试用例的编写:**  文件中定义了大量的宏 (如 `UTEST_R2_FORM_WITH_RES`, `UTEST_I_FORM_WITH_RES`, `UTEST_LOAD_STORE` 等)，这些宏抽象了测试用例的通用结构，使得编写新的测试用例更加简洁方便。

4. **模拟执行:**  测试用例通常会使用 `GenAndRunTest` 或类似的函数来生成汇编代码并在 V8 的模拟器上执行。模拟器允许在非 RISC-V 硬件上测试 RISC-V 代码的正确性。

5. **验证结果:**  每个测试用例都会定义一个期望的输出结果，然后将模拟器执行的实际结果与期望结果进行比较，如果两者不一致，则测试失败。

**如果 `v8/test/cctest/test-assembler-riscv32.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码。** 但实际上它的后缀是 `.cc`，所以它是 C++ 源代码。Torque 是一种 V8 自定义的类型化的中间语言，用于生成高效的机器代码。

**它与 javascript 的功能有关系，因为底层的汇编器是将 JavaScript 代码编译成机器码的关键组成部分。**  当 V8 运行 JavaScript 代码时，它会将 JavaScript 代码编译成机器码以便执行。在 RISC-V 架构上，`MacroAssembler` 类用于生成这些机器码。这个测试文件确保了生成的 RISC-V 机器码是正确的，从而保证了 JavaScript 代码在 RISC-V 架构上的正确执行。

**JavaScript 例子说明:**

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 3);
console.log(result); // 输出 8
```

当 V8 执行这段 JavaScript 代码时，`add` 函数会被编译成 RISC-V 机器码。`test-assembler-riscv32.cc` 中的 `UTEST_R2_FORM_WITH_OP(add, int32_t, LARGE_INT_UNDER_32_BIT, MIN_VAL_IMM12, +)` 这样的测试用例就直接测试了 RISC-V 的 `add` 指令的正确性，确保了 `a + b` 在 RISC-V 架构上能得到正确的计算结果。

**代码逻辑推理 (以 `UTEST_R2_FORM_WITH_RES(add, int32_t, 5, 3, 8)` 为例):**

* **假设输入:**  寄存器 `a0` 初始化为 5，寄存器 `a1` 初始化为 3。
* **汇编代码:**  生成 RISC-V 的 `add a0, a0, a1` 指令。
* **代码逻辑:**  执行 `add` 指令，将寄存器 `a0` 的值加上寄存器 `a1` 的值，结果存储回寄存器 `a0`。
* **预期输出:**  寄存器 `a0` 的值应为 8。
* **测试过程:**  模拟器执行这段代码后，会检查寄存器 `a0` 的值是否为 8。

**涉及用户常见的编程错误 (虽然此文件是测试代码，但它测试的功能与编程错误有关):**

用户在使用 JavaScript 或其他高级语言时，可能不会直接接触到汇编代码。但是，如果底层的汇编器存在错误，会导致高级语言的程序出现意想不到的错误。例如：

* **整数溢出:**  如果汇编器在处理大整数的加法时存在错误，可能会导致计算结果不正确，甚至出现程序崩溃。例如，如果 RISC-V 的 `add` 指令实现有误，`2147483647 + 1` 可能不会得到预期的溢出行为。
* **浮点数精度问题:**  如果浮点运算指令的实现存在错误，可能会导致浮点数计算结果的精度不准确。例如，`0.1 + 0.2` 在某些错误的实现下可能不会精确等于 `0.3`。
* **内存访问错误:**  如果加载和存储指令的实现存在错误，可能会导致程序读写到错误的内存地址，造成数据损坏或程序崩溃。

**总结 (第 1 部分的功能):**

该文件的主要功能是 **测试 V8 JavaScript 引擎中 RISC-V 32 位汇编器的正确性**。它通过大量的单元测试用例，覆盖了各种 RISC-V 指令及其组合，确保 `MacroAssembler` 类能够生成正确的机器码，从而保证 JavaScript 代码在 RISC-V 架构上的可靠执行。它使用了 V8 的测试框架和模拟器来完成这项任务。

### 提示词
```
这是目录为v8/test/cctest/test-assembler-riscv32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-riscv32.cc以.tq结尾，那它是个v8 torque源代码，
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
#include "test/cctest/test-helper-riscv32.h"
#include "test/common/value-helper.h"

namespace v8 {
namespace internal {
//  Define these function prototypes to match JSEntryFunction in execution.cc
using F1 = void*(int x, int p1, int p2, int p3, int p4);
using F2 = void*(int x, int y, int p2, int p3, int p4);
using F3 = void*(void* p, int p1, int p2, int p3, int p4);
using F4 = void*(int64_t x, int64_t y, int64_t p2, int64_t p3, int64_t p4);
using F5 = void*(void* p0, void* p1, int p2, int p3, int p4);

#define MIN_VAL_IMM12 -(1 << 11)
#define LARGE_INT_UNDER_32_BIT 0x12345678
#define LARGE_UINT_UNDER_32_BIT (uint32_t)0xFDCB12341

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
// due to sign-extension of lw
// instruction, value-to-stored must have
// its 32th least significant bit be 0
UTEST_LOAD_STORE(lw, sw, int32_t, 0x456AF894)
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
UTEST_I_FORM_WITH_OP(addi, int32_t, LARGE_INT_UNDER_32_BIT, MIN_VAL_IMM12, +)
UTEST_I_FORM_WITH_OP(slti, int32_t, LARGE_INT_UNDER_32_BIT, MIN_VAL_IMM12, <)
UTEST_I_FORM_WITH_OP(sltiu, uint32_t, LARGE_UINT_UNDER_32_BIT, 0x4FB, <)
UTEST_I_FORM_WITH_OP(xori, int32_t, LARGE_INT_UNDER_32_BIT, MIN_VAL_IMM12, ^)
UTEST_I_FORM_WITH_OP(ori, int32_t, LARGE_INT_UNDER_32_BIT, MIN_VAL_IMM12, |)
UTEST_I_FORM_WITH_OP(andi, int32_t, LARGE_INT_UNDER_32_BIT, MIN_VAL_IMM12, &)
UTEST_I_FORM_WITH_OP(slli, uint32_t, 0x12345678U, 17, <<)
UTEST_I_FORM_WITH_OP(srli, uint32_t, 0x82340000U, 17, >>)
UTEST_I_FORM_WITH_OP(srai, int32_t, -0x12340000, 17, >>)

// -- arithmetic --
UTEST_R2_FORM_WITH_OP(add, int32_t, LARGE_INT_UNDER_32_BIT, MIN_VAL_IMM12, +)
UTEST_R2_FORM_WITH_OP(sub, int32_t, LARGE_INT_UNDER_32_BIT, MIN_VAL_IMM12, -)
UTEST_R2_FORM_WITH_OP(slt, int32_t, MIN_VAL_IMM12, LARGE_INT_UNDER_32_BIT, <)
UTEST_R2_FORM_WITH_OP(sltu, uint32_t, 0x4FB, LARGE_UINT_UNDER_32_BIT, <)
UTEST_R2_FORM_WITH_OP(xor_, int32_t, LARGE_INT_UNDER_32_BIT, MIN_VAL_IMM12, ^)
UTEST_R2_FORM_WITH_OP(or_, int32_t, LARGE_INT_UNDER_32_BIT, MIN_VAL_IMM12, |)
UTEST_R2_FORM_WITH_OP(and_, int32_t, LARGE_INT_UNDER_32_BIT, MIN_VAL_IMM12, &)
UTEST_R2_FORM_WITH_OP(sll, uint32_t, 0x12345678U, 17, <<)
UTEST_R2_FORM_WITH_OP(srl, uint32_t, 0x82340000U, 17, >>)
UTEST_R2_FORM_WITH_OP(sra, int32_t, -0x12340000, 17, >>)

// RV64B

UTEST_R2_FORM_WITH_RES(sh1add, int32_t, LARGE_UINT_UNDER_32_BIT,
                       LARGE_INT_UNDER_32_BIT,
                       int32_t((LARGE_INT_UNDER_32_BIT) +
                               (LARGE_UINT_UNDER_32_BIT << 1)))
UTEST_R2_FORM_WITH_RES(sh2add, int32_t, LARGE_UINT_UNDER_32_BIT,
                       LARGE_INT_UNDER_32_BIT,
                       int32_t((LARGE_INT_UNDER_32_BIT) +
                               (LARGE_UINT_UNDER_32_BIT << 2)))
UTEST_R2_FORM_WITH_RES(sh3add, int32_t, LARGE_UINT_UNDER_32_BIT,
                       LARGE_INT_UNDER_32_BIT,
                       int32_t((LARGE_INT_UNDER_32_BIT) +
                               (LARGE_UINT_UNDER_32_BIT << 3)))

UTEST_R2_FORM_WITH_RES(andn, int32_t, LARGE_UINT_UNDER_32_BIT,
                       LARGE_INT_UNDER_32_BIT,
                       int32_t((LARGE_UINT_UNDER_32_BIT) &
                               (~LARGE_INT_UNDER_32_BIT)))

UTEST_R2_FORM_WITH_RES(orn, int32_t, LARGE_UINT_UNDER_32_BIT,
                       LARGE_INT_UNDER_32_BIT,
                       int32_t((LARGE_UINT_UNDER_32_BIT) |
                               (~LARGE_INT_UNDER_32_BIT)))

UTEST_R2_FORM_WITH_RES(xnor, int32_t, LARGE_UINT_UNDER_32_BIT,
                       LARGE_INT_UNDER_32_BIT,
                       int32_t((~LARGE_UINT_UNDER_32_BIT) ^
                               (~LARGE_INT_UNDER_32_BIT)))

UTEST_R1_FORM_WITH_RES(clz, int32_t, int32_t, 0b000011000100000000000, 15)
UTEST_R1_FORM_WITH_RES(ctz, int32_t, int32_t, 0b000011000100000000000, 11)
UTEST_R1_FORM_WITH_RES(cpop, int32_t, int32_t, 0b000011000100000000000, 3)

UTEST_R2_FORM_WITH_RES(max, int32_t, -1012, 3456, 3456)
UTEST_R2_FORM_WITH_RES(min, int32_t, -1012, 3456, -1012)
UTEST_R2_FORM_WITH_RES(maxu, uint32_t, -1012, 3456, uint32_t(-1012))
UTEST_R2_FORM_WITH_RES(minu, uint32_t, -1012, 3456, 3456)

UTEST_R1_FORM_WITH_RES(sextb, int32_t, int32_t, 0xB080, int32_t(0xffffff80))
UTEST_R1_FORM_WITH_RES(sexth, int32_t, int32_t, 0xB080, int32_t(0xffffb080))
UTEST_R1_FORM_WITH_RES(zexth, int32_t, int32_t, 0xB080, 0xB080)

UTEST_R2_FORM_WITH_RES(rol, uint32_t, 16, 2, 64)
UTEST_R2_FORM_WITH_RES(ror, uint32_t, 16, 2, 4)
UTEST_I_FORM_WITH_RES(rori, int32_t, 16, 2, 4)
UTEST_R1_FORM_WITH_RES(orcb, int32_t, int32_t, 0x10010011, int32_t(0xFFFF00FF))

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

// -- RV32M Standard Extension --
UTEST_R2_FORM_WITH_OP(mul, int32_t, 0x045001, MIN_VAL_IMM12, *)
UTEST_R2_FORM_WITH_RES(mulh, int32_t, 0x12344321, -0x56171234,
                       static_cast<int32_t>((0x12344321LL * -0x56171234LL) >>
                                            32))
UTEST_R2_FORM_WITH_RES(mulhu, int32_t, 0x12345678, 0xF8967021,
                       static_cast<int32_t>((0x12345678ULL * 0xF8967021ULL) >>
                                            32))
UTEST_R2_FORM_WITH_RES(mulhsu, int32_t, -0x12345678, 0xF2345678,
                       static_cast<int32_t>((-0x12345678LL * 0xF2345678ULL) >>
                                            32))
UTEST_R2_FORM_WITH_OP(div, int32_t, LARGE_INT_UNDER_32_BIT, MIN_VAL_IMM12, /)
UTEST_R2_FORM_WITH_OP(divu, uint32_t, LARGE_UINT_UNDER_32_BIT, 100, /)
UTEST_R2_FORM_WITH_OP(rem, int32_t, LARGE_INT_UNDER_32_BIT, MIN_VAL_IMM12, %)
UTEST_R2_FORM_WITH_OP(remu, uint32_t, LARGE_UINT_UNDER_32_BIT, 100, %)

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
UTEST_COMPARE_WITH_OP_F(flt_s, float, -3456.56, -3456.56, <)
UTEST_COMPARE_WITH_OP_F(fle_s, float, -3456.56, -3456.56, <=)
UTEST_CONV_F_FROM_I(fcvt_s_w, int32_t, float, -100, (float)(-100))
UTEST_CONV_F_FROM_I(fcvt_s_wu, uint32_t, float,
                    std::numeric_limits<uint32_t>::max(),
                    (float)(std::numeric_limits<uint32_t>::max()))
UTEST_CONV_I_FROM_F(fcvt_w_s, float, int32_t, RMM, -100.5f, -101)
UTEST_CONV_I_FROM_F(fcvt_wu_s, float, uint32_t, RUP, 256.1f, 257)
UTEST_R2_FORM_WITH_RES_F(fsgnj_s, float, -100.0f, 200.0f, 100.0f)
UTEST_R2_FORM_WITH_RES_F(fsgnjn_s, float, 100.0f, 200.0f, -100.0f)
UTEST_R2_FORM_WITH_RES_F(fsgnjx_s, float, -100.0f, 200.0f, -100.0f)

// -- RV32D Standard Extension --
// TODO(rv32 simulator don't support double args)
// UTEST_CONV_F_FROM_F(fcvt_s_d, double, float, 100.0, 100.0f)
// UTEST_CONV_F_FROM_F(fcvt_d_s, float, double, 100.0f, 100.0)

// UTEST_R2_FORM_WITH_RES_F(fsgnj_d, double, -100.0, 200.0, 100.0)
// UTEST_R2_FORM_WITH_RES_F(fsgnjn_d, double, 100.0, 200.0, -100.0)
// UTEST_R2_FORM_WITH_RES_F(fsgnjx_d, double, -100.0, 200.0, -100.0)

// -- RVC Standard Extension --
UTEST_R1_FORM_WITH_RES_C(c_mv, int32_t, int32_t, 0x0f5600ab, 0x0f5600ab)

// -- Assembler Pseudo Instructions --
UTEST_R1_FORM_WITH_RES(mv, int32_t, int32_t, 0x0f5600ab, 0x0f5600ab)
UTEST_R1_FORM_WITH_RES(not_, int32_t, int32_t, 0, ~0)
UTEST_R1_FORM_WITH_RES(neg, int32_t, int32_t, 0xab123400, -(0xab123400))
UTEST_R1_FORM_WITH_RES(seqz, int32_t, int32_t, 20, 20 == 0)
UTEST_R1_FORM_WITH_RES(snez, int32_t, int32_t, 20, 20 != 0)
UTEST_R1_FORM_WITH_RES(sltz, int32_t, int32_t, -20, -20 < 0)
UTEST_R1_FORM_WITH_RES(sgtz, int32_t, int32_t, -20, -20 > 0)

UTEST_R1_FORM_WITH_RES_F(fmv_s, float, -23.5f, -23.5f)
UTEST_R1_FORM_WITH_RES_F(fabs_s, float, -23.5f, 23.5f)
UTEST_R1_FORM_WITH_RES_F(fneg_s, float, 23.5f, -23.5f)
// TODO(rv32 simulator don't support double args)
// UTEST_R1_FORM_WITH_RES_F(fmv_d, double, -23.5, -23.5)
// UTEST_R1_FORM_WITH_RES_F(fabs_d, double, -23.5, 23.5)
// UTEST_R1_FORM_WITH_RES_F(fneg_d, double, 23.5, -23.5)

// Test fmv_d
TEST(RISCV_UTEST_fmv_d_double) {
  CcTest::InitializeVM();

  double src = base::bit_cast<double>(0xC037800000000000);  // -23.5
  double dst;
  auto fn = [](MacroAssembler& assm) {
    __ fld(ft0, a0, 0);
    __ fmv_d(fa0, ft0);
    __ fsd(fa0, a1, 0);
  };
  GenAndRunTest<int32_t, int32_t>(reinterpret_cast<int32_t>(&src),
                                  reinterpret_cast<int32_t>(&dst), fn);
  CHECK_EQ(base::bit_cast<int64_t>(0xC037800000000000),
           base::bit_cast<int64_t>(dst));
}

// Test signaling NaN in FMV.D
TEST(RISCV_UTEST_fmv_d_double_signaling_NaN) {
  CcTest::InitializeVM();

  int64_t src = base::bit_cast<int64_t>(0x7ff4000000000000);
  int64_t dst;
  auto fn = [](MacroAssembler& assm) {
    __ fld(ft0, a0, 0);
    __ fmv_d(fa0, ft0);
    __ fsd(fa0, a1, 0);
  };

  GenAndRunTest<int32_t, int32_t>(reinterpret_cast<int32_t>(&src),
                                  reinterpret_cast<int32_t>(&dst), fn);
  CHECK_EQ(base::bit_cast<int64_t>(0x7ff4000000000000),
           base::bit_cast<int64_t>(dst));
}

// Test LI
TEST(RISCV0) {
  CcTest::InitializeVM();

  FOR_INT32_INPUTS(i) {
    auto fn = [i](MacroAssembler& assm) { __ RV_li(a0, i); };
    auto res = GenAndRunTest(fn);
    CHECK_EQ(i, res);
  }
}

TEST(RISCV1) {
  CcTest::InitializeVM();

  Label L, C;
  auto fn = [&L, &C](MacroAssembler& assm) {
    __ mv(a1, a0);
    __ RV_li(a0, 0l);
    __ j(&C);

    __ bind(&L);
    __ add(a0, a0, a1);
    __ addi(a1, a1, -1);

    __ bind(&C);
    __ xori(a2, a1, 0);
    __ bnez(a2, &L);
  };

  int32_t input = 50;
  int32_t expected_res = 1275L;
  auto res = GenAndRunTest<int32_t>(input, fn);
  CHECK_EQ(expected_res, res);
}

TEST(RISCV2) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Label exit, error;
  int64_t expected_res = 0x31415926L;

  // ----- Test all instructions.

  // Test lui, ori, and addi, used in the
  // li pseudo-instruction. This way we
  // can then safely load registers with
  // chosen values.
  auto fn = [&exit, &error, expected_res](MacroAssembler& assm) {
    __ ori(a4, zero_reg, 0);
    __ lui(a4, 0x12345);
    __ ori(a4, a4, 0);
    __ ori(a4, a4, 0xF0F);
    __ ori(a4, a4, 0x0F0);
    __ addi(a5, a4, 1);
    __ addi(a6, a5, -0x10);

    // Load values in temporary registers.
    __ RV_li(a4, 0x00000004);
    __ RV_li(a5, 0x00001234);
    __ RV_li(a6, 0x12345678);
    __ RV_li(a7, 0x7FFFFFFF);
    __ RV_li(t0, 0xFFFFFFFC);
    __ RV_li(t1, 0xFFFFEDCC);
    __ RV_li(t2, 0xEDCBA988);
    __ RV_li(t3, 0x80000000);

    __ srli(t0, a6, 8);   // 0x00123456
    __ slli(t0, t0, 11);  // 0x91A2B000
    __ srai(t0, t0, 3);   // 0xF2345600
    __ sra(t0, t0, a4);   // 0xFF234560
    __ sll(t0, t0, a4);   // 0xF2345600
    __ srl(t0, t0, a4);   // 0x0F234560
    __ RV_li(t5, 0x0F234560);
    __ bne(t0, t5, &error);

    __ add(t0, a4, a5);  // 0x00001238
    __ sub(t0, t0, a4);  // 0x00001234
    __ RV_li(t5, 0x00001234);
    __ bne(t0, t5, &error);
    _
```