Response: The user wants me to analyze a C++ source code file for the RISC-V architecture within the V8 JavaScript engine. Specifically, I need to:

1. **Summarize the file's purpose.**  Based on the file name (`test-assembler-riscv32.cc`) and the included headers (`assembler-inl.h`, `macro-assembler.h`, `simulator.h`, `test/cctest/cctest.h`), it's clear this file contains unit tests for the RISC-V 32-bit assembler in V8. These tests likely verify the correct generation of RISC-V instructions.

2. **Explain the connection to JavaScript.** The V8 engine executes JavaScript code. To do this efficiently, it often compiles JavaScript to native machine code. This file tests the part of V8 responsible for generating RISC-V machine code. The tests ensure that when V8 needs to generate a specific RISC-V instruction for a JavaScript operation, it does so correctly.

3. **Provide a JavaScript example.**  I need to come up with a simple JavaScript snippet and explain how its execution might lead to the generation of the RISC-V instructions being tested in the C++ file. The C++ code has numerous tests for arithmetic operations, memory access, and floating-point operations. I should choose a basic example that covers some of these.

**Mental Sandbox:**

* **Initial thought for JavaScript example:**  `let x = 1 + 2;`  This involves integer addition, which has corresponding tests in the C++ file (`UTEST_R2_FORM_WITH_OP(add, ...)`).

* **Expanding the example:**  To demonstrate memory access, I could use an array: `let arr = [1, 2]; let y = arr[0];`. This relates to load instructions (`UTEST_LOAD_STORE(lw, sw, ...)`).

* **Adding floating-point:** `let f = 1.5 * 2.0;`. This connects to the floating-point instruction tests (`UTEST_R2_FORM_WITH_OP_F(fmul_s, ...)`).

* **Considering the macros:** The C++ code heavily uses macros like `UTEST_R2_FORM_WITH_RES`, `UTEST_I_FORM_WITH_RES`, etc. These seem to define individual test cases for specific RISC-V instructions or instruction patterns. The goal of these tests is to generate a snippet of RISC-V code for a particular instruction and then simulate its execution to check if the result is as expected.

* **Refining the JavaScript explanation:** I need to explain that V8's compiler (like TurboFan or Crankshaft) would be responsible for translating the JavaScript into RISC-V. The tests in the C++ file verify that this translation process works correctly for different RISC-V instructions.

**Final Plan:**

1. State that the C++ file tests the RISC-V 32-bit assembler in V8.
2. Explain that this assembler is used by V8's compiler to generate machine code from JavaScript.
3. Provide a JavaScript example covering integer arithmetic, array access, and floating-point multiplication.
4. Explain how each part of the JavaScript example might correspond to specific RISC-V instructions being tested in the C++ file (e.g., addition maps to `add`, array access maps to load/store instructions, floating-point multiplication maps to `fmul.s`).
这个C++源代码文件 `test-assembler-riscv32.cc` 的功能是**为 V8 JavaScript 引擎中的 RISC-V 32位汇编器编写单元测试**。

具体来说，这个文件的主要目的是：

1. **测试 RISC-V 32位指令的正确生成和执行:** 文件中包含了大量的测试用例，每个测试用例都针对 RISC-V 架构的特定指令或指令序列。这些测试用例会生成相应的 RISC-V 汇编代码，然后在模拟器中运行，并验证其结果是否符合预期。

2. **覆盖 RISC-V 的各种指令类型:**  从代码中可以看出，测试覆盖了算术运算指令 (如 `add`, `sub`, `mul`, `div`)、逻辑运算指令 (`and`, `or`, `xor`)、位操作指令 (`sll`, `srl`, `sra`)、加载和存储指令 (`lw`, `sw`, `lb`, `sb`)、浮点运算指令 (`fadd.s`, `fmul.s`, `fdiv.s`)、原子操作指令 (`amoswap.w`)、控制流指令 (通过 `GenAndRunTest` 等辅助函数间接测试) 以及 RISC-V 扩展指令集 (如 RV32M 和 RV32F)。

3. **使用宏简化测试用例的编写:**  文件中定义了大量的宏，如 `UTEST_R2_FORM_WITH_RES`, `UTEST_I_FORM_WITH_RES`, `UTEST_LOAD_STORE` 等。这些宏可以大大简化编写重复性测试代码的工作，提高了测试代码的效率和可读性。

**它与 JavaScript 的功能有很强的关系。** V8 引擎负责执行 JavaScript 代码，而为了提高执行效率，V8 会将 JavaScript 代码编译成机器码执行。在 RISC-V 架构上，V8 就需要一个 RISC-V 汇编器来生成相应的机器码指令。

这个 `test-assembler-riscv32.cc` 文件中的测试用例，正是用来保证 V8 的 RISC-V 汇编器能够正确地将 V8 内部的操作 (这些操作是执行 JavaScript 代码的基础) 翻译成正确的 RISC-V 机器指令。

**JavaScript 举例说明:**

假设我们在 JavaScript 中执行以下代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
```

当 V8 引擎执行这段 JavaScript 代码时，它会将 `add` 函数编译成 RISC-V 机器码。  `a + b` 这个加法操作就需要被翻译成 RISC-V 的加法指令。

在 `test-assembler-riscv32.cc` 中，你可能会找到类似以下的测试用例来验证 RISC-V 加法指令的正确性：

```c++
UTEST_R2_FORM_WITH_OP(add, int32_t, LARGE_INT_UNDER_32_BIT, MIN_VAL_IMM12, +)
```

这个测试用例会：

1. **生成 RISC-V `add` 指令:**  它会生成将两个寄存器中的值相加的 RISC-V 指令。
2. **设置输入值:** 将 `LARGE_INT_UNDER_32_BIT` 和 `MIN_VAL_IMM12` 放入模拟器的寄存器中。
3. **执行指令:** 在 RISC-V 模拟器中执行生成的 `add` 指令。
4. **验证结果:** 检查模拟器中目标寄存器的值是否等于预期的结果 (`LARGE_INT_UNDER_32_BIT + MIN_VAL_IMM12`)。

当 V8 在编译 JavaScript 的 `a + b` 时，它会使用其内部的 RISC-V 汇编器来生成相应的 `add` 指令，类似于测试用例中生成的那样。  这些测试确保了 V8 生成的 `add` 指令是正确的，从而保证了 JavaScript 代码的加法操作能够被正确执行。

再举一个例子，如果 JavaScript 中有数组访问：

```javascript
let arr = [1, 2, 3];
let firstElement = arr[0];
```

V8 编译这段代码时，访问 `arr[0]` 就需要生成 RISC-V 的加载指令 (例如 `lw`) 来从内存中读取数组的第一个元素。  在 `test-assembler-riscv32.cc` 中，你可以找到类似的加载指令测试：

```c++
UTEST_LOAD_STORE(lw, sw, int32_t, 0x456AF894)
```

这个测试用例会测试 `lw` (load word) 和 `sw` (store word) 指令的组合使用，确保数据可以正确地从内存加载到寄存器。

总而言之，`test-assembler-riscv32.cc` 通过大量的单元测试来保证 V8 引擎在 RISC-V 32位架构下，能够正确地将 JavaScript 的各种操作翻译成底层的机器指令，从而确保 JavaScript 代码能够在该架构上正确高效地执行。

### 提示词
```
这是目录为v8/test/cctest/test-assembler-riscv32.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```
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
    __ add(a1, a7,
           a4);  // 32bit addu result is sign-extended into 64bit reg.
    __ RV_li(t5, 0x80000003);
    __ bne(a1, t5, &error);
    __ sub(a1, t3, a4);  // 0x7FFFFFFC
    __ RV_li(t5, 0x7FFFFFFC);
    __ bne(a1, t5, &error);

    __ and_(t0, a5, a6);  // 0x00001230
    __ or_(t0, t0, a5);   // 0x00001234
    __ xor_(t0, t0, a6);  // 0x1234444C
    __ or_(t0, t0, a6);
    __ not_(t0, t0);  // 0xEDCBA983
    __ RV_li(t5, 0xEDCBA983);
    __ bne(t0, t5, &error);

    // Test slli, slt and sltu.
    __ slli(a7, a7, 31);  // 0x80000000
    __ addi(t3, t3, 1);   // 0x80000001
    __ slli(t3, t3, 30);  // 0x40000000
    __ RV_li(t5, 1);

    __ slt(t0, a7, t3);
    __ bne(t0, t5, &error);
    __ sltu(t0, a7, t3);
    __ bne(t0, zero_reg, &error);

    __ RV_li(t0, 0x7421);    // 0x00007421
    __ addi(t0, t0, -0x1);   // 0x00007420
    __ addi(t0, t0, -0x20);  // 0x00007400
    __ RV_li(t5, 0x00007400);
    __ bne(t0, t5, &error);
    __ addi(a1, a7, 0x0);  // 0x80000000 -
    __ RV_li(t5, 0x80000000);
    __ bne(a1, t5, &error);

    // Everything was correctly executed.
    // Load the expected result.
    __ RV_li(a0, expected_res);
    __ j(&exit);

    __ bind(&error);
    // Got an error. Return a wrong result.
    __ RV_li(a0, 666);

    __ bind(&exit);
  };
  auto res = GenAndRunTest(fn);
  CHECK_EQ(expected_res, res);
}

TEST(RISCV3) {
  // Test floating point instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    double a;
    double b;
    double c;
    double d;
    double e;
    double f;
    double g;
    double h;
    double i;
    float fa;
    float fb;
    float fc;
    float fd;
    float fe;
    float ff;
    float fg;
  } t;

  // Create a function that accepts &t and loads, manipulates, and stores
  // the doubles t.a ... t.f.

  // Double precision floating point instructions.
  auto fn = [](MacroAssembler& assm) {
    __ fld(ft0, a0, offsetof(T, a));
    __ fld(ft1, a0, offsetof(T, b));
    __ fadd_d(ft2, ft0, ft1);
    __ fsd(ft2, a0, offsetof(T, c));  // c = a + b.

    __ fmv_d(ft3, ft2);   // c
    __ fneg_d(fa0, ft1);  // -b
    __ fsub_d(ft3, ft3, fa0);
    __ fsd(ft3, a0, offsetof(T, d));  // d = c - (-b).

    __ fsd(ft0, a0, offsetof(T, b));  // b = a.

    __ RV_li(a4, 120);
    __ fcvt_d_w(ft5, a4);
    __ fmul_d(ft3, ft3, ft5);
    __ fsd(ft3, a0, offsetof(T, e));  // e = d * 120 = 1.8066e16.

    __ fdiv_d(ft4, ft3, ft0);
    __ fsd(ft4, a0, offsetof(T, f));  // f = e / a = 120.44.

    __ fsqrt_d(ft5, ft4);
    __ fsd(ft5, a0, offsetof(T, g));
    // g = sqrt(f) = 10.97451593465515908537

    __ fld(ft0, a0, offsetof(T, h));
    __ fld(ft1, a0, offsetof(T, i));
    __ fmadd_d(ft5, ft1, ft0, ft1);
    __ fsd(ft5, a0, offsetof(T, h));

    // // Single precision floating point instructions.
    __ flw(ft0, a0, offsetof(T, fa));
    __ flw(ft1, a0, offsetof(T, fb));
    __ fadd_s(ft2, ft0, ft1);
    __ fsw(ft2, a0, offsetof(T, fc));  // fc = fa + fb.

    __ fneg_s(ft3, ft1);  // -fb
    __ fsub_s(ft3, ft2, ft3);
    __ fsw(ft3, a0, offsetof(T, fd));  // fd = fc - (-fb).

    __ fsw(ft0, a0, offsetof(T, fb));  // fb = fa.

    __ RV_li(t0, 120);
    __ fcvt_s_w(ft5, t0);  // ft5 = 120.0.
    __ fmul_s(ft3, ft3, ft5);
    __ fsw(ft3, a0, offsetof(T, fe));  // fe = fd * 120

    __ fdiv_s(ft4, ft3, ft0);
    __ fsw(ft4, a0, offsetof(T, ff));  // ff = fe / fa

    __ fsqrt_s(ft5, ft4);
    __ fsw(ft5, a0, offsetof(T, fg));
  };
  auto f = AssembleCode<F3>(isolate, fn);

  // Double test values.
  t.a = 1.5e14;
  t.b = 2.75e11;
  t.c = 0.0;
  t.d = 0.0;
  t.e = 0.0;
  t.f = 0.0;
  t.h = 1.5;
  t.i = 2.75;
  // Single test values.
  t.fa = 1.5e6;
  t.fb = 2.75e4;
  t.fc = 0.0;
  t.fd = 0.0;
  t.fe = 0.0;
  t.ff = 0.0;
  f.Call(&t, 0, 0, 0, 0);
  // Expected double results.
  CHECK_EQ(1.5e14, t.a);
  CHECK_EQ(1.5e14, t.b);
  CHECK_EQ(1.50275e14, t.c);
  CHECK_EQ(1.50550e14, t.d);
  CHECK_EQ(1.8066e16, t.e);
  CHECK_EQ(120.44, t.f);
  CHECK_EQ(10.97451593465515908537, t.g);
  CHECK_EQ(6.875, t.h);
  // Expected single results.
  CHECK_EQ(1.5e6, t.fa);
  CHECK_EQ(1.5e6, t.fb);
  CHECK_EQ(1.5275e06, t.fc);
  CHECK_EQ(1.5550e06, t.fd);
  CHECK_EQ(1.866e08, t.fe);
  CHECK_EQ(124.40000152587890625, t.ff);
  CHECK_EQ(11.1534748077392578125, t.fg);
}
TEST(RISCV4) {
  // Test moves between floating point and
  // integer registers.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    float a;
    float b;
    float c;
    float d;
    int32_t e;
  } t;

  auto fn = [](MacroAssembler& assm) {
    __ flw(ft0, a0, offsetof(T, a));
    __ flw(fa1, a0, offsetof(T, b));

    // Swap ft0 and fa1, by using 2 integer registers, a4-a5,
    __ fmv_x_w(a4, ft0);
    __ fmv_x_w(a5, fa1);

    __ fmv_w_x(fa1, a4);
    __ fmv_w_x(ft0, a5);

    // Store the swapped ft0 and fa1 back to memory.
    __ fsw(ft0, a0, offsetof(T, a));
    __ fsw(fa1, a0, offsetof(T, c));

    __ flw(ft0, a0, offsetof(T, d));
    __ fmv_x_w(a4, ft0);

    __ sw(a4, a0, offsetof(T, e));
  };
  auto f = AssembleCode<F3>(isolate, fn);

  t.a = 1.5e22;
  t.b = 2.75e11;
  t.c = 17.17;
  t.d = -2.75e11;
  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(2.75e11f, t.a);
  CHECK_EQ(2.75e11f, t.b);
  CHECK_EQ(1.5e22f, t.c);
  CHECK_EQ(static_cast<int32_t>(0xD2800E8E), t.e);
}

TEST(RISCV5) {
  // Test conversions between doubles and
  // integers.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    double a;
    double b;
    int i;
    int j;
  } t;

  auto fn = [](MacroAssembler& assm) {
    // Load all structure elements to registers.
    __ fld(ft0, a0, offsetof(T, a));
    __ fld(ft1, a0, offsetof(T, b));
    __ lw(a4, a0, offsetof(T, i));
    __ lw(a5, a0, offsetof(T, j));

    // Convert double in ft0 to int in element i.
    __ fcvt_w_d(a6, ft0);
    __ sw(a6, a0, offsetof(T, i));

    // Convert double in ft1 to int in element j.
    __ fcvt_w_d(a7, ft1);
    __ sw(a7, a0, offsetof(T, j));

    // Convert int in original i (a4) to double in a.
    __ fcvt_d_w(fa0, a4);
    __ fsd(fa0, a0, offsetof(T, a));

    // Convert int in original j (a5) to double in b.
    __ fcvt_d_w(fa1, a5);
    __ fsd(fa1, a0, offsetof(T, b));
  };
  auto f = AssembleCode<F3>(isolate, fn);

  t.a = 1.5e4;
  t.b = 2.75e4;
  t.i = 24000;
  t.j = -100000;
  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(24000, t.a);
  CHECK_EQ(-100000.0, t.b);
  CHECK_EQ(15000, t.i);
  CHECK_EQ(27500, t.j);
}

TEST(RISCV6) {
  // Test simple memory loads and stores.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    uint32_t ui;
    int32_t si;
    int32_t r1;
    int32_t r2;
    int32_t r3;
    int32_t r4;
    int32_t r5;
    int32_t r6;
  } t;

  auto fn = [](MacroAssembler& assm) {
    // Basic word load/store.
    __ lw(a4, a0, offsetof(T, ui));
    __ sw(a4, a0, offsetof(T, r1));

    // lh with positive data.
    __ lh(a5, a0, offsetof(T, ui));
    __ sw(a5, a0, offsetof(T, r2));

    // lh with negative data.
    __ lh(a6, a0, offsetof(T, si));
    __ sw(a6, a0, offsetof(T, r3));

    // lhu with negative data.
    __ lhu(a7, a0, offsetof(T, si));
    __ sw(a7, a0, offsetof(T, r4));

    // Lb with negative data.
    __ lb(t0, a0, offsetof(T, si));
    __ sw(t0, a0, offsetof(T, r5));

    // sh writes only 1/2 of word.
    __ RV_li(t1, 0x33333333);
    __ sw(t1, a0, offsetof(T, r6));
    __ lhu(t1, a0, offsetof(T, si));
    __ sh(t1, a0, offsetof(T, r6));
  };
  auto f = AssembleCode<F3>(isolate, fn);

  t.ui = 0x11223344;
  t.si = 0x99AABBCC;
  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(static_cast<int32_t>(0x11223344), t.r1);
  if (kArchEndian == kLittle) {
    CHECK_EQ(static_cast<int32_t>(0x3344), t.r2);
    CHECK_EQ(static_cast<int32_t>(0xFFFFBBCC), t.r3);
    CHECK_EQ(static_cast<int32_t>(0x0000BBCC), t.r4);
    CHECK_EQ(static_cast<int32_t>(0xFFFFFFCC), t.r5);
    CHECK_EQ(static_cast<int32_t>(0x3333BBCC), t.r6);
  } else {
    CHECK_EQ(static_cast<int32_t>(0x1122), t.r2);
    CHECK_EQ(static_cast<int32_t>(0xFFFF99AA), t.r3);
    CHECK_EQ(static_cast<int32_t>(0x000099AA), t.r4);
    CHECK_EQ(static_cast<int32_t>(0xFFFFFF99), t.r5);
    CHECK_EQ(static_cast<int32_t>(0x99AA3333), t.r6);
  }
}

// pair.first is the F_TYPE input to test, pair.second is I_TYPE expected result
template <typename T>
static const std::vector<std::pair<T, uint32_t>> fclass_test_values() {
  static const std::pair<T, uint32_t> kValues[] = {
      std::make_pair(-std::numeric_limits<T>::infinity(), kNegativeInfinity),
      std::make_pair(-10240.56, kNegativeNormalNumber),
      std::make_pair(-(std::numeric_limits<T>::min() / 2),
                     kNegativeSubnormalNumber),
      std::make_pair(-0.0, kNegativeZero),
      std::make_pair(+0.0, kPositiveZero),
      std::make_pair((std::numeric_limits<T>::min() / 2),
                     kPositiveSubnormalNumber),
      std::make_pair(10240.56, kPositiveNormalNumber),
      std::make_pair(std::numeric_limits<T>::infinity(), kPositiveInfinity),
#ifndef USE_SIMULATOR
      std::make_pair(std::numeric_limits<T>::signaling_NaN(), kSignalingNaN),
#endif
      std::make_pair(std::numeric_limits<T>::quiet_NaN(), kQuietNaN)};
  return std::vector<std::pair<T, uint32_t>>(&kValues[0],
                                             &kValues[arraysize(kValues)]);
}

TEST(FCLASS) {
  CcTest::InitializeVM();
  {
    auto i_vec = fclass_test_values<float>();
    for (auto i = i_vec.begin(); i != i_vec.end(); ++i) {
      auto input = *i;
      auto fn = [](MacroAssembler& assm) { __ fclass_s(a0, fa0); };
      auto res = GenAndRunTest<uint32_t>(input.first, fn);
      CHECK_EQ(input.second, res);
    }
  }

  // {
  //   auto i_vec = fclass_test_values<double>();
  //   for (auto i = i_vec.begin(); i != i_vec.end(); ++i) {
  //     auto input = *i;
  //     auto fn = [](MacroAssembler& assm) { __ fclass_d(a0, fa0); };
  //     auto res = GenAndRunTest<uint32_t>(input.first, fn);
  //     CHECK_EQ(input.second, res);
  //   }
  // }
}

TEST(RISCV7) {
  // Test floating point compare and
  // branch instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    double a;
    double b;
    double c;
    double d;
    double e;
    double f;
    int32_t result;
  } t;

  // Create a function that accepts &t,
  // and loads, manipulates, and stores
  // the doubles t.a ... t.f.
  Label neither_is_nan, less_than, outa_here;
  auto fn = [&neither_is_nan, &less_than, &outa_here](MacroAssembler& assm) {
    __ fld(ft0, a0, offsetof(T, a));
    __ fld(ft1, a0, offsetof(T, b));

    __ fclass_d(t5, ft0);
    __ fclass_d(t6, ft1);
    __ or_(t5, t5, t6);
    __ andi(t5, t5, kSignalingNaN | kQuietNaN);
    __ beq(t5, zero_reg, &neither_is_nan);
    __ sw(zero_reg, a0, offsetof(T, result));
    __ j(&outa_here);

    __ bind(&neither_is_nan);

    __ flt_d(t5, ft1, ft0);
    __ bne(t5, zero_reg, &less_than);

    __ sw(zero_reg, a0, offsetof(T, result));
    __ j(&outa_here);

    __ bind(&less_than);
    __ RV_li(a4, 1);
    __ sw(a4, a0, offsetof(T, result));  // Set true.

    // This test-case should have additional
    // tests.

    __ bind(&outa_here);
  };

  auto f = AssembleCode<F3>(isolate, fn);

  t.a = 1.5e14;
  t.b = 2.75e11;
  t.c = 2.0;
  t.d = -4.0;
  t.e = 0.0;
  t.f = 0.0;
  t.result = 0;
  f.Call(&t, 0, 0, 0, 0);
  CHECK_EQ(1.5e14, t.a);
  CHECK_EQ(2.75e11, t.b);
  CHECK_EQ(1, t.result);
}

TEST(RISCV9) {
  // Test BRANCH improvements.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  Label exit, exit2, exit3;

  __ Branch(&exit, ge, a0, Operand(zero_reg));
  __ Branch(&exit2, ge, a0, Operand(0x00001FFF));
  __ Branch(&exit3, ge, a0, Operand(0x0001FFFF));

  __ bind(&exit);
  __ bind(&exit2);
  __ bind(&exit3);
  __ jr(ra);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  USE(code);
}

TEST(NAN_BOX) {
  // Test float NaN-boxing.
  CcTest::InitializeVM();
  // Test NaN boxing in FMV.X.W
  {
    auto fn = [](MacroAssembler& assm) { __ fmv_x_w(a0, fa0); };
    auto res = GenAndRunTest<uint32_t>(1234.56f, fn);
    CHECK_EQ((uint32_t)base::bit_cast<uint32_t>(1234.56f), res);
  }

  // Test signaling NaN in FMV.S
  {
    auto fn = [](MacroAssembler& assm) {
      __ fmv_w_x(fa0, a0);
      __ fmv_s(ft1, fa0);
      __ fmv_s(fa0, ft1);
    };
    auto res = GenAndRunTest<uint32_t>(0x7f400000, fn);
    CHECK_EQ((uint32_t)base::bit_cast<uint32_t>(0x7f400000), res);
  }

  // Test FLW and FSW
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    float a;
    uint64_t box;
    uint64_t res;
  } t;

  auto fn = [](MacroAssembler& assm) {
    // Load all structure elements to registers.
    __ flw(fa0, a0, offsetof(T, a));
    // Check boxing when flw
    __ fsd(fa0, a0, offsetof(T, box));
    // Check only transfer low 32bits when fsw
    __ fsw(fa0, a0, offsetof(T, res));
  };
  auto f = AssembleCode<F3>(isolate, fn);

  t.a = -123.45;
  t.box = 0;
  t.res = 0;
  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(0xFFFFFFFF00000000 | base::bit_cast<int32_t>(t.a), t.box);
  CHECK_EQ((uint64_t)base::bit_cast<uint32_t>(t.a), t.res);
}

TEST(RVC_CI) {
  // Test RV64C extension CI type instructions.
  i::v8_flags.riscv_c_extension = true;
  CcTest::InitializeVM();

  // Test c.addi
  {
    auto fn = [](MacroAssembler& assm) { __ c_addi(a0, -15); };
    auto res = GenAndRunTest<int32_t>(LARGE_INT_UNDER_32_BIT, fn);
    CHECK_EQ(LARGE_INT_UNDER_32_BIT - 15, res);
  }

  // Test c.addi16sp
  {
    auto fn = [](MacroAssembler& assm) {
      __ mv(t1, sp);
      __ mv(sp, a0);
      __ c_addi16sp(-432);
      __ mv(a0, sp);
      __ mv(sp, t1);
    };
    auto res = GenAndRunTest<int32_t>(66666, fn);
    CHECK_EQ(66666 - 432, res);
  }

  // Test c.li
  {
    auto fn = [](MacroAssembler& assm) { __ c_li(a0, -15); };
    auto res = GenAndRunTest<int32_t>(1234543, fn);
    CHECK_EQ(-15, res);
  }

  // Test c.lui
  {
    auto fn = [](MacroAssembler& assm) { __ c_lui(a0, -20); };
    auto res = GenAndRunTest<int32_t>(0x1234567, fn);
    CHECK_EQ(0xfffec000, (uint32_t)res);
  }

  // Test c.slli
  {
    auto fn = [](MacroAssembler& assm) { __ c_slli(a0, 13); };
    auto res = GenAndRunTest<int32_t>(0x12345678, fn);
    CHECK_EQ(0x8acf0000, (uint32_t)res);
  }
}

TEST(RVC_CIW) {
  i::v8_flags.riscv_c_extension = true;
  CcTest::InitializeVM();

  // Test c.addi4spn
  {
    auto fn = [](MacroAssembler& assm) {
      __ mv(t1, sp);
      __ mv(sp, a0);
      __ c_addi4spn(a0, 924);
      __ mv(sp, t1);
    };
    auto res = GenAndRunTest<int32_t>(66666, fn);
    CHECK_EQ(66666 + 924, res);
  }
}

TEST(RVC_CR) {
  // Test RV64C extension CR type instructions.
  i::v8_flags.riscv_c_extension = true;
  CcTest::InitializeVM();

  // Test c.add
  {
    auto fn = [](MacroAssembler& assm) {
      __ RV_li(a1, MIN_VAL_IMM12);
      __ c_add(a0, a1);
    };
    auto res = GenAndRunTest<int32_t>(LARGE_INT_UNDER_32_BIT, fn);
    CHECK_EQ(LARGE_INT_UNDER_32_BIT + MIN_VAL_IMM12, res);
  }
}

TEST(RVC_CA) {
  // Test RV64C extension CA type instructions.
  i::v8_flags.riscv_c_extension = true;
  CcTest::InitializeVM();

  // Test c.sub
  {
    auto fn = [](MacroAssembler& assm) {
      __ RV_li(a1, MIN_VAL_IMM12);
      __ c_sub(a0, a1);
    };
    auto res = GenAndRunTest<int32_t>(LARGE_INT_UNDER_32_BIT, fn);
    CHECK_EQ(LARGE_INT_UNDER_32_BIT - MIN_VAL_IMM12, res);
  }

  // Test c.xor
  {
    auto fn = [](MacroAssembler& assm) {
      __ RV_li(a1, MIN_VAL_IMM12);
      __ c_xor(a0, a1);
    };
    auto res = GenAndRunTest<int32_t>(LARGE_INT_UNDER_32_BIT, fn);
    CHECK_EQ(LARGE_INT_UNDER_32_BIT ^ MIN_VAL_IMM12, res);
  }

  // Test c.or
  {
    auto fn = [](MacroAssembler& assm) {
      __ RV_li(a1, MIN_VAL_IMM12);
      __ c_or(a0, a1);
    };
    auto res = GenAndRunTest<int32_t>(LARGE_INT_UNDER_32_BIT, fn);
    CHECK_EQ(LARGE_INT_UNDER_32_BIT | MIN_VAL_IMM12, res);
  }

  // Test c.and
  {
    auto fn = [](MacroAssembler& assm) {
      __ RV_li(a1, MIN_VAL_IMM12);
      __ c_and(a0, a1);
    };
    auto res = GenAndRunTest<int32_t>(LARGE_INT_UNDER_32_BIT, fn);
    CHECK_EQ(LARGE_INT_UNDER_32_BIT & MIN_VAL_IMM12, res);
  }
}

TEST(RVC_LOAD_STORE_SP) {
  // Test RV32C extension flwsp/fswsp, lwsp/swsp.
  i::v8_flags.riscv_c_extension = true;
  CcTest::InitializeVM();

  {
    auto fn = [](MacroAssembler& assm) {
      __ c_fsdsp(fa0, 80);
      __ c_fldsp(fa0, 80);
    };
    auto res = GenAndRunTest<float>(-3456.678f, fn);
    CHECK_EQ(-3456.678f, res);
  }

  {
    auto fn = [](MacroAssembler& assm) {
      __ c_swsp(a0, 40);
      __ c_lwsp(a0, 40);
    };
    auto res = GenAndRunTest<int32_t>(0x456AF894, fn);
    CHECK_EQ(0x456AF894, res);
  }
}

TEST(RVC_LOAD_STORE_COMPRESSED) {
  // Test RV64C extension fld,  lw, ld.
  i::v8_flags.riscv_c_extension = true;

  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct S {
    int32_t a;
    int32_t b;
    int32_t c;
  } s;
  // c.lw
  {
    auto fn = [](MacroAssembler& assm) {
      __ c_lw(a1, a0, offsetof(S, a));
      __ c_lw(a2, a0, offsetof(S, b));
      __ add(a3, a1, a2);
      __ c_sw(a3, a0, offsetof(S, c));  // c = a + b.
    };
    auto f = AssembleCode<F3>(isolate, fn);

    s.a = 1;
    s.b = 2;
    s.c = 3;
    f.Call(&s, 0, 0, 0, 0);
    CHECK_EQ(1, s.a);
    CHECK_EQ(2, s.b);
    CHECK_EQ(3, s.c);
  }
}

TEST(RVC_JUMP) {
  i::v8_flags.riscv_c_extension = true;
  CcTest::InitializeVM();

  Label L, C;
  auto fn = [&L, &C](MacroAssembler& assm) {
    __ mv(a1, a0);
    __ RV_li(a0, 0l);
    __ c_j(&C);

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

TEST(RVC_CB) {
  // Test RV64C extension CI type instructions.
  v8_flags.riscv_c_extension = true;
  CcTest::InitializeVM();

  // Test c.srai
  {
    auto fn = [](MacroAssembler& assm) { __ c_srai(a0, 13); };
    auto res = GenAndRunTest<int32_t>(0x12345678, fn);
    CHECK_EQ(0x12345678UL >> 13, res);
  }

  // Test c.srli
  {
    auto fn = [](MacroAssembler& assm) { __ c_srli(a0, 13); };
    auto res = GenAndRunTest<int32_t>(0x12345678, fn);
    CHECK_EQ(0x1234'5678ULL >> 13, res);
  }

  // Test c.andi
  {
    auto fn = [](MacroAssembler& assm) { __ c_andi(a0, 13); };
    auto res = GenAndRunTest<int32_t>(LARGE_INT_UNDER_32_BIT, fn);
    CHECK_EQ(LARGE_INT_UNDER_32_BIT & 13, res);
  }
}

TEST(RVC_CB_BRANCH) {
  v8_flags.riscv_c_extension = true;
  // Test floating point compare and
  // branch instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    double a;
    double b;
    double c;
    double d;
    double e;
    double f;
    int32_t result;
  } t;

  // Create a function that accepts &t,
  // and loads, manipulates, and stores
  // the doubles t.a ... t.f.
  Label neither_is_nan, less_than, outa_here;
  auto fn = [&neither_is_nan, &less_than, &outa_here](MacroAssembler& assm) {
    __ fld(ft0, a0, offsetof(T, a));
    __ fld(ft1, a0, offsetof(T, b));

    __ fclass_d(t5, ft0);
    __ fclass_d(t6, ft1);
    __ or_(a1, t5, t6);
    __ andi(a1, a1, kSignalingNaN | kQuietNaN);
    __ c_beqz(a1, &neither_is_nan);
    __ sw(zero_reg, a0, offsetof(T, result));
    __ j(&outa_here);

    __ bind(&neither_is_nan);

    __ flt_d(a1, ft1, ft0);
    __ c_bnez(a1, &less_than);

    __ sw(zero_reg, a0, offsetof(T, result));
    __ j(&outa_here);

    __ bind(&less_than);
    __ RV_li(a4, 1);
    __ sw(a4, a0, offsetof(T, result));  // Set true.

    // This test-case should have additional
    // tests.

    __ bind(&outa_here);
  };

  auto f = AssembleCode<F3>(isolate, fn);

  t.a = 1.5e14;
  t.b = 2.75e11;
  t.c = 2.0;
  t.d = -4.0;
  t.e = 0.0;
  t.f = 0.0;
  t.result = 0;
  f.Call(&t, 0, 0, 0, 0);
  CHECK_EQ(1.5e14, t.a);
  CHECK_EQ(2.75e11, t.b);
  CHECK_EQ(1, t.result);
}

TEST(TARGET_ADDR) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  // This is the series of instructions to load 32 bit address 0x01234567 to a6
  // (li a6,0x1234567)
  uint32_t buffer[2] = {0x01234837,   // lui     a6,0x1234
                        0x56780813};  // addi    a6,a6,1383

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  uintptr_t addr = reinterpret_cast<uintptr_t>(&buffer[0]);
  Address res = __ target_address_at(static_cast<Address>(addr));
  CHECK_EQ(0x01234567L, res);
}

TEST(SET_TARGET_ADDR) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  // This is the series of instructions to load 48 bit address 0xba9876543210
  uint32_t buffer[6] = {0x091ab37,  0x2b330213, 0x00b21213,
                        0x62626213, 0x00621213, 0x02b26213};

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  uintptr_t addr = reinterpret_cast<uintptr_t>(&buffer[0]);
  __ set_target_value_at(static_cast<Address>(addr), 0xba987654L, nullptr,
                         FLUSH_ICACHE_IF_NEEDED);
  Address res = __ target_address_at(static_cast<Address>(addr));
  CHECK_EQ(0xba987654L, res);
}

// pair.first is the F_TYPE input to test, pair.second is I_TYPE expected
// result
template <typename F_TYPE, typename I_TYPE>
static const std::vector<std::pair<F_TYPE, I_TYPE>> out_of_range_test_values() {
  static const std::pair<F_TYPE, I_TYPE> kValues[] = {
      std::make_pair(std::numeric_limits<F_TYPE>::quiet_NaN(),
                     std::numeric_limits<I_TYPE>::max()),
      std::make_pair(std::numeric_limits<F_TYPE>::signaling_NaN(),
                     std::numeric_limits<I_TYPE>::max()),
      std::make_pair(std::numeric_limits<F_TYPE>::infinity(),
                     std::numeric_limits<I_TYPE>::max()),
      std::make_pair(-std::numeric_limits<F_TYPE>::infinity(),
                     std::numeric_limits<I_TYPE>::min()),
      std::make_pair(
          static_cast<F_TYPE>(std::numeric_limits<I_TYPE>::max()) + 1024,
          std::numeric_limits<I_TYPE>::max()),
      std::make_pair(
          static_cast<F_TYPE>(std::numeric_limits<I_TYPE>::min()) - 1024,
          std::numeric_limits<I_TYPE>::min()),
  };
  return std::vector<std::pair<F_TYPE, I_TYPE>>(&kValues[0],
                                                &kValues[arraysize(kValues)]);
}

// Test conversion from wider to narrower types w/ out-of-range values or from
// nan, inf, -inf
TEST(OUT_OF_RANGE_CVT) {
  CcTest::InitializeVM();

  // {  // test fvt_w_d
  //   auto i_vec = out_of_range_test_values<double, int32_t>();
  //   for (auto i = i_vec.begin(); i != i_vec.end(); ++i) {
  //     auto input = *i;
  //     auto fn = [](MacroAssembler& assm) { __ fcvt_w_d(a0, fa0); };
  //     auto res = GenAndRunTest<int32_t>(input.first, fn);
  //     CHECK_EQ(input.second, res);
  //   }
  // }

  {  // test fvt_w_s
    auto i_vec = out_of_range_test_values<float, int32_t>();
    for (auto i = i_vec.begin(); i != i_vec.end(); ++i) {
      auto input = *i;
      auto fn = [](MacroAssembler& assm) { __ fcvt_w_s(a0, fa0); };
      auto res = GenAndRunTest<int32_t>(input.first, fn);
      CHECK_EQ(input.second, res);
    }
  }

  // {  // test fvt_wu_d
  //   auto i_vec = out_of_range_test_values<double, uint32_t>();
  //   for (auto i = i_vec.begin(); i != i_vec.end(); ++i) {
  //     auto input = *i;
  //     auto fn = [](MacroAssembler& assm) { __ fcvt_wu_d(a0, fa0); };
  //     auto res = GenAndRunTest<uint32_t>(input.first, fn);
  //     CHECK_EQ(input.second, res);
  //   }
  // }

  {  // test fvt_wu_s
    auto i_vec = out_of_range_test_values<float, uint32_t>();
    for (auto i = i_vec.begin(); i != i_vec.end(); ++i) {
      auto input = *i;
      auto fn = [](MacroAssembler& assm) { __ fcvt_wu_s(a0, fa0); };
      auto res = GenAndRunTest<uint32_t>(input.first, fn);
      CHECK_EQ(input.second, res);
    }
  }
}

#define FCMP_TEST_HELPER(F, fn, op)                                         \
  {                                                                         \
    auto res1 = GenAndRunTest<int32_t>(std::numeric_limits<F>::quiet_NaN(), \
                                       static_cast<F>(1.0), fn);            \
    CHECK_EQ(false, res1);                                                  \
    auto res2 =                                                             \
        GenAndRunTest<int32_t>(std::numeric_limits<F>::quiet_NaN(),         \
                               std::numeric_limits<F>::quiet_NaN(), fn);    \
    CHECK_EQ(false, res2);                                                  \
    auto res3 =                                                             \
        GenAndRunTest<int32_t>(std::numeric_limits<F>::signaling_NaN(),     \
                               std::numeric_limits<F>::quiet_NaN(), fn);    \
    CHECK_EQ(false, res3);                                                  \
    auto res4 =                                                             \
        GenAndRunTest<int32_t>(std::numeric_limits<F>::quiet_NaN(),         \
                               std::numeric_limits<F>::infinity(), fn);     \
    CHECK_EQ(false, res4);                                                  \
    auto res5 =                                                             \
        GenAndRunTest<int32_t>(std::numeric_limits<F>::infinity(),          \
                               std::numeric_limits<F>::infinity(), fn);     \
    CHECK_EQ((std::numeric_limits<F>::infinity()                            \
                  op std::numeric_limits<F>::infinity()),                   \
             res5);                                                         \
    auto res6 =                                                             \
        GenAndRunTest<int32_t>(-std::numeric_limits<F>::infinity(),         \
                               std::numeric_limits<F>::infinity(), fn);     \
    CHECK_EQ((-std::numeric_limits<F>::infinity()                           \
                  op std::numeric_limits<F>::infinity()),                   \
             res6);                                                         \
  }

TEST(F_NAN) {
  // test floating-point compare w/ NaN, +/-Inf
  CcTest::InitializeVM();

  // floating compare
  auto fn1 = [](MacroAssembler& assm) { __ feq_s(a0, fa0, fa1); };
  FCMP_TEST_HELPER(float, fn1, ==);
  auto fn2 = [](MacroAssembler& assm) { __ flt_s(a0, fa0, fa1); };
  FCMP_TEST_HELPER(float, fn2, <);
  auto fn3 = [](MacroAssembler& assm) { __ fle_s(a0, fa0, fa1); };
  FCMP_TEST_HELPER(float, fn3, <=);

  // double compare
  // auto fn4 = [](MacroAssembler& assm) { __ feq_d(a0, fa0, fa1); };
  // FCMP_TEST_HELPER(double, fn4, ==);
  // auto fn5 = [](MacroAssembler& assm) { __ flt_d(a0, fa0, fa1); };
  // FCMP_TEST_HELPER(double, fn5, <);
  // auto fn6 = [](MacroAssembler& assm) { __ fle_d(a0, fa0, fa1); };
  // FCMP_TEST_HELPER(double, fn6, <=);
}

TEST(jump_tables1) {
  // Test jump tables with forward jumps.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  const int kNumCases = 128;
  int values[kNumCases];
  isolate->random_number_generator()->NextBytes(values, sizeof(values));
  Label labels[kNumCases], done;

  auto fn = [&labels, &done, values](MacroAssembler& assm) {
    __ addi(sp, sp, -4);
    __ Sw(ra, MemOperand(sp));
    __ Align(4);
    {
      __ BlockTrampolinePoolFor(kNumCases * 2 + 6);

      __ auipc(ra, 0);
      __ slli(t3, a0, 2);
      __ add(t3, t3, ra);
      __ Lw(t3, MemOperand(t3, 6 * kInstrSize));
      __ jr(t3);
      __ nop();  // For 16-byte alignment
      for (int i = 0; i < kNumCases; ++i) {
        __ dd(&labels[i]);
      }
    }

    for (int i = 0; i < kNumCases; ++i) {
      __ bind(&labels[i]);
      __ RV_li(a0, values[i]);
      __ j(&done);
    }

    __ bind(&done);
    __ Lw(ra, MemOperand(sp));
    __ addi(sp, sp, 4);

    CHECK_EQ(0, assm.UnboundLabelsCount());
  };
  auto f = AssembleCode<F1>(isolate, fn);

  for (int i = 0; i < kNumCases; ++i) {
    int32_t res = reinterpret_cast<int32_t>(f.Call(i, 0, 0, 0, 0));
    CHECK_EQ(values[i], static_cast<int>(res));
  }
}

TEST(jump_tables2) {
  // Test jump tables with backward jumps.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  const int kNumCases = 128;
  int32_t values[kNumCases];
  isolate->random_number_generator()->NextBytes(values, sizeof(values));
  Label labels[kNumCases], done, dispatch;

  auto fn = [&labels, &done, &dispatch, values](MacroAssembler& assm) {
    __ addi(sp, sp, -4);
    __ Sw(ra, MemOperand(sp));
    __ j(&dispatch);

    for (int i = 0; i < kNumCases; ++i) {
      __ bind(&labels[i]);
      __ RV_li(a0, values[i]);
      __ j(&done);
    }

    __ Align(4);
    __ bind(&dispatch);

    {
      __ BlockTrampolinePoolFor(kNumCases * 2 + 6);

      __ auipc(ra, 0);
      __ slli(t3, a0, 2);
      __ add(t3, t3, ra);
      __ Lw(t3, MemOperand(t3, 6 * kInstrSize));
      __ jr(t3);
      __ nop();  // For 16-byte alignment
      for (int i = 0; i < kNumCases; ++i) {
        __ dd(&labels[i]);
      }
    }
    __ bind(&done);
    __ Lw(ra, MemOperand(sp));
    __ addi(sp, sp, 4);
  };
  auto f = AssembleCode<F1>(isolate, fn);

  for (int i = 0; i < kNumCases; ++i) {
    int32_t res = reinterpret_cast<int32_t>(f.Call(i, 0, 0, 0, 0));
    CHECK_EQ(values[i], res);
  }
}

TEST(jump_tables3) {
  // Test jump tables with backward jumps and embedded heap objects.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  const int kNumCases = 128;
  Handle<Object> values[kNumCases];
  for (int i = 0; i < kNumCases; ++i) {
    double value = isolate->random_number_generator()->NextDouble();
    values[i] = isolate->factory()->NewHeapNumber<AllocationType::kOld>(value);
  }
  Label labels[kNumCases], done, dispatch;
  Tagged<Object> obj;
  int32_t imm32;

  auto fn = [&labels, &done, &dispatch, values, &obj,
             &imm32](MacroAssembler& assm) {
    __ addi(sp, sp, -4);
    __ Sw(ra, MemOperand(sp));

    __ j(&dispatch);

    for (int i = 0; i < kNumCases; ++i) {
      __ bind(&labels[i]);
      obj = *values[i];
      imm32 = obj.ptr();
      __ nop();  // For 8 byte alignment
      __ RV_li(a0, imm32);
      __ nop();  // For 8 byte alignment
      __ j(&done);
    }

    __ bind(&dispatch);
    {
      __ BlockTrampolinePoolFor(kNumCases * 2 + 6);
      __ Align(4);
      __ auipc(ra, 0);
      __ slli(t3, a0, 2);
      __ add(t3, t3, ra);
      __ Lw(t3, MemOperand(t3, 6 * kInstrSize));
      __ jr(t3);
      __ nop();  // For 16-byte alignment
      for (int i = 0; i < kNumCases; ++i) {
        __ dd(&labels[i]);
      }
    }

    __ bind(&done);
    __ Lw(ra, MemOperand(sp));
    __ addi(sp, sp, 4);
  };
  auto f = AssembleCode<F1>(isolate, fn);

  for (int i = 0; i < kNumCases; ++i) {
    Handle<Object> result(
        Tagged<Object>(reinterpret_cast<Address>(f.Call(i, 0, 0, 0, 0))),
        isolate);
#ifdef OBJECT_PRINT
    ::printf("f(%d) = ", i);
    Print(*result, std::cout);
    ::printf("\n");
#endif
    CHECK(values[i].is_identical_to(result));
  }
}

TEST(li_estimate) {
  std::vector<int64_t> immediates = {
      -256,      -255,          0,         255,        8192,      0x7FFFFFFF,
      INT32_MIN, INT32_MAX / 2, INT32_MAX, UINT32_MAX, INT64_MAX, INT64_MAX / 2,
      INT64_MIN};
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  for (auto p : immediates) {
    Label a;
    assm.bind(&a);
    assm.RV_li(t0, p);
    int expected_count = assm.RV_li_count(p, true);
    int count = assm.InstructionsGeneratedSince(&a);
    CHECK_EQ(count, expected_count);
  }
}

#ifdef CAN_USE_RVV_INSTRUCTIONS
#define UTEST_LOAD_STORE_RVV(ldname, stname, SEW, arry)                      \
  TEST(RISCV_UTEST_##stname##ldname##SEW) {                                  \
    if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;                       \
    CcTest::InitializeVM();                                                  \
    Isolate* isolate = CcTest::i_isolate();                                  \
    Han
```