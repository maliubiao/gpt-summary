Response:
The user wants to understand the functionality of a C++ file for testing assembler instructions on the LoongArch64 architecture within the V8 JavaScript engine.

Here's a breakdown of the thought process to analyze the provided code snippet:

1. **Identify the core purpose:** The file name `test-assembler-loong64.cc` and the presence of `TEST()` macros immediately suggest that this file contains unit tests for the assembler component of V8, specifically targeting the LoongArch64 architecture.

2. **Examine individual `TEST()` blocks:** Each `TEST()` block seems to focus on testing a specific set of assembler instructions or a specific instruction. The test names (e.g., `BNEZ_B`, `BL`, `PCADD`, `JIRL`, `LA12`, `LA13`, `FCMP_COND`, `FCVT`, `FFINT`) directly correspond to assembler instructions or groups of instructions.

3. **Analyze the structure within each `TEST()`:**
    * **Initialization:**  `CcTest::InitializeVM()` is a common setup step in V8 tests. `Isolate* isolate = CcTest::i_isolate(); HandleScope scope(isolate);` sets up the necessary V8 environment for code generation.
    * **MacroAssembler:** `MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);` is the key component for generating machine code instructions.
    * **Instruction Emission:**  The `__ instruction(...)` syntax indicates the emission of specific LoongArch64 instructions. For example, `__ li(a2, 0l);` loads an immediate value into a register.
    * **Code Execution:** The generated code is compiled into a `Code` object and then executed using `GeneratedCode<F*>::FromCode(...).Call(...)`. The `F*` template parameter likely indicates the function signature of the generated code (number of arguments).
    * **Verification:** `CHECK_EQ(expected, actual)` is used to assert that the result of the executed code matches the expected value.

4. **Identify test case structures:** Several tests use structs like `TestCaseBnez`, `TestCaseBl`, `TestCaseJirl`, and `TestFloat` to define input values and expected output values for different scenarios. This is a common practice for parameterizing unit tests.

5. **Focus on the logic of individual tests:**
    * **`BNEZ_B`:**  Tests the `bnez` instruction (branch if not equal to zero) by providing different values and offsets and verifying the resulting program counter.
    * **`BL`:** Tests the `bl` instruction (branch with link), which calls a subroutine. The test verifies the return address and the execution flow.
    * **`PCADD`:** Tests PC-relative addressing instructions (`pcaddi`, `pcaddu12i`, `pcaddu18i`, `pcalau12i`) by calculating addresses relative to the program counter.
    * **`JIRL`:** Tests the `jirl` instruction (jump and link register), which is used for indirect jumps and subroutine returns.
    * **`LA12` and `LA13`:** These tests cover various floating-point arithmetic instructions for double-precision (`LA12`) and single-precision (`LA13`) floating-point numbers.
    * **`FCMP_COND`:** Tests floating-point comparison instructions with different condition codes, verifying the results using the `fsel` instruction (floating-point select).
    * **`FCVT`:** Tests floating-point conversion instructions between single and double precision.
    * **`FFINT`:** Tests floating-point to integer conversion instructions.

6. **Check for JavaScript relevance:** The code is primarily focused on testing low-level assembler instructions. While these instructions are the building blocks for the V8 JavaScript engine, the tests themselves don't directly involve JavaScript code or functionality. The connection is indirect: these tests ensure the correctness of the underlying architecture support that allows V8 to execute JavaScript efficiently.

7. **Look for potential programming errors:** The tests implicitly reveal potential errors in the *implementation* of the assembler and the generated code. For example, incorrect offset calculations in branch instructions or incorrect handling of floating-point operations. The `CHECK_EQ` assertions are designed to catch these implementation errors. From a *user's* perspective, a common error could be misunderstanding how branch offsets are calculated or how floating-point comparisons work, which this code verifies.

8. **Address the ".tq" question:** The code provided is `.cc`, not `.tq`. `.tq` files are related to Torque, V8's built-in language for implementing built-in functions. This file is about testing the *assembler*, which is a lower-level component.

9. **Synthesize the summary:** Combine the observations from the individual tests and the overall purpose of the file to create a concise summary of its functionality.

**(Self-correction during the process):** Initially, one might think that because it's part of V8, it must have a direct connection to JavaScript. However, careful examination shows that the code focuses on testing the *assembler* for a specific architecture. The JavaScript connection is that this assembler is used by V8 to execute JavaScript, but the tests themselves are at the machine code level. Also, double-checking the file extension is crucial to answer the `.tq` question correctly.
Based on the provided code snippet, here's a breakdown of the functionality of `v8/test/cctest/test-assembler-loong64.cc` (part 3):

**Core Functionality:**

This part of the file continues to test the functionality of the LoongArch64 assembler within the V8 JavaScript engine. It focuses on verifying the correctness of specific assembler instructions by generating small code snippets and executing them. The tests compare the actual results of the executed instructions with expected outcomes.

**Specific Instructions and Features Tested in this Part:**

* **`bnez_b` (Branch if Not Equal to Zero, Byte Offset):** Tests the conditional branch instruction `bnez` with byte offsets. It verifies that the branch is taken correctly based on the value of a register.
* **`bl` (Branch with Link):**  Tests the `bl` instruction used for function calls. It checks if the program counter jumps to the correct offset and if the return address (ra) is saved correctly.
* **PC-Relative Addressing Instructions (`PCADD` test):**  Tests instructions that calculate addresses relative to the Program Counter (PC), including:
    * `pcaddi`: PC-relative address calculation with a signed 12-bit immediate.
    * `pcaddu12i`: PC-relative address calculation with an unsigned 12-bit immediate.
    * `pcaddu18i`: PC-relative address calculation with an unsigned 18-bit immediate.
    * `pcalau12i`: PC-relative address calculation for loading addresses with an unsigned 12-bit immediate.
* **`jirl` (Jump and Link Register):** Tests the indirect jump instruction `jirl`, which jumps to an address stored in a register. It also verifies the linking behavior (saving the return address).
* **Floating-Point Arithmetic Instructions (`LA12` and `LA13` tests):**  Tests a range of double-precision (`LA12`) and single-precision (`LA13`) floating-point arithmetic instructions like:
    * `fneg_d/s` (Floating-point negate)
    * `fadd_d/s` (Floating-point add)
    * `fsub_d/s` (Floating-point subtract)
    * `fmul_d/s` (Floating-point multiply)
    * `fdiv_d/s` (Floating-point divide)
    * `fmin_d/s`, `fmax_d/s` (Floating-point minimum/maximum)
    * `fmina_d/s`, `fmaxa_d/s` (Absolute floating-point minimum/maximum)
    * `fmadd_d/s`, `fmsub_d/s` (Floating-point fused multiply-add/subtract)
    * `fnmadd_d/s`, `fnmsub_d/s` (Floating-point negated fused multiply-add/subtract)
    * `fsqrt_d/s` (Floating-point square root)
    * (Commented out instructions like `frecip_d/s`, `frsqrt_d/s`, `fscaleb_d/s`, `flogb_d/s`, `fcopysign_d/s`, `fclass_d/s` indicate potential future tests or instructions not fully tested in this snippet.)
* **Floating-Point Comparison Instructions (`FCMP_COND` test):** Tests the `fcmp_cond_d/s` instructions with various condition codes (e.g., `CAF`, `CUN`, `CEQ`, `CLT`, `CNE`, etc.) and uses `fsel` (floating-point select) to verify the comparison results.
* **Floating-Point Conversion Instructions (`FCVT` test):** Tests the conversion between single-precision and double-precision floating-point numbers using `fcvt_d_s` and `fcvt_s_d`.
* **Floating-Point to Integer Conversion Instructions (`FFINT` test):** Tests the conversion of floating-point numbers to integers using `ffint_s_w`, `ffint_s_l`, `ffint_d_w`, and `ffint_d_l`.

**Relationship to JavaScript:**

While this code is C++ and directly tests assembler instructions, it's crucial for the correct execution of JavaScript in V8 on LoongArch64. V8's JavaScript engine compiles JavaScript code into machine code for the target architecture. These tests ensure that the assembler, which is responsible for generating that machine code, is functioning correctly for the LoongArch64 architecture. If these assembler instructions are generated incorrectly, JavaScript code execution would be faulty.

**If `v8/test/cctest/test-assembler-loong64.cc` ended with `.tq`:**

If the file ended with `.tq`, it would be a **Torque** source file. Torque is V8's internal language for defining built-in JavaScript functions and runtime code. Torque code is closer to the JavaScript level but still gets compiled down to machine code. This particular file, being a C++ file testing the assembler, is at a lower level than Torque.

**Code Logic Inference (with assumptions):**

Let's take the `BL` test as an example:

**Assumption:** The code execution starts at the beginning of the generated assembly.

**Input:** `offset` values provided in the `TestCaseBl` struct.

**Logic:**
1. The code initializes a register `a2` to 0.
2. It pushes the current return address (ra) onto the stack.
3. It jumps to the `main_block`.
4. The `bl(offset)` instruction is executed. This will:
   - Store the address of the instruction *after* the `bl` instruction into the `ra` register.
   - Jump to the address `main_block + offset`.
5. Based on the `offset`, execution will jump to one of the labeled blocks (Block 1, Block 2, or Block 4 if positive, Block 1 or Block 2 if negative).
6. Each block increments `a2` by specific values (0x3, 0x30, 0x300, 0x700 respectively).
7. After the block, `jirl(zero_reg, ra, 0)` is executed, which effectively returns to the instruction after the `bl` call in the `main_block`.
8. `or_(a0, a2, zero_reg)` moves the value of `a2` into `a0`.
9. The original return address is popped from the stack.
10. `jirl(zero_reg, ra, 0)` returns from the test function.

**Output:** The final value of `a0`, which reflects the increments performed in the jumped-to block.

**Example with input `offset = -6`:**
- The `bl(-6)` instruction jumps back 6 bytes from the `bl` instruction, landing in "Block 1".
- `a2` is incremented by 0x1 and then 0x2, resulting in `a2 = 3`.
- The function returns, and `a0` becomes 3 (0x3).

**User-Common Programming Errors (Related to Assembler Concepts):**

While users don't directly write this assembler code, understanding these tests can help them grasp potential pitfalls in lower-level programming or when dealing with concepts that assemblers handle:

* **Incorrect Branch Offsets:**  Calculating branch target addresses incorrectly can lead to jumping to the wrong code sections, causing unexpected behavior or crashes. The `BNEZ_B` and `BL` tests directly verify the correct calculation of these offsets.
    ```c++
    // Incorrectly calculating a backward branch offset (assuming instruction sizes)
    // Instead of -6, a programmer might mistakenly use -3 if not accounting for instruction length.
    ```
* **Stack Overflow/Underflow:** Incorrectly managing the stack when pushing and popping registers (like the `Push(ra)` and `Pop(ra)` in the `BL` test) can lead to stack corruption and crashes.
* **Register Allocation Errors:** In more complex assembler code, using the wrong registers or clobbering registers that hold important values can lead to incorrect computations. While not explicitly tested in this snippet, the tests implicitly rely on correct register usage within the generated code.
* **Floating-Point Precision and Comparison Issues:**  Misunderstanding how floating-point numbers are represented and compared can lead to unexpected results. The `FCMP_COND` test highlights the nuances of floating-point comparisons (e.g., handling NaN, different comparison predicates).
    ```javascript
    // JavaScript example demonstrating a common floating-point comparison issue
    let a = 0.1 + 0.2;
    let b = 0.3;
    if (a !== b) { // This might be true due to floating-point representation
      console.log("Floating-point comparison can be tricky!");
    }
    ```

**Summary of Functionality (Part 3):**

This part of `v8/test/cctest/test-assembler-loong64.cc` focuses on unit-testing various LoongArch64 assembler instructions within V8. It covers conditional branches, subroutine calls, PC-relative addressing, indirect jumps, and a wide array of floating-point arithmetic, comparison, and conversion instructions. These tests are essential for ensuring the correctness of V8's code generation for the LoongArch64 architecture, which directly impacts the correct execution of JavaScript code on those processors.

### 提示词
```
这是目录为v8/test/cctest/test-assembler-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
off
  struct TestCaseBnez tc[] = {
    // value, offset, expected_res
    {      1,     -6,          0x3 },
    {     -2,     -3,         0x30 },
    {      3,      3,        0x300 },
    {     -4,      6,        0x700 },
    {      0,      6,            0 },
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseBnez);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t res = run_bnez_b(tc[i].value, tc[i].offset);
    CHECK_EQ(tc[i].expected_res, res);
  }
}

uint64_t run_bl(int32_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label main_block;
  __ li(a2, 0l);
  __ Push(ra);  // Push is implemented by two instructions, addi_d and st_d
  __ b(&main_block);

  // Block 1
  __ addi_d(a2, a2, 0x1);
  __ addi_d(a2, a2, 0x2);
  __ jirl(zero_reg, ra, 0);

  // Block 2
  __ addi_d(a2, a2, 0x10);
  __ addi_d(a2, a2, 0x20);
  __ jirl(zero_reg, ra, 0);

  // Block 3 (Main)
  __ bind(&main_block);
  __ bl(offset);
  __ or_(a0, a2, zero_reg);
  __ Pop(ra);  // Pop is implemented by two instructions, ld_d and addi_d.
  __ jirl(zero_reg, ra, 0);

  // Block 4
  __ addi_d(a2, a2, 0x100);
  __ addi_d(a2, a2, 0x200);
  __ jirl(zero_reg, ra, 0);

  // Block 5
  __ addi_d(a2, a2, 0x300);
  __ addi_d(a2, a2, 0x400);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}

TEST(BL) {
  CcTest::InitializeVM();
  struct TestCaseBl {
    int32_t offset;
    uint64_t expected_res;
  };

  // clang-format off
  struct TestCaseBl tc[] = {
    // offset, expected_res
    {     -6,          0x3 },
    {     -3,         0x30 },
    {      5,        0x300 },
    {      8,        0x700 },
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseBl);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t res = run_bl(tc[i].offset);
    CHECK_EQ(tc[i].expected_res, res);
  }
}

TEST(PCADD) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label exit, error;
  __ Push(ra);

  // pcaddi
  __ li(a4, 0x1FFFFC);
  __ li(a5, 0);
  __ li(a6, static_cast<int32_t>(0xFFE00000));

  __ bl(1);
  __ pcaddi(a3, 0x7FFFF);
  __ add_d(a2, ra, a4);
  __ Branch(&error, ne, a2, Operand(a3));

  __ bl(1);
  __ pcaddi(a3, 0);
  __ add_d(a2, ra, a5);
  __ Branch(&error, ne, a2, Operand(a3));

  __ bl(1);
  __ pcaddi(a3, 0x80000);
  __ add_d(a2, ra, a6);
  __ Branch(&error, ne, a2, Operand(a3));

  // pcaddu12i
  __ li(a4, 0x7FFFF000);
  __ li(a5, 0);
  __ li(a6, static_cast<int32_t>(0x80000000));

  __ bl(1);
  __ pcaddu12i(a2, 0x7FFFF);
  __ add_d(a3, ra, a4);
  __ Branch(&error, ne, a2, Operand(a3));
  __ bl(1);
  __ pcaddu12i(a2, 0);
  __ add_d(a3, ra, a5);
  __ Branch(&error, ne, a2, Operand(a3));
  __ bl(1);
  __ pcaddu12i(a2, 0x80000);
  __ add_d(a3, ra, a6);
  __ Branch(&error, ne, a2, Operand(a3));

  // pcaddu18i
  __ li(a4, 0x1FFFFC0000);
  __ li(a5, 0);
  __ li(a6, static_cast<int64_t>(0xFFFFFFE000000000));

  __ bl(1);
  __ pcaddu18i(a2, 0x7FFFF);
  __ add_d(a3, ra, a4);
  __ Branch(&error, ne, a2, Operand(a3));

  __ bl(1);
  __ pcaddu18i(a2, 0);
  __ add_d(a3, ra, a5);
  __ Branch(&error, ne, a2, Operand(a3));

  __ bl(1);
  __ pcaddu18i(a2, 0x80000);
  __ add_d(a3, ra, a6);
  __ Branch(&error, ne, a2, Operand(a3));

  // pcalau12i
  __ li(a4, 0x7FFFF000);
  __ li(a5, 0);
  __ li(a6, static_cast<int32_t>(0x80000000));
  __ li(a7, static_cast<int64_t>(0xFFFFFFFFFFFFF000));

  __ bl(1);
  __ pcalau12i(a3, 0x7FFFF);
  __ add_d(a2, ra, a4);
  __ and_(t0, a2, a7);
  __ and_(t1, a3, a7);
  __ Branch(&error, ne, t0, Operand(t1));

  __ bl(1);
  __ pcalau12i(a3, 0);
  __ add_d(a2, ra, a5);
  __ and_(t0, a2, a7);
  __ and_(t1, a3, a7);
  __ Branch(&error, ne, t0, Operand(t1));

  __ bl(1);
  __ pcalau12i(a2, 0x80000);
  __ add_d(a3, ra, a6);
  __ and_(t0, a2, a7);
  __ and_(t1, a3, a7);
  __ Branch(&error, ne, t0, Operand(t1));

  __ li(a0, 0x31415926);
  __ b(&exit);

  __ bind(&error);
  __ li(a0, 0x666);

  __ bind(&exit);
  __ Pop(ra);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  int64_t res = reinterpret_cast<int64_t>(f.Call(0, 0, 0, 0, 0));

  CHECK_EQ(0x31415926L, res);
}

uint64_t run_jirl(int16_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label main_block;
  __ li(a2, 0l);
  __ Push(ra);
  __ b(&main_block);

  // Block 1
  __ addi_d(a2, a2, 0x1);
  __ addi_d(a2, a2, 0x2);
  __ jirl(zero_reg, ra, 0);

  // Block 2
  __ addi_d(a2, a2, 0x10);
  __ addi_d(a2, a2, 0x20);
  __ jirl(zero_reg, ra, 0);

  // Block 3 (Main)
  __ bind(&main_block);
  __ pcaddi(a3, 1);
  __ jirl(ra, a3, offset);
  __ or_(a0, a2, zero_reg);
  __ Pop(ra);  // Pop is implemented by two instructions, ld_d and addi_d.
  __ jirl(zero_reg, ra, 0);

  // Block 4
  __ addi_d(a2, a2, 0x100);
  __ addi_d(a2, a2, 0x200);
  __ jirl(zero_reg, ra, 0);

  // Block 5
  __ addi_d(a2, a2, 0x300);
  __ addi_d(a2, a2, 0x400);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}

TEST(JIRL) {
  CcTest::InitializeVM();
  struct TestCaseJirl {
    int16_t offset;
    uint64_t expected_res;
  };

  // clang-format off
  struct TestCaseJirl tc[] = {
    // offset, expected_res
    {     -7,          0x3 },
    {     -4,         0x30 },
    {      5,        0x300 },
    {      8,        0x700 },
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseJirl);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t res = run_jirl(tc[i].offset);
    CHECK_EQ(tc[i].expected_res, res);
  }
}

TEST(LA12) {
  // Test floating point calculate instructions.
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
    double result_fadd_d;
    double result_fsub_d;
    double result_fmul_d;
    double result_fdiv_d;
    double result_fmadd_d;
    double result_fmsub_d;
    double result_fnmadd_d;
    double result_fnmsub_d;
    double result_fsqrt_d;
    double result_frecip_d;
    double result_frsqrt_d;
    double result_fscaleb_d;
    double result_flogb_d;
    double result_fcopysign_d;
    double result_fclass_d;
  };
  T t;

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // Double precision floating point instructions.
  __ Fld_d(f8, MemOperand(a0, offsetof(T, a)));
  __ Fld_d(f9, MemOperand(a0, offsetof(T, b)));

  __ fneg_d(f10, f8);
  __ fadd_d(f11, f9, f10);
  __ Fst_d(f11, MemOperand(a0, offsetof(T, result_fadd_d)));
  __ fabs_d(f11, f11);
  __ fsub_d(f12, f11, f9);
  __ Fst_d(f12, MemOperand(a0, offsetof(T, result_fsub_d)));

  __ Fld_d(f13, MemOperand(a0, offsetof(T, c)));
  __ Fld_d(f14, MemOperand(a0, offsetof(T, d)));
  __ Fld_d(f15, MemOperand(a0, offsetof(T, e)));

  __ fmin_d(f16, f13, f14);
  __ fmul_d(f17, f15, f16);
  __ Fst_d(f17, MemOperand(a0, offsetof(T, result_fmul_d)));
  __ fmax_d(f18, f13, f14);
  __ fdiv_d(f19, f15, f18);
  __ Fst_d(f19, MemOperand(a0, offsetof(T, result_fdiv_d)));

  __ fmina_d(f16, f13, f14);
  __ fmadd_d(f18, f17, f15, f16);
  __ Fst_d(f18, MemOperand(a0, offsetof(T, result_fmadd_d)));
  __ fnmadd_d(f19, f17, f15, f16);
  __ Fst_d(f19, MemOperand(a0, offsetof(T, result_fnmadd_d)));
  __ fmaxa_d(f16, f13, f14);
  __ fmsub_d(f20, f17, f15, f16);
  __ Fst_d(f20, MemOperand(a0, offsetof(T, result_fmsub_d)));
  __ fnmsub_d(f21, f17, f15, f16);
  __ Fst_d(f21, MemOperand(a0, offsetof(T, result_fnmsub_d)));

  __ Fld_d(f8, MemOperand(a0, offsetof(T, f)));
  __ fsqrt_d(f10, f8);
  __ Fst_d(f10, MemOperand(a0, offsetof(T, result_fsqrt_d)));
  //__ frecip_d(f11, f10);
  //__ frsqrt_d(f12, f8);
  //__ Fst_d(f11, MemOperand(a0, offsetof(T, result_frecip_d)));
  //__ Fst_d(f12, MemOperand(a0, offsetof(T, result_frsqrt_d)));

  /*__ fscaleb_d(f16, f13, f15);
  __ flogb_d(f17, f15);
  __ fcopysign_d(f18, f8, f9);
  __ fclass_d(f19, f9);
  __ Fst_d(f16, MemOperand(a0, offsetof(T, result_fscaleb_d)));
  __ Fst_d(f17, MemOperand(a0, offsetof(T, result_flogb_d)));
  __ Fst_d(f18, MemOperand(a0, offsetof(T, result_fcopysign_d)));
  __ Fst_d(f19, MemOperand(a0, offsetof(T, result_fclass_d)));*/

  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  // Double test values.
  t.a = 1.5e14;
  t.b = -2.75e11;
  t.c = 1.5;
  t.d = -2.75;
  t.e = 120.0;
  t.f = 120.44;
  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(static_cast<double>(-1.502750e14), t.result_fadd_d);
  CHECK_EQ(static_cast<double>(1.505500e14), t.result_fsub_d);
  CHECK_EQ(static_cast<double>(-3.300000e02), t.result_fmul_d);
  CHECK_EQ(static_cast<double>(8.000000e01), t.result_fdiv_d);
  CHECK_EQ(static_cast<double>(-3.959850e04), t.result_fmadd_d);
  CHECK_EQ(static_cast<double>(-3.959725e04), t.result_fmsub_d);
  CHECK_EQ(static_cast<double>(3.959850e04), t.result_fnmadd_d);
  CHECK_EQ(static_cast<double>(3.959725e04), t.result_fnmsub_d);
  CHECK_EQ(static_cast<double>(10.97451593465515908537), t.result_fsqrt_d);
  // CHECK_EQ(static_cast<double>( 8.164965e-08), t.result_frecip_d);
  // CHECK_EQ(static_cast<double>( 8.164966e-08), t.result_frsqrt_d);
  // CHECK_EQ(static_cast<double>(), t.result_fscaleb_d);
  // CHECK_EQ(static_cast<double>( 6.906891), t.result_flogb_d);
  // CHECK_EQ(static_cast<double>( 2.75e11), t.result_fcopysign_d);
  // CHECK_EQ(static_cast<double>(), t.result_fclass_d);
}

TEST(LA13) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    float a;
    float b;
    float c;
    float d;
    float e;
    float result_fadd_s;
    float result_fsub_s;
    float result_fmul_s;
    float result_fdiv_s;
    float result_fmadd_s;
    float result_fmsub_s;
    float result_fnmadd_s;
    float result_fnmsub_s;
    float result_fsqrt_s;
    float result_frecip_s;
    float result_frsqrt_s;
    float result_fscaleb_s;
    float result_flogb_s;
    float result_fcopysign_s;
    float result_fclass_s;
  };
  T t;

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // Float precision floating point instructions.
  __ Fld_s(f8, MemOperand(a0, offsetof(T, a)));
  __ Fld_s(f9, MemOperand(a0, offsetof(T, b)));

  __ fneg_s(f10, f8);
  __ fadd_s(f11, f9, f10);
  __ Fst_s(f11, MemOperand(a0, offsetof(T, result_fadd_s)));
  __ fabs_s(f11, f11);
  __ fsub_s(f12, f11, f9);
  __ Fst_s(f12, MemOperand(a0, offsetof(T, result_fsub_s)));

  __ Fld_s(f13, MemOperand(a0, offsetof(T, c)));
  __ Fld_s(f14, MemOperand(a0, offsetof(T, d)));
  __ Fld_s(f15, MemOperand(a0, offsetof(T, e)));

  __ fmin_s(f16, f13, f14);
  __ fmul_s(f17, f15, f16);
  __ Fst_s(f17, MemOperand(a0, offsetof(T, result_fmul_s)));
  __ fmax_s(f18, f13, f14);
  __ fdiv_s(f19, f15, f18);
  __ Fst_s(f19, MemOperand(a0, offsetof(T, result_fdiv_s)));

  __ fmina_s(f16, f13, f14);
  __ fmadd_s(f18, f17, f15, f16);
  __ Fst_s(f18, MemOperand(a0, offsetof(T, result_fmadd_s)));
  __ fnmadd_s(f19, f17, f15, f16);
  __ Fst_s(f19, MemOperand(a0, offsetof(T, result_fnmadd_s)));
  __ fmaxa_s(f16, f13, f14);
  __ fmsub_s(f20, f17, f15, f16);
  __ Fst_s(f20, MemOperand(a0, offsetof(T, result_fmsub_s)));
  __ fnmsub_s(f21, f17, f15, f16);
  __ Fst_s(f21, MemOperand(a0, offsetof(T, result_fnmsub_s)));

  __ fsqrt_s(f10, f8);
  //__ frecip_s(f11, f10);
  //__ frsqrt_s(f12, f8);
  __ Fst_s(f10, MemOperand(a0, offsetof(T, result_fsqrt_s)));
  //__ Fst_s(f11, MemOperand(a0, offsetof(T, result_frecip_s)));
  //__ Fst_s(f12, MemOperand(a0, offsetof(T, result_frsqrt_s)));

  /*__ fscaleb_s(f16, f13, f15);
  __ flogb_s(f17, f15);
  __ fcopysign_s(f18, f8, f9);
  __ fclass_s(f19, f9);
  __ Fst_s(f16, MemOperand(a0, offsetof(T, result_fscaleb_s)));
  __ Fst_s(f17, MemOperand(a0, offsetof(T, result_flogb_s)));
  __ Fst_s(f18, MemOperand(a0, offsetof(T, result_fcopysign_s)));
  __ Fst_s(f19, MemOperand(a0, offsetof(T, result_fclass_s)));*/
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  // Float test values.
  t.a = 1.5e6;
  t.b = -2.75e4;
  t.c = 1.5;
  t.d = -2.75;
  t.e = 120.0;
  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(static_cast<float>(-1.527500e06), t.result_fadd_s);
  CHECK_EQ(static_cast<float>(1.555000e06), t.result_fsub_s);
  CHECK_EQ(static_cast<float>(-3.300000e02), t.result_fmul_s);
  CHECK_EQ(static_cast<float>(8.000000e01), t.result_fdiv_s);
  CHECK_EQ(static_cast<float>(-3.959850e04), t.result_fmadd_s);
  CHECK_EQ(static_cast<float>(-3.959725e04), t.result_fmsub_s);
  CHECK_EQ(static_cast<float>(3.959850e04), t.result_fnmadd_s);
  CHECK_EQ(static_cast<float>(3.959725e04), t.result_fnmsub_s);
  CHECK_EQ(static_cast<float>(1224.744873), t.result_fsqrt_s);
  // CHECK_EQ(static_cast<float>( 8.164966e-04), t.result_frecip_s);
  // CHECK_EQ(static_cast<float>( 8.164966e-04), t.result_frsqrt_s);
  // CHECK_EQ(static_cast<float>(), t.result_fscaleb_s);
  // CHECK_EQ(static_cast<float>( 6.906890), t.result_flogb_s);
  // CHECK_EQ(static_cast<float>( 2.75e4), t.result_fcopysign_s);
  // CHECK_EQ(static_cast<float>(), t.result_fclass_s);
}

TEST(FCMP_COND) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct TestFloat {
    double dTrue;
    double dFalse;
    double dOp1;
    double dOp2;
    double dCaf;
    double dCun;
    double dCeq;
    double dCueq;
    double dClt;
    double dCult;
    double dCle;
    double dCule;
    double dCne;
    double dCor;
    double dCune;
    double dSaf;
    double dSun;
    double dSeq;
    double dSueq;
    double dSlt;
    double dSult;
    double dSle;
    double dSule;
    double dSne;
    double dSor;
    double dSune;
    float fTrue;
    float fFalse;
    float fOp1;
    float fOp2;
    float fCaf;
    float fCun;
    float fCeq;
    float fCueq;
    float fClt;
    float fCult;
    float fCle;
    float fCule;
    float fCne;
    float fCor;
    float fCune;
    float fSaf;
    float fSun;
    float fSeq;
    float fSueq;
    float fSlt;
    float fSult;
    float fSle;
    float fSule;
    float fSne;
    float fSor;
    float fSune;
  };

  TestFloat test;

  __ Fld_d(f8, MemOperand(a0, offsetof(TestFloat, dOp1)));
  __ Fld_d(f9, MemOperand(a0, offsetof(TestFloat, dOp2)));

  __ Fld_s(f10, MemOperand(a0, offsetof(TestFloat, fOp1)));
  __ Fld_s(f11, MemOperand(a0, offsetof(TestFloat, fOp2)));

  __ Fld_d(f12, MemOperand(a0, offsetof(TestFloat, dFalse)));
  __ Fld_d(f13, MemOperand(a0, offsetof(TestFloat, dTrue)));

  __ Fld_s(f14, MemOperand(a0, offsetof(TestFloat, fFalse)));
  __ Fld_s(f15, MemOperand(a0, offsetof(TestFloat, fTrue)));

  __ fcmp_cond_d(CAF, f8, f9, FCC0);
  __ fcmp_cond_s(CAF, f10, f11, FCC1);
  __ fsel(FCC0, f16, f12, f13);
  __ fsel(FCC1, f17, f14, f15);
  __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dCaf)));
  __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fCaf)));

  __ fcmp_cond_d(CUN, f8, f9, FCC0);
  __ fcmp_cond_s(CUN, f10, f11, FCC1);
  __ fsel(FCC0, f16, f12, f13);
  __ fsel(FCC1, f17, f14, f15);
  __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dCun)));
  __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fCun)));

  __ fcmp_cond_d(CEQ, f8, f9, FCC0);
  __ fcmp_cond_s(CEQ, f10, f11, FCC1);
  __ fsel(FCC0, f16, f12, f13);
  __ fsel(FCC1, f17, f14, f15);
  __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dCeq)));
  __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fCeq)));

  __ fcmp_cond_d(CUEQ, f8, f9, FCC0);
  __ fcmp_cond_s(CUEQ, f10, f11, FCC1);
  __ fsel(FCC0, f16, f12, f13);
  __ fsel(FCC1, f17, f14, f15);
  __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dCueq)));
  __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fCueq)));

  __ fcmp_cond_d(CLT, f8, f9, FCC0);
  __ fcmp_cond_s(CLT, f10, f11, FCC1);
  __ fsel(FCC0, f16, f12, f13);
  __ fsel(FCC1, f17, f14, f15);
  __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dClt)));
  __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fClt)));

  __ fcmp_cond_d(CULT, f8, f9, FCC0);
  __ fcmp_cond_s(CULT, f10, f11, FCC1);
  __ fsel(FCC0, f16, f12, f13);
  __ fsel(FCC1, f17, f14, f15);
  __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dCult)));
  __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fCult)));

  __ fcmp_cond_d(CLE, f8, f9, FCC0);
  __ fcmp_cond_s(CLE, f10, f11, FCC1);
  __ fsel(FCC0, f16, f12, f13);
  __ fsel(FCC1, f17, f14, f15);
  __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dCle)));
  __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fCle)));

  __ fcmp_cond_d(CULE, f8, f9, FCC0);
  __ fcmp_cond_s(CULE, f10, f11, FCC1);
  __ fsel(FCC0, f16, f12, f13);
  __ fsel(FCC1, f17, f14, f15);
  __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dCule)));
  __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fCule)));

  __ fcmp_cond_d(CNE, f8, f9, FCC0);
  __ fcmp_cond_s(CNE, f10, f11, FCC1);
  __ fsel(FCC0, f16, f12, f13);
  __ fsel(FCC1, f17, f14, f15);
  __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dCne)));
  __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fCne)));

  __ fcmp_cond_d(COR, f8, f9, FCC0);
  __ fcmp_cond_s(COR, f10, f11, FCC1);
  __ fsel(FCC0, f16, f12, f13);
  __ fsel(FCC1, f17, f14, f15);
  __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dCor)));
  __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fCor)));

  __ fcmp_cond_d(CUNE, f8, f9, FCC0);
  __ fcmp_cond_s(CUNE, f10, f11, FCC1);
  __ fsel(FCC0, f16, f12, f13);
  __ fsel(FCC1, f17, f14, f15);
  __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dCune)));
  __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fCune)));

  /*  __ fcmp_cond_d(SAF, f8, f9, FCC0);
    __ fcmp_cond_s(SAF, f10, f11, FCC1);
    __ fsel(FCC0, f16, f12, f13);
    __ fsel(FCC1, f17, f14, f15);
    __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dSaf)));
    __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fSaf)));

    __ fcmp_cond_d(SUN, f8, f9, FCC0);
    __ fcmp_cond_s(SUN, f10, f11, FCC1);
    __ fsel(FCC0, f16, f12, f13);
    __ fsel(FCC1, f17, f14, f15);
    __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dSun)));
    __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fSun)));

    __ fcmp_cond_d(SEQ, f8, f9, FCC0);
    __ fcmp_cond_s(SEQ, f10, f11, FCC1);
    __ fsel(FCC0, f16, f12, f13);
    __ fsel(FCC1, f17, f14, f15);
    __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dSeq)));
    __ Fst_f(f17, MemOperand(a0, offsetof(TestFloat, fSeq)));

    __ fcmp_cond_d(SUEQ, f8, f9, FCC0);
    __ fcmp_cond_s(SUEQ, f10, f11, FCC1);
    __ fsel(FCC0, f16, f12, f13);
    __ fsel(FCC1, f17, f14, f15);
    __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dSueq)));
    __ Fst_f(f17, MemOperand(a0, offsetof(TestFloat, fSueq)));

    __ fcmp_cond_d(SLT, f8, f9, FCC0);
    __ fcmp_cond_s(SLT, f10, f11, FCC1);
    __ fsel(f16, f12, f13, FCC0);
    __ fsel(f17, f14, f15, FCC1);
    __ Fld_d(f16, MemOperand(a0, offsetof(TestFloat, dSlt)));
    __ Fst_d(f17, MemOperand(a0, offsetof(TestFloat, fSlt)));

    __ fcmp_cond_d(SULT, f8, f9, FCC0);
    __ fcmp_cond_s(SULT, f10, f11, FCC1);
    __ fsel(FCC0, f16, f12, f13);
    __ fsel(FCC1, f17, f14, f15);
    __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dSult)));
    __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fSult)));

    __ fcmp_cond_d(SLE, f8, f9, FCC0);
    __ fcmp_cond_s(SLE, f10, f11, FCC1);
    __ fsel(FCC0, f16, f12, f13);
    __ fsel(FCC1, f17, f14, f15);
    __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dSle)));
    __ Fst_f(f17, MemOperand(a0, offsetof(TestFloat, fSle)));

    __ fcmp_cond_d(SULE, f8, f9, FCC0);
    __ fcmp_cond_s(SULE, f10, f11, FCC1);
    __ fsel(FCC0, f16, f12, f13);
    __ fsel(FCC1, f17, f14, f15);
    __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dSule)));
    __ Fst_f(f17, MemOperand(a0, offsetof(TestFloat, fSule)));

    __ fcmp_cond_d(SNE, f8, f9, FCC0);
    __ fcmp_cond_s(SNE, f10, f11, FCC1);
    __ fsel(FCC0, f16, f12, f13);
    __ fsel(FCC1, f17, f14, f15);
    __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dSne)));
    __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fSne)));

    __ fcmp_cond_d(SOR, f8, f9, FCC0);
    __ fcmp_cond_s(SOR, f10, f11, FCC1);
    __ fsel(FCC0, f16, f12, f13);
    __ fsel(FCC1, f17, f14, f15);
    __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dSor)));
    __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fSor)));

    __ fcmp_cond_d(SUNE, f8, f9, FCC0);
    __ fcmp_cond_s(SUNE, f10, f11, FCC1);
    __ fsel(FCC0, f16, f12, f13);
    __ fsel(FCC1, f17, f14, f15);
    __ Fst_d(f16, MemOperand(a0, offsetof(TestFloat, dSune)));
    __ Fst_s(f17, MemOperand(a0, offsetof(TestFloat, fSune)));*/

  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  test.dTrue = 1234.0;
  test.dFalse = 0.0;
  test.fTrue = 12.0;
  test.fFalse = 0.0;

  test.dOp1 = 2.0;
  test.dOp2 = 3.0;
  test.fOp1 = 2.0;
  test.fOp2 = 3.0;
  f.Call(&test, 0, 0, 0, 0);

  CHECK_EQ(test.dCaf, test.dFalse);
  CHECK_EQ(test.fCaf, test.fFalse);
  CHECK_EQ(test.dCun, test.dFalse);
  CHECK_EQ(test.fCun, test.fFalse);
  CHECK_EQ(test.dCeq, test.dFalse);
  CHECK_EQ(test.fCeq, test.fFalse);
  CHECK_EQ(test.dCueq, test.dFalse);
  CHECK_EQ(test.fCueq, test.fFalse);
  CHECK_EQ(test.dClt, test.dTrue);
  CHECK_EQ(test.fClt, test.fTrue);
  CHECK_EQ(test.dCult, test.dTrue);
  CHECK_EQ(test.fCult, test.fTrue);
  CHECK_EQ(test.dCle, test.dTrue);
  CHECK_EQ(test.fCle, test.fTrue);
  CHECK_EQ(test.dCule, test.dTrue);
  CHECK_EQ(test.fCule, test.fTrue);
  CHECK_EQ(test.dCne, test.dTrue);
  CHECK_EQ(test.fCne, test.fTrue);
  CHECK_EQ(test.dCor, test.dTrue);
  CHECK_EQ(test.fCor, test.fTrue);
  CHECK_EQ(test.dCune, test.dTrue);
  CHECK_EQ(test.fCune, test.fTrue);
  /*  CHECK_EQ(test.dSaf, test.dFalse);
    CHECK_EQ(test.fSaf, test.fFalse);
    CHECK_EQ(test.dSun, test.dFalse);
    CHECK_EQ(test.fSun, test.fFalse);
    CHECK_EQ(test.dSeq, test.dFalse);
    CHECK_EQ(test.fSeq, test.fFalse);
    CHECK_EQ(test.dSueq, test.dFalse);
    CHECK_EQ(test.fSueq, test.fFalse);
    CHECK_EQ(test.dClt, test.dTrue);
    CHECK_EQ(test.fClt, test.fTrue);
    CHECK_EQ(test.dCult, test.dTrue);
    CHECK_EQ(test.fCult, test.fTrue);
    CHECK_EQ(test.dSle, test.dTrue);
    CHECK_EQ(test.fSle, test.fTrue);
    CHECK_EQ(test.dSule, test.dTrue);
    CHECK_EQ(test.fSule, test.fTrue);
    CHECK_EQ(test.dSne, test.dTrue);
    CHECK_EQ(test.fSne, test.fTrue);
    CHECK_EQ(test.dSor, test.dTrue);
    CHECK_EQ(test.fSor, test.fTrue);
    CHECK_EQ(test.dSune, test.dTrue);
    CHECK_EQ(test.fSune, test.fTrue);*/

  test.dOp1 = std::numeric_limits<double>::max();
  test.dOp2 = std::numeric_limits<double>::min();
  test.fOp1 = std::numeric_limits<float>::min();
  test.fOp2 = -std::numeric_limits<float>::max();
  f.Call(&test, 0, 0, 0, 0);

  CHECK_EQ(test.dCaf, test.dFalse);
  CHECK_EQ(test.fCaf, test.fFalse);
  CHECK_EQ(test.dCun, test.dFalse);
  CHECK_EQ(test.fCun, test.fFalse);
  CHECK_EQ(test.dCeq, test.dFalse);
  CHECK_EQ(test.fCeq, test.fFalse);
  CHECK_EQ(test.dCueq, test.dFalse);
  CHECK_EQ(test.fCueq, test.fFalse);
  CHECK_EQ(test.dClt, test.dFalse);
  CHECK_EQ(test.fClt, test.fFalse);
  CHECK_EQ(test.dCult, test.dFalse);
  CHECK_EQ(test.fCult, test.fFalse);
  CHECK_EQ(test.dCle, test.dFalse);
  CHECK_EQ(test.fCle, test.fFalse);
  CHECK_EQ(test.dCule, test.dFalse);
  CHECK_EQ(test.fCule, test.fFalse);
  CHECK_EQ(test.dCne, test.dTrue);
  CHECK_EQ(test.fCne, test.fTrue);
  CHECK_EQ(test.dCor, test.dTrue);
  CHECK_EQ(test.fCor, test.fTrue);
  CHECK_EQ(test.dCune, test.dTrue);
  CHECK_EQ(test.fCune, test.fTrue);
  /*  CHECK_EQ(test.dSaf, test.dFalse);
    CHECK_EQ(test.fSaf, test.fFalse);
    CHECK_EQ(test.dSun, test.dFalse);
    CHECK_EQ(test.fSun, test.fFalse);
    CHECK_EQ(test.dSeq, test.dFalse);
    CHECK_EQ(test.fSeq, test.fFalse);
    CHECK_EQ(test.dSueq, test.dFalse);
    CHECK_EQ(test.fSueq, test.fFalse);
    CHECK_EQ(test.dSlt, test.dFalse);
    CHECK_EQ(test.fSlt, test.fFalse);
    CHECK_EQ(test.dSult, test.dFalse);
    CHECK_EQ(test.fSult, test.fFalse);
    CHECK_EQ(test.dSle, test.dFalse);
    CHECK_EQ(test.fSle, test.fFalse);
    CHECK_EQ(test.dSule, test.dFalse);
    CHECK_EQ(test.fSule, test.fFalse);
    CHECK_EQ(test.dSne, test.dTrue);
    CHECK_EQ(test.fSne, test.fTrue);
    CHECK_EQ(test.dSor, test.dTrue);
    CHECK_EQ(test.fSor, test.fTrue);
    CHECK_EQ(test.dSune, test.dTrue);
    CHECK_EQ(test.fSune, test.fTrue);*/

  test.dOp1 = std::numeric_limits<double>::quiet_NaN();
  test.dOp2 = 0.0;
  test.fOp1 = std::numeric_limits<float>::quiet_NaN();
  test.fOp2 = 0.0;
  f.Call(&test, 0, 0, 0, 0);

  CHECK_EQ(test.dCaf, test.dFalse);
  CHECK_EQ(test.fCaf, test.fFalse);
  CHECK_EQ(test.dCun, test.dTrue);
  CHECK_EQ(test.fCun, test.fTrue);
  CHECK_EQ(test.dCeq, test.dFalse);
  CHECK_EQ(test.fCeq, test.fFalse);
  CHECK_EQ(test.dCueq, test.dTrue);
  CHECK_EQ(test.fCueq, test.fTrue);
  CHECK_EQ(test.dClt, test.dFalse);
  CHECK_EQ(test.fClt, test.fFalse);
  CHECK_EQ(test.dCult, test.dTrue);
  CHECK_EQ(test.fCult, test.fTrue);
  CHECK_EQ(test.dCle, test.dFalse);
  CHECK_EQ(test.fCle, test.fFalse);
  CHECK_EQ(test.dCule, test.dTrue);
  CHECK_EQ(test.fCule, test.fTrue);
  CHECK_EQ(test.dCne, test.dFalse);
  CHECK_EQ(test.fCne, test.fFalse);
  CHECK_EQ(test.dCor, test.dFalse);
  CHECK_EQ(test.fCor, test.fFalse);
  CHECK_EQ(test.dCune, test.dTrue);
  CHECK_EQ(test.fCune, test.fTrue);
  /*  CHECK_EQ(test.dSaf, test.dTrue);
    CHECK_EQ(test.fSaf, test.fTrue);
    CHECK_EQ(test.dSun, test.dTrue);
    CHECK_EQ(test.fSun, test.fTrue);
    CHECK_EQ(test.dSeq, test.dFalse);
    CHECK_EQ(test.fSeq, test.fFalse);
    CHECK_EQ(test.dSueq, test.dTrue);
    CHECK_EQ(test.fSueq, test.fTrue);
    CHECK_EQ(test.dSlt, test.dFalse);
    CHECK_EQ(test.fSlt, test.fFalse);
    CHECK_EQ(test.dSult, test.dTrue);
    CHECK_EQ(test.fSult, test.fTrue);
    CHECK_EQ(test.dSle, test.dFalse);
    CHECK_EQ(test.fSle, test.fFalse);
    CHECK_EQ(test.dSule, test.dTrue);
    CHECK_EQ(test.fSule, test.fTrue);
    CHECK_EQ(test.dSne, test.dFalse);
    CHECK_EQ(test.fSne, test.fFalse);
    CHECK_EQ(test.dSor, test.dFalse);
    CHECK_EQ(test.fSor, test.fFalse);
    CHECK_EQ(test.dSune, test.dTrue);
    CHECK_EQ(test.fSune, test.fTrue);*/
}

TEST(FCVT) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct TestFloat {
    float fcvt_d_s_in;
    double fcvt_s_d_in;
    double fcvt_d_s_out;
    float fcvt_s_d_out;
    int fcsr;
  };
  TestFloat test;
  __ xor_(a4, a4, a4);
  __ xor_(a5, a5, a5);
  __ Ld_w(a4, MemOperand(a0, offsetof(TestFloat, fcsr)));
  __ movfcsr2gr(a5);
  __ movgr2fcsr(a4);
  __ Fld_s(f8, MemOperand(a0, offsetof(TestFloat, fcvt_d_s_in)));
  __ Fld_d(f9, MemOperand(a0, offsetof(TestFloat, fcvt_s_d_in)));
  __ fcvt_d_s(f10, f8);
  __ fcvt_s_d(f11, f9);
  __ Fst_d(f10, MemOperand(a0, offsetof(TestFloat, fcvt_d_s_out)));
  __ Fst_s(f11, MemOperand(a0, offsetof(TestFloat, fcvt_s_d_out)));
  __ movgr2fcsr(a5);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  test.fcsr = kRoundToNearest;

  test.fcvt_d_s_in = -0.51;
  test.fcvt_s_d_in = -0.51;
  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.fcvt_d_s_out, static_cast<double>(test.fcvt_d_s_in));
  CHECK_EQ(test.fcvt_s_d_out, static_cast<float>(test.fcvt_s_d_in));

  test.fcvt_d_s_in = 0.49;
  test.fcvt_s_d_in = 0.49;
  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.fcvt_d_s_out, static_cast<double>(test.fcvt_d_s_in));
  CHECK_EQ(test.fcvt_s_d_out, static_cast<float>(test.fcvt_s_d_in));

  test.fcvt_d_s_in = std::numeric_limits<float>::max();
  test.fcvt_s_d_in = std::numeric_limits<double>::max();
  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.fcvt_d_s_out, static_cast<double>(test.fcvt_d_s_in));
  CHECK_EQ(test.fcvt_s_d_out, static_cast<float>(test.fcvt_s_d_in));

  test.fcvt_d_s_in = -std::numeric_limits<float>::max();
  test.fcvt_s_d_in = -std::numeric_limits<double>::max();
  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.fcvt_d_s_out, static_cast<double>(test.fcvt_d_s_in));
  CHECK_EQ(test.fcvt_s_d_out, static_cast<float>(test.fcvt_s_d_in));

  test.fcvt_d_s_in = std::numeric_limits<float>::min();
  test.fcvt_s_d_in = std::numeric_limits<double>::min();
  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.fcvt_d_s_out, static_cast<double>(test.fcvt_d_s_in));
  CHECK_EQ(test.fcvt_s_d_out, static_cast<float>(test.fcvt_s_d_in));
}

TEST(FFINT) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct TestFloat {
    int32_t ffint_s_w_in;
    int64_t ffint_s_l_in;
    int32_t ffint_d_w_in;
    int64_t ffint_d_l_in;
    float ffint_s_w_out;
    float ffint_s_l_out;
    double ffint_d_w_out;
    double ffint_d_l_out;
    int fcsr;
  };
  TestFloat test;
  __ xor_(a4, a4, a4);
  __ xor_(a5, a5, a5);
  __ Ld_w(a4, MemOperand(a0, offsetof(TestFloat, fcsr)));
  __ movfcsr2gr(a5);
  __ movgr2fcsr(a4);
  __ Fld_s(f8, MemOperand(a0, offsetof(TestFloat, ffint_s_w_in)));
  __ Fld_d(f9, MemOperand(a0, offsetof(TestFloat, ffint_s_l_in)));
  __ Fld_s(f10, MemOperand(a0, offsetof(TestFloat, ffint_d_w_in)));
  __ Fld_d(f11, MemOperand(a0, offsetof(TestFloat, ffint_d_l_in)));
  __ ffint_s_w(f12, f8);
  __ ffint_s_l(f13, f9);
  __ ffint_d_w(f14, f10);
  __ ffint_d_l(f15, f11);
  __ Fst_s(f12, MemOperand(a0, offsetof(TestFloat, ffint_s_w_out)));
  __ Fst_s(f13, MemOperand(a0, offsetof(TestFloat, ffint_s_l_out)));
  __ Fst_d(f14, MemOperand(a0, offsetof(TestFloat, ffint_d_w_out)));
  __ Fst_d(f15, MemOperand(a0, offsetof(TestFloat, ffint_d_l_out)));
  __ movgr2fcsr(a5);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  test.fcsr = kRoundToNearest;

  test.ffint_s_w_in = -1;
  test.ffint_s_l_in = -1;
  test.ffint_d_w_in = -1;
  test.ffint_d_l_in = -1;
  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.ffint_s_w_out, static_cast<float>(test.ffint_s_w_in));
  CHECK_EQ(test.ffint_s_l_out, static_cast<float>(test.ffint_s_l_in));
  CHECK_EQ(test.ffint_d_w_out, static_cast<double>(test.ffint_d_w_in));
  CHECK_EQ(test.ffint_d_l_out, static_cast<double>(test.ffint_d_l_in));

  test.ffint_s_w_in = 1;
  test.ffint_s_l_in = 1;
  test.ffint_d_w_in = 1;
  test.ffint_d_l_in = 1;
  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.ffint_s_w_out, static_cast<float>(test.ffint_s_w_in));
  CHECK_EQ(test.ffint_s_l_out, static_cast<float>(test.ffint_s_l_in));
  CHECK_EQ(test.ffint_d_w_out, static_cast<double>(test.ffint_d_w_in));
  CHECK_EQ(test.ffint_d_l_out, static_cast<double>(test.ffint_d_l_in));

  test.ffint_s_w_in = std::numeric_limits<int32_t>::max();
  test.ffint_s_l_in = std::numeric_limits<int64_t>::max();
  test.ffint_d_w_in = std::numeric_limits<int32_t>::max();
  test.ffint_d_l_in = std::numeric_limits<int64_t>::max();
  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.ffint_s_w_out, static_cast<float>(test.ffint_s_w_in));
  CHECK_EQ(test.ffint_s_l_out, static_cast<float>(test.ffint_s_l_in));
  CHECK_EQ(test.ffint_d_w_out, static_cast<double>(test.ffint_d_w_in));
  CHECK_EQ(test.ffint_d_l_out, static_cast<double>(te
```