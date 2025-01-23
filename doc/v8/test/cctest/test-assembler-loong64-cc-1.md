Response:
The user wants a summary of the provided C++ code snippet. The code snippet appears to be a series of unit tests for the LoongArch64 assembler in the V8 JavaScript engine.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The code contains functions prefixed with `TEST`. This strongly suggests it's a test suite. The file path `v8/test/cctest/test-assembler-loong64.cc` confirms this is a test for the LoongArch64 assembler.

2. **Analyze individual tests:** Each `TEST` function seems to be testing specific assembler instructions. Look for patterns within each test:
    * **Data structure `T`:** Defines input values and expected output values for the instruction being tested.
    * **`MacroAssembler`:** Used to generate the machine code.
    * **Assembler instructions (`__ Ld_d`, `__ sll_d`, etc.):** These are the core instructions being tested. Note the different categories (shift, bit manipulation, branching).
    * **Storing results (`__ St_d`, `__ St_w`):**  Results of the instructions are stored in the `T` structure.
    * **Calling the generated code:**  The `GeneratedCode` template executes the generated assembly.
    * **Assertions (`CHECK_EQ`):** Verify that the actual output matches the expected output.

3. **Categorize the tested instructions:**  Group the instructions by their functionality:
    * **Shift operations:** `sll_d`, `srl_d`, `sra_d`, `rotr_d`, `slli_d`, `srli_d`, `srai_d`, `rotri_d`
    * **32-bit bit manipulation:** `ext_w_b`, `ext_w_h`, `clz_w`, `ctz_w`, `bytepick_w`, `revb_2h`, `bitrev_4b`, `bitrev_w`, `bstrins_w`, `bstrpick_w`
    * **64-bit bit manipulation:** `clo_d`, `clz_d`, `cto_d`, `ctz_d`, `bytepick_d`, `revb_4h`, `revb_2w`, `revb_d`, `revh_2w`, `revh_d`, `bitrev_8b`, `bitrev_d`, `bstrins_d`, `bstrpick_d`, `maskeqz`, `masknez`
    * **Branch instructions:** `beq`, `bne`, `blt`, `bge`, `bltu`, `bgeu`, `beqz`, `bnez`

4. **Identify common testing patterns:**  Notice that many tests follow a similar structure: load input, execute the instruction, store the result, and check against expected values.

5. **Address the specific questions:**
    * **Functionality:**  The primary function is to test the LoongArch64 assembler.
    * **`.tq` extension:** The code is C++, not Torque.
    * **JavaScript relation:**  Assembler code is the low-level implementation that JavaScript engines use to execute code. Provide a conceptual example.
    * **Code logic and I/O:**  Explain how the tests work by setting inputs and checking outputs.
    * **Common programming errors:** Shifting by amounts greater than the register size is a common error.

6. **Synthesize the summary:** Combine the observations into a concise summary, addressing each of the user's points. Emphasize the role of the code in verifying the correctness of the assembler implementation.

7. **Review and refine:** Ensure the summary is accurate, clear, and addresses all aspects of the provided code snippet and the user's specific questions. For example, ensure the JavaScript example correctly illustrates the underlying assembler operations. Double-check the instruction categorization.
好的，这是对提供的代码片段的功能归纳：

**功能归纳：**

这段代码是 `v8/test/cctest/test-assembler-loong64.cc` 文件的一部分，它主要功能是**测试 LoongArch64 架构下的汇编器指令的正确性**。具体来说，这段代码包含了多个针对不同 LoongArch64 指令的单元测试用例。

**测试内容概要:**

这段代码主要测试了以下类型的 LoongArch64 指令：

* **64位移位操作 (带有寄存器和立即数):**  逻辑左移 (`sll_d`, `slli_d`)、逻辑右移 (`srl_d`, `srli_d`)、算术右移 (`sra_d`, `srai_d`) 和循环右移 (`rotr_d`, `rotri_d`)。
* **32位位操作指令:**  位扩展 (`ext_w_b`, `ext_w_h`)、前导零计数 (`clz_w`)、尾部零计数 (`ctz_w`)、字节选择 (`bytepick_w`)、半字内字节反转 (`revb_2h`)、4字节位反转 (`bitrev_4b`)、字位反转 (`bitrev_w`)、位域插入 (`bstrins_w`) 和位域提取 (`bstrpick_w`)。
* **64位位操作指令:**  前导零计数 (`clz_d`)、尾部零计数 (`ctz_d`)、字节选择 (`bytepick_d`)、半字内字节反转 (`revb_4h`)、字内字节反转 (`revb_2w`)、双字字节反转 (`revb_d`)、字内半字反转 (`revh_2w`)、双字半字反转 (`revh_d`)、8字节位反转 (`bitrev_8b`)、双字位反转 (`bitrev_d`)、位域插入 (`bstrins_d`)、位域提取 (`bstrpick_d`)、等于零掩码 (`maskeqz`) 和不等于零掩码 (`masknez`)。
* **条件分支指令:**  相等分支 (`beq`)、不等分支 (`bne`)、小于分支 (`blt`)、大于等于分支 (`bge`)、无符号小于分支 (`bltu`)、无符号大于等于分支 (`bgeu`)、等于零分支 (`beqz`) 和不等于零分支 (`bnez`) (带相对偏移的 `b` 指令)。

**测试方法:**

每个测试用例通常会：

1. **定义一个结构体 `T`:**  该结构体包含要测试的指令的输入值以及用于存储输出结果的成员变量。
2. **创建一个 `MacroAssembler` 对象:**  用于生成 LoongArch64 汇编代码。
3. **使用汇编指令生成代码:**  使用 `MacroAssembler` 的方法 (例如 `__ Ld_d`, `__ sll_d`, `__ St_d` 等) 生成要测试的指令序列。
4. **将生成的代码编译成可执行代码:**  使用 `GetCode` 和 `Factory::CodeBuilder`。
5. **创建一个 `T` 结构体的实例并设置输入值。**
6. **调用生成的代码:**  使用 `GeneratedCode` 模板来执行生成的汇编代码。
7. **使用 `CHECK_EQ` 断言来验证输出结果是否与预期值一致。**

**总结:**

这段代码是 V8 引擎中用于确保 LoongArch64 汇编器正确生成目标代码的关键组成部分。它通过针对各种指令编写详细的测试用例，覆盖了不同操作数和场景，从而验证了汇编器的功能和准确性。

### 提示词
```
这是目录为v8/test/cctest/test-assembler-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
_d_30;
    int64_t result_sll_d_63;
    int64_t result_srl_d_0;
    int64_t result_srl_d_13;
    int64_t result_srl_d_30;
    int64_t result_srl_d_63;
    int64_t result_sra_d_0;
    int64_t result_sra_d_13;
    int64_t result_sra_d_30;
    int64_t result_sra_d_63;
    int64_t result_rotr_d_0;
    int64_t result_rotr_d_13;
    int64_t result_slli_d_0;
    int64_t result_slli_d_13;
    int64_t result_slli_d_30;
    int64_t result_slli_d_63;
    int64_t result_srli_d_0;
    int64_t result_srli_d_13;
    int64_t result_srli_d_30;
    int64_t result_srli_d_63;
    int64_t result_srai_d_0;
    int64_t result_srai_d_13;
    int64_t result_srai_d_30;
    int64_t result_srai_d_63;
    int64_t result_rotri_d_0;
    int64_t result_rotri_d_13;
    int64_t result_rotri_d_30;
    int64_t result_rotri_d_63;
  };

  T t;
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ Ld_d(a4, MemOperand(a0, offsetof(T, input)));

  // sll_d
  __ li(a5, 0);
  __ sll_d(t0, a4, a5);
  __ li(a5, 0xD);
  __ sll_d(t1, a4, a5);
  __ li(a5, 0x1E);
  __ sll_d(t2, a4, a5);
  __ li(a5, 0x3F);
  __ sll_d(t3, a4, a5);

  __ St_d(t0, MemOperand(a0, offsetof(T, result_sll_d_0)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_sll_d_13)));
  __ St_d(t2, MemOperand(a0, offsetof(T, result_sll_d_30)));
  __ St_d(t3, MemOperand(a0, offsetof(T, result_sll_d_63)));

  // srl_d
  __ li(a5, 0x0);
  __ srl_d(t0, a4, a5);
  __ li(a5, 0xD);
  __ srl_d(t1, a4, a5);
  __ li(a5, 0x1E);
  __ srl_d(t2, a4, a5);
  __ li(a5, 0x3F);
  __ srl_d(t3, a4, a5);

  __ St_d(t0, MemOperand(a0, offsetof(T, result_srl_d_0)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_srl_d_13)));
  __ St_d(t2, MemOperand(a0, offsetof(T, result_srl_d_30)));
  __ St_d(t3, MemOperand(a0, offsetof(T, result_srl_d_63)));

  // sra_d
  __ li(a5, 0x0);
  __ sra_d(t0, a4, a5);
  __ li(a5, 0xD);
  __ sra_d(t1, a4, a5);

  __ li(a6, static_cast<int64_t>(0x8000000000000000));
  __ add_d(a6, a6, a4);
  __ li(a5, 0x1E);
  __ sra_d(t2, a6, a5);
  __ li(a5, 0x3F);
  __ sra_d(t3, a6, a5);

  __ St_d(t0, MemOperand(a0, offsetof(T, result_sra_d_0)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_sra_d_13)));
  __ St_d(t2, MemOperand(a0, offsetof(T, result_sra_d_30)));
  __ St_d(t3, MemOperand(a0, offsetof(T, result_sra_d_63)));

  // rotr
  __ li(a5, 0x0);
  __ rotr_d(t0, a4, a5);
  __ li(a6, 0xD);
  __ rotr_d(t1, a4, a6);

  __ St_d(t0, MemOperand(a0, offsetof(T, result_rotr_d_0)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_rotr_d_13)));

  // slli_d
  __ slli_d(t0, a4, 0);
  __ slli_d(t1, a4, 0xD);
  __ slli_d(t2, a4, 0x1E);
  __ slli_d(t3, a4, 0x3F);

  __ St_d(t0, MemOperand(a0, offsetof(T, result_slli_d_0)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_slli_d_13)));
  __ St_d(t2, MemOperand(a0, offsetof(T, result_slli_d_30)));
  __ St_d(t3, MemOperand(a0, offsetof(T, result_slli_d_63)));

  // srli_d
  __ srli_d(t0, a4, 0);
  __ srli_d(t1, a4, 0xD);
  __ srli_d(t2, a4, 0x1E);
  __ srli_d(t3, a4, 0x3F);

  __ St_d(t0, MemOperand(a0, offsetof(T, result_srli_d_0)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_srli_d_13)));
  __ St_d(t2, MemOperand(a0, offsetof(T, result_srli_d_30)));
  __ St_d(t3, MemOperand(a0, offsetof(T, result_srli_d_63)));

  // srai_d
  __ srai_d(t0, a4, 0);
  __ srai_d(t1, a4, 0xD);

  __ li(a6, static_cast<int64_t>(0x8000000000000000));
  __ add_d(a6, a6, a4);
  __ srai_d(t2, a6, 0x1E);
  __ srai_d(t3, a6, 0x3F);

  __ St_d(t0, MemOperand(a0, offsetof(T, result_srai_d_0)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_srai_d_13)));
  __ St_d(t2, MemOperand(a0, offsetof(T, result_srai_d_30)));
  __ St_d(t3, MemOperand(a0, offsetof(T, result_srai_d_63)));

  // rotri_d
  __ rotri_d(t0, a4, 0);
  __ rotri_d(t1, a4, 0xD);
  __ rotri_d(t2, a4, 0x1E);
  __ rotri_d(t3, a4, 0x3F);

  __ St_d(t0, MemOperand(a0, offsetof(T, result_rotri_d_0)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_rotri_d_13)));
  __ St_d(t2, MemOperand(a0, offsetof(T, result_rotri_d_30)));
  __ St_d(t3, MemOperand(a0, offsetof(T, result_rotri_d_63)));

  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  t.input = 0x51F4B764A26E7412;
  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(static_cast<int64_t>(0x51f4b764a26e7412), t.result_sll_d_0);
  CHECK_EQ(static_cast<int64_t>(0x96ec944dce824000), t.result_sll_d_13);
  CHECK_EQ(static_cast<int64_t>(0x289b9d0480000000), t.result_sll_d_30);
  CHECK_EQ(static_cast<int64_t>(0x0), t.result_sll_d_63);

  CHECK_EQ(static_cast<int64_t>(0x51f4b764a26e7412), t.result_srl_d_0);
  CHECK_EQ(static_cast<int64_t>(0x28fa5bb251373), t.result_srl_d_13);
  CHECK_EQ(static_cast<int64_t>(0x147d2dd92), t.result_srl_d_30);
  CHECK_EQ(static_cast<int64_t>(0x0), t.result_srl_d_63);

  CHECK_EQ(static_cast<int64_t>(0x51f4b764a26e7412), t.result_sra_d_0);
  CHECK_EQ(static_cast<int64_t>(0x28fa5bb251373), t.result_sra_d_13);
  CHECK_EQ(static_cast<int64_t>(0xffffffff47d2dd92), t.result_sra_d_30);
  CHECK_EQ(static_cast<int64_t>(0xffffffffffffffff), t.result_sra_d_63);

  CHECK_EQ(static_cast<int64_t>(0x51f4b764a26e7412), t.result_rotr_d_0);
  CHECK_EQ(static_cast<int64_t>(0xa0928fa5bb251373), t.result_rotr_d_13);

  CHECK_EQ(static_cast<int64_t>(0x51f4b764a26e7412), t.result_slli_d_0);
  CHECK_EQ(static_cast<int64_t>(0x96ec944dce824000), t.result_slli_d_13);
  CHECK_EQ(static_cast<int64_t>(0x289b9d0480000000), t.result_slli_d_30);
  CHECK_EQ(static_cast<int64_t>(0x0), t.result_slli_d_63);

  CHECK_EQ(static_cast<int64_t>(0x51f4b764a26e7412), t.result_srli_d_0);
  CHECK_EQ(static_cast<int64_t>(0x28fa5bb251373), t.result_srli_d_13);
  CHECK_EQ(static_cast<int64_t>(0x147d2dd92), t.result_srli_d_30);
  CHECK_EQ(static_cast<int64_t>(0x0), t.result_srli_d_63);

  CHECK_EQ(static_cast<int64_t>(0x51f4b764a26e7412), t.result_srai_d_0);
  CHECK_EQ(static_cast<int64_t>(0x28fa5bb251373), t.result_srai_d_13);
  CHECK_EQ(static_cast<int64_t>(0xffffffff47d2dd92), t.result_srai_d_30);
  CHECK_EQ(static_cast<int64_t>(0xffffffffffffffff), t.result_srai_d_63);

  CHECK_EQ(static_cast<int64_t>(0x51f4b764a26e7412), t.result_rotri_d_0);
  CHECK_EQ(static_cast<int64_t>(0xa0928fa5bb251373), t.result_rotri_d_13);
  CHECK_EQ(static_cast<int64_t>(0x89b9d04947d2dd92), t.result_rotri_d_30);
  CHECK_EQ(static_cast<int64_t>(0xa3e96ec944dce824), t.result_rotri_d_63);
}

TEST(LA10) {
  // Test 32bit bit operation instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct T {
    int64_t si1;
    int64_t si2;
    int32_t result_ext_w_b_si1;
    int32_t result_ext_w_b_si2;
    int32_t result_ext_w_h_si1;
    int32_t result_ext_w_h_si2;
    int32_t result_clo_w_si1;
    int32_t result_clo_w_si2;
    int32_t result_clz_w_si1;
    int32_t result_clz_w_si2;
    int32_t result_cto_w_si1;
    int32_t result_cto_w_si2;
    int32_t result_ctz_w_si1;
    int32_t result_ctz_w_si2;
    int32_t result_bytepick_w_si1;
    int32_t result_bytepick_w_si2;
    int32_t result_revb_2h_si1;
    int32_t result_revb_2h_si2;
    int32_t result_bitrev_4b_si1;
    int32_t result_bitrev_4b_si2;
    int32_t result_bitrev_w_si1;
    int32_t result_bitrev_w_si2;
    int32_t result_bstrins_w_si1;
    int32_t result_bstrins_w_si2;
    int32_t result_bstrpick_w_si1;
    int32_t result_bstrpick_w_si2;
  };
  T t;

  __ Ld_d(a4, MemOperand(a0, offsetof(T, si1)));
  __ Ld_d(a5, MemOperand(a0, offsetof(T, si2)));

  // ext_w_b
  __ ext_w_b(t0, a4);
  __ ext_w_b(t1, a5);
  __ St_w(t0, MemOperand(a0, offsetof(T, result_ext_w_b_si1)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_ext_w_b_si2)));

  // ext_w_h
  __ ext_w_h(t0, a4);
  __ ext_w_h(t1, a5);
  __ St_w(t0, MemOperand(a0, offsetof(T, result_ext_w_h_si1)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_ext_w_h_si2)));

  /*    //clo_w
    __ clo_w(t0, a4);
    __ clo_w(t1, a5);
    __ St_w(t0, MemOperand(a0, offsetof(T, result_clo_w_si1)));
    __ St_w(t1, MemOperand(a0, offsetof(T, result_clo_w_si2)));*/

  // clz_w
  __ clz_w(t0, a4);
  __ clz_w(t1, a5);
  __ St_w(t0, MemOperand(a0, offsetof(T, result_clz_w_si1)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_clz_w_si2)));

  /*    //cto_w
    __ cto_w(t0, a4);
    __ cto_w(t1, a5);
    __ St_w(t0, MemOperand(a0, offsetof(T, result_cto_w_si1)));
    __ St_w(t1, MemOperand(a0, offsetof(T, result_cto_w_si2)));*/

  // ctz_w
  __ ctz_w(t0, a4);
  __ ctz_w(t1, a5);
  __ St_w(t0, MemOperand(a0, offsetof(T, result_ctz_w_si1)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_ctz_w_si2)));

  // bytepick_w
  __ bytepick_w(t0, a4, a5, 0);
  __ bytepick_w(t1, a5, a4, 2);
  __ St_w(t0, MemOperand(a0, offsetof(T, result_bytepick_w_si1)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_bytepick_w_si2)));

  // revb_2h
  __ revb_2h(t0, a4);
  __ revb_2h(t1, a5);
  __ St_w(t0, MemOperand(a0, offsetof(T, result_revb_2h_si1)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_revb_2h_si2)));

  // bitrev
  __ bitrev_4b(t0, a4);
  __ bitrev_4b(t1, a5);
  __ St_w(t0, MemOperand(a0, offsetof(T, result_bitrev_4b_si1)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_bitrev_4b_si2)));

  // bitrev_w
  __ bitrev_w(t0, a4);
  __ bitrev_w(t1, a5);
  __ St_w(t0, MemOperand(a0, offsetof(T, result_bitrev_w_si1)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_bitrev_w_si2)));

  // bstrins
  __ or_(t0, zero_reg, zero_reg);
  __ or_(t1, zero_reg, zero_reg);
  __ bstrins_w(t0, a4, 0xD, 0x4);
  __ bstrins_w(t1, a5, 0x16, 0x5);
  __ St_w(t0, MemOperand(a0, offsetof(T, result_bstrins_w_si1)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_bstrins_w_si2)));

  // bstrpick
  __ or_(t0, zero_reg, zero_reg);
  __ or_(t1, zero_reg, zero_reg);
  __ bstrpick_w(t0, a4, 0xD, 0x4);
  __ bstrpick_w(t1, a5, 0x16, 0x5);
  __ St_w(t0, MemOperand(a0, offsetof(T, result_bstrpick_w_si1)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_bstrpick_w_si2)));

  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  t.si1 = 0x51F4B764A26E7412;
  t.si2 = 0x81F25A87C423B891;
  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(static_cast<int32_t>(0x12), t.result_ext_w_b_si1);
  CHECK_EQ(static_cast<int32_t>(0xffffff91), t.result_ext_w_b_si2);
  CHECK_EQ(static_cast<int32_t>(0x7412), t.result_ext_w_h_si1);
  CHECK_EQ(static_cast<int32_t>(0xffffb891), t.result_ext_w_h_si2);
  //    CHECK_EQ(static_cast<int32_t>(0x1), t.result_clo_w_si1);
  //    CHECK_EQ(static_cast<int32_t>(0x2), t.result_clo_w_si2);
  CHECK_EQ(static_cast<int32_t>(0x0), t.result_clz_w_si1);
  CHECK_EQ(static_cast<int32_t>(0x0), t.result_clz_w_si2);
  //    CHECK_EQ(static_cast<int32_t>(0x0), t.result_cto_w_si1);
  //    CHECK_EQ(static_cast<int32_t>(0x1), t.result_cto_w_si2);
  CHECK_EQ(static_cast<int32_t>(0x1), t.result_ctz_w_si1);
  CHECK_EQ(static_cast<int32_t>(0x0), t.result_ctz_w_si2);
  CHECK_EQ(static_cast<int32_t>(0xc423b891), t.result_bytepick_w_si1);
  CHECK_EQ(static_cast<int32_t>(0x7412c423),
           t.result_bytepick_w_si2);  // 0xffffc423
  CHECK_EQ(static_cast<int32_t>(0x6ea21274), t.result_revb_2h_si1);
  CHECK_EQ(static_cast<int32_t>(0x23c491b8), t.result_revb_2h_si2);
  CHECK_EQ(static_cast<int32_t>(0x45762e48), t.result_bitrev_4b_si1);
  CHECK_EQ(static_cast<int32_t>(0x23c41d89), t.result_bitrev_4b_si2);
  CHECK_EQ(static_cast<int32_t>(0x482e7645), t.result_bitrev_w_si1);
  CHECK_EQ(static_cast<int32_t>(0x891dc423), t.result_bitrev_w_si2);
  CHECK_EQ(static_cast<int32_t>(0x120), t.result_bstrins_w_si1);
  CHECK_EQ(static_cast<int32_t>(0x771220), t.result_bstrins_w_si2);
  CHECK_EQ(static_cast<int32_t>(0x341), t.result_bstrpick_w_si1);
  CHECK_EQ(static_cast<int32_t>(0x11dc4), t.result_bstrpick_w_si2);
}

TEST(LA11) {
  // Test 64bit bit operation instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct T {
    int64_t si1;
    int64_t si2;
    int64_t result_clo_d_si1;
    int64_t result_clo_d_si2;
    int64_t result_clz_d_si1;
    int64_t result_clz_d_si2;
    int64_t result_cto_d_si1;
    int64_t result_cto_d_si2;
    int64_t result_ctz_d_si1;
    int64_t result_ctz_d_si2;
    int64_t result_bytepick_d_si1;
    int64_t result_bytepick_d_si2;
    int64_t result_revb_4h_si1;
    int64_t result_revb_4h_si2;
    int64_t result_revb_2w_si1;
    int64_t result_revb_2w_si2;
    int64_t result_revb_d_si1;
    int64_t result_revb_d_si2;
    int64_t result_revh_2w_si1;
    int64_t result_revh_2w_si2;
    int64_t result_revh_d_si1;
    int64_t result_revh_d_si2;
    int64_t result_bitrev_8b_si1;
    int64_t result_bitrev_8b_si2;
    int64_t result_bitrev_d_si1;
    int64_t result_bitrev_d_si2;
    int64_t result_bstrins_d_si1;
    int64_t result_bstrins_d_si2;
    int64_t result_bstrpick_d_si1;
    int64_t result_bstrpick_d_si2;
    int64_t result_maskeqz_si1;
    int64_t result_maskeqz_si2;
    int64_t result_masknez_si1;
    int64_t result_masknez_si2;
  };

  T t;

  __ Ld_d(a4, MemOperand(a0, offsetof(T, si1)));
  __ Ld_d(a5, MemOperand(a0, offsetof(T, si2)));

  /*    //clo_d
    __ clo_d(t0, a4);
    __ clo_d(t1, a5);
    __ St_w(t0, MemOperand(a0, offsetof(T, result_clo_d_si1)));
    __ St_w(t1, MemOperand(a0, offsetof(T, result_clo_d_si2)));*/

  // clz_d
  __ or_(t0, zero_reg, zero_reg);
  __ clz_d(t0, a4);
  __ clz_d(t1, a5);
  __ St_d(t0, MemOperand(a0, offsetof(T, result_clz_d_si1)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_clz_d_si2)));

  /*    //cto_d
    __ cto_d(t0, a4);
    __ cto_d(t1, a5);
    __ St_w(t0, MemOperand(a0, offsetof(T, result_cto_d_si1)));
    __ St_w(t1, MemOperand(a0, offsetof(T, result_cto_d_si2)));*/

  // ctz_d
  __ ctz_d(t0, a4);
  __ ctz_d(t1, a5);
  __ St_d(t0, MemOperand(a0, offsetof(T, result_ctz_d_si1)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_ctz_d_si2)));

  // bytepick_d
  __ bytepick_d(t0, a4, a5, 0);
  __ bytepick_d(t1, a5, a4, 5);
  __ St_d(t0, MemOperand(a0, offsetof(T, result_bytepick_d_si1)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_bytepick_d_si2)));

  // revb_4h
  __ revb_4h(t0, a4);
  __ revb_4h(t1, a5);
  __ St_d(t0, MemOperand(a0, offsetof(T, result_revb_4h_si1)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_revb_4h_si2)));

  // revb_2w
  __ revb_2w(t0, a4);
  __ revb_2w(t1, a5);
  __ St_d(t0, MemOperand(a0, offsetof(T, result_revb_2w_si1)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_revb_2w_si2)));

  // revb_d
  __ revb_d(t0, a4);
  __ revb_d(t1, a5);
  __ St_d(t0, MemOperand(a0, offsetof(T, result_revb_d_si1)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_revb_d_si2)));

  // revh_2w
  __ revh_2w(t0, a4);
  __ revh_2w(t1, a5);
  __ St_d(t0, MemOperand(a0, offsetof(T, result_revh_2w_si1)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_revh_2w_si2)));

  // revh_d
  __ revh_d(t0, a4);
  __ revh_d(t1, a5);
  __ St_d(t0, MemOperand(a0, offsetof(T, result_revh_d_si1)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_revh_d_si2)));

  // bitrev_8b
  __ bitrev_8b(t0, a4);
  __ bitrev_8b(t1, a5);
  __ St_d(t0, MemOperand(a0, offsetof(T, result_bitrev_8b_si1)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_bitrev_8b_si2)));

  // bitrev_d
  __ bitrev_d(t0, a4);
  __ bitrev_d(t1, a5);
  __ St_d(t0, MemOperand(a0, offsetof(T, result_bitrev_d_si1)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_bitrev_d_si2)));

  // bstrins_d
  __ or_(t0, zero_reg, zero_reg);
  __ or_(t1, zero_reg, zero_reg);
  __ bstrins_d(t0, a4, 5, 0);
  __ bstrins_d(t1, a5, 39, 12);
  __ St_d(t0, MemOperand(a0, offsetof(T, result_bstrins_d_si1)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_bstrins_d_si2)));

  // bstrpick_d
  __ or_(t0, zero_reg, zero_reg);
  __ or_(t1, zero_reg, zero_reg);
  __ bstrpick_d(t0, a4, 5, 0);
  __ bstrpick_d(t1, a5, 63, 48);
  __ St_d(t0, MemOperand(a0, offsetof(T, result_bstrpick_d_si1)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_bstrpick_d_si2)));

  // maskeqz
  __ maskeqz(t0, a4, a4);
  __ maskeqz(t1, a5, zero_reg);
  __ St_d(t0, MemOperand(a0, offsetof(T, result_maskeqz_si1)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_maskeqz_si2)));

  // masknez
  __ masknez(t0, a4, a4);
  __ masknez(t1, a5, zero_reg);
  __ St_d(t0, MemOperand(a0, offsetof(T, result_masknez_si1)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_masknez_si2)));

  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  t.si1 = 0x10C021098B710CDE;
  t.si2 = 0xFB8017FF781A15C3;
  f.Call(&t, 0, 0, 0, 0);

  //    CHECK_EQ(static_cast<int64_t>(0x0), t.result_clo_d_si1);
  //    CHECK_EQ(static_cast<int64_t>(0x5), t.result_clo_d_si2);
  CHECK_EQ(static_cast<int64_t>(0x3), t.result_clz_d_si1);
  CHECK_EQ(static_cast<int64_t>(0x0), t.result_clz_d_si2);
  //    CHECK_EQ(static_cast<int64_t>(0x0), t.result_cto_d_si1);
  //    CHECK_EQ(static_cast<int64_t>(0x2), t.result_cto_d_si2);
  CHECK_EQ(static_cast<int64_t>(0x1), t.result_ctz_d_si1);
  CHECK_EQ(static_cast<int64_t>(0x0), t.result_ctz_d_si2);
  CHECK_EQ(static_cast<int64_t>(0xfb8017ff781a15c3), t.result_bytepick_d_si1);
  CHECK_EQ(static_cast<int64_t>(0x710cdefb8017ff78), t.result_bytepick_d_si2);
  CHECK_EQ(static_cast<int64_t>(0xc0100921718bde0c), t.result_revb_4h_si1);
  CHECK_EQ(static_cast<int64_t>(0x80fbff171a78c315), t.result_revb_4h_si2);
  CHECK_EQ(static_cast<int64_t>(0x921c010de0c718b), t.result_revb_2w_si1);
  CHECK_EQ(static_cast<int64_t>(0xff1780fbc3151a78), t.result_revb_2w_si2);
  CHECK_EQ(static_cast<int64_t>(0xde0c718b0921c010), t.result_revb_d_si1);
  CHECK_EQ(static_cast<int64_t>(0xc3151a78ff1780fb), t.result_revb_d_si2);
  CHECK_EQ(static_cast<int64_t>(0x210910c00cde8b71), t.result_revh_2w_si1);
  CHECK_EQ(static_cast<int64_t>(0x17fffb8015c3781a), t.result_revh_2w_si2);
  CHECK_EQ(static_cast<int64_t>(0xcde8b71210910c0), t.result_revh_d_si1);
  CHECK_EQ(static_cast<int64_t>(0x15c3781a17fffb80), t.result_revh_d_si2);
  CHECK_EQ(static_cast<int64_t>(0x8038490d18e307b), t.result_bitrev_8b_si1);
  CHECK_EQ(static_cast<int64_t>(0xdf01e8ff1e58a8c3), t.result_bitrev_8b_si2);
  CHECK_EQ(static_cast<int64_t>(0x7b308ed190840308), t.result_bitrev_d_si1);
  CHECK_EQ(static_cast<int64_t>(0xc3a8581effe801df), t.result_bitrev_d_si2);
  CHECK_EQ(static_cast<int64_t>(0x1e), t.result_bstrins_d_si1);
  CHECK_EQ(static_cast<int64_t>(0x81a15c3000), t.result_bstrins_d_si2);
  CHECK_EQ(static_cast<int64_t>(0x1e), t.result_bstrpick_d_si1);
  CHECK_EQ(static_cast<int64_t>(0xfb80), t.result_bstrpick_d_si2);
  CHECK_EQ(static_cast<int64_t>(0x10C021098B710CDE), t.result_maskeqz_si1);
  CHECK_EQ(static_cast<int64_t>(0), t.result_maskeqz_si2);
  CHECK_EQ(static_cast<int64_t>(0), t.result_masknez_si1);
  CHECK_EQ(static_cast<int64_t>(0xFB8017FF781A15C3), t.result_masknez_si2);
}

uint64_t run_beq(int64_t value1, int64_t value2, int16_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label main_block, L;
  __ li(a2, 0l);
  __ b(&main_block);
  // Block 1
  __ addi_d(a2, a2, 0x1);
  __ addi_d(a2, a2, 0x2);
  __ b(&L);

  // Block 2
  __ addi_d(a2, a2, 0x10);
  __ addi_d(a2, a2, 0x20);
  __ b(&L);

  // Block 3 (Main)
  __ bind(&main_block);
  __ beq(a0, a1, offset);
  __ bind(&L);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  // Block 4
  __ addi_d(a2, a2, 0x100);
  __ addi_d(a2, a2, 0x200);
  __ b(&L);

  // Block 5
  __ addi_d(a2, a2, 0x300);
  __ addi_d(a2, a2, 0x400);
  __ b(&L);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  uint64_t res = reinterpret_cast<uint64_t>(f.Call(value1, value2, 0, 0, 0));

  return res;
}

TEST(BEQ) {
  CcTest::InitializeVM();
  struct TestCaseBeq {
    int64_t value1;
    int64_t value2;
    int16_t offset;
    uint64_t expected_res;
  };

  // clang-format off
  struct TestCaseBeq tc[] = {
    // value1, value2, offset, expected_res
    {       0,      0,    -6,          0x3 },
    {       1,      1,    -3,         0x30 },
    {      -2,     -2,     3,        0x300 },
    {       3,     -3,     6,            0 },
    {       4,      4,     6,        0x700 },
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseBeq);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t res = run_beq(tc[i].value1, tc[i].value2, tc[i].offset);
    CHECK_EQ(tc[i].expected_res, res);
  }
}

uint64_t run_bne(int64_t value1, int64_t value2, int16_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label main_block, L;
  __ li(a2, 0l);
  __ b(&main_block);
  // Block 1
  __ addi_d(a2, a2, 0x1);
  __ addi_d(a2, a2, 0x2);
  __ b(&L);

  // Block 2
  __ addi_d(a2, a2, 0x10);
  __ addi_d(a2, a2, 0x20);
  __ b(&L);

  // Block 3 (Main)
  __ bind(&main_block);
  __ bne(a0, a1, offset);
  __ bind(&L);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  // Block 4
  __ addi_d(a2, a2, 0x100);
  __ addi_d(a2, a2, 0x200);
  __ b(&L);

  // Block 5
  __ addi_d(a2, a2, 0x300);
  __ addi_d(a2, a2, 0x400);
  __ b(&L);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  uint64_t res = reinterpret_cast<uint64_t>(f.Call(value1, value2, 0, 0, 0));

  return res;
}

TEST(BNE) {
  CcTest::InitializeVM();
  struct TestCaseBne {
    int64_t value1;
    int64_t value2;
    int16_t offset;
    uint64_t expected_res;
  };

  // clang-format off
  struct TestCaseBne tc[] = {
    // value1, value2, offset, expected_res
    {       1,     -1,    -6,          0x3 },
    {       2,     -2,    -3,         0x30 },
    {       3,     -3,     3,        0x300 },
    {       4,     -4,     6,        0x700 },
    {       0,      0,     6,            0 },
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseBne);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t res = run_bne(tc[i].value1, tc[i].value2, tc[i].offset);
    CHECK_EQ(tc[i].expected_res, res);
  }
}

uint64_t run_blt(int64_t value1, int64_t value2, int16_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label main_block, L;
  __ li(a2, 0l);
  __ b(&main_block);
  // Block 1
  __ addi_d(a2, a2, 0x1);
  __ addi_d(a2, a2, 0x2);
  __ b(&L);

  // Block 2
  __ addi_d(a2, a2, 0x10);
  __ addi_d(a2, a2, 0x20);
  __ b(&L);

  // Block 3 (Main)
  __ bind(&main_block);
  __ blt(a0, a1, offset);
  __ bind(&L);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  // Block 4
  __ addi_d(a2, a2, 0x100);
  __ addi_d(a2, a2, 0x200);
  __ b(&L);

  // Block 5
  __ addi_d(a2, a2, 0x300);
  __ addi_d(a2, a2, 0x400);
  __ b(&L);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  uint64_t res = reinterpret_cast<uint64_t>(f.Call(value1, value2, 0, 0, 0));

  return res;
}

TEST(BLT) {
  CcTest::InitializeVM();
  struct TestCaseBlt {
    int64_t value1;
    int64_t value2;
    int16_t offset;
    uint64_t expected_res;
  };

  // clang-format off
  struct TestCaseBlt tc[] = {
    // value1, value2, offset, expected_res
    {      -1,      1,    -6,          0x3 },
    {      -2,      2,    -3,         0x30 },
    {      -3,      3,     3,        0x300 },
    {      -4,      4,     6,        0x700 },
    {       5,     -5,     6,            0 },
    {       0,      0,     6,            0 },
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseBlt);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t res = run_blt(tc[i].value1, tc[i].value2, tc[i].offset);
    CHECK_EQ(tc[i].expected_res, res);
  }
}

uint64_t run_bge(uint64_t value1, uint64_t value2, int16_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label main_block, L;
  __ li(a2, 0l);
  __ b(&main_block);
  // Block 1
  __ addi_d(a2, a2, 0x1);
  __ addi_d(a2, a2, 0x2);
  __ b(&L);

  // Block 2
  __ addi_d(a2, a2, 0x10);
  __ addi_d(a2, a2, 0x20);
  __ b(&L);

  // Block 3 (Main)
  __ bind(&main_block);
  __ bge(a0, a1, offset);
  __ bind(&L);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  // Block 4
  __ addi_d(a2, a2, 0x100);
  __ addi_d(a2, a2, 0x200);
  __ b(&L);

  // Block 5
  __ addi_d(a2, a2, 0x300);
  __ addi_d(a2, a2, 0x400);
  __ b(&L);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  uint64_t res = reinterpret_cast<uint64_t>(f.Call(value1, value2, 0, 0, 0));

  return res;
}

TEST(BGE) {
  CcTest::InitializeVM();
  struct TestCaseBge {
    int64_t value1;
    int64_t value2;
    int16_t offset;
    uint64_t expected_res;
  };

  // clang-format off
  struct TestCaseBge tc[] = {
    // value1, value2, offset, expected_res
    {       0,      0,    -6,          0x3 },
    {       1,      1,    -3,         0x30 },
    {       2,     -2,     3,        0x300 },
    {       3,     -3,     6,        0x700 },
    {      -4,      4,     6,            0 },
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseBge);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t res = run_bge(tc[i].value1, tc[i].value2, tc[i].offset);
    CHECK_EQ(tc[i].expected_res, res);
  }
}

uint64_t run_bltu(int64_t value1, int64_t value2, int16_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label main_block, L;
  __ li(a2, 0l);
  __ b(&main_block);
  // Block 1
  __ addi_d(a2, a2, 0x1);
  __ addi_d(a2, a2, 0x2);
  __ b(&L);

  // Block 2
  __ addi_d(a2, a2, 0x10);
  __ addi_d(a2, a2, 0x20);
  __ b(&L);

  // Block 3 (Main)
  __ bind(&main_block);
  __ bltu(a0, a1, offset);
  __ bind(&L);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  // Block 4
  __ addi_d(a2, a2, 0x100);
  __ addi_d(a2, a2, 0x200);
  __ b(&L);

  // Block 5
  __ addi_d(a2, a2, 0x300);
  __ addi_d(a2, a2, 0x400);
  __ b(&L);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  uint64_t res = reinterpret_cast<uint64_t>(f.Call(value1, value2, 0, 0, 0));

  return res;
}

TEST(BLTU) {
  CcTest::InitializeVM();
  struct TestCaseBltu {
    int64_t value1;
    int64_t value2;
    int16_t offset;
    uint64_t expected_res;
  };

  // clang-format off
  struct TestCaseBltu tc[] = {
    // value1, value2, offset, expected_res
    {       0,      1,    -6,          0x3 },
    {       1,     -1,    -3,         0x30 },
    {       2,     -2,     3,        0x300 },
    {       3,     -3,     6,        0x700 },
    {       4,      4,     6,            0 },
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseBltu);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t res = run_bltu(tc[i].value1, tc[i].value2, tc[i].offset);
    CHECK_EQ(tc[i].expected_res, res);
  }
}

uint64_t run_bgeu(int64_t value1, int64_t value2, int16_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label main_block, L;
  __ li(a2, 0l);
  __ b(&main_block);
  // Block 1
  __ addi_d(a2, a2, 0x1);
  __ addi_d(a2, a2, 0x2);
  __ b(&L);

  // Block 2
  __ addi_d(a2, a2, 0x10);
  __ addi_d(a2, a2, 0x20);
  __ b(&L);

  // Block 3 (Main)
  __ bind(&main_block);
  __ bgeu(a0, a1, offset);
  __ bind(&L);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  // Block 4
  __ addi_d(a2, a2, 0x100);
  __ addi_d(a2, a2, 0x200);
  __ b(&L);

  // Block 5
  __ addi_d(a2, a2, 0x300);
  __ addi_d(a2, a2, 0x400);
  __ b(&L);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  uint64_t res = reinterpret_cast<uint64_t>(f.Call(value1, value2, 0, 0, 0));

  return res;
}

TEST(BGEU) {
  CcTest::InitializeVM();
  struct TestCaseBgeu {
    int64_t value1;
    int64_t value2;
    int16_t offset;
    uint64_t expected_res;
  };

  // clang-format off
  struct TestCaseBgeu tc[] = {
    // value1, value2, offset, expected_res
    {       0,      0,    -6,          0x3 },
    {      -1,      1,    -3,         0x30 },
    {      -2,      2,     3,        0x300 },
    {      -3,      3,     6,        0x700 },
    {       4,     -4,     6,            0 },
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseBgeu);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t res = run_bgeu(tc[i].value1, tc[i].value2, tc[i].offset);
    CHECK_EQ(tc[i].expected_res, res);
  }
}

uint64_t run_beqz(int64_t value, int32_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label main_block, L;
  __ li(a2, 0l);
  __ b(&main_block);
  // Block 1
  __ addi_d(a2, a2, 0x1);
  __ addi_d(a2, a2, 0x2);
  __ b(&L);

  // Block 2
  __ addi_d(a2, a2, 0x10);
  __ addi_d(a2, a2, 0x20);
  __ b(&L);

  // Block 3 (Main)
  __ bind(&main_block);
  __ beqz(a0, offset);
  __ bind(&L);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  // Block 4
  __ addi_d(a2, a2, 0x100);
  __ addi_d(a2, a2, 0x200);
  __ b(&L);

  // Block 5
  __ addi_d(a2, a2, 0x300);
  __ addi_d(a2, a2, 0x400);
  __ b(&L);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  uint64_t res = reinterpret_cast<uint64_t>(f.Call(value, 0, 0, 0, 0));

  return res;
}

TEST(BEQZ) {
  CcTest::InitializeVM();
  struct TestCaseBeqz {
    int64_t value;
    int32_t offset;
    uint64_t expected_res;
  };

  // clang-format off
  struct TestCaseBeqz tc[] = {
    // value, offset, expected_res
    {      0,     -6,          0x3 },
    {      0,     -3,         0x30 },
    {      0,      3,        0x300 },
    {      0,      6,        0x700 },
    {      1,      6,            0 },
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseBeqz);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t res = run_beqz(tc[i].value, tc[i].offset);
    CHECK_EQ(tc[i].expected_res, res);
  }
}

uint64_t run_bnez_b(int64_t value, int32_t offset) {
  // bnez, b.
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label main_block, L;
  __ li(a2, 0l);
  __ b(&main_block);
  // Block 1
  __ addi_d(a2, a2, 0x1);
  __ addi_d(a2, a2, 0x2);
  __ b(5);

  // Block 2
  __ addi_d(a2, a2, 0x10);
  __ addi_d(a2, a2, 0x20);
  __ b(2);

  // Block 3 (Main)
  __ bind(&main_block);
  __ bnez(a0, offset);
  __ bind(&L);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  // Block 4
  __ addi_d(a2, a2, 0x100);
  __ addi_d(a2, a2, 0x200);
  __ b(-4);

  // Block 5
  __ addi_d(a2, a2, 0x300);
  __ addi_d(a2, a2, 0x400);
  __ b(-7);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  uint64_t res = reinterpret_cast<uint64_t>(f.Call(value, 0, 0, 0, 0));

  return res;
}

TEST(BNEZ_B) {
  CcTest::InitializeVM();
  struct TestCaseBnez {
    int64_t value;
    int32_t offset;
    uint64_t expected_res;
  };

  // clang-format
```