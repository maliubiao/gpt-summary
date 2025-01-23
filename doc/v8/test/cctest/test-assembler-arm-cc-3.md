Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of V8's test suite for the ARM assembler.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The filename `test-assembler-arm.cc` and the presence of `TEST` macros strongly suggest this is a unit test file specifically for the ARM assembler within V8.

2. **Analyze individual tests:** Go through each `TEST` block and try to understand what it's testing. Look for the assembly instructions being used (`__ msr`, `__ mov`, `__ vldr`, etc.) and the `CHECK_EQ` assertions that verify the results.

3. **Group related tests:** Notice patterns and group tests by the functionality they are exercising. For example, several tests start with `ARMv8_` and deal with floating-point instructions. Others focus on condition codes (`msr_mrs`), and some on memory access (`unaligned_loads`, `unaligned_stores`).

4. **Summarize each group:** For each group, write a concise description of the tested feature. Be specific about the instructions or concepts being validated.

5. **Address specific instructions:** The prompt asks about `.tq` files, JavaScript relevance, code logic, and common errors.

    * **`.tq` files:**  The code is `.cc`, not `.tq`, so clarify this. Explain what Torque is.
    * **JavaScript relevance:** Since this tests the ARM assembler, it's directly related to how V8 compiles JavaScript for ARM. Provide a simple JavaScript example that could involve these assembly instructions (e.g., arithmetic operations, floating-point calculations).
    * **Code logic:** Look for tests with defined inputs and outputs. The `msr_mrs`, `ARMv8_float32_vrintX`, `ARMv8_vrintX`, `ARMv8_vsel`, and `ARMv8_vminmax_f64`/`ARMv8_vminmax_f32` tests all have explicit checks with defined input and expected output. Pick a couple of illustrative examples and explain the mapping.
    * **Common errors:**  Consider what errors a programmer might make when working with assembly or low-level concepts. Unaligned memory access and incorrect conditional flag usage are good examples given the tested instructions.

6. **Address the "Part 4 of 5" instruction:**  Since it's part of a larger series, acknowledge that it likely focuses on a subset of ARM assembler features and suggest that the other parts probably cover different aspects.

7. **Structure the answer:** Organize the findings logically with clear headings and bullet points for readability. Start with a general summary and then delve into the specifics.

8. **Review and refine:** Check the answer for accuracy, clarity, and completeness. Ensure all aspects of the prompt are addressed. For instance, initially, I might focus heavily on the technical details of each assembly instruction. However, the prompt also asks for JavaScript relevance and common errors, so I need to add those perspectives. Also, double-check if any tests involve conditional logic that can be used for input/output examples.

By following these steps, I can create a comprehensive and informative answer that addresses all the user's requests.
这是提供的 V8 源代码文件 `v8/test/cctest/test-assembler-arm.cc` 的第四部分。根据其内容，我们可以归纳出以下功能：

**总体功能：**

这个文件包含了针对 ARM 架构汇编器的单元测试。它使用 V8 的测试框架 (CcTest) 来验证 `Assembler` 类在生成 ARM 汇编代码时的正确性。 这些测试覆盖了各种 ARM 指令的功能和组合，包括：

* **数据处理指令:**  如 `mov`, `orr`, `and_` 等。
* **状态寄存器访问指令:** `msr` (将值写入状态寄存器), `mrs` (从状态寄存器读取值)。
* **浮点运算指令 (ARMv8):** `vrinta`, `vrintn`, `vrintp`, `vrintm`, `vrintz` (各种舍入模式的浮点数取整), `vsel` (条件选择), `vminnm`, `vmaxnm` (非传播 NaN 的最小值和最大值)。
* **内存访问指令:**  `ldr`, `str`, `ldrh`, `ldrsh`, `strh` (包括对非对齐内存的访问测试)。
* **NEON 指令:** `vswp` (向量寄存器交换)。
* **宏汇编功能:** 测试了 `FloatMin` 和 `FloatMax` 宏。

**具体功能分解 (按测试用例)：**

* **`msr_mrs`:**  测试 `msr` 和 `mrs` 指令，验证程序状态寄存器 (CPSR) 的条件标志 (N, Z, C, V) 能否正确设置和读取。
* **`ARMv8_float32_vrintX` 和 `ARMv8_vrintX`:** 测试 ARMv8 架构中的单精度 (`float`) 和双精度 (`double`) 浮点数取整指令，涵盖不同的舍入模式：
    * `vrinta` (round to nearest, ties away from zero)
    * `vrintn` (round to nearest, ties to even)
    * `vrintp` (round towards positive infinity)
    * `vrintm` (round towards negative infinity)
    * `vrintz` (round towards zero)
    同时测试了 NaN (Not a Number) 的传播。
* **`ARMv8_vsel`:** 测试 ARMv8 的条件选择指令 `vsel`，它根据条件标志从两个源寄存器中选择一个值写入目标寄存器。测试了各种条件码 (eq, ge, gt, vs, ne, lt, le, vc)。
* **`ARMv8_vminmax_f64` 和 `ARMv8_vminmax_f32`:** 测试 ARMv8 的非传播 NaN 的最小值 (`vminnm`) 和最大值 (`vmaxnm`) 指令，分别针对双精度和单精度浮点数。
* **`macro_float_minmax_f64` 和 `macro_float_minmax_f32`:** 测试宏汇编器提供的 `FloatMin` 和 `FloatMax` 宏，这些宏在内部可能使用多个指令来实现浮点数的最小值和最大值计算，并处理 NaN 的情况。
* **`unaligned_loads`:** 测试从非对齐内存地址加载数据的指令 (`ldrh`, `ldrsh`, `ldr`) 的正确性。
* **`unaligned_stores`:** 测试将数据存储到非对齐内存地址的指令 (`strh`, `str`) 的正确性。
* **`vswp`:** 测试 NEON 扩展中的寄存器交换指令 `vswp`，用于交换两个 D 寄存器（64位）或两个 Q 寄存器（128位）的内容。

**关于 .tq 文件：**

你提到如果文件以 `.tq` 结尾，则它是 V8 Torque 源代码。这个说法是正确的。Torque 是一种用于编写 V8 运行时代码的类型化的领域特定语言。  **`v8/test/cctest/test-assembler-arm.cc` 以 `.cc` 结尾，因此它是 C++ 源代码，不是 Torque 源代码。**

**与 JavaScript 的关系：**

`v8/test/cctest/test-assembler-arm.cc` 中的测试直接关系到 V8 如何将 JavaScript 代码编译成 ARM 机器码。当 V8 执行 JavaScript 代码时，它会将部分代码（特别是性能关键的部分）编译成高效的机器码。 这些测试验证了 V8 的 ARM 后端在生成这些机器码时的正确性。

**JavaScript 示例：**

```javascript
function test(a, b) {
  if (a > b) {
    return Math.max(a, 0);
  } else {
    return Math.min(b, 10);
  }
}

console.log(test(5.5, 3.2)); // 输出 5.5
console.log(test(2.1, 8.9)); // 输出 8.9
```

上述 JavaScript 代码中的比较操作 (`a > b`) 可能在底层被编译成设置 ARM 条件标志的指令。 `Math.max` 和 `Math.min` 函数在某些情况下可能会使用到类似于 `vminnm` 和 `vmaxnm` 的浮点指令。  对非对齐内存的访问在某些优化的 JavaScript 操作中也可能发生。

**代码逻辑推理 (假设输入与输出):**

以 `msr_mrs` 测试为例：

**假设输入：** `nzcv` 的值为 `0b1010` (N=1, Z=0, C=1, V=0)。

**代码逻辑：**
1. `__ msr(CPSR_f, Operand(r0));`  将 `r0` 寄存器的值（即 `nzcv`）写入 CPSR 的条件标志位。
2. 后面的 `orr` 指令会根据 CPSR 的条件标志位来设置 `r3` 的特定位。
3. `__ mrs(r3, CPSR);` 将整个 CPSR 的值读入 `r3`。
4. `__ and_(r3, r3, Operand(kSpecialCondition));`  将 `r3` 与一个掩码进行按位与操作，该掩码只保留条件标志位。

**预期输出：**
* `result_conditionals` 指向的内存地址将存储 `nzcv` 的值 `0b1010`。
* `result_mrs` 指向的内存地址也将存储 `nzcv` 的值 `0b1010`（因为掩码只保留了条件标志位）。

**用户常见的编程错误：**

* **错误地使用条件码：**  例如，在 `vsel` 指令中使用了错误的条件码，导致在不应该选择某个值的时候选择了它。
    ```c++
    // 错误示例：假设本意是当 a >= b 时选择 a，但使用了 gt (大于)
    __ vsel(gt, s0, s1, s2); // 如果 a > b 则 s0 = s1，否则 s0 = s2
    ```
    **JavaScript 场景：**  在 JavaScript 中编写复杂的条件语句时，V8 编译出的机器码可能会因为对条件判断的理解偏差而产生错误的行为。

* **未考虑 NaN 的浮点运算：**  在浮点数比较和最小值/最大值计算中，未正确处理 NaN 值可能导致意外结果。例如，直接使用 `<` 或 `>` 比较包含 NaN 的浮点数总会返回 `false`。
    ```c++
    // 错误示例：假设直接比较浮点数而不考虑 NaN
    __ vcmp(d0, d1);
    __ vmov(eq, d2, d0); // 如果 d0 == d1 则 d2 = d0，但如果 d0 或 d1 是 NaN，eq 永远不会成立
    ```
    **JavaScript 场景：** 在 JavaScript 中进行浮点数运算时，程序员可能会忽略 NaN 的特殊性，导致逻辑错误。

* **非对齐内存访问错误 (在某些架构上)：** 虽然 ARM 允许非对齐访问，但在一些其他架构上，尝试从非对齐地址加载或存储数据会导致程序崩溃或产生不可预测的结果。 即使在 ARM 上，非对齐访问也可能比对齐访问慢。
    ```c++
    // 虽然在 ARM 上可行，但在其他架构上可能出错
    char data[10];
    uint32_t* ptr = reinterpret_cast<uint32_t*>(data + 1); // ptr 指向非 4 字节对齐的地址
    __ ldr(r0, MemOperand(ptr));
    ```
    **JavaScript 场景：** 在操作 `ArrayBuffer` 等底层数据结构时，如果计算的偏移量不正确，可能会导致尝试非对齐访问。

**总结 (第 4 部分功能)：**

这部分测试文件专注于验证 V8 的 ARM 汇编器在生成与 **状态寄存器操作**、**浮点数取整 (ARMv8)**、**条件浮点数选择 (ARMv8)**、**非传播 NaN 的最小值/最大值计算 (ARMv8)**、**宏汇编浮点数最小值/最大值** 以及 **非对齐内存访问和 NEON 寄存器交换** 相关的指令时的正确性。它是 V8 确保其在 ARM 架构上正确执行 JavaScript 代码的关键组成部分。

### 提示词
```
这是目录为v8/test/cctest/test-assembler-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
(ia_w, sp, {r4, r5, pc});

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code = Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING)
                          .set_self_reference(code_object)
                          .Build();
  auto f = GeneratedCode<F_iiiii>::FromCode(isolate, *code);
  int res = reinterpret_cast<int>(f.Call(21, 0, 0, 0, 0));
  ::printf("f() = %d\n", res);
  CHECK_EQ(42, res);
}

TEST(msr_mrs) {
  // Test msr and mrs.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});

  // Create a helper function:
  //  void TestMsrMrs(uint32_t nzcv,
  //                  uint32_t * result_conditionals,
  //                  uint32_t * result_mrs);
  __ msr(CPSR_f, Operand(r0));

  // Test that the condition flags have taken effect.
  __ mov(r3, Operand(0));
  __ orr(r3, r3, Operand(1 << 31), LeaveCC, mi);  // N
  __ orr(r3, r3, Operand(1 << 30), LeaveCC, eq);  // Z
  __ orr(r3, r3, Operand(1 << 29), LeaveCC, cs);  // C
  __ orr(r3, r3, Operand(1 << 28), LeaveCC, vs);  // V
  __ str(r3, MemOperand(r1));

  // Also check mrs, ignoring everything other than the flags.
  __ mrs(r3, CPSR);
  __ and_(r3, r3, Operand(kSpecialCondition));
  __ str(r3, MemOperand(r2));

  __ bx(lr);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  StdoutStream os;
  Print(*code, os);
#endif
  auto f = GeneratedCode<F_ippii>::FromCode(isolate, *code);

#define CHECK_MSR_MRS(n, z, c, v)                                  \
  do {                                                             \
    uint32_t nzcv = (n << 31) | (z << 30) | (c << 29) | (v << 28); \
    uint32_t result_conditionals = -1;                             \
    uint32_t result_mrs = -1;                                      \
    f.Call(nzcv, &result_conditionals, &result_mrs, 0, 0);         \
    CHECK_EQ(nzcv, result_conditionals);                           \
    CHECK_EQ(nzcv, result_mrs);                                    \
  } while (0);

  //            N  Z  C  V
  CHECK_MSR_MRS(0, 0, 0, 0);
  CHECK_MSR_MRS(0, 0, 0, 1);
  CHECK_MSR_MRS(0, 0, 1, 0);
  CHECK_MSR_MRS(0, 0, 1, 1);
  CHECK_MSR_MRS(0, 1, 0, 0);
  CHECK_MSR_MRS(0, 1, 0, 1);
  CHECK_MSR_MRS(0, 1, 1, 0);
  CHECK_MSR_MRS(0, 1, 1, 1);
  CHECK_MSR_MRS(1, 0, 0, 0);
  CHECK_MSR_MRS(1, 0, 0, 1);
  CHECK_MSR_MRS(1, 0, 1, 0);
  CHECK_MSR_MRS(1, 0, 1, 1);
  CHECK_MSR_MRS(1, 1, 0, 0);
  CHECK_MSR_MRS(1, 1, 0, 1);
  CHECK_MSR_MRS(1, 1, 1, 0);
  CHECK_MSR_MRS(1, 1, 1, 1);

#undef CHECK_MSR_MRS
}

TEST(ARMv8_float32_vrintX) {
  // Test the vrintX floating point instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    float input;
    float ar;
    float nr;
    float mr;
    float pr;
    float zr;
  };
  T t;

  // Create a function that accepts &t, and loads, manipulates, and stores
  // the floats.
  Assembler assm(AssemblerOptions{});


  if (CpuFeatures::IsSupported(ARMv8)) {
    CpuFeatureScope scope(&assm, ARMv8);

    __ mov(ip, Operand(sp));
    __ stm(db_w, sp, {r4, fp, lr});

    __ mov(r4, Operand(r0));

    // Test vrinta
    __ vldr(s6, r4, offsetof(T, input));
    __ vrinta(s5, s6);
    __ vstr(s5, r4, offsetof(T, ar));

    // Test vrintn
    __ vldr(s6, r4, offsetof(T, input));
    __ vrintn(s5, s6);
    __ vstr(s5, r4, offsetof(T, nr));

    // Test vrintp
    __ vldr(s6, r4, offsetof(T, input));
    __ vrintp(s5, s6);
    __ vstr(s5, r4, offsetof(T, pr));

    // Test vrintm
    __ vldr(s6, r4, offsetof(T, input));
    __ vrintm(s5, s6);
    __ vstr(s5, r4, offsetof(T, mr));

    // Test vrintz
    __ vldr(s6, r4, offsetof(T, input));
    __ vrintz(s5, s6);
    __ vstr(s5, r4, offsetof(T, zr));

    __ ldm(ia_w, sp, {r4, fp, pc});

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
    StdoutStream os;
    Print(*code, os);
#endif
    auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);

#define CHECK_VRINT(input_val, ares, nres, mres, pres, zres) \
  t.input = input_val;                                       \
  f.Call(&t, 0, 0, 0, 0);                                    \
  CHECK_EQ(ares, t.ar);                                      \
  CHECK_EQ(nres, t.nr);                                      \
  CHECK_EQ(mres, t.mr);                                      \
  CHECK_EQ(pres, t.pr);                                      \
  CHECK_EQ(zres, t.zr);

    CHECK_VRINT(-0.5, -1.0, -0.0, -1.0, -0.0, -0.0)
    CHECK_VRINT(-0.6, -1.0, -1.0, -1.0, -0.0, -0.0)
    CHECK_VRINT(-1.1, -1.0, -1.0, -2.0, -1.0, -1.0)
    CHECK_VRINT(0.5, 1.0, 0.0, 0.0, 1.0, 0.0)
    CHECK_VRINT(0.6, 1.0, 1.0, 0.0, 1.0, 0.0)
    CHECK_VRINT(1.1, 1.0, 1.0, 1.0, 2.0, 1.0)
    float inf = std::numeric_limits<float>::infinity();
    CHECK_VRINT(inf, inf, inf, inf, inf, inf)
    CHECK_VRINT(-inf, -inf, -inf, -inf, -inf, -inf)
    CHECK_VRINT(-0.0, -0.0, -0.0, -0.0, -0.0, -0.0)

    // Check NaN propagation.
    float nan = std::numeric_limits<float>::quiet_NaN();
    t.input = nan;
    f.Call(&t, 0, 0, 0, 0);
    CHECK_EQ(base::bit_cast<int32_t>(nan), base::bit_cast<int32_t>(t.ar));
    CHECK_EQ(base::bit_cast<int32_t>(nan), base::bit_cast<int32_t>(t.nr));
    CHECK_EQ(base::bit_cast<int32_t>(nan), base::bit_cast<int32_t>(t.mr));
    CHECK_EQ(base::bit_cast<int32_t>(nan), base::bit_cast<int32_t>(t.pr));
    CHECK_EQ(base::bit_cast<int32_t>(nan), base::bit_cast<int32_t>(t.zr));

#undef CHECK_VRINT
  }
}


TEST(ARMv8_vrintX) {
  // Test the vrintX floating point instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    double input;
    double ar;
    double nr;
    double mr;
    double pr;
    double zr;
  };
  T t;

  // Create a function that accepts &t, and loads, manipulates, and stores
  // the doubles and floats.
  Assembler assm(AssemblerOptions{});


  if (CpuFeatures::IsSupported(ARMv8)) {
    CpuFeatureScope scope(&assm, ARMv8);

    __ mov(ip, Operand(sp));
    __ stm(db_w, sp, {r4, fp, lr});

    __ mov(r4, Operand(r0));

    // Test vrinta
    __ vldr(d6, r4, offsetof(T, input));
    __ vrinta(d5, d6);
    __ vstr(d5, r4, offsetof(T, ar));

    // Test vrintn
    __ vldr(d6, r4, offsetof(T, input));
    __ vrintn(d5, d6);
    __ vstr(d5, r4, offsetof(T, nr));

    // Test vrintp
    __ vldr(d6, r4, offsetof(T, input));
    __ vrintp(d5, d6);
    __ vstr(d5, r4, offsetof(T, pr));

    // Test vrintm
    __ vldr(d6, r4, offsetof(T, input));
    __ vrintm(d5, d6);
    __ vstr(d5, r4, offsetof(T, mr));

    // Test vrintz
    __ vldr(d6, r4, offsetof(T, input));
    __ vrintz(d5, d6);
    __ vstr(d5, r4, offsetof(T, zr));

    __ ldm(ia_w, sp, {r4, fp, pc});

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
    StdoutStream os;
    Print(*code, os);
#endif
    auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);

#define CHECK_VRINT(input_val, ares, nres, mres, pres, zres) \
  t.input = input_val;                                       \
  f.Call(&t, 0, 0, 0, 0);                                    \
  CHECK_EQ(ares, t.ar);                                      \
  CHECK_EQ(nres, t.nr);                                      \
  CHECK_EQ(mres, t.mr);                                      \
  CHECK_EQ(pres, t.pr);                                      \
  CHECK_EQ(zres, t.zr);

    CHECK_VRINT(-0.5, -1.0, -0.0, -1.0, -0.0, -0.0)
    CHECK_VRINT(-0.6, -1.0, -1.0, -1.0, -0.0, -0.0)
    CHECK_VRINT(-1.1, -1.0, -1.0, -2.0, -1.0, -1.0)
    CHECK_VRINT(0.5, 1.0, 0.0, 0.0, 1.0, 0.0)
    CHECK_VRINT(0.6, 1.0, 1.0, 0.0, 1.0, 0.0)
    CHECK_VRINT(1.1, 1.0, 1.0, 1.0, 2.0, 1.0)
    double inf = std::numeric_limits<double>::infinity();
    CHECK_VRINT(inf, inf, inf, inf, inf, inf)
    CHECK_VRINT(-inf, -inf, -inf, -inf, -inf, -inf)
    CHECK_VRINT(-0.0, -0.0, -0.0, -0.0, -0.0, -0.0)

    // Check NaN propagation.
    double nan = std::numeric_limits<double>::quiet_NaN();
    t.input = nan;
    f.Call(&t, 0, 0, 0, 0);
    CHECK_EQ(base::bit_cast<int64_t>(nan), base::bit_cast<int64_t>(t.ar));
    CHECK_EQ(base::bit_cast<int64_t>(nan), base::bit_cast<int64_t>(t.nr));
    CHECK_EQ(base::bit_cast<int64_t>(nan), base::bit_cast<int64_t>(t.mr));
    CHECK_EQ(base::bit_cast<int64_t>(nan), base::bit_cast<int64_t>(t.pr));
    CHECK_EQ(base::bit_cast<int64_t>(nan), base::bit_cast<int64_t>(t.zr));

#undef CHECK_VRINT
  }
}

TEST(ARMv8_vsel) {
  // Test the vsel floating point instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});

  // Used to indicate whether a condition passed or failed.
  static constexpr float kResultPass = 1.0f;
  static constexpr float kResultFail = -kResultPass;

  struct ResultsF32 {
    float vseleq_;
    float vselge_;
    float vselgt_;
    float vselvs_;

    // The following conditions aren't architecturally supported, but the
    // assembler implements them by swapping the inputs.
    float vselne_;
    float vsellt_;
    float vselle_;
    float vselvc_;
  };

  struct ResultsF64 {
    double vseleq_;
    double vselge_;
    double vselgt_;
    double vselvs_;

    // The following conditions aren't architecturally supported, but the
    // assembler implements them by swapping the inputs.
    double vselne_;
    double vsellt_;
    double vselle_;
    double vselvc_;
  };

  if (CpuFeatures::IsSupported(ARMv8)) {
    CpuFeatureScope scope(&assm, ARMv8);

    // Create a helper function:
    //  void TestVsel(uint32_t nzcv,
    //                ResultsF32* results_f32,
    //                ResultsF64* results_f64);
    __ msr(CPSR_f, Operand(r0));

    __ vmov(s1, Float32(kResultPass));
    __ vmov(s2, Float32(kResultFail));

    __ vsel(eq, s0, s1, s2);
    __ vstr(s0, r1, offsetof(ResultsF32, vseleq_));
    __ vsel(ge, s0, s1, s2);
    __ vstr(s0, r1, offsetof(ResultsF32, vselge_));
    __ vsel(gt, s0, s1, s2);
    __ vstr(s0, r1, offsetof(ResultsF32, vselgt_));
    __ vsel(vs, s0, s1, s2);
    __ vstr(s0, r1, offsetof(ResultsF32, vselvs_));

    __ vsel(ne, s0, s1, s2);
    __ vstr(s0, r1, offsetof(ResultsF32, vselne_));
    __ vsel(lt, s0, s1, s2);
    __ vstr(s0, r1, offsetof(ResultsF32, vsellt_));
    __ vsel(le, s0, s1, s2);
    __ vstr(s0, r1, offsetof(ResultsF32, vselle_));
    __ vsel(vc, s0, s1, s2);
    __ vstr(s0, r1, offsetof(ResultsF32, vselvc_));

    __ vmov(d1, base::Double(kResultPass));
    __ vmov(d2, base::Double(kResultFail));

    __ vsel(eq, d0, d1, d2);
    __ vstr(d0, r2, offsetof(ResultsF64, vseleq_));
    __ vsel(ge, d0, d1, d2);
    __ vstr(d0, r2, offsetof(ResultsF64, vselge_));
    __ vsel(gt, d0, d1, d2);
    __ vstr(d0, r2, offsetof(ResultsF64, vselgt_));
    __ vsel(vs, d0, d1, d2);
    __ vstr(d0, r2, offsetof(ResultsF64, vselvs_));

    __ vsel(ne, d0, d1, d2);
    __ vstr(d0, r2, offsetof(ResultsF64, vselne_));
    __ vsel(lt, d0, d1, d2);
    __ vstr(d0, r2, offsetof(ResultsF64, vsellt_));
    __ vsel(le, d0, d1, d2);
    __ vstr(d0, r2, offsetof(ResultsF64, vselle_));
    __ vsel(vc, d0, d1, d2);
    __ vstr(d0, r2, offsetof(ResultsF64, vselvc_));

    __ bx(lr);

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
    StdoutStream os;
    Print(*code, os);
#endif
    auto f = GeneratedCode<F_ippii>::FromCode(isolate, *code);

    static_assert(kResultPass == -kResultFail);
#define CHECK_VSEL(n, z, c, v, vseleq, vselge, vselgt, vselvs)     \
  do {                                                             \
    ResultsF32 results_f32;                                        \
    ResultsF64 results_f64;                                        \
    uint32_t nzcv = (n << 31) | (z << 30) | (c << 29) | (v << 28); \
    f.Call(nzcv, &results_f32, &results_f64, 0, 0);                \
    CHECK_EQ(vseleq, results_f32.vseleq_);                         \
    CHECK_EQ(vselge, results_f32.vselge_);                         \
    CHECK_EQ(vselgt, results_f32.vselgt_);                         \
    CHECK_EQ(vselvs, results_f32.vselvs_);                         \
    CHECK_EQ(-vseleq, results_f32.vselne_);                        \
    CHECK_EQ(-vselge, results_f32.vsellt_);                        \
    CHECK_EQ(-vselgt, results_f32.vselle_);                        \
    CHECK_EQ(-vselvs, results_f32.vselvc_);                        \
    CHECK_EQ(vseleq, results_f64.vseleq_);                         \
    CHECK_EQ(vselge, results_f64.vselge_);                         \
    CHECK_EQ(vselgt, results_f64.vselgt_);                         \
    CHECK_EQ(vselvs, results_f64.vselvs_);                         \
    CHECK_EQ(-vseleq, results_f64.vselne_);                        \
    CHECK_EQ(-vselge, results_f64.vsellt_);                        \
    CHECK_EQ(-vselgt, results_f64.vselle_);                        \
    CHECK_EQ(-vselvs, results_f64.vselvc_);                        \
  } while (0);

    //         N  Z  C  V  vseleq       vselge       vselgt       vselvs
    CHECK_VSEL(0, 0, 0, 0, kResultFail, kResultPass, kResultPass, kResultFail);
    CHECK_VSEL(0, 0, 0, 1, kResultFail, kResultFail, kResultFail, kResultPass);
    CHECK_VSEL(0, 0, 1, 0, kResultFail, kResultPass, kResultPass, kResultFail);
    CHECK_VSEL(0, 0, 1, 1, kResultFail, kResultFail, kResultFail, kResultPass);
    CHECK_VSEL(0, 1, 0, 0, kResultPass, kResultPass, kResultFail, kResultFail);
    CHECK_VSEL(0, 1, 0, 1, kResultPass, kResultFail, kResultFail, kResultPass);
    CHECK_VSEL(0, 1, 1, 0, kResultPass, kResultPass, kResultFail, kResultFail);
    CHECK_VSEL(0, 1, 1, 1, kResultPass, kResultFail, kResultFail, kResultPass);
    CHECK_VSEL(1, 0, 0, 0, kResultFail, kResultFail, kResultFail, kResultFail);
    CHECK_VSEL(1, 0, 0, 1, kResultFail, kResultPass, kResultPass, kResultPass);
    CHECK_VSEL(1, 0, 1, 0, kResultFail, kResultFail, kResultFail, kResultFail);
    CHECK_VSEL(1, 0, 1, 1, kResultFail, kResultPass, kResultPass, kResultPass);
    CHECK_VSEL(1, 1, 0, 0, kResultPass, kResultFail, kResultFail, kResultFail);
    CHECK_VSEL(1, 1, 0, 1, kResultPass, kResultPass, kResultFail, kResultPass);
    CHECK_VSEL(1, 1, 1, 0, kResultPass, kResultFail, kResultFail, kResultFail);
    CHECK_VSEL(1, 1, 1, 1, kResultPass, kResultPass, kResultFail, kResultPass);

#undef CHECK_VSEL
  }
}

TEST(ARMv8_vminmax_f64) {
  // Test the vminnm and vmaxnm floating point instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});

  struct Inputs {
    double left_;
    double right_;
  };

  struct Results {
    double vminnm_;
    double vmaxnm_;
  };

  if (CpuFeatures::IsSupported(ARMv8)) {
    CpuFeatureScope scope(&assm, ARMv8);

    // Create a helper function:
    //  void TestVminmax(const Inputs* inputs,
    //                   Results* results);
    __ vldr(d1, r0, offsetof(Inputs, left_));
    __ vldr(d2, r0, offsetof(Inputs, right_));

    __ vminnm(d0, d1, d2);
    __ vstr(d0, r1, offsetof(Results, vminnm_));
    __ vmaxnm(d0, d1, d2);
    __ vstr(d0, r1, offsetof(Results, vmaxnm_));

    __ bx(lr);

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
    StdoutStream os;
    Print(*code, os);
#endif
    auto f = GeneratedCode<F_ppiii>::FromCode(isolate, *code);

#define CHECK_VMINMAX(left, right, vminnm, vmaxnm)                  \
  do {                                                              \
    Inputs inputs = {left, right};                                  \
    Results results;                                                \
    f.Call(&inputs, &results, 0, 0, 0);                             \
    /* Use a base::bit_cast to correctly identify -0.0 and NaNs. */ \
    CHECK_EQ(base::bit_cast<uint64_t>(vminnm),                      \
             base::bit_cast<uint64_t>(results.vminnm_));            \
    CHECK_EQ(base::bit_cast<uint64_t>(vmaxnm),                      \
             base::bit_cast<uint64_t>(results.vmaxnm_));            \
  } while (0);

    double nan_a = base::bit_cast<double>(UINT64_C(0x7FF8000000000001));
    double nan_b = base::bit_cast<double>(UINT64_C(0x7FF8000000000002));

    CHECK_VMINMAX(1.0, -1.0, -1.0, 1.0);
    CHECK_VMINMAX(-1.0, 1.0, -1.0, 1.0);
    CHECK_VMINMAX(0.0, -1.0, -1.0, 0.0);
    CHECK_VMINMAX(-1.0, 0.0, -1.0, 0.0);
    CHECK_VMINMAX(-0.0, -1.0, -1.0, -0.0);
    CHECK_VMINMAX(-1.0, -0.0, -1.0, -0.0);
    CHECK_VMINMAX(0.0, 1.0, 0.0, 1.0);
    CHECK_VMINMAX(1.0, 0.0, 0.0, 1.0);

    CHECK_VMINMAX(0.0, 0.0, 0.0, 0.0);
    CHECK_VMINMAX(-0.0, -0.0, -0.0, -0.0);
    CHECK_VMINMAX(-0.0, 0.0, -0.0, 0.0);
    CHECK_VMINMAX(0.0, -0.0, -0.0, 0.0);

    CHECK_VMINMAX(0.0, nan_a, 0.0, 0.0);
    CHECK_VMINMAX(nan_a, 0.0, 0.0, 0.0);
    CHECK_VMINMAX(nan_a, nan_b, nan_a, nan_a);
    CHECK_VMINMAX(nan_b, nan_a, nan_b, nan_b);

#undef CHECK_VMINMAX
  }
}

TEST(ARMv8_vminmax_f32) {
  // Test the vminnm and vmaxnm floating point instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});

  struct Inputs {
    float left_;
    float right_;
  };

  struct Results {
    float vminnm_;
    float vmaxnm_;
  };

  if (CpuFeatures::IsSupported(ARMv8)) {
    CpuFeatureScope scope(&assm, ARMv8);

    // Create a helper function:
    //  void TestVminmax(const Inputs* inputs,
    //                   Results* results);
    __ vldr(s1, r0, offsetof(Inputs, left_));
    __ vldr(s2, r0, offsetof(Inputs, right_));

    __ vminnm(s0, s1, s2);
    __ vstr(s0, r1, offsetof(Results, vminnm_));
    __ vmaxnm(s0, s1, s2);
    __ vstr(s0, r1, offsetof(Results, vmaxnm_));

    __ bx(lr);

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
    StdoutStream os;
    Print(*code, os);
#endif
    auto f = GeneratedCode<F_ppiii>::FromCode(isolate, *code);

#define CHECK_VMINMAX(left, right, vminnm, vmaxnm)                  \
  do {                                                              \
    Inputs inputs = {left, right};                                  \
    Results results;                                                \
    f.Call(&inputs, &results, 0, 0, 0);                             \
    /* Use a base::bit_cast to correctly identify -0.0 and NaNs. */ \
    CHECK_EQ(base::bit_cast<uint32_t>(vminnm),                      \
             base::bit_cast<uint32_t>(results.vminnm_));            \
    CHECK_EQ(base::bit_cast<uint32_t>(vmaxnm),                      \
             base::bit_cast<uint32_t>(results.vmaxnm_));            \
  } while (0);

    float nan_a = base::bit_cast<float>(UINT32_C(0x7FC00001));
    float nan_b = base::bit_cast<float>(UINT32_C(0x7FC00002));

    CHECK_VMINMAX(1.0f, -1.0f, -1.0f, 1.0f);
    CHECK_VMINMAX(-1.0f, 1.0f, -1.0f, 1.0f);
    CHECK_VMINMAX(0.0f, -1.0f, -1.0f, 0.0f);
    CHECK_VMINMAX(-1.0f, 0.0f, -1.0f, 0.0f);
    CHECK_VMINMAX(-0.0f, -1.0f, -1.0f, -0.0f);
    CHECK_VMINMAX(-1.0f, -0.0f, -1.0f, -0.0f);
    CHECK_VMINMAX(0.0f, 1.0f, 0.0f, 1.0f);
    CHECK_VMINMAX(1.0f, 0.0f, 0.0f, 1.0f);

    CHECK_VMINMAX(0.0f, 0.0f, 0.0f, 0.0f);
    CHECK_VMINMAX(-0.0f, -0.0f, -0.0f, -0.0f);
    CHECK_VMINMAX(-0.0f, 0.0f, -0.0f, 0.0f);
    CHECK_VMINMAX(0.0f, -0.0f, -0.0f, 0.0f);

    CHECK_VMINMAX(0.0f, nan_a, 0.0f, 0.0f);
    CHECK_VMINMAX(nan_a, 0.0f, 0.0f, 0.0f);
    CHECK_VMINMAX(nan_a, nan_b, nan_a, nan_a);
    CHECK_VMINMAX(nan_b, nan_a, nan_b, nan_b);

#undef CHECK_VMINMAX
  }
}

template <typename T, typename Inputs, typename Results>
static GeneratedCode<F_ppiii> GenerateMacroFloatMinMax(
    MacroAssembler* assm_ptr) {
  MacroAssembler& assm = *assm_ptr;

  T a = T::from_code(0);  // d0/s0
  T b = T::from_code(1);  // d1/s1
  T c = T::from_code(2);  // d2/s2

  // Create a helper function:
  //  void TestFloatMinMax(const Inputs* inputs,
  //                       Results* results);
  Label ool_min_abc, ool_min_aab, ool_min_aba;
  Label ool_max_abc, ool_max_aab, ool_max_aba;

  Label done_min_abc, done_min_aab, done_min_aba;
  Label done_max_abc, done_max_aab, done_max_aba;

  // a = min(b, c);
  __ vldr(b, r0, offsetof(Inputs, left_));
  __ vldr(c, r0, offsetof(Inputs, right_));
  __ FloatMin(a, b, c, &ool_min_abc);
  __ bind(&done_min_abc);
  __ vstr(a, r1, offsetof(Results, min_abc_));

  // a = min(a, b);
  __ vldr(a, r0, offsetof(Inputs, left_));
  __ vldr(b, r0, offsetof(Inputs, right_));
  __ FloatMin(a, a, b, &ool_min_aab);
  __ bind(&done_min_aab);
  __ vstr(a, r1, offsetof(Results, min_aab_));

  // a = min(b, a);
  __ vldr(b, r0, offsetof(Inputs, left_));
  __ vldr(a, r0, offsetof(Inputs, right_));
  __ FloatMin(a, b, a, &ool_min_aba);
  __ bind(&done_min_aba);
  __ vstr(a, r1, offsetof(Results, min_aba_));

  // a = max(b, c);
  __ vldr(b, r0, offsetof(Inputs, left_));
  __ vldr(c, r0, offsetof(Inputs, right_));
  __ FloatMax(a, b, c, &ool_max_abc);
  __ bind(&done_max_abc);
  __ vstr(a, r1, offsetof(Results, max_abc_));

  // a = max(a, b);
  __ vldr(a, r0, offsetof(Inputs, left_));
  __ vldr(b, r0, offsetof(Inputs, right_));
  __ FloatMax(a, a, b, &ool_max_aab);
  __ bind(&done_max_aab);
  __ vstr(a, r1, offsetof(Results, max_aab_));

  // a = max(b, a);
  __ vldr(b, r0, offsetof(Inputs, left_));
  __ vldr(a, r0, offsetof(Inputs, right_));
  __ FloatMax(a, b, a, &ool_max_aba);
  __ bind(&done_max_aba);
  __ vstr(a, r1, offsetof(Results, max_aba_));

  __ bx(lr);

  // Generate out-of-line cases.
  __ bind(&ool_min_abc);
  __ FloatMinOutOfLine(a, b, c);
  __ b(&done_min_abc);

  __ bind(&ool_min_aab);
  __ FloatMinOutOfLine(a, a, b);
  __ b(&done_min_aab);

  __ bind(&ool_min_aba);
  __ FloatMinOutOfLine(a, b, a);
  __ b(&done_min_aba);

  __ bind(&ool_max_abc);
  __ FloatMaxOutOfLine(a, b, c);
  __ b(&done_max_abc);

  __ bind(&ool_max_aab);
  __ FloatMaxOutOfLine(a, a, b);
  __ b(&done_max_aab);

  __ bind(&ool_max_aba);
  __ FloatMaxOutOfLine(a, b, a);
  __ b(&done_max_aba);

  CodeDesc desc;
  assm.GetCode(assm.isolate(), &desc);
  Handle<Code> code =
      Factory::CodeBuilder(assm.isolate(), desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  StdoutStream os;
  Print(*code, os);
#endif
  return GeneratedCode<F_ppiii>::FromCode(assm.isolate(), *code);
}

TEST(macro_float_minmax_f64) {
  // Test the FloatMin and FloatMax macros.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, CodeObjectRequired::kYes);

  struct Inputs {
    double left_;
    double right_;
  };

  struct Results {
    // Check all register aliasing possibilities in order to exercise all
    // code-paths in the macro assembler.
    double min_abc_;
    double min_aab_;
    double min_aba_;
    double max_abc_;
    double max_aab_;
    double max_aba_;
  };

  auto f = GenerateMacroFloatMinMax<DwVfpRegister, Inputs, Results>(&assm);

#define CHECK_MINMAX(left, right, min, max)                         \
  do {                                                              \
    Inputs inputs = {left, right};                                  \
    Results results;                                                \
    f.Call(&inputs, &results, 0, 0, 0);                             \
    /* Use a base::bit_cast to correctly identify -0.0 and NaNs. */ \
    CHECK_EQ(base::bit_cast<uint64_t>(min),                         \
             base::bit_cast<uint64_t>(results.min_abc_));           \
    CHECK_EQ(base::bit_cast<uint64_t>(min),                         \
             base::bit_cast<uint64_t>(results.min_aab_));           \
    CHECK_EQ(base::bit_cast<uint64_t>(min),                         \
             base::bit_cast<uint64_t>(results.min_aba_));           \
    CHECK_EQ(base::bit_cast<uint64_t>(max),                         \
             base::bit_cast<uint64_t>(results.max_abc_));           \
    CHECK_EQ(base::bit_cast<uint64_t>(max),                         \
             base::bit_cast<uint64_t>(results.max_aab_));           \
    CHECK_EQ(base::bit_cast<uint64_t>(max),                         \
             base::bit_cast<uint64_t>(results.max_aba_));           \
  } while (0)

  double nan_a = base::bit_cast<double>(UINT64_C(0x7FF8000000000001));
  double nan_b = base::bit_cast<double>(UINT64_C(0x7FF8000000000002));

  CHECK_MINMAX(1.0, -1.0, -1.0, 1.0);
  CHECK_MINMAX(-1.0, 1.0, -1.0, 1.0);
  CHECK_MINMAX(0.0, -1.0, -1.0, 0.0);
  CHECK_MINMAX(-1.0, 0.0, -1.0, 0.0);
  CHECK_MINMAX(-0.0, -1.0, -1.0, -0.0);
  CHECK_MINMAX(-1.0, -0.0, -1.0, -0.0);
  CHECK_MINMAX(0.0, 1.0, 0.0, 1.0);
  CHECK_MINMAX(1.0, 0.0, 0.0, 1.0);

  CHECK_MINMAX(0.0, 0.0, 0.0, 0.0);
  CHECK_MINMAX(-0.0, -0.0, -0.0, -0.0);
  CHECK_MINMAX(-0.0, 0.0, -0.0, 0.0);
  CHECK_MINMAX(0.0, -0.0, -0.0, 0.0);

  CHECK_MINMAX(0.0, nan_a, nan_a, nan_a);
  CHECK_MINMAX(nan_a, 0.0, nan_a, nan_a);
  CHECK_MINMAX(nan_a, nan_b, nan_a, nan_a);
  CHECK_MINMAX(nan_b, nan_a, nan_b, nan_b);

#undef CHECK_MINMAX
}

TEST(macro_float_minmax_f32) {
  // Test the FloatMin and FloatMax macros.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, CodeObjectRequired::kYes);

  struct Inputs {
    float left_;
    float right_;
  };

  struct Results {
    // Check all register aliasing possibilities in order to exercise all
    // code-paths in the macro assembler.
    float min_abc_;
    float min_aab_;
    float min_aba_;
    float max_abc_;
    float max_aab_;
    float max_aba_;
  };

  auto f = GenerateMacroFloatMinMax<SwVfpRegister, Inputs, Results>(&assm);

#define CHECK_MINMAX(left, right, min, max)                         \
  do {                                                              \
    Inputs inputs = {left, right};                                  \
    Results results;                                                \
    f.Call(&inputs, &results, 0, 0, 0);                             \
    /* Use a base::bit_cast to correctly identify -0.0 and NaNs. */ \
    CHECK_EQ(base::bit_cast<uint32_t>(min),                         \
             base::bit_cast<uint32_t>(results.min_abc_));           \
    CHECK_EQ(base::bit_cast<uint32_t>(min),                         \
             base::bit_cast<uint32_t>(results.min_aab_));           \
    CHECK_EQ(base::bit_cast<uint32_t>(min),                         \
             base::bit_cast<uint32_t>(results.min_aba_));           \
    CHECK_EQ(base::bit_cast<uint32_t>(max),                         \
             base::bit_cast<uint32_t>(results.max_abc_));           \
    CHECK_EQ(base::bit_cast<uint32_t>(max),                         \
             base::bit_cast<uint32_t>(results.max_aab_));           \
    CHECK_EQ(base::bit_cast<uint32_t>(max),                         \
             base::bit_cast<uint32_t>(results.max_aba_));           \
  } while (0)

  float nan_a = base::bit_cast<float>(UINT32_C(0x7FC00001));
  float nan_b = base::bit_cast<float>(UINT32_C(0x7FC00002));

  CHECK_MINMAX(1.0f, -1.0f, -1.0f, 1.0f);
  CHECK_MINMAX(-1.0f, 1.0f, -1.0f, 1.0f);
  CHECK_MINMAX(0.0f, -1.0f, -1.0f, 0.0f);
  CHECK_MINMAX(-1.0f, 0.0f, -1.0f, 0.0f);
  CHECK_MINMAX(-0.0f, -1.0f, -1.0f, -0.0f);
  CHECK_MINMAX(-1.0f, -0.0f, -1.0f, -0.0f);
  CHECK_MINMAX(0.0f, 1.0f, 0.0f, 1.0f);
  CHECK_MINMAX(1.0f, 0.0f, 0.0f, 1.0f);

  CHECK_MINMAX(0.0f, 0.0f, 0.0f, 0.0f);
  CHECK_MINMAX(-0.0f, -0.0f, -0.0f, -0.0f);
  CHECK_MINMAX(-0.0f, 0.0f, -0.0f, 0.0f);
  CHECK_MINMAX(0.0f, -0.0f, -0.0f, 0.0f);

  CHECK_MINMAX(0.0f, nan_a, nan_a, nan_a);
  CHECK_MINMAX(nan_a, 0.0f, nan_a, nan_a);
  CHECK_MINMAX(nan_a, nan_b, nan_a, nan_a);
  CHECK_MINMAX(nan_b, nan_a, nan_b, nan_b);

#undef CHECK_MINMAX
}

TEST(unaligned_loads) {
  // All supported ARM targets allow unaligned accesses.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    uint32_t ldrh;
    uint32_t ldrsh;
    uint32_t ldr;
  };
  T t;

  Assembler assm(AssemblerOptions{});
  __ ldrh(ip, MemOperand(r1, r2));
  __ str(ip, MemOperand(r0, offsetof(T, ldrh)));
  __ ldrsh(ip, MemOperand(r1, r2));
  __ str(ip, MemOperand(r0, offsetof(T, ldrsh)));
  __ ldr(ip, MemOperand(r1, r2));
  __ str(ip, MemOperand(r0, offsetof(T, ldr)));
  __ bx(lr);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  StdoutStream os;
  Print(*code, os);
#endif
  auto f = GeneratedCode<F_ppiii>::FromCode(isolate, *code);

#ifndef V8_TARGET_LITTLE_ENDIAN
#error This test assumes a little-endian layout.
#endif
  uint64_t data = UINT64_C(0x84838281807F7E7D);
  f.Call(&t, &data, 0, 0, 0);
  CHECK_EQ(0x00007E7Du, t.ldrh);
  CHECK_EQ(0x00007E7Du, t.ldrsh);
  CHECK_EQ(0x807F7E7Du, t.ldr);
  f.Call(&t, &data, 1, 0, 0);
  CHECK_EQ(0x00007F7Eu, t.ldrh);
  CHECK_EQ(0x00007F7Eu, t.ldrsh);
  CHECK_EQ(0x81807F7Eu, t.ldr);
  f.Call(&t, &data, 2, 0, 0);
  CHECK_EQ(0x0000807Fu, t.ldrh);
  CHECK_EQ(0xFFFF807Fu, t.ldrsh);
  CHECK_EQ(0x8281807Fu, t.ldr);
  f.Call(&t, &data, 3, 0, 0);
  CHECK_EQ(0x00008180u, t.ldrh);
  CHECK_EQ(0xFFFF8180u, t.ldrsh);
  CHECK_EQ(0x83828180u, t.ldr);
}

TEST(unaligned_stores) {
  // All supported ARM targets allow unaligned accesses.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});
  __ strh(r3, MemOperand(r0, r2));
  __ str(r3, MemOperand(r1, r2));
  __ bx(lr);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  StdoutStream os;
  Print(*code, os);
#endif
  auto f = GeneratedCode<F_ppiii>::FromCode(isolate, *code);

#ifndef V8_TARGET_LITTLE_ENDIAN
#error This test assumes a little-endian layout.
#endif
  {
    uint64_t strh = 0;
    uint64_t str = 0;
    f.Call(&strh, &str, 0, 0xFEDCBA98, 0);
    CHECK_EQ(UINT64_C(0x000000000000BA98), strh);
    CHECK_EQ(UINT64_C(0x00000000FEDCBA98), str);
  }
  {
    uint64_t strh = 0;
    uint64_t str = 0;
    f.Call(&strh, &str, 1, 0xFEDCBA98, 0);
    CHECK_EQ(UINT64_C(0x0000000000BA9800), strh);
    CHECK_EQ(UINT64_C(0x000000FEDCBA9800), str);
  }
  {
    uint64_t strh = 0;
    uint64_t str = 0;
    f.Call(&strh, &str, 2, 0xFEDCBA98, 0);
    CHECK_EQ(UINT64_C(0x00000000BA980000), strh);
    CHECK_EQ(UINT64_C(0x0000FEDCBA980000), str);
  }
  {
    uint64_t strh = 0;
    uint64_t str = 0;
    f.Call(&strh, &str, 3, 0xFEDCBA98, 0);
    CHECK_EQ(UINT64_C(0x000000BA98000000), strh);
    CHECK_EQ(UINT64_C(0x00FEDCBA98000000), str);
  }
}

TEST(vswp) {
  if (!CpuFeatures::IsSupported(NEON)) return;

  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  Assembler assm(AssemblerOptions{});

  struct T {
    uint64_t vswp_d0;
    uint64_t vswp_d1;
    uint64_t vswp_d30;
    uint64_t vswp_d31;
    uint32_t vswp_q4[4];
    uint32_t vswp_q5[4];
  };
  T t;

  __ stm(db_w, sp, {r4, r5, r6, r7, lr});

  uint64_t one = base::bit_cast<uint64_t>(1.0);
  __ mov(r5, Operand(one >> 32));
  __ mov(r4, Operand(one & 0xFFFFFFFF));
  uint64_t minus_one = base::bit_cast<uint64_t>(-1.0);
  __ mov(r7, Operand(minus_one >> 32));
  __ mov(r6, Operand(minus_one & 0xFFFFFFFF));

  __ vmov(d0, r4, r5);  // d0 = 1.0
  __ vmov(d1, r6, r7);  // d1 = -1.0
  __ vswp(d0, d1);
  __ vstr(d0, r0, offsetof(T, vswp_d0));
  __ vstr(d1, r0, offsetof(T, vswp_d1));

  if (CpuFeatures::IsSupported(VFP32DREGS)) {
    __ vmov(d30, r4, r5);  // d30 = 1.0
    __ vmov(d31, r6, r7);  // d31 = -1.0
    __ vswp(d30, d31);
    __ vstr(d30, r0, offsetof(T, vswp_d30));
    __ vstr(d31, r0, offsetof(T, vswp_d31));
  }

  // q-register swap.
  const uint32_t test_1 = 0x01234567;
  const uint32_t test_2 = 0x89ABCDEF;
  __ mov(r4, Operand(test_1));
  __ mov(r5, Operand(test_2));
  __ vdup(Neon32, q4, r4);
  __ vdup(Neon32, q5, r5);
  __ vswp(q4, q5);
  __ add(r6, r0, Operand(static_cast<int32_t>(offsetof(T, vswp_q4))));
  __ vst1(Neon8, NeonListOperand(q4), NeonMemOperand(r6));
  __ add(r6, r0, Operand(static_cast<int32_t>(offsetof(T, vswp_q5))));
  __ vst1(Neon8, NeonLis
```